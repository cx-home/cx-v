module code

import cx

// ── ProgramState locked accessors ──────────────────────────
//
// Encapsulates the per-field `sync.RwMutex` discipline so directive
// evaluators don't sprinkle inline `.lock()` / `.unlock()` calls. Each
// helper acquires the appropriate lock, performs one minimal map /
// scalar operation, and releases. Read-modify-write callers acquire
// once, call helper-pair, release — or use the closure-based
// `*_with_write_lock` helpers for atomic update sequences that must
// span the read + write.
//
// Critically, these helpers do NOT span an `eval_node` body. POSIX
// rwlocks are non-recursive: holding `cb_state_lock` and recursing
// into another `[?circuit-breaker]` would deadlock. The pattern at
// `eval_circuit_breaker` / `eval_bulkhead` / `eval_rate_limit` is:
//
//   1. Acquire write lock, snapshot rec, apply pre-body update,
//      write back, release.
//   2. Call `eval_node(body, env)` unlocked.
//   3. Acquire write lock, re-read latest rec, apply post-body
//      update, write back, release.
//
// The split-RMW pattern leaves a small re-read window during the
// body eval. Concurrent workers at the SAME source-text key may see
// each other's pre-body updates; that's the §10.2.7 state-identity
// contract working as designed.

// ── cb_state (circuit-breaker) ──────────────────────────────────────────────

@[inline]
fn (mut s ProgramState) cb_get(key string) ?CbStateRecord {
	s.cb_state_lock.rlock()
	defer { s.cb_state_lock.runlock() }
	if r := s.cb_state[key] {
		return r
	}
	return none
}

@[inline]
fn (mut s ProgramState) cb_set(key string, r CbStateRecord) {
	s.cb_state_lock.lock()
	defer { s.cb_state_lock.unlock() }
	s.cb_state[key] = r
}

// ── rate_state (rate-limit) ─────────────────────────────────────────────────

@[inline]
fn (mut s ProgramState) rate_get(key string) ?RateStateRecord {
	s.rate_state_lock.rlock()
	defer { s.rate_state_lock.runlock() }
	if r := s.rate_state[key] {
		return r
	}
	return none
}

@[inline]
fn (mut s ProgramState) rate_set(key string, r RateStateRecord) {
	s.rate_state_lock.lock()
	defer { s.rate_state_lock.unlock() }
	s.rate_state[key] = r
}

// ── bulkhead_state ──────────────────────────────────────────────────────────

@[inline]
fn (mut s ProgramState) bh_get(key string) BulkheadStateRecord {
	s.bulkhead_state_lock.rlock()
	defer { s.bulkhead_state_lock.runlock() }
	if r := s.bulkhead_state[key] {
		return r
	}
	return BulkheadStateRecord{}
}

@[inline]
fn (mut s ProgramState) bh_set(key string, r BulkheadStateRecord) {
	s.bulkhead_state_lock.lock()
	defer { s.bulkhead_state_lock.unlock() }
	s.bulkhead_state[key] = r
}

// bh_snapshot_all returns a copy of every (key, record) pair under
// the read lock. Used by the scheduler's bulkhead-queue settle pass
// (vcx/code/scheduler.v) so the iteration doesn't race with worker
// `bh_set` calls from spawned `:par` tasks.
fn (mut s ProgramState) bh_snapshot_all() map[string]BulkheadStateRecord {
	s.bulkhead_state_lock.rlock()
	defer { s.bulkhead_state_lock.runlock() }
	mut out := map[string]BulkheadStateRecord{}
	for k, v in s.bulkhead_state {
		out[k] = v
	}
	return out
}

// ── channels ────────────────────────────────────────────────────────────────

@[inline]
fn (mut s ProgramState) channel_get(name string) ?&ChannelRecord {
	s.channels_lock.rlock()
	defer { s.channels_lock.runlock() }
	if c := s.channels[name] {
		return c
	}
	return none
}

@[inline]
fn (mut s ProgramState) channel_set(name string, c &ChannelRecord) {
	s.channels_lock.lock()
	defer { s.channels_lock.unlock() }
	s.channels[name] = c
}

@[inline]
fn (mut s ProgramState) channel_has(name string) bool {
	s.channels_lock.rlock()
	defer { s.channels_lock.runlock() }
	return name in s.channels
}

// ── workers ─────────────────────────────────────────────────────────────────

@[inline]
fn (mut s ProgramState) worker_get(name string) ?&WorkerRecord {
	s.workers_lock.rlock()
	defer { s.workers_lock.runlock() }
	if w := s.workers[name] {
		return w
	}
	return none
}

@[inline]
fn (mut s ProgramState) worker_set(name string, w &WorkerRecord) {
	s.workers_lock.lock()
	defer { s.workers_lock.unlock() }
	s.workers[name] = w
}

@[inline]
fn (mut s ProgramState) worker_has(name string) bool {
	s.workers_lock.rlock()
	defer { s.workers_lock.runlock() }
	return name in s.workers
}

// ── worker lifecycle (concurrent [?worker] ↔ [?cancel] arbitration) ──────────
//
// The cancel request ([?cancel], main thread) and the terminal publish
// (run_worker_thread, worker thread) both check-then-write the record's
// done/cancelled/result fields. Without a shared critical section the two
// interleave: a body completing between [?cancel]'s done-check and its stamp
// clobbered the WORKER_CANCELLED chain with the body's value — the
// program-conc-017 "[ok] instead of CXER0221/CXER0260" flake. All three
// transitions below take workers_lock so exactly one terminal outcome wins,
// per §10.5.4: cancel-while-running wins over a later body completion; a
// body that completed FIRST keeps its value (cancel of a done worker is a
// no-op).

// worker_request_cancel implements the §10.5.4 request semantics: a
// still-running worker is marked cancelled with the WORKER_CANCELLED /
// CANCELLED chain stamped as its terminal result; a worker that already
// ran to completion keeps its value. `result` is written BEFORE the
// `cancelled` flag flips so the [?wait-for] spin (which exits on the flag,
// unlocked) always reads a complete record.
fn (mut s ProgramState) worker_request_cancel(rec_ptr &WorkerRecord) {
	mut rec := unsafe { rec_ptr }
	s.workers_lock.lock()
	defer { s.workers_lock.unlock() }
	if rec.done {
		return
	}
	rec.result = mk_err_with_slots('cx-err:CXER0221', [
		Slot{ label: 'cause', value: mk_err_with_slots('cx-err:CXER0260', []) },
	])
	rec.cancelled = true
}

// worker_publish stores a concurrent worker's terminal result. A record
// already stamped cancelled keeps the WORKER_CANCELLED chain (the cancel
// request won the §10.5.4 arbitration); `done` flips last either way.
fn (mut s ProgramState) worker_publish(rec_ptr &WorkerRecord, result cx.Node) {
	mut rec := unsafe { rec_ptr }
	s.workers_lock.lock()
	defer { s.workers_lock.unlock() }
	if !rec.cancelled {
		rec.result = result
	}
	rec.done = true
}

// worker_publish_cancelled marks the terminal state of a worker whose BODY
// observed cancellation at a cancellation point (CXER0260 surfaced from
// [?send]/[?receive]/[?check-cancel]/[?sleep]/[?for], §10.5.4) — the worker
// terminated via [?cancel], so the terminal shape is the same
// WORKER_CANCELLED chain the cancel-side stamp writes (idempotent with it).
fn (mut s ProgramState) worker_publish_cancelled(rec_ptr &WorkerRecord) {
	mut rec := unsafe { rec_ptr }
	s.workers_lock.lock()
	defer { s.workers_lock.unlock() }
	rec.result = mk_err_with_slots('cx-err:CXER0221', [
		Slot{ label: 'cause', value: mk_err_with_slots('cx-err:CXER0260', []) },
	])
	rec.cancelled = true
	rec.done = true
}

// ── services ────────────────────────────────────────────────────────────────

@[inline]
fn (mut s ProgramState) service_get(name string) ?&ServiceRecord {
	s.services_lock.rlock()
	defer { s.services_lock.runlock() }
	if r := s.services[name] {
		return r
	}
	return none
}

@[inline]
fn (mut s ProgramState) service_set(name string, r &ServiceRecord) {
	s.services_lock.lock()
	defer { s.services_lock.unlock() }
	s.services[name] = r
}

@[inline]
fn (mut s ProgramState) service_has(name string) bool {
	s.services_lock.rlock()
	defer { s.services_lock.runlock() }
	return name in s.services
}

// service_next_port atomically increments and returns the previous
// next_service_port value (the assigned port).
fn (mut s ProgramState) service_next_port() int {
	s.services_lock.lock()
	defer { s.services_lock.unlock() }
	port := s.next_service_port
	s.next_service_port++
	return port
}

// ── futures ─────────────────────────────────────────────────────────────────

@[inline]
fn (mut s ProgramState) future_get(id string) ?&FutureRecord {
	s.futures_lock.rlock()
	defer { s.futures_lock.runlock() }
	if f := s.futures[id] {
		return f
	}
	return none
}

@[inline]
fn (mut s ProgramState) future_set(id string, f &FutureRecord) {
	s.futures_lock.lock()
	defer { s.futures_lock.unlock() }
	s.futures[id] = f
}

// future_alloc_id atomically returns the next future id and bumps
// the counter. Used by `eval_async` to mint unique handles.
fn (mut s ProgramState) future_alloc_id() string {
	s.futures_lock.lock()
	defer { s.futures_lock.unlock() }
	id := 'f-${s.next_future_id}'
	s.next_future_id++
	return id
}

// ── test_counters / test_err_counts / test_seq_idx ──────────────────────────

@[inline]
fn (mut s ProgramState) test_counter_get(key string) i64 {
	s.test_counters_lock.rlock()
	defer { s.test_counters_lock.runlock() }
	return s.test_counters[key] or { i64(0) }
}

@[inline]
fn (mut s ProgramState) test_counter_set(key string, v i64) {
	s.test_counters_lock.lock()
	defer { s.test_counters_lock.unlock() }
	s.test_counters[key] = v
}

@[inline]
fn (mut s ProgramState) test_err_count_get(key string) i64 {
	s.test_err_counts_lock.rlock()
	defer { s.test_err_counts_lock.runlock() }
	return s.test_err_counts[key] or { i64(0) }
}

@[inline]
fn (mut s ProgramState) test_err_count_set(key string, v i64) {
	s.test_err_counts_lock.lock()
	defer { s.test_err_counts_lock.unlock() }
	s.test_err_counts[key] = v
}

@[inline]
fn (mut s ProgramState) test_seq_idx_get(key string) int {
	s.test_seq_idx_lock.rlock()
	defer { s.test_seq_idx_lock.runlock() }
	return s.test_seq_idx[key] or { 0 }
}

@[inline]
fn (mut s ProgramState) test_seq_idx_set(key string, v int) {
	s.test_seq_idx_lock.lock()
	defer { s.test_seq_idx_lock.unlock() }
	s.test_seq_idx[key] = v
}

// ── scheduler_tasks ─────────────────────────────────────────────────────────

@[inline]
fn (mut s ProgramState) scheduler_task_get(id int) ?&TaskRecord {
	s.scheduler_tasks_lock.rlock()
	defer { s.scheduler_tasks_lock.runlock() }
	if t := s.scheduler_tasks[id] {
		return t
	}
	return none
}

@[inline]
fn (mut s ProgramState) scheduler_task_has(id int) bool {
	s.scheduler_tasks_lock.rlock()
	defer { s.scheduler_tasks_lock.runlock() }
	return id in s.scheduler_tasks
}

@[inline]
fn (mut s ProgramState) scheduler_task_set(id int, t &TaskRecord) {
	s.scheduler_tasks_lock.lock()
	defer { s.scheduler_tasks_lock.unlock() }
	s.scheduler_tasks[id] = t
}

@[inline]
fn (mut s ProgramState) scheduler_task_delete(id int) {
	s.scheduler_tasks_lock.lock()
	defer { s.scheduler_tasks_lock.unlock() }
	s.scheduler_tasks.delete(id)
}

// ── clock_lock group (now_ns / await_deadline_ns / current_future_id
//                     / current_task_id) ─────────────────────────────────────

@[inline]
fn (mut s ProgramState) clock_now() i64 {
	s.clock_lock.rlock()
	defer { s.clock_lock.runlock() }
	return s.now_ns
}

@[inline]
fn (mut s ProgramState) clock_advance(ns i64) i64 {
	s.clock_lock.lock()
	defer { s.clock_lock.unlock() }
	s.now_ns += ns
	return s.now_ns
}

@[inline]
fn (mut s ProgramState) clock_set(ns i64) {
	s.clock_lock.lock()
	defer { s.clock_lock.unlock() }
	s.now_ns = ns
}

@[inline]
fn (mut s ProgramState) await_deadline_get() i64 {
	s.clock_lock.rlock()
	defer { s.clock_lock.runlock() }
	return s.await_deadline_ns
}

@[inline]
fn (mut s ProgramState) await_deadline_set(v i64) {
	s.clock_lock.lock()
	defer { s.clock_lock.unlock() }
	s.await_deadline_ns = v
}

@[inline]
fn (mut s ProgramState) current_future_get() string {
	s.clock_lock.rlock()
	defer { s.clock_lock.runlock() }
	return s.current_future_id
}

@[inline]
fn (mut s ProgramState) current_future_set(v string) {
	s.clock_lock.lock()
	defer { s.clock_lock.unlock() }
	s.current_future_id = v
}

@[inline]
fn (mut s ProgramState) current_task_get() int {
	s.clock_lock.rlock()
	defer { s.clock_lock.runlock() }
	return s.current_task_id
}

@[inline]
fn (mut s ProgramState) current_task_set(v int) {
	s.clock_lock.lock()
	defer { s.clock_lock.unlock() }
	s.current_task_id = v
}
