module code

import cx
import time

// ── ProgramState locked accessors ──────────────────────────
//
// Encapsulates the per-field `sync.RwMutex` discipline so directive
// evaluators don't sprinkle inline `.lock()` / `.unlock()` calls. Each
// helper acquires the appropriate lock, performs one minimal map /
// scalar operation, and releases.
//
// A read-modify-write MUST NOT be built by pairing a `*_get` with a
// `*_set`: the gap between them is unlocked, so a concurrent writer's
// update is read stale and then clobbered. Give each RMW its own helper
// that does the whole decision inside ONE critical section — see
// `clock_advance` for the scalar case and the `bh_*` permit helpers
// below for the record case. (#1050 was exactly this: the `[?bulkhead]`
// permit counter was a get/set pair, and it lost both increments and
// decrements under real threads.)
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

// ── bulkhead permit path (#1050) ────────────────────────────────────────────
//
// The permit counter is a read-modify-write — "is a slot free? then take
// it" on entry, "give it back" on exit. Split across `bh_get` … `bh_set`
// it was NOT atomic: two arrivals could read the same `in_flight`, both
// admit over capacity, and the later `bh_set` clobber the earlier's
// increment. The same split lost DECREMENTS on release, so `in_flight`
// only ever drifted upward and every later arrival shed CXER0152 while
// the bulkhead sat under capacity. Wrong in both directions, permanently.
//
// The helpers below each perform one whole decision inside a SINGLE
// write-lock critical section — the shape `clock_advance` already uses
// for the mock clock. They are the only supported way to move a permit;
// `bh_get`/`bh_set` remain for the config/inspection paths that do not
// touch the counter.

// bh_try_acquire records the directive's configured caps and takes a slot
// if one is free, atomically. Returns true when the caller owns a permit,
// which it MUST pair with exactly one `bh_release`.
fn (mut s ProgramState) bh_try_acquire(key string, max_n i64, queue_n i64) bool {
	s.bulkhead_state_lock.lock()
	defer { s.bulkhead_state_lock.unlock() }
	mut r := BulkheadStateRecord{}
	if existing := s.bulkhead_state[key] {
		r = existing
	}
	// Record max + queue cap so the cooperative scheduler's settle phase
	// (scheduler.v `settle`) can detect "slot freed → wake first queued
	// waiter" without reaching back into the originating directive's AST.
	// Recorded on EVERY arrival, admitted or shed, as before the fix.
	r.max_concurrent = int(max_n)
	r.queue_cap = int(queue_n)
	mut took := false
	if i64(r.in_flight) < max_n {
		r.in_flight++
		took = true
	}
	s.bulkhead_state[key] = r
	return took
}

// bh_try_enqueue parks `tid` on the FIFO wait queue when the queue has
// room, atomically. Returns true when the caller is queued — the
// scheduler will convert that entry into an in-flight slot via
// `bh_grant_next`, so a true return also owes exactly one `bh_release`.
fn (mut s ProgramState) bh_try_enqueue(key string, queue_n i64, tid int) bool {
	s.bulkhead_state_lock.lock()
	defer { s.bulkhead_state_lock.unlock() }
	mut r := BulkheadStateRecord{}
	if existing := s.bulkhead_state[key] {
		r = existing
	}
	if i64(r.queued) >= queue_n {
		return false
	}
	r.queued++
	r.wait_queue << tid
	s.bulkhead_state[key] = r
	return true
}

// bh_release returns one in-flight slot, atomically. Exactly one call per
// successful `bh_try_acquire` / granted `bh_try_enqueue`.
fn (mut s ProgramState) bh_release(key string) {
	s.bulkhead_state_lock.lock()
	defer { s.bulkhead_state_lock.unlock() }
	mut r := BulkheadStateRecord{}
	if existing := s.bulkhead_state[key] {
		r = existing
	}
	r.in_flight--
	s.bulkhead_state[key] = r
}

// bh_grant_next pops the wait-queue head and converts it into an
// in-flight slot, atomically — the scheduler's half of the permit
// handshake. Returns the granted task id, or none when no slot is free
// or nobody is waiting.
fn (mut s ProgramState) bh_grant_next(key string) ?int {
	s.bulkhead_state_lock.lock()
	defer { s.bulkhead_state_lock.unlock() }
	mut r := BulkheadStateRecord{}
	if existing := s.bulkhead_state[key] {
		r = existing
	} else {
		return none
	}
	if r.in_flight >= r.max_concurrent || r.wait_queue.len == 0 {
		return none
	}
	granted := r.wait_queue[0]
	r.wait_queue.delete(0)
	r.queued--
	r.in_flight++
	s.bulkhead_state[key] = r
	return granted
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
pub fn (mut s ProgramState) service_get(name string) ?&ServiceRecord {
	s.services_lock.rlock()
	defer { s.services_lock.runlock() }
	if r := s.services[name] {
		return r
	}
	return none
}

@[inline]
pub fn (mut s ProgramState) service_set(name string, r &ServiceRecord) {
	s.services_lock.lock()
	defer { s.services_lock.unlock() }
	s.services[name] = r
}

@[inline]
pub fn (mut s ProgramState) service_has(name string) bool {
	s.services_lock.rlock()
	defer { s.services_lock.runlock() }
	return name in s.services
}

// service_next_port atomically increments and returns the previous
// next_service_port value (the assigned port).
pub fn (mut s ProgramState) service_next_port() int {
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

// future_publish stamps a concurrent future's terminal state under the
// futures lock (#541) — one locked transition, mirroring worker_publish's
// arbitration: an already-terminal future is never re-stamped (completion
// and cancellation cannot interleave into a torn state; for a body with no
// cancellation point, completion wins — §10.5.1 terminal states never
// change).
fn (mut s ProgramState) future_publish(mut f FutureRecord, state string, value cx.Node, cause cx.Node) {
	s.futures_lock.lock()
	defer { s.futures_lock.unlock() }
	if f.state in ['done', 'failed', 'cancelled'] {
		return
	}
	f.state = state
	f.value = value
	f.cause = cause
	f.parked_until_ns = 0
}

// futures_parked_earliest reports the concurrent-future park picture for
// the await barriers (#541): (runnable, earliest) where `runnable` counts
// spawned futures that are non-terminal AND not parked at a mock sleep,
// and `earliest` is the soonest parked wake time (0 when none parked).
// The barrier may advance the logical clock ONLY when runnable == 0 —
// otherwise a real-time body still making progress would race the clock.
fn (mut s ProgramState) futures_parked_earliest() (int, i64) {
	s.futures_lock.rlock()
	defer { s.futures_lock.runlock() }
	mut runnable := 0
	mut earliest := i64(0)
	for _, f in s.futures {
		if !f.concurrent {
			continue
		}
		if f.state in ['done', 'failed', 'cancelled'] {
			continue
		}
		p := f.parked_until_ns
		if p == 0 {
			runnable++
		} else if earliest == 0 || p < earliest {
			earliest = p
		}
	}
	return runnable, earliest
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

// drain_workers_at_exit is EV-WORKER-EXIT (code.md §14.4, stream 22
// W4 — the one register row RULED AGAINST shipped behavior, L76):
// cancel-and-drain at top-level return. Every non-terminal worker
// receives the cancellation stamp (a body parked at a §10.5.4
// cancellation point observes it and terminates CANCELLED; a body
// with no cancellation point runs to completion — cancellation is
// cooperative, so its effects land and it is never orphaned), then
// the runtime JOINS each to quiescence. Exit is deterministic: no
// worker outlives the program. A non-cancellable infinite body hangs
// exit by construction — inherent to cooperative cancellation, and
// exactly the visibility the rule wants (never a silent kill).
pub fn (mut s ProgramState) drain_workers_at_exit() {
	// REPEATED passes, not one shot: a single snapshot+cancel+join RACES
	// spawns that happen DURING the drain — a supervisor worker reacting
	// to a cancelled child by RESTARTING it mints a fresh record after the
	// snapshot, and that newborn is never stamped, parks at its (checked!)
	// cancellation point with cancelled=false, and outlives the program.
	// Measured 2026-08-23 (supervise sup-012, cli profile, full-parallel
	// suite): main sat in this join for 3.5 hours while a post-snapshot
	// supervise worker spun in channel_sub_receive_single — whose
	// worker_cancel_pending check was live the whole time — because no
	// pass ever cancelled it. Each pass joins its own snapshot fully;
	// the next pass catches anything born meanwhile; quiescence = an
	// empty snapshot. Restart chains terminate because the SPAWNING
	// worker is itself stamped in the following pass and observes it at
	// its next cancellation point.
	for {
		s.workers_lock.lock()
		mut live := []&WorkerRecord{}
		for _, rec in s.workers {
			if !rec.done {
				live << rec
			}
		}
		s.workers_lock.unlock()
		if live.len == 0 {
			return
		}
		for rec in live {
			s.worker_request_cancel(rec)
		}
		for rec in live {
			for !rec.done {
				time.sleep(time.millisecond)
			}
		}
	}
}

// drain_futures_at_exit is the OTHER half of the §10.5.1 spawn contract —
// "a spawned body that is never awaited still runs to a terminal state
// BEFORE TOP-LEVEL PROGRAM RETURN", the clause that makes
// `[?async [ship $order]]` with no await ship the order.
//
// It was not implemented. An un-awaited future was simply abandoned when
// the top level returned, so a fire-and-forget body outlived by the
// program's own return never ran to completion: a spawn whose body slept
// 800 ms returned in 106 ms with the body dropped. Eagerness was fine —
// the body STARTS without an await (#541) — but starting is not the
// guarantee; completing is (found working #814).
//
// This JOINS, it does not cancel, and that is the difference from
// drain_workers_at_exit above. EV-WORKER-EXIT rules `[?worker]` bodies
// cancel-and-drained, so a worker parked at a §10.5.4 point terminates
// CANCELLED. §10.5.1 makes the stronger promise for futures: the body runs
// to a terminal state, subject only to a cancellation someone explicitly
// requested. Cancelling here would break exactly the case the spec names —
// the order would not ship.
//
// The mock-clock arm mirrors the await barrier (async.v await_concurrent):
// an un-awaited body parked at `[?sleep DUR mock]` is waiting on LOGICAL
// time, which only a barrier moves. With no awaiter left to move it, this
// drain is the barrier — when nothing is runnable and something is parked,
// advance to the earliest wake. Without that arm a fire-and-forget mock
// sleep would hang exit forever, since real time never reaches a logical
// deadline.
//
// A fire-and-forget body that blocks forever on something real hangs exit
// by construction. That is the same visibility EV-WORKER-EXIT accepts, and
// it is preferable to the silent drop it replaces.
pub fn (mut s ProgramState) drain_futures_at_exit() {
	for {
		s.futures_lock.rlock()
		mut live := 0
		for _, f in s.futures {
			if !f.concurrent {
				continue // the lazy drive-at-await substrate has nothing running
			}
			if f.state in ['done', 'failed', 'cancelled'] {
				continue
			}
			live++
		}
		s.futures_lock.runlock()
		if live == 0 {
			return
		}
		runnable, earliest := s.futures_parked_earliest()
		if runnable == 0 && earliest > 0 {
			now := s.clock_now()
			if earliest > now {
				s.clock_advance(earliest - now)
			}
		}
		time.sleep(time.millisecond)
	}
}
