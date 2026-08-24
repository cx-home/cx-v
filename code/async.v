module code

import cx
import time

// ── §10.5 async / await / cancellation ─────────────────────────────────────
//
// Implements:
//   [?async EXPR]              — EAGER spawn (§10.5.1): the body runs on
//                                its own V thread whether or not awaited
//   [?await $f]                — barrier; propagate value/err
//   [?await $f timeout=DUR]    — bound the wait; CXER0241 on expiry
//                                (a LABELED argument, code.md §10.5.2 —
//                                `:timeout DUR` is a positional atom and
//                                is refused, see await_check_args)
//   [?await-all FUTURES]       — barrier; CXER0240 collects non-done causes
//   [?await-any FUTURES]       — first done in source order
//   [?await-race FUTURES]      — first terminal; cancels losers
//   [?cancel $f]               — cooperative flag + §10.5.7.2 thread revoke
//   [?check-cancel]            — reads the active future's cancel flag
//   [?sleep DUR]               — cancel-observing; DUR mock PARKS in a
//                                spawned body (never self-advances)
//
// Execution model (#541): [?async] spawns the body eagerly on the #58
// worker-thread substrate — §10.5.1's "returns immediately with a future"
// with the state machine running independently of any await. LOGICAL time
// stays deterministic across threads: a mock sleep in a spawned body
// PARKS (parked_until_ns) and the await barriers advance the shared
// clock only when every runnable spawned future is parked, bounded by the
// awaiter's own deadline (await_concurrent). The lazy drive-at-await
// substrate (and its CX_WORKER_THREADS=0 selector) is RETIRED — rule
// EV-ASYNC-SPAWN (code.md §14.4; the #707 residual, stream 22 W3):
// CX_WORKER_THREADS is thread-pool SIZING only, never a semantics dial.

fn mk_future_handle(id string) cx.Node {
	// id (scalar) → attribute. The future handle also carries the nominal
	// close-contract marker (`__cx_close_id__`, §10.5.7.1) so [?with-open]
	// recognizes it as closeable and its close cancels-and-joins the task.
	return cx.Element{
		name:  'future-handle'
		attrs: [
			cx.new_attribute('id', cx.ScalarValue(id), cx.AttributeMeta{
				data_type: ?string(none)
			}),
			cx.Attribute{ name: close_id_attr, value: cx.ScalarValue('future:${id}') },
		]
	}
}

fn read_future_id(el cx.Element) ?string {
	n := read_result_field(el, 'id') or { return none }
	if n is cx.ScalarNode {
		x := n.value
		if x is string { return x }
	}
	return none
}

// future_handle_attr resolves a `@`-attribute access on a future handle
// against the LIVE future record in env.state, per the spec'd future
// shape (§10.5.1):
//
//   [future id=ID state=STATE created=INSTANT
//    value=VALUE          ; present when state = done
//    [cause [err ...]]    ; present when state = failed
//    cancel-reason=STRING] ; present when state = cancelled
//
// The future binding `$f` captures the handle at [?async] time (state
// `pending`); the record it points to mutates as [?await] drives the
// body. So `$f@state` / `$f@value` / `$f@cause` / `$f@id` MUST read the
// live record rather than the stale captured handle. Returns `none`
// when `el` is not a future handle or when the attribute is not one of
// the spec'd future fields (so the caller falls through to ordinary
// attribute resolution).
fn future_handle_attr(el cx.Element, attr string, mut env MatchEnv) ?cx.Node {
	if el.name != 'future-handle' {
		return none
	}
	id := read_future_id(el) or { return none }
	if attr == 'id' {
		return cx.ScalarNode{ value: id, data_type: cx.ScalarType.string_type }
	}
	fut := env.state.future_get(id) or { return none }
	match attr {
		'state' {
			return cx.ScalarNode{ value: fut.state, data_type: cx.ScalarType.string_type }
		}
		'value' {
			// Only meaningful when terminal-done; for non-done states the
			// field is absent per the spec, so signal `none`.
			if fut.state == 'done' {
				return fut.value
			}
			return none
		}
		'cause' {
			if fut.state == 'failed' {
				return fut.cause
			}
			return none
		}
		else {
			return none
		}
	}
}

fn resolve_future(node cx.ProgramNode, mut env MatchEnv) !&FutureRecord {
	v := eval_node(node, mut env)!
	if v is cx.Element && v.name == 'future-handle' {
		id := read_future_id(v) or {
			return error('[?await] future-handle missing :id')
		}
		fut := env.state.future_get(id) or {
			return error('future "${id}" not registered')
		}
		return fut
	}
	return error('expected future-handle')
}

// ── [?async] ──────────────────────────────────────────────────────────────

fn eval_async(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	// [?async EXPR] takes one positional slot — the body to evaluate.
	if d.slots.len == 0 {
		return EvalError{ code: 'cx-err:CXER0001',
			message: '[?async] requires a positional body slot' }
	}
	body_node := d.slots[0].value
	id := env.state.future_alloc_id()
	// Snapshot bindings so closures over the surrounding lexical scope
	// remain valid when the body runs lazily.
	mut snapshot := map[string]cx.Node{}
	for k, v in env.bindings {
		snapshot[k] = v
	}
	rec := &FutureRecord{
		id:                id
		body:              [body_node]
		bindings_snapshot: snapshot
		state:             'pending'
		value:             cx.Node(cx.Element{ name: '' })
		cause:             cx.Node(cx.Element{ name: '' })
		cancel_requested:  false
	}
	env.state.future_set(id, rec)
	// Register the close-contract (§10.5.7.1): closing the future handle in
	// a [?with-open] scope cancels-and-joins it. The generic close_fn is a
	// no-op; fire_close dispatches on handle_kind to do the real work (it
	// has the `mut env` needed to reach the futures registry).
	cclose_id := 'future:${id}'
	env.state.closeables[cclose_id] = &CloseableRecord{
		label:       'future:${id}'
		closed:      false
		close_fn:    fn () ! {}
		handle_kind: 'future'
		handle_id:   id
	}
	// #541: EAGER spawn is the §10.5.1 DEFAULT — "evaluates EXPR in a new
	// asynchronous context and RETURNS IMMEDIATELY"; the body runs whether
	// or not the future is ever awaited (fire-and-forget is legitimate).
	// Rides the #58 worker-thread substrate (same vgc multi-mutator
	// soundness lineage). Spawn is UNCONDITIONAL — rule EV-ASYNC-SPAWN
	// (code.md §14.4, stream 22 W3): no environment value may select a
	// lazy substrate; the pre-W3 CX_WORKER_THREADS=0 drive-at-await
	// fallback is RETIRED (the #707 residual).
	mut mrec := unsafe { rec }
	mrec.concurrent = true
	mrec.state = 'running'
	spawn run_future_thread(rec, unsafe { env.state }, env.bindings.clone(),
		env.closures.clone(), env.scope, env.dyn_context.clone(), body_node)
	return mk_future_handle(id)
}

// run_future_thread is the spawned-thread body for an eager [?async]
// (#541) — run_worker_thread's shape verbatim: a private env (cloned
// bindings/closures + shared &ProgramState + the program scope), the
// §10.5.1 dynamic-context capture-at-spawn (dyn snapshot), and terminal
// publication through the LOCKED future_publish (which arbitrates against
// a racing [?cancel]: terminal states never change, so a body with no
// cancellation point completes done even if the flag was set mid-run —
// cancellation is cooperative, §10.5.4). Cancellation points inside the
// body observe env.current_future (the thread-local rec) and raise/return
// CXER0260 → the CANCELLED terminal.
fn run_future_thread(rec_ptr &FutureRecord, state_ptr &ProgramState, binds map[string]cx.Node, closures_snap map[string]Closure, scope_ptr &Scope, dyn []cx.Node, body cx.ProgramNode) {
	mut rec := unsafe { rec_ptr }
	mut fenv := MatchEnv{
		bindings:       binds
		closures:       closures_snap
		state:          unsafe { state_ptr }
		scope:          unsafe { scope_ptr }
		dyn_context:    dyn
		anon_counter:   0
		frame_pool:     &FramePool{}
		current_future: rec
	}
	mut st := unsafe { state_ptr }
	// §10.5.7.2 (#541): stamp this thread's id so a [?cancel] can revoke
	// its capability set for the remainder of the body; clear the
	// revocation with the thread (terminal futures need no backstop).
	rec.thread_id = cap_thread_id()
	if rec.cancel_requested {
		caps_revoke_thread(rec.thread_id)
	}
	defer { caps_unrevoke_thread(rec.thread_id) }
	empty := cx.Node(cx.Element{ name: '' })
	result := eval_node(body, mut fenv) or {
		if err.msg().contains('cx-err:CXER0260') {
			st.future_publish(mut rec, 'cancelled', empty, mk_err_with_slots('cx-err:CXER0260', []))
			return
		}
		st.future_publish(mut rec, 'failed', empty, mk_err('inner', err.msg()))
		return
	}
	if is_err_value(result) {
		if err_code_of(result) == 'cx-err:CXER0260' {
			st.future_publish(mut rec, 'cancelled', empty, result)
			return
		}
		st.future_publish(mut rec, 'failed', empty, result)
		return
	}
	// Multi-value top-level wrapper → first-class sequence (mirrors
	// drive_future's normalisation; program-async-013 shape).
	if result is cx.Element && result.name == '' && result.items.len > 1 {
		st.future_publish(mut rec, 'done', cx.Node(cx.Element{
			name:  '__cx_seq__'
			items: result.items
		}), empty)
		return
	}
	st.future_publish(mut rec, 'done', result, empty)
}

// (drive_future — the lazy body driver — RETIRED at stream 22 W3
// with the lazy substrate; EV-ASYNC-SPAWN.)

fn future_state_to_result(fut FutureRecord) cx.Node {
	match fut.state {
		'done'      { return fut.value }
		'failed'    { return fut.cause }
		'cancelled' { return mk_err_with_slots('cx-err:CXER0260', []) }
		else        { return mk_err_with_slots('cx-err:CXER0260', []) }
	}
}

pub fn err_code_of(n cx.Node) string {
	// draft-3 — a failure outcome is `[result status=err …]`
	// with code carried as an attribute (the legacy `[err …]` slot/attr
	// child forms below are read transitionally).
	if n is cx.Element && is_err_value(n) {
		for c in n.items {
			if c is cx.Element && c.name == '${slot_child_prefix}code' && c.items.len > 0 {
				inner := c.items[0]
				if inner is cx.ScalarNode {
					x := inner.value
					if x is string { return x }
				}
			}
			// Legacy attr form.
			if c is cx.Element && c.name == 'code' && c.items.len > 0 {
				inner := c.items[0]
				if inner is cx.ScalarNode {
					x := inner.value
					if x is string { return x }
				}
			}
		}
		for a in n.attrs {
			if a.name == 'code' {
				v := a.value
				if v is string { return v }
			}
		}
	}
	return ''
}

// ── [?await] family ───────────────────────────────────────────────────────

// await_check_args refuses every argument the await family does not
// define, instead of dropping it (#793). Silent tolerance turned a
// spelling mistake into a behavior change: `[?await $f :timeout 2ms]`
// parses as THREE positional slots, the trailing two were ignored, and
// the bounded await the author wrote ran as an unbounded one — fail-open
// at exactly the point a deadline was being asked for. Per code.md
// §10.5.2 the whole family takes ONE positional (the future, or the
// future sequence); only [?await] defines a label, `timeout=`.
fn await_check_args(d cx.ProgramDirective, allowed []string) ! {
	mut positional := 0
	for s in d.slots {
		if s.kind == .labeled {
			if s.label in allowed {
				continue
			}
			expected := if allowed.len == 0 {
				'it takes no labeled arguments'
			} else {
				'the only labeled argument is `${allowed.join('=`, `')}=`'
			}
			return EvalError{
				code:    'cx-err:CXER0100'
				message: '[?${d.name}] has no `${s.label}=` argument — ${expected} (code.md §10.5.2)'
			}
		}
		positional++
		if positional > 1 {
			return EvalError{
				code:    'cx-err:CXER0100'
				message: '[?${d.name}] takes exactly one positional argument (code.md §10.5.2), got ${positional}' +
					await_label_hint(s.value, allowed)
			}
		}
	}
}

// await_label_hint names the exact fail-open spelling the issue reports:
// `:label value` written where `label=value` was meant. The atom lands as
// a positional atom literal, so a positional whose name IS a defined
// label is worth calling out by name rather than reporting a bare arity.
fn await_label_hint(n cx.ProgramNode, allowed []string) string {
	if n is cx.ProgramLiteral {
		if n.kind == .atom_lit && n.str_val in allowed {
			return ' — `:${n.str_val}` is a positional atom; write `${n.str_val}=…` for the labeled argument'
		}
	}
	return ''
}

fn eval_await(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	if d.slots.len == 0 {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?await] requires a future' }
	}
	await_check_args(d, ['timeout'])!
	fut := resolve_future(d.slots[0].value, mut env)!
	deadline_ns := if dur_node := labeled_slot(d, 'timeout') {
		if dur_node is cx.ProgramLiteral && (dur_node as cx.ProgramLiteral).kind == .duration_lit {
			ns := duration_to_ns((dur_node as cx.ProgramLiteral).dur_val) or {
				return error('[?await] :timeout malformed duration')
			}
			env.state.clock_now() + ns
		} else {
			i64(0)
		}
	} else {
		i64(0)
	}
	mut rec := fut
	return await_with_deadline(mut rec, deadline_ns, mut env)
}

fn await_with_deadline(mut fut FutureRecord, deadline_ns i64,
                       mut env MatchEnv) cx.Node {
	if fut.concurrent {
		return await_concurrent(mut fut, deadline_ns, mut env)
	}
	// Every [?async] future is concurrent (EV-ASYNC-SPAWN, W3 — the
	// lazy substrate is retired); a non-concurrent record can only be
	// terminal (defensive read).
	return future_state_to_result(fut)
}

// await_concurrent is the eager-spawn await barrier (#541): block until
// the target future is terminal, coordinating LOGICAL time across the
// spawned threads. The clock is purely logical (state_locks.v now_ns —
// only mock sleeps and this barrier move it), so the §10.2.2 honest
// posture is preserved: deadlines are logical-time deadlines.
//
//   - the target terminal → its result (§10.5.2).
//   - a bounded await whose LOGICAL deadline lapses → CXER0241; the
//     future stays pending/parked (the deadline is the caller's, §10.5.3).
//   - when EVERY non-terminal spawned future is parked at a mock sleep
//     (none runnable), nothing can move except time: advance the clock to
//     the earliest wake — bounded by this awaiter's deadline, so a
//     10s-mock-sleeping body under a 50ms await times the AWAIT out
//     deterministically (program-async-003) instead of racing the body.
//   - otherwise a runnable body is making real progress: poll.
fn await_concurrent(mut fut FutureRecord, deadline_ns i64, mut env MatchEnv) cx.Node {
	for {
		if fut.state in ['done', 'failed', 'cancelled'] {
			return future_state_to_result(fut)
		}
		if deadline_ns > 0 && env.state.clock_now() >= deadline_ns {
			return mk_err_with_slots('cx-err:CXER0241', [])
		}
		runnable, earliest := env.state.futures_parked_earliest()
		if runnable == 0 && earliest > 0 {
			mut target := earliest
			if deadline_ns > 0 && deadline_ns < target {
				target = deadline_ns
			}
			now := env.state.clock_now()
			if target > now {
				env.state.clock_advance(target - now)
			}
			// woken sleepers observe the new clock on their next poll
		}
		time.sleep(time.millisecond)
	}
	return cx.Node(cx.Element{})
}

fn eval_await_all(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	futures := collect_future_args(d, mut env)!
	mut values := []cx.Node{}
	mut causes := []cx.Node{}
	for fh in futures {
		mut fut := resolve_future_from_handle(fh, mut env) or {
			return EvalError{ code: 'cx-err:CXER0001',
				message: '[?await-all] expects a sequence of future-handles' }
		}
		result := await_with_deadline(mut fut, i64(0), mut env)
		if fut.state == 'done' {
			values << result
		} else {
			// failed / cancelled / still-pending: collect the cause
			cause_val := match fut.state {
				'failed'    { fut.cause }
				'cancelled' { mk_err_with_slots('cx-err:CXER0260', []) }
				else        { result }  // pending after timeout-less await: shouldn't happen
			}
			causes << cause_val
		}
	}
	if causes.len > 0 {
		// `[causes …]` carries the failed/cancelled futures' errors as
		// direct body children: a single cause renders bare
		// (`[causes [err …]]`), multiple as a sequence
		// (`[causes (err1, err2)]`). The single-cause unwrap matches the
		// general CX single-item shape and the await-all fixtures.
		causes_val := if causes.len == 1 {
			causes[0]
		} else {
			cx.Node(cx.Element{ name: '__cx_seq__', items: causes })
		}
		return mk_err_with_slots('cx-err:CXER0240', [
			Slot{ label: 'causes', value: causes_val },
		])
	}
	return cx.Element{ name: '__cx_seq__', items: values }
}

fn eval_await_any(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	futures := collect_future_args(d, mut env)!
	mut last_err := cx.Node(cx.Element{ name: '' })
	for fh in futures {
		mut fut := resolve_future_from_handle(fh, mut env) or { continue }
		result := await_with_deadline(mut fut, i64(0), mut env)
		if fut.state == 'done' {
			return result
		}
		last_err = result
	}
	return last_err
}

fn eval_await_race(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	futures := collect_future_args(d, mut env)!
	mut winner := cx.Node(cx.Element{ name: '' })
	mut winner_idx := -1
	for i, fh in futures {
		mut fut := resolve_future_from_handle(fh, mut env) or { continue }
		result := await_with_deadline(mut fut, i64(0), mut env)
		if fut.state in ['done', 'failed', 'cancelled'] {
			winner = result
			winner_idx = i
			break
		}
	}
	// Cancel every loser (per §10.5.2: "Other futures MUST be issued
	// [?cancel]"). Lazy losers are 'pending' (not yet driven); eager
	// losers are 'running' (#541) — their parked/running bodies observe
	// the flag at the next cancellation point. Terminal losers stay
	// terminal (§10.5.1).
	for i, fh in futures {
		if i == winner_idx { continue }
		if mut fut := resolve_future_from_handle(fh, mut env) {
			if fut.state in ['pending', 'running'] {
				future_request_cancel(mut fut)
			}
		}
	}
	return winner
}

fn collect_future_args(d cx.ProgramDirective, mut env MatchEnv) ![]cx.Node {
	if d.slots.len == 0 {
		return error('[?await-*] requires a future sequence')
	}
	// The -all / -any / -race barriers take the future sequence and
	// nothing else — no `timeout=` (they always await unbounded), so
	// every label and every extra positional is refused here (#793).
	await_check_args(d, [])!
	first := d.slots[0].value
	val := eval_node(first, mut env)!
	mut out := []cx.Node{}
	if val is cx.Element && (val.name == '__cx_seq__' || val.name == '__cx_arr__') {
		for c in val.items {
			out << c
		}
		return out
	}
	// Single future handle — accept for ergonomics.
	out << val
	return out
}

fn resolve_future_from_handle(h cx.Node, mut env MatchEnv) !&FutureRecord {
	if h is cx.Element && h.name == 'future-handle' {
		id := read_future_id(h) or { return error('future-handle missing :id') }
		fut := env.state.future_get(id) or { return error('future "${id}" not registered') }
		return fut
	}
	return error('expected future-handle')
}

// ── Cancellation hooks for [?sleep] / [?check-cancel] / [?cancel] ─────────

// future_request_cancel raises a future's cancel flag AND, for a running
// concurrent body, registers its thread in the §10.5.7.2 revocation set —
// raw capability-gated effects on that thread deny (CXER0271) for the
// remainder of the body, while cancellation points keep their CXER0260
// precedence. Every cancel path routes here.
pub fn future_request_cancel(mut fut FutureRecord) {
	fut.cancel_requested = true
	if fut.concurrent && fut.thread_id != 0 {
		caps_revoke_thread(fut.thread_id)
	}
}

// active_future_cancelled returns true if the current evaluation is inside
// a future whose cancel_requested flag is set — the thread-local
// env.current_future for an eager spawned body (#541), or the global
// current_future_id the lazy drive-at-await path stamps.
fn active_future_cancelled(env MatchEnv) bool {
	if env.current_future != unsafe { nil } {
		return env.current_future.cancel_requested
	}
	mut s := unsafe { env.state }
	cur := s.current_future_get()
	if cur == '' { return false }
	fut := s.future_get(cur) or { return false }
	return fut.cancel_requested
}

// would_exceed_await_deadline reports whether the current await context
// is bounded and adding sleep_ns would push past the deadline.
fn would_exceed_await_deadline(env MatchEnv, sleep_ns i64) bool {
	mut s := unsafe { env.state }
	dl := s.await_deadline_get()
	if dl == 0 { return false }
	return s.clock_now() + sleep_ns > dl
}
