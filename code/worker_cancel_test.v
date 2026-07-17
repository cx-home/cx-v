module code

import cx
import time

// worker_cancel_test.v — determinism tests for [?cancel] on a concurrent
// [?worker] (spec/code.md §10.4.2/§10.4.3 blocking channel ops, §10.5.4
// cooperative cancellation, §10.5.7.2 cancellation-point precedence).
//
// The program-conc-016/017/020 conformance fixtures cancel a worker whose
// body is expected to be BLOCKED at a cancellation point. On the concurrent
// worker substrate the pre-fix [?send]/[?receive] never blocked (the
// single-threaded-substrate simplification), so the worker body raced the
// main thread's [?cancel]: under CPU starvation the body ran to completion
// first and [?wait-for] surfaced the body's value ([ok]) instead of the
// WORKER_CANCELLED chain — the flake observed on the 2026-07-04 cold gate.
// These tests pin the spec semantics under ADVERSARIAL scheduling: the main
// thread sleeps long enough that a non-blocking body would always win the
// race before [?cancel] is issued.

const cancel_chain_outer = 'cx-err:CXER0221'
const cancel_chain_cause = 'cx-err:CXER0260'

fn eval_step(mut env MatchEnv, src string) cx.Node {
	prog := cx.parse_program(src) or { panic('parse failed: ${err.msg()}\n${src}') }
	return eval(prog.body, mut env) or { panic('eval failed: ${err.msg()}\n${src}') }
}

// worker_rec fetches the WorkerRecord for `name` (test-side observability).
fn worker_rec(mut env MatchEnv, name string) &WorkerRecord {
	mut st := env.state
	return st.worker_get(name) or { panic('no worker record "${name}"') }
}

// join_done spin-waits (up to `ms` milliseconds) for the worker body's
// thread to publish its terminal state.
fn join_done(rec &WorkerRecord, ms int) bool {
	mut waited := 0
	for !rec.done {
		if waited >= ms {
			return false
		}
		time.sleep(time.millisecond)
		waited++
	}
	return true
}

// §10.4.2: a worker's [?send] on an unbuffered channel with no receiver
// MUST block (it is also a §10.5.4 cancellation point). Cancelling the
// blocked worker MUST surface the WORKER_CANCELLED/CANCELLED chain from
// [?wait-for] — regardless of how late the [?cancel] arrives.
// (program-conc-017-send-cancelled, de-raced.)
fn test_send_cancel_deterministic_under_adversarial_delay() {
	caps_set_all()
	mut env := new_env()
	eval_step(mut env, '[?let [= $ch [?channel name="tc17" buffer=0]] [?worker name="tw17" [body [?send "blocked" to=$ch]]]]')
	// Adversarial scheduling: with a non-blocking send the body completes
	// within microseconds; 200ms guarantees the pre-fix race is ALWAYS lost.
	time.sleep(200 * time.millisecond)
	rec := worker_rec(mut env, 'tw17')
	assert !rec.done, '[?send] on an unbuffered channel with no receiver must block (§10.4.2); worker completed with: ${render_canonical(rec.result)}'
	res := eval_step(mut env, '[?let [= $h [?worker-handle name="tw17"]] [?let [= $_ [?cancel worker=$h]] [?wait-for worker=$h]]]')
	rendered := render_canonical(res)
	assert rendered.contains(cancel_chain_outer), 'expected WORKER_CANCELLED chain, got: ${rendered}'
	assert rendered.contains(cancel_chain_cause), 'expected CANCELLED cause, got: ${rendered}'
	// The blocked body must EXIT via the cancellation point (§10.5.4) —
	// a leaked forever-blocked thread means send never observed the cancel.
	assert join_done(rec, 2000), 'worker body never exited its blocked [?send] after [?cancel]'
	assert rec.cancelled
}

// §10.4.3: a worker's [?receive] on an empty open channel MUST block (and
// is a cancellation point). (program-conc-016-receive-cancelled, de-raced.)
fn test_receive_cancel_deterministic_under_adversarial_delay() {
	caps_set_all()
	mut env := new_env()
	eval_step(mut env, '[?let [= $ch [?channel name="tc16" buffer=0]] [?worker name="tw16" [body [?receive from=$ch]]]]')
	time.sleep(200 * time.millisecond)
	rec := worker_rec(mut env, 'tw16')
	assert !rec.done, '[?receive] on an empty open channel must block (§10.4.3); worker completed with: ${render_canonical(rec.result)}'
	res := eval_step(mut env, '[?let [= $h [?worker-handle name="tw16"]] [?let [= $_ [?cancel worker=$h]] [?wait-for worker=$h]]]')
	rendered := render_canonical(res)
	assert rendered.contains(cancel_chain_outer), 'expected WORKER_CANCELLED chain, got: ${rendered}'
	assert rendered.contains(cancel_chain_cause), 'expected CANCELLED cause, got: ${rendered}'
	assert join_done(rec, 2000), 'worker body never exited its blocked [?receive] after [?cancel]'
	assert rec.cancelled
}

// §10.5.4: [?check-cancel] inside a worker body observes the worker's
// cancel request — a pure spin loop whose only exit is the cancel signal
// (the takewhile check-cancel predicate, or the [?for] iteration-boundary
// cancellation point) terminates promptly once [?cancel] lands, and
// [?wait-for] surfaces the WORKER_CANCELLED chain. (program-conc-020,
// de-raced: the loop cannot complete before cancel by construction.
// A recursive [?def] spin is not usable here — def bodies are purity-
// checked and [?check-cancel] is impure, CXER0233.)
fn test_check_cancel_observes_worker_cancel() {
	caps_set_all()
	mut env := new_env()
	eval_step(mut env, '[?worker name="tw20" [body [?for [in $i [$range 1 *]]
      [takewhile [?match [?check-cancel] [case [err @code="cx-err:CXER0260"] false] [else true]]]
      [yield $i]]]]')
	// Let the spin loop run hot for a while — pre-fix, [?check-cancel]
	// never observes worker cancellation, so the body can never exit.
	time.sleep(100 * time.millisecond)
	rec := worker_rec(mut env, 'tw20')
	assert !rec.done, 'spin worker must still be looping before [?cancel]; completed with: ${render_canonical(rec.result)}'
	res := eval_step(mut env, '[?let [= $h [?worker-handle name="tw20"]] [?let [= $_ [?cancel worker=$h]] [?wait-for worker=$h]]]')
	rendered := render_canonical(res)
	assert rendered.contains(cancel_chain_outer), 'expected WORKER_CANCELLED chain, got: ${rendered}'
	assert rendered.contains(cancel_chain_cause), 'expected CANCELLED cause, got: ${rendered}'
	assert join_done(rec, 2000), 'worker body never exited its [?check-cancel] spin loop after [?cancel]'
	assert rec.cancelled
}

// §10.5.4 request semantics stay intact: cancelling an ALREADY-COMPLETED
// worker is a no-op — its terminal value is not retroactively replaced.
// (program-conc-012 guard; also proves the fix does not overshoot.)
fn test_cancel_after_done_keeps_value() {
	caps_set_all()
	mut env := new_env()
	eval_step(mut env, '[?worker name="tw12" [body 42]]')
	rec := worker_rec(mut env, 'tw12')
	assert join_done(rec, 2000), 'trivial worker body must complete'
	res := eval_step(mut env, '[?let [= $h [?worker-handle name="tw12"]] [?let [= $_ [?cancel worker=$h]] [?wait-for worker=$h]]]')
	assert render_canonical(res) == '42'
}
