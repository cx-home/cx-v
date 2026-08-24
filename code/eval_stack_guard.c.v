module code

import cx

// eval_stack_guard.c.v — V-side wiring for the native-stack headroom guard
// (#319; mechanism in cx_stack_guard.c).
//
// Non-tail cx recursion has no trampoline (only tail calls do, #60): every
// level of `[+ 1 [f …]]`-shaped recursion is a real C-stack cycle through
// eval_node → eval_cx_element → dispatch → run_closure_body → eval_tail —
// ~63 KB/level on a dev (-O0) build, ~8 KB/level under -Os. Before the guard,
// ~120 levels overflowed the default 8 MB stack and SIGSEGV'd (#319). eval_node
// (the single funnel every evaluation shape passes through) now probes the
// remaining headroom and, under the margin, returns the catchable value-form
// err `cx-err:CXER0272 E_STACK_EXHAUSTED` (spec/core/code.md §9.4/§9.5 — the
// host-capability / runtime-environment range) instead of crashing. Value-form
// per §9.1 errors-are-values: it railway-propagates out and IS recoverable by
// [?fallback] / [?match] / [?with-error-hook] at any frame above.
//
// The margin must cover everything that can run below one probe before the
// next: the rest of the current level's chain (~63 KB dev), leaf builtin work
// (string ops, err construction), and the unwind itself (V result-path
// returns — no extra recursion). 1 MiB ≈ 16 dev-build levels of slack, so the
// probe fires while completion is still comfortably possible. Threads with
// tiny stacks (< 4 MiB, e.g. `ulimit -s 1024` runs) scale the margin down to
// size/4 so they keep proportional headroom instead of refusing every call.

#include "cx_stack_guard.c"

fn C.cx_stack_guard_remaining() usize
fn C.cx_stack_guard_stack_size() usize

// eval_stack_margin_bytes — headroom under which eval raises CXER0272.
const eval_stack_margin_bytes = usize(1024 * 1024)

const err_stack_exhausted = 'cx-err:CXER0272'

// eval_stack_low reports whether the current thread's remaining native stack
// is inside the guard margin. Armed lazily per thread (worker threads probe
// their own bounds); once armed the fast path is one TLS load + a compare.
// A thread whose bounds cannot be resolved reports usize max = never low
// (pre-#319 status quo, never a false positive).
@[inline]
fn eval_stack_low() bool {
	remaining := C.cx_stack_guard_remaining()
	if remaining >= eval_stack_margin_bytes {
		return false
	}
	// Inside the fixed margin — scale down for tiny stacks (< 4 MiB total):
	// proportional margin of size/4 keeps small-ulimit runs usable.
	total := C.cx_stack_guard_stack_size()
	if total != 0 && total < eval_stack_margin_bytes * 4 {
		return remaining < total / 4
	}
	return true
}

// mk_err_stack_exhausted builds the catchable E_STACK_EXHAUSTED err value.
// The message is deterministic (no addresses / sizes) so conformance fixtures
// can pin the full err shape.
fn mk_err_stack_exhausted() cx.Node {
	return mk_err(err_stack_exhausted, 'evaluation stack exhausted — non-tail recursion too deep for this thread stack; rewrite the hot recursion tail-recursively (trampolined), iterate with [?for]/[?reduce], or raise the stack limit')
}

// err_eval_budget builds the THROWN E_EVAL_BUDGET_EXCEEDED error (F4/S6.2,
// spec/core/code.md §9.4 — the 0270–0279 runtime-environment band, sibling
// of 0272). Deterministic message: the conjunct + the configured limit only.
// Thrown (EvalError), not an err value — a value-form refusal is collectable
// by the streamed iterator hot paths (measured); the thrown form
// short-circuits mechanically. Terminal in effect regardless of catching:
// the budget latches, so every further evaluation step re-refuses.
fn err_eval_budget(conjunct string, limit u64) EvalError {
	return EvalError{
		code:    'cx-err:CXER0273'
		message: 'evaluation budget exceeded: ${conjunct} limit ${limit} — the budgeted evaluation is over (every further step re-refuses); raise the operator limit or narrow the computation'
	}
}
