module main

import cx

// ── EvaluatorHook signature tests (EE7, ADR 0023 §D11) ────────────────
//
// EE7 reserves the hook interface for v0.8.0+ debug adapters and log
// subscribers. v0.7.0 ships the signature and a no-op default
// implementation only; no external registration mechanism. These
// tests validate that the data-payload shape (HookFrame /
// EvalOrigin) is callable from outside the cx package and that
// NoOpEvaluatorHook satisfies the EvaluatorHook interface contract.
// Method-dispatch tests on a real CXLEnv live alongside FF1/DD11
// wiring rows (CXLEnv is package-private at v0.7.0).

fn test_hook_frame_zero_value_is_safe() {
	frame := cx.HookFrame{}
	assert frame.fn_name == ''
	assert frame.arity == 0
	assert frame.args.len == 0
	assert frame.source_line == 0
	assert frame.source_col == 0
	assert frame.eval_depth == 0
	if _ := frame.eval_origin {
		assert false, 'zero-value HookFrame must have none for eval_origin'
	}
}

fn test_hook_frame_populated() {
	frame := cx.HookFrame{
		fn_name:     'cx:parse'
		arity:       1
		source_line: 5
		source_col:  12
		eval_depth:  0
	}
	assert frame.fn_name == 'cx:parse'
	assert frame.arity == 1
	assert frame.source_line == 5
	assert frame.source_col == 12
}

fn test_hook_frame_with_eval_origin() {
	frame := cx.HookFrame{
		fn_name:     'cx:eval'
		eval_depth:  1
		eval_origin: cx.EvalOrigin{
			uri:        'file:///x.cx'
			line:       10
			column:     4
			eval_depth: 1
		}
	}
	origin := frame.eval_origin or { panic('eval_origin must be present') }
	assert origin.uri == 'file:///x.cx'
	assert origin.line == 10
	assert origin.column == 4
	assert origin.eval_depth == 1
}

fn test_eval_origin_zero_value() {
	origin := cx.EvalOrigin{}
	assert origin.uri == ''
	assert origin.line == 0
	assert origin.column == 0
	assert origin.eval_depth == 0
}

fn test_eval_origin_populated() {
	origin := cx.EvalOrigin{
		uri:        'file:///path/to/source.cx'
		line:       1
		column:     1
		eval_depth: 2
	}
	assert origin.uri == 'file:///path/to/source.cx'
	assert origin.line == 1
	assert origin.column == 1
	assert origin.eval_depth == 2
}

fn test_noop_hook_satisfies_evaluator_hook_interface() {
	// The cast forces V's interface-conformance check at compile time:
	// if NoOpEvaluatorHook's four methods do not match EvaluatorHook
	// byte-for-byte (receiver mutability, argument types, argument
	// count), the cast fails to compile. Reaching this runtime point
	// proves the interface contract is satisfied. v0.7.0's hook
	// signature is thus locked.
	_ := cx.EvaluatorHook(cx.new_noop_hook())
	assert true
}

fn test_new_noop_hook_returns_concrete_type() {
	hook := cx.new_noop_hook()
	_ = hook  // discard unused-var diagnostic; constructor smoke test
	assert true
}
