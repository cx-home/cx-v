module main
import cx

import code

// byte-adjacent binding postfix (predicate vs separate arg).
//
// A `[…]` touching a binding/path is a predicate/slice on it; a
// space-separated `[…]` is a separate operand. This is what lets a call
// arg list `[$f $x [g]]` mean "two args" instead of "filter $x by g"
// (the greedy-predicate hazard that broke stdlib hash-031). See
// `lbrack_adjacent_to_prev` in vcx/code/parser.v.

fn parse_ok(src string) cx.Program {
	return cx.parse_program(src) or { panic('parse failed: ${src} — ${err}') }
}

fn test_qualified_call_arg_binding_then_bracket_is_two_args() {
	// `[hash/equals $p@digest [hash/sha384 "hi"]]` — the spaced `[…]` is the
	// SECOND argument, not a predicate on `$p@digest`.
	body := parse_ok('[hash/equals $p@digest [hash/sha384 "hi"]]').body
	if body is cx.ProgramCall {
		assert body.name == 'hash/equals'
		assert body.args.len == 2, 'expected 2 args, got ${body.args.len}'
		a0 := body.args[0]
		if a0 is cx.ProgramBinding {
			assert a0.name == 'p'
			assert a0.path.len == 1
			assert a0.path[0].predicates.len == 0, 'arg0 must not carry a predicate'
		} else {
			assert false, 'arg0 should be a ProgramBinding'
		}
		assert body.args[1] is cx.ProgramCall, 'arg1 should be the [hash/sha384 …] call'
	} else {
		assert false, 'expected ProgramCall'
	}
}

fn test_dollar_call_arg_binding_then_bracket_is_two_args() {
	// Common lambda-call shape `[$myfn $x [g]]` — `[g]` is the second arg.
	body := parse_ok('[$myfn $x [g]]').body
	if body is cx.ProgramCall {
		assert body.name == 'myfn'
		assert body.args.len == 2, 'expected 2 args, got ${body.args.len}'
	} else {
		assert false, 'expected ProgramCall'
	}
}

fn test_adjacent_bracket_stays_predicate() {
	// No space: `$x/item[1]` keeps the `[1]` as a position predicate.
	body := parse_ok('$x/item[1]').body
	if body is cx.ProgramBinding {
		assert body.path.len == 1
		assert body.path[0].name == 'item'
		assert body.path[0].predicates.len == 1, 'adjacent [1] must be a predicate'
	} else {
		assert false, 'expected ProgramBinding'
	}
}

fn test_adjacent_slice_stays_slice() {
	// No space: `$xs[2:5]` stays a slice access on `$xs`.
	body := parse_ok('$xs[2:5]').body
	assert body is cx.ProgramSliceAccess, 'adjacent [2:5] must be a slice access'
}

// ── byte-adjacent path-step harvest (call head vs path) ────────────
//
// Path-step tokens (/, //, @, .) bind to a $binding only when byte-adjacent.
// A spaced step token is a separate operand — so `[$count //*]` parses as a
// call to $count on the `//*` arg, not as the head `$count//*` (which the
// parser rejects as "call head may not carry path steps").

fn test_spaced_pathexpr_is_call_arg_not_head_path() {
	body := parse_ok('[$count //*]').body
	if body is cx.ProgramCall {
		assert body.name == 'count'
		assert body.args.len == 1, 'expected 1 arg (//*), got ${body.args.len}'
		assert body.args[0] is cx.ProgramPathExpr, 'arg should be a //* PathExpr'
	} else {
		assert false, 'expected ProgramCall'
	}
}

fn test_adjacent_path_stays_path() {
	// No space: `$doc/user/name` keeps all three child steps on the binding.
	body := parse_ok('$doc/user/name').body
	if body is cx.ProgramBinding {
		assert body.name == 'doc'
		assert body.path.len == 2, 'expected 2 path steps, got ${body.path.len}'
	} else {
		assert false, 'expected ProgramBinding'
	}
}

// ── qualified-name colon (prefix:local) is not a slice marker ──────
//
// A CXPath nodetest with a namespace prefix (`//svg:circle`) as a call arg
// must not misroute the bracket to slice-literal parsing on its `:`.

fn test_prefixed_nodetest_call_arg_not_slice() {
	body := parse_ok('[$local-name //svg:circle]').body
	if body is cx.ProgramCall {
		assert body.name == 'local-name'
		assert body.args.len == 1, 'expected 1 arg, got ${body.args.len}'
		assert body.args[0] is cx.ProgramPathExpr, 'arg should be a //svg:circle PathExpr'
	} else {
		assert false, 'expected ProgramCall'
	}
}

fn test_slice_literal_still_detected() {
	// The qualified-colon skip must not break real slice literals.
	assert parse_ok('[2:5]').body is cx.ProgramSliceLiteral, '[2:5] must stay a slice literal'
}

// ── [?let] clause-child eval (gap-a fix) ───────────────────────────
//
// `[?let [= $x V] BODY]` must (1) put $x in scope for BODY of any shape — a
// space-separated sequence value like `(1, 2, 3)` must not be eaten as a
// `$x(...)` paren-call (byte-adjacency for `$name(`); and (2) treat the LAST
// positional as the body even when shape-identical to a `[= …]` binding (an
// equality expression).

fn evlet(src string) string {
	prog := cx.parse_program(src) or { return 'PARSE_ERR' }
	mut env := code.new_env()
	r := code.eval(prog.body, mut env) or { return 'EVAL_ERR ' + err.msg() }
	return code.render_node_pub(r)
}

fn test_let_clause_seq_value_binds() {
	// Bug 2: `$xs (1,2,3)` must NOT parse as `$xs(1,2,3)` paren-call.
	assert evlet('[?let [= $xs (1, 2, 3)] $xs]') == '(1, 2, 3)'
}

fn test_let_clause_seq_slice_body() {
	assert evlet('[?let [= $xs (10, 20, 30, 40, 50)] $xs[2:5]]') == '(20, 30, 40, 50)'
}

fn test_let_clause_equality_body() {
	// Bug 1: body `[= $a 5]` is equality, not another binding.
	assert evlet('[?let [= $a 5] [= $a 5]]') == 'true'
	assert evlet('[?let [= $a 5] [= $a 6]]') == 'false'
}

fn test_let_clause_multi_binding() {
	assert evlet('[?let [= $a 1] [= $b 2] [+ $a $b]]') == '3'
}
