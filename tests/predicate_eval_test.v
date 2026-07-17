module main

import cx
import code

// Tests for Phase 2.21-standalone — eval_predicate_filter, eager-iteration
// PredicateExpr evaluator.
//
// Coverage map (each §D3/§D4/§D5/§D7 contract gets at
// least one direct test):
//
//   - attr_test predicate filters candidates with the attr.
//   - attr_compare predicate (all 6 prefix ops `[OP $_@name V]`) filters
//     correctly; missing attribute → ABSENCE → comparison false (all ops,
//     including `!=`) — never an error.
//   - int_position predicate keeps only the Nth candidate.
//   - `$_position` reference inside predicate works.
//   - `$_last` reference works.
//   - bool_expr connectives `[and …]` / `[or …]` / `[not …]` evaluate
//     (EBV fold over children).
//   - `:bind NAME` from PredicateEvalContext is visible inside the predicate
//     (cross-step reference via reserved_binding-shaped AST).
//   - Empty candidate sequence → empty result, no error.
//   - Single-candidate sequence with passing predicate → [single].
//   - 3-candidate mixed pass/fail → expected filtered subset.
//   - EBV coercion: each table row gives the documented result.
//   - function_call count AST (hand-built — the paren-call SURFACE is
//     retired per #110) filters by children_count.
//   - Generic / unsupported predicate → MATCH_PREDICATE_EVAL_NOT_YET_IMPLEMENTED.

// ── helpers ─────────────────────────────────────────────────────────────────

fn elem(name string, attrs map[string]string) code.Item {
	return code.Item{
		kind:  'element'
		name:  name
		attrs: attrs.clone()
	}
}

fn elem_with_count(name string, attrs map[string]string, children int) code.Item {
	return code.Item{
		kind:           'element'
		name:           name
		attrs:          attrs.clone()
		children_count: children
	}
}

fn empty_ctx() code.PredicateEvalContext {
	return code.PredicateEvalContext{
		bindings: map[string]code.Value{}
	}
}

// ── attr_test ────────────────────────────────────────────────────────────────

fn test_attr_test_filters_present_attr() {
	candidates := [
		elem('user', {'active': 'true'}),
		elem('user', {}),
		elem('user', {'active': 'false'}),
	]
	pred := cx.predicate_expr_parse('@active') or {
		assert false, 'parse failed: ${err}'
		return
	}
	out := code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert false, 'filter failed: ${err}'
		return
	}
	assert out.len == 2
	// Attribute existence — value irrelevant.
	assert 'active' in out[0].attrs
	assert 'active' in out[1].attrs
}

fn test_attr_test_empty_input_empty_output() {
	candidates := []code.Item{}
	pred := cx.predicate_expr_parse('@x') or {
		assert false
		return
	}
	out := code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert false, '${err}'
		return
	}
	assert out.len == 0
}

fn test_attr_test_single_candidate_pass() {
	candidates := [elem('user', {'role': 'admin'})]
	pred := cx.predicate_expr_parse('@role') or {
		assert false
		return
	}
	out := code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert false, '${err}'
		return
	}
	assert out.len == 1
}

// ── attr_compare — all 6 ops ─────────────────────────────────────────────────

fn test_attr_compare_eq_string() {
	candidates := [
		elem('user', {'role': 'admin'}),
		elem('user', {'role': 'guest'}),
		elem('user', {'role': 'admin'}),
	]
	pred := cx.predicate_expr_parse('= \$_@role "admin"') or {
		assert false, '${err}'
		return
	}
	out := code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert false, '${err}'
		return
	}
	assert out.len == 2
}

fn test_attr_compare_neq_string() {
	candidates := [
		elem('u', {'r': 'a'}),
		elem('u', {'r': 'b'}),
	]
	pred := cx.predicate_expr_parse('!= \$_@r "a"') or {
		assert false
		return
	}
	out := code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert false
		return
	}
	assert out.len == 1
	assert out[0].attrs['r'] == 'b'
}

fn test_attr_compare_lt_int() {
	candidates := [
		elem('u', {'age': '21'}),
		elem('u', {'age': '17'}),
		elem('u', {'age': '30'}),
	]
	pred := cx.predicate_expr_parse('< \$_@age 18') or {
		assert false, '${err}'
		return
	}
	out := code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert false
		return
	}
	assert out.len == 1
	assert out[0].attrs['age'] == '17'
}

fn test_attr_compare_lte_int() {
	candidates := [
		elem('u', {'n': '1'}),
		elem('u', {'n': '2'}),
		elem('u', {'n': '3'}),
	]
	pred := cx.predicate_expr_parse('<= \$_@n 2') or {
		assert false
		return
	}
	out := code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert false
		return
	}
	assert out.len == 2
}

fn test_attr_compare_gt_int() {
	candidates := [
		elem('u', {'n': '1'}),
		elem('u', {'n': '5'}),
		elem('u', {'n': '10'}),
	]
	pred := cx.predicate_expr_parse('> \$_@n 4') or {
		assert false
		return
	}
	out := code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert false
		return
	}
	assert out.len == 2
}

fn test_attr_compare_gte_int() {
	candidates := [
		elem('u', {'n': '1'}),
		elem('u', {'n': '5'}),
		elem('u', {'n': '10'}),
	]
	pred := cx.predicate_expr_parse('>= \$_@n 5') or {
		assert false
		return
	}
	out := code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert false
		return
	}
	assert out.len == 2
}

fn test_attr_compare_absent_attr_is_false() {
	// An item missing the attribute being compared MUST fail the
	// predicate (per attr_compare contract): a missing-attribute read
	// yields ABSENCE (empty sequence), and comparisons with absence are
	// false — never an error (§9.2).
	candidates := [
		elem('u', {'r': 'a'}),
		elem('u', {}),
	]
	pred := cx.predicate_expr_parse('= \$_@r "a"') or {
		assert false
		return
	}
	out := code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert false
		return
	}
	assert out.len == 1
}

fn test_attr_compare_absent_attr_neq_also_false() {
	// Comparisons with absence are false for ALL ops, INCLUDING `!=` —
	// `[!= $_@missing 1]` filters everything out; it does not pass items
	// lacking the attribute.
	candidates := [
		elem('u', {}),
		elem('u', {}),
	]
	pred := cx.predicate_expr_parse('!= \$_@missing 1') or {
		assert false, '${err}'
		return
	}
	out := code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert false, 'absence comparison must not error: ${err}'
		return
	}
	assert out.len == 0
}

fn test_attr_compare_all_absent_filters_out_without_error() {
	// `[= $_@missing 1]` over a sequence where NO item carries the
	// attribute → empty result, no error.
	candidates := [
		elem('u', {'other': 'x'}),
		elem('u', {}),
	]
	pred := cx.predicate_expr_parse('= \$_@missing 1') or {
		assert false, '${err}'
		return
	}
	out := code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert false, 'absence comparison must not error: ${err}'
		return
	}
	assert out.len == 0
}

// ── int_position ─────────────────────────────────────────────────────────────

fn test_int_position_keeps_only_nth() {
	candidates := [
		elem('u', {}),
		elem('u', {'mark': 'second'}),
		elem('u', {}),
	]
	pred := cx.predicate_expr_parse('2') or {
		assert false
		return
	}
	out := code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert false
		return
	}
	assert out.len == 1
	assert out[0].attrs['mark'] == 'second'
}

fn test_int_position_first_is_one_based() {
	candidates := [
		elem('u', {'mark': 'first'}),
		elem('u', {'mark': 'second'}),
	]
	pred := cx.predicate_expr_parse('1') or {
		assert false
		return
	}
	out := code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert false
		return
	}
	assert out.len == 1
	assert out[0].attrs['mark'] == 'first'
}

fn test_int_position_out_of_range_returns_empty() {
	candidates := [elem('u', {}), elem('u', {})]
	pred := cx.predicate_expr_parse('5') or {
		assert false
		return
	}
	out := code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert false
		return
	}
	assert out.len == 0
}

// ── $_position / $_last ──────────────────────────────────────────────────────

fn test_dollar_position_bare_truthy_after_first() {
	// Bare `$_position` → returns the position int → EBV true iff non-zero.
	// position is 1-based so all positions ≥ 1 are truthy ⇒ all pass.
	candidates := [
		elem('u', {}),
		elem('u', {}),
		elem('u', {}),
	]
	pred := cx.predicate_expr_parse('\$_position') or {
		assert false, '${err}'
		return
	}
	out := code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert false
		return
	}
	assert out.len == 3
}

fn test_dollar_last_bare_returns_count_truthy() {
	// `$_last` on a non-empty sequence is ≥ 1 → all pass.
	candidates := [elem('u', {}), elem('u', {})]
	pred := cx.predicate_expr_parse('\$_last') or {
		assert false, '${err}'
		return
	}
	out := code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert false
		return
	}
	assert out.len == 2
}

// ── :bind NAME visibility (cross-step reference) ─────────────────────────────

fn test_bind_name_visible_in_predicate_via_eval_context() {
	// Simulate `//team :bind t / member[$t]` where the path walker
	// (Phase 2.6 / Phase 2.20) has captured the outer team value and
	// passed it in via PredicateEvalContext.bindings.
	//
	// At Phase 2.21-standalone we construct the reserved_binding
	// PredicateExpr directly — the Phase 2.19 parser doesn't admit
	// `$NAME` as a top-level atomic body (only `$_*`), so this test
	// is the closest standalone equivalent to a future cross-step
	// reference once the path walker is wired up.
	candidates := [elem('member', {}), elem('member', {})]
	pred := &cx.PredicateExpr{
		kind:   .reserved_binding
		name:   '\$t'
		source: '\$t'
	}
	mut ctx := empty_ctx()
	ctx.bindings['t'] = code.value_bool(true)
	out := code.eval_predicate_filter(candidates, pred, ctx) or {
		assert false, '${err}'
		return
	}
	assert out.len == 2
}

fn test_bind_name_falsy_filters_all() {
	candidates := [elem('member', {}), elem('member', {})]
	pred := &cx.PredicateExpr{
		kind:   .reserved_binding
		name:   '\$t'
		source: '\$t'
	}
	mut ctx := empty_ctx()
	ctx.bindings['t'] = code.value_bool(false)
	out := code.eval_predicate_filter(candidates, pred, ctx) or {
		assert false, '${err}'
		return
	}
	assert out.len == 0
}

fn test_bind_name_missing_in_scope_raises_error() {
	candidates := [elem('member', {})]
	pred := &cx.PredicateExpr{
		kind:   .reserved_binding
		name:   '\$missing'
		source: '\$missing'
	}
	code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		// Expected — `$missing` is not in the supplied PredicateEvalContext.
		assert err.msg().contains('PREDICATE_EVAL')
		return
	}
	assert false, 'expected error for missing binding'
}

fn test_reserved_underscore_name_in_eval_context_rejected() {
	// Per gate 36.7, the bare identifier `_` is reserved
	// for `$_`; supplying it via PredicateEvalContext.bindings is a programmer
	// error and is rejected at scope-build time.
	candidates := [elem('u', {})]
	pred := &cx.PredicateExpr{
		kind:   .reserved_binding
		name:   '\$_'
		source: '\$_'
	}
	mut ctx := empty_ctx()
	ctx.bindings['_'] = code.value_bool(true)
	code.eval_predicate_filter(candidates, pred, ctx) or {
		assert err.msg().contains('reserved')
		return
	}
	assert false, 'expected scope-build to reject reserved `_` binding'
}

// ── bool_expr connectives (prefix `and` / `or` / `not`) ──────────────────────

fn test_bool_expr_and_filters_intersection() {
	candidates := [
		elem('u', {'a': '1', 'b': '2'}),
		elem('u', {'a': '1'}),
		elem('u', {'b': '2'}),
	]
	pred := cx.predicate_expr_parse('and [@a] [@b]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	out := code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert false, '${err}'
		return
	}
	assert out.len == 1
	assert 'a' in out[0].attrs
	assert 'b' in out[0].attrs
}

fn test_bool_expr_or_with_compares_filters_union() {
	candidates := [
		elem('u', {'a': '1'}),
		elem('u', {'b': '3'}),
		elem('u', {'c': '9'}),
	]
	pred := cx.predicate_expr_parse('or [= \$_@a 1] [> \$_@b 2]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	out := code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert false, '${err}'
		return
	}
	assert out.len == 2
}

fn test_bool_expr_not_inverts() {
	candidates := [
		elem('u', {'deleted': 'true'}),
		elem('u', {}),
	]
	pred := cx.predicate_expr_parse('not [@deleted]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	out := code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert false, '${err}'
		return
	}
	assert out.len == 1
	assert 'deleted' !in out[0].attrs
}

fn test_bool_expr_and_absence_operand_is_false_not_error() {
	// A comparison over a missing attribute inside a connective is just
	// false — the whole `and` folds to false, no error.
	candidates := [elem('u', {'a': '1'})]
	pred := cx.predicate_expr_parse('and [= \$_@a 1] [= \$_@missing 1]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	out := code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert false, 'absence inside connective must not error: ${err}'
		return
	}
	assert out.len == 0
}

// ── count function_call AST (hand-built) ─────────────────────────────────────
//
// The paren-call SURFACE `count(*)` is RETIRED (#110) — predicate_expr_parse
// hard-errors on it (see predicate_expr_test.v). The evaluator's
// function_call arm still services hand-built ASTs; keep its behavior
// pinned here.

fn test_count_paren_surface_retired() {
	_ := cx.predicate_expr_parse('count(*) > 1') or {
		assert err.msg().contains('retired'), 'expected retired-surface message, got: ${err.msg()}'
		return
	}
	assert false, 'paren-call count(*) should be a hard parse error'
}

fn test_count_compare_filters_by_arity() {
	candidates := [
		elem_with_count('group', {}, 0),
		elem_with_count('group', {}, 2),
		elem_with_count('group', {}, 5),
	]
	pred := &cx.PredicateExpr{
		kind:     .function_call
		name:     'count'
		value:    '*'
		op:       '>'
		position: 1
		source:   'count(*) > 1'
	}
	out := code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert false, '${err}'
		return
	}
	assert out.len == 2
}

fn test_count_bare_truthy_iff_nonzero() {
	// Bare count → returns the int → EBV true iff non-zero.
	candidates := [
		elem_with_count('group', {}, 0),
		elem_with_count('group', {}, 1),
		elem_with_count('group', {}, 3),
	]
	pred := &cx.PredicateExpr{
		kind:   .function_call
		name:   'count'
		value:  '*'
		source: 'count(*)'
	}
	out := code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert false
		return
	}
	assert out.len == 2
}

// ── EBV coercion table — direct unit tests ───────────────────────────────────

fn test_ebv_bool_identity() {
	assert (code.ebv(code.value_bool(true)) or { false }) == true
	assert (code.ebv(code.value_bool(false)) or { true }) == false
}

fn test_ebv_int_nonzero() {
	assert (code.ebv(code.value_int(0)) or { true }) == false
	assert (code.ebv(code.value_int(1)) or { false }) == true
	assert (code.ebv(code.value_int(-5)) or { false }) == true
}

fn test_ebv_string_non_empty() {
	assert (code.ebv(code.value_string('')) or { true }) == false
	assert (code.ebv(code.value_string('x')) or { false }) == true
}

fn test_ebv_null_false() {
	assert (code.ebv(code.value_null()) or { true }) == false
}

fn test_ebv_item_truthy() {
	it := code.Item{ kind: 'element', name: 'x' }
	assert (code.ebv(code.value_item(&it)) or { false }) == true
}

fn test_ebv_empty_sequence_false() {
	assert (code.ebv(code.value_seq([])) or { true }) == false
}

fn test_ebv_singleton_sequence_recurses() {
	// [false] → false (per cxdm §4.6 rule 2 via rule 7)
	assert (code.ebv(code.value_seq([code.value_bool(false)])) or { true }) == false
	// [42] → true (int 42 truthy)
	assert (code.ebv(code.value_seq([code.value_int(42)])) or { false }) == true
}

fn test_ebv_multi_element_sequence_true() {
	// Length > 1 → always true.
	assert (code.ebv(code.value_seq([code.value_bool(false), code.value_bool(false)])) or { false }) == true
}

// ── Generic / unsupported predicate ──────────────────────────────────────────

fn test_generic_predicate_returns_not_yet_implemented_error() {
	// A `generic`-kind PredicateExpr is never produced by the parser;
	// we synthesize one directly to confirm the evaluator surfaces the
	// MATCH_PREDICATE_EVAL_NOT_YET_IMPLEMENTED error gracefully.
	// (bool_expr now EVALUATES — see the connective tests above.)
	candidates := [elem('u', {})]
	pred := &cx.PredicateExpr{
		kind:   .generic
		source: 'instance of thing'
	}
	code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert err.msg().contains('MATCH_PREDICATE_EVAL_NOT_YET_IMPLEMENTED')
		return
	}
	assert false, 'expected NOT_YET_IMPLEMENTED error on generic kind'
}

fn test_unsupported_function_call_returns_not_yet_implemented() {
	// A function_call AST referencing a function other than `count`
	// is rejected at evaluation time. The Phase 2.19 parser only
	// produces `count(*)`-shaped function_calls so we build this
	// manually.
	candidates := [elem_with_count('u', {}, 3)]
	pred := &cx.PredicateExpr{
		kind:   .function_call
		name:   'sum'
		value:  '*'
		source: 'sum(*)'
	}
	code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert err.msg().contains('MATCH_PREDICATE_EVAL_NOT_YET_IMPLEMENTED')
		return
	}
	assert false, 'expected NOT_YET_IMPLEMENTED error on non-count function'
}

// ── 3-candidate mixed pass/fail (overall shape sanity) ──────────────────────

fn test_three_candidate_mixed_pass_fail_preserves_order() {
	candidates := [
		elem('u', {'a': '1'}),     // pass
		elem('u', {}),             // fail (no @a)
		elem('u', {'a': '2'}),     // pass
	]
	pred := cx.predicate_expr_parse('@a') or {
		assert false
		return
	}
	out := code.eval_predicate_filter(candidates, pred, empty_ctx()) or {
		assert false
		return
	}
	assert out.len == 2
	assert out[0].attrs['a'] == '1'
	assert out[1].attrs['a'] == '2'
}
