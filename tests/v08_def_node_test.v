module main

import cx

// Tests for the Phase 2.12 Part 1 DefNode AST.
//
// Covers construction + field access, structural equality with the
// source/loc exclusions, canonical disjoint-domain hashing, JSON
// projection, and disjoint-domain hash separation from PathNode,
// MatchNode, ModifyNode, PredicateExpr, and the text-hash pipeline.
//
// Out of scope at Phase 2.12 Part 1 (no evaluator, no binary codec,
// no Node sum-type integration):
//   - End-to-end evaluator semantics — Phases 2.13 + 2.16.
//   - ast_bin round-trip — wire-format slot allocation pending.
//
// Phase 2.23 extension: `:pure` / `:impure` modifier slot per
// amendment. Identity-relevant: same-body different-
// purity DefNodes are NOT equal and hash to disjoint values.

// ── Construction + field access ───────────────────────────────────────────────

fn test_def_node_construction_minimal() {
	params := [
		cx.new_def_param_positional('a', ?string(none)),
		cx.new_def_param_positional('b', ?string(none)),
	]
	n := cx.new_def_node('add', params, '[+ a b]')
	assert n.name == 'add'
	assert n.params.len == 2
	assert n.params[0].name == 'a'
	assert n.params[0].type_expr_source == none
	assert n.params[0].type_expr == none
	assert n.params[1].name == 'b'
	assert n.body == '[+ a b]'
	assert n.returns_type_source == none
	assert n.returns_type_expr == none
	assert n.scope == none
	assert n.source == none
	assert n.loc == none
}

fn test_def_param_positional_with_type() {
	p := cx.new_def_param_positional('msg', ?string('string'))
	assert p.name == 'msg'
	if t := p.type_expr_source {
		assert t == 'string'
	} else {
		assert false, 'type_expr_source should be set'
	}
	assert p.is_named == false
	assert p.is_rest == false
	assert p.default == none
}

fn test_def_param_named_with_default() {
	p := cx.new_def_param_named('greeting', ?string('string'), ?string('"hello"'))
	assert p.name == 'greeting'
	assert p.is_named == true
	assert p.is_rest == false
	if d := p.default {
		assert d == '"hello"'
	} else {
		assert false, 'default should be set'
	}
}

fn test_def_param_rest() {
	p := cx.new_def_param_rest('nums', ?string(none))
	assert p.name == 'nums'
	assert p.is_rest == true
	assert p.is_named == false
}

// ── Equality ──────────────────────────────────────────────────────────────────

fn make_def_simple() cx.DefNode {
	return cx.DefNode{
		name:   'add'
		params: [
			cx.new_def_param_positional('a', ?string(none)),
			cx.new_def_param_positional('b', ?string(none)),
		]
		body:   '[+ a b]'
	}
}

fn test_def_node_eq_same_shape() {
	a := make_def_simple()
	b := make_def_simple()
	assert a.eq(b)
	assert b.eq(a)
}

fn test_def_node_eq_ignores_source() {
	mut a := make_def_simple()
	mut b := make_def_simple()
	a.source = '[?def add (a b) [+ a b]]'
	b.source = '[?def add  (a b)  [+ a b]]'
	assert a.eq(b), 'source differences must not break equality'
}

fn test_def_node_eq_ignores_loc() {
	mut a := make_def_simple()
	mut b := make_def_simple()
	a.loc = cx.DefLoc{ start: 0, end: 30 }
	b.loc = cx.DefLoc{ start: 99, end: 200 }
	assert a.eq(b), 'loc differences must not break equality'
}

fn test_def_param_eq_ignores_loc() {
	mut a := cx.new_def_param_positional('a', ?string(none))
	mut b := cx.new_def_param_positional('a', ?string(none))
	a.loc = cx.DefLoc{ start: 0, end: 1 }
	b.loc = cx.DefLoc{ start: 50, end: 60 }
	assert a.eq(b)
}

fn test_def_node_eq_differs_on_name() {
	a := make_def_simple()
	mut b := make_def_simple()
	b.name = 'subtract'
	assert !a.eq(b)
}

fn test_def_node_eq_differs_on_param_count() {
	a := make_def_simple()
	mut b := make_def_simple()
	b.params = [b.params[0]]
	assert !a.eq(b)
}

fn test_def_node_eq_differs_on_param_name() {
	a := make_def_simple()
	mut b := make_def_simple()
	b.params[0].name = 'x'
	assert !a.eq(b)
}

fn test_def_node_eq_differs_on_param_type() {
	a := make_def_simple()
	mut b := make_def_simple()
	b.params[0].type_expr_source = ?string('int')
	assert !a.eq(b)
}

fn test_def_node_eq_differs_on_body() {
	a := make_def_simple()
	mut b := make_def_simple()
	b.body = '[- a b]'
	assert !a.eq(b)
}

fn test_def_node_eq_differs_on_returns_type() {
	mut a := make_def_simple()
	mut b := make_def_simple()
	a.returns_type_source = ?string('int')
	b.returns_type_source = ?string('float')
	assert !a.eq(b)
}

fn test_def_node_eq_differs_on_returns_presence() {
	mut a := make_def_simple()
	mut b := make_def_simple()
	a.returns_type_source = ?string('int')
	// b.returns_type_source stays none.
	assert !a.eq(b)
}

fn test_def_node_eq_differs_on_scope() {
	mut a := make_def_simple()
	mut b := make_def_simple()
	a.scope = ?string('public')
	b.scope = ?string('private')
	assert !a.eq(b)
}

fn test_def_node_eq_differs_on_param_kind() {
	a := cx.new_def_node('f', [cx.new_def_param_positional('x', ?string(none))], 'x')
	b := cx.new_def_node('f', [cx.new_def_param_named('x', ?string(none), ?string(none))],
		'x')
	assert !a.eq(b)
}

// ── Hashing ───────────────────────────────────────────────────────────────────

fn test_def_node_hash_equal_for_equal_nodes() {
	a := make_def_simple()
	b := make_def_simple()
	assert cx.def_node_hash(a) == cx.def_node_hash(b)
}

fn test_def_node_hash_ignores_source_and_loc() {
	mut a := make_def_simple()
	mut b := make_def_simple()
	a.source = 'aaa'
	b.source = 'bbb'
	a.loc = cx.DefLoc{ start: 0, end: 10 }
	b.loc = cx.DefLoc{ start: 99, end: 200 }
	assert cx.def_node_hash(a) == cx.def_node_hash(b)
}

fn test_def_node_hash_differs_on_structural_change() {
	a := make_def_simple()
	mut b := make_def_simple()
	b.body = '[- a b]'
	assert cx.def_node_hash(a) != cx.def_node_hash(b)
}

fn test_def_node_hash_differs_on_param_order() {
	a := cx.new_def_node('f', [
		cx.new_def_param_positional('a', ?string(none)),
		cx.new_def_param_positional('b', ?string(none)),
	], 'body')
	b := cx.new_def_node('f', [
		cx.new_def_param_positional('b', ?string(none)),
		cx.new_def_param_positional('a', ?string(none)),
	], 'body')
	assert cx.def_node_hash(a) != cx.def_node_hash(b)
}

fn test_def_node_hash_differs_on_returns_presence() {
	mut a := make_def_simple()
	mut b := make_def_simple()
	a.returns_type_source = ?string('int')
	assert cx.def_node_hash(a) != cx.def_node_hash(b)
}

fn test_def_node_hash_six_way_disjoint() {
	// DefNode whose payload happens to spell the same characters as
	// a PathNode / MatchNode / ModifyNode / PredicateExpr / element
	// surface MUST hash to a distinct value because each lives in
	// its own type-tag-prefixed domain.
	d := cx.new_def_node('x', [], 'y')
	dh := cx.def_node_hash(d)

	p := cx.PathNode{
		form:  cx.PathForm.relative
		steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'x' }]
	}
	ph := cx.path_node_hash(p)

	m := cx.new_match_node(?string(none), [cx.new_else_arm('y')])
	mh := cx.match_node_hash(m)

	mn := cx.new_modify_node('x', '/y', [cx.new_modify_action_delete()])
	mnh := cx.modify_node_hash(mn)

	pe := cx.new_predicate_expr(cx.PredicateExprKind.attr_test, 'y')
	peh := cx.predicate_expr_hash(pe)

	th := cx.cx_text_hash('[x]') or { panic(err) }

	// All six hashes must be pairwise distinct.
	assert dh != ph, 'DefNode hash must not collide with PathNode hash'
	assert dh != mh, 'DefNode hash must not collide with MatchNode hash'
	assert dh != mnh, 'DefNode hash must not collide with ModifyNode hash'
	assert dh != peh, 'DefNode hash must not collide with PredicateExpr hash'
	assert dh != th, 'DefNode hash must not collide with text hash'
	// Cross-check the others stay distinct from each other (sanity).
	assert ph != mh
	assert mh != mnh
	assert mnh != peh
	assert peh != th
}

// ── JSON projection ───────────────────────────────────────────────────────────

fn test_def_node_to_json_minimal() {
	n := cx.new_def_node('add', [
		cx.new_def_param_positional('a', ?string(none)),
		cx.new_def_param_positional('b', ?string(none)),
	], '[+ a b]')
	got := cx.def_node_to_json(n)
	want := '{"type":"ProgramDefExpr","name":"add","params":[{"name":"a"},{"name":"b"}],"body":"[+ a b]","purity":"pure"}'
	assert got == want, 'got: ${got}\nwant: ${want}'
}

fn test_def_node_to_json_with_typed_params_and_returns() {
	mut n := cx.new_def_node('greet', [
		cx.new_def_param_positional('name', ?string('string')),
	], '[+ "hello, " name]')
	n.returns_type_source = ?string('string')
	n.scope = ?string('public')
	got := cx.def_node_to_json(n)
	want := '{"type":"ProgramDefExpr","name":"greet","params":[{"name":"name","type":"string"}],"body":"[+ \\"hello, \\" name]","returns":"string","scope":"public","purity":"pure"}'
	assert got == want, 'got: ${got}\nwant: ${want}'
}

fn test_def_node_to_json_named_and_rest_params() {
	n := cx.new_def_node('http-get', [
		cx.new_def_param_positional('url', ?string('string')),
		cx.new_def_param_named('timeout', ?string(none), ?string('30')),
		cx.new_def_param_rest('extra-headers', ?string(none)),
	], '[request]')
	got := cx.def_node_to_json(n)
	want := '{"type":"ProgramDefExpr","name":"http-get","params":[{"name":"url","type":"string"},{"name":"timeout","named":true,"default":"30"},{"name":"extra-headers","rest":true}],"body":"[request]","purity":"pure"}'
	assert got == want, 'got: ${got}\nwant: ${want}'
}

// ── Purity (Phase 2.23) ────────────────────────────────────────

fn test_def_node_default_purity_is_pure() {
	n := make_def_simple()
	assert n.purity == cx.Purity.pure_
}

fn test_def_node_eq_differs_on_purity() {
	mut a := make_def_simple()
	mut b := make_def_simple()
	a.purity = cx.Purity.pure_
	b.purity = cx.Purity.impure_
	assert !a.eq(b), 'same-body different-purity DefNodes must NOT compare equal'
	assert !b.eq(a)
}

fn test_def_node_eq_same_purity_pure() {
	mut a := make_def_simple()
	mut b := make_def_simple()
	a.purity = cx.Purity.pure_
	b.purity = cx.Purity.pure_
	assert a.eq(b)
}

fn test_def_node_eq_same_purity_impure() {
	mut a := make_def_simple()
	mut b := make_def_simple()
	a.purity = cx.Purity.impure_
	b.purity = cx.Purity.impure_
	assert a.eq(b)
}

fn test_def_node_hash_differs_on_purity() {
	mut a := make_def_simple()
	mut b := make_def_simple()
	a.purity = cx.Purity.pure_
	b.purity = cx.Purity.impure_
	assert cx.def_node_hash(a) != cx.def_node_hash(b), 'purity must enter the canonical hash domain'
}

fn test_def_node_to_json_purity_default_pure() {
	n := cx.new_def_node('f', [], 'body')
	got := cx.def_node_to_json(n)
	assert got.contains('"purity":"pure"'), 'default purity must project as "pure"; got: ${got}'
}

fn test_def_node_to_json_purity_explicit_impure() {
	mut n := cx.new_def_node('now-iso', [], '[now]')
	n.purity = cx.Purity.impure_
	got := cx.def_node_to_json(n)
	assert got.contains('"purity":"impure"'), 'explicit impure must project as "impure"; got: ${got}'
}
