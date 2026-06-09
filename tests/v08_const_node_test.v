module main

import cx

// Tests for the Phase 2.12 Part 2 ConstNode AST.
//
// Covers construction + field access, structural equality with the
// source/loc exclusions, canonical disjoint-domain hashing, JSON
// projection, and disjoint-domain hash separation from PathNode,
// MatchNode, ModifyNode, PredicateExpr, DefNode, and the text-hash
// pipeline.
//
// Out of scope at Phase 2.12 Part 2 (no evaluator, no binary codec,
// no Node sum-type integration):
//   - Two-pass module-load semantics + CXER0214 cycle / CXER0215
//     body-failure — Phase 2.13.
//   - ast_bin round-trip — wire-format slot allocation pending.
//   - `:scope` visibility enforcement — Phase 2.15.

// ── Construction + field access ───────────────────────────────────────────────

fn test_const_node_construction_minimal() {
	n := cx.new_const_node('GREETING', '"hello"')
	assert n.name == 'GREETING'
	assert n.value_source == '"hello"'
	assert n.lazy == false
	assert n.scope == none
	assert n.source == none
	assert n.loc == none
}

fn test_const_node_construction_lazy() {
	n := cx.new_const_node_lazy('BIG-TABLE', '[load-big-table]')
	assert n.name == 'BIG-TABLE'
	assert n.value_source == '[load-big-table]'
	assert n.lazy == true
}

// ── Equality ──────────────────────────────────────────────────────────────────

fn make_const_simple() cx.ConstNode {
	return cx.ConstNode{
		name:         'A'
		value_source: '5'
	}
}

fn test_const_node_eq_same_shape() {
	a := make_const_simple()
	b := make_const_simple()
	assert a.eq(b)
	assert b.eq(a)
}

fn test_const_node_eq_ignores_source() {
	mut a := make_const_simple()
	mut b := make_const_simple()
	a.source = '[?const A 5]'
	b.source = '[?const A  5]'
	assert a.eq(b), 'source differences must not break equality'
}

fn test_const_node_eq_ignores_loc() {
	mut a := make_const_simple()
	mut b := make_const_simple()
	a.loc = cx.ConstLoc{ start: 0, end: 14 }
	b.loc = cx.ConstLoc{ start: 99, end: 200 }
	assert a.eq(b), 'loc differences must not break equality'
}

fn test_const_node_eq_differs_on_name() {
	a := make_const_simple()
	mut b := make_const_simple()
	b.name = 'B'
	assert !a.eq(b)
}

fn test_const_node_eq_differs_on_value() {
	a := make_const_simple()
	mut b := make_const_simple()
	b.value_source = '6'
	assert !a.eq(b)
}

fn test_const_node_eq_differs_on_lazy_flag() {
	a := make_const_simple()
	mut b := make_const_simple()
	b.lazy = true
	assert !a.eq(b)
}

fn test_const_node_eq_differs_on_scope() {
	mut a := make_const_simple()
	mut b := make_const_simple()
	a.scope = ?string('public')
	b.scope = ?string('private')
	assert !a.eq(b)
}

fn test_const_node_eq_differs_on_scope_presence() {
	mut a := make_const_simple()
	b := make_const_simple()
	a.scope = ?string('public')
	// b.scope stays none.
	assert !a.eq(b)
}

// ── Hashing ───────────────────────────────────────────────────────────────────

fn test_const_node_hash_equal_for_equal_nodes() {
	a := make_const_simple()
	b := make_const_simple()
	assert cx.const_node_hash(a) == cx.const_node_hash(b)
}

fn test_const_node_hash_ignores_source_and_loc() {
	mut a := make_const_simple()
	mut b := make_const_simple()
	a.source = 'aaa'
	b.source = 'bbb'
	a.loc = cx.ConstLoc{ start: 0, end: 10 }
	b.loc = cx.ConstLoc{ start: 99, end: 200 }
	assert cx.const_node_hash(a) == cx.const_node_hash(b)
}

fn test_const_node_hash_differs_on_value() {
	a := make_const_simple()
	mut b := make_const_simple()
	b.value_source = '6'
	assert cx.const_node_hash(a) != cx.const_node_hash(b)
}

fn test_const_node_hash_differs_on_lazy_flag() {
	a := make_const_simple()
	mut b := make_const_simple()
	b.lazy = true
	assert cx.const_node_hash(a) != cx.const_node_hash(b)
}

fn test_const_node_hash_differs_on_scope() {
	mut a := make_const_simple()
	mut b := make_const_simple()
	a.scope = ?string('public')
	b.scope = ?string('private')
	assert cx.const_node_hash(a) != cx.const_node_hash(b)
}

// Eight-way disjoint hash assertion: ConstNode vs PathNode, MatchNode,
// ModifyNode, PredicateExpr, DefNode, text-hash, plus
// Const-vs-Const-with-different-name AND
// Const-vs-Const-with-same-content (round-trip eq).
fn test_const_node_hash_eight_way_disjoint() {
	// ConstNode whose payload happens to spell the same characters as
	// a PathNode / MatchNode / ModifyNode / PredicateExpr / DefNode /
	// element surface MUST hash to a distinct value because each
	// lives in its own type-tag-prefixed domain.
	c := cx.new_const_node('x', 'y')
	ch := cx.const_node_hash(c)

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

	d := cx.new_def_node('x', [], 'y')
	dh := cx.def_node_hash(d)

	th := cx.cx_text_hash('[x]') or { panic(err) }

	// (7) Same-name-same-content ConstNode hashes identically (eq round-trip).
	c_same := cx.new_const_node('x', 'y')
	csh := cx.const_node_hash(c_same)
	assert ch == csh, 'same-shape ConstNodes must hash identically'

	// (8) Different-name ConstNode hashes differently (sanity).
	c_diff := cx.new_const_node('z', 'y')
	cdh := cx.const_node_hash(c_diff)
	assert ch != cdh, 'different-name ConstNodes must hash differently'

	// All six external-domain hashes must be distinct from ConstNode.
	assert ch != ph, 'ConstNode hash must not collide with PathNode hash'
	assert ch != mh, 'ConstNode hash must not collide with MatchNode hash'
	assert ch != mnh, 'ConstNode hash must not collide with ModifyNode hash'
	assert ch != peh, 'ConstNode hash must not collide with PredicateExpr hash'
	assert ch != dh, 'ConstNode hash must not collide with DefNode hash'
	assert ch != th, 'ConstNode hash must not collide with text hash'
	// Cross-check the others stay distinct from each other (sanity).
	assert ph != mh
	assert mh != mnh
	assert mnh != peh
	assert peh != dh
	assert dh != th
}

// ── JSON projection ───────────────────────────────────────────────────────────

fn test_const_node_to_json_minimal() {
	n := cx.new_const_node('A', '5')
	got := cx.const_node_to_json(n)
	want := '{"type":"ProgramConstExpr","name":"A","value":"5"}'
	assert got == want, 'got: ${got}\nwant: ${want}'
}

fn test_const_node_to_json_with_lazy() {
	n := cx.new_const_node_lazy('BIG-TABLE', '[load-big-table]')
	got := cx.const_node_to_json(n)
	want := '{"type":"ProgramConstExpr","name":"BIG-TABLE","value":"[load-big-table]","lazy":true}'
	assert got == want, 'got: ${got}\nwant: ${want}'
}

fn test_const_node_to_json_with_scope_public_and_lazy() {
	mut n := cx.new_const_node('PUBLIC-VERSION', '"1.0"')
	n.scope = ?string('public')
	n.lazy = true
	got := cx.const_node_to_json(n)
	want := '{"type":"ProgramConstExpr","name":"PUBLIC-VERSION","value":"\\"1.0\\"","lazy":true,"scope":"public"}'
	assert got == want, 'got: ${got}\nwant: ${want}'
}

fn test_const_node_to_json_with_quoted_string_value_escaped() {
	n := cx.new_const_node('GREETING', '"hello"')
	got := cx.const_node_to_json(n)
	want := '{"type":"ProgramConstExpr","name":"GREETING","value":"\\"hello\\""}'
	assert got == want, 'got: ${got}\nwant: ${want}'
}
