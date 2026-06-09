module main

import cx

// Tests for the Phase 2.4 MatchNode AST.
//
// Covers construction + field access, structural equality with the
// source/loc exclusions, canonical disjoint-domain hashing, JSON
// projection, and disjoint-domain hash separation from PathNode and
// the text-hash pipeline.
//
// Out of scope at Phase 2.4 (no evaluator, no binary codec, no Node
// sum-type integration):
//   - End-to-end evaluator semantics — Phase 2.7.
//   - ast_bin round-trip — wire-format slot allocation pending.

// ── Construction + field access ───────────────────────────────────────────────

fn test_match_node_construction_with_scrutinee() {
	arms := [
		cx.new_case_arm('200', ':ok'),
		cx.new_case_arm('404', ':not-found'),
		cx.new_else_arm(':err'),
	]
	n := cx.new_match_node(?string('\$s'), arms)
	if s := n.scrutinee {
		assert s == '\$s'
	} else {
		assert false, 'scrutinee should be present'
	}
	assert n.arms.len == 3
	assert n.arms[0].kind == cx.ArmKind.case_arm
	assert n.arms[0].pattern == '200'
	assert n.arms[0].body == ':ok'
	assert n.arms[2].kind == cx.ArmKind.else_arm
	assert n.arms[2].body == ':err'
	assert n.source == none
	assert n.loc == none
}

fn test_match_node_construction_predicate_only() {
	arms := [
		cx.new_when_arm('(\$x > 100)', ':big'),
		cx.new_when_arm('(\$x > 50)', ':medium'),
		cx.new_else_arm(':small'),
	]
	n := cx.new_match_node(?string(none), arms)
	assert n.scrutinee == none
	assert n.arms.len == 3
	assert n.arms[0].kind == cx.ArmKind.when_arm
	if g := n.arms[0].guard {
		assert g == '(\$x > 100)'
	} else {
		assert false, 'when_arm guard should be set'
	}
}

fn test_match_arm_constructors() {
	c := cx.new_case_arm('[user \$u]', ':adult')
	assert c.kind == cx.ArmKind.case_arm
	assert c.pattern == '[user \$u]'
	assert c.guard == none
	assert c.body == ':adult'

	cg := cx.new_case_arm_guarded('[user \$u]', '(\$u@age >= 18)', ':adult')
	assert cg.kind == cx.ArmKind.case_arm
	assert cg.pattern == '[user \$u]'
	if g := cg.guard {
		assert g == '(\$u@age >= 18)'
	} else {
		assert false, 'guard should be set'
	}
	assert cg.body == ':adult'

	w := cx.new_when_arm('(\$x > 100)', ':big')
	assert w.kind == cx.ArmKind.when_arm
	assert w.pattern == ''
	if g := w.guard {
		assert g == '(\$x > 100)'
	} else {
		assert false, 'when arm guard slot should hold predicate'
	}

	e := cx.new_else_arm(':err')
	assert e.kind == cx.ArmKind.else_arm
	assert e.body == ':err'
	assert e.guard == none
	assert e.pattern == ''
}

// ── ArmKind ↔ name round-trip ─────────────────────────────────────────────────

fn test_arm_kind_name_round_trip() {
	kinds := [cx.ArmKind.case_arm, cx.ArmKind.when_arm, cx.ArmKind.else_arm]
	for k in kinds {
		name := cx.arm_kind_name(k)
		round := cx.arm_kind_from_name(name) or {
			assert false, 'round-trip failed for ${name}'
			return
		}
		assert round == k
	}
}

fn test_arm_kind_from_unknown_name() {
	r := cx.arm_kind_from_name('bogus')
	assert r == none
}

// ── Equality ──────────────────────────────────────────────────────────────────

fn make_match_simple() cx.MatchNode {
	return cx.MatchNode{
		scrutinee: ?string('\$s')
		arms: [
			cx.new_case_arm('200', ':ok'),
			cx.new_case_arm('404', ':not-found'),
			cx.new_else_arm(':err'),
		]
	}
}

fn test_match_node_eq_same_shape() {
	a := make_match_simple()
	b := make_match_simple()
	assert a.eq(b)
	assert b.eq(a)
}

fn test_match_node_eq_ignores_source() {
	mut a := make_match_simple()
	mut b := make_match_simple()
	a.source = '[?match \$s :case 200 :yield :ok :case 404 :yield :not-found :else :yield :err]'
	b.source = '[?match  \$s :case 200 :yield :ok  :case 404 :yield :not-found :else :yield :err]'
	assert a.eq(b), 'source differences must not break equality'
}

fn test_match_node_eq_ignores_loc() {
	mut a := make_match_simple()
	mut b := make_match_simple()
	a.loc = cx.MatchLoc{ start: 0, end: 80 }
	b.loc = cx.MatchLoc{ start: 99, end: 200 }
	assert a.eq(b), 'loc differences must not break equality'
}

fn test_match_arm_eq_ignores_loc() {
	mut a := cx.new_case_arm('200', ':ok')
	mut b := cx.new_case_arm('200', ':ok')
	a.loc = cx.MatchLoc{ start: 0, end: 10 }
	b.loc = cx.MatchLoc{ start: 50, end: 60 }
	assert a.eq(b)
}

fn test_match_node_eq_differs_on_scrutinee() {
	mut a := make_match_simple()
	mut b := make_match_simple()
	b.scrutinee = ?string('\$t')
	assert !a.eq(b)
}

fn test_match_node_eq_differs_on_scrutinee_presence() {
	mut a := make_match_simple()
	mut b := make_match_simple()
	b.scrutinee = ?string(none)
	assert !a.eq(b)
}

fn test_match_node_eq_differs_on_arm_count() {
	mut a := make_match_simple()
	mut b := make_match_simple()
	b.arms = [b.arms[0], b.arms[1]] // drop :else
	assert !a.eq(b)
}

fn test_match_node_eq_differs_on_arm_pattern() {
	mut a := make_match_simple()
	mut b := make_match_simple()
	b.arms[0].pattern = '500'
	assert !a.eq(b)
}

fn test_match_node_eq_differs_on_arm_body() {
	mut a := make_match_simple()
	mut b := make_match_simple()
	b.arms[0].body = ':still-ok'
	assert !a.eq(b)
}

fn test_match_node_eq_differs_on_arm_kind() {
	mut a := make_match_simple()
	mut b := make_match_simple()
	b.arms[2] = cx.new_case_arm('500', ':err')
	assert !a.eq(b)
}

fn test_match_node_eq_differs_on_guard_presence() {
	mut a := cx.new_match_node(?string('\$u'), [cx.new_case_arm('[user \$u]', ':x')])
	mut b := cx.new_match_node(?string('\$u'), [cx.new_case_arm_guarded('[user \$u]', '(\$u@age >= 18)', ':x')])
	assert !a.eq(b)
}

fn test_match_node_eq_differs_on_arm_order() {
	a := cx.new_match_node(?string('\$s'), [
		cx.new_case_arm('200', ':ok'),
		cx.new_case_arm('404', ':not-found'),
	])
	b := cx.new_match_node(?string('\$s'), [
		cx.new_case_arm('404', ':not-found'),
		cx.new_case_arm('200', ':ok'),
	])
	assert !a.eq(b), 'arm order matters (first-match-wins)'
}

// ── Hashing ───────────────────────────────────────────────────────────────────

fn test_match_node_hash_equal_for_equal_nodes() {
	a := make_match_simple()
	b := make_match_simple()
	assert cx.match_node_hash(a) == cx.match_node_hash(b)
}

fn test_match_node_hash_ignores_source_and_loc() {
	mut a := make_match_simple()
	mut b := make_match_simple()
	a.source = 'aaa'
	b.source = 'bbb'
	a.loc = cx.MatchLoc{ start: 0, end: 10 }
	b.loc = cx.MatchLoc{ start: 99, end: 200 }
	assert cx.match_node_hash(a) == cx.match_node_hash(b)
}

fn test_match_node_hash_differs_on_structural_change() {
	a := make_match_simple()
	mut b := make_match_simple()
	b.arms[0].pattern = '500'
	assert cx.match_node_hash(a) != cx.match_node_hash(b)
}

fn test_match_node_hash_differs_on_arm_order() {
	a := cx.new_match_node(?string('\$s'), [
		cx.new_case_arm('200', ':ok'),
		cx.new_case_arm('404', ':not-found'),
	])
	b := cx.new_match_node(?string('\$s'), [
		cx.new_case_arm('404', ':not-found'),
		cx.new_case_arm('200', ':ok'),
	])
	assert cx.match_node_hash(a) != cx.match_node_hash(b)
}

fn test_match_node_hash_differs_on_scrutinee_presence() {
	// Predicate-only vs scrutinee-bound — same arms, must hash differently.
	a := cx.new_match_node(?string(none), [cx.new_when_arm('(\$x > 0)', ':ok'), cx.new_else_arm(':err')])
	b := cx.new_match_node(?string('\$x'), [cx.new_when_arm('(\$x > 0)', ':ok'), cx.new_else_arm(':err')])
	assert cx.match_node_hash(a) != cx.match_node_hash(b)
}

fn test_match_node_hash_disjoint_from_path_node() {
	// A MatchNode and a PathNode whose canonical-bytes happened to align
	// MUST hash differently because each lives in its own domain (the
	// type-tag prefix differs: `MatchNode\x00` vs `PathNode\x00`).
	m := cx.new_match_node(?string(none), [cx.new_else_arm(':x')])
	p := cx.PathNode{
		form:  cx.PathForm.relative
		steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'foo' }]
	}
	mh := cx.match_node_hash(m)
	ph := cx.path_node_hash(p)
	assert mh != ph, 'MatchNode hash must not collide with PathNode hash by construction'
}

fn test_match_node_hash_disjoint_from_text_hash() {
	// A MatchNode whose body strings happened to spell a CX element
	// surface MUST NOT hash-collide with that element's text hash —
	// the disjoint `MatchNode\x00` prefix guarantees separation.
	m := cx.new_match_node(?string(none), [cx.new_else_arm('[user]')])
	mh := cx.match_node_hash(m)
	th := cx.cx_text_hash('[user]') or { panic(err) }
	assert mh != th, 'MatchNode hash must not collide with text hash'
}

// ── JSON projection ───────────────────────────────────────────────────────────

fn test_match_node_to_json_simple_case_arms() {
	n := cx.new_match_node(?string('\$s'), [
		cx.new_case_arm('200', ':ok'),
		cx.new_else_arm(':err'),
	])
	got := cx.match_node_to_json(n)
	want := '{"type":"ProgramMatchExpr","scrutinee":"\$s","arms":[{"kind":"case","pattern":"200","body":":ok"},{"kind":"else","body":":err"}]}'
	assert got == want, 'got: ${got}\nwant: ${want}'
}

fn test_match_node_to_json_when_arms_predicate_only() {
	n := cx.new_match_node(?string(none), [
		cx.new_when_arm('(\$x > 100)', ':big'),
		cx.new_else_arm(':small'),
	])
	got := cx.match_node_to_json(n)
	want := '{"type":"ProgramMatchExpr","arms":[{"kind":"when","guard":"(\$x > 100)","body":":big"},{"kind":"else","body":":small"}]}'
	assert got == want, 'got: ${got}\nwant: ${want}'
}

fn test_match_node_to_json_case_with_where_guard() {
	n := cx.new_match_node(?string('\$u'), [
		cx.new_case_arm_guarded('[user \$u]', '(\$u@age >= 18)', ':adult'),
		cx.new_case_arm('[user \$u]', ':minor'),
	])
	got := cx.match_node_to_json(n)
	want := '{"type":"ProgramMatchExpr","scrutinee":"\$u","arms":[{"kind":"case","pattern":"[user \$u]","guard":"(\$u@age >= 18)","body":":adult"},{"kind":"case","pattern":"[user \$u]","body":":minor"}]}'
	assert got == want, 'got: ${got}\nwant: ${want}'
}

fn test_match_node_to_json_with_source_and_loc() {
	mut n := cx.new_match_node(?string('\$s'), [cx.new_else_arm(':err')])
	n.source = '[?match \$s :else :yield :err]'
	n.loc = cx.MatchLoc{ start: 0, end: 29 }
	got := cx.match_node_to_json(n)
	assert got.contains('"source":"[?match \$s :else :yield :err]"')
	assert got.contains('"loc":{"start":0,"end":29}')
}

fn test_match_node_to_json_omits_empty_optional_fields() {
	n := cx.new_match_node(?string(none), [cx.new_else_arm(':err')])
	got := cx.match_node_to_json(n)
	assert !got.contains('"scrutinee"')
	assert !got.contains('"source"')
	assert !got.contains('"loc"')
}

fn test_match_node_to_json_else_arm_omits_pattern_and_guard() {
	n := cx.new_match_node(?string('\$s'), [cx.new_else_arm(':err')])
	got := cx.match_node_to_json(n)
	// :else arms should NOT carry a "pattern" or "guard" key in the
	// projection — they only have the :yield body.
	assert !got.contains('"pattern":'), 'else arm leaked pattern key: ${got}'
	assert !got.contains('"guard":'), 'else arm leaked guard key: ${got}'
}

fn test_match_node_to_json_escapes_strings() {
	n := cx.new_match_node(?string(none), [
		cx.new_when_arm('(\$s = "hello \\ \"world\"")', ':ok'),
	])
	got := cx.match_node_to_json(n)
	// Inner double-quotes + backslash must JSON-escape correctly.
	assert got.contains('\\"hello'), 'JSON escape missing: ${got}'
	assert got.contains('\\\\'), 'backslash escape missing: ${got}'
}
