module main

import cx

// Tests for the Phase 2.1 PathNode AST.
// Covers construction + field access, structural equality (with the
// source/loc exclusions), canonical disjoint-domain
// hashing, and JSON projection round-trip-as-literal.
//
// Out of scope at Phase 2.1 (no parser, no binary codec):
//   - End-to-end parse of `//user[@active=true]` source — Phase 2.3.
//   - ast_bin round-trip — Phase 1.7 wire-slot allocation pending.

// ── Construction + field access ───────────────────────────────────────────────

fn test_path_node_construction_descendant() {
	step := cx.new_path_step(cx.PathAxis.child, 'user')
	p := cx.new_path_node(cx.PathForm.descendant, [step])
	assert p.form == cx.PathForm.descendant
	assert p.steps.len == 1
	assert p.steps[0].axis == cx.PathAxis.child
	assert p.steps[0].node_test == 'user'
	assert p.binding == none
	assert p.predicates.len == 0
	assert p.source == none
	assert p.loc == none
}

fn test_path_node_construction_binding() {
	step := cx.new_path_step(cx.PathAxis.child, 'name')
	mut p := cx.new_path_node(cx.PathForm.binding, [step])
	p.binding = 'u'
	assert p.form == cx.PathForm.binding
	if b := p.binding {
		assert b == 'u'
	} else {
		assert false, 'binding should be set'
	}
}

fn test_path_step_with_predicate() {
	step := cx.PathStep{
		axis:       cx.PathAxis.child
		node_test:  'user'
		predicates: [cx.PathPredicate{ source: '@active=true' }]
	}
	assert step.predicates.len == 1
	assert step.predicates[0].source == '@active=true'
}

// ── Axis ↔ name round-trip ────────────────────────────────────────────────────

fn test_path_axis_name_round_trip() {
	axes := [
		cx.PathAxis.child,
		cx.PathAxis.descendant,
		cx.PathAxis.descendant_or_self,
		cx.PathAxis.parent,
		cx.PathAxis.ancestor,
		cx.PathAxis.ancestor_or_self,
		cx.PathAxis.following_sibling,
		cx.PathAxis.preceding_sibling,
		cx.PathAxis.following,
		cx.PathAxis.preceding,
		cx.PathAxis.self_,
		cx.PathAxis.attribute,
	]
	for a in axes {
		name := cx.path_axis_name(a)
		round := cx.path_axis_from_name(name) or {
			assert false, 'round-trip failed for ${name}'
			return
		}
		assert round == a
	}
}

fn test_path_axis_from_unknown_name() {
	r := cx.path_axis_from_name('bogus-axis')
	assert r == none
}

fn test_path_form_round_trip() {
	forms := [
		cx.PathForm.absolute,
		cx.PathForm.descendant,
		cx.PathForm.relative,
		cx.PathForm.binding,
	]
	for f in forms {
		round := cx.path_form_from_name(cx.path_form_name(f)) or {
			assert false, 'form round-trip failed'
			return
		}
		assert round == f
	}
}

// ── Equality ──────────────────────────────────────────────────────────────────

fn make_path_simple() cx.PathNode {
	return cx.PathNode{
		form: cx.PathForm.descendant
		steps: [
			cx.PathStep{
				axis:       cx.PathAxis.child
				node_test:  'user'
				predicates: [cx.PathPredicate{ source: '@active=true' }]
			},
			cx.PathStep{
				axis:      cx.PathAxis.child
				node_test: 'email'
			},
		]
	}
}

fn test_path_node_eq_same_shape() {
	a := make_path_simple()
	b := make_path_simple()
	assert a.eq(b)
	assert b.eq(a)
}

fn test_path_node_eq_ignores_source() {
	mut a := make_path_simple()
	mut b := make_path_simple()
	a.source = '//user[@active=true]/email'
	b.source = '// user [ @active = true ] / email'
	assert a.eq(b), 'source differences must not break equality'
}

fn test_path_node_eq_ignores_loc() {
	mut a := make_path_simple()
	mut b := make_path_simple()
	a.loc = cx.PathLoc{ line: 1, col: 1 }
	b.loc = cx.PathLoc{ line: 99, col: 17 }
	assert a.eq(b), 'loc differences must not break equality'
}

fn test_path_node_eq_differs_on_form() {
	mut a := make_path_simple()
	mut b := make_path_simple()
	b.form = cx.PathForm.absolute
	assert !a.eq(b)
}

fn test_path_node_eq_differs_on_step_axis() {
	mut a := make_path_simple()
	mut b := make_path_simple()
	b.steps[0].axis = cx.PathAxis.descendant
	assert !a.eq(b)
}

fn test_path_node_eq_differs_on_step_node_test() {
	mut a := make_path_simple()
	mut b := make_path_simple()
	b.steps[0].node_test = 'admin'
	assert !a.eq(b)
}

fn test_path_node_eq_differs_on_predicate_body() {
	mut a := make_path_simple()
	mut b := make_path_simple()
	b.steps[0].predicates[0].source = '@active=false'
	assert !a.eq(b)
}

fn test_path_node_eq_differs_on_binding() {
	mut a := make_path_simple()
	mut b := make_path_simple()
	a.form = cx.PathForm.binding
	b.form = cx.PathForm.binding
	a.binding = 'u'
	b.binding = 'v'
	assert !a.eq(b)
}

fn test_path_node_eq_differs_on_step_count() {
	mut a := make_path_simple()
	mut b := make_path_simple()
	b.steps = [b.steps[0]] // drop the trailing step
	assert !a.eq(b)
}

// ── Hashing ───────────────────────────────────────────────────────────────────

fn test_path_node_hash_equal_for_equal_paths() {
	a := make_path_simple()
	b := make_path_simple()
	assert cx.path_node_hash(a) == cx.path_node_hash(b)
}

fn test_path_node_hash_ignores_source_and_loc() {
	mut a := make_path_simple()
	mut b := make_path_simple()
	a.source = '//user[@active=true]/email'
	b.source = '// user [@active = true]/email'
	a.loc = cx.PathLoc{ line: 1, col: 1 }
	b.loc = cx.PathLoc{ line: 42, col: 7 }
	assert cx.path_node_hash(a) == cx.path_node_hash(b)
}

fn test_path_node_hash_differs_on_structural_change() {
	a := make_path_simple()
	mut b := make_path_simple()
	b.steps[0].node_test = 'admin'
	assert cx.path_node_hash(a) != cx.path_node_hash(b)
}

fn test_path_node_hash_disjoint_from_text_hash() {
	// A PathNode whose source-text is `user` (a plain element name)
	// must NOT hash-collide with the text hash of the element source
	// `[user]`. The disjoint-domain prefix `PathNode\x00` guarantees
	// the canonical-bytes input differs from anything the text-hash
	// pipeline could produce. Even if a future canonical-form change
	// made the two byte streams identical, the `\x00` byte is
	// forbidden by the CX canonical text grammar (which is UTF-8
	// content with no control bytes inside the bracket body), so
	// collision-by-construction stays disjoint.
	p := cx.PathNode{
		form: cx.PathForm.relative
		steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user' }]
	}
	ph := cx.path_node_hash(p)
	th := cx.cx_text_hash('[user]') or { panic(err) }
	assert ph != th, 'PathNode hash must not collide with text hash for same-content surface'
}

fn test_path_node_hash_differs_form_to_form() {
	// Same step list, different `form` must hash differently.
	a := cx.PathNode{
		form:  cx.PathForm.relative
		steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user' }]
	}
	b := cx.PathNode{
		form:  cx.PathForm.descendant
		steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user' }]
	}
	assert cx.path_node_hash(a) != cx.path_node_hash(b)
}

// ── JSON projection ───────────────────────────────────────────────────────────

fn test_path_node_to_json_descendant_minimal() {
	p := cx.PathNode{
		form:  cx.PathForm.descendant
		steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user' }]
	}
	got := cx.path_node_to_json(p)
	want := '{"type":"ProgramPathExpr","form":"descendant","steps":[{"axis":"child","node_test":"user"}]}'
	assert got == want, 'got: ${got}\nwant: ${want}'
}

fn test_path_node_to_json_with_predicate() {
	p := cx.PathNode{
		form: cx.PathForm.descendant
		steps: [
			cx.PathStep{
				axis:       cx.PathAxis.child
				node_test:  'user'
				predicates: [cx.PathPredicate{ source: '@active=true' }]
			},
		]
	}
	got := cx.path_node_to_json(p)
	want := '{"type":"ProgramPathExpr","form":"descendant","steps":[{"axis":"child","node_test":"user","predicates":[{"source":"@active=true"}]}]}'
	assert got == want, 'got: ${got}\nwant: ${want}'
}

fn test_path_node_to_json_binding_form() {
	p := cx.PathNode{
		form:    cx.PathForm.binding
		binding: 'u'
		steps:   [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'name' }]
	}
	got := cx.path_node_to_json(p)
	want := '{"type":"ProgramPathExpr","form":"binding","binding":"u","steps":[{"axis":"child","node_test":"name"}]}'
	assert got == want, 'got: ${got}\nwant: ${want}'
}

fn test_path_node_to_json_with_source_and_loc() {
	p := cx.PathNode{
		form:   cx.PathForm.descendant
		steps:  [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user' }]
		source: '//user'
		loc:    cx.PathLoc{ line: 12, col: 3 }
	}
	got := cx.path_node_to_json(p)
	want := '{"type":"ProgramPathExpr","form":"descendant","steps":[{"axis":"child","node_test":"user"}],"source":"//user","loc":{"line":12,"col":3}}'
	assert got == want, 'got: ${got}\nwant: ${want}'
}

fn test_path_node_to_json_omits_empty_optional_fields() {
	// Minimal node: predicates [], no binding, no source, no loc.
	// Projection must elide all four.
	p := cx.PathNode{
		form:  cx.PathForm.absolute
		steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'root' }]
	}
	got := cx.path_node_to_json(p)
	assert !got.contains('"binding"')
	assert !got.contains('"predicates"')
	assert !got.contains('"source"')
	assert !got.contains('"loc"')
}

fn test_path_node_to_json_escapes_strings() {
	// JSON-special characters in predicate body must escape correctly.
	p := cx.PathNode{
		form: cx.PathForm.descendant
		steps: [
			cx.PathStep{
				axis:       cx.PathAxis.child
				node_test:  'item'
				predicates: [cx.PathPredicate{ source: '@name="quoted \\ value"' }]
			},
		]
	}
	got := cx.path_node_to_json(p)
	// Verify the embedded `"` and `\` characters survived escape.
	assert got.contains('@name=\\"quoted \\\\ value\\"'), 'unexpected JSON: ${got}'
}
