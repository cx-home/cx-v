module main

import cx

// Tests for the Phase 2.5 ModifyNode AST.
//
// Covers construction + field access, structural equality with the
// source/loc exclusions, canonical disjoint-domain hashing, JSON
// projection, and disjoint-domain hash separation from PathNode,
// MatchNode, PredicateExpr, and the text-hash pipeline.
//
// Out of scope at Phase 2.5 (no evaluator, no binary codec, no Node
// sum-type integration):
//   - End-to-end evaluator semantics — Phase 2.8.
//   - ast_bin round-trip — wire-format slot allocation pending.

// ── Construction + field access ───────────────────────────────────────────────

fn test_modify_node_construction_canonical() {
	actions := [
		cx.new_modify_action_set('"Alicia"'),
	]
	n := cx.new_modify_node('\$doc', '//user[@id=1]/@name', actions)
	assert n.doc == '\$doc'
	assert n.focus == '//user[@id=1]/@name'
	assert n.actions.len == 1
	assert n.actions[0].kind == cx.ModifyActionKind.set
	assert n.actions[0].value == '"Alicia"'
	assert n.source == none
	assert n.loc == none
}

fn test_modify_node_construction_pipeline_implicit_doc() {
	// Pipeline-implicit-doc form: doc empty, focus carries the path.
	actions := [cx.new_modify_action_delete()]
	n := cx.new_modify_node('', '//user[@banned=true]', actions)
	assert n.doc == ''
	assert n.focus == '//user[@banned=true]'
	assert n.actions[0].kind == cx.ModifyActionKind.delete
}

fn test_modify_action_constructors_cover_all_eleven_actions() {
	a_set := cx.new_modify_action_set('"x"')
	assert a_set.kind == cx.ModifyActionKind.set
	assert a_set.value == '"x"'
	assert a_set.name == ''

	a_delete := cx.new_modify_action_delete()
	assert a_delete.kind == cx.ModifyActionKind.delete
	assert a_delete.value == ''
	assert a_delete.name == ''

	a_using := cx.new_modify_action_using('[?fn \$p :body \$p]')
	assert a_using.kind == cx.ModifyActionKind.using_fn
	assert a_using.value == '[?fn \$p :body \$p]'

	a_rename := cx.new_modify_action_rename('component')
	assert a_rename.kind == cx.ModifyActionKind.rename
	assert a_rename.name == 'component'
	assert a_rename.value == ''

	a_set_attr := cx.new_modify_action_set_attr('status', '"active"')
	assert a_set_attr.kind == cx.ModifyActionKind.set_attr
	assert a_set_attr.name == 'status'
	assert a_set_attr.value == '"active"'

	a_delete_attr := cx.new_modify_action_delete_attr('email')
	assert a_delete_attr.kind == cx.ModifyActionKind.delete_attr
	assert a_delete_attr.name == 'email'
	assert a_delete_attr.value == ''

	a_append := cx.new_modify_action_append('[para "Added"]')
	assert a_append.kind == cx.ModifyActionKind.append
	assert a_append.value == '[para "Added"]'

	a_prepend := cx.new_modify_action_prepend('[para "First"]')
	assert a_prepend.kind == cx.ModifyActionKind.prepend
	assert a_prepend.value == '[para "First"]'

	a_ins_before := cx.new_modify_action_insert_before('[h1 "Title"]')
	assert a_ins_before.kind == cx.ModifyActionKind.insert_before
	assert a_ins_before.value == '[h1 "Title"]'

	a_ins_after := cx.new_modify_action_insert_after('[hr]')
	assert a_ins_after.kind == cx.ModifyActionKind.insert_after
	assert a_ins_after.value == '[hr]'

	a_replace := cx.new_modify_action_replace('[gone]')
	assert a_replace.kind == cx.ModifyActionKind.replace
	assert a_replace.value == '[gone]'
}

// ── ModifyActionKind ↔ string round-trip ─────────────────────────────────────

fn test_modify_action_kind_canonical_spelling() {
	want := {
		cx.ModifyActionKind.set:           'set'
		cx.ModifyActionKind.delete:        'delete'
		cx.ModifyActionKind.using_fn:      'using'
		cx.ModifyActionKind.rename:        'rename'
		cx.ModifyActionKind.set_attr:      'set-attr'
		cx.ModifyActionKind.delete_attr:   'delete-attr'
		cx.ModifyActionKind.append:        'append'
		cx.ModifyActionKind.prepend:       'prepend'
		cx.ModifyActionKind.insert_before: 'insert-before'
		cx.ModifyActionKind.insert_after:  'insert-after'
		cx.ModifyActionKind.replace:       'replace'
	}
	for k, name in want {
		assert cx.modify_action_kind_name(k) == name
		// Round-trip back through modify_action_kind_from_name.
		if round := cx.modify_action_kind_from_name(name) {
			assert round == k, 'round-trip mismatch for ${name}'
		} else {
			assert false, 'modify_action_kind_from_name returned none for ${name}'
		}
	}
}

fn test_modify_action_kind_from_unknown_name() {
	r := cx.modify_action_kind_from_name('bogus')
	assert r == none
}

// ── Equality ──────────────────────────────────────────────────────────────────

fn make_modify_simple() cx.ModifyNode {
	return cx.ModifyNode{
		doc: '\$doc'
		focus: '//user'
		actions: [
			cx.new_modify_action_set_attr('status', '"active"'),
		]
	}
}

fn test_modify_node_eq_same_shape() {
	a := make_modify_simple()
	b := make_modify_simple()
	assert a.eq(b)
	assert b.eq(a)
}

fn test_modify_node_eq_ignores_source() {
	mut a := make_modify_simple()
	mut b := make_modify_simple()
	a.source = '[?modify \$doc //user :set-attr status "active"]'
	b.source = '[?modify  \$doc  //user  :set-attr  status  "active"]'
	assert a.eq(b), 'source differences must not break equality'
}

fn test_modify_node_eq_ignores_loc() {
	mut a := make_modify_simple()
	mut b := make_modify_simple()
	a.loc = cx.ModifyLoc{ start: 0, end: 60 }
	b.loc = cx.ModifyLoc{ start: 99, end: 200 }
	assert a.eq(b), 'loc differences must not break equality'
}

fn test_modify_action_eq_ignores_loc() {
	mut a := cx.new_modify_action_set('1')
	mut b := cx.new_modify_action_set('1')
	a.loc = cx.ModifyLoc{ start: 0, end: 10 }
	b.loc = cx.ModifyLoc{ start: 50, end: 60 }
	assert a.eq(b)
}

fn test_modify_node_eq_differs_on_doc() {
	mut a := make_modify_simple()
	mut b := make_modify_simple()
	b.doc = '\$other'
	assert !a.eq(b)
}

fn test_modify_node_eq_differs_on_focus() {
	mut a := make_modify_simple()
	mut b := make_modify_simple()
	b.focus = '//widget'
	assert !a.eq(b)
}

fn test_modify_node_eq_differs_on_action_count() {
	mut a := make_modify_simple()
	mut b := make_modify_simple()
	b.actions = [b.actions[0], cx.new_modify_action_delete()]
	assert !a.eq(b)
}

fn test_modify_node_eq_differs_on_action_kind() {
	mut a := make_modify_simple()
	mut b := make_modify_simple()
	b.actions = [cx.new_modify_action_delete()]
	assert !a.eq(b)
}

fn test_modify_node_eq_differs_on_action_order() {
	a := cx.new_modify_node('\$doc', '//u', [
		cx.new_modify_action_set('1'),
		cx.new_modify_action_set_attr('s', '"a"'),
	])
	b := cx.new_modify_node('\$doc', '//u', [
		cx.new_modify_action_set_attr('s', '"a"'),
		cx.new_modify_action_set('1'),
	])
	assert !a.eq(b), 'action order matters (left-to-right)'
}

fn test_modify_node_eq_differs_on_action_name() {
	a := cx.new_modify_node('\$doc', '//u', [cx.new_modify_action_set_attr('status', '"a"')])
	b := cx.new_modify_node('\$doc', '//u', [cx.new_modify_action_set_attr('tier', '"a"')])
	assert !a.eq(b)
}

fn test_modify_node_eq_differs_on_action_value() {
	a := cx.new_modify_node('\$doc', '//u', [cx.new_modify_action_set_attr('s', '"a"')])
	b := cx.new_modify_node('\$doc', '//u', [cx.new_modify_action_set_attr('s', '"b"')])
	assert !a.eq(b)
}

// ── Hashing ───────────────────────────────────────────────────────────────────

fn test_modify_node_hash_equal_for_equal_nodes() {
	a := make_modify_simple()
	b := make_modify_simple()
	assert cx.modify_node_hash(a) == cx.modify_node_hash(b)
}

fn test_modify_node_hash_ignores_source_and_loc() {
	mut a := make_modify_simple()
	mut b := make_modify_simple()
	a.source = 'aaa'
	b.source = 'bbb'
	a.loc = cx.ModifyLoc{ start: 0, end: 10 }
	b.loc = cx.ModifyLoc{ start: 99, end: 200 }
	assert cx.modify_node_hash(a) == cx.modify_node_hash(b)
}

fn test_modify_node_hash_differs_on_structural_change() {
	a := make_modify_simple()
	mut b := make_modify_simple()
	b.focus = '//widget'
	assert cx.modify_node_hash(a) != cx.modify_node_hash(b)
}

fn test_modify_node_hash_differs_on_action_order() {
	a := cx.new_modify_node('\$doc', '//u', [
		cx.new_modify_action_set('1'),
		cx.new_modify_action_set_attr('s', '"a"'),
	])
	b := cx.new_modify_node('\$doc', '//u', [
		cx.new_modify_action_set_attr('s', '"a"'),
		cx.new_modify_action_set('1'),
	])
	assert cx.modify_node_hash(a) != cx.modify_node_hash(b)
}

fn test_modify_node_hash_differs_on_doc_presence() {
	// Pipeline-implicit (empty doc) vs explicit doc — must hash differently.
	a := cx.new_modify_node('', '//u', [cx.new_modify_action_delete()])
	b := cx.new_modify_node('\$doc', '//u', [cx.new_modify_action_delete()])
	assert cx.modify_node_hash(a) != cx.modify_node_hash(b)
}

fn test_modify_node_hash_disjoint_from_path_node() {
	// A ModifyNode and a PathNode whose canonical-bytes happened to
	// align MUST hash differently because each lives in its own domain
	// (the type-tag prefix differs: `ModifyNode\x00` vs `PathNode\x00`).
	m := cx.new_modify_node('', '//foo', [cx.new_modify_action_delete()])
	p := cx.PathNode{
		form:  cx.PathForm.relative
		steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'foo' }]
	}
	mh := cx.modify_node_hash(m)
	ph := cx.path_node_hash(p)
	assert mh != ph, 'ModifyNode hash must not collide with PathNode hash by construction'
}

fn test_modify_node_hash_disjoint_from_match_node() {
	// ModifyNode and MatchNode live in disjoint hash domains.
	m := cx.new_modify_node('', '//foo', [cx.new_modify_action_delete()])
	mt := cx.new_match_node(?string(none), [cx.new_else_arm(':x')])
	assert cx.modify_node_hash(m) != cx.match_node_hash(mt)
}

fn test_modify_node_hash_disjoint_from_predicate_expr() {
	// ModifyNode and PredicateExpr live in disjoint hash domains.
	m := cx.new_modify_node('', '//foo', [cx.new_modify_action_delete()])
	p := cx.new_predicate_expr(cx.PredicateExprKind.atom_test, '@active')
	assert cx.modify_node_hash(m) != cx.predicate_expr_hash(p)
}

fn test_modify_node_hash_disjoint_from_text_hash() {
	// A ModifyNode whose value strings happened to spell a CX element
	// surface MUST NOT hash-collide with that element's text hash —
	// the disjoint `ModifyNode\x00` prefix guarantees separation.
	m := cx.new_modify_node('', '//u', [cx.new_modify_action_append('[user]')])
	mh := cx.modify_node_hash(m)
	th := cx.cx_text_hash('[user]') or { panic(err) }
	assert mh != th, 'ModifyNode hash must not collide with text hash'
}

// ── JSON projection ───────────────────────────────────────────────────────────

fn test_modify_node_to_json_simple_set() {
	n := cx.new_modify_node('\$doc', '//user/@name', [
		cx.new_modify_action_set('"Alicia"'),
	])
	got := cx.modify_node_to_json(n)
	want := '{"type":"ProgramModifyExpr","doc":"\$doc","focus":"//user/@name","actions":[{"kind":"set","value":"\\"Alicia\\""}]}'
	assert got == want, 'got: ${got}\nwant: ${want}'
}

fn test_modify_node_to_json_delete_has_no_value_or_name() {
	n := cx.new_modify_node('\$doc', '//user', [
		cx.new_modify_action_delete(),
	])
	got := cx.modify_node_to_json(n)
	assert got.contains('"kind":"delete"')
	// :delete should NOT carry name or value keys.
	assert !got.contains('"name":'), 'delete leaked name key: ${got}'
	assert !got.contains('"value":'), 'delete leaked value key: ${got}'
}

fn test_modify_node_to_json_rename_has_name_no_value() {
	n := cx.new_modify_node('\$doc', '//widget', [
		cx.new_modify_action_rename('component'),
	])
	got := cx.modify_node_to_json(n)
	assert got.contains('"kind":"rename"')
	assert got.contains('"name":"component"')
	assert !got.contains('"value":'), 'rename leaked value key: ${got}'
}

fn test_modify_node_to_json_set_attr_has_both_name_and_value() {
	n := cx.new_modify_node('\$doc', '//user', [
		cx.new_modify_action_set_attr('status', '"active"'),
	])
	got := cx.modify_node_to_json(n)
	assert got.contains('"kind":"set-attr"')
	assert got.contains('"name":"status"')
	assert got.contains('"value":"\\"active\\""')
}

fn test_modify_node_to_json_delete_attr_has_name_no_value() {
	n := cx.new_modify_node('\$doc', '//user', [
		cx.new_modify_action_delete_attr('email'),
	])
	got := cx.modify_node_to_json(n)
	assert got.contains('"kind":"delete-attr"')
	assert got.contains('"name":"email"')
	assert !got.contains('"value":'), 'delete-attr leaked value key: ${got}'
}

fn test_modify_node_to_json_multi_action() {
	n := cx.new_modify_node('\$doc', '//user', [
		cx.new_modify_action_set_attr('verified', 'true'),
		cx.new_modify_action_delete_attr('temp'),
	])
	got := cx.modify_node_to_json(n)
	// Two action objects expected, in order.
	assert got.contains('"actions":[{"kind":"set-attr"')
	idx_set_attr := got.index('"kind":"set-attr"') or { -1 }
	idx_delete_attr := got.index('"kind":"delete-attr"') or { -1 }
	assert idx_set_attr >= 0 && idx_delete_attr > idx_set_attr,
		'action order must be preserved in JSON: ${got}'
}

fn test_modify_node_to_json_with_source_and_loc() {
	mut n := cx.new_modify_node('\$d', '//u', [cx.new_modify_action_delete()])
	n.source = '[?modify \$d //u :delete]'
	n.loc = cx.ModifyLoc{ start: 0, end: 23 }
	got := cx.modify_node_to_json(n)
	assert got.contains('"source":"[?modify \$d //u :delete]"')
	assert got.contains('"loc":{"start":0,"end":23}')
}

fn test_modify_node_to_json_omits_empty_optional_fields() {
	n := cx.new_modify_node('\$d', '//u', [cx.new_modify_action_delete()])
	got := cx.modify_node_to_json(n)
	assert !got.contains('"source"')
	assert !got.contains('"loc"')
}

fn test_modify_node_to_json_escapes_strings() {
	n := cx.new_modify_node('\$d', '//u', [
		cx.new_modify_action_set('"hello \\ \"world\""'),
	])
	got := cx.modify_node_to_json(n)
	// Inner double-quotes + backslash must JSON-escape correctly.
	assert got.contains('\\"hello'), 'JSON escape missing: ${got}'
	assert got.contains('\\\\'), 'backslash escape missing: ${got}'
}

fn test_modify_node_to_json_pipeline_implicit_doc_emits_empty_doc() {
	// In pipeline-implicit form the doc slot is empty string.
	n := cx.new_modify_node('', '//user[@banned=true]', [cx.new_modify_action_delete()])
	got := cx.modify_node_to_json(n)
	assert got.contains('"doc":""')
	assert got.contains('"focus":"//user[@banned=true]"')
}
