module main

import cx

// Tests for the Phase 2.16 structural TypeExpr AST (vcx/cx/type_expr.v).
//
// Covers:
//   - parse_type_expr for every kind name, element names, `[or …]`
//     unions, `[sequence T]` parameterisation, nested composites.
//   - Parse error paths (empty bracket, single-member or, zero-member
//     sequence, unknown kind, unknown bracket head, malformed
//     identifier, unbalanced brackets, trailing garbage).
//   - Structural equality + hashing + JSON projection.
//   - Disjoint-domain hash (ten-way disjoint vs PathNode / MatchNode /
//     ModifyNode / PredicateExpr / DefNode / ConstNode / LibNode /
//     same-shape / different-shape / text-hash).
//   - DefNode-level integration: def_parser populates DefParam.type_expr
//     (structural) alongside DefParam.type_expr_source (verbatim);
//     DefNode.returns_type_expr ditto.
//   - Equality fallback (structural-vs-structural; structural-vs-
//     source-string).

// ── Positive parses ──────────────────────────────────────────────────────────

fn test_parse_type_expr_kind_string() {
	t := cx.parse_type_expr('string') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert t.kind == cx.TypeKind.kind_name
	if n := t.name {
		assert n == 'string'
	} else {
		assert false, 'name should be `string`'
	}
	assert t.members.len == 0
}

fn test_parse_type_expr_kind_int() {
	t := cx.parse_type_expr('int') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert t.kind == cx.TypeKind.kind_name
	if n := t.name {
		assert n == 'int'
	} else {
		assert false
	}
}

fn test_parse_type_expr_kind_bool() {
	t := cx.parse_type_expr('bool') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert t.kind == cx.TypeKind.kind_name
}

fn test_parse_type_expr_kind_float() {
	t := cx.parse_type_expr('float') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert t.kind == cx.TypeKind.kind_name
}

fn test_parse_type_expr_kind_null() {
	t := cx.parse_type_expr('null') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert t.kind == cx.TypeKind.kind_name
}

fn test_parse_type_expr_kind_atom() {
	t := cx.parse_type_expr('atom') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert t.kind == cx.TypeKind.kind_name
}

fn test_parse_type_expr_kind_element() {
	t := cx.parse_type_expr('element') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert t.kind == cx.TypeKind.kind_name
}

fn test_parse_type_expr_kind_array() {
	t := cx.parse_type_expr('array') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert t.kind == cx.TypeKind.kind_name
}

fn test_parse_type_expr_kind_map() {
	t := cx.parse_type_expr('map') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert t.kind == cx.TypeKind.kind_name
}

fn test_parse_type_expr_kind_sequence() {
	t := cx.parse_type_expr('sequence') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert t.kind == cx.TypeKind.kind_name
}

fn test_parse_type_expr_kind_path() {
	t := cx.parse_type_expr('path') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert t.kind == cx.TypeKind.kind_name
}

fn test_parse_type_expr_kind_bytes() {
	t := cx.parse_type_expr('bytes') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert t.kind == cx.TypeKind.kind_name
}

fn test_parse_type_expr_kind_date() {
	t := cx.parse_type_expr('date') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert t.kind == cx.TypeKind.kind_name
}

fn test_parse_type_expr_kind_datetime() {
	t := cx.parse_type_expr('datetime') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert t.kind == cx.TypeKind.kind_name
}

fn test_parse_type_expr_element_name() {
	t := cx.parse_type_expr('User') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert t.kind == cx.TypeKind.element_name
	if n := t.name {
		assert n == 'User'
	} else {
		assert false
	}
}

fn test_parse_type_expr_element_name_post() {
	t := cx.parse_type_expr('Post') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert t.kind == cx.TypeKind.element_name
	if n := t.name {
		assert n == 'Post'
	} else {
		assert false
	}
}

fn test_parse_type_expr_union_string_int() {
	t := cx.parse_type_expr('[or string int]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert t.kind == cx.TypeKind.union_
	assert t.members.len == 2
	assert t.members[0].kind == cx.TypeKind.kind_name
	if n := t.members[0].name {
		assert n == 'string'
	} else {
		assert false
	}
	assert t.members[1].kind == cx.TypeKind.kind_name
}

fn test_parse_type_expr_union_with_null() {
	t := cx.parse_type_expr('[or Person null]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert t.kind == cx.TypeKind.union_
	assert t.members.len == 2
	assert t.members[0].kind == cx.TypeKind.element_name
	assert t.members[1].kind == cx.TypeKind.kind_name
}

fn test_parse_type_expr_sequence_of_user() {
	t := cx.parse_type_expr('[sequence User]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert t.kind == cx.TypeKind.sequence_
	assert t.members.len == 1
	assert t.members[0].kind == cx.TypeKind.element_name
}

fn test_parse_type_expr_nested_union_in_sequence() {
	t := cx.parse_type_expr('[sequence [or Person null]]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert t.kind == cx.TypeKind.sequence_
	assert t.members.len == 1
	assert t.members[0].kind == cx.TypeKind.union_
	assert t.members[0].members.len == 2
}

fn test_parse_type_expr_nested_sequence_in_union() {
	t := cx.parse_type_expr('[or string [sequence int]]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert t.kind == cx.TypeKind.union_
	assert t.members.len == 2
	assert t.members[0].kind == cx.TypeKind.kind_name
	assert t.members[1].kind == cx.TypeKind.sequence_
	assert t.members[1].members.len == 1
}

fn test_parse_type_expr_whitespace_tolerant() {
	t := cx.parse_type_expr('  [or  string   int]  ') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert t.kind == cx.TypeKind.union_
	assert t.members.len == 2
}

fn test_parse_type_expr_ternary_union() {
	t := cx.parse_type_expr('[or string int bool]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert t.kind == cx.TypeKind.union_
	assert t.members.len == 3
}

// ── Error paths ──────────────────────────────────────────────────────────────

fn test_parse_type_expr_error_empty_input() {
	cx.parse_type_expr('') or {
		assert err.msg().contains('empty input'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_type_expr_error_empty_bracket() {
	cx.parse_type_expr('[]') or {
		assert err.msg().contains('empty bracket'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_type_expr_error_single_member_or() {
	cx.parse_type_expr('[or string]') or {
		assert err.msg().contains('at least 2 members'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_type_expr_error_zero_member_sequence() {
	cx.parse_type_expr('[sequence]') or {
		assert err.msg().contains('exactly 1 member'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_type_expr_error_two_member_sequence() {
	cx.parse_type_expr('[sequence int string]') or {
		assert err.msg().contains('exactly 1 member'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_type_expr_error_unknown_kind() {
	cx.parse_type_expr('foobar') or {
		assert err.msg().contains('unknown kind name'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_type_expr_error_unknown_bracket_head() {
	cx.parse_type_expr('[and string int]') or {
		assert err.msg().contains('unknown bracket head'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_type_expr_error_unbalanced_bracket() {
	cx.parse_type_expr('[or string int') or {
		assert err.msg().contains('unterminated bracket') || err.msg().contains('CXTYPE_PARSE'),
			'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_type_expr_error_trailing_garbage() {
	cx.parse_type_expr('string junk') or {
		assert err.msg().contains('trailing input') || err.msg().contains('unknown kind'),
			'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

// ── Equality ──────────────────────────────────────────────────────────────────

fn test_type_expr_eq_same_kind_name() {
	a := cx.parse_type_expr('string') or {
		assert false
		return
	}
	b := cx.parse_type_expr('string') or {
		assert false
		return
	}
	assert a.eq(b)
}

fn test_type_expr_eq_different_kinds_inequal() {
	a := cx.parse_type_expr('string') or {
		assert false
		return
	}
	b := cx.parse_type_expr('int') or {
		assert false
		return
	}
	assert !a.eq(b)
}

fn test_type_expr_eq_kind_vs_element_inequal() {
	// `string` (lowercase kind) vs `String` (capitalized element-name)
	// — distinct kinds, must not compare equal.
	a := cx.parse_type_expr('string') or {
		assert false
		return
	}
	b := cx.parse_type_expr('String') or {
		assert false
		return
	}
	assert !a.eq(b)
}

fn test_type_expr_eq_union_same_members() {
	a := cx.parse_type_expr('[or string int]') or {
		assert false
		return
	}
	b := cx.parse_type_expr('[or string int]') or {
		assert false
		return
	}
	assert a.eq(b)
}

fn test_type_expr_eq_union_different_order_inequal() {
	// Order matters — `[or string int]` is a
	// distinct surface form from `[or int string]`.
	a := cx.parse_type_expr('[or string int]') or {
		assert false
		return
	}
	b := cx.parse_type_expr('[or int string]') or {
		assert false
		return
	}
	assert !a.eq(b)
}

fn test_type_expr_eq_ignores_source() {
	mut a := cx.parse_type_expr('string') or {
		assert false
		return
	}
	mut b := cx.parse_type_expr('  string  ') or {
		assert false
		return
	}
	// Source differs (one was padded), structural equality holds.
	assert a.eq(b)
}

// ── Hashing ───────────────────────────────────────────────────────────────────

fn test_type_expr_hash_equal_for_equal_exprs() {
	a := cx.parse_type_expr('[or Person null]') or {
		assert false
		return
	}
	b := cx.parse_type_expr('[or Person null]') or {
		assert false
		return
	}
	assert cx.type_expr_hash(a) == cx.type_expr_hash(b)
}

fn test_type_expr_hash_differs_on_kind_change() {
	a := cx.parse_type_expr('string') or {
		assert false
		return
	}
	b := cx.parse_type_expr('int') or {
		assert false
		return
	}
	assert cx.type_expr_hash(a) != cx.type_expr_hash(b)
}

fn test_type_expr_hash_ten_way_disjoint() {
	// TypeExpr's `string` kind has bytes "string" — could clash with
	// surface text that happens to spell the same thing in another
	// node's canonical bytes. The disjoint-domain prefix prevents
	// that. We sanity-check disjointness from all nine sibling AST
	// hashes + the global text-hash.
	t := cx.parse_type_expr('string') or {
		assert false
		return
	}
	th := cx.type_expr_hash(t)

	// PathNode.
	p := cx.PathNode{
		form:  cx.PathForm.relative
		steps: [cx.PathStep{
			axis:      cx.PathAxis.child
			node_test: 'string'
		}]
	}
	ph := cx.path_node_hash(p)

	// MatchNode.
	m := cx.new_match_node(?string(none), [cx.new_else_arm('string')])
	mh := cx.match_node_hash(m)

	// ModifyNode.
	mn := cx.new_modify_node('string', '/x', [cx.new_modify_action_delete()])
	mnh := cx.modify_node_hash(mn)

	// PredicateExpr.
	pe := cx.new_predicate_expr(cx.PredicateExprKind.attr_test, 'string')
	peh := cx.predicate_expr_hash(pe)

	// DefNode.
	d := cx.new_def_node('string', [], 'body')
	dh := cx.def_node_hash(d)

	// ConstNode.
	cn := cx.new_const_node('string', 'body')
	cnh := cx.const_node_hash(cn)

	// LibNode.
	ln := cx.new_lib_node(cx.ResolverKind.registered_name, 'string')
	lnh := cx.lib_node_hash(ln)

	// Text hash.
	txh := cx.cx_text_hash('[x]') or { panic(err) }

	// TypeExpr hash MUST be distinct from every sibling AST hash.
	assert th != ph, 'TypeExpr hash must not collide with PathNode hash'
	assert th != mh, 'TypeExpr hash must not collide with MatchNode hash'
	assert th != mnh, 'TypeExpr hash must not collide with ModifyNode hash'
	assert th != peh, 'TypeExpr hash must not collide with PredicateExpr hash'
	assert th != dh, 'TypeExpr hash must not collide with DefNode hash'
	assert th != cnh, 'TypeExpr hash must not collide with ConstNode hash'
	assert th != lnh, 'TypeExpr hash must not collide with LibNode hash'
	assert th != txh, 'TypeExpr hash must not collide with text hash'

	// Plus a same-shape vs different-shape TypeExpr cross-check.
	t2 := cx.parse_type_expr('string') or {
		assert false
		return
	}
	assert th == cx.type_expr_hash(t2), 'same-shape TypeExprs hash equal'
	t3 := cx.parse_type_expr('int') or {
		assert false
		return
	}
	assert th != cx.type_expr_hash(t3), 'different-shape TypeExprs hash distinct'
}

// ── JSON projection ───────────────────────────────────────────────────────────

fn test_type_expr_to_json_kind_name() {
	t := cx.parse_type_expr('string') or {
		assert false
		return
	}
	got := cx.type_expr_to_json(t)
	assert got == '{"kind":"kind_name","name":"string"}', 'got: ${got}'
}

fn test_type_expr_to_json_element_name() {
	t := cx.parse_type_expr('Person') or {
		assert false
		return
	}
	got := cx.type_expr_to_json(t)
	assert got == '{"kind":"element_name","name":"Person"}', 'got: ${got}'
}

fn test_type_expr_to_json_union() {
	t := cx.parse_type_expr('[or string int]') or {
		assert false
		return
	}
	got := cx.type_expr_to_json(t)
	want := '{"kind":"union","members":[{"kind":"kind_name","name":"string"},{"kind":"kind_name","name":"int"}]}'
	assert got == want, 'got: ${got}'
}

fn test_type_expr_to_json_sequence() {
	t := cx.parse_type_expr('[sequence Person]') or {
		assert false
		return
	}
	got := cx.type_expr_to_json(t)
	want := '{"kind":"sequence","members":[{"kind":"element_name","name":"Person"}]}'
	assert got == want, 'got: ${got}'
}

// ── DefNode integration — Phase 2.16 graft ─────────────────────────────────────

fn test_parse_def_populates_structural_param_type_expr() {
	n := cx.parse_def('[?def echo ($x::int) x]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.params.len == 1
	// Verbatim source slot still set.
	if t := n.params[0].type_expr_source {
		assert t == 'int'
	} else {
		assert false, 'type_expr_source should be `int`'
	}
	// Structural slot populated.
	if te := n.params[0].type_expr {
		assert te.kind == cx.TypeKind.kind_name
		if name := te.name {
			assert name == 'int'
		} else {
			assert false
		}
	} else {
		assert false, 'structural type_expr should be populated for `int`'
	}
}

fn test_parse_def_populates_structural_returns_type_expr() {
	n := cx.parse_def('[?def f [returns string] () "hi"]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	// Verbatim slot still set.
	if rt := n.returns_type_source {
		assert rt == 'string'
	} else {
		assert false, 'returns_type_source should be `string`'
	}
	// Structural slot populated.
	if rte := n.returns_type_expr {
		assert rte.kind == cx.TypeKind.kind_name
		if name := rte.name {
			assert name == 'string'
		} else {
			assert false
		}
	} else {
		assert false, 'structural returns_type_expr should be populated'
	}
}

fn test_parse_def_populates_structural_union() {
	n := cx.parse_def('[?def find [returns [or Person null]] ($id::string) null]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	if rte := n.returns_type_expr {
		assert rte.kind == cx.TypeKind.union_
		assert rte.members.len == 2
		assert rte.members[0].kind == cx.TypeKind.element_name
		assert rte.members[1].kind == cx.TypeKind.kind_name
	} else {
		assert false, 'structural returns_type_expr should be populated for `[or Person null]`'
	}
}

fn test_parse_def_populates_structural_sequence() {
	n := cx.parse_def('[?def list [returns [sequence Person]] () []]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	if rte := n.returns_type_expr {
		assert rte.kind == cx.TypeKind.sequence_
		assert rte.members.len == 1
		assert rte.members[0].kind == cx.TypeKind.element_name
	} else {
		assert false, 'structural returns_type_expr should be populated for `[sequence Person]`'
	}
}

// ── Equality fallback (structural vs source) ─────────────────────────────────

fn test_def_node_eq_structural_vs_source_param() {
	// One DefNode parsed (so structural slot populated); the other
	// constructed manually with only `type_expr_source` set. Should
	// still compare equal under the fallback rule.
	parsed := cx.parse_def('[?def f ($x::int) x]') or {
		assert false
		return
	}
	manual := cx.DefNode{
		name:   'f'
		params: [
			cx.DefParam{
				name:             'x'
				type_expr_source: ?string('int')
				type_expr:        ?cx.TypeExpr(none)
			},
		]
		body:   'x'
	}
	assert parsed.eq(manual), 'parsed (structural) and manual (source-only) should compare equal'
}

fn test_def_node_eq_structural_different_shape_inequal() {
	a := cx.parse_def('[?def f ($x::int) x]') or {
		assert false
		return
	}
	b := cx.parse_def('[?def f ($x::string) x]') or {
		assert false
		return
	}
	assert !a.eq(b), 'differently-typed params should NOT compare equal'
}
