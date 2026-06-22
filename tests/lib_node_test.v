module main

import cx

// Tests for the Phase 2.12 Part 3 LibNode AST.
//
// Covers construction + field access, structural equality with the
// source/loc exclusions, canonical disjoint-domain hashing, JSON
// projection, and disjoint-domain hash separation from PathNode,
// MatchNode, ModifyNode, PredicateExpr, DefNode, ConstNode, and the
// text-hash pipeline (nine-way disjoint per the file-level comment in
// lib_node.v).
//
// Out of scope at Phase 2.12 Part 3 (no evaluator, no binary codec,
// no Node sum-type integration):
//   - Loader / resolver dispatch / lockfile cross-check — Phase 2.13 / 2.14.
//   - ast_bin round-trip — wire-format slot allocation pending.
//   - SRI verification + HTTPS fetch — Phase 2.14.

// ── Construction + field access ───────────────────────────────────────────────

fn test_lib_node_construction_minimal_file() {
	n := cx.new_lib_node(cx.ResolverKind.file_path, './local-helpers.cx')
	assert n.resolver_kind == cx.ResolverKind.file_path
	assert n.resolver_source == './local-helpers.cx'
	assert n.alias == none
	assert n.only_imports == none
	assert n.source == none
	assert n.loc == none
}

fn test_lib_node_construction_minimal_registered() {
	n := cx.new_lib_node(cx.ResolverKind.registered_name, 'cx-stdlib/json')
	assert n.resolver_kind == cx.ResolverKind.registered_name
	assert n.resolver_source == 'cx-stdlib/json'
}

fn test_lib_node_construction_minimal_https() {
	n := cx.new_lib_node(cx.ResolverKind.https_url, 'https://cdn.example.com/regex-1.2.3.zip')
	assert n.resolver_kind == cx.ResolverKind.https_url
	assert n.resolver_source == 'https://cdn.example.com/regex-1.2.3.zip'
}

fn test_resolver_kind_str() {
	assert cx.resolver_kind_str(cx.ResolverKind.file_path) == 'file'
	assert cx.resolver_kind_str(cx.ResolverKind.registered_name) == 'registered'
	assert cx.resolver_kind_str(cx.ResolverKind.https_url) == 'https'
}

// ── Equality ──────────────────────────────────────────────────────────────────

fn make_lib_simple() cx.LibNode {
	return cx.LibNode{
		resolver_kind:   cx.ResolverKind.registered_name
		resolver_source: 'cx-stdlib/json'
	}
}

fn test_lib_node_eq_same_shape() {
	a := make_lib_simple()
	b := make_lib_simple()
	assert a.eq(b)
	assert b.eq(a)
}

fn test_lib_node_eq_ignores_source() {
	mut a := make_lib_simple()
	mut b := make_lib_simple()
	a.source = "[?lib 'cx-stdlib/json']"
	b.source = "[?lib  'cx-stdlib/json']"
	assert a.eq(b), 'source differences must not break equality'
}

fn test_lib_node_eq_ignores_loc() {
	mut a := make_lib_simple()
	mut b := make_lib_simple()
	a.loc = cx.LibLoc{ start: 0, end: 25 }
	b.loc = cx.LibLoc{ start: 99, end: 200 }
	assert a.eq(b), 'loc differences must not break equality'
}

fn test_lib_node_eq_differs_on_kind() {
	a := make_lib_simple()
	mut b := make_lib_simple()
	b.resolver_kind = cx.ResolverKind.file_path
	assert !a.eq(b)
}

fn test_lib_node_eq_differs_on_resolver_source() {
	a := make_lib_simple()
	mut b := make_lib_simple()
	b.resolver_source = 'cx-stdlib/strings'
	assert !a.eq(b)
}

fn test_lib_node_eq_differs_on_alias() {
	mut a := make_lib_simple()
	mut b := make_lib_simple()
	a.alias = ?string('json')
	b.alias = ?string('j')
	assert !a.eq(b)
}

fn test_lib_node_eq_differs_on_alias_presence() {
	mut a := make_lib_simple()
	b := make_lib_simple()
	a.alias = ?string('json')
	// b.alias stays none.
	assert !a.eq(b)
}

fn test_lib_node_eq_differs_on_only_imports() {
	mut a := make_lib_simple()
	mut b := make_lib_simple()
	a.only_imports = ?[]string(['a', 'b'])
	b.only_imports = ?[]string(['a', 'c'])
	assert !a.eq(b)
}

fn test_lib_node_eq_differs_on_only_imports_presence() {
	mut a := make_lib_simple()
	b := make_lib_simple()
	a.only_imports = ?[]string(['a', 'b'])
	// b.only_imports stays none.
	assert !a.eq(b)
}

// ── Hashing ───────────────────────────────────────────────────────────────────

fn test_lib_node_hash_equal_for_equal_nodes() {
	a := make_lib_simple()
	b := make_lib_simple()
	assert cx.lib_node_hash(a) == cx.lib_node_hash(b)
}

fn test_lib_node_hash_ignores_source_and_loc() {
	mut a := make_lib_simple()
	mut b := make_lib_simple()
	a.source = 'aaa'
	b.source = 'bbb'
	a.loc = cx.LibLoc{ start: 0, end: 10 }
	b.loc = cx.LibLoc{ start: 99, end: 200 }
	assert cx.lib_node_hash(a) == cx.lib_node_hash(b)
}

fn test_lib_node_hash_differs_on_kind() {
	a := make_lib_simple()
	mut b := make_lib_simple()
	b.resolver_kind = cx.ResolverKind.file_path
	assert cx.lib_node_hash(a) != cx.lib_node_hash(b)
}

fn test_lib_node_hash_differs_on_resolver_source() {
	a := make_lib_simple()
	mut b := make_lib_simple()
	b.resolver_source = 'cx-stdlib/strings'
	assert cx.lib_node_hash(a) != cx.lib_node_hash(b)
}

fn test_lib_node_hash_differs_on_alias() {
	mut a := make_lib_simple()
	mut b := make_lib_simple()
	a.alias = ?string('json')
	b.alias = ?string('j')
	assert cx.lib_node_hash(a) != cx.lib_node_hash(b)
}

fn test_lib_node_hash_differs_on_only_imports() {
	mut a := make_lib_simple()
	mut b := make_lib_simple()
	a.only_imports = ?[]string(['a', 'b'])
	b.only_imports = ?[]string(['a', 'c'])
	assert cx.lib_node_hash(a) != cx.lib_node_hash(b)
}

// Nine-way disjoint hash assertion: LibNode vs PathNode, MatchNode,
// ModifyNode, PredicateExpr, DefNode, ConstNode, text-hash, plus
// Lib-vs-Lib-with-different-resolver AND
// Lib-vs-Lib-with-same-content (round-trip eq).
fn test_lib_node_hash_nine_way_disjoint() {
	// LibNode whose payload happens to spell the same characters as
	// a PathNode / MatchNode / ModifyNode / PredicateExpr / DefNode /
	// ConstNode / element surface MUST hash to a distinct value
	// because each lives in its own type-tag-prefixed domain.
	l := cx.new_lib_node(cx.ResolverKind.registered_name, 'x')
	lh := cx.lib_node_hash(l)

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

	cn := cx.new_const_node('x', 'y')
	cnh := cx.const_node_hash(cn)

	th := cx.cx_text_hash('[x]') or { panic(err) }

	// (8) Same-shape LibNode hashes identically (eq round-trip).
	l_same := cx.new_lib_node(cx.ResolverKind.registered_name, 'x')
	lsh := cx.lib_node_hash(l_same)
	assert lh == lsh, 'same-shape LibNodes must hash identically'

	// (9) Different-resolver LibNode hashes differently (sanity).
	l_diff := cx.new_lib_node(cx.ResolverKind.file_path, './x')
	ldh := cx.lib_node_hash(l_diff)
	assert lh != ldh, 'different-resolver LibNodes must hash differently'

	// All seven external-domain hashes must be distinct from LibNode.
	assert lh != ph, 'LibNode hash must not collide with PathNode hash'
	assert lh != mh, 'LibNode hash must not collide with MatchNode hash'
	assert lh != mnh, 'LibNode hash must not collide with ModifyNode hash'
	assert lh != peh, 'LibNode hash must not collide with PredicateExpr hash'
	assert lh != dh, 'LibNode hash must not collide with DefNode hash'
	assert lh != cnh, 'LibNode hash must not collide with ConstNode hash'
	assert lh != th, 'LibNode hash must not collide with text hash'
	// Cross-check the others stay distinct from each other (sanity).
	assert ph != mh
	assert mh != mnh
	assert mnh != peh
	assert peh != dh
	assert dh != cnh
	assert cnh != th
}

// ── JSON projection ───────────────────────────────────────────────────────────

fn test_lib_node_to_json_minimal_file() {
	n := cx.new_lib_node(cx.ResolverKind.file_path, './local-helpers.cx')
	got := cx.lib_node_to_json(n)
	want := '{"type":"ProgramLibExpr","resolver-kind":"file","resolver":"./local-helpers.cx"}'
	assert got == want, 'got: ${got}\nwant: ${want}'
}

fn test_lib_node_to_json_minimal_registered() {
	n := cx.new_lib_node(cx.ResolverKind.registered_name, 'cx-stdlib/json')
	got := cx.lib_node_to_json(n)
	want := '{"type":"ProgramLibExpr","resolver-kind":"registered","resolver":"cx-stdlib/json"}'
	assert got == want, 'got: ${got}\nwant: ${want}'
}

fn test_lib_node_to_json_https_with_alias() {
	mut n := cx.new_lib_node(cx.ResolverKind.https_url, 'https://cdn.example.com/regex-1.2.3.zip')
	n.alias = ?string('regex')
	got := cx.lib_node_to_json(n)
	want := '{"type":"ProgramLibExpr","resolver-kind":"https","resolver":"https://cdn.example.com/regex-1.2.3.zip","alias":"regex"}'
	assert got == want, 'got: ${got}\nwant: ${want}'
}

fn test_lib_node_to_json_with_only_imports() {
	mut n := cx.new_lib_node(cx.ResolverKind.registered_name, 'cx-stdlib/strings')
	n.only_imports = ?[]string(['trim', 'split'])
	got := cx.lib_node_to_json(n)
	want := '{"type":"ProgramLibExpr","resolver-kind":"registered","resolver":"cx-stdlib/strings","only":["trim","split"]}'
	assert got == want, 'got: ${got}\nwant: ${want}'
}

fn test_lib_node_to_json_with_alias_and_only_imports() {
	mut n := cx.new_lib_node(cx.ResolverKind.registered_name, 'cx-stdlib/strings')
	n.alias = ?string('strs')
	n.only_imports = ?[]string(['trim', 'split'])
	got := cx.lib_node_to_json(n)
	want := '{"type":"ProgramLibExpr","resolver-kind":"registered","resolver":"cx-stdlib/strings","alias":"strs","only":["trim","split"]}'
	assert got == want, 'got: ${got}\nwant: ${want}'
}
