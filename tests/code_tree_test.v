// v0.8.0 Phase 2.11 — cx_code_tree walker tests.
//
// Verifies the V-side `cx.code_tree(source)` walker against the
// JSON contract: every node has `{kind, loc}` with
// optional `name` / `value` / `children` per the kind discriminator;
// `loc` byte offsets are valid UTF-8 substrings of `source`.
//
// Authoritative fixture-driven validation lives in
// `scripts/check_code_diagram_fixtures.py` against
// `conformance/code_diagram.txt`; this V-side test exercises the
// per-kind paths directly so module-level regressions surface
// inside `v test`.

module main

import cx
import x.json2

// ── Helpers ────────────────────────────────────────────────────────────

fn parse_json(s string) json2.Any {
	v := json2.decode[json2.Any](s) or { panic('bad json: ${err.msg()} (input: ${s})') }
	return v
}

fn get_obj(v json2.Any) map[string]json2.Any {
	return v.as_map()
}

fn get_str(v json2.Any) string {
	return v.str()
}

fn get_int(v json2.Any) i64 {
	return v.int()
}

fn loc_start(n map[string]json2.Any) int {
	loc := n['loc'] or { panic('missing loc') }
	lo := loc.as_map()
	s := lo['start'] or { panic('missing loc.start') }
	return int(s.int())
}

fn loc_end(n map[string]json2.Any) int {
	loc := n['loc'] or { panic('missing loc') }
	lo := loc.as_map()
	e := lo['end'] or { panic('missing loc.end') }
	return int(e.int())
}

fn kind_of(n map[string]json2.Any) string {
	k := n['kind'] or { panic('missing kind') }
	return k.str()
}

// ── Empty / minimal ────────────────────────────────────────────────────

fn test_empty_source_returns_root_element_zero_loc() {
	out := cx.code_tree('') or { panic('${err}') }
	n := get_obj(parse_json(out))
	assert kind_of(n) == 'element'
	assert n['name']!.str() == 'root'
	assert loc_start(n) == 0
	assert loc_end(n) == 0
}

fn test_whitespace_only_source() {
	out := cx.code_tree('   \n\n  ') or { panic('${err}') }
	n := get_obj(parse_json(out))
	assert kind_of(n) == 'element'
	assert n['name']!.str() == 'root'
}

// ── Per-kind discriminators ────────────────────────────────────────────

fn test_bare_element() {
	source := '[user]'
	out := cx.code_tree(source) or { panic('${err}') }
	n := get_obj(parse_json(out))
	assert kind_of(n) == 'element'
	assert n['name']!.str() == 'user'
	assert loc_start(n) == 0
	assert loc_end(n) == source.len
}

fn test_element_body_atom_then_int() {
	// `:id` is an atom literal (grammar.ebnf:319), NOT an attribute; `1` is a
	// separate int scalar. The walker emits per-token nodes for the diagram.
	source := '[user :id 1]'
	out := cx.code_tree(source) or { panic('${err}') }
	n := get_obj(parse_json(out))
	assert kind_of(n) == 'element'
	assert n['name']!.str() == 'user'
	assert loc_end(n) == source.len
	children := n['children']!.as_array()
	assert children.len == 2, 'expected 2 body items, got ${children.len}'
	atom := children[0].as_map()
	assert kind_of(atom) == 'scalar'
	assert atom['value']!.str() == ':id'
	// `:id` spans bytes 6..9.
	assert loc_start(atom) == 6
	assert loc_end(atom) == 9
	num := children[1].as_map()
	assert kind_of(num) == 'scalar'
	assert num['value']!.int() == 1
}

fn test_element_body_atoms_and_values() {
	// `:id` / `:name` are atom scalars (not attributes); `1` is an int scalar
	// and `'alice'` a text node — four per-token body items.
	source := "[user :id 1 :name 'alice']"
	out := cx.code_tree(source) or { panic('${err}') }
	n := get_obj(parse_json(out))
	assert kind_of(n) == 'element'
	children := n['children']!.as_array()
	assert children.len == 4, 'expected 4 body items, got ${children.len}'
	a_id := children[0].as_map()
	assert kind_of(a_id) == 'scalar'
	assert a_id['value']!.str() == ':id'
	assert children[1].as_map()['value']!.int() == 1
	a_name := children[2].as_map()
	assert kind_of(a_name) == 'scalar'
	assert a_name['value']!.str() == ':name'
	t := children[3].as_map()
	assert kind_of(t) == 'text'
	assert t['value']!.str() == 'alice'
}

fn test_element_with_text_body() {
	source := "[name 'alice']"
	out := cx.code_tree(source) or { panic('${err}') }
	n := get_obj(parse_json(out))
	assert kind_of(n) == 'element'
	children := n['children']!.as_array()
	assert children.len == 1
	t := children[0].as_map()
	assert kind_of(t) == 'text'
	assert t['value']!.str() == 'alice'
	// 'alice' spans 6..13 (positions of the two quotes inclusive at 6 and 12; end exclusive = 13).
	assert loc_start(t) == 6
	assert loc_end(t) == 13
}

fn test_nested_elements() {
	source := '[doc [user :id 1]]'
	out := cx.code_tree(source) or { panic('${err}') }
	n := get_obj(parse_json(out))
	assert kind_of(n) == 'element'
	assert n['name']!.str() == 'doc'
	children := n['children']!.as_array()
	assert children.len == 1
	inner := children[0].as_map()
	assert kind_of(inner) == 'element'
	assert inner['name']!.str() == 'user'
	inner_children := inner['children']!.as_array()
	// `:id` is an atom scalar, `1` an int scalar — two body items.
	assert inner_children.len == 2
	atom := inner_children[0].as_map()
	assert kind_of(atom) == 'scalar'
	assert atom['value']!.str() == ':id'
	assert inner_children[1].as_map()['value']!.int() == 1
}

fn test_directive_kind() {
	// Canonical clause-child surface (grammar [129] / code.md §7). Per [59]
	// the data walker treats directive children as uniform BodyItems: the
	// `[in …]` and `[yield …]` clauses surface as nested element children,
	// with no data-side clause interpretation.
	source := '[?for [in \$x /a] [yield \$x]]'
	out := cx.code_tree(source) or { panic('${err}') }
	n := get_obj(parse_json(out))
	assert kind_of(n) == 'directive'
	assert n['name']!.str() == 'for'
	assert loc_start(n) == 0
	assert loc_end(n) == source.len
	children := n['children']!.as_array()
	assert children.len == 2, 'expected 2 clause children, got ${children.len}'
	c_in := children[0].as_map()
	c_yield := children[1].as_map()
	assert kind_of(c_in) == 'element'
	assert c_in['name']!.str() == 'in'
	in_kids := c_in['children']!.as_array()
	assert in_kids.len == 2
	assert in_kids[0].as_map()['value']!.str() == '\$x'
	assert kind_of(in_kids[1].as_map()) == 'path'
	assert kind_of(c_yield) == 'element'
	assert c_yield['name']!.str() == 'yield'
}

fn test_directive_colon_surface_decomposes_as_atoms() {
	// The legacy colon surface is no longer interpreted by the data walker.
	// Per [59], `:then`/`:else` round-trip as `:NAME` atom scalars (clause
	// interpretation is the program-AST layer's job, not the data side's).
	source := '[?if cond :then T :else E]'
	out := cx.code_tree(source) or { panic('${err}') }
	n := get_obj(parse_json(out))
	assert kind_of(n) == 'directive'
	assert n['name']!.str() == 'if'
	children := n['children']!.as_array()
	assert children.len == 5, 'expected 5 atom/scalar children, got ${children.len}'
	assert kind_of(children[0].as_map()) == 'scalar'
	assert children[0].as_map()['value']!.str() == 'cond'
	assert kind_of(children[1].as_map()) == 'scalar'
	assert children[1].as_map()['value']!.str() == ':then'
	assert children[2].as_map()['value']!.str() == 'T'
	assert children[3].as_map()['value']!.str() == ':else'
	assert children[4].as_map()['value']!.str() == 'E'
}

fn test_directive_with_nested_element_body() {
	// Directive bodies recurse through nested clause elements. The
	// `[then …]`/`[else …]` clauses surface as element children; the
	// operator-headed condition `[> …]` has no valid element name and
	// surfaces as an anonymous `_` element (pre-existing walker trait).
	source := '[?if [> \$x 0] [then T] [else E]]'
	out := cx.code_tree(source) or { panic('${err}') }
	n := get_obj(parse_json(out))
	assert kind_of(n) == 'directive'
	assert n['name']!.str() == 'if'
	children := n['children']!.as_array()
	assert children.len == 3
	assert kind_of(children[0].as_map()) == 'element'
	c_then := children[1].as_map()
	c_else := children[2].as_map()
	assert kind_of(c_then) == 'element' && c_then['name']!.str() == 'then'
	assert kind_of(c_else) == 'element' && c_else['name']!.str() == 'else'
}

// ── name=value attribute form ──────────────────────────────────────────

fn test_element_name_eq_value_int() {
	source := '[el a=1 b=2]'
	out := cx.code_tree(source) or { panic('${err}') }
	n := get_obj(parse_json(out))
	assert kind_of(n) == 'element'
	assert n['name']!.str() == 'el'
	children := n['children']!.as_array()
	assert children.len == 2, 'expected 2 attributes, got ${children.len}'
	a0 := children[0].as_map()
	a1 := children[1].as_map()
	assert kind_of(a0) == 'attribute'
	assert a0['name']!.str() == 'a'
	assert a0['value']!.int() == 1
	assert kind_of(a1) == 'attribute'
	assert a1['name']!.str() == 'b'
	assert a1['value']!.int() == 2
	// loc substrings must contain the `=` form.
	a0s, a0e := loc_start(a0), loc_end(a0)
	assert source[a0s..a0e] == 'a=1'
	a1s, a1e := loc_start(a1), loc_end(a1)
	assert source[a1s..a1e] == 'b=2'
}

fn test_element_name_eq_value_string_quoted() {
	source := "[pizza size='large']"
	out := cx.code_tree(source) or { panic('${err}') }
	n := get_obj(parse_json(out))
	assert kind_of(n) == 'element'
	children := n['children']!.as_array()
	assert children.len == 1
	attr := children[0].as_map()
	assert kind_of(attr) == 'attribute'
	assert attr['name']!.str() == 'size'
	assert attr['value']!.str() == 'large'
}

fn test_element_name_eq_value_bare_token() {
	source := '[pizza size=large]'
	out := cx.code_tree(source) or { panic('${err}') }
	n := get_obj(parse_json(out))
	children := n['children']!.as_array()
	assert children.len == 1
	attr := children[0].as_map()
	assert kind_of(attr) == 'attribute'
	assert attr['name']!.str() == 'size'
	assert attr['value']!.str() == 'large'
}

fn test_element_eq_attr_then_atom() {
	// `id=1` is a real `name=value` attribute; `:name` is an atom scalar (not
	// an attribute) and `'alice'` is text — three body items.
	source := "[user id=1 :name 'alice']"
	out := cx.code_tree(source) or { panic('${err}') }
	n := get_obj(parse_json(out))
	children := n['children']!.as_array()
	assert children.len == 3, 'expected 3 body items, got ${children.len}'
	a_eq := children[0].as_map()
	assert kind_of(a_eq) == 'attribute'
	assert a_eq['name']!.str() == 'id'
	assert a_eq['value']!.int() == 1
	a_atom := children[1].as_map()
	assert kind_of(a_atom) == 'scalar'
	assert a_atom['value']!.str() == ':name'
	t := children[2].as_map()
	assert kind_of(t) == 'text'
	assert t['value']!.str() == 'alice'
}

fn test_bare_ident_without_eq_stays_scalar() {
	// A bare identifier with no `=` must NOT be reclassified as an
	// attribute — it stays a scalar child (covers `true`, keywords,
	// bare function names, etc.).
	source := '[doc true false hello]'
	out := cx.code_tree(source) or { panic('${err}') }
	n := get_obj(parse_json(out))
	children := n['children']!.as_array()
	assert children.len == 3
	for c in children {
		assert kind_of(c.as_map()) == 'scalar'
	}
	assert children[0].as_map()['value']!.bool() == true
	assert children[1].as_map()['value']!.bool() == false
	assert children[2].as_map()['value']!.str() == 'hello'
}

fn test_scalar_int_top_level() {
	source := '42'
	out := cx.code_tree(source) or { panic('${err}') }
	n := get_obj(parse_json(out))
	assert kind_of(n) == 'scalar'
	assert n['value']!.int() == 42
	assert loc_start(n) == 0
	assert loc_end(n) == 2
}

fn test_scalar_float_top_level() {
	source := '3.14'
	out := cx.code_tree(source) or { panic('${err}') }
	n := get_obj(parse_json(out))
	assert kind_of(n) == 'scalar'
	// JSON number — round-trip as float.
	assert n['value']!.f64() == 3.14
}

fn test_scalar_bool_top_level() {
	source := 'true'
	out := cx.code_tree(source) or { panic('${err}') }
	n := get_obj(parse_json(out))
	assert kind_of(n) == 'scalar'
	assert n['value']!.bool() == true
}

fn test_path_top_level_absolute() {
	source := '/users/user'
	out := cx.code_tree(source) or { panic('${err}') }
	n := get_obj(parse_json(out))
	assert kind_of(n) == 'path'
	assert n['value']!.str() == '/users/user'
	assert loc_start(n) == 0
	assert loc_end(n) == source.len
}

fn test_path_top_level_descendant() {
	source := '//user[@active]'
	out := cx.code_tree(source) or { panic('${err}') }
	n := get_obj(parse_json(out))
	assert kind_of(n) == 'path'
	assert n['value']!.str().starts_with('//user')
}

// ── Loc invariants ─────────────────────────────────────────────────────

fn validate_loc_recursive(n map[string]json2.Any, source string) {
	s := loc_start(n)
	e := loc_end(n)
	assert s >= 0, 'loc.start must be >= 0'
	assert e > s, 'loc.end (${e}) must be > loc.start (${s})'
	assert e <= source.len, 'loc.end (${e}) must be <= source.len (${source.len})'
	// substring extraction must not panic.
	_ := source[s..e]
	if children := n['children'] {
		for c in children.as_array() {
			validate_loc_recursive(c.as_map(), source)
		}
	}
}

fn test_loc_invariants_complex_source() {
	source := "[doc [user :id 1 :name 'alice' [email 'a@x']] [other 'value']]"
	out := cx.code_tree(source) or { panic('${err}') }
	n := get_obj(parse_json(out))
	validate_loc_recursive(n, source)
}

fn test_loc_substring_resolves_to_element_open() {
	source := '[outer [inner]]'
	out := cx.code_tree(source) or { panic('${err}') }
	n := get_obj(parse_json(out))
	children := n['children']!.as_array()
	inner := children[0].as_map()
	// inner element's loc substring must start with `[inner`.
	s := loc_start(inner)
	e := loc_end(inner)
	assert source[s..e] == '[inner]'
}

// ── Round-trip / shape ─────────────────────────────────────────────────

fn test_round_trip_parses_as_valid_json() {
	source := "[user :id 1 :name 'alice' [profile :email 'a@x']]"
	out := cx.code_tree(source) or { panic('${err}') }
	// json2.raw_decode must accept the emitter's output without
	// raising.
	_ := json2.decode[json2.Any](out) or {
		panic('emitter produced invalid JSON: ${err.msg()}')
	}
}

fn test_required_fields_present_per_kind() {
	cases := {
		'[user]':           'element'
		'[user :id 1]':     'element'
		"[name 'a']":       'element'
		'[?for]':           'directive'
		'42':               'scalar'
		'/foo':             'path'
	}
	for src, expected_kind in cases {
		out := cx.code_tree(src) or { panic('${err} for ${src}') }
		n := get_obj(parse_json(out))
		assert kind_of(n) == expected_kind, 'expected ${expected_kind} for ${src}, got ${kind_of(n)}'
		// loc always present.
		assert 'loc' in n, 'missing loc for ${src}'
		// kind-specific required fields.
		match expected_kind {
			'element', 'directive' { assert 'name' in n }
			'scalar', 'path'       { assert 'value' in n }
			else {}
		}
	}
}

// ── Multiple top-level statements ──────────────────────────────────────

fn test_multiple_top_level_wraps_in_synthetic_root() {
	source := '[a][b]'
	out := cx.code_tree(source) or { panic('${err}') }
	n := get_obj(parse_json(out))
	assert kind_of(n) == 'element'
	assert n['name']!.str() == 'root'
	children := n['children']!.as_array()
	assert children.len == 2
	c0 := children[0].as_map()
	c1 := children[1].as_map()
	assert c0['name']!.str() == 'a'
	assert c1['name']!.str() == 'b'
}

// ── Attribute value typing ─────────────────────────────────────────────

fn test_element_body_atom_value_sequence() {
	// Colon tokens are atom scalars (not typed attributes); each following
	// value is its own scalar/text node — eight per-token body items.
	source := "[x :i 42 :f 3.14 :b true :s 'hi']"
	out := cx.code_tree(source) or { panic('${err}') }
	n := get_obj(parse_json(out))
	children := n['children']!.as_array()
	assert children.len == 8, 'expected 8 body items, got ${children.len}'
	assert children[0].as_map()['value']!.str() == ':i'
	assert children[1].as_map()['value']!.int() == 42
	assert children[2].as_map()['value']!.str() == ':f'
	assert children[3].as_map()['value']!.f64() == 3.14
	assert children[4].as_map()['value']!.str() == ':b'
	assert children[5].as_map()['value']!.bool() == true
	assert children[6].as_map()['value']!.str() == ':s'
	t := children[7].as_map()
	assert kind_of(t) == 'text'
	assert t['value']!.str() == 'hi'
}

// ── Edge cases ─────────────────────────────────────────────────────────

fn test_element_with_text_and_nested_element() {
	source := "[doc 'intro' [user]]"
	out := cx.code_tree(source) or { panic('${err}') }
	n := get_obj(parse_json(out))
	assert kind_of(n) == 'element'
	children := n['children']!.as_array()
	assert children.len == 2
	assert kind_of(children[0].as_map()) == 'text'
	assert kind_of(children[1].as_map()) == 'element'
}

fn test_deeply_nested_elements() {
	source := '[a [b [c [d [e]]]]]'
	out := cx.code_tree(source) or { panic('${err}') }
	mut cur := get_obj(parse_json(out)).clone()
	mut depth := 0
	for {
		depth++
		if children := cur['children'] {
			arr := children.as_array()
			if arr.len == 0 { break }
			cur = arr[0].as_map().clone()
		} else { break }
	}
	assert depth == 5
}
