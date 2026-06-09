module code

import cx

// cxpath_test.v — unit tests for CXPath chunk-1 foundation.
// Covers descendant-rooted simple paths:
//
//   //name           descendant-or-self by element name
//   //*              descendant-or-self any element
//   //name/child     descendant-or-self → child step
//   //name/*         descendant-or-self → all-children step
//
// Predicates `[…]`, the remaining 10 axes, absolute '/'-rooted paths,
// relative paths, sequence operators (union/intersect/except), and
// BindingPath `$x/step+` are out of chunk-1 scope and tracked for
// subsequent chunks.

// ── helpers ────────────────────────────────────────────────────────

// eval_path_against runs `src` (a CXPath expression) against the given
// document and returns the result. The document is bound under `$doc`
// per CXPath descendant-rooted semantics.
fn eval_path_against(src string, doc cx.Node) !cx.Node {
	prog := cx.parse_program(src)!
	mut env := new_env()
	env.bindings['doc'] = doc
	return eval(prog.body, mut env)
}

// element_names extracts the names of all Element nodes in a result
// sequence (the `cx.Element{ name: '', items: […] }` wrapper).
fn element_names(result cx.Node) []string {
	mut names := []string{}
	if result is cx.Element {
		for item in result.items {
			if item is cx.Element {
				names << item.name
			}
		}
	}
	return names
}

fn make_doc(src string) !cx.Node {
	doc := cx.parse(src)!
	if doc.elements.len == 0 {
		return error('empty document')
	}
	return doc.elements[0]
}

// ── parse-side: AST shape ──────────────────────────────────────────

fn test_path_descendant_single_step_parses() {
	prog := cx.parse_program('//user') or {
		assert false, 'parse //user failed: ${err}'
		return
	}
	body := prog.body
	if body is cx.ProgramPathExpr {
		assert body.leading == .descendant, 'expected leading=.descendant'
		assert body.steps.len == 1
		assert body.steps[0].axis == .descendant_or_self
		assert body.steps[0].name == 'user'
	} else {
		assert false, 'expected cx.ProgramPathExpr, got ${body.type_name()}'
	}
}

fn test_path_descendant_then_child_step_parses() {
	prog := cx.parse_program('//user/name') or {
		assert false, 'parse failed: ${err}'
		return
	}
	body := prog.body
	if body is cx.ProgramPathExpr {
		assert body.steps.len == 2
		assert body.steps[0].axis == .descendant_or_self
		assert body.steps[0].name == 'user'
		assert body.steps[1].axis == .child
		assert body.steps[1].name == 'name'
	} else {
		assert false, 'expected cx.ProgramPathExpr'
	}
}

fn test_path_wildcard_step_parses() {
	prog := cx.parse_program('//*') or {
		assert false, 'parse //* failed: ${err}'
		return
	}
	body := prog.body
	if body is cx.ProgramPathExpr {
		assert body.steps.len == 1
		assert body.steps[0].name == '*'
	} else {
		assert false, 'expected cx.ProgramPathExpr'
	}
}

// ── eval-side: against a real document ────────────────────────────

fn test_path_descendant_returns_all_matching_at_any_depth() {
	doc := make_doc('[users [user [name "Alice"]] [user [name "Bob"]]]') or {
		assert false, 'doc parse failed: ${err}'
		return
	}
	result := eval_path_against('//user', doc) or {
		assert false, 'eval failed: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 2, 'expected 2 user elements, got ${names.len}: ${names}'
	for n in names {
		assert n == 'user', 'expected user, got ${n}'
	}
}

fn test_path_descendant_then_child_step_returns_nested_children() {
	doc := make_doc('[users [user [name "Alice"]] [user [name "Bob"]]]') or {
		assert false, 'doc parse failed: ${err}'
		return
	}
	result := eval_path_against('//user/name', doc) or {
		assert false, 'eval failed: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 2, 'expected 2 name elements, got ${names.len}'
	for n in names {
		assert n == 'name'
	}
}

fn test_path_descendant_at_arbitrary_depth() {
	// Match should work at any nesting depth (descendant-or-self).
	doc := make_doc('[doc [section [para [figure id=f1]]] [section [para [figure id=f2]]]]') or {
		assert false, 'doc parse failed: ${err}'
		return
	}
	result := eval_path_against('//figure', doc) or {
		assert false, 'eval failed: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 2, 'expected 2 figure elements at any depth, got ${names.len}'
}

fn test_path_no_match_returns_empty_sequence() {
	doc := make_doc('[doc [item "a"]]') or {
		assert false, 'doc parse failed: ${err}'
		return
	}
	result := eval_path_against('//missing', doc) or {
		assert false, 'eval failed: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 0, 'expected empty result for non-matching name'
}

fn test_path_wildcard_matches_all_elements_at_any_depth() {
	doc := make_doc('[doc [a] [b] [c]]') or {
		assert false, 'doc parse failed: ${err}'
		return
	}
	result := eval_path_against('//*', doc) or {
		assert false, 'eval failed: ${err}'
		return
	}
	names := element_names(result)
	// Includes the doc root (descendant-or-self) plus the three children.
	assert names.len >= 4, 'expected at least 4 elements (doc + a + b + c), got ${names.len}: ${names}'
}

fn test_path_child_wildcard_step_returns_all_children_of_matches() {
	doc := make_doc('[users [user [name "Alice"] [email "a@x"]] [user [name "Bob"] [email "b@x"]]]') or {
		assert false, 'doc parse failed: ${err}'
		return
	}
	result := eval_path_against('//user/*', doc) or {
		assert false, 'eval failed: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 4, 'expected 4 children (2 users x 2 children each), got ${names.len}: ${names}'
}

// ── ast_json: round-trip the terse surface ───────────

fn test_path_emits_canonical_terse_form_in_ast_json() {
	json := program_ast_json('//user/name') or {
		assert false, 'program_ast_json failed: ${err}'
		return
	}
	// Per, canonical emit is the terse `//step/step` form.
	assert json.contains('//user/name'), 'expected canonical //user/name in AST-JSON, got: ${json}'
}

// ── no $doc bound → empty sequence (truthiness friendly, §5.5.1 D4) ─

fn test_path_with_no_doc_binding_returns_empty() {
	mut env := new_env()
	prog := cx.parse_program('//anything') or {
		assert false, 'parse failed: ${err}'
		return
	}
	// No $doc bound in the env.
	result := eval(prog.body, mut env) or {
		assert false, 'eval should return empty, not error: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 0, 'expected empty sequence when no $doc bound'
}

// ── chunk-2: predicates ────────────────────────────────────────────

fn test_path_predicate_attr_equality_filters_matches() {
	doc := make_doc('[users [user active=true [name "A"]] [user active=false [name "B"]] [user active=true [name "C"]]]') or {
		assert false, 'doc parse: ${err}'
		return
	}
	result := eval_path_against('//user[@active=true]', doc) or {
		assert false, 'eval: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 2, 'expected 2 active users, got ${names.len}'
}

fn test_path_predicate_attr_existence() {
	doc := make_doc('[users [user banned=true name=a] [user name=b] [user banned=false name=c]]') or {
		assert false, 'doc parse: ${err}'
		return
	}
	result := eval_path_against('//user[@banned]', doc) or {
		assert false, 'eval: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 2, 'expected 2 users with @banned attr (existence ignores value), got ${names.len}'
}

fn test_path_predicate_attr_absence() {
	doc := make_doc('[users [user banned=true name=a] [user name=b] [user banned=false name=c]]') or {
		assert false, 'doc parse: ${err}'
		return
	}
	result := eval_path_against('//user[@!banned]', doc) or {
		assert false, 'eval: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 1, 'expected 1 user without @banned, got ${names.len}'
}

fn test_path_predicate_attr_comparison_ge() {
	doc := make_doc('[users [user age=15 name=a] [user age=18 name=b] [user age=30 name=c]]') or {
		assert false, 'doc parse: ${err}'
		return
	}
	result := eval_path_against('//user[@age>=18]', doc) or {
		assert false, 'eval: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 2, 'expected 2 adult users, got ${names.len}'
}

fn test_path_predicate_positional_first() {
	doc := make_doc('[users [user name=a] [user name=b] [user name=c]]') or {
		assert false, 'doc parse: ${err}'
		return
	}
	result := eval_path_against('//user[1]', doc) or {
		assert false, 'eval: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 1, 'expected 1 user (positional), got ${names.len}'
}

fn test_path_predicate_positional_third() {
	doc := make_doc('[users [user name=a] [user name=b] [user name=c]]') or {
		assert false, 'doc parse: ${err}'
		return
	}
	result := eval_path_against('//user[3]', doc) or {
		assert false, 'eval: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 1, 'expected 1 user (positional 3), got ${names.len}'
}

fn test_path_predicate_conjunctive() {
	doc := make_doc('[users [user active=false name=a] [user active=true name=b] [user active=true name=c]]') or {
		assert false, 'doc parse: ${err}'
		return
	}
	// First active user — conjunctive predicates [@active=true][1].
	result := eval_path_against('//user[@active=true][1]', doc) or {
		assert false, 'eval: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 1, 'expected 1 user (first active), got ${names.len}'
}

// ── chunk-2: explicit axes ────────────────────────────────────────

fn test_path_axis_self_identity() {
	doc := make_doc('[doc [div [span "x"]]]') or {
		assert false, 'doc parse: ${err}'
		return
	}
	result := eval_path_against('//div/self::div', doc) or {
		assert false, 'eval: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 1 && names[0] == 'div', 'expected self::div to return div, got ${names}'
}

fn test_path_axis_parent_returns_parent() {
	doc := make_doc('[doc [section [figure id=f1]]]') or {
		assert false, 'doc parse: ${err}'
		return
	}
	result := eval_path_against('//figure/parent::*', doc) or {
		assert false, 'eval: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 1 && names[0] == 'section', 'expected parent::* to return section, got ${names}'
}

fn test_path_axis_ancestor_walks_up() {
	doc := make_doc('[doc [section [para [figure id=f1]]]]') or {
		assert false, 'doc parse: ${err}'
		return
	}
	result := eval_path_against('//figure/ancestor::doc', doc) or {
		assert false, 'eval: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 1 && names[0] == 'doc', 'expected ancestor::doc, got ${names}'
}

fn test_path_axis_ancestor_or_self_includes_self() {
	doc := make_doc('[doc [section [section [figure id=f1]]]]') or {
		assert false, 'doc parse: ${err}'
		return
	}
	result := eval_path_against('//figure/ancestor-or-self::section', doc) or {
		assert false, 'eval: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 2, 'expected 2 ancestor sections, got ${names.len}: ${names}'
}

fn test_path_axis_descendant_excludes_self() {
	doc := make_doc('[root [leaf "a"] [branch [leaf "b"]]]') or {
		assert false, 'doc parse: ${err}'
		return
	}
	result := eval_path_against('//root/descendant::leaf', doc) or {
		assert false, 'eval: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 2, 'expected 2 leaves under root (descendant), got ${names.len}'
}

fn test_path_axis_following_sibling() {
	doc := make_doc('[doc [h2 "Heading"] [p "first"] [p "second"] [div "other"]]') or {
		assert false, 'doc parse: ${err}'
		return
	}
	result := eval_path_against('//h2/following-sibling::p', doc) or {
		assert false, 'eval: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 2, 'expected 2 p siblings after h2, got ${names.len}'
}

fn test_path_axis_preceding_sibling() {
	doc := make_doc('[doc [label "L1"] [label "L2"] [item id=i] [label "L3"]]') or {
		assert false, 'doc parse: ${err}'
		return
	}
	result := eval_path_against('//item/preceding-sibling::label', doc) or {
		assert false, 'eval: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 2, 'expected 2 labels preceding item, got ${names.len}'
}

fn test_path_axis_following_document_order() {
	doc := make_doc('[doc [section [intro "x"]] [p "1"] [section [body "y"]] [p "2"]]') or {
		assert false, 'doc parse: ${err}'
		return
	}
	// `//section/following::p` — every p after the first section in
	// document order (excludes section descendants).
	result := eval_path_against('//section/following::p', doc) or {
		assert false, 'eval: ${err}'
		return
	}
	names := element_names(result)
	// First section is at index 1; following p's = p"1", p"2" (both)
	// Second section is at index ~5; following p = p"2" only
	// Union, document-order, dedup → 2 p's.
	assert names.len == 2, 'expected 2 following p elements, got ${names.len}'
}

fn test_path_axis_preceding_document_order() {
	doc := make_doc('[doc [p "1"] [section [intro "x"]] [p "2"]]') or {
		assert false, 'doc parse: ${err}'
		return
	}
	result := eval_path_against('//section/preceding::p', doc) or {
		assert false, 'eval: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 1, 'expected 1 preceding p, got ${names.len}'
}

fn test_path_axis_attribute_emits_attribute_wrappers() {
	doc := make_doc('[users [user name="Alice" age=30]]') or {
		assert false, 'doc parse: ${err}'
		return
	}
	result := eval_path_against('//user/attribute::name', doc) or {
		assert false, 'eval: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 1 && names[0] == 'name', 'expected 1 attribute wrapper named "name", got ${names}'
}

// ── chunk-2: ast_json canonical emit ──────────────────────────────

fn test_path_emits_predicate_in_canonical_form() {
	json := program_ast_json('//user[@active=true]') or {
		assert false, 'ast_json: ${err}'
		return
	}
	assert json.contains('//user[@active=true]'), 'expected canonical predicate emit, got: ${json}'
}

fn test_path_emits_positional_predicate_in_canonical_form() {
	json := program_ast_json('//item[3]') or {
		assert false, 'ast_json: ${err}'
		return
	}
	assert json.contains('//item[3]'), 'expected canonical positional emit, got: ${json}'
}

fn test_path_emits_explicit_axis_in_canonical_form() {
	json := program_ast_json('//figure/ancestor::doc') or {
		assert false, 'ast_json: ${err}'
		return
	}
	// Default axis at head (descendant-or-self under //) is bare; explicit
	// `ancestor::` at non-head positions must round-trip with the prefix.
	assert json.contains('ancestor::doc'), 'expected ancestor:: in canonical emit, got: ${json}'
}

fn test_path_atom_literal_unaffected_by_double_colon() {
	// Regression: `:atom` (atom literal) must still parse as a literal
	// after the lexer's `::` lookahead. The atom test only emits
	// double_colon when two consecutive colons appear in source.
	prog := cx.parse_program(':ok') or {
		assert false, 'parse :ok failed: ${err}'
		return
	}
	body := prog.body
	if body is cx.ProgramLiteral {
		assert body.kind == .atom_lit, 'expected atom_lit kind'
		assert body.str_val == 'ok'
	} else {
		assert false, 'expected cx.ProgramLiteral, got ${body.type_name()}'
	}
}

// ── namespace-wildcard NodeTests ──────────────
//
// Three new NodeTest forms beyond `Name` and `*`:
//
//   *:LocalName   any namespace, specific local name
//   Prefix:*      specific namespace, any local name
//   Prefix:Name   fully qualified (regression check for the QName form)
//
// Prefix resolution is first-occurrence-wins across the document's
// xmlns declarations plus the reserved prefixes ('xml', 'cx') per
// spec/namespaces.md §1.4.

// ns_doc_src — a doc that binds two prefixes (xhtml, svg) and uses each
// alongside an unprefixed `user`; shared by the four eval-side tests.
const ns_doc_src = '[doc xmlns:xhtml=http://www.w3.org/1999/xhtml ' +
	'xmlns:svg=http://www.w3.org/2000/svg ' +
	'[xhtml:user "Alice"] ' +
	'[svg:user "Bob"] ' +
	'[user "Charlie"]]'

fn test_path_ns_any_namespace_local_name_parses() {
	prog := cx.parse_program('//*:user') or {
		assert false, 'parse //*:user failed: ${err}'
		return
	}
	body := prog.body
	if body is cx.ProgramPathExpr {
		assert body.steps.len == 1
		s := body.steps[0]
		assert s.ns_kind == .any_ns, 'expected ns_kind=.any_ns'
		assert s.name == 'user'
		assert s.ns_prefix == ''
	} else {
		assert false, 'expected cx.ProgramPathExpr, got ${body.type_name()}'
	}
}

fn test_path_ns_prefix_any_local_parses() {
	prog := cx.parse_program('//xhtml:*') or {
		assert false, 'parse //xhtml:* failed: ${err}'
		return
	}
	body := prog.body
	if body is cx.ProgramPathExpr {
		assert body.steps.len == 1
		s := body.steps[0]
		assert s.ns_kind == .prefix_any_local
		assert s.ns_prefix == 'xhtml'
		assert s.name == '*'
	} else {
		assert false, 'expected cx.ProgramPathExpr'
	}
}

fn test_path_ns_fully_qualified_parses() {
	prog := cx.parse_program('//xhtml:user') or {
		assert false, 'parse //xhtml:user failed: ${err}'
		return
	}
	body := prog.body
	if body is cx.ProgramPathExpr {
		assert body.steps.len == 1
		s := body.steps[0]
		assert s.ns_kind == .prefix_local
		assert s.ns_prefix == 'xhtml'
		assert s.name == 'user'
	} else {
		assert false, 'expected cx.ProgramPathExpr'
	}
}

fn test_path_axis_double_colon_still_unambiguous() {
	// Lexer disambiguation: `descendant::user` uses double_colon (axis
	// separator); `xhtml:user` uses single colon (QName separator).
	// The two token streams must stay distinct after the parser hook
	// for namespace-wildcards landed.
	prog := cx.parse_program('//descendant::user') or {
		assert false, 'parse //descendant::user failed: ${err}'
		return
	}
	body := prog.body
	if body is cx.ProgramPathExpr {
		s := body.steps[0]
		assert s.axis == .descendant
		assert s.axis_explicit
		assert s.ns_kind == .none
		assert s.name == 'user'
	} else {
		assert false, 'expected cx.ProgramPathExpr'
	}
}

fn test_path_ns_any_namespace_matches_all_locals() {
	// `*:user` should match all three: `xhtml:user`, `svg:user`, and
	// the unprefixed `user` — local-name equality, namespace ignored.
	doc := make_doc(ns_doc_src) or {
		assert false, 'doc parse failed: ${err}'
		return
	}
	result := eval_path_against('//*:user', doc) or {
		assert false, 'eval //*:user failed: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 3, 'expected 3 matches for //*:user, got ${names.len}: ${names}'
}

fn test_path_ns_prefix_any_local_matches_namespace_only() {
	// `xhtml:*` matches only elements whose ns_uri equals the xhtml
	// binding's URI — so only `xhtml:user` in the fixture.
	doc := make_doc(ns_doc_src) or {
		assert false, 'doc parse failed: ${err}'
		return
	}
	result := eval_path_against('//xhtml:*', doc) or {
		assert false, 'eval //xhtml:* failed: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 1, 'expected 1 match for //xhtml:*, got ${names.len}: ${names}'
	assert names[0] == 'xhtml:user', 'expected xhtml:user, got ${names[0]}'
}

fn test_path_ns_fully_qualified_matches_namespace_and_local() {
	// `xhtml:user` matches only `xhtml:user` — both namespace URI and
	// local name must coincide. Regression check that landing the
	// namespace-wildcard forms didn't break the QName-NodeTest path.
	doc := make_doc(ns_doc_src) or {
		assert false, 'doc parse failed: ${err}'
		return
	}
	result := eval_path_against('//xhtml:user', doc) or {
		assert false, 'eval //xhtml:user failed: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 1, 'expected 1 match for //xhtml:user, got ${names.len}: ${names}'
	assert names[0] == 'xhtml:user'
}

fn test_path_ns_unbound_prefix_returns_empty() {
	// A prefix with no in-scope binding (and not reserved) yields zero
	// matches: element ns_uri stays none per spec/namespaces.md §2.2,
	// so no candidate satisfies the URI equality check.
	doc := make_doc(ns_doc_src) or {
		assert false, 'doc parse failed: ${err}'
		return
	}
	result := eval_path_against('//unknown:*', doc) or {
		assert false, 'eval //unknown:* failed: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 0, 'expected 0 matches for //unknown:*, got ${names.len}: ${names}'
}

fn test_path_ns_star_colon_star_equivalent_to_star() {
	// Edge case: `*:*` is the any-namespace + any-local form. The
	// any_ns branch matches by local-name equality, and `name='*'`
	// makes that universal — equivalent to plain `*`.
	doc := make_doc('[doc [a 1] [b 2] [c 3]]') or {
		assert false, 'doc parse failed: ${err}'
		return
	}
	r_star := eval_path_against('//*', doc) or {
		assert false, 'eval //* failed: ${err}'
		return
	}
	r_starcolon := eval_path_against('//*:*', doc) or {
		assert false, 'eval //*:* failed: ${err}'
		return
	}
	n1 := element_names(r_star)
	n2 := element_names(r_starcolon)
	assert n1.len == n2.len, 'expected //* and //*:* to match the same count, got ${n1.len} vs ${n2.len}'
	for i, name in n1 {
		assert n2[i] == name, 'expected match at #${i}'
	}
}

fn test_path_ns_reserved_xml_prefix_resolves_unconditionally() {
	// Reserved prefix `xml:` always resolves per spec/namespaces.md §1.4.
	// A doc that uses `xml:base` should be findable via `//xml:*`
	// even without an `xmlns:xml=...` declaration.
	doc := make_doc('[doc [xml:base hello]]') or {
		assert false, 'doc parse failed: ${err}'
		return
	}
	result := eval_path_against('//xml:*', doc) or {
		assert false, 'eval //xml:* failed: ${err}'
		return
	}
	names := element_names(result)
	assert names.len == 1, 'expected 1 match for //xml:*, got ${names.len}'
	assert names[0] == 'xml:base'
}

// ── ast_json round-trip for namespace-wildcard NodeTests ───────────

fn test_path_emits_any_namespace_form_in_canonical_form() {
	json := program_ast_json('//*:user') or {
		assert false, 'ast_json: ${err}'
		return
	}
	assert json.contains('//*:user'), 'expected canonical //*:user emit, got: ${json}'
}

fn test_path_emits_prefix_any_local_form_in_canonical_form() {
	json := program_ast_json('//xhtml:*') or {
		assert false, 'ast_json: ${err}'
		return
	}
	assert json.contains('//xhtml:*'), 'expected canonical //xhtml:* emit, got: ${json}'
}

fn test_path_emits_fully_qualified_form_in_canonical_form() {
	json := program_ast_json('//xhtml:user') or {
		assert false, 'ast_json: ${err}'
		return
	}
	assert json.contains('//xhtml:user'), 'expected canonical //xhtml:user emit, got: ${json}'
}
