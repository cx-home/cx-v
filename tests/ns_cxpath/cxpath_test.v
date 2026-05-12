module main

// CXPath namespace-aware predicate tests (ADR 0002, spec/cxpath.md).
// Verifies:
//   - Prefixed element name tests resolve query prefix via document
//     xmlns declarations and match by expanded name (ns_uri + local).
//   - Prefixed attribute predicates resolve identically.
//   - Unbound query prefixes fall back to verbatim source-name match
//     (back-compat with namespace-free CXPath usage).
//   - local-name() and namespace-uri() predicate functions.
//   - Reserved xml:/cx: prefixes are always available.
//   - Cross-prefix equivalence: a document declaring `xmlns:foo=urn:x`
//     and one declaring `xmlns:bar=urn:x` both match the query
//     `//*[namespace-uri()='urn:x']`.

import cx

fn parse_or_panic(src string) cx.Document {
	return cx.parse(src) or { panic('parse failed: ${err}') }
}

fn names_of(els []cx.Element) []string {
	return els.map(it.name)
}

fn test_prefixed_name_test_matches_via_ns_map() {
	doc := parse_or_panic('
[chapter xmlns:dc=http://purl.org/dc/elements/1.1/
  [dc:title "Intro"]
  [dc:author "Alice"]
  [section
    [dc:title "Section title"]
  ]
]
')
	results := doc.select_all('//dc:title')
	assert results.len == 2
	for r in results {
		assert r.local == 'title'
		assert r.ns_uri or { '' } == 'http://purl.org/dc/elements/1.1/'
	}
}

fn test_prefixed_attr_predicate() {
	doc := parse_or_panic('
[doc xmlns:xl=http://www.w3.org/1999/xlink
  [link xl:href=https://example.com text]
  [link href=plain plain-link]
]
')
	with_xl := doc.select_all('//link[@xl:href]')
	assert with_xl.len == 1
	assert with_xl[0].attrs.any(it.name == 'xl:href')

	plain := doc.select_all('//link[@href]')
	assert plain.len == 1
}

fn test_unbound_query_prefix_falls_back_to_source_match() {
	// `nope:` is not declared — the query must fall back to
	// matching the literal source name `nope:thing`. This preserves
	// back-compat for namespace-free queries that happen to use
	// colon-bearing identifiers.
	doc := parse_or_panic('
[root
  [nope:thing literal]
]
')
	results := doc.select_all('//nope:thing')
	assert results.len == 1
}

fn test_local_name_function() {
	doc := parse_or_panic('
[root xmlns:a=urn:a xmlns:b=urn:b
  [a:item id=1]
  [b:item id=2]
  [item id=3]
]
')
	any_item := doc.select_all("//*[local-name()='item']")
	assert any_item.len == 3
	ids := any_item.map(it.attr('id'))
	assert '1' in ids
	assert '2' in ids
	assert '3' in ids
}

fn test_namespace_uri_function() {
	doc := parse_or_panic('
[root xmlns:a=urn:a xmlns:b=urn:b
  [a:item id=1]
  [b:item id=2]
  [item id=3]
]
')
	in_a := doc.select_all("//*[namespace-uri()='urn:a']")
	assert in_a.len == 1
	assert in_a[0].attr('id') == '1'

	no_ns := doc.select_all("//*[namespace-uri()='']")
	// 'root' has no ns_uri (declarations only), 'item' has no ns_uri.
	// In subtree from virtual_root, descendants only — root included.
	assert no_ns.len >= 1
	assert no_ns.any(it.name == 'item')
}

fn test_reserved_xml_prefix_resolves() {
	doc := parse_or_panic('
[doc xml:base=https://example.com
  [child xml:id=c1 body]
]
')
	// `xml:` always resolves to the XML built-in URI even without
	// an xmlns:xml declaration.
	with_xml_id := doc.select_all('//child[@xml:id]')
	assert with_xml_id.len == 1
}

fn test_cross_prefix_equivalence_via_namespace_uri() {
	// Same URI, different prefix choice — namespace-uri() finds
	// both equally.
	doc_a := parse_or_panic('
[root xmlns:foo=urn:shared
  [foo:thing tag=A]
]
')
	doc_b := parse_or_panic('
[root xmlns:bar=urn:shared
  [bar:thing tag=B]
]
')
	a := doc_a.select_all("//*[namespace-uri()='urn:shared']")
	b := doc_b.select_all("//*[namespace-uri()='urn:shared']")
	assert a.len == 1
	assert b.len == 1
	assert a[0].local == 'thing'
	assert b[0].local == 'thing'
}

fn test_prefixed_query_works_across_prefix_redeclaration() {
	// xmlns:p declares urn:outer at root; nested redeclaration
	// rebinds to urn:inner. A `//p:item` query resolves p against
	// the FIRST occurrence (urn:outer), so it matches the outer
	// items but NOT the inner one. Document the behavior — this is
	// the v0.6.0 "first-occurrence-wins" CXPath ns-map convention.
	doc := parse_or_panic('
[outer xmlns:p=urn:outer
  [p:item v=1]
  [inner xmlns:p=urn:inner
    [p:item v=2]
  ]
  [p:item v=3]
]
')
	results := doc.select_all('//p:item')
	// All three p:item elements have ns_uri set by resolve_namespaces:
	//   - v=1: urn:outer
	//   - v=2: urn:inner
	//   - v=3: urn:outer
	// Query prefix p resolves to urn:outer (first occurrence). So
	// v=1 and v=3 match; v=2 does not.
	values := results.map(it.attr('v'))
	assert results.len == 2
	assert '1' in values
	assert '3' in values
	assert '2' !in values
}

fn test_id_predicate_matches_declared_id() {
	// ADR 0003 D8: `[#id]` matches the element whose syntactic ID
	// equals the given string. Distinct from `[@id=...]` (attribute
	// equality) and from `[name]` (child existence).
	doc := parse_or_panic('
[users
  [user #u-1 name=alice]
  [user #u-2 name=bob]
  [user name=charlie]
]
')
	matches := doc.select_all('//user[#u-1]')
	assert matches.len == 1
	assert matches[0].attr('name') == 'alice'

	none_match := doc.select_all('//user[#u-99]')
	assert none_match.len == 0

	// Wildcard with [#id]: any element with that ID.
	any_match := doc.select_all('//*[#u-2]')
	assert any_match.len == 1
	assert any_match[0].attr('name') == 'bob'
}

fn test_select_on_element_uses_local_ns_map() {
	doc := parse_or_panic('
[root
  [section xmlns:s=urn:section
    [s:para text=hello]
  ]
]
')
	section := doc.select('//section') or { panic('no section') }
	paras := section.select_all('//s:para')
	assert paras.len == 1
}

