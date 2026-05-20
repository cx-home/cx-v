// Z-row — cx:lang attribute + inherited-scope semantics per
// spec/i18n.md §1. Verifies that resolve_namespaces (and its
// language-scope pass) populates Element.lang_resolved per the
// spec's inheritance rules:
//   §1.3 — descendant inherits ancestor's cx:lang until redeclared
//   §1.4 — cx:lang="" shadows without substituting (Some(""))
//   §1.1 — values are BCP 47 tags; parser does not validate against
//          the IANA registry (any well-formed tag passes)

module main

import cx

fn find_element_named(items []cx.Node, name string) ?cx.Element {
	for it in items {
		if it is cx.Element {
			el := it as cx.Element
			if el.name == name {
				return el
			}
			if found := find_element_named(el.items, name) {
				return found
			}
		}
	}
	return none
}

fn test_cxlang_local_declaration() {
	doc := cx.parse('[para cx:lang=en Hello]') or { panic(err) }
	root := find_element_named(doc.elements, 'para') or {
		panic('no para element')
	}
	assert root.lang() == 'en', 'got: ${root.lang()}'
}

fn test_cxlang_inheritance() {
	src := '[doc cx:lang=en [title English] [body [span English content]]]'
	doc := cx.parse(src) or { panic(err) }
	span := find_element_named(doc.elements, 'span') or {
		panic('no span element')
	}
	assert span.lang() == 'en', 'span should inherit en, got: ${span.lang()}'
}

fn test_cxlang_redeclaration() {
	src := '[doc cx:lang=en [aside cx:lang=fr [deep Still French]]]'
	doc := cx.parse(src) or { panic(err) }
	deep := find_element_named(doc.elements, 'deep') or {
		panic('no deep element')
	}
	assert deep.lang() == 'fr', 'deep should inherit fr, got: ${deep.lang()}'
}

fn test_cxlang_empty_shadows() {
	src := "[doc cx:lang=en [secret cx:lang='' [data x]]]"
	doc := cx.parse(src) or { panic(err) }
	data := find_element_named(doc.elements, 'data') or {
		panic('no data element')
	}
	// Per spec §1.4, cx:lang="" means "no language declared for this
	// subtree" — Element.lang() flattens to "" (same as no scope).
	assert data.lang() == '', 'data should have shadowed scope, got: ${data.lang()}'
}

fn test_cxlang_no_declaration_anywhere() {
	src := '[doc [title plain] [body plain]]'
	doc := cx.parse(src) or { panic(err) }
	body := find_element_named(doc.elements, 'body') or {
		panic('no body element')
	}
	assert body.lang() == '', 'no cx:lang in scope, got: ${body.lang()}'
}

fn test_cxlang_bcp47_passthrough() {
	// BCP 47 forms per spec/i18n.md §1.1.
	cases := [
		'en',
		'zh-Hans',
		'en-US',
		'zh-Hans-CN',
		'de-1996',
		'x-klingon',
	]
	for tag in cases {
		src := '[el cx:lang=${tag} content]'
		doc := cx.parse(src) or { panic('parse failed for tag ${tag}: ${err}') }
		el := find_element_named(doc.elements, 'el') or {
			panic('no el element for tag ${tag}')
		}
		assert el.lang() == tag, 'tag ${tag}: got ${el.lang()}'
	}
}

fn test_cxlang_sibling_isolation() {
	// Sibling subtrees with different cx:lang values do not bleed into
	// each other.
	src := '[doc [en cx:lang=en [body english]] [fr cx:lang=fr [body french]]]'
	doc := cx.parse(src) or { panic(err) }
	root_doc := doc.elements[0] as cx.Element
	en_branch := root_doc.items[0] as cx.Element
	fr_branch := root_doc.items[1] as cx.Element
	en_body := en_branch.items[0] as cx.Element
	fr_body := fr_branch.items[0] as cx.Element
	assert en_body.lang() == 'en', 'en/body: ${en_body.lang()}'
	assert fr_body.lang() == 'fr', 'fr/body: ${fr_body.lang()}'
}
