module main

import cx

// GG13 — Document.resolve_body_ref() helper. Maps an Element with
// a body-position [ref @id] form to the target Element declaring that
// id, walking the same ID table resolve_id() uses.

fn test_resolve_body_ref_finds_target() {
	src := '[doc [section #s-1 [title Intro]] [para See [ref @s-1] for context.]]'
	doc := cx.parse(src) or { panic(err) }
	cx.resolve_ids(doc) or { panic(err) }
	// Walk to the [ref @s-1] element inside the para.
	doc_el := doc.elements[0] as cx.Element
	para := doc_el.items[1] as cx.Element
	mut ref_el := cx.Element{}
	for it in para.items {
		if it is cx.Element {
			if it.name == 'ref' && it.body_ref != none {
				ref_el = it
				break
			}
		}
	}
	target := doc.resolve_body_ref(ref_el) or { panic('resolve_body_ref returned none') }
	assert target.name == 'section', 'expected section, got: ${target.name}'
	if id_val := target.id {
		assert id_val == 's-1', 'expected s-1, got: ${id_val}'
	} else {
		panic('target.id is none')
	}
}

fn test_resolve_body_ref_undeclared_id_returns_none() {
	// Parse a valid doc, then call resolve_body_ref with a synthetic
	// Element whose body_ref points at an undeclared id. (Parsing
	// `[ref @nonexistent]` directly would trip the validator —
	// resolve_body_ref is the lookup primitive, not the validator.)
	src := '[doc [section #s-1]]'
	doc := cx.parse(src) or { panic(err) }
	cx.resolve_ids(doc) or { panic(err) }
	synthetic := cx.Element{ name: 'ref', body_ref: ?string('nonexistent') }
	if _ := doc.resolve_body_ref(synthetic) {
		assert false, 'expected none for undeclared id'
	}
}

fn test_resolve_body_ref_no_body_ref_returns_none() {
	src := '[doc [item name=foo]]'
	doc := cx.parse(src) or { panic(err) }
	doc_el := doc.elements[0] as cx.Element
	item := doc_el.items[0] as cx.Element
	if _ := doc.resolve_body_ref(item) {
		assert false, 'expected none for element with no body_ref'
	}
}

// GG9 — CXPath [#bodyref=id-name] predicate matches elements whose
// body_ref equals the given id.

fn test_cxpath_bodyref_predicate_matches() {
	src := '[doc [section #s-1 [title T]] [para See [ref @s-1] for context.]]'
	doc := cx.parse(src) or { panic(err) }
	cx.resolve_ids(doc) or { panic(err) }
	matches := doc.select_all('//ref[#bodyref=s-1]')
	assert matches.len == 1, 'expected 1 match, got ${matches.len}'
	first := matches[0]
	assert first.name == 'ref', 'expected ref, got ${first.name}'
	if br := first.body_ref {
		assert br == 's-1', 'expected s-1, got ${br}'
	} else {
		panic('body_ref missing')
	}
}

fn test_cxpath_bodyref_predicate_no_match() {
	src := '[doc [section #s-1] [para [ref @s-1]]]'
	doc := cx.parse(src) or { panic(err) }
	cx.resolve_ids(doc) or { panic(err) }
	matches := doc.select_all('//ref[#bodyref=nonexistent]')
	assert matches.len == 0, 'expected 0 matches for nonexistent body-ref, got ${matches.len}'
}

fn test_cxpath_bodyref_predicate_with_star() {
	// `//*[#bodyref=id-name]` matches any element with that body_ref.
	src := '[doc [section #s-1] [para [ref @s-1]]]'
	doc := cx.parse(src) or { panic(err) }
	cx.resolve_ids(doc) or { panic(err) }
	matches := doc.select_all('//*[#bodyref=s-1]')
	assert matches.len == 1, 'expected 1 match via star, got ${matches.len}'
}
