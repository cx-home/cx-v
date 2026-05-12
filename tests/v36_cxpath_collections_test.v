module main

import cx

// Tests for v0.6.0 / cxpath v1.1 / ADR 0017 §D13 — union operator `|`,
// sequence-literal sugar `(p1, p2)`, and map-key access `.key` /
// `['key']`. Array indexing `arr[N]` continues to evaluate as the v1.0
// position predicate for element-returning APIs (the runtime
// type-disambiguation per spec promotes it to array indexing once
// value-returning paths land with the CXL evaluator at §F).

// ── Union operator ──────────────────────────────────────────────────────────

fn test_cxpath_union_two_paths() {
	doc := cx.parse('[root [services [a port=80] [b port=81]] [products [a port=90]]]') or {
		panic(err)
	}
	// Union of two descendant paths returns both subtrees.
	got := doc.select_all('//services/a | //products/a')
	assert got.len == 2
	assert got[0].name == 'a'
	assert got[1].name == 'a'
	// Left alternative's match precedes the right alternative's per spec.
	assert got[0].attr('port') == '80'
	assert got[1].attr('port') == '90'
}

fn test_cxpath_union_three_paths() {
	doc := cx.parse('[root [a x=1] [b x=2] [c x=3]]') or { panic(err) }
	got := doc.select_all('//a | //b | //c')
	assert got.len == 3
	assert got[0].name == 'a'
	assert got[1].name == 'b'
	assert got[2].name == 'c'
}

fn test_cxpath_union_dedup_structural() {
	// Two alternatives that both match the same element produce one
	// occurrence in the union per ADR 0017 §D13.
	doc := cx.parse('[root [a id=1]]') or { panic(err) }
	got := doc.select_all('//a | //a')
	assert got.len == 1
}

// ── Sequence-literal sugar ──────────────────────────────────────────────────

fn test_cxpath_sequence_literal_two_paths() {
	doc := cx.parse('[root [s [a id=1]] [p [a id=2]]]') or { panic(err) }
	got := doc.select_all('(//s/a, //p/a)')
	assert got.len == 2
	assert got[0].attr('id') == '1'
	assert got[1].attr('id') == '2'
}

fn test_cxpath_sequence_literal_equivalent_to_union() {
	doc := cx.parse('[root [a id=1] [b id=2]]') or { panic(err) }
	via_union := doc.select_all('//a | //b')
	via_seq := doc.select_all('(//a, //b)')
	assert via_union.len == via_seq.len
	for i, el in via_union {
		assert el.name == via_seq[i].name
	}
}

// ── Map-key access ──────────────────────────────────────────────────────────

fn test_cxpath_map_key_bare_name() {
	doc := cx.parse('[root [cfg {primary: [server host=a], backup: [server host=b]}]]') or {
		panic(err)
	}
	got := doc.select_all('//cfg.primary')
	assert got.len == 1
	assert got[0].name == 'server'
	assert got[0].attr('host') == 'a'
}

fn test_cxpath_map_key_quoted() {
	doc := cx.parse("[root [cfg {primary: [server host=a]}]]") or { panic(err) }
	got := doc.select_all("//cfg['primary']")
	assert got.len == 1
	assert got[0].name == 'server'
}

fn test_cxpath_map_key_chain() {
	// `.outer.inner` — first .outer matches a MapNode with key 'outer'
	// whose value is an Element containing a MapNode with key 'inner'.
	doc := cx.parse(
		'[root [cfg {outer: [grp {inner: [leaf z=42]}]}]]'
	) or { panic(err) }
	got := doc.select_all('//cfg.outer.inner')
	assert got.len == 1
	assert got[0].name == 'leaf'
}

fn test_cxpath_map_key_missing_returns_empty() {
	doc := cx.parse('[root [cfg {primary: [server host=a]}]]') or { panic(err) }
	got := doc.select_all('//cfg.absent')
	assert got.len == 0
}

fn test_cxpath_map_key_non_element_value_returns_empty() {
	// v0.6.0 element-returning surface returns empty when a key
	// resolves to a Scalar value; full value semantics land with §F.
	doc := cx.parse('[root [cfg {answer: 42}]]') or { panic(err) }
	got := doc.select_all('//cfg.answer')
	assert got.len == 0
}

// ── Disambiguation / regression guards ──────────────────────────────────────

fn test_cxpath_existing_path_unchanged() {
	// v1.0 paths must continue to parse & evaluate identically; the
	// v1.1 additions are strictly additive.
	doc := cx.parse('[root [a port=80] [a port=81]]') or { panic(err) }
	got := doc.select_all('//a[@port=80]')
	assert got.len == 1
	assert got[0].attr('port') == '80'
}

fn test_cxpath_position_predicate_unchanged() {
	// Existing `arr[N]` position-predicate semantics for element
	// sequences continue per ADR §D13 (LHS type-based disambiguation:
	// element-sequence LHS uses position predicate; array-value LHS
	// uses array indexing — the latter requires §F value semantics).
	doc := cx.parse('[root [a id=1] [a id=2] [a id=3]]') or { panic(err) }
	got := doc.select_all('//a[2]')
	assert got.len == 1
	assert got[0].attr('id') == '2'
}
