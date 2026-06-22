module main

import cx

// v0.8.0 — `--lossless` XML (conversions.md §0.2) + the CXLS007 ambiguous
// string-list warning premise.
//
// (a) emit_xml_lossless tags each typed scalar with its `<cx:T>` carrier so the
//     XML→CX round-trip is faithful, WITHOUT changing the idiomatic (default)
//     form. The headline case: adjacent string items `[x "a" "b"]` keep their
//     boundary as `<cx:string>` carriers (the default collapses them to `ab`).
// (b) the LSP CXLS007 warning fires on a cx_element body with ≥2 adjacent
//     QUOTED-string items; this test pins the parse_program shape the detector
//     relies on (and that the comma form is distinct → no false positive).

fn lossless_xml(src string) string {
	return cx.to_xml_lossless(src) or { panic('to_xml_lossless: ${err}') }
}

fn default_xml(src string) string {
	return cx.to_xml(src) or { panic('to_xml: ${err}') }
}

// ── (a) the default (lossy) form is UNCHANGED ────────────────────────────────

fn test_default_unchanged_single_scalar() {
	assert default_xml('[x 1]') == '<x>1</x>'
	assert default_xml('[x :ok]') == '<x>ok</x>'
	assert default_xml('[d 2024-01-15]') == '<d>2024-01-15</d>'
}

fn test_default_unchanged_string_list_collapses() {
	// The idiomatic form collapses adjacent strings (documented, accepted).
	assert default_xml('[x "a" "b"]') == '<x>ab</x>'
}

fn test_default_unchanged_prose() {
	assert default_xml('[p the quick fox]') == '<p>the quick fox</p>'
}

fn test_default_unchanged_typed_list() {
	// Non-string scalars already carry `<cx:T>` in BOTH modes.
	assert default_xml('[x 1 2]') == '<x><cx:int>1</cx:int><cx:int>2</cx:int></x>'
}

// ── (a) lossless adds per-item `<cx:T>` carriers ─────────────────────────────

fn test_lossless_string_list_carriers() {
	// The headline case — adjacent string items keep their boundary.
	assert lossless_xml('[x "a" "b"]') == '<x><cx:string>a</cx:string><cx:string>b</cx:string></x>'
}

fn test_lossless_single_scalar_carrier() {
	assert lossless_xml('[x 1]') == '<x><cx:int>1</cx:int></x>'
	assert lossless_xml('[x :ok]') == '<x><cx:atom>ok</cx:atom></x>'
	assert lossless_xml('[d 2024-01-15]') == '<d><cx:date>2024-01-15</cx:date></d>'
}

fn test_lossless_single_string_stays_bare() {
	// A SINGLE string re-infers as string — no carrier needed (conversions.md
	// §0.2: string XML lossless = default).
	assert lossless_xml('[x hi]') == '<x>hi</x>'
}

fn test_lossless_prose_stays_bare() {
	assert lossless_xml('[p the quick fox]') == '<p>the quick fox</p>'
}

fn test_lossless_mixed_list() {
	assert lossless_xml('[mixed 1 "two" :three true]') == '<mixed><cx:int>1</cx:int><cx:string>two</cx:string><cx:atom>three</cx:atom><cx:bool>true</cx:bool></mixed>'
}

// ── (a) faithful round-trip: cx → lossless xml → cx-node ──────────────────────

fn body_item_count(src string) int {
	doc := cx.parse(src) or { panic('parse: ${err}') }
	for n in doc.elements {
		if n is cx.Element {
			return n.items.len
		}
	}
	return -1
}

fn roundtrip_item_count(src string) int {
	xml := lossless_xml(src)
	doc := cx.parse_xml(xml) or { panic('parse_xml: ${err}') }
	for n in doc.elements {
		if n is cx.Element {
			return n.items.len
		}
	}
	return -1
}

fn test_lossless_roundtrip_preserves_string_list_items() {
	// `[x "a" "b"]` is TWO string items; the lossless XML→CX round-trip must
	// preserve both (the default form would collapse them to one).
	assert body_item_count('[x "a" "b"]') == 2
	assert roundtrip_item_count('[x "a" "b"]') == 2
}

fn test_lossless_roundtrip_preserves_atom_type() {
	xml := lossless_xml('[x :ok]')
	doc := cx.parse_xml(xml) or { panic('parse_xml: ${err}') }
	mut found_atom := false
	for n in doc.elements {
		if n is cx.Element {
			for it in n.items {
				if it is cx.ScalarNode {
					if it.data_type == .atom_type {
						found_atom = true
					}
				}
			}
		}
	}
	assert found_atom, 'atom type lost on lossless XML round-trip'
}

// ── (b) CXLS007 detection premise — parse_program shape ──────────────────────

fn cx_element_items(src string) []cx.ProgramNode {
	prog := cx.parse_program(src) or { panic('parse_program: ${err}') }
	lit := prog.body as cx.ProgramLiteral
	assert lit.kind == .cx_element, 'expected cx_element, got ${lit.kind}'
	return lit.items
}

fn test_warning_premise_two_quoted_strings_are_adjacent_items() {
	// `[x "a" "b"]` → cx_element with two adjacent string_lit items, each whose
	// SOURCE position points at a quote. This is exactly what CXLS007 detects.
	src := '[x "a" "b"]'
	items := cx_element_items(src)
	assert items.len == 2
	mut quoted := 0
	for it in items {
		if it is cx.ProgramLiteral {
			if it.kind == .string_lit {
				c := src[it.pos.offset]
				if c == `"` || c == `'` {
					quoted++
				}
			}
		}
	}
	assert quoted == 2, 'expected 2 quoted string items, got ${quoted}'
}

fn test_warning_premise_comma_form_does_not_parse_as_program() {
	// `[x "a", "b"]` (the comma array) is NOT valid program-body syntax — a
	// top-level comma in element-body expression position is a parse error. So
	// CXLS007 (which runs on parse_program and bails on parse failure) can never
	// false-positive on the comma form; it only sees the no-comma ambiguous shape.
	if _ := cx.parse_program('[x "a", "b"]') {
		assert false, 'expected the comma array form to be a program parse error'
	}
}

fn test_warning_premise_single_quoted_string_is_not_flagged() {
	// A SINGLE quoted string is not ambiguous (no adjacent sibling) — exactly one
	// item, so the ≥2-run detector never triggers.
	items := cx_element_items('[x "a"]')
	assert items.len == 1
}
