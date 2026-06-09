module main

import cx

// v08_typed_attr_test — D3 (conversions.md §2.1): typed scalar attributes
// `name::T=value` and their lossless CX⇄XML round-trip via the reserved
// `cx:attr-types` sidecar.
//
// Coverage:
//   • the glued `name::T=value` form PARSES (it previously fell through to
//     element body text) and coerces the value to T;
//   • attributes are scalar-only (D2) — an array type `::T[]` is an error;
//   • CX canonical emit: auto-recoverable types stay bare, atoms keep the
//     `:` sigil, sized/decimal/bigint/bytes carry the glued annotation;
//   • CX→XML emits a `cx:attr-types` sidecar listing exactly the types the
//     XML→CX auto-typer can't recover (and explicit-string-over-numeric);
//   • XML→CX import applies the sidecar (overriding) + auto-types the rest;
//   • the full CX→XML→CX round-trip is data-equivalent.

// canon renders via cx.emit_cx — the canonical-CX emitter behind
// `cx canonical` / `cx --to=cx`, i.e. the D3 round-trip path.
fn canon(src string) string {
	doc := cx.parse(src) or { return 'REJECT: ${err}' }
	return cx.emit_cx(doc).trim_space()
}

fn to_xml(src string) string {
	doc := cx.parse(src) or { return 'REJECT: ${err}' }
	return cx.emit_xml(doc).trim_space()
}

fn xml_to_cx(xml string) string {
	doc := cx.parse_xml(xml) or { return 'REJECT: ${err}' }
	return cx.emit_cx(doc).trim_space()
}

// ── parsing: the glued form is now a typed attribute, not body text ────────

fn test_typed_attr_parses() {
	doc := cx.parse('[event count::u16=5]') or {
		assert false, 'parse: ${err}'
		return
	}
	e := doc.elements[0] as cx.Element
	assert e.attrs.len == 1, 'expected 1 attr, got ${e.attrs.len} (items=${e.items.len})'
	a := e.attrs[0]
	assert a.name == 'count'
	dt := a.data_type() or {
		assert false, 'count has no data_type'
		return
	}
	assert dt == 'u16', 'expected u16, got ${dt}'
	assert a.value as i64 == 5
}

fn test_typed_attr_value_coercion() {
	// `::int`/`::u16` coerce to i64; `::decimal`/`::bigint`/`::atom` keep the
	// string payload; `::string` stays a raw string even over a numeric form.
	assert canon('[e n::i32=42]') == '[e n::i32=42]'
	assert canon('[e d::decimal=1.50]') == '[e d::decimal=1.50]'
	assert canon('[e big::bigint=99999999999999999999]') == '[e big::bigint=99999999999999999999]'
	assert canon('[e k::atom=urgent]') == '[e k=:urgent]' // atom canonicalises to the sigil
	assert canon("[e code::string=007]") == "[e code='007']"
}

// ── D2: attributes are scalar-only ─────────────────────────────────────────

fn test_array_type_attr_is_error() {
	r := canon('[e xs::int[]=5]')
	assert r.starts_with('REJECT'), r
	assert r.contains('CXER0100'), r
}

// ── canonical emit: auto-recoverable types stay bare (no annotation) ───────

fn test_auto_recoverable_stays_bare() {
	assert canon('[e count::int=5]') == '[e count=5]'
	assert canon('[e active::bool=true]') == '[e active=true]'
	assert canon('[e when::date=2024-01-15]') == '[e when=2024-01-15]'
}

// ── CX→XML: the cx:attr-types sidecar ──────────────────────────────────────

fn test_xml_sidecar_emit() {
	got := to_xml('[event count::u16=5 score::decimal=1.5 tag::atom=urgent host=db-1]')
	assert got == '<event count="5" score="1.5" tag="urgent" host="db-1" cx:attr-types="count=u16 score=decimal tag=atom"/>', got
}

fn test_xml_no_sidecar_when_all_auto() {
	// int/bool/date round-trip from the lexical form — no sidecar at all.
	got := to_xml('[event count=5 active=true when=2024-01-15 host=db-1]')
	assert got == '<event count="5" active="true" when="2024-01-15" host="db-1"/>', got
}

fn test_xml_sidecar_string_over_numeric() {
	// A quoted numeric-looking string would auto-type to int on import, so it
	// is pinned with a `=string` sidecar entry.
	got := to_xml("[event code='007']")
	assert got == '<event code="007" cx:attr-types="code=string"/>', got
}

// ── XML→CX: import auto-typing + sidecar application ────────────────────────

fn test_xml_import_autotypes() {
	got := xml_to_cx('<event count="5" active="true" when="2024-01-15" host="db-1"/>')
	assert got == '[event count=5 active=true when=2024-01-15 host=db-1]', got
}

fn test_xml_import_applies_sidecar() {
	got := xml_to_cx('<event count="5" score="1.5" tag="urgent" host="db-1" cx:attr-types="count=u16 score=decimal tag=atom"/>')
	assert got == '[event count::u16=5 score::decimal=1.5 tag=:urgent host=db-1]', got
}

fn test_xml_import_pins_string() {
	got := xml_to_cx('<event code="007" cx:attr-types="code=string"/>')
	assert got == "[event code='007']", got
}

// ── the round-trip is data-equivalent ──────────────────────────────────────

fn test_round_trip_equivalent() {
	src := '[event count::u16=5 score::decimal=1.5 tag::atom=urgent host=db-1]'
	round := xml_to_cx(to_xml(src))
	// canonicalise the source too — atoms normalise to the sigil form.
	assert round == canon(src), 'round=${round}\ncanon=${canon(src)}'
}
