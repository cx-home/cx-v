module main

import cx
import code

// Pass-2 Duration/Period type promotion (lexicon [L25]/[L26]).
//
// Duration is an EXACT span ({ns,us,ms,s,m,h,d,w} → i64 ns); Period is a
// CALENDAR span ({mo,y}). Both are first-class ScalarType refinements
// recognized in the data AND program readings, carrying their verbatim CX
// text as the value and rendering bare. This test covers recognition, the
// ::annotation forms, both readings, the binary wire round-trip, and the
// lexing rules (longest-match, whole-token, no mixed family).

fn scalar_of(src string) cx.ScalarNode {
	doc := cx.parse(src) or {
		assert false, 'parse failed: ${err}'
		return cx.ScalarNode{}
	}
	el := doc.elements[0] as cx.Element
	return el.items[0] as cx.ScalarNode
}

// ── Data-reader recognition ──────────────────────────────────────────────────

fn test_data_duration_units() {
	for tok in ['100ms', '1h30m', '90s', '2w', '5d', '250us', '40ns'] {
		s := scalar_of('[t ${tok}]')
		assert s.data_type == .duration_type, '${tok} expected duration, got ${s.data_type}'
		assert (s.value as string) == tok, 'value mismatch for ${tok}'
	}
}

fn test_data_period_units() {
	for tok in ['3mo', '1y', '1y6mo', '18mo'] {
		s := scalar_of('[t ${tok}]')
		assert s.data_type == .period_type, '${tok} expected period, got ${s.data_type}'
	}
}

fn test_data_minutes_vs_months() {
	// `m` is minutes (duration); `mo` is months (period) — longest-match.
	assert scalar_of('[t 5m]').data_type == .duration_type, '5m should be duration'
	assert scalar_of('[t 5mo]').data_type == .period_type, '5mo should be period'
}

fn test_data_non_temporal_stays_text() {
	// Whole-token rule: a trailing non-unit run is NOT a span.
	doc := cx.parse('[t 5mph]') or {
		assert false, '${err}'
		return
	}
	el := doc.elements[0] as cx.Element
	// `5mph` must be a TextNode (or a string scalar), never a duration/period.
	item := el.items[0]
	if item is cx.ScalarNode {
		assert item.data_type != .duration_type && item.data_type != .period_type, '5mph wrongly typed temporal'
	}
}

fn test_data_mixed_family_not_one_literal() {
	// `1y2h` mixes period + duration units → not a single span literal (it
	// becomes Text, not a typed scalar).
	doc := cx.parse('[t 1y2h]') or {
		assert false, '${err}'
		return
	}
	item := (doc.elements[0] as cx.Element).items[0]
	if item is cx.ScalarNode {
		assert item.data_type != .duration_type && item.data_type != .period_type, '1y2h wrongly typed as a span'
	}
}

// ── Explicit annotations ─────────────────────────────────────────────────────

fn test_explicit_duration_period_annotation() {
	assert scalar_of('[t::duration 90m]').data_type == .duration_type, '::duration'
	assert scalar_of('[t::period 2y]').data_type == .period_type, '::period'
}

// ── Binary wire round-trip (the promotion the user asked for) ────────────────

fn test_wire_codec_preserves_duration_period() {
	doc := cx.parse('[a 1h30m]\n[b 1y6mo]') or {
		assert false, '${err}'
		return
	}
	bytes := cx.emit_ast_bin(doc)
	doc2 := cx.bin_to_doc(bytes) or {
		assert false, 'decode: ${err}'
		return
	}
	a := (doc2.elements[0] as cx.Element).items[0] as cx.ScalarNode
	b := (doc2.elements[1] as cx.Element).items[0] as cx.ScalarNode
	assert a.data_type == .duration_type, 'wire lost duration type, got ${a.data_type}'
	assert (a.value as string) == '1h30m', 'wire duration value mismatch'
	assert b.data_type == .period_type, 'wire lost period type, got ${b.data_type}'
	assert (b.value as string) == '1y6mo', 'wire period value mismatch'
}

// ── Program reading ──────────────────────────────────────────────────────────

fn test_program_duration_period_types() {
	dur := code.eval_code('', '2w', 'json') or {
		assert false, '${err}'
		return
	}
	assert dur.contains('"dataType":"duration"'), 'program 2w not duration: ${dur}'
	per := code.eval_code('', '1y6mo', 'json') or {
		assert false, '${err}'
		return
	}
	assert per.contains('"dataType":"period"'), 'program 1y6mo not period: ${per}'
}

fn test_program_renders_bare() {
	for tok in ['100ms', '1h30m', '2w', '5d', '3mo', '1y6mo'] {
		out := code.eval_code('', tok, 'cx') or {
			assert false, '${err}'
			return
		}
		assert out.trim_space() == tok, '${tok} should render bare, got ${out}'
	}
}

fn test_program_invalid_temporal_is_error() {
	if _ := code.eval_code('', '5mph', 'cx') {
		assert false, 'expected lex error for 5mph in program'
	}
}

// ── XML ISO-8601 image (lexicon [L25]/[L26]) ─────────────────────────────────

fn test_cx_to_xml_iso_image() {
	doc := cx.parse('[timeout 90m]\n[span 1y6mo]\n[wk 2w]\n[sub 500ms]') or {
		assert false, '${err}'
		return
	}
	xml := cx.emit_xml(doc)
	// Duration/period bodies carry the ISO 8601 image inside a <cx:T> carrier.
	assert xml.contains('<cx:duration>PT1H30M</cx:duration>'), '90m→ISO: ${xml}'
	assert xml.contains('<cx:period>P1Y6M</cx:period>'), '1y6mo→ISO: ${xml}'
	assert xml.contains('<cx:duration>P2W</cx:duration>'), '2w→ISO: ${xml}'
	assert xml.contains('<cx:duration>PT0.5S</cx:duration>'), '500ms→ISO: ${xml}'
}

fn test_xml_to_cx_round_trip_value_stable() {
	src := '[combo 1h30m]\n[span 1y6mo]\n[sub 500ms]\n[nano 40ns]'
	doc := cx.parse(src) or {
		assert false, '${err}'
		return
	}
	xml := cx.emit_xml(doc)
	doc2 := cx.parse_xml(xml) or {
		assert false, 'xml parse: ${err}'
		return
	}
	// Types survive; values are value-stable (already canonical here).
	c := (doc2.elements[0] as cx.Element).items[0] as cx.ScalarNode
	assert c.data_type == .duration_type && (c.value as string) == '1h30m', 'combo: ${c.value}'
	s := (doc2.elements[1] as cx.Element).items[0] as cx.ScalarNode
	assert s.data_type == .period_type && (s.value as string) == '1y6mo', 'span: ${s.value}'
	n := (doc2.elements[3] as cx.Element).items[0] as cx.ScalarNode
	assert n.data_type == .duration_type && (n.value as string) == '40ns', 'nano: ${n.value}'
}

fn test_iso_helpers_round_trip() {
	assert cx.duration_cx_to_iso('1h30m') or { '' } == 'PT1H30M'
	assert cx.duration_cx_to_iso('2w') or { '' } == 'P2W'
	assert cx.duration_cx_to_iso('10d') or { '' } == 'P10D'
	assert cx.period_cx_to_iso('1y6mo') or { '' } == 'P1Y6M'
	assert cx.iso_to_duration_cx('PT1H30M') or { '' } == '1h30m'
	assert cx.iso_to_period_cx('P1Y6M') or { '' } == '1y6mo'
	// value-stable canonicalization: 90m → ISO → 1h30m
	assert cx.iso_to_duration_cx(cx.duration_cx_to_iso('90m') or { '' }) or { '' } == '1h30m'
}

// ── Datetime range stepped by extended duration unit ─────────────────────────

fn test_datetime_range_by_day_unit() {
	out := code.eval_code('', '[\$range 2024-01-01T00:00:00Z 2024-01-03T00:00:00Z 1d]', 'cx') or {
		assert false, '${err}'
		return
	}
	// lo, lo+1d, lo+2d (inclusive) → three datetimes.
	assert out.contains('2024-01-02T00:00:00Z'), 'range by 1d missing middle step: ${out}'
}
