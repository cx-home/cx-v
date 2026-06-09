module main

import cx

// Phase 7.74c-datetime-foundations — strict-cell datetime wire form.
// Covers parse_iso_datetime_canonical edge cases, format_iso_datetime_utc
// reconstruction, and chunked-table strict-cell datetime round-trip.
// Spec: spec/core/data-bin.md §3.6.1.

// ── parse_iso_datetime_canonical ─────────────────────────────────────────────

fn test_parse_iso_datetime_zulu() {
	ns, off := cx.parse_iso_datetime_canonical('1970-01-01T00:00:00Z') or {
		panic('parse failed: ${err}')
	}
	assert ns == 0, 'expected ns=0 for Unix epoch; got ${ns}'
	assert off == 0
}

fn test_parse_iso_datetime_positive_offset() {
	// 2024-01-15T12:34:56+05:30 = local 12:34:56, UTC 07:04:56
	ns, off := cx.parse_iso_datetime_canonical('2024-01-15T12:34:56+05:30') or {
		panic('parse failed: ${err}')
	}
	// UTC equivalent string:
	round := cx.format_iso_datetime_utc(ns, 0)
	assert round == '2024-01-15T07:04:56Z', 'got ${round}'
	assert off == i16(330)
}

fn test_parse_iso_datetime_negative_offset() {
	// 2024-01-15T12:34:56-08:00 = UTC 20:34:56
	ns, off := cx.parse_iso_datetime_canonical('2024-01-15T12:34:56-08:00') or {
		panic('parse failed: ${err}')
	}
	round := cx.format_iso_datetime_utc(ns, 0)
	assert round == '2024-01-15T20:34:56Z', 'got ${round}'
	assert off == i16(-480)
}

fn test_parse_iso_datetime_naive_treated_as_utc() {
	ns, off := cx.parse_iso_datetime_canonical('2024-01-15T12:34:56') or {
		panic('parse failed: ${err}')
	}
	round := cx.format_iso_datetime_utc(ns, 0)
	assert round == '2024-01-15T12:34:56Z', 'got ${round}'
	assert off == 0
}

fn test_parse_iso_datetime_fractional_seconds() {
	ns, _ := cx.parse_iso_datetime_canonical('2024-01-15T12:34:56.123456789Z') or {
		panic('parse failed: ${err}')
	}
	round := cx.format_iso_datetime_utc(ns, 0)
	assert round == '2024-01-15T12:34:56.123456789Z', 'got ${round}'
}

fn test_parse_iso_datetime_fractional_truncates_beyond_ns() {
	// 12 digits after dot → truncate to 9.
	ns, _ := cx.parse_iso_datetime_canonical('2024-01-15T12:34:56.123456789012Z') or {
		panic('parse failed: ${err}')
	}
	round := cx.format_iso_datetime_utc(ns, 0)
	assert round == '2024-01-15T12:34:56.123456789Z', 'got ${round}'
}

fn test_parse_iso_datetime_fractional_pads_ns() {
	// 3 digits after dot → 0.123 s → 123_000_000 ns.
	ns, _ := cx.parse_iso_datetime_canonical('2024-01-15T12:34:56.123Z') or {
		panic('parse failed: ${err}')
	}
	round := cx.format_iso_datetime_utc(ns, 0)
	assert round == '2024-01-15T12:34:56.123Z', 'got ${round}'
}

fn test_parse_iso_datetime_pre_epoch() {
	// 1969-12-31T23:59:59Z = -1 second from epoch.
	ns, _ := cx.parse_iso_datetime_canonical('1969-12-31T23:59:59Z') or {
		panic('parse failed: ${err}')
	}
	assert ns == i64(-1_000_000_000), 'expected -1e9 ns; got ${ns}'
	round := cx.format_iso_datetime_utc(ns, 0)
	assert round == '1969-12-31T23:59:59Z', 'got ${round}'
}

fn test_parse_iso_datetime_rejects_leap_second() {
	cx.parse_iso_datetime_canonical('2024-06-30T23:59:60Z') or {
		assert err.msg().contains('leap'), 'expected leap-second error; got ${err.msg()}'
		return
	}
	assert false, 'expected error on leap second'
}

fn test_parse_iso_datetime_rejects_bad_month() {
	cx.parse_iso_datetime_canonical('2024-13-01T00:00:00Z') or { return }
	assert false, 'expected error on month 13'
}

fn test_parse_iso_datetime_rejects_malformed() {
	cx.parse_iso_datetime_canonical('not-a-datetime') or { return }
	assert false, 'expected error on malformed input'
}

// ── chunked-table strict-cell datetime round-trip ────────────────────────────

fn test_chunked_datetime_column_round_trip() {
	src := '[evts [table[name::string when::datetime]]
  alpha 2024-01-15T12:34:56Z
  beta  2025-06-30T23:00:00+02:00
  gamma 2023-12-25T08:15:30.250Z
]'
	doc := cx.parse(src) or { panic('parse failed: ${err}') }
	bytes := cx.emit_data_bin_chunked(doc, cx.ChunkedEmitOptions{ chunk_size: 4, compress: .never }) or {
		panic('chunked emit failed: ${err}')
	}
	doc2 := cx.parse_data_bin(bytes) or { panic('decode failed: ${err}') }
	cx_out := cx.emit_cx(doc2)

	// Names round-trip; UTC normalization makes +02:00 → 21:00 prior day.
	assert cx_out.contains('alpha'), 'missing alpha row: ${cx_out}'
	assert cx_out.contains('2024-01-15T12:34:56Z'), 'missing first datetime: ${cx_out}'
	assert cx_out.contains('2025-06-30T21:00:00Z'),
		'expected UTC-normalized 2025-06-30T21:00:00Z; got: ${cx_out}'
	assert cx_out.contains('2023-12-25T08:15:30.25Z'),
		'expected fractional truncated trailing zero; got: ${cx_out}'
}
