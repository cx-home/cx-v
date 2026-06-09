module main

import cx

// cxparse_temporal_fork_test — the date/datetime recognizers unified into
// cx/lexical.v (cxparse Phase 1, batch 4). The strictness fork is now CONVERGED
// (Phase 3): all three derive from the ONE strict temporal grammar.
//
//   cx.temporal_len  — STRICT byte scanner (full [L23]/[L24] + glued-name guard);
//                      the program lexer's token-boundary recognizer.
//   cx.is_date       — derived from temporal_len (the single date grammar).
//   cx.is_datetime   — DATA classification, now STRICT: a token is a datetime iff
//                      it scans as a clean temporal run of datetime length.
//
// Formerly data is_datetime was LOOSE — it accepted a malformed
// `YYYY-MM-DDT<garbage>` run as a datetime. [L24] and the program scanner reject
// it; Phase 3 converged the data side onto the strict scanner (lexicon-mandated),
// reclassifying those runs to text. This test now asserts the AGREEMENT.

fn tlen(s string) int {
	return cx.temporal_len(s.bytes(), 0) or { -1 }
}

fn test_is_date_strict() {
	assert cx.is_date('2024-01-15')
	assert !cx.is_date('0000-00-00') // calendar-gated now (@CHOICE-3): month/day 00 invalid
	assert !cx.is_date('2024-1-15') // wrong widths
	assert !cx.is_date('2024-01-15 ') // length != 10
	assert !cx.is_date('24-01-15')
	assert !cx.is_date('abcd-ef-gh')
}

// @CHOICE-3 / LX-DATE — a shape-valid but calendar-INVALID date or datetime is
// NOT a date/datetime token; it falls through to a string. calendar_ok gates the
// CLASSIFICATION (is_date/is_datetime), while temporal_len (the extent scanner)
// stays shape-only so the program lexer keeps the full run as one token.
fn test_calendar_ok_gates_classification() {
	// Bad calendar fields → not a date/datetime (the LX-DATE-BAD witness).
	assert !cx.is_date('2024-13-45') // month 13, day 45
	assert !cx.is_date('2024-02-30') // Feb 30 — shape-valid, calendar-invalid
	assert !cx.is_date('2023-02-29') // 2023 is not a leap year
	assert !cx.is_datetime('2024-01-15T25:00:00') // hour 25
	assert !cx.is_datetime('2024-01-15T10:60:00') // minute 60
	// Good calendar fields → still classify.
	assert cx.is_date('2024-02-29') // 2024 IS a leap year
	assert cx.is_date('2000-02-29') // 2000 divisible by 400 → leap
	assert !cx.is_date('1900-02-29') // 1900 divisible by 100 not 400 → not leap
	assert cx.is_datetime('2024-01-15T10:30:00+05:30')
	assert cx.is_datetime('2024-01-15T23:59:59Z')
	// temporal_len (extent recognizer) is shape-only and UNCHANGED — it still
	// spans the calendar-invalid run as one token (no fragmentation).
	assert tlen('2024-13-45') == 10
	assert tlen('2024-01-15T25:00:00') == 19
}

fn test_temporal_len_date_and_datetime() {
	assert tlen('2024-01-15') == 10
	assert tlen('2024-01-15T10:30:00') == 19
	assert tlen('2024-01-15T10:30:00Z') == 20
	assert tlen('2024-01-15T10:30:00.500') == 23
	assert tlen('2024-01-15T10:30:00+05:30') == 25
	// glued to a name char → not a clean token
	assert tlen('2024-01-15abc') == -1
	assert tlen('not-a-date') == -1
}

fn test_datetime_strictness_converged() {
	// A well-formed datetime: data classification and the strict scanner agree.
	good := '2024-01-15T10:30:00'
	assert cx.is_datetime(good)
	assert tlen(good) == good.len

	// A MALFORMED `YYYY-MM-DDT<garbage>` run, length >= 19. Post-convergence the
	// data classifier is STRICT and agrees with the scanner — both reject it, so
	// it falls through to text:
	bad := '2024-01-15Tgarbage1' // len 19, date + 'T' + non-time tail
	assert bad.len >= 19
	assert !cx.is_datetime(bad) // strict (was LOOSE-accept before Phase 3)
	assert tlen(bad) == -1 // strict scanner: not a temporal token

	// A well-formed datetime with trailing junk is likewise not a datetime token.
	assert !cx.is_datetime('2024-01-15T10:30:00xyz')
}

fn test_is_datetime_min_length() {
	assert !cx.is_datetime('2024-01-15T10:30') // < 19 chars
	assert !cx.is_datetime('2024-01-15') // no 'T'
}
