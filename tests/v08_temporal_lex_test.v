module main

import code
import cx

// v08_temporal_lex_test — cluster 1 (LEXER/DATETIME) of the parser-parity
// convergence. The PROGRAM parser (code.parse) must lex `2024-01-15` as ONE
// date token and `…T..Z` as ONE datetime token per lexicon §9 [L23]/[L24],
// instead of shattering into `2024 -1 -15` / rejecting. Convergence target is
// cx.parse (the spec-faithful side): both must render identically through
// code.render_canonical.

fn code_canon(src string) string {
	n := code.program_parse_to_typed_node(src) or { return 'REJECT' }
	return code.render_canonical(n)
}

fn cx_canon(src string) string {
	doc := cx.parse(src) or { return 'REJECT: ${err}' }
	if doc.elements.len != 1 {
		return 'REJECT: ${doc.elements.len} elements'
	}
	return code.render_canonical(doc.elements[0])
}

fn test_single_date_token() {
	// Date is one token → date scalar, NOT 2024 -1 -15. It renders BARE — a bare
	// `2024-01-15` re-auto-types to a date on round-trip, whereas a quoted form
	// would re-parse as a string and lose the date type (@CHOICE-1 slice A: the
	// program renderer now emits date/datetime body items unquoted, matching the
	// data parser and the bijection invariant).
	assert code_canon('[d 2024-01-15]') == '[d 2024-01-15]'
}

fn test_single_datetime_token() {
	assert code_canon('[dt 2024-01-15T10:30:00Z]') == '[dt 2024-01-15T10:30:00Z]'
}

fn test_datetime_with_offset() {
	assert code_canon('[dt 2024-01-15T10:30:00+05:30]') == '[dt 2024-01-15T10:30:00+05:30]'
}

fn test_datetime_fractional() {
	assert code_canon('[dt 2024-01-15T10:30:00.250Z]') == '[dt 2024-01-15T10:30:00.250Z]'
}

fn test_date_parity_with_cx() {
	assert code_canon('[d 2024-01-15]') == cx_canon('[d 2024-01-15]')
	assert code_canon('[dt 2024-01-15T10:30:00Z]') == cx_canon('[dt 2024-01-15T10:30:00Z]')
}

fn test_plain_int_year_unaffected() {
	// A bare year (no -MM-DD) is still a plain int.
	assert code_canon('[n 2024]') == '[n 2024]'
}

fn test_minus_arithmetic_unaffected() {
	// `[- $a $b]` arithmetic head must not be disturbed by temporal lexing.
	got := code.eval_code('[doc]', '[?let [= $a 10] [= $b 3] [- $a $b]]', 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert got == '7', 'got ${got}'
}

fn test_negative_number_unaffected() {
	assert code_canon('[n -7]') == '[n -7]'
}
