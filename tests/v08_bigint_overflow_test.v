module main

import cx
import code

// Pass-2 D-H — over-i64 integer handling.
//
// Ruling: a BARE decimal integer that overflows i64 AUTO-PROMOTES to bigint
// (stays numeric) in BOTH the data and program readings; an EXPLICIT `::int`
// (or sized-int) overflow is a HARD ERROR (CXER0109 / CXERLEX-RANGE), never a
// silent clamp/wrap. The near-boundary case (i64 max + 1) must promote too —
// V's parse_int silently CLAMPS it, which parse_i64_checked guards against.

const over_i64 = '99999999999999999999999999999' // 29 digits, far over
const max_plus_1 = '9223372036854775808'          // i64 max + 1 (clamp trap)
const i64_max = '9223372036854775807'
const i64_min = '-9223372036854775808'

// ── Data reading ─────────────────────────────────────────────────────────────

fn scalar_of(src string) cx.ScalarNode {
	doc := cx.parse(src) or {
		assert false, 'parse failed: ${err}'
		return cx.ScalarNode{}
	}
	el := doc.elements[0] as cx.Element
	return el.items[0] as cx.ScalarNode
}

fn test_data_bare_overflow_promotes_to_bigint() {
	s := scalar_of('[n ${over_i64}]')
	assert s.data_type == .bigint_type, 'expected bigint, got ${s.data_type}'
	assert (s.value as string) == over_i64, 'bigint value mismatch: ${s.value}'
}

fn test_data_near_boundary_promotes_to_bigint() {
	// i64 max + 1 must NOT clamp to max — it promotes to bigint.
	s := scalar_of('[n ${max_plus_1}]')
	assert s.data_type == .bigint_type, 'max+1 should be bigint, got ${s.data_type}'
	assert (s.value as string) == max_plus_1, 'value mismatch: ${s.value}'
}

fn test_data_i64_max_stays_int() {
	s := scalar_of('[n ${i64_max}]')
	assert s.data_type == .int_type, 'i64 max should stay int, got ${s.data_type}'
	assert (s.value as i64) == i64(9223372036854775807), 'value mismatch'
}

fn test_data_explicit_int_overflow_errors() {
	if _ := cx.parse('[n::int ${over_i64}]') {
		assert false, 'expected CXER0109 for ::int overflow'
	}
}

fn test_data_explicit_int_i64_min_ok() {
	// The asymmetric boundary: |i64 min| overflows when read positive, but
	// -9223372036854775808 is a valid i64.
	s := scalar_of('[n::int ${i64_min}]')
	assert s.data_type == .int_type, 'i64 min should be int, got ${s.data_type}'
	assert (s.value as i64) == i64(-9223372036854775808), 'value mismatch: ${s.value}'
}

fn test_data_explicit_int_leading_zero_ok() {
	// Explicit ::int bypasses the leading-zero auto-typing rule: 02134 → 2134.
	s := scalar_of('[n::int 02134]')
	assert s.data_type == .int_type, 'expected int, got ${s.data_type}'
	assert (s.value as i64) == i64(2134), 'value mismatch: ${s.value}'
}

// ── Program reading ──────────────────────────────────────────────────────────

fn test_program_bare_overflow_promotes_to_bigint() {
	out := code.eval_code('', over_i64, 'json') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('"dataType":"bigint"'), 'expected bigint result, got: ${out}'
	assert out.contains(over_i64), 'bigint value missing: ${out}'
}

fn test_program_near_boundary_promotes_to_bigint() {
	out := code.eval_code('', max_plus_1, 'json') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('"dataType":"bigint"'), 'max+1 should be bigint, got: ${out}'
}

fn test_program_bigint_renders_bare() {
	// A bigint result renders WITHOUT quotes in canonical CX (it is numeric).
	out := code.eval_code('', over_i64, 'cx') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.trim_space() == over_i64, 'bigint should render bare, got: ${out}'
}

fn test_program_explicit_int_overflow_errors() {
	if _ := code.eval_code('', '[n::int ${over_i64}]', 'cx') {
		assert false, 'expected CXER0109 for program ::int overflow'
	}
}
