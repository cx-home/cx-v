module main

import cx
import code

// cxparse Phase 4.2 — the program number grammar converges to lexicon [L20]
// (the same grammar the data parser already implements): hex ints (`0x…` with
// optional `_` separators), `_` separators in decimal int / float, and the
// [L20c] leading-zero rule. Before convergence the program lexer rejected
// `0xFF` ("invalid duration suffix 'xFF'") and `1_000`; after, both parsers
// agree. These cases pin the converged behavior.

fn body_scalar(src string) cx.ScalarNode {
	mut env := code.new_env()
	prog := cx.parse_program(src) or { panic('parse failed: ${src} — ${err}') }
	n := code.eval(prog.body, mut env) or { panic('eval failed: ${src} — ${err}') }
	if n is cx.Element {
		if n.items.len == 1 {
			it := n.items[0]
			if it is cx.ScalarNode {
				return it
			}
		}
	}
	panic('expected single-scalar body for ${src}')
}

fn int_body(src string) i64 {
	s := body_scalar(src)
	assert s.data_type == cx.ScalarType.int_type, '${src}: expected int, got ${s.data_type}'
	v := s.value
	return if v is i64 { v } else { i64(-999999) }
}

fn test_hex_int() {
	assert int_body('[x 0xFF]') == 255
	assert int_body('[x 0X10]') == 16
	assert int_body('[x -0x10]') == -16
}

fn test_hex_underscore() {
	assert int_body('[x 0xDEAD_BEEF]') == i64(0xDEADBEEF)
}

fn test_decimal_underscore() {
	assert int_body('[x 1_000]') == 1000
	assert int_body('[x 1_000_000]') == 1000000
}

fn test_float_underscore() {
	s := body_scalar('[x 1_000.5]')
	assert s.data_type == cx.ScalarType.float_type
	v := s.value
	assert (if v is f64 { v } else { 0.0 }) == 1000.5
}

fn test_leading_zero_stays_string() {
	// [L20c]: a leading-zero decimal int is NOT an int — it stays a string
	// (ZIP codes / SKUs). Regression guard; this already held pre-4.2.
	s := body_scalar('[x 02134]')
	assert s.data_type == cx.ScalarType.string_type
	v := s.value
	assert (if v is string { v } else { '' }) == '02134'
}
