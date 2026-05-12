module main

import cx

// Tests for v3.4 sized numeric type annotations and the new
// :decimal / :bigint type names. Spec: spec/grammar.ebnf [26a],
// spec/type_mapping.md §2.

// ── Sized integer annotations parse as int_type ──────────────────────────────

fn test_i8_annotation_parses() {
	doc := cx.parse('[v :i8 42]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is i64 { assert s == 42 } else { assert false, 'expected i64' }
}

fn test_i32_annotation_parses() {
	doc := cx.parse('[v :i32 -1000]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is i64 { assert s == -1000 } else { assert false, 'expected i64' }
}

fn test_i64_annotation_parses() {
	doc := cx.parse('[v :i64 9223372036854775807]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is i64 { assert s == i64(9223372036854775807) } else { assert false, 'expected i64' }
}

fn test_u32_annotation_parses() {
	doc := cx.parse('[v :u32 4294967295]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is i64 { assert s == 4294967295 } else { assert false, 'expected i64' }
}

fn test_sized_int_with_underscores() {
	doc := cx.parse('[v :i32 1_000_000]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is i64 { assert s == 1000000 } else { assert false, 'expected i64' }
}

// ── Sized float annotations parse as float_type ──────────────────────────────

fn test_f32_annotation_parses() {
	doc := cx.parse('[v :f32 3.14]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is f64 { assert s > 3.13 && s < 3.15 } else { assert false, 'expected f64' }
}

fn test_f16_annotation_parses() {
	doc := cx.parse('[v :f16 1.5]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is f64 { assert s == 1.5 } else { assert false, 'expected f64' }
}

fn test_f64_annotation_parses() {
	doc := cx.parse('[v :f64 1.7e10]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is f64 { assert s > 1e10 } else { assert false, 'expected f64' }
}

// ── Decimal type ─────────────────────────────────────────────────────────────

fn test_decimal_annotation_preserves_string() {
	doc := cx.parse('[price :decimal 19.99]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is string { assert s == '19.99' } else { assert false, 'expected string for decimal' }
}

fn test_decimal_high_precision() {
	doc := cx.parse('[v :decimal 3.14159265358979323846264338327950288]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is string {
		assert s == '3.14159265358979323846264338327950288'
	} else {
		assert false, 'expected string for decimal'
	}
}

// ── Bigint type ──────────────────────────────────────────────────────────────

fn test_bigint_annotation_preserves_string() {
	doc := cx.parse('[v :bigint 123456789012345678901234567890]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is string {
		assert s == '123456789012345678901234567890'
	} else {
		assert false, 'expected string for bigint'
	}
}

fn test_bigint_with_underscores() {
	doc := cx.parse('[v :bigint 1_000_000_000_000]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is string { assert s == '1000000000000' } else { assert false, 'expected string' }
}

// ── Type-name preservation in element data_type ──────────────────────────────

fn test_sized_type_preserved_on_element() {
	// The Element.data_type field carries the original annotation
	// string, even though ScalarNode.data_type maps to the base
	// category. This is what binary emission reads to pick the
	// narrowest CXDB tag.
	doc := cx.parse('[v :i32 42]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	if dt := root.data_type {
		assert dt == 'i32', 'expected element data_type=i32, got ${dt}'
	} else {
		assert false, 'expected element data_type to be set'
	}
}

fn test_decimal_type_preserved_on_element() {
	doc := cx.parse('[v :decimal 19.99]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	if dt := root.data_type {
		assert dt == 'decimal', 'expected decimal, got ${dt}'
	} else {
		assert false, 'expected element data_type to be set'
	}
}

fn test_f16_type_preserved_on_element() {
	doc := cx.parse('[v :f16 1.5]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	if dt := root.data_type {
		assert dt == 'f16', 'expected f16, got ${dt}'
	} else {
		assert false, 'expected element data_type to be set'
	}
}
