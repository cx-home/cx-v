module main

import cx

// Tests for v3.4 numeric grammar changes:
//   - Underscores in integer/float/hex literals (additive).
//   - Leading-zero rejection in auto-typed integers (BREAKING).
//
// Spec: spec/grammar.ebnf [20a]/[20b]/[20c], spec/policies.md §1.7.

// ── Underscores accepted ─────────────────────────────────────────────────────

fn test_int_with_underscores() {
	doc := cx.parse('[count 1_000_000]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is i64 { assert s == 1000000 } else { assert false, 'expected i64' }
}

fn test_int_many_underscores() {
	doc := cx.parse('[v 1_2_3_4_5]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is i64 { assert s == 12345 } else { assert false, 'expected i64' }
}

fn test_negative_int_with_underscores() {
	doc := cx.parse('[v -1_000]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is i64 { assert s == -1000 } else { assert false, 'expected i64' }
}

fn test_float_with_underscores_in_fraction() {
	doc := cx.parse('[v 1.234_567]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is f64 { assert s > 1.234 && s < 1.235 } else { assert false, 'expected f64' }
}

fn test_hex_with_underscores() {
	doc := cx.parse('[v 0xDEAD_BEEF]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is i64 { assert s == 0xDEADBEEF } else { assert false, 'expected i64' }
}

fn test_attribute_int_with_underscores() {
	doc := cx.parse('[item count=1_000]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.attr('count') == '1000', 'unexpected: ${root.attr("count")}'
}

// ── Underscores rejected (malformed) ─────────────────────────────────────────

fn test_leading_underscore_falls_through_to_text() {
	// `_1000` is not a valid number; auto-types as Text.
	doc := cx.parse('[v _1000]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	if _ := root.scalar() {
		assert false, 'expected text, got scalar'
	}
}

fn test_trailing_underscore_falls_through_to_text() {
	doc := cx.parse('[v 1000_]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	if _ := root.scalar() {
		assert false, 'expected text, got scalar'
	}
}

fn test_doubled_underscore_falls_through_to_text() {
	doc := cx.parse('[v 1__000]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	if _ := root.scalar() {
		assert false, 'expected text, got scalar'
	}
}

// ── Leading-zero tightening (BREAKING in v3.4) ───────────────────────────────

fn test_leading_zero_zip_falls_through_to_text() {
	// '02134' is no longer auto-typed as int 2134. It's Text "02134".
	doc := cx.parse('[zip 02134]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	if _ := root.scalar() {
		assert false, 'expected text, got scalar — leading-zero tightening failed'
	}
}

fn test_leading_zero_multidigit_falls_through() {
	doc := cx.parse('[v 007]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	if _ := root.scalar() {
		assert false, 'expected text, got scalar'
	}
}

fn test_plain_zero_still_int() {
	// The literal '0' is fine — it's the sole exception.
	doc := cx.parse('[v 0]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is i64 { assert s == 0 } else { assert false, 'expected i64' }
}

fn test_negative_zero_int_still_int() {
	doc := cx.parse('[v -0]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is i64 { assert s == 0 } else { assert false, 'expected i64' }
}

fn test_hex_zero_still_int() {
	// Hex is exempt — '0x...' is unambiguous.
	doc := cx.parse('[v 0x42]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is i64 { assert s == 0x42 } else { assert false, 'expected i64' }
}

fn test_explicit_int_annotation_accepts_leading_zero() {
	// :int annotation overrides the auto-typing rule. The user has
	// declared this is an integer; respect the value.
	doc := cx.parse('[v :int 02134]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is i64 { assert s == 2134 } else { assert false, 'expected i64' }
}
