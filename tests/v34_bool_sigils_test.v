module main

import cx

// Tests for v3.4 boolean attribute sigils. Spec:
// spec/grammar.ebnf [55b], spec/policies.md.

// ── Basic sigil parsing ──────────────────────────────────────────────────────

fn test_plus_sigil_parses_as_true() {
	doc := cx.parse('[user +admin]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.attr('admin') == 'true'
}

fn test_minus_sigil_parses_as_false() {
	doc := cx.parse('[user -admin]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.attr('admin') == 'false'
}

fn test_multiple_sigils() {
	doc := cx.parse('[user +admin -disabled +verified]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.attr('admin') == 'true'
	assert root.attr('disabled') == 'false'
	assert root.attr('verified') == 'true'
}

fn test_sigils_with_regular_attrs() {
	doc := cx.parse("[user name='alice' +admin -disabled]") or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.attr('name') == 'alice'
	assert root.attr('admin') == 'true'
	assert root.attr('disabled') == 'false'
}

fn test_sigils_interleaved_with_attrs() {
	doc := cx.parse("[user +admin name='alice' -disabled age=30]") or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.attr('admin') == 'true'
	assert root.attr('name') == 'alice'
	assert root.attr('disabled') == 'false'
	assert root.attr('age') == '30'
}

// ── Disambiguation: sigil vs other constructs ────────────────────────────────

fn test_minus_followed_by_digit_is_negative_number_in_body() {
	// In body position, `-42` is a negative integer, not a sigil.
	doc := cx.parse('[v -42]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is i64 { assert s == -42 } else { assert false, 'expected i64' }
}

fn test_sigil_requires_no_whitespace_before_name() {
	// `[user + admin]` is NOT a sigil — there's whitespace between
	// `+` and `admin`. The `+` falls through to other handling.
	// For now this should produce a parse-time effect (likely break
	// or error). We assert the sigil semantics do NOT apply.
	if doc := cx.parse('[user + admin]') {
		root := doc.root() or { panic('no root') }
		// The 'admin' here, if it parsed, would be either a body
		// text token or part of malformed input. It should NOT be
		// a bool attribute.
		assert root.attr('admin') == '', 'sigil should not fire when whitespace separates'
	}
}

// ── Round-trip with body content ─────────────────────────────────────────────

fn test_sigil_with_body_scalar() {
	doc := cx.parse('[count +verified 42]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.attr('verified') == 'true'
	s := root.scalar() or { panic('expected scalar body') }
	if s is i64 { assert s == 42 } else { assert false, 'expected i64' }
}
