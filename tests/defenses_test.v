module main

import cx

// Tests for v3.4 adversarial defenses. spec/policies.md §5.

// ── Recursion depth limit ────────────────────────────────────────────────────

fn test_parser_rejects_excessive_nesting() {
	// Build deeply nested CX exceeding max_recursion_depth (64).
	// Stack-overflow without the depth check.
	mut src := ''
	mut close := ''
	for _ in 0 .. 200 {
		src += '[a '
		close += ']'
	}
	src += close
	if _ := cx.parse(src) {
		assert false, 'parser should reject 200-deep nesting'
	} else {
		assert err.msg().contains('nesting'),
			'expected nesting-related error, got: ${err.msg()}'
	}
}

fn test_parser_accepts_bounded_nesting() {
	// 32 levels deep — well under the 64 limit.
	mut src := ''
	mut close := ''
	for _ in 0 .. 32 {
		src += '[a '
		close += ']'
	}
	src += close
	doc := cx.parse(src) or {
		assert false, 'bounded nesting should parse cleanly: ${err.msg()}'
		return
	}
	root := doc.root() or { panic('no root') }
	assert root.name == 'a'
}

// ── Bounds checks in binary readers (already covered in 2b/2c) ───────────────
// See vcx/tests/data_bin_test.v and vcx/tests/ast_bin_test.v
// for length-prefix bounds-check tests on the binary readers.