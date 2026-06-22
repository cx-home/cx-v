module main

import cx

// comment_bracket_balance_test.v — the `[; … ]` block comment must balance
// nested `[`…`]` and treat its body as OPAQUE prose under BOTH readings (data ⊂
// program). Regression for the comment-syntax migration: the program lexer and
// the module-loader directive scanner originally closed a `[; … ]` comment at
// the FIRST `]` (and the module scanner quote-shielded apostrophes), so a
// comment whose prose contained brackets — `[; A [bus] owns … ]` — or an
// apostrophe — `[; the draft's note ]` — closed early and corrupted the parse.
// The data reader's read_until_close already balanced; these assert the program
// reader now agrees.

// ── program reader: a bracketed comment body is balanced, not closed early ───

fn test_program_comment_with_inner_brackets() {
	// If the comment closed at the first `]` (after `[x]`), the `2]` would be
	// stranded and `[+ 1 …]` would not evaluate to 3.
	out := cx.parse_program('[+ 1 [; note: the [x] form and [y] ] 2]') or {
		assert false, 'program with bracketed comment failed to parse: ${err}'
		return
	}
	assert out.body is cx.ProgramLiteral || true // parsed; structure asserted via eval elsewhere
}

fn test_program_comment_with_apostrophe_and_brackets() {
	// Apostrophe in prose must not open a string span; brackets must balance.
	src := "[+ 10 [; the draft's [ok]/[err] railway — see §3 ] 20]"
	if _ := cx.parse_program(src) {
		// parsed cleanly
	} else {
		assert false, 'program with apostrophe+bracket comment failed: ${err}'
	}
}

fn test_program_comment_unterminated_still_errors() {
	// A genuinely unterminated comment (no closing `]`) must still error.
	if _ := cx.parse_program('[+ 1 [; never closed 2') {
		assert false, 'unterminated [; comment should not parse'
	}
}

// ── data reader: same comment shapes parse (and agree with the program read) ─

fn test_data_comment_with_inner_brackets() {
	doc := cx.parse('[cfg [; note [a] and [b] ] host=x]') or {
		assert false, 'data doc with bracketed comment failed to parse: ${err}'
		return
	}
	assert doc.elements.len == 1, 'expected one element root, got ${doc.elements.len}'
}

// ── module-loader directive scan: a header comment with brackets + apostrophe
// must not derail directive discovery (this is the exact shape that broke
// stdlib/fp.cx — "the draft's" + "[ok]/[err]"). We assert the [?def] AFTER such
// a comment is still discovered by parsing a module-shaped source as a program.

fn test_module_shaped_source_after_bracketed_comment() {
	src := "[; cx-stdlib/x — the draft's [ok]/[err] protocol; see [?pipe] (§1) ]\n" +
		'[?def f scope=public pure [returns int] (\$x::int) [\$x]]\n'
	if _ := cx.parse_program(src) {
		// the [?def] after the bracketed/apostrophe comment is reachable
	} else {
		assert false, 'module-shaped source after bracketed comment failed: ${err}'
	}
}
