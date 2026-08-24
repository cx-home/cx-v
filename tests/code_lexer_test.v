module main
import cx

import code
import platform as _

// ── program lexer conformance tests ──────────────────────────────────────────────
//
// Per spec/code.md §3 (lexical structure) + §4.1 (directive
// registry). Every token kind in vcx/code/tokens.v has at least one
// passing test below; every error path in vcx/code/lexer.v has a
// corresponding negative test.

fn kinds(tokens []cx.ProgramToken) []cx.ProgramTokenKind {
	mut out := []cx.ProgramTokenKind{cap: tokens.len}
	for t in tokens {
		out << t.kind
	}
	return out
}

fn texts(tokens []cx.ProgramToken) []string {
	mut out := []string{cap: tokens.len}
	for t in tokens {
		out << t.text
	}
	return out
}

// ── Structural sigils ───────────────────────────────────────────────────────

fn test_brackets_and_parens() {
	t := cx.tokenize('[ ] ( ) { }') or { panic(err) }
	assert kinds(t) == [
		cx.ProgramTokenKind.lbrack, .rbrack, .lparen, .rparen, .lbrace, .rbrace, .eof,
	]
}

fn test_directive_open_emits_ldirective_and_name() {
	t := cx.tokenize('[?for]') or { panic(err) }
	assert t[0].kind == .directive_name
	assert t[0].text == 'for'
	assert t[1].kind == .rbrack
	assert t[2].kind == .eof
}

fn test_every_registered_directive_lexes_cleanly() {
	for name in cx.directive_names {
		t := cx.tokenize('[?${name}]') or {
			panic('directive ${name} failed to lex: ${err}')
		}
		assert t[0].kind == .directive_name
		assert t[0].text == name
	}
}

fn test_directive_membership_check() {
	assert cx.is_directive_name('retry')
	assert cx.is_directive_name('await-race')
	assert !cx.is_directive_name('not-a-real-directive')
	assert !cx.is_directive_name('')
}

// ── Sigils ──────────────────────────────────────────────────────────────────

fn test_dollar_at_atbang_colon_slash_dot_pipe() {
	t := cx.tokenize('$ @ @! : / . |') or { panic(err) }
	assert kinds(t) == [
		cx.ProgramTokenKind.dollar, .at, .at_bang, .colon, .slash, .dot, .pipe, .eof,
	]
}

fn test_star_and_double_star() {
	t := cx.tokenize('* ** *') or { panic(err) }
	assert kinds(t) == [cx.ProgramTokenKind.star, .double_star, .star, .eof]
}

fn test_comparison_operators() {
	t := cx.tokenize('= != < <= > >=') or { panic(err) }
	assert kinds(t) == [
		cx.ProgramTokenKind.eq, .neq, .lt, .le, .gt, .ge, .eof,
	]
}

fn test_bang_and_qmark_postfix() {
	t := cx.tokenize('foo! bar?') or { panic(err) }
	assert kinds(t) == [
		cx.ProgramTokenKind.ident, .bang, .ident, .qmark, .eof,
	]
}

// ── Identifiers and bools ───────────────────────────────────────────────────

fn test_identifiers_kebab_case() {
	t := cx.tokenize('find-stale-orders snake_case _underscore camelCase') or { panic(err) }
	assert kinds(t)[..4] == [cx.ProgramTokenKind.ident, .ident, .ident, .ident]
	assert texts(t)[..4] == ['find-stale-orders', 'snake_case', '_underscore', 'camelCase']
}

fn test_bool_literals() {
	t := cx.tokenize('true false') or { panic(err) }
	assert kinds(t) == [cx.ProgramTokenKind.bool_lit, .bool_lit, .eof]
	assert texts(t) == ['true', 'false', '']
}

// ── Numbers ─────────────────────────────────────────────────────────────────

fn test_integer_literal() {
	t := cx.tokenize('42 0 -17') or { panic(err) }
	assert kinds(t) == [cx.ProgramTokenKind.number_lit, .number_lit, .number_lit, .eof]
	assert texts(t)[..3] == ['42', '0', '-17']
}

fn test_float_literal() {
	t := cx.tokenize('1.5 -3.14 .5') or { panic(err) }
	assert kinds(t) == [cx.ProgramTokenKind.number_lit, .number_lit, .number_lit, .eof]
	assert texts(t)[..3] == ['1.5', '-3.14', '.5']
}

fn test_scientific_notation() {
	t := cx.tokenize('1e10 1.5e-3 2E+4') or { panic(err) }
	assert kinds(t) == [cx.ProgramTokenKind.number_lit, .number_lit, .number_lit, .eof]
}

fn test_malformed_exponent_errors() {
	cx.tokenize('1e') or {
		assert err is cx.LexError
		return
	}
	assert false, 'malformed exponent should be a LexError'
}

// ── Durations ───────────────────────────────────────────────────────────────

fn test_duration_literals() {
	cases := ['100us', '50ms', '5s', '3m', '1h']
	for src in cases {
		t := cx.tokenize(src) or { panic('${src} failed: ${err}') }
		assert t[0].kind == .duration_lit
		assert t[0].text == src
	}
}

fn test_invalid_duration_suffix_errors() {
	cx.tokenize('100xs') or {
		assert err is cx.LexError
		return
	}
	assert false, 'invalid duration suffix should be a LexError'
}

// ── String literals ─────────────────────────────────────────────────────────

fn test_string_single_quoted() {
	t := cx.tokenize("'hello world'") or { panic(err) }
	assert t[0].kind == .string_lit
	assert t[0].text == 'hello world'
}

fn test_string_double_quoted() {
	t := cx.tokenize('"double"') or { panic(err) }
	assert t[0].kind == .string_lit
	assert t[0].text == 'double'
}

fn test_string_escapes() {
	t := cx.tokenize(r"'a\nb\tc\\d\'e'") or { panic(err) }
	assert t[0].kind == .string_lit
	assert t[0].text == 'a\nb\tc\\d\'e'
}

fn test_unterminated_string_errors() {
	cx.tokenize("'open-no-close") or {
		assert err is cx.LexError
		return
	}
	assert false, 'unterminated string should be a LexError'
}

fn test_unknown_escape_lenient() {
	// 2a / lexicon.ebnf §5 [L32]: an unknown backslash-sequence is kept
	// LITERALLY (lenient pass-through, unified with the data parser) — the
	// backslash is preserved so regex shorthands survive verbatim.
	t := cx.tokenize(r"'\q'") or { panic(err) }
	assert t[0].kind == .string_lit
	assert t[0].text == r'\q'
	t2 := cx.tokenize(r"'\d+'") or { panic(err) }
	assert t2[0].text == r'\d+'
}

fn test_unicode_escapes_decode() {
	// 2a: \uXXXX / \UXXXXXXXX decode to the code point in program strings,
	// matching the data parser.
	t := cx.tokenize(r"'\u0041'") or { panic(err) }
	assert t[0].kind == .string_lit
	assert t[0].text == 'A'
}

// ── Whitespace + comments ───────────────────────────────────────────────────

fn test_whitespace_skipped() {
	t := cx.tokenize('  \t\n  foo   \r\n  bar  ') or { panic(err) }
	assert kinds(t) == [cx.ProgramTokenKind.ident, .ident, .eof]
}

fn test_line_comment_skipped() {
	t := cx.tokenize('foo # trailing comment\nbar') or { panic(err) }
	assert kinds(t) == [cx.ProgramTokenKind.ident, .ident, .eof]
	assert texts(t)[..2] == ['foo', 'bar']
}

fn test_block_comment_skipped() {
	// `[; … ]` is the block comment and IS skipped by the lexer.
	t := cx.tokenize('a [; block\ncomment ] b') or { panic(err) }
	assert kinds(t) == [cx.ProgramTokenKind.ident, .ident, .eof]
}

fn test_dash_is_minus_not_comment() {
	// `[- …]` is now the minus operator head, NEVER a comment — so it is NOT
	// skipped: it lexes to real tokens (lbrack + minus + operands + rbrack),
	// not collapsed to a lone eof the way a `[; … ]` comment would be.
	t := cx.tokenize('[- 3 1]') or { panic(err) }
	assert kinds(t) != [cx.ProgramTokenKind.eof]
	assert kinds(t).len > 3
}

fn test_raw_span_is_a_data_span() {
	// DATA↔PROGRAM seam: `[# … #]` is RAW TEXT (code.md §1.3 / lexicon
	// [L2]/[L3]), NOT a comment. It lexes as a single `data_span` token carrying
	// the verbatim span (a prior version wrongly skipped it as a block comment).
	t := cx.tokenize('a [# block\ncomment #] b') or { panic(err) }
	assert kinds(t) == [cx.ProgramTokenKind.ident, .data_span, .ident, .eof]
	assert texts(t)[1] == '[# block\ncomment #]'
}

fn test_unterminated_raw_span_errors() {
	cx.tokenize('[# nope') or {
		assert err is cx.LexError
		return
	}
	assert false, 'unterminated raw text should be a LexError'
}

// ── BOM handling ────────────────────────────────────────────────────────────

fn test_bom_at_start_consumed() {
	t := cx.tokenize('\xEF\xBB\xBFfoo') or { panic(err) }
	assert kinds(t) == [cx.ProgramTokenKind.ident, .eof]
	assert t[0].text == 'foo'
}

// ── Position tracking ───────────────────────────────────────────────────────

fn test_position_tracks_line_and_col() {
	t := cx.tokenize('a\n  b') or { panic(err) }
	// 'a' at line 1 col 1
	assert t[0].pos.line == 1
	assert t[0].pos.col == 1
	// 'b' at line 2 col 3
	assert t[1].pos.line == 2
	assert t[1].pos.col == 3
}

// ── Composite fixtures matching conformance/code.txt shapes ──────────────────

fn test_find_directive_with_pattern() {
	src := '[?for [user [email \$e]] :yield \$e]'
	t := cx.tokenize(src) or { panic(err) }
	// Expected sequence:
	//   [?for   → directive_name "for"
	//   [       → lbrack
	//   user    → ident
	//   [       → lbrack
	//   email   → ident
	//   \$      → dollar
	//   e       → ident
	//   ]       → rbrack
	//   ]       → rbrack
	//   :       → colon
	//   yield   → ident
	//   \$      → dollar
	//   e       → ident
	//   ]       → rbrack
	//   eof
	assert kinds(t) == [
		cx.ProgramTokenKind.directive_name, .lbrack, .ident, .lbrack, .ident,
		.dollar, .ident, .rbrack, .rbrack, .colon, .ident, .dollar,
		.ident, .rbrack, .eof,
	]
	assert t[0].text == 'for'
}

fn test_retry_with_duration_and_pipe() {
	src := '[?retry :max 3 :delay 100ms :body fetch() | dump]'
	t := cx.tokenize(src) or { panic(err) }
	assert t[0].kind == .directive_name && t[0].text == 'retry'
	// Find the duration_lit token.
	mut dur_idx := -1
	for i, tok in t {
		if tok.kind == .duration_lit {
			dur_idx = i
			break
		}
	}
	assert dur_idx > 0
	assert t[dur_idx].text == '100ms'
	// And the pipe token.
	mut pipe_count := 0
	for tok in t {
		if tok.kind == .pipe {
			pipe_count++
		}
	}
	assert pipe_count == 1
}

fn test_empty_source_yields_eof_only() {
	t := cx.tokenize('') or { panic(err) }
	assert kinds(t) == [cx.ProgramTokenKind.eof]
}

fn test_unexpected_char_errors() {
	cx.tokenize('foo \x07 bar') or {
		assert err is cx.LexError
		return
	}
	assert false, 'unexpected byte should be a LexError'
}
