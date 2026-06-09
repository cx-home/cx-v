module code
import cx

// lexer_test.v — unit tests for the code lexer, focused on the
// triple-quote string literal support added for Bug C symmetry with
// the data parser's read_triple_quoted_str_with_quote.

// helper: tokenize and return only the string_lit tokens.
fn lex_strings(src string) ![]string {
	toks := cx.tokenize(src)!
	mut out := []string{}
	for t in toks {
		if t.kind == .string_lit {
			out << t.text
		}
	}
	return out
}

// helper: tokenize and return the first token kind.
fn lex_first(src string) !cx.ProgramTokenKind {
	toks := cx.tokenize(src)!
	if toks.len == 0 {
		return error('no tokens')
	}
	return toks[0].kind
}

// ── Triple-single-quote '''…''' ───────────────────────────────────────

fn test_triple_single_quote_basic() {
	strs := lex_strings("'''hello'''") or {
		assert false, 'lex error: ${err}'
		return
	}
	assert strs.len == 1, 'expected 1 string token, got ${strs.len}'
	assert strs[0] == 'hello', 'expected content "hello", got "${strs[0]}"'
}

fn test_triple_single_quote_lookahead_on_close() {
	// '''hello'''' → content is "hello'" (lookahead-on-close)
	strs := lex_strings("'''hello''''") or {
		assert false, 'lex error: ${err}'
		return
	}
	assert strs.len == 1, 'expected 1 string token'
	assert strs[0] == "hello'", 'expected "hello\'", got "${strs[0]}"'
}

fn test_triple_single_quote_multiline() {
	strs := lex_strings("'''line1\nline2'''") or {
		assert false, 'lex error: ${err}'
		return
	}
	assert strs.len == 1
	assert strs[0] == 'line1\nline2', 'expected multiline content, got "${strs[0]}"'
}

fn test_triple_single_quote_contains_double_quote() {
	// Triple-single-quote can contain " without escaping.
	strs := lex_strings("'''say \"hello\"'''") or {
		assert false, 'lex error: ${err}'
		return
	}
	assert strs.len == 1
	assert strs[0] == 'say "hello"', 'expected embedded double-quote, got "${strs[0]}"'
}

// ── Triple-double-quote """…""" ───────────────────────────────────────

fn test_triple_double_quote_basic() {
	strs := lex_strings('"""world"""') or {
		assert false, 'lex error: ${err}'
		return
	}
	assert strs.len == 1, 'expected 1 string token, got ${strs.len}'
	assert strs[0] == 'world', 'expected content "world", got "${strs[0]}"'
}

fn test_triple_double_quote_lookahead_on_close() {
	// """world"""" → content is 'world"' (lookahead-on-close)
	strs := lex_strings('"""world""""') or {
		assert false, 'lex error: ${err}'
		return
	}
	assert strs.len == 1, 'expected 1 string token'
	assert strs[0] == 'world"', 'expected "world\\"", got "${strs[0]}"'
}

fn test_triple_double_quote_verbatim_no_escape() {
	// Triple-quoted strings are verbatim — backslash is NOT an escape.
	// Content: it's a \"test\"  (literal backslashes stay)
	strs := lex_strings('"""it\'s a \\"test\\""""') or {
		assert false, 'lex error: ${err}'
		return
	}
	assert strs.len == 1
	assert strs[0] == 'it\'s a \\"test\\"', 'expected verbatim backslash, got "${strs[0]}"'
}

fn test_triple_double_quote_multiline() {
	strs := lex_strings('"""line1\nline2"""') or {
		assert false, 'lex error: ${err}'
		return
	}
	assert strs.len == 1
	assert strs[0] == 'line1\nline2', 'expected multiline content, got "${strs[0]}"'
}

// ── Single / double quotes still work unchanged ───────────────────────

fn test_single_quote_still_works() {
	strs := lex_strings("'hello'") or {
		assert false, 'lex error: ${err}'
		return
	}
	assert strs.len == 1
	assert strs[0] == 'hello'
}

fn test_double_quote_still_works() {
	strs := lex_strings('"world"') or {
		assert false, 'lex error: ${err}'
		return
	}
	assert strs.len == 1
	assert strs[0] == 'world'
}

// ── Unterminated triple-quote produces cx.LexError ───────────────────────

fn test_triple_single_quote_unterminated_is_error() {
	cx.tokenize("'''unterminated") or {
		// expected: error message contains 'unterminated'
		assert err.msg().contains('unterminated'), 'expected unterminated error, got: ${err}'
		return
	}
	assert false, 'expected a cx.LexError for unterminated triple-quote, but tokenize succeeded'
}
