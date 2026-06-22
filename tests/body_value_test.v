module main

import code
import cx

// v08_body_value_test — cluster 2 (TYPED-LIST/CONTENT) of the parser-parity
// convergence. Both engines apply §9 [L25a-b] body-value classification: a
// multi-token whitespace body whose every item is a non-bareword scalar is a
// TYPED LIST of discrete items (heterogeneous types preserved, NO auto-array,
// NO int→float promotion — @CHOICE-1 "one layer", slice A); a body with any
// bareword is PROSE (one Text run). Convergence target is cx.parse.

fn cc(src string) string {
	n := code.program_parse_to_typed_node(src) or { return 'REJECT' }
	return code.render_canonical(n)
}

fn xc(src string) string {
	doc := cx.parse(src) or { return 'REJECT: ${err}' }
	if doc.elements.len != 1 {
		return 'REJECT: ${doc.elements.len} elements'
	}
	return code.render_canonical(doc.elements[0])
}

// ── AUTOARRAY ──
fn test_int_array() {
	assert cc('[items 1 2 3]') == '[items 1 2 3]'
	assert cc('[items 1 2 3]') == xc('[items 1 2 3]')
}

fn test_int_float_heterogeneous() {
	// @CHOICE-1 §9-one-layer (slice A): a whitespace scalar run is a TYPED LIST of
	// discrete items — NOT an auto-array. Heterogeneous per-item types are
	// PRESERVED; there is no int→float promotion (the old `[ns 1.0 2.0 3.0]`
	// float[] form is retired). Both engines converge to the heterogeneous list.
	assert cc('[ns 1 2.0 3]') == '[ns 1 2.0 3]'
	assert cc('[ns 1 2.0 3]') == xc('[ns 1 2.0 3]')
}

fn test_bool_array() {
	assert cc('[bs true false true]') == xc('[bs true false true]')
}

fn test_date_array() {
	assert cc('[ds 2024-01-15 2024-02-20]') == '[ds 2024-01-15 2024-02-20]'
	assert cc('[ds 2024-01-15 2024-02-20]') == xc('[ds 2024-01-15 2024-02-20]')
}

// ── CONTENT (prose) ──
fn test_bareword_prose() {
	assert cc('[words alpha beta gamma]') == "[words 'alpha beta gamma']"
	assert cc('[words alpha beta gamma]') == xc('[words alpha beta gamma]')
}

fn test_mixed_string_int_prose() {
	assert cc('[map x 1]') == "[map 'x 1']"
	assert cc('[map x 1]') == xc('[map x 1]')
}

// ── D3: digit-less token is NOT a float ──
fn test_bare_e_is_string() {
	// Regression for cxparse Class-D D3: bare `e` was autotyped to float 0.0
	// by the data parser (strconv.atof64('e') leniently returns 0.0). Lexicon
	// [L20b] Float requires an Integer mantissa, so a digit-less token falls
	// through to Text. cx (data) now matches code (program): a string.
	assert xc('[name e]') == "[name 'e']"
	assert cc('[name e]') == "[name 'e']"
	assert cc('[name e]') == xc('[name e]')
	// the same digit-less class: a lone `E`, `.`, `e+` are all strings, not 0.0
	assert xc('[a E]') == "[a 'E']"
	assert xc('[a e+]') == "[a 'e+']"
	assert xc('[a E]') == cc('[a E]')
}

// ── D4: triple-quoted strings get common-indent strip ──
fn test_triple_quote_dedent() {
	// cxparse Class-D D4: the program lexer delivered triple-quote content
	// verbatim (no dedent), so `[desc '''⏎  hello⏎  world⏎''']` kept the 2-
	// space indent + surrounding blank lines. ast.md §Text + conformance
	// ext-038 require common-indent strip; both parsers now share one impl.
	src := "[desc '''\n  hello\n  world\n''']"
	assert cc(src) == "[desc 'hello\nworld']"
	assert cc(src) == xc(src)
	// no-indent content is unchanged by the strip
	src2 := "[d '''\nx\n''']"
	assert cc(src2) == xc(src2)
}

// ── D2: leading-zero integer is a string, not an int ──
fn test_leading_zero_is_string() {
	// cxparse Class-D D2: the program path read `[zip 02134]` as int 2134
	// (leading zero dropped). Lexicon [L20c]: a leading-zero plain integer is
	// NOT an Integer → Text, preserving ZIPs / SKUs. cx already does this.
	assert cc('[zip 02134]') == "[zip '02134']"
	assert cc('[zip 02134]') == xc('[zip 02134]')
	assert cc('[code 007]') == "[code '007']"
	assert cc('[code 007]') == xc('[code 007]')
	// the lone `0` (and `-0`) stays an int
	assert cc('[n 0]') == '[n 0]'
	assert cc('[n 0]') == xc('[n 0]')
}

// ── single item unaffected ──
fn test_single_scalar_unchanged() {
	// A single scalar child is NOT auto-arrayed; it renders as the lone
	// scalar (a bareword string renders quoted, the canonical form).
	assert cc('[n 42]') == '[n 42]'
	assert cc('[name Alice]') == "[name 'Alice']"
	assert cc('[name Alice]') == xc('[name Alice]')
}
