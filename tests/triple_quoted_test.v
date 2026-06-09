module main

import cx

// Triple-quoted lookahead-on-close (v0.8.0) — a triple-quoted string
// closes at the LAST `'''` (or `"""`) within any maximal run of the
// delimiter character. Operationally: when the scanner sees the
// triple-delimiter, it peeks one byte further; if that byte is the
// same delimiter, the matched triple is treated as content and the
// scanner advances ONE byte rather than three. This makes content
// containing trailing delimiters expressible without escapes (which
// triple-quoted forms otherwise lack).
//
// Symmetric for `'''…'''` and `"""…"""`. The double-quote variant is
// new in v0.8.0 — the data parser previously had no `"""` reading
// path, which forced the doc scaffolder (scripts/gen_docs/scaffold.sh)
// to post-process `cx eval` output via a Python band-aid.

fn scalar_value(doc cx.Document) string {
	if doc.elements.len == 0 { return '' }
	n := doc.elements[0]
	if n is cx.ScalarNode {
		v := n.value
		if v is string { return v }
	}
	if n is cx.TextNode { return n.value }
	return ''
}

// ── Triple-single-quote — existing form (regression checks) ─────────────────

fn test_triple_single_basic() {
	doc := cx.parse("'''hello'''") or { panic(err) }
	assert scalar_value(doc) == 'hello'
}

fn test_triple_single_one_trailing_quote() {
	// '''hello'''' → content `hello'` (one trailing single-quote
	// absorbed via lookahead-on-close).
	doc := cx.parse("'''hello''''") or { panic(err) }
	assert scalar_value(doc) == "hello'"
}

fn test_triple_single_two_trailing_quotes() {
	doc := cx.parse("'''hello'''''") or { panic(err) }
	assert scalar_value(doc) == "hello''"
}

fn test_triple_single_three_trailing_quotes() {
	doc := cx.parse("'''hello''''''") or { panic(err) }
	assert scalar_value(doc) == "hello'''"
}

// ── Triple-double-quote — new in v0.8.0 ─────────────────────────────────────

fn test_triple_double_basic() {
	doc := cx.parse('"""hello"""') or { panic(err) }
	assert scalar_value(doc) == 'hello'
}

fn test_triple_double_one_trailing_quote() {
	// """hello"""" → content `hello"` (the band-aid case — emitted by
	// vcx/code/render.v::choose_render_quote when content has both `'`
	// and `"` but no `"""` and ends with `"`).
	doc := cx.parse('"""hello""""') or { panic(err) }
	assert scalar_value(doc) == 'hello"'
}

fn test_triple_double_two_trailing_quotes() {
	doc := cx.parse('"""hello"""""') or { panic(err) }
	assert scalar_value(doc) == 'hello""'
}

// ── Round-trip through the code-render emitter ──────────────────────────────

fn test_render_quote_roundtrip_band_aid_case() {
	// The exact shape that broke `make docs` before the parser fix: a
	// string containing both `'` and `"` whose last byte is `"`. The
	// emitter picks `"""…"""`, producing `"""…""""` (4 consecutive
	// `"`s at end). The parser must re-read content losslessly.
	original := 'A ::= "x\'y" "z"'
	src := '[code src=\'\'\'${original}\'\'\']'
	doc := cx.parse(src) or { panic(err) }
	mut got := ''
	if doc.elements.len > 0 {
		n := doc.elements[0]
		if n is cx.Element {
			for a in n.attrs {
				if a.name == 'src' {
					v := a.value
					if v is string { got = v }
				}
			}
		}
	}
	assert got == original
}
