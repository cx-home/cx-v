module main

import cx

// v0.8.0 — `cx fmt` lossless + idempotent contract (canonical.md §2.1).
//
// `cx_text_fmt` is the LOSSLESS canonical formatter: unlike `cx_text_canonical`
// (which strips presentation) it MUST round-trip comments, and its output MUST
// be a fixpoint — `fmt(fmt(x)) == fmt(x)` — so format-on-save never mutates a
// buffer twice for the same content. Two regressions are pinned here:
//
//   1. COMMENT LOSS — `[a 1] # keep me` used to drop the comment (emit was
//      byte-identical to `cx canonical`). Comments now round-trip wherever the
//      canonical layout has a line of their own: the document top level
//      (prolog / between+after root nodes) and the line-broken body of a
//      multi-child element. (Inline-only positions — an element head/attrs, an
//      inline `[a, b]` comma list — have no canonical home for a comment and
//      are out of scope by construction; the formatter stays idempotent there.)
//
//   2. NON-IDEMPOTENT ARRAYS — `[origins https://a.com, https://b.com]` emitted
//      a QUOTED array `['https://a.com', …]` on the first pass and a BARE one
//      `[https://a.com, …]` on the second (oscillation). A comma-body string
//      item (a string ScalarNode) and the same item re-parsed from `[ … ]`
//      literal form (a TextNode) now canonicalise identically per §2.3
//      bare-eligibility, so the first pass already lands on the fixpoint.

fn fmt(src string) string {
	return cx.cx_text_fmt(src) or { panic('cx_text_fmt: ${err}') }
}

fn assert_idempotent(src string) string {
	once := fmt(src)
	twice := fmt(once)
	assert once == twice, 'fmt not idempotent:\n  once=  |${once}|\n  twice= |${twice}|'
	return once
}

// ── Acceptance (a): fmt preserves a trailing `# comment` ─────────────────────

fn test_fmt_preserves_trailing_comment() {
	out := assert_idempotent('[a 1]  # keep me')
	assert out.contains('# keep me'), 'trailing comment dropped: |${out}|'
	// The element itself survives intact.
	assert out.contains('[a 1]')
}

fn test_fmt_preserves_leading_comment() {
	out := assert_idempotent('# config header\n[a 1]')
	assert out.contains('# config header'), 'leading comment dropped: |${out}|'
}

fn test_fmt_preserves_comment_between_root_elements() {
	out := assert_idempotent('[a]\n# between a and b\n[b]')
	assert out.contains('# between a and b'), 'between-element comment dropped: |${out}|'
	// Document order is preserved: comment sits between the two elements.
	ia := out.index('[a]') or { -1 }
	ic := out.index('# between') or { -1 }
	ib := out.index('[b]') or { -1 }
	assert ia >= 0 && ic > ia && ib > ic, 'comment out of order: |${out}|'
}

fn test_fmt_preserves_comment_between_child_elements() {
	out := assert_idempotent('[a\n  [b 1]\n  # mid\n  [c 2]\n]')
	assert out.contains('# mid'), 'child-body comment dropped: |${out}|'
}

fn test_fmt_preserves_trailing_comment_in_child_body() {
	out := assert_idempotent('[a\n  [b 1]\n  [c 2]\n  # tail\n]')
	assert out.contains('# tail'), 'trailing child-body comment dropped: |${out}|'
}

// ── Acceptance (b): fmt(fmt(x)) == fmt(x) for array / nested forms ───────────

fn test_idempotent_bareword_comma_array_safe_tokens() {
	// Bare-eligible string items (URLs: no ws/brackets/quotes, no auto-type)
	// canonicalise BARE per §2.3 and stay put on re-format.
	out := assert_idempotent('[origins https://a.com, https://b.com]')
	assert out == '[origins [https://a.com, https://b.com]]', 'unexpected: |${out}|'
}

fn test_idempotent_bareword_comma_array_names() {
	// Bare NAMES must quote (a bare `[admin]` re-parses as an element head, 3a),
	// and the quoted form is itself a fixpoint.
	out := assert_idempotent('[tags admin, user]')
	assert out == "[tags ['admin', 'user']]", 'unexpected: |${out}|'
}

fn test_idempotent_quoted_array_literal() {
	// A quoted array literal of bare-eligible strings normalises to the bare
	// canonical form in ONE pass (no quoted⇄bare oscillation).
	out := assert_idempotent("[urls ['https://a.com', 'https://b.com']]")
	assert out == '[urls [https://a.com, https://b.com]]', 'unexpected: |${out}|'
}

fn test_idempotent_quoted_array_literal_needing_quotes() {
	// Items that would split / re-type stay quoted, and the quoting is stable.
	out := assert_idempotent("[xs ['a b', '80', 'x,y']]")
	assert out.contains("'a b'") && out.contains("'80'") && out.contains("'x,y'"), 'unexpected: |${out}|'
}

fn test_idempotent_typed_int_array() {
	out := assert_idempotent('[ports 80, 443]')
	assert out == '[ports [80, 443]]', 'unexpected: |${out}|'
}

fn test_idempotent_typed_scalar_list_no_comma() {
	// No-comma discrete typed list (ast.md): each token is its own typed child.
	out := assert_idempotent('[scores 10 20 30]')
}

fn test_idempotent_nested_elements() {
	out := assert_idempotent('[a\n  [b 1]\n  [c\n    [d 2]\n    [e 3]\n  ]\n]')
	assert out.contains('[d 2]') && out.contains('[e 3]')
}

// ── Acceptance (b'): EXPLICITLY-typed arrays `::T[]` are lossless + idempotent.
// A typed array keeps its `::T[]` head and whitespace-separated items — the old
// "drop annotation + comma/whitespace signal" form was neither lossless (the
// `::T[]` was discarded) nor a fixpoint (`[scores 80 443]` re-parses to discrete
// children, `[tags admin, user]` to an untyped array). ─────────────────────────

fn test_idempotent_typed_string_array_keeps_annotation() {
	out := assert_idempotent('[tags::string[] admin user guest]')
	assert out == '[tags::string[] admin user guest]', 'unexpected: |${out}|'
}

fn test_idempotent_typed_int_array_keeps_annotation() {
	out := assert_idempotent('[scores::int[] 10 20 30]')
	assert out == '[scores::int[] 10 20 30]', 'unexpected: |${out}|'
}

fn test_idempotent_typed_float_array_no_type_loss() {
	// Integer-looking floats MUST keep `::float[]` — dropping it would re-infer
	// `int` on the next parse (silent type loss).
	out := assert_idempotent('[xs::float[] 1 2 3]')
	assert out.contains('::float[]'), 'float type lost: |${out}|'
}

fn test_idempotent_typed_empty_and_single() {
	assert assert_idempotent('[tags::string[]]') == '[tags::string[]]'
	assert assert_idempotent('[tags::string[] solo]') == '[tags::string[] solo]'
}

// ── Acceptance (c): mixed-content prose round-trips losslessly + idempotently.
// A bijective body-string quote rule (boundary whitespace, leading sigil like
// `+tls`, embedded comma) plus a bare-apostrophe contraction (`it's`) that the
// lookahead scanner used to mis-read as a string opener. ─────────────────────

fn test_idempotent_mixed_content_text_runs() {
	out := assert_idempotent("[p 'See the ' [a x] ' for it, now']")
	assert out.contains("'See the '") && out.contains("' for it, now'"), 'unexpected: |${out}|'
}

fn test_idempotent_sigil_leading_string_quoted() {
	// `'+tls'` must stay quoted — bare `+tls` re-parses as a retired flag sigil.
	out := assert_idempotent("[code '+tls']")
	assert out == "[code '+tls']", 'unexpected: |${out}|'
}

fn test_idempotent_bare_apostrophe_then_comma_quote() {
	// Regression: `it's` (bare contraction) followed by a sibling whose quoted
	// run contains a comma used to throw "unterminated quoted text" at EOF
	// (skip_bracket_region read the apostrophe as a string opener).
	out := assert_idempotent("[doc\n  [h2 What's Next]\n  [p 'See the ' [a x] ' for a, b, c.']\n]")
	assert out.contains("What's Next"), 'unexpected: |${out}|'
}

fn test_idempotent_attrs_and_children() {
	out := assert_idempotent('[server host=localhost port=8080\n  [route /a]\n  [route /b]\n]')
	assert out.contains('host=localhost') && out.contains('port=8080')
}

// ── Strict canonical still STRIPS comments (fmt ≠ canonical here) ────────────

fn test_canonical_still_strips_comments() {
	canon := cx.cx_text_canonical('[a 1]  # keep me') or { panic('canonical: ${err}') }
	assert !canon.contains('# keep me'), 'canonical must strip comments: |${canon}|'
	assert canon.contains('[a 1]')
}
