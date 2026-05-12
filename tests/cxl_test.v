module main

import cx

// ── CXL 1.0 evaluator tests (V reference implementation) ─────────────────────
//
// Per spec/cxl.md and ADR 0016 / ADR 0017 §D7. The V reference
// evaluator is the conformance target; per-binding native evaluators
// MUST produce byte-identical output. Cross-binding fixtures land in
// conformance/cxl.txt.
//
// All tests use the ADR 0017 uniform directive shape
// `[?Name [arg, arg, arg]]` (§D6). The pre-0017 attribute-slot form
// (`:then=…/:else=…`) and bare positional-text form (`[?for v in
// expr body]`) are rejected by the parser — see
// vcx/tests/v36_directive_args_test.v for the parse-level proofs.

fn run(input string, program string, target string) string {
	return cx.eval_cxl(input, program, target) or { panic('cxl: ${err}') }
}

// ── Interpolation ────────────────────────────────────────────────────────────

fn test_cxl_interp_attr() {
	doc := '[product name=Pocket price=12]'
	prog := '[?=@name]'
	assert run(doc, prog, '') == 'Pocket'
}

fn test_cxl_interp_path_attr() {
	doc := '[product [variant sku=PN-A]]'
	prog := '[?=//variant/@sku]'
	assert run(doc, prog, '') == 'PN-A'
}

fn test_cxl_interp_text_content() {
	doc := "[product [description 'A compact ruled notebook']]"
	prog := '[?=//description]'
	out := run(doc, prog, '')
	assert out.contains('A compact ruled notebook'), 'got: "${out}"'
}

fn test_cxl_literal_text_passthrough() {
	// Bare top-level text must live inside a bracket form because CXL
	// programs are CX documents (ADR 0016 R1). Note: comma inside the
	// body would now disambiguate as ArrayLiteral per ADR 0017 §D1,
	// so we use a comma-free body for the element-with-text idiom.
	doc := '[x]'
	prog := '[doc Hello world!]'
	out := run(doc, prog, '')
	assert out.contains('Hello world!'), 'got: "${out}"'
}

// ── `[?if [cond, then, else]]` (spec/cxl.md §3.2) ────────────────────────────

fn test_cxl_if_true_then() {
	doc := '[product stock=10]'
	prog := '[?if [@stock > 0, in stock, out]]'
	assert run(doc, prog, '') == 'in stock'
}

fn test_cxl_if_false_else() {
	doc := '[product stock=0]'
	prog := '[?if [@stock > 0, in stock, out]]'
	assert run(doc, prog, '') == 'out'
}

fn test_cxl_if_no_else() {
	// Two-slot form: else-body omitted → empty Sequence (no output).
	doc := '[product stock=0]'
	prog := '[?if [@stock > 0, yes]]'
	assert run(doc, prog, '') == ''
}

fn test_cxl_if_existence() {
	doc := '[product [tags]]'
	prog := '[?if [//tags, has tags, no tags]]'
	assert run(doc, prog, '') == 'has tags'
}

// ── `[?if [[c1,b1], [c2,b2], [*, default]]]` multi-branch (§3.3) ─────────────

fn test_cxl_if_multi_branch_middle() {
	doc := '[p stock=15]'
	prog := '[?if [[@stock > 100, Plenty], [@stock > 10, Some], [@stock > 0, Low], [*, None]]]'
	out := run(doc, prog, '')
	assert out == 'Some', 'got: "${out}"'
}

fn test_cxl_if_multi_branch_fallback() {
	// Wildcard `*` sentinel fires when no preceding condition matches.
	doc := '[p stock=-1]'
	prog := '[?if [[@stock > 100, Plenty], [*, None]]]'
	out := run(doc, prog, '')
	assert out == 'None', 'got: "${out}"'
}

fn test_cxl_if_multi_branch_first_wins() {
	doc := '[p stock=200]'
	prog := '[?if [[@stock > 100, Plenty], [@stock > 10, Some], [*, None]]]'
	out := run(doc, prog, '')
	assert out == 'Plenty', 'got: "${out}"'
}

// ── `[?for [var, iterable, body]]` (§3.4) ────────────────────────────────────

fn test_cxl_for_iteration() {
	doc := '[product [variant sku=A] [variant sku=B] [variant sku=C]]'
	prog := '[?for [v, //variant, [?=v/@sku]]]'
	out := run(doc, prog, '')
	assert out == 'ABC', 'got: "${out}"'
}

fn test_cxl_for_with_separator_in_body() {
	// Body slot is mixed-content: interpolation + literal separator.
	// Comma can't appear bare inside an arg-array slot (it terminates
	// the slot per §D1) — semicolon, slash, etc. are unaffected.
	doc := '[p [v s=A] [v s=B] [v s=C]]'
	prog := '[?for [x, //v, [?=x/@s];]]'
	out := run(doc, prog, '')
	assert out == 'A;B;C;', 'got: "${out}"'
}

// ── `[?with [context, body]]` (§3.5) ─────────────────────────────────────────

fn test_cxl_with_shifts_context() {
	doc := '[product [meta owner=alice region=us]]'
	prog := '[?with [//meta, [?=@owner]/[?=@region]]]'
	out := run(doc, prog, '')
	assert out == 'alice/us', 'got: "${out}"'
}

// ── `[?def [name, body]]` / `[?use [name, ctx]]` (§3.7/§3.8) ─────────────────

fn test_cxl_def_use_block() {
	doc := '[p [v s=A] [v s=B]]'
	prog := "[?def [row, [?=@s];]]
[?for [x, //v, [?use [row, x]]]]"
	out := run(doc, prog, '')
	assert out.contains('A;') && out.contains('B;'), 'got: "${out}"'
}

fn test_cxl_use_no_context() {
	doc := '[p s=X]'
	prog := '[?def [show, [?=@s]]][?use [show]]'
	out := run(doc, prog, '')
	assert out == 'X', 'got: "${out}"'
}

// ── Filters (§4) ─────────────────────────────────────────────────────────────

fn test_cxl_filter_upper() {
	doc := '[p name=hello]'
	prog := '[?=[?upper [@name]]]'
	assert run(doc, prog, '') == 'HELLO'
}

fn test_cxl_filter_default_missing() {
	doc := '[p]'
	prog := '[?=[?default [@absent, 0]]]'
	assert run(doc, prog, '') == '0'
}

fn test_cxl_filter_default_present() {
	doc := '[p stock=42]'
	prog := '[?=[?default [@stock, 0]]]'
	assert run(doc, prog, '') == '42'
}

fn test_cxl_filter_trim_upper_compose() {
	// Filter composition: outer upper takes inner trim's result.
	doc := "[p name='  alice  ']"
	prog := '[?=[?upper [[?trim [@name]]]]]'
	assert run(doc, prog, '') == 'ALICE'
}

// ── output-target ────────────────────────────────────────────────────────────

fn test_cxl_html_auto_escape() {
	doc := "[p name='<script>alert(1)</script>']"
	prog := '[?cx output-target=html][?=@name]'
	out := run(doc, prog, '')
	assert !out.contains('<script>'), 'got: "${out}"'
	assert out.contains('&lt;script&gt;'), 'got: "${out}"'
}

fn test_cxl_text_no_escape() {
	doc := "[p name='<b>']"
	prog := '[?=@name]'
	out := run(doc, prog, '')
	assert out == '<b>', 'got: "${out}"'
}

// ── Top-of-file config directives ────────────────────────────────────────────

fn test_cxl_strips_output_target_directive() {
	doc := '[p n=A]'
	prog := '[?cx output-target=text][?=@n]'
	out := run(doc, prog, '')
	assert out == 'A', 'got: "${out}"'
}

// ── Errors ───────────────────────────────────────────────────────────────────

fn test_cxl_future_version_directive_errors() {
	// CXL 3.1 directives parse as EvalDirective per ADR 0016 R4 but
	// must error at a v0.6.0 CXL 1.0 evaluator.
	out := cx.eval_cxl('[p]', '[?let]', '') or { return }
	assert false, 'expected error, got "${out}"'
}

fn test_cxl_cond_directive_dropped() {
	// `?cond` was dropped at ADR 0017 §D7 — folded into multi-branch
	// `?if`. The evaluator must error pointing to the new shape.
	out := cx.eval_cxl('[p]', '[?cond [[@a, A]]]', '') or {
		assert err.msg().contains('dropped') || err.msg().contains('§D7')
		return
	}
	assert false, 'expected error, got "${out}"'
}
