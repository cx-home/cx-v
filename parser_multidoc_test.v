module cx

// Regression tests for lexer-driven multi-document detection.
//
// Bug: the multi-doc guard in parse()/parse_cx() was a cheap textual
// `src.contains('\n---\n')`, which is NOT RawText-aware. It false-positived
// on a `---` line INSIDE a `[# … #]` RawText payload (CX multi-doc *examples*
// under test), so the single-doc C ABI (cx_to_ast_bin) and `cx validate`
// rejected the conformance .cxd suites (code, core, extended, xml, md) with
// "use parse_stream for multi-doc input" / "multi-document inputs not yet
// supported".
//
// Fix: parse one document; parse_document consumes a `---` inside RawText as
// content and stops ONLY at a genuine TOP-LEVEL `---` separator. So input
// remaining after the first document ⇒ genuine multi-doc.

// A `---` inside a RawText payload must NOT trigger multi-doc detection.
fn test_parse_dashes_inside_rawtext_is_single_doc() {
	src := '[doc [# line1\n---\nline2 #]]'
	doc := parse(src) or { panic('parse should succeed, got: ${err}') }
	assert doc.elements.len == 1
}

// parse_cx must classify the same input as single (not multi).
fn test_parse_cx_dashes_inside_rawtext_is_single() {
	src := '[doc [# alpha\n---\nbeta #]]'
	res := parse_cx(src) or { panic('parse_cx should succeed, got: ${err}') }
	assert !res.is_multi
	assert res.single != none
}

// A genuine TOP-LEVEL `---` separator must still be reported as multi-doc.
fn test_parse_top_level_separator_still_rejected() {
	src := '[a]\n---\n[b]'
	if _ := parse(src) {
		assert false, 'parse() must reject genuine top-level multi-doc'
	}
}

// parse_cx must classify a genuine top-level separator as multi.
fn test_parse_cx_top_level_separator_is_multi() {
	src := '[a]\n---\n[b]'
	res := parse_cx(src) or { panic('parse_cx should succeed for multi-doc, got: ${err}') }
	assert res.is_multi
	multi := res.multi or { panic('expected multi documents') }
	assert multi.len == 2
}

// A `---` inside RawText AND a real top-level separator: two docs, the first
// of which carries the embedded dashes verbatim.
fn test_parse_cx_mixed_rawtext_and_top_level() {
	src := '[doc [# x\n---\ny #]]\n---\n[other]'
	res := parse_cx(src) or { panic('parse_cx should succeed, got: ${err}') }
	assert res.is_multi
	multi := res.multi or { panic('expected multi documents') }
	assert multi.len == 2
}
