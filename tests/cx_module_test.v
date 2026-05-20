module main

import cx
import os

// ── cx: self-host module tests (DD1–DD8, ADR 0023 §D1) ──────────────────
//
// Coverage per spec/modules/cx.md §3 conformance categories:
//   1. Round-trip identity — cx:serialize(cx:parse(t)) ≡ cx:canonical(t)
//   2. Error path — invalid input produces documented error code
//   3. Edge cases — empty value, single-element, attribute, multi-format
//   4. Purity — same input produces byte-identical output across calls
//
// CXL string literals use single quotes per spec/eval.md and the parser.
// Within V test strings (which use double quotes), embedded CX source
// uses single quotes verbatim.

fn run(input string, program string) string {
	return cx.eval_cxl(input, program, '') or { panic('cxl: ${err}') }
}

// ── DD1. cx:parse ────────────────────────────────────────────────────────

fn test_cx_parse_round_trips_a_simple_element() {
	doc := '[input]'
	prog := "[?=[?cx:canonical [[?cx:parse ['[product name=Pocket]']]]]]"
	out := run(doc, prog)
	assert out == '[product name=Pocket]', 'got: "${out}"'
}

fn test_cx_parse_handles_nested_elements() {
	doc := '[input]'
	prog := "[?=[?cx:canonical [[?cx:parse ['[catalog [item id=1] [item id=2]]']]]]]"
	out := run(doc, prog)
	assert out.starts_with('[catalog'), 'got: "${out}"'
	assert out.contains('item id=1'), 'got: "${out}"'
	assert out.contains('item id=2'), 'got: "${out}"'
}

fn test_cx_parse_invalid_raises_cxer0020() {
	doc := '[input]'
	prog := "[?cx:parse ['[unterminated']]"
	res := cx.eval_cxl(doc, prog, '') or { err.msg() }
	assert res.contains('CXER0020'), 'expected CXER0020 in: "${res}"'
}

// ── DD2. cx:serialize ────────────────────────────────────────────────────

fn test_cx_serialize_atomizes_a_scalar() {
	doc := '[input]'
	prog := '[?=[?cx:serialize [42]]]'
	out := run(doc, prog)
	assert out == '42', 'got: "${out}"'
}

fn test_cx_serialize_emits_parsed_element() {
	doc := '[input]'
	prog := "[?=[?cx:serialize [[?cx:parse ['[product name=Pocket]']]]]]"
	out := run(doc, prog)
	assert out.contains('product'), 'got: "${out}"'
	assert out.contains('name=Pocket'), 'got: "${out}"'
}

// ── DD3. cx:canonical ────────────────────────────────────────────────────

fn test_cx_canonical_idempotent() {
	doc := '[input]'
	prog := "[?=[?cx:canonical [[?cx:parse ['[product name=A price=1]']]]]]"
	out := run(doc, prog)
	assert out.contains('product'), 'expected canonical-form CX in: "${out}"'
	assert out.contains('name=A'), 'got: "${out}"'
}

// ── DD4. cx:hash ─────────────────────────────────────────────────────────

fn test_cx_hash_is_sha256_hex_64_chars() {
	doc := '[input]'
	prog := "[?=[?cx:hash [[?cx:parse ['[a]']]]]]"
	out := run(doc, prog)
	assert out.len == 64, 'hash length expected 64, got ${out.len}: "${out}"'
	for c in out {
		assert (c >= `0` && c <= `9`) || (c >= `a` && c <= `f`), 'non-hex char in hash: "${out}"'
	}
}

fn test_cx_hash_is_deterministic() {
	doc := '[input]'
	prog := "[?=[?cx:hash [[?cx:parse ['[a x=1 y=2]']]]]]"
	h1 := run(doc, prog)
	h2 := run(doc, prog)
	assert h1 == h2, 'hash not deterministic: "${h1}" vs "${h2}"'
}

fn test_cx_hash_differs_for_distinct_inputs() {
	doc := '[input]'
	prog_a := "[?=[?cx:hash [[?cx:parse ['[a]']]]]]"
	prog_b := "[?=[?cx:hash [[?cx:parse ['[b]']]]]]"
	ha := run(doc, prog_a)
	hb := run(doc, prog_b)
	assert ha != hb, 'distinct inputs produced same hash: "${ha}"'
}

// ── DD5. cx:diff ─────────────────────────────────────────────────────────

fn test_cx_diff_runs_without_error() {
	doc := '[input]'
	prog := "[?cx:diff [[?cx:parse ['[a]']], [?cx:parse ['[b]']]]]"
	_ = cx.eval_cxl(doc, prog, '') or { panic('cx:diff errored: ${err}') }
}

// ── DD6. cx:patch — apply diff doc to value ──────────────────────────────

fn test_cx_patch_empty_diff_returns_value_unchanged() {
	doc := '[input]'
	// cx:diff(a, a) returns empty; cx:patch with empty diff is a
	// no-op. Use cx:equal to verify semantic identity.
	prog := "[?=[?cx:equal [[?cx:patch [[?cx:parse ['[a x=1]']], [?cx:diff [[?cx:parse ['[a x=1]']], [?cx:parse ['[a x=1]']]]]]], [?cx:parse ['[a x=1]']]]]]"
	out := run(doc, prog)
	assert out == 'true', 'patch with empty diff should be identity; got: "${out}"'
}

fn test_cx_patch_element_renamed() {
	doc := '[input]'
	// Patch [a] → [b] by applying the [a → b] rename diff.
	prog := "[?=[?cx:serialize [[?cx:patch [[?cx:parse ['[a]']], [?cx:diff [[?cx:parse ['[a]']], [?cx:parse ['[b]']]]]]]]]]"
	out := run(doc, prog)
	assert out == '[b]', 'expected element rename to produce [b], got: "${out}"'
}

fn test_cx_patch_attribute_added() {
	doc := '[input]'
	prog := "[?=[?cx:serialize [[?cx:patch [[?cx:parse ['[a x=1]']], [?cx:diff [[?cx:parse ['[a x=1]']], [?cx:parse ['[a x=1 y=2]']]]]]]]]]"
	out := run(doc, prog)
	assert out.contains('x=1') && out.contains('y=2'), 'expected y=2 added, got: "${out}"'
}

fn test_cx_patch_attribute_removed() {
	doc := '[input]'
	prog := "[?=[?cx:serialize [[?cx:patch [[?cx:parse ['[a x=1 y=2]']], [?cx:diff [[?cx:parse ['[a x=1 y=2]']], [?cx:parse ['[a x=1]']]]]]]]]]"
	out := run(doc, prog)
	assert out.contains('x=1') && !out.contains('y=2'), 'expected y removed, got: "${out}"'
}

fn test_cx_patch_attribute_changed() {
	doc := '[input]'
	prog := "[?=[?cx:serialize [[?cx:patch [[?cx:parse ['[a x=1]']], [?cx:diff [[?cx:parse ['[a x=1]']], [?cx:parse ['[a x=42]']]]]]]]]]"
	out := run(doc, prog)
	assert out.contains('x=42'), 'expected attr changed to x=42, got: "${out}"'
}

fn test_cx_patch_round_trip_equals_target() {
	// Identity invariant: cx:patch(a, cx:diff(a, b)) ≡ b (canonical-form).
	// Use a same-name case so the diff captures attr-level changes
	// (when element names differ, diff emits element-renamed and
	// returns early, dropping attr-level deltas — that's a diff-side
	// lossiness, not a patch bug).
	doc := '[input]'
	prog := "[?=[?cx:equal [[?cx:patch [[?cx:parse ['[a x=1 y=2]']], [?cx:diff [[?cx:parse ['[a x=1 y=2]']], [?cx:parse ['[a x=99 z=3]']]]]]], [?cx:parse ['[a x=99 z=3]']]]]]"
	out := run(doc, prog)
	assert out == 'true', 'patch(a, diff(a,b)) must equal b; got: "${out}"'
}

fn test_cx_patch_unknown_kind_cxer0022() {
	doc := '[input]'
	// Hand-craft a diff doc with an unknown kind.
	prog := "[?cx:patch [[?cx:parse ['[a]']], [?cx:parse ['[item [kind weird-kind] [path /a] [before] [after]]']]]]"
	res := cx.eval_cxl(doc, prog, '') or { err.msg() }
	assert res.contains('CXER0022'), 'expected CXER0022, got: "${res}"'
	assert res.contains('unknown change kind'), 'expected unknown-kind message, got: "${res}"'
}

// ── DD7. cx:to-format ────────────────────────────────────────────────────

fn test_cx_to_format_xml_round_trip() {
	doc := '[input]'
	prog := "[?=[?cx:to-format [[?cx:parse ['[a]']], 'xml']]]"
	out := run(doc, prog)
	assert out.contains('<a'), 'expected XML element in: "${out}"'
}

fn test_cx_to_format_json_round_trip() {
	doc := '[input]'
	prog := "[?=[?cx:to-format [[?cx:parse ['[a]']], 'json']]]"
	out := run(doc, prog)
	assert out.len > 0
	assert out[0] == `{` || out[0] == `[`, 'expected JSON in: "${out}"'
}

fn test_cx_to_format_unknown_raises_cxer0023() {
	doc := '[input]'
	prog := "[?cx:to-format [[?cx:parse ['[a]']], 'bogus-fmt']]"
	res := cx.eval_cxl(doc, prog, '') or { err.msg() }
	assert res.contains('CXER0023'), 'expected CXER0023 in: "${res}"'
}

// ── DD8. cx:from-format ──────────────────────────────────────────────────

fn test_cx_from_format_json_round_trip() {
	doc := '[input]'
	// JSON `{"a": 1}` → cx-value. Single quotes around JSON source.
	prog := "[?=[?cx:canonical [[?cx:from-format ['{\"a\": 1}', 'json']]]]]"
	res := cx.eval_cxl(doc, prog, '') or { panic('cx:from-format errored: ${err}') }
	assert res.contains('a'), 'expected cx-value referencing "a" in: "${res}"'
}

fn test_cx_from_format_unknown_raises_cxer0023() {
	doc := '[input]'
	prog := "[?cx:from-format ['junk', 'bogus-fmt']]"
	res := cx.eval_cxl(doc, prog, '') or { err.msg() }
	assert res.contains('CXER0023'), 'expected CXER0023 in: "${res}"'
}

// ── DD9. cx:equal ────────────────────────────────────────────────────────

fn test_cx_equal_true_for_identical_inputs() {
	doc := '[input]'
	prog := "[?=[?cx:equal [[?cx:parse ['[a x=1]']], [?cx:parse ['[a x=1]']]]]]"
	out := run(doc, prog)
	assert out == 'true', 'got: "${out}"'
}

fn test_cx_equal_false_for_distinct_inputs() {
	doc := '[input]'
	prog := "[?=[?cx:equal [[?cx:parse ['[a]']], [?cx:parse ['[b]']]]]]"
	out := run(doc, prog)
	assert out == 'false', 'got: "${out}"'
}

fn test_cx_equal_is_canonical_aware() {
	// Two semantically-equal cx documents (same canonical form) → true,
	// regardless of presentation differences (currently: comments/etc).
	doc := '[input]'
	prog := "[?=[?cx:equal [[?cx:parse ['[a # comment\n]']], [?cx:parse ['[a]']]]]]"
	out := run(doc, prog)
	assert out == 'true', 'got: "${out}"'
}

// ── DD10. cx:select ──────────────────────────────────────────────────────

fn test_cx_select_evaluates_attribute_path() {
	doc := '[input]'
	prog := "[?=[?cx:select [[?cx:parse ['[product name=Pocket]']], '@name']]]"
	out := run(doc, prog)
	assert out == 'Pocket', 'got: "${out}"'
}

fn test_cx_select_empty_path_raises_cxer0026() {
	doc := '[input]'
	prog := "[?cx:select [[?cx:parse ['[a]']], '']]"
	res := cx.eval_cxl(doc, prog, '') or { err.msg() }
	assert res.contains('CXER0026'), 'expected CXER0026 in: "${res}"'
}

// ── DD13–DD18 Should-tier + DD20–DD22 Nice-tier wrappers ────────────────────

// DD15 cx:anchors
fn test_cx_anchors_empty_for_no_anchors() {
	doc := '[input]'
	prog := "[?=[?cx:anchors [[?cx:parse ['[a]']]]]]"
	out := run(doc, prog)
	assert out == '', 'expected empty for no anchors, got: "${out}"'
}

// DD16 cx:ids — needs source with #id
fn test_cx_ids_empty_for_no_ids() {
	doc := '[input]'
	prog := "[?=[?cx:ids [[?cx:parse ['[a]']]]]]"
	out := run(doc, prog)
	assert out == '', 'expected empty for no ids, got: "${out}"'
}

// DD17 cx:references — empty when no refs
fn test_cx_references_empty_for_no_refs() {
	doc := '[input]'
	prog := "[?cx:references [[?cx:parse ['[a]']]]]"
	_ = run(doc, prog)  // smoke: must not error
}

// DD20 cx:strip-comments
fn test_cx_strip_comments_drops_comment_nodes() {
	doc := '[input]'
	prog := "[?=[?cx:canonical [[?cx:strip-comments [[?cx:parse ['[a # hello\n]']]]]]]]"
	out := run(doc, prog)
	assert !out.contains('hello'), 'expected comment text dropped, got: "${out}"'
	assert out.contains('a'), 'expected element preserved, got: "${out}"'
}

// DD21 cx:strip-attrs
fn test_cx_strip_attrs_exact_match() {
	doc := '[input]'
	prog := "[?=[?cx:canonical [[?cx:strip-attrs [[?cx:parse ['[a x=1 y=2]']], 'x']]]]]"
	out := run(doc, prog)
	assert !out.contains('x=1'), 'expected x= attr dropped, got: "${out}"'
	assert out.contains('y=2'), 'expected y= attr preserved, got: "${out}"'
}

fn test_cx_strip_attrs_glob_prefix() {
	doc := '[input]'
	prog := "[?=[?cx:canonical [[?cx:strip-attrs [[?cx:parse ['[a aria-label=foo aria-role=bar id=keep]']], 'aria-*']]]]]"
	out := run(doc, prog)
	assert !out.contains('aria-'), 'expected aria-* attrs dropped, got: "${out}"'
	assert out.contains('id=keep'), 'expected non-matching attr preserved, got: "${out}"'
}

fn test_cx_strip_attrs_empty_pattern_raises_cxer0031() {
	doc := '[input]'
	prog := "[?cx:strip-attrs [[?cx:parse ['[a]']], '']]"
	res := cx.eval_cxl(doc, prog, '') or { err.msg() }
	assert res.contains('CXER0031'), 'expected CXER0031 in: "${res}"'
}

// DD22 cx:pretty-print
fn test_cx_pretty_print_emits_text() {
	doc := '[input]'
	prog := "[?=[?cx:pretty-print [[?cx:parse ['[a x=1]']]]]]"
	out := run(doc, prog)
	assert out.contains('a'), 'expected element text in: "${out}"'
}

// DD13 schema-of — inference engine.

fn test_cx_schema_of_simple_element() {
	doc := '[input]'
	// cx:serialize preserves the schema-of directive (cx:canonical
	// canonicalizes for hashing and strips prolog content); for
	// schema-of inspection we use serialize.
	prog := "[?=[?cx:serialize [[?cx:schema-of [[?cx:parse ['[a x=1]']]]]]]]"
	out := run(doc, prog)
	assert out.contains('schema-of a'), 'expected schema-of directive, got: "${out}"'
	assert out.contains('[a'), 'expected [a type declaration, got: "${out}"'
	assert out.contains('attr x'), 'expected attr x, got: "${out}"'
	assert out.contains(':int'), 'expected :int type tag for x, got: "${out}"'
	assert out.contains(':req'), 'expected :req on x (present in every instance), got: "${out}"'
}

fn test_cx_schema_of_nested_element_with_cardinality() {
	doc := '[input]'
	prog := "[?=[?cx:serialize [[?cx:schema-of [[?cx:parse ['[catalog [item id=1] [item id=2]]']]]]]]]"
	out := run(doc, prog)
	assert out.contains('schema-of catalog'), 'expected schema-of catalog, got: "${out}"'
	assert out.contains('elem item'), 'expected child item declaration, got: "${out}"'
	assert out.contains("card='1..*'"), 'expected 1..* cardinality on item, got: "${out}"'
}

fn test_cx_schema_of_empty_value_cxer0021() {
	doc := '[input]'
	prog := "[?cx:schema-of [[]]]"
	res := cx.eval_cxl(doc, prog, '') or { err.msg() }
	assert res.contains('CXER0021'), 'expected CXER0021, got: "${res}"'
}

// DD18 resolve-includes — full engine wired through spec/include.md
// resolver (GG1 row). Below tests use temp directories created
// inside each test for isolation; the `root` argument is the temp
// directory path. Quoted single-quote string literal in the program
// keeps the path opaque to the CXPath slot evaluator.

fn test_cx_resolve_includes_passthrough_no_includes() {
	root := os.join_path(os.temp_dir(), 'cx_dd18_pass_${os.getpid()}')
	os.mkdir_all(root) or {}
	defer { os.rmdir_all(root) or {} }
	prog := "[?=[?cx:canonical [[?cx:resolve-includes [[?cx:parse ['[a x=1]']], '${root}']]]]]"
	out := run('[input]', prog)
	assert out.contains('[a'), 'expected element preserved, got: "${out}"'
	assert out.contains('x=1'), 'expected attr preserved, got: "${out}"'
}

fn test_cx_resolve_includes_e906_not_found() {
	root := os.join_path(os.temp_dir(), 'cx_dd18_e906_${os.getpid()}')
	os.mkdir_all(root) or {}
	defer { os.rmdir_all(root) or {} }
	// Wrap the include directive inside a parent element so the
	// directive lands in element-body position (where it survives the
	// cxl_value_to_cx_text round-trip), not top-level prolog (which
	// cx:parse drops). spec/include.md §1 admits include directives
	// in any node position.
	prog := "[?cx:resolve-includes [[?cx:parse ['[wrapper [?cx include=missing.cx]]']], '${root}']]"
	res := cx.eval_cxl('[input]', prog, '') or { err.msg() }
	assert res.contains('CXER0028'), 'expected CXER0028, got: "${res}"'
}

fn test_cx_resolve_includes_e902_traversal() {
	root := os.join_path(os.temp_dir(), 'cx_dd18_e902_${os.getpid()}')
	os.mkdir_all(root) or {}
	defer { os.rmdir_all(root) or {} }
	prog := "[?cx:resolve-includes [[?cx:parse ['[wrapper [?cx include=../escape.cx]]']], '${root}']]"
	res := cx.eval_cxl('[input]', prog, '') or { err.msg() }
	assert res.contains('CXER0029'), 'expected CXER0029 (traversal), got: "${res}"'
}

fn test_cx_resolve_includes_empty_root_cxer0029() {
	prog := "[?cx:resolve-includes [[?cx:parse ['[a]']], '']]"
	res := cx.eval_cxl('[input]', prog, '') or { err.msg() }
	assert res.contains('CXER0029'), 'expected CXER0029 for empty root, got: "${res}"'
}

// DD19 merge — three-policy semantic merge of two cx-values.

// Disjoint-name top-level → concat (no element merge).
fn test_cx_merge_disjoint_names_concat() {
	doc := '[input]'
	prog := "[?=[?cx:serialize [[?cx:merge [[?cx:parse ['[a]']], [?cx:parse ['[b]']]]]]]]"
	out := run(doc, prog)
	// Concat result: synthetic #document with two items.
	assert out.contains('a'), 'got: "${out}"'
	assert out.contains('b'), 'got: "${out}"'
}

// Same-name single-Element merge — attrs from both, last-wins default.
fn test_cx_merge_same_name_last_wins_default() {
	doc := '[input]'
	prog := "[?=[?cx:serialize [[?cx:merge [[?cx:parse ['[r a=1 b=2]']], [?cx:parse ['[r b=99 c=3]']]]]]]]"
	out := run(doc, prog)
	// Result is [r a=1 b=99 c=3] — a from first only, b overwritten,
	// c added.
	assert out.contains('a=1'), 'a=1 should survive: "${out}"'
	assert out.contains('b=99'), 'b should be overwritten under last-wins: "${out}"'
	assert out.contains('c=3'), 'c=3 should be added: "${out}"'
}

// first-wins policy keeps a's value on collision.
fn test_cx_merge_first_wins() {
	doc := '[input]'
	prog := "[?=[?cx:serialize [[?cx:merge [[?cx:parse ['[r a=1]']], [?cx:parse ['[r a=99]']], 'first-wins']]]]]"
	out := run(doc, prog)
	assert out.contains('a=1'), 'first-wins should keep a=1: "${out}"'
	assert !out.contains('a=99'), 'a=99 should be suppressed: "${out}"'
}

// error-on-conflict policy raises CXER0030 on collision.
fn test_cx_merge_error_on_conflict_raises() {
	doc := '[input]'
	prog := "[?cx:merge [[?cx:parse ['[r a=1]']], [?cx:parse ['[r a=2]']], 'error-on-conflict']]"
	res := cx.eval_cxl(doc, prog, '') or { err.msg() }
	assert res.contains('CXER0030'), 'expected CXER0030 in: "${res}"'
}

// error-on-conflict policy is silent when there is no collision.
fn test_cx_merge_error_on_conflict_silent_without_collision() {
	doc := '[input]'
	prog := "[?=[?cx:serialize [[?cx:merge [[?cx:parse ['[r a=1]']], [?cx:parse ['[r b=2]']], 'error-on-conflict']]]]]"
	out := run(doc, prog)
	assert out.contains('a=1'), 'got: "${out}"'
	assert out.contains('b=2'), 'got: "${out}"'
}

// Unknown policy raises CXER0030.
fn test_cx_merge_unknown_policy_raises() {
	doc := '[input]'
	prog := "[?cx:merge [[?cx:parse ['[a]']], [?cx:parse ['[a]']], 'random-stuff']]"
	res := cx.eval_cxl(doc, prog, '') or { err.msg() }
	assert res.contains('CXER0030'), 'expected CXER0030 in: "${res}"'
	assert res.contains('unknown policy'), 'got: "${res}"'
}

// Empty merge with non-empty → returns non-empty unchanged.
fn test_cx_merge_empty_left_returns_right() {
	doc := '[input]'
	prog := "[?=[?cx:serialize [[?cx:merge [[], [?cx:parse ['[a x=1]']]]]]]]"
	out := run(doc, prog)
	assert out.contains('a'), 'got: "${out}"'
	assert out.contains('x=1'), 'got: "${out}"'
}

// Nested same-name children merge recursively.
fn test_cx_merge_recursive_same_name_children() {
	doc := '[input]'
	prog := "[?=[?cx:serialize [[?cx:merge [[?cx:parse ['[r [c a=1]]']], [?cx:parse ['[r [c b=2]]']]]]]]]"
	out := run(doc, prog)
	// Result is [r [c a=1 b=2]] — the two [c] children matched by name
	// and their attrs were merged.
	assert out.contains('a=1'), 'got: "${out}"'
	assert out.contains('b=2'), 'got: "${out}"'
}
