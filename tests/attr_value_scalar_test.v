module main

import os
import testenv

// attr_value_scalar_test.v — element-construction attribute values are
// STRICTLY SCALAR (spec/code.md §6.4.1; #466/#268 owner ruling): ANY
// non-scalar evaluated attr value FAILS LOUD (cx-err:CXER0100), never
// stringifies:
//   • a PathExpr-valued attr (`attr=//a/b`) is a QUERY whose node-set result
//     cannot faithfully stringify — error, with a quote-the-value hint;
//   • any attr value evaluating to the empty sequence — pre-fix it silently
//     stringified to attr='';
//   • literal / $-bound element, array, and map values — the former
//     canonical-stringify seam (which backed the retired validate.md
//     `enum=[v …]` attr surface) is REMOVED; rich data goes in a child
//     element (`[field [enum v …]]`).
//
// Regression anchor (2026-07-06): `[pick select=//features/feature]` inside a
// program parses the bare attr value as a CXPath PathExpr (grammar [130] — a
// first-class ProgramExpr), evaluated at construction time. With no matching
// context it yielded the empty sequence, which pre-fix stringified to
// `select=''` with exit 0 — silent data loss.

fn cx_bin() string {
	return testenv.cx_bin()
}

fn tmp_doc(label string, content string) string {
	path := os.join_path(os.temp_dir(), 'cx_avs_${label}_${os.getpid()}.cx')
	os.write_file(path, content) or { panic(err) }
	return path
}

// ── 1. The reported repro: bare CXPath attr value must FAIL LOUD ─────────────
//
// #454 layering: the original repro ran DOC-LESS, so pre-#454 the query
// yielded the empty sequence and the construction guard (CXER0100 + the
// quote-the-value hint) caught it. Post-#454 a doc-rooted query with
// UNBOUND $doc raises the deeper diagnosis first (cx-err:CXER0001,
// XPDY0002 parity — code.md §1.3), covered by
// test_bare_cxpath_attr_value_docless_raises_unbound_doc below. To keep
// exercising the empty-sequence → CXER0100 + hint construction guard
// (the original silent-'' data-loss anchor), this test binds a
// NON-MATCHING $doc so the query legitimately evaluates to the empty
// sequence.

fn test_bare_cxpath_attr_value_fails_loud() {
	src := '[?let [= \$doc [other]] [?let [= \$sel [pick select=//features/feature]]\n  [out [\$sel]]]]\n'
	f := tmp_doc('repro', src)
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code != 0, 'bare CXPath attr value must error, got: ${r.output}'
	assert r.output.contains('CXER0100'), 'expected CXER0100, got: ${r.output}'
	// The actionable hint: quote the value to carry a literal path string.
	assert r.output.contains("select='//features/feature'"),
		'expected the quote-the-value hint, got: ${r.output}'
	// And the pre-fix silent data loss must be gone.
	assert !r.output.contains("select=''"), 'attr value silently dropped: ${r.output}'
}

// ── 1b. Doc-less variant: unbound $doc raises CXER0001 before construction ───
//
// #454: with NO data input and NO data root, the doc-rooted query itself
// is the error (context item undefined) — still loud, still no silent ''.

fn test_bare_cxpath_attr_value_docless_raises_unbound_doc() {
	src := '[?let [= \$sel [pick select=//features/feature]]\n  [out [\$sel]]]\n'
	f := tmp_doc('docless', src)
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code != 0, 'doc-less CXPath attr value must error, got: ${r.output}'
	assert r.output.contains('cx-err:CXER0001'), 'expected CXER0001 (unbound \$doc), got: ${r.output}'
	assert !r.output.contains("select=''"), 'attr value silently dropped: ${r.output}'
}

// ── 2. A matching doc does not legitimize it: node-set results error too ─────

fn test_cxpath_attr_value_with_matches_still_errors() {
	src := '[?let [= \$doc [features [feature "a"]]]\n  [pick select=//feature]]\n'
	f := tmp_doc('withdoc', src)
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code != 0, 'node-set attr value must error (never stringify): ${r.output}'
	assert r.output.contains('CXER0100'), 'expected CXER0100, got: ${r.output}'
}

// ── 3. Empty-sequence attr values raise CXER0100 (never a silent '') ─────────

fn test_empty_sequence_attr_value_errors() {
	f := tmp_doc('emptyseq', '[?let [= \$e ()] [a x=\$e]]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code != 0, 'empty-sequence attr value must error, got: ${r.output}'
	assert r.output.contains('CXER0100'), 'expected CXER0100, got: ${r.output}'
	assert !r.output.contains("[a x=''"), 'empty sequence silently wrote [a x=\'\']: ${r.output}'
}

// ── 4. The [?attr] computed-attribute VALUE follows the same rule ────────────

fn test_computed_attr_pathexpr_value_errors() {
	// A non-matching $doc is bound so the query evaluates (to the empty
	// sequence) and the CONSTRUCTION guard fires — doc-less would raise
	// the earlier #454 unbound-$doc CXER0001 instead (see test 1b).
	f := tmp_doc('dcattr', '[?let [= \$doc [other]] [?element "pick" [?attr "select" //features/feature]]]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code != 0, '[?attr] PathExpr value must error, got: ${r.output}'
	assert r.output.contains('CXER0100'), 'expected CXER0100, got: ${r.output}'
}

// ── 4b. Collection-valued attrs FAIL LOUD — the stringify seam is gone ───────
//
// The code.md §6.4.1 ↔ validate.md §3.5 conflict was resolved for §6.4.1
// (#466/#268 owner ruling): attributes are strictly scalar, so a literal /
// $-bound element, array, or map attr value raises CXER0100 with a
// child-element migration hint. The record-validator vocabulary moved to
// child elements (`[field [enum v …]]` / `[field [schema …]]` /
// `[schema [extends $Base]]`) — see conformance/stdlib/validate.cxd.

fn test_bound_collection_attr_value_fails_loud() {
	f := tmp_doc('enumattr', '[?let [= \$s [schema [field name="color" enum=["red", "green"]]]]\n  [out [\$s]]]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code != 0, 'collection attr value must error, got: ${r.output}'
	assert r.output.contains('CXER0100'), 'expected CXER0100, got: ${r.output}'
	// The actionable hint: rich data goes in a child element.
	assert r.output.contains('child element'), 'expected the child-element hint, got: ${r.output}'
	// And the old silent stringify must be gone.
	assert !r.output.contains("enum=\"['red', 'green']\""),
		'collection attr value silently stringified: ${r.output}'
}

// ── 5. The correct spelling — a QUOTED CXPath — stays a plain string ──────────

fn test_quoted_cxpath_attr_value_round_trips() {
	f := tmp_doc('quoted', "[pick select='//features/feature']\n")
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code == 0, 'quoted CXPath attr errored: ${r.output}'
	assert r.output.trim_space() == "[pick select='//features/feature']",
		'quoted CXPath attr did not round-trip: ${r.output}'
}

// ── 6. Scalar attr values are unaffected ─────────────────────────────────────

fn test_scalar_attr_values_unaffected() {
	f := tmp_doc('scalar', '[?let [= \$n "cx"] [code lang=\$n level=3 ok=true "hi"]]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code == 0, 'scalar attrs errored: ${r.output}'
	out := r.output.trim_space()
	assert out.contains('lang=cx') && out.contains('level=3') && out.contains('ok=true'),
		'scalar attrs wrong: ${r.output}'
}

fn test_bare_data_identity_unaffected() {
	f := tmp_doc('cfg', '[config host=localhost]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code == 0, 'identity case errored: ${r.output}'
	assert r.output.trim_space() == '[config host=localhost]', 'identity broken: ${r.output}'
}
