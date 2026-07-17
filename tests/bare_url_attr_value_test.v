module main

import os
import testenv
import cx

// bare_url_attr_value_test.v — a bare (unquoted) URL attribute value inside a
// PROGRAM (`[link href=https://x.com/a/b]`) is a parse error: the program
// attribute grammar reads the value as an expression (grammar [127c] — the
// same rule that admits `select=//a/b` as a CXPath PathExpr), so `://` after
// the scheme cannot be more string. DATA's BareValue ([L70]) admits URLs,
// which is exactly why users hit this — the diagnostic must say the fix
// (quote the value), not the pre-fix "expected identifier after ':' in atom
// literal, got '//'" left by the orphaned `: //` tokens.

fn cx_bin() string {
	return testenv.cx_bin()
}

fn tmp_doc(label string, content string) string {
	path := os.join_path(os.temp_dir(), 'cx_urlattr_${label}_${os.getpid()}.cx')
	os.write_file(path, content) or { panic(err) }
	return path
}

// ── 1. The reported repro: bare URL attr value fails with the quote hint ────

fn test_bare_url_attr_value_parse_error_carries_quote_hint() {
	src := '[?let [= \$x 1] [link href=https://x.com/a/b]]'
	cx.parse_program(src) or {
		msg := err.msg()
		assert msg.contains('CXER0100'), 'expected CXER0100, got: ${msg}'
		assert msg.contains("href='https://x.com/a/b'"),
			'expected the quote-the-value hint, got: ${msg}'
		assert !msg.contains('atom literal'),
			'the orphaned-colon atom-literal error must not surface: ${msg}'
		return
	}
	assert false, 'bare URL attr value must be a parse error'
}

// ── 2. Same shape through the computed-name [?element] body ─────────────────

fn test_bare_url_attr_value_in_computed_element_errors() {
	src := '[?element "link" href=https://x.com/a/b]'
	cx.parse_program(src) or {
		msg := err.msg()
		assert msg.contains("href='https://x.com/a/b'"),
			'expected the quote-the-value hint, got: ${msg}'
		return
	}
	assert false, 'bare URL attr value in [?element] must be a parse error'
}

// ── 3. The suggested fix works: the quoted value is a literal string ─────────

fn test_quoted_url_attr_value_parses_and_evaluates() {
	f := tmp_doc('quoted', "[?let [= \$x 1] [link href='https://x.com/a/b']]\n")
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code == 0, 'quoted URL attr value must evaluate, got: ${r.output}'
	assert r.output.contains('https://x.com/a/b'), 'URL lost: ${r.output}'
}

// ── 4. No regression: QName bare values still fold to one string ────────────

fn test_qname_bare_attr_values_still_fold() {
	f := tmp_doc('qname', '[?let [= \$x 1] [rect kind=svg:rect xmlns=urn:example]]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code == 0, 'QName bare attr value must still parse, got: ${r.output}'
	assert r.output.contains('svg:rect'), 'QName fold lost: ${r.output}'
	assert r.output.contains('urn:example'), 'QName fold lost: ${r.output}'
}

// ── 5. No regression: PathExpr-valued attrs stay expressions ([127c]) ────────

fn test_pathexpr_attr_value_still_parses_as_expression() {
	// `select=//a/b` is an intentional CXPath PathExpr attr value; the
	// bare-URL detection (ident ':' '//', byte-adjacent) must not touch it.
	cx.parse_program('[pick select=//a/b]') or {
		assert false, 'PathExpr attr value must still parse: ${err.msg()}'
		return
	}
}

// ── 6. The end-to-end CLI diagnostic (the reported UX) ───────────────────────

fn test_cli_diagnostic_hints_quoting() {
	f := tmp_doc('cli', '[?let [= \$x 1] [link href=https://x.com/a/b]]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code != 0, 'bare URL attr value must fail loud, got: ${r.output}'
	assert r.output.contains('CXER0100'), 'expected CXER0100, got: ${r.output}'
	assert r.output.contains("href='https://x.com/a/b'"),
		'expected the quote-the-value hint, got: ${r.output}'
}
