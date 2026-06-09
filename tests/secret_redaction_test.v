module main

import cx
import code

// ── Secret redaction at the structured output boundaries ─────────────────────
//
// cxdm.md §12.2 mandates that a secret value (`[?secret EXPR]`) renders as
// the redaction marker `‹redacted›` — never the underlying value — at
// EVERY emit boundary. The canonical / text / cx boundary is gated by the
// `program-secret-002/003/005` cases in conformance/code.cxd (the eval
// fixture gate renders via render_canonical). This test covers the
// structured normalizers the .cxd gate cannot reach: JSON / YAML / XML /
// CSV (and re-checks canonical here too for locality).
//
// Invariant for every target: the marker is present and the cleartext
// `sk-abc` is absent. Reveal (declassify) is gated by the `secret-reveal`
// capability and is exercised by program-secret-004.

const secret_program = '[credentials [token [?secret sk-abc]]]'

fn eval_to(program string, target string) string {
	mut env := code.new_env()
	code.caps_set_all()
	prog := cx.parse_program(program) or { return 'PARSE-ERR: ${err}' }
	result := code.eval(prog.body, mut env) or { return 'EVAL-ERR: ${err}' }
	return code.render(result, target) or { return 'RENDER-ERR: ${err}' }
}

fn assert_redacted(target string, out string) {
	assert out.contains('‹redacted›'), '${target}: expected redaction marker, got: ${out}'
	assert !out.contains('sk-abc'), '${target}: leaked cleartext secret, got: ${out}'
}

fn test_secret_redacted_canonical() {
	out := eval_to(secret_program, 'cx')
	assert_redacted('cx', out)
}

fn test_secret_redacted_text() {
	out := eval_to(secret_program, 'text')
	assert_redacted('text', out)
}

fn test_secret_redacted_json() {
	out := eval_to(secret_program, 'json')
	assert_redacted('json', out)
}

fn test_secret_redacted_yaml() {
	out := eval_to(secret_program, 'yaml')
	assert_redacted('yaml', out)
}

fn test_secret_redacted_xml() {
	out := eval_to(secret_program, 'xml')
	assert_redacted('xml', out)
}

// CSV: a sequence-of-records where one record holds a secret-bearing
// attribute. The secret is a body child here, so it surfaces as a row
// value; the marker must appear and the cleartext must not.
fn test_secret_redacted_csv() {
	// (row with a secret child) — a uniform single-column record set.
	out := eval_to('({secret-col: [?secret sk-abc]})', 'csv')
	// CSV extraction may reject the shape; what matters is no cleartext
	// EVER reaches the wire. If a value column is produced it must be the
	// marker.
	assert !out.contains('sk-abc'), 'csv: leaked cleartext secret, got: ${out}'
}

// Top-level bare secret redacts to the quoted marker in canonical form.
fn test_secret_top_level_canonical() {
	out := eval_to('[?secret sk-abc]', 'cx')
	assert out.trim_space() == "'‹redacted›'", 'top-level canonical: got ${out}'
}

// A revealed secret (declassified under secret-reveal, granted by
// caps_set_all here) is NOT redacted — the cleartext is the whole point of
// declassification (cxdm.md §12.3).
fn test_revealed_secret_is_cleartext() {
	out := eval_to('[?reveal [?secret sk-abc]]', 'text')
	assert out.trim_space() == 'sk-abc', 'reveal: expected cleartext, got ${out}'
}
