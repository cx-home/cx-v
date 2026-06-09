module main

import os

// Pass-2 D-A1 — CLI default action is the PROGRAM reading.
//
// Per spec/code.md §1.3: a bare CX resource EVALUATES — `cx <file|->` is
// equivalent to `cx eval <file|->`. The result is rendered per the
// requested target (default canonical CX; --xml/--json/--yaml/--csv/--tsv
// render the RESULT). A pure data document evaluates to itself, so the
// default is a no-op there. Non-CX --from inputs stay on the conversion
// path (no eval).
//
// These tests drive the compiled `cx` binary as a subprocess.

fn cx_bin() string {
	return os.join_path(@VMODROOT, 'target', 'cx')
}

fn tmp_file(label string, content string) string {
	path := os.join_path(os.temp_dir(), 'cx_cli_${label}_${os.getpid()}.cx')
	os.write_file(path, content) or { panic(err) }
	return path
}

// ── 1. Bare program file evaluates ───────────────────────────────────────────

fn test_bare_program_file_evaluates() {
	f := tmp_file('add', '[+ 1 2]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code == 0, 'expected exit 0, got ${r.exit_code}: ${r.output}'
	assert r.output.trim_space() == '3', 'expected 3, got: ${r.output}'
}

// ── 2. Bare pure-data file evaluates to itself ───────────────────────────────

fn test_bare_data_file_is_identity() {
	f := tmp_file('data', '[config host=localhost]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code == 0, 'expected exit 0, got ${r.exit_code}: ${r.output}'
	assert r.output.trim_space() == '[config host=localhost]', 'data not identity: ${r.output}'
}

// ── 3. --xml renders the RESULT, not a CX→XML conversion of source ───────────

fn test_default_xml_renders_result() {
	f := tmp_file('addxml', '[+ 1 2]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f} --xml')
	assert r.exit_code == 0, 'expected exit 0, got ${r.exit_code}: ${r.output}'
	// The evaluated result is the int 3, rendered as XML — NOT the program
	// source `[+ 1 2]` round-tripped through XML.
	assert r.output.contains('3'), 'expected result 3 in xml, got: ${r.output}'
	assert !r.output.contains('+'), 'looks like source was converted, not evaluated: ${r.output}'
}

// ── 4. --json renders the RESULT ─────────────────────────────────────────────

fn test_default_json_renders_result() {
	f := tmp_file('addjson', '[+ 10 20]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f} --json')
	assert r.exit_code == 0, 'expected exit 0, got ${r.exit_code}: ${r.output}'
	assert r.output.contains('30'), 'expected result 30 in json, got: ${r.output}'
}

// ── 5. Non-CX --from input is a conversion, NOT an eval ──────────────────────

fn test_non_cx_from_is_conversion() {
	path := os.join_path(os.temp_dir(), 'cx_cli_xmlin_${os.getpid()}.xml')
	os.write_file(path, '<root><a>1</a></root>') or { panic(err) }
	defer { os.rm(path) or {} }
	r := os.execute('${cx_bin()} --from=xml --to=cx ${path}')
	assert r.exit_code == 0, 'expected exit 0, got ${r.exit_code}: ${r.output}'
	// Conversion preserves structure; no program evaluation happens.
	assert r.output.contains('[root'), 'expected converted CX, got: ${r.output}'
	assert r.output.contains('[a'), 'expected child element, got: ${r.output}'
}

// ── 5b. EXPLICIT --from=cx selects the convert pipeline (data reading) ───────

fn test_explicit_from_cx_converts_not_eval() {
	// A program-shaped body under explicit --from=cx must NOT evaluate —
	// `--from=` is the convert (data-reading) surface. `[+ 1 2]` read as
	// data is an element/array, not arithmetic, so the output is NOT `3`.
	f := tmp_file('explfrom', '[+ 1 2]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} --from=cx --to=cx ${f}')
	assert r.exit_code == 0, 'expected exit 0, got ${r.exit_code}: ${r.output}'
	assert r.output.trim_space() != '3', 'explicit --from=cx evaluated (got 3) — should convert: ${r.output}'
}

// ── 6. `eval` subcommand remains a working alias ─────────────────────────────

fn test_eval_subcommand_alias() {
	f := tmp_file('aliasprog', '[+ 2 5]\n')
	defer { os.rm(f) or {} }
	bare := os.execute('${cx_bin()} ${f}')
	via_eval := os.execute('${cx_bin()} eval ${f}')
	assert bare.exit_code == 0 && via_eval.exit_code == 0, 'both should exit 0'
	assert bare.output == via_eval.output, 'bare and `eval` outputs diverge: ${bare.output} != ${via_eval.output}'
}
