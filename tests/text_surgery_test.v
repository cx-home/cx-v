module main

import os
import testenv

// text_surgery_test.v — #93: in-CX surgical text edits (so cx is viable for the
// whitespace-exact replacements we used to drop to Python/sed for).
//   strings:replace-exactly — fail-loud unless `from` occurs exactly once.
//   io:edit-file            — read → replace-exactly → write (atomic, gated).

fn cx_bin_ts() string {
	return testenv.cx_bin()
}

fn run_ts(src string, allow bool) os.Result {
	f := os.join_path(os.temp_dir(), 'cx_ts_${os.getpid()}_${src.len}.cx')
	os.write_file(f, src) or { panic('write: ${err}') }
	defer { os.rm(f) or {} }
	cap := if allow { '--allow-all ' } else { '' }
	return os.execute('${cx_bin_ts()} ${cap}${f}')
}

// ── strings:replace-exactly ──────────────────────────────────────────────────

fn test_replace_exactly_unique() {
	r := run_ts("[?lib 'cx-stdlib/strings'] [\$strings:replace-exactly \"a.b.c\" \"b\" \"X\"]", false)
	assert r.output.trim_space() == "'a.X.c'", 'unique replace wrong: ${r.output}'
}

fn test_replace_exactly_ambiguous_errs() {
	r := run_ts("[?lib 'cx-stdlib/strings'] [\$strings:replace-exactly \"a.a.a\" \"a\" \"X\"]", false)
	assert r.output.contains('CXER2903'), 'ambiguous should err CXER2903: ${r.output}'
	assert r.output.contains('found 3'), 'should report the count: ${r.output}'
}

fn test_replace_exactly_missing_errs() {
	r := run_ts("[?lib 'cx-stdlib/strings'] [\$strings:replace-exactly \"abc\" \"z\" \"X\"]", false)
	assert r.output.contains('CXER2903'), 'missing target should err CXER2903: ${r.output}'
	assert r.output.contains('found 0'), 'should report zero matches: ${r.output}'
}

// ── io:edit-file ─────────────────────────────────────────────────────────────

fn test_edit_file_real_edit() {
	target := os.join_path(os.temp_dir(), 'cx_ts_edit_${os.getpid()}.txt')
	os.write_file(target, 'hello OLD world') or { panic(err) }
	defer { os.rm(target) or {} }
	r := run_ts("[?lib 'cx-stdlib/io'] [\$io:edit-file \"${target}\" \"OLD\" \"NEW\"]", true)
	assert r.exit_code == 0, 'edit-file errored: ${r.output}'
	got := os.read_file(target) or { panic(err) }
	assert got == 'hello NEW world', 'file not edited correctly: "${got}"'
}

fn test_edit_file_ambiguous_does_not_write() {
	// `from` occurs twice → CXER2903 and the file must be left UNCHANGED.
	target := os.join_path(os.temp_dir(), 'cx_ts_noedit_${os.getpid()}.txt')
	os.write_file(target, 'x and x') or { panic(err) }
	defer { os.rm(target) or {} }
	r := run_ts("[?lib 'cx-stdlib/io'] [\$io:edit-file \"${target}\" \"x\" \"Y\"]", true)
	assert r.output.contains('CXER2903'), 'ambiguous edit-file should err: ${r.output}'
	got := os.read_file(target) or { panic(err) }
	assert got == 'x and x', 'file must be unchanged on a failed edit, got: "${got}"'
}

fn test_edit_file_cap_denied() {
	target := os.join_path(os.temp_dir(), 'cx_ts_cap_${os.getpid()}.txt')
	os.write_file(target, 'old') or { panic(err) }
	defer { os.rm(target) or {} }
	r := run_ts("[?lib 'cx-stdlib/io'] [\$io:edit-file \"${target}\" \"old\" \"new\"]", false)
	assert r.output.contains('CXER0271'), 'no caps → CXER0271 expected: ${r.output}'
	got := os.read_file(target) or { panic(err) }
	assert got == 'old', 'cap-denied edit must not touch the file: "${got}"'
}
