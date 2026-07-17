module main

import os
import testenv

// str_raw_literal_test.v — #93 (literal piece): the `r'''…'''` / `r"""…"""`
// RAW triple-quoted string preserves its content VERBATIM (no common-indent
// dedent), so leading-whitespace-significant blocks (indented code, tab-aligned
// text) survive byte-exact — the authoring half of in-CX surgical edits. Plain
// `'''…'''` keeps its dedent; a bare `r` stays an ordinary identifier.

fn cx_bin_rl() string {
	return testenv.cx_bin()
}

fn run_rl(src string) os.Result {
	f := os.join_path(os.temp_dir(), 'cx_rl_${os.getpid()}_${src.len}.cx')
	os.write_file(f, src) or { panic('write: ${err}') }
	defer { os.rm(f) or {} }
	return os.execute('${cx_bin_rl()} ${f}')
}

fn test_raw_preserves_leading_indent() {
	// r''' → no dedent: the two leading tabs on each content line survive.
	r := run_rl("[?str r'''\n\t\tA\n\t\tB''']")
	assert r.exit_code == 0, 'errored: ${r.output}'
	assert r.output.contains('\t\tA'), 'raw literal must preserve leading tabs: ${r.output}'
	assert r.output.contains('\t\tB'), 'raw literal must preserve leading tabs: ${r.output}'
}

fn test_plain_triple_still_dedents() {
	// plain ''' → dedent strips the leading blank line + common `\t\t` indent.
	r := run_rl("[?str '''\n\t\tA\n\t\tB''']")
	assert r.exit_code == 0, 'errored: ${r.output}'
	assert !r.output.contains('\t\tA'), 'plain triple must dedent (no leading tabs): ${r.output}'
	assert r.output.contains('A'), 'dedented content present: ${r.output}'
}

fn test_raw_double_quote() {
	r := run_rl('[?str r"""\n\tX"""]')
	assert r.exit_code == 0, 'errored: ${r.output}'
	assert r.output.contains('\tX'), 'r""" must preserve the leading tab: ${r.output}'
}

fn test_bare_r_identifier_unaffected() {
	// `r` is only a raw-string prefix immediately before a triple quote; a bare
	// binding named `r` must still be an ordinary identifier.
	r := run_rl('[?let [= $r 5] [+ $r 1]]')
	assert r.exit_code == 0, 'errored: ${r.output}'
	assert r.output.trim_space() == '6', 'bare ident r broke: ${r.output}'
}

fn test_raw_hole_in_str_directive() {
	// r''' composes with [?str] interpolation (#66 holes) — the raw body is the
	// template, computed holes still evaluate.
	r := run_rl("[?let [= \$n 2] [?str r'''v={[* \$n 3]}''']]")
	assert r.exit_code == 0, 'errored: ${r.output}'
	assert r.output.contains('v=6'), 'raw template with computed hole failed: ${r.output}'
}
