module main

import os
import testenv

// #462 — `cx select 'PATH' [FILE]`: the CXPath query subcommand, implemented
// per the reconciled spec/03-approved/misc/cli.md §3.8.
//
// Contract under test:
//   * PATH is a single CXPath value expression ($doc-anchored, /-rooted, or
//     //-descendant); anything else is a usage error (exit 2).
//   * FILE (or stdin when `-` / absent) is read via the DATA reading and
//     bound as $doc / $input.
//   * Matches print one per line, document order, canonical CX; attribute-
//     axis matches materialize as `[name value]` fields; a single-focus plain
//     child-chain attribute read prints the typed scalar (code.md §6.2
//     terminal-attribute unwrap). Empty match set prints nothing.
//   * Exit 0 = ≥1 match, 1 = empty match set, 2 = error.
//   * Capability-neutral: no --allow-* accepted or needed.

fn cx_bin() string {
	return testenv.cx_bin()
}

fn tmp_file(label string, content string) string {
	path := os.join_path(os.temp_dir(), 'cx_cli_select_${label}_${os.getpid()}.cx')
	os.write_file(path, content) or { panic(err) }
	return path
}

const users_doc = '[users [user name=Alice role=admin] [user name=Bob role=dev]]\n'

// ── matches: exit 0, one per line, document order ────────────────────────────

fn test_select_descendant_matches() {
	f := tmp_file('users', users_doc)
	defer { os.rm(f) or {} }
	r := os.execute("${cx_bin()} select '//user' ${f}")
	assert r.exit_code == 0, 'expected exit 0, got ${r.exit_code}: ${r.output}'
	lines := r.output.trim_space().split('\n')
	assert lines.len == 2, 'expected 2 matches, got ${lines.len}: ${r.output}'
	assert lines[0].contains('Alice'), 'document order broken: ${r.output}'
	assert lines[1].contains('Bob'), 'document order broken: ${r.output}'
}

fn test_select_document_rooted() {
	f := tmp_file('rooted', users_doc)
	defer { os.rm(f) or {} }
	r := os.execute("${cx_bin()} select '/users/user' ${f}")
	assert r.exit_code == 0, 'expected exit 0, got ${r.exit_code}: ${r.output}'
	assert r.output.trim_space().split('\n').len == 2, 'expected 2 matches: ${r.output}'
}

fn test_select_doc_anchored() {
	f := tmp_file('anchored', users_doc)
	defer { os.rm(f) or {} }
	r := os.execute("${cx_bin()} select '\$doc/user' ${f}")
	assert r.exit_code == 0, 'expected exit 0, got ${r.exit_code}: ${r.output}'
	assert r.output.contains('Alice') && r.output.contains('Bob'), 'anchored path broken: ${r.output}'
}

// ── predicate query ──────────────────────────────────────────────────────────

fn test_select_predicate_query() {
	f := tmp_file('pred', users_doc)
	defer { os.rm(f) or {} }
	r := os.execute("${cx_bin()} select \"//user[= \\\$_@role 'admin']\" ${f}")
	assert r.exit_code == 0, 'expected exit 0, got ${r.exit_code}: ${r.output}'
	out := r.output.trim_space()
	assert out.contains('Alice'), 'predicate must match Alice: ${out}'
	assert !out.contains('Bob'), 'predicate must not match Bob: ${out}'
}

// ── attribute selects ────────────────────────────────────────────────────────

fn test_select_attr_multi_materializes_fields() {
	f := tmp_file('attrs', users_doc)
	defer { os.rm(f) or {} }
	r := os.execute("${cx_bin()} select '\$doc/user@name' ${f}")
	assert r.exit_code == 0, 'expected exit 0, got ${r.exit_code}: ${r.output}'
	assert r.output.contains("[name 'Alice']"), 'attr match must materialize as field: ${r.output}'
	assert r.output.contains("[name 'Bob']"), 'attr match must materialize as field: ${r.output}'
}

fn test_select_attr_single_unwraps_scalar() {
	f := tmp_file('attr1', '[users [user name=Alice role=admin]]\n')
	defer { os.rm(f) or {} }
	// Single focus + plain child chain → the §6.2 terminal-attribute unwrap:
	// the typed scalar value (in canonical CX, so strings print quoted),
	// not the [name value] field.
	r := os.execute("${cx_bin()} select '\$doc/user@name' ${f}")
	assert r.exit_code == 0, 'expected exit 0, got ${r.exit_code}: ${r.output}'
	assert r.output.trim_space() == "'Alice'", 'single attr read must unwrap to scalar: ${r.output}'
}

// ── stdin lane ───────────────────────────────────────────────────────────────

fn test_select_stdin_pipe() {
	r := os.execute("printf '${users_doc.trim_space()}' | ${cx_bin()} select '//user'")
	assert r.exit_code == 0, 'stdin pipe lane broken (${r.exit_code}): ${r.output}'
	assert r.output.trim_space().split('\n').len == 2, 'expected 2 matches: ${r.output}'
}

fn test_select_stdin_explicit_dash() {
	r := os.execute("printf '${users_doc.trim_space()}' | ${cx_bin()} select '//user' -")
	assert r.exit_code == 0, 'stdin `-` lane broken (${r.exit_code}): ${r.output}'
	assert r.output.trim_space().split('\n').len == 2, 'expected 2 matches: ${r.output}'
}

// ── no match: exit 1, empty stdout ───────────────────────────────────────────

fn test_select_no_match_exits_one() {
	f := tmp_file('nomatch', users_doc)
	defer { os.rm(f) or {} }
	r := os.execute("${cx_bin()} select '//zebra' ${f}")
	assert r.exit_code == 1, 'empty match set must exit 1, got ${r.exit_code}: ${r.output}'
	assert r.output.trim_space() == '', 'empty match set must print nothing: ${r.output}'
}

// ── errors: exit 2 ───────────────────────────────────────────────────────────

fn test_select_bad_path_exits_two() {
	f := tmp_file('badpath', users_doc)
	defer { os.rm(f) or {} }
	r := os.execute("${cx_bin()} select '\$doc/user[=' ${f} 2>&1")
	assert r.exit_code == 2, 'path parse error must exit 2, got ${r.exit_code}: ${r.output}'
}

fn test_select_non_path_expression_exits_two() {
	f := tmp_file('nonpath', users_doc)
	defer { os.rm(f) or {} }
	r := os.execute("${cx_bin()} select '[+ 1 2]' ${f} 2>&1")
	assert r.exit_code == 2, 'non-path PATH must exit 2, got ${r.exit_code}: ${r.output}'
	assert r.output.contains('path'), 'diagnostic must say PATH must be a path expression: ${r.output}'
}

fn test_select_missing_file_exits_two() {
	r := os.execute("${cx_bin()} select '//user' /nonexistent/absent.cx 2>&1")
	assert r.exit_code == 2, 'unreadable FILE must exit 2, got ${r.exit_code}: ${r.output}'
}

fn test_select_bad_document_exits_two() {
	f := tmp_file('baddoc', '[unclosed\n')
	defer { os.rm(f) or {} }
	r := os.execute("${cx_bin()} select '//user' ${f} 2>&1")
	assert r.exit_code == 2, 'document parse error must exit 2, got ${r.exit_code}: ${r.output}'
}

fn test_select_no_args_usage() {
	r := os.execute('${cx_bin()} select 2>&1')
	assert r.exit_code == 2, 'missing PATH must exit 2, got ${r.exit_code}: ${r.output}'
	assert r.output.contains('Usage: cx select'), 'must print usage: ${r.output}'
}

fn test_select_unknown_flag_exits_two() {
	f := tmp_file('flag', users_doc)
	defer { os.rm(f) or {} }
	r := os.execute("${cx_bin()} select '//user' ${f} --require-match 2>&1")
	assert r.exit_code == 2, 'unknown flag must exit 2, got ${r.exit_code}: ${r.output}'
	assert r.output.contains('--require-match'), 'diagnostic must name the flag: ${r.output}'
}

fn test_select_too_many_args_exits_two() {
	f := tmp_file('extra', users_doc)
	defer { os.rm(f) or {} }
	r := os.execute("${cx_bin()} select '//user' ${f} ${f} 2>&1")
	assert r.exit_code == 2, 'extra positional must exit 2, got ${r.exit_code}: ${r.output}'
}
