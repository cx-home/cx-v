module main

import os
import testenv

// #415 — the bare run surface takes `--data=INPUT` (binds $doc / $input via
// the same seam `cx eval` uses; caller-supplied input WINS over the program's
// own data roots per spec/code.md §1.3), and UNKNOWN flags are hard usage
// errors (exit 2) instead of the pre-#415 silent swallow (`--bogus-flag`
// no-op'd with rc=0, which is how four flagship tours ran empty for a whole
// release).
//
// Normative contract: spec/03-approved/misc/cli.md §3.7 (the run surface).
// These tests drive the compiled `cx` binary as a subprocess.

fn cx_bin() string {
	return testenv.cx_bin()
}

fn tmp_file(label string, content string) string {
	path := os.join_path(os.temp_dir(), 'cx_cli_run_${label}_${os.getpid()}.cx')
	os.write_file(path, content) or { panic(err) }
	return path
}

const users_doc = '[users [user name=Alice role=admin] [user name=Bob role=dev]]\n'

// ── 1. `cx FILE --data=INPUT` binds $doc ────────────────────────────────────

fn test_data_flag_binds_doc() {
	prog := tmp_file('prog_doc', '$doc/user@name\n')
	data := tmp_file('data_users', users_doc)
	defer {
		os.rm(prog) or {}
		os.rm(data) or {}
	}
	r := os.execute('${cx_bin()} ${prog} --data=${data}')
	assert r.exit_code == 0, 'expected exit 0, got ${r.exit_code}: ${r.output}'
	assert r.output.contains('Alice'), '\$doc not bound from --data: ${r.output}'
	assert r.output.contains('Bob'), '\$doc not bound from --data: ${r.output}'
}

// Flag order must not matter: --data before the FILE positional.
fn test_data_flag_before_file_positional() {
	prog := tmp_file('prog_doc2', '$doc/user@name\n')
	data := tmp_file('data_users2', users_doc)
	defer {
		os.rm(prog) or {}
		os.rm(data) or {}
	}
	r := os.execute('${cx_bin()} --data=${data} ${prog}')
	assert r.exit_code == 0, 'expected exit 0, got ${r.exit_code}: ${r.output}'
	assert r.output.contains('Alice'), '\$doc not bound (flag-first order): ${r.output}'
}

// ── 2. Caller-supplied --data WINS over the program's own data root ─────────

fn test_data_flag_wins_over_in_document_data_root() {
	prog := tmp_file('prog_root', '[users [user name=Inline]]\n\$doc/user@name\n')
	data := tmp_file('data_users3', users_doc)
	defer {
		os.rm(prog) or {}
		os.rm(data) or {}
	}
	// Without --data: implicit $doc = the program's first data root.
	r0 := os.execute('${cx_bin()} ${prog}')
	assert r0.exit_code == 0, 'expected exit 0, got ${r0.exit_code}: ${r0.output}'
	assert r0.output.contains('Inline'), 'implicit data-root \$doc broken: ${r0.output}'
	// With --data: the caller input wins; the in-document root never rebinds.
	r1 := os.execute('${cx_bin()} ${prog} --data=${data}')
	assert r1.exit_code == 0, 'expected exit 0, got ${r1.exit_code}: ${r1.output}'
	assert r1.output.contains('Alice'), 'caller --data did not win over data root: ${r1.output}'
	assert r1.output.contains('Bob'), 'caller --data did not win over data root: ${r1.output}'
	// The path read must NOT see the inline root's user.
	assert !r1.output.contains("[name 'Inline']"), 'in-document root rebound \$doc: ${r1.output}'
}

// ── 3. --data=- reads the input document from stdin ─────────────────────────

fn test_data_from_stdin() {
	prog := tmp_file('prog_stdin', '$doc/user@name\n')
	defer { os.rm(prog) or {} }
	r := os.execute("printf '${users_doc.trim_space()}' | ${cx_bin()} ${prog} --data=-")
	assert r.exit_code == 0, 'expected exit 0, got ${r.exit_code}: ${r.output}'
	assert r.output.contains('Alice'), '--data=- stdin lane broken: ${r.output}'
}

// Program and --data=- cannot both read stdin.
fn test_program_and_data_both_stdin_is_usage_error() {
	r := os.execute("printf 'x' | ${cx_bin()} - --data=- 2>&1")
	assert r.exit_code == 2, 'expected exit 2, got ${r.exit_code}: ${r.output}'
	assert r.output.contains('stdin'), 'diagnostic must name the stdin conflict: ${r.output}'
}

// ── 4. Unknown flags are hard errors (exit 2, name the flag, point at help) ─

fn test_unknown_flag_hard_errors() {
	prog := tmp_file('prog_ok', '[+ 1 2]\n')
	defer { os.rm(prog) or {} }
	r := os.execute('${cx_bin()} ${prog} --bogus-flag 2>&1')
	assert r.exit_code == 2, 'unknown flag must exit 2, got ${r.exit_code}: ${r.output}'
	assert r.output.contains('--bogus-flag'), 'diagnostic must name the flag: ${r.output}'
	assert r.output.contains('--help'), 'diagnostic must point at --help: ${r.output}'
	// And nothing was evaluated.
	assert !r.output.contains('3'), 'program must not run under an unknown flag: ${r.output}'
}

// The #415 repro verbatim: --data=nonexistent + --bogus-flag used to be a
// silent no-op with rc=0.
fn test_issue_415_repro_is_no_longer_silent() {
	prog := tmp_file('prog_415', '[a 1]\n')
	defer { os.rm(prog) or {} }
	r := os.execute('${cx_bin()} ${prog} --data=nonexistent.cx --bogus-flag 2>&1')
	assert r.exit_code != 0, '#415 repro must not exit 0: ${r.output}'
}

// A misspelled capability grant is an unknown flag, not a silent no-grant.
fn test_misspelled_allow_grant_hard_errors() {
	prog := tmp_file('prog_cap', '[+ 1 2]\n')
	defer { os.rm(prog) or {} }
	r := os.execute('${cx_bin()} ${prog} --allow-nett 2>&1')
	assert r.exit_code == 2, 'misspelled grant must exit 2, got ${r.exit_code}: ${r.output}'
	assert r.output.contains('--allow-nett'), 'diagnostic must name the flag: ${r.output}'
}

// A value-carrying flag given without its value is a usage error.
fn test_bare_data_flag_needs_value() {
	prog := tmp_file('prog_val', '[+ 1 2]\n')
	defer { os.rm(prog) or {} }
	r := os.execute('${cx_bin()} ${prog} --data 2>&1')
	assert r.exit_code == 2, 'bare --data must exit 2, got ${r.exit_code}: ${r.output}'
	assert r.output.contains('--data'), 'diagnostic must name the flag: ${r.output}'
}

// Extra positional arguments are usage errors (previously silently ignored).
fn test_extra_positional_is_usage_error() {
	prog := tmp_file('prog_a', '[+ 1 2]\n')
	prog2 := tmp_file('prog_b', '[+ 3 4]\n')
	defer {
		os.rm(prog) or {}
		os.rm(prog2) or {}
	}
	r := os.execute('${cx_bin()} ${prog} ${prog2} 2>&1')
	assert r.exit_code == 2, 'second FILE must exit 2, got ${r.exit_code}: ${r.output}'
}

// ── 5. Missing --data file is loud ───────────────────────────────────────────

fn test_missing_data_file_is_loud() {
	prog := tmp_file('prog_miss', '$doc/user@name\n')
	defer { os.rm(prog) or {} }
	r := os.execute('${cx_bin()} ${prog} --data=/nonexistent/definitely_absent.cx 2>&1')
	assert r.exit_code == 1, 'missing --data file must exit 1, got ${r.exit_code}: ${r.output}'
	assert r.output.contains('definitely_absent.cx'), 'diagnostic must name the file: ${r.output}'
}

// ── 6. --data belongs to the run surface only ────────────────────────────────

fn test_data_flag_rejected_on_convert_surface() {
	data := tmp_file('data_c', users_doc)
	doc := tmp_file('doc_c', '[a 1]\n')
	defer {
		os.rm(data) or {}
		os.rm(doc) or {}
	}
	r := os.execute('${cx_bin()} --from=cx --to=json ${doc} --data=${data} 2>&1')
	assert r.exit_code == 2, '--data on the convert surface must exit 2, got ${r.exit_code}: ${r.output}'
	assert r.output.contains('--data'), 'diagnostic must name --data: ${r.output}'
}

// ── 7. The documented run flags still route ──────────────────────────────────

fn test_known_run_flags_still_route() {
	prog := tmp_file('prog_flags', '$doc/user@name\n')
	data := tmp_file('data_flags', users_doc)
	defer {
		os.rm(prog) or {}
		os.rm(data) or {}
	}
	// Result rendering + --data together.
	r := os.execute('${cx_bin()} ${prog} --data=${data} --json')
	assert r.exit_code == 0, '--json + --data must run, got ${r.exit_code}: ${r.output}'
	assert r.output.contains('Alice'), 'rendered result missing match: ${r.output}'
	// Capability grants parse (deny-by-default pure program needs none).
	r2 := os.execute('${cx_bin()} ${prog} --data=${data} --allow-read --allow-net=example.com:443')
	assert r2.exit_code == 0, 'valid --allow-* grants must route, got ${r2.exit_code}: ${r2.output}'
	// Convert surface unaffected (no --data): explicit --from/--to.
	r3 := os.execute("printf '[a 1]' | ${cx_bin()} --from=cx --to=json -")
	assert r3.exit_code == 0, 'convert surface broken: ${r3.output}'
	// -v still prints version info.
	r4 := os.execute('${cx_bin()} -v')
	assert r4.exit_code == 0 && r4.output.contains('cx v'), '-v broken: ${r4.output}'
}

// ── 8. `cx version` is a verb, never a ./VERSION file evaluation (#426b) ─────

fn test_version_subcommand_matches_version_flag() {
	flag := os.execute('${cx_bin()} --version')
	assert flag.exit_code == 0, '--version must exit 0: ${flag.output}'
	verb := os.execute('${cx_bin()} version')
	assert verb.exit_code == 0, 'cx version must exit 0: ${verb.output}'
	assert verb.output == flag.output, 'cx version must print exactly what --version prints:\n${verb.output}\nvs\n${flag.output}'
	assert verb.output.starts_with('cx v'), 'version banner missing: ${verb.output}'
}

fn test_version_subcommand_wins_over_version_file() {
	// Repro (#426 item b): at the repo root on a case-insensitive filesystem,
	// bare `cx version` used to resolve the word to ./VERSION and evaluate
	// the file as a program. The verb must dispatch BEFORE any positional
	// file resolution — run from a directory containing a VERSION file.
	dir := os.join_path(os.temp_dir(), 'cx_version_shadow_${os.getpid()}')
	os.mkdir_all(dir) or { panic(err) }
	defer { os.rmdir_all(dir) or {} }
	os.write_file(os.join_path(dir, 'VERSION'), '0.0.0-shadow\n') or { panic(err) }
	r := os.execute('cd ${dir} && ${cx_bin()} version')
	assert r.exit_code == 0, 'cx version next to a VERSION file must exit 0: ${r.output}'
	assert r.output.starts_with('cx v'), 'version banner missing: ${r.output}'
	assert !r.output.contains('0.0.0-shadow'), './VERSION file was evaluated instead of the verb: ${r.output}'
}

// ── 9. The four flagship tours run their documented --data lines ─────────────

fn test_flagship_tours_documented_run_lines_work() {
	root := os.dir(@VMODROOT)
	tours := ['code-tour', 'cxpath-tour', 'match-multi', 'modify-crud']
	for t in tours {
		tour := os.join_path(root, 'examples', '${t}.cx')
		inp := os.join_path(root, 'examples', '${t}.input.cx')
		if !os.is_file(tour) || !os.is_file(inp) {
			eprintln('SKIP tour ${t}: examples not present at ${tour}')
			continue
		}
		r := os.execute('${cx_bin()} ${tour} --data=${inp}')
		head := if r.output.len > 500 { r.output[..500] } else { r.output }
		assert r.exit_code == 0, 'tour ${t} --data run failed (${r.exit_code}): ${head}'
		assert r.output.trim_space().len > 0, 'tour ${t} produced no output'
	}
}
