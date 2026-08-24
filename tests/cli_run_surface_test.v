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
//
// #926 (RULED: PYE-2/PYE-3): the surface is `cx [flags] FILE [args...]` —
// flags bind BEFORE the resource; everything after it is the PROGRAM's argv
// ($env:argv, ungated). Every invocation below therefore puts cx flags
// before the FILE, and the PYE section at the bottom pins the argv contract
// per launch mode (FILE / shebang / -e / stdin).

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
	r := os.execute('${cx_bin()} --data=${data} ${prog}')
	assert r.exit_code == 0, 'expected exit 0, got ${r.exit_code}: ${r.output}'
	assert r.output.contains('Alice'), '\$doc not bound from --data: ${r.output}'
	assert r.output.contains('Bob'), '\$doc not bound from --data: ${r.output}'
}

// PYE-2: flags bind BEFORE the FILE positional (this is the only order).
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
	r1 := os.execute('${cx_bin()} --data=${data} ${prog}')
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
	r := os.execute("printf '${users_doc.trim_space()}' | ${cx_bin()} --data=- ${prog}")
	assert r.exit_code == 0, 'expected exit 0, got ${r.exit_code}: ${r.output}'
	assert r.output.contains('Alice'), '--data=- stdin lane broken: ${r.output}'
}

// Program and --data=- cannot both read stdin (--data=- before `-`: after
// the resource it would be a program arg, PYE-2).
fn test_program_and_data_both_stdin_is_usage_error() {
	r := os.execute("printf 'x' | ${cx_bin()} --data=- - 2>&1")
	assert r.exit_code == 2, 'expected exit 2, got ${r.exit_code}: ${r.output}'
	assert r.output.contains('stdin'), 'diagnostic must name the stdin conflict: ${r.output}'
}

// ── 4. Unknown flags are hard errors (exit 2, name the flag, point at help) ─

fn test_unknown_flag_before_file_hard_errors() {
	prog := tmp_file('prog_ok', '[+ 1 2]\n')
	defer { os.rm(prog) or {} }
	r := os.execute('${cx_bin()} --bogus-flag ${prog} 2>&1')
	assert r.exit_code == 2, 'unknown flag before FILE must exit 2, got ${r.exit_code}: ${r.output}'
	assert r.output.contains('--bogus-flag'), 'diagnostic must name the flag: ${r.output}'
	assert r.output.contains('--help'), 'diagnostic must point at --help: ${r.output}'
	// And nothing was evaluated.
	assert !r.output.contains('3'), 'program must not run under an unknown flag: ${r.output}'
}

// The #415 repro (flags pre-resource per PYE-2): --data=nonexistent +
// --bogus-flag used to be a silent no-op with rc=0.
fn test_issue_415_repro_is_no_longer_silent() {
	prog := tmp_file('prog_415', '[a 1]\n')
	defer { os.rm(prog) or {} }
	r := os.execute('${cx_bin()} --data=nonexistent.cx --bogus-flag ${prog} 2>&1')
	assert r.exit_code != 0, '#415 repro must not exit 0: ${r.output}'
}

// A misspelled capability grant is an unknown flag, not a silent no-grant.
fn test_misspelled_allow_grant_hard_errors() {
	prog := tmp_file('prog_cap', '[+ 1 2]\n')
	defer { os.rm(prog) or {} }
	r := os.execute('${cx_bin()} --allow-nett ${prog} 2>&1')
	assert r.exit_code == 2, 'misspelled grant must exit 2, got ${r.exit_code}: ${r.output}'
	assert r.output.contains('--allow-nett'), 'diagnostic must name the flag: ${r.output}'
}

// A value-carrying flag given without its value is a usage error.
fn test_bare_data_flag_needs_value() {
	prog := tmp_file('prog_val', '[+ 1 2]\n')
	defer { os.rm(prog) or {} }
	r := os.execute('${cx_bin()} --data ${prog} 2>&1')
	assert r.exit_code == 2, 'bare --data must exit 2, got ${r.exit_code}: ${r.output}'
	assert r.output.contains('--data'), 'diagnostic must name the flag: ${r.output}'
}

// PYE-2 REVERSAL of the old "extra positional is a usage error" rule: a
// second positional after the FILE is now the program's FIRST ARGUMENT.
// The old `unexpected extra argument` refusal is gone from the surface.
fn test_second_positional_is_a_program_argument() {
	prog := tmp_file('prog_a', '[+ 1 2]\n')
	prog2 := tmp_file('prog_b', '[+ 3 4]\n')
	defer {
		os.rm(prog) or {}
		os.rm(prog2) or {}
	}
	r := os.execute('${cx_bin()} ${prog} ${prog2} 2>&1')
	assert r.exit_code == 0, 'a second positional is a program arg (PYE-2), got ${r.exit_code}: ${r.output}'
	assert !r.output.contains('unexpected extra argument'), 'the pre-PYE-2 refusal must be gone: ${r.output}'
	// only the FIRST file evaluated
	assert r.output.contains('3'), 'first FILE must evaluate: ${r.output}'
	assert !r.output.contains('7'), 'second positional must NOT evaluate: ${r.output}'
}

// ── 5. Missing --data file is loud ───────────────────────────────────────────

fn test_missing_data_file_is_loud() {
	prog := tmp_file('prog_miss', '$doc/user@name\n')
	defer { os.rm(prog) or {} }
	r := os.execute('${cx_bin()} --data=/nonexistent/definitely_absent.cx ${prog} 2>&1')
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
	r := os.execute('${cx_bin()} --from=cx --to=json --data=${data} ${doc} 2>&1')
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
	// Result rendering + --data together (flags pre-resource, PYE-2).
	r := os.execute('${cx_bin()} --data=${data} --json ${prog}')
	assert r.exit_code == 0, '--json + --data must run, got ${r.exit_code}: ${r.output}'
	assert r.output.contains('Alice'), 'rendered result missing match: ${r.output}'
	// Capability grants parse (deny-by-default pure program needs none).
	r2 := os.execute('${cx_bin()} --data=${data} --allow-read --allow-net=example.com:443 ${prog}')
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
		r := os.execute('${cx_bin()} --data=${inp} ${tour}')
		head := if r.output.len > 500 { r.output[..500] } else { r.output }
		assert r.exit_code == 0, 'tour ${t} --data run failed (${r.exit_code}): ${head}'
		assert r.output.trim_space().len > 0, 'tour ${t} produced no output'
	}
}

// ── 8. RULED R5.13 — a top-level `err` RESULT exits 1 ───────────────────────
//
// Normative: cli.md §3.7.1. CX has no `exit` and no `raise` directive, so a
// program declines by RETURNING an err — and returning one used to exit 0,
// making a refusal indistinguishable from success to `make`, to CI, and to a
// supervisor watching a long-running program. The webhook adapter's R5.12
// refusal is the case that forced the ruling.
//
// The discriminator is POSITION, not value (code.md §6.4.1's rule, inherited
// rather than invented): a source-literal `[err …]` as the program's OWN
// top-level form is DATA. Every assertion below pairs the status with the
// OUTPUT, because the rule must move the exit code and nothing else.

fn test_computed_top_level_err_exits_1() {
	f := tmp_file('r513_computed', "[?element 'err' [?attr 'code' 'cx-err:CXER9999']]\n")
	defer {
		os.rm(f) or {}
	}
	res := os.execute('${cx_bin()} ${f}')
	assert res.exit_code == 1, 'a computed top-level err must exit 1: rc=${res.exit_code} ${res.output}'
	// the err is still the program's ANSWER and still goes to stdout
	assert res.output.contains('CXER9999'), 'the err must still be rendered: ${res.output}'
}

fn test_literal_top_level_err_is_data_and_exits_0() {
	// the half that keeps err-shaped DOCUMENTS expressible. If this ever goes
	// red, every `[err …]`-shaped data file has become a failing program.
	f := tmp_file('r513_literal', "[err code='cx-err:CXER9999' message='data']\n")
	defer {
		os.rm(f) or {}
	}
	res := os.execute('${cx_bin()} ${f}')
	assert res.exit_code == 0, 'a source-literal top-level err is DATA and must exit 0: rc=${res.exit_code} ${res.output}'
	assert res.output.contains('CXER9999'), 'the data document must still render: ${res.output}'
}

fn test_propagated_err_through_a_call_exits_1() {
	// #853: an err in CALL-OPERAND position short-circuits the call, so the
	// result is the err even though the source spelling is a call. Position,
	// not value — the literal carve-out is for the TOP-LEVEL FORM only.
	f := tmp_file('r513_propagated', "[?lib 'cx-stdlib/format' :as format]\n[\$format:canonical [err code='c' message='m']]\n")
	defer {
		os.rm(f) or {}
	}
	res := os.execute('${cx_bin()} ${f}')
	assert res.exit_code == 1, 'a propagated err result must exit 1: rc=${res.exit_code} ${res.output}'
}

fn test_err_nested_in_a_surviving_structure_exits_0() {
	// not a top-level result: the wrapper survived, so the program did not fail.
	f := tmp_file('r513_nested', "[wrapper [err code='c']]\n")
	defer {
		os.rm(f) or {}
	}
	res := os.execute('${cx_bin()} ${f}')
	assert res.exit_code == 0, 'an err nested in a surviving structure must exit 0: rc=${res.exit_code} ${res.output}'
	assert res.output.contains('[wrapper'), 'the wrapper must survive: ${res.output}'
}

fn test_multi_form_classifies_each_form_against_its_own_spelling() {
	// The multi-form path does NOT index-align results with source items —
	// declaration directives evaluate but contribute no output — so these two
	// pin that the pairing is right rather than off by the number of decls.
	lit := tmp_file('r513_multi_lit', "[a 1]\n[err code='c' message='literal']\n")
	comp := tmp_file('r513_multi_comp', "[a 1]\n[?element 'err' [?attr 'code' 'c']]\n")
	defer {
		os.rm(lit) or {}
		os.rm(comp) or {}
	}
	r_lit := os.execute('${cx_bin()} ${lit}')
	assert r_lit.exit_code == 0, 'a literal err form in a multi-form document is DATA: rc=${r_lit.exit_code} ${r_lit.output}'
	assert r_lit.output.contains('[a 1]'), 'both forms must render: ${r_lit.output}'

	r_comp := os.execute('${cx_bin()} ${comp}')
	assert r_comp.exit_code == 1, 'ANY failing top-level form fails the program: rc=${r_comp.exit_code} ${r_comp.output}'
	assert r_comp.output.contains('[a 1]'), 'output bytes are unchanged by the status: ${r_comp.output}'

	// and a decl BEFORE the err form must not shift the pairing
	withdecl := tmp_file('r513_multi_decl', "[?lib 'cx-stdlib/format' :as format]\n[a 1]\n[err code='c' message='literal']\n")
	defer {
		os.rm(withdecl) or {}
	}
	r_decl := os.execute('${cx_bin()} ${withdecl}')
	assert r_decl.exit_code == 0, 'a [?lib] decl must not shift form pairing: rc=${r_decl.exit_code} ${r_decl.output}'
}

fn test_ordinary_program_still_exits_0() {
	// the control: R5.13 must not make successful programs fail.
	f := tmp_file('r513_ok', '[ok [value 1]]\n')
	defer {
		os.rm(f) or {}
	}
	res := os.execute('${cx_bin()} ${f}')
	assert res.exit_code == 0, 'an ordinary program must still exit 0: rc=${res.exit_code} ${res.output}'
}

// ── 10. #926 RULED: PYE-2 + PYE-3 — the program argument vector ─────────────
//
// Normative: cli.md §3.7 (the positional rule) + env.md §3.2/§7. The surface
// is `cx [flags] RESOURCE [args...]`; everything after the resource is the
// program's argv, delivered as [resource, ...args] (sys.argv shape) through
// $env:argv — UNGATED (PYE-3: no --allow-* flag appears in ANY invocation in
// this section). The invariant under test: a program's view of its arguments
// is independent of how it was launched (FILE / shebang / -e / stdin).

const argv_prog = "[?lib 'cx-stdlib/env']\n[$env:argv]\n"

fn test_pye2_file_argv_is_resource_plus_args() {
	prog := tmp_file('pye2_file', argv_prog)
	defer { os.rm(prog) or {} }
	r := os.execute('${cx_bin()} ${prog} alpha beta')
	assert r.exit_code == 0, 'cx FILE args must run (ungranted, PYE-3): ${r.output}'
	assert r.output.contains(prog), 'argv[0] must be the FILE path: ${r.output}'
	assert r.output.contains('alpha') && r.output.contains('beta'), 'program args missing: ${r.output}'
}

fn test_pye2_flag_shaped_tokens_after_file_are_program_args() {
	// The BREAKING half of the cutover: a cx flag written after the resource
	// is a PROGRAM argument — no error, no cx-flag effect.
	prog := tmp_file('pye2_flagargs', argv_prog)
	defer { os.rm(prog) or {} }
	r := os.execute('${cx_bin()} ${prog} --verbose in.txt --json 2>&1')
	assert r.exit_code == 0, 'flag-shaped program args must not error: ${r.output}'
	assert r.output.contains('--verbose') && r.output.contains('in.txt'), 'flag-shaped args must reach argv verbatim: ${r.output}'
	// --json bound to the PROGRAM, not to cx: output stays canonical CX
	// (a JSON rendering of the sequence would open with '[').
	assert r.output.trim_space().starts_with('('), '--json after FILE must NOT select JSON rendering: ${r.output}'
}

fn test_pye2_shebang_matches_cx_file_invocation() {
	// Shebang and `cx FILE` must be IDENTICAL (the PYE-2 invariant). The
	// script is executed directly; the kernel hands cx `script args...`.
	dir := os.join_path(os.temp_dir(), 'cx_pye2_shebang_${os.getpid()}')
	os.mkdir_all(dir) or { panic(err) }
	defer { os.rmdir_all(dir) or {} }
	script := os.join_path(dir, 'tool.cx')
	os.write_file(script, '#!${cx_bin()}\n${argv_prog}') or { panic(err) }
	os.chmod(script, 0o755) or { panic(err) }
	direct := os.execute('${script} alpha --flag')
	via_cx := os.execute('${cx_bin()} ${script} alpha --flag')
	assert direct.exit_code == 0, 'shebang run must succeed: ${direct.output}'
	assert direct.output == via_cx.output, 'shebang and cx FILE must see IDENTICAL argv:\n${direct.output}\nvs\n${via_cx.output}'
	assert direct.output.contains('alpha') && direct.output.contains('--flag'), 'shebang args missing: ${direct.output}'
}

fn test_pye2_inline_e_argv0_is_dash_e() {
	// argv[0] placeholder for the inline launch mode: '-e' (pinned).
	r := os.execute("${cx_bin()} -e '[?lib \"cx-stdlib/env\"] [\$env:argv]' alpha")
	assert r.exit_code == 0, '-e with program args must run: ${r.output}'
	assert r.output.contains('-e') && r.output.contains('alpha'), "argv must be ('-e', alpha): ${r.output}"
}

fn test_pye2_stdin_argv0_is_stdin_placeholder() {
	// argv[0] placeholder for stdin programs: 'stdin' (pinned) — both the
	// explicit `-` and the pipe fall-through.
	prog := tmp_file('pye2_stdin_src', argv_prog)
	defer { os.rm(prog) or {} }
	r := os.execute('cat ${prog} | ${cx_bin()} - alpha beta')
	assert r.exit_code == 0, 'cx - args must run: ${r.output}'
	assert r.output.contains('stdin') && r.output.contains('alpha'), "argv must be (stdin, alpha, beta): ${r.output}"
	r2 := os.execute('cat ${prog} | ${cx_bin()}')
	assert r2.exit_code == 0, 'pipe fall-through must run: ${r2.output}'
	assert r2.output.contains('stdin'), "pipe fall-through argv must be (stdin): ${r2.output}"
}

fn test_pye3_parse_args_reachable_and_ungated() {
	// The #926 headline: env:parse-args over REAL program args, with ZERO
	// capability grants on the invocation.
	prog := tmp_file('pye3_parse', "[?lib 'cx-stdlib/env']\n[?let [= \$spec [argspec [flag name=verbose short=v type=\"bool\"] [flag name=limit short=n type=\"int\" default=100]]]\n  [= \$parsed [\$env:parse-args \$spec]]\n  ([\$env:flag \$parsed \"verbose\"], [\$env:flag \$parsed \"limit\"])]\n")
	defer { os.rm(prog) or {} }
	r := os.execute('${cx_bin()} ${prog} --verbose --limit 10')
	assert r.exit_code == 0, 'parse-args over program args must run ungranted: ${r.output}'
	assert r.output.contains('true') && r.output.contains('10'), 'parsed flags wrong: ${r.output}'
	// Control: $env:var STAYS gated (deny-by-default) — argv ungated is not
	// a widening of the env grant.
	prog2 := tmp_file('pye3_var', "[?lib 'cx-stdlib/env']\n[\$env:var \"HOME\"]\n")
	defer { os.rm(prog2) or {} }
	r2 := os.execute('${cx_bin()} ${prog2} 2>&1')
	assert r2.exit_code != 0, 'env var read must stay denied without --allow-env: ${r2.output}'
	assert r2.output.contains('CXER0271'), 'denial must name the cap error: ${r2.output}'
}

fn test_pye2_convert_surface_refuses_trailing_args() {
	// The convert surface has no program to receive trailing args — they
	// are refused loudly (the #415 no-silent-swallow rule): `cx data.json
	// --to=xml` used to convert; silently ignoring the now-trailing flag
	// would emit the default format as if it were the asked-for one.
	doc := tmp_file('pye2_conv', '[a 1]\n')
	defer { os.rm(doc) or {} }
	r := os.execute('${cx_bin()} --from=cx ${doc} --to=xml 2>&1')
	assert r.exit_code == 2, 'trailing args on the convert surface must exit 2: ${r.output}'
	assert r.output.contains('--to=xml'), 'diagnostic must name the trailing tokens: ${r.output}'
	// flag-first spelling still converts
	r2 := os.execute('${cx_bin()} --from=cx --to=xml ${doc}')
	assert r2.exit_code == 0 && r2.output.contains('<a>'), 'flag-first convert broken: ${r2.output}'
}

fn test_pye2_eval_alias_matches_run_surface_argv() {
	// `cx eval` is the documented alias: same positional rule, same argv.
	prog := tmp_file('pye2_eval', argv_prog)
	defer { os.rm(prog) or {} }
	run := os.execute('${cx_bin()} ${prog} alpha')
	alias := os.execute('${cx_bin()} eval ${prog} alpha')
	assert alias.exit_code == 0, 'cx eval FILE args must run: ${alias.output}'
	assert run.output == alias.output, 'run surface and eval alias must see identical argv:\n${run.output}\nvs\n${alias.output}'
}
