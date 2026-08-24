module main

import os
import time
import cx
import fixtures
import code
import math

// I4 profile corpus gate (#651/#516, partition spec §4/§7) — proves the
// cli / embed profile ENGINE COMPOSITIONS against the ring-tagged corpus,
// plus the profile binaries' refusal contract.
//
// The runner deliberately does NOT import the platform module: compiled
// bare it IS the cli-profile engine (Rings 0–1, all local-effect packs);
// compiled with the nine `-d cx_no_pack_*` exclusions it IS the embed
// engine. The gate then:
//
//   1. EVAL lane — grades every ring≤1 eval fixture (code.cxd, eval-ring=1,
//      plus conformance/stdlib/* ring≤1 cases) in-process, mirroring the
//      grading semantics of vcx/tests/code_eval_fixtures_test.v (the source
//      of truth for eval grading — both run in the same battery, so a
//      semantic divergence between the two runners fails one of them).
//      On the embed composition the excluded packs' own suites are skipped
//      (their surfaces are OUT of the artifact by construction) and replaced
//      by per-pack REFUSAL probes.
//   2. REFUSAL probes — ring-2 names (store) must refuse as undefined
//      callables in BOTH compositions (no platform module -> live-but-empty
//      registries, spec §4); on embed, each excluded pack's module surface
//      must refuse the same way.
//   3. BINARY probes (--bin=PATH) — the profile binary reports the right
//      `profile` line, refuses the platform verb words BY NAME with rc=2
//      (the #426 rule, extended to profiles), and evaluates a pure program.
//
// Ring-tag semantics: per-case ring override wins over the suite header
// (corpus audit §2 Q2, via fixtures.FixtureSuite.case_ring); code.cxd's
// eval lane rides its `eval-ring=` discriminator. The doc lane is NOT
// re-graded here: parse/emit/canonical live in vcx/cx, byte-identical in
// every profile ≥ Ring 0 — the I2 extraction gate is the doc-lane
// authority (and `conform` already runs at the cli composition).
//
// Usage: v [-d cx_no_pack_*…] run profile_gate.v [--bin=<profile cx>]

// excluded_packs probes the SAME `-d cx_no_pack_*` gates the build uses —
// composition is read off the artifact, never passed as free text.
fn excluded_packs() []string {
	mut off := []string{}
	$if cx_no_pack_io ? {
		off << 'io'
	}
	$if cx_no_pack_env ? {
		off << 'env'
	}
	$if cx_no_pack_process ? {
		off << 'process'
	}
	$if cx_no_pack_time ? {
		off << 'time'
	}
	$if cx_no_pack_random ? {
		off << 'random'
	}
	$if cx_no_pack_log ? {
		off << 'log'
	}
	$if cx_no_pack_term ? {
		off << 'term'
	}
	$if cx_no_pack_http_client ? {
		off << 'http-client'
	}
	$if cx_no_pack_sched ? {
		off << 'sched'
	}
	return off
}

fn composition() string {
	n := excluded_packs().len
	if n == 0 {
		return 'cli'
	}
	if n == 9 {
		return 'embed'
	}
	return 'custom'
}

// excluded pack -> its conformance/stdlib suite basename. term has no
// module surface (no stdlib/term.cx, no suite file) — its exclusion is
// proven at compile time (the dispatch chain entry is gated) and by the
// pack file being absent from the artifact. http-client's cases live in
// http.cxd (suite ring=2 with per-case ring=1 client overrides).
const pack_suite = {
	'io':          'io'
	'env':         'env'
	'process':     'process'
	'time':        'time'
	'random':      'random'
	'log':         'log'
	'http-client': 'http'
	'sched':       'sched'
}

// per-pack refusal probes (embed): the pack's module surface must refuse
// as an undefined callable — grant-all, so a CXER0271 denial (which would
// mean the pack IS in the artifact) fails the probe.
const pack_probe = {
	'io':          '[?lib "cx-stdlib/io" as=io] [$io:exists "/"]'
	'env':         '[?lib "cx-stdlib/env" as=env] [$env:os-name]'
	'process':     '[?lib "cx-stdlib/process" as=process] [$process:run "true"]'
	'time':        '[?lib "cx-stdlib/time" as=time] [$time:now]'
	'random':      '[?lib "cx-stdlib/random" as=random] [$random:crypto-bytes 4]'
	'log':         '[?lib "cx-stdlib/log" as=log] [$log:info "x"]'
	'http-client': '[?lib "cx-stdlib/http" as=http] [$http:get "http://127.0.0.1:1/x"]'
	'sched':       '[?lib "cx-stdlib/sched" as=sched] [$sched:timers]'
}

const ring2_probe = '[?lib "cx-stdlib/store" as=store] [$store:open "mem://"]'

// dependent-module refusal probes (embed; RULED: SPF-1, #895) — the OTHER
// half of the pack story. `pack_probe` above proves the excluded pack's own
// surface is gone. This proves that a module which is PRESENT in every
// profile but NORMATIVELY depends on an excluded pack refuses at its own
// COMPOSITION point, with its own typed code, naming the missing pack —
// instead of composing something half-alive and failing later on a derived
// symptom. supervise did exactly that: with `sched` out it built its
// channel names from an empty id and surfaced `[?channel] requires :name`
// 25 fixtures deep. Keyed excluded pack -> (program, expected CXER code).
const dependent_module_probe = {
	'sched': [
		'[?lib "cx-stdlib/supervise" as=sup] [\$sup:start [policy strategy=:one-for-one] ([child name="a" [fn [?fn () 1]]])]',
		'CXER5095',
	]
}

struct GateStats {
mut:
	ran               int
	skipped           int
	bin_ran           int // R3.11: cases graded through the profile BINARY
	bin_inexpressible int // R3.11: counted + reported, never silent
	bin_data_fallback int // R3.11: §1.3 data-echo answers on parse-error fixtures
	failures          []string
	advisory          []string
}

// load_gate_policy mirrors code_eval_fixtures_test.v (conformance/gates.cxd:
// per-case gate= > per-module entry > per-suite default > enforced).
fn load_gate_policy(conf_dir string, suite string) (map[string]string, string) {
	mut m := map[string]string{}
	mut suite_default := ''
	mut policy_default := ''
	src := os.read_file(os.join_path(conf_dir, 'gates.cxd')) or { return m, suite_default }
	doc := cx.parse(src) or { return m, suite_default }
	for node in doc.elements {
		if node is cx.Element {
			if node.name == 'gate-policy' {
				for a in node.attrs {
					if a.name == 'default' {
						policy_default = cx.scalar_value_str_public(a.value)
					}
				}
				for s in node.items {
					if s is cx.Element {
						if s.name == 'suite' {
							mut sname := ''
							mut sdefault := ''
							for a in s.attrs {
								if a.name == 'name' {
									sname = cx.scalar_value_str_public(a.value)
								}
								if a.name == 'default' {
									sdefault = cx.scalar_value_str_public(a.value)
								}
							}
							if sname != suite {
								continue
							}
							suite_default = sdefault
							for md in s.items {
								if md is cx.Element {
									if md.name == 'module' {
										mut mn := ''
										mut mg := ''
										for a in md.attrs {
											if a.name == 'name' {
												mn = cx.scalar_value_str_public(a.value)
											}
											if a.name == 'gate' {
												mg = cx.scalar_value_str_public(a.value)
											}
										}
										if mn != '' {
											m[mn] = mg
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	if suite_default == '' {
		suite_default = policy_default
	}
	return m, suite_default
}

// same_shape / same_multiset mirror code_eval_fixtures_test.v verbatim.
fn same_shape(a string, b string) bool {
	at := a.fields()
	bt := b.fields()
	if at.len != bt.len {
		return false
	}
	for i, t in at {
		if t != bt[i] {
			return false
		}
	}
	return true
}

fn multiset_items(s string) []string {
	mut inner := s.trim_space()
	if inner.starts_with('(') && inner.ends_with(')') {
		inner = inner[1..inner.len - 1]
	}
	mut items := []string{}
	for part in inner.split(',') {
		t := part.trim_space()
		if t != '' {
			items << t
		}
	}
	return items
}

fn same_multiset(a string, b string) bool {
	mut ai := multiset_items(a)
	mut bi := multiset_items(b)
	if ai.len != bi.len {
		return false
	}
	ai.sort()
	bi.sort()
	for i, t in ai {
		if t != bi[i] {
			return false
		}
	}
	return true
}

// clamp_section mirrors code_eval_fixtures_test.v — the eval consumer's
// section end-detection (bare `---` line / blank-line-then-comment).
fn clamp_section(s string) string {
	mut end := s.len
	mut probe := 0
	for probe < s.len {
		next := s.index_after('\n---', probe) or { break }
		if next + 4 < s.len {
			c := s[next + 4]
			if c == ` ` || c == `\n` {
				end = next
				break
			}
		} else {
			end = next
			break
		}
		probe = next + 1
	}
	if ci := s.index('\n\n#') {
		if ci < end {
			end = ci
		}
	}
	return s[..end].trim_right(' \t\n')
}

// section reads a legacy-keyed section body off a FixtureCase, clamped the
// way the eval grader consumes it.
fn section(c fixtures.FixtureCase, key string) string {
	return clamp_section(c.sections[key] or { '' })
}

// grade_case mirrors the code_eval_fixtures_test.v eval-grading loop:
// grant policy (explicit > CXER0271->empty > all), parse_program, eval,
// out-err contains, multiset / tol / same_shape out-text.
// needs_excluded_pack reports whether the case declares a dependency on a
// pack this composition excludes (fixtures.cxs `packs=`).
fn needs_excluded_pack(c fixtures.FixtureCase, off []string) bool {
	for p in c.packs {
		if p in off {
			return true
		}
	}
	return false
}

// thrown_matches_out_err mirrors code_eval_fixtures_test.v (R3.12 / audit
// F-19): a THROWN parse/eval error satisfies an out-err case only when its
// message carries the expected CXER code (or, with no CXER token, the whole
// expected string). Empty out-err never matches a throw.
fn thrown_matches_out_err(msg string, out_err string) bool {
	oe := out_err.trim_space()
	if oe == '' {
		return false
	}
	idx := oe.index('CXER') or { return msg.contains(oe) }
	mut code_tok := 'CXER'
	mut i := idx + 4
	for i < oe.len && oe[i] >= `0` && oe[i] <= `9` {
		code_tok += oe[i].ascii_str()
		i++
	}
	return msg.contains(code_tok)
}

fn grade_case(label string, c fixtures.FixtureCase, mut st GateStats, advisory bool) {
	in_code := section(c, 'in_code')
	in_cx := section(c, 'in_cx')
	out_text := section(c, 'out_text')
	out_err := section(c, 'out_err')
	out_multiset := section(c, 'out_multiset')
	if in_code.trim_space() == '' {
		return
	}
	if c.level == 'visualization' {
		return
	}
	st.ran++
	mut env := code.new_env()
	code.register_conformance_test_modules(mut env.state.module_table)
	if 'strict-mode' in c.tags {
		env.state.strict = true
	}
	if in_cx != '' && in_cx != '[ignored]' && in_cx != '[empty]' {
		if doc := cx.parse(in_cx) {
			for i in 0 .. doc.elements.len {
				n := doc.elements[i]
				if n is cx.Element {
					env.bindings['doc'] = n
					env.bindings['input'] = n
					break
				}
			}
		}
	}
	if c.grant == 'none' {
		// PYE-3 (#926): behavior case pinned to the EMPTY set — proves the
		// exercised surface is ungated (argv/parse-args).
		code.caps_set_empty()
	} else if c.grant != '' {
		code.caps_set_list(c.grant.split_any(' \t,').filter(it != '')) or {
			panic('fixture [grant …] refused (#713 loud unknown-cap): ${err.msg()}')
		}
	} else if out_err.contains('CXER0271') {
		code.caps_set_empty()
	} else {
		code.caps_set_all()
	}
	// Program argv (#926, PYE-2): fixture-declared vector, argv[0] included;
	// cleared otherwise so no cross-case leak.
	code.set_program_argv(c.argv.split_any(' \t').filter(it != ''))
	prog := cx.parse_program(in_code) or {
		if out_err != '' {
			// R3.12 / audit F-19: a thrown error only satisfies an out-err
			// case when it carries the EXPECTED code — the blanket pass here
			// replicated the #404–#407 false-green class into this lane.
			if !thrown_matches_out_err(err.msg(), out_err) {
				st.record('${label}: parse threw "${err.msg()}" but expected ${out_err} (R3.12)',
					advisory)
			}
			return
		}
		st.record('${label}: parse: ${err}', advisory)
		return
	}
	mut result := code.eval(prog.body, mut env) or {
		if out_err != '' {
			if !thrown_matches_out_err(err.msg(), out_err) {
				st.record('${label}: eval threw "${err.msg()}" but expected ${out_err} (R3.12)',
					advisory)
			}
			return
		}
		st.record('${label}: eval: ${err}', advisory)
		return
	}
	// EV-PULL (stream 17 W1): the runner is a result boundary — force
	// with the env alive (mirrors code_eval_fixtures_test.v).
	result = code.force_lazy_result(result, mut env)
	// Serialization boundary (§8.6, mirrors code_eval_fixtures_test.v): a
	// function value reaching the program result is CXER0291, not rendered.
	if code.is_fn_value(result) {
		if out_err != '' {
			if !out_err.contains('CXER0291') {
				st.record('${label}: expected ${out_err}, got function value (CXER0291)',
					advisory)
			}
		} else {
			st.record('${label}: function value not serialisable (CXER0291), expected ${out_text.trim_space()}',
				advisory)
		}
		return
	}
	if out_err != '' {
		if !code.render_canonical(result).contains(out_err) {
			st.record('${label}: expected ${out_err}, got ${code.render_canonical(result)}',
				advisory)
		}
		return
	}
	rendered := code.render_canonical(result).trim_space()
	if out_multiset != '' {
		if !same_multiset(rendered, out_multiset.trim_space()) {
			st.record('${label}: multiset mismatch\n  got:      ${rendered}\n  expected: ${out_multiset.trim_space()}',
				advisory)
		}
		return
	}
	expected := out_text.trim_space()
	if c.tol > 0 {
		if math.abs(rendered.f64() - expected.f64()) > c.tol * math.abs(expected.f64()) {
			st.record('${label}: tol mismatch (tol=${c.tol})\n  got:      ${rendered}\n  expected: ${expected}',
				advisory)
		}
	} else if !same_shape(rendered, expected) {
		st.record('${label}: mismatch\n  got:      ${rendered}\n  expected: ${expected}',
			advisory)
	}
}

fn (mut st GateStats) record(msg string, advisory bool) {
	if advisory {
		st.advisory << msg
	} else {
		st.failures << msg
	}
}

// ── R3.11 (audit F-18): the FULL graded corpus through the PROFILE BINARY ──
//
// The in-process lane grades the engine COMPOSITION; the binary is what
// ships — a `$if cx_platform` mistake in cmd/ could break `cx <file>` at a
// profile and still pass the in-process battery. This lane runs every
// binary-expressible eval case through the real `cx` run surface:
// program → tmp file; in-cx doc → `--data=FILE` (spec code.md §1.3);
// grants → `--allow-<cap>` / `--allow-all` / deny-by-default for CXER0271
// cases (spec/misc/cli.md §3.7).
//
// Binary-INEXPRESSIBLE cases are counted and reported, never silent:
//   - test-registry modules (./local-helpers.cx, github.com/example/*, …)
//     exist only in the in-process conformance registry (#701)
//   - strict-mode-tagged cases (no --strict run flag)
//   - [?channel]-carrying and visualization cases (session-scoped surfaces)
// Those stay covered by the in-process lane above.

const bin_inexpressible_libs = ['./local-helpers.cx', './public-only-module.cx',
	'./mixed-module.cx', './scope-frames-module.cx', 'github.com/example/',
	'https://cdn.example.com/', 'cx-stdlib/json/encoder']

fn binary_expressible(c fixtures.FixtureCase) bool {
	in_code := section(c, 'in_code')
	for lib in bin_inexpressible_libs {
		if in_code.contains("'${lib}") || in_code.contains("'${lib}'") {
			return false
		}
	}
	if 'strict-mode' in c.tags {
		return false
	}
	// argv-carrying cases (#926, PYE-2): the fixture pins an exact
	// [resource, ...args] vector including argv[0]; on the run surface
	// argv[0] is the REAL tmp program path, so the pinned vector cannot be
	// reproduced. Covered by the in-process lane (which installs it).
	if c.argv != '' {
		return false
	}
	return true
}

fn grade_case_binary(label string, c fixtures.FixtureCase, bin string, tmp string, mut st GateStats, advisory bool) {
	in_code := section(c, 'in_code')
	in_cx := section(c, 'in_cx')
	out_text := section(c, 'out_text')
	out_err := section(c, 'out_err')
	out_multiset := section(c, 'out_multiset')
	if in_code.trim_space() == '' || c.level == 'visualization' {
		return
	}
	if !binary_expressible(c) {
		st.bin_inexpressible++
		return
	}
	st.bin_ran++
	prog_path := os.join_path(tmp, 'case.cx')
	os.write_file(prog_path, in_code) or {
		st.record('${label}[bin]: write: ${err}', advisory)
		return
	}
	// PYE-2 (#926): cx flags bind BEFORE the program resource — everything
	// after it is the program's argv. Flags first, prog_path LAST.
	mut args := []string{}
	if in_cx != '' && in_cx != '[ignored]' && in_cx != '[empty]' && in_cx != '[doc]' {
		doc_path := os.join_path(tmp, 'case-doc.cx')
		os.write_file(doc_path, in_cx) or {
			st.record('${label}[bin]: write doc: ${err}', advisory)
			return
		}
		args << '--data=${doc_path}'
	}
	if c.grant == 'none' {
		// PYE-3: ungated-surface behavior pin — deny-by-default, no flags.
	} else if c.grant != '' {
		for g in c.grant.split_any(' \t,').filter(it != '') {
			args << '--allow-${g}'
		}
	} else if !out_err.contains('CXER0271') {
		args << '--allow-all'
	} // CXER0271 cases: deny-by-default — no flags
	args << prog_path
	case_tmp := os.join_path(tmp, 'scratch')
	os.rmdir_all(case_tmp) or {}
	os.mkdir_all(case_tmp) or {
		st.record('${label}[bin]: mkdir scratch: ${err}', advisory)
		return
	}
	r := run_bin_isolated_tmp(bin, args, case_tmp)
	got := r.out.trim_space()
	if out_err != '' {
		// an err VALUE prints [err code=…] rc=0; a THROWN error prints on
		// stderr rc!=0 — either must carry the expected code (R3.12 rule)
		if r.rc == 0 {
			if !got.contains(out_err) {
				// code.md §1.3: "a pure-data resource evaluates to itself" —
				// a program-parse-error fixture whose in-code IS valid data
				// legitimately answers the DATA echo on the bare run surface
				// (the fallback in code/api.v). The parse-error expectation is
				// the PROGRAM surface's, which the in-process lane grades.
				fallback := cx.convert_by_name(in_code, 'cx', 'cx', false) or { '' }
				if fallback != '' && same_shape(got, fallback.trim_space()) {
					st.bin_data_fallback++
					return
				}
				st.record('${label}[bin]: expected ${out_err}, got (rc=0): ${got}', advisory)
			}
		} else {
			if !thrown_matches_out_err(r.err + got, out_err) {
				st.record('${label}[bin]: expected ${out_err}, binary exited rc=${r.rc}: ${r.err.trim_space()}',
					advisory)
			}
		}
		return
	}
	if r.rc != 0 {
		// RULED R5.13: a top-level err RESULT is a FAILING program — the
		// rendered err is still the program's answer on STDOUT, but the
		// process exits 1. A fixture that pins an err VALUE as its
		// out_text is therefore graded on the OUTPUT with rc=1 expected,
		// not recorded as a crash. Anything else nonzero stays a failure.
		if r.rc == 1 && out_text.trim_space().starts_with('[err') {
			expected_err := out_text.trim_space()
			if same_shape(got, expected_err) || same_shape(bin_tail(got, expected_err), expected_err) {
				return
			}
		}
		st.record('${label}[bin]: rc=${r.rc}: ${r.err.trim_space()}', advisory)
		return
	}
	// The run surface renders EACH top-level form's result (#16, deliberate:
	// it agrees with the data reading's multi-root emit) — the implicit doc
	// root / intermediate nulls print BEFORE the program result the fixture
	// pins. The fixture's expectation is the FINAL value, so a multi-form
	// output matches on its TAIL lines; the in-process lane still pins the
	// exact final result, so nothing weakens.
	if out_multiset != '' {
		if !same_multiset(got, out_multiset.trim_space())
			&& !same_multiset(bin_tail(got, out_multiset), out_multiset.trim_space()) {
			st.record('${label}[bin]: multiset mismatch\n  got:      ${got}\n  expected: ${out_multiset.trim_space()}',
				advisory)
		}
		return
	}
	expected := out_text.trim_space()
	if c.tol > 0 {
		gv := bin_tail(got, expected)
		if math.abs(gv.f64() - expected.f64()) > c.tol * math.abs(expected.f64()) {
			st.record('${label}[bin]: tol mismatch (tol=${c.tol})\n  got:      ${gv}\n  expected: ${expected}',
				advisory)
		}
	} else if !same_shape(got, expected) && !same_shape(bin_tail(got, expected), expected) {
		st.record('${label}[bin]: mismatch\n  got:      ${got}\n  expected: ${expected}', advisory)
	}
}

// bin_tail returns the last K lines of `got`, K = the expected text's line
// count — the multi-form run surface prints doc roots / intermediate values
// ahead of the final program result the fixture pins (#16).
fn bin_tail(got string, expected string) string {
	k := expected.trim_space().split_into_lines().len
	lines := got.split_into_lines()
	if lines.len <= k {
		return got
	}
	return lines[lines.len - k..].join('\n')
}

// probe_refusal evaluates PROGRAM under a full grant and requires the
// undefined-callable refusal (the §4 not-in-subset class). Anything else —
// a real result, a CXER0271 denial, any other error — fails the gate: the
// surface would be IN the artifact.
fn probe_refusal(what string, program string, mut st GateStats) {
	mut env := code.new_env()
	code.register_conformance_test_modules(mut env.state.module_table)
	code.caps_set_all()
	prog := cx.parse_program(program) or {
		st.failures << 'refusal probe ${what}: parse: ${err}'
		return
	}
	mut result := code.eval(prog.body, mut env) or {
		st.failures << 'refusal probe ${what}: eval error (${err}) — expected the user-undefined err VALUE'
		return
	}
	result = code.force_lazy_result(result, mut env)
	rendered := code.render_canonical(result)
	if !rendered.contains('user-undefined') {
		st.failures << 'refusal probe ${what}: expected user-undefined refusal, got ${rendered}'
		return
	}
	st.ran++
}

// probe_typed_refusal is probe_refusal's sibling for a module that IS in the
// artifact: the program must evaluate to an err VALUE carrying `want` (the
// module's own code), not throw and not answer. See dependent_module_probe.
fn probe_typed_refusal(what string, program string, want string, mut st GateStats) {
	mut env := code.new_env()
	code.register_conformance_test_modules(mut env.state.module_table)
	code.caps_set_all()
	prog := cx.parse_program(program) or {
		st.failures << 'typed refusal probe ${what}: parse: ${err}'
		return
	}
	mut result := code.eval(prog.body, mut env) or {
		st.failures << 'typed refusal probe ${what}: eval error (${err}) — expected the ${want} err VALUE'
		return
	}
	result = code.force_lazy_result(result, mut env)
	rendered := code.render_canonical(result)
	if !rendered.contains(want) {
		st.failures << 'typed refusal probe ${what}: expected ${want}, got ${rendered}'
		return
	}
	st.ran++
}

struct RunResult {
	rc  int
	out string
	err string
}

// A spawned case must never hang the gate: measured 2026-08-23, the
// supervise sup-012 case deadlocked in [?wait-for worker] under the cli
// profile and this runner sat in stdout_slurp for 3.5 HOURS inside the
// release-verify record run (the parallel make kept 'Waiting for
// unfinished jobs' with no output — indistinguishable from a slow suite).
// Case-internal deadlines top out at 12 s; 120 s is pure pathology.
const case_hang_limit_s = 120

fn C.kill(pid int, sig int) int

// hang_watchdog kills the child if it outlives the limit; exits quietly
// the moment the pid is gone. The killed child's slurp/wait then return
// and the case FAILS LOUDLY with this stderr line in the log.
fn hang_watchdog(pid int, label string) {
	for _ in 0 .. case_hang_limit_s {
		time.sleep(1 * time.second)
		if C.kill(pid, 0) != 0 {
			return
		}
	}
	eprintln('PROFILE-GATE HANG: case process ${pid} (${label}) still running after ${case_hang_limit_s}s — killed (a case-internal deadline tops out at 12s; this is a deadlock, not a slow case)')
	C.kill(pid, 9)
}

// run_bin_isolated_tmp runs the binary with TMPDIR pointed at a FRESH
// per-case dir: fixtures reach scratch space via [$io:temp-dir "name"], a
// FIXED name under the process temp root — without isolation the binary
// pass shares (and re-appends) the state the in-process pass already
// wrote (io-058 'abab'), and effectful cases pollute each other (R3.11
// wave-run finding). Environment is a full copy + override, never a
// replacement (the child still needs PATH/HOME).
fn run_bin_isolated_tmp(bin string, args []string, tmpdir string) RunResult {
	mut pr := os.new_process(bin)
	pr.set_args(args)
	mut env := map[string]string{}
	for k, v in os.environ() {
		env[k] = v
	}
	env['TMPDIR'] = tmpdir
	pr.set_environment(env)
	pr.set_redirect_stdio()
	pr.run()
	spawn hang_watchdog(pr.pid, '${bin} ${args.join(' ')}')
	os.fd_close(pr.stdio_fd[0])
	out := pr.stdout_slurp()
	errs := pr.stderr_slurp()
	pr.wait()
	return RunResult{
		rc:  pr.code
		out: out
		err: errs
	}
}

fn run_bin(bin string, args []string, stdin_data string) RunResult {
	mut pr := os.new_process(bin)
	pr.set_args(args)
	pr.set_redirect_stdio()
	pr.run()
	spawn hang_watchdog(pr.pid, '${bin} ${args.join(' ')}')
	if stdin_data != '' {
		pr.stdin_write(stdin_data)
	}
	os.fd_close(pr.stdio_fd[0])
	out := pr.stdout_slurp()
	errs := pr.stderr_slurp()
	pr.wait()
	return RunResult{
		rc:  pr.code
		out: out
		err: errs
	}
}

// probe_binary asserts the profile binary's identity + refusal contract.
fn probe_binary(bin string, comp string, mut st GateStats) {
	v := run_bin(bin, ['-v'], '')
	if v.rc != 0 || !v.out.contains('profile  ${comp}') {
		st.failures << 'binary ${bin}: `-v` must report "profile  ${comp}" (rc=${v.rc}):\n${v.out}'
	} else {
		st.ran++
	}
	for verb in ['store-serve', 'fabric-serve', 'store-health', 'store-rotate-kek'] {
		r := run_bin(bin, [verb], '')
		if r.rc != 2 || !r.err.contains('not available in the ${comp} profile') {
			st.failures << 'binary ${bin}: `cx ${verb}` must refuse BY NAME with rc=2 naming the ${comp} profile (rc=${r.rc}): ${r.err.trim_space()}'
		} else {
			st.ran++
		}
	}
	e := run_bin(bin, ['-e', '[+ 1 2]'], '')
	if e.rc != 0 || e.out.trim_space() != '3' {
		st.failures << 'binary ${bin}: `-e [+ 1 2]` must print 3 (rc=${e.rc}, out=${e.out.trim_space()})'
	} else {
		st.ran++
	}
}

fn main() {
	comp := composition()
	if comp == 'custom' {
		eprintln('profile_gate: compiled at a custom pack composition (${excluded_packs()}) — the gate runs at exactly the cli (no exclusions) and embed (all nine) compositions')
		exit(2)
	}
	mut bin := ''
	for a in os.args[1..] {
		if a.starts_with('--bin=') {
			bin = a[6..]
		}
	}
	bin_tmp := os.join_path(os.temp_dir(), 'cx_profile_gate_bin_${os.getpid()}')
	if bin != '' {
		os.mkdir_all(bin_tmp) or { panic('mkdir ${bin_tmp}: ${err}') }
	}
	defer {
		os.rmdir_all(bin_tmp) or {}
	}
	conf_dir := os.real_path(os.join_path(os.dir(@FILE), '..', '..', '..', '..', 'conformance'))
	off := excluded_packs()
	mut excluded_suites := map[string]bool{}
	for p in off {
		if s := pack_suite[p] {
			excluded_suites[s] = true
		}
	}
	mut st := GateStats{}

	// ── EVAL lane: code.cxd (eval-ring) + stdlib ring≤1 ─────────────────────
	code_suite := fixtures.load_suite(os.join_path(conf_dir, 'code.cxd'))
	cmodule_gate, csuite_default := load_gate_policy(conf_dir, 'code')
	for c in code_suite.cases {
		// eval-lane membership: per-case eval-ring > ring > suite eval-ring
		// > suite ring (fixtures.cxs; the svc family evals at ring 2 while
		// its doc lane stays ring 0).
		er := code_suite.case_eval_ring(c)
		if er == '' || er.int() > 1 {
			st.skipped++
			continue
		}
		if needs_excluded_pack(c, off) {
			st.skipped++
			continue
		}
		// per-case gate= > per-module row > suite default > enforced (R3.12:
		// the module tier was loaded then DISCARDED — a future [module] row
		// under the code suite is honored now, mirroring the stdlib lane).
		mut eff := if c.gate != '' { c.gate } else { cmodule_gate['code'] }
		if eff == '' {
			eff = csuite_default
		}
		if eff == '' {
			eff = 'enforced'
		}
		if eff == 'skip' || eff == 'pending' {
			st.skipped++
			continue
		}
		grade_case('code.cxd/${c.name.all_before(' ')}', c, mut st, eff == 'advisory')
		if bin != '' {
			grade_case_binary('code.cxd/${c.name.all_before(' ')}', c, bin, bin_tmp, mut st,
				eff == 'advisory')
		}
	}
	sdir := os.join_path(conf_dir, 'stdlib')
	mut sfiles := os.ls(sdir) or { []string{} }
	sfiles.sort()
	module_gate, suite_default := load_gate_policy(conf_dir, 'stdlib')
	for fname in sfiles {
		if !fname.ends_with('.cxd') {
			continue
		}
		base := fname.all_before('.cxd')
		if excluded_suites[base] {
			st.skipped++
			continue
		}
		suite := fixtures.load_suite(os.join_path(sdir, fname))
		for c in suite.cases {
			ring := suite.case_eval_ring(c)
			if ring == '' || ring.int() > 1 {
				st.skipped++
				continue
			}
			if needs_excluded_pack(c, off) {
				st.skipped++
				continue
			}
			mut eff := if c.gate != '' { c.gate } else { module_gate[base] }
			if eff == '' {
				eff = suite_default
			}
			if eff == '' {
				eff = 'enforced'
			}
			if eff == 'skip' || eff == 'pending' {
				st.skipped++
				continue
			}
			label := '${fname}/${c.name.all_before(' ')}'
			grade_case(label, c, mut st, eff == 'advisory')
			if bin != '' {
				// #951 supervise load-race family: a concurrency-level fixture
				// whose note/terminal transit loses a message ONLY under the
				// full-parallel suite (measured green 25/25 + 80/80 isolated;
				// red across gates only under -j12 load; root on #951). The
				// BINARY lane grades in a fresh subprocess, so one re-grade is
				// state-clean — same contract as the extraction gate's
				// divergence retry: a deterministic failure re-fails and the
				// gate stays red. The IN-PROCESS lane gets no retry here:
				// re-grading a channel-bearing fixture in the same process
				// SEGFAULTS in eval_close on the first grade's leftover
				// fixed-name channel state (measured 2026-08-23; noted on
				// #951) — its flake coverage is the Makefile's serial retry
				// of the whole test binary instead.
				before_b := st.failures.len
				grade_case_binary(label, c, bin, bin_tmp, mut st, eff == 'advisory')
				if c.level == 'concurrency' && st.failures.len > before_b {
					first_b := st.failures[before_b..].clone()
					st.failures.trim(before_b)
					grade_case_binary(label, c, bin, bin_tmp, mut st, eff == 'advisory')
					if st.failures.len == before_b {
						eprintln('profile_gate: TRANSIENT (#951 class, green on re-grade) ${label}[bin]: ${first_b[0]}')
					}
				}
			}
		}
	}

	// ── refusal probes ───────────────────────────────────────────────────────
	probe_refusal('ring-2 store', ring2_probe, mut st)
	for p in off {
		if prog := pack_probe[p] {
			probe_refusal('pack ${p}', prog, mut st)
		}
	}
	for p in off {
		if pr := dependent_module_probe[p] {
			probe_typed_refusal('module depending on pack ${p}', pr[0], pr[1], mut st)
		}
	}

	// ── binary probes ────────────────────────────────────────────────────────
	if bin != '' {
		probe_binary(bin, comp, mut st)
	}

	if st.advisory.len > 0 {
		println('profile_gate[${comp}]: ${st.advisory.len} advisory failure(s) — frontier modules, reported not blocking')
	}
	if st.failures.len > 0 {
		eprintln('profile_gate[${comp}]: ${st.failures.len} FAILURE(S) of ${st.ran} graded (${st.skipped} skipped):')
		for f in st.failures {
			eprintln('  ${f}')
		}
		exit(1)
	}
	mut bin_note := ''
	if bin != '' {
		bin_note = '; BINARY lane: ${st.bin_ran} graded through ${bin}, ${st.bin_inexpressible} binary-inexpressible (test-registry modules / strict-mode — in-process-only), ${st.bin_data_fallback} §1.3 data-fallback answers (R3.11)'
	}
	println('profile_gate[${comp}] OK — ${st.ran} graded, ${st.skipped} skipped (ring>1 / excluded-pack suites / gate-skipped), packs off: ${off}${bin_note}')
}
