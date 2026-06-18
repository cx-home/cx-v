module main

import os

// v08_closure_escape_test.v — BEHAVIORAL coverage for the closure-escape
// representation fix (cx-private #45). An ESCAPING closure ([?fn] returned from a
// def) carries its Closure ON its function-value sentinel, so it travels WITH the
// value and resolves against its own DEFINING scope wherever applied — no
// id→scope-table registry. This pins the cross-MODULE cases the single-program
// conformance harness (conformance/code.cxd, stdlib/run.cxd) cannot express:
// they need a real [?lib './m.cx'] boundary. The program-level Bug-1 (zero-arg
// def returns anon) + Bug-3 (nested pipe re-capture) are pinned in code.cxd
// (program-for-013b/013c) and stdlib/run.cxd (run-007).
//
// Bug-2: a returned anon from a MODULE def resolves its module's UNQUALIFIED
// siblings when applied from the caller's frame (not the caller's scope). Before
// the fix the anon resolved against the caller (or the program-scope mirror) and
// failed with `no callable "<sibling>"`.

fn cx_binary() string {
	abs := os.real_path('vcx/target/cx')
	if !os.is_file(abs) {
		panic('vcx/target/cx not found at ${abs} — run `make build-vcx-dev` first')
	}
	return abs
}

// run_program writes the given module + entry sources into a fresh temp dir
// (so `[?lib './m.cx']` resolves relative to the entry file) and runs the entry
// through the real cx binary, returning trimmed stdout+stderr.
fn run_program(files map[string]string, entry string) string {
	dir := os.join_path(os.temp_dir(), 'cx45_${os.getpid()}_${entry.all_before('.')}')
	os.mkdir_all(dir) or { panic('mkdir ${dir}: ${err}') }
	defer {
		os.rmdir_all(dir) or {}
	}
	for name, content in files {
		os.write_file(os.join_path(dir, name), content) or { panic('write ${name}: ${err}') }
	}
	// Run from inside the temp dir so a `[?lib './m.cx']` resolves relative to it
	// (the resolver is process-CWD relative).
	res := os.execute('cd ${dir} && ${cx_binary()} ${entry}')
	return res.output.trim_space()
}

// Bug-2 — a returned anon from a ≥1-arg MODULE def calls an UNQUALIFIED sibling
// (`helper`) of its own module. Resolves against the module, not the caller.
fn test_returned_anon_resolves_module_sibling() {
	mod := "[?def helper scope=public (\$x) [+ \$x 1]]\n" +
		"[?def mk scope=public (\$u) [?fn (\$p) [\$helper \$p]]]\n"
	main := "[?lib './m.cx' :as m]\n[?let [= \$f [\$m:mk 99]] [\$f 10]]\n"
	got := run_program({ 'm.cx': mod, 'main.cx': main }, 'main.cx')
	assert got == '11', 'module-sibling-resolving returned anon: expected 11, got `${got}`'
}

// Bug-2 (zero-arg variant) — a returned anon from a ZERO-arg MODULE def likewise
// resolves its module sibling. The zero-arg def is invoked with the call sigil
// [$m:mk] (a bare 0-arg head is a data element, not a call).
fn test_returned_anon_zero_arg_module_def() {
	mod := "[?def helper scope=public (\$x) [* \$x 2]]\n" +
		"[?def mk scope=public () [?fn (\$p) [\$helper \$p]]]\n"
	main := "[?lib './m.cx' :as m]\n[?let [= \$f [\$m:mk]] [\$f 21]]\n"
	got := run_program({ 'm.cx': mod, 'main.cx': main }, 'main.cx')
	assert got == '42', 'zero-arg module def returned anon: expected 42, got `${got}`'
}

// Variant C — a captured let-BINDING survives when the closure is applied from
// another module (here via cx-x/run's invoke). The returned anon closes over a
// module const ($base) AND its param ($m); both must be live at apply time.
fn test_captured_binding_survives_cross_module_apply() {
	mod := "[?const scope=public base 100]\n" +
		"[?def mk scope=public (\$m) [?fn (\$p) [+ [+ \$base \$m] \$p]]]\n"
	main := "[?lib 'cx-x/run' :as run]\n[?lib './m.cx' :as m]\n" +
		"[?let [= \$f [\$m:mk 20]] [\$run:invoke \$f 3]]\n"
	got := run_program({ 'm.cx': mod, 'main.cx': main }, 'main.cx')
	assert got == '123', 'captured const+param across module apply: expected 123, got `${got}`'
}
