module main

import code
import os

// RED → GREEN TDD for UNIFORM LEXICAL SCOPING (cx-private #19, #22;
// spec/03-approved/core/code.md). A callable must resolve its free
// names — sibling functions AND module values/consts — in its DEFINING
// environment, not the caller's. These fixtures FAIL on the pre-fix engine
// (closures alias the caller's closures table + snapshot bindings before consts
// load) and pass once the defining-scope model lands. Behavior, not names.

// Helper: run a program text in a fresh temp dir (for local [?lib] resolution),
// returning the rendered output. Restores cwd.
fn run_in_tmp(files map[string]string, main_src string) string {
	prev := os.getwd()
	dir := os.join_path(os.temp_dir(), 'cx-scope-${os.getpid()}-${files.len}-${main_src.len}')
	os.mkdir_all(dir) or { return 'MKDIR-FAIL: ${err}' }
	for name, body in files {
		os.write_file(os.join_path(dir, name), body) or { return 'WRITE-FAIL: ${err}' }
	}
	os.chdir(dir) or { return 'CHDIR-FAIL: ${err}' }
	out := code.eval_code('', main_src, 'text') or {
		os.chdir(prev) or {}
		return 'EVAL-ERR: ${err}'
	}
	os.chdir(prev) or {}
	os.rmdir_all(dir) or {}
	return out
}

// #22 — a [?const] referenced inside a [?def] body must dereference to its value
// (consistent with top-level + argument use). Pre-fix: the def captures bindings
// BEFORE the top-level two-pass evaluates consts, so the body sees `Q` as a
// bareword (count 1) instead of the 2-element sequence.
fn test_const_in_def_body() {
	prog := "[?const Q ([q sym=A], [q sym=B])]
[?def f-inside pure () [\$count Q]]
[?def f-arg pure (\$q) [\$count \$q]]
[probe top=[\$count Q] inside=[\$f-inside] viaarg=[\$f-arg Q]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('inside=2'), 'const Q must deref inside a def body (expect inside=2), got: ${out}'
	assert out.contains('top=2'), 'sanity: top-level const deref, got: ${out}'
	assert out.contains('viaarg=2'), 'sanity: const-as-arg deref, got: ${out}'
}

// #19 — in a module loaded via [?lib], a [?def] must be able to call a SIBLING
// [?def] (resolved in the module's defining scope). Pre-fix: `[$l:b]` raises
// `no callable "a"` because the call env aliases the importer's closures, which
// lack the module's unqualified `a`.
fn test_lib_sibling_def_call() {
	out := run_in_tmp({
		'lib_c.cx': '[?def a scope=public pure () 41]\n[?def b scope=public pure () [+ [\$a] 1]]\n'
	}, "[?lib './lib_c.cx' :as l]\n[out [\$l:b]]")
	assert out.contains('42'), 'imported sibling-def call must work (expect 42), got: ${out}'
	assert !out.contains('no callable'), 'sibling a must resolve in the module scope, got: ${out}'
}

// Mutual recursion (letrec) across sibling defs in an imported module.
fn test_lib_mutual_recursion() {
	out := run_in_tmp({
		'lib_mr.cx': '[?def is-even scope=public pure (\$n) [?if [= \$n 0] [then true] [else [\$is-odd [- \$n 1]]]]]\n[?def is-odd scope=public pure (\$n) [?if [= \$n 0] [then false] [else [\$is-even [- \$n 1]]]]]\n'
	}, "[?lib './lib_mr.cx' :as m]\n[out [\$m:is-even 4]]")
	assert out.contains('true'), 'mutual recursion across sibling defs in a lib (is-even 4=true), got: ${out}'
	assert !out.contains('no callable'), 'mutual-recursive sibling must resolve, got: ${out}'
}

// 3-level transitive sibling calls in an imported module (a→b→c).
fn test_lib_transitive_three_level() {
	out := run_in_tmp({
		'lib_t.cx': '[?def c scope=public pure () 3]\n[?def b scope=public pure () [+ [\$c] 10]]\n[?def a scope=public pure () [+ [\$b] 100]]\n'
	}, "[?lib './lib_t.cx' :as t]\n[out [\$t:a]]")
	assert out.contains('113'), 'transitive sibling calls a->b->c (expect 113), got: ${out}'
	assert !out.contains('no callable'), 'transitive siblings must resolve, got: ${out}'
}

// A [?const] referenced inside a [?def] body, both in an imported module.
fn test_lib_const_in_def() {
	out := run_in_tmp({
		'lib_k.cx': "[?const BASE 100]\n[?def bumped scope=public pure () [+ BASE 5]]\n"
	}, "[?lib './lib_k.cx' :as k]\n[out [\$k:bumped]]")
	assert out.contains('105'), 'module const referenced in a sibling def body (expect 105), got: ${out}'
}

// #20 — a [?lib]/[?def]/[?const] directive inside a `#` comment line in an
// IMPORTED module must be ignored (as it is on a direct run), not scanned by the
// module loader's directive extraction (which would try to resolve the commented
// import and fail with MODULE_FILE_NOT_FOUND / a spurious cycle).
fn test_lib_commented_directive_ignored() {
	out := run_in_tmp({
		'lib_cmt.cx': "# [?lib './ghost.cx']\n[?def f scope=public pure () 7]\n"
	}, "[?lib './lib_cmt.cx' :as l]\n[out [\$l:f]]")
	assert out.contains('7'), 'a commented [?lib] in an imported module must be ignored (expect 7), got: ${out}'
	assert !out.contains('ghost'), 'the commented import must NOT be resolved, got: ${out}'
}
