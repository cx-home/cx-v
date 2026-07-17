module main

import os
import testenv

// recursive_def_dispatch_test.v — #53: a self-recursive (or mutually
// recursive) [?def] called by its BAREWORD head — `[loop …]`, not `[$loop …]` —
// must dispatch as a call, not fall through to data-element construction.
//
// Root cause: the element-form closure dispatch (eval_cx_element) gated the
// multi-arg whitespace call on `all_items_are_expr_position`, which rejected an
// argument that is itself an OPERATOR-headed element (`[- $n 1]`). So a recursive
// call doing arithmetic on its counter — `[loop [- $n 1] …]` — was built as the
// data element `[loop 1 'x']` instead of recursing. The corrupted (un-evaluated)
// result then made the caller's downstream stdlib call read as "no callable".

fn cx_bin() string {
	return testenv.cx_bin()
}

fn run_src(src string) os.Result {
	f := os.join_path(os.temp_dir(), 'cx_rec_${os.getpid()}_${src.len}.cx')
	os.write_file(f, src) or { panic(err) }
	defer { os.rm(f) or {} }
	return os.execute('${cx_bin()} --allow-all ${f}')
}

// ── 1. The exact #53 reproducer: recursive impure def + stdlib in the caller ──

fn test_issue53_recursive_impure_then_stdlib() {
	src := "[?lib 'cx-stdlib/strings' :as s]\n" +
		"[?lib 'cx-stdlib/time' :as time]\n" +
		'[?def loop impure (\$n \$acc)\n' +
		'  [?if [<= \$n 0] [then \$acc]\n' +
		'   [else [?let [= \$t [\$time:now]] [loop [- \$n 1] [\$concat \$acc "x"]]]]]]\n' +
		'[?def run impure (\$_)\n' +
		'  [?let [= \$x [loop 3 ""]]\n' +
		'   [?let [= \$len [\$s:length \$x]] [\$concat "len=" \$len]]]]\n' +
		'[run ""]\n'
	r := run_src(src)
	assert r.exit_code == 0, 'exit ${r.exit_code}: ${r.output}'
	assert r.output.trim_space() == "'len=3'", 'expected len=3, got: ${r.output}'
}

// ── 2. Pure self-recursion by bareword head returns the computed value ────────

fn test_bareword_self_recursion() {
	src := '[?def sumto (\$n \$acc) [?if [<= \$n 0] [then \$acc] [else [sumto [- \$n 1] [+ \$acc \$n]]]]]\n[sumto 5 0]\n'
	r := run_src(src)
	assert r.exit_code == 0, 'exit ${r.exit_code}: ${r.output}'
	assert r.output.trim_space() == '15', 'expected 15, got: ${r.output}'
}

// ── 3. Single-arg recursive call with an operator-element argument ────────────

fn test_bareword_single_arg_operator_recursion() {
	src := '[?def cd (\$n) [?if [<= \$n 0] [then :done] [else [cd [- \$n 1]]]]]\n[cd 5]\n'
	r := run_src(src)
	assert r.exit_code == 0, 'exit ${r.exit_code}: ${r.output}'
	assert r.output.trim_space() == ':done', 'expected :done, got: ${r.output}'
}

// ── 4. Mutual recursion by bareword head ──────────────────────────────────────

fn test_bareword_mutual_recursion() {
	src := '[?def ev (\$n) [?if [= \$n 0] [then true] [else [od [- \$n 1]]]]]\n' +
		'[?def od (\$n) [?if [= \$n 0] [then false] [else [ev [- \$n 1]]]]]\n[ev 4]\n'
	r := run_src(src)
	assert r.exit_code == 0, 'exit ${r.exit_code}: ${r.output}'
	assert r.output.trim_space() == 'true', 'expected true, got: ${r.output}'
}

// ── 4b. Zero-arg user-def is callable by its bareword head (#55) ──────────────

fn test_bareword_zero_arg_def_dispatches() {
	// `[?def f () …]` then `[f]` (no args) must RUN f, not construct the data
	// element `[f]`. Before #55 the element-form closure dispatch gated on
	// `items.len >= 1`, so a nullary call fell through to construction → `[f]`.
	src := '[?def f impure () [\$concat "hi-from-" "f"]]\n[f]\n'
	r := run_src(src)
	assert r.exit_code == 0, 'exit ${r.exit_code}: ${r.output}'
	assert r.output.trim_space() == "'hi-from-f'", 'expected hi-from-f, got: ${r.output}'
}

// ── 4c. A bareword that is NOT a def still self-evaluates as a data word ───────

fn test_bareword_nondef_zero_arg_is_data() {
	// The zero-arg widening is gated on `name in env.closures`; an undefined
	// bareword element `[primary]` must remain a data element (homoiconic rule),
	// never an "unknown function" error.
	src := '[?def f impure () "ran"]\n[primary]\n'
	r := run_src(src)
	assert r.exit_code == 0, 'exit ${r.exit_code}: ${r.output}'
	assert r.output.trim_space() == '[primary]', 'expected [primary] data element, got: ${r.output}'
}

// ── 6. #59: a nested USER-DEF call in argument position is APPLIED ─────────────
//
// Same gate as #53: `all_items_are_expr_position`. An argument that is itself a
// bareword element whose head names a registered closure (`[f "a"]`) is a
// value-producing CALL, not a data child. Before the fix `[g [f "a"]]` failed
// the gate → the OUTER `g` fell through to data construction (`[g 'F(a)']`),
// and in stringy callers the downstream stdlib read as a misleading
// `no callable "concat"`. Nested BUILTIN / `$`-calls already applied; this
// restores parity for user defs.

fn test_issue59_nested_userdef_arg_is_applied() {
	src := '[?def f (\$x) [\$concat "F(" \$x ")"]]\n' +
		'[?def g (\$y) [\$concat "G[" \$y "]"]]\n' +
		'[g [f "a"]]\n'
	r := run_src(src)
	assert r.exit_code == 0, 'exit ${r.exit_code}: ${r.output}'
	assert r.output.trim_space() == "'G[F(a)]'", 'expected G[F(a)], got: ${r.output}'
}

fn test_issue59_nested_userdef_arg_numeric() {
	src := '[?def inc (\$x) [+ \$x 1]]\n[?def dbl (\$y) [* \$y 2]]\n[dbl [inc 5]]\n'
	r := run_src(src)
	assert r.exit_code == 0, 'exit ${r.exit_code}: ${r.output}'
	assert r.output.trim_space() == '12', 'expected 12 (dbl(inc(5))), got: ${r.output}'
}

fn test_issue59_three_deep_userdef_nesting() {
	src := '[?def f (\$x) [\$concat "F(" \$x ")"]]\n' +
		'[?def g (\$y) [\$concat "G[" \$y "]"]]\n' +
		'[?def h (\$z) [\$concat "H{" \$z "}"]]\n' +
		'[h [g [f "a"]]]\n'
	r := run_src(src)
	assert r.exit_code == 0, 'exit ${r.exit_code}: ${r.output}'
	assert r.output.trim_space() == "'H{G[F(a)]}'", 'expected H{G[F(a)]}, got: ${r.output}'
}

// A nested non-def element argument still constructs as data (no over-broad
// hijack): `[g [a 1]]` where `a` is not a def keeps `[a 1]` a data child.
fn test_issue59_nested_nondef_arg_stays_data() {
	src := '[?def g (\$y) \$y]\n[g [a 1]]\n'
	r := run_src(src)
	assert r.exit_code == 0, 'exit ${r.exit_code}: ${r.output}'
	assert r.output.contains('[a 1]'), 'nested non-def element must stay data: ${r.output}'
}

// ── 5. A data element whose head is NOT a def still constructs (not hijacked) ──

fn test_data_element_head_not_dispatched() {
	// `widget` is not a [?def] — `[widget …]` must remain data construction even
	// with nested-element children, so the closure-dispatch widening is gated on
	// the head actually being a registered closure.
	f := os.join_path(os.temp_dir(), 'cx_rec_data_${os.getpid()}.cx')
	os.write_file(f, '[widget [child 1] [child 2]]\n') or { panic(err) }
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} --from=cx --to=cx ${f}')
	assert r.exit_code == 0, 'exit ${r.exit_code}: ${r.output}'
	assert r.output.contains('[widget'), 'widget element should construct as data: ${r.output}'
	assert r.output.contains('[child'), 'child elements should be preserved: ${r.output}'
}
