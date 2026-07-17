module main

import os
import testenv

// lint_let_staircase_test.v — #65: the CX-L006 detect-only lint rule flags a
// PURE nested single-binding [?let] staircase (>= 3 levels) and suggests the
// flat [?let] (let*) form. Detect-only (info severity, no rewrite); non-pure
// nestings and shallow chains are left alone.

fn cx_bin_lint() string {
	return testenv.cx_bin()
}

fn lint_out(src string, extra string) string {
	f := os.join_path(os.temp_dir(), 'cx_l006_${os.getpid()}_${src.len}.cx')
	os.write_file(f, src) or { panic('write: ${err}') }
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin_lint()} lint ${extra} ${f}')
	return r.output
}

fn count_l006(out string) int {
	mut n := 0
	for line in out.split('\n') {
		if line.contains('CX-L006') {
			n++
		}
	}
	return n
}

fn test_three_deep_staircase_flagged() {
	out := lint_out('[?let [= \$a 1] [?let [= \$b 2] [?let [= \$c 3] [+ \$a \$b \$c]]]]', '')
	assert count_l006(out) == 1, 'expected one CX-L006, got: ${out}'
	assert out.contains('3 levels'), 'expected "3 levels", got: ${out}'
}

fn test_flat_let_not_flagged() {
	out := lint_out('[?let [= \$a 1] [= \$b 2] [= \$c 3] [+ \$a \$b \$c]]', '')
	assert count_l006(out) == 0, 'flat let* should not be flagged: ${out}'
}

fn test_two_deep_below_threshold_not_flagged() {
	out := lint_out('[?let [= \$a 1] [?let [= \$b 2] [+ \$a \$b]]]', '')
	assert count_l006(out) == 0, '2-deep is below the threshold, should not flag: ${out}'
}

fn test_non_pure_if_body_not_flagged() {
	// outer [?let] body is an [?if] (lets live in its branches) — not a pure
	// chain, must not be flagged.
	out := lint_out('[?let [= \$a 1] [?if true [then [?let [= \$b 2] [?let [= \$c 3] \$b]]] [else 0]]]',
		'')
	assert count_l006(out) == 0, 'non-pure ([?if]-bodied) let must not flag: ${out}'
}

fn test_multi_binding_breaks_chain() {
	// a middle [?let] with two bindings is not single-binding → no pure
	// 3-chain → no flag.
	out := lint_out('[?let [= \$a 1] [?let [= \$b 2] [= \$b2 3] [?let [= \$c 4] \$a]]]', '')
	assert count_l006(out) == 0, 'multi-binding middle breaks the staircase: ${out}'
}

fn test_four_deep_reports_outermost_once() {
	out := lint_out('[?let [= \$a 1] [?let [= \$b 2] [?let [= \$c 3] [?let [= \$d 4] [+ \$a \$b]]]]]',
		'')
	assert count_l006(out) == 1, 'a 4-deep staircase should flag once (outermost), got: ${out}'
	assert out.contains('4 levels'), 'expected "4 levels", got: ${out}'
}

fn test_disable_suppresses_l006() {
	out := lint_out('[?let [= \$a 1] [?let [= \$b 2] [?let [= \$c 3] \$a]]]', '--disable=CX-L006')
	assert count_l006(out) == 0, '--disable=CX-L006 should suppress it: ${out}'
}

fn test_severity_is_info_not_failing() {
	// info severity must not trip the default --fail-on=error (exit 0).
	f := os.join_path(os.temp_dir(), 'cx_l006_exit_${os.getpid()}.cx')
	os.write_file(f, '[?let [= \$a 1] [?let [= \$b 2] [?let [= \$c 3] \$a]]]') or { panic(err) }
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin_lint()} lint ${f}')
	assert r.exit_code == 0, 'CX-L006 is info severity — must not fail the default gate, got exit ${r.exit_code}: ${r.output}'
	assert r.output.contains('CX-L006'), 'expected the finding in output: ${r.output}'
}
