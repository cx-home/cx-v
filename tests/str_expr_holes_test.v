module main

import os
import testenv

// str_expr_holes_test.v — #66: [?str] interpolation holes accept FULL
// expressions (arithmetic, calls, …), not just binding-paths. Computed holes
// previously silently data-fell-back; now they evaluate, and a non-scalar /
// empty / malformed hole fails loud (no data echo).

fn cx_bin_se() string {
	return testenv.cx_bin()
}

fn run_se(src string) os.Result {
	f := os.join_path(os.temp_dir(), 'cx_se_${os.getpid()}_${src.len}.cx')
	os.write_file(f, src) or { panic('write: ${err}') }
	defer { os.rm(f) or {} }
	return os.execute('${cx_bin_se()} --allow-all ${f}')
}

fn test_arithmetic_hole() {
	r := run_se('[?let [= \$a 2] [= \$b 3] [?str "sum={[+ \$a \$b]}"]]')
	assert r.exit_code == 0, 'errored: ${r.output}'
	assert r.output.trim_space() == "'sum=5'", 'arith hole wrong: ${r.output}'
}

fn test_call_hole() {
	r := run_se("[?lib 'cx-stdlib/strings'] [?let [= \$s \"hi\"] [?str \"up={[\$strings:upper \$s]}\"]]")
	assert r.exit_code == 0, 'errored: ${r.output}'
	assert r.output.trim_space() == "'up=HI'", 'call hole wrong: ${r.output}'
}

fn test_mixed_binding_and_computed_holes() {
	r := run_se('[?let [= \$a 2] [?str "a={\$a} double={[* \$a 2]}"]]')
	assert r.exit_code == 0, 'errored: ${r.output}'
	assert r.output.trim_space() == "'a=2 double=4'", 'mixed holes wrong: ${r.output}'
}

fn test_binding_path_hole_still_works() {
	r := run_se('[?let [= \$u [user name=Alice]] [?str "name={\$u@name}"]]')
	assert r.exit_code == 0, 'errored: ${r.output}'
	assert r.output.trim_space() == "'name=Alice'", 'path hole regressed: ${r.output}'
}

fn test_non_scalar_hole_fails_loud() {
	// a hole resolving to a sequence is a CXER0100 at eval — NOT a silent data
	// echo of the program.
	r := run_se('[?str "x={(1,2,3)}"]')
	assert r.exit_code != 0, 'non-scalar hole should fail loud: ${r.output}'
	assert r.output.contains('CXER0100'), 'expected CXER0100: ${r.output}'
	// exit!=0 above already proves fail-loud (a silent data echo would exit 0).
}

fn test_empty_hole_fails_loud() {
	r := run_se('[?str "x={}"]')
	assert r.exit_code != 0, 'empty hole should fail loud: ${r.output}'
	assert r.output.contains('CXER0100'), 'expected CXER0100: ${r.output}'
	// exit!=0 above already proves fail-loud (a silent data echo would exit 0).
}
