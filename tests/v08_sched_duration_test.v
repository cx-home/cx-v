module main

import os

// v08_sched_duration_test.v — sched after/at/every/recur must accept the
// spec-mandated ::duration argument (sched.md §3): both the duration literal
// (1s / 100ms / 10m) and the quoted "10m" string. Previously sch_arg_int took
// only a bare integer, so both forms raised CXER4971 (masked by fixtures that
// passed an int via [$time:duration-m N]).

fn cx_binary() string {
	abs := os.real_path('vcx/target/cx')
	if !os.is_file(abs) {
		panic('vcx/target/cx not found at ${abs} — run `make build-vcx` first')
	}
	return abs
}

fn run_prog(src string) string {
	p := os.join_path(os.temp_dir(), 'cx_sched_dur.cx')
	os.write_file(p, src) or { panic('write: ${err}') }
	return os.execute('${cx_binary()} --allow-all ${p}').output
}

fn test_sched_after_duration_literal() {
	out := run_prog('[?lib \'cx-stdlib/sched\' :as sched]\n[\$sched:after 5s [?fn () :tick]]\n')
	assert !out.contains('CXER4971'), 'after must accept a ::duration literal; got: ${out}'
	assert out.contains('armed') || out.contains('timer'), 'after should arm a timer; got: ${out}'
}

fn test_sched_after_duration_string() {
	out := run_prog('[?lib \'cx-stdlib/sched\' :as sched]\n[\$sched:after "10m" [?fn () :tick]]\n')
	assert !out.contains('CXER4971'), 'after must accept a quoted duration string; got: ${out}'
	assert out.contains('armed') || out.contains('timer'), 'after should arm a timer; got: ${out}'
}
