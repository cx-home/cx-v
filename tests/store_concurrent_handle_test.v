module main

import os
import testenv
import time

// store_concurrent_handle_test.v — #74 Defect 2: concurrent access to a single
// shared cx-stdlib/store handle under `[par]` must NOT crash the process. Before
// the fix, `[par]` put-doc / get-doc over one handle raced the docs/aliases maps
// (and the per-op cap state) and segfaulted nondeterministically (observed exit
// 139 / signal 11 ~1-in-10 runs). The fix serializes per-store ops behind a
// non-blocking try_lock: a contending worker gets a clean E_STORE_HANDLE_RACE
// (CXER1140) value instead of a crash, so the program always completes cleanly.
//
// A data race is nondeterministic, so this asserts the invariant the prompt
// specifies: run the repro MANY times and require every run to exit cleanly
// (never a signal kill). Handle-race errors are values the program discards, so
// the top-level reduce still returns its count → exit 0 on every run.

fn cx_bin_store() string {
	return testenv.cx_bin()
}

const par_put_repro = "[?lib 'cx-stdlib/store']
[?let [= \$s [\$store:open \"mem://\"]]
  [?reduce [\$range 1 5000] [using [?fn (\$a \$i)
    [?let [= \$h [\$store:put-doc \$s [doc [v \$i]]]] [+ \$a 1]]]] [init 0] [par]]]
"

const par_read_repro = "[?lib 'cx-stdlib/store']
[?let [= \$s [\$store:open \"mem://\"]]
  [= \$h0 [\$store:put-doc \$s [doc [v 1]]]]
  [?reduce [\$range 1 5000] [using [?fn (\$a \$i)
    [?let [= \$d [\$store:get-doc \$s \$h0]] [+ \$a 1]]]] [init 0] [par]]]
"

// run the program `runs` times; assert no run dies on a signal (exit >= 128).
fn assert_no_crash(label string, src string, runs int) {
	prog := os.join_path(os.temp_dir(), 'cx_store74_${label}_${os.getpid()}.cx')
	os.write_file(prog, src) or { panic('write: ${err}') }
	defer { os.rm(prog) or {} }
	for i in 0 .. runs {
		r := os.execute('${cx_bin_store()} --allow-all ${prog}')
		// A signal-killed child surfaces as exit_code >= 128 (128 + signum),
		// e.g. 139 for SIGSEGV. The pre-fix race crashed here.
		assert r.exit_code < 128, '${label} run ${i}: process killed by signal (exit ${r.exit_code}) — concurrent shared-handle access crashed:\n${r.output}'
		// Clean completion: handle-race errors are discarded values, so the
		// top-level reduce returns its count and the process exits 0.
		assert r.exit_code == 0, '${label} run ${i}: non-clean exit ${r.exit_code}:\n${r.output}'
	}
}

fn test_par_shared_handle_writes_never_crash() {
	assert_no_crash('write', par_put_repro, 60)
}

fn test_par_shared_handle_reads_never_crash() {
	assert_no_crash('read', par_read_repro, 40)
}

// Sequential use is unaffected by the guard (no deadlock, correct result).
fn test_sequential_store_unaffected() {
	src := "[?lib 'cx-stdlib/store']
[?let [= \$s [\$store:open \"mem://\"]]
  [= \$h [\$store:put-doc \$s [doc [v 7]]]]
  [= \$_ [\$store:set-alias \$s \"k7\" \$h]]
  [\$store:get-doc \$s [\$store:get-alias \$s \"k7\"]]]
"
	prog := os.join_path(os.temp_dir(), 'cx_store74_seq_${os.getpid()}.cx')
	os.write_file(prog, src) or { panic('write: ${err}') }
	defer { os.rm(prog) or {} }
	r := os.execute('${cx_bin_store()} --allow-all ${prog}')
	assert r.exit_code == 0, 'sequential store errored: ${r.output}'
	assert r.output.contains('[doc [v 7]]'), 'sequential round-trip wrong: ${r.output}'
	_ := time.now()
}
