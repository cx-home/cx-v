module main

import os
import testenv

// process_stdio_test.v — BEHAVIORAL conformance for §2.4 child-stdio: a
// spawned child's stdin/stdout/stderr accessors return REAL io-style handles
// wired to the child's pipe fds (process.md §2.4 — "stdout/stderr return
// readable handles; stdin returns a writable handle; closing stdin signals
// EOF"). This is the TDD red test for de-stubbing proc_stdio_handle (which
// returned a synthetic [file role=child-stdout] with no fd). It MUST fail
// against the stub (the handle reads/writes nothing) and pass only once the
// accessors expose the live child fds through cx-stdlib/io.

fn cx_binary() string {
	return testenv.cx_bin()
}

fn write_tmp(name string, content string) string {
	p := os.join_path(os.temp_dir(), name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

// Spawn `cat`, write a line to its stdin handle, close stdin (EOF), then read
// the echoed line back off its stdout handle. Round-trip proves the stdin
// (writable) + stdout (readable) handles are wired to the child's real pipes.
fn test_process_child_stdio_roundtrip() {
	prog := write_tmp('cx_proc_stdio.cx', '[?lib \'cx-stdlib/process\' :as p]\n' +
		'[?lib \'cx-stdlib/io\' :as io]\n' +
		'[?let [= \$h [\$p:spawn ("cat")]]\n' +
		'  [?let [= \$cin [\$p:stdin \$h]]\n' +
		'    [?let [= \$w [\$io:write-line \$cin "hello-child"]]\n' +
		'      [?let [= \$cc [\$io:close \$cin]]\n' +
		'        [?let [= \$cout [\$p:stdout \$h]]\n' +
		'          [\$io:read-line \$cout]]]]]]\n')
	res := os.execute('${cx_binary()} --allow-all ${prog}')
	out := res.output.trim_space()
	assert out.contains('hello-child'), 'child-stdio did not round-trip through the real cat pipe; got: ${out}'
}

// stderr is a readable handle: run a shell that writes to fd 2, read it back.
fn test_process_child_stderr() {
	prog := write_tmp('cx_proc_stderr.cx', '[?lib \'cx-stdlib/process\' :as p]\n' +
		'[?lib \'cx-stdlib/io\' :as io]\n' +
		'[?let [= \$h [\$p:spawn ("sh", "-c", "echo oops 1>&2")]]\n' +
		'  [?let [= \$cerr [\$p:stderr \$h]]\n' +
		'    [\$io:read-line \$cerr]]]\n')
	res := os.execute('${cx_binary()} --allow-all ${prog}')
	out := res.output.trim_space()
	assert out.contains('oops'), 'child stderr handle did not surface the child fd-2 output; got: ${out}'
}
