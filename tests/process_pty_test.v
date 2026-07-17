module main

import os
import testenv

// process_pty_test.v — BEHAVIORAL conformance for §3.6 pseudo-terminal:
// spawn-pty allocates a real pty (openpty + posix_spawn), attaches the child's
// stdio to the slave (so the child sees a tty), and the `pty` accessor returns
// one bidirectional io-style master handle (process.md §3.6). TDD red test for
// the pty stub (CXER4009 even where ptys exist); passes once spawn-pty is real.
// Hermetic loopback: a child prints to its (pty) stdout; we read it off the
// master. The round-trip only works over a real pty master fd.

fn cx_binary() string {
	return testenv.cx_bin()
}

fn write_tmp(name string, content string) string {
	p := os.join_path(os.temp_dir(), name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

fn test_process_spawn_pty_roundtrip() {
	$if windows {
		eprintln('SKIP: ConPTY path not exercised on this runner')
		return
	}
	prog := write_tmp('cx_pty.cx', '[?lib \'cx-stdlib/process\' :as p]\n' +
		'[?lib \'cx-stdlib/io\' :as io]\n' +
		'[?let [= \$h [\$p:spawn-pty ("sh", "-c", "echo pty-hello")]]\n' +
		'  [?let [= \$m [\$p:pty \$h]]\n' +
		'    [\$io:read-line \$m]]]\n')
	res := os.execute('${cx_binary()} --allow-all ${prog}')
	out := res.output
	assert out.contains('pty-hello'), 'spawn-pty did not round-trip child output over a real pty master; got: ${out}'
}

// isatty: a child gating on a tty must see one under spawn-pty (the whole point).
fn test_process_pty_is_a_tty() {
	$if windows {
		eprintln('SKIP: ConPTY path not exercised on this runner')
		return
	}
	prog := write_tmp('cx_pty_isatty.cx', '[?lib \'cx-stdlib/process\' :as p]\n' +
		'[?lib \'cx-stdlib/io\' :as io]\n' +
		'[?let [= \$h [\$p:spawn-pty ("sh", "-c", "test -t 1 && echo IS_TTY || echo NOT_TTY")]]\n' +
		'  [?let [= \$m [\$p:pty \$h]]\n' +
		'    [\$io:read-line \$m]]]\n')
	res := os.execute('${cx_binary()} --allow-all ${prog}')
	out := res.output
	assert out.contains('IS_TTY'), 'child under spawn-pty did not see a tty on stdout; got: ${out}'
}

// lifecycle: wait on a pty child returns its exit code (waitpid on the bare pid).
fn test_process_pty_wait_exit_code() {
	$if windows {
		eprintln('SKIP')
		return
	}
	prog := write_tmp('cx_pty_wait.cx', '[?lib \'cx-stdlib/process\' :as p]\n' +
		'[?let [= \$h [\$p:spawn-pty ("sh", "-c", "exit 7")]]\n' +
		'  [\$p:wait \$h]]\n')
	res := os.execute('${cx_binary()} --allow-all ${prog}')
	out := res.output.trim_space()
	assert out == '7', 'pty child wait did not return the real exit code; got: ${out}'
}

// Regression: stdout/stderr/stdin on a PTY handle must NOT segfault. A pty
// handle has a nil os.Process (native pty); the stream accessors used to deref
// it. They now resolve to the bidirectional master, so reading $p:stdout of a
// pty child works (multiplexed onto the master — the child sees a tty).
fn test_process_pty_stdout_accessor_no_crash() {
	$if windows {
		eprintln('SKIP')
		return
	}
	prog := write_tmp('cx_pty_stdout.cx', '[?lib \'cx-stdlib/process\' :as p]\n' +
		'[?lib \'cx-stdlib/io\' :as io]\n' +
		'[?let [= \$h [\$p:spawn-pty ("bash", "-c", "test -t 1 && echo TTY || echo PIPE")]]\n' +
		'  [\$io:read-line [\$p:stdout \$h]]]\n')
	res := os.execute('${cx_binary()} --allow-all ${prog}')
	assert res.exit_code == 0, 'stdout accessor on a pty handle crashed (exit ${res.exit_code}); out: ${res.output}'
	assert res.output.contains('TTY'), 'pty stdout accessor did not read the master; got: ${res.output}'
}
