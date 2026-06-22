module main

import os

// net_set_deadline_test.v — #29 (fail-loud slice): net:set-deadline /
// net:set-opt are socket operations. Called on a `[std-stream …]` handle
// (stdin/stdout/stderr from cx-stdlib/env) they were SILENTLY accepted yet had
// no effect — a read still blocked past the "deadline". They must now reject
// loudly (CXER4522) so the caller learns it immediately. (A timeout / non-
// blocking std-stream READ is a separate, not-yet-available surface.)

fn cx_bin_dl() string {
	return os.join_path(@VMODROOT, 'target', 'cx')
}

fn run_dl(prog_body string) os.Result {
	path := os.join_path(os.temp_dir(), 'cx_dl29_${os.getpid()}.cx')
	os.write_file(path, prog_body) or { panic(err) }
	defer { os.rm(path) or {} }
	return os.execute('${cx_bin_dl()} --allow-env --allow-net ${path}')
}

// set-deadline on stdin (a std-stream) must be rejected, not silently accepted.
fn test_set_deadline_on_stdin_rejects() {
	r := run_dl("[?lib 'cx-stdlib/env' :as env]\n[?lib 'cx-stdlib/net' :as net]\n" +
		'[?let [= \$in [\$env:stdin]] [\$net:set-deadline \$in {read: 500ms}]]\n')
	assert r.output.contains('CXER4522'), 'set-deadline on stdin should reject (CXER4522): ${r.output}'
	assert r.output.contains('std-stream'), 'denial should name the std-stream handle: ${r.output}'
}

// set-opt on a std-stream is likewise rejected (same socket-op rule).
fn test_set_opt_on_stdout_rejects() {
	r := run_dl("[?lib 'cx-stdlib/env' :as env]\n[?lib 'cx-stdlib/net' :as net]\n" +
		'[?let [= \$out [\$env:stdout]] [\$net:set-opt \$out {nodelay: true}]]\n')
	assert r.output.contains('CXER4522'), 'set-opt on stdout should reject (CXER4522): ${r.output}'
}
