module main

import os

// net_cap_outbound_test.v — #47: `--allow-all` (the grant-EVERYTHING
// opt-out) permits OUTBOUND to ANY host, loopback/private included — it
// bypasses the §4.5 deny-set. A bare `--allow-net` does NOT: the deny-set is
// the secure default for any net grant absent a literal-IP scope, so a private
// target stays denied (CXER4504) unless scoped (--allow-net=127.0.0.1) or
// granted via --allow-all. (Before the fix, --allow-all wrongly forbade
// loopback — it carries no scope spec, so the deny-set's override had nothing
// to match.)
//
// Dials a closed loopback port: bypassing the deny-set reaches the CONNECT
// stage (CXER4506); the deny-set forbids it (CXER4504).

fn cx_bin_net() string {
	return os.join_path(@VMODROOT, 'target', 'cx')
}

fn dial_loopback_prog() string {
	path := os.join_path(os.temp_dir(), 'cx_net47_${os.getpid()}.cx')
	os.write_file(path, "[?lib 'cx-stdlib/net' :as net]\n[\$net:dial \"tcp://127.0.0.1:9\" {}]\n") or {
		panic(err)
	}
	return path
}

// --allow-all must reach loopback (connect error, not a forbidden-address denial).
fn test_allow_all_permits_outbound_loopback() {
	prog := dial_loopback_prog()
	defer { os.rm(prog) or {} }
	r := os.execute('${cx_bin_net()} --allow-all ${prog}')
	assert !r.output.contains('CXER4504'), '--allow-all wrongly SSRF-forbade loopback: ${r.output}'
	assert !r.output.contains('CXER0271'), '--allow-all wrongly cap-denied loopback: ${r.output}'
	assert r.output.contains('CXER4506') || r.output.contains('connect'),
		'--allow-all should reach the connect stage: ${r.output}'
}

// The "adding --allow-all breaks it" combo (#47): a scoped grant PLUS --allow-all
// must still reach loopback (--allow-all wins, bypassing the deny-set).
fn test_scoped_plus_allow_all_reaches_loopback() {
	prog := dial_loopback_prog()
	defer { os.rm(prog) or {} }
	r := os.execute('${cx_bin_net()} --allow-net=127.0.0.1:9 --allow-all ${prog}')
	assert !r.output.contains('CXER4504'), 'scoped + --allow-all wrongly forbade loopback: ${r.output}'
	assert r.output.contains('CXER4506') || r.output.contains('connect'),
		'scoped + --allow-all should reach the connect stage: ${r.output}'
}

// Bare --allow-net keeps the §4.5 deny-set — a private/loopback target is
// FORBIDDEN (CXER4504) without a literal-IP scope. (Preserves the secure
// default; matches test_net_ssrf_dial_guard.)
fn test_bare_allow_net_keeps_deny_set() {
	prog := dial_loopback_prog()
	defer { os.rm(prog) or {} }
	r := os.execute('${cx_bin_net()} --allow-net ${prog}')
	assert r.output.contains('CXER4504'),
		'bare --allow-net must keep the deny-set (loopback forbidden, CXER4504): ${r.output}'
}

// A literal-IP scope reaches the loopback target it names (override) — connect
// stage, not forbidden.
fn test_scoped_literal_ip_reaches_loopback() {
	prog := dial_loopback_prog()
	defer { os.rm(prog) or {} }
	r := os.execute('${cx_bin_net()} --allow-net=127.0.0.1:9 ${prog}')
	assert !r.output.contains('CXER4504'), 'literal-IP scope must override the deny-set: ${r.output}'
	assert r.output.contains('CXER4506') || r.output.contains('connect'),
		'literal-IP scope should reach the connect stage: ${r.output}'
}

// A SCOPED public-host grant must NOT reach loopback (scope/rebinding defense).
fn test_scoped_public_host_still_blocks_loopback() {
	prog := dial_loopback_prog()
	defer { os.rm(prog) or {} }
	r := os.execute('${cx_bin_net()} --allow-net=example.com ${prog}')
	assert !r.output.contains('CXER4506'), 'public-host scope wrongly reached loopback: ${r.output}'
	assert r.output.contains('CXER0271') || r.output.contains('CXER4504'),
		'public-host scope dialing loopback must be denied/forbidden: ${r.output}'
}
