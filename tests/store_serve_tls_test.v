module main

import os
import testenv
import time

// store_serve_tls_test.v — #180: `cx store-serve` with a [tls cert= key=] config
// must actually bind a TLS listener (the cert/key were parsed then discarded, so
// any [tls] config exited(1) with E_NET_TLS_CONFIG). End-to-end: generate a
// self-signed cert, start the daemon with TLS, and assert it binds (no exit(1),
// prints "listening") and answers an HTTPS capabilities probe. Also exercises
// #199 (${env:VAR} key injection). Skips cleanly without openssl/curl.

fn tls_cx_binary() string {
	return testenv.cx_bin()
}

fn tls_pick_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 26720 + int(salt)
}

fn test_store_serve_tls_bind() {
	if os.execute('command -v openssl').exit_code != 0 {
		eprintln('SKIP: openssl not available for TLS bind test')
		return
	}
	if os.execute('command -v curl').exit_code != 0 {
		eprintln('SKIP: curl not available for TLS bind test')
		return
	}
	port := tls_pick_port()
	dir := os.join_path(os.temp_dir(), 'cx_tls_${port}')
	os.mkdir_all(dir) or { panic('mkdir ${dir}: ${err}') }
	defer {
		os.rmdir_all(dir) or {}
	}
	cert := os.join_path(dir, 'tls.crt')
	key := os.join_path(dir, 'tls.key')
	gen := os.execute('openssl req -x509 -newkey rsa:2048 -keyout ${key} -out ${cert} -days 1 -nodes -subj "/CN=127.0.0.1" 2>/dev/null')
	if gen.exit_code != 0 {
		eprintln('SKIP: openssl cert generation failed')
		return
	}
	// #199: inject the key path via ${env:VAR} to also cover env resolution.
	os.setenv('CX_TLS_KEY_PATH', key, true)
	cfg_path := os.join_path(dir, 'svc.cx')
	cfg := '[cxstore-service [bind addr="127.0.0.1:${port}"] [tls cert="${cert}" key="\${env:CX_TLS_KEY_PATH}"] [stores [store name="teststore" url="mem://"]]]'
	os.write_file(cfg_path, cfg) or { panic('write cfg: ${err}') }

	srv_out := os.join_path(dir, 'srv.out')
	// the store-serve subcommand comes FIRST; it parses its own --allow-* flags.
	allow := '--allow-net=127.0.0.1:${port} --allow-read=${dir}'
	pid_s := os.execute('${tls_cx_binary()} store-serve ${allow} --config ${cfg_path} >${srv_out} 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx store-serve')
		return
	}
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(800 * time.millisecond) // let it bind

	srv_log := os.read_file(srv_out) or { '' }
	// the #180 bug: any [tls] config → exit(1) with E_NET_TLS_CONFIG at bind.
	assert !srv_log.contains('E_NET_TLS_CONFIG'), 'TLS bind must not fail with E_NET_TLS_CONFIG (#180); server log: ${srv_log}'
	assert !srv_log.contains('CXER4514'), 'TLS bind must not fail (#180); server log: ${srv_log}'
	assert srv_log.contains('listening on tls://'), 'daemon must report a TLS listener; server log: ${srv_log}'

	// HTTPS capabilities probe (self-signed → -k) must succeed over the TLS wire.
	probe := os.execute('curl -sk --max-time 3 https://127.0.0.1:${port}/cx-store/v1/capabilities')
	assert probe.exit_code == 0, 'HTTPS capabilities probe failed (exit ${probe.exit_code}); server log: ${srv_log}'
	assert probe.output.contains('capabilities'), 'HTTPS probe did not return a capabilities body; got: ${probe.output} | server log: ${srv_log}'
}
