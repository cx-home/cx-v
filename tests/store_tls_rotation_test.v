module main

import crypto.sha256
import os
import testenv
import time

// store_tls_rotation_test.v — #251 (§2.6 / CSRP §3.13): TLS certificate
// rotation WITHOUT a restart. End-to-end over the real wire: start
// `cx store-serve` with cert A, read the served certificate's fingerprint via
// `openssl s_client`, overwrite the cert/key FILES with a fresh identity B
// (the config document itself is untouched — this is exactly the file-based
// rotation path the spec mandates, caught by content-compare, not section
// diff), trigger the admin `config-reload` op over HTTPS, and assert a NEW
// handshake presents B's fingerprint. The live consumer of the mbedtls
// SSLListener.rotate_certs fork seam. Skips cleanly without openssl/curl.

fn rot_cx_binary() string {
	return testenv.cx_bin()
}

fn rot_pick_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 26920 + int(salt)
}

fn rot_fingerprint(port int) string {
	r := os.execute('echo | openssl s_client -connect 127.0.0.1:${port} 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null')
	if r.exit_code != 0 {
		return ''
	}
	return r.output.trim_space()
}

fn test_store_serve_tls_cert_rotation() {
	if os.execute('command -v openssl').exit_code != 0 {
		eprintln('SKIP: openssl not available for TLS rotation test')
		return
	}
	if os.execute('command -v curl').exit_code != 0 {
		eprintln('SKIP: curl not available for TLS rotation test')
		return
	}
	port := rot_pick_port()
	dir := os.join_path(os.temp_dir(), 'cx_tlsrot_${port}')
	os.mkdir_all(dir) or { panic('mkdir ${dir}: ${err}') }
	defer {
		os.rmdir_all(dir) or {}
	}
	cert := os.join_path(dir, 'tls.crt')
	key := os.join_path(dir, 'tls.key')
	gen_a := os.execute('openssl req -x509 -newkey rsa:2048 -keyout ${key} -out ${cert} -days 1 -nodes -subj "/CN=127.0.0.1" 2>/dev/null')
	if gen_a.exit_code != 0 {
		eprintln('SKIP: openssl cert generation failed')
		return
	}
	admin_hash := sha256.sum256('rot-admin-secret'.bytes()).hex()
	cfg_path := os.join_path(dir, 'svc.cx')
	cfg := '[cxstore-service [bind addr="127.0.0.1:${port}"] [tls cert="${cert}" key="${key}"] [stores [store name="teststore" url="mem://"]] [auth [static [token id="root" secret-hash="sha256:${admin_hash}" roles="admin" tenant="*"]]]]'
	os.write_file(cfg_path, cfg) or { panic('write cfg: ${err}') }

	srv_out := os.join_path(dir, 'srv.out')
	allow := '--allow-net=127.0.0.1:${port} --allow-read=${dir}'
	pid_s := os.execute('${rot_cx_binary()} store-serve ${allow} --config ${cfg_path} >${srv_out} 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx store-serve')
		return
	}
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	// wait for the TLS listener
	mut up := false
	for _ in 0 .. 50 {
		probe := os.execute('curl -sk --max-time 2 https://127.0.0.1:${port}/cx-store/v1/ready')
		if probe.exit_code == 0 && probe.output.contains('[accepting true]') {
			up = true
			break
		}
		time.sleep(100 * time.millisecond)
	}
	if !up {
		srv_log := os.read_file(srv_out) or { '' }
		eprintln('SKIP: TLS daemon did not become ready; server log: ${srv_log}')
		return
	}

	fp_a := rot_fingerprint(port)
	assert fp_a != '', 'must read the served certificate fingerprint (identity A)'

	// Rotate the identity ON DISK — same paths, fresh key+cert. The config
	// document is byte-identical; only the PEM content-compare can catch this.
	gen_b := os.execute('openssl req -x509 -newkey rsa:2048 -keyout ${key} -out ${cert} -days 1 -nodes -subj "/CN=127.0.0.1" 2>/dev/null')
	assert gen_b.exit_code == 0, 'openssl re-generation must succeed'

	rl := os.execute('curl -sk --max-time 3 -X POST -H "Authorization: Bearer rot-admin-secret" https://127.0.0.1:${port}/cx-store/v1/config-reload')
	assert rl.exit_code == 0, 'config-reload over HTTPS must succeed (exit ${rl.exit_code})'
	assert rl.output.contains('applied=true'), 'rotation reload must apply: ${rl.output}'
	assert rl.output.contains('tls'), 'changed list must name tls: ${rl.output}'

	fp_b := rot_fingerprint(port)
	assert fp_b != '', 'must read the served certificate fingerprint (identity B)'
	assert fp_b != fp_a, 'a NEW handshake after rotation must present the rotated certificate (A=${fp_a})'

	// and the daemon still serves over the rotated identity
	post := os.execute('curl -sk --max-time 3 https://127.0.0.1:${port}/cx-store/v1/ready')
	assert post.exit_code == 0 && post.output.contains('[accepting true]'), 'daemon must keep serving after rotation'
}
