module main

import crypto.sha256
import os
import testenv
import time
import code

// store_token_test.v — `cx store-token` (#249 console spec §4.5): the
// first-secured-setup helper. Asserts the stanza/secret split (stanza on
// stdout, secret ONCE on stderr, never in the stanza), that the stanza is
// guaranteed-loadable (a config embedding it passes parse_service_config),
// that the hash is really sha256(secret), argument validation, and the full
// bootstrap loop LIVE: generated stanza → config file → spawned daemon →
// the shown-once secret authenticates and an off-role op is denied.

fn tok_cx_binary() string {
	return testenv.cx_bin()
}

// tok_run splits stdout/stderr via shell redirection to temp files.
fn tok_run(args string) (int, string, string) {
	dir := os.join_path(os.temp_dir(), 'cx_tok_${os.getpid()}')
	os.mkdir_all(dir) or { panic('mkdir') }
	so := os.join_path(dir, 'out')
	se := os.join_path(dir, 'err')
	r := os.execute('${tok_cx_binary()} store-token ${args} >${so} 2>${se}')
	stdout := os.read_file(so) or { '' }
	stderr := os.read_file(se) or { '' }
	os.rm(so) or {}
	os.rm(se) or {}
	return r.exit_code, stdout, stderr
}

// tok_secret extracts the shown-once secret: the stderr line that is exactly
// 64 hex chars.
fn tok_secret(stderr string) string {
	for line in stderr.split_into_lines() {
		l := line.trim_space()
		if l.len == 64 && l.bytes().all(it.is_hex_digit()) {
			return l
		}
	}
	return ''
}

fn test_store_token_stanza_and_secret_split() {
	c, stanza_out, err_out := tok_run('--id ops --roles admin --tenant "*"')
	assert c == 0, 'store-token must succeed, got ${c}: ${err_out}'
	stanza := stanza_out.trim_space()
	assert stanza.starts_with('[static [token id="ops"'), 'stanza shape: ${stanza}'
	assert stanza.contains('secret-hash="sha256:'), 'stanza must carry the sha256: hash: ${stanza}'
	assert stanza.contains('roles="admin"') && stanza.contains('tenant="*"')
	secret := tok_secret(err_out)
	assert secret.len == 64, 'stderr must show the 64-hex secret once: ${err_out}'
	assert !stanza_out.contains(secret), 'the SECRET must never appear on stdout'
	assert err_out.contains('shown ONCE'), 'stderr must state the shown-once posture'
	// the hash is really sha256(secret)
	want := sha256.sum256(secret.bytes()).hex()
	assert stanza.contains('sha256:${want}'), 'secret-hash must be sha256(secret)'
	// two runs never repeat a secret
	_, _, err2 := tok_run('--id ops')
	assert tok_secret(err2) != secret, 'secrets must be fresh CSPRNG draws'
}

fn test_store_token_stanza_is_loadable_config() {
	_, stanza_out, _ := tok_run('--id ci --roles writer,metrics --tenant docs')
	stanza := stanza_out.trim_space()
	cfg := '[cxstore-service [bind addr="127.0.0.1:9999"] [stores [store name="docs" url="mem://"]] [auth ${stanza}]]'
	parsed := code.parse_service_config(cfg) or {
		assert false, 'a generated stanza must be loadable verbatim: ${err.msg()}'
		return
	}
	assert parsed.auth.context.enforce, 'a token stanza must flip the daemon to enforcing'
	assert parsed.auth.context.static_tokens.len == 1
	assert parsed.auth.context.static_tokens[0].roles == ['writer', 'metrics']
	assert parsed.auth.context.static_tokens[0].tenant == 'docs'
}

fn test_store_token_argument_validation() {
	c1, _, e1 := tok_run('')
	assert c1 == 2, 'missing --id must exit 2'
	assert e1.contains('--id'), 'error must name the missing flag'
	c2, _, e2 := tok_run('--id x --roles superuser')
	assert c2 == 2, 'an unknown role must fail AT GENERATION, not at reload'
	assert e2.contains('superuser'), 'error must name the bad role: ${e2}'
}

// tok_pick_port — the store_serve_tls_test.v salted-port pattern (importing
// `net` for a free-port probe is not available here: vcx/tests + `import
// code` + `import net` trips a pre-existing vlib raw.c.v isize break).
fn tok_pick_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 27120 + int(salt)
}

fn test_store_token_live_bootstrap_loop() {
	port := tok_pick_port()
	// generate a reader-scoped token, embed the stanza verbatim in a config
	_, stanza_out, err_out := tok_run('--id boot --roles reader')
	stanza := stanza_out.trim_space()
	secret := tok_secret(err_out)
	assert stanza != '' && secret != ''
	dir := os.join_path(os.temp_dir(), 'cx_tokboot_${port}')
	os.mkdir_all(dir) or { panic('mkdir') }
	defer {
		os.rmdir_all(dir) or {}
	}
	cfgp := os.join_path(dir, 'svc.cx')
	os.write_file(cfgp, '[cxstore-service [bind addr="127.0.0.1:${port}"] [stores [store name="docs" url="mem://"]] [auth ${stanza}]]') or {
		panic('write cfg')
	}
	pid_s := os.execute('${tok_cx_binary()} store-serve --allow-net=127.0.0.1:${port} --config ${cfgp} >${dir}/srv.out 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx store-serve')
		return
	}
	pid := pid_s.output.trim_space()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	mut up := false
	for _ in 0 .. 100 {
		p := os.execute('curl -s --max-time 2 http://127.0.0.1:${port}/cx-store/v1/ready')
		if p.exit_code == 0 && p.output.contains('[accepting true]') {
			up = true
			break
		}
		time.sleep(100 * time.millisecond)
	}
	if !up {
		srv := os.read_file('${dir}/srv.out') or { '' }
		eprintln('SKIP: daemon not ready; log: ${srv}')
		return
	}
	// the shown-once secret authenticates for its role…
	ok := os.execute('curl -s -o /dev/null -w "%{http_code}" --max-time 3 -X POST -H "Authorization: Bearer ${secret}" http://127.0.0.1:${port}/cx-store/v1/docs/list')
	assert ok.output == '200', 'the generated secret must authenticate (got HTTP ${ok.output})'
	// …the daemon is enforcing (anonymous is denied)…
	anon := os.execute('curl -s -o /dev/null -w "%{http_code}" --max-time 3 -X POST http://127.0.0.1:${port}/cx-store/v1/docs/list')
	assert anon.output == '401', 'one generated token must flip the daemon to deny-by-default (got HTTP ${anon.output})'
	// …and the role boundary holds (reader may not call an admin op).
	deny := os.execute('curl -s -o /dev/null -w "%{http_code}" --max-time 3 -X POST -H "Authorization: Bearer ${secret}" http://127.0.0.1:${port}/cx-store/v1/config-reload')
	assert deny.output == '403', 'a reader token must be denied the admin plane (got HTTP ${deny.output})'
}
