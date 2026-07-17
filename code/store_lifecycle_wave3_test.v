module code

import cx
import os

// store_lifecycle_wave3_test.v — W3 lifecycle fixes (#183 cxobj open, #180/#199
// TLS+env config, #181 watchdog, #186/#211 drain, #187 read-timeout, #219 framing).
// Behavioral: drives store_open_impl / parse_service_config / the drain path.

// ── #183: a FRESH cxobj store opens via the public [$store:open] path ─────────

fn test_cxobj_fresh_open_via_public_path() {
	caps_set_all()
	root := os.join_path(os.temp_dir(), 'w3_cxobj_${os.getpid()}')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	// fresh open — previously tripped the partial-store guard (objects/ dir created
	// by the backend attach before the presence check).
	h := store_open_impl('file://${root}?encoding=object-per-key', '', '', false, true,
		map[string]string{})
	assert w3_err_code(h) == '', 'fresh cxobj open must succeed, got ${w3_err_code(h)}: ${w3_err_msg(h)}'
	// put → get round-trips
	sk := store_stdlib_builtin_inner('store-put-doc-text', [h, store_str('[doc [x 1]]')]) or {
		panic('put: ${err.msg()}')
	}
	sks := cx.scalar_value_str_public((sk as cx.ScalarNode).value)
	got := store_stdlib_builtin_inner('store-get-doc-text', [h, store_str(sks)]) or {
		panic('get: ${err.msg()}')
	}
	assert cx.scalar_value_str_public((got as cx.ScalarNode).value) == '[doc [x 1]]', 'cxobj round-trip'
	// reopen the now-populated store
	h2 := store_open_impl('file://${root}?encoding=object-per-key', '', '', false, true,
		map[string]string{})
	assert w3_err_code(h2) == '', 'cxobj reopen must succeed, got ${w3_err_code(h2)}'
	got2 := store_stdlib_builtin_inner('store-get-doc-text', [h2, store_str(sks)]) or {
		panic('get2: ${err.msg()}')
	}
	assert cx.scalar_value_str_public((got2 as cx.ScalarNode).value) == '[doc [x 1]]', 'cxobj reopen round-trip'
}

fn test_cxobj_encrypted_fresh_open() {
	caps_set_all()
	os.setenv('CX_STORE_KEK_w3k', 'a'.repeat(64), true)
	root := os.join_path(os.temp_dir(), 'w3_cxobj_enc_${os.getpid()}')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	// #183 + #184: encryption-at-rest is reachable now that cxobj opens.
	h := store_open_impl('file://${root}?encoding=object-per-key', '', '', false, true, {
		'encrypt-key-id': 'w3k'
	})
	assert w3_err_code(h) == '', 'encrypted cxobj open must succeed, got ${w3_err_code(h)}: ${w3_err_msg(h)}'
	sk := store_stdlib_builtin_inner('store-put-doc-text', [h, store_str('[secret [v "PLAINTEXTPROBE"]]')]) or {
		panic('put: ${err.msg()}')
	}
	sks := cx.scalar_value_str_public((sk as cx.ScalarNode).value)
	// the object files on disk must NOT contain the plaintext (sealed at rest).
	mut found_plain := false
	objdir := os.join_path(root, 'objects')
	if os.exists(objdir) {
		for sh in (os.ls(objdir) or { [] }) {
			sub := os.join_path(objdir, sh)
			if !os.is_dir(sub) {
				continue
			}
			for f in (os.ls(sub) or { [] }) {
				blob := os.read_bytes(os.join_path(sub, f)) or { continue }
				if blob.bytestr().contains('PLAINTEXTPROBE') {
					found_plain = true
				}
			}
		}
	}
	assert !found_plain, 'encrypted cxobj must NOT store plaintext on disk'
	// and it round-trips (decrypt)
	got := store_stdlib_builtin_inner('store-get-doc-text', [h, store_str(sks)]) or {
		panic('get: ${err.msg()}')
	}
	assert cx.scalar_value_str_public((got as cx.ScalarNode).value).contains('PLAINTEXTPROBE'), 'encrypted cxobj must decrypt on read'
}

// ── #180 / #199: TLS + env-var config ─────────────────────────────────────────

fn test_config_tls_parses_cert_key_ca() {
	c := parse_service_config('[cxstore-service [bind addr="h:1"] [tls cert="/etc/c.pem" key="/etc/k.pem" ca="/etc/ca.pem"] [stores [store name="s" url="mem://s"]]]') or {
		panic('tls config rejected: ${err}')
	}
	t := c.tls or {
		assert false, 'tls config must be present'
		return
	}
	assert t.cert == '/etc/c.pem'
	assert t.key == '/etc/k.pem'
	assert t.ca == '/etc/ca.pem'
}

fn test_config_env_var_resolution() {
	os.setenv('W3_TLS_KEY_PEM', '-----BEGIN PRIVATE KEY-----\nMII...\n-----END PRIVATE KEY-----', true)
	c := parse_service_config('[cxstore-service [bind addr="h:1"] [tls cert="/etc/c.pem" key="\${env:W3_TLS_KEY_PEM}"] [stores [store name="s" url="mem://s"]]]') or {
		panic('env config rejected: ${err}')
	}
	t := c.tls or {
		assert false, 'tls present'
		return
	}
	assert t.key.contains('BEGIN PRIVATE KEY'), 'env-injected key PEM must resolve'
}

fn test_config_env_var_unset_fails_fast() {
	if _ := parse_service_config('[cxstore-service [bind addr="h:1"] [tls cert="/etc/c.pem" key="\${env:W3_DEFINITELY_UNSET_VAR}"] [stores [store name="s" url="mem://s"]]]') {
		assert false, 'a referenced-but-unset env var must fail config parse'
	}
}

fn test_svc_load_pem_content_vs_path() {
	// PEM content passes through verbatim
	pem := '-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----'
	got := svc_load_pem(pem) or {
		assert false, 'PEM content must load: ${err.msg()}'
		return
	}
	assert got == pem
	// a missing path fails fast
	if _ := svc_load_pem('/nonexistent/path/${os.getpid()}.pem') {
		assert false, 'a missing PEM file path must fail'
	}
}

// ── #187 / #219: read-timeout config + framing ────────────────────────────────

fn test_config_read_timeout() {
	c := parse_service_config('[cxstore-service [bind addr="h:1"] [timeouts read-ms=5000] [stores [store name="s" url="mem://s"]]]') or {
		panic('timeouts config rejected: ${err}')
	}
	assert c.read_timeout_ms == 5000
	// default when omitted
	c2 := parse_service_config('[cxstore-service [bind addr="h:1"] [stores [store name="s" url="mem://s"]]]') or {
		panic('config rejected: ${err}')
	}
	assert c2.read_timeout_ms == 30000, 'default read timeout is 30s'
}

// ── #186 drain_complete is the live in-flight probe ───────────────────────────

fn test_drain_complete_bounded_semantics() {
	mut s := new_service_state()
	s.mark_ready()
	// not draining → drain_complete false
	assert !s.drain_complete(false)
	s.begin_drain()
	// draining, no in-flight → complete
	assert s.drain_complete(false)
	// draining, deadline reached → complete regardless
	assert s.drain_complete(true)
}

fn w3_err_code(n cx.Node) string {
	if n is cx.Element && n.name == 'err' {
		for a in n.attrs {
			if a.name == 'code' {
				return cx.scalar_value_str_public(a.value)
			}
		}
	}
	return ''
}

fn w3_err_msg(n cx.Node) string {
	if n is cx.Element && n.name == 'err' {
		for a in n.attrs {
			if a.name == 'message' {
				return cx.scalar_value_str_public(a.value)
			}
		}
	}
	return ''
}
