module code

import cx
import crypto.sha256
import os

// store_authz_wave2_test.v — W2 security/auth fixes (#179/#201, #195/#212, #184,
// #188, #189, #206). Behavioral: drives svc_handle_request / store_open_impl /
// svc_parse_auth, not symbol names.

fn w2_hash(t string) string {
	return sha256.sum256(t.bytes()).hex()
}

fn w2_req(method string, path string, token string) cx.Element {
	mut hdrs := []cx.Node{}
	if token != '' {
		hdrs << cx.Node(cx.Element{
			name:  'header'
			attrs: [
				cx.Attribute{
					name:  'name'
					value: cx.ScalarValue('Authorization')
				},
				cx.Attribute{
					name:  'value'
					value: cx.ScalarValue('Bearer ${token}')
				},
			]
		})
	}
	return cx.Element{
		name:  'request'
		attrs: [
			cx.Attribute{
				name:  'method'
				value: cx.ScalarValue(method)
			},
			cx.Attribute{
				name:  'path'
				value: cx.ScalarValue(path)
			},
		]
		items: [
			cx.Node(cx.Element{
				name:  'headers'
				items: hdrs
			}),
		]
	}
}

fn w2_status(n cx.Node) int {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'status' {
				return cx.scalar_value_str_public(a.value).int()
			}
		}
	}
	return 0
}

fn w2_body(n cx.Node) string {
	if n is cx.Element {
		for it in n.items {
			if it is cx.Element && it.name == 'body' {
				for b in it.items {
					if b is cx.ScalarNode {
						return csrp_scalar(b)
					}
				}
			}
		}
	}
	return ''
}

// ── #179 tenant-isolation bypass on the sole-store shorthand ──────────────────

fn w2_sole_ctx() ServeContext {
	caps_set_all()
	return ServeContext{
		mounts: {
			'docs': store_open_impl('mem://w2-sole-docs', '', '', false, true, map[string]string{})
		}
		auth:   AuthContext{
			enforce:       true
			static_tokens: [
				StaticToken{
					id:          'w1'
					secret_hash: w2_hash('w1-secret')
					roles:       ['writer']
					tenant:      'othertenant' // does NOT include 'docs'
				},
			]
		}
	}
}

fn test_shorthand_path_enforces_tenant() {
	mut s := new_service_state()
	s.mark_ready()
	ctx := w2_sole_ctx()
	// named path: correctly 403 (tenant othertenant not allowed 'docs')
	named := svc_handle_request(w2_req('POST', '/cx-store/v1/docs/put', 'w1-secret'), mut
		s, ctx)
	assert w2_status(named) == 403, 'named-path disjoint tenant must be 403, got ${w2_status(named)}'
	// shorthand path: MUST also be 403 (was 200 — the bypass, #179)
	short := svc_handle_request(w2_req('POST', '/cx-store/v1/put', 'w1-secret'), mut s,
		ctx)
	assert w2_status(short) == 403, 'shorthand-path disjoint tenant must be 403 (tenant-bypass #179), got ${w2_status(short)}'
}

fn test_shorthand_path_allows_matching_tenant() {
	mut s := new_service_state()
	s.mark_ready()
	caps_set_all()
	ctx := ServeContext{
		mounts: {
			'docs': store_open_impl('mem://w2-sole-ok', '', '', false, true, map[string]string{})
		}
		auth:   AuthContext{
			enforce:       true
			static_tokens: [
				StaticToken{
					id:          'w2'
					secret_hash: w2_hash('w2-secret')
					roles:       ['writer']
					tenant:      'docs'
				},
			]
		}
	}
	short := svc_handle_request(w2_req('POST', '/cx-store/v1/list', 'w2-secret'), mut s,
		ctx)
	assert w2_status(short) == 200, 'matching-tenant shorthand must be 200, got ${w2_status(short)}'
}

// ── #195 object-wire RBAC: writer can objects-put/refs-set, reader can't ───────

fn test_objectwire_rbac_writer_and_reader() {
	// writer needs `write` for objects-put/refs-set; reader needs `read` for
	// objects-have/objects-get/refs — and must NOT get 'admin' (the old bug).
	assert svc_permission_for_op('objects-have') == 'read'
	assert svc_permission_for_op('objects-get') == 'read'
	assert svc_permission_for_op('refs') == 'read'
	assert svc_permission_for_op('objects-put') == 'write'
	assert svc_permission_for_op('refs-set') == 'write'

	writer := Principal{
		id:    'w'
		kind:  'static'
		roles: ['writer']
		tenant: '*'
	}
	// writer can do the whole object-wire push path (incl. the objects-have preflight)
	for op in ['objects-have', 'objects-get', 'refs', 'objects-put', 'refs-set'] {
		if e := svc_authorize(writer, op, 'docs') {
			assert false, 'writer must be allowed ${op}, got ${w2_err_code(e)}'
		}
	}
	reader := Principal{
		id:    'r'
		kind:  'static'
		roles: ['reader']
		tenant: '*'
	}
	// reader can pull (have/get/refs) but not push (put/refs-set)
	for op in ['objects-have', 'objects-get', 'refs'] {
		if e := svc_authorize(reader, op, 'docs') {
			assert false, 'reader must be allowed ${op}, got ${w2_err_code(e)}'
		}
	}
	// svc_authorize returns a value on DENY, none on ALLOW — so a must-deny op
	// must yield a value (the else branch is the failure).
	if _ := svc_authorize(reader, 'objects-put', 'docs') {
		// denied as required
	} else {
		assert false, 'reader must NOT be allowed objects-put'
	}
	if _ := svc_authorize(reader, 'refs-set', 'docs') {
		// denied as required
	} else {
		assert false, 'reader must NOT be allowed refs-set'
	}
}

fn w2_err_code(n cx.Node) string {
	if n is cx.Element && n.name == 'err' {
		for a in n.attrs {
			if a.name == 'code' {
				return cx.scalar_value_str_public(a.value)
			}
		}
	}
	return ''
}

// ── #212 Defect B: a denied op logs the real principal, not "anon" ────────────

fn test_rbac_deny_logs_real_principal() {
	mut s := new_service_state()
	s.mark_ready()
	caps_set_all()
	// a reader trying to write → 403, and meta.role must carry 'reader' (not anon)
	mut meta := RequestMeta{}
	ctx := ServeContext{
		mounts: {
			'docs': store_open_impl('mem://w2-denylog', '', '', false, true, map[string]string{})
		}
		auth:   AuthContext{
			enforce:       true
			static_tokens: [
				StaticToken{
					id:          'r1'
					secret_hash: w2_hash('r1-secret')
					roles:       ['reader']
					tenant:      'docs'
				},
			]
		}
	}
	resp := svc_dispatch_request(w2_req('POST', '/cx-store/v1/docs/put', 'r1-secret'), mut
		s, ctx, mut meta)
	assert w2_status(resp) == 403, 'reader put must be 403'
	assert meta.role == 'reader', 'denied op must log the authenticated role, got "${meta.role}" (#212 Defect B)'
}

// ── #184 encryption fail-closed on substrates that cannot seal ────────────────
// (#229 update: pack/sqlite/s3 now SEAL — see store_pack_encryption_test.v /
// store_sqlite_encryption_test.v / store_s3_encryption_test.v. The fail-closed
// guarantee here is what remains #184's: a substrate with no sealing path, and
// a sealing substrate whose KEK cannot be resolved, must hard-error — never
// silently store plaintext.)

fn test_encryption_failclosed_on_pack_without_kek() {
	caps_set_all()
	// pack now seals (#229), but an unresolvable KEK (no CX_STORE_KEK_<id> env)
	// is still a HARD open error — never a silent ephemeral key or plaintext.
	os.unsetenv('CX_STORE_KEK_w2nokek')
	r := store_open_impl('file:///tmp/w2-enc-pack-${sha256.sum256('x'.bytes()).hex()[..8]}',
		'', '', false, true, {
		'encrypt-key-id': 'w2nokek'
	})
	assert w2_err_code(r) == 'cx-err:CXER1120', 'encrypt-key-id with an absent KEK must fail-closed CXER1120, got ${w2_err_code(r)}'
	assert w2_body_or_msg(r).contains('CX_STORE_KEK_w2nokek'), 'error must name the missing KEK env var'
}

fn test_encryption_failclosed_on_mem() {
	caps_set_all()
	r := store_open_impl('mem://w2-enc-mem', '', '', false, true, {
		'encrypt-key-id': 't1'
	})
	assert w2_err_code(r) == 'cx-err:CXER1100', 'encrypt-key-id on mem must fail-closed, got ${w2_err_code(r)}'
}

fn w2_body_or_msg(n cx.Node) string {
	if n is cx.Element && n.name == 'err' {
		for a in n.attrs {
			if a.name == 'message' {
				return cx.scalar_value_str_public(a.value)
			}
		}
	}
	return ''
}

// ── #188 static-token secret-hash sha256: prefix ──────────────────────────────

fn test_secret_hash_sha256_prefix_accepted() {
	h := w2_hash('ci-secret')
	// the Appendix-A 'sha256:<hex>' form normalizes to the bare digest
	got := svc_normalize_secret_hash('sha256:${h}') or {
		assert false, 'sha256: form must parse: ${err.msg()}'
		return
	}
	assert got == h, 'sha256: prefix must strip to the bare digest'
	// bare hex still accepted
	bare := svc_normalize_secret_hash(h) or {
		assert false, 'bare hex must parse'
		return
	}
	assert bare == h
	// uppercase normalizes
	up := svc_normalize_secret_hash(h.to_upper()) or {
		assert false, 'uppercase hex must parse'
		return
	}
	assert up == h
}

fn test_secret_hash_bad_forms_rejected() {
	if _ := svc_normalize_secret_hash('md5:abcd') {
		assert false, 'unknown algo prefix must reject'
	}
	if _ := svc_normalize_secret_hash('sha256:deadbeef') {
		assert false, 'short digest must reject'
	}
	if _ := svc_normalize_secret_hash('sha256:${'z'.repeat(64)}') {
		assert false, 'non-hex digest must reject'
	}
}

// ── #189 DID methods= filtering ───────────────────────────────────────────────

fn test_did_method_allowed() {
	assert svc_did_method_allowed('did:key:z6Mk', ['key', 'web'])
	assert svc_did_method_allowed('did:web:example.com', ['key', 'web'])
	assert !svc_did_method_allowed('did:web:example.com', ['key']) // web not allowed
	assert !svc_did_method_allowed('did:ethr:0x1', ['key', 'web']) // unknown method
	assert !svc_did_method_allowed('notadid', ['key', 'web'])
}

// ── #206.5 constant-time compare ──────────────────────────────────────────────

fn test_ct_eq() {
	assert svc_ct_eq('abc', 'abc')
	assert !svc_ct_eq('abc', 'abd')
	assert !svc_ct_eq('abc', 'ab') // length differs
	assert svc_ct_eq('', '')
}
