module code

import cx
import crypto.sha256
import crypto.ed25519
import encoding.base58
import encoding.base64

// #105 authZ step 2a — static-token auth + RBAC + tenant scoping (pure logic).

fn tok_hash(t string) string {
	return sha256.sum256(t.bytes()).hex()
}

fn req_with_auth(token string) cx.Element {
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
				value: cx.ScalarValue('POST')
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

fn sample_ctx() AuthContext {
	return AuthContext{
		enforce:       true
		static_tokens: [
			StaticToken{
				id:          'alice'
				secret_hash: tok_hash('alice-secret')
				roles:       ['writer']
				tenant:      'docs'
			},
			StaticToken{
				id:          'bob'
				secret_hash: tok_hash('bob-secret')
				roles:       ['reader']
				tenant:      'code'
			},
			StaticToken{
				id:          'root'
				secret_hash: tok_hash('root-secret')
				roles:       ['admin']
				tenant:      '*'
			},
		]
	}
}

// ── authentication ───────────────────────────────────────────────────────────

fn test_authenticate_valid_static_token() {
	p := svc_authenticate(req_with_auth('alice-secret'), sample_ctx())
	assert p.kind == 'static'
	assert p.id == 'alice'
	assert p.roles == ['writer']
	assert p.tenant == 'docs'
}

fn test_authenticate_no_token_is_anonymous() {
	p := svc_authenticate(req_with_auth(''), sample_ctx())
	assert p.kind == 'anonymous'
}

fn test_authenticate_forged_token_is_anonymous() {
	p := svc_authenticate(req_with_auth('not-a-real-token'), sample_ctx())
	assert p.kind == 'anonymous', 'a token not matching any secret-hash must not authenticate'
}

// ── RBAC ───────────────────────────────────────────────────────────────────

fn test_reader_cannot_write() {
	bob := svc_authenticate(req_with_auth('bob-secret'), sample_ctx())
	// bob (reader) → put (write) denied
	if e := svc_authorize(bob, 'put', 'code') {
		assert svc_err_text(e).contains('CXER1703')
	} else {
		assert false, 'reader must be denied write'
	}
	// bob → get (read) on his tenant: allowed
	if _ := svc_authorize(bob, 'get', 'code') {
		assert false, 'reader must be allowed read on own tenant'
	}
}

fn test_writer_can_write_and_read() {
	alice := svc_authenticate(req_with_auth('alice-secret'), sample_ctx())
	if _ := svc_authorize(alice, 'put', 'docs') {
		assert false, 'writer must be allowed write'
	}
	if _ := svc_authorize(alice, 'get', 'docs') {
		assert false, 'writer must be allowed read'
	}
	// writer cannot delete (no delete permission)
	if e := svc_authorize(alice, 'delete', 'docs') {
		assert svc_err_text(e).contains('CXER1703')
	} else {
		assert false, 'writer must be denied delete'
	}
}

fn test_admin_all_permissions() {
	root := svc_authenticate(req_with_auth('root-secret'), sample_ctx())
	for op in ['get', 'put', 'delete'] {
		if _ := svc_authorize(root, op, 'docs') {
			assert false, 'admin must be allowed ${op}'
		}
	}
}

fn test_anonymous_denied_data_op() {
	anon := svc_authenticate(req_with_auth(''), sample_ctx())
	if e := svc_authorize(anon, 'get', 'docs') {
		assert svc_err_text(e).contains('CXER1702'), 'anonymous data op → auth required'
	} else {
		assert false, 'anonymous must be denied data ops'
	}
}

// ── tenant scoping (the isolation enforcement) ───────────────────────────────

fn test_tenant_cannot_cross_to_other_store() {
	alice := svc_authenticate(req_with_auth('alice-secret'), sample_ctx())
	// alice is tenant `docs`; reaching `code` must be forbidden even though she
	// has the write permission.
	if e := svc_authorize(alice, 'put', 'code') {
		assert svc_err_text(e).contains('CXER1703')
	} else {
		assert false, 'tenant docs must not reach store code'
	}
	// her own store is fine
	if _ := svc_authorize(alice, 'put', 'docs') {
		assert false, 'tenant docs must reach store docs'
	}
}

fn test_wildcard_tenant_reaches_any_store() {
	root := svc_authenticate(req_with_auth('root-secret'), sample_ctx())
	for store in ['docs', 'code', 'anything'] {
		if _ := svc_authorize(root, 'get', store) {
			assert false, 'wildcard tenant must reach ${store}'
		}
	}
}

fn test_tenant_allows_helper() {
	assert svc_tenant_allows('*', 'anything')
	assert svc_tenant_allows('docs code', 'code')
	assert svc_tenant_allows('docs', 'docs')
	assert !svc_tenant_allows('docs', 'code')
	assert !svc_tenant_allows('', 'docs') // empty spec → no access
}

fn test_permission_for_op_mapping() {
	assert svc_permission_for_op('get') == 'read'
	assert svc_permission_for_op('query') == 'read'
	assert svc_permission_for_op('put') == 'write'
	assert svc_permission_for_op('delete') == 'delete'
	assert svc_permission_for_op('compact') == 'admin' // unknown → admin (deny-by-default)
}

// ── JWT provider (step 2a brick B) — signed test vectors from crypto.cxd ─────

const test_jwks = '{"keys":[{"kid":"rsa-1","kty":"RSA","alg":"RS256","n":"jdwwBcaMZQLoSNYGNEm3l03HIQqpRIv0eqLUNUCkyv7ysVw4i6vZgdYxcdU0D3kSvUCIjH-icqk4PCDx5AwkeNp55Nqt6wKXDv9TH5pr-Wc3BWmZ1sEOEwyN8QlI8_5EpY3i1w5tysDdeFuiR7BOjpkD49RZzF0YajmocsB4_jXoZcldVNCOChXAbEfOw-BtjFJRN0N3EksymF4azkey8Q3rX07sXkRHavRfAOnowH119RL1V-Xmk_DUX8wSR-2zdlp8FxitJWPgbMmnszsTgEQrThTwsuMrndqzJ_nQ7HTnuK2LXEFmFwXw9NADspq2ZnQmZiN7CXnEYG8WCApzxw","e":"AQAB"},{"kid":"ec-1","kty":"EC","crv":"P-256","alg":"ES256","x":"l9ScLzJ2g8ZHlc4zx6jqkLbrw9NB_j7ORJ2HTQBgGeQ","y":"spBDqXfgXOdqDGs4_WenZEmRFmy71qts1dMEp8xrg6M"},{"kid":"ed-1","kty":"OKP","crv":"Ed25519","alg":"EdDSA","x":"W7aFRt4kKu7VuwPv6oBWPpxSwy9jCzk2QqawxURsnsk"}]}'

const eddsa_token = 'eyJhbGciOiJFZERTQSIsImtpZCI6ImVkLTEifQ.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoidXNlci0xIiwiYXVkIjoibXktYXBpIiwiZXhwIjoxNzAwMDAzNjAwLCJuYmYiOjE2OTk5OTk5OTAsImlhdCI6MTY5OTk5OTk5MH0.hbWfK_3KgwQ86Fw12wZdQrTDdQA_9YoG9fDmsyEj9cp4y9592OnzJ7fCKebr1LgH0IHanrhW66I4ZRDuC3qUAw'

fn jwt_now(y i64, mo i64, d i64) cx.Node {
	return time_datetime_node(TDateTime{ year: y, month: mo, day: d, hour: 22, minute: 13, second: 20 }.datetime_string())
}

fn jwt_provider() JwtProvider {
	return JwtProvider{
		enabled:      true
		jwks:         crypto_jwks_parse(test_jwks)
		issuer:       'https://idp.example'
		audience:     'my-api'
		roles_claim:  'roles'
		tenant_claim: 'tenant'
	}
}

fn test_jwt_valid_vector_authenticates() {
	p := svc_jwt_authenticate(eddsa_token, jwt_provider(), jwt_now(2023, 11, 14)) or {
		panic('valid EdDSA JWT rejected')
	}
	assert p.kind == 'jwt'
	assert p.id == 'user-1'
	// vector carries no roles/tenant claims → empty (a token must carry them to act)
	assert p.roles.len == 0
}

fn test_jwt_expired_rejected() {
	// `now` well after exp (1700003600) → expired → none
	if _ := svc_jwt_authenticate(eddsa_token, jwt_provider(), jwt_now(2024, 6, 1)) {
		assert false, 'expired JWT must be rejected'
	}
}

fn test_jwt_bad_signature_rejected() {
	tampered := eddsa_token[..eddsa_token.len - 4] + 'AAAA'
	if _ := svc_jwt_authenticate(tampered, jwt_provider(), jwt_now(2023, 11, 14)) {
		assert false, 'tampered-signature JWT must be rejected'
	}
}

fn test_jwt_wrong_issuer_rejected() {
	mut jp := jwt_provider()
	jp = JwtProvider{
		...jp
		issuer: 'https://evil.example'
	}
	if _ := svc_jwt_authenticate(eddsa_token, jp, jwt_now(2023, 11, 14)) {
		assert false, 'wrong-issuer JWT must be rejected'
	}
}

fn test_jwt_wrong_audience_rejected() {
	mut jp := jwt_provider()
	jp = JwtProvider{
		...jp
		audience: 'other-api'
	}
	if _ := svc_jwt_authenticate(eddsa_token, jp, jwt_now(2023, 11, 14)) {
		assert false, 'wrong-audience JWT must be rejected'
	}
}

fn test_jwt_disabled_provider_returns_none() {
	if _ := svc_jwt_authenticate(eddsa_token, JwtProvider{ enabled: false }, jwt_now(2023, 11, 14)) {
		assert false, 'disabled JWT provider must return none'
	}
}

// ── DID provider (step 2a brick C1 — did:key, offline, network-free) ─────────

fn b64u(b []u8) string {
	return base64.url_encode(b).trim_right('=')
}

// did_key_for derives the did:key string for an Ed25519 public key.
fn did_key_for(pubk []u8) string {
	mut prefixed := [u8(0xed), u8(0x01)]
	prefixed << pubk
	return 'did:key:z' + base58.encode_bytes(prefixed).bytestr()
}

// sign_did_jwt builds an EdDSA DID-JWT with the given iss, signed by `priv`.
fn sign_did_jwt(iss string, priv ed25519.PrivateKey, exp i64) string {
	header := '{"alg":"EdDSA","typ":"JWT"}'
	payload := '{"iss":"${iss}","sub":"${iss}","exp":${exp},"iat":1700000000}'
	si := b64u(header.bytes()) + '.' + b64u(payload.bytes())
	sig := priv.sign(si.bytes()) or { panic(err) }
	return si + '.' + b64u(sig)
}

fn did_provider_for(did string, roles string, tenant string) DidProvider {
	return DidProvider{
		enabled: true
		grants:  [DidGrant{
			did:    did
			roles:  roles.fields()
			tenant: tenant
		}]
	}
}

fn test_did_jwt_valid_authenticates() {
	pubk, priv := ed25519.generate_key() or { panic(err) }
	did := did_key_for(pubk)
	token := sign_did_jwt(did, priv, 9999999999)
	p := svc_did_authenticate(token, did_provider_for(did, 'reader', 'docs'), svc_now_node()) or {
		panic('valid did:key JWT rejected')
	}
	assert p.kind == 'did'
	assert p.id == did
	assert p.roles == ['reader']
	assert p.tenant == 'docs'
}

fn test_did_without_grant_denied() {
	pubk, priv := ed25519.generate_key() or { panic(err) }
	did := did_key_for(pubk)
	token := sign_did_jwt(did, priv, 9999999999)
	// provider grants a DIFFERENT did → this verified DID has no authority.
	// #207.6: an authenticated-but-ungranted DID now yields an EMPTY-ROLES
	// principal (kind='did'), so the RBAC check denies it with 403 CXER1703 —
	// NOT `none` → anonymous → 401 (matching JWT/OIDC empty-roles semantics).
	p := svc_did_authenticate(token, did_provider_for('did:key:zSomeoneElse', 'admin',
		'*'), svc_now_node()) or {
		assert false, 'a verified DID must authenticate as a principal even without a grant (#207.6)'
		return
	}
	assert p.kind == 'did', 'ungranted DID principal kind=did'
	assert p.roles.len == 0, 'ungranted DID has no roles'
	// and the authorization check denies it with 403, not 401
	if e := svc_authorize(p, 'get', 'docs') {
		assert svc_err_code(e) == 'cx-err:CXER1703', 'ungranted DID op → 403 CXER1703, got ${svc_err_code(e)}'
	} else {
		assert false, 'ungranted DID must be denied'
	}
}

fn test_did_jwt_tampered_rejected() {
	pubk, priv := ed25519.generate_key() or { panic(err) }
	did := did_key_for(pubk)
	token := sign_did_jwt(did, priv, 9999999999)
	tampered := token[..token.len - 4] + 'AAAA'
	if _ := svc_did_authenticate(tampered, did_provider_for(did, 'reader', 'docs'), svc_now_node()) {
		assert false, 'tampered DID-JWT must be rejected'
	}
}

fn test_did_jwt_key_mismatch_rejected() {
	// token claims iss = did_b but is signed by key A → B's key won't verify it.
	pub_a, priv_a := ed25519.generate_key() or { panic(err) }
	pub_b, _ := ed25519.generate_key() or { panic(err) }
	did_a := did_key_for(pub_a)
	did_b := did_key_for(pub_b)
	assert did_a != did_b
	forged := sign_did_jwt(did_b, priv_a, 9999999999) // iss=B, signed by A
	if _ := svc_did_authenticate(forged, did_provider_for(did_b, 'admin', '*'), svc_now_node()) {
		assert false, 'a DID-JWT signed by the wrong key must be rejected'
	}
}

fn test_did_jwt_expired_rejected() {
	pubk, priv := ed25519.generate_key() or { panic(err) }
	did := did_key_for(pubk)
	token := sign_did_jwt(did, priv, 1700000000) // exp in 2023 → past
	if _ := svc_did_authenticate(token, did_provider_for(did, 'reader', 'docs'), svc_now_node()) {
		assert false, 'expired DID-JWT must be rejected'
	}
}

fn test_did_disabled_provider_none() {
	pubk, priv := ed25519.generate_key() or { panic(err) }
	did := did_key_for(pubk)
	token := sign_did_jwt(did, priv, 9999999999)
	if _ := svc_did_authenticate(token, DidProvider{ enabled: false }, svc_now_node()) {
		assert false, 'disabled DID provider must return none'
	}
}

// ── did:web key-extraction + resolver cache (brick C2, offline) ──────────────
// The live HTTPS resolution path (did_web_resolve) is network → smoke-verified;
// here we unit-test the key-extraction from a synthetic DID Document + the cache.

fn cxmap1(key string, val cx.Node) cx.Node {
	return cx.Node(cx.Element{
		name:  '__cx_map__'
		items: [cx.Node(cx.Element{
			name:  key
			items: [val]
		})]
	})
}

fn synth_did_doc(vm cx.Node) cx.Node {
	vmarr := cx.Node(cx.Element{
		name:  '__cx_arr__'
		items: [vm]
	})
	source := cxmap1('verificationMethod', vmarr)
	return cx.Node(cx.Element{
		name:  'did-document'
		items: [cx.Node(cx.Element{
			name:  'source'
			items: [source]
		})]
	})
}

fn test_did_web_extract_multibase_verifies() {
	pubk, priv := ed25519.generate_key() or { panic(err) }
	mut prefixed := [u8(0xed), u8(0x01)]
	prefixed << pubk
	mb := 'z' + base58.encode_bytes(prefixed).bytestr()
	vm := cxmap1('publicKeyMultibase', crypto_string_node(mb))
	jwk := svc_did_doc_extract_jwk(synth_did_doc(vm)) or { panic('multibase extract failed') }
	// the extracted key must verify a JWS signed by the matching private key
	token := sign_did_jwt('did:web:example.com', priv, 9999999999)
	claims := crypto_jwt_verify([crypto_string_node(token), jwk, svc_now_node(), cx.Node(cx.Element{ name: '__cx_map__' })])
	assert !is_err_value(claims), 'multibase-extracted key must verify the JWS'
}

fn test_did_web_extract_jwk_verifies() {
	pubk, priv := ed25519.generate_key() or { panic(err) }
	x := b64u(pubk)
	jwk_map := cx.Node(cx.Element{
		name:  '__cx_map__'
		items: [
			cx.Node(cx.Element{
				name:  'kty'
				items: [crypto_string_node('OKP')]
			}),
			cx.Node(cx.Element{
				name:  'crv'
				items: [crypto_string_node('Ed25519')]
			}),
			cx.Node(cx.Element{
				name:  'x'
				items: [crypto_string_node(x)]
			}),
		]
	})
	vm := cxmap1('publicKeyJwk', jwk_map)
	jwk := svc_did_doc_extract_jwk(synth_did_doc(vm)) or { panic('publicKeyJwk extract failed') }
	token := sign_did_jwt('did:web:example.com', priv, 9999999999)
	claims := crypto_jwt_verify([crypto_string_node(token), jwk, svc_now_node(), cx.Node(cx.Element{ name: '__cx_map__' })])
	assert !is_err_value(claims), 'publicKeyJwk key must verify the JWS'
}

fn test_did_web_extract_non_ed25519_rejected() {
	jwk_map := cx.Node(cx.Element{
		name:  '__cx_map__'
		items: [
			cx.Node(cx.Element{
				name:  'crv'
				items: [crypto_string_node('P-256')]
			}),
			cx.Node(cx.Element{
				name:  'x'
				items: [crypto_string_node('abc')]
			}),
		]
	})
	vm := cxmap1('publicKeyJwk', jwk_map)
	if _ := svc_did_doc_extract_jwk(synth_did_doc(vm)) {
		assert false, 'a non-Ed25519 verification method must not yield an OKP key'
	}
}

fn test_did_resolver_cache_ttl() {
	mut c := new_key_cache()
	jwk := svc_okp_jwks('W7aFRt4kKu7VuwPv6oBWPpxSwy9jCzk2QqawxURsnsk')
	c.put('did:web:x', jwk, 1000) // expires at 1000ns
	if _ := c.get('did:web:x', 500) {} else {
		assert false, 'cache hit expected before expiry'
	}
	if _ := c.get('did:web:x', 1500) {
		assert false, 'cache must miss after expiry'
	}
	if _ := c.get('did:web:absent', 0) {
		assert false, 'absent key → none'
	}
}

// ── OIDC provider (brick D) — verify with cache-injected JWKS (offline) ──────
// The discovery + JWKS fetch is network → smoke-verified. Here the issuer's
// JWKS is pre-seeded into the cache, so the OIDC verify path runs offline.

fn oidc_provider_seeded() OidcProvider {
	mut cache := new_key_cache()
	cache.put('https://idp.example', crypto_jwks_parse(test_jwks), 9_000_000_000_000_000_000)
	return OidcProvider{
		enabled:        true
		issuer:         'https://idp.example'
		audience:       'my-api'
		roles_claim:    'roles'
		tenant_claim:   'tenant'
		cache_ttl_secs: 300
		cache:          cache
	}
}

fn test_oidc_verifies_with_cached_jwks() {
	p := svc_oidc_authenticate(eddsa_token, oidc_provider_seeded(), jwt_now(2023, 11, 14)) or {
		panic('OIDC verify with cached JWKS failed')
	}
	assert p.kind == 'oidc'
	assert p.id == 'user-1'
}

fn test_oidc_expired_rejected() {
	if _ := svc_oidc_authenticate(eddsa_token, oidc_provider_seeded(), jwt_now(2024, 6, 1)) {
		assert false, 'expired OIDC token must be rejected'
	}
}

fn test_oidc_wrong_audience_rejected() {
	mut op := oidc_provider_seeded()
	op = OidcProvider{
		...op
		audience: 'other-api'
	}
	if _ := svc_oidc_authenticate(eddsa_token, op, jwt_now(2023, 11, 14)) {
		assert false, 'OIDC token with wrong audience must be rejected'
	}
}

fn test_oidc_disabled_none() {
	if _ := svc_oidc_authenticate(eddsa_token, OidcProvider{ enabled: false }, jwt_now(2023, 11, 14)) {
		assert false, 'disabled OIDC provider must return none'
	}
}
