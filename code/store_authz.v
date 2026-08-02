module code

import cx
import crypto.sha256
import encoding.base64
import encoding.base58
import sync
import time

// #105 Phase-2 authZ (step 2a). The authentication + authorization logic for the
// cxstore service daemon — pure functions over a request + an AuthContext,
// integrated into svc_handle_request (store_service.v) at the marked point.
//
// Model (spec cxstore_service_tier_phase2.md §3, App C):
//   - A credential (Bearer token) → a Principal{id, kind, roles, tenant}.
//   - RBAC: each CSRP op needs a permission (read/write/delete/admin/metrics);
//     a role bundles permissions; deny-by-default → 403 CXER1703.
//   - Tenant store-scoping (4a): the principal's tenant must allow the target
//     store-name, else 403 — this is the tenant-isolation enforcement.
// Providers ship in order static → JWT → DID → OIDC; this file lands STATIC +
// the shared RBAC/tenant core. The later providers add cases to svc_authenticate.

const e_csrp_forbidden = 'cx-err:CXER1703' // E_CSRP_FORBIDDEN (authenticated, lacks permission/tenant)
const e_csrp_auth_required = 'cx-err:CXER1702' // E_CSRP_AUTH_REQUIRED (no/!valid credential)

// Principal is the authenticated identity for a request.
pub struct Principal {
pub:
	id     string // token id / sub / DID
	kind   string // 'static' | 'jwt' | 'did' | 'oidc' | 'anonymous'
	roles  []string
	tenant string // space-separated allowed store-names; '*' = all; '' = none
}

// StaticToken is a config-listed bearer token (hashed at rest) → roles + tenant.
pub struct StaticToken {
pub:
	id          string
	secret_hash string // lowercase hex SHA-256 of the bearer token
	roles       []string
	tenant      string
}

// JwtProvider verifies issuer-signed JWTs against a configured JWKS (asymmetric
// RS*/ES256/EdDSA — CX's fail-closed crypto_jwt_verify). Principal = the `sub`;
// roles + tenant come from configurable claims (the §9 mapping convention:
// `roles-claim` default "roles", `tenant-claim` default "tenant").
pub struct JwtProvider {
pub:
	enabled      bool
	jwks         cx.Node // parsed JWKS key node (crypto_jwks_parse)
	issuer       string
	audience     string
	roles_claim  string = 'roles'
	tenant_claim string = 'tenant'
}

// DidGrant maps a DID to its roles + tenant (the rename-free authorization layer:
// the DID is the principal; authority is granted here, keyed by DID).
pub struct DidGrant {
pub:
	did    string
	roles  []string
	tenant string
}

// DidProvider authenticates a DID-JWT (an EdDSA JWS whose `iss` is the signer's
// DID). The DID's public key verifies the signature — for did:key it is encoded
// in the DID itself (offline, no network/ledger; the universal default). did:web
// (HTTPS resolution + TTL cache) is the next brick. CX DID is ledger-free.
pub struct DidProvider {
pub:
	enabled        bool
	grants         []DidGrant
	methods        []string = ['key', 'web'] // allowed DID methods (#189 methods=); a did:<m> outside this set is rejected
	audience       string   // #189: when set, the DID-JWT must carry a matching `aud` (binds the token to this service — closes cross-service replay)
	cache_ttl_secs i64                = 300
	cache          &KeyCache = unsafe { nil } // did:web resolver cache (shared across workers)
}

// KeyCache memoizes resolved did:web verification keys (TTL-bounded) so
// per-request auth doesn't re-fetch every time and survives a resolver outage
// (resolve-once, verify-many). Shared across worker threads → mutex-guarded.
// did:key needs no cache (offline). Allocate via new_key_cache.
@[heap]
pub struct KeyCache {
mut:
	mu      &sync.Mutex = unsafe { nil }
	entries map[string]DidCacheEntry
}

struct DidCacheEntry {
	jwk        cx.Node
	expires_ns i64
}

pub fn new_key_cache() &KeyCache {
	return &KeyCache{
		mu:      sync.new_mutex()
		entries: map[string]DidCacheEntry{}
	}
}

// get returns the cached JWK for `did` if present and not past `now_ns`.
pub fn (mut c KeyCache) get(did string, now_ns i64) ?cx.Node {
	c.mu.lock()
	defer {
		c.mu.unlock()
	}
	e := c.entries[did] or { return none }
	if now_ns >= e.expires_ns {
		return none
	}
	return e.jwk
}

// put stores `jwk` for `did`, expiring at `expires_ns`.
pub fn (mut c KeyCache) put(did string, jwk cx.Node, expires_ns i64) {
	c.mu.lock()
	c.entries[did] = DidCacheEntry{
		jwk:        jwk
		expires_ns: expires_ns
	}
	c.mu.unlock()
}

// OidcProvider is the enterprise-SSO bridge: it validates IdP-issued JWTs using
// the IdP's JWKS, discovered + fetched from <issuer>/.well-known/openid-
// configuration → jwks_uri and cached (TTL → key rotation). It reuses the JWT
// verify path (OIDC = JWT with fetched, rotating keys).
pub struct OidcProvider {
pub:
	enabled        bool
	issuer         string
	audience       string
	roles_claim    string    = 'roles'
	tenant_claim   string    = 'tenant'
	cache_ttl_secs i64       = 300
	cache          &KeyCache = unsafe { nil } // JWKS cache keyed by issuer
}

// AuthContext is the daemon's resolved auth config. `enforce` is true iff any
// provider is configured; when false the daemon runs open (anonymous full
// access) for trusted single-tenant/dev deployments (logged at startup).
pub struct AuthContext {
pub:
	enforce       bool
	static_tokens []StaticToken
	jwt           JwtProvider
	did           DidProvider
	oidc          OidcProvider
}

// svc_ct_eq is a constant-time string compare (#206.5): it always scans the full
// length and accumulates differences, so timing does not leak how many leading
// bytes matched. Unequal lengths return false immediately (length is not secret).
fn svc_ct_eq(a string, b string) bool {
	if a.len != b.len {
		return false
	}
	mut diff := u8(0)
	for i in 0 .. a.len {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// svc_authenticate resolves a request's credential to a Principal. No / unknown
// credential → an anonymous principal (the caller decides what anonymous may do).
pub fn svc_authenticate(req cx.Element, auth AuthContext) Principal {
	token := svc_request_bearer(req)
	if token != '' {
		th := sha256.sum256(token.bytes()).hex()
		for st in auth.static_tokens {
			// #206.5: constant-time digest compare (both are 64-hex SHA-256 strings,
			// equal length) — no early-out timing leak of the digest prefix.
			if svc_ct_eq(st.secret_hash, th) {
				return Principal{
					id:     st.id
					kind:   'static'
					roles:  st.roles
					tenant: st.tenant
				}
			}
		}
		// JWT (real current time). The IdP-JWT path checks expected-iss = the
		// configured issuer, so a DID-JWT (iss = did:…) won't match it.
		if auth.jwt.enabled {
			if p := svc_jwt_authenticate(token, auth.jwt, svc_now_node()) {
				return p
			}
		}
		// DID-JWT (iss = did:…).
		if auth.did.enabled {
			if p := svc_did_authenticate(token, auth.did, svc_now_node()) {
				return p
			}
		}
		// OIDC (IdP-issued JWT verified against the discovered+cached JWKS).
		if auth.oidc.enabled {
			if p := svc_oidc_authenticate(token, auth.oidc, svc_now_node()) {
				return p
			}
		}
	}
	return Principal{
		kind: 'anonymous'
	}
}

// svc_oidc_authenticate validates an IdP-issued JWT against the issuer's JWKS
// (discovered + fetched + TTL-cached) — reusing the JWT verify path; the
// principal is the `sub` with kind 'oidc'.
fn svc_oidc_authenticate(token string, oidc OidcProvider, now cx.Node) ?Principal {
	if !oidc.enabled {
		return none
	}
	jwks := svc_oidc_jwks(oidc) or { return none }
	jp := JwtProvider{
		enabled:      true
		jwks:         jwks
		issuer:       oidc.issuer
		audience:     oidc.audience
		roles_claim:  oidc.roles_claim
		tenant_claim: oidc.tenant_claim
	}
	p := svc_jwt_authenticate(token, jp, now) or { return none }
	return Principal{
		id:     p.id
		kind:   'oidc'
		roles:  p.roles
		tenant: p.tenant
	}
}

// svc_oidc_jwks returns the issuer's JWKS, from the TTL cache or by discovery +
// fetch (then cached). Network fetch via cx-stdlib/http; cache survives an IdP
// outage within the TTL.
fn svc_oidc_jwks(oidc OidcProvider) ?cx.Node {
	now_ns := time.now().unix_nano()
	mut cache := oidc.cache
	has_cache := oidc.cache != unsafe { nil }
	if has_cache {
		if j := cache.get(oidc.issuer, now_ns) {
			return j
		}
	}
	jwks := svc_oidc_fetch_jwks(oidc.issuer) or { return none }
	if has_cache {
		ttl := if oidc.cache_ttl_secs > 0 { oidc.cache_ttl_secs } else { i64(300) }
		cache.put(oidc.issuer, jwks, now_ns + ttl * i64(1_000_000_000))
	}
	return jwks
}

// svc_oidc_fetch_jwks does OIDC discovery (GET <issuer>/.well-known/openid-
// configuration → jwks_uri) then fetches + parses the JWKS.
fn svc_oidc_fetch_jwks(issuer string) ?cx.Node {
	disco_body := svc_http_get_body(issuer.trim_right('/') + '/.well-known/openid-configuration') or {
		return none
	}
	disco := json_do_parse(disco_body, map[string]cx.Node{})
	if is_err_value(disco) {
		return none
	}
	jwks_uri := crypto_jstr(crypto_jmap_get(disco, 'jwks_uri') or { return none }) or { return none }
	jwks_text := svc_http_get_body(jwks_uri) or { return none }
	parsed := crypto_jwks_parse(jwks_text)
	if is_err_value(parsed) {
		return none
	}
	return parsed
}

// svc_http_get_body GETs `url` and returns the response body for a 2xx status.
// #210: a fetch failure (esp. a capability net-denial — CXER4504 — when an OIDC
// IdP is on a private/loopback address the daemon's net grant does not scope to)
// is LOGGED with its real cause here, instead of collapsing silently to `none`
// and surfacing downstream as an indistinguishable 401. The return stays `?string`
// (the caller treats a fetch failure as "no JWKS"), but the operator now gets a
// diagnostic pointing at the denied fetch rather than a mystery auth failure.
fn svc_http_get_body(url string) ?string {
	resp := http_request_verb([crypto_string_node('get'), crypto_string_node(url)])
	if is_err_value(resp) {
		mut ecode := ''
		mut msg := ''
		if resp is cx.Element {
			ecode = resp.attr('code')
			msg = resp.attr('message')
		}
		eprintln('cxstore: WARNING OIDC/JWKS fetch of ${url} failed: ${ecode} ${msg}' +
			if ecode == 'cx-err:CXER4504' {
				' — the IdP is on a denied (private/loopback) address; grant the net cap scoped to it (e.g. --allow-net=host:port)'
			} else {
				''
			})
		return none
	}
	if resp is cx.Element {
		if st := resp.attr_val('status') {
			status := cx.scalar_value_str_public(st)
			if !status.starts_with('2') {
				eprintln('cxstore: WARNING OIDC/JWKS fetch of ${url} returned HTTP ${status}')
				return none
			}
		}
		body_node := http_body_text_impl([cx.Node(resp)])
		return arg_string(body_node) or { return none }
	}
	return none
}

// svc_did_authenticate verifies a DID-JWT: the unverified `iss` claim names the
// signer's DID; the DID's public key (derived offline for did:key) verifies the
// JWS via crypto_jwt_verify (self-issued: expected-iss = the DID). The principal
// is the DID; its roles/tenant come from the configured grant (no grant → none).
fn svc_did_authenticate(token string, did_p DidProvider, now cx.Node) ?Principal {
	if !did_p.enabled {
		return none
	}
	parts := token.split('.')
	if parts.len != 3 {
		return none
	}
	payload_bytes := crypto_b64url_decode(parts[1]) or { return none }
	payload := json_do_parse(payload_bytes.bytestr(), map[string]cx.Node{})
	if is_err_value(payload) {
		return none
	}
	did := crypto_jstr(crypto_jmap_get(payload, 'iss') or { return none }) or { return none }
	if !did.starts_with('did:') {
		return none
	}
	// #189: honor methods= — reject a DID whose method is not in the allowed set
	// (e.g. did:web rejected when methods="key"), fail-closed.
	if !svc_did_method_allowed(did, did_p.methods) {
		return none
	}
	jwk := svc_did_jwk(did, did_p) or { return none }
	mut opt_items := [
		cx.Node(cx.Element{
			name:  'expected-iss'
			items: [crypto_string_node(did)]
		}),
	]
	// #189: audience binding — when configured, require a matching `aud` so a
	// DID-JWT minted for a different service cannot be replayed here.
	if did_p.audience != '' {
		opt_items << cx.Node(cx.Element{
			name:  'expected-aud'
			items: [crypto_string_node(did_p.audience)]
		})
	}
	opts := cx.Node(cx.Element{
		name:  '__cx_map__'
		items: opt_items
	})
	claims := crypto_jwt_verify([crypto_string_node(token), jwk, now, opts])
	if is_err_value(claims) {
		return none // fail-closed: signature / exp / iss mismatch
	}
	// #207.6: an authenticated DID with no grant is authenticated-but-unauthorized
	// → return an empty-roles Principal so the RBAC check yields 403 CXER1703 (the
	// graduated semantics), NOT `none` → anonymous → 401 (as JWT/OIDC empty-roles
	// already do). The signature verified; the principal IS the DID.
	grant := svc_did_grant(did_p, did) or {
		return Principal{
			id:   did
			kind: 'did'
		}
	}
	return Principal{
		id:     did
		kind:   'did'
		roles:  grant.roles
		tenant: grant.tenant
	}
}

// svc_did_method_allowed reports whether `did`'s method (the token between the
// first two colons, e.g. `key` in `did:key:z…`) is in the configured allow-set.
fn svc_did_method_allowed(did string, methods []string) bool {
	rest := did.all_after('did:')
	method := rest.all_before(':')
	if method == '' {
		return false
	}
	return method in methods
}

// svc_did_jwk resolves a DID to an OKP/Ed25519 JWK key node. did:key is decoded
// offline (the key is in the DID); did:web does an HTTPS resolve (through the
// TTL cache) and extracts the verification key from the DID Document.
fn svc_did_jwk(did string, did_p DidProvider) ?cx.Node {
	if did.starts_with('did:key:') {
		kb := did_key_bytes(did) or { return none }
		return svc_okp_jwks(base64.url_encode(kb).trim_right('='))
	}
	if did.starts_with('did:web:') {
		now_ns := time.now().unix_nano()
		has_cache := did_p.cache != unsafe { nil }
		mut cache := did_p.cache
		if has_cache {
			if j := cache.get(did, now_ns) {
				return j
			}
		}
		parts := did_split(did) or { return none }
		doc := did_web_resolve(did, parts.id) // HTTPS GET (net)
		if is_err_value(doc) {
			return none
		}
		jwk := svc_did_doc_extract_jwk(doc) or { return none }
		if has_cache {
			ttl := if did_p.cache_ttl_secs > 0 { did_p.cache_ttl_secs } else { i64(300) }
			cache.put(did, jwk, now_ns + ttl * i64(1_000_000_000))
		}
		return jwk
	}
	return none
}

// svc_okp_jwks builds a single-key OKP/Ed25519 JWKS node from the base64url key.
fn svc_okp_jwks(x string) cx.Node {
	return crypto_jwks_parse('{"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","x":"${x}"}]}')
}

// svc_did_doc_extract_jwk pulls the Ed25519 verification key out of a resolved
// DID Document node (the [did-document … [source <parsed-json>]] from
// did_web_resolve) — supporting verificationMethod[0].publicKeyJwk (OKP) and
// publicKeyMultibase — and returns it as an OKP JWKS node.
fn svc_did_doc_extract_jwk(doc cx.Node) ?cx.Node {
	src := svc_doc_source_map(doc) or { return none }
	vmarr := crypto_jmap_get(src, 'verificationMethod') or { return none }
	if vmarr !is cx.Element {
		return none
	}
	arr := vmarr as cx.Element
	if arr.name != '__cx_arr__' || arr.items.len == 0 {
		return none
	}
	vm := arr.items[0]
	// publicKeyJwk (OKP/Ed25519) — use its x directly.
	if jwk := crypto_jmap_get(vm, 'publicKeyJwk') {
		crv := crypto_jstr(crypto_jmap_get(jwk, 'crv') or { return none }) or { return none }
		if crv != 'Ed25519' {
			return none
		}
		x := crypto_jstr(crypto_jmap_get(jwk, 'x') or { return none }) or { return none }
		return svc_okp_jwks(x)
	}
	// publicKeyMultibase — decode 'z' + base58btc(0xed01 ‖ key) → 32-byte key.
	if mbn := crypto_jmap_get(vm, 'publicKeyMultibase') {
		mb := crypto_jstr(mbn) or { return none }
		kb := svc_multibase_ed25519(mb) or { return none }
		return svc_okp_jwks(base64.url_encode(kb).trim_right('='))
	}
	return none
}

// svc_doc_source_map returns the parsed-JSON source map of a did:web document.
fn svc_doc_source_map(doc cx.Node) ?cx.Node {
	if doc is cx.Element {
		for it in doc.items {
			if it is cx.Element && it.name == 'source' && it.items.len > 0 {
				return it.items[0]
			}
		}
	}
	return none
}

// svc_multibase_ed25519 decodes a `z`-base58btc multibase Ed25519 key
// (multicodec 0xed 0x01 prefix) into the 32 raw public-key bytes.
fn svc_multibase_ed25519(mb string) ?[]u8 {
	if mb.len < 2 || mb[0] != `z` {
		return none
	}
	decoded := base58.decode_bytes(mb[1..].bytes()) or { return none }
	if decoded.len != 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
		return none
	}
	return decoded[2..].clone()
}

// svc_did_grant finds the configured grant (roles + tenant) for a DID.
fn svc_did_grant(did_p DidProvider, did string) ?DidGrant {
	for g in did_p.grants {
		if g.did == did {
			return g
		}
	}
	return none
}

// svc_jwt_authenticate verifies a JWT against the provider's JWKS at `now`
// (parameterized for testability) and maps its claims to a Principal, or none
// if verification fails (bad sig / expired / wrong iss·aud / malformed).
fn svc_jwt_authenticate(token string, jwt JwtProvider, now cx.Node) ?Principal {
	if !jwt.enabled {
		return none
	}
	mut entries := []cx.Node{}
	if jwt.issuer != '' {
		entries << cx.Node(cx.Element{
			name:  'expected-iss'
			items: [crypto_string_node(jwt.issuer)]
		})
	}
	if jwt.audience != '' {
		entries << cx.Node(cx.Element{
			name:  'expected-aud'
			items: [crypto_string_node(jwt.audience)]
		})
	}
	opts := cx.Node(cx.Element{
		name:  '__cx_map__'
		items: entries
	})
	claims := crypto_jwt_verify([crypto_string_node(token), jwt.jwks, now, opts])
	if is_err_value(claims) {
		return none // fail-closed: any verification failure → unauthenticated
	}
	sub := crypto_jstr(crypto_claim(claims, 'sub')) or { '' }
	roles := crypto_node_str_list(crypto_claim(claims, jwt.roles_claim))
	tenant := crypto_jstr(crypto_claim(claims, jwt.tenant_claim)) or { '' }
	return Principal{
		id:     sub
		kind:   'jwt'
		roles:  roles
		tenant: tenant
	}
}

// svc_now_node builds a datetime node for the current instant (the `now` arg to
// crypto_jwt_verify's exp/nbf checks).
fn svc_now_node() cx.Node {
	return time_datetime_node(dt_from_instant(time.now().unix_nano(), 0).datetime_string())
}

// svc_authorize enforces RBAC + tenant scoping for a data op on a store. Returns
// none when allowed, else an err value (401 if anonymous, 403 CXER1703 if a known
// principal lacks the permission/tenant).
pub fn svc_authorize(p Principal, op string, store_name string) ?cx.Node {
	if p.kind == 'anonymous' {
		return mk_err(e_csrp_auth_required, 'E_CSRP_AUTH_REQUIRED: data ops require a valid credential')
	}
	perm := svc_permission_for_op(op)
	if !svc_role_grants(p.roles, perm) {
		return mk_err(e_csrp_forbidden, 'E_CSRP_FORBIDDEN: principal `${p.id}` lacks `${perm}` for op `${op}`')
	}
	if store_name != '' && !svc_tenant_allows(p.tenant, store_name) {
		return mk_err(e_csrp_forbidden, 'E_CSRP_FORBIDDEN: tenant of `${p.id}` is not allowed store `${store_name}`')
	}
	return none
}

// svc_permission_for_op maps a CSRP op to its required permission (App C + the
// object-wire rows, #195). Unknown ops require `admin` (deny-by-default for
// anything unmapped).
//
// Object wire (objects-have/get/put + refs/refs-set): these are the plumbing the
// porcelain (push/pull/clone) AND the primary client put path ride on — a
// `put_doc_text` preflights `objects-have`. Mapping them to `admin` (the old
// else-branch) meant a `writer` could not perform even a basic put and a `reader`
// could not pull/clone (#195/#212). They map to the SAME permission classes as
// their data-op peers: read-shaped ops (have/get/refs) → `read`; write-shaped ops
// (put/refs-set) → `write`.
fn svc_permission_for_op(op string) string {
	return match op {
		'get', 'list', 'iter', 'query' { 'read' }
		'put', 'modify' { 'write' }
		'delete' { 'delete' }
		'metrics' { 'metrics' }
		'objects-have', 'objects-get', 'refs' { 'read' }
		'objects-put', 'refs-set' { 'write' }
		// #645 alias remoting: reads answer explicit presence, writes apply
		// through the daemon's local set-alias arm — same classes as their
		// data-op peers.
		'aliases' { 'read' }
		'aliases-set' { 'write' }
		// #248 admin plane (§3.10–3.12): status (store stats), gc (compaction
		// trigger), mounts (daemon-level enumeration) — explicit App C rows; the
		// else-branch would map them to admin anyway, but the matrix is normative.
		// #251 (§3.13): config-reload (daemon-level reload trigger).
		'status', 'gc', 'mounts', 'config-reload' { 'admin' }
		else { 'admin' }
	}
}

// svc_role_grants reports whether any of `roles` grants `perm` (App C matrix).
fn svc_role_grants(roles []string, perm string) bool {
	for r in roles {
		grants := match r {
			'reader' { ['read'] }
			'writer' { ['read', 'write'] }
			'admin' { ['read', 'write', 'delete', 'admin'] }
			'metrics' { ['metrics'] }
			else { []string{} }
		}
		if perm in grants {
			return true
		}
	}
	return false
}

// svc_tenant_allows reports whether a principal scoped to `tenant_spec` (space-
// separated store-names, or `*`) may access `store_name`. Empty spec → no access.
fn svc_tenant_allows(tenant_spec string, store_name string) bool {
	if tenant_spec == '*' {
		return true
	}
	for allowed in tenant_spec.fields() {
		if allowed == store_name {
			return true
		}
	}
	return false
}

// svc_request_bearer extracts the Bearer token from the request's Authorization
// header (case-insensitive name + scheme), or '' if absent.
fn svc_request_bearer(req cx.Element) string {
	for it in req.items {
		if it is cx.Element && it.name == 'headers' {
			for h in it.items {
				if h is cx.Element && h.name == 'header' {
					if h.attr('name').to_lower() == 'authorization' {
						v := h.attr('value').trim_space()
						if v.to_lower().starts_with('bearer ') {
							return v[7..].trim_space()
						}
					}
				}
			}
		}
	}
	return ''
}
