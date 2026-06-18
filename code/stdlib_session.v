@[has_globals]
module code

import cx
import encoding.base64
import crypto.sha256
import crypto.ed25519

// stdlib_session.v — native primitives backing the `cx-stdlib/session`
// module (spec/02-inprogress/xap/stdlib_session.md). The thin (principal,
// tenant) web-session layer: it COMPOSES the already-shipped
// `cx-stdlib/crypto` JWT/JWKS verify (stdlib_crypto.v) for token
// verification and `cx-stdlib/http` (stdlib_http.v) for the request/header/
// cookie transport — session adds NO crypto and NO transport of its own
// (§0/§2.2/§2.8).
//
// ── CAPABILITY POSTURE (§5) ─────────────────────────────────────────
//   session is itself CAPABILITY-FREE: the only network reach is the JWKS
//   fetch INSIDE crypto, gated by crypto's `net` (and only when `jwks` is a
//   URL — a literal in-memory key-set needs no socket). session therefore
//   adds NO new capability and NO cap_guard of its own; it mirrors http's
//   pure-by-default posture at the purity checker (no effect_alignment
//   entry). When a `jwks` URL is supplied and `net` is ungranted the
//   denial surfaces as the core CXER0271 from crypto's fetch, propagated
//   verbatim — never remapped.
//
// ── FAIL-CLOSED (§2.2/§4.1) ─────────────────────────────────────────
//   attach runs verify → map → bind → mirror-attach all-or-nothing: any
//   verification ambiguity REJECTS (a fault, §2.6) and NEVER establishes a
//   half-session. A token that fails [$crypto:jwt-verify] → CXER4801
//   carrying the verbatim crypto fault as a child. No-tenant → CXER4802,
//   no-principal → CXER4803, non-TLS → CXER4806, no-token → CXER4807.
//
// ── ERROR BAND (§8) — session owns CXER4800–CXER4849 ────────────────
//   4801 token-reject / 4802 no-tenant / 4803 no-principal / 4804
//   invalid-or-detached-session-op / 4805 rebind-refused / 4806
//   insecure-transport / 4807 no-token / 4808 csrf-missing / 4809
//   csrf-mismatch / 4810 cookie-insecure-context / 4811 cookie-unsafe-flags.
//   Cancellation is the core CXER0260; capability denial the core CXER0271
//   (both inherited, not session codes).

// ── error codes (§8) ─────────────────────────────────────────────────
const session_err_token_rejected = 'cx-err:CXER4801' // E_SESSION_TOKEN_REJECTED
const session_err_tenant_unresolved = 'cx-err:CXER4802' // E_SESSION_TENANT_UNRESOLVED
const session_err_principal_unresolved = 'cx-err:CXER4803' // E_SESSION_PRINCIPAL_UNRESOLVED
const session_err_invalid = 'cx-err:CXER4804' // E_SESSION_INVALID
const session_err_rebind_refused = 'cx-err:CXER4805' // E_SESSION_REBIND_REFUSED
const session_err_insecure_transport = 'cx-err:CXER4806' // E_SESSION_INSECURE_TRANSPORT
const session_err_no_token = 'cx-err:CXER4807' // E_SESSION_NO_TOKEN
const session_err_csrf_missing = 'cx-err:CXER4808' // E_SESSION_CSRF_MISSING
const session_err_csrf_mismatch = 'cx-err:CXER4809' // E_SESSION_CSRF_MISMATCH
const session_err_cookie_insecure = 'cx-err:CXER4810' // E_SESSION_COOKIE_INSECURE_CONTEXT
const session_err_cookie_unsafe = 'cx-err:CXER4811' // E_SESSION_COOKIE_UNSAFE_FLAGS

// ── server-held session state (§2.1, §9) ─────────────────────────────
//
// The session registry is the process-global tenant-rooted store (§9): a
// map keyed by the opaque session id, holding the (principal, tenant)
// binding, the mirrored-attach client set, the verified claim-set, the
// per-session CSRF synchronizer token (§2.9), and the attach transport
// (`via`) markers. Held behind a nil-default voidptr global lazily
// allocated on first use — the proven stdlib_store.v form (a value
// initializer carrying map fields is not const-evaluable).
@[heap]
struct SessionClient {
mut:
	id          string
	channel     string // http / cx / …
	via         string // bearer / cookie (§2.1) — keys the CSRF exemption (N-SESSION-7)
	attached_at string
	last_seen   string
}

@[heap]
struct SessionRecord {
mut:
	id           string // opaque, high-entropy (§2.8 / N-SESSION-5); the cookie value + store key
	state        string // attached / detached / expired (§2.1)
	principal_id string
	tenant_id    string
	established  string // RFC-3339 established-at marker
	exp_secs     i64    // verified token `exp` (0 = no exp claim)
	now_secs     i64    // attach-time reference clock (Unix secs)
	claims       cx.Node // the verified [claims …] value (§3.4 `claims`)
	csrf_token   string  // synchronizer CSRF secret (§2.9); '' until a cookie client attaches
	clients      []SessionClient
}

@[heap]
struct SessionRegistry {
mut:
	sessions   map[string]&SessionRecord // by session id
	by_subject map[string]string         // "principal\x00tenant" → session id (mirrored attach, §2.7)
	client_idx map[string]string         // client id → session id (by-client, §3.3)
	token_idx  map[string]string         // bearer-token FINGERPRINT (sha256 hex) → session id (of-resolve, §3.3)
	counter    int                       // monotonic for client-id minting
}

__global (
	g_session_reg voidptr
)

// session_reset_state clears the process-global session registry. Called
// from matcher.v::new_env at the start of each evaluated program so the
// server-held session store (sessions / clients / CSRF tokens) never leaks
// across independent programs — the same per-program reset prof uses.
pub fn session_reset_state() {
	if g_session_reg == unsafe { nil } {
		return
	}
	mut reg := unsafe { &SessionRegistry(g_session_reg) }
	reg.sessions = map[string]&SessionRecord{}
	reg.by_subject = map[string]string{}
	reg.client_idx = map[string]string{}
	reg.token_idx = map[string]string{}
	reg.counter = 0
}

fn session_reg() &SessionRegistry {
	if g_session_reg == unsafe { nil } {
		r := &SessionRegistry{
			sessions:   map[string]&SessionRecord{}
			by_subject: map[string]string{}
			client_idx: map[string]string{}
			token_idx:  map[string]string{}
		}
		g_session_reg = voidptr(r)
	}
	return unsafe { &SessionRegistry(g_session_reg) }
}

// ── value builders ───────────────────────────────────────────────────
fn session_str(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	}
}

fn session_bool(b bool) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bool_type
	}
}

fn session_null() cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(cx.NullValue{})
		data_type: cx.ScalarType.null_type
	}
}

fn session_seq(items []cx.Node) cx.Node {
	return cx.Element{
		name:  '__cx_seq__'
		items: items
	}
}

// session_absence is the absence channel (§2.5): an empty node-set. NOT
// null and NOT a fault — the normal "no session established" state.
fn session_absence() cx.Node {
	return session_seq([])
}

fn session_str_attr(name string, s string) cx.Attribute {
	return cx.new_attribute(name, cx.ScalarValue(s), cx.AttributeMeta{})
}

// ── argument readers ─────────────────────────────────────────────────
fn session_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return none
}

// session_opts lifts a `__cx_map__` config node into a V map (mirrors
// crypto_opts).
fn session_opts(n cx.Node) map[string]cx.Node {
	mut m := map[string]cx.Node{}
	if n is cx.Element && n.name == '__cx_map__' {
		for e in n.items {
			if e is cx.Element && e.items.len > 0 {
				m[e.name] = e.items[0]
			}
		}
	}
	return m
}

fn session_opt_str(m map[string]cx.Node, key string, def string) string {
	n := m[key] or { return def }
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return def
}

fn session_opt_bool(m map[string]cx.Node, key string, def bool) bool {
	n := m[key] or { return def }
	if n is cx.ScalarNode {
		v := n.value
		if v is bool {
			return v
		}
	}
	return def
}

// session_opt_node returns the raw config value (e.g. the `jwks` element,
// or a `now` datetime scalar) or none.
fn session_opt_node(m map[string]cx.Node, key string) ?cx.Node {
	return m[key] or { return none }
}

// ── opaque id / CSRF token minting (§2.8 / §2.9, §9) ──────────────────
//
// ≥128-bit CSPRNG via the same crypto random source the crypto module
// uses (crypto_random_octets) → base64url. The session id is the cookie
// value + store key; the CSRF token is a sibling secret held in the
// session record. NEVER asserted by literal value in fixtures (§10) — the
// entropy is fresh per attach; fixtures pin prefix / length / round-trip.
fn session_mint_id() string {
	octets := crypto_random_octets(18) or { []u8{len: 18} }
	return 's-' + base64.url_encode(octets)
}

fn session_mint_csrf() string {
	octets := crypto_random_octets(32) or { []u8{len: 32} }
	return base64.url_encode(octets)
}

// ── claim mapping (§2.3) ─────────────────────────────────────────────
//
// The pure subject → (principal, tenant) mapping. tenant from
// `tenant-claim` (default "tid"); principal from `principal-claim`
// (default "sub"). Reads the verified [claims …] value via crypto_claim
// (same module). Returns [principal id=… [tenant …]] or a CXER4802 /
// CXER4803 fault on an unresolvable claim-set (§2.3 / N-SESSION-2).
//
// The optional `tenant-map` / `principal-map` callable overrides (§3.1)
// need the evaluator env to apply a user [?def]; they are handled in
// session_stdlib_builtin_env (the env-aware path). The claim-name form
// here is the default and covers the full conformance matrix.
fn session_claim_str(claims cx.Node, name string) ?string {
	// A verified [claims …] value carries registered scalar claims as
	// ATTRIBUTES (iss/sub/aud/jti/exp/nbf/iat — crypto_build_claims) and the
	// full claim-set under a [payload __cx_map__] child (crypto_claim reads
	// that). A hand-built [claims tid=… sub=…] test value carries attrs
	// only. Read attrs first (covers the registered claims + a test
	// element), then fall back to the payload (covers any non-registered
	// claim such as a custom `tid`/`org`).
	if claims is cx.Element {
		if av := claims.attr_val(name) {
			s := cx.scalar_value_str_public(av)
			if s != '' {
				return s
			}
		}
	}
	v := crypto_claim(claims, name)
	if is_err_value(v) {
		return none
	}
	if v is cx.Element && v.name == '' && v.items.len == 0 {
		return none // absence channel — claim absent
	}
	return session_node_str(v)
}

fn session_node_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			string { return v }
			i64 { return v.str() }
			f64 { return v.str() }
			bool { return v.str() }
			else { return none }
		}
	}
	return none
}

// session_map_claims builds the [principal id=… [tenant …]] binding from a
// verified [claims …] value + cfg (the §2.3 / §3.4 pure mapping). FAIL-
// CLOSED: no tenant → CXER4802; no principal → CXER4803.
fn session_map_claims(claims cx.Node, cfg map[string]cx.Node) cx.Node {
	if claims !is cx.Element || (claims as cx.Element).name != 'claims' {
		return mk_err(session_err_principal_unresolved, 'E_SESSION_PRINCIPAL_UNRESOLVED: map-claims expects a verified [claims …] value')
	}
	tenant_claim := session_opt_str(cfg, 'tenant-claim', 'tid')
	principal_claim := session_opt_str(cfg, 'principal-claim', 'sub')
	tenant_id := session_claim_str(claims, tenant_claim) or {
		return mk_err(session_err_tenant_unresolved, 'E_SESSION_TENANT_UNRESOLVED: claim "${tenant_claim}" resolves to no tenant')
	}
	if tenant_id == '' {
		return mk_err(session_err_tenant_unresolved, 'E_SESSION_TENANT_UNRESOLVED: claim "${tenant_claim}" is empty')
	}
	principal_id := session_claim_str(claims, principal_claim) or {
		return mk_err(session_err_principal_unresolved, 'E_SESSION_PRINCIPAL_UNRESOLVED: claim "${principal_claim}" resolves to no principal')
	}
	if principal_id == '' {
		return mk_err(session_err_principal_unresolved, 'E_SESSION_PRINCIPAL_UNRESOLVED: claim "${principal_claim}" is empty')
	}
	return session_principal_element(principal_id, tenant_id)
}

fn session_principal_element(principal_id string, tenant_id string) cx.Node {
	return cx.Element{
		name:  'principal'
		attrs: [session_str_attr('id', principal_id)]
		items: [
			cx.Node(cx.Element{
				name:  'tenant'
				attrs: [session_str_attr('id', tenant_id)]
			}),
		]
	}
}

// ── [session] handle materialization (§2.1) ──────────────────────────
//
// Render the server-held SessionRecord into the homoiconic [session …]
// value the surface returns. The raw token is NEVER carried (§4.6); the
// verified claim-set is carried under [claims] for the resolver/audit.
fn session_materialize(rec &SessionRecord) cx.Node {
	mut attrs := [
		session_str_attr('id', rec.id),
		session_str_attr('state', rec.state),
		session_str_attr('on-close', 'session/detach'),
	]
	mut items := []cx.Node{}
	items << session_principal_element(rec.principal_id, rec.tenant_id)
	items << cx.Node(cx.Element{
		name:  'established-at'
		items: [session_str(rec.established)]
	})
	mut client_items := []cx.Node{}
	for c in rec.clients {
		client_items << cx.Node(cx.Element{
			name:  'client'
			attrs: [
				session_str_attr('id', c.id),
				session_str_attr('channel', c.channel),
				session_str_attr('via', c.via),
				session_str_attr('attached-at', c.attached_at),
				session_str_attr('last-seen', c.last_seen),
			]
		})
	}
	items << cx.Node(cx.Element{
		name:  'clients'
		items: client_items
	})
	if rec.csrf_token != '' {
		items << cx.Node(cx.Element{
			name:  'csrf-token'
			items: [session_str(rec.csrf_token)]
		})
	}
	return cx.Element{
		name:  'session'
		attrs: attrs
		items: items
	}
}

// session_subject_key keys the mirrored-attach lookup (§2.7).
fn session_subject_key(principal_id string, tenant_id string) string {
	return principal_id + '\x00' + tenant_id
}

// session_now_secs reads a cfg `now` datetime (or token-derived clock) into
// Unix seconds; 0 when absent.
fn session_cfg_now_secs(cfg map[string]cx.Node) i64 {
	n := session_opt_node(cfg, 'now') or { return 0 }
	dt := decode_datetime(n) or { return 0 }
	return dt.instant_ns() / ns_per_s
}

// ── attach verify pipeline (§2.2/§2.7) ───────────────────────────────
//
// The shared verify → map → bind → mirror-attach engine for the bearer,
// raw-token, and cookie paths. FAIL-CLOSED at every step.
//   token       — the raw bearer token
//   cfg         — the attach config map (§3.1)
//   via         — "bearer" / "cookie"
//   channel     — the client channel marker (http / cx / …)
//   client_id   — caller-supplied client id, or '' to mint one
//   issue_csrf  — mint + store the per-session CSRF token (cookie path)
// Returns the live &SessionRecord (the freshly added client is last) or an
// [err] fault VALUE.
fn session_attach_pipeline(token string, cfg map[string]cx.Node, via string, channel string, client_id string, issue_csrf bool) cx.Node {
	// (verify) — delegate ALL cryptography to crypto's jwt-verify (§2.2,
	// N-SESSION-1). Build the jwt-verify arg vector: token, key (jwks),
	// now (datetime), opts (expected-iss/aud/leeway). A literal in-memory
	// jwks needs no net; a URL string would route through jwks-fetch — but
	// for v1 the cfg supplies a parsed [jwks …] key-set (the air-gapped /
	// test posture, §5) or a [jwks]/[jwk] element directly.
	key := session_opt_node(cfg, 'jwks') or {
		return mk_err(session_err_token_rejected, 'E_SESSION_TOKEN_REJECTED: attach cfg has no `jwks` verification key-set')
	}
	now_node := session_opt_node(cfg, 'now') or { session_str('') }
	// jwt-verify opts: forward expected iss/aud + leeway.
	mut jwt_opts_items := []cx.Node{}
	issuer := session_opt_str(cfg, 'issuer', '')
	if issuer != '' {
		jwt_opts_items << session_kv('expected-iss', session_str(issuer))
	}
	audience := session_opt_str(cfg, 'audience', '')
	if audience != '' {
		jwt_opts_items << session_kv('expected-aud', session_str(audience))
	}
	if lw := session_opt_node(cfg, 'leeway') {
		jwt_opts_items << session_kv('leeway', lw)
	}
	jwt_opts := cx.Element{
		name:  '__cx_map__'
		items: jwt_opts_items
	}
	verified := crypto_jwt_verify([session_str(token), key, now_node, cx.Node(jwt_opts)])
	if is_err_value(verified) {
		// FAIL-CLOSED: wrap the verbatim crypto JWT fault as a child (§2.6).
		return session_err_with_cause(session_err_token_rejected, 'E_SESSION_TOKEN_REJECTED: token failed crypto jwt-verify',
			verified)
	}
	return session_establish_from_verified(verified, cfg, via, channel, client_id,
		issue_csrf, token)
}

// session_establish_from_verified runs the post-verification tail shared by
// every attach path (JWT bearer, DID proof-of-control): map the verified
// claim-set → (principal, tenant), then mirror-attach to a live session for
// that subject or mint a new one. `token` is '' for non-bearer paths (the
// bearer token fingerprint index is only written when via == 'bearer').
fn session_establish_from_verified(verified cx.Node, cfg map[string]cx.Node, via string, channel string, client_id string, issue_csrf bool, token string) cx.Node {
	// (map) — verified claim-set → (principal, tenant) (§2.3).
	binding := session_map_claims(verified, cfg)
	if is_err_value(binding) {
		return binding // CXER4802 / CXER4803 propagate as-is
	}
	bel := binding as cx.Element
	principal_id := bel.attr('id')
	mut tenant_id := ''
	for it in bel.items {
		if it is cx.Element && it.name == 'tenant' {
			tenant_id = it.attr('id')
		}
	}
	now_secs := session_cfg_now_secs(cfg)
	exp_secs := session_claims_exp(verified)
	now_marker := session_opt_str(cfg, 'now', '')

	mut reg := session_reg()
	subj := session_subject_key(principal_id, tenant_id)
	// (mirror-attach) — same subject adds a client to the live session
	// (§2.7); a DIFFERENT binding on an existing id is impossible here
	// because the lookup is keyed by (principal, tenant) — a re-key is
	// refused at the by-id path (rotate/explicit). The CXER4805 case is a
	// token re-presented for a DIFFERENT subject against a session the
	// caller already holds — guarded in attach-to-session below.
	if existing_id := reg.by_subject[subj] {
		if mut rec := reg.sessions[existing_id] {
			if rec.state == 'attached' {
				cid := if client_id != '' { client_id } else { session_next_client_id(mut reg) }
				rec.clients << SessionClient{
					id:          cid
					channel:     channel
					via:         via
					attached_at: now_marker
					last_seen:   now_marker
				}
				reg.client_idx[cid] = existing_id
				if via == 'bearer' {
					reg.token_idx[session_token_fp(token)] = existing_id
				}
				if issue_csrf && rec.csrf_token == '' {
					rec.csrf_token = session_mint_csrf()
				}
				return session_materialize(rec)
			}
		}
	}
	// (mint) — first attach for this subject: a new [session].
	sid := session_mint_id()
	cid := if client_id != '' { client_id } else { session_next_client_id(mut reg) }
	mut rec := &SessionRecord{
		id:           sid
		state:        'attached'
		principal_id: principal_id
		tenant_id:    tenant_id
		established:  now_marker
		exp_secs:     exp_secs
		now_secs:     now_secs
		claims:       verified
		csrf_token:   if issue_csrf { session_mint_csrf() } else { '' }
		clients:      [
			SessionClient{
				id:          cid
				channel:     channel
				via:         via
				attached_at: now_marker
				last_seen:   now_marker
			},
		]
	}
	reg.sessions[sid] = rec
	reg.by_subject[subj] = sid
	reg.client_idx[cid] = sid
	// Index the bearer token by its FINGERPRINT so `of` can resolve a later
	// request carrying the same token (§3.3) without re-running crypto verify
	// (it has no key) and without retaining the raw token (§4.6 — only a
	// one-way sha256, never on the [session] value). Cookie sessions resolve
	// via the cookie id, not the token, so they are not indexed here.
	if via == 'bearer' {
		reg.token_idx[session_token_fp(token)] = sid
	}
	return session_materialize(rec)
}

// session_token_fp is the one-way fingerprint (lowercase sha256 hex) of a raw
// bearer token, used as the of-resolution index key. It is NOT the token and
// is never surfaced on a [session] (§4.6 credential hygiene).
fn session_token_fp(token string) string {
	return sha256.sum256(token.bytes()).hex()
}

fn session_kv(name string, v cx.Node) cx.Node {
	return cx.Element{
		name:  name
		items: [v]
	}
}

fn session_next_client_id(mut reg SessionRegistry) string {
	reg.counter++
	return 'c-${reg.counter}'
}

// session_claims_exp reads the verified `exp` (Unix secs) off the [claims]
// value (registered as an int attr by crypto_build_claims), 0 if absent.
fn session_claims_exp(claims cx.Node) i64 {
	if claims is cx.Element {
		if v := claims.attr_val('exp') {
			s := cx.scalar_value_str_public(v)
			return s.i64()
		}
	}
	return 0
}

// session_err_with_cause builds an [err code=… [cause …]] carrying the
// inherited crypto/transport fault verbatim (§2.6/§8).
fn session_err_with_cause(err_code string, message string, cause cx.Node) cx.Node {
	mut e := mk_err(err_code, message) as cx.Element
	e.items << cx.Node(cx.Element{
		name:  'cause'
		items: [cause]
	})
	return e
}

// ── TLS precondition (§2.4 / N-SESSION-3) ────────────────────────────
//
// session reads the inherited transport posture; it never wraps TLS. A
// server-form [request] attests TLS ONLY via its transport-derived
// `scheme="https"` (the §9 "inspect the carrying listener bind scheme" note);
// a forgeable caller-set `tls` attr / [tls] child is NOT trusted. FAIL-CLOSED:
// a request that does not attest TLS, and without the dev-only allow-insecure
// opt, refuses (§2.4 → CXER4806; the cookie side → CXER4810).
fn session_request_is_tls(req cx.Node) bool {
	if req !is cx.Element {
		return false
	}
	rel := req as cx.Element
	// TRANSPORT-ATTESTED ONLY (§2.4 bright-line). The listener-derived
	// `scheme` is the trustworthy signal: an https/tls/wss request came in
	// over a terminated TLS connection. A caller-set `tls="true"` attr or a
	// bare [tls] child is FORGEABLE on a hand-built [request] — trusting it
	// let any caller bypass the TLS requirement, so both are dropped. (The
	// keyless attach-token path, which carries no request, takes an explicit
	// opts `tls`/`allow-insecure` to vouch for its transport instead.)
	if v := rel.attr_val('scheme') {
		s := cx.scalar_value_str_public(v).to_lower()
		if s == 'https' || s == 'tls' || s == 'wss' {
			return true
		}
	}
	return false
}

// session_read_bearer extracts the bearer token from a [request]'s
// `Authorization: Bearer …` header via the http header accessor (same
// module). Returns the token, or '' when absent / not a Bearer scheme.
fn session_read_bearer(req cx.Node) string {
	h := http_header_impl([req, session_str('Authorization')])
	if h is cx.Element && h.name == 'header' {
		val := http_attr(h, 'value') or { return '' }
		t := val.trim_space()
		if t.len > 7 && t[..7].to_lower() == 'bearer ' {
			return t[7..].trim_space()
		}
	}
	return ''
}

// session_read_cookie extracts a named cookie value from the [request]'s
// `Cookie` header (RFC 6265 `name=value; name2=value2`). Returns '' when
// the header or the named cookie is absent.
fn session_read_cookie(req cx.Node, cookie_name string) string {
	h := http_header_impl([req, session_str('Cookie')])
	if h is cx.Element && h.name == 'header' {
		val := http_attr(h, 'value') or { return '' }
		for pair in val.split(';') {
			p := pair.trim_space()
			eq := p.index('=') or { continue }
			if p[..eq].trim_space() == cookie_name {
				return p[eq + 1..].trim_space()
			}
		}
	}
	return ''
}

// session_read_header reads a named request header's value (e.g. the CSRF
// header), '' when absent.
fn session_read_header(req cx.Node, name string) string {
	h := http_header_impl([req, session_str(name)])
	if h is cx.Element && h.name == 'header' {
		return http_attr(h, 'value') or { return '' }
	}
	return ''
}

// ── cookie directive minting (§2.8 / §2.8.3 / §2.8.4) ────────────────
//
// session CHOOSES the cookie attributes; http owns the wire serialization
// (§1 out-of-scope). We hand back a [set-cookie …] directive element whose
// attributes the http response layer serializes. FAIL-CLOSED refusals:
// non-TLS context → CXER4810; HttpOnly-off / SameSite=None-without-opt →
// CXER4811.
fn session_cookie_flags_ok(cfg map[string]cx.Node) ?cx.Node {
	// HttpOnly is non-negotiable for the session cookie (§2.8.3).
	if !session_opt_bool(cfg, 'cookie-http-only', true) {
		return mk_err(session_err_cookie_unsafe, 'E_SESSION_COOKIE_UNSAFE_FLAGS: HttpOnly cannot be dropped on the session cookie')
	}
	same_site := session_opt_str(cfg, 'cookie-same-site', 'Lax')
	if same_site.to_lower() == 'none' && !session_opt_bool(cfg, 'allow-cross-site-cookie', false) {
		return mk_err(session_err_cookie_unsafe, 'E_SESSION_COOKIE_UNSAFE_FLAGS: SameSite=None requires the explicit allow-cross-site-cookie opt')
	}
	return none
}

fn session_set_cookie_directive(rec &SessionRecord, cfg map[string]cx.Node) cx.Node {
	if e := session_cookie_flags_ok(cfg) {
		return e
	}
	cookie_name := session_opt_str(cfg, 'cookie-name', '__Host-cxsid')
	same_site := session_opt_str(cfg, 'cookie-same-site', 'Lax')
	path := session_opt_str(cfg, 'cookie-path', '/')
	csrf_cookie_name := session_opt_str(cfg, 'csrf-cookie-name', 'cx-csrf')
	mut directives := []cx.Node{}
	// the session cookie — HttpOnly; Secure; SameSite (§2.8 defaults)
	directives << cx.Node(cx.Element{
		name:  'set-cookie'
		attrs: [
			session_str_attr('name', cookie_name),
			session_str_attr('value', rec.id),
			session_str_attr('http-only', 'true'),
			session_str_attr('secure', 'true'),
			session_str_attr('same-site', same_site),
			session_str_attr('path', path),
		]
	})
	// the readable CSRF companion cookie — NON-HttpOnly (the front-end
	// must read it to echo it, §2.9)
	if rec.csrf_token != '' {
		directives << cx.Node(cx.Element{
			name:  'set-cookie'
			attrs: [
				session_str_attr('name', csrf_cookie_name),
				session_str_attr('value', rec.csrf_token),
				session_str_attr('http-only', 'false'),
				session_str_attr('secure', 'true'),
				session_str_attr('same-site', same_site),
				session_str_attr('path', path),
			]
		})
	}
	return session_seq(directives)
}

fn session_clear_cookie_directive(cfg map[string]cx.Node) cx.Node {
	cookie_name := session_opt_str(cfg, 'cookie-name', '__Host-cxsid')
	path := session_opt_str(cfg, 'cookie-path', '/')
	return session_seq([
		cx.Node(cx.Element{
			name:  'set-cookie'
			attrs: [
				session_str_attr('name', cookie_name),
				session_str_attr('value', ''),
				session_str_attr('max-age', '0'),
				session_str_attr('http-only', 'true'),
				session_str_attr('secure', 'true'),
				session_str_attr('path', path),
			]
		}),
	])
}

// ── lookup helpers (§3.3) ────────────────────────────────────────────
fn session_rec_by_id(id string) ?&SessionRecord {
	reg := session_reg()
	rec := reg.sessions[id] or { return none }
	if rec.state != 'attached' {
		return none // expired/detached resolve to absence (§2.8.2)
	}
	return rec
}

// session_via_of returns the attach transport recorded on a [session]
// value (the FIRST client's via, with cookie taking precedence — a request
// with both is cookie-auth, N-SESSION-7). '' for a zero-client / unknown
// session.
fn session_via_of(rec &SessionRecord) string {
	mut via := ''
	for c in rec.clients {
		if c.via == 'cookie' {
			return 'cookie'
		}
		if via == '' {
			via = c.via
		}
	}
	return via
}

// session_lookup_rec resolves a [session] VALUE arg back to its live
// &SessionRecord by id (the surface passes the materialized value; the
// authoritative state is server-held).
fn session_lookup_rec(arg cx.Node) ?&SessionRecord {
	if arg !is cx.Element {
		return none
	}
	el := arg as cx.Element
	if el.name != 'session' {
		return none
	}
	id := el.attr('id')
	if id == '' {
		return none
	}
	reg := session_reg()
	return reg.sessions[id] or { return none }
}

// ── primitive dispatch (env-free) ────────────────────────────────────
fn session_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	if !name.starts_with('session-') {
		return none
	}
	match name {
		'session-attach' {
			return session_attach_impl(args, 'bearer', false)
		}
		'session-attach-cookie' {
			return session_attach_impl(args, 'cookie', true)
		}
		'session-attach-token' {
			return session_attach_token_impl(args)
		}
		'session-attach-did' {
			return session_attach_did_impl(args)
		}
		'session-detach' {
			return session_detach_impl(args)
		}
		'session-detach-client' {
			return session_detach_client_impl(args)
		}
		'session-touch' {
			return session_touch_impl(args)
		}
		'session-of' {
			return session_of_impl(args)
		}
		'session-by-id' {
			return session_by_id_impl(args)
		}
		'session-by-client' {
			return session_by_client_impl(args)
		}
		'session-from-cookie' {
			return session_from_cookie_impl(args)
		}
		'session-principal' {
			return session_principal_impl(args)
		}
		'session-tenant' {
			return session_tenant_impl(args)
		}
		'session-clients' {
			return session_clients_impl(args)
		}
		'session-valid' {
			return session_valid_impl(args)
		}
		'session-claims' {
			return session_claims_impl(args)
		}
		'session-map-claims' {
			return session_map_claims_impl(args)
		}
		'session-set-cookie' {
			return session_set_cookie_impl(args)
		}
		'session-clear-cookie' {
			return session_clear_cookie_impl(args)
		}
		'session-rotate' {
			return session_rotate_impl(args)
		}
		'session-csrf-token' {
			return session_csrf_token_impl(args)
		}
		'session-csrf-verify' {
			return session_csrf_verify_impl(args)
		}
		else {
			return none
		}
	}
}

// ── lifecycle (§3.2) ─────────────────────────────────────────────────
//
// attach $req $cfg — the [request]-driven path (bearer / cookie). Reads
// the bearer token off Authorization, enforces TLS, then runs the verify
// pipeline.
// session_rebind_guard enforces the immutable-binding contract (§4.2).
// When the request carries a session cookie naming a live session, the new
// token MUST verify to the SAME (principal, tenant); a different binding →
// CXER4805 (refused, never re-keyed). Returns the [err] on a refusal, none
// otherwise (no existing cookie session, or a matching binding). Verifying
// the token here is cheap (the pipeline re-verifies anyway) and the refusal
// must precede any mint.
fn session_rebind_guard(req cx.Node, token string, cfg map[string]cx.Node) ?cx.Node {
	cookie_name := session_opt_str(cfg, 'cookie-name', '__Host-cxsid')
	mut cid := session_read_cookie(req, cookie_name)
	if cid == '' && cookie_name == '__Host-cxsid' {
		cid = session_read_cookie(req, 'cxsid')
	}
	if cid == '' {
		return none
	}
	existing := session_rec_by_id(cid) or { return none }
	// verify the new token + map → (principal, tenant) for the comparison.
	key := session_opt_node(cfg, 'jwks') or { return none }
	now_node := session_opt_node(cfg, 'now') or { session_str('') }
	verified := crypto_jwt_verify([session_str(token), key, now_node,
		cx.Node(cx.Element{ name: '__cx_map__' })])
	if is_err_value(verified) {
		return none // a bad token is the pipeline's CXER4801, not a rebind
	}
	binding := session_map_claims(verified, cfg)
	if is_err_value(binding) {
		return none // unresolvable binding is the pipeline's 4802/4803
	}
	bel := binding as cx.Element
	new_principal := bel.attr('id')
	mut new_tenant := ''
	for it in bel.items {
		if it is cx.Element && it.name == 'tenant' {
			new_tenant = it.attr('id')
		}
	}
	if new_principal != existing.principal_id || new_tenant != existing.tenant_id {
		return mk_err(session_err_rebind_refused, 'E_SESSION_REBIND_REFUSED: token resolves to (${new_principal}, ${new_tenant}) but the live session is bound to (${existing.principal_id}, ${existing.tenant_id}) — the binding is immutable')
	}
	return none
}

fn session_attach_impl(args []cx.Node, via string, issue_csrf bool) cx.Node {
	req := args[0]
	cfg := session_opts(args[1])
	allow_insecure := session_opt_bool(cfg, 'allow-insecure', false)
	// TLS precondition (§2.4 / §2.8.3).
	if !session_request_is_tls(req) && !allow_insecure {
		if via == 'cookie' {
			return mk_err(session_err_cookie_insecure, 'E_SESSION_COOKIE_INSECURE_CONTEXT: cannot issue a Secure session cookie over a non-TLS request')
		}
		return mk_err(session_err_insecure_transport, 'E_SESSION_INSECURE_TRANSPORT: attach refused over a non-TLS transport')
	}
	// cookie-flag refusals are evaluated up-front (§2.8.3) so an unsafe
	// config fails before any verification side effect.
	if via == 'cookie' {
		if e := session_cookie_flags_ok(cfg) {
			return e
		}
	}
	token := session_read_bearer(req)
	if token == '' {
		// affirmative attach with no token → CXER4807 (§3.2 / N-SESSION).
		return mk_err(session_err_no_token, 'E_SESSION_NO_TOKEN: attach found no `Authorization: Bearer` token (use `of` for the no-token=unauthenticated posture)')
	}
	// rebind guard (§2.1 / §2.7 / §4.2 → CXER4805): if the request carries a
	// session cookie naming a LIVE session, the re-presented token MUST
	// resolve to the SAME immutable (principal, tenant) binding — a token
	// for a DIFFERENT subject is a refusal, NOT a silent re-key.
	if e := session_rebind_guard(req, token, cfg) {
		return e
	}
	channel := if via == 'cookie' { 'http' } else { 'cx' }
	result := session_attach_pipeline(token, cfg, via, channel, '', issue_csrf)
	if is_err_value(result) {
		return result
	}
	if via == 'cookie' {
		// pair the [session] with the Set-Cookie directives (§2.8.1).
		rec := session_lookup_rec(result) or { return result }
		return session_seq([result, session_set_cookie_directive(rec, cfg)])
	}
	return result
}

// attach-token $token $cfg $client — the raw-token path (channels/tests).
// TLS is the caller's attestation here (allow-insecure or a transport flag
// on $client) since there is no [request] to inspect.
fn session_attach_token_impl(args []cx.Node) cx.Node {
	token := session_arg_str(args[0]) or {
		return mk_err(session_err_no_token, 'E_SESSION_NO_TOKEN: attach-token expects a token string')
	}
	if token == '' {
		return mk_err(session_err_no_token, 'E_SESSION_NO_TOKEN: empty token')
	}
	cfg := session_opts(args[1])
	allow_insecure := session_opt_bool(cfg, 'allow-insecure', false)
	mut channel := 'cx'
	mut client_id := ''
	mut tls_attested := allow_insecure
	if args.len > 2 {
		cl := session_opts(args[2])
		channel = session_opt_str(cl, 'channel', 'cx')
		client_id = session_opt_str(cl, 'id', '')
		if session_opt_bool(cl, 'tls', false) {
			tls_attested = true
		}
	}
	if !tls_attested {
		return mk_err(session_err_insecure_transport, 'E_SESSION_INSECURE_TRANSPORT: attach-token requires a TLS attestation (allow-insecure or $client.tls)')
	}
	return session_attach_pipeline(token, cfg, 'bearer', channel, client_id, false)
}

// attach-did $did $challenge $sig $cfg $client? — establish a (principal,
// tenant) session by DECENTRALIZED proof-of-control (xap.md R9 / §22.1): the
// client proves it controls the key behind `did` by signing a server-issued
// challenge. Identity is the DID; authority (a VC) is consumed by the PEP
// separately (R9 — DID/VC is the authority-basis transport, not enforcement).
// Mirrors attach-token's posture: TLS-attested, fail-closed, capability-free.
// `cfg` supplies `tenant` (required) and may carry a `vc` (+ `now`, `revoked`)
// that MUST verify valid; the cascade stays identity-agnostic (cx-private#43).
fn session_attach_did_impl(args []cx.Node) cx.Node {
	if args.len < 4 {
		return mk_err(session_err_principal_unresolved, 'E_SESSION_NO_PRINCIPAL: attach-did expects (did, challenge, sig, cfg)')
	}
	did := session_arg_str(args[0]) or {
		return mk_err(session_err_principal_unresolved, 'E_SESSION_NO_PRINCIPAL: attach-did expects a DID string')
	}
	challenge := arg_bytes(args[1]) or {
		return mk_err(session_err_token_rejected, 'E_SESSION_TOKEN_REJECTED: attach-did challenge must be bytes')
	}
	sig := arg_bytes(args[2]) or {
		return mk_err(session_err_token_rejected, 'E_SESSION_TOKEN_REJECTED: attach-did signature must be bytes')
	}
	cfg := session_opts(args[3])
	allow_insecure := session_opt_bool(cfg, 'allow-insecure', false)
	mut channel := 'cx'
	mut client_id := ''
	mut tls_attested := allow_insecure
	if args.len > 4 {
		cl := session_opts(args[4])
		channel = session_opt_str(cl, 'channel', 'cx')
		client_id = session_opt_str(cl, 'id', '')
		if session_opt_bool(cl, 'tls', false) {
			tls_attested = true
		}
	}
	if !tls_attested {
		return mk_err(session_err_insecure_transport, 'E_SESSION_INSECURE_TRANSPORT: attach-did requires a TLS attestation (allow-insecure or \$client.tls)')
	}
	// (verify) — proof of DID key control, delegated to cx-stdlib/did
	// (did:key offline). FAIL-CLOSED: any ambiguity rejects (§2.2).
	key := did_key_bytes(did) or {
		return mk_err(session_err_token_rejected, 'E_SESSION_TOKEN_REJECTED: attach-did cannot recover key for ${did}: ${err.msg()}')
	}
	if sig.len != 64 {
		return mk_err(session_err_token_rejected, 'E_SESSION_TOKEN_REJECTED: attach-did signature must be 64 bytes')
	}
	ok := ed25519.verify(ed25519.PublicKey(key), challenge, sig) or {
		return mk_err(session_err_token_rejected, 'E_SESSION_TOKEN_REJECTED: attach-did proof-of-control failed')
	}
	if !ok {
		return mk_err(session_err_token_rejected, 'E_SESSION_TOKEN_REJECTED: attach-did proof-of-control did not verify')
	}
	// (optional VC) — if cfg carries a credential, it MUST verify valid.
	if vc_node := session_opt_node(cfg, 'vc') {
		now_node := session_opt_node(cfg, 'now') or { session_str('') }
		mut vargs := [vc_node, now_node]
		if r := session_opt_node(cfg, 'revoked') {
			vargs << cx.Node(cx.Element{
				name:  '__cx_map__'
				items: [session_kv('revoked', r)]
			})
		}
		verdict := vc_do_verify(vargs)
		status := if verdict is cx.Element { (verdict as cx.Element).attr('status') } else { '' }
		if status != 'valid' {
			return session_err_with_cause(session_err_token_rejected, 'E_SESSION_TOKEN_REJECTED: attach-did credential is not valid (status=${status})',
				verdict)
		}
	}
	tenant := session_opt_str(cfg, 'tenant', '')
	if tenant == '' {
		return mk_err(session_err_tenant_unresolved, 'E_SESSION_NO_TENANT: attach-did cfg has no `tenant`')
	}
	// (map) — the DID is the principal; build a verified claim-set the shared
	// establishment maps via sub/tid (§2.3).
	claims := cx.Element{
		name:  'claims'
		attrs: [
			cx.Attribute{
				name:  'sub'
				value: cx.ScalarValue(did)
			},
			cx.Attribute{
				name:  'tid'
				value: cx.ScalarValue(tenant)
			},
		]
	}
	return session_establish_from_verified(cx.Node(claims), cfg, 'did', channel, client_id,
		false, '')
}

// detach $session — tears the WHOLE session down (terminal "detached",
// idempotent, §3.2). Releases server state; the clearing Set-Cookie is the
// caller's via clear-cookie / set-cookie on the detached value.
fn session_detach_impl(args []cx.Node) cx.Node {
	mut rec := session_lookup_rec(args[0]) or {
		return session_null() // idempotent — already gone
	}
	mut reg := session_reg()
	subj := session_subject_key(rec.principal_id, rec.tenant_id)
	for c in rec.clients {
		reg.client_idx.delete(c.id)
	}
	reg.by_subject.delete(subj)
	rec.state = 'detached'
	rec.clients = []SessionClient{}
	reg.sessions.delete(rec.id)
	return session_null()
}

// detach-client $session $client-id — removes ONE client; the session
// survives at zero clients (§2.7, N-SESSION-4). Unknown client → absence.
fn session_detach_client_impl(args []cx.Node) cx.Node {
	mut rec := session_lookup_rec(args[0]) or { return session_absence() }
	client_id := session_arg_str(args[1]) or { return session_absence() }
	mut reg := session_reg()
	mut found := false
	mut kept := []SessionClient{}
	for c in rec.clients {
		if c.id == client_id {
			found = true
			reg.client_idx.delete(c.id)
		} else {
			kept << c
		}
	}
	if !found {
		return session_absence() // idempotent removal
	}
	rec.clients = kept
	return session_materialize(rec)
}

// touch $session $client-id — refreshes a client's last-seen (heartbeat).
fn session_touch_impl(args []cx.Node) cx.Node {
	mut rec := session_lookup_rec(args[0]) or { return session_absence() }
	client_id := session_arg_str(args[1]) or { return session_absence() }
	mut found := false
	for mut c in rec.clients {
		if c.id == client_id {
			c.last_seen = 'touched'
			found = true
		}
	}
	if !found {
		return session_absence()
	}
	return session_materialize(rec)
}

// ── resolve (§3.3) ───────────────────────────────────────────────────
//
// of $req-or-conn — resolves the session for a request. Resolution is by
// the request's session reference: a cookie id (the §2.8 opaque-id path,
// shared with from-cookie), else the bearer token's verified subject. NO
// fault on a missing/bad token — absence (§2.5). The Bearer resolution
// mechanism is impl-internal (review-Q2 (a)): we match the live session by
// the bearer token's verified subject when a session exists, else absence.
fn session_of_impl(args []cx.Node) cx.Node {
	req := args[0]
	// cookie id first (the ambient-credential path).
	for cname in ['__Host-cxsid', 'cxsid'] {
		cid := session_read_cookie(req, cname)
		if cid != '' {
			if rec := session_rec_by_id(cid) {
				return session_materialize(rec)
			}
		}
	}
	// bearer token: resolve to the live session ESTABLISHED with this exact
	// token (§3.3). `of` never verifies-to-establish; it only resolves — and
	// it must not trust an unverified token's claims (a forged token with a
	// known subject would otherwise resolve to that subject's session). So we
	// match by the token's one-way FINGERPRINT against the index attach
	// populated after a successful crypto verify: only the genuine,
	// already-verified token resolves; a forged/unknown token → absence. No
	// re-verify (of has no key) and no raw-token retention (§4.6).
	tok := session_read_bearer(req)
	if tok != '' {
		reg := session_reg()
		if sid := reg.token_idx[session_token_fp(tok)] {
			if rec := session_rec_by_id(sid) {
				return session_materialize(rec)
			}
		}
	}
	return session_absence()
}

fn session_by_id_impl(args []cx.Node) cx.Node {
	id := session_arg_str(args[0]) or { return session_absence() }
	rec := session_rec_by_id(id) or { return session_absence() }
	return session_materialize(rec)
}

fn session_by_client_impl(args []cx.Node) cx.Node {
	client_id := session_arg_str(args[0]) or { return session_absence() }
	reg := session_reg()
	sid := reg.client_idx[client_id] or { return session_absence() }
	rec := session_rec_by_id(sid) or { return session_absence() }
	return session_materialize(rec)
}

// from-cookie $req $cfg — the cookie-transport resolver (§2.8.2).
fn session_from_cookie_impl(args []cx.Node) cx.Node {
	req := args[0]
	mut cookie_name := '__Host-cxsid'
	if args.len > 1 {
		cfg := session_opts(args[1])
		cookie_name = session_opt_str(cfg, 'cookie-name', '__Host-cxsid')
	}
	cid := session_read_cookie(req, cookie_name)
	if cid == '' {
		// fall back to the plain name if the configured one missed.
		if cookie_name == '__Host-cxsid' {
			alt := session_read_cookie(req, 'cxsid')
			if alt != '' {
				if rec := session_rec_by_id(alt) {
					return session_materialize(rec)
				}
			}
		}
		return session_absence()
	}
	rec := session_rec_by_id(cid) or { return session_absence() }
	return session_materialize(rec)
}

// ── accessors (§3.4 — pure over a materialized [session]) ────────────
fn session_principal_impl(args []cx.Node) cx.Node {
	el := session_session_element(args[0]) or {
		return mk_err(session_err_invalid, 'E_SESSION_INVALID: principal expects a [session] value')
	}
	for it in el.items {
		if it is cx.Element && it.name == 'principal' {
			return it
		}
	}
	return session_absence()
}

fn session_tenant_impl(args []cx.Node) cx.Node {
	el := session_session_element(args[0]) or {
		return mk_err(session_err_invalid, 'E_SESSION_INVALID: tenant expects a [session] value')
	}
	for it in el.items {
		if it is cx.Element && it.name == 'principal' {
			for c in it.items {
				if c is cx.Element && c.name == 'tenant' {
					return c
				}
			}
		}
	}
	return session_absence()
}

fn session_clients_impl(args []cx.Node) cx.Node {
	el := session_session_element(args[0]) or {
		return mk_err(session_err_invalid, 'E_SESSION_INVALID: clients expects a [session] value')
	}
	mut out := []cx.Node{}
	for it in el.items {
		if it is cx.Element && it.name == 'clients' {
			for c in it.items {
				if c is cx.Element && c.name == 'client' {
					out << cx.Node(c)
				}
			}
		}
	}
	return session_seq(out)
}

// valid — true iff state="attached" AND the token window has not lapsed
// (§3.4). Total; never faults. Lazy expiry recheck against the captured
// `exp` and attach reference clock (§2.6/§4.3).
fn session_valid_impl(args []cx.Node) cx.Node {
	el := session_session_element(args[0]) or { return session_bool(false) }
	state := el.attr('state')
	if state != 'attached' {
		return session_bool(false)
	}
	// authoritative server-side recheck (lazy expiry).
	if rec := session_lookup_rec(args[0]) {
		if rec.state != 'attached' {
			return session_bool(false)
		}
		if rec.exp_secs > 0 && rec.now_secs > 0 && rec.now_secs > rec.exp_secs {
			return session_bool(false)
		}
	}
	return session_bool(true)
}

// claims — the verified claim-set captured at attach (read-only, §3.4).
fn session_claims_impl(args []cx.Node) cx.Node {
	rec := session_lookup_rec(args[0]) or {
		return mk_err(session_err_invalid, 'E_SESSION_INVALID: claims expects a live [session]')
	}
	return rec.claims
}

// map-claims $claim-set $cfg — the standalone PURE mapping (§2.3/§3.4).
fn session_map_claims_impl(args []cx.Node) cx.Node {
	cfg := if args.len > 1 { session_opts(args[1]) } else { map[string]cx.Node{} }
	return session_map_claims(args[0], cfg)
}

// session_session_element returns the [session] Element off arg[0]. An op
// on a detached/expired session → CXER4804 is enforced by the caller (the
// materialized value carries state); accessors operate on the value.
fn session_session_element(arg cx.Node) ?cx.Element {
	if arg is cx.Element && arg.name == 'session' {
		return arg
	}
	return none
}

// ── cookie + CSRF surface (§3.5) ─────────────────────────────────────
fn session_set_cookie_impl(args []cx.Node) cx.Node {
	rec := session_lookup_rec(args[0]) or {
		return mk_err(session_err_invalid, 'E_SESSION_INVALID: set-cookie expects a live [session]')
	}
	cfg := if args.len > 1 { session_opts(args[1]) } else { map[string]cx.Node{} }
	return session_set_cookie_directive(rec, cfg)
}

// clear-cookie $cfg — PURE; builds a clearing Set-Cookie from config only
// (§2.8.4 / §3.5).
fn session_clear_cookie_impl(args []cx.Node) cx.Node {
	cfg := if args.len > 0 { session_opts(args[0]) } else { map[string]cx.Node{} }
	return session_clear_cookie_directive(cfg)
}

// rotate $session — mints a NEW opaque id + fresh CSRF token, invalidates
// the old id, leaves (principal, tenant) UNCHANGED (§2.8.4). No-op on a
// Bearer-only session.
fn session_rotate_impl(args []cx.Node) cx.Node {
	mut rec := session_lookup_rec(args[0]) or {
		return mk_err(session_err_invalid, 'E_SESSION_INVALID: rotate expects a live [session]')
	}
	if session_via_of(rec) != 'cookie' {
		// Bearer-only session → no-op (§2.8.4).
		return session_materialize(rec)
	}
	mut reg := session_reg()
	old_id := rec.id
	new_id := session_mint_id()
	reg.sessions.delete(old_id)
	rec.id = new_id
	rec.csrf_token = session_mint_csrf()
	reg.sessions[new_id] = rec
	for c in rec.clients {
		reg.client_idx[c.id] = new_id
	}
	return session_materialize(rec)
}

// csrf-token $session — PURE read of the synchronizer token (§2.9). Absence
// for a Bearer-only session that minted none.
fn session_csrf_token_impl(args []cx.Node) cx.Node {
	el := session_session_element(args[0]) or {
		return mk_err(session_err_invalid, 'E_SESSION_INVALID: csrf-token expects a [session] value')
	}
	for it in el.items {
		if it is cx.Element && it.name == 'csrf-token' && it.items.len > 0 {
			return it.items[0]
		}
	}
	return session_absence()
}

// csrf-verify $req $session $cfg — constant-time compare of the submitted
// CSRF token against the session-stored synchronizer token (§2.9). No-op
// PASS for a Bearer-authenticated session (N-SESSION-7). Missing → 4808;
// mismatch → 4809.
fn session_csrf_verify_impl(args []cx.Node) cx.Node {
	req := args[0]
	rec := session_lookup_rec(args[1]) or {
		return mk_err(session_err_invalid, 'E_SESSION_INVALID: csrf-verify expects a live [session]')
	}
	// Bearer-authenticated session → no-op pass (keyed on `via`, never a
	// client flag, N-SESSION-7). A session with NO cookie client is
	// CSRF-exempt by credential shape.
	if session_via_of(rec) != 'cookie' {
		return session_materialize(rec)
	}
	csrf_header := if args.len > 2 {
		cfg := session_opts(args[2])
		session_opt_str(cfg, 'csrf-header', 'X-CSRF-Token')
	} else {
		'X-CSRF-Token'
	}
	submitted := session_read_header(req, csrf_header)
	if submitted == '' {
		return mk_err(session_err_csrf_missing, 'E_SESSION_CSRF_MISSING: cookie-authenticated state-changing intent carries no CSRF token')
	}
	// constant-time compare against the server-stored token (§2.9).
	if !crypto_ct_equal(submitted.bytes(), rec.csrf_token.bytes()) {
		return mk_err(session_err_csrf_mismatch, 'E_SESSION_CSRF_MISMATCH: submitted CSRF token does not match the session synchronizer token')
	}
	return session_materialize(rec)
}
