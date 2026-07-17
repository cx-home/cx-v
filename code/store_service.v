@[has_globals]
module code

import cx
import sync
import os
import time

// #105 Phase-2 service tier — daemon lifecycle, brick 1: service configuration.
//
// Parses + validates the `cxstore.service.cx` config document (spec
// spec/02-working/cxstore_service_tier_phase2.md, Appendix A) into a typed
// ServiceConfig, failing fast with a structured diagnostic on any invalid
// config (§2.2 — no partial serve). Config is a CX document (owner decision 5a),
// so it parses through the data reader and dogfoods CX.
//
// This brick covers parse + structural validation only. Wiring the bind/listen
// loop, auth-provider runtime, and observability exporters are subsequent
// bricks; the validated shape they consume is fixed here.

const e_svc_cfg = 'cx-err:CXER1711' // E_SVC_CONFIG_INVALID (service-tier config; #198 — distinct from CXER1140 E_STORE_HANDLE_RACE, which it previously collided with). Startup/CLI diagnostic; rides the wire ONLY on the §3.13 config-reload op (#251).

// ServiceConfig is the validated daemon configuration.
pub struct ServiceConfig {
pub:
	bind          string // host:port for the CSRP listener
	tls           ?TlsConfig
	grpc          GrpcConfig
	stores        []StoreMount
	auth          AuthConfig
	observability ObsConfig
	limits        LimitConfig
	query_pool    int = 4
	// #187: per-connection read timeout (ms) — a client that stalls / trickles a
	// request body is dropped after this budget, so a slowloris can't hold a
	// worker (the confirmed 6-connection pool-starvation DoS). Default 30s; 0
	// disables. Parsed from the optional [timeouts read-ms=…] section.
	read_timeout_ms i64 = 30000
	// #234.1: HTTP/1.1 keep-alive idle timeout (ms) — how long an idle persistent
	// connection is held open between requests before the server closes it (CSRP
	// §5.2 "idle 60s"). Default 60s; 0 disables keep-alive (single-turn close, the
	// pre-#234 behavior). Parsed from the optional [timeouts idle-ms=…] section.
	idle_timeout_ms i64 = 60000
	// #233: graceful-drain grace (ms) — on SIGTERM/SIGINT the daemon flips readiness
	// false but KEEPS THE LISTENER OPEN for this long, so a load-balancer readiness
	// probe still connects and observes [ready [accepting false]] (data ops get 503)
	// and de-routes, before the listener closes and in-flight requests drain (§2.5).
	// Default 5s. Parsed from the optional [timeouts drain-ms=…] section.
	drain_ms i64 = 5000
}

pub struct TlsConfig {
pub:
	cert string // cert PEM content, a file path, or ${env:VAR} (resolved at parse/load)
	key  string // key PEM content, a file path, or ${env:VAR}
	ca   string // optional client-CA PEM/path — non-empty enables mTLS (require-client-cert)
}

pub struct GrpcConfig {
pub:
	enabled bool
	addr    string
}

// StoreMount is one mounted store (store-per-tenant: one mount per tenant, §3.3).
pub struct StoreMount {
pub:
	name string
	url  string
}

// AuthConfig records the configured providers (names, for the capabilities
// advert) and the resolved AuthContext the daemon enforces. `enforce` is true
// iff any provider is present (an absent/empty [auth] → open dev mode).
pub struct AuthConfig {
pub:
	providers []string // recognized provider kinds present, in source order
	context   AuthContext
}

pub struct ObsConfig {
pub:
	otel_enabled  bool
	otel_endpoint string
	log_format    string = 'cx'
}

const svc_auth_kinds = ['static', 'jwt', 'did', 'oidc', 'scrape']

// parse_service_config parses a `cxstore.service.cx` document and returns a
// validated ServiceConfig, or a structured error naming the first problem.
pub fn parse_service_config(src string) !ServiceConfig {
	doc := cx.parse(src) or { return error('${e_svc_cfg}: unparseable config: ${err.msg()}') }
	if doc.elements.len == 0 {
		return error('${e_svc_cfg}: empty config document')
	}
	root_node := doc.elements[0]
	if root_node !is cx.Element {
		return error('${e_svc_cfg}: config root must be a `[cxstore-service …]` element')
	}
	root := root_node as cx.Element
	if root.name != 'cxstore-service' {
		return error('${e_svc_cfg}: config root must be `[cxstore-service …]`, got `[${root.name}]`')
	}

	mut bind := ''
	mut tls := ?TlsConfig(none)
	mut grpc := GrpcConfig{}
	mut stores := []StoreMount{}
	mut auth_cfg := AuthConfig{}
	mut obs := ObsConfig{
		log_format: 'cx'
	}
	mut limits := LimitConfig{}
	mut query_pool := 4
	mut read_timeout_ms := i64(30000)
	mut idle_timeout_ms := i64(60000)
	mut drain_ms := i64(5000)

	for child in svc_child_elements(root) {
		// #203.2: attr-EXACT validation — an unknown ATTRIBUTE in a known section
		// is a fast-fail error, not a silent drop (previously only unknown SECTIONS
		// rejected, so a misspelled/unsupported attr — key-path, discovery, methods,
		// challenge — quietly parsed while losing the directive).
		svc_check_section_attrs(child)!
		match child.name {
			'bind' {
				bind = child.attr('addr')
			}
			'timeouts' {
				// #187: per-connection read timeout (ms). 0 disables.
				if child.has_attr('read-ms') {
					read_timeout_ms = svc_int(child.attr_val('read-ms') or { cx.ScalarValue(i64(30000)) })
					if read_timeout_ms < 0 {
						return error('${e_svc_cfg}: [timeouts read-ms] must be ≥ 0 (0 disables)')
					}
				}
				// #234.1: keep-alive idle timeout (ms). 0 disables keep-alive.
				if child.has_attr('idle-ms') {
					idle_timeout_ms = svc_int(child.attr_val('idle-ms') or { cx.ScalarValue(i64(60000)) })
					if idle_timeout_ms < 0 {
						return error('${e_svc_cfg}: [timeouts idle-ms] must be ≥ 0 (0 disables keep-alive)')
					}
				}
				// #233: graceful-drain grace (ms) — listener stays open this long.
				if child.has_attr('drain-ms') {
					drain_ms = svc_int(child.attr_val('drain-ms') or { cx.ScalarValue(i64(5000)) })
					if drain_ms < 0 {
						return error('${e_svc_cfg}: [timeouts drain-ms] must be ≥ 0')
					}
				}
			}
			'tls' {
				// #199: resolve ${env:VAR} references so secrets need not be inlined.
				cert := svc_resolve_env(child.attr('cert'))!
				key := svc_resolve_env(child.attr('key'))!
				if cert == '' || key == '' {
					return error('${e_svc_cfg}: [tls] requires both `cert` and `key`')
				}
				ca := if child.attr('ca') != '' { svc_resolve_env(child.attr('ca'))! } else { '' }
				tls = TlsConfig{
					cert: cert
					key:  key
					ca:   ca
				}
			}
			'grpc' {
				grpc = GrpcConfig{
					enabled: svc_bool_attr(child, 'enabled')
					addr:    child.attr('addr')
				}
				if grpc.enabled && grpc.addr == '' {
					return error('${e_svc_cfg}: [grpc enabled=true] requires `addr`')
				}
			}
			'stores' {
				stores = svc_parse_stores(child)!
			}
			'auth' {
				auth_cfg = svc_parse_auth(child)!
			}
			'observability' {
				obs = svc_parse_obs(child)
			}
			'limits' {
				limits = svc_parse_limits(child)
			}
			'workers' {
				if child.has_attr('query-pool') {
					qp := (child.attr_val('query-pool') or { cx.ScalarValue(i64(0)) })
					query_pool = svc_int(qp)
					if query_pool < 1 {
						return error('${e_svc_cfg}: [workers query-pool] must be ≥ 1')
					}
				}
			}
			else {
				return error('${e_svc_cfg}: unknown config section `[${child.name}]`')
			}
		}
	}

	// Cross-section validation.
	if bind == '' {
		return error('${e_svc_cfg}: missing required `[bind addr=…]`')
	}
	if !svc_is_host_port(bind) {
		return error('${e_svc_cfg}: [bind addr] must be `host:port`, got `${bind}`')
	}
	if stores.len == 0 {
		return error('${e_svc_cfg}: at least one `[stores [store …]]` mount is required')
	}
	if grpc.enabled && grpc.addr == bind {
		return error('${e_svc_cfg}: gRPC addr must differ from the CSRP bind addr')
	}

	return ServiceConfig{
		bind:          bind
		tls:           tls
		grpc:          grpc
		stores:        stores
		auth:          auth_cfg
		observability:   obs
		limits:          limits
		query_pool:      query_pool
		read_timeout_ms: read_timeout_ms
		idle_timeout_ms: idle_timeout_ms
		drain_ms:        drain_ms
	}
}

// svc_parse_limits reads the optional [limits …] section; omitted attrs keep the
// generous default-on LimitConfig values.
fn svc_parse_limits(el cx.Element) LimitConfig {
	mut c := LimitConfig{}
	if el.has_attr('per-principal-concurrency') {
		c = LimitConfig{
			...c
			per_principal_conc: svc_int(el.attr_val('per-principal-concurrency') or { cx.ScalarValue(i64(0)) })
		}
	}
	if el.has_attr('per-principal-rate') {
		c = LimitConfig{
			...c
			per_principal_rate: svc_f64(el.attr_val('per-principal-rate') or { cx.ScalarValue(i64(0)) })
		}
	}
	if el.has_attr('per-principal-burst') {
		c = LimitConfig{
			...c
			per_principal_burst: svc_f64(el.attr_val('per-principal-burst') or { cx.ScalarValue(i64(0)) })
		}
	}
	if el.has_attr('pre-auth-rate') {
		c = LimitConfig{
			...c
			pre_auth_rate: svc_f64(el.attr_val('pre-auth-rate') or { cx.ScalarValue(i64(0)) })
		}
	}
	if el.has_attr('pre-auth-burst') {
		c = LimitConfig{
			...c
			pre_auth_burst: svc_f64(el.attr_val('pre-auth-burst') or { cx.ScalarValue(i64(0)) })
		}
	}
	return c
}

// svc_f64 coerces a scalar value to f64.
fn svc_f64(v cx.ScalarValue) f64 {
	return match v {
		f64 { v }
		i64 { f64(v) }
		string { v.f64() }
		else { 0.0 }
	}
}

// svc_child_elements returns the Element children of `e`, in order.
fn svc_child_elements(e cx.Element) []cx.Element {
	mut out := []cx.Element{}
	for it in e.items {
		if it is cx.Element {
			out << it
		}
	}
	return out
}

fn svc_parse_stores(stores_el cx.Element) ![]StoreMount {
	mut out := []StoreMount{}
	mut seen := map[string]bool{}
	for s in svc_child_elements(stores_el) {
		if s.name != 'store' {
			return error('${e_svc_cfg}: [stores] may only contain [store …], got `[${s.name}]`')
		}
		name := s.attr('name')
		url := s.attr('url')
		if name == '' {
			return error('${e_svc_cfg}: [store] requires a `name`')
		}
		if url == '' {
			return error('${e_svc_cfg}: [store name=${name}] requires a `url`')
		}
		if name in seen {
			return error('${e_svc_cfg}: duplicate store name `${name}`')
		}
		seen[name] = true
		out << StoreMount{
			name: name
			url:  url
		}
	}
	return out
}

// svc_normalize_secret_hash accepts a static-token secret-hash in either the
// Appendix-A `sha256:<64-hex>` form or bare `<64-hex>`, and returns the bare
// lowercase-hex digest svc_authenticate compares against (#188). An unknown algo
// prefix or a non-64-hex digest is a fast-fail config error (§2.2) — never a
// silently-non-authenticating token.
fn svc_normalize_secret_hash(raw string) !string {
	mut hexpart := raw
	if idx := raw.index(':') {
		algo := raw[..idx]
		if algo != 'sha256' {
			return error('secret-hash: unsupported algorithm `${algo}:` (only `sha256:` or bare hex)')
		}
		hexpart = raw[idx + 1..]
	}
	hexpart = hexpart.to_lower()
	if hexpart.len != 64 {
		return error('secret-hash: expected 64 hex chars (sha256), got ${hexpart.len}')
	}
	for c in hexpart {
		is_hex := (c >= `0` && c <= `9`) || (c >= `a` && c <= `f`)
		if !is_hex {
			return error('secret-hash: non-hex character in digest')
		}
	}
	return hexpart
}

// svc_check_section_attrs enforces attr-exact validation (#203.2): every
// attribute of a known top-level config section must be in that section's
// allowlist, else a fast-fail error (§2.2) — never a silently-dropped directive.
// Sections with nested elements (stores/auth/observability/limits) carry no
// top-level attrs here; their inner elements are validated by their sub-parsers.
fn svc_check_section_attrs(el cx.Element) ! {
	allowed := match el.name {
		'bind' { ['addr'] }
		'tls' { ['cert', 'key', 'ca'] }
		'grpc' { ['enabled', 'addr'] }
		'timeouts' { ['read-ms', 'idle-ms', 'drain-ms'] }
		'workers' { ['query-pool'] }
		else { return } // stores/auth/observability/limits: no top-level attrs to gate
	}
	for a in el.attrs {
		if a.name !in allowed {
			return error('${e_svc_cfg}: unknown attribute `${a.name}` in `[${el.name}]` (recognized: ${allowed.join(", ")}) — refusing to silently drop it')
		}
	}
}

// svc_resolve_env substitutes a `${env:VAR}` config value with the environment
// variable's contents (#199 — "never inline secrets in the config"). A bare value
// (no `${env:…}`) passes through unchanged. A referenced-but-unset env var is a
// fast-fail config error (§2.2). This lets an operator externalize any
// secret-bearing field — TLS key/passphrase PEM, signing material — into the
// environment instead of the config document.
fn svc_resolve_env(raw string) !string {
	prefix := r'${env:'
	if !raw.starts_with(prefix) || !raw.ends_with('}') {
		return raw
	}
	varname := raw[prefix.len..raw.len - 1]
	if varname == '' {
		return error('${e_svc_cfg}: empty env-var reference `${raw}`')
	}
	val := os.getenv(varname)
	if val == '' {
		return error('${e_svc_cfg}: config references env var `${varname}` which is unset (or empty)')
	}
	return val
}

fn svc_parse_auth(auth_el cx.Element) !AuthConfig {
	mut providers := []string{}
	mut static_tokens := []StaticToken{}
	mut jwt := JwtProvider{}
	mut did := DidProvider{}
	mut oidc := OidcProvider{}
	for p in svc_child_elements(auth_el) {
		if p.name !in svc_auth_kinds {
			return error('${e_svc_cfg}: unknown auth provider `[${p.name}]` (expected one of ${svc_auth_kinds})')
		}
		providers << p.name
		if p.name == 'jwt' {
			// [jwt issuer=… audience=… jwks="<json>" roles-claim=… tenant-claim=…]
			// #199: jwks may be inline JSON or ${env:VAR} (externalized key material).
			jwks_json := svc_resolve_env(p.attr('jwks'))!
			if jwks_json == '' {
				return error('${e_svc_cfg}: [jwt] requires `jwks` (a JWKS JSON document)')
			}
			// #206.3 / §3.1: iss/aud verification is mandated. Require `issuer`
			// (without it any signature-valid token from any issuer authenticates);
			// loudly warn on a missing `audience` (a token minted for another
			// audience would otherwise be accepted) rather than silently allowing it.
			if p.attr('issuer') == '' {
				return error('${e_svc_cfg}: [jwt] requires `issuer` (§3.1 mandates issuer verification; without it any issuer\'s token is accepted)')
			}
			if p.attr('audience') == '' {
				eprintln('cxstore: WARNING [jwt issuer="${p.attr('issuer')}"] has no `audience` — tokens minted for any audience will be accepted (§3.1 recommends audience binding)')
			}
			roles_claim := if p.attr('roles-claim') != '' { p.attr('roles-claim') } else { 'roles' }
			tenant_claim := if p.attr('tenant-claim') != '' { p.attr('tenant-claim') } else { 'tenant' }
			jwt = JwtProvider{
				enabled:      true
				jwks:         crypto_jwks_parse(jwks_json)
				issuer:       p.attr('issuer')
				audience:     p.attr('audience')
				roles_claim:  roles_claim
				tenant_claim: tenant_claim
			}
		}
		if p.name == 'did' {
			// [did [grant did="did:key:z…" roles="reader" tenant="docs"] …]
			mut grants := []DidGrant{}
			for g in svc_child_elements(p) {
				if g.name != 'grant' {
					continue
				}
				gdid := g.attr('did')
				if gdid == '' {
					return error('${e_svc_cfg}: [grant] requires `did`')
				}
				grants << DidGrant{
					did:    gdid
					roles:  g.attr('roles').replace(',', ' ').fields()
					tenant: g.attr('tenant')
				}
			}
			mut ttl := i64(300)
			if p.has_attr('cache-ttl') {
				ttl = svc_int(p.attr_val('cache-ttl') or { cx.ScalarValue(i64(300)) })
				if ttl < 1 {
					ttl = 300
				}
			}
			// #189: honor `methods=` (allowed DID methods; default key,web) and
			// `audience=` (DID-JWT aud binding). `challenge=true` is NOT silently
			// inert — full nonce challenge-response is a stateful protocol addition
			// (tracked); until it lands, fail-fast so an operator relying on it is
			// not lulled by an accepted-but-ignored knob. Audience binding is the
			// current cross-service-replay defense.
			mut methods := ['key', 'web']
			if p.attr('methods') != '' {
				methods = p.attr('methods').replace(',', ' ').fields()
				for m in methods {
					if m !in ['key', 'web'] {
						return error('${e_svc_cfg}: [did] unknown method `${m}` (supported: key, web)')
					}
				}
			}
			if p.has_attr('challenge') && svc_bool_attr(p, 'challenge') {
				return error('${e_svc_cfg}: [did challenge=true] is not yet implemented (nonce challenge-response is a tracked follow-up); use `audience=` for cross-service-replay binding')
			}
			did = DidProvider{
				enabled:        true
				grants:         grants
				methods:        methods
				audience:       p.attr('audience')
				cache_ttl_secs: ttl
				cache:          new_key_cache()
			}
		}
		if p.name == 'oidc' {
			// [oidc issuer="https://idp" audience= roles-claim= tenant-claim= cache-ttl=300]
			iss := p.attr('issuer')
			if iss == '' {
				return error('${e_svc_cfg}: [oidc] requires `issuer`')
			}
			mut ottl := i64(300)
			if p.has_attr('cache-ttl') {
				ottl = svc_int(p.attr_val('cache-ttl') or { cx.ScalarValue(i64(300)) })
				if ottl < 1 {
					ottl = 300
				}
			}
			oidc = OidcProvider{
				enabled:        true
				issuer:         iss
				audience:       p.attr('audience')
				roles_claim:    if p.attr('roles-claim') != '' { p.attr('roles-claim') } else { 'roles' }
				tenant_claim:   if p.attr('tenant-claim') != '' { p.attr('tenant-claim') } else { 'tenant' }
				cache_ttl_secs: ottl
				cache:          new_key_cache()
			}
		}
		if p.name == 'static' || p.name == 'scrape' {
			// [static [token id=… secret-hash=… roles="…" tenant="…"] …]
			for t in svc_child_elements(p) {
				if t.name != 'token' {
					continue
				}
				id := t.attr('id')
				secret_hash_raw := t.attr('secret-hash')
				if id == '' || secret_hash_raw == '' {
					return error('${e_svc_cfg}: [token] requires `id` and `secret-hash`')
				}
				// #188: accept the Appendix-A `sha256:<hex>` form (canonical) AND bare
				// hex, normalizing to the bare lowercase-hex digest that
				// svc_authenticate compares against. Reject an unknown algo prefix or
				// a malformed digest fast (§2.2 fail-fast config), rather than silently
				// failing to authenticate a spec-conformant config.
				secret_hash := svc_normalize_secret_hash(secret_hash_raw) or {
					return error('${e_svc_cfg}: [token id="${id}"] ${err.msg()}')
				}
				mut roles := t.attr('roles').replace(',', ' ').fields()
				if p.name == 'scrape' && roles.len == 0 {
					roles = ['metrics']
				}
				static_tokens << StaticToken{
					id:          id
					secret_hash: secret_hash
					roles:       roles
					tenant:      t.attr('tenant')
				}
			}
		}
	}
	return AuthConfig{
		providers: providers
		context:   AuthContext{
			enforce:       providers.len > 0
			static_tokens: static_tokens
			jwt:           jwt
			did:           did
			oidc:          oidc
		}
	}
}

fn svc_parse_obs(obs_el cx.Element) ObsConfig {
	mut otel_enabled := false
	mut otel_endpoint := ''
	mut log_format := 'cx'
	for c in svc_child_elements(obs_el) {
		match c.name {
			'otel' {
				otel_enabled = svc_bool_attr(c, 'enabled')
				otel_endpoint = c.attr('endpoint')
			}
			'log' {
				if c.attr('format') != '' {
					log_format = c.attr('format')
				}
			}
			else {}
		}
	}
	return ObsConfig{
		otel_enabled:  otel_enabled
		otel_endpoint: otel_endpoint
		log_format:    log_format
	}
}

fn svc_bool_attr(e cx.Element, name string) bool {
	v := e.attr_val(name) or { return false }
	return match v {
		bool { v }
		string { v == 'true' }
		else { false }
	}
}

fn svc_int(v cx.ScalarValue) int {
	return match v {
		i64 { int(v) }
		f64 { int(v) }
		string { v.int() }
		else { 0 }
	}
}

// svc_is_host_port checks `host:port` shape with a numeric 1..65535 port.
fn svc_is_host_port(s string) bool {
	idx := s.last_index(':') or { return false }
	host := s[..idx]
	port := s[idx + 1..]
	if host == '' || port == '' {
		return false
	}
	if !port.bytes().all(it >= `0` && it <= `9`) {
		return false
	}
	p := port.int()
	return p >= 1 && p <= 65535
}

// ── Daemon lifecycle state + health/ready endpoints (brick 2) ────────────────
//
// ServiceState is the daemon's runtime readiness model, SHARED across the accept
// loop, every worker thread, and the signal handler — so all access is guarded
// by `mu`. `ready` flips true once bind + store-open succeed; `draining` flips
// true on graceful shutdown (§2.5), which also forces readiness false so a load
// balancer stops routing while in-flight requests finish. Always construct via
// new_service_state() (a nil `mu` would crash on first lock).
@[heap]
pub struct ServiceState {
mut:
	mu       &sync.Mutex = unsafe { nil }
	ready    bool
	draining bool
	inflight int
}

// new_service_state allocates a ServiceState with its mutex ready.
pub fn new_service_state() &ServiceState {
	return &ServiceState{
		mu: sync.new_mutex()
	}
}

// accepting_locked is the lock-free predicate; callers MUST hold `mu` (keeps the
// public methods non-reentrant — locking accepting() inside enter_request() would
// self-deadlock on the non-recursive mutex).
fn (s &ServiceState) accepting_locked() bool {
	return s.ready && !s.draining
}

// mark_ready records that bind + store-open succeeded (sd_notify READY=1, §2.3).
pub fn (mut s ServiceState) mark_ready() {
	s.mu.lock()
	s.ready = true
	s.mu.unlock()
}

// begin_drain starts graceful shutdown: stop advertising readiness, mark
// draining so new work is refused while in-flight requests finish (§2.5).
pub fn (mut s ServiceState) begin_drain() {
	s.mu.lock()
	s.draining = true
	s.ready = false
	s.mu.unlock()
}

// accepting reports whether the daemon should take new traffic.
pub fn (mut s ServiceState) accepting() bool {
	s.mu.lock()
	r := s.accepting_locked()
	s.mu.unlock()
	return r
}

// in_flight returns the current in-flight request count (test/observability).
pub fn (mut s ServiceState) in_flight() int {
	s.mu.lock()
	n := s.inflight
	s.mu.unlock()
	return n
}

// svc_health_response is the liveness body — the process is up if it can answer.
pub fn svc_health_response() string {
	return '[health [status "ok"]]'
}

// ready_response is the readiness body, reflecting the live drain state.
pub fn (mut s ServiceState) ready_response() string {
	s.mu.lock()
	acc := s.accepting_locked()
	dr := s.draining
	s.mu.unlock()
	return '[ready [accepting ${acc}] [draining ${dr}]]'
}

// svc_lifecycle_path reports whether (method, path) is an unauthenticated
// lifecycle endpoint this layer owns (health/ready) — the listen loop checks
// this BEFORE auth + the CSRP store router.
pub fn svc_lifecycle_path(method string, path string) bool {
	return method == 'GET' && (path == csrp_base + 'health' || path == csrp_base + 'ready')
}

// svc_route_lifecycle returns the CX response body for a lifecycle endpoint, or
// none if the request is not a lifecycle endpoint (caller falls through to the
// authenticated CSRP store router). Health/ready are unauthenticated (§2.4).
pub fn svc_route_lifecycle(method string, path string, mut state ServiceState) ?string {
	if method != 'GET' {
		return none
	}
	if path == csrp_base + 'health' {
		return svc_health_response()
	}
	if path == csrp_base + 'ready' {
		return state.ready_response()
	}
	return none
}

// ── Graceful-drain sequence (brick 3) ────────────────────────────────────────
//
// On SIGTERM the daemon flips readiness false (begin_drain), refuses NEW work,
// and lets in-flight requests finish up to a bounded deadline before exit (§2.5).
// The signal/timer wiring is the listen-loop brick; the testable core is the
// in-flight counter + the two predicates below.

// enter_request admits a request iff the daemon is accepting; returns false when
// draining/not-ready (the caller then refuses with 503). On true it increments
// the in-flight count — pair with exit_request.
pub fn (mut s ServiceState) enter_request() bool {
	s.mu.lock()
	defer {
		s.mu.unlock()
	}
	if !s.accepting_locked() {
		return false
	}
	s.inflight++
	return true
}

// exit_request marks one in-flight request complete.
pub fn (mut s ServiceState) exit_request() {
	s.mu.lock()
	if s.inflight > 0 {
		s.inflight--
	}
	s.mu.unlock()
}

// drain_complete reports whether a draining daemon may exit now: it is draining
// AND either all in-flight requests finished OR the bounded deadline elapsed
// (the loop passes deadline_reached; a second signal forces it true — §2.5).
pub fn (mut s ServiceState) drain_complete(deadline_reached bool) bool {
	s.mu.lock()
	defer {
		s.mu.unlock()
	}
	if !s.draining {
		return false
	}
	return s.inflight == 0 || deadline_reached
}

// ── Request dispatch (brick 4) ───────────────────────────────────────────────
//
// svc_handle_request is the daemon's per-request router, composing the lifecycle
// state (bricks 2-3) with the CSRP store router (#78). Dispatch order:
//   1. health/ready  — unauthenticated, served regardless of drain state (§2.4).
//   2. capabilities  — discovery; always served.
//   3. data ops      — refused with 503 while draining / before ready; otherwise
//                      counted in-flight and delegated to store_csrp_route.
// AuthN/authZ is inserted between steps 2 and 3 by the authZ sub-area; until then
// the daemon enforces only lifecycle/drain semantics, not permissions.
// Service-tier admission failures reuse the CSRP §4 protocol codes by HTTP
// semantics (RFC 9110/6585), not by server-internal reason: 429 = the client is
// over its allowance (rate OR concurrency OR the pre-auth cap — all → back off +
// Retry-After), 503 = the server is not in a state to serve (draining/not-ready/
// overloaded). The which-limiter-tripped detail lives in /metrics + logs, not the
// wire. (#105 item-1 reconciliation; replaces the earlier 1730/1731/1732 block.)
const e_svc_unavail = 'cx-err:CXER1708' // E_CSRP_SERVER_UNAVAILABLE (503 — draining/not ready)
const e_svc_rate_limited = 'cx-err:CXER1706' // E_CSRP_RATE_LIMITED (429 — rate or concurrency)
const e_svc_too_large = 'cx-err:CXER1705' // E_CSRP_PAYLOAD_TOO_LARGE (413 — over max-request-bytes)
const svc_max_request_bytes = i64(16777216) // 16 MiB request body cap (#196; advertised in capabilities §3.1)

// ServeContext is the per-daemon serving state svc_handle_request needs: the
// mounted stores (name → handle), the resolved auth config, and the DoS-fairness
// limiter (nil = unlimited; the CLI always sets it → default-on in production).
pub struct ServeContext {
pub:
	mounts          map[string]cx.Node
	auth            AuthContext
	limiter         &Limiter         = unsafe { nil }
	metrics         &MetricsRegistry = unsafe { nil } // observability; nil = not recording
	tracer          &TraceExporter   = unsafe { nil } // OTel; nil = no trace ids/spans
	read_timeout_ms i64 // #187 per-connection read deadline (0 = none)
	idle_timeout_ms i64 // #234.1 keep-alive idle timeout between requests (0 = single-turn close)
	log_json        bool // #207.2 — render request logs as JSON (from [observability [log format="json"]])
	// #251 config reload (§2.6): the live hot-config box. When set, dispatch
	// resolves the CURRENT snapshot per request (svc_ctx_live) instead of the
	// startup-frozen fields above; nil (tests / embedded) = startup-static.
	cfgbox &SvcConfigBox = unsafe { nil }
	// #251: executes one reload (captures path + deps at daemon startup). nil =
	// the op is not served here (404 CXER1709 — embedded/test contexts).
	reloader fn () ReloadOutcome = unsafe { nil }
}

// svc_ctx_live projects the current hot-config snapshot (§2.6) over a
// ServeContext: auth, tracer, timeouts, and log format come from the box; the
// startup-frozen identity (mounts, limiter, metrics — mutated in place or
// restart-only) passes through. With no box the context is returned unchanged
// (the pre-#251 static behavior).
pub fn svc_ctx_live(ctx ServeContext) ServeContext {
	if ctx.cfgbox == unsafe { nil } {
		return ctx
	}
	mut box := ctx.cfgbox
	s := box.snapshot()
	return ServeContext{
		...ctx
		auth:            s.auth.context
		tracer:          s.tracer
		read_timeout_ms: s.read_timeout_ms
		idle_timeout_ms: s.idle_timeout_ms
		log_json:        s.log_json
	}
}

// svc_handle_request is the daemon's per-request router over the mounted stores
// (name → handle). CSRP paths are `/cx-store/v1/<op>` (sole-store form) or
// `/cx-store/v1/<store-name>/<op>` (named form — store-per-tenant, §3.3). Store
// selection + the principal→tenant authorization together enforce tenant
// isolation.
pub fn svc_handle_request(req cx.Element, mut state ServiceState, ctx_in ServeContext) cx.Node {
	// #251: resolve the CURRENT hot-config snapshot once per request — the
	// request runs to completion under this view; a mid-request reload is
	// observed by the NEXT request (§2.6).
	ctx := svc_ctx_live(ctx_in)
	method := http_attr(req, 'method') or { 'GET' }
	path := http_attr(req, 'path') or { '/' }
	// /metrics — daemon-level Prometheus scrape, gated by the `metrics` scope
	// (decision 6a). Store-independent; not part of the CSRP `/cx-store/v1/`
	// surface, so it is matched before path-parsing. Open when not enforcing.
	// #206.4: count it against the pre-auth admission cap — an unauthenticated
	// /metrics flood forces sha256 + the full provider chain per hit, so it must
	// not bypass the global pre-auth bucket (only health/ready are exempt).
	if method == 'GET' && path == '/metrics' {
		if ctx.limiter != unsafe { nil } {
			mut lim := ctx.limiter
			if !lim.allow_pre_auth() {
				return csrp_resp_retry(429, '[err code="${e_svc_rate_limited}" message="E_CSRP_RATE_LIMITED: too many requests"]', 1)
			}
		}
		return svc_serve_metrics(req, ctx)
	}
	if ctx.metrics == unsafe { nil } {
		mut meta0 := RequestMeta{}
		return svc_dispatch_request(req, mut state, ctx, mut meta0)
	}
	// Instrumented path: time the dispatch, then record one bounded-cardinality
	// sample (Appendix F.1) + emit one structured log record (F.3). Labels are
	// normalized so a bogus path/store-name can never inflate the series count.
	mut m := ctx.metrics
	mut meta := RequestMeta{}
	// Trace context (F.2): continue an inbound trace or mint a root. Ids are
	// always minted (so logs correlate); only OTLP export is gated by the tracer.
	has_tracer := ctx.tracer != unsafe { nil }
	tc := svc_trace_for_request(req, if has_tracer { ctx.tracer.enabled } else { false })
	meta.trace_id = tc.trace_id
	m.enter_inflight()
	started := time.now()
	resp := svc_dispatch_request(req, mut state, ctx, mut meta)
	ended := time.now()
	dur := ended - started
	m.exit_inflight()
	sname, op := svc_path_parts(path) or { '', '' }
	ep := obs_norm_endpoint(if op == '' { svc_metric_op_for_path(path) } else { op })
	// #201: resolve the sole-store shorthand to the real mount name so the sole-
	// store form is not misattributed to `_unknown` in metrics/logs/spans.
	store := obs_norm_store(svc_resolve_sname(sname, ctx.mounts), ctx.mounts)
	bytes_in := u64(http_body_octets(req).len)
	bytes_out := u64(svc_response_body(resp).len)
	dur_secs := dur.seconds()
	status := svc_resp_status(resp)
	m.record_request(ep, status, store, bytes_in, bytes_out, dur_secs)
	if !svc_log_sampled_out(ep) {
		eprintln(svc_format_log(ep, store, status, dur_secs * 1000.0, bytes_in,
			bytes_out, meta.role, meta.trace_id, started.unix(), ctx.log_json))
	}
	if has_tracer {
		ctx.tracer.export(Span{
			tc:       tc
			name:     'csrp.${ep}'
			start_ns: started.unix_nano()
			end_ns:   ended.unix_nano()
			status:   status
			attrs:    {
				'endpoint':        ep
				'store':           store
				'principal.role':  meta.role
				'http.status':     status.str()
				// #200: the span carries bytes in/out (was computed for metrics/logs
				// but never attached to the span).
				'bytes.in':        bytes_in.str()
				'bytes.out':       bytes_out.str()
			}
		})
		// #200: a store-op CHILD span (parent = the request span), so the trace has
		// a real parent→child hierarchy (build_otlp_json emits parentSpanId). Only
		// for the data ops (not health/ready/metrics/capabilities).
		if svc_is_data_op(op) {
			child := TraceContext{
				trace_id:  tc.trace_id
				span_id:   obs_new_span_id()
				parent_id: tc.span_id
				sampled:   tc.sampled
			}
			ctx.tracer.export(Span{
				tc:       child
				name:     'store.${ep}'
				start_ns: started.unix_nano()
				end_ns:   ended.unix_nano()
				status:   status
				attrs:    {
					'store':    store
					'endpoint': ep
				}
			})
		}
	}
	return resp
}

// svc_is_data_op reports whether an op is a store data operation (gets a store-op
// child span, #200) — as opposed to a lifecycle/discovery endpoint.
fn svc_is_data_op(op string) bool {
	return op in ['get', 'put', 'delete', 'list', 'iter', 'query', 'modify',
		'objects-have', 'objects-get', 'objects-put', 'refs', 'refs-set']
}

// svc_metric_op_for_path classifies a non-`/cx-store/v1/<op>` path for the
// endpoint label (health/ready carry no store-name and parse outside the CSRP
// base). Anything unrecognized normalizes to `_other` downstream.
fn svc_metric_op_for_path(path string) string {
	return match path {
		csrp_base + 'health' { 'health' }
		csrp_base + 'ready' { 'ready' }
		else { path }
	}
}

// svc_serve_metrics renders the Prometheus exposition, gated by the `metrics`
// scrape scope when enforcing (a `metrics`-role principal may read this and
// nothing else). 404 when no registry is wired.
fn svc_serve_metrics(req cx.Element, ctx ServeContext) cx.Node {
	if ctx.metrics == unsafe { nil } {
		return csrp_resp(404, '[err code="cx-err:CXER1707" message="E_CSRP_SERVER_INTERNAL: metrics not enabled"]')
	}
	if ctx.auth.enforce {
		p := svc_authenticate(req, ctx.auth)
		if e := svc_authorize(p, 'metrics', '') {
			status := if svc_err_code(e) == e_csrp_auth_required { 401 } else { 403 }
			return csrp_resp(status, '[err code="${svc_err_code(e)}" message="${svc_err_msg(e)}"]')
		}
	}
	mut m := ctx.metrics
	// request-level series + the live store-internal series (§7 introspection
	// seam): index size per mounted backend, gauged at scrape time. #207.4: emit
	// the Prometheus exposition Content-Type.
	return csrp_resp_hdrs(200, m.render_prometheus() + svc_store_internal_metrics(ctx.mounts),
		[['Content-Type', 'text/plain; version=0.0.4; charset=utf-8']])
}

// svc_dispatch_request is the per-request router (lifecycle → capabilities →
// authN/Z → DoS fairness → data op). svc_handle_request wraps it with metrics.
fn svc_dispatch_request(req cx.Element, mut state ServiceState, ctx ServeContext, mut meta RequestMeta) cx.Node {
	method := http_attr(req, 'method') or { 'GET' }
	path := http_attr(req, 'path') or { '/' }
	// 1. lifecycle endpoints (daemon-level, unauthenticated, drain-independent)
	if body := svc_route_lifecycle(method, path, mut state) {
		return csrp_resp(200, body)
	}
	// health/ready are exempt from rate limiting (orchestration/LB probes must
	// always answer); the pre-auth cap covers capabilities + data-op admission
	// AND the non-CSRP fallthrough below (#206.4 — a flood of bogus paths must not
	// bypass the pre-auth bucket).
	has_lim := ctx.limiter != unsafe { nil }
	mut lim := ctx.limiter
	sname, op := svc_path_parts(path) or {
		// not a CSRP path — admission-capped, then let the store router 404.
		if has_lim && !lim.allow_pre_auth() {
			return csrp_resp_retry(429, '[err code="${e_svc_rate_limited}" message="E_CSRP_RATE_LIMITED: too many requests"]', 1)
		}
		return store_csrp_route(req, svc_any_mount(ctx.mounts))
	}
	if has_lim && !lim.allow_pre_auth() {
		return csrp_resp_retry(429, '[err code="${e_svc_rate_limited}" message="E_CSRP_RATE_LIMITED: too many requests"]', 1)
	}
	// #196: enforce the advertised max-request-bytes → 413 CXER1705 (was
	// unreachable; LimitConfig had no byte cap).
	if i64(http_body_octets(req).len) > svc_max_request_bytes {
		return csrp_resp(413, '[err code="${e_svc_too_large}" message="E_CSRP_PAYLOAD_TOO_LARGE: request body exceeds max-request-bytes (${svc_max_request_bytes})"]')
	}
	// 2. capabilities discovery (#193). Two forms (approved §3.1):
	//    - SERVER-LEVEL (no store-name): unauthenticated bootstrap; version +
	//      encodings + auth advert, NO backend fields.
	//    - PER-STORE (`/<store-name>/capabilities`): resolve the mount (404
	//      CXER1710 on unknown — no oracle-free 200), reflect that store's backend,
	//      real read/write/list flags, query-features, and limits.
	if method == 'GET' && op == 'capabilities' {
		if sname == '' {
			return svc_splice_auth_advert(csrp_resp(200, svc_server_capabilities(ctx)),
				ctx.auth)
		}
		mount := svc_select_mount(sname, ctx.mounts) or {
			return csrp_resp(404, '[err code="cx-err:CXER1710" message="E_CSRP_STORE_NOT_FOUND: ${csrp_msg_esc(sname)}"]')
		}
		return svc_splice_auth_advert(csrp_resp(200, svc_store_capabilities(mount, ctx)),
			ctx.auth)
	}
	// #248 admin plane (§3.12): daemon-level mount enumeration. Server-level like
	// capabilities (no store-name) but — unlike capabilities/health/ready —
	// AUTHENTICATED: admin permission required, and the enumeration is
	// tenant-FILTERED (a principal never learns of stores outside its tenant —
	// the §3 no-cross-tenant-probing invariant applies to existence itself).
	// Handled before the generic flow because sname='' must mean DAEMON-level
	// here, not the sole-store shorthand the resolver below would apply.
	if method == 'GET' && sname == '' && op == 'mounts' {
		mut tenant := '*'
		if ctx.auth.enforce {
			p := svc_authenticate(req, ctx.auth)
			if p.kind != 'anonymous' && p.roles.len > 0 {
				meta.role = p.roles.join(',') // audit identity before the deny (#212)
			}
			if e := svc_authorize(p, 'mounts', '') {
				status := if svc_err_code(e) == e_csrp_auth_required { 401 } else { 403 }
				return csrp_resp(status, '[err code="${svc_err_code(e)}" message="${svc_err_msg(e)}"]')
			}
			tenant = p.tenant
		}
		return csrp_resp(200, svc_mounts_body(ctx, tenant))
	}
	// #251 config reload (§3.13): daemon-level like mounts, POST, admin. The op
	// is daemon-GLOBAL (config is daemon-global state) — tenant scoping does not
	// partition it; RBAC admin is the gate. The daemon re-reads its own config
	// source: nothing on the wire carries config content (the console TRIGGERS
	// reload, it never writes config).
	if method == 'POST' && sname == '' && op == 'config-reload' {
		if ctx.auth.enforce {
			p := svc_authenticate(req, ctx.auth)
			if p.kind != 'anonymous' && p.roles.len > 0 {
				meta.role = p.roles.join(',') // audit identity before the deny (#212)
			}
			if e := svc_authorize(p, 'config-reload', '') {
				status := if svc_err_code(e) == e_csrp_auth_required { 401 } else { 403 }
				return csrp_resp(status, '[err code="${svc_err_code(e)}" message="${svc_err_msg(e)}"]')
			}
		}
		if ctx.reloader == unsafe { nil } {
			// No daemon config to reload here (embedded reference server / test
			// contexts) — honest unsupported, same §3.13 posture as mounts.
			return csrp_resp(404, '[err code="cx-err:CXER1709" message="E_CSRP_OPERATION_UNSUPPORTED: config-reload"]')
		}
		out := ctx.reloader()
		eprintln(svc_reload_log(out, 'csrp'))
		return svc_reload_response(out)
	}
	// 3. authN/Z — deny-by-default when enforcing: authenticate the Bearer
	//    credential, then check RBAC (op → permission) + tenant (→ store-name).
	//    The tenant check runs against the RESOLVED store name so the sole-store
	//    shorthand cannot bypass tenant isolation (#179).
	eff_sname := svc_resolve_sname(sname, ctx.mounts)
	mut pid := 'anon'
	if ctx.auth.enforce {
		p := svc_authenticate(req, ctx.auth)
		// Populate the audit identity BEFORE the RBAC check so a denied op logs
		// against the real authenticated principal, not "anon" (#212 Defect B).
		if p.kind != 'anonymous' {
			pid = p.id
			if p.roles.len > 0 {
				meta.role = p.roles.join(',') // role(s) only — never the token (F.3)
			}
		}
		if e := svc_authorize(p, op, eff_sname) {
			status := if svc_err_code(e) == e_csrp_auth_required { 401 } else { 403 }
			return csrp_resp(status, '[err code="${svc_err_code(e)}" message="${svc_err_msg(e)}"]')
		}
	}
	// 4. per-principal DoS fairness — a flooding principal gets backpressure
	//    (429 — rate or concurrency, CXER1706) without starving others.
	if has_lim {
		if !lim.allow_principal_rate(pid) {
			return csrp_resp_retry(429, '[err code="${e_svc_rate_limited}" message="E_CSRP_RATE_LIMITED: principal rate exceeded"]', 1)
		}
		if !lim.acquire_principal(pid) {
			// over its concurrency allowance → 429 (client over-quota), not 503:
			// the server is healthy, this one client has too many in flight.
			return csrp_resp_retry(429, '[err code="${e_svc_rate_limited}" message="E_CSRP_RATE_LIMITED: principal concurrency exceeded"]', 1)
		}
	}
	// 5. data op — route to the named store. The acquired slot is released on
	//    every path via the helper return.
	resp := svc_dispatch_data_op(req, mut state, ctx, sname, op)
	if has_lim {
		lim.release_principal(pid)
	}
	return resp
}

// svc_server_capabilities is the server-level advert (#193 / approved §3.1): the
// server-wide profile only — csrp-version, server-impl, both encodings (cxbin
// default + cxd), rate-limit — with NO backend/store fields (a server serves many
// stores). The [auth …] block is spliced by the caller.
fn svc_server_capabilities(ctx ServeContext) string {
	rl := svc_rate_limit_advert(ctx)
	// #251/§3.1: the admin-ops advert — the ops THIS daemon routes; a management
	// client (#249) degrades features off this list instead of probing for 404s.
	// config-reload appears only when a reloader is wired (the daemon CLI).
	admin_ops := if ctx.reloader != unsafe { nil } {
		'[admin-ops "status" "gc" "mounts" "config-reload"]'
	} else {
		'[admin-ops "status" "gc" "mounts"]'
	}
	return '[capabilities [csrp-version "1.0"] [server-impl "cx-stdlib-store-ref"] [encodings [supported "cxbin" "cxd"] [default "cxbin"]] ${admin_ops} ${rl}]'
}

// svc_store_capabilities is the per-store advert (#193): it reflects the ADDRESSED
// store's backend and real read/write/list flags (from the handle's capability
// trait), the query-features block, both encodings, and the rate limits. No more
// hardcoded static body / lying flags.
fn svc_store_capabilities(mount cx.Node, ctx ServeContext) string {
	backend, readf, writef, listf := svc_mount_caps(mount)
	rl := svc_rate_limit_advert(ctx)
	// query-features: the embedded engine supports CXPath + predicates + push-down
	// filter/aggregate over every backend (the query route runs server-side).
	qf := '[query-features [cxpath true] [cxpath-axes "child" "descendant" "ancestor" "attribute" "self" "parent"] [predicates true] [push-down-filter true] [push-down-aggregate true] [push-down-aggregates "count" "sum" "avg" "min" "max"]]'
	return '[capabilities [csrp-version "1.0"] [server-impl "cx-stdlib-store-ref"] [backend-tier "embedded"] [backend-name "${backend}"] [encodings [supported "cxbin" "cxd"] [default "cxbin"]] [compressions [supported "zst" "gz" "none"] [default "none"]] ${qf} [read ${readf}] [write ${writef}] [list ${listf}] [iter ${listf}] ${rl}]'
}

// svc_mount_caps reads a mount's real capability trait (the store-capabilities
// builtin): backend name + read/write/list flags. Shared by the per-store
// capabilities advert (§3.1) and the mounts enumeration (§3.12) so both reflect
// the same source of truth.
fn svc_mount_caps(mount cx.Node) (string, bool, bool, bool) {
	caps := store_stdlib_builtin_inner('store-capabilities', [mount]) or { cx.Node(cx.ScalarNode{}) }
	mut backend := 'unknown'
	mut readf := true
	mut writef := true
	mut listf := true
	if caps is cx.Element {
		for a in caps.attrs {
			v := cx.scalar_value_str_public(a.value)
			match a.name {
				'backend' { backend = v }
				'read' { readf = v == 'true' }
				'write' { writef = v == 'true' }
				'list' { listf = v == 'true' }
				else {}
			}
		}
	}
	return backend, readf, writef, listf
}

// svc_mounts_body renders the §3.12 [mounts …] enumeration (#248): one [mount]
// per store the principal's tenant allows, sorted by name (deterministic), the
// flags reflecting the mount's real capability trait. An authorized-but-empty
// enumeration is a valid [mounts] — never an error.
fn svc_mounts_body(ctx ServeContext, tenant string) string {
	mut names := ctx.mounts.keys()
	names.sort()
	mut out := '[mounts'
	for name in names {
		if !svc_tenant_allows(tenant, name) {
			continue
		}
		mount := ctx.mounts[name] or { continue }
		backend, readf, writef, listf := svc_mount_caps(mount)
		out += ' [mount name="${name}" backend="${backend}" read=${readf} write=${writef} list=${listf}]'
	}
	return out + ']'
}

// svc_rate_limit_advert renders the [rate-limit …] + max-request-bytes block from
// the configured limiter (§3.1), or sane defaults when unlimited.
fn svc_rate_limit_advert(ctx ServeContext) string {
	mut rpm := i64(0)
	if ctx.limiter != unsafe { nil } {
		mut lim := ctx.limiter
		rpm = i64(lim.get_cfg().per_principal_rate * 60.0)
	}
	return '[max-request-bytes ${svc_max_request_bytes}] [max-response-bytes 0] [rate-limit [requests-per-minute ${rpm}] [bytes-per-second 0]]'
}

// svc_auth_advert renders the CSRP capabilities [auth …] block from the resolved
// auth config: bearer iff any token/JWT/DID/OIDC provider is configured, mtls
// not yet implemented, anonymous iff the daemon is not enforcing auth.
fn svc_auth_advert(auth AuthContext) string {
	has_bearer := auth.static_tokens.len > 0 || auth.jwt.enabled || auth.did.enabled
		|| auth.oidc.enabled
	return '[auth [bearer ${has_bearer}] [mtls false] [anonymous ${!auth.enforce}]]'
}

// svc_splice_auth_advert inserts the [auth …] advert into a [capabilities …]
// response body (before its closing bracket).
fn svc_splice_auth_advert(resp cx.Node, auth AuthContext) cx.Node {
	body := svc_response_body(resp).trim_space()
	if !body.ends_with(']') {
		return resp
	}
	return csrp_resp(200, body[..body.len - 1] + ' ' + svc_auth_advert(auth) + ']')
}

// svc_response_body extracts the body text of a [response … [body …]] node.
fn svc_response_body(n cx.Node) string {
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

// svc_dispatch_data_op selects the target store, gates on the global accepting
// state, and delegates to the CSRP store router (store-name-stripped canonical
// path so the single-store router matches `/cx-store/v1/<op>`).
fn svc_dispatch_data_op(req cx.Element, mut state ServiceState, ctx ServeContext, sname string, op string) cx.Node {
	local := svc_select_mount(sname, ctx.mounts) or {
		// #204: an unknown/ambiguous store-name is the STORE-granularity wire code
		// CXER1710 E_CSRP_STORE_NOT_FOUND (per the approved §3/§4 invariant that the
		// std-lib CXER1121 never rides the wire), NOT CXER1121.
		return csrp_resp(404, '[err code="cx-err:CXER1710" message="E_CSRP_STORE_NOT_FOUND: ${csrp_msg_esc(err.msg())}"]')
	}
	if !state.enter_request() {
		return csrp_resp_retry(503, '[err code="${e_svc_unavail}" message="E_CSRP_SERVER_UNAVAILABLE: not accepting new requests"]', 5)
	}
	resp := store_csrp_route(svc_req_with_path(req, csrp_base + op), local)
	state.exit_request()
	return resp
}

// svc_path_parts splits a CSRP path into (store-name, op). store-name is '' for
// the sole-store form. none when `path` is not under the CSRP base.
fn svc_path_parts(path string) ?(string, string) {
	if !path.starts_with(csrp_base) {
		return none
	}
	suffix := path[csrp_base.len..]
	if suffix == '' {
		return none
	}
	if idx := suffix.index('/') {
		return suffix[..idx], suffix[idx + 1..]
	}
	return '', suffix
}

// svc_valid_store_name accepts only [A-Za-z0-9_-] (≤128) — so a store-name can
// never carry path traversal (`..`, `/`), percent-encoding, or whitespace.
fn svc_valid_store_name(name string) bool {
	if name == '' || name.len > 128 {
		return false
	}
	for c in name {
		ok := (c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`) || (c >= `0` && c <= `9`)
			|| c == `-` || c == `_`
		if !ok {
			return false
		}
	}
	return true
}

// svc_resolve_sname maps the sole-store shorthand (empty name with exactly one
// mount) to that mount's actual name, so authorization (tenant scoping) and
// observability recording run against the store that will ACTUALLY be served
// (#179 tenant-isolation bypass / #201 store="_unknown" misattribution). Without
// this, the shorthand path skipped the tenant check (empty store-name) and logged
// every sole-store request as `_unknown`. A multi-mount server keeps '' (ambiguous
// → svc_select_mount 404s it, so no unauthorized mount is ever reached); an
// explicit valid name passes through unchanged.
fn svc_resolve_sname(sname string, mounts map[string]cx.Node) string {
	if sname == '' && mounts.len == 1 {
		for name, _ in mounts {
			return name
		}
	}
	return sname
}

// svc_select_mount resolves the target store: a named store must exist (and be a
// valid name); the empty name resolves to the sole mount, or errors when the
// daemon serves multiple stores (the client must name one).
fn svc_select_mount(sname string, mounts map[string]cx.Node) !cx.Node {
	if sname != '' {
		if !svc_valid_store_name(sname) {
			return error('invalid store name `${sname}`')
		}
		return mounts[sname] or { return error('unknown store `${sname}`') }
	}
	if mounts.len == 1 {
		for _, v in mounts {
			return v
		}
	}
	return error('store name required (server mounts ${mounts.len} stores)')
}

// svc_any_mount returns an arbitrary mount (for store-independent endpoints like
// capabilities, which ignore the store handle).
fn svc_any_mount(mounts map[string]cx.Node) cx.Node {
	for _, v in mounts {
		return v
	}
	return cx.Node(cx.ScalarNode{})
}

// svc_req_with_path returns `req` with its `path` attribute replaced.
fn svc_req_with_path(req cx.Element, newpath string) cx.Element {
	mut attrs := []cx.Attribute{cap: req.attrs.len}
	for a in req.attrs {
		if a.name == 'path' {
			attrs << cx.Attribute{
				name:  'path'
				value: cx.ScalarValue(newpath)
			}
		} else {
			attrs << a
		}
	}
	return cx.Element{
		...req
		attrs: attrs
	}
}

// ── Bounded worker pool (brick 6) ────────────────────────────────────────────
//
// ServePool is the daemon's connection concurrency: N worker threads drain a
// bounded job channel (cap = queue → natural backpressure: submit blocks when
// full). Each job is an opaque int token (the accept loop passes a connection
// fd; the handler resolves it). Mirrors the proven par_eval pool idiom (chan +
// spawn + WaitGroup). drain() closes the channel so workers finish queued jobs
// then exit, and joins them — the graceful-shutdown primitive (§2.5). Sound
// under the default cooperative-safepoint STW vgc.
pub struct ServePool {
mut:
	work    chan int
	wg      &sync.WaitGroup = unsafe { nil }
	handler fn (int) = unsafe { nil }
}

// new_serve_pool starts `workers` threads draining a `queue`-deep job channel,
// each running `handler` per job.
pub fn new_serve_pool(workers int, queue int, handler fn (int)) &ServePool {
	mut p := &ServePool{
		work:    chan int{cap: queue}
		wg:      sync.new_waitgroup()
		handler: handler
	}
	for _ in 0 .. workers {
		p.wg.add(1)
		spawn p.run_worker()
	}
	return p
}

fn (mut p ServePool) run_worker() {
	work := p.work
	for {
		job := <-work or { break } // channel closed + drained → worker exits
		p.handler(job)
	}
	p.wg.done()
}

// submit enqueues a job; blocks when the queue is full (backpressure).
pub fn (mut p ServePool) submit(job int) {
	p.work <- job
}

// drain closes the queue (no new jobs), lets workers finish what's queued, and
// joins them. Idempotent-safe only once — call from the shutdown path.
pub fn (mut p ServePool) drain() {
	p.work.close()
	p.wg.wait()
}

// drain_bounded closes the queue and waits for workers to finish up to
// `deadline_ms` (#186 defect 1 — the old drain() was an unbounded wg.wait()). The
// per-connection read deadline (#187) already bounds each in-flight handler, so a
// full drain normally completes well within the deadline; this is the belt-and-
// suspenders cap so a wedged worker cannot stall exit indefinitely. Returns true
// if fully drained, false if the deadline was hit (the caller exits anyway;
// process teardown reaps the daemon worker threads). `state.drain_complete` is the
// live in-flight probe (wiring the previously-dead §2.5 seam — defect 2).
pub fn (mut p ServePool) drain_bounded(mut state ServiceState, deadline_ms i64) bool {
	p.work.close()
	done := chan bool{cap: 1}
	spawn fn (mut wg sync.WaitGroup, ch chan bool) {
		wg.wait()
		ch <- true
	}(mut p.wg, done)
	deadline := time.now().add(deadline_ms * time.millisecond)
	for {
		select {
			_ := <-done {
				return true // all workers joined
			}
			20 * time.millisecond {
				if state.drain_complete(false) {
					// no data ops in flight; give queued connection handlers a beat
					// to return, then report drained.
					select {
						_ := <-done {
							return true
						}
						100 * time.millisecond {
							return true
						}
					}
				}
				if time.now() >= deadline {
					return false // deadline hit — exit anyway
				}
			}
		}
	}
	return false
}

// ── Accept loop + per-connection handler (brick 7, signal-free lib part) ─────
//
// These compose the tested logic (svc_handle_request) with the real net/http
// primitives. Signal handling + the daemon process loop live in the CLI
// (cmd/store_serve.v) — the shared lib must never install process signal
// handlers (a binding loading libcx must not hijack SIGTERM). The accept loop is
// therefore driven by a caller-supplied `should_stop` predicate; the CLI closes
// the listener on signal to unblock the in-progress accept().

// serve_connection handles one accepted connection (by fd) end-to-end: relabel
// it as an [exchange], read the request, dispatch via svc_handle_request, write
// the response, and finalize (close a connection a handler left unanswered).
fn serve_connection(fd int, mut state ServiceState, ctx_in ServeContext) {
	// #251: new connections pick up the CURRENT timeouts (§2.6 — read-ms/idle-ms
	// are hot for connections accepted after a reload; this one keeps its view).
	ctx := svc_ctx_live(ctx_in)
	ex := cx.Node(cx.Element{
		name:  'exchange'
		attrs: [
			cx.Attribute{
				name:  'fd'
				value: cx.ScalarValue(i64(fd))
			},
			cx.Attribute{
				name:  'state'
				value: cx.ScalarValue('open')
			},
			cx.Attribute{
				name:  'on-close'
				value: cx.ScalarValue('http/close')
			},
		]
	})
	// #234.1: HTTP/1.1 keep-alive — serve successive requests on the SAME connection
	// until the client asks to close, the server is draining, the response cannot be
	// pipelined, or the connection sits idle past the keep-alive budget. This retires
	// the per-request TCP+TLS handshake cost that §2.1/§5.2 call out. When
	// idle_timeout_ms is 0 keep-alive is disabled and this serves exactly one request
	// (the pre-#234 single-turn behavior).
	ka_enabled := ctx.idle_timeout_ms > 0
	mut served := 0
	for {
		// #187: arm the per-connection read deadline BEFORE reading, so a slow/
		// trickling client (slowloris) or a duplicate-Content-Length hang cannot hold
		// this worker past the budget. Between requests on a kept-alive connection the
		// wait is bounded by the (larger) idle budget instead — an idle persistent
		// connection is reaped rather than pinning the worker forever.
		deadline := if served == 0 { ctx.read_timeout_ms } else { ctx.idle_timeout_ms }
		if deadline > 0 {
			net_set_read_deadline_id(fd, deadline)
		}
		reqn := http_exchange_request_real([ex])
		if reqn !is cx.Element {
			break // read fault / idle timeout / peer closed
		}
		re := reqn as cx.Element
		if re.name == 'err' {
			// A clean EOF / idle timeout (no request line) closes the connection
			// silently — the normal keep-alive teardown (or a client that connected
			// then sent nothing), not a fault. Close here so the finalizer's
			// "returned without responding" diagnostic doesn't fire on a clean close.
			if svc_err_code(reqn) == 'cx-err:CXER4542' {
				if id := net_handle_id(ex) {
					net_close_id(id)
				}
				break
			}
			// #219: a request-framing rejection (conflicting Content-Length,
			// missing HTTP-version, …) → 400 CXER1701, not a silent connection drop.
			http_respond_impl([ex, csrp_resp(400, '[err code="cx-err:CXER1701" message="E_CSRP_REQUEST_MALFORMED: ${csrp_msg_esc(svc_err_msg(reqn))}"]')])
			break // framing errors terminate the connection
		}
		if re.name != 'request' {
			break
		}
		resp := svc_handle_request(re, mut state, ctx)
		// Keep the connection alive only if: keep-alive is enabled, the client did
		// not send `Connection: close`, the daemon is still accepting (a draining
		// daemon closes so the LB de-routes, §2.5), and the response is pipelinable.
		want_ka := ka_enabled && svc_req_wants_keepalive(re) && state.accepting()
		if want_ka && http_write_response_keepalive(ex, resp, ctx.idle_timeout_ms) {
			served++
			continue
		}
		// single-turn (or non-keepalive) response: http_respond_impl closes the fd.
		http_respond_impl([ex, resp])
		break
	}
	http_finalize_unresponded_exchange(ex)
}

// svc_req_wants_keepalive reports whether the client is willing to reuse the
// connection. HTTP/1.1 defaults to keep-alive, so this is true UNLESS the request
// carries `Connection: close` (case-insensitive) — the standard opt-out.
fn svc_req_wants_keepalive(req cx.Element) bool {
	return !csrp_header(req, 'connection').to_lower().contains('close')
}

// run_serve_loop accepts connections off `server` and dispatches each to a
// bounded worker pool until the listener closes (the shutdown watcher closes it
// after the drain grace, §2.5/#233). While DRAINING — after the first signal but
// before the grace elapses — the listener stays open, so this keeps accepting:
// health/ready probes are answered [ready [accepting false]] and data ops get 503,
// letting a load balancer de-route before the connection source disappears. The
// old model broke on the first signal, so the listener closed at once and a
// probe got connection-refused instead of the draining readiness state.
// `mounts` maps store-name → handle; requests route by the path's store-name.
pub fn run_serve_loop(server cx.Node, mut state ServiceState, ctx ServeContext, workers int, queue int, should_stop fn () bool) {
	mut pool := new_serve_pool(workers, queue, fn [mut state, ctx] (fd int) {
		serve_connection(fd, mut state, ctx)
	})
	// #233: publish the live state so the shutdown watcher can begin_drain the
	// instant the first signal arrives (readiness→false), independent of this loop.
	g_svc_state = voidptr(state)
	state.mark_ready()
	mut drained := false
	for {
		mut h := net_mut_handle(server) or { break }
		conn := net_accept_real(mut h)
		if is_err_value(conn) {
			break // listener closed (drain grace elapsed) or accept fault
		}
		// #233: on the first connection observed after a shutdown signal, ensure the
		// draining state is set (the watcher normally set it already; this is the
		// belt-and-suspenders path if the signal raced the watcher's state publish).
		if !drained && should_stop() {
			state.begin_drain()
			drained = true
		}
		fd := net_handle_id(conn) or { continue }
		pool.submit(fd)
	}
	state.begin_drain()
	// #186 defect 1/2: bounded drain (deadline-capped, uses drain_complete) rather
	// than the old unbounded wg.wait(). 30s matches the shipped unit's
	// TimeoutStopSec; the per-connection read deadline keeps handlers from
	// stalling, so this normally returns promptly.
	pool.drain_bounded(mut state, 30000)
}

// ── Daemon CLI helpers (brick 8 support) ─────────────────────────────────────
// Pub wrappers so the `cx store-serve` CLI (cmd/, module main) can drive the
// daemon without reaching module-internal store/http/net primitives.

// svc_open_store opens a persistent store mount by URL (§2.2).
pub fn svc_open_store(url string) cx.Node {
	return store_open_impl(url, '', '', false, true, map[string]string{})
}

// svc_listen binds a tcp:// or tls:// CSRP listener; returns an [http-server]
// handle, or an err value (e.g. denied net capability / bind failure).
pub fn svc_listen(bind_url string) cx.Node {
	return http_listen_impl([store_str(bind_url)])
}

// svc_listen_tls binds a tls:// listener with the given PEM cert/key content
// (#180 — the config's cert/key were parsed then discarded; this threads them
// into the listener's opts.tls, which net_listen_tls_real / mbedtls consume).
// `ca_pem` non-empty enables mTLS (require-client-cert).
pub fn svc_listen_tls(bind_url string, cert_pem string, key_pem string, ca_pem string) cx.Node {
	mut tls_entries := [
		cx.Node(cx.Element{
			name:  'cert'
			items: [store_str(cert_pem)]
		}),
		cx.Node(cx.Element{
			name:  'key'
			items: [store_str(key_pem)]
		}),
	]
	if ca_pem != '' {
		tls_entries << cx.Node(cx.Element{
			name:  'ca'
			items: [store_str(ca_pem)]
		})
	}
	// svc_load_pem gives PEM CONTENT (file read or ${env:VAR}), so parse in memory
	// rather than treating cert/key as filesystem paths.
	tls_entries << cx.Node(cx.Element{
		name:  'in-memory'
		items: [store_str('true')]
	})
	// opts shape: [__cx_map__ [tls [__cx_map__ [cert …] [key …] [ca …]]]] — the
	// `tls` key's VALUE is itself a map (net_opts_submap/net_map_get read the tls
	// submap's cert/key/ca), matching how the dial path reads opts.tls.
	opts := cx.Node(cx.Element{
		name:  '__cx_map__'
		items: [
			cx.Node(cx.Element{
				name:  'tls'
				items: [
					cx.Node(cx.Element{
						name:  '__cx_map__'
						items: tls_entries
					}),
				]
			}),
		]
	})
	return http_listen_impl([store_str(bind_url), opts])
}

// svc_load_pem resolves a TLS cert/key config value to PEM CONTENT (#180/#199):
// a value that already looks like PEM (`-----BEGIN`) is used verbatim (supports
// `${env:VAR}`-injected PEM per svc_resolve_env), otherwise it is treated as a
// filesystem PATH and read. A read failure is a hard error (fail-fast — never
// bind plaintext because a cert file was missing).
pub fn svc_load_pem(val string) !string {
	if val.trim_space().starts_with('-----BEGIN') {
		return val
	}
	return os.read_file(val) or {
		return error('cannot read TLS PEM file `${val}`: ${err.msg()}')
	}
}

// svc_listener_fd returns the OS fd of a listener handle (for signal-close).
pub fn svc_listener_fd(server cx.Node) ?int {
	return net_handle_id(server)
}

// svc_is_err reports whether a node is an err value.
pub fn svc_is_err(n cx.Node) bool {
	return is_err_value(n)
}

// svc_err_text renders an err value as `code: message` for a CLI diagnostic.
pub fn svc_err_text(n cx.Node) string {
	if n is cx.Element {
		return '${n.attr('code')}: ${n.attr('message')}'
	}
	return 'unknown error'
}

// svc_err_code / svc_err_msg extract an err value's fields (for HTTP mapping).
pub fn svc_err_code(n cx.Node) string {
	if n is cx.Element {
		return n.attr('code')
	}
	return ''
}

pub fn svc_err_msg(n cx.Node) string {
	if n is cx.Element {
		return n.attr('message')
	}
	return ''
}

// ── Daemon shutdown signals (brick 8; opt-in, daemon-CLI only) ───────────────
// Installed ONLY by `cx store-serve`, never automatically — so a binding
// loading libcx never hijacks signals. A signal handler cannot capture, so it
// communicates via module globals (the module is `@[has_globals]`). The handler
// does the minimum async-signal-safe work — a single atomic flag store — and a
// watcher thread (a normal thread, so registry access is safe) observes the flag
// and closes the listener via net_close_id, which unblocks the in-progress
// blocking accept() in run_serve_loop. (Closing from the handler is unsafe: it
// would touch the net handle registry from signal context; and net_handle_id is
// a registry id, not the OS fd, so a raw close() would hit the wrong descriptor.)
__global (
	g_svc_shutdown         int
	g_svc_listener_id      int
	g_svc_grpc_listener_id int
	// #233: how long to keep the listener OPEN after the first shutdown signal so
	// readiness probes still connect (and observe accepting=false) before the
	// listener closes and in-flight requests drain. Set by svc_install_shutdown_signals.
	g_svc_drain_grace_ms i64
	// #233: the live ServiceState (set by run_serve_loop) so the shutdown watcher can
	// begin_drain immediately on the first signal — readiness flips false at once,
	// not only when the accept loop next wakes on a connection. voidptr (cast to
	// &ServiceState on use) because a __global block takes no typed initializer.
	g_svc_state voidptr
	// #251: SIGHUP → config-reload counter (async-signal-safe single write; the
	// reload watcher in store_reload.v observes it — same pattern as g_svc_shutdown).
	g_svc_reload int
)

// The handler INCREMENTS the flag (async-signal-safe single write): 1 = graceful
// drain, ≥2 = a second signal forcing immediate exit (§2.5).
fn svc_shutdown_signal_handler(sig os.Signal) {
	g_svc_shutdown = g_svc_shutdown + 1
}

// svc_install_shutdown_signals arms graceful shutdown: SIGTERM/SIGINT increment
// the shutdown flag, and a watcher closes the listener(s) to unblock accept().
// Call once, from the daemon CLI only.
pub fn svc_install_shutdown_signals(server cx.Node, drain_grace_ms i64) {
	g_svc_shutdown = 0
	g_svc_listener_id = net_handle_id(server) or { -1 }
	g_svc_grpc_listener_id = -1 // set by svc_register_grpc_listener if gRPC is enabled
	g_svc_drain_grace_ms = drain_grace_ms
	os.signal_opt(.term, svc_shutdown_signal_handler) or {}
	os.signal_opt(.int, svc_shutdown_signal_handler) or {}
	spawn svc_shutdown_watcher()
}

// svc_register_grpc_listener records the gRPC listener id so the shutdown watcher
// closes BOTH listeners on signal (#211 — the gRPC listener was never registered,
// so a gRPC accept blocked in accept() was never unblocked and its in-flight
// streams were severed rather than drained). Call after the gRPC listener binds.
pub fn svc_register_grpc_listener(server cx.Node) {
	g_svc_grpc_listener_id = net_handle_id(server) or { -1 }
}

// svc_shutdown_watcher polls the shutdown flag. On the first signal it flips
// readiness false (begin_drain) but KEEPS the listener(s) OPEN for the drain grace
// (#233) — so a load-balancer readiness probe still connects and observes
// [ready [accepting false]] (data ops get 503) and can de-route — then closes BOTH
// listeners (from a normal thread → registry-safe) to unblock accept() and let
// run_serve_loop drain in-flight. A SECOND signal at any point (#186 defect 3)
// forces immediate process exit rather than waiting out the grace/drain.
fn svc_shutdown_watcher() {
	for {
		if g_svc_shutdown != 0 {
			break
		}
		time.sleep(50 * time.millisecond)
	}
	// First signal observed. begin_drain (readiness→false) immediately so probes in
	// the grace window see accepting=false, even before the accept loop next wakes.
	if g_svc_state != unsafe { nil } {
		mut st := unsafe { &ServiceState(g_svc_state) }
		st.begin_drain()
	}
	// Hold the listener open for the grace, watching for a force-exit second signal.
	grace_iters := if g_svc_drain_grace_ms > 0 { g_svc_drain_grace_ms / 50 } else { i64(0) }
	mut i := i64(0)
	for i < grace_iters {
		if g_svc_shutdown >= 2 {
			eprintln('cx store-serve: second signal — forcing immediate exit')
			exit(0)
		}
		time.sleep(50 * time.millisecond)
		i++
	}
	// Grace elapsed: close both listeners to unblock accept() so the loop drains.
	if g_svc_listener_id >= 0 {
		net_close_id(g_svc_listener_id)
	}
	if g_svc_grpc_listener_id >= 0 {
		net_close_id(g_svc_grpc_listener_id)
	}
	// Keep watching for a second signal → forced immediate exit.
	for {
		if g_svc_shutdown >= 2 {
			eprintln('cx store-serve: second signal — forcing immediate exit')
			exit(0)
		}
		time.sleep(50 * time.millisecond)
	}
}

// svc_shutdown_requested is the run_serve_loop should_stop predicate.
pub fn svc_shutdown_requested() bool {
	return g_svc_shutdown != 0
}

// svc_shutdown_checkpoint flushes every mounted store before exit (#186 defect 4):
// a final durability barrier on top of the per-op flush, so a graceful shutdown
// never leaves an unflushed write. Best-effort per mount (logged), so one failing
// store does not block the others.
pub fn svc_shutdown_checkpoint(mounts map[string]cx.Node) {
	for name, handle in mounts {
		mut ms := store_for_guard(handle) or { continue }
		if ms.op_lock != unsafe { nil } {
			ms.op_lock.@lock()
		}
		store_persist(mut ms) or {
			eprintln('cx store-serve: checkpoint of store `${name}` failed: ${err.msg()}')
		}
		if ms.op_lock != unsafe { nil } {
			ms.op_lock.unlock()
		}
	}
}

// ── systemd sd_notify (brick 9; Linux/Type=notify, no-op elsewhere) ──────────
// Sends "READY=1" to $NOTIFY_SOCKET so systemd (Type=notify) marks the unit
// started only after bind+open succeed (§2.3). No-op when NOTIFY_SOCKET is
// unset (every non-systemd host, incl. macOS dev), so the C path below only
// ever executes on Linux/systemd. Best-effort: failures are ignored (sd_notify
// is advisory). Uses C AF_UNIX SOCK_DGRAM (V's net.unix is stream-only).

#include <sys/socket.h>
#include <sys/un.h>

fn C.socket(domain int, typ int, protocol int) int
fn C.sendto(fd int, buf voidptr, len usize, flags int, addr voidptr, addrlen u32) isize
fn C.close(fd int) int

struct C.sockaddr_un {
mut:
	sun_family u16
	sun_path   [108]char
}

// svc_sd_notify sends one sd_notify datagram (`msg`) to $NOTIFY_SOCKET, or a
// no-op when unset (every non-systemd host). Best-effort (sd_notify is advisory).
fn svc_sd_notify(msg string) {
	raw := os.getenv('NOTIFY_SOCKET')
	if raw == '' {
		return
	}
	// Bytes written into sun_path: an abstract socket (`@name`) is a leading NUL
	// then the name (Linux); a pathname socket is the path itself.
	mut path_bytes := raw.bytes()
	if path_bytes.len > 0 && path_bytes[0] == `@` {
		path_bytes[0] = 0
	}
	if path_bytes.len > 107 {
		return
	}
	fd := C.socket(C.AF_UNIX, C.SOCK_DGRAM, 0)
	if fd < 0 {
		return
	}
	mut addr := C.sockaddr_un{}
	addr.sun_family = u16(C.AF_UNIX)
	unsafe {
		for i := 0; i < path_bytes.len; i++ {
			addr.sun_path[i] = char(path_bytes[i])
		}
	}
	// addrlen = offsetof(sun_path) [= sizeof(sun_family) = 2 on Linux] + path len.
	addrlen := u32(2 + path_bytes.len)
	C.sendto(fd, msg.str, usize(msg.len), 0, voidptr(&addr), addrlen)
	C.close(fd)
}

// svc_sd_notify_ready signals systemd readiness (Type=notify). Call once, after
// the listener is bound and stores are open.
pub fn svc_sd_notify_ready() {
	svc_sd_notify('READY=1')
}

// svc_sd_watchdog_start starts the systemd watchdog pinger (#181). The shipped
// unit sets `WatchdogSec`, which systemd surfaces as `WATCHDOG_USEC` (µs) — a
// `Type=notify` service that never sends `WATCHDOG=1` within that window is
// SIGABRT'd and restarted every interval (the shipped daemon's kill/restart
// loop). This parses `WATCHDOG_USEC` and, from a background thread, pings
// `WATCHDOG=1` at HALF the interval (the systemd-recommended cadence — leaves
// margin for scheduling jitter) until shutdown is requested. No-op when
// `WATCHDOG_USEC` is unset (non-systemd, or `WatchdogSec` not configured).
pub fn svc_sd_watchdog_start() {
	usec_raw := os.getenv('WATCHDOG_USEC')
	if usec_raw == '' {
		return
	}
	usec := usec_raw.i64()
	if usec <= 0 {
		return
	}
	// ping at half the watchdog interval (µs → ns, /2).
	interval_ns := (usec * i64(1000)) / i64(2)
	spawn svc_sd_watchdog_loop(interval_ns)
}

fn svc_sd_watchdog_loop(interval_ns i64) {
	for {
		if g_svc_shutdown != 0 {
			return
		}
		svc_sd_notify('WATCHDOG=1')
		// sleep the interval in small slices so shutdown is observed promptly.
		mut slept := i64(0)
		for slept < interval_ns {
			if g_svc_shutdown != 0 {
				return
			}
			step := if interval_ns - slept < i64(200) * time.millisecond {
				interval_ns - slept
			} else {
				i64(200) * time.millisecond
			}
			time.sleep(step * time.nanosecond)
			slept += step
		}
	}
}
