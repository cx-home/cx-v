@[has_globals]
module platform
import code {
	crypto_jwks_parse,
	http_attr,
	http_body_octets,
	is_err_value,
	net_close_id,
	net_handle_id,
	net_mut_handle,
	net_set_read_deadline_id,
}

import cx
import sync
import os
import time
import crypto.ed25519
import encoding.hex

// #105 Phase-2 service tier — daemon lifecycle, brick 1: service configuration.
//
// Parses + validates the `cxstore.service.cx` config document (spec
// spec/03-approved/misc/cxstore_service_tier_phase2.md, Appendix A) into a typed
// ServiceConfig, failing fast with a structured diagnostic on any invalid
// config (§2.2 — no partial serve). Config is a CX document (owner decision 5a),
// so it parses through the data reader and dogfoods CX.
//
// This brick covers parse + structural validation only. Wiring the bind/listen
// loop, auth-provider runtime, and observability exporters are subsequent
// bricks; the validated shape they consume is fixed here.

// the bootstrap HTTP base path (health/ready/metrics/capabilities live here;
// the path shape survives the CSRP protocol retirement for LB/probe stability).
const svc_http_base = '/cx-store/v1/'

const e_svc_cfg = 'cx-err:CXER1711' // E_SVC_CONFIG_INVALID (service-tier config; #198 — distinct from CXER1140 E_STORE_HANDLE_RACE, which it previously collided with). Startup/CLI diagnostic; rides the wire ONLY on the §3.13 config-reload op (#251).

// ServiceConfig is the validated daemon configuration.
pub struct ServiceConfig {
pub:
	bind          string // host:port for the CSRP listener
	tls           ?TlsConfig
	grpc          GrpcConfig
	xsp           XspConfig
	stores        []StoreMount
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

// XspConfig is the opt-in XSP store-profile listener (I5 stream 4, W3 —
// spec/03-approved/xap/xsp_store_profile.md §4.1): the third daemon listener
// beside CSRP (transitional) and gRPC, destined to become THE store wire.
// Attach is XSP-AUTH, so an enabled listener REQUIRES a daemon [identity]
// (there is no anonymous responder, N-IDENT-2). [policy mode=floor
// floor=<name>] admits anonymous initiators under the host-constructed
// `floor:<name>` principal; the default posture is mutual (DID-proven
// initiators only).
pub struct XspConfig {
pub:
	enabled         bool
	addr            string
	identity_did    string
	identity_seed   []u8
	mutual          bool = true
	floor           string // 'floor:<name>' under [policy mode=floor], else ''
	liveness_ms     i64 = 30000
	handshake_ms    i64 = 10000
	max_frame_bytes i64 = 16777216
	pending_window  int = 64
	// W4 §6.1: [grants [grant did=… caps=… over=?]… [grant floor caps=…]?].
	// Non-empty ⇒ the deny-by-default VC-compiled PEP owns every verb (each
	// grant compiles to an ordinary root delegation in the SESSION's
	// authority basis at attach); empty ⇒ the W3 open posture (data verbs
	// open, admin verbs behind the CXER5018 mutual gate). The same posture
	// rule the daemon's [auth] section has always had.
	grants []XspGrant
	// W5 §7.1: [revocations journal="<tenant>"] designates the mount's
	// revocations journal — the source of the feed's `revocations` plane AND
	// of the daemon's own revoked-set fold. '' = no designation: the peer
	// token is not offered and the plane refuses (CXER5022).
	revocations_tenant string
	// W5 §7.1: [peers [peer url= did= tenant=]…] — outbound peering: the
	// daemon dials each peer as a mutual XSP-AUTH initiator, subscribes the
	// revocations plane, and folds arriving revocations into its revoked-set.
	peers []XspPeer
	// S6 §4.3 (F4a): the pushdown evaluation budget — [xsp [limits
	// [pushdown steps= memory-mb=]]]. Every daemon-side pushdown evaluation
	// arms this step limit + memory ceiling; exceeding either answers the
	// loud typed CXER5024 (engine: CXER0273), never a takedown. Only
	// positive numerics are spellable — an unbounded budget cannot be
	// written; the named defaults below apply when the section is absent.
	pushdown_steps  u64 = 100000000
	pushdown_mem_mb u64 = 512
}

// XspPeer is one outbound peering target (§7.1): the daemon-to-daemon
// revocation-propagation subscription. `did` pins the responder identity;
// `tenant` names the mount to attach at the peer.
pub struct XspPeer {
pub:
	url    string
	did    string
	tenant string
}

// XspGrant is one operator-granted root of authority: a DID (or the
// configured floor) → capability classes, optionally sliced. This is the
// CSRP DidGrant table become ordinary delegations — same operator intent,
// ONE calculus (§6.1).
pub struct XspGrant {
pub:
	did  string // '' = the floor principal
	caps []string
	over string
}

// StoreMount is one mounted store (store-per-tenant: one mount per tenant, §3.3).
pub struct StoreMount {
pub:
	name string
	url  string
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
	mut xsp := XspConfig{}
	mut stores := []StoreMount{}
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
			'xsp' {
				xsp = svc_parse_xsp(child)!
			}
			'stores' {
				stores = svc_parse_stores(child)!
			}
			'auth' {
				// S3 (RULED G2a): the bearer/RBAC plane is retired — one grant
				// table, one calculus. Hard error, never silently ignored.
				return error(': the [auth …] bearer plane is retired — operator grants ride [xsp [grants …]] (XSP-AUTH on the profile; per-call CxCall credentials on the gRPC edge)')
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
	if xsp.enabled && (xsp.addr == bind || (grpc.enabled && xsp.addr == grpc.addr)) {
		return error('${e_svc_cfg}: [xsp] addr must differ from the CSRP and gRPC addrs')
	}

	return ServiceConfig{
		bind:          bind
		tls:           tls
		grpc:          grpc
		xsp:           xsp
		stores:        stores
		observability:   obs
		limits:          limits
		query_pool:      query_pool
		read_timeout_ms: read_timeout_ms
		idle_timeout_ms: idle_timeout_ms
		drain_ms:        drain_ms
	}
}

// svc_parse_xsp reads the [xsp …] section (the store-profile listener,
// I5 stream 4 W3). Enabled requires addr + [identity]: attach is XSP-AUTH
// and there is no anonymous responder (N-IDENT-2). The identity validation
// mirrors the fabric daemon's exactly — offline-resolvable DID, 32-byte
// Ed25519 seed from the environment (never inline), seed must re-derive
// the declared DID.
fn svc_parse_xsp(el cx.Element) !XspConfig {
	enabled := svc_bool_attr(el, 'enabled')
	addr := el.attr('addr')
	mut identity_did := ''
	mut identity_seed := []u8{}
	mut mutual := true
	mut floor := ''
	mut liveness_ms := i64(30000)
	mut handshake_ms := i64(10000)
	mut max_frame_bytes := i64(16777216)
	mut pending_window := 64
	mut grants := []XspGrant{}
	mut revocations_tenant := ''
	mut peers := []XspPeer{}
	mut pushdown_steps := u64(100000000)
	mut pushdown_mem_mb := u64(512)
	xsp_child_attrs := {
		'identity':    ['did', 'seed-env']
		'policy':      ['mode', 'floor']
		'limits':      ['pending-window', 'liveness-ms', 'handshake-ms', 'max-frame-bytes']
		'grants':      []string{}
		'revocations': ['journal']
		'peers':       []string{}
	}
	for child in svc_child_elements(el) {
		// attr-EXACT inside the subsections too (#203.2): a misspelled attr is
		// a fast-fail error, never a silently dropped directive.
		if allowed := xsp_child_attrs[child.name] {
			for a in child.attrs {
				if a.name !in allowed {
					return error('${e_svc_cfg}: unknown attribute `${a.name}` in `[xsp [${child.name}]]` (recognized: ${allowed.join(', ')})')
				}
			}
		}
		match child.name {
			'identity' {
				did := child.attr('did')
				seed_env := child.attr('seed-env')
				if did == '' || seed_env == '' {
					return error('${e_svc_cfg}: [xsp [identity]] needs both did= and seed-env= — there is no anonymous responder (N-IDENT-2)')
				}
				seed_hex := os.getenv(seed_env)
				if seed_hex == '' {
					return error('${e_svc_cfg}: [xsp [identity]] seed-env "${seed_env}" is unset')
				}
				seed := hex.decode(seed_hex) or {
					return error('${e_svc_cfg}: [xsp [identity]] seed-env "${seed_env}" is not hex: ${err.msg()}')
				}
				if seed.len != 32 {
					return error('${e_svc_cfg}: [xsp [identity]] seed must be a 32-byte Ed25519 seed (got ${seed.len} bytes)')
				}
				declared := did_key_bytes(did) or {
					return error('${e_svc_cfg}: [xsp [identity]] did "${did}" is not offline-resolvable (did:key/did:peer:0 in v1)')
				}
				priv := ed25519.new_key_from_seed(seed)
				derived := []u8(priv.public_key())
				if !xsp_auth_ct_eq(declared, derived) {
					return error('${e_svc_cfg}: [xsp [identity]] seed-env "${seed_env}" does not derive did "${did}"')
				}
				identity_did = did
				identity_seed = seed.clone()
			}
			'policy' {
				mode := child.attr('mode')
				match mode {
					'', 'mutual' {}
					'floor' {
						fname := child.attr('floor')
						if fname == '' {
							return error('${e_svc_cfg}: [xsp [policy mode=floor]] needs floor=')
						}
						mutual = false
						// host-constructed prefix, so the floor never collides
						// with a real DID principal (the fabric/xap-host shape).
						floor = 'floor:${fname}'
					}
					else {
						return error('${e_svc_cfg}: [xsp [policy]] unknown mode "${mode}" (mutual|floor)')
					}
				}
			}
			'grants' {
				// W4 §6.1: each [grant] compiles to a root delegation at attach.
				for g in svc_child_elements(child) {
					if g.name != 'grant' {
						return error('${e_svc_cfg}: [xsp [grants]] holds [grant …] entries, got [${g.name}]')
					}
					for a in g.attrs {
						if a.name !in ['did', 'floor', 'caps', 'over'] {
							return error('${e_svc_cfg}: unknown attribute `${a.name}` in `[xsp [grants [grant]]]` (recognized: did, floor, caps, over)')
						}
					}
					is_floor := svc_bool_attr(g, 'floor')
					did := g.attr('did')
					if is_floor && did != '' {
						return error('${e_svc_cfg}: [xsp [grants [grant]]] takes did= OR floor=true, not both')
					}
					if !is_floor && did == '' {
						return error('${e_svc_cfg}: [xsp [grants [grant]]] needs did= (or floor=true)')
					}
					caps_str := g.attr('caps')
					caps := caps_str.split(' ').filter(it != '')
					if caps.len == 0 {
						return error('${e_svc_cfg}: [xsp [grants [grant]]] needs caps= (space-separated: read write delete admin peer)')
					}
					for c in caps {
						if c !in ['read', 'write', 'delete', 'admin', 'peer'] {
							return error('${e_svc_cfg}: [xsp [grants [grant]]] unknown capability "${c}" (the v1 grammar: read write delete admin peer — §6.1)')
						}
					}
					grants << XspGrant{
						did:  did
						caps: caps
						over: g.attr('over')
					}
				}
			}
			'revocations' {
				// W5 §7.1: the designated revocations journal — offering the
				// peer token without a servable journal would be a lie, so the
				// designation is what turns the peer surface on.
				t := child.attr('journal')
				if t == '' {
					return error('${e_svc_cfg}: [xsp [revocations]] needs journal=<tenant>')
				}
				revocations_tenant = t
			}
			'peers' {
				for p in svc_child_elements(child) {
					if p.name != 'peer' {
						return error('${e_svc_cfg}: [xsp [peers]] holds [peer …] entries, got [${p.name}]')
					}
					for a in p.attrs {
						if a.name !in ['url', 'did', 'tenant'] {
							return error('${e_svc_cfg}: unknown attribute `${a.name}` in `[xsp [peers [peer]]]` (recognized: url, did, tenant)')
						}
					}
					purl := p.attr('url')
					pdid := p.attr('did')
					ptenant := p.attr('tenant')
					if purl == '' || pdid == '' || ptenant == '' {
						return error('${e_svc_cfg}: [xsp [peers [peer]]] needs url=, did= (the pinned responder), and tenant=')
					}
					if !purl.starts_with('xsp://') && !purl.starts_with('xsps://') {
						return error('${e_svc_cfg}: [xsp [peers [peer url]]] must be xsp://host:port or xsps://host:port')
					}
					peers << XspPeer{
						url:    purl
						did:    pdid
						tenant: ptenant
					}
				}
			}
			'limits' {
				if child.has_attr('pending-window') {
					w := int(svc_int(child.attr_val('pending-window') or { cx.ScalarValue(i64(64)) }))
					if w < 1 {
						return error('${e_svc_cfg}: [xsp [limits pending-window]] must be ≥ 1')
					}
					pending_window = w
				}
				if child.has_attr('liveness-ms') {
					lv := svc_int(child.attr_val('liveness-ms') or { cx.ScalarValue(i64(30000)) })
					if lv < 1 {
						return error('${e_svc_cfg}: [xsp [limits liveness-ms]] must be ≥ 1')
					}
					liveness_ms = lv
				}
				if child.has_attr('handshake-ms') {
					hs := svc_int(child.attr_val('handshake-ms') or { cx.ScalarValue(i64(10000)) })
					if hs < 1 {
						return error('${e_svc_cfg}: [xsp [limits handshake-ms]] must be ≥ 1')
					}
					handshake_ms = hs
				}
				if child.has_attr('max-frame-bytes') {
					mb := svc_int(child.attr_val('max-frame-bytes') or {
						cx.ScalarValue(i64(16777216))
					})
					if mb < 1024 {
						return error('${e_svc_cfg}: [xsp [limits max-frame-bytes]] must be ≥ 1024')
					}
					max_frame_bytes = mb
				}
				// S6 §4.3 (F4a): [limits [pushdown steps= memory-mb=]] — the
				// pushdown evaluation budget. Positive numerics only: zero or
				// negative is a hard config error, so an unbounded budget is
				// not spellable; unknown attrs refuse loudly.
				for it in child.items {
					if it is cx.Element && it.name == 'pushdown' {
						for a in it.attrs {
							if a.name !in ['steps', 'memory-mb'] {
								return error('${e_svc_cfg}: unknown attribute `${a.name}` in `[xsp [limits [pushdown]]]` (recognized: steps, memory-mb)')
							}
						}
						if it.has_attr('steps') {
							st := svc_int(it.attr_val('steps') or { cx.ScalarValue(i64(0)) })
							if st < 1 {
								return error('${e_svc_cfg}: [xsp [limits [pushdown steps]]] must be ≥ 1 (an unbounded budget is not spellable — §4.3/F4)')
							}
							pushdown_steps = u64(st)
						}
						if it.has_attr('memory-mb') {
							mm := svc_int(it.attr_val('memory-mb') or { cx.ScalarValue(i64(0)) })
							if mm < 1 {
								return error('${e_svc_cfg}: [xsp [limits [pushdown memory-mb]]] must be ≥ 1 (an unbounded budget is not spellable — §4.3/F4)')
							}
							pushdown_mem_mb = u64(mm)
						}
					}
				}
			}
			else {
				return error('${e_svc_cfg}: unknown [xsp] subsection `[${child.name}]`')
			}
		}
	}
	if enabled {
		if addr == '' {
			return error('${e_svc_cfg}: [xsp enabled=true] requires `addr`')
		}
		if !svc_is_host_port(addr) {
			return error('${e_svc_cfg}: [xsp addr] must be `host:port`, got `${addr}`')
		}
		if identity_did == '' {
			return error('${e_svc_cfg}: [xsp enabled=true] requires an [identity did= seed-env=] — attach is XSP-AUTH')
		}
	}
	if enabled && peers.len > 0 && identity_did == '' {
		return error('${e_svc_cfg}: [xsp [peers]] needs the daemon [identity] — peering is mutual XSP-AUTH (§7.1)')
	}
	return XspConfig{
		enabled:            enabled
		addr:               addr
		identity_did:       identity_did
		identity_seed:      identity_seed
		mutual:             mutual
		floor:              floor
		liveness_ms:        liveness_ms
		handshake_ms:       handshake_ms
		max_frame_bytes:    max_frame_bytes
		pending_window:     pending_window
		grants:             grants
		revocations_tenant: revocations_tenant
		peers:              peers
		pushdown_steps:     pushdown_steps
		pushdown_mem_mb:    pushdown_mem_mb
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
		'xsp' { ['enabled', 'addr'] }
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

// (svc_parse_auth and the bearer/RBAC provider matrix — static tokens, JWT,
// DID-grant, OIDC — are RETIRED, stream-4 S3 RULED G2(a): [xsp [grants …]]
// is the ONLY grant table; authentication is XSP-AUTH on the profile and
// the per-call CxCall credential on the gRPC edge. An [auth …] config block
// is a HARD error at parse — cutover-first, no dual-accept.)

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
	return method == 'GET' && (path == svc_http_base + 'health' || path == svc_http_base + 'ready')
}

// svc_route_lifecycle returns the CX response body for a lifecycle endpoint, or
// none if the request is not a lifecycle endpoint (caller falls through to the
// authenticated CSRP store router). Health/ready are unauthenticated (§2.4).
pub fn svc_route_lifecycle(method string, path string, mut state ServiceState) ?string {
	if method != 'GET' {
		return none
	}
	if path == svc_http_base + 'health' {
		return svc_health_response()
	}
	if path == svc_http_base + 'ready' {
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
	// I5 stream 4 W6: the XSP store-profile listener's address + responder
	// DID, advertised in the server-level capabilities so a management client
	// discovers THE store wire from the HTTP bootstrap surface it already
	// knows (profile spec §8). Empty = the [xsp] listener is not enabled.
	xsp_addr string
	xsp_did  string
	// S3 (RULED G1a): the gRPC edge's per-call XSP-AUTH reads the SAME
	// [xsp …] config the profile listener runs under — grants seed the
	// authority basis, identity_did recognizes chain roots. Zero-value =
	// no grants = the open/dev posture.
	xsp_cfg XspConfig
	// The daemon's live revoked-set provider (the fold lives on the profile
	// listener). nil = no revocations designation = empty set.
	revoked_fn fn () map[string]bool = unsafe { nil }
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
				return sw_resp_retry(429, '[err code="${e_svc_rate_limited}" message="E_CSRP_RATE_LIMITED: too many requests"]', 1)
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
			name:     'store.svc.'
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
		'objects-have', 'objects-get', 'objects-put', 'refs', 'refs-set', 'aliases',
		'aliases-set']
}

// svc_metric_op_for_path classifies a non-`/cx-store/v1/<op>` path for the
// endpoint label (health/ready carry no store-name and parse outside the CSRP
// base). Anything unrecognized normalizes to `_other` downstream.
fn svc_metric_op_for_path(path string) string {
	return match path {
		svc_http_base + 'health' { 'health' }
		svc_http_base + 'ready' { 'ready' }
		else { path }
	}
}

// svc_serve_metrics renders the Prometheus exposition. S3 (RULED G3a): the
// bootstrap HTTP surface is unauthenticated operator-plane — the bind
// address is the operator's control (standard Prometheus scrapers cannot
// sign requests); the posture is stated in the spec. 404 when no registry
// is wired.
fn svc_serve_metrics(req cx.Element, ctx ServeContext) cx.Node {
	if ctx.metrics == unsafe { nil } {
		return sw_resp(404, '[err code="cx-err:CXER1707" message="E_CSRP_SERVER_INTERNAL: metrics not enabled"]')
	}
	mut m := ctx.metrics
	// request-level series + the live store-internal series (§7 introspection
	// seam): index size per mounted backend, gauged at scrape time. #207.4: emit
	// the Prometheus exposition Content-Type.
	return sw_resp_hdrs(200, m.render_prometheus() + svc_store_internal_metrics(ctx.mounts),
		[['Content-Type', 'text/plain; version=0.0.4; charset=utf-8']])
}

// svc_dispatch_request is the per-request router (lifecycle → capabilities →
// authN/Z → DoS fairness → data op). svc_handle_request wraps it with metrics.
fn svc_dispatch_request(req cx.Element, mut state ServiceState, ctx ServeContext, mut meta RequestMeta) cx.Node {
	method := http_attr(req, 'method') or { 'GET' }
	path := http_attr(req, 'path') or { '/' }
	// 1. lifecycle endpoints (daemon-level, unauthenticated, drain-independent)
	if body := svc_route_lifecycle(method, path, mut state) {
		return sw_resp(200, body)
	}
	// health/ready are exempt from rate limiting (orchestration/LB probes must
	// always answer); the pre-auth cap covers capabilities + data-op admission
	// AND the non-CSRP fallthrough below (#206.4 — a flood of bogus paths must not
	// bypass the pre-auth bucket).
	has_lim := ctx.limiter != unsafe { nil }
	mut lim := ctx.limiter
	sname, op := svc_path_parts(path) or {
		// not a bootstrap path — admission-capped, then an honest 404 (the
		// CSRP data router is retired, stream-4 S3).
		if has_lim && !lim.allow_pre_auth() {
			return sw_resp_retry(429, '[err code="${e_svc_rate_limited}" message="E_CSRP_RATE_LIMITED: too many requests"]', 1)
		}
		return sw_resp(404, '[err code="cx-err:CXER1709" message="E_CSRP_OPERATION_UNSUPPORTED: unknown path — the HTTP surface is bootstrap-only (health/ready/metrics/capabilities); the store wire is the XSP store profile"]')
	}
	if has_lim && !lim.allow_pre_auth() {
		return sw_resp_retry(429, '[err code="${e_svc_rate_limited}" message="E_CSRP_RATE_LIMITED: too many requests"]', 1)
	}
	// #196: enforce the advertised max-request-bytes → 413 CXER1705 (was
	// unreachable; LimitConfig had no byte cap).
	if i64(http_body_octets(req).len) > svc_max_request_bytes {
		return sw_resp(413, '[err code="${e_svc_too_large}" message="E_CSRP_PAYLOAD_TOO_LARGE: request body exceeds max-request-bytes (${svc_max_request_bytes})"]')
	}
	// 2. capabilities discovery (#193). Two forms (approved §3.1):
	//    - SERVER-LEVEL (no store-name): unauthenticated bootstrap; version +
	//      encodings + auth advert, NO backend fields.
	//    - PER-STORE (`/<store-name>/capabilities`): resolve the mount (404
	//      CXER1710 on unknown — no oracle-free 200), reflect that store's backend,
	//      real read/write/list flags, query-features, and limits.
	if method == 'GET' && op == 'capabilities' {
		if sname == '' {
			return sw_resp(200, svc_server_capabilities(ctx))
		}
		mount := svc_select_mount(sname, ctx.mounts) or {
			return sw_resp(404, '[err code="cx-err:CXER1710" message="E_CSRP_STORE_NOT_FOUND: ${sw_msg_esc(sname)}"]')
		}
		return sw_resp(200, svc_store_capabilities(mount, ctx))
	}
	// S3 (RULED G1a/G3a): the HTTP surface is bootstrap-ONLY and its bearer
	// plane is retired. Data/admin ops arrive ONLY as the gRPC edge's
	// synthesized `pipeline="profile"` requests, and per-CALL identity +
	// authorization were already established by grpc_call_gate (XSP-AUTH).
	// Here the limiter provides tenant-level backpressure keyed on the
	// resolved store name (the per-principal key retired with bearer).
	pid := svc_resolve_sname(sname, ctx.mounts)
	if has_lim {
		if !lim.allow_principal_rate(pid) {
			return sw_resp_retry(429, '[err code="${e_svc_rate_limited}" message="E_CSRP_RATE_LIMITED: rate exceeded"]', 1)
		}
		if !lim.acquire_principal(pid) {
			return sw_resp_retry(429, '[err code="${e_svc_rate_limited}" message="E_CSRP_RATE_LIMITED: concurrency exceeded"]', 1)
		}
	}
	// data op — route to the named store. The acquired slot is released on
	// every path via the helper return.
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
// svc_config_generation_advert emits the [config-generation N] child —
// stream 7 F3 (#714 item 3): the guarantee/capability advert BINDS the
// config-reload generation (CSRP §3.13 answers the same counter). The
// daemon computes the advert live per request, so IT can never serve a
// stale one; a CLIENT-cached advert is valid only for its generation —
// a cached advert across config-reload is a cached lie, and any consumer
// must revalidate on a generation change (consistency_vocabulary.md §3).
fn svc_config_generation_advert(ctx ServeContext) string {
	if ctx.cfgbox == unsafe { nil } {
		return ''
	}
	mut box := ctx.cfgbox
	return ' [config-generation ${box.generation()}]'
}

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
	// I5 stream 4 W6 (profile spec §8): when the [xsp] listener is up, the
	// bootstrap advert names THE store wire — address + responder DID — so a
	// management client dials the profile instead of the transitional CSRP
	// data plane. Absent = this daemon serves no profile listener.
	xsp_advert := if ctx.xsp_addr != '' {
		' [xsp [addr "${ctx.xsp_addr}"] [did "${ctx.xsp_did}"]]'
	} else {
		''
	}
	return '[capabilities [csrp-version "1.0"] [server-impl "cx-stdlib-store-ref"]${svc_config_generation_advert(ctx)} [encodings [supported "cxbin" "cxd"] [default "cxbin"]] ${admin_ops}${xsp_advert} ${rl}]'
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
	// #718 item 3 (closed in-gate, S6.5): the advert claimed zst/gz support no
	// wire lane implements — an advert states what the daemon DOES. "none" only,
	// until a compression lane actually lands.
	return '[capabilities [csrp-version "1.0"] [server-impl "cx-stdlib-store-ref"]${svc_config_generation_advert(ctx)} [backend-tier "embedded"] [backend-name "${backend}"] [encodings [supported "cxbin" "cxd"] [default "cxbin"]] [compressions [supported "none"] [default "none"]] ${qf} [read ${readf}] [write ${writef}] [list ${listf}] [iter ${listf}] ${rl}]'
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
		// tenant filtering rides the profile's XSP-AUTH now; the '*' caller
		// (the gRPC gate, already tenant-scoped by the compiled basis) sees
		// every mount.
		if tenant != '*' && tenant != name {
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

// svc_response_body extracts the body text of a [response … [body …]] node.
fn svc_response_body(n cx.Node) string {
	if n is cx.Element {
		for it in n.items {
			if it is cx.Element && it.name == 'body' {
				for b in it.items {
					if b is cx.ScalarNode {
						return sw_scalar(b)
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
	// S3 (RULED G3a): the CSRP HTTP data router is retired — HTTP is
	// bootstrap-only (health/ready/metrics/capabilities). ONLY the gRPC edge's
	// synthesized `pipeline="profile"` requests carry data/admin ops here; a
	// real HTTP data-op request (no pipeline attr) is an honest 404.
	pipeline := http_attr(req, 'pipeline') or { '' }
	if pipeline != 'profile' {
		return sw_resp(404, '[err code="cx-err:CXER1709" message="E_CSRP_OPERATION_UNSUPPORTED: the HTTP surface is bootstrap-only (health/ready/metrics/capabilities); the store wire is the XSP store profile (cx-store://) with the gRPC edge"]')
	}
	if !state.enter_request() {
		return sw_resp_retry(503, '[err code="${e_svc_unavail}" message="E_CSRP_SERVER_UNAVAILABLE: not accepting new requests"]', 5)
	}
	defer {
		state.exit_request()
	}
	// Daemon-level admin ops (§3.12/§3.13) carry no store-name — served with
	// ctx directly (the gRPC call gate already authenticated + PEP-decided).
	if op == 'mounts' {
		return sw_resp(200, svc_mounts_body(ctx, '*'))
	}
	if op == 'config-reload' {
		if ctx.reloader == unsafe { nil } {
			return sw_resp(404, '[err code="cx-err:CXER1709" message="E_CSRP_OPERATION_UNSUPPORTED: config-reload"]')
		}
		out := ctx.reloader()
		eprintln(svc_reload_log(out, 'grpc'))
		return svc_reload_response(out)
	}
	// store-scoped ops resolve the mount, then run the profile data-op core.
	local := svc_select_mount(sname, ctx.mounts) or {
		return sw_resp(404, '[err code="cx-err:CXER1710" message="E_CSRP_STORE_NOT_FOUND: ${sw_msg_esc(err.msg())}"]')
	}
	return svc_profile_data_op(req, local, op)
}

// svc_path_parts splits a CSRP path into (store-name, op). store-name is '' for
// the sole-store form. none when `path` is not under the CSRP base.
fn svc_path_parts(path string) ?(string, string) {
	if !path.starts_with(svc_http_base) {
		return none
	}
	suffix := path[svc_http_base.len..]
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
			http_respond_impl([ex, sw_resp(400, '[err code="cx-err:CXER1701" message="E_CSRP_REQUEST_MALFORMED: ${sw_msg_esc(svc_err_msg(reqn))}"]')])
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
	return !wire_req_header(req, 'connection').to_lower().contains('close')
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
	g_svc_xsp_listener_id  int
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
	g_svc_xsp_listener_id = -1 // set by svc_register_xsp_listener if the profile listener is enabled
	g_svc_drain_grace_ms = drain_grace_ms
	os.signal_opt(.term, svc_shutdown_signal_handler) or {}
	os.signal_opt(.int, svc_shutdown_signal_handler) or {}
	spawn svc_shutdown_watcher()
}

// svc_install_stdin_tether (#648): tether the daemon's lifetime to its
// spawner. A harness (or supervisor) that spawns the daemon with a PIPE on
// stdin holds the write end; when the spawner dies — a V panic skips defers,
// a SIGKILLed test binary runs no cleanup — the pipe closes, stdin reaches
// EOF, and the daemon drains gracefully instead of orphaning (squatting its
// port band, poisoning subsequent runs, and wedging make via inherited
// jobserver FDs). Opt-in via --exit-on-stdin-eof ONLY: a production daemon's
// detached/redirected stdin must never take it down.
pub fn svc_install_stdin_tether(label string) {
	spawn fn (label string) {
		mut f := os.stdin()
		mut buf := []u8{len: 256}
		for {
			n := f.read(mut buf) or { break }
			if n <= 0 {
				break
			}
		}
		eprintln('${label}: stdin EOF — spawner is gone, draining (tether, #648)')
		g_svc_shutdown = g_svc_shutdown + 1
	}(label)
}

// svc_register_grpc_listener records the gRPC listener id so the shutdown watcher
// closes BOTH listeners on signal (#211 — the gRPC listener was never registered,
// so a gRPC accept blocked in accept() was never unblocked and its in-flight
// streams were severed rather than drained). Call after the gRPC listener binds.
pub fn svc_register_grpc_listener(server cx.Node) {
	g_svc_grpc_listener_id = net_handle_id(server) or { -1 }
}

// svc_register_xsp_listener records the XSP store-profile listener id so the
// shutdown watcher closes it with the other two (the #211 lesson applied at
// birth: an unregistered listener's accept() is never unblocked on drain).
pub fn svc_register_xsp_listener(server cx.Node) {
	g_svc_xsp_listener_id = net_handle_id(server) or { -1 }
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
	if g_svc_xsp_listener_id >= 0 {
		net_close_id(g_svc_xsp_listener_id)
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
		// #628: owner-tracked reentrant acquisition — store_persist itself
		// re-enters this mutex; a raw @lock() self-deadlocked against it.
		store_lock_enter(mut ms)
		store_persist(mut ms) or {
			eprintln('cx store-serve: checkpoint of store `${name}` failed: ${err.msg()}')
		}
		store_lock_exit(mut ms)
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
