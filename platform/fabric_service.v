@[has_globals]
module platform
import code {
	err_summary,
	NetHandle,
	arg_bytes,
	arg_string,
	bytes_node,
	crypto_random_octets,
	crypto_string_node,
	err_code_of,
	is_err_value,
	mk_err,
	net_arm_read_deadline,
	net_close_id,
	net_h_read_step,
	net_h_write,
	net_handle_id,
	net_mut_handle,
	net_read_line_buf,
	render_canonical,
	x25519_clamp,
	x25519_scalar_base_mult,
}

import cx
import os
import sync
import time
import crypto.ed25519
import encoding.hex

// fabric_service.v — the cx-fabric SERVED tier (spec/03-approved/xap/fabric.md
// §13/§19.2/§19.3/§19.6; issue #531 P1): the `cx fabric-serve` daemon that
// mounts named fabrics, accepts XSP attaches, sequences durable publishes,
// pushes delivery, fans out transient traffic, and hosts consumer-group
// assignment.
//
// The wire is RAW XSP FRAMES OVER TCP/TLS (xsp.md §2) — not HTTP: fabric is
// XSP's first consumer larger than xap coordination (spec §11), and HTTP/SSE
// reach arrives as the P3 edge ADAPTER (§19.7), never as the core protocol.
//   attach    stream-0 `request` frames carrying the XSP-AUTH M1/M3 payloads;
//             the server replies M2/M4 as stream-0 `reply` frames. M1→M2 is
//             xsp-auth-challenge under the daemon's [identity]; M3→M4 is
//             [$session:attach-xsp] verbatim (the full §4 verification — no
//             second implementation), with require-mutual / anonymous-floor
//             from [policy]. The M3 [attach [tenant …]] selects the mount —
//             tenant is the leading structural partition (§19.4).
//   requests  `request` frames whose payload is one verb element; the reply
//             echoes the request's stream-id:
//               [publish stream="S" [event E] [attribution …]?] → [receipt …]
//               [subscribe stream="S" group="G"? from=N? [pattern P]]
//                                                        → [fabric-sub …]
//               [observe stream="S" [pattern P]]         → [fabric-sub …]
//               [subscribe channel="C" [pattern P]]      → [fabric-sub …]
//               [ack sub=K seq=N]                        → null
//               [emit channel="C" [value V]]             → null
//               [read channel="C"]                       → value | () absence
//             `ping` frames answer `pong`; `error` frames carry refusals.
//   push      the served tier's delivery (§19.1): matching [entry …] elements
//             arrive as `event` frames whose stream-id is the subscription id;
//             transient fan-out arrives as [channel-value channel=… [V]].
//
// Authorization is spec §11 verbatim: three independently grantable actions —
// observe / publish / consume — per stream/channel scope, deny-by-default,
// configured per principal DID; the committing actor of a served publish is
// the channel's SESSION principal (a claimed frame principal must match it,
// the §4.8 demotion rule), never a client-supplied attribution field.
//
// Backpressure is the §19.2 interim contract: grouped durable subscriptions
// get a BOUNDED PENDING WINDOW (default 64 pushed-unacked events) — at the
// bound the server stops pushing and the consumer catches up from the journal
// by offset on its next ack (the log is the buffer; a slow consumer never
// blocks a publisher). Group assignment is §19.3: sticky exclusive per
// (tenant, stream, group); failover on connection death or a missed liveness
// window (any inbound frame refreshes liveness — an idle standby-shadowed
// consumer heartbeats with `ping`); the successor resumes from the last
// COMMITTED offset, so the redelivery window is exactly the uncommitted tail.
//
// Sequencing (§10): every state mutation — journal appends included —
// serializes under one server mutex: the fabric-serve node IS the sequencer
// for the streams it mounts. Socket writes never happen under that lock: each
// connection has an outbound frame queue drained by its own writer thread, so
// a wedged consumer socket wedges only itself (its queue fills and the
// connection is closed as dead).
//
// Predicate-fn subscription patterns are an EMBEDDED-tier form: a fn value has
// no data-bin encoding, so it cannot arrive on the wire — remote subscriptions
// carry the three data forms (topic atom / terminal-.* glob / head name), and
// anything else refuses as an invalid pattern at bus_compile_pattern, exactly
// as in-proc.
//
// Operational posture rides the store-serve plumbing wholesale (§19.6):
// attr-exact-validated CX config, svc_listen/svc_listen_tls listeners,
// ServiceState readiness + svc_install_shutdown_signals drain, and an
// unauthenticated health/ready HTTP listener probe-compatible with
// `cx store-health`.

// ── #617 wire-latency tracing ─────────────────────────────────────────────
// CX_FABRIC_TRACE=1 prints one [fab-trace …] line per instrumented wire step
// to stderr: the daemon's publish-batch handler split, per-frame socket
// writes, dispatch lock-waits, and (client side, stdlib_fabric_remote.v) the
// request-turn encode/write/reply-wait split. wall-us stamps are
// CLOCK_REALTIME µs so a same-host client/daemon pair correlates across
// processes. Diagnostic only — one cached env read, zero cost when unset.

__global g_fab_trace = i8(-1)

fn fab_trace_on() bool {
	if g_fab_trace < 0 {
		g_fab_trace = if os.getenv('CX_FABRIC_TRACE') == '1' { i8(1) } else { i8(0) }
	}
	return g_fab_trace == 1
}

fn fab_trace_wall_us() i64 {
	return time.now().unix_nano() / 1000
}

// ── error band (continues stdlib_fabric.v's CXER4920–4949) ────────────────
const fab_err_denied = 'cx-err:CXER4925' // E_FABRIC_DENIED (missing observe/publish/consume grant)
const fab_err_wire = 'cx-err:CXER4926' // E_FABRIC_WIRE (malformed request on an established channel)
const fab_err_tenant = 'cx-err:CXER4927' // E_FABRIC_TENANT (attach tenant matches no mount)
const fab_err_attach = 'cx-err:CXER4928' // E_FABRIC_ATTACH (handshake state: prove without hello, attach twice, verb before attach)
const fab_err_config = 'cx-err:CXER4929' // E_FABRIC_CONFIG (boot-time config refusal)
const fab_err_rotating = 'cx-err:CXER4935' // E_FABRIC_ROTATING (#640: mount mid-rotation — publish refused, retry after [rotated])
const fab_err_rotate_blocked = 'cx-err:CXER4936' // E_FABRIC_ROTATE_BLOCKED (#640: a group's committed offset is below a boundary — sealing would strand its uncommitted tail)

// ── configuration (attr-exact validated, the store-serve idiom) ───────────

pub struct FabricMount {
pub:
	name      string
	store_url string
	tenant    string
	hash_algo string // '' = journal default (sha256)
}

pub struct FabricGrant {
pub:
	action string // observe | publish | consume | rotate
	scope  string // stream/channel name, or '*'
}

// FabricRetention is ONE per-stream retention policy (#636): the hot window
// the daemon keeps live, and what happens to what falls out of it. Policy
// DRIVES the #640 rotation mechanism — it adds no new log surgery.
//
//   [retention sweep-ms=60000
//     [stream name="jobs"   hot=100000 archive="file:///var/cx/archive"]
//     [stream name="*"      hot=500000 archive="none"]
//     [stream name="ledger" hot=100000 archive="file:///var/cx/archive" hold=true]]
//
// `hot` is the entry count each stream keeps live (the sizing dial —
// bench/xap/SIZING.md §1). `archive`: a store URL the sealed predecessor is
// preserved under, or "none" to drop it (the chain ANCHOR is retained in the
// segment index either way — nothing is ever silently lost). `hold=true` is
// the legal hold: it suspends archival AND truncation for that stream, so
// the sweeper never rotates it.
pub struct FabricRetention {
pub:
	stream  string // stream name, or '*' (the default policy)
	hot     int    // hot-window entry count (0 = no policy)
	archive string // archive store URL, or 'none'
	hold    bool   // legal hold: suspend rotation for this stream
}

pub struct FabricServiceConfig {
pub mut:
	bind               string
	health             string // '' = no health listener
	tls                ?TlsConfig
	identity_did       string
	identity_seed      []u8
	mutual             bool = true
	floor              string // 'floor:<name>' under [policy mode=floor], else ''
	pending_window     int = 64
	liveness_ms        i64 = 30000
	max_frame_bytes    i64 = 16777216
	handshake_ms       i64 = 10000
	drain_ms           i64 = 5000
	request_timeout_ms i64 = 30000 // §12.1 pending-call expiry
	mounts             []FabricMount
	grants             map[string][]FabricGrant // principal (DID or floor:<name>) → grants
	// #636 retention policy: per-stream hot windows + archive disposition,
	// evaluated by the retention sweeper every `retention_sweep_ms`
	// (0 = policy present but sweeping disabled → operator-driven [rotate]).
	retention          []FabricRetention
	retention_sweep_ms i64 = 60000
}

const fs_cfg_sections = {
	'bind':       ['addr']
	'health':     ['addr']
	'tls':        ['cert', 'key', 'ca']
	'identity':   ['did', 'seed-env']
	'policy':     ['mode', 'floor']
	'limits':     ['pending-window', 'liveness-ms', 'max-frame-bytes', 'handshake-ms',
		'request-timeout-ms']
	'timeouts':   ['drain-ms']
	'retention':  ['sweep-ms']
	'fabrics':    []string{}
	'principals': []string{}
	'anonymous':  []string{}
}

const fs_grant_actions = ['observe', 'publish', 'consume', 'rotate']

fn fs_cfg_err(msg string) string {
	return '${fab_err_config}: ${msg}'
}

// fs_check_attrs is the attr-EXACT gate (store-serve #203.2 posture): an
// unknown attribute in a known section fails the boot, never silently drops.
fn fs_check_attrs(e cx.Element, allowed []string) ! {
	for a in e.attrs {
		if a.name !in allowed {
			return error(fs_cfg_err('unknown attribute `${a.name}` in [${e.name}] (known: ${allowed.join(', ')})'))
		}
	}
}

fn fs_parse_grants(parent cx.Element, who string) ![]FabricGrant {
	mut out := []FabricGrant{}
	for g in svc_child_elements(parent) {
		if g.name != 'grant' {
			return error(fs_cfg_err('[${parent.name}] takes only [grant …] children, got [${g.name}]'))
		}
		fs_check_attrs(g, ['action', 'scope'])!
		action := g.attr('action')
		scope := g.attr('scope')
		if action !in fs_grant_actions {
			return error(fs_cfg_err('grant action must be observe|publish|consume|rotate (${who} has "${action}")'))
		}
		if scope == '' {
			return error(fs_cfg_err('grant needs a scope= (stream/channel name, or "*") on ${who}'))
		}
		out << FabricGrant{
			action: action
			scope:  scope
		}
	}
	if out.len == 0 {
		return error(fs_cfg_err('${who} declares no [grant …] rows (deny-by-default needs explicit grants)'))
	}
	return out
}

// parse_fabric_service_config parses + validates a `fabric.service.cx`
// document. Any defect — including an [identity] seed that does not re-derive
// the declared DID — is a boot refusal, never a latent runtime denial.
pub fn parse_fabric_service_config(src string) !FabricServiceConfig {
	doc := cx.parse(src) or { return error(fs_cfg_err('unparseable config: ${err.msg()}')) }
	if doc.elements.len == 0 {
		return error(fs_cfg_err('empty config document'))
	}
	root_node := doc.elements[0]
	if root_node !is cx.Element {
		return error(fs_cfg_err('config root must be `[fabric-service …]`'))
	}
	root := root_node as cx.Element
	if root.name != 'fabric-service' {
		return error(fs_cfg_err('config root must be `[fabric-service …]`, got `[${root.name}]`'))
	}
	mut cfg := FabricServiceConfig{}
	mut saw_identity := false
	for child in svc_child_elements(root) {
		allowed := fs_cfg_sections[child.name] or {
			return error(fs_cfg_err('unknown config section `[${child.name}]`'))
		}
		fs_check_attrs(child, allowed)!
		match child.name {
			'bind' {
				cfg.bind = child.attr('addr')
			}
			'health' {
				cfg.health = child.attr('addr')
				if cfg.health == '' {
					return error(fs_cfg_err('[health] requires addr='))
				}
			}
			'tls' {
				cert := svc_resolve_env(child.attr('cert'))!
				key := svc_resolve_env(child.attr('key'))!
				if cert == '' || key == '' {
					return error(fs_cfg_err('[tls] requires both cert= and key='))
				}
				ca := if child.attr('ca') != '' { svc_resolve_env(child.attr('ca'))! } else { '' }
				cfg.tls = TlsConfig{
					cert: cert
					key:  key
					ca:   ca
				}
			}
			'identity' {
				did := child.attr('did')
				seed_env := child.attr('seed-env')
				if did == '' || seed_env == '' {
					return error(fs_cfg_err('[identity] needs both did= and seed-env= — there is no anonymous responder (N-IDENT-2)'))
				}
				seed_hex := os.getenv(seed_env)
				if seed_hex == '' {
					return error(fs_cfg_err('[identity] seed-env "${seed_env}" is unset'))
				}
				seed := hex.decode(seed_hex) or {
					return error(fs_cfg_err('[identity] seed-env "${seed_env}" is not hex: ${err.msg()}'))
				}
				if seed.len != 32 {
					return error(fs_cfg_err('[identity] seed must be a 32-byte Ed25519 seed (got ${seed.len} bytes)'))
				}
				declared := did_key_bytes(did) or {
					return error(fs_cfg_err('[identity] did "${did}" is not offline-resolvable (did:key/did:peer:0 in v1)'))
				}
				priv := ed25519.new_key_from_seed(seed)
				derived := []u8(priv.public_key())
				if !xsp_auth_ct_eq(declared, derived) {
					return error(fs_cfg_err('[identity] seed-env "${seed_env}" does not derive did "${did}"'))
				}
				cfg.identity_did = did
				cfg.identity_seed = seed
				saw_identity = true
			}
			'policy' {
				mode := child.attr('mode')
				match mode {
					'', 'mutual' {}
					'floor' {
						fname := child.attr('floor')
						if fname == '' {
							return error(fs_cfg_err('[policy mode=floor] needs floor='))
						}
						cfg.mutual = false
						// host-constructed prefix, so the floor never collides
						// with a real DID principal (the xap host-auth shape).
						cfg.floor = 'floor:${fname}'
					}
					else {
						return error(fs_cfg_err('[policy] unknown mode "${mode}" (mutual|floor)'))
					}
				}
			}
			'limits' {
				if child.has_attr('pending-window') {
					w := int(svc_int(child.attr_val('pending-window') or { cx.ScalarValue(i64(64)) }))
					if w < 1 {
						return error(fs_cfg_err('[limits pending-window] must be ≥ 1'))
					}
					cfg.pending_window = w
				}
				if child.has_attr('liveness-ms') {
					lv := svc_int(child.attr_val('liveness-ms') or { cx.ScalarValue(i64(30000)) })
					if lv < 1 {
						return error(fs_cfg_err('[limits liveness-ms] must be ≥ 1'))
					}
					cfg.liveness_ms = lv
				}
				if child.has_attr('max-frame-bytes') {
					mb := svc_int(child.attr_val('max-frame-bytes') or {
						cx.ScalarValue(i64(16777216))
					})
					if mb < 1024 {
						return error(fs_cfg_err('[limits max-frame-bytes] must be ≥ 1024'))
					}
					cfg.max_frame_bytes = mb
				}
				if child.has_attr('handshake-ms') {
					hs := svc_int(child.attr_val('handshake-ms') or { cx.ScalarValue(i64(10000)) })
					if hs < 1 {
						return error(fs_cfg_err('[limits handshake-ms] must be ≥ 1'))
					}
					cfg.handshake_ms = hs
				}
				if child.has_attr('request-timeout-ms') {
					rt := svc_int(child.attr_val('request-timeout-ms') or {
						cx.ScalarValue(i64(30000))
					})
					if rt < 1 {
						return error(fs_cfg_err('[limits request-timeout-ms] must be ≥ 1'))
					}
					cfg.request_timeout_ms = rt
				}
			}
			'timeouts' {
				if child.has_attr('drain-ms') {
					dm := svc_int(child.attr_val('drain-ms') or { cx.ScalarValue(i64(5000)) })
					if dm < 0 {
						return error(fs_cfg_err('[timeouts drain-ms] must be ≥ 0'))
					}
					cfg.drain_ms = dm
				}
			}
			'retention' {
				// #636: per-stream hot windows + archive disposition. Policy
				// drives the #640 rotation mechanism; it adds no log surgery.
				if child.has_attr('sweep-ms') {
					sm := svc_int(child.attr_val('sweep-ms') or { cx.ScalarValue(i64(60000)) })
					if sm < 0 {
						return error(fs_cfg_err('[retention sweep-ms] must be ≥ 0 (0 disables sweeping — operator-driven [rotate] only)'))
					}
					cfg.retention_sweep_ms = sm
				}
				for r in svc_child_elements(child) {
					if r.name != 'stream' {
						return error(fs_cfg_err('[retention] takes only [stream …] children'))
					}
					fs_check_attrs(r, ['name', 'hot', 'archive', 'hold'])!
					sname := r.attr('name')
					if sname == '' {
						return error(fs_cfg_err('[retention [stream]] needs name= (a stream name, or "*" for the default policy)'))
					}
					hot := int(svc_int(r.attr_val('hot') or { cx.ScalarValue(i64(0)) }))
					if hot < 0 {
						return error(fs_cfg_err('[retention [stream name="${sname}"]] hot= must be ≥ 0'))
					}
					archive := r.attr('archive')
					if archive != '' && archive != 'none' && !archive.contains('://') {
						return error(fs_cfg_err('[retention [stream name="${sname}"]] archive= must be a store URL or "none" (got "${archive}")'))
					}
					hold := r.attr('hold') == 'true'
					if hot == 0 && !hold {
						return error(fs_cfg_err('[retention [stream name="${sname}"]] needs hot= (the live entry window) unless hold=true'))
					}
					for prev in cfg.retention {
						if prev.stream == sname {
							return error(fs_cfg_err('duplicate [retention [stream name="${sname}"]]'))
						}
					}
					cfg.retention << FabricRetention{
						stream:  sname
						hot:     hot
						archive: archive
						hold:    hold
					}
				}
			}
			'fabrics' {
				for m in svc_child_elements(child) {
					if m.name != 'fabric' {
						return error(fs_cfg_err('[fabrics] takes only [fabric …] children'))
					}
					fs_check_attrs(m, ['name', 'store', 'tenant', 'hash-algo'])!
					name := m.attr('name')
					url := m.attr('store')
					tenant := m.attr('tenant')
					if name == '' || url == '' || tenant == '' {
						return error(fs_cfg_err('[fabric] needs name=, store=, tenant='))
					}
					for prev in cfg.mounts {
						if prev.tenant == tenant {
							return error(fs_cfg_err('two mounts share tenant "${tenant}" — tenant is the structural partition and routes the attach (§19.4)'))
						}
					}
					cfg.mounts << FabricMount{
						name:      name
						store_url: url
						tenant:    tenant
						hash_algo: m.attr('hash-algo')
					}
				}
			}
			'principals' {
				for p in svc_child_elements(child) {
					if p.name != 'principal' {
						return error(fs_cfg_err('[principals] takes only [principal …] children'))
					}
					fs_check_attrs(p, ['did'])!
					pdid := p.attr('did')
					if pdid == '' {
						return error(fs_cfg_err('[principal] needs did='))
					}
					if pdid in cfg.grants {
						return error(fs_cfg_err('duplicate [principal did="${pdid}"]'))
					}
					cfg.grants[pdid] = fs_parse_grants(p, 'principal ${pdid}')!
				}
			}
			'anonymous' {
				// grants of the anonymous-floor principal; only meaningful with
				// [policy mode=floor] — cross-checked below.
				cfg.grants['__anonymous__'] = fs_parse_grants(child, '[anonymous]')!
			}
			else {
				return error(fs_cfg_err('unknown config section `[${child.name}]`'))
			}
		}
	}
	if cfg.bind == '' {
		return error(fs_cfg_err('[bind addr=…] is required'))
	}
	if !saw_identity {
		return error(fs_cfg_err('[identity did=… seed-env=…] is required'))
	}
	if cfg.mounts.len == 0 {
		return error(fs_cfg_err('[fabrics] must mount at least one [fabric …]'))
	}
	if anon := cfg.grants['__anonymous__'] {
		if cfg.floor == '' {
			return error(fs_cfg_err('[anonymous] grants need [policy mode=floor] (mutual policy refuses anonymous attach)'))
		}
		cfg.grants[cfg.floor] = anon
		cfg.grants.delete('__anonymous__')
	}
	return cfg
}

// fs_granted is the §11 deny-by-default check: `principal` holds `action` on
// `scope` iff a configured grant row says so ('*' = every scope).
fn fs_granted(cfg &FabricServiceConfig, principal string, action string, scope string) bool {
	grants := cfg.grants[principal] or { return false }
	for g in grants {
		if g.action == action && (g.scope == '*' || g.scope == scope) {
			return true
		}
	}
	return false
}

// ── server state ──────────────────────────────────────────────────────────

struct FsMount {
mut:
	name         string
	tenant       string
	journal_elem cx.Node
	fab_elem     cx.Node // the EMBEDDED fabric composed over the journal —
	// publish/emit/read delegate to stdlib_fabric.v verbatim (the served tier
	// is delivery over the embedded core, never a second implementation).
	// #640 rotation state: the live store URL (updates on each rotation),
	// the hot-store generation (target derivation appends -g<gen+1>), and
	// the in-flight flag — one rotation at a time, publishes refused while
	// it runs (entries appended mid-copy would vanish from the hot window
	// on the swap).
	store_url string
	gen       int = 1
	rotating  bool
}

struct FsSub {
mut:
	id      int
	conn_id int
	tenant  string
	stream  string // durable stream ('' for a transient subscription)
	channel string // full transient key `<tenant>/<scope>/<name>` ('' for durable)
	label   string // the client-visible channel name (without the tenant prefix)
	pattern BusPattern
	group   string
	observe bool
	active  bool
	// durable delivery state: cursor = next journal seq to scan; committed =
	// the group's committed offset (mirror of the persisted value); inflight =
	// pushed-unacked seqs, len-bounded by the pending window (§19.2).
	cursor    i64
	committed i64
	inflight  []i64
	// xsp.md §5.2 flow control (#560). window: the client-declared credit
	// window from `[subscribe … window=W]` (0 = undeclared → group subs use
	// the server's pending-window; observe subs stay unbounded, the
	// pre-§5 contract). credits: the observe-mode credit balance —
	// decremented per pushed event, replenished by `credit` frames.
	window  int
	credits i64
	// dropped counts transient values this WINDOWED subscription missed
	// while its credit balance was exhausted (stream 7 F7, #714 item 6):
	// a transient channel has no log to catch up from, so a credit-paused
	// push is an inherent drop — drop-oldest stays inherent, its MAGNITUDE
	// stops being invisible (the cumulative count rides every subsequent
	// [channel-value] frame as dropped=N).
	dropped i64
	// §9.1 redelivery policy (group state; max_deliveries = 0 means none).
	// `counted` marks that this assignment tenure already did its
	// head-of-tail attempt accounting — reset on failover (a new tenure's
	// redelivery is a new attempt).
	max_deliveries i64
	dlq            string
	// #642 single-pumper flags: `pumping` marks an fs_pump in flight for
	// this subscription (its render phase runs outside srv.mu); a request
	// arriving mid-pump sets `repump` and the active pumper loops.
	pumping bool
	repump  bool
	counted        bool
}

struct FsConn {
mut:
	id          int
	net_id      int
	handle      &NetHandle = unsafe { nil }
	out         chan []u8
	open        bool
	established bool
	principal   string
	tenant      string
	last_seen   i64 // unix_milli of the last inbound frame (liveness, §19.3)
	created     i64
	// the one pending handshake (connection-scoped: M1 arrived, M3 awaited)
	has_pend      bool
	pend_m1       cx.Element
	pend_m2       cx.Element
	pend_eph_priv []u8
	// the §4.4a transcript-confirmed semantic feature set (from M4's
	// [confirmed]); the post-attach advert RESTATES this, never extends it.
	confirmed_features string
}

// FsResponder is one §12.1 responder registration: the connection answering
// calls on a channel — sticky-exclusive per (tenant, channel), freed on
// connection death.
struct FsResponder {
mut:
	id      int
	conn_id int
	tenant  string
	label   string // the client-visible channel name
}

// FsPending is one in-flight §12.1 call: the requester blocks client-side on
// its own stream id while the server-assigned correlation id rides to the
// responder and back. Expired by the sweeper (request-timeout-ms); failed
// loudly on responder death.
struct FsPending {
mut:
	requester_conn   int
	requester_stream i64
	responder_conn   int
	created          i64
}

@[heap]
pub struct FabricServer {
mut:
	mu        &sync.Mutex   = unsafe { nil }
	state     &ServiceState = unsafe { nil }
	cfg       FabricServiceConfig
	mounts    map[string]&FsMount // keyed by tenant (the attach router, §19.4)
	conns     map[int]&FsConn
	subs      map[int]&FsSub
	assigns   map[string]int // "<tenant>\x00<stream>\x00<group>" → owning sub id
	next_conn int
	next_sub  int
	// §12.1 request-reply state.
	resp      map[int]&FsResponder
	resp_chan map[string]int // "<tenant>/<label>" → responder id
	pending   map[i64]&FsPending
	next_resp int
	// correlation ids live in a high band so a pushed request frame's stream
	// id can never read as one of the client's own verb-turn ids.
	next_corr i64 = 1000000000
	// pump_q — subscriptions awaiting a delivery pass (#642): verb handlers
	// request under srv.mu (fs_pump_request_locked), the connection loops
	// drain OUTSIDE it (fs_drain_pumps), so the journal read + frame render
	// never run under the sequencer lock.
	pump_q []int
	// rotate_q — mount rotations awaiting the heavy copy (#640): the verb
	// handler validates + marks the mount rotating under srv.mu; the drain
	// runs journal-rotate (the tail copy) with the lock RELEASED and swaps
	// the mount under a re-acquired lock.
	rotate_q []FsRotateJob
}

// FsRotateJob is one queued mount rotation (#640).
struct FsRotateJob {
	tenant    string
	conn_id   int
	stream    i64 // the requester's verb-turn stream id (the reply address)
	keep_n    int
}

fn fs_assign_key(tenant string, stream string, group string) string {
	return '${tenant}\x00${stream}\x00${group}'
}

// new_fabric_server opens every configured mount (journal over its store,
// embedded fabric over the journal) and returns the ready-to-serve state.
// Store capability gating applies at the journal-open effect points exactly
// as embedded fabric documents — the CLI's --allow-* flags are the authority.
pub fn new_fabric_server(cfg FabricServiceConfig) !&FabricServer {
	mut srv := &FabricServer{
		mu:    sync.new_mutex()
		state: new_service_state()
		cfg:   cfg
	}
	for m in cfg.mounts {
		mut jargs := [cx.Node(bus_str(m.store_url)), cx.Node(bus_str(m.tenant))]
		if m.hash_algo != '' {
			jargs << cx.Node(cx.Element{
				name:  code.map_marker_name
				items: [session_kv('hash-algo', bus_str(m.hash_algo))]
			})
		}
		jn := journal_stdlib_builtin('journal-open', jargs) or {
			return error('open fabric "${m.name}": journal-open unavailable')
		}
		if is_err_value(jn) {
			// #655: the mount error renders the FULL err node — the journal's
			// open-time failures carry the underlying refusal as a [cause]
			// child (#644), and printing only the outer message hid it (the
			// URL is redacted; the raw node carries the userinfo token).
			return error('open fabric "${m.name}" (${store_url_redact_userinfo(m.store_url)}): ${render_canonical(jn)}')
		}
		fn_ := fabric_open([jn])
		if is_err_value(fn_) {
			return error('open fabric "${m.name}": ${svc_err_text(fn_)}')
		}
		srv.mounts[m.tenant] = &FsMount{
			name:         m.name
			tenant:       m.tenant
			journal_elem: jn
			fab_elem:     fn_
			store_url:    m.store_url
			gen:          1
		}
	}
	return srv
}

// fabric_server_state exposes the readiness model to the CLI (health loop).
pub fn fabric_server_state(mut srv FabricServer) &ServiceState {
	return srv.state
}

// fabric_serve_shutdown closes every mount's journal (which persists and
// releases its owned store) after the accept loop drains — the durability
// barrier symmetric with store-serve's shutdown checkpoint.
pub fn fabric_serve_shutdown(mut srv FabricServer) {
	srv.mu.lock()
	mut ids := srv.conns.keys()
	for id in ids {
		fs_close_conn_locked(mut srv, id)
	}
	for _, m in srv.mounts {
		journal_stdlib_builtin('journal-close', [m.journal_elem]) or { continue }
	}
	srv.mu.unlock()
}

// ── frame plumbing ────────────────────────────────────────────────────────

// fs_frame_bytes encodes one server frame. Fabric's verb/delivery plane rides
// XSP TEXT payloads (flag bit0 clear, xsp.md §2) carrying CANONICAL CX TEXT:
// the data-bin binary payload canonicalizes general element trees (a
// single-scalar child collapses to an attribute, atoms stringify — the
// element-as-map duality the xsp-auth readers are built for), which would
// silently rewrite a published event. The text canonical form is the lossless
// canonical form — so events, entries, receipts, and errors ride it verbatim.
fn fs_frame_bytes(ftype string, stream i64, payload cx.Node) ?[]u8 {
	fr := cx.Element{
		name:  'frame'
		attrs: [xap_attr('type', ftype), xap_attr('stream', stream.str()),
			xap_attr('binary', 'false')]
		items: [
			cx.Node(cx.Element{
				name:  'payload'
				items: [cx.Node(bus_str(render_canonical(payload)))]
			}),
		]
	}
	wire := xsp_encode_one(fr)
	if is_err_value(wire) {
		return none
	}
	return arg_bytes(wire)
}

// fs_frame_bytes_bin encodes a BINARY (data-bin) frame — the attach phase
// only: the shipped $xsp:auth-* client calculus exchanges M1–M4 as data-bin
// payloads (whose readers are built for the element-as-map duality), exactly
// as the xap host does. Everything after establishment rides text frames.
fn fs_frame_bytes_bin(ftype string, stream i64, payload cx.Node) ?[]u8 {
	fr := cx.Element{
		name:  'frame'
		attrs: [xap_attr('type', ftype), xap_attr('stream', stream.str())]
		items: [
			cx.Node(cx.Element{
				name:  'payload'
				items: [payload]
			}),
		]
	}
	wire := xsp_encode_one(fr)
	if is_err_value(wire) {
		return none
	}
	return arg_bytes(wire)
}

fn fs_reply_bin_locked(mut srv FabricServer, conn_id int, stream i64, payload cx.Node) {
	b := fs_frame_bytes_bin('reply', stream, payload) or { return }
	fs_send_locked(mut srv, conn_id, b)
}

fn fs_error_bin_locked(mut srv FabricServer, conn_id int, stream i64, err_node cx.Node) {
	b := fs_frame_bytes_bin('error', stream, err_node) or { return }
	fs_send_locked(mut srv, conn_id, b)
}

// fs_send_locked enqueues frame bytes on a connection's outbound queue.
// Caller holds srv.mu. A full queue means the consumer's socket is wedged
// well past the pending window — the connection is closed as dead rather
// than ever blocking the sequencer (§19.2).
fn fs_send_locked(mut srv FabricServer, conn_id int, b []u8) {
	mut c := srv.conns[conn_id] or { return }
	if !c.open {
		return
	}
	item := b
	if c.out.try_push(&item) != .success {
		eprintln('cx fabric-serve: connection ${conn_id} outbound queue wedged — closing')
		fs_close_conn_locked(mut srv, conn_id)
	}
}

fn fs_reply_locked(mut srv FabricServer, conn_id int, stream i64, payload cx.Node) {
	b := fs_frame_bytes('reply', stream, payload) or { return }
	fs_send_locked(mut srv, conn_id, b)
}

fn fs_error_locked(mut srv FabricServer, conn_id int, stream i64, err_node cx.Node) {
	b := fs_frame_bytes('error', stream, err_node) or { return }
	fs_send_locked(mut srv, conn_id, b)
}

enum FsReadStatus {
	frame  // a complete frame was read
	idle   // no bytes arrived within one deadline tick (poll shutdown, handshake budget)
	closed // EOF / fault / oversized frame — tear the connection down
}

// fs_read_exact reads exactly n bytes off the buffered handle, re-arming the
// read deadline per transport pull. `allow_idle` (first read of a frame):
// a deadline tick with NOTHING buffered is a clean idle poll; once any frame
// byte is in flight the budget is `ticks` deadline laps before the peer is
// declared dead (a trickling frame is tolerated, a stalled one is not).
fn fs_read_exact(mut h NetHandle, n int, allow_idle bool, ticks int) (FsReadStatus, []u8) {
	mut lapses := 0
	for h.rbuf.len < n {
		if h.eof {
			return FsReadStatus.closed, []u8{}
		}
		net_arm_read_deadline(mut h)
		mut tmp := []u8{len: 4096}
		kind, rd := net_h_read_step(mut h, mut tmp)
		match kind {
			.timeout {
				if allow_idle && h.rbuf.len == 0 {
					return FsReadStatus.idle, []u8{}
				}
				lapses++
				if lapses >= ticks {
					return FsReadStatus.closed, []u8{}
				}
			}
			.eof {
				return FsReadStatus.closed, []u8{}
			}
			.data {
				unsafe {
					h.rbuf << tmp[..rd]
				}
			}
		}
	}
	out := h.rbuf[..n].clone()
	h.rbuf = h.rbuf[n..].clone()
	return FsReadStatus.frame, out
}

// fs_read_frame reads ONE self-delimiting XSP frame (17+P+L, xsp.md §2) and
// returns its raw bytes. Header sanity (version/type/lengths) fails closed.
fn fs_read_frame(mut h NetHandle, max_bytes i64) (FsReadStatus, []u8) {
	// version(1) type(1) stream(8) flags(1) principal-len(2)
	st, head := fs_read_exact(mut h, 13, true, 30)
	if st != .frame {
		return st, []u8{}
	}
	if head[0] != xsp_version {
		return FsReadStatus.closed, []u8{}
	}
	plen := (int(head[11]) << 8) | int(head[12])
	st2, prin := fs_read_exact(mut h, plen + 4, false, 30)
	if st2 != .frame {
		return FsReadStatus.closed, []u8{}
	}
	mut paylen := i64(0)
	for i in plen .. plen + 4 {
		paylen = (paylen << 8) | i64(prin[i])
	}
	if paylen > max_bytes {
		return FsReadStatus.closed, []u8{}
	}
	st3, payload := fs_read_exact(mut h, int(paylen), false, 30)
	if st3 != .frame {
		return FsReadStatus.closed, []u8{}
	}
	mut buf := []u8{cap: 17 + plen + int(paylen)}
	buf << head
	buf << prin
	buf << payload
	return FsReadStatus.frame, buf
}

// ── connection lifecycle ──────────────────────────────────────────────────

// fabric_serve_accept_loop accepts connections until the listener closes
// (svc_install_shutdown_signals closes it after the drain grace) and spawns a
// reader + writer thread per connection — fabric connections are long-lived
// duplex subscriber channels, not request/response turns, so a bounded worker
// pool would cap the subscriber count at the pool size.
pub fn fabric_serve_accept_loop(mut srv FabricServer, server cx.Node, should_stop fn () bool) {
	g_svc_state = voidptr(srv.state)
	srv.state.mark_ready()
	for {
		mut lh := net_mut_handle(server) or { break }
		conn := net_accept_real(mut lh)
		if is_err_value(conn) {
			break // listener closed (shutdown) or accept fault
		}
		if should_stop() {
			break
		}
		net_id := net_handle_id(conn) or { continue }
		mut h := net_mut_handle(conn) or { continue }
		h.read_deadline_ms = 1000 // idle tick: shutdown poll + handshake budget
		srv.mu.lock()
		srv.next_conn++
		mut c := &FsConn{
			id:        srv.next_conn
			net_id:    net_id
			handle:    h
			out:       chan []u8{cap: 1024}
			open:      true
			last_seen: time.now().unix_milli()
			created:   time.now().unix_milli()
		}
		srv.conns[c.id] = c
		srv.mu.unlock()
		spawn fs_conn_writer(mut srv, mut c)
		spawn fs_conn_reader(mut srv, mut c)
	}
	srv.state.begin_drain()
}

// fs_conn_writer drains the connection's outbound queue onto the socket —
// the ONLY thread that writes this socket, so pushed event frames and replies
// keep their enqueue order. A write fault closes the connection (which
// releases its group assignments → failover, §19.3).
fn fs_conn_writer(mut srv FabricServer, mut c FsConn) {
	tr := fab_trace_on()
	for {
		b := <-c.out or { break } // queue closed on connection teardown
		t0 := time.sys_mono_now()
		net_h_write(mut c.handle, b) or {
			srv.mu.lock()
			fs_close_conn_locked(mut srv, c.id)
			srv.mu.unlock()
			fs_drain_pumps(mut srv) // #642: write-fault failover may queue the successor
			break
		}
		if tr {
			eprintln('[fab-trace side=daemon step=conn-write conn=${c.id} bytes=${b.len} write-us=${(time.sys_mono_now() - t0) / 1000} wall-us=${fab_trace_wall_us()}]')
		}
	}
}

// fs_conn_reader is the connection's inbound loop: frames dispatch under the
// server lock; idle ticks poll shutdown and enforce the handshake budget.
fn fs_conn_reader(mut srv FabricServer, mut c FsConn) {
	for {
		st, raw := fs_read_frame(mut c.handle, srv.cfg.max_frame_bytes)
		match st {
			.idle {
				if svc_shutdown_requested() {
					break
				}
				srv.mu.lock()
				alive := c.open
				expired := !c.established
					&& time.now().unix_milli() - c.created > srv.cfg.handshake_ms
				srv.mu.unlock()
				if !alive || expired {
					break
				}
				continue
			}
			.closed {
				break
			}
			.frame {
				tr := fab_trace_on()
				t_read := time.sys_mono_now()
				node := xsp_decode_at(raw, 0)
				if node !is cx.Element {
					break
				}
				fe := node as cx.Element
				if fe.name != 'frame' {
					break // a decode err element: broken framing, tear down
				}
				t_decoded := time.sys_mono_now()
				srv.mu.lock()
				if tr {
					// a slow lock acquire here is CROSS-CONNECTION sequencer
					// contention (another conn's verb turn holds srv.mu) —
					// only notable waits print, the quiet path stays quiet.
					lock_us := (time.sys_mono_now() - t_decoded) / 1000
					if lock_us >= 100 {
						eprintln('[fab-trace side=daemon step=dispatch-wait conn=${c.id} bytes=${raw.len} decode-us=${(t_decoded - t_read) / 1000} lock-wait-us=${lock_us} wall-us=${fab_trace_wall_us()}]')
					}
				}
				if !c.open {
					srv.mu.unlock()
					break
				}
				c.last_seen = time.now().unix_milli()
				fs_dispatch_locked(mut srv, mut c, fe)
				srv.mu.unlock()
				// #642: run the deliveries this verb turn queued — journal
				// read + render happen out here, never under srv.mu.
				fs_drain_pumps(mut srv)
				// #640: run any queued mount rotation (the heavy tail copy)
				// with the sequencer lock released.
				fs_drain_rotations(mut srv)
			}
		}
	}
	srv.mu.lock()
	fs_close_conn_locked(mut srv, c.id)
	srv.mu.unlock()
	fs_drain_pumps(mut srv) // teardown failover may queue the successor
}

// fs_close_conn_locked tears one connection down (idempotent; caller holds
// srv.mu): deactivate its subscriptions, release its group assignments, and
// fail the streams over to a live group sibling — the successor resumes from
// the last COMMITTED offset, redelivering exactly the uncommitted tail.
fn fs_close_conn_locked(mut srv FabricServer, conn_id int) {
	mut c := srv.conns[conn_id] or { return }
	if !c.open {
		return
	}
	c.open = false
	c.out.close()
	net_close_id(c.net_id)
	mut freed := []string{}
	mut dead := []int{}
	for sid, mut s in srv.subs {
		if s.conn_id != conn_id {
			continue
		}
		s.active = false
		dead << sid
		if s.group != '' {
			key := fs_assign_key(s.tenant, s.stream, s.group)
			if (srv.assigns[key] or { -1 }) == sid {
				srv.assigns.delete(key)
				freed << key
			}
		}
	}
	for sid in dead {
		srv.subs.delete(sid)
	}
	// §12.1: death frees the connection's responder registrations and fails
	// its pending calls LOUDLY — a requester never waits out the timeout on a
	// responder the server already knows is gone.
	mut dead_resp := []int{}
	for rid, r in srv.resp {
		if r.conn_id == conn_id {
			dead_resp << rid
		}
	}
	for rid in dead_resp {
		r := srv.resp[rid] or { continue }
		srv.resp_chan.delete('${r.tenant}/${r.label}')
		srv.resp.delete(rid)
	}
	mut dead_pend := []i64{}
	for corr, p in srv.pending {
		if p.responder_conn == conn_id || p.requester_conn == conn_id {
			dead_pend << corr
		}
	}
	srv.conns.delete(conn_id)
	for corr in dead_pend {
		p := srv.pending[corr] or { continue }
		srv.pending.delete(corr)
		if p.responder_conn == conn_id && p.requester_conn != conn_id {
			fs_error_locked(mut srv, p.requester_conn, p.requester_stream, mk_err(fab_err_no_responder,
				'E_FABRIC_NO_RESPONDER: the responder connection died with this call in flight'))
		}
	}
	for key in freed {
		fs_failover_locked(mut srv, key, -1)
	}
}

// fs_failover_locked hands a freed (tenant,stream,group) assignment to the
// lowest-id live subscription in that group — excluding `deposed_sid` (a
// liveness-window deposal must not hand the stream straight back to the
// stale holder; pass -1 for death-failover, where the dead subs are already
// gone) — and pumps it from the committed offset (§19.3: the successor
// resumes from the last committed offset).
fn fs_failover_locked(mut srv FabricServer, key string, deposed_sid int) {
	parts := key.split('\x00')
	if parts.len != 3 {
		return
	}
	tenant, stream, group := parts[0], parts[1], parts[2]
	mut best := -1
	for sid, s in srv.subs {
		if sid != deposed_sid && s.active && s.tenant == tenant && s.stream == stream
			&& s.group == group {
			if best == -1 || sid < best {
				best = sid
			}
		}
	}
	if best == -1 {
		return
	}
	srv.assigns[key] = best
	mut s := srv.subs[best] or { return }
	mount := srv.mounts[tenant] or { return }
	j, _, jok := jrn_get_open(mount.journal_elem)
	if jok {
		s.committed = fab_load_committed(j, stream, group)
	}
	s.cursor = s.committed + 1
	s.inflight = []i64{}
	s.counted = false // a new tenure's redelivery is a new §9.1 attempt
	fs_pump_request_locked(mut srv, best)
}

// fabric_liveness_sweeper enforces the §19.3 liveness window: an assignment
// holder whose connection has sent nothing (ack/ping/any frame) for the
// window loses the assignment IF a live group sibling is waiting — no
// competitor, no churn. Runs until shutdown.
pub fn fabric_liveness_sweeper(mut srv FabricServer) {
	for {
		if svc_shutdown_requested() {
			return
		}
		time.sleep(250 * time.millisecond)
		now := time.now().unix_milli()
		srv.mu.lock()
		mut stale := []string{}
		for key, sid in srv.assigns {
			s := srv.subs[sid] or {
				stale << key
				continue
			}
			c := srv.conns[s.conn_id] or {
				stale << key
				continue
			}
			if now - c.last_seen <= srv.cfg.liveness_ms {
				continue
			}
			// missed window: reassign only when a sibling is ready to take over.
			mut sibling := false
			for osid, o in srv.subs {
				if osid != sid && o.active && o.tenant == s.tenant && o.stream == s.stream
					&& o.group == s.group {
					sibling = true
					break
				}
			}
			if sibling {
				stale << key
			}
		}
		for key in stale {
			sid := srv.assigns[key] or { continue }
			srv.assigns.delete(key)
			// the deposed holder's subscription stays live (it may win the
			// stream back on a LATER failover by heartbeating); only the
			// assignment moves, and never straight back to the stale holder.
			if mut old := srv.subs[sid] {
				old.inflight = []i64{}
			}
			fs_failover_locked(mut srv, key, sid)
		}
		// §12.1 pending-call expiry: an unanswered call past
		// request-timeout-ms fails loudly to its requester (CXER4934).
		mut expired := []i64{}
		for corr, p in srv.pending {
			if now - p.created > srv.cfg.request_timeout_ms {
				expired << corr
			}
		}
		for corr in expired {
			p := srv.pending[corr] or { continue }
			srv.pending.delete(corr)
			fs_error_locked(mut srv, p.requester_conn, p.requester_stream, mk_err(fab_err_req_timeout,
				'E_FABRIC_REQUEST_TIMEOUT: no reply within ${srv.cfg.request_timeout_ms} ms'))
		}
		srv.mu.unlock()
		fs_drain_pumps(mut srv) // #642: failovers above queue the successor's delivery
	}
}

// ── dispatch ──────────────────────────────────────────────────────────────

fn fs_dispatch_locked(mut srv FabricServer, mut c FsConn, fe cx.Element) {
	ftype := xap_elem_attr(fe, 'type')
	stream := xap_elem_attr(fe, 'stream').i64()
	if ftype == 'ping' {
		// xsp.md §5.1: pong echoes the stream-id and payload VERBATIM (opaque
		// echo). The payload used to be dropped here — the divergence the
		// stream-4 ledger recorded at W3; fixed at W6 for the parity posture
		// (the store-profile listener has echoed from birth).
		binary := xap_elem_attr(fe, 'binary') == 'true'
		mut b := []u8{}
		if pv := xsp_payload_value(fe) {
			if binary {
				b = fs_frame_bytes_bin('pong', stream, pv) or { return }
			} else {
				txt := arg_string(pv) or { '' }
				b = sx_frame_text('pong', stream, txt, false) or { return }
			}
		} else {
			b = sx_frame_text('pong', stream, '', false) or { return }
		}
		fs_send_locked(mut srv, c.id, b)
		return
	}
	if ftype == 'credit' {
		// xsp.md §5.2 (#560): grants N credits on the subscription whose id
		// is the frame's stream. Negotiated-only on the wire (the client saw
		// `credit` in [fabric-session]); meaningful for windowed observe
		// subs — a group sub's window replenishes through cumulative ack.
		if !c.established {
			fs_error_bin_locked(mut srv, c.id, stream, mk_err(fab_err_attach,
				'E_FABRIC_ATTACH: credit before attach'))
			return
		}
		n := xsp_payload_value(fe) or { cx.Node(bus_int(0)) }
		// a data-bin scalar payload decodes wrapped (`[_ 1]`) — unwrap it.
		inner := if n is cx.Element && n.items.len > 0 { n.items[0] } else { n }
		mut grant := i64(0)
		if inner is cx.ScalarNode {
			v := inner.value
			if v is i64 {
				grant = v
			}
		}
		if grant < 1 {
			fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
				'E_FABRIC_WIRE: credit frame payload must be an integer ≥ 1'))
			return
		}
		mut s := srv.subs[int(stream)] or {
			fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
				'E_FABRIC_WIRE: credit on unknown subscription ${stream}'))
			return
		}
		if s.conn_id != c.id {
			fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
				'E_FABRIC_WIRE: credit on a subscription this connection does not hold'))
			return
		}
		s.credits += grant
		fs_pump_request_locked(mut srv, int(stream))
		return
	}
	if ftype == 'reply' || ftype == 'error' {
		// §12.1: a responder answering a pushed request frame — the only
		// reply/error a client legitimately sends. The §4.8 demotion rule
		// holds here exactly as on verb frames.
		if !c.established {
			fs_error_bin_locked(mut srv, c.id, stream, mk_err(fab_err_attach,
				'E_FABRIC_ATTACH: reply before attach'))
			return
		}
		rfp := xap_elem_attr(fe, 'principal')
		if rfp != '' && rfp != c.principal {
			fs_error_locked(mut srv, c.id, stream, mk_err('cx-err:CXER-XSP-AUTH-PRINCIPAL-MISMATCH',
				'E_FABRIC: frame principal "${rfp}" ≠ session principal "${c.principal}" (§4.8)'))
			return
		}
		fs_route_rr_answer_locked(mut srv, mut c, stream, fe, ftype == 'error')
		return
	}
	if ftype != 'request' {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
			'E_FABRIC_WIRE: clients send request/reply/ping frames (got ${ftype})'))
		return
	}
	payload := xsp_payload_value(fe) or {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
			'E_FABRIC_WIRE: request frame has no payload'))
		return
	}
	if !c.established {
		fs_attach_locked(mut srv, mut c, stream, payload)
		return
	}
	// §4.8 demotion rule on the live channel: a non-empty frame principal must
	// equal the session principal byte-for-byte; empty inherits it.
	fp := xap_elem_attr(fe, 'principal')
	if fp != '' && fp != c.principal {
		fs_error_locked(mut srv, c.id, stream, mk_err('cx-err:CXER-XSP-AUTH-PRINCIPAL-MISMATCH',
			'E_FABRIC: frame principal "${fp}" ≠ session principal "${c.principal}" (§4.8)'))
		return
	}
	// verbs ride TEXT frames (canonical CX; see fs_frame_bytes): a data-bin
	// verb payload would silently canonicalize the published event's element
	// tree, so it refuses loudly instead.
	if xap_elem_attr(fe, 'binary') == 'true' {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
			'E_FABRIC_WIRE: fabric verbs ride text frames carrying canonical CX (binary=false); a data-bin payload would rewrite the event tree (element-as-map canonicalization)'))
		return
	}
	text := arg_string(payload) or {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
			'E_FABRIC_WIRE: text request payload must be a string of canonical CX'))
		return
	}
	parsed := cx.parse(text) or {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
			'E_FABRIC_WIRE: unparseable request payload: ${err.msg()}'))
		return
	}
	if parsed.elements.len == 0 || parsed.elements[0] !is cx.Element {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
			'E_FABRIC_WIRE: request payload must be one verb element'))
		return
	}
	req := parsed.elements[0] as cx.Element
	if fab_trace_on() {
		// name the sequencer HOLDER: one line per verb turn ≥ 1ms, so a
		// dispatch-wait line's culprit is the turn that printed just before it.
		t_turn := time.sys_mono_now()
		fs_dispatch_verb_locked(mut srv, mut c, stream, req)
		turn_us := (time.sys_mono_now() - t_turn) / 1000
		if turn_us >= 1000 {
			eprintln('[fab-trace side=daemon step=turn verb=${req.name} conn=${c.id} us=${turn_us} wall-us=${fab_trace_wall_us()}]')
		}
		return
	}
	fs_dispatch_verb_locked(mut srv, mut c, stream, req)
}

// fs_dispatch_verb_locked routes one established-channel verb element —
// split from fs_dispatch_locked so the #617 trace can time a turn without
// duplicating the match.
fn fs_dispatch_verb_locked(mut srv FabricServer, mut c FsConn, stream i64, req cx.Element) {
	match req.name {
		'publish' {
			fs_publish_locked(mut srv, mut c, stream, req)
		}
		'publish-batch' {
			fs_publish_batch_locked(mut srv, mut c, stream, req)
		}
		'subscribe' {
			if req.attr('channel') != '' {
				fs_subscribe_transient_locked(mut srv, mut c, stream, req)
			} else {
				fs_subscribe_durable_locked(mut srv, mut c, stream, req, false)
			}
		}
		'observe' {
			fs_subscribe_durable_locked(mut srv, mut c, stream, req, true)
		}
		'ack' {
			fs_ack_locked(mut srv, mut c, stream, req)
		}
		'emit' {
			fs_emit_locked(mut srv, mut c, stream, req)
		}
		'read' {
			fs_read_channel_locked(mut srv, mut c, stream, req)
		}
		'respond' {
			fs_respond_locked(mut srv, mut c, stream, req)
		}
		'request' {
			fs_request_locked(mut srv, mut c, stream, req)
		}
		'session' {
			// xsp.md §5.0 surface 2 (stream 4, §4.4a): semantic tokens are
			// negotiated INSIDE the signed transcript (M1/M2 offers, M4
			// confirmed); this post-attach query only tunes operational
			// limits and RESTATES the confirmed set — it never extends it.
			// `heartbeat` is operational (liveness cadence), listed always.
			mut feats := 'heartbeat'
			if c.confirmed_features != '' {
				feats += ' ' + c.confirmed_features
			}
			fs_reply_locked(mut srv, c.id, stream, cx.Node(cx.Element{
				name:  'fabric-session'
				attrs: [
					bus_attr('features', feats),
					bus_attr_int('liveness-ms', int(srv.cfg.liveness_ms)),
					bus_attr_int('pending-window', srv.cfg.pending_window),
					bus_attr_int('request-timeout-ms', int(srv.cfg.request_timeout_ms)),
				]
			}))
		}
		'rotate' {
			fs_rotate_request_locked(mut srv, mut c, stream, req)
		}
		else {
			fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
				'E_FABRIC_WIRE: unknown verb [${req.name}] (publish|subscribe|observe|ack|emit|read|respond|request|session|rotate)'))
		}
	}
}

// ── attach (XSP-AUTH responder, stream 0) ─────────────────────────────────

fn fs_attach_locked(mut srv FabricServer, mut c FsConn, stream i64, payload cx.Node) {
	if payload !is cx.Element {
		fs_error_bin_locked(mut srv, c.id, stream, mk_err(fab_err_attach,
			'E_FABRIC_ATTACH: attach expects [xsp-auth …] payloads before any verb'))
		return
	}
	msg := payload as cx.Element
	phase := xap_elem_attr(msg, 'phase')
	match phase {
		'hello' {
			// M1 → M2: fresh responder nonce/ephemeral per handshake, signed
			// challenge via the shipped calculus.
			nonce := crypto_random_octets(32) or {
				fs_error_bin_locked(mut srv, c.id, stream, mk_err(fab_err_attach,
					'E_FABRIC_ATTACH: entropy unavailable'))
				return
			}
			eph_priv := crypto_random_octets(32) or {
				fs_error_bin_locked(mut srv, c.id, stream, mk_err(fab_err_attach,
					'E_FABRIC_ATTACH: entropy unavailable'))
				return
			}
			mut sk := eph_priv.clone()
			x25519_clamp(mut sk)
			eph_pub := x25519_scalar_base_mult(sk)
			opts := cx.Node(cx.Element{
				name:  code.map_marker_name
				items: [
					session_kv('did', crypto_string_node(srv.cfg.identity_did)),
					session_kv('nonce', bytes_node(nonce)),
					session_kv('eph', bytes_node(eph_pub)),
					session_kv('key', bytes_node(srv.cfg.identity_seed)),
					// §4.4a: the daemon's semantic token set, offered inside
					// the signed transcript (the advert only RESTATES the
					// confirmed intersection — it can never extend it).
					session_kv('offer-profiles', crypto_string_node('xap')),
					session_kv('offer-features', crypto_string_node('credit publish-batch resume rotate')),
				]
			})
			m2 := xsp_auth_stdlib_builtin('xsp-auth-challenge', [cx.Node(msg), opts]) or {
				fs_error_bin_locked(mut srv, c.id, stream, mk_err(fab_err_attach,
					'E_FABRIC_ATTACH: challenge failed'))
				return
			}
			if is_err_value(m2) {
				fs_error_bin_locked(mut srv, c.id, stream, m2)
				return
			}
			c.has_pend = true
			c.pend_m1 = msg
			c.pend_m2 = m2 as cx.Element
			c.pend_eph_priv = eph_priv
			fs_reply_bin_locked(mut srv, c.id, stream, m2)
		}
		'prove' {
			// M3 → M4: [$session:attach-xsp] is the WHOLE §4 verification; the
			// M3 [attach [tenant …]] routes to the mount (structural partition).
			if !c.has_pend {
				fs_error_bin_locked(mut srv, c.id, stream, mk_err(fab_err_attach,
					'E_FABRIC_ATTACH: prove without a pending hello on this connection'))
				return
			}
			m1 := c.pend_m1
			m2 := c.pend_m2
			eph_priv := c.pend_eph_priv
			c.has_pend = false
			tenant := fs_m3_tenant(msg)
			if tenant == '' {
				fs_error_bin_locked(mut srv, c.id, stream, mk_err(fab_err_tenant,
					'E_FABRIC_TENANT: M3 [attach] names no [tenant …]'))
				return
			}
			if tenant !in srv.mounts {
				fs_error_bin_locked(mut srv, c.id, stream, mk_err(fab_err_tenant,
					'E_FABRIC_TENANT: no fabric mounted for tenant "${tenant}"'))
				return
			}
			mut cfg_items := [
				session_kv('eph-priv', bytes_node(eph_priv)),
				session_kv('tenant', crypto_string_node(tenant)),
			]
			if srv.cfg.mutual {
				cfg_items << session_kv('require-mutual', crypto_string_node('true'))
			} else {
				cfg_items << session_kv('anonymous-floor', crypto_string_node(srv.cfg.floor))
			}
			cfg := cx.Node(cx.Element{
				name:  code.map_marker_name
				items: cfg_items
			})
			attached := session_attach_xsp_impl([cx.Node(m1), cx.Node(m2), cx.Node(msg), cfg])
			if is_err_value(attached) {
				// the exact CXER-XSP-AUTH-* refusal, verbatim — fail-closed.
				fs_error_bin_locked(mut srv, c.id, stream, attached)
				return
			}
			ae := attached as cx.Element
			mut m4 := cx.Node(cx.Element{
				name: 'xsp-auth'
			})
			for it in ae.items {
				if it is cx.Element && it.name == 'confirm' && it.items.len > 0 {
					m4 = it.items[0]
				}
			}
			mut principal := xsp_auth_child_text(m1, 'initiator') or { '' }
			if principal == '' {
				principal = srv.cfg.floor
			}
			c.established = true
			c.principal = principal
			c.tenant = tenant
			// hold the transcript-confirmed feature set for the §5.0 surface-2
			// advert (restated there, never extended).
			if m4 is cx.Element {
				c.confirmed_features = xsp_auth_child_text(m4, 'confirmed-features') or { '' }
			}
			c.handle.read_deadline_ms = 1000 // keep the idle tick for shutdown polls
			fs_reply_bin_locked(mut srv, c.id, stream, m4)
		}
		else {
			fs_error_bin_locked(mut srv, c.id, stream, mk_err(fab_err_attach,
				'E_FABRIC_ATTACH: expects phase=hello or phase=prove (got "${phase}")'))
		}
	}
}

fn fs_m3_tenant(m3 cx.Element) string {
	attach := xsp_auth_child(m3, 'attach') or { return '' }
	return xsp_auth_child_text(attach, 'tenant') or { '' }
}

// ── verbs ─────────────────────────────────────────────────────────────────

// fs_publish_locked sequences one durable publish: grant check, then the
// EMBEDDED fabric_publish (journal append under the per-stream commit lock —
// the sequencing, §10) with the attribution actor FORCED to the session
// principal (§11: claimed fields never bind), then delivery pumps for every
// live subscription on the stream.
fn fs_publish_locked(mut srv FabricServer, mut c FsConn, stream i64, req cx.Element) {
	sname := req.attr('stream')
	if sname == '' {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
			'E_FABRIC_WIRE: publish needs stream='))
		return
	}
	if !fs_granted(&srv.cfg, c.principal, 'publish', sname) {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_denied,
			'E_FABRIC_DENIED: "${c.principal}" holds no publish grant on stream "${sname}"'))
		return
	}
	if mnt := srv.mounts[c.tenant] {
		if mnt.rotating {
			// #640: an append that lands mid-copy would vanish from the hot
			// window on the swap — refuse loudly; the client retries after
			// the rotation's [rotated] completes.
			fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_rotating,
				'E_FABRIC_ROTATING: mount "${mnt.name}" is rotating its journal — retry the publish shortly'))
			return
		}
	}
	mut event := cx.Node(bus_null())
	mut has_event := false
	mut extra := []cx.Node{}
	for it in req.items {
		if it is cx.Element {
			if it.name == 'event' && it.items.len > 0 {
				event = it.items[0]
				has_event = true
			} else if it.name == 'attribution' {
				// The served attribution vocabulary is CLOSED: actor/authority
				// are server-owned (the session principal commits, §11), and
				// journal ignores keys outside its own vocabulary — so
				// anything the server would drop or override refuses LOUDLY
				// instead of silently vanishing. A claimed actor equal to the
				// session principal is redundant-but-fine; a different one is
				// the §4.8 principal-mismatch refusal, exactly as the xap
				// host demotes claimed author=. Only expect-pos — the
				// caller-legitimate optimistic-concurrency key — forwards.
				for kv in it.items {
					if kv !is cx.Element {
						continue
					}
					kve := kv as cx.Element
					match kve.name {
						'actor' {
							mut claimed := ''
							if kve.items.len > 0 {
								claimed = arg_string(kve.items[0]) or { '' }
							}
							if claimed != c.principal {
								fs_error_locked(mut srv, c.id, stream, mk_err('cx-err:CXER-XSP-AUTH-PRINCIPAL-MISMATCH',
									'E_FABRIC: claimed attribution actor "${claimed}" ≠ session principal "${c.principal}" (§4.8 — the session principal commits)'))
								return
							}
						}
						'expect-pos' {
							extra << kv
						}
						else {
							fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
								'E_FABRIC_WIRE: attribution key "${kve.name}" is not client-settable on the served tier (actor/authority are the session\'s; journal ignores unknown keys — put metadata in the event)'))
							return
						}
					}
				}
			}
		}
	}
	if !has_event {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
			'E_FABRIC_WIRE: publish needs an [event …] child'))
		return
	}
	mount := srv.mounts[c.tenant] or {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_tenant,
			'E_FABRIC_TENANT: no fabric mounted for tenant "${c.tenant}"'))
		return
	}
	mut entries := [
		session_kv('actor', bus_str(c.principal)),
		session_kv('authority', bus_str('fabric:publish')),
	]
	entries << extra
	attribution := cx.Node(cx.Element{
		name:  code.map_marker_name
		items: entries
	})
	r := fabric_publish([mount.fab_elem, cx.Node(bus_str(sname)), event, attribution])
	if is_err_value(r) {
		fs_error_locked(mut srv, c.id, stream, r)
		return
	}
	fs_reply_locked(mut srv, c.id, stream, r)
	// delivery: pump every live durable subscription on this (tenant, stream).
	mut targets := []int{}
	for sid, s in srv.subs {
		if s.active && s.channel == '' && s.tenant == c.tenant && s.stream == sname {
			targets << sid
		}
	}
	for sid in targets {
		fs_pump_request_locked(mut srv, sid)
	}
}

// fs_publish_batch_locked appends N events to one stream in ONE verb turn
// (#607): [publish-batch stream=… [event …]+ [attribution …]?] →
// [receipt-batch stream=… first=F last=L count=N]. Validation is ATOMIC —
// every event shape, the grant, and the attribution vocabulary are checked
// BEFORE the first append, so a refusal appends nothing. An append-time
// FAULT mid-batch (a store failure — the journal is append-only, landed
// entries cannot be unwound) replies an [err … landed=k first=F] so the
// client folds exactly what the stream holds. Delivery pumps once for the
// whole batch. Attribution rules are fs_publish_locked's, applied once for
// the batch (the session principal commits, §11/§4.8).
fn fs_publish_batch_locked(mut srv FabricServer, mut c FsConn, stream i64, req cx.Element) {
	tr := fab_trace_on()
	t_entry := time.sys_mono_now()
	entry_wall := if tr { fab_trace_wall_us() } else { i64(0) }
	sname := req.attr('stream')
	if sname == '' {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
			'E_FABRIC_WIRE: publish-batch needs stream='))
		return
	}
	if !fs_granted(&srv.cfg, c.principal, 'publish', sname) {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_denied,
			'E_FABRIC_DENIED: "${c.principal}" holds no publish grant on stream "${sname}"'))
		return
	}
	if mnt := srv.mounts[c.tenant] {
		if mnt.rotating {
			fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_rotating,
				'E_FABRIC_ROTATING: mount "${mnt.name}" is rotating its journal — retry the batch shortly'))
			return
		}
	}
	mut events := []cx.Node{}
	for it in req.items {
		if it is cx.Element {
			if it.name == 'event' {
				if it.items.len == 0 {
					fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire, 'E_FABRIC_WIRE: publish-batch event ${
						events.len + 1} is empty — a refused batch appends NOTHING (atomic validation)'))
					return
				}
				events << it.items[0]
			} else if it.name == 'attribution' {
				for kv in it.items {
					if kv !is cx.Element {
						continue
					}
					kve := kv as cx.Element
					match kve.name {
						'actor' {
							mut claimed := ''
							if kve.items.len > 0 {
								claimed = arg_string(kve.items[0]) or { '' }
							}
							if claimed != c.principal {
								fs_error_locked(mut srv, c.id, stream, mk_err('cx-err:CXER-XSP-AUTH-PRINCIPAL-MISMATCH',
									'E_FABRIC: claimed attribution actor "${claimed}" ≠ session principal "${c.principal}" (§4.8 — the session principal commits)'))
								return
							}
						}
						'expect-pos' {
							// optimistic concurrency is a SINGLE-append
							// contract — a batch has no one position to expect.
							fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
								'E_FABRIC_WIRE: expect-pos does not compose with publish-batch (single-append optimistic concurrency) — use publish'))
							return
						}
						else {
							fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
								'E_FABRIC_WIRE: attribution key "${kve.name}" is not client-settable on the served tier (actor/authority are the session\'s; journal ignores unknown keys — put metadata in the event)'))
							return
						}
					}
				}
			}
		}
	}
	if events.len == 0 {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
			'E_FABRIC_WIRE: publish-batch needs at least one [event …] child'))
		return
	}
	mount := srv.mounts[c.tenant] or {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_tenant,
			'E_FABRIC_TENANT: no fabric mounted for tenant "${c.tenant}"'))
		return
	}
	attribution := cx.Node(cx.Element{
		name:  code.map_marker_name
		items: [
			session_kv('actor', bus_str(c.principal)),
			session_kv('authority', bus_str('fabric:publish')),
		]
	})
	// #614 group commit: the whole batch appends inside ONE store flush
	// scope — one segment pack + one manifest append instead of one per
	// event. Nothing is acknowledged until the release lands, so the
	// durability contract moves to the batch boundary.
	t_validated := time.sys_mono_now()
	jrn_flush_hold(mount.journal_elem)
	mut first := i64(0)
	mut last := i64(0)
	mut landed := 0
	mut fault := cx.Element{}
	mut has_fault := false
	for i, ev in events {
		r := fabric_publish([mount.fab_elem, cx.Node(bus_str(sname)), ev, attribution])
		if is_err_value(r) {
			if r is cx.Element {
				fault = r as cx.Element
			}
			has_fault = true
			break
		}
		mut seq := i64(0)
		if r is cx.Element {
			seq = r.attr('seq').i64()
		}
		if i == 0 {
			first = seq
		}
		last = seq
		landed++
	}
	t_appended := time.sys_mono_now()
	mut rel_failed := false
	jrn_flush_release(mount.journal_elem) or { rel_failed = true }
	t_flushed := time.sys_mono_now()
	if rel_failed {
		// nothing durable — reply landed=0. The staged in-memory state
		// self-heals at the next successful flush (the store contract); a
		// client retry may then produce duplicates, which the group's
		// at-least-once redelivery contract already tolerates.
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
			'E_FABRIC_WIRE: publish-batch flush failed — nothing durable (landed=0); retry the batch'))
		return
	}
	if has_fault {
		// append fault after `landed` durable entries: name exactly what
		// the stream now holds so the client folds the truth.
		mut fattrs := fault.attrs.clone()
		fattrs << bus_attr_int('landed', landed)
		if landed > 0 {
			fattrs << bus_attr_int('first', first)
		}
		fs_error_locked(mut srv, c.id, stream, cx.Node(cx.Element{
			name:  fault.name
			attrs: fattrs
			items: fault.items
		}))
		if landed > 0 {
			fs_batch_pump_locked(mut srv, c.tenant, sname)
		}
		return
	}
	fs_reply_locked(mut srv, c.id, stream, cx.Node(cx.Element{
		name:  'receipt-batch'
		attrs: [
			bus_attr('stream', sname),
			bus_attr_int('first', first),
			bus_attr_int('last', last),
			bus_attr_int('count', events.len),
		]
	}))
	t_replied := time.sys_mono_now()
	reply_wall := if tr { fab_trace_wall_us() } else { i64(0) }
	// delivery: ONE pump pass for the whole batch (not per event).
	fs_batch_pump_locked(mut srv, c.tenant, sname)
	if tr {
		t_done := time.sys_mono_now()
		eprintln('[fab-trace side=daemon verb=publish-batch conn=${c.id} stream=${sname} count=${events.len} entry-wall-us=${entry_wall} reply-wall-us=${reply_wall} validate-us=${(t_validated - t_entry) / 1000} append-us=${(t_appended - t_validated) / 1000} flush-us=${(t_flushed - t_appended) / 1000} reply-enq-us=${(t_replied - t_flushed) / 1000} pump-us=${(t_done - t_replied) / 1000} total-us=${(t_done - t_entry) / 1000}]')
	}
}

// fs_batch_pump_locked pumps every live durable subscription on
// (tenant, stream) once — the batch-amortized delivery pass.
fn fs_batch_pump_locked(mut srv FabricServer, tenant string, sname string) {
	mut targets := []int{}
	for sid, s in srv.subs {
		if s.active && s.channel == '' && s.tenant == tenant && s.stream == sname {
			targets << sid
		}
	}
	for sid in targets {
		fs_pump_request_locked(mut srv, sid)
	}
}

// fs_subscribe_durable_locked registers a durable subscription (observe=true
// for the read-only wire-tap form). Grouped subscriptions need `consume`,
// everything else `observe` (§11). The reply carries assigned= for grouped
// subs — sticky exclusive, a standby stays registered and takes over on
// failover (§19.3).
fn fs_subscribe_durable_locked(mut srv FabricServer, mut c FsConn, stream i64, req cx.Element, observe bool) {
	sname := req.attr('stream')
	if sname == '' {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
			'E_FABRIC_WIRE: subscribe/observe needs stream='))
		return
	}
	group := req.attr('group')
	if observe && group != '' {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_group,
			'E_FABRIC_GROUP: an observe subscription takes no group (observe is read-only; no offsets)'))
		return
	}
	action := if group != '' { 'consume' } else { 'observe' }
	if !fs_granted(&srv.cfg, c.principal, action, sname) {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_denied,
			'E_FABRIC_DENIED: "${c.principal}" holds no ${action} grant on stream "${sname}"'))
		return
	}
	pat_node := fs_pattern_child(req) or {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
			'E_FABRIC_WIRE: subscribe/observe needs a [pattern …] child (bus.md §2.2 data forms)'))
		return
	}
	pat, perr, pok := bus_compile_pattern(pat_node)
	if !pok {
		fs_error_locked(mut srv, c.id, stream, perr)
		return
	}
	mount := srv.mounts[c.tenant] or {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_tenant,
			'E_FABRIC_TENANT: no fabric mounted for tenant "${c.tenant}"'))
		return
	}
	// §9.1 policy declaration: max-deliveries= and dlq= come together or not
	// at all; the policy is group state and needs a group; declaring a DLQ
	// destination requires a publish grant on it (a consume-only principal
	// cannot write into a stream through a policy side door).
	mut decl_max := i64(0)
	decl_dlq := req.attr('dlq')
	if req.has_attr('max-deliveries') {
		decl_max = req.attr('max-deliveries').i64()
	}
	if (decl_max != 0) != (decl_dlq != '') {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_policy,
			'E_FABRIC_POLICY: max-deliveries and dlq come together or not at all'))
		return
	}
	if decl_max < 0 || (req.has_attr('max-deliveries') && decl_max < 1) {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_policy,
			'E_FABRIC_POLICY: max-deliveries must be ≥ 1'))
		return
	}
	if decl_max > 0 {
		if group == '' {
			fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_policy,
				'E_FABRIC_POLICY: a redelivery policy is group state (§9.1) — it needs a group subscription'))
			return
		}
		if !fs_granted(&srv.cfg, c.principal, 'publish', decl_dlq) {
			fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_denied,
				'E_FABRIC_DENIED: "${c.principal}" holds no publish grant on dlq stream "${decl_dlq}" (declaring a policy writes there)'))
			return
		}
	}
	mut committed := i64(0)
	mut eff_max := i64(0)
	mut eff_dlq := ''
	if group != '' {
		j, jerr, jok := jrn_get_open(mount.journal_elem)
		if !jok {
			fs_error_locked(mut srv, c.id, stream, jerr)
			return
		}
		committed = fab_load_committed(j, sname, group)
		rmax, rdlq, rerr, rok := fab_policy_resolve(j, sname, group, decl_max, decl_dlq)
		if !rok {
			fs_error_locked(mut srv, c.id, stream, rerr)
			return
		}
		eff_max = rmax
		eff_dlq = rdlq
	}
	mut cursor := i64(1)
	if req.has_attr('from') {
		// §5.3 (#560): a group's resume point is the COMMITTED offset —
		// authoritative server-side state. A client-supplied cursor could
		// skip past uncommitted events for the whole group (data loss) or
		// silently rewind it; both are operator actions, not client whims.
		if group != '' {
			fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
				'E_FABRIC_WIRE: from= is refused on a group subscription — the committed offset is the resume point (xsp.md §5.3)'))
			return
		}
		cursor = req.attr('from').i64()
		if cursor < 1 {
			fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
				'E_FABRIC_WIRE: from= must be ≥ 1'))
			return
		}
	} else if group != '' {
		cursor = committed + 1
	}
	// §5.2 (#560): the client-declared credit window. Group subs clamp to
	// the server's pending-window ceiling; observe subs start with a full
	// credit balance (undeclared observe stays unbounded — the pre-§5
	// replay contract).
	mut window := 0
	if req.has_attr('window') {
		window = int(req.attr('window').i64())
		if window < 1 {
			fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
				'E_FABRIC_WIRE: window= must be ≥ 1'))
			return
		}
		if window > srv.cfg.pending_window {
			window = srv.cfg.pending_window
		}
	}
	srv.next_sub++
	mut s := &FsSub{
		id:             srv.next_sub
		conn_id:        c.id
		tenant:         c.tenant
		stream:         sname
		pattern:        pat
		group:          group
		observe:        observe
		active:         true
		cursor:         cursor
		committed:      committed
		max_deliveries: eff_max
		dlq:            eff_dlq
		window:         window
		credits:        i64(window)
	}
	srv.subs[s.id] = s
	mut assigned := true
	if group != '' {
		key := fs_assign_key(c.tenant, sname, group)
		holder := srv.assigns[key] or { -1 }
		if holder == -1 || holder !in srv.subs {
			srv.assigns[key] = s.id
		}
		assigned = (srv.assigns[key] or { -1 }) == s.id
	}
	mut attrs := [
		bus_attr_int('id', s.id),
		bus_attr('stream', sname),
	]
	if group != '' {
		attrs << bus_attr('group', group)
		attrs << bus_attr_bool('assigned', assigned)
	}
	if observe {
		attrs << bus_attr_bool('observe', true)
	}
	// #605: the stream's head seq rides the reply, so a replay consumer can
	// stop exactly at the head instead of probing for an empty batch (one
	// receive deadline saved per boot). 0 = empty stream.
	mut head := i64(0)
	if hn := journal_stdlib_builtin('journal-head', [mount.journal_elem, cx.Node(bus_str(sname))]) {
		if hn is cx.Element && hn.name == 'entry' {
			head = hn.attr('seq').i64()
		}
	}
	attrs << bus_attr_int('head', head)
	fs_reply_locked(mut srv, c.id, stream, cx.Node(cx.Element{
		name:  'fabric-sub'
		attrs: attrs
	}))
	fs_pump_request_locked(mut srv, s.id)
}

// fs_subscribe_transient_locked registers a transient-plane subscription:
// fan-out-now on emit, latest-wins, no history/cursor/ack (§6/§12). The
// channel key is tenant-prefixed structurally (§19.4).
fn fs_subscribe_transient_locked(mut srv FabricServer, mut c FsConn, stream i64, req cx.Element) {
	label := req.attr('channel')
	if req.attr('group') != '' {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_group,
			'E_FABRIC_GROUP: transient channels take no group (no offsets, no ack)'))
		return
	}
	if !fs_granted(&srv.cfg, c.principal, 'observe', label) {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_denied,
			'E_FABRIC_DENIED: "${c.principal}" holds no observe grant on channel "${label}"'))
		return
	}
	pat_node := fs_pattern_child(req) or {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
			'E_FABRIC_WIRE: subscribe needs a [pattern …] child (bus.md §2.2 data forms)'))
		return
	}
	pat, perr, pok := bus_compile_pattern(pat_node)
	if !pok {
		fs_error_locked(mut srv, c.id, stream, perr)
		return
	}
	// Stream 7 F7: a transient subscription MAY declare a credit window
	// (xsp.md §5.2 — at zero the server MUST stop pushing). Undeclared
	// (window=0) keeps the unbounded fan-out-now contract byte-identically.
	mut twindow := 0
	if req.has_attr('window') {
		twindow = int(req.attr('window').i64())
		if twindow < 1 {
			fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
				'E_FABRIC_WIRE: window= must be >= 1 when declared'))
			return
		}
	}
	srv.next_sub++
	mut s := &FsSub{
		id:      srv.next_sub
		conn_id: c.id
		tenant:  c.tenant
		channel: '${c.tenant}/${label}'
		label:   label
		pattern: pat
		active:  true
		window:  twindow
		credits: i64(twindow)
	}
	srv.subs[s.id] = s
	fs_reply_locked(mut srv, c.id, stream, cx.Node(cx.Element{
		name:  'fabric-sub'
		attrs: [
			bus_attr_int('id', s.id),
			bus_attr('channel', label),
		]
	}))
}

fn fs_pattern_child(req cx.Element) ?cx.Node {
	for it in req.items {
		if it is cx.Element && it.name == 'pattern' && it.items.len > 0 {
			p := it.items[0]
			// a head-name pattern arrives off parsed request TEXT as element
			// content (a TextNode); bus_compile_pattern reads scalars.
			if p is cx.TextNode {
				return bus_str(p.value)
			}
			return p
		}
	}
	return none
}

// fs_pattern_matches applies the wire pattern forms (atom / terminal-.* glob
// / head). Predicate patterns cannot arrive here — a fn value has no data-bin
// encoding — so .pred is structurally unreachable and matches nothing.
fn fs_pattern_matches(pat BusPattern, msg cx.Node) bool {
	match pat.kind {
		.atom {
			topic := bus_topic_of(msg) or { return false }
			if pat.glob {
				return topic == pat.text || topic.starts_with(pat.text + '.')
			}
			return topic == pat.text
		}
		.head {
			if msg is cx.Element {
				return msg.name == pat.text
			}
			return false
		}
		.pred {
			return false
		}
	}
}

// fs_ack_locked commits a group offset cumulatively through seq (§19.5),
// persists it as store data through the journal's own store (§9), releases
// the acked in-flight window and pumps the freed room — the log-is-the-buffer
// catch-up path (§19.2).
fn fs_ack_locked(mut srv FabricServer, mut c FsConn, stream i64, req cx.Element) {
	sid := req.attr('sub').int()
	seq := req.attr('seq').i64()
	mut s := srv.subs[sid] or {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_handle,
			'E_FABRIC_HANDLE: unknown subscription id ${sid}'))
		return
	}
	if s.conn_id != c.id {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_denied,
			'E_FABRIC_DENIED: subscription ${sid} belongs to another connection'))
		return
	}
	if s.observe {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_observe_only,
			'E_FABRIC_OBSERVE_ONLY: ack on an observe subscription (observe is read-only)'))
		return
	}
	if s.group == '' || s.channel != '' {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_group,
			'E_FABRIC_GROUP: ack needs a group subscription (no group, no committable offset)'))
		return
	}
	if !req.has_attr('seq') || seq < 0 {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_offset,
			'E_FABRIC_OFFSET: ack needs seq= ≥ 0'))
		return
	}
	if seq > s.committed {
		mount := srv.mounts[s.tenant] or { return }
		j, jerr, jok := jrn_get_open(mount.journal_elem)
		if !jok {
			fs_error_locked(mut srv, c.id, stream, jerr)
			return
		}
		s.committed = seq
		fab_persist_committed(j, s.stream, s.group, seq)
	}
	s.inflight = s.inflight.filter(it > seq)
	fs_reply_locked(mut srv, c.id, stream, bus_null())
	fs_pump_request_locked(mut srv, sid)
}

// fs_emit_locked publishes on a transient channel — the EMBEDDED latest-wins
// slot (read serves from it) plus fan-out-now event frames to live matching
// subscribers (§6/§12). Best-effort by contract: no history, no ack.
fn fs_emit_locked(mut srv FabricServer, mut c FsConn, stream i64, req cx.Element) {
	label := req.attr('channel')
	if label == '' {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
			'E_FABRIC_WIRE: emit needs channel='))
		return
	}
	if !fs_granted(&srv.cfg, c.principal, 'publish', label) {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_denied,
			'E_FABRIC_DENIED: "${c.principal}" holds no publish grant on channel "${label}"'))
		return
	}
	mut value := cx.Node(bus_null())
	mut has_value := false
	for it in req.items {
		if it is cx.Element && it.name == 'value' && it.items.len > 0 {
			value = it.items[0]
			has_value = true
		}
	}
	if !has_value {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
			'E_FABRIC_WIRE: emit needs a [value …] child'))
		return
	}
	mount := srv.mounts[c.tenant] or {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_tenant,
			'E_FABRIC_TENANT: no fabric mounted for tenant "${c.tenant}"'))
		return
	}
	key := '${c.tenant}/${label}'
	r := fabric_emit([mount.fab_elem, cx.Node(bus_str(key)), value])
	if is_err_value(r) {
		fs_error_locked(mut srv, c.id, stream, r)
		return
	}
	fs_reply_locked(mut srv, c.id, stream, bus_null())
	// fan-out-now to live matching transient subscribers.
	mut targets := []int{}
	for sid, s in srv.subs {
		if s.active && s.channel == key && fs_pattern_matches(s.pattern, value) {
			targets << sid
		}
	}
	for sid in targets {
		mut s := srv.subs[sid] or { continue }
		// Stream 7 F7 (#714 item 6): a windowed transient subscription at
		// zero credits gets NO push (xsp.md §5.2) — and a transient value
		// has no log to catch up from, so the miss is an inherent drop.
		// COUNT it; the cumulative count rides every later delivery.
		if s.window > 0 && s.credits <= 0 {
			s.dropped++
			continue
		}
		mut pattrs := [bus_attr('channel', s.label)]
		if s.dropped > 0 {
			pattrs << bus_attr_int('dropped', s.dropped)
		}
		payload := cx.Node(cx.Element{
			name:  'channel-value'
			attrs: pattrs
			items: [value]
		})
		b := fs_frame_bytes('event', i64(sid), payload) or { continue }
		if s.window > 0 {
			s.credits--
		}
		fs_send_locked(mut srv, s.conn_id, b)
	}
}

// fs_read_channel_locked serves a transient channel's latest value — the
// embedded read verbatim (the empty node-set on a never-published channel:
// absence, never null).
fn fs_read_channel_locked(mut srv FabricServer, mut c FsConn, stream i64, req cx.Element) {
	label := req.attr('channel')
	if label == '' {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
			'E_FABRIC_WIRE: read needs channel='))
		return
	}
	if !fs_granted(&srv.cfg, c.principal, 'observe', label) {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_denied,
			'E_FABRIC_DENIED: "${c.principal}" holds no observe grant on channel "${label}"'))
		return
	}
	mount := srv.mounts[c.tenant] or {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_tenant,
			'E_FABRIC_TENANT: no fabric mounted for tenant "${c.tenant}"'))
		return
	}
	r := fabric_read([mount.fab_elem, cx.Node(bus_str('${c.tenant}/${label}'))])
	if is_err_value(r) {
		fs_error_locked(mut srv, c.id, stream, r)
		return
	}
	// a never-published channel reads as the empty node-set — the canonical
	// text `()` rides the wire verbatim (absence, never null; the embedded
	// contract unchanged).
	fs_reply_locked(mut srv, c.id, stream, r)
}

// ── §12.1 request-reply (calls routed between client connections) ─────────

// fs_respond_locked registers this connection as the responder for a
// transient channel — sticky-exclusive per (tenant, channel): a second
// respond while the holder lives refuses; connection death frees the
// channel (fs_close_conn_locked). Grant: `consume` on the channel (§11).
fn fs_respond_locked(mut srv FabricServer, mut c FsConn, stream i64, req cx.Element) {
	label := req.attr('channel')
	if label == '' {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
			'E_FABRIC_WIRE: respond needs channel='))
		return
	}
	if !fs_granted(&srv.cfg, c.principal, 'consume', label) {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_denied,
			'E_FABRIC_DENIED: "${c.principal}" holds no consume grant on channel "${label}"'))
		return
	}
	key := '${c.tenant}/${label}'
	if held := srv.resp_chan[key] {
		if held in srv.resp {
			fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_responder,
				'E_FABRIC_RESPONDER: channel "${label}" already has a live responder (sticky-exclusive, §12.1)'))
			return
		}
	}
	srv.next_resp++
	r := &FsResponder{
		id:      srv.next_resp
		conn_id: c.id
		tenant:  c.tenant
		label:   label
	}
	srv.resp[r.id] = r
	srv.resp_chan[key] = r.id
	fs_reply_locked(mut srv, c.id, stream, cx.Node(cx.Element{
		name:  'fabric-responder'
		attrs: [
			bus_attr_int('id', r.id),
			bus_attr('channel', label),
		]
	}))
}

// fs_request_locked routes one call: the request pushes to the responder's
// connection as a `request` frame under a server-assigned correlation
// stream-id; the requester gets NOTHING now — its reply arrives when the
// responder answers (fs_route_rr_answer_locked) or the pending call expires
// (sweeper). The sequencer never blocks on a responder. Grant: `publish` on
// the channel (§11).
fn fs_request_locked(mut srv FabricServer, mut c FsConn, stream i64, req cx.Element) {
	label := req.attr('channel')
	if label == '' {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
			'E_FABRIC_WIRE: request needs channel='))
		return
	}
	if !fs_granted(&srv.cfg, c.principal, 'publish', label) {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_denied,
			'E_FABRIC_DENIED: "${c.principal}" holds no publish grant on channel "${label}"'))
		return
	}
	mut value := cx.Node(bus_null())
	mut has_value := false
	for it in req.items {
		if it is cx.Element && it.name == 'value' && it.items.len > 0 {
			value = it.items[0]
			has_value = true
		}
	}
	if !has_value {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
			'E_FABRIC_WIRE: request needs a [value …] child'))
		return
	}
	key := '${c.tenant}/${label}'
	rid := srv.resp_chan[key] or {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_no_responder,
			'E_FABRIC_NO_RESPONDER: no live responder on channel "${label}"'))
		return
	}
	r := srv.resp[rid] or {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_no_responder,
			'E_FABRIC_NO_RESPONDER: no live responder on channel "${label}"'))
		return
	}
	srv.next_corr++
	corr := srv.next_corr
	srv.pending[corr] = &FsPending{
		requester_conn:   c.id
		requester_stream: stream
		responder_conn:   r.conn_id
		created:          time.now().unix_milli()
	}
	push := cx.Node(cx.Element{
		name:  'fabric-request'
		attrs: [
			bus_attr_int('id', corr),
			bus_attr('channel', label),
		]
		items: [
			cx.Node(cx.Element{
				name:  'value'
				items: [value]
			}),
		]
	})
	b := fs_frame_bytes('request', corr, push) or { return }
	fs_send_locked(mut srv, r.conn_id, b)
}

// fs_route_rr_answer_locked routes a responder's reply/error frame back to
// the blocked requester by correlation id. An unknown correlation (already
// expired, requester gone) drops silently — a late answer is expected noise;
// a frame from a connection that is NOT the registered responder for the
// call is ignored (the spoof guard).
fn fs_route_rr_answer_locked(mut srv FabricServer, mut c FsConn, corr i64, fe cx.Element, is_error bool) {
	p := srv.pending[corr] or { return }
	if p.responder_conn != c.id {
		return
	}
	if xap_elem_attr(fe, 'binary') == 'true' {
		fs_error_locked(mut srv, c.id, corr, mk_err(fab_err_wire,
			'E_FABRIC_WIRE: reply frames ride text canonical CX (binary=false)'))
		return
	}
	payload := xsp_payload_value(fe) or {
		fs_error_locked(mut srv, c.id, corr, mk_err(fab_err_wire,
			'E_FABRIC_WIRE: reply frame has no payload'))
		return
	}
	text := arg_string(payload) or {
		fs_error_locked(mut srv, c.id, corr, mk_err(fab_err_wire,
			'E_FABRIC_WIRE: text reply payload must be a string of canonical CX'))
		return
	}
	mut node := cx.Node(bus_empty())
	if text.trim_space() != '' && text.trim_space() != '()' {
		parsed := cx.parse(text) or {
			fs_error_locked(mut srv, c.id, corr, mk_err(fab_err_wire,
				'E_FABRIC_WIRE: unparseable reply payload: ${err.msg()}'))
			return
		}
		if parsed.elements.len > 0 {
			node = parsed.elements[0]
		}
	}
	srv.pending.delete(corr)
	ftype := if is_error { 'error' } else { 'reply' }
	b := fs_frame_bytes(ftype, p.requester_stream, node) or { return }
	fs_send_locked(mut srv, p.requester_conn, b)
}

// ── delivery pump (push under the bounded pending window, §19.2) ──────────
//
// #642: the pump's journal READ + frame RENDER run OUTSIDE srv.mu. Before,
// every consumer ack re-pumped its subscription entirely under the daemon's
// global sequencer lock — the entry read + render (~36ms avg per turn at
// K=2000) made every publisher's dispatch wait behind every consumer's
// re-render, the measured shared ceiling of both legs (#617 traces).
//
// Shape: verb handlers (which hold srv.mu) REQUEST pumps
// (fs_pump_request_locked → srv.pump_q); the lock-free drain sites
// (fs_drain_pumps — called after srv.mu is released) run fs_pump, which
// alternates a LOCKED snapshot/apply phase with an UNLOCKED read+render
// phase. Per-sub `pumping`/`repump` flags guarantee a single pumper per
// subscription (a request that arrives mid-pump sets repump; the active
// pumper loops). The §9.1 policy gate stays in the LOCKED apply phase: it
// is the rare exhaustion path, its journal writes race concurrent acks if
// run unlocked (a mid-render ack could dead-letter an entry the client
// just acked), and its cost is not the hot leg. Lock order is
// srv.mu → journal.jmu everywhere; the unlocked render takes jmu alone.

// fs_pump_request_locked queues one subscription for delivery (caller holds
// srv.mu). Deduplicated; drained by fs_drain_pumps outside the lock.
fn fs_pump_request_locked(mut srv FabricServer, sub_id int) {
	if sub_id !in srv.pump_q {
		srv.pump_q << sub_id
	}
}

// fs_drain_pumps runs every queued pump with srv.mu RELEASED between locked
// phases. Loops because a pump's apply phase can queue more (the DLQ
// cascade).
fn fs_drain_pumps(mut srv FabricServer) {
	for {
		srv.mu.@lock()
		if srv.pump_q.len == 0 {
			srv.mu.unlock()
			return
		}
		ids := srv.pump_q.clone()
		srv.pump_q.clear()
		srv.mu.unlock()
		for id in ids {
			fs_pump(mut srv, id)
		}
	}
}

// ── mount rotation (#640 — segmentation + eviction on the served tier) ────
//
// `[rotate keep-n=N]` seals every stream of the requester's tenant mount at
// its own boundary (head−N) and moves the hot window to a fresh store
// (journal-rotate streams=all), then SWAPS the mount — per-op cost tracks
// the hot window from then on. The verb needs an explicit `rotate` grant
// (deny-by-default; nobody holds it implicitly). The heavy copy runs with
// srv.mu RELEASED (the #642 drain pattern); publishes are refused while the
// mount rotates (an append landing mid-copy would vanish on the swap), and
// the reply is deferred until the swap commits.

// ── retention policy (#636 — the policy layer over #640's mechanism) ──────
//
// A policy names, per stream, the HOT WINDOW the daemon keeps live and what
// becomes of what falls out of it. The sweeper evaluates head-vs-window and
// drives the SAME rotation path an operator's `[rotate]` drives — retention
// invents no log surgery, and every rotation invariant (committed floor,
// publish refusal, off-lock copy) holds identically.

// fs_retention_for returns the policy governing `stream` — an exact-name
// entry wins over the `*` default; none means the stream is unmanaged.
fn fs_retention_for(cfg &FabricServiceConfig, stream string) ?FabricRetention {
	mut star := ?FabricRetention(none)
	for r in cfg.retention {
		if r.stream == stream {
			return r
		}
		if r.stream == '*' {
			star = r
		}
	}
	return star
}

// fabric_retention_sweeper is the #636 policy tick: for each mount, evaluate
// every stream's head against its hot window and rotate when one exceeds it.
// A stream under legal hold is never rotated. The window that governs the
// rotation is the SMALLEST hot window among the streams due (a rotation
// seals every stream at head−keep-n, so a smaller window elsewhere must not
// over-seal a stream with a larger one — see fs_rotate_run's per-stream
// floor). A blocked rotation (a group behind the boundary) is not an error
// here: the sweeper logs it and retries next tick, because the consumer is
// expected to catch up.
pub fn fabric_retention_sweeper(mut srv FabricServer) {
	if srv.cfg.retention.len == 0 || srv.cfg.retention_sweep_ms <= 0 {
		return // no policy, or sweeping disabled (operator-driven rotate only)
	}
	for {
		if svc_shutdown_requested() {
			return
		}
		time.sleep(time.Duration(srv.cfg.retention_sweep_ms * time.millisecond))
		if svc_shutdown_requested() {
			return
		}
		srv.mu.@lock()
		mut tenants := []string{}
		for t, m in srv.mounts {
			if !m.rotating {
				tenants << t
			}
		}
		srv.mu.unlock()
		for tenant in tenants {
			fs_retention_tick(mut srv, tenant)
		}
	}
}

// fs_retention_tick evaluates one mount's streams and queues a rotation when
// a hot window is exceeded.
fn fs_retention_tick(mut srv FabricServer, tenant string) {
	srv.mu.@lock()
	mnt := srv.mounts[tenant] or {
		srv.mu.unlock()
		return
	}
	if mnt.rotating {
		srv.mu.unlock()
		return
	}
	jelem := mnt.journal_elem
	srv.mu.unlock()

	// unlocked: read each stream's head and compare against its window.
	mut keep_n := 0
	mut due := []string{}
	if sl := journal_stdlib_builtin('journal-streams', [jelem]) {
		if sl is cx.Element {
			for it in sl.items {
				sname := if it is cx.ScalarNode {
					cx.scalar_value_str_public(it.value)
				} else {
					''
				}
				if sname == '' {
					continue
				}
				pol := fs_retention_for(&srv.cfg, sname) or { continue }
				if pol.hold || pol.hot <= 0 {
					continue // legal hold / unmanaged: never swept
				}
				mut head := i64(0)
				if hn := journal_stdlib_builtin('journal-head', [jelem, cx.Node(bus_str(sname))]) {
					if hn is cx.Element && hn.name == 'entry' {
						head = hn.attr('seq').i64()
					}
				}
				if head > i64(pol.hot) {
					due << sname
					// the SMALLEST due window governs — a rotation seals every
					// stream at head−keep-n, and a stream under a LARGER window
					// must not be over-sealed by a smaller one's due-ness.
					if keep_n == 0 || pol.hot < keep_n {
						keep_n = pol.hot
					}
				}
			}
		}
	}
	if due.len == 0 {
		return
	}
	// a stream under legal hold anywhere on this mount blocks the whole
	// rotation: rotation moves EVERY stream, so it cannot honor a per-stream
	// hold without leaving that stream behind.
	for r in srv.cfg.retention {
		if r.hold {
			eprintln('cx fabric-serve: retention: tenant "${tenant}" has ${due.len} stream(s) over their hot window, but stream "${r.stream}" is under legal hold — rotation suspended (release the hold, or move the held stream to its own mount)')
			return
		}
	}
	srv.mu.@lock()
	mut m := srv.mounts[tenant] or {
		srv.mu.unlock()
		return
	}
	if m.rotating {
		srv.mu.unlock()
		return
	}
	m.rotating = true
	srv.rotate_q << FsRotateJob{
		tenant:  tenant
		conn_id: 0 // sweeper-driven: no requester to reply to
		stream:  0
		keep_n:  keep_n
	}
	srv.mu.unlock()
	eprintln('cx fabric-serve: retention: rotating tenant "${tenant}" (streams over window: ${due.join(', ')}; keep-n ${keep_n})')
	fs_drain_rotations(mut srv)
}

// fs_rotate_target derives the next-generation hot store URL. v1 supports
// the local substrates a fabric daemon owns outright (file:// + mem://);
// a cx-store:// journal mount refuses — rotating a SERVED store means
// creating a mount on the store daemon, which is that daemon's lifecycle,
// not this one's.
fn fs_rotate_target(url string, gen int) (string, string) {
	mut base := url
	// strip a previous generation suffix so rotations don't stack -gN-gM.
	if idx := base.last_index('-g') {
		suffix := base[idx + 2..]
		if suffix.len > 0 && suffix.bytes().all(it.is_digit()) {
			base = base[..idx]
		}
	}
	if base.starts_with('file://') || base.starts_with('mem://') {
		return '${base}-g${gen}', ''
	}
	return '', 'rotation of a ${base.all_before('://')}:// journal mount is not supported — the hot store must be a substrate this daemon owns (file:// or mem://); a served (cx-store://) journal store rotates on the store daemon side'
}

// fs_rotate_request_locked validates + queues one rotation (caller holds
// srv.mu). The reply is DEFERRED — it lands after the swap commits (or the
// refusal surfaces from the drain).
fn fs_rotate_request_locked(mut srv FabricServer, mut c FsConn, stream i64, req cx.Element) {
	if !fs_granted(&srv.cfg, c.principal, 'rotate', '*') {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_denied,
			'E_FABRIC_DENIED: "${c.principal}" holds no rotate grant'))
		return
	}
	keep_n := req.attr('keep-n').int()
	if keep_n <= 0 {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire,
			'E_FABRIC_WIRE: rotate needs keep-n= (a positive per-stream hot-window size)'))
		return
	}
	mut mnt := srv.mounts[c.tenant] or {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_tenant,
			'E_FABRIC_TENANT: no mount for tenant "${c.tenant}"'))
		return
	}
	if mnt.rotating {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_rotating,
			'E_FABRIC_ROTATING: mount "${mnt.name}" is already rotating'))
		return
	}
	_, terr := fs_rotate_target(mnt.store_url, mnt.gen + 1)
	if terr != '' {
		fs_error_locked(mut srv, c.id, stream, mk_err(fab_err_wire, 'E_FABRIC_WIRE: ${terr}'))
		return
	}
	mnt.rotating = true
	srv.rotate_q << FsRotateJob{
		tenant:  c.tenant
		conn_id: c.id
		stream:  stream
		keep_n:  keep_n
	}
}

// fs_drain_rotations runs queued rotations with srv.mu released around the
// heavy copy. Called after fs_drain_pumps at the connection loops' drain
// points.
fn fs_drain_rotations(mut srv FabricServer) {
	for {
		srv.mu.@lock()
		if srv.rotate_q.len == 0 {
			srv.mu.unlock()
			return
		}
		jobs := srv.rotate_q.clone()
		srv.rotate_q.clear()
		srv.mu.unlock()
		for job in jobs {
			fs_rotate_run(mut srv, job)
		}
	}
}

// fs_rotate_fail clears the rotating flag and surfaces the refusal to the
// requester.
fn fs_rotate_fail(mut srv FabricServer, job FsRotateJob, errn cx.Node) {
	srv.mu.@lock()
	if mut mnt := srv.mounts[job.tenant] {
		mnt.rotating = false
	}
	if job.conn_id != 0 {
		fs_error_locked(mut srv, job.conn_id, job.stream, errn)
	}
	srv.mu.unlock()
	if job.conn_id == 0 {
		// #636 sweeper-driven: no requester to answer. A blocked rotation is
		// EXPECTED (a consumer is behind) — log and retry next tick; anything
		// else is a real fault and says so.
		ecode := err_code_of(errn)
		if ecode == fab_err_rotate_blocked {
			eprintln('cx fabric-serve: retention: rotation of "${job.tenant}" deferred — ${svc_err_text(errn)}')
		} else {
			eprintln('cx fabric-serve: retention: rotation of "${job.tenant}" FAILED — ${svc_err_text(errn)}')
		}
	}
}

fn fs_rotate_run(mut srv FabricServer, job FsRotateJob) {
	// ── locked: snapshot the mount ──
	srv.mu.@lock()
	mnt0 := srv.mounts[job.tenant] or {
		srv.mu.unlock()
		return
	}
	jelem := mnt0.journal_elem
	old_url := mnt0.store_url
	gen := mnt0.gen
	seed_hex := srv.cfg.identity_seed.hex()
	// LIVE group state joins the persisted offsets in the floor check below: a
	// group that has never acked holds NO offset alias, so the persisted scan
	// alone would not see it — and it is exactly the consumer a rotation would
	// strand (committed 0).
	mut live_groups := [][]string{}
	for _, s in srv.subs {
		if s.active && s.channel == '' && s.group != '' && s.tenant == job.tenant {
			live_groups << [s.stream, s.group, s.committed.str()]
		}
	}
	srv.mu.unlock()

	target, terr := fs_rotate_target(old_url, gen + 1)
	if terr != '' {
		fs_rotate_fail(mut srv, job, mk_err(fab_err_wire, 'E_FABRIC_WIRE: ${terr}'))
		return
	}
	// ── unlocked: the committed-floor guard — sealing a seq range some group
	// has not committed through would strand its uncommitted tail in the cold
	// segment; refuse with the offending group named. Persisted offsets are
	// the authority (a group with no live subscription still holds one).
	j, _, jok := jrn_get_open(jelem)
	if !jok {
		fs_rotate_fail(mut srv, job, mk_err(fab_err_wire, 'E_FABRIC_WIRE: rotate found no open journal'))
		return
	}
	// journal-streams answers a SEQUENCE OF NAMES (scalars), not elements.
	mut heads := map[string]i64{}
	if sl := journal_stdlib_builtin('journal-streams', [jelem]) {
		if sl is cx.Element {
			for it in sl.items {
				sname := if it is cx.ScalarNode {
					cx.scalar_value_str_public(it.value)
				} else {
					''
				}
				if sname == '' {
					continue
				}
				if hn := journal_stdlib_builtin('journal-head', [jelem, cx.Node(bus_str(sname))]) {
					if hn is cx.Element && hn.name == 'entry' {
						heads[sname] = hn.attr('seq').i64()
					}
				}
			}
		}
	}
	// every (stream, group) pair the mount knows: persisted offsets + live
	// subscriptions (the union — see the live_groups note above).
	mut pairs := [][]string{}
	lst := store_stdlib_builtin('store-list-aliases', [jrn_store_handle(j.store_id)]) or {
		cx.Node(bus_null())
	}
	if lst is cx.Element {
		prefix := 'fabric/${job.tenant}/'
		for it in lst.items {
			if it is cx.Element && it.name == 'alias' {
				aname := it.attr('name')
				if !aname.starts_with(prefix) || !aname.ends_with('/offset') {
					continue
				}
				rest := aname[prefix.len..aname.len - '/offset'.len]
				parts := rest.split('/')
				if parts.len == 2 {
					pairs << [parts[0], parts[1], '']
				}
			}
		}
	}
	for lg in live_groups {
		mut seen := false
		for p in pairs {
			if p[0] == lg[0] && p[1] == lg[1] {
				seen = true
				break
			}
		}
		if !seen {
			pairs << [lg[0], lg[1], lg[2]]
		}
	}
	for p in pairs {
		sname := p[0]
		group := p[1]
		head := heads[sname] or { continue }
		mut boundary := head - job.keep_n
		if boundary < 0 {
			boundary = 0
		}
		if boundary == 0 {
			continue
		}
		// the persisted offset is the authority; a live-only group with no
		// persisted offset uses its in-memory committed mirror.
		mut committed := fab_load_committed(j, sname, group)
		if p[2] != '' && committed == 0 {
			committed = p[2].i64()
		}
		if committed < boundary {
			fs_rotate_fail(mut srv, job, mk_err(fab_err_rotate_blocked,
				'E_FABRIC_ROTATE_BLOCKED: group "${group}" on stream "${sname}" is committed through ${committed} < boundary ${boundary} — sealing would strand its uncommitted tail'))
			return
		}
	}
	// ── unlocked: the heavy copy ──
	r := journal_stdlib_builtin('journal-rotate', [jelem, cx.Node(cx.Element{
		name:  code.map_marker_name
		items: [
			session_kv('streams', bus_str('all')),
			session_kv('keep-n', bus_int(job.keep_n)),
			session_kv('target', bus_str(target)),
			session_kv('signing-key', bus_str(seed_hex)),
			session_kv('carry', bus_str('fabric/${job.tenant}/')),
		]
	})]) or {
		fs_rotate_fail(mut srv, job, mk_err(fab_err_wire, 'E_FABRIC_WIRE: journal-rotate unavailable'))
		return
	}
	if is_err_value(r) {
		fs_rotate_fail(mut srv, job, r)
		return
	}
	re := r as cx.Element
	mut new_j := cx.Node(cx.Element{})
	mut have_j := false
	for it in re.items {
		if it is cx.Element && it.name == 'journal' {
			new_j = it
			have_j = true
		}
	}
	if !have_j {
		fs_rotate_fail(mut srv, job, mk_err(fab_err_wire, 'E_FABRIC_WIRE: rotation returned no journal'))
		return
	}
	new_fab := fabric_open([new_j])
	if is_err_value(new_fab) {
		fs_rotate_fail(mut srv, job, new_fab)
		return
	}
	// ── locked: the swap — the eviction moment ──
	srv.mu.@lock()
	mut mnt := srv.mounts[job.tenant] or {
		srv.mu.unlock()
		return
	}
	old_jelem := mnt.journal_elem
	mnt.journal_elem = new_j
	mnt.fab_elem = new_fab
	mnt.store_url = target
	mnt.gen = gen + 1
	mnt.rotating = false
	mut reply_attrs := []cx.Attribute{}
	for a in re.attrs {
		reply_attrs << a
	}
	if job.conn_id != 0 {
		fs_reply_locked(mut srv, job.conn_id, job.stream, cx.Node(cx.Element{
			name:  'rotated'
			attrs: reply_attrs
		}))
	}
	// wake every durable subscription on the tenant — cursors stay valid
	// (committed ≥ boundary was enforced above; the hot window keeps
	// boundary..head).
	for sid, s in srv.subs {
		if s.active && s.channel == '' && s.tenant == job.tenant {
			fs_pump_request_locked(mut srv, sid)
		}
	}
	srv.mu.unlock()
	// close the OLD journal handle (owns_store → persists + releases the old
	// store: the sealed segment at rest) and deliver the queued pumps.
	journal_stdlib_builtin('journal-close', [old_jelem]) or { cx.Node(bus_null()) }
	fs_drain_pumps(mut srv)
	// #636 archive disposition: the sealed predecessor is preserved under the
	// policy's archive store, or dropped when the policy says `none`. The
	// chain ANCHOR stays in the segment index either way — an archived
	// segment is rehydratable, a dropped one is still provably accounted for
	// (nothing is ever silently lost).
	fs_retention_dispose(mut srv, job.tenant, old_url, new_j)
}

// fs_retention_dispose applies the archive disposition to a just-sealed
// predecessor store. Uses the mount's governing policy (the `*` default when
// no stream-specific entry exists); an unmanaged mount keeps its predecessor
// in place, which is the conservative default.
fn fs_retention_dispose(mut srv FabricServer, tenant string, sealed_url string, hot_journal cx.Node) {
	pol := fs_retention_for(&srv.cfg, '*') or { return }
	if pol.hold {
		return // legal hold: never archive, never truncate
	}
	if pol.archive == '' {
		return // no disposition configured: leave the sealed store in place
	}
	if pol.archive == 'none' {
		// EPHEMERAL: drop the sealed store. Only a substrate the daemon owns
		// outright is dropped, and only after the swap — the live chain no
		// longer references it, and the anchor survives in the segment index.
		if sealed_url.starts_with('file://') {
			path := sealed_url['file://'.len..]
			os.rmdir_all(path) or {
				eprintln('cx fabric-serve: retention: could not drop sealed store ${store_url_redact_userinfo(sealed_url)}: ${err}')
				return
			}
			// Stream 20 (erasure_compliance §7): record the disposition on the
			// segment index so it stays TRUTHFUL — the erase walk follows it
			// (a dropped segment holds nothing to shred; an unrecorded drop
			// would read as an unreachable compliance surface).
			journal_stdlib_builtin('journal-segment-disposed', [hot_journal,
				bus_str(sealed_url), bus_str('none')]) or { cx.Node(bus_null()) }
			eprintln('cx fabric-serve: retention: dropped sealed store ${store_url_redact_userinfo(sealed_url)} (archive="none"; the chain anchor is retained in the segment index)')
		}
		return
	}
	// ARCHIVE: copy the sealed store into the archive namespace under a
	// tenant/generation-qualified name, then drop the local copy. `store-clone`
	// is the porcelain that copies a whole store preserving content-hash IDs.
	if !sealed_url.starts_with('file://') {
		return
	}
	name := sealed_url.all_after_last('/')
	dest := '${pol.archive.trim_right('/')}/${tenant}/${name}'
	src := store_stdlib_builtin('store-open', [bus_str(sealed_url)]) or { return }
	if is_err_value(src) {
		eprintln('cx fabric-serve: retention: archive open failed for ${store_url_redact_userinfo(sealed_url)}: ${svc_err_text(src)}')
		return
	}
	dst := store_stdlib_builtin('store-open', [bus_str(dest)]) or { return }
	if is_err_value(dst) {
		eprintln('cx fabric-serve: retention: archive target open failed for ${store_url_redact_userinfo(dest)}: ${svc_err_text(dst)}')
		return
	}
	r := store_stdlib_builtin('store-clone', [src, dst]) or { return }
	if is_err_value(r) {
		eprintln('cx fabric-serve: retention: archive copy failed for ${store_url_redact_userinfo(sealed_url)}: ${svc_err_text(r)}')
		return
	}
	store_stdlib_builtin('store-close', [dst]) or { cx.Node(bus_null()) }
	store_stdlib_builtin('store-close', [src]) or { cx.Node(bus_null()) }
	// Stream 20 (erasure_compliance §7): record WHERE the archive copy lives
	// on the segment index — the erase walk reaches `archive=` stores through
	// it (the enumerated derived-artifact reach; an unrecorded copy would be
	// a silent compliance hole).
	journal_stdlib_builtin('journal-segment-disposed', [hot_journal, bus_str(sealed_url),
		bus_str(dest)]) or { cx.Node(bus_null()) }
	eprintln('cx fabric-serve: retention: archived sealed store → ${store_url_redact_userinfo(dest)}')
}

// FsPumpRecord is one scanned journal entry from the unlocked render phase:
// the seq (cursor advance), the parsed entry (the locked policy gate needs
// it), and the pre-rendered event frame for a pattern match.
struct FsPumpRecord {
	seq     i64
	matched bool
	entry   cx.Element
	frame   []u8
}

// fs_pump delivers committed entries to ONE durable subscription — the
// lock-managed #642 pump. Semantics are fs_pump_locked's, phase-split:
// scan the journal from the cursor, push pattern-matching entries as
// `event` frames (stream-id = subscription id), advance the cursor past
// every scanned entry; a grouped subscription pushes only while it HOLDS
// the assignment and only up to the pending window's room; at the bound
// the pump stops — the next ack frees room and re-pumps (the log is the
// buffer).
fn fs_pump(mut srv FabricServer, sub_id int) {
	srv.mu.@lock()
	mut s := srv.subs[sub_id] or {
		srv.mu.unlock()
		return
	}
	if s.pumping {
		s.repump = true
		srv.mu.unlock()
		return
	}
	s.pumping = true
	for {
		s.repump = false
		// ── locked: snapshot the delivery state ──
		if !s.active || s.channel != '' {
			break
		}
		if s.group != '' {
			key := fs_assign_key(s.tenant, s.stream, s.group)
			if (srv.assigns[key] or { -1 }) != s.id {
				break
			}
		}
		mount := srv.mounts[s.tenant] or { break }
		mut room := if s.group != '' {
			eff := if s.window > 0 { s.window } else { srv.cfg.pending_window }
			eff - s.inflight.len
		} else if s.window > 0 {
			int(s.credits)
		} else {
			2147483647
		}
		if room <= 0 {
			break
		}
		cursor := s.cursor
		stream := s.stream
		pattern := s.pattern
		jelem := mount.journal_elem
		srv.mu.unlock()

		// ── UNLOCKED: journal read + pattern match + frame render (#642) ──
		records, more := fs_pump_render(jelem, cursor, stream, pattern, sub_id, room)

		srv.mu.@lock()
		s = srv.subs[sub_id] or {
			srv.mu.unlock()
			return
		}
		// ── locked: revalidate + apply ──
		if !s.active || s.channel != '' {
			break
		}
		if s.group != '' {
			key := fs_assign_key(s.tenant, s.stream, s.group)
			if (srv.assigns[key] or { -1 }) != s.id {
				break // assignment moved mid-render: apply nothing
			}
		}
		mut dead_lettered := false
		mut gate_fault := false
		for rec in records {
			if !rec.matched {
				s.cursor = rec.seq + 1 // every scanned entry is consumed
				continue
			}
			// room LIVE: acks can only have grown it mid-render (inflight
			// shrinks via ack; credits grow via credit frames) — recompute so
			// a mid-render replenishment is not wasted.
			room = if s.group != '' {
				eff := if s.window > 0 { s.window } else { srv.cfg.pending_window }
				eff - s.inflight.len
			} else if s.window > 0 {
				int(s.credits)
			} else {
				2147483647
			}
			if room <= 0 {
				// unsendable: the cursor stays BEFORE this record; an ack
				// re-pump resumes exactly here.
				s.repump = true
				break
			}
			// §9.1 head-of-tail accounting — LOCKED (see the block comment).
			if s.max_deliveries > 0 && !s.counted && rec.seq > s.committed {
				j, _, jok := jrn_get_open(mount.journal_elem)
				if !jok {
					gate_fault = true
					break
				}
				deliver, _, gok := fab_policy_gate(j, mount.journal_elem, s.stream,
					s.group, rec.seq, rec.entry, s.max_deliveries, s.dlq)
				if !gok {
					gate_fault = true
					break
				}
				if !deliver {
					if rec.seq > s.committed {
						s.committed = rec.seq // dead-lettered + committed through
					}
					s.cursor = rec.seq + 1
					dead_lettered = true
					continue
				}
				s.counted = true
			}
			if s.group != '' {
				s.inflight << rec.seq
			} else if s.window > 0 {
				s.credits--
			}
			s.cursor = rec.seq + 1
			fs_send_locked(mut srv, s.conn_id, rec.frame)
		}
		if dead_lettered {
			// a fired policy appended to the DLQ stream — queue its live
			// subscribers (drained by our fs_drain_pumps caller).
			for osid, o in srv.subs {
				if osid != s.id && o.active && o.channel == '' && o.tenant == s.tenant
					&& o.stream == s.dlq {
					fs_pump_request_locked(mut srv, osid)
				}
			}
		}
		if gate_fault {
			break // journal fault: stop this pass (fs_pump_locked returned here)
		}
		// another round if a request landed mid-pump, or the render was
		// truncated by the room cap / batch bound and entries remain.
		if !s.repump && !more {
			break
		}
	}
	s.pumping = false
	srv.mu.unlock()
}

// fs_pump_render is the UNLOCKED phase: read entries above `cursor`, match
// the pattern, and pre-render up to `room` event frames. Returns the ordered
// records plus whether the scan stopped early (more entries may remain).
// Journal access serializes on the journal's own lock (jmu), never srv.mu.
fn fs_pump_render(jelem cx.Node, cursor i64, stream string, pattern BusPattern, sub_id int, room int) ([]FsPumpRecord, bool) {
	mut records := []FsPumpRecord{}
	r := journal_stdlib_builtin('journal-since', [jelem, cx.Node(bus_int(cursor)),
		cx.Node(bus_str(stream))]) or { return records, false }
	if r !is cx.Element {
		return records, false
	}
	re := r as cx.Element
	if re.name == 'err' {
		return records, false
	}
	mut framed := 0
	for it in re.items {
		if it is cx.Element && it.name == 'entry' {
			if framed >= room {
				return records, true // room-capped: entries remain behind
			}
			mut seq := i64(0)
			for a in it.attrs {
				if a.name == 'seq' {
					seq = cx.scalar_value_str_public(a.value).i64()
				}
			}
			mut event := cx.Node(bus_null())
			mut has_event := false
			for ch in it.items {
				if ch is cx.Element {
					if ch.name == 'event' && ch.items.len > 0 {
						event = ch.items[0]
						has_event = true
					}
				}
			}
			if has_event && fs_pattern_matches(pattern, event) {
				b := fs_frame_bytes('event', i64(sub_id), cx.Node(it)) or { continue }
				records << FsPumpRecord{
					seq:     seq
					matched: true
					entry:   it
					frame:   b
				}
				framed++
			} else {
				records << FsPumpRecord{
					seq:     seq
					matched: false
				}
			}
		}
	}
	return records, false
}


// ── health/ready listener (store-serve posture: unauthenticated, minimal) ─

// fabric_serve_health_loop answers GET /health and GET /ready with the shared
// ServiceState bodies — probe-compatible with `cx store-health --url` (it
// checks for `[accepting true]`). Anything else is 404. One request per
// connection; this is a probe endpoint, not a data plane.
pub fn fabric_serve_health_loop(mut srv FabricServer, server cx.Node) {
	for {
		mut lh := net_mut_handle(server) or { break }
		conn := net_accept_real(mut lh)
		if is_err_value(conn) {
			break
		}
		net_id := net_handle_id(conn) or { continue }
		mut h := net_mut_handle(conn) or {
			net_close_id(net_id)
			continue
		}
		h.read_deadline_ms = 2000
		req_line := net_read_line_buf(mut h) or {
			net_close_id(net_id)
			continue
		}
		// drain headers to the blank line so the peer's write completes.
		for {
			l := net_read_line_buf(mut h) or { break }
			if l == '' {
				break
			}
		}
		parts := req_line.split(' ')
		mut status := '404 Not Found'
		mut body := '[err code="cx-err:CXER4926" message="E_FABRIC_WIRE: unknown probe path"]'
		if parts.len >= 2 && parts[0] == 'GET' {
			if parts[1] == '/health' {
				status = '200 OK'
				body = svc_health_response()
			} else if parts[1] == '/ready' {
				status = '200 OK'
				mut st := srv.state
				body = st.ready_response()
			}
		}
		resp := 'HTTP/1.1 ${status}\r\nContent-Type: application/cx; charset=utf-8\r\nContent-Length: ${body.len}\r\nConnection: close\r\n\r\n${body}'
		net_h_write(mut h, resp.bytes()) or {}
		net_close_id(net_id)
	}
}
