module platform

import code {
	NetHandle,
	arg_bytes,
	arg_string,
	bytes_node,
	crypto_random_octets,
	crypto_string_node,
	is_err_value,
	mk_err,
	net_close_id,
	net_h_write,
	net_handle_id,
	net_mut_handle,
	render_canonical,
	x25519_clamp,
	x25519_scalar_base_mult,
}
import cx
import sync
import time
import encoding.hex
import crypto.sha256

// store_xsp_serve.v — the XSP STORE-PROFILE listener (I5 stream 4 W3;
// spec/03-approved/xap/xsp_store_profile.md §4.1). The third `cx store-serve`
// listener beside CSRP (transitional) and gRPC, destined to become THE store
// wire (store.md §6.4). The design is the fabric daemon's listener shape
// (fabric_service.v — the §11 profile template) over the ONE op core:
//
//   decode text-canonical verb envelope → store_stdlib_builtin_inner → reply
//
// which is exactly why the W7 three-listener parity gate is a framing-layer
// property, not a comparison of two op implementations.
//
// Lanes (L165, §4.1): verb ENVELOPES ride text frames carrying canonical CX;
// doc BODIES ride framed ast_bin imaged as `[body::bytes 0x…]` fields (the
// ast_bin round-trip reproduces the exact canonical text the content address
// hashes, so addresses stay byte-exact end to end); doc addresses in
// envelopes are tagged text (`sha2-256:<hex>`); OBJECT-wire addresses are
// varint-multihash bytes fields (`h::bytes=0x1220…` — the crypto-agility
// bijection, live on this wire, fail-closed on unregistered codes).
//
// Errors (L166, §4.2): the profile refuses with its own CXER5010–5018 rows;
// op-layer faults cross the wire VERBATIM (CXER11xx, the one ref-conflict
// code CXER1114) — never remapped onto a transport band. The CSRP 17xx
// remapping is precisely the drift this listener retires. Absence is DATA
// (`present=false`), never an error frame.

const sx_err_attach = 'cx-err:CXER5010' // E_XSP_STORE_ATTACH
const sx_err_wire = 'cx-err:CXER5011' // E_XSP_STORE_WIRE
const sx_err_unsupported = 'cx-err:CXER5012' // E_XSP_STORE_UNSUPPORTED
const sx_err_mount = 'cx-err:CXER5013' // E_XSP_STORE_MOUNT
const sx_err_credit = 'cx-err:CXER5014' // E_XSP_STORE_CREDIT
const sx_err_internal = 'cx-err:CXER5015' // E_XSP_STORE_INTERNAL
const sx_err_body = 'cx-err:CXER5016' // E_XSP_STORE_BODY
const sx_err_address = 'cx-err:CXER5017' // E_XSP_STORE_ADDRESS
const sx_err_admin = 'cx-err:CXER5018' // E_XSP_STORE_ADMIN

// The v1 op vocabulary, advertised by `capabilities` and refused-by-name on
// an unknown verb (never silently tolerated, xsp.md §6).
const sx_verbs = ['capabilities', 'get', 'put', 'delete', 'erase', 'modify', 'list', 'iter',
	'query', 'feed', 'objects-have', 'objects-get', 'objects-put', 'refs', 'refs-set', 'aliases',
	'aliases-set', 'log', 'status', 'gc', 'mounts', 'config-reload', 'session', 'put-blob', 'get-blob',
	'journal-read',
	'journal-slice', 'journal-since', 'journal-query', 'journal-verify', 'journal-verify-slice',
	'journal-snapshot-verify', 'journal-fold', 'journal-fold-slice', 'journal-replay',
	'journal-dry-run']

// the daemon's semantic token set, offered INSIDE the signed transcript
// (§4.4a; canonical sorted — the transcript signs bytes). `peer` is offered
// only by a daemon that designates a revocations journal (§7.1 — a token
// that cannot be served is never offered).
fn sx_offer_features(cfg XspConfig) string {
	// S6 §4.3: `store-journal` gates the journal pushdown verb family —
	// transcript-bound (it changes verb vocabulary), offered unconditionally
	// (every mount can carry journal tenants). Canonical sorted order.
	if cfg.revocations_tenant != '' {
		return 'credit peer store-delta store-feed store-journal'
	}
	return 'credit store-delta store-feed store-journal'
}

// SxStream is one live result stream (list/iter/query): the materialized,
// pre-rendered event payloads plus the credit balance. Results ride `event`
// frames on the REQUEST's stream-id; the terminal frame carries the eos flag
// (xsp.md §2 bit1) and an `[eos count=N]` payload.
struct SxStream {
mut:
	items    []string // rendered event payload texts, in push order
	sent     int
	credits  i64
	windowed bool // false = unbounded (undeclared window, the pre-§5 posture)
}

// SxConn is one connection: XSP-AUTH state until established, then the
// authenticated (principal, mount) pair plus its live result streams.
struct SxConn {
mut:
	id          int
	net_id      int
	handle      &NetHandle = unsafe { nil }
	out         chan []u8
	open        bool
	established bool
	principal   string
	mutual      bool // DID-proven initiator (false = admitted under the floor)
	mount       string
	last_seen   i64
	created     i64
	// the one pending handshake (M1 arrived, M3 awaited)
	has_pend      bool
	pend_m1       cx.Element
	pend_m2       cx.Element
	pend_eph_priv []u8
	// §4.4a transcript-confirmed sets (restated by `session`, never extended)
	confirmed_profiles string
	confirmed_features string
	streams            map[i64]&SxStream
	// W4 §6.1: the SESSION's authority basis + its live meters. nil = the
	// open posture (no [grants] configured — data verbs open, admin verbs
	// behind the CXER5018 mutual gate); non-nil = deny-by-default PEP.
	authz  &AuthzStore = unsafe { nil }
	meters map[string]&SxMeter
	// W5 §6.1: compiled-delegation id → source VC id — the map the PEP
	// consults to drop revoked-sourced authority at the next check.
	vc_of map[string]string
}

@[heap]
pub struct StoreXspServer {
mut:
	mu        &sync.Mutex = unsafe { nil }
	cfg       XspConfig
	ctx       ServeContext
	conns     map[int]&SxConn
	next_conn int
	// W4 §5: live change-feed subscriptions, SERVER-level (a put on one
	// connection reaches subscribers on every other), keyed conn:stream.
	feeds map[string]&SxFeed
	// W5 §7a.1: the last config generation advertised — the sweeper's F3
	// watch re-advertises every established session when it moves.
	last_gen int
	// W5 §7: the daemon's revoked-set (vc-id → true), folded from its own
	// designated revocations journal and from every peer subscription.
	// Enforcement is LOCAL (§6.1): refuse at present; drop compiled-from-
	// revoked delegations at the next PEP check. Guarded by srv.mu.
	revoked map[string]bool
	// per-tenant fold cursor into the local revocations journal (seq).
	rev_folded map[string]int
}

pub fn new_store_xsp_server(cfg XspConfig, ctx ServeContext) &StoreXspServer {
	return &StoreXspServer{
		mu:  sync.new_mutex()
		cfg: cfg
		ctx: ctx
	}
}

// ── frame plumbing (the fabric shape: text after establishment, data-bin
//    during the handshake — the shipped $xsp:auth-* calculus exchanges M1–M4
//    as data-bin payloads) ─────────────────────────────────────────────────

fn sx_frame_text(ftype string, stream i64, payload_text string, eos bool) ?[]u8 {
	mut attrs := [xap_attr('type', ftype), xap_attr('stream', stream.str()),
		xap_attr('binary', 'false')]
	if eos {
		attrs << xap_attr('eos', 'true')
	}
	fr := cx.Element{
		name:  'frame'
		attrs: attrs
		items: [
			cx.Node(cx.Element{
				name:  'payload'
				items: [cx.Node(bus_str(payload_text))]
			}),
		]
	}
	wire := xsp_encode_one(fr)
	if is_err_value(wire) {
		return none
	}
	return arg_bytes(wire)
}

fn sx_frame_bin(ftype string, stream i64, payload cx.Node) ?[]u8 {
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

// sx_send_locked enqueues frame bytes; a wedged outbound queue closes the
// connection rather than ever blocking the dispatch turn (the fabric rule).
fn sx_send_locked(mut srv StoreXspServer, conn_id int, b []u8) {
	mut c := srv.conns[conn_id] or { return }
	if !c.open {
		return
	}
	item := b
	if c.out.try_push(&item) != .success {
		eprintln('cx store-serve[xsp]: connection ${conn_id} outbound queue wedged — closing')
		sx_close_conn_locked(mut srv, conn_id)
	}
}

fn sx_reply_locked(mut srv StoreXspServer, conn_id int, stream i64, body string) {
	b := sx_frame_text('reply', stream, body, false) or { return }
	sx_send_locked(mut srv, conn_id, b)
}

fn sx_event_locked(mut srv StoreXspServer, conn_id int, stream i64, body string, eos bool) {
	b := sx_frame_text('event', stream, body, eos) or { return }
	sx_send_locked(mut srv, conn_id, b)
}

// sx_error_locked sends an `error` frame whose payload is the failure-channel
// value rendered canonical — profile rows and op-layer faults alike ride this
// one shape (error transparency, §4.1).
fn sx_error_locked(mut srv StoreXspServer, conn_id int, stream i64, err_node cx.Node) {
	b := sx_frame_text('error', stream, render_canonical(err_node), false) or { return }
	sx_send_locked(mut srv, conn_id, b)
}

fn sx_error_bin_locked(mut srv StoreXspServer, conn_id int, stream i64, err_node cx.Node) {
	b := sx_frame_bin('error', stream, err_node) or { return }
	sx_send_locked(mut srv, conn_id, b)
}

fn sx_reply_bin_locked(mut srv StoreXspServer, conn_id int, stream i64, payload cx.Node) {
	b := sx_frame_bin('reply', stream, payload) or { return }
	sx_send_locked(mut srv, conn_id, b)
}

// ── connection lifecycle (fabric's reader/writer-per-connection shape) ─────

pub fn store_xsp_accept_loop(mut srv StoreXspServer, server cx.Node, should_stop fn () bool) {
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
		mut c := &SxConn{
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
		spawn sx_conn_writer(mut srv, mut c)
		spawn sx_conn_reader(mut srv, mut c)
	}
}

fn sx_conn_writer(mut srv StoreXspServer, mut c SxConn) {
	for {
		b := <-c.out or { break } // queue closed on teardown
		net_h_write(mut c.handle, b) or {
			srv.mu.lock()
			sx_close_conn_locked(mut srv, c.id)
			srv.mu.unlock()
			break
		}
	}
}

fn sx_conn_reader(mut srv StoreXspServer, mut c SxConn) {
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
				node := xsp_decode_at(raw, 0)
				if node !is cx.Element {
					break
				}
				fe := node as cx.Element
				if fe.name != 'frame' {
					break // decode err element: broken framing, tear down
				}
				srv.mu.lock()
				if !c.open {
					srv.mu.unlock()
					break
				}
				c.last_seen = time.now().unix_milli()
				sx_dispatch_locked(mut srv, mut c, fe)
				srv.mu.unlock()
			}
		}
	}
	srv.mu.lock()
	sx_close_conn_locked(mut srv, c.id)
	srv.mu.unlock()
}

fn sx_close_conn_locked(mut srv StoreXspServer, conn_id int) {
	mut c := srv.conns[conn_id] or { return }
	if !c.open {
		return
	}
	c.open = false
	c.out.close()
	net_close_id(c.net_id)
	srv.conns.delete(conn_id) // stream state dies with the connection
	mut dead := []string{}
	for key, f in srv.feeds {
		if f.conn_id == conn_id {
			dead << key
		}
	}
	for key in dead {
		srv.feeds.delete(key)
	}
}

// store_xsp_liveness_sweeper enforces the §5.1 liveness window: a peer silent
// past `liveness-ms` is DEAD and its connection (with all stream state) is
// torn down. Any inbound frame refreshes the window; ping is the idle
// keepalive.
pub fn store_xsp_liveness_sweeper(mut srv StoreXspServer) {
	for {
		if svc_shutdown_requested() {
			return
		}
		time.sleep(250 * time.millisecond)
		now := time.now().unix_milli()
		srv.mu.lock()
		mut dead := []int{}
		for id, c in srv.conns {
			if c.established && now - c.last_seen > srv.cfg.liveness_ms {
				dead << id
			}
		}
		for id in dead {
			eprintln('cx store-serve[xsp]: connection ${id} missed the liveness window — closing')
			sx_close_conn_locked(mut srv, id)
		}
		// W4 §5: the cross-listener wake — writes landing through CSRP/gRPC
		// (or embedded, on a shared mount) reach feed subscribers here.
		sx_pump_all_feeds_locked(mut srv)
		// W5 §7a.1: the F3 generation watch — a reload applied through ANY
		// listener re-advertises every established session.
		sx_readvertise_locked(mut srv)
		// W5 §7.1: fold the local revocations journal into the revoked-set.
		sx_fold_local_revocations_locked(mut srv)
		srv.mu.unlock()
	}
}

// ── dispatch ───────────────────────────────────────────────────────────────

fn sx_dispatch_locked(mut srv StoreXspServer, mut c SxConn, fe cx.Element) {
	ftype := xap_elem_attr(fe, 'type')
	stream := xap_elem_attr(fe, 'stream').i64()
	if ftype == 'ping' {
		// §5.1: pong echoes the stream-id and payload verbatim (opaque echo).
		binary := xap_elem_attr(fe, 'binary') == 'true'
		mut b := []u8{}
		if pv := xsp_payload_value(fe) {
			if binary {
				b = sx_frame_bin('pong', stream, pv) or { return }
			} else {
				txt := arg_string(pv) or { '' }
				b = sx_frame_text('pong', stream, txt, false) or { return }
			}
		} else {
			b = sx_frame_text('pong', stream, '', false) or { return }
		}
		sx_send_locked(mut srv, c.id, b)
		return
	}
	if ftype == 'credit' {
		// §5.2: grants N credits on the result stream named by the frame's
		// stream-id. Transcript-negotiated (`credit` confirmed at attach).
		if !c.established {
			sx_error_bin_locked(mut srv, c.id, stream, mk_err(sx_err_attach,
				'E_XSP_STORE_ATTACH: credit before attach'))
			return
		}
		n := xsp_payload_value(fe) or { cx.Node(bus_int(0)) }
		// a data-bin scalar payload decodes wrapped — unwrap it.
		inner := if n is cx.Element && n.items.len > 0 { n.items[0] } else { n }
		mut grant := i64(0)
		if inner is cx.ScalarNode {
			v := inner.value
			if v is i64 {
				grant = v
			}
		}
		if grant < 1 {
			sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_credit,
				'E_XSP_STORE_CREDIT: credit frame payload must be an integer ≥ 1'))
			return
		}
		mut s := c.streams[stream] or {
			// a feed subscription on this stream-id replenishes the same way
			fk := sx_feed_key(c.id, stream)
			mut f := srv.feeds[fk] or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_credit,
					'E_XSP_STORE_CREDIT: credit on unknown stream ${stream}'))
				return
			}
			f.credits += grant
			sx_pump_feed_locked(mut srv, fk)
			return
		}
		s.credits += grant
		sx_pump_stream_locked(mut srv, mut c, stream)
		return
	}
	if ftype == 'cancel' {
		// §4.1: cancel aborts a result stream; the server acknowledges with a
		// terminal eos event (`cancelled=true`) so the client knows the stream
		// is closed server-side. Cancel on an unknown stream is ignored — the
		// benign race against an in-flight eos.
		if !c.established {
			sx_error_bin_locked(mut srv, c.id, stream, mk_err(sx_err_attach,
				'E_XSP_STORE_ATTACH: cancel before attach'))
			return
		}
		if s := c.streams[stream] {
			sx_event_locked(mut srv, c.id, stream, '[eos count=${s.sent} cancelled=true]',
				true)
			c.streams.delete(stream)
		} else if f := srv.feeds[sx_feed_key(c.id, stream)] {
			// a feed has no natural end — cancel IS its termination (§5.2)
			sx_event_locked(mut srv, c.id, stream, '[eos count=${f.sent} cancelled=true]',
				true)
			srv.feeds.delete(sx_feed_key(c.id, stream))
		}
		return
	}
	if ftype != 'request' {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
			'E_XSP_STORE_WIRE: clients send request/cancel/credit/ping frames (got ${ftype})'))
		return
	}
	payload := xsp_payload_value(fe) or {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
			'E_XSP_STORE_WIRE: request frame has no payload'))
		return
	}
	if !c.established {
		sx_attach_locked(mut srv, mut c, stream, payload)
		return
	}
	// §4.8 demotion rule: a non-empty frame principal must equal the session
	// principal byte-for-byte; empty inherits it. The identity model's code
	// rides verbatim (it is not a store-profile row).
	fp := xap_elem_attr(fe, 'principal')
	if fp != '' && fp != c.principal {
		sx_error_locked(mut srv, c.id, stream, mk_err('cx-err:CXER-XSP-AUTH-PRINCIPAL-MISMATCH',
			'E_XSP_STORE: frame principal "${fp}" ≠ session principal "${c.principal}" (§4.8)'))
		return
	}
	// §5.1: a post-attach presentation rides the control channel as a binary
	// [xsp-auth phase=present [vp …]] message — late grants extend the
	// session without re-attach.
	if payload is cx.Element {
		pe := payload as cx.Element
		if pe.name == 'xsp-auth' && xap_elem_attr(pe, 'phase') == 'present' {
			if c.authz == unsafe { nil } {
				sx_error_bin_locked(mut srv, c.id, stream, mk_err(sx_err_authority,
					'E_XSP_STORE_AUTHORITY: this listener has no [grants] configured — presentations need the enforcing posture (§6.1)'))
				return
			}
			vpt := xsp_auth_child_text(pe, 'vp') or {
				sx_error_bin_locked(mut srv, c.id, stream, mk_err(sx_err_authority,
					'E_XSP_STORE_AUTHORITY: phase=present carries no [vp "<canonical text>"] field'))
				return
			}
			vp := sx_parse_vp_text(vpt) or {
				sx_error_bin_locked(mut srv, c.id, stream, mk_err(sx_err_authority,
					'E_XSP_STORE_AUTHORITY: [vp …] field must carry canonical [vp [vc …]…] text'))
				return
			}
			pres := sx_present_locked(mut srv, mut c, vp)
			if is_err_value(pres) {
				sx_error_bin_locked(mut srv, c.id, stream, pres)
				return
			}
			sx_reply_bin_locked(mut srv, c.id, stream, pres)
			return
		}
	}
	// verbs ride TEXT frames (canonical CX) — the fabric lane ruling
	// generalized (data-bin never carries verb trees).
	if xap_elem_attr(fe, 'binary') == 'true' {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
			'E_XSP_STORE_WIRE: store verbs ride text frames carrying canonical CX (binary=false)'))
		return
	}
	text := arg_string(payload) or {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
			'E_XSP_STORE_WIRE: text request payload must be a string of canonical CX'))
		return
	}
	parsed := cx.parse(text) or {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
			'E_XSP_STORE_WIRE: unparseable request payload: ${err.msg()}'))
		return
	}
	if parsed.elements.len == 0 || parsed.elements[0] !is cx.Element {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
			'E_XSP_STORE_WIRE: request payload must be one verb element'))
		return
	}
	req := parsed.elements[0] as cx.Element
	sx_dispatch_verb_locked(mut srv, mut c, stream, req)
}

// ── attach (XSP-AUTH responder, the fabric shape) ──────────────────────────

fn sx_attach_locked(mut srv StoreXspServer, mut c SxConn, stream i64, payload cx.Node) {
	if payload !is cx.Element {
		sx_error_bin_locked(mut srv, c.id, stream, mk_err(sx_err_attach,
			'E_XSP_STORE_ATTACH: attach expects [xsp-auth …] payloads before any verb'))
		return
	}
	msg := payload as cx.Element
	phase := xap_elem_attr(msg, 'phase')
	match phase {
		'hello' {
			nonce := crypto_random_octets(32) or {
				sx_error_bin_locked(mut srv, c.id, stream, mk_err(sx_err_attach,
					'E_XSP_STORE_ATTACH: entropy unavailable'))
				return
			}
			eph_priv := crypto_random_octets(32) or {
				sx_error_bin_locked(mut srv, c.id, stream, mk_err(sx_err_attach,
					'E_XSP_STORE_ATTACH: entropy unavailable'))
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
					// §4.4a: the daemon's semantic token set, offered INSIDE the
					// signed transcript. W4 added store-feed (the §5 change
					// feed) and store-delta (∂ body carriage); W5 adds peer
					// when the daemon designates a revocations journal —
					// growth = a token.
					session_kv('offer-profiles', crypto_string_node('store')),
					session_kv('offer-features', crypto_string_node(sx_offer_features(srv.cfg))),
				]
			})
			m2 := xsp_auth_stdlib_builtin('xsp-auth-challenge', [cx.Node(msg), opts]) or {
				sx_error_bin_locked(mut srv, c.id, stream, mk_err(sx_err_attach,
					'E_XSP_STORE_ATTACH: challenge failed'))
				return
			}
			if is_err_value(m2) {
				sx_error_bin_locked(mut srv, c.id, stream, m2)
				return
			}
			c.has_pend = true
			c.pend_m1 = msg
			c.pend_m2 = m2 as cx.Element
			c.pend_eph_priv = eph_priv
			sx_reply_bin_locked(mut srv, c.id, stream, m2)
		}
		'prove' {
			if !c.has_pend {
				sx_error_bin_locked(mut srv, c.id, stream, mk_err(sx_err_attach,
					'E_XSP_STORE_ATTACH: prove without a pending hello on this connection'))
				return
			}
			m1 := c.pend_m1
			m2 := c.pend_m2
			eph_priv := c.pend_eph_priv
			c.has_pend = false
			// mount routing: M3 [attach [tenant "<store-name>"]]; absent = the
			// sole mount (the CSRP sole-store shorthand); ambiguous or unknown
			// is a loud refusal.
			mut mount_name := fs_m3_tenant(msg)
			if mount_name == '' {
				if srv.ctx.mounts.len == 1 {
					mount_name = srv.ctx.mounts.keys()[0]
				} else {
					sx_error_bin_locked(mut srv, c.id, stream, mk_err(sx_err_mount,
						'E_XSP_STORE_MOUNT: M3 [attach] names no [tenant …] and the daemon mounts ${srv.ctx.mounts.len} stores'))
					return
				}
			}
			if mount_name !in srv.ctx.mounts {
				sx_error_bin_locked(mut srv, c.id, stream, mk_err(sx_err_mount,
					'E_XSP_STORE_MOUNT: no store mounted as "${mount_name}"'))
				return
			}
			mut cfg_items := [
				session_kv('eph-priv', bytes_node(eph_priv)),
				session_kv('tenant', crypto_string_node(mount_name)),
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
				sx_error_bin_locked(mut srv, c.id, stream, attached)
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
			mut confirmed_profiles := ''
			mut confirmed_features := ''
			if m4 is cx.Element {
				confirmed_profiles = xsp_auth_child_text(m4, 'confirmed-profiles') or { '' }
				confirmed_features = xsp_auth_child_text(m4, 'confirmed-features') or { '' }
			}
			// §4.4a: the confirmed intersection is the vocabulary. A peer that
			// did not offer `store` has nothing to say on this listener —
			// refused loudly at attach, never a half-attached session.
			if !confirmed_profiles.split(' ').contains('store') {
				peer_offer := xsp_auth_child_text(m1, 'offer-profiles') or { '' }
				sx_error_bin_locked(mut srv, c.id, stream, mk_err(sx_err_attach,
					'E_XSP_STORE_ATTACH: no common profile — this listener serves "store", the peer offered "${peer_offer}"'))
				return
			}
			mut principal := xsp_auth_child_text(m1, 'initiator') or { '' }
			mutual := principal != ''
			if principal == '' {
				principal = srv.cfg.floor
			}
			c.established = true
			c.principal = principal
			c.mutual = mutual
			c.mount = mount_name
			c.confirmed_profiles = confirmed_profiles
			c.confirmed_features = confirmed_features
			// W4 §6.1: with [grants …] configured the session carries a
			// VC-compilable authority basis and every verb is PEP-checked.
			if srv.cfg.grants.len > 0 {
				c.authz = sx_authority_new(srv.cfg, mount_name, principal)
			}
			// an M3 [attach [vp "<canonical text>"]] presentation compiles
			// BEFORE the attach completes — a bad credential fails the attach
			// loudly, never a half-authorized session (identity model §5.1;
			// the single-scalar text carriage is the §4.4a shape rule + the
			// L165 lossless-lane rule, see sx_m3_vp_text).
			if vpt := sx_m3_vp_text(msg) {
				if c.authz == unsafe { nil } {
					c.established = false
					sx_error_bin_locked(mut srv, c.id, stream, mk_err(sx_err_authority,
						'E_XSP_STORE_AUTHORITY: this listener has no [grants] configured — presentations need the enforcing posture (§6.1)'))
					return
				}
				vp := sx_parse_vp_text(vpt) or {
					c.established = false
					c.authz = unsafe { nil }
					sx_error_bin_locked(mut srv, c.id, stream, mk_err(sx_err_authority,
						'E_XSP_STORE_AUTHORITY: [vp …] field must carry canonical [vp [vc …]…] text'))
					return
				}
				pres := sx_present_locked(mut srv, mut c, vp)
				if is_err_value(pres) {
					c.established = false
					c.authz = unsafe { nil }
					sx_error_bin_locked(mut srv, c.id, stream, pres)
					return
				}
			} else if sx_m3_vp_present(msg) {
				// R3.1 / audit F-20: a [vp] field IS present but not in the
				// single-scalar canonical-text carriage (e.g. the nested
				// [vp [vc …]] element). Refuse the attach LOUDLY — the spec'd
				// CXER5021 — never a quietly under-authorized session with
				// zero compiled authority and opaque per-verb denies.
				c.established = false
				c.authz = unsafe { nil }
				sx_error_bin_locked(mut srv, c.id, stream, mk_err(sx_err_authority,
					'E_XSP_STORE_AUTHORITY: [vp] must be the single-scalar canonical-text carriage ([vp "<canonical [vp [vc …]…] text>"]) — a nested element does not survive the signed-transcript/data-bin lanes (§6.1, §4.4a shape rule)'))
				return
			}
			c.handle.read_deadline_ms = 1000 // keep the idle tick for shutdown polls
			sx_reply_bin_locked(mut srv, c.id, stream, m4)
			// §7a.1: the M4-confirmed attach is followed by the signed,
			// generation-bound profile advert (ONE stream-0 event).
			sx_send_advert_locked(mut srv, c.id)
		}
		else {
			sx_error_bin_locked(mut srv, c.id, stream, mk_err(sx_err_attach,
				'E_XSP_STORE_ATTACH: expects phase=hello or phase=prove (got "${phase}")'))
		}
	}
}

// ── envelope field readers ─────────────────────────────────────────────────

// sx_hex_image decodes a `::bytes` field's canonical text image (`0x<hex>`,
// lowercase). Only the canonical spelling is accepted — validators refuse,
// builders normalize (the W2 canonicality posture).
fn sx_hex_image(img string) ?[]u8 {
	if !img.starts_with('0x') {
		return none
	}
	return hex.decode(img[2..]) or { return none }
}

// sx_bytes_child reads a `[<name>::bytes 0x…]` child's octets.
fn sx_bytes_child(e cx.Element, name string) ?[]u8 {
	for it in e.items {
		if it is cx.Element && it.name == name {
			for ch in it.items {
				if ch is cx.ScalarNode {
					return sx_hex_image(cx.scalar_value_str_public(ch.value))
				}
			}
		}
	}
	return none
}

// sx_mh_attr reads a varint-multihash `<name>::bytes=0x…` attribute and
// returns (multihash bytes, algo name, digest). Fail-closed on an
// unregistered code or a digest-length mismatch (the crypto-agility
// bijection's refusal rules).
fn sx_mh_attr(e cx.Element, name string) ?([]u8, string, []u8) {
	img := sw_attr(e, name)
	if img == '' {
		return none
	}
	mh := sx_hex_image(img) or { return none }
	algo, digest := cx.cx_multihash_decode(mh) or { return none }
	return mh, algo, digest
}

// ── verbs ──────────────────────────────────────────────────────────────────

fn sx_dispatch_verb_locked(mut srv StoreXspServer, mut c SxConn, stream i64, req cx.Element) {
	local := srv.ctx.mounts[c.mount] or {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_mount,
			'E_XSP_STORE_MOUNT: mount "${c.mount}" is gone'))
		return
	}
	// W4 §6.1: under the enforcing posture EVERY KNOWN verb is decided by the
	// ONE decision function over the session's authority basis; the [deny …]
	// value rides the wire VERBATIM (CXER4700-band as data; budget
	// exhaustion carries CXER4713 + [retry-after …]). An UNKNOWN verb is not
	// in sx_verbs, so it never enters this PEP block at all — it falls through
	// to the refuse-by-name path below (CXER5012). (Corrected R3.5: the PEP
	// does NOT map unknown verbs to `admin`; they are gated purely by name.)
	if c.authz != unsafe { nil } && req.name in sx_verbs {
		slice := if req.name == 'query' { req.attr('path') } else { '' }
		// W5 §7.1: a revocations-plane feed is the `peer` class (narrower
		// than read — a peer daemon receives revocations without holding
		// read on the data planes); everything else maps by verb.
		mut cap := sx_verb_capability(req.name)
		if req.name == 'feed' && sx_feed_names_revocations(req) {
			cap = 'peer'
		}
		dec := sx_pep_decide(mut c, cap, slice, srv.revoked)
		mut permitted := false
		if dec is cx.Element && dec.name == 'permit' {
			permitted = true
		}
		if !permitted {
			sx_error_locked(mut srv, c.id, stream, dec)
			return
		}
	}
	// Serialize store ops on the mount's op lock, exactly as the CSRP route
	// does (the daemon has many connections on one handle and must SERIALIZE;
	// store_stdlib_builtin_inner bypasses the eval-path try_lock guard).
	mut guard := store_for_guard(local) or { unsafe { nil } }
	if guard != unsafe { nil } {
		store_lock_enter(mut guard)
	}
	defer {
		if guard != unsafe { nil } {
			store_lock_exit(mut guard)
		}
	}
	match req.name {
		'capabilities' {
			backend, readf, writef, listf := svc_mount_caps(local)
			// §7a.1/§4.1: capabilities RESTATES the advert's `generation=` —
			// the ATTR form, matching the advert's own spelling (F-30/R3.14
			// cutover: the former [generation N] child element is gone; two
			// surfaces, one truth, ONE shape) — plus the [guarantees …] set.
			mut sb := '[capabilities generation=${sx_advert_generation(mut srv)} [profile "store"] [profile-version "1"] [server-impl "cx-store-serve"]'
			sb += ' [store name="${c.mount}" backend="${backend}" read=${readf} write=${writef} list=${listf}]'
			sb += ' [ops'
			for v in sx_verbs {
				sb += ' "${v}"'
			}
			sb += '] [features "${sx_offer_features(srv.cfg)}"] [guarantees "${sx_guarantees}"]]'
			sx_reply_locked(mut srv, c.id, stream, sb)
		}
		'get' {
			hash := req.attr('hash')
			if hash == '' {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
					'E_XSP_STORE_WIRE: get needs hash='))
				return
			}
			cx.cx_parse_tagged_address(hash) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_address,
					'E_XSP_STORE_ADDRESS: ${err.msg()}'))
				return
			}
			// §7b: a lawfully erased doc answers the typed tombstone VERBATIM.
			// Checked BEFORE the doc read: since #720 the local get-doc-text
			// ALSO answers the tombstone (as present text) — reaching the
			// present branch would wrap the tombstone as an ordinary
			// [doc present=true …] body, breaking the wire shape.
			if guard != unsafe { nil } {
				if tomb := guard.erased[hash] {
					sx_reply_locked(mut srv, c.id, stream, tomb)
					return
				}
			}
			r := store_stdlib_builtin_inner('store-get-doc-text', [local, store_str(hash)]) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: get failed'))
				return
			}
			if is_err_value(r) {
				sx_error_locked(mut srv, c.id, stream, r)
				return
			}
			if r is cx.ScalarNode {
				text := cx.scalar_value_str_public(r.value)
				doc := cx.parse(text) or {
					sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
						'E_XSP_STORE_INTERNAL: stored doc unparseable'))
					return
				}
				// §7b via a PROXIED substrate: when the mount's own read
				// answers the tombstone as text (a cx-store:// inner hop, or
				// the #720 local read), pass it through VERBATIM — never
				// wrapped as a present doc body. Unambiguous: a tombstone's
				// hash= names the REQUESTED address, while a genuine stored
				// [erased …] document's own address is the hash of its text
				// (attr==address would be a hash fixpoint).
				if doc.elements.len > 0 {
					root := doc.elements[0]
					if root is cx.Element {
						if root.name == 'erased' && root.attr('hash') == hash {
							sx_reply_locked(mut srv, c.id, stream, text)
							return
						}
					}
				}
				bin := cx.emit_ast_bin(doc)
				sx_reply_locked(mut srv, c.id, stream, '[doc hash="${hash}" present=true [body::bytes 0x${bin.hex()}]]')
				return
			}
			// (the erased answer moved ABOVE the doc read — see the §7b note
			// at the top of this arm; #720 made the local read tombstone-aware.)
			// absence is DATA, never an error frame (§4.1)
			sx_reply_locked(mut srv, c.id, stream, '[doc hash="${hash}" present=false]')
		}
		'put-blob' {
			// S6/F1': the OPAQUE-document write — raw bytes, byte-exact,
			// identity = hash of the bytes as given (store.md §4).
			raw := sx_bytes_child(req, 'bytes') or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_body,
					'E_XSP_STORE_BODY: put-blob needs a [bytes::bytes 0x…] child (the raw bytes)'))
				return
			}
			r := store_stdlib_builtin_inner('store-put-blob', [local, store_str(raw.bytestr())]) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: put-blob failed'))
				return
			}
			if is_err_value(r) {
				sx_error_locked(mut srv, c.id, stream, r)
				return
			}
			sx_reply_locked(mut srv, c.id, stream, '[put-blob-result key="${sw_scalar(r)}" stored=true]')
		}
		'get-blob' {
			key := req.attr('key')
			if key == '' {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
					'E_XSP_STORE_WIRE: get-blob needs key='))
				return
			}
			cx.cx_parse_tagged_address(key) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_address,
					'E_XSP_STORE_ADDRESS: ${err.msg()}'))
				return
			}
			r := store_stdlib_builtin_inner('store-get-blob', [local, store_str(key)]) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: get-blob failed'))
				return
			}
			if is_err_value(r) {
				// F1' absence contract crosses VERBATIM (CXER1121; unlike
				// get's absence-is-data — each surface keeps its own contract)
				sx_error_locked(mut srv, c.id, stream, r)
				return
			}
			sx_reply_locked(mut srv, c.id, stream, '[blob key="${key}" [bytes::bytes 0x${sw_scalar(r).bytes().hex()}]]')
		}
		'put' {
			body := sx_bytes_child(req, 'body') or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_body,
					'E_XSP_STORE_BODY: put needs a [body::bytes 0x…] child (framed ast_bin)'))
				return
			}
			doc := cx.bin_to_doc(body) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_body,
					'E_XSP_STORE_BODY: ast_bin decode failed: ${err.msg()}'))
				return
			}
			mut parts := []string{}
			for el in doc.elements {
				parts << render_canonical(el)
			}
			text := parts.join('\n')
			// content-dedup signal, computed atomically under the op lock
			// (the #190 CSRP semantics, kept op-for-op for the parity gate).
			canonical := cx.cx_text_canonical(text) or { '' }
			mut existed := false
			if canonical != '' {
				if h := cx.cx_text_hash(canonical) {
					ex := store_stdlib_builtin_inner('store-exists', [local, store_str(h)]) or {
						store_bool(false)
					}
					existed = sw_scalar(ex) == 'true'
				}
			}
			r := store_stdlib_builtin_inner('store-put-doc-text', [local, store_str(text)]) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: put failed'))
				return
			}
			if is_err_value(r) {
				sx_error_locked(mut srv, c.id, stream, r)
				return
			}
			stored := if existed { 'false' } else { 'true' }
			sx_reply_locked(mut srv, c.id, stream, '[put-result hash="${sw_scalar(r)}" stored=${stored}]')
		}
		'delete' {
			hash := req.attr('hash')
			if hash == '' {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
					'E_XSP_STORE_WIRE: delete needs hash='))
				return
			}
			r := store_stdlib_builtin_inner('store-delete-doc', [local, store_str(hash)]) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: delete failed'))
				return
			}
			if is_err_value(r) {
				sx_error_locked(mut srv, c.id, stream, r)
				return
			}
			sx_reply_locked(mut srv, c.id, stream, '[delete-result hash="${hash}" deleted=${sw_scalar(r)}]')
		}
		'erase' {
			// §7b.1: the doc-level lawful shred — destroys the doc entry AND
			// records the attributed [erased …] tombstone in one act. The
			// actor is ALWAYS the session principal (server-asserted).
			// Idempotent: re-erasing answers deduped=true; erasing an absent
			// doc still records the tombstone (replica convergence).
			hash := req.attr('hash')
			if hash == '' {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
					'E_XSP_STORE_WIRE: erase needs hash='))
				return
			}
			cx.cx_parse_tagged_address(hash) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_address,
					'E_XSP_STORE_ADDRESS: ${err.msg()}'))
				return
			}
			if guard == unsafe { nil } {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: this mount keeps no local substrate — remote mounts erase at their origin'))
				return
			}
			if guard.read_only {
				sx_error_locked(mut srv, c.id, stream, mk_err('cx-err:CXER1110',
					'E_STORE_READ_ONLY: ${guard.url}'))
				return
			}
			mut root := []u8{}
			if r := guard.obj_roots[hash] {
				root = r.clone()
			}
			mut request := req.attr('request')
			if request == '' {
				rb := crypto_random_octets(8) or { []u8{} }
				request = 'shred-${rb.hex()}'
			}
			tomb := store_erase_tombstone(hash, root, time.utc().format_rfc3339(),
				c.principal, req.attr('authority'), request)
			landed := store_erase_doc_local(mut guard, hash, tomb)
			if !landed {
				sx_reply_locked(mut srv, c.id, stream, '[erase-result hash="${hash}" erased=false deduped=true]')
				return
			}
			// durability: the removal's T record + the tombstone's E record
			// land in ONE append (file:// replays both; the object-graph
			// backends flush the same state as their manifest delta).
			store_append(mut guard, store_tombstone_record(hash) +
				store_erase_record(hash, tomb)) or {
				sx_error_locked(mut srv, c.id, stream, store_persist_err(guard, err.msg()))
				return
			}
			// §5.0 shape: [erase-result hash= erased= deduped=?] — the request
			// attribution rides the TOMBSTONE and the §5.3 feed act, never this
			// reply (F-30/R3.14: the extra request= attr conformed away).
			sx_reply_locked(mut srv, c.id, stream, '[erase-result hash="${hash}" erased=true]')
		}
		'modify' {
			hash := req.attr('hash')
			mut action := cx.Node(cx.Element{
				name: ''
			})
			mut has_action := false
			for it in req.items {
				if it is cx.Element && it.name == 'action' && it.items.len > 0 {
					action = it.items[0]
					has_action = true
				}
			}
			if hash == '' || !has_action {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
					'E_XSP_STORE_WIRE: modify needs hash= and an [action <element>] child'))
				return
			}
			r := store_stdlib_builtin_inner('store-modify-doc', [local, store_str(hash), action]) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: modify failed'))
				return
			}
			if is_err_value(r) {
				sx_error_locked(mut srv, c.id, stream, r) // CXER1121 etc., verbatim
				return
			}
			sx_reply_locked(mut srv, c.id, stream, '[modify-result old-hash="${hash}" new-hash="${sw_scalar(r)}" stored=true]')
		}
		'list', 'iter', 'query', 'journal-slice', 'journal-since', 'journal-query' {
			sx_stream_start_locked(mut srv, mut c, stream, req, local)
		}
		'journal-read', 'journal-verify', 'journal-verify-slice', 'journal-snapshot-verify',
		'journal-fold', 'journal-fold-slice', 'journal-replay', 'journal-dry-run' {
			// S6 §4.3: the journal pushdown family's request→reply verbs
			sxj_reply_verb(mut srv, mut c, stream, req, local)
		}
		'feed' {
			sx_feed_start_locked(mut srv, mut c, stream, req, local)
		}
		'objects-have', 'objects-get', 'objects-put' {
			if guard == unsafe { nil } {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: no object graph on this mount'))
				return
			}
			sx_objects_locked(mut srv, mut c, stream, req, mut guard)
		}
		'refs' {
			if guard == unsafe { nil } {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: no object graph on this mount'))
				return
			}
			mut sb := '[refs-result'
			for it in req.items {
				if it is cx.Element && it.name == 'k' {
					k := sw_attr(it, 'key')
					if k == '' {
						continue
					}
					if root := guard.obj_roots[k] {
						mh := cx.cx_multihash_encode('sha2-256', root) or {
							sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
								'E_XSP_STORE_INTERNAL: multihash encode failed'))
							return
						}
						sb += ' [r key="${sw_msg_esc(k)}" present=true root::bytes=0x${mh.hex()}]'
					} else {
						sb += ' [r key="${sw_msg_esc(k)}" present=false]'
					}
				}
			}
			sx_reply_locked(mut srv, c.id, stream, sb + ']')
		}
		'refs-set' {
			if guard == unsafe { nil } {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: no object graph on this mount'))
				return
			}
			sx_refs_set_locked(mut srv, mut c, stream, req, mut guard)
		}
		'aliases' {
			mut sb := '[aliases-result'
			if req.attr('all') == 'true' {
				lst := store_stdlib_builtin_inner('store-list-aliases', [local]) or {
					sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
						'E_XSP_STORE_INTERNAL: list-aliases failed'))
					return
				}
				if is_err_value(lst) {
					sx_error_locked(mut srv, c.id, stream, lst)
					return
				}
				if lst is cx.Element {
					for it in lst.items {
						if it is cx.Element && it.name == 'alias' {
							sb += ' [a name="${sw_msg_esc(sw_attr(it, 'name'))}" present=true hash="${sw_attr(it,
								'hash')}"]'
						}
					}
				}
			}
			for it in req.items {
				if it is cx.Element && it.name == 'k' {
					name := sw_attr(it, 'name')
					if name == '' {
						continue
					}
					r := store_stdlib_builtin_inner('store-get-alias', [local, store_str(name)]) or {
						sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
							'E_XSP_STORE_INTERNAL: get-alias failed'))
						return
					}
					if r is cx.ScalarNode {
						sb += ' [a name="${sw_msg_esc(name)}" present=true hash="${sw_scalar(r)}"]'
					} else {
						sb += ' [a name="${sw_msg_esc(name)}" present=false]'
					}
				}
			}
			sx_reply_locked(mut srv, c.id, stream, sb + ']')
		}
		'aliases-set' {
			sx_aliases_set_locked(mut srv, mut c, stream, req, local)
		}
		'log' {
			// stream 9 (the peer-lineage read): the E3 advance log, the
			// coordinate the wire reconcile/classify consumes. Read-only;
			// the porcelain builtin is the ONE producer (no second shape).
			r := store_stdlib_builtin_inner('store-log', [local]) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: log failed'))
				return
			}
			if is_err_value(r) {
				sx_error_locked(mut srv, c.id, stream, r)
				return
			}
			mut sb := '[log-result'
			// store-log returns the advance sequence directly.
			mut seqn := []cx.Node{}
			if r is cx.Element {
				seqn = [cx.Node(r)]
			} else if r is cx.SequenceNode {
				seqn = r.items.clone()
			}
			for it in seqn {
				if it is cx.Element && it.name == 'advance' {
					sb += ' ' + render_canonical(it)
				}
			}
			sx_reply_locked(mut srv, c.id, stream, sb + ']')
		}
		'status' {
			r := store_stdlib_builtin_inner('store-status', [local]) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: status failed'))
				return
			}
			if is_err_value(r) {
				sx_error_locked(mut srv, c.id, stream, r)
				return
			}
			sx_reply_locked(mut srv, c.id, stream, render_canonical(r))
		}
		'gc' {
			r := store_stdlib_builtin_inner('store-gc', [local]) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: gc failed'))
				return
			}
			if is_err_value(r) {
				sx_error_locked(mut srv, c.id, stream, r) // porcelain codes verbatim
				return
			}
			sx_reply_locked(mut srv, c.id, stream, render_canonical(r))
		}
		'mounts' {
			// daemon-level. OPEN MODE ONLY (§6.1): with no [grants] configured
			// the mutual gate stands; under grants the PEP above owns admin
			// and this row never fires.
			if c.authz == unsafe { nil } && !c.mutual {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_admin,
					'E_XSP_STORE_ADMIN: mounts requires a DID-proven principal (open mode — configure [grants …] for the VC-compiled PEP)'))
				return
			}
			mut names := srv.ctx.mounts.keys()
			names.sort()
			mut sb := '[mounts'
			for name in names {
				mnt := srv.ctx.mounts[name] or { continue }
				backend, readf, writef, listf := svc_mount_caps(mnt)
				sb += ' [mount name="${name}" backend="${backend}" read=${readf} write=${writef} list=${listf}]'
			}
			sx_reply_locked(mut srv, c.id, stream, sb + ']')
		}
		'config-reload' {
			if c.authz == unsafe { nil } && !c.mutual {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_admin,
					'E_XSP_STORE_ADMIN: config-reload requires a DID-proven principal (open mode — configure [grants …] for the VC-compiled PEP)'))
				return
			}
			if srv.ctx.reloader == unsafe { nil } {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_unsupported,
					'E_XSP_STORE_UNSUPPORTED: no daemon config to reload here'))
				return
			}
			out := srv.ctx.reloader()
			eprintln(svc_reload_log(out, 'xsp'))
			if out.err_code != '' {
				// the §3.13 refusal codes (CXER1711/1712), verbatim
				sx_error_locked(mut srv, c.id, stream, mk_err(out.err_code, out.err_msg))
				return
			}
			ch := out.changed.join(' ')
			sx_reply_locked(mut srv, c.id, stream, '[config-reload applied=${out.applied} generation=${out.gen} changed="${ch}"]')
			// §7a.1 F3: the reload verb pushes the fresh advert DIRECTLY to
			// every established session on this listener, right now — the
			// sweeper's generation-watch is only the fallback for reloads that
			// land through the OTHER listeners (CSRP/gRPC). sx_readvertise_locked
			// is idempotent on srv.last_gen, so this direct push consumes the
			// generation move and the sweeper's later call is a no-op (no double
			// advert). Audit F-22 / register R3.6.
			sx_readvertise_locked(mut srv)
		}
		'session' {
			// §5.0 surface 2: operational limits + a RESTATEMENT of the
			// transcript-confirmed set (never an extension).
			mut feats := 'heartbeat'
			if c.confirmed_features != '' {
				feats += ' ' + c.confirmed_features
			}
			sx_reply_locked(mut srv, c.id, stream, '[store-session profiles="${c.confirmed_profiles}" features="${feats}" liveness-ms=${srv.cfg.liveness_ms} pending-window=${srv.cfg.pending_window}]')
		}
		else {
			sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_unsupported,
				'E_XSP_STORE_UNSUPPORTED: unknown verb [${req.name}]'))
		}
	}
	// W4 §5: a write just landed in the lineage — wake the feeds now (the
	// sweeper covers writes arriving through the OTHER listeners). A no-op
	// when nothing advanced (each feed short-circuits at its index).
	sx_pump_all_feeds_locked(mut srv)
}

// sx_feed_names_revocations reports whether a [feed …] request's [planes …]
// names the revocations plane (the PEP-class discriminator, §7.1).
fn sx_feed_names_revocations(req cx.Element) bool {
	for it in req.items {
		if it is cx.Element && it.name == 'planes' {
			for pit in it.items {
				t := authz_node_text(pit)
				if t.split(' ').contains('revocations') {
					return true
				}
			}
		}
	}
	return false
}

// ── result streams (list/iter/query — credit-governed, cancel + eos) ───────

fn sx_stream_start_locked(mut srv StoreXspServer, mut c SxConn, stream i64, req cx.Element, local cx.Node) {
	mut windowed := false
	mut window := i64(0)
	if req.has_attr('window') {
		window = req.attr('window').i64()
		if window < 1 {
			sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
				'E_XSP_STORE_WIRE: window= must be ≥ 1'))
			return
		}
		windowed = true
	}
	if stream in c.streams {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
			'E_XSP_STORE_WIRE: stream ${stream} already carries a live result stream'))
		return
	}
	mut items := []string{}
	match req.name {
		'journal-slice', 'journal-since', 'journal-query' {
			// S6 §4.3: the streamed journal pushdown verbs — same credit tail
			items = sxj_stream_items(mut srv, mut c, stream, req, local) or { return }
		}
		'list' {
			r := store_stdlib_builtin_inner('store-list-docs', [local]) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: list failed'))
				return
			}
			if is_err_value(r) {
				sx_error_locked(mut srv, c.id, stream, r)
				return
			}
			if r is cx.Element {
				for it in r.items {
					h := sw_scalar(it)
					if h != '' {
						items << '[hash "${h}"]'
					}
				}
			}
		}
		'iter' {
			r := store_stdlib_builtin_inner('store-iter-docs', [local]) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: iter failed'))
				return
			}
			if is_err_value(r) {
				sx_error_locked(mut srv, c.id, stream, r)
				return
			}
			if r is cx.Element {
				for entry in r.items {
					if entry is cx.Element && entry.name == 'entry' {
						hash := sw_attr(entry, 'hash')
						// the entry's items ARE the doc nodes; the body rides as
						// the framed ast_bin of that document (the get lane).
						bin := cx.emit_ast_bin(cx.Document{
							elements: entry.items.clone()
						})
						items << '[doc hash="${hash}" [body::bytes 0x${bin.hex()}]]'
					}
				}
			}
		}
		'query' {
			cxpath := req.attr('path')
			comp := req.attr('comp')
			if (cxpath == '') == (comp == '') {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
					'E_XSP_STORE_WIRE: query needs exactly one of path= / comp='))
				return
			}
			if comp != '' {
				// L99: the quoted planar comprehension's source text —
				// server-side membership + layers; rows ride [item …]
				// envelopes, one per event frame.
				planar_items, perr, pok := store_server_query_planar_items(local, comp)
				if !pok {
					sx_error_locked(mut srv, c.id, stream, perr)
					return
				}
				items << planar_items
				c.streams[stream] = &SxStream{
					items:    items
					credits:  window
					windowed: windowed
				}
				sx_pump_stream_locked(mut srv, mut c, stream)
				return
			}
			r := store_stdlib_builtin_inner('store-query', [local, store_str(cxpath)]) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: query failed'))
				return
			}
			if is_err_value(r) {
				sx_error_locked(mut srv, c.id, stream, r)
				return
			}
			if r is cx.Element {
				// The L97 flat relation: one [result doc= source= MATCH] tuple per
				// match, carried on the wire VERBATIM (parity by construction — the
				// wire frame IS the executor's tuple).
				for result in r.items {
					if result is cx.Element && result.name == 'result' {
						items << render_canonical(result)
					}
				}
			}
		}
		else {}
	}
	c.streams[stream] = &SxStream{
		items:    items
		credits:  window
		windowed: windowed
	}
	sx_pump_stream_locked(mut srv, mut c, stream)
}

// sx_pump_stream_locked pushes buffered results while credit remains; at the
// end of the set it emits the terminal eos event and drops the stream state.
// One result, one frame — ∂ frames are never coalesced (§5), and neither are
// these.
fn sx_pump_stream_locked(mut srv StoreXspServer, mut c SxConn, stream i64) {
	mut s := c.streams[stream] or { return }
	for s.sent < s.items.len {
		if s.windowed && s.credits <= 0 {
			return // window exhausted: the next credit frame resumes exactly here
		}
		sx_event_locked(mut srv, c.id, stream, s.items[s.sent], false)
		s.sent++
		if s.windowed {
			s.credits--
		}
	}
	sx_event_locked(mut srv, c.id, stream, '[eos count=${s.sent}]', true)
	c.streams.delete(stream)
}

// ── the object wire (multihash addresses, verified puts) ───────────────────

fn sx_objects_locked(mut srv StoreXspServer, mut c SxConn, stream i64, req cx.Element, mut guard MemStore) {
	getter := store_graph_getter(guard)
	match req.name {
		'objects-have' {
			// reply the MISSING addresses only — the dedup-on-wire primitive.
			// §7b: an erased root counts MISSING even while its bytes await
			// reclamation — it cannot be fetched, so "have" would be a lie.
			mut sb := '[have-result'
			for it in req.items {
				if it is cx.Element && it.name == 'o' {
					mh, _, digest := sx_mh_attr(it, 'h') or {
						sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_address,
							'E_XSP_STORE_ADDRESS: objects-have: h must be a registered varint multihash (h::bytes=0x…)'))
						return
					}
					if digest.hex() in guard.erased_roots || getter(digest) == none {
						sb += ' [o h::bytes=0x${mh.hex()}]'
					}
				}
			}
			sx_reply_locked(mut srv, c.id, stream, sb + ']')
		}
		'objects-get' {
			// absent objects are omitted; each object self-verifies client-side.
			// §7b: a former root of a lawfully erased doc answers erased=true
			// and NEVER its bytes — the erased marker wins over physical
			// presence (the object may await reclamation; serving it would
			// leak lawfully erased content on the object wire).
			mut sb := '[get-result'
			for it in req.items {
				if it is cx.Element && it.name == 'o' {
					mh, _, digest := sx_mh_attr(it, 'h') or {
						sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_address,
							'E_XSP_STORE_ADDRESS: objects-get: h must be a registered varint multihash (h::bytes=0x…)'))
						return
					}
					if digest.hex() in guard.erased_roots {
						sb += ' [o h::bytes=0x${mh.hex()} erased=true]'
						continue
					}
					payload := getter(digest) or { continue }
					sb += ' [o h::bytes=0x${mh.hex()} [bytes::bytes 0x${payload.hex()}]]'
				}
			}
			sx_reply_locked(mut srv, c.id, stream, sb + ']')
		}
		'objects-put' {
			// VALIDATE-THEN-APPLY: every record's claimed address is verified
			// against its bytes BEFORE anything is stored (§7a — never
			// trust-the-label); one mismatch refuses the whole batch.
			mut records := [][]u8{}
			for it in req.items {
				if it is cx.Element && it.name == 'o' {
					_, algo, digest := sx_mh_attr(it, 'h') or {
						sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_address,
							'E_XSP_STORE_ADDRESS: objects-put: h must be a registered varint multihash (h::bytes=0x…)'))
						return
					}
					pb := sx_bytes_child(it, 'bytes') or {
						sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_body,
							'E_XSP_STORE_BODY: objects-put: each [o] needs a [bytes::bytes 0x…] child'))
						return
					}
					if algo != 'sha2-256' {
						sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_address,
							'E_XSP_STORE_ADDRESS: objects-put: the object graph addresses with sha2-256 (got ${algo})'))
						return
					}
					actual := sha256.sum256(pb)
					if !xsp_auth_ct_eq(actual[..], digest) {
						sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_address,
							'E_XSP_STORE_ADDRESS: objects-put: claimed address does not match the bytes'))
						return
					}
					records << pb
				}
			}
			for pb in records {
				guard.obj_sink.put(pb)
			}
			store_persist(mut guard) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: persist failed: ${err.msg()}'))
				return
			}
			sx_reply_locked(mut srv, c.id, stream, '[put-result stored=${records.len}]')
		}
		else {}
	}
}

// sx_refs_set_locked advances store-key → root pointers: VALIDATE-THEN-APPLY
// under the op lock, all-or-nothing; a CAS mismatch is the one ref-conflict
// code CXER1114, verbatim. `expect::bytes=0x` (empty) = must-not-exist;
// absent expect = unconditional (content-addressed refs are immutable by
// construction — the CAS is for the mutable-pointer layer).
fn sx_refs_set_locked(mut srv StoreXspServer, mut c SxConn, stream i64, req cx.Element, mut guard MemStore) {
	// validate pass
	for it in req.items {
		if it is cx.Element && it.name == 'r' {
			k := sw_attr(it, 'key')
			if k == '' || !sw_has_attr(it, 'expect') {
				continue
			}
			expect_img := sw_attr(it, 'expect')
			mut expect_digest := []u8{}
			if expect_img != '0x' && expect_img != '' {
				mh := sx_hex_image(expect_img) or {
					sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_address,
						'E_XSP_STORE_ADDRESS: refs-set: expect must be a varint multihash or empty (0x)'))
					return
				}
				_, d := cx.cx_multihash_decode(mh) or {
					sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_address,
						'E_XSP_STORE_ADDRESS: refs-set: ${err.msg()}'))
					return
				}
				expect_digest = d.clone()
			}
			mut cur := []u8{}
			if cd := guard.obj_roots[k] {
				cur = cd.clone()
			}
			if cur.hex() != expect_digest.hex() {
				sx_error_locked(mut srv, c.id, stream, mk_err('cx-err:CXER1114',
					'E_STORE_REF_CONFLICT: ref ${sw_msg_esc(k)} is at ${cur.hex()}, expected ${expect_digest.hex()}'))
				return
			}
		}
	}
	// apply pass
	mut n := 0
	for it in req.items {
		if it is cx.Element && it.name == 'r' {
			k := sw_attr(it, 'key')
			if k == '' {
				continue
			}
			_, _, root := sx_mh_attr(it, 'root') or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_address,
					'E_XSP_STORE_ADDRESS: refs-set: root must be a registered varint multihash (root::bytes=0x…)'))
				return
			}
			store_ref_advance_local(mut guard, k, root) // the E3 lineage funnel (§5.1)
			n++
		}
	}
	store_persist(mut guard) or {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
			'E_XSP_STORE_INTERNAL: persist failed: ${err.msg()}'))
		return
	}
	sx_reply_locked(mut srv, c.id, stream, '[refs-set-result set=${n}]')
}

// sx_aliases_set_locked applies alias writes through the same local arm as an
// in-process set-alias; per-record expect="<hash>" is the refs-set CAS on the
// alias pointer layer (expect="" = must-not-exist), validate-then-apply,
// all-or-nothing. Faults ride verbatim: conflict CXER1114, target-presence
// CXER1121, read-only CXER1110 — the profile never remaps them.
fn sx_aliases_set_locked(mut srv StoreXspServer, mut c SxConn, stream i64, req cx.Element, local cx.Node) {
	// validate pass
	for it in req.items {
		if it is cx.Element && it.name == 'a' {
			name := sw_attr(it, 'name')
			if name == '' || !sw_has_attr(it, 'expect') {
				continue
			}
			expect := sw_attr(it, 'expect')
			mut cur := ''
			r := store_stdlib_builtin_inner('store-get-alias', [local, store_str(name)]) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: get-alias failed'))
				return
			}
			if r is cx.ScalarNode {
				cur = sw_scalar(r)
			}
			if cur != expect {
				sx_error_locked(mut srv, c.id, stream, mk_err('cx-err:CXER1114',
					'E_STORE_REF_CONFLICT: alias ${sw_msg_esc(name)} is at ${sw_msg_esc(cur)}, expected ${sw_msg_esc(expect)}'))
				return
			}
		}
	}
	// apply pass
	mut n := 0
	for it in req.items {
		if it is cx.Element && it.name == 'a' {
			name := sw_attr(it, 'name')
			hash := sw_attr(it, 'hash')
			if name == '' || hash == '' {
				continue
			}
			r := store_stdlib_builtin_inner('store-set-alias', [local, store_str(name),
				store_str(hash)]) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: set-alias failed'))
				return
			}
			if is_err_value(r) {
				sx_error_locked(mut srv, c.id, stream, r) // CXER1121/1110, verbatim
				return
			}
			n++
		}
	}
	sx_reply_locked(mut srv, c.id, stream, '[aliases-set-result set=${n}]')
}

// ── daemon wiring ──────────────────────────────────────────────────────────

// run_store_xsp_serve_loop is the CLI entry: builds the server state, spawns
// the liveness sweeper, and runs the accept loop until the listener closes.
pub fn run_store_xsp_serve_loop(server cx.Node, cfg XspConfig, ctx ServeContext, should_stop fn () bool) {
	mut srv := new_store_xsp_server(cfg, ctx)
	spawn store_xsp_liveness_sweeper(mut srv)
	// W5 §7.1: one worker per configured [peer …] — dial, subscribe the
	// revocations plane, fold. An offline peer is lag, never an error state.
	store_xsp_peer_workers(mut srv)
	store_xsp_accept_loop(mut srv, server, should_stop)
	// teardown: close every connection so reader/writer threads drain
	srv.mu.lock()
	mut ids := srv.conns.keys()
	for id in ids {
		sx_close_conn_locked(mut srv, id)
	}
	srv.mu.unlock()
}
