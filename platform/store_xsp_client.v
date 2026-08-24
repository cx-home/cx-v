module platform

import code {
	arg_string,
	bytes_node,
	cap_guard,
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

// store_xsp_client.v — the XSP STORE-PROFILE CLIENT (I5 stream 4 W6; spec
// spec/03-approved/xap/xsp_store_profile.md §8 migration order: "remote client via
// ObjWireTransport"). This is the THIRD ObjWireTransport impl beside CSRP and
// gRPC, plus the profile client arms for the catalog/admin verbs — together
// they make `cx-store://` (TLS) and `cx-store+xsp://` (cleartext, loopback/
// dev) full Layer-1 store URLs whose wire is the profile:
//
//  * ONE session per open handle: dial → mutual-or-anonymous XSP-AUTH
//    (M1–M4 through the SAME $xsp:auth-* calculus the daemon and the peer
//    worker use) → tenant-bound attach ([attach [tenant <store-name>]]) →
//    verbs as TEXT frames of canonical CX on fresh stream-ids. The session
//    persists across ops (reconnect-on-drop; an idle session past the probe
//    window is ping-probed before reuse so a liveness-swept connection is
//    re-established rather than surfacing as a spurious transport fault).
//  * Identity comes from open-opts (`xsp-did` + `xsp-seed-env` — the seed
//    ALWAYS rides an env var, never a URL or opts literal; the deprecated
//    bearer-in-URL pattern does not carry over). Absent = anonymous: the
//    daemon's floor policy decides (§6.1 posture).
//  * Error transparency (§4.1): an `error` frame's payload is the op-layer
//    [err …] value VERBATIM — CXER1121/1114/1110 and the PEP's [deny …]
//    cross unmapped. Only genuine transport faults synthesize CXER1101.
//  * The object wire (§7a): XspObjWireTransport adapts the CSRP-shaped
//    object-verb bodies RemoteObjectBackend speaks (bare-hex `h="…"`) to the
//    profile's varint-multihash envelopes (`h::bytes=0x…`, the crypto-agility
//    bijection) and back — so decompose-locally / transfer-only-missing /
//    advance-the-ref runs over the profile at exact parity with the other
//    two transports.

const xcl_max_frame = i64(16777216)
const xcl_reply_ticks = 30 // 1s idle ticks: unary-reply budget
const xcl_stream_ticks = 30 // per-frame budget while streaming
const xcl_probe_idle_ms = i64(2000) // reused-session ping-probe threshold

// XspClientSession is the one live profile session behind an open
// cx-store(+xsp):// handle. Guarded by its own mutex — the store op lock
// already serializes ops per handle; the mutex makes the session safe under
// shared-handle concurrency too.
@[heap]
pub struct XspClientSession {
mut:
	mu       &sync.Mutex = unsafe { nil }
	tls      bool
	host     string
	port     int
	tenant   string // the store name — the M3 attach tenant
	endpoint string // the M1 channel-binding endpoint (the dial URL)
	did      string // client identity; '' = anonymous (floor)
	seed     []u8
	// live connection state
	connected   bool
	net_id      int
	handle      &code.NetHandle = unsafe { nil }
	next_stream i64 = 100
	last_used   i64
}

// xcl_session returns the session hanging off a RemoteBackend, mutable (the
// backend rides behind `&` everywhere; the session is @[heap] with its own
// lock — the ow_note_fail pattern).
fn xcl_session(rb &RemoteBackend) ?&XspClientSession {
	if rb.xsp == unsafe { nil } {
		return none
	}
	return unsafe { rb.xsp }
}

fn xcl_unreachable(op string, detail string) cx.Node {
	tail := if detail != '' { ': ${detail}' } else { '' }
	return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: xsp ${op}${tail}')
}

// ── session lifecycle ────────────────────────────────────────────────────────

fn xcl_teardown_locked(mut s XspClientSession) {
	if s.connected {
		net_close_id(s.net_id)
	}
	s.connected = false
	s.handle = unsafe { nil }
}

// xcl_connect_locked dials and attaches: XSP-AUTH M1–M4 through the shipped
// calculus, tenant-bound, anonymous unless the session carries an identity.
// Returns an [err] node on failure (CXER1101 transport; handshake refusals
// verbatim).
fn xcl_connect_locked(mut s XspClientSession) ?cx.Node {
	url := if s.tls { 'tls://${s.host}:${s.port}' } else { 'tcp://${s.host}:${s.port}' }
	opts := cx.Node(cx.Element{
		name:  code.map_marker_name
		items: [
			cx.Node(cx.Element{
				name:  'read-deadline'
				items: [
					cx.Node(cx.ScalarNode{
						value:     cx.ScalarValue(i64(1000))
						data_type: cx.ScalarType.int_type
					}),
				]
			}),
		]
	})
	conn := net_dial_impl(if s.tls { 'net-dial-tls' } else { 'net-dial-tcp' }, [
		cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(url)
			data_type: cx.ScalarType.string_type
		}),
		opts,
	])
	if is_err_value(conn) {
		mut detail := ''
		if conn is cx.Element {
			detail = xap_elem_attr(conn, 'code')
			m := xap_elem_attr(conn, 'message')
			if m != '' {
				detail += ': ${m}'
			}
		}
		return xcl_unreachable('dial ${url}', detail)
	}
	net_id := net_handle_id(conn) or { return xcl_unreachable('dial ${url}', 'no handle') }
	mut h := net_mut_handle(conn) or { return xcl_unreachable('dial ${url}', 'no handle') }
	h.read_deadline_ms = 1000

	// M1 (hello) — anonymous unless the open-opts named an identity.
	nonce := crypto_random_octets(32) or {
		net_close_id(net_id)
		return xcl_unreachable('attach', 'entropy unavailable')
	}
	eph_priv := crypto_random_octets(32) or {
		net_close_id(net_id)
		return xcl_unreachable('attach', 'entropy unavailable')
	}
	mut sk := eph_priv.clone()
	x25519_clamp(mut sk)
	eph_pub := x25519_scalar_base_mult(sk)
	mut m1_items := [
		session_kv('nonce', bytes_node(nonce)),
		session_kv('eph', bytes_node(eph_pub)),
		session_kv('endpoint', crypto_string_node(s.endpoint)),
		session_kv('offer-profiles', crypto_string_node('store')),
		// S6 §4.3: the embedded client offers store-journal — the journal
		// pushdown family rides its sessions (canonical sorted set).
		session_kv('offer-features', crypto_string_node('credit store-delta store-feed store-journal')),
	]
	if s.did != '' {
		m1_items << session_kv('did', crypto_string_node(s.did))
	}
	m1 := xsp_auth_stdlib_builtin('xsp-auth-hello', [
		cx.Node(cx.Element{
			name:  code.map_marker_name
			items: m1_items
		}),
	]) or {
		net_close_id(net_id)
		return xcl_unreachable('attach', 'hello failed')
	}
	if is_err_value(m1) {
		net_close_id(net_id)
		return m1
	}
	m2 := xcl_handshake_turn(mut h, m1) or {
		net_close_id(net_id)
		return xcl_unreachable('attach', 'no M2')
	}
	if is_err_value(m2) {
		net_close_id(net_id)
		return m2 // the responder's refusal, verbatim
	}
	// M3 (prove) — tenant-bound attach; key only when mutual.
	mut attach_items := []cx.Node{}
	if s.tenant != '' {
		attach_items << cx.Node(cx.Element{
			name:  'tenant'
			items: [cx.Node(bus_str(s.tenant))]
		})
	}
	mut m3_items := [
		session_kv('eph-priv', bytes_node(eph_priv)),
		session_kv('attach', cx.Node(cx.Element{
			name:  'attach'
			items: attach_items
		})),
	]
	if s.did != '' {
		m3_items << session_kv('key', bytes_node(s.seed))
	}
	m3 := xsp_auth_stdlib_builtin('xsp-auth-prove', [m1, m2,
		cx.Node(cx.Element{
			name:  code.map_marker_name
			items: m3_items
		})]) or {
		net_close_id(net_id)
		return xcl_unreachable('attach', 'prove failed')
	}
	if is_err_value(m3) {
		net_close_id(net_id)
		return m3
	}
	m4 := xcl_handshake_turn(mut h, m3) or {
		net_close_id(net_id)
		return xcl_unreachable('attach', 'no M4')
	}
	if is_err_value(m4) {
		net_close_id(net_id)
		return m4 // attach refusal (mount unknown, no common profile, …) verbatim
	}
	done := xsp_auth_stdlib_builtin('xsp-auth-finish', [m1, m2, m4,
		cx.Node(cx.Element{
			name:  code.map_marker_name
			items: [session_kv('eph-priv', bytes_node(eph_priv))]
		})]) or {
		net_close_id(net_id)
		return xcl_unreachable('attach', 'finish failed')
	}
	if is_err_value(done) {
		net_close_id(net_id)
		return done // transcript-confirm failure (downgrade strip, …) verbatim
	}
	mut confirmed := ''
	if done is cx.Element {
		if conf := xsp_auth_child(done, 'confirmed') {
			confirmed = xap_elem_attr(conf, 'profiles')
		}
	}
	if !confirmed.split(' ').contains('store') {
		net_close_id(net_id)
		return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: xsp attach: the responder did not confirm the store profile (confirmed "${confirmed}")')
	}
	s.connected = true
	s.net_id = net_id
	s.handle = h
	s.last_used = time.now().unix_milli()
	return none
}

// xcl_handshake_turn sends one handshake message as a BINARY stream-0 request
// and returns the reply/error payload (the peer worker's turn, client-side).
fn xcl_handshake_turn(mut h code.NetHandle, msg cx.Node) ?cx.Node {
	b := fs_frame_bytes_bin('request', 0, msg) or { return none }
	net_h_write(mut h, b) or { return none }
	mut ticks := 0
	for ticks < 10 {
		st, raw := fs_read_frame(mut h, xcl_max_frame)
		match st {
			.idle {
				ticks++
				continue
			}
			.closed {
				return none
			}
			.frame {
				node := xsp_decode_at(raw, 0)
				if node !is cx.Element {
					return none
				}
				fe := node as cx.Element
				if fe.name != 'frame' {
					return none
				}
				return xsp_payload_value(fe)
			}
		}
	}
	return none
}

// xcl_ensure_locked makes the session usable: fresh connect, or a ping probe
// on an idle reused session (the liveness sweeper may have closed it —
// re-establish rather than surface a spurious CXER1101).
fn xcl_ensure_locked(mut s XspClientSession) ?cx.Node {
	if s.connected {
		if time.now().unix_milli() - s.last_used <= xcl_probe_idle_ms {
			return none
		}
		if xcl_ping_locked(mut s) {
			return none
		}
		xcl_teardown_locked(mut s)
	}
	return xcl_connect_locked(mut s)
}

// xcl_ping_locked runs one ping→pong round trip on the live session.
fn xcl_ping_locked(mut s XspClientSession) bool {
	s.next_stream++
	stream := s.next_stream
	b := sx_frame_text('ping', stream, 'probe', false) or { return false }
	net_h_write(mut s.handle, b) or { return false }
	mut ticks := 0
	for ticks < 5 {
		st, raw := fs_read_frame(mut s.handle, xcl_max_frame)
		match st {
			.idle {
				ticks++
				continue
			}
			.closed {
				return false
			}
			.frame {
				node := xsp_decode_at(raw, 0)
				if node is cx.Element && node.name == 'frame' {
					if xap_elem_attr(node, 'type') == 'pong' {
						return true
					}
					// anything else (a late advert) — keep reading
					continue
				}
				return false
			}
		}
	}
	return false
}

// xcl_frame_payload_node extracts a frame's payload as a parsed node: text
// frames carry canonical CX (parse it); binary frames (handshake-era errors)
// carry the value directly.
fn xcl_frame_payload_node(fe cx.Element) ?cx.Node {
	pv := xsp_payload_value(fe) or { return none }
	if xap_elem_attr(fe, 'binary') == 'true' {
		return pv
	}
	txt := arg_string(pv) or { return none }
	doc := cx.parse(txt) or { return none }
	if doc.elements.len == 0 {
		return none
	}
	return doc.elements[0]
}

// ── one request → one reply ─────────────────────────────────────────────────

// xcl_exchange sends one verb (canonical CX text) and returns the reply/error
// payload node. ok=false ONLY on a transport fault (errn = CXER1101); a
// server-side [err]/[deny] is a COMPLETED exchange (ok=true, node = the value
// verbatim — error transparency, §4.1).
fn xcl_exchange(rb &RemoteBackend, op string, verb string) (cx.Node, bool) {
	if d := cap_guard('net', 'store xsp ${op}') {
		return d, false
	}
	sref := xcl_session(rb) or { return xcl_unreachable(op, 'no session'), false }
	mut s := unsafe { &XspClientSession(sref) }
	s.mu.lock()
	defer {
		s.mu.unlock()
	}
	if errn := xcl_ensure_locked(mut s) {
		return errn, false
	}
	s.next_stream++
	stream := s.next_stream
	b := sx_frame_text('request', stream, verb, false) or {
		return xcl_unreachable(op, 'frame encode'), false
	}
	net_h_write(mut s.handle, b) or {
		// the write itself failed — the request never left; reconnect once.
		xcl_teardown_locked(mut s)
		if errn := xcl_connect_locked(mut s) {
			return errn, false
		}
		net_h_write(mut s.handle, b) or {
			xcl_teardown_locked(mut s)
			return xcl_unreachable(op, 'write: ${err.msg()}'), false
		}
	}
	mut ticks := 0
	for ticks < xcl_reply_ticks {
		st, raw := fs_read_frame(mut s.handle, xcl_max_frame)
		match st {
			.idle {
				ticks++
				continue
			}
			.closed {
				xcl_teardown_locked(mut s)
				return xcl_unreachable(op, 'connection closed mid-exchange'), false
			}
			.frame {
				node := xsp_decode_at(raw, 0)
				if node !is cx.Element {
					xcl_teardown_locked(mut s)
					return xcl_unreachable(op, 'broken framing'), false
				}
				fe := node as cx.Element
				if fe.name != 'frame' {
					xcl_teardown_locked(mut s)
					return xcl_unreachable(op, 'broken framing'), false
				}
				if xap_elem_attr(fe, 'stream').i64() != stream {
					continue // stream-0 advert / unrelated traffic
				}
				ftype := xap_elem_attr(fe, 'type')
				payload := xcl_frame_payload_node(fe) or {
					return xcl_unreachable(op, 'unreadable ${ftype} payload'), false
				}
				if ftype == 'reply' || ftype == 'error' {
					s.last_used = time.now().unix_milli()
					return payload, true
				}
				continue
			}
		}
	}
	xcl_teardown_locked(mut s)
	return xcl_unreachable(op, 'reply timeout'), false
}

// xcl_stream sends one streaming verb (list/iter/query — subscribed
// UNBOUNDED: no window attr, so the server pushes the whole result set + eos)
// and returns the ordered event payload elements. Server-side faults ride
// back verbatim as (errn, true)-shaped: ok=true, err non-nil.
fn xcl_stream(rb &RemoteBackend, op string, verb string) ([]cx.Element, cx.Node, bool) {
	if d := cap_guard('net', 'store xsp ${op}') {
		return []cx.Element{}, d, false
	}
	sref := xcl_session(rb) or {
		return []cx.Element{}, xcl_unreachable(op, 'no session'), false
	}
	mut s := unsafe { &XspClientSession(sref) }
	s.mu.lock()
	defer {
		s.mu.unlock()
	}
	if errn := xcl_ensure_locked(mut s) {
		return []cx.Element{}, errn, false
	}
	s.next_stream++
	stream := s.next_stream
	b := sx_frame_text('request', stream, verb, false) or {
		return []cx.Element{}, xcl_unreachable(op, 'frame encode'), false
	}
	net_h_write(mut s.handle, b) or {
		xcl_teardown_locked(mut s)
		if errn := xcl_connect_locked(mut s) {
			return []cx.Element{}, errn, false
		}
		net_h_write(mut s.handle, b) or {
			xcl_teardown_locked(mut s)
			return []cx.Element{}, xcl_unreachable(op, 'write: ${err.msg()}'), false
		}
	}
	mut out := []cx.Element{}
	mut ticks := 0
	for ticks < xcl_stream_ticks {
		st, raw := fs_read_frame(mut s.handle, xcl_max_frame)
		match st {
			.idle {
				ticks++
				continue
			}
			.closed {
				xcl_teardown_locked(mut s)
				return []cx.Element{}, xcl_unreachable(op, 'connection closed mid-stream'), false
			}
			.frame {
				node := xsp_decode_at(raw, 0)
				if node !is cx.Element {
					xcl_teardown_locked(mut s)
					return []cx.Element{}, xcl_unreachable(op, 'broken framing'), false
				}
				fe := node as cx.Element
				if fe.name != 'frame' {
					xcl_teardown_locked(mut s)
					return []cx.Element{}, xcl_unreachable(op, 'broken framing'), false
				}
				if xap_elem_attr(fe, 'stream').i64() != stream {
					continue
				}
				ticks = 0 // progress — reset the idle budget
				ftype := xap_elem_attr(fe, 'type')
				payload := xcl_frame_payload_node(fe) or {
					return []cx.Element{}, xcl_unreachable(op, 'unreadable ${ftype} payload'), false
				}
				if ftype == 'error' {
					s.last_used = time.now().unix_milli()
					return []cx.Element{}, payload, true
				}
				if ftype != 'event' {
					continue
				}
				if payload is cx.Element {
					pe := payload as cx.Element
					if pe.name == 'eos' {
						s.last_used = time.now().unix_milli()
						return out, store_null(), true
					}
					out << pe
				}
			}
		}
	}
	xcl_teardown_locked(mut s)
	return []cx.Element{}, xcl_unreachable(op, 'stream timeout'), false
}

// ── the profile client arms (the same op shapes the retired CSRP client /
//    grpc_client_* return, so cx-store(+xsp):// is a drop-in transport) ──────

// xcl_is_err reports whether a completed exchange carried a server-side
// failure value ([err …] or the PEP's [deny …] — both ride verbatim).
fn xcl_is_err(n cx.Node) bool {
	return is_err_value(n) || (n is cx.Element && n.name == 'deny')
}

fn xsp_client_get(rb &RemoteBackend, hash string) (string, cx.Node, bool) {
	r, ok := xcl_exchange(rb, 'get', '[get hash="${sw_msg_esc(hash)}"]')
	if !ok {
		return '', r, false
	}
	if xcl_is_err(r) {
		return '', r, false
	}
	if r is cx.Element {
		re := r as cx.Element
		if re.name == 'erased' {
			// §7b.1: the lawful-shred tombstone rides VERBATIM — the caller
			// sees the same [erased …] value a wire get answers.
			return render_canonical(r), store_null(), true
		}
		if re.name == 'doc' {
			if sw_attr(re, 'present') != 'true' {
				return '', mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: ${hash}'), false
			}
			body := sx_bytes_child(re, 'body') or {
				return '', xcl_unreachable('get', 'doc reply carries no body'), false
			}
			doc := cx.bin_to_doc(body) or {
				return '', xcl_unreachable('get', 'ast_bin decode: ${err.msg()}'), false
			}
			mut parts := []string{}
			for el in doc.elements {
				parts << render_canonical(el)
			}
			return parts.join('\n'), store_null(), true
		}
	}
	return '', xcl_unreachable('get', 'malformed reply'), false
}

fn xsp_client_put(rb &RemoteBackend, hash string, text string) cx.Node {
	doc := cx.parse(text) or {
		return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: unparseable doc for put: ${err.msg()}')
	}
	bin := cx.emit_ast_bin(doc)
	r, ok := xcl_exchange(rb, 'put', '[put [body::bytes 0x${bin.hex()}]]')
	if !ok || xcl_is_err(r) {
		return r
	}
	return store_null()
}

// xsp_client_put_blob / xsp_client_get_blob — the F1' OPAQUE-document pair
// over the wire (S6, §4.1 put-blob/get-blob rows): raw bytes, byte-exact,
// identity = hash of the bytes as given; get-blob absence crosses the
// embedded surface's CXER1121 VERBATIM.
fn xsp_client_put_blob(rb &RemoteBackend, raw string) cx.Node {
	r, ok := xcl_exchange(rb, 'put-blob', '[put-blob [bytes::bytes 0x${raw.bytes().hex()}]]')
	if !ok || xcl_is_err(r) {
		return r
	}
	if r is cx.Element && r.name == 'put-blob-result' {
		return store_str(sw_attr(r, 'key'))
	}
	return xcl_unreachable('put-blob', 'malformed reply')
}

fn xsp_client_get_blob(rb &RemoteBackend, key string) cx.Node {
	r, ok := xcl_exchange(rb, 'get-blob', '[get-blob key="${sw_msg_esc(key)}"]')
	if !ok || xcl_is_err(r) {
		return r
	}
	if r is cx.Element && r.name == 'blob' {
		b := sx_bytes_child(r, 'bytes') or {
			return xcl_unreachable('get-blob', 'blob reply carries no bytes')
		}
		return store_str(b.bytestr())
	}
	return xcl_unreachable('get-blob', 'malformed reply')
}

fn xsp_client_has(rb &RemoteBackend, hash string) (bool, cx.Node, bool) {
	r, ok := xcl_exchange(rb, 'get', '[get hash="${sw_msg_esc(hash)}"]')
	if !ok || xcl_is_err(r) {
		return false, r, false
	}
	if r is cx.Element {
		re := r as cx.Element
		if re.name == 'erased' {
			return false, store_null(), true // erased ≠ present (§7b.1)
		}
		if re.name == 'doc' {
			return sw_attr(re, 'present') == 'true', store_null(), true
		}
	}
	return false, xcl_unreachable('get', 'malformed reply'), false
}

fn xsp_client_delete(rb &RemoteBackend, hash string) (bool, cx.Node, bool) {
	r, ok := xcl_exchange(rb, 'delete', '[delete hash="${sw_msg_esc(hash)}"]')
	if !ok || xcl_is_err(r) {
		return false, r, false
	}
	if r is cx.Element && r.name == 'delete-result' {
		return sw_attr(r, 'deleted') == 'true', store_null(), true
	}
	return false, xcl_unreachable('delete', 'malformed reply'), false
}

// xsp_client_list streams the daemon's doc-hash catalog ([hash "…"] events).
fn xsp_client_list(rb &RemoteBackend) ([]string, cx.Node, bool) {
	events, errn, ok := xcl_stream(rb, 'list', '[list]')
	if !ok || xcl_is_err(errn) {
		return []string{}, errn, false
	}
	mut out := []string{}
	for ev in events {
		if ev.name == 'hash' {
			for it in ev.items {
				h := sw_scalar(it)
				if store_is_doc_hash(h) {
					out << h
				}
			}
		}
	}
	return out, store_null(), true
}

// xsp_client_query collects the L97 flat-relation tuples from the streamed
// [result doc= source= MATCH] events — the wire frame IS the executor's
// tuple, so the client forwards each event verbatim (no reassembly).
fn xsp_client_query(rb &RemoteBackend, cxpath string) cx.Node {
	events, errn, ok := xcl_stream(rb, 'query', '[query path="${sw_msg_esc(cxpath)}"]')
	if !ok || xcl_is_err(errn) {
		return errn
	}
	mut results := []cx.Node{}
	for ev in events {
		if ev.name != 'result' {
			continue
		}
		results << cx.Node(ev)
	}
	return store_seq(results)
}

// xsp_client_iter reconstructs the local store-iter-docs shape from the
// streamed [doc hash="H" [body::bytes 0x…]] events.
fn xsp_client_iter(rb &RemoteBackend) cx.Node {
	events, errn, ok := xcl_stream(rb, 'iter', '[iter]')
	if !ok || xcl_is_err(errn) {
		return errn
	}
	mut entries := []cx.Node{}
	for ev in events {
		if ev.name != 'doc' {
			continue
		}
		body := sx_bytes_child(ev, 'body') or { continue }
		doc := cx.bin_to_doc(body) or { continue }
		mut inner := []cx.Node{}
		for el in doc.elements {
			inner << el
		}
		entries << cx.Element{
			name:  'entry'
			attrs: [cx.Attribute{
				name:  'hash'
				value: cx.ScalarValue(sw_attr(ev, 'hash'))
			}]
			items: inner
		}
	}
	return store_seq(entries)
}

// xsp_client_admin drives the admin verbs (status/gc are store-level; mounts/
// config-reload are daemon-level and need a DID-proven principal in open mode
// — the refusal rides verbatim). The reply IS the porcelain element.
fn xsp_client_admin(rb &RemoteBackend, op string) cx.Node {
	verb := match op {
		'status' { '[status]' }
		'gc' { '[gc]' }
		'config-reload' { '[config-reload]' }
		else { '[mounts]' }
	}
	r, _ := xcl_exchange(rb, op, verb)
	return r // porcelain element on success; [err]/[deny] verbatim otherwise
}

fn xsp_client_modify(rb &RemoteBackend, hash string, action_text string) cx.Node {
	r, ok := xcl_exchange(rb, 'modify', '[modify hash="${sw_msg_esc(hash)}" [action ${action_text}]]')
	if !ok || xcl_is_err(r) {
		return r
	}
	if r is cx.Element && r.name == 'modify-result' {
		nh := sw_attr(r, 'new-hash')
		if store_is_doc_hash(nh) {
			return store_str(nh)
		}
	}
	return xcl_unreachable('modify', 'malformed reply')
}

// ── the object wire over the profile (the third ObjWireTransport impl) ──────
//
// RemoteObjectBackend speaks the CSRP object-verb bodies (bare-hex h="…" /
// bytes="…" attrs, HTTP-ish statuses). The profile addresses objects with
// varint multihashes (h::bytes=0x…, the crypto-agility bijection) and answers
// typed [err] values. This transport is the adapter: op+body → profile verb,
// reply → CSRP-shaped body + synthesized status (200 ok; the err statuses
// mirror the CSRP route's own mapping so store_objwire_err and the alias/ref
// callers classify identically across all three transports).

fn xcl_mh_of_hex(hex64 string) ?string {
	digest := hex.decode(hex64) or { return none }
	mh := cx.cx_multihash_encode('sha2-256', digest) or { return none }
	return mh.hex()
}

fn xcl_hex_of_mh(img string) ?string {
	if !img.starts_with('0x') {
		return none
	}
	mh := hex.decode(img[2..]) or { return none }
	_, digest := cx.cx_multihash_decode(mh) or { return none }
	return digest.hex()
}

// xcl_ow_status maps a completed exchange's failure value to the HTTP-ish
// status RemoteObjectBackend's callers classify on (store_csrp.v's own wire
// mapping): 1114→409, 1121→404, 1131/deny→403, 1132/4713→429, else 500.
fn xcl_ow_status(errn cx.Node) int {
	if errn is cx.Element && errn.name == 'deny' {
		return 403
	}
	code_s := svc_err_code(errn)
	return match code_s {
		'cx-err:CXER1114' { 409 }
		'cx-err:CXER1121' { 404 }
		'cx-err:CXER1131' { 403 }
		'cx-err:CXER1132', 'cx-err:CXER4713' { 429 }
		else { 500 }
	}
}

struct XspObjWireTransport {
	rb &RemoteBackend
}

fn (t &XspObjWireTransport) send(op string, query string, body string) (int, string, bool) {
	doc := cx.parse(body) or { return 0, 'unparseable object-wire body', false }
	if doc.elements.len == 0 || doc.elements[0] !is cx.Element {
		return 0, 'empty object-wire body', false
	}
	top := doc.elements[0] as cx.Element
	verb := match op {
		'objects-have', 'objects-get' {
			// [have|get [o h="hex"]…] → [<op> [o h::bytes=0x<mh>]…]
			mut sb := '[${op}'
			for it in top.items {
				if it is cx.Element && it.name == 'o' {
					mh := xcl_mh_of_hex(sw_attr(it, 'h')) or {
						return 0, 'bad object hash in ${op}', false
					}
					sb += ' [o h::bytes=0x${mh}]'
				}
			}
			sb + ']'
		}
		'objects-put' {
			// [put [o bytes="hex"]…] → [objects-put [o h::bytes=0x<mh> [bytes::bytes 0x…]]…]
			mut sb := '[objects-put'
			for it in top.items {
				if it is cx.Element && it.name == 'o' {
					pb := hex.decode(sw_attr(it, 'bytes')) or {
						return 0, 'bad object bytes in objects-put', false
					}
					digest := sha256.sum256(pb)
					mh := cx.cx_multihash_encode('sha2-256', digest[..]) or {
						return 0, 'multihash encode failed', false
					}
					sb += ' [o h::bytes=0x${mh.hex()} [bytes::bytes 0x${pb.hex()}]]'
				}
			}
			sb + ']'
		}
		'refs' {
			mut sb := '[refs'
			for it in top.items {
				if it is cx.Element && it.name == 'k' {
					sb += ' [k key="${sw_msg_esc(sw_attr(it, 'key'))}"]'
				}
			}
			sb + ']'
		}
		'refs-set' {
			// [refs-set [r key= root="hex" expect="hex|"]…] → multihash carriage;
			// expect="" (must-not-exist) rides as the empty string attr.
			mut sb := '[refs-set'
			for it in top.items {
				if it is cx.Element && it.name == 'r' {
					mh := xcl_mh_of_hex(sw_attr(it, 'root')) or {
						return 0, 'bad root hash in refs-set', false
					}
					sb += ' [r key="${sw_msg_esc(sw_attr(it, 'key'))}" root::bytes=0x${mh}'
					if sw_has_attr(it, 'expect') {
						exp := sw_attr(it, 'expect')
						if exp == '' {
							sb += ' expect=""'
						} else {
							emh := xcl_mh_of_hex(exp) or {
								return 0, 'bad expect hash in refs-set', false
							}
							sb += ' expect="0x${emh}"'
						}
					}
					sb += ']'
				}
			}
			sb + ']'
		}
		'aliases', 'aliases-set' {
			body // same envelope both sides — the daemon's alias table speaks names+hashes
		}
		'log' {
			// stream 9: the peer-lineage read — same envelope both sides.
			body
		}
		else {
			return 0, 'unknown object-wire op ${op}', false
		}
	}
	r, ok := xcl_exchange(t.rb, op, verb)
	if !ok {
		// transport fault — the error text rides the body slot (#655 posture)
		return 0, render_canonical(r), false
	}
	if xcl_is_err(r) {
		return xcl_ow_status(r), render_canonical(r), true
	}
	// success — translate the reply back to the CSRP-shaped body the
	// RemoteObjectBackend readers consume.
	if r !is cx.Element {
		return 500, '', true
	}
	re := r as cx.Element
	match op {
		'objects-have' {
			// [have-result [o h::bytes=0x…]…] → [missing [o h="hex"]…]
			mut sb := '[missing'
			for it in re.items {
				if it is cx.Element && it.name == 'o' {
					hx := xcl_hex_of_mh(sw_attr(it, 'h')) or { continue }
					sb += ' [o h="${hx}"]'
				}
			}
			return 200, sb + ']', true
		}
		'objects-get' {
			// [get-result [o h::bytes [bytes::bytes 0x…]] | [o … erased=true]]
			//   → [objects [o h="hex" bytes="hex"]…] (absent/erased omitted —
			//     the erased marker means the bytes never cross, §7b.1)
			mut sb := '[objects'
			for it in re.items {
				if it is cx.Element && it.name == 'o' {
					if sw_attr(it, 'erased') == 'true' {
						continue
					}
					hx := xcl_hex_of_mh(sw_attr(it, 'h')) or { continue }
					pb := sx_bytes_child(it, 'bytes') or { continue }
					sb += ' [o h="${hx}" bytes="${pb.hex()}"]'
				}
			}
			return 200, sb + ']', true
		}
		'refs' {
			// [refs-result [r key= present= root::bytes=0x…]…] → [refs [r key= root="hex"]…]
			mut sb := '[refs'
			for it in re.items {
				if it is cx.Element && it.name == 'r' && sw_attr(it, 'present') == 'true' {
					hx := xcl_hex_of_mh(sw_attr(it, 'root')) or { continue }
					sb += ' [r key="${sw_msg_esc(sw_attr(it, 'key'))}" root="${hx}"]'
				}
			}
			return 200, sb + ']', true
		}
		'aliases' {
			return 200, render_canonical(r), true
		}
		else {
			// objects-put / refs-set / aliases-set: the result counters aren't
			// consumed — a clean exchange is the signal.
			return 200, render_canonical(r), true
		}
	}
	return 500, '', true
}

// new_xsp_remote_object_backend builds the cx-store(+xsp):// CLIENT
// object-wire backend — the profile sibling of new_remote_object_backend
// (CSRP) and new_grpc_remote_object_backend (gRPC).
pub fn new_xsp_remote_object_backend(rb &RemoteBackend) &RemoteObjectBackend {
	return &RemoteObjectBackend{
		transport: ObjWireTransport(&XspObjWireTransport{
			rb: rb
		})
	}
}
