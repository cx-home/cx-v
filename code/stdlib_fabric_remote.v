module code

import cx
import sync
import time

// stdlib_fabric_remote.v — the REMOTE tier of the cx-fabric client surface
// (spec/03-approved/xap/fabric.md §15: `[$fabric:open URL|CFG]` → "embedded or
// remote"; issue #531 P3): `[$fabric:open "xsp://host:port" OPTS]` dials a
// `cx fabric-serve` daemon, runs the XSP-AUTH attach (M1–M4, the same
// calculus the served tier's engine tests drive), and returns a `[fabric]`
// handle whose verbs marshal onto the served wire — one client surface,
// two tiers, exactly as store's embedded/remote gradient.
//
// Wire discipline mirrors fabric_service.v verbatim (it is the same
// protocol): the attach phase rides BINARY (data-bin) stream-0 frames — the
// shipped $xsp:auth-* payload shape — and everything after establishment
// rides TEXT frames carrying canonical CX (lossless for event trees).
// Pushed `event` frames buffer client-side per subscription; `receive` is
// the batched pull over that buffer plus a deadline-bounded socket drain —
// so the embedded contract (pull is the primitive, §19.1) holds unchanged
// against a pushing server.
//
// CAPABILITY: the remote tier is NET-gated at the dial (`net-dial` /
// `net-dial-tls` are deny-by-default), the exact posture embedded fabric
// documents — a mem:// journal is capability-free, remote is gated by net.
//
// Authorization is the SERVER's (§11): the client forwards a caller's
// attribution entries verbatim and the daemon enforces the closed
// vocabulary — one enforcement point, never two.
//
// Predicate-fn patterns have no wire form (a fn value has no data-bin or
// canonical-text encoding) — a remote subscribe with one refuses loudly;
// the three data forms (topic atom / terminal-.* glob / head name) render
// as canonical text and travel.
//
// Concurrency: one socket per handle; every verb serializes under the
// handle's mutex for its full request/reply turn (frames read while
// awaiting a reply are routed to the subscription buffers, never dropped).

const fab_err_remote = 'cx-err:CXER4930' // E_FABRIC_REMOTE (dial/wire/timeout/refusal transport faults)

const fab_remote_max_frame = i64(16777216) // parity with the daemon's default max-frame-bytes
const fab_remote_reply_ticks = 10 // reply budget: 10 × 1s read ticks

@[heap]
struct FabricRemote {
mut:
	handle      int
	open        bool
	mu          &sync.Mutex = unsafe { nil }
	net         &NetHandle  = unsafe { nil }
	net_id      int
	url         string
	tenant      string
	principal   string // the attached identity (did, or the server's floor)
	responder   string // the daemon DID auth-finish verified
	next_stream i64
	// pushed-but-not-received entries, per server subscription id — the
	// client half of the §19.2 window (the server stops pushing at its
	// bound; whatever is pushed is buffered here until receive drains it).
	buf map[int][]cx.Node
	// §12.1 request-reply: the responder callables this client registered
	// (per channel label — they NEVER travel; only the registration crossed
	// the wire) and the pushed-but-unserved request frames awaiting a
	// `serve` pump (pull stays the primitive, §19.1).
	responders map[string]cx.Node
	req_buf    []cx.Element
	// xsp.md §5 session state (#560), negotiated at open via the [session]
	// verb: `features` + `liveness_ms` drive the half-window auto-ping in
	// receive's drain loop (§5.1); `sub_windows` records windowed observe
	// subscriptions so receive auto-credits consumption (§5.2);
	// `last_write` is the write-idle clock the ping cadence reads.
	features    string
	liveness_ms i64
	last_write  i64
	sub_windows map[int]int
}

// fab_remote_maybe_ping sends a `ping` when the connection has been
// write-idle for half the negotiated liveness window (xsp.md §5.1) — the
// parked-consumer case: a standby group sibling blocked in receive must
// keep refreshing its liveness or the §19.3 sweeper deposes it. No-op
// before negotiation (an old daemon advertised nothing). Caller holds fr.mu.
fn fab_remote_maybe_ping(mut fr FabricRemote) {
	if fr.liveness_ms <= 0 || !fr.features.contains('heartbeat') {
		return
	}
	now := time.now().unix_milli()
	if now - fr.last_write < fr.liveness_ms / 2 {
		return
	}
	b := fs_frame_bytes('ping', 0, cx.Node(bus_null())) or { return }
	net_h_write(mut fr.net, b) or { return }
	fr.last_write = now
}

// fab_remote_lookup resolves a remote handle id (none = not a remote handle,
// caller falls through to the embedded registry).
fn fab_remote_lookup(id int) ?&FabricRemote {
	reg := fabric_reg()
	return reg.remotes[id] or { return none }
}

fn fab_remote_elem(fr &FabricRemote) cx.Node {
	return cx.Element{
		name:  'fabric'
		attrs: [
			bus_attr_int('handle', fr.handle),
			bus_attr('state', if fr.open { 'open' } else { 'closed' }),
			bus_attr('remote', fr.url),
			bus_attr('tenant', fr.tenant),
			bus_attr('responder', fr.responder),
			bus_attr('on-close', 'fabric/close'),
		]
	}
}

// ── open (dial + XSP-AUTH attach) ─────────────────────────────────────────

// fab_remote_url_is_remote reports whether an open target is the remote form.
fn fab_remote_url_is_remote(s string) bool {
	return s.starts_with('xsp://') || s.starts_with('xsps://')
}

// fabric_open_remote dials the daemon and attaches. OPTS (a map):
//   tenant     required — the mount to attach (§19.4 structural partition)
//   did, seed  the client identity (Ed25519 seed bytes); absent = anonymous
//              (admitted only by a floor-policy daemon)
//   responder  optional expected daemon DID — auth-finish always verifies the
//              responder's transcript signature; this additionally pins WHO
//   tls        optional map forwarded to the net dial (xsps:// form)
fn fabric_open_remote(url string, opts cx.Node) cx.Node {
	tenant := bus_map_value(opts, 'tenant') or {
		return mk_err(fab_err_arg_invalid,
			'E_FABRIC_ARG_INVALID: remote open needs opts.tenant (the mount to attach)')
	}
	tenant_s := bus_plain_string(tenant) or {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: opts.tenant must be a string')
	}
	// scheme → transport (net's dial is the capability gate)
	mut dial_name := 'net-dial'
	mut dial_url := ''
	if url.starts_with('xsp://') {
		dial_url = 'tcp://' + url['xsp://'.len..]
	} else {
		dial_name = 'net-dial-tls'
		dial_url = 'tls://' + url['xsps://'.len..]
	}
	mut dial_args := [cx.Node(bus_str(dial_url))]
	if tls_opts := bus_map_value(opts, 'tls') {
		dial_args << cx.Node(cx.Element{
			name:  map_marker_name
			items: [session_kv('tls', tls_opts)]
		})
	}
	sock := net_dial_impl(dial_name, dial_args)
	if is_err_value(sock) {
		return sock // CXER0271 net denial / dial fault, verbatim
	}
	net_id := net_handle_id(sock) or {
		return mk_err(fab_err_remote, 'E_FABRIC_REMOTE: dial returned no socket handle')
	}
	mut h := net_mut_handle(sock) or {
		return mk_err(fab_err_remote, 'E_FABRIC_REMOTE: dial returned no socket handle')
	}
	h.read_deadline_ms = 1000

	// M1: fresh nonce + X25519 ephemeral; identity from opts (or anonymous).
	nonce := crypto_random_octets(32) or {
		net_close_id(net_id)
		return mk_err(fab_err_remote, 'E_FABRIC_REMOTE: entropy unavailable')
	}
	eph_priv := crypto_random_octets(32) or {
		net_close_id(net_id)
		return mk_err(fab_err_remote, 'E_FABRIC_REMOTE: entropy unavailable')
	}
	mut sk := eph_priv.clone()
	x25519_clamp(mut sk)
	eph_pub := x25519_scalar_base_mult(sk)
	mut did := ''
	mut seed := []u8{}
	if v := bus_map_value(opts, 'did') {
		did = bus_plain_string(v) or { '' }
	}
	if v := bus_map_value(opts, 'seed') {
		seed = arg_bytes(v) or { []u8{} }
	}
	if (did == '') != (seed.len == 0) {
		net_close_id(net_id)
		return mk_err(fab_err_arg_invalid,
			'E_FABRIC_ARG_INVALID: remote open needs BOTH opts.did and opts.seed, or neither (anonymous)')
	}
	mut hello_items := [
		session_kv('nonce', bytes_node(nonce)),
		session_kv('eph', bytes_node(eph_pub)),
		session_kv('endpoint', crypto_string_node(url)),
	]
	if did != '' {
		hello_items << session_kv('did', crypto_string_node(did))
	}
	m1 := xsp_auth_stdlib_builtin('xsp-auth-hello', [
		cx.Node(cx.Element{
			name:  map_marker_name
			items: hello_items
		}),
	]) or {
		net_close_id(net_id)
		return mk_err(fab_err_remote, 'E_FABRIC_REMOTE: auth-hello unavailable')
	}
	if is_err_value(m1) {
		net_close_id(net_id)
		return m1
	}
	m2 := fab_remote_attach_turn(mut h, net_id, m1) or { return err_from_attach(net_id) }
	if is_err_value(m2) {
		net_close_id(net_id)
		return m2
	}
	// M3: prove (+ the attach request naming the tenant), anonymous when no key.
	mut prove_items := [
		session_kv('eph-priv', bytes_node(eph_priv)),
		session_kv('attach', cx.Node(cx.Element{
			name:  'attach'
			items: [
				cx.Node(cx.Element{
					name:  'tenant'
					items: [cx.Node(bus_str(tenant_s))]
				}),
				cx.Node(cx.Element{
					name:  'session'
					items: [cx.Node(bus_str('mirror'))]
				}),
			]
		})),
	]
	if seed.len > 0 {
		prove_items << session_kv('key', bytes_node(seed))
	}
	m3 := xsp_auth_stdlib_builtin('xsp-auth-prove', [m1, m2,
		cx.Node(cx.Element{
			name:  map_marker_name
			items: prove_items
		})]) or {
		net_close_id(net_id)
		return mk_err(fab_err_remote, 'E_FABRIC_REMOTE: auth-prove unavailable')
	}
	if is_err_value(m3) {
		net_close_id(net_id)
		return m3
	}
	m4 := fab_remote_attach_turn(mut h, net_id, m3) or { return err_from_attach(net_id) }
	if is_err_value(m4) {
		// the daemon's refusal (ANONYMOUS-REFUSED / TENANT / …), verbatim.
		net_close_id(net_id)
		return m4
	}
	// client-side proof the handshake established: auth-finish verifies the
	// responder transcript signature and key confirmation — never skipped.
	done := xsp_auth_stdlib_builtin('xsp-auth-finish', [m1, m2, m4,
		cx.Node(cx.Element{
			name:  map_marker_name
			items: [session_kv('eph-priv', bytes_node(eph_priv))]
		})]) or {
		net_close_id(net_id)
		return mk_err(fab_err_remote, 'E_FABRIC_REMOTE: auth-finish unavailable')
	}
	if is_err_value(done) {
		net_close_id(net_id)
		return done
	}
	mut responder := ''
	if done is cx.Element {
		responder = xap_elem_attr(done, 'responder')
	}
	if v := bus_map_value(opts, 'responder') {
		want := bus_plain_string(v) or { '' }
		if want != '' && want != responder {
			net_close_id(net_id)
			return mk_err(fab_err_remote,
				'E_FABRIC_REMOTE: daemon identity "${responder}" is not the pinned responder "${want}"')
		}
	}
	mut reg := fabric_reg()
	reg.next_id++
	mut fr := &FabricRemote{
		handle:    reg.next_id
		open:      true
		mu:        sync.new_mutex()
		net:       h
		net_id:    net_id
		url:       url
		tenant:    tenant_s
		principal:  if did != '' { did } else { 'anonymous' }
		responder:  responder
		buf:        map[int][]cx.Node{}
		responders: map[string]cx.Node{}
	}
	reg.remotes[fr.handle] = fr
	// xsp.md §5.0 (#560): feature negotiation is a post-attach session
	// query — never a mutation of the graduated XSP-AUTH M4 shape. An
	// older daemon answers with the unknown-verb refusal, which is
	// tolerated: features stay empty and this client simply neither
	// heartbeats nor credits (the pre-§5 posture, wire-compatible).
	fr.mu.lock()
	sres := fab_remote_request(mut fr, cx.Node(cx.Element{ name: 'session' }))
	if sres is cx.Element {
		if sres.name == 'fabric-session' {
			fr.features = sres.attr('features')
			fr.liveness_ms = sres.attr('liveness-ms').i64()
		}
	}
	fr.last_write = time.now().unix_milli()
	fr.mu.unlock()
	return fab_remote_elem(fr)
}

fn err_from_attach(net_id int) cx.Node {
	net_close_id(net_id)
	return mk_err(fab_err_remote, 'E_FABRIC_REMOTE: connection lost during attach')
}

// fab_remote_attach_turn sends one handshake message as a BINARY stream-0
// request frame and returns the reply/error payload element.
fn fab_remote_attach_turn(mut h NetHandle, net_id int, msg cx.Node) ?cx.Node {
	b := fs_frame_bytes_bin('request', 0, msg) or {
		return mk_err(fab_err_remote, 'E_FABRIC_REMOTE: frame encode failed')
	}
	net_h_write(mut h, b) or { return none }
	mut ticks := 0
	for ticks < fab_remote_reply_ticks {
		st, raw := fs_read_frame(mut h, fab_remote_max_frame)
		match st {
			.idle {
				ticks++
				continue
			}
			.closed {
				return none
			}
			.frame {
				fe_node := xsp_decode_at(raw, 0)
				if fe_node !is cx.Element {
					return none
				}
				fe := fe_node as cx.Element
				payload := xsp_payload_value(fe) or { continue }
				ftype := xap_elem_attr(fe, 'type')
				if ftype == 'reply' {
					return payload
				}
				if ftype == 'error' {
					if payload is cx.Element {
						return cx.Node(payload)
					}
					return mk_err(fab_err_remote, 'E_FABRIC_REMOTE: attach refused')
				}
				// anything else during attach is out of protocol — keep reading
			}
		}
	}
	return mk_err(fab_err_remote, 'E_FABRIC_REMOTE: attach reply timeout')
}

// ── wire turns (established channel, text frames) ─────────────────────────

// fab_remote_parse_payload maps a TEXT frame payload back to a node: one
// parsed element, the empty node-set for `()` absence, or a scalar (`null`).
fn fab_remote_parse_payload(fe cx.Element) cx.Node {
	payload := xsp_payload_value(fe) or { return bus_null() }
	text := arg_string(payload) or { return payload }
	parsed := cx.parse(text) or {
		return mk_err(fab_err_remote, 'E_FABRIC_REMOTE: unparseable reply payload: ${err.msg()}')
	}
	if parsed.elements.len == 0 {
		return bus_empty()
	}
	return parsed.elements[0]
}

// fab_remote_route_event buffers a pushed frame under its subscription id.
fn fab_remote_route_event(mut fr FabricRemote, fe cx.Element) {
	sid := int(xap_elem_attr(fe, 'stream').i64())
	entry := fab_remote_parse_payload(fe)
	if entry is cx.SequenceNode {
		return
	}
	mut lst := fr.buf[sid] or { []cx.Node{} }
	lst << entry
	fr.buf[sid] = lst
}

// fab_remote_request performs one verb turn: send the request as a text
// frame, pump frames until ITS reply/error arrives (events and pushed
// request frames buffer, never drop), and return the parsed payload.
// Caller holds fr.mu.
fn fab_remote_request(mut fr FabricRemote, verb cx.Node) cx.Node {
	return fab_remote_request_deadline(mut fr, verb, i64(fab_remote_reply_ticks) * 1000)
}

// fab_remote_request_deadline is the deadline-parameterized turn — the §12.1
// `request` verb passes the caller's deadline; every other verb uses the
// fixed reply budget. A lapsed deadline is the request-timeout refusal.
fn fab_remote_request_deadline(mut fr FabricRemote, verb cx.Node, deadline_ms i64) cx.Node {
	if !fr.open {
		return mk_err(fab_err_handle, 'E_FABRIC_HANDLE: operation on a closed fabric')
	}
	tr := fab_trace_on()
	mut vname := ''
	if tr {
		if verb is cx.Element {
			vname = verb.name
		}
	}
	t0 := time.sys_mono_now()
	fr.next_stream++
	sid := fr.next_stream
	b := fs_frame_bytes('request', sid, verb) or {
		return mk_err(fab_err_remote, 'E_FABRIC_REMOTE: frame encode failed')
	}
	t_encoded := time.sys_mono_now()
	net_h_write(mut fr.net, b) or {
		fab_remote_teardown(mut fr)
		return mk_err(fab_err_remote, 'E_FABRIC_REMOTE: connection lost (write)')
	}
	t_written := time.sys_mono_now()
	write_wall := if tr { fab_trace_wall_us() } else { i64(0) }
	fr.last_write = time.now().unix_milli()
	started := time.now().unix_milli()
	for time.now().unix_milli() - started < deadline_ms {
		st, raw := fs_read_frame(mut fr.net, fab_remote_max_frame)
		match st {
			.idle {
				continue
			}
			.closed {
				fab_remote_teardown(mut fr)
				return mk_err(fab_err_remote, 'E_FABRIC_REMOTE: connection lost (read)')
			}
			.frame {
				fe_node := xsp_decode_at(raw, 0)
				if fe_node !is cx.Element {
					continue
				}
				fe := fe_node as cx.Element
				ftype := xap_elem_attr(fe, 'type')
				fstream := xap_elem_attr(fe, 'stream').i64()
				match ftype {
					'event' {
						fab_remote_route_event(mut fr, fe)
					}
					'request' {
						fr.req_buf << fe // a pushed §12.1 call: served on the next serve pump
					}
					'reply', 'error' {
						if fstream == sid {
							if tr {
								t_frame := time.sys_mono_now()
								frame_wall := fab_trace_wall_us()
								out := fab_remote_parse_payload(fe)
								eprintln('[fab-trace side=client verb=${vname} sid=${sid} req-bytes=${b.len} reply-bytes=${raw.len} write-wall-us=${write_wall} reply-wall-us=${frame_wall} encode-us=${(t_encoded - t0) / 1000} write-us=${(t_written - t_encoded) / 1000} wait-us=${(t_frame - t_written) / 1000} parse-us=${(time.sys_mono_now() - t_frame) / 1000}]')
								return out
							}
							return fab_remote_parse_payload(fe)
						}
					}
					else {}
				}
			}
		}
	}
	return mk_err(fab_err_req_timeout, 'E_FABRIC_REQUEST_TIMEOUT: no reply within ${deadline_ms} ms')
}

fn fab_remote_teardown(mut fr FabricRemote) {
	if !fr.open {
		return
	}
	fr.open = false
	net_close_id(fr.net_id)
}

// ── remote verb implementations ───────────────────────────────────────────

// fab_publish_verb builds the wire [publish stream=… [event …] [attribution …]]
// verb — attribution entries forward VERBATIM (the daemon owns the closed
// vocabulary, §11, and refuses loudly; one enforcement point, not two).
fn fab_publish_verb(stream string, event cx.Node, att cx.Node) cx.Node {
	mut items := [
		cx.Node(cx.Element{
			name:  'event'
			items: [event]
		}),
	]
	if entries := bus_map_entries(att) {
		if entries.len > 0 {
			items << cx.Node(cx.Element{
				name:  'attribution'
				items: entries
			})
		}
	}
	return cx.Element{
		name:  'publish'
		attrs: [bus_attr('stream', stream)]
		items: items
	}
}

fn fab_remote_publish(mut fr FabricRemote, args []cx.Node) cx.Node {
	if args.len < 3 {
		return mk_err(fab_err_arg_invalid,
			'E_FABRIC_ARG_INVALID: publish expects ($fabric, $stream, $event, $attribution)')
	}
	stream := fab_arg_string(args[1]) or {
		return mk_err(fab_err_arg_invalid,
			'E_FABRIC_ARG_INVALID: stream must be a non-empty string')
	}
	if args[2] !is cx.Element {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: event must be an element')
	}
	att := if args.len > 3 { args[3] } else { cx.Node(cx.Element{ name: map_marker_name }) }
	verb := fab_publish_verb(stream, args[2], att)
	fr.mu.lock()
	defer {
		fr.mu.unlock()
	}
	return fab_remote_request(mut fr, verb)
}

// fab_remote_publish_pipeline appends N events to one stream, preferring
// the negotiated `publish-batch` frame (#607: ONE request, ONE
// receipt-batch, atomic validation) and falling back to the #593
// send-all-then-collect pipeline — against daemons that predate the
// feature, when per-event attributions differ (the batch frame carries
// one), or to ISOLATE a poison event after a batch-validation refusal.
// Returns one receipt-or-err per event, in order; per-event fail-closed.
fn fab_remote_publish_pipeline(mut fr FabricRemote, stream string, events []cx.Node, atts []cx.Node) []cx.Node {
	if events.len > 1 && fr.features.contains('publish-batch') && fab_atts_uniform_empty(atts) {
		out, decided := fab_remote_publish_batch_frame(mut fr, stream, events)
		if decided {
			return out
		}
		// validation refusal: retry as pipelined singles so a poison event
		// refuses alone and its batch-mates land (§3.1.2 skip-and-ack).
	}
	return fab_remote_publish_pipelined(mut fr, stream, events, atts)
}

// fab_atts_uniform_empty reports whether every attribution map is empty —
// the served-tier norm (the session principal commits; a claimed actor
// refuses, §4.8), and the precondition for the single-attribution batch
// frame.
fn fab_atts_uniform_empty(atts []cx.Node) bool {
	for a in atts {
		if entries := bus_map_entries(a) {
			if entries.len > 0 {
				return false
			}
		}
	}
	return true
}

// fab_remote_publish_batch_frame sends ONE [publish-batch …] verb and maps
// the reply onto per-event receipts. decided=false means the caller should
// isolate via the pipelined path (a batch-validation refusal — nothing
// appended). An append-time FAULT reply carries landed=k (+first=F): the
// stream holds exactly k entries of this batch, so the first k get
// synthesized receipts and the rest carry the fault (fold exactly the
// truth, §3.1.1).
fn fab_remote_publish_batch_frame(mut fr FabricRemote, stream string, events []cx.Node) ([]cx.Node, bool) {
	mut items := []cx.Node{cap: events.len}
	for ev in events {
		items << cx.Node(cx.Element{
			name:  'event'
			items: [ev]
		})
	}
	verb := cx.Node(cx.Element{
		name:  'publish-batch'
		attrs: [bus_attr('stream', stream)]
		items: items
	})
	fr.mu.lock()
	r := fab_remote_request(mut fr, verb)
	fr.mu.unlock()
	mut out := []cx.Node{len: events.len, init: cx.Node(cx.Element{})}
	if r is cx.Element {
		if r.name == 'receipt-batch' {
			first := r.attr('first').i64()
			for i in 0 .. events.len {
				out[i] = cx.Element{
					name:  'receipt'
					attrs: [
						bus_attr_int('seq', first + i64(i)),
						bus_attr('stream', stream),
					]
				}
			}
			return out, true
		}
		if is_err_value(cx.Node(r)) {
			if r.has_attr('landed') {
				landed := int(r.attr('landed').i64())
				first := r.attr('first').i64()
				for i in 0 .. events.len {
					if i < landed {
						out[i] = cx.Element{
							name:  'receipt'
							attrs: [
								bus_attr_int('seq', first + i64(i)),
								bus_attr('stream', stream),
							]
						}
					} else {
						out[i] = cx.Node(r)
					}
				}
				return out, true
			}
			// validation refusal — nothing appended; isolate via singles.
			return out, false
		}
	}
	// unrecognized reply shape: fall back to singles (fail-safe).
	return out, false
}

// fab_remote_publish_pipelined is the #593 send-all-then-collect lane:
// every publish frame is sent BEFORE any reply is read, then the replies
// collect by stream id — the connection is a single ordered channel, so
// receipts arrive in send order (out-of-band event/request frames buffer
// exactly as in fab_remote_request_deadline, never drop).
fn fab_remote_publish_pipelined(mut fr FabricRemote, stream string, events []cx.Node, atts []cx.Node) []cx.Node {
	mut out := []cx.Node{len: events.len, init: cx.Node(cx.Element{})}
	fr.mu.lock()
	defer {
		fr.mu.unlock()
	}
	if !fr.open {
		for i in 0 .. events.len {
			out[i] = mk_err(fab_err_handle, 'E_FABRIC_HANDLE: operation on a closed fabric')
		}
		return out
	}
	// send phase — all frames before any read.
	mut sids := []i64{len: events.len, init: i64(-1)}
	for i, ev in events {
		verb := fab_publish_verb(stream, ev, atts[i])
		fr.next_stream++
		sid := fr.next_stream
		b := fs_frame_bytes('request', sid, verb) or {
			out[i] = mk_err(fab_err_remote, 'E_FABRIC_REMOTE: frame encode failed')
			continue
		}
		net_h_write(mut fr.net, b) or {
			fab_remote_teardown(mut fr)
			for j := 0; j < events.len; j++ {
				if j == i || sids[j] >= 0 {
					out[j] = mk_err(fab_err_remote, 'E_FABRIC_REMOTE: connection lost (write)')
					sids[j] = -1
				}
			}
			return out
		}
		sids[i] = sid
	}
	fr.last_write = time.now().unix_milli()
	// collect phase — replies match by stream id; a generous per-batch
	// budget (the fixed reply budget + 50ms per frame) bounds a silent peer.
	mut pending := map[i64]int{}
	for i, sid in sids {
		if sid >= 0 {
			pending[sid] = i
		}
	}
	started := time.now().unix_milli()
	deadline := i64(fab_remote_reply_ticks) * 1000 + i64(events.len) * 50
	for pending.len > 0 && time.now().unix_milli() - started < deadline {
		st, raw := fs_read_frame(mut fr.net, fab_remote_max_frame)
		match st {
			.idle {
				continue
			}
			.closed {
				fab_remote_teardown(mut fr)
				for _, idx in pending {
					out[idx] = mk_err(fab_err_remote, 'E_FABRIC_REMOTE: connection lost (read)')
				}
				return out
			}
			.frame {
				fe_node := xsp_decode_at(raw, 0)
				if fe_node !is cx.Element {
					continue
				}
				fe := fe_node as cx.Element
				ftype := xap_elem_attr(fe, 'type')
				fstream := xap_elem_attr(fe, 'stream').i64()
				match ftype {
					'event' {
						fab_remote_route_event(mut fr, fe)
					}
					'request' {
						fr.req_buf << fe
					}
					'reply', 'error' {
						if idx := pending[fstream] {
							out[idx] = fab_remote_parse_payload(fe)
							pending.delete(fstream)
						}
					}
					else {}
				}
			}
		}
	}
	for _, idx in pending {
		out[idx] = mk_err(fab_err_req_timeout, 'E_FABRIC_REQUEST_TIMEOUT: no publish receipt within the batch budget')
	}
	return out
}

fn fab_remote_subscribe(mut fr FabricRemote, args []cx.Node, observe bool) cx.Node {
	if args.len < 3 {
		verb := if observe { 'observe' } else { 'subscribe' }
		return mk_err(fab_err_arg_invalid,
			'E_FABRIC_ARG_INVALID: ${verb} expects ($fabric, $stream, $pattern)')
	}
	stream := fab_arg_string(args[1]) or {
		return mk_err(fab_err_arg_invalid,
			'E_FABRIC_ARG_INVALID: stream must be a non-empty string')
	}
	pat, perr, pok := bus_compile_pattern(args[2])
	if !pok {
		return perr
	}
	if pat.kind == .pred {
		return mk_err(fab_err_arg_invalid,
			'E_FABRIC_ARG_INVALID: a predicate-fn pattern has no wire form — remote subscriptions carry the data forms (topic atom / terminal-.* glob / head name); apply predicates over the received entries')
	}
	mut attrs := [bus_attr('stream', stream)]
	mut window := 0
	if args.len > 3 {
		opts := args[3]
		if _ := bus_map_entries(opts) {
			if !observe {
				if v := bus_map_value(opts, 'group') {
					if s := fab_arg_string(v) {
						attrs << bus_attr('group', s)
					}
				}
				// §9.1 policy keys forward verbatim — the daemon owns validation,
				// grant checks, and group-state reconciliation (one enforcement
				// point, never two).
				if v := bus_map_value(opts, 'max-deliveries') {
					if iv := fab_arg_int(v) {
						attrs << bus_attr_int('max-deliveries', iv)
					}
				}
				if v := bus_map_value(opts, 'dlq') {
					if s := fab_arg_string(v) {
						attrs << bus_attr('dlq', s)
					}
				}
			}
			// `from` is the §5.3 explicit resume cursor — observe-mode
			// re-subscribes with its last processed seq + 1 (the daemon
			// refuses it on group subs, where the committed offset rules).
			if v := bus_map_value(opts, 'from') {
				if iv := fab_arg_int(v) {
					attrs << bus_attr_int('from', iv)
				}
			}
			// `window` is the §5.2 credit window declaration; forwarded
			// verbatim (the daemon clamps to its pending-window ceiling).
			if v := bus_map_value(opts, 'window') {
				if iv := fab_arg_int(v) {
					window = int(iv)
					attrs << bus_attr_int('window', iv)
				}
			}
		}
	}
	verb := cx.Node(cx.Element{
		name:  if observe { 'observe' } else { 'subscribe' }
		attrs: attrs
		items: [
			cx.Node(cx.Element{
				name:  'pattern'
				items: [args[2]]
			}),
		]
	})
	fr.mu.lock()
	defer {
		fr.mu.unlock()
	}
	r := fab_remote_request(mut fr, verb)
	if is_err_value(r) {
		return r
	}
	// rewrap: the daemon's [fabric-sub id=…] gains this handle's handle= so
	// the one client surface routes receive/ack back here.
	if r is cx.Element {
		if r.name == 'fabric-sub' {
			// a windowed observe sub auto-credits from receive (§5.2) —
			// record it, but only when the daemon negotiated `credit`.
			if observe && window > 0 && fr.features.contains('credit') {
				fr.sub_windows[int(r.attr('id').i64())] = window
			}
			mut out_attrs := [bus_attr_int('handle', fr.handle)]
			out_attrs << r.attrs
			return cx.Element{
				name:  'fabric-sub'
				attrs: out_attrs
			}
		}
	}
	return r
}

fn fab_remote_receive(mut fr FabricRemote, args []cx.Node) cx.Node {
	sid := fab_sub_id_of(args[0]) or {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: not a [fabric-sub] handle')
	}
	mut max := i64(-1)
	mut deadline_ms := i64(0)
	if args.len > 1 {
		opts := args[1]
		if _ := bus_map_entries(opts) {
			if v := bus_map_value(opts, 'max') {
				if iv := fab_arg_int(v) {
					if iv < 1 {
						return mk_err(fab_err_arg_invalid,
							'E_FABRIC_ARG_INVALID: max must be a positive int')
					}
					max = iv
				}
			}
			if v := bus_map_value(opts, 'deadline') {
				if iv := fab_arg_int(v) {
					if iv < 0 {
						return mk_err(fab_err_arg_invalid,
							'E_FABRIC_ARG_INVALID: deadline must be ≥ 0 (ms)')
					}
					deadline_ms = iv
				}
			}
		}
	}
	fr.mu.lock()
	defer {
		fr.mu.unlock()
	}
	if !fr.open {
		return mk_err(fab_err_handle, 'E_FABRIC_HANDLE: operation on a closed fabric')
	}
	mut out := []cx.Node{}
	fab_remote_drain_buf(mut fr, sid, max, mut out)
	started := time.now().unix_milli()
	// deadline-bounded socket drain: pushed frames land in buffers; stop on
	// a quiet socket once something arrived, on max, or on the deadline.
	for (max < 0 || i64(out.len) < max) && time.now().unix_milli() - started < deadline_ms {
		st, raw := fs_read_frame(mut fr.net, fab_remote_max_frame)
		match st {
			.idle {
				if out.len > 0 {
					break
				}
				// §5.1: the parked consumer heartbeats at half the liveness
				// window so its group assignment survives the sweeper.
				fab_remote_maybe_ping(mut fr)
			}
			.closed {
				fab_remote_teardown(mut fr)
				break
			}
			.frame {
				fe_node := xsp_decode_at(raw, 0)
				if fe_node is cx.Element {
					fe := fe_node as cx.Element
					ft := xap_elem_attr(fe, 'type')
					if ft == 'event' {
						fab_remote_route_event(mut fr, fe)
					} else if ft == 'request' {
						fr.req_buf << fe // §12.1 push: served on the next serve pump
					}
				}
				fab_remote_drain_buf(mut fr, sid, max, mut out)
			}
		}
	}
	// windowed observe (§5.2): consumption IS the replenishment — grant one
	// credit per entry handed to the app, so the server's balance tracks
	// what the application has actually taken (never the socket buffer).
	if out.len > 0 && sid in fr.sub_windows {
		// binary frame: the credit payload is a data-bin integer (§5.2).
		if b := fs_frame_bytes_bin('credit', i64(sid), cx.Node(bus_int(i64(out.len)))) {
			net_h_write(mut fr.net, b) or {}
			fr.last_write = time.now().unix_milli()
		}
	}
	if out.len == 0 {
		return bus_empty()
	}
	return bus_seq(out)
}

fn fab_remote_drain_buf(mut fr FabricRemote, sid int, max i64, mut out []cx.Node) {
	mut lst := fr.buf[sid] or { return }
	for lst.len > 0 && (max < 0 || i64(out.len) < max) {
		out << lst[0]
		lst = lst[1..].clone()
	}
	if lst.len == 0 {
		fr.buf.delete(sid)
	} else {
		fr.buf[sid] = lst
	}
}

fn fab_remote_ack(mut fr FabricRemote, args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: ack expects ($sub, $seq)')
	}
	sid := fab_sub_id_of(args[0]) or {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: not a [fabric-sub] handle')
	}
	seq := fab_arg_int(args[1]) or {
		return mk_err(fab_err_offset, 'E_FABRIC_OFFSET: ack seq must be an int')
	}
	verb := cx.Node(cx.Element{
		name:  'ack'
		attrs: [bus_attr_int('sub', sid), bus_attr_int('seq', seq)]
	})
	fr.mu.lock()
	defer {
		fr.mu.unlock()
	}
	return fab_remote_request(mut fr, verb)
}

fn fab_remote_emit(mut fr FabricRemote, args []cx.Node) cx.Node {
	if args.len < 3 {
		return mk_err(fab_err_arg_invalid,
			'E_FABRIC_ARG_INVALID: emit expects ($fabric, $channel, $value)')
	}
	channel := fab_arg_string(args[1]) or {
		return mk_err(fab_err_arg_invalid,
			'E_FABRIC_ARG_INVALID: channel must be a non-empty string')
	}
	verb := cx.Node(cx.Element{
		name:  'emit'
		attrs: [bus_attr('channel', channel)]
		items: [
			cx.Node(cx.Element{
				name:  'value'
				items: [args[2]]
			}),
		]
	})
	fr.mu.lock()
	defer {
		fr.mu.unlock()
	}
	return fab_remote_request(mut fr, verb)
}

fn fab_remote_read(mut fr FabricRemote, args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: read expects ($fabric, $channel)')
	}
	channel := fab_arg_string(args[1]) or {
		return mk_err(fab_err_arg_invalid,
			'E_FABRIC_ARG_INVALID: channel must be a non-empty string')
	}
	verb := cx.Node(cx.Element{
		name:  'read'
		attrs: [bus_attr('channel', channel)]
	})
	fr.mu.lock()
	defer {
		fr.mu.unlock()
	}
	return fab_remote_request(mut fr, verb)
}

fn fab_remote_close(mut fr FabricRemote) cx.Node {
	fr.mu.lock()
	defer {
		fr.mu.unlock()
	}
	fab_remote_teardown(mut fr)
	fr.buf = map[int][]cx.Node{}
	fr.responders = map[string]cx.Node{}
	fr.req_buf = []cx.Element{}
	return bus_null()
}

// ── §12.1 request-reply (remote tier) ─────────────────────────────────────

// fab_remote_respond registers this client as the channel's responder: the
// registration crosses the wire (the daemon enforces grants + exclusivity),
// the callable stays HERE — applied by the serve pump.
fn fab_remote_respond(mut fr FabricRemote, args []cx.Node) cx.Node {
	if args.len < 3 {
		return mk_err(fab_err_arg_invalid,
			'E_FABRIC_ARG_INVALID: respond expects ($fabric, $channel, $fn)')
	}
	channel := fab_arg_string(args[1]) or {
		return mk_err(fab_err_arg_invalid,
			'E_FABRIC_ARG_INVALID: channel must be a non-empty string')
	}
	if !is_fn_value(args[2]) {
		return mk_err(fab_err_arg_invalid,
			'E_FABRIC_ARG_INVALID: responder must be a callable (an arity-1 fn over the request value)')
	}
	verb := cx.Node(cx.Element{
		name:  'respond'
		attrs: [bus_attr('channel', channel)]
	})
	fr.mu.lock()
	defer {
		fr.mu.unlock()
	}
	r := fab_remote_request(mut fr, verb)
	if is_err_value(r) {
		return r
	}
	if r is cx.Element {
		if r.name == 'fabric-responder' {
			fr.responders[channel] = args[2]
			mut out_attrs := [bus_attr_int('handle', fr.handle)]
			out_attrs << r.attrs
			return cx.Element{
				name:  'fabric-responder'
				attrs: out_attrs
			}
		}
	}
	return r
}

// fab_remote_request_call is the blocking §12.1 call: one wire turn whose
// reply is the responder's answer, deadline-bounded (default 10 000 ms).
fn fab_remote_request_call(mut fr FabricRemote, args []cx.Node) cx.Node {
	if args.len < 3 {
		return mk_err(fab_err_arg_invalid,
			'E_FABRIC_ARG_INVALID: request expects ($fabric, $channel, $value)')
	}
	channel := fab_arg_string(args[1]) or {
		return mk_err(fab_err_arg_invalid,
			'E_FABRIC_ARG_INVALID: channel must be a non-empty string')
	}
	mut deadline_ms := i64(10000)
	if args.len > 3 {
		opts := args[3]
		if _ := bus_map_entries(opts) {
			if v := bus_map_value(opts, 'deadline') {
				iv := fab_arg_int(v) or {
					return mk_err(fab_err_arg_invalid,
						'E_FABRIC_ARG_INVALID: deadline must be ≥ 0 (ms)')
				}
				if iv < 0 {
					return mk_err(fab_err_arg_invalid,
						'E_FABRIC_ARG_INVALID: deadline must be ≥ 0 (ms)')
				}
				deadline_ms = iv
			}
		}
	}
	verb := cx.Node(cx.Element{
		name:  'request'
		attrs: [bus_attr('channel', channel)]
		items: [
			cx.Node(cx.Element{
				name:  'value'
				items: [args[2]]
			}),
		]
	})
	fr.mu.lock()
	defer {
		fr.mu.unlock()
	}
	return fab_remote_request_deadline(mut fr, verb, deadline_ms)
}

// fab_remote_answer_one applies the registered callable to one pushed
// request frame and sends the reply/error frame back (stream-id = the
// server's correlation id). A raised or returned err value travels as an
// `error` frame — the requester receives it verbatim.
fn fab_remote_answer_one(mut fr FabricRemote, fe cx.Element, mut env MatchEnv) {
	corr := xap_elem_attr(fe, 'stream').i64()
	req := fab_remote_parse_payload(fe)
	mut channel := ''
	mut value := cx.Node(bus_null())
	if req is cx.Element {
		if req.name == 'fabric-request' {
			channel = req.attr('channel')
			for it in req.items {
				if it is cx.Element && it.name == 'value' && it.items.len > 0 {
					value = it.items[0]
				}
			}
		}
	}
	fv := fr.responders[channel] or {
		b := fs_frame_bytes('error', corr, mk_err(fab_err_no_responder,
			'E_FABRIC_NO_RESPONDER: no callable registered for channel "${channel}" on this client')) or {
			return
		}
		net_h_write(mut fr.net, b) or { fab_remote_teardown(mut fr) }
		return
	}
	result := apply_fn_value(fv, [value], mut env) or { bus_err_value_of(err) }
	ftype := if is_err_value(result) { 'error' } else { 'reply' }
	b := fs_frame_bytes(ftype, corr, result) or { return }
	net_h_write(mut fr.net, b) or { fab_remote_teardown(mut fr) }
}

// fab_remote_serve is the responder's pump (§12.1/§19.1 — pull stays the
// primitive): drain buffered request frames, apply the callable, answer;
// then keep draining the socket until the deadline/max. Returns the count
// of calls answered.
fn fab_remote_serve(mut fr FabricRemote, args []cx.Node, mut env MatchEnv) cx.Node {
	mut max := i64(-1)
	mut deadline_ms := i64(0)
	if args.len > 1 {
		opts := args[1]
		if _ := bus_map_entries(opts) {
			if v := bus_map_value(opts, 'max') {
				iv := fab_arg_int(v) or {
					return mk_err(fab_err_arg_invalid,
						'E_FABRIC_ARG_INVALID: max must be a positive int')
				}
				if iv < 1 {
					return mk_err(fab_err_arg_invalid,
						'E_FABRIC_ARG_INVALID: max must be a positive int')
				}
				max = iv
			}
			if v := bus_map_value(opts, 'deadline') {
				iv := fab_arg_int(v) or {
					return mk_err(fab_err_arg_invalid,
						'E_FABRIC_ARG_INVALID: deadline must be ≥ 0 (ms)')
				}
				if iv < 0 {
					return mk_err(fab_err_arg_invalid,
						'E_FABRIC_ARG_INVALID: deadline must be ≥ 0 (ms)')
				}
				deadline_ms = iv
			}
		}
	}
	fr.mu.lock()
	defer {
		fr.mu.unlock()
	}
	if !fr.open {
		return mk_err(fab_err_handle, 'E_FABRIC_HANDLE: operation on a closed fabric')
	}
	mut served := i64(0)
	for fr.req_buf.len > 0 && (max < 0 || served < max) {
		fe := fr.req_buf[0]
		fr.req_buf = fr.req_buf[1..].clone()
		fab_remote_answer_one(mut fr, fe, mut env)
		served++
	}
	started := time.now().unix_milli()
	for fr.open && (max < 0 || served < max)
		&& time.now().unix_milli() - started < deadline_ms {
		st, raw := fs_read_frame(mut fr.net, fab_remote_max_frame)
		match st {
			.idle {}
			.closed {
				fab_remote_teardown(mut fr)
				break
			}
			.frame {
				fe_node := xsp_decode_at(raw, 0)
				if fe_node is cx.Element {
					fe := fe_node as cx.Element
					ft := xap_elem_attr(fe, 'type')
					if ft == 'event' {
						fab_remote_route_event(mut fr, fe)
					} else if ft == 'request' {
						fab_remote_answer_one(mut fr, fe, mut env)
						served++
					}
				}
			}
		}
	}
	return bus_int(served)
}

// ── dispatch routing ──────────────────────────────────────────────────────

// fab_remote_arg_id extracts the handle id of a [fabric]/[fabric-sub]/
// [fabric-responder] first argument IF it names a remote handle.
fn fab_remote_arg_id(args []cx.Node) ?int {
	if args.len < 1 {
		return none
	}
	id := fab_handle_of(args[0], 'fabric') or {
		fab_handle_of(args[0], 'fabric-sub') or {
			fab_handle_of(args[0], 'fabric-responder') or { return none }
		}
	}
	fab_remote_lookup(id) or { return none }
	return id
}

// fabric_remote_builtin routes a fabric verb whose first argument is a
// REMOTE handle; returns none for embedded handles (the caller falls
// through to the embedded implementations).
fn fabric_remote_builtin(name string, args []cx.Node) ?cx.Node {
	id := fab_remote_arg_id(args) or { return none }
	mut fr := fab_remote_lookup(id) or { return none }
	match name {
		'fabric-publish' {
			return fab_remote_publish(mut fr, args)
		}
		'fabric-subscribe' {
			return fab_remote_subscribe(mut fr, args, false)
		}
		'fabric-observe' {
			return fab_remote_subscribe(mut fr, args, true)
		}
		'fabric-receive' {
			return fab_remote_receive(mut fr, args)
		}
		'fabric-ack' {
			return fab_remote_ack(mut fr, args)
		}
		'fabric-emit' {
			return fab_remote_emit(mut fr, args)
		}
		'fabric-read' {
			return fab_remote_read(mut fr, args)
		}
		'fabric-respond' {
			return fab_remote_respond(mut fr, args)
		}
		'fabric-close' {
			return fab_remote_close(mut fr)
		}
		else {
			return none
		}
	}
}

// fabric_remote_builtin_env routes the env-aware verbs whose first argument
// is a remote handle — `request` (a wire turn; env unused but the chain is
// one) and `serve` (applies the client-held responder callable).
fn fabric_remote_builtin_env(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	id := fab_remote_arg_id(args) or { return none }
	mut fr := fab_remote_lookup(id) or { return none }
	match name {
		'fabric-request' {
			return fab_remote_request_call(mut fr, args)
		}
		'fabric-serve' {
			return fab_remote_serve(mut fr, args, mut env)
		}
		else {
			return none
		}
	}
}
