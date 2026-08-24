@[has_globals]
module platform

import net
import net.mbedtls
import os
import sync
import time

// http_h2_serve.v — TLS + HTTP/2 on the [?http-service] / [$http:serve]
// serve path (#875; spec/03-approved/std-lib/http.md §13, ruling H2-1).
//
// With a `[tls cert=PATH key=PATH]` child present the listener terminates
// TLS (mbedtls, the net-layer stack) and offers ALPN ("h2", "http/1.1");
// the negotiated protocol selects the connection's framing:
//
//   - "h2"        → the RFC-7540 connection driver below. TRANSPORT-ONLY
//                   REUSE of the #105 codec that shipped for the store's
//                   gRPC edge (store_grpc_h2.v frame layer + the HPACK
//                   coder) — no gRPC semantics exist anywhere on this path
//                   (gRPC stays an external-adapter surface, owner doctrine
//                   2026-08-20). Each h2 stream materializes exactly one
//                   exchange dispatched through the SAME transport-neutral
//                   dispatch_request the picoev lane uses; handlers run on
//                   the SHARED bounded executor pool (http.md §14 — the
//                   connection's I/O thread never evaluates CX), and a full
//                   ring sheds an inline 503 HEADERS, no evaluation.
//   - "http/1.1"  → the existing h1 semantics over the TLS transport:
//     (or none)     requests parse to the same shapes, dispatch through the
//                   same dispatch_request, and responses serialize through
//                   the SAME serialize_wire — byte-identical to the
//                   cleartext path by construction.
//
// There is NO h2c: cleartext stays HTTP/1.1 only (browsers do not speak
// cleartext h2 — §13.1). An h2 preface on a cleartext or ALPN-http/1.1
// connection is answered as a malformed h1 request, never as h2.
//
// SSE over h2 (§13.3): a handler's `[sse-subscribe topic=…]` promotion
// lowers to a held-open stream whose event writes are DATA frames under
// PER-STREAM flow control (WINDOW_UPDATE): a slow consumer's frames queue
// against its own stream window and a bounded per-stream buffer — never
// against the connection or a sibling stream. Buffer overflow terminates
// exactly that stream (RST_STREAM ENHANCE_YOUR_CALM); siblings continue.
// This replaces §3.6's OS-write-blocking backpressure rule for h2 streams.
//
// Threading model: mbedtls does not permit concurrent operations on one
// ssl context, so ALL socket I/O for a connection happens on its OWNER
// thread (the per-connection loop): executors and SSE publishers only
// ENQUEUE frames under the connection mutex (bounded, never blocking on
// I/O), and the owner loop alternates a short-timeout read with a drain
// of the writable frames. The h2 protocol-error discipline mirrors the
// hardened gRPC lane (#222/#223): exact preface, oversized-frame refusal,
// header-block caps, GOAWAY on connection errors. Protocol errors stay
// wire-level (GOAWAY/RST error codes); no CX-level error value surfaces
// from them, so no new CXER is minted (§13.2's band stays unallocated
// until a CX-visible surface needs one).

// ── tuning constants ─────────────────────────────────────────────────────────

// h2s_tick — the owner loop's read timeout: the upper bound on how long a
// queued outbound frame waits for the wire (mean ~half). Small enough for
// live-feed latency, large enough that an idle connection costs ~200
// syscalls/s. (A wakeable writer would need concurrent mbedtls access —
// unsafe on one ssl context; this is the v1 pacing.)
const h2s_tick = 5 * time.millisecond

// h2s_stream_pend_cap bounds one stream's outbound queue (a slow SSE
// consumer). Overflow resets that stream only (§13.3).
const h2s_stream_pend_cap = 1 << 20 // 1 MiB

// h2s_body_cap bounds one stream's accumulated inbound DATA (request body).
const h2s_body_cap = 10 << 20 // 10 MiB — mirrors the default max-body-bytes

// h2s_recv_window_grant — the connection-level receive window the server
// grants up front (mirrors the gRPC lane's conservative floor); per-stream
// inbound credit is re-granted 1:1 as DATA is consumed.
const h2s_recv_window_grant = u32(1) << 20

// h1s_idle_timeout — how long a kept-alive TLS h1 connection may sit idle
// between requests before the owner thread closes it.
const h1s_idle_timeout = 30 * time.second

// ── connection cap ────────────────────────────────────────────────────────────
// TLS connections are thread-per-connection (h2 multiplexes all of one
// client's tabs onto one connection, so connections ≈ clients). The cap
// refuses accepts beyond it — bounded by construction, never unbounded
// thread growth. CX_HTTP_TLS_CONNS overrides (deploy-time ops config).
__global (
	cx_tls_conn_count u32
	cx_tls_conn_cap   u32
)

// ── SSE subscriber registries (TLS transports) ───────────────────────────────
// The picoev lane's registry (cx_sse_topic_subs) is raw-fd keyed; TLS
// transports cannot take raw fd writes, so they register here instead and
// cx_sse_topic_publish fans out to both. Same atomicity contract: the
// initial ack is enqueued under the registry lock, so a concurrent publish
// either misses the not-yet-acked subscriber or follows its ack in order.
struct H2TopicSub {
mut:
	conn   &H2ServeConn = unsafe { nil }
	stream u32
}

@[heap]
struct TlsSseSink {
mut:
	mu     &sync.Mutex = unsafe { nil }
	q      [][]u8
	bytes  int
	closed bool
}

__global (
	cx_sse_h2_lock   &sync.Mutex
	cx_sse_h2_subs   map[string][]H2TopicSub
	cx_sse_tls1_lock &sync.Mutex
	cx_sse_tls1_subs map[string][]&TlsSseSink
)

// http_tls_serve_init_globals — called from services_listener_init_globals
// (module init, before any thread): reference-typed mutexes + explicit
// empty-map inits, per the Darwin value-mutex trap (#275/#303).
fn http_tls_serve_init_globals() {
	cx_sse_h2_lock = sync.new_mutex()
	cx_sse_h2_subs = map[string][]H2TopicSub{}
	cx_sse_tls1_lock = sync.new_mutex()
	cx_sse_tls1_subs = map[string][]&TlsSseSink{}
	cx_tls_conn_count = 0
	cx_tls_conn_cap = 256
	if ov := os.getenv_opt('CX_HTTP_TLS_CONNS') {
		k := ov.int()
		if k >= 1 {
			cx_tls_conn_cap = u32(k)
		}
	}
}

// ── the TLS listener ─────────────────────────────────────────────────────────

// start_tls_service_listener binds host:port as a TLS listener offering
// ALPN ("h2", "http/1.1") and spawns the accept loop. Used by BOTH serve
// surfaces (§13.1): [?http-service] with a [tls] child (mode .service) and
// [$http:serve "tls://…" $handler {tls: {…}}] (mode .handler).
fn start_tls_service_listener(mut h ListenerHandler, host string, port int, cert string, key string) ! {
	serve_file_cache_init()
	cx_dispatch_start_executors() // idempotent; h2 jobs ride the shared pool
	bind_host := if host == '' { '0.0.0.0' } else { host }
	// read_timeout here IS the accepted connections' C-level read timeout
	// (mbedtls applies the LISTENER conf to every accepted conn; a per-conn
	// set_read_timeout writes an unused conf) — it becomes the owner loops'
	// tick. The handshake is immune: tls_accept_loop drives it through the
	// NONBLOCKING bio (accept_raw + complete_handshake) with its own budget.
	cfg := mbedtls.SSLConnectConfig{
		cert:           cert
		cert_key:       key
		validate:       false
		alpn_protocols: ['h2', 'http/1.1']
		read_timeout:   h2s_tick
	}
	mut l := mbedtls.new_ssl_listener('${bind_host}:${port}', cfg) or {
		return error('tls listen ${bind_host}:${port}: ${err.msg()}')
	}
	spawn tls_accept_loop(mut l, h)
}

fn tls_accept_loop(mut l mbedtls.SSLListener, h &ListenerHandler) {
	for {
		// accept the TCP connection (1s poll, retried forever), then run the
		// TLS handshake over the nonblocking bio with a real budget — the
		// 5ms conf read-tick must never bound a handshake round trip.
		mut conn := l.accept_raw_with_timeout(1 * time.second) or { continue }
		conn.complete_handshake(10 * time.second) or {
			conn.shutdown() or {}
			continue
		}
		if C.atomic_load_u32(&cx_tls_conn_count) >= cx_tls_conn_cap {
			// over the connection cap: refuse loudly (close), never queue.
			conn.shutdown() or {}
			continue
		}
		C.atomic_fetch_add_u32(&cx_tls_conn_count, 1)
		spawn tls_conn_thread(mut conn, h)
	}
}

fn tls_conn_thread(mut conn mbedtls.SSLConn, h &ListenerHandler) {
	defer {
		C.atomic_fetch_sub_u32(&cx_tls_conn_count, 1)
	}
	alpn := conn.negotiated_alpn()
	if alpn == 'h2' {
		h2s_serve_conn(mut conn, h)
	} else {
		// "http/1.1" or no ALPN offered → the existing h1 path over TLS (§13.1).
		h1s_serve_conn(mut conn, h)
	}
}

// tls_err_is_timeout — a short-timeout read tick (owner-loop pacing), as
// distinct from a fatal read error / EOF.
fn tls_err_is_timeout(e IError) bool {
	if e.code() == net.err_timed_out_code {
		return true
	}
	if e.code() == -26624 { // MBEDTLS_ERR_SSL_TIMEOUT (-0x6800)
		return true
	}
	m := e.msg()
	return m.contains('timed out') || m.contains('did not receive any data')
}

// ── HTTP/1.1 over TLS ────────────────────────────────────────────────────────
//
// The same request shapes, the same dispatch_request, the same
// serialize_wire — byte-identical responses to the cleartext lane. One
// connection serves one request at a time (h1 semantics), on its own
// thread: a blocking handler parks exactly this connection, nothing else.

struct TlsLineReader {
mut:
	conn &mbedtls.SSLConn = unsafe { nil }
	buf  []u8
	pos  int
}

// fill reads more bytes, riding out the listener-conf read ticks (the 5ms
// pacing every accepted conn inherits) until `deadline`. Returns false on
// EOF / fatal error / the deadline elapsing with nothing received.
fn (mut r TlsLineReader) fill(deadline time.Time) bool {
	mut tmp := []u8{len: 8192}
	for {
		n := r.conn.read(mut tmp) or {
			if tls_err_is_timeout(err) {
				if time.now() < deadline {
					continue
				}
				return false
			}
			return false
		}
		if n <= 0 {
			return false
		}
		r.buf << tmp[..n]
		return true
	}
	return false
}

// read_line returns one \r\n- (or \n-) terminated line, without the
// terminator. none on EOF or on `deadline` before a full line arrives.
fn (mut r TlsLineReader) read_line(deadline time.Time) ?string {
	for {
		for i := r.pos; i < r.buf.len; i++ {
			if r.buf[i] == `\n` {
				mut end := i
				if end > r.pos && r.buf[end - 1] == `\r` {
					end--
				}
				line := r.buf[r.pos..end].bytestr()
				r.pos = i + 1
				r.compact()
				return line
			}
		}
		if !r.fill(deadline) {
			return none
		}
	}
	return none
}

fn (mut r TlsLineReader) read_exact(n int, deadline time.Time) ?[]u8 {
	for r.buf.len - r.pos < n {
		if !r.fill(deadline) {
			return none
		}
	}
	out := r.buf[r.pos..r.pos + n].clone()
	r.pos += n
	r.compact()
	return out
}

fn (mut r TlsLineReader) compact() {
	if r.pos > 0 {
		r.buf = r.buf[r.pos..].clone()
		r.pos = 0
	}
}

fn h1s_serve_conn(mut conn mbedtls.SSLConn, hl &ListenerHandler) {
	mut h := unsafe { &ListenerHandler(hl) }
	mut r := TlsLineReader{
		conn: unsafe { &mbedtls.SSLConn(conn) }
	}
	for {
		// idle budget: a kept-alive connection may sit quiet this long
		// between requests; once a request starts, the same deadline bounds
		// its head+body arrival.
		deadline := time.now().add(h1s_idle_timeout)
		req_line := r.read_line(deadline) or { break } // EOF or idle timeout — close
		if req_line.trim_space() == '' {
			continue // tolerate a bare CRLF between pipelined requests
		}
		parts := req_line.split(' ')
		if parts.len < 3 {
			break // malformed request line — close (mirrors the parser lane)
		}
		method := parts[0].to_upper()
		target := parts[1]
		mut hdrs := []WireHeader{}
		mut xsp := XspReqHdrs{}
		mut clen := 0
		mut header_ok := true
		for {
			line := r.read_line(deadline) or {
				header_ok = false
				break
			}
			if line == '' {
				break
			}
			ci := line.index(':') or { continue }
			hname := line[..ci].trim_space()
			hval := line[ci + 1..].trim_space()
			lname := hname.to_lower()
			if lname == 'content-length' {
				clen = hval.int()
			} else if lname == 'xsp-channel' {
				xsp.channel = hval
			} else if lname == 'xsp-counter' {
				xsp.counter = hval
			} else if lname == 'xsp-proof' {
				xsp.proof = hval
			}
			hdrs << WireHeader{
				name:  hname
				value: hval
			}
		}
		if !header_ok {
			break
		}
		mut body := ''
		if clen > 0 {
			bb := r.read_exact(clen, deadline) or { break }
			body = bb.bytestr()
		}
		w := dispatch_request(mut h, method, target, body, xsp, hdrs)
		if w.sse {
			if w.sse_topic == '' {
				// the xap-runtime feed rides the cleartext xap lane; over TLS
				// only the generic topic promotion is wired (§13.3).
				e := serialize_wire(mk_wire(500, [], 'sse promotion unsupported on this transport lane\n'),
					false)
				conn.write(e.bytes()) or {}
				break
			}
			prelude := 'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n' +
				w.body
			mut sink := &TlsSseSink{
				mu: sync.new_mutex()
			}
			// SSE-1: an XSP-envelope subscription registers under the topic's
			// envelope sibling key — same topic, negotiated carriage.
			cx_sse_tls1_subscribe(sse_topic_key(w.sse_topic, w.sse_xsp), mut sink,
				prelude)
			h1s_sse_pump(mut conn, mut sink)
			cx_sse_tls1_drop_sink(sink)
			break
		}
		out := serialize_wire(w, method == 'HEAD')
		conn.write(out.bytes()) or { break }
		// keep-alive: loop for the next request on this connection (h1.1
		// default — serialize_wire sets no Connection header, same as the
		// cleartext lane).
	}
	conn.shutdown() or {}
}

// h1s_sse_pump — the owner loop for a TLS h1 connection promoted to an SSE
// feed: drain the sink's queued frames to the wire, tick-read to detect the
// peer closing. All ssl I/O stays on this thread.
fn h1s_sse_pump(mut conn mbedtls.SSLConn, mut sink TlsSseSink) {
	// the listener-conf read timeout (h2s_tick) paces this loop
	mut tmp := []u8{len: 512}
	for {
		sink.mu.lock()
		mut batch := []u8{}
		for b in sink.q {
			batch << b
		}
		sink.q = [][]u8{}
		sink.bytes = 0
		closed := sink.closed
		sink.mu.unlock()
		if batch.len > 0 {
			conn.write(batch) or { break }
		}
		if closed {
			break
		}
		n := conn.read(mut tmp) or {
			if tls_err_is_timeout(err) {
				continue
			}
			break
		}
		if n <= 0 {
			break // peer closed the feed
		}
		// bytes from an SSE client are ignored (h1 half-close semantics)
	}
	sink.mu.lock()
	sink.closed = true
	sink.mu.unlock()
}

// cx_sse_tls1_subscribe enqueues the ack (prelude + optional initial frame)
// and registers the sink — atomically under the registry lock, mirroring
// the fd lane's readiness-barrier contract.
fn cx_sse_tls1_subscribe(topic string, mut sink TlsSseSink, ack string) {
	cx_sse_tls1_lock.lock()
	sink.mu.lock()
	sink.q << ack.bytes()
	sink.bytes += ack.len
	sink.mu.unlock()
	// -prod checker: a map value holding pointers reads through `or {}`.
	mut subs := cx_sse_tls1_subs[topic] or { []&TlsSseSink{} }
	subs << sink
	cx_sse_tls1_subs[topic] = subs
	cx_sse_tls1_lock.unlock()
}

// cx_sse_tls1_drop_sink removes a closed sink from every topic.
fn cx_sse_tls1_drop_sink(sink &TlsSseSink) {
	cx_sse_tls1_lock.lock()
	for topic, sinks in cx_sse_tls1_subs {
		mut kept := []&TlsSseSink{}
		for s in sinks {
			if s != sink {
				kept << s
			}
		}
		cx_sse_tls1_subs[topic] = kept
	}
	cx_sse_tls1_lock.unlock()
}

// cx_sse_tls1_topic_publish enqueues one frame to every TLS-h1 subscriber
// of `topic`; returns the number accepted. Pure memcpy under the sink lock
// — a publisher never blocks on any connection's I/O.
fn cx_sse_tls1_topic_publish(topic string, frame string) int {
	cx_sse_tls1_lock.lock()
	sinks := (cx_sse_tls1_subs[topic] or { []&TlsSseSink{} }).clone()
	cx_sse_tls1_lock.unlock()
	mut delivered := 0
	mut dead := []&TlsSseSink{}
	for s in sinks {
		mut sink := unsafe { &TlsSseSink(s) }
		sink.mu.lock()
		if sink.closed || sink.bytes + frame.len > h2s_stream_pend_cap {
			// closed, or a slow consumer over the buffer bound: drop the feed
			// (the owner loop observes `closed` and tears the connection down).
			sink.closed = true
			sink.mu.unlock()
			dead << s
			continue
		}
		sink.q << frame.bytes()
		sink.bytes += frame.len
		sink.mu.unlock()
		delivered++
	}
	for s in dead {
		cx_sse_tls1_drop_sink(s)
	}
	return delivered
}

// ── HTTP/2 server connection ─────────────────────────────────────────────────

// H2SrvStream accumulates one inbound stream's header block + DATA until it
// half-closes (mirrors the gRPC lane's assembly, minus the gRPC message
// framing — the DATA bytes ARE the request body here).
@[heap]
struct H2SrvStream {
mut:
	header_block []u8
	headers      map[string]string
	data         []u8
	headers_done bool
	stream_done  bool
	cont_frames  int
	dispatched   bool
}

// H2SendQ is one stream's outbound DATA queue + send-side flow-control
// window (client-controlled via SETTINGS_INITIAL_WINDOW_SIZE and
// WINDOW_UPDATE).
@[heap]
struct H2SendQ {
mut:
	window    i64
	chunks    [][]u8
	off       int // read offset into chunks[0] (partial frame under a tight window)
	bytes     int
	end_after bool // emit END_STREAM once the queue drains (response bodies)
	dead      bool // stream reset (overflow / client RST) — drop writes
}

// H2ServeConn is one h2 connection's server state. The owner thread (the
// per-connection loop) is the ONLY thread that touches `ssl` and the
// inbound-assembly fields; `mu` guards everything executors and publishers
// reach (outq / pend / windows / sse_streams / closed).
@[heap]
pub struct H2ServeConn {
mut:
	ssl     &mbedtls.SSLConn = unsafe { nil }
	handler &ListenerHandler = unsafe { nil }
	mu      &sync.Mutex      = unsafe { nil }
	// inbound (owner thread only)
	dec          HpackDecoder
	streams      map[u32]&H2SrvStream
	preface_seen bool
	max_stream   u32
	fatal        bool
	// outbound (shared, under mu)
	outq        [][]u8
	pend        map[u32]&H2SendQ
	conn_window i64 = 65535
	init_window i64 = 65535
	max_frame   int = 16384
	sse_streams map[u32]string
	closed      bool
}

// ctl enqueues one non-flow-controlled frame (SETTINGS/ACK/PING-ACK/
// WINDOW_UPDATE/RST/GOAWAY/response HEADERS).
fn (mut c H2ServeConn) ctl(f H2Frame) {
	c.mu.lock()
	if !c.closed {
		c.outq << h2_frame_encode(f)
	}
	c.mu.unlock()
}

// sendq returns (creating lazily) the stream's outbound queue. Caller holds mu.
fn (mut c H2ServeConn) sendq(sid u32) &H2SendQ {
	if sid in c.pend {
		return c.pend[sid] or { &H2SendQ{} }
	}
	q := &H2SendQ{
		window: c.init_window
	}
	c.pend[sid] = q
	return q
}

// enqueue_data queues DATA bytes for a stream (any thread; bounded, never
// blocks on I/O). Returns false when the connection is closed or the stream
// is dead / overflowed — the overflow resets exactly that stream (§13.3).
fn (mut c H2ServeConn) enqueue_data(sid u32, data []u8, end bool) bool {
	c.mu.lock()
	if c.closed {
		c.mu.unlock()
		return false
	}
	mut q := c.sendq(sid)
	if q.dead {
		c.mu.unlock()
		return false
	}
	if q.bytes + data.len > h2s_stream_pend_cap {
		// slow consumer: terminate THIS stream only; siblings keep flowing.
		q.dead = true
		q.chunks = [][]u8{}
		q.bytes = 0
		c.outq << h2_frame_encode(h2_rst_stream(sid, h2_err_enhance_your_calm))
		c.sse_streams.delete(sid)
		c.mu.unlock()
		return false
	}
	q.chunks << data
	q.bytes += data.len
	if end {
		q.end_after = true
	}
	c.mu.unlock()
	return true
}

// credit applies a WINDOW_UPDATE (stream 0 = connection-level).
fn (mut c H2ServeConn) credit(sid u32, inc u32) {
	c.mu.lock()
	if sid == 0 {
		c.conn_window += i64(inc)
	} else {
		mut q := c.sendq(sid)
		q.window += i64(inc)
	}
	c.mu.unlock()
}

// collect_writable drains everything currently writable — control frames
// first, then per-stream DATA within min(stream window, connection window,
// max frame size). Called by the owner thread only.
fn (mut c H2ServeConn) collect_writable() []u8 {
	c.mu.lock()
	mut out := []u8{}
	for b in c.outq {
		out << b
	}
	c.outq = [][]u8{}
	mut done := []u32{}
	sids := c.pend.keys()
	for sid in sids {
		mut q := c.pend[sid] or { continue }
		if q.dead {
			done << sid
			continue
		}
		for q.chunks.len > 0 && q.window > 0 && c.conn_window > 0 {
			first := q.chunks[0]
			mut n := first.len - q.off
			if i64(n) > q.window {
				n = int(q.window)
			}
			if i64(n) > c.conn_window {
				n = int(c.conn_window)
			}
			if n > c.max_frame {
				n = c.max_frame
			}
			if n <= 0 {
				break
			}
			payload := first[q.off..q.off + n].clone()
			last := q.chunks.len == 1 && q.off + n == first.len
			flags := if last && q.end_after { h2_flag_end_stream } else { u8(0) }
			out << h2_frame_encode(H2Frame{
				typ:       h2_data
				flags:     flags
				stream_id: sid
				payload:   payload
			})
			q.window -= i64(n)
			c.conn_window -= i64(n)
			q.bytes -= n
			q.off += n
			if q.off == first.len {
				q.chunks.delete(0)
				q.off = 0
			}
		}
		if q.chunks.len == 0 && q.end_after {
			done << sid
		}
	}
	for sid in done {
		c.pend.delete(sid)
	}
	c.mu.unlock()
	return out
}

// write_response emits one exchange's response: HEADERS (+ flow-controlled
// DATA). h2 forbids connection-specific headers (RFC 7540 §8.1.2.2); the
// content-length is recomputed from the body, exactly like serialize_wire.
fn (mut c H2ServeConn) write_response(sid u32, w WireResp, is_head bool) {
	mut hdrs := [HpackHeader{':status', w.status.str()}]
	for hv in w.headers {
		ln := hv.name.to_lower()
		if ln in ['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade',
			'content-length'] {
			continue
		}
		hdrs << HpackHeader{ln, hv.value}
	}
	hdrs << HpackHeader{'content-length', w.body.len.str()}
	body_empty := is_head || w.body.len == 0
	flags := h2_flag_end_headers | if body_empty { h2_flag_end_stream } else { u8(0) }
	c.ctl(H2Frame{
		typ:       h2_headers
		flags:     flags
		stream_id: sid
		payload:   hpack_encode_header_list(hdrs)
	})
	if !body_empty {
		c.enqueue_data(sid, w.body.bytes(), true)
	}
}

// begin_sse_stream promotes a stream to a held-open event feed: the SSE
// response HEADERS (no END_STREAM), then — atomically under the registry
// lock — the initial frame enqueue + the subscriber registration (the same
// readiness-barrier contract as the fd lane).
fn (mut c H2ServeConn) begin_sse_stream(sid u32, topic string, initial string) {
	// The whole promotion happens under the registry lock: the response
	// HEADERS and the initial frame are queued BEFORE the registration
	// becomes visible, so a concurrent publish either misses this stream
	// (client hasn't seen its ack) or enqueues strictly after the ack —
	// and DATA can never precede the HEADERS on the wire (outq drains
	// first within a batch, and both were queued before any publish).
	cx_sse_h2_lock.lock()
	c.ctl(H2Frame{
		typ:       h2_headers
		flags:     h2_flag_end_headers
		stream_id: sid
		payload:   hpack_encode_header_list([
			HpackHeader{':status', '200'},
			HpackHeader{'content-type', 'text/event-stream'},
			HpackHeader{'cache-control', 'no-cache'},
		])
	})
	if initial != '' {
		c.enqueue_data(sid, initial.bytes(), false)
	}
	c.mu.lock()
	c.sse_streams[sid] = topic
	c.mu.unlock()
	// -prod checker: a map value holding pointers reads through `or {}`.
	mut subs := cx_sse_h2_subs[topic] or { []H2TopicSub{} }
	subs << H2TopicSub{
		conn:   c
		stream: sid
	}
	cx_sse_h2_subs[topic] = subs
	cx_sse_h2_lock.unlock()
}

// cx_sse_h2_topic_publish enqueues one frame on every h2 subscriber stream
// of `topic`; returns the number accepted. Enqueue-only — a publisher never
// blocks on any connection's I/O; per-stream flow control + the pend cap do
// the §13.3 backpressure.
fn cx_sse_h2_topic_publish(topic string, frame string) int {
	cx_sse_h2_lock.lock()
	subs := (cx_sse_h2_subs[topic] or { []H2TopicSub{} }).clone()
	cx_sse_h2_lock.unlock()
	mut delivered := 0
	mut any_dead := false
	for s in subs {
		mut conn := unsafe { &H2ServeConn(s.conn) }
		if conn.enqueue_data(s.stream, frame.bytes(), false) {
			delivered++
		} else {
			any_dead = true
		}
	}
	if any_dead {
		cx_sse_h2_prune(topic)
	}
	return delivered
}

// cx_sse_h2_prune drops subscribers whose stream died or connection closed.
fn cx_sse_h2_prune(topic string) {
	cx_sse_h2_lock.lock()
	subs := cx_sse_h2_subs[topic] or {
		cx_sse_h2_lock.unlock()
		return
	}
	mut kept := []H2TopicSub{}
	for s in subs {
		mut conn := unsafe { &H2ServeConn(s.conn) }
		conn.mu.lock()
		alive := !conn.closed && (s.stream in conn.sse_streams)
		conn.mu.unlock()
		if alive {
			kept << s
		}
	}
	cx_sse_h2_subs[topic] = kept
	cx_sse_h2_lock.unlock()
}

// cx_sse_h2_drop_conn removes every subscription of a closing connection.
fn cx_sse_h2_drop_conn(conn &H2ServeConn) {
	cx_sse_h2_lock.lock()
	for topic, subs in cx_sse_h2_subs {
		mut kept := []H2TopicSub{}
		for s in subs {
			if s.conn != conn {
				kept << s
			}
		}
		cx_sse_h2_subs[topic] = kept
	}
	cx_sse_h2_lock.unlock()
}

// h2s_execute_job — the executor-pool hook for an h2-lane DispatchJob: run
// the SAME transport-neutral dispatch as the fd lane, then complete the
// stream (response frames or SSE promotion). No fd flags / pipelining — h2
// streams are concurrent by construction.
fn h2s_execute_job(mut job DispatchJob) {
	w := dispatch_request(mut job.h, job.method, job.path, job.body, job.xsp, job.hdrs)
	mut conn := unsafe { &H2ServeConn(job.h2c) }
	if w.sse && w.sse_topic != '' {
		// SSE-1: an XSP-envelope subscription registers under the topic's
		// envelope sibling key — same topic, negotiated carriage.
		conn.begin_sse_stream(job.h2_stream, sse_topic_key(w.sse_topic, w.sse_xsp),
			w.body)
		return
	}
	if w.sse {
		conn.write_response(job.h2_stream, mk_wire(500, [], 'sse promotion unsupported on this transport lane\n'),
			false)
		return
	}
	conn.write_response(job.h2_stream, w, job.method.to_upper() == 'HEAD')
}

// h2s_shed_503 — the reactor-side shed when the executor ring is full: a
// constant 503 HEADERS, no evaluation (the §14 discipline on this lane).
fn (mut c H2ServeConn) shed_503(sid u32) {
	c.ctl(H2Frame{
		typ:       h2_headers
		flags:     h2_flag_end_headers | h2_flag_end_stream
		stream_id: sid
		payload:   hpack_encode_header_list([
			HpackHeader{':status', '503'},
			HpackHeader{'content-type', 'text/plain'},
		])
	})
}

// h2s_serve_conn — the per-connection owner loop: validate the client
// preface, exchange SETTINGS, assemble streams, dispatch completed
// exchanges to the shared executor pool, and pace reads against the
// outbound drain. All ssl I/O happens here.
fn h2s_serve_conn(mut ssl mbedtls.SSLConn, hl &ListenerHandler) {
	hpack_huffman_init()
	mut c := &H2ServeConn{
		ssl:     unsafe { &mbedtls.SSLConn(ssl) }
		handler: unsafe { &ListenerHandler(hl) }
		mu:      sync.new_mutex()
		dec:     new_hpack_decoder(4096)
	}
	// (the listener-conf read timeout — h2s_tick — paces this loop's reads)
	// server preface: SETTINGS (the hardened inbound limits, same as the
	// gRPC lane) + a connection-level receive-window grant.
	c.ctl(h2_settings_frame([
		H2Setting{h2_settings_max_frame_size, h2_max_frame_size},
		H2Setting{h2_settings_max_header_list_size, h2_max_header_list_size},
	]))
	c.ctl(h2_window_update(0, h2s_recv_window_grant))
	mut reader := H2FrameReader{}
	mut prebuf := []u8{}
	mut buf := []u8{len: 16384}
	for {
		wb := c.collect_writable()
		if wb.len > 0 {
			ssl.write(wb) or { break }
		}
		if c.fatal {
			break
		}
		n := ssl.read(mut buf) or {
			if tls_err_is_timeout(err) {
				continue
			}
			break
		}
		if n <= 0 {
			break
		}
		mut input := buf[..n].clone()
		if !c.preface_seen {
			prebuf << input
			pf := h2_preface.bytes()
			if prebuf.len < pf.len {
				continue
			}
			if prebuf[..pf.len] != pf {
				// not the RFC 7540 §3.5 preface on an h2-negotiated connection —
				// a protocol connection error, never silent acceptance (#223).
				c.ctl(h2_goaway(0, h2_err_protocol))
				c.fatal = true
				continue
			}
			input = prebuf[pf.len..].clone()
			prebuf = []u8{}
			c.preface_seen = true
		}
		reader.feed(input)
		for {
			if reader.oversized_frame() {
				c.ctl(h2_goaway(c.max_stream, h2_err_frame_size))
				c.fatal = true
				break
			}
			f := reader.next() or { break }
			c.handle_frame(f)
			if c.fatal {
				break
			}
		}
	}
	// teardown: mark closed, then purge every SSE registration so a publish
	// can never enqueue to (or a late executor write reach) a dead wire.
	c.mu.lock()
	c.closed = true
	c.sse_streams = map[u32]string{}
	c.mu.unlock()
	cx_sse_h2_drop_conn(c)
	ssl.shutdown() or {}
}

fn (mut c H2ServeConn) conn_error(code u32) {
	c.ctl(h2_goaway(c.max_stream, code))
	c.fatal = true
}

fn (mut c H2ServeConn) stream(sid u32) &H2SrvStream {
	if sid in c.streams {
		return c.streams[sid] or { &H2SrvStream{} }
	}
	st := &H2SrvStream{}
	c.streams[sid] = st
	return st
}

fn (mut c H2ServeConn) handle_frame(f H2Frame) {
	match f.typ {
		h2_settings {
			if f.has_flag(h2_flag_ack) {
				return
			}
			settings := h2_parse_settings(f.payload) or {
				c.conn_error(h2_err_protocol) // §6.5: length % 6 != 0
				return
			}
			for s in settings {
				match s.id {
					h2_settings_initial_window_size {
						// RFC §6.9.2: the delta applies to every open stream's
						// send window, and to streams opened later.
						c.mu.lock()
						delta := i64(s.value) - c.init_window
						c.init_window = i64(s.value)
						sids := c.pend.keys()
						for sid in sids {
							mut q := c.pend[sid] or { continue }
							q.window += delta
						}
						c.mu.unlock()
					}
					h2_settings_max_frame_size {
						c.mu.lock()
						mut v := int(s.value)
						if v < 16384 {
							v = 16384
						}
						if v > int(h2_max_frame_size) {
							v = int(h2_max_frame_size)
						}
						c.max_frame = v
						c.mu.unlock()
					}
					else {}
				}
			}
			c.ctl(h2_settings_ack())
		}
		h2_ping {
			if !f.has_flag(h2_flag_ack) {
				c.ctl(h2_ping_ack(f.payload))
			}
		}
		h2_window_update {
			if f.payload.len != 4 {
				c.conn_error(h2_err_frame_size)
				return
			}
			inc := (u32(f.payload[0]) << 24 | u32(f.payload[1]) << 16 | u32(f.payload[2]) << 8 | u32(f.payload[3])) & 0x7fffffff
			c.credit(f.stream_id, inc)
		}
		h2_headers {
			if f.stream_id == 0 {
				c.conn_error(h2_err_protocol) // §5.1.1
				return
			}
			if f.stream_id > c.max_stream {
				c.max_stream = f.stream_id
			}
			mut st := c.stream(f.stream_id)
			st.header_block << h2_headers_block(f)
			if st.header_block.len > int(h2_max_header_list_size) {
				c.conn_error(h2_err_enhance_your_calm) // #222 header-block cap
				return
			}
			if f.has_flag(h2_flag_end_headers) {
				c.decode_headers(mut st)
				if c.fatal {
					return
				}
			}
			if f.has_flag(h2_flag_end_stream) {
				st.stream_done = true
			}
			c.maybe_dispatch(f.stream_id)
		}
		h2_continuation {
			if f.stream_id == 0 {
				c.conn_error(h2_err_protocol)
				return
			}
			mut st := c.stream(f.stream_id)
			st.cont_frames++
			if st.cont_frames > h2_max_continuation_frames {
				c.conn_error(h2_err_enhance_your_calm)
				return
			}
			st.header_block << f.payload
			if st.header_block.len > int(h2_max_header_list_size) {
				c.conn_error(h2_err_enhance_your_calm)
				return
			}
			if f.has_flag(h2_flag_end_headers) {
				c.decode_headers(mut st)
				if c.fatal {
					return
				}
			}
			c.maybe_dispatch(f.stream_id)
		}
		h2_data {
			if f.stream_id == 0 {
				c.conn_error(h2_err_protocol)
				return
			}
			mut st := c.stream(f.stream_id)
			payload := h2_data_payload(f)
			if st.data.len + payload.len > h2s_body_cap {
				c.ctl(h2_rst_stream(f.stream_id, h2_err_enhance_your_calm))
				c.streams.delete(f.stream_id)
				return
			}
			st.data << payload
			if payload.len > 0 {
				// re-grant inbound flow-control credit 1:1 as the body is consumed
				c.ctl(h2_window_update(f.stream_id, u32(payload.len)))
				c.ctl(h2_window_update(0, u32(payload.len)))
			}
			if f.has_flag(h2_flag_end_stream) {
				st.stream_done = true
			}
			c.maybe_dispatch(f.stream_id)
		}
		h2_rst_stream {
			c.streams.delete(f.stream_id)
			c.mu.lock()
			mut had_sse := f.stream_id in c.sse_streams
			c.sse_streams.delete(f.stream_id)
			if f.stream_id in c.pend {
				mut q := c.pend[f.stream_id] or { &H2SendQ{} }
				q.dead = true
				q.chunks = [][]u8{}
				q.bytes = 0
			}
			c.mu.unlock()
			if had_sse {
				// lazily pruned per topic on the next publish; nothing to do here
			}
		}
		h2_goaway {
			// the client is going away: finish in-flight work; the TCP close
			// (or our drained loop) ends the connection.
		}
		else {
			// PRIORITY and unknown frame types: ignored (RFC §4.1 — a receiver
			// MUST ignore frames of unknown type).
		}
	}
}

fn (mut c H2ServeConn) decode_headers(mut st H2SrvStream) {
	hdrs := c.dec.decode(st.header_block) or {
		c.conn_error(h2_err_compression) // #223: malformed HPACK, never swallowed
		return
	}
	for h in hdrs {
		st.headers[h.name.to_lower()] = h.value
	}
	st.headers_done = true
}

// maybe_dispatch enqueues one completed exchange (headers done + half-close)
// onto the shared executor pool; ring-full sheds an inline 503 HEADERS.
fn (mut c H2ServeConn) maybe_dispatch(sid u32) {
	mut st := c.streams[sid] or { return }
	if !(st.headers_done && st.stream_done) || st.dispatched {
		return
	}
	st.dispatched = true
	method := st.headers[':method'] or { '' }
	path := st.headers[':path'] or { '/' }
	if method == '' {
		c.ctl(h2_rst_stream(sid, h2_err_protocol))
		c.streams.delete(sid)
		return
	}
	mut hdrs := []WireHeader{}
	mut xsp := XspReqHdrs{}
	for k, v in st.headers {
		if k.starts_with(':') {
			if k == ':authority' && v != '' {
				hdrs << WireHeader{
					name:  'host'
					value: v
				}
			}
			continue
		}
		if k == 'xsp-channel' {
			xsp.channel = v
		} else if k == 'xsp-counter' {
			xsp.counter = v
		} else if k == 'xsp-proof' {
			xsp.proof = v
		}
		hdrs << WireHeader{
			name:  k
			value: v
		}
	}
	job := DispatchJob{
		h:         c.handler
		method:    method
		path:      path
		body:      st.data.bytestr()
		xsp:       xsp
		hdrs:      hdrs
		fd:        -1
		h2c:       c
		h2_stream: sid
	}
	c.streams.delete(sid)
	if cx_disp_ring_try_push(job) {
		cx_dispatch_wake_one()
	} else {
		c.shed_503(sid)
	}
}
