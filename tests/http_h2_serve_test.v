// http_h2_serve_test.v — BEHAVIORAL gate for TLS + HTTP/2 on the serve path
// (#875; spec/03-approved/std-lib/http.md §13, ruling H2-1).
//
// A cx program is the SERVER: one cleartext [?http-service] and one carrying
// the `[tls cert= key=]` child (same resources). The V side is the CLIENT —
// a real mbedtls TLS dial with ALPN, and a minimal RFC-7540 frame driver
// built from the platform module's PUBLIC h2 codec (h2_frame_encode /
// H2FrameReader / HPACK), i.e. the same transport bricks the server reuses.
//
// What this proves (the §13 contract, end to end over real sockets):
//   1. ALPN offering ("h2","http/1.1") negotiates h2, and a request/response
//      round-trips over h2 frames (HEADERS/DATA, HPACK, :status).
//   2. ALPN offering only http/1.1 falls back to the h1 path over TLS with
//      responses BYTE-IDENTICAL to the cleartext listener's.
//   3. SSE over ONE h2 connection multiplexes two feed streams under
//      per-stream flow control: a slow stream (window starved by the
//      client) never blocks its sibling; crediting it later drains it.
//      The publishes arrive over the SAME connection (a third stream) —
//      one connection carrying every feed is the §13.3 acceptance shape.
//   4. h2c is refused: a cleartext h2 preface and an h2 preface on an
//      ALPN-http/1.1 TLS connection are both answered as h1 (or dropped),
//      never with h2 frames.

module main

import encoding.base64
import net
import net.mbedtls
import os
import platform
import testenv
import time

// Disjoint PID + nanosecond-salted band (28600-28698, two ports per run) so
// concurrent `v test vcx/tests/` gate processes don't collide.
fn h2t_ports() (int, int) {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 49
	base := 28600 + int(salt) * 2
	return base, base + 1
}

// Self-signed localhost cert/key (test fixture — same PEMs the V fork's
// net.ssl ALPN test uses; valid to 2050). The client dials with
// validate:false, so only the handshake mechanics matter.
const h2t_cert = '-----BEGIN CERTIFICATE-----
MIIEOTCCAyECFG64Q2g46jZb3kRbDOJWX/BwjSp6MA0GCSqGSIb3DQEBCwUAMEUx
CzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl
cm5ldCBXaWRnaXRzIFB0eSBMdGQwIBcNMjMwODAyMTcyOTQyWhgPMjA1MDEyMTcx
NzI5NDJaMGsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRQwEgYD
VQQHDAtMb3MgQW5nZWxlczEdMBsGA1UECgwUQ2F0YWx5c3QgRGV2ZWxvcG1lbnQx
EjAQBgNVBAMMCWxvY2FsaG9zdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
ggIBALqAI4fqUi+QBVWcsXglouLdOML5+w0+1hSR1KdO0Q5XPdQAs/yYWJ+KUkDw
G++rfy9DUPq7FNRBVurXQkcAtn6gXdllGUSjwUiDo/N4mMOyS/2sufBuaeww7jVi
rppH+zwP1tUnjRd6khl6bi1Ian9VSzr3Iy9CkXIg1GU4CPXkOydLeoQfepXxWoK1
OUNwT3VKC/stAfY3j/NIIeiJYkyuRGFCkxn/BUjN+AsXiTugRcYKEFHdIPkOuCXp
Ybhf+lLsczpxCs3rdZG9b/N6mEDCzXTmeHkmsjdPTf+1k5DZZvKzVBBrgdxCgBb7
5RwjF5v9WmnIc33wWgfJC6FaUzj9NYxYUbPHD+jTz0rJB/jj4u/xJlM/e5NRmXdW
70pOMKXtWjRSolLOFIPKLY1qs3KMTAZxKKWPDDF7WlMJxMRt7nnnks5yw43Nog4C
jDLk1ZgETnPpLgo3jbmJdIv+OHKTJrBlVvDq7VTyixCoS5G8KoOmyQJhaXG6NwE2
iVhH5JIKgzgCfetfDsnjxqJ/qtrFXPa8FF2TsomD0NK/GZmIcs+9OeVB75Jn5uhF
fLHScpiTbuu5w3P/LI/MqihLRB6RRNnRzPH8fIg5bYC9b770ta/8GcFRuYE8t+UR
GtqXJoIKixbDlqV54kal8FQzYzhETf9+NM6Kb/lKEfG/pslvAgMBAAEwDQYJKoZI
hvcNAQELBQADggEBALI3uNiNO0QE1brA3QYFK+d9ZroB72NrJ0UNkzYHDg2Fc6xg
4aVVfaxY08+TmKc0JlMOW+pUxeCW/+UBSngdQiR9EE9xm0k0XIrAsy9RXxRvEtPu
M1VI2h7ayp1Y2BrnQinevTSgtqLRyS1VbOFRl1FiyVvinw2I0KsDdAMNevAPXcOa
Q8pUgUq6f56DkhocQaj+hxD/uV8HryNxuoSXnPhvfTN3z4YRGzsaWevJ9EYJliOM
+XugcqfFJ+W7/QCEcAHCL+Bw6OydG5NFORr3p57PXjjcL/uKmxPBrWg2Bz6uT4uR
Mhj0zttiFHLAt9jGfyk6W57UNUja1e1ggftJJhs=
-----END CERTIFICATE-----
'

const h2t_key = '-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
'

fn write_tmp_file(name string, content string) string {
	p := os.join_path(os.temp_dir(), name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

fn h2t_server_prog(clear_port int, tls_port int, cert string, key string) string {
	return '[?lib \'cx-stdlib/http\' :as http]\n' +
		'[?http-service\n' +
		'   [name "h2t-clear"]\n' +
		'   [on http]\n' +
		'   [port ${clear_port}]\n' +
		'   [bind-host "127.0.0.1"]\n' +
		'   [resource [GET "/hello"]\n' +
		'     [response status=200\n' +
		'       [headers [header name="X-Lane" value="h2t"]]\n' +
		'       [body "hello-h2-lane"]]]]\n' +
		'[?http-service\n' +
		'   [name "h2t-tls"]\n' +
		'   [on http]\n' +
		'   [port ${tls_port}]\n' +
		'   [bind-host "127.0.0.1"]\n' +
		'   [block true]\n' +
		'   [tls cert="${cert}" key="${key}"]\n' +
		'   [resource [GET "/hello"]\n' +
		'     [response status=200\n' +
		'       [headers [header name="X-Lane" value="h2t"]]\n' +
		'       [body "hello-h2-lane"]]]\n' +
		'   [resource [GET "/feed"]\n' +
		'     [sse-subscribe topic="h2t"]]\n' +
		'   [resource [GET "/feedx"]\n' +
		'     [sse-subscribe topic="h2t" [envelope codec="xsp"]]]\n' +
		'   [resource [POST "/pub"]\n' +
		'     [?let [= \$n [\$http:sse-publish "h2t" [event data="tick-tock-goes-the-clock"]]]\n' +
		'       [response status=200 [body \$n]]]]]\n'
}

// one SSE wire frame per publish, as the server emits it
const h2t_event_frame = 'data: tick-tock-goes-the-clock\n\n'

// ── tiny h2 client driver (over an mbedtls SSLConn) ─────────────────────────

fn h2t_dial(port int, protos []string) !&mbedtls.SSLConn {
	mut conn := mbedtls.new_ssl_conn(mbedtls.SSLConnectConfig{
		validate:       false
		alpn_protocols: protos
		read_timeout:   100 * time.millisecond
	})!
	conn.dial('127.0.0.1', port)!
	return conn
}

// h2t_read_frames pumps inbound frames into `frames` until `deadline` or
// until `enough` returns true over the collected set.
fn h2t_read_frames(mut conn mbedtls.SSLConn, mut reader platform.H2FrameReader, mut frames []platform.H2Frame, deadline time.Time, enough fn (fs []platform.H2Frame) bool) {
	mut buf := []u8{len: 16384}
	for time.now() < deadline {
		if enough(frames) {
			return
		}
		n := conn.read(mut buf) or {
			// read tick (timeout) — keep pumping until the deadline
			continue
		}
		if n <= 0 {
			return
		}
		reader.feed(buf[..n].clone())
		for {
			f := reader.next() or { break }
			frames << f
		}
	}
}

// h2t_open_stream writes one request's HEADERS (+ optional DATA) frames.
fn h2t_open_stream(mut conn mbedtls.SSLConn, sid u32, method string, path string, authority string, body string) ! {
	block := platform.hpack_encode_header_list([
		platform.HpackHeader{':method', method},
		platform.HpackHeader{':path', path},
		platform.HpackHeader{':scheme', 'https'},
		platform.HpackHeader{':authority', authority},
	])
	mut flags := platform.h2_flag_end_headers
	if body == '' {
		flags |= platform.h2_flag_end_stream
	}
	mut wire := platform.h2_frame_encode(platform.H2Frame{
		typ:       platform.h2_headers
		flags:     flags
		stream_id: sid
		payload:   block
	})
	if body != '' {
		wire << platform.h2_frame_encode(platform.H2Frame{
			typ:       platform.h2_data
			flags:     platform.h2_flag_end_stream
			stream_id: sid
			payload:   body.bytes()
		})
	}
	conn.write(wire)!
}

// h2t_client_preface writes the RFC 7540 §3.5 preface + a client SETTINGS
// (optionally shrinking the server's per-stream send window — the flow-
// control starvation lever for test 3).
fn h2t_client_preface(mut conn mbedtls.SSLConn, initial_window u32) ! {
	mut wire := platform.h2_preface.bytes()
	mut settings := []platform.H2Setting{}
	if initial_window > 0 {
		settings << platform.H2Setting{platform.h2_settings_initial_window_size, initial_window}
	}
	wire << platform.h2_frame_encode(platform.h2_settings_frame(settings))
	conn.write(wire)!
}

fn h2t_window_update(mut conn mbedtls.SSLConn, sid u32, inc u32) ! {
	conn.write(platform.h2_frame_encode(platform.h2_window_update(sid, inc)))!
}

// h2t_headers_status decodes a HEADERS payload and returns :status ('' if
// absent). One decoder per connection (HPACK dynamic-table discipline).
fn h2t_headers_status(mut dec platform.HpackDecoder, payload []u8) string {
	hdrs := dec.decode(payload) or { return '' }
	for h in hdrs {
		if h.name == ':status' {
			return h.value
		}
	}
	return ''
}

fn h2t_stream_data(frames []platform.H2Frame, sid u32) []u8 {
	mut out := []u8{}
	for f in frames {
		if f.typ == platform.h2_data && f.stream_id == sid {
			out << f.payload
		}
	}
	return out
}

fn h2t_has_response(frames []platform.H2Frame, sid u32) bool {
	mut got_headers := false
	mut got_end := false
	for f in frames {
		if f.stream_id != sid {
			continue
		}
		if f.typ == platform.h2_headers {
			got_headers = true
			if f.has_flag(platform.h2_flag_end_stream) {
				got_end = true
			}
		}
		if f.typ == platform.h2_data && f.has_flag(platform.h2_flag_end_stream) {
			got_end = true
		}
	}
	return got_headers && got_end
}

// ── server lifecycle ─────────────────────────────────────────────────────────

// h2t_pid_alive — is OUR server still running? `kill -0` probes existence
// without signalling.
fn h2t_pid_alive(pid string) bool {
	if pid == '' {
		return false
	}
	return os.execute('kill -0 ${pid} 2>/dev/null').exit_code == 0
}

// h2t_start_server — spawn the fixture server and prove OUR process owns the
// ports before any test dials them.
//
// The trap this guards (hit for real at the v0.16.0 cut): the readiness check
// used to accept ANY process answering the port. This lane's ports come from a
// 49-slot range, and a leaked server from an earlier run still holding one made
// a fresh spawn fail to bind ("socket error: 48") while the check happily saw
// the ORPHAN listening, so the test dialled a stale process and reported a
// bogus `mbedtls_ssl_handshake failed` — a confusing TLS error for what was
// really a port collision. That is exactly the failure the approved deployment
// doctrine names (spec/03-approved/misc/deployment.md §1-2: the port is the
// only mutex, and a launcher that cannot tell its own server from someone
// else's has no health check at all).
//
// So: the spawned pid must be ALIVE at every poll, a dead pid fails
// immediately with the server's own log (which says why — usually the bind),
// and a bind collision retries on a fresh port instead of dialling a stranger.
fn h2t_start_server() (int, int, string) {
	cert := write_tmp_file('h2t_cert_${os.getpid()}.pem', h2t_cert)
	key := write_tmp_file('h2t_key_${os.getpid()}.pem', h2t_key)
	out_file := os.join_path(os.temp_dir(), 'h2t_srv_${os.getpid()}.log')
	for attempt in 0 .. 6 {
		clear_port, tls_port := h2t_ports()
		prog := write_tmp_file('h2t_srv_${os.getpid()}.cx', h2t_server_prog(clear_port,
			tls_port, cert, key))
		pid_s := os.execute('${testenv.cx_bin()} --allow-net ${prog} >${out_file} 2>&1 & echo \$!')
		pid := pid_s.output.trim_space()
		if h2t_wait_own_listener(pid, clear_port) && h2t_wait_own_listener(pid, tls_port) {
			return clear_port, tls_port, pid
		}
		// our process died (or never bound) — reap and try a different port
		if pid != '' {
			os.execute('kill ${pid} 2>/dev/null')
		}
		log := os.read_file(out_file) or { '' }
		if !log.contains('socket error: 48') {
			assert false, 'h2 fixture server failed to start on attempt ${attempt} (log: ${out_file}):\n${log}'
			break
		}
		// port collision — the 49-slot range picked an occupied pair; retry
		time.sleep(120 * time.millisecond)
	}
	assert false, 'h2 fixture server could not claim a free port pair after 6 attempts (log: ${out_file})'
	return 0, 0, ''
}

// h2t_wait_own_listener — the port is listening AND our pid is still alive.
// Both halves matter: alive-but-not-listening is "still starting", and
// listening-but-dead is someone else's process on our port.
fn h2t_wait_own_listener(pid string, port int) bool {
	deadline := time.now().add(15 * time.second)
	for time.now() < deadline {
		if !h2t_pid_alive(pid) {
			return false
		}
		mut c := net.dial_tcp('127.0.0.1:${port}') or {
			time.sleep(50 * time.millisecond)
			continue
		}
		c.close() or {}
		return true
	}
	return false
}

fn h2t_stop_server(pid string) {
	if pid == '' {
		return
	}
	os.execute('kill ${pid} 2>/dev/null')
	// Reap for real: a server that ignores TERM would otherwise be left
	// holding a port from this lane's 49-slot range and break the NEXT run
	// (that is how the cut hit a bogus TLS handshake error). Escalate only
	// after TERM went unanswered — the deployment doctrine's rule.
	for _ in 0 .. 40 {
		if !h2t_pid_alive(pid) {
			return
		}
		time.sleep(50 * time.millisecond)
	}
	os.execute('kill -9 ${pid} 2>/dev/null')
}

// ── the tests (one server for the whole battery) ────────────────────────────

fn test_h2_serve_battery() {
	clear_port, tls_port, pid := h2t_start_server()
	defer {
		h2t_stop_server(pid)
	}
	check_alpn_h2_roundtrip(tls_port)
	check_http11_fallback_byte_identical(clear_port, tls_port)
	check_sse_multiplex_flow_control(tls_port)
	check_sse_xsp_envelope_over_h2(tls_port)
	check_h2c_refused(clear_port, tls_port)
}

// 1. ALPN negotiates h2; GET /hello round-trips over h2 frames.
fn check_alpn_h2_roundtrip(tls_port int) {
	mut conn := h2t_dial(tls_port, ['h2', 'http/1.1']) or {
		assert false, 'tls dial: ${err}'
		return
	}
	assert conn.negotiated_alpn() == 'h2', 'ALPN must select h2 when offered'
	h2t_client_preface(mut conn, 0) or {
		assert false, 'preface write: ${err}'
		return
	}
	h2t_open_stream(mut conn, 1, 'GET', '/hello', '127.0.0.1:${tls_port}', '') or {
		assert false, 'open stream: ${err}'
		return
	}
	mut reader := platform.H2FrameReader{}
	mut frames := []platform.H2Frame{}
	h2t_read_frames(mut conn, mut reader, mut frames, time.now().add(10 * time.second),
		fn (fs []platform.H2Frame) bool {
		return h2t_has_response(fs, 1)
	})
	assert h2t_has_response(frames, 1), 'no complete h2 response on stream 1 (frames: ${frames.len})'
	// server preface must include its SETTINGS
	mut saw_settings := false
	mut dec := platform.new_hpack_decoder(4096)
	mut status := ''
	for f in frames {
		if f.typ == platform.h2_settings && !f.has_flag(platform.h2_flag_ack) {
			saw_settings = true
		}
		if f.typ == platform.h2_headers && f.stream_id == 1 {
			status = h2t_headers_status(mut dec, f.payload)
		}
	}
	assert saw_settings, 'server must emit its SETTINGS preface'
	assert status == '200', 'h2 :status must be 200, got `${status}`'
	body := h2t_stream_data(frames, 1)
	assert body.bytestr() == 'hello-h2-lane', 'h2 body mismatch: `${body.bytestr()}`'
	conn.shutdown() or {}
}

// 2. ALPN without h2 → the h1 path over TLS, byte-identical to cleartext.
fn check_http11_fallback_byte_identical(clear_port int, tls_port int) {
	req := 'GET /hello HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: */*\r\n\r\n'
	// cleartext reference bytes (the picoev lane)
	mut tc := net.dial_tcp('127.0.0.1:${clear_port}') or {
		assert false, 'tcp dial: ${err}'
		return
	}
	tc.set_read_timeout(2 * time.second)
	tc.write_string(req) or {
		assert false, 'tcp write: ${err}'
		return
	}
	clear_resp := h1_read_response_tcp(mut tc)
	tc.close() or {}
	// TLS with ALPN restricted to http/1.1
	mut sc := h2t_dial(tls_port, ['http/1.1']) or {
		assert false, 'tls dial: ${err}'
		return
	}
	assert sc.negotiated_alpn() == 'http/1.1', 'ALPN must fall back to http/1.1'
	sc.write(req.bytes()) or {
		assert false, 'tls write: ${err}'
		return
	}
	tls_resp := h1_read_response_tls(mut sc)
	sc.shutdown() or {}
	assert clear_resp.len > 0, 'no cleartext response'
	assert clear_resp.bytestr().starts_with('HTTP/1.1 200 OK'), 'cleartext lane: ${clear_resp.bytestr()}'
	assert tls_resp == clear_resp, 'h1-over-TLS response must be byte-identical to cleartext:\n--- clear ---\n${clear_resp.bytestr()}\n--- tls ---\n${tls_resp.bytestr()}'
}

// h1_read_response_* read exactly one h1 response (headers + Content-Length
// body) off a kept-alive connection.
fn h1_read_response_tcp(mut c net.TcpConn) []u8 {
	mut acc := []u8{}
	mut buf := []u8{len: 8192}
	deadline := time.now().add(5 * time.second)
	for time.now() < deadline {
		if h1_response_complete(acc) {
			break
		}
		n := c.read(mut buf) or { break }
		if n <= 0 {
			break
		}
		acc << buf[..n]
	}
	return acc
}

fn h1_read_response_tls(mut c mbedtls.SSLConn) []u8 {
	mut acc := []u8{}
	mut buf := []u8{len: 8192}
	deadline := time.now().add(5 * time.second)
	for time.now() < deadline {
		if h1_response_complete(acc) {
			break
		}
		n := c.read(mut buf) or {
			// read tick — keep pumping
			continue
		}
		if n <= 0 {
			break
		}
		acc << buf[..n]
	}
	return acc
}

fn h1_response_complete(acc []u8) bool {
	s := acc.bytestr()
	hdr_end := s.index('\r\n\r\n') or { return false }
	head := s[..hdr_end].to_lower()
	cl_at := head.index('content-length:') or { return false }
	rest := head[cl_at + 15..].trim_space()
	mut digits := ''
	for ch in rest {
		if ch >= `0` && ch <= `9` {
			digits += ch.ascii_str()
		} else {
			break
		}
	}
	clen := digits.int()
	return acc.len >= hdr_end + 4 + clen
}

// 3. SSE over ONE h2 connection: two feed streams multiplex; a window-
//    starved stream never blocks its sibling; crediting drains it.
fn check_sse_multiplex_flow_control(tls_port int) {
	mut conn := h2t_dial(tls_port, ['h2']) or {
		assert false, 'tls dial: ${err}'
		return
	}
	assert conn.negotiated_alpn() == 'h2'
	// starve the server's per-stream send windows: 8 octets each.
	h2t_client_preface(mut conn, 8) or {
		assert false, 'preface: ${err}'
		return
	}
	authority := '127.0.0.1:${tls_port}'
	// two feed subscriptions on ONE connection
	h2t_open_stream(mut conn, 1, 'GET', '/feed', authority, '') or {
		assert false, 'feed 1: ${err}'
		return
	}
	h2t_open_stream(mut conn, 3, 'GET', '/feed', authority, '') or {
		assert false, 'feed 3: ${err}'
		return
	}
	// credit ONLY stream 3 — stream 1 stays starved at 8 octets.
	h2t_window_update(mut conn, 3, 1 << 20) or {
		assert false, 'wu 3: ${err}'
		return
	}
	mut reader := platform.H2FrameReader{}
	mut frames := []platform.H2Frame{}
	// both feeds must be promoted (SSE response HEADERS) before publishing
	h2t_read_frames(mut conn, mut reader, mut frames, time.now().add(10 * time.second),
		fn (fs []platform.H2Frame) bool {
		mut h1 := false
		mut h3 := false
		for f in fs {
			if f.typ == platform.h2_headers && f.stream_id == 1 {
				h1 = true
			}
			if f.typ == platform.h2_headers && f.stream_id == 3 {
				h3 = true
			}
		}
		return h1 && h3
	})
	// three publishes, each a request/response exchange on the SAME
	// connection (streams 5/7/9) — multiplexing while two feeds are held.
	want := h2t_event_frame.repeat(3).bytes()
	mut pub_sid := u32(5)
	for _ in 0 .. 3 {
		h2t_open_stream(mut conn, pub_sid, 'POST', '/pub', authority, 'x') or {
			assert false, 'pub ${pub_sid}: ${err}'
			return
		}
		sid := pub_sid
		h2t_read_frames(mut conn, mut reader, mut frames, time.now().add(10 * time.second),
			fn [sid] (fs []platform.H2Frame) bool {
			return h2t_has_response(fs, sid)
		})
		assert h2t_has_response(frames, pub_sid), 'publish on stream ${pub_sid} got no response'
		pub_body := h2t_stream_data(frames, pub_sid)
		assert pub_body.bytestr() == '2', 'publish must reach both feed streams, delivered=${pub_body.bytestr()}'
		pub_sid += 2
	}
	// the credited sibling must receive ALL three events…
	h2t_read_frames(mut conn, mut reader, mut frames, time.now().add(10 * time.second),
		fn [want] (fs []platform.H2Frame) bool {
		return h2t_stream_data(fs, 3).len >= want.len
	})
	s3 := h2t_stream_data(frames, 3)
	s1_mid := h2t_stream_data(frames, 1)
	assert s3 == want, 'credited stream must carry all events; got ${s3.len} bytes: `${s3.bytestr()}`'
	// …while the starved stream is pinned at its 8-octet window: the slow
	// stream never blocked its sibling, and never got past its window.
	assert s1_mid.len <= 8, 'starved stream must be window-bound (≤8 octets), got ${s1_mid.len}'
	// credit the starved stream — it must now drain the queued events.
	h2t_window_update(mut conn, 1, 1 << 20) or {
		assert false, 'wu 1: ${err}'
		return
	}
	h2t_read_frames(mut conn, mut reader, mut frames, time.now().add(10 * time.second),
		fn [want] (fs []platform.H2Frame) bool {
		return h2t_stream_data(fs, 1).len >= want.len
	})
	s1 := h2t_stream_data(frames, 1)
	assert s1 == want, 'credited-late stream must drain to the same bytes; got ${s1.len}: `${s1.bytestr()}`'
	conn.shutdown() or {}
}

// 3b. SSE-1 (xsp.md §4.1): the negotiated XSP-envelope carriage over the
//     TLS/h2 lane — a plain feed and an [envelope codec="xsp"] feed COEXIST
//     ON ONE TOPIC over ONE h2 connection; a publish reaches both; the
//     plain stream's bytes are the pre-SSE-1 frame verbatim, and the xsp
//     stream's data: is one base64 line whose decoded bytes are a valid
//     XSP event frame carrying the SAME event text byte-for-byte.
fn h2t_xsp_event_payload(b64 string) ?string {
	buf := base64.decode(b64)
	if buf.len < 17 {
		return none
	}
	// xsp.md §2: version 1, type 2 (event), stream 0, flags 0 (binary=false,
	// no eos), anonymous principal.
	if buf[0] != 1 || buf[1] != 2 || buf[10] != 0 {
		return none
	}
	for i in 2 .. 10 {
		if buf[i] != 0 {
			return none
		}
	}
	if buf[11] != 0 || buf[12] != 0 {
		return none
	}
	paylen := (u32(buf[13]) << 24) | (u32(buf[14]) << 16) | (u32(buf[15]) << 8) | u32(buf[16])
	if buf.len != 17 + int(paylen) {
		return none
	}
	return buf[17..].bytestr()
}

fn check_sse_xsp_envelope_over_h2(tls_port int) {
	mut conn := h2t_dial(tls_port, ['h2']) or {
		assert false, 'tls dial: ${err}'
		return
	}
	assert conn.negotiated_alpn() == 'h2'
	h2t_client_preface(mut conn, 0) or {
		assert false, 'preface: ${err}'
		return
	}
	authority := '127.0.0.1:${tls_port}'
	// one topic, two carriages, ONE connection: stream 1 plain, stream 3 xsp.
	h2t_open_stream(mut conn, 1, 'GET', '/feed', authority, '') or {
		assert false, 'feed: ${err}'
		return
	}
	h2t_open_stream(mut conn, 3, 'GET', '/feedx', authority, '') or {
		assert false, 'feedx: ${err}'
		return
	}
	mut reader := platform.H2FrameReader{}
	mut frames := []platform.H2Frame{}
	h2t_read_frames(mut conn, mut reader, mut frames, time.now().add(10 * time.second),
		fn (fs []platform.H2Frame) bool {
		mut h1 := false
		mut h3 := false
		for f in fs {
			if f.typ == platform.h2_headers && f.stream_id == 1 {
				h1 = true
			}
			if f.typ == platform.h2_headers && f.stream_id == 3 {
				h3 = true
			}
		}
		return h1 && h3
	})
	// publish once on stream 5 of the same connection.
	h2t_open_stream(mut conn, 5, 'POST', '/pub', authority, 'x') or {
		assert false, 'pub: ${err}'
		return
	}
	h2t_read_frames(mut conn, mut reader, mut frames, time.now().add(10 * time.second),
		fn (fs []platform.H2Frame) bool {
		return h2t_has_response(fs, 5)
	})
	assert h2t_has_response(frames, 5), 'publish got no response'
	// at least our two subscribers (a just-shutdown prior connection may
	// still be pruning); the content assertions below are the real proof.
	assert h2t_stream_data(frames, 5).bytestr().int() >= 2, 'publish must reach both carriage lanes of the topic: delivered=${h2t_stream_data(frames, 5).bytestr()}'
	// the plain stream carries the pre-SSE-1 frame verbatim…
	h2t_read_frames(mut conn, mut reader, mut frames, time.now().add(10 * time.second),
		fn (fs []platform.H2Frame) bool {
		return h2t_stream_data(fs, 1).len >= h2t_event_frame.len
			&& h2t_stream_data(fs, 3).bytestr().contains('\n\n')
	})
	s1 := h2t_stream_data(frames, 1)
	assert s1 == h2t_event_frame.bytes(), 'plain h2 feed moved (must be byte-identical): `${s1.bytestr()}`'
	// …and the xsp stream carries one base64 data line decoding to the SAME
	// event text (byte-compare after decode).
	s3 := h2t_stream_data(frames, 3).bytestr()
	assert s3.starts_with('data: ') && s3.ends_with('\n\n'), 'xsp h2 feed frame malformed: `${s3}`'
	b64 := s3.all_after('data: ').all_before('\n')
	payload := h2t_xsp_event_payload(b64) or {
		assert false, 'xsp h2 feed data is not a valid base64 XSP event frame: `${s3}`'
		return
	}
	assert payload == 'tick-tock-goes-the-clock', 'decoded XSP payload must byte-equal the plain lane event: `${payload}`'
	conn.shutdown() or {}
}

// 4. h2c is refused: an h2 preface on cleartext, and on an ALPN-http/1.1
//    TLS connection, is never answered with h2 frames.
fn check_h2c_refused(clear_port int, tls_port int) {
	preface := platform.h2_preface.bytes()
	// (a) cleartext prior-knowledge preface → h1 error or drop, never h2.
	mut tc := net.dial_tcp('127.0.0.1:${clear_port}') or {
		assert false, 'tcp dial: ${err}'
		return
	}
	tc.set_read_timeout(2 * time.second)
	tc.write(preface) or {
		assert false, 'tcp write: ${err}'
		return
	}
	mut buf := []u8{len: 8192}
	mut acc := []u8{}
	for {
		n := tc.read(mut buf) or { break }
		if n <= 0 {
			break
		}
		acc << buf[..n]
		if acc.len > 0 {
			break
		}
	}
	tc.close() or {}
	assert !h2t_looks_like_h2(acc), 'cleartext h2 preface must not be answered with h2 frames'
	if acc.len > 0 {
		assert acc.bytestr().starts_with('HTTP/1.1'), 'cleartext h2c attempt must get an h1 answer (or a drop), got: ${acc.bytestr()}'
	}
	// (b) TLS negotiated http/1.1, then an h2 preface → h1 error, never h2.
	mut sc := h2t_dial(tls_port, ['http/1.1']) or {
		assert false, 'tls dial: ${err}'
		return
	}
	sc.write(preface) or {
		assert false, 'tls write: ${err}'
		return
	}
	mut sacc := []u8{}
	deadline := time.now().add(3 * time.second)
	for time.now() < deadline && sacc.len == 0 {
		n := sc.read(mut buf) or { continue }
		if n <= 0 {
			break
		}
		sacc << buf[..n]
	}
	sc.shutdown() or {}
	assert !h2t_looks_like_h2(sacc), 'ALPN http/1.1 + h2 preface must not be answered with h2 frames'
	if sacc.len > 0 {
		assert sacc.bytestr().starts_with('HTTP/1.1'), 'TLS h2c attempt must get an h1 answer (or a drop), got: ${sacc.bytestr()}'
	}
}

// h2t_looks_like_h2 — does the byte stream begin with a well-formed h2
// frame header of a type the server would emit first (SETTINGS)?
fn h2t_looks_like_h2(acc []u8) bool {
	if acc.len < 9 {
		return false
	}
	return acc[3] == platform.h2_settings
}
