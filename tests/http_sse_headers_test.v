module main

import os
import testenv
import time
import net

// http_sse_headers_test.v — #661: `sse-connect` must send `opts.headers` on the
// subscription GET. `headers` is a parent client key (http.md §3 table) and
// §3.6 specifies sse-connect's opts as "plus the parent client keys", but the
// verb hand-built its request line and never consulted them — so a caller could
// not authenticate a stream at all. xap_identity_model §4.12 requires
// `GET /stream` to carry the same three XSP proof headers as every other
// request; they had nowhere to ride.
//
// The raw-socket server CAPTURES the request head to a file, so these lanes
// assert what actually reached the wire rather than what the client believed it
// sent.
//   1. caller headers appear on the GET
//   2. managed fields are ignored, not errors (§4.6) — a caller-supplied Host
//      does not displace the URL's, and the stream still opens
//   3. CR/LF in a header is request-splitting → CXER4531

fn hdr_cx_binary() string {
	return testenv.cx_bin()
}

fn hdr_salt() int {
	return int((u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100)
}

fn hdr_write_tmp(name string, content string) string {
	p := os.join_path(os.temp_dir(), name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

// hdr_capture_server accepts one connection, writes the request head to
// `cap_path`, answers with a minimal event stream, and exits.
fn hdr_capture_server(mut l net.TcpListener, cap_path string) {
	mut c := l.accept() or {
		l.close() or {}
		return
	}
	mut req := []u8{}
	mut hb := []u8{len: 1}
	for {
		n := c.read(mut hb) or { break }
		if n <= 0 {
			break
		}
		req << hb[0]
		if req.len >= 4 && req#[-4..].bytestr() == '\r\n\r\n' {
			break
		}
	}
	os.write_file(cap_path, req.bytestr()) or {}
	c.write_string('HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n') or {}
	c.write_string('id: 1\ndata: alpha\n\n') or {}
	time.sleep(150 * time.millisecond)
	c.close() or {}
	l.close() or {}
}

// 1 + 2: caller headers reach the wire; a managed field is ignored, not fatal.
fn test_sse_connect_sends_opts_headers() {
	port := 26200 + hdr_salt()
	mut listener := net.listen_tcp(.ip, '127.0.0.1:${port}') or {
		eprintln('SKIP: cannot bind 127.0.0.1:${port}: ${err}')
		return
	}
	listener.set_accept_timeout(5 * time.second)
	cap_path := os.join_path(os.temp_dir(), 'cx-sse-hdrs.${port}.head')
	os.rm(cap_path) or {}
	srv := spawn hdr_capture_server(mut listener, cap_path)

	// XSP-* are the §4.12 proof headers this defect blocked; Host is the
	// managed-field probe (§4.6: ignored and overwritten, never an error).
	prog := hdr_write_tmp('cx_sse_hdrs.cx', '[?lib \'cx-stdlib/http\' :as http]\n' +
		'[?let [= \$src [\$http:sse-connect "http://127.0.0.1:${port}/stream"\n' +
		'        {reconnect: false, headers: {XSP-Channel: "abc123", XSP-Counter: "1",\n' +
		'         XSP-Proof: "cHJvb2Y=", Host: "evil.example"}}]]\n' +
		'  [?for [in \$ev [\$http:sse-events \$src]] [yield \$ev]]]\n')
	res := os.execute('${hdr_cx_binary()} --allow-net=127.0.0.1:${port} ${prog}')
	srv.wait()

	head := os.read_file(cap_path) or { '' }
	assert head.contains('XSP-Channel: abc123'), 'sse-connect dropped opts.headers (#661); request head was: ${head}'
	assert head.contains('XSP-Counter: 1'), 'sse-connect dropped XSP-Counter; head: ${head}'
	assert head.contains('XSP-Proof: cHJvb2Y='), 'sse-connect dropped XSP-Proof; head: ${head}'
	// §4.6: the URL's Host wins and the caller's is silently dropped
	assert head.contains('Host: 127.0.0.1'), 'the URL Host was not sent; head: ${head}'
	assert !head.contains('evil.example'), 'a caller-supplied managed Host reached the wire; head: ${head}'
	// the stream still opens and reads — a managed field is not an error
	assert res.output.contains('alpha'), 'the stream did not read after headers were applied; got: ${res.output}'
}

// 3: CR/LF in a caller header is request-splitting, refused (CXER4531).
fn test_sse_connect_rejects_header_injection() {
	port := 26300 + hdr_salt()
	mut listener := net.listen_tcp(.ip, '127.0.0.1:${port}') or {
		eprintln('SKIP: cannot bind 127.0.0.1:${port}: ${err}')
		return
	}
	listener.set_accept_timeout(2 * time.second)
	cap_path := os.join_path(os.temp_dir(), 'cx-sse-inject.${port}.head')
	os.rm(cap_path) or {}
	srv := spawn hdr_capture_server(mut listener, cap_path)

	prog := hdr_write_tmp('cx_sse_inject.cx', '[?lib \'cx-stdlib/http\' :as http]\n' +
		'[?let [= \$src [\$http:sse-connect "http://127.0.0.1:${port}/stream"\n' +
		'        {reconnect: false, headers: {X-Bad: "a\\r\\nX-Injected: yes"}}]]\n' +
		'  [out \$src]]\n')
	res := os.execute('${hdr_cx_binary()} --allow-net=127.0.0.1:${port} ${prog}')
	srv.wait()

	captured := os.read_file(cap_path) or { '' }
	assert res.output.contains('CXER4531'), 'a CR/LF header was not refused with CXER4531; got: ${res.output}'
	assert !captured.contains('X-Injected'), 'the split header reached the wire; head: ${captured}'
}
