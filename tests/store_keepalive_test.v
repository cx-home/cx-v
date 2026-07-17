module main

import os
import testenv
import net
import time

// store_keepalive_test.v — #234.1: HTTP/1.1 keep-alive on the CSRP daemon. The
// pre-#234 server read one request, responded, and closed (Connection: close), so
// every CSRP op paid a fresh TCP (and TLS) handshake — contrary to §2.1/§5.2. This
// drives TWO sequential requests over ONE socket and asserts both are answered
// (the connection stayed open) and the first response advertises keep-alive. A
// close-after-each server would fail the second request (connection reset/refused).

fn ka_cx_binary() string {
	return testenv.cx_bin()
}

fn ka_pick_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 26800 + int(salt)
}

// The daemon: one mem:// store, config carries an explicit small idle-ms so the
// keep-alive path is unambiguously enabled.
fn ka_server_prog(port int) string {
	return "[?lib 'cx-stdlib/http' :as http]\n" +
		"[?lib 'cx-stdlib/store' :as store]\n" + '[?let [= \$local [\$store:open "mem://"]]\n' +
		'  [?let [= \$srv [\$http:listen "tcp://127.0.0.1:${port}" {}]]\n' +
		'    [?for [in \$ex [\$http:accept-iter \$srv]]\n' +
		'      [yield [\$store:csrp-handle \$ex \$local]]]]]\n'
}

fn ka_read_response(mut conn net.TcpConn) string {
	mut raw := []u8{}
	mut tmp := []u8{len: 4096}
	conn.set_read_timeout(3 * time.second)
	for {
		n := conn.read(mut tmp) or { break }
		if n <= 0 {
			break
		}
		raw << tmp[..n]
		s := raw.bytestr()
		if he := s.index('\r\n\r\n') {
			// read the full Content-Length body then stop (do NOT wait for EOF —
			// a keep-alive server never closes the socket).
			mut clen := -1
			for ln in s[..he].split('\r\n') {
				ci := ln.index(':') or { continue }
				if ln[..ci].trim_space().to_lower() == 'content-length' {
					clen = ln[ci + 1..].trim_space().int()
				}
			}
			if clen >= 0 && raw.len >= he + 4 + clen {
				break
			}
		}
	}
	return raw.bytestr()
}

fn test_csrp_keepalive_two_requests_one_connection() {
	// The daemon runs via the low-level http accept loop, which serve_connection's
	// keep-alive path is NOT part of (that path is the compiled `store-serve`
	// daemon). So this test drives the REAL `cx store-serve` binary instead.
	port := ka_pick_port()
	dir := os.join_path(os.temp_dir(), 'cx_ka_${port}')
	os.mkdir_all(dir) or { panic('mkdir: ${err}') }
	defer {
		os.rmdir_all(dir) or {}
	}
	cfg := os.join_path(dir, 'svc.cx')
	os.write_file(cfg, '[cxstore-service [bind addr="127.0.0.1:${port}"] [timeouts idle-ms=5000] [stores [store name="t" url="mem://"]]]') or {
		panic('write cfg: ${err}')
	}
	srv_out := os.join_path(dir, 'srv.out')
	allow := '--allow-net=127.0.0.1:${port} --allow-read=${dir}'
	pid_s := os.execute('${ka_cx_binary()} store-serve ${allow} --config ${cfg} >${srv_out} 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx store-serve')
		return
	}
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(800 * time.millisecond)

	mut conn := net.dial_tcp('127.0.0.1:${port}') or {
		srv_log := os.read_file(srv_out) or { '' }
		assert false, 'dial failed: ${err}; srv: ${srv_log}'
		return
	}
	defer {
		conn.close() or {}
	}

	// Request 1 — capabilities probe, explicit keep-alive.
	req1 := 'GET /cx-store/v1/capabilities HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n'
	conn.write(req1.bytes()) or {
		assert false, 'write req1: ${err}'
		return
	}
	resp1 := ka_read_response(mut conn)
	srv_log := os.read_file(srv_out) or { '' }
	assert resp1.contains('200'), 'first response should be 200; got: ${resp1} | srv: ${srv_log}'
	assert resp1.to_lower().contains('connection: keep-alive'), 'first response must advertise keep-alive (#234.1); got: ${resp1}'
	assert resp1.contains('capabilities'), 'first response should carry a capabilities body; got: ${resp1}'

	// Request 2 — on the SAME connection. A close-after-each server would have shut
	// the socket after resp1, so this write/read would fail or return empty.
	req2 := 'GET /cx-store/v1/capabilities HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n'
	conn.write(req2.bytes()) or {
		srv_log2 := os.read_file(srv_out) or { '' }
		assert false, 'the connection did not stay open for a second request (#234.1): write req2: ${err}; srv: ${srv_log2}'
		return
	}
	resp2 := ka_read_response(mut conn)
	assert resp2.contains('200'), 'second request on the SAME connection must be answered (keep-alive); got: ${resp2}'
	assert resp2.contains('capabilities'), 'second response should carry a capabilities body; got: ${resp2}'
}

// test_csrp_keepalive_client_close — a client that sends `Connection: close` gets a
// close-advertised response and the server closes after it (single-turn honored).
fn test_csrp_keepalive_client_close() {
	port := ka_pick_port() + 1
	dir := os.join_path(os.temp_dir(), 'cx_kac_${port}')
	os.mkdir_all(dir) or { panic('mkdir: ${err}') }
	defer {
		os.rmdir_all(dir) or {}
	}
	cfg := os.join_path(dir, 'svc.cx')
	os.write_file(cfg, '[cxstore-service [bind addr="127.0.0.1:${port}"] [timeouts idle-ms=5000] [stores [store name="t" url="mem://"]]]') or {
		panic('write cfg: ${err}')
	}
	srv_out := os.join_path(dir, 'srv.out')
	allow := '--allow-net=127.0.0.1:${port} --allow-read=${dir}'
	pid_s := os.execute('${ka_cx_binary()} store-serve ${allow} --config ${cfg} >${srv_out} 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx store-serve')
		return
	}
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(800 * time.millisecond)

	mut conn := net.dial_tcp('127.0.0.1:${port}') or {
		assert false, 'dial failed: ${err}'
		return
	}
	defer {
		conn.close() or {}
	}
	req := 'GET /cx-store/v1/capabilities HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'
	conn.write(req.bytes()) or {
		assert false, 'write: ${err}'
		return
	}
	resp := ka_read_response(mut conn)
	assert resp.contains('200'), 'response should be 200; got: ${resp}'
	assert resp.to_lower().contains('connection: close'), 'a Connection: close request must get a close response; got: ${resp}'
}
