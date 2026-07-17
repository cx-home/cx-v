module main

import net
import os
import testenv
import time

// http_client_timeout_test.v — BEHAVIORAL guard for the §4.5 whole-request
// client timeout (cx-private #275; spec/03-approved/std-lib/http.md §3.1/§4.5).
//
// The net layer alone cannot bound a request: connect is select-bounded (5s)
// and each single read has a 30s socket default, but a response that keeps
// DRIBBLING bytes resets the per-read clock on every arrival — an LLM upstream
// streaming a generation held a connection (and, served inline, its reactor —
// the #275 helm wedge) for minutes with no single read ever timing out. Only a
// whole-request budget bounds that, surfaced as CXER4534 E_HTTP_REQUEST_TIMEOUT.
//
// Each test runs a raw V TCP server with a pathological behavior and asserts
// the cx one-shot client (through the real CLI + capability layer) fails with
// CXER4534 promptly — or, for the control, succeeds.

fn cx_bin() string {
	return testenv.cx_bin()
}

// run_fixture evaluates one [$http:get] against 127.0.0.1:port with the given
// timeout opt and returns (combined output, wall ms).
fn run_fixture(port int, timeout_opt string) (string, i64) {
	prog := "[?lib 'cx-stdlib/http' :as http]\n" +
		'[\$http:get "http://127.0.0.1:${port}/" {timeout: ${timeout_opt}}]'
	dir := os.join_path(os.temp_dir(), 'cx_275_timeout_${os.getpid()}_${port}')
	os.mkdir_all(dir) or { panic('mkdir: ${err}') }
	defer {
		os.rmdir_all(dir) or {}
	}
	src := os.join_path(dir, 'req.cx')
	os.write_file(src, prog) or { panic('write: ${err}') }
	t0 := time.ticks()
	res := os.execute('${cx_bin()} --allow-net=127.0.0.1 ${os.quoted_path(src)} 2>&1')
	return res.output, time.ticks() - t0
}

// Server loops exit on the first accept error — each test closes its listener
// when done, which ends its server thread cleanly (an `or { continue }` retry
// here spins hot on the closed listener for the rest of the process).

// blackhole: accept, read the request, never write a byte.
fn serve_blackhole(mut l net.TcpListener) {
	for {
		mut c := l.accept() or { return }
		spawn fn (mut c net.TcpConn) {
			mut buf := []u8{len: 4096}
			c.read(mut buf) or {}
			time.sleep(3 * time.second) // hold the conn silent past the test's budget
			c.close() or {}
		}(mut c)
	}
}

// dribble: valid headers with a huge Content-Length, then one body byte every
// 100ms — every read succeeds, so ONLY a whole-request budget can stop it.
fn serve_dribble(mut l net.TcpListener) {
	for {
		mut c := l.accept() or { return }
		spawn fn (mut c net.TcpConn) {
			mut buf := []u8{len: 4096}
			c.read(mut buf) or {}
			c.write_string('HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n') or {
				c.close() or {}
				return
			}
			for _ in 0 .. 50 {
				c.write_string('x') or { break }
				time.sleep(100 * time.millisecond)
			}
			c.close() or {}
		}(mut c)
	}
}

// ok: a normal, prompt 200 per connection.
fn serve_ok(mut l net.TcpListener) {
	for {
		mut c := l.accept() or { return }
		mut buf := []u8{len: 4096}
		c.read(mut buf) or {}
		c.write_string('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok') or {}
		c.close() or {}
	}
}

fn listen_local() (&net.TcpListener, int) {
	mut l := net.listen_tcp(.ip, '127.0.0.1:0') or { panic('listen: ${err}') }
	addr := l.addr() or { panic('addr: ${err}') }
	return l, addr.port() or { panic('port: ${err}') }
}

fn test_blackhole_times_out_with_cxer4534() {
	mut l, port := listen_local()
	spawn serve_blackhole(mut l)
	out, wall := run_fixture(port, '500ms')
	l.close() or {}
	assert out.contains('CXER4534'), 'expected CXER4534 from a silent upstream, got: ${out}'
	assert wall < 10_000, 'timeout took ${wall}ms — not bounded by the 500ms budget'
}

fn test_dribbling_body_defeats_per_read_timeouts_but_not_the_budget() {
	mut l, port := listen_local()
	spawn serve_dribble(mut l)
	out, wall := run_fixture(port, '700ms')
	l.close() or {}
	assert out.contains('CXER4534'), 'expected CXER4534 from a dribbling upstream (whole-request budget), got: ${out}'
	assert wall < 10_000, 'dribble timeout took ${wall}ms — the per-read clock was reset instead of the request being bounded'
}

fn test_prompt_response_unaffected() {
	mut l, port := listen_local()
	spawn serve_ok(mut l)
	out, wall := run_fixture(port, '5s')
	l.close() or {}
	assert !out.contains('CXER4534'), 'prompt response wrongly timed out after ${wall}ms: ${out}'
	assert out.contains('200'), 'expected a 200 response, got: ${out}'
}
