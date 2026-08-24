module main

import net
import os
import testenv
import time

// http_slow_handler_isolation_test.v — BEHAVIORAL guard for cx-private #275(b)
// (handlers off reactors; http.md §14).
//
// A handler that blocks on a slow upstream must not freeze the serve plane.
// Pre-fix, handler evaluation ran ON the picoev reactor threads: min(4, cores)
// concurrent slow handlers parked every reactor and NOTHING answered — health
// checks included (the third marine-helm wedge mechanism). Post-fix, reactors
// only do socket I/O; handlers run on a bounded executor pool; a full queue is
// answered 503 by the reactor itself.
//
// The slow handler parks on a real blocking upstream call — [$http:get] against
// a black-hole listener with a 3s whole-request timeout (§4.5) — exactly the
// LLM-call shape that wedged the helm.

const fast_probe_budget_ms = 1500

fn cx_bin() string {
	return testenv.cx_bin()
}

// blackhole upstream: accept, read, never respond (holds the handler's client
// call until its §4.5 timeout).
fn serve_blackhole(mut l net.TcpListener) {
	for {
		mut c := l.accept() or { return }
		spawn fn (mut c net.TcpConn) {
			mut buf := []u8{len: 4096}
			c.read(mut buf) or {}
			time.sleep(8 * time.second)
			c.close() or {}
		}(mut c)
	}
}

fn listen_local() (&net.TcpListener, int) {
	mut l := net.listen_tcp(.ip, '127.0.0.1:0') or { panic('listen: ${err}') }
	addr := l.addr() or { panic('addr: ${err}') }
	return l, addr.port() or { panic('port: ${err}') }
}

// write_fixture renders the serve program: /slow dials the blackhole (3s
// timeout), anything else answers immediately.
fn write_fixture(dir string, srv_port int, bh_port int) string {
	prog := "[?lib 'cx-stdlib/http' :as http]\n" +
		"[?lib 'cx-stdlib/strings' :as s]\n" +
		'[?def handler impure (\$req)\n' +
		'  [?if [\$s:starts-with [\$concat "" \$req/@path] "/slow"]\n' +
		'    [then [?let [= \$r [?else [\$http:get "http://127.0.0.1:${bh_port}/" {timeout: 3s}] "timed-out"]]\n' +
		'           [response status=200 [headers] [body "slow-done"]]]]\n' +
		'    [else [response status=200 [headers] [body "fast"]]]]]\n' +
		'[\$http:serve "tcp://127.0.0.1:${srv_port}" handler {block: true}]\n'
	src := os.join_path(dir, 'slowserve.cx')
	os.write_file(src, prog) or { panic('write: ${err}') }
	return src
}

// raw_get opens a fresh connection, sends GET `path`, and returns the raw
// response (waiting up to `read_ms` for the FIRST data) — '' on failure.
// It returns after one successful read: the server keeps the connection open
// (keep-alive; it does not close on the client's Connection: close), so a
// read-until-EOF loop would idle out the full deadline on EVERY probe and
// report the deadline as "latency" (the fixture responses are single-segment,
// so one read carries the whole response).
fn raw_get(port int, path string, read_ms i64) string {
	mut c := net.dial_tcp('127.0.0.1:${port}') or { return '' }
	defer {
		c.close() or {}
	}
	c.write_string('GET ${path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n') or { return '' }
	c.set_read_timeout(read_ms * time.millisecond)
	mut buf := []u8{len: 8192}
	n := c.read(mut buf) or { return '' }
	if n <= 0 {
		return ''
	}
	return buf[..n].bytestr()
}

// hold_slow fires GET /slow and leaves the connection waiting (the handler is
// parked on the blackhole upstream for ~3s).
fn hold_slow(port int) {
	raw_get(port, '/slow', 6000)
}

fn wait_up(port int) bool {
	for _ in 0 .. 60 {
		r := raw_get(port, '/fast', 1000)
		if r.contains('200') {
			return true
		}
		time.sleep(250 * time.millisecond)
	}
	return false
}

fn start_server(src string, extra_env string) &os.Process {
	// Server output goes to a per-fixture log (next to the fixture) — a silent
	// server is undebuggable when an isolation contract fails.
	log := src + '.log'
	mut p := os.new_process('/bin/sh')
	// `exec` so the shell REPLACES itself with cx: signal_kill then reaches
	// the server, not just the sh wrapper. Without it, a failing lane leaves
	// a stray server holding this test's FIXED port — and every later run's
	// probes hit the stray, false-greening the lane (#355 was masked for two
	// days exactly this way).
	p.set_args(['-c', '${extra_env} exec ${cx_bin()} --allow-net=127.0.0.1 ${os.quoted_path(src)} >${os.quoted_path(log)} 2>&1'])
	p.run()
	return p
}

fn test_fast_requests_survive_saturating_slow_handlers() {
	mut bl, bh_port := listen_local()
	spawn serve_blackhole(mut bl)
	dir := os.join_path(os.temp_dir(), 'cx_275b_iso_${os.getpid()}')
	os.mkdir_all(dir) or { panic('mkdir: ${err}') }
	srv_port := 39041
	src := write_fixture(dir, srv_port, bh_port)
	mut p := start_server(src, '')
	defer {
		p.signal_kill()
		p.close()
	}
	assert wait_up(srv_port), 'serve did not come up on :${srv_port}'
	// Saturate the old reactor count (min(4, cores)) with slow handlers, plus
	// margin: 6 concurrent requests each parked ~3s on the blackhole upstream.
	for _ in 0 .. 6 {
		spawn hold_slow(srv_port)
	}
	time.sleep(400 * time.millisecond) // let the slow dispatches start
	// The plane must keep answering: serial /fast probes during the slow window.
	mut worst := i64(0)
	for _ in 0 .. 8 {
		t0 := time.ticks()
		r := raw_get(srv_port, '/fast', 4000)
		dt := time.ticks() - t0
		if dt > worst {
			worst = dt
		}
		assert r.contains('fast'), 'fast probe failed during slow saturation: ${r}'
	}
	eprintln('slow-saturation fast-probe worst latency: ${worst}ms')
	assert worst < fast_probe_budget_ms, 'fast request took ${worst}ms while slow handlers were in flight — the serve plane is blocked behind handler evaluation (#275 pre-fix behavior; server log: ${dir})'
	bl.close() or {}
	os.rmdir_all(dir) or {} // success path only — a failing run leaves the log
}

fn test_full_queue_sheds_load_with_503_not_a_wedge() {
	mut bl, bh_port := listen_local()
	spawn serve_blackhole(mut bl)
	dir := os.join_path(os.temp_dir(), 'cx_275b_q_${os.getpid()}')
	os.mkdir_all(dir) or { panic('mkdir: ${err}') }
	srv_port := 39042
	src := write_fixture(dir, srv_port, bh_port)
	// One executor, one queue slot: the third concurrent slow request MUST be
	// answered 503 by the reactor (shed loudly), not queued into a wedge.
	mut p := start_server(src, 'CX_HTTP_EXEC=1 CX_HTTP_QUEUE=1')
	defer {
		p.signal_kill()
		p.close()
	}
	assert wait_up(srv_port), 'serve did not come up on :${srv_port}'
	spawn hold_slow(srv_port) // occupies the single executor
	time.sleep(300 * time.millisecond)
	spawn hold_slow(srv_port) // occupies the single queue slot
	time.sleep(300 * time.millisecond)
	r := raw_get(srv_port, '/slow', 4000)
	assert r.contains('503'), 'expected a reactor-side 503 with the executor and queue saturated, got: ${r} (server log: ${dir})'
	bl.close() or {}
	os.rmdir_all(dir) or {} // success path only — a failing run leaves the log
}
