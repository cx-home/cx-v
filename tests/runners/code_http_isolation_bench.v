// HTTP backend-direction isolation bench — is the ~10k req/s ceiling
// TRANSPORT-bound or INTERPRETER-bound?
//
// The decision deferred in spec/02-inprogress/stdlib_http.md is which
// backend the post-rc1 cx http server should target. The candidate
// stack (slow→fast) is:
//
//   net.http (current) < veb (picoev framework) < raw picoev+picohttpparser
//
// But a backend rewrite is wasted effort if the ceiling is the
// INTERPRETER (code.eval + per-request env clone), not the socket
// stack. This harness settles that empirically with a two-point
// measurement against the SAME no-op workload:
//
//   • Interpreter leg — drive a no-op CX handler through `code.eval`
//     IN-PROCESS (no socket, no port). This is the existing gate-16
//     path (code_http_throughput_bench.v): parse a fresh
//     [?http-client … | get("/ping")] expression against a cached,
//     post-register env and eval it. Measures eval + env.clone cost
//     per request — the irreducible interpreter floor.
//
//   • Transport leg — serve a TRIVIAL V no-op handler (return 200
//     "ok", NO code.eval) over the real net.http listener on an
//     EPHEMERAL port (localhost:0), and drive it with the net.http
//     client in a serial loop. Measures the socket accept + worker-
//     pool handoff + HTTP/1.1 parse + wire-write stack in isolation
//     from the interpreter.
//
// Both legs run a SERIAL request loop (one in-flight request at a
// time) so 1/mean-latency is apples-to-apples between them; the
// reported RATIO (what % of a single-request's wall-clock is transport
// vs interpreter) is robust to absolute CPU speed and contention.
//
// Reading the verdict:
//   • transport-bound (transport ≫ interpreter)  → a cx-native
//     picoev+picohttpparser server (incl. hand-wired TLS) is worth
//     scoping; net.http's blocking accept→bounded-channel→fixed-
//     worker-pool model (vlib server.v) is the bottleneck.
//   • interpreter-bound (interpreter ≫ transport) → a backend swap is
//     wasted; redirect effort to code.eval / env-clone.
//
// This bench makes NO pass/fail assertion — it is a direction-finding
// instrument. Env knobs:
//   ISO_REQUESTS  — measured requests per leg (default 20 000)
//   ISO_WARMUP    — warmup requests per leg  (default 1 000)

module main

import code
import platform as _
import cx
import net
import net.http
import time
import os

const default_requests = 20_000
const default_warmup   = 1_000

fn env_int(name string, dflt int) int {
	v := os.getenv(name)
	if v == '' { return dflt }
	return v.int()
}

fn fmt_us(us f64) string {
	if us >= 1000.0 { return '${us / 1000.0:8.3f}ms' }
	return '${us:8.3f}us'
}

// LegStats — sorted-sample summary for one measurement leg.
struct LegStats {
	mean_us f64
	p50_us  f64
	p99_us  f64
	max_us  f64
	rps_lat f64 // 1 / mean-latency
}

fn summarize(mut samples_us []f64) LegStats {
	samples_us.sort()
	n := samples_us.len
	mut sum_us := 0.0
	for v in samples_us { sum_us += v }
	mean_us := sum_us / f64(n)
	return LegStats{
		mean_us: mean_us
		p50_us:  samples_us[n / 2]
		p99_us:  samples_us[(n * 99) / 100]
		max_us:  samples_us[n - 1]
		rps_lat: if mean_us <= 0.0 { 0.0 } else { 1_000_000.0 / mean_us }
	}
}

fn print_leg(name string, s LegStats) {
	println('  ${name}:')
	println('    mean = ${fmt_us(s.mean_us)}   p50 = ${fmt_us(s.p50_us)}   p99 = ${fmt_us(s.p99_us)}   max = ${fmt_us(s.max_us)}')
	println('    1/mean-latency = ${s.rps_lat:10.1f} req/s')
}

// ─── Transport leg: a trivial V no-op handler (no code.eval) ───────────────────

struct NoopHandler {}

fn (mut h NoopHandler) handle(req http.Request) http.Response {
	mut hdr := http.new_header()
	hdr.add_custom('Content-Type', 'text/plain; charset=utf-8') or {}
	return http.Response{
		status_code:  200
		http_version: '1.1'
		header:       hdr
		body:         'ok'
	}
}

fn run_noop_server(mut srv http.Server) {
	srv.listen_and_serve()
}

fn measure_interpreter(requests int, warmup int) LegStats {
	// Mirror gate-16: register a one-resource service, then loop a
	// fresh client GET against the cached post-register env.
	setup_src := '[?http-service on=http port=0 name="echo"
		[resource [get "/ping"] [response status=200 body="ok"]]]'
	setup_prog := cx.parse_program(setup_src) or { panic('setup parse: ${err}') }
	mut env := code.new_env()
	_ := code.eval(setup_prog.body, mut env) or { panic('setup eval: ${err}') }

	client_src := '[?let [= \$c [?http-client target="cx-test://echo/"]] [?pipe \$c [\$get _ "/ping"]]]'
	client_prog := cx.parse_program(client_src) or { panic('client parse: ${err}') }

	// Sanity probe.
	probe := code.eval(client_prog.body, mut env) or { panic('probe failed: ${err}') }
	if probe !is cx.Element || (probe as cx.Element).name != 'response' {
		panic('probe: expected [response …], got ${probe}')
	}

	for _ in 0 .. warmup {
		_ := code.eval(client_prog.body, mut env) or { panic('warmup failed: ${err}') }
	}

	mut samples_us := []f64{cap: requests}
	for _ in 0 .. requests {
		t0 := time.now()
		_ := code.eval(client_prog.body, mut env) or { panic('measured call failed: ${err}') }
		samples_us << f64(time.since(t0).nanoseconds()) / 1000.0
	}
	return summarize(mut samples_us)
}

// read_one_response drains exactly one HTTP/1.1 response (headers +
// Content-Length body) off a persistent connection. The no-op handler
// emits a tiny, Content-Length-framed response, so in practice one
// read() returns the whole message; the loop is the robust fallback.
fn read_one_response(mut conn net.TcpConn, mut buf []u8) ! {
	mut acc := []u8{}
	for {
		n := conn.read(mut buf) or { return err }
		if n <= 0 { return error('unexpected EOF mid-response') }
		acc << buf[..n]
		s := acc.bytestr()
		if idx := s.index('\r\n\r\n') {
			head := s[..idx].to_lower()
			mut clen := 0
			if ci := head.index('content-length:') {
				clen = head[ci + 15..].all_before('\r\n').trim_space().int()
			}
			if acc.len >= idx + 4 + clen { return }
		}
	}
}

// TransportLegs — net.http measured two ways against the same listener.
struct TransportLegs {
	connect_per_req LegStats // http.get — fresh TCP connection each request
	keep_alive      LegStats // one warm connection reused for every request
}

fn measure_transport(requests int, warmup int) TransportLegs {
	// Bind the real net.http listener on an ephemeral port. addr is
	// rewritten to the bound address (e.g. 127.0.0.1:54321) once
	// listen_and_serve reaches .running, so wait_till_running gives us
	// the port deterministically (server.v:61,73). max_keep_alive_requests
	// = 0 (unlimited) so one warm connection can serve the whole loop
	// (the default 100 would force a reconnect mid-leg).
	mut srv := &http.Server{
		addr:                    'localhost:0'
		handler:                 NoopHandler{}
		show_startup_message:    false
		max_keep_alive_requests: 0
	}
	spawn run_noop_server(mut srv)
	srv.wait_till_running() or { panic('server never reached running state: ${err}') }
	addr := srv.addr
	base := 'http://${addr}/ping'

	// ── Sub-leg A: connect-per-request (http.get) ──────────────────────────────
	probe := http.get(base) or { panic('transport probe failed: ${err}') }
	if probe.status_code != 200 {
		panic('transport probe: expected 200, got ${probe.status_code}')
	}
	for _ in 0 .. warmup {
		_ := http.get(base) or { panic('connect-per-req warmup failed: ${err}') }
	}
	mut cpr_us := []f64{cap: requests}
	for _ in 0 .. requests {
		t0 := time.now()
		_ := http.get(base) or { panic('connect-per-req call failed: ${err}') }
		cpr_us << f64(time.since(t0).nanoseconds()) / 1000.0
	}

	// ── Sub-leg B: keep-alive (one warm connection) ────────────────────────────
	// Isolates net.http's per-request serving cost (parse + worker
	// handoff + wire-write) from the TCP handshake that sub-leg A pays
	// every request. HTTP/1.1 with no Connection header defaults to
	// keep-alive server-side (server.v:247).
	req_bytes := 'GET /ping HTTP/1.1\r\nHost: ${addr}\r\n\r\n'.bytes()
	mut conn := net.dial_tcp(addr) or { panic('keep-alive dial failed: ${err}') }
	mut rbuf := []u8{len: 4096}
	for _ in 0 .. warmup {
		conn.write(req_bytes) or { panic('keep-alive warmup write failed: ${err}') }
		read_one_response(mut conn, mut rbuf) or { panic('keep-alive warmup read failed: ${err}') }
	}
	mut ka_us := []f64{cap: requests}
	for _ in 0 .. requests {
		t0 := time.now()
		conn.write(req_bytes) or { panic('keep-alive write failed: ${err}') }
		read_one_response(mut conn, mut rbuf) or { panic('keep-alive read failed: ${err}') }
		ka_us << f64(time.since(t0).nanoseconds()) / 1000.0
	}
	conn.close() or {}

	srv.stop()
	srv.close()
	return TransportLegs{
		connect_per_req: summarize(mut cpr_us)
		keep_alive:      summarize(mut ka_us)
	}
}

fn main() {
	requests := env_int('ISO_REQUESTS', default_requests)
	warmup   := env_int('ISO_WARMUP', default_warmup)
	assert requests >= 1000, 'request count too low for p99 stability'

	println('CX HTTP backend-direction isolation bench')
	println('  question          : is the ~10k req/s ceiling transport- or interpreter-bound?')
	println('  requests per leg  : ${requests}  (warmup ${warmup})')
	println('  interpreter leg   : code.eval of [?http-client … | get("/ping")] in-process (no socket)')
	println('  transport leg     : net.http listener on localhost:0, trivial V no-op handler (no code.eval)')
	println('')

	interp := measure_interpreter(requests, warmup)
	trans  := measure_transport(requests, warmup)

	print_leg('interpreter leg (code.eval + env.clone, no socket)', interp)
	println('')
	print_leg('transport leg — connect-per-request (http.get, fresh TCP each req)', trans.connect_per_req)
	println('')
	print_leg('transport leg — keep-alive (one warm conn: net.http parse+pool+write)', trans.keep_alive)
	println('')

	// Verdict is based on the KEEP-ALIVE transport leg: it isolates
	// net.http's per-request serving cost from the TCP handshake (which
	// any backend pays equally for non-keep-alive clients and so is not
	// a backend differentiator). Both legs are serial single-in-flight
	// loops, so their mean per-request wall-clocks are directly
	// comparable. The connect-per-request leg is reported for context
	// (it shows the handshake tax real short-lived clients pay).
	ka := trans.keep_alive
	total_us := interp.mean_us + ka.mean_us
	interp_pct := if total_us <= 0.0 { 0.0 } else { 100.0 * interp.mean_us / total_us }
	trans_pct  := if total_us <= 0.0 { 0.0 } else { 100.0 * ka.mean_us / total_us }
	println('  per-request mean (warm conn): interpreter ${fmt_us(interp.mean_us)}  +  transport ${fmt_us(ka.mean_us)}')
	println('  share of combined single-request cost:')
	println('    interpreter : ${interp_pct:5.1f} %')
	println('    transport   : ${trans_pct:5.1f} %')
	ratio := if interp.mean_us <= 0.0 { 0.0 } else { ka.mean_us / interp.mean_us }
	println('    transport / interpreter ratio : ${ratio:.2f}x  (keep-alive)')
	handshake_us := trans.connect_per_req.mean_us - ka.mean_us
	println('    TCP-handshake tax (connect-per-req − keep-alive) : ${fmt_us(handshake_us)} / req')
	println('')

	verdict := if ka.mean_us > interp.mean_us {
		'TRANSPORT-BOUND — net.http per-request serving cost dominates even on a warm connection; a cx-native picoev+picohttpparser server is worth scoping (TLS hand-wired).'
	} else {
		'INTERPRETER-BOUND — code.eval + env.clone dominates; a backend swap is wasted, redirect to eval/env-clone.'
	}
	println('  VERDICT: ${verdict}')
}
