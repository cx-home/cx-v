// §11.6 Gate 16 — HTTP service throughput + p99 latency.
//
// Threshold (BOTH must hold, spec/code.md §11.4.4):
//   - throughput ≥ 10 000 req/s
//   - p99 per-request latency ≤ 10 ms
//
// PROTOCOL (OWNER-RULED, #805 gate-truth batch, 2026-08-13, option
// (b) of the Q5a gate-16 letter): the gate measures a REAL
// `[?http-service]` listener under the spec's external `wrk` driver —
// concurrency 64, 3-minute steady state — exactly as §11.4.4 writes
// it. The prior in-process request-loop form (whose rationale block
// lived here) is SUPERSEDED: it measured the dispatch substrate, not
// the service. RIDER (same ruling): "skipping gates silently is
// forbidden" — a missing `wrk`, a service that fails to come up, or
// unparseable driver output is a LOUD exit-1 RED, never a skip.
//
// Mechanics:
//   1. Refuse loudly unless `wrk` is on PATH (the ruled rider).
//   2. Write the trivial echo-service fixture ([?http-service] with
//      one GET resource, [block true], real 127.0.0.1 port) and
//      spawn it under the repo's cx binary with --allow-net.
//   3. Poll TCP readiness (10 s cap), then run
//      `wrk -t<threads> -c64 -d<dur> --latency http://127.0.0.1:P/ping`.
//   4. Parse Requests/sec + the 99% latency row from wrk's output,
//      apply BOTH thresholds, kill the service, exit accordingly.
//
// Env overrides:
//   GATE16_DURATION_SEC — steady-state seconds (default 180 = the
//                         spec's 3-minute form; smoke runs may
//                         shorten, the DEFAULT is the gate).
//   GATE16_PORT         — listener port  (default 39061)
//   GATE16_THREADS      — wrk -t         (default 8)
//
// Spec-citation drift noted for the gate-registry re-home (NOT
// silently amended here): §11.4.4's *Inputs*/*Tool* lines cite
// retired-era artifacts (`cxl_http_service_bench.v`,
// `run_bench_json.cx (cxl_http_payload section)`, `check_perf_gate.sh`) that
// do not exist; the PROTOCOL rows (wrk, c=64, 3 min, both
// thresholds) are what this runner implements verbatim. wrk's
// native output is text (its JSON needs a lua sidecar) — the
// citation row rides the same re-home note.

module main

import net
import os
import time

const threshold_rps = 10_000.0
const threshold_p99_ms = 10.0

fn env_int(name string, dflt int) int {
	v := os.getenv(name)
	if v == '' {
		return dflt
	}
	return v.int()
}

fn fail(msg string) {
	eprintln('gate-16 FAIL — ${msg}')
	exit(1)
}

// parse_latency_ms parses a wrk latency figure like `1.23ms`,
// `456.00us`, `1.20s` into milliseconds.
fn parse_latency_ms(tok string) ?f64 {
	t := tok.trim_space()
	if t.ends_with('us') {
		return t[..t.len - 2].f64() / 1000.0
	}
	if t.ends_with('ms') {
		return t[..t.len - 2].f64()
	}
	if t.ends_with('s') {
		return t[..t.len - 1].f64() * 1000.0
	}
	return none
}

fn main() {
	duration := env_int('GATE16_DURATION_SEC', 180)
	port := env_int('GATE16_PORT', 39061)
	threads := env_int('GATE16_THREADS', 8)

	// 1 — the ruled rider: no tool, no gate, LOUDLY.
	wrk_path := os.find_abs_path_of_executable('wrk') or {
		fail('`wrk` not found on PATH. The ruled §11.4.4 protocol drives the gate through wrk (owner ruling (b), 2026-08-13) and skipping gates silently is FORBIDDEN — install wrk (e.g. `brew install wrk`) and re-run.')
		return
	}

	repo := os.dir(os.dir(os.dir(os.dir(@FILE))))
	cx_bin := os.join_path(repo, 'vcx', 'target', 'cx')
	if !os.exists(cx_bin) {
		fail('cx binary not built at ${cx_bin} (run `make -C vcx build` / the bench-code-http target depends on build-vcx)')
	}

	// 2 — the trivial echo service on a real listener.
	fixture := '[?http-service\n' + '   [name "gate16-echo"]\n' + '   [on http]\n' +
		'   [port ${port}]\n' + '   [block true]\n' + '   [bind-host "127.0.0.1"]\n' +
		'   [resource [GET "/ping"]\n' + '     [response status=200 [body "ok"]]]]\n'
	tmp := os.join_path(os.temp_dir(), 'gate16_echo_${os.getpid()}.cx')
	os.write_file(tmp, fixture) or { fail('write fixture: ${err}') }
	defer {
		os.rm(tmp) or {}
	}

	println('CX §11.6 gate-16 HTTP-service-throughput bench (wrk protocol, ruled (b))')
	println('  service          : real [?http-service] listener @ 127.0.0.1:${port}')
	println('  driver           : ${wrk_path} -t${threads} -c64 -d${duration}s --latency')
	println('  thresholds       : ≥ ${threshold_rps} req/s AND p99 ≤ ${threshold_p99_ms} ms')

	mut svc := os.new_process(cx_bin)
	svc.set_args(['--allow-net=127.0.0.1', tmp])
	svc.set_redirect_stdio()
	svc.run()
	defer {
		svc.signal_kill()
	}

	// 3 — readiness poll (10 s cap).
	mut ready := false
	for _ in 0 .. 100 {
		if mut c := net.dial_tcp('127.0.0.1:${port}') {
			c.close() or {}
			ready = true
			break
		}
		time.sleep(100 * time.millisecond)
		if !svc.is_alive() {
			break
		}
	}
	if !ready {
		out := svc.stdout_slurp() + svc.stderr_slurp()
		fail('service never became ready on :${port} (loud, never a skip). service output:\n${out}')
	}

	// 4 — the wrk steady-state run.
	cmd := '${os.quoted_path(wrk_path)} -t${threads} -c64 -d${duration}s --latency http://127.0.0.1:${port}/ping'
	println('  running          : ${cmd}')
	res := os.execute(cmd)
	if res.exit_code != 0 {
		fail('wrk exited ${res.exit_code}:\n${res.output}')
	}
	println(res.output)

	mut rps := -1.0
	mut p99_ms := -1.0
	for line in res.output.split_into_lines() {
		l := line.trim_space()
		if l.starts_with('Requests/sec:') {
			rps = l.all_after(':').trim_space().f64()
		}
		if l.starts_with('99%') {
			tok := l.all_after('99%').trim_space()
			p99_ms = parse_latency_ms(tok) or { -1.0 }
		}
	}
	if rps < 0 || p99_ms < 0 {
		fail('could not parse Requests/sec + 99% latency from wrk output (loud, never a skip)')
	}

	pass_rps := rps >= threshold_rps
	pass_p99 := p99_ms <= threshold_p99_ms
	println('')
	println('  requests/sec     : ${rps:10.1f}  (threshold ${threshold_rps})  ${if pass_rps { 'PASS' } else { 'FAIL' }}')
	println('  p99 latency      : ${p99_ms:10.3f} ms (threshold ${threshold_p99_ms} ms)  ${if pass_p99 { 'PASS' } else { 'FAIL' }}')
	if pass_rps && pass_p99 {
		println('gate-16 PASS  (${rps:.0f} req/s, p99 ${p99_ms:.3f} ms over ${duration}s steady state)')
		exit(0)
	}
	fail('thresholds not met (${rps:.0f} req/s, p99 ${p99_ms:.3f} ms)')
}
