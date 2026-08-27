module main

import net
import os
import testenv
import time

// net_udp_read_deadline_test.v — net.md §3.7 marks set-deadline ✅ for udp and
// §3.2's dial opt {read-deadline} applies to dial generally; the udp half was
// a spec-compliance gap: recv/recv-from ignored the stored budget and blocked
// forever on a silent peer. Field motivation: the marine NMEA ingest must
// detect a silent gateway (flip instruments to STALE, pace reconnects) — a
// recv that can block indefinitely makes staleness undetectable.
//
// Tests (child = the cx binary, the real product surface):
//   1. bound socket + set-deadline {read: 400} + recv-from with no sender →
//      cx-err:CXER4507 E_NET_TIMEOUT, within ~0.4-5s (not a hang);
//   2. dial opt {read-deadline: 400} on dial-udp + recv → same;
//   3. a datagram that ARRIVES within the budget is delivered normally
//      (the deadline must not break live traffic).

fn cx_bin_udl() string {
	return testenv.cx_bin()
}

fn run_prog_udl(src string) os.Result {
	return run_prog_udl_granted(src, '')
}

// run_prog_udl_granted runs the child with EXTRA grants beyond --allow-net.
// The delivery case needs --allow-write so the child can post its readiness
// file; the two deadline cases take no extra grant, so the surface each test
// exercises stays the surface it pins.
fn run_prog_udl_granted(src string, extra_grants string) os.Result {
	f := os.join_path(os.temp_dir(), 'cx_udl_${os.getpid()}_${src.len}.cx')
	os.write_file(f, src) or { panic('write: ${err}') }
	defer {
		os.rm(f) or {}
	}
	return os.execute('timeout 15 ${cx_bin_udl()} --allow-net=127.0.0.1 ${extra_grants} ${f} 2>&1')
}

fn pick_port_udl(salt int) int {
	return 29500 + int((u64(os.getpid()) * u64(2654435761) + u64(salt)) % 200)
}

// 1. Bound datagram socket, deadline via set-deadline, silent peer → CXER4507.
fn test_udp_recv_from_deadline_raises_timeout() {
	port := pick_port_udl(1)
	t0 := time.now()
	r := run_prog_udl("[?lib 'cx-stdlib/net' :as net]
[?let [= \$s [\$net:listen-udp \"udp://127.0.0.1:${port}\" {}]]
 [?let [= \$z [\$net:set-deadline \$s {read: 400}]]
  [?else [\$net:recv-from \$s 2048] \"TIMED-OUT\"]]]
")
	elapsed := time.since(t0)
	assert r.exit_code == 0, 'recv-from deadline run failed: ${r.output}'
	assert r.output.contains('TIMED-OUT'), 'expected a CXER4507 raise, got: ${r.output}'
	assert elapsed < 10 * time.second, 'recv-from blocked past its deadline (${elapsed})'
}

// 2. The §3.2 dial opt arms the same budget on a connected datagram socket.
fn test_udp_dial_read_deadline_opt() {
	port := pick_port_udl(2)
	t0 := time.now()
	r := run_prog_udl("[?lib 'cx-stdlib/net' :as net]
[?let [= \$s [\$net:dial-udp \"udp://127.0.0.1:${port}\" {read-deadline: 400}]]
 [?else [\$net:recv \$s 2048] \"TIMED-OUT\"]]
")
	elapsed := time.since(t0)
	assert r.exit_code == 0, 'dial-udp deadline run failed: ${r.output}'
	assert r.output.contains('TIMED-OUT'), 'expected a CXER4507 raise, got: ${r.output}'
	assert elapsed < 10 * time.second, 'recv blocked past its deadline (${elapsed})'
}

// 3. A datagram arriving within the budget is delivered — the deadline must
// not break live traffic.
//
// HANDOFF (#1055): this used to sleep a flat 150 ms and then send, betting
// that the child had reached listen-udp by then. That is not a property of
// the thing under test — it is a property of how fast `cx` boots, and when
// #1055 pushed startup from 70 ms to 530 ms the bet lost and this case went
// deterministically red while UDP delivery was perfectly healthy. A timing
// bet that reds on an unrelated regression is a bad oracle in both
// directions: it also passes silently if the child never binds at all and
// the datagram merely happens to be late.
//
// The handoff is now an ACKNOWLEDGEMENT, not a guess. The child posts a
// readiness file AFTER listen-udp has bound and AFTER set-deadline has armed
// the budget, and only then does the sender fire. What the case pins is
// therefore unchanged and, if anything, tighter: the datagram is sent into a
// socket that is already bound and already under an armed read deadline.
//
// Why a file and not a port probe: probing by binding the port ourselves
// works (measured: it flips to EADDRINUSE within ~20 ms of the child's bind)
// but the probe socket briefly HOLDS the port, so a probe landing in the
// child's bind window makes the child's listen-udp fail. That trades a
// startup race for a rarer, nastier one. The readiness file touches nothing
// the test is about.
//
// The wait is bounded and, on timeout, refuses BY NAME — a child that never
// binds must fail as "never signalled readiness", never as a lost datagram.
const udl_ready_timeout_ms = 10000

fn test_udp_deadline_does_not_break_delivery() {
	port := pick_port_udl(3)
	tmp := os.temp_dir()
	ready := os.join_path(tmp, 'cx_udl_ready_${os.getpid()}_${port}')
	os.rm(ready) or {}
	defer {
		os.rm(ready) or {}
	}
	mut sent := false
	mut ready_seen := false
	spawn fn (port int, ready string, mut_sent &bool, mut_ready &bool) {
		// Wait for the child's own acknowledgement that it is bound and armed.
		mut waited := 0
		for waited < udl_ready_timeout_ms {
			if os.exists(ready) {
				unsafe {
					*mut_ready = true
				}
				break
			}
			time.sleep(5 * time.millisecond)
			waited += 5
		}
		if !os.exists(ready) {
			return
		}
		mut c := net.dial_udp('127.0.0.1:${port}') or { return }
		c.write_string('$GPRMC,live') or {}
		c.close() or {}
		unsafe {
			*mut_sent = true
		}
	}(port, ready, &sent, &ready_seen)
	r := run_prog_udl_granted("[?lib 'cx-stdlib/net' :as net]
[?lib 'cx-stdlib/io' :as io]
[?let [= \$s [\$net:listen-udp \"udp://127.0.0.1:${port}\" {}]]
 [?let [= \$z [\$net:set-deadline \$s {read: 2000}]]
  [?let [= \$ack [\$io:write-file \"${ready}\" \"bound\"]]
   [?let [= \$d [?else [\$net:recv-from \$s 2048] \"TIMED-OUT\"]]
    \$d]]]]
", '--allow-write')
	assert r.exit_code == 0, 'delivery run failed: ${r.output}'
	assert ready_seen, 'child never signalled readiness within ${udl_ready_timeout_ms}ms — it did not reach listen-udp + set-deadline, so this is a bind/startup failure, not a delivery failure: ${r.output}'
	assert !r.output.contains('TIMED-OUT'), 'datagram lost under an armed deadline: ${r.output}'
	assert r.output.contains('GPRMC'), 'datagram content missing: ${r.output}'
	assert sent, 'test sender never fired'
}
