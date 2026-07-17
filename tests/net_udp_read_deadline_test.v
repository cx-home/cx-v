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
	f := os.join_path(os.temp_dir(), 'cx_udl_${os.getpid()}_${src.len}.cx')
	os.write_file(f, src) or { panic('write: ${err}') }
	defer {
		os.rm(f) or {}
	}
	return os.execute('timeout 15 ${cx_bin_udl()} --allow-net=127.0.0.1 ${f} 2>&1')
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
// not break live traffic. The test process sends after 150ms; the child's
// 2000ms budget comfortably covers it.
fn test_udp_deadline_does_not_break_delivery() {
	port := pick_port_udl(3)
	mut sent := false
	spawn fn (port int, mut_sent &bool) {
		time.sleep(150 * time.millisecond)
		mut c := net.dial_udp('127.0.0.1:${port}') or { return }
		c.write_string('$GPRMC,live') or {}
		c.close() or {}
		unsafe {
			*mut_sent = true
		}
	}(port, &sent)
	r := run_prog_udl("[?lib 'cx-stdlib/net' :as net]
[?lib 'cx-stdlib/bytes' :as b]
[?let [= \$s [\$net:listen-udp \"udp://127.0.0.1:${port}\" {}]]
 [?let [= \$z [\$net:set-deadline \$s {read: 2000}]]
  [?let [= \$d [?else [\$net:recv-from \$s 2048] \"TIMED-OUT\"]]
   \$d]]]
")
	assert r.exit_code == 0, 'delivery run failed: ${r.output}'
	assert !r.output.contains('TIMED-OUT'), 'datagram lost under an armed deadline: ${r.output}'
	assert r.output.contains('GPRMC'), 'datagram content missing: ${r.output}'
	assert sent, 'test sender never fired'
}
