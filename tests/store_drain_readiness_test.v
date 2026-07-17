module main

import os
import testenv
import time

// store_drain_readiness_test.v — #233: readiness probes THROUGH graceful drain.
// Pre-#233, the first SIGTERM closed the listener at once, so a load-balancer
// readiness probe got connection-refused and never observed the drain state. Now
// the daemon keeps the listener open for the drain grace ([timeouts drain-ms]):
// on signal it flips readiness false, still answers /ready ([accepting false]) and
// /health, refuses data ops with 503, then closes and drains after the grace.
//
// This spawns `cx store-serve`, sends SIGTERM, and — WITHIN the grace window —
// asserts /ready connects and reports accepting=false (not connection-refused) and
// a data op returns 503. Then it confirms the daemon exits after the grace.

fn dr_cx_binary() string {
	return testenv.cx_bin()
}

fn dr_pick_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 26900 + int(salt)
}

fn test_drain_readiness_probe_during_grace() {
	if os.execute('command -v curl').exit_code != 0 {
		eprintln('SKIP: curl not available for drain-readiness test')
		return
	}
	port := dr_pick_port()
	dir := os.join_path(os.temp_dir(), 'cx_drain_${port}')
	os.mkdir_all(dir) or { panic('mkdir: ${err}') }
	defer {
		os.rmdir_all(dir) or {}
	}
	cfg := os.join_path(dir, 'svc.cx')
	// generous 4s grace so the probe fires comfortably inside the window.
	os.write_file(cfg, '[cxstore-service [bind addr="127.0.0.1:${port}"] [timeouts drain-ms=4000] [stores [store name="t" url="mem://"]]]') or {
		panic('write cfg: ${err}')
	}
	srv_out := os.join_path(dir, 'srv.out')
	allow := '--allow-net=127.0.0.1:${port} --allow-read=${dir}'
	pid_s := os.execute('${dr_cx_binary()} store-serve ${allow} --config ${cfg} >${srv_out} 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx store-serve')
		return
	}
	pid := pid_s.output.trim_space().int()
	mut killed := false
	defer {
		if !killed {
			os.execute('kill ${pid} 2>/dev/null')
		}
	}
	time.sleep(900 * time.millisecond) // let it bind + mark ready

	// Sanity: before drain, /ready is accepting=true.
	pre := os.execute('curl -s --max-time 2 http://127.0.0.1:${port}/cx-store/v1/ready')
	assert pre.output.contains('[accepting true]'), 'before drain /ready must be accepting=true; got: ${pre.output} | srv: ${os.read_file(srv_out) or {
		''
	}}'

	// Send the FIRST SIGTERM → graceful drain begins; listener stays open for grace.
	os.execute('kill -TERM ${pid}')
	killed = true
	time.sleep(400 * time.millisecond) // inside the 4s grace window

	// #233 core: the readiness probe still CONNECTS and observes the draining state
	// (accepting=false), rather than connection-refused.
	ready := os.execute('curl -s --max-time 2 http://127.0.0.1:${port}/cx-store/v1/ready')
	srv_log := os.read_file(srv_out) or { '' }
	assert ready.exit_code == 0, 'readiness probe during drain must connect (not refused) (#233); curl exit ${ready.exit_code}; srv: ${srv_log}'
	assert ready.output.contains('[accepting false]'), 'during drain /ready must report accepting=false; got: ${ready.output}; srv: ${srv_log}'

	// A data op during drain is refused with 503 (not accepted, not refused).
	code := os.execute('curl -s -o /dev/null -w "%{http_code}" --max-time 2 -X POST http://127.0.0.1:${port}/cx-store/v1/t/list')
	assert code.output.trim_space() == '503', 'a data op during drain must return 503; got HTTP ${code.output}; srv: ${srv_log}'

	// After the grace elapses the daemon exits: the listener closes and the probe is
	// refused (process gone).
	time.sleep(4500 * time.millisecond)
	gone := os.execute('curl -s --max-time 2 http://127.0.0.1:${port}/cx-store/v1/ready')
	assert gone.exit_code != 0, 'after the drain grace the daemon must have exited (probe should now fail); got: ${gone.output}'
}
