module main

import os
import testenv
import time
import net

// net_read_deadline_test.v — #56: on a connected socket whose peer never
// sends EOF (a continuous / held-open stream), the read-until-EOF forms
// (`read-all`, `line-iter`) MUST honor a configured read-deadline and surface
// CXER4507 instead of blocking forever. `read-line` honors it too. The deadline
// may come from the dial opts (`{read-deadline: ms}`) OR from `set-deadline`
// (`{read|both: ms}`). The bounded `read-bytes` is unaffected (a short read on
// timeout is its documented contract, not a hang) and a normal EOF still
// returns the accumulated bytes.
//
// The test fails RED against the pre-fix build, which dropped the dial opt and
// no-op'd set-deadline: read-all would block until the server closed (~the hold
// time) rather than returning at ~the deadline, and would yield the (empty)
// data through [?else] instead of the CXER4507 fallback.

fn cx_bin_rd() string {
	return testenv.cx_bin()
}

// Disjoint PID + nanosecond-salted band (26700-26799) so concurrent gate
// processes don't collide on a port.
fn pick_port_rd() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 26700 + int(salt)
}

fn write_tmp_rd(name string, content string) string {
	p := os.join_path(os.temp_dir(), name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

// A one-shot server that accepts, optionally writes a teaser line, then HOLDS
// the connection open for `hold_ms` WITHOUT sending EOF — modeling an always-on
// stream (the issue's NMEA gateway). The hold outlasts the client's deadline so
// a working deadline returns well before the close.
fn spawn_holding_server(mut l net.TcpListener, teaser string, hold_ms int) thread {
	return spawn fn (mut l net.TcpListener, teaser string, hold_ms int) {
		mut c := l.accept() or {
			l.close() or {}
			return
		}
		if teaser != '' {
			c.write(teaser.bytes()) or {}
		}
		time.sleep(hold_ms * time.millisecond)
		c.close() or {}
		l.close() or {}
	}(mut l, teaser, hold_ms)
}

// ── read-all honors a dial-opt read-deadline on a never-EOF stream ───────────
fn test_read_all_dial_deadline_does_not_hang() {
	port := pick_port_rd()
	mut listener := net.listen_tcp(.ip, '127.0.0.1:${port}') or {
		eprintln('SKIP: cannot bind 127.0.0.1:${port}: ${err}')
		return
	}
	listener.set_accept_timeout(5 * time.second)
	srv := spawn_holding_server(mut listener, 'teaser-line\n', 6000)

	prog := write_tmp_rd('cx_rd_all_dial.cx', "[?lib 'cx-stdlib/net' :as net]\n" +
		'[?def run impure ()\n' +
		'  [?let [= \$c [\$net:dial-tcp "tcp://127.0.0.1:${port}" {read-deadline: 500}]]\n' +
		'   [?else [\$net:read-all \$c {}] "TIMED-OUT"]]]\n' + '[run]\n')

	t0 := time.now()
	r := os.execute('${cx_bin_rd()} --allow-net=127.0.0.1:${port} ${prog}')
	elapsed_ms := (time.now() - t0).milliseconds()
	srv.wait()
	os.rm(prog) or {}

	assert r.exit_code == 0, 'exit ${r.exit_code}: ${r.output}'
	// Working deadline → CXER4507 → the [?else] fallback. The teaser bytes are
	// NOT returned (read-all could not drain to EOF; the deadline is an error,
	// not a successful partial read).
	assert r.output.contains('TIMED-OUT'), 'read-all should hit the deadline and take the fallback, got: ${r.output}'
	// Returned at ~the 500ms deadline, NOT at the server's 6s hold (pre-fix hang).
	assert elapsed_ms < 4000, 'read-all should return at ~the deadline (<4s), took ${elapsed_ms}ms: ${r.output}'
}

// ── read-all honors a deadline set via set-deadline (not dial opts) ──────────
fn test_read_all_set_deadline_does_not_hang() {
	port := pick_port_rd()
	mut listener := net.listen_tcp(.ip, '127.0.0.1:${port}') or {
		eprintln('SKIP: cannot bind 127.0.0.1:${port}: ${err}')
		return
	}
	listener.set_accept_timeout(5 * time.second)
	srv := spawn_holding_server(mut listener, '', 6000)

	prog := write_tmp_rd('cx_rd_all_setdl.cx', "[?lib 'cx-stdlib/net' :as net]\n" +
		'[?def run impure ()\n' +
		'  [?let [= \$c [\$net:dial-tcp "tcp://127.0.0.1:${port}" {}]]\n' +
		'   [?let [= \$_ [\$net:set-deadline \$c {read: 500}]]\n' +
		'    [?else [\$net:read-all \$c {}] "TIMED-OUT"]]]]\n' + '[run]\n')

	t0 := time.now()
	r := os.execute('${cx_bin_rd()} --allow-net=127.0.0.1:${port} ${prog}')
	elapsed_ms := (time.now() - t0).milliseconds()
	srv.wait()
	os.rm(prog) or {}

	assert r.exit_code == 0, 'exit ${r.exit_code}: ${r.output}'
	assert r.output.contains('TIMED-OUT'), 'set-deadline read-all should hit the deadline, got: ${r.output}'
	assert elapsed_ms < 4000, 'set-deadline read-all should return at ~the deadline (<4s), took ${elapsed_ms}ms: ${r.output}'
}

// ── line-iter honors a read-deadline on a never-EOF stream ───────────────────
fn test_line_iter_deadline_raises_not_hangs() {
	port := pick_port_rd()
	mut listener := net.listen_tcp(.ip, '127.0.0.1:${port}') or {
		eprintln('SKIP: cannot bind 127.0.0.1:${port}: ${err}')
		return
	}
	listener.set_accept_timeout(5 * time.second)
	// Send one complete line, then hold — line-iter yields the first line, then
	// the next pull must lapse the deadline rather than block forever.
	srv := spawn_holding_server(mut listener, 'first-line\n', 6000)

	prog := write_tmp_rd('cx_rd_lineiter.cx', "[?lib 'cx-stdlib/net' :as net]\n" +
		'[?def run impure ()\n' +
		'  [?let [= \$c [\$net:dial-tcp "tcp://127.0.0.1:${port}" {read-deadline: 500}]]\n' +
		'   [?else [?for [in \$l [\$net:line-iter \$c]] [yield \$l]] "ITER-TIMED-OUT"]]]\n' +
		'[run]\n')

	t0 := time.now()
	r := os.execute('${cx_bin_rd()} --allow-net=127.0.0.1:${port} ${prog}')
	elapsed_ms := (time.now() - t0).milliseconds()
	srv.wait()
	os.rm(prog) or {}

	assert r.exit_code == 0, 'exit ${r.exit_code}: ${r.output}'
	assert r.output.contains('ITER-TIMED-OUT'), 'line-iter should hit the deadline and take the fallback, got: ${r.output}'
	assert elapsed_ms < 4000, 'line-iter should return at ~the deadline (<4s), took ${elapsed_ms}ms: ${r.output}'
}

// ── regression: a normal EOF still returns the accumulated bytes ─────────────
fn test_read_all_normal_eof_still_returns() {
	port := pick_port_rd()
	mut listener := net.listen_tcp(.ip, '127.0.0.1:${port}') or {
		eprintln('SKIP: cannot bind 127.0.0.1:${port}: ${err}')
		return
	}
	listener.set_accept_timeout(5 * time.second)
	// Send data then CLOSE immediately (clean EOF). No deadline configured.
	srv := spawn_holding_server(mut listener, 'payload-bytes', 0)

	prog := write_tmp_rd('cx_rd_all_eof.cx', "[?lib 'cx-stdlib/net' :as net]\n" +
		'[?def run impure ()\n' +
		'  [?let [= \$c [\$net:dial-tcp "tcp://127.0.0.1:${port}" {}]]\n' +
		'   [\$net:read-all \$c {}]]]\n' + '[run]\n')

	r := os.execute('${cx_bin_rd()} --allow-net=127.0.0.1:${port} ${prog}')
	srv.wait()
	os.rm(prog) or {}

	assert r.exit_code == 0, 'exit ${r.exit_code}: ${r.output}'
	assert r.output.contains('payload-bytes'), 'read-all should return the bytes read up to a clean EOF, got: ${r.output}'
}
