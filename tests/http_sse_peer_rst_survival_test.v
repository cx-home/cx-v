module main

import os
import testenv
import net
import time

// http_sse_peer_rst_survival_test.v — a server must survive a subscriber that
// vanishes between pushes.
//
// The failure this pins: SSE holds fds open and pushes to them asynchronously
// (`cx_sse_topic_publish` / `xap_sse_push` / `send_all` write with raw
// C.write). A subscriber that disconnects sends FIN; the NEXT push into that
// fd is accepted by the kernel but answered with RST; the push AFTER that
// raises SIGPIPE — whose default action terminates the process SILENTLY (no V
// panic, no crash report; the marine helm died this way every few minutes
// under client reconnect churn). The fix ignores SIGPIPE at the listener
// (transport.picoev new() + SO_NOSIGPIPE on accepted fds), so the write
// reports EPIPE and the publish path drops the fd.
//
// Asserts:
//   1. subscriber closes → two pushes (FIN-write, then RST-write) → the server
//      PROCESS is still alive and answers /ping.
//   2. the dead fd was reaped: a later publish reports pushed=0.

fn cx_bin_rst() string {
	return testenv.cx_bin()
}

fn pick_port_rst() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 29300 + int(salt)
}

fn rst_server_prog(port int) string {
	return "[?lib 'cx-stdlib/http' :as http]\n" +
		'[?def h impure (\$req)\n' +
		'  [?let [= \$p [\$text \$req@path]]\n' +
		'    [?if [= \$p "/events"]\n' +
		'      [then [sse-subscribe topic="t" [event data="hello"]]]\n' +
		'      [else [?if [= \$p "/push"]\n' +
		'        [then [?let [= \$n [\$http:sse-publish "t" [event data="beat"]]]\n' +
		'                [response status=200 [body [\$concat "pushed=" [\$text \$n]]]]]]\n' +
		'        [else [response status=200 [body "pong"]]]]]]]]\n' +
		'[\$http:serve "tcp://127.0.0.1:${port}" \$h {block: true}]\n'
}

fn rst_get(port int, path string) string {
	mut c := net.dial_tcp('127.0.0.1:${port}') or { return '' }
	defer { c.close() or {} }
	c.write_string('GET ${path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n') or { return '' }
	c.set_read_timeout(4 * time.second)
	mut raw := []u8{}
	mut buf := []u8{len: 4096}
	for {
		n := c.read(mut buf) or { break }
		if n <= 0 {
			break
		}
		raw << buf[..n]
		if raw.len > 65536 {
			break
		}
	}
	return raw.bytestr()
}

fn test_sse_peer_rst_survival() {
	port := pick_port_rst()
	prog := os.join_path(os.temp_dir(), 'cx_sse_rst_${os.getpid()}.cx')
	os.write_file(prog, rst_server_prog(port)) or { panic('write: ${err}') }
	defer { os.rm(prog) or {} }
	out_file := '/tmp/cx-sse-rst.${port}.out'
	pid_s := os.execute('${cx_bin_rst()} --allow-net ${prog} >${out_file} 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx sse server')
		return
	}
	pid := pid_s.output.trim_space()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
		os.rm(out_file) or {}
	}

	mut up := false
	for _ in 0 .. 50 {
		mut c := net.dial_tcp('127.0.0.1:${port}') or {
			time.sleep(100 * time.millisecond)
			continue
		}
		c.close() or {}
		up = true
		break
	}
	assert up, 'cx sse server never came up on ${port}'

	// subscribe, confirm registration via the initial frame, then VANISH
	mut a := net.dial_tcp('127.0.0.1:${port}') or {
		assert false, 'could not open SSE client'
		return
	}
	a.write_string('GET /events HTTP/1.1\r\nHost: x\r\n\r\n') or {}
	a.set_read_timeout(4 * time.second)
	mut raw := []u8{}
	mut buf := []u8{len: 4096}
	for {
		n := a.read(mut buf) or { break }
		if n <= 0 {
			break
		}
		raw << buf[..n]
		if raw.bytestr().contains('data: hello') {
			break
		}
	}
	assert raw.bytestr().contains('data: hello'), 'subscriber never registered'
	a.close() or {}

	// push #1 lands on the FIN'd socket (kernel accepts, peer answers RST);
	// push #2 writes into the RST'd socket — pre-fix this is the SIGPIPE kill.
	rst_get(port, '/push')
	time.sleep(200 * time.millisecond)
	rst_get(port, '/push')
	time.sleep(200 * time.millisecond)

	// (1) the server process survived and still serves
	alive := os.execute('kill -0 ${pid}')
	assert alive.exit_code == 0, 'server process died after pushing to an RST\'d subscriber (SIGPIPE regression)'
	pong := rst_get(port, '/ping')
	assert pong.contains('pong'), 'server not serving after RST push: "${pong}"'

	// (2) the dead fd was reaped from the topic — a fresh publish reaches 0
	final := rst_get(port, '/push')
	assert final.contains('pushed=0'), 'dead subscriber fd not reaped: "${final}"'
}
