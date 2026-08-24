module main

import os
import testenv
import time
import net

// http_sse_real_test.v — BEHAVIORAL conformance for §3.6 SSE over REAL
// loopback sockets. The pure framing/parsing codec was already enforced; this
// is the TDD red test for the LIVE held-open transport that http.md §3.6 had
// deferred: send-event/heartbeat must FLUSH real bytes, sse-connect must open a
// real streaming GET, sse-events must read live frames. It MUST fail against the
// synthetic shapes (send-event→null-without-flush, sse-events over a buffered
// `wire=` attr) and pass only once the transport is real.
//
// Two legs:
//   - server push: a cx [$http:sse] server pushes events; a raw-socket V client
//     reads the event-stream and sees the framed events.
//   - client read: a raw-socket V event-stream server pushes events; a cx
//     [$http:sse-connect] + [?for [$http:sse-events]] client collects them.

fn cx_binary() string {
	return testenv.cx_bin()
}

// Disjoint PID + nanosecond-salted band (26000-26099) so the concurrent
// `v test vcx/tests/` gate processes don't collide on a port.
fn pick_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 26000 + int(salt)
}

fn write_tmp(name string, content string) string {
	p := os.join_path(os.temp_dir(), name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

// ── server push leg: cx is the SSE server, a raw V client reads the stream ──
fn test_http_sse_server_push() {
	port := pick_port()
	// cx server: accept one connection, promote it to an SSE stream, push two
	// events, then close. (A single exchange is enough to prove the transport.)
	prog := write_tmp('cx_sse_srv.cx', '[?lib \'cx-stdlib/http\' :as http]\n' +
		'[?let [= \$srv [\$http:listen "tcp://127.0.0.1:${port}" {}]]\n' +
		'  [?for [in \$ex [\$http:accept-iter \$srv]] [take 1]\n' +
		'    [yield [?let [= \$s [\$http:sse \$ex {}]]\n' +
		'      [?let [= \$e1 [\$http:send-event \$s [event id="1" data="hello"]]]\n' +
		'        [?let [= \$e2 [\$http:send-event \$s [event id="2" data="world"]]]\n' +
		'          [\$http:close \$s]]]]]]]\n')
	out_file := '/tmp/cx-sse-srv.${port}.out'
	pid_s := os.execute('${cx_binary()} --allow-net ${prog} >${out_file} 2>&1 & echo \$!')
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(400 * time.millisecond)

	mut resp := ''
	for _ in 0 .. 40 {
		mut c := net.dial_tcp('127.0.0.1:${port}') or {
			time.sleep(100 * time.millisecond)
			continue
		}
		c.write_string('GET /stream HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n\r\n') or {}
		c.set_read_timeout(3 * time.second)
		mut sink := []u8{}
		mut buf := []u8{len: 4096}
		for {
			n := c.read(mut buf) or { break }
			if n <= 0 {
				break
			}
			sink << buf[..n]
			if sink.len > 65536 {
				break
			}
		}
		c.close() or {}
		resp = sink.bytestr()
		break
	}
	srv_log := os.read_file(out_file) or { '' }
	assert resp.contains('text/event-stream'), 'sse server did not write the event-stream prelude; got: ${resp} | log: ${srv_log}'
	assert resp.contains('data: hello'), 'sse server did not flush the first event; got: ${resp} | log: ${srv_log}'
	assert resp.contains('data: world'), 'sse server did not flush the second event; got: ${resp} | log: ${srv_log}'
}

// ── client read leg: cx is the SSE client, a raw V server pushes the stream ──
fn test_http_sse_client_read() {
	port := pick_port() + 40
	mut listener := net.listen_tcp(.ip, '127.0.0.1:${port}') or {
		eprintln('SKIP: cannot bind 127.0.0.1:${port}: ${err}')
		return
	}
	listener.set_accept_timeout(5 * time.second)
	srv := spawn fn (mut l net.TcpListener) {
		mut c := l.accept() or {
			l.close() or {}
			return
		}
		// drain the request line + headers (until blank line)
		mut req := []u8{}
		mut hb := []u8{len: 1}
		for {
			n := c.read(mut hb) or { break }
			if n <= 0 {
				break
			}
			req << hb[0]
			if req.len >= 4 && req#[-4..].bytestr() == '\r\n\r\n' {
				break
			}
		}
		c.write_string('HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n') or {}
		c.write_string('id: 1\ndata: alpha\n\n') or {}
		c.write_string('id: 2\ndata: bravo\n\n') or {}
		time.sleep(150 * time.millisecond)
		c.close() or {}
		l.close() or {}
	}(mut listener)

	// cx client: connect, walk sse-events, emit each event's data joined.
	prog := write_tmp('cx_sse_cli.cx', '[?lib \'cx-stdlib/http\' :as http]\n' +
		'[?let [= \$src [\$http:sse-connect "http://127.0.0.1:${port}/stream" {reconnect: false}]]\n' +
		'  [?for [in \$ev [\$http:sse-events \$src]]\n' +
		'    [yield \$ev]]]\n')
	res := os.execute('${cx_binary()} --allow-net=127.0.0.1:${port} ${prog}')
	srv.wait()
	out := res.output
	assert out.contains('alpha'), 'cx sse client did not read the first live event; got: ${out}'
	assert out.contains('bravo'), 'cx sse client did not read the second live event; got: ${out}'
}

// ── #852 — `[?term:select]` must actually wake on an SSE source ────────────
//
// `[sse-source fd=N]`'s `fd=` is the net REGISTRY id (`net_register` returns
// `next_id++`), not a descriptor. `term:select` handed that number to poll(2),
// so the first connection in a process was polled as fd 1 — stdout. The SSE
// arm never fired, and nothing errored: `select` returned on schedule, the
// stream stayed open, the server published happily, the client never
// repainted. term.md §3.6 names SSE handles as valid sources, and this is the
// primitive #28/#29 exist to deliver ("one loop, both signals").
//
// HOW THIS TEST DISCRIMINATES, which took a rethink. Asserting `[ready]` alone
// does NOT: under the bug, polling a redirected stdout can report readable
// immediately and yield `[ready index=0]` for the wrong reason. The property
// that separates them is TIME — a correct `select` CANNOT return before the
// server sends, because there is nothing to wake on. So the server holds the
// stream open for 600 ms after the prelude, and the test asserts both that
// the wake happened AND that it took at least 400 ms.
//
// The bound is a LOWER one on purpose: load pushes a real run further into
// the passing side, while the buggy behaviour (waking immediately on the
// wrong descriptor) is what a lower bound catches. An upper bound here would
// turn machine load into a false failure.
fn test_sse_source_wakes_term_select() {
	port := pick_port() + 70
	mut listener := net.listen_tcp(.ip, '127.0.0.1:${port}') or {
		eprintln('SKIP: cannot bind 127.0.0.1:${port}: ${err}')
		return
	}
	listener.set_accept_timeout(8 * time.second)
	srv := spawn fn (mut l net.TcpListener) {
		mut c := l.accept() or {
			l.close() or {}
			return
		}
		mut req := []u8{}
		mut hb := []u8{len: 1}
		for {
			n := c.read(mut hb) or { break }
			if n <= 0 {
				break
			}
			req << hb[0]
			if req.len >= 4 && req#[-4..].bytestr() == '\r\n\r\n' {
				break
			}
		}
		// Prelude only. sse-connect consumes the headers, so after this the
		// socket has NOTHING pending and a correct select must block.
		c.write_string('HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n\r\n') or {}
		time.sleep(600 * time.millisecond)
		c.write_string('id: 1\ndata: late\n\n') or {}
		time.sleep(400 * time.millisecond)
		c.close() or {}
		l.close() or {}
	}(mut listener)

	prog := write_tmp('cx_sse_select_${port}.cx', "[?lib 'cx-stdlib/http' :as http]\n" +
		"[?lib 'cx-x/term' :as term]\n" +
		'[?let [= \$src [\$http:sse-connect "http://127.0.0.1:${port}/stream" {reconnect: false}]]\n' +
		'      [= \$ev [\$term:select {keys: false sources: (\$src) timeout: 5000}]]\n' +
		'  [\$name \$ev]]\n')
	t0 := time.now()
	res := os.execute('${cx_binary()} --allow-net=127.0.0.1:${port} --allow-read ${prog}')
	elapsed := time.since(t0).milliseconds()
	srv.wait()
	out := res.output.trim_space()

	assert out.contains('ready'),
		'#852: term:select never woke on the SSE source (got [${out}] after ${elapsed} ms)'
	assert elapsed >= 400,
		'#852: term:select returned after only ${elapsed} ms — it cannot have been waiting on the stream, which stayed silent for 600 ms (got [${out}])'
}
