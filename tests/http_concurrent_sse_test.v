module main

import os
import testenv
import net
import time

// http_concurrent_sse_test.v — #28: concurrent SSE push on the [$http:serve]
// path. A handler promotes GET /events to a held-open feed by returning
// `[sse-subscribe topic="…" [event …]?]`; any handler fans out with
// `[$http:sse-publish "…" [event …]]`. The reactor is never blocked — other
// requests (and other SSE feeds) are served concurrently while a feed is held.
//
// Asserts:
//   1. Two independent SSE clients both receive the initial frame.
//   2. A plain GET /ping returns promptly WHILE both feeds are held (the bug:
//      a held stream used to serialize the server).
//   3. After GET /push, BOTH feeds receive the published event (fan-out).
//   4. sse-publish reports the subscriber count it delivered to (2).

fn cx_bin_sse() string {
	return testenv.cx_bin()
}

fn pick_port_sse() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 28900 + int(salt)
}

fn sse_server_prog(port int) string {
	return "[?lib 'cx-stdlib/http' :as http]\n" +
		'[?def h impure (\$req)\n' +
		'  [?let [= \$p [\$text \$req@path]]\n' +
		'    [?if [= \$p "/events"]\n' +
		'      [then [sse-subscribe topic="prices" [event data="hello"]]]\n' +
		'      [else [?if [= \$p "/push"]\n' +
		'        [then [?let [= \$n [\$http:sse-publish "prices" [event data="tick-42"]]]\n' +
		'                [response status=200 [body [\$concat "pushed=" [\$text \$n]]]]]]\n' +
		'        [else [response status=200 [body "pong"]]]]]]]]\n' +
		'[\$http:serve "tcp://127.0.0.1:${port}" \$h {block: true}]\n'
}

// open an SSE subscriber connection and return the socket
fn open_sse(port int) ?&net.TcpConn {
	mut c := net.dial_tcp('127.0.0.1:${port}') or { return none }
	c.write_string('GET /events HTTP/1.1\r\nHost: x\r\n\r\n') or { return none }
	c.set_read_timeout(4 * time.second)
	return c
}

// a one-shot GET returning the response body, measuring round-trip ms. Reads
// exactly the Content-Length body and returns — does NOT wait for the socket
// close (the server advertises Connection: close but defers the actual close to
// its idle path; waiting for EOF would measure that, not response latency).
fn get_body(port int, path string) (string, f64) {
	t0 := time.now()
	mut c := net.dial_tcp('127.0.0.1:${port}') or { return '', 0.0 }
	defer { c.close() or {} }
	c.write_string('GET ${path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n') or { return '', 0.0 }
	c.set_read_timeout(4 * time.second)
	mut raw := []u8{}
	mut buf := []u8{len: 4096}
	mut want := -1
	mut head_end := -1
	for {
		n := c.read(mut buf) or { break }
		if n <= 0 {
			break
		}
		raw << buf[..n]
		resp_now := raw.bytestr()
		if head_end < 0 {
			head_end = resp_now.index('\r\n\r\n') or { -1 }
			if head_end >= 0 {
				for line in resp_now[..head_end].split('\r\n') {
					if line.to_lower().starts_with('content-length:') {
						want = line.all_after(':').trim_space().int()
					}
				}
			}
		}
		if head_end >= 0 {
			have := raw.len - (head_end + 4)
			if want < 0 || have >= want {
				break
			}
		}
		if raw.len > 65536 {
			break
		}
	}
	ms := f64(time.now() - t0) / f64(time.millisecond)
	resp := raw.bytestr()
	idx := resp.index('\r\n\r\n') or { return resp, ms }
	body_all := resp[idx + 4..]
	if want >= 0 && body_all.len >= want {
		return body_all[..want], ms
	}
	return body_all, ms
}

// read whatever the SSE connection has so far (up to deadline / target)
fn read_sse(mut c net.TcpConn, target string) string {
	mut raw := []u8{}
	mut buf := []u8{len: 4096}
	for {
		n := c.read(mut buf) or { break }
		if n <= 0 {
			break
		}
		raw << buf[..n]
		if raw.bytestr().contains(target) || raw.len > 65536 {
			break
		}
	}
	return raw.bytestr()
}

fn test_concurrent_sse_push() {
	port := pick_port_sse()
	prog := os.join_path(os.temp_dir(), 'cx_sse28_${os.getpid()}.cx')
	os.write_file(prog, sse_server_prog(port)) or { panic('write: ${err}') }
	defer { os.rm(prog) or {} }
	out_file := '/tmp/cx-sse28.${port}.out'
	pid_s := os.execute('${cx_bin_sse()} --allow-net ${prog} >${out_file} 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx sse server')
		return
	}
	pid := pid_s.output.trim_space()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
		os.rm(out_file) or {}
	}

	// wait for the listener
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

	// two SSE subscribers
	mut a := open_sse(port) or {
		assert false, 'could not open SSE client A'
		return
	}
	mut b := open_sse(port) or {
		assert false, 'could not open SSE client B'
		return
	}
	defer {
		a.close() or {}
		b.close() or {}
	}
	// Wait for BOTH subscriptions to actually register before pushing — don't
	// guess a duration. `sse-subscribe` writes each client's initial
	// [event data="hello"] frame ATOMICALLY with the subscriber registration,
	// under the topic-registry lock (cx_sse_topic_subscribe), so receiving that
	// frame IS the readiness ack: every publish issued after it must count this
	// subscriber. Blocking on it (read deadline 4s, set in open_sse) makes the
	// pushed=2 count deterministic under heavy parallel-test CPU load. History:
	// a fixed sleep here raced and intermittently saw pushed=1 (#124); the first
	// fix waited for the initial frame, but the runtime then wrote that frame
	// BEFORE registering the fd, so a publish on another reactor could still
	// slip into the gap — same intermittent pushed=1. If this assert ever
	// reports pushed=1 again, that ack/registration atomicity has regressed —
	// do not paper over it with a retry.
	init_a := read_sse(mut a, 'data: hello')
	assert init_a.contains('data: hello'), 'client A never received its initial frame (subscribe not registered): "${init_a}"'
	init_b := read_sse(mut b, 'data: hello')
	assert init_b.contains('data: hello'), 'client B never received its initial frame: "${init_b}"'

	// (2) a plain request returns PROMPTLY while both feeds are held — the
	// concurrency the bug denied. The pre-fix failure mode blocked until the
	// stream ENDED (~seconds); a concurrent server answers immediately. Under a
	// saturated CI box (the V suite runs ~12 compile/run jobs in parallel) a
	// single round-trip can spike past 1s purely from scheduler contention, even
	// though the server is concurrent — so take the BEST of three pings (a
	// serialized server would block ALL of them) and use a generous ceiling.
	// Every ping must still return the correct body WHILE the feeds are held.
	mut best_ping_ms := 1.0e9
	for _ in 0 .. 3 {
		ping_body, ping_ms := get_body(port, '/ping')
		assert ping_body.trim_space() == 'pong', 'ping not served while SSE held: "${ping_body}"'
		if ping_ms < best_ping_ms {
			best_ping_ms = ping_ms
		}
	}
	assert best_ping_ms < 2500.0, 'ping blocked ${best_ping_ms}ms (best of 3) while SSE feed held — not concurrent'

	// (3)/(4) publish fans out to both subscribers; the count is reported. Both
	// are confirmed-registered above (each got its initial frame), so this is
	// deterministically 2 — no longer a race against a fixed sleep.
	push_body, _ := get_body(port, '/push')
	assert push_body.contains('pushed=2'), 'sse-publish should report 2 subscribers, got: "${push_body}"'

	// (3) the pushed event reaches BOTH feeds. (The initial `data: hello` frame
	// was already consumed + asserted above as the subscription-readiness gate.)
	got_a := read_sse(mut a, 'tick-42')
	got_b := read_sse(mut b, 'tick-42')
	assert got_a.contains('data: tick-42'), 'client A missing pushed event: "${got_a}"'
	assert got_b.contains('data: tick-42'), 'client B missing pushed event: "${got_b}"'
}
