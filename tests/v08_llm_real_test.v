module main

import os
import time
import net

// v08_llm_real_test.v — BEHAVIORAL coverage for cx-x/llm (the first Runnable,
// #6 S10). The pure protocol layer (chat-request / completion-of) is enforced in
// conformance/stdlib/llm.cxd; THIS proves the effectful surface end-to-end over a
// REAL loopback socket: a mock Ollama /api/chat server returns a canned reply, and
// a cx client composes [$llm:complete] as a Runnable through cx-x/run — exercising
// [$run:invoke] → lib-qualified closure → [$llm:complete] → http:post → json:parse →
// completion-of. It would fail against any synthetic/stub http body (no real POST
// round-trip), so it pins the composition, not a name.

fn cx_binary() string {
	abs := os.real_path('vcx/target/cx')
	if !os.is_file(abs) {
		panic('vcx/target/cx not found at ${abs} — run `make build-vcx` first')
	}
	return abs
}

// pick_port: llm owns the disjoint band 20000-20799, salted with PID + the
// nanosecond clock so the concurrent `v test vcx/tests/` processes in the 12-way
// gate land on distinct ports. A collision would need both a base clash (none —
// each real-server test owns its own 800-wide band) and a salt clash (a 1-in-800
// shot between any two processes started in the same nanosecond), so the prior
// CXER3100 cross-test port collisions are eliminated.
fn pick_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 800
	return 20000 + int(salt)
}

fn write_tmp(name string, content string) string {
	p := os.join_path(os.temp_dir(), name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

// run_cx_client runs the cx client command, retrying on transport flake: a
// CXER3100 (malformed/partial JSON) or an empty body means the client read a
// half-open / not-yet-ready HTTP response. The mock server accepts repeatedly, so
// each retry gets a fresh connection. A real round-trip carries a non-3100 payload
// and returns on the first attempt.
fn run_cx_client(cmd string) string {
	mut out := ''
	for _ in 0 .. 6 {
		out = os.execute(cmd).output
		if out.trim_space() != '' && !out.contains('CXER3100')
			&& !out.contains('E_JSON_MALFORMED') {
			return out
		}
		time.sleep(150 * time.millisecond)
	}
	return out
}

// A raw V TCP server playing Ollama: accept one connection, drain the request
// head + body, then return a canned /api/chat JSON reply with a Content-Length so
// the cx http client knows the body is complete without waiting for EOF.
fn test_llm_chat_runnable_round_trip() {
	port := pick_port()
	mut listener := net.listen_tcp(.ip, '127.0.0.1:${port}') or {
		eprintln('SKIP: cannot bind 127.0.0.1:${port}: ${err}')
		return
	}
	// Short accept timeout so the loop re-checks `done` ~4×/s; it keeps waiting
	// (does not break) until `done` is set, so it tolerates the cx client's
	// startup latency on the first connection AND serves each client-side retry.
	listener.set_accept_timeout(250 * time.millisecond)
	mut done := false
	srv := spawn fn (mut l net.TcpListener, done &bool) {
		for !(*done) {
			mut c := l.accept() or { continue } // timeout → re-check done
			// Drain the request: read until the header terminator, then read any
			// Content-Length body so the socket is clean before we reply.
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
			head := req.bytestr()
			mut content_len := 0
			for line in head.split('\r\n') {
				if line.to_lower().starts_with('content-length:') {
					content_len = line.all_after(':').trim_space().int()
				}
			}
			if content_len > 0 {
				mut body := []u8{len: content_len}
				c.read(mut body) or {}
			}
			reply := '{"model":"llama3","message":{"role":"assistant","content":"pong-42"},"done":true}'
			c.write_string('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${reply.len}\r\nConnection: close\r\n\r\n${reply}') or {}
			time.sleep(20 * time.millisecond)
			c.close() or {}
		}
		l.close() or {}
	}(mut listener, &done)

	// cx client: compose [$llm:complete] as a Runnable and invoke it through cx-x/run.
	prog := write_tmp('cx_llm_cli.cx', '[?lib \'cx-x/llm\' :as llm]\n' +
		'[?lib \'cx-x/run\' :as run]\n' +
		'[\$run:invoke [?fn (\$p) [\$llm:complete "http://127.0.0.1:${port}" "llama3" \$p]] "ping"]\n')
	out := run_cx_client('${cx_binary()} --allow-net=127.0.0.1:${port} ${prog}')
	done = true
	srv.wait()
	assert out.contains('pong-42'), 'cx-x/llm chat Runnable did not return the canned completion; got: ${out}'
}
