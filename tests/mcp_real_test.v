module main

import os
import time
import net

// mcp_real_test.v — BEHAVIORAL coverage for cx-x/mcp (#6 S9). The pure layer
// (request shaping / response extraction / validate-args) is enforced in
// conformance/stdlib/mcp.cxd; THIS proves the effectful transport end-to-end over
// a REAL loopback socket: a mock MCP server answers a JSON-RPC tools/call with a
// canned result, and a cx client invokes the tool as a Runnable through cx-x/run —
// exercising [$run:invoke] → lib-qualified closure → [$mcp:call-tool] → rpc-call →
// http:post → json:parse → result-text. It fails against any synthetic http body
// (no real POST round-trip), so it pins the composition, not a name.

fn cx_binary() string {
	abs := os.real_path('vcx/target/cx')
	if !os.is_file(abs) {
		panic('vcx/target/cx not found at ${abs} — run `make build-vcx` first')
	}
	return abs
}

// pick_port: mcp owns the disjoint band 21000-21799, salted with PID + the
// nanosecond clock so the concurrent `v test vcx/tests/` processes in the 12-way
// gate land on distinct ports. A collision would need both a base clash (none —
// each real-server test owns its own 800-wide band) and a salt clash (a 1-in-800
// shot between any two processes started in the same nanosecond), so the prior
// CXER3100 cross-test port collisions are eliminated.
fn pick_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 800
	return 21000 + int(salt)
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

// A raw V TCP server playing an MCP endpoint: accept one connection, drain the
// request head + body, then return a canned JSON-RPC tools/call result with a
// Content-Length so the cx http client knows the body is complete.
fn test_mcp_call_tool_runnable_round_trip() {
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
			reply := '{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"72F and sunny"}],"isError":false}}'
			c.write_string('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${reply.len}\r\nConnection: close\r\n\r\n${reply}') or {}
			time.sleep(20 * time.millisecond)
			c.close() or {}
		}
		l.close() or {}
	}(mut listener, &done)

	// cx client: compose [$mcp:call-tool] as a Runnable and invoke it via cx-x/run.
	prog := write_tmp('cx_mcp_cli.cx', '[?lib \'cx-x/mcp\' :as mcp]\n' +
		'[?lib \'cx-x/run\' :as run]\n' +
		'[\$run:invoke [?fn (\$a) [\$mcp:call-tool "http://127.0.0.1:${port}/mcp" "get_weather" \$a]] {location: "NYC"}]\n')
	out := run_cx_client('${cx_binary()} --allow-net=127.0.0.1:${port} ${prog}')
	done = true
	srv.wait()
	assert out.contains('72F and sunny'), 'cx-x/mcp call-tool Runnable did not return the canned tool result; got: ${out}'
}
