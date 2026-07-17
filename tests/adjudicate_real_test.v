module main

import os
import testenv
import time
import net

// adjudicate_real_test.v — BEHAVIORAL coverage for cx-x/adjudicate (#376, the
// similar.md §5.3 ruling-Q4 follow-up). The pure surface (verdict-of /
// resolution-of / prompt-of / decisive) is enforced in
// conformance/stdlib/adjudicate.cxd; THIS proves the effectful surface
// end-to-end over a REAL loopback socket: a mock Ollama /api/chat server returns
// a canned "no-match" verdict, and one cx program runs the whole #376 loop —
// review pairs → [$adj:adjudicate] (prompt-of → llm:complete → verdict-of →
// resolution-of, decided-by='agent:<model>') → [$adj:decisive] →
// [$similar:predicate {resolutions: …}] → the pair short-circuits OUT of the
// review band with [resolved …] provenance (similar.md §5.4). It would fail
// against any synthetic/stub http body (no real POST round-trip), so it pins
// the producer→consumer composition, not a name.

fn cx_binary() string {
	return testenv.cx_bin()
}

// pick_port: adjudicate owns the disjoint band 27000-27199, salted with PID +
// the nanosecond clock so the concurrent `v test vcx/tests/` processes in the
// 12-way gate land on distinct ports (same scheme as llm_real_test.v).
fn pick_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 200
	return 27000 + int(salt)
}

fn write_tmp(name string, content string) string {
	p := os.join_path(os.temp_dir(), name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

// run_cx_client runs the cx client command, retrying on transport flake: a
// CXER3100 (malformed/partial JSON) or an empty body means the client read a
// half-open / not-yet-ready HTTP response. The mock server accepts repeatedly,
// so each retry gets a fresh connection.
fn run_cx_client(cmd string) string {
	mut out := ''
	for _ in 0 .. 6 {
		out = os.execute(cmd).output
		if out.trim_space() != '' && !out.contains('CXER3100') && !out.contains('E_JSON_MALFORMED') {
			return out
		}
		time.sleep(150 * time.millisecond)
	}
	return out
}

// A raw V TCP server playing Ollama: accept repeatedly (adjudicate POSTs once
// per pair), drain each request head + body, then return a canned /api/chat
// reply whose assistant turn is the verdict word "no-match".
fn test_adjudicate_review_pair_round_trip() {
	port := pick_port()
	mut listener := net.listen_tcp(.ip, '127.0.0.1:${port}') or {
		eprintln('SKIP: cannot bind 127.0.0.1:${port}: ${err}')
		return
	}
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
			reply := '{"model":"test-model","message":{"role":"assistant","content":"no-match"},"done":true}'
			c.write_string('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${reply.len}\r\nConnection: close\r\n\r\n${reply}') or {}
			time.sleep(20 * time.millisecond)
			c.close() or {}
		}
		l.close() or {}
	}(mut listener, &done)

	// One cx program runs the whole #376 loop: adjudicate a review pair against
	// the mock endpoint, filter to firm verdicts, feed them back into a similar
	// predicate, and re-run the comparison.
	prog := write_tmp('cx_adjudicate_cli.cx', "[?lib 'cx-x/adjudicate' :as adj]\n" +
		"[?lib 'cx-stdlib/similar' :as similar]\n" + '[?let\n' +
		'  [= \$pairs ([pair score=0.92 band=:review [left "globex"] [right "globex inc"]],)]\n' + '  [= \$records [\$adj:adjudicate "http://127.0.0.1:${port}" "test-model" \$pairs]]\n' + '  [= \$firm [\$adj:decisive \$records]]\n' + '  {records: \$records,\n' + '   rerun: [~ "globex" "globex inc" [\$similar:predicate {decide: {match: 0.9, review: 0.8}, resolutions: \$firm}]]}]\n')
	out := run_cx_client('${cx_binary()} --allow-net=127.0.0.1:${port} ${prog}')
	done = true
	srv.wait()
	assert out.contains('verdict=:no-match'), 'adjudicate did not produce a :no-match resolution record; got: ${out}'
	assert out.contains('decided-by=agent:test-model'), 'resolution record lacks agent:<model> provenance; got: ${out}'
	assert out.contains('score=0.0 band=:no-match'), 're-run did not short-circuit the review pair to :no-match via the resolutions tier; got: ${out}'
	assert out.contains('[resolved decided-by=agent:test-model :no-match]'), 're-run evidence lacks [resolved …] provenance; got: ${out}'
}
