module main

import os
import net
import time

// http_split_body_test.v — #48: a POST whose body arrives in a SEPARATE TCP
// segment from the headers must NOT be seen as empty by the handler.
//
// picohttpparser's parse return covers only the request line + headers, not the
// body. The picoev read loop used to break as soon as the headers parsed and
// hand the request to the callback with whatever body bytes happened to already
// be buffered — empty when the body landed in a later segment (cold/rapid
// connections). The fix keeps reading until the full Content-Length body is
// buffered before invoking the callback.
//
// This test makes the race DETERMINISTIC: it writes the headers, flushes,
// sleeps so the server's first recv() sees only the headers, then writes the
// body as a second segment. The echo server must still see the full body.

fn cx_bin_sb() string {
	abs := os.real_path('vcx/target/cx')
	if !os.is_file(abs) {
		panic('vcx/target/cx not found at ${abs} — run `make build-vcx` first')
	}
	return abs
}

fn pick_port_sb() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 26700 + int(salt)
}

// A `[$http:serve]` HANDLER-mode echo server — the picoev reactor path
// (listener_callback) that reads the body via picohttpparser. The handler
// echoes the request body verbatim. This is the path #48 reported against
// (NOT accept-iter, which reads the body synchronously via net_read_exact_buf).
fn echo_server_prog(port int) string {
	return '[?lib \'cx-stdlib/http\' :as http]\n' +
		'[?def h (\$req::element)\n' +
		'  [response status=200 [body [\$http:body-text \$req]]]]\n' +
		'[\$http:serve "tcp://127.0.0.1:${port}" \$h {block: true}]\n'
}

// Send a POST with headers and body in two separate segments, with a gap so the
// server's first read observes only the headers. Returns the echoed body.
fn split_post(port int, body string) ?string {
	mut c := net.dial_tcp('127.0.0.1:${port}') or { return none }
	defer { c.close() or {} }
	head := 'POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: ${body.len}\r\nConnection: close\r\n\r\n'
	c.write_string(head) or { return none }
	// Force the body into a distinct TCP segment, after the server has had a
	// chance to recv() just the headers.
	time.sleep(120 * time.millisecond)
	c.write_string(body) or { return none }

	c.set_read_timeout(4 * time.second)
	// Read until we have the full response: headers + a Content-Length body. We
	// parse the response's own Content-Length rather than reading to EOF so the
	// test doesn't wait on the server's idle timeout for the socket close.
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
		resp_so_far := raw.bytestr()
		if head_end < 0 {
			head_end = resp_so_far.index('\r\n\r\n') or { -1 }
			if head_end >= 0 {
				for line in resp_so_far[..head_end].split('\r\n') {
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
	resp := raw.bytestr()
	idx := resp.index('\r\n\r\n') or { return none }
	body_all := resp[idx + 4..]
	if want >= 0 && body_all.len >= want {
		return body_all[..want]
	}
	return body_all
}

fn test_split_segment_post_body_not_empty() {
	port := pick_port_sb()
	prog := os.join_path(os.temp_dir(), 'cx_sb_${os.getpid()}.cx')
	os.write_file(prog, echo_server_prog(port)) or { panic('write: ${err}') }
	defer { os.rm(prog) or {} }
	out_file := '/tmp/cx-sb.${port}.out'
	pid_s := os.execute('${cx_bin_sb()} --allow-net ${prog} >${out_file} 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx http server')
		return
	}
	pid := pid_s.output.trim_space()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
		os.rm(out_file) or {}
	}

	// Wait for the listener to come up.
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
	assert up, 'cx echo server never came up on ${port}'

	// Run the split-segment POST several times — the bug was intermittent, so a
	// single pass could pass by luck. The body must echo back in full every time.
	expected := 'verb=greet actor=alice'
	for i in 0 .. 8 {
		got := split_post(port, expected) or {
			assert false, 'split POST #${i} got no response'
			return
		}
		assert got == expected, 'split POST #${i}: body lost — expected "${expected}", got "${got}"'
	}
}
