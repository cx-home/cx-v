module main

import os
import testenv
import time
import net

// http_server_real_test.v — BEHAVIORAL conformance for the §3.5 LOW-LEVEL
// http server loop over a REAL loopback socket (http.md §3.5: listen →
// [http-server]; accept-iter → single-use [exchange] stream; exchange-request →
// parsed server-form [request]; respond → writes the [response] on the
// exchange's connection). This is the TDD red test for de-stubbing the
// low-level server: it MUST fail against the synthetic shapes (http_server_handle
// / http_seq([]) / fake [request] / respond→null) and pass only once the loop
// performs real accept/read/parse/serialize/write on net.
//
// A cx program is the SERVER (listen + [?for accept-iter] echo); a raw-socket V
// client drives it: POST a body, read it back. The round-trip proves the request
// line + headers + Content-Length body were parsed off the wire and the response
// was serialized + written — none of which a stub can do.

fn cx_binary() string {
	return testenv.cx_bin()
}

// Disjoint PID + nanosecond-salted band (26400-26499) so the concurrent
// `v test vcx/tests/` gate processes don't collide on a port.
fn pick_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 26400 + int(salt)
}

fn write_tmp(name string, content string) string {
	p := os.join_path(os.temp_dir(), name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

// The cx low-level server: bind tcp://, accept in a loop, and for each exchange
// echo the request body back as a 200 response body. body-text exercises the
// Content-Length body read; respond exercises the response serializer.
fn server_prog(port int) string {
	return '[?lib \'cx-stdlib/http\' :as http]\n' +
		'[?let [= \$srv [\$http:listen "tcp://127.0.0.1:${port}" {}]]\n' +
		'  [?for [in \$ex [\$http:accept-iter \$srv]]\n' +
		'    [yield [?let [= \$req [\$http:exchange-request \$ex]]\n' +
		'      [?let [= \$b [\$http:body-text \$req]]\n' +
		'        [\$http:respond \$ex [response status=200 [body \$b]]]]]]]]\n'
}

fn raw_round_trip(port int, body string) (bool, string) {
	for _ in 0 .. 40 {
		mut c := net.dial_tcp('127.0.0.1:${port}') or {
			time.sleep(100 * time.millisecond)
			continue
		}
		req := 'POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: ${body.len}\r\nConnection: close\r\n\r\n${body}'
		c.write_string(req) or {
			c.close() or {}
			return false, 'write failed'
		}
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
		return true, sink.bytestr()
	}
	return false, 'never connected'
}

fn test_http_server_low_level_echo() {
	port := pick_port()
	prog := write_tmp('cx_http_srv.cx', server_prog(port))
	out_file := '/tmp/cx-http-srv.${port}.out'
	pid_s := os.execute('${cx_binary()} --allow-net ${prog} >${out_file} 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx http server')
		return
	}
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(400 * time.millisecond) // let the server bind

	connected, resp := raw_round_trip(port, 'ping-server')
	srv_log := os.read_file(out_file) or { '' }
	assert connected, 'cx http server never accepted a connection on ${port}; server log: ${srv_log}'
	assert resp.contains('200'), 'response missing 200 status line; got: ${resp} | server log: ${srv_log}'
	assert resp.contains('ping-server'), 'low-level server did not echo the request body over a real socket; got: ${resp} | server log: ${srv_log}'
}

// A second sequential client must also be served — accept-iter is a LOOP, not a
// one-shot. (The first exchange's single-use iterator is per-connection.)
fn test_http_server_two_clients() {
	port := pick_port() + 50
	prog := write_tmp('cx_http_srv2.cx', server_prog(port))
	out_file := '/tmp/cx-http-srv2.${port}.out'
	pid_s := os.execute('${cx_binary()} --allow-net ${prog} >${out_file} 2>&1 & echo \$!')
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(400 * time.millisecond)

	mut bodies := []string{}
	for msg in ['alpha', 'bravo'] {
		ok, resp := raw_round_trip(port, msg)
		if !ok {
			break
		}
		bodies << resp
	}
	srv_log := os.read_file(out_file) or { '' }
	assert bodies.len == 2, 'accept-iter did not serve two sequential clients; server log: ${srv_log}'
	assert bodies[0].contains('alpha'), 'first client not echoed; got: ${bodies[0]}'
	assert bodies[1].contains('bravo'), 'second client not echoed; got: ${bodies[1]}'
}
