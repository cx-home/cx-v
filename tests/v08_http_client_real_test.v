module main

import os
import time
import net

// v08_http_client_real_test.v — BEHAVIORAL conformance for the cx-stdlib/http
// CLIENT over a real socket (http.md §3.2 one-shot verbs). The TDD red test for
// the client: it MUST fail against the synthetic stub (which returns an empty
// [response status=200] with no body) and pass only once get/post issue a real
// HTTP/1.1 request over the net TCP core and parse the real response.
//
// A minimal V HTTP/1.1 server backs it; the cx program is the CLIENT.

fn cx_binary() string {
	abs := os.real_path('vcx/target/cx')
	if !os.is_file(abs) {
		panic('vcx/target/cx not found at ${abs} — run `make build-vcx` first')
	}
	return abs
}

fn pick_port() int {
	return 19600 + int(time.now().unix_milli() % 200)
}

fn write_tmp(name string, content string) string {
	p := os.join_path(os.temp_dir(), name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

// minimal HTTP/1.1 origin server: one request, fixed 200 + body, then closes.
fn test_http_client_get_real() {
	port := pick_port()
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
		mut buf := []u8{len: 4096}
		c.read(mut buf) or {} // consume the request line + headers (ignored)
		body := 'hello-http'
		resp := 'HTTP/1.1 200 OK\r\nContent-Length: ${body.len}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n${body}'
		c.write_string(resp) or {}
		c.close() or {}
		l.close() or {}
	}(mut listener)

	prog := write_tmp('cx_http_client.cx', '[?lib \'cx-stdlib/http\' :as http]\n' +
		'[?let [= \$r [\$http:get "http://127.0.0.1:${port}/hi" {}]]\n' + '  [\$http:body-text \$r]]\n')

	res := os.execute('${cx_binary()} --allow-net=127.0.0.1:${port} ${prog}')
	srv.wait()
	out := res.output.trim_space()
	// body-text returns the response body string; the cx CLI renders it quoted.
	assert out == "'hello-http'", 'cx http client did not read the real response body; got: ${out}'
}
