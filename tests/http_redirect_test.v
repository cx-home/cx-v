module main

import os
import time
import net

// http_redirect_test.v — BEHAVIORAL conformance for §4.3 redirect-following.
// A raw-socket V server answers the first request with a 302 → /final and the
// second with 200 "arrived". The cx client (follow-redirects default true) must
// transparently follow and return the final body; with follow-redirects=false it
// must return the 302 as a value (§2.4). Loopback → needs --allow-net=ip:port.

fn cx_binary() string {
	abs := os.real_path('vcx/target/cx')
	if !os.is_file(abs) {
		panic('vcx/target/cx not found at ${abs} — run `make build-vcx` first')
	}
	return abs
}

// Disjoint PID + nanosecond-salted band (25800-25899) so the concurrent
// `v test vcx/tests/` gate processes don't collide on a port.
fn pick_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 25800 + int(salt)
}

fn write_tmp(name string, content string) string {
	p := os.join_path(os.temp_dir(), name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

// A V server: first accepted connection → 302 to /final; second → 200 arrived.
// (The http client uses Connection: close, so each hop is a fresh connection.)
fn spawn_redirect_server(mut l net.TcpListener) thread {
	return spawn fn (mut l net.TcpListener) {
		for hop in 0 .. 2 {
			mut c := l.accept() or { break }
			mut buf := []u8{len: 1024}
			c.read(mut buf) or {}
			if hop == 0 {
				c.write_string('HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n') or {}
			} else {
				body := 'arrived'
				c.write_string('HTTP/1.1 200 OK\r\nContent-Length: ${body.len}\r\nConnection: close\r\n\r\n${body}') or {}
			}
			c.close() or {}
		}
		l.close() or {}
	}(mut l)
}

fn test_http_follows_redirect() {
	port := pick_port()
	mut l := net.listen_tcp(.ip, '127.0.0.1:${port}') or {
		eprintln('SKIP: cannot bind ${port}: ${err}')
		return
	}
	l.set_accept_timeout(5 * time.second)
	srv := spawn_redirect_server(mut l)

	prog := write_tmp('cx_redir.cx', '[?lib \'cx-stdlib/http\' :as http]\n' +
		'[?let [= \$r [\$http:get "http://127.0.0.1:${port}/start" {}]]\n' +
		'  [\$http:body-text \$r]]\n')
	res := os.execute('${cx_binary()} --allow-net=127.0.0.1:${port} ${prog}')
	srv.wait()
	out := res.output.trim_space()
	assert out.contains('arrived'), 'client did not follow the 302 to the final body; got: ${out}'
}

fn test_http_no_follow_returns_3xx() {
	port := pick_port() + 20
	mut l := net.listen_tcp(.ip, '127.0.0.1:${port}') or {
		eprintln('SKIP: cannot bind ${port}: ${err}')
		return
	}
	l.set_accept_timeout(5 * time.second)
	// only one hop needed (no follow)
	srv := spawn fn (mut l net.TcpListener) {
		mut c := l.accept() or {
			l.close() or {}
			return
		}
		mut buf := []u8{len: 1024}
		c.read(mut buf) or {}
		c.write_string('HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n') or {}
		c.close() or {}
		l.close() or {}
	}(mut l)

	prog := write_tmp('cx_noredir.cx', '[?lib \'cx-stdlib/http\' :as http]\n' +
		'[?let [= \$r [\$http:get "http://127.0.0.1:${port}/start" {follow-redirects: false}]]\n' +
		'  [\$http:status \$r]]\n')
	res := os.execute('${cx_binary()} --allow-net=127.0.0.1:${port} ${prog}')
	srv.wait()
	out := res.output.trim_space()
	assert out == '302', 'follow-redirects=false must return the 302 as a value; got: ${out}'
}
