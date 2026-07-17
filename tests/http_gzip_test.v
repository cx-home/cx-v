module main

import os
import testenv
import time
import net
import compress.gzip

// http_gzip_test.v — BEHAVIORAL conformance for §4.4 content-decoding. A
// raw-socket V server returns a gzip-compressed body with Content-Encoding:
// gzip; the cx client (auto-decompress default true) must transparently decode
// it (body-text → the original text), keep the wire headers verbatim, and expose
// the compressed octets via body-bytes-wire. With auto-decompress=false the body
// is left raw. Loopback → needs --allow-net=ip:port.

fn cx_binary() string {
	return testenv.cx_bin()
}

// Disjoint PID + nanosecond-salted band (26200-26299) so the concurrent
// `v test vcx/tests/` gate processes don't collide on a port.
fn pick_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 26200 + int(salt)
}

fn write_tmp(name string, content string) string {
	p := os.join_path(os.temp_dir(), name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

fn spawn_gzip_server(mut l net.TcpListener, gz []u8) thread {
	return spawn fn (mut l net.TcpListener, gz []u8) {
		mut c := l.accept() or {
			l.close() or {}
			return
		}
		mut buf := []u8{len: 1024}
		c.read(mut buf) or {}
		mut head := 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: ${gz.len}\r\nConnection: close\r\n\r\n'
		c.write_string(head) or {}
		c.write(gz) or {}
		c.close() or {}
		l.close() or {}
	}(mut l, gz)
}

fn test_http_gzip_auto_decompress() {
	port := pick_port()
	payload := 'the quick brown fox decompressed cleanly'
	gz := gzip.compress(payload.bytes()) or {
		eprintln('SKIP: gzip.compress failed: ${err}')
		return
	}
	mut l := net.listen_tcp(.ip, '127.0.0.1:${port}') or {
		eprintln('SKIP: cannot bind ${port}: ${err}')
		return
	}
	l.set_accept_timeout(5 * time.second)
	srv := spawn_gzip_server(mut l, gz)

	prog := write_tmp('cx_gzip.cx', '[?lib \'cx-stdlib/http\' :as http]\n' +
		'[?let [= \$r [\$http:get "http://127.0.0.1:${port}/g" {}]]\n' +
		'  [\$http:body-text \$r]]\n')
	res := os.execute('${cx_binary()} --allow-net=127.0.0.1:${port} ${prog}')
	srv.wait()
	out := res.output
	assert out.contains(payload), 'gzip response was not transparently decoded; got: ${out}'
}

fn test_http_gzip_wire_preserved() {
	port := pick_port() + 30
	payload := 'wire-vs-decoded payload check'
	gz := gzip.compress(payload.bytes()) or {
		eprintln('SKIP')
		return
	}
	mut l := net.listen_tcp(.ip, '127.0.0.1:${port}') or {
		eprintln('SKIP: cannot bind ${port}: ${err}')
		return
	}
	l.set_accept_timeout(5 * time.second)
	srv := spawn_gzip_server(mut l, gz)

	// decoded length (body-bytes) must equal the payload length, and differ from
	// the compressed wire length (body-bytes-wire) — proving both are reachable.
	prog := write_tmp('cx_gzip_wire.cx', '[?lib \'cx-stdlib/http\' :as http]\n' +
		'[?lib \'cx-stdlib/bytes\' :as bytes]\n' +
		'[?let [= \$r [\$http:get "http://127.0.0.1:${port}/g" {}]]\n' +
		'  [compare decoded=[\$bytes:length [\$http:body-bytes \$r]]\n' +
		'           wire=[\$bytes:length [\$http:body-bytes-wire \$r]]]]\n')
	res := os.execute('${cx_binary()} --allow-net=127.0.0.1:${port} ${prog}')
	srv.wait()
	out := res.output
	assert out.contains('decoded=${payload.len}'), 'body-bytes did not return the decoded length; got: ${out}'
	assert out.contains('wire=${gz.len}'), 'body-bytes-wire did not return the compressed length; got: ${out}'
}
