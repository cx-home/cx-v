module main

import os
import testenv
import time
import net.mbedtls

// net_tls_test.v — BEHAVIORAL conformance for cx-stdlib/net TLS client core
// (net.md §3.6): [$net:dial-tls] performs a REAL mbedTLS handshake over a real
// TCP connection and the §3.4 stream verbs work over the secured socket. Backed
// by an in-process mbedTLS TLS echo server with a throwaway self-signed cert.
// Skipped only when openssl (cert gen) is unavailable. MUST fail against a stub.

fn cx_binary() string {
	return testenv.cx_bin()
}

fn test_net_dial_tls_roundtrip() {
	if os.execute('which openssl').exit_code != 0 {
		eprintln('SKIP: openssl not available (cert generation)')
		return
	}
	// Disjoint PID + nanosecond-salted slot (27500-27599) so the concurrent
	// `v test vcx/tests/` gate processes don't collide on a port.
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	port := 27500 + int(salt)
	dir := os.temp_dir()
	cert := os.join_path(dir, 'cx_tls_cert.pem')
	key := os.join_path(dir, 'cx_tls_key.pem')
	gen := os.execute('openssl req -x509 -newkey rsa:2048 -keyout ${key} -out ${cert} -days 1 -nodes -subj "/CN=localhost" 2>/dev/null')
	if gen.exit_code != 0 || !os.is_file(cert) {
		eprintln('SKIP: openssl self-signed cert generation failed')
		return
	}
	cfg := mbedtls.SSLConnectConfig{
		cert:     cert
		cert_key: key
		validate: false
	}
	mut l := mbedtls.new_ssl_listener('127.0.0.1:${port}', cfg) or {
		eprintln('SKIP: mbedtls TLS listen failed: ${err}')
		return
	}
	srv := spawn fn (mut l mbedtls.SSLListener) {
		mut c := l.accept() or {
			l.shutdown() or {}
			return
		}
		mut buf := []u8{len: 256}
		n := c.read(mut buf) or { 0 }
		if n > 0 {
			c.write(buf[..n]) or {}
		}
		c.shutdown() or {}
		l.shutdown() or {}
	}(mut l)

	prog := os.join_path(dir, 'cx_tls_client.cx')
	os.write_file(prog, '[?lib \'cx-stdlib/net\' :as net]\n' +
		'[?let [= \$s [\$net:dial-tls "tls://127.0.0.1:${port}" {tls: {verify: false}}]]\n' +
		'[?let [= \$w [\$net:write-line \$s "tls-ping"]]\n' +
		'[?let [= \$line [\$net:read-line \$s]]\n' +
		'[?let [= \$c [\$net:close \$s]]\n' + '  \$line]]]]\n') or { panic(err) }

	res := os.execute('${cx_binary()} --allow-net=127.0.0.1:${port} ${prog}')
	srv.wait()
	out := res.output.trim_space()
	assert out == "'tls-ping'", 'cx dial-tls did not round-trip over real TLS; got: ${out}'
}

// the http CLIENT over https:// — real TLS handshake + HTTP/1.1 over the secured
// socket (verify:false against a self-signed loopback origin, the §3.6 dev opt).
fn test_http_client_https_real() {
	if os.execute('which openssl').exit_code != 0 {
		eprintln('SKIP: openssl not available (cert generation)')
		return
	}
	// Disjoint PID + nanosecond-salted slot (27620-27719) so the concurrent
	// `v test vcx/tests/` gate processes don't collide on a port.
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	port := 27620 + int(salt)
	dir := os.temp_dir()
	cert := os.join_path(dir, 'cx_https_cert.pem')
	key := os.join_path(dir, 'cx_https_key.pem')
	gen := os.execute('openssl req -x509 -newkey rsa:2048 -keyout ${key} -out ${cert} -days 1 -nodes -subj "/CN=localhost" 2>/dev/null')
	if gen.exit_code != 0 || !os.is_file(cert) {
		eprintln('SKIP: openssl self-signed cert generation failed')
		return
	}
	cfg := mbedtls.SSLConnectConfig{
		cert:     cert
		cert_key: key
		validate: false
	}
	mut l := mbedtls.new_ssl_listener('127.0.0.1:${port}', cfg) or {
		eprintln('SKIP: mbedtls TLS listen failed: ${err}')
		return
	}
	srv := spawn fn (mut l mbedtls.SSLListener) {
		mut c := l.accept() or {
			l.shutdown() or {}
			return
		}
		mut buf := []u8{len: 4096}
		c.read(mut buf) or {}
		body := 'hello-https'
		resp := 'HTTP/1.1 200 OK\r\nContent-Length: ${body.len}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n${body}'
		c.write(resp.bytes()) or {}
		c.shutdown() or {}
		l.shutdown() or {}
	}(mut l)

	prog := os.join_path(dir, 'cx_https_client.cx')
	os.write_file(prog, '[?lib \'cx-stdlib/http\' :as http]\n' +
		'[?let [= \$r [\$http:get "https://127.0.0.1:${port}/" {verify: false}]]\n' +
		'  [\$http:body-text \$r]]\n') or { panic(err) }

	res := os.execute('${cx_binary()} --allow-net=127.0.0.1:${port} ${prog}')
	srv.wait()
	out := res.output.trim_space()
	assert out == "'hello-https'", 'cx https client did not read the real TLS response body; got: ${out}'
}

// the cx TLS SERVER core (net.md §3.3/§3.6): [$net:listen-tls] binds a real
// mbedTLS listener (server cert/key from opts.tls), [$net:accept] does the
// per-peer handshake and yields a secure socket. A V mbedTLS client drives it.
fn test_net_listen_tls_roundtrip() {
	if os.execute('which openssl').exit_code != 0 {
		eprintln('SKIP: openssl not available (cert generation)')
		return
	}
	// Disjoint PID + nanosecond-salted slot (27740-27839) so the concurrent
	// `v test vcx/tests/` gate processes don't collide on a port.
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	port := 27740 + int(salt)
	dir := os.temp_dir()
	cert := os.join_path(dir, 'cx_tlssrv_cert.pem')
	key := os.join_path(dir, 'cx_tlssrv_key.pem')
	gen := os.execute('openssl req -x509 -newkey rsa:2048 -keyout ${key} -out ${cert} -days 1 -nodes -subj "/CN=localhost" 2>/dev/null')
	if gen.exit_code != 0 || !os.is_file(cert) {
		eprintln('SKIP: openssl self-signed cert generation failed')
		return
	}
	prog := os.join_path(dir, 'cx_tls_server.cx')
	os.write_file(prog, '[?lib \'cx-stdlib/net\' :as net]\n' +
		'[?let [= \$l [\$net:listen-tls "tls://127.0.0.1:${port}" {tls: {cert: "${cert}" key: "${key}"}}]]\n' +
		'[?let [= \$conn [\$net:accept \$l]]\n' +
		'[?let [= \$line [\$net:read-line \$conn]]\n' +
		'[?let [= \$w [\$net:write-line \$conn \$line]]\n' +
		'[?let [= \$cc [\$net:close \$conn]]\n' + '  [\$net:close \$l]]]]]]\n') or { panic(err) }

	pid_s := os.execute('${cx_binary()} --allow-net ${prog} >/tmp/cx-tlssrv.${port}.out 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx tls server')
		return
	}
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	mut got := ''
	for _ in 0 .. 40 {
		mut c := mbedtls.new_ssl_conn(mbedtls.SSLConnectConfig{ validate: false }) or {
			time.sleep(100 * time.millisecond)
			continue
		}
		c.dial('127.0.0.1', port) or {
			time.sleep(100 * time.millisecond)
			continue
		}
		c.write_string('hello-tls-server\n') or {}
		mut buf := []u8{len: 256}
		n := c.read(mut buf) or { 0 }
		c.close() or {}
		got = buf[..n].bytestr().trim_space()
		break
	}
	assert got == 'hello-tls-server', 'cx tls server did not echo over a real TLS handshake; got: ${got}'
}
