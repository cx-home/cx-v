module main

import os
import testenv
import time
import net
import net.unix

// net_real_socket_test.v — BEHAVIORAL conformance for cx-stdlib/net over
// a REAL loopback socket (net.md §10: "Hermetic, loopback-only. Positives:
// stream round-trip; read-line empty-at-EOF + is-eof"). This is the TDD red
// test for the TCP stream core: it proves the cx `net` verbs perform real I/O,
// not the synthetic handle shape. It MUST fail against the stub (which returns
// '' / 0 / a fake [socket fd=N]) and pass only once dial/listen/accept/read/
// write/close do real syscalls.
//
// Two legs, mirroring the two endpoints:
//   - client leg: a V echo server in-process; the cx program is the CLIENT
//     (dial-tcp + write-line + read-line) and must read back what it wrote.
//   - server leg: the cx program is the SERVER (listen-tcp + accept-iter echo);
//     a V client connects and must read back what it sent.
//
// Both legs are BOUNDED (accept-timeout / bounded dial retries) so the test
// fails fast against the stub rather than hanging on a blocking accept.

fn cx_binary() string {
	return testenv.cx_bin()
}

// Disjoint PID + nanosecond-salted band (26600-26699) so the concurrent
// `v test vcx/tests/` gate processes don't collide on a port.
fn pick_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 26600 + int(salt)
}

fn write_tmp(name string, content string) string {
	p := os.join_path(os.temp_dir(), name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

// ── client leg: cx is the client, a V echo server backs it ──────────────────
fn test_net_tcp_client_roundtrip() {
	port := pick_port()
	mut listener := net.listen_tcp(.ip, '127.0.0.1:${port}') or {
		eprintln('SKIP: cannot bind 127.0.0.1:${port}: ${err}')
		return
	}
	listener.set_accept_timeout(3 * time.second)
	// one-shot echo server on a background thread; bounded by accept-timeout so
	// it returns even if the cx client never really connects (the stub case).
	srv := spawn fn (mut l net.TcpListener) {
		mut c := l.accept() or {
			l.close() or {}
			return
		}
		mut buf := []u8{len: 256}
		n := c.read(mut buf) or { 0 }
		if n > 0 {
			c.write(buf[..n]) or {}
		}
		c.close() or {}
		l.close() or {}
	}(mut listener)

	prog := write_tmp('cx_net_client.cx', '[?lib \'cx-stdlib/net\' :as net]\n' +
		'[?let [= \$s [\$net:dial-tcp "tcp://127.0.0.1:${port}" {}]]\n' +
		'[?let [= \$w [\$net:write-line \$s "ping-from-cx"]]\n' +
		'[?let [= \$line [\$net:read-line \$s]]\n' +
		'[?let [= \$c [\$net:close \$s]]\n' + '  \$line]]]]\n')

	// loopback dial needs the §4.5 literal-IP override grant (bare --allow-net
	// is denied for 127.0.0.0/8 by the deny set).
	res := os.execute('${cx_binary()} --allow-net=127.0.0.1:${port} ${prog}')
	srv.wait()
	// the program's last expression is the read-back string; the cx CLI renders
	// a string value in canonical quoted form, so the real round-trip surfaces
	// as 'ping-from-cx' (quotes are the render, the bytes are what crossed).
	out := res.output.trim_space()
	assert out == "'ping-from-cx'", 'cx net client did not round-trip a real socket; got: ${out}'
}

// ── server leg: cx is the server, a V client drives it ──────────────────────
// PENDING the next net sub-layer: real `listen-tcp` + the lazy `accept-iter`
// connection: a cx server that listen-tcp + accept (single) + echoes one line.
// (Lazy `accept-iter` — the loop form — is a later sub-layer; single `accept`
// is the real server primitive exercised here.)
fn test_net_tcp_server_roundtrip() {
	port := pick_port() + 1
	prog := write_tmp('cx_net_server.cx', '[?lib \'cx-stdlib/net\' :as net]\n' +
		'[?let [= \$l [\$net:listen-tcp "tcp://127.0.0.1:${port}" {}]]\n' +
		'[?let [= \$conn [\$net:accept \$l]]\n' +
		'[?let [= \$line [\$net:read-line \$conn]]\n' +
		'[?let [= \$w [\$net:write-line \$conn \$line]]\n' +
		'[?let [= \$cc [\$net:close \$conn]]\n' + '  [\$net:close \$l]]]]]]\n')

	pid_s := os.execute('${cx_binary()} --allow-net ${prog} >/tmp/cx-net-srv.${port}.out 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx net server')
		return
	}
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	mut got := ''
	mut connected := false
	for _ in 0 .. 30 {
		mut c := net.dial_tcp('127.0.0.1:${port}') or {
			time.sleep(100 * time.millisecond)
			continue
		}
		connected = true
		c.write_string('hello-from-v\n') or {}
		mut buf := []u8{len: 256}
		n := c.read(mut buf) or { 0 }
		c.close() or {}
		got = buf[..n].bytestr().trim_space()
		break
	}
	assert connected, 'cx net server never accepted a connection on ${port}'
	assert got == 'hello-from-v', 'cx net server did not echo over a real socket; got: ${got}'
}

// UDP connected client (§3.5): cx dial-udp + send + recv round-trips a datagram
// against a V UDP echo server over loopback.
fn test_net_udp_client_roundtrip() {
	port := pick_port() + 5
	mut server := net.listen_udp('127.0.0.1:${port}') or {
		eprintln('SKIP: cannot bind udp 127.0.0.1:${port}: ${err}')
		return
	}
	server.set_read_timeout(4 * time.second)
	srv := spawn fn (mut s net.UdpConn) {
		mut buf := []u8{len: 256}
		n, addr := s.read(mut buf) or {
			s.close() or {}
			return
		}
		if n > 0 {
			s.write_to(addr, buf[..n]) or {}
		}
		s.close() or {}
	}(mut server)

	prog := write_tmp('cx_udp_client.cx', '[?lib \'cx-stdlib/net\' :as net]\n' +
		'[?lib \'cx-stdlib/bytes\' :as bytes]\n' +
		'[?let [= \$s [\$net:dial-udp "udp://127.0.0.1:${port}" {}]]\n' +
		'[?let [= \$w [\$net:send \$s "udp-ping"]]\n' +
		'[?let [= \$r [\$net:recv \$s 256]]\n' +
		'[?let [= \$c [\$net:close \$s]]\n' + '  [\$bytes:to-string-latin1 \$r]]]]]\n')

	res := os.execute('${cx_binary()} --allow-net=127.0.0.1:${port} ${prog}')
	srv.wait()
	out := res.output.trim_space()
	assert out.contains('udp-ping'), 'cx udp client did not round-trip a datagram; got: ${out}'
}

// accept-iter (§3.3): a cx listen-tcp + [?for [in $conn accept-iter]] echo
// server accepts connections in a LOOP — two sequential clients both get echoed.
fn test_net_accept_iter_loop() {
	port := pick_port() + 20
	prog := write_tmp('cx_accept_iter.cx', '[?lib \'cx-stdlib/net\' :as net]\n' +
		'[?let [= \$l [\$net:listen-tcp "tcp://127.0.0.1:${port}" {}]]\n' +
		'  [?for [in \$conn [\$net:accept-iter \$l]]\n' +
		'    [yield [?let [= \$line [\$net:read-line \$conn]]\n' +
		'            [?let [= \$w [\$net:write-line \$conn \$line]]\n' +
		'              [\$net:close \$conn]]]]]]\n')
	pid_s := os.execute('${cx_binary()} --allow-net ${prog} >/tmp/cx-ai.out 2>&1 & echo \$!')
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	mut got := []string{}
	for msg in ['first', 'second'] {
		for _ in 0 .. 30 {
			mut c := net.dial_tcp('127.0.0.1:${port}') or {
				time.sleep(100 * time.millisecond)
				continue
			}
			c.write_string('${msg}\n') or {}
			mut buf := []u8{len: 64}
			n := c.read(mut buf) or { 0 }
			c.close() or {}
			got << buf[..n].bytestr().trim_space()
			break
		}
	}
	assert got.len == 2 && got[0] == 'first' && got[1] == 'second', 'accept-iter loop did not echo both clients; got: ${got}'
}

// UDP recv-from (§3.5): a cx listen-udp server surfaces the datagram bytes +
// the sender addr; a V client sends one datagram.
fn test_net_udp_recv_from() {
	port := pick_port() + 7
	out_file := os.join_path(os.temp_dir(), 'cx-udp-rf-${port}.out')
	os.rm(out_file) or {}
	prog := write_tmp('cx_udp_recvfrom.cx', '[?lib \'cx-stdlib/net\' :as net]\n' +
		'[?let [= \$s [\$net:listen-udp "udp://127.0.0.1:${port}" {}]]\n' + '  [\$net:recv-from \$s 256]]\n')
	pid_s := os.execute('${cx_binary()} --allow-net ${prog} >${out_file} 2>&1 & echo \$!')
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(500 * time.millisecond) // let the server bind
	mut c := net.dial_udp('127.0.0.1:${port}') or {
		eprintln('SKIP: udp dial failed: ${err}')
		return
	}
	c.write('udp-ping'.bytes()) or {}
	c.close() or {}
	mut out := ''
	for _ in 0 .. 30 {
		out = os.read_file(out_file) or { '' }
		if out.contains('datagram') {
			break
		}
		time.sleep(100 * time.millisecond)
	}
	assert out.contains('udp-ping'), 'recv-from did not surface the datagram bytes; got: ${out}'
	assert out.contains('127.0.0.1'), 'recv-from did not surface the sender addr; got: ${out}'
}

// UDP send-to (§3.5, §4.5-gated): a cx program sends one datagram to a V server.
fn test_net_udp_send_to() {
	port := pick_port() + 8
	out_file := os.join_path(os.temp_dir(), 'cx-udp-st-${port}.out')
	os.rm(out_file) or {}
	mut server := net.listen_udp('127.0.0.1:${port}') or {
		eprintln('SKIP: cannot bind udp ${port}: ${err}')
		return
	}
	server.set_read_timeout(4 * time.second)
	srv := spawn fn (mut s net.UdpConn, f string) {
		mut buf := []u8{len: 128}
		n, _ := s.read(mut buf) or {
			s.close() or {}
			return
		}
		os.write_file(f, buf[..n].bytestr()) or {}
		s.close() or {}
	}(mut server, out_file)

	src := port + 100
	prog := write_tmp('cx_udp_sendto.cx', '[?lib \'cx-stdlib/net\' :as net]\n' +
		'[?let [= \$s [\$net:listen-udp "udp://127.0.0.1:${src}" {}]]\n' +
		'  [\$net:send-to \$s "udp-to-srv" "127.0.0.1:${port}"]]\n')
	// send-to to loopback needs the §4.5 literal-IP override grant.
	os.execute('${cx_binary()} --allow-net=127.0.0.1:${port} ${prog}')
	srv.wait()
	got := os.read_file(out_file) or { '' }
	assert got.contains('udp-to-srv'), 'cx send-to did not deliver the datagram; got: ${got}'
}

// Unix-domain stream round-trip (§3.2/§3.3): cx listen-unix + accept echo
// server, driven by a V unix client over a temp socket path.
fn test_net_unix_roundtrip() {
	$if windows {
		eprintln('SKIP: Unix-domain sockets not on Windows')
		return
	}
	sock := os.join_path(os.temp_dir(), 'cx_unix_${pick_port()}.sock')
	os.rm(sock) or {}
	prog := write_tmp('cx_unix_server.cx', '[?lib \'cx-stdlib/net\' :as net]\n' +
		'[?let [= \$l [\$net:listen-unix "${sock}" {}]]\n' +
		'[?let [= \$conn [\$net:accept \$l]]\n' +
		'[?let [= \$line [\$net:read-line \$conn]]\n' +
		'[?let [= \$w [\$net:write-line \$conn \$line]]\n' +
		'[?let [= \$cc [\$net:close \$conn]]\n' + '  [\$net:close \$l]]]]]]\n')
	pid_s := os.execute('${cx_binary()} --allow-net ${prog} >/tmp/cx-unix-srv.out 2>&1 & echo \$!')
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
		os.rm(sock) or {}
	}
	mut got := ''
	for _ in 0 .. 30 {
		mut c := unix.connect_stream(sock) or {
			time.sleep(100 * time.millisecond)
			continue
		}
		c.write_string('hello-unix\n') or {}
		mut buf := []u8{len: 128}
		n := c.read(mut buf) or { 0 }
		c.close() or {}
		got = buf[..n].bytestr().trim_space()
		break
	}
	assert got == 'hello-unix', 'cx unix server did not echo over a real unix socket; got: ${got}'
}

// §4.5 SSRF guard on dial (behavioral): the deny set blocks private/loopback
// candidates under a bare grant; a literal-IP grant overrides (reaches connect).
fn test_net_ssrf_dial_guard() {
	bin := cx_binary()
	priv := write_tmp('cx_ssrf_priv.cx', '[?lib \'cx-stdlib/net\' :as net]\n' +
		'[\$net:dial-tcp "tcp://10.0.0.1:80" {}]\n')
	r1 := os.execute('${bin} --allow-net ${priv}')
	assert r1.output.contains('CXER4504'), 'private range must be denied (CXER4504); got: ${r1.output}'

	lb := write_tmp('cx_ssrf_lb.cx', '[?lib \'cx-stdlib/net\' :as net]\n' +
		'[\$net:dial-tcp "tcp://127.0.0.1:9" {}]\n')
	r2 := os.execute('${bin} --allow-net ${lb}')
	assert r2.output.contains('CXER4504'), 'loopback must be denied under a bare grant; got: ${r2.output}'

	// literal-IP grant overrides the deny set → reaches the actual connect
	// (refused/unreachable on the dead port :9), NOT CXER4504.
	r3 := os.execute('${bin} --allow-net=127.0.0.1:9 ${lb}')
	assert !r3.output.contains('CXER4504'), 'literal-IP grant must override the deny set; got: ${r3.output}'
	assert r3.output.contains('CXER4505') || r3.output.contains('CXER4506'), 'override should reach connect on :9; got: ${r3.output}'
}

// resolve: real getaddrinfo (§3.1). `localhost` always resolves to loopback
// locally (hermetic — no external network), so the result must contain 127.0.0.1.
fn test_net_resolve_localhost() {
	prog := write_tmp('cx_net_resolve.cx', '[?lib \'cx-stdlib/net\' :as net]\n' +
		'[\$net:resolve "localhost" {}]\n')
	res := os.execute('${cx_binary()} --allow-net ${prog}')
	out := res.output
	assert out.contains('127.0.0.1') || out.contains('::1'), 'net:resolve localhost did not return a real loopback addr; got: ${out}'
}
