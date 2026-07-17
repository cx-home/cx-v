module main

import os
import testenv
import time
import net.mbedtls

// net_dtls_test.v — BEHAVIORAL conformance for cx-stdlib/net DTLS
// (net.md §3.6a). DTLS-over-UDP secures a *datagram* socket: the cx verbs are
// [$net:dial-dtls] (client = connected UDP + DTLS handshake) and
// [$net:listen-dtls] + [$net:accept] (server, with the MANDATORY stateless
// HelloVerifyRequest cookie exchange before per-peer handshake state is
// allocated — the anti-amplification defense, §3.6a/H3). A DTLS socket then
// uses the §3.5 datagram verbs (send/recv), NOT the §3.4 stream verbs.
//
// Two legs:
//   - dial leg:  a cx DTLS server + a cx DTLS client (both subprocesses) round-
//     trip one application datagram — proves [$net:dial-dtls] runs a real
//     handshake + send/recv over the secured socket.
//   - listen leg: a cx DTLS server (subprocess) driven by an INDEPENDENT V
//     mbedTLS DTLS client — proves the cx server's [$net:listen-dtls]/accept
//     completes the mandatory HelloVerifyRequest cookie exchange against an
//     external implementation, then echoes a datagram.
//
// Hermetic, loopback-only; loopback dialing uses the §4.5 literal-IP grant.
// Every subprocess is wrapped in a shell-level watchdog so a regression fails
// fast instead of blocking. (We deliberately avoid an in-process V server
// thread + os.execute, which would fork a multithreaded V process — the macOS
// fork hazard; the cx subprocess path exercises the same wrapper either way.)
// MUST fail against the honest-CXER "dtls not yet implemented" fall-through.

fn cx_binary() string {
	return testenv.cx_bin()
}

fn gen_selfsigned(cert string, key string) bool {
	if os.execute('which openssl').exit_code != 0 {
		eprintln('SKIP: openssl not available (cert generation)')
		return false
	}
	gen := os.execute('openssl req -x509 -newkey rsa:2048 -keyout ${key} -out ${cert} -days 1 -nodes -subj "/CN=localhost" 2>/dev/null')
	if gen.exit_code != 0 || !os.is_file(cert) {
		eprintln('SKIP: openssl self-signed cert generation failed')
		return false
	}
	return true
}

// run_guarded runs `inner` in the background under a hard `secs` watchdog, so a
// stuck handshake fails fast rather than hanging the suite. Returns when the
// command finishes or is killed.
fn run_guarded(inner string, secs int) os.Result {
	return os.execute('( ${inner} ) & CMDPID=\$!; ( sleep ${secs}; kill -9 \$CMDPID 2>/dev/null ) & WDPID=\$!; wait \$CMDPID; STAT=\$?; kill \$WDPID 2>/dev/null; exit \$STAT')
}

// ── dial leg: cx DTLS client round-trips against a cx DTLS server ───────────
fn test_net_dial_dtls_roundtrip() {
	// Disjoint PID + nanosecond-salted slot (27200-27299) so the concurrent
	// `v test vcx/tests/` gate processes don't collide on a port.
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	port := 27200 + int(salt)
	dir := os.temp_dir()
	cert := os.join_path(dir, 'cx_dtls_cert.pem')
	key := os.join_path(dir, 'cx_dtls_key.pem')
	if !gen_selfsigned(cert, key) {
		return
	}

	srv_prog := os.join_path(dir, 'cx_dtls_server_a.cx')
	os.write_file(srv_prog, '[?lib \'cx-stdlib/net\' :as net]\n' +
		'[?let [= \$l [\$net:listen-dtls "dtls://127.0.0.1:${port}" {tls: {cert: "${cert}" key: "${key}"}}]]\n' +
		'[?let [= \$conn [\$net:accept \$l]]\n' +
		'[?let [= \$msg [\$net:recv \$conn 512]]\n' +
		'[?let [= \$w [\$net:send \$conn \$msg]]\n' +
		'[?let [= \$cc [\$net:close \$conn]]\n' + '  [\$net:close \$l]]]]]]\n') or { panic(err) }

	srv_out := os.join_path(dir, 'cx-dtls-srv-a.${port}.out')
	pid_s := os.execute('${cx_binary()} --allow-net ${srv_prog} >${srv_out} 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx dtls server')
		return
	}
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(1500 * time.millisecond) // let the server bind before the client dials

	cli_prog := os.join_path(dir, 'cx_dtls_client_a.cx')
	os.write_file(cli_prog, '[?lib \'cx-stdlib/net\' :as net]\n' +
		'[?lib \'cx-stdlib/bytes\' :as bytes]\n' +
		'[?let [= \$s [\$net:dial-dtls "dtls://127.0.0.1:${port}" {tls: {verify: false}}]]\n' +
		'[?let [= \$w [\$net:send \$s "dtls-ping"]]\n' +
		'[?let [= \$r [\$net:recv \$s 512]]\n' +
		'[?let [= \$c [\$net:close \$s]]\n' + '  [\$bytes:to-string-latin1 \$r]]]]]\n') or { panic(err) }

	res := run_guarded('${cx_binary()} --allow-net=127.0.0.1:${port} ${cli_prog}', 15)
	out := res.output.trim_space()
	assert out.contains('dtls-ping'), 'cx dial-dtls did not round-trip a datagram over real DTLS; got: ${out}'
}

// ── listen leg: cx DTLS server driven by an independent V DTLS client ───────
// Exercises the server-side mandatory HelloVerifyRequest cookie exchange: the
// V client's first ClientHello carries no cookie, the cx server replies with a
// HelloVerifyRequest, and only the cookie-bearing retransmission completes.
fn test_net_listen_dtls_roundtrip() {
	// Disjoint PID + nanosecond-salted slot (27320-27419) so the concurrent
	// `v test vcx/tests/` gate processes don't collide on a port.
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	port := 27320 + int(salt)
	dir := os.temp_dir()
	cert := os.join_path(dir, 'cx_dtlssrv_cert.pem')
	key := os.join_path(dir, 'cx_dtlssrv_key.pem')
	if !gen_selfsigned(cert, key) {
		return
	}
	prog := os.join_path(dir, 'cx_dtls_server_b.cx')
	os.write_file(prog, '[?lib \'cx-stdlib/net\' :as net]\n' +
		'[?let [= \$l [\$net:listen-dtls "dtls://127.0.0.1:${port}" {tls: {cert: "${cert}" key: "${key}"}}]]\n' +
		'[?let [= \$conn [\$net:accept \$l]]\n' +
		'[?let [= \$msg [\$net:recv \$conn 512]]\n' +
		'[?let [= \$w [\$net:send \$conn \$msg]]\n' +
		'[?let [= \$cc [\$net:close \$conn]]\n' + '  [\$net:close \$l]]]]]]\n') or { panic(err) }

	srv_out := os.join_path(dir, 'cx-dtlssrv-b.${port}.out')
	pid_s := os.execute('${cx_binary()} --allow-net ${prog} >${srv_out} 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx dtls server')
		return
	}
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}

	// DTLS dial to an unbound UDP port does NOT fail fast (unlike a refused TCP
	// connect) — it retransmits the ClientHello until the handshake timeout. Bound
	// that window so a dial racing the server's bind fails in ~2.5 s and we retry,
	// rather than blocking on the 60 s RFC default. (Production leaves the default;
	// this is a hermetic-test-only bound.)
	cli_cfg := mbedtls.SSLConnectConfig{
		validate:              false
		dtls_handshake_min_ms: 400
		dtls_handshake_max_ms: 2500
	}
	mut got := ''
	for _ in 0 .. 12 {
		mut c := mbedtls.new_dtls_client(cli_cfg) or {
			time.sleep(100 * time.millisecond)
			continue
		}
		c.dial('127.0.0.1', port) or {
			c.close() or {}
			time.sleep(100 * time.millisecond)
			continue
		}
		c.write('hello-dtls-server'.bytes()) or {}
		mut buf := []u8{len: 512}
		n := c.read(mut buf) or { 0 }
		c.close() or {}
		got = buf[..n].bytestr().trim_space()
		break
	}
	assert got == 'hello-dtls-server', 'cx dtls server did not echo over a real DTLS handshake (cookie path); got: ${got}'
}
