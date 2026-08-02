module main

import os
import testenv
import time
import net

// net_set_opt_test.v — BEHAVIORAL gate for #548: `[$net:set-opt]` either
// APPLIES a §3.7 option or REFUSES it loudly, per key — never a phantom
// accept (before the fix every option except the #56 deadlines was
// silently swallowed). Availability per this build's V net surface:
// line-terminator / keepalive / recv-buf / send-buf / nodelay=true apply;
// nodelay=false, linger, multicast-*, unknown keys, and cross-transport
// misuse (broadcast on TCP) refuse with E_NET_ARG_INVALID naming the
// option. UDP broadcast applies.

fn nso_pick_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 80
	return 26200 + int(salt)
}

fn test_set_opt_applies_or_refuses_per_key() {
	port := nso_pick_port()
	mut listener := net.listen_tcp(.ip, '127.0.0.1:${port}') or {
		eprintln('SKIP: cannot bind 127.0.0.1:${port}: ${err}')
		return
	}
	listener.set_accept_timeout(10 * time.second)
	srv := spawn fn (mut l net.TcpListener) {
		mut c := l.accept() or {
			l.close() or {}
			return
		}
		time.sleep(3000 * time.millisecond)
		c.close() or {}
		l.close() or {}
	}(mut listener)

	prog := os.join_path(os.temp_dir(), 'nso-${os.getpid()}.cx')
	os.write_file(prog, "[?lib 'cx-stdlib/net' :as net]
[?let
  [= \$s [\$net:dial-tcp 'tcp://127.0.0.1:${port}' {read-deadline: 1000}]]
  [= \$u [\$net:dial-udp 'udp://127.0.0.1:${port}' {}]]
  ([applies ([\$net:set-opt \$s {line-terminator: 'crlf'}],
             [\$net:set-opt \$s {keepalive: true}],
             [\$net:set-opt \$s {keepalive: 30000}],
             [\$net:set-opt \$s {recv-buf: 65536, send-buf: 65536}],
             [\$net:set-opt \$s {nodelay: true}],
             [\$net:set-opt \$u {broadcast: true}])],
   [nod-false [\$net:set-opt \$s {nodelay: false}]],
   [linger [\$net:set-opt \$s {linger: 5}]],
   [bcast-tcp [\$net:set-opt \$s {broadcast: true}]],
   [mcast [\$net:set-opt \$u {multicast-ttl: 4}]],
   [unknown [\$net:set-opt \$s {frobnicate: 1}]])]
") or { panic(err) }
	defer {
		os.rm(prog) or {}
	}
	res := os.execute('${testenv.cx_bin()} --allow-net=127.0.0.1:${port} ${prog}')
	srv.wait()
	assert res.exit_code == 0, 'program failed: ${res.output}'
	out := res.output
	// the applying keys all yield null — no [err] inside the applies group
	applies := out.all_before('[nod-false')
	assert !applies.contains('[err'), 'an applying option refused: ${applies}'
	assert applies.contains('(null, null, null, null, null, null)'), 'expected six nulls: ${applies}'
	// each refusal names its option
	assert out.contains('nodelay=false cannot be applied'), 'nodelay=false: ${out}'
	assert out.contains('linger is not settable'), 'linger: ${out}'
	assert out.contains('broadcast is a UDP option'), 'broadcast-on-tcp: ${out}'
	assert out.contains('multicast-ttl is not settable'), 'multicast: ${out}'
	assert out.contains('unknown socket option "frobnicate"'), 'unknown key: ${out}'
}
