module main

import os
import testenv
import time
import net
import net.http

// fabric_nats_bridge_test.v — BEHAVIORAL proof of the cx-fabric NATS bridge
// adapter (#547; spec/03-approved/xap/fabric.md §14/§18): tooling/cxfabric/
// nats-bridge.cx (pure cx over cx-stdlib/net) driven end-to-end against a
// real `cx fabric-serve` daemon and a MOCK NATS server implemented right
// here (the client subset of the NATS text protocol: INFO/CONNECT/PING/
// PONG/SUB/PUB/MSG) — the suite stays hermetic, no external NATS binary.
//
// The single lane proves BOTH directions plus the ack barrier in one round
// trip: the mock injects a MSG on the bridge's in-route subject → the
// bridge publishes it as canonical CX onto the daemon's `orders` stream
// (ingress) → the bridge's own out-route group receives it → PUB back to
// the mock on `cx.orders` (egress) → the bridge PINGs and only acks after
// the mock's PONG. A separate cx client then reads the stream to prove the
// ingress event landed durable and verbatim.

const nb_host_did = 'did:key:z6MkiaMbhXHNA4eJVCCj8dbzKzTgYDKf6crKgHVHid1F1WCT' // RFC 8032 TEST 2
const nb_host_seed_hex = '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'
const nb_client_did = 'did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw' // RFC 8032 TEST 1
const nb_client_seed_hex = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'

// Disjoint PID + nanosecond-salted band (27900-27999) from the other
// engine tests' daemon/TLS bands.
fn nb_pick_port(lane int) int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 20
	return 27900 + lane * 30 + int(salt)
}

fn nb_write(dir string, name string, content string) string {
	p := os.join_path(dir, name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

fn nb_boot_daemon(port int, hport int, tmp string) &os.Process {
	cfg := '[fabric-service
  [bind addr="127.0.0.1:${port}"]
  [health addr="127.0.0.1:${hport}"]
  [identity did="${nb_host_did}" seed-env="CX_FABRIC_SEED"]
  [policy mode="mutual"]
  [limits pending-window=32 liveness-ms=30000]
  [fabrics [fabric name="main" store="mem://natsb" tenant="acme"]]
  [principals
    [principal did="${nb_client_did}"
      [grant action="publish" scope="*"]
      [grant action="consume" scope="*"]
      [grant action="observe" scope="*"]]]]'
	cfg_path := nb_write(tmp, 'fabric.service.cx', cfg)
	os.setenv('CX_FABRIC_SEED', nb_host_seed_hex, true)
	mut proc := os.new_process('/bin/sh')
	proc.set_args(['-c',
		'exec "${testenv.cx_bin()}" fabric-serve --config "${cfg_path}" --allow-net=127.0.0.1:${port} --allow-net=127.0.0.1:${hport} --allow-env >"${tmp}/daemon.log" 2>&1'])
	proc.run()
	mut up := false
	for _ in 0 .. 100 {
		time.sleep(100 * time.millisecond)
		r := http.get('http://127.0.0.1:${hport}/ready') or { continue }
		if r.status_code == 200 && r.body.contains('[accepting true]') {
			up = true
			break
		}
	}
	if !up {
		proc.signal_kill()
		out := os.read_file(os.join_path(tmp, 'daemon.log')) or { '' }
		panic('fabric-serve never came up: ${out}')
	}
	return proc
}

// ── the mock NATS server ─────────────────────────────────────────────────────

fn nb_index_of_crlf(b []u8) int {
	for i := 0; i + 1 < b.len; i++ {
		if b[i] == u8(`\r`) && b[i + 1] == u8(`\n`) {
			return i
		}
	}
	return -1
}

// nb_nats_mock accepts ONE connection (the bridge) and speaks the server
// side of the protocol subset: greets with INFO; answers every PING with
// PONG; records CONNECT / SUB / PUB (with its counted payload) as events
// on the channel; injects exactly one MSG on the first SUB it sees (the
// ingress probe). Runs until the hold deadline, then closes.
fn nb_nats_mock(mut l net.TcpListener, events chan string, payload string, hold_ms int) {
	mut c := l.accept() or {
		events <- 'accept-failed ${err}'
		return
	}
	c.set_read_timeout(200 * time.millisecond)
	c.write('INFO {"server_id":"cx-mock","max_payload":1048576}\r\n'.bytes()) or {}
	mut acc := []u8{}
	mut pending_pub := ''
	mut pending_len := -1
	mut injected := false
	sw := time.new_stopwatch()
	for sw.elapsed().milliseconds() < hold_ms {
		mut buf := []u8{len: 4096}
		n := c.read(mut buf) or {
			continue // read timeout — keep serving until the hold expires
		}
		if n <= 0 {
			time.sleep(20 * time.millisecond)
			continue
		}
		acc << buf[..n]
		for {
			if pending_len >= 0 {
				// a PUB header announced pending_len payload bytes + CRLF
				if acc.len < pending_len + 2 {
					break
				}
				body := acc[..pending_len].bytestr()
				acc = acc[pending_len + 2..].clone()
				events <- 'pub ${pending_pub} ${body}'
				pending_len = -1
				continue
			}
			idx := nb_index_of_crlf(acc)
			if idx < 0 {
				break
			}
			line := acc[..idx].bytestr()
			acc = acc[idx + 2..].clone()
			if line.starts_with('CONNECT ') {
				events <- 'connect'
			} else if line == 'PING' {
				c.write('PONG\r\n'.bytes()) or {}
				events <- 'ping'
			} else if line.starts_with('SUB ') {
				events <- 'sub ${line[4..]}'
				if !injected {
					injected = true
					parts := line.split(' ') // SUB <subject> <sid>
					c.write('MSG ${parts[1]} ${parts[2]} ${payload.len}\r\n${payload}\r\n'.bytes()) or {}
				}
			} else if line.starts_with('PUB ') {
				p := line.split(' ')
				pending_pub = p[1]
				pending_len = p[p.len - 1].int()
			}
		}
	}
	c.close() or {}
	l.close() or {}
}

// nb_wait drains the event channel until an event with the wanted prefix
// arrives (skipping others — extra pings are legal) or the timeout lapses.
fn nb_wait(events chan string, want_prefix string, timeout_ms int) string {
	sw := time.new_stopwatch()
	for sw.elapsed().milliseconds() < timeout_ms {
		mut item := ''
		if events.try_pop(mut item) == .success {
			if item.starts_with(want_prefix) {
				return item
			}
			continue
		}
		time.sleep(25 * time.millisecond)
	}
	return ''
}

// ── the end-to-end lane ──────────────────────────────────────────────────────

fn test_nats_bridge_round_trip() {
	fport := nb_pick_port(0)
	hport := fport + 1
	nport := nb_pick_port(2)
	tmp := os.join_path(os.temp_dir(), 'cx-nats-bridge-${os.getpid()}')
	os.rmdir_all(tmp) or {}
	os.mkdir_all(tmp) or { panic('mkdir: ${err}') }
	mut daemon := nb_boot_daemon(fport, hport, tmp)
	defer {
		daemon.signal_kill()
		os.unsetenv('CX_FABRIC_SEED')
		os.rmdir_all(tmp) or {}
	}

	// the mock NATS server (one connection, 20s hold)
	mut listener := net.listen_tcp(.ip, '127.0.0.1:${nport}') or {
		panic('cannot bind mock NATS on 127.0.0.1:${nport}: ${err}')
	}
	listener.set_accept_timeout(15 * time.second)
	events := chan string{cap: 256}
	payload := '[do :order.placed]'
	mock := spawn nb_nats_mock(mut listener, events, payload, 20000)

	// the bridge, on the REAL adapter source
	bridge_cfg := nb_write(tmp, 'nats-bridge.config.cx', '[nats-bridge
  [fabric url="xsp://127.0.0.1:${fport}" tenant="acme"
          did="${nb_client_did}" seed-env="CX_BRIDGE_SEED"
          responder="${nb_host_did}"]
  [nats url="tcp://127.0.0.1:${nport}"]
  [routes
    [in subject="legacy.orders" stream="orders"]
    [out stream="orders" pattern=":order.*" group="nats-out"
         subject="cx.orders" fmt="cx"]]]')
	os.setenv('CX_BRIDGE_SEED', nb_client_seed_hex, true)
	bridge_src := os.real_path(os.join_path(os.dir(@FILE), '..', '..', 'tooling', 'cxfabric',
		'nats-bridge.cx'))
	mut bridge := os.new_process('/bin/sh')
	bridge.set_args(['-c',
		'exec "${testenv.cx_bin()}" --data="${bridge_cfg}" --allow-net=127.0.0.1:${fport} --allow-net=127.0.0.1:${nport} --allow-env "${bridge_src}" >"${tmp}/bridge.log" 2>&1'])
	bridge.run()
	defer {
		bridge.signal_kill()
		os.unsetenv('CX_BRIDGE_SEED')
	}

	// handshake: CONNECT then the liveness PING (the mock answered PONG)
	assert nb_wait(events, 'connect', 8000) != '', 'bridge never sent CONNECT: ${os.read_file(os.join_path(tmp,
		'bridge.log')) or { '' }}'
	assert nb_wait(events, 'ping', 8000) != '', 'bridge never sent the handshake PING'

	// the in-route SUB (subject + position-derived sid); the mock injects
	// the MSG the moment it sees it
	sub := nb_wait(events, 'sub ', 8000)
	assert sub == 'sub legacy.orders in-1', 'unexpected SUB: "${sub}"'

	// full echo: MSG → ingress publish (canonical CX, verbatim element) →
	// daemon → egress group receive → PUB back on the out-route subject
	pub_ev := nb_wait(events, 'pub ', 10000)
	assert pub_ev == 'pub cx.orders ${payload}', 'unexpected PUB echo: "${pub_ev}" (bridge log: ${os.read_file(os.join_path(tmp,
		'bridge.log')) or { '' }})'

	// the ack barrier: a PING follows the PUB batch (ack commits on PONG)
	assert nb_wait(events, 'ping', 8000) != '', 'bridge never sent the ack-barrier PING'

	// daemon-side proof: the ingress event is durable on `orders` and
	// verbatim — a second principal group reads it from seq 1
	reader := nb_write(tmp, 'reader.cx', "[?lib 'cx-fabric' :as fabric]
[?lib 'cx-stdlib/bytes' :as bytes]
[?let
  [= \$f [\$fabric:open \"xsp://127.0.0.1:${fport}\" {tenant: \"acme\", did: \"${nb_client_did}\", seed: [\$bytes:from-hex \"${nb_client_seed_hex}\"], responder: \"${nb_host_did}\"}]]
  [= \$s [\$fabric:subscribe \$f \"orders\" :order.* {group: \"verify\"}]]
  [= \$es [\$fabric:receive \$s {max: 10, deadline: 3000}]]
  [?element 'out'
    [?attr 'n' [\$concat '' [\$count \$es]]]
    [\$first \$es]]]
")
	res := os.execute('${testenv.cx_bin()} --allow-net=127.0.0.1:${fport} ${reader}')
	assert res.exit_code == 0, 'reader failed: ${res.output}'
	assert res.output.contains("n='1'"), 'expected exactly the injected event on the stream: ${res.output}'
	assert res.output.contains('[do :order.placed]'), 'ingress event not verbatim: ${res.output}'

	listener.close() or {}
	mock.wait()
}
