module main

import os
import testenv
import time
import net
import net.http

// fabric_adapter_test.v — BEHAVIORAL proof of cx-fabric P3 (#531;
// spec/03-approved/xap/fabric.md §14/§15/§19.7): the REMOTE tier of the client
// surface ([$fabric:open "xsp://…"] — dial + XSP-AUTH attach + verbs over
// the served wire) and the HTTP/SSE webhook adapter riding it as an
// ordinary edge client, both driven end-to-end against a real
// `cx fabric-serve` daemon.
//
// Lane groups:
//   remote client (a cx program on the real [$fabric:*] surface):
//     open xsp:// with did/seed/responder pinning → publish receipts →
//     grouped subscribe → receive (buffered push, deadline) → cumulative
//     ack → offset persistence proven by a SECOND connection resuming past
//     the committed offset → transient emit/read → anonymous open refused
//     under mutual policy (the daemon's CXER-XSP-AUTH-ANONYMOUS-REFUSED
//     surfaces through open, verbatim)
//   webhook adapter (tooling/cxfabric/webhook-adapter.cx, pure cx):
//     bearer door (401 without, 404 with on unknown path) → webhook-in →
//     [receipt] with the payload published VERBATIM (canonical CX at the
//     boundary; JSON converts) → 400 on an unparseable body → SSE out
//     (live fan-out of matching entries as canonical CX data frames) →
//     webhook push (batch POST to a callback; cumulative ack after 2xx)

const fa_host_did = 'did:key:z6MkiaMbhXHNA4eJVCCj8dbzKzTgYDKf6crKgHVHid1F1WCT' // RFC 8032 TEST 2
const fa_host_seed_hex = '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'
const fa_client_did = 'did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw' // RFC 8032 TEST 1
const fa_client_seed_hex = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'

// Disjoint port band (27300-27499) from the other engine tests.
fn fa_pick_port(lane int) int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 40
	return 27300 + lane * 60 + int(salt)
}

fn fa_write(dir string, name string, content string) string {
	p := os.join_path(dir, name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

fn fa_boot_daemon(port int, hport int, tmp string) &os.Process {
	cfg := '[fabric-service
  [bind addr="127.0.0.1:${port}"]
  [health addr="127.0.0.1:${hport}"]
  [identity did="${fa_host_did}" seed-env="CX_FABRIC_SEED"]
  [policy mode="mutual"]
  [limits pending-window=32 liveness-ms=30000]
  [fabrics [fabric name="main" store="mem://p3t" tenant="acme"]]
  [principals
    [principal did="${fa_client_did}"
      [grant action="publish" scope="*"]
      [grant action="consume" scope="*"]
      [grant action="observe" scope="*"]]]]'
	cfg_path := fa_write(tmp, 'fabric.service.cx', cfg)
	os.setenv('CX_FABRIC_SEED', fa_host_seed_hex, true)
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

// ── remote client surface ────────────────────────────────────────────────────

fn test_fabric_remote_client_surface() {
	port := fa_pick_port(0)
	hport := port + 1
	tmp := os.join_path(os.temp_dir(), 'cx-fabric-p3-remote-${os.getpid()}')
	os.rmdir_all(tmp) or {}
	os.mkdir_all(tmp) or { panic('mkdir: ${err}') }
	mut daemon := fa_boot_daemon(port, hport, tmp)
	defer {
		daemon.signal_kill()
		os.unsetenv('CX_FABRIC_SEED')
		os.rmdir_all(tmp) or {}
	}

	// one cx program drives the whole client surface; its [out …] element is
	// the assertion carrier.
	prog := fa_write(tmp, 'client.cx', "[?lib 'cx-fabric' :as fabric]
[?lib 'cx-stdlib/bytes' :as bytes]
[?let
  [= \$f [\$fabric:open \"xsp://127.0.0.1:${port}\" {tenant: \"acme\", did: \"${fa_client_did}\", seed: [\$bytes:from-hex \"${fa_client_seed_hex}\"], responder: \"${fa_host_did}\"}]]
  [= \$r1 [\$fabric:publish \$f \"orders\" [do :order.placed] {}]]
  [= \$r2 [\$fabric:publish \$f \"orders\" [do :order.shipped] {}]]
  [= \$s  [\$fabric:subscribe \$f \"orders\" :order.* {group: \"g1\"}]]
  [= \$e1 [\$fabric:receive \$s {max: 10, deadline: 3000}]]
  [= \$a  [\$fabric:ack \$s 1]]
  [= \$em [\$fabric:emit \$f \"coord/map\" [viewport zoom=12]]]
  [= \$rd [\$fabric:read \$f \"coord/map\"]]
  [= \$e1first [\$first \$e1]]
  [?element 'out'
    [?attr 'state' \$f@state] [?attr 'responder' \$f@responder]
    [?attr 'seq1' [\$concat '' \$r1@seq]] [?attr 'seq2' [\$concat '' \$r2@seq]]
    [?attr 'assigned' [\$concat '' \$s@assigned]]
    [?attr 'n1' [\$concat '' [\$count \$e1]]]
    [?attr 'first-seq' [\$concat '' \$e1first@seq]]
    [?attr 'zoom' [\$concat '' \$rd@zoom]]]]
")
	res := os.execute('${testenv.cx_bin()} --allow-net=127.0.0.1:${port} ${prog}')
	assert res.exit_code == 0, 'remote client program failed: ${res.output}'
	out := res.output
	assert out.contains('state=open'), 'remote open: ${out}'
	assert out.contains('responder=${fa_host_did}'), 'responder pin: ${out}'
	assert out.contains("seq1='1'") && out.contains("seq2='2'"), 'publish receipts: ${out}'
	assert out.contains("assigned='true'"), 'group assignment: ${out}'
	assert out.contains("n1='2'"), 'receive both entries: ${out}'
	assert out.contains("first-seq='1'"), 'receive order: ${out}'
	assert out.contains("zoom='12'"), 'transient read: ${out}'

	// a SECOND connection in the same group resumes past the committed
	// offset — the acked entry (seq 1) never redelivers, the uncommitted
	// tail (seq 2) does. Offsets are store data on the daemon (§9).
	prog2 := fa_write(tmp, 'client2.cx', "[?lib 'cx-fabric' :as fabric]
[?lib 'cx-stdlib/bytes' :as bytes]
[?let
  [= \$f [\$fabric:open \"xsp://127.0.0.1:${port}\" {tenant: \"acme\", did: \"${fa_client_did}\", seed: [\$bytes:from-hex \"${fa_client_seed_hex}\"]}]]
  [= \$s  [\$fabric:subscribe \$f \"orders\" :order.* {group: \"g1\"}]]
  [= \$es [\$fabric:receive \$s {max: 10, deadline: 3000}]]
  [= \$efirst [\$first \$es]]
  [?element 'out2' [?attr 'n' [\$concat '' [\$count \$es]]]
                   [?attr 'first-seq' [\$concat '' \$efirst@seq]]]]
")
	res2 := os.execute('${testenv.cx_bin()} --allow-net=127.0.0.1:${port} ${prog2}')
	assert res2.exit_code == 0, 'remote client 2 failed: ${res2.output}'
	assert res2.output.contains("n='1'") && res2.output.contains("first-seq='2'"), 'committed-offset resume (redeliver exactly the uncommitted tail): ${res2.output}'

	// xsp.md §5.2 through the CLIENT surface (#560): a windowed observe
	// ({window: 2}) is credit-bounded — the daemon pushes exactly the
	// window, the client library auto-credits what receive hands the app,
	// and the released tail arrives on the NEXT receive. from=1 is the
	// §5.3 explicit observe resume cursor over the same journal.
	prog_w := fa_write(tmp, 'client-window.cx', "[?lib 'cx-fabric' :as fabric]
[?lib 'cx-stdlib/bytes' :as bytes]
[?let
  [= \$f [\$fabric:open \"xsp://127.0.0.1:${port}\" {tenant: \"acme\", did: \"${fa_client_did}\", seed: [\$bytes:from-hex \"${fa_client_seed_hex}\"]}]]
  [= \$r3 [\$fabric:publish \$f \"orders\" [do :order.archived] {}]]
  [= \$s  [\$fabric:observe \$f \"orders\" :order.* {window: 2, from: 1}]]
  [= \$b1 [\$fabric:receive \$s {max: 10, deadline: 3000}]]
  [= \$b2 [\$fabric:receive \$s {max: 10, deadline: 3000}]]
  [?element 'out3' [?attr 'n1' [\$concat '' [\$count \$b1]]]
                   [?attr 'n2' [\$concat '' [\$count \$b2]]]]]
")
	res_w := os.execute('${testenv.cx_bin()} --allow-net=127.0.0.1:${port} ${prog_w}')
	assert res_w.exit_code == 0, 'windowed-observe client failed: ${res_w.output}'
	assert res_w.output.contains("n1='2'"), 'windowed observe must push exactly the window: ${res_w.output}'
	assert res_w.output.contains("n2='1'"), 'auto-credit must release the held tail: ${res_w.output}'

	// anonymous open under a mutual-policy daemon: the refusal surfaces
	// through open, verbatim.
	prog3 := fa_write(tmp, 'client3.cx', "[?lib 'cx-fabric' :as fabric]
[\$fabric:open \"xsp://127.0.0.1:${port}\" {tenant: \"acme\"}]
")
	res3 := os.execute('${testenv.cx_bin()} --allow-net=127.0.0.1:${port} ${prog3}')
	assert res3.output.contains('ANONYMOUS-REFUSED'), 'anonymous remote open admitted: ${res3.output}'
}

// ── webhook adapter ──────────────────────────────────────────────────────────

// fa_callback_listener accepts push-callback POSTs, answers 200, and appends
// each body to `sink` — the V-side stand-in for a customer webhook endpoint.
fn fa_callback_listener(mut listener net.TcpListener, sink string) {
	for {
		mut conn := listener.accept() or { return }
		conn.set_read_timeout(3 * time.second)
		mut buf := []u8{}
		mut tmp := []u8{len: 8192}
		mut body_start := -1
		mut clen := 0
		for {
			n := conn.read(mut tmp) or { break }
			if n <= 0 {
				break
			}
			buf << tmp[..n]
			s := buf.bytestr()
			if body_start < 0 {
				if he := s.index('\r\n\r\n') {
					body_start = he + 4
					lower := s.to_lower()
					if ci := lower.index('content-length:') {
						rest := s[ci + 15..]
						clen = rest.all_before('\r').trim_space().int()
					}
				}
			}
			if body_start >= 0 && buf.len >= body_start + clen {
				break
			}
		}
		if body_start >= 0 {
			body := buf[body_start..].bytestr()
			mut f := os.open_append(sink) or { return }
			f.writeln(body.replace('\n', ' ')) or {}
			f.close()
		}
		conn.write_string('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok') or {}
		conn.close() or {}
	}
}

fn test_fabric_webhook_adapter() {
	port := fa_pick_port(1)
	hport := port + 1
	aport := port + 2
	cbport := port + 3
	tmp := os.join_path(os.temp_dir(), 'cx-fabric-p3-adapter-${os.getpid()}')
	os.rmdir_all(tmp) or {}
	os.mkdir_all(tmp) or { panic('mkdir: ${err}') }
	mut daemon := fa_boot_daemon(port, hport, tmp)
	defer {
		daemon.signal_kill()
		os.unsetenv('CX_FABRIC_SEED')
		os.rmdir_all(tmp) or {}
	}

	// the V-side push-callback endpoint.
	sink := os.join_path(tmp, 'callback-bodies.log')
	mut listener := net.listen_tcp(.ip, '127.0.0.1:${cbport}') or { panic('cb listen: ${err}') }
	spawn fa_callback_listener(mut listener, sink)

	acfg := fa_write(tmp, 'adapter.config.cx', '[webhook-adapter
  [fabric url="xsp://127.0.0.1:${port}" tenant="acme"
          did="${fa_client_did}" seed-env="CX_ADAPTER_SEED"
          responder="${fa_host_did}"]
  [http addr="127.0.0.1:${aport}" token-env="CX_ADAPTER_TOKEN"]
  [routes
    [webhook name="orders-in" path="/hooks/orders" stream="orders"]
    [sse path="/sse/orders" stream="orders" pattern=":order.*"]
    [push url="http://127.0.0.1:${cbport}/callback" stream="orders"
          group="push-1" pattern=":order.*"]]]')
	adapter_src := os.real_path(os.join_path(os.dir(@FILE), '..', '..', 'tooling', 'cxfabric',
		'webhook-adapter.cx'))
	os.setenv('CX_ADAPTER_SEED', fa_client_seed_hex, true)
	os.setenv('CX_ADAPTER_TOKEN', 'sekrit', true)
	mut adapter := os.new_process('/bin/sh')
	adapter.set_args(['-c',
		'exec "${testenv.cx_bin()}" --data="${acfg}" --allow-net=127.0.0.1:${port} --allow-net=127.0.0.1:${aport} --allow-net=127.0.0.1:${cbport} --allow-env "${adapter_src}" >"${tmp}/adapter.log" 2>&1'])
	adapter.run()
	defer {
		adapter.signal_kill()
		os.unsetenv('CX_ADAPTER_SEED')
		os.unsetenv('CX_ADAPTER_TOKEN')
	}
	// readiness: the bearer door answers (401 without a token proves the
	// listener + handler are live).
	mut up := false
	for _ in 0 .. 100 {
		time.sleep(100 * time.millisecond)
		r := http.get('http://127.0.0.1:${aport}/nope') or { continue }
		if r.status_code == 401 || r.status_code == 404 {
			up = true
			break
		}
	}
	if !up {
		out := os.read_file(os.join_path(tmp, 'adapter.log')) or { '' }
		panic('adapter never came up: ${out}')
	}

	auth := {
		'Authorization': 'Bearer sekrit'
		'Content-Type':  'application/cx'
	}

	// bearer door: no token → 401; token + unknown path → 404.
	r401 := fa_post(aport, '/hooks/orders', '[do :order.x]', {
		'Content-Type': 'application/cx'
	})
	assert r401.status == 401 && r401.body.contains('CXER0271'), 'no-bearer admitted: ${r401.status} ${r401.body}'
	r404 := fa_get(aport, '/nope', auth)
	assert r404.status == 404 && r404.body.contains('CXER4926'), 'unknown path: ${r404.status} ${r404.body}'

	// SSE client joins BEFORE the hooks so the live fan-out is observable.
	mut sse := net.dial_tcp('127.0.0.1:${aport}') or { panic('sse dial: ${err}') }
	sse.write_string('GET /sse/orders HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer sekrit\r\n\r\n') or {
		panic('sse write: ${err}')
	}
	sse_prelude := fa_read_until(mut sse, 'data: ready', 5)
	assert sse_prelude.contains('200'), 'sse prelude: ${sse_prelude}'

	// webhook-in: the CX payload publishes VERBATIM (atom topic + nested
	// element intact); JSON converts to its map element.
	rc := fa_post(aport, '/hooks/orders', '[do :order.placed [item sku="X1"]]', auth)
	assert rc.status == 200 && rc.body.contains('seq=1'), 'cx hook: ${rc.status} ${rc.body}'
	rj := fa_post(aport, '/hooks/orders', '{"n": 7}', {
		'Authorization': 'Bearer sekrit'
		'Content-Type':  'application/json'
	})
	assert rj.status == 200 && rj.body.contains('seq=2'), 'json hook: ${rj.status} ${rj.body}'
	rb := fa_post(aport, '/hooks/orders', '[broken', auth)
	assert rb.status == 400, 'bad body admitted: ${rb.status} ${rb.body}'

	// SSE fan-out: entry 1 (matching :order.*) arrives lossless; the JSON
	// map event (seq 2) does NOT match the atom pattern — filtered.
	sse_feed := fa_read_until(mut sse, ':order.placed', 8)
	assert sse_feed.contains('seq=1') && sse_feed.contains('sku=X1'), 'sse entry lossless: ${sse_feed}'
	sse.close() or {}

	// webhook push: the callback received a [batch …] with the matching
	// entry, answered 200, and the adapter acked — at-least-once delivered.
	mut cb := ''
	for _ in 0 .. 50 {
		time.sleep(200 * time.millisecond)
		cb = os.read_file(sink) or { '' }
		if cb.contains('seq=1') {
			break
		}
	}
	assert cb.contains('[batch') && cb.contains(':order.placed'), 'push callback body: ${cb}'
}

// ── HTTP glue ────────────────────────────────────────────────────────────────

struct FaResp {
	status int
	body   string
}

fn fa_get(port int, path string, hdrs map[string]string) FaResp {
	mut cfg := http.FetchConfig{
		url:    'http://127.0.0.1:${port}${path}'
		method: .get
	}
	cfg.header = http.new_custom_header_from_map(hdrs) or { panic('hdrs: ${err}') }
	resp := http.fetch(cfg) or { return FaResp{0, 'GET-FAILED: ${err}'} }
	return FaResp{resp.status_code, resp.body}
}

fn fa_post(port int, path string, body string, hdrs map[string]string) FaResp {
	mut cfg := http.FetchConfig{
		url:    'http://127.0.0.1:${port}${path}'
		method: .post
		data:   body
	}
	cfg.header = http.new_custom_header_from_map(hdrs) or { panic('hdrs: ${err}') }
	resp := http.fetch(cfg) or { return FaResp{0, 'POST-FAILED: ${err}'} }
	return FaResp{resp.status_code, resp.body}
}

// fa_read_until reads off a raw socket until `needle` appears (or the
// deadline lapses) and returns everything read so far.
fn fa_read_until(mut conn net.TcpConn, needle string, seconds int) string {
	conn.set_read_timeout(1 * time.second)
	mut buf := []u8{}
	deadline := time.now().add(seconds * time.second)
	for time.now() < deadline {
		mut tmp := []u8{len: 4096}
		n := conn.read(mut tmp) or {
			if buf.bytestr().contains(needle) {
				break
			}
			continue
		}
		if n > 0 {
			buf << tmp[..n]
			if buf.bytestr().contains(needle) {
				break
			}
		}
	}
	return buf.bytestr()
}
