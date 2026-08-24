// sse_xsp_downstream_test.v — BEHAVIORAL gate for the SSE-1 negotiated
// XSP-envelope downstream (xsp.md §4.1 amendment; owner "1b" 2026-08-20,
// ledger/rulings_2026_08_20_sse_downstream.md).
//
// The v1 web binding's SSE downstream carries base64-encoded XSP `event`
// frames — negotiated PER SUBSCRIPTION, mirroring the upstream's
// `[envelope codec="xsp"]` opt-in. The envelope changes CARRIAGE only:
// the framed payload is byte-for-byte the CX event text the plain lane
// delivers, and non-opt-in subscribers keep today's plain frames
// byte-identically (zero movement on the plain lane).
//
// What this proves over real loopback sockets:
//   1. Generic `[$http:serve]` topic layer: a plain and an XSP-envelope
//      subscriber COEXIST ON ONE TOPIC; the publish reports both; the
//      plain lane's bytes are the pre-SSE-1 frames verbatim; the XSP
//      lane's data: is one base64 line whose decoded bytes are a valid
//      XSP event frame (version 1, type event, binary=false, anonymous)
//      whose payload BYTE-COMPARES against the plain lane's data payload.
//   2. The decoded frame round-trips through the ONE shipped codec:
//      `[$xsp:decode [$bytes:from-base64 …]]` yields the same event text.
//   3. An unknown envelope codec refuses the promotion loudly (500) —
//      never a silent plain fallback.
//   4. The `[$xap:serve]` §24 feed: GET /events (plain, pinned) and
//      GET /events?envelope=xsp receive the SAME committed surface —
//      the initial frame and the post-intent push both byte-compare
//      after decode; ?envelope=<unknown> refuses 400.

module main

import encoding.base64
import net
import os
import testenv
import time

// Disjoint PID + nanosecond-salted band (29400-29499) from the sibling SSE
// suites (28900 http_umbrella, 28600 h2, 26800 xap-host, 24000 xap-render).
fn sxd_port(slot int) int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 40
	return 29400 + slot * 45 + int(salt)
}

// sxd_decode_event_frame validates one base64 SSE-1 data payload against the
// xsp.md §2 wire layout INDEPENDENTLY of the shipped codec (a differential
// check: version 1, type 2 = event, stream 0, flags 0 = binary=false + no
// eos, anonymous principal) and returns the frame's payload text.
fn sxd_decode_event_frame(b64 string) ?string {
	buf := base64.decode(b64)
	if buf.len < 17 {
		return none
	}
	if buf[0] != 1 || buf[1] != 2 {
		return none
	}
	for i in 2 .. 10 {
		if buf[i] != 0 {
			return none
		}
	}
	if buf[10] != 0 {
		return none
	}
	plen := (int(buf[11]) << 8) | int(buf[12])
	if plen != 0 {
		return none
	}
	paylen := (u32(buf[13]) << 24) | (u32(buf[14]) << 16) | (u32(buf[15]) << 8) | u32(buf[16])
	if buf.len != 17 + int(paylen) {
		return none
	}
	return buf[17..].bytestr()
}

// sxd_frames splits an SSE capture into frames (blank-line separated) and
// returns, per frame, the LF-rejoined data payload — exactly what the SSE
// client reassembles. Comment-only frames (`: hb`) yield no entry.
fn sxd_frames(capture string) []string {
	mut out := []string{}
	for block in capture.split('\n\n') {
		mut datas := []string{}
		for line in block.split('\n') {
			if line.starts_with('data: ') {
				datas << line[6..]
			}
		}
		if datas.len > 0 {
			out << datas.join('\n')
		}
	}
	return out
}

// ── lane 1: the generic topic layer (one topic, two carriages) ───────────────

fn sxd_server_prog(port int) string {
	return "[?lib 'cx-stdlib/http' :as http]\n" +
		'[?def h impure (\$req)\n' +
		'  [?let [= \$p [\$text \$req@path]]\n' +
		'    [?if [= \$p "/events"]\n' +
		'      [then [sse-subscribe topic="prices" [event data="hello"]]]\n' +
		'      [else [?if [= \$p "/events-xsp"]\n' +
		'        [then [sse-subscribe topic="prices" [envelope codec="xsp"] [event data="hello"]]]\n' +
		'        [else [?if [= \$p "/events-bad"]\n' +
		'          [then [sse-subscribe topic="prices" [envelope codec="cbor"]]]\n' +
		'          [else [?if [= \$p "/push"]\n' +
		'            [then [?let [= \$n [\$http:sse-publish "prices" [event data="tick-42"]]]\n' +
		'                    [response status=200 [body [\$concat "pushed=" [\$text \$n]]]]]]\n' +
		'            [else [response status=200 [body "pong"]]]]]]]]]]]]\n' +
		'[\$http:serve "tcp://127.0.0.1:${port}" \$h {block: true}]\n'
}

fn sxd_open_sse(port int, path string) ?&net.TcpConn {
	mut c := net.dial_tcp('127.0.0.1:${port}') or { return none }
	c.write_string('GET ${path} HTTP/1.1\r\nHost: x\r\n\r\n') or { return none }
	c.set_read_timeout(4 * time.second)
	return c
}

fn sxd_read_until(mut c net.TcpConn, target string) string {
	mut raw := []u8{}
	mut buf := []u8{len: 4096}
	for {
		n := c.read(mut buf) or { break }
		if n <= 0 {
			break
		}
		raw << buf[..n]
		if raw.bytestr().contains(target) || raw.len > 65536 {
			break
		}
	}
	return raw.bytestr()
}

fn sxd_get(port int, path string) string {
	mut c := net.dial_tcp('127.0.0.1:${port}') or { return '' }
	defer { c.close() or {} }
	c.write_string('GET ${path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n') or { return '' }
	c.set_read_timeout(4 * time.second)
	mut raw := []u8{}
	mut buf := []u8{len: 4096}
	for {
		n := c.read(mut buf) or { break }
		if n <= 0 {
			break
		}
		raw << buf[..n]
		if raw.len > 65536 {
			break
		}
	}
	return raw.bytestr()
}

fn sxd_wait_up(port int) bool {
	for _ in 0 .. 50 {
		mut c := net.dial_tcp('127.0.0.1:${port}') or {
			time.sleep(100 * time.millisecond)
			continue
		}
		c.close() or {}
		return true
	}
	return false
}

fn test_topic_layer_negotiated_xsp_carriage() {
	port := sxd_port(0)
	prog := os.join_path(os.temp_dir(), 'cx_sse_xsp_${os.getpid()}.cx')
	os.write_file(prog, sxd_server_prog(port)) or { panic('write: ${err}') }
	defer { os.rm(prog) or {} }
	out_file := os.join_path(os.temp_dir(), 'cx_sse_xsp_${port}.out')
	pid_s := os.execute('${testenv.cx_bin()} --allow-net ${prog} >${out_file} 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		assert false, 'could not spawn cx sse server'
		return
	}
	pid := pid_s.output.trim_space()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
		os.rm(out_file) or {}
	}
	assert sxd_wait_up(port), 'server never came up on ${port}'

	// (3) unknown codec refuses the promotion loudly — never a held plain feed.
	bad := sxd_get(port, '/events-bad')
	assert bad.starts_with('HTTP/1.1 500'), 'unknown envelope codec must refuse (500): ${bad}'
	assert bad.contains('unknown codec "cbor"'), 'refusal must name the codec: ${bad}'

	// one topic, two carriages: subscribe plain + xsp (initial frame = the ack).
	mut plain := sxd_open_sse(port, '/events') or {
		assert false, 'plain subscribe failed'
		return
	}
	mut xspc := sxd_open_sse(port, '/events-xsp') or {
		assert false, 'xsp subscribe failed'
		return
	}
	defer {
		plain.close() or {}
		xspc.close() or {}
	}
	init_plain := sxd_read_until(mut plain, '\n\n')
	assert init_plain.contains('data: hello\n\n'), 'plain lane initial frame moved (must be byte-identical to pre-SSE-1): ${init_plain}'
	init_xsp := sxd_read_until(mut xspc, '\n\n')
	ifr := sxd_frames(init_xsp.all_after('\r\n\r\n'))
	assert ifr.len == 1, 'xsp initial frame missing: ${init_xsp}'
	ipay := sxd_decode_event_frame(ifr[0]) or {
		assert false, 'xsp initial data is not a valid base64 XSP event frame: ${ifr[0]}'
		return
	}
	assert ipay == 'hello', 'xsp initial payload != plain event text: ${ipay}'

	// (1) publish reaches BOTH lanes of the one topic; the count says so.
	push := sxd_get(port, '/push')
	assert push.contains('pushed=2'), 'publish must reach the plain AND xsp subscriber of one topic: ${push}'

	got_plain := sxd_read_until(mut plain, 'tick-42')
	assert got_plain.contains('data: tick-42\n\n'), 'plain lane pushed frame moved: ${got_plain}'
	got_xsp := sxd_read_until(mut xspc, '\n\n')
	xfr := sxd_frames(got_xsp)
	assert xfr.len >= 1, 'xsp pushed frame missing: ${got_xsp}'
	xpay := sxd_decode_event_frame(xfr[xfr.len - 1]) or {
		assert false, 'xsp pushed data is not a valid base64 XSP event frame: ${xfr[xfr.len - 1]}'
		return
	}
	// the byte-compare: decoded frame payload == the plain lane's data payload.
	assert xpay == 'tick-42', 'decoded XSP payload must byte-equal the plain lane event: "${xpay}"'

	// (2) the SAME bytes round-trip through the ONE shipped codec.
	rt_prog := os.join_path(os.temp_dir(), 'cx_sse_xsp_rt_${os.getpid()}.cx')
	os.write_file(rt_prog, "[?lib 'cx-stdlib/xsp' :as xsp]\n[?lib 'cx-stdlib/bytes' :as bytes]\n" +
		'[?let [= \$f [\$xsp:decode [\$bytes:from-base64 "${xfr[xfr.len - 1]}"]]]\n' +
		'  [\$concat [\$text \$f@type] "|" [\$text \$f@binary] "|" [\$first \$f/payload]]]\n') or {
		panic('write: ${err}')
	}
	defer { os.rm(rt_prog) or {} }
	rt := os.execute('${testenv.cx_bin()} ${rt_prog}')
	assert rt.exit_code == 0, 'codec round-trip run failed: ${rt.output}'
	assert rt.output.contains('event|false|tick-42'), 'shipped codec disagrees with the wire: ${rt.output}'
}

// ── lane 2: the [$xap:serve] §24 feed (?envelope=xsp) ────────────────────────

fn test_xap_events_feed_negotiated_xsp_carriage() {
	if os.execute('which curl').exit_code != 0 {
		eprintln('SKIP: curl not available')
		return
	}
	port := sxd_port(1)
	dir := os.temp_dir()
	srv := os.join_path(dir, 'cx_xap_sse_xsp_server_${os.getpid()}.cx')
	os.write_file(srv, '[?lib \'cx-xap\' :as xap]\n' +
		'[\$xap:component guestbook\n' +
		'  {bind: "/guestbook"\n' +
		'   emits: ([do :sign [name :string]])\n' +
		'   view: [?fn (\$gs)\n' +
		'           [panel [list [?for [in \$g \$gs] [yield [item \$g/name]]]]\n' +
		'                  [control :sign [label "Sign"] [input :name]]]]\n' +
		'   working-panel: :none}]\n' +
		'[?let [= \$rt [\$xap:run {tenant: "demo" components: (guestbook)}]]\n' +
		'  [\$xap:serve "http://127.0.0.1:${port}" {runtime: \$rt}]]\n') or { panic(err) }
	defer { os.rm(srv) or {} }
	out_file := os.join_path(dir, 'cx_xap_sse_xsp_${port}.out')
	pid_s := os.execute('${testenv.cx_bin()} --allow-net ${srv} >${out_file} 2>&1 & echo \$!')
	pid := pid_s.output.trim_space()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
		os.rm(out_file) or {}
	}
	mut up := false
	for _ in 0 .. 50 {
		s := sxd_get(port, '/surface')
		if s.starts_with('HTTP/1.1 200') {
			up = true
			break
		}
		time.sleep(100 * time.millisecond)
	}
	assert up, 'xap serve never bound on ${port}'

	// unknown envelope value refuses (400) — never a silently plain feed.
	bad := sxd_get(port, '/events?envelope=cbor')
	assert bad.starts_with('HTTP/1.1 400'), 'unknown feed envelope must refuse (400): ${bad}'

	// hold BOTH carriages open, then commit one intent mid-stream.
	plain_cap := os.join_path(dir, 'cx_xap_sse_xsp_${port}.plain.cap')
	xsp_cap := os.join_path(dir, 'cx_xap_sse_xsp_${port}.xsp.cap')
	os.rm(plain_cap) or {}
	os.rm(xsp_cap) or {}
	os.execute('curl -sN --max-time 3 http://127.0.0.1:${port}/events >${plain_cap} 2>&1 & echo \$!')
	os.execute('curl -sN --max-time 3 "http://127.0.0.1:${port}/events?envelope=xsp" >${xsp_cap} 2>&1 & echo \$!')
	defer {
		os.rm(plain_cap) or {}
		os.rm(xsp_cap) or {}
	}
	time.sleep(700 * time.millisecond) // both connected + initial frames written
	sign := os.execute('curl -s -X POST http://127.0.0.1:${port}/intent/sign -d "name=Vera"')
	assert sign.exit_code == 0, 'sign POST failed'
	time.sleep(2600 * time.millisecond) // pushes land, then curl --max-time fires

	pcap := os.read_file(plain_cap) or { '' }
	xcap := os.read_file(xsp_cap) or { '' }
	// plain lane: untouched §24 shapes (the existing fixture's pin).
	pframes := sxd_frames(pcap)
	assert pframes.len >= 2, 'plain feed missing initial+push frames: ${pcap}'
	assert pframes[0].contains('[surface'), 'plain initial frame not a [surface …]: ${pframes[0]}'
	assert pframes[pframes.len - 1].contains("[item 'Vera']"), 'plain push missing the commit: ${pcap}'
	// xsp lane: same events, negotiated carriage — byte-compare after decode.
	xframes := sxd_frames(xcap)
	assert xframes.len >= 2, 'xsp feed missing initial+push frames: ${xcap}'
	xinit := sxd_decode_event_frame(xframes[0]) or {
		assert false, 'xsp initial data not a valid XSP event frame: ${xframes[0]}'
		return
	}
	assert xinit == pframes[0], 'initial surface must byte-compare across carriages:\n--- plain ---\n${pframes[0]}\n--- decoded xsp ---\n${xinit}'
	xpush := sxd_decode_event_frame(xframes[xframes.len - 1]) or {
		assert false, 'xsp push data not a valid XSP event frame: ${xframes[xframes.len - 1]}'
		return
	}
	assert xpush == pframes[pframes.len - 1], 'pushed surface must byte-compare across carriages:\n--- plain ---\n${pframes[pframes.len - 1]}\n--- decoded xsp ---\n${xpush}'
}
