module main

import os
import testenv
import time
import net
import net.http
import encoding.base64

// fabric_serve_test.v — BEHAVIORAL proof of the cx-fabric SERVED tier
// (spec/03-approved/xap/fabric.md §13/§19.2/§19.3/§19.6; issue #531 P1), following
// the xap_host_auth_test.v pattern: the REAL `cx fabric-serve` daemon boots as
// a subprocess over an attr-exact config, and every client-side handshake
// runs through the real cx binary's $xsp:auth-* calculus (RFC 7748/8032
// fixture vectors) — the server generates its nonce/ephemeral fresh, so every
// lane exercises a live handshake, not a recording.
//
// The wire is raw XSP frames over TCP: the attach phase (M1–M4) rides binary
// (data-bin) stream-0 frames exactly as the shipped calculus emits them;
// verbs, replies, pushes, and refusals ride TEXT frames carrying canonical CX
// (lossless for event trees), so this test parses/builds them directly.
//
// Lanes (boot 1 — mutual policy, pending-window=4):
//   health/ready endpoints                    → 200, [accepting true]
//   verb before attach                        → CXER4928 fail-closed
//   mutual attach (M1→M2, M3→M4)              → established
//   publish                                   → [receipt seq=1], actor = the
//                                               proven session DID (never a
//                                               claimed attribution field)
//   subscribe group + pattern                 → push delivery of the LOSSLESS
//                                               [entry …] (atom topic intact)
//   cumulative ack                            → null
//   pending window (4)                        → exactly 4 unacked frames
//                                               pushed; ack frees the tail
//                                               from the journal (log-is-the-
//                                               buffer catch-up)
//   frame principal ≠ session principal       → CXER-XSP-AUTH-PRINCIPAL-MISMATCH
//   anonymous M3 under require-mutual         → CXER-XSP-AUTH-ANONYMOUS-REFUSED
//   observe-only principal: publish / grouped → CXER4925 deny-by-default;
//   subscribe refused, observe replay admitted
//   transient plane: emit → fan-out push + latest-wins read; emit denied
//   without a publish grant
// Lanes (boot 2 — floor policy, liveness-ms=1500):
//   anonymous attach → floor principal        → observe ok, publish denied
//   sticky-exclusive group: standby gets      → assigned=false, no delivery
//   failover on death                         → successor redelivers exactly
//                                               the uncommitted tail from the
//                                               committed offset
//   liveness-window failover                  → a silent holder loses the
//                                               stream to a live sibling

const fb_host_did = 'did:key:z6MkiaMbhXHNA4eJVCCj8dbzKzTgYDKf6crKgHVHid1F1WCT' // RFC 8032 TEST 2
const fb_host_seed_hex = '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'
const fb_client_did = 'did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw' // RFC 8032 TEST 1
const fb_client_seed_hex = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
const fb_rogue_did = 'did:key:z6MkwSD8dBdqcXQzKJZQFPy2hh2izzxskndKCjdmC2dBpfME' // RFC 8032 TEST 3
const fb_rogue_seed_hex = 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7'
const fb_eph_priv_hex = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a' // RFC 7748 alice
const fb_eph_pub_hex = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'

// Disjoint port band (27100-27299) from http (26400) / xap-host (26800) /
// xap-host-auth (26900).
fn fb_pick_port(lane int) int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 40
	return 27100 + lane * 50 + int(salt)
}

fn fb_write(dir string, name string, content string) string {
	p := os.join_path(dir, name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

fn fb_run_cx(args string, prog string) string {
	res := os.execute('${testenv.cx_bin()} ${args} ${prog}')
	if res.exit_code != 0 {
		panic('cx helper failed (${res.exit_code}): ${res.output}')
	}
	return res.output.trim_space().trim("'")
}

// ── client-side calculus (the same $xsp:auth-* surface the web client uses) ─

const fb_vec_prelude = "[?lib 'cx-stdlib/xsp' :as xsp]\n[?lib 'cx-stdlib/bytes' :as bytes]\n" +
	"[?lib 'cx-stdlib/io' :as io]\n[?lib 'cx-stdlib/strings' :as str]\n"

// prints base64(frame(M1)); did='' → anonymous hello.
fn fb_m1_prog(endpoint string, did string, nonce_hex string) string {
	did_field := if did == '' { '' } else { 'did: "${did}", ' }
	return fb_vec_prelude +
		'[?let [= \$m1 [\$xsp:auth-hello {${did_field}nonce: [\$bytes:from-hex "${nonce_hex}"], eph: [\$bytes:from-hex "${fb_eph_pub_hex}"], endpoint: "${endpoint}"}]]\n' +
		'[\$bytes:to-base64 [\$xsp:encode [frame type=request stream=0 [payload \$m1]]]]]\n'
}

// reads base64(frame(M2)) from m2_path; prints base64(frame(M3)).
// seed_hex='' → anonymous prove (no sig).
fn fb_m3_prog(m2_path string, endpoint string, did string, seed_hex string, nonce_hex string, tenant string) string {
	did_field := if did == '' { '' } else { 'did: "${did}", ' }
	key_field := if seed_hex == '' { '' } else { 'key: [\$bytes:from-hex "${seed_hex}"], ' }
	return fb_vec_prelude + '[?let\n' +
		'  [= \$m1 [\$xsp:auth-hello {${did_field}nonce: [\$bytes:from-hex "${nonce_hex}"], eph: [\$bytes:from-hex "${fb_eph_pub_hex}"], endpoint: "${endpoint}"}]]\n' +
		'  [= \$d2 [\$xsp:decode [\$bytes:from-base64 [\$str:trim [\$io:read-file "${m2_path}"]]]]]\n' +
		'  [= \$m2 \$d2/payload]\n' +
		'  [= \$m3 [\$xsp:auth-prove \$m1 \$m2 {eph-priv: [\$bytes:from-hex "${fb_eph_priv_hex}"], ${key_field}attach: [attach [tenant "${tenant}"] [session mirror]]}]]\n' +
		'  [\$bytes:to-base64 [\$xsp:encode [frame type=request stream=0 [payload \$m3]]]]]\n'
}

// ── frame codec (V side — the wire layout is xsp.md §2, 17+P+L) ─────────────

struct FbFrame {
	ftype   u8 // 1 request 2 event 3 reply 4 cancel 5 ping 6 pong 7 error
	stream  u64
	flags   u8
	payload []u8
	raw     []u8
}

// fb_frame_req builds a TEXT request frame (flags=0) carrying canonical CX.
fn fb_frame_req(stream u64, text string, principal string) []u8 {
	return fb_frame_text(1, stream, text, principal)
}

// fb_frame_text builds a TEXT frame of any type (the §12.1 responder answers
// with reply/error frames — the only frames a client sends besides
// request/ping).
fn fb_frame_text(ftype u8, stream u64, text string, principal string) []u8 {
	pr := principal.bytes()
	pl := text.bytes()
	mut buf := []u8{cap: 17 + pr.len + pl.len}
	buf << u8(0x01) // version
	buf << ftype
	for i := 7; i >= 0; i-- {
		buf << u8(stream >> (u64(i) * 8))
	}
	buf << u8(0) // flags: text payload
	buf << u8(pr.len >> 8)
	buf << u8(pr.len)
	buf << pr
	buf << u8(pl.len >> 24)
	buf << u8(pl.len >> 16)
	buf << u8(pl.len >> 8)
	buf << u8(pl.len)
	buf << pl
	return buf
}

fn fb_frame_ping() []u8 {
	mut buf := []u8{}
	buf << u8(0x01)
	buf << u8(5) // ping
	for _ in 0 .. 8 {
		buf << u8(0)
	}
	buf << u8(0)
	buf << u8(0)
	buf << u8(0)
	// zero-length payload
	for _ in 0 .. 4 {
		buf << u8(0)
	}
	return buf
}

// FbChan is one client connection plus its CARRY buffer: pushed frames
// arrive back-to-back in a single TCP segment, so bytes past the first
// frame must persist across fb_read_frame calls, never be discarded.
struct FbChan {
mut:
	conn  &net.TcpConn = unsafe { nil }
	carry []u8
}

fn (mut ch FbChan) close() {
	ch.conn.close() or {}
}

// fb_read_frame reads ONE frame off the channel within `deadline`, or none;
// surplus bytes stay in the carry buffer for the next call.
fn fb_read_frame(mut ch FbChan, deadline time.Duration) ?FbFrame {
	ch.conn.set_read_timeout(deadline)
	mut buf := ch.carry.clone()
	mut need := 13
	for {
		for buf.len >= need {
			plen := int(u16(buf[11]) << 8 | u16(buf[12]))
			if need == 13 {
				need = 17 + plen
				continue
			}
			mut paylen := 0
			if buf.len >= 13 + plen + 4 {
				mut pl32 := u32(0)
				for i in 13 + plen .. 13 + plen + 4 {
					pl32 = (pl32 << 8) | u32(buf[i])
				}
				paylen = int(pl32)
				total := 17 + plen + paylen
				if buf.len >= total {
					mut stream := u64(0)
					for i in 2 .. 10 {
						stream = (stream << 8) | u64(buf[i])
					}
					ch.carry = buf[total..].clone()
					return FbFrame{
						ftype:   buf[1]
						stream:  stream
						flags:   buf[10]
						payload: buf[13 + plen + 4..total].clone()
						raw:     buf[..total].clone()
					}
				}
				need = total
			} else {
				need = 13 + plen + 4
			}
			break
		}
		mut tmp := []u8{len: 4096}
		n := ch.conn.read(mut tmp) or {
			ch.carry = buf
			return none
		}
		if n <= 0 {
			ch.carry = buf
			return none
		}
		buf << tmp[..n]
	}
	return none
}

fn fb_send(mut ch FbChan, frame []u8) {
	ch.conn.write(frame) or { panic('frame write: ${err}') }
}

fn fb_send_b64(mut ch FbChan, b64 string) {
	fb_send(mut ch, base64.decode(b64))
}

// fb_request sends one text verb request and returns the reply/error frame.
fn fb_request(mut ch FbChan, stream u64, text string) FbFrame {
	fb_send(mut ch, fb_frame_req(stream, text, ''))
	return fb_read_frame(mut ch, 5 * time.second) or {
		panic('no reply to request on stream ${stream}: ${text}')
	}
}

// ── attach choreography ──────────────────────────────────────────────────────

// fb_attach dials + runs M1→M2→M3→M4 on the new connection; returns the
// channel and the M4-position frame (reply on success, error on refusal).
fn fb_attach(port int, tmp string, tag string, did string, seed_hex string, nonce_hex string, tenant string) (&FbChan, FbFrame) {
	endpoint := 'tcp://127.0.0.1:${port}'
	conn := net.dial_tcp('127.0.0.1:${port}') or { panic('dial ${port}: ${err}') }
	mut ch := &FbChan{
		conn: conn
	}
	m1_prog := fb_write(tmp, 'm1-${tag}.cx', fb_m1_prog(endpoint, did, nonce_hex))
	fb_send_b64(mut ch, fb_run_cx('', m1_prog))
	m2 := fb_read_frame(mut ch, 5 * time.second) or { panic('no M2 (${tag})') }
	assert m2.ftype == 3, 'M2 is not a reply frame (${tag}): type ${m2.ftype} ${m2.raw.bytestr()}'
	m2_path := fb_write(tmp, 'm2-${tag}.b64', base64.encode(m2.raw))
	m3_prog := fb_write(tmp, 'm3-${tag}.cx', fb_m3_prog(m2_path, endpoint, did, seed_hex,
		nonce_hex, tenant))
	fb_send_b64(mut ch, fb_run_cx('--allow-read', m3_prog))
	m4 := fb_read_frame(mut ch, 5 * time.second) or { panic('no M4 (${tag})') }
	return ch, m4
}

// ── daemon boot ──────────────────────────────────────────────────────────────

fn fb_boot(lane int, policy string, principals string) (int, int, string, &os.Process) {
	cxbin := testenv.cx_bin()
	port := fb_pick_port(lane)
	hport := port + 1
	tmp := os.join_path(os.temp_dir(), 'cx-fabric-serve-test-${os.getpid()}-${lane}')
	os.rmdir_all(tmp) or {}
	os.mkdir_all(tmp) or { panic('mkdir ${tmp}: ${err}') }
	cfg := '[fabric-service
  [bind addr="127.0.0.1:${port}"]
  [health addr="127.0.0.1:${hport}"]
  [identity did="${fb_host_did}" seed-env="CX_FABRIC_SEED"]
  ${policy}
  [limits pending-window=4 liveness-ms=1500 request-timeout-ms=1500]
  [fabrics [fabric name="main" store="file://${tmp}/store" tenant="acme"]]
  ${principals}]'
	cfg_path := fb_write(tmp, 'fabric.service.cx', cfg)
	os.setenv('CX_FABRIC_SEED', fb_host_seed_hex, true)
	// The daemon's stdOUT/stdERR go to a FILE (the shell redirect replaces the
	// pipes before exec): a subscriber daemon outlives any pipe-drain loop this
	// test could run, and an un-drained pipe would eventually block its writes.
	// stdIN stays a PIPE held by this test process + --exit-on-stdin-eof (#648):
	// if the test dies without running its defers (a V panic skips them), the
	// pipe closes and the daemon drains itself instead of orphaning — squatting
	// the port band, poisoning retries, and wedging make via inherited FDs.
	mut proc := os.new_process('/bin/sh')
	proc.set_args(['-c',
		'exec "${cxbin}" fabric-serve --config "${cfg_path}" --exit-on-stdin-eof --allow-read --allow-write --allow-net=127.0.0.1:${port} --allow-net=127.0.0.1:${hport} --allow-env >"${tmp}/daemon.log" 2>&1'])
	proc.set_redirect_stdio()
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
	return port, hport, tmp, proc
}

const fb_principals_full = '[principals
    [principal did="${fb_client_did}"
      [grant action="publish" scope="*"]
      [grant action="consume" scope="*"]
      [grant action="observe" scope="*"]]
    [principal did="${fb_rogue_did}"
      [grant action="observe" scope="*"]]]'

// fb_boot_on_store is fb_boot with the journal mounted on an arbitrary store
// URL (#644: fabric.md §13 — a deployment MAY point fabric-serve at a served
// store) and the extra net grants the store connection needs.
fn fb_boot_on_store(lane int, policy string, principals string, store_url string, extra_net string) (int, int, string, &os.Process) {
	cxbin := testenv.cx_bin()
	port := fb_pick_port(lane)
	hport := port + 1
	tmp := os.join_path(os.temp_dir(), 'cx-fabric-serve-test-${os.getpid()}-${lane}')
	os.rmdir_all(tmp) or {}
	os.mkdir_all(tmp) or { panic('mkdir ${tmp}: ${err}') }
	cfg := '[fabric-service
  [bind addr="127.0.0.1:${port}"]
  [health addr="127.0.0.1:${hport}"]
  [identity did="${fb_host_did}" seed-env="CX_FABRIC_SEED"]
  ${policy}
  [limits pending-window=4 liveness-ms=1500 request-timeout-ms=1500]
  [fabrics [fabric name="main" store="${store_url}" tenant="acme"]]
  ${principals}]'
	cfg_path := fb_write(tmp, 'fabric.service.cx', cfg)
	os.setenv('CX_FABRIC_SEED', fb_host_seed_hex, true)
	mut proc := os.new_process('/bin/sh')
	proc.set_args(['-c',
		'exec "${cxbin}" fabric-serve --config "${cfg_path}" --exit-on-stdin-eof --allow-read --allow-write --allow-net=127.0.0.1:${port} --allow-net=127.0.0.1:${hport} --allow-net=${extra_net} --allow-env >"${tmp}/daemon.log" 2>&1'])
	proc.set_redirect_stdio() // stdin pipe = the #648 tether (see fb_boot)
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
		panic('fabric-serve (on ${store_url}) never came up: ${out}')
	}
	return port, hport, tmp, proc
}

// #644: the fabric journal rides a cx-store:// mount — the full §13
// self-hosting shape over real sockets: store-serve holds the journal store,
// fabric-serve mounts it over CSRP, a client publishes durably and a
// subscriber receives. Also pins the boot banner's token redaction: the
// mount URL carries a bearer token that must never reach the log.
fn test_fabric_serve_journal_on_csrp_store() {
	cxbin := testenv.cx_bin()
	sport := fb_pick_port(7) + 40 // disjoint from the fabric lanes
	stmp := os.join_path(os.temp_dir(), 'cx-fabric-csrp-store-${os.getpid()}')
	os.rmdir_all(stmp) or {}
	os.mkdir_all(stmp) or { panic('mkdir ${stmp}: ${err}') }
	scfg := fb_write(stmp, 'store.service.cx', '[cxstore-service
  [bind addr="127.0.0.1:${sport}"]
  [stores [store name="journal" url="mem://fabric-644"]]]')
	mut sproc := os.new_process('/bin/sh')
	sproc.set_args(['-c',
		'exec "${cxbin}" store-serve --config "${scfg}" --exit-on-stdin-eof --allow-net=127.0.0.1:${sport} >"${stmp}/store.log" 2>&1'])
	sproc.set_redirect_stdio() // stdin pipe = the #648 tether (see fb_boot)
	sproc.run()
	defer {
		sproc.signal_kill()
		os.rmdir_all(stmp) or {}
	}
	mut sup := false
	for _ in 0 .. 100 {
		time.sleep(100 * time.millisecond)
		r := http.get('http://127.0.0.1:${sport}/cx-store/v1/health') or { continue }
		if r.status_code == 200 {
			sup = true
			break
		}
	}
	assert sup, 'store-serve never came up: ${os.read_file(os.join_path(stmp, 'store.log')) or { '' }}'

	// the mount URL carries a (fake) bearer token — the banner must redact it.
	store_url := 'cx-store+http://sekrit-token-644@127.0.0.1:${sport}/journal/'
	port, _, tmp, mut proc := fb_boot_on_store(7, '[policy mode="mutual"]', fb_principals_full,
		store_url, '127.0.0.1:${sport}')
	defer {
		proc.signal_kill()
		os.unsetenv('CX_FABRIC_SEED')
		os.rmdir_all(tmp) or {}
	}

	dlog := os.read_file(os.join_path(tmp, 'daemon.log')) or { '' }
	assert !dlog.contains('sekrit-token-644'), 'boot banner leaked the bearer token: ${dlog}'
	assert dlog.contains('***@127.0.0.1:${sport}'), 'banner must show the redacted mount: ${dlog}'

	// durable publish lands at seq 1/2 (the #644 repro shape), and the entries
	// live in the SERVED store — visible in its request log as object-wire ops.
	mut pubc, pm4 := fb_attach(port, tmp, 'csrp-pub', fb_client_did, fb_client_seed_hex,
		'0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'acme')
	assert pm4.ftype == 3, 'publisher attach: ${pm4.raw.bytestr()}'
	p1 := fb_request(mut pubc, 30, '[publish stream="jobs" [event [do :job.a]]]')
	assert p1.ftype == 3 && p1.payload.bytestr().contains('seq=1'), 'publish 1 on a CSRP-mounted journal: ${p1.payload.bytestr()}'
	p2 := fb_request(mut pubc, 31, '[publish stream="jobs" [event [do :job.b]]]')
	assert p2.payload.bytestr().contains('seq=2'), 'publish 2: ${p2.payload.bytestr()}'

	// a consumer receives both from the CSRP-backed journal.
	mut cc, cm4 := fb_attach(port, tmp, 'csrp-con', fb_client_did, fb_client_seed_hex,
		'0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c', 'acme')
	assert cm4.ftype == 3
	csub := fb_request(mut cc, 32, '[subscribe stream="jobs" group="g6" [pattern :job.*]]')
	assert csub.payload.bytestr().contains('assigned=true'), 'subscribe: ${csub.payload.bytestr()}'
	e1 := fb_read_frame(mut cc, 5 * time.second) or { panic('entry 1 missing') }
	assert e1.payload.bytestr().contains('seq=1')
	e2 := fb_read_frame(mut cc, 5 * time.second) or { panic('entry 2 missing') }
	assert e2.payload.bytestr().contains('seq=2')

	// the journal's data actually rode the wire into the served store.
	slog := os.read_file(os.join_path(stmp, 'store.log')) or { '' }
	assert slog.contains('endpoint="objects-put"'), 'entries must land as objects in the served store: ${slog}'
	assert slog.contains('endpoint="aliases-set"'), 'chain pointers must ride the alias wire: ${slog}'

	pubc.close()
	cc.close()
}

// #648: the stdin tether — a daemon spawned with --exit-on-stdin-eof and a
// pipe on stdin drains ITSELF when the spawner's pipe end closes (the exact
// thing a panicking test binary does: V panics skip defers, so signal_kill
// cleanup never runs, and pre-tether the orphan squatted its port band,
// poisoned every retry, and wedged make via inherited jobserver FDs).
fn test_daemon_stdin_tether_reaps_on_spawner_death() {
	cxbin := testenv.cx_bin()
	sport := fb_pick_port(8) + 60
	stmp := os.join_path(os.temp_dir(), 'cx-tether-test-${os.getpid()}')
	os.rmdir_all(stmp) or {}
	os.mkdir_all(stmp) or { panic('mkdir ${stmp}: ${err}') }
	defer {
		os.rmdir_all(stmp) or {}
	}
	scfg := fb_write(stmp, 'store.service.cx', '[cxstore-service
  [bind addr="127.0.0.1:${sport}"]
  [stores [store name="t" url="mem://tether-648"]]]')
	mut proc := os.new_process('/bin/sh')
	proc.set_args(['-c',
		'exec "${cxbin}" store-serve --config "${scfg}" --exit-on-stdin-eof --allow-net=127.0.0.1:${sport} >"${stmp}/store.log" 2>&1'])
	proc.set_redirect_stdio()
	proc.run()
	defer {
		proc.signal_kill() // backstop only — the tether should have reaped it
	}
	mut up := false
	for _ in 0 .. 100 {
		time.sleep(100 * time.millisecond)
		r := http.get('http://127.0.0.1:${sport}/cx-store/v1/health') or { continue }
		if r.status_code == 200 {
			up = true
			break
		}
	}
	assert up, 'store-serve never came up: ${os.read_file(os.join_path(stmp, 'store.log')) or { '' }}'

	// simulate the spawner dying without cleanup: close OUR end of the pipes.
	proc.close()
	mut gone := false
	for _ in 0 .. 100 {
		time.sleep(100 * time.millisecond)
		if !proc.is_alive() {
			gone = true
			break
		}
	}
	slog := os.read_file(os.join_path(stmp, 'store.log')) or { '' }
	assert gone, 'the daemon must drain itself on stdin EOF — tether did not fire: ${slog}'
	assert slog.contains('stdin EOF'), 'the drain must be attributed to the tether: ${slog}'
}

fn test_fabric_serve_mutual_publish_push_ack_window_and_denials() {
	port, hport, tmp, mut proc := fb_boot(0, '[policy mode="mutual"]', fb_principals_full)
	defer {
		proc.signal_kill()
		os.unsetenv('CX_FABRIC_SEED')
		os.rmdir_all(tmp) or {}
	}

	// health endpoint answers unauthenticated; unknown paths 404.
	h := http.get('http://127.0.0.1:${hport}/health') or { panic('health: ${err}') }
	assert h.status_code == 200 && h.body.contains('[health'), 'health probe: ${h.status_code} ${h.body}'
	nf := http.get('http://127.0.0.1:${hport}/nope') or { panic('404 probe: ${err}') }
	assert nf.status_code == 404, 'unknown probe path admitted: ${nf.status_code}'

	// a verb before attach fails closed (CXER4928, binary error frame).
	mut cold := &FbChan{
		conn: net.dial_tcp('127.0.0.1:${port}') or { panic('dial: ${err}') }
	}
	fb_send(mut cold, fb_frame_req(9, '[publish stream="orders" [event [do :x]]]', ''))
	cerr := fb_read_frame(mut cold, 5 * time.second) or { panic('no pre-attach refusal') }
	assert cerr.ftype == 7 && cerr.raw.bytestr().contains('CXER4928'), 'pre-attach verb: type ${cerr.ftype} ${cerr.raw.bytestr()}'
	cold.close()

	// mutual attach: publisher connection.
	mut pubc, pm4 := fb_attach(port, tmp, 'pub', fb_client_did, fb_client_seed_hex,
		'0101010101010101010101010101010101010101010101010101010101010101', 'acme')
	assert pm4.ftype == 3, 'publisher attach refused: ${pm4.raw.bytestr()}'

	// a claimed attribution actor ≠ session principal refuses loudly (§4.8 —
	// the xap host's demotion rule, mirrored), and a key the journal would
	// silently drop refuses instead of vanishing. Neither consumes a seq.
	ca := fb_request(mut pubc, 9,
		'[publish stream="orders" [event [do :order.placed]] [attribution [actor "not-me"]]]')
	assert ca.ftype == 7 && ca.payload.bytestr().contains('CXER-XSP-AUTH-PRINCIPAL-MISMATCH'), 'claimed actor admitted: ${ca.payload.bytestr()}'
	ck := fb_request(mut pubc, 10,
		'[publish stream="orders" [event [do :order.placed]] [attribution [note "n1"]]]')
	assert ck.ftype == 7 && ck.payload.bytestr().contains('CXER4926'), 'unknown attribution key admitted: ${ck.payload.bytestr()}'

	// publish → sequenced receipt; the committing actor is the SESSION
	// principal (server-constructed attribution, §11).
	r1 := fb_request(mut pubc, 11, '[publish stream="orders" [event [do :order.placed]]]')
	assert r1.ftype == 3, 'publish refused: ${r1.payload.bytestr()}'
	assert r1.payload.bytestr().contains('seq=1'), 'receipt: ${r1.payload.bytestr()}'

	// subscriber connection: grouped subscription, prefix-glob pattern.
	mut subc, sm4 := fb_attach(port, tmp, 'sub', fb_client_did, fb_client_seed_hex,
		'0202020202020202020202020202020202020202020202020202020202020202', 'acme')
	assert sm4.ftype == 3, 'subscriber attach refused: ${sm4.raw.bytestr()}'
	sr := fb_request(mut subc, 12, '[subscribe stream="orders" group="g1" [pattern :order.*]]')
	assert sr.ftype == 3 && sr.payload.bytestr().contains('assigned=true'), 'subscribe: ${sr.payload.bytestr()}'
	// push delivery: the LOSSLESS entry (atom topic + proven actor) arrives.
	ev1 := fb_read_frame(mut subc, 5 * time.second) or { panic('no pushed entry seq=1') }
	ev1t := ev1.payload.bytestr()
	assert ev1.ftype == 2, 'push is not an event frame: ${ev1t}'
	assert ev1t.contains('seq=1') && ev1t.contains(':order.placed'), 'entry 1: ${ev1t}'
	assert ev1t.contains('actor=${fb_client_did}'), 'actor must be the session principal: ${ev1t}'
	assert ev1t.contains('authority=fabric:publish'), 'served authority label: ${ev1t}'

	// live delivery of a second publish.
	r2 := fb_request(mut pubc, 13, '[publish stream="orders" [event [do :order.shipped]]]')
	assert r2.payload.bytestr().contains('seq=2'), 'receipt 2: ${r2.payload.bytestr()}'
	ev2 := fb_read_frame(mut subc, 5 * time.second) or { panic('no pushed entry seq=2') }
	assert ev2.payload.bytestr().contains('seq=2'), 'entry 2: ${ev2.payload.bytestr()}'
	assert ev2.stream == sr_sub_id(sr), 'event stream-id must be the subscription id'

	// a non-matching topic is consumed silently (pattern filter).
	r3 := fb_request(mut pubc, 14, '[publish stream="orders" [event [do :invoice.sent]]]')
	assert r3.payload.bytestr().contains('seq=3'), 'receipt 3: ${r3.payload.bytestr()}'
	if _ := fb_read_frame(mut subc, 1 * time.second) {
		panic('non-matching event was pushed')
	}

	// cumulative ack through seq=3.
	ar := fb_request(mut subc, 15, '[ack sub=${sr_sub_id(sr)} seq=3]')
	assert ar.ftype == 3 && ar.payload.bytestr() == 'null', 'ack: ${ar.payload.bytestr()}'

	// pending window (4): six matching publishes, exactly four push before the
	// window fills; the ack frees the tail from the journal (§19.2).
	for i in 0 .. 6 {
		rr := fb_request(mut pubc, u64(20 + i),
			'[publish stream="orders" [event [do :order.w${i}]]]')
		assert rr.ftype == 3, 'window publish ${i}: ${rr.payload.bytestr()}'
	}
	mut got := []string{}
	for i in 0 .. 4 {
		e := fb_read_frame(mut subc, 5 * time.second) or {
			dlog := os.read_file(os.join_path(tmp, 'daemon.log')) or { '' }
			panic('window push ${i} missing; got so far: ${got}; daemon: ${dlog}')
		}
		got << e.payload.bytestr()
	}
	assert got[0].contains('seq=4') && got[3].contains('seq=7'), 'window frames: ${got[0]} … ${got[3]}'
	if _ := fb_read_frame(mut subc, 1 * time.second) {
		panic('pending window exceeded: a 5th unacked frame was pushed')
	}
	wr := fb_request(mut subc, 30, '[ack sub=${sr_sub_id(sr)} seq=7]')
	assert wr.ftype == 3, 'window ack: ${wr.payload.bytestr()}'
	e8 := fb_read_frame(mut subc, 5 * time.second) or { panic('catch-up push missing') }
	assert e8.payload.bytestr().contains('seq=8'), 'catch-up: ${e8.payload.bytestr()}'
	e9 := fb_read_frame(mut subc, 5 * time.second) or { panic('catch-up push 2 missing') }
	assert e9.payload.bytestr().contains('seq=9'), 'catch-up 2: ${e9.payload.bytestr()}'

	// a claimed frame principal ≠ session principal refuses (§4.8 demotion).
	fb_send(mut pubc, fb_frame_req(31, '[read channel="coord/map"]', fb_rogue_did))
	mm := fb_read_frame(mut pubc, 5 * time.second) or { panic('no principal-mismatch refusal') }
	assert mm.ftype == 7 && mm.payload.bytestr().contains('CXER-XSP-AUTH-PRINCIPAL-MISMATCH'), 'principal mismatch: ${mm.payload.bytestr()}'

	// a binary verb payload refuses loudly (it would rewrite the event tree).
	binreq := fb_run_cx('', fb_write(tmp, 'binreq.cx', fb_vec_prelude +
		'[\$bytes:to-base64 [\$xsp:encode [frame type=request stream=32 [payload [read channel="coord/map"]]]]]\n'))
	fb_send_b64(mut pubc, binreq)
	bres := fb_read_frame(mut pubc, 5 * time.second) or { panic('no binary-verb refusal') }
	assert bres.ftype == 7 && bres.payload.bytestr().contains('CXER4926'), 'binary verb: ${bres.payload.bytestr()}'

	// transient plane: subscriber registers on a channel, publisher emits —
	// fan-out push + latest-wins read.
	ts := fb_request(mut subc, 40, '[subscribe channel="coord/map" [pattern "viewport"]]')
	assert ts.ftype == 3 && ts.payload.bytestr().contains('coord/map'), 'transient sub: ${ts.payload.bytestr()}'
	er := fb_request(mut pubc, 41, '[emit channel="coord/map" [value [viewport zoom=12]]]')
	assert er.ftype == 3 && er.payload.bytestr() == 'null', 'emit: ${er.payload.bytestr()}'
	tv := fb_read_frame(mut subc, 5 * time.second) or { panic('no transient push') }
	assert tv.ftype == 2 && tv.payload.bytestr().contains('zoom=12'), 'transient push: ${tv.payload.bytestr()}'
	er2 := fb_request(mut pubc, 42, '[emit channel="coord/map" [value [viewport zoom=13]]]')
	assert er2.ftype == 3, 'emit 2: ${er2.payload.bytestr()}'
	rd := fb_request(mut pubc, 43, '[read channel="coord/map"]')
	assert rd.payload.bytestr().contains('zoom=13'), 'latest-wins read: ${rd.payload.bytestr()}'
	rd0 := fb_request(mut pubc, 44, '[read channel="coord/none"]')
	assert rd0.payload.bytestr() == '()', 'never-published read must be absence: ${rd0.payload.bytestr()}'

	// deny-by-default (§11): the observe-only principal cannot publish, emit,
	// or join a group — observe replay is admitted.
	mut rogc, rm4 := fb_attach(port, tmp, 'rogue', fb_rogue_did, fb_rogue_seed_hex,
		'0303030303030303030303030303030303030303030303030303030303030303', 'acme')
	assert rm4.ftype == 3, 'rogue attach refused: ${rm4.raw.bytestr()}'
	rp := fb_request(mut rogc, 50, '[publish stream="orders" [event [do :order.x]]]')
	assert rp.ftype == 7 && rp.payload.bytestr().contains('CXER4925'), 'rogue publish: ${rp.payload.bytestr()}'
	rg := fb_request(mut rogc, 51, '[subscribe stream="orders" group="g2" [pattern :order.*]]')
	assert rg.ftype == 7 && rg.payload.bytestr().contains('CXER4925'), 'rogue grouped subscribe: ${rg.payload.bytestr()}'
	re := fb_request(mut rogc, 52, '[emit channel="coord/map" [value [viewport zoom=1]]]')
	assert re.ftype == 7 && re.payload.bytestr().contains('CXER4925'), 'rogue emit: ${re.payload.bytestr()}'
	ro := fb_request(mut rogc, 53, '[observe stream="orders" [pattern :order.*]]')
	assert ro.ftype == 3 && ro.payload.bytestr().contains('observe=true'), 'rogue observe: ${ro.payload.bytestr()}'
	oe := fb_read_frame(mut rogc, 5 * time.second) or { panic('observe replay missing') }
	assert oe.payload.bytestr().contains('seq=1'), 'observe replay starts at seq=1: ${oe.payload.bytestr()}'
	// drain the rest of the replay — 7 more matches (seq 2, 4..9; the
	// :invoice.sent entry does not match :order.*) — so the next reply read
	// is the ack refusal, not a queued push.
	for i in 0 .. 7 {
		oez := fb_read_frame(mut rogc, 5 * time.second) or {
			panic('observe replay match ${i + 2} missing')
		}
		assert oez.ftype == 2, 'replay frame type: ${oez.ftype}'
	}
	if _ := fb_read_frame(mut rogc, 1 * time.second) {
		panic('observe replay pushed a non-matching entry')
	}
	// an observe subscription can never ack (read-only inspection).
	oa := fb_request(mut rogc, 54, '[ack sub=${sr_sub_id(ro)} seq=1]')
	assert oa.ftype == 7 && oa.payload.bytestr().contains('CXER4922'), 'observe ack: ${oa.payload.bytestr()}'

	// anonymous under require-mutual: M1→M2 proceeds, M3 refuses.
	mut anonc, am4 := fb_attach(port, tmp, 'anon', '', '',
		'0404040404040404040404040404040404040404040404040404040404040404', 'acme')
	assert am4.ftype == 7 && am4.raw.bytestr().contains('CXER-XSP-AUTH-ANONYMOUS-REFUSED'), 'anonymous attach admitted under mutual: ${am4.raw.bytestr()}'
	anonc.close()

	// an attach naming an unmounted tenant refuses (structural partition).
	mut wtc, wm4 := fb_attach(port, tmp, 'wrongtenant', fb_client_did, fb_client_seed_hex,
		'0505050505050505050505050505050505050505050505050505050505050505', 'nosuch')
	assert wm4.ftype == 7 && wm4.raw.bytestr().contains('CXER4927'), 'unmounted tenant admitted: ${wm4.raw.bytestr()}'
	wtc.close()

	pubc.close()
	subc.close()
	rogc.close()
}

const fb_principals_dlq = '[principals
    [principal did="${fb_client_did}"
      [grant action="publish" scope="*"]
      [grant action="consume" scope="*"]
      [grant action="observe" scope="*"]]
    [principal did="${fb_rogue_did}"
      [grant action="consume" scope="jobs"]
      [grant action="observe" scope="*"]]]'

// Boot 3 — §9.1 redelivery policy on the served tier: declaration + group-state
// inheritance + conflict refusal + the dlq-publish-grant check at declaration,
// then the poison loop across a failover — the successor's redelivery is the
// exhausted attempt, so the head dead-letters instead of redelivering, the DLQ
// observer receives the [dead-letter] envelope (fabric-constructed attribution:
// actor = the group, authority = fabric:dlq), and the group unblocks.
fn test_fabric_serve_dlq_redelivery_policy() {
	port, _, tmp, mut proc := fb_boot(2, '[policy mode="mutual"]', fb_principals_dlq)
	defer {
		proc.signal_kill()
		os.unsetenv('CX_FABRIC_SEED')
		os.rmdir_all(tmp) or {}
	}

	// seed the poison event.
	mut pubc, pm4 := fb_attach(port, tmp, 'dlqpub', fb_client_did, fb_client_seed_hex,
		'0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'acme')
	assert pm4.ftype == 3, 'publisher attach: ${pm4.raw.bytestr()}'
	assert fb_request(mut pubc, 10, '[publish stream="jobs" [event [do :job.poison]]]').payload.bytestr().contains('seq=1')

	// a DLQ observer watches the dead-letter stream (ordinary stream, §9.1).
	mut obsc, om4 := fb_attach(port, tmp, 'dlqobs', fb_client_did, fb_client_seed_hex,
		'0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c', 'acme')
	assert om4.ftype == 3
	oo := fb_request(mut obsc, 11, '[observe stream="jobs.dlq" [pattern "dead-letter"]]')
	assert oo.ftype == 3, 'dlq observe: ${oo.payload.bytestr()}'

	// consumer A declares the policy: max-deliveries=1, dlq="jobs.dlq" — the
	// head delivers once (attempt 1 recorded before A sees it).
	mut ac, am4 := fb_attach(port, tmp, 'dlqA', fb_client_did, fb_client_seed_hex,
		'0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d', 'acme')
	assert am4.ftype == 3
	asub := fb_request(mut ac, 12,
		'[subscribe stream="jobs" group="g" max-deliveries=1 dlq="jobs.dlq" [pattern :job.*]]')
	assert asub.ftype == 3 && asub.payload.bytestr().contains('assigned=true'), 'A subscribe: ${asub.payload.bytestr()}'
	a1 := fb_read_frame(mut ac, 5 * time.second) or { panic('A: poison delivery missing') }
	assert a1.payload.bytestr().contains('seq=1'), 'A delivery: ${a1.payload.bytestr()}'

	// a CONFLICTING redeclaration in the same group refuses loudly (§9.1 —
	// group siblings never run divergent policies silently).
	mut bc, bm4 := fb_attach(port, tmp, 'dlqB', fb_client_did, fb_client_seed_hex,
		'0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e', 'acme')
	assert bm4.ftype == 3
	bconf := fb_request(mut bc, 13,
		'[subscribe stream="jobs" group="g" max-deliveries=3 dlq="jobs.dlq" [pattern :job.*]]')
	assert bconf.ftype == 7 && bconf.payload.bytestr().contains('CXER4931'), 'conflicting policy admitted: ${bconf.payload.bytestr()}'
	// the policy keys come together or not at all.
	bhalf := fb_request(mut bc, 14, '[subscribe stream="jobs" group="g3" max-deliveries=2 [pattern :job.*]]')
	assert bhalf.ftype == 7 && bhalf.payload.bytestr().contains('CXER4931'), 'half policy admitted: ${bhalf.payload.bytestr()}'
	// an undeclared subscribe INHERITS the group's persisted policy — standby.
	bsub := fb_request(mut bc, 15, '[subscribe stream="jobs" group="g" [pattern :job.*]]')
	assert bsub.ftype == 3 && bsub.payload.bytestr().contains('assigned=false'), 'B standby: ${bsub.payload.bytestr()}'

	// declaring a policy whose dlq the principal cannot publish to refuses —
	// no writing into a stream through a policy side door (§9.1/§11).
	mut rogc, rm4 := fb_attach(port, tmp, 'dlqrogue', fb_rogue_did, fb_rogue_seed_hex,
		'0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f', 'acme')
	assert rm4.ftype == 3
	rr := fb_request(mut rogc, 16,
		'[subscribe stream="jobs" group="g2" max-deliveries=1 dlq="jobs.dlq" [pattern :job.*]]')
	assert rr.ftype == 7 && rr.payload.bytestr().contains('CXER4925'), 'policy side-door admitted: ${rr.payload.bytestr()}'

	// A dies without acking → failover to B; the redelivery would be attempt 2
	// of a max-1 policy, so the head DEAD-LETTERS instead of redelivering.
	ac.close()
	dl := fb_read_frame(mut obsc, 5 * time.second) or { panic('dead-letter push missing') }
	dlt := dl.payload.bytestr()
	assert dlt.contains('dead-letter'), 'dlq push: ${dlt}'
	assert dlt.contains('attempts=1') && dlt.contains(':job.poison'), 'envelope: ${dlt}'
	assert dlt.contains('actor=g') && dlt.contains('authority=fabric:dlq'), 'dlq attribution: ${dlt}'
	if _ := fb_read_frame(mut bc, 1 * time.second) {
		panic('the exhausted head redelivered to the successor')
	}

	// the group is unblocked: the offset committed through the poison seq, so
	// the next publish delivers to B immediately.
	assert fb_request(mut pubc, 17, '[publish stream="jobs" [event [do :job.next]]]').payload.bytestr().contains('seq=2')
	b2 := fb_read_frame(mut bc, 5 * time.second) or { panic('B: post-dlq delivery missing') }
	assert b2.payload.bytestr().contains('seq=2') && b2.payload.bytestr().contains(':job.next'), 'B delivery: ${b2.payload.bytestr()}'

	pubc.close()
	obsc.close()
	bc.close()
	rogc.close()
}

// Boot 4 — §12.1 request-reply on the served tier: registration (grants,
// sticky-exclusive), call routing requester→responder over native XSP
// request/reply frames (server-assigned correlation stream-id), the failure
// channel (error answers verbatim), pending-call expiry (request-timeout-ms),
// responder-death loud failure — then the REMOTE CLIENT tier end to end: a
// cx responder process (respond + serve pump) answers a cx requester's
// blocking request over the live daemon.
fn test_fabric_serve_request_reply() {
	port, _, tmp, mut proc := fb_boot(3, '[policy mode="mutual"]', fb_principals_full)
	defer {
		proc.signal_kill()
		os.unsetenv('CX_FABRIC_SEED')
		os.rmdir_all(tmp) or {}
	}

	mut reqc, qm4 := fb_attach(port, tmp, 'rrreq', fb_client_did, fb_client_seed_hex,
		'1111111111111111111111111111111111111111111111111111111111111111', 'acme')
	assert qm4.ftype == 3, 'requester attach: ${qm4.raw.bytestr()}'

	// no responder yet: the request refuses immediately, never hangs.
	nr := fb_request(mut reqc, 10, '[request channel="svc/sum" [value [args [a 2] [b 3]]]]')
	assert nr.ftype == 7 && nr.payload.bytestr().contains('CXER4932'), 'no-responder request: ${nr.payload.bytestr()}'

	// responder registers (consume grant); a competing respond refuses —
	// sticky-exclusive per channel.
	mut rspc, sm4 := fb_attach(port, tmp, 'rrresp', fb_client_did, fb_client_seed_hex,
		'1212121212121212121212121212121212121212121212121212121212121212', 'acme')
	assert sm4.ftype == 3
	rg := fb_request(mut rspc, 11, '[respond channel="svc/sum"]')
	assert rg.ftype == 3 && rg.payload.bytestr().contains('fabric-responder'), 'respond: ${rg.payload.bytestr()}'
	dup := fb_request(mut reqc, 12, '[respond channel="svc/sum"]')
	assert dup.ftype == 7 && dup.payload.bytestr().contains('CXER4933'), 'competing respond admitted: ${dup.payload.bytestr()}'

	// deny-by-default (§11): the observe-only principal can neither respond
	// (consume) nor request (publish).
	mut rogc, rm4 := fb_attach(port, tmp, 'rrrogue', fb_rogue_did, fb_rogue_seed_hex,
		'1313131313131313131313131313131313131313131313131313131313131313', 'acme')
	assert rm4.ftype == 3
	rr1 := fb_request(mut rogc, 13, '[respond channel="svc/other"]')
	assert rr1.ftype == 7 && rr1.payload.bytestr().contains('CXER4925'), 'rogue respond: ${rr1.payload.bytestr()}'
	rr2 := fb_request(mut rogc, 14, '[request channel="svc/sum" [value [args [a 1] [b 1]]]]')
	assert rr2.ftype == 7 && rr2.payload.bytestr().contains('CXER4925'), 'rogue request: ${rr2.payload.bytestr()}'
	rogc.close()

	// the call: requester sends, the server pushes a `request` frame to the
	// responder under a correlation stream-id, the responder's reply routes
	// back to the requester's own stream id.
	fb_send(mut reqc, fb_frame_req(20, '[request channel="svc/sum" [value [args [a 2] [b 3]]]]',
		''))
	pushed := fb_read_frame(mut rspc, 5 * time.second) or { panic('no pushed request frame') }
	pt := pushed.payload.bytestr()
	assert pushed.ftype == 1, 'push type: ${pushed.ftype} ${pt}'
	assert pt.contains('fabric-request') && pt.contains('svc/sum') && pt.contains('[a 2]'), 'pushed call: ${pt}'
	corr := pushed.stream
	assert corr == u64(sr_sub_id(pushed)), 'correlation id mismatch: stream ${corr} vs id ${sr_sub_id(pushed)}'
	fb_send(mut rspc, fb_frame_text(3, corr, '5', ''))
	rep := fb_read_frame(mut reqc, 5 * time.second) or { panic('no routed reply') }
	assert rep.ftype == 3 && rep.stream == 20 && rep.payload.bytestr() == '5', 'routed reply: type ${rep.ftype} stream ${rep.stream} ${rep.payload.bytestr()}'

	// the §4.8 demotion rule holds on reply frames exactly as on verbs.
	fb_send(mut rspc, fb_frame_text(3, 999, 'null', fb_rogue_did))
	pm := fb_read_frame(mut rspc, 5 * time.second) or { panic('no reply-frame principal refusal') }
	assert pm.ftype == 7 && pm.payload.bytestr().contains('CXER-XSP-AUTH-PRINCIPAL-MISMATCH'), 'reply-frame principal: ${pm.payload.bytestr()}'

	// the failure channel: an error answer routes back verbatim.
	fb_send(mut reqc, fb_frame_req(21, '[request channel="svc/sum" [value [args [a 0] [b 0]]]]',
		''))
	p2 := fb_read_frame(mut rspc, 5 * time.second) or { panic('no pushed request 2') }
	fb_send(mut rspc, fb_frame_text(7, p2.stream,
		"[err code=cx-err:CXER0108 message='E_ARG: no zeros']", ''))
	er := fb_read_frame(mut reqc, 5 * time.second) or { panic('no routed error') }
	assert er.ftype == 7 && er.stream == 21 && er.payload.bytestr().contains('CXER0108'), 'routed error: ${er.payload.bytestr()}'

	// pending-call expiry: a silent responder fails the requester loudly with
	// CXER4934 after request-timeout-ms (1500), via the sweeper.
	fb_send(mut reqc, fb_frame_req(22, '[request channel="svc/sum" [value [args [a 9] [b 9]]]]',
		''))
	if _ := fb_read_frame(mut rspc, 2 * time.second) {
		// drain the pushed frame; the responder stays silent on purpose.
	}
	to := fb_read_frame(mut reqc, 5 * time.second) or { panic('no timeout refusal') }
	assert to.ftype == 7 && to.stream == 22 && to.payload.bytestr().contains('CXER4934'), 'timeout: ${to.payload.bytestr()}'

	// responder death with a call in flight fails the requester loudly —
	// never a silent wait-out.
	fb_send(mut reqc, fb_frame_req(23, '[request channel="svc/sum" [value [args [a 4] [b 4]]]]',
		''))
	if _ := fb_read_frame(mut rspc, 2 * time.second) {
	}
	rspc.close()
	dd := fb_read_frame(mut reqc, 5 * time.second) or { panic('no responder-death refusal') }
	assert dd.ftype == 7 && dd.stream == 23 && dd.payload.bytestr().contains('CXER4932'), 'responder death: ${dd.payload.bytestr()}'
	// …and death freed the registration: a fresh respond succeeds.
	rg2 := fb_request(mut reqc, 24, '[respond channel="svc/sum"]')
	assert rg2.ftype == 3 && rg2.payload.bytestr().contains('fabric-responder'), 'post-death respond: ${rg2.payload.bytestr()}'
	reqc.close()

	// REMOTE CLIENT tier end to end (the §12.1 verbs over the live daemon):
	// a cx responder process registers a callable and serve-pumps; a cx
	// requester's blocking request gets the applied reply.
	cxbin := testenv.cx_bin()
	resp_prog := fb_write(tmp, 'rr-responder.cx', "[?lib 'cx-fabric' :as fabric]\n" +
		"[?lib 'cx-stdlib/bytes' :as bytes]\n" +
		'[?let [= \$f [\$fabric:open "xsp://127.0.0.1:${port}" {tenant: "acme" did: "${fb_client_did}" seed: [\$bytes:from-hex "${fb_client_seed_hex}"]}]]\n' +
		'  [= \$r [\$fabric:respond \$f "svc/echo2" [?fn (\$v) [echoed \$v]]]]\n' +
		'  [\$fabric:serve \$r {deadline: 10000 max: 1}]]\n')
	mut rproc := os.new_process('/bin/sh')
	rproc.set_args(['-c',
		'exec "${cxbin}" --allow-net=127.0.0.1:${port} "${resp_prog}" >"${tmp}/rr-responder.out" 2>&1'])
	rproc.run()
	defer {
		rproc.signal_kill()
	}
	time.sleep(2000 * time.millisecond) // registration window (attach + respond)
	req_prog := fb_write(tmp, 'rr-requester.cx', "[?lib 'cx-fabric' :as fabric]\n" +
		"[?lib 'cx-stdlib/bytes' :as bytes]\n" +
		'[?let [= \$f [\$fabric:open "xsp://127.0.0.1:${port}" {tenant: "acme" did: "${fb_client_did}" seed: [\$bytes:from-hex "${fb_client_seed_hex}"]}]]\n' +
		'  [\$fabric:request \$f "svc/echo2" [ping 7] {deadline: 8000}]]\n')
	reply := fb_run_cx('--allow-net=127.0.0.1:${port}', req_prog)
	assert reply.contains('[echoed [ping 7]]'), 'remote request reply: ${reply}'
	rproc.wait()
	served := os.read_file(os.join_path(tmp, 'rr-responder.out')) or { '' }
	assert served.trim_space().ends_with('1'), 'responder served count: ${served}'
}

// sr_sub_id extracts id= from a [fabric-sub id=N …] text reply.
fn sr_sub_id(f FbFrame) u64 {
	t := f.payload.bytestr()
	idx := t.index('id=') or { panic('no id= in ${t}') }
	mut end := idx + 3
	for end < t.len && t[end].is_digit() {
		end++
	}
	return t[idx + 3..end].u64()
}

const fb_principals_floor = '[principals
    [principal did="${fb_client_did}"
      [grant action="publish" scope="*"]
      [grant action="consume" scope="*"]
      [grant action="observe" scope="*"]]]
  [anonymous [grant action="observe" scope="*"]]'

fn test_fabric_serve_floor_groups_failover_and_liveness() {
	port, _, tmp, mut proc := fb_boot(1, '[policy mode="floor" floor="dev"]', fb_principals_floor)
	defer {
		proc.signal_kill()
		os.unsetenv('CX_FABRIC_SEED')
		os.rmdir_all(tmp) or {}
	}

	// anonymous attach lands on the floor principal: observe admitted by the
	// [anonymous] grants, publish denied — deny-by-default holds on the floor.
	mut anonc, am4 := fb_attach(port, tmp, 'floor', '', '',
		'0606060606060606060606060606060606060606060606060606060606060606', 'acme')
	assert am4.ftype == 3, 'anonymous floor attach failed: ${am4.raw.bytestr()}'
	fo := fb_request(mut anonc, 10, '[observe stream="jobs" [pattern :job.*]]')
	assert fo.ftype == 3, 'floor observe refused: ${fo.payload.bytestr()}'
	fp := fb_request(mut anonc, 11, '[publish stream="jobs" [event [do :job.new]]]')
	assert fp.ftype == 7 && fp.payload.bytestr().contains('CXER4925'), 'floor publish admitted: ${fp.payload.bytestr()}'

	// seed the stream: two events.
	mut pubc, pm4 := fb_attach(port, tmp, 'pub2', fb_client_did, fb_client_seed_hex,
		'0707070707070707070707070707070707070707070707070707070707070707', 'acme')
	assert pm4.ftype == 3, 'publisher attach: ${pm4.raw.bytestr()}'
	assert fb_request(mut pubc, 12, '[publish stream="jobs" [event [do :job.a]]]').payload.bytestr().contains('seq=1')
	assert fb_request(mut pubc, 13, '[publish stream="jobs" [event [do :job.b]]]').payload.bytestr().contains('seq=2')

	// consumer A takes the assignment, receives both, commits through seq=1.
	mut ac, aam4 := fb_attach(port, tmp, 'consA', fb_client_did, fb_client_seed_hex,
		'0808080808080808080808080808080808080808080808080808080808080808', 'acme')
	assert aam4.ftype == 3
	asub := fb_request(mut ac, 14, '[subscribe stream="jobs" group="g" [pattern :job.*]]')
	assert asub.payload.bytestr().contains('assigned=true'), 'A not assigned: ${asub.payload.bytestr()}'
	a1 := fb_read_frame(mut ac, 5 * time.second) or { panic('A: entry 1 missing') }
	assert a1.payload.bytestr().contains('seq=1')
	a2 := fb_read_frame(mut ac, 5 * time.second) or { panic('A: entry 2 missing') }
	assert a2.payload.bytestr().contains('seq=2')
	assert fb_request(mut ac, 15, '[ack sub=${sr_sub_id(asub)} seq=1]').ftype == 3

	// consumer B joins the same group: sticky exclusive — standby, no frames.
	mut bc, bm4 := fb_attach(port, tmp, 'consB', fb_client_did, fb_client_seed_hex,
		'0909090909090909090909090909090909090909090909090909090909090909', 'acme')
	assert bm4.ftype == 3
	bsub := fb_request(mut bc, 16, '[subscribe stream="jobs" group="g" [pattern :job.*]]')
	assert bsub.payload.bytestr().contains('assigned=false'), 'B stole the assignment: ${bsub.payload.bytestr()}'
	// Keep the holder LIVE through the standby quiet-check (#648 finding): A's
	// last frame was its ack; under machine load the 1s check races the 1500ms
	// liveness window and the sweeper could depose A mid-check — a false
	// "standby received delivery". A ping pins A's liveness deterministically.
	fb_send(mut ac, fb_frame_ping())
	_ := fb_read_frame(mut ac, 5 * time.second) or { panic('A: no pong') }
	if _ := fb_read_frame(mut bc, 1 * time.second) {
		panic('standby received delivery while the holder is live')
	}

	// failover on death: A's connection dies → B resumes from the COMMITTED
	// offset — the uncommitted tail (exactly seq=2) redelivers (§19.3).
	ac.close()
	b2 := fb_read_frame(mut bc, 5 * time.second) or { panic('B: failover redelivery missing') }
	assert b2.payload.bytestr().contains('seq=2'), 'B redelivery: ${b2.payload.bytestr()}'
	if _ := fb_read_frame(mut bc, 1 * time.second) {
		panic('B received more than the uncommitted tail')
	}

	// liveness-window failover: B holds but goes silent; C joins and B misses
	// the 1500ms window → the sweeper hands the stream to C, which redelivers
	// the still-uncommitted tail (B never acked seq=2).
	mut cc, cm4 := fb_attach(port, tmp, 'consC', fb_client_did, fb_client_seed_hex,
		'0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a', 'acme')
	assert cm4.ftype == 3
	csub := fb_request(mut cc, 17, '[subscribe stream="jobs" group="g" [pattern :job.*]]')
	assert csub.payload.bytestr().contains('assigned=false'), 'C stole the assignment: ${csub.payload.bytestr()}'
	c2 := fb_read_frame(mut cc, 6 * time.second) or { panic('C: liveness failover missing') }
	assert c2.payload.bytestr().contains('seq=2'), 'C redelivery: ${c2.payload.bytestr()}'

	// a ping keeps a holder alive: C heartbeats through 2× the window and
	// keeps the assignment (no redelivery lands on B).
	for _ in 0 .. 6 {
		fb_send(mut cc, fb_frame_ping())
		pong := fb_read_frame(mut cc, 5 * time.second) or { panic('no pong') }
		assert pong.ftype == 6, 'ping answer: type ${pong.ftype}'
		time.sleep(500 * time.millisecond)
	}
	if _ := fb_read_frame(mut bc, 1 * time.second) {
		panic('a heartbeating holder lost the assignment')
	}

	pubc.close()
	anonc.close()
	bc.close()
	cc.close()
}

// xsp.md §5 session layer (#560): the post-attach [session] query advertises
// features + liveness (§5.0); a windowed observe subscription is
// credit-bounded — the push stops at the declared window and a `credit`
// frame (type 8) resumes it (§5.2; the client library's receive-side
// auto-credit is this same frame); ping answers pong (§5.1); and from= on a
// group subscription is refused — the committed offset is the resume point
// (§5.3).
fn test_fabric_serve_xsp_s5_session_credit_and_resume() {
	port, hport, tmp, mut proc := fb_boot(2, '[policy mode="mutual"]', fb_principals_full)
	defer {
		proc.signal_kill()
		os.unsetenv('CX_FABRIC_SEED')
		os.rmdir_all(tmp) or {}
	}
	_ = hport

	mut pubc, pm4 := fb_attach(port, tmp, 's5pub', fb_client_did, fb_client_seed_hex,
		'0303030303030303030303030303030303030303030303030303030303030303', 'acme')
	assert pm4.ftype == 3, 's5 publisher attach refused: ${pm4.raw.bytestr()}'

	// §5.0: the session query answers features + limits.
	sres := fb_request(mut pubc, 21, '[session]')
	assert sres.ftype == 3, 'session query refused: ${sres.payload.bytestr()}'
	sbody := sres.payload.bytestr()
	assert sbody.contains('fabric-session'), 'session reply shape: ${sbody}'
	for feat in ['heartbeat', 'credit', 'resume'] {
		assert sbody.contains(feat), 'features missing ${feat}: ${sbody}'
	}
	assert sbody.contains('liveness-ms='), 'liveness-ms not advertised: ${sbody}'

	// §5.1: ping answers pong.
	fb_send(mut pubc, fb_frame_ping())
	pong := fb_read_frame(mut pubc, 5 * time.second) or { panic('no pong for ping') }
	assert pong.ftype == 6, 'ping answered with type ${pong.ftype}'

	// §5.3: from= on a group subscription is refused loudly.
	fres := fb_request(mut pubc, 22,
		'[subscribe stream="orders" group="g5" from=1 [pattern :order.*]]')
	assert fres.ftype == 7 && fres.payload.bytestr().contains('from= is refused'), 'group from= admitted: ${fres.payload.bytestr()}'

	// observe-only principal, window=2 (§5.2).
	mut obsc, om4 := fb_attach(port, tmp, 's5obs', fb_rogue_did, fb_rogue_seed_hex,
		'0404040404040404040404040404040404040404040404040404040404040404', 'acme')
	assert om4.ftype == 3, 's5 observer attach refused: ${om4.raw.bytestr()}'
	ores := fb_request(mut obsc, 30,
		'[observe stream="orders" window=2 [pattern :order.*]]')
	obody := ores.payload.bytestr()
	assert ores.ftype == 3 && obody.contains('fabric-sub'), 'windowed observe refused: ${obody}'
	idx := obody.index('id=') or { panic('no sub id in ${obody}') }
	mut sub_id := 0
	for i := idx + 3; i < obody.len && obody[i].is_digit(); i++ {
		sub_id = sub_id * 10 + int(obody[i] - `0`)
	}
	assert sub_id > 0, 'unparsed sub id: ${obody}'

	// three publishes; only TWO frames may arrive (the window).
	for i in 0 .. 3 {
		pr := fb_request(mut pubc, u64(23 + i), '[publish stream="orders" [event [do :order.placed]]]')
		assert pr.ftype == 3, 'publish ${i} refused: ${pr.payload.bytestr()}'
	}
	e1 := fb_read_frame(mut obsc, 5 * time.second) or { panic('first windowed event missing') }
	assert e1.ftype == 2, 'expected event, got type ${e1.ftype}'
	e2 := fb_read_frame(mut obsc, 5 * time.second) or { panic('second windowed event missing') }
	assert e2.ftype == 2, 'expected event, got type ${e2.ftype}'
	if extra := fb_read_frame(mut obsc, 1500 * time.millisecond) {
		assert false, 'window=2 exceeded: got a third frame type ${extra.ftype}: ${extra.raw.bytestr()}'
	}

	// §5.2: one credit frame (type 8, payload = data-bin int) releases the third.
	credit_b64 := fb_run_cx('', fb_write(tmp, 's5credit.cx', fb_vec_prelude +
		'[\$bytes:to-base64 [\$xsp:encode [frame type=credit stream=${sub_id} [payload 1]]]]\n'))
	fb_send_b64(mut obsc, credit_b64)
	e3 := fb_read_frame(mut obsc, 5 * time.second) or { panic('credited third event missing') }
	assert e3.ftype == 2, 'expected credited event, got type ${e3.ftype}: ${e3.raw.bytestr()}'

	// §5.3 observe resume: a fresh observe from=2 replays exactly seq 2..3.
	rres := fb_request(mut obsc, 31,
		'[observe stream="orders" from=2 [pattern :order.*]]')
	assert rres.ftype == 3 && rres.payload.bytestr().contains('fabric-sub'), 'resume observe refused: ${rres.payload.bytestr()}'
	r1 := fb_read_frame(mut obsc, 5 * time.second) or { panic('resume replay missing') }
	assert r1.ftype == 2 && r1.payload.bytestr().contains('seq=2'), 'resume did not start at from=: ${r1.payload.bytestr()}'
	r2 := fb_read_frame(mut obsc, 5 * time.second) or { panic('resume tail missing') }
	assert r2.ftype == 2 && r2.payload.bytestr().contains('seq=3'), 'resume tail wrong: ${r2.payload.bytestr()}'

	obsc.close()
	pubc.close()
}

// #607: the negotiated publish-batch verb — N events, ONE turn, ONE
// receipt covering the batch; validation is ATOMIC (a refused batch
// appends nothing — seq continuity proves it); expect-prev-seq and
// claimed-actor attributions refuse the whole batch.
fn test_fabric_serve_publish_batch() {
	port, _, tmp, mut proc := fb_boot(3, '[policy mode="mutual"]', fb_principals_full)
	defer {
		proc.signal_kill()
		os.unsetenv('CX_FABRIC_SEED')
		os.rmdir_all(tmp) or {}
	}
	mut pubc, m4 := fb_attach(port, tmp, 'pb', fb_client_did, fb_client_seed_hex,
		'0909090909090909090909090909090909090909090909090909090909090909', 'acme')
	assert m4.ftype == 3, 'attach refused: ${m4.raw.bytestr()}'

	// the session advertises the feature.
	sres := fb_request(mut pubc, 9, '[session]')
	assert sres.ftype == 3 && sres.payload.bytestr().contains('publish-batch'), 'feature not advertised: ${sres.payload.bytestr()}'

	// three events, one turn, one receipt covering seq 1..3.
	rb := fb_request(mut pubc, 10,
		'[publish-batch stream="orders" [event [do :order.a]] [event [do :order.b]] [event [do :order.c]]]')
	assert rb.ftype == 3, 'batch refused: ${rb.payload.bytestr()}'
	rbt := rb.payload.bytestr()
	assert rbt.contains('receipt-batch') && rbt.contains('first=1') && rbt.contains('last=3')
		&& rbt.contains('count=3'), 'batch receipt wrong: ${rbt}'

	// atomic validation: an empty event refuses the WHOLE batch — the next
	// single publish gets seq 4, proving nothing from the refused batch
	// appended.
	bad := fb_request(mut pubc, 11,
		'[publish-batch stream="orders" [event [do :order.d]] [event]]')
	assert bad.ftype == 7 && bad.payload.bytestr().contains('atomic'), 'empty event admitted: ${bad.payload.bytestr()}'

	// a claimed actor ≠ session principal refuses the batch (§4.8), atomically.
	ca := fb_request(mut pubc, 12,
		'[publish-batch stream="orders" [event [do :order.e]] [attribution [actor "not-me"]]]')
	assert ca.ftype == 7 && ca.payload.bytestr().contains('PRINCIPAL-MISMATCH'), 'claimed actor admitted: ${ca.payload.bytestr()}'

	// expect-prev-seq does not compose with a batch.
	eps := fb_request(mut pubc, 13,
		'[publish-batch stream="orders" [event [do :order.f]] [attribution [expect-prev-seq 3]]]')
	assert eps.ftype == 7 && eps.payload.bytestr().contains('expect-prev-seq'), 'expect-prev-seq admitted: ${eps.payload.bytestr()}'

	// seq continuity: the refused batches appended nothing.
	r4 := fb_request(mut pubc, 14, '[publish stream="orders" [event [do :order.g]]]')
	assert r4.ftype == 3 && r4.payload.bytestr().contains('seq=4'), 'refused batches leaked appends: ${r4.payload.bytestr()}'

	// delivery: a fresh subscriber replays all four committed events.
	mut subc, sm4 := fb_attach(port, tmp, 'pbs', fb_client_did, fb_client_seed_hex,
		'0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a', 'acme')
	assert sm4.ftype == 3
	sr := fb_request(mut subc, 15, '[subscribe stream="orders" group="gpb" [pattern :order.*]]')
	assert sr.ftype == 3, 'subscribe refused: ${sr.payload.bytestr()}'
	mut got := 0
	for _ in 0 .. 4 {
		ev := fb_read_frame(mut subc, 5 * time.second) or { break }
		if ev.ftype == 2 {
			got++
		}
	}
	assert got == 4, 'batch delivery incomplete: got ${got} of 4'
	subc.close()
	pubc.close()
}

// #655: a journal store the net grant cannot reach fails AT BOOT with the
// full cause chain — the innermost error NAMES the §4.5 loopback deny and
// its fix (a literal --allow-net=host:port grant). Pre-#655 the boot error
// was an anonymous algo-stamp message with zero wire traffic and the deny
// was misclassified as integrity corruption.
fn test_fabric_serve_csrp_store_denied_grant_fails_loud_with_cause() {
	cxbin := testenv.cx_bin()
	sport := fb_pick_port(9) + 70
	stmp := os.join_path(os.temp_dir(), 'cx-fabric-655-${os.getpid()}')
	os.rmdir_all(stmp) or {}
	os.mkdir_all(stmp) or { panic('mkdir ${stmp}: ${err}') }
	defer {
		os.rmdir_all(stmp) or {}
	}
	scfg := fb_write(stmp, 'store.service.cx', '[cxstore-service
  [bind addr="127.0.0.1:${sport}"]
  [stores [store name="journal" url="mem://f655"]]]')
	mut sproc := os.new_process('/bin/sh')
	sproc.set_args(['-c',
		'exec "${cxbin}" store-serve --config "${scfg}" --exit-on-stdin-eof --allow-net=127.0.0.1:${sport} >"${stmp}/store.log" 2>&1'])
	sproc.set_redirect_stdio()
	sproc.run()
	defer {
		sproc.signal_kill()
	}
	mut sup := false
	for _ in 0 .. 100 {
		time.sleep(100 * time.millisecond)
		r := http.get('http://127.0.0.1:${sport}/cx-store/v1/health') or { continue }
		if r.status_code == 200 {
			sup = true
			break
		}
	}
	assert sup, 'store-serve never came up'

	port := fb_pick_port(9) + 72
	hport := port + 1
	fcfg := fb_write(stmp, 'fabric.service.cx', '[fabric-service
  [bind addr="127.0.0.1:${port}"]
  [health addr="127.0.0.1:${hport}"]
  [identity did="${fb_host_did}" seed-env="CX_FABRIC_SEED"]
  [policy mode="mutual"]
  [fabrics [fabric name="main" store="cx-store+http://127.0.0.1:${sport}/journal/" tenant="probe"]]
  [principals [principal did="${fb_client_did}" [grant action="publish" scope="*"]]]]')
	os.setenv('CX_FABRIC_SEED', fb_host_seed_hex, true)
	defer {
		os.unsetenv('CX_FABRIC_SEED')
	}
	// BARE --allow-net: the §4.5 deny-set refuses outbound loopback — the
	// daemon must fail at boot, loudly, with the deny named in the cause.
	r := os.execute('"${cxbin}" fabric-serve --config "${fcfg}" --allow-net --allow-read --allow-write --allow-env 2>&1')
	assert r.exit_code != 0, 'bare --allow-net against a loopback store must fail at boot: ${r.output}'
	assert r.output.contains('CXER4504'), 'the cause chain must name the §4.5 deny: ${r.output}'
	assert r.output.contains('literal-IP/localhost grant'), 'the cause must name the fix: ${r.output}'
	slog := os.read_file(os.join_path(stmp, 'store.log')) or { '' }
	assert !slog.contains('request-log'), 'the deny is client-side — nothing may reach the store: ${slog}'
}

const fb_principals_rotate = '[principals
    [principal did="${fb_client_did}"
      [grant action="publish" scope="*"]
      [grant action="consume" scope="*"]
      [grant action="observe" scope="*"]
      [grant action="rotate" scope="*"]]
    [principal did="${fb_rogue_did}"
      [grant action="observe" scope="*"]]]'

// #640: mount rotation over the wire — [rotate keep-n=N] seals every stream
// at head−N, moves the hot window to a fresh next-generation store, swaps
// the mount, and the chain continues; a group whose committed offset is
// below a boundary BLOCKS the rotation (its uncommitted tail would strand
// in the cold segment); the verb needs an explicit rotate grant.
fn test_fabric_serve_rotate_mount() {
	port, _, tmp, mut proc := fb_boot(3, '[policy mode="mutual"]', fb_principals_rotate)
	defer {
		proc.signal_kill()
		os.unsetenv('CX_FABRIC_SEED')
		os.rmdir_all(tmp) or {}
	}

	mut pubc, pm4 := fb_attach(port, tmp, 'rot-pub', fb_client_did, fb_client_seed_hex,
		'0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d', 'acme')
	assert pm4.ftype == 3, 'publisher attach: ${pm4.raw.bytestr()}'
	for i in 1 .. 6 {
		p := fb_request(mut pubc, 40 + i, '[publish stream="jobs" [event [do :job.r${i}]]]')
		assert p.ftype == 3 && p.payload.bytestr().contains('seq=${i}'), 'publish ${i}: ${p.payload.bytestr()}'
	}

	// consumer group g8 receives all five and commits through 5.
	mut cc, cm4 := fb_attach(port, tmp, 'rot-con', fb_client_did, fb_client_seed_hex,
		'0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e', 'acme')
	assert cm4.ftype == 3
	csub := fb_request(mut cc, 50, '[subscribe stream="jobs" group="g8" [pattern :job.*]]')
	assert csub.payload.bytestr().contains('assigned=true'), 'subscribe: ${csub.payload.bytestr()}'
	// the boot's pending-window is 4: entries 1..4 push, the ack frees room
	// for 5 (the log is the buffer — §19.2).
	for i in 1 .. 5 {
		e := fb_read_frame(mut cc, 5 * time.second) or { panic('entry ${i} missing') }
		assert e.payload.bytestr().contains('seq=${i}')
	}
	assert fb_request(mut cc, 51, '[ack sub=${sr_sub_id(csub)} seq=4]').ftype == 3
	e5 := fb_read_frame(mut cc, 5 * time.second) or { panic('entry 5 missing after ack') }
	assert e5.payload.bytestr().contains('seq=5')
	assert fb_request(mut cc, 52, '[ack sub=${sr_sub_id(csub)} seq=5]').ftype == 3

	// an observe-only principal may NOT rotate.
	mut rc, rm4 := fb_attach(port, tmp, 'rot-rogue', fb_rogue_did, fb_rogue_seed_hex,
		'0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f', 'acme')
	assert rm4.ftype == 3
	rr := fb_request(mut rc, 60, "[rotate keep-n=2]")
	assert rr.ftype == 7 && rr.payload.bytestr().contains('CXER4925'), 'ungranted rotate admitted: ${rr.payload.bytestr()}'
	rc.close()

	// the granted rotation: seals at boundary 3, swaps the mount, replies.
	rot := fb_request(mut pubc, 53, '[rotate keep-n=2]')
	assert rot.ftype == 3, 'rotate refused: ${rot.payload.bytestr()}'
	assert rot.payload.bytestr().contains('sealed='), 'rotate reply shape: ${rot.payload.bytestr()}'

	// the chain CONTINUES on the swapped mount and the live subscriber
	// receives from the new hot window.
	p6 := fb_request(mut pubc, 54, '[publish stream="jobs" [event [do :job.r6]]]')
	assert p6.ftype == 3 && p6.payload.bytestr().contains('seq=6'), 'post-rotation publish: ${p6.payload.bytestr()}'
	e6 := fb_read_frame(mut cc, 5 * time.second) or { panic('post-rotation delivery missing') }
	assert e6.payload.bytestr().contains('seq=6'), 'post-rotation delivery: ${e6.payload.bytestr()}'

	// a NEW group subscribing post-rotation resumes from the seam (the hot
	// window is the replay horizon) — and its low committed offset BLOCKS
	// the next rotation until it acks.
	mut bc, bm4 := fb_attach(port, tmp, 'rot-behind', fb_client_did, fb_client_seed_hex,
		'1010101010101010101010101010101010101010101010101010101010101010', 'acme')
	assert bm4.ftype == 3
	bsub := fb_request(mut bc, 55, '[subscribe stream="jobs" group="g9" [pattern :job.*]]')
	assert bsub.payload.bytestr().contains('assigned=true')
	b4 := fb_read_frame(mut bc, 5 * time.second) or { panic('seam replay missing') }
	assert b4.payload.bytestr().contains('seq=4'), 'seam replay starts at boundary+1: ${b4.payload.bytestr()}'
	_ := fb_read_frame(mut bc, 5 * time.second) or { panic('seam replay 5 missing') }
	_ := fb_read_frame(mut bc, 5 * time.second) or { panic('seam replay 6 missing') }
	blocked := fb_request(mut pubc, 56, '[rotate keep-n=1]')
	assert blocked.ftype == 7 && blocked.payload.bytestr().contains('CXER4936'), 'behind group must block rotation: ${blocked.payload.bytestr()}'
	assert blocked.payload.bytestr().contains('g9'), 'the refusal names the group: ${blocked.payload.bytestr()}'

	// after g9 commits, the second rotation goes through.
	assert fb_request(mut bc, 57, '[ack sub=${sr_sub_id(bsub)} seq=6]').ftype == 3
	rot2 := fb_request(mut pubc, 58, '[rotate keep-n=1]')
	assert rot2.ftype == 3, 'second rotation: ${rot2.payload.bytestr()}'

	pubc.close()
	cc.close()
	bc.close()
}

// fb_boot_retention: fb_boot with a [retention …] policy block (#636).
fn fb_boot_retention(lane int, policy string, principals string, retention string) (int, int, string, &os.Process) {
	cxbin := testenv.cx_bin()
	port := fb_pick_port(lane)
	hport := port + 1
	tmp := os.join_path(os.temp_dir(), 'cx-fabric-serve-test-${os.getpid()}-${lane}')
	os.rmdir_all(tmp) or {}
	os.mkdir_all(tmp) or { panic('mkdir ${tmp}: ${err}') }
	cfg := '[fabric-service
  [bind addr="127.0.0.1:${port}"]
  [health addr="127.0.0.1:${hport}"]
  [identity did="${fb_host_did}" seed-env="CX_FABRIC_SEED"]
  ${policy}
  [limits pending-window=64 liveness-ms=30000 request-timeout-ms=5000]
  ${retention}
  [fabrics [fabric name="main" store="file://${tmp}/store" tenant="acme"]]
  ${principals}]'
	cfg_path := fb_write(tmp, 'fabric.service.cx', cfg)
	os.setenv('CX_FABRIC_SEED', fb_host_seed_hex, true)
	mut proc := os.new_process('/bin/sh')
	proc.set_args(['-c',
		'exec "${cxbin}" fabric-serve --config "${cfg_path}" --exit-on-stdin-eof --allow-read --allow-write --allow-net=127.0.0.1:${port} --allow-net=127.0.0.1:${hport} --allow-env >"${tmp}/daemon.log" 2>&1'])
	proc.set_redirect_stdio()
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
		panic('fabric-serve (retention) never came up: ${out}')
	}
	return port, hport, tmp, proc
}

// #636: the retention POLICY drives the #640 rotation mechanism — a stream
// past its hot window is rotated by the sweeper (no operator action), the
// sealed predecessor is archived per policy, and the chain anchor survives
// in the segment index. The live set stays bounded by the window under
// continuous ingest, which is the issue's headline acceptance.
fn test_fabric_serve_retention_policy_rotates_and_archives() {
	arch := os.join_path(os.temp_dir(), 'cx-fabric-archive-${os.getpid()}')
	os.rmdir_all(arch) or {}
	os.mkdir_all(arch) or { panic('mkdir arch: ${err}') }
	defer {
		os.rmdir_all(arch) or {}
	}
	port, _, tmp, mut proc := fb_boot_retention(4, '[policy mode="mutual"]', fb_principals_rotate,
		'[retention sweep-ms=300 [stream name="*" hot=4 archive="file://${arch}"]]')
	defer {
		proc.signal_kill()
		os.unsetenv('CX_FABRIC_SEED')
		os.rmdir_all(tmp) or {}
	}

	mut pubc, pm4 := fb_attach(port, tmp, 'ret-pub', fb_client_did, fb_client_seed_hex,
		'1111111111111111111111111111111111111111111111111111111111111111', 'acme')
	assert pm4.ftype == 3, 'publisher attach: ${pm4.raw.bytestr()}'
	// eight entries: past the hot window of 4, with no consumer group to
	// hold the floor down.
	for i in 1 .. 9 {
		p := fb_request(mut pubc, 70 + i, '[publish stream="jobs" [event [do :job.p${i}]]]')
		assert p.ftype == 3, 'publish ${i}: ${p.payload.bytestr()}'
	}
	// the sweeper rotates on its own — poll the daemon log for the rotation.
	mut rotated := false
	for _ in 0 .. 60 {
		time.sleep(200 * time.millisecond)
		log := os.read_file(os.join_path(tmp, 'daemon.log')) or { '' }
		if log.contains('retention: rotating tenant "acme"') {
			rotated = true
			break
		}
	}
	dlog := os.read_file(os.join_path(tmp, 'daemon.log')) or { '' }
	assert rotated, 'the retention sweeper must rotate a stream past its hot window: ${dlog}'

	// the sealed predecessor is archived per policy (poll: the copy follows
	// the swap).
	mut archived := false
	for _ in 0 .. 40 {
		time.sleep(200 * time.millisecond)
		log := os.read_file(os.join_path(tmp, 'daemon.log')) or { '' }
		if log.contains('retention: archived sealed store') {
			archived = true
			break
		}
	}
	dlog2 := os.read_file(os.join_path(tmp, 'daemon.log')) or { '' }
	assert archived, 'the sealed predecessor must be archived: ${dlog2}'
	assert os.exists(os.join_path(arch, 'acme')), 'the archive namespace must carry the tenant: ${os.ls(arch) or {
		[]
	}}'

	// the mount keeps serving on the new hot store: the chain continues and
	// a fresh subscriber replays only the HOT window (the retention horizon).
	p9 := fb_request(mut pubc, 90, '[publish stream="jobs" [event [do :job.p9]]]')
	assert p9.ftype == 3 && p9.payload.bytestr().contains('seq=9'), 'post-rotation publish: ${p9.payload.bytestr()}'
	mut cc, cm4 := fb_attach(port, tmp, 'ret-con', fb_client_did, fb_client_seed_hex,
		'1212121212121212121212121212121212121212121212121212121212121212', 'acme')
	assert cm4.ftype == 3
	csub := fb_request(mut cc, 91, '[observe stream="jobs" [pattern :job.*]]')
	assert csub.ftype == 3, 'observe: ${csub.payload.bytestr()}'
	first := fb_read_frame(mut cc, 5 * time.second) or { panic('no replay after rotation') }
	fb := first.payload.bytestr()
	assert !fb.contains('seq=1 '), 'the retention horizon must exclude sealed history: ${fb}'

	pubc.close()
	cc.close()
}

// #636: a stream under LEGAL HOLD suspends rotation — the sweeper refuses to
// seal (and says so) rather than archiving or truncating held history.
fn test_fabric_serve_retention_legal_hold_suspends_rotation() {
	port, _, tmp, mut proc := fb_boot_retention(5, '[policy mode="mutual"]', fb_principals_rotate,
		'[retention sweep-ms=300 [stream name="*" hot=3 archive="none"] [stream name="ledger" hot=3 hold=true]]')
	defer {
		proc.signal_kill()
		os.unsetenv('CX_FABRIC_SEED')
		os.rmdir_all(tmp) or {}
	}
	mut pubc, pm4 := fb_attach(port, tmp, 'hold-pub', fb_client_did, fb_client_seed_hex,
		'1313131313131313131313131313131313131313131313131313131313131313', 'acme')
	assert pm4.ftype == 3
	for i in 1 .. 7 {
		p := fb_request(mut pubc, 100 + i, '[publish stream="jobs" [event [do :job.h${i}]]]')
		assert p.ftype == 3, 'publish ${i}: ${p.payload.bytestr()}'
	}
	// the hold suspends the sweep: no rotation, and the reason is logged.
	mut suspended := false
	for _ in 0 .. 40 {
		time.sleep(200 * time.millisecond)
		log := os.read_file(os.join_path(tmp, 'daemon.log')) or { '' }
		if log.contains('legal hold') {
			suspended = true
			break
		}
	}
	dlog := os.read_file(os.join_path(tmp, 'daemon.log')) or { '' }
	assert suspended, 'a legal hold must suspend the retention sweep loudly: ${dlog}'
	assert !dlog.contains('retention: rotating tenant'), 'nothing may rotate under a hold: ${dlog}'
	pubc.close()
}
