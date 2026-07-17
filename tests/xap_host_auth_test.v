module main

import os
import testenv
import time
import net
import net.http

// xap_host_auth_test.v — BEHAVIORAL proof of the identity model's §4.12
// deployment-host auth binding (issue #394): a deployment document carrying
// an [auth] block turns [$xap:host] into the XSP-AUTH responder — attach
// rides POST /attach as stream-0 frames, every other request carries the
// §4.8 rule-2 possession-proof headers, and the committing actor is the
// channel's session principal (claimed author=/role= demoted to checked
// labels). The auth-OFF regression (byte-identical behavior without the
// block) is xap_host_real_test.v, which this file deliberately mirrors.
//
// All client-side calculus runs through the REAL cx binary (the same
// $xsp:auth-* surface the web client uses), with the RFC 7748/8032 fixture
// vectors — offline and deterministic. The server side generates its
// nonce/ephemeral fresh per handshake, so every lane exercises a live
// handshake, not a recording.
//
// Lanes (mutual policy):
//   unauthenticated GET /grammar            → 401 CXER-XSP-AUTH-PROOF
//   [public] route /whoami                  → 200 without a channel
//   POST /attach M1 → M2; M3 → M4           → established (auth-finish verifies)
//   POST /intent (proof, counter=1)         → ok=true, actor = the proven DID
//   replayed counter                        → 401 CXER-XSP-AUTH-PROOF
//   tampered proof                          → 401 CXER-XSP-AUTH-PROOF
//   claimed author= ≠ session principal     → 403 CXER-XSP-AUTH-PRINCIPAL-MISMATCH
//   claimed role= on a proven channel       → ignored (the DID's dials decide)
//   unmapped-DID attach                     → attaches, but every intent PEP-denied
//   anonymous M1/M3 under require-mutual    → 403 CXER-XSP-AUTH-ANONYMOUS-REFUSED
//   GET /stream with proof                  → SSE prelude under the channel
// Lanes (floor policy, second boot):
//   anonymous attach → floor principal      → read-door ok (role grant), unlock denied

const xa_host_did = 'did:key:z6MkiaMbhXHNA4eJVCCj8dbzKzTgYDKf6crKgHVHid1F1WCT' // RFC 8032 TEST 2
const xa_host_seed_hex = '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'
const xa_client_did = 'did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw' // RFC 8032 TEST 1
const xa_client_seed_hex = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
const xa_rogue_did = 'did:key:z6MkwSD8dBdqcXQzKJZQFPy2hh2izzxskndKCjdmC2dBpfME' // RFC 8032 TEST 3
const xa_rogue_seed_hex = 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7'
const xa_eph_priv_hex = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a' // RFC 7748 alice
const xa_eph_pub_hex = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'

fn xa_cx_binary() string {
	return testenv.cx_bin()
}

// Disjoint port band (26900-26999) from http (26400) / xap-host (26800).
fn xa_pick_port(lane int) int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 40
	return 26900 + lane * 50 + int(salt)
}

fn xa_write(dir string, name string, content string) string {
	p := os.join_path(dir, name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

fn xa_run_cx(args string, prog string) string {
	res := os.execute('${xa_cx_binary()} ${args} ${prog}')
	if res.exit_code != 0 {
		panic('cx helper failed (${res.exit_code}): ${res.output}')
	}
	return res.output.trim_space().trim("'")
}

// the same toy door feature the auth-off host test boots.
const xa_door_spec = "[feature name=door version=1.0.0
 [nouns [noun name=door singular=true [field name=locked type=int]]]
 [verbs
  [verb name=read-door effect=observe scope=local consequence=none [intent [do :read-door]] [reads door]]
  [verb name=unlock effect=act scope=shared consequence=reversible [intent [do :unlock]] [writes door]]]
 [governance [grant verb=read-door to=any] [grant verb=unlock to=resident]]
 [requirements
  [requirement kind=functional as=resident traces=read-door [want 'to see the door'] [so 'I know its state']]
  [requirement kind=functional as=resident traces=unlock [want 'to unlock the door'] [so 'guests can enter']]]]"

const xa_door_code = "[?lib 'cx-stdlib/store' :as store]
[?def readout scope=public impure (\$store \$t)
  [?let [= \$h [\$store:get-alias \$store 'door-count']]
   [= \$n [?else [\$store:get-doc \$store \$h] '0']]
   [?element 'readout' [?attr 'feature' 'door'] [?attr 'unlocks' [\$concat '' \$n]]]]]
[?def apply scope=public impure (\$verb \$intent \$store)
  [?let [= \$h [?else [\$store:get-alias \$store 'door-count'] '']]
   [= \$n [?if [= \$h ''] [then 0] [else [\$cast [\$concat '' [\$store:get-doc \$store \$h]] 'int']]]]
   [= \$nh [\$store:put-doc \$store [\$concat '' [+ \$n 1]]]]
   [= \$a [\$store:set-alias \$store 'door-count' \$nh]]
   \$verb]]"

fn xa_publish_prog(reg_dir string) string {
	return "[?lib 'cx-xap' :as xap]\n[?lib 'cx-stdlib/store' :as store]\n" +
		"[?lib 'cx-stdlib/crypto' :as crypto]\n[?lib 'cx-stdlib/did' :as did]\n" +
		"[?lib 'cx-stdlib/io' :as io]\n" +
		'[?let [= \$s [\$store:open "file://${reg_dir}"]]\n' +
		'[?let [= \$kp [\$crypto:ed25519-keypair]]\n' +
		'[?let [= \$pub [\$did:key-create \$kp@public]]\n' +
		'[?let [= \$dspec [\$io:read-file "${reg_dir}/../door.feature.cxd"]]\n' +
		'[?let [= \$dcode [\$io:read-file "${reg_dir}/../door.cx"]]\n' +
		'[?let [= \$t1 [\$xap:pkg-tree ([?element "entry" [?attr "path" "door.feature.cxd"] \$dspec], [?element "entry" [?attr "path" "door.cx"] \$dcode])]]\n' +
		'[?let [= \$d1 [?element "package" [?attr "name" "door"] [?attr "version" "1.0.0"] [?attr "kind" "feature"]\n' +
		'               [?element "publisher" [?attr "did" \$pub]]\n' +
		'               [?element "exports" [?element "def" [?attr "name" "door/readout"]] [?element "def" [?attr "name" "door/apply"]]]]]\n' +
		'[?let [= \$s1 [\$xap:pkg-seal \$s \$t1 \$d1]]\n' +
		'[?let [= \$m1 [\$store:put-doc \$s [\$xap:pkg-sign [\$store:get-doc \$s \$s1@manifest] \$kp@private]]]\n' +
		'[?let [= \$p1 [\$xap:pkg-publish \$s "door" "1.0.0" \$m1]]\n' +
		'[\$concat \$m1 " " \$s1@hash]]]]]]]]]]]\n'
}

fn xa_host_prog(port int, xap_path string) string {
	return "[?lib 'cx-xap' :as xap]\n[?lib 'cx-stdlib/store' :as store]\n" +
		"[?lib 'cx-stdlib/io' :as io]\n" +
		'[?let [= \$xdoc [\$cx:parse [\$io:read-file "${xap_path}"]]]\n' +
		'[?let [= \$x [\$first [?for [in \$e \$xdoc//xap] [yield \$e]]]]\n' +
		'[?let [= \$ws [\$store:open "mem://"]]\n' +
		'[\$xap:host \$x {url: "http://127.0.0.1:${port}" store: \$ws\n' +
		'  routes: {whoami: [?fn (\$req) [response status=200 [headers [header name="content-type" value="text/plain"]] [body "toy-xap"]]]}}]]]]\n'
}

// ── client-side calculus helpers (the same $xsp:auth-* surface the web
//    client uses; vectors injected, server values read off the wire) ─────────

const xa_vec_prelude = "[?lib 'cx-stdlib/xsp' :as xsp]\n[?lib 'cx-stdlib/bytes' :as bytes]\n" +
	"[?lib 'cx-stdlib/io' :as io]\n[?lib 'cx-stdlib/strings' :as str]\n"

// prints base64(frame(M1)). did='' → anonymous hello.
fn xa_m1_prog(endpoint string, did string, nonce_hex string) string {
	did_field := if did == '' { '' } else { 'did: "${did}", ' }
	return xa_vec_prelude +
		'[?let [= \$m1 [\$xsp:auth-hello {${did_field}nonce: [\$bytes:from-hex "${nonce_hex}"], eph: [\$bytes:from-hex "${xa_eph_pub_hex}"], endpoint: "${endpoint}"}]]\n' +
		'[\$bytes:to-base64 [\$xsp:encode [frame type=request stream=0 [payload \$m1]]]]]\n'
}

// reads base64(frame(M2)) from m2_path; prints `chan-hex|proofkey-hex|base64(frame(M3))`.
// seed_hex='' → anonymous prove (no sig).
fn xa_m3_prog(m2_path string, endpoint string, did string, seed_hex string, nonce_hex string, tenant string) string {
	did_field := if did == '' { '' } else { 'did: "${did}", ' }
	key_field := if seed_hex == '' { '' } else { 'key: [\$bytes:from-hex "${seed_hex}"], ' }
	return xa_vec_prelude +
		'[?let\n' +
		'  [= \$m1 [\$xsp:auth-hello {${did_field}nonce: [\$bytes:from-hex "${nonce_hex}"], eph: [\$bytes:from-hex "${xa_eph_pub_hex}"], endpoint: "${endpoint}"}]]\n' +
		'  [= \$d2 [\$xsp:decode [\$bytes:from-base64 [\$str:trim [\$io:read-file "${m2_path}"]]]]]\n' +
		'  [= \$m2 \$d2/payload]\n' +
		'  [= \$m3 [\$xsp:auth-prove \$m1 \$m2 {eph-priv: [\$bytes:from-hex "${xa_eph_priv_hex}"], ${key_field}attach: [attach [tenant "${tenant}"] [session mirror]]}]]\n' +
		'  [= \$ks [\$xsp:auth-keys [\$bytes:from-hex "${xa_eph_priv_hex}"] \$m2/@eph [\$bytes:from-hex "${nonce_hex}"] \$m2/@nonce]]\n' +
		'  [\$concat [\$bytes:to-hex [\$first \$ks/chan-id]] "|" [\$bytes:to-hex [\$first \$ks/proof-i]] "|" [\$bytes:to-base64 [\$xsp:encode [frame type=request stream=0 [payload \$m3]]]]]]\n'
}

// reads base64(frame(M2)) + base64(frame(M4)); prints `<responder-did>|<chan-id>`
// from auth-finish — the client-side proof the handshake established.
fn xa_finish_prog(m2_path string, m4_path string, endpoint string, did string, nonce_hex string) string {
	did_field := if did == '' { '' } else { 'did: "${did}", ' }
	return xa_vec_prelude +
		'[?let\n' +
		'  [= \$m1 [\$xsp:auth-hello {${did_field}nonce: [\$bytes:from-hex "${nonce_hex}"], eph: [\$bytes:from-hex "${xa_eph_pub_hex}"], endpoint: "${endpoint}"}]]\n' +
		'  [= \$d2 [\$xsp:decode [\$bytes:from-base64 [\$str:trim [\$io:read-file "${m2_path}"]]]]]\n' +
		'  [= \$m2 \$d2/payload]\n' +
		'  [= \$d4 [\$xsp:decode [\$bytes:from-base64 [\$str:trim [\$io:read-file "${m4_path}"]]]]]\n' +
		'  [= \$m4 \$d4/payload]\n' +
		'  [= \$done [\$xsp:auth-finish \$m1 \$m2 \$m4 {eph-priv: [\$bytes:from-hex "${xa_eph_priv_hex}"]}]]\n' +
		'  [\$concat [\$text \$done/@responder] "|" [\$text \$done/@chan-id]]]\n'
}

// prints base64(proof) over `body` for `counter` with the channel's proof key.
fn xa_proof_prog(key_hex string, counter int, body string) string {
	body_lit := body.replace('\\', '\\\\').replace("'", "\\'")
	return xa_vec_prelude +
		"[\$bytes:to-base64 [\$xsp:auth-proof [\$bytes:from-hex \"${key_hex}\"] ${counter} [\$bytes:from-string-utf8 '${body_lit}']]]\n"
}

// ── HTTP glue ────────────────────────────────────────────────────────────────

struct XaResp {
	status int
	body   string
}

fn xa_get(port int, path string, hdrs map[string]string) XaResp {
	mut cfg := http.FetchConfig{
		url:    'http://127.0.0.1:${port}${path}'
		method: .get
	}
	cfg.header = http.new_custom_header_from_map(hdrs) or { panic('hdrs: ${err}') }
	resp := http.fetch(cfg) or { return XaResp{0, 'GET-FAILED: ${err}'} }
	return XaResp{resp.status_code, resp.body}
}

fn xa_post(port int, path string, body string, hdrs map[string]string) XaResp {
	mut cfg := http.FetchConfig{
		url:    'http://127.0.0.1:${port}${path}'
		method: .post
		data:   body
	}
	cfg.header = http.new_custom_header_from_map(hdrs) or { panic('hdrs: ${err}') }
	resp := http.fetch(cfg) or { return XaResp{0, 'POST-FAILED: ${err}'} }
	return XaResp{resp.status_code, resp.body}
}

fn xa_proof_hdrs(ch string, counter int, proof string) map[string]string {
	return {
		'XSP-Channel': ch
		'XSP-Counter': counter.str()
		'XSP-Proof':   proof
	}
}

// one attach round: M1 → M2 → M3 → M4. Returns (chan-hex, proofkey-hex, m4-resp).
fn xa_attach(port int, tmp string, tag string, did string, seed_hex string, nonce_hex string, tenant string) (string, string, XaResp) {
	endpoint := 'http://127.0.0.1:${port}'
	m1_prog := xa_write(tmp, 'm1-${tag}.cx', xa_m1_prog(endpoint, did, nonce_hex))
	m1_b64 := xa_run_cx('', m1_prog)
	r2 := xa_post(port, '/attach', m1_b64, {})
	if r2.status != 200 {
		return '', '', r2
	}
	m2_path := xa_write(tmp, 'm2-${tag}.b64', r2.body)
	m3_prog := xa_write(tmp, 'm3-${tag}.cx', xa_m3_prog(m2_path, endpoint, did, seed_hex,
		nonce_hex, tenant))
	out := xa_run_cx('--allow-read', m3_prog)
	parts := out.split('|')
	if parts.len != 3 {
		panic('m3 helper output: ${out}')
	}
	chan_hex, key_hex, m3_b64 := parts[0], parts[1], parts[2]
	r4 := xa_post(port, '/attach', m3_b64, {
		'XSP-Channel': chan_hex
	})
	return chan_hex, key_hex, r4
}

// boot a host subprocess over a fresh registry+deployment; returns (port, tmp, proc).
fn xa_boot(lane int, auth_block string) (int, string, &os.Process) {
	cxbin := xa_cx_binary()
	port := xa_pick_port(lane)
	tmp := os.join_path(os.temp_dir(), 'cx-xap-host-auth-test-${os.getpid()}-${lane}')
	os.rmdir_all(tmp) or {}
	os.mkdir_all(tmp) or { panic('mkdir ${tmp}: ${err}') }
	reg := os.join_path(tmp, 'registry')
	os.mkdir_all(reg) or { panic('mkdir ${reg}: ${err}') }
	xa_write(tmp, 'door.feature.cxd', xa_door_spec)
	xa_write(tmp, 'door.cx', xa_door_code)
	pub_prog := xa_write(tmp, 'publish.cx', xa_publish_prog(reg))
	pres := os.execute('${cxbin} --allow-read --allow-write --allow-random ${pub_prog}')
	if pres.exit_code != 0 {
		panic('publish failed (${pres.exit_code}): ${pres.output}')
	}
	parts := pres.output.trim_space().trim("'").split(' ')
	if parts.len != 2 {
		panic('unexpected publish output: ${pres.output}')
	}
	door_m, door_t := parts[0], parts[1]
	xap_doc := '[xap name=authtoy
  [roles [role name=resident rank=1] [role name=guest rank=0]]
  [features
    [feature name=door version=1.0.0 manifest=${door_m} hash=${door_t}]]
  ${auth_block}]'
	xap_path := xa_write(tmp, 'authtoy.xap.cxd', xap_doc)
	host_prog := xa_write(tmp, 'host.cx', xa_host_prog(port, xap_path))
	os.setenv('CX_REGISTRY', 'file://${reg}', true)
	os.setenv('CX_XAP_HOST_SEED', xa_host_seed_hex, true)
	mut proc := os.new_process(cxbin)
	proc.set_args(['--allow-read', '--allow-write', '--allow-net=127.0.0.1:${port}',
		'--allow-env', host_prog])
	proc.set_redirect_stdio()
	proc.run()
	// wait for the listener: the [public]-less auth host still serves /attach,
	// so probe readiness with a bare GET and accept any HTTP answer.
	mut up := false
	for _ in 0 .. 100 {
		time.sleep(100 * time.millisecond)
		r := xa_get(port, '/grammar', {})
		if r.status != 0 {
			up = true
			break
		}
	}
	if !up {
		out := proc.stdout_slurp() + proc.stderr_slurp()
		proc.signal_kill()
		panic('auth host never came up: ${out}')
	}
	return port, tmp, proc
}

const xa_auth_mutual = '[host-auth
    [identity did="${xa_host_did}" seed-env="CX_XAP_HOST_SEED"]
    [policy mode="mutual"]
    [principals [principal did="${xa_client_did}" role="resident"]]
    [public [route "/"] [route "/whoami"]]]'

const xa_auth_floor = '[host-auth
    [identity did="${xa_host_did}" seed-env="CX_XAP_HOST_SEED"]
    [policy mode="floor" floor="dev" role="guest"]
    [public [route "/whoami"]]]'

fn test_xap_host_auth_mutual_attach_proofs_and_proven_actor() {
	port, tmp, mut proc := xa_boot(0, xa_auth_mutual)
	defer {
		proc.signal_kill()
		os.unsetenv('CX_REGISTRY')
		os.unsetenv('CX_XAP_HOST_SEED')
		os.rmdir_all(tmp) or {}
	}
	endpoint := 'http://127.0.0.1:${port}'

	// unauthenticated standard surface → 401, fail-closed.
	g := xa_get(port, '/grammar', {})
	assert g.status == 401, 'unauthenticated /grammar admitted: ${g.status} ${g.body}'
	assert g.body.contains('CXER-XSP-AUTH-PROOF'), 'missing proof error: ${g.body}'
	i0 := xa_post(port, '/intent', '[intent verb="unlock"]', {})
	assert i0.status == 401, 'unauthenticated intent admitted: ${i0.status} ${i0.body}'
	s0 := xa_get(port, '/stream', {})
	assert s0.status == 401, 'unauthenticated stream admitted: ${s0.status}'

	// [public] route serves without a channel.
	who := xa_get(port, '/whoami', {})
	assert who.status == 200 && who.body.contains('toy-xap'), 'public route: ${who.status} ${who.body}'

	// a bare '/' public route is EXACT, never a prefix — /grammar stays gated
	// even though '/' is public (regression: a '/'-as-prefix rule made every
	// path public, caught at the marine live-boot). '/' itself is public here,
	// so it reaches the host and 404s (the toy host has no root route) rather
	// than 401ing — proving the gate let it through.
	gg := xa_get(port, '/grammar', {})
	assert gg.status == 401, 'root-public leaked /grammar past the gate: ${gg.status}'
	rootr := xa_get(port, '/', {})
	assert rootr.status == 404, 'bare-/ public route did not reach the host: ${rootr.status}'

	// attach: M1 → M2 → M3 → M4, verified client-side by auth-finish.
	chan_hex, key_hex, r4 := xa_attach(port, tmp, 'main', xa_client_did, xa_client_seed_hex,
		'0101010101010101010101010101010101010101010101010101010101010101', 'authtoy')
	assert r4.status == 200, 'attach M3 failed: ${r4.status} ${r4.body}'
	m4_path := xa_write(tmp, 'm4-main.b64', r4.body)
	m2_path := os.join_path(tmp, 'm2-main.b64')
	fin_prog := xa_write(tmp, 'finish-main.cx', xa_finish_prog(m2_path, m4_path, endpoint,
		xa_client_did, '0101010101010101010101010101010101010101010101010101010101010101'))
	fin := xa_run_cx('--allow-read', fin_prog).split('|')
	assert fin.len == 2 && fin[0] == xa_host_did, 'auth-finish responder: ${fin}'
	assert fin[1] == chan_hex, 'chan-id mismatch: ${fin[1]} vs ${chan_hex}'

	// proven intent: counter=1, no author claim → actor = the session principal.
	body1 := '[intent verb="unlock"]'
	p1_prog := xa_write(tmp, 'p1.cx', xa_proof_prog(key_hex, 1, body1))
	p1 := xa_run_cx('', p1_prog)
	a1 := xa_post(port, '/intent', body1, xa_proof_hdrs(chan_hex, 1, p1))
	assert a1.status == 200 && a1.body.contains('ok=true'), 'proven unlock refused: ${a1.status} ${a1.body}'
	assert a1.body.contains(xa_client_did), 'ack actor is not the proven DID: ${a1.body}'

	// the proof-bound readout: counter=2 over the empty GET body.
	p2_prog := xa_write(tmp, 'p2.cx', xa_proof_prog(key_hex, 2, ''))
	p2 := xa_run_cx('', p2_prog)
	ro := xa_get(port, '/surface/door', xa_proof_hdrs(chan_hex, 2, p2))
	assert ro.status == 200 && (ro.body.contains("'1'") || ro.body.contains('unlocks=1')), 'authed readout: ${ro.status} ${ro.body}'

	// replay: counter=2 again with the same valid proof → refused, state intact.
	rp := xa_get(port, '/surface/door', xa_proof_hdrs(chan_hex, 2, p2))
	assert rp.status == 401 && rp.body.contains('CXER-XSP-AUTH-PROOF'), 'replayed counter admitted: ${rp.status} ${rp.body}'

	// tampered proof at a fresh counter → refused.
	bad := xa_get(port, '/surface/door', xa_proof_hdrs(chan_hex, 3, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='))
	assert bad.status == 401 && bad.body.contains('CXER-XSP-AUTH-PROOF'), 'tampered proof admitted: ${bad.status}'

	// claimed author ≠ session principal → the §4.8 principal-mismatch refusal.
	body3 := '[intent verb="unlock" author="${xa_rogue_did}"]'
	p3_prog := xa_write(tmp, 'p3.cx', xa_proof_prog(key_hex, 3, body3))
	p3 := xa_run_cx('', p3_prog)
	mm := xa_post(port, '/intent', body3, xa_proof_hdrs(chan_hex, 3, p3))
	assert mm.status == 403 && mm.body.contains('CXER-XSP-AUTH-PRINCIPAL-MISMATCH'), 'claimed author admitted: ${mm.status} ${mm.body}'

	// claimed role= is ignored on a proven channel: the DID's dials decide.
	body4 := '[intent verb="unlock" role="guest"]'
	p4_prog := xa_write(tmp, 'p4.cx', xa_proof_prog(key_hex, 4, body4))
	p4 := xa_run_cx('', p4_prog)
	a4 := xa_post(port, '/intent', body4, xa_proof_hdrs(chan_hex, 4, p4))
	assert a4.status == 200 && a4.body.contains('ok=true'), 'proven channel denied by claimed role: ${a4.body}'
	assert a4.body.contains(xa_client_did), 'actor should stay the proven DID: ${a4.body}'

	// SSE: the subscription GET carries the same proof and binds the downstream.
	p5_prog := xa_write(tmp, 'p5.cx', xa_proof_prog(key_hex, 5, ''))
	p5 := xa_run_cx('', p5_prog)
	mut conn := net.dial_tcp('127.0.0.1:${port}') or { panic('sse dial: ${err}') }
	conn.set_read_timeout(5 * time.second)
	conn.write_string('GET /stream HTTP/1.1\r\nHost: t\r\nXSP-Channel: ${chan_hex}\r\nXSP-Counter: 5\r\nXSP-Proof: ${p5}\r\n\r\n') or {
		panic('sse write: ${err}')
	}
	mut buf := []u8{len: 512}
	n := conn.read(mut buf) or { 0 }
	conn.close() or {}
	prelude := buf[..n].bytestr()
	assert prelude.contains('200'), 'sse subscription refused: ${prelude}'

	// an authenticated-but-unmapped DID: the session binds, authority is empty.
	rchan, rkey, rr4 := xa_attach(port, tmp, 'rogue', xa_rogue_did, xa_rogue_seed_hex,
		'0303030303030303030303030303030303030303030303030303030303030303', 'authtoy')
	assert rr4.status == 200, 'unmapped-DID attach failed: ${rr4.status} ${rr4.body}'
	rbody := '[intent verb="read-door"]'
	rp_prog := xa_write(tmp, 'p6.cx', xa_proof_prog(rkey, 1, rbody))
	rproof := xa_run_cx('', rp_prog)
	ra := xa_post(port, '/intent', rbody, xa_proof_hdrs(rchan, 1, rproof))
	assert ra.status == 200 && ra.body.contains('ok=false'), 'unmapped DID admitted: ${ra.body}'

	// anonymous under require-mutual: M1→M2 proceeds, M3 is refused.
	_, _, ar4 := xa_attach(port, tmp, 'anon', '', '',
		'0404040404040404040404040404040404040404040404040404040404040404', 'authtoy')
	assert ar4.status == 403, 'anonymous attach admitted under mutual: ${ar4.status} ${ar4.body}'
	assert ar4.body.contains('CXER-XSP-AUTH-ANONYMOUS-REFUSED'), 'wrong anon refusal: ${ar4.body}'

	// auth-off wire shape is untouched: /attach exists ONLY under [auth]
	// (xap_host_real_test.v is the full byte-identical regression lane).
}

fn test_xap_host_auth_floor_policy_anonymous_floor() {
	port, tmp, mut proc := xa_boot(1, xa_auth_floor)
	defer {
		proc.signal_kill()
		os.unsetenv('CX_REGISTRY')
		os.unsetenv('CX_XAP_HOST_SEED')
		os.rmdir_all(tmp) or {}
	}
	// anonymous attach lands on the floor principal.
	chan_hex, key_hex, r4 := xa_attach(port, tmp, 'floor', '', '',
		'0505050505050505050505050505050505050505050505050505050505050505', 'authtoy')
	assert r4.status == 200, 'anonymous floor attach failed: ${r4.status} ${r4.body}'

	// the floor principal holds the mapped role's grants: read-door (to=any) admits…
	body1 := '[intent verb="read-door"]'
	p1_prog := xa_write(tmp, 'fp1.cx', xa_proof_prog(key_hex, 1, body1))
	p1 := xa_run_cx('', p1_prog)
	a1 := xa_post(port, '/intent', body1, xa_proof_hdrs(chan_hex, 1, p1))
	assert a1.status == 200 && a1.body.contains('ok=true'), 'floor read-door refused: ${a1.body}'
	assert a1.body.contains('floor:dev'), 'floor actor attribution: ${a1.body}'

	// …and unlock (to=resident, above the floor role) stays denied.
	body2 := '[intent verb="unlock"]'
	p2_prog := xa_write(tmp, 'fp2.cx', xa_proof_prog(key_hex, 2, body2))
	p2 := xa_run_cx('', p2_prog)
	a2 := xa_post(port, '/intent', body2, xa_proof_hdrs(chan_hex, 2, p2))
	assert a2.status == 200 && a2.body.contains('ok=false'), 'floor unlock admitted: ${a2.body}'
}
