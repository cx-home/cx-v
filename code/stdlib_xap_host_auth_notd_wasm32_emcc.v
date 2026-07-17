module code

// stdlib_xap_host_auth_notd_wasm32_emcc.v — the deployment host's auth layer
// (identity model §4.12, issue #394): an [host-auth] block in the deployment
// document turns [$xap:host] into the XSP-AUTH responder.
//
//   [host-auth
//     [identity did="did:key:…" seed-env="CX_XAP_HOST_SEED"]
//     [policy mode="mutual"]                 ; or mode="floor" floor="dev" role="guest"
//     [principals [principal did="…" role="helm"]*]
//     [public [route "/"] [route "/static/"]*]]
//
// Absent block ⇒ the host behaves byte-for-byte as before (the xap.md §22.1
// dev-floor — the N-IMPL-1 one-seam promise). Present ⇒
//   POST /attach carries the XSP-AUTH M1–M4 handshake as stream-0 frames
//   (base64 of the XSP v1 encoding — the same codec the envelope=xsp intent
//   path speaks), terminating in [$session:attach-xsp];
//   every non-[public] request must carry XSP-Channel/-Counter/-Proof and
//   verify against the handshake-derived k_proof_i (§4.8 rule 2, strict
//   counter monotonicity, atomic verify-and-advance);
//   the committing actor of an admitted intent is the channel's session
//   principal via [$xsp:auth-frame-check] — claimed author=/role= demoted to
//   checked labels, the resolve-actor adapter hook not consulted.
//
// No new trust primitive: everything here composes the shipped xsp-auth
// calculus + session attach; the PEP stays the single enforcement point.
// Compiles only on the native build, like the host it extends.

import cx
import os
import sync
import time
import crypto.ed25519
import encoding.base64
import encoding.hex

// one handshake awaiting its M3, keyed by chan-id (§4.5 — the
// non-connection locator; both sides can derive it after M1/M2).
struct XapHostAuthPend {
	m1        cx.Element
	m2        cx.Element
	eph_priv  []u8
	proof_key []u8
	created   i64
}

// one established channel: the §4.8 rule-2 verification state.
struct XapHostAuthChan {
mut:
	proof_key []u8
	counter   u64 // high-water; a request must carry counter > this
	principal string
	session   string
}

const xap_host_auth_pend_ttl = i64(60) // seconds; expired handshakes re-run
const xap_host_auth_pend_cap = 64

@[heap]
struct XapHostAuth {
mut:
	did     string   // the host's responder DID (offline-resolvable, v1)
	seed    []u8     // its Ed25519 seed (from the [identity] seed-env)
	mutual  bool     // policy mode=mutual (anonymous M3 refused)
	floor   string   // policy mode=floor: 'floor:<name>' — the anonymous principal
	tenant  string   // the deployment tenant every attach binds to
	public  []string // [public] routes served without a channel ('/x/' = prefix)
	mu      &sync.Mutex
	pending map[string]XapHostAuthPend
	chans   map[string]XapHostAuthChan
}

// the outcome of the per-request gate: pass with the channel's principal, or
// the wire refusal to send.
struct XapAuthAdmit {
	ok        bool
	resp      WireResp
	principal string
}

// ── boot: parse + fail-closed identity check + authority wiring ─────────────

// xap_host_auth_build parses a PRESENT [host-auth] block (the caller checks
// presence — absent means auth off, today's behavior verbatim). Any defect is
// a boot refusal (error), never a latent runtime denial.
fn xap_host_auth_build(ab cx.Element, tenant string) !&XapHostAuth {
	ident := xap_gc_child(ab, 'identity') or {
		return error('[host-auth] needs [identity did=… seed-env=…] — there is no anonymous responder (N-IDENT-2)')
	}
	did := xap_elem_attr(ident, 'did')
	seed_env := xap_elem_attr(ident, 'seed-env')
	if did == '' || seed_env == '' {
		return error('[host-auth identity] needs both did= and seed-env=')
	}
	seed_hex := os.getenv(seed_env)
	if seed_hex == '' {
		return error('[host-auth identity] seed-env "${seed_env}" is unset')
	}
	seed := hex.decode(seed_hex) or {
		return error('[host-auth identity] seed-env "${seed_env}" is not hex: ${err.msg()}')
	}
	if seed.len != 32 {
		return error('[host-auth identity] seed must be a 32-byte Ed25519 seed (got ${seed.len} bytes)')
	}
	// the seed must re-derive the declared DID — a wrong env var refuses boot.
	declared := did_key_bytes(did) or {
		return error('[host-auth identity] did "${did}" is not offline-resolvable (did:key/did:peer:0 in v1)')
	}
	priv := ed25519.new_key_from_seed(seed)
	derived := []u8(priv.public_key())
	if !xsp_auth_ct_eq(declared, derived) {
		return error('[host-auth identity] seed-env "${seed_env}" does not derive did "${did}"')
	}
	mut auth := &XapHostAuth{
		did:    did
		seed:   seed
		mutual: true
		tenant: tenant
		mu:     sync.new_mutex()
	}
	if pol := xap_gc_child(ab, 'policy') {
		mode := xap_elem_attr(pol, 'mode')
		match mode {
			'', 'mutual' {}
			'floor' {
				fname := xap_elem_attr(pol, 'floor')
				frole := xap_elem_attr(pol, 'role')
				if fname == '' || frole == '' {
					return error('[host-auth policy mode=floor] needs floor= and role=')
				}
				auth.mutual = false
				// host-constructed prefix: never a bare name, so the floor can
				// never collide with the PEP's inherent-authority `principal:` kind.
				auth.floor = 'floor:${fname}'
			}
			else {
				return error('[host-auth policy] unknown mode "${mode}" (mutual|floor)')
			}
		}
	}
	if pb := xap_gc_child(ab, 'public') {
		for r in xap_gc_children(pb, 'route') {
			p := xd_text_content(r).trim_space()
			if p != '' {
				auth.public << p
			}
		}
	}
	return auth
}

// xap_host_auth_wire compiles the [host-auth] authority map into runtime dials,
// mirroring xap_host_wire_dials: every [governance] grant that reaches a
// mapped principal's role= is dialed to the DID itself (the actor id IS the
// DID; its `did:` kind keeps it PEP-checked, never `principal:` inherent
// authority). The floor principal is wired the same way through its role.
fn xap_host_auth_wire(rt cx.Node, xdoc cx.Element, specs []cx.Node, auth &XapHostAuth) ! {
	ab := xap_gc_child(xdoc, 'host-auth') or { return }
	mut role_rank := map[string]f64{}
	for container in ['roles', 'principals'] {
		if rl := xap_gc_child(xdoc, container) {
			for r in xap_gc_children(rl, 'role') {
				rn := xap_elem_attr(r, 'name')
				if rn == '' || rn in role_rank {
					continue
				}
				role_rank[rn] = xap_elem_attr(r, 'rank').f64()
			}
		}
	}
	// actor id → its granted role, from [principals] rows + the floor policy.
	mut actor_role := map[string]string{}
	if ps := xap_gc_child(ab, 'principals') {
		for p in xap_gc_children(ps, 'principal') {
			pdid := xap_elem_attr(p, 'did')
			prole := xap_elem_attr(p, 'role')
			if pdid == '' || prole == '' {
				return error('[host-auth principals] rows need did= and role=')
			}
			if prole !in role_rank {
				return error('[host-auth principals] role "${prole}" is not in the deployment ladder')
			}
			actor_role[pdid] = prole
		}
	}
	if auth.floor != '' {
		if pol := xap_gc_child(ab, 'policy') {
			frole := xap_elem_attr(pol, 'role')
			if frole !in role_rank {
				return error('[host-auth policy mode=floor] role "${frole}" is not in the deployment ladder')
			}
			actor_role[auth.floor] = frole
		}
	}
	for sn in specs {
		if sn !is cx.Element {
			continue
		}
		spec := sn as cx.Element
		fname := xap_elem_attr(spec, 'name')
		gov := xap_gc_child(spec, 'governance') or { continue }
		for g in xap_gc_children(gov, 'grant') {
			verb := xap_elem_attr(g, 'verb')
			to := xap_elem_attr(g, 'to')
			if verb == '' {
				continue
			}
			need := if to == 'any' { -1.0 } else { role_rank[to] or { 1e18 } }
			for aid, arole in actor_role {
				rank := role_rank[arole] or { 0.0 }
				if to == 'any' || rank >= need {
					xap_host_dial(rt, 'principal:vessel', aid, '${fname}/${verb}')
				}
			}
		}
	}
}

// ── the wire: frame codec glue ───────────────────────────────────────────────

// xap_host_auth_decode_msg unwraps a base64 stream-0 frame body into the
// xsp-auth payload element (xsp.md §4.1 — base64 for the text-only path).
fn xap_host_auth_decode_msg(raw_body string) ?cx.Element {
	bytes := base64.decode(raw_body.trim_space())
	if bytes.len == 0 {
		return none
	}
	frame := xsp_stdlib_builtin('xsp-decode', [bytes_node(bytes)]) or { return none }
	if xd_is_err(frame) || frame !is cx.Element {
		return none
	}
	fe := frame as cx.Element
	for it in fe.items {
		if it is cx.Element && it.name == 'payload' {
			if it.items.len > 0 && it.items[0] is cx.Element {
				return it.items[0] as cx.Element
			}
		}
	}
	return none
}

// xap_host_auth_encode_msg wraps a handshake reply as base64(frame(M)).
fn xap_host_auth_encode_msg(m cx.Node) ?string {
	frame := cx.Element{
		name:  'frame'
		attrs: [xap_attr('type', 'reply'), xap_attr('stream', '0')]
		items: [cx.Node(cx.Element{
			name:  'payload'
			items: [m]
		})]
	}
	wire := xsp_stdlib_builtin('xsp-encode', [cx.Node(frame)]) or { return none }
	b := arg_bytes(wire) or { return none }
	return base64.encode(b)
}

fn xap_host_auth_wire_err(status int, n cx.Node) WireResp {
	return WireResp{
		status:  status
		headers: [WireHeader{
			name:  'Content-Type'
			value: 'application/cx; charset=utf-8'
		}]
		body:    render_canonical(n) + '\n'
	}
}

fn xap_host_auth_refuse(status int, ecode string, msg string) WireResp {
	return xap_host_auth_wire_err(status, mk_err(ecode, msg))
}

// ── POST /attach: the responder side of XSP-AUTH over SSE+POST ──────────────

fn xap_host_attach(mut h XapHost, raw_body string, hdrs XspReqHdrs) WireResp {
	mut auth := h.auth
	msg := xap_host_auth_decode_msg(raw_body) or {
		return xap_host_auth_refuse(400, 'cx-err:CXER-XSP-AUTH-STATE', 'E_XAP_AUTH: /attach body must be a base64 XSP stream-0 frame carrying an [xsp-auth …] payload')
	}
	phase := xap_elem_attr(msg, 'phase')
	match phase {
		'hello' {
			return xap_host_attach_m1(mut auth, msg)
		}
		'prove' {
			return xap_host_attach_m3(mut auth, msg, hdrs)
		}
		else {
			return xap_host_auth_refuse(400, 'cx-err:CXER-XSP-AUTH-STATE', 'E_XAP_AUTH: /attach expects phase=hello or phase=prove (got "${phase}")')
		}
	}
}

// M1 → M2: generate the responder nonce/ephemeral, sign, derive the §4.5
// schedule, pend the handshake by chan-id.
fn xap_host_attach_m1(mut auth XapHostAuth, m1 cx.Element) WireResp {
	nonce := crypto_random_octets(32) or {
		return xap_host_auth_refuse(500, 'cx-err:CXER-XSP-AUTH-STATE', 'E_XAP_AUTH: entropy unavailable')
	}
	eph_priv := crypto_random_octets(32) or {
		return xap_host_auth_refuse(500, 'cx-err:CXER-XSP-AUTH-STATE', 'E_XAP_AUTH: entropy unavailable')
	}
	mut sk := eph_priv.clone()
	x25519_clamp(mut sk)
	eph_pub := x25519_scalar_base_mult(sk)
	opts := cx.Node(cx.Element{
		name:  '__cx_map__'
		items: [
			session_kv('did', crypto_string_node(auth.did)),
			session_kv('nonce', bytes_node(nonce)),
			session_kv('eph', bytes_node(eph_pub)),
			session_kv('key', bytes_node(auth.seed)),
		]
	})
	m2 := xsp_auth_stdlib_builtin('xsp-auth-challenge', [cx.Node(m1), opts]) or {
		return xap_host_auth_refuse(403, 'cx-err:CXER-XSP-AUTH-STATE', 'E_XAP_AUTH: challenge failed')
	}
	if xd_is_err(m2) {
		return xap_host_auth_wire_err(403, m2)
	}
	// derive the schedule now: chan-id keys the pending entry, proof-i is the
	// §4.8 rule-2 verification key once the channel establishes.
	i_eph := xsp_auth_child_bytes(m1, 'eph') or { []u8{} }
	i_nonce := xsp_auth_child_bytes(m1, 'nonce') or { []u8{} }
	keys := xsp_auth_derive(eph_priv, i_eph, i_nonce, nonce) or {
		return xap_host_auth_refuse(403, 'cx-err:CXER-XSP-AUTH-STATE', 'E_XAP_AUTH: key derivation failed: ${err.msg()}')
	}
	chan_hex := keys.chan_id.hex()
	now := time.now().unix()
	auth.mu.lock()
	// prune expired handshakes; bound the table (eviction is silent — the
	// client simply re-runs the handshake).
	mut dead := []string{}
	for k, p in auth.pending {
		if now - p.created > xap_host_auth_pend_ttl {
			dead << k
		}
	}
	for k in dead {
		auth.pending.delete(k)
	}
	if auth.pending.len >= xap_host_auth_pend_cap {
		auth.mu.unlock()
		return xap_host_auth_refuse(429, 'cx-err:CXER-XSP-AUTH-STATE', 'E_XAP_AUTH: too many pending handshakes')
	}
	auth.pending[chan_hex] = XapHostAuthPend{
		m1:        m1
		m2:        m2 as cx.Element
		eph_priv:  eph_priv
		proof_key: keys.proof_i
		created:   now
	}
	auth.mu.unlock()
	wire := xap_host_auth_encode_msg(m2) or {
		return xap_host_auth_refuse(500, 'cx-err:CXER-XSP-AUTH-STATE', 'E_XAP_AUTH: frame encode failed')
	}
	return WireResp{
		status:  200
		headers: [WireHeader{
			name:  'Content-Type'
			value: 'text/plain; charset=utf-8'
		}, WireHeader{
			name:  'XSP-Channel'
			value: chan_hex
		}]
		body:    wire
	}
}

// M3 → M4: verify via [$session:attach-xsp] (the full §4 verification — no
// second implementation), establish the session, move the channel to the
// established table, and reply with the session-spliced M4.
fn xap_host_attach_m3(mut auth XapHostAuth, m3 cx.Element, hdrs XspReqHdrs) WireResp {
	chan_hex := hdrs.channel.trim_space()
	if chan_hex == '' {
		return xap_host_auth_refuse(400, 'cx-err:CXER-XSP-AUTH-STATE', 'E_XAP_AUTH: M3 needs the XSP-Channel header (the chan-id from M2)')
	}
	auth.mu.lock()
	pend := auth.pending[chan_hex] or {
		auth.mu.unlock()
		return xap_host_auth_refuse(403, 'cx-err:CXER-XSP-AUTH-STATE', 'E_XAP_AUTH: no pending handshake for that channel (expired? re-run the handshake)')
	}
	auth.pending.delete(chan_hex)
	auth.mu.unlock()
	mut cfg_items := [
		session_kv('eph-priv', bytes_node(pend.eph_priv)),
		session_kv('tenant', crypto_string_node(auth.tenant)),
	]
	if auth.mutual {
		cfg_items << session_kv('require-mutual', crypto_string_node('true'))
	} else {
		cfg_items << session_kv('anonymous-floor', crypto_string_node(auth.floor))
	}
	cfg := cx.Node(cx.Element{
		name:  '__cx_map__'
		items: cfg_items
	})
	attached := session_attach_xsp_impl([cx.Node(pend.m1), cx.Node(pend.m2), cx.Node(m3),
		cfg])
	if xd_is_err(attached) {
		// the exact CXER-XSP-AUTH-* / session err value, verbatim — fail-closed,
		// nothing binds (§8.6).
		return xap_host_auth_wire_err(403, attached)
	}
	ae := attached as cx.Element
	mut session_id := ''
	mut m4 := cx.Node(cx.Element{ name: 'xsp-auth' })
	for it in ae.items {
		if it is cx.Element {
			if it.name == 'session' {
				session_id = xap_elem_attr(it, 'id')
			} else if it.name == 'confirm' && it.items.len > 0 {
				m4 = it.items[0]
			}
		}
	}
	// the proven principal: the authenticated initiator DID, or the floor.
	mut principal := xsp_auth_child_text(pend.m1, 'initiator') or { '' }
	if principal == '' {
		principal = auth.floor
	}
	auth.mu.lock()
	auth.chans[chan_hex] = XapHostAuthChan{
		proof_key: pend.proof_key
		counter:   0
		principal: principal
		session:   session_id
	}
	auth.mu.unlock()
	wire := xap_host_auth_encode_msg(m4) or {
		return xap_host_auth_refuse(500, 'cx-err:CXER-XSP-AUTH-STATE', 'E_XAP_AUTH: frame encode failed')
	}
	return WireResp{
		status:  200
		headers: [WireHeader{
			name:  'Content-Type'
			value: 'text/plain; charset=utf-8'
		}]
		body:    wire
	}
}

// ── per-request enforcement (§4.8 rule 2) ────────────────────────────────────

fn xap_host_auth_public(auth &XapHostAuth, path string) bool {
	for p in auth.public {
		// A route longer than '/' and ending in '/' is a prefix ('/static/'
		// serves /static/…). Bare '/' is the root page — EXACT only; treating
		// it as a prefix would make every path public (it is a prefix of all).
		if p.len > 1 && p.ends_with('/') {
			if path.starts_with(p) {
				return true
			}
		} else if path == p {
			return true
		}
	}
	return false
}

// xap_host_auth_admit verifies the three headers against the channel state:
// proof = HMAC-SHA256(k_proof_i, counter-be8 ‖ sha256(raw body)) and strict
// counter monotonicity — verify-and-advance atomic under the registry lock.
// A GET proves the empty body. Every failure is the §4.10 proof error.
fn xap_host_auth_admit(mut h XapHost, hdrs XspReqHdrs, raw_body string) XapAuthAdmit {
	mut auth := h.auth
	if hdrs.channel == '' || hdrs.counter == '' || hdrs.proof == '' {
		return xap_host_auth_deny('request needs XSP-Channel/-Counter/-Proof (attach first: POST /attach)')
	}
	counter := hdrs.counter.u64()
	if counter < 1 {
		return xap_host_auth_deny('counter must be a positive integer')
	}
	proof := base64.decode(hdrs.proof)
	if proof.len == 0 {
		return xap_host_auth_deny('proof must be base64')
	}
	auth.mu.lock()
	defer {
		auth.mu.unlock()
	}
	mut ch := auth.chans[hdrs.channel] or {
		return xap_host_auth_deny('unknown channel (expired? re-run the handshake)')
	}
	if counter <= ch.counter {
		return xap_host_auth_deny('replayed or reordered counter (§8.1)')
	}
	want := xsp_auth_proof_bytes(ch.proof_key, counter, raw_body.bytes()) or {
		return xap_host_auth_deny('proof computation failed')
	}
	if !xsp_auth_ct_eq(want, proof) {
		return xap_host_auth_deny('possession proof does not verify')
	}
	ch.counter = counter
	auth.chans[hdrs.channel] = ch
	return XapAuthAdmit{
		ok:        true
		principal: ch.principal
	}
}

fn xap_host_auth_deny(msg string) XapAuthAdmit {
	return XapAuthAdmit{
		ok:   false
		resp: xap_host_auth_refuse(401, 'cx-err:CXER-XSP-AUTH-PROOF', 'E_XAP_AUTH: ${msg}')
	}
}
