@[has_globals]
module platform

import code {
	crypto_random_octets,
	is_err_value,
}
import cx
import crypto.sha256
import encoding.base64
import sync
import time

// store_grpc_call_auth.v — per-call XSP-AUTH for the gRPC edge (I5 stream 4
// S3, RULED G1(a) 2026-08-08; cxstore-grpc.md §4). The bearer/RBAC plane is
// RETIRED: the gRPC `authorization` metadata now carries the PROFILE's
// credential form — the presenting DID's ed25519 signature binding it to
// THIS call (method path + body hash + timestamp + nonce), plus an optional
// `[vp …]` delegation chain — verified by the SAME delegation-compile +
// capability-grammar + PEP path the profile listener uses
// (store_xsp_authority.v). ONE authority calculus, no session state on the
// edge, no second implementation.
//
// Header form (the public wire shape — any conformant client can build it):
//   authorization: CxCall <base64url(
//     [grpc-call-auth did="<did:key…>" at=<unix-ms> nonce="<hex32>"
//        path="/cxstore.v1.CxStore/<Method>" body-sha256="<hex64>"
//        sig="<hex128>" [vp [vc …]…]?] )>
// The signature covers the STRICT canonical text of
//   [grpc-call-auth-canonical did= at= nonce= path= body-sha256=]
// (the store-advert signing pattern) — the [vp] rides OUTSIDE the signed
// form because each [vc] carries its own signature and the chain's terminal
// subject MUST equal `did` (sx_present_locked enforces it).
//
// Posture (mirrors the profile §6.1 exactly):
//   [xsp [grants …]] configured ⇒ deny-by-default: every call needs a valid
//     header (missing/invalid → UNAUTHENTICATED), and the compiled basis
//     decides per-op (deny → PERMISSION_DENIED, the [deny] value verbatim).
//   no grants ⇒ the open/dev posture: data ops open; admin ops require a
//     valid header (the CXER5018 mutual-gate analog).
// Replay is bounded by the freshness window + a nonce seen-cache.

const grpc_call_auth_scheme = 'CxCall '
const grpc_call_auth_window_ms = i64(60000)

// the daemon-lifetime nonce replay cache (initialized by platform init).
__global g_grpc_nonces &GrpcNonceCache

// grpc_nonces returns the daemon-lifetime cache (init() built it before any
// listener thread, so the reference is race-free to hand out).
fn grpc_nonces() &GrpcNonceCache {
	return g_grpc_nonces
}

// grpc_call_auth_canonical builds the SIGNED bytes: the strict canonical
// text of the binding form. Returns none on canonicalization failure.
fn grpc_call_auth_canonical(did string, at_ms i64, nonce string, path string, body_sha string) ?string {
	text := '[grpc-call-auth-canonical did="${did}" at=${at_ms} nonce="${nonce}" path="${path}" body-sha256="${body_sha}"]'
	return cx.cx_text_canonical(text) or { return none }
}

// grpc_call_auth_header builds the client-side `authorization` value for one
// call: `did` + 32-byte ed25519 `seed` sign the (path, body) binding. The
// optional `vp_text` is a canonical `[vp …]` presentation appended verbatim
// (delegated authority; '' = none — the DID is expected to be named directly
// in the daemon's grants).
pub fn grpc_call_auth_header(did string, seed []u8, path string, body []u8, vp_text string) ?string {
	at := time.now().unix_milli()
	nb := crypto_random_octets(16) or { return none }
	nonce := nb.hex()
	body_sha := sha256.sum256(body).hex()
	canonical := grpc_call_auth_canonical(did, at, nonce, path, body_sha) or { return none }
	sig := jrn_sign(canonical, seed) or { return none }
	mut el := '[grpc-call-auth did="${did}" at=${at} nonce="${nonce}" path="${path}" body-sha256="${body_sha}" sig="${sig}"'
	if vp_text != '' {
		el += ' ${vp_text}'
	}
	el += ']'
	return grpc_call_auth_scheme + base64.url_encode(el.bytes())
}

// GrpcNonceCache bounds replay: a nonce is admitted once inside the
// freshness window; entries older than the window are pruned on insert.
@[heap]
pub struct GrpcNonceCache {
mut:
	mu   &sync.Mutex = unsafe { nil }
	seen map[string]i64
}

pub fn new_grpc_nonce_cache() &GrpcNonceCache {
	return &GrpcNonceCache{
		mu:   sync.new_mutex()
		seen: map[string]i64{}
	}
}

// admit reports whether `nonce` is fresh (unseen inside the window) and
// records it. Pruning rides every insert so the cache stays window-bounded.
fn (mut nc GrpcNonceCache) admit(nonce string, now_ms i64) bool {
	nc.mu.lock()
	defer {
		nc.mu.unlock()
	}
	if at := nc.seen[nonce] {
		if now_ms - at <= grpc_call_auth_window_ms {
			return false
		}
	}
	mut stale := []string{}
	for k, v in nc.seen {
		if now_ms - v > grpc_call_auth_window_ms {
			stale << k
		}
	}
	for k in stale {
		nc.seen.delete(k)
	}
	nc.seen[nonce] = now_ms
	return true
}

// grpc_call_auth_attr reads one attr off the parsed header element.
fn grpc_call_auth_attr(el cx.Element, name string) string {
	for a in el.attrs {
		if a.name == name {
			return cx.scalar_value_str_public(a.value)
		}
	}
	return ''
}

// grpc_call_auth_verify verifies one call credential end-to-end and returns
// the authenticated transient session (principal + compiled authority basis,
// the SAME objects the profile listener builds) for the PEP decision.
// Errors return the profile's authority code (the caller maps to the gRPC
// status per cxstore-grpc.md §3).
fn grpc_call_auth_verify(header string, path string, body []u8, cfg XspConfig, revoked map[string]bool, mount string, mut nc GrpcNonceCache) !&SxConn {
	if !header.starts_with(grpc_call_auth_scheme) {
		return error('E_XSP_STORE_AUTHORITY: authorization is not a CxCall credential (the bearer plane is retired — cxstore-grpc.md §4)')
	}
	raw := base64.url_decode(header[grpc_call_auth_scheme.len..].trim_space())
	if raw.len == 0 {
		return error('E_XSP_STORE_AUTHORITY: CxCall credential is not base64url')
	}
	doc := cx.parse(raw.bytestr()) or {
		return error('E_XSP_STORE_AUTHORITY: CxCall credential does not parse: ${err.msg()}')
	}
	if doc.elements.len == 0 {
		return error('E_XSP_STORE_AUTHORITY: CxCall credential is empty')
	}
	first := doc.elements[0]
	if first !is cx.Element {
		return error('E_XSP_STORE_AUTHORITY: CxCall credential is not an element')
	}
	el := first as cx.Element
	if el.name != 'grpc-call-auth' {
		return error('E_XSP_STORE_AUTHORITY: CxCall credential must be [grpc-call-auth …]')
	}
	did := grpc_call_auth_attr(el, 'did')
	nonce := grpc_call_auth_attr(el, 'nonce')
	cpath := grpc_call_auth_attr(el, 'path')
	body_sha := grpc_call_auth_attr(el, 'body-sha256')
	sig_hex := grpc_call_auth_attr(el, 'sig')
	at := grpc_call_auth_attr(el, 'at').i64()
	if did == '' || nonce == '' || sig_hex == '' {
		return error('E_XSP_STORE_AUTHORITY: CxCall credential missing did/nonce/sig')
	}
	// 1. the binding: this call, these bytes, now.
	if cpath != path {
		return error('E_XSP_STORE_AUTHORITY: credential path "${cpath}" does not bind this call "${path}"')
	}
	real_sha := sha256.sum256(body).hex()
	if body_sha != real_sha {
		return error('E_XSP_STORE_AUTHORITY: credential body-sha256 does not bind this call body')
	}
	now_ms := time.now().unix_milli()
	if at <= 0 || now_ms - at > grpc_call_auth_window_ms || at - now_ms > grpc_call_auth_window_ms {
		return error('E_XSP_STORE_AUTHORITY: credential timestamp outside the freshness window')
	}
	if !nc.admit(nonce, now_ms) {
		return error('E_XSP_STORE_AUTHORITY: credential nonce replayed inside the freshness window')
	}
	// 2. the possession proof: ed25519 over the canonical binding form.
	pub_bytes := did_key_bytes(did) or {
		return error('E_XSP_STORE_AUTHORITY: did "${did}" is not offline-resolvable (did:key/did:peer:0)')
	}
	canonical := grpc_call_auth_canonical(did, at, nonce, cpath, body_sha) or {
		return error('E_XSP_STORE_AUTHORITY: credential canonicalization failed')
	}
	if !jrn_snapshot_verify_sig(canonical, sig_hex, pub_bytes) {
		return error('E_XSP_STORE_AUTHORITY: credential signature does not verify for ${did}')
	}
	// 3. the authority basis: the SAME objects the profile listener builds —
	// config grants seed the basis; an attached [vp …] chain compiles through
	// sx_present_locked (terminal subject MUST equal the signing DID; the
	// per-call signature above is the possession proof the session handshake
	// provides on the profile).
	mut c := &SxConn{
		principal: did
		mutual:    true
		mount:     mount
		authz:     sx_authority_new(cfg, mount, did)
		meters:    map[string]&SxMeter{}
		vc_of:     map[string]string{}
	}
	for it in el.items {
		if it is cx.Element && it.name == 'vp' {
			mut srv := &StoreXspServer{
				mu:      sync.new_mutex()
				cfg:     cfg
				revoked: revoked.clone()
			}
			srv.mu.lock()
			r := sx_present_locked(mut srv, mut c, it)
			srv.mu.unlock()
			if is_err_value(r) {
				return error(sw_err_text_of(r))
			}
		}
	}
	return c
}

// sw_err_text_of extracts "code: message" from an [err …] node for error()
// carriage across the ! boundary.
fn sw_err_text_of(n cx.Node) string {
	if n is cx.Element {
		mut c := ''
		mut m := ''
		for a in n.attrs {
			if a.name == 'code' {
				c = cx.scalar_value_str_public(a.value)
			}
			if a.name == 'message' {
				m = cx.scalar_value_str_public(a.value)
			}
		}
		return '${c}: ${m}'
	}
	return 'error'
}

// grpc_call_gate is the ONE per-call decision the dispatch adapter runs
// before routing an op (RULED G1a/G3a): resolves the posture, verifies the
// credential when one is required, and runs the profile PEP over the
// compiled basis. Returns none = permitted; a GrpcReply = the refusal to
// send. `mount` is the store the decoded request targets ('' = server-level
// discovery like Capabilities — read-class, open in both postures).
fn grpc_call_gate(authz string, path string, body []u8, op string, mount string, ctx ServeContext, mut nc GrpcNonceCache) ?GrpcReply {
	cap_name := sx_verb_capability(op)
	enforcing := ctx.xsp_cfg.grants.len > 0
	if !enforcing {
		// open/dev posture (profile §6.1 W3): data verbs open; admin verbs
		// behind the mutual gate — a VALID call credential is the per-call
		// mutual-proof analog.
		if cap_name != 'admin' {
			return none
		}
		if authz == '' {
			return GrpcReply{
				status: GrpcStatus{grpc_unauthenticated, 'grpc: admin op requires a CxCall credential (open posture mutual gate; cxstore-grpc.md §4)', 'cx-err:CXER5018'}
			}
		}
		grpc_call_auth_verify(authz, path, body, ctx.xsp_cfg, grpc_ctx_revoked(ctx),
			mount, mut nc) or {
			return GrpcReply{
				status: GrpcStatus{grpc_unauthenticated, 'grpc: ${err.msg()}', 'cx-err:CXER5021'}
			}
		}
		return none
	}
	// deny-by-default posture: every call authenticates, then the PEP decides.
	if authz == '' {
		return GrpcReply{
			status: GrpcStatus{grpc_unauthenticated, 'grpc: a CxCall credential is required (grants configured; cxstore-grpc.md §4)', 'cx-err:CXER5021'}
		}
	}
	mut c := grpc_call_auth_verify(authz, path, body, ctx.xsp_cfg, grpc_ctx_revoked(ctx),
		mount, mut nc) or {
		return GrpcReply{
			status: GrpcStatus{grpc_unauthenticated, 'grpc: ${err.msg()}', 'cx-err:CXER5021'}
		}
	}
	decision := sx_pep_decide(mut c, cap_name, '', grpc_ctx_revoked(ctx))
	if is_err_value(decision) {
		return GrpcReply{
			status: GrpcStatus{grpc_permission_denied, 'grpc: ${sw_err_text_of(decision)}', 'cx-err:CXER5021'}
		}
	}
	return none
}

// grpc_ctx_revoked resolves the daemon's live revoked-set for the edge (the
// fold lives on the profile listener; nil provider = no designation = empty).
fn grpc_ctx_revoked(ctx ServeContext) map[string]bool {
	if ctx.revoked_fn == unsafe { nil } {
		return map[string]bool{}
	}
	f := ctx.revoked_fn
	return f()
}
