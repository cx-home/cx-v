// stdlib_session_guest_test.v — attach-guest, the anonymous-floor transport
// (GA-1 / #857; xap_identity_model.md §4.7, session.md §2.11).
//
// The fourth attach transport: a session-establishing act for the principal
// that proves NOTHING — the deployment's anonymous floor. Pins the three
// normative properties:
//   1. REMINT on privilege transition — an anonymous session that logs in
//      does not keep its pre-login id (the guest id is invalidated and the
//      proven session mints fresh).
//   2. The floor is a REAL (principal, tenant) and the authz PEP gates it
//      like any other — no anonymous commit by default.
//   3. REFUSAL is the common case — a deployment policy with no anonymous
//      floor refuses with the typed CXER4812, naming the policy.
// Plus the same-cookie-adapter guarantees: HttpOnly/Secure/SameSite posture,
// the per-session CSRF synchronizer (guest is cookie-shaped, never exempt),
// per-visitor independence, and registry resolution (from-cookie/by-id).
//
// session is capability-free; everything runs under eval_code's deny-all
// caps (mirrors the stdlib_umbrella session family).

module main

import code
import platform as _
import testenv as _

// The hermetic golden RS256 JWT + literal JWKS reused across the session
// corpus (crypto-071 material): iss=https://idp.example, sub=user-1,
// aud=my-api, exp=1700003600; pinned clock 2023-11-14T22:13:20 (inside the
// window). tenant-claim "aud" maps tenant=my-api, principal=user-1.
const guest_golden_token = 'eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYS0xIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoidXNlci0xIiwiYXVkIjoibXktYXBpIiwiZXhwIjoxNzAwMDAzNjAwLCJuYmYiOjE2OTk5OTk5OTAsImlhdCI6MTY5OTk5OTk5MH0.e4bn1A_a5Q0_4IZxKWipmmrUCCdmNkiTUs071mBMtMVXb68RGPtV2FTR1nRWvM3Zw2XTMuBsk_Y1HPinat_2JQkm3s90lltrErpYOky6Nwm6ha57BxQ0Sg5kWxuQF5KhWUqHzePIVDTfkr0WeN591nDTDn6VuajLaHn2pjXBsaJ0reT6mh6v40UQcBW-yy-XOfrsMeGVj_qZd1UmlE81XN957rjPENcPpH2E1SHfVhu3fQP3QZapxtdMADgWmryw_z5O2lDIIWb7miT0siXRCDjVEhDzKH6Hsf1aUPcYx9x44o1B5OBpX6z1uM1SP0qaOZu6x26H0AbHj84nIISE1A'

const guest_golden_jwks = '{\\"keys\\":[{\\"kid\\":\\"rsa-1\\",\\"kty\\":\\"RSA\\",\\"alg\\":\\"RS256\\",\\"n\\":\\"jdwwBcaMZQLoSNYGNEm3l03HIQqpRIv0eqLUNUCkyv7ysVw4i6vZgdYxcdU0D3kSvUCIjH-icqk4PCDx5AwkeNp55Nqt6wKXDv9TH5pr-Wc3BWmZ1sEOEwyN8QlI8_5EpY3i1w5tysDdeFuiR7BOjpkD49RZzF0YajmocsB4_jXoZcldVNCOChXAbEfOw-BtjFJRN0N3EksymF4azkey8Q3rX07sXkRHavRfAOnowH119RL1V-Xmk_DUX8wSR-2zdlp8FxitJWPgbMmnszsTgEQrThTwsuMrndqzJ_nQ7HTnuK2LXEFmFwXw9NADspq2ZnQmZiN7CXnEYG8WCApzxw\\",\\"e\\":\\"AQAB\\"}]}'

// A successful floor attach mints a [session] bound to the REAL
// (floor-principal, tenant), state=attached, guest-marked, with the CSRF
// synchronizer and the same Set-Cookie posture attach-cookie writes
// (HttpOnly; Secure; SameSite) — the SAME cookie adapter, not a parallel one.
fn test_attach_guest_mints_floor_session_via_cookie_adapter() {
	prog := "[?lib 'cx-stdlib/session' :as s]
[\$s:attach-guest [request scheme=\"https\"] {anonymous-floor: \"web-public\" tenant: \"shop\"}]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert !out.contains('cx-err:'), 'floor attach must establish cleanly, got: ${out}'
	assert out.contains('web-public'), 'session must bind the floor principal, got: ${out}'
	assert out.contains('shop'), 'session must bind the tenant, got: ${out}'
	assert out.contains('state=attached') || out.contains('state="attached"'), 'session must be attached, got: ${out}'
	assert out.contains("guest='true'") || out.contains('guest=true'), 'session must carry the guest marker, got: ${out}'
	assert out.contains('via=guest'), 'the client must record via=guest, got: ${out}'
	assert out.contains('csrf-token'), 'guest session must mint the CSRF synchronizer, got: ${out}'
	assert out.contains('set-cookie'), 'attach-guest must return the Set-Cookie directives, got: ${out}'
	assert out.contains('__Host-cxsid'), 'same cookie adapter — same default cookie name, got: ${out}'
	assert out.contains("http-only='true'") || out.contains('http-only=true'), 'HttpOnly posture must hold, got: ${out}'
	assert out.contains("secure='true'") || out.contains('secure=true'), 'Secure posture must hold, got: ${out}'
	assert out.contains('same-site=Lax') || out.contains("same-site='Lax'"), 'SameSite=Lax default must hold, got: ${out}'
}

// Property 3 — REFUSAL IS THE COMMON CASE: no `anonymous-floor` in cfg (the
// production default per §4.7) refuses with the typed CXER4812 naming the
// policy; nothing is minted.
fn test_attach_guest_refuses_without_floor_policy() {
	prog := "[?lib 'cx-stdlib/session' :as s]
[\$s:attach-guest [request scheme=\"https\"] {tenant: \"shop\"}]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('CXER4812'), 'expected the typed anonymous-refused fault, got: ${out}'
	assert out.contains('anonymous'), 'the refusal must name the policy, got: ${out}'
}

// The cookie-side TLS bright line holds for the guest credential too: a
// non-TLS request without allow-insecure → CXER4810, fail-closed.
fn test_attach_guest_requires_tls_for_the_cookie() {
	prog := "[?lib 'cx-stdlib/session' :as s]
[\$s:attach-guest [request scheme=\"http\"] {anonymous-floor: \"web-public\" tenant: \"shop\"}]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('CXER4810'), 'expected cookie-insecure-context over non-TLS, got: ${out}'
}

// Property 1 — REMINT ON PRIVILEGE TRANSITION: a proven attach-cookie over a
// request whose cookie names the live guest session (a) mints a DIFFERENT
// session id, (b) invalidates the guest id server-side (by-id → absence),
// and (c) binds the proven principal. One program: the registry resets per
// evaluated program.
fn test_attach_guest_remints_on_login_transition() {
	prog := "[?lib 'cx-stdlib/session' :as s]
[?lib 'cx-stdlib/crypto' :as c]
[?lib 'cx-stdlib/time' :as t]
[?lib 'cx-stdlib/strings' :as str]
[?let [= \$gpair [\$s:attach-guest [request scheme=\"https\"] {anonymous-floor: \"web-public\" tenant: \"my-api\"}]]
  [= \$g [\$first \$gpair]]
  [= \$gid \$g@id]
  [= \$cv [\$str:join (\"__Host-cxsid=\", \$gid) \"\"]]
  [= \$pair2 [\$s:attach-cookie [request scheme=\"https\" [headers [header name=\"Authorization\" value=\"Bearer ${guest_golden_token}\"] [header name=\"Cookie\" [?attr value \$cv]]]] {jwks: [\$c:jwks-parse \"${guest_golden_jwks}\"] tenant-claim: \"aud\" now: [\$t:datetime 2023 11 14 22 13 20]}]]
  [= \$s2 [\$first \$pair2]]
  [?let [= \$p2 [\$s:principal \$s2]]
    [\$str:join ([\$string [not [= \$gid \$s2@id]]], \":\", [?else [\$s:by-id \$gid] \"GONE\"], \":\", \$p2@id) \"\"]]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('true:GONE:user-1'), 'expected remint (new id, old id gone, proven principal), got: ${out}'
}

// Fail-closed ordering on the transition: a login attempt whose token FAILS
// verification leaves the guest session (and the visitor state it anchors)
// INTACT — the fault is the pipeline CXER4801; the guest id still resolves.
fn test_attach_guest_survives_a_failed_login() {
	prog := "[?lib 'cx-stdlib/session' :as s]
[?lib 'cx-stdlib/crypto' :as c]
[?lib 'cx-stdlib/time' :as t]
[?lib 'cx-stdlib/strings' :as str]
[?let [= \$gpair [\$s:attach-guest [request scheme=\"https\"] {anonymous-floor: \"web-public\" tenant: \"my-api\"}]]
  [= \$g [\$first \$gpair]]
  [= \$gid \$g@id]
  [= \$cv [\$str:join (\"__Host-cxsid=\", \$gid) \"\"]]
  [= \$bad [?fallback [\$s:attach-cookie [request scheme=\"https\" [headers [header name=\"Authorization\" value=\"Bearer notajwt\"] [header name=\"Cookie\" [?attr value \$cv]]]] {jwks: [\$c:jwks-parse \"${guest_golden_jwks}\"] tenant-claim: \"aud\" now: [\$t:datetime 2023 11 14 22 13 20]}] [recover-with \"FAULTED\"]]]
  [?let [= \$back [\$s:by-id \$gid]]
    [?let [= \$p [\$s:principal \$back]] \$p@id]]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('web-public'), 'a failed login must leave the guest session intact, got: ${out}'
}

// Guest sessions are PER-VISITOR INDEPENDENT: two guest attaches (no cookie
// carried) mint two DIFFERENT sessions even though they share the one floor
// (principal, tenant) — a guest attach never mirrors by subject.
fn test_attach_guest_sessions_are_per_visitor_independent() {
	prog := "[?lib 'cx-stdlib/session' :as s]
[?let [= \$p1 [\$s:attach-guest [request scheme=\"https\"] {anonymous-floor: \"web-public\" tenant: \"shop\"}]]
  [= \$a [\$first \$p1]]
  [= \$p2 [\$s:attach-guest [request scheme=\"https\"] {anonymous-floor: \"web-public\" tenant: \"shop\"}]]
  [= \$b [\$first \$p2]]
  [not [= \$a@id \$b@id]]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('true'), 'two visitors must hold two independent sessions, got: ${out}'
}

// Idempotence + registry resolution: a request carrying the live guest
// cookie re-attaches to the SAME session (the basket survives), and
// from-cookie resolves it — the guest session is REGISTERED, unlike the
// pre-GA-1 shim.
fn test_attach_guest_idempotent_over_live_cookie_and_resolvable() {
	prog := "[?lib 'cx-stdlib/session' :as s]
[?lib 'cx-stdlib/strings' :as str]
[?let [= \$p1 [\$s:attach-guest [request scheme=\"https\"] {anonymous-floor: \"web-public\" tenant: \"shop\"}]]
  [= \$a [\$first \$p1]]
  [= \$cv [\$str:join (\"__Host-cxsid=\", \$a@id) \"\"]]
  [= \$req2 [request scheme=\"https\" [headers [header name=\"Cookie\" [?attr value \$cv]]]]]
  [= \$p2 [\$s:attach-guest \$req2 {anonymous-floor: \"web-public\" tenant: \"shop\"}]]
  [= \$b [\$first \$p2]]
  [= \$r [\$s:from-cookie \$req2 {}]]
  [\$str:join ([\$string [= \$a@id \$b@id]], \":\", [\$string [= \$a@id \$r@id]]) \"\"]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('true:true'), 'guest re-attach must be idempotent and from-cookie must resolve it, got: ${out}'
}

// GA-1a — no downgrade: attach-guest over a request carrying a live PROVEN
// session cookie refuses (CXER4805) — an authenticated binding never
// downgrades to anonymous.
fn test_attach_guest_never_downgrades_a_proven_session() {
	prog := "[?lib 'cx-stdlib/session' :as s]
[?lib 'cx-stdlib/crypto' :as c]
[?lib 'cx-stdlib/time' :as t]
[?lib 'cx-stdlib/strings' :as str]
[?let [= \$pair [\$s:attach-cookie [request scheme=\"https\" [headers [header name=\"Authorization\" value=\"Bearer ${guest_golden_token}\"]]] {jwks: [\$c:jwks-parse \"${guest_golden_jwks}\"] tenant-claim: \"aud\" now: [\$t:datetime 2023 11 14 22 13 20]}]]
  [= \$sv [\$first \$pair]]
  [= \$cv [\$str:join (\"__Host-cxsid=\", \$sv@id) \"\"]]
  [\$s:attach-guest [request scheme=\"https\" [headers [header name=\"Cookie\" [?attr value \$cv]]]] {anonymous-floor: \"web-public\" tenant: \"my-api\"}]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('CXER4805'), 'a proven session must never downgrade to anonymous, got: ${out}'
}

// The CSRF synchronizer applies to guest sessions (cookie-shaped, GA-1b):
// a state-changing intent with no submitted token → CXER4808, never the
// Bearer no-op exemption.
fn test_attach_guest_is_csrf_guarded() {
	prog := "[?lib 'cx-stdlib/session' :as s]
[?let [= \$pair [\$s:attach-guest [request scheme=\"https\"] {anonymous-floor: \"web-public\" tenant: \"shop\"}]]
  [= \$g [\$first \$pair]]
  [\$s:csrf-verify [request scheme=\"https\"] \$g {}]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('CXER4808'), 'guest state-changing intent without a CSRF token must refuse, got: ${out}'
}

// Property 2 — the PEP gates the floor like any other principal: with no
// delegation for the floor actor, an authz check on a commit-shaped
// capability DENIES (deny-by-default; no anonymous commit).
fn test_pep_gates_the_floor_principal_deny_by_default() {
	prog := "[?lib 'cx-stdlib/session' :as s]
[?lib 'cx-stdlib/authz' :as authz]
[?let [= \$pair [\$s:attach-guest [request scheme=\"https\"] {anonymous-floor: \"web-public\" tenant: \"shop\"}]]
  [= \$g [\$first \$pair]]
  [?let [= \$p [\$s:principal \$g]]
    [?let [= \$az [\$authz:store {tenant: \"shop\"}]]
      [\$authz:check \$az [authz-request [actor [agent [?attr id \$p@id]]] [capability commit] [tenant shop]]]]]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('deny'), 'the ungranted floor principal must be DENIED by the PEP, got: ${out}'
	assert !out.contains('permit'), 'no anonymous commit by default, got: ${out}'
}
