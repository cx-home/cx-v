module platform

import code {
	caps_set_all,
	is_err_value,
}

import cx
import os

// store_config_reload_test.v — #251 runtime config reload (§2.6, §3.13). S3
// (RULED G2a/G3a 2026-08-08): the bearer/RBAC HTTP forms + the [auth …]
// section are retired — the reload op rides the gRPC edge (authorized by the
// per-call XSP-AUTH gate) and SIGHUP. This file pins the transport-independent
// reload ENGINE (svc_reload_config: validate-then-swap, fail-closed,
// restart-required refusal, generation/metrics), the limiter bucket
// preservation, the bootstrap capabilities advert, and the gRPC Reload shape.

// cr_config renders a daemon config. G2a: NO [auth …] section (retired) —
// operator grants ride [xsp [grants …]]. A hot [limits] change is the reload
// probe here (auth rotation is gone).
fn cr_config(bind string, rate int) string {
	return '[cxstore-service [bind addr="${bind}"] [stores [store name="docs" url="mem://cr-docs"]] [limits per-principal-rate="${rate}"]]'
}

struct CrHarness {
	path string
mut:
	box  &SvcConfigBox
	deps ReloadDeps
	ctx  ServeContext
}

fn cr_harness(name string) CrHarness {
	caps_set_all()
	path := os.join_path(os.temp_dir(), 'cr_${name}_${os.getpid()}.cx')
	src := cr_config('127.0.0.1:19999', 600)
	os.write_file(path, src) or { panic('write config: ${err}') }
	cfg := parse_service_config(src) or { panic('seed config must parse: ${err}') }
	limiter := new_limiter(cfg.limits)
	metrics := new_metrics_registry('test')
	mut box := new_svc_config_box(cfg, src, '', '', '')
	deps := ReloadDeps{
		config_path: path
		limiter:     limiter
		metrics:     metrics
	}
	reload_fn := fn [mut box, deps] () ReloadOutcome {
		return svc_reload_config(mut box, deps)
	}
	return CrHarness{
		path: path
		box:  box
		deps: deps
		ctx:  ServeContext{
			mounts:   {
				'docs': store_open_impl('mem://cr-docs', '', '', false, true, map[string]string{})
			}
			limiter:  limiter
			metrics:  metrics
			cfgbox:   box
			reloader: reload_fn
		}
	}
}

fn (h CrHarness) cleanup() {
	os.rm(h.path) or {}
}

// cr_body renders a reload-outcome element to its response text for shape checks.
fn cr_body(n cx.Node) string {
	return svc_response_body(n)
}

// ── reload engine: validate-then-swap, fail-closed, generation ────────────────

fn test_reload_noop_on_unchanged_file() {
	h := cr_harness('noop')
	defer {
		h.cleanup()
	}
	mut box := h.box
	out := svc_reload_config(mut box, h.deps)
	assert !out.applied, 'unchanged file must be a no-op'
	assert box.generation() == 0, 'a no-op must not bump the generation'
}

fn test_reload_applies_hot_change() {
	h := cr_harness('apply')
	defer {
		h.cleanup()
	}
	os.write_file(h.path, cr_config('127.0.0.1:19999', 1200)) or { panic('rewrite') }
	mut box := h.box
	out := svc_reload_config(mut box, h.deps)
	assert out.applied, 'a hot [limits] change must apply: ${out.err_msg}'
	assert box.generation() == 1, 'an applied reload bumps the generation'
}

// Stream 7 F3 (#679 / #714 item 3): the capability advert BINDS the
// config-reload generation. The daemon computes the advert live per
// request — it reports the startup generation before a reload and the
// bumped one after, so a CLIENT-cached advert is detectably stale across
// a reload (a cached advert across config-reload is a cached lie —
// consistency_vocabulary.md §3).
fn test_capabilities_advert_binds_config_generation() {
	mut s := new_service_state()
	s.mark_ready()
	h := cr_harness('genbind')
	defer {
		h.cleanup()
	}
	caps0 := svc_handle_request(cr_req('GET', '/cx-store/v1/capabilities'), mut s, h.ctx)
	assert cr_body(caps0).contains('[config-generation 0]'), 'startup server advert must carry generation 0: ${cr_body(caps0)}'
	caps0s := svc_handle_request(cr_req('GET', '/cx-store/v1/docs/capabilities'), mut s, h.ctx)
	assert cr_body(caps0s).contains('[config-generation 0]'), 'startup per-store advert must carry generation 0: ${cr_body(caps0s)}'
	os.write_file(h.path, cr_config('127.0.0.1:19999', 1800)) or { panic('rewrite') }
	mut box := h.box
	out := svc_reload_config(mut box, h.deps)
	assert out.applied, 'the generation-bind reload must apply: ${out.err_msg}'
	caps1 := svc_handle_request(cr_req('GET', '/cx-store/v1/capabilities'), mut s, h.ctx)
	assert cr_body(caps1).contains('[config-generation 1]'), 'post-reload advert must carry the bumped generation: ${cr_body(caps1)}'
}

fn test_reload_invalid_candidate_keeps_running_config() {
	h := cr_harness('invalid')
	defer {
		h.cleanup()
	}
	os.write_file(h.path, '[cxstore-service [nonsense-section x=1]]') or { panic('rewrite') }
	mut box := h.box
	out := svc_reload_config(mut box, h.deps)
	assert !out.applied, 'an invalid candidate must not apply'
	assert out.err_code == 'cx-err:CXER1711', 'invalid candidate must carry CXER1711, got ${out.err_code}'
	assert box.generation() == 0, 'a refused reload must not bump the generation'
}

fn test_reload_restart_required_refused_whole() {
	h := cr_harness('restart')
	defer {
		h.cleanup()
	}
	// bind is restart-only; a candidate that changes it is refused whole even if
	// it also carries a hot [limits] change (all-or-nothing).
	os.write_file(h.path, cr_config('127.0.0.1:20000', 1200)) or { panic('rewrite') }
	mut box := h.box
	out := svc_reload_config(mut box, h.deps)
	assert !out.applied, 'a restart-required candidate must not apply'
	assert out.err_code == 'cx-err:CXER1712', 'must carry CXER1712, got ${out.err_code}'
	assert out.err_msg.contains('bind'), 'refusal must NAME the offending section: ${out.err_msg}'
	assert box.generation() == 0, 'a refused reload must not bump the generation'
}

// ── limiter: config swap preserves bucket/in-flight state ─────────────────────

fn test_limiter_set_config_preserves_buckets() {
	mut l := new_limiter(LimitConfig{
		per_principal_rate:  0.0001 // effectively no refill during the test
		per_principal_burst: 2.0
	})
	assert l.allow_principal_rate('p1')
	assert l.allow_principal_rate('p1')
	assert !l.allow_principal_rate('p1'), 'burst of 2 exhausted'
	l.set_config(LimitConfig{
		per_principal_rate:  0.0001
		per_principal_burst: 50.0
	})
	assert !l.allow_principal_rate('p1'), 'reload must preserve the drained bucket, not refill it'
	assert l.allow_principal_rate('p2'), 'new principals admit under the new config'
}

// ── capabilities advert (§3.1 admin-ops) ──────────────────────────────────────

fn cr_req(method string, path string) cx.Element {
	return cx.Element{
		name:  'request'
		attrs: [
			cx.Attribute{
				name:  'method'
				value: cx.ScalarValue(method)
			},
			cx.Attribute{
				name:  'path'
				value: cx.ScalarValue(path)
			},
		]
		items: [cx.Node(cx.Element{
			name: 'headers'
		})]
	}
}

fn test_capabilities_admin_ops_advert() {
	mut s := new_service_state()
	s.mark_ready()
	h := cr_harness('advert')
	defer {
		h.cleanup()
	}
	caps := svc_handle_request(cr_req('GET', '/cx-store/v1/capabilities'), mut s, h.ctx)
	body := cr_body(caps)
	assert body.contains('[admin-ops "status" "gc" "mounts" "config-reload"]'), 'daemon advert must list config-reload: ${body}'
	// the bootstrap advert carries NO [auth …] block (G2a — the bearer plane
	// is retired; authority is XSP-AUTH on the wire).
	assert !body.contains('[auth '), 'the retired [auth] advert must be gone: ${body}'
}

// ── gRPC Reload: op shape through the edge (admin caller) ──────────────────────

fn cr_grpc_call(method string, did string, seed []u8) GrpcCall {
	msg := pb_encode_store_request(GrpcStoreRequest{})
	mut hdrs := {
		':path': '/cxstore.v1.CxStore/${method}'
	}
	if seed.len == 32 {
		path := '/cxstore.v1.CxStore/${method}'
		if cred := grpc_call_auth_header(did, seed, path, msg, '') {
			hdrs['authorization'] = cred
		}
	}
	return GrpcCall{
		stream_id: 1
		headers:   hdrs
		message:   msg
	}
}

fn cr_identity() (string, []u8) {
	mut seed := []u8{len: 32}
	for i in 0 .. 32 {
		seed[i] = u8((i * 3 + 11) & 0xff)
	}
	did := did_key_from_seed(seed) or { panic('did') }
	return did, seed
}

fn test_reload_grpc_shape_and_anon_denied() {
	mut s := new_service_state()
	s.mark_ready()
	h := cr_harness('grpc')
	defer {
		h.cleanup()
	}
	did, seed := cr_identity()
	// anonymous (no credential) → UNAUTHENTICATED (admin op, open-posture gate)
	deny := grpc_dispatch(cr_grpc_call('Reload', '', []u8{}), mut s, h.ctx)
	assert deny.status.code == grpc_unauthenticated, 'anon Reload must be UNAUTHENTICATED(16), got ${deny.status.code}'
	// DID-proven admin caller → OK, the [config-reload …] element
	ok := grpc_dispatch(cr_grpc_call('Reload', did, seed), mut s, h.ctx)
	assert ok.status.code == grpc_ok, 'admin Reload must be OK, got ${ok.status.code}: ${ok.status.message}'
	om := pb_decode_objwire_response(ok.frames[0]) or { panic('reload response decode') }
	assert om.body.bytestr().contains('config-reload') || om.body.bytestr().contains('applied='), 'reload body shape: ${om.body.bytestr()}'
}

// ── CX porcelain: local handles are an honest error ───────────────────────────

fn test_porcelain_config_reload_local_is_honest_error() {
	caps_set_all()
	local := store_open_impl('mem://cr-local', '', '', false, true, map[string]string{})
	r := store_stdlib_builtin_inner('store-config-reload', [local]) or { panic('dispatch') }
	assert is_err_value(r), 'config-reload on a local handle must error'
	assert svc_err_code(r) == 'cx-err:CXER1709', 'local config-reload must be CXER1709, got ${svc_err_code(r)}'
}

// ── #986: `[xsp [grants …]]` is HOT — a revocation is live at the next
//    decision, and the non-grants half of the section refuses BY NAME ─────────
//
// The defect these pin shut: `[xsp]` was in NEITHER svc_hot_sections nor
// svc_restart_sections, so a grant-table edit + SIGHUP reported SUCCESS while
// the running daemon kept the old grants. An operator who revoked a principal
// and reloaded believed the revocation was live. The fix classifies the
// section: `[grants]` is hot (re-folded into every live session), everything
// else (addr, identity, policy, limits, peers, revocations) is
// restart-required and refuses loudly.

// cr_principal mints a stable test DID from a fixed seed.
fn cr_principal(b u8) string {
	seed := []u8{len: 32, init: b}
	return did_key_from_seed(seed) or { panic('cr principal: ${err}') }
}

// cr_xsp_did is the responder identity every cr_xsp_config take shares — the
// section requires one (attach is XSP-AUTH), and holding it FIXED is what
// makes the grant table the only thing moving between takes.
fn cr_xsp_did() string {
	seed := []u8{len: 32, init: 0x21}
	os.setenv('CX_CR_XSP_SEED', seed.hex(), true)
	return did_key_from_seed(seed) or { panic('cr xsp did: ${err}') }
}

// cr_xsp_config renders a daemon config carrying an [xsp] section whose
// `grants` text and listener `addr` are the two knobs the pins below turn —
// one hot, one restart-required.
fn cr_xsp_config(addr string, grants string) string {
	return '[cxstore-service [bind addr="127.0.0.1:19999"] [stores [store name="docs" url="mem://cr-docs"]] [xsp enabled=true addr="${addr}" [identity did="${cr_xsp_did()}" seed-env="CX_CR_XSP_SEED"] ${grants}]]'
}

fn cr_xsp_harness(name string, grants string) CrHarness {
	caps_set_all()
	path := os.join_path(os.temp_dir(), 'cr_${name}_${os.getpid()}.cx')
	src := cr_xsp_config('127.0.0.1:19998', grants)
	os.write_file(path, src) or { panic('write config: ${err}') }
	cfg := parse_service_config(src) or { panic('seed config must parse: ${err}') }
	limiter := new_limiter(cfg.limits)
	metrics := new_metrics_registry('test')
	mut box := new_svc_config_box(cfg, src, '', '', '')
	deps := ReloadDeps{
		config_path: path
		limiter:     limiter
		metrics:     metrics
	}
	reload_fn := fn [mut box, deps] () ReloadOutcome {
		return svc_reload_config(mut box, deps)
	}
	return CrHarness{
		path: path
		box:  box
		deps: deps
		ctx:  ServeContext{
			mounts:   {
				'docs': store_open_impl('mem://cr-docs', '', '', false, true, map[string]string{})
			}
			limiter:  limiter
			metrics:  metrics
			cfgbox:   box
			reloader: reload_fn
			xsp_cfg:  cfg.xsp
		}
	}
}

// cr_attach stands up one ESTABLISHED session on the profile listener with the
// authority basis the real M3 attach seats (sx_seat_config_roots — the same one
// entry point), without needing a socket.
fn cr_attach(mut srv StoreXspServer, principal string) &SxConn {
	mut c := &SxConn{
		id:          1
		open:        true
		established: true
		principal:   principal
		mutual:      true
		mount:       'docs'
	}
	if srv.cfg.grants.len > 0 {
		sx_seat_config_roots(mut c, srv.cfg)
	}
	srv.conns[c.id] = c
	return c
}

// cr_permits runs the REAL per-verb decision the dispatch path runs.
fn cr_permits(mut c SxConn, cap_name string) bool {
	if c.authz == unsafe { nil } {
		return true // open posture — no grants configured
	}
	dec := sx_pep_decide(mut c, cap_name, '', map[string]bool{})
	return dec is cx.Element && (dec as cx.Element).name == 'permit'
}

// PIN (a), the revocation path — the case that matters. An operator edits the
// grant table to drop a principal and reloads; that principal's NEXT call on
// its ALREADY-LIVE session refuses. Reverting `xsp` out of svc_hot_sections
// red-proves this on `out.applied` (the silent no-op the issue describes);
// reverting the sx_refold_grants_locked call red-proves it on the final assert
// (reload applies, running daemon keeps the old grants).
fn test_xsp_grant_revocation_is_live_at_the_next_decision() {
	alice := cr_principal(0x31)
	h := cr_xsp_harness('xsprevoke', '[grants [grant did="${alice}" caps="read write"]]')
	defer {
		h.cleanup()
	}
	mut srv := new_store_xsp_server(h.ctx.xsp_cfg, h.ctx)
	mut c := cr_attach(mut srv, alice)
	assert cr_permits(mut c, 'read'), 'the configured grant must permit read before any reload'
	// the operator revokes alice, then SIGHUPs.
	os.write_file(h.path, cr_xsp_config('127.0.0.1:19998', '')) or { panic('rewrite') }
	mut box := h.box
	out := svc_reload_config(mut box, h.deps)
	assert out.applied, 'a [xsp [grants]] edit must APPLY hot, not report a silent no-op: ${out.err_code} ${out.err_msg}'
	assert 'xsp' in out.changed, 'the applied reload must name xsp among the changed sections: ${out.changed}'
	assert box.generation() == 1, 'an applied grants reload bumps the generation'
	// the listener folds the new table; the live session narrows.
	sx_refold_grants_locked(mut srv)
	assert !cr_permits(mut c, 'read'), 'a REVOKED principal must be refused at its next decision (#986 — the reload said success, so the revocation must be real)'
}

// PIN (a), the other direction — a newly granted principal passes. Together
// with the revocation pin this is the whole "the new grants are LIVE" claim.
// It also pins the posture flip: a session that attached under a table naming
// someone else must not stay unrestricted once the operator grants it.
fn test_xsp_grant_addition_is_live_at_the_next_decision() {
	bob := cr_principal(0x32)
	h := cr_xsp_harness('xspadd', '[grants [grant did="${cr_principal(0x31)}" caps="read"]]')
	defer {
		h.cleanup()
	}
	mut srv := new_store_xsp_server(h.ctx.xsp_cfg, h.ctx)
	mut c := cr_attach(mut srv, bob)
	assert !cr_permits(mut c, 'read'), 'bob holds no grant before the reload'
	os.write_file(h.path, cr_xsp_config('127.0.0.1:19998', '[grants [grant did="${bob}" caps="read"]]')) or {
		panic('rewrite')
	}
	mut box := h.box
	out := svc_reload_config(mut box, h.deps)
	assert out.applied, 'the grant addition must apply hot: ${out.err_code} ${out.err_msg}'
	sx_refold_grants_locked(mut srv)
	assert cr_permits(mut c, 'read'), 'a NEWLY granted principal must pass at its next decision (#986)'
}

// PIN (b): the reload NEVER reports success while the grants did not move.
// Stated as the conjunction the defect broke — outcome `applied` AND the LIVE
// table actually carrying the candidate's grants.
fn test_applied_xsp_reload_actually_moves_the_live_grant_table() {
	alice := cr_principal(0x31)
	bob := cr_principal(0x32)
	h := cr_xsp_harness('xspmoved', '[grants [grant did="${alice}" caps="read"]]')
	defer {
		h.cleanup()
	}
	mut box := h.box
	assert box.xsp_grants().len == 1, 'the box seeds the startup grant table'
	assert box.xsp_grants()[0].did == alice, 'the startup table names alice'
	os.write_file(h.path, cr_xsp_config('127.0.0.1:19998', '[grants [grant did="${bob}" caps="read write"]]')) or {
		panic('rewrite')
	}
	out := svc_reload_config(mut box, h.deps)
	assert out.applied, 'a grant-table edit reported as success must BE a success: ${out.err_code} ${out.err_msg}'
	live := box.xsp_grants()
	assert live.len == 1, 'the live table must hold exactly the candidate grants, got ${live.len}'
	assert live[0].did == bob, 'the live table must name bob after the reload, got "${live[0].did}"'
	assert live[0].caps == ['read', 'write'], 'the live table must carry the candidate caps, got ${live[0].caps}'
}

// The gRPC edge compiles its basis per call, so the reload reaches it through
// the ONE resolution point (svc_ctx_xsp_cfg) — including the open-vs-enforcing
// posture test, which reads the same table.
fn test_xsp_grants_reload_reaches_the_grpc_edge() {
	alice := cr_principal(0x31)
	h := cr_xsp_harness('xspgrpc', '[grants [grant did="${alice}" caps="read"]]')
	defer {
		h.cleanup()
	}
	assert svc_ctx_xsp_cfg(h.ctx).grants.len == 1, 'the edge starts enforcing under the startup grants'
	os.write_file(h.path, cr_xsp_config('127.0.0.1:19998', '')) or { panic('rewrite') }
	mut box := h.box
	out := svc_reload_config(mut box, h.deps)
	assert out.applied, 'the revocation must apply: ${out.err_code} ${out.err_msg}'
	assert svc_ctx_xsp_cfg(h.ctx).grants.len == 0, 'the edge must resolve the LIVE table, not the startup-frozen copy (#986)'
	assert h.ctx.xsp_cfg.grants.len == 1, 'the startup copy itself is untouched — the box is the live truth'
}

// The other half of "exactly one set, never a silent third state": everything
// in [xsp] that is NOT [grants] is restart-required and refuses BY NAME. A
// listener cannot rebind its address under live sessions, so reporting success
// there would be the very same defect one level down.
fn test_xsp_non_grants_edit_refuses_naming_the_section() {
	alice := cr_principal(0x31)
	h := cr_xsp_harness('xsprestart', '[grants [grant did="${alice}" caps="read"]]')
	defer {
		h.cleanup()
	}
	// move the listener addr AND drop the grants in one candidate: all-or-
	// nothing means the hot half must NOT ride in on the refused one.
	os.write_file(h.path, cr_xsp_config('127.0.0.1:19997', '')) or { panic('rewrite') }
	mut box := h.box
	out := svc_reload_config(mut box, h.deps)
	assert !out.applied, 'an [xsp addr] change must not apply'
	assert out.err_code == 'cx-err:CXER1712', 'must carry CXER1712, got ${out.err_code}'
	assert out.err_msg.contains('xsp'), 'the refusal must NAME the offending section: ${out.err_msg}'
	assert out.err_msg.contains('[grants]'), 'the refusal must say which half of [xsp] is hot: ${out.err_msg}'
	assert box.generation() == 0, 'a refused reload must not bump the generation'
	assert box.xsp_grants().len == 1, 'a refused reload leaves the running grant table byte-for-byte untouched'
}

// An unchanged [xsp] section is a no-op — the hot classification must not make
// every reload look like a grant change.
fn test_xsp_unchanged_section_is_a_noop() {
	alice := cr_principal(0x31)
	h := cr_xsp_harness('xspnoop', '[grants [grant did="${alice}" caps="read"]]')
	defer {
		h.cleanup()
	}
	mut box := h.box
	out := svc_reload_config(mut box, h.deps)
	assert !out.applied, 'an unchanged file must stay a no-op with [xsp] hot'
	assert box.generation() == 0, 'a no-op must not bump the generation'
}

// The re-fold is idempotent per generation: a second fold at the same
// generation must not rebuild (or disturb) a live session's basis.
fn test_xsp_refold_is_idempotent_per_generation() {
	alice := cr_principal(0x31)
	h := cr_xsp_harness('xspidem', '[grants [grant did="${alice}" caps="read"]]')
	defer {
		h.cleanup()
	}
	mut srv := new_store_xsp_server(h.ctx.xsp_cfg, h.ctx)
	mut c := cr_attach(mut srv, alice)
	before := c.authz.delegations.len
	sx_refold_grants_locked(mut srv)
	sx_refold_grants_locked(mut srv)
	assert c.authz.delegations.len == before, 'a fold at an unmoved generation must not duplicate the config roots'
	assert cr_permits(mut c, 'read'), 'an idempotent fold leaves authority intact'
}
