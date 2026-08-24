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
