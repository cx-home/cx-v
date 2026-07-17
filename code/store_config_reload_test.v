module code

import cx
import crypto.sha256
import net
import os
import time

// store_config_reload_test.v — #251 runtime config reload (§2.6, CSRP §3.13).
// Behavioral over the reload engine (svc_reload_config: validate-then-swap,
// fail-closed, restart-required refusal), the daemon pipeline
// (svc_handle_request: RBAC lanes + atomic auth rotation observed by the NEXT
// request), the gRPC Reload parity, the capabilities admin-ops advert, the
// limiter set_config bucket preservation, the reload metric, the CX porcelain
// (store-config-reload), and a LIVE end-to-end (spawn `cx store-serve`, rotate
// a token via [$store:config-reload] over cx-store://, prove the old token
// stops authenticating and SIGHUP drives the same path).

fn cr_hash(t string) string {
	return sha256.sum256(t.bytes()).hex()
}

fn cr_req(method string, path string, token string) cx.Element {
	mut hdrs := []cx.Node{}
	if token != '' {
		hdrs << cx.Node(cx.Element{
			name:  'header'
			attrs: [
				cx.Attribute{
					name:  'name'
					value: cx.ScalarValue('Authorization')
				},
				cx.Attribute{
					name:  'value'
					value: cx.ScalarValue('Bearer ${token}')
				},
			]
		})
	}
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
		items: [
			cx.Node(cx.Element{
				name:  'headers'
				items: hdrs
			}),
		]
	}
}

fn cr_status(n cx.Node) int {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'status' {
				return cx.scalar_value_str_public(a.value).int()
			}
		}
	}
	return 0
}

fn cr_body(n cx.Node) string {
	return svc_response_body(n)
}

// cr_config renders a daemon config with two static tokens: a stable admin
// (never rotated — reload authorization must survive the rotation it performs)
// and a `worker` token whose secret the rotation tests swap.
fn cr_config(bind string, worker_secret string) string {
	return '[cxstore-service [bind addr="${bind}"] [stores [store name="docs" url="mem://cr-docs"]] [auth [static [token id="root" secret-hash="sha256:${cr_hash('root-secret')}" roles="admin" tenant="*"] [token id="wk" secret-hash="sha256:${cr_hash(worker_secret)}" roles="writer" tenant="*"]]]]'
}

// cr_harness builds the hermetic daemon: a real temp config FILE (the reload
// source), the box seeded from it, and a ServeContext wired exactly as the CLI
// wires it (cfgbox + reloader sharing one closure).
struct CrHarness {
	path string
mut:
	box &SvcConfigBox
	ctx ServeContext
}

fn cr_harness(name string) CrHarness {
	caps_set_all()
	path := os.join_path(os.temp_dir(), 'cr_${name}_${os.getpid()}.cx')
	src := cr_config('127.0.0.1:19999', 'wk-secret')
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
		ctx:  ServeContext{
			mounts:   {
				'docs': store_open_impl('mem://cr-docs', '', '', false, true, map[string]string{})
			}
			auth:     cfg.auth.context
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

// ── App C: permission mapping + RBAC lanes ────────────────────────────────────

fn test_reload_permission_is_admin() {
	assert svc_permission_for_op('config-reload') == 'admin'
}

fn test_reload_rbac_lanes() {
	mut s := new_service_state()
	s.mark_ready()
	h := cr_harness('rbac')
	defer {
		h.cleanup()
	}
	anon := svc_handle_request(cr_req('POST', '/cx-store/v1/config-reload', ''), mut s,
		h.ctx)
	assert cr_status(anon) == 401, 'anon config-reload must be 401, got ${cr_status(anon)}'
	deny := svc_handle_request(cr_req('POST', '/cx-store/v1/config-reload', 'wk-secret'), mut
		s, h.ctx)
	assert cr_status(deny) == 403, 'writer config-reload must be 403, got ${cr_status(deny)}'
	assert cr_body(deny).contains('CXER1703')
	ok := svc_handle_request(cr_req('POST', '/cx-store/v1/config-reload', 'root-secret'), mut
		s, h.ctx)
	assert cr_status(ok) == 200, 'admin config-reload must be 200, got ${cr_status(ok)}: ${cr_body(ok)}'
	assert cr_body(ok).contains('applied=false'), 'unchanged file must be a no-op success: ${cr_body(ok)}'
}

fn test_reload_unsupported_without_reloader() {
	mut s := new_service_state()
	s.mark_ready()
	h := cr_harness('nowire')
	defer {
		h.cleanup()
	}
	ctx := ServeContext{
		...h.ctx
		reloader: unsafe { nil }
	}
	r := svc_handle_request(cr_req('POST', '/cx-store/v1/config-reload', 'root-secret'), mut
		s, ctx)
	assert cr_status(r) == 404, 'config-reload without a wired reloader must be 404, got ${cr_status(r)}'
	assert cr_body(r).contains('CXER1709')
}

// ── §3.13 core semantics over the daemon pipeline ─────────────────────────────

fn test_reload_token_rotation_atomic() {
	mut s := new_service_state()
	s.mark_ready()
	h := cr_harness('rotate')
	defer {
		h.cleanup()
	}
	// pre-rotation: the worker token authenticates (a data op it is allowed)
	pre := svc_handle_request(cr_req('POST', '/cx-store/v1/docs/list', 'wk-secret'), mut
		s, h.ctx)
	assert cr_status(pre) == 200, 'pre-rotation worker op must be 200, got ${cr_status(pre)}: ${cr_body(pre)}'
	// rotate the worker secret in the config FILE, trigger reload as admin
	os.write_file(h.path, cr_config('127.0.0.1:19999', 'wk-secret-v2')) or { panic('rewrite') }
	rl := svc_handle_request(cr_req('POST', '/cx-store/v1/config-reload', 'root-secret'), mut
		s, h.ctx)
	assert cr_status(rl) == 200, 'reload must be 200, got ${cr_status(rl)}: ${cr_body(rl)}'
	assert cr_body(rl).contains('applied=true'), 'rotation reload must apply: ${cr_body(rl)}'
	assert cr_body(rl).contains('generation=1')
	assert cr_body(rl).contains('auth'), 'changed list must name auth: ${cr_body(rl)}'
	// the NEXT request with the old token is 401 (CXER1702); the new one works
	old := svc_handle_request(cr_req('POST', '/cx-store/v1/docs/list', 'wk-secret'), mut
		s, h.ctx)
	assert cr_status(old) == 401, 'rotated-away token must 401, got ${cr_status(old)}: ${cr_body(old)}'
	assert cr_body(old).contains('CXER1702')
	new_t := svc_handle_request(cr_req('POST', '/cx-store/v1/docs/list', 'wk-secret-v2'), mut
		s, h.ctx)
	assert cr_status(new_t) == 200, 'rotated-in token must authenticate, got ${cr_status(new_t)}: ${cr_body(new_t)}'
	// the admin credential survived the rotation it performed
	again := svc_handle_request(cr_req('POST', '/cx-store/v1/config-reload', 'root-secret'), mut
		s, h.ctx)
	assert cr_status(again) == 200
	assert cr_body(again).contains('applied=false'), 'second reload of the same file is a no-op'
}

fn test_reload_invalid_candidate_keeps_running_config() {
	mut s := new_service_state()
	s.mark_ready()
	h := cr_harness('invalid')
	defer {
		h.cleanup()
	}
	os.write_file(h.path, '[cxstore-service [nonsense-section x=1]]') or { panic('rewrite') }
	r := svc_handle_request(cr_req('POST', '/cx-store/v1/config-reload', 'root-secret'), mut
		s, h.ctx)
	assert cr_status(r) == 400, 'invalid candidate must be 400, got ${cr_status(r)}: ${cr_body(r)}'
	assert cr_body(r).contains('CXER1711'), 'invalid candidate must carry CXER1711: ${cr_body(r)}'
	// the running config is demonstrably still in force
	ok := svc_handle_request(cr_req('POST', '/cx-store/v1/docs/list', 'wk-secret'), mut
		s, h.ctx)
	assert cr_status(ok) == 200, 'running config must survive an invalid candidate'
	mut box := h.box
	assert box.generation() == 0, 'a refused reload must not bump the generation'
}

fn test_reload_restart_required_refused_whole() {
	mut s := new_service_state()
	s.mark_ready()
	h := cr_harness('restart')
	defer {
		h.cleanup()
	}
	// candidate changes bind (restart-only) AND rotates the worker token (hot):
	// the refusal must name bind and apply NOTHING — the old token stays valid.
	os.write_file(h.path, cr_config('127.0.0.1:20000', 'wk-secret-v2')) or { panic('rewrite') }
	r := svc_handle_request(cr_req('POST', '/cx-store/v1/config-reload', 'root-secret'), mut
		s, h.ctx)
	assert cr_status(r) == 400, 'restart-required candidate must be 400, got ${cr_status(r)}: ${cr_body(r)}'
	assert cr_body(r).contains('CXER1712'), 'must carry CXER1712: ${cr_body(r)}'
	assert cr_body(r).contains('bind'), 'refusal must NAME the offending section: ${cr_body(r)}'
	still := svc_handle_request(cr_req('POST', '/cx-store/v1/docs/list', 'wk-secret'), mut
		s, h.ctx)
	assert cr_status(still) == 200, 'the hot change riding a refused candidate must NOT apply (all-or-nothing)'
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
	// swap to a LARGER burst: the existing bucket must be preserved (still
	// empty), never re-primed to the new burst — set_config is not a refill.
	l.set_config(LimitConfig{
		per_principal_rate:  0.0001
		per_principal_burst: 50.0
	})
	assert !l.allow_principal_rate('p1'), 'reload must preserve the drained bucket, not refill it'
	// a NEW principal gets the new burst
	assert l.allow_principal_rate('p2'), 'new principals admit under the new config'
}

// ── capabilities advert (§3.1 admin-ops) ──────────────────────────────────────

fn test_capabilities_admin_ops_advert() {
	mut s := new_service_state()
	s.mark_ready()
	h := cr_harness('advert')
	defer {
		h.cleanup()
	}
	// daemon with a wired reloader advertises config-reload
	caps := svc_handle_request(cr_req('GET', '/cx-store/v1/capabilities', ''), mut s,
		h.ctx)
	body := cr_body(caps)
	assert body.contains('[admin-ops "status" "gc" "mounts" "config-reload"]'), 'daemon advert must list config-reload: ${body}'
	// without a reloader the op is not advertised (and 404s, proven above)
	ctx2 := ServeContext{
		...h.ctx
		reloader: unsafe { nil }
	}
	caps2 := svc_handle_request(cr_req('GET', '/cx-store/v1/capabilities', ''), mut s,
		ctx2)
	assert cr_body(caps2).contains('[admin-ops "status" "gc" "mounts"]'), 'reloader-less advert lists the routed ops'
	assert !cr_body(caps2).contains('config-reload'), 'an un-routed op must not be advertised'
	// embedded reference server: status/gc only
	local := store_open_impl('mem://cr-embed', '', '', false, true, map[string]string{})
	ec := store_csrp_route(cr_req('GET', '/cx-store/v1/capabilities', ''), local)
	assert cr_body(ec).contains('[admin-ops "status" "gc"]'), 'embedded advert must list status/gc only: ${cr_body(ec)}'
}

// ── gRPC parity (Reload → the SAME pipeline) ──────────────────────────────────

fn cr_grpc_call(method string, token string) GrpcCall {
	mut hdrs := {
		':path': '/cxstore.v1.CxStore/${method}'
	}
	if token != '' {
		hdrs['authorization'] = 'Bearer ${token}'
	}
	return GrpcCall{
		stream_id: 1
		headers:   hdrs
		message:   pb_encode_store_request(GrpcStoreRequest{})
	}
}

fn test_reload_grpc_parity() {
	mut s := new_service_state()
	s.mark_ready()
	h := cr_harness('grpc')
	defer {
		h.cleanup()
	}
	// RBAC parity: writer denied with PERMISSION_DENIED(7) + exact trailer
	deny := grpc_dispatch(cr_grpc_call('Reload', 'wk-secret'), mut s, h.ctx)
	assert deny.status.code == 7, 'grpc writer Reload must be PERMISSION_DENIED(7), got ${deny.status.code}'
	assert deny.status.cx_err == 'cx-err:CXER1703'
	// no-op success parity: the same [config-reload …] element CSRP returns
	ok := grpc_dispatch(cr_grpc_call('Reload', 'root-secret'), mut s, h.ctx)
	assert ok.status.code == 0, 'grpc admin Reload must be OK, got ${ok.status.code}: ${ok.status.message}'
	om := pb_decode_objwire_response(ok.frames[0]) or { panic('reload response decode') }
	csrp := svc_handle_request(cr_req('POST', '/cx-store/v1/config-reload', 'root-secret'), mut
		s, h.ctx)
	assert om.body.bytestr() == cr_body(csrp), 'gRPC and CSRP reload must return the identical element'
	// restart-required refusal parity: INVALID_ARGUMENT(3) + exact CXER1712
	os.write_file(h.path, cr_config('127.0.0.1:20001', 'wk-secret')) or { panic('rewrite') }
	ref := grpc_dispatch(cr_grpc_call('Reload', 'root-secret'), mut s, h.ctx)
	assert ref.status.code == 3, 'grpc restart-required must be INVALID_ARGUMENT(3), got ${ref.status.code}'
	assert ref.status.cx_err == 'cx-err:CXER1712', 'grpc refusal must carry CXER1712, got ${ref.status.cx_err}'
}

// ── observability: one metric sample per attempt ──────────────────────────────

fn test_reload_metric_outcomes() {
	mut s := new_service_state()
	s.mark_ready()
	h := cr_harness('metric')
	defer {
		h.cleanup()
	}
	// applied → noop → invalid
	os.write_file(h.path, cr_config('127.0.0.1:19999', 'wk-secret-v2')) or { panic('rewrite') }
	_ := svc_handle_request(cr_req('POST', '/cx-store/v1/config-reload', 'root-secret'), mut
		s, h.ctx)
	_ := svc_handle_request(cr_req('POST', '/cx-store/v1/config-reload', 'root-secret'), mut
		s, h.ctx)
	os.write_file(h.path, 'not a config') or { panic('rewrite') }
	_ := svc_handle_request(cr_req('POST', '/cx-store/v1/config-reload', 'root-secret'), mut
		s, h.ctx)
	mut m := h.ctx.metrics
	exp := m.render_prometheus()
	assert exp.contains('cxstore_config_reload_total{outcome="applied"} 1'), 'applied sample missing:\n${exp}'
	assert exp.contains('cxstore_config_reload_total{outcome="noop"} 1'), 'noop sample missing:\n${exp}'
	assert exp.contains('cxstore_config_reload_total{outcome="invalid"} 1'), 'invalid sample missing:\n${exp}'
}

// ── CX porcelain: local handles are an honest error ───────────────────────────

fn test_porcelain_config_reload_local_is_honest_error() {
	caps_set_all()
	local := store_open_impl('mem://cr-local', '', '', false, true, map[string]string{})
	r := store_stdlib_builtin_inner('store-config-reload', [local]) or { panic('dispatch') }
	assert is_err_value(r), 'config-reload on a local handle must error'
	assert svc_err_code(r) == 'cx-err:CXER1709', 'local config-reload must be CXER1709, got ${svc_err_code(r)}'
}

// ── LIVE end-to-end: [$store:config-reload] + SIGHUP against a real daemon ────
// Spawns `cx store-serve` with auth enforced, rotates the worker token in the
// config file, triggers reload via the CX porcelain over cx-store:// (HTTP),
// proves the old token stops authenticating, then rotates AGAIN via SIGHUP —
// both triggers driving the one shared path. Skips without the cx binary.

fn cr_live_free_port() int {
	mut l := net.listen_tcp(.ip, '127.0.0.1:0') or { return 0 }
	port := l.addr() or { return 0 }.port() or { return 0 }
	l.close() or {}
	return port
}

fn test_config_reload_live_end_to_end() {
	bin := os.real_path(os.join_path(os.dir(os.dir(@FILE)), 'target', 'cx'))
	if !os.exists(bin) {
		eprintln('SKIP: cx binary not found at ${bin} — run `make build-vcx`')
		return
	}
	caps_set_all()
	cport := cr_live_free_port()
	if cport == 0 {
		eprintln('SKIP: no free port')
		return
	}
	dir := os.join_path(os.temp_dir(), 'cr_live_${os.getpid()}')
	os.rmdir_all(dir) or {}
	os.mkdir_all(dir) or { panic('mkdir') }
	defer {
		os.rmdir_all(dir) or {}
	}
	cfgp := os.join_path(dir, 'cxstore.service.cx')
	os.write_file(cfgp, cr_config('127.0.0.1:${cport}', 'wk-secret')) or { panic('write cfg') }
	pid_s := os.execute('${bin} store-serve --config ${cfgp} --allow-all >/tmp/cx-reload-live.${cport}.out 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx store-serve')
		return
	}
	pid := pid_s.output.trim_space()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	// wait for readiness
	mut up := false
	for _ in 0 .. 100 {
		r, _, ok := remote_http('GET', 'http://127.0.0.1:${cport}/cx-store/v1/ready', [][]string{},
			[]u8{})
		if ok && r.status == 200 && r.body.bytestr().contains('[accepting true]') {
			up = true
			break
		}
		time.sleep(100 * time.millisecond)
	}
	if !up {
		eprintln('SKIP: daemon did not become ready (log: /tmp/cx-reload-live.${cport}.out)')
		return
	}
	// worker token works; admin handle drives the reload
	wk_url := 'cx-store+http://wk-secret@127.0.0.1:${cport}/docs'
	root_url := 'cx-store+http://root-secret@127.0.0.1:${cport}/docs'
	wk := store_open_impl(wk_url, '', '', false, true, map[string]string{})
	assert !is_err_value(wk), 'worker open must succeed: ${svc_err_text(wk)}'
	pre := store_stdlib_builtin_inner('store-list-docs', [wk]) or { cx.Node(cx.ScalarNode{}) }
	assert !is_err_value(pre), 'pre-rotation worker list must succeed: ${svc_err_text(pre)}'
	root := store_open_impl(root_url, '', '', false, true, map[string]string{})
	assert !is_err_value(root), 'admin open must succeed: ${svc_err_text(root)}'
	// rotate wk → v2, trigger via the porcelain (the live consumer of
	// store_remote_admin/csrp_client_admin for this op)
	os.write_file(cfgp, cr_config('127.0.0.1:${cport}', 'wk-secret-v2')) or { panic('rewrite') }
	rl := store_stdlib_builtin_inner('store-config-reload', [root]) or { panic('reload dispatch') }
	assert !is_err_value(rl), 'live config-reload must succeed: ${svc_err_text(rl)}'
	rls := cx.cx_emit_node_str(rl, true)
	assert rls.contains('applied=true'), 'live reload must apply: ${rls}'
	// old worker token now 401s → surfaces as the store auth error
	post := store_stdlib_builtin_inner('store-list-docs', [wk]) or { cx.Node(cx.ScalarNode{}) }
	assert is_err_value(post), 'rotated-away token must stop authenticating'
	// SIGHUP drives the SAME path: rotate wk → v3 by signal
	os.write_file(cfgp, cr_config('127.0.0.1:${cport}', 'wk-secret-v3')) or { panic('rewrite') }
	os.execute('kill -HUP ${pid}')
	mut hup_ok := false
	wk3_url := 'cx-store+http://wk-secret-v3@127.0.0.1:${cport}/docs'
	for _ in 0 .. 50 {
		time.sleep(100 * time.millisecond)
		wk3 := store_open_impl(wk3_url, '', '', false, true, map[string]string{})
		if is_err_value(wk3) {
			continue
		}
		r3 := store_stdlib_builtin_inner('store-list-docs', [wk3]) or { cx.Node(cx.ScalarNode{}) }
		if !is_err_value(r3) {
			hup_ok = true
			break
		}
	}
	assert hup_ok, 'SIGHUP must apply the v3 rotation (log: /tmp/cx-reload-live.${cport}.out)'
}
