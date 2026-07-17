module code

import cx
import crypto.sha256
import net
import os
import time

// store_admin_plane_test.v — #248 admin plane (CSRP §3.10–3.12): `status`
// (store stats), `gc` (compaction trigger), `mounts` (daemon-level,
// tenant-filtered enumeration). Behavioral over svc_handle_request (the daemon
// pipeline: authN → admin RBAC → tenant → route), the embedded reference
// server (store_csrp_route), the gRPC dispatch (cross-transport parity), and
// the CX porcelain surface (store-status/store-gc/store-mounts builtins).

fn ap_hash(t string) string {
	return sha256.sum256(t.bytes()).hex()
}

fn ap_req(method string, path string, token string) cx.Element {
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

fn ap_status(n cx.Node) int {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'status' {
				return cx.scalar_value_str_public(a.value).int()
			}
		}
	}
	return 0
}

fn ap_body(n cx.Node) string {
	return svc_response_body(n)
}

// ap_ctx — a two-mount daemon with auth enforced: four static tokens covering
// every role, tenants scoped so 'admin-docs' sees only the docs store.
fn ap_ctx() ServeContext {
	caps_set_all()
	return ServeContext{
		mounts: {
			'docs':  store_open_impl('mem://ap-docs', '', '', false, true, map[string]string{})
			'audit': store_open_impl('mem://ap-audit', '', '', false, true, map[string]string{})
		}
		auth:   AuthContext{
			enforce:       true
			static_tokens: [
				StaticToken{
					id:          'root'
					secret_hash: ap_hash('root-secret')
					roles:       ['admin']
					tenant:      '*'
				},
				StaticToken{
					id:          'admin-docs'
					secret_hash: ap_hash('admin-docs-secret')
					roles:       ['admin']
					tenant:      'docs'
				},
				StaticToken{
					id:          'rd'
					secret_hash: ap_hash('rd-secret')
					roles:       ['reader']
					tenant:      '*'
				},
				StaticToken{
					id:          'wr'
					secret_hash: ap_hash('wr-secret')
					roles:       ['writer']
					tenant:      '*'
				},
				StaticToken{
					id:          'mx'
					secret_hash: ap_hash('mx-secret')
					roles:       ['metrics']
					tenant:      '*'
				},
			]
		}
	}
}

// ── App C: admin permission mapping ───────────────────────────────────────────

fn test_admin_ops_map_to_admin_permission() {
	assert svc_permission_for_op('status') == 'admin'
	assert svc_permission_for_op('gc') == 'admin'
	assert svc_permission_for_op('mounts') == 'admin'
}

// ── §3.10 status + §3.11 gc: RBAC deny lanes + admin success ──────────────────

fn test_admin_status_rbac_and_shape() {
	mut s := new_service_state()
	s.mark_ready()
	ctx := ap_ctx()
	// unauthenticated → 401 CXER1702
	anon := svc_handle_request(ap_req('GET', '/cx-store/v1/docs/status', ''), mut s, ctx)
	assert ap_status(anon) == 401, 'anon status must be 401, got ${ap_status(anon)}'
	// reader / writer / metrics → 403 CXER1703 (admin plane is admin-only)
	for tok in ['rd-secret', 'wr-secret', 'mx-secret'] {
		r := svc_handle_request(ap_req('GET', '/cx-store/v1/docs/status', tok), mut s, ctx)
		assert ap_status(r) == 403, '${tok} on status must be 403, got ${ap_status(r)}'
		assert ap_body(r).contains('CXER1703'), '${tok} deny must carry CXER1703'
	}
	// admin → 200 with the porcelain [status …] element
	ok := svc_handle_request(ap_req('GET', '/cx-store/v1/docs/status', 'root-secret'), mut
		s, ctx)
	assert ap_status(ok) == 200, 'admin status must be 200, got ${ap_status(ok)}: ${ap_body(ok)}'
	parsed := cx.parse(ap_body(ok)) or { panic('status body must parse: ${err.msg()}') }
	el := parsed.elements[0]
	assert el is cx.Element && (el as cx.Element).name == 'status', 'body must be [status …]: ${ap_body(ok)}'
	assert ap_body(ok).contains('backend='), 'status must report the backend'
}

fn test_admin_gc_rbac_success_and_unsupported() {
	mut s := new_service_state()
	s.mark_ready()
	caps_set_all()
	mut ctx := ap_ctx()
	// stage a doc + delete it so gc has something legitimate to walk (mem:// is a
	// live object-graph store — the sink IS the store).
	mount := ctx.mounts['docs'] or { panic('docs mount') }
	put := store_stdlib_builtin_inner('store-put-doc-text', [mount,
		store_str('[d [x "gc-me"]]')]) or { panic('put') }
	assert !is_err_value(put), 'seed put must succeed'
	// reader → 403
	deny := svc_handle_request(ap_req('POST', '/cx-store/v1/docs/gc', 'rd-secret'), mut s,
		ctx)
	assert ap_status(deny) == 403, 'reader gc must be 403, got ${ap_status(deny)}'
	// admin → 200 [gc-result reclaimed=… objects=…]
	ok := svc_handle_request(ap_req('POST', '/cx-store/v1/docs/gc', 'root-secret'), mut s,
		ctx)
	assert ap_status(ok) == 200, 'admin gc must be 200, got ${ap_status(ok)}: ${ap_body(ok)}'
	assert ap_body(ok).contains('gc-result'), 'gc body must be [gc-result …]: ${ap_body(ok)}'
	// a mount on the flat file document model also supports gc now (#290 —
	// store.md §15 lists gc under write for file/local): flat semantics reclaim
	// nothing sub-doc (every present doc is a root) and compact the append log.
	flat_dir := os.join_path(os.temp_dir(), 'ap_flat_${os.getpid()}')
	os.rmdir_all(flat_dir) or {}
	defer {
		os.rmdir_all(flat_dir) or {}
	}
	ctx = ServeContext{
		mounts: {
			'flat': store_open_impl('document+file://${flat_dir}', '', '', false, true, map[string]string{})
		}
		auth:   ctx.auth
	}
	fok := svc_handle_request(ap_req('POST', '/cx-store/v1/flat/gc', 'root-secret'), mut s,
		ctx)
	assert ap_status(fok) == 200, 'gc on a flat file mount must succeed (#290), got ${ap_status(fok)}: ${ap_body(fok)}'
	assert ap_body(fok).contains('gc-result') && ap_body(fok).contains('reclaimed=0'), 'flat gc reports honestly: ${ap_body(fok)}'
}

// ── §3.12 mounts: RBAC + tenant filtering + shape ─────────────────────────────

fn test_mounts_rbac_tenant_filter_and_shape() {
	mut s := new_service_state()
	s.mark_ready()
	ctx := ap_ctx()
	// unauthenticated → 401; non-admin → 403
	anon := svc_handle_request(ap_req('GET', '/cx-store/v1/mounts', ''), mut s, ctx)
	assert ap_status(anon) == 401, 'anon mounts must be 401, got ${ap_status(anon)}'
	deny := svc_handle_request(ap_req('GET', '/cx-store/v1/mounts', 'wr-secret'), mut s,
		ctx)
	assert ap_status(deny) == 403, 'writer mounts must be 403, got ${ap_status(deny)}'
	// tenant '*' admin sees BOTH mounts, sorted by name, with backend + flags
	all := svc_handle_request(ap_req('GET', '/cx-store/v1/mounts', 'root-secret'), mut s,
		ctx)
	assert ap_status(all) == 200
	body := ap_body(all)
	assert body.contains('name="audit"') && body.contains('name="docs"'), 'tenant * must enumerate both mounts: ${body}'
	assert body.index('name="audit"') or { -1 } < body.index('name="docs"') or { -1 }, 'mounts must be name-sorted: ${body}'
	assert body.contains('backend=') && body.contains('read=') && body.contains('write='), 'mounts must carry backend + capability flags: ${body}'
	// tenant-scoped admin sees ONLY its tenant's mounts — store B's NAME never
	// appears (no cross-tenant existence probing).
	scoped := svc_handle_request(ap_req('GET', '/cx-store/v1/mounts', 'admin-docs-secret'), mut
		s, ctx)
	assert ap_status(scoped) == 200
	sbody := ap_body(scoped)
	assert sbody.contains('name="docs"'), 'tenant-scoped admin must see its mount: ${sbody}'
	assert !sbody.contains('audit'), 'tenant-scoped admin must NOT learn of other mounts: ${sbody}'
}

fn test_mounts_unsupported_on_embedded_reference_server() {
	caps_set_all()
	local := store_open_impl('mem://ap-embedded', '', '', false, true, map[string]string{})
	r := store_csrp_route(ap_req('GET', '/cx-store/v1/mounts', ''), local)
	assert ap_status(r) == 404, 'mounts on the embedded reference server must be 404, got ${ap_status(r)}'
	assert ap_body(r).contains('CXER1709'), 'embedded mounts must carry CXER1709'
}

// ── embedded reference server: status/gc are served (protocol-complete) ───────

fn test_embedded_status_and_gc() {
	caps_set_all()
	local := store_open_impl('mem://ap-embed2', '', '', false, true, map[string]string{})
	st := store_csrp_route(ap_req('GET', '/cx-store/v1/status', ''), local)
	assert ap_status(st) == 200, 'embedded status must be 200, got ${ap_status(st)}'
	assert ap_body(st).contains('backend='), 'embedded status must report backend'
	gc := store_csrp_route(ap_req('POST', '/cx-store/v1/gc', ''), local)
	assert ap_status(gc) == 200, 'embedded gc must be 200, got ${ap_status(gc)}: ${ap_body(gc)}'
	assert ap_body(gc).contains('gc-result')
}

// ── gRPC parity: same pipeline, same RBAC, same elements ──────────────────────

fn ap_grpc_call(method string, store string, token string) GrpcCall {
	mut hdrs := {
		':path': '/cxstore.v1.CxStore/${method}'
	}
	if token != '' {
		hdrs['authorization'] = 'Bearer ${token}'
	}
	return GrpcCall{
		stream_id: 1
		headers:   hdrs
		message:   pb_encode_store_request(GrpcStoreRequest{
			store: store
		})
	}
}

fn test_admin_grpc_parity() {
	mut s := new_service_state()
	s.mark_ready()
	ctx := ap_ctx()
	// RBAC parity: reader denied with PERMISSION_DENIED(7) + exact cx-err trailer
	deny := grpc_dispatch(ap_grpc_call('Status', 'docs', 'rd-secret'), mut s, ctx)
	assert deny.status.code == 7, 'grpc reader status must be PERMISSION_DENIED(7), got ${deny.status.code}'
	assert deny.status.cx_err == 'cx-err:CXER1703', 'grpc deny must carry the exact CXER1703 trailer, got ${deny.status.cx_err}'
	// Status parity: same [status …] element the CSRP transport returns
	st := grpc_dispatch(ap_grpc_call('Status', 'docs', 'root-secret'), mut s, ctx)
	assert st.status.code == 0, 'grpc admin status must be OK, got ${st.status.code}: ${st.status.message}'
	stm := pb_decode_objwire_response(st.frames[0]) or { panic('status response decode') }
	csrp := svc_handle_request(ap_req('GET', '/cx-store/v1/docs/status', 'root-secret'), mut
		s, ctx)
	assert stm.body.bytestr() == ap_body(csrp), 'gRPC and CSRP status must return the identical element'
	// Mounts parity incl. tenant filter
	mts := grpc_dispatch(ap_grpc_call('Mounts', '', 'admin-docs-secret'), mut s, ctx)
	assert mts.status.code == 0, 'grpc mounts must be OK, got ${mts.status.code}: ${mts.status.message}'
	mm := pb_decode_objwire_response(mts.frames[0]) or { panic('mounts response decode') }
	assert mm.body.bytestr().contains('name="docs"') && !mm.body.bytestr().contains('audit'), 'grpc mounts must be tenant-filtered: ${mm.body.bytestr()}'
	// Gc parity on a flat file mount: succeeds since #290 (flat semantics —
	// reclaimed=0, log compacted), same as the CSRP surface.
	gflat_dir := os.join_path(os.temp_dir(), 'ap_gflat_${os.getpid()}')
	os.rmdir_all(gflat_dir) or {}
	defer {
		os.rmdir_all(gflat_dir) or {}
	}
	ctx2 := ServeContext{
		mounts: {
			'flat': store_open_impl('document+file://${gflat_dir}', '', '', false, true, map[string]string{})
		}
		auth:   ctx.auth
	}
	fgc := grpc_dispatch(ap_grpc_call('Gc', 'flat', 'root-secret'), mut s, ctx2)
	assert fgc.status.code == 0, 'grpc gc on a flat file mount must succeed (#290), got ${fgc.status.code}: ${fgc.status.message}'
	fm := pb_decode_objwire_response(fgc.frames[0]) or { panic('flat gc response decode') }
	assert fm.body.bytestr().contains('gc-result'), 'grpc flat gc returns the porcelain element: ${fm.body.bytestr()}'
}

// ── CX porcelain surface: local handles ───────────────────────────────────────

fn test_porcelain_mounts_local_is_honest_error() {
	caps_set_all()
	local := store_open_impl('mem://ap-local', '', '', false, true, map[string]string{})
	r := store_stdlib_builtin_inner('store-mounts', [local]) or { panic('mounts dispatch') }
	assert is_err_value(r), 'mounts on a local handle must error'
	assert svc_err_code(r) == 'cx-err:CXER1709', 'local mounts must be CXER1709, got ${svc_err_code(r)}'
}

// ── LIVE end-to-end: the CX porcelain over real cx-store:// handles ───────────
// Spawns `cx store-serve` (one mem mount, gRPC enabled, no auth — the RBAC deny
// lanes are proven hermetically above) and drives [$store:status] / [$store:gc]
// / [$store:mounts] through BOTH transports: the HTTP CSRP client and the gRPC
// client — the live consumers of store_remote_admin / csrp_client_admin /
// grpc_client_admin. Skips when the cx binary is absent (same posture as
// store_grpc_live_test.v).

fn ap_live_free_port() int {
	mut l := net.listen_tcp(.ip, '127.0.0.1:0') or { return 0 }
	port := l.addr() or { return 0 }.port() or { return 0 }
	l.close() or {}
	return port
}

fn test_admin_plane_live_end_to_end() {
	bin := os.real_path(os.join_path(os.dir(os.dir(@FILE)), 'target', 'cx'))
	if !os.exists(bin) {
		eprintln('SKIP: cx binary not found at ${bin} — run `make build-vcx`')
		return
	}
	caps_set_all()
	cport := ap_live_free_port()
	gport := ap_live_free_port()
	if cport == 0 || gport == 0 || cport == gport {
		eprintln('SKIP: could not allocate ports')
		return
	}
	cfg := os.join_path(os.temp_dir(), 'cx_admin_live_${cport}.cx')
	os.write_file(cfg, '[cxstore-service\n  [bind addr="127.0.0.1:${cport}"]\n  [grpc enabled=true addr="127.0.0.1:${gport}"]\n  [stores\n    [store name="t" url="mem://ap-live"]]]\n') or {
		eprintln('SKIP: write cfg: ${err}')
		return
	}
	defer {
		os.rm(cfg) or {}
	}
	pid_s := os.execute('${bin} store-serve --config ${cfg} --allow-net=127.0.0.1:${cport} --allow-net=127.0.0.1:${gport} >/tmp/cx-admin-live.${cport}.out 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx store-serve')
		return
	}
	pid := pid_s.output.trim_space()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(700 * time.millisecond) // let both listeners bind

	// HTTP CSRP handle → status / gc / mounts through the porcelain builtins.
	h := store_open_impl('cx-store+http://127.0.0.1:${cport}/t/', '', '', false, true,
		map[string]string{})
	assert !is_err_value(h), 'live open must succeed: ${svc_err_msg(h)}'
	st := store_stdlib_builtin_inner('store-status', [h]) or { panic('status dispatch') }
	assert !is_err_value(st), 'live status must succeed: ${svc_err_msg(st)}'
	assert st is cx.Element && (st as cx.Element).name == 'status', 'live status must return [status …]: ${render_canonical(st)}'
	assert render_canonical(st).contains('backend='), 'live status must report the backend'
	gc := store_stdlib_builtin_inner('store-gc', [h]) or { panic('gc dispatch') }
	assert !is_err_value(gc), 'live gc must succeed: ${svc_err_msg(gc)}'
	assert gc is cx.Element && (gc as cx.Element).name == 'gc-result', 'live gc must return [gc-result …]: ${render_canonical(gc)}'
	mts := store_stdlib_builtin_inner('store-mounts', [h]) or { panic('mounts dispatch') }
	assert !is_err_value(mts), 'live mounts must succeed: ${svc_err_msg(mts)}'
	mbody := render_canonical(mts)
	assert mts is cx.Element && (mts as cx.Element).name == 'mounts', 'live mounts must return [mounts …]: ${mbody}'
	assert mbody.contains('name="t"') || mbody.contains('name=t'), 'live mounts must enumerate the daemon mount: ${mbody}'

	// gRPC handle → the same elements over the other transport (parity).
	hg := store_open_impl('cx-store+grpc://127.0.0.1:${gport}/t/', '', '', false, true,
		map[string]string{})
	assert !is_err_value(hg), 'live grpc open must succeed: ${svc_err_msg(hg)}'
	stg := store_stdlib_builtin_inner('store-status', [hg]) or { panic('grpc status dispatch') }
	assert !is_err_value(stg), 'live grpc status must succeed: ${svc_err_msg(stg)}'
	assert render_canonical(stg) == render_canonical(st), 'gRPC and CSRP status must return the identical element'
	mtg := store_stdlib_builtin_inner('store-mounts', [hg]) or { panic('grpc mounts dispatch') }
	assert !is_err_value(mtg), 'live grpc mounts must succeed: ${svc_err_msg(mtg)}'
	assert render_canonical(mtg) == render_canonical(mts), 'gRPC and CSRP mounts must return the identical element'
}
