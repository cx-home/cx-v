module platform

import code {
	caps_set_all,
	is_err_value,
	render_canonical,
}

import cx
import os

// store_admin_plane_test.v — the admin plane (§3.10–3.12): `status` (store
// stats), `gc` (compaction trigger), `mounts` (daemon-level enumeration). S3
// (RULED G1a/G3a 2026-08-08): the bearer/RBAC HTTP forms are retired — admin
// ops ride the gRPC edge (authorized by the per-call XSP-AUTH gate, covered
// by store_grpc_call_auth_test.v). This file pins the op SHAPES through the
// gRPC dispatch + the surviving profile core + the CX porcelain builtins.

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

// ap_ctx — a two-mount daemon in the OPEN posture (no [xsp [grants]] → data
// ops open, admin ops behind the mutual gate). The gRPC gate reads xsp_cfg;
// an empty grants set is the open/dev posture.
fn ap_ctx() ServeContext {
	caps_set_all()
	return ServeContext{
		mounts: {
			'docs':  store_open_impl('mem://ap-docs', '', '', false, true, map[string]string{})
			'audit': store_open_impl('mem://ap-audit', '', '', false, true, map[string]string{})
		}
	}
}

// a gRPC call carrying a valid CxCall credential for `did`/`seed` (admin ops
// need a DID-proven caller even in the open posture — the mutual-gate analog).
fn ap_grpc_call(method string, store string, did string, seed []u8) GrpcCall {
	msg := pb_encode_store_request(GrpcStoreRequest{
		store: store
	})
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

// ── §3.10 status: shape over the gRPC edge (admin caller) ─────────────────────

fn test_admin_status_shape() {
	mut s := new_service_state()
	s.mark_ready()
	ctx := ap_ctx()
	did, seed := ap_test_identity()
	st := grpc_dispatch(ap_grpc_call('Status', 'docs', did, seed), mut s, ctx)
	assert st.status.code == grpc_ok, 'admin status must be OK, got ${st.status.code}: ${st.status.message}'
	stm := pb_decode_objwire_response(st.frames[0]) or { panic('status response decode') }
	body := stm.body.bytestr()
	parsed := cx.parse(body) or { panic('status body must parse: ${err.msg()}') }
	el := parsed.elements[0]
	assert el is cx.Element && (el as cx.Element).name == 'status', 'body must be [status …]: ${body}'
	assert body.contains('backend='), 'status must report the backend: ${body}'
}

// an anonymous gRPC caller (no credential) is DENIED admin in the open posture
// (the mutual gate — data ops open, admin needs a DID-proven caller).
fn test_admin_status_anon_denied() {
	mut s := new_service_state()
	s.mark_ready()
	ctx := ap_ctx()
	deny := grpc_dispatch(ap_grpc_call('Status', 'docs', '', []u8{}), mut s, ctx)
	assert deny.status.code == grpc_unauthenticated, 'anon admin must be UNAUTHENTICATED(16), got ${deny.status.code}'
}

// ── §3.11 gc: shape over the gRPC edge ────────────────────────────────────────

fn test_admin_gc_shape() {
	mut s := new_service_state()
	s.mark_ready()
	caps_set_all()
	ctx := ap_ctx()
	did, seed := ap_test_identity()
	mount := ctx.mounts['docs'] or { panic('docs mount') }
	put := store_stdlib_builtin_inner('store-put-doc-text', [mount, store_str('[d [x "gc-me"]]')]) or {
		panic('put')
	}
	assert !is_err_value(put), 'seed put must succeed'
	gc := grpc_dispatch(ap_grpc_call('Gc', 'docs', did, seed), mut s, ctx)
	assert gc.status.code == grpc_ok, 'admin gc must be OK, got ${gc.status.code}: ${gc.status.message}'
	gm := pb_decode_objwire_response(gc.frames[0]) or { panic('gc response decode') }
	assert gm.body.bytestr().contains('gc-result'), 'gc body must be [gc-result …]: ${gm.body.bytestr()}'
}

// a flat file mount also supports gc (#290 — reclaimed=0, log compacted).
fn test_admin_gc_flat_mount() {
	mut s := new_service_state()
	s.mark_ready()
	caps_set_all()
	did, seed := ap_test_identity()
	flat_dir := os.join_path(os.temp_dir(), 'ap_flat_${os.getpid()}')
	os.rmdir_all(flat_dir) or {}
	defer {
		os.rmdir_all(flat_dir) or {}
	}
	ctx := ServeContext{
		mounts: {
			'flat': store_open_impl('document+file://${flat_dir}', '', '', false, true, map[string]string{})
		}
	}
	fgc := grpc_dispatch(ap_grpc_call('Gc', 'flat', did, seed), mut s, ctx)
	assert fgc.status.code == grpc_ok, 'gc on a flat file mount must succeed (#290), got ${fgc.status.code}'
	fm := pb_decode_objwire_response(fgc.frames[0]) or { panic('flat gc response decode') }
	assert fm.body.bytestr().contains('gc-result') && fm.body.bytestr().contains('reclaimed=0'), 'flat gc reports honestly: ${fm.body.bytestr()}'
}

// ── §3.12 mounts: enumeration shape over the gRPC edge ────────────────────────

fn test_mounts_shape() {
	mut s := new_service_state()
	s.mark_ready()
	ctx := ap_ctx()
	did, seed := ap_test_identity()
	mts := grpc_dispatch(ap_grpc_call('Mounts', '', did, seed), mut s, ctx)
	assert mts.status.code == grpc_ok, 'mounts must be OK, got ${mts.status.code}: ${mts.status.message}'
	mm := pb_decode_objwire_response(mts.frames[0]) or { panic('mounts response decode') }
	body := mm.body.bytestr()
	assert body.contains('name="audit"') && body.contains('name="docs"'), 'must enumerate both mounts: ${body}'
	assert body.index('name="audit"') or { -1 } < body.index('name="docs"') or { -1 }, 'mounts must be name-sorted: ${body}'
	assert body.contains('backend=') && body.contains('read=') && body.contains('write='), 'mounts must carry backend + capability flags: ${body}'
}

// ── the profile core: status/gc served on a mounted store ─────────────────────

fn test_profile_core_status_and_gc() {
	caps_set_all()
	local := store_open_impl('mem://ap-embed2', '', '', false, true, map[string]string{})
	st := svc_profile_route(ap_synth('GET', '/cx-store/v1/status'), local)
	assert ap_status(st) == 200, 'profile status must be 200, got ${ap_status(st)}'
	assert ap_body(st).contains('backend='), 'profile status must report backend'
	gc := svc_profile_route(ap_synth('POST', '/cx-store/v1/gc'), local)
	assert ap_status(gc) == 200, 'profile gc must be 200, got ${ap_status(gc)}: ${ap_body(gc)}'
	assert ap_body(gc).contains('gc-result')
}

// ap_synth builds a minimal pipeline="profile" request for the core.
fn ap_synth(method string, path string) cx.Element {
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
			cx.Attribute{
				name:  'pipeline'
				value: cx.ScalarValue('profile')
			},
		]
		items: [cx.Node(cx.Element{
			name: 'headers'
		})]
	}
}

// ── CX porcelain surface: local handles ───────────────────────────────────────

fn test_porcelain_mounts_local_is_honest_error() {
	caps_set_all()
	local := store_open_impl('mem://ap-local', '', '', false, true, map[string]string{})
	r := store_stdlib_builtin_inner('store-mounts', [local]) or { panic('mounts dispatch') }
	assert is_err_value(r), 'mounts on a local handle must error'
	assert svc_err_code(r) == 'cx-err:CXER1709', 'local mounts must be CXER1709, got ${svc_err_code(r)}'
}

// ap_test_identity mints a deterministic-per-process client identity (a fresh
// Ed25519 seed → its did:key). The daemon is in the open posture, so ANY
// DID-proven caller passes the admin mutual gate — the point is that a
// credential exists, not which principal.
fn ap_test_identity() (string, []u8) {
	seed := ap_seed32()
	did := did_key_from_seed(seed) or { panic('did:key from seed: ${err}') }
	return did, seed
}

fn ap_seed32() []u8 {
	mut b := []u8{len: 32}
	for i in 0 .. 32 {
		b[i] = u8((i * 7 + 3) & 0xff)
	}
	return b
}
