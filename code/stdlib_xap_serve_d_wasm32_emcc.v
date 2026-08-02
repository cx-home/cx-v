module code

import cx

// stdlib_xap_serve_d_wasm32_emcc.v — wasm32_emcc build stub for `[$xap:serve]`.
//
// The real cx-xap web bridge (stdlib_xap_serve_notd_wasm32_emcc.v) binds the
// picoev listener, which is not linked under `-d wasm32_emcc` (same rationale
// as services_listener_d_wasm32_emcc.v). Surface a clean error rather than a
// silent no-op so an accidental call in the playground is obvious.
fn xap_serve(args []cx.Node, mut env MatchEnv) ?cx.Node {
	return mk_err(xap_err_arg_invalid, 'E_XAP_SERVE_UNAVAILABLE: [\$xap:serve] needs the native socket engine (picoev is not linked under -d wasm32_emcc); run cx natively')
}

// §3.1.2 push seam — no /events feed exists on this target; commits still
// fold, there is just no held reader to push to.
fn xap_push_live(rt_id int, mut env MatchEnv) {
}

// #604: no threads under -d wasm32_emcc — the persist runs inline (the
// pre-#604 behavior; correct, just synchronous on this target).
fn xap_ckpt_persist_dispatch(snap XapCkptSnap) {
	xap_ckpt_persist_run(snap)
}

// §3.1.2 source pumps ride threads + the socket engine; refuse cleanly.
fn xap_start_source_pumps(rt_id int, sources []cx.Node, tenant string, mut env MatchEnv) ?cx.Node {
	return mk_err(xap_err_arg_invalid, 'E_XAP: run {sources: …} needs the native engine (threads/sockets are not linked under -d wasm32_emcc); run cx natively')
}
