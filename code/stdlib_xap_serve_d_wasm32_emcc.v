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
