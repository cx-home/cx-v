module platform
import code {
	MatchEnv,
	mk_err,
}

import cx

// stdlib_xap_host_d_wasm32_emcc.v — wasm32_emcc build stubs for the
// `[$xap:host …]` / `[$xap:host-push …]` verbs.
//
// The real host (stdlib_xap_host_notd_wasm32_emcc.v) binds the picoev
// listener and spawns worker threads — neither is linked/available under
// `-d wasm32_emcc` (same rationale and filename convention as
// stdlib_xap_serve_d_wasm32_emcc.v). Surface a clean error rather than a
// silent no-op so an accidental call in the playground is obvious (#329
// wasm-revival: these verbs landed after the last wasm build with no stub
// twins, breaking the wasm compile).

fn xap_host(args []cx.Node, mut env MatchEnv) ?cx.Node {
	return mk_err(xap_err_arg_invalid, 'E_XAP_HOST_UNAVAILABLE: [\$xap:host] needs the native socket engine and worker threads (not linked under -d wasm32_emcc); run cx natively')
}

fn xap_host_push(args []cx.Node, mut env MatchEnv) ?cx.Node {
	return mk_err(xap_err_arg_invalid, 'E_XAP_HOST_UNAVAILABLE: [\$xap:host-push] needs a live [\$xap:host] runtime (not available under -d wasm32_emcc); run cx natively')
}
