module code

import cx

// services_listener_d_wasm32_emcc.v — wasm32_emcc build stub.
//
// The full real-socket [?http-service] listener (services_listener_
// notd_wasm32_emcc.v) imports `net.http`, which transitively pulls in
// V's mbedtls bindings. Emscripten's sysroot has no mbedtls headers,
// so that compile path explodes. The wasm playground also doesn't
// need a real HTTP listener — the in-process `cx-test://` scheme path
// in services.v covers every conformance fixture, and the playground
// never spawns a server. So under `-d wasm32_emcc` we substitute
// no-op / error stubs for the two crossings into the listener
// surface (`start_http_listener` + `stop_http_listener_for`).
//
// Filename convention: V's compile_value mechanism includes a file
// named `*_d_FLAG.v` only when `-d FLAG` is set, and a file named
// `*_notd_FLAG.v` only when `-d FLAG` is NOT set. The wasm build
// script (`scripts/wasm/build_libcx_wasm.sh`) passes `-d wasm32_emcc`,
// so this file is included for wasm and the real listener is excluded.
//
// Per: a real listener is requested only when `port > 0`
// AND a serve-file resource / bind-host / block clause is present.
// In wasm none of those make sense, so `start_http_listener` would
// never actually run productively. Returning an error makes any
// accidental call surface as a clean CXER0001 rather than a silent
// no-op (which could be confusing if a CX program is run via cxlib).

fn start_http_listener(mut rec ServiceRecord, mut env MatchEnv) ! {
	return error('[?http-service] real-socket listener is not available in the wasm build (V net.http requires mbedtls which is not in the emscripten sysroot). Use `cx-test://` scheme for in-process testing or run cx natively.')
}

fn stop_http_listener_for(rec &ServiceRecord) {
	// No-op — no listener could have been started in the wasm build.
}

// start_handler_listener — wasm stub for module `[$http:serve url $handler]`.
// Same rationale as start_http_listener: no real socket in the emscripten
// build. Surfaces a clean error rather than a silent no-op.
fn start_handler_listener(handler cx.Node, host string, port int, block bool, mut env MatchEnv) !cx.Node {
	return error('[\$http:serve] real-socket listener is not available in the wasm build (picoev/net not linked under -d wasm32_emcc). Run cx natively.')
}
