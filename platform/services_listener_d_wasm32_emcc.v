module platform
import code {
	MatchEnv,
	ServiceRecord,
}

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
fn start_handler_listener(handler cx.Node, host string, port int, block bool, tls_cert string, tls_key string, mut env MatchEnv) !cx.Node {
	return error('[\$http:serve] real-socket listener is not available in the wasm build (picoev/net not linked under -d wasm32_emcc). Run cx natively.')
}

// ── SSE topic pub/sub stubs ────────────────────────────────────────────────
//
// cx_sse_topic_subscribe, cx_sse_topic_on_close_fd, and cx_sse_topic_publish
// are defined in services_listener_notd_wasm32_emcc.v (the real picoev
// listener, excluded from the wasm build). cx_sse_topic_publish is called
// unconditionally from stdlib_http.v, so it must be present in this stub
// file. The other two are included for completeness (they may be referenced
// from future shared code or via V's cross-module analysis).
//
// In the wasm playground there are no held SSE fds and no subscriber map, so
// all three are no-ops / return a benign zero value.

// cx_sse_topic_subscribe — no-op in the wasm build (no picoev, no fds). The
// `ack` (SSE prelude + initial frame, written atomically with registration in
// the real listener) has no fd to go to here.
fn cx_sse_topic_subscribe(topic string, fd int, ack string) {
	// No subscriber map in the wasm build; SSE topic pub/sub requires a
	// real socket listener which is not available under -d wasm32_emcc.
}

// cx_sse_topic_on_close_fd — no-op in the wasm build (no picoev, no fds).
fn cx_sse_topic_on_close_fd(fd int) {
	// No subscriber map to clean up in the wasm build.
}

// cx_sse_topic_publish — returns 0 (no subscribers) in the wasm build.
// stdlib_http.v calls this at every [?sse-publish] invocation; returning 0
// means "zero fds accepted the write", which is the correct answer when
// there is no real listener.
fn cx_sse_topic_publish(topic string, frame string) int {
	return 0
}

// services_listener_init_globals — wasm no-op twin of the notd variant's
// init hook (stdlib_codec.v init() calls it unconditionally): the dispatch/
// gc/SSE globals it initializes live in the excluded notd file, and nothing
// in the wasm build can reach them (#329).
fn services_listener_init_globals() {
}
