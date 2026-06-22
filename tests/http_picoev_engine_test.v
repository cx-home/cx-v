module main

import os
import net
import net.http
import transport.picoev
import transport.picohttpparser
import time

// Increment-1 spike for the cx-native picoev + picohttpparser server leg
// (spec/02-inprogress/stdlib_http.md §9 backend note). This does NOT
// touch the production [?http-service] listener yet — it proves, in
// isolation, that:
//   • picoev + picohttpparser LINK and run under the patched V fork in
//     the `vcx` build context (nothing in cx has ever driven picoev),
//   • the top-level callback + `voidptr` user_data ABI we will use in
//     the production swap behaves as expected,
//   • a request parsed by picohttpparser round-trips a response a real
//     HTTP client can read.
// Once green, the production net.http listener
// (services_listener_notd_wasm32_emcc.v) is swapped onto this engine
// while keeping http_service_real_socket_test.v green.

// SpikeCtx is handed to the callback via picoev's user_data voidptr —
// the same mechanism the production engine uses to carry the
// per-service handler context across the C callback boundary.
struct SpikeCtx {
	payload string
}

// spike_callback is a TOP-LEVEL fn (no closure) so V's C-callback ABI
// gets a clean function pointer. It echoes the request path back in the
// body so the test can confirm picohttpparser actually parsed the line.
fn spike_callback(data voidptr, req picohttpparser.Request, mut res picohttpparser.Response) {
	ctx := unsafe { &SpikeCtx(data) }
	body := '${ctx.payload}:${req.method}:${req.path}'
	res.http_ok()
	res.plain()
	res.body(body)
	res.end()
}

// free_port returns a likely-free port on a disjoint PID + nanosecond-salted
// band (25000-25099) so the concurrent `v test vcx/tests/` gate processes don't
// collide — two same-nanosecond starts still differ via the PID term.
fn free_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 25000 + int(salt)
}

fn test_picoev_engine_links_and_serves() {
	port := free_port()
	ctx := &SpikeCtx{
		payload: 'pico-ok'
	}
	mut server := picoev.new(
		port:      port
		host:      '127.0.0.1'
		family:    net.AddrFamily.ip
		cb:        spike_callback
		user_data: ctx
	) or {
		assert false, 'picoev.new failed to bind 127.0.0.1:${port}: ${err}'
		return
	}
	// serve() blocks on its event loop; run it on its own thread. The
	// spike has no stop path — the thread is reclaimed at process exit
	// (stoppable serve lands with the production engine's [?stop] work).
	spawn server.serve()

	// Poll until the listener answers (bind + first accept are async).
	mut up := false
	for _ in 0 .. 30 {
		probe := http.get('http://127.0.0.1:${port}/__ping__') or {
			time.sleep(50 * time.millisecond)
			continue
		}
		if probe.status_code == 200 {
			up = true
			break
		}
	}
	assert up, 'picoev listener never answered on 127.0.0.1:${port}'

	// Confirm picohttpparser parsed the request line: method + path echo.
	resp := http.get('http://127.0.0.1:${port}/hello/world') or {
		assert false, 'GET failed: ${err}'
		return
	}
	assert resp.status_code == 200
	assert resp.body == 'pico-ok:GET:/hello/world', 'unexpected body: ${resp.body}'
}
