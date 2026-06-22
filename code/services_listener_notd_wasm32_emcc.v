@[has_globals]
module code

import cx
import os
import net
import runtime
import transport.picoev
import transport.picohttpparser
import strings
import sync
import time

// services_listener.v — real-socket HTTP/1.1 listener for [?http-service]
//
// This file owns the picoev + picohttpparser surface (the cx-native
// server-leg backend; spec/02-inprogress/stdlib_http.md §9). Keeping it
// isolated from services.v (otherwise pure data-plumbing) lets the
// substrate compile under build modes that don't link the event-loop
// stack (the `_d_wasm32_emcc` sibling stubs it out), and makes the wire
// emitter a single grep target.
//
// The isolation bench (fe99c6ea) settled the backend question
// empirically: the request path is transport-bound (~93.5% of
// wall-clock on V's blocking net.http serve), so this listener runs a
// picoev event loop driving picohttpparser instead of a
// thread-per-request accept-loop.
//
// Spawned by `start_http_listener` when the trigger fires. The loop:
//   1. binds an OS socket on `bind_host:port` (defaulting to 0.0.0.0
//      when bind_host is empty) — picoev.new() binds synchronously,
//   2. accepts + reads + parses each HTTP/1.1 request via picohttpparser
//      inside the event loop,
//   3. looks up the matching resource via match_resource, evaluates the
//      handler body in a per-request MatchEnv clone (with $request bound
//      and cx-service-root stashed into dyn_context), maps the
//      [response …] envelope onto the wire,
//   4. sends the response directly on the connection fd (C.send) so a
//      large static-file body is NOT capped by picoev's per-fd write
//      buffer (max_write).
//
// Concurrency model mirrors par_eval.v: each request-handler clones
// bindings + closures, shares `&ProgramState` via pointer. The
// `state_locks.v` mutexes already cover concurrent map mutations.
//
// KNOWN LIMITATION (increment-2): picoev exposes only an infinite
// `serve()` (no `loop_once`/break). In-process `[?stop]` therefore
// flips the service to `stopped` (subsequent requests get 503) but does
// NOT close the listening socket until process exit — the serve thread
// leaks. A clean stop (and SSE held-open fds) needs a small picoev fork
// patch, deferred to a single later increment. No test exercises
// in-process stop-then-continue; `[block true]` programs are killed by
// signal, which tears the socket down with the process.

// ListenerMode selects how a parsed request is dispatched:
//   .service — directive `[?http-service]`: route via match_resource over
//              the service's [resource] table (path-params, HEAD→GET).
//   .handler — module `[$http:serve url $handler]`: invoke a single CX
//              handler closure with the built [request].
// Both modes share the picoev engine, the per-request env clone, and the
// [response]→wire mapping (the "one HTTP stack" the spec requires —
// spec/02-inprogress/stdlib_http.md §3.5/§6).
enum ListenerMode {
	service
	handler
	xap // cx-xap `[$xap:serve]` — dispatch via xap_dispatch_http (V, no CX closure)
}

// ListenerHandler carries the env snapshot (bindings + closures + state
// pointer) plus either the service name (.service) or the handler
// closure value (.handler) across the picoev C-callback boundary via the
// `user_data voidptr`. Per-request env clones happen in dispatch_request.
// One picoev instance (hence one handler) per listener, so the pointer is
// stable for the listener's life. @[heap] — always created via `&ListenerHandler{}`
// and shared by reference (picoev voidptr + the cx_http_live_handlers vgc root, #57);
// the attribute lets the reference be stored in that global retainer.
@[heap]
struct ListenerHandler {
	mode         ListenerMode
	service_name string
mut:
	handler            cx.Node = cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue('')
		data_type: cx.ScalarType.string_type
	})
	enclosing_bindings map[string]cx.Node
	enclosing_closures map[string]Closure
	enclosing_dyn      []cx.Node
	// enclosing_scope is the program's lexical Scope at serve time. Per-request
	// envs carry it so a caller-supplied handler closure (a top-level [?def]/[?fn]
	// passed into the lib `[$http:serve …]`) resolves via the program scope —
	// `serve`'s own call env only sees the http module's scope (#19 higher-order).
	enclosing_scope    &Scope = unsafe { nil }
	state              &ProgramState = unsafe { nil }
	xap_rt             int // .xap mode: the cx-xap runtime id this listener serves
}

// WireHeader / WireResp are the transport-neutral response shape the CX
// dispatch pipeline produces; serialize_wire turns one into HTTP/1.1
// bytes. (Replaces the former dependency on V's http.Response.)
struct WireHeader {
	name  string
	value string
}

struct WireResp {
	status  int
	headers []WireHeader
	body    string
	// §24 SSE: when sse=true the dispatcher is promoting this connection to a
	// held-open event-stream — `body` is the initial frame and `sse_rt` is the
	// runtime whose subscriber set this fd joins. listener_callback writes the
	// prelude, holds the fd, and subscribes it instead of a one-shot response.
	sse    bool
	sse_rt int
	// Generic SSE topic (#28): when sse=true and sse_topic is non-empty, the fd
	// joins the named string-keyed topic in the generic registry instead of an
	// xap runtime's set — the concurrent-SSE path for `[$http:serve]` handlers
	// (a handler returns `[sse-subscribe topic="…" [event …]?]`; any other
	// handler fans out with `[$http:sse-publish "…" [event …]]`).
	sse_topic string
}

// listener_callback is the picoev request callback — a TOP-LEVEL fn (no
// closure) so V's C-callback ABI gets a clean function pointer. picoev
// has already accepted, read, and parsed the request via picohttpparser
// by the time we are called.
__global (
	cx_http_gc_lock  sync.Mutex
	cx_http_gc_count u64
	cx_http_gc_every u64
	cx_http_gc_bytes u64
	cx_http_gc_last  u64
	cx_http_gc_init  bool
)

// ── #57 reactor UAF fix: retain &ListenerHandler as a vgc root ───────────────
// picoev stores the handler only as a `voidptr` (Config/Picoev.user_data),
// which vgc cannot trace. The only V-typed reference is the local `h` in
// start_*_listener, which goes dead after spawn (and during the block-loop).
// So the collector frees the handler AND its enclosing_bindings strings while
// the reactor threads still read them via the voidptr — under concurrent
// multi-reactor load a reactor's per-request `env.clone()` then reads a freed
// binding string and crashes in builtin__string_clone (#57: the residual
// "vgc frees a live object" UAF; boehm was clean because its conservative scan
// kept the handler alive). Retaining each handler here roots it: the fixed
// array's pointer slots live in the __DATA segment, which vgc scans
// conservatively (vgc_data_segments), so the handler + its bindings stay
// marked. Handlers live for the process lifetime (no stop path — see the
// KNOWN LIMITATION), so retaining forever is correct and bounded (a handful
// per process, capped well under the slot count).
__global (
	cx_http_live_handlers [256]&ListenerHandler
	cx_http_live_count    int
	cx_http_live_lock     sync.Mutex
)

// retain_listener_handler pins `h` so vgc never reclaims it while reactors hold
// it only through picoev's untraced voidptr user_data (#57).
fn retain_listener_handler(h &ListenerHandler) {
	cx_http_live_lock.lock()
	if cx_http_live_count < 256 {
		cx_http_live_handlers[cx_http_live_count] = h
		cx_http_live_count++
	}
	cx_http_live_lock.unlock()
}

// http_reactor_maybe_collect drives a periodic GC collection from the reactor
// request loop (#57). The per-request path allocates transient garbage — the
// parsed [request], the handler's comprehension results and cx:parse ASTs, the
// [response] tree — that is dead once the response is written. vgc's auto-collect
// (the heap-doubling trigger) does NOT fire on the reactor's allocation pattern,
// so this garbage accumulates monotonically until malloc returns null →
// `V panic: memory allocation failure` (the reported OOM). It is genuinely
// reclaimable, not rooted: forcing a collect holds RSS to the working set
// (verified — a 200-item `[?for]` handler grows unbounded past 1.4 GB at 2000
// requests without this; with periodic collects it plateaus near baseline,
// ~50 MB).
//
// The collect is gated by HEAP GROWTH, not request count. A request-count gate
// cannot serve both handler shapes: a small count (the old default 64) fires a
// global STW collect ~hundreds of times/sec under load, which serialized every
// reactor thread and cut throughput ~3x (125k→61k single, and NEGATIVE
// multi-reactor scaling); a large count would OOM a heavy handler. Instead we
// collect once the heap has grown by CX_HTTP_GC_MB megabytes since the last
// collect (default 64): a light handler barely allocates so it almost never
// trips (full throughput + multi-reactor scaling restored), while a heavy
// 200-item-[?for] handler trips every few requests so RSS stays bounded (#57;
// the rss-bound test holds well under its 300 MB ceiling). CX_HTTP_GC_MB=0
// disables it. Legacy CX_HTTP_GC_EVERY (request count) is still honored when
// explicitly set, for callers that pinned it.
fn http_reactor_maybe_collect() {
	cx_http_gc_lock.lock()
	if !cx_http_gc_init {
		cx_http_gc_init = true
		cx_http_gc_bytes = u64(64) * 1024 * 1024 // 64 MB heap-growth default
		if ov := os.getenv_opt('CX_HTTP_GC_MB') {
			k := ov.i64()
			if k >= 0 {
				cx_http_gc_bytes = u64(k) * 1024 * 1024 // 0 ⇒ disabled
			}
		}
		// Legacy request-count gate — only when explicitly set; takes precedence.
		if ov := os.getenv_opt('CX_HTTP_GC_EVERY') {
			k := ov.i64()
			if k >= 0 {
				cx_http_gc_every = u64(k)
			}
		}
		cx_http_gc_last = u64(gc_memory_use())
	}
	mut hit := false
	if cx_http_gc_every > 0 {
		cx_http_gc_count++
		if cx_http_gc_count >= cx_http_gc_every {
			cx_http_gc_count = 0
			hit = true
		}
	} else if cx_http_gc_bytes > 0 {
		cur := u64(gc_memory_use())
		if cur >= cx_http_gc_last + cx_http_gc_bytes {
			// Claim the growth window under the lock so peer reactors don't
			// also trip and double-collect; the post-collect reset below
			// corrects the baseline down to the live set.
			cx_http_gc_last = cur
			hit = true
		}
	}
	cx_http_gc_lock.unlock()
	// Collect outside the lock; the STW pause must not serialize other reactor
	// threads behind a held mutex.
	if hit {
		gc_collect()
		cur2 := u64(gc_memory_use())
		cx_http_gc_lock.lock()
		cx_http_gc_last = cur2
		cx_http_gc_lock.unlock()
	}
}

fn listener_callback(data voidptr, req picohttpparser.Request, mut res picohttpparser.Response) {
	mut h := unsafe { &ListenerHandler(data) }
	w := dispatch_request(mut h, req.method, req.path, req.body)
	if w.sse {
		// §24: promote to a held-open SSE feed. Write the event-stream prelude +
		// the initial frame, mark the fd held (exempt from picoev's idle timeout),
		// and subscribe it so /intent/sign pushes reach it. The reactor returns
		// immediately — no blocking; pushes are event-driven from other handlers.
		prelude := 'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n'
		send_all(res.fd, prelude + w.body)
		picoev.cx_hold_fd(res.fd)
		if w.sse_topic != '' {
			// #28: generic string-topic feed (the `[$http:serve]` concurrent path).
			cx_sse_topic_subscribe(w.sse_topic, res.fd)
		} else {
			// XAP runtime feed (the original §24 path).
			xap_sse_subscribe(w.sse_rt, res.fd)
		}
		return
	}
	is_head := req.method.to_upper() == 'HEAD'
	send_all(res.fd, serialize_wire(w, is_head))
	// Reclaim this request's transients before the next one (#57). Runs after
	// the response is on the wire, so the collect never delays this response.
	http_reactor_maybe_collect()
}

// send_all writes the full response on the connection fd, bypassing
// picoev's bounded per-fd write buffer (max_write) so a large static-file
// body is not capped. Uses C.write (works on socket fds, no flags) — the
// same raw-fd write the cxcol streaming path uses (cx/data_bin_streaming.v).
fn send_all(fd int, data string) {
	mut off := 0
	for off < data.len {
		n := unsafe { C.write(fd, voidptr(data.str + off), usize(data.len - off)) }
		if n <= 0 {
			break
		}
		off += int(n)
	}
}

// dispatch_request routes one request to its resource handler and
// returns the wire-ready response. Mirrors the former net.http
// `ListenerHandler.handle`, retargeted onto picohttpparser inputs.
fn dispatch_request(mut h ListenerHandler, raw_method string, raw_path string, raw_body string) WireResp {
	// cx-xap `[$xap:serve]` — dispatch the request against the runtime in V
	// (no CX closure). Renders the surface as text/html on GET, runs the
	// cascade on POST, and re-renders the swapped fragment (xap.md §9/§13.2).
	if h.mode == .xap {
		// per-request env clone so the dispatcher can apply the component's pure
		// view [?fn] over the live slice (the single render path, §2.5/§13.2).
		mut xenv := MatchEnv{
			bindings:     h.enclosing_bindings.clone()
			closures:     h.enclosing_closures.clone()
			state:        unsafe { h.state }
			anon_counter: 0
			dyn_context:  h.enclosing_dyn.clone()
			scope:        h.enclosing_scope
		}
		return xap_dispatch_http(h.xap_rt, raw_method.to_upper(), raw_path, raw_body, mut xenv)
	}
	// Module `[$http:serve url $handler]` — invoke the single CX handler
	// closure with the built [request] in a per-request env clone. No
	// resource table / routing (that is the directive's .service layer).
	if h.mode == .handler {
		method := raw_method.to_upper()
		mut path := raw_path
		if q := path.index('?') {
			path = path[..q]
		}
		mut renv := MatchEnv{
			bindings:     h.enclosing_bindings.clone()
			closures:     h.enclosing_closures.clone()
			state:        unsafe { h.state }
			anon_counter: 0
			dyn_context:  h.enclosing_dyn.clone()
			scope:        h.enclosing_scope
		}
		// Forward the request body as a string scalar so the handler can read
		// `$request/body` for POST/PUT payloads (form-encoded or raw).
		body_node := cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(raw_body)
			data_type: cx.ScalarType.string_type
		})
		reqnode := build_request_node(method, path, []cx.Node{}, ?cx.Node(body_node))
		result := apply_fn_value(h.handler, [reqnode], mut renv) or {
			return mk_wire(500, [], 'handler error: ${err.msg()}\n')
		}
		return cx_response_to_wire(result, [])
	}
	// Snapshot the service record; a [?stop] races in-flight requests
	// gracefully — we keep serving with the current handler table.
	svc := h.state.service_get(h.service_name) or {
		return mk_wire(503, [], 'service vanished\n')
	}
	// Post-stop: socket may still be open (see KNOWN LIMITATION) — answer
	// 503 so a draining service does not serve stale content.
	if svc.status == 'stopped' {
		return mk_wire(503, svc.default_headers, 'service stopping\n')
	}
	method := raw_method.to_upper()
	// req path is the request-target; strip query for path matching.
	mut path := raw_path
	if q := path.index('?') {
		path = path[..q]
	}
	// HEAD falls back to GET so static-file routes Just Work under
	// `curl -I` (HTTP/1.1 §9.4 — HEAD MUST be supported by any
	// GET-supporting resource). serialize_wire drops the body for HEAD.
	res, path_params := match_resource(svc, method, path) or {
		if method == 'HEAD' {
			r2, p2 := match_resource(svc, 'GET', path) or {
				return mk_wire(404, svc.default_headers, 'not found: ${method} ${path}\n')
			}
			return invoke_handler(svc, r2, p2, 'HEAD', path, mut h)
		}
		return mk_wire(404, svc.default_headers, 'not found: ${method} ${path}\n')
	}
	return invoke_handler(svc, res, path_params, method, path, mut h)
}

// ServeFileSpec marks a resource body that is a bare static `[$serve-file]`
// / `[$serve-file "PATH"]` call, eligible for the allocation-cheap fast path.
struct ServeFileSpec {
	has_literal bool   // true for `[$serve-file "PATH"]`, false for `[$serve-file]`
	literal     string // the literal path arg (only when has_literal)
}

// static_serve_file_spec returns a ServeFileSpec iff `body` is exactly a
// bare `[$serve-file]` or `[$serve-file "PATH"]` call (no `?`/`!` postfix,
// at most one plain string-literal arg) AND `serve-file` is not shadowed by
// an enclosing closure / closure-valued binding (in which case the slow path
// would invoke that instead of the builtin). Returns none otherwise so the
// caller falls back to the general eval path. The check is purely structural
// (AST + the per-service enclosing scope), so the fast path can NEVER change
// behaviour for a non-static-file handler.
fn static_serve_file_spec(body cx.ProgramNode, closures map[string]Closure, bindings map[string]cx.Node) ?ServeFileSpec {
	if body !is cx.ProgramCall {
		return none
	}
	call := body as cx.ProgramCall
	if call.name != 'serve-file' || call.fallible || call.must_succeed {
		return none
	}
	// serve-file shadowed by a user closure / closure-valued binding → the
	// eval path would call that, not the builtin; do not fast-path.
	if _ := closures['serve-file'] {
		return none
	}
	if v := bindings['serve-file'] {
		if is_fn_value(v) {
			return none
		}
	}
	if call.args.len == 0 {
		return ServeFileSpec{ has_literal: false }
	}
	if call.args.len == 1 {
		a := call.args[0]
		if a is cx.ProgramLiteral {
			al := a as cx.ProgramLiteral
			if al.kind == .string_lit {
				return ServeFileSpec{ has_literal: true, literal: al.str_val }
			}
		}
	}
	return none
}

// serve_file_fast_wire produces the WireResp for a static `[$serve-file]`
// resource WITHOUT the per-request env clone, `$request` node, or call
// dispatch — the dominant per-request allocation (see the alloc attribution
// in the http multicore work). It deliberately reuses the SAME
// serve_file_outcome (cache + resolution), mk_serve_response, and
// cx_response_to_wire the eval path uses, so its wire output is byte-identical
// to evaluating `[$serve-file]` through the handler — only the wasteful
// allocation is skipped. Verified by v08_http_serve_file_fastpath_test.v.
fn serve_file_fast_wire(spec ServeFileSpec, svc &ServiceRecord, req_path string) WireResp {
	// invoke_handler stashes svc.root into dyn_context only when non-empty,
	// so an empty root means "no service root in scope" (500) — match it.
	if svc.root == '' {
		return cx_response_to_wire(mk_serve_response(500, '', 'no service root in scope'),
			svc.default_headers)
	}
	rp := if spec.has_literal { spec.literal } else { req_path }
	o := serve_file_outcome(rp, svc.root, svc.cache)
	return cx_response_to_wire(mk_serve_response(o.status, o.ct, o.body), svc.default_headers)
}

// invoke_handler runs a matched resource handler in a per-request env
// clone and maps the [response …] envelope to a WireResp. Factored out
// so the HEAD-falls-back-to-GET branch reuses the eval + wire pipeline.
fn invoke_handler(svc &ServiceRecord, res ResourceRecord, path_params []cx.Node,
	method string, path string, mut h ListenerHandler) WireResp {
	// Static-file fast path: a bare `[$serve-file]` resource skips the
	// per-request env clone + `$request` node (the bulk of per-request
	// allocation) while producing byte-identical wire output.
	if spec := static_serve_file_spec(res.body, h.enclosing_closures, h.enclosing_bindings) {
		return serve_file_fast_wire(spec, svc, path)
	}
	mut env := MatchEnv{
		bindings:     h.enclosing_bindings.clone()
		closures:     h.enclosing_closures.clone()
		state:        unsafe { h.state }
		anon_counter: 0
		dyn_context:  h.enclosing_dyn.clone()
		scope:        h.enclosing_scope
	}
	env.bindings['request'] = build_request_node(method, path, path_params, ?cx.Node(none))
	if svc.root != '' {
		env.dyn_context << cx.Node(cx.Element{
			name:  'cx-service-root'
			// `cache` attr carries the service's static-file cache opt-in
			// to [$serve-file] (read via serve_file_lookup_cache).
			attrs: [
				cx.new_attribute('cache', cx.ScalarValue(svc.cache), cx.AttributeMeta{
					data_type: ?string('bool')
				}),
			]
			items: [
				cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(svc.root)
					data_type: cx.ScalarType.string_type
				}),
			]
		})
	}
	body_result := eval_node(res.body, mut env) or {
		msg := err.msg()
		return mk_wire(500, svc.default_headers, 'handler error: ${msg}\n')
	}
	wire := cx_response_to_wire(body_result, svc.default_headers)
	return wire
}

// cx_response_to_wire converts a CX response envelope (cx.Element named
// 'response') to a WireResp, applying default headers where the handler
// did not override (per-key, per-response overrides win).
// ── generic SSE topic registry (#28) ─────────────────────────────────────────
//
// The concurrent-SSE path for `[$http:serve]`. Mirrors the proven XAP SSE
// machinery (xap_sse_subs) but keyed by a generic STRING topic instead of an
// xap runtime id, so a plain CX handler can promote a connection to a live feed
// and any other handler can fan-out to it WITHOUT blocking a reactor thread:
//
//   - A handler returns `[sse-subscribe topic="…" [event …]?]`; listener_callback
//     writes the SSE prelude + the optional initial frame, holds the fd
//     (exempt from the idle timeout), and adds it to `cx_sse_topic_subs[topic]`.
//   - Any handler (on any reactor) calls `[$http:sse-publish "…" [event …]]`,
//     which renders one SSE frame and writes it to every subscriber fd.
//
// Cleanup is synchronous: picoev's close_conn invokes cx_sse_topic_on_close_fd
// (registered via cx_set_sse_on_close at handler-listener startup) under this
// lock BEFORE the socket closes, so a push from another reactor can never write
// to a reused fd. Same safety model as the XAP feed.
__global (
	cx_sse_topic_subs map[string][]int
	cx_sse_topic_lock sync.Mutex
)

// cx_sse_topic_subscribe adds a held SSE fd to a topic's subscriber set.
fn cx_sse_topic_subscribe(topic string, fd int) {
	cx_sse_topic_lock.lock()
	cx_sse_topic_subs[topic] << fd
	cx_sse_topic_lock.unlock()
}

// cx_sse_topic_on_close_fd drops `fd` from every topic. Invoked by picoev's
// close_conn (held-fd close) and by a failed publish write; idempotent.
fn cx_sse_topic_on_close_fd(fd int) {
	cx_sse_topic_lock.lock()
	for topic, fds in cx_sse_topic_subs {
		mut kept := []int{}
		for f in fds {
			if f != fd {
				kept << f
			}
		}
		cx_sse_topic_subs[topic] = kept
	}
	cx_sse_topic_lock.unlock()
}

// cx_sse_topic_publish writes `frame` to every subscriber of `topic` and returns
// the number of fds that accepted the write. A fd whose write fails (peer gone)
// is dropped (picoev closes the socket on its own disconnect read event).
fn cx_sse_topic_publish(topic string, frame string) int {
	cx_sse_topic_lock.lock()
	fds := (cx_sse_topic_subs[topic] or { []int{} }).clone()
	cx_sse_topic_lock.unlock()
	mut dead := []int{}
	mut delivered := 0
	for fd in fds {
		mut off := 0
		mut ok := true
		for off < frame.len {
			n := unsafe { C.write(fd, voidptr(frame.str + off), usize(frame.len - off)) }
			if n <= 0 {
				ok = false
				break
			}
			off += int(n)
		}
		if ok {
			delivered++
		} else {
			dead << fd
		}
	}
	for fd in dead {
		cx_sse_topic_on_close_fd(fd)
	}
	return delivered
}

fn cx_response_to_wire(node cx.Node, defaults []cx.Attribute) WireResp {
	// #28 concurrent-SSE: a handler promotes its connection to a live feed by
	// returning `[sse-subscribe topic="…" [event …]?]`. The reactor holds the fd
	// and subscribes it to the topic; pushes arrive via [$http:sse-publish] from
	// other handlers. The optional `[event …]` child is the initial frame.
	if node is cx.Element {
		sub := node as cx.Element
		if sub.name == 'sse-subscribe' {
			topic := sub.attr('topic')
			if topic == '' {
				return mk_wire(500, defaults, 'sse-subscribe requires a non-empty topic="…" attribute\n')
			}
			mut frame := ''
			for it in sub.items {
				if it is cx.Element && (it as cx.Element).name == 'event' {
					fr := http_sse_frame_event(it as cx.Element)
					if fr is cx.Element && (fr as cx.Element).name == 'err' {
						// malformed initial [event] — surface it instead of holding a feed
						return mk_wire(500, defaults, 'sse-subscribe initial event invalid\n')
					}
					frame = http_node_str(fr)
					break
				}
			}
			return WireResp{
				status:    200
				sse:       true
				sse_topic: topic
				body:      frame
			}
		}
	}
	if node !is cx.Element {
		return mk_wire(200, defaults, render_node_text(node))
	}
	el := node as cx.Element
	if el.name != 'response' {
		return mk_wire(200, defaults, render_node_text(node))
	}
	mut status := 200
	if s_attr := el.attr_val('status') {
		match s_attr {
			i64 { status = int(s_attr) }
			string { status = s_attr.int() }
			else {}
		}
	}
	// Defaults first (ordered), then per-response headers override per key.
	mut hdr := map[string]string{}
	mut order := []string{}
	for a in defaults {
		v := match a.value {
			string { a.value as string }
			else { '' }
		}
		if a.name !in hdr {
			order << a.name
		}
		hdr[a.name] = v
	}
	mut body_str := ''
	for it in el.items {
		if it is cx.Element {
			ce := it as cx.Element
			if ce.name == 'headers' {
				for h_it in ce.items {
					if h_it is cx.Element && (h_it as cx.Element).name == 'header' {
						he := h_it as cx.Element
						hname := he.attr('name')
						hval := he.attr('value')
						if hname != '' {
							if hname !in hdr {
								order << hname
							}
							hdr[hname] = hval
						}
					}
				}
				continue
			}
			if ce.name == 'body' {
				body_str = render_response_body(ce)
				continue
			}
		}
	}
	// Alternate: body as a direct attribute on the response element.
	if body_str == '' {
		if b := el.attr_val('body') {
			match b {
				string { body_str = b }
				else {}
			}
		}
	}
	mut headers := []WireHeader{}
	for name in order {
		headers << WireHeader{
			name:  name
			value: hdr[name]
		}
	}
	return WireResp{
		status:  status
		headers: headers
		body:    body_str
	}
}

// mk_wire builds a minimal text/plain WireResp with default headers
// (the 404/500/503 fallback shape).
fn mk_wire(status int, defaults []cx.Attribute, body string) WireResp {
	mut headers := []WireHeader{}
	for a in defaults {
		v := match a.value {
			string { a.value as string }
			else { '' }
		}
		headers << WireHeader{
			name:  a.name
			value: v
		}
	}
	headers << WireHeader{
		name:  'Content-Type'
		value: 'text/plain; charset=utf-8'
	}
	return WireResp{
		status:  status
		headers: headers
		body:    body
	}
}

// serialize_wire emits HTTP/1.1 response bytes. Content-Length is always
// computed from the body length (the GET body length, even for HEAD);
// any handler-supplied Content-Length is dropped. For HEAD the body
// bytes are omitted but Content-Length is preserved (HTTP/1.1 §9.4).
fn serialize_wire(w WireResp, is_head bool) string {
	mut sb := strings.new_builder(256 + w.body.len)
	sb.write_string('HTTP/1.1 ${w.status} ${reason_phrase(w.status)}\r\n')
	for hkv in w.headers {
		if hkv.name.to_lower() == 'content-length' {
			continue
		}
		sb.write_string('${hkv.name}: ${hkv.value}\r\n')
	}
	sb.write_string('Content-Length: ${w.body.len}\r\n')
	sb.write_string('\r\n')
	if is_head {
		return sb.str()
	}
	sb.write_string(w.body)
	return sb.str()
}

// reason_phrase maps the status codes this listener emits to RFC 9110
// reason phrases; unknown codes fall back to a class-generic phrase.
fn reason_phrase(status int) string {
	return match status {
		200 { 'OK' }
		201 { 'Created' }
		204 { 'No Content' }
		301 { 'Moved Permanently' }
		302 { 'Found' }
		304 { 'Not Modified' }
		400 { 'Bad Request' }
		403 { 'Forbidden' }
		404 { 'Not Found' }
		405 { 'Method Not Allowed' }
		408 { 'Request Timeout' }
		500 { 'Internal Server Error' }
		503 { 'Service Unavailable' }
		else {
			match status / 100 {
				2 { 'OK' }
				3 { 'Redirect' }
				4 { 'Client Error' }
				5 { 'Server Error' }
				else { 'Status' }
			}
		}
	}
}

// render_response_body produces the wire body string from a `[body …]`
// element. Scalar string → verbatim; scalar non-string → stringified;
// structured child → re-rendered via CX text-render.
fn render_response_body(body_el cx.Element) string {
	if body_el.items.len == 0 {
		if body_el.attrs.len > 0 {
			b := body_el.attrs[0]
			match b.value {
				string { return b.value as string }
				else {}
			}
		}
		return ''
	}
	first := body_el.items[0]
	return render_node_text(first)
}

// render_node_text — simple text rendering for response bodies. A
// ScalarNode string is returned verbatim; other node kinds run through
// the standard render pipeline.
fn render_node_text(n cx.Node) string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
		return scalar_to_text(v)
	}
	return render(n, 'text') or { '' }
}

// http_listener_max_loops is an ABSOLUTE safety ceiling on worker count — a
// typo guard (`CX_HTTP_WORKERS=99999`), NOT a functional cap: it sits well above
// any realistic core count so `max` and explicit requests (e.g. a 64-core test)
// are honored, never silently shrunk. Each worker holds its own picoev per-fd
// buffers (~12 MiB), so 256 workers ≈ 3 GiB of buffers — only reachable by
// explicitly asking for it.
const http_listener_max_loops = 256

// spawn_shared_reactors binds ONE listening socket and spawns N picoev
// worker loops (one per core) that all watch that shared fd — the kernel
// distributes accept()s across the worker threads (the shared-listener
// multi-reactor model; picoev cx_shared_listener patch). macOS
// SO_REUSEPORT does not load-balance, but shared-fd accept does. All
// workers share the read-only &ListenerHandler; per-request env clones +
// the &ProgramState locks keep concurrent handler eval safe.
fn spawn_shared_reactors(mut h ListenerHandler, host string, port int) ! {
	bind_host := if host == '' { '0.0.0.0' } else { host }
	family := if bind_host.contains(':') { net.AddrFamily.ip6 } else { net.AddrFamily.ip }
	config := picoev.Config{
		port:      port
		host:      bind_host
		family:    family
		cb:        listener_callback
		user_data: h
	}
	// Warm the static-file cache singleton before workers spawn (the
	// cache fills concurrently afterward under its own rwlock).
	serve_file_cache_init()
	listen_fd := picoev.listen_socket(config)!
	// Default to a SINGLE reactor for soundness. The multi-reactor model exposes a
	// residual macOS-specific vgc allocator concurrency corruption (#57): under >=2
	// concurrent reactor mutators a small-object span slot can be reissued while live,
	// crashing ~3% of heavy-load runs. Single-reactor is sound BY CONSTRUCTION — one
	// mutator on the HTTP request path means the race's >=2-mutator precondition cannot
	// occur (verified: 0 crashes single-reactor vs ~3% multi; Linux 0/92, i.e. the bug
	// is in the macOS mach-suspend-STW interaction, not the request logic). That residual
	// is fixed on the cooperative-safepoint collector (the default -gc e; #63/#58 — the
	// concurrency-soundness gate passes on it), so the listener now DEFAULTS to a small
	// multi-core fan-out (min(4, cores)); CX_HTTP_WORKERS tunes it. The #37 own-vs-rent
	// allocator rework remains a perf follow-up. The #57 OOM is addressed in three parts: the vgc_alloc_large wait
	// (large-span path), the per-iteration closures-table aliasing in the [?for] walker
	// (eval.v / matcher.v clone_frame_sharing_closures), and http_reactor_maybe_collect()
	// below, which bounds the per-request transient heap (the large-span fix alone left a
	// linear small-object leak that still OOM'd under sustained polling).
	// Reactor (worker) count. Default: a small multi-core fan-out — min(4, cores).
	// 4 is where the per-request global GC lock starts to dominate on a many-core
	// box, so the default doesn't fan out to every core (it scales sensibly from a
	// laptop to a big server without tuning). CX_HTTP_WORKERS overrides:
	//   - an integer → that many workers (HONORED, incl. > cores — a 64-core test
	//                  gets 64; only the http_listener_max_loops typo-guard caps it).
	//                  > cores oversubscribes (kernel time-slices, usually slower) —
	//                  honored but flagged, never silently shrunk.
	//   - `max`      → one worker per core.
	ncpu := runtime.nr_cpus()
	mut n := if ncpu < 4 { ncpu } else { 4 }
	mut requested := 0 // >0 when the user asked for an explicit count
	if ov := os.getenv_opt('CX_HTTP_WORKERS') {
		s := ov.trim_space().to_lower()
		if s == 'max' {
			n = ncpu
		} else {
			k := s.int()
			if k >= 1 {
				n = k
				requested = k
			}
		}
	}
	if n < 1 {
		n = 1
	}
	if n > http_listener_max_loops {
		eprintln('cx http: ${n} workers exceeds the ${http_listener_max_loops} safety ceiling — using ${http_listener_max_loops}')
		n = http_listener_max_loops
	}
	if requested > ncpu && n > ncpu {
		// Guidance, not a cap: more workers than cores time-slice and usually run
		// SLOWER on this workload. Honored as asked.
		eprintln('cx http: ${n} workers on ${ncpu} cores — oversubscribed (usually slower than ~${ncpu})')
	}
	for _ in 0 .. n {
		mut w := picoev.new_with_listen_fd(config, listen_fd)!
		spawn w.serve()
	}
}

// start_http_listener binds + spawns the real-socket picoev listener for
// the service. listen_socket() binds synchronously, so the socket is
// listening (backlog queued) by the time we return — callers may issue
// requests immediately. When `rec.block` is true, blocks until [?stop]
// or process termination flips the service status.
fn start_http_listener(mut rec ServiceRecord, mut env MatchEnv) ! {
	host := if rec.bind_host == '' { '0.0.0.0' } else { rec.bind_host }
	mut h := &ListenerHandler{
		mode:               .service
		service_name:       rec.name
		enclosing_bindings: env.bindings.clone()
		enclosing_closures: env.closures.clone()
		enclosing_dyn:      env.dyn_context.clone()
		enclosing_scope:    env.scope
		state:              unsafe { env.state }
	}
	// Stash the handler pointer (no stoppable server handle exists — see
	// KNOWN LIMITATION). stop is observed via the service `status`.
	rec.listener_handle = voidptr(h)
	retain_listener_handler(h) // vgc root — picoev holds h only as voidptr (#57)
	spawn_shared_reactors(mut h, host, rec.port)!
	if rec.block {
		// Block until [?stop] or process termination flips status. Polls
		// every 100ms — coarse but ample for a static-file host.
		for {
			cur := env.state.service_get(rec.name) or { break }
			if cur.status == 'stopped' {
				break
			}
			time.sleep(100 * time.millisecond)
		}
	}
}

// start_handler_listener is the module `[$http:serve url $handler $opts]`
// entry (env-aware dispatch in stdlib_http.v). It runs the SAME picoev
// engine as the directive, dispatching each request to the single CX
// handler closure (.handler mode). picoev.new() binds synchronously.
// When `block` is true, serve() runs on the calling fiber and does not
// return (until process termination — picoev has no break path, see
// KNOWN LIMITATION); otherwise the listener is spawned and an
// [http-server] handle is returned.
fn start_handler_listener(handler cx.Node, host string, port int, block bool, mut env MatchEnv) !cx.Node {
	mut h := &ListenerHandler{
		mode:               .handler
		service_name:       ''
		handler:            handler
		enclosing_bindings: env.bindings.clone()
		enclosing_closures: env.closures.clone()
		enclosing_dyn:      env.dyn_context.clone()
		enclosing_scope:    env.scope
		state:              unsafe { env.state }
	}
	// #28: register the generic-topic SSE close hook so a held feed fd is dropped
	// from every topic synchronously when picoev closes the socket (under the
	// publish lock), preventing a concurrent [$http:sse-publish] from writing to
	// a reused fd. Matches the XAP feed's cx_set_sse_on_close discipline.
	picoev.cx_set_sse_on_close(cx_sse_topic_on_close_fd)
	retain_listener_handler(h) // vgc root — picoev holds h only as voidptr (#57)
	spawn_shared_reactors(mut h, host, port)!
	bind_host := if host == '' { '0.0.0.0' } else { host }
	url := 'tcp://${bind_host}:${port}'
	if block {
		// All worker loops spawned on their own threads; keep the calling
		// fiber alive (no in-process stop pre-fork-patch — a signal tears
		// it down with the process).
		for {
			time.sleep(time.hour)
		}
		return http_server_handle(url) // unreachable; satisfies the return type
	}
	return http_server_handle(url)
}

// stop_http_listener_for marks the listener bound to `rec` as drained.
// picoev has no break path (see KNOWN LIMITATION), so the listening
// socket is freed only at process exit; until then dispatch_request
// answers 503 for the stopped service. The service-status flip is owned
// by eval_stop (services.v); this hook exists for symmetry with the
// wasm stub and future fork-patched teardown.
fn stop_http_listener_for(rec &ServiceRecord) {
	// No socket-level teardown available pre-fork-patch; intentional no-op.
}
