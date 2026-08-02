module code

import cx
import sync
import time

// store_grpc_serve.v — gRPC dispatch adapter (#105 sub-area 2b, brick 4). Maps a
// reassembled GrpcCall (from store_grpc_conn.v) onto the EXISTING request
// pipeline by synthesizing a CSRP-equivalent cx request and calling
// svc_handle_request — so auth, RBAC + tenant, the DoS limiter, and observability
// all apply UNCHANGED (no logic duplication; the spec §6.1 single-source-of-truth
// principle applied server-side). The cx response is translated back to a proto
// reply + gRPC trailer. This layer is socket-free and unit-testable; the socket
// listener (next sub-brick) feeds it H2Conn output.

// GrpcReply is the dispatch result: zero or more response DATA messages (one for
// a unary op, N for a server-streaming op) + the completion status/trailer.
pub struct GrpcReply {
pub:
	frames [][]u8 // proto-encoded response messages (each becomes a DATA frame)
	status GrpcStatus
}

// grpc_dispatch runs one gRPC call through the store pipeline. `call.headers`
// carries the HTTP/2 pseudo-headers (`:path`) + metadata (`authorization`).
pub fn grpc_dispatch(call GrpcCall, mut state ServiceState, ctx ServeContext) GrpcReply {
	// #224: this server negotiates identity (no compression); a message with the
	// LPM compressed flag set was previously read AS-IS (misparse). Reject it with
	// UNIMPLEMENTED per the gRPC compression spec, never silently misparse.
	if call.compressed {
		return GrpcReply{
			status: GrpcStatus{grpc_unimplemented, 'grpc: compressed messages are not supported (identity only)', 'cx-err:CXER1709'}
		}
	}
	op := grpc_op_from_path(call.headers[':path'] or { '' })
	authz := call.headers['authorization'] or { '' }
	// W3C trace-context rides gRPC metadata as `traceparent`; forward it so the shared
	// pipeline continues the inbound trace instead of minting a fresh root (full OTel).
	tp := call.headers['traceparent'] or { '' }
	match op {
		'put' {
			m := pb_decode_put_request(call.message) or { return grpc_invalid('put: bad request') }
			resp := svc_handle_request(grpc_synth_req('put', m.store, m.body.bytestr(),
				map[string]string{}, authz, tp), mut state, ctx)
			if e := grpc_resp_error(resp) {
				return e
			}
			// [put-result hash="H" stored="true|false"] — #190: read the REAL
			// content-dedup flag (a re-put of an existing doc reports stored=false),
			// not a hardcoded true.
			body := svc_response_body(resp)
			hash := grpc_attr_of(body, 'hash')
			return grpc_unary(pb_encode_put_response(GrpcPutResponse{
				hash:   hash
				stored: grpc_attr_of(body, 'stored') == 'true'
			}))
		}
		'get' {
			m := pb_decode_get_request(call.message) or { return grpc_invalid('get: bad request') }
			resp := svc_handle_request(grpc_synth_req('get', m.store, '', {
				'hash': m.hash
			}, authz, tp), mut state, ctx)
			if e := grpc_resp_error(resp) {
				return e
			}
			// 200 body is the canonical doc text.
			return grpc_unary(pb_encode_get_response(GrpcGetResponse{
				body:     svc_response_body(resp).bytes()
				encoding: 'cxd'
			}))
		}
		'delete' {
			m := pb_decode_delete_request(call.message) or {
				return grpc_invalid('delete: bad request')
			}
			resp := svc_handle_request(grpc_synth_req('delete', m.store, '', {
				'hash': m.hash
			}, authz, tp), mut state, ctx)
			if e := grpc_resp_error(resp) {
				return e
			}
			// [delete-result hash="H" deleted="true|false"]
			deleted := grpc_attr_of(svc_response_body(resp), 'deleted') == 'true'
			return grpc_unary(pb_encode_delete_response(GrpcDeleteResponse{
				deleted: deleted
			}))
		}
		'list' {
			m := pb_decode_store_request(call.message) or { return grpc_invalid('list: bad request') }
			resp := svc_handle_request(grpc_synth_req('list', m.store, '', map[string]string{},
				authz, tp), mut state, ctx)
			if e := grpc_resp_error(resp) {
				return e
			}
			// [list-result [hashes [hash "h1"] …]] → one HashItem DATA frame per hash.
			mut frames := [][]u8{}
			for h in grpc_list_hashes(svc_response_body(resp)) {
				frames << pb_encode_hash_item(GrpcHashItem{
					hash: h
				})
			}
			return GrpcReply{
				frames: frames
				status: GrpcStatus{grpc_ok, '', ''}
			}
		}
		'capabilities' {
			resp := svc_handle_request(grpc_synth_capabilities(authz), mut state, ctx)
			if e := grpc_resp_error(resp) {
				return e
			}
			return grpc_unary(pb_encode_capabilities_response(GrpcCapabilitiesResponse{
				capabilities: svc_response_body(resp).bytes()
			}))
		}
		'query' {
			// Server-streaming: the CXPath is the request's `query` field; it rides
			// the CSRP `path` query-param so the shared query route runs it. Each
			// [result hash="H" <matches>] in the [query-result …] body becomes one
			// QueryRow DATA frame (the serialized result element), preserving the
			// per-doc hash + matches identically to the CSRP wire form.
			m := pb_decode_query_request(call.message) or { return grpc_invalid('query: bad request') }
			resp := svc_handle_request(grpc_synth_req('query', m.store, '', {
				'path': m.query.bytestr()
			}, authz, tp), mut state, ctx)
			if e := grpc_resp_error(resp) {
				return e
			}
			mut frames := [][]u8{}
			for row in grpc_query_rows(svc_response_body(resp)) {
				frames << pb_encode_query_row(GrpcQueryRow{
					row:      row
					encoding: 'cxd'
				})
			}
			return GrpcReply{
				frames: frames
				status: GrpcStatus{grpc_ok, '', ''}
			}
		}
		'iter' {
			// Server-streaming: enumerate the mount via the shared CSRP iter route
			// and emit one Doc DATA frame per stored doc (hash + canonical body).
			m := pb_decode_store_request(call.message) or { return grpc_invalid('iter: bad request') }
			resp := svc_handle_request(grpc_synth_req('iter', m.store, '', map[string]string{},
				authz, tp), mut state, ctx)
			if e := grpc_resp_error(resp) {
				return e
			}
			mut frames := [][]u8{}
			for d in grpc_iter_docs(svc_response_body(resp)) {
				frames << pb_encode_doc(d)
			}
			return GrpcReply{
				frames: frames
				status: GrpcStatus{grpc_ok, '', ''}
			}
		}
		'modify' {
			// Unary: the source hash is the CSRP `hash` query-param, the action
			// element is the request body. The shared modify route applies it,
			// content-addresses the result, and returns
			// [modify-result old-hash="…" new-hash="…" stored="…"].
			m := pb_decode_modify_request(call.message) or {
				return grpc_invalid('modify: bad request')
			}
			resp := svc_handle_request(grpc_synth_req('modify', m.store, m.action.bytestr(),
				{
				'hash': m.hash
			}, authz, tp), mut state, ctx)
			if e := grpc_resp_error(resp) {
				return e
			}
			body := svc_response_body(resp)
			return grpc_unary(pb_encode_modify_response(GrpcModifyResponse{
				old_hash: grpc_attr_of(body, 'old-hash')
				new_hash: grpc_attr_of(body, 'new-hash')
				stored:   grpc_attr_of(body, 'stored') == 'true'
			}))
		}
		'objects-have', 'objects-get', 'objects-put', 'refs', 'refs-set', 'aliases',
		'aliases-set' {
			// Object wire: every verb is cxd-text-body in, cxd-text-body out, so one
			// shape drives all five — synthesize the CSRP-equivalent request and route
			// it through the SAME store_csrp_route the CSRP listener uses (exact
			// cross-transport parity, spec §6.1 single-source-of-truth). The hex object
			// bytes ride the cxd body unchanged.
			m := pb_decode_objwire_request(call.message) or {
				return grpc_invalid('${op}: bad request')
			}
			resp := svc_handle_request(grpc_synth_req(op, m.store, m.body.bytestr(),
				map[string]string{}, authz, tp), mut state, ctx)
			if e := grpc_resp_error(resp) {
				return e
			}
			return grpc_unary(pb_encode_objwire_response(GrpcObjWireResponse{
				body: svc_response_body(resp).bytes()
			}))
		}
		'status', 'gc', 'mounts', 'config-reload' {
			// #248 admin plane: synthesize the CSRP-equivalent request and route it
			// through the SAME svc pipeline (admin RBAC + tenant enforced there —
			// exact cross-transport parity, §6.1). status/mounts are GET routes on
			// the CSRP side, gc + config-reload (#251 §3.13) are POST; mounts and
			// config-reload are daemon-level (store ignored).
			// Request = GrpcStoreRequest {store=1}; response = the porcelain element
			// as a cxd-text body (the same {body=1} carrier the object wire uses).
			m := pb_decode_store_request(call.message) or {
				return grpc_invalid('${op}: bad request')
			}
			verb := if op in ['gc', 'config-reload'] { 'POST' } else { 'GET' }
			sname := if op in ['mounts', 'config-reload'] { '' } else { m.store }
			resp := svc_handle_request(grpc_synth_req_m(op, sname, '', map[string]string{},
				authz, tp, verb), mut state, ctx)
			if e := grpc_resp_error(resp) {
				return e
			}
			return grpc_unary(pb_encode_objwire_response(GrpcObjWireResponse{
				body: svc_response_body(resp).bytes()
			}))
		}
		else {
			// A genuinely unknown method reports UNIMPLEMENTED honestly rather than
			// faking a result. (put/get/delete/list/capabilities/query/iter/modify +
			// the object wire + the admin plane are all wired above — the full op
			// surface.)
			return GrpcReply{
				status: GrpcStatus{grpc_unimplemented, 'E_CSRP_OPERATION_UNSUPPORTED: op `${op}`', 'cx-err:CXER1709'}
			}
		}
	}
}

// grpc_encode_response serializes a dispatch reply as the HTTP/2 frames the
// server writes back on `stream_id`: a response HEADERS (:status 200,
// content-type application/grpc), one DATA frame per reply message (gRPC
// length-prefixed), and a trailer HEADERS (END_STREAM) carrying grpc-status +
// grpc-message + the cx-err-code (the CSRP CXER, for cross-transport identity).
// Header blocks use the literal (no-Huffman) HPACK encoder.
pub fn grpc_encode_response(stream_id u32, reply GrpcReply) []u8 {
	mut out := []u8{}
	out << h2_frame_encode(H2Frame{
		typ:       h2_headers
		flags:     h2_flag_end_headers
		stream_id: stream_id
		payload:   hpack_encode_header_list([
			HpackHeader{':status', '200'},
			HpackHeader{'content-type', 'application/grpc'},
		])
	})
	for f in reply.frames {
		out << h2_frame_encode(H2Frame{
			typ:       h2_data
			stream_id: stream_id
			payload:   grpc_frame_encode(f)
		})
	}
	mut trailer := [
		HpackHeader{'grpc-status', reply.status.code.str()},
	]
	if reply.status.message != '' {
		trailer << HpackHeader{'grpc-message', grpc_message_encode(reply.status.message)}
	}
	// #194: the cx-err-code trailer carries the EXACT `cx-err:CXERnnnn` (not the
	// mnemonic / free text), so a client keys on the precise CXER regardless of
	// transport — the parity contract (§3).
	if reply.status.cx_err != '' {
		trailer << HpackHeader{'cx-err-code', reply.status.cx_err}
	}
	out << h2_frame_encode(H2Frame{
		typ:       h2_headers
		flags:     h2_flag_end_headers | h2_flag_end_stream
		stream_id: stream_id
		payload:   hpack_encode_header_list(trailer)
	})
	return out
}

// GrpcServePool is the gRPC listener's connection concurrency — the analogue of
// ServePool, but the job is a whole connection node (cx.Node) rather than a bare
// fd: a gRPC connection carries V-side state (the net handle, its buffered
// reader, any TLS session) that an int fd cannot reconstruct. N worker threads
// drain a bounded `queue`-deep channel (submit blocks when full → backpressure,
// the same robustness floor as the CSRP pool — never unbounded thread spawning).
// Each worker owns its OWN lifecycle ServiceState (created once, reused across
// the connections it serves sequentially), so there is no shared `mut state`
// contention across threads; the shared ServeContext's `&` members
// (limiter/metrics/tracer) are mutex-guarded. Sound under the default
// cooperative-safepoint STW vgc.
pub struct GrpcServePool {
mut:
	work chan cx.Node
	wg   &sync.WaitGroup = unsafe { nil }
	ctx  ServeContext
}

// new_grpc_serve_pool starts `workers` threads draining a `queue`-deep connection
// channel; each worker serves connections through the gRPC dispatch adapter.
pub fn new_grpc_serve_pool(workers int, queue int, ctx ServeContext) &GrpcServePool {
	mut p := &GrpcServePool{
		work: chan cx.Node{cap: queue}
		wg:   sync.new_waitgroup()
		ctx:  ctx
	}
	for _ in 0 .. workers {
		p.wg.add(1)
		spawn p.run_grpc_worker()
	}
	return p
}

fn (mut p GrpcServePool) run_grpc_worker() {
	work := p.work
	mut state := new_service_state()
	state.mark_ready()
	for {
		conn := <-work or { break } // channel closed + drained → worker exits
		serve_grpc_connection(conn, mut state, p.ctx)
	}
	p.wg.done()
}

// submit enqueues an accepted connection; blocks when the queue is full
// (backpressure — the accept loop stops pulling new connections until a worker
// frees a slot).
pub fn (mut p GrpcServePool) submit(conn cx.Node) {
	p.work <- conn
}

// drain closes the queue (no new connections), lets workers finish what's in
// flight, and joins them — the graceful-shutdown primitive.
pub fn (mut p GrpcServePool) drain() {
	p.work.close()
	p.wg.wait()
}

// drain_bounded closes the queue and waits for the gRPC workers to finish up to
// `deadline_ms` (#211/#186 — parity with the CSRP bounded drain; a stuck stream
// cannot stall exit indefinitely). Returns true if fully drained.
pub fn (mut p GrpcServePool) drain_bounded(deadline_ms i64) bool {
	p.work.close()
	done := chan bool{cap: 1}
	spawn fn (mut wg sync.WaitGroup, ch chan bool) {
		wg.wait()
		ch <- true
	}(mut p.wg, done)
	select {
		_ := <-done {
			return true
		}
		deadline_ms * time.millisecond {
			return false
		}
	}
	return false
}

// run_grpc_serve_loop is the opt-in gRPC listener (decision 2b), run on its own
// thread alongside the CSRP loop. It accepts connections off `server` and
// dispatches each to a bounded worker pool (concurrent multiplexing across
// connections; within a connection, H2Conn reassembles every stream and
// grpc_dispatch handles each call), sharing the ServeContext
// (mounts/auth/limiter/metrics/tracer — the `&` members are mutex-guarded). It
// runs until `should_stop()` or the listener closes (the CLI closes it on signal
// to unblock the blocking accept), then drains the pool. Mirrors run_serve_loop.
pub fn run_grpc_serve_loop(server cx.Node, ctx ServeContext, workers int, queue int, should_stop fn () bool) {
	mut pool := new_grpc_serve_pool(workers, queue, ctx)
	// #233: like run_serve_loop, keep accepting until the listener is closed by the
	// shutdown watcher after the drain grace — so a gRPC client mid-drain is
	// accepted and served (the store dispatch reports draining/unavailable) rather
	// than connection-refused the instant a signal lands. `should_stop` is retained
	// as a defensive belt (an accept fault still breaks the loop).
	_ = should_stop
	for {
		mut h := net_mut_handle(server) or { break }
		conn := net_accept_real(mut h)
		if is_err_value(conn) {
			break // listener closed (drain grace elapsed) or accept fault
		}
		pool.submit(conn)
	}
	pool.drain_bounded(30000)
}

// serve_grpc_connection drives one HTTP/2 connection: raw socket bytes →
// H2Conn.feed → write the server's frames → dispatch each completed call and
// write its response. net_h_read_step is a single recv (NOT net_read_bytes_real,
// which blocks until it fills N and would deadlock a request/response exchange).
fn serve_grpc_connection(conn cx.Node, mut state ServiceState, ctx ServeContext) {
	mut ch := net_mut_handle(conn) or { return }
	mut gc := new_h2_conn()
	mut buf := []u8{len: 16384}
	for {
		if !net_h_connected(ch) {
			break
		}
		kind, rd := net_h_read_step(mut ch, mut buf)
		if kind == .eof {
			break
		}
		if kind == .timeout {
			continue
		}
		if rd <= 0 {
			continue
		}
		out := gc.feed(buf[..rd].clone())
		if out.len > 0 {
			net_h_write(mut ch, out) or { break }
		}
		// #223: a connection error (GOAWAY emitted) terminates the connection —
		// write nothing further and close, per RFC §5.4.1.
		if gc.is_fatal() {
			break
		}
		for call in gc.take_calls() {
			wire := grpc_encode_response(call.stream_id, grpc_dispatch(call, mut state, ctx))
			net_h_write(mut ch, wire) or { return }
		}
	}
}

// grpc_op_from_path maps a gRPC method path (/cxstore.v1.CxStore/<Method>) to the
// CSRP op name. Unknown → '' (→ UNIMPLEMENTED).
fn grpc_op_from_path(path string) string {
	method := path.all_after_last('/')
	return match method {
		'Put' { 'put' }
		'Get' { 'get' }
		'Delete' { 'delete' }
		'List' { 'list' }
		'Iter' { 'iter' }
		'Query' { 'query' }
		'Modify' { 'modify' }
		'Capabilities' { 'capabilities' }
		// object wire (#129 PR-B item 4) — content-addressed objects + refs.
		'ObjectsHave' { 'objects-have' }
		'ObjectsGet' { 'objects-get' }
		'ObjectsPut' { 'objects-put' }
		'Refs' { 'refs' }
		'RefsSet' { 'refs-set' }
		// alias remoting (#645) — same objwire body shape, spec §3.14.
		'Aliases' { 'aliases' }
		'AliasesSet' { 'aliases-set' }
		// admin plane (#248 / CSRP §3.10–3.12; #251 §3.13)
		'Status' { 'status' }
		'Gc' { 'gc' }
		'Mounts' { 'mounts' }
		'Reload' { 'config-reload' }
		else { '' }
	}
}

// grpc_synth_req synthesizes the CSRP-equivalent cx request the pipeline expects:
// POST /cx-store/v1/[<store>/]<op>, with the bearer (if any) as an Authorization
// header, the inbound W3C `traceparent` (if any) so a gRPC hop CONTINUES the
// distributed trace rather than minting a fresh root, the named query-params, and the
// body octets.
fn grpc_synth_req(op string, store string, body string, qparams map[string]string, authz string, traceparent string) cx.Element {
	return grpc_synth_req_m(op, store, body, qparams, authz, traceparent, 'POST')
}

// grpc_synth_req_m is grpc_synth_req with an explicit HTTP method — the #248
// admin ops status/mounts are GET routes on the CSRP side.
fn grpc_synth_req_m(op string, store string, body string, qparams map[string]string, authz string, traceparent string, method string) cx.Element {
	mut items := []cx.Node{}
	mut hdrs := []cx.Node{}
	if authz != '' {
		hdrs << cx.Node(cx.Element{
			name:  'header'
			attrs: [
				cx.Attribute{
					name:  'name'
					value: cx.ScalarValue('Authorization')
				},
				cx.Attribute{
					name:  'value'
					value: cx.ScalarValue(authz)
				},
			]
		})
	}
	if traceparent != '' {
		hdrs << cx.Node(cx.Element{
			name:  'header'
			attrs: [
				cx.Attribute{
					name:  'name'
					value: cx.ScalarValue('traceparent')
				},
				cx.Attribute{
					name:  'value'
					value: cx.ScalarValue(traceparent)
				},
			]
		})
	}
	items << cx.Node(cx.Element{
		name:  'headers'
		items: hdrs
	})
	if qparams.len > 0 {
		mut qp := []cx.Node{}
		for k, v in qparams {
			qp << cx.Node(cx.Element{
				name:  k
				items: [cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(v)
					data_type: cx.ScalarType.string_type
				})]
			})
		}
		items << cx.Node(cx.Element{
			name:  'query-params'
			items: qp
		})
	}
	if body != '' {
		items << cx.Node(cx.Element{
			name:  'body'
			items: [cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(body)
				data_type: cx.ScalarType.string_type
			})]
		})
	}
	path := if store != '' { '/cx-store/v1/${store}/${op}' } else { '/cx-store/v1/${op}' }
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
		items: items
	}
}

fn grpc_synth_capabilities(authz string) cx.Element {
	mut req := grpc_synth_req('capabilities', '', '', map[string]string{}, authz, '')
	// capabilities is a GET in CSRP.
	return cx.Element{
		...req
		attrs: [
			cx.Attribute{
				name:  'method'
				value: cx.ScalarValue('GET')
			},
			cx.Attribute{
				name:  'path'
				value: cx.ScalarValue('/cx-store/v1/capabilities')
			},
		]
	}
}

// grpc_unary wraps a single response message as a 1-frame OK reply.
fn grpc_unary(data []u8) GrpcReply {
	return GrpcReply{
		frames: [data]
		status: GrpcStatus{grpc_ok, '', ''}
	}
}

fn grpc_invalid(msg string) GrpcReply {
	return GrpcReply{
		status: GrpcStatus{grpc_invalid_argument, msg, 'cx-err:CXER1701'}
	}
}

// grpc_resp_error maps a non-200 CSRP response to a gRPC error reply (status +
// CXER-derived trailer), or none when the response is a 200 success.
fn grpc_resp_error(resp cx.Node) ?GrpcReply {
	status := svc_resp_status(resp)
	if status == 200 {
		return none
	}
	body := svc_response_body(resp)
	errcode := grpc_attr_of(body, 'code') // [err code="cx-err:CXERnnnn" …]
	gs := grpc_status_for_cxer(errcode)
	return GrpcReply{
		status: gs
	}
}

// grpc_attr_of extracts a `key="value"` (or key='value') attribute value from a
// CSRP wire element body like [put-result hash="…"] / [err code="…"]. Cheap
// surface scan — the wire forms are flat single elements.
fn grpc_attr_of(body string, key string) string {
	needle := '${key}="'
	mut i := body.index(needle) or {
		alt := "${key}='"
		j := body.index(alt) or { return '' }
		end := body.index_after("'", j + alt.len) or { return '' }
		return body[j + alt.len..end]
	}
	start := i + needle.len
	end := body.index_after('"', start) or { return '' }
	return body[start..end]
}

// grpc_query_rows parses a [query-result [result hash="H" <matches>] …] wire body
// into one serialized [result …] element per matching doc — each becomes a
// QueryRow DATA frame. The result element is rendered canonically so the gRPC
// row carries the same hash + match content as the CSRP wire form
// (cross-transport parity by construction).
fn grpc_query_rows(body string) [][]u8 {
	mut out := [][]u8{}
	doc := cx.parse(body) or { return out }
	for el in doc.elements {
		if el is cx.Element && el.name == 'query-result' {
			for r in el.items {
				if r is cx.Element && r.name == 'result' {
					out << render_canonical(r).bytes()
				}
			}
		}
	}
	return out
}

// grpc_iter_docs parses an [iter-result [doc hash="H" <doc>] …] wire body into
// one GrpcDoc per stored doc (hash + canonical body), each becoming a Doc DATA
// frame. The body is rendered canonically so a gRPC iter doc carries the same
// bytes a CSRP iter / gRPC get would (cross-transport parity by construction).
fn grpc_iter_docs(body string) []GrpcDoc {
	mut out := []GrpcDoc{}
	doc := cx.parse(body) or { return out }
	for el in doc.elements {
		if el is cx.Element && el.name == 'iter-result' {
			for dn in el.items {
				if dn is cx.Element && dn.name == 'doc' {
					mut hash := ''
					for a in dn.attrs {
						if a.name == 'hash' {
							hash = cx.scalar_value_str_public(a.value)
						}
					}
					mut sb := ''
					for inner in dn.items {
						sb += render_canonical(inner)
					}
					out << GrpcDoc{
						hash:     hash
						body:     sb.bytes()
						encoding: 'cxd'
					}
				}
			}
		}
	}
	return out
}

// grpc_list_hashes extracts the 64-hex hashes from a [list-result [hashes [hash
// "h"] …]] wire body.
fn grpc_list_hashes(body string) []string {
	mut out := []string{}
	needle := '[hash "'
	mut from := 0
	for {
		i := body.index_after(needle, from) or { break }
		hs := i + needle.len // index_after returns the match start → skip the prefix
		end := body.index_after('"', hs) or { break }
		h := body[hs..end]
		if h.len == 64 {
			out << h
		}
		from = end + 1
	}
	return out
}
