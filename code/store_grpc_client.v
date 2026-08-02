module code

import cx

// store_grpc_client.v — the gRPC CLIENT transport for `cx-store+grpc://` /
// `cx-store+grpcs://` store backends. It is the dialing-side counterpart to the
// server's gRPC listener: it reuses the SAME HTTP/2 framing + HPACK + protobuf
// codec (store_grpc_{frame,hpack,proto}.v) the server uses, so client and server
// speak provably the same wire. Without this, the gRPC server has no client to
// talk to it — a listener nobody can reach. With it, `[$store:open]` (and, via
// the cx_code_eval_caps façade, the Python/Go/Rust client libraries) drive the
// store over gRPC through ONE implementation, at parity with the CSRP client.
//
// Transport: net_dial_impl (the cap-gated, §4.5-SSRF-guarded dial) yields a
// NetHandle; the request is one HTTP/2 stream (preface + SETTINGS + HEADERS +
// END_STREAM DATA), and the response frames are read back, HPACK-decoded for the
// grpc-status trailer, and the DATA frames drained into gRPC messages.

// per-read budget so a stalled/half-open server cannot hang the store op.
const grpc_client_read_deadline_ms = i64(5000)

// GrpcClientResult is one call's outcome: the gRPC trailer status + message and
// the ordered response messages (one for a unary op, N for a server-streaming op).
struct GrpcClientResult {
mut:
	grpc_status  int = -1
	http_status  string
	grpc_message string
	cx_err       string // the `cx-err-code` trailer (`cx-err:CXERnnnn`) — #194, the precise error identity
	messages     [][]u8
}

// grpc_client_call dials the gRPC server, issues ONE call (`method` = the CxStore
// RPC name, e.g. "Put"), and returns its result. ok=false with errn set on a
// transport failure (unreachable / write / no trailer); a non-zero grpc_status is
// a SUCCESSFUL exchange carrying a server error — the caller maps it to the store
// error space.
fn grpc_client_call(rb &RemoteBackend, method string, msg []u8) (GrpcClientResult, cx.Node, bool) {
	// net effect — deny-by-default. The dial impl below bypasses the verb-level
	// cap_guard (it is called directly), so gate here (mirrors store_csrp_handle).
	if d := cap_guard('net', 'store grpc ${method}') {
		return GrpcClientResult{}, d, false
	}
	tls := rb.scheme == 'cx-store+grpcs'
	url := if tls { 'tls://${rb.host}:${rb.port}' } else { 'tcp://${rb.host}:${rb.port}' }
	opts := cx.Node(cx.Element{
		name:  '__cx_map__'
		items: [
			cx.Node(cx.Element{
				name:  'read-deadline'
				items: [
					cx.Node(cx.ScalarNode{
						value:     cx.ScalarValue(grpc_client_read_deadline_ms)
						data_type: cx.ScalarType.int_type
					}),
				]
			}),
		]
	})
	conn := net_dial_impl(if tls { 'net-dial-tls' } else { 'net-dial-tcp' }, [
		cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(url)
			data_type: cx.ScalarType.string_type
		}),
		opts,
	])
	if is_err_value(conn) {
		mut detail := ''
		if conn is cx.Element {
			detail = http_attr(conn, 'code') or { '' }
		}
		return GrpcClientResult{}, mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: grpc ${method} ${url}: ${detail}'), false
	}
	defer {
		if id := net_handle_id(conn) {
			net_close_id(id)
		}
	}
	mut ch := net_mut_handle(conn) or {
		return GrpcClientResult{}, mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: grpc ${method}: no connection handle'), false
	}

	// ── request: one HTTP/2 stream (stream id 1) ──────────────────────────────
	scheme_hdr := if tls { 'https' } else { 'http' }
	mut hdrs := [
		HpackHeader{':method', 'POST'},
		HpackHeader{':scheme', scheme_hdr},
		HpackHeader{':path', '/cxstore.v1.CxStore/${method}'},
		HpackHeader{':authority', '${rb.host}:${rb.port}'},
		HpackHeader{'content-type', 'application/grpc'},
		HpackHeader{'te', 'trailers'},
	]
	if rb.bearer != '' {
		hdrs << HpackHeader{'authorization', 'Bearer ${rb.bearer}'}
	}
	mut req := []u8{}
	req << h2_preface.bytes()
	req << h2_frame_encode(h2_settings_frame([]H2Setting{}))
	req << h2_frame_encode(H2Frame{
		typ:       h2_headers
		flags:     h2_flag_end_headers
		stream_id: 1
		payload:   hpack_encode_header_list(hdrs)
	})
	req << h2_frame_encode(H2Frame{
		typ:       h2_data
		flags:     h2_flag_end_stream
		stream_id: 1
		payload:   grpc_frame_encode(msg)
	})
	net_h_write(mut ch, req) or {
		return GrpcClientResult{}, mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: grpc ${method}: write: ${err.msg()}'), false
	}

	// ── response: read frames until the grpc-status trailer (or EOF/timeout) ──
	mut r := H2FrameReader{}
	mut dec := new_hpack_decoder(4096)
	mut gfr := GrpcFrameReader{} // persistent: a gRPC message MAY span DATA frames
	mut res := GrpcClientResult{}
	mut buf := []u8{len: 16384}
	for {
		if !net_h_connected(ch) {
			break
		}
		kind, n := net_h_read_step(mut ch, mut buf)
		if kind == .eof {
			break
		}
		if kind == .timeout {
			break // deadline lapsed — stop rather than hang
		}
		if n <= 0 {
			continue
		}
		r.feed(buf[..n].clone())
		mut done := false
		for {
			f := r.next() or { break }
			if f.typ == h2_headers {
				for h in dec.decode(f.payload) or { []HpackHeader{} } {
					match h.name {
						':status' { res.http_status = h.value }
						'grpc-status' {
							res.grpc_status = h.value.int()
							done = true // trailer seen
						}
						'grpc-message' {
							res.grpc_message = h.value
						}
						'cx-err-code' {
							res.cx_err = h.value // #194: the exact cx-err:CXERnnnn
						}
						else {}
					}
				}
			} else if f.typ == h2_data {
				gfr.feed(f.payload)
				for {
					gf := gfr.next() or { break }
					res.messages << gf.data.clone()
				}
			}
		}
		if done {
			break
		}
	}
	if res.grpc_status < 0 {
		return GrpcClientResult{}, mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: grpc ${method}: no grpc-status trailer (server closed early?)'), false
	}
	return res, store_null(), true
}

// grpc_client_status_err maps a non-zero gRPC trailer status onto the store error
// space, mirroring csrp_status_err so the cx-store+grpc backend reports the same
// grpc_client_admin — the #248 admin plane over gRPC (Status / Gc / Mounts):
// returns the same porcelain element the CSRP transport returns, decoded from
// the generic {body=1} cxd-text carrier. mounts is daemon-level (empty store
// field); status/gc target rb.dir. The exact wire CXER rides the cx-err-code
// trailer: 1709 (unsupported — e.g. gc on a backend with no object graph)
// surfaces symbolically, exactly as the local porcelain raises it.
fn grpc_client_admin(rb &RemoteBackend, op string) cx.Node {
	method := match op {
		'status' { 'Status' }
		'gc' { 'Gc' }
		'config-reload' { 'Reload' }
		else { 'Mounts' }
	}
	sname := if op in ['mounts', 'config-reload'] { '' } else { rb.dir }
	res, errn, ok := grpc_client_call(rb, method, pb_encode_store_request(GrpcStoreRequest{
		store: sname
	}))
	if !ok {
		return errn
	}
	if res.grpc_status != 0 {
		num := grpc_cxer_num(res.cx_err)
		if num == 1709 {
			return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: grpc ${op}: ${res.grpc_message}')
		}
		// #251 §3.13: the reload refusals are actionable, distinct outcomes
		// (fix the config vs restart the daemon) — surface the exact wire code
		// from the cx-err-code trailer, never a coarse transport error.
		if num == 1711 || num == 1712 {
			return mk_err('cx-err:CXER${num}', res.grpc_message)
		}
		return grpc_client_status_err(op, '', res)
	}
	if res.messages.len == 0 {
		return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: grpc ${op}: empty response')
	}
	m := pb_decode_objwire_response(res.messages[0]) or {
		return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: grpc ${op}: malformed response')
	}
	parsed := cx.parse(m.body.bytestr()) or {
		return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: grpc ${op}: malformed response body')
	}
	if parsed.elements.len == 0 {
		return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: grpc ${op}: empty response body')
	}
	return parsed.elements[0]
}

// store errors a cx-store+http backend would. The grpc-status codes are the
// reconciled CSRP↔gRPC table (store_grpc_frame.v grpc_status_for_cxer, applied in
// reverse here): 5 NOT_FOUND, 16 UNAUTHENTICATED, 7 PERMISSION_DENIED, 8
// RESOURCE_EXHAUSTED, 14 UNAVAILABLE, 12 UNIMPLEMENTED.
fn grpc_client_status_err(op string, hash string, res GrpcClientResult) cx.Node {
	detail := if res.grpc_message != '' { res.grpc_message } else { 'grpc-status ${res.grpc_status}' }
	// #194: prefer the precise CXER carried in the cx-err-code trailer — it
	// disambiguates codes that share one grpc-status (413 CXER1705 and 429 CXER1706
	// are both RESOURCE_EXHAUSTED (8); 404 CXER1721 hash-not-found and CXER1710
	// store-not-found are both NOT_FOUND (5)). Fall back to the coarse grpc-status.
	num := grpc_cxer_num(res.cx_err)
	match num {
		1705 { return mk_err('cx-err:CXER1132', 'E_STORE_RATE_LIMIT: grpc ${op}: payload too large: ${detail}') }
		1706 { return mk_err('cx-err:CXER1132', 'E_STORE_RATE_LIMIT: grpc ${op}: ${detail}') }
		1710 { return mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: store: ${detail}') }
		1720 { return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: grpc ${op}: ${detail}') }
		1704 { return mk_err('cx-err:CXER1114', 'E_STORE_REF_CONFLICT: grpc ${op}: ${detail}') }
		else {}
	}
	return match res.grpc_status {
		5 { mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: ${hash}') }
		16 { mk_err('cx-err:CXER1131', 'E_STORE_AUTH_FAILED: grpc ${op}: ${detail}') }
		7 { mk_err('cx-err:CXER1131', 'E_STORE_AUTH_FAILED: grpc ${op}: ${detail}') }
		8 { mk_err('cx-err:CXER1132', 'E_STORE_RATE_LIMIT: grpc ${op}: ${detail}') }
		14 { mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: grpc ${op}: ${detail}') }
		12 { mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: grpc ${op}: ${detail}') }
		else { mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: grpc ${op}: ${detail}') }
	}
}

// ── per-op client helpers (return the SAME shapes csrp_client_* / the local
//    builtins return, so the cx-store+grpc backend is a drop-in transport) ──────

// rb.dir is the store-name path segment; the gRPC request's `store` field routes
// it to the named mount (the server's grpc_synth_req builds /cx-store/v1/<store>/…).

fn grpc_client_get(rb &RemoteBackend, hash string) (string, cx.Node, bool) {
	res, errn, ok := grpc_client_call(rb, 'Get', pb_encode_get_request(GrpcGetRequest{
		store: rb.dir
		hash:  hash
	}))
	if !ok {
		return '', errn, false
	}
	if res.grpc_status == 5 {
		return '', mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: ${hash}'), false
	}
	if res.grpc_status != 0 {
		return '', grpc_client_status_err('get', hash, res), false
	}
	if res.messages.len == 0 {
		return '', mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: grpc get: empty response'), false
	}
	m := pb_decode_get_response(res.messages[0]) or {
		return '', mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: grpc get: malformed GetResponse'), false
	}
	return m.body.bytestr(), store_null(), true
}

fn grpc_client_put(rb &RemoteBackend, hash string, text string) cx.Node {
	res, errn, ok := grpc_client_call(rb, 'Put', pb_encode_put_request(GrpcPutRequest{
		store:    rb.dir
		body:     text.bytes()
		encoding: 'cxd'
	}))
	if !ok {
		return errn
	}
	if res.grpc_status != 0 {
		return grpc_client_status_err('put', hash, res)
	}
	return store_null()
}

fn grpc_client_has(rb &RemoteBackend, hash string) (bool, cx.Node, bool) {
	res, errn, ok := grpc_client_call(rb, 'Get', pb_encode_get_request(GrpcGetRequest{
		store: rb.dir
		hash:  hash
	}))
	if !ok {
		return false, errn, false
	}
	if res.grpc_status == 5 {
		return false, store_null(), true
	}
	if res.grpc_status != 0 {
		return false, grpc_client_status_err('get', hash, res), false
	}
	return true, store_null(), true
}

fn grpc_client_delete(rb &RemoteBackend, hash string) (bool, cx.Node, bool) {
	res, errn, ok := grpc_client_call(rb, 'Delete', pb_encode_delete_request(GrpcDeleteRequest{
		store: rb.dir
		hash:  hash
	}))
	if !ok {
		return false, errn, false
	}
	if res.grpc_status != 0 {
		return false, grpc_client_status_err('delete', hash, res), false
	}
	if res.messages.len == 0 {
		return false, store_null(), true
	}
	m := pb_decode_delete_response(res.messages[0]) or {
		return false, mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: grpc delete: malformed DeleteResponse'), false
	}
	return m.deleted, store_null(), true
}

fn grpc_client_list(rb &RemoteBackend) ([]string, cx.Node, bool) {
	res, errn, ok := grpc_client_call(rb, 'List', pb_encode_store_request(GrpcStoreRequest{
		store: rb.dir
	}))
	if !ok {
		return []string{}, errn, false
	}
	if res.grpc_status != 0 {
		return []string{}, grpc_client_status_err('list', '', res), false
	}
	mut out := []string{}
	for m in res.messages {
		hi := pb_decode_hash_item(m) or { continue }
		if store_is_doc_hash(hi.hash) {
			out << hi.hash
		}
	}
	return out, store_null(), true
}

// grpc_client_query reconstructs the local store_query shape: store_seq of
// [result hash="H" [seq <matches>]]. Each QueryRow.row is a rendered
// [result hash="H" <m1> <m2> …] element (the flattened CSRP wire form).
fn grpc_client_query(rb &RemoteBackend, cxpath string) cx.Node {
	res, errn, ok := grpc_client_call(rb, 'Query', pb_encode_query_request(GrpcQueryRequest{
		store: rb.dir
		query: cxpath.bytes()
	}))
	if !ok {
		return errn
	}
	if res.grpc_status == 12 {
		return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: the gRPC server does not support the query op')
	}
	if res.grpc_status != 0 {
		return grpc_client_status_err('query', '', res)
	}
	mut results := []cx.Node{}
	for m in res.messages {
		qr := pb_decode_query_row(m) or { continue }
		doc := cx.parse(qr.row.bytestr()) or { continue }
		for el in doc.elements {
			if el is cx.Element && el.name == 'result' {
				mut hash := ''
				for a in el.attrs {
					if a.name == 'hash' {
						hash = cx.scalar_value_str_public(a.value)
					}
				}
				mut matches := []cx.Node{}
				for mm in el.items {
					matches << mm
				}
				results << cx.Element{
					name:  'result'
					attrs: [cx.Attribute{
						name:  'hash'
						value: cx.ScalarValue(hash)
					}]
					items: [store_seq(matches)]
				}
			}
		}
	}
	return store_seq(results)
}

// grpc_client_iter reconstructs the local store-iter-docs shape: store_seq of
// [entry hash="H" <doc>]. Each Doc frame carries the hash + canonical doc body.
fn grpc_client_iter(rb &RemoteBackend) cx.Node {
	res, errn, ok := grpc_client_call(rb, 'Iter', pb_encode_store_request(GrpcStoreRequest{
		store: rb.dir
	}))
	if !ok {
		return errn
	}
	if res.grpc_status == 12 {
		return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: the gRPC server does not support the iter op')
	}
	if res.grpc_status != 0 {
		return grpc_client_status_err('iter', '', res)
	}
	mut entries := []cx.Node{}
	for m in res.messages {
		d := pb_decode_doc(m) or { continue }
		docnode := cx.parse(d.body.bytestr()) or { continue }
		mut inner := []cx.Node{}
		for el in docnode.elements {
			inner << el
		}
		entries << cx.Element{
			name:  'entry'
			attrs: [cx.Attribute{
				name:  'hash'
				value: cx.ScalarValue(d.hash)
			}]
			items: inner
		}
	}
	return store_seq(entries)
}

// ── object wire over gRPC (#129 PR-B item 4) ────────────────────────────────────
//
// GrpcObjWireTransport is the gRPC counterpart to CsrpObjWireTransport: it carries the
// SAME cxd-text object-wire body (have/get/put + refs/refs-set) the CSRP transport
// sends, only framed as a unary gRPC call. So a cx-store+grpc:// client drives the
// object wire — decompose locally, transfer only missing objects, advance the ref — at
// exact parity with cx-store+http. RemoteObjectBackend treats `send` like an HTTP call
// (status 200 = ok), so map a clean gRPC exchange (grpc-status 0) to 200 and any
// non-zero trailer to a non-200 so a failed verb surfaces, never a silent success.

// grpc_objwire_method maps a CSRP object-verb op to its gRPC RPC method name.
fn grpc_objwire_method(op string) string {
	return match op {
		'objects-have' { 'ObjectsHave' }
		'objects-get' { 'ObjectsGet' }
		'objects-put' { 'ObjectsPut' }
		'refs' { 'Refs' }
		'refs-set' { 'RefsSet' }
		'aliases' { 'Aliases' }
		'aliases-set' { 'AliasesSet' }
		else { '' }
	}
}

struct GrpcObjWireTransport {
	rb &RemoteBackend
}

fn (t &GrpcObjWireTransport) send(op string, query string, body string) (int, string, bool) {
	method := grpc_objwire_method(op)
	if method == '' {
		return 0, '', false
	}
	res, _, ok := grpc_client_call(t.rb, method, pb_encode_objwire_request(GrpcObjWireRequest{
		store: t.rb.dir
		body:  body.bytes()
	}))
	if !ok {
		return 0, '', false
	}
	if res.grpc_status != 0 {
		// a successful exchange carrying a server error → non-200 (RemoteObjectBackend
		// treats it as a failed verb); 5xx mirrors the CSRP route's internal-error code.
		return 500, '', true
	}
	if res.messages.len == 0 {
		return 200, '', true
	}
	m := pb_decode_objwire_response(res.messages[0]) or { return 500, '', true }
	return 200, m.body.bytestr(), true
}

// new_grpc_remote_object_backend builds the cx-store+grpc:// CLIENT object-wire backend
// (RemoteObjectBackend over the gRPC transport) — the gRPC sibling of
// new_remote_object_backend (CSRP).
pub fn new_grpc_remote_object_backend(rb &RemoteBackend) &RemoteObjectBackend {
	return &RemoteObjectBackend{
		transport: ObjWireTransport(&GrpcObjWireTransport{
			rb: rb
		})
	}
}

fn grpc_client_modify(rb &RemoteBackend, hash string, action_text string) cx.Node {
	res, errn, ok := grpc_client_call(rb, 'Modify', pb_encode_modify_request(GrpcModifyRequest{
		store:  rb.dir
		hash:   hash
		action: action_text.bytes()
	}))
	if !ok {
		return errn
	}
	if res.grpc_status == 5 {
		return mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: ${hash}')
	}
	if res.grpc_status != 0 {
		return grpc_client_status_err('modify', hash, res)
	}
	if res.messages.len == 0 {
		return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: grpc modify: empty response')
	}
	m := pb_decode_modify_response(res.messages[0]) or {
		return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: grpc modify: malformed ModifyResponse')
	}
	if !store_is_doc_hash(m.new_hash) {
		return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: grpc modify: malformed new-hash')
	}
	return store_str(m.new_hash)
}
