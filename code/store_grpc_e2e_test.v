module code

// store_grpc_e2e_test.v — full gRPC server path, in memory + socket-free
// (brick 4b core): a client byte stream (preface+SETTINGS+HEADERS+DATA) → H2Conn
// reassembly → grpc_dispatch (real store pipeline) → grpc_encode_response →
// decoded back with a *client-side* HPACK decoder. Proves request decode,
// dispatch, response framing, and the trailer status are all wire-correct,
// without the socket plumbing (that glue is brick 4b-ii).

fn e2e_ctx() (&ServiceState, ServeContext) {
	mut s := new_service_state()
	s.mark_ready()
	ctx := ServeContext{
		mounts: {
			'docs': store_open_impl('mem://grpc-e2e', '', '', false, true, map[string]string{})
		}
		auth:   AuthContext{}
	}
	return s, ctx
}

// build a client request byte stream for one unary call on stream 1.
fn e2e_client_stream(method string, msg []u8) []u8 {
	mut b := []u8{}
	b << h2_preface.bytes()
	b << h2_frame_encode(h2_settings_frame([]H2Setting{}))
	b << h2_frame_encode(H2Frame{
		typ:       h2_headers
		flags:     h2_flag_end_headers
		stream_id: 1
		payload:   hpack_encode_header_list([
			HpackHeader{':method', 'POST'},
			HpackHeader{':scheme', 'http'},
			HpackHeader{':path', '/cxstore.v1.CxStore/${method}'},
			HpackHeader{'content-type', 'application/grpc'},
			HpackHeader{'te', 'trailers'},
		])
	})
	b << h2_frame_encode(H2Frame{
		typ:       h2_data
		flags:     h2_flag_end_stream
		stream_id: 1
		payload:   grpc_frame_encode(msg)
	})
	return b
}

// run one full call against an H2Conn-backed server; return the decoded response
// (status pseudo-header, the first DATA message, the grpc-status trailer).
struct E2EResponse {
	http_status string
	message     []u8
	grpc_status string
}

fn e2e_call(mut c H2Conn, mut s ServiceState, ctx ServeContext, method string, msg []u8) E2EResponse {
	c.feed(e2e_client_stream(method, msg)) // server preface bytes ignored here
	mut wire := []u8{}
	for call in c.take_calls() {
		reply := grpc_dispatch(call, mut s, ctx)
		wire << grpc_encode_response(call.stream_id, reply)
	}
	// client-side decode of the server's frames
	mut r := H2FrameReader{}
	r.feed(wire)
	mut cli_dec := new_hpack_decoder(4096)
	mut http_status := ''
	mut grpc_status := ''
	mut message := []u8{}
	for {
		f := r.next() or { break }
		match f.typ {
			h2_headers {
				hdrs := cli_dec.decode(f.payload) or { []HpackHeader{} }
				for h in hdrs {
					if h.name == ':status' {
						http_status = h.value
					}
					if h.name == 'grpc-status' {
						grpc_status = h.value
					}
				}
			}
			h2_data {
				mut fr := GrpcFrameReader{}
				fr.feed(f.payload)
				if gf := fr.next() {
					message = gf.data.clone()
				}
			}
			else {}
		}
	}
	return E2EResponse{http_status, message, grpc_status}
}

fn test_grpc_e2e_put_then_get() {
	mut s, ctx := e2e_ctx()

	// PUT over the full wire path
	mut put_conn := new_h2_conn()
	put_resp := e2e_call(mut put_conn, mut s, ctx, 'Put', pb_encode_put_request(GrpcPutRequest{
		store:    'docs'
		body:     '[note [body "grpc-e2e"]]'.bytes()
		encoding: 'cxd'
	}))
	assert put_resp.http_status == '200', 'put :status ${put_resp.http_status}'
	assert put_resp.grpc_status == '0', 'put grpc-status ${put_resp.grpc_status}'
	pr := pb_decode_put_response(put_resp.message) or { panic('decode put') }
	assert pr.hash.len == 64, 'put hash ${pr.hash}'

	// GET it back over the full wire path (new connection)
	mut get_conn := new_h2_conn()
	get_resp := e2e_call(mut get_conn, mut s, ctx, 'Get', pb_encode_get_request(GrpcGetRequest{
		store: 'docs'
		hash:  pr.hash
	}))
	assert get_resp.http_status == '200'
	assert get_resp.grpc_status == '0'
	gr := pb_decode_get_response(get_resp.message) or { panic('decode get') }
	assert gr.body.bytestr().contains('grpc-e2e'), 'doc round-trip over gRPC wire: ${gr.body.bytestr()}'
}

fn test_grpc_e2e_missing_hash_trailer_status() {
	mut s, ctx := e2e_ctx()
	mut conn := new_h2_conn()
	resp := e2e_call(mut conn, mut s, ctx, 'Get', pb_encode_get_request(GrpcGetRequest{
		store: 'docs'
		hash:  '0'.repeat(64)
	}))
	// HTTP/2 is still 200 (gRPC errors ride the trailer, not the HTTP status).
	assert resp.http_status == '200'
	assert resp.grpc_status == grpc_not_found.str(), 'missing hash trailer grpc-status ${resp.grpc_status}, want ${grpc_not_found}'
}
