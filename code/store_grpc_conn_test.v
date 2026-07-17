module code

// store_grpc_conn_test.v — HTTP/2 connection/stream reassembly (brick 3c). A
// hand-built client byte stream (preface + SETTINGS + HEADERS + DATA) is fed to
// H2Conn; we assert the server preface (SETTINGS + ACK) is emitted and one
// GrpcCall is reassembled with the right :path / content-type / message — fed
// both as one chunk and split across frame boundaries.

fn grpc_req_headers_block() []u8 {
	return hpack_encode_header_list([
		HpackHeader{':method', 'POST'},
		HpackHeader{':scheme', 'http'},
		HpackHeader{':path', '/cxstore.v1.CxStore/Put'},
		HpackHeader{'content-type', 'application/grpc'},
		HpackHeader{'te', 'trailers'},
	])
}

// build a full client request byte stream on stream 1 carrying `msg`.
fn grpc_client_stream(msg []u8) []u8 {
	mut b := []u8{}
	b << h2_preface.bytes()
	b << h2_frame_encode(h2_settings_frame([]H2Setting{}))
	b << h2_frame_encode(H2Frame{
		typ:       h2_headers
		flags:     h2_flag_end_headers
		stream_id: 1
		payload:   grpc_req_headers_block()
	})
	b << h2_frame_encode(H2Frame{
		typ:       h2_data
		flags:     h2_flag_end_stream
		stream_id: 1
		payload:   grpc_frame_encode(msg)
	})
	return b
}

// summarize the server's written frames: was a non-ACK SETTINGS sent, and an ACK?
fn server_emitted_settings_and_ack(out []u8) (bool, bool) {
	mut r := H2FrameReader{}
	r.feed(out)
	mut settings := false
	mut ack := false
	for {
		f := r.next() or { break }
		if f.typ == h2_settings {
			if f.has_flag(h2_flag_ack) {
				ack = true
			} else {
				settings = true
			}
		}
	}
	return settings, ack
}

fn assert_one_put_call(mut c H2Conn, msg []u8) {
	calls := c.take_calls()
	assert calls.len == 1, 'expected exactly one GrpcCall, got ${calls.len}'
	call := calls[0]
	assert call.stream_id == 1, 'stream id ${call.stream_id}'
	assert call.headers[':path'] == '/cxstore.v1.CxStore/Put', 'path: ${call.headers[':path']}'
	assert call.headers['content-type'] == 'application/grpc', 'content-type: ${call.headers['content-type']}'
	assert call.headers[':method'] == 'POST'
	assert call.message == msg, 'message bytes mismatch: ${call.message} vs ${msg}'
}

fn test_h2conn_single_chunk() {
	msg := [u8(0x0a), 0x03, `a`, `b`, `c`] // arbitrary proto-ish bytes
	mut c := new_h2_conn()
	out := c.feed(grpc_client_stream(msg))
	settings, ack := server_emitted_settings_and_ack(out)
	assert settings, 'server must emit its SETTINGS'
	assert ack, 'server must ACK the client SETTINGS'
	assert_one_put_call(mut c, msg)
}

fn test_h2conn_split_chunks() {
	msg := [u8(1), 2, 3, 4, 5, 6, 7]
	stream := grpc_client_stream(msg)
	mut c := new_h2_conn()
	// feed in three arbitrary slices straddling preface + frame boundaries
	a := stream.len / 3
	b := (stream.len * 2) / 3
	mut out := []u8{}
	out << c.feed(stream[..a])
	out << c.feed(stream[a..b])
	out << c.feed(stream[b..])
	settings, ack := server_emitted_settings_and_ack(out)
	assert settings, 'server SETTINGS across chunked feed'
	assert ack, 'server SETTINGS ACK across chunked feed'
	assert_one_put_call(mut c, msg)
}

fn test_h2conn_ping_ack() {
	mut c := new_h2_conn()
	mut b := []u8{}
	b << h2_preface.bytes()
	b << h2_frame_encode(h2_settings_frame([]H2Setting{}))
	b << h2_frame_encode(H2Frame{
		typ:     h2_ping
		payload: '12345678'.bytes()
	})
	out := c.feed(b)
	mut r := H2FrameReader{}
	r.feed(out)
	mut got_ping_ack := false
	for {
		f := r.next() or { break }
		if f.typ == h2_ping && f.has_flag(h2_flag_ack) && f.payload.bytestr() == '12345678' {
			got_ping_ack = true
		}
	}
	assert got_ping_ack, 'server must answer PING with PING-ACK echoing the payload'
}
