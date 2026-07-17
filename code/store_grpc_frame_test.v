module code

// store_grpc_frame_test.v — gRPC framing reassembly + status mapping (#105 2b
// brick 2). Pure, deterministic — no transport.

fn test_frame_roundtrip_single() {
	msg := '[note [body "hi"]]'.bytes()
	mut r := GrpcFrameReader{}
	r.feed(grpc_frame_encode(msg))
	f := r.next() or { panic('expected one frame') }
	assert !f.compressed
	assert f.data == msg
	if _ := r.next() {
		assert false, 'no second frame expected'
	}
}

fn test_frame_empty_message() {
	mut r := GrpcFrameReader{}
	r.feed(grpc_frame_encode([]u8{}))
	f := r.next() or { panic('empty frame should still decode') }
	assert f.data.len == 0
}

fn test_frame_multi_message_in_one_buffer() {
	mut buf := []u8{}
	buf << grpc_frame_encode('a'.bytes())
	buf << grpc_frame_encode('bb'.bytes())
	buf << grpc_frame_encode('ccc'.bytes())
	mut r := GrpcFrameReader{}
	r.feed(buf)
	mut got := []string{}
	for {
		f := r.next() or { break }
		got << f.data.bytestr()
	}
	assert got == ['a', 'bb', 'ccc'], '${got}'
}

fn test_frame_partial_then_completed() {
	full := grpc_frame_encode('hello-world'.bytes())
	mut r := GrpcFrameReader{}
	// feed only the first 3 bytes (less than the 5-byte header) → incomplete
	r.feed(full[..3])
	if _ := r.next() {
		assert false, 'must not yield from a partial header'
	}
	// feed the header remainder + half the body → still incomplete
	r.feed(full[3..8])
	if _ := r.next() {
		assert false, 'must not yield from a partial body'
	}
	// feed the rest → now a complete frame
	r.feed(full[8..])
	f := r.next() or { panic('frame should complete') }
	assert f.data.bytestr() == 'hello-world'
	assert r.pending() == 0
}

fn test_compressed_flag_surfaced() {
	// a frame with compression flag 1 must be reported as compressed (the
	// dispatcher rejects it — identity only — rather than mis-decode).
	mut framed := grpc_frame_encode('x'.bytes())
	framed[0] = 1
	mut r := GrpcFrameReader{}
	r.feed(framed)
	f := r.next() or { panic('frame') }
	assert f.compressed
}

fn test_status_for_cxer_full_table() {
	cases := {
		'cx-err:CXER1701': grpc_invalid_argument
		'cx-err:CXER1702': grpc_unauthenticated
		'cx-err:CXER1703': grpc_permission_denied
		'cx-err:CXER1704': grpc_aborted
		'cx-err:CXER1705': grpc_resource_exhausted
		'cx-err:CXER1706': grpc_resource_exhausted
		'cx-err:CXER1707': grpc_internal
		'cx-err:CXER1708': grpc_unavailable
		'cx-err:CXER1720': grpc_data_loss
		'cx-err:CXER1721': grpc_not_found
	}
	for code, want in cases {
		got := grpc_status_for_cxer(code)
		assert got.code == want, '${code} -> ${got.code}, want ${want}'
		assert got.message.starts_with('E_'), '${code} message ${got.message}'
	}
	// bare form parses too
	assert grpc_status_for_cxer('CXER1703').code == grpc_permission_denied
	// unmapped → UNKNOWN, never OK
	assert grpc_status_for_cxer('cx-err:CXER9999').code == grpc_unknown
	assert grpc_status_for_cxer('not-a-code').code == grpc_unknown
}

fn test_grpc_message_percent_encoding() {
	assert grpc_message_encode('plain text 1.0') == 'plain text 1.0'
	// newline (0x0A) and a non-ASCII byte get %XX-encoded; '%' escapes itself
	assert grpc_message_encode('a\nb') == 'a%0Ab'
	assert grpc_message_encode('100%') == '100%25'
}
