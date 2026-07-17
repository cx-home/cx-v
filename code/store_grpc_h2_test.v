module code

// store_grpc_h2_test.v — HTTP/2 frame codec (brick 3a). Pure, deterministic.

fn test_h2_frame_header_roundtrip() {
	f := H2Frame{
		typ:       h2_headers
		flags:     h2_flag_end_headers | h2_flag_end_stream
		stream_id: 5
		payload:   [u8(1), 2, 3, 4]
	}
	mut r := H2FrameReader{}
	r.feed(h2_frame_encode(f))
	got := r.next() or { panic('frame') }
	assert got.typ == h2_headers
	assert got.has_flag(h2_flag_end_headers)
	assert got.has_flag(h2_flag_end_stream)
	assert got.stream_id == 5
	assert got.payload == [u8(1), 2, 3, 4]
}

fn test_h2_reserved_bit_cleared() {
	// the high bit of the stream-id word is reserved and must be masked off.
	f := H2Frame{
		typ:       h2_data
		stream_id: 0x80000003
	}
	mut r := H2FrameReader{}
	r.feed(h2_frame_encode(f))
	got := r.next() or { panic('frame') }
	assert got.stream_id == 3, 'reserved bit must be cleared: ${got.stream_id}'
}

fn test_h2_multi_frame_and_partial() {
	mut buf := []u8{}
	buf << h2_frame_encode(H2Frame{
		typ:     h2_data
		payload: 'aa'.bytes()
	})
	buf << h2_frame_encode(H2Frame{
		typ:     h2_data
		payload: 'bbbb'.bytes()
	})
	mut r := H2FrameReader{}
	// feed in two arbitrary chunks straddling a frame boundary
	r.feed(buf[..5])
	if _ := r.next() {
		assert false, 'partial header must not yield'
	}
	r.feed(buf[5..])
	a := r.next() or { panic('a') }
	b := r.next() or { panic('b') }
	assert a.payload.bytestr() == 'aa'
	assert b.payload.bytestr() == 'bbbb'
	assert r.pending() == 0
}

fn test_h2_settings_roundtrip() {
	settings := [
		H2Setting{h2_settings_max_concurrent_streams, 128},
		H2Setting{h2_settings_initial_window_size, 1048576},
	]
	frame := h2_settings_frame(settings)
	assert frame.typ == h2_settings
	assert frame.stream_id == 0
	parsed := h2_parse_settings(frame.payload) or { panic('parse') }
	assert parsed.len == 2
	assert parsed[0].id == h2_settings_max_concurrent_streams && parsed[0].value == 128
	assert parsed[1].id == h2_settings_initial_window_size && parsed[1].value == 1048576
}

fn test_h2_settings_malformed_length() {
	if _ := h2_parse_settings([u8(0), 1, 2]) { // 3 bytes, not a multiple of 6
		assert false, 'malformed SETTINGS length must be rejected'
	}
}

fn test_h2_settings_ack() {
	ack := h2_settings_ack()
	assert ack.typ == h2_settings
	assert ack.has_flag(h2_flag_ack)
	assert ack.payload.len == 0
}

fn test_h2_control_frames() {
	wu := h2_window_update(0, 65535)
	assert wu.typ == h2_window_update && wu.payload.len == 4

	rst := h2_rst_stream(7, 0)
	assert rst.typ == h2_rst_stream && rst.stream_id == 7 && rst.payload.len == 4

	ga := h2_goaway(9, 0)
	assert ga.typ == h2_goaway && ga.payload.len == 8

	pa := h2_ping_ack('12345678'.bytes())
	assert pa.typ == h2_ping && pa.has_flag(h2_flag_ack) && pa.payload.bytestr() == '12345678'
}

fn test_h2_preface_constant() {
	// the exact RFC 7540 §3.5 client preface octets.
	assert h2_preface == 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
	assert h2_preface.len == 24
}
