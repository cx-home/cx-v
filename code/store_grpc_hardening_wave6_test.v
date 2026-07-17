module code

// store_grpc_hardening_wave6_test.v — W6 gRPC transport hardening (#222
// CONTINUATION-flood cap + SETTINGS advert, #223 RFC error emission + inbound
// limits, #224 proto3 compressed-flag reject + u64-length-before-i32-cast).

// a GOAWAY frame with the given error code present in the server output?
fn w6_goaway_code(out []u8) ?u32 {
	mut r := H2FrameReader{}
	r.feed(out)
	for {
		f := r.next() or { break }
		if f.typ == h2_goaway && f.payload.len >= 8 {
			return u32(f.payload[4]) << 24 | u32(f.payload[5]) << 16 | u32(f.payload[6]) << 8 | u32(f.payload[7])
		}
	}
	return none
}

fn w6_settings_advertises(out []u8, id u16) ?u32 {
	mut r := H2FrameReader{}
	r.feed(out)
	for {
		f := r.next() or { break }
		if f.typ == h2_settings && !f.has_flag(h2_flag_ack) {
			settings := h2_parse_settings(f.payload) or { continue }
			for s in settings {
				if s.id == id {
					return s.value
				}
			}
		}
	}
	return none
}

// ── #222: SETTINGS advertise the header-list limit; CONTINUATION flood → GOAWAY ─

fn test_settings_advertise_limits() {
	mut c := new_h2_conn()
	out := c.feed(h2_preface.bytes())
	mfs := w6_settings_advertises(out, h2_settings_max_frame_size) or {
		assert false, 'server must advertise SETTINGS_MAX_FRAME_SIZE (#223)'
		return
	}
	assert mfs == h2_max_frame_size
	mhls := w6_settings_advertises(out, h2_settings_max_header_list_size) or {
		assert false, 'server must advertise SETTINGS_MAX_HEADER_LIST_SIZE (#222)'
		return
	}
	assert mhls == h2_max_header_list_size
}

fn test_continuation_flood_goaway() {
	mut c := new_h2_conn()
	mut b := []u8{}
	b << h2_preface.bytes()
	b << h2_frame_encode(h2_settings_frame([]H2Setting{}))
	// HEADERS without END_HEADERS, then a flood of CONTINUATION frames (no
	// END_HEADERS) → must trip the CONTINUATION cap with a GOAWAY, not buffer
	// unboundedly (CVE-2024-27983 class).
	b << h2_frame_encode(H2Frame{
		typ:       h2_headers
		flags:     0 // NO end_headers
		stream_id: 1
		payload:   []u8{len: 8}
	})
	for _ in 0 .. (h2_max_continuation_frames + 5) {
		b << h2_frame_encode(H2Frame{
			typ:       h2_continuation
			flags:     0 // never END_HEADERS
			stream_id: 1
			payload:   []u8{len: 16}
		})
	}
	out := c.feed(b)
	gac := w6_goaway_code(out) or {
		assert false, 'CONTINUATION flood must emit a GOAWAY (#222)'
		return
	}
	assert gac == h2_err_enhance_your_calm, 'CONTINUATION flood → ENHANCE_YOUR_CALM, got ${gac}'
	assert c.is_fatal(), 'connection must be marked fatal after the flood'
}

// ── #223: bad preface, stream-0 HEADERS, oversized frame → RFC errors ─────────

fn test_bad_preface_goaway() {
	mut c := new_h2_conn()
	// 24 bytes that are NOT the preface
	bad := []u8{len: h2_preface.len, init: u8(0x41)}
	out := c.feed(bad)
	gac := w6_goaway_code(out) or {
		assert false, 'a non-matching preface must be a connection error (#223)'
		return
	}
	assert gac == h2_err_protocol, 'bad preface → PROTOCOL_ERROR, got ${gac}'
}

fn test_headers_on_stream_zero_goaway() {
	mut c := new_h2_conn()
	mut b := []u8{}
	b << h2_preface.bytes()
	b << h2_frame_encode(h2_settings_frame([]H2Setting{}))
	b << h2_frame_encode(H2Frame{
		typ:       h2_headers
		flags:     h2_flag_end_headers
		stream_id: 0 // illegal — HEADERS on the connection stream
		payload:   []u8{len: 4}
	})
	out := c.feed(b)
	gac := w6_goaway_code(out) or {
		assert false, 'HEADERS on stream 0 must be a connection error (#223 §5.1.1)'
		return
	}
	assert gac == h2_err_protocol, 'stream-0 HEADERS → PROTOCOL_ERROR, got ${gac}'
}

fn test_oversized_frame_goaway() {
	mut c := new_h2_conn()
	_ := c.feed(h2_preface.bytes()) // establish preface + server settings
	// a frame header declaring a length over the max frame size (payload need not
	// be present — the length is rejected before buffering).
	big := int(h2_max_frame_size) + 1
	hdr := [u8(big >> 16), u8(big >> 8), u8(big), h2_data, 0, 0, 0, 0, 1]
	out := c.feed(hdr)
	gac := w6_goaway_code(out) or {
		assert false, 'an oversized frame must be a FRAME_SIZE_ERROR (#223 §4.2)'
		return
	}
	assert gac == h2_err_frame_size, 'oversized frame → FRAME_SIZE_ERROR, got ${gac}'
}

// ── #224: proto length truncation guard + compressed-flag reject ──────────────

fn test_proto_length_truncation_guard() {
	// a length-delimited field whose varint length is > pb_max_len_delim must be
	// rejected (not int()-truncated → wrong read). Field 1 (store), wire type 2,
	// then a huge varint length.
	mut b := []u8{}
	b << u8(0x0a) // field 1, wire type 2 (len-delim)
	// varint for 2^40 (way over the 64 MiB cap, and > i32) — 6 bytes
	pb_write_varint(mut b, u64(1) << 40)
	b << [u8(1), 2, 3] // a few bytes (far fewer than declared)
	r := pb_decode_put_request(b)
	assert r == none, 'a >cap length-delimited field must be rejected (#224), not truncated'
}

fn test_grpc_compressed_message_rejected() {
	// an LPM with the compressed flag set → the reader flags it; dispatch must
	// reject with UNIMPLEMENTED, never read the (compressed) bytes as identity.
	mut fr := GrpcFrameReader{}
	mut lpm := []u8{}
	lpm << u8(1) // compressed flag = 1
	lpm << [u8(0), 0, 0, 3] // length 3
	lpm << [u8(0x0a), 0x01, `x`]
	fr.feed(lpm)
	f := fr.next() or {
		assert false, 'frame must parse'
		return
	}
	assert f.compressed, 'the compressed flag must be surfaced (#224)'
}
