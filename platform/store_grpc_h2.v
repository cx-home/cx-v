module platform

// store_grpc_h2.v — HTTP/2 server codec for the gRPC interface (#105 sub-area
// 2b, brick 3; RFC 7540). Built in tested sub-layers: (3a) this frame codec —
// the 9-octet frame header + typed frame helpers; (3b) HPACK header coding;
// (3c) connection/stream state + the SETTINGS/flow-control handshake. gRPC rides
// HTTP/2: HEADERS (request metadata / response trailers) + DATA (the
// length-prefixed messages from store_grpc_frame.v).

// HTTP/2 client connection preface (RFC 7540 §3.5) — the exact octets a client
// sends before its first frame; the server validates it then expects SETTINGS.
pub const h2_preface = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

// Frame types (RFC 7540 §6).
pub const h2_data = u8(0x0)
pub const h2_headers = u8(0x1)
pub const h2_rst_stream = u8(0x3)
pub const h2_settings = u8(0x4)
pub const h2_ping = u8(0x6)
pub const h2_goaway = u8(0x7)
pub const h2_window_update = u8(0x8)
pub const h2_continuation = u8(0x9)

// Frame flags (RFC 7540 §6). ACK shares 0x1 with END_STREAM but on disjoint
// frame types (SETTINGS/PING vs DATA/HEADERS).
pub const h2_flag_end_stream = u8(0x1)
pub const h2_flag_ack = u8(0x1)
pub const h2_flag_end_headers = u8(0x4)
pub const h2_flag_padded = u8(0x8)
pub const h2_flag_priority = u8(0x20)

// HTTP/2 error codes (RFC 7540 §7) used for connection errors (GOAWAY) + stream
// resets. #223: the codec must emit the RFC-mandated error rather than silently
// accept malformed input.
pub const h2_err_no_error = u32(0x0)
pub const h2_err_protocol = u32(0x1)
pub const h2_err_flow_control = u32(0x3)
pub const h2_err_frame_size = u32(0x6)
pub const h2_err_compression = u32(0x9)
pub const h2_err_enhance_your_calm = u32(0xb)

// Inbound limits (#222/#223). The server advertises these in SETTINGS and enforces
// them: a violation is a connection error (GOAWAY), never unbounded buffering.
pub const h2_max_frame_size = u32(1) << 20 // 1 MiB — advertised SETTINGS_MAX_FRAME_SIZE + inbound frame-length cap (§4.2)
pub const h2_max_header_list_size = u32(128) << 10 // 128 KiB — advertised SETTINGS_MAX_HEADER_LIST_SIZE + accumulated HEADERS+CONTINUATION cap (CVE-2024-27983 class, #222)
pub const h2_max_continuation_frames = 32 // hard cap on CONTINUATION frames per header block (defense-in-depth alongside the byte cap)

// SETTINGS parameter identifiers (RFC 7540 §6.5.2).
pub const h2_settings_header_table_size = u16(0x1)
pub const h2_settings_enable_push = u16(0x2)
pub const h2_settings_max_concurrent_streams = u16(0x3)
pub const h2_settings_initial_window_size = u16(0x4)
pub const h2_settings_max_frame_size = u16(0x5)
pub const h2_settings_max_header_list_size = u16(0x6)

// H2Frame is one decoded frame. stream_id 0 is the connection-control stream.
pub struct H2Frame {
pub:
	typ       u8
	flags     u8
	stream_id u32
	payload   []u8
}

pub fn (f &H2Frame) has_flag(flag u8) bool {
	return f.flags & flag != 0
}

// h2_frame_encode serializes a frame: 9-octet header (length:24, type:8,
// flags:8, R:1+stream_id:31) + payload.
pub fn h2_frame_encode(f H2Frame) []u8 {
	n := u32(f.payload.len)
	mut b := []u8{cap: 9 + f.payload.len}
	b << u8(n >> 16)
	b << u8(n >> 8)
	b << u8(n)
	b << f.typ
	b << f.flags
	sid := f.stream_id & 0x7fffffff // clear the reserved bit
	b << u8(sid >> 24)
	b << u8(sid >> 16)
	b << u8(sid >> 8)
	b << u8(sid)
	b << f.payload
	return b
}

// H2FrameReader reassembles frames from arbitrarily-chunked socket reads.
pub struct H2FrameReader {
mut:
	buf []u8
}

pub fn (mut r H2FrameReader) feed(data []u8) {
	r.buf << data
}

// oversized is set when the last next() saw a frame whose declared length exceeds
// h2_max_frame_size — a §4.2 FRAME_SIZE_ERROR connection error the caller raises
// (rather than buffering the oversized payload).
pub fn (mut r H2FrameReader) oversized_frame() bool {
	if r.buf.len < 3 {
		return false
	}
	length := u32(r.buf[0]) << 16 | u32(r.buf[1]) << 8 | u32(r.buf[2])
	return length > h2_max_frame_size
}

// next returns the oldest complete frame, or none when more bytes are needed.
pub fn (mut r H2FrameReader) next() ?H2Frame {
	if r.buf.len < 9 {
		return none
	}
	length := int(u32(r.buf[0]) << 16 | u32(r.buf[1]) << 8 | u32(r.buf[2]))
	if length < 0 || r.buf.len < 9 + length {
		return none
	}
	typ := r.buf[3]
	flags := r.buf[4]
	sid := (u32(r.buf[5]) << 24 | u32(r.buf[6]) << 16 | u32(r.buf[7]) << 8 | u32(r.buf[8])) & 0x7fffffff
	payload := r.buf[9..9 + length].clone()
	r.buf = r.buf[9 + length..].clone()
	return H2Frame{
		typ:       typ
		flags:     flags
		stream_id: sid
		payload:   payload
	}
}

pub fn (r &H2FrameReader) pending() int {
	return r.buf.len
}

// ── typed frame builders (server → client) ───────────────────────────────────

// H2Setting is one (id, value) pair in a SETTINGS frame.
pub struct H2Setting {
pub:
	id    u16
	value u32
}

// h2_settings_frame builds a SETTINGS frame from a list of parameters (each 6
// octets: u16 id + u32 value).
pub fn h2_settings_frame(settings []H2Setting) H2Frame {
	mut p := []u8{cap: settings.len * 6}
	for s in settings {
		p << u8(s.id >> 8)
		p << u8(s.id)
		p << u8(s.value >> 24)
		p << u8(s.value >> 16)
		p << u8(s.value >> 8)
		p << u8(s.value)
	}
	return H2Frame{
		typ:       h2_settings
		flags:     0
		stream_id: 0
		payload:   p
	}
}

// h2_settings_ack is the empty SETTINGS frame with the ACK flag.
pub fn h2_settings_ack() H2Frame {
	return H2Frame{
		typ:       h2_settings
		flags:     h2_flag_ack
		stream_id: 0
	}
}

// h2_parse_settings decodes a SETTINGS payload into its parameters. none if the
// payload length is not a multiple of 6 (a connection error per §6.5).
pub fn h2_parse_settings(payload []u8) ?[]H2Setting {
	if payload.len % 6 != 0 {
		return none
	}
	mut out := []H2Setting{}
	mut i := 0
	for i < payload.len {
		id := u16(payload[i]) << 8 | u16(payload[i + 1])
		value := u32(payload[i + 2]) << 24 | u32(payload[i + 3]) << 16 | u32(payload[i + 4]) << 8 | u32(payload[i + 5])
		out << H2Setting{
			id:    id
			value: value
		}
		i += 6
	}
	return out
}

// h2_window_update builds a WINDOW_UPDATE frame granting `increment` octets of
// flow-control credit on `stream_id` (0 = connection-level).
pub fn h2_window_update(stream_id u32, increment u32) H2Frame {
	inc := increment & 0x7fffffff
	return H2Frame{
		typ:       h2_window_update
		flags:     0
		stream_id: stream_id
		payload:   [u8(inc >> 24), u8(inc >> 16), u8(inc >> 8), u8(inc)]
	}
}

// h2_rst_stream builds a RST_STREAM frame closing `stream_id` with an error code.
pub fn h2_rst_stream(stream_id u32, error_code u32) H2Frame {
	return H2Frame{
		typ:       h2_rst_stream
		flags:     0
		stream_id: stream_id
		payload:   [u8(error_code >> 24), u8(error_code >> 16), u8(error_code >> 8), u8(error_code)]
	}
}

// h2_goaway builds a GOAWAY frame (graceful connection shutdown) naming the last
// processed stream id + an error code.
pub fn h2_goaway(last_stream_id u32, error_code u32) H2Frame {
	lsid := last_stream_id & 0x7fffffff
	return H2Frame{
		typ:       h2_goaway
		flags:     0
		stream_id: 0
		payload:   [u8(lsid >> 24), u8(lsid >> 16), u8(lsid >> 8), u8(lsid), u8(error_code >> 24),
			u8(error_code >> 16), u8(error_code >> 8), u8(error_code)]
	}
}

// h2_ping_ack echoes a PING payload with the ACK flag (RFC 7540 §6.7).
pub fn h2_ping_ack(opaque []u8) H2Frame {
	return H2Frame{
		typ:       h2_ping
		flags:     h2_flag_ack
		stream_id: 0
		payload:   opaque.clone()
	}
}
