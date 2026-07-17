module code

// store_grpc_conn.v — HTTP/2 server connection + stream state machine for the
// gRPC interface (#105 sub-area 2b, brick 3c; RFC 7540). Socket-free and
// unit-testable: bytes are fed in (feed), frames-to-write come back, and
// completed gRPC calls are drained (take_calls). Dispatch to the store pipeline
// is the NEXT brick — this layer only reassembles HTTP/2 framing + HPACK headers
// + DATA into a GrpcCall.

// GrpcCall is one fully-received unary request on a stream: the decoded request
// metadata (lowercased header name → value) + the single gRPC message body.
pub struct GrpcCall {
pub:
	stream_id  u32
	headers    map[string]string
	message    []u8
	compressed bool // #224: the inbound LPM's compressed flag — this server negotiates identity only, so a compressed message is rejected UNIMPLEMENTED (never silently read as identity → misparse)
}

// H2Stream accumulates one stream's HEADERS(+CONTINUATION) block and DATA until
// the stream half-closes (END_STREAM).
@[heap]
struct H2Stream {
mut:
	header_block  []u8
	headers       map[string]string
	data          []u8
	headers_done  bool
	stream_done   bool
	cont_frames   int // #222: CONTINUATION frames seen for this header block (capped)
}

// H2Conn is the per-connection HTTP/2 server state. The HpackDecoder carries the
// connection's HPACK dynamic table (shared across this connection's streams).
@[heap]
pub struct H2Conn {
mut:
	reader       H2FrameReader
	dec          HpackDecoder
	preface_seen bool
	settings_out bool // server SETTINGS + initial WINDOW_UPDATE emitted once
	streams      map[u32]&H2Stream
	completed    []GrpcCall
	fatal        bool // #223: a connection error (GOAWAY) was raised — stop processing input
	max_stream   u32  // highest client stream id seen (for GOAWAY last-stream-id)
}

// h2_conn_fatal reports whether a connection error has terminated this connection
// (the caller closes the socket after writing the returned GOAWAY).
pub fn (c &H2Conn) is_fatal() bool {
	return c.fatal
}

// conn_error records a connection error: emits GOAWAY(error_code) once and marks
// the connection fatal so feed() stops processing (#223 — the RFC-mandated error,
// not silent acceptance).
fn (mut c H2Conn) conn_error(error_code u32, mut out []u8) {
	if c.fatal {
		return
	}
	out << h2_frame_encode(h2_goaway(c.max_stream, error_code))
	c.fatal = true
}

pub fn new_h2_conn() &H2Conn {
	hpack_huffman_init() // build the Huffman trie once, before any concurrent use
	return &H2Conn{
		dec: new_hpack_decoder(4096)
	}
}

// h2_initial_window is the connection/stream flow-control window the server
// advertises. Large + topped up via WINDOW_UPDATE so the server never stalls a
// client mid-message (a conservative floor — real per-stream accounting is a
// later refinement; gRPC unary bodies are small).
const h2_initial_window = u32(1) << 20

// feed consumes inbound bytes and returns the bytes the server must write back
// (its SETTINGS + ACKs + PING-ACKs). Completed calls are queued for take_calls.
pub fn (mut c H2Conn) feed(data []u8) []u8 {
	if c.fatal {
		return []u8{} // connection already terminated by a protocol error
	}
	mut input := data.clone()
	// The 24-byte client connection preface precedes the first frame (RFC §3.5).
	if !c.preface_seen {
		pf := h2_preface.bytes()
		if input.len < pf.len {
			// not enough yet — stash and wait (rare; the preface arrives whole)
			c.reader.feed(input)
			return []u8{}
		}
		// #223: the preface MUST match exactly. A non-matching preface was
		// previously accepted (preface_seen set, bytes fed as frames → garbage
		// silently parsed). Reject it as a connection error (§3.5).
		if input[..pf.len] != pf {
			mut oute := []u8{}
			c.conn_error(h2_err_protocol, mut oute)
			return oute
		}
		input = input[pf.len..]
		c.preface_seen = true
	}

	mut out := []u8{}
	if !c.settings_out {
		// Server preface: our SETTINGS (advertising the inbound frame-size + header-
		// list limits, #222/#223), then a connection-level WINDOW_UPDATE.
		out << h2_frame_encode(h2_settings_frame([
			H2Setting{h2_settings_max_frame_size, h2_max_frame_size},
			H2Setting{h2_settings_max_header_list_size, h2_max_header_list_size},
		]))
		out << h2_frame_encode(h2_window_update(0, h2_initial_window))
		c.settings_out = true
	}

	c.reader.feed(input)
	for {
		// #223 §4.2: reject an oversized frame BEFORE buffering/parsing its payload.
		if c.reader.oversized_frame() {
			c.conn_error(h2_err_frame_size, mut out)
			break
		}
		f := c.reader.next() or { break }
		c.handle_frame(f, mut out)
		if c.fatal {
			break
		}
	}
	return out
}

fn (mut c H2Conn) handle_frame(f H2Frame, mut out []u8) {
	match f.typ {
		h2_settings {
			if !f.has_flag(h2_flag_ack) {
				out << h2_frame_encode(h2_settings_ack()) // ACK the client's SETTINGS
			}
		}
		h2_ping {
			if !f.has_flag(h2_flag_ack) {
				out << h2_frame_encode(h2_ping_ack(f.payload))
			}
		}
		h2_headers {
			// #223 §5.1.1: HEADERS on stream 0 is a connection error.
			if f.stream_id == 0 {
				c.conn_error(h2_err_protocol, mut out)
				return
			}
			c.track_stream(f.stream_id)
			mut st := c.stream(f.stream_id)
			block := h2_headers_block(f) // strip PADDED/PRIORITY framing
			st.header_block << block
			// #222: cap the accumulated header block (CVE-2024-27983 class).
			if st.header_block.len > int(h2_max_header_list_size) {
				c.conn_error(h2_err_enhance_your_calm, mut out)
				return
			}
			if f.has_flag(h2_flag_end_headers) {
				c.decode_headers(mut st, mut out)
				if c.fatal {
					return
				}
			}
			if f.has_flag(h2_flag_end_stream) {
				st.stream_done = true
			}
			c.maybe_complete(f.stream_id)
		}
		h2_continuation {
			if f.stream_id == 0 {
				c.conn_error(h2_err_protocol, mut out)
				return
			}
			mut st := c.stream(f.stream_id)
			st.cont_frames++
			// #222: cap CONTINUATION-frame count AND accumulated bytes so a flood of
			// tiny (even empty) CONTINUATION frames cannot exhaust memory/CPU.
			if st.cont_frames > h2_max_continuation_frames {
				c.conn_error(h2_err_enhance_your_calm, mut out)
				return
			}
			st.header_block << f.payload
			if st.header_block.len > int(h2_max_header_list_size) {
				c.conn_error(h2_err_enhance_your_calm, mut out)
				return
			}
			if f.has_flag(h2_flag_end_headers) {
				c.decode_headers(mut st, mut out)
				if c.fatal {
					return
				}
			}
			c.maybe_complete(f.stream_id)
		}
		h2_data {
			// #223 §5.1.1: DATA on stream 0 is a connection error.
			if f.stream_id == 0 {
				c.conn_error(h2_err_protocol, mut out)
				return
			}
			mut st := c.stream(f.stream_id)
			st.data << h2_data_payload(f) // strip padding if PADDED
			if f.has_flag(h2_flag_end_stream) {
				st.stream_done = true
			}
			c.maybe_complete(f.stream_id)
		}
		h2_rst_stream {
			c.streams.delete(f.stream_id)
		}
		else {
			// WINDOW_UPDATE / PRIORITY / GOAWAY: nothing to do for this floor.
		}
	}
}

// decode_headers HPACK-decodes a completed header block into the stream's headers,
// raising a COMPRESSION_ERROR connection error on a decode failure (#223 — a
// malformed HPACK block was previously swallowed, leaving empty headers that
// dispatched as an unknown op instead of a protocol error).
fn (mut c H2Conn) decode_headers(mut st H2Stream, mut out []u8) {
	hdrs := c.dec.decode(st.header_block) or {
		c.conn_error(h2_err_compression, mut out)
		return
	}
	for h in hdrs {
		st.headers[h.name.to_lower()] = h.value
	}
	st.headers_done = true
}

// track_stream records the highest client stream id (odd, per §5.1.1) for the
// GOAWAY last-stream-id.
fn (mut c H2Conn) track_stream(id u32) {
	if id > c.max_stream {
		c.max_stream = id
	}
}

fn (mut c H2Conn) stream(id u32) &H2Stream {
	if id in c.streams {
		return c.streams[id] or { &H2Stream{} }
	}
	st := &H2Stream{}
	c.streams[id] = st
	return st
}

// maybe_complete assembles a GrpcCall once a stream has both its headers and a
// half-close (END_STREAM). The gRPC request is a single length-prefixed message
// in the DATA bytes.
fn (mut c H2Conn) maybe_complete(id u32) {
	st := c.streams[id] or { return }
	if !(st.headers_done && st.stream_done) {
		return
	}
	mut fr := GrpcFrameReader{}
	fr.feed(st.data)
	mut msg := []u8{}
	mut compressed := false
	if frame := fr.next() {
		msg = frame.data.clone()
		compressed = frame.compressed // #224: surface the LPM compressed flag
	}
	c.completed << GrpcCall{
		stream_id:  id
		headers:    st.headers.clone()
		message:    msg
		compressed: compressed
	}
	c.streams.delete(id)
}

// take_calls drains the completed gRPC calls received so far.
pub fn (mut c H2Conn) take_calls() []GrpcCall {
	calls := c.completed.clone()
	c.completed = []GrpcCall{}
	return calls
}

// h2_headers_block returns the header-block fragment of a HEADERS frame, after
// stripping the optional pad-length octet (PADDED) and the 5-octet priority
// field (PRIORITY) per RFC §6.2.
fn h2_headers_block(f H2Frame) []u8 {
	mut p := f.payload.clone()
	mut pad := 0
	if f.has_flag(h2_flag_padded) {
		if p.len == 0 {
			return []u8{}
		}
		pad = int(p[0])
		p = p[1..]
	}
	if f.has_flag(h2_flag_priority) {
		if p.len < 5 {
			return []u8{}
		}
		p = p[5..] // 4-octet stream dependency + 1-octet weight
	}
	if pad > 0 {
		if pad > p.len {
			return []u8{}
		}
		p = p[..p.len - pad]
	}
	return p
}

// h2_data_payload returns a DATA frame's application bytes, stripping padding.
fn h2_data_payload(f H2Frame) []u8 {
	if !f.has_flag(h2_flag_padded) {
		return f.payload
	}
	mut p := f.payload.clone()
	if p.len == 0 {
		return []u8{}
	}
	pad := int(p[0])
	p = p[1..]
	if pad > p.len {
		return []u8{}
	}
	return p[..p.len - pad]
}
