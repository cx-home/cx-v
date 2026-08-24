module platform

// store_grpc_frame.v — gRPC message framing + status mapping (#105 sub-area 2b,
// brick 2; contract in spec/02-working/cxstore_grpc_design.md §3, §5).
//
// On the wire each gRPC message is a Length-Prefixed-Message: a 1-byte
// compressed flag (0 = identity, which is all this server emits/accepts) + a
// 4-byte big-endian length + that many message bytes. A DATA stream carries one
// or more such frames; GrpcFrameReader reassembles them from arbitrarily-chunked
// input. Call completion is signalled by the trailer (grpc-status / grpc-message
// / the cx-err-code carrying the reconciled CSRP CXER — §3).

// ── gRPC status codes (google.rpc.Code) ──────────────────────────────────────
pub const grpc_ok = 0
pub const grpc_unknown = 2
pub const grpc_invalid_argument = 3
pub const grpc_not_found = 5
pub const grpc_permission_denied = 7
pub const grpc_resource_exhausted = 8
pub const grpc_aborted = 10
pub const grpc_unimplemented = 12
pub const grpc_internal = 13
pub const grpc_unavailable = 14
pub const grpc_data_loss = 15
pub const grpc_unauthenticated = 16

// ── message framing ──────────────────────────────────────────────────────────

// GrpcFrame is one reassembled Length-Prefixed-Message. `compressed` reflects the
// frame's flag byte; this server negotiates identity only, so a compressed frame
// is a protocol error the dispatcher rejects (brick 4) rather than silently mis-read.
pub struct GrpcFrame {
pub:
	compressed bool
	data       []u8
}

// grpc_frame_encode wraps a message body in the identity (uncompressed) framing.
pub fn grpc_frame_encode(msg []u8) []u8 {
	mut b := []u8{cap: msg.len + 5}
	b << u8(0) // compressed flag: identity
	n := u32(msg.len)
	b << u8(n >> 24)
	b << u8(n >> 16)
	b << u8(n >> 8)
	b << u8(n)
	b << msg
	return b
}

// GrpcFrameReader reassembles whole frames from chunked DATA input. feed() appends
// bytes; next() returns the oldest complete frame, or none when more bytes are
// needed (so a partial tail is retained for the next feed).
pub struct GrpcFrameReader {
mut:
	buf []u8
}

pub fn (mut r GrpcFrameReader) feed(data []u8) {
	r.buf << data
}

pub fn (mut r GrpcFrameReader) next() ?GrpcFrame {
	if r.buf.len < 5 {
		return none
	}
	flag := r.buf[0]
	msg_len := int(u32(r.buf[1]) << 24 | u32(r.buf[2]) << 16 | u32(r.buf[3]) << 8 | u32(r.buf[4]))
	if msg_len < 0 || r.buf.len < 5 + msg_len {
		return none
	}
	data := r.buf[5..5 + msg_len].clone()
	r.buf = r.buf[5 + msg_len..].clone()
	return GrpcFrame{
		compressed: flag != 0
		data:       data
	}
}

// pending reports bytes buffered but not yet a complete frame (diagnostics/tests).
pub fn (r &GrpcFrameReader) pending() int {
	return r.buf.len
}

// ── status / trailer mapping (§3) ─────────────────────────────────────────────

// GrpcStatus is the call-completion trailer: the gRPC status code + a default
// message. The exact CSRP CXER travels alongside in the cx-err-code trailer so
// the 1:1 symbolic↔wire identity holds across both transports.
pub struct GrpcStatus {
pub:
	code    int
	message string
	cx_err  string // the exact `cx-err:CXERnnnn` for the `cx-err-code` trailer (#194 — parity: a client keys on this, disambiguating e.g. 413 vs 429 which share RESOURCE_EXHAUSTED)
}

// grpc_status_for_cxer maps a reconciled CSRP error code (e.g. `cx-err:CXER1703`
// or `CXER1703`) onto the gRPC status + mnemonic per the design §3 table. An
// unmapped code → UNKNOWN (2) so a future CXER never silently reads as OK.
pub fn grpc_status_for_cxer(cxer string) GrpcStatus {
	num := grpc_cxer_num(cxer)
	// #194: carry the exact `cx-err:CXERnnnn` in the trailer so a client keys on
	// the precise CXER (413 vs 429 share RESOURCE_EXHAUSTED; the trailer
	// disambiguates). An unmapped code preserves whatever was passed (or empty).
	// The ORIGINAL token is preserved verbatim when present — reconstructing
	// from the parsed number dropped leading zeros (CXER0120 → CXER120, the
	// stream-2 W6 finding).
	cx_err := if num > 0 {
		if cxer.contains('cx-err:CXER') { cxer } else { 'cx-err:CXER${num}' }
	} else {
		''
	}
	gs := match num {
		// I1 stream 19 / #691 §10: address-shape refusals at the verb boundary
		// (bare hex / unknown algo / malformed digest) are 400-class — the
		// request argument is the problem, never NOT_FOUND.
		130 { GrpcStatus{grpc_invalid_argument, 'E_STORE_ADDRESS_INVALID', cx_err} }
		131 { GrpcStatus{grpc_invalid_argument, 'E_STORE_ADDRESS_INVALID', cx_err} }
		132 { GrpcStatus{grpc_invalid_argument, 'E_STORE_ADDRESS_INVALID', cx_err} }
		1701 { GrpcStatus{grpc_invalid_argument, 'E_CSRP_REQUEST_MALFORMED', cx_err} }
		1702 { GrpcStatus{grpc_unauthenticated, 'E_CSRP_AUTH_REQUIRED', cx_err} }
		1703 { GrpcStatus{grpc_permission_denied, 'E_CSRP_FORBIDDEN', cx_err} }
		1114 { GrpcStatus{grpc_aborted, 'E_STORE_REF_CONFLICT', cx_err} }
		1705 { GrpcStatus{grpc_resource_exhausted, 'E_CSRP_PAYLOAD_TOO_LARGE', cx_err} }
		1706 { GrpcStatus{grpc_resource_exhausted, 'E_CSRP_RATE_LIMITED', cx_err} }
		1707 { GrpcStatus{grpc_internal, 'E_CSRP_SERVER_INTERNAL', cx_err} }
		1708 { GrpcStatus{grpc_unavailable, 'E_CSRP_SERVER_UNAVAILABLE', cx_err} }
		1709 { GrpcStatus{grpc_unimplemented, 'E_CSRP_OPERATION_UNSUPPORTED', cx_err} }
		1710 { GrpcStatus{grpc_not_found, 'E_CSRP_STORE_NOT_FOUND', cx_err} }
		// #251 §3.13 config-reload refusals — both 400-class (the candidate is
		// the problem) → INVALID_ARGUMENT; the trailer CXER disambiguates.
		1711 { GrpcStatus{grpc_invalid_argument, 'E_SVC_CONFIG_INVALID', cx_err} }
		1712 { GrpcStatus{grpc_invalid_argument, 'E_SVC_CONFIG_RESTART_REQUIRED', cx_err} }
		1720 { GrpcStatus{grpc_data_loss, 'E_CSRP_INTEGRITY_MISMATCH', cx_err} }
		1721 { GrpcStatus{grpc_not_found, 'E_CSRP_NOT_FOUND', cx_err} }
		else { GrpcStatus{grpc_unknown, 'UNKNOWN', cx_err} }
	}
	return gs
}

// grpc_cxer_num extracts the numeric part of a `…CXER<n>…` code, or -1.
fn grpc_cxer_num(cxer string) int {
	idx := cxer.index('CXER') or { return -1 }
	mut i := idx + 4
	mut digits := ''
	for i < cxer.len && cxer[i].is_digit() {
		digits += cxer[i].ascii_str()
		i++
	}
	if digits == '' {
		return -1
	}
	return digits.int()
}

// grpc_message_encode percent-encodes a grpc-message trailer value per the gRPC
// spec: bytes outside 0x20–0x7E, and '%' itself, become %XX (uppercase hex).
pub fn grpc_message_encode(s string) string {
	mut b := []u8{}
	for c in s.bytes() {
		if c < 0x20 || c > 0x7e || c == `%` {
			b << `%`
			b << grpc_hex_digit(c >> 4)
			b << grpc_hex_digit(c & 0x0f)
		} else {
			b << c
		}
	}
	return b.bytestr()
}

fn grpc_hex_digit(n u8) u8 {
	return if n < 10 { `0` + n } else { `A` + (n - 10) }
}
