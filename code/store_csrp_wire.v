@[has_globals]
module code

import cx
import encoding.hex

// store_csrp_wire.v — the APPROVED CSRP binary wire (#182,
// spec/03-approved/misc/cxstore-remote-protocol.md §2.1/§3.2). Request bodies are
// ast_bin (cxbin) by default, cxd-text via Content-Type negotiation; streaming
// responses are concatenated length-prefixed frames:
//
//   [u32 frame_length][u8 frame_kind][frame_payload]      (frame_length = 1 + payload.len)
//
// frame kinds (§3.2):
//   0x01 doc-pair          [u8 hash[32]][u32 ast_bin_len][ast_bin_bytes]
//   0x02 match             [u8 hash[32]][u32 ast_bin_len][ast_bin_bytes]
//   0x03 error (terminal)  [u32 code_len][code][u32 msg_len][msg]
//   0x04 end   (terminal)  [u32 total_count]
//   0x05 aggregate (term.) [u32 ast_bin_len][ast_bin_bytes]
//
// This layer is socket-free (bytes in / bytes out) so the router and the client
// share ONE frame implementation — parity by construction across CSRP + gRPC.

pub const csrp_frame_docpair = u8(0x01)
pub const csrp_frame_match = u8(0x02)
pub const csrp_frame_error = u8(0x03)
pub const csrp_frame_end = u8(0x04)
pub const csrp_frame_aggregate = u8(0x05)

// media types (§2.1)
pub const csrp_ct_astbin = 'application/cx-astbin'
pub const csrp_ct_cxd = 'text/cx'
pub const csrp_ct_frame_stream = 'application/cx-frame-stream'

// csrp_u32_be appends `n` as 4 big-endian octets.
fn csrp_u32_be(mut b []u8, n u32) {
	b << u8(n >> 24)
	b << u8(n >> 16)
	b << u8(n >> 8)
	b << u8(n)
}

fn csrp_read_u32_be(buf []u8, off int) u32 {
	return u32(buf[off]) << 24 | u32(buf[off + 1]) << 16 | u32(buf[off + 2]) << 8 | u32(buf[off + 3])
}

// csrp_wire_frame wraps a payload as [u32 1+len][kind][payload].
fn csrp_wire_frame(kind u8, payload []u8) []u8 {
	mut b := []u8{cap: 5 + payload.len}
	csrp_u32_be(mut b, u32(1 + payload.len))
	b << kind
	b << payload
	return b
}

// csrp_wire_docframe builds a 0x01/0x02 (doc-pair / match) frame:
// [u8 hash[32]][u32 ast_bin_len][ast_bin_bytes]. `hash_hex` is the 64-hex
// store-key; a non-32-byte hash is left-padded/truncated defensively.
fn csrp_wire_docframe(kind u8, hash_hex string, astbin []u8) []u8 {
	mut hb := hex.decode(hash_hex) or { []u8{} }
	mut h32 := []u8{len: 32}
	for i in 0 .. 32 {
		if i < hb.len {
			h32[i] = hb[i]
		}
	}
	mut payload := []u8{cap: 32 + 4 + astbin.len}
	payload << h32
	csrp_u32_be(mut payload, u32(astbin.len))
	payload << astbin
	return csrp_wire_frame(kind, payload)
}

// csrp_wire_error builds a terminal 0x03 error frame:
// [u32 code_len][code][u32 msg_len][msg].
pub fn csrp_wire_error(err_code string, msg string) []u8 {
	cb := err_code.bytes()
	mb := msg.bytes()
	mut payload := []u8{cap: 8 + cb.len + mb.len}
	csrp_u32_be(mut payload, u32(cb.len))
	payload << cb
	csrp_u32_be(mut payload, u32(mb.len))
	payload << mb
	return csrp_wire_frame(csrp_frame_error, payload)
}

// csrp_wire_end builds a terminal 0x04 end frame: [u32 total_count].
fn csrp_wire_end(total u32) []u8 {
	mut payload := []u8{cap: 4}
	csrp_u32_be(mut payload, total)
	return csrp_wire_frame(csrp_frame_end, payload)
}

// csrp_wire_aggregate builds a terminal 0x05 aggregate-result frame:
// [u32 ast_bin_len][ast_bin_bytes].
fn csrp_wire_aggregate(astbin []u8) []u8 {
	mut payload := []u8{cap: 4 + astbin.len}
	csrp_u32_be(mut payload, u32(astbin.len))
	payload << astbin
	return csrp_wire_frame(csrp_frame_aggregate, payload)
}

// ── frame reader (client + tests) ─────────────────────────────────────────────

pub struct CsrpFrame {
pub:
	kind     u8
	hash     string // 0x01/0x02: the 64-hex store-key
	astbin   []u8   // 0x01/0x02: doc ast_bin bytes; 0x05: aggregate ast_bin
	err_code string // 0x03
	message  string // 0x03
	total    u32    // 0x04
}

// csrp_parse_frames decodes a concatenated frame stream into typed frames. A
// truncated tail is ignored (the caller has what completed); a terminal 0x03/0x04/
// 0x05 does not stop the parse here (callers inspect the list).
pub fn csrp_parse_frames(buf []u8) []CsrpFrame {
	mut out := []CsrpFrame{}
	mut pos := 0
	for pos + 5 <= buf.len {
		flen := int(csrp_read_u32_be(buf, pos))
		if flen < 1 || pos + 4 + flen > buf.len {
			break // truncated / malformed tail
		}
		kind := buf[pos + 4]
		payload := buf[pos + 5..pos + 4 + flen]
		pos += 4 + flen
		out << csrp_decode_frame(kind, payload)
	}
	return out
}

fn csrp_decode_frame(kind u8, payload []u8) CsrpFrame {
	match kind {
		csrp_frame_docpair, csrp_frame_match {
			if payload.len < 36 {
				return CsrpFrame{
					kind: kind
				}
			}
			hh := payload[..32].hex()
			alen := int(csrp_read_u32_be(payload, 32))
			end := 36 + alen
			ab := if end <= payload.len { payload[36..end].clone() } else { []u8{} }
			return CsrpFrame{
				kind:   kind
				hash:   hh
				astbin: ab
			}
		}
		csrp_frame_error {
			if payload.len < 8 {
				return CsrpFrame{
					kind: kind
				}
			}
			clen := int(csrp_read_u32_be(payload, 0))
			if 4 + clen + 4 > payload.len {
				return CsrpFrame{
					kind: kind
				}
			}
			ecode := payload[4..4 + clen].bytestr()
			mpos := 4 + clen
			mlen := int(csrp_read_u32_be(payload, mpos))
			mend := mpos + 4 + mlen
			msg := if mend <= payload.len { payload[mpos + 4..mend].bytestr() } else { '' }
			return CsrpFrame{
				kind:     kind
				err_code: ecode
				message:  msg
			}
		}
		csrp_frame_end {
			t := if payload.len >= 4 { csrp_read_u32_be(payload, 0) } else { u32(0) }
			return CsrpFrame{
				kind:  kind
				total: t
			}
		}
		csrp_frame_aggregate {
			if payload.len < 4 {
				return CsrpFrame{
					kind: kind
				}
			}
			alen := int(csrp_read_u32_be(payload, 0))
			end := 4 + alen
			ab := if end <= payload.len { payload[4..end].clone() } else { []u8{} }
			return CsrpFrame{
				kind:   kind
				astbin: ab
			}
		}
		else {
			return CsrpFrame{
				kind: kind
			}
		}
	}
}

// ── request-body encoding negotiation (§2.1) ─────────────────────────────────

// csrp_req_encoding returns the request body encoding from Content-Type: cxbin
// (application/cx-astbin, the default) or cxd (text/cx). An absent/unknown
// Content-Type defaults to cxbin per §2.1.
fn csrp_req_encoding(req cx.Element) string {
	ct := csrp_header(req, 'content-type').to_lower()
	if ct.contains('text/cx') || (ct.contains('application/cx') && ct.contains('cxd')) {
		return 'cxd'
	}
	return 'cxbin'
}

// csrp_wants_binary reports whether the client speaks the approved binary wire.
// A client opts in EXPLICITLY — either a cxbin request body (`Content-Type:
// application/cx-astbin`) or an `Accept` naming the cxbin / frame-stream media
// types. During the transition the DEFAULT (no such signal) stays the cxd/query-
// param path (the negotiated alternate encoding), so legacy clients keep working;
// once the client library migrates to cxbin, the default flips per §2.1.
fn csrp_wants_binary(req cx.Element) bool {
	ct := csrp_header(req, 'content-type').to_lower()
	if ct.contains('cx-astbin') {
		return true
	}
	acc := csrp_header(req, 'accept').to_lower()
	return acc.contains('cx-astbin') || acc.contains('cx-frame-stream')
}

// csrp_header reads a request header value (case-insensitive), or ''.
fn csrp_header(req cx.Element, name string) string {
	ln := name.to_lower()
	for it in req.items {
		if it is cx.Element && it.name == 'headers' {
			for h in it.items {
				if h is cx.Element && h.name == 'header' {
					if csrp_attr(h, 'name').to_lower() == ln {
						return csrp_attr(h, 'value')
					}
				}
			}
		}
	}
	return ''
}

// csrp_decode_request_body decodes the request body into a Document per the
// negotiated encoding (cxbin → cx.bin_to_doc; cxd → cx.parse). The body carries
// the operation element (`[get hash="…"]`, `[query …]`, …) — the approved
// body-carried form (§3.3-§3.8), replacing the retired URL query-param form.
fn csrp_decode_request_body(req cx.Element) ?cx.Document {
	body := http_body_octets(req)
	if body.len == 0 {
		return none
	}
	if csrp_req_encoding(req) == 'cxbin' {
		return cx.bin_to_doc(body) or {
			// tolerate a cxd body mislabeled/omitted Content-Type: fall back to text.
			cx.parse(body.bytestr()) or { return none }
		}
	}
	return cx.parse(body.bytestr()) or { return none }
}

// csrp_req_op_elem returns the top-level operation element of a decoded request
// body (e.g. the `[get …]` / `[query …]` element), or none.
fn csrp_req_op_elem(doc cx.Document) ?cx.Element {
	if doc.elements.len == 0 {
		return none
	}
	top := doc.elements[0]
	if top is cx.Element {
		return top
	}
	return none
}
