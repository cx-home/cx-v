module platform
import code {
	arg_bytes,
	arg_string,
	bytes_node,
	bytes_string_node,
	is_err_value,
	mk_err,
}

import cx
import encoding.base64

// stdlib_xsp.v — native primitives backing the cx-stdlib/xsp module
// (spec/03-approved/xap/xsp.md). XSP is the XAP Stream Protocol: a self-describing,
// self-delimiting frame that carries XAP over any transport. The payload is
// opaque bytes; the canonical binary encoding dogfoods CX `data-bin` via the
// codec registry (cx.codec_emit_bytes_node / codec_parse_bytes_node).
//
// Bodies in /stdlib/xsp.cx call these primitives under unique `xsp-*` names.
// Reuses shared `module code` helpers (bytes_node/bytes_string_node from bytes,
// xap_elem/xap_attr/xap_elem_attr from xap, mk_err from eval).
//
// Frame layout (network byte order / big-endian), spec/03-approved/xap/xsp.md §2:
//   0     1  version (0x01)
//   1     1  type    (1 request 2 event 3 reply 4 cancel 5 ping 6 pong 7 error)
//   2     8  stream-id (u64)
//   10    1  flags   (bit0 payload-binary, bit1 end-of-stream)
//   11    2  principal-len (u16)
//   13    P  principal (UTF-8 DID)
//   13+P  4  payload-len (u32)
//   17+P  L  payload (data-bin if bit0 set, else UTF-8 text)

// CXER codes per spec/03-approved/xap/xsp.md §3. Numeric since I5 stream 4
// (L166, #717): the symbolic CXER-XSP-VERSION/-TRUNCATED/-TYPE/-LENGTH/-PAYLOAD
// spellings are RETIRED (cutover, no dual-accept); registry rows live in the
// store-profile spec's §4 error table (governance §9.6 band CXER5000–5049,
// generic-layer sub-block 5000–5009).
const xsp_err_version   = 'cx-err:CXER5000' // E_XSP_VERSION
const xsp_err_truncated = 'cx-err:CXER5001' // E_XSP_TRUNCATED
const xsp_err_type      = 'cx-err:CXER5002' // E_XSP_TYPE
const xsp_err_length    = 'cx-err:CXER5003' // E_XSP_LENGTH
const xsp_err_payload   = 'cx-err:CXER5004' // E_XSP_PAYLOAD
const xsp_err_flags     = 'cx-err:CXER5005' // E_XSP_FLAGS (reserved bits 2-7 set)

const xsp_version = u8(0x01)
const xsp_flag_binary = u8(0x01)
const xsp_flag_eos = u8(0x02)
const xsp_payload_ceiling = u64(4294967295)

// xsp_type_code maps the frame `type` head to its wire byte.
fn xsp_type_code(s string) ?u8 {
	return match s {
		'request' { u8(1) }
		'event' { u8(2) }
		'reply' { u8(3) }
		'cancel' { u8(4) }
		'ping' { u8(5) }
		'pong' { u8(6) }
		'error' { u8(7) }
		// §5.2 flow control (#560): grants N credits on a stream (payload =
		// a non-negative integer). NEGOTIATED-ONLY on the wire — a client
		// sends it only to a server that advertised the `credit` feature
		// (xsp.md §5.0), so pre-§5 peers never see the byte.
		'credit' { u8(8) }
		else { none }
	}
}

// xsp_type_name maps a wire byte back to the frame `type` head.
fn xsp_type_name(b u8) ?string {
	return match b {
		1 { 'request' }
		2 { 'event' }
		3 { 'reply' }
		4 { 'cancel' }
		5 { 'ping' }
		6 { 'pong' }
		7 { 'error' }
		8 { 'credit' }
		else { none }
	}
}

// ── big-endian writers ───────────────────────────────────────────────────────
fn xsp_put_u16(mut buf []u8, v u16) {
	buf << u8(v >> 8)
	buf << u8(v)
}

fn xsp_put_u32(mut buf []u8, v u32) {
	buf << u8(v >> 24)
	buf << u8(v >> 16)
	buf << u8(v >> 8)
	buf << u8(v)
}

fn xsp_put_u64(mut buf []u8, v u64) {
	for i := 7; i >= 0; i-- {
		buf << u8(v >> (u64(i) * 8))
	}
}

// xsp_payload_value finds the `[payload …]` child and returns its first item.
fn xsp_payload_value(e cx.Element) ?cx.Node {
	for it in e.items {
		if it is cx.Element {
			if it.name == 'payload' && it.items.len > 0 {
				return it.items[0]
			}
		}
	}
	return none
}

// xsp_encode_one builds the wire frame bytes from a `[frame …]` element.
fn xsp_encode_one(e cx.Element) cx.Node {
	type_s := xap_elem_attr(e, 'type')
	tcode := xsp_type_code(type_s) or {
		return mk_err(xsp_err_type, 'E_XSP_TYPE: xsp/encode: unknown frame type "${type_s}"')
	}
	stream := xap_elem_attr(e, 'stream').u64()
	principal := xap_elem_attr(e, 'principal')
	eos := xap_elem_attr(e, 'eos') == 'true'
	binary := xap_elem_attr(e, 'binary') != 'false' // default binary

	// payload bytes
	mut payload := []u8{}
	if pv := xsp_payload_value(e) {
		if binary {
			payload = cx.codec_emit_bytes_node('data-bin', pv) or {
				return mk_err(xsp_err_payload, 'E_XSP_PAYLOAD: xsp/encode: data-bin emit failed: ${err.msg()}')
			}
		} else {
			// text payload — the value must be a string-bearing scalar
			s := arg_string(pv) or {
				return mk_err(xsp_err_payload, 'E_XSP_PAYLOAD: xsp/encode: text payload must be a string scalar')
			}
			payload = s.bytes()
		}
	}
	if u64(payload.len) > xsp_payload_ceiling {
		return mk_err(xsp_err_length, 'E_XSP_LENGTH: xsp/encode: payload ${payload.len} exceeds 2^32-1')
	}
	pr := principal.bytes()
	if pr.len > 65535 {
		return mk_err(xsp_err_length, 'E_XSP_LENGTH: xsp/encode: principal length ${pr.len} exceeds 2^16-1')
	}

	mut flags := u8(0)
	if binary {
		flags |= xsp_flag_binary
	}
	if eos {
		flags |= xsp_flag_eos
	}

	mut buf := []u8{cap: 17 + pr.len + payload.len}
	buf << xsp_version
	buf << tcode
	xsp_put_u64(mut buf, stream)
	buf << flags
	xsp_put_u16(mut buf, u16(pr.len))
	buf << pr
	xsp_put_u32(mut buf, u32(payload.len))
	buf << payload
	return bytes_node(buf)
}

// xsp_sse_data_b64 — SSE-1 (xsp.md §4.1): the v1 web binding's downstream
// envelope carriage. Wraps ONE downstream CX event text as
// base64(XSP `event` frame, binary=false): the frame payload carries
// byte-for-byte the text the plain lane delivers for the same event, so the
// negotiated envelope changes CARRIAGE only, never content. Uses the ONE
// frame encoder (xsp_encode_one) — no second framer. Returns none only when
// the frame-level refusal (the 2^32-1 payload ceiling) trips.
fn xsp_sse_data_b64(payload string) ?string {
	fr := xsp_encode_one(cx.Element{
		name:  'frame'
		attrs: [xap_attr('type', 'event'), xap_attr('binary', 'false')]
		items: [xap_elem('payload', [], [cx.Node(bytes_string_node(payload))])]
	})
	if is_err_value(fr) {
		return none
	}
	b := arg_bytes(fr) or { return none }
	return base64.encode(b)
}

// xsp_decode_at parses ONE frame starting at absolute offset `base` of `buf`;
// returns the `[frame …]` element (with a `consumed` attr = total frame length)
// or an err value. Using an absolute offset (rather than a re-sliced buffer)
// avoids slice-of-slice aliasing that confuses the data-bin payload parser.
fn xsp_decode_at(buf []u8, base int) cx.Node {
	avail := buf.len - base
	if avail < 17 {
		return mk_err(xsp_err_truncated, 'E_XSP_TRUNCATED: xsp/decode: need ≥17 header bytes, have ${avail}')
	}
	ver := buf[base]
	if ver != xsp_version {
		return mk_err(xsp_err_version, 'E_XSP_VERSION: xsp/decode: unknown XSP version ${ver}')
	}
	tname := xsp_type_name(buf[base + 1]) or {
		return mk_err(xsp_err_type, 'E_XSP_TYPE: xsp/decode: unknown type byte ${buf[base + 1]}')
	}
	mut stream := u64(0)
	for i in base + 2 .. base + 10 {
		stream = (stream << 8) | u64(buf[i])
	}
	flags := buf[base + 10]
	// §2: flags bits 2-7 are reserved and MUST be 0 in v1 — a set reserved bit
	// is rejected loudly (never silently ignored: a future flag must be
	// negotiated, and tolerating unknown bits would make that negotiation
	// unenforceable — the same posture as un-negotiated frame types).
	if flags & ~(xsp_flag_binary | xsp_flag_eos) != 0 {
		return mk_err(xsp_err_flags, 'E_XSP_FLAGS: xsp/decode: reserved flag bits set (0x${flags.hex()}) — bits 2-7 MUST be 0 in XSP/1')
	}
	binary := (flags & xsp_flag_binary) != 0
	eos := (flags & xsp_flag_eos) != 0
	plen := (u16(buf[base + 11]) << 8) | u16(buf[base + 12])
	principal_end := base + 13 + int(plen)
	if buf.len < principal_end + 4 {
		return mk_err(xsp_err_truncated, 'E_XSP_TRUNCATED: xsp/decode: truncated before payload-len')
	}
	principal := buf[base + 13..principal_end].bytestr()
	mut paylen := u32(0)
	for i in principal_end .. principal_end + 4 {
		paylen = (paylen << 8) | u32(buf[i])
	}
	payload_start := principal_end + 4
	// i64 arithmetic: a declared length near the 2^32-1 ceiling must compare
	// (and refuse) correctly — int(u32) overflow here previously slipped past
	// the truncation check and crashed on a negative allocation (caught by the
	// corpus ceiling case, xsp-012).
	payload_end_64 := i64(payload_start) + i64(paylen)
	if i64(buf.len) < payload_end_64 {
		return mk_err(xsp_err_truncated, 'E_XSP_TRUNCATED: xsp/decode: declared payload ${paylen} bytes, buffer short')
	}
	payload_end := int(payload_end_64)
	// Copy the payload into a fresh contiguous buffer — codec_parse_bytes_node
	// aliases its input, and a view into a larger buffer otherwise misparses.
	mut payload := []u8{cap: int(paylen)}
	for i in payload_start .. payload_end {
		payload << buf[i]
	}
	consumed := payload_end - base

	// A ZERO-LENGTH payload is a payload-less frame (ping/pong/cancel commonly
	// carry none) — the [payload] child is empty, never a codec error. The
	// encoder is symmetric: an absent/empty payload emits 0 bytes either lane,
	// so encode(decode(f)) is stable. (Corpus xsp-004 caught the pre-W3 shape:
	// a payload-less binary frame mis-refused as a data-bin parse failure.)
	mut payload_items := []cx.Node{}
	if paylen > 0 {
		if binary {
			pc := cx.codec_parse_bytes_node('data-bin', payload) or {
				return mk_err(xsp_err_payload, 'E_XSP_PAYLOAD: xsp/decode: data-bin parse failed: ${err.msg()}')
			}
			payload_items << pc
		} else {
			payload_items << cx.Node(bytes_string_node(payload.bytestr()))
		}
	} else if !binary {
		payload_items << cx.Node(bytes_string_node(''))
	}

	return xap_elem('frame', [
		xap_attr('version', ver.str()),
		xap_attr('type', tname),
		xap_attr('stream', stream.str()),
		xap_attr('principal', principal),
		xap_attr('eos', if eos { 'true' } else { 'false' }),
		xap_attr('binary', if binary { 'true' } else { 'false' }),
		xap_attr('consumed', consumed.str()),
	], [
		xap_elem('payload', [], payload_items),
	])
}

fn xsp_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		'xsp-encode' {
			if args.len != 1 {
				return none
			}
			fr := args[0]
			if fr is cx.Element {
				return xsp_encode_one(fr)
			}
			return mk_err(xsp_err_type, 'E_XSP_TYPE: xsp/encode: argument must be a [frame …] element')
		}
		'xsp-decode' {
			if args.len != 1 {
				return none
			}
			buf := arg_bytes(args[0]) or { return none }
			return xsp_decode_at(buf, 0)
		}
		'xsp-decode-all' {
			if args.len != 1 {
				return none
			}
			buf := arg_bytes(args[0]) or { return none }
			mut frames := []cx.Node{}
			mut off := 0
			for off < buf.len {
				node := xsp_decode_at(buf, off)
				if is_err_value(node) {
					// remaining bytes are an incomplete trailing frame
					mut rest := []u8{cap: buf.len - off}
					for i in off .. buf.len {
						rest << buf[i]
					}
					frames << xap_elem('remainder', [xap_attr('bytes', rest.len.str())],
						[bytes_node(rest)])
					break
				}
				if node is cx.Element {
					consumed := xap_elem_attr(node, 'consumed').int()
					if consumed <= 0 {
						break
					}
					frames << node
					off += consumed
				} else {
					break
				}
			}
			// Carried as a [frames …] element (not a bare SequenceNode): the
			// language-core count/first/`//`-axis treat an Element's items as the
			// collection, so `$fs//frame`, `[$count $fs]`, `[?for [in $f $fs]]`
			// all work. A trailing partial frame appears as a [remainder …] child.
			return xap_elem('frames', [], frames)
		}
		else {
			return none
		}
	}
}
