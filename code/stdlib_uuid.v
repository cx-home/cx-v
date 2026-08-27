@[has_globals]
module code

import cx
import crypto.sha1
import crypto.md5
import crypto.rand
import time as vtime

// stdlib_uuid.v — bundled source const + native primitives for the
// `cx-stdlib/uuid` module (spec/stdlib_uuid.md). Per-module ownership:
// the whole implementation (the [?def] source bodies AND the native
// primitives backing them) lives in this one file. Registered via
// bundled_stdlib_source / bundled_stdlib_names (stdlib_bundle.v) and the
// stdlib_builtin chain (stdlib_dispatch.v).
//
// UUIDs are 128-bit values carried as either a 16-byte CXDM `bytes`
// scalar or a canonical 8-4-4-4-12 lowercase-hex `string` scalar
// (spec/stdlib_uuid.md §2). The `v4` / `v7` / `v5` / `v3` generators
// return the string form; the `-bytes` variants return raw bytes;
// `parse` / `format` interconvert; `validate` / `variant` / `version`
// inspect.
//
// Error model (spec §5): typed errors are returned as catchable
// err-values (`[err :code … :message …]` via mk_err) — a normal cx.Node
// result, not a thrown EvalError — matching the rest of the §9 model.
//
//   CXER1800 E_UUID_MALFORMED     — parse on a non-canonical string
//                                   (and, with lenient, still none of §4)
//   CXER1801 E_UUID_WRONG_LENGTH  — format / inspectors on bytes ≠ 16;
//                                   v5/v3 on a namespace ≠ 16 bytes
//
// `parse` is declared `(s:string :rest opts)`: the bundle body passes the
// collected opts sequence to the native primitive, which reads an
// optional trailing bool as the `:lenient` flag (false when absent). This
// mirrors the spec's `cx.parse_program(s :lenient false)` strict-by-default surface
// within the positional closure-call engine.

const stdlib_src_uuid = $embed_file('../stdlib/uuid.cx').to_string()

// CXER codes per spec/stdlib_uuid.md §5.
const uuid_err_malformed     = 'cx-err:CXER1800'
const uuid_err_wrong_length  = 'cx-err:CXER1801'

// RFC 4122 Appendix C predefined namespace UUIDs (canonical strings).
const uuid_ns_dns_str  = '6ba7b810-9dad-11d1-80b4-00c04fd430c8'
const uuid_ns_url_str  = '6ba7b811-9dad-11d1-80b4-00c04fd430c8'
const uuid_ns_oid_str  = '6ba7b812-9dad-11d1-80b4-00c04fd430c8'
const uuid_ns_x500_str = '6ba7b814-9dad-11d1-80b4-00c04fd430c8'

// ── v7 intra-millisecond monotonic counter state (spec §3.1) ─────────────
//
// Single-process model. `uuid_v7_last_ts` is the timestamp (Unix ms, or a
// synthetic advanced value on counter rollover) used by the most recent
// v7; `uuid_v7_counter` is the 12-bit rand_a monotonic counter. The
// generator is the only writer; calls are serialised by the
// single-threaded evaluator.
__global (
	uuid_v7_last_ts  i64
	uuid_v7_counter  u32
)

// ── value helpers ────────────────────────────────────────────────────────

// uuid_bytes_node wraps a raw byte buffer as a CXDM bytes scalar.
fn uuid_bytes_node(buf []u8) cx.Node {
	return cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(buf.bytestr())
		data_type: cx.ScalarType.bytes_type
	})
}

// uuid_string_node wraps a string as a CXDM string scalar.
fn uuid_string_node(s string) cx.Node {
	return cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	})
}

// uuid_int_node wraps an i64 as a CXDM int scalar.
fn uuid_int_node(n i64) cx.Node {
	return cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(n)
		data_type: cx.ScalarType.int_type
	})
}

// uuid_bool_node wraps a bool as a CXDM bool scalar.
fn uuid_bool_node(b bool) cx.Node {
	return cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bool_type
	})
}

// uuid_arg_bytes extracts the raw byte buffer from a bytes-or-string
// scalar arg. Both .bytes_type and .string_type carry a string
// ScalarValue (see stdlib_bytes.v), so a canonical-string namespace also
// works; none for other node shapes.
fn uuid_arg_bytes(n cx.Node) ?[]u8 {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v.bytes()
		}
	}
	note_operand_fault('uuid', 'uuid-', 'bytes', n)
	return none
}

// uuid_arg_string extracts a UTF-8 string from a string/bytes scalar arg.
fn uuid_arg_string(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	note_operand_fault('uuid', 'uuid-', 'string', n)
	return none
}

// uuid_arg_bool reads a bool scalar arg.
fn uuid_arg_bool(n cx.Node) ?bool {
	if n is cx.ScalarNode {
		v := n.value
		if v is bool {
			return v
		}
	}
	note_operand_fault('uuid', 'uuid-', 'bool', n)
	return none
}

// uuid_opts_lenient reads the optional trailing bool out of the `:rest`
// opts envelope bound by the `parse` closure. Missing / non-bool ⇒ false
// (strict-by-default, spec §3.3).
fn uuid_opts_lenient(n cx.Node) bool {
	if n is cx.Element {
		if n.name == '__cx_seq__' && n.items.len > 0 {
			return uuid_arg_bool(n.items[0]) or { false }
		}
	}
	return false
}

// ── hex / canonical-string helpers ────────────────────────────────────────

const uuid_hex_lower = '0123456789abcdef'

// uuid_format_bytes renders 16 bytes as canonical lowercase 8-4-4-4-12.
fn uuid_format_bytes(b []u8) string {
	mut out := []u8{cap: 36}
	for i, byte_v in b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out << `-`
		}
		out << uuid_hex_lower[byte_v >> 4]
		out << uuid_hex_lower[byte_v & 0x0f]
	}
	return out.bytestr()
}

// uuid_hex_val maps a hex digit byte to its 0-15 value, or -1 if not hex.
fn uuid_hex_val(c u8) int {
	if c >= `0` && c <= `9` {
		return int(c - `0`)
	}
	if c >= `a` && c <= `f` {
		return int(c - `a`) + 10
	}
	if c >= `A` && c <= `F` {
		return int(c - `A`) + 10
	}
	return -1
}

// uuid_is_canonical reports whether `s` is the strict canonical
// 8-4-4-4-12 hex form (case-insensitive). Hyphens at 8/13/18/23; all
// other positions hex.
fn uuid_is_canonical(s string) bool {
	if s.len != 36 {
		return false
	}
	for i in 0 .. 36 {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != `-` {
				return false
			}
			continue
		}
		if uuid_hex_val(c) < 0 {
			return false
		}
	}
	return true
}

// uuid_canonical_to_bytes decodes a known-canonical 36-char string into
// its 16 raw bytes.
fn uuid_canonical_to_bytes(s string) []u8 {
	mut out := []u8{cap: 16}
	mut i := 0
	for i < 36 {
		c := s[i]
		if c == `-` {
			i++
			continue
		}
		hi := uuid_hex_val(s[i])
		lo := uuid_hex_val(s[i + 1])
		out << u8((hi << 4) | lo)
		i += 2
	}
	return out
}

// uuid_hexbody_to_bytes decodes a bare 32-hex-char body into 16 bytes;
// none if not exactly 32 hex chars.
fn uuid_hexbody_to_bytes(body string) ?[]u8 {
	if body.len != 32 {
		return none
	}
	mut out := []u8{cap: 16}
	mut i := 0
	for i < 32 {
		hi := uuid_hex_val(body[i])
		lo := uuid_hex_val(body[i + 1])
		if hi < 0 || lo < 0 {
			return none
		}
		out << u8((hi << 4) | lo)
		i += 2
	}
	return out
}

// ── parse (spec §3.3 / §4) ─────────────────────────────────────────────────

// uuid_parse decodes a UUID string to its 16 bytes. Strict by default
// (canonical 8-4-4-4-12 only). With lenient=true it additionally accepts
// the §4 relaxed forms: a `urn:uuid:` prefix, `{…}` brace wrapper, and a
// hyphen-less 32-hex body (these may combine). Raises CXER1800 on
// anything that does not resolve to a valid UUID.
fn uuid_parse(s string, lenient bool) cx.Node {
	if uuid_is_canonical(s) {
		return uuid_bytes_node(uuid_canonical_to_bytes(s))
	}
	if !lenient {
		return mk_err(uuid_err_malformed, 'E_UUID_MALFORMED: ${s}')
	}
	// Lenient: strip urn:uuid: prefix and/or {…} braces (in either order),
	// then accept the inner body as canonical or hyphen-less 32-hex.
	mut body := s
	if body.len >= 2 && body[0] == `{` && body[body.len - 1] == `}` {
		body = body[1..body.len - 1]
	}
	low := body.to_lower()
	if low.starts_with('urn:uuid:') {
		body = body[9..]
	}
	// A urn:uuid: inside braces (already stripped) or braces inside the
	// urn body — re-strip braces once more to cover the combined case.
	if body.len >= 2 && body[0] == `{` && body[body.len - 1] == `}` {
		body = body[1..body.len - 1]
	}
	if uuid_is_canonical(body) {
		return uuid_bytes_node(uuid_canonical_to_bytes(body))
	}
	if hb := uuid_hexbody_to_bytes(body) {
		return uuid_bytes_node(hb)
	}
	return mk_err(uuid_err_malformed, 'E_UUID_MALFORMED: ${s}')
}

// ── RFC bit-setting ─────────────────────────────────────────────────────────

// uuid_set_version overwrites the 4-bit version nibble (byte 6 high
// nibble) in-place.
fn uuid_set_version(mut b []u8, ver u8) {
	b[6] = (b[6] & 0x0f) | (ver << 4)
}

// uuid_set_variant sets the RFC 4122 variant (byte 8 top two bits = 10).
fn uuid_set_variant(mut b []u8) {
	b[8] = (b[8] & 0x3f) | 0x80
}

// ── generators ──────────────────────────────────────────────────────────────

// uuid_v4_bytes builds an RFC 4122 v4 UUID: 122 random bits + version 4
// + RFC variant.
fn uuid_v4_bytes() []u8 {
	mut b := rand.bytes(16) or { []u8{len: 16} }
	if b.len != 16 {
		b = []u8{len: 16}
	}
	uuid_set_version(mut b, 4)
	uuid_set_variant(mut b)
	return b
}

// uuid_v7_bytes builds an RFC 9562 v7 UUID: 48-bit Unix-ms timestamp +
// version 7 + 12-bit rand_a monotonic counter + RFC variant + 62-bit
// CSPRNG-random rand_b. Implements §3.1 method-1 intra-millisecond
// monotonicity with timestamp-advance on counter rollover.
fn uuid_v7_bytes() []u8 {
	now_ms := vtime.now().unix_milli()
	mut rnd := rand.bytes(16) or { []u8{len: 16} }
	if rnd.len != 16 {
		rnd = []u8{len: 16}
	}
	mut ts := now_ms
	mut counter := u32(0)
	if now_ms > uuid_v7_last_ts {
		// Fresh millisecond: seed the counter low (leave rollover
		// headroom per the RFC) from CSPRNG randomness — 10 bits.
		ts = now_ms
		counter = (u32(rnd[0]) << 8 | u32(rnd[1])) & 0x03ff
	} else {
		// Same millisecond (or clock went backwards): increment the
		// counter. On 12-bit overflow, advance the synthetic timestamp
		// and reseed.
		ts = uuid_v7_last_ts
		counter = uuid_v7_counter + 1
		if counter > 0x0fff {
			ts = uuid_v7_last_ts + 1
			counter = (u32(rnd[0]) << 8 | u32(rnd[1])) & 0x03ff
		}
	}
	uuid_v7_last_ts = ts
	uuid_v7_counter = counter

	mut b := []u8{len: 16}
	// 48-bit big-endian timestamp.
	uts := u64(ts)
	b[0] = u8((uts >> 40) & 0xff)
	b[1] = u8((uts >> 32) & 0xff)
	b[2] = u8((uts >> 24) & 0xff)
	b[3] = u8((uts >> 16) & 0xff)
	b[4] = u8((uts >> 8) & 0xff)
	b[5] = u8(uts & 0xff)
	// rand_a (12 bits) = monotonic counter, packed into byte 6 low nibble
	// + byte 7. Version nibble set after.
	b[6] = u8((counter >> 8) & 0x0f)
	b[7] = u8(counter & 0xff)
	// rand_b (62 bits) = fully random tail (bytes 8..15 from CSPRNG).
	for i in 8 .. 16 {
		b[i] = rnd[i]
	}
	uuid_set_version(mut b, 7)
	uuid_set_variant(mut b)
	return b
}

// uuid_name_based_bytes computes an RFC 4122 §4.3 name-based UUID:
// digest(namespace ++ utf8(name))[..16] with the given version nibble +
// RFC variant. digest is SHA-1 (v5) or MD5 (v3).
fn uuid_name_based_bytes(namespace []u8, name string, ver u8) ?[]u8 {
	if namespace.len != 16 {
		return none
	}
	mut input := []u8{cap: namespace.len + name.len}
	input << namespace
	input << name.bytes()
	digest := if ver == 5 {
		sha1.sum(input)
	} else {
		md5.sum(input)
	}
	mut b := digest[..16].clone()
	uuid_set_version(mut b, ver)
	uuid_set_variant(mut b)
	return b
}

// ── inspection (spec §3.4) ──────────────────────────────────────────────────

// uuid_variant returns the RFC 4122 §4.1.1 variant: 0 NCS, 2 RFC 4122,
// 6 Microsoft, 7 future. Derived from the top bits of byte 8.
fn uuid_variant(b []u8) cx.Node {
	if b.len != 16 {
		return mk_err(uuid_err_wrong_length, 'E_UUID_WRONG_LENGTH: ${b.len} bytes')
	}
	hi := b[8]
	if hi & 0x80 == 0x00 {
		return uuid_int_node(0) // 0xx — NCS legacy
	}
	if hi & 0xc0 == 0x80 {
		return uuid_int_node(2) // 10x — RFC 4122
	}
	if hi & 0xe0 == 0xc0 {
		return uuid_int_node(6) // 110 — Microsoft
	}
	return uuid_int_node(7) // 111 — future
}

// uuid_version returns the version nibble (byte 6 high nibble).
fn uuid_version(b []u8) cx.Node {
	if b.len != 16 {
		return mk_err(uuid_err_wrong_length, 'E_UUID_WRONG_LENGTH: ${b.len} bytes')
	}
	return uuid_int_node(i64(b[6] >> 4))
}

// ── dispatch table ────────────────────────────────────────────────────────

// uuid_random_prims are the random-backed UUID generators (uuid.md §7:
// require `random`). v3/v5 (name-based) + parse/format/inspect are pure.
const uuid_random_prims = ['uuid-v4', 'uuid-v4-bytes', 'uuid-v7', 'uuid-v7-bytes']

fn uuid_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	if name in uuid_random_prims {
		if d := cap_guard('random', name) {
			return d
		}
	}
	match name {
		'uuid-v4' {
			return uuid_string_node(uuid_format_bytes(uuid_v4_bytes()))
		}
		'uuid-v4-bytes' {
			return uuid_bytes_node(uuid_v4_bytes())
		}
		'uuid-v7' {
			return uuid_string_node(uuid_format_bytes(uuid_v7_bytes()))
		}
		'uuid-v7-bytes' {
			return uuid_bytes_node(uuid_v7_bytes())
		}
		'uuid-v5' {
			ns := uuid_arg_bytes(args[0]) or { return none }
			nm := uuid_arg_string(args[1]) or { return none }
			b := uuid_name_based_bytes(ns, nm, 5) or {
				return mk_err(uuid_err_wrong_length, 'E_UUID_WRONG_LENGTH: namespace ${ns.len} bytes')
			}
			return uuid_string_node(uuid_format_bytes(b))
		}
		'uuid-v5-bytes' {
			ns := uuid_arg_bytes(args[0]) or { return none }
			nm := uuid_arg_string(args[1]) or { return none }
			b := uuid_name_based_bytes(ns, nm, 5) or {
				return mk_err(uuid_err_wrong_length, 'E_UUID_WRONG_LENGTH: namespace ${ns.len} bytes')
			}
			return uuid_bytes_node(b)
		}
		'uuid-v3' {
			ns := uuid_arg_bytes(args[0]) or { return none }
			nm := uuid_arg_string(args[1]) or { return none }
			b := uuid_name_based_bytes(ns, nm, 3) or {
				return mk_err(uuid_err_wrong_length, 'E_UUID_WRONG_LENGTH: namespace ${ns.len} bytes')
			}
			return uuid_string_node(uuid_format_bytes(b))
		}
		'uuid-v3-bytes' {
			ns := uuid_arg_bytes(args[0]) or { return none }
			nm := uuid_arg_string(args[1]) or { return none }
			b := uuid_name_based_bytes(ns, nm, 3) or {
				return mk_err(uuid_err_wrong_length, 'E_UUID_WRONG_LENGTH: namespace ${ns.len} bytes')
			}
			return uuid_bytes_node(b)
		}
		'uuid-parse' {
			s := uuid_arg_string(args[0]) or { return none }
			lenient := if args.len > 1 { uuid_opts_lenient(args[1]) } else { false }
			return uuid_parse(s, lenient)
		}
		'uuid-format' {
			b := uuid_arg_bytes(args[0]) or { return none }
			if b.len != 16 {
				return mk_err(uuid_err_wrong_length, 'E_UUID_WRONG_LENGTH: ${b.len} bytes')
			}
			return uuid_string_node(uuid_format_bytes(b))
		}
		'uuid-validate' {
			s := uuid_arg_string(args[0]) or { return none }
			return uuid_bool_node(uuid_is_canonical(s))
		}
		'uuid-variant' {
			b := uuid_arg_bytes(args[0]) or { return none }
			return uuid_variant(b)
		}
		'uuid-version' {
			b := uuid_arg_bytes(args[0]) or { return none }
			return uuid_version(b)
		}
		'uuid-nil' {
			return uuid_string_node('00000000-0000-0000-0000-000000000000')
		}
		'uuid-ns-dns' {
			return uuid_bytes_node(uuid_canonical_to_bytes(uuid_ns_dns_str))
		}
		'uuid-ns-url' {
			return uuid_bytes_node(uuid_canonical_to_bytes(uuid_ns_url_str))
		}
		'uuid-ns-oid' {
			return uuid_bytes_node(uuid_canonical_to_bytes(uuid_ns_oid_str))
		}
		'uuid-ns-x500' {
			return uuid_bytes_node(uuid_canonical_to_bytes(uuid_ns_x500_str))
		}
		else {
			return none
		}
	}
}
