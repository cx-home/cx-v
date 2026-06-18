module code

import cx
import encoding.hex
import encoding.base64
import encoding.base32
import encoding.base58
import compress.gzip
import compress.zstd
import math

// stdlib_bytes.v — native primitives backing the cx-stdlib/bytes module
// (spec/stdlib_bytes.md). Operates on the CXDM `bytes` scalar kind, which
// is carried as a `string` ScalarValue holding the raw byte buffer with
// `data_type: .bytes_type` (see vcx/cx/data_bin.v:526, parser.v:3469).
//
// The bundle's [?def] bodies (vcx/code/stdlib_bundle.v :: stdlib_src_bytes)
// call these primitives under unique `bytes-*` names so they never collide
// with the language-core `invoke_builtin` set (which already owns `length`,
// `slice`, `head`, `tail`, `concat`, `contains`, `find`, etc.).
//
// Error model: spec §5 typed errors are returned as catchable err-values
// (`[err :code … :message …]` via mk_err) — a normal cx.Node result, not a
// thrown EvalError — matching the rest of the evaluator's §9 model.

// CXER codes per spec/stdlib_bytes.md §5.
const bytes_err_index_oob    = 'cx-err:CXER2300'
const bytes_err_invalid_hex  = 'cx-err:CXER2301'
const bytes_err_invalid_b64  = 'cx-err:CXER2302'
const bytes_err_invalid_utf8 = 'cx-err:CXER2303'
const bytes_err_decompress   = 'cx-err:CXER2304'
const bytes_err_pack_format  = 'cx-err:CXER2305'
const bytes_err_pack_length  = 'cx-err:CXER2306'
const bytes_err_length_exc   = 'cx-err:CXER2307'

// 2^32-1 byte length ceiling (§2 / §4.4).
const bytes_length_ceiling = i64(4294967295)

// ── value helpers ───────────────────────────────────────────────────────────

// bytes_node wraps a raw byte buffer as a CXDM bytes scalar.
fn bytes_node(buf []u8) cx.Node {
	return cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(buf.bytestr())
		data_type: cx.ScalarType.bytes_type
	})
}

// string_node wraps a string as a CXDM string scalar.
fn bytes_string_node(s string) cx.Node {
	return cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	})
}

// int_node wraps an i64 as a CXDM int scalar.
fn bytes_int_node(n i64) cx.Node {
	return cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(n)
		data_type: cx.ScalarType.int_type
	})
}

// bool_node wraps a bool as a CXDM bool scalar.
fn bytes_bool_node(b bool) cx.Node {
	return cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bool_type
	})
}

// arg_bytes extracts the raw byte buffer from a bytes-or-string scalar arg.
// Accepts both .bytes_type and .string_type payloads (both carry a string
// ScalarValue) so a string literal can stand in for a bytes value in
// composition. Returns none for non-scalar or non-string-payload nodes.
fn arg_bytes(n cx.Node) ?[]u8 {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v.bytes()
		}
	}
	return none
}

// arg_string extracts a UTF-8 string from a string/bytes scalar arg.
fn arg_string(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return none
}

// arg_int extracts an i64 from an int scalar arg.
fn arg_int(n cx.Node) ?i64 {
	if n is cx.ScalarNode {
		v := n.value
		if v is i64 {
			return v
		}
	}
	return none
}

// arg_items returns the element list of a sequence / array arg, or none.
fn arg_items(n cx.Node) ?[]cx.Node {
	match n {
		cx.SequenceNode { return n.items }
		cx.ArrayNode    { return n.items }
		cx.Element {
			if n.name == '__cx_seq__' || n.name == '__cx_arr__' {
				return n.items
			}
			return none
		}
		else { return none }
	}
}

// seq_node builds a paren-sequence value from a list of byte buffers.
fn bytes_seq_node(parts [][]u8) cx.Node {
	mut items := []cx.Node{cap: parts.len}
	for p in parts {
		items << bytes_node(p)
	}
	return cx.Node(cx.SequenceNode{ items: items })
}

// ── dispatch ──────────────────────────────────────────────────────────────

fn bytes_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		// §3.1 inspection
		'bytes-length' {
			if args.len != 1 { return none }
			b := arg_bytes(args[0]) or { return none }
			return bytes_int_node(i64(b.len))
		}
		'bytes-at' {
			if args.len != 2 { return none }
			b := arg_bytes(args[0]) or { return none }
			i := arg_int(args[1]) or { return none }
			if i < 0 || i >= i64(b.len) {
				return mk_err(bytes_err_index_oob,
					'bytes/at: index ${i} out of range for length ${b.len}')
			}
			return bytes_int_node(i64(b[i]))
		}
		'bytes-is-empty' {
			if args.len != 1 { return none }
			b := arg_bytes(args[0]) or { return none }
			return bytes_bool_node(b.len == 0)
		}
		'bytes-equals' {
			if args.len != 2 { return none }
			a := arg_bytes(args[0]) or { return none }
			b := arg_bytes(args[1]) or { return none }
			return bytes_bool_node(a == b)
		}
		'bytes-ct-equals' {
			if args.len != 2 { return none }
			a := arg_bytes(args[0]) or { return none }
			b := arg_bytes(args[1]) or { return none }
			// §3.1 / §4.5: different length → false via fast path; the
			// constant-time guarantee holds only over equal-length inputs
			// (matches Python hmac.compare_digest).
			if a.len != b.len {
				return bytes_bool_node(false)
			}
			mut diff := u8(0)
			for i in 0 .. a.len {
				diff |= a[i] ^ b[i]
			}
			return bytes_bool_node(diff == 0)
		}
		// §3.2 slicing + search
		'bytes-slice' {
			if args.len != 3 { return none }
			b := arg_bytes(args[0]) or { return none }
			start := arg_int(args[1]) or { return none }
			end := arg_int(args[2]) or { return none }
			n := i64(b.len)
			// §4.1 — Python-style negative indices + clamp to length.
			mut s := if start < 0 { start + n } else { start }
			mut e := if end < 0 { end + n } else { end }
			if s < 0 { s = 0 }
			if e < 0 { e = 0 }
			if s > n { s = n }
			if e > n { e = n }
			if s >= e {
				return bytes_node([]u8{})
			}
			return bytes_node(b[s..e].clone())
		}
		'bytes-head' {
			if args.len != 2 { return none }
			b := arg_bytes(args[0]) or { return none }
			n := arg_int(args[1]) or { return none }
			mut k := if n < 0 { i64(0) } else { n }
			if k > i64(b.len) { k = i64(b.len) }
			return bytes_node(b[..k].clone())
		}
		'bytes-tail' {
			if args.len != 2 { return none }
			b := arg_bytes(args[0]) or { return none }
			n := arg_int(args[1]) or { return none }
			mut k := if n < 0 { i64(0) } else { n }
			if k > i64(b.len) { k = i64(b.len) }
			return bytes_node(b[i64(b.len) - k..].clone())
		}
		'bytes-concat' {
			if args.len != 1 { return none }
			items := arg_items(args[0]) or { return none }
			// §4.4 — ceiling check before allocation.
			mut total := i64(0)
			mut bufs := [][]u8{cap: items.len}
			for it in items {
				p := arg_bytes(it) or { return none }
				total += i64(p.len)
				if total > bytes_length_ceiling {
					return mk_err(bytes_err_length_exc,
						'bytes/concat: result would exceed the 2^32-1 byte ceiling')
				}
				bufs << p
			}
			mut out := []u8{cap: int(total)}
			for p in bufs {
				out << p
			}
			return bytes_node(out)
		}
		'bytes-repeat' {
			if args.len != 2 { return none }
			b := arg_bytes(args[0]) or { return none }
			n := arg_int(args[1]) or { return none }
			if n <= 0 {
				return bytes_node([]u8{})
			}
			// §4.4 — ceiling check before allocation.
			total := i64(b.len) * n
			if total > bytes_length_ceiling {
				return mk_err(bytes_err_length_exc,
					'bytes/repeat: result would exceed the 2^32-1 byte ceiling')
			}
			mut out := []u8{cap: int(total)}
			for _ in 0 .. n {
				out << b
			}
			return bytes_node(out)
		}
		'bytes-find' {
			if args.len != 2 { return none }
			hay := arg_bytes(args[0]) or { return none }
			needle := arg_bytes(args[1]) or { return none }
			return bytes_int_node(i64(bytes_index_of(hay, needle)))
		}
		'bytes-contains' {
			if args.len != 2 { return none }
			hay := arg_bytes(args[0]) or { return none }
			needle := arg_bytes(args[1]) or { return none }
			return bytes_bool_node(bytes_index_of(hay, needle) >= 0)
		}
		'bytes-starts-with' {
			if args.len != 2 { return none }
			b := arg_bytes(args[0]) or { return none }
			prefix := arg_bytes(args[1]) or { return none }
			if prefix.len > b.len {
				return bytes_bool_node(false)
			}
			return bytes_bool_node(b[..prefix.len] == prefix)
		}
		'bytes-ends-with' {
			if args.len != 2 { return none }
			b := arg_bytes(args[0]) or { return none }
			suffix := arg_bytes(args[1]) or { return none }
			if suffix.len > b.len {
				return bytes_bool_node(false)
			}
			return bytes_bool_node(b[b.len - suffix.len..] == suffix)
		}
		'bytes-split' {
			if args.len != 2 { return none }
			b := arg_bytes(args[0]) or { return none }
			sep := arg_bytes(args[1]) or { return none }
			return bytes_seq_node(bytes_split(b, sep))
		}
		// §3.3 hex
		'bytes-to-hex' {
			if args.len != 1 { return none }
			b := arg_bytes(args[0]) or { return none }
			return bytes_string_node(hex.encode(b))
		}
		'bytes-to-hex-upper' {
			if args.len != 1 { return none }
			b := arg_bytes(args[0]) or { return none }
			return bytes_string_node(hex.encode(b).to_upper())
		}
		'bytes-from-hex' {
			if args.len != 1 { return none }
			s := arg_string(args[0]) or { return none }
			buf := hex.decode(s) or {
				return mk_err(bytes_err_invalid_hex,
					'bytes/from-hex: invalid hex input')
			}
			return bytes_node(buf)
		}
		// §3.4 base64
		'bytes-to-base64' {
			if args.len != 1 { return none }
			b := arg_bytes(args[0]) or { return none }
			return bytes_string_node(base64.encode(b))
		}
		'bytes-to-base64-url' {
			if args.len != 1 { return none }
			b := arg_bytes(args[0]) or { return none }
			// RFC 4648 §5 URL-safe alphabet, UNPADDED (JWT/web default).
			enc := base64.url_encode(b)
			return bytes_string_node(enc.trim_right('='))
		}
		'bytes-from-base64' {
			if args.len != 1 { return none }
			s := arg_string(args[0]) or { return none }
			buf := base64_decode_tolerant(s, false) or {
				return mk_err(bytes_err_invalid_b64,
					'bytes/from-base64: malformed base64 input')
			}
			return bytes_node(buf)
		}
		'bytes-from-base64-url' {
			if args.len != 1 { return none }
			s := arg_string(args[0]) or { return none }
			buf := base64_decode_tolerant(s, true) or {
				return mk_err(bytes_err_invalid_b64,
					'bytes/from-base64-url: malformed base64 input')
			}
			return bytes_node(buf)
		}
		// §3.5 base32
		'bytes-to-base32' {
			if args.len != 1 { return none }
			b := arg_bytes(args[0]) or { return none }
			return bytes_string_node(base32.encode_to_string(b))
		}
		'bytes-from-base32' {
			if args.len != 1 { return none }
			s := arg_string(args[0]) or { return none }
			buf := base32.decode(s.bytes()) or {
				return mk_err(bytes_err_invalid_b64,
					'bytes/from-base32: malformed base32 input')
			}
			return bytes_node(buf)
		}
		// §3.5 base58 (multibase base58btc, Bitcoin alphabet) — backs did:key
		'bytes-to-base58' {
			if args.len != 1 { return none }
			b := arg_bytes(args[0]) or { return none }
			return bytes_string_node(base58.encode_bytes(b).bytestr())
		}
		'bytes-from-base58' {
			if args.len != 1 { return none }
			s := arg_string(args[0]) or { return none }
			buf := base58.decode_bytes(s.bytes()) or {
				return mk_err(bytes_err_invalid_b64,
					'bytes/from-base58: malformed base58 input')
			}
			return bytes_node(buf)
		}
		// §3.6 compression
		'bytes-gzip-compress' {
			if args.len != 1 { return none }
			b := arg_bytes(args[0]) or { return none }
			out := gzip.compress(b) or {
				return mk_err(bytes_err_decompress,
					'bytes/gzip-compress: compression failed')
			}
			return bytes_node(out)
		}
		'bytes-gzip-decompress' {
			if args.len != 1 { return none }
			b := arg_bytes(args[0]) or { return none }
			out := gzip.decompress(b) or {
				// §4.3 — a valid empty-payload gzip frame (header + empty
				// DEFLATE body + trailer, ~20 bytes) must round-trip to
				// empty. V's gzip.decompress errors on a zero-length output,
				// so detect the empty case via the ISIZE trailer (last 4
				// bytes, little-endian uncompressed size) on an otherwise
				// well-formed frame and return empty bytes.
				if gzip_frame_isize_zero(b) {
					return bytes_node([]u8{})
				}
				return mk_err(bytes_err_decompress,
					'bytes/gzip-decompress: malformed gzip input')
			}
			return bytes_node(out)
		}
		'bytes-zstd-compress' {
			if args.len != 1 { return none }
			b := arg_bytes(args[0]) or { return none }
			out := zstd.compress(b, compression_level: 3) or {
				return mk_err(bytes_err_decompress,
					'bytes/zstd-compress: compression failed')
			}
			return bytes_node(out)
		}
		'bytes-zstd-compress-level' {
			if args.len != 2 { return none }
			b := arg_bytes(args[0]) or { return none }
			level := arg_int(args[1]) or { return none }
			out := zstd.compress(b, compression_level: int(level)) or {
				return mk_err(bytes_err_decompress,
					'bytes/zstd-compress-with-level: compression failed')
			}
			return bytes_node(out)
		}
		'bytes-zstd-decompress' {
			if args.len != 1 { return none }
			b := arg_bytes(args[0]) or { return none }
			out := zstd.decompress(b) or {
				return mk_err(bytes_err_decompress,
					'bytes/zstd-decompress: malformed zstd input')
			}
			return bytes_node(out)
		}
		// §3.7 binary packing
		'bytes-pack' {
			if args.len != 2 { return none }
			format := arg_string(args[0]) or { return none }
			items := arg_items(args[1]) or { return none }
			return bytes_pack(format, items)
		}
		'bytes-unpack' {
			if args.len != 2 { return none }
			format := arg_string(args[0]) or { return none }
			b := arg_bytes(args[1]) or { return none }
			return bytes_unpack(format, b)
		}
		// §3.8 string conversion
		'bytes-from-string-utf8' {
			if args.len != 1 { return none }
			s := arg_string(args[0]) or { return none }
			return bytes_node(s.bytes())
		}
		'bytes-to-string-utf8' {
			if args.len != 1 { return none }
			b := arg_bytes(args[0]) or { return none }
			if !utf8_validate(b) {
				return mk_err(bytes_err_invalid_utf8,
					'bytes/to-string-utf8: invalid UTF-8 sequence')
			}
			return bytes_string_node(b.bytestr())
		}
		'bytes-to-string-utf8-lossy' {
			if args.len != 1 { return none }
			b := arg_bytes(args[0]) or { return none }
			return bytes_string_node(utf8_lossy(b))
		}
		'bytes-from-string-latin1' {
			if args.len != 1 { return none }
			s := arg_string(args[0]) or { return none }
			// Each codepoint 0..255 → one byte (byte-clean round-trip).
			mut out := []u8{cap: s.len}
			for r in s.runes() {
				out << u8(u32(r) & 0xFF)
			}
			return bytes_node(out)
		}
		'bytes-to-string-latin1' {
			if args.len != 1 { return none }
			b := arg_bytes(args[0]) or { return none }
			// Each byte → its Latin-1 codepoint (always valid).
			mut sb := []rune{cap: b.len}
			for c in b {
				sb << rune(c)
			}
			return bytes_string_node(sb.string())
		}
		else { return none }
	}
}

// ── search / split helpers ──────────────────────────────────────────────────

// bytes_index_of returns the first index of needle in hay, or -1.
// §4.2 — an empty needle matches at index 0 (even in an empty haystack).
fn bytes_index_of(hay []u8, needle []u8) int {
	if needle.len == 0 {
		return 0
	}
	if needle.len > hay.len {
		return -1
	}
	for i := 0; i <= hay.len - needle.len; i++ {
		mut ok := true
		for j in 0 .. needle.len {
			if hay[i + j] != needle[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

// bytes_split splits hay on each non-overlapping occurrence of sep.
// An empty separator yields the whole buffer as a single segment.
fn bytes_split(hay []u8, sep []u8) [][]u8 {
	mut out := [][]u8{}
	if sep.len == 0 {
		out << hay.clone()
		return out
	}
	mut start := 0
	for i := 0; i <= hay.len - sep.len; {
		mut hit := true
		for j in 0 .. sep.len {
			if hay[i + j] != sep[j] {
				hit = false
				break
			}
		}
		if hit {
			out << hay[start..i].clone()
			i += sep.len
			start = i
		} else {
			i++
		}
	}
	out << hay[start..].clone()
	return out
}

// gzip_frame_isize_zero reports whether b looks like a well-formed gzip
// frame (magic 0x1f 0x8b, DEFLATE method 0x08) whose ISIZE trailer (the
// last 4 bytes, little-endian original-data size mod 2^32) is zero — i.e.
// an empty-payload frame. Used to recover the §4.3 empty round-trip that
// V's gzip.decompress rejects.
fn gzip_frame_isize_zero(b []u8) bool {
	if b.len < 18 {
		return false
	}
	if b[0] != 0x1f || b[1] != 0x8b || b[2] != 0x08 {
		return false
	}
	orig_size := u32(b[b.len - 4]) | (u32(b[b.len - 3]) << 8) |
		(u32(b[b.len - 2]) << 16) | (u32(b[b.len - 1]) << 24)
	return orig_size == 0
}

// ── base64 padding-tolerant decode ──────────────────────────────────────────

// base64_decode_tolerant decodes standard or URL-safe base64, accepting both
// padded and unpadded input (§3.4 — decoders are padding-tolerant in both
// directions). Returns none on malformed input.
fn base64_decode_tolerant(s string, url bool) ?[]u8 {
	mut norm := s.trim_right('=')
	// Re-pad to a multiple of 4 so the underlying decoder (which expects
	// canonical padded input) accepts unpadded forms.
	rem := norm.len % 4
	if rem == 1 {
		// A length ≡ 1 mod 4 is never a valid base64 encoding.
		return none
	}
	if rem != 0 {
		norm += '='.repeat(4 - rem)
	}
	if url {
		out := base64.url_decode(norm)
		if out.len == 0 && norm.trim_right('=').len != 0 {
			return none
		}
		return out
	}
	out := base64.decode(norm)
	if out.len == 0 && norm.trim_right('=').len != 0 {
		return none
	}
	return out
}

// ── UTF-8 validation + lossy decode ─────────────────────────────────────────

// utf8_validate reports whether b is a well-formed UTF-8 byte sequence,
// rejecting overlong encodings, surrogates, and out-of-range codepoints.
fn utf8_validate(b []u8) bool {
	mut i := 0
	for i < b.len {
		c0 := b[i]
		if c0 < 0x80 {
			i++
			continue
		}
		mut size := 0
		mut cp := u32(0)
		mut min := u32(0)
		if c0 & 0xE0 == 0xC0 {
			size = 2
			cp = u32(c0 & 0x1F)
			min = 0x80
		} else if c0 & 0xF0 == 0xE0 {
			size = 3
			cp = u32(c0 & 0x0F)
			min = 0x800
		} else if c0 & 0xF8 == 0xF0 {
			size = 4
			cp = u32(c0 & 0x07)
			min = 0x10000
		} else {
			return false
		}
		if i + size > b.len {
			return false
		}
		for k in 1 .. size {
			cc := b[i + k]
			if cc & 0xC0 != 0x80 {
				return false
			}
			cp = (cp << 6) | u32(cc & 0x3F)
		}
		if cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF) {
			return false
		}
		i += size
	}
	return true
}

// utf8_lossy decodes b as UTF-8, replacing each maximal invalid run with
// U+FFFD (matches Rust String::from_utf8_lossy). §3.8 — never raises.
fn utf8_lossy(b []u8) string {
	replacement := [u8(0xEF), 0xBF, 0xBD]  // U+FFFD in UTF-8
	mut out := []u8{cap: b.len}
	mut i := 0
	for i < b.len {
		c0 := b[i]
		if c0 < 0x80 {
			out << c0
			i++
			continue
		}
		mut size := 0
		mut cp := u32(0)
		mut min := u32(0)
		if c0 & 0xE0 == 0xC0 {
			size = 2
			cp = u32(c0 & 0x1F)
			min = 0x80
		} else if c0 & 0xF0 == 0xE0 {
			size = 3
			cp = u32(c0 & 0x0F)
			min = 0x800
		} else if c0 & 0xF8 == 0xF0 {
			size = 4
			cp = u32(c0 & 0x07)
			min = 0x10000
		} else {
			out << replacement
			i++
			continue
		}
		if i + size > b.len {
			out << replacement
			i++
			continue
		}
		mut valid := true
		for k in 1 .. size {
			cc := b[i + k]
			if cc & 0xC0 != 0x80 {
				valid = false
				break
			}
			cp = (cp << 6) | u32(cc & 0x3F)
		}
		if !valid || cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF) {
			out << replacement
			i++
			continue
		}
		for k in 0 .. size {
			out << b[i + k]
		}
		i += size
	}
	return out.bytestr()
}

// ── binary packing (§3.7, struct-inspired, CX-owned format-char table) ───────

struct PackField {
mut:
	ch     u8
	count  int  // repeat count for s (byte string length) / generic prefix
	size   int  // bytes consumed per value
	signed bool
	is_pad bool
	is_str bool
}

// parse_pack_format parses the format string into a byte-order flag and a
// field list. Returns an err-value on any unsupported / malformed char.
fn parse_pack_format(format string) (bool, []PackField, ?cx.Node) {
	mut big_endian := false
	mut fields := []PackField{}
	mut i := 0
	if format.len > 0 {
		c := format[0]
		match c {
			`<` { big_endian = false  i = 1 }
			`>` { big_endian = true   i = 1 }
			`!` { big_endian = true   i = 1 }
			`=` { big_endian = false  i = 1 }  // native byte order (LE on supported targets)
			`@` { big_endian = false  i = 1 }  // native byte order, no alignment padding
			else {}
		}
	}
	for i < format.len {
		c := format[i]
		if c == ` ` {
			i++
			continue
		}
		// Optional decimal count prefix.
		mut count := 0
		mut had_count := false
		for i < format.len && format[i] >= `0` && format[i] <= `9` {
			count = count * 10 + int(format[i] - `0`)
			had_count = true
			i++
		}
		if i >= format.len {
			return big_endian, fields, mk_err(bytes_err_pack_format,
				'bytes/pack: dangling count in format string')
		}
		fc := format[i]
		i++
		mut f := PackField{ ch: fc, count: if had_count { count } else { 1 } }
		match fc {
			`b` { f.size = 1  f.signed = true }
			`B` { f.size = 1 }
			`h` { f.size = 2  f.signed = true }
			`H` { f.size = 2 }
			`i` { f.size = 4  f.signed = true }
			`I` { f.size = 4 }
			`q` { f.size = 8  f.signed = true }
			`Q` { f.size = 8 }
			`f` { f.size = 4 }
			`d` { f.size = 8 }
			`?` { f.size = 1 }
			`s` { f.is_str = true  f.size = if had_count { count } else { 1 } }
			`x` { f.is_pad = true  f.size = 1 }
			else {
				// §3.7 — out-of-scope chars (p / P / e / others) rejected.
				return big_endian, fields, mk_err(bytes_err_pack_format,
					'bytes/pack: unsupported format char `${fc.ascii_str()}`')
			}
		}
		// Numeric chars with an explicit count expand to `count` fields.
		if had_count && !f.is_str && !f.is_pad {
			for _ in 0 .. count {
				fields << PackField{ ch: fc, count: 1, size: f.size, signed: f.signed }
			}
		} else if f.is_pad && had_count {
			for _ in 0 .. count {
				fields << PackField{ ch: `x`, count: 1, size: 1, is_pad: true }
			}
		} else {
			fields << f
		}
	}
	return big_endian, fields, none
}

// put_uint writes an unsigned integer of `size` bytes in the chosen order.
fn put_uint(mut out []u8, v u64, size int, big_endian bool) {
	if big_endian {
		for k := size - 1; k >= 0; k-- {
			out << u8((v >> (u32(k) * 8)) & 0xFF)
		}
	} else {
		for k in 0 .. size {
			out << u8((v >> (u32(k) * 8)) & 0xFF)
		}
	}
}

// get_uint reads an unsigned integer of `size` bytes in the chosen order.
fn get_uint(b []u8, off int, size int, big_endian bool) u64 {
	mut v := u64(0)
	if big_endian {
		for k in 0 .. size {
			v = (v << 8) | u64(b[off + k])
		}
	} else {
		for k := size - 1; k >= 0; k-- {
			v = (v << 8) | u64(b[off + k])
		}
	}
	return v
}

// sign_extend reinterprets the low `size` bytes of v as a signed i64.
fn sign_extend(v u64, size int) i64 {
	bitsz := u32(size) * 8
	sign_bit := u64(1) << (bitsz - 1)
	if v & sign_bit != 0 {
		mask := (u64(1) << bitsz) - 1
		return i64(v) - i64(mask + 1)
	}
	return i64(v)
}

// scalar_as_i64 / scalar_as_f64 / scalar_as_bytes extract pack input values.
fn pack_as_i64(n cx.Node) ?i64 {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			i64  { return v }
			f64  { return i64(v) }
			bool { return if v { i64(1) } else { i64(0) } }
			else { return none }
		}
	}
	return none
}

fn pack_as_f64(n cx.Node) ?f64 {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			f64  { return v }
			i64  { return f64(v) }
			else { return none }
		}
	}
	return none
}

fn pack_as_bool(n cx.Node) ?bool {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			bool { return v }
			i64  { return v != 0 }
			else { return none }
		}
	}
	return none
}

// bytes_pack implements §3.7 pack.
fn bytes_pack(format string, values []cx.Node) cx.Node {
	big_endian, fields, perr := parse_pack_format(format)
	if e := perr {
		return e
	}
	// Count value-consuming fields (everything but padding).
	mut needed := 0
	for f in fields {
		if !f.is_pad {
			needed++
		}
	}
	if needed != values.len {
		return mk_err(bytes_err_pack_length,
			'bytes/pack: value count ${values.len} != format field count ${needed}')
	}
	mut out := []u8{}
	mut vi := 0
	for f in fields {
		if f.is_pad {
			out << u8(0)
			continue
		}
		val := values[vi]
		vi++
		if f.is_str {
			buf := arg_bytes(val) or {
				return mk_err(bytes_err_pack_format,
					'bytes/pack: `s` field requires a bytes/string value')
			}
			// Fixed-width: truncate or zero-pad to f.size.
			for k in 0 .. f.size {
				out << if k < buf.len { buf[k] } else { u8(0) }
			}
			continue
		}
		match f.ch {
			`f` {
				fv := pack_as_f64(val) or {
					return mk_err(bytes_err_pack_length, 'bytes/pack: `f` requires a number')
				}
				put_uint(mut out, u64(math.f32_bits(f32(fv))), 4, big_endian)
			}
			`d` {
				fv := pack_as_f64(val) or {
					return mk_err(bytes_err_pack_length, 'bytes/pack: `d` requires a number')
				}
				put_uint(mut out, math.f64_bits(fv), 8, big_endian)
			}
			`?` {
				bv := pack_as_bool(val) or {
					return mk_err(bytes_err_pack_length, 'bytes/pack: `?` requires a bool')
				}
				out << if bv { u8(1) } else { u8(0) }
			}
			else {
				iv := pack_as_i64(val) or {
					return mk_err(bytes_err_pack_length, 'bytes/pack: integer field requires a number')
				}
				put_uint(mut out, u64(iv), f.size, big_endian)
			}
		}
	}
	return bytes_node(out)
}

// bytes_unpack implements §3.7 unpack.
fn bytes_unpack(format string, b []u8) cx.Node {
	big_endian, fields, perr := parse_pack_format(format)
	if e := perr {
		return e
	}
	// Verify the total declared width matches the buffer length.
	mut total := 0
	for f in fields {
		total += f.size
	}
	if total != b.len {
		return mk_err(bytes_err_pack_length,
			'bytes/unpack: buffer length ${b.len} != format width ${total}')
	}
	mut out := []cx.Node{}
	mut off := 0
	for f in fields {
		if f.is_pad {
			off += f.size
			continue
		}
		if f.is_str {
			out << bytes_node(b[off..off + f.size].clone())
			off += f.size
			continue
		}
		match f.ch {
			`f` {
				u := u32(get_uint(b, off, 4, big_endian))
				out << cx.Node(cx.ScalarNode{
					value: cx.ScalarValue(f64(math.f32_from_bits(u)))
					data_type: cx.ScalarType.float_type
				})
			}
			`d` {
				u := get_uint(b, off, 8, big_endian)
				out << cx.Node(cx.ScalarNode{
					value: cx.ScalarValue(math.f64_from_bits(u))
					data_type: cx.ScalarType.float_type
				})
			}
			`?` {
				out << bytes_bool_node(b[off] != 0)
			}
			else {
				u := get_uint(b, off, f.size, big_endian)
				if f.signed {
					out << bytes_int_node(sign_extend(u, f.size))
				} else {
					out << bytes_int_node(i64(u))
				}
			}
		}
		off += f.size
	}
	return cx.Node(cx.SequenceNode{ items: out })
}
