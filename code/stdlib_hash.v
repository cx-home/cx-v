module code

import cx
import crypto.sha256
import crypto.sha512
import crypto.blake3
import encoding.hex
import encoding.base64
import encoding.base32

// cx-stdlib/hash — bundled source const + native primitives.
// Per-module ownership: this whole module's implementation (the [?def]
// source bodies AND the native primitives backing them) lives in this
// one file, so modules land in parallel with zero shared-file edits.
// Registered via bundled_stdlib_source / bundled_stdlib_names
// (stdlib_bundle.v) and the stdlib_builtin chain (stdlib_dispatch.v).
//
// The CX bodies below are written in CALL FORM `prim(args)` bottoming
// out in the `hash_stdlib_builtin` primitives. The const is a single-
// quoted V string, so the CX source contains NO single-quote characters
// (comments use [; … ], strings use double quotes).

const stdlib_src_hash = $embed_file('../stdlib/hash.cx').to_string()

// stdlib_hash.v — native primitives backing the `cx-stdlib/hash` module
// (spec/stdlib_hash.md). Content-addressable hashing — SHA-256/384/512
// and BLAKE3 (including XOF) — plus digest encoding (hex / base64-url /
// base32), SRI helpers, constant-time digest comparison, and streaming
// hashers. These operations are not expressible in pure CX `[?def]`
// bodies (they bottom out in C-level digest routines), so the bundle
// bodies dispatch into the primitives below. See stdlib_dispatch.v for
// the registration line.
//
// ── CX value model ──────────────────────────────────────────────────
//   bytes   → ScalarType.bytes_type, ScalarValue string carrying raw
//             octets (V strings hold arbitrary bytes).
//   string  → ScalarType.string_type (hex / base64 / base32 / SRI tag).
//   bool    → ScalarType.bool_type   (constant-time equals result).
//   element → a named Element. The streaming hasher is an opaque
//             `[__cx_hasher__ :algo "…" :buf <bytes>]` element; `sri-parse`
//             returns `[sri :algo "…" :digest <bytes>]`.
//
// The streaming hasher is OBSERVABLY pure (spec §3.3): `hasher-update`
// returns a NEW element whose buffer is the old buffer concatenated
// with the new chunk; the input hasher is never mutated. `finalize`
// hashes the accumulated buffer. Same updates over same data always
// produce the same digest, and single-shot == streaming.
//
// Errors are returned as `[err :code cx-err:CXERxxxx :message …]`
// element nodes (the renderer surfaces the code string, which the
// conformance harness matches against `--- out_err`).

// ── scalar / element builders ───────────────────────────────────────

fn hash_bytes(b []u8) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(b.bytestr()), data_type: cx.ScalarType.bytes_type }
}

fn hash_bytes_str(s string) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(s), data_type: cx.ScalarType.bytes_type }
}

fn hash_str(s string) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(s), data_type: cx.ScalarType.string_type }
}

fn hash_bool(b bool) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(b), data_type: cx.ScalarType.bool_type }
}

fn hash_err(err_code string, msg string) cx.Node {
	// err scalar fields (code/message) are attributes; reuse the
	// shared err shape so all err values round-trip identically.
	return mk_err(err_code, msg)
}

// ── argument readers ────────────────────────────────────────────────

// hash_arg_bytes reads a bytes-or-string scalar argument as raw octets.
// `bytes` carries octets in its string payload; a `string` argument is
// taken as its UTF-8 octet content (used by `*-string` convenience fns
// and by callers who pass a literal string where bytes are expected).
fn hash_arg_bytes(n cx.Node) ?[]u8 {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v.bytes()
		}
	}
	note_operand_fault('hash', 'hash-', 'bytes', n)
	return none
}

fn hash_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	note_operand_fault('hash', 'hash-', 'string', n)
	return none
}

fn hash_arg_int(n cx.Node) ?i64 {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			i64 { return v }
			f64 { return i64(v) }
			else {}
		}
	}
	note_operand_fault('hash', 'hash-', 'int', n)
	return none
}

// ── digest cores ────────────────────────────────────────────────────

fn digest_sha256(data []u8) []u8 {
	return sha256.sum256(data)
}

fn digest_sha384(data []u8) []u8 {
	return sha512.sum384(data)
}

fn digest_sha512(data []u8) []u8 {
	return sha512.sum512(data)
}

fn digest_blake3(data []u8) []u8 {
	return blake3.sum256(data)
}

// digest_blake3_xof produces `out_len` BLAKE3 output bytes (XOF mode).
fn digest_blake3_xof(data []u8, out_len u64) []u8 {
	mut d := blake3.Digest.new_hash() or { return []u8{} }
	d.write(data) or { return []u8{} }
	return d.checksum(out_len)
}

// digest_by_algo dispatches a streaming-style single-shot by algo name.
// Returns none for an unknown algorithm.
fn digest_by_algo(algo string, data []u8) ?[]u8 {
	match algo {
		'sha256' { return digest_sha256(data) }
		'sha384' { return digest_sha384(data) }
		'sha512' { return digest_sha512(data) }
		'blake3' { return digest_blake3(data) }
		else { return none }
	}
}

// ── encoding helpers ────────────────────────────────────────────────

fn enc_hex(b []u8) string {
	return hex.encode(b)
}

fn enc_base64_url(b []u8) string {
	// URL-safe base64 with no padding (SRI tags use standard base64 with
	// padding; `format-base64-url` per spec §2 is the URL-safe no-pad
	// variant). Strip the `=` padding that url_encode emits.
	return base64.url_encode(b).trim_right('=')
}

fn enc_base64_std(b []u8) string {
	// Standard base64 (with padding) — used by SRI tags per W3C SRI.
	return base64.encode(b)
}

fn enc_base32(b []u8) string {
	// Uppercase RFC 4648 base32 with standard `=` padding.
	return base32.encode_to_string(b)
}

// ── constant-time comparison (spec §3.5) ────────────────────────────

// ct_equals compares two byte slices in time independent of where the
// first differing byte is (resistant to timing attacks). The loop runs
// over the longer length so wall-time does not leak the mismatch index.
fn ct_equals(a []u8, b []u8) bool {
	mut diff := u8(0)
	// Length mismatch is folded into the accumulator without an early
	// return; we still walk max(len) bytes so timing is data-independent.
	if a.len != b.len {
		diff |= 1
	}
	n := if a.len > b.len { a.len } else { b.len }
	for i in 0 .. n {
		av := if i < a.len { a[i] } else { u8(0) }
		bv := if i < b.len { b[i] } else { u8(0) }
		diff |= (av ^ bv)
	}
	return diff == 0
}

// ── SRI helpers (spec §3.6) ──────────────────────────────────────────

// expected_sri_len returns the digest byte-length required by an SRI
// algo name, or none for an unrecognised algo.
fn expected_sri_len(algo string) ?int {
	match algo {
		'sha256' { return 32 }
		'sha384' { return 48 }
		'sha512' { return 64 }
		else { return none }
	}
}

// sri_format builds `<algo>-<base64>` per W3C SRI (standard base64 with
// padding). Raises CXER2001 when the digest length does not match the
// algorithm's expected length.
fn sri_format(digest []u8, algo string) cx.Node {
	want := expected_sri_len(algo) or {
		return hash_err('cx-err:CXER2000', 'E_HASH_ALGO_UNKNOWN: ${algo}')
	}
	if digest.len != want {
		return hash_err('cx-err:CXER2001', 'E_HASH_DIGEST_WRONG_LENGTH: ${algo} expects ${want} bytes, got ${digest.len}')
	}
	return hash_str('${algo}-${enc_base64_std(digest)}')
}

// sri_parse splits `<algo>-<base64>` into `[sri :algo "…" :digest <bytes>]`.
// Raises CXER2004 when the input does not match the SRI grammar.
fn sri_parse(s string) cx.Node {
	dash := s.index('-') or {
		return hash_err('cx-err:CXER2004', 'E_HASH_SRI_MALFORMED: ${s}')
	}
	algo := s[..dash]
	b64 := s[dash + 1..]
	want := expected_sri_len(algo) or {
		return hash_err('cx-err:CXER2004', 'E_HASH_SRI_MALFORMED: unknown algo in ${s}')
	}
	if b64 == '' {
		return hash_err('cx-err:CXER2004', 'E_HASH_SRI_MALFORMED: ${s}')
	}
	digest := base64.decode(b64)
	if digest.len == 0 || digest.len != want {
		return hash_err('cx-err:CXER2004', 'E_HASH_SRI_MALFORMED: ${s}')
	}
	// algo/digest are scalar fields → attributes (read via
	// $sri@algo / $sri@digest).
	mut attrs := []cx.Attribute{}
	mut items := []cx.Node{}
	append_result_field('algo', hash_str(algo), mut attrs, mut items)
	append_result_field('digest', hash_bytes(digest), mut attrs, mut items)
	return cx.Element{ name: 'sri', attrs: attrs, items: items }
}

// ── streaming hasher (spec §3.3) ─────────────────────────────────────

const hasher_marker = '__cx_hasher__'

// hasher_new constructs an opaque hasher element for `algo`. Raises
// CXER2000 for an unsupported algorithm.
fn hasher_new(algo string) cx.Node {
	match algo {
		'sha256', 'sha384', 'sha512', 'blake3' {}
		else {
			return hash_err('cx-err:CXER2000', 'E_HASH_ALGO_UNKNOWN: ${algo}')
		}
	}
	return mk_hasher(algo, '')
}

// mk_hasher builds the hasher element carrying the algo + accumulated
// buffer (raw octets in a bytes scalar). Observably immutable.
fn mk_hasher(algo string, buf string) cx.Node {
	return cx.Element{
		name: hasher_marker
		items: [
			cx.Node(cx.Element{
				name:  '${slot_child_prefix}algo'
				items: [hash_str(algo)]
			}),
			cx.Node(cx.Element{
				name:  '${slot_child_prefix}buf'
				items: [hash_bytes_str(buf)]
			}),
		]
	}
}

// read_hasher extracts (algo, buffer-octets) from a hasher element.
fn read_hasher(n cx.Node) ?(string, string) {
	if n is cx.Element {
		if n.name == hasher_marker {
			mut algo := ''
			mut buf := ''
			mut got_algo := false
			mut got_buf := false
			for it in n.items {
				if it is cx.Element {
					if it.name == '${slot_child_prefix}algo' && it.items.len > 0 {
						algo = hash_arg_str(it.items[0]) or { '' }
						got_algo = true
					} else if it.name == '${slot_child_prefix}buf' && it.items.len > 0 {
						buf = hash_arg_str(it.items[0]) or { '' }
						got_buf = true
					}
				}
			}
			if got_algo && got_buf {
				return algo, buf
			}
		}
	}
	return none
}

// hasher_update returns a NEW hasher with `chunk` appended to the
// buffer; the input hasher is untouched (observable purity).
fn hasher_update(h cx.Node, chunk []u8) ?cx.Node {
	algo, buf := read_hasher(h) or { return none }
	return mk_hasher(algo, buf + chunk.bytestr())
}

// hasher_finalize digests the accumulated buffer with the hasher's algo.
fn hasher_finalize(h cx.Node) ?cx.Node {
	algo, buf := read_hasher(h) or { return none }
	digest := digest_by_algo(algo, buf.bytes()) or { return none }
	return hash_bytes(digest)
}

// ── dispatch table ───────────────────────────────────────────────────

fn hash_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		// §3.1 single-shot hashers ───────────────────────────────────
		'hash-sha256' {
			data := hash_arg_bytes(args[0]) or { return none }
			return hash_bytes(digest_sha256(data))
		}
		'hash-sha384' {
			data := hash_arg_bytes(args[0]) or { return none }
			return hash_bytes(digest_sha384(data))
		}
		'hash-sha512' {
			data := hash_arg_bytes(args[0]) or { return none }
			return hash_bytes(digest_sha512(data))
		}
		'hash-blake3' {
			data := hash_arg_bytes(args[0]) or { return none }
			return hash_bytes(digest_blake3(data))
		}
		'hash-blake3-xof' {
			data := hash_arg_bytes(args[0]) or { return none }
			out_len := hash_arg_int(args[1]) or { return none }
			if out_len <= 0 {
				return hash_err('cx-err:CXER2005', 'E_HASH_XOF_LENGTH_INVALID: ${out_len}')
			}
			return hash_bytes(digest_blake3_xof(data, u64(out_len)))
		}
		// §3.2 string convenience ─────────────────────────────────────
		'hash-sha256-hex' {
			data := hash_arg_bytes(args[0]) or { return none }
			return hash_str(enc_hex(digest_sha256(data)))
		}
		'hash-sha384-hex' {
			data := hash_arg_bytes(args[0]) or { return none }
			return hash_str(enc_hex(digest_sha384(data)))
		}
		'hash-sha512-hex' {
			data := hash_arg_bytes(args[0]) or { return none }
			return hash_str(enc_hex(digest_sha512(data)))
		}
		'hash-blake3-hex' {
			data := hash_arg_bytes(args[0]) or { return none }
			return hash_str(enc_hex(digest_blake3(data)))
		}
		'hash-sha256-string' {
			s := hash_arg_str(args[0]) or { return none }
			return hash_bytes(digest_sha256(s.bytes()))
		}
		'hash-blake3-string' {
			s := hash_arg_str(args[0]) or { return none }
			return hash_bytes(digest_blake3(s.bytes()))
		}
		// §3.3 streaming hashers ──────────────────────────────────────
		'hash-hasher-new' {
			algo := hash_arg_str(args[0]) or { return none }
			return hasher_new(algo)
		}
		'hash-hasher-update' {
			chunk := hash_arg_bytes(args[1]) or { return none }
			return hasher_update(args[0], chunk)
		}
		'hash-hasher-finalize' {
			return hasher_finalize(args[0])
		}
		// §3.4 format conversion ──────────────────────────────────────
		'hash-format-hex' {
			d := hash_arg_bytes(args[0]) or { return none }
			return hash_str(enc_hex(d))
		}
		'hash-format-base64-url' {
			d := hash_arg_bytes(args[0]) or { return none }
			return hash_str(enc_base64_url(d))
		}
		'hash-format-base32' {
			d := hash_arg_bytes(args[0]) or { return none }
			return hash_str(enc_base32(d))
		}
		'hash-parse-hex' {
			s := hash_arg_str(args[0]) or { return none }
			if s.len % 2 != 0 || !is_all_hex(s) {
				return hash_err('cx-err:CXER2002', 'E_HASH_INVALID_HEX: ${s}')
			}
			decoded := hex.decode(s) or {
				return hash_err('cx-err:CXER2002', 'E_HASH_INVALID_HEX: ${s}')
			}
			return hash_bytes(decoded)
		}
		'hash-parse-base64-url' {
			s := hash_arg_str(args[0]) or { return none }
			if !is_valid_base64_url(s) {
				return hash_err('cx-err:CXER2003', 'E_HASH_INVALID_BASE64: ${s}')
			}
			decoded := base64.url_decode(s)
			if decoded.len == 0 && s.len != 0 {
				return hash_err('cx-err:CXER2003', 'E_HASH_INVALID_BASE64: ${s}')
			}
			return hash_bytes(decoded)
		}
		// §3.5 comparison ─────────────────────────────────────────────
		'hash-equals' {
			a := hash_arg_bytes(args[0]) or { return none }
			b := hash_arg_bytes(args[1]) or { return none }
			return hash_bool(ct_equals(a, b))
		}
		// §3.6 SRI helpers ────────────────────────────────────────────
		'hash-sri-format' {
			d := hash_arg_bytes(args[0]) or { return none }
			algo := hash_arg_str(args[1]) or { return none }
			return sri_format(d, algo)
		}
		'hash-sri-parse' {
			s := hash_arg_str(args[0]) or { return none }
			return sri_parse(s)
		}
		else {
			return none
		}
	}
}

// is_all_hex reports whether every byte of `s` is a hex digit (either
// case). Empty string is valid hex (the empty byte string).
fn is_all_hex(s string) bool {
	for c in s {
		is_digit := c >= `0` && c <= `9`
		is_lower := c >= `a` && c <= `f`
		is_upper := c >= `A` && c <= `F`
		if !is_digit && !is_lower && !is_upper {
			return false
		}
	}
	return true
}

// is_valid_base64_url reports whether `s` uses only URL-safe base64
// alphabet chars (A-Z a-z 0-9 - _) with optional trailing `=` padding.
fn is_valid_base64_url(s string) bool {
	for c in s {
		ok := (c >= `A` && c <= `Z`) || (c >= `a` && c <= `z`) || (c >= `0` && c <= `9`)
			|| c == `-` || c == `_` || c == `=`
		if !ok {
			return false
		}
	}
	return true
}
