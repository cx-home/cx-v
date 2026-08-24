module cx

// hash_registry.v — the ONE algorithm registry (I1 identity epoch, stream
// 19, L31/L32/L35): self-describing tagged addresses. Text-visible
// addresses everywhere (CLI, attributes, store keys, aliases, pkg pins)
// are `<algo-name>:<lowercase-hex>` with the multiformats NAME spelling;
// binary lanes carry true varint multihash (uvarint(code) ‖ uvarint(len)
// ‖ digest) with a normative bijection to the text form. Bare hex is
// REJECTED after I1 — fail-loud, no dual-accept.

pub struct CxHashAlgo {
pub:
	name     string // multiformats name-registry spelling
	code     u32    // multicodec code
	dlen     int    // digest length in bytes
	required bool   // 1.0 status: required (true) vs optional
}

// The 1.0 rows. sha2-256 is REQUIRED and the default (content-addressing
// canon); all other algorithm names are reserved.
pub const cx_hash_registry = [
	CxHashAlgo{ name: 'sha2-256', code: 0x12, dlen: 32, required: true },
	CxHashAlgo{ name: 'sha2-384', code: 0x20, dlen: 48, required: false },
	CxHashAlgo{ name: 'sha2-512', code: 0x13, dlen: 64, required: false },
	CxHashAlgo{ name: 'blake3',   code: 0x1e, dlen: 32, required: false },
]!

pub const cx_default_hash_algo = 'sha2-256'

pub fn cx_hash_algo_by_name(name string) ?CxHashAlgo {
	for a in cx_hash_registry {
		if a.name == name {
			return a
		}
	}
	return none
}

pub fn cx_hash_algo_by_code(code u32) ?CxHashAlgo {
	for a in cx_hash_registry {
		if a.code == code {
			return a
		}
	}
	return none
}

// cx_tag_address composes the text-visible tagged form.
pub fn cx_tag_address(algo string, hex string) string {
	return '${algo}:${hex}'
}

// cx_parse_tagged_address splits a tagged address into (algo, hex),
// failing loud on an unrecognized algorithm, a digest-length mismatch,
// non-hex digest bytes — and on BARE HEX (rejected post-I1, no
// dual-accept).
pub fn cx_parse_tagged_address(s string) !(string, string) {
	idx := s.index(':') or {
		return error('bare hex is not an address — tagged form `<algo>:<hex>` required since I1 (e.g. `sha2-256:…`) (cx-err:CXER0130)')
	}
	algo := s[..idx]
	hex := s[idx + 1..]
	a := cx_hash_algo_by_name(algo) or {
		return error('unrecognized hash algorithm `${algo}` — registry: sha2-256 (default), sha2-384, sha2-512, blake3 (cx-err:CXER0131)')
	}
	if hex.len != a.dlen * 2 {
		return error('digest length ${hex.len / 2} does not match ${algo} (${a.dlen} bytes) (cx-err:CXER0132)')
	}
	for c in hex {
		if !((c >= `0` && c <= `9`) || (c >= `a` && c <= `f`)) {
			return error('digest must be lowercase hex (cx-err:CXER0132)')
		}
	}
	return algo, hex
}

// ── Multihash binary bijection (L32) ─────────────────────────────────────────

// cx_multihash_encode: uvarint(code) ‖ uvarint(len) ‖ digest.
pub fn cx_multihash_encode(algo string, digest []u8) ![]u8 {
	a := cx_hash_algo_by_name(algo) or {
		return error('unrecognized hash algorithm `${algo}` (cx-err:CXER0131)')
	}
	if digest.len != a.dlen {
		return error('digest length ${digest.len} does not match ${algo} (${a.dlen}) (cx-err:CXER0132)')
	}
	mut out := []u8{cap: digest.len + 4}
	mh_uvarint(u64(a.code), mut out)
	mh_uvarint(u64(digest.len), mut out)
	out << digest
	return out
}

// cx_multihash_decode: the inverse; returns (algo-name, digest).
pub fn cx_multihash_decode(b []u8) !(string, []u8) {
	code, i1 := mh_read_uvarint(b, 0)!
	dlen, i2 := mh_read_uvarint(b, i1)!
	a := cx_hash_algo_by_code(u32(code)) or {
		return error('unrecognized multicodec 0x${code:x} (cx-err:CXER0131)')
	}
	if u64(a.dlen) != dlen {
		return error('multihash length ${dlen} does not match ${a.name} (${a.dlen}) (cx-err:CXER0132)')
	}
	if i2 + int(dlen) > b.len {
		return error('multihash truncated (cx-err:CXER0132)')
	}
	return a.name, b[i2..i2 + int(dlen)].clone()
}

fn mh_uvarint(v_in u64, mut out []u8) {
	mut v := v_in
	for v >= 0x80 {
		out << u8(v & 0x7f | 0x80)
		v >>= 7
	}
	out << u8(v)
}

fn mh_read_uvarint(b []u8, at int) !(u64, int) {
	mut v := u64(0)
	mut shift := 0
	mut i := at
	for i < b.len {
		c := b[i]
		v |= u64(c & 0x7f) << shift
		i++
		if c < 0x80 {
			return v, i
		}
		shift += 7
		if shift > 63 {
			break
		}
	}
	return error('multihash varint malformed (cx-err:CXER0132)')
}
