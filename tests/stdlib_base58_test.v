module main

import code

// TDD for cx-stdlib/bytes base58 (multibase base58btc, Bitcoin alphabet).
// Needed by cx-stdlib/did did:key encoding (spec/std-lib/did.md §2.1).
// spec/std-lib/bytes.md §3.5.

// Round-trip through base58, including a LEADING ZERO byte (0x00 → '1'),
// which is the subtle path in base58btc.
fn test_base58_roundtrip_with_leading_zero() {
	prog := "[?lib 'cx-stdlib/bytes' :as b]
[\$b:to-hex [\$b:from-base58 [\$b:to-base58 [\$b:from-hex \"00010203\"]]]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('00010203'), 'base58 round-trip lost data (leading zero): ${out}'
}

// The canonical base58btc test vector: "Hello World!" → "2NEpo7TZRRrLZSi2U".
fn test_base58_known_vector_encode() {
	prog := "[?lib 'cx-stdlib/bytes' :as b]
[\$b:to-base58 [\$b:from-string-utf8 \"Hello World!\"]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('2NEpo7TZRRrLZSi2U'), 'expected base58 vector 2NEpo7TZRRrLZSi2U, got: ${out}'
}

// Decoding the canonical vector reproduces the original bytes.
fn test_base58_known_vector_decode() {
	prog := "[?lib 'cx-stdlib/bytes' :as b]
[\$b:to-string-utf8 [\$b:from-base58 \"2NEpo7TZRRrLZSi2U\"]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('Hello World!'), 'expected decoded "Hello World!", got: ${out}'
}
