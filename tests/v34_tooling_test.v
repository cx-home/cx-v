module main

import cx

// Tests for the canonical-form tooling C ABI (Phase 6 / spec/abi.md §2.6):
//   cx_text_fmt        — lossless canonical (preserves comments)
//   cx_text_canonical  — strict canonical (strips presentation)
//   cx_text_hash       — SHA-256 hex of strict canonical bytes
//   cx_text_eq         — strict canonical equality

fn test_fmt_preserves_comments() {
	src := '[config
  [- a comment]
  [server host=localhost port=8080]
]'
	out := cx.cx_text_fmt(src) or { panic(err) }
	assert out.contains('a comment'), 'fmt must preserve comments; got: ${out}'
	assert out.contains('host=localhost')
}

fn test_canonical_strips_comments() {
	src := '[config
  [- a comment]
  [server host=localhost port=8080]
]'
	out := cx.cx_text_canonical(src) or { panic(err) }
	assert !out.contains('a comment'), 'canonical must strip comments; got: ${out}'
	assert out.contains('host=localhost')
}

fn test_canonical_normalizes_whitespace() {
	src1 := '[config
  [server host=localhost port=8080]
]'
	src2 := '[config [server host=localhost port=8080]]'
	c1 := cx.cx_text_canonical(src1) or { panic(err) }
	c2 := cx.cx_text_canonical(src2) or { panic(err) }
	assert c1 == c2, 'whitespace-equivalent inputs must canonicalize the same\nc1=${c1}\nc2=${c2}'
}

fn test_hash_is_64_hex_chars() {
	src := '[config [server host=localhost]]'
	h := cx.cx_text_hash(src) or { panic(err) }
	assert h.len == 64, 'sha256 hex is 64 chars; got len=${h.len}'
	for c in h {
		ok := (c >= `0` && c <= `9`) || (c >= `a` && c <= `f`)
		assert ok, 'hash must be lowercase hex; got char ${rune(c).str()}'
	}
}

fn test_hash_is_stable() {
	src := '[config [server host=localhost port=8080]]'
	h1 := cx.cx_text_hash(src) or { panic(err) }
	h2 := cx.cx_text_hash(src) or { panic(err) }
	assert h1 == h2
}

fn test_hash_changes_when_data_changes() {
	a := '[config [server host=localhost port=8080]]'
	b := '[config [server host=localhost port=8081]]'
	ha := cx.cx_text_hash(a) or { panic(err) }
	hb := cx.cx_text_hash(b) or { panic(err) }
	assert ha != hb, 'different ports must hash differently'
}

fn test_eq_equivalent_inputs() {
	a := '[config
  [- comment one]
  [server host=localhost port=8080]
]'
	b := '[config [server host=localhost port=8080]]'
	assert cx.cx_text_eq(a, b) or { panic(err) }
}

fn test_eq_different_inputs() {
	a := '[config [server host=a]]'
	b := '[config [server host=b]]'
	assert !cx.cx_text_eq(a, b) or { panic(err) }
}

fn test_fmt_idempotent() {
	src := '[config
  [server host=localhost port=8080 active=true]
  [database host=db.example.com]
]'
	once := cx.cx_text_fmt(src) or { panic(err) }
	twice := cx.cx_text_fmt(once) or { panic(err) }
	assert once == twice, 'fmt must be idempotent\nonce=${once}\ntwice=${twice}'
}

fn test_canonical_idempotent() {
	src := '[config
  [- ignore]
  [server host=localhost]
]'
	once := cx.cx_text_canonical(src) or { panic(err) }
	twice := cx.cx_text_canonical(once) or { panic(err) }
	assert once == twice, 'canonical must be idempotent'
}
