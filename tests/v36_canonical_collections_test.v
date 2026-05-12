module main

import cx

// Tests for v0.6.0 / spec/canonical.md v1.1 / ADR 0017 §D14 — canonical
// form treatment of collection literals: map-key lex sort, sequence-
// flat hash, array-nested hash, and diff round-trips.

// ── Map key ordering (§2.11.1) ──────────────────────────────────────────────

fn test_map_canonical_sorts_keys_lex() {
	// Insertion order differs; canonical form sorts keys lexicographically.
	src := "[r {zeta: 1, alpha: 2, mu: 3}]"
	out := cx.cx_text_canonical(src) or { panic(err) }
	// Expect alpha → mu → zeta in canonical output.
	a := out.index('alpha') or { panic('alpha missing in: ${out}') }
	m := out.index('mu') or { panic('mu missing in: ${out}') }
	z := out.index('zeta') or { panic('zeta missing in: ${out}') }
	assert a < m, 'expected alpha before mu; out=${out}'
	assert m < z, 'expected mu before zeta; out=${out}'
}

fn test_map_hash_invariant_under_insertion_order() {
	// Two docs that differ only in map insertion order must hash the same
	// after canonicalization per ADR §D14.
	a := "[r {alpha: 1, beta: 2, gamma: 3}]"
	b := "[r {gamma: 3, alpha: 1, beta: 2}]"
	hash_a := cx.cx_text_hash(a) or { panic(err) }
	hash_b := cx.cx_text_hash(b) or { panic(err) }
	assert hash_a == hash_b, 'expected equal hashes; got ${hash_a} vs ${hash_b}'
}

fn test_map_eq_invariant_under_insertion_order() {
	a := "[r {alpha: 1, beta: 2}]"
	b := "[r {beta: 2, alpha: 1}]"
	eq := cx.cx_text_eq(a, b) or { panic(err) }
	assert eq
}

fn test_map_canonicalize_recurses_into_nested_map() {
	src := "[r {z: {bb: 1, aa: 2}, a: 3}]"
	out := cx.cx_text_canonical(src) or { panic(err) }
	// Outer map sorts a before z; inner map sorts aa before bb.
	a_pos := out.index('a:') or { panic('a: missing') }
	z_pos := out.index('z:') or { panic('z: missing') }
	assert a_pos < z_pos, 'outer order wrong; out=${out}'
	aa_pos := out.index('aa') or { panic('aa missing') }
	bb_pos := out.index('bb') or { panic('bb missing') }
	assert aa_pos < bb_pos, 'inner order wrong; out=${out}'
}

fn test_map_canonical_is_idempotent() {
	// Canonicalize-of-canonicalize equals canonicalize per §11.4
	// idempotence requirement.
	src := "[r {zeta: 1, alpha: 2}]"
	once := cx.cx_text_canonical(src) or { panic(err) }
	twice := cx.cx_text_canonical(once) or { panic(err) }
	assert once == twice
}

// ── Array vs Sequence treatment (hash) ──────────────────────────────────────

fn test_array_hash_preserves_nesting() {
	// `[[1, 2], [3, 4]]` and `[1, 2, 3, 4]` are distinct Array values
	// per ADR §D3. Their hashes must differ.
	a := '[r [[1, 2], [3, 4]]]'
	b := '[r [1, 2, 3, 4]]'
	hash_a := cx.cx_text_hash(a) or { panic(err) }
	hash_b := cx.cx_text_hash(b) or { panic(err) }
	assert hash_a != hash_b, 'expected distinct hashes; got ${hash_a}'
}

fn test_sequence_hash_flattens() {
	// Sequences flatten on construction per CXDM §1 / ADR §D2 — they
	// flatten at PARSE time, before canonicalization. So nested and
	// flat sources of the same final sequence hash identically.
	a := '[r ((1, 2), 3)]'
	b := '[r (1, 2, 3)]'
	hash_a := cx.cx_text_hash(a) or { panic(err) }
	hash_b := cx.cx_text_hash(b) or { panic(err) }
	assert hash_a == hash_b, 'expected equal seq-flatten hashes; got ${hash_a} vs ${hash_b}'
}

fn test_sequence_vs_array_hash_distinct() {
	a := '[r (1, 2, 3)]'
	b := '[r [1, 2, 3]]'
	hash_a := cx.cx_text_hash(a) or { panic(err) }
	hash_b := cx.cx_text_hash(b) or { panic(err) }
	assert hash_a != hash_b, 'sequence and array must hash differently; ${hash_a}'
}

// ── Diff round-trips (ADR §D14 + spec/canonical.md §11.4) ───────────────────

fn test_diff_map_reordered_is_empty() {
	a := "[r {alpha: 1, beta: 2}]"
	b := "[r {beta: 2, alpha: 1}]"
	ch := cx.cx_text_diff(a, b) or { panic(err) }
	assert ch.len == 0, 'expected no changes; got ${ch.map(it.path + " " + it.before + " -> " + it.after)}'
}

fn test_diff_array_value_change_detected() {
	a := '[r [1, 2, 3]]'
	b := '[r [1, 2, 4]]'
	ch := cx.cx_text_diff(a, b) or { panic(err) }
	assert ch.len >= 1, 'expected at least one change'
}

fn test_diff_seq_flatten_no_change() {
	// ((1, 2), 3) flattens to (1, 2, 3) at parse — diff sees them as
	// identical.
	a := '[r ((1, 2), 3)]'
	b := '[r (1, 2, 3)]'
	ch := cx.cx_text_diff(a, b) or { panic(err) }
	assert ch.len == 0
}
