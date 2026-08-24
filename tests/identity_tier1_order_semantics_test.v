module main

import cx

// #82 — Tier-1 (data) identity: type-driven order-semantics.
//
// Tier-1 identity = SHA-256 of the strict canonical bytes
// (canonical.md §1.4 / §1.2; store.md §2.1). Strict canonicalization is
// type-driven: UNORDERED constructs normalize (so they collide), ORDERED
// constructs are preserved (so order changes stay distinct), and
// presentation is stripped (so it never affects identity).
//
// Map-key normalization + sequence-flatten + array-vs-sequence distinctness
// are already proven in canonical_collections_test.v. This file pins the
// complementary #82 claims that file does NOT cover:
//   (1) sequence ITEM ORDER is significant   (ordered → distinct)
//   (2) array ITEM ORDER is significant       (ordered → distinct)
//   (3) element ATTRIBUTE ORDER is significant (ordered → distinct; attrs
//       are never an identity-normalization axis, canonical.md §1.4/§2.1)
//   (4) comments are excluded from identity    (presentation → collide)
// plus one map-normalization assertion so this file reads as a complete
// Tier-1 matrix.

fn h(src string) string {
	return cx.cx_text_hash(src) or { panic('hash failed for `${src}`: ${err}') }
}

// ── ordered constructs: order is part of identity ───────────────────────────

fn test_tier1_sequence_order_is_significant() {
	// (2, 1) and (1, 2) are different ordered sequences → different identity.
	assert h('[r (2, 1)]') != h('[r (1, 2)]'), 'sequence order must change the Tier-1 hash'
}

fn test_tier1_array_order_is_significant() {
	assert h('[r::int [3, 1, 2]]') != h('[r::int [1, 2, 3]]'), 'array order must change the Tier-1 hash'
}

fn test_tier1_attribute_order_is_significant() {
	// [rec a=1 b=2] and [rec b=2 a=1] differ only in attribute order.
	// Attributes are NOT a normalization axis (canonical.md §1.4/§2.1):
	// order is semantic, so identity must differ.
	assert h('[rec a=1 b=2]') != h('[rec b=2 a=1]'), 'attribute order must change the Tier-1 hash'
}

// ── unordered construct: order is NOT part of identity ───────────────────────

fn test_tier1_map_key_order_collides() {
	// Map keys normalize (lexicographic, §2.11.1) → reordering collides.
	assert h('[rec {b: 2, a: 1}]') == h('[rec {a: 1, b: 2}]'), 'map key order must NOT change the Tier-1 hash'
}

// ── presentation: stripped from identity ─────────────────────────────────────

fn test_tier1_comments_excluded_from_identity() {
	with_comment := '[; identity ignores comments ;]
[rec a=1]'
	without_comment := '[rec a=1]'
	assert h(with_comment) == h(without_comment), 'comments must NOT change the Tier-1 hash'
}

// ── guard: the distinct cases are genuinely distinct documents, not a
//    canonicalization error masquerading as a hash (both sides must hash). ───

fn test_tier1_distinct_pairs_are_well_formed() {
	pairs := [
		['[r (2, 1)]', '[r (1, 2)]'],
		['[r::int [3, 1, 2]]', '[r::int [1, 2, 3]]'],
		['[rec a=1 b=2]', '[rec b=2 a=1]'],
	]
	for p in pairs {
		assert h(p[0]).len == 73, 'expected tagged sha2-256 (73 chars) for `${p[0]}`'
		assert h(p[1]).len == 73, 'expected tagged sha2-256 (73 chars) for `${p[1]}`'
	}
}
