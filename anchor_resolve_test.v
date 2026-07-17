module cx

// Strict-canonical anchor/alias/merge expansion (spec/core/canonical.md §2.8,
// Tier-1 completion #82). The lossless form preserves &/*/[*]; the STRICT form
// (cx_text_canonical / cx_text_hash / cx_text_eq) must expand them so that two
// documents differing only in how they share data have identical Tier-1 bytes.

fn test_alias_expands_to_anchored_content() {
	src := '[root [defaults &def timeout=30 retries=3] [*def]]'
	got := cx_text_canonical(src) or {
		assert false, 'canonical: ${err}'
		return
	}
	// No anchor/alias/merge structure survives strict canonical.
	assert !got.contains('&def'), 'anchor must be stripped: ${got}'
	assert !got.contains('[*def]'), 'alias must be expanded: ${got}'
	// The alias became a copy of the anchored element: the defaults element
	// (anchor-free) appears twice.
	assert got.count('[defaults timeout=30 retries=3]') == 2, got
}

fn test_alias_equivalent_to_inline() {
	aliased := '[root [defaults &def timeout=30 retries=3] [*def]]'
	inline := '[root [defaults timeout=30 retries=3] [defaults timeout=30 retries=3]]'
	eq := cx_text_eq(aliased, inline) or {
		assert false, 'eq: ${err}'
		return
	}
	assert eq, 'an aliased doc must be Tier-1-identical to its inlined form'
	ha := cx_text_hash(aliased) or { panic(err) }
	hi := cx_text_hash(inline) or { panic(err) }
	assert ha == hi, 'alias-equivalent docs must hash identically'
}

fn test_merge_inlines_with_host_override() {
	src := '[root [defaults &def timeout=30 retries=3] [production *def host=prod retries=5]]'
	got := cx_text_canonical(src) or {
		assert false, 'canonical: ${err}'
		return
	}
	assert !got.contains('*def'), 'merge ref must be inlined: ${got}'
	// base in anchor order (timeout, retries), host override in place (retries=5),
	// host-only appended (host=prod).
	assert got.contains('[production timeout=30 retries=5 host=prod]'), got
}

fn test_merge_equivalent_to_inline() {
	merged := '[root [defaults &def timeout=30 retries=3] [production *def host=prod retries=5]]'
	inline := '[root [defaults timeout=30 retries=3] [production timeout=30 retries=5 host=prod]]'
	eq := cx_text_eq(merged, inline) or {
		assert false, 'eq: ${err}'
		return
	}
	assert eq, 'a merged doc must be Tier-1-identical to its inlined form'
}

fn test_nested_anchor_inside_anchor() {
	// An anchored element whose body references another anchor; an alias to it
	// must expand fully (no residual alias).
	src := '[root [inner &i [leaf v=1]] [outer &o [*i]] [*o]]'
	got := cx_text_canonical(src) or {
		assert false, 'canonical: ${err}'
		return
	}
	assert !got.contains('[*'), 'all aliases must expand: ${got}'
	assert !got.contains('&'), 'all anchors must strip: ${got}'
	// Fully expanded: format-independent structural equivalence to the inlined form.
	inline := '[root [inner [leaf v=1]] [outer [inner [leaf v=1]]] [outer [inner [leaf v=1]]]]'
	eq := cx_text_eq(src, inline) or {
		assert false, 'eq: ${err}'
		return
	}
	assert eq, 'nested anchors must fully expand to the inlined form'
}

fn test_anchor_and_comment_stripped_from_identity() {
	withmeta := '[; a comment ;]\n[item &a v=42]'
	plain := '[item v=42]'
	eq := cx_text_eq(withmeta, plain) or {
		assert false, 'eq: ${err}'
		return
	}
	assert eq, 'comments + anchors are invisible to Tier-1'
}

fn test_dangling_alias_is_error() {
	if _ := cx_text_canonical('[root [*missing]]') {
		assert false, 'a dangling alias must be a hard canonical error'
	}
}

fn test_dangling_merge_is_noop_strip() {
	// L003 is warn-level: a merge to a missing anchor strips the ref, inlines
	// nothing — the host stands alone.
	got := cx_text_canonical('[root [production *missing host=prod]]') or {
		assert false, 'dangling merge must not error: ${err}'
		return
	}
	assert !got.contains('*missing'), 'dangling merge ref must be stripped: ${got}'
	assert got.contains('[production host=prod]'), got
}

fn test_cyclic_alias_is_error() {
	if _ := cx_text_canonical('[root [a &x [*x]]]') {
		assert false, 'a cyclic anchor reference must be a hard error'
	}
}
