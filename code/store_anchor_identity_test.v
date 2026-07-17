module code

import cx

// Tier-1 anchor/alias/merge expansion (#82, spec/core/canonical.md §2.8) seen
// through a LIVE [$store] consumer: the store keys docs on the strict canonical
// hash, so two documents that differ only in data-sharing (inline vs
// anchored/merged) get the SAME store-key and dedup to one logical doc. This is
// the store-level proof that §2.8 resolution is on the store's identity path.

fn sa_put_text(handle cx.Node, text string) string {
	r := store_stdlib_builtin_inner('store-put-doc-text', [handle, store_str(text)]) or {
		panic('put-doc-text: ${err.msg()}')
	}
	if is_err_value(r) {
		panic('put-doc-text returned error: ${csrp_err_code(r)}')
	}
	return csrp_scalar(r)
}

fn test_store_alias_equivalent_to_inline() {
	handle := store_open_impl('mem://anchor-id', '', '', false, true, map[string]string{})
	aliased := '[root [defaults &def timeout=30 retries=3] [*def]]'
	inline := '[root [defaults timeout=30 retries=3] [defaults timeout=30 retries=3]]'

	h_alias := sa_put_text(handle, aliased)
	h_inline := sa_put_text(handle, inline)
	assert h_alias == h_inline, 'an aliased doc must share the store-key of its inlined form (${h_alias} vs ${h_inline})'

	// The second put was a content-addressed no-op: exactly one logical doc.
	mut ms, _, ok := store_get_open(handle)
	assert ok, 'store handle must resolve'
	assert ms.doc_order.len == 1, 'alias-equivalent puts must dedup to one doc, got ${ms.doc_order.len}'
}

fn test_store_merge_equivalent_to_inline() {
	handle := store_open_impl('mem://anchor-id-merge', '', '', false, true, map[string]string{})
	merged := '[root [defaults &def timeout=30 retries=3] [production *def host=prod retries=5]]'
	inline := '[root [defaults timeout=30 retries=3] [production timeout=30 retries=5 host=prod]]'

	assert sa_put_text(handle, merged) == sa_put_text(handle, inline), 'a merged doc must share the store-key of its inlined form'
}

fn test_store_anchor_doc_round_trips() {
	handle := store_open_impl('mem://anchor-rt', '', '', false, true, map[string]string{})
	h := sa_put_text(handle, '[root [defaults &def timeout=30] [*def]]')
	r := store_stdlib_builtin_inner('store-get-doc-text', [handle, store_str(h)]) or {
		panic('get-doc-text: ${err.msg()}')
	}
	assert r is cx.ScalarNode, 'stored anchored doc must round-trip'
	got := csrp_scalar(r)
	// The reconstructed doc is the resolved (anchor-free) form.
	assert !got.contains('&def'), 'round-trip must be the resolved form: ${got}'
	assert !got.contains('[*def]'), 'round-trip must be the resolved form: ${got}'
}
