module code

// #79 — content-addressed code storage (pre-Phase-1 floor). Stored in-module
// because MemStore is module-internal. Proves: storing two Tier-2-equivalent
// definitions dedups to ONE object, retrievable by the Tier-2 hash; distinct
// computations stay separate.

fn new_code_store() MemStore {
	return MemStore{
		url:       'mem://code'
		backend:   'mem'
		is_open:   true
		docs:      map[string]string{}
		doc_order: []string{}
	}
}

fn test_code_store_dedups_alpha_and_name_variants() {
	mut ms := new_code_store()
	// alpha + name variant of the same computation
	a := '[?def f (\$x) [+ \$x 1]]'
	b := '[?def g (\$y) [+ \$y 1]]'
	ha := cx_code_store_put_def(mut ms, a) or { panic(err) }
	hb := cx_code_store_put_def(mut ms, b) or { panic(err) }
	assert ha == hb, 'alpha/name variants must share one Tier-2 identity'
	// mem is now the subtree object-graph model — code defs are keyed in doc_order
	// (the flat docs map stays empty). Dedup is observed as one stored entry.
	assert ms.doc_order.len == 1, 'variants must dedup to ONE stored object; got ${ms.doc_order.len}'
	got := cx_code_store_get_def(ms, ha) or { panic('stored def not retrievable by Tier-2 hash') }
	assert got == a, 'first representative must round-trip'
}

fn test_code_store_keeps_distinct_definitions() {
	mut ms := new_code_store()
	cx_code_store_put_def(mut ms, '[?def f (\$x) [+ \$x 1]]') or { panic(err) }
	cx_code_store_put_def(mut ms, '[?def f (\$x) [+ \$x 2]]') or { panic(err) }
	assert ms.doc_order.len == 2, 'different computations must be distinct objects; got ${ms.doc_order.len}'
}

fn test_code_store_get_absent_is_none() {
	ms := new_code_store()
	if _ := cx_code_store_get_def(ms, 'deadbeef') {
		assert false, 'absent code hash must return none'
	}
}

fn test_code_store_namespace_distinct_from_tier1() {
	// The code namespace uses a `code:` key prefix so it never collides with a
	// Tier-1 data doc stored under a bare hash.
	mut ms := new_code_store()
	h := cx_code_store_put_def(mut ms, '[?def f (\$x) [+ \$x 1]]') or { panic(err) }
	assert 'code:${h}' in ms.obj_roots
	assert h !in ms.obj_roots, 'code key must be namespaced, not a bare Tier-1-style hash key'
}
