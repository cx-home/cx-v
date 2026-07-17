module code

import cx
import cxstore

// store_introspection_test.v — #129-D: object-graph introspection (object_count
// + dedup ratio) surfaces through StoreStats / store_mount_stats and the
// /metrics exposition, ONLY for the content-addressed backend (no fabricated
// zeros for the flat backends), with the dedup walk cached against a mutation
// fingerprint.

fn ti_canon_hash(text string) (string, string) {
	doc := cx.parse(text) or { return text, '' }
	c := render_canonical(doc.elements[0])
	h := cx.cx_text_hash(c) or { return c, '' }
	return c, h
}

fn ti_put(mut ms MemStore, text string) {
	c, h := ti_canon_hash(text)
	store_put_canonical(mut ms, h, c) or { panic('put: ' + err.msg()) }
}

// a cxpack store reports object_count and a >1 dedup ratio once docs share
// subtrees; the engine-level stat walk distinguishes logical vs distinct.
fn test_objgraph_stats_object_count_and_dedup() {
	mut ms := &MemStore{
		backend: 'cxpack'
		root:    ''
		is_open: true
	}
	big := '[customer [name "Acme"] [addr [street "1 Main"] [city "NYC"] [zip "10001"]] [tags [t "a"] [t "b"] [t "c"]]]'
	ti_put(mut ms, '[order [id 1] ${big}]')
	ti_put(mut ms, '[order [id 2] ${big}]') // shares the whole `big` subtree

	stats := store_objgraph_stats(mut ms, ms.doc_order.len)
	assert stats.has_object_graph
	assert stats.object_count == ms.obj_sink.objects.len
	// two docs share a big subtree → logical (no-sharing) count strictly exceeds
	// the distinct objects actually stored → dedup ratio > 1.
	assert stats.logical_objects > i64(stats.distinct_objects), 'expected sharing: logical ${stats.logical_objects} vs distinct ${stats.distinct_objects}'
	assert stats.distinct_objects > 0
}

// the dedup walk is cached: a second stats call with no mutation in between does
// not change the cached fingerprint (and a mutation invalidates it).
fn test_objgraph_stats_cache_fingerprint() {
	mut ms := &MemStore{
		backend: 'cxpack'
		is_open: true
	}
	ti_put(mut ms, '[a [x 1]]')
	_ := store_objgraph_stats(mut ms, ms.doc_order.len)
	g_docs := ms.graph_stats_docs
	g_objs := ms.graph_stats_objects
	assert g_docs == 1
	// re-read with no mutation → fingerprint unchanged (cache hit).
	_ = store_objgraph_stats(mut ms, ms.doc_order.len)
	assert ms.graph_stats_docs == g_docs && ms.graph_stats_objects == g_objs

	// a mutation moves the fingerprint → next read recomputes.
	ti_put(mut ms, '[b [y 2]]')
	s2 := store_objgraph_stats(mut ms, ms.doc_order.len)
	assert ms.graph_stats_docs == 2
	assert s2.object_count > g_objs
}

// engine-level: object_graph_stats counts logical (with multiplicity) vs distinct.
fn test_object_graph_stats_engine() {
	mut sink := cxstore.ObjectSink{}
	doc := cx.parse('[order [id 1] [a [k "v"]] [a [k "v"]]]') or { panic('parse') }
	root := cxstore.store_document(mut sink, doc, cxstore.default_fanout)
	getter := fn [sink] (h []u8) ?[]u8 {
		return sink.get(h)
	}
	logical, distinct := cxstore.object_graph_stats(getter, [root])
	// the two identical `[a [k "v"]]` children collapse to one object set →
	// logical (counts both) strictly exceeds distinct (stores them once).
	assert logical > i64(distinct), 'logical ${logical} should exceed distinct ${distinct} given repeated subtree'
	assert distinct > 0
}

// /metrics: cxpack emits cxstore_store_objects + cxstore_store_dedup_ratio; the
// flat mem backend emits ONLY docs — no object-graph series (no fabricated zeros).
fn test_metrics_objgraph_series_gated_by_backend() {
	// cxpack mount registered directly (bypasses cap_guard, like the other
	// engine-level cxpack tests).
	mut cp := &MemStore{
		backend: 'cxpack'
		is_open: true
	}
	ti_put(mut cp, '[doc [x 1] [y 2]]')
	cp_id := store_register(cp)
	cp_handle := store_handle_element(cp_id, cp)

	// a flat (document-model) mount — file:// keeps the flat index, so it must emit
	// the docs gauge but NO object-graph series (mem is now the subtree model, so
	// file:// is the genuine flat example here).
	mut flat := &MemStore{
		backend: 'file'
		is_open: true
	}
	flat.docs['h1'] = '[a 1]'
	flat.doc_order << 'h1'
	flat_id := store_register(flat)
	flat_handle := store_handle_element(flat_id, flat)

	out := svc_store_internal_metrics({
		'graph': cp_handle
		'flat':  flat_handle
	})
	// docs gauge for both
	assert out.contains('cxstore_store_docs{store="graph",backend="cxpack"}'), out
	assert out.contains('cxstore_store_docs{store="flat",backend="file"}'), out
	// object-graph series ONLY for the cxpack mount
	assert out.contains('cxstore_store_objects{store="graph",backend="cxpack"}'), out
	assert out.contains('cxstore_store_dedup_ratio{store="graph",backend="cxpack"}'), out
	assert !out.contains('store="flat"') || !out.contains('cxstore_store_objects{store="flat"'), 'flat backend must not emit object-graph series (no fabricated zeros): ${out}'
	assert !out.contains('cxstore_store_objects{store="flat"'), out
	assert !out.contains('cxstore_store_dedup_ratio{store="flat"'), out
}
