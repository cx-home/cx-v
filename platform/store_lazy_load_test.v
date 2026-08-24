module platform
import code {
	caps_set_all,
	is_err_value,
	render_canonical,
}

import cx
import os

// store_lazy_load_test.v — #637: demand-paged object resolution. Opening a
// cxpack store populates only the REFS layer; objects page in on first touch
// through the self-verifying composite getter (so corruption still refuses
// loudly at that touch), and the exhaustive whole-graph check moves to the
// explicit `verify` op.

fn slz_root(tag string) string {
	p := os.join_path(os.temp_dir(), 'cx-lazy-${tag}-${os.getpid()}')
	os.rmdir_all(p) or {}
	os.mkdir_all(p) or { panic('mkdir ${p}: ${err}') }
	return p
}

fn slz_put(h cx.Node, text string) string {
	r := store_stdlib_builtin_inner('store-put-doc-text', [h, store_str(text)]) or {
		panic('put: ${err.msg()}')
	}
	assert !is_err_value(r), 'put must succeed: ${render_canonical(r)}'
	return sw_scalar(r)
}

fn test_lazy_open_pages_objects_on_first_touch() {
	caps_set_all()
	root := slz_root('page')
	defer {
		os.rmdir_all(root) or {}
	}
	// seed a store with several docs + an alias.
	w := store_open_impl('file://${root}', '', '', false, true, map[string]string{})
	assert !is_err_value(w), 'open: ${render_canonical(w)}'
	mut keys := []string{}
	for i in 1 .. 6 {
		keys << slz_put(w, '[doc n=${i} [body "payload ${i}"]]')
	}
	a := store_stdlib_builtin_inner('store-set-alias', [w, store_str('head'), store_str(keys[4])]) or {
		panic('alias')
	}
	assert !is_err_value(a), 'set-alias: ${render_canonical(a)}'
	store_stdlib_builtin_inner('store-close', [w]) or { panic('close') }

	// LAZY reopen (the default): the sink starts EMPTY — no whole-graph slurp —
	// while the refs layer is fully replayed.
	h := store_open_impl('file://${root}', '', '', false, true, map[string]string{})
	assert !is_err_value(h), 'reopen: ${render_canonical(h)}'
	ms := store_for_guard(h) or { panic('guard') }
	assert ms.lazy_objects, 'lazy is the default for a cxpack store'
	assert ms.obj_sink.objects.len == 0, 'a lazy open must NOT slurp the graph (sink holds ${ms.obj_sink.objects.len})'
	assert ms.doc_order.len == 5, 'the refs layer is fully replayed: ${ms.doc_order.len} docs'
	// the alias replay needed its NAME object — paged in, not slurped.
	ga := store_stdlib_builtin_inner('store-get-alias', [h, store_str('head')]) or { panic('get-alias') }
	assert sw_scalar(ga) == keys[4], 'alias resolves after a lazy open: ${render_canonical(ga)}'

	// first touch pages the doc in and returns it byte-identically.
	before := ms.obj_cache.len
	g := store_stdlib_builtin_inner('store-get-doc-text', [h, store_str(keys[0])]) or {
		panic('get: ${err.msg()}')
	}
	assert !is_err_value(g), 'paged read: ${render_canonical(g)}'
	assert sw_scalar(g).contains('payload 1'), 'paged read content: ${sw_scalar(g)}'
	ms2 := store_for_guard(h) or { panic('guard2') }
	assert ms2.obj_cache.len > before, 'the first touch must page objects into the cache'
	// the working set is what is resident — NOT the whole graph.
	assert ms2.obj_sink.objects.len == 0, 'paged reads must not enter the flush sink (watermark safety)'

	// a WRITE after lazy reads flushes only its own delta — the paged-in
	// objects are already durable and must not be re-persisted.
	k6 := slz_put(h, '[doc n=6 [body "payload 6"]]')
	fr := store_stdlib_builtin_inner('store-get-doc-text', [h, store_str(k6)]) or { panic('get6') }
	assert sw_scalar(fr).contains('payload 6'), 'write-after-lazy-read round trip'
	store_stdlib_builtin_inner('store-close', [h]) or { panic('close2') }

	// everything survives the round trip: reopen and read every doc.
	h2 := store_open_impl('file://${root}', '', '', false, true, map[string]string{})
	for i, k in keys {
		r := store_stdlib_builtin_inner('store-get-doc-text', [h2, store_str(k)]) or {
			panic('reread ${i}')
		}
		assert sw_scalar(r).contains('payload ${i + 1}'), 'doc ${i + 1} survived: ${sw_scalar(r)}'
	}
	r6 := store_stdlib_builtin_inner('store-get-doc-text', [h2, store_str(k6)]) or { panic('reread 6') }
	assert sw_scalar(r6).contains('payload 6'), 'the post-lazy write survived the reopen'
}

fn test_verify_is_the_explicit_whole_graph_pass() {
	caps_set_all()
	root := slz_root('verify')
	defer {
		os.rmdir_all(root) or {}
	}
	w := store_open_impl('file://${root}', '', '', false, true, map[string]string{})
	for i in 1 .. 4 {
		slz_put(w, '[doc n=${i} [body "v${i}"]]')
	}
	store_stdlib_builtin_inner('store-close', [w]) or { panic('close') }

	h := store_open_impl('file://${root}', '', '', false, true, map[string]string{})
	v := store_stdlib_builtin_inner('store-verify', [h]) or { panic('verify: ${err.msg()}') }
	assert !is_err_value(v), 'verify must pass on a sound store: ${render_canonical(v)}'
	rendered := render_canonical(v)
	assert rendered.contains('valid=true'), 'verification shape: ${rendered}'
	assert rendered.contains('docs=3'), 'verify walks every live doc: ${rendered}'
	store_stdlib_builtin_inner('store-close', [h]) or { panic('close2') }
}

// An EAGER open still does the whole-graph reconstruction inline — the opt-out
// for a caller that wants the check at open rather than on demand.
fn test_eager_open_opt_out_still_slurps() {
	caps_set_all()
	root := slz_root('eager')
	defer {
		os.rmdir_all(root) or {}
	}
	w := store_open_impl('file://${root}', '', '', false, true, map[string]string{})
	slz_put(w, '[doc n=1 [body "eager"]]')
	store_stdlib_builtin_inner('store-close', [w]) or { panic('close') }

	h := store_open_impl('file://${root}', '', '', false, true, {
		'eager': 'true'
	})
	assert !is_err_value(h), 'eager reopen: ${render_canonical(h)}'
	ms := store_for_guard(h) or { panic('guard') }
	assert !ms.lazy_objects, 'eager=true opts out of demand paging'
	assert ms.obj_sink.objects.len > 0, 'an eager open loads the graph at open'
	store_stdlib_builtin_inner('store-close', [h]) or { panic('close2') }
}

// #662 regression guard: the demand-paged getter must page via the object-
// location index — every durable object gets an obj_where entry at seed (lazy
// open), load (eager open), and flush (new segment). Without the index every
// first touch re-scanned the pack directory and probed every pack (the 33x
// embedded-ingest collapse). Structural, not timed: index coverage == durable
// object count across multi-segment stores and reopens.
fn test_pack_location_index_covers_every_durable_object() {
	caps_set_all()
	root := slz_root('where')
	defer {
		os.rmdir_all(root) or {}
	}
	// Three puts on one handle → per-put flushes → multiple segment packs.
	w := store_open_impl('file://${root}', '', '', false, true, map[string]string{})
	slz_put(w, '[doc n=1 [body "a"]]')
	slz_put(w, '[doc n=2 [body "b"]]')
	slz_put(w, '[doc n=3 [body "c"]]')
	wms := store_for_guard(w) or { panic('guard w') }
	assert wms.obj_pack.located_count() == wms.obj_pack.object_count() - wms.obj_pack.pending_count(), 'flush indexes every durable object: located=${wms.obj_pack.located_count()} durable=${wms.obj_pack.object_count() - wms.obj_pack.pending_count()}'
	store_stdlib_builtin_inner('store-close', [w]) or { panic('close w') }

	// Lazy reopen: seed_index fills the index without reading payloads.
	h := store_open_impl('file://${root}', '', '', false, true, map[string]string{})
	ms := store_for_guard(h) or { panic('guard') }
	assert ms.lazy_objects, 'cxpack opens lazy by default'
	assert ms.obj_pack.located_count() > 0, 'seed_index fills the location index'
	assert ms.obj_pack.located_count() == ms.obj_pack.object_count(), 'lazy open: located=${ms.obj_pack.located_count()} vs objects=${ms.obj_pack.object_count()}'
	store_stdlib_builtin_inner('store-close', [h]) or { panic('close') }

	// Eager reopen: load_objects fills it too (verify et al. still page).
	e := store_open_impl('file://${root}', '', '', false, true, {
		'eager': 'true'
	})
	ems := store_for_guard(e) or { panic('guard e') }
	assert ems.obj_pack.located_count() == ems.obj_pack.object_count(), 'eager open: located=${ems.obj_pack.located_count()} vs objects=${ems.obj_pack.object_count()}'
	store_stdlib_builtin_inner('store-close', [e]) or { panic('close e') }
}
