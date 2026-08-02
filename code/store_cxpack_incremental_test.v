module code

import cx
import cxstore
import os

// store_cxpack_incremental_test.v — #129-B behavioral evidence that cxpack://
// persists INCREMENTALLY: each mutation flushes only the delta (new objects to a
// fresh segment pack, new/removed manifest entries appended/tombstoned), the
// store reloads correctly across many segments, deletes survive a reload, and
// accumulated segments compact back into one pack — all without changing what a
// reader observes.

fn ci_canon_hash(text string) (string, string) {
	doc := cx.parse(text) or { return text, '' }
	c := render_canonical(doc.elements[0])
	h := cx.cx_text_hash(c) or { return c, '' }
	return c, h
}

fn ci_root(tag string) string {
	return os.join_path(os.temp_dir(), 'cxpack_inc_${tag}_${os.getpid()}')
}

fn ci_new(root string) &MemStore {
	return &MemStore{
		url:     'file://${root}'
		backend: 'cxpack'
		root:    root
		is_open: true
	}
}

// a put that mirrors the real mutation hook: stage into the live graph, then
// flush the delta (store_persist routes here for cxpack).
fn ci_put(mut ms MemStore, text string) string {
	c, h := ci_canon_hash(text)
	store_put_canonical(mut ms, h, c) or { panic('put: ' + err.msg()) }
	store_cxpack_flush(mut ms) or { panic('flush: ${err.msg()}') }
	return h
}

fn ci_seg_count(root string) int {
	mut n := 0
	for e in os.ls(root) or { []string{} } {
		if cxpack_seg_index(e) >= 0 {
			n++
		}
	}
	return n
}

// Each incremental put writes a separate segment, and a one-field-different doc's
// segment holds only the delta objects (structural sharing across flushes — the
// core O(delta) property the snapshot model lacked). Everything reloads.
fn test_incremental_segments_and_delta() {
	root := ci_root('delta')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	big := '[customer [name "Acme"] [addr [street "1 Main"] [city "NYC"] [zip "10001"]] [tags [t "a"] [t "b"] [t "c"]]]'
	mut ms := ci_new(root)
	h1 := ci_put(mut ms, '[order [id 1] ${big}]')
	assert ci_seg_count(root) == 1, 'first put should write one segment'
	seg0 := cxstore.open_pack(os.join_path(root, cxpack_seg_name(0))) or {
		panic('open seg0: ' + err.msg())
	}
	n0 := seg0.hashes().len

	h2 := ci_put(mut ms, '[order [id 2] ${big}]') // shares the whole `big` subtree
	assert ci_seg_count(root) == 2, 'second put should write a second segment'
	seg1 := cxstore.open_pack(os.join_path(root, cxpack_seg_name(1))) or {
		panic('open seg1: ' + err.msg())
	}
	n1 := seg1.hashes().len
	assert n1 > 0 && n1 < n0, 'delta segment (${n1}) must be smaller than the full first doc (${n0}) — shared subtree not re-stored'

	// reload across BOTH segments: both docs reconstruct byte-identically.
	mut ms2 := ci_new(root)
	store_cxpack_load(mut ms2) or { panic('load: ' + err.msg()) }
	assert ms2.doc_order == [h1, h2], 'order/contents changed across multi-segment reload'
	// reconstruct byte-identically to the live (pre-reload) canonical text.
	assert (store_doc_text(ms2, h1) or { '' }) == (store_doc_text(ms, h1) or { 'x' })
	assert (store_doc_text(ms2, h2) or { '' }) == (store_doc_text(ms, h2) or { 'x' })
}

// A deleted doc is tombstoned in the append-only manifest and is GONE after a
// reload, while the surviving docs remain intact (no whole-store rewrite needed).
fn test_incremental_delete_tombstone_survives_reload() {
	root := ci_root('del')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	mut ms := ci_new(root)
	h1 := ci_put(mut ms, '[a [x 1]]')
	h2 := ci_put(mut ms, '[b [y 2]]')
	h3 := ci_put(mut ms, '[c [z 3]]')

	store_delete_local(mut ms, h2)
	store_cxpack_flush(mut ms) or { panic('flush: ${err.msg()}') } // appends a 'T' tombstone

	mut ms2 := ci_new(root)
	store_cxpack_load(mut ms2) or { panic('load: ' + err.msg()) }
	assert ms2.doc_order == [h1, h3], 'deleted doc must not reappear after reload (got ${ms2.doc_order})'
	assert store_doc_present(ms2, h1)
	assert !store_doc_present(ms2, h2), 'tombstoned doc is data loss if it reloads'
	assert store_doc_present(ms2, h3)
}

// #603 scan-cursor alignment: deleting a doc BELOW the flush scan cursor shifts
// doc_order left — a doc put afterwards must still reach the manifest (a
// misaligned cursor would silently skip it: data loss on reload).
fn test_incremental_delete_below_cursor_then_put() {
	root := ci_root('cursor')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	mut ms := ci_new(root)
	h1 := ci_put(mut ms, '[a [x 1]]')
	h2 := ci_put(mut ms, '[b [y 2]]') // cursor now sits past both docs
	// delete below the cursor and stage a NEW doc before any flush: the put
	// lands at an index the stale cursor would already have covered.
	store_delete_local(mut ms, h1)
	c3, h3 := ci_canon_hash('[c [z 3]]')
	store_put_canonical(mut ms, h3, c3) or { panic('put: ' + err.msg()) }
	store_cxpack_flush(mut ms) or { panic('flush: ${err.msg()}') }

	mut ms2 := ci_new(root)
	store_cxpack_load(mut ms2) or { panic('load: ' + err.msg()) }
	assert ms2.doc_order == [h2, h3], 'doc put after a below-cursor delete must survive reload (got ${ms2.doc_order})'
	assert store_doc_present(ms2, h3), 'post-delete put lost — scan cursor misaligned'
}

// Alias set / update / delete are all carried incrementally (A records +
// last-write-wins, X tombstone) and reload to the final live state.
fn test_incremental_alias_lifecycle() {
	root := ci_root('alias')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	mut ms := ci_new(root)
	h1 := ci_put(mut ms, '[a [x 1]]')
	h2 := ci_put(mut ms, '[b [y 2]]')

	// set, then update, then a second alias, then delete the first — through the
	// #603 mutation seam (direct map pokes bypass the O(delta) flush discovery).
	store_alias_set_local(mut ms, 'latest', h1)
	store_cxpack_flush(mut ms) or { panic('flush: ${err.msg()}') }
	store_alias_set_local(mut ms, 'latest', h2) // update → new 'A' record (last-write-wins)
	store_cxpack_flush(mut ms) or { panic('flush: ${err.msg()}') }
	store_alias_set_local(mut ms, 'pinned', h1)
	store_cxpack_flush(mut ms) or { panic('flush: ${err.msg()}') }
	assert store_alias_delete_local(mut ms, 'pinned')
	store_cxpack_flush(mut ms) or { panic('flush: ${err.msg()}') }

	mut ms2 := ci_new(root)
	store_cxpack_load(mut ms2) or { panic('load: ' + err.msg()) }
	assert ms2.aliases['latest'] == h2, 'alias update lost across reload'
	assert 'pinned' !in ms2.aliases, 'deleted alias must not reload'
	assert ms2.alias_order == ['latest'], 'alias order wrong after reload (${ms2.alias_order})'
}

// #603: garbage-free appends never trip the O(live) full compaction — the
// size-tiered segment fold (binary counter over segment sizes) keeps the live
// segment-file count logarithmic instead, and everything reloads identically
// from the folded segments.
fn test_incremental_append_only_tiers_segments_no_full_compaction() {
	root := ci_root('compact')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	mut ms := ci_new(root)
	mut hashes := []string{}
	// well past the old every-16-segments threshold: 3× worth of appends.
	for i in 0 .. 3 * cxpack_compact_segments {
		hashes << ci_put(mut ms, '[rec [id ${i}] [v "val-${i}"]]')
	}
	// no garbage → no full compaction: the single store.cxpack never appears...
	assert !os.exists(os.join_path(root, cxpack_pack)), 'append-only store must not pay the O(live) full compaction'
	// ...and tiered folding keeps the segment-file count far below one-per-append.
	segs := ci_seg_count(root)
	assert segs > 0 && segs < 8, 'size-tiered fold should bound ${3 * cxpack_compact_segments} appends to a few segment files (found ${segs})'
	assert ms.obj_pack.live_segments() == segs, 'backend live-segment bookkeeping out of step with the files on disk'

	mut ms2 := ci_new(root)
	store_cxpack_load(mut ms2) or { panic('load: ' + err.msg()) }
	assert ms2.doc_order.len == hashes.len, 'doc count changed across tiered-fold reload'
	for i, h in hashes {
		// canonical renders quoted scalars with single quotes.
		assert (store_doc_text(ms2, h) or { '' }) == "[rec [id ${i}] [v 'val-${i}']]", 'doc ${h} wrong after tiered-fold reload'
	}
}

// Compaction reclaims objects no longer reachable from any live doc (GC): after
// deleting a doc whose subtree is unique, a compaction drops its objects.
fn test_compaction_reclaims_unreferenced_objects() {
	root := ci_root('gc')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	mut ms := ci_new(root)
	keep := ci_put(mut ms, '[keep [k 1]]')
	doomed := ci_put(mut ms,
		'[doomed [big "a-unique-subtree-not-shared-with-keep"] [more [deep "x"]]]')
	store_delete_local(mut ms, doomed)
	store_cxpack_flush(mut ms) or { panic('flush: ${err.msg()}') }

	before := ms.obj_sink.objects.len
	store_cxpack_compact(mut ms) or { panic('compact: ${err.msg()}') }
	after := ms.obj_sink.objects.len
	assert after < before, 'compaction must reclaim the deleted doc objects (before ${before}, after ${after})'

	// the kept doc still reloads; the doomed one stays gone.
	mut ms2 := ci_new(root)
	store_cxpack_load(mut ms2) or { panic('load: ' + err.msg()) }
	assert store_doc_present(ms2, keep)
	assert !store_doc_present(ms2, doomed)
	assert (store_doc_text(ms2, keep) or { '' }) == '[keep [k 1]]'
}
