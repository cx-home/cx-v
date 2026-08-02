module code

import cx
import cxstore
import os
import sync
import time

// store_cxpack_fold_test.v — #617 behavioral evidence that the #603 size-tiered
// segment fold runs OFF the flush turn without changing what a reader observes:
// a LOCKED store's folds land via the background worker and converge to the
// same logarithmic segment bound, everything reloads identically, and a fold
// plan overtaken by a compaction abandons cleanly (generation guard) instead of
// clobbering the fresh segment set.

fn cf_root(tag string) string {
	return os.join_path(os.temp_dir(), 'cxpack_fold_${tag}_${os.getpid()}')
}

fn cf_new(root string) &MemStore {
	return &MemStore{
		url:     'file://${root}'
		backend: 'cxpack'
		root:    root
		is_open: true
		op_lock: sync.new_mutex()
	}
}

fn cf_put(mut ms MemStore, text string) string {
	doc := cx.parse(text) or { panic('parse: ${text}') }
	c := render_canonical(doc.elements[0])
	h := cx.cx_text_hash(c) or { panic('hash') }
	store_lock_enter(mut ms)
	store_put_canonical(mut ms, h, c) or { panic('put: ' + err.msg()) }
	store_cxpack_flush(mut ms) or { panic('flush: ${err.msg()}') }
	store_lock_exit(mut ms)
	return h
}

// cf_quiesce waits (bounded) until no fold is running or pending — the async
// worker owns no completion signal by design (folding is amortization, not
// durability), so tests converge by polling under the lock.
fn cf_quiesce(mut ms MemStore) {
	for _ in 0 .. 2000 {
		store_lock_enter(mut ms)
		done := !ms.fold_running && !ms.obj_pack.fold_pending()
		store_lock_exit(mut ms)
		if done {
			return
		}
		time.sleep(5 * time.millisecond)
	}
	panic('background segment folds did not quiesce within the deadline')
}

fn cf_seg_files(root string) int {
	mut n := 0
	for e in os.ls(root) or { []string{} } {
		if cxpack_seg_index(e) >= 0 {
			n++
		}
	}
	return n
}

// A LOCKED store (the shape every opened store has) folds via the background
// worker: many appends still converge to a logarithmic segment-file count, the
// backend bookkeeping matches the disk, and every doc reloads byte-identically
// from the folded segments.
fn test_background_fold_converges_and_reloads() {
	root := cf_root('async')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	mut ms := cf_new(root)
	mut hashes := []string{}
	for i in 0 .. 3 * cxpack_compact_segments {
		hashes << cf_put(mut ms, '[rec [id ${i}] [v "val-${i}"]]')
	}
	cf_quiesce(mut ms)

	assert !os.exists(os.join_path(root, cxpack_pack)), 'append-only store must not pay the O(live) full compaction'
	segs := cf_seg_files(root)
	assert segs > 0 && segs < 8, 'background tier fold should bound ${3 * cxpack_compact_segments} appends to a few segment files (found ${segs})'
	store_lock_enter(mut ms)
	live := ms.obj_pack.live_segments()
	store_lock_exit(mut ms)
	assert live == segs, 'backend live-segment bookkeeping out of step with the files on disk'

	mut ms2 := cf_new(root)
	store_cxpack_load(mut ms2) or { panic('load: ' + err.msg()) }
	assert ms2.doc_order.len == hashes.len, 'doc count changed across background-fold reload'
	for i, h in hashes {
		assert (store_doc_text(ms2, h) or { '' }) == "[rec [id ${i}] [v 'val-${i}']]", 'doc ${h} wrong after background-fold reload'
	}
}

// A fold plan whose I/O was overtaken by a compaction must ABANDON at commit
// (generation guard): the merged temp is discarded, the fresh segment set is
// untouched, and the store reloads whole. Driven synchronously through the
// backend primitives so the race window is deterministic.
fn test_fold_commit_abandons_after_compaction_reset() {
	dir := cf_root('genabort')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
	}
	mut be := cxstore.open_pack_object_backend(dir)
	mut payloads := [][]u8{}
	// two same-size segments → a due fold
	for i in 0 .. 2 {
		p := 'fold-abort-payload-${i}'.bytes()
		payloads << p
		_ := be.put_object(p) or { panic('put: ${err}') }
		be.flush_segment() or { panic('flush: ${err}') }
	}
	plan := be.fold_plan() or { panic('a same-size segment pair must plan a fold') }
	merged := cxstore.fold_perform(plan) or { panic('perform: ${err}') }
	assert merged == 2

	// the compaction wins the race: generation bumps, segments are replaced
	be.write_compacted(payloads) or { panic('compact: ${err}') }
	committed := be.fold_commit(plan, merged) or { panic('commit: ${err}') }
	assert !committed, 'a fold planned under an older generation must abandon at commit'
	assert !os.exists(plan.tmp), 'an abandoned fold must discard its merged temp'
	assert be.live_segments() == 0, 'an abandoned fold must not touch the compacted segment set'

	mut be2 := cxstore.open_pack_object_backend(dir)
	objs := be2.load_objects() or { panic('reload: ${err}') }
	assert objs.len == 2, 'both objects must survive in the compacted pack (found ${objs.len})'
}

// The ratio guard (#617): a small tier stranded below a much larger newer one
// must NOT plan a fold — bare prev<=cur would license an O(big) rewrite for an
// O(1) gain on every batch (the measured async pathology). Folding proceeds
// normally ABOVE the stranded tier and converges without ever touching it.
fn test_fold_plan_skips_disproportionate_pair() {
	dir := cf_root('ratio')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
	}
	mut be := cxstore.open_pack_object_backend(dir)
	// sizes [1, 4]: prev <= cur but 1*2 < 4 — stranded, never folded.
	sizes := [1, 4]
	for si, n in sizes {
		for i in 0 .. n {
			_ := be.put_object('ratio-${si}-${i}'.bytes()) or { panic('put: ${err}') }
		}
		be.flush_segment() or { panic('flush: ${err}') }
	}
	assert !be.fold_pending(), 'a >2x disproportionate pair must not plan a fold'
	assert be.live_segments() == 2

	// appends above the stranded tier still tier normally: [1,4] + 3 + 3 →
	// (3,3) folds to 6, (4,6) folds to 10, (1,10) stays stranded.
	for si, n in [3, 3] {
		for i in 0 .. n {
			_ := be.put_object('ratio-above-${si}-${i}'.bytes()) or { panic('put: ${err}') }
		}
		be.flush_segment() or { panic('flush: ${err}') }
	}
	be.fold_drain() or { panic('drain: ${err}') }
	assert be.live_segments() == 2, 'tiers above a stranded segment must still fold (found ${be.live_segments()})'
	assert !be.fold_pending()
	assert be.object_count() == 11
}

// fold_drain (the lockless/inline driver) pairs by SIZE, not by position:
// the equal smalls fold first wherever they sit, and the merge then earns its
// fold with the bigger tier (2+2 → 4, then 4+4 within ratio) — converging to
// one segment with every object still resolvable.
fn test_fold_drain_pairs_by_size_and_converges() {
	dir := cf_root('bysize')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
	}
	mut be := cxstore.open_pack_object_backend(dir)
	mut keys := [][]u8{}
	sizes := [4, 1, 1]
	for si, n in sizes {
		for i in 0 .. n {
			k := be.put_object('bysize-${si}-${i}'.bytes()) or { panic('put: ${err}') }
			keys << k
		}
		be.flush_segment() or { panic('flush: ${err}') }
	}
	assert be.live_segments() == 3
	be.fold_drain() or { panic('drain: ${err}') }
	assert be.live_segments() == 1, 'size-paired drain must converge [4,1,1] → [2,4] → [6] (found ${be.live_segments()} segments)'
	assert !be.fold_pending()
	for k in keys {
		if _ := be.get_object(k) {
		} else {
			panic('object ${k.hex()} unresolvable after folds')
		}
	}
}
