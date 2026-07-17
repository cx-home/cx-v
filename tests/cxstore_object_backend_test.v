module main

import cx
import cxstore
import os

// cxstore_object_backend_test.v — #129-E / #76: the object-level storage seam.
// Proves the subtree object graph is no longer tied to local packs: a document
// content-addressed by the engine can be persisted into and reconstructed from an
// object-per-key substrate (DirObjectBackend — the local analog of an S3/daemon
// backend), and the SAME graph algorithms (reconstruct, GC mark, dedup
// introspection) run over it unchanged via getter_of().

fn tmp_dir(tag string) string {
	return os.join_path(os.temp_dir(), 'cxobjbe_${tag}_${os.getpid()}')
}

// a doc persisted into an object-per-key backend reconstructs byte-identically
// through the standard Getter-based reader.
fn test_object_backend_roundtrip() {
	dir := tmp_dir('rt')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
	}
	mut be := cxstore.open_dir_object_backend(dir) or { panic('open: ${err}') }
	doc := cx.parse('[order [id 1] [customer [name "Acme"] [addr [city "NYC"]]]]') or {
		panic('parse')
	}
	mut sink := cxstore.ObjectSink{}
	root := cxstore.store_document(mut sink, doc, cxstore.default_fanout)
	cxstore.persist_objects(mut be, sink) or { panic('persist: ${err}') }

	// reload via the backend's getter — the graph reader is unchanged.
	g := cxstore.getter_of(be)
	got := cxstore.load_document_from(g, root) or { panic('load: ${err}') }
	assert cx.emit_cx(got) == cx.emit_cx(doc), 'object-per-key reload not byte-identical'
}

// identical subtrees across documents collapse to one stored object (content
// dedup holds on the object-per-key substrate, not just in packs).
fn test_object_backend_dedup_across_docs() {
	dir := tmp_dir('dedup')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
	}
	mut be := cxstore.open_dir_object_backend(dir) or { panic('open: ${err}') }
	big := '[customer [name "Acme"] [addr [street "1 Main"] [city "NYC"]] [tags [t "a"] [t "b"]]]'

	mut s1 := cxstore.ObjectSink{}
	r1 := cxstore.store_document(mut s1, cx.parse('[order [id 1] ${big}]') or { panic('p') },
		cxstore.default_fanout)
	cxstore.persist_objects(mut be, s1) or { panic('persist1: ${err}') }
	after1 := be.object_count()

	mut s2 := cxstore.ObjectSink{}
	r2 := cxstore.store_document(mut s2, cx.parse('[order [id 2] ${big}]') or { panic('p') },
		cxstore.default_fanout)
	cxstore.persist_objects(mut be, s2) or { panic('persist2: ${err}') }
	after2 := be.object_count()

	added := after2 - after1
	assert added > 0 && added < after1, 'second doc must add only its delta (shared `big` deduped): doc1=${after1}, doc2 added ${added}'
	// both still reconstruct from the shared object set
	g := cxstore.getter_of(be)
	assert (cxstore.load_document_from(g, r1) or { panic('l1') }).elements.len == 1
	assert (cxstore.load_document_from(g, r2) or { panic('l2') }).elements.len == 1
}

// the GC mark algorithm runs over the remote-shaped backend exactly as over a
// pack — proving the seam generalizes the whole object-graph machinery, not just
// the document reader: mark_live walks every reachable object through getter_of.
fn test_object_backend_drives_graph_algorithms() {
	dir := tmp_dir('algo')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
	}
	mut be := cxstore.open_dir_object_backend(dir) or { panic('open: ${err}') }
	mut sink := cxstore.ObjectSink{}
	root := cxstore.store_document(mut sink, cx.parse('[doc [a [k "v"]] [a [k "v"]] [b 2]]') or {
		panic('p')
	}, cxstore.default_fanout)
	cxstore.persist_objects(mut be, sink) or { panic('persist: ${err}') }

	g := cxstore.getter_of(be)
	live := cxstore.mark_live(g, [root])
	// every reachable object resolved from the object-per-key substrate, and the
	// reachable set equals what the in-memory sink built (full graph traversal).
	assert live.len > 0, 'mark_live found nothing over the object-per-key backend'
	assert live.len == be.object_count(), 'reachable set (${live.len}) should equal the objects persisted (${be.object_count()})'
}

// a tampered object on the substrate fails its content-address check on read —
// never handed back as if valid (data-integrity invariant carried to the seam).
fn test_object_backend_self_verifies_on_read() {
	dir := tmp_dir('tamper')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
	}
	mut be := cxstore.open_dir_object_backend(dir) or { panic('open: ${err}') }
	h := be.put_object('an object payload'.bytes()) or { panic('put: ${err}') }
	assert be.has_object(h)
	assert (be.get_object(h) or { []u8{} }).bytestr() == 'an object payload'

	// corrupt the stored file → read must reject it (content address no longer matches)
	hx := h.hex()
	p := os.join_path(dir, hx[..2], hx)
	os.write_file(p, 'tampered bytes') or { panic('overwrite: ${err}') }
	if _ := be.get_object(h) {
		assert false, 'a tampered object must not be returned as valid (content-address self-verify)'
	}
}

// ── PackObjectBackend — the durable local-fs × subtree × pack ObjectBackend ────
// (#129 spec §7.1) — exercised through the SAME seam surface as DirObjectBackend,
// proving `cxpack` is one implementation of the universal object model.

// a doc staged + flushed into the pack backend reconstructs byte-identically
// after a fresh open replays the packs through load_objects + getter_of.
fn test_pack_backend_roundtrip_reopen() {
	dir := tmp_dir('packrt')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
	}
	doc := cx.parse('[order [id 1] [customer [name "Acme"] [addr [city "NYC"]]]]') or {
		panic('parse')
	}
	mut sink := cxstore.ObjectSink{}
	root := cxstore.store_document(mut sink, doc, cxstore.default_fanout)

	mut be := cxstore.open_pack_object_backend(dir)
	cxstore.persist_objects(mut be, sink) or { panic('persist: ${err}') }
	assert be.pending_count() > 0, 'objects should be staged before flush'
	be.flush_segment() or { panic('flush: ${err}') }
	assert be.pending_count() == 0, 'flush_segment should drain the staging buffer'

	// fresh backend over the same directory: discover packs, reload, reconstruct.
	mut be2 := cxstore.open_pack_object_backend(dir)
	objs := be2.load_objects() or { panic('load: ${err}') }
	assert objs.len == be.object_count(), 'reload must surface every persisted object'
	g := cxstore.getter_of(be2)
	got := cxstore.load_document_from(g, root) or { panic('reload: ${err}') }
	assert cx.emit_cx(got) == cx.emit_cx(doc), 'pack reload not byte-identical'
}

// identical subtrees across docs collapse to one stored object on the pack
// substrate too (dedup is a property of the object model, not the encoding).
fn test_pack_backend_dedup_across_docs() {
	dir := tmp_dir('packdedup')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
	}
	mut be := cxstore.open_pack_object_backend(dir)
	big := '[customer [name "Acme"] [addr [street "1 Main"] [city "NYC"]] [tags [t "a"] [t "b"]]]'

	mut s1 := cxstore.ObjectSink{}
	cxstore.store_document(mut s1, cx.parse('[order [id 1] ${big}]') or { panic('p') },
		cxstore.default_fanout)
	cxstore.persist_objects(mut be, s1) or { panic('persist1: ${err}') }
	be.flush_segment() or { panic('flush1: ${err}') }
	after1 := be.object_count()

	mut s2 := cxstore.ObjectSink{}
	cxstore.store_document(mut s2, cx.parse('[order [id 2] ${big}]') or { panic('p') },
		cxstore.default_fanout)
	cxstore.persist_objects(mut be, s2) or { panic('persist2: ${err}') }
	be.flush_segment() or { panic('flush2: ${err}') }
	added := be.object_count() - after1
	assert added > 0 && added < after1, 'second doc must add only its delta (shared `big` deduped): doc1=${after1}, doc2 added ${added}'
}

// the durable watermark makes flushes O(delta): an object already in a pack is
// never re-staged, so a no-change persist produces no new segment.
fn test_pack_backend_incremental_watermark() {
	dir := tmp_dir('packinc')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
	}
	mut be := cxstore.open_pack_object_backend(dir)
	mut sink := cxstore.ObjectSink{}
	cxstore.store_document(mut sink, cx.parse('[doc [a 1] [b 2]]') or { panic('p') },
		cxstore.default_fanout)
	cxstore.persist_objects(mut be, sink) or { panic('persist: ${err}') }
	be.flush_segment() or { panic('flush: ${err}') }
	seg_after_first := be.segment_count()

	// re-persisting the SAME sink stages nothing (every object already durable).
	cxstore.persist_objects(mut be, sink) or { panic('repersist: ${err}') }
	assert be.pending_count() == 0, 'an already-durable object must not be re-staged (O(delta) flush)'
	be.flush_segment() or { panic('flush2: ${err}') }
	assert be.segment_count() == seg_after_first, 'a no-op flush must not write a new segment'
}

// compaction folds every accumulated segment into one pack and resets the
// durable watermark to exactly the reachable set.
fn test_pack_backend_compaction() {
	dir := tmp_dir('packcompact')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
	}
	mut be := cxstore.open_pack_object_backend(dir)
	mut sink := cxstore.ObjectSink{}
	root := cxstore.store_document(mut sink, cx.parse('[doc [a [k "v"]] [b 2]]') or { panic('p') },
		cxstore.default_fanout)
	cxstore.persist_objects(mut be, sink) or { panic('persist: ${err}') }
	be.flush_segment() or { panic('flush: ${err}') }

	mut payloads := [][]u8{}
	for _, p in sink.objects {
		payloads << p
	}
	be.write_compacted(payloads) or { panic('compact: ${err}') }
	assert be.segment_count() == 0, 'compaction resets the segment count'
	assert be.object_count() == payloads.len, 'compacted watermark = reachable set'

	// the compacted pack alone reconstructs the doc.
	mut be2 := cxstore.open_pack_object_backend(dir)
	be2.load_objects() or { panic('reload: ${err}') }
	g := cxstore.getter_of(be2)
	got := cxstore.load_document_from(g, root) or { panic('reload doc: ${err}') }
	assert got.elements.len == 1, 'doc must reconstruct from the compacted pack'
}

// #302: plaintext compaction must NEVER open the live store.cxpack for write in
// place — the new pack lands complete at a temp sibling and is installed by
// atomic rename, so a failed (or crashed) compaction leaves the previous pack
// whole. Proven by blocking the temp path: with a directory squatting on
// `store.cxpack.tmp`, the compaction write MUST error out and the live pack
// MUST be byte-identical to before (an in-place writer would have succeeded —
// straight through the live pack — and this test would fail).
fn test_pack_backend_compaction_never_writes_live_pack_in_place() {
	dir := tmp_dir('packatomic')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
	}
	mut be := cxstore.open_pack_object_backend(dir)
	mut sink := cxstore.ObjectSink{}
	root := cxstore.store_document(mut sink,
		cx.parse('[doc [a [k "v1"]] [b 2]]') or { panic('p') }, cxstore.default_fanout)
	cxstore.persist_objects(mut be, sink) or { panic('persist: ${err}') }
	be.flush_segment() or { panic('flush: ${err}') }
	mut payloads := [][]u8{}
	for _, p in sink.objects {
		payloads << p
	}
	be.write_compacted(payloads) or { panic('compact: ${err}') }
	pack_path := os.join_path(dir, 'store.cxpack')
	orig := os.read_bytes(pack_path) or { panic('read pack: ${err}') }

	// Squat on the temp sibling so the compaction's temp write cannot land.
	os.mkdir_all(pack_path + '.tmp') or { panic('mkdir tmp: ${err}') }
	mut sink2 := cxstore.ObjectSink{}
	cxstore.store_document(mut sink2, cx.parse('[doc [a [k "v2"]] [b 3]]') or { panic('p') },
		cxstore.default_fanout)
	mut payloads2 := [][]u8{}
	for _, p in sink2.objects {
		payloads2 << p
	}
	mut failed := false
	be.write_compacted(payloads2) or { failed = true }
	assert failed, 'compaction with an unwritable temp path must ERROR (an in-place write of the live pack would sail through)'

	// The live pack is untouched — byte-identical and still fully readable.
	after := os.read_bytes(pack_path) or { panic('re-read pack: ${err}') }
	assert after == orig, 'a failed compaction must leave the previous pack byte-identical'
	mut be3 := cxstore.open_pack_object_backend(dir)
	be3.load_objects() or { panic('reload after failed compaction: ${err}') }
	g3 := cxstore.getter_of(be3)
	got3 := cxstore.load_document_from(g3, root) or { panic('reload doc: ${err}') }
	assert got3.elements.len == 1, 'the original doc must survive a failed compaction'
}
