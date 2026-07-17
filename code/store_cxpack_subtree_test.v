module code

import cx
import cxstore
import os

// store_cxpack_subtree_test.v — #129 store-level behavioral evidence that the
// cxpack:// backend now persists via the subtree object graph: docs round-trip
// across persist/reload, identical subtrees dedup across documents, and a new
// version of a doc reuses the untouched subtree objects (structural sharing).

fn canon_and_hash(text string) (string, string) {
	doc := cx.parse(text) or { return text, '' }
	c := render_canonical(doc.elements[0])
	h := cx.cx_text_hash(c) or { return c, '' }
	return c, h
}

fn build_cxpack(root string, texts []string) &MemStore {
	mut ms := &MemStore{
		url:     'file://${root}'
		backend: 'cxpack'
		root:    root
		is_open: true
	}
	for t in texts {
		c, h := canon_and_hash(t)
		if h != '' {
			// #129-A: populate the LIVE object graph (not the docs map).
			store_put_canonical(mut ms, h, c) or { panic('put: ' + err.msg()) }
		}
	}
	return ms
}

fn pack_object_count(root string) int {
	r := cxstore.open_pack(os.join_path(root, cxpack_pack)) or { return -1 }
	return r.hashes().len
}

fn tmp_root(tag string) string {
	return os.join_path(os.temp_dir(), 'cxpack_${tag}_${os.getpid()}')
}

// (correctness) docs persisted as an object graph reload byte-identically.
fn test_cxpack_subtree_roundtrip() {
	root := tmp_root('rt')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	texts := [
		'[order [id 1] [customer [name "Acme"] [addr [city "NYC"]]]]',
		'[order [id 2] [customer [name "Acme"] [addr [city "NYC"]]]]',
	]
	mut ms := build_cxpack(root, texts)
	store_cxpack_compact(mut ms) or { panic('compact: ${err.msg()}') }
	mut ms2 := &MemStore{
		backend: 'cxpack'
		root:    root
		is_open: true
	}
	store_cxpack_load(mut ms2) or { panic('load: ' + err.msg()) }
	assert ms2.doc_order.len == ms.doc_order.len, 'doc count changed across reload'
	for h in ms.doc_order {
		assert store_doc_present(ms2, h), 'doc ${h} missing after reload'
		got := store_doc_text(ms2, h) or { panic('reconstruct ${h}: ' + err.msg()) }
		want := store_doc_text(ms, h) or { panic('reconstruct src ${h}: ' + err.msg()) }
		assert got == want, 'doc ${h} canonical text changed across reload'
	}
}

// (#129-A) dedup + structural sharing are LIVE in the in-memory object sink —
// before any persistence. Two docs sharing a subtree share objects in the live
// store, and a one-field modify adds only the changed path.
fn test_objgraph_live_in_memory_sharing() {
	mut ms := &MemStore{
		backend: 'mem-objgraph-probe'
		is_open: true
	}
	// force the object-graph path for this probe regardless of backend name
	ms.backend = 'cxpack'
	big := '[customer [name "Acme"] [addr [street "1 Main"] [city "NYC"]] [tags [t "a"] [t "b"] [t "c"]]]'
	c1, h1 := canon_and_hash('[order [id 1] ${big}]')
	c2, h2 := canon_and_hash('[order [id 2] ${big}]')
	store_put_canonical(mut ms, h1, c1) or { panic(err.msg()) }
	after1 := ms.obj_sink.objects.len
	store_put_canonical(mut ms, h2, c2) or { panic(err.msg()) }
	after2 := ms.obj_sink.objects.len
	// the second doc shares the `big` subtree → adds far fewer objects than the first
	added := after2 - after1
	assert added > 0 && added < after1, 'expected live sharing: doc1 added ${after1}, doc2 added only ${added}'
	// both docs are readable from the live graph (no persistence happened)
	assert (store_doc_text(ms, h1) or { '' }) == c1, 'doc1 not live-reconstructable'
	assert (store_doc_text(ms, h2) or { '' }) == c2, 'doc2 not live-reconstructable'
}

// (cross-doc dedup) two docs sharing a subtree store fewer objects than two docs
// that share nothing.
fn test_cxpack_cross_doc_dedup() {
	big := '[customer [name "Acme"] [addr [street "1 Main"] [city "NYC"] [zip "10001"]] [contacts [c "a@x"] [c "b@x"] [c "d@x"]]]'
	big2 := '[supplier [name "Globex"] [addr [street "9 Oak"] [city "LA"] [zip "90001"]] [contacts [c "p@y"] [c "q@y"] [c "r@y"]]]'
	shared_texts := ['[order [id 1] ${big}]', '[order [id 2] ${big}]']
	disjoint_texts := ['[order [id 1] ${big}]', '[order [id 2] ${big2}]']

	rs := tmp_root('shared')
	rd := tmp_root('disjoint')
	os.rmdir_all(rs) or {}
	os.rmdir_all(rd) or {}
	defer {
		os.rmdir_all(rs) or {}
		os.rmdir_all(rd) or {}
	}
	mut ms_s := build_cxpack(rs, shared_texts)
	store_cxpack_compact(mut ms_s) or { panic('compact: ${err.msg()}') }
	mut ms_d := build_cxpack(rd, disjoint_texts)
	store_cxpack_compact(mut ms_d) or { panic('compact: ${err.msg()}') }
	ns := pack_object_count(rs)
	nd := pack_object_count(rd)
	assert ns > 0 && nd > 0, 'pack object count unavailable (${ns}, ${nd})'
	assert ns < nd, 'expected shared-subtree pack (${ns} objs) to be smaller than disjoint (${nd} objs)'
}

// (version sharing) a one-field new version of a doc adds far fewer objects than
// the whole doc — untouched subtrees are reused, not rewritten.
fn test_cxpack_modify_version_sharing() {
	big := '[body [a "1"] [b "2"] [c "3"] [d "4"] [e "5"] [f "6"] [g "7"] [h "8"]]'
	v1 := '[doc ${big} [v "ORIGINAL"]]'
	v2 := '[doc ${big} [v "CHANGED"]]'

	r1 := tmp_root('v1')
	r12 := tmp_root('v12')
	os.rmdir_all(r1) or {}
	os.rmdir_all(r12) or {}
	defer {
		os.rmdir_all(r1) or {}
		os.rmdir_all(r12) or {}
	}
	mut ms_1 := build_cxpack(r1, [v1])
	store_cxpack_compact(mut ms_1) or { panic('compact: ${err.msg()}') }
	mut ms_12 := build_cxpack(r12, [v1, v2])
	store_cxpack_compact(mut ms_12) or { panic('compact: ${err.msg()}') }
	n1 := pack_object_count(r1)
	n12 := pack_object_count(r12)
	added := n12 - n1
	assert n1 > 0 && added > 0, 'unexpected object counts (n1=${n1}, added=${added})'
	assert added < n1, 'a one-field new version should add fewer objects (${added}) than a full doc has (${n1})'
}

// (#129-C integrity) corruption on load is a HARD ERROR, never a silent drop.
// A manifest entry pointing at an object absent from the pack must fail the load
// — a silently-dropped doc would be data loss masquerading as success.
fn test_cxpack_load_corruption_is_hard_error() {
	root := tmp_root('corrupt')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	// a valid store on disk first
	mut ms0 := build_cxpack(root, ['[doc [x 1]]'])
	store_cxpack_compact(mut ms0) or { panic('compact: ${err.msg()}') }
	assert os.exists(os.join_path(root, cxpack_pack)), 'precondition: pack written'

	// corrupt the manifest: a doc whose object root is absent from the pack
	missing := '0'.repeat(64)
	os.write_file(os.join_path(root, cxpack_manifest), 'D\tdeadbeefdoc\t${missing}\n') or {
		assert false, 'could not rewrite manifest'
		return
	}
	mut ms := &MemStore{
		backend: 'cxpack'
		root:    root
		is_open: true
	}
	store_cxpack_load(mut ms) or {
		// expected: integrity error, and NO doc silently loaded
		assert ms.doc_order.len == 0, 'corrupt doc must not be partially loaded'
		return
	}
	assert false, 'expected a hard integrity error on a missing-object manifest entry; load silently succeeded (data-loss regression)'
}

// (#129-C) a manifest present without its pack is incomplete → hard error.
fn test_cxpack_incomplete_store_is_hard_error() {
	root := tmp_root('incomplete')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	mut ms0 := build_cxpack(root, ['[doc [y 2]]'])
	store_cxpack_compact(mut ms0) or { panic('compact: ${err.msg()}') }
	os.rm(os.join_path(root, cxpack_pack)) or {
		assert false, 'could not remove pack'
		return
	}
	mut ms := &MemStore{
		backend: 'cxpack'
		root:    root
		is_open: true
	}
	store_cxpack_load(mut ms) or { return } // expected error
	assert false, 'expected a hard error when the pack is missing but the manifest is present'
}
