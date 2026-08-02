module code

import os

// Tests the cxpack:// persistence path directly (store_cxpack_persist/load +
// the store_append snapshot hook), which is what store_persist/store_append/
// store_open_impl call for backend 'cxpack'. The full [$store cxpack://]
// dispatch goes through cap_guard (needs a granted capability context from
// eval), so it is exercised by the conformance gate; here we verify the
// engine-backed persistence round-trips, including aliases.
//
// cxpack:// now persists via the subtree object graph (#129), so a doc reloads
// as its CANONICAL text. In real use this is exact — the store only ever stores
// render_canonical output (put-doc-text) — so the inputs below are canonical.

fn test_cxpack_persist_load_roundtrip() {
	dir := os.join_path(os.temp_dir(), 'cxpack_persist_rt')
	os.rmdir_all(dir) or {}

	mut ms := &MemStore{
		backend: 'cxpack'
		root:    dir
		is_open: true
	}
	// #129-A: docs land in the LIVE object graph via the real put path.
	store_put_canonical(mut ms, 'h1', '[db [rec [id 1] [v 1]]]') or { panic(err.msg()) }
	store_put_canonical(mut ms, 'h2', '[db [rec [id 2] [v 2]]]') or { panic(err.msg()) }
	store_put_canonical(mut ms, 'h3', "[note [body 'hello']]") or { panic(err.msg()) }
	store_alias_set_local(mut ms, 'latest', 'h3')
	store_alias_set_local(mut ms, 'first', 'h1')
	store_cxpack_compact(mut ms) or { panic('compact: ${err.msg()}') }
	assert os.exists(os.join_path(dir, cxpack_pack))
	assert os.exists(os.join_path(dir, cxpack_manifest))

	// fresh store loads the same docs + aliases back (canonical) and in order
	mut ms2 := &MemStore{
		backend: 'cxpack'
		root:    dir
		is_open: true
	}
	store_cxpack_load(mut ms2) or { panic('load: ' + err.msg()) }
	assert ms2.doc_order == ['h1', 'h2', 'h3']
	assert (store_doc_text(ms2, 'h1') or { '' }) == '[db [rec [id 1] [v 1]]]'
	assert (store_doc_text(ms2, 'h3') or { '' }) == "[note [body 'hello']]"
	assert ms2.alias_order == ['latest', 'first']
	assert ms2.aliases['latest'] == 'h3'
	assert ms2.aliases['first'] == 'h1'

	os.rmdir_all(dir) or {}
}

// store_append snapshots for cxpack (the put/alias/modify mutation hook).
fn test_cxpack_store_append_persists() {
	dir := os.join_path(os.temp_dir(), 'cxpack_append')
	os.rmdir_all(dir) or {}
	mut ms := &MemStore{
		backend: 'cxpack'
		root:    dir
		is_open: true
	}
	store_put_canonical(mut ms, 'k1', '[doc [x 1]]') or { panic(err.msg()) }
	// mutation hook used by put/alias/modify
	store_append(mut ms, store_doc_record('k1', '[doc [x 1]]')) or { panic('append: ${err.msg()}') }
	mut ms2 := &MemStore{
		backend: 'cxpack'
		root:    dir
		is_open: true
	}
	store_cxpack_load(mut ms2) or { panic('load: ' + err.msg()) }
	assert (store_doc_text(ms2, 'k1') or { '' }) == '[doc [x 1]]'
	os.rmdir_all(dir) or {}
}

// Identical document content is stored once in the object graph (content dedup).
fn test_cxpack_dedups_identical_docs() {
	dir := os.join_path(os.temp_dir(), 'cxpack_dedup')
	os.rmdir_all(dir) or {}
	same := '[doc [x 1]]'
	mut ms := &MemStore{
		backend: 'cxpack'
		root:    dir
		is_open: true
	}
	store_put_canonical(mut ms, 'k1', same) or { panic(err.msg()) }
	store_put_canonical(mut ms, 'k2', same) or { panic(err.msg()) }
	store_cxpack_compact(mut ms) or { panic('compact: ${err.msg()}') }
	mut ms2 := &MemStore{
		backend: 'cxpack'
		root:    dir
		is_open: true
	}
	store_cxpack_load(mut ms2) or { panic('load: ' + err.msg()) }
	assert (store_doc_text(ms2, 'k1') or { '' }) == same
	assert (store_doc_text(ms2, 'k2') or { '' }) == same
	os.rmdir_all(dir) or {}
}
