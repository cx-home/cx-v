module code

import cx
import os

// sqlite:// [$store] SUBTREE object-model round-trip (#129 spec §6). The body is
// gated on `-d cxstore_sqlite` (matching the backend's feature gate); without the
// flag this is a no-op (proving the default build compiles without libsqlite3 — and
// without referencing any sqlite-gated symbol). Covers gate items 1 (round-trip +
// reopen), 2 (dedup), and exercises persist/load over object rows.
fn test_store_sqlite_subtree_roundtrip_and_dedup() {
	$if cxstore_sqlite ? {
		path := os.join_path(os.temp_dir(), 'cxstore_sqlite_subtree_${os.getpid()}.db')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		mut ms := &MemStore{
			url:     'sqlite://${path}'
			backend: 'sqlite'
			root:    path
			is_open: true
		}
		store_sqlite_attach(mut ms) or { panic('attach: ${err.msg()}') }

		// two docs sharing the [customer …] subtree.
		shared_sub := '[customer [name "Acme"] [addr [city "NYC"]]]'
		c1 := render_canonical(cx.parse('[order [id 1] ${shared_sub}]') or { panic('p1') }.elements[0])
		h1 := cx.cx_text_hash(c1) or { panic('h1') }
		store_put_canonical(mut ms, h1, c1) or { panic('put1: ${err.msg()}') }
		store_sqlite_persist(ms) or { panic('persist: ${err.msg()}') }
		after1 := ms.obj_backend or { panic('no backend') }.object_count()

		c2 := render_canonical(cx.parse('[order [id 2] ${shared_sub}]') or { panic('p2') }.elements[0])
		h2 := cx.cx_text_hash(c2) or { panic('h2') }
		store_put_canonical(mut ms, h2, c2) or { panic('put2: ${err.msg()}') }
		store_sqlite_persist(ms) or { panic('persist: ${err.msg()}') }
		after2 := ms.obj_backend or { panic('no backend') }.object_count()

		// GATE 2 (dedup): the shared subtree is stored once — doc2 adds only its delta.
		added := after2 - after1
		assert added > 0 && added < after1, 'second doc must add only its delta (shared subtree deduped): doc1=${after1}, doc2 added ${added}'

		// GATE 1 (round-trip + reopen): a fresh open replays the manifest and
		// reconstructs both docs byte-identically from the object rows (lazily).
		mut ms2 := &MemStore{
			url:     'sqlite://${path}'
			backend: 'sqlite'
			root:    path
			is_open: true
		}
		store_sqlite_load(mut ms2) or { panic('reopen: ${err.msg()}') }
		assert store_doc_present(ms2, h1), 'doc1 missing after reopen'
		assert store_doc_present(ms2, h2), 'doc2 missing after reopen'
		got1 := store_doc_text(ms2, h1) or { panic('get1: ${err.msg()}') }
		got2 := store_doc_text(ms2, h2) or { panic('get2: ${err.msg()}') }
		assert got1 == c1, 'doc1 round-trip not byte-identical after reopen'
		assert got2 == c2, 'doc2 round-trip not byte-identical after reopen'
	}
}

// GATE 6 (universal integrity / CXER1120): a corrupted object row makes the reopen
// fail HARD, never a silent drop.
fn test_store_sqlite_corruption_is_hard_error() {
	$if cxstore_sqlite ? {
		path := os.join_path(os.temp_dir(), 'cxstore_sqlite_corrupt_${os.getpid()}.db')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		mut ms := &MemStore{
			url:     'sqlite://${path}'
			backend: 'sqlite'
			root:    path
			is_open: true
		}
		store_sqlite_attach(mut ms) or { panic('attach: ${err.msg()}') }
		c1 := render_canonical(cx.parse('[order [id 1] [customer [name "Acme"]]]') or { panic('p') }.elements[0])
		h1 := cx.cx_text_hash(c1) or { panic('h') }
		store_put_canonical(mut ms, h1, c1) or { panic('put: ${err.msg()}') }
		store_sqlite_persist(ms) or { panic('persist: ${err.msg()}') }

		// corrupt every object row's bytes in place.
		corrupt_sqlite_objects(path)

		mut ms2 := &MemStore{
			url:     'sqlite://${path}'
			backend: 'sqlite'
			root:    path
			is_open: true
		}
		if _ := store_sqlite_load_result(mut ms2) {
			assert false, 'reopen of a corrupted sqlite store must be a hard error, not a silent success'
		}
	}
}

// ── #299: per-mutation cost is O(delta), never O(store) ───────────────────────
//
// store_append's sqlite path used to call store_sqlite_persist per mutation — a
// whole-store snapshot (every sink object re-INSERTed + the full manifest row
// rewritten) on every op. These tests pin the incremental contract with the
// SqliteObjectBackend.writes gauge: one mutation on a big store issues the same
// write-statement count as on a small one; deletes append T/X manifest deltas;
// the manifest log compacts back to a snapshot under redundancy.

// Helpers keep every sqlite-gated symbol inside `$if cxstore_sqlite ?` so the
// DEFAULT build still compiles this file without libsqlite3 (the file's gate
// contract, see the header comment).
fn sq_open(path string) cx.Node {
	$if cxstore_sqlite ? {
		caps_set_all()
		h := store_sqlite_open('sqlite://${path}', '', '', false, '', '')
		store_handle_of(h) or { panic('sqlite open failed: ${h}') }
		return h
	}
	panic('sq_open requires -d cxstore_sqlite')
}

fn sq_ms(h cx.Node) &MemStore {
	id := store_handle_of(h) or { panic('no handle') }
	return store_lookup(id) or { panic('no store') }
}

fn sq_writes(h cx.Node) int {
	$if cxstore_sqlite ? {
		mut ms := sq_ms(h)
		mut rb := store_sqlite_row_backend(mut ms) or { panic('no row backend') }
		return rb.writes
	}
	panic('sq_writes requires -d cxstore_sqlite')
}

fn sq_put(h cx.Node, text string) string {
	r := store_stdlib_builtin_inner('store-put-doc-text', [h, store_str(text)]) or {
		panic('put: ${err.msg()}')
	}
	assert !is_err_value(r), 'put must succeed: ${r}'
	return csrp_scalar(r)
}

fn test_store_sqlite_append_writes_o_delta() {
	$if cxstore_sqlite ? {
		pa := os.join_path(os.temp_dir(), 'cxstore_sqlite_odelta_a_${os.getpid()}.db')
		pb := os.join_path(os.temp_dir(), 'cxstore_sqlite_odelta_b_${os.getpid()}.db')
		os.rm(pa) or {}
		os.rm(pb) or {}
		defer {
			os.rm(pa) or {}
			os.rm(pb) or {}
		}
		// store A: 40 docs live before the probed put.
		ha := sq_open(pa)
		for i in 0 .. 40 {
			sq_put(ha, '[doc [n "a${i}"]]')
		}
		wa0 := sq_writes(ha)
		sq_put(ha, '[doc [n "probe"]]')
		da := sq_writes(ha) - wa0
		// store B: 5 docs live before the SAME probed put.
		hb := sq_open(pb)
		for i in 0 .. 5 {
			sq_put(hb, '[doc [n "a${i}"]]')
		}
		wb0 := sq_writes(hb)
		sq_put(hb, '[doc [n "probe"]]')
		db_ := sq_writes(hb) - wb0
		// THE #299 contract: per-op write cost is a function of the DELTA, not of
		// store size — the 41-doc store issues the same statements as the 6-doc one.
		assert da <= db_ + 1, 'per-op writes must not scale with store size: 41-doc store issued ${da} write stmts for one put, 6-doc store issued ${db_}'
		assert da < 16, 'one small-doc put must be a handful of writes, got ${da}'
	}
}

fn test_store_sqlite_delete_doc_and_alias_durable_o_delta() {
	$if cxstore_sqlite ? {
		path := os.join_path(os.temp_dir(), 'cxstore_sqlite_del_${os.getpid()}.db')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		h := sq_open(path)
		// enough live docs that a whole-snapshot delete is clearly visible.
		mut keep_hashes := []string{}
		for i in 0 .. 10 {
			keep_hashes << sq_put(h, '[doc [k "keep${i}"]]')
		}
		gone := sq_put(h, '[doc [k "gone"]]')
		sa := store_stdlib_builtin_inner('store-set-alias', [h, store_str('cur'),
			store_str(keep_hashes[0])]) or { panic('set-alias: ${err.msg()}') }
		assert !is_err_value(sa), 'set-alias: ${sa}'
		sb := store_stdlib_builtin_inner('store-set-alias', [h, store_str('doomed'),
			store_str(gone)]) or { panic('set-alias 2: ${err.msg()}') }
		assert !is_err_value(sb), 'set-alias 2: ${sb}'

		// delete-doc + delete-alias: O(delta) writes (a T/X manifest append + the
		// tombstoned alias-name object), NOT a whole-store re-persist.
		w0 := sq_writes(h)
		dd := store_stdlib_builtin_inner('store-delete-doc', [h, store_str(gone)]) or {
			panic('delete-doc: ${err.msg()}')
		}
		assert dd is cx.ScalarNode && csrp_scalar(dd) == 'true', 'delete-doc: ${dd}'
		dala := store_stdlib_builtin_inner('store-delete-alias', [h, store_str('doomed')]) or {
			panic('delete-alias: ${err.msg()}')
		}
		assert dala is cx.ScalarNode && csrp_scalar(dala) == 'true', 'delete-alias: ${dala}'
		dw := sq_writes(h) - w0
		assert dw <= 6, 'delete-doc + delete-alias on an 11-doc store must be O(delta) writes, got ${dw}'

		// durable-on-return: a FRESH load sees the deletions (and the survivors,
		// byte-identical).
		mut ms2 := &MemStore{
			url:     'sqlite://${path}'
			backend: 'sqlite'
			root:    path
			is_open: true
		}
		store_sqlite_load(mut ms2) or { panic('reopen: ${err.msg()}') }
		assert !store_doc_present(ms2, gone), 'deleted doc must not replay'
		assert store_doc_present(ms2, keep_hashes[0]), 'survivor doc must replay'
		got := store_doc_text(ms2, keep_hashes[0]) or { panic('get: ${err.msg()}') }
		assert got.contains('keep0'), 'survivor doc content intact'
		assert 'doomed' !in ms2.aliases, 'deleted alias must not replay'
		assert ms2.aliases['cur'] == keep_hashes[0], 'survivor alias must replay'

		// replay-order: a re-put after the tombstone comes back.
		gone2 := sq_put(h, '[doc [k "gone"]]')
		assert gone2 == gone, 'same content re-puts under the same store key'
		mut ms3 := &MemStore{
			url:     'sqlite://${path}'
			backend: 'sqlite'
			root:    path
			is_open: true
		}
		store_sqlite_load(mut ms3) or { panic('reopen 3: ${err.msg()}') }
		assert store_doc_present(ms3, gone), 're-put doc after tombstone must come back on replay'
	}
}

fn test_store_sqlite_delete_heavy_manifest_compacts() {
	$if cxstore_sqlite ? {
		path := os.join_path(os.temp_dir(), 'cxstore_sqlite_compact_${os.getpid()}.db')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		h := sq_open(path)
		keep := sq_put(h, '[doc [k "base"]]')
		// 40 put+delete cycles against live=1: the manifest delta log MUST fold
		// back to a snapshot instead of growing without bound.
		for i in 0 .. 40 {
			ki := sq_put(h, '[doc [k "churn${i}"]]')
			r := store_stdlib_builtin_inner('store-delete-doc', [h, store_str(ki)]) or {
				panic('delete: ${err.msg()}')
			}
			assert r is cx.ScalarNode && csrp_scalar(r) == 'true', 'delete churn${i}: ${r}'
		}
		mut ms := sq_ms(h)
		live := ms.doc_order.len + ms.alias_order.len
		assert live == 1, 'only the base doc stays live'
		mut rb := store_sqlite_row_backend(mut ms) or { panic('no row backend') }
		mlines := rb.read_manifest().split_into_lines().filter(it.trim_space() != '').len
		assert mlines <= 2 * live + 64, 'on-disk manifest must be bounded after compaction, got ${mlines} lines'
		assert rb.manifest_lines == mlines, 'manifest-line bookkeeping (${rb.manifest_lines}) must match disk (${mlines})'
		// durability: the survivor replays on a fresh load.
		mut ms2 := &MemStore{
			url:     'sqlite://${path}'
			backend: 'sqlite'
			root:    path
			is_open: true
		}
		store_sqlite_load(mut ms2) or { panic('reopen: ${err.msg()}') }
		assert store_doc_present(ms2, keep), 'base doc survives compaction'
		assert ms2.doc_order.len == 1, 'exactly the live doc replays, got ${ms2.doc_order.len}'
	}
}
