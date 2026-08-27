module platform
import code {
	caps_set_all,
	is_err_value,
	render_canonical,
}

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
	return sw_scalar(r)
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
		assert dd is cx.ScalarNode && sw_scalar(dd) == 'true', 'delete-doc: ${dd}'
		dala := store_stdlib_builtin_inner('store-delete-alias', [h, store_str('doomed')]) or {
			panic('delete-alias: ${err.msg()}')
		}
		assert dala is cx.ScalarNode && sw_scalar(dala) == 'true', 'delete-alias: ${dala}'
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
			assert r is cx.ScalarNode && sw_scalar(r) == 'true', 'delete churn${i}: ${r}'
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

// ── #891: shared-open protection for the sqlite substrate ───────────────────
//
// Two writable opens of one sqlite file were two independent connections whose
// in-memory views diverge the moment either writes, with the later flush
// winning over rows the other believes it owns — and before #891 sqlite
// registered with neither store_open_shared_or_conflict nor any lock, so that
// divergence was silent. These pin the #628 shape for this substrate.

fn sq_handle_id(n cx.Node) string {
	return (n as cx.Element).attr('handle')
}

fn sq_err_code(n cx.Node) string {
	return (n as cx.Element).attr('code')
}

// A second WRITABLE open of one sqlite file is a live view of the SAME store.
fn test_store_sqlite_second_writable_open_shares_the_live_store() {
	$if cxstore_sqlite ? {
		path := os.join_path(os.temp_dir(), 'cxstore_sqlite_share_${os.getpid()}.db')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		h1 := sq_open(path)
		key := sq_put(h1, '[event [level "error"] [ts 1]]')

		caps_set_all()
		h2 := store_sqlite_open('sqlite://${path}', '', '', false, '', '')
		assert !is_err_value(h2), 'second open err: ${h2}'
		assert sq_handle_id(h1) != sq_handle_id(h2), 'sharing returns a distinct HANDLE over the same store'

		got := store_stdlib_builtin_inner('store-get-doc-text', [h2, store_str(key)]) or {
			panic('get: ${err.msg()}')
		}
		assert !is_err_value(got), 'second handle cannot see the first handle write — the opens did not share (#891): ${got}'
		assert render_canonical(got).contains('error'), 'shared view returned the wrong doc: ${got}'
	}
}

// Divergent at-rest options on a LIVE writable file refuse loudly
// (CXER1143 E_STORE_OPEN_CONFLICT) instead of applying one opener's options to
// the other's writes.
fn test_store_sqlite_conflicting_at_rest_options_refuse() {
	$if cxstore_sqlite ? {
		path := os.join_path(os.temp_dir(), 'cxstore_sqlite_conflict_${os.getpid()}.db')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		h1 := sq_open(path)
		assert !is_err_value(h1), 'first open err: ${h1}'
		// Same file, different at-rest compression.
		caps_set_all()
		h2 := store_sqlite_open('sqlite://${path}', 'zstd', '', false, '', '')
		assert is_err_value(h2), 'a live sqlite file reopened with different compression must REFUSE (#891), got: ${h2}'
		assert sq_err_code(h2) == 'cx-err:CXER1143', 'wrong refusal code: ${h2}'
	}
}

// READ-ONLY opens keep their private snapshot view — they never write, so a
// private MemStore is both safe and cheaper.
fn test_store_sqlite_read_only_opens_stay_private() {
	$if cxstore_sqlite ? {
		path := os.join_path(os.temp_dir(), 'cxstore_sqlite_ro_${os.getpid()}.db')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		h := sq_open(path)
		sq_put(h, '[event [level "info"] [ts 1]]')
		store_stdlib_builtin_inner('store-close', [h]) or { panic('close: ${err.msg()}') }

		caps_set_all()
		r1 := store_sqlite_open('sqlite://${path}', '', '', true, '', '')
		assert !is_err_value(r1), 'first read-only open err: ${r1}'
		r2 := store_sqlite_open('sqlite://${path}', '', '', true, '', '')
		assert !is_err_value(r2), 'second read-only open err: ${r2}'
		assert sq_handle_id(r1) != sq_handle_id(r2), 'read-only opens must stay private (distinct handles), got the same id'
	}
}

// ── #1005: the same protection ACROSS processes ─────────────────────────────
//
// #891 (above) shares one live MemStore through a process-global registry, so
// it cannot span processes at all. Two sqlite writers in two processes were
// therefore still admitted in silence — two connections whose views diverge on
// the first write, the later flush winning over rows the other believes it
// owns. `store_root_lock_take` now guards the writable open with an flock on a
// sentinel beside the db file.
//
// The holder here is an INDEPENDENT open file description rather than a second
// `cx` process, and that is the mechanism and not a stand-in for it: flock's
// conflict domain IS the description, so the open under test meets exactly the
// condition a second process creates. (A `cx` holder is not available for this
// substrate — the dev binary is built without `-d cxstore_sqlite`, which is why
// this file is flag-gated in the first place.)
fn sq_hold_foreign_lock(path string, fake_pid int) os.File {
	mut f := os.open_file(path, 'a+', 0o644) or { panic('sentinel: ${err.msg()}') }
	assert C.flock(f.fd, C.LOCK_EX | C.LOCK_NB) == 0, 'could not take the sentinel lock at ${path}'
	C.ftruncate(f.fd, 0)
	f.write_string('cxstore-lock v1 pid=${fake_pid} host=elsewhere.test url=sqlite://${path} since=2026-08-26T00:00:00.000Z\n') or {
	}
	f.flush()
	return f
}

fn test_store_sqlite_cross_process_writable_open_refuses_1005() {
	$if cxstore_sqlite ? {
		path := os.join_path(os.temp_dir(), 'cxstore_sqlite_xproc_${os.getpid()}.db')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		lockp := store_root_lock_path('sqlite', path)
		assert lockp == path + '.cxstore-lock', 'a FILE root takes a SIBLING sentinel, never a directory: ${lockp}'
		defer {
			os.rm(lockp) or {}
		}
		// Create the db and release our own lock, so the only holder below is
		// the foreign one.
		h0 := sq_open(path)
		store_stdlib_builtin_inner('store-close', [h0]) or { panic('close: ${err.msg()}') }
		mut held := sq_hold_foreign_lock(lockp, 424242)

		caps_set_all()
		h := store_sqlite_open('sqlite://${path}', '', '', false, '', '')
		assert is_err_value(h), '#1005: a sqlite file held WRITABLE elsewhere was opened writable anyway: ${h}'
		assert sq_err_code(h) == 'cx-err:CXER1143', 'wrong refusal code: ${h}'
		assert render_canonical(h).contains('pid=424242'), 'the refusal does not NAME the holder: ${h}'
		assert render_canonical(h).contains('RECOVERY:'), 'the refusal names no recovery path: ${h}'

		// The read-only exemption reaches this substrate too: N readers
		// alongside the one writer is the supported shape.
		r := store_sqlite_open('sqlite://${path}', '', '', true, '', '')
		assert !is_err_value(r), '#1005: the read-only exemption was lost for sqlite: ${r}'

		// Release: the root is immediately available again. A crashed holder
		// releases the same way — the kernel drops the lock when the last
		// descriptor on it closes, which is the whole reason flock and not an
		// O_EXCL sentinel.
		C.flock(held.fd, C.LOCK_UN)
		held.close()
		w := store_sqlite_open('sqlite://${path}', '', '', false, '', '')
		assert !is_err_value(w), '#1005: the sqlite root stayed refused after its holder released: ${w}'
	}
}
