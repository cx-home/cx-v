module code

import cx
import os

// store_flat_file_test.v — flat file:// document-model parity + hygiene
// (#290 / #291 / #292). The flat model is the LEGACY on-disk form (new file://
// stores land on the cxpack object graph), but pre-existing stores replay
// through it forever, so it keeps the same contracts:
//
//   #290 gc/prune succeed per the store.md §15 capability table (flat
//        semantics: every present doc is its own object AND a root, mirroring
//        pc_reclaim's obj_roots semantics — reclaimed=0, objects=len(docs);
//        gc additionally compacts the append log to a snapshot).
//   #291 delete-doc appends a T (tombstone) record — the O(1) append path —
//        instead of rewriting the whole snapshot; store_read_index replays it;
//        the compaction heuristic folds tombstones away; an OLD index (no
//        tombstones) replays identically; a re-put after a tombstone comes back.
//   #292 open sweeps stale sibling `.cxstore-index.tmp.<pid>` files whose pid
//        is no longer a live process (crash between temp write and rename).
//   #298 delete-alias appends an X (alias tombstone) record — the #291
//        contract on the alias plane (durability, re-add ordering, compaction).

fn ff_root(tag string) string {
	root := os.join_path(os.temp_dir(), 'cxflat_${tag}_${os.getpid()}')
	os.rmdir_all(root) or {}
	return root
}

// ff_open opens (or reopens) a flat document-model store at root via the
// PUBLIC open path (self-describing reopen included), with all caps granted.
fn ff_open(url string, read_only bool) cx.Node {
	caps_set_all()
	h := store_open_impl(url, '', '', read_only, true, map[string]string{})
	store_handle_of(h) or { panic('flat open ${url} did not return a handle: ${h}') }
	return h
}

fn ff_ms(h cx.Node) &MemStore {
	id := store_handle_of(h) or { panic('no handle: ${h}') }
	return store_lookup(id) or { panic('no store for handle ${id}') }
}

fn ff_put(h cx.Node, text string) string {
	r := store_stdlib_builtin_inner('store-put-doc-text', [h, store_str(text)]) or {
		panic('put: ${err.msg()}')
	}
	assert !is_err_value(r), 'put must succeed: ${r}'
	return csrp_scalar(r)
}

fn ff_get(h cx.Node, hash string) cx.Node {
	return store_stdlib_builtin_inner('store-get-doc-text', [h, store_str(hash)]) or {
		panic('get: ${err.msg()}')
	}
}

fn ff_delete(h cx.Node, hash string) cx.Node {
	return store_stdlib_builtin_inner('store-delete-doc', [h, store_str(hash)]) or {
		panic('delete: ${err.msg()}')
	}
}

fn ff_err_code(n cx.Node) string {
	if !is_err_value(n) {
		return ''
	}
	if n is cx.Element {
		return csrp_attr(n, 'code')
	}
	return ''
}

fn ff_attr_int(n cx.Node, name string) int {
	if n is cx.Element {
		return csrp_attr(n, name).int()
	}
	return -999
}

fn ff_index_path(root string) string {
	return os.join_path(root, store_index_name)
}

// ff_canon_hash produces the STRICT canonical text + its genuine store key —
// the same canonical.md §1.2 identity put-doc-text computes (needed when
// fabricating an index by hand and when asserting round-trip bytes).
fn ff_canon_hash(text string) (string, string) {
	c := cx.cx_text_canonical(text) or { panic('canonical: ${err.msg()}') }
	h := cx.cx_text_hash(c) or { panic('hash: ${err.msg()}') }
	return c, h
}

// ── #290: gc / prune succeed on the flat model ────────────────────────────────

fn test_flat_prune_succeeds_with_flat_semantics() {
	root := ff_root('prune')
	defer {
		os.rmdir_all(root) or {}
	}
	h := ff_open('document+file://${root}', false)
	ff_put(h, '[doc [item "x"]]')
	ka := ff_put(h, '[doc [item "y"]]')
	d := ff_delete(h, ka)
	assert !is_err_value(d), 'delete must succeed: ${d}'
	r := store_stdlib_builtin_inner('store-prune', [h]) or { panic('prune: ${err.msg()}') }
	assert !is_err_value(r), 'prune on flat file:// must succeed per §15, got ${r}'
	assert r is cx.Element && (r as cx.Element).name == 'prune-result', 'prune result shape: ${r}'
	// flat semantics: every present doc is its own object and a root — nothing
	// sub-doc to reclaim, honest zero.
	assert ff_attr_int(r, 'reclaimed') == 0, 'flat prune reclaims nothing: ${r}'
	assert ff_attr_int(r, 'objects') == 1, 'flat prune reports live docs as objects: ${r}'
}

fn test_flat_prune_empty_store() {
	root := ff_root('prune_empty')
	defer {
		os.rmdir_all(root) or {}
	}
	h := ff_open('document+file://${root}', false)
	r := store_stdlib_builtin_inner('store-prune', [h]) or { panic('prune: ${err.msg()}') }
	assert !is_err_value(r), 'prune on an empty flat store must succeed: ${r}'
	assert ff_attr_int(r, 'reclaimed') == 0 && ff_attr_int(r, 'objects') == 0, 'empty flat prune: ${r}'
}

fn test_flat_gc_succeeds_and_compacts_log() {
	root := ff_root('gc')
	defer {
		os.rmdir_all(root) or {}
	}
	h := ff_open('document+file://${root}', false)
	keep := ff_put(h, '[doc [item "keep"]]')
	gone := ff_put(h, '[doc [item "gone"]]')
	ff_delete(h, gone)
	r := store_stdlib_builtin_inner('store-gc', [h]) or { panic('gc: ${err.msg()}') }
	assert !is_err_value(r), 'gc on flat file:// must succeed per §15, got ${r}'
	assert r is cx.Element && (r as cx.Element).name == 'gc-result', 'gc result shape: ${r}'
	assert ff_attr_int(r, 'reclaimed') == 0, 'flat gc reclaims nothing sub-doc: ${r}'
	assert ff_attr_int(r, 'objects') == 1, 'flat gc reports live docs as objects: ${r}'
	// gc = prune + compaction: the on-disk index is now a snapshot of live state
	// (one D record for the kept doc, no tombstones, no stale records).
	mut ms := ff_ms(h)
	raw := os.read_file(ff_index_path(root)) or { panic('read index: ${err.msg()}') }
	assert raw.contains('D\t${keep}\t'), 'compacted snapshot keeps the live doc'
	assert !raw.contains('D\t${gone}\t'), 'compacted snapshot drops the deleted doc record'
	assert !raw.contains('T\t'), 'compacted snapshot carries no tombstones'
	assert ms.log_records == ms.doc_order.len + ms.alias_order.len, 'gc resets the log to live size, got ${ms.log_records}'
	// live state intact + durable
	h2 := ff_open('file://${root}', false)
	keep_c, _ := ff_canon_hash('[doc [item "keep"]]')
	assert csrp_scalar(ff_get(h2, keep)) == keep_c, 'kept doc round-trips after gc'
}

fn test_flat_gc_prune_read_only_still_denied() {
	root := ff_root('gc_ro')
	defer {
		os.rmdir_all(root) or {}
	}
	h := ff_open('document+file://${root}', false)
	ff_put(h, '[doc [item "x"]]')
	ro := ff_open('file://${root}', true)
	g := store_stdlib_builtin_inner('store-gc', [ro]) or { panic('gc: ${err.msg()}') }
	assert ff_err_code(g) == 'cx-err:CXER1110', 'gc on a read-only flat store stays denied: ${g}'
	p := store_stdlib_builtin_inner('store-prune', [ro]) or { panic('prune: ${err.msg()}') }
	assert ff_err_code(p) == 'cx-err:CXER1110', 'prune on a read-only flat store stays denied: ${p}'
}

// ── #291: delete-doc appends a tombstone, replayed on open ───────────────────

fn test_flat_delete_appends_tombstone_not_snapshot() {
	root := ff_root('tomb')
	defer {
		os.rmdir_all(root) or {}
	}
	h := ff_open('document+file://${root}', false)
	ka := ff_put(h, '[doc [item "a"]]')
	kb := ff_put(h, '[doc [item "b"]]')
	d := ff_delete(h, ka)
	assert d is cx.ScalarNode && csrp_scalar(d) == 'true', 'delete of a present doc returns true: ${d}'
	raw := os.read_file(ff_index_path(root)) or { panic('read index: ${err.msg()}') }
	// O(1) append path: the log carries the ORIGINAL D record AND the T record —
	// no whole-snapshot rewrite happened.
	assert raw.contains('T\t${ka}\t'), 'delete must append a tombstone record, index:\n${raw}'
	assert raw.contains('D\t${ka}\t'), 'the original D record stays in the log (append, not rewrite)'
	assert raw.contains('D\t${kb}\t'), 'unrelated doc record intact'
	// tombstone replays on reopen: deleted doc absent, sibling present.
	h2 := ff_open('file://${root}', false)
	ms2 := ff_ms(h2)
	assert ka !in ms2.docs, 'tombstoned doc must not replay'
	b_c, _ := ff_canon_hash('[doc [item "b"]]')
	assert csrp_scalar(ff_get(h2, kb)) == b_c, 'sibling doc replays intact'
	// deleting an absent doc is a clean false, and appends nothing new.
	before := os.file_size(ff_index_path(root))
	d2 := ff_delete(h2, ka)
	assert d2 is cx.ScalarNode && csrp_scalar(d2) == 'false', 'delete of an absent doc returns false'
	assert os.file_size(ff_index_path(root)) == before, 'a no-op delete appends no record'
}

fn test_flat_old_index_without_tombstones_replays_identically() {
	root := ff_root('oldidx')
	defer {
		os.rmdir_all(root) or {}
	}
	// Fabricate a pre-tombstone index EXACTLY as the old writer laid it out:
	// header + D records + A record. This is the #291 back-compat contract.
	c1, h1 := ff_canon_hash('[user name=al]')
	c2, h2 := ff_canon_hash('[user name=bo]')
	os.mkdir_all(root) or { panic('mkdir: ${err.msg()}') }
	mut content := 'CXSTORE\tv1\n'
	content += store_doc_record(h1, c1)
	content += store_doc_record(h2, c2)
	content += store_alias_record('current', h1)
	os.write_file(ff_index_path(root), content) or { panic('write: ${err.msg()}') }
	// bare file:// reopen (self-describing detection picks the flat model).
	h := ff_open('file://${root}', false)
	ms := ff_ms(h)
	assert ms.model == 'document', 'legacy index reopens as the flat document model'
	assert ms.doc_order == [h1, h2], 'doc order preserved from the old index'
	assert csrp_scalar(ff_get(h, h1)) == c1, 'old doc 1 replays byte-identically'
	assert csrp_scalar(ff_get(h, h2)) == c2, 'old doc 2 replays byte-identically'
	assert ms.aliases['current'] == h1, 'old alias replays'
	assert ms.log_records == 3, 'replay seeds the log count from the inherited records'
}

fn test_flat_tombstoned_doc_reput_comes_back() {
	root := ff_root('reput')
	defer {
		os.rmdir_all(root) or {}
	}
	h := ff_open('document+file://${root}', false)
	k := ff_put(h, '[doc [item "phoenix"]]')
	ff_delete(h, k)
	k2 := ff_put(h, '[doc [item "phoenix"]]')
	assert k2 == k, 'same content re-puts under the same hash'
	// replay order semantics: D, T, D → the doc is PRESENT after reopen.
	ha := ff_open('file://${root}', false)
	phoenix_c, _ := ff_canon_hash('[doc [item "phoenix"]]')
	assert csrp_scalar(ff_get(ha, k)) == phoenix_c, 're-put after tombstone must come back on replay'
	// and a trailing tombstone wins again: D, T, D, T → absent.
	ff_delete(ha, k)
	hb := ff_open('file://${root}', false)
	msb := ff_ms(hb)
	assert k !in msb.docs, 'trailing tombstone must win on replay'
}

fn test_flat_delete_heavy_log_compacts() {
	root := ff_root('compact')
	defer {
		os.rmdir_all(root) or {}
	}
	h := ff_open('document+file://${root}', false)
	keep := ff_put(h, '[doc [item "base"]]')
	// 45 put+delete cycles = 90 log records against live=1 — well past the
	// store_append redundancy threshold (2*live + 64). Tombstones MUST count
	// toward redundancy so a delete-heavy log folds to a snapshot.
	for i in 0 .. 45 {
		k := ff_put(h, '[doc [item "churn-${i}"]]')
		ff_delete(h, k)
	}
	ms := ff_ms(h)
	live := ms.doc_order.len + ms.alias_order.len
	assert live == 1, 'only the base doc stays live'
	// 91 records were appended against live=1; tombstones count toward the
	// redundancy measure, so compaction MUST have fired and the log stays
	// bounded by the store_append threshold (a tail of post-compaction appends
	// may legitimately remain, tombstones included).
	assert ms.log_records <= 2 * live + 64, 'delete-heavy log must have compacted, log_records=${ms.log_records}'
	raw := os.read_file(ff_index_path(root)) or { panic('read index: ${err.msg()}') }
	d_count := raw.count('D\t')
	t_count := raw.count('T\t')
	assert d_count + t_count == ms.log_records, 'on-disk records (${d_count}D + ${t_count}T) must match the log bookkeeping (${ms.log_records})'
	assert t_count < 45, 'compaction folds tombstoned records away, ${t_count} T records remain'
	// durability: the survivor replays.
	h2 := ff_open('file://${root}', false)
	base_c, _ := ff_canon_hash('[doc [item "base"]]')
	assert csrp_scalar(ff_get(h2, keep)) == base_c, 'base doc survives compaction'
}

// ── #298: delete-alias appends an X tombstone, replayed on open ──────────────

fn ff_set_alias(h cx.Node, alias string, hash string) {
	r := store_stdlib_builtin_inner('store-set-alias', [h, store_str(alias), store_str(hash)]) or {
		panic('set-alias: ${err.msg()}')
	}
	assert !is_err_value(r), 'set-alias must succeed: ${r}'
}

fn ff_delete_alias(h cx.Node, alias string) cx.Node {
	return store_stdlib_builtin_inner('store-delete-alias', [h, store_str(alias)]) or {
		panic('delete-alias: ${err.msg()}')
	}
}

fn test_flat_delete_alias_appends_tombstone_not_snapshot() {
	root := ff_root('atomb')
	defer {
		os.rmdir_all(root) or {}
	}
	h := ff_open('document+file://${root}', false)
	k := ff_put(h, '[doc [item "target"]]')
	ff_set_alias(h, 'cur', k)
	ff_set_alias(h, 'other', k)
	d := ff_delete_alias(h, 'cur')
	assert d is cx.ScalarNode && csrp_scalar(d) == 'true', 'delete-alias of a present alias returns true: ${d}'
	raw := os.read_file(ff_index_path(root)) or { panic('read index: ${err.msg()}') }
	// O(1) append path: the log carries the ORIGINAL A record AND the X record —
	// no whole-snapshot rewrite happened. X mirrors A's length-prefixed payload
	// shape (alias names may contain any bytes).
	assert raw.contains('X\t${'cur'.len}\t0\ncur\n'), 'delete-alias must append an X tombstone, index:\n${raw}'
	assert raw.contains('A\t${'cur'.len}\t${k}\ncur\n'), 'the original A record stays in the log (append, not rewrite)'
	// tombstone replays on reopen: deleted alias absent, sibling present.
	h2 := ff_open('file://${root}', false)
	ms2 := ff_ms(h2)
	assert 'cur' !in ms2.aliases, 'tombstoned alias must not replay'
	assert 'cur' !in ms2.alias_order, 'tombstoned alias must leave alias_order'
	assert ms2.aliases['other'] == k, 'sibling alias replays intact'
	// deleting an absent alias is a clean false, and appends nothing new.
	before := os.file_size(ff_index_path(root))
	d2 := ff_delete_alias(h2, 'cur')
	assert d2 is cx.ScalarNode && csrp_scalar(d2) == 'false', 'delete-alias of an absent alias returns false'
	assert os.file_size(ff_index_path(root)) == before, 'a no-op delete-alias appends no record'
}

fn test_flat_alias_tombstone_reset_comes_back() {
	root := ff_root('areset')
	defer {
		os.rmdir_all(root) or {}
	}
	h := ff_open('document+file://${root}', false)
	k1 := ff_put(h, '[doc [item "v1"]]')
	k2 := ff_put(h, '[doc [item "v2"]]')
	ff_set_alias(h, 'ptr', k1)
	ff_delete_alias(h, 'ptr')
	ff_set_alias(h, 'ptr', k2)
	// replay order semantics: A, X, A → the alias is PRESENT at its LAST target.
	ha := ff_open('file://${root}', false)
	msa := ff_ms(ha)
	assert msa.aliases['ptr'] == k2, 're-set alias after tombstone must come back at the new target'
	assert msa.alias_order.filter(it == 'ptr').len == 1, 'alias_order holds the re-set alias exactly once'
	// and a trailing tombstone wins again: A, X, A, X → absent.
	ff_delete_alias(ha, 'ptr')
	hb := ff_open('file://${root}', false)
	msb := ff_ms(hb)
	assert 'ptr' !in msb.aliases, 'trailing alias tombstone must win on replay'
}

fn test_flat_delete_alias_heavy_log_compacts() {
	root := ff_root('acompact')
	defer {
		os.rmdir_all(root) or {}
	}
	h := ff_open('document+file://${root}', false)
	k := ff_put(h, '[doc [item "abase"]]')
	ff_set_alias(h, 'keep', k)
	// 45 set+delete cycles = 90 log records against live=2 (1 doc + 1 alias) —
	// past the store_append threshold (2*live + 64). Alias tombstones MUST count
	// toward redundancy so a delete-alias-heavy log folds to a snapshot.
	for i in 0 .. 45 {
		ff_set_alias(h, 'churn-${i}', k)
		ff_delete_alias(h, 'churn-${i}')
	}
	ms := ff_ms(h)
	live := ms.doc_order.len + ms.alias_order.len
	assert live == 2, 'only the base doc + kept alias stay live'
	assert ms.log_records <= 2 * live + 64, 'delete-alias-heavy log must have compacted, log_records=${ms.log_records}'
	raw := os.read_file(ff_index_path(root)) or { panic('read index: ${err.msg()}') }
	recs := raw.count('D\t') + raw.count('A\t') + raw.count('T\t') + raw.count('X\t')
	assert recs == ms.log_records, 'on-disk records (${recs}) must match the log bookkeeping (${ms.log_records})'
	assert raw.count('X\t') < 45, 'compaction folds alias-tombstoned records away, ${raw.count('X\t')} X records remain'
	// durability: the survivors replay.
	h2 := ff_open('file://${root}', false)
	ms2 := ff_ms(h2)
	assert ms2.aliases['keep'] == k, 'kept alias survives compaction'
}

// ── #292: open sweeps stale .cxstore-index.tmp.<pid> orphans ─────────────────

// ff_dead_pid returns a pid that is guaranteed not to be a live process: it
// spawns /usr/bin/true and waits for it to exit.
fn ff_dead_pid() int {
	mut p := os.new_process('/usr/bin/true')
	p.run()
	p.wait()
	assert p.pid > 0, 'spawn for dead-pid fixture failed'
	return p.pid
}

fn test_open_sweeps_stale_tmp_files() {
	root := ff_root('sweep')
	defer {
		os.rmdir_all(root) or {}
	}
	h := ff_open('document+file://${root}', false)
	k := ff_put(h, '[doc [item "survivor"]]')
	idx := ff_index_path(root)
	dead := ff_dead_pid()
	stale := '${idx}.tmp.${dead}'
	live_tmp := '${idx}.tmp.${os.getpid()}' // our own pid = a live writer's in-flight persist
	weird := '${idx}.tmp.not-a-pid' // unknown shape — never touched
	os.write_file(stale, '') or { panic('stale fixture: ${err.msg()}') }
	os.write_file(live_tmp, 'in-flight') or { panic('live fixture: ${err.msg()}') }
	os.write_file(weird, 'unknown') or { panic('weird fixture: ${err.msg()}') }
	// reopen → the dead writer's orphan is swept; everything else untouched.
	h2 := ff_open('file://${root}', false)
	assert !os.exists(stale), 'stale tmp from a dead pid must be swept at open'
	assert os.exists(live_tmp), 'a live pid tmp (in-flight persist) is never touched'
	assert os.exists(weird), 'non-pid-suffixed files are never touched'
	assert os.exists(idx), 'the live index is never touched'
	survivor_c, _ := ff_canon_hash('[doc [item "survivor"]]')
	assert csrp_scalar(ff_get(h2, k)) == survivor_c, 'store content intact after sweep'
	os.rm(live_tmp) or {}
	os.rm(weird) or {}
}

fn test_read_only_open_does_not_sweep() {
	root := ff_root('sweep_ro')
	defer {
		os.rmdir_all(root) or {}
	}
	h := ff_open('document+file://${root}', false)
	ff_put(h, '[doc [item "x"]]')
	idx := ff_index_path(root)
	dead := ff_dead_pid()
	stale := '${idx}.tmp.${dead}'
	os.write_file(stale, '') or { panic('stale fixture: ${err.msg()}') }
	// a read-only open holds only the read grant — it must not delete files.
	ff_open('file://${root}', true)
	assert os.exists(stale), 'read-only open must not sweep (no write grant)'
	os.rm(stale) or {}
}
