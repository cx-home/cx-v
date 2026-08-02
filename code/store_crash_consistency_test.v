module code

import cx
import cxstore
import hash.crc32
import os

// store_crash_consistency_test.v — #624: a file:// cxpack store survives an
// unclean shutdown at ANY point with a clean verdict — either it opens (at
// worst discarding the torn, never-acknowledged tail record) or it refuses
// with a typed integrity error. Never a crash, never data loss of an acked
// record, never a silently partial view. Pins the three crash windows the
// pre-#624 write path lost to, plus the WAL torn-tail discard.

fn cc_root(tag string) string {
	return os.join_path(os.temp_dir(), 'cxpack_crash_${tag}_${os.getpid()}')
}

fn cc_new(root string) &MemStore {
	return &MemStore{
		url:     'file://${root}'
		backend: 'cxpack'
		root:    root
		is_open: true
	}
}

fn cc_put(mut ms MemStore, text string) string {
	doc := cx.parse(text) or { panic('parse: ${text}') }
	c := render_canonical(doc.elements[0])
	h := cx.cx_text_hash(c) or { panic('hash') }
	store_put_canonical(mut ms, h, c) or { panic('put: ' + err.msg()) }
	store_cxpack_flush(mut ms) or { panic('flush: ${err.msg()}') }
	return h
}

// The pre-#624 compaction CRASH WINDOW: the pack fold had already destroyed
// GC'd objects while the OLD append-log manifest (with its superseded /
// tombstoned lines) was still on disk. With the reordered compaction the
// window no longer exists going forward, and the two-pass replay makes a
// store already damaged that way load cleanly: its dangling doc references
// are all tombstoned later in the same log, and only the FINAL live state is
// verified.
fn test_pre624_compaction_crash_window_store_recovers() {
	root := cc_root('window')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	mut ms := cc_new(root)
	keep := cc_put(mut ms, '[keep [k 1]]')
	doomed := cc_put(mut ms, '[doomed [unique "not-shared-with-keep"] [deep [x "y"]]]')
	store_delete_local(mut ms, doomed)
	store_cxpack_flush(mut ms) or { panic('flush: ${err.msg()}') } // T tombstone appended
	// Simulate the old-ordering crash: objects GC'd (compacted pack + segments
	// replaced by the live set) while the APPEND-LOG manifest survives.
	old_manifest := os.read_file(os.join_path(root, cxpack_manifest)) or { panic('read manifest') }
	store_cxpack_compact(mut ms) or { panic('compact: ${err.msg()}') }
	os.write_file(os.join_path(root, cxpack_manifest), old_manifest) or { panic('write manifest') }

	mut ms2 := cc_new(root)
	store_cxpack_load(mut ms2) or {
		panic('a pre-#624 crash-window store must RECOVER, got: ${err.msg()}')
	}
	assert ms2.doc_order == [keep], 'live doc must survive recovery (got ${ms2.doc_order})'
	assert store_doc_present(ms2, keep)
	assert !store_doc_present(ms2, doomed), 'tombstoned doc must stay gone'
}

// TORN TAIL: a kill mid-append tears the manifest's final line structurally.
// The record was never acknowledged (its flush never returned) — the loader
// discards it loudly and opens at the last whole state. An acked (whole)
// record is never dropped.
fn test_torn_manifest_tail_is_discarded_not_fatal() {
	root := cc_root('torn')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	mut ms := cc_new(root)
	h1 := cc_put(mut ms, '[a [x 1]]')
	h2 := cc_put(mut ms, '[b [y 2]]')
	mp := os.join_path(root, cxpack_manifest)
	whole := os.read_file(mp) or { panic('read manifest') }
	// tear the final record mid-hash (what a kill mid-write leaves)
	assert whole.ends_with('\n')
	torn := whole[..whole.len - 20]
	os.write_file(mp, torn) or { panic('write torn') }

	mut ms2 := cc_new(root)
	store_cxpack_load(mut ms2) or { panic('torn tail must not refuse the store: ${err.msg()}') }
	// h1's records are earlier lines — the acked doc survives; the torn final
	// record is discarded (whichever doc/alias it carried).
	assert store_doc_present(ms2, h1), 'acked doc lost to a torn tail'
	assert ms2.doc_order.len >= 1
	// a torn line ANYWHERE ELSE stays a hard integrity error
	mut mid := whole.split_into_lines().filter(it.trim_space() != '')
	assert mid.len >= 2
	mid[0] = mid[0][..mid[0].len - 5] // tear the FIRST record instead
	os.write_file(mp, mid.join('\n') + '\n') or { panic('write mid-torn') }
	mut ms3 := cc_new(root)
	if _ := store_cxpack_load(mut ms3) {
		assert false, 'a torn NON-final record must be a hard integrity error'
	} else {
		assert ms3.doc_order.len == 0, 'refused load must leave no partial state'
	}
	_ = h2
}

// A kill mid-segment-write must never expose a torn pack at a segment's final
// name: the writer goes through a temp sibling + atomic rename, discovery
// ignores the .tmp, and the store reopens whole without the in-flight flush.
fn test_stray_segment_tmp_is_ignored() {
	root := cc_root('tmpseg')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	mut ms := cc_new(root)
	h1 := cc_put(mut ms, '[a [x 1]]')
	// what a kill mid-flush_segment leaves: a partial pack at the temp name
	next_seg := os.join_path(root, cxpack_seg_name(ms.obj_pack.segment_count()))
	os.write_file(next_seg + '.tmp', 'PARTIAL-GARBAGE-NOT-A-PACK') or { panic('write tmp') }

	mut ms2 := cc_new(root)
	store_cxpack_load(mut ms2) or { panic('a stray segment .tmp must be invisible: ${err.msg()}') }
	assert store_doc_present(ms2, h1)
	// and a TRUNCATED pack at a FINAL segment name (pre-#624 direct writes
	// could leave one) refuses with a typed error — never a crash.
	seg0 := os.join_path(root, cxpack_seg_name(0))
	whole := os.read_bytes(seg0) or { panic('read seg0') }
	os.write_file_array(seg0, whole[..whole.len / 2]) or { panic('truncate seg0') }
	mut ms3 := cc_new(root)
	if _ := store_cxpack_load(mut ms3) {
		assert false, 'a truncated pack at a final segment name must refuse loudly'
	}
}

// Corrupt pack internals (a lying index count / garbage entry offsets) yield
// typed refusals from the reader — pinned at the cxstore layer so the mmap
// path can never walk out of bounds (#624's SIGBUS leg).
fn test_pack_reader_bounds_are_checked() {
	root := cc_root('bounds')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	os.mkdir_all(root) or { panic(err) }
	p := os.join_path(root, 'p.cxpack')
	cxstore.write_pack(p, ['payload-one'.bytes(), 'payload-two'.bytes()]) or { panic(err.msg()) }
	mut data := os.read_bytes(p) or { panic('read pack') }
	// footer layout: …[index_count u32][records]…[footer_crc32][flen u64].
	// Overwrite index_count with a huge value AND refresh the footer crc so
	// the count check (not the crc) is what refuses.
	flen := int(u64(data[data.len - 8]) | (u64(data[data.len - 7]) << 8) | (u64(data[data.len - 6]) << 16) | (u64(data[data.len - 5]) << 24))
	fstart := data.len - 8 - flen
	data[fstart] = 0xff
	data[fstart + 1] = 0xff
	data[fstart + 2] = 0xff
	data[fstart + 3] = 0x7f
	refreshed := crc32.sum(data[fstart..data.len - 12])
	data[data.len - 12] = u8(refreshed & 0xff)
	data[data.len - 11] = u8((refreshed >> 8) & 0xff)
	data[data.len - 10] = u8((refreshed >> 16) & 0xff)
	data[data.len - 9] = u8((refreshed >> 24) & 0xff)
	os.write_file_array(p, data) or { panic('rewrite') }
	if _ := cxstore.open_pack(p) {
		assert false, 'a pack whose index count exceeds its footer must refuse'
	}
}
