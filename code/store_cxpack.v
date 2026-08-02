module code

import cxstore
import os
import encoding.hex
import time

// cxpack:// backend persistence for the [$store] stdlib (additive — mem:// and
// file:// paths are untouched). The store's in-memory MemStore model is the
// session surface (all store methods operate on it unchanged); cxpack:// swaps
// the *persistence format* from the flat file index to the content-addressed
// pack engine (vcx/cxstore).
//
// SUBTREE-GRANULAR (#129): each doc is content-addressed into the engine's
// object graph (cxstore.store_document): every element becomes a Node object
// (children stripped, addressed via a seqtree spine) and every scalar a Leaf,
// so identical subtrees dedup across documents AND across versions of a doc
// (a one-field edit re-stores only the path from the change to the root; every
// untouched subtree object is shared). The manifest maps each store hash to its
// document-root object hash; alias names persist as raw leaf objects.
//
// Byte-exactness: the store hashes docs with render_canonical (code) and
// store-get-doc re-verifies cx_text_hash(text) == hash. On load each doc is
// reconstructed from the object graph (cxstore.load_document_from) and
// re-rendered with render_canonical — which reproduces the exact canonical bytes
// (proven across varied + adversarial constructs in
// store_subtree_objectmodel_test.v), so the store hash is preserved.
//
// PERSIST MODEL: incremental (#129-B). A mutation flushes only the DELTA since
// the last flush — the objects new to the graph go into a fresh segment pack
// `store-NNNN.cxpack`, and the new/changed/removed manifest entries are appended
// to an append-only manifest (`os.open_append`). So the durable disk work per
// mutation is O(delta) — only the new objects/records — instead of the O(live)
// re-serialization the old whole-pack snapshot did on every mutation (an O(N²)
// total cost for N puts). When
// segments — or manifest redundancy from updates/removals — accumulate past a
// threshold, the store is COMPACTED: every live object is reachability-marked
// (cxstore.mark_live), folded into a single `store.cxpack`, the manifest is
// rewritten as a clean snapshot, the segment packs are deleted, and objects no
// longer referenced by any live doc/code root or alias are reclaimed. Load
// discovers every pack (the compacted one + all segments) and replays the
// manifest, so the layout is transparent to readers.

const cxpack_manifest = '.cxpack-manifest'
const cxpack_pack = 'store.cxpack' // the compacted single pack
const cxpack_seg_prefix = 'store-' // store-NNNN.cxpack incremental segments
const cxpack_seg_suffix = '.cxpack'
// Compact once this many segment packs accrue (bounds the open-pack count and
// the cross-pack index rebuild on load).
const cxpack_compact_segments = 16

// cxpack_seg_name is the filename of segment N (zero-padded so a lexical sort of
// the directory listing is also the numeric order up to 9999 — compaction at 16
// keeps the live count far below that).
fn cxpack_seg_name(n int) string {
	mut s := n.str()
	for s.len < 4 {
		s = '0' + s
	}
	return '${cxpack_seg_prefix}${s}${cxpack_seg_suffix}'
}

// cxpack_seg_index parses the numeric index out of a segment filename, or -1 if
// the name is not a segment pack.
fn cxpack_seg_index(name string) int {
	if !name.starts_with(cxpack_seg_prefix) || !name.ends_with(cxpack_seg_suffix) {
		return -1
	}
	mid := name[cxpack_seg_prefix.len..name.len - cxpack_seg_suffix.len]
	if mid == '' {
		return -1
	}
	for c in mid {
		if c < `0` || c > `9` {
			return -1
		}
	}
	return mid.int()
}

// cxpack_discover_packs lists the store's pack files under `root`: the compacted
// `store.cxpack` (if present) first, then every `store-NNNN.cxpack` segment in
// numeric order. Returns the absolute paths plus the highest segment index seen
// (-1 if none), used to seed seg_count on load.
fn cxpack_discover_packs(root string) ([]string, int) {
	mut paths := []string{}
	mut max_seg := -1
	if os.exists(os.join_path(root, cxpack_pack)) {
		paths << os.join_path(root, cxpack_pack)
	}
	entries := os.ls(root) or { []string{} }
	mut segs := []int{}
	for e in entries {
		idx := cxpack_seg_index(e)
		if idx >= 0 {
			segs << idx
		}
	}
	segs.sort()
	for idx in segs {
		paths << os.join_path(root, cxpack_seg_name(idx))
		if idx > max_seg {
			max_seg = idx
		}
	}
	return paths, max_seg
}

// store_cxpack_flush incrementally persists everything new since the last flush:
// the objects new to the live graph go into a fresh segment pack, and the
// new/changed/removed manifest entries are appended to the append-only manifest
// (removals as T/X tombstones). The mutation hooks (store_persist / store_append)
// route here for backend 'cxpack'. When segments or manifest redundancy build up,
// it folds them back via store_cxpack_compact.
//
// COST (#603): O(delta) end to end — both the DURABLE work (serialize/compress/
// hash/CRC only the objects new since the last flush; append only the new
// manifest records) AND the in-memory diff that finds it. The diff used to be an
// O(live) scan per mutation, which made every journal append O(journal) and sank
// publish latency linearly with history; store_graph_delta now walks only the
// doc_order tail past its scan cursor, the dirty-alias list, and (when a delete
// happened) the manifested maps. The manifested/obj_flushed watermarks remain
// the single source of truth for "what is durable" — they advance strictly
// after the segment + manifest land, so a crash or failed flush between the two
// just re-emits the same pending delta next time (self-healing unchanged).
fn store_cxpack_flush(mut ms MemStore) ! {
	if ms.root == '' {
		return
	}
	tr := fab_trace_on()
	t0 := time.sys_mono_now()
	store_cxpack_backend(mut ms)!
	os.mkdir_all(ms.root) or { return error('cxpack ${ms.root}: mkdir failed: ${err.msg()}') }

	// 1. OBJECT layer (through the seam): stage every object new to the live graph
	//    into the pack ObjectBackend. put_object is content-addressed and idempotent
	//    — an object already durable in some pack (the backend's flushed watermark)
	//    is skipped, so only objects new since the last flush are staged. This is
	//    the live consumer of persist_objects/put_object (#76 seam, spec §7.1):
	//    cxpack persistence now routes THROUGH the object interface, not a hardcoded
	//    write_pack of a caller-diffed payload list. #229: on an encrypted store
	//    the objects route through the EncryptingWrapper instead — same seam, same
	//    plaintext keys, AEAD envelopes staged keyed on the pack backend.
	// #603: stage only the sink TAIL past the durability watermark — the
	// per-mutation flush is O(delta), not O(every object ever). The
	// watermark advances at step 5 (after the segment + manifest land), so
	// a failed flush re-stages the same tail (self-healing unchanged).
	mut staged_upto := 0
	if ms.enc_key_id != '' {
		staged_upto = cxstore.persist_objects_from(mut ms.obj_pack_enc, ms.obj_sink, ms.obj_flushed) or {
			return error('cxpack ${ms.root}: object stage failed: ${err.msg()}')
		}
	} else {
		staged_upto = cxstore.persist_objects_from(mut ms.obj_pack, ms.obj_sink, ms.obj_flushed) or {
			return error('cxpack ${ms.root}: object stage failed: ${err.msg()}')
		}
	}

	// 2. Manifest delta (the REFS layer — store-key → doc-root, and aliases):
	//    the ONE shared O(delta) computation (store_graph_delta, #603 — the
	//    former inline copy here is retired). The alias NAMES the A/X records
	//    reference are themselves content-addressed objects (raw leaves of the
	//    name bytes); stage them through the seam so replay can resolve them
	//    (put_object dedups if already present — re-staging a tombstoned name
	//    is an idempotent no-op that also self-heals a missing name object).
	t_staged := time.sys_mono_now()
	d := store_graph_delta(ms)
	for a, _ in d.set_aliases {
		store_cxpack_stage(mut ms, a.bytes()) or {
			return error('cxpack ${ms.root}: alias-name object stage failed: ${err.msg()}')
		}
	}
	for a in d.removed_aliases {
		store_cxpack_stage(mut ms, a.bytes()) or {
			return error('cxpack ${ms.root}: alias-tombstone object stage failed: ${err.msg()}')
		}
	}
	lines := d.lines

	if ms.obj_pack.pending_count() == 0 && lines.len == 0 {
		// Nothing reached the disk, but the scan window is settled: the staged
		// tail deduped to already-durable objects and the delta was empty —
		// advance the #603 watermarks so the same ground is not re-walked.
		ms.obj_flushed = staged_upto
		store_graph_delta_commit(mut ms, d)
		return
	}

	t_delta := time.sys_mono_now()
	pending := ms.obj_pack.pending_count()
	// 3. Flush the staged objects as a fresh segment pack — durable BEFORE the
	//    manifest references them, so a crash between the two leaves unreferenced
	//    objects (reclaimed at compaction), never a dangling manifest pointer.
	ms.obj_pack.flush_segment() or {
		return error('cxpack ${ms.root}: segment flush failed: ${err.msg()}')
	}
	t_seg := time.sys_mono_now()

	// 4. Append the manifest deltas (no header — load splits on lines). #624:
	//    fsync before the watermarks advance — the receipt the caller returns
	//    means power-loss durable, not just in the page cache. A kill mid-append
	//    can still tear the TRAILING line; the loader treats a torn tail as
	//    WAL discard (that flush never returned, so nothing acked is lost).
	mp := os.join_path(ms.root, cxpack_manifest)
	blob := lines.join('\n') + '\n'
	if lines.len > 0 {
		if os.exists(mp) {
			mut f := os.open_append(mp) or {
				return error('cxpack ${ms.root}: manifest open failed: ${err.msg()}')
			}
			f.write_string(blob) or {
				f.close()
				return error('cxpack ${ms.root}: manifest append failed: ${err.msg()}')
			}
			f.flush()
			C.fsync(f.fd)
			f.close()
		} else {
			store_write_file_sync(mp, blob) or {
				return error('cxpack ${ms.root}: manifest write failed: ${err.msg()}')
			}
		}
	}

	t_manifest := time.sys_mono_now()
	// 5. Advance the watermarks now that the deltas are durable.
	ms.obj_flushed = staged_upto
	store_graph_delta_commit(mut ms, d)

	// 6. Amortization work — never on this receipt's critical path. #617: the
	//    #603 size-tiered segment fold runs OFF the flush turn (background
	//    worker on locked stores; inline only for lockless direct-model
	//    stores — see store_cxpack_fold.v). Kicked BEFORE the compaction
	//    check so a fold backlog reads as fold_pending (should_compact stays
	//    false) instead of tripping the O(live) full compaction.
	store_cxpack_fold_kick(mut ms)!
	//    Compaction proper: fold segments back into one pack when a genuine
	//    16-tier tower accrues, or when the append-only manifest carries
	//    materially more records than live state (updates/removals leave
	//    superseded lines that only a rewrite clears).
	live := ms.doc_order.len + ms.alias_order.len
	mut compacted := false
	if ms.obj_pack.should_compact() || ms.log_records > 2 * live + 64 {
		store_cxpack_compact(mut ms)!
		compacted = true
	}
	if tr {
		t_done := time.sys_mono_now()
		eprintln('[fab-trace side=store step=cxpack-flush objs=${pending} lines=${lines.len} live=${live} stage-us=${(t_staged - t0) / 1000} delta-us=${(t_delta - t_staged) / 1000} seg-us=${(t_seg - t_delta) / 1000} manifest-us=${(t_manifest - t_seg) / 1000} compact=${compacted} compact-us=${(t_done - t_manifest) / 1000} total-us=${(t_done - t0) / 1000}]')
	}
}

// store_cxpack_backend lazily ensures the pack ObjectBackend exists for this store
// (the open path sets it, but tests construct a MemStore directly). The backend is
// rooted at ms.root and owns the object-layer durability; this MemStore keeps the
// refs layer. #229: with enc_key_id set the backend opens in KEYED mode (v2
// packs) and an EncryptingWrapper is attached over it — fail-closed here on a
// missing/malformed KEK, so an encrypted store can never be touched keyless.
fn store_cxpack_backend(mut ms MemStore) ! {
	if ms.obj_pack == unsafe { nil } {
		ms.obj_pack = if ms.enc_key_id != '' {
			cxstore.open_pack_object_backend_keyed(ms.root)
		} else {
			cxstore.open_pack_object_backend(ms.root)
		}
	}
	if ms.enc_key_id != '' && ms.obj_pack_enc == unsafe { nil } {
		kms := store_kek_kms(ms.enc_key_id)!
		ms.obj_pack_enc = cxstore.new_encrypting_wrapper(ms.obj_pack, ms.enc_key_id, kms)
	}
}

// store_write_file_sync writes content to path and fsyncs it before returning
// (#624): the caller is about to treat the file as durable (rename it over a
// live manifest, or return a durability receipt) — without the fsync a power
// loss could drop acked bytes. Process kill alone never loses completed
// writes (page cache), but the journal contract is power-loss durability.
fn store_write_file_sync(path string, content string) ! {
	mut f := os.create(path)!
	f.write_string(content) or {
		f.close()
		return err
	}
	f.flush()
	C.fsync(f.fd)
	f.close()
}

fn C.fsync(fd int) int

// store_cxpack_stage stages one content-addressed object on the store's pack
// backend, routing through the EncryptingWrapper when the store is encrypted
// (#229) — the returned key is the PLAINTEXT hash either way, so the refs layer
// is mode-blind.
fn store_cxpack_stage(mut ms MemStore, payload []u8) ![]u8 {
	if ms.enc_key_id != '' {
		return ms.obj_pack_enc.put_object(payload)
	}
	return ms.obj_pack.put_object(payload)
}

// store_cxpack_compact folds every accumulated segment pack into a single
// content-addressed pack and rewrites the manifest as a clean snapshot of live
// state. Reachability is the authority (cxstore.mark_live from the live doc/code
// roots + alias-name objects): objects no longer referenced by anything live are
// dropped from both the persisted pack AND the in-memory sink — the promised
// "unreferenced objects are reclaimed at compaction". Resets all incremental
// watermarks. Also the full-snapshot entry point used directly by tests.
fn store_cxpack_compact(mut ms MemStore) ! {
	if ms.root == '' {
		return
	}
	store_cxpack_backend(mut ms)!
	os.mkdir_all(ms.root) or { return error('cxpack ${ms.root}: mkdir failed: ${err.msg()}') }

	// Live roots: every doc/code root object (alias names are leaves with no
	// outgoing edges, handled explicitly below so they survive even when a caller
	// populated aliases without routing the name through the sink, e.g. tests).
	mut roots := [][]u8{}
	for _, r in ms.obj_roots {
		roots << r
	}
	// Reachability over the live in-memory graph, resolved through the seam.
	getter := cxstore.getter_of(ms.obj_sink)
	live := cxstore.mark_live(getter, roots)

	mut payloads := [][]u8{cap: live.len + ms.alias_order.len}
	for _, p in live {
		payloads << p
	}
	// Prune the in-memory sink to the reachable doc/code objects so memory does
	// not grow unboundedly across delete/put cycles (mirrors the on-disk GC).
	mut pruned := cxstore.ObjectSink{}
	for hk, p in live {
		pruned.objects[hk] = p
	}
	ms.obj_sink = pruned

	// Alias name objects (explicit — a deleted alias's name is not a root, so it
	// is correctly excluded).
	mut name_hashes := map[string]bool{}
	mut name_payloads := [][]u8{}
	for a in ms.alias_order {
		nb := a.bytes()
		nk := cxstore.object_name(nb).hex()
		if nk !in name_hashes {
			payloads << nb
			name_payloads << nb
			name_hashes[nk] = true
		}
	}

	// #624 CRASH ORDERING: land the manifest SNAPSHOT before the pack fold.
	// The snapshot references only live docs/aliases, whose objects are all
	// durable in the CURRENT pack+segments — so a kill after the snapshot but
	// before the fold leaves a loadable store (extra unreferenced objects,
	// reclaimed next compaction). The OLD order (pack fold first) destroyed
	// objects that the still-on-disk append-log manifest referenced through
	// superseded/tombstoned lines: a kill in that window made the store
	// unloadable (E_STORE_INTEGRITY_MISMATCH on reopen — the #624 corruption).
	//
	// Rewrite the manifest as a clean snapshot (live D/C/A only — no
	// tombstones). Temp-file (fsynced) + atomic rename: a reopen sees either
	// the old or the new manifest, whole.
	mut lines := []string{}
	for h in ms.doc_order {
		root := ms.obj_roots[h] or { continue }
		rec := if h.starts_with('code:') { 'C' } else { 'D' }
		lines << '${rec}\t${h}\t${root.hex()}'
	}
	for a in ms.alias_order {
		dh := ms.aliases[a] or { continue }
		nk := cxstore.object_name(a.bytes()).hex()
		lines << 'A\t${nk}\t${dh}'
	}
	mp := os.join_path(ms.root, cxpack_manifest)
	tmp := mp + '.tmp.${os.getpid()}'
	store_write_file_sync(tmp, lines.join('\n') + '\n') or {
		return error('cxpack ${ms.root}: manifest snapshot write failed: ${err.msg()}')
	}
	os.mv(tmp, mp) or {
		os.rm(tmp) or {}
		return error('cxpack ${ms.root}: manifest snapshot rename failed: ${err.msg()}')
	}

	// Fold every live object into a single compacted pack through the backend; it
	// drops the now-folded segments and resets its durable watermark to exactly the
	// reachable set (the on-disk GC — objects no longer referenced are reclaimed).
	// #229: an encrypted store compacts ENVELOPES — each live key's at-rest bytes
	// are read back raw (staged or durable) and folded verbatim, so compaction
	// never decrypts or re-encrypts; a payload with no envelope yet (e.g. a direct
	// compact call before any flush) is sealed fresh through the wrapper.
	if ms.enc_key_id != '' {
		mut entries := []cxstore.KeyedPayload{cap: live.len + name_payloads.len}
		mut folded := map[string]bool{}
		for hk, p in live {
			key := hex.decode(hk) or {
				return error('cxpack ${ms.root}: bad live object key ${hk}: ${err.msg()}')
			}
			env := ms.obj_pack.get_object_raw(key) or {
				ms.obj_pack_enc.seal_envelope(key, p) or {
					return error('cxpack ${ms.root}: compaction seal failed for ${hk}: ${err.msg()}')
				}
			}
			entries << cxstore.KeyedPayload{
				key:  key
				blob: env
			}
			folded[hk] = true
		}
		for nb in name_payloads {
			key := cxstore.object_name(nb)
			if key.hex() in folded {
				continue
			}
			env := ms.obj_pack.get_object_raw(key) or {
				ms.obj_pack_enc.seal_envelope(key, nb) or {
					return error('cxpack ${ms.root}: compaction seal failed for alias name: ${err.msg()}')
				}
			}
			entries << cxstore.KeyedPayload{
				key:  key
				blob: env
			}
		}
		ms.obj_pack.write_compacted_keyed(entries) or {
			return error('cxpack ${ms.root}: compacted pack write failed: ${err.msg()}')
		}
	} else {
		ms.obj_pack.write_compacted(payloads) or {
			return error('cxpack ${ms.root}: compacted pack write failed: ${err.msg()}')
		}
	}

	// Reset the watermarks to the compacted state: the full live state is durable
	// here (the pack backend's own watermark was reset by write_compacted; the
	// sink was pruned to exactly the reachable set above, all of it durable).
	store_graph_seed_watermarks(mut ms)
	ms.obj_flushed = ms.obj_sink.objects.len
	ms.log_records = ms.doc_order.len + ms.alias_order.len
}

// store_cxpack_load restores the LIVE object graph (#129-A): every object across
// every pack — the compacted `store.cxpack` plus all `store-NNNN.cxpack`
// segments (#129-B) — is loaded into ms.obj_sink (so the in-memory graph and its
// dedup are live after open), and obj_roots/doc_order/aliases are rebuilt by
// replaying the append-only manifest top-to-bottom (D/C set, A set last-wins,
// T/X remove). `docs` stays empty; reads reconstruct from the sink.
//
// INTEGRITY (#129-C): genuine corruption — an unreadable/unopenable pack, a
// malformed manifest line, a bad object hash, a referenced object missing from
// every pack, or a doc that reconstructs to nothing — is a HARD ERROR, never a
// silent skip. A silently-dropped doc is data loss masquerading as success. Only
// true non-data conditions are tolerated: a store that was never persisted (no
// files = fresh, empty), blank manifest lines, and unknown record types.
fn store_cxpack_load(mut ms MemStore) ! {
	store_cxpack_backend(mut ms)!
	mp := os.join_path(ms.root, cxpack_manifest)
	pack_paths, _ := ms.obj_pack.discover_packs()
	if !os.exists(mp) && pack_paths.len == 0 {
		return
	}
	if !os.exists(mp) || pack_paths.len == 0 {
		return error('cxpack store at ${ms.root} is incomplete (manifest/pack missing) — refusing to open a partially-present store')
	}
	// Load every object through the seam (the backend discovers segments +
	// compacted pack, reads each object once, and records its durable watermark +
	// segment number). Identical objects across packs collapse in the sink (dedup).
	// A bad pack/object is a HARD error inside load_objects (#129-C / spec §4) —
	// as is a keyed(v2)↔plaintext(v1) mode mismatch (an encrypted store opened
	// without its key, or a key given for a plaintext store).
	// #637 LAZY (the default): skip the whole-graph slurp — open populates only
	// the REFS layer below, and objects page in on first touch through the
	// composite getter (self-verifying, so corruption still refuses loudly at
	// that touch). Boot then costs O(refs) instead of O(live set), and RSS
	// tracks the working set rather than the whole graph. The eager
	// whole-graph reconstruction that used to run at every open is now the
	// explicit `[$store:verify]` pass (§ store.md), runnable on demand or in
	// the background. `[opts eager="true"]` restores load-time verification
	// for a caller that wants it inline.
	if ms.lazy_objects {
		return store_cxpack_load_refs(mut ms, mp)
	}
	objs := ms.obj_pack.load_objects()!
	if ms.enc_key_id != '' {
		// #229: the loaded bytes are AEAD envelopes keyed by the plaintext hash —
		// decrypt + verify each into the live sink. A wrong KEK / tampered
		// envelope is a HARD open error (fail-closed), never a silent wrong doc.
		for hx, env in objs {
			key := hex.decode(hx) or {
				return error('cxpack ${ms.root}: bad object key ${hx}: ${err.msg()}')
			}
			payload := ms.obj_pack_enc.open_envelope(key, env) or {
				return error('cxpack ${ms.root}: object ${hx} failed to decrypt (wrong KEK or corrupt envelope): ${err.msg()}')
			}
			ms.obj_sink.put(payload)
		}
	} else {
		for _, payload in objs {
			ms.obj_sink.put(payload)
		}
	}
	return store_cxpack_replay(mut ms, mp, true)
}

// store_cxpack_load_refs is the #637 LAZY open: replay the refs layer with no
// whole-graph slurp and no load-time doc reconstruction. Alias-name objects
// (the few the replay itself needs) page in through the composite getter.
fn store_cxpack_load_refs(mut ms MemStore, mp string) ! {
	// The eager path seeded the pack backend's durability state as a side
	// effect of slurping every object; a lazy open seeds it from the pack
	// INDEXES instead (hash lists, never payloads — O(objects) index entries,
	// no bytes materialized). Without this the next flush would restart the
	// segment numbering and overwrite a pack on disk, and put_object would
	// re-persist objects already durable.
	ms.obj_pack.seed_index()!
	return store_cxpack_replay(mut ms, mp, false)
}

// store_cxpack_replay applies the manifest's append-log to the refs layer.
// `verify_docs` runs the #129-C whole-graph pass (every live doc must
// reconstruct) — true on an eager open, false on a lazy one, where the same
// guarantee is enforced per-object at first touch (the self-verifying getter)
// and wholesale by the explicit `[$store:verify]` pass.
fn store_cxpack_replay(mut ms MemStore, mp string, verify_docs bool) ! {
	// the COMPOSITE getter: the sink for an eager open (already whole), the
	// pack backend for a lazy one (paging + caching per hash).
	getter := store_graph_getter(ms)
	content := os.read_file(mp) or {
		return error('cxpack manifest ${mp} unreadable: ${err.msg()}')
	}

	// #624 TWO-PASS REPLAY. Pass 1 applies the append-log records to the refs
	// maps WITHOUT verifying doc reconstruction; pass 2 verifies exactly the
	// FINAL live state. Eager per-line verification was wrong twice over: it
	// hard-failed on docs a LATER tombstone removes (whose objects a compaction
	// legitimately reclaimed — the pre-#624 crash-window corruption, now also
	// the recovery path for stores damaged by the old ordering), and it did
	// wasted graph walks for superseded records.
	//
	// TORN TAIL (WAL discard): a kill mid-append can tear the manifest's LAST
	// line STRUCTURALLY — wrong field count, or a truncated/odd hex hash. The
	// flush that wrote it never returned, so nothing acked is lost; the tail
	// is discarded LOUDLY (stderr) and the store opens at the last whole
	// record. The rule is deliberately structural-only: the flush fsyncs the
	// segment BEFORE the manifest line, so a structurally whole record always
	// has durable objects — a whole record that fails pass-2 verification is
	// GENUINE corruption and stays a hard error (#129-C), as does any
	// structural defect before the final record.
	all_lines := content.split_into_lines()
	mut recs := [][]string{cap: all_lines.len}
	for line in all_lines {
		if line.trim_space() == '' {
			continue
		}
		recs << line.split('\t')
	}
	// A refused load leaves NO partial refs state (#129-C: the caller sees a
	// hard error and an empty view, never a silently half-loaded store).
	mut load_ok := false
	defer {
		if !load_ok {
			ms.obj_roots = map[string][]u8{}
			ms.doc_order = []
			ms.aliases = map[string]string{}
			ms.alias_order = []
		}
	}
	mut torn := false // the final record was discarded as a torn tail
	for ri, parts in recs {
		is_last := ri == recs.len - 1
		if parts.len != 3 {
			if is_last {
				torn = true
				break
			}
			return error('cxpack manifest ${mp}: malformed line (${parts.len} fields): ${parts.join('\t')}')
		}
		match parts[0] {
			'D', 'C' {
				// #128-A: 'C' is a code: entry — a verbatim raw leaf, presence-
				// checked (not doc-reconstructed) in pass 2.
				store_hash := parts[1]
				root := hex.decode(parts[2]) or {
					if is_last {
						torn = true
						break
					}
					return error('cxpack manifest ${mp}: bad object hash for ${store_hash}: ${err.msg()}')
				}
				if root.len != 32 {
					if is_last {
						torn = true
						break
					}
					return error('cxpack manifest ${mp}: object hash for ${store_hash} is ${root.len} bytes, not 32')
				}
				if store_hash !in ms.obj_roots {
					ms.doc_order << store_hash
				}
				ms.obj_roots[store_hash] = root
			}
			'A', 'X' {
				obj := hex.decode(parts[1]) or {
					if is_last {
						torn = true
						break
					}
					return error('cxpack manifest ${mp}: bad alias object hash: ${err.msg()}')
				}
				if obj.len != 32 {
					if is_last {
						torn = true
						break
					}
					return error('cxpack manifest ${mp}: alias name hash is ${obj.len} bytes, not 32')
				}
				payload := getter(obj) or {
					return error('cxpack ${ms.root}: alias ${if parts[0] == 'X' {
						'tombstone '
					} else {
						''
					}}object missing from pack: ${parts[1]}')
				}
				alias := payload.bytestr()
				if parts[0] == 'A' {
					if alias !in ms.aliases {
						ms.alias_order << alias
					}
					ms.aliases[alias] = parts[2]
				} else {
					ms.aliases.delete(alias)
					idx := ms.alias_order.index(alias)
					if idx >= 0 {
						ms.alias_order.delete(idx)
					}
				}
			}
			'T' {
				// #129-B: doc tombstone — remove a previously-set doc/code entry.
				store_hash := parts[1]
				ms.obj_roots.delete(store_hash)
				idx := ms.doc_order.index(store_hash)
				if idx >= 0 {
					ms.doc_order.delete(idx)
				}
			}
			else {} // unknown record type — forward-compatible, ignore
		}
	}
	if torn {
		eprintln('cx store: ${ms.root}: manifest tail was torn by an unclean shutdown — discarded the final (unacknowledged) record and opened at the last whole state')
	}
	// Pass 2: verify the FINAL live state (#129-C hard integrity, unchanged in
	// strength — only superseded records are no longer verified, which is also
	// the recovery path for stores damaged by the pre-#624 compaction ordering:
	// their dangling doc references are all tombstoned later in the same log).
	if verify_docs {
	for h, root in ms.obj_roots {
		if h.starts_with('code:') {
			getter(root) or {
				return error('cxpack ${ms.root}: code object missing from pack for ${h}')
			}
			continue
		}
		doc := cxstore.load_document_from(getter, root) or {
			return error('cxpack ${ms.root}: doc ${h} failed to reconstruct from the object graph (corrupt or missing object): ${err.msg()}')
		}
		if doc.elements.len == 0 {
			return error('cxpack ${ms.root}: doc ${h} reconstructed to an empty document (corruption)')
		}
	}
	}

	load_ok = true
	// Seed the watermarks to match the loaded on-disk state, so the next mutation
	// appends only its own delta. The pack backend's own watermark and the segment
	// number were seeded by load_objects; the sink was loaded FROM the packs, so
	// all of it is durable.
	store_graph_seed_watermarks(mut ms)
	ms.obj_flushed = ms.obj_sink.objects.len
	ms.log_records = ms.doc_order.len + ms.alias_order.len
}
