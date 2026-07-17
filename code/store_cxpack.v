module code

import cxstore
import os
import encoding.hex

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
// COST: the DURABLE work — serialize/compress/hash/CRC each object and write it,
// the heavy part the old whole-pack snapshot redid for every object on every
// mutation — is O(delta): only objects/records new since the last flush touch the
// disk. The delta is computed by diffing the live graph against the obj_flushed /
// doc_manifested / alias_manifested watermarks: an O(live) in-memory scan (map
// lookups, no I/O). That scan is deliberately watermark-diff rather than a
// caller-maintained dirty queue: the watermarks are the single source of truth
// for "what is durable", so the flush self-heals after any partial-write
// interleaving (a crash between the segment and the manifest just re-emits the
// pending records next time) — correctness the data path values over shaving the
// in-memory scan.
fn store_cxpack_flush(mut ms MemStore) ! {
	if ms.root == '' {
		return
	}
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
	if ms.enc_key_id != '' {
		cxstore.persist_objects(mut ms.obj_pack_enc, ms.obj_sink) or {
			return error('cxpack ${ms.root}: object stage failed: ${err.msg()}')
		}
	} else {
		cxstore.persist_objects(mut ms.obj_pack, ms.obj_sink) or {
			return error('cxpack ${ms.root}: object stage failed: ${err.msg()}')
		}
	}

	// 2. Manifest delta lines (the REFS layer — store-key → doc-root, and aliases).
	mut lines := []string{}

	// 2a. Docs / code defs with no live manifest record yet.
	mut new_docs := []string{}
	for h in ms.doc_order {
		if h in ms.doc_manifested {
			continue
		}
		root := ms.obj_roots[h] or { continue }
		// #128-A: a code: entry is a verbatim raw-leaf object (not a data doc) → a
		// 'C' record so load restores it raw instead of reconstructing a doc graph.
		rec := if h.starts_with('code:') { 'C' } else { 'D' }
		lines << '${rec}\t${h}\t${root.hex()}'
		new_docs << h
	}

	// 2b. Docs removed since they were manifested → tombstone.
	mut removed_docs := []string{}
	for h, _ in ms.doc_manifested {
		if h !in ms.obj_roots {
			lines << 'T\t${h}\t-'
			removed_docs << h
		}
	}

	// 2c. New / updated aliases. The alias NAME is itself a content-addressed
	//     object (a raw leaf of the name bytes); stage it through the seam so the
	//     A/X records can resolve it on replay (put_object dedups if already present).
	mut set_aliases := map[string]string{}
	for a in ms.alias_order {
		dh := ms.aliases[a] or { continue }
		if pv := ms.alias_manifested[a] {
			if pv == dh {
				continue // unchanged
			}
		}
		nb := a.bytes()
		nk := store_cxpack_stage(mut ms, nb) or {
			return error('cxpack ${ms.root}: alias-name object stage failed: ${err.msg()}')
		}
		lines << 'A\t${nk.hex()}\t${dh}'
		set_aliases[a] = dh
	}

	// 2d. Aliases removed since they were manifested → tombstone (referencing the
	//     name object, which was staged when the alias was first written;
	//     re-staging is an idempotent no-op that also self-heals a missing name).
	mut removed_aliases := []string{}
	for a, _ in ms.alias_manifested {
		if a !in ms.aliases {
			nb := a.bytes()
			nk := store_cxpack_stage(mut ms, nb) or {
				return error('cxpack ${ms.root}: alias-tombstone object stage failed: ${err.msg()}')
			}
			lines << 'X\t${nk.hex()}\t-'
			removed_aliases << a
		}
	}

	if ms.obj_pack.pending_count() == 0 && lines.len == 0 {
		return // nothing changed
	}

	// 3. Flush the staged objects as a fresh segment pack — durable BEFORE the
	//    manifest references them, so a crash between the two leaves unreferenced
	//    objects (reclaimed at compaction), never a dangling manifest pointer.
	ms.obj_pack.flush_segment() or {
		return error('cxpack ${ms.root}: segment flush failed: ${err.msg()}')
	}

	// 4. Append the manifest deltas (no header — load splits on lines).
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
			f.close()
		} else {
			os.write_file(mp, blob) or {
				return error('cxpack ${ms.root}: manifest write failed: ${err.msg()}')
			}
		}
	}

	// 5. Advance manifest watermarks now that the deltas are durable.
	for h in new_docs {
		ms.doc_manifested[h] = true
	}
	for h in removed_docs {
		ms.doc_manifested.delete(h)
	}
	for a, dh in set_aliases {
		ms.alias_manifested[a] = dh
	}
	for a in removed_aliases {
		ms.alias_manifested.delete(a)
	}
	ms.log_records += lines.len

	// 6. Compaction: fold segments back into one pack when they accrue, or when
	//    the append-only manifest carries materially more records than live state
	//    (updates/removals leave superseded lines that only a rewrite clears).
	live := ms.doc_order.len + ms.alias_order.len
	if ms.obj_pack.should_compact() || ms.log_records > 2 * live + 64 {
		store_cxpack_compact(mut ms)!
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

	// Rewrite the manifest as a clean snapshot (live D/C/A only — no tombstones).
	// Temp-file + atomic rename: a truncate-in-place write torn by a crash would
	// leave a manifest referencing nothing (data loss); rename is atomic on the
	// same filesystem, so a reopen sees either the old or the new manifest, whole.
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
	os.write_file(tmp, lines.join('\n') + '\n') or {
		return error('cxpack ${ms.root}: manifest snapshot write failed: ${err.msg()}')
	}
	os.mv(tmp, mp) or {
		os.rm(tmp) or {}
		return error('cxpack ${ms.root}: manifest snapshot rename failed: ${err.msg()}')
	}

	// Reset the manifest (refs) watermarks to the compacted state. The object-layer
	// watermark was reset by write_compacted.
	mut dm := map[string]bool{}
	for h in ms.doc_order {
		dm[h] = true
	}
	ms.doc_manifested = dm.move()
	mut am := map[string]string{}
	for a in ms.alias_order {
		am[a] = ms.aliases[a] or { continue }
	}
	ms.alias_manifested = am.move()
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
		return // never persisted — a legitimately empty store, not an error
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
	snk := ms.obj_sink
	getter := cxstore.getter_of(ms.obj_sink)
	content := os.read_file(mp) or { return error('cxpack manifest ${mp} unreadable: ${err.msg()}') }
	for line in content.split_into_lines() {
		if line.trim_space() == '' {
			continue
		}
		parts := line.split('\t')
		if parts.len != 3 {
			return error('cxpack manifest ${mp}: malformed line (${parts.len} fields): ${line}')
		}
		match parts[0] {
			'D' {
				store_hash := parts[1]
				root := hex.decode(parts[2]) or {
					return error('cxpack manifest ${mp}: bad object hash for doc ${store_hash}: ${err.msg()}')
				}
				// eager integrity: the doc MUST reconstruct from the live graph.
				doc := cxstore.load_document_from(getter, root) or {
					return error('cxpack ${ms.root}: doc ${store_hash} failed to reconstruct from the object graph (corrupt or missing object): ${err.msg()}')
				}
				if doc.elements.len == 0 {
					return error('cxpack ${ms.root}: doc ${store_hash} reconstructed to an empty document (corruption)')
				}
				if store_hash !in ms.obj_roots {
					ms.obj_roots[store_hash] = root
					ms.doc_order << store_hash
				}
			}
			'C' {
				// #128-A: a code: entry — its object is a verbatim raw leaf (source
				// text), restored as-is, NOT reconstructed as a data-doc graph.
				key := parts[1]
				root := hex.decode(parts[2]) or {
					return error('cxpack manifest ${mp}: bad object hash for code ${key}: ${err.msg()}')
				}
				snk.get(root) or {
					return error('cxpack ${ms.root}: code object missing from pack for ${key}')
				}
				if key !in ms.obj_roots {
					ms.obj_roots[key] = root
					ms.doc_order << key
				}
			}
			'A' {
				obj := hex.decode(parts[1]) or {
					return error('cxpack manifest ${mp}: bad alias object hash: ${err.msg()}')
				}
				doc_hash := parts[2]
				payload := snk.get(obj) or {
					return error('cxpack ${ms.root}: alias object missing from pack: ${parts[1]}')
				}
				alias := payload.bytestr()
				if alias !in ms.aliases {
					ms.alias_order << alias
				}
				ms.aliases[alias] = doc_hash
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
			'X' {
				// #129-B: alias tombstone — resolve the name object and remove it.
				obj := hex.decode(parts[1]) or {
					return error('cxpack manifest ${mp}: bad alias tombstone hash: ${err.msg()}')
				}
				payload := snk.get(obj) or {
					return error('cxpack ${ms.root}: alias tombstone object missing from pack: ${parts[1]}')
				}
				alias := payload.bytestr()
				ms.aliases.delete(alias)
				idx := ms.alias_order.index(alias)
				if idx >= 0 {
					ms.alias_order.delete(idx)
				}
			}
			else {} // unknown record type — forward-compatible, ignore
		}
	}

	// Seed the manifest (refs) watermarks to match the loaded on-disk state, so the
	// next mutation appends only its own delta. The object-layer watermark and the
	// segment number were seeded by the backend's load_objects.
	mut dm := map[string]bool{}
	for h in ms.doc_order {
		dm[h] = true
	}
	ms.doc_manifested = dm.move()
	mut am := map[string]string{}
	for a in ms.alias_order {
		am[a] = ms.aliases[a] or { continue }
	}
	ms.alias_manifested = am.move()
	ms.log_records = ms.doc_order.len + ms.alias_order.len
}
