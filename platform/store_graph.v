module platform

import cx
import crypto.rand
import crypto.sha256
import cxstore
import os
import encoding.hex

// store_graph.v — the SUBSTRATE-AGNOSTIC object-graph store (spec §2, §7.2).
//
// Every object-graph substrate decomposes a document into the content-addressed
// subtree object graph (cxstore.store_document) in the live in-memory ObjectSink,
// and persists/resolves those objects through the universal ObjectBackend seam.
// What differs between substrates is ONLY object durability (pack segments vs an
// object-per-key directory vs sqlite rows vs the wire); the document engine, the
// dedup/structural-sharing, the refs (store-key → doc-root) manifest, and the
// reconstruction+integrity path are all shared and live here.
//
// The cxpack backend keeps its own specialized flush/compact (incremental segment
// packs + reachability GC, store_cxpack.v) but shares this module's manifest
// REPLAY + SNAPSHOT + DELTA helpers, so there is exactly one refs-format
// implementation. The simple durable backends (cxobj:// object-per-key, sqlite)
// use store_graph_flush / store_graph_load below directly.
//
// READS: store_graph_getter resolves an object from the live sink FIRST (covers a
// just-written, not-yet-persisted doc) then the durable backend (covers everything
// persisted, including after a reopen when the sink starts empty). So the same
// reader serves mem (sink only), the lazy disk backends (sink + backend), and
// cxpack (sink preloaded). No substrate needs to eagerly slurp every object into
// RAM on open unless its get_object is slow (only the pack backend is).

// store_graph_getter — the composite object resolver for any object-graph store.
// Returns the bare getter signature (V coerces it to cxstore.Getter at each call
// site, exactly as the hand-rolled closures did).
// store_graph_getter is the composite object resolver: the live sink (this
// session's writes), then the #637 page cache, then the durable substrate —
// the pack backend (or its encrypting wrapper for a keyed store) or the
// non-pack object backend. A backend hit is CACHED so the second touch is
// memory-speed; the cache is separate from the sink so the flush watermark
// never sees a paged-in read as a new object. Every backend read
// self-verifies its hash, so corruption refuses here rather than
// materializing a wrong doc.
fn store_graph_getter(ms &MemStore) fn (h []u8) ?[]u8 {
	return fn [ms] (h []u8) ?[]u8 {
		if p := ms.obj_sink.get(h) {
			return p
		}
		hx := h.hex()
		if p := ms.obj_cache[hx] {
			return p
		}
		mut mms := unsafe { &MemStore(ms) }
		if be := ms.obj_backend {
			// NOT cached: a remote substrate's reads must keep reaching the
			// backend. Serving a REVOKED session from a local cache would
			// swallow the auth failure the doc layer is supposed to surface
			// (#212 / store_objwire_err) — the #637 page cache is for the
			// local pack substrate, where there is no such signal to lose.
			return be.get_object(h)
		}
		if ms.obj_pack != unsafe { nil } {
			// keyed stores resolve through the AEAD wrapper (plaintext-hash
			// keyed envelopes); plaintext stores read the pack directly.
			if ms.enc_key_id != '' && ms.obj_pack_enc != unsafe { nil } {
				p := ms.obj_pack_enc.get_object(h) or { return none }
				mms.obj_cache[hx] = p
				return p
			}
			p := ms.obj_pack.get_object(h) or { return none }
			mms.obj_cache[hx] = p
			return p
		}
		return none
	}
}

// ── Shared refs (manifest) format: D doc · C code-raw · A alias · T/X tombstones ─

// store_graph_snapshot_lines emits the manifest as a clean full snapshot of live
// state (no tombstones) — used on compaction / full rewrite.
fn store_graph_snapshot_lines(ms &MemStore) []string {
	mut lines := []string{}
	for h in ms.doc_order {
		root := ms.obj_roots[h] or { continue }
		rec := if h in ms.blob_kind { 'B' } else { 'D' } // F1': 'B' = opaque blob (key = hash of raw bytes); legacy 'C' retired (A3)
		lines << '${rec}\t${h}\t${root.hex()}'
	}
	for a in ms.alias_order {
		dh := ms.aliases[a] or { continue }
		nk := cxstore.object_name(a.bytes()).hex()
		lines << 'A\t${nk}\t${dh}'
	}
	// E erased-tombstone records survive the snapshot — attribution always
	// survives compaction (xsp store profile §7b.1 / erasure_compliance §6).
	for h in ms.erased_order {
		tomb := ms.erased[h] or { continue }
		lines << 'E\t${h}\t${cxstore.object_name(tomb.bytes()).hex()}'
	}
	return lines
}

// GraphDelta is the refs delta since the last persist — the manifest lines to
// append plus the doc/alias sets they cover, computed ONCE by store_graph_delta
// and applied to the watermarks by store_graph_delta_commit only after the
// substrate has made the lines durable (file append for cxobj, a manifest row
// for sqlite, #299). Keeping compute/commit apart is what lets each substrate
// own its durable write while there stays exactly ONE refs-format
// implementation.
struct GraphDelta {
	lines           []string
	new_docs        []string
	removed_docs    []string
	set_aliases     map[string]string
	removed_aliases []string
	// new erased tombstones (hash → tombstone text) — the E records this
	// delta appends; their payload objects were sink-routed at erase time.
	new_erased map[string]string
}

// store_graph_delta computes the refs delta since the last persist — new
// docs/code (D/C), removed docs (T), new/updated aliases (A), removed aliases
// (X) — against the doc_manifested / alias_manifested watermarks. Pure compute;
// commits nothing.
//
// COST (#603): the scan is O(delta), never O(live). New docs can only sit past
// the doc_scanned cursor (doc_order is append-ordered; store_delete_local keeps
// the cursor aligned across mid-array deletes); changed aliases can only be in
// alias_dirty (every live alias-set site appends there); the removal scans over
// the manifested maps run only when a delete-shaped op raised has_removals.
// The manifested watermarks stay the source of truth for WHAT is durable — the
// #603 bookkeeping only narrows WHERE the diff can be, and it is consumed by
// store_graph_delta_commit strictly after the substrate made the lines durable,
// so a failed flush recomputes the identical delta (self-healing unchanged).
fn store_graph_delta(ms &MemStore) GraphDelta {
	mut lines := []string{}
	mut new_docs := []string{}
	for di := ms.doc_scanned; di < ms.doc_order.len; di++ {
		h := ms.doc_order[di]
		if h in ms.doc_manifested {
			continue
		}
		root := ms.obj_roots[h] or { continue }
		rec := if h in ms.blob_kind { 'B' } else { 'D' } // F1': 'B' = opaque blob (key = hash of raw bytes); legacy 'C' retired (A3)
		lines << '${rec}\t${h}\t${root.hex()}'
		new_docs << h
	}
	mut removed_docs := []string{}
	if ms.has_removals {
		for h, _ in ms.doc_manifested {
			if h !in ms.obj_roots {
				lines << 'T\t${h}\t-'
				removed_docs << h
			}
		}
	}
	mut set_aliases := map[string]string{}
	for a in ms.alias_dirty {
		if a in set_aliases {
			continue // deduped: set twice since the last flush
		}
		dh := ms.aliases[a] or { continue }
		if pv := ms.alias_manifested[a] {
			if pv == dh {
				continue
			}
		}
		nk := cxstore.object_name(a.bytes()).hex()
		lines << 'A\t${nk}\t${dh}'
		set_aliases[a] = dh
	}
	mut removed_aliases := []string{}
	if ms.has_removals {
		for a, _ in ms.alias_manifested {
			if a !in ms.aliases {
				nk := cxstore.object_name(a.bytes()).hex()
				lines << 'X\t${nk}\t-'
				removed_aliases << a
			}
		}
	}
	mut new_erased := map[string]string{}
	for h in ms.erased_dirty {
		if h in new_erased || h in ms.erased_manifested {
			continue
		}
		tomb := ms.erased[h] or { continue } // superseded before this flush — the D record decides
		lines << 'E\t${h}\t${cxstore.object_name(tomb.bytes()).hex()}'
		new_erased[h] = tomb
	}
	return GraphDelta{
		lines:           lines
		new_docs:        new_docs
		removed_docs:    removed_docs
		set_aliases:     set_aliases
		removed_aliases: removed_aliases
		new_erased:      new_erased
	}
}

// store_graph_delta_commit advances the doc_manifested / alias_manifested /
// log_records watermarks for a delta the caller has just made durable.
fn store_graph_delta_commit(mut ms MemStore, d GraphDelta) {
	for h in d.new_docs {
		ms.doc_manifested[h] = true
	}
	for h in d.removed_docs {
		ms.doc_manifested.delete(h)
	}
	for a, dh in d.set_aliases {
		ms.alias_manifested[a] = dh
	}
	for a in d.removed_aliases {
		ms.alias_manifested.delete(a)
	}
	for h, _ in d.new_erased {
		ms.erased_manifested[h] = true
	}
	ms.erased_dirty = []
	// #603: the delta's scan window is settled — everything below the cursor /
	// in the dirty list is either durable now or was a no-op. Committing an
	// EMPTY delta is valid and still advances the bookkeeping (a scanned tail
	// of already-manifested docs, unchanged dirty aliases).
	ms.doc_scanned = ms.doc_order.len
	ms.alias_dirty = []
	ms.has_removals = false
	ms.log_records += d.lines.len
}

// store_graph_seed_watermarks resets every incremental-flush watermark to "the
// full live state is durable": the manifested maps cover all live docs/aliases
// and the #603 delta bookkeeping (scan cursor, dirty aliases, removal flag)
// starts clean. Call ONLY when the substrate has just made the entire live
// state durable (load, snapshot persist, compaction). The object-layer
// watermark (obj_flushed) is the caller's — substrates seed it differently.
fn store_graph_seed_watermarks(mut ms MemStore) {
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
	mut em := map[string]bool{}
	for h in ms.erased_order {
		em[h] = true
	}
	ms.erased_manifested = em.move()
	ms.doc_scanned = ms.doc_order.len
	ms.alias_dirty = []
	ms.erased_dirty = []
	ms.has_removals = false
}

// store_graph_manifest_delta appends the refs delta since the last persist to
// the manifest FILE at `mp` and advances the watermarks. The caller MUST have
// already made the referenced objects (doc roots + alias-name objects) durable
// in its backend. SHARED by the file-manifest substrates (cxobj; cxpack has its
// own flush over the same delta helpers).
fn store_graph_manifest_delta(mut ms MemStore, mp string) ! {
	d := store_graph_delta(ms)
	if d.lines.len == 0 {
		// nothing to append — still commit so the #603 scan bookkeeping advances
		store_graph_delta_commit(mut ms, d)
		return
	}
	blob := d.lines.join('\n') + '\n'
	if os.exists(mp) {
		mut f := os.open_append(mp) or {
			return error('manifest ${mp}: open failed: ${err.msg()}')
		}
		f.write_string(blob) or {
			f.close()
			return error('manifest ${mp}: append failed: ${err.msg()}')
		}
		f.close()
	} else {
		os.write_file(mp, blob) or {
			return error('manifest ${mp}: write failed: ${err.msg()}')
		}
	}
	store_graph_delta_commit(mut ms, d)
}

// store_graph_replay applies a manifest's records to ms (the refs layer), resolving
// + integrity-checking every referenced object through `getter`. INTEGRITY (#129-C
// / spec §4 universal): a D record whose doc cannot be reconstructed, or a C/A/X
// record whose object is missing, is a HARD error — never a silent drop. `where`
// names the store for diagnostics. SHARED across every object-graph substrate.
fn store_graph_replay(mut ms MemStore, getter fn (h []u8) ?[]u8, content string, where string) ! {
	for line in content.split_into_lines() {
		if line.trim_space() == '' {
			continue
		}
		parts := line.split('\t')
		if parts.len != 3 {
			return error('${where}: malformed manifest line (${parts.len} fields): ${line}')
		}
		match parts[0] {
			'D' {
				store_hash := parts[1]
				root := hex.decode(parts[2]) or {
					return error('${where}: bad object hash for doc ${store_hash}: ${err.msg()}')
				}
				if ms.model == 'document' || store_whole_doc_root(store_hash, root) {
					// Degenerate model — or a stream-20 subject-bearing doc
					// stored whole: the doc is one raw object — verify it is
					// present + self-verifying (the getter rejects a hash
					// mismatch), no decompose.
					getter(root) or {
						return error('${where}: document ${store_hash} object missing/corrupt')
					}
				} else {
					doc := cxstore.load_document_from(getter, root) or {
						return error('${where}: doc ${store_hash} failed to reconstruct from the object graph (corrupt or missing object): ${err.msg()}')
					}
					if doc.elements.len == 0 {
						return error('${where}: doc ${store_hash} reconstructed to an empty document (corruption)')
					}
				}
				if store_hash !in ms.obj_roots {
					ms.obj_roots[store_hash] = root
					ms.doc_order << store_hash
				}
				store_replay_clear_erased(mut ms, store_hash) // a later put supersedes a tombstone
			}
			'B' {
				// F1' opaque blob: fetch the raw leaf and VERIFY key == hash(raw)
				// here too (this loader CAN error loudly; the per-read check in
				// store_get_blob_local still runs on every get).
				key := parts[1]
				root := hex.decode(parts[2]) or {
					return error('${where}: bad object hash for blob ${key}: ${err.msg()}')
				}
				payload := getter(root) or {
					return error('${where}: blob object missing for ${key}')
				}
				rehash := cx.cx_tag_address(cx.cx_default_hash_algo, sha256.sum256(payload).hex())
				if rehash != key {
					return error('${where}: blob ${key} rehashes to ${rehash}')
				}
				if key !in ms.obj_roots {
					ms.obj_roots[key] = root
					ms.doc_order << key
				}
				ms.blob_kind[key] = true
				store_replay_clear_erased(mut ms, key)
			}
			'C' {
				// A3 (RULED 2026-08-08): the legacy computation-identity-keyed
				// code record is REFUSED LOUDLY — its key was never the hash of
				// the stored bytes, so no read path may admit it. No tolerance
				// window: re-ingest the source through put-blob.
				return error('${where}: legacy code record ${parts[1]} — the computation-identity-keyed store form is retired (F1-prime/A3); re-ingest the source through put-blob')
			}
			'A' {
				obj := hex.decode(parts[1]) or {
					return error('${where}: bad alias object hash: ${err.msg()}')
				}
				doc_hash := parts[2]
				payload := getter(obj) or {
					return error('${where}: alias object missing: ${parts[1]}')
				}
				alias := payload.bytestr()
				if alias !in ms.aliases {
					ms.alias_order << alias
				}
				ms.aliases[alias] = doc_hash
			}
			'T' {
				store_hash := parts[1]
				ms.obj_roots.delete(store_hash)
				idx := ms.doc_order.index(store_hash)
				if idx >= 0 {
					ms.doc_order.delete(idx)
				}
			}
			'X' {
				obj := hex.decode(parts[1]) or {
					return error('${where}: bad alias tombstone hash: ${err.msg()}')
				}
				payload := getter(obj) or {
					return error('${where}: alias tombstone object missing: ${parts[1]}')
				}
				alias := payload.bytestr()
				ms.aliases.delete(alias)
				idx := ms.alias_order.index(alias)
				if idx >= 0 {
					ms.alias_order.delete(idx)
				}
			}
			'E' {
				// W5 erased-tombstone record: `E <doc-hash> <tombstone-obj-hex>`
				// — records the attributed erasure (the doc's removal rides its
				// own T record in the same flush). A missing tombstone object is
				// genuine corruption: erasure evidence must never silently vanish.
				obj := hex.decode(parts[2]) or {
					return error('${where}: bad erased tombstone object hash: ${err.msg()}')
				}
				payload := getter(obj) or {
					return error('${where}: erased tombstone object missing: ${parts[2]}')
				}
				store_replay_apply_erased(mut ms, parts[1], payload.bytestr())
			}
			else {} // unknown record type — forward-compatible, ignore
		}
	}
}

// store_replay_apply_erased applies one E record to the live erased state
// (load/replay path — direct map sets, no events). The tombstone's root=
// attr rebuilds the object-wire discriminator index.
fn store_replay_apply_erased(mut ms MemStore, hash string, tombstone string) {
	if hash !in ms.erased {
		ms.erased_order << hash
	}
	ms.erased[hash] = tombstone
	if doc := cx.parse(tombstone) {
		if doc.elements.len > 0 {
			e := doc.elements[0]
			if e is cx.Element {
				rh := e.attr('root')
				if rh != '' {
					ms.erased_roots[rh] = hash
				}
			}
		}
	}
}

// store_replay_clear_erased clears an erased record when a LATER put record
// replays for the same hash — replay order decides (the T re-put precedent):
// an insert supersedes a tombstone.
fn store_replay_clear_erased(mut ms MemStore, hash string) {
	if hash !in ms.erased {
		return
	}
	ms.erased.delete(hash)
	idx := ms.erased_order.index(hash)
	if idx >= 0 {
		ms.erased_order.delete(idx)
	}
	mut dead := []string{}
	for rh, dh in ms.erased_roots {
		if dh == hash {
			dead << rh
		}
	}
	for rh in dead {
		ms.erased_roots.delete(rh)
	}
}

// store_graph_stage_aliases makes every live alias-name object (and every
// manifested-but-now-removed name, so its X tombstone resolves on replay) durable
// in the backend. put_object is content-addressed + idempotent, so already-durable
// names are a cheap no-op.
fn store_graph_stage_aliases(mut be cxstore.ObjectBackend, ms &MemStore) ! {
	for a in ms.alias_order {
		be.put_object(a.bytes())!
	}
	for a, _ in ms.alias_manifested {
		if a !in ms.aliases {
			be.put_object(a.bytes())!
		}
	}
}

// ── cxobj:// — local-fs object-per-key subtree backend (spec §1: local-fs ×
// subtree × object-per-key; the second local-fs encoding alongside cxpack pack) ──

const cxobj_objects_dir = 'objects'
const cxobj_manifest = '.cxobj-manifest'

// store_cxobj_flush persists the object-graph delta for a cxobj:// store: new
// objects are written object-per-key (DirObjectBackend writes each file on put —
// durable immediately, no segment/flush step), then the refs delta is appended to
// the manifest. Routes object durability + resolution entirely through the seam.
fn store_cxobj_flush(mut ms MemStore) ! {
	if ms.root == '' {
		return
	}
	store_cxobj_backend(mut ms) or {
		return error('cxobj ${ms.root}: backend attach failed: ${err.msg()}')
	}
	// #603: O(delta) — persist only the sink tail past the durability watermark
	// (DirObjectBackend puts are durable immediately, so the watermark advances
	// right after), and only THIS delta's alias-name objects (set + removed — an
	// X tombstone resolves its name object on replay), never the whole table.
	d := store_graph_delta(ms)
	if mut be := ms.obj_backend {
		nf := cxstore.persist_objects_from(mut be, ms.obj_sink, ms.obj_flushed) or {
			ms.obj_backend = be
			return error('cxobj ${ms.root}: object write failed: ${err.msg()}')
		}
		for a, _ in d.set_aliases {
			be.put_object(a.bytes()) or {
				ms.obj_backend = be
				return error('cxobj ${ms.root}: alias-name object write failed: ${err.msg()}')
			}
		}
		for a in d.removed_aliases {
			be.put_object(a.bytes()) or {
				ms.obj_backend = be
				return error('cxobj ${ms.root}: alias-name object write failed: ${err.msg()}')
			}
		}
		ms.obj_backend = be
		ms.obj_flushed = nf
	}
	store_graph_manifest_delta(mut ms, os.join_path(ms.root, cxobj_manifest))!
}

// store_cxobj_load reopens a cxobj:// store: it replays the refs manifest, resolving
// every referenced object lazily through the composite getter (DirObjectBackend
// reads one object file per hash, self-verifying — no eager slurp into RAM). A
// present-but-broken object is a HARD integrity error (#129-C). A never-persisted
// path is a legitimately empty store.
fn store_cxobj_load(mut ms MemStore) ! {
	// #183: capture on-disk presence BEFORE attaching the backend — attaching
	// (store_cxobj_backend → open_dir_object_backend) mkdir_all's `<root>/objects`,
	// so a presence check taken after would ALWAYS see the objects dir and trip
	// the partial-store guard on a brand-new path. The manifest is the ref layer;
	// the objects dir holds content-addressed blobs.
	mp := os.join_path(ms.root, cxobj_manifest)
	objdir := os.join_path(ms.root, cxobj_objects_dir)
	manifest_present := os.exists(mp)
	// manifest present but its objects dir is gone → genuine corruption (the ref
	// layer references objects that cannot be there).
	if manifest_present && !os.exists(objdir) {
		return error('cxobj store at ${ms.root} is incomplete (manifest present but objects/ missing) — refusing to open a corrupt store')
	}
	// Attach now (creates objects/ for a fresh store — harmless once presence is
	// already captured).
	store_cxobj_backend(mut ms)!
	if !manifest_present {
		// No manifest: a fresh/empty store (objects dir absent or empty) opens
		// clean. Objects present without a manifest would be unreferenced blobs
		// from a crash mid-flush — treated as an empty store (the objects are
		// unreachable, never silently resurrected), matching the object-graph
		// self-healing posture; the next flush writes a correct manifest.
		return
	}
	content := os.read_file(mp) or {
		return error('cxobj manifest ${mp} unreadable: ${err.msg()}')
	}
	getter := store_graph_getter(ms)
	store_graph_replay(mut ms, getter, content, 'cxobj ${ms.root}')!
}

// store_cxobj_backend lazily attaches the object-per-key DirObjectBackend rooted at
// `<root>/objects` (the open path sets it; tests may construct a MemStore directly).
fn store_cxobj_backend(mut ms MemStore) ! {
	if ms.obj_backend == none {
		objdir := os.join_path(ms.root, cxobj_objects_dir)
		if ms.enc_key_id != '' {
			// #114: encryption-at-rest — the durable backend AEAD-seals each object;
			// the graph keys by plaintext hash, so dedup/sharing are unchanged.
			ms.obj_backend = store_enc_object_backend(objdir, ms.enc_key_id, ms.root)!
		} else {
			be := cxstore.open_dir_object_backend(objdir)!
			ms.obj_backend = cxstore.ObjectBackend(&be)
		}
	}
}

// EnvKms — the environment-resolving reference KMS provider. Wraps LocalKms
// (which owns the wrap/unwrap crypto) with the fail-closed env policy: any
// key-id an envelope records resolves lazily from `CX_STORE_KEK_<id>` on first
// use, so a store holding envelopes under several key-ids (mid-KEK-rotation,
// #287 / store.md §9.1) opens and reads while every referenced env key is
// present — and errors precisely, naming the id, when one is not. The store's
// CONFIGURED key-id is still resolved eagerly at open (store_kek_kms), so a
// keyless open of an encrypted store fails before any data is touched.
// Stream 20 (#692): the SEK tier. The reference provider persists each
// per-subject key (SEK, `sek/<tenant>/<token>`) as a KEK-wrapped blob under
// `keys_dir` (the store-root `keys/` sidecar) — the same operator-host custody
// boundary the env KEKs live in; a production deployment holds SEKs in its
// real KMS through the same cxstore.Kms seam. Destruction = removing the blob
// (+ the in-memory copy), after which every envelope wrapped under that SEK
// fails closed with the typed unavailable finding — crypto-shredding. SEK ids
// NEVER resolve from env and are never lazily minted.
@[heap]
struct EnvKms {
mut:
	inner &cxstore.LocalKms
	// keys_dir — the SEK custody home ('' = none, e.g. s3: subject-key
	// creation refuses loudly; reads of sek-wrapped envelopes report the
	// typed unavailable finding).
	keys_dir string
	// wrap_id — the tenant key-id NEW SEKs wrap under; follows KEK rotation.
	wrap_id string
}

// env_kek ensures key_id's KEK is pinned on the inner provider, resolving it
// from env `CX_STORE_KEK_<key_id>` (64 hex chars = a 32-byte master key).
// Fail-closed: a missing or malformed KEK is a hard error, never a silent
// ephemeral key (which would make already-written objects unrecoverable).
fn (mut k EnvKms) env_kek(key_id string) ! {
	if k.inner.has_master(key_id) {
		return
	}
	kek_hex := os.getenv('CX_STORE_KEK_${key_id}')
	if kek_hex == '' {
		return error('encryption requires env CX_STORE_KEK_${key_id} (64 hex chars = 32-byte KEK)')
	}
	kek := hex.decode(kek_hex) or {
		return error('CX_STORE_KEK_${key_id}: not valid hex')
	}
	k.inner.add_master(key_id, kek)!
}

// kms_resolve routes a key-id to its custody: SEK ids load from the sidecar
// (KEK-wrapped blob → unwrap → pin on the inner provider), everything else
// resolves from env. SEK ids never touch env and never lazily mint.
fn (mut k EnvKms) kms_resolve(key_id string) ! {
	if key_id.starts_with(cxstore.sek_id_prefix) {
		return k.sek_load(key_id)
	}
	return k.env_kek(key_id)
}

// sek_path — the sidecar blob for a SEK id. The id's own segments form the
// path under keys_dir (`keys/sek/<tenant>/<token>.key`).
fn (k &EnvKms) sek_path(key_id string) string {
	return os.join_path(k.keys_dir, key_id + '.key')
}

// sek_guard refuses SEK ids that cannot map to sidecar custody safely.
fn (k &EnvKms) sek_guard(key_id string) ! {
	if k.keys_dir == '' {
		return error('${cxstore.key_unavailable_msg}: subject key ${key_id}: this substrate has no local key custody (reference provider); a production KMS supplies subject keys through the same seam')
	}
	if key_id.contains('..') {
		return error('subject key id ${key_id} refused (path traversal)')
	}
}

// sek_load pins a persisted SEK on the inner provider: read the sidecar blob,
// unwrap under its RECORDED tenant key (mid-rotation coexistence, same as
// envelopes), pin. Absence is the typed unavailable finding — destroyed,
// never created, or wrong host — fail-closed, never re-minted.
fn (mut k EnvKms) sek_load(key_id string) ! {
	if k.inner.has_key(key_id) {
		return
	}
	k.sek_guard(key_id)!
	blob := os.read_bytes(k.sek_path(key_id)) or {
		return error('${cxstore.key_unavailable_msg}: subject key ${key_id} is not available (destroyed, never created, or provider outage)')
	}
	env := cxstore.parse_envelope(blob)!
	k.env_kek(env.key_id)!
	sek := k.inner.decrypt_data_key(env.key_id, env.wrapped)!
	k.inner.add_master(key_id, sek)!
}

// sek_write_blob persists a KEK-wrapped SEK blob atomically (temp + rename,
// fsynced): a torn blob would strand every payload sealed under that subject.
fn (k &EnvKms) sek_write_blob(path string, blob []u8) ! {
	os.mkdir_all(os.dir(path))!
	tmp := path + '.tmp'
	mut f := os.create(tmp)!
	f.write(blob) or {
		f.close()
		os.rm(tmp) or {}
		return err
	}
	f.flush()
	C.fsync(f.fd)
	f.close()
	os.mv(tmp, path) or {
		os.rm(tmp) or {}
		return error('subject key blob install rename failed: ${err.msg()}')
	}
}

fn (mut k EnvKms) generate_data_key(key_id string) !([]u8, []u8) {
	k.kms_resolve(key_id)!
	return k.inner.generate_data_key(key_id)!
}

fn (mut k EnvKms) decrypt_data_key(key_id string, wrapped []u8) ![]u8 {
	k.kms_resolve(key_id)!
	return k.inner.decrypt_data_key(key_id, wrapped)!
}

fn (mut k EnvKms) encrypt_data_key(key_id string, dek []u8) ![]u8 {
	k.kms_resolve(key_id)!
	return k.inner.encrypt_data_key(key_id, dek)!
}

// create_key mints a named key if absent. For a SEK id: create-if-absent with
// durable sidecar custody (an existing blob loads instead — first-writer-wins
// across reopens); the fresh 32-byte CSPRNG key wraps under the current
// tenant wrap key. Non-SEK ids delegate to the inner provider (memory-only).
fn (mut k EnvKms) create_key(key_id string) ! {
	if !key_id.starts_with(cxstore.sek_id_prefix) {
		return k.inner.create_key(key_id)
	}
	if k.inner.has_key(key_id) {
		return
	}
	k.sek_guard(key_id)!
	if os.exists(k.sek_path(key_id)) {
		return k.sek_load(key_id)
	}
	if k.wrap_id == '' {
		return error('subject key creation needs a tenant wrap key (store not opened with encrypt-key-id)')
	}
	k.env_kek(k.wrap_id)!
	sek := rand.bytes(32)!
	wrapped := k.inner.encrypt_data_key(k.wrap_id, sek)!
	blob := cxstore.build_envelope(k.wrap_id, wrapped, [])!
	k.sek_write_blob(k.sek_path(key_id), blob)!
	k.inner.add_master(key_id, sek)!
}

// destroy_key removes a named key — for a SEK, the crypto-shred primitive:
// the sidecar blob AND the in-memory copy go; every envelope wrapped under it
// fails closed from here on. Idempotent (matching erase-subject's
// deduped-replay posture).
fn (mut k EnvKms) destroy_key(key_id string) ! {
	k.inner.destroy_key(key_id)!
	if key_id.starts_with(cxstore.sek_id_prefix) && k.keys_dir != ''
		&& !key_id.contains('..') {
		p := k.sek_path(key_id)
		if os.exists(p) {
			os.rm(p)!
		}
	}
}

// has_key — the typed-absence probe, without minting or env side effects
// beyond the lazy env resolution the read path performs anyway.
fn (mut k EnvKms) has_key(key_id string) bool {
	if k.inner.has_key(key_id) {
		return true
	}
	if key_id.starts_with(cxstore.sek_id_prefix) {
		if k.keys_dir == '' || key_id.contains('..') {
			return false
		}
		return os.exists(k.sek_path(key_id))
	}
	k.env_kek(key_id) or { return false }
	return true
}

// subject_sek_id resolves (create-if-absent) the SEK id for a subject. The
// mapping lives in the custody sidecar (`keys/subjects/<hex(subject)>` → the
// full SEK id) — the same operator boundary as the keys themselves, OUT of
// the store's data plane; the erase walk removes it with the SEK, after which
// the substrate names the subject only from the journaled shred-request
// (erasure_compliance §4). The mapping file records the FULL id (not just the
// token): the id embeds the tenant segment at mint time and must stay stable
// across KEK rotations (a rotation renames the tenant KEY, never the SEKs).
// The token is 128-bit CSPRNG — never the subject id, never derivable from it
// (the key namespace must not be a subject oracle, §9).
fn (mut k EnvKms) subject_sek_id(subject string) !string {
	if k.keys_dir == '' {
		return error('this substrate has no local subject-key custody (reference provider); a production KMS supplies subject keys through the same seam')
	}
	fname := os.join_path(k.keys_dir, 'subjects', hex.encode(subject.bytes()))
	if os.exists(fname) {
		raw := os.read_file(fname) or {
			return error('subject map ${fname} unreadable: ${err.msg()}')
		}
		id := raw.trim_space()
		if !id.starts_with(cxstore.sek_id_prefix) {
			return error('subject map ${fname} corrupt (not a subject key id)')
		}
		return id
	}
	tok := rand.bytes(16)!.hex()
	id := '${cxstore.sek_id_prefix}${k.wrap_id}/${tok}'
	k.sek_write_blob(fname, id.bytes())!
	return id
}

// subject_sek_lookup resolves the SEK id for a subject WITHOUT minting — the
// erase walk's read (minting a key during erasure would fabricate custody
// where none exists). none = no mapping: the subject never wrote here, or was
// already erased (the mapping is removed with the SEK, erasure_compliance §4).
fn (k &EnvKms) subject_sek_lookup(subject string) ?string {
	if k.keys_dir == '' {
		return none
	}
	fname := os.join_path(k.keys_dir, 'subjects', hex.encode(subject.bytes()))
	raw := os.read_file(fname) or { return none }
	id := raw.trim_space()
	if !id.starts_with(cxstore.sek_id_prefix) {
		return none
	}
	return id
}

// subject_unmap removes the subject→SEK mapping — the erase walk's companion
// to destroy_key: post-shred the substrate names the subject only from the
// journaled shred-request (erasure_compliance §4). Idempotent.
fn (k &EnvKms) subject_unmap(subject string) {
	if k.keys_dir == '' {
		return
	}
	fname := os.join_path(k.keys_dir, 'subjects', hex.encode(subject.bytes()))
	if os.exists(fname) {
		os.rm(fname) or {}
	}
}

// rotate_subject_keys re-wraps every persisted SEK blob under new_key_id —
// the stream-20 companion to the envelope walk: envelopes wrapped under a SEK
// never move at tenant rotation (re-wrapping them under the tenant KEK would
// defeat crypto-shredding); the SEK's own KEK wrap is what moves. Returns the
// re-wrapped count; blobs already under new_key_id are left byte-identical
// (resumable). Also pins new_key_id as the wrap key for future SEK mints.
fn (mut k EnvKms) rotate_subject_keys(new_key_id string) !int {
	defer {
		k.wrap_id = new_key_id
	}
	if k.keys_dir == '' {
		return 0
	}
	base := os.join_path(k.keys_dir, 'sek')
	if !os.is_dir(base) {
		return 0
	}
	k.env_kek(new_key_id)!
	mut n := 0
	for path in os.walk_ext(base, '.key') {
		blob := os.read_bytes(path) or {
			return error('subject key blob ${path} unreadable: ${err.msg()}')
		}
		env := cxstore.parse_envelope(blob)!
		if env.key_id == new_key_id {
			continue
		}
		k.env_kek(env.key_id)!
		sek := k.inner.decrypt_data_key(env.key_id, env.wrapped) or {
			return error('subject key blob ${path}: unwrap under `${env.key_id}` failed: ${err.msg()}')
		}
		wrapped := k.inner.encrypt_data_key(new_key_id, sek)!
		nb := cxstore.build_envelope(new_key_id, wrapped, [])!
		k.sek_write_blob(path, nb)!
		n++
	}
	return n
}

// store_kek_kms resolves the tenant KEK from env `CX_STORE_KEK_<key_id>` into
// the EnvKms reference provider (eagerly for the configured id — fail-closed at
// open; lazily for any other key-id an envelope records, the mid-rotation read
// path). A production deployment supplies a real KMS (AWS/GCP/Vault) through
// the same cxstore.Kms seam.
// keys_root — the store's key-custody home ('' for substrates with no local
// home, e.g. s3: SEK creation refuses loudly there; a production KMS supplies
// subject keys host-independently through the same seam).
fn store_kek_kms(key_id string, keys_root string) !cxstore.Kms {
	mut kms := &EnvKms{
		inner:    cxstore.new_local_kms_locked()
		keys_dir: if keys_root == '' { '' } else { os.join_path(keys_root, 'keys') }
		wrap_id:  key_id
	}
	kms.env_kek(key_id)!
	return cxstore.Kms(kms)
}

// store_enc_object_backend builds an EncryptingObjectBackend (#114) over `objdir`
// for the object-per-key substrate, KEK-resolved via store_kek_kms; keys_root
// hosts the stream-20 SEK sidecar (the store root).
fn store_enc_object_backend(objdir string, key_id string, keys_root string) !cxstore.ObjectBackend {
	kms := store_kek_kms(key_id, keys_root)!
	be := cxstore.new_encrypting_object_backend(objdir, key_id, kms)!
	return cxstore.ObjectBackend(&be)
}
