module platform
import code {
	crypto_random_octets,
	cx_code_tier2_hash,
	render_canonical,
}

import cx
import cxstore
import crypto.sha256
import encoding.hex
import time

// store_objgraph.v — #129-A: the LIVE in-memory object-graph storage layer for
// the cxpack backend. Docs are content-addressed into the cxstore subtree object
// graph (cxstore.store_document) inside a live in-memory ObjectSink, and
// reconstructed on read (cxstore.load_document_from + render_canonical). So
// cross-document subtree dedup and modify structural sharing hold IN MEMORY, not
// only in the persisted pack: the sink holds each shared subtree object once, and
// `docs` is never populated for this backend.
//
// These accessors abstract local doc storage over the two models (object graph
// vs the flat `docs` text map) so the store ops route through one surface.
// Remote backends are handled separately (store_remote_active) and never reach
// here.

// store_objgraph_active reports whether a local store keeps its docs as a live
// object graph rather than the flat `docs` text map.
fn store_objgraph_active(ms &MemStore) bool {
	// mem://, cxpack://, cxobj:// all keep docs as the content-addressed subtree
	// object graph (subtree is the default model — spec §1/§5). mem has no durable
	// backend (the in-memory sink IS the store); file:// stays the document model
	// (flat index); remote byte-source backends route via store_remote.
	// Name-keyed for the writable object substrates (mem/cxpack/cxobj/sqlite/s3);
	// plus any LOCAL store carrying an obj_backend (e.g. the B3 read-only remote
	// subtree reader over http/ftp/sftp). cxpack uses obj_pack (not obj_backend), so
	// the name check is still required for it.
	//
	// A cx-store:// CLIENT also carries an obj_backend (a RemoteObjectBackend), but it
	// ALSO sets `remote` (the daemon serves the authoritative catalog — list/iter/
	// query/modify). For it the object wire is reached through a dedicated put/get
	// intercept (store_objwire_client), NOT this local object-graph path, so exclude
	// remote-backed object backends here (obj_backend present AND remote set).
	return ms.backend == 'mem' || ms.backend == 'cxpack' || ms.backend == 'cxobj'
		|| ms.backend == 'sqlite' || ms.backend == 's3'
		|| (ms.obj_backend != none && ms.remote == unsafe { nil })
}

// store_doc_present reports whether a local store holds a doc at `hash`.
fn store_doc_present(ms &MemStore, hash string) bool {
	// #628: reads on a possibly-shared store serialize on the reentrant
	// op-lock too — a V map read racing a sibling handle's rehash is UB.
	mut m := unsafe { ms }
	store_lock_enter(mut m)
	defer {
		store_lock_exit(mut m)
	}
	if store_objgraph_active(ms) {
		return hash in ms.obj_roots
	}
	return hash in ms.docs
}

// store_doc_text returns the canonical TEXT of a locally-held doc. For the
// object-graph backend it reconstructs from the live sink and re-renders
// canonical (reproducing the stored bytes, so the content hash is preserved); a
// present-but-unreconstructable doc is a HARD integrity error (#129-C), never a
// silent miss. Callers MUST check store_doc_present first for absence semantics.
fn store_doc_text(ms &MemStore, hash string) !string {
	mut m := unsafe { ms }
	store_lock_enter(mut m)
	defer {
		store_lock_exit(mut m)
	}
	if store_objgraph_active(ms) {
		root := ms.obj_roots[hash] or { return error('E_STORE_NOT_FOUND: ${hash}') }
		// Resolve objects through the universal ObjectBackend seam (#76): the live
		// in-memory graph FIRST (just-written docs), then the durable backend (every
		// persisted object, incl. after a reopen when the sink starts empty). The same
		// composite reader serves mem, the lazy disk backends, and cxpack alike.
		getter := store_graph_getter(ms)
		if ms.model == 'document' {
			// Degenerate model (spec §2/§4.6): the doc IS a single raw object (its
			// canonical bytes), not a decomposed graph — return it verbatim.
			payload := getter(root) or {
				return error('object graph: document ${hash} object missing/corrupt')
			}
			return payload.bytestr()
		}
		if store_whole_doc_root(hash, root) {
			// Stream 20: a subject-bearing doc is stored WHOLE (one sealed
			// object — structural sharing never crosses the shred boundary);
			// self-identifying: the root object's key IS the doc hash. A
			// failed open classifies from EVIDENCE (M29): shredded iff a
			// journaled erasure record covers the address, unavailable
			// fail-closed otherwise — never guessed from key absence alone.
			payload := getter(root) or {
				return error(store_shredded_read_err(mut m, hash, root))
			}
			return payload.bytestr()
		}
		doc := cxstore.load_document_from(getter, root) or {
			return error('object graph: doc ${hash} failed to reconstruct (corrupt/missing object): ${err.msg()}')
		}
		if doc.elements.len == 0 {
			return error('object graph: doc ${hash} reconstructed to an empty document')
		}
		return render_canonical(doc.elements[0])
	}
	if hash in ms.docs {
		return ms.docs[hash]
	}
	return error('E_STORE_NOT_FOUND: ${hash}')
}

// store_put_canonical stores canonical doc TEXT locally under `hash` — into the
// live object graph (cxpack) or the docs map. Idempotent: re-putting an existing
// hash is a no-op (content-addressed). Appends to doc_order on first insert.
// Returns true iff the doc was newly inserted (so the caller persists only on a
// real change).
fn store_put_canonical(mut ms MemStore, hash string, canonical string) !bool {
	store_lock_enter(mut ms)
	defer {
		store_lock_exit(mut ms)
	}
	if store_objgraph_active(ms) {
		if hash in ms.obj_roots {
			return false
		}
		store_erased_clear_local(mut ms, hash) // an insert supersedes a tombstone (§7b.1)
		if ms.model == 'document' {
			// Degenerate model (spec §2/§4.6): store the whole canonical doc as ONE
			// object ("don't decompose"); no cross-subtree dedup, simplest/perf form.
			// Same store-key (doc hash) as subtree → model is invisible to the API.
			root := ms.obj_sink.put(canonical.bytes())
			ms.obj_roots[hash] = root
			ms.doc_order << hash
			store_feed_append(mut ms, 'docs', 'insert', '', hash, root)
			return true
		}
		doc := cx.parse(canonical) or {
			return error('object graph: undecodable canonical for ${hash}: ${err.msg()}')
		}
		root := cxstore.store_document(mut ms.obj_sink, doc, cxstore.default_fanout)
		ms.obj_roots[hash] = root
		ms.doc_order << hash
		store_feed_append(mut ms, 'docs', 'insert', '', hash, root)
		return true
	}
	if hash !in ms.docs {
		store_erased_clear_local(mut ms, hash)
		ms.docs[hash] = canonical
		ms.doc_order << hash
		store_feed_append(mut ms, 'docs', 'insert', '', hash, []u8{})
		return true
	}
	return false
}

// ── F1' OPAQUE documents (blobs): identity = hash of the RAW bytes ──────────
// store_put_blob_local stores raw bytes under their raw-hash key —
// content-addressed, byte-exact, never canonicalized (CX code, images, plain
// text). Idempotent (dedup by key). The key self-verifies: every READ
// re-checks key == hash(raw) in store_get_blob_local, so the skip-verify
// class the retired code-record kind carried cannot exist for blobs.
fn store_put_blob_local(mut ms MemStore, raw string) !string {
	key := cx.cx_tag_address(cx.cx_default_hash_algo, sha256.sum256(raw.bytes()).hex())
	store_lock_enter(mut ms)
	defer {
		store_lock_exit(mut ms)
	}
	if key in ms.blob_kind {
		return key // content-addressed dedup: same bytes, same key, no-op
	}
	store_erased_clear_local(mut ms, key)
	if store_objgraph_active(ms) {
		leaf := ms.obj_sink.put(raw.bytes())
		ms.obj_roots[key] = leaf
	} else {
		ms.docs[key] = raw
	}
	ms.doc_order << key
	ms.blob_kind[key] = true
	store_feed_append(mut ms, 'docs', 'insert', '', key, []u8{})
	return key
}

// store_get_blob_local returns the raw bytes at a blob key, VERIFYING
// key == hash(raw) at the read boundary (F1': every storage path verifies —
// this per-read check also covers the flat-index replay path, which has no
// error return of its own). Absent-or-not-a-blob → a NOT_FOUND-classed
// error; a rehash mismatch → an INTEGRITY-classed error (the verb layer maps
// on the message class).
fn store_get_blob_local(ms &MemStore, key string) !string {
	mut m := unsafe { ms }
	store_lock_enter(mut m)
	defer {
		store_lock_exit(mut m)
	}
	if key !in ms.blob_kind {
		return error('E_STORE_NOT_FOUND: ${key}')
	}
	raw := if store_objgraph_active(ms) {
		root := ms.obj_roots[key] or { return error('E_STORE_NOT_FOUND: ${key}') }
		getter := store_graph_getter(ms)
		payload := getter(root) or {
			return error('E_STORE_INTEGRITY_MISMATCH: blob object missing for ${key}')
		}
		payload.bytestr()
	} else {
		ms.docs[key] or { return error('E_STORE_NOT_FOUND: ${key}') }
	}
	rehash := cx.cx_tag_address(cx.cx_default_hash_algo, sha256.sum256(raw.bytes()).hex())
	if rehash != key {
		return error('E_STORE_INTEGRITY_MISMATCH: blob ${key} rehashes to ${rehash}')
	}
	return raw
}

// store_erase_doc_local — the ONE doc-level lawful-shred funnel (xsp store
// profile §7b.1; stream 20 mounts the SEK key hierarchy UNDER this same
// funnel later). It destroys the doc entry AND records the attributed
// tombstone in the same act. Returns false when the hash is already erased
// (idempotent — `deduped`, never a second destructive act). Erasing an
// ABSENT doc still records the tombstone: a replica applying a shred for a
// doc it never held converges to the same erased answer, not to not-found.
fn store_erase_doc_local(mut ms MemStore, hash string, tombstone string) bool {
	store_lock_enter(mut ms)
	defer {
		store_lock_exit(mut ms)
	}
	if hash in ms.erased {
		return false
	}
	mut root := []u8{}
	if store_objgraph_active(ms) {
		if r := ms.obj_roots[hash] {
			root = r.clone()
		}
		ms.obj_roots.delete(hash)
		// the tombstone text rides the object layer as one more
		// content-addressed leaf (the alias-name precedent), so every
		// object-graph substrate persists it through the ordinary sink
		// staging and the E manifest record resolves it on replay.
		ms.obj_sink.put(tombstone.bytes())
	} else {
		ms.docs.delete(hash)
	}
	// F1': erased opaque docs drop their kind mark too (put-blob dedup must
	// never hit an erased entry).
	ms.blob_kind.delete(hash)
	idx := ms.doc_order.index(hash)
	if idx >= 0 {
		ms.doc_order.delete(idx)
		if idx < ms.doc_scanned {
			ms.doc_scanned--
		}
	}
	ms.has_removals = true // the doc's removal rides the ordinary T path
	ms.erased[hash] = tombstone
	ms.erased_order << hash
	if root.len > 0 {
		ms.erased_roots[root.hex()] = hash
	}
	ms.erased_dirty << hash
	store_feed_append(mut ms, 'docs', 'erase', '', hash, root)
	return true
}

// store_erased_clear_local removes an erased record when a later put
// re-lands the same content — the insert SUPERSEDES the tombstone (§7b.1:
// erasure destroys what was held, it does not censor future acts; the
// lineage records both). Caller holds the op lock.
fn store_erased_clear_local(mut ms MemStore, hash string) {
	if hash !in ms.erased {
		return
	}
	ms.erased.delete(hash)
	idx := ms.erased_order.index(hash)
	if idx >= 0 {
		ms.erased_order.delete(idx)
	}
	mut dead_roots := []string{}
	for rh, dh in ms.erased_roots {
		if dh == hash {
			dead_roots << rh
		}
	}
	for rh in dead_roots {
		ms.erased_roots.delete(rh)
	}
	// The superseding put's own D record clears the tombstone on replay
	// (replay order decides — the T re-put precedent), so a clear emits no
	// line of its own; dropping the manifested mark is what lets a LATER
	// re-erase emit a fresh operative E record.
	ms.erased_manifested.delete(hash)
}

// store_erase_tombstone builds the attributed `[erased …]` tombstone's
// canonical text — the §6 ruled shape `[erased subject? at= authority=
// actor= shred-request=]` (who erased, under what authority, when —
// attribution always survives). `subject` is deliberately never emitted:
// post-shred the substrate names the subject only from the journaled
// record (§4); the tombstone lives in the substrate. `hash`/`root` lead as
// addressing mechanics (`root`, the former doc root, rides for the
// object-wire discriminator); `authority` is omitted when unclaimed (the
// pre-§6 xsp erase arm — the shred walk always claims one).
fn store_erase_tombstone(hash string, root []u8, at string, actor string, authority string, request string) string {
	mut attrs := [
		cx.Attribute{
			name:  'hash'
			value: cx.ScalarValue(hash)
		},
	]
	if root.len > 0 {
		attrs << cx.Attribute{
			name:  'root'
			value: cx.ScalarValue(root.hex())
		}
	}
	attrs << cx.Attribute{
		name:  'at'
		value: cx.ScalarValue(at)
	}
	if authority != '' {
		attrs << cx.Attribute{
			name:  'authority'
			value: cx.ScalarValue(authority)
		}
	}
	attrs << cx.Attribute{
		name:  'actor'
		value: cx.ScalarValue(actor)
	}
	attrs << cx.Attribute{
		name:  'shred-request'
		value: cx.ScalarValue(request)
	}
	return render_canonical(cx.Element{
		name:  'erased'
		attrs: attrs
	})
}

// store_delete_local removes a doc from local storage (object graph or docs map)
// and from doc_order. Object-graph objects left unreferenced are reclaimed at
// compaction (content-addressed; a shared object stays live for other docs).
fn store_delete_local(mut ms MemStore, hash string) {
	store_lock_enter(mut ms)
	defer {
		store_lock_exit(mut ms)
	}
	if store_objgraph_active(ms) {
		ms.obj_roots.delete(hash)
	} else {
		ms.docs.delete(hash)
	}
	// F1': drop the opaque-kind mark too, or a later put-blob of the same
	// bytes would dedup against a deleted entry and never re-add it.
	ms.blob_kind.delete(hash)
	idx := ms.doc_order.index(hash)
	if idx >= 0 {
		ms.doc_order.delete(idx)
		// #603: deleting below the scan cursor shifts the unscanned tail left
		// by one — keep the cursor aligned or a later-put doc would slip under
		// it and never reach the manifest.
		if idx < ms.doc_scanned {
			ms.doc_scanned--
		}
	}
	// #603: arm the tombstone scan on the next delta.
	ms.has_removals = true
	store_feed_append(mut ms, 'docs', 'retract', '', hash, []u8{})
}

// ── E3 lineage (#708 + I5 stream-4 W4) ───────────────────────────────────────
//
// StoreAdvance is one recorded act on a mount: a doc insert/retract (the docs
// plane is ONE stream) or a named-ref/alias advance/retract (per-name
// streams). `pos` is the dense per-stream E3 position ("v17" = the 17th
// advance of that ref); re-pointing a ref at its current target IS an advance
// and branch-force advances APPEAR (an invisible force-move hollows the audit
// story — semantic_value_model §4).
struct StoreAdvance {
	plane string // 'docs' | 'refs' | 'aliases'
	kind  string // 'insert' | 'retract' | 'advance'
	name  string // ref/alias name; '' on the docs plane
	hash  string // doc hash (docs) / alias target (aliases); '' on refs
	root  []u8   // object root digest (docs/refs planes; empty on docs-map backends)
	pos   i64
}

fn store_feed_stream_key(plane string, name string) string {
	if plane == 'docs' {
		return 'docs'
	}
	return plane + '/' + name
}

// store_feed_append records one live act. Callers hold the op lock (every
// funnel below enters it reentrantly).
fn store_feed_append(mut ms MemStore, plane string, kind string, name string, hash string, root []u8) {
	key := store_feed_stream_key(plane, name)
	pos := (ms.adv_pos[key] or { i64(0) }) + 1
	ms.adv_pos[key] = pos
	a := StoreAdvance{
		plane: plane
		kind:  kind
		name:  name
		hash:  hash
		root:  root
		pos:   pos
	}
	ms.advances << a
	// FL-1 (#764): the same act lands in the durable lineage sidecar —
	// append-ordered, BEFORE the caller's state append — so positions
	// survive restart (a no-op while lineage_active is false: seeding,
	// read-only handles, substrates with no local root).
	store_lineage_append(mut ms, a)
}

// store_feed_seed compacts the just-loaded snapshot into the lineage: one
// insert per live doc (doc_order = the canonical snapshot order), one advance
// per named ref and alias — the store's honest history-compacted-to-snapshot
// form (`changes-since` from the empty cursor ≡ a one-time [?for], the
// live-modes equivalence quartet). Since FL-1 (#764) this is the FIRST-BOOT
// path only (no persisted lineage yet — fresh store, upgraded store, or a
// discarded sidecar): store_feed_open reloads a verified sidecar instead,
// and the epoch token then survives restarts. Runs ONCE per MemStore (first
// open of a shared root); the epoch token marks the retention boundary.
fn store_feed_seed(mut ms MemStore) {
	if ms.feed_boot != '' {
		return
	}
	ms.feed_boot = store_feed_boot_token()
	for key in ms.doc_order {
		mut root := []u8{}
		if r := ms.obj_roots[key] {
			root = r.clone()
		}
		mut tagged := true
		cx.cx_parse_tagged_address(key) or { tagged = false }
		if tagged {
			store_feed_append(mut ms, 'docs', 'insert', '', key, root)
		} else {
			// an untagged doc_order key is a named wire ref (refs-set)
			store_feed_append(mut ms, 'refs', 'advance', key, '', root)
		}
	}
	for name in ms.alias_order {
		target := ms.aliases[name] or { continue }
		store_feed_append(mut ms, 'aliases', 'advance', name, target, []u8{})
	}
	// erased tombstones compact into the seed as erase acts (after the
	// inserts, matching act order for any doc that was put-then-erased
	// before this boot): the from-empty replay tells the honest story.
	for hash in ms.erased_order {
		mut root := []u8{}
		for rh, dh in ms.erased_roots {
			if dh == hash {
				root = hex_decode_or_empty(rh)
			}
		}
		store_feed_append(mut ms, 'docs', 'erase', '', hash, root)
	}
}

fn hex_decode_or_empty(s string) []u8 {
	return hex.decode(s) or { []u8{} }
}

fn store_feed_boot_token() string {
	b := crypto_random_octets(8) or {
		return 'boot-${time.now().unix_nano()}'
	}
	return b.hex()
}

// store_ref_advance_local — the ONE live funnel for advancing a named wire
// ref (store-key → root; the refs-set verb on both the CSRP and XSP
// listeners). Validate-then-apply stays the caller's job; this applies one
// advance and records it.
fn store_ref_advance_local(mut ms MemStore, key string, root []u8) {
	store_lock_enter(mut ms)
	defer {
		store_lock_exit(mut ms)
	}
	if key !in ms.obj_roots {
		ms.doc_order << key
	}
	ms.obj_roots[key] = root
	store_feed_append(mut ms, 'refs', 'advance', key, '', root)
}

// store_alias_set_local / store_alias_delete_local — the ONE internal seam for
// mutating the live alias table (#603): they keep alias_order and the O(delta)
// flush discovery (alias_dirty / has_removals) aligned with the aliases map.
// Every live writer (the set/delete verbs, branch, migrate, tests poking a
// MemStore directly) routes here; load/replay paths set the maps directly and
// reseed the watermarks wholesale (store_graph_seed_watermarks) instead.
fn store_alias_set_local(mut ms MemStore, name string, hash string) {
	store_lock_enter(mut ms)
	defer {
		store_lock_exit(mut ms)
	}
	if name !in ms.aliases {
		ms.alias_order << name
	}
	ms.aliases[name] = hash
	ms.alias_dirty << name
	store_feed_append(mut ms, 'aliases', 'advance', name, hash, []u8{})
}

fn store_alias_delete_local(mut ms MemStore, name string) bool {
	store_lock_enter(mut ms)
	defer {
		store_lock_exit(mut ms)
	}
	if name !in ms.aliases {
		return false
	}
	ms.aliases.delete(name)
	idx := ms.alias_order.index(name)
	if idx >= 0 {
		ms.alias_order.delete(idx)
	}
	ms.has_removals = true
	store_feed_append(mut ms, 'aliases', 'retract', name, '', []u8{})
	return true
}

// (The computation-identity-keyed code namespace — cx_code_store_put_def /
// cx_code_store_get_def / store_put_raw, the `code:` key prefix — is RETIRED
// under F1'/A3, 2026-08-08: code is an OPAQUE document, stored byte-exact by
// put-blob under the hash of its raw bytes. Computation identity remains the
// pure relation [$cx:computation-id] / cx_code_tier2_hash — an index/claim,
// never a storage key. Legacy code:-keyed records refuse loudly at load.)
