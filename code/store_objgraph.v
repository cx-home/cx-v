module code

import cx
import cxstore

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
	if store_objgraph_active(ms) {
		root := ms.obj_roots[hash] or { return error('E_STORE_NOT_FOUND: ${hash}') }
		// Resolve objects through the universal ObjectBackend seam (#76): the live
		// in-memory graph FIRST (just-written docs), then the durable backend (every
		// persisted object, incl. after a reopen when the sink starts empty). The same
		// composite reader serves mem, the lazy disk backends, and cxpack alike.
		getter := store_graph_getter(ms)
		if hash.starts_with('code:') {
			// #128-A: a code: entry is verbatim source stored as a single raw-leaf
			// object (CX code does not data-parse), not a decomposed data doc.
			payload := getter(root) or {
				return error('object graph: code ${hash} object missing')
			}
			return payload.bytestr()
		}
		if ms.model == 'document' {
			// Degenerate model (spec §2/§4.6): the doc IS a single raw object (its
			// canonical bytes), not a decomposed graph — return it verbatim.
			payload := getter(root) or {
				return error('object graph: document ${hash} object missing/corrupt')
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
	if store_objgraph_active(ms) {
		if hash in ms.obj_roots {
			return false
		}
		if ms.model == 'document' {
			// Degenerate model (spec §2/§4.6): store the whole canonical doc as ONE
			// object ("don't decompose"); no cross-subtree dedup, simplest/perf form.
			// Same store-key (doc hash) as subtree → model is invisible to the API.
			root := ms.obj_sink.put(canonical.bytes())
			ms.obj_roots[hash] = root
			ms.doc_order << hash
			return true
		}
		doc := cx.parse(canonical) or {
			return error('object graph: undecodable canonical for ${hash}: ${err.msg()}')
		}
		root := cxstore.store_document(mut ms.obj_sink, doc, cxstore.default_fanout)
		ms.obj_roots[hash] = root
		ms.doc_order << hash
		return true
	}
	if hash !in ms.docs {
		ms.docs[hash] = canonical
		ms.doc_order << hash
		return true
	}
	return false
}

// store_put_raw stores a verbatim text payload (NOT a parseable data doc — e.g.
// CX code source) under `key` as a single raw-leaf object in the live graph (or
// the docs map for non-graph backends). Used for the `code:` namespace (#128-A):
// code entries are source text, not data documents, so they are never
// decomposed. Idempotent; returns true iff newly inserted.
fn store_put_raw(mut ms MemStore, key string, raw string) !bool {
	if store_objgraph_active(ms) {
		if key in ms.obj_roots {
			return false
		}
		leaf := ms.obj_sink.put(raw.bytes())
		ms.obj_roots[key] = leaf
		ms.doc_order << key
		return true
	}
	if key !in ms.docs {
		ms.docs[key] = raw
		ms.doc_order << key
		return true
	}
	return false
}

// store_delete_local removes a doc from local storage (object graph or docs map)
// and from doc_order. Object-graph objects left unreferenced are reclaimed at
// compaction (content-addressed; a shared object stays live for other docs).
fn store_delete_local(mut ms MemStore, hash string) {
	if store_objgraph_active(ms) {
		ms.obj_roots.delete(hash)
	} else {
		ms.docs.delete(hash)
	}
	idx := ms.doc_order.index(hash)
	if idx >= 0 {
		ms.doc_order.delete(idx)
	}
}
