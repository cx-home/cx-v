module code

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
fn store_graph_getter(ms &MemStore) fn (h []u8) ?[]u8 {
	return fn [ms] (h []u8) ?[]u8 {
		if p := ms.obj_sink.get(h) {
			return p
		}
		if be := ms.obj_backend {
			return be.get_object(h)
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
		rec := if h.starts_with('code:') { 'C' } else { 'D' }
		lines << '${rec}\t${h}\t${root.hex()}'
	}
	for a in ms.alias_order {
		dh := ms.aliases[a] or { continue }
		nk := cxstore.object_name(a.bytes()).hex()
		lines << 'A\t${nk}\t${dh}'
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
}

// store_graph_delta computes the refs delta since the last persist — new
// docs/code (D/C), removed docs (T), new/updated aliases (A), removed aliases
// (X) — against the doc_manifested / alias_manifested watermarks. Pure compute;
// commits nothing.
fn store_graph_delta(ms &MemStore) GraphDelta {
	mut lines := []string{}
	mut new_docs := []string{}
	for h in ms.doc_order {
		if h in ms.doc_manifested {
			continue
		}
		root := ms.obj_roots[h] or { continue }
		rec := if h.starts_with('code:') { 'C' } else { 'D' }
		lines << '${rec}\t${h}\t${root.hex()}'
		new_docs << h
	}
	mut removed_docs := []string{}
	for h, _ in ms.doc_manifested {
		if h !in ms.obj_roots {
			lines << 'T\t${h}\t-'
			removed_docs << h
		}
	}
	mut set_aliases := map[string]string{}
	for a in ms.alias_order {
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
	for a, _ in ms.alias_manifested {
		if a !in ms.aliases {
			nk := cxstore.object_name(a.bytes()).hex()
			lines << 'X\t${nk}\t-'
			removed_aliases << a
		}
	}
	return GraphDelta{
		lines:           lines
		new_docs:        new_docs
		removed_docs:    removed_docs
		set_aliases:     set_aliases
		removed_aliases: removed_aliases
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
	ms.log_records += d.lines.len
}

// store_graph_manifest_delta appends the refs delta since the last persist to
// the manifest FILE at `mp` and advances the watermarks. The caller MUST have
// already made the referenced objects (doc roots + alias-name objects) durable
// in its backend. SHARED by the file-manifest substrates (cxobj; cxpack has its
// own flush over the same delta helpers).
fn store_graph_manifest_delta(mut ms MemStore, mp string) ! {
	d := store_graph_delta(ms)
	if d.lines.len == 0 {
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
				if ms.model == 'document' {
					// Degenerate model: the doc is one raw object — verify it is present
					// + self-verifying (the getter rejects a hash mismatch), no decompose.
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
			}
			'C' {
				key := parts[1]
				root := hex.decode(parts[2]) or {
					return error('${where}: bad object hash for code ${key}: ${err.msg()}')
				}
				getter(root) or {
					return error('${where}: code object missing for ${key}')
				}
				if key !in ms.obj_roots {
					ms.obj_roots[key] = root
					ms.doc_order << key
				}
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
			else {} // unknown record type — forward-compatible, ignore
		}
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
	if mut be := ms.obj_backend {
		cxstore.persist_objects(mut be, ms.obj_sink) or {
			return error('cxobj ${ms.root}: object write failed: ${err.msg()}')
		}
		store_graph_stage_aliases(mut be, ms) or {
			return error('cxobj ${ms.root}: alias-name object write failed: ${err.msg()}')
		}
		ms.obj_backend = be
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
			ms.obj_backend = store_enc_object_backend(objdir, ms.enc_key_id)!
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
@[heap]
struct EnvKms {
mut:
	inner &cxstore.LocalKms
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

fn (mut k EnvKms) generate_data_key(key_id string) !([]u8, []u8) {
	k.env_kek(key_id)!
	return k.inner.generate_data_key(key_id)!
}

fn (mut k EnvKms) decrypt_data_key(key_id string, wrapped []u8) ![]u8 {
	k.env_kek(key_id)!
	return k.inner.decrypt_data_key(key_id, wrapped)!
}

fn (mut k EnvKms) encrypt_data_key(key_id string, dek []u8) ![]u8 {
	k.env_kek(key_id)!
	return k.inner.encrypt_data_key(key_id, dek)!
}

// store_kek_kms resolves the tenant KEK from env `CX_STORE_KEK_<key_id>` into
// the EnvKms reference provider (eagerly for the configured id — fail-closed at
// open; lazily for any other key-id an envelope records, the mid-rotation read
// path). A production deployment supplies a real KMS (AWS/GCP/Vault) through
// the same cxstore.Kms seam.
fn store_kek_kms(key_id string) !cxstore.Kms {
	mut kms := &EnvKms{
		inner: cxstore.new_local_kms_locked()
	}
	kms.env_kek(key_id)!
	return cxstore.Kms(kms)
}

// store_enc_object_backend builds an EncryptingObjectBackend (#114) over `objdir`
// for the object-per-key substrate, KEK-resolved via store_kek_kms.
fn store_enc_object_backend(objdir string, key_id string) !cxstore.ObjectBackend {
	kms := store_kek_kms(key_id)!
	be := cxstore.new_encrypting_object_backend(objdir, key_id, kms)!
	return cxstore.ObjectBackend(&be)
}
