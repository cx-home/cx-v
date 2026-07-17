module code

import cx
import cxstore

// store_rotation.v — KEK rotation for encrypted stores (#287 / store.md §9.1).
//
// `[$store:rotate-kek $store <new-key-id>]` walks every at-rest envelope on the
// open store's durable substrate and re-wraps its per-object DEK from the
// envelope's RECORDED key-id to the new tenant key. Payloads (sealed by
// unchanged DEKs) and content addresses (plaintext hashes) are untouched — no
// data re-encryption, no address churn, dedup preserved. Atomic per object,
// resumable (an envelope already under the new key-id is `already-current` and
// left byte-identical), fail-closed throughout: an envelope whose DEK unwraps
// under NEITHER key aborts with CXER1142 naming the object — never a silent
// skip, which would surface as data loss only after the old KEK is destroyed.
//
// Per-substrate walk (each has its own enumeration + atomic-replace surface):
//   cxobj  — EncryptingObjectBackend.rotate_kek (temp file + rename per object)
//   cxpack — re-wrap every durable envelope, fold into ONE new compacted keyed
//            pack installed by atomic rename (store-level atomicity — stronger
//            than per-object; the manifest is hash-keyed and untouched)
//   sqlite — one INSERT OR REPLACE per row (statement-level atomicity)
//   s3     — one unconditional PUT per key (PUT is atomic per key)
// After the walk the handle's write key becomes the new key-id (new objects
// wrap under the new KEK); reads never cared (they follow each envelope's
// recorded key-id), which is what keeps the store serving THROUGHOUT.

const store_err_rotation_unsupported = 'cx-err:CXER1141'
const store_err_rotation_failed = 'cx-err:CXER1142'

// store_rotate_kek — the `store-rotate-kek` builtin behind
// `[$store:rotate-kek $store $new-key-id]`.
fn store_rotate_kek(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err('cx-err:CXER0108', 'E_ARG: rotate-kek expects ($store $new-key-id)')
	}
	mut ms, errn, ok := store_get_open(args[0])
	if !ok {
		return errn
	}
	// Encryption is a local at-rest concern; CSRP carries no key material, so a
	// service-tier handle refuses (operators rotate on the daemon host via
	// `cx store-rotate-kek`, where the KEK env lives) — store.md §6.3/§9.1.
	if store_remote_active(ms) {
		return mk_err('cx-err:CXER1709',
			'E_CSRP_OPERATION_UNSUPPORTED: rotate-kek is a local at-rest op — rotate on the daemon host (cx store-rotate-kek), never over the wire')
	}
	if ms.read_only {
		return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${ms.url}')
	}
	if ms.enc_key_id == '' {
		return mk_err(store_err_rotation_unsupported,
			'E_STORE_ROTATION_UNSUPPORTED: ${ms.url} is not encrypted at rest — rotate-kek re-wraps envelope data keys and has nothing to rotate on a plaintext store (store.md §9.1)')
	}
	new_key_id := store_arg_str(args[1]) or { return none }
	if new_key_id.len == 0 || new_key_id.len > 255 {
		return mk_err('cx-err:CXER0108', 'E_ARG: rotate-kek new-key-id must be 1..255 bytes')
	}
	// Flush staged objects first so the walk sees every envelope durable (the
	// handle keeps serving; this is the same persist any mutation performs).
	store_persist(mut ms) or { return store_persist_err(ms, err.msg()) }
	mut rep := cxstore.KekRotation{}
	match ms.backend {
		'cxobj' {
			rep = store_rotate_cxobj(mut ms, new_key_id) or {
				return mk_err(store_err_rotation_failed,
					'E_STORE_ROTATION_FAILED: ${ms.url}: ${err.msg()}')
			}
		}
		'cxpack' {
			rep = store_rotate_cxpack(mut ms, new_key_id) or {
				return mk_err(store_err_rotation_failed,
					'E_STORE_ROTATION_FAILED: ${ms.url}: ${err.msg()}')
			}
		}
		'sqlite' {
			mut failed := ''
			$if cxstore_sqlite ? {
				rep = store_rotate_sqlite(mut ms, new_key_id) or {
					failed = err.msg()
					cxstore.KekRotation{}
				}
			} $else {
				failed = 'sqlite backend not built (-d cxstore_sqlite)'
			}
			if failed != '' {
				return mk_err(store_err_rotation_failed,
					'E_STORE_ROTATION_FAILED: ${ms.url}: ${failed}')
			}
		}
		's3' {
			rep = store_rotate_s3(mut ms, new_key_id) or {
				return mk_err(store_err_rotation_failed,
					'E_STORE_ROTATION_FAILED: ${ms.url}: ${err.msg()}')
			}
		}
		else {
			return mk_err(store_err_rotation_unsupported,
				'E_STORE_ROTATION_UNSUPPORTED: substrate `${ms.backend}` has no at-rest envelopes to rotate (store.md §9.1)')
		}
	}

	// The handle's write key is now the new tenant key: objects sealed from here
	// on wrap under it (the walk above re-wrapped everything already durable).
	ms.enc_key_id = new_key_id
	return cx.Element{
		name:  'rotation-report'
		attrs: [
			cx.Attribute{
				name:  'objects'
				value: cx.ScalarValue(i64(rep.objects))
			},
			cx.Attribute{
				name:  'rewrapped'
				value: cx.ScalarValue(i64(rep.rewrapped))
			},
			cx.Attribute{
				name:  'already-current'
				value: cx.ScalarValue(i64(rep.already_current))
			},
			cx.Attribute{
				name:  'from'
				value: cx.ScalarValue(rep.from_ids.join(','))
			},
			cx.Attribute{
				name:  'to'
				value: cx.ScalarValue(new_key_id)
			},
		]
	}
}

// store_enc_wrapper resolves the store's EncryptingWrapper (the sealed
// substrates route their durable objects through it), reaching through the
// obj_backend interface. none for cxobj (EncryptingObjectBackend) and cxpack
// (obj_pack_enc field).
fn store_enc_wrapper(mut ms MemStore) ?&cxstore.EncryptingWrapper {
	mut be := ms.obj_backend or { return none }
	if mut be is cxstore.EncryptingWrapper {
		return be
	}
	return none
}

// store_rotate_cxobj — object-per-key substrate: the walk lives on the backend
// itself (one envelope file per object; temp + rename per object).
fn store_rotate_cxobj(mut ms MemStore, new_key_id string) !cxstore.KekRotation {
	mut be := ms.obj_backend or { return error('object backend not attached') }

	if mut be is cxstore.EncryptingObjectBackend {
		rep := be.rotate_kek(new_key_id)!
		ms.obj_backend = be
		return rep
	}
	return error('object-per-key store is not routed through the encrypting backend')
}

// store_rotate_cxpack — pack substrate: every durable envelope is re-wrapped
// and folded into ONE new compacted keyed pack, installed by atomic rename
// (write_compacted_keyed). A crash mid-rotation leaves the previous pack whole;
// the hash-keyed manifest is untouched (rotation keeps every key — it is not a
// GC). Requires nothing staged, which the caller's persist guarantees.
fn store_rotate_cxpack(mut ms MemStore, new_key_id string) !cxstore.KekRotation {
	if ms.obj_pack == unsafe { nil } || ms.obj_pack_enc == unsafe { nil } {
		return error('encrypted pack backend not attached')
	}
	if ms.obj_pack.pending_count() > 0 {
		return error('staged objects pending — persist before rotation')
	}
	ms.obj_pack_enc.probe_key(new_key_id)!
	mut rep := cxstore.KekRotation{}
	mut seen_from := map[string]bool{}
	keys := ms.obj_pack.durable_keys()
	if keys.len == 0 {
		// Never-persisted / empty store: nothing at rest to re-wrap, and writing
		// an empty compacted pack to a manifest-less directory would fabricate a
		// "partially-present store" for the next open.
		ms.obj_pack_enc.set_key_id(new_key_id)
		return rep
	}
	mut entries := []cxstore.KeyedPayload{cap: keys.len}
	for key in keys {
		env := ms.obj_pack.get_object_raw(key) or {
			return error('object ${key.hex()}: envelope missing from packs')
		}
		nb, old_id, changed := ms.obj_pack_enc.rewrap_envelope(env, new_key_id) or {
			return error('object ${key.hex()}: ${err.msg()}')
		}
		rep.objects++
		if changed {
			rep.rewrapped++
			if old_id !in seen_from {
				seen_from[old_id] = true
				rep.from_ids << old_id
			}
		} else {
			rep.already_current++
		}
		entries << cxstore.KeyedPayload{
			key:  key
			blob: nb
		}
	}
	ms.obj_pack.write_compacted_keyed(entries) or {
		return error('rotated pack write failed: ${err.msg()}')
	}
	ms.obj_pack_enc.set_key_id(new_key_id)
	return rep
}

// store_rotate_s3 — s3 substrate: enumerate the object keys, re-wrap each
// envelope, PUT it back unconditionally (atomic per key).
fn store_rotate_s3(mut ms MemStore, new_key_id string) !cxstore.KekRotation {
	mut w := store_enc_wrapper(mut ms) or {
		return error('s3 store is not routed through the encrypting wrapper')
	}
	mut ib := w.inner_backend()
	if mut ib is S3ObjectBackend {
		w.probe_key(new_key_id)!
		mut rep := cxstore.KekRotation{}
		mut seen_from := map[string]bool{}
		keys := ib.object_keys()!
		for key in keys {
			env := ib.get_object_raw(key) or {
				femsg := store_s3_take_fail_error(mut ib, ms.url)
				if femsg != '' {
					return error('object ${key.hex()}: ${femsg}')
				}
				return error('object ${key.hex()}: envelope missing')
			}
			nb, old_id, changed := w.rewrap_envelope(env, new_key_id) or {
				return error('object ${key.hex()}: ${err.msg()}')
			}
			rep.objects++
			if !changed {
				rep.already_current++
				continue
			}
			ib.replace_object_keyed(key, nb) or {
				return error('object ${key.hex()}: ${err.msg()}')
			}
			rep.rewrapped++
			if old_id !in seen_from {
				seen_from[old_id] = true
				rep.from_ids << old_id
			}
		}
		w.set_key_id(new_key_id)
		return rep
	}
	return error('s3 store backend shape unexpected')
}

// ── daemon/operator CLI wrapper (`cx store-rotate-kek`, cmd/) ────────────────

// svc_rotate_kek opens `url` under old_key_id, rotates every envelope to
// new_key_id, closes the handle, and returns the [rotation-report …] (or the
// err value). The `cx store-rotate-kek` CLI verb drives this; the caller is
// responsible for capability grants (cmd sets read/write and net for s3).
pub fn svc_rotate_kek(url string, old_key_id string, new_key_id string) cx.Node {
	mut auth := map[string]string{}
	auth['encrypt-key-id'] = old_key_id
	h := store_open_impl(url, '', '', false, true, auth)
	if is_err_value(h) {
		return h
	}
	r := store_stdlib_builtin_inner('store-rotate-kek', [h, store_str(new_key_id)]) or {
		mk_err(store_err_rotation_failed,
			'E_STORE_ROTATION_FAILED: rotation produced no result for ${url}')
	}
	store_stdlib_builtin_inner('store-close', [h]) or { cx.Node(cx.Element{}) }
	return r
}
