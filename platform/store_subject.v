module platform

import cx
import cxstore
import code {
	mk_err,
}

// store_subject.v — stream 20 (#692, erasure_compliance §3/§4): the reserved
// subject vocabulary on the store write surface.
//
// `subject=` and `nonce=` are RESERVED PAYLOAD ATTRIBUTES on a doc's root
// element. A subject-bearing doc:
//   - MUST carry a ≥128-bit CSPRNG `nonce=` inside the payload (the digest-
//     oracle defense; refusal CXER4619 E_ERASURE_NONCE_REQUIRED, never a
//     warning) — the nonce IS content, covered by the address, destroyed by
//     the same shred;
//   - stores as ONE WHOLE sealed object (its canonical bytes), never the
//     decomposed subtree graph: structural sharing must not cross the shred
//     boundary (a shared subtree sealed under one subject's SEK would strand
//     unrelated docs when that subject is shredded, or leak subject bytes
//     under the tenant key in the reverse order). Dedup is correctly lost
//     only for nonced records (§3). The whole-doc object self-identifies:
//     its object key IS the doc hash (canonical bytes both ways);
//   - seals under the subject's SEK (`sek/<tenant>/<token>`) — the
//     destroyable middle key tier; destroying that one key crypto-shreds
//     exactly this subject's payloads.
//
// Custody is fail-closed: a plaintext store, a remote/wire handle, or a
// substrate with no key custody refuses (CXER1144) — accepting a subject
// declaration the substrate can never shred would be a compliance trap.
// Erasure over the wire is the stream-4/9 joint surface, not this one.

// store_whole_doc_root reports whether a doc's root object IS the doc itself
// (its canonical bytes stored whole): the object key's tagged form equals the
// doc hash — cryptographically self-identifying, no per-doc metadata needed.
// True for every subject-bearing doc and for document-model roots; never true
// for a decomposed subtree root (node encoding ≠ canonical text bytes).
fn store_whole_doc_root(hash string, root []u8) bool {
	return cx.cx_tag_address(cx.cx_default_hash_algo, root.hex()) == hash
}

// store_subject_attr returns the doc root's `subject=` attribute, if any.
fn store_subject_attr(n cx.Node) ?string {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'subject' {
				s := cx.scalar_value_str_public(a.value)
				if s != '' {
					return s
				}
			}
		}
	}
	return none
}

// store_nonce_attr returns the doc root's `nonce=` attribute, if any.
fn store_nonce_attr(n cx.Node) ?string {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'nonce' {
				s := cx.scalar_value_str_public(a.value)
				if s != '' {
					return s
				}
			}
		}
	}
	return none
}

// store_subject_nonce_err applies the §3 nonce discipline: mandatory on every
// subject-bearing payload, ≥16 bytes, not trivially derived from the subject.
// (Byte-equality against journal coordinates is checked at the append site,
// where the coordinates exist.) Returns the CXER4619 refusal or none.
fn store_subject_nonce_err(doc cx.Node, subject string) ?cx.Node {
	nonce := store_nonce_attr(doc) or {
		return mk_err('cx-err:CXER4619', 'E_ERASURE_NONCE_REQUIRED: payload carries subject= but no nonce= — every subject-bearing payload MUST carry a ≥128-bit CSPRNG nonce inside the sealed payload (erasure_compliance §3); a missing nonce leaves a confirmable digest after shredding')
	}
	if nonce.len < 16 {
		return mk_err('cx-err:CXER4619', 'E_ERASURE_NONCE_REQUIRED: nonce is shorter than 16 bytes — a low-entropy nonce restores the digest oracle the rule exists to defeat (erasure_compliance §3)')
	}
	if nonce == subject {
		return mk_err('cx-err:CXER4619', 'E_ERASURE_NONCE_REQUIRED: nonce equals the subject id — a derived nonce is recomputable by the adversary the defense exists to defeat (erasure_compliance §3)')
	}
	return none
}

// store_subject_sek resolves (create-if-absent) the subject's SEK through the
// store's key provider: mapping + key material live in the custody sidecar.
fn store_subject_sek(mut ms MemStore, subject string) !string {
	mut kk := store_rotation_kms(mut ms) or {
		return error('no key provider attached')
	}
	if mut kk is EnvKms {
		sek_id := kk.subject_sek_id(subject)!
		kk.create_key(sek_id)!
		return sek_id
	}
	return error('subject keys need the reference key provider or a production KMS')
}

// store_seal_override registers the object-key → SEK routing on whichever
// encrypting layer the substrate uses.
fn store_seal_override(mut ms MemStore, key_hex string, sek_id string) ! {
	if ms.obj_pack_enc != unsafe { nil } {
		ms.obj_pack_enc.set_seal_override(key_hex, sek_id)
		return
	}
	mut be := ms.obj_backend or { return error('no object backend attached') }
	if mut be is cxstore.EncryptingWrapper {
		be.set_seal_override(key_hex, sek_id)
		return
	}
	if mut be is cxstore.EncryptingObjectBackend {
		be.set_seal_override(key_hex, sek_id)
		ms.obj_backend = be
		return
	}
	return error('store is not routed through an encrypting backend')
}

// store_put_subject_canonical stores the doc as ONE whole object (its
// canonical bytes) routed to seal under sek_id — the subject twin of
// store_put_canonical's document-model branch. Same store-key, so the model
// stays invisible to the API; the read path self-identifies the whole-doc
// shape (root object key == doc hash). Returns true iff newly inserted.
fn store_put_subject_canonical(mut ms MemStore, hash string, canonical string, sek_id string) !bool {
	store_lock_enter(mut ms)
	defer {
		store_lock_exit(mut ms)
	}
	if !store_objgraph_active(ms) {
		return error('subject-bearing docs need an object-graph substrate')
	}
	if hash in ms.obj_roots {
		return false
	}
	store_erased_clear_local(mut ms, hash) // an insert supersedes a tombstone (§7b.1)
	// The whole object holds the STRICT canonical bytes — the exact Tier-1
	// identity bytes the doc hash covers (cx_text_hash canonicalizes before
	// hashing), so the root object key self-identifies against the doc hash.
	strict := cx.cx_text_canonical(canonical) or {
		return error('canonicalize failed: ${err.msg()}')
	}
	root := ms.obj_sink.put(strict.bytes())
	store_seal_override(mut ms, root.hex(), sek_id)!
	ms.obj_roots[hash] = root
	ms.doc_order << hash
	store_feed_append(mut ms, 'docs', 'insert', '', hash, root)
	return true
}

// store_put_doc_subject is the subject-bearing arm of `store-put-doc` (and
// the text/stream spellings): nonce discipline, custody checks, SEK
// resolution, the whole-object sealed put.
fn store_put_doc_subject(mut ms MemStore, doc cx.Node, subject string, canonical string, hash string) cx.Node {
	if nerr := store_subject_nonce_err(doc, subject) {
		return nerr
	}
	if _ := store_objwire_client(ms) {
		return mk_err('cx-err:CXER1144', 'E_STORE_SUBJECT_UNSUPPORTED: subject-bearing payloads are a local-custody write — erasure over the wire is the stream-4/9 joint surface; write on the daemon host')
	}
	if store_remote_active(ms) {
		return mk_err('cx-err:CXER1144', 'E_STORE_SUBJECT_UNSUPPORTED: subject-bearing payloads are a local-custody write — erasure over the wire is the stream-4/9 joint surface; write on the daemon host')
	}
	if ms.enc_key_id == '' {
		return mk_err('cx-err:CXER1144', 'E_STORE_SUBJECT_UNSUPPORTED: ${ms.url} is not encrypted at rest — a subject-bearing payload here could never be crypto-shredded; open the store with encrypt-key-id (erasure_compliance §2)')
	}
	sek_id := store_subject_sek(mut ms, subject) or {
		return mk_err('cx-err:CXER1144', 'E_STORE_SUBJECT_UNSUPPORTED: subject-key custody: ${err.msg()}')
	}
	inserted := store_put_subject_canonical(mut ms, hash, canonical, sek_id) or {
		return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
	}
	if inserted {
		store_append(mut ms, store_doc_record(hash, canonical)) or {
			return store_persist_err(ms, err.msg())
		}
	}
	return store_str(hash)
}
