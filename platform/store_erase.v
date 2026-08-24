module platform

import cx
import cxstore
import code {
	mk_err,
}

// store_erase.v — stream 20 (#692, erasure_compliance §7): the per-store
// crypto-shred walk behind the journal's erase-subject command, and the M29
// read-time `shredded` classification.
//
// The real erasure is the SEK destroy: every payload sealed under the
// subject's key becomes unrecoverable with ZERO writes to the sealed bytes —
// wherever the envelope lives (compacted segments, rotation targets, sqlite
// rows, s3 keys). The walk exists for everything the envelope does NOT cover:
// the doc-level refs (tombstoned through the §7b.1 funnel so reads answer
// `[erased]`, attributed), the IN-PROCESS plaintext copies (the object sink's
// staged objects and the demand-paged obj_cache — the W2 carried note), and
// the derived surfaces that hold plaintext DERIVED from subject payloads
// (stream-5 computation-cache records/results, materialization checkpoints).
//
// Each store's subject copies seal under that store's OWN sidecar SEK
// (rotation re-puts payload docs through the subject arm at carry time), so
// the walk runs per store: the journal command drives it over the hot backing
// store plus every store its segment index names (§7 "rotation targets +
// segment index, archived predecessors, archive= stores").

// StoreShredCounts — one store's walk outcome (summed into the §9.1-shaped
// balanced report: docs = erased + already-erased).
struct StoreShredCounts {
mut:
	docs        int  // scoped doc acts on this store
	erased      int  // newly tombstoned
	already     int  // already tombstoned (idempotent re-walk / self-heal)
	derived     int  // computation-cache entries purged
	checkpoints int  // materialization checkpoints purged
	sek         bool // this store's SEK existed and was destroyed
	scoped      []string // the scoped doc addresses (unique, sorted)
}

// store_raw_envelope returns the at-rest envelope blob for one object root,
// per substrate (durable copies only — a staged-only object has no envelope
// yet; the seal-override registry scopes those).
fn store_raw_envelope(mut ms MemStore, root []u8) ?[]u8 {
	if ms.obj_pack != unsafe { nil } {
		return ms.obj_pack.get_object_raw(root)
	}
	mut be := ms.obj_backend or { return none }
	if mut be is cxstore.EncryptingObjectBackend {
		return be.get_object_raw(root)
	}
	if mut be is cxstore.EncryptingWrapper {
		return be.get_object_raw(root)
	}
	return none
}

// store_seal_override_for reads the substrate's live seal-override routing
// for one object key (staged subject docs — routed to a SEK, not yet sealed).
fn store_seal_override_for(mut ms MemStore, key_hex string) ?string {
	if ms.obj_pack_enc != unsafe { nil } {
		return ms.obj_pack_enc.seal_override_for(key_hex)
	}
	mut be := ms.obj_backend or { return none }
	if mut be is cxstore.EncryptingObjectBackend {
		return be.seal_override_for(key_hex)
	}
	if mut be is cxstore.EncryptingWrapper {
		return be.seal_override_for(key_hex)
	}
	return none
}

// store_erase_sek_lookup resolves the subject's SEK id on this store's
// custody sidecar WITHOUT minting (an erase must never fabricate custody).
fn store_erase_sek_lookup(mut ms MemStore, subject string) ?string {
	kk := store_rotation_kms(mut ms) or { return none }
	mut kmi := kk
	if mut kmi is EnvKms {
		return kmi.subject_sek_lookup(subject)
	}
	return none
}

// store_erase_scope enumerates the subject's whole-doc addresses on ONE open
// store: every doc root whose at-rest envelope records the subject's SEK as
// its wrapping key-id, plus staged docs routed to it by a live seal override.
// Read-only; sorted for determinism. Caller holds the op lock.
fn store_erase_scope(mut ms MemStore, sek_id string) []string {
	mut out := []string{}
	if sek_id == '' || !store_objgraph_active(ms) {
		return out
	}
	for hash, root in ms.obj_roots {
		if !store_whole_doc_root(hash, root) {
			continue
		}
		mut kid := ''
		if raw := store_raw_envelope(mut ms, root) {
			if env := cxstore.parse_envelope(raw) {
				kid = env.key_id
			}
		}
		if kid == '' {
			if ov := store_seal_override_for(mut ms, root.hex()) {
				kid = ov
			}
		}
		if kid == sek_id {
			out << hash
		}
	}
	out.sort()
	return out
}

// store_erase_computation_victims collects stream-5 visible-cache entries
// (`computation/<record-addr>` aliases) whose record doc references the
// subject or a scoped address — the record embeds its input addresses, a
// derived index over the shredded payloads (§7); its result doc is derived
// plaintext. An unreadable record cannot be proven clean and is purged
// fail-closed. Read-only collection; sorted. Caller holds the op lock.
fn store_erase_computation_victims(mut ms MemStore, needles []string) []string {
	mut victims := []string{}
	for alias, _ in ms.aliases {
		if !alias.starts_with('computation/') {
			continue
		}
		addr := alias.all_after('computation/')
		txt := store_doc_text(ms, addr) or {
			victims << alias
			continue
		}
		for n in needles {
			if n != '' && txt.contains(n) {
				victims << alias
				break
			}
		}
	}
	victims.sort()
	return victims
}

// store_erase_checkpoint_victims collects materialization checkpoint aliases
// (`cx-live/materialization/…` → a `[checkpoint …]` doc). Checkpoint ROWS are
// folded payload data whose subject linkage is not attributable row-by-row,
// so every checkpoint purges (derived-state posture: a missing checkpoint is
// a full replay, never an error). `[live-materialization]` REGISTRATION
// markers are untouched — they carry no payload rows, and the retention-cover
// extension depends on them. Read-only collection; sorted.
fn store_erase_checkpoint_victims(mut ms MemStore) []string {
	mut victims := []string{}
	for alias, target in ms.aliases {
		if !alias.starts_with('cx-live/materialization/') {
			continue
		}
		txt := store_doc_text(ms, target) or { continue }
		if txt.starts_with('[checkpoint') {
			victims << alias
		}
	}
	victims.sort()
	return victims
}

// store_erase_plan reports (sek-id, scoped docs) on one open store without
// mutating anything — the erase command's pre-commit scope enumeration (the
// hash-scoped hold check and the recorded [docs] scope read it).
fn store_erase_plan(mut ms MemStore, subject string) (string, []string) {
	store_lock_enter(mut ms)
	defer {
		store_lock_exit(mut ms)
	}
	mut sek_id := ''
	mut scoped := []string{}
	if id := store_erase_sek_lookup(mut ms, subject) {
		sek_id = id
		scoped = store_erase_scope(mut ms, sek_id)
	}
	return sek_id, scoped
}

// store_erase_subject_walk executes the §7 shred walk on ONE open store:
// tombstone every scoped doc through the §7b.1 funnel (T+E records — the
// attribution survives), destroy the store's SEK + subject mapping, sweep the
// derived surfaces, persist, then purge in-process plaintext (the sink
// rebuild drops shredded staged objects AFTER their tombstone objects flush;
// obj_cache evicts the scoped roots). `needles` carries the subject plus the
// CROSS-STORE scope union (addresses are store-independent: a derived record
// here may reference a payload that lives in a sibling store). Idempotent
// throughout — re-running converges (the deduped-replay self-heal path). KMS
// destroy ordering is the CALLER's contract: this runs strictly after the
// shred-request committed.
fn store_erase_subject_walk(mut ms MemStore, subject string, request string, actor string, authority string, at string, needles []string) !StoreShredCounts {
	store_lock_enter(mut ms)
	defer {
		store_lock_exit(mut ms)
	}
	if ms.read_only {
		return error('E_STORE_READ_ONLY: ${ms.url}')
	}
	mut c := StoreShredCounts{}
	mut sek_id := ''
	if id := store_erase_sek_lookup(mut ms, subject) {
		sek_id = id
		c.scoped = store_erase_scope(mut ms, sek_id)
	}
	comp_victims := store_erase_computation_victims(mut ms, needles)
	ckpt_victims := store_erase_checkpoint_victims(mut ms)
	// 1. Doc-level tombstones (the §7b.1 funnel): the T removal + the E
	//    attributed tombstone ride ONE append (the xsp erase pattern), and the
	//    whole-doc plaintext leaves the page cache (the W2 carried note).
	mut recs := ''
	mut purge := [][]u8{}
	for h in c.scoped {
		c.docs++
		mut root := []u8{}
		if r := ms.obj_roots[h] {
			root = r.clone()
		}
		if root.len == 0 {
			// already-erased docs have no live root; the doc hash IS the
			// whole-doc object key (self-identifying), so the residue purge
			// and cache eviction derive the key from the address.
			root = hex_decode_or_empty(h.all_after_last(':'))
		}
		tomb := store_erase_tombstone(h, root, at, actor, authority, request)
		if store_erase_doc_local(mut ms, h, tomb) {
			c.erased++
			recs += store_tombstone_record(h) + store_erase_record(h, tomb)
		} else {
			c.already++
		}
		if root.len > 0 {
			ms.obj_cache.delete(root.hex())
			purge << root
		}
	}
	// 2. Derived sweeps: computation-cache entries (record + result docs
	//    erased, alias dropped) and materialization checkpoints (doc erased,
	//    alias dropped — re-attach replays in full).
	for alias in comp_victims {
		addr := alias.all_after('computation/')
		mut victims := [addr]
		if target := ms.aliases[alias] {
			if target != addr {
				victims << target
			}
		}
		for v in victims {
			mut vroot := []u8{}
			if r := ms.obj_roots[v] {
				vroot = r.clone()
			}
			tomb := store_erase_tombstone(v, vroot, at, actor, authority, request)
			if store_erase_doc_local(mut ms, v, tomb) {
				recs += store_tombstone_record(v) + store_erase_record(v, tomb)
			}
			if vroot.len > 0 {
				ms.obj_cache.delete(vroot.hex())
			}
		}
		if store_alias_delete_local(mut ms, alias) {
			recs += store_alias_tombstone_record(alias)
		}
		c.derived++
	}
	for alias in ckpt_victims {
		if target := ms.aliases[alias] {
			mut troot := []u8{}
			if r := ms.obj_roots[target] {
				troot = r.clone()
			}
			tomb := store_erase_tombstone(target, troot, at, actor, authority, request)
			if store_erase_doc_local(mut ms, target, tomb) {
				recs += store_tombstone_record(target) + store_erase_record(target, tomb)
			}
			if troot.len > 0 {
				ms.obj_cache.delete(troot.hex())
			}
		}
		if store_alias_delete_local(mut ms, alias) {
			recs += store_alias_tombstone_record(alias)
		}
		c.checkpoints++
	}
	if recs != '' {
		store_append(mut ms, recs)!
	}
	// 3. The crypto-shred: destroy this store's SEK + the subject mapping
	//    (idempotent; absence = already shredded here). Post-destroy, every
	//    envelope under it fails closed with the typed unavailable finding.
	if sek_id != '' {
		kk := store_rotation_kms(mut ms) or {
			return error('subject key custody unreachable on ${ms.url}')
		}
		mut kmi := kk
		if mut kmi is EnvKms {
			kmi.destroy_key(sek_id) or {
				return error('subject key destroy failed on ${ms.url}: ${err.msg()}')
			}
			kmi.subject_unmap(subject)
			c.sek = true
		}
	}
	// 4. Make the tombstones durable FIRST (their sink objects flush with the
	//    E records), then purge the durable residue (the sealed envelopes
	//    under the destroyed key — restart-safe supersede: a re-landed doc at
	//    the same address must never content-dedup against a stale shredded
	//    envelope), then drop the now-unreachable staged plaintext from the
	//    in-process sink (§7 reach: the W2 carried note). pc_reclaim resets
	//    the flush watermark; content-addressed re-puts are idempotent.
	if c.erased > 0 || c.derived > 0 || c.checkpoints > 0 || purge.len > 0 {
		store_persist(mut ms)!
		store_erase_purge_durable(mut ms, purge)!
		if store_objgraph_active(ms) {
			pc_reclaim(mut ms)
		}
	}
	return c
}

// store_erase_purge_durable removes the shredded whole-doc envelopes from the
// durable substrate. Crypto-shredding already made them unreadable everywhere
// (the SEK is gone); the physical purge exists for RESTART-SAFE supersede —
// content-address dedup at a later re-put must find nothing at the address —
// and for §7's leave-nothing-to-chance posture. Per substrate, the same
// shapes the rotation walk proved: pack = fold the survivors into one
// compacted keyed pack (atomic rename; the shredded keys just don't ride
// along); cxobj = per-file unlink; sqlite = row DELETE; s3 = keyed DELETE.
// Caller holds the op lock and has persisted (nothing staged).
fn store_erase_purge_durable(mut ms MemStore, keys [][]u8) ! {
	if keys.len == 0 {
		return
	}
	mut kill := map[string]bool{}
	for k in keys {
		kill[k.hex()] = true
	}
	if ms.obj_pack != unsafe { nil } {
		if ms.obj_pack.pending_count() > 0 {
			return error('staged objects pending — persist before the durable purge')
		}
		durable := ms.obj_pack.durable_keys()
		mut entries := []cxstore.KeyedPayload{cap: durable.len}
		mut hit := false
		for key in durable {
			if key.hex() in kill {
				hit = true
				continue
			}
			env := ms.obj_pack.get_object_raw(key) or {
				return error('object ${key.hex()}: envelope missing from packs')
			}
			entries << cxstore.KeyedPayload{
				key:  key
				blob: env
			}
		}
		if hit {
			ms.obj_pack.write_compacted_keyed(entries) or {
				return error('purged pack write failed: ${err.msg()}')
			}
		}
		return
	}
	match ms.backend {
		'cxobj' {
			mut be := ms.obj_backend or { return }
			if mut be is cxstore.EncryptingObjectBackend {
				for k in keys {
					be.remove_object(k)!
				}
				ms.obj_backend = be
			}
		}
		'sqlite' {
			$if cxstore_sqlite ? {
				store_erase_purge_sqlite(mut ms, keys)!
			}
		}
		's3' {
			mut w := store_enc_wrapper(mut ms) or { return }
			mut ib := w.inner_backend()
			if mut ib is S3ObjectBackend {
				for k in keys {
					ib.remove_object_keyed(k)!
				}
			}
		}
		else {}
	}
}

// ── M29 read-time classification ────────────────────────────────────────────

// store_erasure_record_covering scans the store's journaled erase-subject
// records (the reserved `cx:erasure` stream's entry pointers live beside the
// docs as ordinary aliases) for one whose `[docs]` scope covers `hash`;
// returns its request id. THE evidence basis for the `shredded` finding —
// never key absence alone (audit M33/M29).
fn store_erasure_record_covering(mut ms MemStore, hash string) ?string {
	for alias, target in ms.aliases {
		if !alias.starts_with('cx-journal/entry/') || !alias.contains('/s/cx:erasure/') {
			continue
		}
		etxt := store_doc_text(ms, target) or { continue }
		edoc := cx.parse(etxt) or { continue }
		if edoc.elements.len == 0 {
			continue
		}
		e0 := edoc.elements[0]
		if e0 !is cx.Element {
			continue
		}
		e := e0 as cx.Element
		payload_addr := e.attr('payload')
		if payload_addr == '' {
			continue
		}
		rtxt := store_doc_text(ms, payload_addr) or { continue }
		rdoc := cx.parse(rtxt) or { continue }
		if rdoc.elements.len == 0 {
			continue
		}
		r0 := rdoc.elements[0]
		if r0 !is cx.Element {
			continue
		}
		re := r0 as cx.Element
		if re.name != 'erase-subject' {
			continue
		}
		mut covered := false
		mut request := ''
		for it in re.items {
			if it is cx.Element && it.name == 'docs' {
				for d in it.items {
					if d is cx.Element && d.name == 'd' && d.items.len > 0 {
						v := d.items[0]
						mut dh := ''
						if v is cx.ScalarNode {
							dh = cx.scalar_value_str_public(v.value)
						} else if v is cx.TextNode {
							dh = v.value
						}
						if dh == hash {
							covered = true
						}
					}
				}
			}
			if it is cx.Element && it.name == 'request' && it.items.len > 0 {
				v := it.items[0]
				if v is cx.ScalarNode {
					request = cx.scalar_value_str_public(v.value)
				} else if v is cx.TextNode {
					request = v.value
				}
			}
		}
		if covered {
			return request
		}
	}
	return none
}

// store_read_err_node maps a doc-read failure message to its typed code at
// the verb boundary: the M29 `shredded` finding gets CXER1145 (the store
// band's second code); the typed-unavailable message keeps its honest text
// on the integrity code (fail-closed — W5's unattributed-missing counts read
// the same class); everything else stays the plain integrity fault.
fn store_read_err_node(msg string) cx.Node {
	if msg.contains('E_STORE_SHREDDED') {
		return mk_err('cx-err:CXER1145', msg)
	}
	if msg.contains(cxstore.key_unavailable_msg) {
		return mk_err('cx-err:CXER1120', msg)
	}
	return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${msg}')
}

// store_shredded_read_err builds the typed error message for a whole-doc
// object that failed to open (the M29 read-time reconciliation): a present
// envelope under an ABSENT subject key is `shredded` iff a journaled erasure
// record covers the address (CXER1145 at the verb boundary), and the
// fail-closed `unavailable` otherwise (outage, misconfiguration, or unlawful
// destruction — NEVER reported as lawful erasure; W5's unattributed-missing
// counts feed on the same discrimination). Everything else stays the plain
// integrity error.
fn store_shredded_read_err(mut ms MemStore, hash string, root []u8) string {
	plain := 'object graph: document ${hash} object missing/corrupt'
	raw := store_raw_envelope(mut ms, root) or { return plain }
	env := cxstore.parse_envelope(raw) or { return plain }
	if !env.key_id.starts_with(cxstore.sek_id_prefix) {
		return plain
	}
	mut absent := false
	if kk := store_rotation_kms(mut ms) {
		mut kmi := kk
		absent = !kmi.has_key(env.key_id)
	}
	if !absent {
		return plain
	}
	if req := store_erasure_record_covering(mut ms, hash) {
		return 'E_STORE_SHREDDED: document ${hash} was crypto-shredded per journaled shred-request `${req}` (subject key ${env.key_id} destroyed) — lawful erasure, attributed (erasure_compliance §2/§7)'
	}
	return '${cxstore.key_unavailable_msg}: document ${hash} is sealed under absent subject key ${env.key_id} with NO covering erasure record — fail-closed: outage, misconfiguration, or unlawful destruction, never reported as lawful erasure (erasure_compliance §2, audit M29)'
}
