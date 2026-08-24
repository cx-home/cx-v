module platform

import strconv

// store_s3_lineage.v — durable feed lineage on an object transport (#885,
// RULED: FL-2, the s3 completion of FL-1/#764; #887, RULED: FL-3, the
// columnar completion; xsp_store_profile.md §5.1).
//
// An S3 transport has no append primitive, so the FL-1 sidecar FILE becomes
// a family of small bucket objects under a `.cxstore-lineage/` key prefix
// (same transport, same at-rest posture as the substrate metadata they sit
// beside):
//
//   <prefix>G-<gen 16-hex>-full       — one generation's base: header +
//       epoch + per-stream floor/head records + the retained acts
//       (byte-identical to the FL-1 sidecar format — ONE parser,
//       store_lineage_install, serves both media)
//   <prefix>G-<gen>-S-<seq 16-hex>    — one act per segment, PUT at write
//       time from the same funnel (store_feed_append), BEFORE the state
//       flush lands — append-ordered
//
// FL-3 (#887): the prefix is a MOUNT, not a constant. There are exactly two
// lineage media in CX and there will not be a third — a sidecar file beside a
// local root (store_lineage.v) and this object family under a key prefix — so
// a substrate joins the durability contract by MOUNTING on one of them, never
// by growing its own. Two mounts ride this file (StoreLineageBucket below).
//
// Design (FL-2, ledger/rulings_2026_08_20_s3_lineage.md): per-segment PUTs,
// never read-modify-write under conditional PUT. The substrate's existing
// durability contract is single-writer-daemon per bucket root (the refs
// manifest is already one unconditional snapshot PUT — see the ledger's
// evidence), so monotonic segment names are unique by construction and
// there is no RMW race to guard; S3 PUT is atomic per key, so a crashed
// append leaves a whole segment or nothing — no torn tails on this medium.
//
// Boot = one LIST + GET full + GETs of that generation's segments in seq
// order, concatenated and verified by the SAME verify-before-trust replay
// as the local sidecar (epoch intact, per-stream density above the floors,
// retained-acts fold agreeing with the manifest-loaded snapshot). Anything
// untrusted is discarded: seed compacted-from-snapshot under a FRESH epoch
// (today's exact behavior — also the first-boot path) and write the initial
// full object under a new generation.
//
// Compaction (the shared records > 2 × live + 64 heuristic) writes the
// state-compacted full object under generation g+1 — the GENERATION GUARD:
// boot trusts the highest generation that has a full object — then deletes
// the old generation's keys best-effort (a crash mid-purge leaves stragglers
// the guard ignores and the next compaction sweeps). Unrecognized keys under
// the lineage namespace are ignored, never trusted and never a reseed-flap:
// content verification is the authority, not key names.

const s3_lineage_prefix = '.cxstore-lineage/'

// StoreLineageBucket — ONE bucket-lineage mount: the object transport plus the
// key prefix this store's lineage objects live under (RULED: FL-3, #887).
//
// FL-2 shipped a single implicit mount — the s3 SUBTREE store, whose lineage
// keys are siblings of `.cxstore-manifest` at the bucket root. The columnar
// substrate's s3 shape is a different mount on the same medium: a columnar
// store IS one Parquet/Arrow object (backend 'columnar', root '', the whole
// store at `columnar_s3_key`), so its lineage keys hang off THAT object —
// `<object-key>.cxstore-lineage/…` — exactly as its alias sidecar is
// `<object-key>.cxstore-aliases`. Two columnar stores in one bucket therefore
// keep separate lineages by construction, and the subtree layout is unchanged
// byte-for-byte.
struct StoreLineageBucket {
mut:
	tr     S3Transport
	prefix string
}

// store_lineage_is_bucket reports whether this store's lineage medium is the
// object family rather than a local sidecar file: an s3-rooted subtree store
// (FL-2) or a columnar store hosted as a single s3 object (FL-3). A columnar
// store over a LOCAL root keeps the FL-1 sidecar (store_lineage_path_of
// resolves `<root>.cxstore-lineage` for it).
fn store_lineage_is_bucket(ms &MemStore) bool {
	if ms.backend == 's3' {
		return true
	}
	return ms.backend == 'columnar' && ms.columnar_s3 != none
}

// store_lineage_bucket_of resolves the store's mount. none = this store keeps
// no bucket lineage (no concrete s3 backend behind an 's3' handle; a columnar
// store over a local root).
fn store_lineage_bucket_of(mut ms MemStore) ?StoreLineageBucket {
	if ms.backend == 'columnar' {
		tr := ms.columnar_s3 or { return none }
		return StoreLineageBucket{
			tr:     tr
			prefix: ms.columnar_s3_key + s3_lineage_prefix
		}
	}
	mut be := store_s3_concrete(mut ms) or { return none }
	return StoreLineageBucket{
		tr:     be.transport
		prefix: s3_lineage_prefix
	}
}

fn s3_lineage_hex16(n i64) string {
	s := n.hex()
	if s.len >= 16 {
		return s
	}
	return '0'.repeat(16 - s.len) + s
}

fn s3_lineage_full_key(prefix string, gen i64) string {
	return '${prefix}G-${s3_lineage_hex16(gen)}-full'
}

fn s3_lineage_seg_key(prefix string, gen i64, seq i64) string {
	return '${prefix}G-${s3_lineage_hex16(gen)}-S-${s3_lineage_hex16(seq)}'
}

// S3LineageScan — one LIST pass over the bucket's lineage namespace.
struct S3LineageScan {
mut:
	full    map[i64]bool  // generations that have a full (base) object
	segs    map[i64][]i64 // generation → its segment seqs (unsorted)
	max_gen i64           // highest generation seen in ANY well-formed key
}

fn store_s3_lineage_scan(bk StoreLineageBucket) S3LineageScan {
	mut sc := S3LineageScan{
		full: map[i64]bool{}
		segs: map[i64][]i64{}
	}
	for k in bk.tr.keys() {
		idx := k.index(bk.prefix) or { continue }
		rest := k[idx + bk.prefix.len..]
		// G-<16 hex>-full | G-<16 hex>-S-<16 hex>; anything else is ignored
		// (an alien key carries no content this loader consumes).
		if !rest.starts_with('G-') || rest.len < 2 + 16 + 1 {
			continue
		}
		gen := strconv.parse_int(rest[2..18], 16, 64) or { continue }
		if gen < 1 {
			continue
		}
		tail := rest[18..]
		if tail == '-full' {
			sc.full[gen] = true
		} else if tail.starts_with('-S-') && tail.len == 3 + 16 {
			seq := strconv.parse_int(tail[3..], 16, 64) or { continue }
			if seq < 1 {
				continue
			}
			mut lst := sc.segs[gen] or { []i64{} }
			lst << seq
			sc.segs[gen] = lst
		} else {
			continue
		}
		if gen > sc.max_gen {
			sc.max_gen = gen
		}
	}
	return sc
}

// store_s3_lineage_read fetches one generation's complete lineage byte
// stream: the full object, then its segments in ascending seq order. Any
// missing/failed piece means the generation is not trusted (none).
fn store_s3_lineage_read(bk StoreLineageBucket, sc S3LineageScan, gen i64) ?[]u8 {
	st, body, ok := bk.tr.fetch('GET', s3_lineage_full_key(bk.prefix, gen))
	if !ok || st != 200 {
		return none
	}
	mut data := body.clone()
	mut seqs := (sc.segs[gen] or { []i64{} }).clone()
	seqs.sort()
	for s in seqs {
		st2, b2, ok2 := bk.tr.fetch('GET', s3_lineage_seg_key(bk.prefix, gen, s))
		if !ok2 || st2 != 200 {
			return none
		}
		data << b2
	}
	return data
}

// store_s3_lineage_full_bytes renders the store's whole current lineage in
// the sidecar byte format (header, epoch, sorted floors, retained acts) —
// the exact stream store_lineage_write_full writes locally.
fn store_s3_lineage_full_bytes(ms &MemStore) []u8 {
	mut outp := '${store_lineage_header}\n'
	outp += store_lineage_epoch_record(ms.feed_boot)
	mut fkeys := ms.adv_floor.keys()
	fkeys.sort()
	for k in fkeys {
		fl := ms.adv_floor[k] or { continue }
		hd := ms.adv_pos[k] or { i64(0) }
		outp += store_lineage_floor_record(k, fl, hd)
	}
	for a in ms.advances {
		outp += store_lineage_act_record(a)
	}
	return outp.bytes()
}

fn store_s3_lineage_put_full(mut bk StoreLineageBucket, ms &MemStore, gen i64) bool {
	st, ok := bk.tr.store(s3_lineage_full_key(bk.prefix, gen), store_s3_lineage_full_bytes(ms))
	return ok && (st == 200 || st == 201)
}

// store_s3_lineage_purge_below deletes every well-formed lineage key of a
// generation below `gen` — best-effort (statuses ignored): the generation
// guard makes stragglers harmless and the next compaction sweeps them.
fn store_s3_lineage_purge_below(mut bk StoreLineageBucket, gen i64) {
	sc := store_s3_lineage_scan(bk)
	for g, _ in sc.full {
		if g < gen {
			bk.tr.remove(s3_lineage_full_key(bk.prefix, g))
		}
	}
	for g, seqs in sc.segs {
		if g < gen {
			for s in seqs {
				bk.tr.remove(s3_lineage_seg_key(bk.prefix, g, s))
			}
		}
	}
}

// ── boot: load-else-seed (the object medium of store_feed_open) ───────────

// store_s3_lineage_open establishes a bucket-mounted store's lineage at
// registration: reload the highest generation when it verifies (positions
// survive the restart), else seed from the just-loaded snapshot exactly as
// before FL-2/FL-3 (first boot / pre-lineage bucket / discarded lineage) and
// write the initial full object under a fresh generation. Runs ONCE per
// MemStore (store_register), after the substrate's own load has replayed the
// state (store_s3_load for the subtree mount, store_columnar_load for the
// columnar mount) — so the fold-match verifies against the loaded snapshot,
// FL-1 §6 unchanged.
fn store_s3_lineage_open(mut ms MemStore) {
	mut bk := store_lineage_bucket_of(mut ms) or {
		// no resolvable mount (never expected on a bucket-lineage substrate):
		// keep the volatile process-lifetime story — honest refusals, nothing
		// durable.
		store_feed_seed(mut ms)
		return
	}
	sc := store_s3_lineage_scan(bk)
	mut gen := i64(0)
	for g, _ in sc.full {
		if g > gen {
			gen = g
		}
	}
	if gen > 0 {
		if data := store_s3_lineage_read(bk, sc, gen) {
			if store_lineage_install(mut ms, data) {
				mut mx := i64(0)
				for s in sc.segs[gen] or { []i64{} } {
					if s > mx {
						mx = s
					}
				}
				ms.lineage_gen = gen
				ms.lineage_seq = mx + 1
				ms.lineage_active = !ms.read_only
				return
			}
		}
	}
	// no trusted bucket lineage — seed compacted-from-snapshot under a FRESH
	// epoch (today's exact behavior) and persist it under a new generation.
	store_feed_seed(mut ms)
	if ms.read_only {
		return
	}
	new_gen := sc.max_gen + 1
	if store_s3_lineage_put_full(mut bk, ms, new_gen) {
		ms.lineage_gen = new_gen
		ms.lineage_seq = 1
		ms.lineage_records = ms.advances.len
		ms.lineage_active = true
		store_s3_lineage_purge_below(mut bk, new_gen)
	}
	// on a failed PUT: durable lineage unavailable this boot (transport /
	// auth fault) — the volatile epoch already refuses prior cursors
	// honestly, exactly the FL-1 disk-fault tolerance.
}

// ── write paths ────────────────────────────────────────────────────────────

// store_s3_lineage_append persists one live act as one segment object
// (called from store_lineage_append under the op lock, BEFORE the state
// flush lands — append-ordered). A failed PUT is tolerated in-process (the
// in-memory lineage keeps serving this boot); the resulting position gap is
// caught by the next boot's density check, which discards the bucket lineage
// and reseeds under a fresh epoch — degraded retention, never silent
// divergence (FL-1 §6 verbatim).
fn store_s3_lineage_append(mut ms MemStore, a StoreAdvance) {
	if ms.lineage_gen < 1 {
		return
	}
	mut bk := store_lineage_bucket_of(mut ms) or { return }
	st, ok := bk.tr.store(s3_lineage_seg_key(bk.prefix, ms.lineage_gen, ms.lineage_seq),
		store_lineage_act_record(a).bytes())
	if !ok || (st != 200 && st != 201) {
		return
	}
	ms.lineage_seq++
	ms.lineage_records++
}

// store_s3_lineage_write_compacted persists the compacted story (the caller
// — store_lineage_compact — has already swapped ms.advances/adv_floor to the
// retained view) as the NEXT generation's full object: the generation guard.
// Only after the new base is durable does the old generation get purged,
// best-effort. false = nothing moved (the caller reverts the floors).
fn store_s3_lineage_write_compacted(mut ms MemStore) bool {
	if ms.lineage_gen < 1 {
		return false
	}
	mut bk := store_lineage_bucket_of(mut ms) or { return false }
	new_gen := ms.lineage_gen + 1
	if !store_s3_lineage_put_full(mut bk, ms, new_gen) {
		return false
	}
	ms.lineage_gen = new_gen
	ms.lineage_seq = 1
	ms.lineage_records = ms.advances.len
	store_s3_lineage_purge_below(mut bk, new_gen)
	return true
}
