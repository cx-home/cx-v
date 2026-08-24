module platform

import os
import cx
import encoding.hex

// store_lineage.v — durable feed lineage across daemon restarts (#764,
// RULED: FL-1; xsp_store_profile.md §5.1/§5.2).
//
// The three data planes (docs / refs / aliases) get what the revocations
// plane already had: durable, monotonic, journal-backed positions that
// survive restart. Every local durable substrate keeps an append-ordered
// lineage SIDECAR log beside its state; each live act appends ONE record at
// write time through the same funnel that records the in-memory act
// (store_feed_append) — one log, two media. On boot the sidecar is replayed
// and VERIFIED before it is trusted (header + epoch intact, per-stream
// density above the retention floors, retained-acts fold agreeing with the
// loaded snapshot); a clean replay restores the persisted epoch token,
// floors, and positions — a prior-boot resume cursor RESUMES. Any mismatch
// (torn tail, a crash between the lineage append and the state append, a
// store mutated by a pre-lineage binary) discards the sidecar, mints a
// FRESH epoch, and reseeds from the snapshot — exactly the pre-FL-1
// behavior: the failure mode is the honest typed refusal + re-seed
// (CXER5020), never a gap served silently.
//
// Retention is explicit and bounded: when the sidecar accumulates
// redundancy (records > 2 × live entities + 64 — the file-index log's own
// compaction heuristic) it is rewritten as the state-compacted story (the
// latest act per live entity, erase evidence included — attribution
// survives compaction, the E-record precedent) at their ORIGINAL positions,
// and each stream's retention FLOOR rises to its highest compacted-away
// position. Invariant: above its floor every stream is dense (floor+1 …
// head, gap-free); at or below the floor only the sparse state story
// remains. A resume cursor below a floor (or above a head — a position this
// lineage never issued) refuses typed; everything else replays gapless.

const store_lineage_name = '.cxstore-lineage'
const store_lineage_header = 'CXLINEAGE\tv1'

// store_lineage_path_of resolves the sidecar path for a store's substrate.
// Directory-rooted substrates keep it under the root; file-rooted ones
// beside the file. '' = no local sidecar file (mem:// loses the store
// itself at exit and remote-proxy mounts keep no local lineage — both keep
// the seed-per-boot behavior, FL-1 §1; the bucket-mounted substrates keep
// their lineage as OBJECTS instead — s3 subtree, FL-2 #885, and a columnar
// store hosted as one s3 object, FL-3 #887 (root '' there, so the guard
// below already declines) — see store_s3_lineage.v. A columnar store over a
// LOCAL root takes the sidecar beside its Parquet/Arrow file, like sqlite.)
fn store_lineage_path_of(ms &MemStore) string {
	if ms.root == '' {
		return ''
	}
	match ms.backend {
		'file', 'cxpack', 'cxobj' {
			return os.join_path(ms.root, store_lineage_name)
		}
		'sqlite', 'columnar' {
			return ms.root + store_lineage_name
		}
		else {
			return ''
		}
	}
}

// ── record shapes ────────────────────────────────────────────────────────
// E\t<epoch-token>\t0                      — the durable epoch (once, first)
// F\t<key-len>\t<floor>\t<head>\n<key>\n   — per-stream retention floor +
//                                            head (head carries dead streams
//                                            whose positions must stay
//                                            monotonic forever)
// V\t<plane>\t<kind>\t<pos>\t<root-hex>\t<name-len>\t<hash-len>\n<name><hash>\n
//                                          — one act (name/hash are length-
//                                            prefixed: names may hold any
//                                            bytes, the A-record precedent)

fn store_lineage_epoch_record(token string) string {
	return 'E\t${token}\t0\n'
}

fn store_lineage_floor_record(key string, floor i64, head i64) string {
	return 'F\t${key.len}\t${floor}\t${head}\n${key}\n'
}

fn store_lineage_act_record(a StoreAdvance) string {
	return 'V\t${a.plane}\t${a.kind}\t${a.pos}\t${a.root.hex()}\t${a.name.len}\t${a.hash.len}\n${a.name}${a.hash}\n'
}

// ── boot: load-else-seed ─────────────────────────────────────────────────

// store_feed_open establishes the store's lineage at registration: reload
// the persisted lineage when it verifies (positions survive the restart),
// else seed from the snapshot exactly as before FL-1 (first boot / upgraded
// store / discarded sidecar) and write the initial sidecar. Runs ONCE per
// MemStore (store_register), before any live mutation can interleave.
fn store_feed_open(mut ms MemStore) {
	if ms.feed_boot != '' {
		return
	}
	if store_lineage_is_bucket(ms) {
		// FL-2 (#885) / FL-3 (#887): the bucket-mounted substrates keep their
		// lineage as objects (per-segment appends under a generation guard) —
		// same load-else-seed contract, different medium (store_s3_lineage.v).
		store_s3_lineage_open(mut ms)
		return
	}
	ms.lineage_path = store_lineage_path_of(ms)
	if store_lineage_load(mut ms) {
		ms.lineage_active = !ms.read_only
		return
	}
	store_feed_seed(mut ms)
	if ms.lineage_path != '' && !ms.read_only {
		if store_lineage_write_full(mut ms) {
			ms.lineage_active = true
		} else {
			// durable lineage unavailable this boot (disk fault): keep the
			// process-lifetime story — the volatile epoch already refuses
			// prior cursors honestly. Never leave a torn sidecar behind.
			os.rm(ms.lineage_path) or {}
			ms.lineage_path = ''
		}
	}
}

// store_lineage_load replays + verifies the sidecar file. true = the lineage
// is trusted and installed (epoch, floors, heads, retained acts); false = the
// caller reseeds fresh (the sidecar, if any, is rewritten by the seed path).
fn store_lineage_load(mut ms MemStore) bool {
	p := ms.lineage_path
	if p == '' || !os.exists(p) {
		return false
	}
	data := os.read_bytes(p) or { return false }
	return store_lineage_install(mut ms, data)
}

// LineageCursor — a byte cursor with the sidecar's read discipline (lines +
// length-prefixed raw payloads), so ONE parser serves both lineage media:
// the local sidecar file (FL-1) and the concatenated s3 bucket objects
// (FL-2, store_s3_lineage.v).
struct LineageCursor {
	data []u8
mut:
	pos int
}

// line returns the next line without its trailing newline; a final
// unterminated line returns its partial content (the torn-tail shape the
// record validation below then refuses). none = end of data.
fn (mut c LineageCursor) line() ?string {
	if c.pos >= c.data.len {
		return none
	}
	mut i := c.pos
	for i < c.data.len && c.data[i] != `\n` {
		i++
	}
	s := c.data[c.pos..i].bytestr()
	c.pos = if i < c.data.len { i + 1 } else { i }
	return s
}

// exact returns the next n raw bytes (names/hashes may hold any bytes,
// newlines included — the length prefix is the only authority).
fn (mut c LineageCursor) exact(n int) ?string {
	if n < 0 || c.pos + n > c.data.len {
		return none
	}
	s := c.data[c.pos..c.pos + n].bytestr()
	c.pos += n
	return s
}

// store_lineage_install parses + verifies one complete lineage byte stream
// (header, epoch, floors, acts) and installs it on a clean replay. false =
// the bytes are not trusted; the caller reseeds fresh.
fn store_lineage_install(mut ms MemStore, data []u8) bool {
	mut cur := LineageCursor{
		data: data
	}
	hd := cur.line() or { return false }
	if hd != store_lineage_header {
		return false
	}
	mut token := ''
	mut floors := map[string]i64{}
	mut heads := map[string]i64{}
	mut last := map[string]i64{}
	mut acts := []StoreAdvance{}
	for {
		line := cur.line() or { break }
		parts := line.split('\t')
		if parts.len < 3 {
			return false
		}
		if parts[0] == 'E' {
			if token != '' || acts.len > 0 {
				return false // exactly one epoch record, before any act
			}
			token = parts[1]
			if token == '' {
				return false
			}
		} else if parts[0] == 'F' {
			if parts.len != 4 {
				return false
			}
			key := cur.exact(parts[1].int()) or { return false }
			cur.exact(1) or { return false }
			floor := parts[2].i64()
			head := parts[3].i64()
			if key == '' || floor < 0 || head < floor {
				return false
			}
			floors[key] = floor
			heads[key] = head
		} else if parts[0] == 'V' {
			if parts.len != 7 {
				return false
			}
			nlen := parts[5].int()
			hlen := parts[6].int()
			payload := cur.exact(nlen + hlen) or { return false }
			cur.exact(1) or { return false }
			a := StoreAdvance{
				plane: parts[1]
				kind:  parts[2]
				name:  payload[..nlen]
				hash:  payload[nlen..]
				root:  hex.decode(parts[4]) or { return false }
				pos:   parts[3].i64()
			}
			if a.plane !in sx_feed_planes || a.pos < 1 {
				return false
			}
			if a.kind !in ['insert', 'retract', 'advance', 'erase'] {
				return false
			}
			key := store_feed_stream_key(a.plane, a.name)
			fl := floors[key] or { i64(0) }
			prev := last[key] or { i64(0) }
			if a.pos <= prev {
				return false // positions strictly increase within a stream
			}
			if a.pos > fl {
				// dense above the floor: a gap here means an act was written
				// and lost (a failed append / torn tail) — never trusted.
				base := if prev > fl { prev } else { fl }
				if a.pos != base + 1 {
					return false
				}
			}
			last[key] = a.pos
			acts << a
		} else {
			return false
		}
	}
	if token == '' {
		return false
	}
	for key, pos in last {
		fh := heads[key] or { i64(0) }
		if pos > fh {
			heads[key] = pos
		}
	}
	for key, fl in floors {
		hd2 := heads[key] or { i64(0) }
		if hd2 < fl {
			return false
		}
	}
	if !store_lineage_fold_matches(ms, acts) {
		return false
	}
	ms.feed_boot = token
	ms.adv_floor = floors.move()
	ms.adv_pos = heads.move()
	ms.advances = acts
	ms.lineage_records = acts.len
	return true
}

// store_lineage_fold_matches verifies the retained acts' fold against the
// snapshot the state load just produced: live docs (with roots), wire refs
// (with roots), alias targets, and the erased set must all agree — in both
// directions. A store a pre-lineage binary mutated, or a crash between the
// lineage append and the state append, lands here and is honestly reseeded.
fn store_lineage_fold_matches(ms &MemStore, acts []StoreAdvance) bool {
	mut doc_kind := map[string]string{}
	mut doc_root := map[string]string{}
	mut ref_root := map[string]string{}
	mut alias_val := map[string]string{}
	for a in acts {
		match a.plane {
			'docs' {
				doc_kind[a.hash] = a.kind
				doc_root[a.hash] = a.root.hex()
			}
			'refs' {
				ref_root[a.name] = a.root.hex()
			}
			'aliases' {
				if a.kind == 'retract' {
					alias_val.delete(a.name)
				} else {
					alias_val[a.name] = a.hash
				}
			}
			else {
				return false
			}
		}
	}
	mut live_docs := 0
	mut live_refs := 0
	for key in ms.doc_order {
		mut root := []u8{}
		if r := ms.obj_roots[key] {
			root = r.clone()
		}
		mut tagged := true
		cx.cx_parse_tagged_address(key) or { tagged = false }
		if tagged {
			k := doc_kind[key] or { return false }
			if k != 'insert' {
				return false
			}
			if (doc_root[key] or { '' }) != root.hex() {
				return false
			}
			live_docs++
		} else {
			rr := ref_root[key] or { return false }
			if rr != root.hex() {
				return false
			}
			live_refs++
		}
	}
	mut fold_live := 0
	mut fold_erased := 0
	for _, k in doc_kind {
		if k == 'insert' {
			fold_live++
		} else if k == 'erase' {
			fold_erased++
		}
	}
	if fold_live != live_docs || ref_root.len != live_refs {
		return false
	}
	if fold_erased != ms.erased.len {
		return false
	}
	for h, _ in ms.erased {
		if (doc_kind[h] or { '' }) != 'erase' {
			return false
		}
	}
	if alias_val.len != ms.aliases.len {
		return false
	}
	for name, target in ms.aliases {
		if (alias_val[name] or { '' }) != target {
			return false
		}
	}
	return true
}

// ── write paths ──────────────────────────────────────────────────────────

// store_lineage_write_full streams the whole current lineage (epoch, floors,
// every retained act) to a temp sidecar and installs it atomically. Used by
// the first seed and by compaction. false = nothing installed.
fn store_lineage_write_full(mut ms MemStore) bool {
	if ms.lineage_path == '' || ms.read_only {
		return false
	}
	tmp := ms.lineage_path + '.tmp.${os.getpid()}'
	mut f := os.create(tmp) or { return false }
	mut ok := true
	f.write_string('${store_lineage_header}\n') or { ok = false }
	if ok {
		f.write_string(store_lineage_epoch_record(ms.feed_boot)) or { ok = false }
	}
	if ok {
		mut fkeys := ms.adv_floor.keys()
		fkeys.sort()
		for k in fkeys {
			fl := ms.adv_floor[k] or { continue }
			hd := ms.adv_pos[k] or { i64(0) }
			f.write_string(store_lineage_floor_record(k, fl, hd)) or {
				ok = false
				break
			}
		}
	}
	if ok {
		for a in ms.advances {
			f.write_string(store_lineage_act_record(a)) or {
				ok = false
				break
			}
		}
	}
	f.close()
	if !ok {
		os.rm(tmp) or {}
		return false
	}
	os.mv(tmp, ms.lineage_path) or {
		os.rm(tmp) or {}
		return false
	}
	ms.lineage_records = ms.advances.len
	return true
}

// store_lineage_append persists one live act (called from store_feed_append
// under the op lock, BEFORE the state append lands — append-ordered). A
// failed append is tolerated in-process (the in-memory lineage keeps
// serving this boot); the resulting position gap in the sidecar is caught
// by the next boot's density check, which discards the sidecar and reseeds
// under a fresh epoch — degraded retention, never silent divergence.
fn store_lineage_append(mut ms MemStore, a StoreAdvance) {
	if !ms.lineage_active {
		return
	}
	if store_lineage_is_bucket(ms) {
		// FL-2 (#885) / FL-3 (#887): one small object per act, monotonic name
		// under this store's mount — S3 PUT is atomic per key, so there is no
		// torn-tail shape; a failed PUT leaves the same position gap the
		// density check catches.
		store_s3_lineage_append(mut ms, a)
	} else {
		if ms.lineage_path == '' {
			return
		}
		rec := store_lineage_act_record(a)
		mut f := os.open_append(ms.lineage_path) or { return }
		f.write_string(rec) or {
			f.close()
			return
		}
		f.close()
		ms.lineage_records++
	}
	// Bounded retention (FL-1 §4): compact when the log accumulates
	// materially more records than live entities — the file-index log's own
	// redundancy heuristic. Insert-only workloads never fire it.
	live := ms.doc_order.len + ms.alias_order.len + ms.erased_order.len
	if ms.lineage_records > 2 * live + 64 {
		store_lineage_compact(mut ms)
	}
}

// store_lineage_compact rewrites the sidecar as the state-compacted story —
// the latest act per live entity (erase evidence retained: attribution
// survives compaction) at their ORIGINAL positions — and raises each
// stream's retention floor to its highest compacted-away position. The
// in-memory act list is left whole for this boot (live feeds hold indexes
// into it); only the durable retention and the floors move. Caller holds
// the op lock.
fn store_lineage_compact(mut ms MemStore) {
	if ms.read_only {
		return
	}
	if !store_lineage_is_bucket(ms) && ms.lineage_path == '' {
		return
	}
	mut keep_at := map[string]int{} // entity key → index of its latest act
	for i, a in ms.advances {
		match a.plane {
			'docs' {
				keep_at['d/${a.hash}'] = i
			}
			'refs' {
				keep_at['r/${a.name}'] = i
			}
			'aliases' {
				keep_at['a/${a.name}'] = i
			}
			else {}
		}
	}
	mut keep := map[int]bool{}
	for ent, i in keep_at {
		a := ms.advances[i]
		if ent.starts_with('d/') {
			// live insert and erase evidence survive; a retracted doc's
			// whole history compacts away (the floor covers it).
			if a.kind == 'insert' || a.kind == 'erase' {
				keep[i] = true
			}
		} else if ent.starts_with('r/') {
			if a.name in ms.obj_roots {
				keep[i] = true
			}
		} else {
			if a.kind != 'retract' && a.name in ms.aliases {
				keep[i] = true
			}
		}
	}
	mut floors := ms.adv_floor.clone()
	mut retained := []StoreAdvance{cap: keep.len}
	for i, a in ms.advances {
		if i in keep {
			retained << a
		} else {
			key := store_feed_stream_key(a.plane, a.name)
			if a.pos > (floors[key] or { i64(0) }) {
				floors[key] = a.pos
			}
		}
	}
	saved := ms.advances
	ms.advances = retained
	mut old_floors := ms.adv_floor.move()
	ms.adv_floor = floors.move()
	// FL-2 (#885) / FL-3 (#887): the compacted rewrite lands per medium — the
	// atomic temp+rename sidecar rewrite on a local root; a generation-guarded
	// full object (new gen written first, old gen purged best-effort after) on
	// a bucket mount.
	persisted := if store_lineage_is_bucket(ms) {
		store_s3_lineage_write_compacted(mut ms)
	} else {
		store_lineage_write_full(mut ms)
	}
	if !persisted {
		ms.adv_floor = old_floors.move()
	}
	// this boot keeps serving from the whole in-memory list either way
	ms.advances = saved
}
