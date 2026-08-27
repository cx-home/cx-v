@[has_globals]
module platform
import code {
	err_diagnostic,
	Closure,
	Item,
	MatchEnv,
	PredicateEvalContext,
	Value,
	cap_guard,
	cap_thread_id,
	err_boundary_refusal,
	errs_permitted_node,
	eval_predicate_filter,
	find_err_at_rest,
	http_attr,
	invoke_closure,
	is_err_value,
	mk_err,
	render_canonical,
	resolve_closure,
}

import cx
import cxstore
import io
import os
import sync
import time
import encoding.hex
import crypto.ed25519

// errno/ESRCH for the stale-tmp sweep's kill(pid, 0) liveness probe (#292);
// C.kill itself is declared in stdlib_process.v (same module).
#include <errno.h>

// flock(2) + LOCK_EX/LOCK_NB/LOCK_UN for the #1005 cross-process
// writable-open guard (store_root_lock). ftruncate(2) re-stamps the holder
// record in place once the lock is ours.
#include <sys/file.h>

fn C.flock(fd int, operation int) int

fn C.ftruncate(fd int, length i64) int

// stdlib_store.v — native primitives + mem:// backend for the
// `cx-stdlib/store` content-addressed object store (spec/std-lib/store.md).
//
// The module's `[?def]` bodies (stdlib_src_store, below) forward to the
// native primitives here, dispatched via stdlib_dispatch.v::stdlib_builtin.
// Storage state cannot be expressed in pure CX (a Store is mutated
// in-place across calls; CX values are immutable), so each open Store is
// a heap MemStore registered in a process-global registry and referenced
// by an integer handle carried on the returned `[store handle=N …]`
// element.
//
// BACKEND COVERAGE: `mem://` and `file://` are functional.
// `mem://` is the Memory tier (§2.2.1) — pure in-process, no filesystem
// and no network — so per §9 it requires NO host capability (D-STORE-1).
// `file://` is the LocalFiles tier (§2.2.1): it persists the same in-process
// store model to a directory and is capability-gated (`write` for a
// read-write open, `read` for a read-only open) — denied at `open` with
// CXER0271 when ungranted (deny-by-default, security.md §4). On open it
// loads the directory's index (if any); each mutation is written through to
// the index file, so docs/aliases survive across opens of the same path.
// The current on-disk form is a single length-prefixed `.cxstore-index`
// file; the §4.1 sharded/zstd layout is a future on-disk refinement
// (the API contract + content-addressed identity are unaffected). The
// remote/service backends (network I/O) remain deferred to the integration
// suite and are denied at open without a `net` grant.
//
// Doc identity = SHA-256 of the doc's strict canonical bytes (§2.1,
// spec/core/canonical.md §1.2), computed via the Layer-1 text-hash
// surface cx.cx_text_hash over render_canonical(doc) — identical to the
// `cx hash` CLI and cross-binding parity hashes.

// ── mem:// backend state ─────────────────────────────────────────────

// MemStore is the in-process state for one open `mem://` Store handle.
// `docs` maps a doc hash (lowercase hex) → the doc's strict canonical
// text; `doc_order` / `alias_order` preserve insertion order for stable
// list / iter enumeration.
@[heap]
struct MemStore {
mut:
	url         string
	backend     string
	encoding    string
	compression string
	read_only   bool
	is_open     bool
	// model is the storage model for object-graph backends (spec §4.6, an open-time
	// property): '' / 'subtree' = decompose into the content-addressed Merkle graph
	// (default); 'document' = the degenerate one-object-per-doc form (store the whole
	// canonical blob as a single object, "don't decompose"). Both satisfy the same
	// Layer-1 API; the model is invisible to it. Set from the `model=` open-opt;
	// must be re-specified on reopen until self-describing reopen lands (Phase 5).
	model string
	// root is the filesystem directory for the `file://` backend (the path
	// component of the open URL); empty for the in-process `mem://` backend.
	root        string
	docs        map[string]string
	doc_order   []string
	// blob_kind marks keys stored under the OPAQUE identity rule (F1', ruled
	// 2026-08-08): identity = hash of the RAW bytes; byte-exact round-trip; no
	// canonicalization ever. Structured docs (canonical-bytes identity) never
	// appear here. Persisted as the 'B' record kind; every blob READ re-verifies
	// key == hash(raw) at the boundary (store_get_blob_local).
	blob_kind   map[string]bool
	aliases     map[string]string
	alias_order []string
	// op_lock serializes access to this store's mutable state. A Store handle
	// is single-owner; `[par]` over one shared handle used to race the docs/
	// aliases maps and crash the process (#74 Defect 2). Each op claims the
	// lock with a non-blocking try_lock; a contending thread gets a clean
	// E_STORE_HANDLE_RACE value instead of a segfault. Lazily allocated at
	// open (a nil lock = legacy/unopened handle → guard is skipped).
	op_lock &sync.Mutex = unsafe { nil }
	// #628: WRITABLE opens of one canonical root SHARE this MemStore (two
	// independent writers on one root used to collide on segment numbering —
	// the second flush clobbered the first's segment file). open_count
	// refcounts the live handles; close retires the store only at zero.
	// lock_owner/lock_depth make op-lock acquisition REENTRANT per thread
	// (store_lock_enter/exit): a verb's guard, the jrn layer's flush scope,
	// and the mutation funnels nest on one mutex instead of deadlocking.
	// Ops on a shared store BLOCK on contention (two legitimate owners);
	// the single-handle try-lock refusal contract is unchanged.
	open_count int = 1
	lock_owner u64
	lock_depth int
	// #1005: the cross-process writable-open guard's sentinel path, when this
	// store took it (a WRITABLE open of a substrate with a local root). Empty
	// for a read-only open — exempt by the one-writer + N-read-only-readers
	// discipline — and for a store with no local root (mem://,
	// columnar-over-s3). store-close releases it when the LAST handle on this
	// store goes; every open-time error path after the take releases it too.
	lock_key string
	// declared_consistency is the stream-7 handle floor (L123,
	// consistency_vocabulary.md): the `consistency` open-opts tokens,
	// validated ONCE at declaration against store_guarantee_advert. Empty =
	// undeclared (pre-vocabulary behavior, byte-identical). A declared
	// `:linearizable-ref` makes expect-less ref writes (set-alias /
	// delete-alias) and `branch-force` REFUSE on this handle (F5).
	declared_consistency []string
	// replica_role marks a REPLICA surface (stream 9, audit M8 — the
	// replica declaration profile): its guarantee advert is the replica
	// set, so :read-your-writes / :linearizable-ref declarations refuse
	// at wiring time (offline ref advance is where conflict values land).
	replica_role bool
	// log_records counts records currently in the on-disk append log (#74
	// Defect 1). file:// mutations APPEND one record instead of rewriting the
	// whole index (O(n) per op → O(n^2) total); when the log accumulates enough
	// redundancy vs live state it is compacted back to a snapshot. mem:// unused.
	log_records int
	// #603 O(delta) flush bookkeeping: doc_scanned = doc_order prefix already
	// manifest-scanned (new docs live past it); alias_dirty = alias names
	// whose values changed since the last flush; has_removals gates the
	// (rare) tombstone scans. Together they turn the per-mutation cxpack
	// flush from O(live) map scans into O(delta) — the watermark-diff
	// guards stay (self-healing unchanged), only the CANDIDATE SET shrinks.
	doc_scanned  int
	alias_dirty  []string
	has_removals bool
	// #614 group-commit: while flush_hold > 0, store_append DEFERS durability
	// — file:// records buffer in held_recs, incremental backends just mark
	// flush_dirty — and store_flush_release performs ONE backend flush for
	// the whole scope (one segment pack + one manifest append for cxpack,
	// instead of one per mutation). The caller acknowledges nothing until
	// release returns, so the durability contract moves to the SCOPE
	// boundary, never disappears.
	flush_hold  int
	flush_dirty bool
	held_recs   []string
	// #617: a background segment-fold worker is live for this store (spawned
	// by store_cxpack_fold_kick; at most one — this flag is the guard).
	// Mutated only under the op-lock. store_stdlib_builtin's single-owner
	// try-lock refusal treats contention against this INTERNAL worker as
	// wait-your-turn, never as a user handle race.
	fold_running bool
	// obj_flushed is the sink-tail durability watermark (#299): the count of
	// obj_sink.objects (an insertion-ordered map — V maps preserve insertion
	// order) already durable in obj_backend, so an incremental flush persists
	// only the tail — O(delta) per mutation, never O(sink). Advanced by the
	// sqlite incremental flush; reset by the snapshot persist path and by
	// pc_reclaim (which rebuilds the sink map, invalidating any prefix count).
	// The pack backend keeps its own watermark (obj_pack.flushed); 0 elsewhere.
	obj_flushed int
	// remote pins the network config for a URL-dispatched byte-source backend
	// (s3://, http(s)://). Non-nil ⇒ ops route over the transport per key
	// rather than the in-memory docs map (which stays empty). nil for
	// mem:///file:///cxpack/sqlite. (#91)
	remote &RemoteBackend = unsafe { nil }
	// #129-A object-graph backend (cxpack): the LIVE source of truth is the
	// in-memory object sink + a store-hash → doc-root map, NOT `docs`. Docs are
	// content-addressed into the subtree object graph on put and reconstructed on
	// get, so identical subtrees dedup and a one-field edit shares every untouched
	// subtree object — in memory, not just on disk. `docs` stays empty for this
	// backend; `doc_order` remains the ordered store-hash list. nil for the
	// docs-backed backends (mem/file/sqlite). See store_objgraph.v.
	obj_sink  cxstore.ObjectSink
	obj_roots map[string][]u8
	// E3 lineage (#708 + I5 stream-4 W4, store profile §5.1): the ONE
	// per-ref advance log read by BOTH the fixed `store:log` porcelain and
	// the XSP wire feed — the local view and the remote subscription can
	// never disagree. Live mutations append through store_feed_append (the
	// funnels: put_canonical/put_raw, delete_local, alias_set/delete_local,
	// store_ref_advance_local); load/replay paths set the maps directly and
	// SEED instead (store_feed_seed at open) — a rebuild is history
	// compacted to a snapshot, never a burst of live events. Positions are
	// dense per stream ('docs' is one stream; refs/aliases are per-name).
	// FL-1 (#764): on the local durable substrates the lineage is DURABLE —
	// each act also appends to the .cxstore-lineage sidecar (store_lineage.v)
	// and a verified boot reload restores epoch/floors/positions, so a
	// prior-boot resume cursor RESUMES. feed_boot is the durable EPOCH
	// token a positioned cursor must present; adv_floor holds each stream's
	// retention floor (acts at or below it were compacted away). A cursor
	// outside the retained window — wrong epoch, below a floor, above a
	// head — is REFUSED loudly (CXER5020) and re-seeds; never served
	// silently divergent. Clone/migrate destinations copy state without
	// events (their lineage starts at the destination open's seed — fresh
	// epoch; positions are per-store, never transplanted).
	advances  []StoreAdvance
	adv_pos   map[string]i64
	adv_floor map[string]i64
	feed_boot string
	// FL-1 durable-lineage sidecar bookkeeping: the sidecar path ('' = no
	// local durable substrate), whether live acts append to it (false while
	// seeding / on read-only handles), and the sidecar's record count (the
	// bounded-retention compaction trigger).
	lineage_path    string
	lineage_active  bool
	lineage_records int
	// FL-2 (#885) s3 bucket-lineage bookkeeping (store_s3_lineage.v): the
	// current generation (boot trusts the highest generation with a full
	// object) and the next segment sequence — single-writer names, minted by
	// the daemon that owns the store. Handle bookkeeping, like the sidecar
	// fields above: it never travels in the reload swap.
	lineage_gen i64
	lineage_seq i64
	// W5 erasure (xsp store profile §7b.1): `erased` maps a lawfully-shredded
	// doc hash → the attributed `[erased …]` tombstone's canonical text —
	// the three-way get discriminator's substrate (never-existed / corrupt /
	// erased). erased_order keeps deterministic enumeration for the feed
	// seed and snapshot writers; erased_roots maps a former doc ROOT (hex) →
	// doc hash for the object-wire discriminator (objects-get `erased=true`);
	// erased_dirty is the #603 O(delta) flush list against erased_manifested.
	// The tombstone SURVIVES compaction and restart (E manifest/index
	// records) — attribution always survives (erasure_compliance §6). A
	// later re-put of the same content SUPERSEDES the tombstone (the
	// T-record re-put precedent; the lineage keeps both acts).
	erased            map[string]string
	erased_order      []string
	erased_roots      map[string]string
	erased_dirty      []string
	erased_manifested map[string]bool
	// #637 demand paging: `lazy_objects` marks a store opened WITHOUT the
	// whole-graph slurp — open populates only the refs layer (manifest replay
	// + doc_order/aliases) and objects resolve on first touch through the
	// composite getter. `obj_cache` holds those paged-in objects. It is
	// DELIBERATELY separate from obj_sink: the sink's insertion order is the
	// flush watermark (obj_flushed / persist_objects_from), so caching reads
	// there would re-persist already-durable objects on the next mutation.
	// Reads self-verify at the backend (object_name(payload) == hash), so a
	// corrupt object refuses LOUDLY at first touch — never a silent wrong doc
	// (#129-C posture preserved; the whole-graph check moves to `verify`).
	lazy_objects bool
	obj_cache    map[string][]u8
	// obj_pack is the DURABLE object substrate for the cxpack backend — a pack-backed
	// ObjectBackend (#76 / spec §2, §7.1). Object persistence/resolution route through
	// the seam (put_object / getter_of) rather than hardcoded write_pack/open_pack, so
	// `cxpack` is now ONE implementation of the universal object model. It owns the
	// object-layer durability watermark (which objects are in a persisted pack) and the
	// segment count; this MemStore owns only the REFS layer (obj_roots + the manifest
	// watermarks below). nil for the docs-backed backends (mem/file/sqlite/remote).
	obj_pack &cxstore.PackObjectBackend = unsafe { nil }
	// obj_backend is the durable object substrate for the NON-pack object-graph
	// backends (spec §7.2+): object-per-key on local-fs (cxobj://, DirObjectBackend),
	// sqlite object rows, s3 object-per-key, or the remote object wire. The document
	// engine runs over it through the seam exactly as it does over the pack backend —
	// objects persist via put_object and resolve via the composite getter (the live
	// obj_sink for in-session writes, this backend for everything persisted). none for
	// mem (in-memory only — obj_sink IS the store) and for cxpack (uses obj_pack).
	obj_backend ?cxstore.ObjectBackend
	// #114 (PR-E) encryption-at-rest: when set (open-opt `encrypt-key-id=<id>` on a
	// local object substrate), the durable object backend is an
	// EncryptingObjectBackend keyed by this tenant key-id — objects are AEAD-sealed
	// at rest (envelope: per-object DEK wrapped by the KEK), keyed by the PLAINTEXT
	// hash so the object graph / dedup / structural sharing are UNCHANGED. The KEK is
	// resolved from env `CX_STORE_KEK_<id>` (fail-closed if absent — never a silent
	// ephemeral key that would lose data on restart). '' ⇒ no encryption.
	enc_key_id string
	// #229 encryption-at-rest for the PACK substrate: when enc_key_id is set on a
	// cxpack store, this EncryptingWrapper seals every object into an AEAD
	// envelope keyed by the PLAINTEXT hash and stages it on obj_pack (opened in
	// KEYED mode, v2 packs) through the KeyedObjectBackend seam — the object
	// graph/dedup are unchanged, only the at-rest bytes are ciphertext. nil for
	// plaintext stores and non-pack backends (cxobj wraps via obj_backend).
	obj_pack_enc &cxstore.EncryptingWrapper = unsafe { nil }
	// #129-B incremental cxpack manifest (REFS) watermarks (empty for the other
	// backends). doc_manifested / alias_manifested record which manifest D/C/A entries
	// are currently live on disk, so a flush appends only the delta — new entries plus
	// T/X tombstones for removed ones. The object-layer watermark (which objects are
	// durable) lives on obj_pack.
	doc_manifested   map[string]bool
	alias_manifested map[string]string
	// #129-D introspection cache (cxpack object-graph only; -1/0 for the others).
	// The dedup gauges (logical-vs-distinct objects) need a graph walk, so it is
	// recomputed only when the (doc_count, object_count) fingerprint changes — a
	// scrape over an unchanged store never re-walks, so the metrics plane can't be
	// turned into an O(graph) CPU amplifier (the same "no client may degrade the
	// shared service" discipline observability.v enforces for cardinality).
	graph_stats_docs    int = -1 // doc-count fingerprint of the cached walk
	graph_stats_objects int = -1 // object-count fingerprint of the cached walk
	graph_logical       i64 // Σ live-doc objects if NOTHING were shared
	graph_distinct      int // distinct objects reachable from the live docs
	// #129 D5 columnar: whether the most recent flush/load promoted ≥1 top-level
	// scalar field to its own typed column (so [$store:query] can push a column
	// projection + scalar predicate down to a columnar scan). false ⇒ the
	// collection is stored blob-only (__cx_key + __cx_doc) and queries materialize
	// rows. The full canonical doc ALWAYS rides in __cx_doc regardless, so promotion
	// is a pure pushdown projection — never the reconstruction source. Only
	// meaningful for the columnar backend.
	columnar_pushdown bool
	// #129 D5 (G3-Q5=b) columnar over s3: when set, the columnar file bytes are
	// stored as a SINGLE s3 object (one PUT/GET) at columnar_s3_key via this
	// injected transport (the same S3Transport seam the s3 subtree backend uses, so
	// the §9 gate runs hermetically against a stub). none ⇒ file:// substrate
	// (bytes land at ms.root). The s3 object IS a standard Parquet/Arrow file.
	columnar_s3     ?S3Transport
	columnar_s3_key string
	// #891 sharing identity for the s3 case. The transport is an opaque seam
	// (an S3Transport interface, deliberately stubbable), so the addressing
	// parts are recorded here rather than reached for through it: endpoint +
	// bucket + columnar_s3_key IS "the same store" for same-root sharing. The
	// endpoint is part of it because one bucket name on two endpoints is two
	// different stores. Empty for the file:// case, which keys on ms.root.
	columnar_s3_endpoint string
	columnar_s3_bucket   string
	// #129 D5 (G3-Q3=a) declared schema: when a columnar store is opened with
	// `?schema=<path>`, this holds the schema TEXT (a cx-stdlib/validate `[schema …]`
	// shape). Every put is then validated against it and a non-conforming doc is
	// REJECTED (CXER1115) — pinning the table's shape. '' ⇒ inference (the default).
	columnar_schema string
}

// ── file:// persistence ──────────────────────────────────────────────
//
// The file backend persists the whole store model to a single
// length-prefixed index file under `root`. Records carry an explicit byte
// length so doc text and alias names may contain any bytes (newlines,
// tabs) without an escaping pass. doc_order / alias_order are preserved by
// record order, so a reopened store enumerates identically.

const store_index_name = '.cxstore-index'

fn store_path_from_url(url string) string {
	// The `file` location is everything after `file://`, verbatim — supporting both
	// absolute (`file:///abs` → `/abs`) and relative (`file://./rel` → `./rel`,
	// `file://rel` → `rel`) paths, as the retired `cxpack://`/`cxobj://` tokens did.
	// (No host-authority form: a local file store is a path, not `file://host/…`.)
	if url.starts_with('file://') {
		return url['file://'.len..]
	}
	return url
}

// store_write_index streams the snapshot to `path`, record by record, through
// libc's FILE buffering — the whole index is never materialized in memory
// (#283). The former single-Builder encode needed a contiguous buffer tracking
// the index size: once the marine helm's index passed 32 MB, the Builder's
// doubling asked vgc for >64 MB — larger than an arena, so a dedicated
// oversized arena slot — and at arena exhaustion every persist died (the #277
// field OOM, `store_encode_index` in both crash traces). Streaming bounds the
// persist's allocation to one record HEADER at a time; doc bodies are written
// straight from the strings the store already holds. A failed or aborted
// write removes the partial file so the temp+rename caller never renames a
// torn snapshot into place.
fn store_write_index(ms &MemStore, path string) ! {
	mut f := os.create(path)!
	mut ok := false
	defer {
		f.close()
		if !ok {
			os.rm(path) or {}
		}
	}
	f.write_string('CXSTORE\tv1\n')!
	for h in ms.doc_order {
		body := ms.docs[h]
		if h in ms.blob_kind {
			f.write_string(store_blob_record_header(h, body.len))!
		} else {
			f.write_string(store_doc_record_header(h, body.len))!
		}
		f.write_string(body)!
		f.write_string('\n')!
	}
	for a in ms.alias_order {
		hash := ms.aliases[a]
		f.write_string(store_alias_record_header(a.len, hash))!
		f.write_string(a)!
		f.write_string('\n')!
	}
	for h in ms.erased_order {
		tomb := ms.erased[h] or { continue }
		f.write_string(store_erase_record_header(h, tomb.len))!
		f.write_string(tomb)!
		f.write_string('\n')!
	}
	ok = true
}

// store_read_exact fills exactly n bytes from the buffered reader into a fresh
// string, or reports none on a short/torn stream. Each iteration reads into a
// chunk sized to min(remaining, 64 KiB) — the exact length caps the read so it
// can never overrun the record boundary into the next header. NOT a shared
// slice window: `mut w := buf[got..]` binds a COPY in V, so reads into it are
// silently discarded (verified: every replayed payload came back NUL-filled).
fn store_read_exact(mut br io.BufferedReader, n int) ?string {
	if n < 0 {
		return none
	}
	if n == 0 {
		return ''
	}
	mut buf := []u8{len: n}
	mut got := 0
	for got < n {
		remaining := n - got
		csz := if remaining < 65536 { remaining } else { 65536 }
		mut chunk := []u8{len: csz}
		k := br.read(mut chunk) or { return none }
		if k <= 0 || k > csz {
			return none
		}
		unsafe { C.memcpy(&u8(buf.data) + got, chunk.data, k) }
		got += k
	}
	return buf.bytestr()
}

// store_read_index replays the index file into ms record-by-record through a
// buffered reader — the file is never materialized as one string (#283: the
// open path was the read-side twin of the monolithic snapshot encode, peaking
// at ~2x index size — the whole-file string plus the per-body copies — right
// at boot). Peak transient is now the reader's buffer plus one record body.
// Tolerance is unchanged from the previous whole-string decode: a torn or
// malformed tail stops the replay and keeps every record before it (the
// temp+rename snapshot writer makes a torn HEAD impossible; a torn tail is an
// interrupted append).
fn store_read_index(path string, mut ms MemStore) ! {
	mut f := os.open(path) or { return }
	defer {
		f.close()
	}
	mut br := io.new_buffered_reader(reader: f)
	// Header line ('CXSTORE\tv1') — absent/torn ⇒ empty store, as before.
	br.read_line() or { return }
	mut recs := 0
	for {
		line := br.read_line() or { break }
		parts := line.split('\t')
		if parts.len < 3 {
			break
		}
		if parts[0] == 'D' {
			hash := parts[1]
			if hash.starts_with('code:') {
				// A3 (RULED 2026-08-08): a legacy code:-keyed record is REFUSED
				// LOUDLY — its key was never the hash of the stored bytes (the
				// retired computation-identity keying), so no read path may
				// admit it. No tolerance window: re-ingest through put-blob.
				return error('E_STORE_INTEGRITY_MISMATCH: legacy code: record ${hash} — the computation-identity-keyed store form is retired (F1-prime/A3); re-ingest the source through put-blob')
			}
			body := store_read_exact(mut br, parts[2].int()) or { break }
			// trailing record newline
			store_read_exact(mut br, 1) or { break }
			recs++
			if hash !in ms.docs {
				ms.docs[hash] = body
				ms.doc_order << hash
			}
			store_replay_clear_erased(mut ms, hash) // a later put supersedes a tombstone
		} else if parts[0] == 'B' {
			// F1' opaque blob: raw bytes, key = hash(raw). Replay records state
			// only; the raw-hash verification runs at EVERY read
			// (store_get_blob_local) — strictly stronger for this
			// error-return-less replay path than a load-time-only check.
			hash := parts[1]
			body := store_read_exact(mut br, parts[2].int()) or { break }
			store_read_exact(mut br, 1) or { break }
			recs++
			if hash !in ms.docs {
				ms.docs[hash] = body
				ms.doc_order << hash
			}
			ms.blob_kind[hash] = true
			store_replay_clear_erased(mut ms, hash)
		} else if parts[0] == 'A' {
			hash := parts[2]
			name := store_read_exact(mut br, parts[1].int()) or { break }
			store_read_exact(mut br, 1) or { break }
			recs++
			if name !in ms.aliases {
				ms.alias_order << name
			}
			ms.aliases[name] = hash
		} else if parts[0] == 'T' {
			// #291 doc tombstone (header-only record): REMOVE the doc. Replay
			// order decides, so a later D record for the same hash re-adds it
			// (delete → re-put comes back). A pre-tombstone index simply never
			// carries T records and replays exactly as before.
			recs++
			store_delete_local(mut ms, parts[1])
		} else if parts[0] == 'X' {
			// #298 alias tombstone (A's length-prefixed payload shape): REMOVE
			// the alias. Replay order decides — a later A record re-adds it.
			name := store_read_exact(mut br, parts[1].int()) or { break }
			store_read_exact(mut br, 1) or { break }
			recs++
			if name in ms.aliases {
				ms.aliases.delete(name)
				ai := ms.alias_order.index(name)
				if ai >= 0 {
					ms.alias_order.delete(ai)
				}
			}
		} else if parts[0] == 'E' {
			// W5 erased tombstone (§7b.1): record the attributed erasure (the
			// doc's removal rode its own T record). Replay order decides — a
			// later D record for the same hash supersedes the tombstone.
			tomb := store_read_exact(mut br, parts[2].int()) or { break }
			store_read_exact(mut br, 1) or { break }
			recs++
			store_replay_apply_erased(mut ms, parts[1], tomb)
		} else {
			break
		}
	}
	// Seed the append-log record count from what was just replayed, so the
	// compaction heuristic (store_append) measures redundancy against the
	// on-disk log it actually inherited (#74 Defect 1).
	ms.log_records = recs
}

// store_sweep_stale_tmp removes orphaned `.cxstore-index.tmp.<pid>` snapshot
// temps left behind by a writer that died between store_persist's temp write
// and its atomic rename (#292 — the marine helm's store dir carried four
// 0-byte orphans from the pre-#284 OOM-death era). Safe by construction: a
// tmp sibling is either from a dead writer of THIS store or the in-flight
// persist of the live owner (the port-as-mutex process model admits no second
// live writer), so a tmp whose pid suffix is not a live process is garbage.
// kill(pid, 0) probes liveness; only ESRCH (no such process) qualifies for
// removal — 0/EPERM mean the pid is alive (possibly under another uid) and a
// non-numeric suffix is not ours to touch. The live index is never a
// candidate (the required `.tmp.` prefix excludes it). Called only from a
// WRITABLE flat open: a read-only handle holds no write grant, so it must
// not delete files.
fn store_sweep_stale_tmp(root string) {
	prefix := store_index_name + '.tmp.'
	entries := os.ls(root) or { return }
	for e in entries {
		if !e.starts_with(prefix) {
			continue
		}
		suffix := e[prefix.len..]
		if suffix == '' || !suffix.bytes().all(it.is_digit()) {
			continue
		}
		pid := suffix.int()
		if pid <= 0 || C.kill(pid, 0) == 0 {
			continue // live process — possibly an in-flight persist
		}
		if C.errno != C.ESRCH {
			continue // EPERM etc.: the pid exists beyond our sight — keep
		}
		os.rm(os.join_path(root, e)) or {}
	}
}

// store_persist_err maps a persist/flush failure onto the store error space
// (#213/#217 never-lie rule: an op whose durable write failed raises — never a
// phantom success): a substrate auth rejection → CXER1131, a backend rate-limit
// → CXER1132, everything else → CXER1116 E_STORE_WRITE_FAILED. The in-memory
// state stays authoritative for the open handle, and the watermark-diff flush
// re-attempts the pending delta on the next persist (self-healing).
fn store_persist_err(ms &MemStore, msg string) cx.Node {
	if msg.contains('status 401') || msg.contains('status 403') || msg.contains('auth rejected') {
		return mk_err('cx-err:CXER1131', 'E_STORE_AUTH_FAILED: ${ms.url}: ${msg}')
	}
	if msg.contains('status 429') {
		return mk_err('cx-err:CXER1132', 'E_STORE_RATE_LIMIT: ${ms.url}: ${msg}')
	}
	return mk_err('cx-err:CXER1116', 'E_STORE_WRITE_FAILED: ${ms.url}: ${msg}')
}

// store_persist writes the current store model to `root/.cxstore-index`.
// A no-op for the mem backend. A durable-write failure PROPAGATES (`!`) so the
// op that triggered it raises (store_persist_err) instead of acknowledging a
// write that didn't land; the in-process state remains authoritative for the
// open handle and the next successful persist self-heals.
fn store_persist(mut ms MemStore) ! {
	// #628: persists serialize on the reentrant op-lock (see store_append).
	store_lock_enter(mut ms)
	defer {
		store_lock_exit(mut ms)
	}
	$if cxstore_sqlite ? {
		if ms.backend == 'sqlite' {
			// #299: incremental, like cxpack below — a delta over the durable
			// base IS the current model (deletes land as T/X manifest rows,
			// migrate/clone as one bulk delta row). The flush's own threshold
			// check folds the manifest log back to a snapshot
			// (store_sqlite_persist) when redundancy accrues, which also serves
			// gc's durable-compaction half.
			store_sqlite_flush(mut ms)!
			return
		}
	}
	if ms.backend == 'cxpack' {
		// #129-B: incremental — flush only the delta since the last persist
		// (removals included, as manifest tombstones), not a whole-pack snapshot.
		store_cxpack_flush(mut ms)!
		return
	}
	if ms.backend == 'cxobj' {
		// §7.2: local-fs object-per-key subtree — objects written per-key, refs
		// delta appended to the manifest, all through the universal seam.
		store_cxobj_flush(mut ms)!
		return
	}
	if ms.backend == 's3' {
		// §7.3: s3 object-per-key subtree — objects PUT per-key, refs snapshot to
		// the manifest key, all through the universal seam.
		store_s3_flush(mut ms)!
		return
	}
	if ms.backend == 'columnar' {
		// #129 D5: document-model store with a columnar at-rest encoding — the live
		// collection is serialized column-wise to a Parquet/Arrow file (gated).
		$if cxstore_columnar ? {
			store_columnar_flush(mut ms)!
		}
		return
	}
	if ms.backend != 'file' || ms.root == '' {
		return
	}
	os.mkdir_all(ms.root) or { return error('file ${ms.root}: mkdir failed: ${err.msg()}') }
	idx := os.join_path(ms.root, store_index_name)
	// Temp-file + atomic rename: the snapshot replaces the whole index; a torn
	// truncate-in-place write would lose every doc on a crash mid-write.
	tmp := idx + '.tmp.${os.getpid()}'
	store_write_index(ms, tmp) or {
		return error('file ${ms.root}: index snapshot write failed: ${err.msg()}')
	}
	os.mv(tmp, idx) or {
		os.rm(tmp) or {}
		return error('file ${ms.root}: index snapshot rename failed: ${err.msg()}')
	}
}

// store_doc_record_header / store_alias_record_header /
// store_tombstone_record / store_alias_tombstone_record are the single source
// of the index wire format's record headers — shared by the append log
// (store_doc_record / store_alias_record / the tombstones) and the streamed
// snapshot (store_write_index), so a log always replays identically through
// store_read_index (dedup for docs, last-write-wins for aliases, removal for
// tombstones — with replay ORDER deciding, so a re-put doc / re-set alias
// after its tombstone comes back).
fn store_doc_record_header(h string, body_len int) string {
	return 'D\t${h}\t${body_len}\n'
}

fn store_alias_record_header(alias_len int, hash string) string {
	return 'A\t${alias_len}\t${hash}\n'
}

// store_tombstone_record is the T (doc tombstone) record (#291) — the header
// IS the whole record (no payload; the third field keeps the uniform
// three-column header shape). Appended by delete-doc so deletion rides the
// same O(1) append path as puts and alias updates instead of rewriting the
// whole snapshot; cxpack manifests' T/X tombstones are the precedent. The
// snapshot writer never emits tombstones — compaction folds them away.
fn store_tombstone_record(h string) string {
	return 'T\t${h}\t0\n'
}

// store_alias_tombstone_record is the X (alias tombstone) record (#298) — the
// alias-plane sibling of T, completing the cxpack-manifest T/X precedent.
// It mirrors the A record's length-prefixed payload shape (alias names may
// contain any bytes; the '0' third field keeps the uniform 3-column header).
// Appended by delete-alias so alias removal rides the O(1) append path; the
// snapshot writer never emits it — compaction folds it away.
fn store_alias_tombstone_record_header(alias_len int) string {
	return 'X\t${alias_len}\t0\n'
}

fn store_alias_tombstone_record(alias string) string {
	return '${store_alias_tombstone_record_header(alias.len)}${alias}\n'
}

// store_blob_record_header / store_blob_record — the 'B' (F1' opaque blob)
// record: the same length-prefixed payload shape as 'D', but the key is the
// hash of the RAW payload bytes; verification uses the raw-bytes rule at
// every read (store_get_blob_local), never canonicalization.
fn store_blob_record_header(h string, body_len int) string {
	return 'B\t${h}\t${body_len}\n'
}

fn store_blob_record(h string, raw string) string {
	return store_blob_record_header(h, raw.len) + raw + '\n'
}

fn store_doc_record(h string, body string) string {
	return '${store_doc_record_header(h, body.len)}${body}\n'
}

// store_erase_record is the E (erased tombstone) record (W5, xsp store
// profile §7b.1): the doc-level lawful shred's attributed evidence. Payload =
// the `[erased …]` tombstone's canonical text. Unlike T/X, the SNAPSHOT
// writer EMITS it — attribution survives compaction (erasure_compliance §6).
fn store_erase_record_header(h string, body_len int) string {
	return 'E\t${h}\t${body_len}\n'
}

fn store_erase_record(h string, tombstone string) string {
	return '${store_erase_record_header(h, tombstone.len)}${tombstone}\n'
}

fn store_alias_record(alias string, hash string) string {
	return '${store_alias_record_header(alias.len, hash)}${alias}\n'
}

// store_append — #74 Defect 1: append ONE record to the file:// index rather
// than rewriting the entire index on every mutation (the per-op O(n) →
// O(n^2)-total cost that made file:// unusable past a few thousand keys). The
// log replays through store_read_index, so an append-only file reads back
// identically to a snapshot. mem:// is a no-op. When the log accumulates
// materially more records than live state (from alias updates / re-puts) it is
// compacted back to a snapshot via store_persist, keeping replay O(live) and
// appends amortized O(1). A durable-write failure PROPAGATES (`!`), matching
// store_persist — the triggering op raises instead of acknowledging a write
// that didn't land.
// store_flush_hold opens a #614 group-commit scope: mutations inside it
// stay in-memory-staged; durability lands at the matching release. Nestable.
// #628: the scope also TAKES the store's reentrant op-lock, so a whole
// journal append (entry doc + entry alias + head meta + head alias) is
// atomic against a sibling handle's writers — the hash chain can never
// interleave — and releases it after the flush lands.
fn store_flush_hold(mut ms MemStore) {
	store_lock_enter(mut ms)
	ms.flush_hold++
}

// store_flush_release closes a group-commit scope; the OUTERMOST release
// performs one backend flush covering every held mutation. A flush failure
// propagates exactly as a per-op failure does (the op-in-progress raises;
// in-process state stays authoritative; the next flush self-heals).
fn store_flush_release(mut ms MemStore) ! {
	defer {
		store_lock_exit(mut ms)
	}
	if ms.flush_hold > 0 {
		ms.flush_hold--
	}
	if ms.flush_hold > 0 {
		return
	}
	if !ms.flush_dirty && ms.held_recs.len == 0 {
		return
	}
	ms.flush_dirty = false
	if ms.backend == 'file' && ms.held_recs.len > 0 {
		n := ms.held_recs.len
		recs := ms.held_recs.join('')
		ms.held_recs = []
		store_append_file_now(mut ms, recs, n)!
		return
	}
	ms.held_recs = []
	store_append_flush_backend(mut ms)!
}

// store_append_flush_backend runs the incremental backend flush once —
// the tail store_append performs per mutation outside a hold scope.
fn store_append_flush_backend(mut ms MemStore) ! {
	$if cxstore_sqlite ? {
		if ms.backend == 'sqlite' {
			store_sqlite_flush(mut ms)!
			return
		}
	}
	if ms.backend == 'cxpack' {
		store_cxpack_flush(mut ms)!
		return
	}
	if ms.backend == 'cxobj' {
		store_cxobj_flush(mut ms)!
		return
	}
	if ms.backend == 's3' {
		store_s3_flush(mut ms)!
		return
	}
	if ms.backend == 'columnar' {
		$if cxstore_columnar ? {
			store_columnar_flush(mut ms)!
		}
		return
	}
}

fn store_append(mut ms MemStore, rec string) ! {
	// #628: durable appends serialize on the store's reentrant op-lock (a
	// no-op re-enter inside a verb guard or a flush scope; the real
	// acquisition for direct jrn/fabric-layer calls on a shared store).
	store_lock_enter(mut ms)
	defer {
		store_lock_exit(mut ms)
	}
	// #614: inside a group-commit scope, defer — release flushes once.
	if ms.flush_hold > 0 {
		ms.flush_dirty = true
		if ms.backend == 'file' && ms.root != '' {
			ms.held_recs << rec
		}
		return
	}
	$if cxstore_sqlite ? {
		if ms.backend == 'sqlite' {
			// #299: incremental — the mutation's new objects (sink tail) + ONE
			// manifest delta row land in a single transaction, O(delta) per op.
			// The snapshot path (store_sqlite_persist) remains for gc/migrate
			// and for the flush's own log-fold compaction.
			store_sqlite_flush(mut ms)!
			return
		}
	}
	if ms.backend == 'cxpack' {
		// #129-B: incremental append — new objects go to a fresh segment pack and
		// the new manifest entries are appended (the `rec` wire-format string is a
		// file:// artifact; the cxpack live graph is the source of truth).
		store_cxpack_flush(mut ms)!
		return
	}
	if ms.backend == 'cxobj' {
		store_cxobj_flush(mut ms)!
		return
	}
	if ms.backend == 's3' {
		store_s3_flush(mut ms)!
		return
	}
	if ms.backend == 'columnar' {
		// Parquet is write-once-per-file: an "append" rewrites the columnar file
		// from the live collection (the in-memory docs map is the source of truth;
		// the file is a column-wise snapshot). Row-group-incremental append is a
		// later refinement (spec §3 write batching).
		$if cxstore_columnar ? {
			store_columnar_flush(mut ms)!
		}
		return
	}
	if ms.backend != 'file' || ms.root == '' {
		return
	}
	store_append_file_now(mut ms, rec, 1)!
}

// store_append_file_now writes `recs` (n records, pre-joined) to the file://
// index in ONE open/append/close — the per-op path passes a single record;
// a #614 group-commit release passes the whole held scope.
fn store_append_file_now(mut ms MemStore, recs string, n int) ! {
	tr := fab_trace_on()
	t0 := time.sys_mono_now()
	os.mkdir_all(ms.root) or { return error('file ${ms.root}: mkdir failed: ${err.msg()}') }
	idx := os.join_path(ms.root, store_index_name)
	if !os.exists(idx) {
		os.write_file(idx, 'CXSTORE\tv1\n${recs}') or {
			return error('file ${ms.root}: index write failed: ${err.msg()}')
		}
		ms.log_records = n
		return
	}
	mut f := os.open_append(idx) or {
		return error('file ${ms.root}: index open failed: ${err.msg()}')
	}
	f.write_string(recs) or {
		f.close()
		return error('file ${ms.root}: index append failed: ${err.msg()}')
	}
	f.close()
	ms.log_records += n
	t_appended := time.sys_mono_now()
	// Compaction: when redundancy builds up (each alias update / re-append adds
	// a record without growing live state), snapshot the live model and reset
	// the log to live size. Insert-only workloads append zero redundancy, so
	// this never fires for them.
	live := ms.doc_order.len + ms.alias_order.len
	mut compacted := false
	if ms.log_records > 2 * live + 64 {
		store_persist(mut ms)!
		ms.log_records = live
		compacted = true
	}
	if tr {
		t_done := time.sys_mono_now()
		eprintln('[fab-trace side=store step=file-append recs=${n} bytes=${recs.len} log-records=${ms.log_records} live=${live} io-us=${(t_appended - t0) / 1000} compact=${compacted} compact-us=${(t_done - t_appended) / 1000}]')
	}
}

// StoreRegistry holds every open Store keyed by integer handle. Process
// -global and impure — shared across all callers in the process.
//
// The `@[has_globals]` file attribute enables module-level state without
// the `-enable-globals` CLI flag (same as stdlib_random.v / stdlib_uuid.v
// / code/cabi.v). The registry is held behind a nil-default `voidptr`
// global (the proven code/cabi.v streaming-sink form) and lazily
// allocated on first use, since a value initializer carrying a `map`
// field is not const-evaluable.
@[heap]
struct StoreRegistry {
mut:
	stores  map[int]&MemStore
	next_id int
	// #628: ids retired by store-close. A closed HANDLE's later ops must
	// report CXER1130 (the spec's closed-store error), not "unknown handle" —
	// and on a shared store the id must stop resolving to the still-live
	// sibling view.
	closed map[int]bool
}

__global (
	g_store_reg voidptr
)

// g_store_reg_lock guards the registry map (#628: registration, lookup, the
// same-root dedupe scan, and close's id retirement can race across threads).
const g_store_reg_lock = &sync.Mutex(sync.new_mutex())

fn store_reg() &StoreRegistry {
	if g_store_reg == unsafe { nil } {
		r := &StoreRegistry{
			stores: map[int]&MemStore{}
		}
		g_store_reg = voidptr(r)
	}
	return unsafe { &StoreRegistry(g_store_reg) }
}

fn store_register(ms &MemStore) int {
	mut l := unsafe { g_store_reg_lock }
	l.@lock()
	mut reg := store_reg()
	reg.next_id++
	id := reg.next_id
	reg.stores[id] = ms
	l.unlock()
	// E3 lineage (§5.1): establish the advance log ONCE per MemStore,
	// before any live mutation can interleave — the registry is the single
	// point every fresh store passes through. FL-1 (#764): reload the
	// verified durable sidecar when one exists (positions survive the
	// restart); else seed compacted-from-snapshot and write the initial
	// sidecar.
	mut m := unsafe { ms }
	store_feed_open(mut m)
	return id
}

fn store_lookup(id int) ?&MemStore {
	mut l := unsafe { g_store_reg_lock }
	l.@lock()
	reg := store_reg()
	ms := reg.stores[id] or {
		l.unlock()
		return none
	}
	l.unlock()
	return ms
}

// store_id_closed reports whether a handle id was retired by store-close
// (#628: the CXER1130 closed-store contract survives per-handle retirement).
fn store_id_closed(id int) bool {
	mut l := unsafe { g_store_reg_lock }
	l.@lock()
	reg := store_reg()
	hit := id in reg.closed
	l.unlock()
	return hit
}

// store_find_shared returns an already-open WRITABLE store on the same
// canonical (backend, root) — the #628 same-root sharing dedupe — bumping its
// refcount under the registry lock. `key_fp` fingerprints the open options
// that shape at-rest bytes; a mismatch is the CALLER's to refuse (sharing
// with divergent options would silently apply one opener's options to the
// other's writes).
fn store_find_shared(backend string, root string, key_fp string) ?&MemStore {
	mut l := unsafe { g_store_reg_lock }
	l.@lock()
	mut reg := store_reg()
	for _, ms in reg.stores {
		if ms.is_open && !ms.read_only && ms.backend == backend && store_share_root(ms) == root {
			if store_share_fp(ms) == key_fp {
				mut m := unsafe { ms }
				m.open_count++
				l.unlock()
				return m
			}
			l.unlock()
			return none // caller refuses loudly (option mismatch on a live root)
		}
	}
	l.unlock()
	return none
}

// store_share_fp fingerprints the open options that shape a store's at-rest
// bytes — two writable opens may share the live MemStore only when they agree.
//
// #891: the columnar schema joins the fingerprint. It shapes the at-rest file
// layout exactly as encoding and compression do, so two writers declaring
// different schemas over one path are NOT sharing-compatible. The component is
// '' for every other backend, so their fingerprints are unchanged in meaning.
fn store_share_fp(ms &MemStore) string {
	return '${ms.enc_key_id}|${ms.model}|${ms.encoding}|${ms.compression}|${ms.columnar_schema}'
}

// store_share_root is the sharing IDENTITY of a store — what "the same store"
// means for #628 dedupe.
//
// For every local substrate that is `ms.root`, a filesystem path. #891 extends
// sharing to the columnar-over-s3 case, which has no local path at all: its
// identity is endpoint + bucket + object key. The endpoint belongs in it
// because one bucket name on two endpoints is two different stores, and using
// `ms.root` for this would be wrong — `root` is a filesystem path everywhere
// else and code that treats it as one must keep working.
fn store_share_root(ms &MemStore) string {
	if ms.backend == 'columnar' && ms.columnar_s3 != none {
		return store_share_root_s3(ms.columnar_s3_endpoint, ms.columnar_s3_bucket,
			ms.columnar_s3_key)
	}
	return ms.root
}

// store_share_root_s3 builds that identity from its parts, so the open site and
// the registry derive it the same way instead of spelling it twice.
fn store_share_root_s3(endpoint string, bucket string, key string) string {
	return 's3://${endpoint}/${bucket}/${key}'
}

// store_share_conflict reports whether root is open WRITABLE with different
// at-rest options (the refusal case store_find_shared signalled with none).
fn store_share_conflict(backend string, root string, key_fp string) bool {
	mut l := unsafe { g_store_reg_lock }
	l.@lock()
	reg := store_reg()
	for _, ms in reg.stores {
		if ms.is_open && !ms.read_only && ms.backend == backend && store_share_root(ms) == root {
			hit := store_share_fp(ms) != key_fp
			l.unlock()
			return hit
		}
	}
	l.unlock()
	return false
}

// ── #1005 cross-process writable-open guard ─────────────────────────────
//
// #628 (file/cxobj/cxpack) and #891 (columnar/sqlite) make a SECOND WRITABLE
// open of one root sound IN-PROCESS: it returns a second handle over the same
// live MemStore. That remedy is a process-global registry and cannot span
// processes by construction, so a second PROCESS opening the same root
// writable proceeded in silence and destroyed the root — two writers collide
// on segment numbering, the later flush clobbers the earlier's segment file,
// and the damage surfaces only at the NEXT open as `CXER1120
// E_STORE_INTEGRITY_MISMATCH` with a segment missing from the pack sequence
// (#993 measured it, 5 runs of 5). The supported cross-process shape on a
// local root is ONE writer + N READ-ONLY readers (journal.md §3.3); it was
// stated and unenforced, and is now enforced at open.
//
// MECHANISM: advisory `flock(2)` `LOCK_EX|LOCK_NB` on a sentinel file at the
// root. flock rather than an `O_EXCL` sentinel because of the staleness story:
//
//   THERE IS NONE. An flock lives on the open file DESCRIPTION, so the kernel
//   releases it when the holder's last descriptor closes — normal exit,
//   `_exit`, an unhandled signal, SIGKILL, an OOM kill, a V panic. A crashed
//   writer therefore CANNOT brick the root: the very next open takes the lock.
//   An O_EXCL sentinel would have to tell a crashed holder from a live one by
//   pid liveness plus a boot/start-time identity, and a pid recycled across a
//   reboot would then refuse a root that nothing holds — a brick, which is a
//   worse failure than the corruption being fixed. So the guard is built on the
//   one primitive whose release is the kernel's job, not a heuristic's.
//
// The sentinel's BYTES are only the holder's NAME (pid / host / url / since),
// for the refusal text. They are never the authority on whether the lock is
// held, so a record left behind by a crash cannot mislead anyone: whoever
// acquires the lock next truncates and re-stamps it, and a refusal is issued
// only when flock itself says the lock is taken — i.e. by a LIVE holder.
//
// The sentinel is never unlinked at close. Unlinking races a peer that already
// holds the file open (it would lock an unlinked inode while a third process
// creates a fresh one), and an idle sentinel costs one inode and one line.
//
// SCOPE. Writable opens of a substrate with a local root: `file` (all three
// framings — the flat document index, `cxobj`, `cxpack`), `sqlite`, and
// local-file `columnar`. Read-only opens are EXEMPT by the discipline itself.
// `mem://` has no at-rest bytes; columnar-over-s3 has no local root to key on
// (its sharing identity is endpoint+bucket+key, #891) and no filesystem to
// lock — the object-store tier's own concurrency story, not this guard's.

const store_root_lock_name = '.cxstore-lock'

// RootLock is one held sentinel: the descriptor carrying the flock, plus an
// in-process refcount. The refcount exists because flock is per-DESCRIPTION —
// a second `flock` on a second descriptor conflicts even inside one process —
// so an in-process second writable open must refcount this lock rather than
// take it again. Which is also the correct semantics: an in-process second
// writable open is #628/#891 territory (a shared live view, or a loud
// option-mismatch refusal upstream of here), never this guard's business.
@[heap]
struct RootLock {
mut:
	f     os.File
	count int
}

@[heap]
struct RootLockReg {
mut:
	held map[string]&RootLock
	// roots already announced as unguarded (degrade-with-visibility, once
	// per root per process — never a per-open reprint).
	announced map[string]bool
}

__global (
	g_store_rootlocks voidptr
)

// g_store_rootlock_mu is held across the WHOLE acquire, file I/O included.
// Two threads racing the same root would otherwise both reach flock, and the
// loser would refuse against ITSELF (flock is per-description). Opens are not
// a hot path, so serializing them is free.
const g_store_rootlock_mu = &sync.Mutex(sync.new_mutex())

fn store_rootlock_reg() &RootLockReg {
	if g_store_rootlocks == unsafe { nil } {
		r := &RootLockReg{
			held:      map[string]&RootLock{}
			announced: map[string]bool{}
		}
		g_store_rootlocks = voidptr(r)
	}
	return unsafe { &RootLockReg(g_store_rootlocks) }
}

// store_root_lock_path derives the sentinel path. `file`/`cxobj`/`cxpack` open
// a DIRECTORY root, so the sentinel is a child of it; `sqlite` and `columnar`
// open a FILE root, so it is a sibling — one sentinel per store either way,
// and never a stray directory next to a user's database.
fn store_root_lock_path(backend string, root string) string {
	if backend in ['file', 'cxobj', 'cxpack'] {
		return os.join_path(root, store_root_lock_name)
	}
	return root + store_root_lock_name
}

// store_root_lock_holder reads the holder record for the refusal text. Empty
// when there is none, when it is unreadable, or when it is not ours to read —
// the refusal then says so instead of guessing.
fn store_root_lock_holder(path string) string {
	txt := os.read_file(path) or { return '' }
	line := txt.all_before('\n').trim_space()
	if !line.starts_with('cxstore-lock v1 ') {
		return ''
	}
	return line['cxstore-lock v1 '.len..]
}

// store_root_lock_refusal names the holder AND the way out. Both halves are
// load-bearing: a refusal that only says "conflict" turns a mis-wired
// deployment into a mystery, and #1005 exists because the failure was silent.
fn store_root_lock_refusal(root string, url string, holder string) string {
	who := if holder == '' { 'no holder record — the sentinel was empty' } else { holder }
	return 'E_STORE_OPEN_CONFLICT: ${root} is already open WRITABLE by another process (${who}) — ' +
		'the supported cross-process shape on a local root is ONE writer + N READ-ONLY readers ' +
		'(journal.md §3.3): two writers collide on segment numbering and leave the root structurally dead. ' +
		'RECOVERY: close that handle or end that process and reopen, or open this one READ-ONLY ' +
		'(`[\$store:open-opts URL [map read-only="true"]]`) — read-only opens are never gated. ' +
		'The lock is released by the kernel when its holder dies, so a crashed writer never keeps ' +
		'it: this refusal always names a LIVE holder. (${url})'
}

// store_root_lock_unsupported announces, once per root, that the guard is
// inactive here. Called with g_store_rootlock_mu held. Not a refusal: a
// filesystem that cannot honor advisory locks (some network mounts) would
// otherwise be unopenable, which is a worse outcome than the unguarded open it
// already had. Silent, though, it would be a security control failing open
// without saying so.
fn store_root_lock_unsupported(path string, why string) {
	mut reg := store_rootlock_reg()
	if path in reg.announced {
		return
	}
	reg.announced[path] = true
	eprintln('cx: note: the cross-process writable-open guard is INACTIVE for ${path} (${why}) — ' +
		'this substrate cannot honor advisory locks, so a second writer on this root is unguarded (#1005)')
}

// store_root_lock takes the guard. Returns the refusal node, or none on
// success (lock taken, or refcounted because this process already holds it).
fn store_root_lock(backend string, root string, url string) ?cx.Node {
	path := store_root_lock_path(backend, root)
	mut mu := unsafe { g_store_rootlock_mu }
	mu.@lock()
	defer {
		mu.unlock()
	}
	mut reg := store_rootlock_reg()
	if existing := reg.held[path] {
		mut e := unsafe { existing }
		e.count++
		return none
	}
	// The writable open arms create their root only AFTER this point, so the
	// sentinel's directory has to exist here.
	dir := if backend in ['file', 'cxobj', 'cxpack'] { root } else { os.dir(root) }
	if dir != '' && dir != '.' {
		os.mkdir_all(dir) or {
			return mk_err('cx-err:CXER1100',
				'E_STORE_UNRESOLVED_BACKEND: cannot create ${dir}: ${err.msg()}')
		}
	}
	// 'a+' = O_CREAT|O_APPEND|O_RDWR: creates when absent, and NEVER truncates
	// — merely opening the sentinel must not erase a live holder's record.
	mut f := os.open_file(path, 'a+', 0o644) or {
		store_root_lock_unsupported(path, 'cannot open the lock sentinel: ${err.msg()}')
		return none
	}
	if C.flock(f.fd, C.LOCK_EX | C.LOCK_NB) != 0 {
		en := C.errno
		holder := store_root_lock_holder(path)
		f.close()
		if en == C.EWOULDBLOCK || en == C.EAGAIN {
			return mk_err(store_err_open_conflict, store_root_lock_refusal(root, url, holder))
		}
		store_root_lock_unsupported(path, 'flock errno=${en}')
		return none
	}
	// Ours. Re-stamp the record so any later refusal names the CURRENT holder
	// and not whoever last crashed here.
	C.ftruncate(f.fd, 0)
	host := os.hostname() or { '?' }
	f.write_string('cxstore-lock v1 pid=${os.getpid()} host=${host} url=${url} since=${time.utc().format_rfc3339()}\n') or {}
	f.flush()
	reg.held[path] = &RootLock{
		f:     f
		count: 1
	}
	return none
}

// store_root_lock_take is the call-site form: takes the guard for a writable
// open and hands back the key to record on the MemStore (`lock_key`), released
// at close. READ-ONLY opens are EXEMPT — they never write, so N of them
// alongside the one writer IS the supported shape; and an empty root means
// there is no local filesystem identity to lock (mem://, columnar-over-s3).
fn store_root_lock_take(backend string, root string, read_only bool, url string) (string, cx.Node, bool) {
	if read_only || root == '' {
		return '', store_null(), true
	}
	if e := store_root_lock(backend, root, url) {
		return '', e, false
	}
	return store_root_lock_path(backend, root), store_null(), true
}

// store_root_unlock releases the guard for one key: the in-process refcount
// drops, and the last holder unlocks and closes the descriptor. Called from
// store-close when the last handle on a store goes, and from every open-time
// error path AFTER the lock was taken — a failed open must not leave the root
// locked for the life of the process.
fn store_root_unlock(key string) {
	if key == '' {
		return
	}
	mut mu := unsafe { g_store_rootlock_mu }
	mu.@lock()
	defer {
		mu.unlock()
	}
	mut reg := store_rootlock_reg()
	rl := reg.held[key] or { return }
	mut l := unsafe { rl }
	l.count--
	if l.count > 0 {
		return
	}
	C.flock(l.f.fd, C.LOCK_UN)
	l.f.close()
	reg.held.delete(key)
}

// ── #628 reentrant op-lock (shared-store serialization) ─────────────────
//
// One mutex per MemStore, acquired through owner-tid + depth bookkeeping so
// a verb's dispatch guard, the jrn/group-commit flush scope, and the
// mutation/read funnels NEST instead of self-deadlocking. Blocking: a
// shared store has two legitimate owners (e.g. an embedded publisher and a
// source pump on one root), so contention waits — the single-owner
// try-lock refusal in store_stdlib_builtin is unchanged for unshared
// handles.

fn store_lock_enter(mut ms MemStore) {
	if ms.op_lock == unsafe { nil } {
		return
	}
	tid := cap_thread_id()
	if ms.lock_owner == tid && ms.lock_depth > 0 {
		ms.lock_depth++
		return
	}
	mut lk := ms.op_lock
	lk.@lock()
	ms.lock_owner = tid
	ms.lock_depth = 1
}

// store_try_enter is the non-blocking twin (the #74 single-owner guard):
// false = another thread holds the lock.
fn store_try_enter(mut ms MemStore) bool {
	if ms.op_lock == unsafe { nil } {
		return true
	}
	tid := cap_thread_id()
	if ms.lock_owner == tid && ms.lock_depth > 0 {
		ms.lock_depth++
		return true
	}
	if !ms.op_lock.try_lock() {
		return false
	}
	ms.lock_owner = tid
	ms.lock_depth = 1
	return true
}

fn store_lock_exit(mut ms MemStore) {
	if ms.op_lock == unsafe { nil } {
		return
	}
	if ms.lock_depth > 1 {
		ms.lock_depth--
		return
	}
	ms.lock_depth = 0
	ms.lock_owner = 0
	mut lk := ms.op_lock
	lk.unlock()
}

// store_swap_read_view exchanges the complete READ view (docs + refs +
// object layers + erasure + feed lineage) between two MemStore instances —
// stream 7 (F1, #714 item 1): a read-only local handle is a PRIVATE SNAPSHOT
// view (store_open_shared_or_conflict), so freshness is re-TAKEN, never
// merged: the caller opens a scratch read-only handle at the same URL
// (through the normal capability-gated open path), swaps views, and closes
// the scratch — which walks away with the OLD view and releases it through
// the ordinary close path. Both directions swap so no resource is orphaned.
// The flush/watermark bookkeeping is NOT swapped: a read-only handle never
// flushes, and the scratch is closed immediately. feed lineage swaps WITH
// the view (a cursor bound to the old boot token refuses loudly — CXER5020
// — never silently serves a divergent view).
fn store_swap_read_view(mut a MemStore, mut b MemStore) {
	mut tm_docs := a.docs.move()
	a.docs = b.docs.move()
	b.docs = tm_docs.move()
	tm_doc_order := a.doc_order
	a.doc_order = b.doc_order
	b.doc_order = tm_doc_order
	mut tm_blob := a.blob_kind.move()
	a.blob_kind = b.blob_kind.move()
	b.blob_kind = tm_blob.move()
	mut tm_aliases := a.aliases.move()
	a.aliases = b.aliases.move()
	b.aliases = tm_aliases.move()
	tm_alias_order := a.alias_order
	a.alias_order = b.alias_order
	b.alias_order = tm_alias_order
	tm_sink := a.obj_sink
	a.obj_sink = b.obj_sink
	b.obj_sink = tm_sink
	mut tm_roots := a.obj_roots.move()
	a.obj_roots = b.obj_roots.move()
	b.obj_roots = tm_roots.move()
	mut tm_cache := a.obj_cache.move()
	a.obj_cache = b.obj_cache.move()
	b.obj_cache = tm_cache.move()
	tm_pack := a.obj_pack
	a.obj_pack = b.obj_pack
	b.obj_pack = tm_pack
	tm_backend := a.obj_backend
	a.obj_backend = b.obj_backend
	b.obj_backend = tm_backend
	mut tm_erased := a.erased.move()
	a.erased = b.erased.move()
	b.erased = tm_erased.move()
	tm_erased_order := a.erased_order
	a.erased_order = b.erased_order
	b.erased_order = tm_erased_order
	mut tm_erased_roots := a.erased_roots.move()
	a.erased_roots = b.erased_roots.move()
	b.erased_roots = tm_erased_roots.move()
	tm_erased_dirty := a.erased_dirty
	a.erased_dirty = b.erased_dirty
	b.erased_dirty = tm_erased_dirty
	mut tm_erased_man := a.erased_manifested.move()
	a.erased_manifested = b.erased_manifested.move()
	b.erased_manifested = tm_erased_man.move()
	tm_advances := a.advances
	a.advances = b.advances
	b.advances = tm_advances
	mut tm_adv_pos := a.adv_pos.move()
	a.adv_pos = b.adv_pos.move()
	b.adv_pos = tm_adv_pos.move()
	// FL-1: the retention floors travel with the read view; the sidecar
	// bookkeeping (lineage_path/active/records) stays with each handle's
	// own writability.
	mut tm_adv_floor := a.adv_floor.move()
	a.adv_floor = b.adv_floor.move()
	b.adv_floor = tm_adv_floor.move()
	tm_boot := a.feed_boot
	a.feed_boot = b.feed_boot
	b.feed_boot = tm_boot
	tm_logrec := a.log_records
	a.log_records = b.log_records
	b.log_records = tm_logrec
	tm_lazy := a.lazy_objects
	a.lazy_objects = b.lazy_objects
	b.lazy_objects = tm_lazy
}

const store_err_open_conflict = 'cx-err:CXER1143' // E_STORE_OPEN_CONFLICT

// store_open_shared_or_conflict implements #628 same-root sharing for a
// WRITABLE local-filesystem open: a root already open writable in-process
// returns a second handle over the SAME live MemStore (two independent
// writers on one root collide on segment numbering — the second flush
// clobbers the first's segment file — so a shared live view is the only
// sound multi-handle shape; ruling (a)). A live root whose at-rest options
// differ refuses loudly. Returns none to proceed with a fresh MemStore
// (first open, or read-only opens — which keep snapshot semantics: they
// never write, so a private view is safe and cheaper).
fn store_open_shared_or_conflict(backend string, root string, read_only bool, fp string) ?cx.Node {
	if read_only {
		return none
	}
	if live := store_find_shared(backend, root, fp) {
		id := store_register(live)
		return store_handle_element(id, live)
	}
	if store_share_conflict(backend, root, fp) {
		return mk_err(store_err_open_conflict,
			'E_STORE_OPEN_CONFLICT: ${root} is already open WRITABLE in-process with different at-rest options — close it first or match the open options')
	}
	return none
}

// ── value helpers ────────────────────────────────────────────────────

fn store_str(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	}
}

fn store_bool(b bool) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bool_type
	}
}

fn store_int(i i64) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(i)
		data_type: cx.ScalarType.int_type
	}
}

fn store_null() cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(cx.NullValue{})
		data_type: cx.ScalarType.null_type
	}
}

// store_empty is the absence channel: the empty node-set / empty sequence
// (`code.md` §9.1.2). An alias that does not resolve is "nothing here" — a
// pure, in-memory, optional structural lookup found nothing — absence, NOT a
// `null` value (the §9.1.2.1 no-conflation guard). The caller extracts the
// hash with `[?else]` (getOrElse). SAP C1. (Side-effect unit-null returns —
// set-alias / close — are successful no-payload returns, §9.1.2.1 rule 2b, and
// KEEP `store_null`.)
fn store_empty() cx.Node {
	return cx.Element{
		name:  '__cx_seq__'
		items: []
	}
}

fn store_seq(items []cx.Node) cx.Node {
	return cx.Element{
		name:  code.seq_marker_name
		items: items
	}
}

fn store_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return none
}

// store_addr_shape_err validates a doc/blob KEY argument at the verb
// boundary (store.md §11: the primary key is the self-describing tagged
// address; I1 stream 19 L32, #691 §10). Bare hex (CXER0130), an unknown
// algorithm (CXER0131), and a malformed digest (CXER0132) are typed
// refusals — never routed to the not-found channel, which would make a
// mistyped address indistinguishable from an absent document.
fn store_addr_shape_err(key string) ?cx.Node {
	cx.cx_parse_tagged_address(key) or {
		msg := err.msg()
		ecode := if msg.contains('CXER0131') {
			'cx-err:CXER0131'
		} else if msg.contains('CXER0132') {
			'cx-err:CXER0132'
		} else {
			'cx-err:CXER0130'
		}
		return mk_err(ecode, 'E_STORE_ADDRESS_INVALID: ${msg}')
	}
	return none
}

// store_handle_of reads the integer Store handle off a `[store handle=N …]`
// element returned by open / open-opts.
fn store_handle_of(n cx.Node) ?int {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'handle' {
				return cx.scalar_value_str_public(a.value).int()
			}
		}
	}
	return none
}

// StoreStats is the live backend-introspection surface the service tier's metrics
// plane scrapes (the #105 §7 storage-seam metrics hook). Phase 2 populates it
// from the embedded backend; a Phase-3 backend (S3 / network metadata service)
// provides its own via the same shape. Only truthfully-tracked counters appear —
// series the backend does not yet instrument (dedup ratio, ref-log length,
// compaction events) are ABSENT by design (no fabricated zeros; spec Appendix F.1).
pub struct StoreStats {
pub:
	backend   string // the mount's backend kind (mem/file/cxpack/…)
	doc_count int    // unique content hashes currently held (master-index size)
	// #129-D object-graph introspection — populated ONLY for the content-addressed
	// backend (cxpack). has_object_graph gates the object/dedup series so the flat
	// backends (mem/file/sqlite), which have no object graph, emit no fabricated
	// zeros (Appendix F.1). object_count is the distinct content-addressed objects
	// physically held; logical_objects is what the live docs WOULD occupy with no
	// subtree sharing, and distinct_objects the unique objects they actually
	// resolve to — logical/distinct is the dedup ratio.
	has_object_graph bool
	object_count     int
	logical_objects  i64
	distinct_objects int
}

// store_mount_stats returns live stats for a LOCAL store handle. Returns none for
// a remote-backed mount (s3/http/cx-store): the doc count is not known locally
// and a per-scrape network round-trip would be wrong — callers omit the series
// rather than fabricate it. The read is taken under the store's op-lock so it is
// consistent against a concurrent mutation.
pub fn store_mount_stats(handle cx.Node) ?StoreStats {
	id := store_handle_of(handle)?
	mut ms := store_lookup(id)?
	if ms.remote != unsafe { nil } {
		return none
	}
	// #628: owner-tracked reentrant acquisition (a raw @lock() self-deadlocks
	// against the mutation/read funnels on the same thread).
	store_lock_enter(mut ms)
	defer {
		store_lock_exit(mut ms)
	}
	// doc_order is the unique-doc list for BOTH the docs-map backends and the
	// object-graph backend (where docs is empty), so it is the correct count.
	count := ms.doc_order.len
	mut stats := StoreStats{
		backend:   ms.backend
		doc_count: count
	}
	if store_objgraph_active(ms) {
		stats = store_objgraph_stats(mut ms, count)
	}
	return stats
}

// store_objgraph_stats builds the object-graph introspection for a cxpack mount,
// reusing the cached dedup walk when the (doc_count, object_count) fingerprint is
// unchanged since the last computation. Caller holds the op-lock.
fn store_objgraph_stats(mut ms MemStore, doc_count int) StoreStats {
	// Distinct-object count: the durable backend's when there is one (the lazy disk
	// backends do not slurp every object into the sink), else the in-memory sink.
	// RULED: UOM-1 — the pack backend carries its durable substrate in obj_pack
	// (not obj_backend); counting the live sink there under-reported the
	// physically-held objects (durable + staged) relative to every other
	// object substrate for the same docs — a substrate-consistency defect
	// (mem/opk answered 28 where pack answered a sink remnant). The durable
	// count is the documented meaning of object_count ("distinct
	// content-addressed objects physically held").
	object_count := if be := ms.obj_backend {
		be.object_count()
	} else if ms.obj_pack != unsafe { nil } {
		ms.obj_pack.object_count()
	} else {
		ms.obj_sink.objects.len
	}
	if ms.graph_stats_docs != doc_count || ms.graph_stats_objects != object_count {
		// fingerprint moved → recompute the dedup walk over the live doc roots.
		mut roots := [][]u8{cap: ms.obj_roots.len}
		for _, r in ms.obj_roots {
			roots << r
		}
		getter := store_graph_getter(ms)
		logical, distinct := cxstore.object_graph_stats(getter, roots)
		ms.graph_logical = logical
		ms.graph_distinct = distinct
		ms.graph_stats_docs = doc_count
		ms.graph_stats_objects = object_count
	}
	return StoreStats{
		backend:          ms.backend
		doc_count:        doc_count
		has_object_graph: true
		object_count:     object_count
		logical_objects:  ms.graph_logical
		distinct_objects: ms.graph_distinct
	}
}

const store_closed_msg = 'E_STORE_CLOSED: operation on a closed Store'

// store_err_handle_race — concurrent access to one shared Store handle (#74
// Defect 2). A Store is single-owner; `[par]` over a shared handle is
// unsupported. Mirrors net's handle-race contract: shard (use separate
// handles per worker) for parallelism.
const store_err_handle_race = 'cx-err:CXER1140' // E_STORE_HANDLE_RACE

// store_for_guard resolves a Store argument to its live MemStore for the
// concurrency guard, WITHOUT the open/closed check (the inner op produces the
// precise CXER for an invalid/closed handle). Returns none when the arg is not
// a resolvable Store handle, so the wrapper falls through to the inner op.
fn store_for_guard(arg cx.Node) ?&MemStore {
	id := store_handle_of(arg)?
	return store_lookup(id)
}

// store_get_open resolves a Store argument to its live MemStore. On
// success returns `(store, _, true)`. On failure returns
// `(_, err_node, false)` where err_node is the spec error: CXER0100 for
// an invalid handle, CXER1130 for a closed Store.
fn store_get_open(arg cx.Node) (&MemStore, cx.Node, bool) {
	id := store_handle_of(arg) or {
		return unsafe { nil }, mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: expected a Store element'), false
	}
	if store_id_closed(id) {
		return unsafe { nil }, mk_err('cx-err:CXER1130', store_closed_msg), false
	}
	ms := store_lookup(id) or {
		return unsafe { nil }, mk_err('cx-err:CXER0100',
			'E_OPERAND_KIND: unknown Store handle ${id}'), false
	}
	if !ms.is_open {
		return unsafe { nil }, mk_err('cx-err:CXER1130', store_closed_msg), false
	}
	return ms, store_null(), true
}

// store_doc_hash computes the content identity of a doc node: SHA-256 of
// its strict canonical bytes (lowercase hex), via the Layer-1 text hash.
fn store_doc_hash(doc cx.Node) !string {
	return cx.cx_text_hash(render_canonical(doc))!
}

fn store_url_scheme(url string) string {
	if idx := url.index('://') {
		return url[..idx]
	}
	if ci := url.index(':') {
		return url[..ci]
	}
	return ''
}

// store_file_detect sniffs an existing `file` store's on-disk form for
// self-describing reopen (#129 PR-G / spec §3): the marker present at the root
// identifies the (model, framing) the store was created with, so a bare `file://`
// reopen of a legacy flat store re-opens AS document rather than overlaying a new
// subtree store. Returns ('', '') for a new/empty path (the caller then uses the
// URI's requested model + framing). Checked subtree-first since a subtree store
// never writes the flat `.cxstore-index`.
fn store_file_detect(root string) (string, string) {
	if os.exists(os.join_path(root, cxpack_manifest)) {
		return 'subtree', 'pack'
	}
	if os.exists(os.join_path(root, cxobj_manifest)) {
		return 'subtree', 'object-per-key'
	}
	if os.exists(os.join_path(root, store_index_name)) {
		return 'document', 'flat'
	}
	return '', ''
}

// ── open ─────────────────────────────────────────────────────────────

// store_normalize_uri splits a canonical-URI form into its base URL, query
// parameters, and `model` prefix. The grammar is `[document+|subtree+]<scheme>://
// <loc>[?k=v&…]` (memory project_cxstore_url_and_surface_design). It is additive:
// a URL with neither a `model+` prefix nor a `?query` returns `(url, {}, '')`
// unchanged, so existing backends are unaffected. Subtree is the default and
// elided; `document+` is required to name the document model in the URI.
fn store_normalize_uri(url string) (string, map[string]string, string) {
	mut base := url
	mut model := ''
	if base.starts_with('document+') {
		model = 'document'
		base = base['document+'.len..]
	} else if base.starts_with('subtree+') {
		model = 'subtree'
		base = base['subtree+'.len..]
	}
	mut qparams := map[string]string{}
	if qi := base.index('?') {
		query := base[qi + 1..]
		base = base[..qi]
		for pair in query.split('&') {
			if pair == '' {
				continue
			}
			if eq := pair.index('=') {
				qparams[pair[..eq]] = pair[eq + 1..]
			} else {
				qparams[pair] = ''
			}
		}
	}
	return base, qparams, model
}

// store_open_columnar dispatches the columnar (Parquet / Arrow-IPC) encoding
// (#129 D5 / #76; spec/03-approved/misc/cxstore_columnar_backend.md). Columnar is a
// GATED substrate (`-d cxstore_columnar`, libcx_arrow + libparquet via the
// `arrow` module): without the flag it errors honestly. The capability gate is
// applied FIRST (deny-by-default) so an ungranted caller learns nothing about
// whether the Arrow build is present (§7.1).
fn store_open_columnar(base_url string, compression string, encoding string, read_only bool, model_prefix string, auth map[string]string, qparams map[string]string) cx.Node {
	scheme := store_url_scheme(base_url)
	// §2: columnar is inherently the document model — `document+` is REQUIRED.
	// A bare (subtree-default) `…?encoding=parquet` is a hard error: subtree +
	// columnar are incompatible (there is no object graph to share).
	if model_prefix == 'subtree' || (model_prefix == '' && auth['model'] != 'document') {
		return mk_err('cx-err:CXER1100',
			'E_STORE_UNRESOLVED_BACKEND: columnar encoding requires the document model — use `document+${base_url}?encoding=${encoding}` (subtree + columnar are incompatible) in ${base_url}')
	}
	codec := if compression != '' {
		compression
	} else {
		qparams['compression']
	}
	// Capability gate first (deny-by-default; §7.1). file ⇒ read/write; s3 ⇒ net.
	cap := match scheme {
		's3' {
			'net'
		}
		else {
			if read_only { 'read' } else { 'write' }
		}
	}

	if d := cap_guard(cap, 'store open ${base_url}') {
		return d
	}
	// G3-Q3=a: a declared `?schema=<path>` (or [opts schema=]) pins + validates the
	// table. Resolve + read it here (the open already holds the capability); the
	// schema TEXT is threaded into the backend and checked on every put.
	mut schema_text := ''
	schema_ref := if qparams['schema'] != '' { qparams['schema'] } else { auth['schema'] }
	if schema_ref != '' {
		p := if schema_ref.starts_with('file://') {
			store_path_from_url(schema_ref)
		} else {
			schema_ref
		}
		// #206.1: reading the local ?schema= file is a filesystem effect distinct
		// from the substrate's own gate (an s3 columnar store gated only `net` would
		// otherwise read a local file with no `read` grant). Gate it explicitly.
		if d := cap_guard('read', 'store open ?schema=${p}') {
			return d
		}
		schema_text = os.read_file(p) or {
			return mk_err('cx-err:CXER1100',
				'E_STORE_UNRESOLVED_BACKEND: cannot read ?schema= file ${p}: ${err.msg()}')
		}
	}
	$if cxstore_columnar ? {
		match scheme {
			'file' {
				path := store_path_from_url(base_url)
				if path == '' {
					return mk_err('cx-err:CXER1100',
						'E_STORE_UNRESOLVED_BACKEND: malformed file URL ${base_url}')
				}
				return store_columnar_open(base_url, path, encoding, codec, read_only, schema_text)
			}
			's3' {
				return store_columnar_open_s3(base_url, encoding, codec, read_only, auth,
					schema_text)
			}
			else {
				return mk_err('cx-err:CXER1100',
					'E_STORE_UNRESOLVED_BACKEND: columnar encoding is supported on file:// and s3:// (got ${scheme}://) in ${base_url}')
			}
		}
	}
	return mk_err('cx-err:CXER1100',
		'E_STORE_UNRESOLVED_BACKEND: columnar encoding requires the Arrow build — rebuild with `-d cxstore_columnar -d cx_arrow_files` (+ `make build-lib-arrow`) for ${base_url}')
}

// store_columnar_schema_violation validates a doc against a columnar store's
// declared `?schema=` (G3-Q3=a) and returns an err value (CXER1115) when the doc
// does not conform — pinning the table's shape by REJECTING non-conformers at put
// time. Returns none when no schema is declared (inference mode) or the doc
// conforms. Reuses the cx-stdlib/validate engine (cx.validate). Backend-agnostic
// guard cheap: callers gate on ms.columnar_schema != '' before building the doc.
fn store_columnar_schema_violation(ms &MemStore, doc cx.Document) ?cx.Node {
	rep := cx.validate(doc, ms.columnar_schema, cx.ValidateOptions{}) or {
		return mk_err('cx-err:CXER1115',
			'E_STORE_SCHEMA_VIOLATION: schema load/validate error: ${err.msg()}')
	}
	if !rep.is_valid() {
		mut msgs := []string{}
		for d in rep.diagnostics {
			if d.severity == .error_severity {
				msgs << '${d.code}: ${d.message}'
			}
		}
		return mk_err('cx-err:CXER1115',
			'E_STORE_SCHEMA_VIOLATION: doc does not conform to the store\'s declared ?schema=: ${msgs.join('; ')}')
	}
	return none
}

// store_encrypt_unsupported_err is the #184 fail-closed error for an encryption
// request on a substrate that cannot seal at rest — a hard CXER1100-class error
// directing to a sealing substrate, never a silent plaintext write.
fn store_encrypt_unsupported_err(scheme string, base_url string) cx.Node {
	return mk_err('cx-err:CXER1100',
		'E_STORE_UNRESOLVED_BACKEND: encryption-at-rest (encrypt-key-id) is supported on the sealing substrates — `file://…` (pack, the default), `file://…?encoding=object-per-key`, `sqlite://…`, or `s3://…` (got ${scheme}); refusing to store plaintext for ${base_url}')
}

// store_reject_unbuilt_compression fail-closes an at-rest compression request on
// a substrate whose compression path is not built (#205.2 / store.md §6.1,§10.2):
// a non-`none` value is a hard CXER1100-class error, never accepted-and-ignored.
// The columnar substrate (its own zstd path via Arrow) is handled separately and
// never reaches here. `''` (unset → the `none` default) passes.
fn store_reject_unbuilt_compression(compression string, url string) ?cx.Node {
	if compression != '' && compression != 'none' {
		return mk_err('cx-err:CXER1100',
			'E_STORE_UNRESOLVED_BACKEND: compression `${compression}` requested but the at-rest compression path is not built — only `none` is supported (store.md §6.1/§10.2); refusing to store uncompressed while claiming `${compression}` for ${url}')
	}
	return none
}

// g_store_open_lock serializes store OPENS process-wide (#628): the same-root
// sharing dedupe (store_find_shared) and the subsequent construct+register are
// otherwise not atomic — two threads opening one root concurrently would both
// miss the scan and build private stores, reintroducing the segment-collision
// data loss the sharing exists to prevent. Opens are rare (per mount/boot,
// never per op), so one process-wide open at a time costs nothing; per-op
// lookups take only the registry lock and never wait on an open.
const g_store_open_lock = &sync.Mutex(sync.new_mutex())

fn store_open_impl(url string, compression string, encoding string, read_only bool, tls_verify bool, auth map[string]string) cx.Node {
	mut opl := unsafe { g_store_open_lock }
	opl.@lock()
	defer {
		opl.unlock()
	}
	// #129 D5 (columnar): canonical-URI routing for the columnar encoding. Parse a
	// `document+` model prefix and `?encoding=/?compression=/?schema=` query so the
	// G3-locked surface `document+file://…?encoding=parquet` resolves. This is
	// ADDITIVE — URLs without a `document+` prefix or `?query` are byte-identical to
	// before, so every other backend keeps its `[opts]` surface untouched (the full
	// canonical-URI scheme rename for those is the later PR-F graduation). Columnar
	// is the only backend that needs this surface today.
	base_url, qparams, model_prefix := store_normalize_uri(url)
	// #205.5: `subtree+` is NEVER written — subtree is the elided default (spec §3,
	// "subtree+ is never written"). A stated `subtree+` prefix is a hard error
	// (cutover, no dual-accept), so the one canonical spelling is the bare scheme.
	if model_prefix == 'subtree' {
		return mk_err('cx-err:CXER1100',
			'E_STORE_UNRESOLVED_BACKEND: `subtree+` is never written — subtree is the default; use the bare scheme (store.md §3) for ${url}')
	}
	// #205.4: reject query parameters that are accepted-but-unimplemented rather
	// than silently ignoring them (a caller who wrote `?cache=…`/`?wire=…` must not
	// believe it took effect). Only encoding/compression/schema are consulted.
	for k, _ in qparams {
		if k !in ['encoding', 'compression', 'schema'] {
			return mk_err('cx-err:CXER1100',
				'E_STORE_UNRESOLVED_BACKEND: unsupported URI query parameter `${k}` (recognized: encoding, compression, schema) in ${url}')
		}
	}
	mut col_encoding := encoding
	if col_encoding == '' {
		col_encoding = qparams['encoding']
	}
	if col_encoding == 'parquet' || col_encoding == 'arrow-ipc' {
		return store_open_columnar(base_url, compression, col_encoding, read_only, model_prefix,
			auth, qparams)
	}
	// Canonical-URI routing (#129 PR-G): the scheme is read off the model-stripped
	// base_url, so `document+<substrate>://` resolves to its substrate. `document+`
	// (or the legacy `[opts model=document]`) selects the degenerate document model;
	// subtree is the default. `?encoding=` (or the `encoding` opt) names the at-rest
	// framing within a substrate.
	doc_model := model_prefix == 'document' || auth['model'] == 'document'
	framing := if col_encoding != '' { col_encoding } else { qparams['encoding'] }
	scheme := store_url_scheme(base_url)
	// #184/#229 encryption-at-rest fail-closed: encrypt-key-id is honored on the
	// local subtree substrates — object-per-key (EncryptingObjectBackend seals
	// each object file, #114) and pack (EncryptingWrapper seals AEAD envelopes
	// into v2 keyed packs, #229). The sqlite/s3 keyed slices land next (#229);
	// mem:// has no at-rest bytes at all and the document model has no object
	// graph to seal. Silently dropping the key and storing PLAINTEXT is the worst
	// failure for a security control (§9's fail-closed mandate), so an encryption
	// request on any substrate that cannot seal is a HARD error — never a silent
	// plaintext write. Schemes without a sealing path are rejected here; the
	// `file` arm rejects the document model after self-describing reopen resolves
	// the on-disk shape (so reopening an existing encrypted store via bare
	// `file://` still works), sqlite enforces its at-rest marker at attach, and
	// s3 enforces its marker key at load.
	if auth['encrypt-key-id'] != '' && scheme !in ['file', 'sqlite', 's3'] {
		return store_encrypt_unsupported_err('scheme=${scheme}', base_url)
	}
	match scheme {
		'mem' {
			comp := if compression == '' { 'none' } else { compression }
			enc := if encoding == '' { 'cxbin' } else { encoding }
			ms := &MemStore{
				url:         url
				backend:     'mem'
				encoding:    enc
				compression: comp
				read_only:   read_only
				is_open:     true
				op_lock:     sync.new_mutex()
				model:       if doc_model { 'document' } else { '' }
			}
			id := store_register(ms)
			return store_handle_element(id, ms)
		}
		'file' {
			// #129 PR-G: `file` is the local-filesystem substrate across BOTH models.
			// Bare `file://` is SUBTREE (the universal default, spec §2/§3);
			// `document+file://` is the degenerate document model (the legacy flat
			// index). `?encoding=` names the subtree at-rest framing — `pack`
			// (default) or `object-per-key`. The retired `cxpack://` / `cxobj://`
			// tokens are exactly `file://?encoding=pack` / `…=object-per-key`.
			// Filesystem effect → `read` (read-path) / `write` (write-path).
			cap := if read_only { 'read' } else { 'write' }
			if d := cap_guard(cap, 'store open ${url}') {
				return d
			}
			// #205.2: compression is a fail-closed normative requirement (store.md
			// §6.1/§10.2) — the at-rest compression path is not built, so a non-`none`
			// request is a hard error, NEVER accept-and-ignore (which would let a
			// caller believe data was compressed when it is stored raw). After the cap
			// gate so a denied open still reports CXER0271.
			if d := store_reject_unbuilt_compression(compression, url) {
				return d
			}
			root := store_path_from_url(base_url)
			if root == '' {
				return mk_err('cx-err:CXER1100',
					'E_STORE_UNRESOLVED_BACKEND: malformed file URL ${url}')
			}
			comp := if compression == '' { 'none' } else { compression }
			enc := if encoding == '' { 'cxbin' } else { encoding }
			// Self-describing reopen (spec §3): an existing store's on-disk marker
			// determines its model + framing; a stated value that contradicts it is a
			// hard error. A new/empty path uses the requested (URI) model + framing.
			mut want_doc := doc_model
			mut want_framing := framing
			det_model, det_framing := store_file_detect(root)
			if det_model != '' {
				if (model_prefix != '' || auth['model'] != '')
					&& want_doc != (det_model == 'document') {
					return mk_err('cx-err:CXER1120',
						'E_STORE_INTEGRITY_MISMATCH: stated model contradicts the on-disk store at ${root}')
				}
				if want_framing != '' && want_framing != 'cxbin' && det_framing != ''
					&& want_framing != det_framing {
					return mk_err('cx-err:CXER1120',
						'E_STORE_INTEGRITY_MISMATCH: stated encoding ${want_framing} contradicts on-disk ${det_framing} at ${root}')
				}
				want_doc = det_model == 'document'
				want_framing = det_framing
			}
			// #184/#229 fail-closed: both subtree framings (object-per-key #114,
			// pack #229) seal at rest; the DOCUMENT model (flat index — no object
			// graph) does not. Check the RESOLVED model (post self-describing
			// reopen) so a bare `file://` reopen of an existing encrypted store is
			// allowed, while a document file store with encrypt-key-id is a hard
			// error (never silent plaintext).
			if auth['encrypt-key-id'] != '' && want_doc {
				return store_encrypt_unsupported_err('the file document model', base_url)
			}
			if want_doc {
				if !read_only {
					// #292: sweep dead writers' orphaned snapshot temps before
					// touching the index (never the live index, never a live
					// pid's in-flight temp — see store_sweep_stale_tmp). Runs
					// BEFORE the shared-handle resolution: a same-root reopen
					// that lands on the live in-process MemStore (#628) is
					// still a writable open, and the sweep is filesystem
					// hygiene independent of handle sharing — after #628 the
					// old post-share call site was unreachable on exactly the
					// reopen path #292 exists for.
					store_sweep_stale_tmp(root)
				}
				// document model on `file` = the flat index store.
				if r := store_open_shared_or_conflict('file', root, read_only,
					'|document|${enc}|${comp}|')
				{
					return r
				}
				// #1005: no in-process share to join, so this is a FRESH writable
				// view of the root — the point where a second PROCESS has to be
				// refused. Before the load, so a conflicting open never even reads
				// a state the other writer is mutating.
				flk, flerr, flok := store_root_lock_take('file', root, read_only, url)
				if !flok {
					return flerr
				}
				mut ms := &MemStore{
					url:         url
					backend:     'file'
					root:        root
					encoding:    enc
					compression: comp
					read_only:   read_only
					is_open:     true
					model:       'document'
					op_lock:     sync.new_mutex()
					lock_key:    flk
				}
				idx := os.join_path(root, store_index_name)
				if os.exists(idx) {
					store_read_index(idx, mut ms) or {
						store_root_unlock(flk)
						return mk_err('cx-err:CXER1120', err.msg())
					}
				} else if !read_only {
					os.mkdir_all(root) or {
						store_root_unlock(flk)
						return mk_err('cx-err:CXER1100',
							'E_STORE_UNRESOLVED_BACKEND: cannot create ${root}: ${err.msg()}')
					}
				}
				id := store_register(ms)
				return store_handle_element(id, ms)
			}
			// subtree model — object-per-key on request, pack by default.
			if want_framing == 'object-per-key' {
				if r := store_open_shared_or_conflict('cxobj', root, read_only,
					'${auth['encrypt-key-id']}||${enc}|${comp}|')
				{
					return r
				}
				// #1005 cross-process guard, as for the flat index arm.
				olk, olerr, olok := store_root_lock_take('cxobj', root, read_only, url)
				if !olok {
					return olerr
				}
				mut ms := &MemStore{
					url:         url
					backend:     'cxobj'
					root:        root
					encoding:    enc
					compression: comp
					read_only:   read_only
					is_open:     true
					op_lock:     sync.new_mutex()
					enc_key_id:  auth['encrypt-key-id']
					lock_key:    olk
				}
				if !read_only {
					os.mkdir_all(root) or {
						store_root_unlock(olk)
						return mk_err('cx-err:CXER1100',
							'E_STORE_UNRESOLVED_BACKEND: cannot create ${root}: ${err.msg()}')
					}
				}
				store_cxobj_load(mut ms) or {
					store_root_unlock(olk)
					return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
				}
				id := store_register(ms)
				return store_handle_element(id, ms)
			}
			// obj_pack attaches lazily in store_cxpack_load (store_cxpack_backend
			// picks keyed vs plain mode from enc_key_id, #229).
			if r := store_open_shared_or_conflict('cxpack', root, read_only,
				'${auth['encrypt-key-id']}||${enc}|${comp}|')
			{
				return r
			}
			// #779-class (stream 20 W2): a FRESH instance over this root must
			// not race an orphaned fold worker from a prior (closed) instance
			// — its segment renames/removals would interleave with this open's
			// discovery/load under a different lock identity. Shared opens
			// (above) never wait: their worker is legitimately theirs.
			// #1005 cross-process guard. THIS is the arm #993 measured dying:
			// two writing processes on one pack root collide on segment
			// numbering, the loser's segment file is clobbered, and the hole in
			// the sequence surfaces only at the NEXT open as CXER1120. Taken
			// before the quiesce and the load, so a refused open touches nothing.
			plk, plerr, plok := store_root_lock_take('cxpack', root, read_only,
				url)
			if !plok {
				return plerr
			}
			store_fold_quiesce_root(root)
			mut ms := &MemStore{
				url:         url
				backend:     'cxpack'
				root:        root
				encoding:    enc
				compression: comp
				read_only:   read_only
				is_open:     true
				op_lock:     sync.new_mutex()
				enc_key_id:  auth['encrypt-key-id']
				// #637: demand-paged object resolution is the DEFAULT — open
				// costs O(refs) and RSS tracks the working set. `[opts
				// eager="true"]` restores the whole-graph slurp + load-time
				// reconstruction for a caller that wants that check inline
				// (the same check the explicit `verify` op runs on demand).
				lazy_objects: auth['eager'] != 'true'
				lock_key:     plk
			}
			if !read_only {
				os.mkdir_all(root) or {
					store_root_unlock(plk)
					return mk_err('cx-err:CXER1100',
						'E_STORE_UNRESOLVED_BACKEND: cannot create ${root}: ${err.msg()}')
				}
			}
			store_cxpack_load(mut ms) or {
				store_root_unlock(plk)
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
			}
			id := store_register(ms)
			return store_handle_element(id, ms)
		}
		'sqlite' {
			// §9 + #77: sqlite:// external engine. Feature-gated via
			// `-d cxstore_sqlite` so the default/core/wasm build never links
			// libsqlite3; without the flag, error clearly (degrade-with-visibility).
			mut r := mk_err('cx-err:CXER1100',
				'E_STORE_UNRESOLVED_BACKEND: sqlite backend not built — rebuild with `-d cxstore_sqlite` (${url})')
			$if cxstore_sqlite ? {
				r = store_sqlite_open(base_url, compression, encoding, read_only, if doc_model {
					'document'
				} else {
					''
				}, auth['encrypt-key-id'])
			}
			return r
		}
		's3' {
			// §7.3: s3 is a SUBTREE object substrate (s3 × subtree × object-per-key),
			// NOT a document byte-source. Network I/O → `net` (deny-by-default first).
			// Unlike the document remotes below it does NOT set ms.remote: objects route
			// through the universal seam (obj_backend = S3ObjectBackend) and the live
			// object graph, so store_objgraph_active(s3) wins and the same doc yields the
			// same object hashes as every other substrate (cross-tier identity, §4.3).
			if d := cap_guard('net', 'store open ${url}') {
				return d
			}
			mut rb, errn, ok := store_remote_parse(base_url)
			if !ok {
				return errn
			}
			rb.tls_verify = tls_verify
			// #229: with encrypt-key-id, the durable backend is an EncryptingWrapper
			// over the S3 backend's KeyedObjectBackend seam (objects at rest = AEAD
			// envelopes keyed by plaintext hash; graph/dedup unchanged). KEK resolves
			// fail-closed here; store_s3_load enforces the at-rest marker.
			s3be := new_s3_object_backend(rb)
			mut s3ob := cxstore.ObjectBackend(s3be)
			if auth['encrypt-key-id'] != '' {
				kms := store_kek_kms(auth['encrypt-key-id'], '') or {
					return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
				}
				s3ob = cxstore.ObjectBackend(cxstore.new_encrypting_wrapper(s3be,
					auth['encrypt-key-id'], kms))
			}
			mut ms := &MemStore{
				url:         url
				backend:     's3'
				encoding:    if encoding == '' { 'cxbin' } else { encoding }
				compression: if compression == '' { 'none' } else { compression }
				read_only:   read_only
				is_open:     true
				op_lock:     sync.new_mutex()
				model:       if doc_model { 'document' } else { '' }
				enc_key_id:  auth['encrypt-key-id']
				obj_backend: s3ob
			}
			store_s3_load(mut ms) or {
				// #213: an auth-rejected / transport-failed manifest read is a
				// credentials/connectivity problem, never integrity corruption and
				// never a silently-empty store.
				msg := err.msg()
				if msg.contains('auth rejected') {
					return mk_err('cx-err:CXER1131', 'E_STORE_AUTH_FAILED: ${msg}')
				}
				if msg.contains('transport failure') {
					return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: ${msg}')
				}
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${msg}')
			}
			id := store_register(ms)
			return store_handle_element(id, ms)
		}
		'http', 'https', 'ftp', 'ftps', 'sftp', 'cx-store', 'cx-store+xsp', 'cx-store+http',
		'cx-store+https', 'cx-store+grpc', 'cx-store+grpcs' {
			// NOTE: the retired cx-store+http(s) tokens stay in this NET-GATE list
			// deliberately — the capability refusal (CXER0271) must come FIRST;
			// granted callers then hit the retirement refusal in store_remote_parse.

			// §9: remote / URL-dispatched byte-source backend performs network
			// I/O → requires `net`. Deny-by-default: the `net` capability gate is
			// the FIRST thing (security.md §2), BEFORE any backend-status check —
			// an ungranted caller gets CXER0271 and learns nothing about whether
			// sftp is built or ftps is enabled. Ops route over the transport per
			// key (#91); the docs map stays empty (never load the whole store).
			if d := cap_guard('net', 'store open ${url}') {
				return d
			}
			// sftp:// additionally requires the `-d cx_sftp` build (libssh2, #106);
			// the default build links no SSH lib and fails honestly (after the gate).
			if scheme == 'sftp' {
				$if cx_sftp ? {
					// allowed — fall through to the shared remote-open below
				} $else {
					return store_sftp_unbuilt()
				}
			}
			// ftps:// is EXPERIMENTAL/unverified end-to-end (#107): the FTPS data
			// path works against some servers but is not yet a verified round
			// trip, and a mbedTLS handshake has crashed older vsftpd builds. It is
			// opt-in only — `open-opts … [opts ftps-experimental="true"]` — so it
			// never silently fails or endangers a server by default. (ftp:// plain
			// is unaffected and fully supported.)
			if scheme == 'ftps' && auth['ftps-experimental'] != 'true' {
				return mk_err('cx-err:CXER1100',
					'E_STORE_UNRESOLVED_BACKEND: ftps:// is experimental/unverified (see #107) — pass [opts ftps-experimental="true"] to attempt it; ftp:// (plain) is supported, or use s3://')
			}
			// #205.4: parse the QUERY-STRIPPED, model-prefix-stripped base_url — the
			// original `url` glued its `?…` query (and any `document+`) into the remote
			// object path (`…/objects/?cache=…/<hash>`). base_url keeps host/path/
			// userinfo (the cx-store:// token + store-name) intact. This also makes
			// `document+ftp://…` open (the model prefix is stripped) rather than
			// tripping CXER1100.
			mut rb, errn, ok := store_remote_parse(base_url)
			if !ok {
				return errn
			}
			rb.tls_verify = tls_verify
			// sftp:// auth + host-key options (from open-opts; ignored by other
			// schemes). password from opts overrides URL userinfo.
			rb.key_path = auth['key-path']
			rb.known_hosts = auth['known-hosts']
			rb.host_key_check = auth['host-key-check']
			if auth['password'] != '' {
				rb.pass = auth['password']
			}
			// cx-store:// CSRP bearer token (from open-opts; overrides any token
			// carried in the URL userinfo). Ignored by other schemes.
			if auth['bearer'] != '' {
				rb.bearer = auth['bearer']
			}
			// #129 B3: opt-in read-only SUBTREE read. `model=subtree` turns a read-only
			// byte source (http/https/ftp/sftp) into an object-graph READER of a published
			// object-per-key set (objects/aa/… + .cxstore-manifest), via the universal seam
			// — same object hashes as every other substrate. Default (no model=subtree) is
			// the document byte-source path below. Read-only: writes error at put_object.
			if auth['model'] == 'subtree' && scheme in ['http', 'https', 'ftp', 'sftp'] {
				mut ms := &MemStore{
					url:         url
					backend:     scheme
					encoding:    if encoding == '' { 'cxbin' } else { encoding }
					compression: if compression == '' { 'none' } else { compression }
					read_only:   true
					is_open:     true
					op_lock:     sync.new_mutex()
					model:       'subtree'
					obj_backend: cxstore.ObjectBackend(new_remote_read_object_backend(rb))
				}
				store_remote_read_load(mut ms) or {
					return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
				}
				id := store_register(ms)
				return store_handle_element(id, ms)
			}
			// http(s):// is a read-only byte source (store.md §2.3); s3://,
			// ftp(s)://, sftp:// honor the requested read-only flag.
			ro := read_only || scheme == 'http' || scheme == 'https'
			mut ms := &MemStore{
				url:         url
				backend:     scheme
				encoding:    if encoding == '' { 'cxbin' } else { encoding }
				compression: if compression == '' { 'none' } else { compression }
				read_only:   ro
				is_open:     true
				op_lock:     sync.new_mutex()
				remote:      rb
			}
			// #129 PR-B: a cx-store:// CSRP CLIENT also drives the OBJECT wire — put-doc
			// decomposes locally and transfers only the objects the daemon is missing,
			// get-doc resolves the ref over the wire and rebuilds from those objects. So
			// the client and the daemon share ONE object space ("change the URL, same
			// model"). `remote` stays set: the daemon serves the authoritative catalog
			// (list/iter/query/modify/delete); only put/get use the object wire (via
			// store_objwire_client). gRPC object-wire parity is a follow-up (item 4) — the
			// production transport here is CSRP over remote_http for the http schemes,
			// and the unary gRPC transport for the grpc schemes (item 4) — both drive
			// the SAME object verbs at parity, so the client decomposes + transfers only
			// missing objects regardless of wire.
			// Client identity (both service wires): open-opts xsp-did names the
			// client DID, xsp-seed-env names the env var holding its 32-byte
			// Ed25519 seed hex (the seed NEVER rides a URL or an opts literal).
			// Absent = anonymous (the daemon's floor policy decides). Validated
			// once here — a did/seed mismatch fails the open loudly, never a
			// confusing signature refusal at first op. The profile wire threads
			// it into the attach; the gRPC edge signs each call with it (G1a).
			if auth['xsp-did'] != '' || auth['xsp-seed-env'] != '' {
				did := auth['xsp-did']
				seed_env := auth['xsp-seed-env']
				if did == '' || seed_env == '' {
					return mk_err('cx-err:CXER1100',
						'E_STORE_UNRESOLVED_BACKEND: client identity needs BOTH xsp-did and xsp-seed-env open-opts (got one)')
				}
				seed_hex := os.getenv(seed_env)
				if seed_hex == '' {
					return mk_err('cx-err:CXER1131', 'E_STORE_AUTH_FAILED: xsp-seed-env "${seed_env}" is unset')
				}
				seed := hex.decode(seed_hex) or {
					return mk_err('cx-err:CXER1131', 'E_STORE_AUTH_FAILED: xsp-seed-env "${seed_env}" is not hex: ${err.msg()}')
				}
				if seed.len != 32 {
					return mk_err('cx-err:CXER1131', 'E_STORE_AUTH_FAILED: xsp-seed-env "${seed_env}" must hold a 32-byte Ed25519 seed (got ${seed.len} bytes)')
				}
				declared := did_key_bytes(did) or {
					return mk_err('cx-err:CXER1131', 'E_STORE_AUTH_FAILED: xsp-did "${did}" is not offline-resolvable (did:key/did:peer:0 in v1)')
				}
				priv := ed25519.new_key_from_seed(seed)
				derived := []u8(priv.public_key())
				if !xsp_auth_ct_eq(declared, derived) {
					return mk_err('cx-err:CXER1131', 'E_STORE_AUTH_FAILED: xsp-seed-env "${seed_env}" does not derive xsp-did "${did}"')
				}
				rb.did = did
				rb.seed = seed
			}
			if scheme in ['cx-store', 'cx-store+xsp'] {
				// I5 stream 4 W6: THE store wire — the XSP store profile.
				if rb.did != '' {
					mut xs := unsafe { rb.xsp }
					xs.did = rb.did
					xs.seed = rb.seed
				}
				ms.obj_backend = cxstore.ObjectBackend(new_xsp_remote_object_backend(rb))
			} else if scheme in ['cx-store+grpc', 'cx-store+grpcs'] {
				ms.obj_backend = cxstore.ObjectBackend(new_grpc_remote_object_backend(rb))
			}
			id := store_register(ms)
			return store_handle_element(id, ms)
		}
		'http+dav', 'https+dav' {
			// Remaining remote schemes still require `net`; they are not yet
			// implemented and fail honestly (no synthetic success). http+dav
			// (WebDAV write) lands in a follow-up.
			if d := cap_guard('net', 'store open ${url}') {
				return d
			}
			return mk_err('cx-err:CXER1100',
				'E_STORE_UNRESOLVED_BACKEND: ${scheme}:// backend not yet implemented in ${url}')
		}
		else {
			return mk_err('cx-err:CXER1100',
				'E_STORE_UNRESOLVED_BACKEND: unknown URL scheme in ${url}')
		}
	}
}

// store_substrate_name maps an internal backend tag to its user-facing SUBSTRATE
// name (spec §2) for the `[store …]` handle + capabilities. The local subtree
// encodings (internally 'cxpack'/'cxobj' = pack / object-per-key framing) and the
// columnar document encoding are all the `file` (or `s3`) substrate — the retired
// `cxpack://`/`cxobj://` scheme tokens never leak to the surface.
fn store_substrate_name(ms &MemStore) string {
	return match ms.backend {
		'cxpack', 'cxobj' {
			'file'
		}
		'columnar' {
			if ms.columnar_s3 != none {
				's3'
			} else {
				'file'
			}
		}
		else {
			ms.backend
		}
	}
}

// store_guarantee_advert is the guarantee set THIS store surface advertises
// (stream 7 L123 — store.md §5/§6): `:linearizable-ref` (the CAS ref
// vocabulary — branch's fast-forward guard + the wire's expect= forms;
// declaring it flips expect-less ref writes to errors, F5),
// `:monotonic-reads` (content reads are immutable by construction; a
// read-only private view is frozen, a live handle's ref reads never
// rewind), and `:read-your-writes` — over a local backing or a
// service-tier remote (reads route to the daemon per op) but NEVER a
// byte-source remote (a caching fetch layer cannot prove its own writes
// visible back).
fn store_guarantee_advert(ms &MemStore) []string {
	if ms.replica_role {
		// Stream 9 (M8, distributed_store §6): the replica declaration
		// profile — CAN :prefix-consistent (chain-checkable),
		// :at-seq-pinned (up to the synced head), :monotonic-reads; MUST
		// refuse :read-your-writes and :linearizable-ref (offline ref
		// advance is exactly where the conflict values land). The refusal
		// is cst_check_floor's wiring-time shape, at open.
		return ['prefix-consistent', 'at-seq-pinned', 'monotonic-reads']
	}
	mut adv := ['linearizable-ref', 'monotonic-reads']
	if store_remote_active(ms) {
		if service_scheme(ms.remote.scheme) {
			adv << 'read-your-writes'
		}
	} else {
		adv << 'read-your-writes'
	}
	return adv
}

// store_floor_declared reports whether the handle's declared consistency
// floor carries a token (stream 7).
fn store_floor_declared(ms &MemStore, token string) bool {
	return token in ms.declared_consistency
}

fn store_handle_element(id int, ms &MemStore) cx.Node {
	writable := !ms.read_only
	mut e := cx.Element{
		name:  'store'
		attrs: [
			cx.Attribute{
				name:  'handle'
				value: cx.ScalarValue(i64(id))
			},
			cx.Attribute{
				name:  'backend'
				value: cx.ScalarValue(store_substrate_name(ms))
			},
			cx.Attribute{
				name:  'url'
				value: cx.ScalarValue(ms.url)
			},
			cx.Attribute{
				name:  'read'
				value: cx.ScalarValue(true)
			},
			cx.Attribute{
				name:  'write'
				value: cx.ScalarValue(writable)
			},
			cx.Attribute{
				name:  'list'
				value: cx.ScalarValue(true)
			},
			cx.Attribute{
				name:  'compression'
				value: cx.ScalarValue(ms.compression)
			},
			cx.Attribute{
				name:  'encoding'
				value: cx.ScalarValue(ms.encoding)
			},
		]
	}
	// Stream 7 (L123): the declared floor is inspectable on the handle —
	// inspection answers VALUES; only declarations refuse. Undeclared
	// handles carry no attribute (byte-identical to the pre-vocabulary
	// handle element).
	if ms.declared_consistency.len > 0 {
		mut toks := []string{}
		for t in ms.declared_consistency {
			toks << ':${t}'
		}
		e.attrs << cx.Attribute{
			name:  'consistency'
			value: cx.ScalarValue(toks.join(' '))
		}
	}
	return e
}

// ── primitive dispatch ───────────────────────────────────────────────

// store_stdlib_builtin guards every handle-bearing op against concurrent
// access to one shared Store handle (#74 Defect 2). A non-blocking try_lock on
// the store's op_lock serializes ops; a contending thread (e.g. a `[par]`
// worker on the same handle) gets a clean E_STORE_HANDLE_RACE value instead of
// racing the docs/aliases maps and crashing. open/open-opts create a handle
// and take no per-store lock; ops whose handle doesn't resolve fall through so
// the inner op emits the precise invalid/closed-handle CXER.
// store_op_host_cap returns the host capability an op needs given the store's
// substrate, or '' when none is required (#206.2). Read ops need the read-side
// cap, write ops the write-side; a remote/networked substrate needs `net` for
// every op; the mem:// tier is capability-free (spec §15). This is the basis for
// the PER-OP re-check on the eval path: opening under a grant then narrowing with
// `[?with-caps [deny …]]` must actually deny subsequent ops on the open handle,
// and a forged `[store handle=N]` to a file/remote store must still hold the cap.
fn store_op_host_cap(name string, ms &MemStore) string {
	// networked substrates: any op is a net effect.
	if ms.remote != unsafe { nil } || ms.backend == 's3' {
		return 'net'
	}
	if ms.obj_backend != none {
		if _ := store_objwire_client(ms) {
			return 'net' // cx-store:// object wire
		}
	}
	if ms.backend == 'mem' {
		return '' // capability-free (spec §15)
	}
	// local substrates (file/cxpack/cxobj/sqlite/columnar-file): read vs write.
	return if store_op_is_write(name) { 'write' } else { 'read' }
}

// store_op_is_write classifies a store builtin as a write-side (mutating) op.
// Non-write ops are reads; open/close/capabilities take no host cap and never
// reach the re-check.
fn store_op_is_write(name string) bool {
	return name in ['store-put-doc', 'store-put-doc-text', 'store-put-doc-stream',
		'store-put-blob', 'store-delete-doc', 'store-modify-doc', 'store-set-alias',
		'store-delete-alias',
		'store-migrate', 'store-clone', 'store-push', 'store-pull', 'store-fetch', 'store-gc',
		'store-prune', 'store-rotate-kek', 'store-branch', 'store-branch-force']
}

// store_op_needs_no_cap names the introspection/lifecycle ops that take no host
// capability (open/open-opts are handled before dispatch; csrp-handle has its own
// net gate).
fn store_op_needs_no_cap(name string) bool {
	return name in ['store-close', 'store-capabilities']
}

fn store_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	if name == 'store-open' || name == 'store-open-opts' || args.len == 0 {
		return store_stdlib_builtin_inner(name, args)
	}
	mut ms := store_for_guard(args[0]) or { return store_stdlib_builtin_inner(name, args) }
	// #206.2 per-op capability re-check (eval path only — the daemon runs
	// store_stdlib_builtin_inner under process-granted caps). Re-checking here
	// makes `[?with-caps [deny read/write/net]]` deny ops on an already-open
	// handle, and forces a forged `[store handle=N]` to a file/remote store to
	// hold the cap. mem:// is capability-free (spec §15), so a mem handle is
	// unaffected — which is correct, not a bypass.
	if !store_op_needs_no_cap(name) {
		reqcap := store_op_host_cap(name, ms)
		if reqcap != '' {
			if d := cap_guard(reqcap, 'store ${name} on ${ms.url}') {
				return d
			}
		}
	}
	if ms.op_lock == unsafe { nil } {
		return store_stdlib_builtin_inner(name, args)
	}
	// #628: a SHARED store (same-root writable opens) has two legitimate
	// owners — contention BLOCKS (per-op serialization). A single-handle
	// store keeps the #74 single-owner contract: contention is a caller bug
	// ([par] over one handle) and refuses cleanly. Both paths go through the
	// reentrant owner-tid bookkeeping so the mutation/read funnels and the
	// group-commit flush scope nest on the same mutex instead of
	// self-deadlocking.
	if ms.open_count > 1 {
		store_lock_enter(mut ms)
	} else {
		if !store_try_enter(mut ms) {
			// #617: contention from the store's OWN background fold worker is
			// not a caller bug — it holds the lock only for µs-scale plan/
			// commit bookkeeping (the pack I/O runs unlocked), so wait it out.
			// Only a genuine second user thread on a single-owner handle
			// refuses. fold_running is read racily here; the fallback is
			// blocking, which is always safe (it is what shared stores do) —
			// at worst a real [par] misuse waits instead of refusing while a
			// fold happens to be live.
			if ms.fold_running {
				store_lock_enter(mut ms)
			} else {
				return mk_err(store_err_handle_race,
					'E_STORE_HANDLE_RACE: concurrent access to a shared Store handle — a Store is single-owner; shard (open separate handles per worker) for parallelism, `[par]` on one handle is unsupported')
			}
		}
	}
	defer {
		store_lock_exit(mut ms)
	}
	return store_stdlib_builtin_inner(name, args)
}

fn store_stdlib_builtin_inner(name string, args []cx.Node) ?cx.Node {
	match name {
		'store-open' {
			url := store_arg_str(args[0]) or { return none }
			return store_open_impl(url, '', '', false, true, map[string]string{})
		}
		'store-open-opts' {
			url := store_arg_str(args[0]) or { return none }
			mut compression := ''
			mut encoding := ''
			mut read_only := false
			mut tls_verify := true
			mut auth := map[string]string{}
			if args.len > 1 {
				opts := args[1]
				if opts is cx.Element {
					// A CX map literal ({"k": v}) materializes its entries as
					// CHILD ELEMENTS of the __cx_map__ envelope, not attrs.
					// Reading only .attrs silently dropped every such opt —
					// for encrypt-key-id that meant a PLAINTEXT store where
					// the caller asked for a sealed one (fail-open, violating
					// store.md §9 fail-closed). Collect both entry shapes.
					mut kvs := []cx.Attribute{}
					for a in opts.attrs {
						kvs << a
					}
					for it in opts.items {
						if it is cx.Element && it.items.len == 1 {
							inner := it.items[0]
							match inner {
								cx.ScalarNode {
									kvs << cx.Attribute{
										name:  it.name
										value: inner.value
									}
								}
								cx.TextNode {
									kvs << cx.Attribute{
										name:  it.name
										value: cx.ScalarValue(inner.value)
									}
								}
								else {}
							}
						}
					}
					for a in kvs {
						val := cx.scalar_value_str_public(a.value)
						match a.name {
							'compression' { compression = val }
							'encoding' { encoding = val }
							'read-only' { read_only = val == 'true' }
							'tls-verify' { tls_verify = val != 'false' }
							// sftp:// (#106) auth + host-key opts
							'key-path' { auth['key-path'] = val }
							'known-hosts' { auth['known-hosts'] = val }
							'host-key-check' { auth['host-key-check'] = val }
							'password' { auth['password'] = val }
							// ftps:// opt-in (experimental/unverified, #107)
							'ftps-experimental' { auth['ftps-experimental'] = val }
							// cx-store:// CSRP bearer token (#78)
							'bearer' { auth['bearer'] = val }
							// cx-store(+xsp):// client identity (I5 stream 4 W6):
							// the DID + the env var naming its Ed25519 seed hex.
							'xsp-did' { auth['xsp-did'] = val }
							'xsp-seed-env' { auth['xsp-seed-env'] = val }
							// #129 B2: storage model — 'document' = degenerate
							// one-object-per-doc; default/'subtree' = decompose.
							'model' { auth['model'] = val }
							// #129 D5 (G3-Q3): declared columnar schema (a path to a
							// cx-stdlib/validate [schema …] file). Pins + validates.
							'schema' { auth['schema'] = val }
							// #114 (PR-E): encryption-at-rest tenant key-id on a local
							// object substrate (KEK from env CX_STORE_KEK_<id>).
							'encrypt-key-id' { auth['encrypt-key-id'] = val }
							else {}
						}
					}
				}
			}
			res := store_open_impl(url, compression, encoding, read_only, tls_verify,
				auth)
			// Stream 7 (L122/L123): the consistency floor — declared tokens
			// validate ONCE here against the surface's advertised guarantee
			// set; an unsatisfiable declaration refuses the open (CXER4990),
			// it never opens degraded.
			if args.len > 1 {
				// stream 9 (M8): opts.replica marks the handle a REPLICA
				// surface BEFORE the floor validates — the declaration
				// profile is the advert the floor checks against.
				mut is_replica := false
				opts1 := args[1]
				if opts1 is cx.Element {
					for oit in opts1.items {
						if oit is cx.Element && oit.name == 'replica' && oit.items.len > 0 {
							ov := oit.items[0]
							if ov is cx.ScalarNode {
								is_replica = cx.scalar_value_str_public(ov.value) == 'true'
							} else if ov is cx.TextNode {
								is_replica = ov.value == 'true'
							}
						}
					}
				}
				if is_replica && !is_err_value(res) {
					if sid0 := store_handle_of(res) {
						if mut sms0 := store_lookup(sid0) {
							sms0.replica_role = true
						}
					}
				}
				cdecl, cerr, cok := cst_read_declared(args[1], 'store:open')
				if !cok {
					return cerr
				}
				if cdecl.len > 0 {
					if is_err_value(res) {
						return res
					}
					sid := store_handle_of(res) or { return res }
					mut sms := store_lookup(sid) or { return res }
					if e := cst_check_floor(cdecl, 'store:open', store_guarantee_advert(sms)) {
						store_stdlib_builtin_inner('store-close', [res]) or {
							cx.Node(store_null())
						}
						return e
					}
					sms.declared_consistency = cdecl
					return store_handle_element(sid, sms)
				}
			}
			return res
		}
		'store-put-doc', 'store-put-doc-stream' {
			// mem:// streaming has no distinct wire from the in-process
			// doc: the source's canonical bytes ARE the doc, so the
			// returned hash is identical to put-doc (§3.2).
			mut ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			if ms.read_only {
				return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${ms.url}')
			}
			// RULED: CO-2 (#975): a store document write is an externalizing
			// effect — a document containing an [err] at any depth refuses
			// (CXER0275) unless the optional opts arg carries errs=:permit.
			// Blob writes stay exempt by construction (opaque bytes).
			if !(args.len > 2 && errs_permitted_node(args[2])) {
				if hit := find_err_at_rest(args[1]) {
					return err_boundary_refusal('store document write', hit)
				}
			}
			if ms.backend == 'columnar' && ms.columnar_schema != '' {
				if v := store_columnar_schema_violation(ms, cx.Document{
					elements: [
						args[1],
					]
				})
				{
					return v
				}
			}
			canonical := render_canonical(args[1])
			hash := cx.cx_text_hash(canonical) or {
				return mk_err('cx-err:CXER1120',
					'E_STORE_INTEGRITY_MISMATCH: hash failed: ${err.msg()}')
			}
			// Stream 20 (#692): reserved subject vocabulary — a subject-bearing
			// doc takes the sealed whole-object path (store_subject.v).
			if subj := store_subject_attr(args[1]) {
				return store_put_doc_subject(mut ms, args[1], subj, canonical, hash)
			}
			if owc := store_objwire_client(ms) {
				// cx-store:// object wire: decompose locally, push only the missing
				// objects, advance the ref. Same store-key as every other substrate.
				sk := owc.push_doc(canonical, ms.model) or {
					// #212 Defect A: a 403/401 on the object wire is an auth failure,
					// not integrity corruption — surface the real code.
					if ae := store_objwire_err(mut ms) {
						return ae
					}
					return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
				}
				return store_str(sk)
			}
			if store_remote_active(ms) {
				// Content-addressed PUT is idempotent (same hash = same bytes);
				// dedup is implicit. No local docs map for a remote store.
				perr := store_remote_put(ms.remote, hash, canonical)
				if is_err_value(perr) {
					return perr
				}
				return store_str(hash)
			}
			if store_put_canonical(mut ms, hash, canonical) or {
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
			}
			{
				store_append(mut ms, store_doc_record(hash, canonical)) or {
					return store_persist_err(ms, err.msg())
				}
			}
			return store_str(hash)
		}
		'store-put-doc-text' {
			// Text doc-I/O (#78 CSRP): store a doc given as canonical/parseable
			// TEXT rather than a node. Canonicalizes to the STRICT canonical form
			// (spec/core/canonical.md §1.2/§1.4 — the store's Tier-1 identity): this
			// resolves §2.8 anchor/alias/merge structure, strips comments, and
			// normalizes unordered map keys, so the store-key + dedup match `cx hash`
			// and two docs differing only in data-sharing get one key. (render_canonical
			// is the runtime VALUE renderer and does not resolve aliases — using it here
			// gave an aliased doc the wrong key.)
			mut ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			if ms.read_only {
				return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${ms.url}')
			}
			text := store_arg_str(args[1]) or { return none }
			parsed := cx.parse(text) or {
				return mk_err('cx-err:CXER1120',
					'E_STORE_INTEGRITY_MISMATCH: undecodable doc text: ${err.msg()}')
			}
			// RULED: CO-2 (#975): put-doc-text stores a PARSED document (the
			// canonicalization below proves it), so the effect boundary applies
			// exactly as for put-doc — this is not an opaque byte write.
			if !(args.len > 2 && errs_permitted_node(args[2])) {
				for pel in parsed.elements {
					if hit := find_err_at_rest(pel) {
						return err_boundary_refusal('store document write', hit)
					}
				}
			}
			if parsed.elements.len == 0 {
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: empty doc text')
			}
			if ms.backend == 'columnar' && ms.columnar_schema != '' {
				if v := store_columnar_schema_violation(ms, parsed) {
					return v
				}
			}
			canonical := cx.cx_text_canonical(text) or {
				return mk_err('cx-err:CXER1120',
					'E_STORE_INTEGRITY_MISMATCH: undecodable doc text: ${err.msg()}')
			}
			hash := cx.cx_text_hash(canonical) or {
				return mk_err('cx-err:CXER1120',
					'E_STORE_INTEGRITY_MISMATCH: hash failed: ${err.msg()}')
			}
			// Stream 20 (#692): reserved subject vocabulary (store_subject.v).
			if parsed.elements.len > 0 {
				if subj := store_subject_attr(parsed.elements[0]) {
					return store_put_doc_subject(mut ms, parsed.elements[0], subj,
						canonical, hash)
				}
			}
			if owc := store_objwire_client(ms) {
				// cx-store:// object wire (text-body CSRP server's enabling verb too).
				sk := owc.push_doc(canonical, ms.model) or {
					// #212 Defect A: a 403/401 on the object wire is an auth failure,
					// not integrity corruption — surface the real code.
					if ae := store_objwire_err(mut ms) {
						return ae
					}
					return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
				}
				return store_str(sk)
			}
			if store_remote_active(ms) {
				perr := store_remote_put(ms.remote, hash, canonical)
				if is_err_value(perr) {
					return perr
				}
				return store_str(hash)
			}
			if store_put_canonical(mut ms, hash, canonical) or {
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
			}
			{
				store_append(mut ms, store_doc_record(hash, canonical)) or {
					return store_persist_err(ms, err.msg())
				}
			}
			return store_str(hash)
		}
		'store-get-doc-text' {
			// Text doc-I/O (#78 CSRP): return the stored canonical TEXT for a
			// hash (vs get-doc which returns the parsed node), or the absence
			// channel () on a miss — never null, never an [err] (§9.1.2.1).
			mut ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			hash := store_arg_str(args[1]) or { return none }
			if serr := store_addr_shape_err(hash) {
				return serr
			}
			if tomb := ms.erased[hash] {
				// #720 item 1 (erasure_compliance §6): the text form answers the
				// tombstone's canonical text VERBATIM — §7b wire parity with the
				// XSP get arm; never absence, never the not-found fault.
				return store_str(tomb)
			}
			if hash in ms.blob_kind {
				// F1': an OPAQUE document is not readable through the structured
				// verbs — its bytes are not canonical doc text. One typed refusal
				// on every model (never model-divergent, never silent bytes).
				return mk_err('cx-err:CXER0100',
					'E_OPERAND_KIND: ${hash} is an opaque document (raw-byte identity) — read it with get-blob')
			}
			if owc := store_objwire_client(ms) {
				// cx-store:// object wire: resolve the ref over the wire (a miss is
				// absence, §9.1.2.1), then rebuild the doc from the daemon's objects.
				// A 403 on the ref read is an auth failure, not absence (#212).
				root := owc.resolve_ref(hash) or {
					if ae := store_objwire_err(mut ms) {
						return ae
					}
					return store_empty()
				}
				text := owc.reconstruct(root, ms.model) or {
					if ae := store_objwire_err(mut ms) {
						return ae
					}
					return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
				}
				return store_str(text)
			}
			if store_remote_active(ms) {
				t, gerr, gok := store_remote_get(ms.remote, hash)
				if gok {
					return store_str(t)
				}
				// not-found → absence; any other transport error propagates.
				if gerr is cx.Element && gerr.name == 'err' {
					if c := http_attr(gerr, 'code') {
						if c == 'cx-err:CXER1121' {
							return store_empty()
						}
					}
				}
				return gerr
			}
			if !store_doc_present(ms, hash) {
				return store_empty()
			}
			text := store_doc_text(ms, hash) or {
				if fe := store_s3_fail_err(mut ms) {
					return fe
				}
				return store_read_err_node(err.msg())
			}
			return store_str(text)
		}
		'store-get-doc' {
			mut ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			hash := store_arg_str(args[1]) or { return none }
			if serr := store_addr_shape_err(hash) {
				return serr
			}
			if tomb := ms.erased[hash] {
				// #720 item 1 (erasure_compliance §6): a lawfully-shredded doc
				// is the THIRD answer of the get discriminator — the attributed
				// [erased] tombstone on the VALUE channel (§7b wire parity) —
				// never the not-found fault (erased ≠ never-existed ≠ corrupt).
				tdoc := cx.parse(tomb) or {
					return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: tombstone unparseable for ${hash}')
				}
				if tdoc.elements.len > 0 {
					return tdoc.elements[0]
				}
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: empty tombstone for ${hash}')
			}
			if hash in ms.blob_kind {
				// F1': structured read of an opaque document — one typed refusal.
				return mk_err('cx-err:CXER0100',
					'E_OPERAND_KIND: ${hash} is an opaque document (raw-byte identity) — read it with get-blob')
			}
			mut text := ''
			if owc := store_objwire_client(ms) {
				// cx-store:// object wire: resolve the ref (miss → NOT_FOUND for the
				// node form), then rebuild from the daemon's objects. A 403 is an
				// auth failure, not not-found/integrity (#212).
				root := owc.resolve_ref(hash) or {
					if ae := store_objwire_err(mut ms) {
						return ae
					}
					return mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: ${hash}')
				}
				text = owc.reconstruct(root, ms.model) or {
					if ae := store_objwire_err(mut ms) {
						return ae
					}
					return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
				}
			} else if store_remote_active(ms) {
				t, gerr, ok := store_remote_get(ms.remote, hash)
				if !ok {
					return gerr
				}
				text = t
			} else {
				if !store_doc_present(ms, hash) {
					return mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: ${hash}')
				}
				text = store_doc_text(ms, hash) or {
					// #213: an s3 object read denied mid-session is an auth/transport
					// failure, not corruption — prefer the recorded honest cause.
					if fe := store_s3_fail_err(mut ms) {
						return fe
					}
					return store_read_err_node(err.msg())
				}
			}
			rehash := cx.cx_text_hash(text) or {
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${hash}')
			}
			if rehash != hash {
				return mk_err('cx-err:CXER1120',
					'E_STORE_INTEGRITY_MISMATCH: stored ${hash} rehashes to ${rehash}')
			}
			parsed := cx.parse(text) or {
				return mk_err('cx-err:CXER1120',
					'E_STORE_INTEGRITY_MISMATCH: undecodable doc at ${hash}')
			}
			if parsed.elements.len > 0 {
				return parsed.elements[0]
			}
			return store_null()
		}
		'store-list-docs' {
			ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			if store_remote_active(ms) {
				hashes, lerr, ok := store_remote_list(ms.remote)
				if !ok {
					return lerr
				}
				mut ritems := []cx.Node{}
				for h in hashes {
					ritems << store_str(h)
				}
				return store_seq(ritems)
			}
			mut items := []cx.Node{}
			for h in ms.doc_order {
				items << store_str(h)
			}
			return store_seq(items)
		}
		'store-iter-docs' {
			ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			// §3.4: yields [hash $h doc $d] element pairs. mem:// is
			// bounded, so eager materialization keeps the same shape.
			mut items := []cx.Node{}
			if store_remote_active(ms) {
				// CSRP service tier: a dedicated server-side iter op — one round
				// trip, server-authoritative order, the doc objects decoded from the
				// wire elements (NOT a client-side list+get reassembly).
				if service_scheme(ms.remote.scheme) {
					return store_remote_iter(ms.remote)
				}
				// Generic byte-source backends (s3/http/ftp/sftp) have no iter op;
				// reassemble the [entry hash="H" <doc>] sequence via list + get.
				hashes, lerr, ok := store_remote_list(ms.remote)
				if !ok {
					return lerr
				}
				for h in hashes {
					t, gerr, gok := store_remote_get(ms.remote, h)
					if !gok {
						return gerr
					}
					items << cx.Element{
						name:  'entry'
						attrs: [
							cx.Attribute{
								name:  'hash'
								value: cx.ScalarValue(h)
							},
						]
						items: [store_decode_doc(t)]
					}
				}
				return store_seq(items)
			}
			for h in ms.doc_order {
				if h in ms.blob_kind {
					// F1': opaque documents are not structured docs — iteration
					// yields structured entries only (list-docs still lists every
					// key; get-blob is the opaque read).
					continue
				}
				text := store_doc_text(ms, h) or {
					return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
				}
				doc_node := store_decode_doc(text)
				items << cx.Element{
					name:  'entry'
					attrs: [
						cx.Attribute{
							name:  'hash'
							value: cx.ScalarValue(h)
						},
					]
					items: [doc_node]
				}
			}
			return store_seq(items)
		}
		'store-exists' {
			ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			hash := store_arg_str(args[1]) or { return none }
			if serr := store_addr_shape_err(hash) {
				return serr
			}
			if store_remote_active(ms) {
				present, herr, ok := store_remote_has(ms.remote, hash)
				if !ok {
					return herr
				}
				return store_bool(present)
			}
			return store_bool(store_doc_present(ms, hash))
		}
		'store-delete-doc' {
			mut ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			if ms.read_only {
				return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${ms.url}')
			}
			hash := store_arg_str(args[1]) or { return none }
			if serr := store_addr_shape_err(hash) {
				return serr
			}
			if store_remote_active(ms) {
				deleted, derr, ok := store_remote_delete(ms.remote, hash)
				if !ok {
					return derr
				}
				return store_bool(deleted)
			}
			if store_doc_present(ms, hash) {
				store_delete_local(mut ms, hash)
				// #291: deletion rides the same O(1) append path as puts — a T
				// (tombstone) record — instead of a whole-snapshot rewrite per
				// delete. Durable-on-return like every other append (a failed
				// write raises); the tombstone counts toward store_append's
				// redundancy measure, so a delete-heavy log still folds back to
				// a snapshot. Non-file backends flush through store_append
				// exactly as store_persist did (cxpack keeps its own manifest
				// tombstones).
				store_append(mut ms, store_tombstone_record(hash)) or {
					return store_persist_err(ms, err.msg())
				}
				return store_bool(true)
			}
			return store_bool(false)
		}
		'store-modify-doc' {
			return store_modify_doc(args)
		}
		'store-put-blob' {
			// F1' (RULED 2026-08-08): the OPAQUE-document surface — identity =
			// hash of the RAW bytes as given; byte-exact round-trip; no
			// canonicalization ever (CX code, images, plain text).
			mut ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			if ms.read_only {
				return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${ms.url}')
			}
			raw := store_arg_str(args[1]) or { return none }
			// S6: the SERVICE wires carry the pair as profile verbs — a local
			// mirror write against a cx-store(+xsp):// handle would be the
			// silent-partial anti-pattern (the daemon never sees the blob).
			if ms.remote != unsafe { nil } && ms.remote.scheme.starts_with('cx-store') {
				return store_remote_blob_put(ms.remote, raw)
			}
			key := store_put_blob_local(mut ms, raw) or {
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: blob put: ${err.msg()}')
			}
			store_append(mut ms, store_blob_record(key, raw)) or {
				return store_persist_err(ms, err.msg())
			}
			return store_str(key)
		}
		'store-get-blob' {
			ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			key := store_arg_str(args[1]) or { return none }
			if serr := store_addr_shape_err(key) {
				return serr
			}
			if ms.remote != unsafe { nil } && ms.remote.scheme.starts_with('cx-store') {
				return store_remote_blob_get(ms.remote, key)
			}
			raw := store_get_blob_local(ms, key) or {
				if err.msg().contains('INTEGRITY') {
					return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
				}
				return mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: no blob at ${key}')
			}
			return store_str(raw)
		}
		'store-query' {
			return store_query(args)
		}
		'store-source' {
			return store_source(args)
		}
		'store-capabilities' {
			ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			writable := !ms.read_only
			return cx.Element{
				name:  'map'
				attrs: [
					cx.Attribute{
						name:  'read'
						value: cx.ScalarValue(true)
					},
					cx.Attribute{
						name:  'write'
						value: cx.ScalarValue(writable)
					},
					cx.Attribute{
						name:  'list'
						value: cx.ScalarValue(true)
					},
					cx.Attribute{
						name:  'backend'
						value: cx.ScalarValue(store_substrate_name(ms))
					},
					cx.Attribute{
						name:  'url'
						value: cx.ScalarValue(ms.url)
					},
					cx.Attribute{
						name:  'compression'
						value: cx.ScalarValue(ms.compression)
					},
					cx.Attribute{
						name:  'encoding'
						value: cx.ScalarValue(ms.encoding)
					},
				]
			}
		}
		'store-close' {
			mut ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			// #628: retire THIS handle (its id reports CXER1130 from now on)
			// and decrement the share refcount; the live store closes only
			// when the last handle goes. Retirement stops a closed handle from
			// silently operating via a sibling's live view.
			if hid := store_handle_of(args[0]) {
				mut l := unsafe { g_store_reg_lock }
				l.@lock()
				mut reg := store_reg()
				reg.stores.delete(hid)
				reg.closed[hid] = true
				ms.open_count--
				l.unlock()
			} else {
				ms.open_count--
			}
			if ms.open_count <= 0 {
				ms.is_open = false
				// #1005: the LAST handle on this store releases the
				// cross-process writable-open guard, so the next process — or
				// the next open here — can have the root. Empty key for a
				// read-only or rootless open, which never took it.
				store_root_unlock(ms.lock_key)
				ms.lock_key = ''
			}
			return store_null()
		}
		'store-set-alias' {
			mut ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			// #645: a cx-store:// CLIENT routes the write to the daemon's
			// AUTHORITATIVE alias table over the `aliases-set` wire op — one
			// authority, so target-presence (CXER1121), gc pinning, and the pack
			// alias record all apply daemon-side. Byte-source remotes (http/ftp/
			// sftp/s3-doc) keep the honest CXER1709 refusal: there is no service
			// to ask (#264 posture unchanged for them).
			if store_remote_active(ms) {
				if owc := store_objwire_client(ms) {
					if ms.read_only {
						return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${ms.url}')
					}
					// Stream 7 F5: same declaring-handle rule as the local arm —
					// the objwire alias_set here carries no expect=.
					if store_floor_declared(ms, 'linearizable-ref') {
						return cst_refusal('write', cst_atom('linearizable-ref'), ':linearizable-ref',
							'store:set-alias', store_guarantee_advert(ms), 'expect-less ref writes are last-writer-wins — this handle declared CAS-only ref advancement; use the expect= wire CAS',
							'')
					}
					alias := store_arg_str(args[1]) or { return none }
					hash := store_arg_str(args[2]) or { return none }
					if serr := store_addr_shape_err(hash) {
						return serr
					}
					st, _, tok := owc.alias_set(alias, hash)
					if !tok {
						return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: aliases-set on ${ms.url}')
					}
					match st {
						200 { return store_null() }
						404 { return mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: alias target ${hash}') }
						409 { return mk_err('cx-err:CXER1114', 'E_STORE_REF_CONFLICT: alias ${alias} moved') }
						401, 403 { return mk_err('cx-err:CXER1131', 'E_STORE_AUTH_FAILED: aliases-set on ${ms.url} (status ${st})') }
						429 { return mk_err('cx-err:CXER1132', 'E_STORE_RATE_LIMITED: aliases-set on ${ms.url}') }
						else { return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: aliases-set on ${ms.url} (status ${st})') }
					}
				}
				return mk_err('cx-err:CXER1709',
					'E_CSRP_OPERATION_UNSUPPORTED: set-alias — this remote is a byte source with no CSRP service; aliases are local-registry state (discover remotely via store-query pushdown)')
			}
			if ms.read_only {
				return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${ms.url}')
			}
			// Stream 7 F5 (L122 :linearizable-ref): a declaring handle makes
			// expect-less ref writes ERRORS — set-alias is silent LWW under a
			// second writer; the sanctioned moves are branch (fast-forward
			// guarded) and the wire expect= CAS forms.
			if store_floor_declared(ms, 'linearizable-ref') {
				return cst_refusal('write', cst_atom('linearizable-ref'), ':linearizable-ref',
					'store:set-alias', store_guarantee_advert(ms), 'expect-less ref writes are last-writer-wins — this handle declared CAS-only ref advancement; use branch (fast-forward) or the expect= wire CAS',
					'')
			}
			alias := store_arg_str(args[1]) or { return none }
			hash := store_arg_str(args[2]) or { return none }
			if serr := store_addr_shape_err(hash) {
				return serr
			}
			// the target may be a structured doc or an opaque blob (F1') — both
			// live in doc_order under their own hash rule, one presence check.
			if !store_doc_present(ms, hash) {
				return mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: alias target ${hash}')
			}
			// computation/<addr> is the stream-5 result-cache namespace
			// (L106): admission validates fail-loud — record identity +
			// fn purity + result cacheability (store_computation.v). The
			// daemon's aliases-set wire op routes through this same arm,
			// so one authority holds on every surface.
			if alias.starts_with('computation/') {
				if refusal := store_computation_admission_check(ms, alias, hash) {
					return refusal
				}
			}
			store_alias_set_local(mut ms, alias, hash)
			store_append(mut ms, store_alias_record(alias, hash)) or {
				return store_persist_err(ms, err.msg())
			}
			return store_null()
		}
		'store-get-alias' {
			mut ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			if store_remote_active(ms) {
				// #645: resolve against the daemon's alias table over the `aliases`
				// wire op. The answer carries EXPLICIT per-name presence, so an
				// absent alias is a server-asserted absence () — the #264
				// miss-vs-absence concern is answered by the wire, not assumed.
				if owc := store_objwire_client(ms) {
					alias := store_arg_str(args[1]) or { return none }
					hash, present, tok := owc.alias_get(alias)
					if !tok {
						if e := store_objwire_err(mut ms) {
							return e
						}
						return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: aliases on ${ms.url}')
					}
					if present {
						return store_str(hash)
					}
					return store_empty() // server-asserted miss → absence (§9.1.2)
				}
				return mk_err('cx-err:CXER1709',
					'E_CSRP_OPERATION_UNSUPPORTED: get-alias — this remote is a byte source with no CSRP service to ask; a remote miss would be indistinguishable from absence, so the op refuses instead (#264)')
			}
			alias := store_arg_str(args[1]) or { return none }
			if alias in ms.aliases {
				return store_str(ms.aliases[alias])
			}
			return store_empty() // §9.1.2: alias miss → absence, not null
		}
		'store-list-aliases' {
			mut ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			if store_remote_active(ms) {
				// #645: list from the daemon's authoritative table (server order),
				// same [alias name=… hash=…] shape as the local listing.
				if owc := store_objwire_client(ms) {
					pairs := owc.alias_list() or {
						if e := store_objwire_err(mut ms) {
							return e
						}
						return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: aliases on ${ms.url}')
					}
					mut ritems := []cx.Node{}
					for p in pairs {
						if p.len != 2 {
							continue
						}
						ritems << cx.Element{
							name:  'alias'
							attrs: [
								cx.Attribute{
									name:  'name'
									value: cx.ScalarValue(p[0])
								},
								cx.Attribute{
									name:  'hash'
									value: cx.ScalarValue(p[1])
								},
							]
						}
					}
					return store_seq(ritems)
				}
				return mk_err('cx-err:CXER1709',
					'E_CSRP_OPERATION_UNSUPPORTED: list-aliases — this remote is a byte source with no CSRP service; catalog discovery over the wire is store-query pushdown (pkg-catalog composes it)')
			}
			mut items := []cx.Node{}
			for a in ms.alias_order {
				items << cx.Element{
					name:  'alias'
					attrs: [
						cx.Attribute{
							name:  'name'
							value: cx.ScalarValue(a)
						},
						cx.Attribute{
							name:  'hash'
							value: cx.ScalarValue(ms.aliases[a])
						},
					]
				}
			}
			return store_seq(items)
		}
		'store-delete-alias' {
			mut ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			// #645: deletion is deliberately NOT carried on the wire (no live
			// consumer; the wire carries `aliases`/`aliases-set` only). On any
			// remote handle the local alias map is dead state, so mutating it
			// and answering true/false would lie — refuse honestly instead
			// (the #264 posture).
			if store_remote_active(ms) {
				return mk_err('cx-err:CXER1709',
					'E_CSRP_OPERATION_UNSUPPORTED: delete-alias is not carried on the CSRP wire (#645 carries aliases/aliases-set); delete on the daemon side')
			}
			if ms.read_only {
				return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${ms.url}')
			}
			// Stream 7 F5: a ref delete is an expect-less ref write (there is
			// no expect-bearing delete) — a declaring handle refuses it.
			if store_floor_declared(ms, 'linearizable-ref') {
				return cst_refusal('write', cst_atom('linearizable-ref'), ':linearizable-ref',
					'store:delete-alias', store_guarantee_advert(ms), 'ref deletion has no expect= form — this handle declared CAS-only ref advancement',
					'')
			}
			alias := store_arg_str(args[1]) or { return none }
			if store_alias_delete_local(mut ms, alias) {
				// #298: alias removal rides the same O(1) append path as set-alias
				// — an X (alias tombstone) record — instead of a whole-snapshot
				// rewrite per delete (the #291 contract on the alias plane:
				// durable-on-return, counted by the compaction redundancy measure,
				// folded at snapshot; non-file backends flush through store_append
				// exactly as store_persist did).
				store_append(mut ms, store_alias_tombstone_record(alias)) or {
					return store_persist_err(ms, err.msg())
				}
				return store_bool(true)
			}
			return store_bool(false)
		}
		'store-migrate' {
			return store_migrate(args)
		}
		'store-clone' {
			return store_clone(args)
		}
		'store-push' {
			return store_push(args)
		}
		'store-pull' {
			return store_pull(args)
		}
		'store-pull-report' {
			return store_pull_report(args)
		}
		'store-fetch' {
			return store_fetch(args)
		}
		'store-status' {
			return store_status(args)
		}
		'store-mounts' {
			// #248 (CSRP §3.12): daemon-level mount enumeration — inherently a
			// service-tier op (a local handle IS its only store; there is no daemon
			// to enumerate), so it requires a cx-store:// handle and fails honestly
			// otherwise. The server enforces admin RBAC + tenant filtering.
			if args.len < 1 {
				return mk_err('cx-err:CXER0108', 'E_ARG: mounts expects ($store)')
			}
			ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			if store_remote_active(ms) && service_scheme(ms.remote.scheme) {
				return store_remote_admin(ms.remote, 'mounts')
			}
			return mk_err('cx-err:CXER1709',
				'E_CSRP_OPERATION_UNSUPPORTED: mounts is a daemon-level op — it requires a cx-store:// service-tier handle')
		}
		'store-config-reload' {
			// #251 (CSRP §3.13): daemon-level runtime config reload — like mounts,
			// inherently service-tier (a local handle has no daemon config), so it
			// requires a cx-store:// handle and fails honestly otherwise. The daemon
			// re-reads its OWN config source (nothing rides the wire) and enforces
			// admin RBAC; refusals surface as CXER1711/1712 verbatim.
			if args.len < 1 {
				return mk_err('cx-err:CXER0108', 'E_ARG: config-reload expects ($store)')
			}
			ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			if store_remote_active(ms) && service_scheme(ms.remote.scheme) {
				return store_remote_admin(ms.remote, 'config-reload')
			}
			return mk_err('cx-err:CXER1709',
				'E_CSRP_OPERATION_UNSUPPORTED: config-reload is a daemon-level op — it requires a cx-store:// service-tier handle')
		}
		'store-log' {
			return store_log(args)
		}
		'store-verify' {
			return store_verify(args)
		}
		'store-gc' {
			return store_gc(args)
		}
		'store-prune' {
			return store_prune(args)
		}
		'store-rotate-kek' {
			return store_rotate_kek(args)
		}
		'store-reconcile' {
			// stream 9 (#681, L175/L176): the enforcing twin — raises
			// CXER5053 carrying every [conflict] iff the report says
			// ok=false (the agreement law).
			return store_reconcile_impl(args, true)
		}
		'store-reconcile-report' {
			return store_reconcile_impl(args, false)
		}
		'store-diff' {
			return store_diff(args)
		}
		'store-branch' {
			return store_branch(args)
		}
		'store-branch-force' {
			return store_branch_force(args)
		}
		else {
			return none
		}
	}
}

// store_decode_doc parses a stored canonical doc text back to a node.
fn store_decode_doc(text string) cx.Node {
	parsed := cx.parse(text) or { return store_null() }
	if parsed.elements.len > 0 {
		return parsed.elements[0]
	}
	return store_null()
}

// store_modify_doc implements §3.6: fetch the doc at `hash`, apply the
// `action`, store the result as a NEW doc (content-addressed = immutable;
// the original is never deleted), return the new hash.
//
// SUBSET (first landing): the action verbs supported in the mem://
// backend are `[set-attr name=N value=V]`, `[remove-attr name=N]`,
// `[append CHILD…]`, and `[rename NEW]` on the doc root element. The full
// Layer-1 modify surface (path-targeted edits) is deferred to the
// integration suite; an unsupported action raises CXER0100.
fn store_modify_doc(args []cx.Node) ?cx.Node {
	mut ms, errn, ok := store_get_open(args[0])
	if !ok {
		return errn
	}
	// CSRP service tier: push the modify to the server (the local doc map is
	// EMPTY for a remote-backed handle, so a client-side modify would always
	// report NOT_FOUND). The server applies the action, content-addresses the
	// result, and returns the new hash. A backend without modify pushdown raises
	// CXER1709 rather than failing silently.
	if store_remote_active(ms) {
		if args.len < 3 {
			return mk_err('cx-err:CXER0108', 'E_ARG: modify-doc expects ($store, $hash, $action)')
		}
		rhash := store_arg_str(args[1]) or { return none }
		if serr := store_addr_shape_err(rhash) {
			return serr
		}
		raction := args[2]
		if raction !is cx.Element {
			return mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: modify action must be an element')
		}
		// RULED: CO-2 (#975): the action's payload is the only vehicle by
		// which a modify can inject an [err] into a stored document — guard
		// it at the effect form, remote and local alike (opts = args[3]).
		if !(args.len > 3 && errs_permitted_node(args[3])) {
			if hit := find_err_at_rest(raction) {
				return err_boundary_refusal('store document write', hit)
			}
		}
		return store_remote_modify(ms.remote, rhash, render_canonical(raction))
	}
	if ms.read_only {
		return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${ms.url}')
	}
	hash := store_arg_str(args[1]) or { return none }
	if serr := store_addr_shape_err(hash) {
		return serr
	}
	if hash in ms.blob_kind {
		// F1': an opaque document has no structure to modify — one typed
		// refusal (delete + re-put-blob is the opaque edit).
		return mk_err('cx-err:CXER0100',
			'E_OPERAND_KIND: ${hash} is an opaque document (raw-byte identity) — modify-doc applies to structured documents only')
	}
	if !store_doc_present(ms, hash) {
		return mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: ${hash}')
	}
	doc_text := store_doc_text(ms, hash) or {
		if fe := store_s3_fail_err(mut ms) {
			return fe
		}
		return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
	}
	doc := store_decode_doc(doc_text)
	if doc !is cx.Element {
		return mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: doc root is not an element')
	}
	root_el := doc as cx.Element
	action := args[2]
	if action !is cx.Element {
		return mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: modify action must be an element')
	}
	// RULED: CO-2 (#975): see the remote branch above — same guard, local path.
	if !(args.len > 3 && errs_permitted_node(args[3])) {
		if hit := find_err_at_rest(action) {
			return err_boundary_refusal('store document write', hit)
		}
	}
	act := action as cx.Element
	// #134-1: an action MAY carry select="<cxpath>" to target nested child node(s)
	// instead of the document root. Same path subset as `query` (//name descendant,
	// /name direct-child; empty = the root element). #134-2: the `remove` action
	// deletes matched child node(s).
	mut sel := ''
	for a in act.attrs {
		if a.name == 'select' {
			sel = cx.scalar_value_str_public(a.value)
		}
	}
	el := store_modify_apply(root_el, sel.trim_space(), act) or {
		return mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: ${err.msg()}')
	}
	new_canonical := render_canonical(el)
	new_hash := cx.cx_text_hash(new_canonical) or {
		return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
	}
	if store_put_canonical(mut ms, new_hash, new_canonical) or {
		return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
	}
	{
		store_append(mut ms, store_doc_record(new_hash, new_canonical)) or {
			return store_persist_err(ms, err.msg())
		}
	}
	return store_str(new_hash)
}

// store_stdlib_builtin_env — env-aware store surface, consulted by the
// evaluator BEFORE the env-free chain (same tier as test/ft/log). Only
// `store-modify-doc` with a `[using FN]` action lands here: the FN closure
// must be applied with the evaluator env in scope (resolve_closure /
// invoke_closure — the SAME §8.10 engine behind [?modify]'s :using arm, no
// parallel lambda implementation). Every other store name/action returns
// none and falls through to the env-free chain unchanged.
fn store_stdlib_builtin_env(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	// L99 (stream-2 W6): quoted planar queries + explain-query are
	// env-aware (source-ref handle names resolve against the CALLER's
	// bindings). Claims store-query only for the quoted form; CXPath
	// strings fall through to the env-free store_query below.
	if r := store_planar_query_env(name, args, mut env) {
		return r
	}
	if name != 'store-modify-doc' || args.len < 3 {
		return none
	}
	action := args[2]
	if action !is cx.Element {
		return none
	}
	act := action as cx.Element
	if act.name != 'using' {
		return none
	}
	return store_modify_doc_using(args, act, mut env)
}

// store_modify_doc_using (#141) — `modify-doc` with the §8.10 `[using FN]`
// action. store.md says modify-doc "applies a Layer-1 action", and
// bindings.md's Layer-1 action table includes `[using FN]` — one of the
// eleven §8.10 actions, so the store verb must accept it. Semantics per
// code.md §8.10: FN receives each selected node; its return value replaces
// the node (ANY kind — kind-shift allowed); a non-callable `using` value and
// an FN that fails to produce a value are both CXER0104, never a silent
// no-op. A lambda is NEVER pushed to a server: on a remote-backed handle
// this degrades to get → transform locally → put — the result is the same
// new content-addressed hash either way (docs are immutable).
fn store_modify_doc_using(args []cx.Node, act cx.Element, mut env MatchEnv) ?cx.Node {
	mut ms, errn, ok := store_get_open(args[0])
	if !ok {
		return errn
	}
	// Resolve the closure operand FIRST — a non-callable value is a hard
	// CXER0104 on every backend, before any store I/O.
	mut resolved := ?Closure(none)
	for it in act.items {
		if c := resolve_closure(it, env) {
			resolved = c
			break
		}
	}
	closure := resolved or {
		return mk_err('cx-err:CXER0104',
			'E_USING_NOT_CALLABLE: modify-doc [using …] must be a [?fn] lambda')
	}

	mut sel := ''
	for a in act.attrs {
		if a.name == 'select' {
			sel = cx.scalar_value_str_public(a.value)
		}
	}
	uf := fn [closure, mut env] (el cx.Element) !cx.Node {
		result := invoke_closure(closure, [cx.Node(el)], mut env) or {
			return error('E_USING_FAILED: modify-doc [using …] body trapped: ${err.msg()}')
		}
		// §8.10: an FN that traps (yields an [err …] value) FAILED to produce
		// a value — CXER0104, not an err embedded as a document node. A
		// legitimate kind-shift yields a non-err value and passes through.
		if is_err_value(result) {
			return error('E_USING_FAILED: modify-doc [using …] body trapped: ${err_diagnostic(result)}')
		}
		return result
	}
	hash := store_arg_str(args[1]) or { return none }
	// Remote-backed handle: fetch, transform locally, put. The lambda never
	// crosses the wire — client-side execution is the ONLY lambda semantics
	// (a server cannot be asked to run caller code).
	if store_remote_active(ms) {
		text, gerr, gok := store_remote_get(ms.remote, hash)
		if !gok {
			return gerr
		}
		new_hash, new_canonical := store_modify_using_result(text, sel, uf) or {
			return store_using_err(err.msg())
		}
		perr := store_remote_put(ms.remote, new_hash, new_canonical)
		if is_err_value(perr) {
			return perr
		}
		return store_str(new_hash)
	}
	if ms.read_only {
		return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${ms.url}')
	}
	if !store_doc_present(ms, hash) {
		return mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: ${hash}')
	}
	doc_text := store_doc_text(ms, hash) or {
		if fe := store_s3_fail_err(mut ms) {
			return fe
		}
		return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
	}
	new_hash, new_canonical := store_modify_using_result(doc_text, sel, uf) or {
		return store_using_err(err.msg())
	}
	if store_put_canonical(mut ms, new_hash, new_canonical) or {
		return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
	}
	{
		store_append(mut ms, store_doc_record(new_hash, new_canonical)) or {
			return store_persist_err(ms, err.msg())
		}
	}
	return store_str(new_hash)
}

// store_modify_using_result decodes the doc, applies the using transform over
// the selection, and returns (new content hash, new canonical text). Shared
// by the local and remote (get → transform → put) paths so both produce the
// identical content address for the identical input.
fn store_modify_using_result(doc_text string, sel string, uf StoreUsingFn) !(string, string) {
	doc := store_decode_doc(doc_text)
	if doc !is cx.Element {
		return error('doc root is not an element')
	}
	root_el := doc as cx.Element
	result := store_modify_apply_using(root_el, sel.trim_space(), uf)!
	new_canonical := render_canonical(result)
	new_hash := cx.cx_text_hash(new_canonical)!
	return new_hash, new_canonical
}

// store_using_err maps a using-application error to its wire error: an FN
// failure is CXER0104 (per code.md §8.10), anything else (bad select path,
// unparseable doc) keeps the CXER0100 E_OPERAND_KIND shape of the env-free
// modify path.
fn store_using_err(msg string) cx.Node {
	if msg.starts_with('E_USING_FAILED') {
		return mk_err('cx-err:CXER0104', msg)
	}
	return mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: ${msg}')
}

// store_apply_action applies one in-place edit (set-attr / remove-attr / append
// / rename) to a single element and returns the modified element. The `remove`
// action is NOT handled here — it deletes a node, which store_modify_rebuild does
// at the parent level. Unknown actions are a hard error.
fn store_apply_action(elem cx.Element, act cx.Element) !cx.Node {
	mut el := elem
	match act.name {
		'set-attr' {
			mut aname := ''
			mut aval := ''
			for a in act.attrs {
				if a.name == 'name' {
					aname = cx.scalar_value_str_public(a.value)
				}
				if a.name == 'value' {
					aval = cx.scalar_value_str_public(a.value)
				}
			}
			mut found := false
			for mut a in el.attrs {
				if a.name == aname {
					a.value = cx.ScalarValue(aval)
					found = true
				}
			}
			if !found {
				el.attrs << cx.Attribute{
					name:  aname
					value: cx.ScalarValue(aval)
				}
			}
		}
		'remove-attr' {
			mut aname := ''
			for a in act.attrs {
				if a.name == 'name' {
					aname = cx.scalar_value_str_public(a.value)
				}
			}
			mut kept := []cx.Attribute{}
			for a in el.attrs {
				if a.name != aname {
					kept << a
				}
			}
			el.attrs = kept
		}
		'append' {
			for child in act.items {
				el.items << child
			}
		}
		'rename' {
			mut newname := ''
			for it in act.items {
				if it is cx.ScalarNode {
					newname = cx.scalar_value_str_public(it.value)
				}
			}
			if newname != '' {
				el.name = newname
			}
		}
		else {
			return error('unsupported modify action "${act.name}"')
		}
	}

	return cx.Node(el)
}

// store_modify_apply (#134-1/#134-2) applies `act` to nodes selected by `sel`
// within `root`, returning the rebuilt root. sel: '' = the root element itself
// (the original root-only behavior; `remove` here is an error — the document root
// cannot be removed); '//name' = every descendant element named `name`; '/name'
// (or bare `name`) = direct children of root named `name`. The path subset
// matches `query`. `[remove select=…]` deletes the matched node(s).
fn store_modify_apply(root cx.Element, sel string, act cx.Element) !cx.Element {
	is_remove := act.name == 'remove'
	if sel == '' {
		if is_remove {
			return error('remove requires a select path (the document root cannot be removed)')
		}
		nr := store_apply_action(root, act)!
		if nr is cx.Element {
			return nr as cx.Element
		}
		return error('modify action did not yield an element')
	}
	target, descendant, preds := store_parse_select(sel)!
	op := StoreModifyOp{
		act:       act
		is_remove: is_remove
	}
	return store_modify_rebuild(root, target, descendant, true, preds, op)
}

// store_parse_select parses an action's `select=` path into (target element
// name, descendant-axis flag, final-step predicates). Extracted from
// store_modify_apply so the `[using FN]` path (#141) shares EXACTLY the same
// select semantics — including the fail-closed predicate handling — with the
// other actions.
//
// #141: a select MAY carry a step predicate (`//t[@mmsi='1']`) to target
// ONE element of a keyed collection. Parse the path via the canonical
// path parser so the final step's element-name and its predicate(s) are
// recovered separately — the old code used the whole remainder as the
// element name, so any `[…]` predicate made the name un-matchable and the
// modify silently became a no-op. The predicate(s) are evaluated per
// candidate by `store_elem_matches_predicates` (the canonical
// PredicateExpr engine), consistent with the cx path engine used in
// `for`-expressions and `query`.
fn store_parse_select(sel string) !(string, bool, []cx.PathPredicate) {
	mut descendant := false
	mut rest := sel
	if rest.starts_with('//') {
		descendant = true
		rest = rest[2..]
	} else if rest.starts_with('/') {
		rest = rest[1..]
	}
	if rest == '' {
		return error('empty select path')
	}
	mut target := rest
	mut preds := []cx.PathPredicate{}
	has_pred_syntax := rest.contains('[')
	if path := cx.parse_path(sel) {
		if path.steps.len > 0 {
			last := path.steps[path.steps.len - 1]
			nt := last.node_test.trim_space()
			if nt.len > 0 && nt != '*' && !nt.contains('(') {
				target = nt
			}
			preds = last.predicates.clone()
		}
	}
	if has_pred_syntax && preds.len == 0 {
		// A predicate was written but could not be parsed/extracted. Fail
		// CLOSED (error) rather than dropping the predicate and matching
		// every element — silently widening a keyed `remove` to the whole
		// collection would be far worse than a clear error.
		return error('unsupported select predicate in "${sel}"')
	}
	// Strip any residual predicate text if the parser did not yield a clean
	// element-name token (keeps the bare-name match correct).
	if i := target.index('[') {
		target = target[..i]
	}
	if target == '' {
		return error('empty select path')
	}
	return target, descendant, preds
}

// StoreUsingFn applies the resolved `[using FN]` closure to one matched
// element, returning its replacement — ANY kind (§8.10 kind-shift).
type StoreUsingFn = fn (cx.Element) !cx.Node

// StoreModifyOp is the walker's operation: either a plain action element
// (set-attr / remove-attr / append / rename, with `remove` handled at the
// parent level), or — when `using_fn` is set — the #141 `[using FN]`
// computed replacement.
struct StoreModifyOp {
	act       cx.Element
	is_remove bool
	using_fn  ?StoreUsingFn
}

// store_modify_apply_using (#141) applies the §8.10 `[using FN]` action: FN
// replaces each node selected by `sel`, with the SAME select semantics as
// every other action (store_parse_select + fail-closed predicates). Empty
// sel = the document root: FN's return becomes the whole new doc. The result
// is a cx.Node, not necessarily an element — kind-shift is allowed.
fn store_modify_apply_using(root cx.Element, sel string, uf StoreUsingFn) !cx.Node {
	if sel == '' {
		return uf(root)!
	}
	target, descendant, preds := store_parse_select(sel)!
	op := StoreModifyOp{
		act:      cx.Element{
			name: 'using'
		}
		using_fn: uf
	}
	return cx.Node(store_modify_rebuild(root, target, descendant, true, preds, op)!)
}

// store_elem_matches_predicates evaluates the final-step predicate(s) of a
// `select` path against a single candidate element, reusing the canonical
// `eval_predicate_filter` engine (the same evaluator that powers CXPath
// predicates in `for`-expressions, e.g. `$d//t[@mmsi='1']`). Returns true
// iff EVERY predicate holds. An empty predicate list matches unconditionally
// (the bare-name path already gated entry). A predicate whose shape the
// engine does not support fails CLOSED (returns false) so a keyed select can
// never accidentally widen to every element — critical for the destructive
// `remove` action (#141).
fn store_elem_matches_predicates(el cx.Element, preds []cx.PathPredicate) bool {
	if preds.len == 0 {
		return true
	}
	mut attrs := map[string]string{}
	for a in el.attrs {
		attrs[a.name] = cx.scalar_value_str_public(a.value)
	}
	mut child_count := 0
	for it in el.items {
		if it is cx.Element {
			child_count++
		}
	}
	item := Item{
		kind:           'element'
		name:           el.name
		attrs:          attrs
		children_count: child_count
	}
	ctx := PredicateEvalContext{
		bindings: map[string]Value{}
	}
	for pred in preds {
		expr := pred.expr or {
			// No parsed expr available — cannot evaluate; fail closed.
			return false
		}

		filtered := eval_predicate_filter([item], expr, ctx) or {
			// Unsupported predicate shape — fail closed (do NOT match).
			return false
		}
		if filtered.len == 0 {
			return false
		}
	}
	return true
}

// store_modify_rebuild walks an element, applying the op to (or, for `remove`,
// deleting) child elements named `target`. `match_here` gates whether matches
// apply at the current level: true everywhere for the descendant axis, true only
// at the root level for the child axis (deeper structure is preserved verbatim).
fn store_modify_rebuild(el cx.Element, target string, descendant bool, match_here bool, preds []cx.PathPredicate, op StoreModifyOp) !cx.Element {
	mut new_items := []cx.Node{}
	for item in el.items {
		if item is cx.Element {
			child := item as cx.Element
			// #141: a name match is necessary but not sufficient — the
			// step predicate(s) must also hold, so `//t[@mmsi='1']` hits
			// exactly the keyed element, not every `t`.
			if match_here && child.name == target && store_elem_matches_predicates(child, preds) {
				if uf := op.using_fn {
					// #141 [using FN]: the replacement is a NEW computed
					// value — the walker does not descend into it looking
					// for further matches (the outermost match wins), unlike
					// set-attr &co whose result preserves the original
					// structure.
					new_items << uf(child)!
					continue
				}
				if op.is_remove {
					continue // delete the matched node
				}
				nr := store_apply_action(child, op.act)!
				if descendant && nr is cx.Element {
					new_items << cx.Node(store_modify_rebuild(nr as cx.Element, target, descendant,
						true, preds, op)!)
				} else {
					new_items << nr
				}
			} else if descendant {
				new_items << cx.Node(store_modify_rebuild(child, target, descendant, true, preds, op)!)
			} else {
				new_items << item // child axis: deeper structure unchanged
			}
		} else {
			new_items << item
		}
	}
	return cx.Element{
		...el
		items: new_items
	}
}

// StoreQueryMatch is one (doc-hash, match) pair of the row-path scan — the
// shared substrate under [$store:query] (which wraps each pair in the L97
// provenance tuple) and [$store:source] (which returns the payloads).
struct StoreQueryMatch {
	hash string
	node cx.Node
}

// store_source_ref spells the L97 source-reference string carried on every
// query tuple's `source=` attribute: the store's canonical URL + `#` + the
// CXPath as given (store.md §6.2).
fn store_source_ref(ms &MemStore, cxpath string) string {
	return '${ms.url}#${cxpath}'
}

// store_query_tuple builds one row of the L97 flat provenance-bearing
// relation: [result doc=HASH source=REF MATCH] (store.md §6.2/§12).
fn store_query_tuple(doc_hash string, source_ref string, m cx.Node) cx.Node {
	return cx.Element{
		name:  'result'
		attrs: [
			cx.Attribute{
				name:  'doc'
				value: cx.ScalarValue(doc_hash)
			},
			cx.Attribute{
				name:  'source'
				value: cx.ScalarValue(source_ref)
			},
		]
		items: [m]
	}
}

// store_query_plan parses a query CXPath into its name-path steps and the
// FINAL step's predicates, refusing (error) anything outside the shipped §12
// subset: plain-name child/descendant steps, predicates on the final step
// only, a leading `//`. Fail-closed — an unsupported axis, wildcard, function
// step, or intermediate predicate is an error, never a silently-wrong walk
// (the pre-fix engine matched the LAST segment's name only, answering
// `/meta/src` with root-level `src` elements — the exact silent-wrong-answer
// class this closes).
fn store_query_plan(elem_path string) !(cx.PathNode, []cx.PathPredicate) {
	path := cx.parse_path(elem_path)!
	if path.form !in [cx.PathForm.absolute, cx.PathForm.relative, cx.PathForm.descendant] {
		return error('path form `${path.form}` is not a name path')
	}
	if path.steps.len == 0 {
		return error('empty path')
	}
	for i, st in path.steps {
		if st.axis !in [cx.PathAxis.child, cx.PathAxis.descendant, cx.PathAxis.descendant_or_self] {
			return error('unsupported axis `${st.axis}` at step ${i + 1}')
		}
		nt := st.node_test.trim_space()
		if nt == '' || nt == '*' || nt.contains('(') {
			return error('unsupported node test `${st.node_test}` at step ${i + 1}')
		}
		if st.predicates.len > 0 && i != path.steps.len - 1 {
			return error('predicates are supported on the final step only')
		}
	}
	return path, path.steps[path.steps.len - 1].predicates
}

// store_query_walk evaluates the planned name-path steps over one decoded
// doc, STEPWISE, anchored at the DOCUMENT node (#768, ruled 2026-08-10 —
// XPath-correct): `/a` selects the ROOT element when named a (so a
// per-entity doc whose root IS the entity is addressable); `//a` is
// descendant-or-self (the root INCLUDED) plus every descendant named a;
// `/a/b` = b children of a root named a; `//a/b` = b children of a elements
// at any depth; `//a//b` = b descendants of those a's. Returns the final
// step's candidates in document order (the root precedes its descendants).
fn store_query_walk(doc cx.Node, path cx.PathNode) []cx.Node {
	first := path.steps[0]
	mut cur := []cx.Node{}
	first_desc := path.form == cx.PathForm.descendant
		|| first.axis in [cx.PathAxis.descendant, cx.PathAxis.descendant_or_self]
	if doc is cx.Element && doc.name == first.node_test {
		// The document node's child axis reaches the root element itself.
		cur << doc
	}
	if first_desc {
		store_collect_by_name(doc, first.node_test, true, mut cur)
	}
	for si in 1 .. path.steps.len {
		st := path.steps[si]
		desc := st.axis in [cx.PathAxis.descendant, cx.PathAxis.descendant_or_self]
		mut next := []cx.Node{}
		for c in cur {
			store_collect_by_name(c, st.node_test, desc, mut next)
		}
		cur = next.clone()
	}
	return cur
}

// store_query_scan is the row-path CXPath scan: (doc-hash, match) pairs in
// (doc insertion order × document order). §3.5/§12 SUBSET: multi-segment
// plain-name paths (child + descendant axes), FINAL-step predicates, and a
// trailing attribute axis. The full CXPath grammar + parallel scan are
// deferred to the integration suite. A failure returns the err VALUE via the
// (matches, errn, ok) triple — never a silent empty.
fn store_query_scan(ms &MemStore, path_text string) ([]StoreQueryMatch, cx.Node, bool) {
	// #192: a trailing attribute step (`/@name`) and element predicates
	// (`[= $_@k 'v']`) reuse the same predicate engine as modify-doc's
	// `select=`, so `query` and `modify` are symmetric. A path the plan cannot
	// evaluate exactly fails CLOSED with CXER1709 (never a silent empty result
	// masquerading as "no matches" — the exact bug this closes).
	attr_name, elem_path := store_query_split_attr(path_text)
	path, preds := store_query_plan(elem_path) or {
		return []StoreQueryMatch{}, mk_err('cx-err:CXER1709',
			'E_CSRP_OPERATION_UNSUPPORTED: query CXPath `${path_text}` has an unsupported predicate/step (${err.msg()}) — refusing to return a lying empty result'), false
	}
	mut out := []StoreQueryMatch{}
	for h in ms.doc_order {
		if h in ms.blob_kind {
			// F1': opaque documents carry no queryable structure — the
			// structured query walks structured docs only.
			continue
		}
		text := store_doc_text(ms, h) or {
			return []StoreQueryMatch{}, mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}'), false
		}
		doc := store_decode_doc(text)
		elems := store_query_walk(doc, path)
		for e in elems {
			if e is cx.Element {
				if !store_elem_matches_predicates(e, preds) {
					continue
				}
				if attr_name != '' {
					// attribute axis: emit the attribute VALUE (a scalar), or skip
					// the element when the attribute is absent.
					if av := store_elem_attr_node(e, attr_name) {
						out << StoreQueryMatch{
							hash: h
							node: av
						}
					}
				} else {
					out << StoreQueryMatch{
						hash: h
						node: e
					}
				}
			}
		}
	}
	return out, store_null(), true
}

// store_source implements [$store:source]: the L97 source-form scan — the
// SAME CXPath evaluation as [$store:query], returning the matched VALUES
// (the query tuples' payloads, same order, no provenance wrapper). This is
// THE store-side generator source form for planar comprehensions (code.md
// §7.8): `[?for [in $o [$store:source $s "//order"]] …]` binds `$o` to each
// match, and the comprehension's source set stays nameable from the text.
fn store_source(args []cx.Node) ?cx.Node {
	ms, errn, ok := store_get_open(args[0])
	if !ok {
		return errn
	}
	path_text := (store_arg_str(args[1]) or { return none }).trim_space()
	if store_remote_active(ms) {
		// The wire carries the L97 tuples; the source form is their payloads.
		r := store_remote_query(ms.remote, path_text)
		if is_err_value(r) {
			return r
		}
		mut vals := []cx.Node{}
		if r is cx.Element {
			for it in r.items {
				if it is cx.Element && it.name == 'result' && it.items.len == 1 {
					vals << it.items[0]
				}
			}
		}
		return store_seq(vals)
	}
	if ms.backend == 'columnar' {
		// The same pushdown envelope as query — identical values from either
		// executor (the L97 parity contract).
		$if cxstore_columnar ? {
			if pairs := store_columnar_query_matches(ms, path_text) {
				mut vals := []cx.Node{cap: pairs.len}
				for p in pairs {
					vals << p.node
				}
				return store_seq(vals)
			}
		}
	}
	pairs, qerr, qok := store_query_scan(ms, path_text)
	if !qok {
		return qerr
	}
	mut vals := []cx.Node{cap: pairs.len}
	for p in pairs {
		vals << p.node
	}
	return store_seq(vals)
}

// store_query_rebase_source rewrites each tuple's `source=` to the CALLER's
// source reference. A remote answer arrives with the SERVER's own store URL
// (its honest local provenance), but the caller's coordinates for that source
// are its handle URL — the rebase keeps provenance caller-coherent and keeps
// the server's local URL spelling out of caller-visible tuples (beyond what
// `capabilities` already reports). Non-tuple nodes (err values) pass through.
fn store_query_rebase_source(r cx.Node, src string) cx.Node {
	if r is cx.Element {
		if r.name == 'err' {
			return r
		}
		mut items := []cx.Node{cap: r.items.len}
		for it in r.items {
			if it is cx.Element && it.name == 'result' {
				mut attrs := []cx.Attribute{cap: it.attrs.len}
				for a in it.attrs {
					if a.name == 'source' {
						attrs << cx.Attribute{
							name:  'source'
							value: cx.ScalarValue(src)
						}
					} else {
						attrs << a
					}
				}
				items << cx.Element{
					...it
					attrs: attrs
				}
			} else {
				items << it
			}
		}
		return cx.Element{
			...r
			items: items
		}
	}
	return r
}

// store_query implements [$store:query]: the L97 FLAT provenance-bearing
// relation — one [result doc= source= MATCH] tuple per match (store.md
// §6.2/§12; the former doc-keyed [result hash= [seq …]] nesting is retired).
// Both execution paths (this row scan and the columnar column projection)
// emit the identical relation — the #711 shape-parity contract.
fn store_query(args []cx.Node) ?cx.Node {
	ms, errn, ok := store_get_open(args[0])
	if !ok {
		return errn
	}
	// The CXPath argument is a plain string scalar; take its raw value, NOT
	// render_canonical (which would quote it to `'//user'` and defeat the
	// `//` / `/` prefix check).
	path_text := (store_arg_str(args[1]) or { return none }).trim_space()
	// Remote backend: push the query to the server instead of scanning the
	// local doc map — which is EMPTY for a remote-backed handle, so the old code
	// silently returned `()` even when the server had matches (#119). A backend
	// without query pushdown raises CXER1709 rather than lying with an empty seq.
	if store_remote_active(ms) {
		r := store_remote_query(ms.remote, path_text)
		return store_query_rebase_source(r, store_source_ref(ms, path_text))
	}
	src := store_source_ref(ms, path_text)
	if ms.backend == 'columnar' {
		// #129 D5 §6: a column-projecting query is lowered to a columnar scan that
		// reads only the projected column (not every doc). A path that does not
		// reduce to a single promoted column returns none here and falls through to
		// row materialization below (which reads __cx_doc) — correct, just not
		// accelerated. No silent full-scan masquerading as pushdown.
		$if cxstore_columnar ? {
			if pairs := store_columnar_query_matches(ms, path_text) {
				mut results := []cx.Node{}
				for p in pairs {
					results << store_query_tuple(p.hash, src, p.node)
				}
				return store_seq(results)
			}
		}
	}
	pairs, qerr, qok := store_query_scan(ms, path_text)
	if !qok {
		return qerr
	}
	mut results := []cx.Node{}
	for p in pairs {
		results << store_query_tuple(p.hash, src, p.node)
	}
	return store_seq(results)
}

// store_query_split_attr splits a CXPath ending in a `/@attr` attribute step into
// (attr-name, element-path). Returns ('', path) when there is no trailing
// attribute step. Only a FINAL attribute step is an axis (`//user/@email`);
// `@k=` inside `[…]` is a predicate handled by store_parse_select.
fn store_query_split_attr(path string) (string, string) {
	idx := path.last_index('/@') or { return '', path }
	// the `@` must be after the last `]` (else it is inside a predicate).
	last_pred := path.last_index(']') or { -1 }
	if idx < last_pred {
		return '', path
	}
	attr := path[idx + 2..]
	// a bare attr name only (no further steps / brackets)
	if attr == '' || attr.contains('/') || attr.contains('[') {
		return '', path
	}
	return attr, path[..idx]
}

// store_elem_attr_node returns an element's attribute value as a scalar node, or
// none when the attribute is absent (the attribute-axis match).
fn store_elem_attr_node(el cx.Element, name string) ?cx.Node {
	for a in el.attrs {
		if a.name == name {
			return cx.Node(cx.ScalarNode{
				value:     a.value
				data_type: cx.ScalarType.string_type
			})
		}
	}
	return none
}

// store_collect_by_name walks `node` collecting elements named `target`.
// When `descendant` is true it recurses into every descendant; otherwise
// it inspects only the direct children of the root element.
fn store_collect_by_name(node cx.Node, target string, descendant bool, mut out []cx.Node) {
	if node is cx.Element {
		for child in node.items {
			if child is cx.Element {
				if child.name == target {
					out << child
				}
			}
			if descendant {
				store_collect_by_name(child, target, descendant, mut out)
			}
		}
	}
}

// store_migrate implements §3.10: copy every doc + alias from `from` to
// `to`, re-validating integrity on fetch. Doc IDs are content hashes, so
// IDs are preserved. Returns the migration-report element.
fn store_migrate(args []cx.Node) ?cx.Node {
	from, ferr, fok := store_get_open(args[0])
	if !fok {
		return ferr
	}
	mut to, terr, tok := store_get_open(args[1])
	if !tok {
		return terr
	}
	if to.read_only {
		return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${to.url}')
	}
	// Stream 20: erasure attribution rides the copy — but columnar persists
	// no E records, so tombstone attribution would silently vanish there on
	// the first flush (the columnar carriage gap, recorded); refuse instead.
	if to.backend == 'columnar' && from.erased.len > 0 {
		return mk_err('cx-err:CXER1144',
			'E_STORE_SUBJECT_UNSUPPORTED: migrate destination ${to.url} is columnar — it persists no erasure tombstones, so ${from.erased.len} lawful-erasure attribution record(s) would be dropped (erasure_compliance §6/§7)')
	}
	mut doc_count := 0
	mut verified := 0
	mut bytes_written := 0
	for h in from.doc_order {
		if h in from.blob_kind {
			// F1' opaque blob: read through the VERIFYING blob path (raw-hash
			// checked at the read boundary), copy through the blob channel so
			// the destination keeps the kind — never the canonical doc path.
			raw := store_get_blob_local(from, h) or {
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${h}: ${err.msg()}')
			}
			key := store_put_blob_local(mut to, raw) or {
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${h}: ${err.msg()}')
			}
			if key != h {
				return mk_err('cx-err:CXER1120',
					'E_STORE_INTEGRITY_MISMATCH: blob ${h} re-keyed to ${key} on migrate')
			}
			bytes_written += raw.len
			verified++
			doc_count++
			continue
		}
		// Route through the doc abstraction on BOTH sides so migration copies the
		// real docs regardless of each store's model (object-graph stores keep docs
		// in the graph, not the flat `docs` map). A reconstruct failure on the source
		// is a hard integrity error — never a silent skip / zero-doc migration.
		text := store_doc_text(from, h) or {
			return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${h}: ${err.msg()}')
		}
		rehash := cx.cx_text_hash(text) or {
			return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${h}')
		}
		if rehash != h {
			return mk_err('cx-err:CXER1120',
				'E_STORE_INTEGRITY_MISMATCH: stored ${h} rehashes to ${rehash}')
		}
		verified++
		// Stream 20: a subject-bearing doc routes through the subject arm on
		// the destination (whole-doc sealed object under the destination's
		// OWN SEK; custody refusals CXER1144 apply there) — the plain path
		// would silently re-key it under the tenant KEK and defeat
		// crypto-shredding at the copy.
		mut routed := false
		if text.contains('subject=') {
			if pd := cx.parse(text) {
				if pd.elements.len > 0 {
					if subj := store_subject_attr(pd.elements[0]) {
						r := store_put_doc_subject(mut to, pd.elements[0], subj, text,
							h)
						if is_err_value(r) {
							return r
						}
						routed = true
						bytes_written += text.len
					}
				}
			}
		}
		if !routed {
			if store_put_canonical(mut to, h, text) or {
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${h}: ${err.msg()}')
			}
			{
				bytes_written += text.len
			}
		}
		doc_count++
	}
	for a in from.alias_order {
		store_alias_set_local(mut to, a, from.aliases[a])
	}
	store_erased_carry(from, mut to) or {
		return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: migrate: erased-map carriage: ${err.msg()}')
	}
	store_persist(mut to) or { return store_persist_err(to, err.msg()) }
	to.log_records = to.doc_order.len + to.alias_order.len
	return cx.Element{
		name:  'migration-report'
		attrs: [
			cx.Attribute{
				name:  'doc-count'
				value: cx.ScalarValue(i64(doc_count))
			},
			cx.Attribute{
				name:  'hashes-verified'
				value: cx.ScalarValue(i64(verified))
			},
			cx.Attribute{
				name:  'bytes-written'
				value: cx.ScalarValue(i64(bytes_written))
			},
		]
	}
}

// ── bundled module source ────────────────────────────────────────────
//
// The canonical cx-stdlib/store surface (stdlib/store.cx) is embedded as
// stdlib_src_store in Ring-1 stdlib_bundle.v with the other bundle
// sources (relocated at I3 seam H — a Ring-1 file must not reference a
// const defined in this Ring-2 pack). Bodies forward to the native
// primitives above.
