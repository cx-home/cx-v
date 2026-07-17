@[has_globals]
module code

import cx
import cxstore
import io
import os
import sync

// errno/ESRCH for the stale-tmp sweep's kill(pid, 0) liveness probe (#292);
// C.kill itself is declared in stdlib_process.v (same module).
#include <errno.h>

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
	model       string
	// root is the filesystem directory for the `file://` backend (the path
	// component of the open URL); empty for the in-process `mem://` backend.
	root        string
	docs        map[string]string
	doc_order   []string
	aliases     map[string]string
	alias_order []string
	// op_lock serializes access to this store's mutable state. A Store handle
	// is single-owner; `[par]` over one shared handle used to race the docs/
	// aliases maps and crash the process (#74 Defect 2). Each op claims the
	// lock with a non-blocking try_lock; a contending thread gets a clean
	// E_STORE_HANDLE_RACE value instead of a segfault. Lazily allocated at
	// open (a nil lock = legacy/unopened handle → guard is skipped).
	op_lock &sync.Mutex = unsafe { nil }
	// log_records counts records currently in the on-disk append log (#74
	// Defect 1). file:// mutations APPEND one record instead of rewriting the
	// whole index (O(n) per op → O(n^2) total); when the log accumulates enough
	// redundancy vs live state it is compacted back to a snapshot. mem:// unused.
	log_records int
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
	graph_logical       i64      // Σ live-doc objects if NOTHING were shared
	graph_distinct      int      // distinct objects reachable from the live docs
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
		f.write_string(store_doc_record_header(h, body.len))!
		f.write_string(body)!
		f.write_string('\n')!
	}
	for a in ms.alias_order {
		hash := ms.aliases[a]
		f.write_string(store_alias_record_header(a.len, hash))!
		f.write_string(a)!
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
fn store_read_index(path string, mut ms MemStore) {
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
			body := store_read_exact(mut br, parts[2].int()) or { break }
			// trailing record newline
			store_read_exact(mut br, 1) or { break }
			recs++
			if hash !in ms.docs {
				ms.docs[hash] = body
				ms.doc_order << hash
			}
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

fn store_doc_record(h string, body string) string {
	return '${store_doc_record_header(h, body.len)}${body}\n'
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
fn store_append(mut ms MemStore, rec string) ! {
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
	os.mkdir_all(ms.root) or { return error('file ${ms.root}: mkdir failed: ${err.msg()}') }
	idx := os.join_path(ms.root, store_index_name)
	if !os.exists(idx) {
		os.write_file(idx, 'CXSTORE\tv1\n${rec}') or {
			return error('file ${ms.root}: index write failed: ${err.msg()}')
		}
		ms.log_records = 1
		return
	}
	mut f := os.open_append(idx) or {
		return error('file ${ms.root}: index open failed: ${err.msg()}')
	}
	f.write_string(rec) or {
		f.close()
		return error('file ${ms.root}: index append failed: ${err.msg()}')
	}
	f.close()
	ms.log_records++
	// Compaction: when redundancy builds up (each alias update / re-append adds
	// a record without growing live state), snapshot the live model and reset
	// the log to live size. Insert-only workloads append zero redundancy, so
	// this never fires for them.
	live := ms.doc_order.len + ms.alias_order.len
	if ms.log_records > 2 * live + 64 {
		store_persist(mut ms)!
		ms.log_records = live
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
}

__global (
	g_store_reg voidptr
)

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
	mut reg := store_reg()
	reg.next_id++
	id := reg.next_id
	reg.stores[id] = ms
	return id
}

fn store_lookup(id int) ?&MemStore {
	reg := store_reg()
	return reg.stores[id] or { return none }
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
		name:  seq_marker_name
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
	doc_count int     // unique content hashes currently held (master-index size)
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
	locked := ms.op_lock != unsafe { nil }
	if locked {
		mut lk := ms.op_lock
		lk.@lock()
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
	if locked {
		mut lk := ms.op_lock
		lk.unlock()
	}
	return stats
}

// store_objgraph_stats builds the object-graph introspection for a cxpack mount,
// reusing the cached dedup walk when the (doc_count, object_count) fingerprint is
// unchanged since the last computation. Caller holds the op-lock.
fn store_objgraph_stats(mut ms MemStore, doc_count int) StoreStats {
	// Distinct-object count: the durable backend's when there is one (the lazy disk
	// backends do not slurp every object into the sink), else the in-memory sink.
	object_count := if be := ms.obj_backend {
		be.object_count()
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
	ms := store_lookup(id) or {
		return unsafe { nil }, mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: unknown Store handle ${id}'), false
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
// (#129 D5 / #76; spec/02-working/cxstore_columnar_backend.md). Columnar is a
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
		's3' { 'net' }
		else { if read_only { 'read' } else { 'write' } }
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
				return store_columnar_open(base_url, path, encoding, codec, read_only,
					schema_text)
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
		return mk_err('cx-err:CXER1115', 'E_STORE_SCHEMA_VIOLATION: schema load/validate error: ${err.msg()}')
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

fn store_open_impl(url string, compression string, encoding string, read_only bool, tls_verify bool, auth map[string]string) cx.Node {
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
				if (model_prefix != '' || auth['model'] != '') && want_doc != (det_model == 'document') {
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
				// document model on `file` = the flat index store.
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
				}
				idx := os.join_path(root, store_index_name)
				if !read_only {
					// #292: sweep dead writers' orphaned snapshot temps before
					// touching the index (never the live index, never a live
					// pid's in-flight temp — see store_sweep_stale_tmp).
					store_sweep_stale_tmp(root)
				}
				if os.exists(idx) {
					store_read_index(idx, mut ms)
				} else if !read_only {
					os.mkdir_all(root) or {
						return mk_err('cx-err:CXER1100',
							'E_STORE_UNRESOLVED_BACKEND: cannot create ${root}: ${err.msg()}')
					}
				}
				id := store_register(ms)
				return store_handle_element(id, ms)
			}
			// subtree model — object-per-key on request, pack by default.
			if want_framing == 'object-per-key' {
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
				}
				if !read_only {
					os.mkdir_all(root) or {
						return mk_err('cx-err:CXER1100',
							'E_STORE_UNRESOLVED_BACKEND: cannot create ${root}: ${err.msg()}')
					}
				}
				store_cxobj_load(mut ms) or {
					return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
				}
				id := store_register(ms)
				return store_handle_element(id, ms)
			}
			// obj_pack attaches lazily in store_cxpack_load (store_cxpack_backend
			// picks keyed vs plain mode from enc_key_id, #229).
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
			}
			if !read_only {
				os.mkdir_all(root) or {
					return mk_err('cx-err:CXER1100',
						'E_STORE_UNRESOLVED_BACKEND: cannot create ${root}: ${err.msg()}')
				}
			}
			store_cxpack_load(mut ms) or {
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
			}
			id := store_register(ms)
			return store_handle_element(id, ms)
		}
		'sqlite' {
			// §9 + #77: sqlite:// external engine. Feature-gated via
			// `-d cxstore_sqlite` so the default/core/wasm build never links
			// libsqlite3; without the flag, error clearly (degrade-with-visibility).
			mut r := mk_err('cx-err:CXER1100', 'E_STORE_UNRESOLVED_BACKEND: sqlite backend not built — rebuild with `-d cxstore_sqlite` (${url})')
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
				kms := store_kek_kms(auth['encrypt-key-id']) or {
					return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
				}
				s3ob = cxstore.ObjectBackend(cxstore.new_encrypting_wrapper(s3be, auth['encrypt-key-id'],
					kms))
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
		'http', 'https', 'ftp', 'ftps', 'sftp', 'cx-store', 'cx-store+http', 'cx-store+https',
		'cx-store+grpc', 'cx-store+grpcs' {
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
			if scheme in ['cx-store', 'cx-store+http', 'cx-store+https'] {
				ms.obj_backend = cxstore.ObjectBackend(new_remote_object_backend(rb))
				// #234.2 / §5.3: capability discovery at open over the http(s) CSRP wire.
				// Validates the server's csrp-version (same major) and caches its
				// advertised encodings. A version mismatch fails the open; an
				// unreachable server is tolerated (lazy open, the first op surfaces it).
				disc := csrp_client_discover(mut rb)
				if is_err_value(disc) {
					return disc
				}
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
			if ms.columnar_s3 != none { 's3' } else { 'file' }
		}
		else {
			ms.backend
		}
	}
}

fn store_handle_element(id int, ms &MemStore) cx.Node {
	writable := !ms.read_only
	return cx.Element{
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
		'store-put-def', 'store-delete-doc', 'store-modify-doc', 'store-set-alias',
		'store-delete-alias', 'store-migrate', 'store-clone', 'store-push', 'store-pull',
		'store-fetch', 'store-gc', 'store-prune', 'store-rotate-kek', 'store-branch',
		'store-branch-force']
}

// store_op_needs_no_cap names the introspection/lifecycle ops that take no host
// capability (open/open-opts are handled before dispatch; csrp-handle has its own
// net gate).
fn store_op_needs_no_cap(name string) bool {
	return name in ['store-close', 'store-capabilities', 'store-csrp-handle']
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
	if !ms.op_lock.try_lock() {
		return mk_err(store_err_handle_race,
			'E_STORE_HANDLE_RACE: concurrent access to a shared Store handle — a Store is single-owner; shard (open separate handles per worker) for parallelism, `[par]` on one handle is unsupported')
	}
	defer {
		ms.op_lock.unlock()
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
			return store_open_impl(url, compression, encoding, read_only, tls_verify, auth)
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
			if ms.backend == 'columnar' && ms.columnar_schema != '' {
				if v := store_columnar_schema_violation(ms, cx.Document{ elements: [args[1]] }) {
					return v
				}
			}
			canonical := render_canonical(args[1])
			hash := cx.cx_text_hash(canonical) or {
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: hash failed: ${err.msg()}')
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
			} {
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
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: undecodable doc text: ${err.msg()}')
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
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: undecodable doc text: ${err.msg()}')
			}
			hash := cx.cx_text_hash(canonical) or {
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: hash failed: ${err.msg()}')
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
			} {
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
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
			}
			return store_str(text)
		}
		'store-csrp-handle' {
			// CSRP reference-server per-request handler (#78); impl in store_csrp.v.
			return store_csrp_handle(args)
		}
		'store-get-doc' {
			mut ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			hash := store_arg_str(args[1]) or { return none }
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
					return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
				}
			}
			rehash := cx.cx_text_hash(text) or {
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${hash}')
			}
			if rehash != hash {
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: stored ${hash} rehashes to ${rehash}')
			}
			parsed := cx.parse(text) or {
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: undecodable doc at ${hash}')
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
				sch := ms.remote.scheme
				if sch == 'cx-store' || sch == 'cx-store+http' || sch == 'cx-store+https'
					|| sch == 'cx-store+grpc' || sch == 'cx-store+grpcs' {
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
						attrs: [cx.Attribute{
							name:  'hash'
							value: cx.ScalarValue(h)
						}]
						items: [store_decode_doc(t)]
					}
				}
				return store_seq(items)
			}
			for h in ms.doc_order {
				text := store_doc_text(ms, h) or {
					return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
				}
				doc_node := store_decode_doc(text)
				items << cx.Element{
					name:  'entry'
					attrs: [cx.Attribute{
						name:  'hash'
						value: cx.ScalarValue(h)
					}]
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
		'store-put-def' {
			// #128-A: store CX code by Tier-2 code identity (alpha/comment-
			// insensitive, dependency-by-hash). Source is held verbatim (code does
			// not data-parse) in the `code:` namespace, deduped by identity.
			mut ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			if ms.read_only {
				return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${ms.url}')
			}
			src := store_arg_str(args[1]) or { return none }
			h := cx_code_store_put_def(mut ms, src) or {
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: code put: ${err.msg()}')
			}
			// persist hook: cxpack snapshots the whole graph (code included); the
			// flat-index backends append a record keyed by the code: namespace.
			store_append(mut ms, store_doc_record('code:${h}', src)) or {
				return store_persist_err(ms, err.msg())
			}
			return store_str(h)
		}
		'store-get-def' {
			ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			hash := store_arg_str(args[1]) or { return none }
			src := cx_code_store_get_def(ms, hash) or { return store_empty() }
			return store_str(src)
		}
		'store-query' {
			return store_query(args)
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
			ms.is_open = false
			return store_null()
		}
		'store-set-alias' {
			mut ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			// CSRP carries NO alias verbs (M3): on a remote-backed handle the
			// local alias map is dead state, so a silent no-op ack would lie.
			// Same posture as query pushdown (#119) — CXER1709, never empty (#264).
			if store_remote_active(ms) {
				return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: set-alias — CSRP carries no alias verbs; aliases are local-registry state (discover remotely via store-query pushdown)')
			}
			if ms.read_only {
				return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${ms.url}')
			}
			alias := store_arg_str(args[1]) or { return none }
			hash := store_arg_str(args[2]) or { return none }
			// the target may be a data doc (bare hash) OR a code def (stored under
			// the code: namespace by Tier-2 identity, #128-A) — accept either.
			if !store_doc_present(ms, hash) && !store_doc_present(ms, 'code:${hash}') {
				return mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: alias target ${hash}')
			}
			if alias !in ms.aliases {
				ms.alias_order << alias
			}
			ms.aliases[alias] = hash
			store_append(mut ms, store_alias_record(alias, hash)) or {
				return store_persist_err(ms, err.msg())
			}
			return store_null()
		}
		'store-get-alias' {
			ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			if store_remote_active(ms) {
				return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: get-alias — CSRP carries no alias verbs; a remote miss is indistinguishable from absence, so the op refuses instead (#264)')
			}
			alias := store_arg_str(args[1]) or { return none }
			if alias in ms.aliases {
				return store_str(ms.aliases[alias])
			}
			return store_empty() // §9.1.2: alias miss → absence, not null
		}
		'store-list-aliases' {
			ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			if store_remote_active(ms) {
				return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: list-aliases — CSRP carries no alias verbs; catalog discovery over the wire is store-query pushdown (pkg-catalog composes it)')
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
			if ms.read_only {
				return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${ms.url}')
			}
			alias := store_arg_str(args[1]) or { return none }
			if alias in ms.aliases {
				ms.aliases.delete(alias)
				idx := ms.alias_order.index(alias)
				if idx >= 0 {
					ms.alias_order.delete(idx)
				}
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
			if store_remote_active(ms) && csrp_scheme(ms.remote.scheme) {
				return store_remote_admin(ms.remote, 'mounts')
			}
			return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: mounts is a daemon-level op — it requires a cx-store:// service-tier handle')
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
			if store_remote_active(ms) && csrp_scheme(ms.remote.scheme) {
				return store_remote_admin(ms.remote, 'config-reload')
			}
			return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: config-reload is a daemon-level op — it requires a cx-store:// service-tier handle')
		}
		'store-log' {
			return store_log(args)
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
		raction := args[2]
		if raction !is cx.Element {
			return mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: modify action must be an element')
		}
		return store_remote_modify(ms.remote, rhash, render_canonical(raction))
	}
	if ms.read_only {
		return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${ms.url}')
	}
	hash := store_arg_str(args[1]) or { return none }
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
	} {
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
		return mk_err('cx-err:CXER0104', 'E_USING_NOT_CALLABLE: modify-doc [using …] must be a [?fn] lambda')
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
			return error('E_USING_FAILED: modify-doc [using …] body trapped: ${err_summary(result)}')
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
	} {
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
					new_items << cx.Node(store_modify_rebuild(nr as cx.Element, target,
						descendant, true, preds, op)!)
				} else {
					new_items << nr
				}
			} else if descendant {
				new_items << cx.Node(store_modify_rebuild(child, target, descendant,
					true, preds, op)!)
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

// store_query implements a SUBSET of §3.5 for the mem:// backend: the
// element-name descendant (`//name`) and direct-child (`/name`) steps.
// Returns a sequence of [hash $h matches [sequence …]] for docs with a
// non-empty match. The full CXPath grammar + parallel scan are deferred
// to the integration suite.
fn store_query(args []cx.Node) ?cx.Node {
	ms, errn, ok := store_get_open(args[0])
	if !ok {
		return errn
	}
	// The CXPath argument is a plain string scalar; take its raw value, NOT
	// render_canonical (which would quote it to `'//user'` and defeat the
	// `//` / `/` prefix check).
	path_text := (store_arg_str(args[1]) or { return none }).trim_space()
	// Remote backend: push the query to the server (CSRP) instead of scanning the
	// local doc map — which is EMPTY for a remote-backed handle, so the old code
	// silently returned `()` even when the server had matches (#119). A backend
	// without query pushdown raises CXER1709 rather than lying with an empty seq.
	if store_remote_active(ms) {
		return store_remote_query(ms.remote, path_text)
	}
	if ms.backend == 'columnar' {
		// #129 D5 §6: a column-projecting query is lowered to a columnar scan that
		// reads only the projected column (not every doc). A path that does not
		// reduce to a single promoted column returns none here and falls through to
		// row materialization below (which reads __cx_doc) — correct, just not
		// accelerated. No silent full-scan masquerading as pushdown.
		$if cxstore_columnar ? {
			if res := store_columnar_query(ms, path_text) {
				return res
			}
		}
	}
	// #192: evaluate the FULL CXPath — a trailing attribute step (`/@name`) and
	// element predicates (`[@k='v']`) — reusing the same predicate engine as
	// modify-doc's `select=`, so `query` and `modify` are symmetric. An
	// element-name step alone still uses the fast name walker. A predicate the
	// engine cannot parse fails CLOSED with CXER1709 (never a silent empty result
	// masquerading as "no matches" — the exact bug this closes).
	attr_name, elem_path := store_query_split_attr(path_text)
	target, descendant, preds := store_parse_select(elem_path) or {
		return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: query CXPath `${path_text}` has an unsupported predicate/step (${err.msg()}) — refusing to return a lying empty result')
	}
	mut results := []cx.Node{}
	for h in ms.doc_order {
		text := store_doc_text(ms, h) or {
			return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
		}
		doc := store_decode_doc(text)
		mut elems := []cx.Node{}
		store_collect_by_name(doc, target, descendant, mut elems)
		mut matches := []cx.Node{}
		for e in elems {
			if e is cx.Element {
				if !store_elem_matches_predicates(e, preds) {
					continue
				}
				if attr_name != '' {
					// attribute axis: emit the attribute VALUE (a scalar), or skip
					// the element when the attribute is absent.
					if av := store_elem_attr_node(e, attr_name) {
						matches << av
					}
				} else {
					matches << e
				}
			}
		}
		if matches.len > 0 {
			results << cx.Element{
				name:  'result'
				attrs: [cx.Attribute{
					name:  'hash'
					value: cx.ScalarValue(h)
				}]
				items: [store_seq(matches)]
			}
		}
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
	mut doc_count := 0
	mut verified := 0
	mut bytes_written := 0
	for h in from.doc_order {
		// Route through the doc abstraction on BOTH sides so migration copies the
		// real docs regardless of each store's model (object-graph stores keep docs
		// in the graph, not the flat `docs` map). A reconstruct failure on the source
		// is a hard integrity error — never a silent skip / zero-doc migration.
		text := store_doc_text(from, h) or {
			return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${h}: ${err.msg()}')
		}
		if h.starts_with('code:') {
			// #128-A: a code: entry is verbatim source (not a data doc) — copy raw.
			if store_put_raw(mut to, h, text) or {
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${h}: ${err.msg()}')
			} {
				bytes_written += text.len
			}
			verified++
			doc_count++
			continue
		}
		rehash := cx.cx_text_hash(text) or {
			return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${h}')
		}
		if rehash != h {
			return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: stored ${h} rehashes to ${rehash}')
		}
		verified++
		if store_put_canonical(mut to, h, text) or {
			return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${h}: ${err.msg()}')
		} {
			bytes_written += text.len
		}
		doc_count++
	}
	for a in from.alias_order {
		if a !in to.aliases {
			to.alias_order << a
		}
		to.aliases[a] = from.aliases[a]
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
// The canonical cx-stdlib/store surface. Bodies forward to the native
// primitives above. Registered into the module table by stdlib_bundle.v.

const stdlib_src_store = $embed_file('../stdlib/store.cx').to_string()
