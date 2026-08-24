module platform
import code {
	cap_guard,
	mk_err,
}

import cx
import cxstore
import db.sqlite
import encoding.hex
import os
import sync

// sqlite:// backend wiring for the [$store] stdlib (#77 / #129 spec §7.2), per the
// #75 external-engine framework. FEATURE-GATED: this file (and the libsqlite3 link
// it pulls in) compiles ONLY with `-d cxstore_sqlite`, so the default/core/wasm
// build is unaffected. stdlib_store.v consults these via `$if cxstore_sqlite ?`
// guards; without the flag, `[$store sqlite://…]` errors clearly.
//
// SUBTREE OBJECT MODEL (#129): sqlite is now an object-graph substrate, not a flat
// doc-blob store. It is `sqlite × subtree × object-rows`: each content-addressed
// object is one row `cxstore_objects(hash, bytes_hex)`, so identical subtrees dedup
// across docs and across versions — the SAME object hashes the embedded pack/object
// substrates produce (model ⟂ substrate). The store-key → doc-root refs are the
// shared manifest format (store_graph.v) persisted as a single row. Object bytes are
// hex-encoded into a TEXT column (binary-safe with the string SQL surface; hashes are
// hex so all interpolated values are injection-safe). Reads resolve objects lazily
// per-hash through the composite getter — no eager slurp of the whole graph into RAM.

// SqliteObjectBackend — the ObjectBackend (object seam, #76) over a sqlite table.
// Holds one open connection for the store's lifetime so object get/put during a
// session do not reconnect per object.
@[heap]
pub struct SqliteObjectBackend {
mut:
	db sqlite.DB
	// writes counts write-path SQL statements issued on this connection (object
	// puts, manifest/meta writes) — the #299 write-amplification gauge. The gated
	// suite pins per-mutation cost O(delta) with it: one put/delete on a large
	// store must issue the same statement count as on a small one.
	writes int
	// manifest_lines counts the refs-manifest lines currently on disk (#299) —
	// seeded from the replayed content at load, advanced by append_manifest,
	// reset by write_manifest's snapshot. It drives the fold heuristic and lives
	// HERE (beside the log it counts) rather than on ms.log_records, which the
	// file:// backend's handlers reset around their own persist calls.
	manifest_lines int
}

fn (b &SqliteObjectBackend) has_object(hash []u8) bool {
	hx := hash.hex()
	rows := b.db.exec("SELECT 1 FROM cxstore_objects WHERE hash='${hx}' LIMIT 1") or { return false }
	return rows.len > 0
}

// get_object reads an object by content hash and self-verifies it against its
// address (a corrupt/substituted row is rejected as none — spec §4 integrity).
fn (b &SqliteObjectBackend) get_object(hash []u8) ?[]u8 {
	hx := hash.hex()
	rows := b.db.exec("SELECT bytes_hex FROM cxstore_objects WHERE hash='${hx}'") or { return none }
	if rows.len == 0 {
		return none
	}
	payload := hex_decode_or_empty(rows[0].vals[0])
	if payload.len == 0 {
		return none
	}
	if compare_object_hash(payload, hash) != 0 {
		return none
	}
	return payload
}

fn (mut b SqliteObjectBackend) put_object(payload []u8) ![]u8 {
	h := cxstore.object_name(payload)
	hx := h.hex()
	b.writes++
	b.db.exec_none("INSERT OR IGNORE INTO cxstore_objects (hash, bytes_hex) VALUES ('${hx}', '${payload.hex()}')")
	return h
}

// get_object_raw resolves the stored bytes under `key` WITHOUT self-verifying
// them against it (cxstore.KeyedObjectBackend seam, #229) — on an encrypted
// store the row holds an AEAD envelope that deliberately does not hash to the
// key; the EncryptingWrapper owns the key↔bytes relation (tag + post-decrypt
// hash check).
fn (b &SqliteObjectBackend) get_object_raw(key []u8) ?[]u8 {
	kx := key.hex()
	rows := b.db.exec("SELECT bytes_hex FROM cxstore_objects WHERE hash='${kx}'") or { return none }
	if rows.len == 0 {
		return none
	}
	blob := hex_decode_or_empty(rows[0].vals[0])
	if blob.len == 0 {
		return none
	}
	return blob
}

// put_object_keyed stores caller-keyed bytes verbatim under `key` (#229 seam) —
// one row per key, idempotent (INSERT OR IGNORE), exactly like put_object minus
// the content addressing.
fn (mut b SqliteObjectBackend) put_object_keyed(key []u8, blob []u8) ! {
	b.writes++
	b.db.exec_none("INSERT OR IGNORE INTO cxstore_objects (hash, bytes_hex) VALUES ('${key.hex()}', '${blob.hex()}')")
}

// object_keys enumerates every stored object's key (hash column) — the #287
// KEK-rotation walk's enumeration surface. A non-hex row key is a hard error
// (rotation aborts, never skips).
fn (b &SqliteObjectBackend) object_keys() ![][]u8 {
	rows := b.db.exec('SELECT hash FROM cxstore_objects') or {
		return error('sqlite rotation: key enumeration failed: ${err}')
	}
	mut out := [][]u8{cap: rows.len}
	for r in rows {
		key := hex.decode(r.vals[0]) or {
			return error('sqlite rotation: non-hash object key `${r.vals[0]}`: ${err.msg()}')
		}
		out << key
	}
	return out
}

// replace_object_keyed stores caller-keyed bytes under `key` REPLACING any
// existing row — the #287 rotation write (put_object_keyed is INSERT OR IGNORE
// by design; rotation must overwrite the envelope in place). One row per key;
// the row update is atomic (SQLite statement-level atomicity), which is the
// per-object rotation atomicity §9.1 requires.
fn (mut b SqliteObjectBackend) replace_object_keyed(key []u8, blob []u8) ! {
	rc := b.db.exec_none("INSERT OR REPLACE INTO cxstore_objects (hash, bytes_hex) VALUES ('${key.hex()}', '${blob.hex()}')")
	if rc != 101 && rc != 0 && rc != 100 {
		return error('sqlite rotation: envelope replace failed (code ${rc}) for ${key.hex()}')
	}
}

// remove_object_keyed deletes one at-rest envelope row (stream 20 §7: the
// shred-residue purge; see EncryptingObjectBackend.remove_object). DELETE is
// statement-atomic; an absent row is already-gone — idempotent.
fn (mut b SqliteObjectBackend) remove_object_keyed(key []u8) ! {
	rc := b.db.exec_none("DELETE FROM cxstore_objects WHERE hash = '${key.hex()}'")
	if rc != 101 && rc != 0 && rc != 100 {
		return error('sqlite erase: envelope delete failed (code ${rc}) for ${key.hex()}')
	}
}

// store_erase_purge_sqlite — the sqlite arm of store_erase_purge_durable
// (lives here so the ungated build never references the gated backend type).
fn store_erase_purge_sqlite(mut ms MemStore, keys [][]u8) ! {
	mut w := store_enc_wrapper(mut ms) or {
		return error('sqlite store is not routed through the encrypting wrapper')
	}
	mut ib := w.inner_backend()
	if mut ib is SqliteObjectBackend {
		for k in keys {
			ib.remove_object_keyed(k)!
		}
		return
	}
	return error('sqlite store backend shape unexpected')
}

fn (b &SqliteObjectBackend) object_count() int {
	rows := b.db.exec('SELECT COUNT(*) FROM cxstore_objects') or { return 0 }
	if rows.len == 0 {
		return 0
	}
	return rows[0].vals[0].int()
}

// compare_object_hash — 0 iff object_name(payload) == want.
fn compare_object_hash(payload []u8, want []u8) int {
	got := cxstore.object_name(payload)
	if got.len != want.len {
		return 1
	}
	for i in 0 .. got.len {
		if got[i] != want[i] {
			return 1
		}
	}
	return 0
}

// (hex_decode_or_empty lives in store_objgraph.v — the always-compiled copy;
// a second definition here broke every `-d cxstore_sqlite` build since W5.)

// ── schema + refs manifest (the refs layer; transient connection per op) ──────

fn store_sqlite_ensure(mut db sqlite.DB) {
	db.exec_none('CREATE TABLE IF NOT EXISTS cxstore_objects (hash TEXT PRIMARY KEY, bytes_hex TEXT NOT NULL)')
	db.exec_none('CREATE TABLE IF NOT EXISTS cxstore_manifest (id INTEGER PRIMARY KEY, lines TEXT NOT NULL)')
	// #229: store-level metadata (currently the at-rest encryption marker).
	// Additive — legacy plaintext stores gain an empty table on reopen.
	db.exec_none('CREATE TABLE IF NOT EXISTS cxstore_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
}

// ── #229 store metadata: the at-rest format marker ────────────────────────────
// `encryption` = 'keyed' declares every object row an AEAD envelope keyed by its
// plaintext hash (the sqlite analogue of the v2 keyed pack version). Absence =
// plaintext. Written once when an encrypted store is first created; checked on
// every attach so a mode mismatch is a HARD error — an encrypted store opened
// without its key must ERROR, never appear empty/corrupt, and encryption can
// never be silently enabled on existing plaintext data (mixed-mode store).

fn (b &SqliteObjectBackend) read_meta(k string) string {
	rows := b.db.exec("SELECT value FROM cxstore_meta WHERE key='${k}'") or { return '' }
	if rows.len == 0 {
		return ''
	}
	return rows[0].vals[0]
}

fn (mut b SqliteObjectBackend) write_meta(k string, v string) ! {
	b.writes++
	rc := b.db.exec_none("INSERT OR REPLACE INTO cxstore_meta (key, value) VALUES ('${k}', '${v}')")
	if rc != 101 && rc != 0 && rc != 100 {
		return error('sqlite meta write failed (code ${rc})')
	}
}

// is_empty — true iff the store holds no objects and no refs manifest (a fresh
// database, safe to declare a new at-rest mode for).
fn (b &SqliteObjectBackend) is_empty() bool {
	return b.object_count() == 0 && b.read_manifest() == ''
}

// ── #299 write transactions on the ONE persistent connection (#220) ───────────
// begin_txn/commit_txn bracket a mutation's writes (object rows + the manifest
// delta row) so they land atomically: a raise mid-flush rolls back and the op
// re-raises with the store exactly as before — durable-on-return, matching
// store_persist's contract. Single connection under the store op_lock = the
// single-writer discipline SQLite requires, so BEGIN IMMEDIATE never contends.

fn (mut b SqliteObjectBackend) begin_txn() ! {
	rc := b.db.exec_none('BEGIN IMMEDIATE')
	// sqlite result codes: 101 = DONE (statement finished), 0/100 also non-error.
	if rc != 101 && rc != 0 && rc != 100 {
		return error('sqlite begin failed (code ${rc})')
	}
}

fn (mut b SqliteObjectBackend) commit_txn() ! {
	rc := b.db.exec_none('COMMIT')
	if rc != 101 && rc != 0 && rc != 100 {
		return error('sqlite commit failed (code ${rc})')
	}
}

fn (mut b SqliteObjectBackend) rollback_txn() {
	b.db.exec_none('ROLLBACK')
}

// store_sqlite write_manifest replaces the refs manifest with the current live
// snapshot (the shared D/C/A format — no tombstones needed for a snapshot),
// clearing any appended delta rows (#299) atomically. O(live); the SNAPSHOT
// path — gc/compaction/migrate — while per-op mutations ride append_manifest.
// Runs on the store's ONE persistent connection (#220): a second transient
// connection to the same file was both a per-flush reconnect cost and a second
// writer path; the single connection under the store op_lock is the
// single-writer discipline SQLite requires.
fn (mut b SqliteObjectBackend) write_manifest(lines string) ! {
	esc := lines.replace("'", "''")
	b.begin_txn()!
	b.writes += 2
	b.db.exec_none('DELETE FROM cxstore_manifest')
	rc := b.db.exec_none("INSERT INTO cxstore_manifest (id, lines) VALUES (0, '${esc}')")
	if rc != 101 && rc != 0 && rc != 100 {
		b.rollback_txn()
		return error('sqlite manifest write failed (code ${rc})')
	}
	b.commit_txn() or {
		b.rollback_txn()
		return error('sqlite manifest write commit failed: ${err.msg()}')
	}
	b.manifest_lines = store_sqlite_count_lines(lines)
}

// append_manifest appends ONE manifest delta row (#299) — the incremental
// sibling of write_manifest's snapshot. Replay concatenates rows in id order,
// so a delta replays after everything before it; a legacy single-row (id=0)
// snapshot store reads back unchanged.
fn (mut b SqliteObjectBackend) append_manifest(lines string) ! {
	esc := lines.replace("'", "''")
	b.writes++
	rc := b.db.exec_none("INSERT INTO cxstore_manifest (lines) VALUES ('${esc}')")
	if rc != 101 && rc != 0 && rc != 100 {
		return error('sqlite manifest append failed (code ${rc})')
	}
	b.manifest_lines += store_sqlite_count_lines(lines)
}

// store_sqlite_count_lines counts the non-blank refs lines in a manifest blob.
fn store_sqlite_count_lines(blob string) int {
	return blob.split_into_lines().filter(it.trim_space() != '').len
}

fn (b &SqliteObjectBackend) read_manifest() string {
	rows := b.db.exec('SELECT lines FROM cxstore_manifest ORDER BY id') or { return '' }
	if rows.len == 0 {
		return ''
	}
	mut parts := []string{cap: rows.len}
	for r in rows {
		parts << r.vals[0]
	}
	return parts.join('\n')
}

// ── open / load / persist ─────────────────────────────────────────────────────

// store_sqlite_attach lazily attaches the object-row backend (opens the persistent
// connection + ensures the schema). The open path sets it; tests may construct a
// MemStore directly. #229: with enc_key_id set, the durable backend is an
// EncryptingWrapper over the row backend (objects at rest = AEAD envelopes keyed
// by plaintext hash; graph/dedup unchanged) — fail-closed here on a missing KEK
// and on any at-rest-mode mismatch, so an encrypted store can never be touched
// keyless and encryption can never be half-enabled on existing plaintext data.
fn store_sqlite_attach(mut ms MemStore) ! {
	if ms.obj_backend == none {
		mut db := sqlite.connect(ms.root)!
		store_sqlite_ensure(mut db)
		mut be := &SqliteObjectBackend{
			db: db
		}
		marker := be.read_meta('encryption')
		if ms.enc_key_id != '' {
			if marker != 'keyed' {
				if !be.is_empty() {
					return error('sqlite store at ${ms.root} is not encrypted (plaintext at rest) — encrypt-key-id was given for an unencrypted store; encryption cannot be enabled on existing data in place')
				}
				be.write_meta('encryption', 'keyed')!
			}
			kms := store_kek_kms(ms.enc_key_id, os.dir(ms.root))!
			ms.obj_backend = cxstore.ObjectBackend(cxstore.new_encrypting_wrapper(be,
				ms.enc_key_id, kms))
		} else {
			if marker == 'keyed' {
				return error('sqlite store at ${ms.root} is encrypted at rest — reopen it with its encrypt-key-id')
			}
			ms.obj_backend = cxstore.ObjectBackend(be)
		}
	}
}

// store_sqlite_row_backend resolves the concrete row backend for the refs
// manifest (which rides the same connection the object rows do), reaching
// through the EncryptingWrapper on an encrypted store. Manifest bytes are the
// refs layer (hashes, no doc content) — same at-rest posture as the cxpack/
// cxobj manifests.
fn store_sqlite_row_backend(mut ms MemStore) ?&SqliteObjectBackend {
	mut be := ms.obj_backend or { return none }
	if mut be is SqliteObjectBackend {
		return be
	}
	if mut be is cxstore.EncryptingWrapper {
		mut ib := be.inner_backend()
		if mut ib is SqliteObjectBackend {
			return ib
		}
	}
	return none
}

// store_sqlite_load reopens a sqlite store: attaches the object-row backend and
// replays the refs manifest, resolving every referenced object lazily through the
// composite getter. A corrupt object row makes the affected doc fail HARD (#129-C /
// spec §4) — never a silent partial store.
fn store_sqlite_load(mut ms MemStore) ! {
	store_sqlite_attach(mut ms)!
	mut content := ''
	if mut rb := store_sqlite_row_backend(mut ms) {
		content = rb.read_manifest()
		// #299: count the inherited manifest lines so pre-existing redundancy
		// (T/X tombstones, superseded A lines) counts toward the fold heuristic.
		rb.manifest_lines = store_sqlite_count_lines(content)
	}
	if content == '' {
		return // never persisted / empty store
	}
	getter := store_graph_getter(ms)
	store_graph_replay(mut ms, getter, content, 'sqlite ${ms.root}')!
	// #299: seed the delta watermarks from the replayed state, so the first
	// incremental flush appends only what changes after this open.
	store_graph_seed_watermarks(mut ms)
}

// store_sqlite_flush — the #299 per-op INCREMENTAL persist: everything one
// mutation changed — the new sink objects (the tail past the obj_flushed
// watermark), the delta's alias-name objects, and ONE manifest delta row —
// lands inside a single transaction. O(delta) statements per op, never
// O(store); durable-on-return (a raise rolls back and propagates, matching
// store_persist's contract). A refs-empty delta with new sink objects (the
// CSRP object-wire put stages objects before their refs arrive) persists just
// the objects. The snapshot path (store_sqlite_persist) remains the fold: when
// the manifest log accumulates materially more lines than live state
// (tombstones, superseded aliases) it is compacted back to a snapshot — the
// same 2*live+64 heuristic the file:// append log uses.
fn store_sqlite_flush(mut ms MemStore) ! {
	if ms.root == '' {
		return
	}
	store_sqlite_attach(mut ms) or {
		return error('sqlite ${ms.root}: attach failed: ${err.msg()}')
	}
	d := store_graph_delta(ms)
	tail := ms.obj_sink.objects.len - ms.obj_flushed
	if d.lines.len > 0 || tail > 0 {
		mut rb := store_sqlite_row_backend(mut ms) or {
			return error('sqlite ${ms.root}: row backend not attached')
		}
		rb.begin_txn() or { return error('sqlite ${ms.root}: begin failed: ${err.msg()}') }
		mut committed := false
		defer {
			if !committed {
				rb.rollback_txn()
			}
		}
		if mut be := ms.obj_backend {
			// new objects only: the sink map is insertion-ordered, so everything
			// past the obj_flushed watermark is exactly what this session's
			// unflushed mutations added.
			mut i := 0
			for _, payload in ms.obj_sink.objects {
				if i >= ms.obj_flushed {
					be.put_object(payload) or {
						ms.obj_backend = be
						return error('sqlite ${ms.root}: object write failed: ${err.msg()}')
					}
				}
				i++
			}
			// alias-name objects for THIS delta only (set + removed — an X
			// tombstone resolves its name object on replay), never the whole
			// alias table.
			for a, _ in d.set_aliases {
				be.put_object(a.bytes()) or {
					ms.obj_backend = be
					return error('sqlite ${ms.root}: alias-name object write failed: ${err.msg()}')
				}
			}
			for a in d.removed_aliases {
				be.put_object(a.bytes()) or {
					ms.obj_backend = be
					return error('sqlite ${ms.root}: alias-name object write failed: ${err.msg()}')
				}
			}
			ms.obj_backend = be
		}
		if d.lines.len > 0 {
			rb.append_manifest(d.lines.join('\n')) or {
				return error('sqlite ${ms.root}: manifest append failed: ${err.msg()}')
			}
		}
		rb.commit_txn() or { return error('sqlite ${ms.root}: commit failed: ${err.msg()}') }
		committed = true
		ms.obj_flushed = ms.obj_sink.objects.len
		store_graph_delta_commit(mut ms, d)
	} else {
		// Nothing to persist — still commit the empty delta so the #603 scan
		// bookkeeping (doc cursor, dirty aliases) advances instead of re-walking.
		store_graph_delta_commit(mut ms, d)
	}
	// Fold check runs even on an empty delta so a redundancy-heavy store folds
	// on its next durability hook (gc's durable-compaction half rides this).
	// The counter lives on the row backend (manifest_lines), not ms.log_records
	// — the file:// handlers reset that around their own persists.
	if mut frb := store_sqlite_row_backend(mut ms) {
		live := ms.doc_order.len + ms.alias_order.len + ms.erased_order.len
		if frb.manifest_lines > 2 * live + 64 {
			store_sqlite_persist(ms)!
		}
	}
}

fn store_sqlite_persist(ms &MemStore) ! {
	if ms.root == '' {
		return
	}
	mut m := unsafe { ms }
	store_sqlite_attach(mut m) or {
		return error('sqlite ${m.root}: attach failed: ${err.msg()}')
	}
	if mut be := m.obj_backend {
		cxstore.persist_objects(mut be, m.obj_sink) or {
			m.obj_backend = be
			return error('sqlite ${m.root}: object write failed: ${err.msg()}')
		}
		store_graph_stage_aliases(mut be, m) or {
			m.obj_backend = be
			return error('sqlite ${m.root}: alias-name object write failed: ${err.msg()}')
		}
		m.obj_backend = be
	}
	if mut rb := store_sqlite_row_backend(mut m) {
		rb.write_manifest(store_graph_snapshot_lines(m).join('\n')) or {
			return error('sqlite ${m.root}: manifest write failed: ${err.msg()}')
		}
	}
	// #299: a snapshot IS the full live state — reset the delta watermarks so
	// the next incremental flush appends only what changes after this point
	// (write_manifest above already reset the on-disk line counter).
	store_graph_seed_watermarks(mut m)
	m.obj_flushed = m.obj_sink.objects.len
}

// ── #287 KEK rotation (store.md §9.1) — sqlite walk ───────────────────────────

// store_rotate_sqlite re-wraps every object row's envelope DEK under
// new_key_id: enumerate the keys, unwrap each envelope's DEK under its
// RECORDED key-id, re-wrap, and REPLACE the row (statement-level atomicity =
// per-object atomicity). Resumable (already-current rows are untouched);
// fail-closed (any unwrap failure aborts, never skips). The at-rest 'keyed'
// meta marker is unchanged — rotation never changes the store's mode.
fn store_rotate_sqlite(mut ms MemStore, new_key_id string) !cxstore.KekRotation {
	mut w := store_enc_wrapper(mut ms) or {
		return error('sqlite store is not routed through the encrypting wrapper')
	}
	mut rb := store_sqlite_row_backend(mut ms) or {
		return error('sqlite row backend not attached')
	}
	w.probe_key(new_key_id)!
	mut rep := cxstore.KekRotation{}
	mut seen_from := map[string]bool{}
	keys := rb.object_keys()!
	for key in keys {
		env := rb.get_object_raw(key) or {
			return error('object ${key.hex()}: envelope row missing')
		}
		// Stream 20: SEK-wrapped envelopes are out of tenant-rotation scope —
		// left in place verbatim, counted visibly.
		env0 := cxstore.parse_envelope(env) or {
			return error('object ${key.hex()}: ${err.msg()}')
		}
		if env0.key_id.starts_with(cxstore.sek_id_prefix) {
			rep.objects++
			rep.subject_keyed++
			continue
		}
		nb, old_id, changed := w.rewrap_envelope(env, new_key_id) or {
			return error('object ${key.hex()}: ${err.msg()}')
		}
		rep.objects++
		if !changed {
			rep.already_current++
			continue
		}
		rb.replace_object_keyed(key, nb) or {
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

// ── test helpers (compiled only with -d cxstore_sqlite, like the backend) ─────

// store_sqlite_load_result wraps store_sqlite_load as `?` so a test can assert that
// a corrupted store fails to open.
fn store_sqlite_load_result(mut ms MemStore) ?bool {
	store_sqlite_load(mut ms) or { return none }
	return true
}

// corrupt_sqlite_objects rewrites every object row's bytes to a non-matching value,
// so each object fails its content-address self-verify on read.
fn corrupt_sqlite_objects(path string) {
	mut db := sqlite.connect(path) or { return }
	defer {
		db.close() or {}
	}
	db.exec_none("UPDATE cxstore_objects SET bytes_hex='00'")
}

fn store_sqlite_open(url string, compression string, encoding string, read_only bool, model string, enc_key_id string) cx.Node {
	cap := if read_only { 'read' } else { 'write' }
	if d := cap_guard(cap, 'store open ${url}') {
		return d
	}
	mut path := url
	if path.starts_with('sqlite://') {
		path = path['sqlite://'.len..]
	}
	if path == '' {
		return mk_err('cx-err:CXER1100', 'E_STORE_UNRESOLVED_BACKEND: malformed sqlite URL ${url}')
	}
	comp := if compression == '' { 'none' } else { compression }
	enc := if encoding == '' { 'cxbin' } else { encoding }
	mut ms := &MemStore{
		url:         url
		backend:     'sqlite'
		root:        path
		encoding:    enc
		compression: comp
		read_only:   read_only
		is_open:     true
		op_lock:     sync.new_mutex()
		model:       model
		enc_key_id:  enc_key_id
	}
	// Eager integrity: a corrupt object row makes the affected doc fail HARD at open
	// (#129-C / spec §4), never a silent partial store.
	store_sqlite_load(mut ms) or {
		return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
	}
	id := store_register(ms)
	return store_handle_element(id, ms)
}
