module platform
import code {
	mk_err,
}

import cx
import cxstore
import encoding.hex

// store_s3_subtree.v — s3 as a SUBTREE object substrate (#129 Phase 3 / spec §1:
// the point `s3 × subtree × object-per-key`). Each content-addressed object is one
// S3 key `objects/aa/aabb…hex` (2-char shard, git/DirObjectBackend-style); the
// store-key → doc-root refs manifest is a single S3 key. Object durability +
// resolution route through the universal ObjectBackend seam and the shared
// store_graph.v refs/replay, so dedup, structural sharing, version-sharing and
// CXER1120 integrity are IDENTICAL to every other substrate — only the transport
// (SigV4 PUT/GET/HEAD/LIST, store_remote.v) differs. The same document therefore
// produces the SAME object hashes on s3 as on mem/file/sqlite (model ⟂ substrate;
// cross-tier identity, spec §4.3).
//
// The transport is an INJECTED S3Transport interface, so the §6 conformance test
// runs HERMETICALLY against an in-memory map (no live S3/minio in the gate); the
// production transport (S3HttpTransport) wires the SigV4 ops over a RemoteBackend.

// S3Transport — the object-key transport. Reads (fetch/keys) are non-mut so the
// ObjectBackend read surface stays non-mut; store (a write) is mut.
pub interface S3Transport {
	fetch(method string, key string) (int, []u8, bool) // (status, body, transport-ok); method = HEAD|GET
	keys() []string
mut:
	store(key string, body []u8) (int, bool) // PUT; (status, transport-ok)
	remove(key string) (int, bool) // DELETE; (status, transport-ok) — stream 20: the shred-residue purge
}

// S3ObjectBackend — the ObjectBackend (#76 seam) over an S3 bucket, object-per-key.
//
// fail_status (#213): the ObjectBackend read surface (`has_object bool`,
// `get_object ?[]u8`) cannot carry an error, so a non-404 transport/auth failure
// would otherwise be indistinguishable from genuine absence — which turned an
// enforced 403 into "not found"/"empty store" (silently masking auth failures).
// The backend records the last such failure here; the s3-aware op paths check it
// (store_s3_check) and raise the honest error (CXER1131 auth / CXER1132
// rate-limit / CXER1101 transport) instead of absence. Ops are serialized by the
// store op_lock, so the field is race-free.
@[heap]
pub struct S3ObjectBackend {
mut:
	transport   S3Transport
	fail_status int // last non-404 failure HTTP status (-1 = transport error, 0 = none)
	fail_op     string
}

// s3_note_fail records a non-404 read-path failure for store_s3_check to raise.
fn (mut b S3ObjectBackend) s3_note_fail(st int, op string) {
	b.fail_status = st
	b.fail_op = op
}

// s3_take_fail returns-and-clears the recorded failure.
fn (mut b S3ObjectBackend) s3_take_fail() (int, string) {
	st, op := b.fail_status, b.fail_op
	b.fail_status = 0
	b.fail_op = ''
	return st, op
}

const s3_objects_prefix = 'objects/'
const s3_manifest_key = '.cxstore-manifest'
// #229: the at-rest encryption marker key (the s3 analogue of the v2 keyed pack
// version / the sqlite cxstore_meta row). Contains 'keyed' when every object
// under objects/ is an AEAD envelope keyed by its plaintext hash; absence =
// plaintext. Written once when a fresh encrypted store opens; checked on every
// open so a mode mismatch is a HARD error.
const s3_encryption_marker_key = '.cxstore-encryption'

fn s3_obj_key(hash []u8) string {
	hx := hash.hex()
	return '${s3_objects_prefix}${hx[..2]}/${hx}'
}

pub fn (b &S3ObjectBackend) has_object(hash []u8) bool {
	st, _, ok := b.transport.fetch('HEAD', s3_obj_key(hash))
	if !ok || (st != 200 && st != 404) {
		mut mb := unsafe { &S3ObjectBackend(b) }
		mb.s3_note_fail(if ok { st } else { -1 }, 'has')
	}
	return ok && st == 200
}

// get_object reads an object by content hash and self-verifies it against its
// address (a corrupt/substituted object is rejected as none — spec §4 integrity).
pub fn (b &S3ObjectBackend) get_object(hash []u8) ?[]u8 {
	st, body, ok := b.transport.fetch('GET', s3_obj_key(hash))
	if !ok || (st != 200 && st != 404) {
		// A denied/failed read is NOT absence — record it so the op path raises
		// CXER1131/1101 instead of a lying CXER1121 (#213).
		mut mb := unsafe { &S3ObjectBackend(b) }
		mb.s3_note_fail(if ok { st } else { -1 }, 'get ${hash.hex()}')
		return none
	}
	if st != 200 {
		return none
	}
	if cxstore.object_name(body) != hash {
		return none
	}
	return body
}

// put_object uploads the object under its content-address key. Idempotent: a HEAD
// short-circuits when the object is already present (dedup-on-wire — the missing-
// object economy that makes structural sharing span the network).
pub fn (mut b S3ObjectBackend) put_object(payload []u8) ![]u8 {
	h := cxstore.object_name(payload)
	if b.has_object(h) {
		return h
	}
	// A failed dedup-HEAD (e.g. 403) must not linger past the authoritative PUT
	// outcome below.
	b.fail_status = 0
	b.fail_op = ''
	st, ok := b.transport.store(s3_obj_key(h), payload)
	if !ok {
		return error('s3 object put failed (transport): ${h.hex()}')
	}
	if st != 200 && st != 201 {
		return error('s3 object put status ${st}: ${h.hex()}')
	}
	return h
}

// get_object_raw resolves the stored bytes under `key` WITHOUT self-verifying
// them against it (cxstore.KeyedObjectBackend seam, #229) — on an encrypted
// store the S3 object is an AEAD envelope that deliberately does not hash to
// the key; the EncryptingWrapper owns the key↔bytes relation. #213 fail
// recording is identical to get_object (a denied read is never absence).
pub fn (b &S3ObjectBackend) get_object_raw(key []u8) ?[]u8 {
	st, body, ok := b.transport.fetch('GET', s3_obj_key(key))
	if !ok || (st != 200 && st != 404) {
		mut mb := unsafe { &S3ObjectBackend(b) }
		mb.s3_note_fail(if ok { st } else { -1 }, 'get ${key.hex()}')
		return none
	}
	if st != 200 {
		return none
	}
	return body
}

// put_object_keyed uploads caller-keyed bytes under the object key (#229 seam).
// Same HEAD-dedup + status discipline as put_object, minus the content
// addressing.
pub fn (mut b S3ObjectBackend) put_object_keyed(key []u8, blob []u8) ! {
	if b.has_object(key) {
		return
	}
	// A failed dedup-HEAD must not linger past the authoritative PUT below.
	b.fail_status = 0
	b.fail_op = ''
	st, ok := b.transport.store(s3_obj_key(key), blob)
	if !ok {
		return error('s3 object put failed (transport): ${key.hex()}')
	}
	if st != 200 && st != 201 {
		return error('s3 object put status ${st}: ${key.hex()}')
	}
}

// object_keys enumerates the content-hash keys of every object physically
// stored (keys under objects/) — the #287 KEK-rotation walk's enumeration
// surface. A key whose basename is not a valid hex hash is a hard error
// (an alien object in the namespace must abort a rotation, never be skipped).
pub fn (b &S3ObjectBackend) object_keys() ![][]u8 {
	mut out := [][]u8{}
	for k in b.transport.keys() {
		idx := k.index(s3_objects_prefix) or { continue }
		rest := k[idx + s3_objects_prefix.len..]
		parts := rest.split('/')
		if parts.len != 2 {
			return error('s3 rotation: unexpected object key layout `${k}`')
		}
		hash := hex.decode(parts[1]) or {
			return error('s3 rotation: non-hash object key `${k}`: ${err.msg()}')
		}
		out << hash
	}
	return out
}

// replace_object_keyed PUTs caller-keyed bytes UNCONDITIONALLY (no dedup HEAD)
// — the #287 rotation write: overwrite the existing envelope under the same
// key. S3 PUT is atomic per key (readers see the old or the new envelope,
// whole), which is exactly the per-object rotation atomicity §9.1 requires.
pub fn (mut b S3ObjectBackend) replace_object_keyed(key []u8, blob []u8) ! {
	st, ok := b.transport.store(s3_obj_key(key), blob)
	if !ok {
		return error('s3 object replace failed (transport): ${key.hex()}')
	}
	if st != 200 && st != 201 {
		return error('s3 object replace status ${st}: ${key.hex()}')
	}
}

// remove_object_keyed deletes one at-rest envelope (stream 20 §7: the shred
// walk purges the sealed residue under a destroyed SEK; see
// EncryptingObjectBackend.remove_object). DELETE is atomic per key;
// already-gone (404) counts as done — idempotent, matching the walk's
// self-heal replay.
pub fn (mut b S3ObjectBackend) remove_object_keyed(key []u8) ! {
	st, ok := b.transport.remove(s3_obj_key(key))
	if !ok {
		return error('s3 object delete failed (transport): ${key.hex()}')
	}
	if st != 200 && st != 202 && st != 204 && st != 404 {
		return error('s3 object delete status ${st}: ${key.hex()}')
	}
}

// object_count — distinct objects physically stored (keys under objects/).
pub fn (b &S3ObjectBackend) object_count() int {
	mut n := 0
	for k in b.transport.keys() {
		if k.contains(s3_objects_prefix) {
			n++
		}
	}
	return n
}

// put_manifest / get_manifest persist the refs (manifest) blob as a single S3 key,
// through the same transport (the refs layer is substrate-independent; only its
// medium — a row, a file, an S3 key — differs).
pub fn (mut b S3ObjectBackend) put_manifest(body []u8) ! {
	st, ok := b.transport.store(s3_manifest_key, body)
	if !ok || (st != 200 && st != 201) {
		return error('s3 manifest put failed: status ${st}')
	}
}

pub fn (b &S3ObjectBackend) get_manifest() ?string {
	st, body, ok := b.transport.fetch('GET', s3_manifest_key)
	if !ok || (st != 200 && st != 404) {
		// 403 on the manifest is NOT an empty store (#213) — record it so the
		// open path raises instead of opening a lying empty store.
		mut mb := unsafe { &S3ObjectBackend(b) }
		mb.s3_note_fail(if ok { st } else { -1 }, 'get manifest')
		return none
	}
	if st != 200 {
		return none
	}
	return body.bytestr()
}

// get_encryption_marker reads the #229 at-rest mode marker ('' = absent =
// plaintext), with the same #213 fail recording as get_manifest (a denied
// marker read must raise, never masquerade as a plaintext store).
fn (b &S3ObjectBackend) get_encryption_marker() ?string {
	st, body, ok := b.transport.fetch('GET', s3_encryption_marker_key)
	if !ok || (st != 200 && st != 404) {
		mut mb := unsafe { &S3ObjectBackend(b) }
		mb.s3_note_fail(if ok { st } else { -1 }, 'get encryption marker')
		return none
	}
	if st != 200 {
		return none
	}
	return body.bytestr()
}

fn (mut b S3ObjectBackend) put_encryption_marker() ! {
	st, ok := b.transport.store(s3_encryption_marker_key, 'keyed'.bytes())
	if !ok || (st != 200 && st != 201) {
		return error('s3 encryption-marker put failed: status ${st}')
	}
}

// ── production transport: SigV4 ops over a RemoteBackend (store_remote.v) ──────

struct S3HttpTransport {
	rb &RemoteBackend
}

fn (t &S3HttpTransport) fetch(method string, key string) (int, []u8, bool) {
	resp, _, ok := s3_object_op(t.rb, method, key, '', []u8{})
	return resp.status, resp.body, ok
}

fn (mut t S3HttpTransport) store(key string, body []u8) (int, bool) {
	resp, _, ok := s3_object_op(t.rb, 'PUT', key, '', body)
	return resp.status, ok
}

fn (mut t S3HttpTransport) remove(key string) (int, bool) {
	resp, _, ok := s3_object_op(t.rb, 'DELETE', key, '', []u8{})
	return resp.status, ok
}

fn (t &S3HttpTransport) keys() []string {
	mut ks := []string{}
	mut cont := ''
	for {
		resp, _, ok := s3_bucket_list_op(t.rb, cont)
		if !ok || resp.status != 200 {
			break
		}
		xml := resp.body.bytestr()
		ks << s3_extract_keys(xml)
		cont = s3_extract_tag(xml, 'NextContinuationToken')
		if cont == '' {
			break
		}
	}
	return ks
}

// new_s3_object_backend wires the production SigV4 transport over `rb` (bucket /
// prefix / creds live on rb).
pub fn new_s3_object_backend(rb &RemoteBackend) &S3ObjectBackend {
	return &S3ObjectBackend{
		transport: S3Transport(&S3HttpTransport{
			rb: rb
		})
	}
}

// store_s3_concrete resolves the concrete S3 backend for the substrate side
// surfaces (refs manifest, #213 fail-take, #229 encryption marker), reaching
// through the EncryptingWrapper on an encrypted store. The object DATA path
// never bypasses the wrapper.
fn store_s3_concrete(mut ms MemStore) ?&S3ObjectBackend {
	mut be := ms.obj_backend or { return none }
	if mut be is S3ObjectBackend {
		return be
	}
	if mut be is cxstore.EncryptingWrapper {
		mut ib := be.inner_backend()
		if mut ib is S3ObjectBackend {
			return ib
		}
	}
	return none
}

// store_s3_fail_err consults the s3 backend's recorded read failure (#213):
// after a miss / reconstruct failure on an s3 store, a recorded 401/403/429/5xx
// means the truthful outcome is an auth / rate-limit / transport error — never
// absence (CXER1121) or corruption (CXER1120). Returns none when nothing was
// recorded (the miss is genuine).
fn store_s3_fail_err(mut ms MemStore) ?cx.Node {
	if ms.backend != 's3' {
		return none
	}
	if mut be := store_s3_concrete(mut ms) {
		st, op := be.s3_take_fail()
		if st == 401 || st == 403 {
			return mk_err('cx-err:CXER1131', 'E_STORE_AUTH_FAILED: s3 rejected ${op} (status ${st}) for ${ms.url}')
		}
		if st == 429 {
			return mk_err('cx-err:CXER1132', 'E_STORE_RATE_LIMIT: s3 throttled ${op} for ${ms.url}')
		}
		if st != 0 {
			return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: s3 ${op} failed (status ${st}) for ${ms.url}')
		}
	}
	return none
}

// store_s3_take_fail_error maps a recorded #213 read failure to a load-path
// error string ('' when nothing was recorded).
fn store_s3_take_fail_error(mut be S3ObjectBackend, url string) string {
	st, op := be.s3_take_fail()
	if st == 401 || st == 403 {
		return 's3 auth rejected (status ${st}) on ${op} for ${url}'
	}
	if st != 0 {
		return 's3 transport failure (status ${st}) on ${op} for ${url}'
	}
	return ''
}

// store_s3_mode_check enforces the #229 at-rest mode on open: an encrypted
// store (marker present) opened without its key is a HARD error, as is
// encrypt-key-id on an existing plaintext store (the manifest is the existing-
// data signal — encryption cannot be enabled on existing data in place). A
// fresh encrypted store writes the marker here (before any object lands), so a
// keyless reopen is caught from the first byte onward.
fn store_s3_mode_check(mut ms MemStore) ! {
	mut be := store_s3_concrete(mut ms) or { return }
	mut marker := ''
	if m := be.get_encryption_marker() {
		marker = m
	} else {
		femsg := store_s3_take_fail_error(mut be, ms.url)
		if femsg != '' {
			return error(femsg)
		}
		// genuine 404 — no marker (plaintext or fresh store)
	}
	if ms.enc_key_id != '' {
		if marker == 'keyed' {
			return
		}
		if _ := be.get_manifest() {
			return error('s3 store at ${ms.url} is not encrypted (plaintext at rest) — encrypt-key-id was given for an unencrypted store; encryption cannot be enabled on existing data in place')
		}
		femsg := store_s3_take_fail_error(mut be, ms.url)
		if femsg != '' {
			return error(femsg)
		}
		// fresh store: declare the at-rest mode durably before any data lands.
		if !ms.read_only {
			be.put_encryption_marker()!
		}
	} else if marker == 'keyed' {
		return error('s3 store at ${ms.url} is encrypted at rest — reopen it with its encrypt-key-id')
	}
}

// ── store_graph integration (refs manifest = one S3 key) ──────────────────────

// store_s3_flush persists the object-graph delta: new objects are staged through the
// seam (persist_objects) + uploaded object-per-key, alias-name objects too, then the
// refs manifest snapshot is written to the manifest key. Snapshot (O(live)) matches
// the existing s3 document-mode posture; object uploads are O(delta) via has-then-put.
fn store_s3_flush(mut ms MemStore) ! {
	if mut be := ms.obj_backend {
		cxstore.persist_objects(mut be, ms.obj_sink) or {
			ms.obj_backend = be
			return error('s3 object write failed: ${err.msg()}')
		}
		store_graph_stage_aliases(mut be, ms) or {
			ms.obj_backend = be
			return error('s3 alias-name object write failed: ${err.msg()}')
		}
		ms.obj_backend = be
	}
	lines := store_graph_snapshot_lines(ms).join('\n')
	if mut cbe := store_s3_concrete(mut ms) {
		cbe.put_manifest(lines.bytes()) or {
			return error('s3 manifest write failed: ${err.msg()}')
		}
	}
}

// store_s3_load reopens an s3 subtree store: it reads the refs manifest key and
// replays it, resolving every referenced object lazily through the composite getter
// (each get is one S3 GET, self-verifying). A corrupt object → HARD CXER1120 error
// (#129-C / spec §4); a missing manifest → a legitimately empty store.
fn store_s3_load(mut ms MemStore) ! {
	// #229: enforce the at-rest mode (and stamp a fresh encrypted store's marker)
	// BEFORE reading any data.
	store_s3_mode_check(mut ms)!
	mut be := store_s3_concrete(mut ms) or { return }
	content := be.get_manifest() or {
		// Distinguish "never persisted" (genuine 404 → empty store) from a
		// swallowed transport/auth failure (#213): a 403 manifest read is a
		// credentials problem, not an empty store.
		femsg := store_s3_take_fail_error(mut be, ms.url)
		if femsg != '' {
			return error(femsg)
		}
		return // never persisted — empty store
	}
	getter := store_graph_getter(ms)
	store_graph_replay(mut ms, getter, content, 's3 ${ms.url}')!
}
