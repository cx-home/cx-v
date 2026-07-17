module code

import cxstore

// store_remote_read.v — B3 (#129): OPT-IN read-only SUBTREE read over a read-only
// remote byte source (http/https/ftp/sftp). Those schemes are document byte-sources
// by DEFAULT; `model=subtree` makes them an object-graph READER of a published
// object-per-key set (e.g. a subtree store mirrored to a static web server / CDN —
// the immutable-object, cache-forever shape from the surface design). Objects are
// fetched per-key `objects/aa/aabb…hex`, self-verifying; the refs manifest is the
// `.cxstore-manifest` key. Reuses the shared store_graph replay — same object hashes
// as every other substrate, so a set published from s3/cxobj/cxpack reads back here
// byte-identically (cross-substrate object identity). Read-only: writes error.
//
// The fetch transport is injected (ReadTransport) so the §6 test runs HERMETICALLY
// over an in-memory map; production fetches via the existing remote GET.

// ReadTransport — read-only object fetch by key: (status, body, transport-ok).
pub interface ReadTransport {
	fetch(key string) (int, []u8, bool)
}

@[heap]
pub struct RemoteReadObjectBackend {
mut:
	transport ReadTransport
}

fn rro_obj_key(hash []u8) string {
	hx := hash.hex()
	return 'objects/${hx[..2]}/${hx}'
}

pub fn (b &RemoteReadObjectBackend) has_object(hash []u8) bool {
	st, body, ok := b.transport.fetch(rro_obj_key(hash))
	return ok && st == 200 && cxstore.object_name(body) == hash
}

// get_object fetches by content hash and self-verifies (a corrupt/substituted
// object is rejected as none — spec §4 integrity).
pub fn (b &RemoteReadObjectBackend) get_object(hash []u8) ?[]u8 {
	st, body, ok := b.transport.fetch(rro_obj_key(hash))
	if !ok || st != 200 {
		return none
	}
	if cxstore.object_name(body) != hash {
		return none
	}
	return body
}

// put_object — this backend is READ-ONLY (http GET / passive byte source). Writes
// fail loud; publish via a writable substrate (s3 / cxobj / cxpack) and mirror.
pub fn (mut b RemoteReadObjectBackend) put_object(payload []u8) ![]u8 {
	return error('remote subtree-read backend is read-only — publish via a writable substrate (s3/cxobj/cxpack) and mirror the object set')
}

// object_count — best-effort 0 (a passive byte source has no cheap listing).
pub fn (b &RemoteReadObjectBackend) object_count() int {
	return 0
}

pub fn (b &RemoteReadObjectBackend) get_manifest() ?string {
	st, body, ok := b.transport.fetch('.cxstore-manifest')
	if !ok || st != 200 {
		return none
	}
	return body.bytestr()
}

// ── production transport over the existing remote GET (store_remote.v) ────────

struct RemoteHttpReadTransport {
	rb &RemoteBackend
}

fn (t &RemoteHttpReadTransport) fetch(key string) (int, []u8, bool) {
	text, _, ok := store_remote_get(t.rb, key)
	if !ok {
		return 404, []u8{}, false
	}
	return 200, text.bytes(), true
}

pub fn new_remote_read_object_backend(rb &RemoteBackend) &RemoteReadObjectBackend {
	return &RemoteReadObjectBackend{
		transport: ReadTransport(&RemoteHttpReadTransport{
			rb: rb
		})
	}
}

// store_remote_read_load reopens a remote subtree-read store: read the refs manifest
// key and replay it, resolving every object lazily through the composite getter (one
// remote GET per object, self-verifying). A corrupt object → HARD CXER1120 error; a
// missing manifest → a legitimately empty (or non-subtree) source.
fn store_remote_read_load(mut ms MemStore) ! {
	if mut be := ms.obj_backend {
		if mut be is RemoteReadObjectBackend {
			content := be.get_manifest() or {
				ms.obj_backend = be
				return
			}
			ms.obj_backend = be
			getter := store_graph_getter(ms)
			store_graph_replay(mut ms, getter, content, 'remote-subtree ${ms.url}')!
			return
		}
		ms.obj_backend = be
	}
}
