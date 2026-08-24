module platform
import code {
	render_canonical,
}

import cx
import cxstore

// §6 conformance for the s3 SUBTREE object substrate (#129 Phase 3), run HERMETICALLY
// against an in-memory S3 stub (no live S3/minio). White-box over S3ObjectBackend +
// store_graph: gate items 1 (round-trip + reopen), 2 (dedup), 3 (version-sharing),
// 6 (integrity → hard error). The dispatch wiring ([$store s3://] → this path) is a
// separate increment; this proves the backend's behavior in isolation.

// StubTransport — an in-memory S3 transport (PUT/GET/HEAD over a map, LIST = keys).
// Two backends sharing one stub model a reopen against the same bucket.
@[heap]
struct StubTransport {
mut:
	blobs map[string][]u8
}

fn (t &StubTransport) fetch(method string, key string) (int, []u8, bool) {
	match method {
		'HEAD' {
			return if key in t.blobs { 200 } else { 404 }, []u8{}, true
		}
		'GET' {
			if v := t.blobs[key] {
				return 200, v, true
			}
			return 404, []u8{}, true
		}
		else {
			return 400, []u8{}, true
		}
	}
}

fn (mut t StubTransport) store(key string, body []u8) (int, bool) {
	t.blobs[key] = body.clone()
	return 200, true
}

fn (mut t StubTransport) remove(key string) (int, bool) {
	t.blobs.delete(key)
	return 204, true
}

fn (t &StubTransport) keys() []string {
	return t.blobs.keys()
}

fn s3t_new(t &StubTransport) &MemStore {
	return &MemStore{
		url:         's3://bucket/prefix'
		backend:     's3'
		is_open:     true
		obj_backend: cxstore.ObjectBackend(&S3ObjectBackend{
			transport: S3Transport(t)
		})
	}
}

// s3t_put stages a doc into the live graph (as the dispatch's store_put_canonical
// would) and flushes through the s3 backend.
fn s3t_put(mut ms MemStore, text string) string {
	pdoc := cx.parse(text) or { panic('parse: ${err.msg()}') }
	c := render_canonical(pdoc.elements[0])
	cdoc := cx.parse(c) or { panic('reparse: ${err.msg()}') }
	h := cx.cx_text_hash(c) or { panic('hash: ${err.msg()}') }
	root := cxstore.store_document(mut ms.obj_sink, cdoc, cxstore.default_fanout)
	if h !in ms.obj_roots {
		ms.obj_roots[h] = root
		ms.doc_order << h
	}
	store_s3_flush(mut ms) or { panic('flush: ${err.msg()}') }
	return h
}

fn s3t_canon(text string) string {
	return render_canonical(cx.parse(text) or { panic('p') }.elements[0])
}

fn test_s3_subtree_roundtrip_dedup_versionsharing() {
	mut stub := &StubTransport{}
	mut ms := s3t_new(stub)

	shared_sub := '[customer [name "Acme"] [addr [city "NYC"] [zip "10001"]]]'
	h1 := s3t_put(mut ms, '[order [id 1] ${shared_sub}]')
	after1 := ms.obj_backend or { panic('nb') }.object_count()

	// GATE 2 (dedup): second doc shares the whole [customer …] subtree.
	h2 := s3t_put(mut ms, '[order [id 2] ${shared_sub}]')
	after2 := ms.obj_backend or { panic('nb') }.object_count()
	added := after2 - after1
	assert added > 0 && added < after1, 'dedup: doc2 must add only its delta (shared subtree stored once): doc1=${after1}, doc2 added ${added}'

	// GATE 3 (version-sharing): a one-field new version of doc1 re-stores only the
	// changed root-to-node path; the customer subtree object is shared.
	before_v := ms.obj_backend or { panic('nb') }.object_count()
	_ := s3t_put(mut ms, '[order [id 1] [rev "2"] ${shared_sub}]')
	added_v := (ms.obj_backend or { panic('nb') }.object_count()) - before_v
	assert added_v > 0 && added_v < after1, 'version-sharing: a one-field version must add only the changed path: added ${added_v} vs full ${after1}'

	// GATE 1 (round-trip + reopen): a fresh backend over the same bucket replays the
	// manifest and reconstructs both docs byte-identically (objects fetched lazily,
	// self-verifying).
	mut ms2 := s3t_new(stub)
	store_s3_load(mut ms2) or { panic('reopen: ${err.msg()}') }
	getter := store_graph_getter(ms2)
	for h, want in {
		h1: s3t_canon('[order [id 1] ${shared_sub}]')
		h2: s3t_canon('[order [id 2] ${shared_sub}]')
	} {
		root := ms2.obj_roots[h] or { panic('missing root after reopen: ${h}') }
		doc := cxstore.load_document_from(getter, root) or { panic('reconstruct ${h}: ${err.msg()}') }
		assert render_canonical(doc.elements[0]) == want, 's3 round-trip not byte-identical after reopen for ${h}'
	}
}

// GATE 6 (universal integrity / CXER1120): a corrupted object makes the reopen fail
// HARD — never a silent drop.
fn test_s3_subtree_corruption_is_hard_error() {
	mut stub := &StubTransport{}
	mut ms := s3t_new(stub)
	h1 := s3t_put(mut ms, '[order [id 1] [customer [name "Acme"]]]')
	_ := h1

	// corrupt every stored object (not the manifest) — bytes no longer hash to key,
	// so each fails its content-address self-verify on read.
	for k in stub.blobs.keys() {
		if k.contains(s3_objects_prefix) {
			stub.blobs[k] = 'corrupted'.bytes()
		}
	}

	mut ms2 := s3t_new(stub)
	if _ := store_s3_load_result(mut ms2) {
		assert false, 'reopen of a corrupted s3 store must be a hard error, not a silent success'
	}
}

// store_s3_load_result wraps store_s3_load as `?` so the test can assert failure.
fn store_s3_load_result(mut ms MemStore) ?bool {
	store_s3_load(mut ms) or { return none }
	return true
}

// LIVE CONSUMER: drive the actual store verb-level functions (store_put_canonical /
// store_persist / store_doc_text — what [$store:put-doc]/[get-doc] call) over an
// s3-backed MemStore, proving the dispatch routes s3 through the object graph and
// the seam, not just the backend in isolation.
fn test_s3_subtree_live_verb_path() {
	mut stub := &StubTransport{}
	mut ms := s3t_new(stub)
	assert store_objgraph_active(ms), 's3 must route through the object graph (not the docs map / remote-doc path)'

	c := s3t_canon('[order [id 7] [customer [name "Beta"] [addr [city "LA"]]]]')
	h := cx.cx_text_hash(c) or { panic('h: ${err.msg()}') }
	store_put_canonical(mut ms, h, c) or { panic('put: ${err.msg()}') }
	store_persist(mut ms) or { panic('persist: ${err.msg()}') }
	assert store_doc_present(ms, h), 'doc must be present via the verb path'
	got := store_doc_text(ms, h) or { panic('get: ${err.msg()}') }
	assert got == c, 'live verb round-trip not byte-identical'

	// reopen via a fresh handle over the same bucket, then read through the verb path.
	mut ms2 := s3t_new(stub)
	store_s3_load(mut ms2) or { panic('reopen: ${err.msg()}') }
	assert store_doc_present(ms2, h), 'doc must survive reopen via the verb path'
	got2 := store_doc_text(ms2, h) or { panic('get2: ${err.msg()}') }
	assert got2 == c, 'reopen round-trip via the verb path not byte-identical'
}

// ── #213: wrong-secret / enforced-403 honesty ─────────────────────────────────
// The transport returns 403 for everything (what a wrong secret produces after
// correct SigV4 signing). Every surface must raise CXER1131 E_STORE_AUTH_FAILED
// — never phantom write success, never not-found/empty-store masking.

@[heap]
struct DenyTransport {
mut:
	puts int
}

fn (t &DenyTransport) fetch(method string, key string) (int, []u8, bool) {
	return 403, []u8{}, true
}

fn (mut t DenyTransport) store(key string, body []u8) (int, bool) {
	t.puts++
	return 403, true
}

fn (mut t DenyTransport) remove(key string) (int, bool) {
	return 403, true
}

fn (t &DenyTransport) keys() []string {
	return []string{}
}

fn s3t_deny_new(t &DenyTransport) &MemStore {
	return &MemStore{
		url:         's3://bucket/denied'
		backend:     's3'
		is_open:     true
		obj_backend: cxstore.ObjectBackend(&S3ObjectBackend{
			transport: S3Transport(t)
		})
	}
}

fn s3t_err_code(n cx.Node) string {
	if n is cx.Element {
		if n.name == 'err' {
			return sw_attr(n, 'code')
		}
	}
	return ''
}

fn test_s3_wrong_secret_open_raises_auth_failed() {
	// open: the 403 manifest GET is a credentials problem, NOT an empty store.
	deny := &DenyTransport{}
	mut ms := s3t_deny_new(deny)
	mut raised := false
	store_s3_load(mut ms) or {
		raised = true
		assert err.msg().contains('auth rejected'), 'open: expected auth-rejected, got: ${err.msg()}'
	}
	assert raised, 'open against a 403-enforcing bucket must raise, not open an empty store'
}

fn test_s3_wrong_secret_put_raises_never_phantom() {
	// put: the flush must RAISE (the phantom "returns the hash, nothing lands"
	// was the data-loss shape) and classify as CXER1131.
	mut deny := &DenyTransport{}
	mut ms := s3t_deny_new(deny)
	pdoc := cx.parse('[order [id 9] [who "mallory"]]') or { panic('parse') }
	c := render_canonical(pdoc.elements[0])
	cdoc := cx.parse(c) or { panic('reparse') }
	h := cx.cx_text_hash(c) or { panic('hash') }
	root := cxstore.store_document(mut ms.obj_sink, cdoc, cxstore.default_fanout)
	ms.obj_roots[h] = root
	ms.doc_order << h
	mut raised := false
	store_s3_flush(mut ms) or {
		raised = true
		en := store_persist_err(ms, err.msg())
		assert s3t_err_code(en) == 'cx-err:CXER1131', 'put: 403 must classify as E_STORE_AUTH_FAILED, got ${s3t_err_code(en)}: ${err.msg()}'
	}
	assert raised, 'put against a 403-enforcing bucket must raise, never ack'
}

fn test_s3_midsession_denial_get_raises_auth_failed() {
	// A doc stored while authorized, then credentials revoked (transport starts
	// 403ing): get must surface CXER1131, not CXER1120/1121.
	mut stub := &StubTransport{}
	mut ms := s3t_new(stub)
	h := s3t_put(mut ms, '[order [id 4] [customer [name "Gamma"]]]')
	// fresh handle over the same bucket, replay refs, then revoke:
	mut ms2 := s3t_new(stub)
	store_s3_load(mut ms2) or { panic('reopen: ${err.msg()}') }
	deny := &DenyTransport{}
	ms2.obj_backend = cxstore.ObjectBackend(&S3ObjectBackend{
		transport: S3Transport(deny)
	})
	id := store_register(ms2)
	handle := store_handle_element(id, ms2)
	r := store_stdlib_builtin_inner('store-get-doc', [handle, store_str(h)]) or {
		panic('dispatch failed')
	}
	assert s3t_err_code(r) == 'cx-err:CXER1131', 'mid-session 403 get must raise E_STORE_AUTH_FAILED, got: ${s3t_err_code(r)}'
}
