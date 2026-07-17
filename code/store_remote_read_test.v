module code

import cx
import cxstore

// §6 for B3 (#129): read-only SUBTREE read over a read-only byte source (http/ftp/
// sftp), run HERMETICALLY over an in-memory published object set. Proves a set
// published in object-per-key layout (objects/aa/… + .cxstore-manifest) reads back
// byte-identically through the universal seam (cross-substrate object identity),
// is read-only, and fails HARD on a corrupted object.

@[heap]
struct ReadStub {
mut:
	blobs map[string][]u8
}

fn (s &ReadStub) fetch(key string) (int, []u8, bool) {
	if v := s.blobs[key] {
		return 200, v, true
	}
	return 404, []u8{}, true
}

fn rr_canon_hash(text string) (string, string) {
	c := render_canonical(cx.parse(text) or { panic('parse: ${err.msg()}') }.elements[0])
	h := cx.cx_text_hash(c) or { panic('hash: ${err.msg()}') }
	return c, h
}

// rr_publish builds the subtree object graph for `texts` (as a writable substrate
// would) and mirrors it into the stub as object-per-key + a refs manifest.
fn rr_publish(mut stub ReadStub, texts []string) map[string]string {
	mut pub_ms := &MemStore{
		backend: 'mem'
		is_open: true
	}
	mut canon := map[string]string{}
	for t in texts {
		c, h := rr_canon_hash(t)
		root := cxstore.store_document(mut pub_ms.obj_sink, cx.parse(c) or { panic('p') },
			cxstore.default_fanout)
		pub_ms.obj_roots[h] = root
		pub_ms.doc_order << h
		canon[h] = c
	}
	for hk, payload in pub_ms.obj_sink.objects {
		stub.blobs['objects/${hk[..2]}/${hk}'] = payload.clone()
	}
	stub.blobs['.cxstore-manifest'] = store_graph_snapshot_lines(pub_ms).join('\n').bytes()
	return canon
}

fn rr_reader(stub &ReadStub) &MemStore {
	return &MemStore{
		url:         'https://cdn.example/store'
		backend:     'https'
		is_open:     true
		read_only:   true
		model:       'subtree'
		obj_backend: cxstore.ObjectBackend(&RemoteReadObjectBackend{
			transport: ReadTransport(stub)
		})
	}
}

fn test_remote_subtree_read_roundtrip_and_readonly() {
	mut stub := &ReadStub{}
	canon := rr_publish(mut stub, ['[order [id 1] [customer [name "Acme"]]]',
		'[order [id 2] [customer [name "Acme"]]]'])

	mut ms := rr_reader(stub)
	assert store_objgraph_active(ms), 'model=subtree remote read must route through the object graph'
	store_remote_read_load(mut ms) or { panic('load: ${err.msg()}') }
	for h, want in canon {
		assert store_doc_present(ms, h), 'published doc ${h} must be present'
		got := store_doc_text(ms, h) or { panic('get ${h}: ${err.msg()}') }
		assert got == want, 'remote subtree-read round-trip not byte-identical for ${h}'
	}

	// read-only: writes must fail loud.
	mut rrb := RemoteReadObjectBackend{
		transport: ReadTransport(stub)
	}
	if _ := rrb.put_object('x'.bytes()) {
		assert false, 'remote subtree-read backend must reject writes (read-only)'
	}
}

fn test_remote_subtree_read_corruption_is_hard_error() {
	mut stub := &ReadStub{}
	rr_publish(mut stub, ['[doc [item "hello"]]'])
	// corrupt every object (not the manifest) — bytes no longer hash to key.
	for k in stub.blobs.keys() {
		if k.contains('objects/') {
			stub.blobs[k] = 'corrupted'.bytes()
		}
	}
	mut ms := rr_reader(stub)
	if _ := rr_load_result(mut ms) {
		assert false, 'reopen of a corrupted remote subtree set must be a hard error'
	}
}

fn rr_load_result(mut ms MemStore) ?bool {
	store_remote_read_load(mut ms) or { return none }
	return true
}
