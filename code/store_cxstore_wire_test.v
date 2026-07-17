module code

import cx
import cxstore
import sync

// store_cxstore_wire_test.v — the LIVE [$store] cx-store:// put-doc → get-doc round trip
// over the OBJECT wire (#129 PR-B item 3). Exercised HERMETICALLY by routing the client's
// object-wire transport straight through store_csrp_route against an in-process daemon
// mount (no socket — avoids the port/timing flakiness of a spawned server, like the
// PR-B.2 client test). Proves a cx-store:// client decomposes locally, transfers only the
// objects the daemon is missing, advances the ref, and that a reader rebuilds
// byte-identically from the daemon's objects — and that the client and daemon share ONE
// object space (the daemon reconstructs the same doc, structural sharing crosses the wire).

struct CxsWireLoopback {
	daemon cx.Node
}

fn (t &CxsWireLoopback) send(op string, query string, body string) (int, string, bool) {
	mut qp := map[string]string{}
	if query != '' {
		for part in query.split('&') {
			kv := part.split('=')
			if kv.len == 2 {
				qp[kv[0]] = kv[1]
			}
		}
	}
	resp := store_csrp_route(grpc_synth_req(op, '', body, qp, '', ''), t.daemon)
	mut status := 0
	if resp is cx.Element {
		status = csrp_attr(resp, 'status').int()
	}
	return status, svc_response_body(resp), true
}

// cxs_client builds a cx-store:// CLIENT handle whose object wire loops back to `daemon`
// in-process. `remote` is set (as the real open arm does), so store_objgraph_active stays
// false and the put/get intercept (store_objwire_client) drives the wire; the dummy rb is
// never dialed because put/get are intercepted before the document path.
fn cxs_client(daemon cx.Node, tag string) cx.Node {
	rb, _, _ := store_remote_parse('cx-store+http://loopback/${tag}/')
	mut ms := &MemStore{
		url:         'cx-store+http://loopback/${tag}/'
		backend:     'cx-store'
		encoding:    'cxbin'
		compression: 'none'
		is_open:     true
		op_lock:     sync.new_mutex()
		remote:      rb
		obj_backend: cxstore.ObjectBackend(&RemoteObjectBackend{
			transport: ObjWireTransport(&CxsWireLoopback{
				daemon: daemon
			})
		})
	}
	id := store_register(ms)
	return store_handle_element(id, ms)
}

fn cxs_daemon(tag string) cx.Node {
	return store_open_impl('mem://cxs-${tag}', '', '', false, true, map[string]string{})
}

// cxs_object_count reads how many distinct objects a (mem) daemon holds.
fn cxs_object_count(handle cx.Node) int {
	g := store_for_guard(handle) or { return -1 }
	return g.obj_sink.objects.len
}

// cxs_decompose_count is how many objects the doc decomposes into on its own.
fn cxs_decompose_count(text string) int {
	c := render_canonical(cx.parse(text) or { panic('p') }.elements[0])
	mut sink := cxstore.ObjectSink{}
	cxstore.store_document(mut sink, cx.parse(c) or { panic('p2') }, cxstore.default_fanout)
	return sink.objects.len
}

fn test_cxstore_object_wire_put_get_roundtrip() {
	daemon := cxs_daemon('rt')
	client := cxs_client(daemon, 't')
	text := '[order [id 1] [customer [name "Acme"] [addr [city "NYC"] [zip "10001"]]]]'
	canonical := render_canonical(cx.parse(text) or { panic('p') }.elements[0])
	store_key := cx.cx_text_hash(canonical) or { panic('h') }

	// put-doc-text over the object wire → the canonical store-key.
	ph := store_stdlib_builtin_inner('store-put-doc-text', [client, store_str(text)]) or {
		panic('put: ${err.msg()}')
	}
	assert !is_err_value(ph), 'put must succeed: ${ph}'
	assert csrp_scalar(ph) == store_key, 'put store-key must be the canonical doc hash'

	// get-doc-text over the object wire (resolve ref + reconstruct) → byte-identical.
	gh := store_stdlib_builtin_inner('store-get-doc-text', [client, store_str(store_key)]) or {
		panic('get: ${err.msg()}')
	}
	assert gh is cx.ScalarNode, 'get-doc-text must return the canonical text'
	assert csrp_scalar(gh) == canonical, 'object-wire round trip not byte-identical'

	// get-doc (node form) reconstructs + rehash-verifies.
	gd := store_stdlib_builtin_inner('store-get-doc', [client, store_str(store_key)]) or {
		panic('get-doc: ${err.msg()}')
	}
	assert !is_err_value(gd), 'get-doc must succeed: ${gd}'
	assert render_canonical(gd) == canonical, 'get-doc node not byte-identical'

	// cross-tier: the daemon reconstructs the SAME doc from the wired objects (ONE space).
	dh := store_stdlib_builtin_inner('store-get-doc-text', [daemon, store_str(store_key)]) or {
		panic('daemon get: ${err.msg()}')
	}
	assert dh is cx.ScalarNode && csrp_scalar(dh) == canonical, 'cross-tier reconstruction mismatch'

	// a miss is the absence channel (), never null/[err] (§9.1.2.1).
	miss := store_stdlib_builtin_inner('store-get-doc-text', [client, store_str('0'.repeat(64))]) or {
		panic('miss: ${err.msg()}')
	}
	assert !is_err_value(miss), 'miss must be absence, not an error'
	assert miss !is cx.ScalarNode, 'a miss must be the absence channel, not text'
}

fn test_cxstore_object_wire_economy() {
	daemon := cxs_daemon('econ')
	client := cxs_client(daemon, 'e')
	sub := '[customer [name "Acme"] [addr [city "NYC"] [zip "10001"] [country "US"]]]'
	doc1 := '[order [id 1] ${sub}]'
	doc2 := '[order [id 2] ${sub}]'

	store_stdlib_builtin_inner('store-put-doc-text', [client, store_str(doc1)]) or {
		panic('put1: ${err.msg()}')
	}
	n1 := cxs_object_count(daemon)
	store_stdlib_builtin_inner('store-put-doc-text', [client, store_str(doc2)]) or {
		panic('put2: ${err.msg()}')
	}
	n2 := cxs_object_count(daemon)

	added := n2 - n1
	d2 := cxs_decompose_count(doc2)
	// doc2 shares the [customer …] subtree, so the second put adds FEWER objects than the
	// doc decomposes into — the shared subtree was already resident and did NOT re-transfer.
	assert added > 0, 'doc2 must add at least its new objects (added ${added})'
	assert added < d2, 'wire economy: shared subtree must not re-transfer — added ${added} of ${d2} objects'
}
