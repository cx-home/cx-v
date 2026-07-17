module code

import cx
import cxstore

// §3/§6.4/§6.5 for the object-level wire (#129 PR-B): the daemon exchanges
// content-addressed OBJECTS (objects-have/get/put) + ref resolution (refs/refs-set)
// so a client's object graph and the daemon's are ONE space. Driven hermetically
// through store_csrp_route (the CSRP router) against an in-process mem store —
// proving cross-tier object identity (same hashes embedded vs over the wire) and
// wire economy (only missing objects transfer).

fn ow_open(tag string) cx.Node {
	return store_open_impl('mem://objwire-${tag}-${cx.cx_text_hash(tag) or { tag }}', '',
		'', false, true, map[string]string{})
}

// ow_decompose decomposes a doc with the EMBEDDED engine → (root hex, hexhash→payload).
fn ow_decompose(text string) (string, map[string][]u8) {
	c := render_canonical(cx.parse(text) or { panic('p') }.elements[0])
	mut sink := cxstore.ObjectSink{}
	root := cxstore.store_document(mut sink, cx.parse(c) or { panic('p2') }, cxstore.default_fanout)
	mut objs := map[string][]u8{}
	for hk, payload in sink.objects {
		objs[hk] = payload.clone()
	}
	return root.hex(), objs
}

fn ow_route(local cx.Node, op string, body string) string {
	resp := store_csrp_route(grpc_synth_req(op, '', body, map[string]string{}, '', ''), local)
	return svc_response_body(resp)
}

// ow_obj_hashes collects the h="…" attrs of the [o …] children of a result element.
fn ow_obj_hashes(body string) []string {
	mut out := []string{}
	doc := cx.parse(body) or { return out }
	if doc.elements.len > 0 {
		top := doc.elements[0]
		if top is cx.Element {
			for it in top.items {
				if it is cx.Element && it.name == 'o' {
					h := csrp_attr(it, 'h')
					if h != '' {
						out << h
					}
				}
			}
		}
	}
	return out
}

fn ow_have_body(objs map[string][]u8) string {
	mut b := '[have'
	for hk, _ in objs {
		b += ' [o h="${hk}"]'
	}
	return b + ']'
}

fn test_object_wire_have_put_get_refs_crosstier() {
	local := ow_open('a')
	text := '[order [id 1] [customer [name "Acme"] [addr [city "NYC"] [zip "10001"]]]]'
	c := render_canonical(cx.parse(text) or { panic('p') }.elements[0])
	root_hex, objs := ow_decompose(text)
	store_key := cx.cx_text_hash(c) or { panic('h') }

	// have: a fresh daemon is missing EVERY object.
	missing0 := ow_obj_hashes(ow_route(local, 'objects-have', ow_have_body(objs)))
	assert missing0.len == objs.len, 'fresh daemon must report all ${objs.len} objects missing, got ${missing0.len}'

	// put the missing objects (the client uploads only what have reported).
	mut put_body := '[put'
	for _, payload in objs {
		put_body += ' [o bytes="${payload.hex()}"]'
	}
	put_body += ']'
	ow_route(local, 'objects-put', put_body)

	// have again → nothing missing: the daemon now holds the SAME object hashes the
	// embedded engine produced (cross-tier object identity, §6.4).
	missing1 := ow_obj_hashes(ow_route(local, 'objects-have', ow_have_body(objs)))
	assert missing1.len == 0, 'after put, no objects missing, got ${missing1.len}'

	// get one back, self-verifying.
	any_h := objs.keys()[0]
	got := ow_obj_hashes(ow_route(local, 'objects-get', '[get [o h="${any_h}"]]'))
	assert got.len == 1 && got[0] == any_h, 'objects-get must return the requested object'

	// refs-set then refs: the store-key resolves to the doc root.
	ow_route(local, 'refs-set', '[refs-set [r key="${store_key}" root="${root_hex}"]]')
	refs_body := ow_route(local, 'refs', '[refs [k key="${store_key}"]]')
	rdoc := cx.parse(refs_body) or { panic('refs parse') }
	mut resolved := ''
	if rdoc.elements.len > 0 {
		top := rdoc.elements[0]
		if top is cx.Element {
			for it in top.items {
				if it is cx.Element && it.name == 'r' && csrp_attr(it, 'key') == store_key {
					resolved = csrp_attr(it, 'root')
				}
			}
		}
	}
	assert resolved == root_hex, 'refs must resolve store-key → doc root: got ${resolved} want ${root_hex}'

	// cross-tier reconstruction: the daemon rebuilds the doc from the wired objects,
	// byte-identical to the embedded canonical.
	r := store_stdlib_builtin_inner('store-get-doc-text', [local, store_str(store_key)]) or {
		panic('reconstruct: ${err.msg()}')
	}
	assert r is cx.ScalarNode, 'daemon must reconstruct the doc from wired objects'
	assert csrp_scalar(r) == c, 'cross-tier reconstruction not byte-identical'
}

// §6.5 object-wire economy: putting a doc that shares a subtree with one already on
// the server transfers ONLY the new objects.
fn test_object_wire_economy_shared_subtree() {
	local := ow_open('b')
	shared_sub := '[customer [name "Acme"] [addr [city "NYC"] [zip "10001"] [country "US"]]]'
	_, objs1 := ow_decompose('[order [id 1] ${shared_sub}]')
	_, objs2 := ow_decompose('[order [id 2] ${shared_sub}]')

	// upload doc1 fully.
	mut put1 := '[put'
	for _, p in objs1 {
		put1 += ' [o bytes="${p.hex()}"]'
	}
	ow_route(local, 'objects-put', put1 + ']')

	// have(doc2): only doc2's NEW objects (the changed root-to-node path) are missing;
	// the shared [customer …] subtree objects are already resident.
	missing := ow_obj_hashes(ow_route(local, 'objects-have', ow_have_body(objs2)))
	assert missing.len > 0, 'doc2 must have some new objects'
	assert missing.len < objs2.len, 'wire economy: shared subtree must NOT re-transfer — missing ${missing.len} of ${objs2.len}'
}
