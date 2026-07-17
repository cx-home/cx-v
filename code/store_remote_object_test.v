module code

import cx
import cxstore
import encoding.hex

// §3/§6.4/§6.5 for the CLIENT object wire (#129 PR-B.2): RemoteObjectBackend drives
// the real object-wire verbs against a daemon, exercised HERMETICALLY by routing
// through store_csrp_route (no socket — avoids the port/timing flakiness of a live
// server). Proves a client and daemon share ONE object space (cross-tier identity)
// and that only missing objects transfer (wire economy).

// LoopbackTransport sends each object-wire request straight to the in-process CSRP
// router against the daemon's store handle.
struct LoopbackTransport {
	local cx.Node
}

fn (t &LoopbackTransport) send(op string, query string, body string) (int, string, bool) {
	mut qp := map[string]string{}
	if query != '' {
		for part in query.split('&') {
			kv := part.split('=')
			if kv.len == 2 {
				qp[kv[0]] = kv[1]
			}
		}
	}
	resp := store_csrp_route(grpc_synth_req(op, '', body, qp, '', ''), t.local)
	mut status := 0
	if resp is cx.Element {
		status = csrp_attr(resp, 'status').int()
	}
	return status, svc_response_body(resp), true
}

fn ro_client(local cx.Node) &RemoteObjectBackend {
	return &RemoteObjectBackend{
		transport: ObjWireTransport(&LoopbackTransport{
			local: local
		})
	}
}

fn ro_decompose(text string) (string, map[string][]u8) {
	c := render_canonical(cx.parse(text) or { panic('p') }.elements[0])
	mut sink := cxstore.ObjectSink{}
	root := cxstore.store_document(mut sink, cx.parse(c) or { panic('p2') }, cxstore.default_fanout)
	mut objs := map[string][]u8{}
	for hk, payload in sink.objects {
		objs[hk] = payload.clone()
	}
	return root.hex(), objs
}

fn ro_daemon(tag string) cx.Node {
	return store_open_impl('mem://ro-${tag}-${cx.cx_text_hash(tag) or { tag }}', '', '',
		false, true, map[string]string{})
}

fn test_remote_object_backend_client_wire_crosstier() {
	daemon := ro_daemon('a')
	mut client := ro_client(daemon)
	text := '[order [id 1] [customer [name "Acme"] [addr [city "NYC"] [zip "10001"]]]]'
	c := render_canonical(cx.parse(text) or { panic('p') }.elements[0])
	store_key := cx.cx_text_hash(c) or { panic('h') }
	root_hex, objs := ro_decompose(text)

	// the daemon starts empty: the client sees every object missing.
	for hk, _ in objs {
		hb := hex.decode(hk) or { panic('hx') }
		assert !client.has_object(hb), 'daemon must not have object ${hk} yet'
	}
	// client uploads the objects over the wire.
	for _, payload in objs {
		client.put_object(payload) or { panic('put: ${err.msg()}') }
	}
	// now present; get round-trips + self-verifies (same hashes embedded vs wired → §6.4).
	for hk, payload in objs {
		hb := hex.decode(hk) or { panic('hx') }
		assert client.has_object(hb), 'object ${hk} must be present after put'
		got := client.get_object(hb) or { panic('get ${hk}: ${err.msg()}') }
		assert got == payload, 'get_object payload mismatch for ${hk}'
	}
	// ref set/resolve over the wire.
	rootb := hex.decode(root_hex) or { panic('rx') }
	client.set_ref(store_key, rootb) or { panic('set_ref: ${err.msg()}') }
	resolved := client.resolve_ref(store_key) or { panic('resolve_ref') }
	assert resolved.hex() == root_hex, 'ref must resolve store-key → root'

	// cross-tier reconstruction: the daemon rebuilds the doc from the wired objects.
	r := store_stdlib_builtin_inner('store-get-doc-text', [daemon, store_str(store_key)]) or {
		panic('reconstruct: ${err.msg()}')
	}
	assert r is cx.ScalarNode, 'daemon must reconstruct the doc from wired objects'
	assert csrp_scalar(r) == c, 'cross-tier reconstruction not byte-identical'
}

fn test_remote_object_backend_wire_economy() {
	daemon := ro_daemon('b')
	mut client := ro_client(daemon)
	shared_sub := '[customer [name "Acme"] [addr [city "NYC"] [zip "10001"] [country "US"]]]'
	_, objs1 := ro_decompose('[order [id 1] ${shared_sub}]')
	_, objs2 := ro_decompose('[order [id 2] ${shared_sub}]')

	for _, p in objs1 {
		client.put_object(p) or { panic('put1: ${err.msg()}') }
	}
	// doc2 shares the [customer …] subtree: only its NEW objects are missing.
	mut missing := 0
	for hk, _ in objs2 {
		hb := hex.decode(hk) or { panic('hx') }
		if !client.has_object(hb) {
			missing++
		}
	}
	assert missing > 0 && missing < objs2.len, 'wire economy: shared subtree must be resident; only new objects missing — ${missing} of ${objs2.len}'
}
