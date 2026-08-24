module platform
import code {
	render_canonical,
}

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
	resp := svc_profile_data_op(grpc_synth_req(op, '', body, qp, '', ''), t.local, op)
	mut status := 0
	if resp is cx.Element {
		status = sw_attr(resp, 'status').int()
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
	assert sw_scalar(r) == c, 'cross-tier reconstruction not byte-identical'
}

// §6 item 5 in the task's literal form (RULED: UOM-1): pushing a doc that
// shares a subtree with one already on the server transfers STRICTLY FEWER
// content bytes than the whole doc — measured through the REAL client funnel
// (push_doc = decompose → objects-have → objects-put of only the missing →
// refs-set), counting the objects-put request bodies (the content-transfer
// direction; the have probe is membership metadata, not content).
@[heap]
struct WireByteBox {
mut:
	put_bytes int
	have_hits int
}

struct CountingTransport {
	inner &LoopbackTransport
	box   &WireByteBox
}

fn (t &CountingTransport) send(op string, query string, body string) (int, string, bool) {
	mut b := unsafe { t.box }
	if op == 'objects-put' {
		b.put_bytes += body.len
	}
	if op == 'objects-have' {
		b.have_hits++
	}
	return t.inner.send(op, query, body)
}

fn test_remote_object_backend_put_doc_bytes_on_wire_lt_whole_doc() {
	daemon := ro_daemon('c')
	box := &WireByteBox{}
	client := &RemoteObjectBackend{
		transport: ObjWireTransport(&CountingTransport{
			inner: &LoopbackTransport{
				local: daemon
			}
			box:   box
		})
	}
	mut lines := []string{}
	for i in 0 .. 24 {
		lines << '[item [sku "SKU-${i}"] [qty ${i}] [desc "warehouse line item ${i} with enough descriptive padding text to carry real content weight"]]'
	}
	shared_sub := '[lines ${lines.join(' ')}]'
	c1 := render_canonical(cx.parse('[order [id 1] ${shared_sub}]') or { panic('p1') }.elements[0])
	c2 := render_canonical(cx.parse('[order [id 2] ${shared_sub}]') or { panic('p2') }.elements[0])

	k1 := client.push_doc(c1, '') or { panic('push1: ${err.msg()}') }
	assert k1 == (cx.cx_text_hash(c1) or { panic('h1') }), 'store key = canonical doc hash'

	// second doc shares the fat [lines …] subtree: reset the meter and push.
	mut mbox := unsafe { box }
	mbox.put_bytes = 0
	mbox.have_hits = 0
	k2 := client.push_doc(c2, '') or { panic('push2: ${err.msg()}') }
	assert k2 == (cx.cx_text_hash(c2) or { panic('h2') }), 'store key = canonical doc hash'
	assert box.have_hits > 0, 'push_doc must probe objects-have (the dedup-on-wire primitive)'
	assert box.put_bytes > 0, 'the second push still transfers its new root-path objects'
	assert box.put_bytes < c2.len, 'wire economy (§6.5): bytes-on-wire ${box.put_bytes} must be < whole-doc ${c2.len} — an unchanged shared subtree is never re-sent'

	// and the daemon serves doc2 back byte-identical (the delta really landed).
	r := store_stdlib_builtin_inner('store-get-doc-text', [daemon, store_str(k2)]) or {
		panic('get: ${err.msg()}')
	}
	assert r is cx.ScalarNode, 'daemon must reconstruct doc2'
	assert sw_scalar(r) == c2, 'doc2 reconstruction not byte-identical'
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
