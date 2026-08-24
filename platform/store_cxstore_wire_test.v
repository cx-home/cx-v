module platform
import code {
	err_code_of,
	is_err_value,
	render_canonical,
}

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
	resp := svc_profile_data_op(grpc_synth_req(op, '', body, qp, '', ''), t.daemon, op)
	mut status := 0
	if resp is cx.Element {
		status = sw_attr(resp, 'status').int()
	}
	return status, svc_response_body(resp), true
}

// cxs_client builds a cx-store:// CLIENT handle whose object wire loops back to `daemon`
// in-process. `remote` is set (as the real open arm does), so store_objgraph_active stays
// false and the put/get intercept (store_objwire_client) drives the wire; the dummy rb is
// never dialed because put/get are intercepted before the document path.
fn cxs_client(daemon cx.Node, tag string) cx.Node {
	rb, _, _ := store_remote_parse('cx-store+xsp://loopback:1/${tag}/')
	mut ms := &MemStore{
		url:         'cx-store+xsp://loopback:1/${tag}/'
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
	assert sw_scalar(ph) == store_key, 'put store-key must be the canonical doc hash'

	// get-doc-text over the object wire (resolve ref + reconstruct) → byte-identical.
	gh := store_stdlib_builtin_inner('store-get-doc-text', [client, store_str(store_key)]) or {
		panic('get: ${err.msg()}')
	}
	assert gh is cx.ScalarNode, 'get-doc-text must return the canonical text'
	assert sw_scalar(gh) == canonical, 'object-wire round trip not byte-identical'

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
	assert dh is cx.ScalarNode && sw_scalar(dh) == canonical, 'cross-tier reconstruction mismatch'

	// a miss is the absence channel (), never null/[err] (§9.1.2.1).
	miss := store_stdlib_builtin_inner('store-get-doc-text', [client,
		store_str('sha2-256:${'0'.repeat(64)}')]) or {
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

// ── #645: alias remoting over the object wire ────────────────────────────────
//
// get-alias / list-aliases / set-alias on a cx-store:// CLIENT route to the
// daemon's authoritative alias table via the `aliases` / `aliases-set` wire
// ops (spec §3.14) — the CXER1709 refusal remains only for byte-source
// remotes with no CSRP service to ask. The wire answers presence EXPLICITLY
// (present="true|false" per name), resolving the #264 miss-vs-absence
// concern: an absent alias is a server-asserted absence (), never a
// client-side shrug, and never a lying empty.

fn test_cxstore_alias_wire_set_get_list() {
	daemon := cxs_daemon('alias')
	client := cxs_client(daemon, 'a')
	text := '[users [user [name "Ann"]]]'
	ph := store_stdlib_builtin_inner('store-put-doc-text', [client, store_str(text)]) or {
		panic('put: ${err.msg()}')
	}
	key := sw_scalar(ph)

	// set-alias over the wire lands in the DAEMON's alias table (one authority).
	sr := store_stdlib_builtin_inner('store-set-alias', [client, store_str('users'),
		store_str(key)]) or { panic('set-alias: ${err.msg()}') }
	assert !is_err_value(sr), 'remote set-alias must succeed: ${render_canonical(sr)}'
	dg := store_stdlib_builtin_inner('store-get-alias', [daemon, store_str('users')]) or {
		panic('daemon get-alias: ${err.msg()}')
	}
	assert sw_scalar(dg) == key, 'daemon-side alias table is the single authority'

	// get-alias over the wire resolves the same entry.
	cg := store_stdlib_builtin_inner('store-get-alias', [client, store_str('users')]) or {
		panic('get-alias: ${err.msg()}')
	}
	assert !is_err_value(cg), 'remote get-alias must succeed: ${render_canonical(cg)}'
	assert sw_scalar(cg) == key, 'remote get-alias must resolve the daemon alias'

	// a miss is the absence channel (server-asserted present="false"), never err.
	miss := store_stdlib_builtin_inner('store-get-alias', [client, store_str('nope')]) or {
		panic('miss: ${err.msg()}')
	}
	assert !is_err_value(miss), 'remote alias miss must be absence, not an error'
	assert miss !is cx.ScalarNode, 'remote alias miss must be the absence channel'

	// list-aliases over the wire: same [alias name=… hash=…] shape as local.
	lst := store_stdlib_builtin_inner('store-list-aliases', [client]) or {
		panic('list: ${err.msg()}')
	}
	assert !is_err_value(lst), 'remote list-aliases must succeed: ${render_canonical(lst)}'
	rendered := render_canonical(lst)
	assert rendered.contains('name=users') || rendered.contains("name='users'"), 'listing must carry the alias: ${rendered}'

	// set-alias to a hash the daemon does not hold refuses loudly (CXER1121,
	// the wire's 404 CXER1721 translated to the std-lib code — never silent).
	bad := store_stdlib_builtin_inner('store-set-alias', [client, store_str('ghost'),
		store_str('sha2-256:${'0'.repeat(64)}')]) or { panic('bad set: ${err.msg()}') }
	assert is_err_value(bad), 'set-alias to a missing target must refuse'
	assert err_code_of(bad) == 'cx-err:CXER1121', 'missing target maps to CXER1121: ${render_canonical(bad)}'
}

// The wire-level CAS on aliases-set (expect="…" / expect="" ⇒ must-not-exist):
// validate-then-apply, 409 CXER1114 on mismatch — the conflict-safe pointer
// advance the remote journal head rides (#644).
fn test_cxstore_alias_wire_cas() {
	daemon := cxs_daemon('aliascas')
	client := cxs_client(daemon, 'c')
	t1 := '[head [seq 1]]'
	t2 := '[head [seq 2]]'
	h1 := sw_scalar(store_stdlib_builtin_inner('store-put-doc-text', [client, store_str(t1)]) or {
		panic('put1')
	})
	h2 := sw_scalar(store_stdlib_builtin_inner('store-put-doc-text', [client, store_str(t2)]) or {
		panic('put2')
	})
	lb := CxsWireLoopback{
		daemon: daemon
	}

	// expect="" — the alias must not exist yet: first create wins…
	st1, _, _ := lb.send('aliases-set', '', '[aliases-set [a name="head" hash="${h1}" expect=""]]')
	assert st1 == 200, 'create-if-absent must apply (status ${st1})'
	// …the second create-if-absent conflicts.
	st2, body2, _ := lb.send('aliases-set', '', '[aliases-set [a name="head" hash="${h2}" expect=""]]')
	assert st2 == 409, 'second create-if-absent must 409 (status ${st2})'
	assert body2.contains('CXER1114'), 'conflict carries CXER1114: ${body2}'

	// CAS advance with the correct expectation applies…
	st3, _, _ := lb.send('aliases-set', '', '[aliases-set [a name="head" hash="${h2}" expect="${h1}"]]')
	assert st3 == 200, 'CAS advance with correct expect must apply (status ${st3})'
	g := store_stdlib_builtin_inner('store-get-alias', [daemon, store_str('head')]) or {
		panic('get')
	}
	assert sw_scalar(g) == h2, 'alias advanced to h2'
	// …and a stale expectation refuses without applying.
	st4, _, _ := lb.send('aliases-set', '', '[aliases-set [a name="head" hash="${h1}" expect="${h1}"]]')
	assert st4 == 409, 'stale CAS must 409 (status ${st4})'
	g2 := store_stdlib_builtin_inner('store-get-alias', [daemon, store_str('head')]) or {
		panic('get2')
	}
	assert sw_scalar(g2) == h2, 'stale CAS must not move the alias'
}
