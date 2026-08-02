module code

import cx
import cxstore
import sync

// journal_remote_wire_test.v — #644: the journal rides a cx-store:// mount.
//
// A journal ATTACHED to a CSRP client handle appends, re-reads, verifies, and
// reloads entirely over the object wire: entry docs travel as objects
// (put-doc), the per-stream head/algo metadata and entry pointers ride the
// #645 alias remoting (`aliases` / `aliases-set`) into the DAEMON's
// authoritative tables — so a second attach (a fresh journal instance, or a
// different process) rehydrates the chain from the daemon and the hash chain
// verifies green. Exercised HERMETICALLY through store_csrp_route (no socket),
// like store_cxstore_wire_test.v.

struct JrwLoopback {
	daemon cx.Node
}

fn (t &JrwLoopback) send(op string, query string, body string) (int, string, bool) {
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

fn jrw_client(daemon cx.Node, tag string) cx.Node {
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
			transport: ObjWireTransport(&JrwLoopback{
				daemon: daemon
			})
		})
	}
	id := store_register(ms)
	return store_handle_element(id, ms)
}

fn jrw_append(j cx.Node, event string) cx.Node {
	ev := cx.parse(event) or { panic('parse event') }.elements[0]
	attribution := cx.Element{
		name:  map_marker_name
		items: [
			cx.Node(cx.Element{
				name:  'actor'
				items: [cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue('did:key:test')
					data_type: cx.ScalarType.string_type
				})]
			}),
			cx.Node(cx.Element{
				name:  'authority'
				items: [cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue('test:suite')
					data_type: cx.ScalarType.string_type
				})]
			}),
		]
	}
	return journal_stdlib_builtin('journal-append', [j, cx.Node(ev), cx.Node(attribution)]) or {
		panic('append: ${err.msg()}')
	}
}

fn test_journal_attach_on_csrp_client_appends_and_reloads() {
	caps_set_all() // remote store ops are net effects; grant like the daemon process does
	daemon := store_open_impl('mem://jrw-daemon', '', '', false, true, map[string]string{})
	client := jrw_client(daemon, 'j')

	// attach a journal to the REMOTE handle and append two events.
	j := journal_stdlib_builtin('journal-attach', [client, store_str('acme')]) or {
		panic('attach: ${err.msg()}')
	}
	assert !is_err_value(j), 'attach on a CSRP client handle must succeed: ${render_canonical(j)}'
	r1 := jrw_append(j, '[do :a]')
	assert !is_err_value(r1), 'append 1 over the wire: ${render_canonical(r1)}'
	r2 := jrw_append(j, '[do :b]')
	assert !is_err_value(r2), 'append 2 over the wire: ${render_canonical(r2)}'

	// the chain head advanced on the DAEMON's authoritative tables.
	hd := journal_stdlib_builtin('journal-head', [j]) or { panic('head: ${err.msg()}') }
	assert render_canonical(hd).contains('seq=2'), 'head must be seq 2: ${render_canonical(hd)}'

	// verify green over the wire.
	v := journal_stdlib_builtin('journal-verify', [j]) or { panic('verify: ${err.msg()}') }
	assert !is_err_value(v), 'verify: ${render_canonical(v)}'
	assert render_canonical(v).contains('valid=true'), 'chain must verify: ${render_canonical(v)}'

	// a FRESH attach (second client instance — the reopen path) rehydrates the
	// chain from the daemon: head, entries, and verification all green.
	client2 := jrw_client(daemon, 'j2')
	j2 := journal_stdlib_builtin('journal-attach', [client2, store_str('acme')]) or {
		panic('re-attach: ${err.msg()}')
	}
	assert !is_err_value(j2), 're-attach: ${render_canonical(j2)}'
	hd2 := journal_stdlib_builtin('journal-head', [j2]) or { panic('head2: ${err.msg()}') }
	assert render_canonical(hd2).contains('seq=2'), 'rehydrated head must be seq 2: ${render_canonical(hd2)}'
	rd := journal_stdlib_builtin('journal-read', [j2, cx.Node(bus_int(1))]) or {
		panic('read: ${err.msg()}')
	}
	assert render_canonical(rd).contains(':a'), 'entry 1 must rehydrate: ${render_canonical(rd)}'
	v2 := journal_stdlib_builtin('journal-verify', [j2]) or { panic('verify2: ${err.msg()}') }
	assert render_canonical(v2).contains('valid=true'), 'rehydrated chain must verify: ${render_canonical(v2)}'

	// a third append CONTINUES the chain from the rehydrated head.
	r3 := jrw_append(j2, '[do :c]')
	assert !is_err_value(r3), 'append 3 after rehydrate: ${render_canonical(r3)}'
	assert render_canonical(r3).contains('seq=3'), 'chain continues at seq 3: ${render_canonical(r3)}'
}
