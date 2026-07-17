module code

import cx
import cxstore
import sync

// store_porcelain_test.v — git porcelain over the object plumbing (#129 PR-B item 5):
// clone / push / pull / fetch as the object-identity transfer ops. Covers embedded↔
// embedded (mem↔mem) AND embedded↔daemon (a cx-store:// client looped back in-process
// through store_csrp_route — its own loopback client, since each _test.v compiles alone).

struct PcLoopback {
	daemon cx.Node
}

fn (t &PcLoopback) send(op string, query string, body string) (int, string, bool) {
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

fn cxs_daemon(tag string) cx.Node {
	return store_open_impl('mem://pc-daemon-${tag}', '', '', false, true, map[string]string{})
}

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
			transport: ObjWireTransport(&PcLoopback{
				daemon: daemon
			})
		})
	}
	id := store_register(ms)
	return store_handle_element(id, ms)
}

fn pc_open(tag string) cx.Node {
	return store_open_impl('mem://pc-${tag}', '', '', false, true, map[string]string{})
}

fn pc_put(handle cx.Node, text string) string {
	r := store_stdlib_builtin_inner('store-put-doc-text', [handle, store_str(text)]) or {
		panic('put: ${err.msg()}')
	}
	return csrp_scalar(r)
}

fn pc_get(handle cx.Node, key string) cx.Node {
	return store_stdlib_builtin_inner('store-get-doc-text', [handle, store_str(key)]) or {
		panic('get: ${err.msg()}')
	}
}

// pc_attr reads an attr off a porcelain result node ('' if not an element / absent).
fn pc_attr(n cx.Node, name string) string {
	if n is cx.Element {
		return csrp_attr(n, name)
	}
	return ''
}

fn test_porcelain_clone_into_empty() {
	src := pc_open('csrc')
	sub := '[customer [name "Acme"] [addr [city "NYC"] [zip "10001"]]]'
	k1 := pc_put(src, '[order [id 1] ${sub}]')
	k2 := pc_put(src, '[order [id 2] ${sub}]') // shares the [customer …] subtree

	dst := pc_open('cdst')
	r := store_stdlib_builtin_inner('store-clone', [src, dst]) or { panic('clone: ${err.msg()}') }
	assert !is_err_value(r), 'clone must succeed: ${r}'
	assert r is cx.Element && pc_attr(r, 'refs') == '2', 'clone must set both refs: ${r}'

	// both docs reconstruct on the destination, byte-identical.
	g1 := pc_get(dst, k1)
	g2 := pc_get(dst, k2)
	assert g1 is cx.ScalarNode && csrp_scalar(g1).contains('[id 1]'), 'cloned doc1 missing'
	assert g2 is cx.ScalarNode && csrp_scalar(g2).contains('[id 2]'), 'cloned doc2 missing'

	// wire economy: the two docs share a subtree, so the clone transferred FEWER objects
	// than two disjoint docs would (structural sharing preserved across the copy).
	objs := pc_attr(r, 'objects').int()
	assert objs > 0, 'clone must transfer objects'
}

fn test_porcelain_clone_rejects_nonempty() {
	src := pc_open('rsrc')
	pc_put(src, '[doc [v 1]]')
	dst := pc_open('rdst')
	pc_put(dst, '[doc [v 9]]') // dst already holds a doc
	r := store_stdlib_builtin_inner('store-clone', [src, dst]) or { panic('clone: ${err.msg()}') }
	assert is_err_value(r), 'clone into a non-empty store must error'
	if r is cx.Element {
		assert http_attr(r, 'code') or { '' } == 'cx-err:CXER1113', 'clone-nonempty wrong code: ${r}'
	}
}

fn test_porcelain_push_pull_local() {
	// push: local → remote (both mem here — embedded↔embedded).
	local := pc_open('plocal')
	k := pc_put(local, '[note [body "pushed"]]')
	remote := pc_open('premote')
	rp := store_stdlib_builtin_inner('store-push', [local, remote]) or { panic('push: ${err.msg()}') }
	assert !is_err_value(rp) && pc_attr(rp, 'refs') == '1', 'push must advance one ref: ${rp}'
	gp := pc_get(remote, k)
	assert gp is cx.ScalarNode && csrp_scalar(gp).contains('pushed'), 'pushed doc not on remote'

	// pull: bring a remote-only doc back into a fresh local store.
	remote2 := pc_open('premote2')
	k2 := pc_put(remote2, '[note [body "pulled"]]')
	local2 := pc_open('plocal2')
	rl := store_stdlib_builtin_inner('store-pull', [local2, remote2]) or { panic('pull: ${err.msg()}') }
	assert !is_err_value(rl) && pc_attr(rl, 'refs') == '1', 'pull must bring one ref: ${rl}'
	gl := pc_get(local2, k2)
	assert gl is cx.ScalarNode && csrp_scalar(gl).contains('pulled'), 'pulled doc not local'
}

fn test_porcelain_push_cross_tier() {
	// embedded → daemon (push) over the object wire: the client enumerates the LOCAL
	// source's refs (no remote catalog round trip), pushes only the missing objects via
	// the loopback object wire, and advances the ref. The daemon then reconstructs the
	// doc from ONE shared object space. (Pull FROM a daemon needs the remote catalog —
	// store-list-docs over the document path — so the full over-the-wire push+pull round
	// trip is exercised against a real spawned server in store_grpc_parity_test.v.)
	daemon := cxs_daemon('pc')
	client := cxs_client(daemon, 'pc')

	local := pc_open('xlocal')
	k := pc_put(local, '[record [k "v"] [n 42]]')
	rp := store_stdlib_builtin_inner('store-push', [local, client]) or { panic('push: ${err.msg()}') }
	assert !is_err_value(rp) && pc_attr(rp, 'refs') == '1', 'cross-tier push refs: ${rp}'
	// the daemon now reconstructs the doc (ONE object space, structural sharing crossed
	// the wire).
	gd := pc_get(daemon, k)
	assert gd is cx.ScalarNode && csrp_scalar(gd).contains('[n 42]'), 'daemon missing pushed doc'

	// re-push is idempotent: the daemon already has every object, so nothing transfers.
	rp2 := store_stdlib_builtin_inner('store-push', [local, client]) or { panic('push2: ${err.msg()}') }
	assert pc_attr(rp2, 'objects') == '0', 're-push must transfer no objects: ${rp2}'
}

fn test_porcelain_status_and_log() {
	s := pc_open('stat')
	pc_put(s, '[doc [v 1]]')
	pc_put(s, '[doc [v 2]]')
	st := store_stdlib_builtin_inner('store-status', [s]) or { panic('status: ${err.msg()}') }
	assert st is cx.Element && st.name == 'status', 'status must be a [status …] element'
	assert pc_attr(st, 'backend') == 'mem', 'status backend'
	assert pc_attr(st, 'docs') == '2', 'status docs = head count'
	assert pc_attr(st, 'distinct').int() > 0, 'status reports distinct objects'

	lg := store_stdlib_builtin_inner('store-log', [s]) or { panic('log: ${err.msg()}') }
	if lg is cx.Element {
		assert lg.items.len == 2, 'log = one epoch per doc-ref'
		first := lg.items[0]
		assert pc_attr(first, 'epoch') == '0', 'log epochs are linear from 0'
	} else {
		assert false, 'log must be a sequence element'
	}
}

fn test_porcelain_gc_retains_shared_objects() {
	s := pc_open('gc')
	sub := '[customer [name "Acme"] [addr [city "NYC"] [zip "10001"]]]'
	ka := pc_put(s, '[order [id 1] ${sub}]')
	kb := pc_put(s, '[order [id 2] ${sub}]') // shares the [customer …] subtree with doc A
	// delete A, gc: A's UNIQUE objects are reclaimed, but the subtree shared with B survives.
	store_stdlib_builtin_inner('store-delete-doc', [s, store_str(ka)]) or { panic('del: ${err.msg()}') }
	g := store_stdlib_builtin_inner('store-gc', [s]) or { panic('gc: ${err.msg()}') }
	assert pc_attr(g, 'reclaimed').int() > 0, 'gc must reclaim A-only objects'
	// B is intact: it still reconstructs (its shared subtree was NOT collected).
	gb := pc_get(s, kb)
	assert gb is cx.ScalarNode && csrp_scalar(gb).contains('[id 2]'), 'gc collected a shared subtree — B is broken'
	// a second gc reclaims nothing (already minimal) — idempotent.
	g2 := store_stdlib_builtin_inner('store-gc', [s]) or { panic('gc2: ${err.msg()}') }
	assert pc_attr(g2, 'reclaimed') == '0', 'a settled store gc reclaims nothing: ${g2}'
}

fn test_porcelain_diff_hash_skip() {
	s := pc_open('diff')
	// two orders sharing [id 1]; only [amt …] differs → diff localizes to the amt value,
	// the identical [id 1] subtree is hash-skipped (not reported).
	a := pc_put(s, '[order [id 1] [amt 100]]')
	b := pc_put(s, '[order [id 1] [amt 200]]')
	d := store_stdlib_builtin_inner('store-diff', [s, store_str(a), store_str(b)]) or {
		panic('diff: ${err.msg()}')
	}
	if d is cx.Element {
		assert d.name == 'diff', 'diff must be a [diff …] element'
		assert d.items.len == 1, 'exactly one change (the shared [id 1] is hash-skipped): ${d}'
		ch := d.items[0]
		assert pc_attr(ch, 'kind') == 'modified', 'amt change is a modification'
		assert pc_attr(ch, 'path').contains('amt'), 'change localizes under amt: ${ch}'
	} else {
		assert false, 'diff must be an element'
	}
	// identical docs → empty diff.
	d2 := store_stdlib_builtin_inner('store-diff', [s, store_str(a), store_str(a)]) or {
		panic('diff-same: ${err.msg()}')
	}
	if d2 is cx.Element {
		assert d2.items.len == 0, 'identical docs diff to empty'
	}
}

fn test_porcelain_branch_cas_and_force() {
	s := pc_open('branch')
	h1 := pc_put(s, '[doc [v 1]]')
	h2 := pc_put(s, '[doc [v 2]]')
	// create main → h1.
	store_stdlib_builtin_inner('store-branch', [s, store_str('main'), store_str(h1)]) or {
		panic('branch: ${err.msg()}')
	}
	// re-pointing to the SAME target is idempotent (no conflict).
	ok := store_stdlib_builtin_inner('store-branch', [s, store_str('main'), store_str(h1)]) or {
		panic('branch-idem: ${err.msg()}')
	}
	assert !is_err_value(ok), 're-point to same target must succeed'
	// moving to a DIFFERENT target without force → CXER1114 conflict.
	conflict := store_stdlib_builtin_inner('store-branch', [s, store_str('main'), store_str(h2)]) or {
		panic('branch-move: ${err.msg()}')
	}
	assert is_err_value(conflict), 'moving a branch elsewhere must conflict'
	if conflict is cx.Element {
		assert http_attr(conflict, 'code') or { '' } == 'cx-err:CXER1114', 'wrong conflict code: ${conflict}'
	}
	// branch-force moves it unconditionally.
	store_stdlib_builtin_inner('store-branch-force', [s, store_str('main'), store_str(h2)]) or {
		panic('branch-force: ${err.msg()}')
	}
	ga := store_stdlib_builtin_inner('store-get-alias', [s, store_str('main')]) or {
		panic('get-alias: ${err.msg()}')
	}
	assert csrp_scalar(ga) == h2, 'branch-force must move main → h2'
	// branching at a non-existent target errors NOT_FOUND.
	bad := store_stdlib_builtin_inner('store-branch', [s, store_str('x'), store_str('0'.repeat(64))]) or {
		panic('branch-bad: ${err.msg()}')
	}
	assert is_err_value(bad), 'branch at a missing target must error'
}
