module code

import cx
import cxstore

// store_porcelain.v — git-style porcelain over the object plumbing have/get/put/refs
// (#129 PR-B item 5, spec §3 / the locked surface design). The transfer verbs
// (clone/push/pull/fetch) are the OBJECT-IDENTITY ops: they move only the objects the
// destination is MISSING and then advance its refs (store-key → doc-root). Because a
// store-key is content-addressed (the SHA-256 of the doc's canonical bytes), a doc ref
// is IMMUTABLE — re-setting it is idempotent and conflict-free, so a doc push never needs
// a non-fast-forward reject (that concern belongs to the mutable alias/branch layer).
//
// All four transfer verbs are ONE engine (pc_transfer) differing only in direction and,
// for clone, an empty-destination precondition:
//   clone $src $dst   — copy src into an empty dst.
//   push  $local $rem — local → remote.
//   pull  $local $rem — remote → local (objects + refs).
//   fetch $local $rem — remote → local (objects + refs).
// An endpoint may be embedded (a local object-graph store) OR a cx-store:// client (the
// daemon is just one endpoint) — the engine treats both uniformly through the object
// seam, so "clone/push/pull works embedded↔embedded AND embedded↔daemon" is literal.

// pc_list_keys returns the store-keys (doc refs) a store endpoint holds. A cx-store://
// client asks the daemon's authoritative catalog (store-list-docs over the wire); a
// local object-graph store enumerates its own ref order.
fn pc_list_keys(handle cx.Node, ms &MemStore) ![]string {
	if store_objwire_client(ms) != none {
		r := store_stdlib_builtin_inner('store-list-docs', [handle]) or {
			return error('list-docs failed')
		}
		if is_err_value(r) {
			return error('list-docs error')
		}
		mut out := []string{}
		if r is cx.Element {
			for it in r.items {
				k := csrp_scalar(it)
				if k != '' {
					out << k
				}
			}
		}
		return out
	}
	return ms.doc_order.clone()
}

// pc_resolve maps a store-key → its doc-root object hash for an endpoint (remote over
// the wire, local from the refs map).
fn pc_resolve(ms &MemStore, key string) ?[]u8 {
	if owc := store_objwire_client(ms) {
		return owc.resolve_ref(key)
	}
	return ms.obj_roots[key] or { none }
}

// pc_source_getter resolves objects from the SOURCE endpoint for the reachability walk:
// over the wire for a cx-store client (one objects-get per object), from the live graph
// + durable backend for a local store.
fn pc_source_getter(ms &MemStore) fn (h []u8) ?[]u8 {
	if owc := store_objwire_client(ms) {
		return fn [owc] (h []u8) ?[]u8 {
			return owc.get_object(h)
		}
	}
	return store_graph_getter(ms)
}

// pc_transfer copies every object reachable from the SOURCE store's doc-refs into the
// DEST store, transferring only the objects the dest is MISSING, then advances the dest's
// refs. Returns (objects_transferred, refs_set). Content-addressed → idempotent: a
// re-run transfers nothing new.
fn pc_transfer(src_handle cx.Node, src &MemStore, mut dst MemStore) !(int, int) {
	keys := pc_list_keys(src_handle, src)!
	src_get := pc_source_getter(src)
	dst_owc := store_objwire_client(dst)
	mut objects := 0
	mut refs := 0
	for key in keys {
		root := pc_resolve(src, key) or { continue }
		live := cxstore.mark_live(src_get, [root]) // hex(hash) → payload, all reachable
		if mut owc := dst_owc {
			// remote dest: one batched have→put-missing for the whole reachable set.
			sink := cxstore.ObjectSink{
				objects: live.clone()
			}
			objects += owc.push_sink(sink)!
			owc.set_ref(key, root)!
		} else {
			// local dest: put each missing object into the live sink.
			dst_get := store_graph_getter(dst)
			for _, payload in live {
				h := cxstore.object_name(payload)
				if dst_get(h) != none {
					continue
				}
				dst.obj_sink.put(payload)
				objects++
			}
			if key !in dst.obj_roots {
				dst.doc_order << key
			}
			dst.obj_roots[key] = root
		}
		refs++
	}
	if dst_owc == none {
		// make the transferred objects + refs durable locally
		store_persist(mut dst) or {
			return error('transfer persist failed: ${err.msg()}')
		}
	}
	return objects, refs
}

// pc_result builds the [<verb>-result objects=N refs=M] element the transfer verbs return.
fn pc_result(verb string, objects int, refs int) cx.Node {
	return cx.Element{
		name:  '${verb}-result'
		attrs: [
			cx.Attribute{
				name:  'objects'
				value: cx.ScalarValue(i64(objects))
			},
			cx.Attribute{
				name:  'refs'
				value: cx.ScalarValue(i64(refs))
			},
		]
	}
}

// store_clone — `[$store:clone $src $dst]`: copy every reachable object + doc-ref from
// `src` into the EMPTY `dst`. Errors (CXER1113) if `dst` already holds docs — clone is
// "fetch-all into empty"; use pull/fetch to merge into a populated store.
// pc_object_transfer_guard rejects an object-identity porcelain op (clone/push/
// pull/fetch) against an endpoint that has NO Merkle object identity — a columnar
// store (doc-identity only; columnar spec §4: "a capability-gated error directing
// the caller to migrate — never a silent partial") or a remote byte-source
// backend that isn't the object wire (#185: migrate/porcelain over ftp/http/etc.
// were client-local phantoms). Returns none when the endpoint supports object
// transfer (object-graph-active, or a cx-store:// object-wire client). Never lets
// the op fall through to a fabricated `objects=0` success.
fn pc_object_transfer_guard(ms &MemStore, verb string, role string) ?cx.Node {
	if ms.backend == 'columnar' {
		return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: ${verb} ${role} `${ms.url}` is a columnar store (doc-identity only, no Merkle object graph) — use `migrate` to copy docs across the model boundary (columnar spec §4)')
	}
	if ms.remote != unsafe { nil } && store_objwire_client(ms) == none {
		return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: ${verb} ${role} `${ms.url}` is a remote byte-source backend with no object wire — use `migrate` (object-identity transfer needs a subtree/object-wire endpoint, store.md §6.3)')
	}
	if !store_objgraph_active(ms) && store_objwire_client(ms) == none {
		return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: ${verb} ${role} `${ms.url}` has no object graph — use `migrate` (store.md §6.3)')
	}
	return none
}

fn store_clone(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err('cx-err:CXER0108', 'E_ARG: clone expects ($src $dst)')
	}
	src, serr, sok := store_get_open(args[0])
	if !sok {
		return serr
	}
	mut dst, derr, dok := store_get_open(args[1])
	if !dok {
		return derr
	}
	if dst.read_only {
		return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${dst.url}')
	}
	if e := pc_object_transfer_guard(src, 'clone', 'source') {
		return e
	}
	if e := pc_object_transfer_guard(dst, 'clone', 'destination') {
		return e
	}
	existing := pc_list_keys(args[1], dst) or {
		return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
	}
	if existing.len > 0 {
		return mk_err('cx-err:CXER1113', 'E_STORE_NOT_EMPTY: clone target ${dst.url} already holds ${existing.len} doc(s) — use pull/fetch to merge')
	}
	objects, refs := pc_transfer(args[0], src, mut dst) or {
		return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: clone: ${err.msg()}')
	}
	return pc_result('clone', objects, refs)
}

// store_push — `[$store:push $local $remote]`: send `local`'s objects the `remote` is
// missing, then advance the remote's refs. have→put-missing→set-ref; idempotent.
fn store_push(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err('cx-err:CXER0108', 'E_ARG: push expects ($local $remote)')
	}
	local, lerr, lok := store_get_open(args[0])
	if !lok {
		return lerr
	}
	mut remote, rerr, rok := store_get_open(args[1])
	if !rok {
		return rerr
	}
	if remote.read_only {
		return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${remote.url}')
	}
	if e := pc_object_transfer_guard(local, 'push', 'source') {
		return e
	}
	if e := pc_object_transfer_guard(remote, 'push', 'destination') {
		return e
	}
	objects, refs := pc_transfer(args[0], local, mut remote) or {
		return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: push: ${err.msg()}')
	}
	return pc_result('push', objects, refs)
}

// store_pull — `[$store:pull $local $remote]`: bring the `remote`'s objects the `local`
// is missing + its refs into `local`. For a content-addressed store there is no working
// tree and doc-refs are immutable, so pull and fetch coincide (no semantic merge — that
// is the future mutable-branch layer).
fn store_pull(args []cx.Node) ?cx.Node {
	return store_pull_fetch(args, 'pull')
}

// store_fetch — `[$store:fetch $local $remote]`: bring the `remote`'s objects + refs into
// `local` (see store_pull on the pull/fetch equivalence here).
fn store_fetch(args []cx.Node) ?cx.Node {
	return store_pull_fetch(args, 'fetch')
}

fn store_pull_fetch(args []cx.Node, verb string) ?cx.Node {
	if args.len < 2 {
		return mk_err('cx-err:CXER0108', 'E_ARG: ${verb} expects ($local $remote)')
	}
	mut local, lerr, lok := store_get_open(args[0])
	if !lok {
		return lerr
	}
	remote, rerr, rok := store_get_open(args[1])
	if !rok {
		return rerr
	}
	if local.read_only {
		return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${local.url}')
	}
	if e := pc_object_transfer_guard(remote, verb, 'source') {
		return e
	}
	if e := pc_object_transfer_guard(local, verb, 'destination') {
		return e
	}
	// direction is remote → local (the source is args[1], the dest args[0]).
	objects, refs := pc_transfer(args[1], remote, mut local) or {
		return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: ${verb}: ${err.msg()}')
	}
	return pc_result(verb, objects, refs)
}

// ── introspection + maintenance: status / log / gc / prune ───────────────────────

// store_status — `[$store:status $store]`: a snapshot of the store's heads + object
// economy. For a local object-graph store it reports docs (heads), distinct objects,
// the logical/distinct dedup ratio, and the unflushed-ref count; for a remote/byte-source
// store it reports the head count from the catalog (object economy lives server-side).
fn store_status(args []cx.Node) ?cx.Node {
	if args.len < 1 {
		return mk_err('cx-err:CXER0108', 'E_ARG: status expects ($store)')
	}
	mut ms, errn, ok := store_get_open(args[0])
	if !ok {
		return errn
	}
	// #248: on a service-tier handle, status is the SERVER's admin-plane op
	// (CSRP §3.10) — the daemon reports its authoritative object economy
	// (admin RBAC enforced server-side). Byte-source remotes keep the local
	// catalog-derived summary below.
	if store_remote_active(ms) && csrp_scheme(ms.remote.scheme) {
		return store_remote_admin(ms.remote, 'status')
	}
	mut attrs := [
		cx.Attribute{
			name:  'backend'
			value: cx.ScalarValue(ms.backend)
		},
	]
	if store_objgraph_active(ms) {
		count := ms.doc_order.len
		st := store_objgraph_stats(mut ms, count)
		mut unflushed := 0
		for h in ms.doc_order {
			if h !in ms.doc_manifested {
				unflushed++
			}
		}
		attrs << cx.Attribute{
			name:  'docs'
			value: cx.ScalarValue(i64(st.doc_count))
		}
		attrs << cx.Attribute{
			name:  'objects'
			value: cx.ScalarValue(i64(st.object_count))
		}
		attrs << cx.Attribute{
			name:  'logical'
			value: cx.ScalarValue(st.logical_objects)
		}
		attrs << cx.Attribute{
			name:  'distinct'
			value: cx.ScalarValue(i64(st.distinct_objects))
		}
		attrs << cx.Attribute{
			name:  'unflushed'
			value: cx.ScalarValue(i64(unflushed))
		}
	} else if ms.backend == 'columnar' {
		// #129 D5 §4: a columnar store is doc-identity only — object_count / dedup
		// are object-graph metrics, reported as NOT-APPLICABLE (absent; no fabricated
		// zeros and NOT remote). It reports its OWN observables: row count (docs),
		// encoding, codec, the pushdown flag, and column count (reserved + promoted).
		attrs << cx.Attribute{
			name:  'docs'
			value: cx.ScalarValue(i64(ms.doc_order.len))
		}
		attrs << cx.Attribute{
			name:  'encoding'
			value: cx.ScalarValue(ms.encoding)
		}
		attrs << cx.Attribute{
			name:  'codec'
			value: cx.ScalarValue(ms.compression)
		}
		attrs << cx.Attribute{
			name:  'columnar-pushdown'
			value: cx.ScalarValue(ms.columnar_pushdown)
		}
		$if cxstore_columnar ? {
			attrs << cx.Attribute{
				name:  'columns'
				value: cx.ScalarValue(i64(2 + store_columnar_schema(ms).len))
			}
		}
	} else {
		keys := pc_list_keys(args[0], ms) or { []string{} }
		attrs << cx.Attribute{
			name:  'docs'
			value: cx.ScalarValue(i64(keys.len))
		}
		attrs << cx.Attribute{
			name:  'remote'
			value: cx.ScalarValue(true)
		}
	}
	return cx.Element{
		name:  'status'
		attrs: attrs
	}
}

// store_log — `[$store:log $store]`: the ref-log, linear. Each held doc-ref is one epoch
// in insertion order (store-key → doc-root); old roots persist as objects, so this is the
// store's history without a separate commit DAG (object_model.md §4/A.5). Returns a
// sequence of [ref epoch=N key="…" root="…"].
fn store_log(args []cx.Node) ?cx.Node {
	if args.len < 1 {
		return mk_err('cx-err:CXER0108', 'E_ARG: log expects ($store)')
	}
	ms, errn, ok := store_get_open(args[0])
	if !ok {
		return errn
	}
	if !store_objgraph_active(ms) {
		return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: log needs a local object-graph store (the ref-log is server-side for a remote mount)')
	}
	mut items := []cx.Node{}
	for i, key in ms.doc_order {
		root := ms.obj_roots[key] or { continue }
		items << cx.Element{
			name:  'ref'
			attrs: [
				cx.Attribute{
					name:  'epoch'
					value: cx.ScalarValue(i64(i))
				},
				cx.Attribute{
					name:  'key'
					value: cx.ScalarValue(key)
				},
				cx.Attribute{
					name:  'root'
					value: cx.ScalarValue(root.hex())
				},
			]
		}
	}
	return store_seq(items)
}

// pc_reclaim drops every in-memory object NOT reachable from the store's live doc-refs and
// returns (reclaimed, kept). Shared by gc + prune: a content-addressed object stays live
// while ANY ref reaches it, so a shared subtree is never collected on another doc's delete.
fn pc_reclaim(mut ms MemStore) (int, int) {
	mut roots := [][]u8{cap: ms.obj_roots.len}
	for _, r in ms.obj_roots {
		roots << r
	}
	getter := store_graph_getter(ms)
	live := cxstore.mark_live(getter, roots)
	before := ms.obj_sink.objects.len
	mut kept := map[string][]u8{}
	for hk, payload in ms.obj_sink.objects {
		if hk in live {
			kept[hk] = payload
		}
	}
	reclaimed := before - kept.len
	ms.obj_sink.objects = kept.move()
	// #299: the sink map was rebuilt, so any sink-tail durability watermark
	// (obj_flushed prefix count) is meaningless now — reset it. The next flush
	// re-puts the kept objects (content-addressed, idempotent) once.
	ms.obj_flushed = 0
	return reclaimed, ms.obj_sink.objects.len
}

// store_prune — `[$store:prune $store]`: reclaim objects no live doc-ref reaches (the
// subset of gc that drops unreachable objects without rewriting durable storage).
fn store_prune(args []cx.Node) ?cx.Node {
	if args.len < 1 {
		return mk_err('cx-err:CXER0108', 'E_ARG: prune expects ($store)')
	}
	mut ms, errn, ok := store_get_open(args[0])
	if !ok {
		return errn
	}
	if ms.read_only {
		return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${ms.url}')
	}
	if !store_objgraph_active(ms) {
		if store_remote_active(ms) {
			return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: prune needs a local object-graph store')
		}
		// #290 flat document model (the legacy file:// index and its kin): every
		// doc IS its own single object AND a root — exactly pc_reclaim's
		// obj_roots semantics — so there is never a sub-doc object to reclaim.
		// §15 lists prune under write (file/local): succeed and report honestly
		// (reclaimed=0, objects=live docs) instead of raising.
		return cx.Element{
			name:  'prune-result'
			attrs: [
				cx.Attribute{
					name:  'reclaimed'
					value: cx.ScalarValue(i64(0))
				},
				cx.Attribute{
					name:  'objects'
					value: cx.ScalarValue(i64(ms.docs.len))
				},
			]
		}
	}
	reclaimed, kept := pc_reclaim(mut ms)
	return cx.Element{
		name:  'prune-result'
		attrs: [
			cx.Attribute{
				name:  'reclaimed'
				value: cx.ScalarValue(i64(reclaimed))
			},
			cx.Attribute{
				name:  'objects'
				value: cx.ScalarValue(i64(kept))
			},
		]
	}
}

// store_gc — `[$store:gc $store]`: prune unreachable objects AND make the result durable
// (per-substrate compaction). gc = prune + flush/compact; for an in-memory store the sink
// IS the store, so it equals prune; for the durable backends store_persist rewrites the
// reclaimed graph.
fn store_gc(args []cx.Node) ?cx.Node {
	if args.len < 1 {
		return mk_err('cx-err:CXER0108', 'E_ARG: gc expects ($store)')
	}
	mut ms, errn, ok := store_get_open(args[0])
	if !ok {
		return errn
	}
	// #248: on a service-tier handle, gc triggers the SERVER's compaction (CSRP
	// §3.11, admin RBAC enforced server-side) — the object economy lives there.
	if store_remote_active(ms) && csrp_scheme(ms.remote.scheme) {
		return store_remote_admin(ms.remote, 'gc')
	}
	if ms.read_only {
		return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${ms.url}')
	}
	if !store_objgraph_active(ms) {
		if store_remote_active(ms) {
			return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: gc needs a local object-graph store')
		}
		// #290 flat document model: gc = prune + durable compaction. The prune
		// half reclaims nothing (every present doc is a root — see store_prune);
		// the durable half folds the append log (stale D records, #291
		// tombstones) into a snapshot of live state via store_persist.
		store_persist(mut ms) or { return store_persist_err(ms, err.msg()) }
		ms.log_records = ms.doc_order.len + ms.alias_order.len
		return cx.Element{
			name:  'gc-result'
			attrs: [
				cx.Attribute{
					name:  'reclaimed'
					value: cx.ScalarValue(i64(0))
				},
				cx.Attribute{
					name:  'objects'
					value: cx.ScalarValue(i64(ms.docs.len))
				},
			]
		}
	}
	reclaimed, kept := pc_reclaim(mut ms)
	// durable compaction (cxpack reachability-GC, etc.)
	store_persist(mut ms) or { return store_persist_err(ms, err.msg()) }
	return cx.Element{
		name:  'gc-result'
		attrs: [
			cx.Attribute{
				name:  'reclaimed'
				value: cx.ScalarValue(i64(reclaimed))
			},
			cx.Attribute{
				name:  'objects'
				value: cx.ScalarValue(i64(kept))
			},
		]
	}
}

// ── diff + branch (mutable named refs) ───────────────────────────────────────────

// store_diff — `[$store:diff $store $a $b]`: the structural diff of two stored docs BY
// HASH. Resolves both store-keys to doc-roots and walks the object graphs in tandem,
// skipping identical subtrees in O(1) (content-addressed) — so the cost is O(changed),
// not O(document size). Returns [diff [change path="…" kind="modified|added|removed"] …]
// (an empty [diff] means the two docs are identical). Read-only.
fn store_diff(args []cx.Node) ?cx.Node {
	if args.len < 3 {
		return mk_err('cx-err:CXER0108', 'E_ARG: diff expects ($store $a $b)')
	}
	ms, errn, ok := store_get_open(args[0])
	if !ok {
		return errn
	}
	ka := store_arg_str(args[1]) or { return none }
	kb := store_arg_str(args[2]) or { return none }
	root_a := pc_resolve(ms, ka) or {
		return mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: ${ka}')
	}
	root_b := pc_resolve(ms, kb) or {
		return mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: ${kb}')
	}
	getter := pc_source_getter(ms)
	entries := cxstore.diff_docs(getter, root_a, root_b)
	mut items := []cx.Node{}
	for e in entries {
		items << cx.Element{
			name:  'change'
			attrs: [
				cx.Attribute{
					name:  'path'
					value: cx.ScalarValue(e.path)
				},
				cx.Attribute{
					name:  'kind'
					value: cx.ScalarValue(e.kind)
				},
			]
		}
	}
	return cx.Element{
		name:  'diff'
		items: items
	}
}

// store_branch / store_branch_force — `[$store:branch $store $name $target]` points a
// mutable named ref at a doc (branches/tags ARE git refs over the alias layer). The
// default refuses to MOVE an existing branch that points elsewhere (CXER1114 — the
// CAS-style safe default, "non-fast-forward reject"); `branch-force` moves it
// unconditionally (the `--force` that skips the check). Creating a new branch, or
// re-pointing one at its current target, always succeeds.
fn store_branch(args []cx.Node) ?cx.Node {
	return store_branch_impl(args, false)
}

fn store_branch_force(args []cx.Node) ?cx.Node {
	return store_branch_impl(args, true)
}

fn store_branch_impl(args []cx.Node, force bool) ?cx.Node {
	if args.len < 3 {
		return mk_err('cx-err:CXER0108', 'E_ARG: branch expects ($store $name $target)')
	}
	mut ms, errn, ok := store_get_open(args[0])
	if !ok {
		return errn
	}
	if ms.read_only {
		return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${ms.url}')
	}
	name := store_arg_str(args[1]) or { return none }
	target := store_arg_str(args[2]) or { return none }
	if !store_doc_present(ms, target) && !store_doc_present(ms, 'code:${target}') {
		return mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: branch target ${target}')
	}
	if !force {
		if cur := ms.aliases[name] {
			if cur != target {
				return mk_err('cx-err:CXER1114', 'E_STORE_REF_CONFLICT: branch ${name} points at ${cur}, not ${target} — use branch-force to move it')
			}
		}
	}
	if name !in ms.aliases {
		ms.alias_order << name
	}
	ms.aliases[name] = target
	store_append(mut ms, store_alias_record(name, target)) or {
		return store_persist_err(ms, err.msg())
	}
	return cx.Element{
		name:  'branch'
		attrs: [
			cx.Attribute{
				name:  'name'
				value: cx.ScalarValue(name)
			},
			cx.Attribute{
				name:  'target'
				value: cx.ScalarValue(target)
			},
		]
	}
}
