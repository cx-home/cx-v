module platform
import code {
	is_err_value,
	mk_err,
}

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
				k := sw_scalar(it)
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
			landed := key !in dst.obj_roots
			if landed {
				dst.doc_order << key
			}
			dst.obj_roots[key] = root
			if landed {
				// Stream 9 (the W4 finding, fixed at W7): a transferred doc is
				// a LIVE insert — it must reach the E3 docs feed exactly like
				// a local put, or a changes-since consumer over a synced store
				// silently misses pulled docs (the M5 replica's live views).
				store_feed_append(mut dst, 'docs', 'insert', '', key, root)
			}
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

// pc_heads builds the destination's per-stream HEAD-SET element — the same
// [heads [stream name= pos= hash?=]…] shape status reports (ONE vocabulary;
// stream 9, L176: sync results are head-set-bearing reports, never bare
// counters). Empty (absent) when the destination is not an object-graph
// store (byte-source remotes hold their heads server-side).
fn pc_heads(ms &MemStore) ?cx.Node {
	if !store_objgraph_active(ms) {
		return none
	}
	mut skeys := ms.adv_pos.keys()
	skeys.sort()
	mut hchildren := []cx.Node{}
	for k in skeys {
		mut hattrs := [
			cx.Attribute{
				name:  'name'
				value: cx.ScalarValue(k)
			},
			cx.Attribute{
				name:  'pos'
				value: cx.ScalarValue(ms.adv_pos[k] or { i64(0) })
			},
		]
		if k.starts_with('aliases/') {
			target := ms.aliases[k.all_after('aliases/')] or { '' }
			if target != '' {
				hattrs << cx.Attribute{
					name:  'hash'
					value: cx.ScalarValue(target)
				}
			}
		}
		hchildren << cx.Element{
			name:  'stream'
			attrs: hattrs
		}
	}
	return cx.Node(cx.Element{
		name:  'heads'
		items: hchildren
	})
}

// pc_result builds the [<verb>-result objects=N refs=M [heads …]] report the
// transfer verbs return — head-set-bearing (L176), with the DESTINATION's
// post-transfer heads when it is an object-graph store.
fn pc_result_heads(verb string, objects int, refs int, ms_dst &MemStore) cx.Node {
	mut items := []cx.Node{}
	if h := pc_heads(ms_dst) {
		items << h
	}
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
		items: items
	}
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

// store_erased_carry copies the source's erasure tombstones to the
// destination — stream 20's carriage (the R3.16 interim guard that refused
// transfer until this landed is REMOVED with it): the attributed `[erased …]`
// records ride whole-store transfer, so lawful-erasure attribution survives
// archival (§7: archived predecessors / archive= stores are inside the shred
// reach) and a later re-put of shredded content at the copy supersedes a
// RECORDED tombstone, never a silent void. The tombstone text stages as an
// ordinary sink object on object-graph destinations (the cxpack E-replay
// resolves it there) and each E record appends for durability — the §7b.1
// funnel's own persistence shape.
fn store_erased_carry(src &MemStore, mut dst MemStore) ! {
	if src.erased.len == 0 {
		return
	}
	mut recs := ''
	for h in src.erased_order {
		tomb := src.erased[h] or { continue }
		if h in dst.erased {
			continue
		}
		if h in dst.obj_roots || h in dst.docs {
			// the destination independently holds LIVE content at this
			// address — an insert supersedes a tombstone (§7b.1); replay
			// order decides, exactly as on the log.
			continue
		}
		store_replay_apply_erased(mut dst, h, tomb)
		if store_objgraph_active(dst) {
			dst.obj_sink.put(tomb.bytes())
		}
		dst.erased_dirty << h
		recs += store_erase_record(h, tomb)
	}
	if recs != '' {
		store_append(mut dst, recs)!
	}
}

// store_subject_docs enumerates the source's subject-keyed whole-doc set
// (doc hash → subject id), read through the doc path — the `subject=` attr
// lives INSIDE the sealed payload. The whole-store transfer verbs use it to
// preserve SEK custody across a copy (stream 20). Fail-closed: a
// subject-keyed doc that cannot be read or attributed is an error, never a
// silent partial.
fn store_subject_docs(src &MemStore) !map[string]string {
	mut out := map[string]string{}
	if !store_objgraph_active(src) {
		return out
	}
	mut m := unsafe { src }
	for hash, root in src.obj_roots {
		if !store_whole_doc_root(hash, root) {
			continue
		}
		mut kid := ''
		if raw := store_raw_envelope(mut m, root) {
			if env := cxstore.parse_envelope(raw) {
				kid = env.key_id
			}
		}
		if kid == '' {
			if ov := store_seal_override_for(mut m, root.hex()) {
				kid = ov
			}
		}
		if !kid.starts_with(cxstore.sek_id_prefix) {
			continue
		}
		text := store_doc_text(src, hash) or {
			return error('subject doc ${hash} unreadable on ${src.url}: ${err.msg()}')
		}
		doc := cx.parse(text) or { return error('subject doc ${hash} undecodable on ${src.url}') }
		if doc.elements.len == 0 {
			return error('subject doc ${hash} empty on ${src.url}')
		}
		subj := store_subject_attr(doc.elements[0]) or {
			return error('subject-keyed doc ${hash} carries no subject= attr on ${src.url}')
		}
		out[hash] = subj
	}
	return out
}

// store_subject_custody_carry pre-registers destination seal routing for the
// source's subject docs: each subject gets the DESTINATION's own SEK
// (mint-if-absent through its custody sidecar), so the copied whole-doc
// objects seal under a destroyable key THERE — a copy re-sealed under the
// tenant KEK (or landing plaintext) would defeat crypto-shredding exactly
// where §7 demands reach (archive= stores). Refuses CXER1144 when the
// destination cannot honor custody — never a silent plaintext landing.
fn store_subject_custody_carry(src &MemStore, mut dst MemStore, verb string) ?cx.Node {
	subs := store_subject_docs(src) or {
		return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${verb}: ${err.msg()}')
	}
	if subs.len == 0 {
		return none
	}
	if dst.enc_key_id == '' {
		return mk_err('cx-err:CXER1144', 'E_STORE_SUBJECT_UNSUPPORTED: ${verb} destination ${dst.url} is not encrypted at rest — ${subs.len} subject-keyed doc(s) could never be crypto-shredded there (erasure_compliance §2/§7)')
	}
	mut hashes := subs.keys()
	hashes.sort()
	for h in hashes {
		subj := subs[h]
		sek := store_subject_sek(mut dst, subj) or {
			return mk_err('cx-err:CXER1144', 'E_STORE_SUBJECT_UNSUPPORTED: ${verb} destination ${dst.url}: subject-key custody: ${err.msg()}')
		}
		root := src.obj_roots[h] or { continue }
		store_seal_override(mut dst, root.hex(), sek) or {
			return mk_err('cx-err:CXER1144', 'E_STORE_SUBJECT_UNSUPPORTED: ${verb} destination ${dst.url}: ${err.msg()}')
		}
	}
	return none
}

// store_subject_transfer_guard refuses wire-flavored object transfer of
// subject-keyed docs (push): subject custody does not ride the object wire —
// erasure/custody over the wire is the stream-4/9 joint surface (the ruled
// named landing); clone/migrate carry custody locally.
fn store_subject_transfer_guard(src &MemStore, verb string) ?cx.Node {
	subs := store_subject_docs(src) or {
		return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${verb}: ${err.msg()}')
	}
	if subs.len == 0 {
		return none
	}
	return mk_err('cx-err:CXER1144', 'E_STORE_SUBJECT_UNSUPPORTED: ${verb} source ${src.url} holds ${subs.len} subject-keyed doc(s) — subject custody does not ride ${verb} (erasure over the wire is the stream-4/9 joint surface); use clone or migrate')
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
	// Stream 20: subject custody + erasure attribution both ride the copy —
	// destination SEK routing registers BEFORE the transfer (the objects seal
	// under destroyable keys as they land), the erased-map carries after it.
	if e := store_subject_custody_carry(src, mut dst, 'clone') {
		return e
	}
	objects, refs := pc_transfer(args[0], src, mut dst) or {
		return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: clone: ${err.msg()}')
	}
	store_erased_carry(src, mut dst) or {
		return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: clone: erased-map carriage: ${err.msg()}')
	}
	return pc_result_heads('clone', objects, refs, dst)
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
	if e := store_subject_transfer_guard(local, 'push') {
		return e
	}
	objects, refs := pc_transfer(args[0], local, mut remote) or {
		return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: push: ${err.msg()}')
	}
	return pc_result_heads('push', objects, refs, remote)
}

// store_pull — `[$store:pull $local $remote $opts?]` (stream 9, L176 — the
// pull/fetch split, #719 item 4): **pull = fetch + per-ref reconciliation.**
// The objects + doc-refs move exactly as fetch moves them; then the ALIAS
// plane reconciles from the source (fast-forwards apply; divergence yields
// the Ring-0 [conflict] values; opts.resolutions re-enter as the input
// table — store_reconcile.v). The ENFORCING surface: raises CXER5053
// carrying every [conflict] iff the composed report says ok=false (the
// agreement law); `pull-report` is the never-raising twin. A REMOTE source
// refuses loud (the ref plane needs the peer lineage — the stream-9 wire
// lane; `fetch` is the remote-safe verb meanwhile): pull never silently
// degrades to fetch again.
fn store_pull(args []cx.Node) ?cx.Node {
	report := store_pull_impl(args)?
	if report is cx.Element && report.name == 'err' {
		return report
	}
	mut ok := true
	mut conflict_children := []cx.Node{}
	mut nconf := '0'
	if report is cx.Element {
		ok = report.attr('ok') != 'false'
		for it in report.items {
			if it is cx.Element && it.name == 'reconcile-report' {
				nconf = it.attr('conflicts')
				for c in it.items {
					if c is cx.Element && c.name == 'conflict' {
						conflict_children << c
					}
				}
			}
		}
	}
	if ok {
		return report
	}
	return cx.Node(cx.Element{
		name:  'err'
		attrs: [
			cx.Attribute{
				name:  'code'
				value: cx.ScalarValue(sync_err_diverged)
			},
			cx.Attribute{
				name:  'message'
				value: cx.ScalarValue('E_SYNC_DIVERGED: pull reconciliation found ${nconf} diverged ref(s) — objects + fast-forwards landed (partial success reported); each [conflict] child carries base/ours/theirs with patchable diffs; resolve via opts.resolutions or use pull-report to keep conflicts as data (distributed_store §4/§5)')
			},
		]
		items: conflict_children
	})
}

// store_pull_report — the never-raising twin (agreement law: pull raises ⟺
// this report says ok=false).
fn store_pull_report(args []cx.Node) ?cx.Node {
	return store_pull_impl(args)
}

fn store_pull_impl(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err('cx-err:CXER0108', 'E_ARG: pull expects ($local $remote $opts?)')
	}
	fres := store_pull_fetch(args, 'pull')?
	if fres is cx.Element && fres.name == 'err' {
		return fres
	}
	rres := store_reconcile_impl(args, false)?
	if rres is cx.Element && rres.name == 'err' {
		return rres
	}
	mut objects := ''
	mut refs := ''
	mut items := []cx.Node{}
	if fres is cx.Element {
		objects = fres.attr('objects')
		refs = fres.attr('refs')
	}
	mut ok := 'true'
	if rres is cx.Element {
		ok = rres.attr('ok')
	}
	// the post-reconcile head-set (heads moved again if refs advanced).
	mut local2, _, lok2 := store_get_open(args[0])
	if lok2 {
		if h := pc_heads(local2) {
			items << h
		}
	}
	items << rres
	return cx.Node(cx.Element{
		name:  'pull-result'
		attrs: [
			cx.Attribute{
				name:  'objects'
				value: cx.ScalarValue(objects.i64())
			},
			cx.Attribute{
				name:  'refs'
				value: cx.ScalarValue(refs.i64())
			},
			cx.Attribute{
				name:  'ok'
				value: cx.ScalarValue(ok == 'true')
			},
		]
		items: items
	})
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
	if verb == 'pull' {
		// store_pull_impl composes the full pull report; the transfer half
		// returns bare counts for it to lift.
		return pc_result(verb, objects, refs)
	}
	return pc_result_heads(verb, objects, refs, local)
}

// ── introspection + maintenance: status / log / gc / prune ───────────────────────

// store_status — `[$store:status $store]`: a snapshot of the store's heads + object
// economy. For a local object-graph store it reports docs (heads), distinct objects,
// the logical/distinct dedup ratio, and the unflushed-ref count; for a remote/byte-source
// store it reports the head count from the catalog (object economy lives server-side).
fn store_status(args []cx.Node) ?cx.Node {
	if args.len < 1 {
		return mk_err('cx-err:CXER0108', 'E_ARG: status expects ($store $opts?)')
	}
	mut ms, errn, ok := store_get_open(args[0])
	if !ok {
		return errn
	}
	// stream 9 (L177, #719 item 1): opts.peer engages the ahead/behind
	// classification — the dry reconcile examination against a peer handle;
	// per-stream states ride a [peer …] head-set block on the report.
	mut peer_block := ?cx.Node(none)
	if args.len > 1 {
		opts0 := args[1]
		if opts0 is cx.Element {
			for it in opts0.items {
				if it is cx.Element && it.name == 'peer' && it.items.len > 0 {
					ph := it.items[0]
					mut ms_peer, perr, pok := store_get_open(ph)
					if !pok {
						return perr
					}
					if store_remote_active(ms) {
						return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: status peer comparison runs on a LOCAL store (ask the daemon for its own)')
					}
					view := store_peer_view(ph, mut ms_peer) or {
						return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: the status peer must be a local store or a service-tier (cx-store://) remote')
					}
					peer_block = store_status_peer(ms, &view, ms_peer.url)
				}
			}
		}
	}
	// #248: on a service-tier handle, status is the SERVER's admin-plane op
	// (CSRP §3.10) — the daemon reports its authoritative object economy
	// (admin RBAC enforced server-side). Byte-source remotes keep the local
	// catalog-derived summary below.
	if store_remote_active(ms) && service_scheme(ms.remote.scheme) {
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
		// RULED: UOM-1 — `remote` states a FACT (ops route over a byte-source
		// transport), never a model. A LOCAL document-model store (the `file`
		// flat index) lands in this arm too and is not remote; reporting
		// remote=true for it was a substrate-consistency defect (the owner's
		// 2026-08-20 "across all substrates the same" ruling).
		if ms.remote != unsafe { nil } {
			attrs << cx.Attribute{
				name:  'remote'
				value: cx.ScalarValue(true)
			}
		}
	}
	// #719 item 1 (distributed_store L177, local half): the per-stream
	// HEAD-SET — 'docs' plus one 'aliases/<name>' stream per ref, each at
	// its dense E3 position; ref streams carry the current head hash. This
	// is the coordinate the L177 ahead/behind comparison consumes; the
	// comparison itself needs a peer and lands with stream 9 (#681).
	mut items := []cx.Node{}
	if store_objgraph_active(ms) {
		mut skeys := ms.adv_pos.keys()
		skeys.sort()
		mut hchildren := []cx.Node{}
		for k in skeys {
			mut hattrs := [
				cx.Attribute{
					name:  'name'
					value: cx.ScalarValue(k)
				},
				cx.Attribute{
					name:  'pos'
					value: cx.ScalarValue(ms.adv_pos[k] or { i64(0) })
				},
			]
			if k.starts_with('aliases/') {
				target := ms.aliases[k.all_after('aliases/')] or { '' }
				if target != '' {
					hattrs << cx.Attribute{
						name:  'hash'
						value: cx.ScalarValue(target)
					}
				}
			}
			hchildren << cx.Element{
				name:  'stream'
				attrs: hattrs
			}
		}
		items << cx.Element{
			name:  'heads'
			items: hchildren
		}
	}
	if pb := peer_block {
		items << pb
	}
	return cx.Element{
		name:  'status'
		attrs: attrs
		items: items
	}
}

// store_log — `[$store:log $store]`: the linear ref-log in PER-REF ADVANCE
// ORDER (#708 fixed at I5 stream-4 W4 — the E3 lineage, one log shared with
// the wire feed; semantic_value_model §4). One row per recorded act, in
// arrival order: epoch = the linear log index, pos = the dense per-stream E3
// position ("v17" = the 17th advance of that ref). Doc inserts/retracts ride
// the `docs` plane; named wire refs and aliases are per-name streams —
// branch-force advances APPEAR, and re-pointing a ref at its current target
// is an advance. History before the current boot is compacted to the seed
// snapshot (retention v1 = process lifetime; the feed's boot token marks the
// boundary). Returns a sequence of
// [ref epoch=N plane="…" kind=insert|retract|erase|advance key="…" pos=N root="…"? target="…"?].
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
	for i, a in ms.advances {
		key := if a.plane == 'docs' { a.hash } else { a.name }
		mut attrs := [
			cx.Attribute{
				name:  'epoch'
				value: cx.ScalarValue(i64(i))
			},
			cx.Attribute{
				name:  'plane'
				value: cx.ScalarValue(a.plane)
			},
			cx.Attribute{
				name:  'kind'
				value: cx.ScalarValue(a.kind)
			},
			cx.Attribute{
				name:  'key'
				value: cx.ScalarValue(key)
			},
			cx.Attribute{
				name:  'pos'
				value: cx.ScalarValue(a.pos)
			},
		]
		if a.root.len > 0 {
			attrs << cx.Attribute{
				name:  'root'
				value: cx.ScalarValue(a.root.hex())
			}
		}
		if a.plane == 'aliases' && a.hash != '' {
			attrs << cx.Attribute{
				name:  'target'
				value: cx.ScalarValue(a.hash)
			}
		}
		items << cx.Element{
			name:  'ref'
			attrs: attrs
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
	if store_remote_active(ms) && service_scheme(ms.remote.scheme) {
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
	if serr := store_addr_shape_err(ka) {
		return serr
	}
	if serr := store_addr_shape_err(kb) {
		return serr
	}
	if ka in ms.blob_kind || kb in ms.blob_kind {
		// F1': opaque documents carry no structure to diff — one typed refusal.
		return mk_err('cx-err:CXER0100',
			'E_OPERAND_KIND: diff applies to structured documents only (an operand is an opaque document; compare blob keys with $eq)')
	}
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
	// Stream 7 F5 (L122 :linearizable-ref): branch-force advances a ref
	// UNCONDITIONALLY — on a declaring handle that is exactly the blind
	// overwrite the token forbids. Plain branch stays available (its
	// fast-forward guard IS the CAS discipline).
	if force && store_floor_declared(ms, 'linearizable-ref') {
		return cst_refusal('write', cst_atom('linearizable-ref'), ':linearizable-ref',
			'store:branch-force', store_guarantee_advert(ms), 'branch-force advances unconditionally — this handle declared CAS-only ref advancement; use branch (fast-forward guarded)',
			'')
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
	store_alias_set_local(mut ms, name, target)
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

// ── verify (#637): the whole-graph integrity pass, on demand ──────────────
//
// Every live doc reconstructs from the object graph, or the op fails loud.
// This is the check that used to run inline on EVERY open of an object-graph
// store — O(live set) work that made boot scale with lifetime volume. With
// demand paging (#637) it moves here: a corrupt object still refuses loudly
// at first touch (the composite getter self-verifies each read), and the
// exhaustive sweep is available on demand or from a background task instead
// of being paid on every boot.
//
//   [$store:verify $s]  ⇒ [verification valid=true docs=N objects=M]
//                       ⇒ [err code=cx-err:CXER1120 …] on corruption
//
// The pass reports the FIRST failure with the offending store-hash, exactly
// as the load-time check did — same code, same message shape (#129-C).
fn store_verify(args []cx.Node) ?cx.Node {
	if args.len < 1 {
		return mk_err('cx-err:CXER0108', 'E_ARG: verify expects ($store)')
	}
	mut ms, errn, ok := store_get_open(args[0])
	if !ok {
		return errn
	}
	if !store_objgraph_active(ms) {
		// the flat document model keeps its docs whole; there is no object
		// graph to walk, so verification is the doc-hash check `get-doc`
		// already performs per read. Refuse honestly rather than answering a
		// hollow valid=true.
		return mk_err('cx-err:CXER1709',
			'E_CSRP_OPERATION_UNSUPPORTED: verify walks an object graph — this store is the flat document model (its per-read hash check IS its verification)')
	}
	getter := store_graph_getter(ms)
	mut docs := 0
	mut redacted := 0
	for h, root in ms.obj_roots {
		if h.starts_with('code:') {
			getter(root) or {
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${ms.root}: code object missing for ${h}')
			}
			docs++
			continue
		}
		if store_whole_doc_root(h, root) {
			// Stream 20: whole-doc object (subject-bearing) — self-verifying
			// via the getter; presence is the check. A FAILED open reconciles
			// from evidence exactly like a read (M29/W5): covered by a
			// journaled erase record → a lawfully-shredded doc is a FINDING
			// counted visibly (redacted=), never a fault; uncovered → the
			// typed unavailable/integrity error, fail-closed.
			getter(root) or {
				msg := store_shredded_read_err(mut ms, h, root)
				if msg.contains('E_STORE_SHREDDED') {
					redacted++
					continue
				}
				return store_read_err_node(msg)
			}
			docs++
			continue
		}
		doc := cxstore.load_document_from(getter, root) or {
			return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${ms.root}: doc ${h} failed to reconstruct from the object graph (corrupt or missing object): ${err.msg()}')
		}
		if doc.elements.len == 0 {
			return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${ms.root}: doc ${h} reconstructed to an empty document (corruption)')
		}
		docs++
	}
	mut vattrs := [
		cx.Attribute{
			name:  'valid'
			value: cx.ScalarValue(true)
		},
		cx.Attribute{
			name:  'docs'
			value: cx.ScalarValue(i64(docs))
		},
		cx.Attribute{
			name:  'objects'
			value: cx.ScalarValue(i64(ms.obj_sink.objects.len + ms.obj_cache.len))
		},
	]
	if redacted > 0 {
		// The §6 generalized visible-count rule: a surface that omits data
		// for erasure reasons reports the omission count at the point of
		// omission (present when non-zero — the L119 posture).
		vattrs << cx.Attribute{
			name:  'redacted'
			value: cx.ScalarValue(i64(redacted))
		}
	}
	return cx.Element{
		name:  'verification'
		attrs: vattrs
	}
}
