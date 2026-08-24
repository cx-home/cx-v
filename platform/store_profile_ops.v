module platform
import code {
	http_attr,
	http_body_octets,
	is_err_value,
	render_canonical,
}

// store_profile_ops.v — the gRPC adapter's data-op core (I5 stream 4 W6,
// #651/#516: the profile pipeline).
//
// At W6 the gRPC adapter re-bases onto the profile pipeline: grpc_synth_req_m
// marks its synthesized requests pipeline="profile" and svc_dispatch_data_op
// routes those here — INTERNAL ops against the resolved mount — instead of
// through store_csrp_route. Everything upstream (lifecycle, capabilities,
// mounts/config-reload, authN/Z, the DoS limiter, metrics) stays the ONE shared
// svc pipeline, untouched.
//
// This file deliberately DUPLICATES the cxd-text lane of store_csrp_route (the
// same store_stdlib_builtin_inner calls, the same validation order, the same
// response bodies, the same §4 status↔17xx code remapping): at W7 the CSRP
// router files (store_csrp.v / store_csrp_binary_route.v) are DELETED and this
// file remains as the gRPC data-op core. Until W7 the CSRP HTTP listener (the
// parity listener) keeps store_csrp_route unchanged — the store_grpc_*_test
// parity suites pin that both cores answer byte-identically.
//
// Only the TEXT (cxd) lane is reproduced: a gRPC synth request carries no
// Content-Type/Accept, so it never opted into the csrp_wants_binary branch.

import cx
import encoding.hex

// svc_profile_route is the path-deriving entry: it splits the op off the
// synthesized request's `/cx-store/v1/[<store>/]<op>` path and runs the core.
// The single-argument form the loopback-hermetic tests drive (and any caller
// that has the request but not a pre-split op).
pub fn svc_profile_route(req cx.Element, local cx.Node) cx.Node {
	path := http_attr(req, 'path') or { '' }
	suffix := if path.starts_with(svc_http_base) { path[svc_http_base.len..] } else { path }
	op := if idx := suffix.last_index('/') { suffix[idx + 1..] } else { suffix }
	return svc_profile_data_op(req, local, op)
}

// svc_profile_data_op handles one data-plane op for a pipeline="profile"
// request (the gRPC adapter). `req` is the synthesized request element (same
// shape the CSRP route read: query-params + body octets); `local` is the
// mount svc_dispatch_data_op resolved; `op` is the already-split op name.
pub fn svc_profile_data_op(req cx.Element, local cx.Node, op string) cx.Node {
	// Daemon concurrency: the worker pool shares the mounted store handle, so store
	// ops MUST serialize — the same BLOCKING owner-tracked reentrant lock discipline
	// as store_csrp_route (#628: the route body's funnels — store_persist / put /
	// append — re-enter the same mutex on the same thread; a raw @lock() here would
	// self-deadlock against them). Without this a concurrent put/get races the
	// store's obj_roots/obj_sink maps and a just-written doc reads back absent.
	mut guard := store_for_guard(local) or { unsafe { nil } }
	if guard != unsafe { nil } {
		store_lock_enter(mut guard)
	}
	defer {
		if guard != unsafe { nil } {
			store_lock_exit(mut guard)
		}
	}
	method := http_attr(req, 'method') or { 'GET' }
	// #248 admin plane (§3.10/§3.11): status (store stats) + gc (compaction
	// trigger) — the daemon has already enforced admin RBAC + tenant before
	// routing here. Responses are the exact porcelain elements, rendered
	// canonical as text/cx bodies.
	if method == 'GET' && op == 'status' {
		r := store_stdlib_builtin_inner('store-status', [local]) or {
			return sw_resp(500, '[err code="cx-err:CXER1707" message="E_CSRP_SERVER_INTERNAL: status failed"]')
		}
		if is_err_value(r) {
			return sw_admin_op_err(r)
		}
		return sw_resp(200, render_canonical(r))
	}
	if method == 'POST' && op == 'gc' {
		r := store_stdlib_builtin_inner('store-gc', [local]) or {
			return sw_resp(500, '[err code="cx-err:CXER1707" message="E_CSRP_SERVER_INTERNAL: gc failed"]')
		}
		if is_err_value(r) {
			return sw_admin_op_err(r)
		}
		return sw_resp(200, render_canonical(r))
	}
	if method == 'POST' && op == 'put' {
		body := http_body_octets(req).bytestr()
		// #190: surface the real content-dedup signal. Content-addressing means the
		// store-key is deterministic from the body, so "already present" == the key
		// exists BEFORE this put. This fn holds the op-lock (above), so the
		// exists-then-put is atomic — no window where a concurrent put flips it.
		canonical := cx.cx_text_canonical(body) or { '' }
		mut existed := false
		if canonical != '' {
			if h := cx.cx_text_hash(canonical) {
				ex := store_stdlib_builtin_inner('store-exists', [local, store_str(h)]) or {
					store_bool(false)
				}
				existed = sw_scalar(ex) == 'true'
			}
		}
		r := store_stdlib_builtin_inner('store-put-doc-text', [local, store_str(body)]) or {
			return sw_resp(400, '[err code="cx-err:CXER1701"]')
		}
		if is_err_value(r) {
			// classify: an auth/rate failure from a remote-backed mount is not a 400.
			ecode := svc_err_code(r)
			if ecode == 'cx-err:CXER1131' {
				return sw_resp(401, '[err code="cx-err:CXER1702" message="E_CSRP_AUTH_REQUIRED: ${sw_msg_esc(svc_err_msg(r))}"]')
			}
			return sw_resp(400, '[err code="cx-err:CXER1701" message="E_CSRP_REQUEST_MALFORMED: ${sw_msg_esc(svc_err_msg(r))}"]')
		}
		stored := if existed { 'false' } else { 'true' }
		return sw_resp(200, '[put-result hash="${sw_scalar(r)}" stored="${stored}"]')
	}
	if method == 'POST' && op == 'get' {
		hash := sw_query(req, 'hash')
		r := store_stdlib_builtin_inner('store-get-doc-text', [local, store_str(hash)]) or {
			return sw_resp(500, '[err code="cx-err:CXER1707"]')
		}
		// get-doc-text returns the canonical text (ScalarNode) or the absence
		// channel (empty sequence). Absence → 404 / CXER1721.
		if r is cx.ScalarNode {
			return sw_resp(200, sw_scalar(r))
		}
		return sw_resp(404, '[err code="cx-err:CXER1721"]')
	}
	// S6.5 (G13 edge parity): the F1' OPAQUE pair. put-blob's body is the raw
	// bytes VERBATIM (no canonicalization — identity = hash of the bytes as
	// given); get-blob's absence is the blob surface's CXER1121 contract,
	// remapped to this lane's 404/1721 exactly like `get` (the gRPC client
	// surfaces CXER1121 — cross-transport error identity, cxstore-grpc.md §3).
	if method == 'POST' && op == 'put-blob' {
		raw := http_body_octets(req).bytestr()
		r := store_stdlib_builtin_inner('store-put-blob', [local, store_str(raw)]) or {
			return sw_resp(400, '[err code="cx-err:CXER1701"]')
		}
		if is_err_value(r) {
			ecode := svc_err_code(r)
			if ecode == 'cx-err:CXER1131' {
				return sw_resp(401, '[err code="cx-err:CXER1702" message="E_CSRP_AUTH_REQUIRED: ${sw_msg_esc(svc_err_msg(r))}"]')
			}
			return sw_resp(400, '[err code="cx-err:CXER1701" message="E_CSRP_REQUEST_MALFORMED: ${sw_msg_esc(svc_err_msg(r))}"]')
		}
		return sw_resp(200, '[put-blob-result key="${sw_scalar(r)}" stored="true"]')
	}
	if method == 'POST' && op == 'get-blob' {
		key := sw_query(req, 'hash')
		r := store_stdlib_builtin_inner('store-get-blob', [local, store_str(key)]) or {
			return sw_resp(500, '[err code="cx-err:CXER1707"]')
		}
		if is_err_value(r) {
			if svc_err_code(r) == 'cx-err:CXER1121' {
				return sw_resp(404, '[err code="cx-err:CXER1721"]')
			}
			return sw_resp(400, '[err code="cx-err:CXER1701" message="E_CSRP_REQUEST_MALFORMED: ${sw_msg_esc(svc_err_msg(r))}"]')
		}
		return sw_resp(200, sw_scalar(r))
	}
	if method == 'POST' && op == 'delete' {
		hash := sw_query(req, 'hash')
		r := store_stdlib_builtin_inner('store-delete-doc', [local, store_str(hash)]) or {
			return sw_resp(500, '[err code="cx-err:CXER1707"]')
		}
		deleted := sw_scalar(r)
		return sw_resp(200, '[delete-result hash="${hash}" deleted="${deleted}"]')
	}
	if method == 'POST' && op == 'list' {
		r := store_stdlib_builtin_inner('store-list-docs', [local]) or {
			return sw_resp(500, '[err code="cx-err:CXER1707"]')
		}
		// Wire form is [list-result [hashes [hash "h1"] [hash "h2"] …]] — each hash
		// is its own element. (Avoid [sequence …]: it is a reserved collection
		// constructor that the client's parser would fold into a sequence value,
		// not an element the navigation can walk.)
		mut sb := '[list-result [hashes'
		if r is cx.Element {
			for it in r.items {
				h := sw_scalar(it)
				if h != '' {
					sb += ' [hash "${h}"]'
				}
			}
		}
		sb += ']]'
		return sw_resp(200, sb)
	}
	if method == 'POST' && op == 'query' {
		// L99: a `?comp=` query-param carries a QUOTED planar comprehension's
		// source text — server-side membership + layers; rows ride [item …]
		// envelopes (lossless for scalar rows).
		comp := sw_query(req, 'comp')
		if comp != '' {
			items, errn, ok := store_server_query_planar_items(local, comp)
			if !ok {
				// the wire error body shape other ops use (quoted attrs — the
				// gRPC edge's code extractor keys on them; error identity).
				ecode := if errn is cx.Element { sw_attr(errn, 'code') } else { '' }
				emsg := if errn is cx.Element { sw_attr(errn, 'message') } else { '' }
				return sw_resp(400, '[err code="${ecode}" message="${sw_msg_esc(emsg)}"]')
			}
			mut sb := '[query-result'
			for it in items {
				sb += ' ' + it
			}
			sb += ']'
			return sw_resp(200, sb)
		}
		// CXPath pushdown: run the query against the local mount server-side and
		// serialize the result. The CXPath is a query-param (`?path=…`). Wire form
		// is [query-result [result doc= source= MATCH] …] — the L97 flat-relation
		// tuples rendered VERBATIM (raw `(…)` sequences are deliberately NOT
		// emitted; the client's parser would fold them into a value rather than a
		// walkable element).
		cxpath := sw_query(req, 'path')
		r := store_stdlib_builtin_inner('store-query', [local, store_str(cxpath)]) or {
			return sw_resp(500, '[err code="cx-err:CXER1707"]')
		}
		mut sb := '[query-result'
		if r is cx.Element { // the store_seq marker wrapper over [result …] items
			for result in r.items {
				if result is cx.Element && result.name == 'result' {
					sb += ' ' + render_canonical(result)
				}
			}
		}
		sb += ']'
		return sw_resp(200, sb)
	}
	if method == 'POST' && op == 'iter' {
		// Server-side iteration: enumerate every doc in the local mount and
		// serialize each as its own rendered element. Wire form is
		// [iter-result [doc hash="H" <rendered-doc>] …] — each doc is a nested
		// element carrying its content-address, mirroring list/query's
		// nested-element form.
		r := store_stdlib_builtin_inner('store-iter-docs', [local]) or {
			return sw_resp(500, '[err code="cx-err:CXER1707"]')
		}
		mut sb := '[iter-result'
		if r is cx.Element { // store_seq wrapper over [entry hash="H" <doc>] items
			for entry in r.items {
				if entry is cx.Element && entry.name == 'entry' {
					mut hash := ''
					for a in entry.attrs {
						if a.name == 'hash' {
							hash = cx.scalar_value_str_public(a.value)
						}
					}
					sb += ' [doc hash="${hash}"'
					for inner in entry.items {
						sb += ' ' + render_canonical(inner)
					}
					sb += ']'
				}
			}
		}
		sb += ']'
		return sw_resp(200, sb)
	}
	if method == 'POST' && op == 'modify' {
		// Structural modification pushdown: the target doc hash is a query-param
		// (`?hash=…`); the modify action element is the request body (cxd-text).
		// store-modify-doc applies the action server-side, content-addresses the
		// result, and stores it. Wire form is
		// [modify-result old-hash="H" new-hash="NH" stored="true"].
		hash := sw_query(req, 'hash')
		action_text := http_body_octets(req).bytestr()
		action := cx.parse(action_text) or {
			return sw_resp(400, '[err code="cx-err:CXER1701"]')
		}
		mut action_node := cx.Node(cx.Element{
			name: ''
		})
		if action.elements.len > 0 {
			action_node = action.elements[0]
		} else {
			return sw_resp(400, '[err code="cx-err:CXER1701"]')
		}
		r := store_stdlib_builtin_inner('store-modify-doc', [local, store_str(hash), action_node]) or {
			return sw_resp(400, '[err code="cx-err:CXER1701"]')
		}
		if is_err_value(r) {
			// NOT_FOUND (unknown source hash) vs a malformed action — distinguish so
			// the client maps to the right store error rather than a blanket 500. The
			// store layer raises CXER1121 (E_STORE_NOT_FOUND); on the wire that is
			// the not-found code CXER1721 (same convention as the get op), so a gRPC
			// client maps it to NOT_FOUND(5), not UNKNOWN.
			ecode := sw_err_code(r)
			if ecode == 'cx-err:CXER1121' {
				return sw_resp(404, '[err code="cx-err:CXER1721"]')
			}
			return sw_resp(400, '[err code="${ecode}"]')
		}
		new_hash := sw_scalar(r)
		return sw_resp(200, '[modify-result old-hash="${hash}" new-hash="${new_hash}" stored="true"]')
	}
	// ── Object-level wire (#129 spec §3) ────────────────────────────────────────
	// Content-addressed OBJECTS (have/get/put) + ref resolution — object bytes
	// travel hex-encoded (binary-safe on the cxd-text body). The handle lock taken
	// at the top of this fn serializes these against the doc verbs. `guard` is the
	// resolved store.
	if method == 'POST' && op in ['objects-have', 'objects-get', 'objects-put'] {
		if guard == unsafe { nil } {
			return sw_resp(500, '[err code="cx-err:CXER1707"]')
		}
		body := http_body_octets(req).bytestr()
		doc := cx.parse(body) or { return sw_resp(400, '[err code="cx-err:CXER1701"]') }
		if doc.elements.len == 0 {
			return sw_resp(400, '[err code="cx-err:CXER1701"]')
		}
		top := doc.elements[0]
		getter := store_graph_getter(guard)
		if top is cx.Element {
			if op == 'objects-have' {
				// reply only the hashes the daemon is MISSING — the dedup-on-wire primitive.
				mut sb := '[have-result'
				for it in top.items {
					if it is cx.Element && it.name == 'o' {
						hx := sw_attr(it, 'h')
						hb := hex.decode(hx) or { continue }
						if getter(hb) == none {
							sb += ' [o h="${hx}"]'
						}
					}
				}
				return sw_resp(200, sb + ']')
			}
			if op == 'objects-get' {
				// fetch by hash; each object self-verifies via the composite getter.
				mut sb := '[get-result'
				for it in top.items {
					if it is cx.Element && it.name == 'o' {
						hx := sw_attr(it, 'h')
						hb := hex.decode(hx) or { continue }
						payload := getter(hb) or { continue }
						sb += ' [o h="${hx}" bytes="${payload.hex()}"]'
					}
				}
				return sw_resp(200, sb + ']')
			}
			if op == 'objects-put' {
				// store each uploaded object through the seam (content-addressed; a
				// duplicate is a no-op), then persist so it survives a restart.
				mut n := 0
				for it in top.items {
					if it is cx.Element && it.name == 'o' {
						pb := hex.decode(sw_attr(it, 'bytes')) or { continue }
						guard.obj_sink.put(pb)
						n++
					}
				}
				store_persist(mut guard) or {
					return sw_resp(500, '[err code="cx-err:CXER1707" message="E_CSRP_SERVER_INTERNAL: persist failed: ${sw_msg_esc(err.msg())}"]')
				}
				return sw_resp(200, '[put-result stored="${n}"]')
			}
		}
		return sw_resp(404, '[err code="cx-err:CXER1709" message="E_CSRP_OPERATION_UNSUPPORTED: unknown object-wire operation"]')
	}
	if method == 'POST' && op == 'refs' {
		// resolve store-key → doc-root object hash (the ref layer, spec §3).
		if guard == unsafe { nil } {
			return sw_resp(500, '[err code="cx-err:CXER1707"]')
		}
		body := http_body_octets(req).bytestr()
		doc := cx.parse(body) or { return sw_resp(400, '[err code="cx-err:CXER1701"]') }
		mut sb := '[refs-result'
		if doc.elements.len > 0 {
			top := doc.elements[0]
			if top is cx.Element {
				for it in top.items {
					if it is cx.Element && it.name == 'k' {
						k := sw_attr(it, 'key')
						if root := guard.obj_roots[k] {
							sb += ' [r key="${k}" root="${root.hex()}"]'
						}
					}
				}
			}
		}
		return sw_resp(200, sb + ']')
	}
	if method == 'POST' && op == 'refs-set' {
		// advance store-key → root (after the client has put the missing objects).
		if guard == unsafe { nil } {
			return sw_resp(500, '[err code="cx-err:CXER1707"]')
		}
		body := http_body_octets(req).bytestr()
		doc := cx.parse(body) or { return sw_resp(400, '[err code="cx-err:CXER1701"]') }
		mut n := 0
		if doc.elements.len > 0 {
			top := doc.elements[0]
			if top is cx.Element {
				// #218 CAS: an optional expect="<hex>" attr per record makes the
				// advance conditional — the record applies only if the ref's current
				// root equals `expect` (expect="" ⇒ the ref must not exist yet).
				// VALIDATE-THEN-APPLY: all conditions are checked before any record
				// is applied, so a multi-ref set is all-or-nothing; a mismatch is
				// 409 CXER1114 (one ref-conflict code since I1 row 15 / M21
				// E_STORE_REF_CONFLICT). Unconditional records (no expect attr)
				// keep last-writer-wins.
				for it in top.items {
					if it is cx.Element && it.name == 'r' {
						k := sw_attr(it, 'key')
						if k == '' {
							continue
						}
						if !sw_has_attr(it, 'expect') {
							continue
						}
						expect := sw_attr(it, 'expect')
						mut cur := ''
						if c := guard.obj_roots[k] {
							cur = c.hex()
						}
						if cur != expect {
							return sw_resp(409, '[err code="cx-err:CXER1114" message="E_STORE_REF_CONFLICT: ref ${k} is at ${sw_msg_esc(cur)}, expected ${sw_msg_esc(expect)}"]')
						}
					}
				}
				for it in top.items {
					if it is cx.Element && it.name == 'r' {
						k := sw_attr(it, 'key')
						rb := hex.decode(sw_attr(it, 'root')) or { continue }
						if k == '' {
							continue
						}
						store_ref_advance_local(mut guard, k, rb) // the E3 lineage funnel (§5.1)
						n++
					}
				}
			}
		}
		store_persist(mut guard) or {
			return sw_resp(500, '[err code="cx-err:CXER1707" message="E_CSRP_SERVER_INTERNAL: persist failed: ${sw_msg_esc(err.msg())}"]')
		}
		return sw_resp(200, '[refs-set-result set="${n}"]')
	}
	if method == 'POST' && op == 'aliases' {
		// #645: alias READS answer from the mount's authoritative alias table with
		// EXPLICIT per-name presence — an absent alias is a server-asserted
		// present="false", never a silent empty (the #264 miss-vs-absence concern).
		body := http_body_octets(req).bytestr()
		doc := cx.parse(body) or { return sw_resp(400, '[err code="cx-err:CXER1701"]') }
		if doc.elements.len == 0 {
			return sw_resp(400, '[err code="cx-err:CXER1701"]')
		}
		top := doc.elements[0]
		mut sb := '[aliases-result'
		if top is cx.Element {
			if sw_attr(top, 'all') == 'true' {
				lst := store_stdlib_builtin_inner('store-list-aliases', [local]) or {
					return sw_resp(500, '[err code="cx-err:CXER1707"]')
				}
				if lst is cx.Element {
					for it in lst.items {
						if it is cx.Element && it.name == 'alias' {
							sb += ' [a name="${sw_msg_esc(sw_attr(it, 'name'))}" hash="${sw_attr(it,
								'hash')}" present="true"]'
						}
					}
				}
			}
			for it in top.items {
				if it is cx.Element && it.name == 'k' {
					name := sw_attr(it, 'name')
					if name == '' {
						continue
					}
					r := store_stdlib_builtin_inner('store-get-alias', [local, store_str(name)]) or {
						return sw_resp(500, '[err code="cx-err:CXER1707"]')
					}
					if r is cx.ScalarNode {
						sb += ' [a name="${sw_msg_esc(name)}" hash="${sw_scalar(r)}" present="true"]'
					} else {
						sb += ' [a name="${sw_msg_esc(name)}" present="false"]'
					}
				}
			}
		}
		return sw_resp(200, sb + ']')
	}
	if method == 'POST' && op == 'aliases-set' {
		// #645: alias WRITES apply through the same local arm as an in-process
		// set-alias (target-presence CXER1121 → wire 404 CXER1721, read-only →
		// 400, alias record persisted). An optional per-record expect="<hash>"
		// is the refs-set CAS applied to the alias pointer layer (expect="" ⇒
		// must not exist): VALIDATE-THEN-APPLY under this fn's handle lock,
		// all-or-nothing, mismatch = 409 CXER1114 — the conflict-safe pointer
		// advance a remote journal head rides (#644).
		body := http_body_octets(req).bytestr()
		doc := cx.parse(body) or { return sw_resp(400, '[err code="cx-err:CXER1701"]') }
		if doc.elements.len == 0 {
			return sw_resp(400, '[err code="cx-err:CXER1701"]')
		}
		top := doc.elements[0]
		mut n := 0
		if top is cx.Element {
			for it in top.items {
				if it is cx.Element && it.name == 'a' {
					name := sw_attr(it, 'name')
					if name == '' || !sw_has_attr(it, 'expect') {
						continue
					}
					expect := sw_attr(it, 'expect')
					mut cur := ''
					r := store_stdlib_builtin_inner('store-get-alias', [local, store_str(name)]) or {
						return sw_resp(500, '[err code="cx-err:CXER1707"]')
					}
					if r is cx.ScalarNode {
						cur = sw_scalar(r)
					}
					if cur != expect {
						return sw_resp(409, '[err code="cx-err:CXER1114" message="E_STORE_REF_CONFLICT: alias ${sw_msg_esc(name)} is at ${sw_msg_esc(cur)}, expected ${sw_msg_esc(expect)}"]')
					}
				}
			}
			for it in top.items {
				if it is cx.Element && it.name == 'a' {
					name := sw_attr(it, 'name')
					hash := sw_attr(it, 'hash')
					if name == '' || hash == '' {
						continue
					}
					r := store_stdlib_builtin_inner('store-set-alias', [local, store_str(name),
						store_str(hash)]) or {
						return sw_resp(500, '[err code="cx-err:CXER1707"]')
					}
					if is_err_value(r) {
						ecode := sw_err_code(r)
						if ecode == 'cx-err:CXER1121' {
							return sw_resp(404, '[err code="cx-err:CXER1721" message="E_CSRP_NOT_FOUND: alias target ${hash}"]')
						}
						// read-only mount and other write-shape failures map to 400
						// (same convention as the admin/write ops).
						return sw_resp(400, '[err code="${ecode}"]')
					}
					n++
				}
			}
		}
		return sw_resp(200, '[aliases-set-result set="${n}"]')
	}
	// #196: an unrecognized operation is 404 CXER1709 E_CSRP_OPERATION_UNSUPPORTED
	// (a 404-class code, per the 1:1 status↔code invariant), NOT the 500-class
	// CXER1707.
	return sw_resp(404, '[err code="cx-err:CXER1709" message="E_CSRP_OPERATION_UNSUPPORTED: unknown operation `${sw_msg_esc(op)}`"]')
}
