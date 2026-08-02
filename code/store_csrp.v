@[has_globals]
module code

// CSRP reference-server per-request handler (#78, Phase 0.7 minimum).
//
// The CSRP server's accept loop must be a CX program ([?for accept-iter]), but
// a CX program cannot build the protocol's cxd-text responses cleanly (no join
// verb; attr/query nav yields wrapped nodes). So ONE request/response cycle is
// handled here in V — `[$store:csrp-handle $exchange $local-store]` — where the
// http exchange primitives, the store ops, and string building are all in
// reach. The CX reference server is then just:
//   [?for [in $ex [$http:accept-iter $srv]]] [yield [$store:csrp-handle $ex $local]]
//
// net-gated (it reads + writes the socket). Ops: capabilities / get / put /
// delete / list / query / iter / modify. Wire encoding here is the interim
// cxd-text + query-param form — NOT the approved cxstore-remote-protocol.md
// §2.1/§3 wire (cxbin bodies, [u32][u8 kind][payload] streaming frames, body-
// carried requests); the approved binary wire replaces this form (#182).

import cx
import encoding.hex

const csrp_base = '/cx-store/v1/'

// csrp_attr returns the value of attribute `name` on element `e`, or '' if absent.
fn csrp_attr(e cx.Element, name string) string {
	for a in e.attrs {
		if a.name == name {
			return cx.scalar_value_str_public(a.value)
		}
	}
	return ''
}

// csrp_has_attr reports whether attribute `name` is present on `e` (present-but-
// empty is distinct from absent — the refs-set CAS uses expect="" for
// "must not exist").
fn csrp_has_attr(e cx.Element, name string) bool {
	for a in e.attrs {
		if a.name == name {
			return true
		}
	}
	return false
}

// csrp_msg_esc makes an error message safe to embed in a double-quoted cxd
// response attribute.
fn csrp_msg_esc(s string) string {
	return s.replace('"', "'")
}

fn csrp_scalar(n cx.Node) string {
	if n is cx.ScalarNode {
		return cx.scalar_value_str_public(n.value)
	}
	// A quoted string ("…") in cx data parses to a TextNode, not a ScalarNode —
	// the wire form [hash "…"] lands here on the client's list parse.
	if n is cx.TextNode {
		return n.value
	}
	return ''
}

// csrp_query reads a named query-param value off the parsed [request]. The
// http exchange-request models query params as [query-params [<name> "<value>"]]
// — the param name IS the element name, the value its sole scalar child.
fn csrp_query(req cx.Element, name string) string {
	qp := http_child(req, 'query-params') or { return '' }
	for it in qp.items {
		if it is cx.Element && it.name == name {
			for c in it.items {
				if c is cx.ScalarNode {
					return cx.scalar_value_str_public(c.value)
				}
			}
		}
	}
	return ''
}

// csrp_err_code reads the `code` attribute from an [err code="…"] value, so a
// route can map a store-layer fault onto the right HTTP status / wire code.
fn csrp_err_code(n cx.Node) string {
	if n is cx.Element && n.name == 'err' {
		for a in n.attrs {
			if a.name == 'code' {
				return cx.scalar_value_str_public(a.value)
			}
		}
	}
	return ''
}

// csrp_resp builds a server-form [response status=N [body "<text>"]] value.
fn csrp_resp(status int, body string) cx.Node {
	return cx.Element{
		name:  'response'
		attrs: [
			cx.Attribute{
				name:  'status'
				value: cx.ScalarValue(i64(status))
			},
		]
		items: [
			cx.Node(cx.Element{
				name:  'body'
				items: [
					cx.Node(cx.ScalarNode{
						value:     cx.ScalarValue(body)
						data_type: cx.ScalarType.string_type
					}),
				]
			}),
		]
	}
}

// csrp_resp_hdrs builds a response carrying explicit HTTP headers (the §2.2
// `[response [headers [header name= value=]] [body …]]` shape, emitted by
// http_respond_impl). Used for the protocol-required `Retry-After` on 429/503
// (#191) — csrp_resp alone has no header channel.
fn csrp_resp_hdrs(status int, body string, headers [][]string) cx.Node {
	mut hnodes := []cx.Node{}
	for h in headers {
		if h.len != 2 {
			continue
		}
		hnodes << cx.Node(cx.Element{
			name:  'header'
			attrs: [
				cx.Attribute{
					name:  'name'
					value: cx.ScalarValue(h[0])
				},
				cx.Attribute{
					name:  'value'
					value: cx.ScalarValue(h[1])
				},
			]
		})
	}
	return cx.Element{
		name:  'response'
		attrs: [
			cx.Attribute{
				name:  'status'
				value: cx.ScalarValue(i64(status))
			},
		]
		items: [
			cx.Node(cx.Element{
				name:  'headers'
				items: hnodes
			}),
			cx.Node(cx.Element{
				name:  'body'
				items: [
					cx.Node(cx.ScalarNode{
						value:     cx.ScalarValue(body)
						data_type: cx.ScalarType.string_type
					}),
				]
			}),
		]
	}
}

// csrp_resp_retry is a 429/503 with the protocol-required Retry-After header
// (#191, CSRP §4). `secs` is the advised backoff in seconds.
fn csrp_resp_retry(status int, body string, secs int) cx.Node {
	return csrp_resp_hdrs(status, body, [['Retry-After', secs.str()]])
}

// store_csrp_handle — `[$store:csrp-handle $exchange $local]`: read one request,
// route it to the local embedded store, write the cxd-text response.
fn store_csrp_handle(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err('cx-err:CXER0108', 'E_ARG: csrp-handle expects ($exchange, $local-store)')
	}
	// net effect (the verb-level cap_guard is bypassed by calling the impls
	// directly, so gate here): deny-by-default under no `net` grant.
	if d := cap_guard('net', 'store csrp-handle') {
		return d
	}
	ex := args[0]
	local := args[1]
	reqn := http_exchange_request_real([ex])
	if reqn is cx.Element {
		if reqn.name == 'err' {
			// #219: a request-framing rejection (conflicting Content-Length, missing
			// HTTP-version) → write a 400 CXER1701 response, not a silent close.
			return http_respond_impl([ex, csrp_resp(400, '[err code="cx-err:CXER1701" message="E_CSRP_REQUEST_MALFORMED: ${csrp_msg_esc(svc_err_msg(reqn))}"]')])
		}
		if reqn.name == 'request' {
			resp := store_csrp_route(reqn, local)
			return http_respond_impl([ex, resp])
		}
	}
	return mk_err('cx-err:CXER1707', 'E_CSRP_SERVER_INTERNAL: malformed request')
}

// normalize_csrp_op_path collapses the optional `<store-name>/` segment so the
// route table can match a single canonical `/cx-store/v1/<op>`. Returns the path
// unchanged when it is not under the CSRP base (so non-CSRP paths still 404).
fn normalize_csrp_op_path(raw string) string {
	_, op := svc_path_parts(raw) or { return raw }
	return csrp_base + op
}

fn store_csrp_route(req cx.Element, local cx.Node) cx.Node {
	// Daemon concurrency: the worker pool shares the mounted store handle, so store
	// ops MUST serialize. Take a BLOCKING lock on the handle's op_lock here. (The
	// eval-path guard in store_stdlib_builtin uses a NON-blocking try_lock to
	// fail-fast on `[par]` misuse of a single-owner handle; the daemon legitimately
	// has many workers on one handle and must SERIALIZE, not reject — and it calls
	// store_stdlib_builtin_inner, which bypasses that guard.) Without this a
	// concurrent put/get races the store's obj_roots/obj_sink maps and a
	// just-written doc reads back absent (spurious NOT_FOUND) — a latent daemon race
	// turned into a reliable failure by the subtree decompose/reconstruct window.
	// #628: through the owner-tracked reentrant helpers — the route body's
	// funnels (store_persist / put / append) re-enter the same mutex on the
	// same thread; a raw @lock() here self-deadlocked against them.
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
	// Accept both the sole-store form (/cx-store/v1/<op>) and the named form
	// (/cx-store/v1/<store-name>/<op>, sent by csrp_op_url when the cx-store://
	// URL carries a path). The embedded reference server is single-store, so the
	// store-name segment is accepted and ignored — it routes to its sole `local`
	// mount; the daemon does real store-name → mount routing before dispatch.
	// Normalising here keeps the reference server protocol-complete on its own.
	path := normalize_csrp_op_path(http_attr(req, 'path') or { '/' })

	if method == 'GET' && path == csrp_base + 'capabilities' {
		// The daemon splices the per-store/auth advert (svc_store_capabilities);
		// this embedded reference-server default now advertises BOTH encodings
		// (cxbin default + cxd) since the binary wire is live (#182).
		// §3.1 admin-ops: the embedded server routes status/gc (protocol-complete,
		// #248) but not mounts/config-reload (daemon concepts → 404 CXER1709).
		return csrp_resp(200, '[capabilities [csrp-version "1.0"] [server-impl "cx-stdlib-store-ref"] [backend-tier "embedded"] [encodings [supported "cxbin" "cxd"] [default "cxbin"]] [admin-ops "status" "gc"] [read true] [write true] [list true] [query true] [iter true] [modify true]]')
	}
	// #248 admin plane (§3.10/§3.11): status (store stats) + gc (compaction
	// trigger) are the porcelain ops remoted — ONE name across the CX surface and
	// the wire. The daemon has already enforced admin RBAC + tenant before routing
	// here; on the embedded reference server they serve unauthenticated like every
	// other op (the embedded tier has no authn plane). Responses are the exact
	// porcelain elements, rendered canonical as text/cx bodies.
	if method == 'GET' && path == csrp_base + 'status' {
		r := store_stdlib_builtin_inner('store-status', [local]) or {
			return csrp_resp(500, '[err code="cx-err:CXER1707" message="E_CSRP_SERVER_INTERNAL: status failed"]')
		}
		if is_err_value(r) {
			return csrp_admin_op_err(r)
		}
		return csrp_resp(200, render_canonical(r))
	}
	if method == 'POST' && path == csrp_base + 'gc' {
		r := store_stdlib_builtin_inner('store-gc', [local]) or {
			return csrp_resp(500, '[err code="cx-err:CXER1707" message="E_CSRP_SERVER_INTERNAL: gc failed"]')
		}
		if is_err_value(r) {
			return csrp_admin_op_err(r)
		}
		return csrp_resp(200, render_canonical(r))
	}
	// #182: the APPROVED binary wire. When the client speaks it — a cxbin request
	// body (Content-Type: application/cx-astbin, the §2.1 default) OR an Accept of
	// the binary frame stream — dispatch a data op through the body-carried /
	// frame-encoded handler. A legacy `Accept: text/cx` + query-param client keeps
	// the cxd path below (the negotiated alternate encoding during the transition).
	if method == 'POST' {
		bop := path[csrp_base.len..]
		if bop in ['get', 'put', 'delete', 'list', 'iter', 'query', 'modify']
			&& csrp_wants_binary(req) {
			return store_csrp_route_binary(req, local, bop)
		}
	}
	if method == 'POST' && path == csrp_base + 'put' {
		body := http_body_octets(req).bytestr()
		// #190: surface the real content-dedup signal. Content-addressing means the
		// store-key is deterministic from the body, so "already present" == the key
		// exists BEFORE this put. The route holds the op-lock (store_csrp_route), so
		// the exists-then-put is atomic — no window where a concurrent put flips it.
		canonical := cx.cx_text_canonical(body) or { '' }
		mut existed := false
		if canonical != '' {
			if h := cx.cx_text_hash(canonical) {
				ex := store_stdlib_builtin_inner('store-exists', [local, store_str(h)]) or {
					store_bool(false)
				}
				existed = csrp_scalar(ex) == 'true'
			}
		}
		r := store_stdlib_builtin_inner('store-put-doc-text', [local, store_str(body)]) or {
			return csrp_resp(400, '[err code="cx-err:CXER1701"]')
		}
		if is_err_value(r) {
			// classify: an auth/rate failure from a remote-backed mount is not a 400.
			ecode := svc_err_code(r)
			if ecode == 'cx-err:CXER1131' {
				return csrp_resp(401, '[err code="cx-err:CXER1702" message="E_CSRP_AUTH_REQUIRED: ${csrp_msg_esc(svc_err_msg(r))}"]')
			}
			return csrp_resp(400, '[err code="cx-err:CXER1701" message="E_CSRP_REQUEST_MALFORMED: ${csrp_msg_esc(svc_err_msg(r))}"]')
		}
		stored := if existed { 'false' } else { 'true' }
		return csrp_resp(200, '[put-result hash="${csrp_scalar(r)}" stored="${stored}"]')
	}
	if method == 'POST' && path == csrp_base + 'get' {
		hash := csrp_query(req, 'hash')
		r := store_stdlib_builtin_inner('store-get-doc-text', [local, store_str(hash)]) or {
			return csrp_resp(500, '[err code="cx-err:CXER1707"]')
		}
		// get-doc-text returns the canonical text (ScalarNode) or the absence
		// channel (empty sequence). Absence → 404 / CXER1721.
		if r is cx.ScalarNode {
			return csrp_resp(200, csrp_scalar(r))
		}
		return csrp_resp(404, '[err code="cx-err:CXER1721"]')
	}
	if method == 'POST' && path == csrp_base + 'delete' {
		hash := csrp_query(req, 'hash')
		r := store_stdlib_builtin_inner('store-delete-doc', [local, store_str(hash)]) or {
			return csrp_resp(500, '[err code="cx-err:CXER1707"]')
		}
		deleted := csrp_scalar(r)
		return csrp_resp(200, '[delete-result hash="${hash}" deleted="${deleted}"]')
	}
	if method == 'POST' && path == csrp_base + 'list' {
		r := store_stdlib_builtin_inner('store-list-docs', [local]) or {
			return csrp_resp(500, '[err code="cx-err:CXER1707"]')
		}
		// Wire form is [list-result [hashes [hash "h1"] [hash "h2"] …]] — each hash
		// is its own element. (Avoid [sequence …]: it is a reserved collection
		// constructor that the client's parser would fold into a sequence value,
		// not an element the navigation can walk.)
		mut sb := '[list-result [hashes'
		if r is cx.Element {
			for it in r.items {
				h := csrp_scalar(it)
				if h != '' {
					sb += ' [hash "${h}"]'
				}
			}
		}
		sb += ']]'
		return csrp_resp(200, sb)
	}
	if method == 'POST' && path == csrp_base + 'query' {
		// CXPath pushdown: run the query against the local mount server-side and
		// serialize the result. The CXPath is a query-param (`?path=…`). Wire form
		// is [query-result [result hash="H" <match-element> …] …] — each match is
		// a rendered data element, mirroring `list`'s nested-element form (raw
		// `(…)` sequences are deliberately NOT emitted; the client's parser would
		// fold them into a value rather than a walkable element).
		cxpath := csrp_query(req, 'path')
		r := store_stdlib_builtin_inner('store-query', [local, store_str(cxpath)]) or {
			return csrp_resp(500, '[err code="cx-err:CXER1707"]')
		}
		mut sb := '[query-result'
		if r is cx.Element { // the store_seq marker wrapper over [result …] items
			for result in r.items {
				if result is cx.Element && result.name == 'result' {
					mut hash := ''
					for a in result.attrs {
						if a.name == 'hash' {
							hash = cx.scalar_value_str_public(a.value)
						}
					}
					sb += ' [result hash="${hash}"'
					for inner in result.items { // store_seq marker over the matches
						if inner is cx.Element {
							for m in inner.items {
								sb += ' ' + render_canonical(m)
							}
						}
					}
					sb += ']'
				}
			}
		}
		sb += ']'
		return csrp_resp(200, sb)
	}
	if method == 'POST' && path == csrp_base + 'iter' {
		// Server-side iteration: enumerate every doc in the local mount and
		// serialize each as its own rendered element. Wire form is
		// [iter-result [doc hash="H" <rendered-doc>] …] — each doc is a nested
		// element carrying its content-address, mirroring list/query's
		// nested-element form (raw `(…)` sequences are deliberately NOT emitted;
		// the client's parser would fold them into a value, not a walkable node).
		r := store_stdlib_builtin_inner('store-iter-docs', [local]) or {
			return csrp_resp(500, '[err code="cx-err:CXER1707"]')
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
		return csrp_resp(200, sb)
	}
	if method == 'POST' && path == csrp_base + 'modify' {
		// Structural modification pushdown: the target doc hash is a query-param
		// (`?hash=…`); the modify action element is the request body (cxd-text).
		// store-modify-doc applies the action server-side, content-addresses the
		// result, and stores it. Wire form is
		// [modify-result old-hash="H" new-hash="NH" stored="true"].
		hash := csrp_query(req, 'hash')
		action_text := http_body_octets(req).bytestr()
		action := cx.parse(action_text) or {
			return csrp_resp(400, '[err code="cx-err:CXER1701"]')
		}
		mut action_node := cx.Node(cx.Element{
			name: ''
		})
		if action.elements.len > 0 {
			action_node = action.elements[0]
		} else {
			return csrp_resp(400, '[err code="cx-err:CXER1701"]')
		}
		r := store_stdlib_builtin_inner('store-modify-doc', [local, store_str(hash), action_node]) or {
			return csrp_resp(400, '[err code="cx-err:CXER1701"]')
		}
		if is_err_value(r) {
			// NOT_FOUND (unknown source hash) vs a malformed action — distinguish so
			// the client maps to the right store error rather than a blanket 500. The
			// store layer raises CXER1121 (E_STORE_NOT_FOUND); on the CSRP wire that
			// is the CSRP not-found code CXER1721 (same convention as the get route),
			// so a gRPC client maps it to NOT_FOUND(5), not UNKNOWN.
			ecode := csrp_err_code(r)
			if ecode == 'cx-err:CXER1121' {
				return csrp_resp(404, '[err code="cx-err:CXER1721"]')
			}
			return csrp_resp(400, '[err code="${ecode}"]')
		}
		new_hash := csrp_scalar(r)
		return csrp_resp(200, '[modify-result old-hash="${hash}" new-hash="${new_hash}" stored="true"]')
	}
	// ── Object-level wire (#129 spec §3) ────────────────────────────────────────
	// The daemon exchanges content-addressed OBJECTS (have/get/put) + ref resolution
	// so a client's object graph and the daemon's are ONE space — dedup + structural
	// sharing span the network ("change the URL, same model"). Object bytes travel
	// hex-encoded (binary-safe on the cxd-text wire). The handle lock taken at the top
	// of this fn serializes these against the doc verbs. `guard` is the resolved store.
	if method == 'POST' && path in [csrp_base + 'objects-have', csrp_base + 'objects-get',
		csrp_base + 'objects-put'] {
		if guard == unsafe { nil } {
			return csrp_resp(500, '[err code="cx-err:CXER1707"]')
		}
		body := http_body_octets(req).bytestr()
		doc := cx.parse(body) or { return csrp_resp(400, '[err code="cx-err:CXER1701"]') }
		if doc.elements.len == 0 {
			return csrp_resp(400, '[err code="cx-err:CXER1701"]')
		}
		top := doc.elements[0]
		getter := store_graph_getter(guard)
		if top is cx.Element {
			if path == csrp_base + 'objects-have' {
				// reply only the hashes the daemon is MISSING — the dedup-on-wire primitive.
				mut sb := '[have-result'
				for it in top.items {
					if it is cx.Element && it.name == 'o' {
						hx := csrp_attr(it, 'h')
						hb := hex.decode(hx) or { continue }
						if getter(hb) == none {
							sb += ' [o h="${hx}"]'
						}
					}
				}
				return csrp_resp(200, sb + ']')
			}
			if path == csrp_base + 'objects-get' {
				// fetch by hash; each object self-verifies via the composite getter.
				mut sb := '[get-result'
				for it in top.items {
					if it is cx.Element && it.name == 'o' {
						hx := csrp_attr(it, 'h')
						hb := hex.decode(hx) or { continue }
						payload := getter(hb) or { continue }
						sb += ' [o h="${hx}" bytes="${payload.hex()}"]'
					}
				}
				return csrp_resp(200, sb + ']')
			}
			if path == csrp_base + 'objects-put' {
				// store each uploaded object through the seam (content-addressed; a
				// duplicate is a no-op), then persist so it survives a restart.
				mut n := 0
				for it in top.items {
					if it is cx.Element && it.name == 'o' {
						pb := hex.decode(csrp_attr(it, 'bytes')) or { continue }
						guard.obj_sink.put(pb)
						n++
					}
				}
				store_persist(mut guard) or {
					return csrp_resp(500, '[err code="cx-err:CXER1707" message="E_CSRP_SERVER_INTERNAL: persist failed: ${csrp_msg_esc(err.msg())}"]')
				}
				return csrp_resp(200, '[put-result stored="${n}"]')
			}
		}
		return csrp_resp(404, '[err code="cx-err:CXER1709" message="E_CSRP_OPERATION_UNSUPPORTED: unknown object-wire operation"]')
	}
	if method == 'POST' && path == csrp_base + 'refs' {
		// resolve store-key → doc-root object hash (the ref layer, spec §3).
		if guard == unsafe { nil } {
			return csrp_resp(500, '[err code="cx-err:CXER1707"]')
		}
		body := http_body_octets(req).bytestr()
		doc := cx.parse(body) or { return csrp_resp(400, '[err code="cx-err:CXER1701"]') }
		mut sb := '[refs-result'
		if doc.elements.len > 0 {
			top := doc.elements[0]
			if top is cx.Element {
				for it in top.items {
					if it is cx.Element && it.name == 'k' {
						k := csrp_attr(it, 'key')
						if root := guard.obj_roots[k] {
							sb += ' [r key="${k}" root="${root.hex()}"]'
						}
					}
				}
			}
		}
		return csrp_resp(200, sb + ']')
	}
	if method == 'POST' && path == csrp_base + 'refs-set' {
		// advance store-key → root (after the client has put the missing objects).
		if guard == unsafe { nil } {
			return csrp_resp(500, '[err code="cx-err:CXER1707"]')
		}
		body := http_body_octets(req).bytestr()
		doc := cx.parse(body) or { return csrp_resp(400, '[err code="cx-err:CXER1701"]') }
		mut n := 0
		if doc.elements.len > 0 {
			top := doc.elements[0]
			if top is cx.Element {
				// #218 CAS: an optional expect="<hex>" attr per record makes the
				// advance conditional — the record applies only if the ref's current
				// root equals `expect` (expect="" ⇒ the ref must not exist yet).
				// VALIDATE-THEN-APPLY: all conditions are checked before any record
				// is applied, so a multi-ref set is all-or-nothing; a mismatch is
				// 409 CXER1704 (the client maps it onto CXER1114
				// E_STORE_REF_CONFLICT). Unconditional records (no expect attr)
				// keep last-writer-wins — correct for content-addressed doc-key
				// refs, which are immutable by construction; the CAS is for the
				// mutable-pointer layer (alias/branch remoting) built on this op.
				for it in top.items {
					if it is cx.Element && it.name == 'r' {
						k := csrp_attr(it, 'key')
						if k == '' {
							continue
						}
						if !csrp_has_attr(it, 'expect') {
							continue
						}
						expect := csrp_attr(it, 'expect')
						mut cur := ''
						if c := guard.obj_roots[k] {
							cur = c.hex()
						}
						if cur != expect {
							return csrp_resp(409, '[err code="cx-err:CXER1704" message="E_CSRP_CONCURRENT_MODIFY: ref ${k} is at ${csrp_msg_esc(cur)}, expected ${csrp_msg_esc(expect)}"]')
						}
					}
				}
				for it in top.items {
					if it is cx.Element && it.name == 'r' {
						k := csrp_attr(it, 'key')
						rb := hex.decode(csrp_attr(it, 'root')) or { continue }
						if k == '' {
							continue
						}
						if k !in guard.obj_roots {
							guard.doc_order << k
						}
						guard.obj_roots[k] = rb
						n++
					}
				}
			}
		}
		store_persist(mut guard) or {
			return csrp_resp(500, '[err code="cx-err:CXER1707" message="E_CSRP_SERVER_INTERNAL: persist failed: ${csrp_msg_esc(err.msg())}"]')
		}
		return csrp_resp(200, '[refs-set-result set="${n}"]')
	}
	if method == 'POST' && path == csrp_base + 'aliases' {
		// #645: alias READS answer from the mount's authoritative alias table with
		// EXPLICIT per-name presence — an absent alias is a server-asserted
		// present="false", never a silent empty (the #264 miss-vs-absence concern).
		body := http_body_octets(req).bytestr()
		doc := cx.parse(body) or { return csrp_resp(400, '[err code="cx-err:CXER1701"]') }
		if doc.elements.len == 0 {
			return csrp_resp(400, '[err code="cx-err:CXER1701"]')
		}
		top := doc.elements[0]
		mut sb := '[aliases-result'
		if top is cx.Element {
			if csrp_attr(top, 'all') == 'true' {
				lst := store_stdlib_builtin_inner('store-list-aliases', [local]) or {
					return csrp_resp(500, '[err code="cx-err:CXER1707"]')
				}
				if lst is cx.Element {
					for it in lst.items {
						if it is cx.Element && it.name == 'alias' {
							sb += ' [a name="${csrp_msg_esc(csrp_attr(it, 'name'))}" hash="${csrp_attr(it,
								'hash')}" present="true"]'
						}
					}
				}
			}
			for it in top.items {
				if it is cx.Element && it.name == 'k' {
					name := csrp_attr(it, 'name')
					if name == '' {
						continue
					}
					r := store_stdlib_builtin_inner('store-get-alias', [local, store_str(name)]) or {
						return csrp_resp(500, '[err code="cx-err:CXER1707"]')
					}
					if r is cx.ScalarNode {
						sb += ' [a name="${csrp_msg_esc(name)}" hash="${csrp_scalar(r)}" present="true"]'
					} else {
						sb += ' [a name="${csrp_msg_esc(name)}" present="false"]'
					}
				}
			}
		}
		return csrp_resp(200, sb + ']')
	}
	if method == 'POST' && path == csrp_base + 'aliases-set' {
		// #645: alias WRITES apply through the same local arm as an in-process
		// set-alias (target-presence CXER1121 → wire 404 CXER1721, read-only →
		// 400, alias record persisted). An optional per-record expect="<hash>"
		// is the refs-set CAS applied to the alias pointer layer (expect="" ⇒
		// must not exist): VALIDATE-THEN-APPLY under the route's handle lock,
		// all-or-nothing, mismatch = 409 CXER1704 — the conflict-safe pointer
		// advance a remote journal head rides (#644).
		body := http_body_octets(req).bytestr()
		doc := cx.parse(body) or { return csrp_resp(400, '[err code="cx-err:CXER1701"]') }
		if doc.elements.len == 0 {
			return csrp_resp(400, '[err code="cx-err:CXER1701"]')
		}
		top := doc.elements[0]
		mut n := 0
		if top is cx.Element {
			for it in top.items {
				if it is cx.Element && it.name == 'a' {
					name := csrp_attr(it, 'name')
					if name == '' || !csrp_has_attr(it, 'expect') {
						continue
					}
					expect := csrp_attr(it, 'expect')
					mut cur := ''
					r := store_stdlib_builtin_inner('store-get-alias', [local, store_str(name)]) or {
						return csrp_resp(500, '[err code="cx-err:CXER1707"]')
					}
					if r is cx.ScalarNode {
						cur = csrp_scalar(r)
					}
					if cur != expect {
						return csrp_resp(409, '[err code="cx-err:CXER1704" message="E_CSRP_CONCURRENT_MODIFY: alias ${csrp_msg_esc(name)} is at ${csrp_msg_esc(cur)}, expected ${csrp_msg_esc(expect)}"]')
					}
				}
			}
			for it in top.items {
				if it is cx.Element && it.name == 'a' {
					name := csrp_attr(it, 'name')
					hash := csrp_attr(it, 'hash')
					if name == '' || hash == '' {
						continue
					}
					r := store_stdlib_builtin_inner('store-set-alias', [local, store_str(name),
						store_str(hash)]) or {
						return csrp_resp(500, '[err code="cx-err:CXER1707"]')
					}
					if is_err_value(r) {
						ecode := csrp_err_code(r)
						if ecode == 'cx-err:CXER1121' {
							return csrp_resp(404, '[err code="cx-err:CXER1721" message="E_CSRP_NOT_FOUND: alias target ${hash}"]')
						}
						// read-only mount and other write-shape failures map to 400
						// (same convention as the admin/write ops).
						return csrp_resp(400, '[err code="${ecode}"]')
					}
					n++
				}
			}
		}
		return csrp_resp(200, '[aliases-set-result set="${n}"]')
	}
	// #196: an unrecognized operation is 404 CXER1709 E_CSRP_OPERATION_UNSUPPORTED
	// (a 404-class code, per the 1:1 status↔code invariant), NOT the 500-class
	// CXER1707.
	op_name := path.all_after_last('/')
	return csrp_resp(404, '[err code="cx-err:CXER1709" message="E_CSRP_OPERATION_UNSUPPORTED: unknown operation `${csrp_msg_esc(op_name)}`"]')
}

// csrp_admin_op_err maps a porcelain admin-op error (status/gc, #248) onto the
// wire per the §4 status↔code invariant: the porcelain's own CXER1709 (gc on a
// backend with no object graph) rides 404 unchanged; a read-only mount maps to
// 400 CXER1701 (matching the read-only mapping of the other write-shaped ops —
// std-lib CXER1110 never rides the wire); anything else is 500 CXER1707.
fn csrp_admin_op_err(r cx.Node) cx.Node {
	ecode := svc_err_code(r)
	emsg := csrp_msg_esc(svc_err_msg(r))
	if ecode == 'cx-err:CXER1709' {
		return csrp_resp(404, '[err code="cx-err:CXER1709" message="${emsg}"]')
	}
	if ecode == 'cx-err:CXER1110' {
		return csrp_resp(400, '[err code="cx-err:CXER1701" message="E_CSRP_REQUEST_MALFORMED: ${emsg}"]')
	}
	return csrp_resp(500, '[err code="cx-err:CXER1707" message="E_CSRP_SERVER_INTERNAL: ${emsg}"]')
}

// ── CSRP client (cx-store:// backend) ───────────────────────────────────────
//
// The Layer-1 store ops POST cxd-text to the reference server above. Bearer
// auth is optional (loopback/dev runs without it). CSRP server faults map onto
// the store error space (CXER11xx) the rest of the stdlib already speaks.

fn csrp_client_headers(rb &RemoteBackend, content_type string) [][]string {
	mut h := [][]string{}
	if content_type != '' {
		h << ['Content-Type', content_type]
	}
	if rb.bearer != '' {
		h << ['Authorization', 'Bearer ${rb.bearer}']
	}
	return h
}

fn csrp_op_url(rb &RemoteBackend, op string, query string) string {
	// Include the store-name segment (from the cx-store:// URL path, held in
	// rb.dir) so a multi-store server routes to the right mount:
	//   /cx-store/v1/<store-name>/<op>   (named)   vs   /cx-store/v1/<op>  (sole).
	// store-names are [A-Za-z0-9_-] (server-validated) → URL-safe, no escaping.
	mut u := if rb.dir != '' {
		'${rb.base_url}/cx-store/v1/${rb.dir}/${op}'
	} else {
		'${rb.base_url}/cx-store/v1/${op}'
	}
	if query != '' {
		u += '?' + query
	}
	return u
}

// csrp_client_admin performs one admin-plane exchange (#248 / §3.10–3.12;
// #251 §3.13) over the HTTP transport and returns the porcelain element from
// the response body ([status …] / [gc-result …] / [mounts …] /
// [config-reload …]). status and mounts are GET; gc and config-reload are
// POST; mounts and config-reload are SERVER-level (no store-name segment). A
// non-200 whose body carries a wire [err] element is surfaced with that code +
// message (the §4 codes are the documented client-visible surface for the
// admin plane — including the §3.13 CXER1711/1712 reload refusals);
// auth/rate failures map onto the standard store error space.
fn csrp_client_admin(rb &RemoteBackend, op string) cx.Node {
	method := if op in ['gc', 'config-reload'] { 'POST' } else { 'GET' }
	url := if op in ['mounts', 'config-reload'] {
		'${rb.base_url}/cx-store/v1/${op}'
	} else {
		csrp_op_url(rb, op, '')
	}
	resp, errn, ok := remote_http(method, url, csrp_client_headers(rb, ''), []u8{})
	if !ok {
		return errn
	}
	body := resp.body.bytestr()
	if resp.status == 401 || resp.status == 403 || resp.status == 429 || resp.status == 503 {
		return csrp_status_err(op, '', resp.status)
	}
	if resp.status != 200 {
		// surface the wire error verbatim when the body carries one (e.g. 404
		// CXER1709 for gc on a backend with no object graph — the same code the
		// local porcelain raises).
		if parsed := cx.parse(body) {
			if parsed.elements.len > 0 {
				e := parsed.elements[0]
				if e is cx.Element && e.name == 'err' {
					return mk_err(svc_err_code(e), svc_err_msg(e))
				}
			}
		}
		return csrp_status_err(op, '', resp.status)
	}
	parsed := cx.parse(body) or {
		return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: csrp ${op}: malformed response body')
	}
	if parsed.elements.len == 0 {
		return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: csrp ${op}: empty response body')
	}
	return parsed.elements[0]
}

// csrp_status_err maps a non-2xx/404 CSRP response onto the store error space.
fn csrp_status_err(op string, hash string, status int) cx.Node {
	if status == 401 || status == 403 {
		return mk_err('cx-err:CXER1131', 'E_STORE_AUTH_FAILED: csrp ${op} ${hash}: HTTP ${status}')
	}
	if status == 429 || status == 503 {
		return mk_err('cx-err:CXER1132', 'E_STORE_RATE_LIMIT: csrp ${op} ${hash}: HTTP ${status}')
	}
	return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: csrp ${op} ${hash}: HTTP ${status}')
}

