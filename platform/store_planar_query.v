module platform

import code { MatchEnv, is_err_value, mk_err, render_canonical }
import cx

// store_planar_query.v — the Ring-2 orchestration of the L99 quoted planar
// store query (store.md §6.2; W6 of the I5 stream-2 ledger).
//
// [$store:query $s [?quote [?for …]] $opts?] — the quoted comprehension
// arrives as the `[cx:expr '<source>']` lowering; the pipeline is
// parse → §7.8 membership (typed CXER0120) → static slice extraction (the
// L100 which-sources walk; CXER1709 when the set cannot be static) →
// caller-scope handle resolution → the AUTHZ-SLICE layer (per-slice
// [$authz:check] when $opts carries an authz handle — any [deny] refuses
// CXER4700 carrying the deny, and nothing executes) → the L96 admissible
// rewrites (this executor is the rewriter's live consumer) → the sandboxed
// executor (code.planar_query_execute: the eval host-capability gate + the
// narrowed cap set + the handles-only environment).
//
// [$store:explain-query $s QUOTED] — the no-execution introspection twin:
// [query-plan plan= [slices …] [rewrites …]] — plan= is the §7.9 plan
// address (≡ cx:plan-address of the same source), slices the extracted
// source set, rewrites the applied/declined L96 report (the
// honest-reporting obligation).
//
// On a REMOTE handle the comprehension source rides the wire query op's
// comp= attribute (XSP) / comp field (gRPC); the SERVER applies its own
// layers and binds every source-ref handle name to the served store.

// store_planar_query_env is the env-aware dispatch arm (registered through
// store_stdlib_builtin_env): it claims store-query ONLY when the second
// argument is a quoted comprehension, and store-explain-query always.
fn store_planar_query_env(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	if name == 'store-explain-query' {
		return store_explain_query(args)
	}
	if name != 'store-query' || args.len < 2 {
		return none
	}
	if _ := code.planar_query_source(args[1]) {
		return store_query_planar(args, mut env)
	}
	return none
}

fn store_query_planar(args []cx.Node, mut env MatchEnv) cx.Node {
	src := code.planar_query_source(args[1]) or {
		return mk_err('cx-err:CXER0100', 'store:query — the second argument must be a CXPath string or a quoted planar comprehension')
	}
	ms, errn, ok := store_get_open(args[0])
	if !ok {
		return errn
	}
	// remote: the source text rides the wire; the SERVER applies both
	// layers and binds handle names to the served store.
	if store_remote_active(ms) {
		return store_remote_query_planar(ms.remote, src)
	}
	prog := cx.parse_program(src) or {
		return mk_err('cx-err:CXER4100', 'store:query — malformed comprehension source: ${err.msg()}')
	}
	if r := code.planar_membership(prog) {
		return code.planar_refusal_err(r)
	}
	slices := code.planar_extract_slices(prog) or {
		return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: store:query — ${err.msg()}')
	}
	// handle names in a quoted query are FORMAL parameters (portable text,
	// no captured environment): every store-source handle name binds to
	// THE QUERIED STORE — identically local and remote; a journal source
	// refuses (journals have their own surfaces). These are the ONLY names
	// the sandbox receives.
	mut bindings := map[string]cx.Node{}
	for s in slices {
		if s.kind != 'store' {
			return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: store:query — a ${s.kind} source cannot bind inside a quoted STORE query (journals have their own surfaces)')
		}
		bindings[s.handle] = args[0]
	}
	// the AUTHZ-SLICE layer (authorize-before-execute): configured through
	// $opts {authz: HANDLE, actor: …, tenant: …, as-of: …}.
	if args.len > 2 {
		if denial := store_query_authz_layer(args[2], slices) {
			return denial
		}
	}
	// the L96 admissible rewrites — this executor is their live consumer;
	// equivalence is engine-verified (the W5 battery), the report is
	// reachable through explain-query.
	comp, _ := code.planar_rewrite(prog) or {
		// unreachable after the membership gate above; loud if it ever is.
		return mk_err(code.planar_err_code, 'store:query — ${err.msg()}')
	}
	return code.planar_query_execute(cx.ProgramNode(comp), bindings, mut env)
}

// store_query_authz_layer runs the per-slice authz check. Returns the
// refusal node on any [deny] (fail-closed — nothing executes), none when
// every slice is permitted or when no authz handle is configured.
fn store_query_authz_layer(opts cx.Node, slices []code.PlanarSliceRef) ?cx.Node {
	cfg := authz_opts(opts)
	ah := cfg['authz'] or { return none }
	actor := cfg['actor'] or {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: store:query — the authz-slice layer needs an `actor` alongside the `authz` handle')
	}
	tenant := cfg['tenant'] or { cx.Node(cx.ScalarNode{}) }
	mut check_opts := map[string]cx.Node{}
	if asof := cfg['as-of'] {
		check_opts['as-of'] = asof
	}
	for s in slices {
		mut req_items := []cx.Node{}
		req_items << cx.Node(cx.Element{
			name:  'actor'
			items: [actor]
		})
		req_items << cx.Node(cx.Element{
			name:  'capability'
			items: [store_str('read')]
		})
		req_items << cx.Node(cx.Element{
			name:  'slice'
			items: [store_str(s.path)]
		})
		if tenant is cx.ScalarNode && tenant.value is string {
			req_items << cx.Node(cx.Element{
				name:  'tenant'
				items: [tenant]
			})
		} else if tenant is cx.Element {
			req_items << cx.Node(cx.Element{
				name:  'tenant'
				items: [cx.Node(tenant)]
			})
		}
		req := cx.Element{
			name:  'authz-request'
			items: req_items
		}
		opts_node := authz_opts_node(check_opts)
		decision := authz_check_impl([ah, cx.Node(req), opts_node], false)
		if is_err_value(decision) {
			return decision
		}
		if decision is cx.Element && decision.name == 'deny' {
			// fail-closed: the deny rides as the CAUSE of the canonical
			// CXER4700 — a [deny] inside a result relation could be
			// mistaken for data (store.md §6.2, the authz-slice layer).
			return authz_err_with_cause(authz_err_unauthorized,
				'E_AUTHZ_UNAUTHORIZED: store:query — the authz-slice layer denied `read` over slice `${s.path}` (authorize-before-execute: nothing was executed)',
				decision)
		}
	}
	return none
}

// authz_opts_node re-wraps a name→node map as the __cx_map__ opts value
// authz_check_impl expects (empty map → absence-shaped empty element).
fn authz_opts_node(m map[string]cx.Node) cx.Node {
	mut entries := []cx.Node{}
	for k, v in m {
		entries << cx.Node(cx.Element{
			name:  k
			items: [v]
		})
	}
	return cx.Element{
		name:  '__cx_map__'
		items: entries
	}
}

// store_explain_query — [$store:explain-query $s QUOTED]: parse +
// membership + extraction + the rewrite REPORT, no execution (and no eval
// capability needed). Local introspection surface; a remote handle refuses
// honestly.
fn store_explain_query(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err('cx-err:CXER0100', 'store:explain-query expects (store, quoted-comprehension)')
	}
	src := code.planar_query_source(args[1]) or {
		return mk_err('cx-err:CXER0100', 'store:explain-query — the second argument must be a quoted planar comprehension ([?quote [?for …]])')
	}
	ms, errn, ok := store_get_open(args[0])
	if !ok {
		return errn
	}
	if store_remote_active(ms) {
		return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: explain-query is a local introspection surface (run it against a local handle; the remote executor reports through its own explain)')
	}
	prog := cx.parse_program(src) or {
		return mk_err('cx-err:CXER4100', 'store:explain-query — malformed comprehension source: ${err.msg()}')
	}
	if r := code.planar_membership(prog) {
		return code.planar_refusal_err(r)
	}
	slices := code.planar_extract_slices(prog) or {
		return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: store:explain-query — ${err.msg()}')
	}
	plan := code.plan_address_of_node(prog) or {
		return mk_err(code.planar_err_code, 'store:explain-query — ${err.msg()}')
	}
	_, report := code.planar_rewrite(prog) or {
		return mk_err(code.planar_err_code, 'store:explain-query — ${err.msg()}')
	}
	mut slice_items := []cx.Node{}
	for s in slices {
		slice_items << cx.Node(cx.Element{
			name:  'slice'
			attrs: [
				cx.Attribute{
					name:  'kind'
					value: cx.ScalarValue(s.kind)
				},
				cx.Attribute{
					name:  'handle'
					value: cx.ScalarValue(s.handle)
				},
				cx.Attribute{
					name:  'path'
					value: cx.ScalarValue(s.path)
				},
			]
		})
	}
	return cx.Element{
		name:  'query-plan'
		attrs: [
			cx.Attribute{
				name:  'plan'
				value: cx.ScalarValue(plan)
			},
		]
		items: [
			cx.Node(cx.Element{
				name:  'slices'
				items: slice_items
			}),
			code.planar_rewrite_report_node(report),
		]
	}
}

// ── the wire (client side) ────────────────────────────────────────────────────

// store_remote_query_planar routes a quoted planar query to a remote
// backend: the comprehension SOURCE rides the query op (comp= / the comp
// field); only the service tier supports it.
fn store_remote_query_planar(rb &RemoteBackend, src string) cx.Node {
	match rb.scheme {
		'cx-store', 'cx-store+xsp' {
			return xsp_client_query_planar(rb, src)
		}
		'cx-store+grpc', 'cx-store+grpcs' {
			return grpc_client_query_planar(rb, src)
		}
		else {
			return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: planar query pushdown is not supported by the ${rb.scheme}:// backend')
		}
	}
}

// xsp_client_query_planar sends `[query comp="…"]` and reassembles the
// streamed relation items. Each top-level item of the comprehension's
// relation rides ONE event frame inside an `[item …]` envelope (lossless
// for scalar rows — the wire framing is element-shaped) and is unwrapped
// here, so the remote relation is byte-identical to the local one (the
// G13 parity posture).
fn xsp_client_query_planar(rb &RemoteBackend, src string) cx.Node {
	events, errn, ok := xcl_stream(rb, 'query', '[query comp="${sw_msg_esc(src)}"]')
	if !ok || xcl_is_err(errn) {
		return errn
	}
	mut results := []cx.Node{}
	for ev in events {
		if ev.name != 'item' {
			continue
		}
		if row := store_planar_unwrap_item(ev) {
			results << row
		}
	}
	return store_seq(results)
}

// grpc_client_query_planar sends the comp field (3) of QueryRequest and
// reassembles the streamed rows.
fn grpc_client_query_planar(rb &RemoteBackend, src string) cx.Node {
	res, errn, ok := grpc_client_call(rb, 'Query', pb_encode_query_request(GrpcQueryRequest{
		store: rb.dir
		comp:  src.bytes()
	}))
	if !ok {
		return errn
	}
	if res.grpc_status == 12 {
		return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: the gRPC server does not support the query op')
	}
	if res.grpc_status != 0 {
		return grpc_client_status_err('query', '', res)
	}
	mut results := []cx.Node{}
	for m in res.messages {
		qr := pb_decode_query_row(m) or { continue }
		doc := cx.parse(qr.row.bytestr()) or { continue }
		for el in doc.elements {
			// each row rides the [item [body::bytes …]] framed-ast_bin
			// envelope (typed, byte-exact).
			if el is cx.Element && el.name == 'item' {
				if row := store_planar_unwrap_item(el) {
					results << row
				}
			}
		}
	}
	return store_seq(results)
}

// ── the wire (server side, shared) ────────────────────────────────────────────

// store_server_query_planar executes a comp= wire query against the SERVED
// store: parse + membership + extraction server-side; every source-ref
// handle name binds to the served store (one store per wire — a journal
// source or any non-store slice refuses CXER1709); the server's own two
// layers apply (its host caps gate the executor; its authz config, when
// wired, is the server-side PEP). Returns the relation or an err value.
fn store_server_query_planar(local cx.Node, src string) cx.Node {
	prog := cx.parse_program(src) or {
		return mk_err('cx-err:CXER4100', 'query comp= — malformed comprehension source: ${err.msg()}')
	}
	if r := code.planar_membership(prog) {
		return code.planar_refusal_err(r)
	}
	slices := code.planar_extract_slices(prog) or {
		return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: query comp= — ${err.msg()}')
	}
	mut bindings := map[string]cx.Node{}
	for s in slices {
		if s.kind != 'store' {
			return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: query comp= — a ${s.kind} source cannot bind over the store wire (one store per wire)')
		}
		bindings[s.handle] = local
	}
	comp, _ := code.planar_rewrite(prog) or {
		return mk_err(code.planar_err_code, 'query comp= — ${err.msg()}')
	}
	mut env := code.new_env()
	return code.planar_query_execute(cx.ProgramNode(comp), bindings, mut env)
}

// store_server_query_planar_items renders a comp= wire query's relation as
// per-frame `[item [body::bytes 0x…]]` envelopes — each row rides FRAMED
// ast_bin (the doc-body lane: typed, byte-exact end-to-end — a text lane
// would collapse scalar rows to text nodes). The client unwraps; remote ≡
// local byte-identity. (items, err, ok).
fn store_server_query_planar_items(local cx.Node, src string) ([]string, cx.Node, bool) {
	r := store_server_query_planar(local, src)
	if is_err_value(r) {
		return []string{}, r, false
	}
	mut rows := []cx.Node{}
	if r is cx.Element && r.name == '__cx_seq__' {
		// the multi-row relation (an empty one sends no frames, just eos).
		rows = r.items.clone()
	} else {
		rows = [r]
	}
	mut items := []string{}
	for it in rows {
		bin := cx.emit_ast_bin(cx.Document{
			elements: [
				cx.Node(cx.Element{
					name:  'row-env'
					items: [it]
				}),
			]
		})
		items << '[item [body::bytes 0x${bin.hex()}]]'
	}
	return items, cx.Node(cx.ScalarNode{}), true
}

// store_planar_unwrap_item decodes one wire `[item [body::bytes 0x…]]`
// envelope back into the typed row.
fn store_planar_unwrap_item(ev cx.Element) ?cx.Node {
	body := sx_bytes_child(ev, 'body')?
	doc := cx.bin_to_doc(body) or { return none }
	if doc.elements.len == 1 {
		env := doc.elements[0]
		if env is cx.Element && env.name == 'row-env' && env.items.len == 1 {
			return env.items[0]
		}
	}
	return none
}
