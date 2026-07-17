@[has_globals]
module code

// stdlib_xap_host_notd_wasm32_emcc.v — the deployment host (`[$xap:host]`),
// distribution spec §6.3: a XAP server is data plus adapters.
//
// The host boots a COMPLETE XAP from its deployment document: acquire every
// pinned feature from the CX_REGISTRY-bound store (fail closed — a pin
// mismatch or failed §3 verification refuses to boot), compose the grammar
// (W1–W6 at load), attach it to a runtime ([$xap:run] semantics), translate
// the deployment's [roles] ladder + each spec's [governance] grants + the
// [agents] capability/autonomy rows into runtime dials, load each feature's
// §1.2 contract module from its verified tree, and serve the standard
// surface. Deployment-specific transport lives in OPTS adapters (extra
// routes, an actor-resolution hook) that register ONTO the host — they never
// fork it.
//
// Routes (the standard surface):
//   GET  /grammar      → the composed [grammar …] projection (application/cx)
//   GET  /features     → [features [feature name= version=]*] (from the pins)
//   GET  /surface      → [surface <every contract readout>]
//   GET  /surface/<f>  → the feature's contract readout
//   POST /intent       → envelope-decode → ρ-resolve (focus = feature=) →
//                        runtime emit (PEP; N-COMPOSE-2) → contract apply →
//                        [ack …]; refusals name unknown-verb / ambiguous
//                        (+candidates) / the PEP denial
//   GET  /stream       → held-open SSE; one named `event: <feature>` frame
//                        (the fresh readout) per admitted act
//   <adapter routes>   → OPTS.routes closures ([request …] → [response …])
//
// Compiles only on the native build (the `_notd_wasm32_emcc` suffix), like
// the serve bridge it extends.

import cx
import os
import time

// one pinned, verified, loaded feature.
struct XapHostFeat {
	name     string
	version  string
	mhash    string // manifest Tier-1 hash (the pin)
	has_code bool   // tree carries <name>.cx → contract module loaded
}

@[heap]
struct XapHost {
mut:
	rt_id    int
	store    cx.Node // the deployment's working store handle (OPTS.store)
	feats    []XapHostFeat
	envelope string            // '' = raw application/cx intents; 'xsp' = b64+XSP frames
	routes   map[string]cx.Node // adapter routes: exact path → closure value
	actor    cx.Node            // resolve-actor closure (OPTS), or empty element
	has_actor bool
	// the boot env's closure/binding tables — the feature contract closures
	// (<f>:readout, <f>:apply) live here. A push/render from ANY caller (a
	// deployment worker on another thread) must render through THIS env, not
	// the caller's, or the contract closures are absent (empty readouts).
	// Captured at boot, mirroring the listener's enclosing_* snapshot.
	henv_bindings map[string]cx.Node
	henv_closures map[string]Closure
	henv_dyn      []cx.Node
	henv_state    &ProgramState = unsafe { nil }
	// §4.12 (issue #394): the deployment's [auth] block, parsed at boot — the
	// host as XSP-AUTH responder. has_auth=false ⇒ prior behavior verbatim.
	auth     &XapHostAuth = unsafe { nil }
	has_auth bool
}

__global (
	xap_hosts map[int]&XapHost
)

// ── boot ─────────────────────────────────────────────────────────────────────

fn xap_host(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 2 {
		return mk_err(xap_err_arg_invalid, 'E_XAP: host expects (xap-doc, opts)')
	}
	xdoc := xd_elem_of(args[0], 'xap') or {
		return mk_err(xap_err_arg_invalid, 'E_XAP: host expects an [xap …] deployment document')
	}
	opts := args[1]
	url := xap_map_get_str(opts, 'url')
	if url == '' {
		return mk_err(xap_err_arg_invalid, 'E_XAP: host opts need url: (the bind address)')
	}
	store := xap_map_get_node(opts, 'store') or {
		return mk_err(xap_err_arg_invalid, 'E_XAP: host opts need store: (the deployment working store)')
	}
	// registry binding — the same CX_REGISTRY the pkg: loader uses (§6.2).
	pinned := xap_gc_child(xdoc, 'features') or { cx.Element{
		name: 'features'
	} }
	rows := xap_gc_children(pinned, 'feature')
	reg_url := os.getenv('CX_REGISTRY')
	if rows.len > 0 && reg_url == '' {
		return mk_err('cx-err:CXER4889', 'E_XAP_PKG_REGISTRY_UNBOUND: CX_REGISTRY is unset — the host cannot acquire pinned features')
	}
	ro := xap_elem('opts', [xap_attr('read-only', 'true')], [])
	regsh := xd_store('store-open-opts', [cx.Node(xap_str(reg_url)), cx.Node(ro)])
	if xd_is_err(regsh) {
		return regsh
	}
	// acquire every pin: fetch BY manifest hash, cross-check the row, run the
	// full §3 chain, pull the sealed spec layer. Fail closed at each step.
	mut feats := []XapHostFeat{}
	mut specs := []cx.Node{}
	mut trees := map[string]cx.Element{}
	for row in rows {
		name := xap_elem_attr(row, 'name')
		version := xap_elem_attr(row, 'version')
		mhash := xap_elem_attr(row, 'manifest')
		thash := xap_elem_attr(row, 'hash')
		if name == '' || version == '' || mhash == '' || thash == '' {
			return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: host requires fully pinned [feature] rows (name/version/manifest/hash) — row "${name}" is not (re-pin the deployment doc)')
		}
		mdoc := xd_store('store-get-doc', [regsh, cx.Node(xap_str(mhash))])
		m := xd_elem_of(mdoc, 'package') or {
			return mk_err(xap_err_pkg_not_found, 'E_XAP_PKG_NOT_FOUND: no manifest at pinned hash for "${name}@${version}"')
		}
		if xap_elem_attr(m, 'name') != name || xap_elem_attr(m, 'version') != version
			|| xap_elem_attr(m, 'hash') != thash {
			return mk_err('cx-err:CXER4888', 'E_XAP_PKG_PIN_MISMATCH: manifest at pin is ${xap_elem_attr(m, 'name')}@${xap_elem_attr(m, 'version')} (tree ${xap_elem_attr(m, 'hash')}); the deployment row says ${name}@${version} (tree ${thash})')
		}
		empty_opts := xap_elem('__cx_map__', [], [])
		verified := xap_pkg_verify_manifest(regsh, m, cx.Node(empty_opts)) or {
			return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: verify chain errored for "${name}@${version}"')
		}
		if xd_is_err(verified) {
			return verified
		}
		tree := xap_pkg_tree_of(regsh, m) or {
			return mk_err(xap_err_pkg_not_found, 'E_XAP_PKG_NOT_FOUND: pinned content tree absent for "${name}@${version}"')
		}
		spec := xap_pkg_feature_doc(tree) or {
			return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: "${name}@${version}" carries no feature spec layer')
		}
		has_code := xap_pkg_has_entry(tree, '${name}.cx')
		trees[name] = tree
		specs << cx.Node(spec)
		feats << XapHostFeat{
			name:     name
			version:  version
			mhash:    mhash
			has_code: has_code
		}
	}
	// compose (the W1–W6 gate at load — §8.2: attach time is gate time).
	composed := xap_compose_builtin(specs) or {
		return mk_err(xap_err_pkg_gate_rejected, 'E_XAP_PKG_GATE_REJECTED: compose errored at host boot')
	}
	if xd_is_err(composed) {
		return composed
	}
	gram := composed as cx.Element
	// runtime with the grammar attached (xap_run semantics, §8.2).
	tenant0 := xap_map_get_str(opts, 'tenant')
	tenant := if tenant0 == '' { xap_elem_attr(xdoc, 'name') } else { tenant0 }
	run_opts := xap_elem('__cx_map__', [], [
		cx.Node(xap_elem('tenant', [], [cx.Node(xap_str(tenant))])),
		cx.Node(xap_elem('grammar', [], [cx.Node(gram)])),
	])
	rt_handle := xap_run([cx.Node(run_opts)]) or {
		return mk_err(xap_err_arg_invalid, 'E_XAP: host runtime creation failed')
	}
	if xd_is_err(rt_handle) {
		return rt_handle
	}
	rt_id := xap_elem_attr(rt_handle as cx.Element, 'id').int()
	// load each feature's §1.2 contract module from its VERIFIED tree; its
	// public defs register under the feature name (closures '<f>:readout' …).
	for f in feats {
		if !f.has_code {
			continue
		}
		tree := trees[f.name] or { continue }
		src := xap_pkg_entry_exact_text(tree, '${f.name}.cx')
		mod := load_module(src, 'pkg:${f.name}@${f.version}#${f.mhash}', mut env.state.module_table) or {
			return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: contract module of "${f.name}" failed to load: ${err.msg()}')
		}
		register_module_members(mod, f.name, none, mut env) or {
			return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: contract module of "${f.name}" failed to register: ${err.msg()}')
		}
	}
	// govern: roles ladder × spec grants; agent capabilities + autonomy allows.
	xap_host_wire_dials(rt_handle, xdoc, specs, gram)
	// §4.12 (issue #394): a present [host-auth] block makes this host the
	// XSP-AUTH responder — parse fail-closed and compile its DID→role authority
	// map into dials. Absent ⇒ auth off, today's behavior byte-for-byte. The
	// block name is [host-auth], NOT [auth]: a deployment may already carry an
	// [auth] element for its own login/credential config (xap-marine does), a
	// distinct concern from this channel handshake — squatting on [auth] would
	// break the auth-off invariant for those deployments.
	mut auth := &XapHostAuth(unsafe { nil })
	mut has_auth := false
	if ab := xap_gc_child(xdoc, 'host-auth') {
		a := xap_host_auth_build(ab, tenant) or {
			return mk_err('cx-err:CXER-XSP-AUTH-STATE', 'E_XAP_AUTH_BOOT: ${err.msg()}')
		}
		xap_host_auth_wire(rt_handle, xdoc, specs, a) or {
			return mk_err('cx-err:CXER-XSP-AUTH-STATE', 'E_XAP_AUTH_BOOT: ${err.msg()}')
		}
		auth = a
		has_auth = true
	}
	// envelope: the deployment's declared intent codec.
	mut envelope := ''
	if tr := xap_gc_child(xdoc, 'transport') {
		if en := xap_gc_child(tr, 'envelope') {
			envelope = xap_elem_attr(en, 'codec')
		}
	}
	// adapters: extra routes + the actor-resolution hook.
	mut routes := map[string]cx.Node{}
	if rn := xap_map_get_node(opts, 'routes') {
		if rn is cx.Element {
			for it in rn.items {
				if it is cx.Element && it.items.len > 0 {
					routes['/${it.name.trim_left('/')}'] = it.items[0]
				}
			}
		}
	}
	mut actor := cx.Node(xap_elem('', [], []))
	mut has_actor := false
	if an := xap_map_get_node(opts, 'resolve-actor') {
		actor = an
		has_actor = true
	}
	mut h := &XapHost{
		rt_id:    rt_id
		store:    store
		feats:    feats
		envelope: envelope
		routes:   routes
		actor:    actor
		has_actor: has_actor
		henv_bindings: env.bindings.clone()
		henv_closures: env.closures.clone()
		henv_dyn:      env.dyn_context.clone()
		henv_state:    unsafe { env.state }
		auth:          auth
		has_auth:      has_auth
	}
	xap_hosts[rt_id] = h
	// listener — same engine, gate `net` before binding (like xap_serve).
	host, port := xap_serve_authority(url)
	if port == 0 {
		return mk_err(xap_err_arg_invalid, 'E_XAP: host URL needs an explicit port: ${url}')
	}
	if d := cap_guard('net', '${host}:${port}') {
		return d
	}
	block := xap_map_get_str(opts, 'block') != 'false'
	srv := start_xap_listener(rt_id, host, port, block, mut env) or {
		return mk_err(xap_err_arg_invalid, 'E_XAP_HOST_FAILED: ${err.msg()}')
	}
	// A blocking host parks forever (the return never reaches the caller). A
	// non-blocking host RETURNS the [xap-runtime …] handle — not the transport
	// handle — so the deployment's own workers can reference the running XAP
	// ([$xap:host-push …], [$xap:why-allowed …]); the reactors keep serving in
	// the background regardless of what the handle carries.
	if block {
		return srv
	}
	return xap_elem('xap-runtime', [xap_attr('id', rt_id.str()),
		xap_attr('tenant', tenant)], [])
}

// xap_host_wire_dials translates the deployment's authority DATA into runtime
// dials: [roles] rank ladder × each spec's [governance] grants (a grant to a
// role reaches every role of >= rank; to=any reaches all), plus [agents]
// [capability] rows (feature="*" verb=<effect> expands over the composed
// grammar's verbs of that effect) and autonomy-envelope [allow] rows.
fn xap_host_wire_dials(rt cx.Node, xdoc cx.Element, specs []cx.Node, gram cx.Element) {
	mut role_rank := map[string]f64{}
	mut role_names := []string{}
	// the roles ladder may live under [roles] or [principals] (deployment
	// schema variants — marine uses [principals] with [agent] rows beside).
	for container in ['roles', 'principals'] {
		if rl := xap_gc_child(xdoc, container) {
			for r in xap_gc_children(rl, 'role') {
				rn := xap_elem_attr(r, 'name')
				if rn == '' || rn in role_rank {
					continue
				}
				role_rank[rn] = xap_elem_attr(r, 'rank').f64()
				role_names << rn
			}
		}
	}
	for sn in specs {
		if sn !is cx.Element {
			continue
		}
		spec := sn as cx.Element
		fname := xap_elem_attr(spec, 'name')
		gov := xap_gc_child(spec, 'governance') or { continue }
		for g in xap_gc_children(gov, 'grant') {
			verb := xap_elem_attr(g, 'verb')
			to := xap_elem_attr(g, 'to')
			if verb == '' {
				continue
			}
			need := if to == 'any' { -1.0 } else { role_rank[to] or { 1e18 } }
			for rn in role_names {
				rank := role_rank[rn] or { 0.0 }
				if to == 'any' || rank >= need {
					xap_host_dial(rt, 'principal:vessel', 'role:${rn}', '${fname}/${verb}')
				}
			}
		}
	}
	if ags := xap_gc_child(xdoc, 'agents') {
		for a in xap_gc_children(ags, 'agent') {
			aid := 'agent:${xap_elem_attr(a, 'name')}'
			for c in xap_gc_children(a, 'capability') {
				cf := xap_elem_attr(c, 'feature')
				cv := xap_elem_attr(c, 'verb')
				if cf == '*' {
					// effect-class row: every composed verb of that effect.
					if vs := xap_gc_child(gram, 'verbs') {
						for v in xap_gc_children(vs, 'verb') {
							if xap_elem_attr(v, 'effect') == cv {
								xap_host_dial(rt, 'principal:vessel', aid, xap_elem_attr(v, 'name'))
							}
						}
					}
				} else if cf != '' && cv != '' {
					xap_host_dial(rt, 'principal:vessel', aid, '${cf}/${cv}')
				}
			}
			if au := xap_gc_child(a, 'autonomy') {
				for al in xap_gc_children(au, 'allow') {
					af := xap_elem_attr(al, 'feature')
					av := xap_elem_attr(al, 'verb')
					if af != '' && av != '' {
						xap_host_dial(rt, 'principal:vessel', aid, '${af}/${av}')
					}
				}
			}
		}
	}
}

fn xap_host_dial(rt cx.Node, from string, to string, scope string) {
	res := xap_dial([rt, xap_elem('from', [xap_attr('id', from)], []),
		xap_elem('to', [xap_attr('id', to)], []),
		xap_elem('scope', [], [cx.Node(cx.TextNode{
			value: scope
		})])]) or { cx.Node(cx.Element{ name: 'err' }) }
	if xd_is_err(res) {
		// a failed authority translation must be LOUD at boot, never a latent
		// runtime denial with no trace.
		eprintln('cx-xap host: dial ${from} -> ${to} over ${scope} failed: ${xd_err_message(res)}')
	}
}

// ── dispatch (the standard surface) ──────────────────────────────────────────

fn xap_host_readout(mut h XapHost, fname string, has_code bool, mut env MatchEnv) string {
	if !has_code {
		return render_canonical(cx.Node(xap_elem('readout', [xap_attr('feature', fname)],
			[])))
	}
	c := env.closures['${fname}:readout'] or {
		return render_canonical(cx.Node(xap_elem('readout', [xap_attr('feature', fname)],
			[])))
	}
	t := f64(time.sys_mono_now()) / 1e9 // vtime alias below
	out := invoke_closure(c, [h.store, cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(t)
		data_type: cx.ScalarType.float_type
	})], mut env) or { cx.Node(xap_elem('readout', [xap_attr('feature', fname),
		xap_attr('error', err.msg())], [])) }
	return render_canonical(out)
}

fn xap_host_ack(ok bool, verb string, extra []cx.Attribute) WireResp {
	mut attrs := [cx.Attribute{
		name:  'ok'
		value: cx.ScalarValue(ok)
	}, xap_attr('verb', verb)]
	attrs << extra
	return xap_wire_cx(200, render_canonical(cx.Node(xap_elem('ack', attrs, []))))
}

fn xap_host_dispatch(mut h XapHost, method string, raw_path string, body string, hdrs XspReqHdrs, mut env MatchEnv) WireResp {
	reg := xap_reg()
	mut rt := reg.runtimes[h.rt_id] or { return mk_wire(500, [], 'xap-host: unknown runtime\n') }
	mut path := raw_path
	if q := path.index('?') {
		path = path[..q]
	}
	// §4.12 (issue #394): on an auth-enabled host, POST /attach IS the
	// handshake (always open, host-owned — before adapter routes), and every
	// other non-[public] request — adapter routes included — must carry a
	// verifying §4.8 rule-2 possession proof. Auth off ⇒ this block vanishes
	// and the wire shape is the prior one, byte-for-byte.
	mut auth_principal := ''
	if h.has_auth {
		if method == 'POST' && path == '/attach' {
			return xap_host_attach(mut h, body, hdrs)
		}
		if !xap_host_auth_public(h.auth, path) {
			d := xap_host_auth_admit(mut h, hdrs, body)
			if !d.ok {
				return d.resp
			}
			auth_principal = d.principal
		}
	}
	// adapter routes FIRST (§6.3 extend): a deployment may enrich a standard
	// route without forking the host. Exact key match, or prefix match when
	// the registered key ends with '/' ('/history/' serves /history/…).
	if handler := xap_host_route_for(h, path) {
		req := build_host_request(method, path, body)
		if c := resolve_closure(handler, env) {
			out := invoke_closure(c, [cx.Node(req)], mut env) or {
				return mk_wire(500, [], 'adapter route failed: ${err.msg()}\n')
			}
			return cx_response_to_wire(out, [])
		}
		return mk_wire(500, [], 'adapter route is not callable\n')
	}
	if method == 'GET' && path == '/grammar' {
		return xap_wire_cx(200, render_canonical(cx.Node(rt.grammar)))
	}
	if method == 'GET' && path == '/features' {
		mut items := []cx.Node{}
		for f in h.feats {
			items << cx.Node(xap_elem('feature', [xap_attr('name', f.name),
				xap_attr('version', f.version)], []))
		}
		return xap_wire_cx(200, render_canonical(cx.Node(xap_elem('features', [], items))))
	}
	if method == 'GET' && path == '/surface' {
		mut items := []cx.Node{}
		for f in h.feats {
			ro := xap_host_readout(mut h, f.name, f.has_code, mut env)
			items << xap_host_first_elem(ro)
		}
		return xap_wire_cx(200, render_canonical(cx.Node(xap_elem('surface', [], items))))
	}
	if method == 'GET' && path.starts_with('/surface/') {
		fname := path.all_after('/surface/')
		for f in h.feats {
			if f.name == fname {
				return xap_wire_cx(200, xap_host_readout(mut h, fname, f.has_code, mut env))
			}
		}
		return mk_wire(404, [], 'no such feature: ${fname}\n')
	}
	if method == 'GET' && path == '/stream' {
		return WireResp{
			status: 200
			sse:    true
			sse_rt: h.rt_id
			body:   ': hb\n\n'
		}
	}
	if method == 'POST' && path == '/intent' {
		return xap_host_intent(mut h, body, auth_principal, mut env)
	}
	return mk_wire(404, [], 'not found\n')
}

// xap_host_route_for: the adapter route for `path` — exact key, or prefix
// key (ends with '/').
fn xap_host_route_for(h XapHost, path string) ?cx.Node {
	if handler := h.routes[path] {
		return handler
	}
	for k, handler in h.routes {
		if k.ends_with('/') && path.starts_with(k) {
			return handler
		}
	}
	return none
}

// xap_host_first_elem re-parses one rendered readout into its root element
// (the canonical text is the transport form; /surface aggregates values).
fn xap_host_first_elem(ro string) cx.Node {
	doc := cx.parse(ro) or { return cx.Node(xap_str(ro)) }
	for n in doc.elements {
		if n is cx.Element {
			return n
		}
	}
	return cx.Node(xap_str(ro))
}

fn build_host_request(method string, path string, body string) cx.Element {
	body_item := cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(body)
		data_type: cx.ScalarType.string_type
	})
	return cx.Element{
		name:  'request'
		attrs: [
			cx.Attribute{ name: 'method', value: cx.ScalarValue(method) },
			cx.Attribute{ name: 'path', value: cx.ScalarValue(path) },
		]
		items: [
			cx.Node(cx.Element{ name: 'query-params', items: []cx.Node{} }),
			cx.Node(cx.Element{ name: 'headers', items: []cx.Node{} }),
			cx.Node(cx.Element{ name: 'body', items: [body_item] }),
		]
	}
}

// xap_host_intent: envelope-decode → ρ (focus = the intent's feature=) →
// runtime emit (the PEP; qualified journal event) → contract apply → ack.
// auth_principal ≠ '' ⇒ the §4.12 proven-actor path: the channel's session
// principal commits, claimed labels are checked (§4.8), the adapter hook and
// role= carry no authority.
fn xap_host_intent(mut h XapHost, raw_body string, auth_principal string, mut env MatchEnv) WireResp {
	mut text := raw_body
	if h.envelope == 'xsp' {
		bytes := bytes_stdlib_builtin('bytes-from-base64', [cx.Node(xap_str(raw_body.trim_space()))]) or {
			return xap_host_ack(false, '', [xap_attr('reason', 'envelope-decode-failed')])
		}
		frame := xsp_stdlib_builtin('xsp-decode', [bytes]) or {
			return xap_host_ack(false, '', [xap_attr('reason', 'envelope-decode-failed')])
		}
		if frame is cx.Element {
			if auth_principal != '' {
				// §4.8 rule 1 on the decoded frame's principal field, verbatim.
				checked := xsp_auth_stdlib_builtin('xsp-auth-frame-check', [
					cx.Node(xap_str(auth_principal)),
					cx.Node(frame),
				]) or { mk_err('cx-err:CXER-XSP-AUTH-PRINCIPAL-MISMATCH', 'E_XAP_AUTH: frame check failed') }
				if xd_is_err(checked) {
					return xap_host_auth_wire_err(403, checked)
				}
			}
			mut payload := ''
			for it in frame.items {
				if it is cx.Element && it.name == 'payload' {
					payload = xd_text_content(it)
				}
			}
			text = payload
		}
	}
	idoc := cx.parse(text) or {
		return xap_host_ack(false, '', [xap_attr('reason', 'intent-parse-failed')])
	}
	mut intent := cx.Element{}
	mut found := false
	for n in idoc.elements {
		if n is cx.Element && n.name == 'intent' {
			intent = n
			found = true
		}
	}
	if !found {
		return xap_host_ack(false, '', [xap_attr('reason', 'no-intent')])
	}
	verb := xap_elem_attr(intent, 'verb')
	focus := xap_elem_attr(intent, 'feature')
	reg := xap_reg()
	mut rt := reg.runtimes[h.rt_id] or { return mk_wire(500, [], 'xap-host: unknown runtime\n') }
	// ρ — the pure resolver, context focus from the intent's feature=.
	mut rargs := [cx.Node(rt.grammar), cx.Node(xap_str(verb))]
	if focus != '' {
		rargs << cx.Node(xap_elem('__cx_map__', [], [
			cx.Node(xap_elem('focus', [], [cx.Node(xap_str(focus))])),
		]))
	}
	resolved := xap_resolve_builtin(rargs) or {
		return xap_host_ack(false, verb, [xap_attr('reason', 'unknown-verb')])
	}
	if xd_is_err(resolved) {
		re := resolved as cx.Element
		ecode := xap_elem_attr(re, 'code')
		if ecode == 'cx-err:CXER4871' {
			return xap_host_ack(false, verb, [xap_attr('reason', 'ambiguous'),
				xap_attr('candidates', xap_elem_attr(re, 'candidates'))])
		}
		return xap_host_ack(false, verb, [xap_attr('reason', 'unknown-verb')])
	}
	qualified := xd_str_of(resolved)
	// actor — §4.12 proven path: the channel's session principal commits;
	// a claimed author= must equal it byte-for-byte (xsp:auth-frame-check —
	// the §4.8 rule, with the intent's author as the frame label), role= is
	// ignored, and the resolve-actor hook is NOT consulted (a proven
	// principal is never overridden by an adapter's claim).
	// Auth off: the adapter hook, else role:<@role>, else principal:<@author>.
	mut actor := ''
	if auth_principal != '' {
		checked := xsp_auth_stdlib_builtin('xsp-auth-frame-check', [
			cx.Node(xap_str(auth_principal)),
			cx.Node(xap_str(xap_elem_attr(intent, 'author'))),
		]) or { mk_err('cx-err:CXER-XSP-AUTH-PRINCIPAL-MISMATCH', 'E_XAP_AUTH: author check failed') }
		if xd_is_err(checked) {
			return xap_host_auth_wire_err(403, checked)
		}
		actor = auth_principal
	} else {
		if h.has_actor {
			if c := resolve_closure(h.actor, env) {
				out := invoke_closure(c, [cx.Node(intent)], mut env) or { cx.Node(xap_str('')) }
				actor = xd_str_of(out)
			}
		}
		if actor == '' {
			role := xap_elem_attr(intent, 'role')
			actor = if role != '' { 'role:${role}' } else { 'principal:${xap_elem_attr(intent, 'author')}' }
		}
	}
	// emit through the runtime — the single PEP; the journal event is qualified.
	do_el := xap_elem('do', [], [cx.Node(xap_str(qualified))])
	emit_opts := xap_elem('__cx_map__', [], [
		cx.Node(xap_elem('actor', [], [cx.Node(xap_str(actor))])),
	])
	ev := xap_emit([cx.Node(xap_elem('xap-runtime', [xap_attr('id', h.rt_id.str())], [])),
		cx.Node(do_el), cx.Node(emit_opts)]) or {
		return xap_host_ack(false, qualified, [xap_attr('reason', 'emit-failed')])
	}
	if xd_is_err(ev) {
		ee := ev as cx.Element
		return xap_host_ack(false, qualified, [xap_attr('reason', xap_elem_attr(ee, 'code')),
			xap_attr('actor', actor)])
	}
	// admitted — the contract apply runs under the feature's granted slice.
	// The PEP admitted the VERB; the feature may still refuse the VALUES
	// (§1.2/§6.3: its own domain policy — bounds, device state) by returning
	// a [refused reason=…] value, acked ok=false with that reason.
	fname := if i := qualified.index('/') { qualified[..i] } else { qualified }
	if c := env.closures['${fname}:apply'] {
		applied := invoke_closure(c, [cx.Node(xap_str(qualified)), cx.Node(intent),
			h.store], mut env) or {
			return xap_host_ack(false, qualified, [xap_attr('reason', 'apply-failed'),
				xap_attr('detail', err.msg())])
		}
		if applied is cx.Element {
			if applied.name == 'refused' {
				return xap_host_ack(false, qualified, [
					xap_attr('reason', xap_elem_attr(applied, 'reason')),
					xap_attr('actor', actor),
				])
			}
			// An err VALUE returned by the contract apply is a FAILED act —
			// the error-as-value model means it arrives as a normal return,
			// and the or {} above only catches raises. Swallowing it acked
			// ok=true on acts that did nothing (same failure class as a
			// swallowed xap_dial error).
			if xd_is_err(applied) {
				return xap_host_ack(false, qualified, [
					xap_attr('reason', 'apply-error'),
					xap_attr('code', xap_elem_attr(applied, 'code')),
					xap_attr('detail', xap_elem_attr(applied, 'message')),
					xap_attr('actor', actor),
				])
			}
		}
		// push the fresh readout as a named per-feature SSE event.
		xap_host_render_push(mut h, fname)
	}
	return xap_host_ack(true, qualified, [xap_attr('actor', actor)])
}

// xap_host_push_feature renders `fname`'s fresh readout and pushes it as a
// named SSE event — the same frame an admitted act pushes. Deployment
// workers whose changes bypass the intent path (source ingest, sim ticks)
// reach it via [$xap:host-push] (§6.3 extend).
fn xap_host_push_frame(rt_id int, fname string, payload string) {
	mut frame := 'event: ${fname}\n'
	for line in payload.trim_right('\n').split('\n') {
		frame += 'data: ${line}\n'
	}
	frame += '\n'
	xap_sse_push(rt_id, frame)
}

// render `fname`'s contract readout in the HOST's boot env (its closures) —
// not the caller's — and push it as the named SSE event. This is what lets a
// deployment worker on another thread push a correct readout.
fn xap_host_render_push(mut h XapHost, fname string) {
	mut has_code := false
	for f in h.feats {
		if f.name == fname {
			has_code = f.has_code
		}
	}
	// #317 template-alias env (see dispatch_request): the host's boot env is
	// an immutable template; reads alias it, writes CoW via cow_bindings /
	// cow_closures.
	mut henv := MatchEnv{
		bindings:        h.henv_bindings
		bindings_shared: true
		closures:        h.henv_closures
		closures_shared: true
		state:           unsafe { h.henv_state }
		anon_counter:    0
		dyn_context:     if h.henv_dyn.len > 0 { h.henv_dyn.clone() } else { h.henv_dyn }
	}
	xap_host_push_frame(h.rt_id, fname, xap_host_readout(mut h, fname, has_code, mut henv))
}

// [$xap:host-push RT FEATURE] — the deployment-worker push surface (§6.3): the
// host renders the feature's contract readout (in its own env) and fans it out
// as the named event to every /stream subscriber, exactly as an admitted act
// does. For change-digest workers, source ingest, and simulation ticks whose
// state changes bypass the intent path.
fn xap_host_push(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 2 {
		return mk_err(xap_err_arg_invalid, 'E_XAP: host-push expects (runtime, feature)')
	}
	rt := xap_runtime_of(args[0]) or {
		return mk_err('cx-err:CXER4859', 'E_XAP_RUNTIME_CLOSED: unknown runtime handle')
	}
	fname := xap_arg_name(args[1])
	if mut h := xap_hosts[rt.id] {
		xap_host_render_push(mut h, fname)
		return xap_elem('pushed', [xap_attr('feature', fname)], [])
	}
	return mk_err(xap_err_arg_invalid, 'E_XAP: runtime ${rt.id} is not hosted')
}
