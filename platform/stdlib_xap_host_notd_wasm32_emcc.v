@[has_globals]
module platform
import code {
	Closure,
	MatchEnv,
	ProgramState,
	bytes_stdlib_builtin,
	cap_guard,
	invoke_closure,
	load_module,
	mk_closure_sentinel,
	mk_err,
	register_module_members,
	render_canonical,
	resolve_closure,
}

// stdlib_xap_host_notd_wasm32_emcc.v — the deployment host (`[$xap:host]`),
// distribution spec §6.3: a XAP server is data plus adapters.
//
// The host boots a COMPLETE XAP from its deployment document: acquire every
// pinned feature from the CX_REGISTRY-bound store (fail closed — a pin
// mismatch or failed §3 verification refuses to boot), compose the grammar
// (W1–W6 at load), load each feature's §1.2 contract module from its verified
// tree, attach the grammar + the document's runtime bindings to a runtime
// ([$xap:run] semantics), translate the deployment's [roles] ladder + each
// spec's [governance] grants + the [agents] capability/autonomy rows into
// runtime dials, and serve the standard surface. Deployment-specific transport
// lives in OPTS adapters (extra routes, an actor-resolution hook) that register
// ONTO the host — they never fork it.
//
// The durable plane is DATA, not opts (#982, RULED: CO-9): the document's
// [runtime …] block declares journal / sources / resolver / log-reduce, and
// [principals [deriver …]] declares the derived nouns' producers. Both compile
// into the same run opts [$xap:run] already validates — see
// xap_host_runtime_bindings below.
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
	// #982 (RULED: CO-9): the four durable-plane run options have ONE hosted
	// spelling — the deployment document's [runtime …] block. Spelling one in
	// the host's opts map is a deployment mistake, and the host says so: the
	// class this issue reports is exactly a run option silently unreachable,
	// so a misplaced key REFUSES, it never rides along or drops quietly.
	for misplaced in xap_host_document_only_opts {
		if _ := xap_map_get_node(opts, misplaced) {
			return mk_err(xap_err_arg_invalid, 'E_XAP_HOST_BINDING_MISPLACED: `${misplaced}:` is a HOSTED binding — a deployment declares it as DATA in its document ([xap … [runtime [${misplaced} …]]], distribution spec §6.3.1), not in `[\$xap:host]` opts; the opts map is the direct `[\$xap:run]` surface (xap.md §3.1)')
		}
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
	// load each feature's §1.2 contract module from its VERIFIED tree; its
	// public defs register under the feature name (closures '<f>:readout' …).
	//
	// This runs BEFORE run assembly (#982): a `[runtime [log-reduce fn=…]]`
	// document binding names its reducer as DATA — a public def of a pinned
	// feature's contract module (§6.3 step 4) — so the closure table has to
	// carry the feature defs by the time the run opts are compiled. Nothing
	// here depends on the runtime, and failing before the runtime exists is
	// the stricter order, not the looser one.
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
	// runtime with the grammar attached (xap_run semantics, §8.2).
	tenant0 := xap_map_get_str(opts, 'tenant')
	tenant := if tenant0 == '' { xap_elem_attr(xdoc, 'name') } else { tenant0 }
	mut run_items := [
		cx.Node(xap_elem('tenant', [], [cx.Node(xap_str(tenant))])),
		cx.Node(xap_elem('grammar', [], [cx.Node(gram)])),
	]
	// §4.2 (#977 direct-run parity path): the deployment's deriver bindings
	// ride into run assembly UNCHANGED — the value carried here is exactly
	// what `[$xap:run {… derivers: (…)}]` accepts, so the hosted and direct
	// lanes bind the same producers (composition spec §4.2; the shape is
	// validated ONCE, by xap_run_derivers, never re-parsed here). Without the
	// forward a grammar carrying ANY derived=true noun cannot boot hosted at
	// all: run assembly refuses with CXER4875 (no bound deriver).
	//
	// #982 / RULED: CO-9 — the DOCUMENT's `[principals [deriver …]]` rows,
	// when present, SUPERSEDE that opts key: composition spec §4.2 rule 1
	// puts the deriver beside `[role]`/`[agent]` precisely so "run assembly
	// reads ONE block to know every actor", and a merge would make two.
	// Superseding is announced on stderr — a dropped binding is never silent.
	doc_derivers := xap_host_doc_derivers(xdoc)
	if doc_derivers.len > 0 {
		if _ := xap_map_get_node(opts, 'derivers') {
			eprintln('cx-xap host: the deployment document binds ${doc_derivers.len} [deriver] principal(s); the opts `derivers:` key is SUPERSEDED (composition spec §4.2 rule 1 — run assembly reads ONE block to know every actor)')
		}
		run_items << cx.Node(xap_elem('derivers', [], [
			cx.Node(xap_elem('__cx_seq__', [], doc_derivers)),
		]))
	} else if dv := xap_map_get_node(opts, 'derivers') {
		run_items << cx.Node(xap_elem('derivers', [], [dv]))
	}
	// #982 / RULED: CO-9 — the document's [runtime …] block compiles into the
	// SAME run opts xap_run validates (one validator, never two).
	if brf := xap_host_runtime_bindings(xdoc, mut run_items, env) {
		return brf
	}
	run_opts := xap_elem('__cx_map__', [], run_items)
	// #994 — run assembly is step 2; GOVERN is step 3. A `[runtime [sources …]]`
	// binding's pump consuming between them meets a PEP with no dials yet, and
	// a §3.1.2 denial is skip-and-ack: a pre-seeded stream's first entries were
	// lost on thread-start timing. So the host takes the deferral: the
	// subscriptions open here (a bad binding still refuses at boot) and NOTHING
	// is consumed until step 3 — and step 4's [host-auth] dials — are wired.
	rt_handle := xap_run_composed([cx.Node(run_opts)], mut env, true) or {
		return mk_err(xap_err_arg_invalid, 'E_XAP: host runtime creation failed')
	}
	if xd_is_err(rt_handle) {
		return rt_handle
	}
	rt_id := xap_elem_attr(rt_handle as cx.Element, 'id').int()
	// … and the deferral is a DEBT: every path out of this function from here
	// either arms the pumps or abandons them. A boot that refuses below (a bad
	// [host-auth] block, a portless url, a denied net capability, a listener
	// that will not bind) never consumed an entry and never acked one, so the
	// bound group's entries stay redeliverable to the next boot — announced,
	// not dropped quietly.
	mut pumps_armed := false
	defer {
		if !pumps_armed {
			xap_abandon_source_pumps(rt_id, 'the hosted boot refused after run assembly')
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
	// #994: the listener comes up NON-blocking even for a blocking host — the
	// park moves below the arming step, so the last thing that can refuse this
	// boot (the reactor bind) still refuses with nothing consumed and nothing
	// acked. The transport handle is unused either way: a blocking host parks
	// here, and a non-blocking one returns the [xap-runtime …] handle instead
	// (see below).
	_ := start_xap_listener(rt_id, host, port, false, mut env) or {
		return mk_err(xap_err_arg_invalid, 'E_XAP_HOST_FAILED: ${err.msg()}')
	}
	// #994 — ARM. GOVERN (step 3), the §4.12 [host-auth] dials and the
	// transport are all up; nothing left in this boot can refuse. Only now do
	// the deployment's §3.1.2 source pumps consume, so a stream that was
	// pre-seeded before boot meets exactly the PEP every later entry meets —
	// deterministically, never on thread-start timing (distribution spec
	// §6.3.1; RULED: CO-9).
	pumps_armed = true
	xap_arm_source_pumps(rt_id)
	// A blocking host parks forever (the return never reaches the caller). A
	// non-blocking host RETURNS the [xap-runtime …] handle — not the transport
	// handle — so the deployment's own workers can reference the running XAP
	// ([$xap:host-push …], [$xap:why-allowed …]); the reactors keep serving in
	// the background regardless of what the handle carries.
	if block {
		for {
			time.sleep(time.hour)
		}
	}
	return xap_elem('xap-runtime', [xap_attr('id', rt_id.str()),
		xap_attr('tenant', tenant)], [])
}

// ── deployment-document runtime bindings (#982, RULED: CO-9) ─────────────────
//
// The four §3.1 run options a hosted XAP could not otherwise reach —
// `journal`, `sources`, `resolver`, `log-reduce` — are declared in the
// DEPLOYMENT DOCUMENT, not in the host's opts map: a XAP with a durable
// journal stays "zero server code" (distribution spec §6.3), which is only
// true if the durable binding is deployment DATA. The wiring layer is already
// where the composition spec puts the deriver principals (§4.2), so this is
// the same layer, not a new one. The opts map stays the DIRECT `[$xap:run]`
// surface.
//
// The block is `[runtime …]`, one child per run option, each child named for
// its opt key verbatim:
//
//   [runtime
//     [journal url='file:///var/acme/acts' stream=acts checkpoint='file:///var/acme/ckpt']
//     [sources [source fabric='xsp://127.0.0.1:8447' stream=evidence
//               verb=record group=acme-xap actor='role:operator']]
//     [resolver [affinity component='orders/order-list' when='context[deadline]'
//                class=:orders.urgent rank=1]]
//     [log-reduce window=500 fn='orders:compact']]
//
// The host COMPILES this data into exactly the values `[$xap:run]` accepts and
// hands them to the same validator — nothing below re-checks a run-option
// shape, it only turns attributes into map keys. One validator, never two.

// the run options whose ONLY hosted spelling is the deployment document.
const xap_host_document_only_opts = ['journal', 'sources', 'resolver', 'log-reduce']

// xap_host_attr_map compiles one document binding element into the run-option
// `{k: v …}` map: EVERY attribute becomes a map key, verbatim. That is the
// spec's own shape, not a convenience — §3.1.1 spells the journal binding
// `{url, stream, …}` with "the map's remaining keys as the client opts", and
// §3.1.2's source map likewise carries the fabric client opts beside
// fabric/stream/verb/group. Attribute-for-attribute therefore also means a run
// option that GAINS a key needs no change here.
fn xap_host_attr_map(e cx.Element) cx.Node {
	mut items := []cx.Node{cap: e.attrs.len}
	for a in e.attrs {
		items << cx.Node(xap_elem(a.name, [], [
			cx.Node(xap_str(cx.scalar_value_str_public(a.value))),
		]))
	}
	return xap_elem('__cx_map__', [], items)
}

// xap_host_doc_derivers compiles `[principals [deriver name= produces= reads=]]`
// into the `{derivers: (…)}` run-option entries (composition spec §4.2, R8.1–
// R8.3). `reads=` is the whitespace-separated read set — the same spelling
// `[role features='orders shipments']` already uses — and is the document's
// half of §4.2 rule 3 (the read set must resolve inside the produced noun's
// `[from …]` envelope). `package=`/`doc=` are documentation for the human
// reader and for tooling; run assembly binds name↔noun.
fn xap_host_doc_derivers(xdoc cx.Element) []cx.Node {
	mut out := []cx.Node{}
	pr := xap_gc_child(xdoc, 'principals') or { return out }
	for d in xap_gc_children(pr, 'deriver') {
		mut items := [
			cx.Node(xap_elem('name', [], [cx.Node(xap_str(xap_elem_attr(d, 'name')))])),
			cx.Node(xap_elem('produces', [], [cx.Node(xap_str(xap_elem_attr(d, 'produces')))])),
		]
		reads := xap_elem_attr(d, 'reads')
		if reads != '' {
			mut rs := []cx.Node{}
			for r in reads.fields() {
				rs << cx.Node(xap_str(r))
			}
			items << cx.Node(xap_elem('reads', [], [cx.Node(xap_elem('__cx_seq__', [], rs))]))
		}
		out << cx.Node(xap_elem('__cx_map__', [], items))
	}
	return out
}

// xap_host_source_tier_notice announces the TIER SPLIT of one `[source …]` row
// at boot (#993, RULED: CO-9). It is a notice, never a refusal: an embedded
// (journal-url) source binding is legitimate and fully working within its tier
// — it ingests everything the bound stream carries — so refusing it would break
// a shape §3.1.2 explicitly admits ("any journal url"). What it CANNOT do is
// observe an append another process makes after it subscribes, and a deployment
// that believes otherwise is silently mis-wired.
//
// The reason is the SUBSTRATE's write discipline, not a missing feature. The
// supported cross-process shape on a local root is ONE writer + N READ-ONLY
// readers (stdlib_journal.v jrn_head_fresh; pinned by journal_head_fresh_test).
// A §3.1.2 source binding is required to carry `group:` — "the runtime owns
// committed offsets" — so it commits offsets into that same root and is
// therefore itself a WRITER. A producer in another process is a second writer,
// and #628 records what two independent writers on one root do: they collide on
// segment numbering and the second flush clobbers the first's segment file. The
// shipped remedy (store_open_shared_or_conflict) shares ONE live MemStore and
// is in-process by construction — it cannot span processes. Measured on this
// tree: the next open of such a root refuses E_STORE_INTEGRITY_MISMATCH, 5 runs
// of 5. So the missing delivery is not a reader that failed to follow; it is an
// arrangement the substrate does not support, and teaching the reader to follow
// it would build live delivery over a store that is being destroyed.
//
// `xsp://` is the cross-process path, and it is not a workaround: the
// fabric-serve daemon is the single sequencer for the streams it mounts
// (fabric.md §10) and the single writer of their root, which is exactly the
// discipline a local root cannot provide across processes.
fn xap_host_source_tier_notice(r cx.Element) {
	furl := xap_elem_attr(r, 'fabric')
	if furl == '' || fab_remote_url_is_remote(furl) {
		return
	}
	stream := xap_elem_attr(r, 'stream')
	eprintln('cx-xap: source "${stream}" is EMBEDDED-tier (${furl}): it will NEVER observe entries another process appends after boot — bind an xsp:// fabric for live cross-process ingest (distribution spec §6.3.1).')
}

// xap_host_runtime_bindings compiles the document's `[runtime …]` block onto
// `run_items`. Returns the refusal err VALUE, or none when every declared
// binding compiled. Every refusal is NAMED and loud: a declared binding the
// host cannot honor must never boot a XAP that silently lacks it — that is the
// exact failure #982 reports.
fn xap_host_runtime_bindings(xdoc cx.Element, mut run_items []cx.Node, env MatchEnv) ?cx.Node {
	rtb := xap_gc_child(xdoc, 'runtime') or { return none }
	mut bound := []string{}
	for it in rtb.items {
		if it !is cx.Element {
			continue
		}
		el := it as cx.Element
		// one binding per run option (the run opts map has one key each): a
		// second row would be read past and lost — the silent drop this whole
		// section exists to stop.
		if el.name in bound {
			return mk_err(xap_err_arg_invalid, 'E_XAP_HOST_BINDING_INVALID: [runtime …] declares [${el.name} …] twice — one binding per `[\$xap:run]` option; a second row cannot be honored and is never dropped quietly')
		}
		bound << el.name
		match el.name {
			'journal' {
				// §3.1.1: `{url: …, stream: …}` (+ the client opts / checkpoint
				// keys). A LIVE `[$journal:open]`/`[$fabric:open]` handle is a
				// value, not data — it belongs to the direct run lane.
				if xap_elem_attr(el, 'url') == '' {
					return mk_err(xap_err_arg_invalid, 'E_XAP_HOST_BINDING_INVALID: [runtime [journal …]] needs url= — the durable binding is a {url, stream, …} map (xap.md §3.1.1); an open journal/fabric HANDLE is a value, not deployment data, and binds through the direct `[\$xap:run]` lane')
				}
				run_items << cx.Node(xap_elem('journal', [], [xap_host_attr_map(el)]))
			}
			'sources' {
				// §3.1.2: each `[source …]` row is one binding map. The row
				// element is the singular of its container, the same shape
				// `[features [feature …]]` / `[principals [role …]]` already use.
				rows := xap_gc_children(el, 'source')
				if rows.len == 0 {
					return mk_err(xap_err_arg_invalid, 'E_XAP_HOST_BINDING_INVALID: [runtime [sources …]] declares no [source …] row — a binding block that binds nothing is a deployment mistake, never a silent no-op (xap.md §3.1.2)')
				}
				mut srcs := []cx.Node{cap: rows.len}
				for r in rows {
					xap_host_source_tier_notice(r)
					srcs << xap_host_attr_map(r)
				}
				run_items << cx.Node(xap_elem('sources', [], [
					cx.Node(xap_elem('__cx_seq__', [], srcs)),
				]))
			}
			'resolver' {
				// §3.1/§3.6: the two DATA-expressible resolvers are `:scripted`
				// (the default) and a rule set — `[$xap:resolver-default $rules]`
				// yields `[scripted-resolver [affinity …]…]` as a first-class
				// value that `[$xap:run {resolver: …}]` accepts, so the document
				// carries the rules and the host wraps them in that same head.
				// A CLOSURE resolver is code, not data: the direct lane owns it.
				kind := xap_elem_attr(el, 'kind')
				if kind != '' && kind != 'scripted' {
					return mk_err(xap_err_arg_invalid, 'E_XAP_HOST_BINDING_INVALID: [runtime [resolver kind="${kind}"]] — a deployment declares :scripted, optionally with [affinity …] rules (xap.md §3.1/§3.6); a closure resolver is code, not deployment data, and binds through the direct `[\$xap:run]` lane')
				}
				rules := xap_gc_children(el, 'affinity')
				if rules.len > 0 {
					mut rs := []cx.Node{cap: rules.len}
					for r in rules {
						rs << cx.Node(r)
					}
					run_items << cx.Node(xap_elem('resolver', [], [
						cx.Node(xap_elem('scripted-resolver', [], rs)),
					]))
				} else {
					run_items << cx.Node(xap_elem('resolver', [], [cx.Node(xap_str('scripted'))]))
				}
			}
			'log-reduce' {
				// §3.1 (#606): `{window: N, fn: <pure reducer>}`. `window` is
				// data; the reducer is named as data — a public def of a PINNED
				// feature's §1.2 contract module (`<feature>:<def>`, registered
				// by §6.3 step 4 above), so the compaction the deployment
				// declares still ships inside a verified package and the
				// deployment stays zero server code. `window` itself is left to
				// xap_run: it owns the ≥ 1 rule.
				fname := xap_elem_attr(el, 'fn')
				if fname == '' {
					return mk_err(xap_err_arg_invalid, 'E_XAP_HOST_BINDING_INVALID: [runtime [log-reduce …]] needs fn= — the pure reducer, named as `<feature>:<def>` (xap.md §3.1; distribution spec §1.2)')
				}
				if fname !in env.closures {
					return mk_err(xap_err_arg_invalid, 'E_XAP_HOST_BINDING_UNRESOLVED: [runtime [log-reduce fn="${fname}"]] names no loaded contract def — the reducer is a public def of a pinned feature\'s §1.2 contract module, spelled `<feature>:<def>` (distribution spec §6.3 step 4); the deployment DECLARES the compaction, it never ships the code')
				}
				run_items << cx.Node(xap_elem('log-reduce', [], [
					xap_map_node(['window', 'fn'], [
						cx.Node(xap_str(xap_elem_attr(el, 'window'))),
						mk_closure_sentinel(fname),
					]),
				]))
			}
			else {
				return mk_err(xap_err_arg_invalid, 'E_XAP_HOST_BINDING_UNKNOWN: [runtime [${el.name} …]] is not a runtime binding — the block declares journal / sources / resolver / log-reduce, one child per `[\$xap:run]` option (xap.md §3.1)')
			}
		}
	}
	return none
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

// xap_host_readout renders a feature's contract readout. `actor` is the
// request's RESOLVED identity — the §4.12 proven principal on an
// auth-enabled host, '' (anonymous) otherwise — and reaches the readout as
// a THIRD parameter iff the feature declares one (#647):
//   [?def readout scope=public impure ($store $t)]         — the prior arity,
//                                                            identity-blind
//   [?def readout scope=public impure ($store $t $actor)]  — per-principal
//                                                            lens: the feature
//                                                            composes the lens
//                                                            as DATA, scoping
//                                                            happens where the
//                                                            fold happens, and
//                                                            the wire carries
//                                                            only what this
//                                                            principal may see
// The arity dispatch preserves every existing 2-param contract byte-for-byte.
fn xap_host_readout(mut h XapHost, fname string, has_code bool, actor string, mut env MatchEnv) string {
	if !has_code {
		return render_canonical(cx.Node(xap_elem('readout', [xap_attr('feature', fname)],
			[])))
	}
	c := env.closures['${fname}:readout'] or {
		return render_canonical(cx.Node(xap_elem('readout', [xap_attr('feature', fname)],
			[])))
	}
	t := f64(time.sys_mono_now()) / 1e9 // vtime alias below
	mut rargs := [h.store, cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(t)
		data_type: cx.ScalarType.float_type
	})]
	nparams := if c.param_specs.len > 0 { c.param_specs.len } else { c.params.len }
	if nparams >= 3 {
		rargs << cx.Node(xap_str(actor))
	}
	out := invoke_closure(c, rargs, mut env) or { cx.Node(xap_elem('readout', [
		xap_attr('feature', fname), xap_attr('error', err.msg())], [])) }
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
	mut query_nodes := []cx.Node{}
	if q := path.index('?') {
		// #627: the query rides adapter-route requests as parsed [query-params].
		query_nodes = http_parse_query(path[q + 1..])
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
		req := build_host_request(method, path, body, query_nodes)
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
			// #647: the resolved request identity reaches every readout that
			// declares an actor param — the per-principal lens folds server-side.
			ro := xap_host_readout(mut h, f.name, f.has_code, auth_principal, mut env)
			items << xap_host_first_elem(ro)
		}
		return xap_wire_cx(200, render_canonical(cx.Node(xap_elem('surface', [], items))))
	}
	if method == 'GET' && path.starts_with('/surface/') {
		fname := path.all_after('/surface/')
		for f in h.feats {
			if f.name == fname {
				return xap_wire_cx(200, xap_host_readout(mut h, fname, f.has_code,
					auth_principal, mut env))
			}
		}
		return mk_wire(404, [], 'no such feature: ${fname}\n')
	}
	if method == 'GET' && path == '/stream' {
		// SSE-1 (xsp.md §4.1): ?envelope=xsp negotiates the XSP-envelope
		// carriage for THIS subscription (the downstream twin of the
		// deployment doc's [transport [envelope codec="xsp"]] upstream
		// opt-in). The initial heartbeat is an SSE comment — carriage-neutral.
		wants_xsp, env_refusal := xap_sse_envelope_of(raw_path)
		if env_refusal != '' {
			return mk_wire(400, [], env_refusal)
		}
		return WireResp{
			status:  200
			sse:     true
			sse_rt:  h.rt_id
			sse_xsp: wants_xsp
			body:    ': hb\n\n'
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

fn build_host_request(method string, path string, body string, query_nodes []cx.Node) cx.Element {
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
			cx.Node(cx.Element{ name: 'query-params', items: query_nodes }),
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
		cx.Node(do_el), cx.Node(emit_opts)], mut env) or {
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
	// SSE-1 (xsp.md §4.1): the SAME event in both negotiated carriages — the
	// plain named frame to plain subscribers, and the XSP-envelope twin
	// (event name stays a plain SSE line; data = base64(XSP event frame)
	// carrying the identical readout text) to ?envelope=xsp subscribers.
	xap_sse_push(rt_id, frame, xap_sse_named_frame_xsp(fname, payload))
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
	// #647: SSE pushes FAN OUT to every /stream subscriber, so a lensed
	// (3-param) readout renders with the ANONYMOUS actor ('') — the feature's
	// lens yields its public subset, the broadcast can never carry one
	// principal's view to another, and a lensed client treats the named event
	// as a change SIGNAL and re-fetches GET /surface/<f> under its own proof.
	xap_host_push_frame(h.rt_id, fname, xap_host_readout(mut h, fname, has_code, '', mut henv))
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
