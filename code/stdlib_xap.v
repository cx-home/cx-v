@[has_globals]
module code

// stdlib_xap.v — native primitives backing the `cx-xap` orchestrator subsystem
// (spec/03-approved/xap/xap.md). cx-xap is its OWN bundled package (not cx-stdlib): the
// experience-layer composer over the cx-stdlib primitives.
//
// Surface split:
//   env-free  (xap_stdlib_builtin):      surface / panel  (pure constructors) +
//                                        compose / compose-report / resolve / grammar-hash
//                                        (the §8.1 composition engine — pure functions of
//                                        their inputs: no journal, no PEP, no clock)
//   env-aware (xap_stdlib_builtin_env):  render / run / emit / state / on / dial / why-allowed
//                                        (apply view/handler [?fn]s, mutate runtime)
//
// This is the incremental runtime the demos (spec/03-approved/xap/demos/*) build against.

import cx

const xap_err_arg_invalid = 'cx-err:CXER4852' // E_XAP_COMPONENT_INVALID (reused for arg shape)
const xap_err_surface = 'cx-err:CXER4853' // E_XAP_SURFACE_INVALID
const xap_err_render = 'cx-err:CXER4855' // E_XAP_RENDER_UNSUPPORTED
const xap_err_unauthorized = 'cx-err:CXER4850' // E_XAP_UNAUTHORIZED (PEP deny, §8)

// ── component registry (global, by name) ────────────────────────────────────

struct XapComponent {
mut:
	name          string
	bind          string // CXPath slice it reads ("" for a pure/prop view)
	view          cx.Node // the [?fn (arg) view-tree] closure sentinel
	view_closure  Closure // the captured Closure for the view — durable across scopes (#40)
	working_panel string
	emits         cx.Node // the declared intent vocabulary (a sequence), or empty
	has_view      bool
	has_view_closure bool // true once view_closure has been captured
}

@[heap]
struct XapRegistry {
mut:
	components map[string]XapComponent
	runtimes   map[int]&XapRuntime
	next_id    int
}

struct XapRuntime {
mut:
	id         int
	tenant     string
	state      map[string][]cx.Node // bind-path → appended payload records (the fold)
	components []string             // component names registered with this runtime
	log        []cx.Node            // committed intents (the journal, for the demo)
	coord      map[string]cx.Node   // #25 Tier-2: transient coordination channels
	                                 // (channel → latest frame). NOT journaled, NOT
	                                 // PEP-gated, latest-wins, out of audit (§3.2).
	dials      []cx.Node            // issued delegations (the dial) — display elements
	authz      &AuthzStore = unsafe { nil } // the runtime's authority store (the real PEP, §2.2)
	shell_dir  string               // D3 web bridge: dir holding layout.html + static/
	grammar    cx.Element           // the attached composed grammar (§8.2 runtime integration)
	has_grammar bool                // set by xap-run {grammar: G}; switches on §5 resolution
	                                // + §6 N-COMPOSE-2 at the emit PEP
}

__global (
	g_xap_reg voidptr
)

fn xap_reg() &XapRegistry {
	if g_xap_reg == unsafe { nil } {
		r := &XapRegistry{
			components: map[string]XapComponent{}
			runtimes:   map[int]&XapRuntime{}
		}
		g_xap_reg = voidptr(r)
	}
	return unsafe { &XapRegistry(g_xap_reg) }
}

// ── node helpers ─────────────────────────────────────────────────────────────

fn xap_str(s string) cx.Node {
	return cx.ScalarNode{
		value: cx.ScalarValue(s)
	}
}

fn xap_attr(name string, val string) cx.Attribute {
	return cx.Attribute{
		name:  name
		value: cx.ScalarValue(val)
	}
}

fn xap_elem(name string, attrs []cx.Attribute, items []cx.Node) cx.Node {
	return cx.Element{
		name:  name
		attrs: attrs
		items: items
	}
}

// xap_arg_name extracts a name from a string scalar, a bareword (which parses to
// a TextNode, e.g. `greeting`), or an element head (`[greeting]`). Without the
// TextNode arm the component/surface/panel name silently came out empty (the
// registration key and the panel reference were both '', so lookups matched by
// accident and the bug stayed hidden until a name was actually rendered).
fn xap_arg_name(n cx.Node) string {
	if n is cx.ScalarNode {
		return cx.scalar_value_str_public(n.value)
	}
	if n is cx.TextNode {
		return n.value
	}
	if n is cx.Element {
		return n.name
	}
	return ''
}

// xap_map_get_node returns the value NODE for a key in a `{k: v}` map literal
// (a `__cx_map__`/`map` marker element whose entries are child elements named
// by the key with the value as items[0]).
fn xap_map_get_node(m cx.Node, key string) ?cx.Node {
	if m is cx.Element {
		if m.name == '__cx_map__' || m.name == 'map' {
			for it in m.items {
				if it is cx.Element && it.name == key && it.items.len > 0 {
					return it.items[0]
				}
			}
		}
	}
	return none
}

fn xap_map_get_str(m cx.Node, key string) string {
	if n := xap_map_get_node(m, key) {
		if n is cx.ScalarNode {
			return cx.scalar_value_str_public(n.value)
		}
		if n is cx.Element {
			return n.name
		}
	}
	return ''
}

fn xap_elem_attr(e cx.Element, name string) string {
	for a in e.attrs {
		if a.name == name {
			return cx.scalar_value_str_public(a.value)
		}
	}
	return ''
}

// xap_bind_path returns the first registered component's non-empty bind slice
// (the demos register exactly one stateful component — the guestbook).
fn xap_bind_path() string {
	reg := xap_reg()
	for _, c in reg.components {
		if c.bind != '' {
			return c.bind
		}
	}
	return ''
}

// ── env-free constructors (pure) ─────────────────────────────────────────────

fn xap_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		'xap-surface' {
			return xap_surface(args)
		}
		'xap-panel' {
			return xap_panel(args)
		}
		'xap-compose' {
			return xap_compose_builtin(args)
		}
		'xap-compose-report' {
			return xap_compose_report_builtin(args)
		}
		'xap-resolve' {
			return xap_resolve_builtin(args)
		}
		'xap-grammar-hash' {
			return xap_grammar_hash_builtin(args)
		}
		else {
			return none
		}
	}
}

fn xap_component(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 2 {
		return mk_err(xap_err_arg_invalid, 'E_XAP_COMPONENT_INVALID: component expects (name, opts)')
	}
	cname := xap_arg_name(args[0])
	opts := args[1]
	mut comp := XapComponent{
		name:          cname
		bind:          xap_map_get_str(opts, 'bind')
		working_panel: xap_map_get_str(opts, 'working-panel')
	}
	if v := xap_map_get_node(opts, 'view') {
		comp.view = v
		comp.has_view = true
		// Capture the actual Closure NOW — it lives in this scope's closure
		// table; the sentinel's env.closures entry is gone by render time when
		// the component is built inside a [?for] loop (#40). Storing the Closure
		// makes the deferred view invocable regardless of where render runs.
		// An escaping `[?fn]` carries its Closure ON the sentinel (#45), so
		// resolve_closure returns it directly; a named/builtin view resolves via
		// the durable scope tables.
		if cl := resolve_closure(v, env) {
			comp.view_closure = cl
			comp.has_view_closure = true
		}
	}
	if e := xap_map_get_node(opts, 'emits') {
		comp.emits = e
	}
	mut reg := xap_reg()
	reg.components[cname] = comp
	return xap_elem('component', [xap_attr('name', cname)], [])
}

fn xap_surface(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(xap_err_surface, 'E_XAP_SURFACE_INVALID: surface expects (name, panels)')
	}
	sname := xap_arg_name(args[0])
	return xap_elem('xap-surface', [xap_attr('name', sname)], [args[1]])
}

fn xap_panel(args []cx.Node) ?cx.Node {
	if args.len < 1 {
		return mk_err(xap_err_surface, 'E_XAP_SURFACE_INVALID: panel expects (component, opts?)')
	}
	cname := xap_arg_name(args[0])
	props := if args.len > 1 { args[1] } else { xap_elem('__cx_map__', [], []) }
	return xap_elem('xap-panel', [xap_attr('component', cname)], [props])
}

// ── env-aware verbs ──────────────────────────────────────────────────────────

fn xap_stdlib_builtin_env(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	match name {
		'xap-component' { return xap_component(args, mut env) }
		'xap-render' { return xap_render(args, mut env) }
		'xap-run' { return xap_run(args) }
		'xap-serve' { return xap_serve(args, mut env) }
		'xap-host' { return xap_host(args, mut env) }
		'xap-host-push' { return xap_host_push(args, mut env) }
		'xap-emit' { return xap_emit(args) }
		'xap-state' { return xap_state(args) }
		'xap-coord-publish' { return xap_coord_publish(args) }
		'xap-coord-read' { return xap_coord_read(args) }
		'xap-on' { return xap_on(args) }
		'xap-dial' { return xap_dial(args) }
		'xap-revoke' { return xap_revoke(args) }
		'xap-why-allowed' { return xap_why_allowed(args) }
		else { return none }
	}
}

// xap_runtime_of resolves a [xap-runtime id=K] handle to its live runtime.
fn xap_runtime_of(n cx.Node) ?&XapRuntime {
	if n is cx.Element && n.name == 'xap-runtime' {
		id := xap_elem_attr(n, 'id').int()
		reg := xap_reg()
		if rt := reg.runtimes[id] {
			return rt
		}
	}
	return none
}

// xap-run wires a single-tenant runtime (its journal/bus/authz/sessions — here
// an in-process state fold over the cx-stdlib primitives) and returns its handle.
fn xap_run(args []cx.Node) ?cx.Node {
	opts := if args.len > 0 { args[0] } else { xap_elem('__cx_map__', [], []) }
	mut reg := xap_reg()
	reg.next_id = reg.next_id + 1
	id := reg.next_id
	tenant := xap_map_get_str(opts, 'tenant')
	// §8.2 — a composed [grammar …] (the §8 projection) may be pinned at run
	// creation; it becomes the runtime's control vocabulary and switches on §5
	// resolution + §6 N-COMPOSE-2 evaluation in the emit cascade.
	mut gram := cx.Element{}
	mut has_gram := false
	if gn := xap_map_get_node(opts, 'grammar') {
		g := xap_gc_grammar_arg(gn) or {
			return mk_err(xap_err_arg_invalid, 'E_XAP: run grammar must be a composed [grammar …] document (the §8 projection)')
		}
		gram = g
		has_gram = true
	}
	// The runtime owns a real authority store — the single PEP the cascade calls
	// (§2.2). authz lives in the same V module (stdlib_authz.v); the dial issues
	// real delegations into this store and emit decides against it.
	st := &AuthzStore{
		tenant:  tenant
		is_open: true
	}
	rt := &XapRuntime{
		id:     id
		tenant: tenant
		state:  map[string][]cx.Node{}
		authz:  st
		grammar: gram
		has_grammar: has_gram
	}
	reg.runtimes[id] = rt
	return xap_elem('xap-runtime', [xap_attr('id', id.str()), xap_attr('tenant', tenant)],
		[])
}

// xap_verb_name returns the bare name of a `:verb` atom (or text), '' otherwise.
fn xap_verb_name(n cx.Node) string {
	if n is cx.ScalarNode {
		return cx.scalar_value_str_public(n.value)
	}
	if n is cx.TextNode {
		return n.value
	}
	return ''
}

// xap_seq_items flattens an `emits` value to its `[do …]` element patterns,
// recursing through any sequence/array nesting (the value arrives wrapped, e.g.
// an array whose item is the `([do …])` array). Elements are the leaves.
fn xap_seq_items(n cx.Node) []cx.Node {
	if n is cx.SequenceNode {
		mut out := []cx.Node{}
		for it in n.items {
			out << xap_seq_items(it)
		}
		return out
	}
	if n is cx.ArrayNode {
		mut out := []cx.Node{}
		for it in n.items {
			out << xap_seq_items(it)
		}
		return out
	}
	if n is cx.Element {
		// a `(…)` sequence is carried as a `__cx_seq__` marker element — descend
		// into it; a real element (e.g. `[do …]`) is a leaf pattern.
		if n.name == '__cx_seq__' {
			mut out := []cx.Node{}
			for it in n.items {
				out << xap_seq_items(it)
			}
			return out
		}
		return [cx.Node(n)]
	}
	return []cx.Node{}
}

// xap_session_principal_id extracts a principal id from an opts.session value —
// a [principal id=…] element, a [session … [principal id=…]], or a session with
// an `id` attribute. Returns '' when none (an anonymous emit).
fn xap_session_principal_id(s cx.Node) string {
	if s is cx.Element {
		if s.name == 'principal' {
			return xap_elem_attr(s, 'id')
		}
		for it in s.items {
			if it is cx.Element && it.name == 'principal' {
				return xap_elem_attr(it, 'id')
			}
		}
		id := xap_elem_attr(s, 'id')
		if id != '' {
			return id
		}
	}
	return ''
}

// xap_actor_kind splits a `kind:id` actor string into its kind ('principal',
// 'agent', …). An actor with no prefix is treated as a principal (the bare root).
fn xap_actor_kind(actor string) string {
	if actor.contains(':') {
		return actor.all_before(':')
	}
	return 'principal'
}

// xap_pep_admits is the real PEP decision (cascade step 1, §2.2). A principal
// actor has inherent authority (N-TRUST-1: authority originates from a principal);
// an anonymous emit (no actor) is admitted for back-compat with the bundled-runtime
// demos. Any other actor (an agent) must hold a real authority chain in the
// runtime's store, decided by authz_decide over (actor, capability=verb, slice=bind).
fn xap_pep_admits(rt &XapRuntime, actor string, verb string, bind string) bool {
	if actor == '' {
		return true // anonymous (back-compat); a real deployment requires an actor
	}
	if xap_actor_kind(actor) == 'principal' {
		return true // the principal is the root of the chain
	}
	if rt.authz == unsafe { nil } {
		return false
	}
	req := cx.Element{
		name: 'authz-request'
		items: [
			cx.Node(cx.Element{
				name:  'actor'
				attrs: [xap_attr('kind', xap_actor_kind(actor)), xap_attr('id', actor)]
			}),
			cx.Node(cx.Element{
				name:  'capability'
				attrs: [xap_attr('name', verb)]
			}),
			cx.Node(cx.Element{
				name:  'slice'
				attrs: [xap_attr('path', bind)]
			}),
		]
	}
	decision := authz_decide(rt.authz, req, map[string]cx.Node{})
	return decision is cx.Element && (decision as cx.Element).name == 'permit'
}

// xap_route_bind routes a verb to the bind slice of the component whose
// `emits` declares it (#41) — matching the qualified name or its local part
// (component emit patterns predate qualification) — falling back to the first
// bound component for the single-component demos.
fn xap_route_bind(vname string) string {
	reg := xap_reg()
	local := if vname.contains('/') { vname.all_after_last('/') } else { vname }
	if vname != '' {
		for _, c in reg.components {
			if c.bind == '' {
				continue
			}
			for pat in xap_seq_items(c.emits) {
				if pat is cx.Element && pat.items.len > 0 {
					pv := xap_verb_name(pat.items[0])
					if pv == vname || pv == local {
						return c.bind
					}
				}
			}
		}
	}
	for _, c in reg.components {
		if c.bind != '' {
			return c.bind
		}
	}
	return ''
}

// xap_rt_resolve_term is emit-side ρ (§8.2, resolution before the cascade): a
// qualified term must exist in the attached grammar (CXER4872 otherwise); a
// bare term must resolve uniquely (surviving ambiguity is CXER4871 with
// candidates= — the runtime never guesses, exactly like [$xap:resolve]).
// Returns (qualified, _) on success; ('', err-node) on failure.
fn xap_rt_resolve_term(g cx.Element, term string) (string, cx.Node) {
	ok := cx.Node(cx.TextNode{})
	if term.contains('/') {
		if xap_gc_doc_has_verb(g, term) {
			return term, ok
		}
		return '', xap_gc_err(xap_err_verb_unknown, 'E_XAP_VERB_UNKNOWN: no verb "${term}" in the attached grammar',
			[xap_attr('term', term)], [])
	}
	mut cands := xap_gc_doc_candidates(g, term)
	if cands.len == 0 {
		return '', xap_gc_err(xap_err_verb_unknown, 'E_XAP_VERB_UNKNOWN: no feature of the attached grammar defines "${term}"',
			[xap_attr('term', term)], [])
	}
	if cands.len == 1 {
		return cands[0], ok
	}
	cands.sort()
	return '', xap_gc_err(xap_err_verb_ambiguous, 'E_XAP_VERB_AMBIGUOUS: "${term}" has ${cands.len} candidates — disambiguate, never auto-pick',
		[xap_attr('term', term), xap_attr('candidates', cands.join(' '))], [])
}

// xap-emit runs the cascade for one intent: PEP check (§2.2) → append to the
// journal → the bound component's slice is the fold. The intent payload (fields
// after the :verb atom) is recorded as a map in the target component's bind slice;
// every attached client re-materializes from that shared state (§2.1/§14/§16).
fn xap_emit(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(xap_err_arg_invalid, 'E_XAP: emit expects (runtime, intent, opts?)')
	}
	mut rt := xap_runtime_of(args[0]) or {
		return mk_err('cx-err:CXER4859', 'E_XAP_RUNTIME_CLOSED: unknown runtime handle')
	}
	intent := args[1]
	opts := if args.len > 2 { args[2] } else { cx.Node(xap_elem('__cx_map__', [], [])) }
	// §3.4: the committed event's actor = opts.actor, else opts.session's principal.
	mut actor := ''
	if a := xap_map_get_node(opts, 'actor') {
		actor = xap_arg_name(a)
	} else if s := xap_map_get_node(opts, 'session') {
		actor = xap_session_principal_id(s)
	}
	// Route by the intent VERB (items[0] = the `:verb` atom) to the component whose
	// `emits` declares it (#41); fall back to the first bound component for the
	// single-component demos.
	mut vname := ''
	if intent is cx.Element && intent.items.len > 0 {
		vname = xap_verb_name(intent.items[0])
	}
	// §8.2 — resolution before the cascade (§5). With a grammar attached the
	// committed intent is always QUALIFIED: a bare term resolves through ρ
	// (ambiguity CXER4871 / unknown CXER4872 — values, never guesses) and the
	// journal event carries the qualified verb, so audit is exact.
	mut intent_committed := intent
	if rt.has_grammar {
		qname, rerr := xap_rt_resolve_term(rt.grammar, vname)
		if qname == '' {
			return rerr
		}
		if qname != vname && intent is cx.Element {
			mut qitems := intent.items.clone()
			qitems[0] = xap_str(qname)
			intent_committed = cx.Element{
				name:  intent.name
				attrs: intent.attrs
				items: qitems
			}
		}
		vname = qname
	}
	bind := xap_route_bind(vname)
	// §2.2 — the single PEP. Decide BEFORE any append: deny ⇒ failure channel,
	// commit nothing (CXER4850). Admit ⇒ proceed with the cascade.
	// §8.2 N-COMPOSE-2 — with a grammar attached, a derived verb is admitted by
	// its TRANSITIVE LEAF constituent grants, never the wrapper's name: the
	// denial names the missing constituent exactly as emitting it directly
	// would. (A non-derived verb's leaf set is itself, so plain verbs keep the
	// one-capability check.)
	if rt.has_grammar {
		for gname in xap_gc_leaf_grants(rt.grammar, vname) {
			gbind := xap_route_bind(gname)
			if !xap_pep_admits(rt, actor, gname, gbind) {
				return mk_err(xap_err_unauthorized, 'E_XAP_UNAUTHORIZED: actor "${actor}" is not granted "${gname}" over "${gbind}"')
			}
		}
	} else if !xap_pep_admits(rt, actor, vname, bind) {
		return mk_err(xap_err_unauthorized, 'E_XAP_UNAUTHORIZED: actor "${actor}" is not granted "${vname}" over "${bind}"')
	}
	// build a record map from the intent's payload fields (skip the :verb atom);
	// stamp the committing actor (§3.4) so the fold is per-actor auditable.
	mut fields := []cx.Node{}
	if actor != '' {
		fields << xap_elem('actor', [], [cx.Node(cx.TextNode{ value: actor })])
	}
	if intent is cx.Element {
		for i, it in intent.items {
			if i == 0 {
				continue
			}
			fields << it
		}
	}
	record := xap_elem('__cx_map__', [], fields)
	if bind != '' {
		rt.state[bind] << record
	}
	// the committed EVENT records the authority basis (the actor) and — with a
	// grammar attached — the QUALIFIED intent (§8.2); journal it. An anonymous
	// emit (no opts.actor/session) logs the bare intent (back-compat).
	event := if actor != '' {
		cx.Node(xap_elem('event', [xap_attr('actor', actor)], [intent_committed]))
	} else {
		intent_committed
	}
	rt.log << event
	return event
}

// xap-state returns the live fold over the runtime's journal projected by CXPath
// — a present sequence (absence/empty when nothing is there, never null).
fn xap_state(args []cx.Node) ?cx.Node {
	rt := xap_runtime_of(args[0]) or {
		return mk_err('cx-err:CXER4859', 'E_XAP_RUNTIME_CLOSED: unknown runtime handle')
	}
	path := if args.len > 1 { xap_arg_name(args[1]) } else { '' }
	entries := rt.state[path] or { return jrn_empty() }
	if entries.len == 0 {
		return jrn_empty()
	}
	return jrn_seq(entries)
}

// xap-coord-publish (runtime, channel, frame) — #25 Tier-2: publish ephemeral
// interaction state (viewport/selection/hover) to a transient coordination
// channel. LATEST-WINS (not appended) and held OUTSIDE rt.log — it never flows
// through the journal or the PEP-gated cascade, and is out of audit by design
// (spec/02-working/xap_feature_augmentation.md §3.2). Authorization is a
// wiring-time concern (the subscribing feature's capability), not per-frame.
fn xap_coord_publish(args []cx.Node) ?cx.Node {
	if args.len < 3 {
		return mk_err(xap_err_arg_invalid, 'E_XAP: coord-publish expects (runtime, channel, frame)')
	}
	mut rt := xap_runtime_of(args[0]) or {
		return mk_err('cx-err:CXER4859', 'E_XAP_RUNTIME_CLOSED: unknown runtime handle')
	}
	channel := xap_arg_name(args[1])
	if channel == '' {
		return mk_err(xap_err_arg_invalid, 'E_XAP: coord-publish channel must be a non-empty string')
	}
	rt.coord[channel] = args[2] // latest-wins; transient, not journaled
	return args[2]
}

// xap-coord-read (runtime, channel) — read the latest frame on a coordination
// channel (or empty if none published). The augmenting feature's live read of
// the augmented feature's ephemeral state (#25 Tier-2).
fn xap_coord_read(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(xap_err_arg_invalid, 'E_XAP: coord-read expects (runtime, channel)')
	}
	rt := xap_runtime_of(args[0]) or {
		return mk_err('cx-err:CXER4859', 'E_XAP_RUNTIME_CLOSED: unknown runtime handle')
	}
	channel := xap_arg_name(args[1])
	if frame := rt.coord[channel] {
		return frame
	}
	return jrn_empty()
}

// xap-on registers an intent handler (a thin wrap of bus subscribe + the cascade
// discipline). The demos use auto-projection (emit→bind slice), so this records
// the handler for completeness and returns null.
fn xap_on(args []cx.Node) ?cx.Node {
	return cx.Node(cx.ScalarNode{
		value: cx.ScalarValue('null')
	})
}

// xap_child_named finds the first [name …] element among args.
fn xap_child_named(args []cx.Node, name string) ?cx.Node {
	for a in args {
		if a is cx.Element && a.name == name {
			return a
		}
	}
	return none
}

// xap_party_id reads the id of a [from id=…]/[to id=…] element: the `id` attr,
// else the first bareword/atom item.
fn xap_party_id(n cx.Node) string {
	if n is cx.Element {
		id := xap_elem_attr(n, 'id')
		if id != '' {
			return id
		}
		if n.items.len > 0 {
			return xap_arg_name(n.items[0])
		}
	}
	return ''
}

// xap_scope_caps resolves a [scope :C] name to the verbs the component C emits
// (the conveyed capabilities) and its bind slice (the over). Falls back to the
// scope name itself as a capability when the component is unknown.
fn xap_scope_caps(scope_name string) ([]string, string) {
	reg := xap_reg()
	if c := reg.components[scope_name] {
		mut caps := []string{}
		for pat in xap_seq_items(c.emits) {
			if pat is cx.Element && pat.items.len > 0 {
				v := xap_verb_name(pat.items[0])
				if v != '' && v !in caps {
					caps << v
				}
			}
		}
		if caps.len == 0 {
			caps << scope_name
		}
		return caps, c.bind
	}
	return [scope_name], ''
}

// xap-dial sets the operational-control mode by issuing a REAL authz delegation
// into the runtime's store (the dial IS delegation issuance, §21.3): scoped,
// attenuating (principal-rooted here), revocable. Parties are explicit:
//   [$xap:dial $rt [from id=…] [to id=…] [scope :C] [setting :S]]
// The id is derived (d-dial-<scope>); from/to come from the args (no hardcoding).
fn xap_dial(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(xap_err_arg_invalid, 'E_XAP: dial expects (runtime, [from][to][scope][setting])')
	}
	mut rt := xap_runtime_of(args[0]) or {
		return mk_err('cx-err:CXER4859', 'E_XAP_RUNTIME_CLOSED: unknown runtime handle')
	}
	// the variadic `*$parts` arrives as one sequence arg (or several); flatten to
	// the leaf [from]/[to]/[scope]/[setting] elements.
	mut rest := []cx.Node{}
	for a in args[1..] {
		rest << xap_seq_items(a)
	}
	scope_el := xap_child_named(rest, 'scope') or {
		return mk_err(xap_err_arg_invalid, 'E_XAP: dial requires a [scope :component]')
	}
	setting_el := xap_child_named(rest, 'setting') or { cx.Node(xap_elem('setting', [], [])) }
	mut from_id := 'principal:'
	if f := xap_child_named(rest, 'from') {
		from_id = xap_party_id(f)
	}
	mut to_id := ''
	if t := xap_child_named(rest, 'to') {
		to_id = xap_party_id(t)
	}
	if to_id == '' {
		return mk_err(xap_err_arg_invalid, 'E_XAP: dial requires a [to id=…] (the delegate)')
	}
	scope_name := if scope_el is cx.Element && scope_el.items.len > 0 {
		xap_verb_name(scope_el.items[0])
	} else {
		''
	}
	caps, over := xap_scope_caps(scope_name)
	id := 'd-dial-' + scope_name
	// the display element retained for why-allowed rendering (attrs + scope/setting children).
	deleg := xap_elem('delegation', [xap_attr('id', id), xap_attr('from', from_id), xap_attr('to', to_id)],
		[scope_el, setting_el])
	// the REAL authority grant the PEP decides against.
	real := &AuthzDelegation{
		id:           id
		tenant:       rt.tenant
		from_kind:    'principal'
		from_id:      from_id
		to_kind:      xap_actor_kind(to_id)
		to_id:        to_id
		capabilities: caps
		over:         over
		attenuates:   ''
		revocable:    true
		assurance:    't0'
		value:        deleg
	}
	if rt.authz != unsafe { nil } {
		rt.authz.delegations << real
	}
	rt.dials << deleg
	return deleg
}

// xap-revoke revokes an issued dial delegation by id (§22.2 — revocation is
// absence). After revoke, why-allowed flips to allowed=false and the agent's
// emit is denied (CXER4850). Returns [revoked id=…] (or [revoked id=… ok=false]
// if no such live delegation).
fn xap_revoke(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(xap_err_arg_invalid, 'E_XAP: revoke expects (runtime, id)')
	}
	mut rt := xap_runtime_of(args[0]) or {
		return mk_err('cx-err:CXER4859', 'E_XAP_RUNTIME_CLOSED: unknown runtime handle')
	}
	id := xap_arg_name(args[1])
	mut found := false
	if rt.authz != unsafe { nil } {
		for mut d in rt.authz.delegations {
			if d.id == id && !d.revoked {
				d.revoked = true
				found = true
			}
		}
	}
	ok := if found { 'true' } else { 'false' }
	return xap_elem('revoked', [xap_attr('id', id), xap_attr('ok', ok)], [])
}

// xap-why-allowed answers "why can actor X emit intent Y" — a query over the
// runtime's authority store: the deciding delegation chain + the accountable
// principal (authority always traces to a human, N-CONTROL-2). Computed via
// authz_decide; a revoked/absent grant flips `allowed` to false.
fn xap_why_allowed(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(xap_err_arg_invalid, 'E_XAP: why-allowed expects (runtime, intent, opts?)')
	}
	rt := xap_runtime_of(args[0]) or {
		return mk_err('cx-err:CXER4859', 'E_XAP_RUNTIME_CLOSED: unknown runtime handle')
	}
	intent := args[1]
	opts := if args.len > 2 { args[2] } else { cx.Node(xap_elem('__cx_map__', [], [])) }
	mut actor := ''
	if a := xap_map_get_node(opts, 'actor') {
		actor = xap_arg_name(a)
	} else if s := xap_map_get_node(opts, 'session') {
		actor = xap_session_principal_id(s)
	}
	mut vname := ''
	if intent is cx.Element && intent.items.len > 0 {
		vname = xap_verb_name(intent.items[0])
	}
	// §8.2 — the answer is about the same intent emit would commit: resolve
	// the term against the attached grammar first (errors surface as values).
	if rt.has_grammar {
		qname, rerr := xap_rt_resolve_term(rt.grammar, vname)
		if qname == '' {
			return rerr
		}
		vname = qname
	}
	// a principal actor is inherently authorized (the root); render it accountable.
	if actor != '' && xap_actor_kind(actor) == 'principal' {
		return xap_elem('why-allowed', [xap_attr('allowed', 'true')], [
			xap_elem('chain', [], []),
			xap_elem('accountable', [xap_attr('principal', actor)], []),
		])
	}
	// §8.2 N-COMPOSE-2 — with a grammar attached, a derived verb is answered
	// over its TRANSITIVE LEAF constituent grant set: allowed only when EVERY
	// leaf decision permits; the chain merges the deciding delegations. It
	// never reports the wrapper as allowed while a constituent grant is
	// missing. (A non-derived verb's leaf set is itself.)
	grants := if rt.has_grammar {
		xap_gc_leaf_grants(rt.grammar, vname)
	} else {
		[vname]
	}
	store := if rt.authz != unsafe { nil } { rt.authz } else { &AuthzStore{} }
	mut via_ids := map[string]bool{}
	mut rooted := ''
	mut all_permit := true
	for gname in grants {
		gbind := xap_route_bind(gname)
		req := cx.Element{
			name: 'authz-request'
			items: [
				cx.Node(cx.Element{
					name:  'actor'
					attrs: [xap_attr('kind', xap_actor_kind(actor)), xap_attr('id', actor)]
				}),
				cx.Node(cx.Element{
					name:  'capability'
					attrs: [xap_attr('name', gname)]
				}),
				cx.Node(cx.Element{
					name:  'slice'
					attrs: [xap_attr('path', gbind)]
				}),
			]
		}
		decision := authz_decide(store, req, map[string]cx.Node{})
		if decision is cx.Element && decision.name == 'permit' {
			if rooted == '' {
				rooted = xap_elem_attr(decision, 'rooted-principal')
			}
			// the via list = the deciding delegation ids; collect for the chain.
			for it in decision.items {
				if it is cx.Element && it.name == 'via' {
					for vit in it.items {
						id := xap_arg_name(vit)
						if id != '' {
							via_ids[id] = true
						}
					}
				}
			}
		} else {
			all_permit = false
		}
	}
	if all_permit {
		mut chain := []cx.Node{}
		for d in rt.dials {
			if d is cx.Element && (xap_elem_attr(d, 'id') in via_ids || via_ids.len == 0) {
				chain << d
			}
		}
		return xap_elem('why-allowed', [xap_attr('allowed', 'true')], [
			xap_elem('chain', [], chain),
			xap_elem('accountable', [xap_attr('principal', rooted)], []),
		])
	}
	return xap_elem('why-allowed', [xap_attr('allowed', 'false')], [
		xap_elem('chain', [], []),
		xap_elem('accountable', [], []),
	])
}

// xap_panels_of returns the panel elements of a surface (handles a single panel
// or a sequence of panels).
fn xap_panels_of(surface cx.Node) []cx.Node {
	mut out := []cx.Node{}
	if surface is cx.Element && surface.items.len > 0 {
		inner := surface.items[0]
		if inner is cx.Element {
			if inner.name == 'xap-panel' {
				out << inner
			} else {
				// a sequence/composition of panels
				for it in inner.items {
					if it is cx.Element && it.name == 'xap-panel' {
						out << it
					}
				}
			}
		}
	}
	return out
}

fn xap_render(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 1 {
		return mk_err(xap_err_arg_invalid, 'E_XAP_RENDER: render expects (surface, opts?)')
	}
	surface := args[0]
	opts := if args.len > 1 { args[1] } else { xap_elem('__cx_map__', [], []) }
	mut accept := xap_map_get_str(opts, 'accept')
	if accept == '' {
		accept = 'text/html'
	}
	if accept != 'application/cx' && accept != 'text/html' {
		return mk_err(xap_err_render, 'E_XAP_RENDER_UNSUPPORTED: accept "${accept}" outside {text/html, application/cx}')
	}
	sname := if surface is cx.Element { xap_elem_attr(surface, 'name') } else { '' }
	reg := xap_reg()
	mut rendered := []cx.Node{}
	for panel in xap_panels_of(surface) {
		if panel !is cx.Element {
			continue
		}
		pe := panel as cx.Element
		cname := xap_elem_attr(pe, 'component')
		comp := reg.components[cname] or {
			return mk_err(xap_err_surface, 'E_XAP_SURFACE_INVALID: unregistered component "${cname}"')
		}
		if !comp.has_view {
			continue
		}
		// view argument: a bound (stateful) panel reads its slice from the
		// runtime in opts.context (D2+); a pure panel uses its props map (D1).
		mut view_arg := cx.Node(xap_elem('__cx_map__', [], []))
		if comp.bind != '' {
			if cn := xap_map_get_node(opts, 'context') {
				if rt := xap_runtime_of(cn) {
					view_arg = jrn_seq(rt.state[comp.bind] or { []cx.Node{} })
				}
			}
		} else if pe.items.len > 0 {
			view_arg = pe.items[0]
		}
		out := if comp.has_view_closure {
			invoke_closure(comp.view_closure, [view_arg], mut env) or { return err_to_node(err) }
		} else {
			apply_fn_value(comp.view, [view_arg], mut env) or { return err_to_node(err) }
		}
		rendered << out
	}
	surface_out := xap_elem('surface', [xap_attr('name', sname)], rendered)
	// application/cx → the view-tree value; text/html → html serialization (D3).
	return surface_out
}

// xap_runtime_surface applies the registered (bound) component's pure view [?fn]
// over the runtime's LIVE slice and wraps it as the [surface name=…] value — the
// SINGLE view-tree every medium serializes from (§2.5/§13.2). The serve listener
// renders this (application/cx = canonical print; text/html = view-tree→HTML),
// so the web, /surface, and CLI all materialize ONE view definition — no
// hand-built per-medium strings. Surface name = the served component's name.
fn xap_runtime_surface(rt &XapRuntime, mut env MatchEnv) cx.Node {
	reg := xap_reg()
	for _, c in reg.components {
		if !c.has_view {
			continue
		}
		mut view_arg := cx.Node(xap_elem('__cx_map__', [], []))
		if c.bind != '' {
			view_arg = jrn_seq(rt.state[c.bind] or { []cx.Node{} })
		}
		panel := if c.has_view_closure {
			invoke_closure(c.view_closure, [view_arg], mut env) or {
				return xap_elem('surface', [xap_attr('name', c.name)], [])
			}
		} else {
			apply_fn_value(c.view, [view_arg], mut env) or {
				return xap_elem('surface', [xap_attr('name', c.name)], [])
			}
		}
		// Force any lazy iterators in the view-tree into concrete sequences so
		// EVERY serializer (canonical print + the HTML mapper) reads the same
		// materialized data — a single-use [?for] iterator must not be consumed
		// by one serializer and emptied for the next.
		return xap_elem('surface', [xap_attr('name', c.name)], [xap_materialize(panel)])
	}
	return xap_elem('surface', [xap_attr('name', '')], [])
}

// xap_materialize deep-forces a view-tree: IteratorNode → concrete SequenceNode
// (via iterate), recursing through element items and nested collections. The
// medium-agnostic view-tree (§13.2) becomes a re-readable value, not a one-shot stream.
fn xap_materialize(n cx.Node) cx.Node {
	match n {
		cx.IteratorNode {
			mut items := []cx.Node{}
			for it in iterate(n) {
				items << xap_materialize(it)
			}
			return cx.SequenceNode{
				items: items
			}
		}
		cx.SequenceNode {
			mut items := []cx.Node{}
			for it in n.items {
				items << xap_materialize(it)
			}
			return cx.SequenceNode{
				items: items
			}
		}
		cx.ArrayNode {
			mut items := []cx.Node{}
			for it in n.items {
				items << xap_materialize(it)
			}
			return cx.ArrayNode{
				items: items
			}
		}
		cx.Element {
			mut items := []cx.Node{}
			for it in n.items {
				items << xap_materialize(it)
			}
			return cx.Element{
				...n
				items: items
			}
		}
		else {
			return n
		}
	}
}

// ── §8.1 composition engine (pure, env-free) ─────────────────────────────────
//
// spec/02-working/xap_grammar_composition.md — compose n feature grammars into
// ONE grammar `⊢ grammar.cxs` (or reject with every W1–W6 conflict), plus the
// bare-term resolution function ρ and the Tier-1 grammar hash. Everything here
// is a pure function of its inputs: no journal, no PEP, no clock, no registry.

const xap_err_compose_conflict = 'cx-err:CXER4870' // E_XAP_COMPOSE_CONFLICT
const xap_err_verb_ambiguous = 'cx-err:CXER4871' // E_XAP_VERB_AMBIGUOUS
const xap_err_verb_unknown = 'cx-err:CXER4872' // E_XAP_VERB_UNKNOWN
const xap_err_feature_invalid = 'cx-err:CXER4873' // E_XAP_FEATURE_INVALID

const xap_gc_effects = ['observe', 'act', 'arrange']
const xap_gc_scopes = ['shared', 'local']
const xap_gc_consequences = ['none', 'reversible', 'irreversible']
const xap_gc_rule_kinds = ['validity', 'mandate', 'exclusion', 'ordering', 'cardinality',
	'dependency']
const xap_gc_frame_families = ['geo', 'time', 'value']
const xap_gc_feature_kinds = ['base', 'composite']
const xap_gc_requirement_kinds = ['functional', 'quality', 'domain']

// A verb's grammar entry. scope/consequence keep '' when the source did not
// declare them — the §6 derivation needs declared-vs-absent to check weakening
// (absent adopts the derived floor; declared-but-weaker is a W5-class conflict).
struct XapGVerb {
mut:
	feature      string
	name         string // bare
	effect       string
	scope        string // '' = not declared
	consequence  string // '' = not declared
	constituents []string // qualified — derived verbs only (the N-COMPOSE-2 set)
}

struct XapGNoun {
mut:
	feature string
	name    string // bare
	derived bool
	fields  map[string]string // field name → type
}

struct XapGRule {
	feature  string
	name     string
	kind     string
	verb     string // structured W4 targets (declaring them opts the rule in)
	when     string
	after    string
	requires string
}

struct XapGFrameUse {
	feature string
	family  string
	via     string // '' = a composite's join declaration (no registration)
}

struct XapGKey {
	feature string
	name    string
	via     string
}

struct XapGFeature {
mut:
	name    string
	version string
	hash    string
	kind    string
	uses    []string
	nouns   []XapGNoun
	verbs   []XapGVerb
	rules   []XapGRule
	frames  []XapGFrameUse
	keys    []XapGKey
}

struct XapGConflict {
	code   string // ':w1' … ':w6'
	at     string
	detail string
}

// A resolved frame/key registration (feature, qualified noun, via, field type).
struct XapGReg {
	feature string
	noun    string // qualified
	via     string
	typ     string
}

// sort_key orders registrations deterministically by (feature, noun, via).
fn (r XapGReg) sort_key() string {
	return '${r.feature}\x00${r.noun}\x00${r.via}'
}

fn xap_attr_bool(name string, val bool) cx.Attribute {
	return cx.Attribute{
		name:  name
		value: cx.ScalarValue(val)
	}
}

// xap_gc_err builds an err value carrying structured payload (extra attributes
// like candidates=/term=, child [conflict …] entries) and fires the §9.6
// raise-stage observation, exactly like mk_err.
fn xap_gc_err(err_code string, message string, extra []cx.Attribute, items []cx.Node) cx.Node {
	mut attrs := [xap_attr('code', err_code), xap_attr('message', message)]
	attrs << extra
	e := cx.Node(cx.Element{
		name:  'err'
		attrs: attrs
		items: items
	})
	fire_raise_observe(e)
	return e
}

// xap_gc_flatten unwraps sequence/array packing (the `*$features` variadic
// arrives as one sequence) down to the leaf values — elements AND scalars stay
// leaves, so a non-[feature] argument like `42` reaches validation instead of
// silently vanishing.
fn xap_gc_flatten(n cx.Node) []cx.Node {
	match n {
		cx.SequenceNode {
			mut out := []cx.Node{}
			for it in n.items {
				out << xap_gc_flatten(it)
			}
			return out
		}
		cx.ArrayNode {
			mut out := []cx.Node{}
			for it in n.items {
				out << xap_gc_flatten(it)
			}
			return out
		}
		cx.IteratorNode {
			mut out := []cx.Node{}
			for it in iterate(n) {
				out << xap_gc_flatten(it)
			}
			return out
		}
		cx.Element {
			// '' is the anonymous sequence ENVELOPE (what a for-comprehension
			// yields) — same expansion rule as eval's iterate().
			if n.name == '__cx_seq__' || n.name == '__cx_arr__' || n.name == '' {
				mut out := []cx.Node{}
				for it in n.items {
					out << xap_gc_flatten(it)
				}
				return out
			}
			return [cx.Node(n)]
		}
		else {
			return [n]
		}
	}
}

fn xap_gc_child(e cx.Element, name string) ?cx.Element {
	for it in e.items {
		if it is cx.Element && it.name == name {
			return it
		}
	}
	return none
}

fn xap_gc_children(e cx.Element, name string) []cx.Element {
	mut out := []cx.Element{}
	for it in e.items {
		if it is cx.Element && it.name == name {
			out << it
		}
	}
	return out
}

// xap_gc_text_item returns the first scalar/text item of an element (the
// space-separated payload of [constituents '…'] / [uses features=…] siblings).
fn xap_gc_text_item(e cx.Element) string {
	if e.items.len > 0 {
		return xap_arg_name(e.items[0])
	}
	return ''
}

fn xap_gc_split_names(s string) []string {
	return s.split(' ').filter(it != '')
}

// xap_gc_parse_feature validates the structural surface `compose` consumes
// (feature.cxs-grade for every component the engine reads) and lifts the
// document into the grammar model. Full `.cxs` schema validation joins when
// the draft schemas graduate into the toolchain (spec §10) — the checks here
// cover everything composition itself depends on, so nothing the engine reads
// can be silently malformed.
fn xap_gc_parse_feature(n cx.Node) !XapGFeature {
	if n !is cx.Element {
		return error('not a [feature …] document')
	}
	e := n as cx.Element
	if e.name != 'feature' {
		return error('[${e.name} …] is not a [feature …] document')
	}
	mut f := XapGFeature{}
	f.name = xap_elem_attr(e, 'name')
	if f.name == '' {
		return error('[feature] requires name=')
	}
	f.version = xap_elem_attr(e, 'version')
	f.hash = xap_elem_attr(e, 'hash')
	f.kind = xap_elem_attr(e, 'kind')
	if f.kind == '' {
		f.kind = 'base'
	}
	if f.kind !in xap_gc_feature_kinds {
		return error('feature "${f.name}": kind="${f.kind}" outside {base, composite}')
	}
	if u := xap_gc_child(e, 'uses') {
		us := xap_elem_attr(u, 'features')
		if us == '' {
			return error('feature "${f.name}": [uses] requires features=')
		}
		f.uses = xap_gc_split_names(us)
	}
	nouns_el := xap_gc_child(e, 'nouns') or {
		return error('feature "${f.name}": missing [nouns]')
	}
	for ne in xap_gc_children(nouns_el, 'noun') {
		mut nn := XapGNoun{
			feature: f.name
			name:    xap_elem_attr(ne, 'name')
			derived: xap_elem_attr(ne, 'derived') == 'true'
		}
		if nn.name == '' {
			return error('feature "${f.name}": [noun] requires name=')
		}
		flds := xap_gc_children(ne, 'field')
		if flds.len == 0 {
			return error('feature "${f.name}": noun "${nn.name}" requires at least one [field]')
		}
		for fe in flds {
			fname := xap_elem_attr(fe, 'name')
			ftype := xap_elem_attr(fe, 'type')
			if fname == '' || ftype == '' {
				return error('feature "${f.name}": noun "${nn.name}" [field] requires name= and type=')
			}
			nn.fields[fname] = ftype
		}
		f.nouns << nn
	}
	if f.nouns.len == 0 {
		return error('feature "${f.name}": [nouns] requires at least one [noun]')
	}
	verbs_el := xap_gc_child(e, 'verbs') or {
		return error('feature "${f.name}": missing [verbs]')
	}
	for ve in xap_gc_children(verbs_el, 'verb') {
		mut v := XapGVerb{
			feature:     f.name
			name:        xap_elem_attr(ve, 'name')
			effect:      xap_elem_attr(ve, 'effect')
			scope:       xap_elem_attr(ve, 'scope')
			consequence: xap_elem_attr(ve, 'consequence')
		}
		if v.name == '' {
			return error('feature "${f.name}": [verb] requires name=')
		}
		if v.effect !in xap_gc_effects {
			return error('feature "${f.name}": verb "${v.name}" effect="${v.effect}" outside {observe, act, arrange}')
		}
		if v.scope != '' && v.scope !in xap_gc_scopes {
			return error('feature "${f.name}": verb "${v.name}" scope="${v.scope}" outside {shared, local}')
		}
		if v.consequence != '' && v.consequence !in xap_gc_consequences {
			return error('feature "${f.name}": verb "${v.name}" consequence="${v.consequence}" outside {none, reversible, irreversible}')
		}
		xap_gc_child(ve, 'intent') or {
			return error('feature "${f.name}": verb "${v.name}" requires [intent]')
		}
		if ce := xap_gc_child(ve, 'constituents') {
			v.constituents = xap_gc_split_names(xap_gc_text_item(ce))
		}
		f.verbs << v
	}
	if f.verbs.len == 0 {
		return error('feature "${f.name}": [verbs] requires at least one [verb]')
	}
	if re := xap_gc_child(e, 'rules') {
		for rl in xap_gc_children(re, 'rule') {
			r := XapGRule{
				feature:  f.name
				name:     xap_elem_attr(rl, 'name')
				kind:     xap_elem_attr(rl, 'kind')
				verb:     xap_elem_attr(rl, 'verb')
				when:     xap_elem_attr(rl, 'when')
				after:    xap_elem_attr(rl, 'after')
				requires: xap_elem_attr(rl, 'requires')
			}
			if r.name == '' {
				return error('feature "${f.name}": [rule] requires name=')
			}
			if r.kind !in xap_gc_rule_kinds {
				return error('feature "${f.name}": rule "${r.name}" kind="${r.kind}" outside the rule-kind enum')
			}
			xap_gc_child(rl, 'statement') or {
				return error('feature "${f.name}": rule "${r.name}" requires a [statement]')
			}
			f.rules << r
		}
	}
	if fr := xap_gc_child(e, 'frames') {
		for ue in xap_gc_children(fr, 'use') {
			fam := xap_elem_attr(ue, 'frame')
			if fam !in xap_gc_frame_families {
				return error('feature "${f.name}": [use] frame="${fam}" outside {geo, time, value}')
			}
			f.frames << XapGFrameUse{
				feature: f.name
				family:  fam
				via:     xap_elem_attr(ue, 'via')
			}
		}
	}
	if ke := xap_gc_child(e, 'keys') {
		for kk in xap_gc_children(ke, 'key') {
			knm := xap_elem_attr(kk, 'name')
			kv := xap_elem_attr(kk, 'via')
			if knm == '' || kv == '' {
				return error('feature "${f.name}": [key] requires name= and via=')
			}
			f.keys << XapGKey{
				feature: f.name
				name:    knm
				via:     kv
			}
		}
	}
	reqs_el := xap_gc_child(e, 'requirements') or {
		return error('feature "${f.name}": missing [requirements]')
	}
	reqs := xap_gc_children(reqs_el, 'requirement')
	if reqs.len == 0 {
		return error('feature "${f.name}": [requirements] requires at least one [requirement]')
	}
	for rq in reqs {
		rkind := xap_elem_attr(rq, 'kind')
		if rkind !in xap_gc_requirement_kinds {
			return error('feature "${f.name}": requirement kind="${rkind}" outside {functional, quality, domain}')
		}
	}
	return f
}

// xap_gc_load flattens + validates the argument list into the feature set.
// Structurally identical duplicates collapse (the §3.1 idempotence law —
// `compose(A, A) ≡ A` governs the operator); same-NAME different-CONTENT
// features are both kept so W1 rejects them.
fn xap_gc_load(args []cx.Node) ![]XapGFeature {
	mut items := []cx.Node{}
	for a in args {
		items << xap_gc_flatten(a)
	}
	mut feats := []XapGFeature{}
	mut seen := map[string][]string{} // name → canonical renders already admitted
	for i, it in items {
		f := xap_gc_parse_feature(it) or { return error('argument ${i + 1}: ${err.msg()}') }
		canon := render_canonical(it)
		if canon in seen[f.name] {
			continue // idempotence: the same feature twice composes once
		}
		seen[f.name] << canon
		feats << f
	}
	return feats
}

fn xap_gc_effect_rank(e string) int {
	return match e {
		'act' { 2 }
		'arrange' { 1 }
		else { 0 } // observe
	}
}

fn xap_gc_scope_rank(s string) int {
	return if s == 'shared' { 1 } else { 0 }
}

fn xap_gc_cons_rank(c string) int {
	return match c {
		'irreversible' { 2 }
		'reversible' { 1 }
		else { 0 } // none
	}
}

fn xap_gc_effect_of_rank(r int) string {
	return match r {
		2 { 'act' }
		1 { 'arrange' }
		else { 'observe' }
	}
}

fn xap_gc_scope_of_rank(r int) string {
	return if r == 1 { 'shared' } else { 'local' }
}

fn xap_gc_cons_of_rank(r int) string {
	return match r {
		2 { 'irreversible' }
		1 { 'reversible' }
		else { 'none' }
	}
}

// xap_gc_verb_floor derives a composite verb's signature floor over its
// constituents (§6): effect = max along observe<arrange<act; scope = shared if
// any shared; consequence = max along none<reversible<irreversible. Constituents
// missing from the composed grammar are W5 conflicts elsewhere and skipped here.
// `depth` bounds constituent-chain recursion: a cyclic constituent graph is a
// W5 conflict (xap_gc_gate) and the composition is rejected, so the floor
// value under a cycle is moot — the cap only keeps the walk terminating.
const xap_gc_max_constituent_depth = 64

fn xap_gc_verb_floor(v XapGVerb, vmap map[string]XapGVerb, depth int) (int, int, int) {
	mut ef := 0
	mut sc := 0
	mut cq := 0
	if depth > xap_gc_max_constituent_depth {
		return ef, sc, cq
	}
	for c in v.constituents {
		cv := vmap[c] or { continue }
		cef := xap_gc_effect_rank(cv.effect)
		csc := xap_gc_scope_rank(xap_gc_verb_scope(cv, vmap, depth + 1))
		ccq := xap_gc_cons_rank(xap_gc_verb_consequence(cv, vmap, depth + 1))
		if cef > ef {
			ef = cef
		}
		if csc > sc {
			sc = csc
		}
		if ccq > cq {
			cq = ccq
		}
	}
	return ef, sc, cq
}

// xap_gc_verb_scope / xap_gc_verb_consequence: the EFFECTIVE signature values —
// a declared value wins; an underived verb defaults per feature.cxs (local /
// none); a derived verb's absent value adopts its floor.
fn xap_gc_verb_scope(v XapGVerb, vmap map[string]XapGVerb, depth int) string {
	if v.scope != '' {
		return v.scope
	}
	if v.constituents.len > 0 {
		_, sc, _ := xap_gc_verb_floor(v, vmap, depth)
		return xap_gc_scope_of_rank(sc)
	}
	return 'local'
}

fn xap_gc_verb_consequence(v XapGVerb, vmap map[string]XapGVerb, depth int) string {
	if v.consequence != '' {
		return v.consequence
	}
	if v.constituents.len > 0 {
		_, _, cq := xap_gc_verb_floor(v, vmap, depth)
		return xap_gc_cons_of_rank(cq)
	}
	return 'none'
}

// xap_gc_key_regs resolves one feature key onto its nouns: every noun carrying
// the `via` field registers, contributing that field's type (the W2 subject).
fn xap_gc_key_regs(f XapGFeature, k XapGKey) []XapGReg {
	mut out := []XapGReg{}
	for nn in f.nouns {
		if t := nn.fields[k.via] {
			out << XapGReg{
				feature: f.name
				noun:    '${f.name}/${nn.name}'
				via:     k.via
				typ:     t
			}
		}
	}
	return out
}

fn xap_gc_frame_regs(f XapGFeature, fr XapGFrameUse) []XapGReg {
	mut out := []XapGReg{}
	if fr.via == '' {
		return out
	}
	for nn in f.nouns {
		if t := nn.fields[fr.via] {
			out << XapGReg{
				feature: f.name
				noun:    '${f.name}/${nn.name}'
				via:     fr.via
				typ:     t
			}
		}
	}
	return out
}

// xap_gc_frame_type_ok checks a frame registration's field type against the
// family's coordinate type (W3): geo → position; time → instant/interval;
// value → an ordered scalar (anything that is not a coordinate of the other
// two families — the type vocabulary is deliberately open).
fn xap_gc_frame_type_ok(family string, typ string) bool {
	return match family {
		'geo' { typ == 'geo-point' }
		'time' { typ == 'instant' || typ == 'interval' }
		else { typ != 'geo-point' && typ != 'instant' && typ != 'interval' }
	}
}

// xap_gc_scc finds strongly connected components of the ordering graph
// (Tarjan, recursive) — every ordering cycle lives in an SCC of size > 1 or a
// self-loop, so reporting per-SCC reports ALL cycle violations deterministically.
struct XapGTarjan {
mut:
	edges    map[string][]string
	index    map[string]int
	lowlink  map[string]int
	on_stack map[string]bool
	stack    []string
	counter  int
	sccs     [][]string
}

fn (mut t XapGTarjan) strongconnect(v string) {
	t.index[v] = t.counter
	t.lowlink[v] = t.counter
	t.counter++
	t.stack << v
	t.on_stack[v] = true
	mut nexts := t.edges[v].clone()
	nexts.sort()
	for w in nexts {
		if w !in t.index {
			t.strongconnect(w)
			if t.lowlink[w] < t.lowlink[v] {
				t.lowlink[v] = t.lowlink[w]
			}
		} else if t.on_stack[w] {
			if t.index[w] < t.lowlink[v] {
				t.lowlink[v] = t.index[w]
			}
		}
	}
	if t.lowlink[v] == t.index[v] {
		mut comp := []string{}
		for {
			w := t.stack.pop()
			t.on_stack[w] = false
			comp << w
			if w == v {
				break
			}
		}
		t.sccs << comp
	}
}

fn xap_gc_ordering_cycles(edges map[string][]string) [][]string {
	mut t := XapGTarjan{
		edges: edges.clone()
	}
	mut nodes := map[string]bool{}
	for k, vs in edges {
		nodes[k] = true
		for v in vs {
			nodes[v] = true
		}
	}
	mut keys := nodes.keys()
	keys.sort()
	for k in keys {
		if k !in t.index {
			t.strongconnect(k)
		}
	}
	mut out := [][]string{}
	for comp in t.sccs {
		if comp.len > 1 {
			mut c := comp.clone()
			c.sort()
			out << c
		} else if comp.len == 1 && comp[0] in edges[comp[0]] {
			out << comp // self-loop
		}
	}
	return out
}

// xap_gc_gate runs the W1–W6 compose-time well-formedness checks (§4) over the
// feature set and reports EVERY violation (never first-failure). W6 (bare-term
// resolvability) is structural — the ρ index is built by construction in
// xap_gc_grammar_doc, so it cannot be violated here.
fn xap_gc_gate(feats []XapGFeature) []XapGConflict {
	mut confs := []XapGConflict{}
	// membership indexes (qualified names + feature names)
	mut feat_set := map[string]bool{}
	mut verb_set := map[string]bool{}
	mut noun_set := map[string]bool{}
	mut vmap := map[string]XapGVerb{}
	for f in feats {
		feat_set[f.name] = true
		for v in f.verbs {
			verb_set['${f.name}/${v.name}'] = true
			vmap['${f.name}/${v.name}'] = v
		}
		for nn in f.nouns {
			noun_set['${f.name}/${nn.name}'] = true
		}
	}
	// W1 — feature-name uniqueness (one conflict per duplicated name)
	mut by_name := map[string]int{}
	for f in feats {
		by_name[f.name]++
	}
	mut w1_names := by_name.keys()
	w1_names.sort()
	for nm in w1_names {
		if by_name[nm] > 1 {
			confs << XapGConflict{
				code:   ':w1'
				at:     nm
				detail: '${by_name[nm]} distinct features named "${nm}" — feature names must be unique in a XAP'
			}
		}
	}
	// W2 — key compatibility (every registration onto one key name agrees on type)
	mut key_regs := map[string][]XapGReg{}
	for f in feats {
		for k in f.keys {
			regs := xap_gc_key_regs(f, k)
			if regs.len == 0 {
				confs << XapGConflict{
					code:   ':w2'
					at:     '${f.name}/${k.name}'
					detail: 'key "${k.name}" via="${k.via}" names no field of any ${f.name} noun'
				}
				continue
			}
			key_regs[k.name] << regs
		}
	}
	mut key_names := key_regs.keys()
	key_names.sort()
	for kn in key_names {
		mut types := []string{}
		for r in key_regs[kn] {
			if r.typ !in types {
				types << r.typ
			}
		}
		if types.len > 1 {
			types.sort()
			confs << XapGConflict{
				code:   ':w2'
				at:     kn
				detail: 'key "${kn}" registered with conflicting value types: ${types.join(' vs ')}'
			}
		}
	}
	// W3 — frame-registration validity (via names an existing field, typed to
	// the family's coordinate type)
	for f in feats {
		for fr in f.frames {
			if fr.via == '' {
				continue // a composite's join declaration — no registration
			}
			regs := xap_gc_frame_regs(f, fr)
			if regs.len == 0 {
				confs << XapGConflict{
					code:   ':w3'
					at:     '${f.name}: frame=${fr.family} via=${fr.via}'
					detail: 'frame registration via="${fr.via}" names no field of any ${f.name} noun'
				}
				continue
			}
			for r in regs {
				if !xap_gc_frame_type_ok(fr.family, r.typ) {
					confs << XapGConflict{
						code:   ':w3'
						at:     '${f.name}: frame=${fr.family} via=${fr.via}'
						detail: 'field "${fr.via}" of ${r.noun} has type "${r.typ}", not a ${fr.family} coordinate'
					}
				}
			}
		}
	}
	// W4 — rule consistency over the merged rule set (structured targets only;
	// prose-only rules are runtime-class and not statically checked)
	mut coverage := map[string][]XapGRule{} // '<verb>\x00<when>' → mandate/exclusion rules
	mut ordering_edges := map[string][]string{}
	for f in feats {
		uses_set := f.uses.clone()
		for r in f.rules {
			// scope reach: a structured target must be the rule's own feature's
			// grammar or (for composites) inside its uses set (§3 rule scoping)
			for tgt in [r.verb, r.after] {
				if tgt == '' {
					continue
				}
				owner := tgt.all_before('/')
				if owner != f.name && owner !in uses_set {
					confs << XapGConflict{
						code:   ':w4'
						at:     '${f.name}/${r.name}'
						detail: 'rule target "${tgt}" reaches outside ${f.name}\'s grammar and its uses set'
					}
				} else if tgt !in verb_set {
					confs << XapGConflict{
						code:   ':w4'
						at:     '${f.name}/${r.name}'
						detail: 'rule target "${tgt}" is not a verb of the composed grammar'
					}
				}
			}
			if r.kind in ['mandate', 'exclusion'] && r.verb != '' {
				coverage['${r.verb}\x00${r.when}'] << r
			}
			if r.kind == 'ordering' && r.verb != '' && r.after != '' {
				ordering_edges[r.after] << r.verb // `after` runs first
			}
			if r.kind == 'dependency' && r.requires != '' {
				if r.requires !in verb_set && r.requires !in noun_set && r.requires !in feat_set {
					confs << XapGConflict{
						code:   ':w4'
						at:     '${f.name}/${r.name}'
						detail: 'dependency target "${r.requires}" does not exist in the composed grammar'
					}
				}
			}
		}
	}
	mut cov_keys := coverage.keys()
	cov_keys.sort()
	for ck in cov_keys {
		rules := coverage[ck]
		mandates := rules.filter(it.kind == 'mandate')
		exclusions := rules.filter(it.kind == 'exclusion')
		if mandates.len > 0 && exclusions.len > 0 {
			verb := ck.all_before('\x00')
			when := ck.all_after('\x00')
			confs << XapGConflict{
				code:   ':w4'
				at:     verb
				detail: 'mandate "${mandates[0].feature}/${mandates[0].name}" and exclusion "${exclusions[0].feature}/${exclusions[0].name}" cover the same (verb "${verb}", when=${when}) pair'
			}
		}
	}
	for cyc in xap_gc_ordering_cycles(ordering_edges) {
		confs << XapGConflict{
			code:   ':w4'
			at:     cyc.join(' ')
			detail: 'ordering rules form a cycle over: ${cyc.join(', ')}'
		}
	}
	// W5 — derived-reference existence + §6 signature-weakening (W5-class)
	mut constituent_edges := map[string][]string{}
	for f in feats {
		for u in f.uses {
			if u !in feat_set {
				confs << XapGConflict{
					code:   ':w5'
					at:     f.name
					detail: 'composite "${f.name}" uses "${u}", which is not in the composed feature set'
				}
			}
		}
		for v in f.verbs {
			if v.constituents.len == 0 {
				continue
			}
			qname := '${f.name}/${v.name}'
			for c in v.constituents {
				if c !in verb_set {
					confs << XapGConflict{
						code:   ':w5'
						at:     qname
						detail: 'constituent "${c}" is not a verb of the composed grammar'
					}
				}
				constituent_edges[qname] << c
			}
			fef, fsc, fcq := xap_gc_verb_floor(v, vmap, 0)
			if xap_gc_effect_rank(v.effect) < fef {
				confs << XapGConflict{
					code:   ':w5'
					at:     qname
					detail: 'declared effect="${v.effect}" weakens the derived floor "${xap_gc_effect_of_rank(fef)}"'
				}
			}
			if v.scope != '' && xap_gc_scope_rank(v.scope) < fsc {
				confs << XapGConflict{
					code:   ':w5'
					at:     qname
					detail: 'declared scope="${v.scope}" weakens the derived floor "${xap_gc_scope_of_rank(fsc)}"'
				}
			}
			if v.consequence != '' && xap_gc_cons_rank(v.consequence) < fcq {
				confs << XapGConflict{
					code:   ':w5'
					at:     qname
					detail: 'declared consequence="${v.consequence}" weakens the derived floor "${xap_gc_cons_of_rank(fcq)}"'
				}
			}
		}
	}
	// a cyclic constituent graph can never derive a signature floor (§6)
	for cyc in xap_gc_ordering_cycles(constituent_edges) {
		confs << XapGConflict{
			code:   ':w5'
			at:     cyc.join(' ')
			detail: 'constituent declarations form a cycle over: ${cyc.join(', ')}'
		}
	}
	return confs
}

fn xap_gc_conflict_node(c XapGConflict) cx.Node {
	return xap_elem('conflict', [xap_attr('code', c.code), xap_attr('at', c.at),
		xap_attr('detail', c.detail)], [])
}

// xap_gc_grammar_doc builds the composed grammar `⊢ grammar.cxs` from a
// conflict-free feature set. Every collection is emitted in sorted order —
// composition is a pure function of the feature SET, so the document (and its
// Tier-1 hash) is identical for every enable order (§3.1 determinism).
fn xap_gc_grammar_doc(feats []XapGFeature) cx.Node {
	mut fs := feats.clone()
	fs.sort(a.name < b.name)
	mut vmap := map[string]XapGVerb{}
	for f in fs {
		for v in f.verbs {
			vmap['${f.name}/${v.name}'] = v
		}
	}
	// [features] — the input set (provenance root)
	mut feat_items := []cx.Node{}
	for f in fs {
		mut attrs := [xap_attr('name', f.name)]
		if f.version != '' {
			attrs << xap_attr('version', f.version)
		}
		if f.hash != '' {
			attrs << xap_attr('hash', f.hash)
		}
		feat_items << xap_elem('feature', attrs, [])
	}
	// [verbs] — qualified, with provenance + effective signature
	mut vkeys := vmap.keys()
	vkeys.sort()
	mut verb_items := []cx.Node{}
	mut bare := map[string][]string{} // bare term → qualified candidates
	for qk in vkeys {
		v := vmap[qk]
		mut attrs := [xap_attr('name', qk), xap_attr('feature', v.feature),
			xap_attr('effect', v.effect), xap_attr('scope', xap_gc_verb_scope(v, vmap, 0)),
			xap_attr('consequence', xap_gc_verb_consequence(v, vmap, 0))]
		mut items := []cx.Node{}
		if v.constituents.len > 0 {
			attrs << xap_attr_bool('derived', true)
			mut cs := v.constituents.clone()
			cs.sort()
			items << xap_elem('constituents', [], [xap_str(cs.join(' '))])
		}
		verb_items << xap_elem('verb', attrs, items)
		bare[v.name] << qk
	}
	// [nouns]
	mut nmap := map[string]XapGNoun{}
	for f in fs {
		for nn in f.nouns {
			nmap['${f.name}/${nn.name}'] = nn
		}
	}
	mut nkeys := nmap.keys()
	nkeys.sort()
	mut noun_items := []cx.Node{}
	for qk in nkeys {
		nn := nmap[qk]
		mut attrs := [xap_attr('name', qk), xap_attr('feature', nn.feature)]
		if nn.derived {
			attrs << xap_attr_bool('derived', true)
		}
		noun_items << xap_elem('noun', attrs, [])
	}
	// [rules] — scoped to their owning feature
	mut rule_items := []cx.Node{}
	mut rkeys := []string{}
	mut rmap := map[string]XapGRule{}
	for f in fs {
		for r in f.rules {
			qk := '${f.name}/${r.name}'
			rkeys << qk
			rmap[qk] = r
		}
	}
	rkeys.sort()
	for qk in rkeys {
		r := rmap[qk]
		rule_items << xap_elem('rule', [xap_attr('name', qk), xap_attr('feature', r.feature),
			xap_attr('kind', r.kind)], [])
	}
	// [frames] / [keys] — every registration listed (the join seams)
	mut frame_regs := map[string][]XapGReg{}
	for f in fs {
		for fr in f.frames {
			frame_regs[fr.family] << xap_gc_frame_regs(f, fr)
		}
	}
	mut frame_items := []cx.Node{}
	for fam in xap_gc_frame_families {
		mut regs := frame_regs[fam].clone()
		if regs.len == 0 {
			continue
		}
		regs.sort(a.sort_key() < b.sort_key())
		mut reg_items := []cx.Node{}
		for r in regs {
			reg_items << xap_elem('registration', [xap_attr('feature', r.feature),
				xap_attr('noun', r.noun), xap_attr('via', r.via)], [])
		}
		frame_items << xap_elem('frame', [xap_attr('family', fam)], reg_items)
	}
	mut key_regs := map[string][]XapGReg{}
	for f in fs {
		for k in f.keys {
			key_regs[k.name] << xap_gc_key_regs(f, k)
		}
	}
	mut key_names := key_regs.keys()
	key_names.sort()
	mut key_items := []cx.Node{}
	for kn in key_names {
		mut regs := key_regs[kn].clone()
		if regs.len == 0 {
			continue
		}
		regs.sort(a.sort_key() < b.sort_key())
		mut reg_items := []cx.Node{}
		for r in regs {
			reg_items << xap_elem('registration', [xap_attr('feature', r.feature),
				xap_attr('noun', r.noun), xap_attr('via', r.via)], [])
		}
		key_items << xap_elem('key', [xap_attr('name', kn), xap_attr('type', regs[0].typ)],
			reg_items)
	}
	// [bare-terms] — the precomputed ρ index (W6 total by construction)
	mut tkeys := bare.keys()
	tkeys.sort()
	mut term_items := []cx.Node{}
	for tk in tkeys {
		mut cands := bare[tk].clone()
		cands.sort()
		term_items << xap_elem('term', [xap_attr('name', tk), xap_attr('candidates', cands.join(' '))],
			[])
	}
	return xap_elem('grammar', [], [
		xap_elem('features', [], feat_items),
		xap_elem('verbs', [], verb_items),
		xap_elem('nouns', [], noun_items),
		xap_elem('rules', [], rule_items),
		xap_elem('frames', [], frame_items),
		xap_elem('keys', [], key_items),
		xap_elem('bare-terms', [], term_items),
	])
}

// [$xap:compose FEATURE …] — the enforcing face of the gate (§8.1): the
// composed [grammar …], or CXER4870 carrying EVERY [conflict …], or CXER4873
// for a non-[feature] argument. Zero args → the empty grammar (the §3.1 unit).
fn xap_compose_builtin(args []cx.Node) ?cx.Node {
	feats := xap_gc_load(args) or {
		return xap_gc_err(xap_err_feature_invalid, 'E_XAP_FEATURE_INVALID: ${err.msg()}',
			[], [])
	}
	confs := xap_gc_gate(feats)
	if confs.len > 0 {
		mut items := []cx.Node{}
		for c in confs {
			items << xap_gc_conflict_node(c)
		}
		return xap_gc_err(xap_err_compose_conflict, 'E_XAP_COMPOSE_CONFLICT: composition rejected with ${confs.len} conflict(s)',
			[], items)
	}
	return xap_gc_grammar_doc(feats)
}

// [$xap:compose-report FEATURE …] — the tooling face: never raises on
// conflicts; returns [compose-report ok=<bool> [conflict …]*]. Agreement law:
// compose raises iff this reports ok=false (both run xap_gc_gate). A
// non-[feature] argument still raises CXER4873 — that is an input error,
// not a composition conflict.
fn xap_compose_report_builtin(args []cx.Node) ?cx.Node {
	feats := xap_gc_load(args) or {
		return xap_gc_err(xap_err_feature_invalid, 'E_XAP_FEATURE_INVALID: ${err.msg()}',
			[], [])
	}
	confs := xap_gc_gate(feats)
	mut items := []cx.Node{}
	for c in confs {
		items << xap_gc_conflict_node(c)
	}
	return xap_elem('compose-report', [xap_attr_bool('ok', confs.len == 0)], items)
}

fn xap_gc_grammar_arg(n cx.Node) ?cx.Element {
	if n is cx.Element && n.name == 'grammar' {
		return n
	}
	return none
}

fn xap_gc_doc_has_verb(g cx.Element, qname string) bool {
	if vs := xap_gc_child(g, 'verbs') {
		for ve in xap_gc_children(vs, 'verb') {
			if xap_elem_attr(ve, 'name') == qname {
				return true
			}
		}
	}
	return false
}

// xap_gc_doc_verb finds a [verb] entry by qualified name in a composed grammar.
fn xap_gc_doc_verb(g cx.Element, qname string) ?cx.Element {
	if vs := xap_gc_child(g, 'verbs') {
		for ve in xap_gc_children(vs, 'verb') {
			if xap_elem_attr(ve, 'name') == qname {
				return ve
			}
		}
	}
	return none
}

// xap_gc_leaf_grants expands the N-COMPOSE-2 grant set (§8.2): the transitive
// LEAF (non-derived) constituents of a verb, following [constituents] through
// the grammar. A non-derived verb's set is itself. A constituent naming a verb
// absent from the grammar is required literally (fail-closed; unreachable for
// W5-gated grammars). The visited set is defense, not semantics — constituent
// cycles are W5-rejected at compose time. Sorted for deterministic denial
// order.
fn xap_gc_leaf_grants(g cx.Element, qname string) []string {
	mut out := []string{}
	mut visited := map[string]bool{}
	mut stack := [qname]
	for stack.len > 0 {
		name := stack.pop()
		if visited[name] {
			continue
		}
		visited[name] = true
		ve := xap_gc_doc_verb(g, name) or {
			if name !in out {
				out << name
			}
			continue
		}
		mut cs := []string{}
		if ce := xap_gc_child(ve, 'constituents') {
			cs = xap_gc_split_names(xap_gc_text_item(ce))
		}
		if cs.len == 0 {
			if name !in out {
				out << name
			}
			continue
		}
		for c in cs {
			stack << c
		}
	}
	out.sort()
	return out
}

fn xap_gc_doc_candidates(g cx.Element, term string) []string {
	if bt := xap_gc_child(g, 'bare-terms') {
		for te in xap_gc_children(bt, 'term') {
			if xap_elem_attr(te, 'name') == term {
				return xap_gc_split_names(xap_elem_attr(te, 'candidates'))
			}
		}
	}
	return []string{}
}

// xap_gc_narrow applies one §5.3 narrowing step: keep the candidates whose
// owning feature is in `owners`. A unique survivor resolves; a non-empty
// narrowing carries forward; an empty result means the step was not decisive
// and the prior candidate set stands.
fn xap_gc_narrow(cands []string, owners map[string]bool) []string {
	if owners.len == 0 {
		return cands
	}
	nar := cands.filter(owners[it.all_before('/')])
	if nar.len == 0 {
		return cands
	}
	return nar
}

// [$xap:resolve GRAMMAR TERM CONTEXT?] — ρ (§5). Qualified always wins;
// unique owner resolves; context narrows (focus → arg-nouns → present);
// surviving ambiguity is CXER4871 with candidates= (a value to prompt from,
// never a guess); zero candidates is CXER4872.
fn xap_resolve_builtin(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(xap_err_arg_invalid, 'E_XAP: resolve expects (grammar, term, context?)')
	}
	g := xap_gc_grammar_arg(args[0]) or {
		return mk_err(xap_err_arg_invalid, 'E_XAP: resolve expects a composed [grammar …] as its first argument')
	}
	term := xap_arg_name(args[1])
	if term == '' {
		return mk_err(xap_err_arg_invalid, 'E_XAP: resolve requires a non-empty verb term')
	}
	// §5 step 1 — qualified always wins (steps 2–4 never run)
	if term.contains('/') {
		if xap_gc_doc_has_verb(g, term) {
			return xap_str(term)
		}
		return xap_gc_err(xap_err_verb_unknown, 'E_XAP_VERB_UNKNOWN: no verb "${term}" in the composed grammar',
			[xap_attr('term', term)], [])
	}
	mut cands := xap_gc_doc_candidates(g, term)
	if cands.len == 0 {
		return xap_gc_err(xap_err_verb_unknown, 'E_XAP_VERB_UNKNOWN: no feature of the composed grammar defines "${term}"',
			[xap_attr('term', term)], [])
	}
	if cands.len == 1 {
		return xap_str(cands[0])
	}
	ctx := if args.len > 2 { args[2] } else { cx.Node(xap_elem('__cx_map__', [], [])) }
	// §5.3a — the feature owning the panel in focus
	focus := xap_map_get_str(ctx, 'focus')
	if focus != '' {
		mut fowners := map[string]bool{}
		fowners[focus] = true
		cands = xap_gc_narrow(cands, fowners)
		if cands.len == 1 {
			return xap_str(cands[0])
		}
	}
	// §5.3b — the feature(s) owning the nouns bound in the utterance's args
	if nlist := xap_map_get_node(ctx, 'nouns') {
		mut owners := map[string]bool{}
		for it in xap_gc_flatten(nlist) {
			qn := xap_arg_name(it)
			if qn.contains('/') {
				owners[qn.all_before('/')] = true
			}
		}
		cands = xap_gc_narrow(cands, owners)
		if cands.len == 1 {
			return xap_str(cands[0])
		}
	}
	// §5.3c — candidates whose features are not present on the surface drop
	if plist := xap_map_get_node(ctx, 'present') {
		mut owners := map[string]bool{}
		for it in xap_gc_flatten(plist) {
			fname := xap_arg_name(it)
			if fname != '' {
				owners[fname] = true
			}
		}
		cands = xap_gc_narrow(cands, owners)
		if cands.len == 1 {
			return xap_str(cands[0])
		}
	}
	// §5.4 — ambiguity is a value, not a guess
	cands.sort()
	return xap_gc_err(xap_err_verb_ambiguous, 'E_XAP_VERB_AMBIGUOUS: "${term}" has ${cands.len} candidates — disambiguate, never auto-pick',
		[xap_attr('term', term), xap_attr('candidates', cands.join(' '))], [])
}

// [$xap:grammar-hash GRAMMAR] — the Tier-1 content hash (hex) of the composed
// grammar under canonical form: the §3.1 equality oracle and the distribution
// spec's supply-chain witness. Same route as the store's doc identity.
fn xap_grammar_hash_builtin(args []cx.Node) ?cx.Node {
	if args.len < 1 {
		return mk_err(xap_err_arg_invalid, 'E_XAP: grammar-hash expects (grammar)')
	}
	g := xap_gc_grammar_arg(args[0]) or {
		return mk_err(xap_err_arg_invalid, 'E_XAP: grammar-hash expects a composed [grammar …]')
	}
	h := store_doc_hash(g) or {
		return mk_err(xap_err_arg_invalid, 'E_XAP: grammar-hash failed: ${err.msg()}')
	}
	return xap_str(h)
}

// ── bundled module source (the public cx-xap surface) ────────────────────────

const stdlib_src_xap = $embed_file('../stdlib/xap.cx').to_string()
