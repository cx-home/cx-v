@[has_globals]
module code

// stdlib_xap.v — native primitives backing the `cx-xap` orchestrator subsystem
// (spec/03-approved/xap/xap.md). cx-xap is its OWN bundled package (not cx-stdlib): the
// experience-layer composer over the cx-stdlib primitives.
//
// Surface split:
//   env-free  (xap_stdlib_builtin):      component / surface / panel  (pure constructors)
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
	reg := xap_reg()
	// Route by the intent VERB (items[0] = the `:verb` atom) to the component whose
	// `emits` declares it (#41); fall back to the first bound component for the
	// single-component demos.
	mut vname := ''
	if intent is cx.Element && intent.items.len > 0 {
		vname = xap_verb_name(intent.items[0])
	}
	mut bind := ''
	if vname != '' {
		for _, c in reg.components {
			if c.bind == '' {
				continue
			}
			for pat in xap_seq_items(c.emits) {
				if pat is cx.Element && pat.items.len > 0
					&& xap_verb_name(pat.items[0]) == vname {
					bind = c.bind
					break
				}
			}
			if bind != '' {
				break
			}
		}
	}
	if bind == '' {
		for _, c in reg.components {
			if c.bind != '' {
				bind = c.bind
				break
			}
		}
	}
	// §2.2 — the single PEP. Decide BEFORE any append: deny ⇒ failure channel,
	// commit nothing (CXER4850). Admit ⇒ proceed with the cascade.
	if !xap_pep_admits(rt, actor, vname, bind) {
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
	// the committed EVENT records the authority basis (the actor); journal it. An
	// anonymous emit (no opts.actor/session) logs the bare intent (back-compat).
	event := if actor != '' {
		cx.Node(xap_elem('event', [xap_attr('actor', actor)], [intent]))
	} else {
		intent
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
	// resolve the bind slice the same way emit does (route by verb to its component).
	reg := xap_reg()
	mut bind := ''
	for _, c in reg.components {
		if c.bind == '' {
			continue
		}
		for pat in xap_seq_items(c.emits) {
			if pat is cx.Element && pat.items.len > 0 && xap_verb_name(pat.items[0]) == vname {
				bind = c.bind
				break
			}
		}
		if bind != '' {
			break
		}
	}
	if bind == '' {
		for _, c in reg.components {
			if c.bind != '' {
				bind = c.bind
				break
			}
		}
	}
	// a principal actor is inherently authorized (the root); render it accountable.
	if actor != '' && xap_actor_kind(actor) == 'principal' {
		return xap_elem('why-allowed', [xap_attr('allowed', 'true')], [
			xap_elem('chain', [], []),
			xap_elem('accountable', [xap_attr('principal', actor)], []),
		])
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
				attrs: [xap_attr('name', vname)]
			}),
			cx.Node(cx.Element{
				name:  'slice'
				attrs: [xap_attr('path', bind)]
			}),
		]
	}
	store := if rt.authz != unsafe { nil } { rt.authz } else { &AuthzStore{} }
	decision := authz_decide(store, req, map[string]cx.Node{})
	if decision is cx.Element && decision.name == 'permit' {
		rooted := xap_elem_attr(decision, 'rooted-principal')
		// the via list = the deciding delegation ids; render their display elements.
		mut via_ids := map[string]bool{}
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

// ── bundled module source (the public cx-xap surface) ────────────────────────

const stdlib_src_xap = $embed_file('../stdlib/xap.cx').to_string()
