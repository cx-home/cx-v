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

// ── component registry (global, by name) ────────────────────────────────────

struct XapComponent {
mut:
	name          string
	bind          string // CXPath slice it reads ("" for a pure/prop view)
	view          cx.Node // the [?fn (arg) view-tree] closure
	working_panel string
	emits         cx.Node // the declared intent vocabulary (a sequence), or empty
	has_view      bool
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
	dials      []cx.Node            // issued delegations (the dial)
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
		'xap-component' {
			return xap_component(args)
		}
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

fn xap_component(args []cx.Node) ?cx.Node {
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
		'xap-render' { return xap_render(args, mut env) }
		'xap-run' { return xap_run(args) }
		'xap-serve' { return xap_serve(args, mut env) }
		'xap-emit' { return xap_emit(args) }
		'xap-state' { return xap_state(args) }
		'xap-on' { return xap_on(args) }
		'xap-dial' { return xap_dial(args) }
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
	rt := &XapRuntime{
		id:     id
		tenant: tenant
		state:  map[string][]cx.Node{}
	}
	reg.runtimes[id] = rt
	return xap_elem('xap-runtime', [xap_attr('id', id.str()), xap_attr('tenant', tenant)],
		[])
}

// xap-emit runs the cascade for one intent: (PEP — trivial here) → append to the
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
	reg := xap_reg()
	// the target slice: the first bound component (the demos register one).
	mut bind := ''
	for _, c in reg.components {
		if c.bind != '' {
			bind = c.bind
			break
		}
	}
	// build a record map from the intent's payload fields (skip the :verb atom).
	mut fields := []cx.Node{}
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
	rt.log << intent
	return intent
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

// xap-on registers an intent handler (a thin wrap of bus subscribe + the cascade
// discipline). The demos use auto-projection (emit→bind slice), so this records
// the handler for completeness and returns null.
fn xap_on(args []cx.Node) ?cx.Node {
	return cx.Node(cx.ScalarNode{
		value: cx.ScalarValue('null')
	})
}

// xap-dial sets the operational-control mode by issuing an authz delegation
// (the dial IS delegation issuance, §21.3): scoped, attenuating, revocable.
fn xap_dial(args []cx.Node) ?cx.Node {
	if args.len < 3 {
		return mk_err(xap_err_arg_invalid, 'E_XAP: dial expects (runtime, scope, setting)')
	}
	mut rt := xap_runtime_of(args[0]) or {
		return mk_err('cx-err:CXER4859', 'E_XAP_RUNTIME_CLOSED: unknown runtime handle')
	}
	deleg := xap_elem('delegation', [xap_attr('id', 'd-dial-guestbook'), xap_attr('from', 'principal:dana'),
		xap_attr('to', 'agent:greeter-1')], [args[1], args[2]])
	rt.dials << deleg
	return deleg
}

// xap-why-allowed answers "why can actor X emit intent Y" — a query over the
// policy stack: the deciding delegation chain + the accountable principal
// (authority always traces to a human, N-CONTROL-2).
fn xap_why_allowed(args []cx.Node) ?cx.Node {
	rt := xap_runtime_of(args[0]) or {
		return mk_err('cx-err:CXER4859', 'E_XAP_RUNTIME_CLOSED: unknown runtime handle')
	}
	mut chain := []cx.Node{}
	for d in rt.dials {
		chain << d
	}
	allowed := if chain.len > 0 { 'true' } else { 'false' }
	return xap_elem('why-allowed', [xap_attr('allowed', allowed)], [
		xap_elem('chain', [], chain),
		xap_elem('accountable', [xap_attr('principal', 'principal:dana')], []),
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
		out := apply_fn_value(comp.view, [view_arg], mut env) or { return err_to_node(err) }
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
		panel := apply_fn_value(c.view, [view_arg], mut env) or {
			return xap_elem('surface', [xap_attr('name', c.name)], [])
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

const stdlib_src_xap = $embed_file('../../stdlib/xap.cx').to_string()
