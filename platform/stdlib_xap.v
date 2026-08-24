@[has_globals]
module platform
import code {
	err_diagnostic,
	Closure,
	MatchEnv,
	apply_fn_value,
	cx_mod_select,
	err_to_node,
	fire_raise_observe,
	invoke_closure,
	is_err_value,
	is_sequence_wrapper,
	iterate,
	mk_err,
	render_canonical,
	resolve_closure,
	unwrap_single_item,
}

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
const xap_err_view_failed = 'cx-err:CXER4863' // E_XAP_VIEW_FAILED (render-time view failure, §3.5)
const xap_err_cascade_fault = 'cx-err:CXER4860' // E_XAP_CASCADE_FAULT (journal write failure mid-cascade, §2.3/§3.1.1)

// ── component registry (global, by name) ────────────────────────────────────

// XapAffinity is one declared [affinity when=… class=… rank=…] clause —
// the §19 context-affinity metadata, colocated on the component (§3.2,
// #535 owner ruling 2026-07-21). `when` is a CXPath predicate over the
// [context …] projection; `class` the §20.1 context-class the ramp keys
// on; `rank` the static tie-break (default = declaration order).
struct XapAffinity {
mut:
	when_path string
	class     string
	rank      int
}

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
	affinity      []XapAffinity // §3.2 context-affinity declarations (#535)
	// §5 `reduce` — fold-side compaction (#606, owner ruling b): when the
	// bind slice exceeds reduce_window detail records, the oldest evict
	// through the pure reducer into the slice's single summary record.
	// Captured at declaration (#40 discipline, like the view).
	reduce_window  int
	reduce_closure Closure
	has_reduce     bool
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
	// #25 Tier-2 coordination rides the FABRIC TRANSIENT PLANE (#531 P2,
	// fabric.md §12: one transient-channel mechanism on the platform, not
	// two): a lazily-opened per-runtime embedded fabric over a mem:// journal
	// carries the latest-wins channels. NOT journaled (the durable plane is
	// untouched), NOT PEP-gated, out of audit (§3.2) — behavior unchanged
	// from the retired rt.coord map.
	coord_fab     cx.Node
	has_coord_fab bool
	dials      []cx.Node            // issued delegations (the dial) — display elements
	authz      &AuthzStore = unsafe { nil } // the runtime's authority store (the real PEP, §2.2)
	shell_dir  string               // D3 web bridge: dir holding layout.html + static/
	// #567: the shell's mount geometry, learned at GET / splice time —
	// surface name → the mount element's id / tag, so POST fragments and
	// control hx-targets swap against the SHELL's ids (any mount, not the
	// D3 guestbook literal). Defaults ('<name>-panel' / 'main') apply when
	// no shell has been spliced yet (self-contained fallback page).
	panel_ids  map[string]string
	panel_tags map[string]string
	grammar    cx.Element           // the attached composed grammar (§8.2 runtime integration)
	has_grammar bool                // set by xap-run {grammar: G}; switches on §5 resolution
	                                // + §6 N-COMPOSE-2 at the emit PEP
	// §4.2 (#865, R8.1–R8.3) — the deriver bindings from run assembly:
	// qualified derived noun → bound deriver name. Assembly refuses
	// (CXER4875) unless every derived=true noun of the attached grammar is
	// bound exactly once; [$xap:derive] commits against this map as
	// `actor: deriver:<name>` through the ordinary envelope/fold path.
	derivers   map[string]string
	// §3.6/§19 context→composition resolver (#535). resolver_kind is
	// 'scripted' (the default — the deterministic resolver-default fold
	// over declared §3.2 context-affinity rules, ramp-gated) or 'closure'
	// (a CX closure captured at run time, #40-style, so it stays
	// invocable wherever resolve runs). The resolver PROPOSES; the entry
	// (xap_resolve_context) owns the governance — proposal validation,
	// §20.2 tier demotion, the journaled decision with :reason (§4.5:
	// auditable, never authoritative).
	resolver_kind        string = 'scripted'
	resolver_closure     Closure
	has_resolver_closure bool
	// a [scripted-resolver …] value from [$xap:resolver-default $rules]
	// passed as {resolver: …}: the scripted fold runs over THESE rules
	// instead of the registry's component declarations.
	scripted_comps []string
	scripted_rules []XapAffinity
	has_scripted_rules bool
	// §3.1.1 durable journal binding (#582): every cascade commit publishes
	// the uniform [event …] envelope to this stream BEFORE folding (append
	// failure = CXER4860, nothing folds); run re-folds the stream at boot.
	// journal_remote distinguishes the attribution lane: a direct journal
	// handle carries the PEP-resolved {actor, authority}; a fabric session's
	// attribution is the proven session principal (§4.8), the PEP actor
	// rides in the envelope.
	journal_fab      cx.Node
	journal_stream   string
	journal_remote   bool
	has_journal_bind bool
	// #594: monotone state version — bumped on every fold (the single
	// central mutation point). The serve layer's render cache keys on it:
	// a render computed at seq N serves every request until seq moves.
	commit_seq u64
	// §3.1.1 fold checkpoints (#595): derived-state persistence. journal_seq
	// tracks the last journal seq applied to this fold (from publish
	// receipts on the live path, entry seqs on replay); every ckpt_every
	// committed events the fold persists to ckpt_store as
	// [checkpoint stream=… seq=…] under the alias
	// xap-checkpoint-<tenant>-<stream>. Derived, never authority.
	ckpt_store  cx.Node
	ckpt_every  u64
	has_ckpt    bool
	journal_seq u64
	ckpt_last   u64
	// #604: one checkpoint persist in flight per runtime — the commit path
	// only snapshots and dispatches; the store I/O runs off-thread.
	ckpt_inflight bool
	// #606 fold-side compaction: per-bind summary records (a slice with a
	// declared §5 reduce keeps its most-recent `window` detail records;
	// older ones live folded into summaries[bind]). Every slice read
	// composes summary + detail via xap_slice_view.
	summaries map[string]cx.Node
	// #609 changed-panel SSE: the commit_seq at each bind's last change —
	// a delta frame carries only panels whose bind moved past the
	// subscriber's high-water mark.
	bind_seq map[string]u64
	// #606 log compaction (the run-level `log-reduce` opt): same mechanism
	// over rt.log; log readers (governance folds included) go through
	// xap_log_view. Absent = unbounded (today).
	log_reduce_window  int
	log_reduce_closure Closure
	has_log_reduce     bool
	log_summary        cx.Node
	has_log_summary    bool
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
		'xap-instantiate' {
			return xap_instantiate_builtin(args)
		}
		'xap-cohesion' {
			return xap_cohesion_builtin(args)
		}
		'xap-resolver-default' {
			return xap_resolver_default_builtin(args)
		}
		else {
			return none
		}
	}
}

// xap_resolver_default_builtin — [$xap:resolver-default $rules] (§3.6,
// #535): PURE — validated rules in, the scripted resolver out as a
// first-class VALUE ([scripted-resolver [affinity component=… when=…
// class=… rank=…]…]) that [$xap:run {resolver: …}] accepts. Each rule
// here carries component= explicitly (the standalone form has no
// component declaration to ride on); validation is the same as the §3.2
// declaration path — a malformed rule refuses now.
fn xap_resolver_default_builtin(args []cx.Node) ?cx.Node {
	if args.len < 1 {
		return mk_err(xap_err_arg_invalid,
			'E_XAP: resolver-default expects a sequence of [affinity component=… when=… class=… rank=…] rules (xap.md §3.6)')
	}
	mut items := []cx.Node{}
	for i, it in xap_seq_items(args[0]) {
		a := xap_parse_affinity(it, i) or {
			return mk_err(xap_err_arg_invalid, 'E_XAP: resolver-default: ${err.msg()}')
		}
		comp := if it is cx.Element { it.attr('component') } else { '' }
		if comp == '' {
			return mk_err(xap_err_arg_invalid,
				'E_XAP: resolver-default rules carry component=… (the standalone form has no component declaration to ride on; xap.md §3.6)')
		}
		items << cx.Node(xap_elem('affinity', [
			xap_attr('component', comp),
			xap_attr('when', a.when_path),
			xap_attr('class', a.class),
			xap_attr('rank', a.rank.str()),
		], []))
	}
	return cx.Node(xap_elem('scripted-resolver', [], items))
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
	// §3.2 context-affinity declarations (#535) — validated NOW (a
	// malformed rule refuses at declaration, never sits silently inert).
	if av := xap_map_get_node(opts, 'affinity') {
		for i, it in xap_seq_items(av) {
			a := xap_parse_affinity(it, i) or {
				return mk_err(xap_err_arg_invalid, 'E_XAP_COMPONENT_INVALID: ${err.msg()}')
			}
			comp.affinity << a
		}
	}
	// §5 `reduce` (#606) — validated + captured at declaration: a malformed
	// compaction declaration refuses NOW, never silently truncates later.
	if rv := xap_map_get_node(opts, 'reduce') {
		w := xap_map_get_str(rv, 'window').int()
		if w < 1 {
			return mk_err(xap_err_arg_invalid,
				'E_XAP_COMPONENT_INVALID: reduce needs window: ≥ 1 (the detail records kept; older evict through the reducer — xap.md §5)')
		}
		rfn := xap_map_get_node(rv, 'fn') or {
			return mk_err(xap_err_arg_invalid,
				'E_XAP_COMPONENT_INVALID: reduce needs fn: (the pure (summary-or-absence, evicted-record) → summary reducer — xap.md §5)')
		}
		rcl := resolve_closure(rfn, env) or {
			return mk_err(xap_err_arg_invalid,
				'E_XAP_COMPONENT_INVALID: reduce fn: does not resolve to a callable')
		}
		comp.reduce_window = w
		comp.reduce_closure = rcl
		comp.has_reduce = true
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
	mut attrs := [xap_attr('name', sname)]
	// opts.reason (#535): a resolver proposal must carry its :reason —
	// stamping it here keeps the resolver-author idiom one call
	// ([$xap:surface name panels {reason: …}]) instead of a hand-built
	// element. Other opts keys remain reserved.
	if args.len > 2 {
		reason := xap_map_get_str(args[2], 'reason')
		if reason != '' {
			attrs << xap_attr('reason', reason)
		}
	}
	return xap_elem('xap-surface', attrs, [args[1]])
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
		'xap-run' { return xap_run(args, mut env) }
		'xap-resolve' {
			// §3.6 shape dispatch (#535): a runtime-handle FIRST argument is
			// the context→composition entry (env-aware — it applies the
			// configured resolver closure). Any other first-arg shape falls
			// through (none) to the env-free §8.1 ρ term-resolution path.
			if args.len > 0 {
				if rt := xap_runtime_of(args[0]) {
					mut mrt := unsafe { rt }
					return xap_resolve_context(mut mrt, args, mut env)
				}
			}
			return none
		}
		'xap-resolve-respond' { return xap_resolve_respond(args) }
		'xap-serve' { return xap_serve(args, mut env) }
		'xap-host' { return xap_host(args, mut env) }
		'xap-host-push' { return xap_host_push(args, mut env) }
		'xap-emit' { return xap_emit(args, mut env) }
		'xap-derive' { return xap_derive(args, mut env) }
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

// ── §3.6 context→composition resolve (#535) ─────────────────────────────────

// xap_tier_effective maps a requested placement to the §20.2 tier the
// entry GRANTS: the stakes gate, not a confidence gate — a resolver
// proposal never seizes the foreground (T0/T1 are guardian/decision-
// blocked machinery, not resolver territory), so :foreground demotes to
// T2 (foreground-PROPOSE — inline, encountered on look, never modal),
// :peripheral is T3 (the default posture), :queued is T4. Returns
// (effective, requested-name).
fn xap_tier_effective(opts cx.Node) (string, string) {
	req := xap_map_get_str(opts, 'tier')
	name := req.trim_left(':')
	return match name {
		'foreground', 'T0', 'T1', 'T2' { 'T2', name }
		'queued', 'digest', 'T4' { 'T4', name }
		'', 'peripheral', 'T3' { 'T3', name }
		else { 'T3', name }
	}
}

// xap_parse_affinity validates one [affinity when=… class=… rank=…]
// clause (§3.2, #535). The `when` CXPath must PARSE at declaration time —
// a malformed rule refuses now (CXER4852), never sits silently inert.
// `rank` defaults to 1000000+idx so declared ranks (small ints) win and
// undeclared ones keep declaration order.
fn xap_parse_affinity(it cx.Node, idx int) !XapAffinity {
	if !(it is cx.Element && it.name == 'affinity') {
		return error('affinity declarations are [affinity when=<CXPath> class=<atom> rank=<int>?] elements (xap.md §3.2)')
	}
	e := it as cx.Element
	w := e.attr('when')
	cl := e.attr('class').trim_left(':')
	if w == '' || cl == '' {
		return error('an [affinity] clause requires when=<CXPath> and class=<context-class atom> (xap.md §3.2)')
	}
	joiner := if w.starts_with('/') || w.starts_with('@') || w.starts_with('.') { '' } else { '/' }
	cx.parse_program('\$__cxaff__${joiner}${w}') or {
		return error('affinity when="${w}" is not a CXPath expression: ${err.msg()}')
	}
	mut rank := 1000000 + idx
	rs := e.attr('rank')
	if rs != '' {
		rank = rs.int()
	}
	return XapAffinity{
		when_path: w
		class:     cl
		rank:      rank
	}
}

// xap_affinity_matches evaluates a rule's `when` CXPath against the
// [context …] projection (wrapped in an envelope so the rule addresses
// the context ELEMENT by name — `context[@focus='orders']`, or deeper
// `context/deadline`). A non-empty result = candidate. An eval fault
// propagates loudly as the err it is.
fn xap_affinity_matches(ctx cx.Node, when_path string, mut env MatchEnv) !bool {
	envl := cx.Node(cx.Element{ name: '__cxaff__', items: [ctx] })
	res := cx_mod_select([envl, cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(when_path)
		data_type: cx.ScalarType.string_type
	})], mut env)
	if res is cx.Element {
		if is_err_value(res) {
			return error('affinity when="${when_path}": ${err_diagnostic(res)}')
		}
		return res.items.len > 0
	}
	return false
}

// xap_ramp_level computes the §20.1 trust-ramp level for (capability ×
// context-class). Two inputs, per the spec'd model:
//   1. the MANUAL PIN — an override grant issued through the dial (§21.3,
//      one mechanism): a delegation at scope `ramp/<comp>/<class>` (most
//      specific) or `ramp/<comp>`, whose [setting level=N] pins the
//      level; the LAST matching dial wins (later dials adjust earlier
//      ones). A pin OVERRIDES the fold outright — it is the principal's
//      explicit grant.
//   2. the deterministic FOLD over journaled surfacing outcomes (#553):
//      each [resolution-response surface=S response=R] event attributes R
//      to the (component × class) candidates of the most recent prior
//      [resolved outcome=composed surface=S] decision. Scoring is
//      asymmetric — slow to gain, fast to lose (§20.1):
//        acted-on           streak+1; level = max(level, min(3, streak/2))
//                           (two CONSECUTIVE acted-ons per step); clears a
//                           standing suppression (the principal re-engaged)
//        glanced-dismissed  streak=0; level-1 (floor 0)
//        ignored            streak=0 (no level change)
//        suppressed         sticky level 0 ("don't show me this") until a
//                           later acted-on or a pin
//      New capabilities have no history → level 0 = summon-only, §20.1's
//      conservative posture; the bootstrap is a summon (opts.summon) or a
//      pin, whose surfacings then accumulate organic responses.
fn xap_ramp_level(rt &XapRuntime, comp string, class string) int {
	specific := 'ramp/${comp}/${class}'
	general := 'ramp/${comp}'
	mut pin := -1
	mut have_specific := false
	for d in rt.dials {
		if d is cx.Element && d.name == 'delegation' {
			mut scope := ''
			mut setting_level := -1
			for c in d.items {
				if c is cx.Element {
					if c.name == 'scope' && c.items.len > 0 {
						scope = xap_verb_name(c.items[0])
					}
					if c.name == 'setting' {
						ls := c.attr('level')
						if ls != '' {
							setting_level = ls.int()
						}
					}
				}
			}
			if setting_level < 0 {
				continue
			}
			if scope == specific {
				pin = setting_level
				have_specific = true
			} else if scope == general && !have_specific {
				pin = setting_level
			}
		}
	}
	if pin >= 0 {
		return pin
	}
	// the fold (chronological walk of the demo journal)
	key := '${comp}/${class}'
	mut level := 0
	mut streak := 0
	mut suppressed := false
	mut surface_cands := map[string][]string{}
	for ev in xap_log_view(rt) {
		if ev is cx.Element {
			if ev.name == 'resolved' && ev.attr('outcome') == 'composed' {
				sname := ev.attr('surface')
				mut cands := []string{}
				for c in ev.items {
					if c is cx.Element && c.name == 'candidate' {
						cands << c.attr('component') + '/' + c.attr('class')
					}
				}
				surface_cands[sname] = cands
			} else if ev.name == 'resolution-response' {
				sname := ev.attr('surface')
				if key !in (surface_cands[sname] or { []string{} }) {
					continue
				}
				match ev.attr('response') {
					'acted-on' {
						streak++
						suppressed = false
						cand := streak / 2
						if cand > level {
							level = if cand > 3 { 3 } else { cand }
						}
					}
					'glanced-dismissed' {
						streak = 0
						if level > 0 {
							level--
						}
					}
					'ignored' {
						streak = 0
					}
					'suppressed' {
						streak = 0
						level = 0
						suppressed = true
					}
					else {}
				}
			}
		}
	}
	if suppressed {
		return 0
	}
	return level
}

// xap_scripted_propose is resolver-default's fold (§3.6, #535): filter
// (when matches context) → gate (ramp level ≥2 for inclusion, ≥3 when
// the granted tier is T2) → rank → compose one [xap-surface …] with a
// GENERATED deterministic reason, or the absence channel. `comps`/`rules`
// are parallel arrays — either the runtime's pinned resolver-default
// rules or the registry's component declarations (collected by the
// caller in declaration order).
fn xap_scripted_propose(rt &XapRuntime, ctx cx.Node, tier string, summon string, comps []string, rules []XapAffinity, mut env MatchEnv) !cx.Node {
	need := if tier == 'T2' { 3 } else { 2 }
	mut cand_comps := []string{}
	mut cand_rules := []XapAffinity{}
	mut cand_levels := []int{}
	if summon != '' {
		// §20.1 level 0 IS summon-only: an explicit summon composes the
		// named capability regardless of ramp level or when-match — the
		// principal asked for it. Its class (for response attribution) is
		// the component's first declared affinity class, or 'summoned'.
		mut cl := 'summoned'
		mut rank := 0
		for i, a in rules {
			if comps[i] == summon {
				cl = a.class
				rank = a.rank
				break
			}
		}
		cand_comps << summon
		cand_rules << XapAffinity{
			when_path: '(summoned)'
			class:     cl
			rank:      rank
		}
		cand_levels << xap_ramp_level(rt, summon, cl)
	} else {
		for i, a in rules {
			comp := comps[i]
			if comp in cand_comps {
				continue // first matching+passing clause per component wins
			}
			if !xap_affinity_matches(ctx, a.when_path, mut env)! {
				continue
			}
			lvl := xap_ramp_level(rt, comp, a.class)
			if lvl < need {
				continue
			}
			cand_comps << comp
			cand_rules << a
			cand_levels << lvl
		}
	}
	if cand_comps.len == 0 {
		return cx.Node(cx.Element{ name: code.seq_marker_name })
	}
	// stable rank sort (declared rank asc; insertion order breaks ties —
	// insertion sort keeps it stable and the sets are small)
	mut order := []int{len: cand_comps.len, init: index}
	for i in 1 .. order.len {
		mut j := i
		for j > 0 && cand_rules[order[j - 1]].rank > cand_rules[order[j]].rank {
			order[j - 1], order[j] = order[j], order[j - 1]
			j--
		}
	}
	mut panels := []cx.Node{cap: order.len}
	mut cands := []cx.Node{cap: order.len}
	mut reasons := []string{cap: order.len}
	for oi in order {
		panels << xap_elem('xap-panel', [xap_attr('component', cand_comps[oi])],
			[cx.Node(xap_elem('__cx_map__', [], []))])
		// calibration metadata (#553): the entry relocates [candidate …]
		// children from the proposal onto the journaled [resolved …] event
		// so responses attribute per (component × class).
		cands << cx.Node(xap_elem('candidate', [
			xap_attr('component', cand_comps[oi]),
			xap_attr('class', cand_rules[oi].class),
		], []))
		reasons << '${cand_comps[oi]}: affinity :${cand_rules[oi].class} matched ${cand_rules[oi].when_path} (ramp level ${cand_levels[oi]})'
	}
	prefix := if summon != '' { 'summoned: ' } else { 'scripted: ' }
	reason := prefix + reasons.join('; ')
	mut items := []cx.Node{}
	items << cx.Node(cx.Element{ name: code.seq_marker_name, items: panels })
	items << cands
	return cx.Node(xap_elem('xap-surface', [
		xap_attr('name', if summon != '' { summon } else { 'scripted' }),
		xap_attr('reason', reason),
	], items))
}

// xap_scripted_registry_rules collects the registry's component affinity
// declarations (declaration order) as the parallel comps/rules arrays the
// scripted fold consumes.
fn xap_scripted_registry_rules() ([]string, []XapAffinity) {
	reg := xap_reg()
	mut comps := []string{}
	mut rules := []XapAffinity{}
	for name, c in reg.components {
		for a in c.affinity {
			comps << name
			rules << a
		}
	}
	return comps, rules
}

// xap_resolve_context is the §3.6 entry: ask the runtime's configured
// resolver to compose a surface for $context. The RESOLVER proposes; this
// entry owns the governance for every resolver kind (§4.5 — auditable,
// never authoritative): proposal-shape validation, the required :reason,
// §20.2 tier demotion, and the journaled decision event. Returns the
// composed [xap-surface …] or the ABSENCE channel when nothing meets
// threshold (both outcomes journal).
//
// Closure contract (documented in stdlib/xap.cx): the resolver closure is
// applied as ($context $opts) and returns either the absence channel or
// an [xap-surface …] proposal carrying reason=… (build it with
// [$xap:surface] and stamp the reason attr; a missing reason refuses —
// §19 requires the decision auditable).
fn xap_resolve_context(mut rt XapRuntime, args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 2 {
		return mk_err(xap_err_arg_invalid,
			'E_XAP: resolve (context→composition, §3.6) expects (runtime, context, opts?)')
	}
	ctx := args[1]
	if !(ctx is cx.Element) {
		return mk_err(xap_err_arg_invalid,
			'E_XAP: resolve (§3.6) argument 2 is the [context …] projection element')
	}
	opts := if args.len > 2 { args[2] } else { xap_elem('__cx_map__', [], []) }
	tier, requested := xap_tier_effective(opts)
	via := if rt.has_resolver_closure { 'closure' } else { 'scripted' }
	// ── judgment (pluggable) ────────────────────────────────────────────
	proposal := if rt.has_resolver_closure {
		invoke_closure(rt.resolver_closure, [ctx, opts], mut env) or { err_to_node(err) }
	} else {
		// :scripted — resolver-default's deterministic fold (§3.6) over
		// either the runtime's pinned rules ([$xap:resolver-default …]
		// passed as {resolver: …}) or the registry's §3.2 component
		// affinity declarations.
		comps, rules := if rt.has_scripted_rules {
			rt.scripted_comps, rt.scripted_rules
		} else {
			xap_scripted_registry_rules()
		}
		// opts.summon (#553): an explicit summon of a named capability —
		// §20.1 level 0's own semantics, and the organic bootstrap for the
		// response fold (a fresh capability can be summoned, responded to,
		// and thereby promoted without a pin).
		xap_scripted_propose(rt, ctx, tier, xap_map_get_str(opts, 'summon'), comps, rules, mut env) or {
			mk_err(xap_err_arg_invalid, 'E_XAP: scripted resolve: ${err.msg()}')
		}
	}
	// ── governance (fixed, resolver-independent) ────────────────────────
	if proposal is cx.Element && is_err_value(proposal) {
		return proposal // the resolver faulted; propagate per §9.2
	}
	if is_sequence_wrapper(proposal) && (proposal as cx.Element).items.len == 0 {
		rt.log << cx.Node(xap_elem('resolved', [
			xap_attr('via', via),
			xap_attr('tier', tier),
			xap_attr('outcome', 'below-threshold'),
			xap_attr('reason', 'nothing met threshold for this context'),
		], []))
		return cx.Node(cx.Element{ name: code.seq_marker_name })
	}
	surface := unwrap_single_item(proposal)
	if !(surface is cx.Element && (surface.name == 'xap-surface' || surface.name == 'surface')) {
		return mk_err(xap_err_surface,
			'E_XAP_SURFACE_INVALID: a resolver proposal is an [xap-surface …] (build it with [\$xap:surface]) or the absence channel; got a different shape')
	}
	reason := (surface as cx.Element).attr('reason')
	if reason == '' {
		return mk_err(xap_err_surface,
			'E_XAP_SURFACE_INVALID: a resolver proposal must carry reason=… — the decision is journaled and auditable (xap.md §19); stamp the attr on the proposed surface')
	}
	mut ev_attrs := [
		xap_attr('via', via),
		xap_attr('tier', tier),
		xap_attr('outcome', 'composed'),
		xap_attr('reason', reason),
		xap_attr('surface', (surface as cx.Element).attr('name')),
	]
	if requested != '' && requested != tier {
		// the §20.2 demotion is itself auditable
		ev_attrs << xap_attr('requested', requested)
	}
	// Relocate [candidate component=… class=…] children from the proposal
	// onto the journaled decision (#553): they are CALIBRATION metadata —
	// the response fold joins [resolution-response] events to them — not
	// render content. Scripted proposals carry them by construction; a
	// closure resolver MAY stamp them for the same attribution.
	mut se := surface as cx.Element
	mut ev_items := []cx.Node{}
	mut kept := []cx.Node{cap: se.items.len}
	for c in se.items {
		if c is cx.Element && c.name == 'candidate' {
			ev_items << c
		} else {
			kept << c
		}
	}
	se.items = kept
	rt.log << cx.Node(xap_elem('resolved', ev_attrs, ev_items))
	// The GRANTED placement travels with the surface — the renderer reads
	// it for foreground/periphery placement (§3.1 render context), and a
	// requested-vs-granted demotion is observable on the value itself.
	mut sattrs := []cx.Attribute{cap: se.attrs.len + 1}
	for a in se.attrs {
		if a.name != 'tier' {
			sattrs << a
		}
	}
	sattrs << xap_attr('tier', tier)
	se.attrs = sattrs
	return cx.Node(se)
}

// xap_resolve_respond — [$xap:resolve-respond $rt $surface-name $response]
// (#553; the §20.1 recording surface): journals the principal's response
// to a surfacing as a [resolution-response surface=… response=…] event —
// the ramp fold's second input. Responses are the closed §20.1 vocabulary:
// :acted-on / :glanced-dismissed / :ignored / :suppressed. Returns null
// (unit). The event journals even when no [resolved] decision matches the
// surface name yet — the fold simply attributes nothing for it (an
// unmatched response is inert, not an error: hosts may record responses
// asynchronously of decision replay).
fn xap_resolve_respond(args []cx.Node) ?cx.Node {
	if args.len < 3 {
		return mk_err(xap_err_arg_invalid,
			'E_XAP: resolve-respond expects (runtime, surface-name, response-atom) — responses are :acted-on / :glanced-dismissed / :ignored / :suppressed (xap.md §20.1)')
	}
	mut rt := xap_runtime_of(args[0]) or {
		return mk_err('cx-err:CXER4859', 'E_XAP_RUNTIME_CLOSED: unknown runtime handle')
	}
	sname := xap_arg_name(args[1])
	resp := xap_verb_name(args[2]).trim_left(':')
	if resp !in ['acted-on', 'glanced-dismissed', 'ignored', 'suppressed'] {
		return mk_err(xap_err_arg_invalid,
			'E_XAP: resolve-respond response must be :acted-on, :glanced-dismissed, :ignored, or :suppressed (xap.md §20.1); got "${resp}"')
	}
	rt.log << cx.Node(xap_elem('resolution-response', [
		xap_attr('surface', sname),
		xap_attr('response', resp),
	], []))
	return cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(cx.NullValue{})
		data_type: cx.ScalarType.null_type
	})
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
// xap_name_items flattens a sequence/array value to its scalar/text leaf
// names (the dual of xap_seq_items, whose leaves are ELEMENTS — string
// items would vanish through it).
fn xap_name_items(n cx.Node) []string {
	if n is cx.SequenceNode {
		mut out := []string{}
		for it in n.items {
			out << xap_name_items(it)
		}
		return out
	}
	if n is cx.ArrayNode {
		mut out := []string{}
		for it in n.items {
			out << xap_name_items(it)
		}
		return out
	}
	if n is cx.Element {
		if n.name == '__cx_seq__' || n.name == '__cx_arr__' {
			mut out := []string{}
			for it in n.items {
				out << xap_name_items(it)
			}
			return out
		}
		return []string{}
	}
	s := xap_arg_name(n).trim_space()
	if s == '' {
		return []string{}
	}
	return [s]
}

// xap_grammar_derived_nouns reads the derived=true nouns off an attached
// composed grammar (the §8 projection): qualified noun name → its [from …]
// reference list (the read-authority envelope, §4.2).
fn xap_grammar_derived_nouns(gram cx.Element) map[string][]string {
	mut out := map[string][]string{}
	nouns_el := xap_gc_child(gram, 'nouns') or { return out }
	for ne in xap_gc_children(nouns_el, 'noun') {
		if xap_elem_attr(ne, 'derived') != 'true' {
			continue
		}
		qn := xap_elem_attr(ne, 'name')
		if qn == '' {
			continue
		}
		mut refs := []string{}
		if fe := xap_gc_child(ne, 'from') {
			for it in fe.items {
				r := xap_arg_name(it).trim_space()
				if r != '' {
					refs << r
				}
			}
		}
		out[qn] = refs
	}
	return out
}

// xap_run_derivers parses + validates the {derivers: (…)} run option against
// the attached grammar (§4.2 run assembly, R8.1–R8.3). Each entry is a map
// {name: 'detect', produces: 'feature/noun', reads: ('feature/noun' …)}.
// Refusals: CXER4875 (a produces target that is not a derived noun of the
// grammar; a doubly-bound noun; and — checked by the CALLER after all
// entries land — any derived noun left unbound); CXER4876 (a declared read
// outside the produced noun's [from …] envelope).
fn xap_run_derivers(dv cx.Node, derived map[string][]string) !map[string]string {
	mut bound := map[string]string{}
	for it in xap_seq_items(dv) {
		dname := xap_map_get_str(it, 'name')
		produces := xap_map_get_str(it, 'produces')
		if dname == '' || produces == '' {
			return error('${xap_err_derived_unproduced}|E_XAP_DERIVED_UNPRODUCED: a {derivers:} entry needs name: and produces: (composition spec §4.2)')
		}
		if produces !in derived {
			return error('${xap_err_derived_unproduced}|E_XAP_DERIVED_UNPRODUCED: deriver "${dname}" produces "${produces}", which is not a derived noun of the attached grammar (§4.2)')
		}
		if produces in bound {
			return error('${xap_err_derived_unproduced}|E_XAP_DERIVED_UNPRODUCED: derived noun "${produces}" is bound twice ("${bound[produces]}" and "${dname}") — a grammar binds at most one deriver per derived noun (§4.2)')
		}
		if rv := xap_map_get_node(it, 'reads') {
			envelope := derived[produces]
			for r in xap_name_items(rv) {
				if r !in envelope {
					return error('${xap_err_deriver_reads}|E_XAP_DERIVER_READ_OUTSIDE_FROM: deriver "${dname}" declares read "${r}" outside "${produces}"\'s [from …] envelope (${envelope.join(', ')}) — provenance is the read authority (§4.2)')
				}
			}
		}
		bound[produces] = dname
	}
	return bound
}

fn xap_run(args []cx.Node, mut env MatchEnv) ?cx.Node {
	opts := if args.len > 0 { args[0] } else { xap_elem('__cx_map__', [], []) }
	mut reg := xap_reg()
	reg.next_id = reg.next_id + 1
	id := reg.next_id
	tenant := xap_map_get_str(opts, 'tenant')
	// §3.1 `resolver` run-option (#535): `:scripted` (default) or a CX
	// closure. The closure is captured NOW (#40 discipline — the sentinel's
	// scope table is gone by resolve time). An external LLM resolver handle
	// is spec'd but not yet a shipped surface — refuse it loudly rather
	// than accept-and-ignore.
	mut resolver_kind := 'scripted'
	mut resolver_cl := Closure{}
	mut has_resolver_cl := false
	mut scripted_comps := []string{}
	mut scripted_rules := []XapAffinity{}
	mut has_scripted := false
	if rv := xap_map_get_node(opts, 'resolver') {
		if cl := resolve_closure(rv, env) {
			resolver_kind = 'closure'
			resolver_cl = cl
			has_resolver_cl = true
		} else if rv is cx.Element && rv.name == 'scripted-resolver' {
			// a [$xap:resolver-default $rules] value — the scripted fold
			// runs over THESE rules instead of the registry declarations.
			for i, it in rv.items {
				a := xap_parse_affinity(it, i) or {
					return mk_err(xap_err_arg_invalid, 'E_XAP: run resolver: ${err.msg()}')
				}
				comp := if it is cx.Element { it.attr('component') } else { '' }
				scripted_comps << comp
				scripted_rules << a
			}
			has_scripted = true
		} else {
			rname := xap_verb_name(rv)
			if rname != 'scripted' && rname != ':scripted' {
				return mk_err(xap_err_arg_invalid,
					'E_XAP: run {resolver: …} takes :scripted, a CX closure, or a [$xap:resolver-default …] value — an external resolver handle is not yet a shipped surface (xap.md §3.1/§3.6)')
			}
		}
	}
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
	// §4.2 (#865, R8.1–R8.3) — run assembly binds derivers to derived nouns.
	// The check is fail-closed and NOT first-failure on the unbound set: a
	// grammar whose derived nouns are not all produced refuses with every
	// unproduced noun named (CXER4875). Deriver bindings without a grammar
	// have nothing to bind against and refuse as an argument error.
	mut derivers := map[string]string{}
	if dv := xap_map_get_node(opts, 'derivers') {
		if !has_gram {
			return mk_err(xap_err_arg_invalid,
				'E_XAP: run {derivers: …} needs {grammar: …} — a deriver binds a derived noun of the attached grammar (composition spec §4.2)')
		}
		derived := xap_grammar_derived_nouns(gram)
		derivers = xap_run_derivers(dv, derived) or {
			msg := err.msg()
			ecode := msg.all_before('|')
			return mk_err(ecode, msg.all_after('|'))
		}
	}
	if has_gram {
		derived := xap_grammar_derived_nouns(gram)
		mut unbound := []string{}
		for qn, _ in derived {
			if qn !in derivers {
				unbound << qn
			}
		}
		if unbound.len > 0 {
			unbound.sort()
			return mk_err(xap_err_derived_unproduced,
				'E_XAP_DERIVED_UNPRODUCED: derived noun(s) with no bound deriver: ${unbound.join(', ')} — a derived noun without a producer is refused at run assembly, never silently empty (composition spec §4.2)')
		}
	}
	// The runtime owns a real authority store — the single PEP the cascade calls
	// (§2.2). authz lives in the same V module (stdlib_authz.v); the dial issues
	// real delegations into this store and emit decides against it.
	st := &AuthzStore{
		tenant:  tenant
		is_open: true
	}
	// #606: run-level log compaction — validated at run like a component's
	// reduce; absent = unbounded (today's behavior).
	mut lr_window := 0
	mut lr_cl := Closure{}
	mut has_lr := false
	if lv := xap_map_get_node(opts, 'log-reduce') {
		w := xap_map_get_str(lv, 'window').int()
		if w < 1 {
			return mk_err(xap_err_arg_invalid,
				'E_XAP: run log-reduce needs window: ≥ 1 (xap.md §3.1)')
		}
		lfn := xap_map_get_node(lv, 'fn') or {
			return mk_err(xap_err_arg_invalid,
				'E_XAP: run log-reduce needs fn: (the pure reducer — xap.md §3.1)')
		}
		lcl := resolve_closure(lfn, env) or {
			return mk_err(xap_err_arg_invalid,
				'E_XAP: run log-reduce fn: does not resolve to a callable')
		}
		lr_window = w
		lr_cl = lcl
		has_lr = true
	}
	mut rt := &XapRuntime{
		id:     id
		tenant: tenant
		state:  map[string][]cx.Node{}
		summaries: map[string]cx.Node{}
		bind_seq: map[string]u64{}
		log_reduce_window: lr_window
		log_reduce_closure: lr_cl
		has_log_reduce: has_lr
		authz:  st
		grammar: gram
		has_grammar: has_gram
		derivers: derivers
		resolver_kind: resolver_kind
		resolver_closure: resolver_cl
		has_resolver_closure: has_resolver_cl
		scripted_comps: scripted_comps
		scripted_rules: scripted_rules
		has_scripted_rules: has_scripted
	}
	reg.runtimes[id] = rt
	// §3.1.1 (#582): the durable journal binding — resolve/open it NOW (a
	// bad binding refuses at run, never at first commit), then re-fold the
	// bound stream before returning: restart = re-fold, no PEP re-check.
	if jv := xap_map_get_node(opts, 'journal') {
		jb := xap_open_journal_bind(jv, tenant) or {
			return mk_err(xap_err_arg_invalid, 'E_XAP: run journal binding: ${err.msg()}')
		}
		rt.journal_fab = jb.fab
		rt.journal_stream = jb.stream
		rt.journal_remote = jb.remote
		rt.has_journal_bind = true
		rt.ckpt_store = jb.ckpt_store
		rt.ckpt_every = jb.ckpt_every
		rt.has_ckpt = jb.has_ckpt
		if rerr := xap_replay_journal(mut rt, mut env) {
			return rerr
		}
	}
	// §3.1.2 (#583): event-source bindings — the runtime owns each fabric
	// subscription; a bad binding refuses at run. Pumps start after the
	// §3.1.1 re-fold so ingested deliveries land on the replayed state.
	if sv := xap_map_get_node(opts, 'sources') {
		if serr := xap_start_source_pumps(id, xap_seq_items(sv), tenant, mut env) {
			return serr
		}
	}
	return xap_elem('xap-runtime', [xap_attr('id', id.str()), xap_attr('tenant', tenant)],
		[])
}

// XapJournalBind is the resolved §3.1.1 binding: an open fabric handle over
// the bound journal/stream (embedded for journal urls/handles, the served
// tier for xsp:// urls) — one publish/observe surface for both tiers.
struct XapJournalBind {
	fab    cx.Node
	stream string
	remote bool
	// §3.1.1 fold checkpoints (#595): the derived-state store handle,
	// persist cadence, and presence flag.
	ckpt_store cx.Node
	ckpt_every u64
	has_ckpt   bool
}

// xap_int_node builds an int scalar node (map values for from/max opts).
fn xap_int_node(v i64) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(v)
		data_type: cx.ScalarType.int_type
	}
}

// xap_map_node builds a `{key: value}` map value from parallel key/value arrays.
fn xap_map_node(keys []string, vals []cx.Node) cx.Node {
	mut items := []cx.Node{cap: keys.len}
	for i, k in keys {
		items << cx.Node(cx.Element{ name: k, items: [vals[i]] })
	}
	return cx.Element{ name: '__cx_map__', items: items }
}

// xap_open_journal_bind resolves the §3.1.1 binding value: a {url, stream, …}
// map (xsp://→ the fabric served tier with the map as client opts; any other
// url → [$journal:open] under the runtime tenant), a live [$fabric:open …]
// handle, or a [$journal:open …] handle. stream defaults to "acts".
fn xap_open_journal_bind(jv cx.Node, tenant string) !XapJournalBind {
	if jv is cx.Element {
		if jv.name == '__cx_map__' {
			mut url := ''
			if u := xap_map_get_node(jv, 'url') {
				url = xap_arg_name(u)
			}
			if url == '' {
				return error('binding map needs url: (a journal url, or an xsp:// daemon)')
			}
			mut stream := xap_map_get_str(jv, 'stream')
			if stream == '' {
				stream = 'acts'
			}
			// §3.1.1 checkpoints (#595): open the derived-state store NOW —
			// a bad checkpoint binding refuses at run like the journal does.
			mut ckpt_store := cx.Node(cx.Element{})
			mut ckpt_every := u64(256)
			mut has_ckpt := false
			ckpt_url := xap_map_get_str(jv, 'checkpoint')
			if ckpt_url != '' {
				cs := store_stdlib_builtin('store-open', [cx.Node(bus_str(ckpt_url))]) or {
					return error('checkpoint store-open unavailable')
				}
				if is_err_value(cs) {
					return error('checkpoint store: ${xap_err_message(cs)}')
				}
				ckpt_store = cs
				has_ckpt = true
				ev := xap_map_get_str(jv, 'checkpoint-every')
				if ev != '' {
					n := ev.u64()
					if n == 0 {
						return error('checkpoint-every must be a positive int')
					}
					ckpt_every = n
				}
			}
			if url.starts_with('xsp://') || url.starts_with('xsps://') {
				fab := fabric_stdlib_builtin('fabric-open', [cx.Node(bus_str(url)), cx.Node(jv)]) or {
					return error('fabric-open unavailable')
				}
				if is_err_value(fab) {
					return error(xap_err_message(fab))
				}
				return XapJournalBind{
					fab:        fab
					stream:     stream
					remote:     true
					ckpt_store: ckpt_store
					ckpt_every: ckpt_every
					has_ckpt:   has_ckpt
				}
			}
			jrn := journal_stdlib_builtin('journal-open', [cx.Node(bus_str(url)),
				cx.Node(bus_str(tenant))]) or {
				return error('journal-open unavailable')
			}
			if is_err_value(jrn) {
				return error(xap_err_message(jrn))
			}
			fab := fabric_stdlib_builtin('fabric-open', [jrn]) or {
				return error('fabric-open unavailable')
			}
			if is_err_value(fab) {
				return error(xap_err_message(fab))
			}
			return XapJournalBind{
				fab:        fab
				stream:     stream
				remote:     false
				ckpt_store: ckpt_store
				ckpt_every: ckpt_every
				has_ckpt:   has_ckpt
			}
		}
		if jv.name == 'fabric' || jv.name == 'fabric-remote' {
			return XapJournalBind{ fab: cx.Node(jv), stream: 'acts', remote: jv.name == 'fabric-remote' }
		}
		if jv.name == 'journal' {
			fab := fabric_stdlib_builtin('fabric-open', [cx.Node(jv)]) or {
				return error('fabric-open unavailable')
			}
			if is_err_value(fab) {
				return error(xap_err_message(fab))
			}
			return XapJournalBind{ fab: fab, stream: 'acts', remote: false }
		}
	}
	return error('journal binding must be a {url, stream, …} map, a [\$fabric:open] handle, or a [\$journal:open] handle (xap.md §3.1.1)')
}

// xap_ckpt_alias is the checkpoint's store alias for one (tenant, stream).
fn xap_ckpt_alias(rt &XapRuntime) string {
	return 'xap-checkpoint-${rt.tenant}-${rt.journal_stream}'
}

// xap_ckpt_load seeds the fold from the persisted checkpoint and returns
// the seq it covers (0 = no usable checkpoint → the caller replays in
// full). A checkpoint is DERIVED state, never authority (§3.1.1): any
// missing/unreadable/unparseable checkpoint falls back silently to full
// replay — the stream is the source of truth.
fn xap_ckpt_load(mut rt XapRuntime) u64 {
	al := store_stdlib_builtin('store-get-alias', [rt.ckpt_store,
		cx.Node(bus_str(xap_ckpt_alias(rt)))]) or { return 0 }
	if is_err_value(al) {
		return 0
	}
	href := xap_arg_name(al)
	if href == '' {
		return 0
	}
	doc := store_stdlib_builtin('store-get-doc', [rt.ckpt_store, cx.Node(bus_str(href))]) or {
		return 0
	}
	if is_err_value(doc) {
		return 0
	}
	text := xap_arg_name(doc)
	if text == '' {
		return 0
	}
	parsed := cx.parse(text) or { return 0 }
	for e in parsed.elements {
		if e is cx.Element && e.name == 'checkpoint' {
			seq := e.attr('seq').u64()
			if seq == 0 {
				return 0
			}
			for it in e.items {
				if it is cx.Element && it.name == 'slice' {
					bind := it.attr('bind')
					if bind == '' {
						continue
					}
					mut recs := []cx.Node{}
					for r in it.items {
						// #606: the leading [summary …] child restores the
						// compacted-fold summary, not a detail record.
						if r is cx.Element && r.name == 'summary' && r.items.len > 0 {
							rt.summaries[bind] = r.items[0]
							continue
						}
						recs << r
					}
					rt.state[bind] = recs
				}
			}
			rt.journal_seq = seq
			rt.ckpt_last = seq
			rt.commit_seq++
			return seq
		}
	}
	return 0
}

// XapCkptSnap is one checkpoint's frozen input: the slices are cloned on
// the commit path (cheap — record-pointer copies), everything expensive
// (canonical serialization, store writes) runs off-thread (#604).
struct XapCkptSnap {
	rt_id  int
	seq    u64
	stream string
	alias  string
	store  cx.Node
	slices []cx.Node
}

// xap_ckpt_maybe_persist SNAPSHOTS the fold and dispatches the persist when
// ckpt_every committed events have landed since the last one. The commit
// path never pays the store I/O (#604): one persist in flight per runtime
// (a cadence point that finds one running simply retries at the next), and
// a failed/interrupted persist never fails the commit it trails — the
// put-doc-then-alias order means the alias ALWAYS names a complete
// checkpoint (worst case: the previous one; the stream stays authoritative,
// §3.1.1).
fn xap_ckpt_maybe_persist(mut rt XapRuntime) {
	if !rt.has_ckpt || rt.journal_seq == 0 || rt.journal_seq - rt.ckpt_last < rt.ckpt_every {
		return
	}
	if rt.ckpt_inflight {
		return
	}
	rt.ckpt_inflight = true
	mut slices := []cx.Node{}
	for bind, recs in rt.state {
		mut items := []cx.Node{}
		// #606: the checkpoint IS the compacted fold — the summary record
		// rides as the slice's leading [summary …] child.
		if sm := rt.summaries[bind] {
			items << cx.Node(cx.Element{
				name:  'summary'
				items: [sm]
			})
		}
		items << recs.clone()
		slices << cx.Node(cx.Element{
			name:  'slice'
			attrs: [cx.Attribute{ name: 'bind', value: cx.ScalarValue(bind) }]
			items: items
		})
	}
	xap_ckpt_persist_dispatch(XapCkptSnap{
		rt_id:  rt.id
		seq:    rt.journal_seq
		stream: rt.journal_stream
		alias:  xap_ckpt_alias(rt)
		store:  rt.ckpt_store
		slices: slices
	})
}

// xap_ckpt_done clears the in-flight flag and (on success) advances the
// cadence watermark.
fn xap_ckpt_done(rt_id int, seq u64, ok bool) {
	reg := xap_reg()
	mut rt := reg.runtimes[rt_id] or { return }
	if ok {
		rt.ckpt_last = seq
	}
	rt.ckpt_inflight = false
}

// xap_ckpt_persist_run is the store I/O for one snapshot — off the commit
// path on native targets (#604). Serialize → put-doc → set-alias, in that
// order, so an interrupted persist always leaves the previous complete
// checkpoint aliased. Best-effort per §3.1.1: failures are loud on stderr
// and retried at the next cadence point.
fn xap_ckpt_persist_run(snap XapCkptSnap) {
	doc := cx.Element{
		name:  'checkpoint'
		attrs: [
			cx.Attribute{ name: 'stream', value: cx.ScalarValue(snap.stream) },
			cx.Attribute{ name: 'seq', value: cx.ScalarValue(snap.seq.str()) },
		]
		items: snap.slices
	}
	put := store_stdlib_builtin('store-put-doc', [snap.store,
		cx.Node(bus_str(render_canonical(cx.Node(doc))))]) or {
		eprintln('cx-xap: checkpoint put-doc unavailable (stream "${snap.stream}")')
		xap_ckpt_done(snap.rt_id, snap.seq, false)
		return
	}
	if is_err_value(put) {
		eprintln('cx-xap: checkpoint persist failed: ${xap_err_message(put)}')
		xap_ckpt_done(snap.rt_id, snap.seq, false)
		return
	}
	href := xap_arg_name(put)
	sa := store_stdlib_builtin('store-set-alias', [snap.store,
		cx.Node(bus_str(snap.alias)), cx.Node(bus_str(href))]) or {
		eprintln('cx-xap: checkpoint set-alias unavailable (stream "${snap.stream}")')
		xap_ckpt_done(snap.rt_id, snap.seq, false)
		return
	}
	if is_err_value(sa) {
		eprintln('cx-xap: checkpoint alias failed: ${xap_err_message(sa)}')
		xap_ckpt_done(snap.rt_id, snap.seq, false)
		return
	}
	xap_ckpt_done(snap.rt_id, snap.seq, true)
}

// xap_replay_journal re-folds the bound stream — from the start, or from
// the checkpoint's suffix when one loads (§3.1.1 #595). Committed facts
// fold with no PEP re-check and no re-append. Returns the CXER4860 err
// VALUE on a replay fault.
fn xap_replay_journal(mut rt XapRuntime, mut env MatchEnv) ?cx.Node {
	mut from := u64(0)
	if rt.has_ckpt {
		from = xap_ckpt_load(mut rt)
	}
	// An ungrouped observe reads from the stream head on both tiers —
	// replay from seq 1 is the durable plane's default; a loaded
	// checkpoint replays only the suffix (from seq+1).
	mut obs_args := [rt.journal_fab, cx.Node(bus_str(rt.journal_stream)),
		cx.Node(bus_str('event'))]
	if from > 0 {
		obs_args << xap_map_node(['from'], [xap_int_node(i64(from + 1))])
	}
	sub := fabric_stdlib_builtin_env('fabric-observe', obs_args, mut env) or {
		// #762: observe answers on the env-aware chain (the subscription
		// is closeable — the stamp needs the program registry).
		return mk_err(xap_err_cascade_fault, 'E_XAP_CASCADE_FAULT: journal replay observe unavailable')
	}
	if is_err_value(sub) {
		return mk_err(xap_err_cascade_fault, 'E_XAP_CASCADE_FAULT: journal replay: ${xap_err_message(sub)}')
	}
	// #605: the sub reply carries the stream's head seq — replay ends
	// exactly at the head instead of probing for an empty batch (which on
	// the remote tier costs one full receive deadline). head == 0 means
	// the stream is empty (nothing to replay at all); a daemon that
	// predates the attr yields head == 0 with a NON-empty stream, so the
	// empty-batch probe below remains the fallback.
	mut head := u64(0)
	if sub is cx.Element {
		head = sub.attr('head').u64()
	}
	if head > 0 && rt.journal_seq >= head {
		// the checkpoint already covers the head — zero receives needed.
		xap_ckpt_maybe_persist(mut rt)
		return none
	}
	for {
		// #762: the module verb is retired — the contract arm IS the scan
		// (one turn per batch, max 64 within a 500ms remote deadline).
		batch := fab_sub_contract_receive(sub, 64, 500, mut env)
		if batch is cx.Element && is_err_value(batch) {
			return mk_err(xap_err_cascade_fault, 'E_XAP_CASCADE_FAULT: journal replay: ${xap_err_message(batch)}')
		}
		entries := xap_seq_items(batch)
		if entries.len == 0 {
			break
		}
		for en in entries {
			if en is cx.Element && en.name == 'entry' {
				// [entry seq=… [event <published envelope>]] — the journal's
				// wrapper holds the envelope this runtime committed.
				eseq := en.attr('seq').u64()
				for it in en.items {
					if it is cx.Element && it.name == 'event' && it.items.len > 0 {
						xap_fold_committed(mut rt, it.items[0], mut env)
						if eseq > rt.journal_seq {
							rt.journal_seq = eseq
						}
						break
					}
				}
			}
		}
		// #605: stop exactly at the advertised head — no tail probe. (A
		// foreign entry past our matches keeps journal_seq below head; the
		// empty-batch break above stays as the safety net.)
		if head > 0 && rt.journal_seq >= head {
			break
		}
	}
	// the replayed fold may already be a cadence past the last checkpoint.
	xap_ckpt_maybe_persist(mut rt)
	return none
}

// xap_absence is the empty node-set — the seed a §5 reducer's first
// application receives (its own [?else] handles it).
fn xap_absence() cx.Node {
	return cx.Element{
		name: '__cx_seq__'
	}
}

// xap_reduce_component_for returns the registered component (with a
// declared §5 reduce) whose bind is `bind`, if any.
fn xap_reduce_component_for(bind string) ?XapComponent {
	reg := xap_reg()
	for _, c in reg.components {
		if c.bind == bind && c.has_reduce {
			return c
		}
	}
	return none
}

// xap_slice_reduce applies a component's §5 fold-side compaction (#606):
// when the bind slice exceeds `window` detail records, the OLDEST evict
// through the pure reducer into the slice's single summary record. A
// failing reducer is loud (a [reduce-failed …] event in the log) and
// FAIL-OPEN: the slice keeps its uncompacted records — compaction never
// loses data by failing.
fn xap_slice_reduce(mut rt XapRuntime, bind string, mut env MatchEnv) {
	c := xap_reduce_component_for(bind) or { return }
	recs := rt.state[bind] or { return }
	if recs.len <= c.reduce_window {
		return
	}
	overflow := recs[..recs.len - c.reduce_window]
	mut summary := rt.summaries[bind] or { xap_absence() }
	for rec in overflow {
		nxt := invoke_closure(c.reduce_closure, [summary, rec], mut env) or {
			rt.log << cx.Node(xap_elem('reduce-failed', [
				xap_attr('component', c.name),
				xap_attr('bind', bind),
			], [err_to_node(err)]))
			return
		}
		if nxt is cx.Element && is_err_value(nxt) {
			rt.log << cx.Node(xap_elem('reduce-failed', [
				xap_attr('component', c.name),
				xap_attr('bind', bind),
			], [nxt]))
			return
		}
		summary = nxt
	}
	rt.summaries[bind] = summary
	rt.state[bind] = recs[recs.len - c.reduce_window..].clone()
}

// xap_slice_view composes what every slice READ observes (#606): the
// summary record (when compaction has produced one) followed by the
// most-recent detail records. Without a declared reduce this is exactly
// the complete fold (today's behavior).
fn xap_slice_view(rt &XapRuntime, bind string) []cx.Node {
	mut out := []cx.Node{}
	if s := rt.summaries[bind] {
		out << s
	}
	out << (rt.state[bind] or { []cx.Node{} })
	return out
}

// xap_log_append is the ONE append point for the in-process log — it
// applies the run-level log-reduce (#606) exactly as xap_slice_reduce
// compacts a slice. Absent log-reduce: plain append (today).
fn xap_log_append(mut rt XapRuntime, ev cx.Node, mut env MatchEnv) {
	rt.log << ev
	if !rt.has_log_reduce || rt.log.len <= rt.log_reduce_window {
		return
	}
	overflow := rt.log[..rt.log.len - rt.log_reduce_window]
	mut summary := if rt.has_log_summary { rt.log_summary } else { xap_absence() }
	for rec in overflow {
		nxt := invoke_closure(rt.log_reduce_closure, [summary, rec], mut env) or {
			// loud + fail-open, mirroring xap_slice_reduce: eprintln (the
			// log itself is what failed to compact — appending a failure
			// event would recurse into the same reducer).
			eprintln('cx-xap: log-reduce failed (window ${rt.log_reduce_window}): ${err.msg()}')
			return
		}
		if nxt is cx.Element && is_err_value(nxt) {
			eprintln('cx-xap: log-reduce refused: ${xap_err_message(nxt)}')
			return
		}
		summary = nxt
	}
	rt.log_summary = summary
	rt.has_log_summary = true
	rt.log = rt.log[rt.log.len - rt.log_reduce_window..].clone()
}

// xap_log_view composes what log READERS observe (#606): the log summary
// (when compaction has produced one) followed by the most-recent events.
fn xap_log_view(rt &XapRuntime) []cx.Node {
	mut out := []cx.Node{}
	if rt.has_log_summary {
		out << rt.log_summary
	}
	out << rt.log
	return out
}

// xap_fold_committed folds ONE committed envelope ([event actor=…? [intent]],
// or a bare intent) into the runtime — the shared fold for live commits and
// §3.1.1 boot replay. Mirrors the in-process journal (rt.log) and the state
// slice; no PEP, no append: committed facts fold, period. env carries the
// evaluator for the §5/#606 reducers.
fn xap_fold_committed(mut rt XapRuntime, event cx.Node, mut env MatchEnv) {
	mut actor := ''
	mut intent := event
	if event is cx.Element && event.name == 'event' {
		actor = event.attr('actor')
		for it in event.items {
			if it is cx.Element {
				intent = cx.Node(it)
				break
			}
		}
	}
	// §4.2 (#865) — a derived-noun event ([derived noun='<f>/<n>' RECORD])
	// folds into the noun's own state route ('/<bare-noun>'), fields from
	// the record's attributes and children plus the deriver actor. One fold
	// path serves live derive commits and §3.1.1 boot replay alike.
	if intent is cx.Element && intent.name == 'derived' {
		dnoun := intent.attr('noun')
		if dnoun != '' {
			dbind := '/' + dnoun.all_after('/')
			mut dfields := []cx.Node{}
			if actor != '' {
				dfields << cx.Node(xap_elem('actor', [], [cx.Node(cx.TextNode{ value: actor })]))
			}
			for it in intent.items {
				if it is cx.Element {
					for a in it.attrs {
						dfields << cx.Node(xap_elem(a.name, [], [
							cx.Node(cx.ScalarNode{ value: a.value }),
						]))
					}
					for sub in it.items {
						dfields << sub
					}
				}
			}
			rt.state[dbind] << cx.Node(xap_elem('__cx_map__', [], dfields))
			xap_slice_reduce(mut rt, dbind, mut env)
			xap_log_append(mut rt, event, mut env)
			rt.commit_seq++
			rt.bind_seq[dbind] = rt.commit_seq
			return
		}
	}
	mut vname := ''
	if intent is cx.Element && intent.items.len > 0 {
		vname = xap_verb_name(intent.items[0])
	}
	bind := xap_route_bind(vname)
	if bind != '' {
		mut fields := []cx.Node{}
		if actor != '' {
			fields << cx.Node(xap_elem('actor', [], [cx.Node(cx.TextNode{ value: actor })]))
		}
		if intent is cx.Element {
			for i, it in intent.items {
				if i == 0 {
					continue
				}
				fields << it
			}
		}
		rt.state[bind] << cx.Node(xap_elem('__cx_map__', [], fields))
		xap_slice_reduce(mut rt, bind, mut env)
	}
	xap_log_append(mut rt, event, mut env)
	rt.commit_seq++
	// #609: stamp the bind's change AFTER the seq advances, so a delta
	// subscriber whose high-water mark equals the pre-commit seq sees it.
	if bind != '' {
		rt.bind_seq[bind] = rt.commit_seq
	}
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
		// a `(…)` sequence rides a `__cx_seq__` marker element and an `[…]`
		// array literal a `__cx_arr__` marker — descend both; a real element
		// (e.g. `[do …]`, a `__cx_map__` binding) is a leaf.
		if n.name == '__cx_seq__' || n.name == '__cx_arr__' {
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
fn xap_emit(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 2 {
		return mk_err(xap_err_arg_invalid, 'E_XAP: emit expects (runtime, intent, opts?)')
	}
	mut rt := xap_runtime_of(args[0]) or {
		return mk_err('cx-err:CXER4859', 'E_XAP_RUNTIME_CLOSED: unknown runtime handle')
	}
	intent := args[1]
	opts := if args.len > 2 { args[2] } else { cx.Node(xap_elem('__cx_map__', [], [])) }
	res := xap_emit_into(mut rt, intent, opts, mut env)
	// §3.1.2: live media follow EVERY commit lane — an in-process emit
	// refreshes held /events readers exactly as a web intent does.
	if r := res {
		if !(r is cx.Element && is_err_value(r)) {
			xap_push_live(rt.id, mut env)
		}
	}
	return res
}

// xap_derive — [$xap:derive RT {deriver: 'name', noun: '<feature>/<noun>',
// record: [n …] | {…}}] — the §4.2 (#865, R8.1–R8.3) producer commit: the
// deriver bound at run assembly records ONE derived-noun event as
// `actor: deriver:<name>`, through the SAME durable-append → fold order as
// the emit cascade (a derivation that isn't durable didn't happen). There
// is no PEP call here by design: the binding decided at assembly IS the
// authority — narrow to exactly one noun — and the actor is stamped on the
// envelope, so the act is attributable like any other.
fn xap_derive(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 2 {
		return mk_err(xap_err_arg_invalid,
			'E_XAP: derive expects (runtime, {deriver: …, noun: …, record: …})')
	}
	mut rt := xap_runtime_of(args[0]) or {
		return mk_err('cx-err:CXER4859', 'E_XAP_RUNTIME_CLOSED: unknown runtime handle')
	}
	opts := args[1]
	dname := xap_map_get_str(opts, 'deriver')
	noun := xap_map_get_str(opts, 'noun')
	record := xap_map_get_node(opts, 'record') or {
		return mk_err(xap_err_arg_invalid,
			'E_XAP: derive needs record: (the derived-noun event payload — composition spec §4.2)')
	}
	if dname == '' || noun == '' {
		return mk_err(xap_err_arg_invalid,
			'E_XAP: derive needs deriver: and noun: (composition spec §4.2)')
	}
	if !rt.has_grammar {
		return mk_err(xap_err_arg_invalid,
			'E_XAP: derive needs a runtime with an attached grammar — derivation is a composition concept (composition spec §4.2)')
	}
	if noun !in rt.derivers {
		return mk_err(xap_err_derived_unproduced,
			'E_XAP_DERIVED_UNPRODUCED: "${noun}" is not a derived noun bound at this runtime (composition spec §4.2)')
	}
	if rt.derivers[noun] != dname {
		return mk_err(xap_err_arg_invalid,
			'E_XAP: derived noun "${noun}" is bound to deriver "${rt.derivers[noun]}", not "${dname}" — one noun, one producer (composition spec §4.2)')
	}
	if !(record is cx.Element) {
		return mk_err(xap_err_arg_invalid,
			'E_XAP: derive record: must be an element or map value')
	}
	actor := 'deriver:${dname}'
	intent := cx.Node(xap_elem('derived', [xap_attr('noun', noun)], [record]))
	event := cx.Node(xap_elem('event', [xap_attr('actor', actor)], [intent]))
	if rt.has_journal_bind {
		mut att_keys := []string{}
		mut att_vals := []cx.Node{}
		if !rt.journal_remote {
			att_keys << 'actor'
			att_vals << cx.Node(bus_str(actor))
			att_keys << 'authority'
			att_vals << cx.Node(bus_str('xap:derive'))
		}
		att := xap_map_node(att_keys, att_vals)
		pr := fabric_stdlib_builtin('fabric-publish', [rt.journal_fab,
			cx.Node(bus_str(rt.journal_stream)), event, att]) or {
			return mk_err(xap_err_cascade_fault, 'E_XAP_CASCADE_FAULT: journal publish unavailable')
		}
		if is_err_value(pr) {
			return pr
		}
		if pr is cx.Element {
			rseq := pr.attr('seq').u64()
			if rseq > rt.journal_seq {
				rt.journal_seq = rseq
			}
		}
	}
	xap_fold_committed(mut rt, event, mut env)
	xap_ckpt_maybe_persist(mut rt)
	// live media follow EVERY commit lane (§3.1.2) — a derivation refreshes
	// held /events readers exactly as an intent commit does.
	xap_push_live(rt.id, mut env)
	return event
}

// xap_emit_into is the emit cascade proper, factored off the handle
// resolution so every boundary that already holds the runtime — the
// in-process [$xap:emit] above, the web bridge's POST /intent/<verb>
// (#570) — commits through the ONE path: §8.2 grammar resolution, the
// §2.2 PEP, the record build, the journal append. A client medium can
// never bypass the cascade by arriving over a different transport.
// XapEmitPrep is the cascade's PRE-APPEND half for one intent: actor
// resolution, §8.2 grammar qualification, the §2.2 PEP decision, and the
// event/envelope/attribution build. A refusal carries the err VALUE —
// nothing appends, nothing folds. Factored so the single-emit path and the
// #593 pipelined batch lane run the IDENTICAL cascade head.
struct XapEmitPrep {
	refused  bool
	refusal  cx.Node
	event    cx.Node // the fold/rt.log value (anonymous back-compat shape)
	envelope cx.Node // the §3.1.1 durable [event …] envelope (bound runtimes)
	att      cx.Node // the append attribution map (bound runtimes)
}

fn xap_emit_prepare(mut rt XapRuntime, intent cx.Node, opts cx.Node) XapEmitPrep {
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
			return XapEmitPrep{ refused: true, refusal: rerr }
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
				return XapEmitPrep{
					refused: true
					refusal: mk_err(xap_err_unauthorized, 'E_XAP_UNAUTHORIZED: actor "${actor}" is not granted "${gname}" over "${gbind}"')
				}
			}
		}
	} else if !xap_pep_admits(rt, actor, vname, bind) {
		return XapEmitPrep{
			refused: true
			refusal: mk_err(xap_err_unauthorized, 'E_XAP_UNAUTHORIZED: actor "${actor}" is not granted "${vname}" over "${bind}"')
		}
	}
	// the committed EVENT records the authority basis (the actor) and — with a
	// grammar attached — the QUALIFIED intent (§8.2). An anonymous emit logs
	// the bare intent in-process (back-compat); the DURABLE stream always
	// carries the uniform [event …] envelope (§3.1.1 — head `event` is the
	// stream's total pattern).
	event := if actor != '' {
		cx.Node(xap_elem('event', [xap_attr('actor', actor)], [intent_committed]))
	} else {
		intent_committed
	}
	mut envelope := cx.Node(cx.Element{})
	mut att := cx.Node(cx.Element{})
	if rt.has_journal_bind {
		envelope = if actor != '' {
			event
		} else {
			cx.Node(xap_elem('event', [], [intent_committed]))
		}
		mut att_keys := []string{}
		mut att_vals := []cx.Node{}
		if !rt.journal_remote {
			// Direct journal handle: the append's attribution IS the
			// PEP-resolved {actor, authority}. Over a fabric session the
			// transport's proven principal attributes the append (§4.8 —
			// a claimed actor would refuse); the PEP actor rides in the
			// envelope.
			if actor != '' {
				att_keys << 'actor'
				att_vals << cx.Node(bus_str(actor))
			}
			att_keys << 'authority'
			att_vals << cx.Node(bus_str('xap:emit'))
		}
		att = xap_map_node(att_keys, att_vals)
	}
	return XapEmitPrep{ event: event, envelope: envelope, att: att }
}

// xap_emit_receipt_fold is the cascade's POST-APPEND half for one prepared
// intent: thread the receipt's journal seq (§3.1.1/#595) and fold.
fn xap_emit_receipt_fold(mut rt XapRuntime, p XapEmitPrep, receipt cx.Node, mut env MatchEnv) {
	if receipt is cx.Element {
		rseq := receipt.attr('seq').u64()
		if rseq > rt.journal_seq {
			rt.journal_seq = rseq
		}
	}
	xap_fold_committed(mut rt, p.event, mut env)
}

fn xap_emit_into(mut rt XapRuntime, intent cx.Node, opts cx.Node, mut env MatchEnv) ?cx.Node {
	p := xap_emit_prepare(mut rt, intent, opts)
	if p.refused {
		return p.refusal
	}
	// §3.1.1 commit order: PEP (in prepare) → durable append → fold. An
	// append failure means NOTHING folds — a commit that isn't durable
	// didn't happen. Both commit lanes (in-process emit, the web bridge)
	// arrive here, so authority is never double-recorded downstream.
	mut receipt := cx.Node(cx.Element{})
	if rt.has_journal_bind {
		pr := fabric_stdlib_builtin('fabric-publish', [rt.journal_fab,
			cx.Node(bus_str(rt.journal_stream)), p.envelope, p.att]) or {
			return mk_err(xap_err_cascade_fault, 'E_XAP_CASCADE_FAULT: journal publish unavailable')
		}
		if is_err_value(pr) {
			// The sibling's refusal propagates AS-IS (N-IMPL-1 — e.g. the
			// journal's no-anonymous-appends invariant, or a fabric grant
			// denial). Nothing folds either way.
			return pr
		}
		receipt = pr
	}
	xap_emit_receipt_fold(mut rt, p, receipt, mut env)
	xap_ckpt_maybe_persist(mut rt)
	return p.event
}

// xap_emit_batch_into commits a BATCH of intents through the one cascade:
// PEP per entry (in prepare), then the durable appends PIPELINED over a
// remote binding — ~one wire round-trip per batch instead of per event
// (#593). Embedded/unbound runtimes take the single path per entry (no RTT
// to save; one hot code path). Per-entry results in order: the committed
// event, or the refusal/append err. Folds happen in receipt order = send
// order; an erred append refuses THAT entry only (later receipts folded —
// the journal appended them).
fn xap_emit_batch_into(mut rt XapRuntime, intents []cx.Node, optss []cx.Node, mut env MatchEnv) []cx.Node {
	mut out := []cx.Node{len: intents.len, init: cx.Node(cx.Element{})}
	if !(rt.has_journal_bind && rt.journal_remote) || intents.len <= 1 {
		for i, it in intents {
			r := xap_emit_into(mut rt, it, optss[i], mut env) or {
				cx.Node(mk_err(xap_err_cascade_fault, 'E_XAP_CASCADE_FAULT: emit unavailable'))
			}
			out[i] = r
		}
		return out
	}
	mut preps := []XapEmitPrep{cap: intents.len}
	for i, it in intents {
		preps << xap_emit_prepare(mut rt, it, optss[i])
	}
	mut env_batch := []cx.Node{}
	mut att_batch := []cx.Node{}
	mut idxs := []int{}
	for i, p in preps {
		if p.refused {
			out[i] = p.refusal
			continue
		}
		env_batch << p.envelope
		att_batch << p.att
		idxs << i
	}
	if idxs.len > 0 {
		receipts := fab_batch_publish(rt.journal_fab, rt.journal_stream, env_batch, att_batch)
		for k, r in receipts {
			i := idxs[k]
			if r is cx.Element && is_err_value(r) {
				out[i] = r
				continue
			}
			xap_emit_receipt_fold(mut rt, preps[i], r, mut env)
			out[i] = preps[i].event
		}
	}
	xap_ckpt_maybe_persist(mut rt)
	return out
}

// xap-state returns the live fold over the runtime's journal projected by CXPath
// — a present sequence (absence/empty when nothing is there, never null).
fn xap_state(args []cx.Node) ?cx.Node {
	rt := xap_runtime_of(args[0]) or {
		return mk_err('cx-err:CXER4859', 'E_XAP_RUNTIME_CLOSED: unknown runtime handle')
	}
	path := if args.len > 1 { xap_arg_name(args[1]) } else { '' }
	entries := xap_slice_view(rt, path)
	if entries.len == 0 {
		return jrn_empty()
	}
	return jrn_seq(entries)
}

// xap_coord_fabric resolves the runtime's transient-plane carrier: an
// embedded fabric over a mem:// journal, opened lazily on the first publish
// (a runtime that never coordinates never opens one). mem:// is
// capability-free, so the coord verbs keep their pre-migration authority
// posture — wiring-time, never per-frame.
fn xap_coord_fabric(mut rt XapRuntime) cx.Node {
	if rt.has_coord_fab {
		return rt.coord_fab
	}
	tenant := if rt.tenant == '' { 'xap' } else { rt.tenant }
	jn := journal_stdlib_builtin('journal-open', [cx.Node(bus_str('mem://xap-coord-${rt.id}')),
		cx.Node(bus_str(tenant))]) or {
		return mk_err(xap_err_arg_invalid, 'E_XAP: coord fabric journal-open unavailable')
	}
	if is_err_value(jn) {
		return jn
	}
	fe := fabric_open([jn])
	if is_err_value(fe) {
		return fe
	}
	rt.coord_fab = fe
	rt.has_coord_fab = true
	return fe
}

// xap_coord_key is the fabric §19.4 tenant-first channel key: the runtime's
// tenant is the leading structural segment, the caller's `<scope>/<name>`
// channel follows.
fn xap_coord_key(rt &XapRuntime, channel string) string {
	tenant := if rt.tenant == '' { 'xap' } else { rt.tenant }
	return '${tenant}/${channel}'
}

// xap-coord-publish (runtime, channel, frame) — #25 Tier-2: publish ephemeral
// interaction state (viewport/selection/hover) to a transient coordination
// channel — a fabric transient-plane emit (#531 P2; fabric.md §12
// generalizes exactly this pattern). LATEST-WINS (not appended) and held
// outside rt.log — it never flows through the journal or the PEP-gated
// cascade, and is out of audit by design
// (spec/_archived/xap_feature_augmentation.md §3.2). Authorization is a
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
	fe := xap_coord_fabric(mut rt)
	if is_err_value(fe) {
		return fe
	}
	r := fabric_emit([fe, cx.Node(bus_str(xap_coord_key(rt, channel))), args[2]])
	if is_err_value(r) {
		return r
	}
	return args[2] // the pre-migration return contract: the published frame
}

// xap-coord-read (runtime, channel) — read the latest frame on a coordination
// channel (or empty if none published): a fabric transient-plane read. The
// augmenting feature's live read of the augmented feature's ephemeral state
// (#25 Tier-2). A runtime that never published reads empty without opening a
// carrier.
fn xap_coord_read(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(xap_err_arg_invalid, 'E_XAP: coord-read expects (runtime, channel)')
	}
	rt := xap_runtime_of(args[0]) or {
		return mk_err('cx-err:CXER4859', 'E_XAP_RUNTIME_CLOSED: unknown runtime handle')
	}
	channel := xap_arg_name(args[1])
	if !rt.has_coord_fab {
		return jrn_empty()
	}
	return fabric_read([rt.coord_fab, cx.Node(bus_str(xap_coord_key(rt, channel)))])
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
					view_arg = jrn_seq(xap_slice_view(rt, comp.bind))
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

// xap_component_declaring finds the registered component whose `emits`
// vocabulary declares `vname` (qualified or local form — mirrors
// xap_route_bind's matching). The web bridge's route table derives from
// this (#570): a verb no component declares has no route semantics.
fn xap_component_declaring(vname string) ?XapComponent {
	if vname == '' {
		return none
	}
	reg := xap_reg()
	local := if vname.contains('/') { vname.all_after_last('/') } else { vname }
	for _, c in reg.components {
		for pat in xap_seq_items(c.emits) {
			if pat is cx.Element && pat.items.len > 0 {
				pv := xap_verb_name(pat.items[0])
				if pv == vname || pv == local {
					return c
				}
			}
		}
	}
	return none
}

// xap_emit_slots lists the payload slot names the component's emits
// pattern declares for `vname` — `[do :sign [name :string]]` → ['name'].
// The web bridge maps form params onto exactly these slots (#570).
fn xap_emit_slots(c XapComponent, vname string) []string {
	local := if vname.contains('/') { vname.all_after_last('/') } else { vname }
	for pat in xap_seq_items(c.emits) {
		if pat is cx.Element && pat.items.len > 0 {
			pv := xap_verb_name(pat.items[0])
			if pv == vname || pv == local {
				mut out := []string{}
				for i, it in pat.items {
					if i == 0 {
						continue
					}
					if it is cx.Element && it.name != '' {
						out << it.name
					}
				}
				return out
			}
		}
	}
	return []
}

// xap_err_message reads the message attribute off an [err …] value node
// ('' when absent) — the render boundary quotes the view's own failure text.
fn xap_err_message(n cx.Node) string {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'message' {
				v := a.value
				if v is string {
					return v
				}
			}
		}
		// [message '…'] child (user-built errs carry structured fields as
		// children — code.md §9.5 err shapes).
		for it in n.items {
			if it is cx.Element && it.name == 'message' && it.items.len > 0 {
				inner := it.items[0]
				if inner is cx.ScalarNode {
					v := inner.value
					if v is string {
						return v
					}
				}
			}
		}
		for a in n.attrs {
			if a.name == 'code' {
				v := a.value
				if v is string {
					return v
				}
			}
		}
	}
	return ''
}


// xap_view_failed wraps a render-time view failure as the spec's CXER4863
// E_XAP_VIEW_FAILED err VALUE (xap.md §3.5/§8): it names the component and
// carries the view's own failure as [cause …]. The err flows the single
// view-tree channel, so every medium surfaces it at the transport's failure
// mapping — never folded into absence, never misreported as an unregistered
// component (#585). Absence stays "no registered component with a view".
fn xap_view_failed(comp string, cause cx.Node) cx.Node {
	e := cx.Node(cx.Element{
		name: 'err'
		attrs: [
			cx.Attribute{ name: 'code', value: cx.ScalarValue(xap_err_view_failed) },
			cx.Attribute{
				name:  'message'
				value: cx.ScalarValue('E_XAP_VIEW_FAILED: component "${comp}" view failed at render: ${xap_err_message(cause)}')
			},
		]
		items: [cx.Node(cx.Element{ name: 'cause', items: [cause] })]
	})
	fire_raise_observe(e)
	return e
}

// xap_render_view applies one registered component's view over `view_arg`
// and returns the materialized panel — or the CXER4863 err VALUE when the
// view raises or itself returns an [err] (xap.md §3.5: view failure is
// loud, one contract for every render path).
fn xap_render_view(c XapComponent, view_arg cx.Node, mut env MatchEnv) cx.Node {
	panel := if c.has_view_closure {
		invoke_closure(c.view_closure, [view_arg], mut env) or {
			return xap_view_failed(c.name, err_to_node(err))
		}
	} else {
		apply_fn_value(c.view, [view_arg], mut env) or {
			return xap_view_failed(c.name, err_to_node(err))
		}
	}
	// ONE traversal (#596) materializes the tree AND finds the first [err …]
	// value in document order — the view's own err result and any err
	// EMBEDDED in the projected tree (a failed hole wrapped by data
	// construction; the serializers would drop it silently) are the same
	// failure (§3.5).
	m, e, has_err := xap_materialize_scan(panel)
	if has_err {
		return xap_view_failed(c.name, e)
	}
	return m
}

// xap_runtime_panel_named renders the view of the registered component
// `name` over rt's live slice and returns its materialized panel — none
// when the name is unregistered or has no view (the #567 shell splice
// refuses those as unknown mounts), the CXER4863 err VALUE when the view
// itself fails (xap.md §3.5 — the caller maps it to the transport failure).
fn xap_runtime_panel_named(rt &XapRuntime, name string, mut env MatchEnv) ?cx.Node {
	reg := xap_reg()
	c := reg.components[name] or { return none }
	if !c.has_view {
		return none
	}
	mut view_arg := cx.Node(xap_elem('__cx_map__', [], []))
	if c.bind != '' {
		view_arg = jrn_seq(xap_slice_view(rt, c.bind))
	}
	return xap_render_view(c, view_arg, mut env)
}

// xap_component_by_bind_seg finds the registered component (with a view)
// whose bind path is exactly "/<seg>" — the #578 detail-route lookup
// (GET /<seg>/<key>).
fn xap_component_by_bind_seg(seg string) ?XapComponent {
	if seg == '' {
		return none
	}
	reg := xap_reg()
	want := '/' + seg
	for _, c in reg.components {
		if c.bind == want && c.has_view {
			return c
		}
	}
	return none
}

// xap_runtime_panel_keyed renders component c's view over its slice
// FILTERED to the record(s) whose `id` field equals `key` — the spec's own
// keyed-slice convention (xap.md §5's bind example predicates on @/id).
// Returns none when no record matches: a detail route names a record
// resource, so a missing record is the caller's 404, never an empty page
// (#578).
fn xap_runtime_panel_keyed(rt &XapRuntime, c XapComponent, key string, mut env MatchEnv) ?cx.Node {
	mut hits := []cx.Node{}
	for rec in (rt.state[c.bind] or { []cx.Node{} }) {
		if xap_map_get_str(rec, 'id') == key {
			hits << rec
		}
	}
	if hits.len == 0 {
		return none
	}
	view_arg := jrn_seq(hits)
	return xap_render_view(c, view_arg, mut env)
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
			view_arg = jrn_seq(xap_slice_view(rt, c.bind))
		}
		// xap_render_view materializes the panel (forcing lazy iterators so
		// every serializer reads the same concrete data) or yields the
		// CXER4863 err VALUE; a failed view surfaces as the surface value
		// itself so the serve boundary maps it to the transport failure
		// (xap.md §3.5 — never an empty surface).
		panel := xap_render_view(c, view_arg, mut env)
		if panel is cx.Element && is_err_value(panel) {
			return panel
		}
		return xap_elem('surface', [xap_attr('name', c.name)], [panel])
	}
	return xap_elem('surface', [xap_attr('name', '')], [])
}

// xap_materialize_scan deep-forces a view-tree (IteratorNode → concrete
// SequenceNode via iterate, recursing through element items and nested
// collections — the medium-agnostic view-tree (§13.2) becomes a re-readable
// value, not a one-shot stream) AND, in the SAME traversal (#596), reports
// the first [err …] value found in document order (a failing view's own
// result, or an err embedded by data construction — the §3.5 loud-failure
// scan). Returns (materialized, first-err, found).
fn xap_materialize_scan(n cx.Node) (cx.Node, cx.Node, bool) {
	match n {
		cx.IteratorNode {
			mut items := []cx.Node{}
			mut ferr := cx.Node(cx.Element{})
			mut has := false
			for it in iterate(n) {
				m, e, h := xap_materialize_scan(it)
				items << m
				if h && !has {
					ferr = e
					has = true
				}
			}
			return cx.SequenceNode{
				items: items
			}, ferr, has
		}
		cx.SequenceNode {
			mut items := []cx.Node{}
			mut ferr := cx.Node(cx.Element{})
			mut has := false
			for it in n.items {
				m, e, h := xap_materialize_scan(it)
				items << m
				if h && !has {
					ferr = e
					has = true
				}
			}
			return cx.SequenceNode{
				items: items
			}, ferr, has
		}
		cx.ArrayNode {
			mut items := []cx.Node{}
			mut ferr := cx.Node(cx.Element{})
			mut has := false
			for it in n.items {
				m, e, h := xap_materialize_scan(it)
				items << m
				if h && !has {
					ferr = e
					has = true
				}
			}
			return cx.ArrayNode{
				items: items
			}, ferr, has
		}
		cx.Element {
			mut items := []cx.Node{}
			mut ferr := cx.Node(cx.Element{})
			mut has := false
			for it in n.items {
				m, e, h := xap_materialize_scan(it)
				items << m
				if h && !has {
					ferr = e
					has = true
				}
			}
			out := cx.Element{
				...n
				items: items
			}
			// Self-or-descendant, self first (document order): an err-shaped
			// element IS the finding, its embedded errs are its cause detail.
			if is_err_value(cx.Node(out)) {
				return out, cx.Node(out), true
			}
			return out, ferr, has
		}
		else {
			return n, n, false
		}
	}
}

// ── §8.1 composition engine (pure, env-free) ─────────────────────────────────
//
// spec/03-approved/xap/xap_grammar_composition.md — compose n feature grammars into
// ONE grammar `⊢ grammar.cxs` (or reject with every W1–W6 conflict), plus the
// bare-term resolution function ρ and the Tier-1 grammar hash. Everything here
// is a pure function of its inputs: no journal, no PEP, no clock, no registry.

const xap_err_compose_conflict = 'cx-err:CXER4870' // E_XAP_COMPOSE_CONFLICT
// §4.2 (#865) — run-assembly derivation refusals (composition spec, error table)
const xap_err_derived_unproduced = 'cx-err:CXER4875' // E_XAP_DERIVED_UNPRODUCED
const xap_err_deriver_reads = 'cx-err:CXER4876' // E_XAP_DERIVER_READ_OUTSIDE_FROM
const xap_err_verb_ambiguous = 'cx-err:CXER4871' // E_XAP_VERB_AMBIGUOUS
const xap_err_verb_unknown = 'cx-err:CXER4872' // E_XAP_VERB_UNKNOWN
const xap_err_feature_invalid = 'cx-err:CXER4873' // E_XAP_FEATURE_INVALID
const xap_err_compose_empty = 'cx-err:CXER4874' // E_XAP_COMPOSE_EMPTY

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
	// §4.2/W7 (#865, R8.2) — the nouns this verb declares it [writes].
	// Bare names resolve against the verb's own feature first, then as a
	// unique bare match across the composed set; qualified names directly.
	// W7 refuses a resolved target that is a derived noun (deriver-reserved).
	writes []string
	// §4.4 (#867, R8.9) — the [reads …] targets: verb↔noun cohesion edges.
	reads []string
}

struct XapGNoun {
mut:
	feature string
	name    string // bare
	derived bool
	fields  map[string]string // field name → type
	// #840 — [from …] source list, qualified `<feature>/<noun>` references, one
	// per string item (spec §4.1). W5 requires each to resolve to a noun of the
	// composed grammar. Join SEMANTICS stay unspecified and uncomputed: this
	// records what the noun is derived FROM, never how the sources combine.
	from_refs []string
}

struct XapGRule {
	feature  string
	name     string
	kind     string
	verb     string // structured W4 targets (declaring them opts the rule in)
	when     string
	after    string
	requires string
	// §4.4 (#867, R8.8 rider) — a validity rule's checked noun list
	// (nouns= attr, space-separated): the floor/ceiling noun↔noun edges;
	// existence-checked (W5-class) when declared.
	nouns []string
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
	code   string // ':w1' … ':w7'
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
		// #840 — [from 'feature/noun' …]: ONE reference per string item. A
		// whitespace-bearing string is deliberately ONE (unresolvable)
		// reference, not a separator-joined list — the shape is unambiguous
		// rather than lenient, so a stray join sentence fails the gate instead
		// of being silently split into plausible-looking names.
		if fe := xap_gc_child(ne, 'from') {
			for it in fe.items {
				r := xap_arg_name(it).trim_space()
				if r != '' {
					nn.from_refs << r
				}
			}
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
		// §4.2/W7 (#865) — [writes N …]: one noun name per item (bare or
		// qualified). Parsed for the W7 deriver-reservation check.
		for we in xap_gc_children(ve, 'writes') {
			for it in we.items {
				t := xap_arg_name(it).trim_space()
				if t != '' {
					v.writes << t
				}
			}
		}
		// §4.4 (#867) — [reads N …]: the verb↔noun cohesion edges. Reads
		// stay UNRESTRICTED at runtime (§4.2 rule 3); parsing is for the
		// granularity graph only.
		for re0 in xap_gc_children(ve, 'reads') {
			for it in re0.items {
				t := xap_arg_name(it).trim_space()
				if t != '' {
					v.reads << t
				}
			}
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
				nouns:    xap_gc_split_names(xap_elem_attr(rl, 'nouns'))
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
		// #840 — W5 covers every qualified noun reference in a derived noun's
		// [from …]. Before this the noun parser read `name` and `derived` and
		// stopped, so the one part of a composite describing its actual content
		// was unvalidated free text while `uses` and `constituents` beside it
		// were strict. A composite could name a noun in a feature that is not
		// enabled and compose clean.
		for nn in f.nouns {
			if !nn.derived {
				continue
			}
			nqname := '${f.name}/${nn.name}'
			if nn.from_refs.len == 0 {
				confs << XapGConflict{
					code:   ':w5'
					at:     nqname
					detail: 'derived noun "${nqname}" declares no [from …] source list'
				}
				continue
			}
			for r in nn.from_refs {
				if r !in noun_set {
					confs << XapGConflict{
						code:   ':w5'
						at:     nqname
						detail: '[from …] reference "${r}" is not a noun of the composed grammar'
					}
				}
			}
		}
		// §4.4 rider (#867, ruled 3a) — a validity rule's nouns= list is
		// existence-checked when declared (bare = own feature; qualified =
		// the composed set), exactly like the other structured targets.
		for r in f.rules {
			for n0 in r.nouns {
				qn := if n0.contains('/') { n0 } else { '${f.name}/${n0}' }
				if qn !in noun_set {
					confs << XapGConflict{
						code:   ':w5'
						at:     '${f.name}/${r.name}'
						detail: 'rule nouns= names "${n0}", which is not a noun of the composed grammar (§4.4)'
					}
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
	// W7 (#865, R8.2/§4.2) — derived-noun write exclusivity: no verb of the
	// composed grammar may declare [writes] onto a derived=true noun. The
	// noun is deriver-reserved; the manual-override shape is a SOURCE noun
	// the deriver folds, never a write verb. Resolution mirrors the writes
	// convention in the feature docs: own-feature bare name first, then a
	// qualified reference, then a unique bare match across the set. A writes
	// target that resolves to nothing is not W7's question (reads/writes
	// prose stays otherwise ungated here), so it is skipped, not refused.
	mut derived_q := map[string]bool{}
	mut bare_nouns := map[string][]string{}
	for f in feats {
		for nn in f.nouns {
			qn := '${f.name}/${nn.name}'
			bare_nouns[nn.name] << qn
			if nn.derived {
				derived_q[qn] = true
			}
		}
	}
	for f in feats {
		for v in f.verbs {
			for t in v.writes {
				mut resolved := ''
				if t.contains('/') {
					resolved = t
				} else if '${f.name}/${t}' in noun_set {
					resolved = '${f.name}/${t}'
				} else if t in bare_nouns && bare_nouns[t].len == 1 {
					resolved = bare_nouns[t][0]
				}
				if resolved != '' && resolved in derived_q {
					confs << XapGConflict{
						code:   ':w7'
						at:     '${f.name}/${v.name}'
						detail: 'verb declares [writes] onto derived noun "${resolved}" — a derived noun is deriver-reserved (§4.2); model a manual override as a source noun the deriver folds'
					}
				}
			}
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
		mut nitems := []cx.Node{}
		if nn.derived {
			attrs << xap_attr_bool('derived', true)
			// §4.2 (#865) — the projection carries the [from …] source list
			// so run assembly can enforce the read-authority envelope from
			// the grammar alone (one reference per string item, as authored;
			// the list is a single feature's declaration, so document order
			// is already enable-order-independent).
			if nn.from_refs.len > 0 {
				mut fitems := []cx.Node{}
				for r in nn.from_refs {
					fitems << xap_str(r)
				}
				nitems << cx.Node(xap_elem('from', [], fitems))
			}
		}
		noun_items << xap_elem('noun', attrs, nitems)
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

// xap_gc_vacuous reports whether a composition has no features at all — the
// §3.1 identity row's refusal (#844).
//
// A gate over the empty set has verified the empty set, and answering that
// with a pass is the one failure mode that makes a gate worse than no gate:
// the green is load-bearing in the reader's mind and carries no information.
// A XAP whose feature files were renamed, moved, or not yet written used to
// compose green here.
//
// This is a refusal of the CALL, not of a feature. `compose(A, ∅)` — where ∅
// is a [feature] declaring no verbs and no nouns — is the legitimate identity
// operand and still succeeds; what is refused is composing no operands at all,
// which was only ever a way to spell ∅ by accident.
//
// BOTH faces decide vacuity through this one predicate. The §8.1 agreement law
// ("compose raises iff compose-report has ok=false") then holds by
// construction rather than by two edits that must be kept in step.
@[inline]
fn xap_gc_vacuous(feats []XapGFeature) bool {
	return feats.len == 0
}

// xap_gc_empty_conflict is the reason carried by a vacuous compose-report. The
// `code=` vocabulary is :w1…:w7 plus :empty; this is a vacuity refusal, not a
// W-gate violation, and it says so.
fn xap_gc_empty_conflict() cx.Node {
	return xap_elem('conflict', [xap_attr('code', ':empty'), xap_attr('at', '(no features)'),
		xap_attr('detail', 'composition has no features — a gate over the empty set verifies nothing (§3.1 identity)')],
		[])
}

// [$xap:compose FEATURE …] — the enforcing face of the gate (§8.1): the
// composed [grammar …], or CXER4874 for a composition of no features at all,
// or CXER4870 carrying EVERY [conflict …], or CXER4873 for a non-[feature]
// argument.
fn xap_compose_builtin(args []cx.Node) ?cx.Node {
	feats := xap_gc_load(args) or {
		return xap_gc_err(xap_err_feature_invalid, 'E_XAP_FEATURE_INVALID: ${err.msg()}',
			[], [])
	}
	if xap_gc_vacuous(feats) {
		return xap_gc_err(xap_err_compose_empty, 'E_XAP_COMPOSE_EMPTY: composition has no features — a gate over the empty set verifies nothing (§3.1 identity)',
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
// compose raises iff this reports ok=false — both run xap_gc_vacuous first and
// xap_gc_gate second, so the two faces cannot drift. A non-[feature] argument
// still raises CXER4873 — that is an input error, not a composition conflict.
fn xap_compose_report_builtin(args []cx.Node) ?cx.Node {
	feats := xap_gc_load(args) or {
		return xap_gc_err(xap_err_feature_invalid, 'E_XAP_FEATURE_INVALID: ${err.msg()}',
			[], [])
	}
	if xap_gc_vacuous(feats) {
		return xap_elem('compose-report', [xap_attr_bool('ok', false)], [
			xap_gc_empty_conflict(),
		])
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
		// The one head carries two shape-dispatched contracts (#535): name
		// BOTH so a miss on either sends debugging to the right section.
		return mk_err(xap_err_arg_invalid,
			'E_XAP: resolve is shape-dispatched on its first argument — a composed [grammar …] = §8.1 ρ term resolution (grammar, term, context?); an [xap-runtime …] handle = §3.6 context→composition (runtime, context, opts?); got neither')
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
// ── §4.4 granularity — the cohesion instrument (#867, R8.7–R8.10) ────────────
// [$xap:cohesion FEATURE] — PURE: the feature's internal graph under the
// R8.9 edge set (verb↔noun reads/writes; verb↔verb ordering/dependency +
// constituents; noun↔noun checked rule noun-lists + sub-noun typing +
// [from …]; keys and frames are NOT edges; cross-feature references are
// excluded from the own component count). Report-first, never refuses:
// two connected components are two features wearing one name, and the
// components ARE the split the gate would accept.

// xap_coh_find — union-find with path compression over node indexes.
fn xap_coh_find(mut parent []int, i int) int {
	mut r := i
	for parent[r] != r {
		r = parent[r]
	}
	mut c := i
	for parent[c] != c {
		nxt := parent[c]
		parent[c] = r
		c = nxt
	}
	return r
}

fn xap_coh_union(mut parent []int, a int, b int) {
	ra := xap_coh_find(mut parent, a)
	rb := xap_coh_find(mut parent, b)
	if ra != rb {
		parent[rb] = ra
	}
}

// xap_coh_own resolves a reference to the OWN feature's bare member name:
// a bare name passes through; '<own>/<name>' self-qualification strips;
// any other qualified reference is cross-feature — excluded (R8.9).
fn xap_coh_own(s string, fname string) string {
	if s.contains('/') {
		if s.starts_with('${fname}/') {
			return s.all_after_first('/')
		}
		return ''
	}
	return s
}

fn xap_cohesion_builtin(args []cx.Node) ?cx.Node {
	if args.len < 1 {
		return mk_err(xap_err_arg_invalid, 'E_XAP: cohesion expects (feature)')
	}
	fe_n := args[0]
	if !(fe_n is cx.Element && fe_n.name == 'feature') {
		return mk_err(xap_err_arg_invalid,
			'E_XAP: cohesion expects a [feature …] document (§4.4)')
	}
	// LENIENT extraction, deliberately not xap_gc_parse_feature: the
	// instrument measures ANY feature document's graph — richer grammars
	// (ORIEL's session-scoped verbs, say) are compose's strictness problem,
	// not the ruler's. Cohesion needs only names and declared references.
	fe := fe_n as cx.Element
	mut f := XapGFeature{
		name: xap_elem_attr(fe, 'name')
	}
	if ns0 := xap_gc_child(fe, 'nouns') {
		for ne in xap_gc_children(ns0, 'noun') {
			mut nn := XapGNoun{
				feature: f.name
				name:    xap_elem_attr(ne, 'name')
			}
			for fe2 in xap_gc_children(ne, 'field') {
				nn.fields[xap_elem_attr(fe2, 'name')] = xap_elem_attr(fe2, 'type')
			}
			if fr := xap_gc_child(ne, 'from') {
				for it in fr.items {
					r := xap_arg_name(it).trim_space()
					if r != '' {
						nn.from_refs << r
					}
				}
			}
			f.nouns << nn
		}
	}
	if vs0 := xap_gc_child(fe, 'verbs') {
		for ve in xap_gc_children(vs0, 'verb') {
			mut v := XapGVerb{
				feature: f.name
				name:    xap_elem_attr(ve, 'name')
			}
			for we in xap_gc_children(ve, 'writes') {
				for it in we.items {
					t := xap_arg_name(it).trim_space()
					if t != '' {
						v.writes << t
					}
				}
			}
			for re0 in xap_gc_children(ve, 'reads') {
				for it in re0.items {
					t := xap_arg_name(it).trim_space()
					if t != '' {
						v.reads << t
					}
				}
			}
			if ce := xap_gc_child(ve, 'constituents') {
				v.constituents = xap_gc_split_names(xap_gc_text_item(ce))
			}
			f.verbs << v
		}
	}
	if rs0 := xap_gc_child(fe, 'rules') {
		for rl in xap_gc_children(rs0, 'rule') {
			f.rules << XapGRule{
				feature:  f.name
				name:     xap_elem_attr(rl, 'name')
				kind:     xap_elem_attr(rl, 'kind')
				verb:     xap_elem_attr(rl, 'verb')
				after:    xap_elem_attr(rl, 'after')
				requires: xap_elem_attr(rl, 'requires')
				nouns:    xap_gc_split_names(xap_elem_attr(rl, 'nouns'))
			}
		}
	}
	// Nodes: nouns then verbs, bare names (one feature's own graph).
	mut node_ids := map[string]int{}
	mut node_names := []string{}
	mut noun_set0 := map[string]bool{}
	for nn in f.nouns {
		node_ids['noun:${nn.name}'] = node_names.len
		node_names << 'noun:${nn.name}'
		noun_set0[nn.name] = true
	}
	for v in f.verbs {
		node_ids['verb:${v.name}'] = node_names.len
		node_names << 'verb:${v.name}'
	}
	mut parent := []int{len: node_names.len, init: index}
	// Edge triples are COLLECTED first, then unioned in one plain loop —
	// no closures: a V closure captures the union-find array by value, so
	// unions inside one silently mutate a copy (found live: every node came
	// out its own component).
	mut ek := []string{}
	mut ea := []string{}
	mut eb := []string{}
	// verb ↔ noun — reads/writes
	for v in f.verbs {
		for t in v.reads {
			n0 := xap_coh_own(t, f.name)
			if n0 != '' && n0 in noun_set0 {
				ek << 'reads'
				ea << 'verb:${v.name}'
				eb << 'noun:${n0}'
			}
		}
		for t in v.writes {
			n0 := xap_coh_own(t, f.name)
			if n0 != '' && n0 in noun_set0 {
				ek << 'writes'
				ea << 'verb:${v.name}'
				eb << 'noun:${n0}'
			}
		}
		// verb ↔ verb — a derived verb's constituents (own-feature ones)
		for c in v.constituents {
			c0 := xap_coh_own(c, f.name)
			if c0 != '' {
				ek << 'constituent'
				ea << 'verb:${v.name}'
				eb << 'verb:${c0}'
			}
		}
	}
	// verb ↔ verb — ordering/dependency structured targets
	for r in f.rules {
		v0 := xap_coh_own(r.verb, f.name)
		a0 := xap_coh_own(r.after, f.name)
		q0 := xap_coh_own(r.requires, f.name)
		if v0 != '' && a0 != '' {
			ek << 'ordering'
			ea << 'verb:${v0}'
			eb << 'verb:${a0}'
		}
		if v0 != '' && q0 != '' {
			ek << 'dependency'
			ea << 'verb:${v0}'
			eb << if q0 in noun_set0 { 'noun:${q0}' } else { 'verb:${q0}' }
		}
		// noun ↔ noun — the checked nouns= list, pairwise-chained
		mut prev := ''
		for n1 in r.nouns {
			n0 := xap_coh_own(n1, f.name)
			if n0 == '' || n0 !in noun_set0 {
				continue
			}
			if prev != '' {
				ek << 'rule-nouns'
				ea << 'noun:${prev}'
				eb << 'noun:${n0}'
			}
			prev = n0
		}
	}
	// noun ↔ noun — sub-noun typing + own-feature [from …]
	for nn in f.nouns {
		for _, ftype in nn.fields {
			if ftype in noun_set0 && ftype != nn.name {
				ek << 'sub-noun'
				ea << 'noun:${nn.name}'
				eb << 'noun:${ftype}'
			}
		}
		for r0 in nn.from_refs {
			n0 := xap_coh_own(r0, f.name)
			if n0 != '' && n0 in noun_set0 {
				ek << 'from'
				ea << 'noun:${nn.name}'
				eb << 'noun:${n0}'
			}
		}
	}
	mut edges := []cx.Node{}
	for i in 0 .. ek.len {
		ai := node_ids[ea[i]] or { continue }
		bi := node_ids[eb[i]] or { continue }
		xap_coh_union(mut parent, ai, bi)
		edges << cx.Node(xap_elem('edge', [xap_attr('kind', ek[i]), xap_attr('a', ea[i]),
			xap_attr('b', eb[i])], []))
	}
	// Components: root → sorted member list; components sorted by first member.
	mut comp_members := map[int][]string{}
	for name, idx in node_ids {
		root := xap_coh_find(mut parent, idx)
		mut cur := comp_members[root] or { []string{} }
		cur << name
		comp_members[root] = cur
	}
	$if cx_coh_trace ? {
		eprintln("coh: nodes=${node_ids.len} groups=${comp_members.len}")
		for r0, ms in comp_members {
			eprintln("coh: root=${r0} members=${ms.len} ${ms}")
		}
	}
	mut comps := [][]string{}
	for _, mut members in comp_members {
		if members.len == 0 {
			continue
		}
		members.sort()
		// `comps << members` FLATTENS here (V treats an []string RHS on a
		// [][]string as append-all-elements when the value comes off a mut
		// map iteration) and corrupts memory — reproduced standalone. The
		// one-element wrap forces append-as-one; the clone detaches from
		// the map's storage.
		comps << [members.clone()]
	}
	comps.sort_with_compare(fn (a &[]string, b &[]string) int {
		if (*a).len == 0 || (*b).len == 0 {
			return (*a).len - (*b).len
		}
		return compare_strings((*a)[0], (*b)[0])
	})
	mut citems := []cx.Node{}
	for members in comps {
		mut mitems := []cx.Node{}
		for m in members {
			mitems << cx.Node(xap_elem('member', [xap_attr('kind', m.all_before(':')),
				xap_attr('name', m.all_after_first(':'))], []))
		}
		citems << cx.Node(xap_elem('component', [], mitems))
	}
	citems << edges
	return cx.Node(xap_elem('cohesion-report', [xap_attr('feature', f.name),
		xap_attr('components', comps.len.str())], citems))
}

// ── §4.3 archetype instantiation (#866, R8.5/R8.6) ───────────────────────────
// [$xap:instantiate ARCHETYPE BINDING] — PURE: an immutable, content-addressed
// [feature …] plus a tenant-owned [instance …] binding yields the EFFECTIVE
// [feature …] document, or refuses. The refinement contract is the whole
// vocabulary: rename presentation / add / tighten / select; repurposing an
// inherited name refuses CXER4877, loosening an inherited signature refuses
// CXER4878, a stale pin or malformed binding refuses CXER4879. Removal cannot
// be spelled. Compose's contract is untouched — it receives the result as an
// ordinary feature document.

const xap_err_archetype_repurpose = 'cx-err:CXER4877' // E_XAP_ARCHETYPE_REPURPOSE
const xap_err_archetype_loosen = 'cx-err:CXER4878' // E_XAP_ARCHETYPE_LOOSEN
const xap_err_instance_invalid = 'cx-err:CXER4879' // E_XAP_INSTANCE_INVALID

// xap_elem_set_attr returns the element with one attribute replaced-or-added
// (string value) — the presentation-override primitive of [rename].
fn xap_elem_set_attr(e cx.Element, name string, val string) cx.Element {
	mut out := e
	out.attrs = []cx.Attribute{}
	mut found := false
	for a in e.attrs {
		if a.name == name {
			out.attrs << cx.Attribute{
				name:  name
				value: cx.ScalarValue(val)
			}
			found = true
		} else {
			out.attrs << a
		}
	}
	if !found {
		out.attrs << cx.Attribute{
			name:  name
			value: cx.ScalarValue(val)
		}
	}
	return out
}

// xap_inst_presentation applies a [rename]'s presentation attrs
// (label/doc/summary) onto a member element.
fn xap_inst_presentation(e cx.Element, rn cx.Element) cx.Element {
	mut out := e
	for k in ['label', 'doc', 'summary'] {
		v := xap_elem_attr(rn, k)
		if v != '' {
			out = xap_elem_set_attr(out, k, v)
		}
	}
	return out
}

struct XapInstIndex {
mut:
	noun_fields map[string][]string // noun name → field names
	verbs       map[string]cx.Element
	rules       map[string]bool
}

fn xap_inst_index(arch cx.Element) XapInstIndex {
	mut ix := XapInstIndex{
		noun_fields: map[string][]string{}
		verbs:       map[string]cx.Element{}
		rules:       map[string]bool{}
	}
	if ns := xap_gc_child(arch, 'nouns') {
		for ne in xap_gc_children(ns, 'noun') {
			nn := xap_elem_attr(ne, 'name')
			mut flds := []string{}
			for fe in xap_gc_children(ne, 'field') {
				flds << xap_elem_attr(fe, 'name')
			}
			ix.noun_fields[nn] = flds
		}
	}
	if vs := xap_gc_child(arch, 'verbs') {
		for ve in xap_gc_children(vs, 'verb') {
			ix.verbs[xap_elem_attr(ve, 'name')] = ve
		}
	}
	if rs := xap_gc_child(arch, 'rules') {
		for re_ in xap_gc_children(rs, 'rule') {
			ix.rules[xap_elem_attr(re_, 'name')] = true
		}
	}
	return ix
}

// xap_inst_requalify rewrites a qualified self-reference: the archetype's
// own feature prefix follows the instance name (§4.3 — an archetype's
// internal ordering rules, constituents, and [from …] cite its OWN nouns
// and verbs by its own name; the derived feature is those same members
// under the instance's name, so the references move with it).
fn xap_inst_requalify(s string, aname string, iname string) string {
	if s.starts_with('${aname}/') {
		return '${iname}/${s.all_after_first('/')}'
	}
	return s
}

fn xap_instantiate_builtin(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(xap_err_arg_invalid, 'E_XAP: instantiate expects (archetype, binding)')
	}
	arch_n := args[0]
	inst_n := args[1]
	if !(arch_n is cx.Element && arch_n.name == 'feature') {
		return mk_err(xap_err_instance_invalid,
			'E_XAP_INSTANCE_INVALID: instantiate needs an archetype [feature …] document (§4.3)')
	}
	arch := arch_n as cx.Element
	if !(inst_n is cx.Element && inst_n.name == 'instance') {
		return mk_err(xap_err_instance_invalid,
			'E_XAP_INSTANCE_INVALID: instantiate needs an [instance …] binding document (⊢ instance.cxs, §4.3)')
	}
	inst := inst_n as cx.Element
	iname := xap_elem_attr(inst, 'name')
	pin := xap_elem_attr(inst, 'of')
	if iname == '' || pin == '' {
		return mk_err(xap_err_instance_invalid,
			'E_XAP_INSTANCE_INVALID: [instance] requires name= and of= (the archetype pin)')
	}
	addr := store_doc_hash(cx.Node(arch)) or {
		return mk_err(xap_err_instance_invalid, 'E_XAP_INSTANCE_INVALID: archetype hash failed: ${err.msg()}')
	}
	if pin != addr {
		return mk_err(xap_err_instance_invalid,
			'E_XAP_INSTANCE_INVALID: of= pins ${pin} but the archetype presented is ${addr} — an instance derives from an EXACT base (§4.3); re-bless by moving the pin deliberately')
	}
	ix := xap_inst_index(arch)
	// ── validate every refinement against the contract, collecting ops ──
	mut rn_noun := map[string]cx.Element{}
	mut rn_verb := map[string]cx.Element{}
	mut rn_field := map[string]cx.Element{} // 'noun/field' → rename el
	for rn in xap_gc_children(inst, 'rename') {
		tn := xap_elem_attr(rn, 'noun')
		tv := xap_elem_attr(rn, 'verb')
		tf := xap_elem_attr(rn, 'field')
		mut axes := 0
		if tn != '' { axes++ }
		if tv != '' { axes++ }
		if tf != '' { axes++ }
		if axes != 1 {
			return mk_err(xap_err_instance_invalid,
				'E_XAP_INSTANCE_INVALID: [rename] takes exactly one of noun=/field=/verb= (§4.3)')
		}
		if tn != '' {
			if tn !in ix.noun_fields {
				return mk_err(xap_err_archetype_repurpose,
					'E_XAP_ARCHETYPE_REPURPOSE: [rename noun=${tn}] names no noun of the archetype — a refinement of nothing is a new meaning wearing a familiar shape (§4.3)')
			}
			rn_noun[tn] = rn
		}
		if tv != '' {
			if tv !in ix.verbs {
				return mk_err(xap_err_archetype_repurpose,
					'E_XAP_ARCHETYPE_REPURPOSE: [rename verb=${tv}] names no verb of the archetype (§4.3)')
			}
			rn_verb[tv] = rn
		}
		if tf != '' {
			parts := tf.split('/')
			if parts.len != 2 || parts[0] !in ix.noun_fields || parts[1] !in ix.noun_fields[parts[0]] {
				return mk_err(xap_err_archetype_repurpose,
					'E_XAP_ARCHETYPE_REPURPOSE: [rename field=${tf}] names no field of the archetype (§4.3)')
			}
			rn_field[tf] = rn
		}
	}
	mut add_fields := map[string][]cx.Element{} // noun → new field elements
	mut add_verbs := []cx.Element{}
	mut add_rules := []cx.Element{}
	for ad in xap_gc_children(inst, 'add') {
		if fe := xap_gc_child(ad, 'field') {
			on := xap_elem_attr(ad, 'on')
			if on == '' || on !in ix.noun_fields {
				return mk_err(xap_err_archetype_repurpose,
					'E_XAP_ARCHETYPE_REPURPOSE: [add [field …]] must extend an archetype noun via on= — "${on}" names none (§4.3)')
			}
			fname := xap_elem_attr(fe, 'name')
			if fname in ix.noun_fields[on] {
				return mk_err(xap_err_archetype_repurpose,
					'E_XAP_ARCHETYPE_REPURPOSE: field "${on}/${fname}" is inherited — an [add] may not give an inherited name a different meaning (§4.3)')
			}
			mut cur := add_fields[on] or { []cx.Element{} }
			cur << fe
			add_fields[on] = cur
		}
		if ve := xap_gc_child(ad, 'verb') {
			vname := xap_elem_attr(ve, 'name')
			if vname in ix.verbs {
				return mk_err(xap_err_archetype_repurpose,
					'E_XAP_ARCHETYPE_REPURPOSE: verb "${vname}" is inherited — an [add] may not repurpose it (§4.3)')
			}
			add_verbs << ve
		}
		if re_ := xap_gc_child(ad, 'rule') {
			rname := xap_elem_attr(re_, 'name')
			if rname in ix.rules {
				return mk_err(xap_err_archetype_repurpose,
					'E_XAP_ARCHETYPE_REPURPOSE: rule "${rname}" is inherited — an [add] may not repurpose it (§4.3)')
			}
			add_rules << re_
		}
	}
	mut tightens := map[string]cx.Element{}
	for tg in xap_gc_children(inst, 'tighten') {
		tv := xap_elem_attr(tg, 'verb')
		if tv !in ix.verbs {
			return mk_err(xap_err_archetype_repurpose,
				'E_XAP_ARCHETYPE_REPURPOSE: [tighten verb=${tv}] names no verb of the archetype (§4.3)')
		}
		av := ix.verbs[tv] or { cx.Element{} }
		ne := xap_elem_attr(tg, 'effect')
		if ne != '' && xap_gc_effect_rank(ne) < xap_gc_effect_rank(xap_elem_attr(av, 'effect')) {
			return mk_err(xap_err_archetype_loosen,
				'E_XAP_ARCHETYPE_LOOSEN: verb "${tv}" effect ${xap_elem_attr(av, 'effect')} → ${ne} widens — a derivation must not weaken what it derives from (§4.3)')
		}
		nsc := xap_elem_attr(tg, 'scope')
		asc := xap_elem_attr(av, 'scope')
		if nsc != '' && asc != '' && xap_gc_scope_rank(nsc) < xap_gc_scope_rank(asc) {
			return mk_err(xap_err_archetype_loosen,
				'E_XAP_ARCHETYPE_LOOSEN: verb "${tv}" scope ${asc} → ${nsc} widens (§4.3)')
		}
		ncq := xap_elem_attr(tg, 'consequence')
		acq := xap_elem_attr(av, 'consequence')
		if ncq != '' && acq != '' && xap_gc_cons_rank(ncq) < xap_gc_cons_rank(acq) {
			return mk_err(xap_err_archetype_loosen,
				'E_XAP_ARCHETYPE_LOOSEN: verb "${tv}" consequence ${acq} → ${ncq} widens (§4.3)')
		}
		tightens[tv] = tg
	}
	mut selection := cx.Element{}
	mut has_selection := false
	if sel := xap_gc_child(inst, 'select') {
		for kid in sel.items {
			if kid is cx.Element && kid.name in ['offer', 'not-offered'] {
				sv := xap_elem_attr(kid, 'verb')
				if sv !in ix.verbs && !add_verbs.any(xap_elem_attr(it, 'name') == sv) {
					return mk_err(xap_err_archetype_repurpose,
						'E_XAP_ARCHETYPE_REPURPOSE: [select] names verb "${sv}", which the instance does not have (§4.3)')
				}
			}
		}
		selection = cx.Element{
			name:  'selection'
			items: sel.items
		}
		has_selection = true
	}
	// ── build the effective document ──
	bind_addr := store_doc_hash(cx.Node(inst)) or {
		return mk_err(xap_err_instance_invalid, 'E_XAP_INSTANCE_INVALID: binding hash failed: ${err.msg()}')
	}
	aname := xap_elem_attr(arch, 'name')
	mut eff := arch
	eff = xap_elem_set_attr(eff, 'name', iname)
	iver := xap_elem_attr(inst, 'version')
	if iver != '' {
		eff = xap_elem_set_attr(eff, 'version', iver)
	}
	mut items := []cx.Node{}
	for kid in eff.items {
		if !(kid is cx.Element) {
			items << kid
			continue
		}
		ke := kid as cx.Element
		match ke.name {
			'nouns' {
				mut nitems := []cx.Node{}
				for n0 in ke.items {
					if !(n0 is cx.Element && n0.name == 'noun') {
						nitems << n0
						continue
					}
					mut ne2 := n0 as cx.Element
					nn := xap_elem_attr(ne2, 'name')
					if rn := rn_noun[nn] {
						ne2 = xap_inst_presentation(ne2, rn)
					}
					mut kids := []cx.Node{}
					for fk in ne2.items {
						if fk is cx.Element && fk.name == 'field' {
							key := '${nn}/${xap_elem_attr(fk, 'name')}'
							if rn := rn_field[key] {
								kids << cx.Node(xap_inst_presentation(fk, rn))
								continue
							}
						}
						if fk is cx.Element && fk.name == 'from' {
							// §4.3 — [from …] self-references follow the rename
							mut fitems := []cx.Node{}
							for fi in fk.items {
								fitems << xap_str(xap_inst_requalify(xap_arg_name(fi), aname, iname))
							}
							kids << cx.Node(xap_elem('from', [], fitems))
							continue
						}
						kids << fk
					}
					for fe in add_fields[nn] or { []cx.Element{} } {
						kids << cx.Node(fe)
					}
					ne2.items = kids
					nitems << cx.Node(ne2)
				}
				items << cx.Node(xap_elem('nouns', ke.attrs, nitems))
			}
			'verbs' {
				mut vitems := []cx.Node{}
				for v0 in ke.items {
					if !(v0 is cx.Element && v0.name == 'verb') {
						vitems << v0
						continue
					}
					mut ve2 := v0 as cx.Element
					vn := xap_elem_attr(ve2, 'name')
					if rn := rn_verb[vn] {
						ve2 = xap_inst_presentation(ve2, rn)
					}
					if tg := tightens[vn] {
						for k in ['effect', 'scope', 'consequence'] {
							nv := xap_elem_attr(tg, k)
							if nv != '' {
								ve2 = xap_elem_set_attr(ve2, k, nv)
							}
						}
					}
					// §4.3 — [constituents …] self-references follow the rename
					mut vkids := []cx.Node{}
					for vk in ve2.items {
						if vk is cx.Element && vk.name == 'constituents' {
							raw := xap_gc_text_item(vk)
							mut cs := []string{}
							for c0 in xap_gc_split_names(raw) {
								cs << xap_inst_requalify(c0, aname, iname)
							}
							vkids << cx.Node(xap_elem('constituents', [], [xap_str(cs.join(' '))]))
							continue
						}
						vkids << vk
					}
					ve2.items = vkids
					vitems << cx.Node(ve2)
				}
				for ve in add_verbs {
					vitems << cx.Node(ve)
				}
				items << cx.Node(xap_elem('verbs', ke.attrs, vitems))
			}
			'rules' {
				mut ritems := []cx.Node{}
				for r0 in ke.items {
					if r0 is cx.Element && r0.name == 'rule' {
						// §4.3 — structured rule targets follow the rename
						mut re2 := r0 as cx.Element
						for k in ['verb', 'after', 'requires'] {
							v0 := xap_elem_attr(re2, k)
							if v0 != '' {
								re2 = xap_elem_set_attr(re2, k, xap_inst_requalify(v0, aname, iname))
							}
						}
						ritems << cx.Node(re2)
						continue
					}
					ritems << r0
				}
				for re_ in add_rules {
					ritems << cx.Node(re_)
				}
				add_rules = []cx.Element{}
				items << cx.Node(xap_elem('rules', ke.attrs, ritems))
			}
			else {
				items << kid
			}
		}
	}
	// an archetype with no [rules] still accepts added rules
	if add_rules.len > 0 {
		mut ritems := []cx.Node{}
		for re_ in add_rules {
			ritems << cx.Node(re_)
		}
		items << cx.Node(xap_elem('rules', [], ritems))
	}
	if has_selection {
		items << cx.Node(selection)
	}
	items << cx.Node(xap_elem('instantiated-from', [xap_attr('archetype', addr),
		xap_attr('binding', bind_addr)], []))
	eff.items = items
	return cx.Node(eff)
}

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
// stdlib/xap.cx is embedded as stdlib_src_xap in Ring-1 stdlib_bundle.v
// with the other bundle sources (relocated at I3 seam H).
