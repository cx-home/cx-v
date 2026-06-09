@[has_globals]
module code

import cx

// stdlib_bus.v — native primitives for the `cx-stdlib/bus` in-process
// publish/subscribe module (spec/02-inprogress/xap/stdlib_bus.md, band
// CXER4650–4699).
//
// The module's `[?def]` bodies (stdlib_src_bus in stdlib_bundle.v) forward
// to the `bus-*` primitives dispatched here. A `[bus]` owns an ordered,
// MUTABLE subscription list and a FIFO cascade queue — neither expressible
// as an immutable pure CX value — so each bus is a heap `BusState`
// registered in a process-global registry and referenced by an integer
// handle carried on the returned `[bus handle=N state=… …]` element. A
// `[subscription handle=N id=… …]` likewise carries its bus handle + id.
//
// CAPABILITY: bus introduces NO capability and gates nothing (§5). `bus` /
// `close` / `on` / `off` and all introspection are capability-free; `emit`
// itself reaches no OS resource (§2.3) — any effect is the HANDLER's own,
// gated at the handler's own effect point (a granted `[$store:put]` inside
// a handler succeeds; a denial surfaces as the handler's CXER0271, never a
// bus code). So no `bus-*` prim is in capability_gated_prims(); `bus-emit`
// is impure (it may invoke effectful handlers) and is therefore listed in
// effect_alignment.v::impure_without_capability_exceptions().
//
// THE ONE GUARANTEE (§4): dispatch is synchronous, deterministic, ordered
// — for a single message, matching subscribers fire in descending priority,
// ties by ascending registration order (§4.1) — with a re-entrant FIFO
// emission queue drained before the outer `emit` returns (§4.2), bounded by
// max-cascade-depth / max-cascade-events (§4.4). There is NO async mode
// (N-BUS-1): `emit sync=false` → CXER4665.
//
// emit needs the evaluator env to invoke handler closures, so it dispatches
// through bus_stdlib_builtin_env (wired in eval.v::dispatch_call_l, tried
// before the env-free chain). Every OTHER bus primitive (construction,
// subscribe, unsubscribe, introspection) is env-free and handled by
// bus_stdlib_builtin in the stdlib_dispatch.v chain.

// ── error codes (§8) ─────────────────────────────────────────────────

const bus_err_arg_invalid = 'cx-err:CXER4660' // E_BUS_ARG_INVALID
const bus_err_handle_race = 'cx-err:CXER4661' // E_BUS_HANDLE_RACE
const bus_err_duplicate_id = 'cx-err:CXER4662' // E_BUS_DUPLICATE_ID
const bus_err_cascade_limit = 'cx-err:CXER4663' // E_BUS_CASCADE_LIMIT
const bus_err_handle_closed = 'cx-err:CXER4664' // E_BUS_HANDLE_CLOSED
const bus_err_async_unsupported = 'cx-err:CXER4665' // E_BUS_ASYNC_UNSUPPORTED

// ── pattern model (§2.2) ─────────────────────────────────────────────

enum BusPatternKind {
	atom    // a topic atom; trailing `.*` is a prefix-glob
	head    // a string head-name
	pred    // a callable boolean predicate over the message tree
}

// BusPattern is the compiled form of one of the three §2.2 pattern forms.
struct BusPattern {
mut:
	kind   BusPatternKind
	// atom: the topic atom name (no leading `:`); `glob` when it ended `.*`
	// (then `text` is the prefix without the trailing `.*`).
	text   string
	glob   bool
	// pred: the predicate function VALUE (a closure sentinel node).
	pred   cx.Node
}

// ── subscription + bus state ─────────────────────────────────────────

// BusQueued is one message awaiting dispatch in the §4.2 FIFO cascade
// queue, carried with the re-entrancy depth at which it was enqueued.
struct BusQueued {
	msg   cx.Node
	depth int
}

@[heap]
struct BusSub {
mut:
	id        string
	reg_index int  // registration order (insertion index)
	priority  i64
	once      bool
	active    bool
	pattern   BusPattern
	handler   cx.Node // a function VALUE (closure sentinel)
}

@[heap]
struct BusState {
mut:
	handle      int
	open        bool
	dispatching bool
	subs        []&BusSub
	next_sub    int
	on_fault    string // :isolate | :halt | :collect
	max_depth   int
	max_events  int
	// §4.2 re-entrant cascade queue. While `dispatching`, a nested
	// `[$bus:emit]` from inside a handler ENQUEUES here (with depth+1)
	// instead of host-recursing — the outer bus_emit drains it FIFO before
	// returning. `cur_depth` is the depth of the message currently firing.
	pending     []BusQueued
	cur_depth   int
}

// BusRegistry holds every open bus keyed by integer handle. Process-global
// and impure — shared across all callers in the process (the proven
// stdlib_store.v form; @[has_globals] enables module-level state without
// the -enable-globals CLI flag).
@[heap]
struct BusRegistry {
mut:
	buses    map[int]&BusState
	next_id  int
}

__global (
	g_bus_reg voidptr
)

fn bus_reg() &BusRegistry {
	if g_bus_reg == unsafe { nil } {
		r := &BusRegistry{
			buses: map[int]&BusState{}
		}
		g_bus_reg = voidptr(r)
	}
	return unsafe { &BusRegistry(g_bus_reg) }
}

fn bus_register(b &BusState) int {
	mut reg := bus_reg()
	reg.next_id++
	id := reg.next_id
	reg.buses[id] = b
	return id
}

fn bus_lookup(id int) ?&BusState {
	reg := bus_reg()
	return reg.buses[id] or { return none }
}

// ── value helpers ────────────────────────────────────────────────────

fn bus_str(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	}
}

fn bus_atom(name string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(name)
		data_type: cx.ScalarType.atom_type
	}
}

fn bus_bool(b bool) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bool_type
	}
}

fn bus_int(i i64) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(i)
		data_type: cx.ScalarType.int_type
	}
}

fn bus_null() cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(cx.NullValue{})
		data_type: cx.ScalarType.null_type
	}
}

// bus_empty is the absence channel (§3.5 / code.md §9.1.2): the empty
// node-set, NOT `null` — a structural lookup that found nothing. KEEP
// distinct from bus_null (a successful unit return).
fn bus_empty() cx.Node {
	return cx.Element{
		name:  seq_marker_name
		items: []cx.Node{}
	}
}

fn bus_seq(items []cx.Node) cx.Node {
	return cx.Element{
		name:  seq_marker_name
		items: items
	}
}

fn bus_err(err_code string, msg string) cx.Node {
	return mk_err(err_code, msg)
}

fn bus_attr(name string, value string) cx.Attribute {
	return cx.Attribute{
		name:  name
		value: cx.ScalarValue(value)
	}
}

fn bus_attr_int(name string, value i64) cx.Attribute {
	return cx.Attribute{
		name:  name
		value: cx.ScalarValue(value)
	}
}

fn bus_attr_atom(name string, atom_name string) cx.Attribute {
	mut a := cx.Attribute{
		name:  name
		value: cx.ScalarValue(atom_name)
	}
	a.set_data_type('atom')
	return a
}

fn bus_attr_bool(name string, value bool) cx.Attribute {
	return cx.Attribute{
		name:  name
		value: cx.ScalarValue(value)
	}
}

// bus_atom_name reads an atom scalar's name (`:order.placed` → "order.placed").
fn bus_atom_name(n cx.Node) ?string {
	if n is cx.ScalarNode {
		if n.data_type == cx.ScalarType.atom_type {
			v := n.value
			if v is string {
				return v
			}
		}
	}
	return none
}

// bus_plain_string reads a string-typed (NON-atom) scalar value.
fn bus_plain_string(n cx.Node) ?string {
	if n is cx.ScalarNode {
		if n.data_type == cx.ScalarType.string_type {
			v := n.value
			if v is string {
				return v
			}
		}
	}
	return none
}

// bus_map_entries returns the entry elements of a `__cx_map__` envelope, or
// none if the node is not a map.
fn bus_map_entries(n cx.Node) ?[]cx.Node {
	if n is cx.Element {
		if n.name == map_marker_name {
			return n.items
		}
	}
	return none
}

// bus_map_value returns the value node held under a `__cx_map__` map for
// the given key, or none when absent.
fn bus_map_value(m cx.Node, key string) ?cx.Node {
	entries := bus_map_entries(m) or { return none }
	for e in entries {
		if e is cx.Element {
			if e.name == key && e.items.len > 0 {
				return e.items[0]
			}
		}
	}
	return none
}

// bus_handle_of reads the integer bus handle off a `[bus handle=N …]` or a
// `[subscription handle=N …]` element.
fn bus_handle_of(n cx.Node) ?int {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'handle' {
				return cx.scalar_value_str_public(a.value).int()
			}
		}
	}
	return none
}

// bus_sub_id_of reads the `id` attribute off a `[subscription id=… …]`
// element, or none for a non-subscription node.
fn bus_sub_id_of(n cx.Node) ?string {
	if n is cx.Element {
		if n.name == 'subscription' {
			for a in n.attrs {
				if a.name == 'id' {
					return cx.scalar_value_str_public(a.value)
				}
			}
		}
	}
	return none
}

// bus_get_open resolves a bus argument to its live BusState. Returns the
// state + an ok flag; on failure the second return is the err node:
// CXER4660 for a non-bus arg / unknown handle, CXER4664 for a closed bus.
fn bus_get_open(arg cx.Node) (&BusState, cx.Node, bool) {
	id := bus_handle_of(arg) or {
		return unsafe { nil }, bus_err(bus_err_arg_invalid, 'E_BUS_ARG_INVALID: not a [bus] handle'), false
	}
	b := bus_lookup(id) or {
		return unsafe { nil }, bus_err(bus_err_arg_invalid, 'E_BUS_ARG_INVALID: unknown bus handle ${id}'), false
	}
	if !b.open {
		return unsafe { nil }, bus_err(bus_err_handle_closed, 'E_BUS_HANDLE_CLOSED: operation on a closed bus'), false
	}
	return b, bus_null(), true
}

// ── pattern compilation + matching (§2.2) ────────────────────────────

// bus_compile_pattern turns a pattern argument value into a BusPattern, or
// returns an err node (CXER4660) for a malformed pattern. The three forms:
// an atom (topic, trailing `.*` = prefix-glob); a plain string (head-name);
// a callable function value (boolean predicate over the message).
fn bus_compile_pattern(p cx.Node) (BusPattern, cx.Node, bool) {
	if name := bus_atom_name(p) {
		// §2.2 prefix-glob. The spec writes the hierarchy with `.` and the
		// glob suffix `.*` (`:order.*`); the CX program atom grammar admits
		// neither `.` nor `*` as a NameChar (grammar.ebnf [6a]), so this
		// impl realizes the SAME prefix-glob with `-` as the hierarchy
		// separator and a TRAILING `-` as the glob marker: `:order-` matches
		// `:order-placed` / `:order-cancelled` (and `:order-` itself). The
		// semantics are identical; only the typeable spelling differs.
		if name.len > 1 && name.ends_with('-') {
			return BusPattern{
				kind: .atom
				text: name#[..-1] // strip the trailing `-` glob marker
				glob: true
			}, bus_null(), true
		}
		return BusPattern{
			kind: .atom
			text: name
			glob: false
		}, bus_null(), true
	}
	if s := bus_plain_string(p) {
		return BusPattern{
			kind: .head
			text: s
		}, bus_null(), true
	}
	if is_fn_value(p) {
		return BusPattern{
			kind: .pred
			pred: p
		}, bus_null(), true
	}
	return BusPattern{}, bus_err(bus_err_arg_invalid, 'E_BUS_ARG_INVALID: pattern must be a topic atom, a head-name string, or a predicate function'), false
}

// bus_topic_of computes a message's topic per the §2.2 derivation: the
// leading-atom argument when present, else the head name. Total.
fn bus_topic_of(msg cx.Node) ?string {
	if msg is cx.Element {
		// a leading atom argument (the `[do :verb …]` verb) is the topic.
		for it in msg.items {
			if a := bus_atom_name(it) {
				return a
			}
			// only the FIRST positional item is considered the topic atom;
			// stop at the first non-atom item.
			break
		}
		return msg.name
	}
	return none
}

// bus_pattern_matches reports whether `msg` matches `pat`. The atom/head
// forms are pure structural checks; the predicate form applies the callable
// (pure by contract, §2.2) and reads its boolean result. A predicate that
// raises or returns a non-bool is treated as non-matching (the matcher
// never faults — matching is referentially transparent, §3.4).
fn bus_pattern_matches(pat BusPattern, msg cx.Node, mut env MatchEnv) bool {
	match pat.kind {
		.atom {
			topic := bus_topic_of(msg) or { return false }
			if pat.glob {
				return topic == pat.text || topic.starts_with(pat.text + '-')
			}
			return topic == pat.text
		}
		.head {
			if msg is cx.Element {
				return msg.name == pat.text
			}
			return false
		}
		.pred {
			r := apply_fn_value(pat.pred, [msg], mut env) or { return false }
			if r is cx.ScalarNode {
				v := r.value
				if v is bool {
					return v
				}
			}
			return false
		}
	}
}

// bus_pattern_at_least_as_specific reports whether `sub_pat` (a subscriber's
// registered pattern) is at least as specific as the `query` filter pattern
// — the §3.5 `subscribers` registry query. A subscriber is selected when its
// pattern would be SELECTED-BY the query: same kind + the query is an
// equal-or-broader matcher of the subscriber's own topic/head.
fn bus_pattern_at_least_as_specific(sub_pat BusPattern, query BusPattern) bool {
	match query.kind {
		.atom {
			if sub_pat.kind != .atom {
				return false
			}
			if query.glob {
				return sub_pat.text == query.text || sub_pat.text.starts_with(query.text + '-')
					|| (sub_pat.glob && sub_pat.text.starts_with(query.text))
			}
			// exact query: only an exact subscriber on the same topic.
			return !sub_pat.glob && sub_pat.text == query.text
		}
		.head {
			return sub_pat.kind == .head && sub_pat.text == query.text
		}
		.pred {
			// predicate queries are not statically comparable — match by
			// identity only (same predicate value).
			return sub_pat.kind == .pred && nodes_equal(sub_pat.pred, query.pred)
		}
	}
}

// ── subscription element rendering ────────────────────────────────────

// bus_handle_elem builds the `[bus handle=N state=… dispatching=… on-close=…]`
// handle value returned by `bus` (§2.1).
fn bus_handle_elem(b &BusState) cx.Node {
	return cx.Element{
		name: 'bus'
		attrs: [
			bus_attr_int('handle', b.handle),
			bus_attr('state', if b.open { 'open' } else { 'closed' }),
			bus_attr_bool('dispatching', b.dispatching),
			bus_attr('on-close', 'bus/close'),
		]
	}
}

// bus_sub_elem builds the `[subscription handle=N id=… topic=… state=…
// on-close="bus/off"]` handle value returned by `on` / enumerated by
// introspection (§2.1). `topic` carries the registered pattern's atom (when
// the pattern is an atom form); head/predicate patterns omit it.
fn bus_sub_elem(b &BusState, s &BusSub) cx.Node {
	mut attrs := [
		bus_attr_int('handle', b.handle),
		bus_attr('id', s.id),
	]
	if s.pattern.kind == .atom {
		topic_atom := if s.pattern.glob { s.pattern.text + '-' } else { s.pattern.text }
		attrs << bus_attr_atom('topic', topic_atom)
	}
	attrs << bus_attr('state', if s.active { 'active' } else { 'cancelled' })
	attrs << bus_attr('on-close', 'bus/off')
	return cx.Element{
		name:  'subscription'
		attrs: attrs
	}
}

// bus_dispatch_order returns the bus's ACTIVE subscriptions in dispatch
// order (§4.1): descending priority, ties by ascending registration index.
// A stable selection sort over a copy (the sort is total + deterministic).
fn bus_dispatch_order(b &BusState) []&BusSub {
	mut active := []&BusSub{}
	for s in b.subs {
		if s.active {
			active << s
		}
	}
	// stable sort by (-priority, reg_index). reg_index is unique + ascending,
	// so the order is total and deterministic.
	active.sort_with_compare(fn (a &&BusSub, b &&BusSub) int {
		pa := (*a).priority
		pb := (*b).priority
		if pa > pb {
			return -1
		}
		if pa < pb {
			return 1
		}
		ia := (*a).reg_index
		ib := (*b).reg_index
		if ia < ib {
			return -1
		}
		if ia > ib {
			return 1
		}
		return 0
	})
	return active
}

// ── construction (§3.1) ───────────────────────────────────────────────

// bus_new constructs a fresh `[bus]` with no subscriptions, honoring the
// §3.1 opts (on-fault / max-cascade-depth / max-cascade-events). Pure
// (referentially transparent: two calls yield independent equal-shaped
// empty buses) — though it allocates a handle, it touches no OS resource.
fn bus_new(args []cx.Node) cx.Node {
	mut on_fault := 'isolate'
	mut max_depth := 1000
	mut max_events := 100000
	if args.len > 0 {
		opts := args[0]
		if _ := bus_map_entries(opts) {
			if v := bus_map_value(opts, 'on-fault') {
				if a := bus_atom_name(v) {
					if a != 'isolate' && a != 'halt' && a != 'collect' {
						return bus_err(bus_err_arg_invalid, 'E_BUS_ARG_INVALID: on-fault must be :isolate, :halt, or :collect')
					}
					on_fault = a
				}
			}
			if v := bus_map_value(opts, 'max-cascade-depth') {
				if v is cx.ScalarNode {
					iv := v.value
					if iv is i64 {
						max_depth = int(iv)
					}
				}
			}
			if v := bus_map_value(opts, 'max-cascade-events') {
				if v is cx.ScalarNode {
					iv := v.value
					if iv is i64 {
						max_events = int(iv)
					}
				}
			}
		}
	}
	mut b := &BusState{
		open:       true
		dispatching: false
		subs:       []&BusSub{}
		on_fault:   on_fault
		max_depth:  max_depth
		max_events: max_events
	}
	b.handle = bus_register(b)
	return bus_handle_elem(b)
}

// bus_close marks the bus closed and cancels every active subscription
// (§3.1). Idempotent — closing a closed bus is a no-op null. Impure only
// because it mutates handle state (no I/O).
fn bus_close(args []cx.Node) cx.Node {
	if args.len < 1 {
		return bus_err(bus_err_arg_invalid, 'E_BUS_ARG_INVALID: close expects a [bus]')
	}
	id := bus_handle_of(args[0]) or {
		return bus_err(bus_err_arg_invalid, 'E_BUS_ARG_INVALID: not a [bus] handle')
	}
	mut b := bus_lookup(id) or {
		// unknown handle is also idempotent-friendly: nothing to close.
		return bus_null()
	}
	if !b.open {
		return bus_null()
	}
	b.open = false
	for mut s in b.subs {
		s.active = false
	}
	return bus_null()
}

// ── subscribe / unsubscribe (§3.2 / §3.3) ─────────────────────────────

// bus_on registers a handler on a pattern, returning a [subscription]
// handle (§3.2). Appends to the ordered list (registration order = default
// fire order); opts.priority overrides; opts.once makes it a one-shot;
// opts.id chooses a stable id (CXER4662 if already active).
fn bus_on(args []cx.Node) cx.Node {
	if args.len < 3 {
		return bus_err(bus_err_arg_invalid, 'E_BUS_ARG_INVALID: on expects (bus, pattern, handler)')
	}
	mut b, errv, ok := bus_get_open(args[0])
	if !ok {
		return errv
	}
	pat, perr, pok := bus_compile_pattern(args[1])
	if !pok {
		return perr
	}
	handler := args[2]
	if !is_fn_value(handler) {
		return bus_err(bus_err_arg_invalid, 'E_BUS_ARG_INVALID: handler must be callable')
	}
	mut priority := i64(0)
	mut once := false
	mut chosen_id := ''
	if args.len > 3 {
		opts := args[3]
		if _ := bus_map_entries(opts) {
			if v := bus_map_value(opts, 'priority') {
				if v is cx.ScalarNode {
					iv := v.value
					if iv is i64 {
						priority = iv
					}
				}
			}
			if v := bus_map_value(opts, 'once') {
				if v is cx.ScalarNode {
					bv := v.value
					if bv is bool {
						once = bv
					}
				}
			}
			if v := bus_map_value(opts, 'id') {
				if s := scalar_string(v) {
					chosen_id = s
				}
			}
		}
	}
	if chosen_id != '' {
		for s in b.subs {
			if s.active && s.id == chosen_id {
				return bus_err(bus_err_duplicate_id, 'E_BUS_DUPLICATE_ID: subscription id `${chosen_id}` already active')
			}
		}
	}
	b.next_sub++
	reg_index := b.next_sub
	id := if chosen_id != '' { chosen_id } else { 's-${reg_index}' }
	sub := &BusSub{
		id:        id
		reg_index: reg_index
		priority:  priority
		once:      once
		active:    true
		pattern:   pat
		handler:   handler
	}
	b.subs << sub
	return bus_sub_elem(b, sub)
}

// bus_off cancels a subscription by handle or by id string (§3.3). Returns
// true iff an ACTIVE subscription was found + cancelled, false if already
// cancelled / unknown (idempotent value, never a fault). On a closed bus →
// CXER4664.
fn bus_off(args []cx.Node) cx.Node {
	if args.len < 2 {
		return bus_err(bus_err_arg_invalid, 'E_BUS_ARG_INVALID: off expects (bus, subscription|id)')
	}
	mut b, errv, ok := bus_get_open(args[0])
	if !ok {
		return errv
	}
	mut target_id := ''
	if sid := bus_sub_id_of(args[1]) {
		target_id = sid
	} else if s := scalar_string(args[1]) {
		target_id = s
	} else {
		return bus_err(bus_err_arg_invalid, 'E_BUS_ARG_INVALID: off expects a [subscription] or an id string')
	}
	for mut s in b.subs {
		if s.id == target_id {
			if s.active {
				s.active = false
				return bus_bool(true)
			}
			return bus_bool(false)
		}
	}
	return bus_bool(false)
}

// ── introspection (§3.5, pure) ────────────────────────────────────────

// bus_subscribers returns active subscriptions in dispatch order (§4.1);
// with a $pattern filter, only those whose registered pattern is at least as
// specific as the filter. Empty node-set when none (absence channel).
fn bus_subscribers(args []cx.Node) cx.Node {
	if args.len < 1 {
		return bus_err(bus_err_arg_invalid, 'E_BUS_ARG_INVALID: subscribers expects a [bus]')
	}
	b, errv, ok := bus_get_open(args[0])
	if !ok {
		return errv
	}
	ordered := bus_dispatch_order(b)
	mut has_filter := false
	mut filter := BusPattern{}
	if args.len > 1 {
		// an empty-map second arg means "no filter" (the §3.5 `{}` default);
		// a real pattern filters.
		if _ := bus_map_entries(args[1]) {
			has_filter = false
		} else {
			fp, ferr, fok := bus_compile_pattern(args[1])
			if !fok {
				return ferr
			}
			filter = fp
			has_filter = true
		}
	}
	mut out := []cx.Node{}
	for s in ordered {
		if has_filter && !bus_pattern_at_least_as_specific(s.pattern, filter) {
			continue
		}
		out << bus_sub_elem(b, s)
	}
	if out.len == 0 {
		return bus_empty()
	}
	return bus_seq(out)
}

// bus_topics returns the distinct topic atoms currently subscribed, in
// registration order of first appearance (§3.5). Head/predicate patterns
// contribute no topic atom.
fn bus_topics(args []cx.Node) cx.Node {
	if args.len < 1 {
		return bus_err(bus_err_arg_invalid, 'E_BUS_ARG_INVALID: topics expects a [bus]')
	}
	b, errv, ok := bus_get_open(args[0])
	if !ok {
		return errv
	}
	mut seen := map[string]bool{}
	mut out := []cx.Node{}
	for s in b.subs {
		if !s.active {
			continue
		}
		if s.pattern.kind == .atom {
			name := if s.pattern.glob { s.pattern.text + '-' } else { s.pattern.text }
			if name !in seen {
				seen[name] = true
				out << bus_atom(name)
			}
		}
	}
	if out.len == 0 {
		return bus_empty()
	}
	return bus_seq(out)
}

// bus_topic computes the topic atom of $msg per §2.2 (total). Returns an
// atom value.
fn bus_topic(args []cx.Node) cx.Node {
	if args.len < 1 {
		return bus_err(bus_err_arg_invalid, 'E_BUS_ARG_INVALID: topic expects a message element')
	}
	topic := bus_topic_of(args[0]) or {
		return bus_err(bus_err_arg_invalid, 'E_BUS_ARG_INVALID: topic expects a message element')
	}
	return bus_atom(topic)
}

// ── primitive dispatch ────────────────────────────────────────────────

// bus_stdlib_builtin is the env-free chain entry (stdlib_dispatch.v). It
// handles construction / subscribe / unsubscribe / and all introspection
// EXCEPT the two env-needing ones (`match` / `matches`, which evaluate
// predicate patterns) and `emit` (which invokes handlers) — those return
// none here and are taken by bus_stdlib_builtin_env (tried first in
// dispatch_call_l).
fn bus_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		'bus-close' {
			return bus_close(args)
		}
		'bus-off' {
			return bus_off(args)
		}
		'bus-subscribers' {
			return bus_subscribers(args)
		}
		'bus-topics' {
			return bus_topics(args)
		}
		'bus-topic' {
			return bus_topic(args)
		}
		else {
			return none
		}
	}
}

// ── env-aware dispatch (emit + predicate-pattern introspection) ───────

// bus_stdlib_builtin_env handles the bus primitives that need the evaluator
// env: `emit` (invokes handler closures), and `match` / `matches` (evaluate
// predicate patterns, which apply a callable). Tried before the env-free
// chain in dispatch_call_l; returns none for every other name.
fn bus_stdlib_builtin_env(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	match name {
		'bus-bus' {
			return bus_new_env(args, mut env)
		}
		'bus-on' {
			return bus_on_env(args, mut env)
		}
		'bus-emit' {
			return bus_emit(args, mut env)
		}
		'bus-match' {
			return bus_match(args, mut env)
		}
		'bus-matches' {
			return bus_matches(args, mut env)
		}
		else {
			return none
		}
	}
}

// bus_stamp_closeable registers a CloseableRecord whose close_fn fires
// `close_fn`, and returns `el` with a `__cx_close_id__` attribute appended so
// `[?with-open]` recognizes it (SAP §5.1 / code.md §8.10.7). The handle keeps
// its declared `on-close` attribute for documentation; the runtime contract
// is carried by the stamped id. `el` MUST be an `[bus]` / `[subscription]`
// element (an err value passes through unstamped).
fn bus_stamp_closeable(el cx.Node, label string, close_fn fn () !, mut env MatchEnv) cx.Node {
	if el !is cx.Element {
		return el
	}
	mut e := el as cx.Element
	if e.name == 'err' {
		return el
	}
	id := '${env.state.next_close_id}'
	env.state.next_close_id++
	env.state.closeables[id] = &CloseableRecord{
		label:    label
		closed:   false
		close_fn: close_fn
	}
	e.attrs << cx.Attribute{
		name:  close_id_attr
		value: cx.ScalarValue(id)
	}
	return cx.Node(e)
}

// bus_new_env constructs a bus (§3.1) and stamps it closeable: its close_fn
// marks the bus closed + cancels all subscriptions (= `bus/close`, §2.1),
// reached via the process-global registry (no env needed at close time).
fn bus_new_env(args []cx.Node, mut env MatchEnv) cx.Node {
	el := bus_new(args)
	hid := bus_handle_of(el) or { return el }
	return bus_stamp_closeable(el, 'bus/close', fn [hid] () ! {
		mut b := bus_lookup(hid) or { return }
		if !b.open {
			return
		}
		b.open = false
		for mut s in b.subs {
			s.active = false
		}
	}, mut env)
}

// bus_on_env subscribes (§3.2) and stamps the [subscription] closeable: its
// close_fn cancels exactly that subscription (= `bus/off`, §2.1/§3.3),
// idempotent, via the process-global registry.
fn bus_on_env(args []cx.Node, mut env MatchEnv) cx.Node {
	el := bus_on(args)
	if el is cx.Element && el.name != 'subscription' {
		// an err value (or anything not a subscription) — pass through.
		return el
	}
	hid := bus_handle_of(el) or { return el }
	sid := bus_sub_id_of(el) or { return el }
	return bus_stamp_closeable(el, 'bus/off', fn [hid, sid] () ! {
		mut b := bus_lookup(hid) or { return }
		for mut s in b.subs {
			if s.id == sid && s.active {
				s.active = false
				return
			}
		}
	}, mut env)
}

// bus_match returns the subscriptions that WOULD fire for $msg, in fire
// order, WITHOUT firing them (§3.5 dry-run). Empty node-set when none.
fn bus_match(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 2 {
		return bus_err(bus_err_arg_invalid, 'E_BUS_ARG_INVALID: match expects (bus, msg)')
	}
	b, errv, ok := bus_get_open(args[0])
	if !ok {
		return errv
	}
	msg := args[1]
	if msg !is cx.Element {
		return bus_err(bus_err_arg_invalid, 'E_BUS_ARG_INVALID: message must be an element')
	}
	ordered := bus_dispatch_order(b)
	mut out := []cx.Node{}
	for s in ordered {
		if bus_pattern_matches(s.pattern, msg, mut env) {
			out << bus_sub_elem(b, s)
		}
	}
	if out.len == 0 {
		return bus_empty()
	}
	return bus_seq(out)
}

// bus_matches reports whether $msg matches $pattern (§3.5, the bare matcher).
fn bus_matches(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 2 {
		return bus_err(bus_err_arg_invalid, 'E_BUS_ARG_INVALID: matches expects (msg, pattern)')
	}
	msg := args[0]
	if msg !is cx.Element {
		return bus_err(bus_err_arg_invalid, 'E_BUS_ARG_INVALID: message must be an element')
	}
	pat, perr, pok := bus_compile_pattern(args[1])
	if !pok {
		return perr
	}
	return bus_bool(bus_pattern_matches(pat, msg, mut env))
}

// bus_emit publishes $msg and synchronously drives the full ordered
// dispatch (§4), returning a `[dispatch …]` VALUE (§3.4). The re-entrant
// emission queue is drained FIFO before returning (§4.2), bounded by
// max-cascade-depth / max-cascade-events (§4.4). on-fault governs handler
// faults (§4.3). With zero matching subscribers it is a pure no-op
// returning `[dispatch delivered=0 …]` (§2.3). `emit sync=false` → CXER4665.
fn bus_emit(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 2 {
		return bus_err(bus_err_arg_invalid, 'E_BUS_ARG_INVALID: emit expects (bus, msg)')
	}
	mut b, errv, ok := bus_get_open(args[0])
	if !ok {
		return errv
	}
	msg := args[1]
	if msg !is cx.Element {
		return bus_err(bus_err_arg_invalid, 'E_BUS_ARG_INVALID: message must be an element')
	}
	mut on_fault := b.on_fault
	if args.len > 2 {
		opts := args[2]
		if _ := bus_map_entries(opts) {
			// `sync=false` (or any async opt) is the explicit no-fire-and-forget
			// guard (§3.4/§4.1, N-BUS-1).
			if v := bus_map_value(opts, 'sync') {
				if v is cx.ScalarNode {
					bv := v.value
					if bv is bool {
						if !bv {
							return bus_err(bus_err_async_unsupported, 'E_BUS_ASYNC_UNSUPPORTED: emit has no async mode (N-BUS-1)')
						}
					}
				}
			}
			if v := bus_map_value(opts, 'on-fault') {
				if a := bus_atom_name(v) {
					if a != 'isolate' && a != 'halt' && a != 'collect' {
						return bus_err(bus_err_arg_invalid, 'E_BUS_ARG_INVALID: on-fault must be :isolate, :halt, or :collect')
					}
					on_fault = a
				}
			}
		}
	}

	// §4.2 re-entrancy — a handler's own `[$bus:emit]` runs while the bus is
	// already `dispatching`. It is ENQUEUED on the active cascade's pending
	// list (depth+1), NOT host-recursed, and returns a deferred `[dispatch]`
	// value; the OUTER bus_emit (below) drains it. This is the breadth-first
	// FIFO drain-before-the-next-external-message guarantee.
	if b.dispatching {
		b.pending << BusQueued{
			msg:   msg
			depth: b.cur_depth + 1
		}
		// the deferred outcome is summarized when actually drained; the
		// handler's emit just reports that the message was queued.
		t := bus_topic_of(msg) or { '' }
		return bus_dispatch_value(t, 0, b.cur_depth + 1, 0, []cx.Node{}, []cx.Node{}, false)
	}

	// The topmost (external) message's topic + its delivered count + fired
	// list are reported on the [dispatch] (§3.4). Re-entrant emissions
	// contribute to events/depth/faults but not delivered/fired.
	outer_topic := bus_topic_of(msg) or { '' }

	mut queue := []BusQueued{}
	queue << BusQueued{
		msg:   msg
		depth: 0
	}
	b.pending = []BusQueued{}
	mut events := 0
	mut max_reached_depth := 0
	mut delivered := 0
	mut fired := []cx.Node{}
	mut faults := []cx.Node{}
	mut faulted := false
	mut halted := false
	mut halt_err := cx.Node(bus_null())

	b.dispatching = true

	for queue.len > 0 {
		head := queue[0]
		queue.delete(0)
		events++
		if head.depth > max_reached_depth {
			max_reached_depth = head.depth
		}
		// §4.4 caps — bound every cascade; never unbounded.
		if events > b.max_events || head.depth > b.max_depth {
			b.dispatching = false
			b.pending = []BusQueued{}
			partial := bus_dispatch_value(outer_topic, delivered, max_reached_depth,
				events - 1, fired, faults, faulted)
			mut e := bus_err(bus_err_cascade_limit, 'E_BUS_CASCADE_LIMIT: cascade exceeded max-cascade-depth/max-cascade-events')
			if e is cx.Element {
				mut ee := e as cx.Element
				ee.items << partial
				return cx.Node(ee)
			}
			return e
		}
		is_outer := head.depth == 0
		b.cur_depth = head.depth
		// §2.1/§4.2 — snapshot the matching subscribers when delivery of THIS
		// message begins; mutations during its dispatch take effect for the
		// NEXT message (an `off` of a not-yet-fired peer shrinks the live
		// list, honored below by re-checking active before firing).
		snapshot := bus_dispatch_order(b)
		mut matched := []&BusSub{}
		for s in snapshot {
			if bus_pattern_matches(s.pattern, head.msg, mut env) {
				matched << s
			}
		}
		for mut s in matched {
			// honor a mid-cascade cancel of a not-yet-fired peer (§3.3): a peer
			// that a prior handler in THIS message cancelled is skipped.
			if !s.active {
				continue
			}
			// fire the handler. Its return value is discarded (§4.5). Any
			// re-entrant emit it makes appends to b.pending (above).
			apply_fn_value(s.handler, [head.msg], mut env) or {
				// a handler raised. isolate/collect/halt it (§4.3).
				faulted = true
				if on_fault == 'collect' {
					faults << bus_err_value_of(err)
				} else if on_fault == 'halt' {
					halted = true
					halt_err = bus_err_value_of(err)
				}
				if is_outer {
					delivered++
					fired << bus_sub_elem(b, s)
				}
				once_consume(mut s)
				if halted {
					break
				}
				continue
			}
			// a handler may return an [err] VALUE (not raised) — bus treats any
			// returned value as success (§4.5), so this is NOT a fault.
			if is_outer {
				delivered++
				fired << bus_sub_elem(b, s)
			}
			once_consume(mut s)
		}
		if halted {
			break
		}
		// §4.2 — drain this message's re-entrant emissions (FIFO) into the
		// cascade queue BEFORE the next already-queued message.
		for q in b.pending {
			queue << q
		}
		b.pending = []BusQueued{}
	}

	b.dispatching = false
	b.pending = []BusQueued{}

	if halted && on_fault == 'halt' {
		// §4.3 :halt — surface the handler's [err] on the failure channel.
		return halt_err
	}

	return bus_dispatch_value(outer_topic, delivered, max_reached_depth, events,
		fired, faults, faulted)
}

// once_consume cancels a `once` subscription after it fires (§3.2). Returns
// true when it consumed (was a one-shot).
fn once_consume(mut s BusSub) bool {
	if s.once {
		s.active = false
		return true
	}
	return false
}

// bus_err_value_of normalizes a caught EvalError (or any error) into an
// `err` element VALUE for the §4.3 fault record / :halt surface.
fn bus_err_value_of(e IError) cx.Node {
	if e is EvalError {
		return mk_err_quiet(e.code, e.message)
	}
	return mk_err_quiet('cx-err:CXER0001', e.msg())
}

// bus_dispatch_value builds the `[dispatch delivered=N topic=… depth=D
// events=E [fired …] [faults …]]` value (§3.4). `faulted` is carried as an
// attribute so :isolate callers can observe a fault occurred without
// :collect.
fn bus_dispatch_value(topic string, delivered int, depth int, events int, fired []cx.Node, faults []cx.Node, faulted bool) cx.Node {
	mut attrs := [
		bus_attr_int('delivered', delivered),
	]
	if topic != '' {
		attrs << bus_attr_atom('topic', topic)
	}
	attrs << bus_attr_int('depth', depth)
	attrs << bus_attr_int('events', events)
	attrs << bus_attr_bool('faulted', faulted)
	mut items := []cx.Node{}
	items << cx.Element{
		name:  'fired'
		items: fired
	}
	items << cx.Element{
		name:  'faults'
		items: faults
	}
	return cx.Element{
		name:  'dispatch'
		attrs: attrs
		items: items
	}
}
