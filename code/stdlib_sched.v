@[has_globals]
module code

import cx

// stdlib_sched.v — native primitives + in-process registry for the
// `cx-stdlib/sched` durable scheduler (spec/02-working/stdlib_sched.md).
//
// sched is a THIN module over the picoev timer wheel that COMPOSES three
// shipped modules and adds NO calendar grammar, NO persistence mechanism, and
// NO new capability of its own (§0/§5):
//   - cx-stdlib/time  — every relative verb takes a ::duration (i64 ns scalar);
//     `at` takes a ::datetime; `recur` consumes a [recurrence …] value and
//     re-arms via `time-next-occurrence` (COUNT/UNTIL honored); `cron` parses
//     a cron string via `time-parse-cron` → [recurrence …]. sched does NO
//     date/calendar arithmetic — it asks `time` for the next instant.
//   - cx-stdlib/journal — the `durable` opt persists timer intent+schedule to a
//     caller-supplied [journal] (journal-append); `restore` folds the journal
//     (journal-fold-value over the materialized entries) to re-arm pending
//     timers. sched composes journal-over-store; it adds no store of its own.
//   - the picoev event loop — the LIVE held-open firing loop is the synthetic-
//     transport part (gate=pending, like net/http live paths). The
//     DETERMINISTIC surface implemented + enforced here is: compute next fire
//     from a rule+now, the schedule registry, due-set queries given a pinned
//     `now`, and the `:manual` test clock drain. Any clock read is the caller's
//     pinned virtual `now` (pure), mirroring time's recurrence design.
//
// CLOCK MODEL. The loop clock mode is process/loop-scoped and set at loop
// construction by the harness (§2.6/§3.3) — there is no public verb to flip a
// live production loop to `:manual`. This evaluator IS the conformance/embedding
// loop; it runs the timer wheel under a `:manual` virtual clock by default
// (virtual-now is an absolute ns-since-epoch instant, starting at 0). Under
// `:manual`, timers fire only when `test-clock-advance` moves virtual-now past
// their deadline, in deadline order, deterministically and sleep-free (§4.2).
// `test-clock-advance` under the production `:wall` clock → CXER4970.
//
// FOUR-CHANNEL MODEL (code.md §9.1.2, spec §0):
//   armed/fired/canceled timer  → a present [timer] VALUE (value channel)
//   bad arg / mode / durable     → [err] (failure channel) in the CXER49xx band
//   COUNT/UNTIL exhaustion       → the NORMAL terminal "fired" transition (a
//                                  value), NOT a fault
//   orphaned durable intent      → a present finding in the [restore-report …]
//                                  VALUE, never silently dropped
//   timer-state of present handle → a value; sched never returns null for absence
//
// FIRING. Firing is one of two effects chosen by $ev's shape (§2.1):
//   - a zero-arg callable (closure sentinel) → invoked on the loop (return
//     ignored). A raw effect in the callback without a live grant hits CXER0271
//     at the callback's effect point (§4.1) — sched grants nothing.
//   - a [?channel] value (channel-handle element) → a tick posted to its queue.
// Because firing applies a CX callable / touches the channel queue, the firing
// verbs (test-clock-advance) reach sched via sched_stdlib_builtin_env(name,
// args, mut env) from the env-aware dispatch path in eval.v (alongside
// journal/bus); every non-firing verb routes through the env-free
// sched_stdlib_builtin(name, args) chain in stdlib_dispatch.v.

// ── error band CXER4970–4989 (spec §8) ───────────────────────────────────

const sch_err_test_clock     = 'cx-err:CXER4970' // E_SCHED_TEST_CLOCK
const sch_err_arg_invalid    = 'cx-err:CXER4971' // E_SCHED_ARG_INVALID
const sch_err_mode_invalid   = 'cx-err:CXER4972' // E_SCHED_MODE_INVALID
const sch_err_durable_no_name = 'cx-err:CXER4973' // E_SCHED_DURABLE_NO_NAME
const sch_err_durable_no_jrn = 'cx-err:CXER4974' // E_SCHED_DURABLE_NO_JOURNAL
const sch_err_restore_intent = 'cx-err:CXER4975' // E_SCHED_RESTORE_INTENT

// ── timer kinds + states ──────────────────────────────────────────────────

const sch_kind_after = 'after'
const sch_kind_at    = 'at'
const sch_kind_every = 'every'
const sch_kind_recur = 'recur'
const sch_kind_cron  = 'cron'

const sch_state_armed    = 'armed'
const sch_state_fired    = 'fired'
const sch_state_canceled = 'canceled'

const sch_mode_fixed_delay = 'fixed-delay'
const sch_mode_fixed_rate  = 'fixed-rate'

const sch_miss_skip     = 'skip'
const sch_miss_coalesce = 'coalesce'
const sch_miss_fire_all = 'fire-all'

// ── registry ──────────────────────────────────────────────────────────────

// SchedTimer is the in-process state for one armed [timer] handle. A timer is
// mutable in-process state (its deadline advances across re-arms, its state
// flips on fire/cancel) which cannot be a pure CX value, so — exactly like
// store/journal — each timer is a heap record in a process-global registry
// referenced by an integer handle carried on the returned [timer handle=N …].
@[heap]
struct SchedTimer {
mut:
	id        int
	kind      string // after | at | every | recur | cron
	state     string // armed | fired | canceled
	name      string
	deadline  i64  // virtual ns-since-epoch instant of the next fire
	dur_ns    i64  // for after/every: the relative period
	mode      string // fixed-delay | fixed-rate
	on_missed string // skip | coalesce | fire-all
	anchor_ns i64  // for every:fixed-rate — the arm instant t0 (grid anchor)
	arm_seq   int  // tie-break for deadline ordering (arm order)
	// recurrence (recur/cron): the [recurrence …] rule value + the last-fire
	// cursor (an ISO datetime string) handed to time-next-occurrence.
	rule       cx.Node
	last_fire  string // ISO datetime of the last occurrence consumed
	has_rule   bool
	// fire value: a closure sentinel (callable) or a channel-handle element.
	// Never serialized for durability (a callable/channel is not data) — only
	// the `name` descriptor is persisted; restore rebinds by name (§3.2).
	ev         cx.Node
	// durable: the [journal] handle this timer's intent/progress is persisted
	// to (cx.Element{} when non-durable).
	durable    bool
	journal    cx.Node
}

@[heap]
struct SchedRegistry {
mut:
	timers     map[int]&SchedTimer
	next_id    int
	arm_seq    int
	// virtual clock (the :manual test clock). virtual_now is an absolute
	// ns-since-epoch instant. `wall` records the production posture for the
	// CXER4970 negative — this evaluator loop runs :manual.
	clock_mode string // "manual" | "wall"
	virtual_now i64
}

__global (
	g_sched_reg voidptr
)

fn sched_reg() &SchedRegistry {
	if g_sched_reg == unsafe { nil } {
		r := &SchedRegistry{
			timers:      map[int]&SchedTimer{}
			next_id:     0
			arm_seq:     0
			clock_mode:  'manual'
			virtual_now: 0
		}
		g_sched_reg = voidptr(r)
	}
	return unsafe { &SchedRegistry(g_sched_reg) }
}

// sched_reset_state clears the process-global timer registry + virtual clock
// between programs (called from new_env in matcher.v, mirroring
// session_reset_state). Without this a timer armed in one fixture would leak
// into the next, breaking determinism.
fn sched_reset_state() {
	mut r := sched_reg()
	r.timers = map[int]&SchedTimer{}
	r.next_id = 0
	r.arm_seq = 0
	r.clock_mode = 'manual'
	r.virtual_now = 0
}

fn sched_lookup(id int) ?&SchedTimer {
	r := sched_reg()
	t := r.timers[id] or { return none }
	return t
}

// ── scalar / arg helpers ───────────────────────────────────────────────────

fn sch_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return none
}

fn sch_arg_int(n cx.Node) ?i64 {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			i64 { return v }
			f64 { return i64(v) }
			string {
				// a ::duration literal carries its text ('100ms', '10m', '1s',
				// '2h') — as does the quoted "10m" form (§3); parse it to ns.
				return duration_to_ns(v)
			}
			else {}
		}
	}
	return none
}

fn sch_str(v string) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(v), data_type: cx.ScalarType.string_type }
}

fn sch_bool(v bool) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(v), data_type: cx.ScalarType.bool_type }
}

fn sch_int(v i64) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(v), data_type: cx.ScalarType.int_type }
}

// sch_absence is the empty node-set () — the absence channel (§0). sched never
// returns null for absence.
fn sch_absence() cx.Node {
	return cx.Element{}
}

// sch_map_get reads a value-bearing key from a `{k: v}` map literal — a
// `__cx_map__`/`map` marker element whose entries are child elements named by
// the key (eval.v eval_map), with an attribute-form fallback. Mirrors
// jrn_map_get. Returns the raw node so atoms/handles/strings round-trip.
fn sch_map_get_node(m cx.Node, key string) ?cx.Node {
	if m is cx.Element {
		if m.name == '__cx_map__' || m.name == 'map' {
			for it in m.items {
				if it is cx.Element && it.name == key {
					if it.items.len > 0 {
						return it.items[0]
					}
					return cx.Element{}
				}
			}
		}
	}
	return none
}

fn sch_map_get_str(m cx.Node, key string) ?string {
	n := sch_map_get_node(m, key) or { return none }
	if n is cx.ScalarNode {
		return cx.scalar_value_str_public(n.value)
	}
	return none
}

// sch_atom_of reads an atom value (`:foo` → "foo"). Atoms render with a leading
// colon; the scalar value holds the bare name.
fn sch_atom_of(n cx.Node) ?string {
	if n is cx.ScalarNode && n.data_type == cx.ScalarType.atom_type {
		v := n.value
		if v is string {
			return v
		}
	}
	return none
}

fn sch_map_get_atom(m cx.Node, key string) ?string {
	n := sch_map_get_node(m, key) or { return none }
	return sch_atom_of(n)
}

fn sch_map_has(m cx.Node, key string) bool {
	if _ := sch_map_get_node(m, key) {
		return true
	}
	return false
}

// ── $ev shape (§2.1) ───────────────────────────────────────────────────────

// sch_ev_is_callable reports whether $ev is a zero-arg callable (closure
// sentinel). A builtin/partial closure sentinel also qualifies.
fn sch_ev_is_callable(n cx.Node) bool {
	return is_fn_value(n)
}

// sch_ev_is_channel reports whether $ev is a [?channel] value (channel-handle).
fn sch_ev_is_channel(n cx.Node) bool {
	return n is cx.Element && (n as cx.Element).name == 'channel-handle'
}

fn sch_ev_valid(n cx.Node) bool {
	return sch_ev_is_callable(n) || sch_ev_is_channel(n)
}

// ── canonical datetime <-> instant (composing time's TDateTime core) ─────────
// sched does NO calendar math; these reuse the shared time helpers
// (decode_datetime / dt_from_instant / instant_ns) for at/recur deadlines.

fn sch_datetime_to_instant(n cx.Node) ?i64 {
	dt := decode_datetime(n) or { return none }
	return dt.instant_ns()
}

fn sch_instant_to_datetime_node(instant i64) cx.Node {
	dt := dt_from_instant(instant, 0)
	return cx.ScalarNode{
		value:     cx.ScalarValue(dt.datetime_string())
		data_type: cx.ScalarType.datetime_type
	}
}

// ── [timer] handle value ────────────────────────────────────────────────────

fn sch_timer_handle(t &SchedTimer) cx.Node {
	mut attrs := [
		cx.Attribute{ name: 'handle', value: cx.ScalarValue(i64(t.id)) },
		cx.Attribute{ name: 'kind', value: cx.ScalarValue(t.kind) },
		cx.Attribute{ name: 'state', value: cx.ScalarValue(t.state) },
		cx.Attribute{ name: 'name', value: cx.ScalarValue(t.name) },
		// the closeable-handle contract (SAP §5.1): close ≡ cancel.
		cx.Attribute{ name: 'on-close', value: cx.ScalarValue('sched/close') },
	]
	if t.durable {
		attrs << cx.Attribute{ name: 'durable', value: cx.ScalarValue('true') }
	}
	return cx.Element{ name: 'timer', attrs: attrs }
}

// sch_handle_of reads the integer timer handle off a [timer handle=N …].
fn sch_handle_of(n cx.Node) ?int {
	if n is cx.Element && n.name == 'timer' {
		for a in n.attrs {
			if a.name == 'handle' {
				return int(cx.scalar_value_str_public(a.value).i64())
			}
		}
	}
	return none
}

// ── opts parsing (shared by all arming verbs, §3.1) ──────────────────────────

struct SchedOpts {
mut:
	name      string
	has_name  bool
	mode      string
	on_missed string
	durable   bool
	journal   cx.Node
}

// sch_parse_opts validates the shared $opts map. Returns an err node on a bad
// mode/on-missed value (CXER4972) or a durable-without-journal / durable-
// without-name violation (CXER4974 / CXER4973).
fn sch_parse_opts(opts cx.Node) (SchedOpts, cx.Node, bool) {
	mut o := SchedOpts{
		mode:      sch_mode_fixed_delay
		on_missed: sch_miss_skip
		journal:   cx.Element{}
	}
	if nm := sch_map_get_str(opts, 'name') {
		o.name = nm
		o.has_name = true
	}
	if m := sch_map_get_atom(opts, 'mode') {
		if m !in [sch_mode_fixed_delay, sch_mode_fixed_rate] {
			return o, mk_err(sch_err_mode_invalid, 'E_SCHED_MODE_INVALID: mode must be :fixed-delay or :fixed-rate, got :${m}'), false
		}
		o.mode = m
	}
	if om := sch_map_get_atom(opts, 'on-missed') {
		if om !in [sch_miss_skip, sch_miss_coalesce, sch_miss_fire_all] {
			return o, mk_err(sch_err_mode_invalid, 'E_SCHED_MODE_INVALID: on-missed must be :skip, :coalesce or :fire-all, got :${om}'), false
		}
		o.on_missed = om
	}
	// durable: bool OR a [journal] handle.
	if sch_map_has(opts, 'durable') {
		dn := sch_map_get_node(opts, 'durable') or { cx.Element{} }
		if dn is cx.Element && dn.name == 'journal' {
			o.durable = true
			o.journal = dn
		} else if dn is cx.ScalarNode {
			v := dn.value
			if v is bool {
				o.durable = v
			} else if v is string {
				o.durable = v == 'true'
			}
			// a bare `true` requires a loop-config journal; this loop has none,
			// so a bare durable:true with no journal is CXER4974.
			if o.durable {
				return o, mk_err(sch_err_durable_no_jrn, 'E_SCHED_DURABLE_NO_JOURNAL: durable: true requires a [journal] handle (no loop-config journal available)'), false
			}
		}
		if o.durable && !o.has_name {
			return o, mk_err(sch_err_durable_no_name, 'E_SCHED_DURABLE_NO_NAME: a durable timer must be named (the registry key on restore)'), false
		}
	}
	return o, sch_absence(), true
}

// sch_synthesize_name labels an unnamed timer for diagnostics.
fn sch_synthesize_name(id int) string {
	return 'timer-${id}'
}

// ── arming: register a timer in the registry ─────────────────────────────────

// sch_register builds a SchedTimer, persists its durable intent if requested,
// and returns the [timer] handle. `deadline` is the absolute virtual instant of
// the first fire.
fn sch_register(kind string, deadline i64, dur_ns i64, ev cx.Node, o SchedOpts, rule cx.Node, has_rule bool, last_fire string) cx.Node {
	mut r := sched_reg()
	r.next_id++
	r.arm_seq++
	id := r.next_id
	name := if o.has_name { o.name } else { sch_synthesize_name(id) }
	// Name is the registry IDENTITY for an explicitly-named timer (§3.2 — a
	// durable timer MUST be named, and `restore` rebinds by name). Replace any
	// live timer of the same name rather than leaking a DUPLICATE: without this
	// a second `restore` (or worker-recycle) re-armed every intent again,
	// producing two live timers per name that both fire — making the §2.4
	// worker-recycle contract wrong and unverifiable.
	if o.has_name {
		mut stale := []int{}
		for eid, et in r.timers {
			if et.name == name {
				stale << eid
			}
		}
		for eid in stale {
			r.timers.delete(eid)
		}
	}
	mut t := &SchedTimer{
		id:        id
		kind:      kind
		state:     sch_state_armed
		name:      name
		deadline:  deadline
		dur_ns:    dur_ns
		mode:      o.mode
		on_missed: o.on_missed
		anchor_ns: r.virtual_now
		arm_seq:   r.arm_seq
		rule:      rule
		last_fire: last_fire
		has_rule:  has_rule
		ev:        ev
		durable:   o.durable
		journal:   o.journal
	}
	r.timers[id] = t
	if t.durable {
		sch_persist_intent(t)
	}
	return sch_timer_handle(t)
}

// ── arming verbs (§3.1) ──────────────────────────────────────────────────────

fn sch_after(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: after expects ($dur, $ev)')
	}
	dur := sch_arg_int(args[0]) or {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: after expects a ::duration')
	}
	if dur <= 0 {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: $dur must be a positive ::duration')
	}
	if !sch_ev_valid(args[1]) {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: $ev must be a zero-arg callable or a [?channel]')
	}
	opts := if args.len > 2 { args[2] } else { cx.Node(cx.Element{ name: 'map' }) }
	o, errn, ok := sch_parse_opts(opts)
	if !ok {
		return errn
	}
	r := sched_reg()
	return sch_register(sch_kind_after, r.virtual_now + dur, dur, args[1], o, cx.Element{}, false, '')
}

fn sch_at(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: at expects ($when, $ev)')
	}
	instant := sch_datetime_to_instant(args[0]) or {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: at expects a ::datetime $when')
	}
	if !sch_ev_valid(args[1]) {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: $ev must be a zero-arg callable or a [?channel]')
	}
	opts := if args.len > 2 { args[2] } else { cx.Node(cx.Element{ name: 'map' }) }
	o, errn, ok := sch_parse_opts(opts)
	if !ok {
		return errn
	}
	return sch_register(sch_kind_at, instant, 0, args[1], o, cx.Element{}, false, '')
}

fn sch_every(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: every expects ($dur, $ev)')
	}
	dur := sch_arg_int(args[0]) or {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: every expects a ::duration')
	}
	if dur <= 0 {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: $dur must be a positive ::duration')
	}
	if !sch_ev_valid(args[1]) {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: $ev must be a zero-arg callable or a [?channel]')
	}
	opts := if args.len > 2 { args[2] } else { cx.Node(cx.Element{ name: 'map' }) }
	o, errn, ok := sch_parse_opts(opts)
	if !ok {
		return errn
	}
	r := sched_reg()
	return sch_register(sch_kind_every, r.virtual_now + dur, dur, args[1], o, cx.Element{}, false, '')
}

fn sch_recur(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: recur expects ($rule, $ev)')
	}
	rule := args[0]
	if !(rule is cx.Element && (rule as cx.Element).name == 'recurrence') {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: recur expects a [recurrence …] $rule')
	}
	if !sch_ev_valid(args[1]) {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: $ev must be a zero-arg callable or a [?channel]')
	}
	opts := if args.len > 2 { args[2] } else { cx.Node(cx.Element{ name: 'map' }) }
	o, errn, ok := sch_parse_opts(opts)
	if !ok {
		return errn
	}
	return sch_arm_recurrence(rule, args[1], o)
}

fn sch_cron(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: cron expects ($expr, $ev)')
	}
	expr := sch_arg_str(args[0]) or {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: cron expects a string $expr')
	}
	if !sch_ev_valid(args[1]) {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: $ev must be a zero-arg callable or a [?channel]')
	}
	opts := if args.len > 2 { args[2] } else { cx.Node(cx.Element{ name: 'map' }) }
	o, errn, ok := sch_parse_opts(opts)
	if !ok {
		return errn
	}
	// parse the cron string via time → [recurrence …]; a malformed $expr
	// surfaces time's parse fault UNCHANGED (§2.3/§8 — not a sched code).
	tz := cx.Node(sch_str('UTC'))
	rule := time_stdlib_builtin('time-parse-cron', [sch_str(expr), tz, cx.Element{ name: 'map' }]) or {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: cron parse failed')
	}
	if is_err_value(rule) {
		return rule
	}
	return sch_arm_recurrence(rule, args[1], o)
}

// sch_arm_recurrence arms a recur/cron timer: the first fire is the first
// occurrence AT-OR-AFTER now. `time-next-occurrence` returns the first
// occurrence STRICTLY after its cursor, so we probe with a cursor one second
// before now to include an occurrence landing exactly at now (occurrences are
// at least minute-spaced in practice). When `time` reports absence (no
// occurrence after now), the timer is born terminal "fired" (it does not arm).
fn sch_arm_recurrence(rule cx.Node, ev cx.Node, o SchedOpts) cx.Node {
	r := sched_reg()
	probe_instant := r.virtual_now - ns_per_s
	now_dt := sch_instant_to_datetime_node(probe_instant)
	next := time_stdlib_builtin('time-next-occurrence', [rule, now_dt]) or {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: recurrence has no next occurrence')
	}
	if is_err_value(next) {
		return next
	}
	if sch_is_absence(next) {
		// no occurrence after now: terminal at arm.
		mut tt := &SchedTimer{
			id:        0
			kind:      sch_kind_recur
			state:     sch_state_fired
			name:      if o.has_name { o.name } else { 'recur' }
			has_rule:  true
			rule:      rule
			mode:      o.mode
			on_missed: o.on_missed
		}
		mut rg := sched_reg()
		rg.next_id++
		rg.arm_seq++
		tt.id = rg.next_id
		tt.arm_seq = rg.arm_seq
		rg.timers[tt.id] = tt
		return sch_timer_handle(tt)
	}
	first_instant := sch_datetime_to_instant(next) or { r.virtual_now }
	first_iso := sch_arg_str(next) or { '' }
	return sch_register(sch_kind_recur, first_instant, 0, ev, o, rule, true, first_iso)
}

fn sch_is_absence(n cx.Node) bool {
	return n is cx.Element && (n as cx.Element).name == '' && (n as cx.Element).items.len == 0
}

// ── cancel / state (§3.1) ────────────────────────────────────────────────────

// sch_cancel returns true iff the timer was armed (the fire was prevented),
// false if it had already fired or been canceled (idempotent — never CXER0108).
fn sch_cancel(args []cx.Node) cx.Node {
	if args.len < 1 {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: cancel expects a [timer] handle')
	}
	id := sch_handle_of(args[0]) or {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: cancel expects a [timer] handle')
	}
	mut t := sched_lookup(id) or {
		// unknown handle → benign no-op false (idempotent total cancel, §4.4).
		return sch_bool(false)
	}
	if t.state != sch_state_armed {
		return sch_bool(false)
	}
	t.state = sch_state_canceled
	if t.durable {
		sch_persist_closed(t, 'canceled')
	}
	return sch_bool(true)
}

fn sch_timer_state(args []cx.Node) cx.Node {
	if args.len < 1 {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: timer-state expects a [timer] handle')
	}
	id := sch_handle_of(args[0]) or {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: timer-state expects a [timer] handle')
	}
	t := sched_lookup(id) or {
		// a [timer] value whose registry record is gone reads as its embedded
		// attr (handles round-trip as values). Fall back to the handle's attr.
		if args[0] is cx.Element {
			el := args[0] as cx.Element
			s := el.attr('state')
			if s != '' {
				return sch_str(s)
			}
		}
		return sch_str(sch_state_fired)
	}
	return sch_str(t.state)
}

fn sch_clock_mode(args []cx.Node) cx.Node {
	r := sched_reg()
	return sch_str(':' + r.clock_mode)
}

// ── durability (§3.2): persist intent / progress to the journal ──────────────
// sched appends descriptor entries via journal-append; the fire value itself is
// NEVER serialized (a callable/channel is not data) — only its `name`.

fn sch_persist_intent(t &SchedTimer) {
	if t.journal is cx.Element && (t.journal as cx.Element).name != 'journal' {
		return
	}
	mut items := []cx.Node{}
	items << cx.Element{ name: 'kind', items: [sch_str(t.kind)] }
	items << cx.Element{ name: 'name', items: [sch_str(t.name)] }
	items << cx.Element{ name: 'deadline', items: [sch_int(t.deadline)] }
	items << cx.Element{ name: 'dur-ns', items: [sch_int(t.dur_ns)] }
	items << cx.Element{ name: 'mode', items: [sch_str(t.mode)] }
	items << cx.Element{ name: 'on-missed', items: [sch_str(t.on_missed)] }
	items << cx.Element{ name: 'status', items: [sch_str('pending')] }
	if t.has_rule {
		items << cx.Element{ name: 'rule', items: [t.rule] }
		items << cx.Element{ name: 'last-fire', items: [sch_str(t.last_fire)] }
	}
	intent := cx.Element{ name: 'sched-intent', items: items }
	attribution := cx.Element{ name: 'map', items: [
		cx.Element{ name: 'actor', items: [sch_str('sched')] },
		cx.Element{ name: 'authority', items: [sch_str('sched/durable')] },
	] }
	journal_stdlib_builtin('journal-append', [t.journal, intent, attribution]) or { return }
}

fn sch_persist_closed(t &SchedTimer, status string) {
	if t.journal is cx.Element && (t.journal as cx.Element).name != 'journal' {
		return
	}
	closed := cx.Element{ name: 'sched-intent', items: [
		cx.Element{ name: 'name', items: [sch_str(t.name)] },
		cx.Element{ name: 'status', items: [sch_str(status)] },
	] }
	attribution := cx.Element{ name: 'map', items: [
		cx.Element{ name: 'actor', items: [sch_str('sched')] },
		cx.Element{ name: 'authority', items: [sch_str('sched/durable')] },
	] }
	journal_stdlib_builtin('journal-append', [t.journal, closed, attribution]) or { return }
}

// ── env-free dispatch chain ──────────────────────────────────────────────────
// cancel / timer-state / clock-mode touch only the process-global registry.
// The arming verbs (after/at/every/recur/cron) are env-AWARE so they can stamp
// the returned [timer] handle closeable ([?with-open], SAP §5.1), and restore /
// test-clock-advance are env-aware because they fire $ev callables.

fn sched_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		'sched-cancel' {
			return sch_cancel(args)
		}
		'sched-timer-state' {
			return sch_timer_state(args)
		}
		'sched-clock-mode' {
			return sch_clock_mode(args)
		}
		else {
			return none
		}
	}
}

// ── env-aware dispatch chain (closeable stamp / firing applies $ev) ──────────

fn sched_stdlib_builtin_env(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	match name {
		'sched-after' {
			return sch_stamp_timer(sch_after(args), mut env)
		}
		'sched-at' {
			return sch_stamp_timer(sch_at(args), mut env)
		}
		'sched-every' {
			return sch_stamp_timer(sch_every(args), mut env)
		}
		'sched-recur' {
			return sch_stamp_timer(sch_recur(args), mut env)
		}
		'sched-cron' {
			return sch_stamp_timer(sch_cron(args), mut env)
		}
		'sched-test-clock-advance' {
			return sch_test_clock_advance(args, mut env)
		}
		'sched-restore' {
			return sch_restore(args, mut env)
		}
		else {
			return none
		}
	}
}

// sch_stamp_timer registers a CloseableRecord whose close_fn cancels the timer
// by handle id, and appends a `__cx_close_id__` attr so [?with-open] recognizes
// the [timer] (SAP §5.1 / code.md §8.10.7). close ≡ cancel — idempotent, never
// CXER0108. An err value (a faulted arm) passes through unstamped.
fn sch_stamp_timer(el cx.Node, mut env MatchEnv) cx.Node {
	if el !is cx.Element {
		return el
	}
	mut e := el as cx.Element
	if e.name == 'err' {
		return el
	}
	hid := sch_handle_of(e) or { return el }
	id := '${env.state.next_close_id}'
	env.state.next_close_id++
	env.state.closeables[id] = &CloseableRecord{
		label:    'sched/close'
		closed:   false
		close_fn: fn [hid] () ! {
			mut t := sched_lookup(hid) or { return }
			if t.state != sch_state_armed {
				return
			}
			t.state = sch_state_canceled
			if t.durable {
				sch_persist_closed(t, 'canceled')
			}
		}
	}
	e.attrs << cx.Attribute{
		name:  close_id_attr
		value: cx.ScalarValue(id)
	}
	return cx.Node(e)
}

// ── test-clock-advance (§3.3 / §4.6) ─────────────────────────────────────────
// Advance the manual virtual clock by $dur and DRAIN all timers whose deadline
// is now ≤ virtual-now, in DEADLINE ORDER (ties by arm order), firing each
// deterministically. A recurring timer re-arms against virtual time; how many
// of its crossed occurrences fire follows its on-missed policy (§2.5).

fn sch_test_clock_advance(args []cx.Node, mut env MatchEnv) ?cx.Node {
	r := sched_reg()
	if r.clock_mode != 'manual' {
		return mk_err(sch_err_test_clock, 'E_SCHED_TEST_CLOCK: test-clock-advance is a test-harness control; not available under the production :wall clock')
	}
	if args.len < 1 {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: test-clock-advance expects a ::duration')
	}
	dur := sch_arg_int(args[0]) or {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: test-clock-advance expects a ::duration')
	}
	if dur < 0 {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: test-clock-advance $dur must be non-negative')
	}
	target := r.virtual_now + dur
	// Drain loop: repeatedly find the earliest due armed timer (deadline ≤
	// target), advance virtual-now to its deadline, and fire it. A re-arming
	// timer may push a new deadline still ≤ target, so the loop re-scans until
	// no armed timer is due. The loop is bounded by a fire budget to bound a
	// pathological infinite recurrence under one advance.
	mut budget := 100000
	for budget > 0 {
		budget--
		due_id, due_deadline := sch_earliest_due(target)
		if due_id == 0 {
			break
		}
		mut rr := sched_reg()
		if due_deadline > rr.virtual_now {
			rr.virtual_now = due_deadline
		}
		sch_fire_due(due_id, target, mut env)
	}
	mut rg := sched_reg()
	rg.virtual_now = target
	// the verb returns null (§3.3).
	return cx.ScalarNode{ value: cx.ScalarValue(cx.NullValue{}), data_type: cx.ScalarType.null_type }
}

// sch_earliest_due finds the armed timer with the smallest deadline ≤ target,
// breaking ties by arm order. Returns (0, 0) when none is due.
fn sch_earliest_due(target i64) (int, i64) {
	r := sched_reg()
	mut best_id := 0
	mut best_deadline := i64(0)
	mut best_seq := int(0)
	for id, t in r.timers {
		if t.state != sch_state_armed {
			continue
		}
		if t.deadline > target {
			continue
		}
		if best_id == 0 || t.deadline < best_deadline
			|| (t.deadline == best_deadline && t.arm_seq < best_seq) {
			best_id = id
			best_deadline = t.deadline
			best_seq = t.arm_seq
		}
	}
	return best_id, best_deadline
}

// sch_fire_due fires the timer `id` (currently due) and re-arms it per its kind
// + on-missed policy. `target` is the advance ceiling (for catch-up math).
fn sch_fire_due(id int, target i64, mut env MatchEnv) {
	mut t := sched_lookup(id) or { return }
	if t.state != sch_state_armed {
		return
	}
	match t.kind {
		sch_kind_after, sch_kind_at {
			// one-shot: fire once, terminal.
			sch_invoke(t, mut env)
			t.state = sch_state_fired
			if t.durable {
				sch_persist_closed(t, 'fired')
			}
		}
		sch_kind_every {
			sch_fire_every(mut t, target, mut env)
		}
		sch_kind_recur, sch_kind_cron {
			sch_fire_recur(mut t, target, mut env)
		}
		else {}
	}
}

// sch_fire_every handles a recurring `every` timer due at virtual-now. It fires
// per its cadence mode + on-missed policy (§2.2/§2.5) then re-arms (or stays
// terminal — every never exhausts, only cancel stops it).
fn sch_fire_every(mut t SchedTimer, target i64, mut env MatchEnv) {
	r := sched_reg()
	now := r.virtual_now
	if t.mode == sch_mode_fixed_rate {
		// anchored grid t0 + k·dur. Count grid points in (last_deadline, target].
		// The current deadline is the first crossed grid point. Compute the next
		// grid point strictly after target.
		mut next_grid := t.deadline + t.dur_ns
		for next_grid <= target {
			next_grid += t.dur_ns
		}
		// number of crossed grid points = those in [t.deadline, target].
		mut crossed := i64(1) // the current deadline
		mut g := t.deadline + t.dur_ns
		for g <= target {
			crossed++
			g += t.dur_ns
		}
		sch_fire_count_policy(mut t, crossed, mut env)
		t.deadline = next_grid
		// every stays armed (re-arm).
		t.state = sch_state_armed
	} else {
		// :fixed-delay — no backlog: each crossed re-arm boundary fires once in
		// order; re-arm is now + dur after the callback "returns" (here:
		// instantaneous virtual callback). A single advance that crosses N
		// re-arm boundaries fires N times under :skip (the default) — there is
		// no backlog to coalesce because each boundary is a distinct fire (§2.2).
		// We fire once here; the drain loop re-scans and re-fires the re-armed
		// timer if its new deadline is still ≤ target.
		sch_invoke(t, mut env)
		t.deadline = now + t.dur_ns
		t.state = sch_state_armed
	}
}

// sch_fire_recur handles a recur/cron timer due at virtual-now. It asks `time`
// for the next occurrence, applies on-missed for occurrences crossed in this
// advance, and re-arms (or goes terminal "fired" at COUNT/UNTIL exhaustion).
fn sch_fire_recur(mut t SchedTimer, target i64, mut env MatchEnv) {
	// :skip / :coalesce fire EXACTLY ONCE per advance regardless of how many
	// occurrences were crossed, so they need NO per-occurrence count. The prior
	// code walked time-next-occurrence once per crossed occurrence just to
	// compute a `crossed` value it then discarded for these policies — O(N) in
	// the missed count (≈1s for a year of daily, ≈4.5min for 100k). Jump
	// straight to the first occurrence strictly after `target` in a SINGLE
	// fast-forwarding next-occurrence call.
	if t.on_missed != sch_miss_fire_all {
		sch_fire_count_policy(mut t, 1, mut env) // fire once
		target_node := sch_instant_to_datetime_node(target)
		next := time_stdlib_builtin('time-next-occurrence', [t.rule, target_node]) or {
			t.state = sch_state_fired
			if t.durable {
				sch_persist_closed(t, 'fired')
			}
			return
		}
		if is_err_value(next) || sch_is_absence(next) {
			// no occurrence after target → COUNT/UNTIL exhausted (§3.1).
			t.state = sch_state_fired
			if t.durable {
				sch_persist_closed(t, 'fired')
			}
			return
		}
		ni := sch_datetime_to_instant(next) or {
			t.state = sch_state_fired
			return
		}
		t.deadline = ni
		t.last_fire = sch_arg_str(next) or { t.last_fire }
		t.state = sch_state_armed
		return
	}
	// :fire-all — one fire per crossed occurrence; the walk is bounded by the
	// real occurrences in (last_fire, target] (each is genuine work).
	// Count how many occurrences fall in (last_fire, target]. The current
	// deadline is one. Walk time-next-occurrence forward until past target or
	// absence.
	mut crossed := i64(1)
	mut cursor := t.last_fire
	mut exhausted := false
	for {
		cursor_node := if cursor == '' {
			sch_instant_to_datetime_node((sched_reg()).virtual_now)
		} else {
			cx.Node(cx.ScalarNode{ value: cx.ScalarValue(cursor), data_type: cx.ScalarType.datetime_type })
		}
		next := time_stdlib_builtin('time-next-occurrence', [t.rule, cursor_node]) or { break }
		if is_err_value(next) || sch_is_absence(next) {
			exhausted = true
			break
		}
		ni := sch_datetime_to_instant(next) or { break }
		niso := sch_arg_str(next) or { break }
		if ni <= target {
			crossed++
			cursor = niso
		} else {
			// next occurrence is past the advance ceiling — re-arm there.
			t.deadline = ni
			break
		}
	}
	// crossed counts the current deadline + every further occurrence ≤ target.
	sch_fire_count_policy(mut t, crossed, mut env)
	if exhausted {
		// last occurrence consumed → terminal (COUNT/UNTIL, §3.1).
		t.state = sch_state_fired
		if t.durable {
			sch_persist_closed(t, 'fired')
		}
		return
	}
	// re-arm: t.deadline already set to the next future occurrence above; if the
	// loop broke on exhaustion-after-target it stays armed at the last computed.
	t.last_fire = cursor
	t.state = sch_state_armed
}

// sch_fire_count_policy fires the callback the number of times dictated by the
// on-missed policy for `crossed` occurrences due at once (§2.5/§4.6):
//   :skip     → fire once (only the latest)
//   :coalesce → fire once
//   :fire-all → fire once per crossed occurrence
fn sch_fire_count_policy(mut t SchedTimer, crossed i64, mut env MatchEnv) {
	mut fires := i64(1)
	if t.on_missed == sch_miss_fire_all {
		fires = crossed
	}
	// :skip and :coalesce both fire exactly once.
	for _ in 0 .. fires {
		sch_invoke(t, mut env)
	}
}

// sch_invoke fires $ev: invoke a callable (return ignored) or post a tick to a
// channel (§2.1). A faulted callback's [err] is swallowed at the loop boundary
// (firing is a side effect; the return is ignored, §2.1) — a raw effect without
// a grant still hits CXER0271 at the callback's own effect point.
fn sch_invoke(t &SchedTimer, mut env MatchEnv) {
	if sch_ev_is_callable(t.ev) {
		apply_fn_value(t.ev, [], mut env) or { return }
		return
	}
	if sch_ev_is_channel(t.ev) {
		if t.ev is cx.Element {
			el := t.ev as cx.Element
			nm := el.attr('name')
			if nm != '' {
				if mut ch := env.state.channel_get(nm) {
					tick := cx.Element{
						name:  'tick'
						attrs: [
							cx.Attribute{ name: 'timer', value: cx.ScalarValue(t.name) },
						]
					}
					ch.queue << tick
				}
			}
		}
	}
}

// ── restore (§3.2): fold a journal to its pending intents + re-arm ───────────

// sch_restore folds $journal to its still-pending [sched-intent …] set and
// re-arms each against the CURRENT clock, binding the fire value by `name` from
// $registry. Returns a [restore-report rearmed=N skipped=M [orphaned …]] VALUE.
fn sch_restore(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 2 {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: restore expects ($journal, $registry)')
	}
	journal := args[0]
	if !(journal is cx.Element && (journal as cx.Element).name == 'journal') {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: restore expects a [journal] handle')
	}
	registry := args[1]
	// Read the full entry list via journal-since(1) (a [sequence element]).
	entries_node := journal_stdlib_builtin('journal-since', [journal, sch_int(1)]) or {
		return mk_err(sch_err_arg_invalid, 'E_SCHED_ARG_INVALID: restore could not read the journal')
	}
	if is_err_value(entries_node) {
		return entries_node
	}
	// Fold the entry list to the still-pending intents (a closed/canceled
	// status for a name removes it from the pending set).
	mut pending := map[string]cx.Element{}
	mut order := []string{}
	if entries_node is cx.Element {
		for ent in (entries_node as cx.Element).items {
			intent := sch_intent_of_entry(ent) or { continue }
			nm := sch_intent_field(intent, 'name') or {
				return mk_err(sch_err_restore_intent, 'E_SCHED_RESTORE_INTENT: a [sched-intent] entry has no name')
			}
			status := sch_intent_field(intent, 'status') or { 'pending' }
			if status == 'pending' {
				if nm !in pending {
					order << nm
				}
				pending[nm] = intent
			} else {
				// closed / fired / canceled → drop from pending.
				if nm in pending {
					pending.delete(nm)
					order = order.filter(it != nm)
				}
			}
		}
	}
	mut rearmed := 0
	mut skipped := 0
	mut orphaned := []cx.Node{}
	for nm in order {
		intent := pending[nm] or { continue }
		ev := sch_registry_lookup(registry, nm) or {
			// orphaned: a pending intent with no registry binding — left armed-
			// but-unbound, surfaced as a finding, NEVER silently dropped (§3.2).
			orphaned << cx.Element{ name: 'orphan', attrs: [
				cx.Attribute{ name: 'name', value: cx.ScalarValue(nm) },
			] }
			continue
		}
		res := sch_rearm_intent(intent, ev) or {
			skipped++
			continue
		}
		if sch_is_absence(res) {
			skipped++
		} else {
			rearmed++
		}
	}
	mut items := []cx.Node{}
	if orphaned.len > 0 {
		items << cx.Element{ name: 'orphaned', items: orphaned }
	}
	return cx.Element{
		name:  'restore-report'
		attrs: [
			cx.Attribute{ name: 'rearmed', value: cx.ScalarValue(i64(rearmed)) },
			cx.Attribute{ name: 'skipped', value: cx.ScalarValue(i64(skipped)) },
			cx.Attribute{ name: 'orphaned', value: cx.ScalarValue(i64(orphaned.len)) },
		]
		items: items
	}
}

// sch_intent_of_entry extracts the [sched-intent …] payload from a journal
// [entry … [event [sched-intent …]]] element.
fn sch_intent_of_entry(ent cx.Node) ?cx.Element {
	if ent is cx.Element {
		el := ent as cx.Element
		for it in el.items {
			if it is cx.Element {
				ch := it as cx.Element
				if ch.name == 'event' {
					for inner in ch.items {
						if inner is cx.Element && inner.name == 'sched-intent' {
							return inner as cx.Element
						}
					}
				}
				if ch.name == 'sched-intent' {
					return ch
				}
			}
		}
		if el.name == 'sched-intent' {
			return el
		}
	}
	return none
}

// sch_intent_field reads a string field from a [sched-intent …]. A journal
// round-trip re-parses scalar child text as a TextNode (not a ScalarNode), so
// both shapes are handled.
fn sch_intent_field(intent cx.Element, key string) ?string {
	for it in intent.items {
		if it is cx.Element && it.name == key {
			if it.items.len > 0 {
				v := it.items[0]
				if v is cx.ScalarNode {
					return cx.scalar_value_str_public(v.value)
				}
				if v is cx.TextNode {
					return v.value
				}
			}
			return ''
		}
	}
	return none
}

fn sch_intent_child_node(intent cx.Element, key string) ?cx.Node {
	for it in intent.items {
		if it is cx.Element && it.name == key {
			if it.items.len > 0 {
				return it.items[0]
			}
		}
	}
	return none
}

// sch_registry_lookup binds a persisted timer's name to a live $ev from the
// {name → $ev} registry map.
fn sch_registry_lookup(registry cx.Node, name string) ?cx.Node {
	n := sch_map_get_node(registry, name) or { return none }
	if sch_ev_valid(n) {
		return n
	}
	return none
}

// sch_rearm_intent re-arms a single pending intent against the current clock,
// binding $ev. Returns the re-armed [timer] handle, or absence when the intent
// is already past its bound (e.g. an exhausted recurrence) → skipped.
fn sch_rearm_intent(intent cx.Element, ev cx.Node) ?cx.Node {
	kind := sch_intent_field(intent, 'kind') or { return mk_err(sch_err_restore_intent, 'E_SCHED_RESTORE_INTENT: intent has no kind') }
	name := sch_intent_field(intent, 'name') or { 'restored' }
	on_missed := sch_intent_field(intent, 'on-missed') or { sch_miss_skip }
	mode := sch_intent_field(intent, 'mode') or { sch_mode_fixed_delay }
	r := sched_reg()
	mut o := SchedOpts{
		name:      name
		has_name:  true
		mode:      mode
		on_missed: on_missed
		journal:   cx.Element{}
	}
	match kind {
		sch_kind_after, sch_kind_at {
			deadline := i64(sch_intent_field(intent, 'deadline') or { '0' }.i64())
			// re-arm with REMAINING time: if the original deadline already
			// elapsed during downtime, apply on-missed (:skip → fire on next
			// turn here means arm at current now; the deadline≤now drains on the
			// next advance). We re-arm at the persisted absolute deadline so a
			// window keeps its remaining time relative to the original arm.
			eff_deadline := if deadline < r.virtual_now && on_missed == sch_miss_skip {
				r.virtual_now // already past: fire on next turn (drained on advance)
			} else {
				deadline
			}
			return sch_register(kind, eff_deadline, 0, ev, o, cx.Element{}, false, '')
		}
		sch_kind_every {
			dur := i64(sch_intent_field(intent, 'dur-ns') or { '0' }.i64())
			if dur <= 0 {
				return mk_err(sch_err_restore_intent, 'E_SCHED_RESTORE_INTENT: every intent has no dur-ns')
			}
			return sch_register(sch_kind_every, r.virtual_now + dur, dur, ev, o, cx.Element{}, false, '')
		}
		sch_kind_recur, sch_kind_cron {
			rule := sch_intent_child_node(intent, 'rule') or {
				return mk_err(sch_err_restore_intent, 'E_SCHED_RESTORE_INTENT: recur intent has no rule')
			}
			return sch_arm_recurrence(rule, ev, o)
		}
		else {
			return mk_err(sch_err_restore_intent, 'E_SCHED_RESTORE_INTENT: unknown intent kind "${kind}"')
		}
	}
}

// ── bundled module source (the [?def] surface) ───────────────────────────────
// This const is the SAME source as stdlib/sched.cx (if a disk copy is added).
// Backslash-escaped `$` because V interpolates `$` in a string literal.

const stdlib_src_sched = $embed_file('../../stdlib/sched.cx').to_string()
