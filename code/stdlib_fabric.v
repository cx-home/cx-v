@[has_globals]
module code

import cx

// stdlib_fabric.v — native primitives for the `cx-fabric` bundled package
// (spec/03-approved/xap/fabric.md; issues #518/#531; band CXER4920–4949).
//
// P0 = the EMBEDDED tier: platform eventing composed from shipped primitives
// — the durable plane is a journal stream plus delivery (subscribe/receive/
// ack with consumer-group offsets persisted as store data through the
// journal's own store, spec §9), the transient plane is latest-wins
// in-process channels (spec §6/§12). fabric adds NO storage, digest,
// ordering, or crypto mechanism of its own: publishes delegate to
// journal-append (per-stream commit lock IS the sequencing, spec §10),
// catch-up reads delegate to journal-since, offsets ride the same
// doc-backed-alias pattern journal's own head pointers use.
//
// CAPABILITY: fabric introduces NO capability of its own (the journal/store
// posture): a mem:// journal is capability-free, a file:// journal is gated
// by store's read/write at store's own effect points, remote by net. The
// spec §11 observe/publish/consume GRANTS are the served tier's PEP model
// (P1) — embedded-tier authority is the process's own, exactly as bus/
// journal. Single-threaded by contract, like bus (§2.1 discipline).
//
// PATTERNS: subscription patterns are bus.md §2.2 REUSED VERBATIM —
// bus_compile_pattern / bus_pattern_matches (topic atom with terminal `.*`
// prefix-glob per the #397 cutover, head-name string, arity-1 boolean
// predicate). fabric adds no pattern forms (spec §7). Matching applies to
// the published EVENT (the `[event]` child's payload), never the [entry]
// envelope.
//
// `receive` evaluates predicate patterns (applies a CX callable), so it
// dispatches through fabric_stdlib_builtin_env (env-aware chain in eval.v,
// beside bus/journal); every other primitive is env-free via
// fabric_stdlib_builtin in stdlib_dispatch.v.

// ── error band CXER4920–4949 (spec §16 error posture) ────────────────────

const fab_err_arg_invalid = 'cx-err:CXER4920' // E_FABRIC_ARG_INVALID
const fab_err_handle = 'cx-err:CXER4921' // E_FABRIC_HANDLE (unknown/closed)
const fab_err_observe_only = 'cx-err:CXER4922' // E_FABRIC_OBSERVE_ONLY (ack on observe sub)
const fab_err_group = 'cx-err:CXER4923' // E_FABRIC_GROUP (ack without a group / group on observe)
const fab_err_offset = 'cx-err:CXER4924' // E_FABRIC_OFFSET (malformed ack seq)
const fab_err_policy = 'cx-err:CXER4931' // E_FABRIC_POLICY (malformed/conflicting redelivery policy, §9.1)
const fab_err_no_responder = 'cx-err:CXER4932' // E_FABRIC_NO_RESPONDER (request on a channel with no live responder, §12.1)
const fab_err_responder = 'cx-err:CXER4933' // E_FABRIC_RESPONDER (responder registration conflict — sticky-exclusive, §12.1)
const fab_err_req_timeout = 'cx-err:CXER4934' // E_FABRIC_REQUEST_TIMEOUT (request deadline expired, §12.1)

// ── state model ───────────────────────────────────────────────────────────
//
// A fabric handle owns mutable delivery state (subscription cursors, the
// transient channel map) that cannot live in an immutable CX value, so —
// exactly like bus/journal/store — each open fabric is a heap FabricState in
// a process-global registry, referenced by the integer handle on the
// returned `[fabric handle=N …]` element. The underlying journal is held as
// the ORIGINAL `[journal]` element and re-resolved per operation, so journal
// lifecycle errors (CXER4612 closed etc.) surface verbatim — composition,
// not wrapping.

@[heap]
struct FabricSub {
mut:
	id      int
	stream  string
	pattern BusPattern
	group   string // '' = ungrouped (no committable offset)
	observe bool   // observe-only: receive allowed, ack refused (§11)
	active  bool
	// cursor = the NEXT journal seq this subscription scans (delivery
	// position). Distinct from the group's COMMITTED offset (persisted via
	// ack): crash-and-resubscribe resumes from committed+1 — the uncommitted
	// tail redelivers, the spec §19.3 at-least-once contract.
	cursor    i64
	committed i64
	// §9.1 redelivery policy (group state, persisted beside the offset):
	// max_deliveries = 0 means no policy. `counted` marks that this
	// subscription lifetime already did its head-of-tail attempt accounting —
	// only the resume head gets a delivery record, later deliveries in the
	// same lifetime must not clobber it.
	max_deliveries i64
	dlq            string
	counted        bool
}

@[heap]
struct FabricState {
mut:
	handle       int
	open         bool
	journal_elem cx.Node
	subs         map[int]&FabricSub
	next_sub     int
	// transient plane: latest-wins value per channel key (spec §6/§12);
	// key shape `<tenant>/<scope>/<name>` is the caller's convention —
	// embedded tier is one process/one trust domain, tenancy is enforced at
	// the served tier's attach (P1).
	channels map[string]cx.Node
	// §12.1 request-reply: registered responder callables per channel —
	// sticky-exclusive (a second respond refuses while the holder lives; the
	// embedded holder lives until fabric close). The callable never leaves
	// the process.
	responders map[string]cx.Node
	next_resp  int
}

@[heap]
struct FabricRegistry {
mut:
	fabrics map[int]&FabricState
	// remote handles (stdlib_fabric_remote.v, #531 P3) share the id space so
	// a [fabric handle=N] element is unambiguous across the two tiers.
	remotes map[int]&FabricRemote
	next_id int
}

__global (
	g_fabric_reg voidptr
)

fn fabric_reg() &FabricRegistry {
	if g_fabric_reg == unsafe { nil } {
		r := &FabricRegistry{
			fabrics: map[int]&FabricState{}
			remotes: map[int]&FabricRemote{}
		}
		g_fabric_reg = voidptr(r)
	}
	return unsafe { &FabricRegistry(g_fabric_reg) }
}

fn fabric_lookup(id int) ?&FabricState {
	reg := fabric_reg()
	return reg.fabrics[id] or { return none }
}

// ── value helpers (the bus_* helpers are reused where shapes match) ───────

fn fab_handle_of(n cx.Node, elem_name string) ?int {
	if n is cx.Element {
		if n.name == elem_name {
			for a in n.attrs {
				if a.name == 'handle' {
					return cx.scalar_value_str_public(a.value).int()
				}
			}
		}
	}
	return none
}

fn fab_sub_id_of(n cx.Node) ?int {
	if n is cx.Element {
		if n.name == 'fabric-sub' {
			for a in n.attrs {
				if a.name == 'id' {
					return cx.scalar_value_str_public(a.value).int()
				}
			}
		}
	}
	return none
}

// fab_get_open resolves a `[fabric]` argument to its live state.
fn fab_get_open(arg cx.Node) (&FabricState, cx.Node, bool) {
	id := fab_handle_of(arg, 'fabric') or {
		return unsafe { nil }, mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: not a [fabric] handle'), false
	}
	f := fabric_lookup(id) or {
		return unsafe { nil }, mk_err(fab_err_handle, 'E_FABRIC_HANDLE: unknown fabric handle ${id}'), false
	}
	if !f.open {
		return unsafe { nil }, mk_err(fab_err_handle, 'E_FABRIC_HANDLE: operation on a closed fabric'), false
	}
	return f, bus_null(), true
}

// fab_get_sub resolves a `[fabric-sub]` argument to (fabric, sub).
fn fab_get_sub(arg cx.Node) (&FabricState, &FabricSub, cx.Node, bool) {
	fid := fab_handle_of(arg, 'fabric-sub') or {
		return unsafe { nil }, unsafe { nil }, mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: not a [fabric-sub] handle'), false
	}
	sid := fab_sub_id_of(arg) or {
		return unsafe { nil }, unsafe { nil }, mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: not a [fabric-sub] handle'), false
	}
	f := fabric_lookup(fid) or {
		return unsafe { nil }, unsafe { nil }, mk_err(fab_err_handle, 'E_FABRIC_HANDLE: unknown fabric handle ${fid}'), false
	}
	if !f.open {
		return unsafe { nil }, unsafe { nil }, mk_err(fab_err_handle, 'E_FABRIC_HANDLE: operation on a closed fabric'), false
	}
	s := f.subs[sid] or {
		return unsafe { nil }, unsafe { nil }, mk_err(fab_err_handle, 'E_FABRIC_HANDLE: unknown subscription id ${sid}'), false
	}
	if !s.active {
		return unsafe { nil }, unsafe { nil }, mk_err(fab_err_handle, 'E_FABRIC_HANDLE: subscription ${sid} is cancelled'), false
	}
	return f, s, bus_null(), true
}

fn fab_elem(f &FabricState) cx.Node {
	return cx.Element{
		name:  'fabric'
		attrs: [
			bus_attr_int('handle', f.handle),
			bus_attr('state', if f.open { 'open' } else { 'closed' }),
			bus_attr('on-close', 'fabric/close'),
		]
	}
}

fn fab_sub_elem(f &FabricState, s &FabricSub) cx.Node {
	mut attrs := [
		bus_attr_int('handle', f.handle),
		bus_attr_int('id', s.id),
		bus_attr('stream', s.stream),
	]
	if s.group != '' {
		attrs << bus_attr('group', s.group)
	}
	if s.observe {
		attrs << bus_attr_bool('observe', true)
	}
	// #605: head seq on the sub element — tier parity with the served
	// daemon's [fabric-sub head=…] reply (0 = empty stream).
	mut head := i64(0)
	if hn := journal_stdlib_builtin('journal-head', [f.journal_elem,
		cx.Node(bus_str(s.stream))]) {
		if hn is cx.Element && hn.name == 'entry' {
			head = hn.attr('seq').i64()
		}
	}
	attrs << bus_attr_int('head', head)
	return cx.Element{
		name:  'fabric-sub'
		attrs: attrs
	}
}

// fab_arg_string reads a non-empty plain string argument.
fn fab_arg_string(n cx.Node) ?string {
	s := bus_plain_string(n) or { return none }
	if s == '' {
		return none
	}
	return s
}

fn fab_arg_int(n cx.Node) ?i64 {
	if n is cx.ScalarNode {
		v := n.value
		if v is i64 {
			return v
		}
	}
	return none
}

// fab_journal_of re-resolves the fabric's underlying journal. Journal
// lifecycle errors surface verbatim (composition honesty).
fn fab_journal_of(f &FabricState) (&Journal, cx.Node, bool) {
	return jrn_get_open(f.journal_elem)
}

// ── offsets (spec §9: derived-position artifacts as store data) ───────────
//
// The committed group offset persists as a tiny `[fabric-offset]` doc behind
// a doc-backed alias in the journal's OWN store — the exact pattern journal
// uses for its head/algo pointers (jrn_set_meta_alias): put-doc + set-alias,
// read = alias → doc → attribute. Key convention (spec §9/§19.4):
// `fabric/<tenant>/<stream>/<group>/offset`.

fn fab_offset_alias(tenant string, stream string, group string) string {
	return 'fabric/${tenant}/${stream}/${group}/offset'
}

fn fab_load_committed(j &Journal, stream string, group string) i64 {
	alias := fab_offset_alias(j.tenant, stream, group)
	dhash := jrn_store_get_alias(j.store_id, alias) or { return 0 }
	text := jrn_store_get_doc_text(j.store_id, dhash) or { return 0 }
	parsed := cx.parse(text) or { return 0 }
	if parsed.elements.len > 0 {
		e := parsed.elements[0]
		if e is cx.Element {
			if e.name == 'fabric-offset' {
				for a in e.attrs {
					if a.name == 'seq' {
						return cx.scalar_value_str_public(a.value).i64()
					}
				}
			}
		}
	}
	return 0
}

fn fab_persist_committed(j &Journal, stream string, group string, seq i64) {
	doc := cx.Element{
		name:  'fabric-offset'
		attrs: [
			bus_attr('stream', stream),
			bus_attr('group', group),
			bus_attr_int('seq', seq),
		]
	}
	jrn_set_meta_alias(j.store_id, fab_offset_alias(j.tenant, stream, group), doc)
}

// ── §9.1 redelivery policy + dead-letter (group state beside the offset) ──
//
// The policy (`max-deliveries` + `dlq`) and the delivery record (head seq +
// attempt count) are derived-position artifacts exactly like the committed
// offset: tiny docs behind doc-backed aliases in the journal's own store.
// Attempt accounting keys on the HEAD OF THE UNCOMMITTED TAIL — under
// cumulative ack the head is the only event that can block the group — and
// counts head-deliveries: a subscription resume that redelivers the same
// head increments, a moved head resets. On exhaustion the head publishes to
// the DLQ stream as a [dead-letter] envelope (attribution actor = the
// group, authority = fabric:dlq) and the offset auto-commits through it.

fn fab_policy_alias(tenant string, stream string, group string) string {
	return 'fabric/${tenant}/${stream}/${group}/policy'
}

fn fab_delivery_alias(tenant string, stream string, group string) string {
	return 'fabric/${tenant}/${stream}/${group}/delivery'
}

// fab_load_meta_doc reads one alias-backed meta doc, returning the element
// when present and named `want`.
fn fab_load_meta_doc(j &Journal, alias string, want string) ?cx.Element {
	dhash := jrn_store_get_alias(j.store_id, alias) or { return none }
	text := jrn_store_get_doc_text(j.store_id, dhash) or { return none }
	parsed := cx.parse(text) or { return none }
	if parsed.elements.len > 0 {
		e := parsed.elements[0]
		if e is cx.Element {
			if e.name == want {
				return e
			}
		}
	}
	return none
}

fn fab_elem_attr_i64(e cx.Element, name string) i64 {
	for a in e.attrs {
		if a.name == name {
			return cx.scalar_value_str_public(a.value).i64()
		}
	}
	return 0
}

fn fab_elem_attr_str(e cx.Element, name string) string {
	for a in e.attrs {
		if a.name == name {
			return cx.scalar_value_str_public(a.value)
		}
	}
	return ''
}

// fab_load_policy returns the group's persisted policy (0, '') when none.
fn fab_load_policy(j &Journal, stream string, group string) (i64, string) {
	e := fab_load_meta_doc(j, fab_policy_alias(j.tenant, stream, group), 'fabric-policy') or {
		return 0, ''
	}
	return fab_elem_attr_i64(e, 'max-deliveries'), fab_elem_attr_str(e, 'dlq')
}

fn fab_persist_policy(j &Journal, stream string, group string, max i64, dlq string) {
	doc := cx.Element{
		name:  'fabric-policy'
		attrs: [
			bus_attr('stream', stream),
			bus_attr('group', group),
			bus_attr_int('max-deliveries', max),
			bus_attr('dlq', dlq),
		]
	}
	jrn_set_meta_alias(j.store_id, fab_policy_alias(j.tenant, stream, group), doc)
}

// fab_load_delivery returns the group's delivery record (head seq, attempts);
// (0, 0) when none.
fn fab_load_delivery(j &Journal, stream string, group string) (i64, i64) {
	e := fab_load_meta_doc(j, fab_delivery_alias(j.tenant, stream, group), 'fabric-delivery') or {
		return 0, 0
	}
	return fab_elem_attr_i64(e, 'seq'), fab_elem_attr_i64(e, 'attempts')
}

fn fab_persist_delivery(j &Journal, stream string, group string, seq i64, attempts i64) {
	doc := cx.Element{
		name:  'fabric-delivery'
		attrs: [
			bus_attr('stream', stream),
			bus_attr('group', group),
			bus_attr_int('seq', seq),
			bus_attr_int('attempts', attempts),
		]
	}
	jrn_set_meta_alias(j.store_id, fab_delivery_alias(j.tenant, stream, group), doc)
}

// fab_policy_from_opts reads the §9.1 policy keys off subscribe opts.
// Returns (max, dlq, err, ok): (0, '', _, true) = no policy declared.
fn fab_policy_from_opts(opts cx.Node) (i64, string, cx.Node, bool) {
	mut max := i64(0)
	mut dlq := ''
	mut saw_max := false
	if v := bus_map_value(opts, 'max-deliveries') {
		iv := fab_arg_int(v) or {
			return 0, '', mk_err(fab_err_policy, 'E_FABRIC_POLICY: max-deliveries must be an int ≥ 1'), false
		}
		max = iv
		saw_max = true
	}
	if v := bus_map_value(opts, 'dlq') {
		s := fab_arg_string(v) or {
			return 0, '', mk_err(fab_err_policy, 'E_FABRIC_POLICY: dlq must be a non-empty stream name'), false
		}
		dlq = s
	}
	if !saw_max && dlq == '' {
		return 0, '', bus_null(), true
	}
	if !saw_max || dlq == '' {
		return 0, '', mk_err(fab_err_policy, 'E_FABRIC_POLICY: max-deliveries and dlq come together or not at all (a limit without a destination would discard truth; a destination without a limit never fires)'), false
	}
	if max < 1 {
		return 0, '', mk_err(fab_err_policy, 'E_FABRIC_POLICY: max-deliveries must be ≥ 1'), false
	}
	return max, dlq, bus_null(), true
}

// fab_policy_resolve reconciles a declared policy with the group's persisted
// one (§9.1): a first declaration persists, an identical redeclaration is
// idempotent, a conflicting one refuses loudly, and an undeclared subscribe
// inherits. Returns the effective (max, dlq).
fn fab_policy_resolve(j &Journal, stream string, group string, decl_max i64, decl_dlq string) (i64, string, cx.Node, bool) {
	if decl_max > 0 && decl_dlq == stream {
		return 0, '', mk_err(fab_err_policy, 'E_FABRIC_POLICY: dlq must differ from the source stream (no self-loop)'), false
	}
	have_max, have_dlq := fab_load_policy(j, stream, group)
	if decl_max == 0 {
		return have_max, have_dlq, bus_null(), true // inherit (possibly none)
	}
	if have_max == 0 {
		fab_persist_policy(j, stream, group, decl_max, decl_dlq)
		return decl_max, decl_dlq, bus_null(), true
	}
	if have_max == decl_max && have_dlq == decl_dlq {
		return have_max, have_dlq, bus_null(), true // idempotent redeclaration
	}
	return 0, '', mk_err(fab_err_policy, 'E_FABRIC_POLICY: group "${group}" already carries {max-deliveries: ${have_max}, dlq: "${have_dlq}"} — a conflicting redeclaration ({max-deliveries: ${decl_max}, dlq: "${decl_dlq}"}) refuses (group siblings never run divergent policies silently)'), false
}

// fab_policy_gate runs the §9.1 accounting for the resume head — the first
// pattern-matching entry above the group's committed offset in a delivery
// pass. Returns (deliver, err, ok):
//   deliver=true  — record persisted (attempts incremented/reset), deliver;
//   deliver=false — attempts exhausted: the entry was dead-lettered to the
//                   DLQ stream and the offset committed THROUGH seq (the
//                   caller updates its committed mirror and must not
//                   deliver);
//   ok=false      — store/journal fault (fail loud, surface err verbatim).
fn fab_policy_gate(j &Journal, journal_elem cx.Node, stream string, group string, seq i64, entry cx.Element, max i64, dlq string) (bool, cx.Node, bool) {
	rec_seq, rec_att := fab_load_delivery(j, stream, group)
	attempts_next := if rec_seq == seq { rec_att + 1 } else { i64(1) }
	if attempts_next <= max {
		fab_persist_delivery(j, stream, group, seq, attempts_next)
		return true, bus_null(), true
	}
	// exhausted: dead-letter the head instead of delivering it.
	mut event := cx.Node(bus_null())
	for ch in entry.items {
		if ch is cx.Element {
			if ch.name == 'event' && ch.items.len > 0 {
				event = ch.items[0]
			}
		}
	}
	dl := cx.Node(cx.Element{
		name:  'dead-letter'
		attrs: [
			bus_attr('stream', stream),
			bus_attr_int('seq', seq),
			bus_attr('group', group),
			bus_attr_int('attempts', rec_att),
		]
		items: [event]
	})
	attribution := cx.Node(cx.Element{
		name:  map_marker_name
		items: [
			session_kv('actor', bus_str(group)),
			session_kv('authority', bus_str('fabric:dlq')),
			session_kv('stream', bus_str(dlq)),
		]
	})
	r := journal_stdlib_builtin('journal-append', [journal_elem, dl, attribution]) or {
		return false, mk_err(fab_err_policy, 'E_FABRIC_POLICY: journal-append unavailable for dead-letter'), false
	}
	if r is cx.Element {
		if r.name == 'err' {
			return false, cx.Node(r), false // the journal's own refusal, verbatim
		}
	}
	fab_persist_committed(j, stream, group, seq)
	fab_persist_delivery(j, stream, group, 0, 0) // clear the record
	return false, bus_null(), true
}

// ── open / close ──────────────────────────────────────────────────────────

// fabric_open is the DUAL-FORM constructor (spec §15: embedded or remote):
// a `[journal]` element composes an embedded fabric over it (spec §6: a
// durable fabric stream IS a journal stream); an `xsp://` / `xsps://` URL
// string dials a fabric-serve daemon and attaches via XSP-AUTH
// (stdlib_fabric_remote.v, #531 P3 — net-capability-gated at the dial).
fn fabric_open(args []cx.Node) cx.Node {
	if args.len < 1 {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: open expects ($journal) or ("xsp://host:port", opts)')
	}
	if url := bus_plain_string(args[0]) {
		if !fab_remote_url_is_remote(url) {
			return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: a string open target must be an xsp:// or xsps:// daemon URL (got "${url}")')
		}
		opts := if args.len > 1 {
			args[1]
		} else {
			cx.Node(cx.Element{
				name: map_marker_name
			})
		}
		return fabric_open_remote(url, opts)
	}
	_, jerr, jok := jrn_get_open(args[0])
	if !jok {
		return jerr
	}
	mut reg := fabric_reg()
	reg.next_id++
	mut f := &FabricState{
		handle:       reg.next_id
		open:         true
		journal_elem: args[0]
		subs:         map[int]&FabricSub{}
		channels:     map[string]cx.Node{}
		responders:   map[string]cx.Node{}
	}
	reg.fabrics[f.handle] = f
	return fab_elem(f)
}

// fabric_close closes the fabric: cancels subscriptions, drops transient
// channels. Idempotent null; the underlying journal is NOT closed (fabric
// composed over it; it never owned it).
fn fabric_close(args []cx.Node) cx.Node {
	if args.len < 1 {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: close expects a [fabric]')
	}
	id := fab_handle_of(args[0], 'fabric') or {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: not a [fabric] handle')
	}
	mut f := fabric_lookup(id) or { return bus_null() }
	if !f.open {
		return bus_null()
	}
	f.open = false
	for _, mut s in f.subs {
		s.active = false
	}
	f.channels = map[string]cx.Node{}
	f.responders = map[string]cx.Node{}
	return bus_null()
}

// ── durable plane: publish ────────────────────────────────────────────────

// fabric_publish appends an event to a named durable stream — a delegation
// to journal-append with the stream injected into the attribution (the
// per-stream commit lock IS the sequencing, spec §10). Returns
// `[receipt seq=N stream=…]`. Attribution rules (actor/authority required)
// are journal's own and surface verbatim.
fn fabric_publish(args []cx.Node) cx.Node {
	if args.len < 4 {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: publish expects ($fabric, $stream, $event, $attribution)')
	}
	f, ferr, fok := fab_get_open(args[0])
	if !fok {
		return ferr
	}
	stream := fab_arg_string(args[1]) or {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: stream must be a non-empty string')
	}
	event := args[2]
	if event !is cx.Element {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: event must be an element')
	}
	// attribution: the caller's map + the stream entry (fabric owns stream
	// routing; a caller-supplied `stream` key is overridden, never trusted to
	// diverge from the addressed stream).
	entries := bus_map_entries(args[3]) or {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: attribution must be a map')
	}
	mut new_entries := []cx.Node{}
	for e in entries {
		if e is cx.Element {
			if e.name == 'stream' {
				continue
			}
		}
		new_entries << e
	}
	new_entries << cx.Node(cx.Element{
		name:  'stream'
		items: [cx.Node(bus_str(stream))]
	})
	attribution := cx.Node(cx.Element{
		name:  map_marker_name
		items: new_entries
	})
	r := journal_stdlib_builtin('journal-append', [f.journal_elem, event, attribution]) or {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: journal-append unavailable')
	}
	if r is cx.Element {
		if r.name == 'err' {
			return r
		}
		if r.name == 'entry' {
			mut seq := i64(0)
			for a in r.attrs {
				if a.name == 'seq' {
					seq = cx.scalar_value_str_public(a.value).i64()
				}
			}
			return cx.Element{
				name:  'receipt'
				attrs: [
					bus_attr_int('seq', seq),
					bus_attr('stream', stream),
				]
			}
		}
	}
	return r
}

// ── durable plane: subscribe / observe ────────────────────────────────────

// fab_subscribe_common builds a subscription. `observe` marks the read-only
// form (§11: the wire-tap grant shape — receive allowed, ack refused).
fn fab_subscribe_common(args []cx.Node, observe bool) cx.Node {
	if args.len < 3 {
		verb := if observe { 'observe' } else { 'subscribe' }
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: ${verb} expects ($fabric, $stream, $pattern)')
	}
	mut f, ferr, fok := fab_get_open(args[0])
	if !fok {
		return ferr
	}
	stream := fab_arg_string(args[1]) or {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: stream must be a non-empty string')
	}
	pat, perr, pok := bus_compile_pattern(args[2])
	if !pok {
		return perr
	}
	mut group := ''
	mut from := i64(0)
	mut has_from := false
	mut decl_max := i64(0)
	mut decl_dlq := ''
	if args.len > 3 {
		opts := args[3]
		if _ := bus_map_entries(opts) {
			if v := bus_map_value(opts, 'group') {
				if s := fab_arg_string(v) {
					group = s
				}
			}
			if v := bus_map_value(opts, 'from') {
				if iv := fab_arg_int(v) {
					from = iv
					has_from = true
				}
			}
			pmax, pdlq, perr2, pok2 := fab_policy_from_opts(opts)
			if !pok2 {
				return perr2
			}
			decl_max = pmax
			decl_dlq = pdlq
		}
	}
	if observe && group != '' {
		return mk_err(fab_err_group, 'E_FABRIC_GROUP: an observe subscription takes no group (observe is read-only; no offsets)')
	}
	if decl_max > 0 && group == '' {
		return mk_err(fab_err_policy, 'E_FABRIC_POLICY: a redelivery policy is group state (§9.1) — it needs a group subscription')
	}
	j, jerr, jok := fab_journal_of(f)
	if !jok {
		return jerr
	}
	mut committed := i64(0)
	mut eff_max := i64(0)
	mut eff_dlq := ''
	if group != '' {
		committed = fab_load_committed(j, stream, group)
		rmax, rdlq, rerr, rok := fab_policy_resolve(j, stream, group, decl_max, decl_dlq)
		if !rok {
			return rerr
		}
		eff_max = rmax
		eff_dlq = rdlq
	}
	// cursor: explicit from wins; else a grouped subscription resumes from
	// its committed offset + 1 (the §19.3 redelivery contract); else the
	// stream head is NOT skipped — an ungrouped/observe subscription reads
	// from the beginning (seq 1), replay being the durable plane's point.
	cursor := if has_from {
		from
	} else if group != '' {
		committed + 1
	} else {
		i64(1)
	}
	f.next_sub++
	sub := &FabricSub{
		id:             f.next_sub
		stream:         stream
		pattern:        pat
		group:          group
		observe:        observe
		active:         true
		cursor:         cursor
		committed:      committed
		max_deliveries: eff_max
		dlq:            eff_dlq
	}
	f.subs[sub.id] = sub
	return fab_sub_elem(f, sub)
}

fn fabric_subscribe(args []cx.Node) cx.Node {
	return fab_subscribe_common(args, false)
}

fn fabric_observe(args []cx.Node) cx.Node {
	return fab_subscribe_common(args, true)
}

// ── durable plane: receive (env-aware — predicate patterns) ───────────────

// fabric_receive is the batched pull primitive (spec §19.1): scans the
// journal from the subscription's cursor, filters by the registered pattern
// (applied to the EVENT payload), returns up to opts.max entries, and
// advances the cursor past every SCANNED entry (matched or not — a
// non-matching entry is consumed for this subscription). Embedded receive
// never blocks: it returns what is committed now (the empty node-set when
// nothing) — blocking semantics arrive with the served tier's push (P1).
fn fabric_receive(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 1 {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: receive expects ($sub)')
	}
	f, mut s, serr, sok := fab_get_sub(args[0])
	if !sok {
		return serr
	}
	mut max := i64(-1)
	if args.len > 1 {
		opts := args[1]
		if _ := bus_map_entries(opts) {
			if v := bus_map_value(opts, 'max') {
				if iv := fab_arg_int(v) {
					if iv < 1 {
						return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: max must be a positive int')
					}
					max = iv
				}
			}
		}
	}
	r := journal_stdlib_builtin('journal-since', [f.journal_elem, cx.Node(bus_int(s.cursor)),
		cx.Node(bus_str(s.stream))]) or {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: journal-since unavailable')
	}
	mut out := []cx.Node{}
	if r is cx.Element {
		if r.name == 'err' {
			return r
		}
		// journal-since returns the seq-marker sequence of [entry] elements,
		// or the empty node-set.
		for it in r.items {
			if max >= 0 && i64(out.len) >= max {
				break
			}
			if it is cx.Element {
				if it.name == 'entry' {
					mut seq := i64(0)
					for a in it.attrs {
						if a.name == 'seq' {
							seq = cx.scalar_value_str_public(a.value).i64()
						}
					}
					// the pattern applies to the published EVENT payload.
					mut event := cx.Node(bus_null())
					mut has_event := false
					for ch in it.items {
						if ch is cx.Element {
							if ch.name == 'event' && ch.items.len > 0 {
								event = ch.items[0]
								has_event = true
							}
						}
					}
					// every scanned entry is consumed for this subscription.
					s.cursor = seq + 1
					if has_event && bus_pattern_matches(s.pattern, event, mut env) {
						// §9.1 head-of-tail accounting: the first matching entry
						// above the committed offset in this subscription's
						// lifetime is the resume head — gate it when a policy is
						// active (deliver + record, or dead-letter + auto-commit).
						if s.max_deliveries > 0 && !s.counted && seq > s.committed {
							j, jerr, jok := fab_journal_of(f)
							if !jok {
								return jerr
							}
							deliver, gerr, gok := fab_policy_gate(j, f.journal_elem,
								s.stream, s.group, seq, it, s.max_deliveries, s.dlq)
							if !gok {
								return gerr
							}
							if !deliver {
								s.committed = seq // dead-lettered + committed through
								continue
							}
							s.counted = true
						}
						out << cx.Node(it)
					}
				}
			}
		}
	}
	if out.len == 0 {
		return bus_empty()
	}
	return bus_seq(out)
}

// ── durable plane: ack (cumulative offset commit) ─────────────────────────

// fabric_ack commits the group offset THROUGH seq (cumulative, spec §19.5)
// and persists it as store data (§9). Idempotent for seq at-or-below the
// committed offset. Observe subscriptions refuse (CXER4922); ungrouped
// subscriptions have no offset to commit (CXER4923).
fn fabric_ack(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: ack expects ($sub, $seq)')
	}
	f, mut s, serr, sok := fab_get_sub(args[0])
	if !sok {
		return serr
	}
	if s.observe {
		return mk_err(fab_err_observe_only, 'E_FABRIC_OBSERVE_ONLY: ack on an observe subscription (observe is read-only)')
	}
	if s.group == '' {
		return mk_err(fab_err_group, 'E_FABRIC_GROUP: ack needs a group subscription (no group, no committable offset)')
	}
	seq := fab_arg_int(args[1]) or {
		return mk_err(fab_err_offset, 'E_FABRIC_OFFSET: ack seq must be an int')
	}
	if seq < 0 {
		return mk_err(fab_err_offset, 'E_FABRIC_OFFSET: ack seq must be >= 0')
	}
	if seq <= s.committed {
		return bus_null() // cumulative: at-or-below committed is a no-op
	}
	j, jerr, jok := fab_journal_of(f)
	if !jok {
		return jerr
	}
	s.committed = seq
	fab_persist_committed(j, s.stream, s.group, seq)
	return bus_null()
}

// ── transient plane: emit / read (latest-wins channels) ───────────────────

// fabric_emit publishes a value on a transient channel — latest-wins
// single-slot semantics (spec §6/§12: no history, no replay, no ack; the
// generalized xap Tier-2 coord pattern). Key convention:
// `<tenant>/<scope>/<name>` (§19.4).
fn fabric_emit(args []cx.Node) cx.Node {
	if args.len < 3 {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: emit expects ($fabric, $channel, $value)')
	}
	mut f, ferr, fok := fab_get_open(args[0])
	if !fok {
		return ferr
	}
	channel := fab_arg_string(args[1]) or {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: channel must be a non-empty string')
	}
	f.channels[channel] = args[2]
	return bus_null()
}

// fabric_read returns a transient channel's latest value, or the empty
// node-set when the channel has never been published (absence, never null).
fn fabric_read(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: read expects ($fabric, $channel)')
	}
	f, ferr, fok := fab_get_open(args[0])
	if !fok {
		return ferr
	}
	channel := fab_arg_string(args[1]) or {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: channel must be a non-empty string')
	}
	return f.channels[channel] or { bus_empty() }
}

// ── §12.1 request-reply (the transient-plane call convention) ─────────────
//
// respond registers an arity-1 callable answering a channel; request is a
// blocking call. The EMBEDDED tier applies the callable synchronously at the
// request site — the degenerate but fully working form (spec §13), exactly
// as bus applies handlers — so `serve` (the remote responder's pump) returns
// 0 by construction: nothing is ever pending in-proc. RPC is not truth:
// nothing here touches the journal.

// fabric_respond registers the responder — sticky-exclusive per channel: a
// second respond while the holder lives refuses (CXER4933); the embedded
// holder lives until fabric close.
fn fabric_respond(args []cx.Node) cx.Node {
	if args.len < 3 {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: respond expects ($fabric, $channel, $fn)')
	}
	mut f, ferr, fok := fab_get_open(args[0])
	if !fok {
		return ferr
	}
	channel := fab_arg_string(args[1]) or {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: channel must be a non-empty string')
	}
	if !is_fn_value(args[2]) {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: responder must be a callable (an arity-1 fn over the request value)')
	}
	if channel in f.responders {
		return mk_err(fab_err_responder, 'E_FABRIC_RESPONDER: channel "${channel}" already has a live responder (sticky-exclusive, §12.1)')
	}
	f.responders[channel] = args[2]
	f.next_resp++
	return cx.Element{
		name:  'fabric-responder'
		attrs: [
			bus_attr_int('handle', f.handle),
			bus_attr_int('id', f.next_resp),
			bus_attr('channel', channel),
		]
	}
}

// fabric_request is the blocking call (env-aware: it applies the responder
// callable). The reply is the callable's return value; a raised or returned
// err travels to the requester verbatim (the failure channel).
fn fabric_request(args []cx.Node, mut env MatchEnv) cx.Node {
	if args.len < 3 {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: request expects ($fabric, $channel, $value)')
	}
	f, ferr, fok := fab_get_open(args[0])
	if !fok {
		return ferr
	}
	channel := fab_arg_string(args[1]) or {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: channel must be a non-empty string')
	}
	if args.len > 3 {
		opts := args[3]
		if _ := bus_map_entries(opts) {
			if v := bus_map_value(opts, 'deadline') {
				iv := fab_arg_int(v) or {
					return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: deadline must be ≥ 0 (ms)')
				}
				if iv < 0 {
					return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: deadline must be ≥ 0 (ms)')
				}
				// the embedded call is synchronous — the deadline is validated
				// for surface parity and applies on the remote tier.
			}
		}
	}
	fv := f.responders[channel] or {
		return mk_err(fab_err_no_responder, 'E_FABRIC_NO_RESPONDER: no live responder on channel "${channel}"')
	}
	return apply_fn_value(fv, [args[2]], mut env) or { bus_err_value_of(err) }
}

// fab_get_responder resolves a `[fabric-responder]` argument on the embedded
// tier.
fn fab_get_responder(arg cx.Node) (&FabricState, string, cx.Node, bool) {
	fid := fab_handle_of(arg, 'fabric-responder') or {
		return unsafe { nil }, '', mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: not a [fabric-responder] handle'), false
	}
	mut channel := ''
	if arg is cx.Element {
		for a in arg.attrs {
			if a.name == 'channel' {
				channel = cx.scalar_value_str_public(a.value)
			}
		}
	}
	f := fabric_lookup(fid) or {
		return unsafe { nil }, '', mk_err(fab_err_handle, 'E_FABRIC_HANDLE: unknown fabric handle ${fid}'), false
	}
	if !f.open {
		return unsafe { nil }, '', mk_err(fab_err_handle, 'E_FABRIC_HANDLE: operation on a closed fabric'), false
	}
	if channel == '' || channel !in f.responders {
		return unsafe { nil }, '', mk_err(fab_err_handle, 'E_FABRIC_HANDLE: no registered responder for channel "${channel}"'), false
	}
	return f, channel, bus_null(), true
}

// fabric_serve_requests pumps a responder — the remote tier drains pushed
// request frames here; embedded requests were answered at the call site, so
// the embedded pump reports 0 served by construction.
fn fabric_serve_requests(args []cx.Node) cx.Node {
	if args.len < 1 {
		return mk_err(fab_err_arg_invalid, 'E_FABRIC_ARG_INVALID: serve expects ($responder)')
	}
	_, _, rerr, rok := fab_get_responder(args[0])
	if !rok {
		return rerr
	}
	return bus_int(0)
}

// ── dispatch ──────────────────────────────────────────────────────────────

// fabric_stdlib_builtin — the env-free chain entry (stdlib_dispatch.v).
// Remote handles route to the wire tier first (one client surface, two
// tiers); embedded handles fall through to the in-proc implementations.
// fab_batch_publish appends N events to one stream through ONE handle —
// PIPELINED over the served tier (send all frames, then collect receipts:
// ~one wire round-trip per batch, #593), a plain loop over the embedded
// tier (no RTT to save). Internal engine helper (the xap §3.1.1 batch
// commit lane), not a dispatched verb. One receipt-or-err per event, in
// order; per-event fail-closed.
fn fab_batch_publish(fab cx.Node, stream string, events []cx.Node, atts []cx.Node) []cx.Node {
	if id := fab_remote_arg_id([fab]) {
		if mut fr := fab_remote_lookup(id) {
			return fab_remote_publish_pipeline(mut fr, stream, events, atts)
		}
	}
	// Embedded tier: no RTT to save, but the DURABILITY amortizes (#614) —
	// the whole batch appends inside one store flush scope. Receipts return
	// only after the release lands; a failed release voids every receipt
	// (nothing durable → nothing folds).
	f, _, fok := fab_get_open(fab)
	mut jnode := cx.Node(cx.Element{})
	mut has_j := false
	if fok {
		jnode = f.journal_elem
		has_j = true
		jrn_flush_hold(jnode)
	}
	mut out := []cx.Node{cap: events.len}
	for i, ev in events {
		r := fabric_publish([fab, cx.Node(bus_str(stream)), ev, atts[i]])
		out << r
	}
	if has_j {
		jrn_flush_release(jnode) or {
			ferr := cx.Node(mk_err(fab_err_arg_invalid,
				'E_FABRIC: batch flush failed — nothing durable: ${err.msg()}'))
			for i in 0 .. out.len {
				out[i] = ferr
			}
		}
	}
	return out
}

fn fabric_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	if r := fabric_remote_builtin(name, args) {
		return r
	}
	match name {
		'fabric-open' {
			return fabric_open(args)
		}
		'fabric-close' {
			return fabric_close(args)
		}
		'fabric-publish' {
			return fabric_publish(args)
		}
		'fabric-subscribe' {
			return fabric_subscribe(args)
		}
		'fabric-observe' {
			return fabric_observe(args)
		}
		'fabric-ack' {
			return fabric_ack(args)
		}
		'fabric-emit' {
			return fabric_emit(args)
		}
		'fabric-read' {
			return fabric_read(args)
		}
		'fabric-respond' {
			return fabric_respond(args)
		}
		else {
			return none
		}
	}
}

// fabric_stdlib_builtin_env — receive applies predicate patterns (a CX
// callable), so it needs the evaluator env; tried in the env-aware chain
// beside bus/journal.
fn fabric_stdlib_builtin_env(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	match name {
		'fabric-receive' {
			// a remote subscription's receive needs no evaluator env — the
			// pattern was applied server-side; route it before the embedded
			// (predicate-capable) implementation.
			if r := fabric_remote_builtin(name, args) {
				return r
			}
			return fabric_receive(args, mut env)
		}
		'fabric-request' {
			// the remote request is a wire turn (the responder applies its
			// callable in ITS process); the embedded request applies the
			// registered callable here — env-aware either way for one chain.
			if r := fabric_remote_builtin_env(name, args, mut env) {
				return r
			}
			return fabric_request(args, mut env)
		}
		'fabric-serve' {
			// the remote serve pump applies the client-held callable to each
			// buffered request frame (env-aware); embedded serve is the
			// degenerate 0 (requests were answered at the call site).
			if r := fabric_remote_builtin_env(name, args, mut env) {
				return r
			}
			return fabric_serve_requests(args)
		}
		else {
			return none
		}
	}
}

// The cx-fabric module surface, embedded like every stdlib bundle and
// registered as its OWN package in stdlib_bundle.v (the cx-xap shape).
const stdlib_src_fabric = $embed_file('../stdlib/fabric.cx').to_string()
