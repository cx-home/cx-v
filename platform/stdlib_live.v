@[has_globals]
module platform

import code { MatchEnv, cap_guard, is_err_value, mk_err }
import cx
import cxstore
import os
import time

// stdlib_live.v — the Ring-2 pack for `cx-stdlib/live` (campaign stream 3,
// #675; pack spec spec/03-approved/std-lib/live.md under the ruled live_modes.md
// L129–L137 + the §10 U1 binding). W1 ships the stateless core:
//
//   [$live:changes-since Q BIND CURSOR OPTS?] → [changes [head-set …] ∂…]
//
// The pipeline is the L99 quoted-planar pipeline verbatim (store.md §6.2 /
// store_planar_query.v — parse → §7.8 membership CXER0120 → static slice
// extraction → binding resolution → authorize-before-execute → admissible
// rewrites → execution), with the ONE deliberate widening the pack spec
// names: live sources may be store sources AND journal sources, resolved
// through an explicit $bind map (formal name → open handle) because a live
// query spans a SOURCE SET where store:query binds all names to the one
// queried store.
//
// THE cursor is a head-set — [head-set [s source= pos=]…], one entry per
// FORMAL source name (profile §5.1 spelling; L131: never a scalar). pos is
// the source's own position: the #708 store:log DOCS-PLANE advance seq for
// a store source (the E3 lineage `ms.advances` IS the local feed), the
// stream seq for a journal source. Head positions are sampled at entry;
// store/journal handles are single-owner (the #74 op-lock model), so the
// sampled heads and the reads they cover cannot interleave with a writer.
//
// Paths (live.md §3):
//   - EMPTY cursor → the exact ∂ is the full relation at head as inserts,
//     for EVERY comprehension (equivalence-quartet leg 1) — executed
//     through code.planar_query_execute (the L99 sandbox).
//   - outside the incremental sub-fragment (planar_incremental_membership,
//     L101) → the honest `[recompute reason=…]` marker + the full relation
//     as inserts. Never a wrong ∂, never a silent full scan.
//   - inside it → source deltas are pulled from the store lineage /
//     journal slices and fed through stream 2's ∂ engine
//     (code.planar_delta_init / planar_delta_apply); the output script is
//     the L101 vocabulary verbatim. A mid-window `[recompute]` from the
//     engine (γ retract, group reorder) supersedes the frames: the answer
//     becomes the marker + the maintained relation re-stated as inserts.
//
// A query err is a fault, not a finding — it surfaces as the [err] value.
// Executing the quoted comprehension requires the `eval` capability in
// BOTH paths (the L99 dynamic-execution posture; registered in
// effect_alignment.v). Errors: CXER5070 not-a-quoted-planar-comprehension,
// CXER0120 membership (reused), CXER5071 unbound/mis-kinded formal,
// CXER5072 invalid cursor, CXER5073 resume below retention, CXER4700
// authz deny (reused), CXER1709 op-unsupported store shapes (reused).

const live_err_not_planar = 'cx-err:CXER5070'
const live_err_source_unbound = 'cx-err:CXER5071'
const live_err_cursor_invalid = 'cx-err:CXER5072'
const live_err_below_retention = 'cx-err:CXER5073'
const live_err_closed_drained = 'cx-err:CXER5074'
const live_err_policy_invalid = 'cx-err:CXER5075'
const live_err_not_maintainable = 'cx-err:CXER5076'
const live_err_rung_insufficient = 'cx-err:CXER5077'
const live_err_exclusive_writer = 'cx-err:CXER5078'

// live_stdlib_builtin is the env-FREE dispatch arm (probed by both the
// main and closure-callback chains): the pure ingest helpers.
fn live_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		'live-lower' {
			return live_lower(args)
		}
		else {
			return none
		}
	}
}

// live_lower — the three-way ingest lowering ladder (live.md §8, the
// NORMATIVE order, never a drop): JSON text → the parsed value wrapped
// as [json …]; CX-parseable text → the FIRST ELEMENT verbatim; anything
// else → the lossless [foreign …] named wrapper.
fn live_lower(args []cx.Node) cx.Node {
	if args.len < 1 {
		return mk_err('cx-err:CXER0108', 'E_ARG: lower expects (raw)')
	}
	raw := args[0]
	if raw is cx.ScalarNode {
		v := raw.value
		if v is string {
			jr := code.json_do_parse(v, map[string]cx.Node{})
			if !is_err_value(jr) {
				return cx.Element{
					name:  'json'
					items: [jr]
				}
			}
			doc := cx.parse(v) or { cx.Document{} }
			if doc.elements.len > 0 {
				el := doc.elements[0]
				if el is cx.Element {
					return cx.Node(el)
				}
			}
		}
	}
	return cx.Element{
		name:  'foreign'
		items: [raw]
	}
}

// live_stdlib_builtin_env is the env-aware dispatch arm (registered through
// ring2_register.v; env-aware because the L99 executor threads MatchEnv).
fn live_stdlib_builtin_env(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	match name {
		'live-changes-since' {
			return live_changes_since(args, mut env)
		}
		'live-observe' {
			return live_observe(args, mut env)
		}
		'live-materialize' {
			return live_materialize(args, mut env)
		}
		'live-advance' {
			return live_advance(args, mut env)
		}
		'live-read' {
			return live_read(args, mut env)
		}
		'live-adapt-poll' {
			return live_adapt_poll(args, mut env)
		}
		'live-adapt-watch' {
			return live_adapt_watch(args)
		}
		'live-ingest' {
			return live_ingest(args, mut env)
		}
		else {
			return none
		}
	}
}

// ── the validated query (shared by every verb) ───────────────────────────────

// LiveQuery is one validated live-verb argument set: the rewritten
// comprehension, the resolved $bind map, and the per-formal source facts —
// everything the answer engine needs. Heap-built by live_prepare on
// success only (error paths return nil — the store_get_open convention),
// because ProgramForComp has required fields and so a zero LiveQuery
// literal cannot exist.
@[heap]
struct LiveQuery {
mut:
	comp           cx.ProgramForComp
	slices         []code.PlanarSliceRef
	bindings       map[string]cx.Node
	formals        []string
	formal_kind    map[string]string
	journal_stream map[string]string
}

// live_prepare runs the verb-independent front of the L99 pipeline: parse →
// §7.8 membership (CXER0120) → static slice extraction → $bind resolution
// (CXER5071 before anything executes) → the authz-slice layer when $opts
// carries an authz handle (any [deny] refuses CXER4700 and nothing
// executes) → the admissible L96 rewrites. (query, err, ok).
fn live_prepare(verb string, qarg cx.Node, bindarg cx.Node, opts ?cx.Node) (&LiveQuery, cx.Node, bool) {
	src := code.planar_query_source(qarg) or {
		return unsafe { nil }, mk_err(live_err_not_planar, 'E_LIVE_NOT_PLANAR: ${verb} — the first argument must be a quoted planar comprehension ([?quote [?for …]])'), false
	}
	prog := cx.parse_program(src) or {
		return unsafe { nil }, mk_err(live_err_not_planar, 'E_LIVE_NOT_PLANAR: ${verb} — malformed comprehension source: ${err.msg()}'), false
	}
	if r := code.planar_membership(prog) {
		return unsafe { nil }, code.planar_refusal_err(r), false
	}
	slices := code.planar_extract_slices(prog) or {
		return unsafe { nil }, mk_err(live_err_not_planar, 'E_LIVE_NOT_PLANAR: ${verb} — ${err.msg()} (the live source set is extracted statically; authorize-before-execute needs it)'), false
	}
	// $bind resolution: every FORMAL source name binds to an OPEN handle of
	// its source-ref kind — refused CXER5071 BEFORE anything executes.
	binds := live_map_entries(bindarg)
	mut bindings := map[string]cx.Node{}
	mut formals := []string{}
	mut formal_kind := map[string]string{}
	mut journal_stream := map[string]string{}
	for s in slices {
		if k := formal_kind[s.handle] {
			if k != s.kind {
				return unsafe { nil }, mk_err(live_err_source_unbound, 'E_LIVE_SOURCE_UNBOUND: ${verb} — formal `${s.handle}` is used as both a store and a journal source; one handle cannot satisfy both'), false
			}
		} else {
			formal_kind[s.handle] = s.kind
			formals << s.handle
		}
		if s.kind == 'journal' {
			if st := journal_stream[s.handle] {
				if st != s.path {
					return unsafe { nil }, mk_err(live_err_cursor_invalid, 'E_LIVE_CURSOR_INVALID: ${verb} — formal `${s.handle}` reads two journal streams (`${st}`, `${s.path}`); one head-set position cannot represent both — bind each stream through its own formal name'), false
				}
			} else {
				journal_stream[s.handle] = s.path
			}
		}
		h := binds[s.handle] or {
			return unsafe { nil }, mk_err(live_err_source_unbound, 'E_LIVE_SOURCE_UNBOUND: ${verb} — formal source name `${s.handle}` is not bound in \$bind'), false
		}
		if s.kind == 'store' {
			_, serr, sok := store_get_open(h)
			if !sok {
				return unsafe { nil }, jrn_err_caused(live_err_source_unbound, 'E_LIVE_SOURCE_UNBOUND: ${verb} — formal `${s.handle}` must bind an OPEN store handle for its [\$store:source] reference',
					serr), false
			}
		} else {
			_, jerr, jok := jrn_get_open(h)
			if !jok {
				return unsafe { nil }, jrn_err_caused(live_err_source_unbound, 'E_LIVE_SOURCE_UNBOUND: ${verb} — formal `${s.handle}` must bind an OPEN journal handle for its [\$journal:source] reference',
					jerr), false
			}
		}
		bindings[s.handle] = h
	}
	// the AUTHZ-SLICE layer (authorize-before-execute) — store:query's layer
	// verbatim: any [deny] refuses CXER4700 and nothing executes.
	if o := opts {
		if denial := store_query_authz_layer(o, slices) {
			return unsafe { nil }, denial, false
		}
	}
	comp, _ := code.planar_rewrite(prog) or {
		return unsafe { nil }, mk_err(code.planar_err_code, '${verb} — ${err.msg()}'), false
	}
	return &LiveQuery{
		comp:           comp
		slices:         slices
		bindings:       bindings
		formals:        formals
		formal_kind:    formal_kind
		journal_stream: journal_stream
	}, store_null(), true
}

// live_ref_key encodes a store formal's named-wire-ref cursor stream in
// the internal position map (the head-set spelling is `[s source=F
// ref=NAME pos=]` — the profile §5.1 per-stream form on the live cursor).
fn live_ref_key(formal string, name string) string {
	return formal + '\x00' + name
}

// live_sample_heads samples every source head and validates the cursor
// against it (an entry beyond its head refuses CXER5072; a cursor entry
// naming an unknown stream refuses CXER5072). A store source samples its
// DOCS-plane head plus one head per named wire ref (#708: the fixed
// store:log is per-ref advance order — W5 wires the full feed).
// (heads, err, ok).
fn live_sample_heads(verb string, q &LiveQuery, cur map[string]i64) (map[string]i64, cx.Node, bool) {
	mut heads := map[string]i64{}
	for fname in q.formals {
		stream := q.journal_stream[fname] or { '' }
		fh := q.bindings[fname] or { cx.Node(cx.ScalarNode{}) }
		if q.formal_kind[fname] == 'store' {
			serr, sok := live_store_heads(fname, fh, mut heads)
			if !sok {
				return heads, serr, false
			}
		} else {
			p, herr, hok := live_head_pos(verb, 'journal', fh, stream)
			if !hok {
				return heads, herr, false
			}
			heads[fname] = p
		}
	}
	for k, cpos in cur {
		p := heads[k] or {
			return heads, mk_err(live_err_cursor_invalid, 'E_LIVE_CURSOR_INVALID: ${verb} — head-set entry `${live_key_label(k)}` names no stream of this source set'), false
		}
		if cpos > p {
			return heads, mk_err(live_err_cursor_invalid, 'E_LIVE_CURSOR_INVALID: ${verb} — head-set entry `${live_key_label(k)}` is beyond the source head (pos=${cpos}, head=${p})'), false
		}
	}
	return heads, store_null(), true
}

fn live_key_label(k string) string {
	return k.replace('\x00', '/ref/')
}

// live_store_heads samples one store formal's per-stream heads: the
// docs-plane position plus one position per named wire ref. (err, ok).
fn live_store_heads(formal string, h cx.Node, mut heads map[string]i64) (cx.Node, bool) {
	ms, errn, ok := store_get_open(h)
	if !ok {
		return errn, false
	}
	if store_remote_active(ms) || !store_objgraph_active(ms) {
		return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: live sources need a local object-graph store (the fixed store:log #708 is the local feed; the wire feed rides the stream-4 store profile)'), false
	}
	mut m := unsafe { ms }
	store_lock_enter(mut m)
	defer {
		store_lock_exit(mut m)
	}
	heads[formal] = ms.adv_pos['docs'] or { i64(0) }
	for k, p in ms.adv_pos {
		if k.starts_with('refs/') {
			heads[live_ref_key(formal, k['refs/'.len..])] = p
		}
	}
	return store_null(), true
}

// ── the verbs ─────────────────────────────────────────────────────────────────

fn live_changes_since(args []cx.Node, mut env MatchEnv) cx.Node {
	if args.len < 3 {
		return mk_err('cx-err:CXER0108', 'E_ARG: changes-since expects (quoted-comprehension, bind-map, cursor, opts?)')
	}
	opts := if args.len > 3 { ?cx.Node(args[3]) } else { ?cx.Node(none) }
	q, perr, pok := live_prepare('changes-since', args[0], args[1], opts)
	if !pok {
		return perr
	}
	// the cursor: a head-set, entries per formal source name (CXER5072).
	cur := live_parse_cursor(args[2], q.formals) or {
		return mk_err(live_err_cursor_invalid, 'E_LIVE_CURSOR_INVALID: changes-since — ${err.msg()}')
	}
	// the L99 dynamic-execution posture: every path executes the quoted
	// comprehension, so every path sits behind the `eval` capability.
	if d := cap_guard('eval', 'live changes-since (quoted planar execution)') {
		return d
	}
	heads, herr, hok := live_sample_heads('changes-since', q, cur)
	if !hok {
		return herr
	}
	return live_answer('changes-since', q, cur, heads, mut env)
}

// live_answer computes the ∂ answer from `cur` to `heads` — the three-path
// core shared VERBATIM by changes-since and each observe poll (observe ≡
// repeated changes-since driven by source advance is the implementation,
// not merely the corpus gate — equivalence-quartet leg 2 by construction).
fn live_answer(verb string, q &LiveQuery, cur map[string]i64, heads map[string]i64, mut env MatchEnv) cx.Node {
	comp := q.comp
	mut empty_cursor := true
	for _, v in cur {
		if v > 0 {
			empty_cursor = false
		}
	}
	// EMPTY cursor: the exact ∂ is the full relation at head as inserts, for
	// every comprehension (equivalence-quartet leg 1 — no [recompute] marker).
	if empty_cursor {
		rows, xerr, xok := live_execute_head(comp, q.bindings, mut env)
		if !xok {
			return xerr
		}
		mut frames := []cx.Node{}
		for i, row in rows {
			frames << live_insert_frame(i, row)
		}
		return live_changes_node(live_headset_node(q.formals, heads), frames)
	}
	// QUIESCENCE exactness: cursor == head on every stream ⇒ the ∂ is empty
	// BY IDENTITY (result@head ⊖ result@cursor at equal coordinates), for
	// every comprehension — the second universal exactness point beside the
	// empty-cursor exception. Positions advance on every source event, so
	// equal heads prove no event happened; answering [recompute] here would
	// claim ignorance of a delta that is provably ∅.
	mut quiescent := true
	for k, hv in heads {
		if (cur[k] or { i64(0) }) != hv {
			quiescent = false
		}
	}
	if quiescent {
		return live_changes_node(live_headset_node(q.formals, heads), [])
	}
	// outside the incremental sub-fragment: the honest [recompute]+full form
	// (strategy-free semantics — result@head re-stated; the consumer rebuilds).
	if x := code.planar_incremental_membership(cx.ProgramNode(comp)) {
		return live_recompute_answer(comp, q.bindings, q.formals, heads, x.reason, mut env)
	}
	gens := live_generator_sources(comp)
	for s in q.slices {
		mut found := false
		for g in gens {
			if g.kind == s.kind && g.formal == s.handle && g.path == s.path {
				found = true
				break
			}
		}
		if !found {
			// the ∂ rules define deltas arriving at independent GENERATORS —
			// a source reference anywhere else has no ∂ entry point.
			return live_recompute_answer(comp, q.bindings, q.formals, heads,
				'a source reference outside a generator position has no ∂ entry point — recompute', mut env)
		}
	}
	// the exact-∂ path: per-generator relation at the cursor + the source
	// deltas in (cursor, head], fed through stream 2's ∂ engine.
	w, werr, wok := live_apply_window(verb, q, comp, gens, cur, heads)
	if !wok {
		return werr
	}
	hs := live_headset_node(q.formals, heads)
	if w.recompute_reason != '' {
		mut out := []cx.Node{}
		out << live_recompute_frame(w.recompute_reason)
		for i, row in w.result {
			out << live_insert_frame(i, row)
		}
		return live_changes_node(hs, out)
	}
	return live_changes_node(hs, w.frames)
}

// LiveApplyOut — one ∂-window application: the output script, the
// maintained relation at head, and the engine's recompute marker (if any).
struct LiveApplyOut {
mut:
	frames           []cx.Node
	result           []cx.Node
	recompute_reason string
}

// live_apply_window replays each generator's relation at the cursor and
// feeds the (cursor, head] source deltas through stream 2's ∂ engine —
// the exact-∂ core shared by changes-since/observe (script consumers) and
// materialize's advance (fold consumer). (out, err, ok).
fn live_apply_window(verb string, q &LiveQuery, comp cx.ProgramForComp, gens []LiveSourceRef, cur map[string]i64, heads map[string]i64) (LiveApplyOut, cx.Node, bool) {
	mut out := LiveApplyOut{}
	mut rels := [][]cx.Node{}
	mut gen_deltas := [][]LiveDelta{}
	for g in gens {
		gh := q.bindings[g.formal] or { cx.Node(cx.ScalarNode{}) }
		if g.kind == 'store' {
			rows, ds, rerr, rok := live_store_replay(verb, gh, g.path, g.formal, cur,
				heads)
			if !rok {
				return out, rerr, false
			}
			rels << rows
			gen_deltas << ds
		} else {
			cpos := cur[g.formal] or { i64(0) }
			hpos := heads[g.formal]
			rows, ds, rerr, rok := live_journal_replay(verb, gh, g.path, cpos, hpos)
			if !rok {
				return out, rerr, false
			}
			rels << rows
			gen_deltas << ds
		}
	}
	mut st := code.planar_delta_init(cx.ProgramNode(comp), rels) or {
		// the incremental-membership gate above admits exactly what init
		// admits — loud if the two ever disagree.
		return out, mk_err('cx-err:CXER0001', 'live ${verb} — ∂ state init failed: ${err.msg()}'), false
	}
	// apply source deltas per generator in clause order (a planar source set
	// has no cross-stream total order — L131; the final relation is
	// interleaving-invariant, frames merge on source-ordinal tuples).
	for gi, ds in gen_deltas {
		for d in ds {
			for row in d.rows {
				delta := cx.Node(cx.Element{
					name:  d.kind
					items: [row]
				})
				script := code.planar_delta_apply(mut st, gi, delta) or {
					// guards inside the sub-fragment are established total
					// (L101/M6), so an application error is an internal
					// inconsistency — loud, never absorbed.
					return out, mk_err('cx-err:CXER0001', 'live ${verb} — ∂ application failed: ${err.msg()}'), false
				}
				if out.recompute_reason == '' {
					for fr in script {
						if fr is cx.Element && fr.name == 'recompute' {
							out.recompute_reason = live_attr_str(fr, 'reason')
							break
						}
					}
					if out.recompute_reason == '' {
						out.frames << script
					} else {
						// superseded: after the honest marker the consumer
						// rebuilds — earlier frames carry no information.
						out.frames = []cx.Node{}
					}
				}
				// keep applying: the engine state must reach head either way.
			}
		}
	}
	out.result = st.result.clone()
	return out, store_null(), true
}

// ── observe: the ∂ subscription (live.md §5; delivery.md §4) ─────────────────
//
// `[$live:observe Q BIND FROM OPTS?] → [live-sub …]` — a live ∂
// subscription over the same validated query. The handle IS a delivery.md
// §4 subscription value from day one (the §10 U1 binding — no bespoke
// handle kind): rung= ALWAYS reported (weakest-of-set for a mixed source
// set), sharing="independent", flow="pull", retention declared
// window|full (retention=latest on a ∂ stream is the structural CXER5075
// policy refusal — delivery §6's rendering of "∂ MUST NOT coalesce",
// L130), the client anchor as the [head-set] child, on-close="live-close"
// ([?with-open]-composable via the __cx_close_id__ stamp).
//
// Client-anchored resume (from=last+1 doctrine): the SOURCES hold no
// per-observer state — the subscription record is the consumer's own
// cursor, advanced by each delivery. Each [?receive] answers the next
// [changes [head-set …] frame…] batch: LITERALLY the changes-since answer
// from the record's cursor to head (live_answer shared verbatim), so
// equivalence-quartet leg 2 (observe ≡ repeated changes-since driven by
// source advance) holds by construction, and a quiescent receive answers
// the honest empty [changes [head-set …]] exactly as changes-since does.
// Stream 7's cursor checks (F2 — engaged always; declaring
// :monotonic-reads/:gapless in $opts is validated and adds nothing the
// default does not already check): from= beyond a head refuses CXER5072,
// from= below the retained tail refuses CXER5073 AT OBSERVE — the honest
// refusal, never a silent re-seed. A fault mid-stream (query err, source
// err, retention loss under the cursor) terminates the subscription LOUD,
// the err delivered as the FINAL FRAME; a drained terminated subscription
// refuses CXER5074 (delivery.md closed-and-drained).

// LiveSubRecord is one observe subscription: the validated query + the
// consumer's cursor. Process-global exactly like the fabric registry (a
// per-program new_env reset is impossible here: new_env is also the L99
// sandbox constructor, and every receive executes the query through it),
// single-owner like the store/journal handles it wraps (the #74 op-lock
// model).
@[heap]
struct LiveSubRecord {
mut:
	id         int
	q          &LiveQuery = unsafe { nil }
	cursor     map[string]i64
	rung       string
	retention  string
	closed     bool
	terminated bool
}

@[heap]
struct LiveRegistry {
mut:
	subs     map[int]&LiveSubRecord
	next_id  int
	mats     map[int]&LiveMatRecord
	next_mat int
}

__global (
	g_live_reg voidptr
)

fn live_reg() &LiveRegistry {
	if g_live_reg == unsafe { nil } {
		r := &LiveRegistry{
			subs:     map[int]&LiveSubRecord{}
			next_id:  1
			mats:     map[int]&LiveMatRecord{}
			next_mat: 1
		}
		g_live_reg = voidptr(r)
	}
	return unsafe { &LiveRegistry(g_live_reg) }
}

fn live_sub_of(n cx.Node) ?&LiveSubRecord {
	if n is cx.Element {
		if n.name == 'live-sub' {
			ids := n.attr('id')
			if ids.starts_with('live-sub-') {
				id := ids['live-sub-'.len..].int()
				reg := live_reg()
				return reg.subs[id] or { return none }
			}
		}
	}
	return none
}

fn live_observe(args []cx.Node, mut env MatchEnv) cx.Node {
	if args.len < 3 {
		return mk_err('cx-err:CXER0108', 'E_ARG: observe expects (quoted-comprehension, bind-map, from, opts?)')
	}
	opts := if args.len > 3 { ?cx.Node(args[3]) } else { ?cx.Node(none) }
	q, perr, pok := live_prepare('observe', args[0], args[1], opts)
	if !pok {
		return perr
	}
	cur := live_parse_cursor(args[2], q.formals) or {
		return mk_err(live_err_cursor_invalid, 'E_LIVE_CURSOR_INVALID: observe — ${err.msg()}')
	}
	// the ∂-subscription policy axes (delivery §6 made structural).
	mut retention := 'window'
	if o := opts {
		if rv := live_opt_str(o, 'retention') {
			if rv == 'latest' {
				return mk_err(live_err_policy_invalid, 'E_LIVE_POLICY_INVALID: observe — retention=latest on a ∂ stream is not a point (each insert/retract is information; ∂ MUST NOT coalesce, L130); declare retention=window|full')
			}
			if rv !in ['window', 'full'] {
				return mk_err(live_err_policy_invalid, 'E_LIVE_POLICY_INVALID: observe — retention=`${rv}` is not a ∂-stream point; declare retention=window|full')
			}
			retention = rv
		}
		if gv := live_opt_str(o, 'rung') {
			// the $opts guarantee declaration (live.md §5/§8): the
			// stream-7 consumer-checkable tokens (:monotonic-reads/
			// :gapless — their checks run unconditionally below) plus
			// the three LADDER atoms as consumer REQUIREMENTS. Requiring
			// a stronger rung than the source set declares refuses
			// CXER5077 at wiring time — refuse-to-lie, never a silent
			// downgrade.
			if rerr := live_check_rung_opt('observe', gv, q) {
				return rerr
			}
		}
	}
	// the L99 dynamic-execution posture (subscription polls execute the
	// quoted comprehension; creation validates by replaying at the anchor).
	if d := cap_guard('eval', 'live observe (quoted planar execution)') {
		return d
	}
	_, herr, hok := live_sample_heads('observe', q, cur)
	if !hok {
		return herr
	}
	// stream 7's cursor checks (F2), engaged always: a from= below the
	// retained tail refuses CXER5073 NOW — never a silent re-seed.
	if verr := live_validate_resume(q, cur) {
		return verr
	}
	mut reg := live_reg()
	id := reg.next_id
	reg.next_id++
	rung := live_source_set_rung(q)
	rec := &LiveSubRecord{
		id:        id
		q:         q
		cursor:    cur.clone()
		rung:      rung
		retention: retention
	}
	reg.subs[id] = rec
	handle := cx.Element{
		name:  'live-sub'
		attrs: [
			bus_attr('id', 'live-sub-${id}'),
			bus_attr('rung', rung),
			bus_attr('sharing', 'independent'),
			bus_attr('flow', 'pull'),
			bus_attr('retention', retention),
			bus_attr('on-close', 'live-close'),
		]
		items: [live_headset_node(q.formals, cur)]
	}
	return bus_stamp_closeable(cx.Node(handle), 'live-close', fn [id] () ! {
		mut reg2 := live_reg()
		mut r := reg2.subs[id] or { return }
		r.closed = true
	}, mut env)
}

// live_validate_resume replays the exact-∂ path's relation at the anchor —
// the eager stream-7 cursor check: history below the anchor that is no
// longer reconstructable refuses CXER5073 at creation. The recompute path
// replays nothing (its answers never depend on history), so it validates
// nothing here — exactly changes-since's behavior for the same cursor.
fn live_validate_resume(q &LiveQuery, cur map[string]i64) ?cx.Node {
	comp := q.comp
	mut nonzero := false
	for f in q.formals {
		if (cur[f] or { i64(0) }) > 0 {
			nonzero = true
		}
	}
	if !nonzero {
		return none
	}
	if _ := code.planar_incremental_membership(cx.ProgramNode(comp)) {
		return none
	}
	gens := live_generator_sources(comp)
	for s in q.slices {
		mut found := false
		for g in gens {
			if g.kind == s.kind && g.formal == s.handle && g.path == s.path {
				found = true
				break
			}
		}
		if !found {
			return none
		}
	}
	for g in gens {
		cpos := cur[g.formal] or { i64(0) }
		gh := q.bindings[g.formal] or { cx.Node(cx.ScalarNode{}) }
		if g.kind == 'store' {
			if cpos == 0 && !live_cur_has_refs(cur, g.formal) {
				continue
			}
			// replay at the anchor: head = the anchor itself.
			_, _, rerr, rok := live_store_replay('observe', gh, g.path, g.formal, cur,
				cur)
			if !rok {
				return rerr
			}
		} else {
			if cpos == 0 {
				continue
			}
			_, _, rerr, rok := live_journal_replay('observe', gh, g.path, cpos, cpos)
			if !rok {
				return rerr
			}
		}
	}
	return none
}

fn live_cur_has_refs(cur map[string]i64, formal string) bool {
	prefix := formal + '\x00'
	for k, v in cur {
		if v > 0 && k.starts_with(prefix) {
			return true
		}
	}
	return false
}

// live_source_set_rung reports the declared guarantee rung of the source
// set — each member's declared rung, WEAKEST wins (live.md §5). Native
// store/journal sources declare :complete-ordered (the store log is
// per-ref ordered, the journal prefix-consistent); a journal stream
// carrying an adapter declaration (the stream-7 handle-floor slice,
// live.md §8) reports the ADAPTER's declared rung.
fn live_source_set_rung(q &LiveQuery) string {
	mut weakest := ''
	for f in q.formals {
		mut r := ':complete-ordered' // native default
		if q.formal_kind[f] == 'journal' {
			if jh := q.bindings[f] {
				if dr := live_journal_declared_rung(jh, q.journal_stream[f] or { '' }) {
					r = dr
				}
			}
		}
		if weakest == '' || live_rung_rank(r) < live_rung_rank(weakest) {
			weakest = r
		}
	}
	if weakest == '' {
		return ':complete-ordered'
	}
	return weakest
}

// live_adapter_decl_alias — the adapter-stream declaration alias inside
// the journal's own store (default stream keeps the segment-less
// spelling; shared with jrn_declare_adapter_stream / jrn_declared_writer).
fn live_adapter_decl_alias(tenant string, stream string) string {
	if stream == '' {
		return 'cx-live/adapter/${tenant}'
	}
	return 'cx-live/adapter/${tenant}/s/${stream}'
}

// live_journal_declared_rung reads a journal stream's declared adapter
// rung, or none for an undeclared (native) stream.
fn live_journal_declared_rung(jh cx.Node, stream string) ?string {
	j, _, ok := jrn_get_open(jh)
	if !ok {
		return none
	}
	sname := if jrn_is_default(stream) { '' } else { stream }
	d := jrn_read_adapter_decl(j, sname) or { return none }
	r := d.attr('rung')
	if r == '' {
		return none
	}
	return r
}

// live_rung_rank orders the closed guarantee ladder (live.md §8), weakest
// first: :snapshot-diff < :coalesced-rescan < :complete-ordered.
fn live_rung_rank(r string) int {
	return match r {
		':snapshot-diff' { 1 }
		':coalesced-rescan' { 2 }
		':complete-ordered' { 3 }
		else { 0 }
	}
}

// live_check_rung_opt validates an $opts rung= declaration: the two
// stream-7 consumer-checkable tokens are accepted (their cursor checks
// run unconditionally at creation), a LADDER atom is a consumer
// REQUIREMENT compared against the source set's declared rung
// (weakest-of-set) — a requirement stronger than the declaration refuses
// CXER5077 at wiring time; anything else refuses CXER5075.
fn live_check_rung_opt(verb string, gv string, q &LiveQuery) ?cx.Node {
	declared := live_source_set_rung(q)
	for tok in gv.split(' ') {
		if tok == '' {
			continue
		}
		if tok.len > 1 && tok[1..] in cst_consumer_checkable {
			// stream 7: the two consumer-checkable consistency tokens come
			// from the ONE vocabulary authority (consistency_vocab.v); their
			// cursor checks run unconditionally below.
			continue
		}
		req := live_rung_rank(tok)
		if req == 0 {
			return mk_err(live_err_policy_invalid, 'E_LIVE_POLICY_INVALID: ${verb} — rung token `${tok}` is not a declarable consumer guarantee (declarable: :monotonic-reads :gapless, or a ladder requirement :snapshot-diff | :coalesced-rescan | :complete-ordered)')
		}
		if req > live_rung_rank(declared) {
			return mk_err(live_err_rung_insufficient, 'E_LIVE_RUNG_INSUFFICIENT: ${verb} — the consumer requires ${tok} but the source set declares ${declared} (weakest member) — refuse-to-lie, never a silent downgrade (live modes L134)')
		}
	}
	return none
}

// ── the consumption arms (registered Ring2SubOps; #762 generalizes) ──────────

// live_sub_receive is the [?receive] arm. max=0 → the unbatched form: ONE
// poll, answered as the [changes …] batch (empty when quiescent — the
// honest changes-since answer). max>0 → the U1.12a batch form: up to max
// NON-EMPTY batches, waiting up to deadline_ms between polls (a quiescent
// poll is a non-delivery for batching); returns the sequence received.
fn live_sub_receive(sub cx.Node, max int, deadline_ms i64, mut env MatchEnv) cx.Node {
	mut rec := live_sub_of(sub) or {
		return mk_err('cx-err:CXER0108', 'E_ARG: [?receive] — unknown or stale live-sub handle')
	}
	// each poll EXECUTES the quoted comprehension — the same eval-capability
	// posture as every live execution path.
	if d := cap_guard('eval', 'live observe receive (quoted planar execution)') {
		return d
	}
	if max == 0 {
		return live_sub_poll(mut rec, mut env)
	}
	mut out := []cx.Node{}
	sw := time.new_stopwatch()
	for {
		if rec.closed || rec.terminated {
			if out.len == 0 {
				return mk_err(live_err_closed_drained, 'E_LIVE_CLOSED_DRAINED: [?receive] — the subscription is terminated and fully drained (delivery.md closed-and-drained)')
			}
			break
		}
		b := live_sub_poll(mut rec, mut env)
		if is_err_value(b) {
			if out.len == 0 {
				return b
			}
			break
		}
		if live_batch_has_frames(b) {
			out << b
			if out.len >= max {
				break
			}
		}
		if deadline_ms < 0 || sw.elapsed().milliseconds() >= deadline_ms {
			break
		}
		time.sleep(time.millisecond)
	}
	return cx.Element{
		name:  code.seq_marker_name
		items: out
	}
}

// live_sub_ready is the [?select] readiness probe (delivery §4: "is a
// delivery available without blocking" — non-consuming): ready when any
// source advanced past the cursor. A sampling fault answers ready — the
// receive that follows delivers the fault loud as the final frame.
fn live_sub_ready(sub cx.Node, mut env MatchEnv) bool {
	rec := live_sub_of(sub) or { return false }
	if rec.closed || rec.terminated {
		return false
	}
	heads, _, hok := live_sample_heads('observe', rec.q, rec.cursor)
	if !hok {
		return true
	}
	for k, hv in heads {
		if hv > (rec.cursor[k] or { i64(0) }) {
			return true
		}
	}
	return false
}

// live_sub_poll answers one poll: the changes-since answer from the sub's
// cursor to head (live_answer verbatim). A fault terminates the
// subscription LOUD — the err is delivered as the FINAL FRAME of a
// terminal [changes] batch whose head-set is the unadvanced cursor (the
// consumer cannot resume past a fault); after it the subscription is
// closed-and-drained (CXER5074).
fn live_sub_poll(mut rec LiveSubRecord, mut env MatchEnv) cx.Node {
	if rec.closed || rec.terminated {
		return mk_err(live_err_closed_drained, 'E_LIVE_CLOSED_DRAINED: [?receive] — the subscription is terminated and fully drained (delivery.md closed-and-drained)')
	}
	heads, herr, hok := live_sample_heads('observe', rec.q, rec.cursor)
	if !hok {
		rec.terminated = true
		return live_changes_node(live_headset_node(rec.q.formals, rec.cursor), [herr])
	}
	ans := live_answer('observe', rec.q, rec.cursor, heads, mut env)
	if is_err_value(ans) {
		rec.terminated = true
		return live_changes_node(live_headset_node(rec.q.formals, rec.cursor), [ans])
	}
	rec.cursor = heads.clone()
	return ans
}

// live_batch_has_frames — a [changes] batch carrying at least one frame
// beyond its head-set (the batching non-delivery test).
fn live_batch_has_frames(b cx.Node) bool {
	if b is cx.Element {
		if b.name == 'changes' {
			return b.items.len > 1
		}
	}
	return false
}

// live_opt_str reads a plain-string option from a `{…}` opts map.
fn live_opt_str(n cx.Node, key string) ?string {
	m := live_map_entries(n)
	v := m[key] or { return none }
	if v is cx.ScalarNode {
		sv := v.value
		if sv is string {
			return sv
		}
	}
	return none
}

// ── materialize: the named, store-aliased, checkpointed fold (live.md §7) ────
//
// `[$live:materialize STORE Q BIND NAME OPTS?] → [materialization …]` — the
// fold value lives in $store as a doc, $name is its alias, and THE
// CHECKPOINT IS THE DURABLE CURSOR (value-anchored, delivery §5):
// checkpoint doc = `[checkpoint q= [head-set …] ROW…]` (q= is the Tier-1
// hash of the canonical comprehension text — it makes re-attachment safe:
// materialize on an existing alias re-attaches iff the query matches, and
// refuses CXER1114 when the name is held by a DIFFERENT fold), written
// put-doc-then-alias with the alias advanced by an expect-pos CAS on its
// per-name advance position (CXER1114 on conflict — L119).
//
// `[$live:advance REF OPTS?]` is the maintenance tick (sched cadence is
// the deployment driver): pull the bound sources to head, apply ∂ inside
// the incremental sub-fragment or recompute LOUD outside it, checkpoint,
// CAS the alias. Per-aggregate maintenance (L130): a γ-retract whose fold
// uses only the invertible aggregates (sum/count/avg — $count included)
// is ABSORBED (recomputed=false, "sum decrements exactly"); max/min/
// distinct force the loud group recompute (recomputed=true, the named
// boundary). `$opts maintenance="incremental"` (declared at materialize)
// turns every loud recompute into the typed refusal CXER5076.
// Derived-state posture: a missing/unreadable/mismatched checkpoint means
// FULL REPLAY (recompute at head; correctness untouched).
//
// `[$live:read REF] → [snapshot [head-set …] ROW…]` — a point-in-time
// read of the checkpoint; the value carries its coordinate ({at-seq} for
// a multi-source fold IS a head-set). Reads MAY coalesce (the sanctioned
// 25ms leading+trailing shape is the XAP SSE edge's); the in-process read
// is exact and needs no coalescer.
//
// Registration (the L133 retention cover extension): a materialization
// over journal sources registers itself IN each journal's own store
// (alias `cx-live/materialization/<tenant>[/s/<stream>]/<name>` → a
// `[live-materialization]` doc — the fabric-offset pattern), and
// journal-retain refuses a pruning boundary while a registration exists
// on the stream (jrn_retain carries the check). Store sources need no
// registration: a store relation is CURRENT state — full replay reads
// live docs, no history.

@[heap]
struct LiveMatRecord {
mut:
	id          int
	q           &LiveQuery = unsafe { nil }
	store       cx.Node // the checkpoint store handle
	name        string  // the alias
	qhash       string  // Tier-1 hash of the canonical comprehension text
	maintenance string  // '' | 'incremental'
}

fn live_mat_of(n cx.Node) ?&LiveMatRecord {
	if n is cx.Element {
		if n.name == 'materialization' {
			ids := n.attr('id')
			if ids.starts_with('live-mat-') {
				id := ids['live-mat-'.len..].int()
				reg := live_reg()
				return reg.mats[id] or { return none }
			}
		}
	}
	return none
}

// live_alias_pos reads the alias's per-name advance position (the CAS
// expect value) and its current target under the op lock.
fn live_alias_pos(ms &MemStore, alias string) (i64, string) {
	mut m := unsafe { ms }
	store_lock_enter(mut m)
	defer {
		store_lock_exit(mut m)
	}
	return ms.adv_pos['aliases/' + alias] or { i64(0) }, ms.aliases[alias] or { '' }
}

// live_alias_advance_cas advances the checkpoint alias iff its per-name
// advance position still equals `expect` — the L119 expect-pos CAS,
// refused CXER1114 on conflict. Mirrors the set-alias verb's local path
// (presence check + live table + persistence record) under ONE hold of
// the reentrant op lock so no writer interleaves the check and the set.
fn live_alias_advance_cas(mut ms MemStore, alias string, hash string, expect i64) ?cx.Node {
	store_lock_enter(mut ms)
	defer {
		store_lock_exit(mut ms)
	}
	cur := ms.adv_pos['aliases/' + alias] or { i64(0) }
	if cur != expect {
		return mk_err('cx-err:CXER1114', 'E_STORE_REF_CONFLICT: materialization alias `${alias}` moved (advance pos=${cur}, expected ${expect}) — re-read the checkpoint and retry')
	}
	if !store_doc_present(ms, hash) {
		return mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: checkpoint doc ${hash}')
	}
	store_alias_set_local(mut ms, alias, hash)
	store_append(mut ms, store_alias_record(alias, hash)) or {
		return store_persist_err(ms, err.msg())
	}
	return none
}

// live_checkpoint_doc builds `[checkpoint q= [head-set …] ROW…]`.
fn live_checkpoint_doc(qhash string, formals []string, pos map[string]i64, rows []cx.Node) cx.Node {
	mut items := []cx.Node{cap: rows.len + 1}
	items << live_headset_node(formals, pos)
	items << rows
	return cx.Element{
		name:  'checkpoint'
		attrs: [
			cx.Attribute{
				name:  'q'
				value: cx.ScalarValue(qhash)
			},
		]
		items: items
	}
}

// live_read_checkpoint loads and validates the checkpoint behind `alias`:
// (cursor, rows, expect-pos, ok). ok=false = the derived-state full-replay
// signal (absent alias, unreadable doc, or a q= mismatch — never an
// error: correctness is untouched by checkpoint loss).
fn live_read_checkpoint(ms &MemStore, alias string, qhash string, formals []string) (map[string]i64, []cx.Node, i64, bool) {
	pos, target := live_alias_pos(ms, alias)
	if target == '' {
		return map[string]i64{}, []cx.Node{}, pos, false
	}
	text := store_doc_text(ms, target) or { return map[string]i64{}, []cx.Node{}, pos, false }
	root := store_decode_doc(text)
	if root !is cx.Element {
		return map[string]i64{}, []cx.Node{}, pos, false
	}
	el := root as cx.Element
	if el.name != 'checkpoint' || el.attr('q') != qhash {
		return map[string]i64{}, []cx.Node{}, pos, false
	}
	if el.items.len == 0 {
		return map[string]i64{}, []cx.Node{}, pos, false
	}
	cur := live_parse_cursor(el.items[0], formals) or {
		return map[string]i64{}, []cx.Node{}, pos, false
	}
	return cur, el.items[1..].clone(), pos, true
}

// live_mat_reg_alias — the registration alias inside a journal's own
// store (default stream keeps the segment-less spelling, the journal
// namespace discipline).
fn live_mat_reg_alias(tenant string, stream string, name string) string {
	if stream == '' {
		return 'cx-live/materialization/${tenant}/${name}'
	}
	return 'cx-live/materialization/${tenant}/s/${stream}/${name}'
}

// live_mat_register writes/updates the registration doc in every journal
// source's own store (the L133 retention cover extension's visible side).
fn live_mat_register(rec &LiveMatRecord, at map[string]i64) {
	for f in rec.q.formals {
		if rec.q.formal_kind[f] != 'journal' {
			continue
		}
		jh := rec.q.bindings[f] or { continue }
		j, _, jok := jrn_get_open(jh)
		if !jok {
			continue
		}
		stream := rec.q.journal_stream[f] or { '' }
		sname := if jrn_is_default(stream) { '' } else { stream }
		doc := cx.Element{
			name:  'live-materialization'
			attrs: [
				cx.Attribute{
					name:  'name'
					value: cx.ScalarValue(rec.name)
				},
				cx.Attribute{
					name:  'stream'
					value: cx.ScalarValue(stream)
				},
				cx.Attribute{
					name:  'at'
					value: cx.ScalarValue(at[f] or { i64(0) })
				},
			]
		}
		jrn_set_meta_alias(j.store_id, live_mat_reg_alias(j.tenant, sname, rec.name),
			cx.Node(doc)) or {}
	}
}

fn live_materialize(args []cx.Node, mut env MatchEnv) cx.Node {
	if args.len < 4 {
		return mk_err('cx-err:CXER0108', 'E_ARG: materialize expects (store, quoted-comprehension, bind-map, name, opts?)')
	}
	ms, serr, sok := store_get_open(args[0])
	if !sok {
		return serr
	}
	if store_remote_active(ms) || !store_objgraph_active(ms) {
		return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: materialize needs a local object-graph checkpoint store (the wire CAS rides the stream-4 store profile)')
	}
	opts := if args.len > 4 { ?cx.Node(args[4]) } else { ?cx.Node(none) }
	q, perr, pok := live_prepare('materialize', args[1], args[2], opts)
	if !pok {
		return perr
	}
	mut name := ''
	if args[3] is cx.ScalarNode {
		v := (args[3] as cx.ScalarNode).value
		if v is string {
			name = v
		}
	}
	if name == '' {
		return mk_err('cx-err:CXER0108', 'E_ARG: materialize — name must be a non-empty string (the fold\'s alias in the store)')
	}
	mut maintenance := ''
	if o := opts {
		if mv := live_opt_str(o, 'maintenance') {
			if mv !in ['incremental', 'auto'] {
				return mk_err(live_err_policy_invalid, 'E_LIVE_POLICY_INVALID: materialize — maintenance=`${mv}` is not a point (declare maintenance=incremental, or omit for the default recompute-loud posture)')
			}
			if mv == 'incremental' {
				maintenance = mv
			}
		}
		if gv := live_opt_str(o, 'rung') {
			// materialize is a consumer too (live.md §8): the same
			// wiring-time rung requirement check as observe.
			if rerr := live_check_rung_opt('materialize', gv, q) {
				return rerr
			}
		}
	}
	if maintenance == 'incremental' {
		if x := code.planar_incremental_membership(cx.ProgramNode(q.comp)) {
			return mk_err(live_err_not_maintainable, 'E_LIVE_NOT_MAINTAINABLE: materialize — maintenance="incremental" demanded outside the incremental sub-fragment: ${x.reason}')
		}
	}
	if d := cap_guard('eval', 'live materialize (quoted planar execution)') {
		return d
	}
	src := code.planar_query_source(args[1]) or { '' }
	qhash := cx.cx_text_hash(src) or { '' }
	mut reg := live_reg()
	id := reg.next_mat
	reg.next_mat++
	rec := &LiveMatRecord{
		id:          id
		q:           q
		store:       args[0]
		name:        name
		qhash:       qhash
		maintenance: maintenance
	}
	// re-attach or create: the alias state decides.
	cur0, _, expect, cvalid := live_read_checkpoint(ms, name, qhash, q.formals)
	mut anchor := map[string]i64{}
	if cvalid {
		// RE-ATTACH: the name already holds THIS fold's checkpoint — the
		// durable cursor resumes; nothing is written.
		anchor = cur0.clone()
	} else if expect > 0 {
		// the alias exists but is NOT this fold's checkpoint — a different
		// fold (or a foreign doc) holds the name: the alias-conflict
		// refusal, never a silent replace.
		return mk_err('cx-err:CXER1114', 'E_STORE_REF_CONFLICT: materialize — alias `${name}` is held by a different value (not this fold\'s checkpoint); choose another name or remove the alias')
	} else {
		// CREATE: fold at head, put-doc-then-alias, CAS from pos 0.
		heads, herr, hok := live_sample_heads('materialize', q, map[string]i64{})
		if !hok {
			return herr
		}
		rows, xerr, xok := live_execute_head(q.comp, q.bindings, mut env)
		if !xok {
			return xerr
		}
		cdoc := live_checkpoint_doc(qhash, q.formals, heads, rows)
		hres := store_stdlib_builtin('store-put-doc', [args[0], cx.Node(cdoc)]) or {
			return mk_err('cx-err:CXER0001', 'materialize — checkpoint put-doc failed')
		}
		if is_err_value(hres) {
			return hres
		}
		mut chash := ''
		if hres is cx.ScalarNode {
			v := hres.value
			if v is string {
				chash = v
			}
		}
		mut m := unsafe { ms }
		if cerr := live_alias_advance_cas(mut m, name, chash, expect) {
			return cerr
		}
		anchor = heads.clone()
	}
	reg.mats[id] = rec
	live_mat_register(rec, anchor)
	return cx.Element{
		name:  'materialization'
		attrs: [
			cx.Attribute{
				name:  'id'
				value: cx.ScalarValue('live-mat-${id}')
			},
			cx.Attribute{
				name:  'name'
				value: cx.ScalarValue(name)
			},
			cx.Attribute{
				name:  'q'
				value: cx.ScalarValue(qhash)
			},
		]
		items: [live_headset_node(q.formals, anchor)]
	}
}

fn live_advance(args []cx.Node, mut env MatchEnv) cx.Node {
	if args.len < 1 {
		return mk_err('cx-err:CXER0108', 'E_ARG: advance expects (materialization-ref, opts?)')
	}
	mut rec := live_mat_of(args[0]) or {
		return mk_err('cx-err:CXER0108', 'E_ARG: [\$live:advance] — unknown or stale materialization ref')
	}
	ms, serr, sok := store_get_open(rec.store)
	if !sok {
		return serr
	}
	if d := cap_guard('eval', 'live advance (quoted planar execution)') {
		return d
	}
	cur, _, expect, cvalid := live_read_checkpoint(ms, rec.name, rec.qhash, rec.q.formals)
	heads, herr, hok := live_sample_heads('advance', rec.q, cur)
	if !hok {
		return herr
	}
	if cvalid {
		mut quiescent := true
		for k, hv in heads {
			if (cur[k] or { i64(0) }) != hv {
				quiescent = false
			}
		}
		if quiescent {
			return live_advanced_node(rec.q.formals, heads, 0, false)
		}
	}
	rows, applied, recomputed, ferr, fok := live_fold_window(rec, cur, cvalid, heads, mut env)
	if !fok {
		return ferr
	}
	if recomputed && rec.maintenance == 'incremental' {
		return mk_err(live_err_not_maintainable, 'E_LIVE_NOT_MAINTAINABLE: advance — this window forces the loud recompute and the materialization declared maintenance="incremental" (callers that must not pay recompute)')
	}
	cdoc := live_checkpoint_doc(rec.qhash, rec.q.formals, heads, rows)
	hres := store_stdlib_builtin('store-put-doc', [rec.store, cx.Node(cdoc)]) or {
		return mk_err('cx-err:CXER0001', 'advance — checkpoint put-doc failed')
	}
	if is_err_value(hres) {
		return hres
	}
	mut chash := ''
	if hres is cx.ScalarNode {
		v := hres.value
		if v is string {
			chash = v
		}
	}
	mut m := unsafe { ms }
	if cerr := live_alias_advance_cas(mut m, rec.name, chash, expect) {
		return cerr
	}
	live_mat_register(rec, heads)
	return live_advanced_node(rec.q.formals, heads, applied, recomputed)
}

fn live_read(args []cx.Node, mut env MatchEnv) cx.Node {
	if args.len < 1 {
		return mk_err('cx-err:CXER0108', 'E_ARG: read expects (materialization-ref)')
	}
	mut rec := live_mat_of(args[0]) or {
		return mk_err('cx-err:CXER0108', 'E_ARG: [\$live:read] — unknown or stale materialization ref')
	}
	ms, serr, sok := store_get_open(rec.store)
	if !sok {
		return serr
	}
	cur, rows, expect, cvalid := live_read_checkpoint(ms, rec.name, rec.qhash, rec.q.formals)
	if cvalid {
		return live_snapshot_node(rec.q.formals, cur, rows)
	}
	// derived-state posture: the checkpoint is missing/unreadable — FULL
	// REPLAY at head, re-checkpoint, correctness untouched. This path
	// executes the comprehension, so it (alone) sits behind `eval`.
	if d := cap_guard('eval', 'live read (checkpoint replay — quoted planar execution)') {
		return d
	}
	heads, herr, hok := live_sample_heads('read', rec.q, map[string]i64{})
	if !hok {
		return herr
	}
	fresh, xerr, xok := live_execute_head(rec.q.comp, rec.q.bindings, mut env)
	if !xok {
		return xerr
	}
	cdoc := live_checkpoint_doc(rec.qhash, rec.q.formals, heads, fresh)
	hres := store_stdlib_builtin('store-put-doc', [rec.store, cx.Node(cdoc)]) or {
		return mk_err('cx-err:CXER0001', 'read — checkpoint put-doc failed')
	}
	if is_err_value(hres) {
		return hres
	}
	mut chash := ''
	if hres is cx.ScalarNode {
		v := hres.value
		if v is string {
			chash = v
		}
	}
	mut m := unsafe { ms }
	if cerr := live_alias_advance_cas(mut m, rec.name, chash, expect) {
		return cerr
	}
	live_mat_register(rec, heads)
	return live_snapshot_node(rec.q.formals, heads, fresh)
}

// live_fold_window computes the fold's relation for one advance window and
// classifies it: (rows, applied, recomputed, err, ok). applied counts the
// source events in the window; recomputed reports the LOUD boundary —
// false on the maintained paths (the exact empty-cursor seed, a clean ∂
// window, or a γ-retract ABSORBED because the fold uses only the
// invertible aggregates: sum/count/avg — the L130 per-aggregate table).
fn live_fold_window(rec &LiveMatRecord, cur map[string]i64, cvalid bool, heads map[string]i64, mut env MatchEnv) ([]cx.Node, int, bool, cx.Node, bool) {
	q := rec.q
	comp := q.comp
	mut applied := 0
	for k, hv in heads {
		applied += int(hv - (cur[k] or { i64(0) }))
	}
	// a lost checkpoint is FULL REPLAY (recompute at head), and any
	// non-maintainable shape recomputes loud.
	mut recompute := !cvalid
	if x := code.planar_incremental_membership(cx.ProgramNode(comp)) {
		_ = x
		recompute = true
	}
	gens := live_generator_sources(comp)
	if !recompute {
		for s in q.slices {
			mut found := false
			for g in gens {
				if g.kind == s.kind && g.formal == s.handle && g.path == s.path {
					found = true
					break
				}
			}
			if !found {
				recompute = true
				break
			}
		}
	}
	mut empty_cursor := true
	for _, v in cur {
		if v > 0 {
			empty_cursor = false
		}
	}
	if recompute || empty_cursor {
		rows, xerr, xok := live_execute_head(comp, q.bindings, mut env)
		if !xok {
			return []cx.Node{}, 0, false, xerr, false
		}
		// the empty-cursor seed is EXACT (quartet leg 1) — only the forced
		// paths report the loud recompute (and pay applied=0: no ∂ applied).
		if recompute {
			return rows, 0, true, store_null(), true
		}
		return rows, applied, false, store_null(), true
	}
	w, werr, wok := live_apply_window('advance', q, comp, gens, cur, heads)
	if !wok {
		return []cx.Node{}, 0, false, werr, false
	}
	if w.recompute_reason == '' {
		return w.result, applied, false, store_null(), true
	}
	// the per-aggregate boundary (L130): a γ-retract is ABSORBED when the
	// yield uses only invertible aggregates; anything else is the loud
	// group recompute.
	if w.recompute_reason == code.planar_delta_reason_gamma_retract
		&& live_yield_invertible(comp) {
		return w.result, applied, false, store_null(), true
	}
	return w.result, applied, true, store_null(), true
}

// live_yield_invertible — the L130 per-aggregate analysis: true iff every
// use of the γ member set ($group) sits inside an INVERTIBLE aggregate
// (sum/avg; $count is a scalar binding and always invertible) and no
// max/min/distinct call appears. Invertible folds absorb a γ-retract;
// everything else forces the loud group recompute.
fn live_yield_invertible(comp cx.ProgramForComp) bool {
	return live_expr_invertible(comp.yield, false)
}

fn live_expr_invertible(n cx.ProgramNode, in_inv_call bool) bool {
	match n {
		cx.ProgramCall {
			if n.name in ['max', 'min', 'distinct'] {
				return false
			}
			inside := in_inv_call || n.name in ['sum', 'avg']
			for a in n.args {
				if !live_expr_invertible(a, inside) {
					return false
				}
			}
			return true
		}
		cx.ProgramBinding {
			return n.name != 'group' || in_inv_call
		}
		cx.ProgramLiteral {
			for it in n.items {
				if !live_expr_invertible(it, in_inv_call) {
					return false
				}
			}
			// element-construction attributes carry the aggregate calls
			// (`total=[$sum $group/amt]` — attrs, not the retired slots).
			for a in n.attrs {
				if !live_expr_invertible(a.value, in_inv_call) {
					return false
				}
			}
			for s in n.slots {
				if !live_expr_invertible(s.value, in_inv_call) {
					return false
				}
			}
			return true
		}
		else {
			return true
		}
	}
}

// ── the v1 floor adapters (live.md §8; the L135 floor) ───────────────────────
//
// The pack ships the ruled adapter floor as pack surface — the same thin
// .cx-over-prim architecture as every stdlib verb; "adapters are ordinary
// edge clients written in cx" (fabric §14) is the posture for REAL
// foreign-protocol adapters (the §14 planned list — separate deployables).
//
//   [$live:adapt-poll URL TENANT STREAM SRC Q WRITER] → [adapter …]
//     — the :snapshot-diff floor: the adapter OWNS its journal (opened
//     with the handle-floor declaration) and, on every ingest tick,
//     pulls the source's exact ∂ via changes-since over the CALLER's
//     single-store-source comprehension. Each non-empty tick appends ONE
//     `[ingested from= at= FRAME…]` entry — the batch is atomic, and the
//     entry CARRIES the resume token (the NATS-bridge shape: the cursor
//     is recoverable from the CX side after a crash, from the stream's
//     own head), so re-ingest after a crash is impossible by
//     construction (the must-not-exist posture, self-anchoring form).
//   [$live:adapt-watch URL TENANT STREAM DIR WRITER] → [adapter …]
//     — the :coalesced-rescan floor (the io.md rung verbatim): fs watch
//     events between ticks; OVERFLOW — or the first tick — means RESCAN.
//     Files lower through the three-way ladder; each non-empty tick
//     appends one `[ingested rescan= [file path= LOWERED]…]` entry.
//     Re-delivery under rescan is the DECLARED semantic of the rung.
//   [$live:ingest ADAPTER] → [ingested …] — the explicit tick both
//     share (`sched` cadence is the deployment driver — the advance
//     precedent).

fn live_slot_of(a cx.Element, slot string) ?cx.Node {
	for it in a.items {
		if it is cx.Element {
			if it.name == slot && it.items.len > 0 {
				return it.items[0]
			}
		}
	}
	return none
}

fn live_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return none
}

// live_adapter_jopts builds the declared journal-open opts map.
fn live_adapter_jopts(stream string, rung string, writer string) cx.Node {
	decl := cx.Element{
		name:  'adapter-stream'
		attrs: [
			cx.Attribute{
				name:  'stream'
				value: cx.ScalarValue(stream)
			},
			cx.Attribute{
				name:  'rung'
				value: cx.ScalarValue(rung)
			},
			cx.Attribute{
				name:  'writer'
				value: cx.ScalarValue(writer)
			},
		]
	}
	return cx.Element{
		name:  'map'
		items: [
			cx.Node(cx.Element{
				name:  'declare'
				items: [cx.Node(decl)]
			}),
		]
	}
}

fn live_mk_map1(key string, v cx.Node) cx.Node {
	return cx.Element{
		name:  '__cx_map__'
		items: [
			cx.Node(cx.Element{
				name:  key
				items: [v]
			}),
		]
	}
}

fn live_adapt_poll(args []cx.Node, mut env MatchEnv) cx.Node {
	if args.len < 6 {
		return mk_err('cx-err:CXER0108', 'E_ARG: adapt-poll expects (journal-url, tenant, stream, src-store, quoted-comprehension, writer)')
	}
	url := live_arg_str(args[0]) or {
		return mk_err('cx-err:CXER0108', 'E_ARG: adapt-poll — journal-url must be a string')
	}
	tenant := live_arg_str(args[1]) or {
		return mk_err('cx-err:CXER0108', 'E_ARG: adapt-poll — tenant must be a string')
	}
	stream := live_arg_str(args[2]) or {
		return mk_err('cx-err:CXER0108', 'E_ARG: adapt-poll — stream must be a string')
	}
	writer := live_arg_str(args[5]) or {
		return mk_err('cx-err:CXER0108', 'E_ARG: adapt-poll — writer must be a string')
	}
	// the comprehension must read exactly ONE store source — the adapter
	// binds it to the given store, whatever the caller named the formal.
	src0 := code.planar_query_source(args[4]) or {
		return mk_err(live_err_not_planar, 'E_LIVE_NOT_PLANAR: adapt-poll — the comprehension must be quoted ([?quote [?for …]])')
	}
	prog := cx.parse_program(src0) or {
		return mk_err(live_err_not_planar, 'E_LIVE_NOT_PLANAR: adapt-poll — malformed comprehension source: ${err.msg()}')
	}
	slices := code.planar_extract_slices(prog) or {
		return mk_err(live_err_not_planar, 'E_LIVE_NOT_PLANAR: adapt-poll — ${err.msg()}')
	}
	mut formal := ''
	for s in slices {
		if s.kind != 'store' {
			return mk_err(live_err_policy_invalid, 'E_LIVE_POLICY_INVALID: adapt-poll — the poll floor reads ONE store source (a journal source is already a CX stream; it needs no adapter)')
		}
		if formal != '' && formal != s.handle {
			return mk_err(live_err_policy_invalid, 'E_LIVE_POLICY_INVALID: adapt-poll — the poll floor reads ONE store source (formals `${formal}` and `${s.handle}` found)')
		}
		formal = s.handle
	}
	if formal == '' {
		return mk_err(live_err_policy_invalid, 'E_LIVE_POLICY_INVALID: adapt-poll — the comprehension names no store source')
	}
	// fail-fast validation of the full pipeline (bind kind, membership,
	// authz-free) at creation.
	bindmap := live_mk_map1(formal, args[3])
	_, perr, pok := live_prepare('adapt-poll', args[4], bindmap, none)
	if !pok {
		return perr
	}
	jr := journal_stdlib_builtin('journal-open', [cx.Node(jrn_str(url)), cx.Node(jrn_str(tenant)),
		live_adapter_jopts(stream, ':snapshot-diff', writer)]) or {
		return mk_err('cx-err:CXER0001', 'adapt-poll — journal open failed')
	}
	if is_err_value(jr) {
		return jr
	}
	return cx.Element{
		name:  'adapter'
		attrs: [
			cx.Attribute{
				name:  'kind'
				value: cx.ScalarValue('poll')
			},
			cx.Attribute{
				name:  'rung'
				value: cx.ScalarValue(':snapshot-diff')
			},
			cx.Attribute{
				name:  'stream'
				value: cx.ScalarValue(stream)
			},
			cx.Attribute{
				name:  'writer'
				value: cx.ScalarValue(writer)
			},
			cx.Attribute{
				name:  'formal'
				value: cx.ScalarValue(formal)
			},
		]
		items: [
			cx.Node(cx.Element{ name: 'jslot', items: [jr] }),
			cx.Node(cx.Element{ name: 'srcslot', items: [args[3]] }),
			cx.Node(cx.Element{ name: 'qslot', items: [args[4]] }),
		]
	}
}

fn live_adapt_watch(args []cx.Node) cx.Node {
	if args.len < 5 {
		return mk_err('cx-err:CXER0108', 'E_ARG: adapt-watch expects (journal-url, tenant, stream, dir, writer)')
	}
	stream := live_arg_str(args[2]) or {
		return mk_err('cx-err:CXER0108', 'E_ARG: adapt-watch — stream must be a string')
	}
	dir := live_arg_str(args[3]) or {
		return mk_err('cx-err:CXER0108', 'E_ARG: adapt-watch — dir must be a string')
	}
	writer := live_arg_str(args[4]) or {
		return mk_err('cx-err:CXER0108', 'E_ARG: adapt-watch — writer must be a string')
	}
	// adapter setup: the watched directory must exist (mkdir-p posture —
	// a write effect, gated as one).
	if d := cap_guard('write', 'adapt-watch (create the watched directory)') {
		return d
	}
	os.mkdir_all(dir) or {
		return mk_err('cx-err:CXER0001', 'adapt-watch — cannot create watched dir ${dir}: ${err.msg()}')
	}
	if d := cap_guard('read', 'io-watch') {
		return d
	}
	w := iowatch_dispatch('io-watch', [cx.Node(jrn_str(dir))]) or {
		return mk_err('cx-err:CXER0001', 'adapt-watch — watch open failed')
	}
	if is_err_value(w) {
		return w
	}
	jr := journal_stdlib_builtin('journal-open', [args[0], args[1],
		live_adapter_jopts(stream, ':coalesced-rescan', writer)]) or {
		return mk_err('cx-err:CXER0001', 'adapt-watch — journal open failed')
	}
	if is_err_value(jr) {
		return jr
	}
	return cx.Element{
		name:  'adapter'
		attrs: [
			cx.Attribute{
				name:  'kind'
				value: cx.ScalarValue('watch')
			},
			cx.Attribute{
				name:  'rung'
				value: cx.ScalarValue(':coalesced-rescan')
			},
			cx.Attribute{
				name:  'stream'
				value: cx.ScalarValue(stream)
			},
			cx.Attribute{
				name:  'writer'
				value: cx.ScalarValue(writer)
			},
			cx.Attribute{
				name:  'dir'
				value: cx.ScalarValue(dir)
			},
		]
		items: [
			cx.Node(cx.Element{ name: 'jslot', items: [jr] }),
			cx.Node(cx.Element{ name: 'wslot', items: [w] }),
		]
	}
}

// live_ingest — the explicit tick. Poll: one changes-since window,
// appended atomically as one [ingested from= at= FRAME…] entry (the
// self-anchoring resume token). Watch: drain fs events; overflow or the
// first tick RESCANS; files lower through the ladder; one
// [ingested rescan= [file …]…] entry per non-empty tick.
fn live_ingest(args []cx.Node, mut env MatchEnv) cx.Node {
	if args.len < 1 {
		return mk_err('cx-err:CXER0108', 'E_ARG: ingest expects (adapter)')
	}
	if args[0] !is cx.Element {
		return mk_err('cx-err:CXER0108', 'E_ARG: ingest expects an [adapter] handle')
	}
	a := args[0] as cx.Element
	if a.name != 'adapter' {
		return mk_err('cx-err:CXER0108', 'E_ARG: ingest expects an [adapter] handle (got [${a.name}])')
	}
	j := live_slot_of(a, 'jslot') or {
		return mk_err('cx-err:CXER0108', 'E_ARG: ingest — adapter handle carries no journal')
	}
	stream := a.attr('stream')
	writer := a.attr('writer')
	// cursor recovery from the stream's own head (crash-safe: the cursor
	// rides the last committed entry).
	mut from := i64(0)
	if hd := journal_stdlib_builtin('journal-head', [j, cx.Node(jrn_str(stream))]) {
		if hd is cx.Element {
			if hd.name == 'entry' {
				for ch in hd.items {
					if ch is cx.Element {
						if ch.name == 'event' && ch.items.len > 0 {
							ev := ch.items[0]
							if ev is cx.Element {
								if ev.name == 'ingested' {
									from = ev.attr('at').i64()
								}
							}
						}
					}
				}
			}
		}
	}
	if a.attr('kind') == 'poll' {
		return live_ingest_poll(a, j, stream, writer, from, mut env)
	}
	return live_ingest_watch(a, j, stream, writer, from)
}

fn live_ingest_poll(a cx.Element, j cx.Node, stream string, writer string, from i64, mut env MatchEnv) cx.Node {
	src := live_slot_of(a, 'srcslot') or {
		return mk_err('cx-err:CXER0108', 'E_ARG: ingest — poll adapter carries no source store')
	}
	q := live_slot_of(a, 'qslot') or {
		return mk_err('cx-err:CXER0108', 'E_ARG: ingest — poll adapter carries no comprehension')
	}
	formal := a.attr('formal')
	mut cur := map[string]i64{}
	cur[formal] = from
	ch := live_changes_since([q, live_mk_map1(formal, src),
		live_headset_node([formal], cur)], mut env)
	if is_err_value(ch) {
		return ch
	}
	mut frames := []cx.Node{}
	mut at := from
	if ch is cx.Element {
		for it in ch.items {
			if it is cx.Element {
				if it.name == 'head-set' {
					for s0 in it.items {
						if s0 is cx.Element {
							if s0.name == 's' {
								at = s0.attr('pos').i64()
							}
						}
					}
					continue
				}
			}
			frames << it
		}
	}
	if frames.len > 0 {
		payload := cx.Element{
			name:  'ingested'
			attrs: [
				cx.Attribute{
					name:  'from'
					value: cx.ScalarValue(from)
				},
				cx.Attribute{
					name:  'at'
					value: cx.ScalarValue(at)
				},
			]
			items: frames
		}
		attrib := cx.Element{
			name:  'map'
			items: [
				cx.Node(cx.Element{ name: 'actor', items: [cx.Node(jrn_str(writer))] }),
				cx.Node(cx.Element{ name: 'authority', items: [cx.Node(jrn_str('cx-live/adapter'))] }),
				cx.Node(cx.Element{ name: 'stream', items: [cx.Node(jrn_str(stream))] }),
			]
		}
		ar := journal_stdlib_builtin('journal-append', [j, cx.Node(payload), cx.Node(attrib)]) or {
			return mk_err('cx-err:CXER0001', 'ingest — journal append failed')
		}
		if is_err_value(ar) {
			return ar
		}
	}
	return cx.Element{
		name:  'ingested'
		attrs: [
			cx.Attribute{
				name:  'from'
				value: cx.ScalarValue(from)
			},
			cx.Attribute{
				name:  'at'
				value: cx.ScalarValue(at)
			},
			cx.Attribute{
				name:  'n'
				value: cx.ScalarValue(i64(frames.len))
			},
		]
	}
}

fn live_ingest_watch(a cx.Element, j cx.Node, stream string, writer string, from i64) cx.Node {
	dir := a.attr('dir')
	w := live_slot_of(a, 'wslot') or {
		return mk_err('cx-err:CXER0108', 'E_ARG: ingest — watch adapter carries no watch handle')
	}
	if d := cap_guard('read', 'ingest (watched-file reads)') {
		return d
	}
	// drain pending fs events; overflow — or the first tick — means RESCAN
	// (the io.md rung: "you missed some — rescan").
	mut rescan := from == 0 && live_stream_head_absent(j, stream)
	mut paths := []string{}
	for {
		ev := iowatch_ring2_builtin('io-watch-next', [w, cx.Node(jrn_int(0))]) or { break }
		if is_err_value(ev) {
			break
		}
		if ev is cx.Element {
			if ev.name == 'change' {
				op := ev.attr('op')
				if op == '' {
					break // closed/none
				}
				if op == 'overflow' {
					rescan = true
					continue
				}
				p := ev.attr('path')
				if p != '' && op != 'deleted' && p !in paths {
					paths << p
				}
				continue
			}
		}
		break
	}
	if rescan {
		paths = []string{}
		entries := os.ls(dir) or { []string{} }
		for e in entries {
			full := os.join_path(dir, e)
			if os.is_file(full) {
				paths << full
			}
		}
		paths.sort()
	}
	mut files := []cx.Node{}
	for p in paths {
		text := os.read_file(p) or { continue }
		lowered := live_lower([cx.Node(jrn_str(text))])
		files << cx.Node(cx.Element{
			name:  'file'
			attrs: [
				cx.Attribute{
					name:  'path'
					value: cx.ScalarValue(p)
				},
			]
			items: [lowered]
		})
	}
	if files.len > 0 {
		payload := cx.Element{
			name:  'ingested'
			attrs: [
				cx.Attribute{
					name:  'rescan'
					value: cx.ScalarValue(rescan)
				},
				cx.Attribute{
					name:  'at'
					value: cx.ScalarValue(from + 1)
				},
			]
			items: files
		}
		attrib := cx.Element{
			name:  'map'
			items: [
				cx.Node(cx.Element{ name: 'actor', items: [cx.Node(jrn_str(writer))] }),
				cx.Node(cx.Element{ name: 'authority', items: [cx.Node(jrn_str('cx-live/adapter'))] }),
				cx.Node(cx.Element{ name: 'stream', items: [cx.Node(jrn_str(stream))] }),
			]
		}
		ar := journal_stdlib_builtin('journal-append', [j, cx.Node(payload), cx.Node(attrib)]) or {
			return mk_err('cx-err:CXER0001', 'ingest — journal append failed')
		}
		if is_err_value(ar) {
			return ar
		}
	}
	return cx.Element{
		name:  'ingested'
		attrs: [
			cx.Attribute{
				name:  'rescan'
				value: cx.ScalarValue(rescan)
			},
			cx.Attribute{
				name:  'n'
				value: cx.ScalarValue(i64(files.len))
			},
		]
	}
}

// live_stream_head_absent — no entry exists on the stream yet.
fn live_stream_head_absent(j cx.Node, stream string) bool {
	hd := journal_stdlib_builtin('journal-head', [j, cx.Node(jrn_str(stream))]) or { return true }
	if hd is cx.Element {
		if hd.name == 'entry' {
			return false
		}
	}
	return true
}

fn live_advanced_node(formals []string, pos map[string]i64, applied int, recomputed bool) cx.Node {
	return cx.Element{
		name:  'advanced'
		attrs: [
			cx.Attribute{
				name:  'applied'
				value: cx.ScalarValue(i64(applied))
			},
			cx.Attribute{
				name:  'recomputed'
				value: cx.ScalarValue(recomputed)
			},
		]
		items: [live_headset_node(formals, pos)]
	}
}

fn live_snapshot_node(formals []string, pos map[string]i64, rows []cx.Node) cx.Node {
	mut items := []cx.Node{cap: rows.len + 1}
	items << live_headset_node(formals, pos)
	items << rows
	return cx.Element{
		name:  'snapshot'
		items: items
	}
}

// ── comprehension-side helpers ────────────────────────────────────────────────

// LiveSourceRef is one per-GENERATOR source reference in clause order: kind
// ('store'|'journal'), the FORMAL handle name, and the literal path/stream.
// Order matches planar_delta's independent-generator ordinals.
struct LiveSourceRef {
	kind   string
	formal string
	path   string
}

fn live_generator_sources(f cx.ProgramForComp) []LiveSourceRef {
	mut out := []LiveSourceRef{}
	for c in f.clauses {
		if c.kind != .generator {
			continue
		}
		src := c.source or { continue }
		if src is cx.ProgramCall {
			if src.name in ['store:source', 'journal:source'] && src.args.len >= 2 {
				handle := src.args[0]
				if handle is cx.ProgramBinding {
					if handle.path.len == 0 {
						parg := src.args[1]
						mut path := ''
						if parg is cx.ProgramLiteral && parg.kind == .string_lit {
							path = parg.str_val
						} else if parg is cx.ProgramLiteral && parg.kind == .atom_lit {
							path = ':${parg.str_val}'
						} else {
							continue // refused upstream by slice extraction
						}
						out << LiveSourceRef{
							kind:   if src.name == 'store:source' { 'store' } else { 'journal' }
							formal: handle.name
							path:   path
						}
					}
				}
			}
		}
	}
	return out
}

// live_map_entries reads a `{name: value}` map argument (the __cx_map__
// shape — the authz_opts convention) into name → node.
fn live_map_entries(n cx.Node) map[string]cx.Node {
	mut m := map[string]cx.Node{}
	if n is cx.Element && n.name == '__cx_map__' {
		for e in n.items {
			if e is cx.Element && e.items.len > 0 {
				m[e.name] = e.items[0]
			}
		}
	}
	return m
}

// live_parse_cursor validates the head-set cursor against the formal source
// set; error text surfaces under CXER5072. [head-set] (no entries) is the
// empty cursor; an absent entry reads as position 0. A `boot=` token is
// tolerated and ignored HERE: this is the in-process live-modes cursor over
// journal/store sources the same process owns — the epoch discipline lives
// on the XSP wire feed, where a positioned cursor must present the mount's
// durable epoch token (FL-1 #764: store feed lineage IS durable across
// restarts on the local durable substrates; see store_lineage.v).
fn live_parse_cursor(n cx.Node, formals []string) !map[string]i64 {
	mut m := map[string]i64{}
	if n !is cx.Element {
		return error('the cursor must be a [head-set [s source= pos=]…] element (never a scalar — L131)')
	}
	el := n as cx.Element
	if el.name != 'head-set' {
		return error('the cursor must be a [head-set …] element (got [${el.name}])')
	}
	for it in el.items {
		if it !is cx.Element {
			return error('a head-set entry must be [s source= pos=]')
		}
		e := it as cx.Element
		if e.name != 's' {
			return error('a head-set entry must be [s source= pos=] (got [${e.name}])')
		}
		mut sname := ''
		mut rname := ''
		mut pos := i64(-1)
		mut has_pos := false
		for a in e.attrs {
			if a.name == 'source' {
				v := a.value
				if v is string {
					sname = v
				}
			} else if a.name == 'ref' {
				// a store formal's named-wire-ref stream (per-ref advance
				// order — the #708 store:log wired at W5).
				v := a.value
				if v is string {
					rname = v
				}
			} else if a.name == 'pos' {
				v := a.value
				if v is i64 {
					pos = v
					has_pos = true
				}
			}
		}
		if sname == '' {
			return error('a head-set entry needs source= (the formal source name)')
		}
		if sname !in formals {
			return error('head-set entry `${sname}` names no source of this comprehension')
		}
		if !has_pos || pos < 0 {
			return error('head-set entry `${sname}` has a malformed pos= (a non-negative integer position)')
		}
		key := if rname == '' { sname } else { live_ref_key(sname, rname) }
		if key in m {
			return error('the head-set carries two entries for `${live_key_label(key)}`')
		}
		m[key] = pos
	}
	return m
}

// ── head sampling ─────────────────────────────────────────────────────────────

// live_head_pos samples a journal source's head position (the per-stream
// seq). Store sources sample through live_store_heads (per-plane, W5).
// (pos, err, ok).
fn live_head_pos(verb string, kind string, h cx.Node, stream string) (i64, cx.Node, bool) {
	_ = verb
	_ = kind
	r := journal_stdlib_builtin('journal-head', [h, jrn_str(stream)]) or {
		return 0, store_null(), true // empty journal → head 0
	}
	if is_err_value(r) {
		return 0, r, false
	}
	if r is cx.Element && r.name == 'entry' {
		for a in r.attrs {
			if a.name == 'seq' {
				v := a.value
				if v is i64 {
					return v, store_null(), true
				}
			}
		}
	}
	return 0, store_null(), true // absence — empty journal/stream
}

// ── source replay (relation at cursor + deltas to head) ───────────────────────

// LiveDelta is one source event lowered to relation rows: kind 'insert' or
// 'retract', rows in document order (one ∂ per row at the generator).
struct LiveDelta {
	kind string
	rows []cx.Node
}

struct LiveDocRef {
	hash string
	root []u8
}

// live_store_replay reconstructs a store slice's relation at the cursor
// and the source deltas in (cursor, head], from the #708 lineage
// (ms.advances) — BOTH planes: docs (per-mount doc position) and every
// named wire ref (per-ref advance order; a ref advance re-points the
// ref's content, answered as retract(old rows) + insert(new rows)).
// Content for docs that have since left the live set is reconstructed
// from the recorded object root (content-addressed objects survive
// delete until gc/prune); unreconstructable history refuses CXER5073 —
// the honest retention refusal, never a guess. `cur`/`heads` are the
// FULL position maps; this formal's streams are read out of them.
fn live_store_replay(verb string, h cx.Node, path_text string, formal string, cur map[string]i64, heads map[string]i64) ([]cx.Node, []LiveDelta, cx.Node, bool) {
	ms, errn, ok := store_get_open(h)
	if !ok {
		return []cx.Node{}, []LiveDelta{}, errn, false
	}
	dcur := cur[formal] or { i64(0) }
	dhead := heads[formal] or { i64(0) }
	// the same fail-closed CXPath plan as the scan (store_query_scan).
	attr_name, elem_path := store_query_split_attr(path_text.trim_space())
	plan, preds := store_query_plan(elem_path) or {
		return []cx.Node{}, []LiveDelta{}, mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: ${verb} — query CXPath `${path_text}` has an unsupported predicate/step (${err.msg()}) — refusing to return a lying empty ∂'), false
	}
	mut m := unsafe { ms }
	store_lock_enter(mut m)
	defer {
		store_lock_exit(mut m)
	}
	// One pass over the lineage, chronological across planes (advance
	// insertion order = first-appearance order = doc_order — the executor's
	// relation order, so the replayed relation and the recompute relation
	// agree in order). `roots` resolves docs retracts (which carry no root)
	// to the content their insert recorded; `ref_root` tracks each named
	// wire ref's CURRENT root as the walk passes its cursor.
	mut roots := map[string][]u8{}
	mut at_cursor := []LiveDocRef{}
	mut ref_slot := map[string]int{} // ref name → at_cursor index (first appearance)
	mut ref_root := map[string][]u8{} // ref name → root at the last event ≤ its cursor…
	mut ref_live := map[string]bool{} // …and whether it exists at its cursor
	mut deltas := []LiveDelta{}
	for a in ms.advances {
		if a.plane == 'docs' {
			mut root := a.root.clone()
			if root.len == 0 {
				if r := roots[a.hash] {
					root = r.clone()
				}
			} else {
				roots[a.hash] = a.root.clone()
			}
			if a.pos <= dcur {
				if a.kind == 'insert' {
					at_cursor << LiveDocRef{
						hash: a.hash
						root: root
					}
				} else {
					for i, d in at_cursor {
						if d.hash == a.hash {
							at_cursor.delete(i)
							break
						}
					}
				}
			} else if a.pos <= dhead {
				rows, rerr := live_store_doc_rows(verb, ms, a.hash, root, plan, preds,
					attr_name)
				if e := rerr {
					return []cx.Node{}, []LiveDelta{}, e, false
				}
				deltas << LiveDelta{
					kind: if a.kind == 'insert' { 'insert' } else { 'retract' }
					rows: rows
				}
			}
			continue
		}
		if a.plane != 'refs' {
			continue // alias advances never enter the doc relation
		}
		rk := live_ref_key(formal, a.name)
		rcur := cur[rk] or { i64(0) }
		rhead := heads[rk] or { i64(0) }
		if a.pos <= rcur {
			// the ref exists at the cursor; remember its slot (first
			// appearance = relation order) and its root AT the cursor.
			if a.name !in ref_slot {
				ref_slot[a.name] = at_cursor.len
				at_cursor << LiveDocRef{
					hash: '\x00ref:' + a.name
					root: a.root.clone()
				}
			} else {
				idx := ref_slot[a.name]
				at_cursor[idx] = LiveDocRef{
					hash: at_cursor[idx].hash
					root: a.root.clone()
				}
			}
			ref_live[a.name] = true
			ref_root[a.name] = a.root.clone()
		} else if a.pos <= rhead {
			// a ref advance inside the window: retract the previous
			// content's rows (if the ref existed), insert the new.
			if ref_live[a.name] or { false } {
				prev := ref_root[a.name] or { []u8{} }
				prows, perr := live_store_ref_rows(ms, prev, plan, preds, attr_name)
				if e := perr {
					return []cx.Node{}, []LiveDelta{}, e, false
				}
				deltas << LiveDelta{
					kind: 'retract'
					rows: prows
				}
			}
			nrows, nerr := live_store_ref_rows(ms, a.root, plan, preds, attr_name)
			if e := nerr {
				return []cx.Node{}, []LiveDelta{}, e, false
			}
			deltas << LiveDelta{
				kind: 'insert'
				rows: nrows
			}
			ref_live[a.name] = true
			ref_root[a.name] = a.root.clone()
		}
	}
	mut rows_at_cursor := []cx.Node{}
	for d in at_cursor {
		if d.hash.starts_with('\x00ref:') {
			rows, rerr := live_store_ref_rows(ms, d.root, plan, preds, attr_name)
			if e := rerr {
				return []cx.Node{}, []LiveDelta{}, e, false
			}
			rows_at_cursor << rows
			continue
		}
		rows, rerr := live_store_doc_rows(verb, ms, d.hash, d.root, plan, preds, attr_name)
		if e := rerr {
			return []cx.Node{}, []LiveDelta{}, e, false
		}
		rows_at_cursor << rows
	}
	return rows_at_cursor, deltas, store_null(), true
}

// live_store_ref_rows evaluates the slice path over a named wire ref's
// content AT A GIVEN ROOT (refs have no content-address binding — the
// name is the identity, the root is authoritative; no hash re-verify).
// An unreconstructable root refuses CXER5073, the honest retention
// refusal.
fn live_store_ref_rows(ms &MemStore, root []u8, plan cx.PathNode, preds []cx.PathPredicate, attr_name string) ([]cx.Node, ?cx.Node) {
	if root.len == 0 {
		return []cx.Node{}, none
	}
	getter := store_graph_getter(ms)
	mut text := ''
	if doc := cxstore.load_document_from(getter, root) {
		if doc.elements.len == 1 {
			text = code.render_canonical(doc.elements[0])
		}
	}
	if text == '' {
		payload := getter(root) or {
			return []cx.Node{}, mk_err(live_err_below_retention, 'E_LIVE_RESUME_BELOW_RETENTION: a named wire ref\'s history root was reclaimed (gc/prune) below head; resume from a newer cursor or re-seed from the empty cursor')
		}
		text = payload.bytestr()
	}
	doc := store_decode_doc(text)
	elems := store_query_walk(doc, plan)
	mut rows := []cx.Node{}
	for e in elems {
		if e is cx.Element {
			if !store_elem_matches_predicates(e, preds) {
				continue
			}
			if attr_name != '' {
				if av := store_elem_attr_node(e, attr_name) {
					rows << av
				}
			} else {
				rows << cx.Node(e)
			}
		}
	}
	return rows, none
}

// live_store_doc_rows evaluates the slice path over ONE doc's content —
// exactly the store_query_scan row semantics (walk + final-step predicates
// + attribute axis; opaque blobs are structurally invisible). Returns the
// rows, or the typed refusal when the doc's history cannot be told honestly.
fn live_store_doc_rows(verb string, ms &MemStore, hash string, root []u8, plan cx.PathNode, preds []cx.PathPredicate, attr_name string) ([]cx.Node, ?cx.Node) {
	if hash in ms.blob_kind {
		return []cx.Node{}, none
	}
	mut text := ''
	if store_doc_present(ms, hash) {
		text = store_doc_text(ms, hash) or {
			return []cx.Node{}, mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
		}
	} else {
		// the doc left the live set below head — reconstruct from the lineage
		// root. A blob's insert records NO root (F1' raw-byte identity), so
		// blob history fail-closes to the retention refusal rather than ever
		// re-parsing raw bytes as structure.
		if root.len == 0 {
			return []cx.Node{}, mk_err(live_err_below_retention, 'E_LIVE_RESUME_BELOW_RETENTION: ${verb} — history at ${hash} is not reconstructable below head; resume from a newer cursor or re-seed from the empty cursor')
		}
		getter := store_graph_getter(ms)
		if doc := cxstore.load_document_from(getter, root) {
			if doc.elements.len == 1 {
				cand := code.render_canonical(doc.elements[0])
				ch := cx.cx_text_hash(cand) or { '' }
				if ch == hash {
					text = cand
				}
			}
		}
		if text == '' {
			// degenerate 'document' model: the root IS the raw canonical object.
			payload := getter(root) or {
				return []cx.Node{}, mk_err(live_err_below_retention, 'E_LIVE_RESUME_BELOW_RETENTION: ${verb} — history at ${hash} was reclaimed (gc/prune) below head; resume from a newer cursor or re-seed from the empty cursor')
			}
			cand := payload.bytestr()
			ch := cx.cx_text_hash(cand) or { '' }
			if ch != hash {
				return []cx.Node{}, mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${verb} — lineage content at ${hash} does not re-verify against its recorded identity')
			}
			text = cand
		}
	}
	doc := store_decode_doc(text)
	elems := store_query_walk(doc, plan)
	mut rows := []cx.Node{}
	for e in elems {
		if e is cx.Element {
			if !store_elem_matches_predicates(e, preds) {
				continue
			}
			if attr_name != '' {
				if av := store_elem_attr_node(e, attr_name) {
					rows << av
				}
			} else {
				rows << cx.Node(e)
			}
		}
	}
	return rows, none
}

// live_journal_replay reconstructs a journal stream's relation at `cur`
// (entries 1..cur) and the appended entries in (cur, head] as insert deltas
// (a journal is append-only — the only source event is an append). A
// retained range shorter than the cursor is the honest CXER5073 refusal.
fn live_journal_replay(verb string, h cx.Node, stream string, cur i64, head i64) ([]cx.Node, []LiveDelta, cx.Node, bool) {
	mut at_cursor := []cx.Node{}
	if cur > 0 {
		r := journal_stdlib_builtin('journal-slice', [h, jrn_int(1), jrn_int(cur),
			jrn_str(stream)]) or { jrn_empty() }
		if is_err_value(r) {
			return []cx.Node{}, []LiveDelta{}, r, false
		}
		at_cursor = live_seq_items(r)
		if i64(at_cursor.len) != cur {
			return []cx.Node{}, []LiveDelta{}, mk_err(live_err_below_retention, 'E_LIVE_RESUME_BELOW_RETENTION: ${verb} — the journal stream retains ${at_cursor.len} of the ${cur} entries at the cursor (compaction below the cursor); resume from a newer cursor or re-seed from the empty cursor'), false
		}
	}
	mut deltas := []LiveDelta{}
	if head > cur {
		r := journal_stdlib_builtin('journal-slice', [h, jrn_int(cur + 1), jrn_int(head),
			jrn_str(stream)]) or { jrn_empty() }
		if is_err_value(r) {
			return []cx.Node{}, []LiveDelta{}, r, false
		}
		for e in live_seq_items(r) {
			deltas << LiveDelta{
				kind: 'insert'
				rows: [e]
			}
		}
	}
	return at_cursor, deltas, store_null(), true
}

// ── execution + answer shapes ─────────────────────────────────────────────────

// live_execute_head runs the rewritten comprehension through the L99
// sandboxed executor (handles-only environment, narrowed caps) and returns
// the relation rows. (rows, err, ok).
fn live_execute_head(comp cx.ProgramForComp, bindings map[string]cx.Node, mut env MatchEnv) ([]cx.Node, cx.Node, bool) {
	r := code.planar_query_execute(cx.ProgramNode(comp), bindings, mut env)
	if is_err_value(r) {
		return []cx.Node{}, r, false
	}
	return live_seq_items(r), store_null(), true
}

// live_recompute_answer is the honest strategy-free form: the [recompute
// reason=…] marker followed by the full relation at head as inserts.
fn live_recompute_answer(comp cx.ProgramForComp, bindings map[string]cx.Node, formals []string, heads map[string]i64, reason string, mut env MatchEnv) cx.Node {
	rows, xerr, xok := live_execute_head(comp, bindings, mut env)
	if !xok {
		return xerr
	}
	mut frames := []cx.Node{}
	frames << live_recompute_frame(reason)
	for i, row in rows {
		frames << live_insert_frame(i, row)
	}
	return live_changes_node(live_headset_node(formals, heads), frames)
}

fn live_seq_items(n cx.Node) []cx.Node {
	if n is cx.Element {
		if n.name == code.seq_marker_name {
			return n.items.clone()
		}
	}
	if n is cx.ScalarNode {
		return []
	}
	return [n]
}

fn live_attr_str(e cx.Element, name string) string {
	for a in e.attrs {
		if a.name == name {
			v := a.value
			if v is string {
				return v
			}
		}
	}
	return ''
}

fn live_insert_frame(pos int, row cx.Node) cx.Node {
	return cx.Element{
		name:  'insert'
		attrs: [
			cx.Attribute{
				name:  'pos'
				value: cx.ScalarValue(i64(pos))
			},
		]
		items: [row]
	}
}

fn live_recompute_frame(reason string) cx.Node {
	return cx.Element{
		name:  'recompute'
		attrs: [
			cx.Attribute{
				name:  'reason'
				value: cx.ScalarValue(reason)
			},
		]
	}
}

fn live_headset_node(formals []string, pos map[string]i64) cx.Node {
	mut items := []cx.Node{}
	for f in formals {
		items << cx.Node(cx.Element{
			name:  's'
			attrs: [
				cx.Attribute{
					name:  'source'
					value: cx.ScalarValue(f)
				},
				cx.Attribute{
					name:  'pos'
					value: cx.ScalarValue(pos[f] or { i64(0) })
				},
			]
		})
		// the formal's named-wire-ref streams (per-ref advance order),
		// sorted by name for a stable head-set spelling.
		prefix := f + '\x00'
		mut rnames := []string{}
		for k, _ in pos {
			if k.starts_with(prefix) {
				rnames << k[prefix.len..]
			}
		}
		rnames.sort()
		for rn in rnames {
			items << cx.Node(cx.Element{
				name:  's'
				attrs: [
					cx.Attribute{
						name:  'source'
						value: cx.ScalarValue(f)
					},
					cx.Attribute{
						name:  'ref'
						value: cx.ScalarValue(rn)
					},
					cx.Attribute{
						name:  'pos'
						value: cx.ScalarValue(pos[live_ref_key(f, rn)] or { i64(0) })
					},
				]
			})
		}
	}
	return cx.Element{
		name:  'head-set'
		items: items
	}
}

fn live_changes_node(headset cx.Node, frames []cx.Node) cx.Node {
	mut items := []cx.Node{cap: frames.len + 1}
	items << headset
	items << frames
	return cx.Element{
		name:  'changes'
		items: items
	}
}
