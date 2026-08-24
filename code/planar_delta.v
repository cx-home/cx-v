module code

// planar_delta.v — the L101 ∂ vocabulary + the normative delta rules
// (planar_algebra.md §2 L101; W7 of the I5 stream-2 ledger). Authored ONCE
// here and consumed downstream: stream 3's [?materialize] refuses or
// recomputes outside the incremental sub-fragment (loudly), stream 4's wire
// delta frames carry the same vocabulary.
//
// THE VOCABULARY (∂ — insert / retract / regroup):
//   INPUT (source-side): `[insert ROW]` / `[retract ROW]`, applied at one
//   INDEPENDENT generator — a source-reference generator, where deltas
//   arrive from a store/journal slice. Correlated generators (`[in $l
//   $o/line]`) and pattern-bind generators derive per frame and take no
//   direct deltas.
//   OUTPUT (result-side): a sequential edit script over the maintained
//   relation, positions in FINAL coordinates applied in ascending order —
//   `[insert pos=N ROW]`, `[retract pos=N]`, `[regroup pos=N ROW]`
//   ([regroup] replaces a γ group's output row in place). When a delta
//   falls outside the rules the answer is the honest `[recompute
//   reason=…]` marker and the state rebuilds — never a wrong ∂, never a
//   silent full scan masquerading as maintenance (the honest-reporting
//   obligation extended to ∂).
//
// THE DELTA RULES (L101, verbatim scope):
//   σ/π — stateless: a source row flows through filters/binders to its
//     result rows or to none.
//   ⋈ — opposite-side state: an insert at generator g joins the new row
//     against the CURRENT relations of every other generator; result order
//     is the nested-loop order (frames ordered lexicographically by their
//     source-index tuples — the algebra is ordered, positions are meaning).
//   γ — group state over MONOTONE deltas: per-key member frames, group
//     order = first key appearance over the frame order (L94). An insert
//     updates exactly its key's group ([regroup]) or first-appears a new
//     one ([insert]). A RETRACT reaching γ is outside the monotone rule —
//     [recompute], loud. An insert that moves an EXISTING key's first
//     appearance across another group's (possible from an inner-generator
//     append) would reorder groups — also answered [recompute], loud.
//   τ/λ — NOT incrementally maintainable: excluded at membership below
//     (recompute-only, loud).
//
// Incremental sub-fragment membership ADDITIONALLY requires ESTABLISHED
// TOTALITY of every [where] predicate (the M6 amendment in L101): guards
// are the whole-comprehension-loud channel, so under the err-totality rule
// a partial predicate makes recompute yield the whole-comprehension err
// while maintenance would yield state-then-err — two values at one cursor,
// which `maintained ≡ recompute` cannot survive.

import cx

// PlanarMaintenanceExclusion — one loud recompute-only exclusion from the
// incremental sub-fragment. The zero value is never a valid exclusion.
pub struct PlanarMaintenanceExclusion {
pub:
	reason string
}

// planar_delta_reason_gamma_retract — the γ-retract [recompute] marker's
// reason text, exported so stream 3's per-aggregate fold layer can
// classify it (sum/count/avg absorb a γ-retract; max/min/distinct report
// the loud recompute) without parsing free text it does not own.
pub const planar_delta_reason_gamma_retract = 'a retract reaching γ is outside the monotone delta rule (L101) — group state rebuilt'

// planar_incremental_membership — the incremental sub-fragment test (L101).
// Returns none when the comprehension IS maintainable under the ∂ rules;
// otherwise the exclusion, whose reason names the operator or predicate
// that forces recompute. Consumers (stream 3) surface the exclusion loudly
// and fall back to recompute — never silently.
pub fn planar_incremental_membership(n cx.ProgramNode) ?PlanarMaintenanceExclusion {
	if n is cx.Program {
		return planar_incremental_membership(n.body)
	}
	if r := planar_membership(n) {
		return PlanarMaintenanceExclusion{
			reason: 'not a planar member: ${r.reason} (membership point ${r.point})'
		}
	}
	f := n as cx.ProgramForComp
	if f.outer_form.str() != 'sequence' {
		return PlanarMaintenanceExclusion{
			reason: 'the v1 delta rules maintain the SEQUENCE relation — [?for-array] / [?for-map] output shapes are recompute-only'
		}
	}
	mut group_seen := false
	for c in f.clauses {
		match c.kind {
			.order_by {
				return PlanarMaintenanceExclusion{
					reason: 'τ ([order-by]) is not incrementally maintainable — recompute (L101)'
				}
			}
			.limit, .take, .drop {
				return PlanarMaintenanceExclusion{
					reason: 'λ ([limit]/[take]/[drop]) is not incrementally maintainable — recompute (L101)'
				}
			}
			.group_by {
				if group_seen {
					return PlanarMaintenanceExclusion{
						reason: 'chained γ barriers are recompute-only in v1 — one [group-by] carries the delta rule'
					}
				}
				group_seen = true
			}
			.filter {
				if e := c.expr {
					if !planar_established_total(e) {
						return PlanarMaintenanceExclusion{
							reason: 'a [where] predicate is not established total — under the err-totality rule maintenance and recompute would disagree at the err cursor; recompute-only (L101/M6)'
						}
					}
				}
				if group_seen {
					return PlanarMaintenanceExclusion{
						reason: 'post-γ clauses are recompute-only in v1 — the delta rule ends at the group row'
					}
				}
			}
			.generator, .binding {
				if group_seen {
					return PlanarMaintenanceExclusion{
						reason: 'post-γ clauses are recompute-only in v1 — the delta rule ends at the group row'
					}
				}
			}
			else {}
		}
	}
	return none
}

// ── the maintained state ─────────────────────────────────────────────────────

struct DeltaGen {
	clause_idx    int
	bind          string
	independent   bool // a source-reference generator — the delta entry point
	indep_ordinal int  // ordinal among independent generators; -1 otherwise
}

struct DeltaFrame {
	idx   []int // per-generator source ordinals — lexicographic = frame order
mut:
	binds map[string]cx.Node
	key   ?cx.Node // γ key value (present iff the plan groups)
}

// PlanarDeltaState — the maintained state: the source relations (the ⋈
// opposite-side state), the surviving frame set in order, the γ key order,
// and the maintained result relation.
pub struct PlanarDeltaState {
pub mut:
	comp      cx.ProgramForComp
	rels      [][]cx.Node // per-INDEPENDENT-generator current relation
	result    []cx.Node   // the maintained relation rows
mut:
	gens      []DeltaGen
	frames    []DeltaFrame
	keys      []cx.Node // γ: first-appearance key order
	has_group bool
	group_idx int // clause index of the [group-by]; frame barrier
	binders   []string
}

// planar_delta_init builds the state from a maintainable comprehension and
// the initial relations (one per independent generator, in clause order).
// A non-maintainable comprehension errors LOUDLY with the exclusion reason
// (the caller's recompute-only signal).
pub fn planar_delta_init(n cx.ProgramNode, rels [][]cx.Node) !PlanarDeltaState {
	if x := planar_incremental_membership(n) {
		return error('not incrementally maintainable: ${x.reason}')
	}
	body := if n is cx.Program { n.body } else { n }
	f := body as cx.ProgramForComp
	mut st := PlanarDeltaState{
		comp:      f
		group_idx: f.clauses.len
	}
	mut indep := 0
	for ci, c in f.clauses {
		if c.kind == .generator {
			src := c.source or { return error('generator missing source') }
			mut is_indep := false
			if src is cx.ProgramCall {
				if src.name in planar_source_ref_names {
					is_indep = true
				}
			}
			st.gens << DeltaGen{
				clause_idx:    ci
				bind:          c.bind
				independent:   is_indep
				indep_ordinal: if is_indep { indep } else { -1 }
			}
			if is_indep {
				indep++
			}
		}
		if c.kind == .group_by {
			st.has_group = true
			st.group_idx = ci
		}
	}
	if rels.len != indep {
		return error('planar_delta_init: ${indep} independent generator(s), got ${rels.len} relation(s)')
	}
	st.rels = rels.clone()
	// The γ $group binder list — generator + [= …] binder names in clause
	// order, deduped (the engine's L94 construction, replicated verbatim;
	// the battery's maintained ≡ engine-recompute equality pins agreement).
	for j := 0; j < st.group_idx; j++ {
		ck := f.clauses[j]
		if (ck.kind == .generator || ck.kind == .binding) && ck.bind != ''
			&& ck.bind !in st.binders {
			st.binders << ck.bind
		}
	}
	st.frames = []
	st.build_frames(0, map[string]cx.Node{}, []int{}, -1, -1, mut st.frames)!
	st.rebuild_result()!
	return st
}

// build_frames — the σ/π/⋈ pipeline over clauses[0..group_idx): generators
// enumerate rows (the pinned independent generator enumerates ONLY the new
// row — the ⋈ delta rule's "new row against the opposite-side state"),
// filters prune (total predicates — established at membership), binders
// extend. Frames carry their source-ordinal tuple; lexicographic order over
// those tuples IS the nested-loop frame order.
fn (mut st PlanarDeltaState) build_frames(clause_i int, binds map[string]cx.Node, idx []int, pin_gen int, pin_row int, mut out []DeltaFrame) ! {
	if clause_i >= st.group_idx {
		mut fr := DeltaFrame{
			idx:   idx.clone()
			binds: binds.clone()
		}
		if st.has_group {
			gc := st.comp.clauses[st.group_idx]
			gexpr := gc.expr or { return error('[group-by] missing key expression') }
			fr.key = st.eval_in(gexpr, binds)!
		}
		out << fr
		return
	}
	c := st.comp.clauses[clause_i]
	match c.kind {
		.generator {
			mut gen := DeltaGen{}
			for g in st.gens {
				if g.clause_idx == clause_i {
					gen = g
					break
				}
			}
			mut rows := []cx.Node{}
			if gen.independent {
				rows = st.rels[gen.indep_ordinal]
			} else {
				src := c.source or { return error('generator missing source') }
				rows = iterate(st.eval_in(src, binds)!)
			}
			for ri, row in rows {
				if gen.independent && gen.indep_ordinal == pin_gen && ri != pin_row {
					continue
				}
				mut nb := binds.clone()
				mut matched_ok := true
				if pex := c.expr {
					if pex is cx.ProgramPattern {
						if m := match_pattern(pex, row) {
							for k, v in m.bindings {
								nb[k] = v
							}
						} else {
							matched_ok = false
						}
					}
				} else if c.bind != '' {
					nb[c.bind] = row
				}
				if !matched_ok {
					continue
				}
				mut nidx := idx.clone()
				nidx << ri
				st.build_frames(clause_i + 1, nb, nidx, pin_gen, pin_row, mut out)!
			}
		}
		.filter {
			e := c.expr or { return error('[where] missing predicate') }
			v := st.eval_in(e, binds)!
			keep := node_ebv(v) or {
				return error('[where] predicate EBV failed: a guard err is whole-comprehension-loud')
			}
			if keep {
				st.build_frames(clause_i + 1, binds, idx, pin_gen, pin_row, mut out)!
			}
		}
		.binding {
			e := c.expr or { return error('[= …] missing expression') }
			v := st.eval_in(e, binds)!
			mut nb := binds.clone()
			if c.bind != '' {
				nb[c.bind] = v
			}
			st.build_frames(clause_i + 1, nb, idx, pin_gen, pin_row, mut out)!
		}
		else {
			// erased hints ([par]/[lazy]/[ordered]) — no frame effect
			st.build_frames(clause_i + 1, binds, idx, pin_gen, pin_row, mut out)!
		}
	}
}

// eval_in evaluates a pure expression in an isolated env carrying exactly
// the frame bindings (the sub-fragment is pure — §7.8 point 4 — so the
// bindings are the whole world).
fn (st PlanarDeltaState) eval_in(e cx.ProgramNode, binds map[string]cx.Node) !cx.Node {
	mut env := new_env()
	for k, v in binds {
		env.bindings[k] = v
	}
	return eval_node(e, mut env)!
}

// eval_row evaluates the yield body for one frame (the π rule).
fn (st PlanarDeltaState) eval_row(fr DeltaFrame) !cx.Node {
	return st.eval_in(st.comp.yield, fr.binds)!
}

// eval_group_row evaluates the yield body for one γ group — the L94 binding
// set: $key, $count, and $group as one [item …] element per member frame
// carrying the generator + binder values as named children in clause order
// (the engine's construction, replicated; battery-pinned against engine
// recompute).
fn (st PlanarDeltaState) eval_group_row(key cx.Node, members []DeltaFrame) !cx.Node {
	if members.len == 0 {
		return error('γ group with no members')
	}
	mut binds := members[0].binds.clone()
	binds['count'] = cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(i64(members.len))
		data_type: cx.ScalarType.int_type
	})
	binds['key'] = key
	mut gitems := []cx.Node{}
	for fr in members {
		mut children := []cx.Node{}
		for b in st.binders {
			if v := fr.binds[b] {
				children << cx.Node(cx.Element{
					name:  b
					items: [v]
				})
			}
		}
		gitems << cx.Node(cx.Element{
			name:  'item'
			items: children
		})
	}
	binds['group'] = cx.Node(cx.Element{
		name:  seq_marker_name
		items: gitems
	})
	return st.eval_in(st.comp.yield, binds)!
}

// group_members returns the member frames of `key` in frame order.
fn (st PlanarDeltaState) group_members(key cx.Node) []DeltaFrame {
	mut out := []DeltaFrame{}
	for fr in st.frames {
		if k := fr.key {
			if nodes_equal(k, key) {
				out << fr
			}
		}
	}
	return out
}

// derive_keys returns the first-appearance key order over the current frames.
fn (st PlanarDeltaState) derive_keys() []cx.Node {
	mut keys := []cx.Node{}
	for fr in st.frames {
		if k := fr.key {
			mut found := false
			for kk in keys {
				if nodes_equal(kk, k) {
					found = true
					break
				}
			}
			if !found {
				keys << k
			}
		}
	}
	return keys
}

// rebuild_result recomputes the maintained relation from the frame set (the
// recompute path — init, and the loud [recompute] fallbacks).
fn (mut st PlanarDeltaState) rebuild_result() ! {
	st.result = []
	if st.has_group {
		st.keys = st.derive_keys()
		for k in st.keys {
			st.result << st.eval_group_row(k, st.group_members(k))!
		}
	} else {
		for fr in st.frames {
			st.result << st.eval_row(fr)!
		}
	}
}

// ── the ∂ constructors (the vocabulary's element shapes) ─────────────────────

fn mk_delta(name string, pos int, row ?cx.Node) cx.Node {
	mut items := []cx.Node{}
	if r := row {
		items << r
	}
	return cx.Element{
		name:  name
		attrs: [
			cx.Attribute{
				name:  'pos'
				value: cx.ScalarValue(i64(pos))
			},
		]
		items: items
	}
}

fn mk_recompute(reason string) cx.Node {
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

fn idx_less(a []int, b []int) bool {
	mut i := 0
	for i < a.len && i < b.len {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
		i++
	}
	return a.len < b.len
}

// ── delta application ────────────────────────────────────────────────────────

// planar_delta_apply applies ONE input ∂ (`[insert ROW]` / `[retract ROW]`)
// at the independent generator `gen` (ordinal among independent generators,
// clause order) and returns the OUTPUT ∂ script: final-coordinate positions,
// applied in ascending order, reproducing the new maintained relation from
// the previous one. A delta outside the rules returns the single
// `[recompute reason=…]` marker and the state rebuilds.
pub fn planar_delta_apply(mut st PlanarDeltaState, gen int, delta cx.Node) ![]cx.Node {
	if gen < 0 || gen >= st.rels.len {
		return error('planar_delta_apply: no independent generator ${gen}')
	}
	if delta !is cx.Element {
		return error('planar_delta_apply: a ∂ is [insert ROW] or [retract ROW]')
	}
	d := delta as cx.Element
	if d.items.len != 1 {
		return error('planar_delta_apply: a ∂ carries exactly one ROW')
	}
	row := d.items[0]
	match d.name {
		'insert' {
			return st.apply_insert(gen, row)
		}
		'retract' {
			return st.apply_retract(gen, row)
		}
		else {
			return error('planar_delta_apply: unknown ∂ kind `${d.name}` (insert/retract)')
		}
	}
}

fn (mut st PlanarDeltaState) apply_insert(gen int, row cx.Node) ![]cx.Node {
	st.rels[gen] << row
	pin_row := st.rels[gen].len - 1
	// The ⋈ rule: exactly the combinations that include the new row,
	// evaluated against the opposite-side state.
	mut fresh := []DeltaFrame{}
	st.build_frames(0, map[string]cx.Node{}, []int{}, gen, pin_row, mut fresh)!
	if fresh.len == 0 {
		return [] // σ pruned every new frame — an empty ∂ script
	}
	// Merge by frame order (lexicographic source-ordinal tuples).
	mut merged := []DeltaFrame{cap: st.frames.len + fresh.len}
	mut fi := 0
	mut positions := []int{} // final frame positions of the fresh frames
	for fr in st.frames {
		for fi < fresh.len && idx_less(fresh[fi].idx, fr.idx) {
			positions << merged.len
			merged << fresh[fi]
			fi++
		}
		merged << fr
	}
	for fi < fresh.len {
		positions << merged.len
		merged << fresh[fi]
		fi++
	}
	st.frames = merged
	if !st.has_group {
		// σ/π/⋈: one [insert] per surviving new frame, final coordinates,
		// ascending.
		mut script := []cx.Node{}
		mut new_result := []cx.Node{cap: st.result.len + fresh.len}
		mut oi := 0
		mut pi := 0
		for p := 0; p < merged.len; p++ {
			if pi < positions.len && positions[pi] == p {
				r := st.eval_row(merged[p])!
				script << mk_delta('insert', p, r)
				new_result << r
				pi++
			} else {
				new_result << st.result[oi]
				oi++
			}
		}
		st.result = new_result
		return script
	}
	// γ — group state over monotone deltas. New keys must FIRST-APPEAR at
	// the end of the key order and existing keys must keep their order;
	// an insert that moves first appearances across groups reorders the
	// relation and is answered [recompute], loud.
	old_keys := st.keys
	new_keys := st.derive_keys()
	if new_keys.len < old_keys.len {
		return error('γ key set shrank on insert — impossible')
	}
	mut order_kept := true
	for i, ok in old_keys {
		if !nodes_equal(new_keys[i], ok) {
			order_kept = false
			break
		}
	}
	if !order_kept {
		st.keys = new_keys
		st.rebuild_result()!
		return [
			mk_recompute('a γ insert moved a key first-appearance across another group — group order rebuilt (outside the monotone in-place rule)'),
		]
	}
	// Affected keys = the fresh frames' keys.
	mut affected := []cx.Node{}
	for fr in fresh {
		if k := fr.key {
			mut seen := false
			for a in affected {
				if nodes_equal(a, k) {
					seen = true
					break
				}
			}
			if !seen {
				affected << k
			}
		}
	}
	mut script := []cx.Node{}
	mut new_result := st.result.clone()
	// Existing groups first ([regroup] at their stable ordinals) …
	for a in affected {
		mut ord := -1
		for i, ok in old_keys {
			if nodes_equal(ok, a) {
				ord = i
				break
			}
		}
		if ord >= 0 {
			r := st.eval_group_row(a, st.group_members(a))!
			script << mk_delta('regroup', ord, r)
			new_result[ord] = r
		}
	}
	// … then new groups, first-appearing at the end in new-key order.
	for i := old_keys.len; i < new_keys.len; i++ {
		r := st.eval_group_row(new_keys[i], st.group_members(new_keys[i]))!
		script << mk_delta('insert', i, r)
		new_result << r
	}
	st.keys = new_keys
	st.result = new_result
	// Ascending final coordinates (regroups reference stable ordinals,
	// inserts land at the tail — sort keeps the script's application order
	// contract).
	script.sort_with_compare(fn (a &cx.Node, b &cx.Node) int {
		ap := delta_pos(*a)
		bp := delta_pos(*b)
		if ap != bp {
			return if ap < bp { -1 } else { 1 }
		}
		return 0
	})
	return script
}

fn (mut st PlanarDeltaState) apply_retract(gen int, row cx.Node) ![]cx.Node {
	mut ridx := -1
	for i, r in st.rels[gen] {
		if nodes_equal(r, row) {
			ridx = i
			break
		}
	}
	if ridx < 0 {
		return error('planar_delta_apply: [retract] row not present in generator ${gen}')
	}
	st.rels[gen] = arr_without(st.rels[gen], ridx)
	// The generator's ordinal position inside the frame idx tuple.
	mut axis := -1
	mut gcount := 0
	for g in st.gens {
		if g.independent && g.indep_ordinal == gen {
			axis = gcount
		}
		gcount++
	}
	if st.has_group {
		// Outside the monotone rule (L101 verbatim) — rebuild, loudly.
		st.frames = []
		st.build_frames(0, map[string]cx.Node{}, []int{}, -1, -1, mut st.frames)!
		st.rebuild_result()!
		return [
			mk_recompute(planar_delta_reason_gamma_retract),
		]
	}
	// σ/π/⋈: dying frames = those whose tuple selects the retracted row.
	mut script := []cx.Node{}
	mut kept := []DeltaFrame{cap: st.frames.len}
	mut new_result := []cx.Node{cap: st.result.len}
	mut removed := 0
	for p, fr in st.frames {
		if axis < fr.idx.len && fr.idx[axis] == ridx {
			// apply-time coordinates: each retract sees the earlier ones
			// already applied.
			script << mk_delta('retract', p - removed, none)
			removed++
			continue
		}
		mut nf := fr
		if axis < fr.idx.len && fr.idx[axis] > ridx {
			mut nidx := fr.idx.clone()
			nidx[axis] = nidx[axis] - 1
			nf = DeltaFrame{
				idx:   nidx
				binds: fr.binds
				key:   fr.key
			}
		}
		kept << nf
		new_result << st.result[p]
	}
	st.frames = kept
	st.result = new_result
	return script
}

fn delta_pos(n cx.Node) int {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'pos' {
				v := a.value
				if v is i64 {
					return int(v)
				}
			}
		}
	}
	return -1
}

fn arr_without(a []cx.Node, i int) []cx.Node {
	mut out := []cx.Node{cap: a.len - 1}
	for j, v in a {
		if j != i {
			out << v
		}
	}
	return out
}
