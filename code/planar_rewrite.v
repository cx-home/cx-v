module code

// planar_rewrite.v — the L96 execution-equivalence set with the err-totality
// rule (spec/03-approved/core/planar_algebra.md §2 L96; W5 of the I5 stream-2
// ledger). These are EXECUTOR rewrites: they never move the plan address
// (code.md §7.9 step 1), and every applied rewrite is REPORTABLE (the
// honest-reporting obligation, runtime_representation.md §7 — the
// columnar_pushdown status-flag precedent).
//
// The normative set: σ/σ commutation; σ-pushdown below τ; NEVER across λ
// (order-fixing barriers); π pruning; join reordering/placement over pure
// predicates.
//
// THE ERR RULE (L96, normative rationale): an err-valued predicate
// short-circuits the whole comprehension (§7.2's normative guard rule),
// and err-raising order is NOT declared unobservable — fail-loud fidelity
// outranks optimizer freedom. A rewrite is therefore admissible only when
// it can neither CREATE, DESTROY, nor REORDER an err observation.
//
// The engine's err-observability map (§7.2 verbatim + live ground truth,
// probed at W5): [where] guards and generator SOURCES surface
// whole-comprehension errs; [order-by]/[group-by] KEYS and [= …] BINDER
// values carry errs INERTLY (per-frame values under §9.2 operand
// propagation — observable only where read). The gates below are
// deliberately CONSERVATIVE — some also guard channels that are inert
// under shipped semantics (τ keys, binder exprs); a conservative decline
// is always sound, and the analyzer is the stream-16 seam:
//
//   - moving σ past τ changes σ's evaluation order (sorted vs source) —
//     the predicate must be established total; the τ key is ALSO gated
//     (conservative: key errs are inert today, the gate survives any
//     future loudening);
//   - commuting σ/σ reorders the two predicates' err observations — both
//     must be total;
//   - moving σ past a [= …] extension or a generator drops frames before
//     the crossed clause evaluates — generator sources surface comp-errs
//     (gate REQUIRED); binder exprs are gated conservatively;
//   - pruning an unread, γ-unobservable [= …] binder is sound today
//     (binder errs are inert and the binder is unread) — still gated
//     conservatively on totality;
//   - generator REORDERING changes the Cartesian result order (the algebra
//     is ordered), so v1 admits none — candidates are declined loudly;
//   - σ never crosses λ: within one comprehension λ is position-independent
//     (the §7.9 OFFSET/LIMIT reading — crossing a λ clause in the clause
//     list is a semantic no-op, not a rewrite), so the REAL λ barrier is
//     the nested-comprehension boundary: σ over a generator whose source
//     is a nested comprehension carrying λ is DECLINED (pushing inside
//     would filter before the truncation — a different relation).
//
// ESTABLISHED TOTALITY (the stream-16 seam): a predicate/key/expression is
// established total when this module can PROVE it cannot produce an err on
// any input; absent a proof it is treated as partial and the rewrite is
// declined with the reason named. v1 is deliberately conservative —
// structural equality, EBV coercion, binding-path navigation, and the
// whitelisted total builtins are proven; STRICT ordered comparison and
// arithmetic are partial without shape inference (stream 16 strengthens
// this analyzer; its inference plugs in here).
//
// Entry is membership-gated like every planar consumer (typed CXER0120).

import cx

// PlanarRewriteEntry — one applied rewrite (kind from the closed vocabulary
// below + a human-readable detail naming the clause).
pub struct PlanarRewriteEntry {
pub:
	kind   string
	detail string
}

// PlanarRewriteDecline — one candidate the err rule (or an order barrier)
// refused, with the reason named. Declines are part of the report: "no
// silent full-scan masquerading as pushdown" applies to rewrites too.
pub struct PlanarRewriteDecline {
pub:
	kind   string
	reason string
}

pub struct PlanarRewriteReport {
pub mut:
	applied  []PlanarRewriteEntry
	declined []PlanarRewriteDecline
}

// planar_rewrite applies the admissible L96 rewrites to a planar MEMBER,
// returning the rewritten comprehension and the full report. A non-member
// refuses with the typed CXER0120 message (planar consumers gate entry).
pub fn planar_rewrite(n cx.ProgramNode) !(cx.ProgramForComp, PlanarRewriteReport) {
	if r := planar_membership(n) {
		return error('comprehension is not planar: ${r.reason} (membership point ${r.point}, code.md §7.8) (${planar_err_code})')
	}
	comp := planar_rewrite_unwrap(n) or {
		return error('not a comprehension (${planar_err_code})')
	}
	mut report := PlanarRewriteReport{}
	out := planar_rewrite_comp(comp, mut report)
	return out, report
}

fn planar_rewrite_unwrap(n cx.ProgramNode) ?cx.ProgramForComp {
	if n is cx.ProgramForComp {
		return n
	}
	if n is cx.Program {
		return planar_rewrite_unwrap(n.body)
	}
	return none
}

// planar_rewrite_report_node renders a report as a CX element for status /
// introspection surfaces (the W6 store:query consumer).
pub fn planar_rewrite_report_node(r PlanarRewriteReport) cx.Node {
	mut items := []cx.Node{}
	for a in r.applied {
		items << cx.Node(cx.Element{
			name:  'applied'
			attrs: [
				cx.Attribute{
					name:  'kind'
					value: cx.ScalarValue(a.kind)
				},
				cx.Attribute{
					name:  'detail'
					value: cx.ScalarValue(a.detail)
				},
			]
		})
	}
	for d in r.declined {
		items << cx.Node(cx.Element{
			name:  'declined'
			attrs: [
				cx.Attribute{
					name:  'kind'
					value: cx.ScalarValue(d.kind)
				},
				cx.Attribute{
					name:  'reason'
					value: cx.ScalarValue(d.reason)
				},
			]
		})
	}
	return cx.Element{
		name:  'rewrites'
		items: items
	}
}

// ── the rewrite pass ──────────────────────────────────────────────────────────

fn planar_rewrite_comp(f cx.ProgramForComp, mut report PlanarRewriteReport) cx.ProgramForComp {
	// Recurse into nested planar comprehensions in generator-source
	// position first (each is its own relation).
	mut clauses := []cx.ProgramForClause{cap: f.clauses.len}
	for c in f.clauses {
		if c.kind == .generator {
			if src := c.source {
				if src is cx.ProgramForComp {
					rewritten := planar_rewrite_comp(src, mut report)
					clauses << cx.ProgramForClause{
						...c
						source: cx.ProgramNode(rewritten)
					}
					continue
				}
			}
		}
		clauses << c
	}
	clauses = planar_prune_extends(clauses, f, mut report)
	clauses = planar_place_filters(clauses, mut report)
	return cx.ProgramForComp{
		...f
		clauses: clauses
	}
}

// planar_place_filters moves each σ to its earliest admissible position
// (σ-pushdown below τ, σ/σ commutation, σ-placement across independent
// generators and extensions), gated clause-by-clause by the err rule.
fn planar_place_filters(clauses_in []cx.ProgramForClause, mut report PlanarRewriteReport) []cx.ProgramForClause {
	mut clauses := clauses_in.clone()
	mut i := 0
	for i < clauses.len {
		c := clauses[i]
		if c.kind != .filter {
			i++
			continue
		}
		pred := c.expr or {
			i++
			continue
		}
		mut free := map[string]bool{}
		planar_free_bindings(pred, map[string]bool{}, mut free)
		pred_total := planar_established_total(pred)
		// Scan left for the earliest admissible slot.
		mut target := i
		mut crossings := []PlanarRewriteEntry{}
		for j := i - 1; j >= 0; j-- {
			cj := clauses[j]
			match cj.kind {
				.par, .lazy, .ordered {
					// erased hints — crossing is invisible, not a rewrite.
					target = j
					continue
				}
				.limit, .take, .drop {
					// λ is position-independent within the clause list (the
					// §7.9 OFFSET/LIMIT reading) — crossing the CLAUSE is a
					// semantic no-op, not σ-across-λ. Not reported.
					target = j
					continue
				}
				.group_by {
					// γ barrier: a σ after [group-by] filters GROUP frames.
					break
				}
				.generator {
					mut binds := map[string]bool{}
					if cj.bind != '' && cj.bind != '_' {
						binds[cj.bind] = true
					}
					if pex := cj.expr {
						if pex is cx.ProgramPattern {
							planar_pattern_binds(pex, mut binds)
						}
					}
					mut depends := false
					for name, _ in binds {
						if name in free {
							depends = true
							break
						}
					}
					if depends {
						// dependency floor; also THE cross-comprehension
						// barrier: a nested source carrying λ is where
						// σ-across-λ would happen — declined loudly.
						if src := cj.source {
							if src is cx.ProgramForComp {
								if src.clauses.any(it.kind in [.limit, .take, .drop]) {
									report.declined << PlanarRewriteDecline{
										kind:   'sigma-pushdown-into-source'
										reason: 'σ across λ (order-fixing barrier): the generator source is a nested comprehension carrying [limit]/[take]/[drop] — filtering below its truncation is a different relation'
									}
								}
							}
						}
						break
					}
					if !pred_total {
						report.declined << PlanarRewriteDecline{
							kind:   'sigma-placement'
							reason: 'predicate not established total (the err rule: dropping frames before the generator expands could destroy or reorder err observations)'
						}
						break
					}
					if pex := cj.expr {
						if pex is cx.ProgramPattern {
							// pattern-bind generator: match admissibility
							// unproven in v1.
							report.declined << PlanarRewriteDecline{
								kind:   'sigma-placement'
								reason: 'pattern-bind generator crossing not established sound in v1'
							}
							break
						}
					}
					src_total := if src := cj.source {
						planar_established_total(src)
					} else {
						false
					}
					if !src_total {
						report.declined << PlanarRewriteDecline{
							kind:   'sigma-placement'
							reason: 'generator source not established total (the err rule: frames dropped by the hoisted σ would skip a source evaluation that can err)'
						}
						break
					}
					target = j
					crossings << PlanarRewriteEntry{
						kind:   'sigma-placement'
						detail: 'σ hoisted above the independent generator at clause ${j + 1}'
					}
				}
				.binding {
					if cj.bind != '' && cj.bind in free {
						break
					}
					if !pred_total {
						report.declined << PlanarRewriteDecline{
							kind:   'sigma-placement'
							reason: 'predicate not established total (the err rule)'
						}
						break
					}
					bexpr_total := if be := cj.expr {
						planar_established_total(be)
					} else {
						false
					}
					if !bexpr_total {
						report.declined << PlanarRewriteDecline{
							kind:   'sigma-placement'
							reason: 'binder expression not established total (conservative decline — the err rule\'s fail-safe side)'
						}
						break
					}
					target = j
					crossings << PlanarRewriteEntry{
						kind:   'sigma-placement'
						detail: 'σ hoisted above the independent [= …] extension at clause ${j + 1}'
					}
				}
				.order_by {
					if !pred_total {
						report.declined << PlanarRewriteDecline{
							kind:   'sigma-pushdown-below-tau'
							reason: 'predicate not established total (the err rule: σ below τ changes the predicate\'s evaluation order from sorted to source order)'
						}
						break
					}
					key_total := if ke := cj.expr {
						planar_established_total(ke)
					} else {
						true
					}
					if !key_total {
						report.declined << PlanarRewriteDecline{
							kind:   'sigma-pushdown-below-tau'
							reason: 'order-by key not established total (conservative decline — key errs are inert under shipped semantics, but the gate survives any future loudening)'
						}
						break
					}
					target = j
					crossings << PlanarRewriteEntry{
						kind:   'sigma-pushdown-below-tau'
						detail: 'σ pushed below the [order-by] barrier at clause ${j + 1}'
					}
				}
				.filter {
					other_total := if oe := cj.expr {
						planar_established_total(oe)
					} else {
						false
					}
					if !pred_total || !other_total {
						report.declined << PlanarRewriteDecline{
							kind:   'sigma-commutation'
							reason: 'σ/σ commutation requires both predicates established total (the err rule: commuting reorders their err observations)'
						}
						break
					}
					target = j
					crossings << PlanarRewriteEntry{
						kind:   'sigma-commutation'
						detail: 'σ commuted with the σ at clause ${j + 1}'
					}
				}
				.takewhile, .dropwhile, .fail_fast {
					// unreachable for members (§7.8 point 2).
					break
				}
			}
		}
		if target < i {
			moved := clauses[i]
			clauses.delete(i)
			clauses.insert(target, moved)
			report.applied << crossings
			// the moved σ landed earlier; re-examine from the slot after it.
			i = target + 1
			continue
		}
		i++
	}
	return clauses
}

// planar_prune_extends removes [= …] extensions that are provably
// unobservable (π pruning): the binder is read by no later clause, no
// yield, and is not observable through γ's $group columns — and the
// binder expression is established total (the err rule: pruning a partial
// extension would destroy its errs).
fn planar_prune_extends(clauses_in []cx.ProgramForClause, f cx.ProgramForComp, mut report PlanarRewriteReport) []cx.ProgramForClause {
	mut clauses := clauses_in.clone()
	has_group := clauses.any(it.kind == .group_by)
	// $group observability: with a [group-by], every binder is a named
	// $group child (§7.2) — any $group read downstream makes ALL binders
	// observable.
	mut group_read := false
	if has_group {
		mut free := map[string]bool{}
		for c in clauses {
			if e := c.expr {
				planar_group_reads(e, mut free)
			}
		}
		planar_group_reads(f.yield, mut free)
		if yv := f.yield_value {
			planar_group_reads(yv, mut free)
		}
		group_read = 'group' in free
	}
	mut i := 0
	for i < clauses.len {
		c := clauses[i]
		if c.kind != .binding || c.bind == '' || c.bind == '_' {
			i++
			continue
		}
		if has_group && group_read {
			i++
			continue
		}
		// rebinding the same name later makes positional reasoning fragile —
		// skip the whole name in that case.
		mut bind_sites := 0
		for cj in clauses {
			if cj.kind == .binding && cj.bind == c.bind {
				bind_sites++
			}
			if cj.kind == .generator && cj.bind == c.bind {
				bind_sites++
			}
		}
		if bind_sites > 1 {
			i++
			continue
		}
		mut read := false
		for j := i + 1; j < clauses.len; j++ {
			if e := clauses[j].expr {
				if planar_reads_name(e, c.bind) {
					read = true
					break
				}
			}
			if s := clauses[j].source {
				if planar_reads_name(s, c.bind) {
					read = true
					break
				}
			}
		}
		if !read && planar_reads_name(f.yield, c.bind) {
			read = true
		}
		if !read {
			if yv := f.yield_value {
				if planar_reads_name(yv, c.bind) {
					read = true
				}
			}
		}
		if read {
			i++
			continue
		}
		expr_total := if e := c.expr {
			planar_established_total(e)
		} else {
			false
		}
		if !expr_total {
			report.declined << PlanarRewriteDecline{
				kind:   'pi-prune-extend'
				reason: 'binder `\$${c.bind}` is unread but its expression is not established total (conservative decline — the err rule\'s fail-safe side; binder errs are inert per §7.2\'s guard-scoped rule, so this gate may relax with stream-16 inference)'
			}
			i++
			continue
		}
		report.applied << PlanarRewriteEntry{
			kind:   'pi-prune-extend'
			detail: 'unread total [= \$${c.bind} …] extension pruned'
		}
		clauses.delete(i)
	}
	return clauses
}

// planar_reads_name reports whether the expression reads `name` (free-read
// analysis, shadowing-aware via planar_free_bindings).
fn planar_reads_name(n cx.ProgramNode, name string) bool {
	mut free := map[string]bool{}
	planar_free_bindings(n, map[string]bool{}, mut free)
	return name in free
}

// planar_group_reads collects reads INCLUDING the γ-reserved names (which
// planar_free_bindings deliberately excludes) — the $group observability
// scan needs them.
fn planar_group_reads(n cx.ProgramNode, mut out map[string]bool) {
	match n {
		cx.ProgramBinding {
			if n.name != '' {
				out[n.name] = true
			}
		}
		cx.ProgramDirective {
			for slot in n.slots {
				planar_group_reads(slot.value, mut out)
			}
		}
		cx.ProgramCall {
			for arg in n.args {
				planar_group_reads(arg, mut out)
			}
		}
		cx.ProgramLiteral {
			for child in n.items {
				planar_group_reads(child, mut out)
			}
			for slot in n.slots {
				planar_group_reads(slot.value, mut out)
			}
			for attr in n.attrs {
				planar_group_reads(attr.value, mut out)
			}
		}
		cx.ProgramForComp {
			for item in cx.for_comp_children(n) {
				planar_group_reads(item.node, mut out)
			}
		}
		cx.ProgramPattern {
			for attr in n.attrs {
				if v := attr.value {
					planar_group_reads(v, mut out)
				}
			}
			for child in n.body {
				planar_group_reads(child, mut out)
			}
		}
		cx.ProgramSliceAccess {
			planar_group_reads(cx.ProgramNode(n.binding), mut out)
			for ax in n.axes {
				if s := ax.start {
					planar_group_reads(s, mut out)
				}
				if s := ax.stop {
					planar_group_reads(s, mut out)
				}
				if s := ax.step {
					planar_group_reads(s, mut out)
				}
			}
		}
		cx.Program {
			planar_group_reads(n.body, mut out)
		}
		else {}
	}
}

// ── established totality (the stream-16 seam) ─────────────────────────────────

// planar_total_call_names — builtins proven total for ANY argument values
// (given total arguments): structural equality (never errs, #753),
// EBV-coercing logic, counting. STRICT ordered comparison ([>] and
// friends) and arithmetic are deliberately absent — they err on
// non-numeric operands, and without shape inference (stream 16) no
// argument shape is provable.
const planar_total_call_names = ['=', '!=', 'eq', 'not', 'and', 'or', 'count']

// planar_established_total reports whether the engine can PROVE the
// expression err-free on every input. Conservative: false means
// "unproven", never "impure/erring".
pub fn planar_established_total(n cx.ProgramNode) bool {
	match n {
		cx.Program {
			return planar_established_total(n.body)
		}
		cx.ProgramBinding {
			// binding-path navigation is total (absent → empty); step
			// predicates: position and equality-class attr tests are
			// total, general expr predicates are unproven.
			for step in n.path {
				for pred in step.predicates {
					match pred.kind {
						.position {}
						.attr_test {
							if pred.attr_op !in ['', '=', '!='] {
								return false
							}
							if av := pred.attr_value {
								if !planar_established_total(av) {
									return false
								}
							}
						}
						.expr {
							return false
						}
					}
				}
			}
			return true
		}
		cx.ProgramLiteral {
			match n.kind {
				.string_lit, .int_lit, .bigint_lit, .decimal_lit, .float_lit, .bool_lit,
				.duration_lit, .period_lit, .date_lit, .datetime_lit, .atom_lit, .node_lit {
					return true
				}
				.sequence_lit, .array_lit, .block, .map_lit {
					for it in n.items {
						if !planar_established_total(it) {
							return false
						}
					}
					return true
				}
				.cx_element {
					// operator-headed S-expressions parse as cx_element
					// literals (eval_operator_element): classify by head.
					// Equality and EBV logic are total; STRICT ordered
					// comparison, arithmetic, and the set operators are
					// unproven without shape inference.
					if n.name in ['<', '<=', '>', '>=', '+', '-', '*', '/', '%', '~', 'union',
						'intersect', 'except'] {
						return false
					}
					// '=' / '!=' / 'and' / 'or' / 'not' operator forms and
					// plain element CONSTRUCTION: total given total children.
					if ne := n.name_expr {
						if !planar_established_total(ne) {
							return false
						}
					}
					for a in n.attrs {
						if !planar_established_total(a.value) {
							return false
						}
					}
					for it in n.items {
						if !planar_established_total(it) {
							return false
						}
					}
					return true
				}
			}
		}
		cx.ProgramCall {
			if n.name == 'range' {
				// total exactly when the bounds are int literals (an
				// open-end range is non-planar anyway).
				for a in n.args {
					if a is cx.ProgramLiteral && a.kind == .int_lit {
						continue
					}
					return false
				}
				return n.args.len >= 2
			}
			if n.name !in planar_total_call_names {
				return false
			}
			for a in n.args {
				if !planar_established_total(a) {
					return false
				}
			}
			return true
		}
		cx.ProgramWildcard {
			return true
		}
		cx.ProgramSliceLiteral {
			return true
		}
		else {
			// directives, nested comprehensions, path expressions (ambient),
			// slice application, patterns: unproven in v1 — stream 16's
			// inference strengthens this seam.
			return false
		}
	}
	return false
}
