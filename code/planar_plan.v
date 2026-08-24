module code

// planar_plan.v — the canonical plan form and the plan address
// (code.md §7.9, stream-2 ruling L93; spec/03-approved/core/planar_algebra.md).
//
// Every member of the planar fragment (§7.8) normalizes to exactly one
// canonical plan encoding; the encoding's tagged hash is the PLAN ADDRESS —
// the identity tier ABOVE E1 text identity. E1 stays name-sensitive; the
// plan tier collapses exactly the ruled equivalences:
//
//   1. clause order PRESERVED for semantic clauses (generators, [where],
//      [= …], [order-by], [group-by]) — their order is meaning;
//   2. execution hints ([par]/[lazy]/[ordered], incl. hint parameters)
//      ERASED — presence and position cannot split the address;
//   3. the λ tail: [limit]/[take]/[drop] carried canonically LAST, drops
//      before takes, [limit]→[take] collapse; runs of consecutive
//      non-negative literal drops SUM (a zero-sum run is erased), runs of
//      consecutive non-negative literal takes take the MIN; a negative
//      literal (always an eval error since W4) or a non-literal count
//      breaks the run and encodes verbatim in surface order within its
//      kind — folding across one would equate an erring spelling with a
//      non-erring one;
//   4. binders the comprehension introduces (clause binds, pattern
//      captures, let/fn/match binders inside clause expressions) encode
//      as de Bruijn LEVELS; free names encode VERBATIM (plan parameters —
//      renaming a parameter is not alpha-equivalence); the γ-introduced
//      $key/$count/$group are operator-defined columns, encoded by name
//      (they are never pushed onto the binder stack); nested planar
//      comprehensions normalize recursively under the enclosing scope
//      (the correlated form). `$_` is never pushed (it also names the
//      context item inside path predicates — pushing it would falsely
//      merge a loop-variable read with a context-item read);
//   5. an [order-by] with no direction encodes the explicit `asc`.
//
// Equality ⟺ byte-identity (canonical.md §2.12.7 posture): the encoding is
// a LENGTH-PREFIXED token stream, injective over plan structure — two
// structurally distinct plans can only collide by hash collision, never by
// encoding. Where alpha-normalization does not reach (binders of pure-flow
// directives beyond let/fn/match, path-step `(bind $n)` annotations), the
// name encodes verbatim on BOTH the bind and read sides — a missed
// alpha-collapse (two respellings keep two addresses) is possible there, a
// false merge is not.
//
// This emitter is DELIBERATELY separate from code_identity.v's T2Emitter:
// Tier-2 is a byte-frozen identity stream (the address-baseline gate pins
// it); the plan form is a new tier with its own normalization rules (hint
// erasure, λ tail, clause-bind alpha) that Tier-2 must never inherit. The
// plan encoding also carries slots Tier-2's stream omits (slice bounds,
// pattern-attr values, the bare-ref-vs-call flag) — see the T2 injectivity
// issue filed at W4.
//
// Entry is GATED by §7.8 membership: every public entry point refuses a
// non-member with the typed CXER0120 message — never a silent fallback.
// Plan-form construction is the membership checker's first runtime
// consumer (W4 of the stream-2 ledger).

import cx
import crypto.sha256
import strings

// plan_address_lead — the distinct token's lead. `plan:<algo>:<hex>` is
// never a document address (the tagged-address reader refuses `plan` as an
// algorithm) and never a `computes-as:` computation-identity claim.
pub const plan_address_lead = 'plan:'

// cx_plan_form returns the canonical plan encoding of a planar
// comprehension source (inspection / tests). Errors carry the CXER token
// their consumer maps to: CXER4100 for malformed source, CXER0120 for a
// non-member.
pub fn cx_plan_form(source string) !string {
	prog := cx.parse_program(source) or {
		return error('malformed CX source: ${err.msg()} (cx-err:CXER4100)')
	}
	return plan_form_of_node(prog)
}

// cx_plan_address returns the plan address `plan:<algo>:<hex>` of a planar
// comprehension source.
pub fn cx_plan_address(source string) !string {
	enc := cx_plan_form(source)!
	return plan_address_of_encoding(enc)
}

// plan_form_of_node is the node-level membership-gated entry (consumers
// that already hold a parsed program — the W6 quoted store query).
pub fn plan_form_of_node(n cx.ProgramNode) !string {
	if r := planar_membership(n) {
		return error('comprehension is not planar: ${r.reason} (membership point ${r.point}, code.md §7.8) (${planar_err_code})')
	}
	return plan_encode(n)
}

// plan_address_of_node — node-level twin of cx_plan_address.
pub fn plan_address_of_node(n cx.ProgramNode) !string {
	return plan_address_of_encoding(plan_form_of_node(n)!)
}

fn plan_address_of_encoding(enc string) string {
	return plan_address_lead +
		cx.cx_tag_address(cx.cx_default_hash_algo, sha256.sum256(enc.bytes()).hex())
}

// plan_encode emits the canonical encoding of a MEMBER. Private: entry
// points gate membership first.
fn plan_encode(n cx.ProgramNode) string {
	mut e := PlanEmitter{
		b: strings.new_builder(256)
	}
	e.b.write_string('plan1')
	e.emit(n)
	return e.b.str()
}

// PlanEmitter walks the program AST read-only, emitting the normalized
// length-prefixed token stream.
struct PlanEmitter {
mut:
	b     strings.Builder
	scope []string // de Bruijn binder stack (index = level)
	// comp_base / comp_grouped — the CURRENT comprehension's binder
	// segment ([comp_base..scope.len]) and whether it carries a
	// [group-by]. γ names $group's children after the comprehension's
	// binders (§7.2: "generator and [= …] binder values as named
	// children"), so a `$group/NAME` first step is a READ of that binder
	// — it alpha-resolves to the binder's level (the M5 pair case is
	// unreachable otherwise). Resolution is confined to the current
	// grouped comprehension's own segment: a nested comprehension reading
	// an ENCLOSING $group keeps the step verbatim (a missed collapse,
	// never a cross-comprehension merge).
	comp_base    int
	comp_grouped bool
}

fn (mut e PlanEmitter) field(s string) {
	e.b.write_string(s.len.str())
	e.b.write_u8(`:`)
	e.b.write_string(s)
}

fn plan_level(scope []string, name string) ?int {
	mut i := scope.len - 1
	for i >= 0 {
		if scope[i] == name {
			return i
		}
		i--
	}
	return none
}

// plan_push pushes a comprehension-introduced binder. '' and '_' are never
// pushed ('_' also names the context item in path predicates — see the
// header). Returns true when a binder was pushed (the presence marker
// keeps level numbering recoverable, hence injective).
fn (mut e PlanEmitter) plan_push(name string) bool {
	if name == '' || name == '_' {
		return false
	}
	e.scope << name
	return true
}

// ── the comprehension arm (the normalization lives here) ─────────────────────

fn (mut e PlanEmitter) emit_comp(f cx.ProgramForComp) {
	e.b.write_string('(F')
	e.b.write_string(match f.outer_form {
		.sequence { 's' }
		.array { 'a' }
		.map { 'm' }
	})
	e.b.write_string(match f.yield_form {
		.sequence { 's' }
		.array { 'a' }
		.map { 'm' }
	})
	saved := e.scope.len
	saved_base := e.comp_base
	saved_grouped := e.comp_grouped
	e.comp_base = saved
	e.comp_grouped = f.clauses.any(it.kind == .group_by)
	defer {
		e.comp_base = saved_base
		e.comp_grouped = saved_grouped
	}
	mut drops := []cx.ProgramNode{}
	mut takes := []cx.ProgramNode{}
	for c in f.clauses {
		match c.kind {
			.generator {
				e.b.write_string('|g')
				if s := c.source {
					e.b.write_u8(`s`)
					e.emit(s) // the source sees only EARLIER binders
				}
				// presence markers keep the level mapping recoverable:
				// which generator pushed a binder is part of the plan.
				if e.plan_push(c.bind) {
					e.b.write_u8(`b`)
				} else {
					e.b.write_u8(`.`)
				}
				if pex := c.expr {
					if pex is cx.ProgramPattern {
						// pattern-bind generator: captures enter scope (head
						// bind first, then body order), the pattern's bind
						// SITES then emit as levels.
						for name in plan_ordered_pattern_binds(pex) {
							e.plan_push(name)
						}
						e.b.write_u8(`p`)
						e.emit_pattern(pex)
					} else {
						e.b.write_u8(`e`)
						e.emit(pex)
					}
				}
			}
			.binding {
				e.b.write_string('|=')
				if ex := c.expr {
					e.emit(ex) // the value sees only EARLIER binders
				}
				if e.plan_push(c.bind) {
					e.b.write_u8(`b`)
				} else {
					e.b.write_u8(`.`)
				}
			}
			.filter {
				e.b.write_string('|w')
				if ex := c.expr {
					e.emit(ex)
				}
			}
			.order_by {
				e.b.write_string('|o')
				if ex := c.expr {
					e.emit(ex)
				}
				// defaults are explicit: no direction encodes `asc` (§7.2).
				e.field(if c.direction == '' { 'asc' } else { c.direction })
			}
			.group_by {
				e.b.write_string('|G')
				if ex := c.expr {
					e.emit(ex)
				}
				// $key/$count/$group become readable downstream as
				// operator-defined columns — encoded BY NAME (never pushed).
			}
			.limit, .take {
				// the ruled collapse: both are the one canonical take.
				if ex := c.expr {
					takes << ex
				}
			}
			.drop {
				if ex := c.expr {
					drops << ex
				}
			}
			.par, .lazy, .ordered {
				// hint erasure (§7.8 point 6): presence, position, and hint
				// parameters ([par N] / [par max]) all vanish from the plan.
			}
			.takewhile, .dropwhile, .fail_fast {
				// unreachable for members (§7.8 point 2 refuses these);
				// entry is membership-gated, so nothing to encode.
			}
		}
	}
	// π: the yield projection.
	e.b.write_string('|y')
	e.emit(f.yield)
	if yv := f.yield_value {
		e.b.write_u8(`v`)
		e.emit(yv)
	}
	// the λ tail — canonically LAST, drops before takes. Count expressions
	// are enclosing-scope expressions (evaluated once at comprehension
	// entry), so they emit OUTSIDE the comprehension's binder scope.
	e.scope.trim(saved)
	e.emit_lambda_tail(drops, takes)
	e.b.write_u8(`)`)
}

// emit_lambda_tail composes and emits the canonical λ tail. Runs of
// consecutive non-negative literals fold (drops SUM — a zero sum is
// erased; takes MIN — a zero take is meaningful and kept); a negative
// literal or a non-literal count breaks the run and encodes verbatim.
fn (mut e PlanEmitter) emit_lambda_tail(drops []cx.ProgramNode, takes []cx.ProgramNode) {
	mut dsum := i64(0)
	mut dhave := false
	for x in drops {
		if x is cx.ProgramLiteral && x.kind == .int_lit && x.int_val >= 0 {
			dsum += x.int_val
			dhave = true
			continue
		}
		if dhave && dsum > 0 {
			e.b.write_string('|dl')
			e.b.write_string(dsum.str())
		}
		dsum = 0
		dhave = false
		e.b.write_string('|de')
		e.emit(x)
	}
	if dhave && dsum > 0 {
		e.b.write_string('|dl')
		e.b.write_string(dsum.str())
	}
	mut tmin := i64(0)
	mut thave := false
	for x in takes {
		if x is cx.ProgramLiteral && x.kind == .int_lit && x.int_val >= 0 {
			if !thave || x.int_val < tmin {
				tmin = x.int_val
			}
			thave = true
			continue
		}
		if thave {
			e.b.write_string('|tl')
			e.b.write_string(tmin.str())
		}
		thave = false
		e.b.write_string('|te')
		e.emit(x)
	}
	if thave {
		e.b.write_string('|tl')
		e.b.write_string(tmin.str())
	}
}

// plan_ordered_pattern_binds returns the names a pattern captures in the
// canonical push order: head bind first, then body binds in document
// order, nested patterns recursively.
fn plan_ordered_pattern_binds(p cx.ProgramPattern) []string {
	mut out := []string{}
	if p.head.bind != '' && p.head.bind != '_' {
		out << p.head.bind
	}
	for it in p.body {
		match it {
			cx.ProgramBinding {
				if it.name != '' && it.name != '_' {
					out << it.name
				}
			}
			cx.ProgramPattern {
				out << plan_ordered_pattern_binds(it)
			}
			else {}
		}
	}
	return out
}

// ── expression encoding (structural, length-prefixed, injective) ─────────────

fn (mut e PlanEmitter) emit_binding(n cx.ProgramBinding) {
	mut is_free_group := false
	if lvl := plan_level(e.scope, n.name) {
		e.b.write_u8(`b`)
		e.b.write_string(lvl.str())
	} else {
		// free — a plan parameter (or an operator-defined γ column),
		// encoded verbatim.
		e.b.write_u8(`r`)
		e.field(n.name)
		is_free_group = n.name == 'group'
	}
	for i, step in n.path {
		e.b.write_u8(`/`)
		e.b.write_string(step.kind.str())
		// `$group/NAME`: the first child step names a comprehension
		// binder's γ column — alpha-resolve it to the binder's level
		// (see PlanEmitter.comp_base).
		if i == 0 && is_free_group && step.kind == .child && e.comp_grouped {
			if lvl := plan_level(e.scope, step.name) {
				if lvl >= e.comp_base {
					e.b.write_u8(`C`)
					e.b.write_string(lvl.str())
				} else {
					e.field(step.name)
				}
			} else {
				e.field(step.name)
			}
		} else {
			e.field(step.name)
		}
		// [131b] kind test, presence-marked off `.none` (same discipline
		// as the #772 predicate-hole fix below): absent → zero bytes, so
		// every pre-existing plan address is byte-identical.
		if step.kind_test != .none {
			e.b.write_u8(`K`)
			e.b.write_string(step.kind_test.str())
		}
		for pred in step.predicates {
			e.b.write_u8(`[`)
			e.emit_predicate(pred)
			e.b.write_u8(`]`)
		}
	}
}

fn (mut e PlanEmitter) emit_predicate(p cx.ProgramPathPredicate) {
	e.b.write_string(p.kind.str())
	e.b.write_u8(`i`)
	e.b.write_string(p.int_index.str())
	e.field(p.attr_name)
	e.field(p.attr_op)
	// #772 rider (the W7-audit continuation): the plan tier had the same
	// predicate holes as pre-#769 Tier-2 — attr KIND (existence ≡ absence)
	// and the type-test TYPE NAME were absent, so DIFFERENT queries shared
	// one plan address (a caching identity — false sharing serves wrong
	// cached rows). Presence-marked off the defaults, so predicates
	// without these fields keep their pre-fix plan bytes.
	if p.attr_kind != .existence {
		e.b.write_u8(`k`)
		e.field(p.attr_kind.str())
	}
	if p.type_name != '' {
		e.b.write_u8(`T`)
		e.field(p.type_name)
	}
	if av := p.attr_value {
		e.b.write_u8(`v`)
		e.emit(av)
	}
	if bd := p.body {
		e.b.write_u8(`e`)
		e.emit(bd)
	}
}

fn (mut e PlanEmitter) emit(node cx.ProgramNode) {
	match node {
		cx.Program {
			e.emit(node.body)
		}
		cx.ProgramBinding {
			e.b.write_u8(`$`)
			e.emit_binding(node)
		}
		cx.ProgramCall {
			e.b.write_string('(c')
			e.field(node.name)
			if node.fallible {
				e.b.write_u8(`?`)
			} else if node.must_succeed {
				e.b.write_u8(`!`)
			} else {
				e.b.write_u8(`.`)
			}
			// bare reference (function value, D1) vs explicit call — two
			// different programs, kept distinct in the plan.
			e.b.write_u8(if node.explicit_call { `(` } else { `_` })
			e.b.write_string(node.args.len.str())
			for i, a in node.args {
				e.b.write_u8(` `)
				if i < node.arg_labels.len {
					e.field(node.arg_labels[i])
				} else {
					e.field('')
				}
				e.emit(a)
			}
			e.b.write_u8(`)`)
		}
		cx.ProgramLiteral {
			e.emit_literal(node)
		}
		cx.ProgramDirective {
			e.emit_directive(node)
		}
		cx.ProgramForComp {
			// nested comprehension — normalizes recursively under the
			// enclosing scope (the correlated form).
			e.emit_comp(node)
		}
		cx.ProgramPattern {
			e.emit_pattern(node)
		}
		cx.ProgramSliceAccess {
			e.b.write_string('(sa')
			e.emit_binding(node.binding)
			e.emit_axes(node.axes)
			e.b.write_u8(`)`)
		}
		cx.ProgramSliceLiteral {
			e.b.write_string('(sl')
			e.emit_axes(node.axes)
			e.b.write_u8(`)`)
		}
		cx.ProgramPathExpr {
			e.b.write_string('(px')
			e.b.write_string(node.leading.str())
			for s in node.steps {
				e.b.write_u8(`|`)
				e.b.write_string(s.axis.str())
				e.field(s.name)
				e.b.write_string(s.ns_kind.str())
				e.field(s.ns_prefix)
				if s.kind_test != .none {
					e.b.write_u8(`K`)
					e.b.write_string(s.kind_test.str())
				}
				e.field(s.bind)
				for pred in s.predicates {
					e.b.write_u8(`[`)
					e.emit_predicate(pred)
					e.b.write_u8(`]`)
				}
			}
			e.b.write_u8(`)`)
		}
		cx.ProgramWildcard {
			e.b.write_string('(w')
			e.b.write_string(if node.deep { '1' } else { '0' })
			e.b.write_u8(`)`)
		}
	}
}

// emit_axes encodes slice axes FULLY (kind + every bound expression) —
// slice bounds are plan structure.
fn (mut e PlanEmitter) emit_axes(axes []cx.SliceAxis) {
	e.b.write_string(axes.len.str())
	for ax in axes {
		e.b.write_u8(`|`)
		e.b.write_string(ax.kind.str())
		if s := ax.start {
			e.b.write_u8(`s`)
			e.emit(s)
		} else {
			e.b.write_u8(`.`)
		}
		if s := ax.stop {
			e.b.write_u8(`t`)
			e.emit(s)
		} else {
			e.b.write_u8(`.`)
		}
		if s := ax.step {
			e.b.write_u8(`p`)
			e.emit(s)
		} else {
			e.b.write_u8(`.`)
		}
	}
}

fn (mut e PlanEmitter) emit_literal(l cx.ProgramLiteral) {
	e.b.write_string('(L')
	e.b.write_string(l.kind.str())
	match l.kind {
		.string_lit, .bigint_lit, .decimal_lit, .duration_lit, .period_lit, .date_lit,
		.datetime_lit, .node_lit, .atom_lit {
			e.field(l.str_val)
		}
		.int_lit {
			e.field(l.int_val.str())
		}
		.float_lit {
			e.field(l.flt_val.str())
		}
		.bool_lit {
			e.b.write_string(if l.bool_val { '1' } else { '0' })
		}
		.sequence_lit, .array_lit, .block {
			e.b.write_string(l.items.len.str())
			for it in l.items {
				e.b.write_u8(` `)
				e.emit(it)
			}
		}
		.map_lit {
			e.b.write_string(l.items.len.str())
			for i, it in l.items {
				e.b.write_u8(` `)
				if i < l.keys.len {
					e.field(l.keys[i])
				} else {
					e.field('')
				}
				e.emit(it)
			}
		}
		.cx_element {
			e.field(l.name)
			e.field(l.data_type)
			if ne := l.name_expr {
				e.b.write_u8(`n`)
				e.emit(ne)
			}
			e.b.write_u8(`a`)
			e.b.write_string(l.attrs.len.str())
			for a in l.attrs {
				e.b.write_u8(` `)
				e.field(a.name)
				e.field(a.data_type)
				e.emit(a.value)
			}
			e.b.write_u8(`i`)
			e.b.write_string(l.items.len.str())
			for it in l.items {
				e.b.write_u8(` `)
				e.emit(it)
			}
		}
	}
	e.b.write_u8(`)`)
}

fn (mut e PlanEmitter) emit_directive(d cx.ProgramDirective) {
	// the binder-introducing pure-flow specials mirror Tier-2's coverage
	// (fn / let / match); everywhere else binder names encode verbatim on
	// both bind and read sides (missed alpha-collapse, never a merge).
	match d.name {
		'fn' { e.emit_fn(d) }
		'let' { e.emit_let(d) }
		'match' { e.emit_match(d) }
		else { e.emit_generic_directive(d) }
	}
}

fn (mut e PlanEmitter) emit_fn(d cx.ProgramDirective) {
	if d.slots.len < 2 || d.slots[0].value !is cx.ProgramLiteral {
		e.emit_generic_directive(d)
		return
	}
	params := d.slots[0].value as cx.ProgramLiteral
	saved := e.scope.len
	mut nparams := 0
	for it in params.items {
		if it is cx.ProgramBinding {
			e.scope << it.name
			nparams++
		}
	}
	e.b.write_string('(fn')
	e.b.write_string(nparams.str())
	for i := 1; i < d.slots.len; i++ {
		e.b.write_u8(` `)
		e.emit(d.slots[i].value)
	}
	e.b.write_u8(`)`)
	e.scope.trim(saved)
}

fn (mut e PlanEmitter) emit_let(d cx.ProgramDirective) {
	if d.slots.len < 2 || d.slots[0].value !is cx.ProgramLiteral {
		e.emit_generic_directive(d)
		return
	}
	cl := d.slots[0].value as cx.ProgramLiteral
	if cl.items.len == 0 || cl.items[0] !is cx.ProgramBinding {
		e.emit_generic_directive(d)
		return
	}
	binder := cl.items[0] as cx.ProgramBinding
	e.b.write_string('(let')
	// value expression(s) in the OUTER scope
	for i := 1; i < cl.items.len; i++ {
		e.b.write_u8(` `)
		e.emit(cl.items[i])
	}
	e.b.write_u8(`|`)
	saved := e.scope.len
	e.scope << binder.name
	for i := 1; i < d.slots.len; i++ {
		e.b.write_u8(` `)
		e.emit(d.slots[i].value)
	}
	e.b.write_u8(`)`)
	e.scope.trim(saved)
}

fn (mut e PlanEmitter) emit_match(d cx.ProgramDirective) {
	if d.slots.len < 3 {
		e.emit_generic_directive(d)
		return
	}
	e.b.write_string('(mat')
	e.emit(d.slots[0].value)
	mut i := 1
	for i < d.slots.len {
		if d.slots[i].value is cx.ProgramPattern && i + 1 < d.slots.len {
			e.b.write_u8(`|`)
			saved := e.scope.len
			pat := d.slots[i].value as cx.ProgramPattern
			for bn in plan_ordered_pattern_binds(pat) {
				e.scope << bn
			}
			e.emit_pattern(pat)
			e.b.write_u8(`=`)
			e.emit(d.slots[i + 1].value)
			e.scope.trim(saved)
			i += 2
		} else {
			e.b.write_u8(`|`)
			e.emit(d.slots[i].value)
			i++
		}
	}
	e.b.write_u8(`)`)
}

fn (mut e PlanEmitter) emit_generic_directive(d cx.ProgramDirective) {
	e.b.write_string('(d')
	e.field(d.name)
	e.b.write_string(d.slots.len.str())
	for s in d.slots {
		e.b.write_u8(` `)
		e.field(s.label)
		e.emit(s.value)
	}
	e.b.write_u8(`)`)
}

fn (mut e PlanEmitter) emit_pattern(p cx.ProgramPattern) {
	e.b.write_string('(p')
	e.b.write_string(p.head.kind.str())
	e.field(p.head.value)
	if p.head.bind != '' {
		if lvl := plan_level(e.scope, p.head.bind) {
			e.b.write_u8(`b`)
			e.b.write_string(lvl.str())
		} else {
			e.b.write_u8(`r`)
			e.field(p.head.bind)
		}
	}
	if p.direct {
		e.b.write_u8(`D`)
	}
	for a in p.attrs {
		e.b.write_u8(`@`)
		e.b.write_string(a.kind.str())
		e.field(a.name)
		e.field(a.op)
		e.field(a.type_name)
		// the attr VALUE is plan structure (`@role="admin"` vs
		// `@role="guest"` are different plans).
		if av := a.value {
			e.b.write_u8(`v`)
			e.emit(av)
		} else {
			e.b.write_u8(`.`)
		}
	}
	for it in p.body {
		e.b.write_u8(` `)
		match it {
			cx.ProgramBinding {
				if lvl := plan_level(e.scope, it.name) {
					e.b.write_string('\$b')
					e.b.write_string(lvl.str())
				} else {
					e.b.write_string('\$r')
					e.field(it.name)
				}
			}
			cx.ProgramPattern {
				e.emit_pattern(it)
			}
			else {
				e.field(it.type_name())
			}
		}
	}
	e.b.write_u8(`)`)
}
