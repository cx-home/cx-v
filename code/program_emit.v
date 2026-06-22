module code
import cx

import strings

// program_emit.v — cx.ProgramNode → CX source-text emitter (Phase 2.13 +
// dispatcher-integration bridge for Z79f).
//
// The output is canonical CX surface that re-parses to a `cx.ProgramNode`
// `.eq()`-equal to the input (the round-trip identity property). The
// dispatcher integration of the standalone `[?match]` / `[?modify]`
// evaluators no longer round-trips through this emitter — it lowers
// the `cx.ProgramDirective` directly to `cx.MatchNode` / `cx.ModifyNode`
// via `vcx/code/lower_to_cx_node.v` (the source round-trip + second
// cx-data parser were removed when the surface moved to clause form).
//
// Cross-references:
//   - `vcx/cx/path_renderer.v` (Phase 2.9): PathNode → text. This file
//     adopts the same conventions for cx.ProgramPathExpr emission.
//   - `vcx/code/code_diagram.v` (Phase 2.10): program AST visualisation.
//   - `vcx/code/render.v`: cx.Node → text (program *value* renderer).
//     Distinct surface — this file renders *AST*, that one renders
//     evaluated *values*.
//   - `spec/code.md §5–§10`: surface syntax for program nodes.
//   - `spec/canonical.md §2.12`: canonical-form rules (this emitter
//     adapts the path-step shape from §2.12).
//
// Round-trip contract: every cx.ProgramNode that the parser produces
// MUST round-trip through `program_node_to_source` then back via
// `code.parse(...)` to an `.eq()`-equal cx.ProgramNode for the variants
// reachable in `[?match]` / `[?modify]` slot positions (the dispatcher
// integration surface). Variants reachable only through unusual
// surface (e.g. `cx.Program` block lit, `cx.ProgramWildcard` outside pattern
// body, `cx.ProgramForComp` with full clause vocabulary) emit canonical
// text but may not be exhaustively round-trip pinned at Phase 2.13 —
// they are emitted with shape preservation pending full 
// graft. See `vcx/tests/v08_program_emit_test.v` for the round-trip
// suite.

// ── Public entry ──────────────────────────────────────────────────────────────

// program_node_to_source emits the canonical CX-source surface for a
// cx.ProgramNode. The output round-trips through `code.parse` to an
// `.eq()`-equal cx.ProgramNode for every node the parser produces
// (Phase 2.13 scope: `[?match]` + `[?modify]` slot variants).
pub fn program_node_to_source(node cx.ProgramNode) string {
	mut b := strings.new_builder(64)
	emit_program_node(mut b, node)
	return b.str()
}

// emit_program_node dispatches on the cx.ProgramNode sum-type variant.
fn emit_program_node(mut b strings.Builder, node cx.ProgramNode) {
	match node {
		cx.Program          { emit_program(mut b, node) }
		cx.ProgramBinding   { emit_program_binding(mut b, node) }
		cx.ProgramCall      { emit_program_call(mut b, node) }
		cx.ProgramPattern   { emit_program_pattern(mut b, node) }
		cx.ProgramDirective { emit_program_directive(mut b, node) }
		cx.ProgramForComp   { emit_program_for_comp(mut b, node) }
		cx.ProgramLiteral   { emit_program_literal(mut b, node) }
		cx.ProgramPathExpr  { emit_program_path_expr(mut b, node) }
		cx.ProgramSliceAccess { emit_program_slice_access(mut b, node) }
		cx.ProgramSliceLiteral { emit_program_slice_literal(mut b, node) }
		cx.ProgramWildcard  { emit_program_wildcard(mut b, node) }
	}
}

// ── cx.Program (top-level wrapper) ──────────────────────────────────────────────

fn emit_program(mut b strings.Builder, p cx.Program) {
	emit_program_node(mut b, p.body)
}

// ── cx.ProgramBinding — `$ident(path)?` ────────────────────────────────────────

fn emit_program_binding(mut b strings.Builder, n cx.ProgramBinding) {
	b.write_string('\$')
	b.write_string(n.name)
	for step in n.path {
		match step.kind {
			.child {
				b.write_string('/')
				b.write_string(step.name)
			}
			.attr {
				b.write_string('@')
				b.write_string(step.name)
			}
			.member {
				b.write_string('.')
				b.write_string(step.name)
			}
			.wildcard_children {
				b.write_string('/*')
			}
			.descendant {
				b.write_string('//')
				b.write_string(step.name)
			}
			.descendant_wildcard {
				b.write_string('//*')
			}
			.parent {
				b.write_string('/..')
			}
		}
		for pred in step.predicates {
			b.write_string('[')
			b.write_string(path_predicate_label(pred))
			b.write_string(']')
		}
	}
}

// ── cx.ProgramCall — `name(args) [? | !]?` ─────────────────────────────────────

fn emit_program_call(mut b strings.Builder, n cx.ProgramCall) {
	b.write_string(n.name)
	b.write_string('(')
	for i, a in n.args {
		if i > 0 {
			b.write_string(', ')
		}
		emit_program_node(mut b, a)
	}
	b.write_string(')')
	if n.fallible {
		b.write_string('?')
	} else if n.must_succeed {
		b.write_string('!')
	}
}

// ── cx.ProgramPattern — structural shape match per §5 ──────────────────────────

fn emit_program_pattern(mut b strings.Builder, p cx.ProgramPattern) {
	b.write_string('[')
	// Head per cx.ProgramPatternHeadKind. `bind` lives on the head; emitted
	// trailing the head selector with a space, then the optional `:direct`,
	// then attrs, then body items.
	match p.head.kind {
		.named      { b.write_string(p.head.value) }
		.wildcard   { b.write_string('*') }
		.deep       { b.write_string('**') }
		.type_guard {
			b.write_string(':')
			b.write_string(p.head.value)
		}
	}
	if p.head.bind != '' {
		b.write_string(' \$')
		b.write_string(p.head.bind)
	}
	if p.direct {
		b.write_string(' :direct')
	}
	for a in p.attrs {
		b.write_string(' ')
		emit_pattern_attr(mut b, a)
	}
	for it in p.body {
		b.write_string(' ')
		emit_program_node(mut b, it)
	}
	b.write_string(']')
}

fn emit_pattern_attr(mut b strings.Builder, a cx.ProgramPatternAttr) {
	match a.kind {
		.existence {
			b.write_string('@')
			b.write_string(a.name)
		}
		.absence {
			b.write_string('@!')
			b.write_string(a.name)
		}
		.equality {
			b.write_string('@')
			b.write_string(a.name)
			b.write_string('=')
			if v := a.value {
				emit_program_node(mut b, v)
			}
		}
		.comparison {
			b.write_string('@')
			b.write_string(a.name)
			b.write_string(a.op)
			if v := a.value {
				emit_program_node(mut b, v)
			}
		}
		.type_test {
			b.write_string('@')
			b.write_string(a.name)
			b.write_string('::')
			b.write_string(a.type_name)
		}
	}
}

// ── cx.ProgramWildcard — `*` / `**` in body position ───────────────────────────

fn emit_program_wildcard(mut b strings.Builder, w cx.ProgramWildcard) {
	if w.deep {
		b.write_string('**')
	} else {
		b.write_string('*')
	}
}

// ── cx.ProgramDirective — `[?name slot+]` ──────────────────────────────────────
//
// Universal directive shape. Slots emit in source order; positional
// slots are bare, labeled slots get a `:label ` prefix. The 39
// directives are all valid `n.name` values.
//
// Special-form parsers in `parser.v` reshape some directives before
// storing them as a cx.ProgramDirective. To round-trip cleanly, the
// emitter MUST reverse that reshape:
//
//   - `[?let]`  : parsed as slots `:bind STRING_LIT :value EXPR :body EXPR`
//                 but the parser only accepts the surface
//                 `[?let $name = expr :in body]`. Emit the surface form.
//   - `[?modify]`: action slots have heterogeneous arities. Emit each
//                  action with its action-specific operand convention.
//   - `[?match]`: `:else` slots carry a placeholder bool that's invalid
//                 in re-parse position; suppress it.
fn emit_program_directive(mut b strings.Builder, d cx.ProgramDirective) {
	if d.name == 'let' {
		emit_let_directive(mut b, d)
		return
	}
	if d.name == 'modify' {
		emit_modify_directive(mut b, d)
		return
	}
	if d.name == 'eval' {
		emit_eval_directive(mut b, d)
		return
	}
	b.write_string('[?')
	b.write_string(d.name)
	for s in d.slots {
		emit_directive_slot(mut b, d.name, s)
	}
	b.write_string(']')
}

// emit_eval_directive emits `[?eval TREE [context MAP]? [opts MAP]?]` in the
// canonical clause-child surface (§6.4.4). The parse stores the leading TREE as
// a positional slot and context/opts as labeled slots; the generic emitter
// would write them as retired `:context`/`:opts` colon-slots, which fail to
// re-parse — so labeled slots reshape to `[label VALUE]` clause-children.
fn emit_eval_directive(mut b strings.Builder, d cx.ProgramDirective) {
	b.write_string('[?eval')
	for s in d.slots {
		b.write_string(' ')
		if s.kind == .labeled {
			b.write_string('[')
			b.write_string(s.label)
			b.write_string(' ')
			emit_program_node(mut b, s.value)
			b.write_string(']')
		} else {
			emit_program_node(mut b, s.value)
		}
	}
	b.write_string(']')
}

fn emit_directive_slot(mut b strings.Builder, directive_name string, s cx.ProgramSlot) {
	b.write_string(' ')
	if s.kind == .labeled {
		b.write_string(':')
		b.write_string(s.label)
		// `:else` on [?match] / [?modify] carries a placeholder bool the
		// parser inserts; suppress the operand on re-emit.
		if directive_name == 'match' && s.label == 'else' {
			return
		}
		b.write_string(' ')
		emit_program_node(mut b, s.value)
	} else {
		emit_program_node(mut b, s.value)
	}
}

// emit_let_directive emits `[?let]` in the canonical surface
// `[?let [= $name value] body]` (code.md §8.5). Two stored encodings are
// reshaped to this one surface: the legacy parse produced three labeled
// slots (`:bind STRING_LIT`, `:value EXPR`, `:body EXPR`); the clause-child
// parse stores positional slots (the `[= …]` binding clause(s) + body
// expr). The legacy `:label` colon surface was retired in the capstone.
fn emit_let_directive(mut b strings.Builder, d cx.ProgramDirective) {
	mut has_labeled := false
	for s in d.slots {
		if s.kind == .labeled {
			has_labeled = true
			break
		}
	}
	b.write_string('[?let')
	if has_labeled {
		mut bind_name := ''
		mut value_expr := ?cx.ProgramNode(none)
		mut body_expr := ?cx.ProgramNode(none)
		for s in d.slots {
			if s.kind != .labeled {
				continue
			}
			match s.label {
				'bind' {
					if s.value is cx.ProgramLiteral && (s.value as cx.ProgramLiteral).kind == .string_lit {
						bind_name = (s.value as cx.ProgramLiteral).str_val
					}
				}
				'value' { value_expr = s.value }
				'body'  { body_expr = s.value }
				else    {}
			}
		}
		b.write_string(' [= \$')
		b.write_string(bind_name)
		b.write_string(' ')
		if v := value_expr {
			emit_program_node(mut b, v)
		}
		b.write_string(']')
		if bd := body_expr {
			b.write_string(' ')
			emit_program_node(mut b, bd)
		}
	} else {
		// Clause-child encoding: positional `[= …]` binding clause(s) +
		// body expr, already in canonical shape — emit each bare.
		for s in d.slots {
			b.write_string(' ')
			emit_program_node(mut b, s.value)
		}
	}
	b.write_string(']')
}

// emit_modify_directive emits `[?modify]` in its surface form
// `[?modify DOC FOCUS_PATH ACTION+]` with each action as a clause-child
// `[label …]` (code.md §8.10). Action emit is heterogeneous per
// `parse_modify_action` in `parser.v`:
//
//   [delete]                  — no operand (parser stores placeholder bool)
//   [rename NAME]             — bareword (parser stores as string_lit)
//   [delete-attr NAME]        — bareword (parser stores as string_lit)
//   [set-attr NAME EXPR]      — bareword + expr (parser stores as sequence_lit)
//   [set …] / [using …] / etc — single expr
fn emit_modify_directive(mut b strings.Builder, d cx.ProgramDirective) {
	b.write_string('[?modify')
	for s in d.slots {
		b.write_string(' ')
		if s.kind == .positional {
			emit_program_node(mut b, s.value)
		} else {
			emit_modify_action(mut b, s)
		}
	}
	b.write_string(']')
}

fn emit_modify_action(mut b strings.Builder, s cx.ProgramSlot) {
	b.write_string('[')
	b.write_string(s.label)
	match s.label {
		'delete' {
			// No operand — placeholder bool suppressed.
		}
		'rename', 'delete-attr' {
			// Bareword name — parser stores as string_lit; emit unquoted.
			if s.value is cx.ProgramLiteral && (s.value as cx.ProgramLiteral).kind == .string_lit {
				b.write_string(' ')
				b.write_string((s.value as cx.ProgramLiteral).str_val)
			} else {
				b.write_string(' ')
				emit_program_node(mut b, s.value)
			}
		}
		'set-attr' {
			// Parser stores as sequence_lit(string_lit name, value_expr).
			// Emit as `NAME EXPR` (no parens, no commas).
			if s.value is cx.ProgramLiteral && (s.value as cx.ProgramLiteral).kind == .sequence_lit {
				lit := s.value as cx.ProgramLiteral
				if lit.items.len == 2 {
					name_item := lit.items[0]
					value_item := lit.items[1]
					b.write_string(' ')
					// Name is a bareword (string_lit) or a computed `[?name …]`
					// sub-form (§6.4.2) — emit the directive verbatim, never the
					// paren-sequence fallback (which the parser rejects).
					if name_item is cx.ProgramLiteral && (name_item as cx.ProgramLiteral).kind == .string_lit {
						b.write_string((name_item as cx.ProgramLiteral).str_val)
					} else {
						emit_program_node(mut b, name_item)
					}
					b.write_string(' ')
					emit_program_node(mut b, value_item)
					b.write_string(']')
					return
				}
			}
			// Fallback — emit verbatim (shouldn't happen with parser-produced AST).
			b.write_string(' ')
			emit_program_node(mut b, s.value)
		}
		else {
			// [set …], [using …], [append …], [prepend …],
			// [insert-before …], [insert-after …], [replace …]
			b.write_string(' ')
			emit_program_node(mut b, s.value)
		}
	}
	b.write_string(']')
}

// ── cx.ProgramForComp — for-comprehension per §7 ────────────────────────────────
//
// Emitted in the canonical clause-child surface (grammar [129],
// code.md §7): `[?for [in $x SRC] [where …] [= $y E] … [yield EXPR]]`.
// Clauses emit in source order; the yield clause emits last. The legacy
// `:label` colon surface was retired in the capstone.
fn emit_program_for_comp(mut b strings.Builder, f cx.ProgramForComp) {
	// outer-container heads.
	head := match f.outer_form {
		.sequence { '[?for' }
		.array    { '[?for-array' }
		.map      { '[?for-map' }
	}
	b.write_string(head)
	for c in f.clauses {
		b.write_string(' ')
		emit_for_clause_src(mut b, c)
	}
	// Yield clause-child: `[yield E]` / `[yield-array E]` / `[yield-map K V]`.
	yield_kw := match f.yield_form {
		.sequence { '[yield ' }
		.array    { '[yield-array ' }
		.map      { '[yield-map ' }
	}
	b.write_string(' ')
	b.write_string(yield_kw)
	emit_program_node(mut b, f.yield)
	if f.yield_form == .map {
		if val_expr := f.yield_value {
			b.write_string(' ')
			emit_program_node(mut b, val_expr)
		}
	}
	b.write_string(']') // close yield clause
	b.write_string(']') // close [?for]
}

// emit_for_clause_src emits one for-comp clause in the clause-child
// bracket surface (grammar [129a]-[129q]).
fn emit_for_clause_src(mut b strings.Builder, c cx.ProgramForClause) {
	match c.kind {
		.generator {
			// `[in $x SRC]` (explicit), `[in SRC]` (anonymous, $_), or
			// `[in PATTERN SRC]` (pattern-bind — c.expr carries the pattern).
			b.write_string('[in ')
			if pat := c.expr {
				emit_program_node(mut b, pat)
				b.write_string(' ')
				if src := c.source {
					emit_program_node(mut b, src)
				}
			} else if c.bind == '_' {
				if src := c.source {
					emit_program_node(mut b, src)
				}
			} else {
				b.write_string('\$')
				b.write_string(c.bind)
				b.write_string(' ')
				if src := c.source {
					emit_program_node(mut b, src)
				}
			}
			b.write_string(']')
		}
		.filter {
			b.write_string('[where ')
			if e := c.expr {
				emit_program_node(mut b, e)
			}
			b.write_string(']')
		}
		.binding {
			b.write_string('[= \$')
			b.write_string(c.bind)
			b.write_string(' ')
			if e := c.expr {
				emit_program_node(mut b, e)
			}
			b.write_string(']')
		}
		.order_by {
			b.write_string('[order-by ')
			if e := c.expr {
				emit_program_node(mut b, e)
			}
			if c.direction != '' {
				b.write_string(' ')
				b.write_string(c.direction)
			}
			b.write_string(']')
		}
		.group_by {
			b.write_string('[group-by ')
			if e := c.expr {
				emit_program_node(mut b, e)
			}
			b.write_string(']')
		}
		.limit {
			b.write_string('[limit ')
			if e := c.expr {
				emit_program_node(mut b, e)
			}
			b.write_string(']')
		}
		.par     { b.write_string('[par]') }
		.stream  { b.write_string('[stream]') }
		.ordered { b.write_string('[ordered]') }
		.take {
			b.write_string('[take ')
			if e := c.expr {
				emit_program_node(mut b, e)
			}
			b.write_string(']')
		}
		.drop {
			b.write_string('[drop ')
			if e := c.expr {
				emit_program_node(mut b, e)
			}
			b.write_string(']')
		}
		.takewhile {
			b.write_string('[takewhile ')
			if e := c.expr {
				emit_program_node(mut b, e)
			}
			b.write_string(']')
		}
		.dropwhile {
			b.write_string('[dropwhile ')
			if e := c.expr {
				emit_program_node(mut b, e)
			}
			b.write_string(']')
		}
	}
}

// ── cx.ProgramLiteral ──────────────────────────────────────────────────────────

fn emit_program_literal(mut b strings.Builder, l cx.ProgramLiteral) {
	match l.kind {
		.string_lit   { emit_quoted_string(mut b, l.str_val) }
		.int_lit      { b.write_string(l.int_val.str()) }
		.bigint_lit   { b.write_string(l.str_val) }
		.float_lit    { b.write_string(l.flt_val.str()) }
		.bool_lit     { b.write_string(l.bool_val.str()) }
		.duration_lit { b.write_string(l.dur_val) }
		.period_lit   { b.write_string(l.dur_val) }
		.date_lit, .datetime_lit { b.write_string(l.str_val) }
		.sequence_lit {
			b.write_string('(')
			for i, it in l.items {
				if i > 0 { b.write_string(', ') }
				emit_program_node(mut b, it)
			}
			b.write_string(')')
		}
		.array_lit {
			b.write_string('[')
			for i, it in l.items {
				if i > 0 { b.write_string(', ') }
				emit_program_node(mut b, it)
			}
			b.write_string(']')
		}
		.map_lit {
			b.write_string('{')
			for i in 0 .. l.items.len {
				if i > 0 { b.write_string(', ') }
				if i < l.keys.len {
					b.write_string(l.keys[i])
				}
				b.write_string(': ')
				emit_program_node(mut b, l.items[i])
			}
			b.write_string('}')
		}
		.cx_element {
			emit_cx_element_literal(mut b, l)
		}
		.block {
			// Multi-statement top-level block — emit each statement on
			// its own line. Round-trips through the parser's block-shape
			// recognition (multiple top-level statements).
			for i, it in l.items {
				if i > 0 { b.write_string('\n') }
				emit_program_node(mut b, it)
			}
		}
		.atom_lit {
			// Atom literal — surface `:NAME`.
			b.write_string(':')
			b.write_string(l.str_val)
		}
		.node_lit {
			// Embedded pure-DATA construct (`[#…#]` / `&…;` / `[!…]`). Re-emit
			// the verbatim span captured by the lexer so program source
			// round-trips identically.
			b.write_string(l.str_val)
		}
	}
}

// emit_cx_element_literal renders a `cx_element` cx.ProgramLiteral as
// `[name attr=val :label slot positional...]`.
fn emit_cx_element_literal(mut b strings.Builder, l cx.ProgramLiteral) {
	// Computed element name `[?element NAME-EXPR …]` (§6.4.2): the name lives
	// in name_expr (l.name is empty). Emit the directive form so it re-parses;
	// the body grammar (static attrs interleaved with items) is identical.
	if name_e := l.name_expr {
		b.write_string('[?element ')
		emit_program_node(mut b, name_e)
		for a in l.attrs {
			b.write_string(' ')
			b.write_string(a.name)
			b.write_string('=')
			emit_program_node(mut b, a.value)
		}
		for it in l.items {
			b.write_string(' ')
			emit_program_node(mut b, it)
		}
		b.write_string(']')
		return
	}
	b.write_string('[')
	b.write_string(l.name)
	// Attributes — element-construction attrs (name=expr).
	for a in l.attrs {
		b.write_string(' ')
		b.write_string(a.name)
		b.write_string('=')
		emit_program_node(mut b, a.value)
	}
	// Body items (positional). Slots come in the parallel `slots` list
	// for labeled `:label value` pairs.
	for it in l.items {
		b.write_string(' ')
		emit_program_node(mut b, it)
	}
	for s in l.slots {
		b.write_string(' :')
		b.write_string(s.label)
		b.write_string(' ')
		emit_program_node(mut b, s.value)
	}
	b.write_string(']')
}

// emit_quoted_string emits a string literal with quote-style chosen
// by preference. Mirrors `vcx/code/render.v::choose_render_quote`.
fn emit_quoted_string(mut b strings.Builder, s string) {
	has_double := s.contains('"')
	has_single := s.contains("'")
	if !has_double {
		b.write_string('"')
		b.write_string(s)
		b.write_string('"')
		return
	}
	if !has_single {
		b.write_string("'")
		b.write_string(s)
		b.write_string("'")
		return
	}
	if !s.contains('"""') {
		b.write_string('"""')
		b.write_string(s)
		b.write_string('"""')
		return
	}
	if !s.contains("'''") {
		b.write_string("'''")
		b.write_string(s)
		b.write_string("'''")
		return
	}
	// Pathological — degrade to double-quote.
	b.write_string('"')
	b.write_string(s)
	b.write_string('"')
}

// ── cx.ProgramPathExpr — CXPath value-kind ─────────────────────────────────────
//
// Adopts the canonical-form rules of `vcx/cx/path_renderer.v` (Phase
// 2.9) adapted to `cx.ProgramPathExpr` shape. The leading discriminator
// is rendered as `/` (absolute), `//` (descendant), or empty
// (relative). Each step renders as `(axis::)?nodetest(predicate)*`
// with the default axis omitted per §2.12.3.
fn emit_program_path_expr(mut b strings.Builder, p cx.ProgramPathExpr) {
	match p.leading {
		.absolute   { b.write_string('/') }
		.descendant { b.write_string('//') }
		.relative   {}
	}
	for i, s in p.steps {
		if i > 0 {
			b.write_string('/')
		}
		emit_path_step(mut b, s)
	}
}

fn emit_path_step(mut b strings.Builder, s cx.ProgramPathExprStep) {
	// Axis prefix. `child` is the default and omitted unless
	// axis_explicit is set. `attribute` uses the `@` sugar.
	// All other axes emit `name::`.
	if s.axis == .attribute && !s.axis_explicit {
		b.write_string('@')
	} else if s.axis_explicit || (s.axis != .child && s.axis != .descendant_or_self) {
		b.write_string(path_axis_emit_name(s.axis))
		b.write_string('::')
	}
	// NodeTest per ns_kind.
	match s.ns_kind {
		.none {
			b.write_string(s.name)
		}
		.any_ns {
			b.write_string('*:')
			b.write_string(s.name)
		}
		.prefix_any_local {
			b.write_string(s.ns_prefix)
			b.write_string(':*')
		}
		.prefix_local {
			b.write_string(s.ns_prefix)
			b.write_string(':')
			b.write_string(s.name)
		}
	}
	for pred in s.predicates {
		emit_path_predicate(mut b, pred)
	}
}

fn path_axis_emit_name(a cx.ProgramPathAxis) string {
	return match a {
		.child              { 'child' }
		.descendant         { 'descendant' }
		.descendant_or_self { 'descendant-or-self' }
		.parent             { 'parent' }
		.ancestor           { 'ancestor' }
		.ancestor_or_self   { 'ancestor-or-self' }
		.following_sibling  { 'following-sibling' }
		.preceding_sibling  { 'preceding-sibling' }
		.following          { 'following' }
		.preceding          { 'preceding' }
		.self_axis          { 'self' }
		.attribute          { 'attribute' }
	}
}

fn emit_path_predicate(mut b strings.Builder, p cx.ProgramPathPredicate) {
	b.write_string('[')
	match p.kind {
		.position {
			b.write_string(p.int_index.str())
		}
		.attr_test {
			emit_pattern_attr(mut b, cx.ProgramPatternAttr{
				kind:  p.attr_kind
				name:  p.attr_name
				op:    p.attr_op
				value: p.attr_value
			})
		}
		.expr {
			// General PredicateExpr body. Emit the
			// body via the canonical program-emit path. The
			// __pred_last sugar marker round-trips as `last()`.
			body := p.body or {
				b.write_string('?')
				b.write_string(']')
				return
			}
			if body is cx.ProgramCall && (body as cx.ProgramCall).name == '__pred_last' {
				b.write_string('last()')
			} else {
				emit_program_node(mut b, body)
			}
		}
	}
	b.write_string(']')
}

// emit_program_slice_access parser-only stub.
//
// Emits the literal `$binding[axes]` source. Per-axis shape:
//   .single → `EXPR`
//   .range  → `START?:STOP?(:STEP)?`  (any of start / stop / step may be
//                                       absent)
//   .full   → `*`
// Round-trip fidelity at this milestone is "good enough to parse back";
// canonical-render pinning lands with W5c when the evaluator surface is
// in place.
// emit_program_slice_literal first-class Slice literal.
//
// Emits a bare `[axes]` source (no preceding $binding). Round-trips to
// the same surface form: a standalone bracket whose body has slice shape
// (leading `:`/`::`/`*`, or top-level `:` between exprs).
fn emit_program_slice_literal(mut b strings.Builder, s cx.ProgramSliceLiteral) {
	b.write_string('[')
	for i, ax in s.axes {
		if i > 0 {
			b.write_string(', ')
		}
		match ax.kind {
			.single {
				if start := ax.start {
					emit_program_node(mut b, start)
				}
			}
			.range {
				if start := ax.start {
					emit_program_node(mut b, start)
				}
				b.write_string(':')
				if stop := ax.stop {
					emit_program_node(mut b, stop)
				}
				if step := ax.step {
					b.write_string(':')
					emit_program_node(mut b, step)
				}
			}
			.full {
				b.write_string('*')
			}
		}
	}
	b.write_string(']')
}

fn emit_program_slice_access(mut b strings.Builder, s cx.ProgramSliceAccess) {
	emit_program_binding(mut b, s.binding)
	b.write_string('[')
	for i, ax in s.axes {
		if i > 0 {
			b.write_string(', ')
		}
		match ax.kind {
			.single {
				if start := ax.start {
					emit_program_node(mut b, start)
				}
			}
			.range {
				if start := ax.start {
					emit_program_node(mut b, start)
				}
				b.write_string(':')
				if stop := ax.stop {
					emit_program_node(mut b, stop)
				}
				if step := ax.step {
					b.write_string(':')
					emit_program_node(mut b, step)
				}
			}
			.full {
				b.write_string('*')
			}
		}
	}
	b.write_string(']')
}
