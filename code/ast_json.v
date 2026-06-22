// ast_json.v — emit the parsed program AST as JSON.
//
// `program_ast_json(src)` parses the source via `code.parse` and
// walks the resulting cx.ProgramNode tree, emitting a JSON document the
// playground tree-view can render.
//
// Shape conventions — each node becomes either:
//   - a single-key object `{name: body}` where `name` describes the
//     node (directive name prefixed `?`, pattern head as-is, slot
//     labels prefixed `:`, call as `name(…)`); body is an array for
//     ordered children, a scalar for atoms;
//   - a scalar string for bindings (`$x`, `$x/path`) and wildcards;
//   - a typed scalar (int / float / bool) for literals.
//
// This mirrors the universal data-projection JSON the tree-view
// already consumes for evaluated values, so the same component
// renders both source-AST and output-value trees with no special
// casing.

module code
import cx

import strings

// program_ast_json parses `src` and returns the program AST as JSON
// (UTF-8, indented with two spaces). Top-level multi-statement
// programs emit a list of per-statement objects.
pub fn program_ast_json(src string) !string {
	if src.trim_space() == '' {
		return '{}'
	}
	prog := cx.parse_program(src) or {
		return error('program_ast_json: parse: ${err.msg()}')
	}
	mut sb := strings.new_builder(512)
	emit_node(prog.body, mut sb, 0)
	return sb.str()
}

fn emit_indent(mut sb strings.Builder, depth int) {
	for _ in 0 .. depth {
		sb.write_string('  ')
	}
}

fn emit_node(n cx.ProgramNode, mut sb strings.Builder, depth int) {
	match n {
		cx.Program {
			emit_node(n.body, mut sb, depth)
		}
		cx.ProgramBinding {
			sb.write_string('"')
			sb.write_string(escape_string(binding_label(n)))
			sb.write_string('"')
		}
		cx.ProgramWildcard {
			if n.deep { sb.write_string('"**"') } else { sb.write_string('"*"') }
		}
		cx.ProgramCall {
			emit_object_start(mut sb, '${n.name}()', depth)
			for i, a in n.args {
				emit_array_item_prefix(mut sb, i, depth + 1)
				emit_node(a, mut sb, depth + 1)
			}
			emit_array_end(mut sb, depth, n.args.len)
			emit_object_end(mut sb, depth)
		}
		cx.ProgramPattern {
			emit_pattern(n, mut sb, depth)
		}
		cx.ProgramDirective {
			emit_directive(n, mut sb, depth)
		}
		cx.ProgramForComp {
			emit_for_comp(n, mut sb, depth)
		}
		cx.ProgramLiteral {
			emit_literal(n, mut sb, depth)
		}
		cx.ProgramPathExpr {
			// CXPath value-kind — serialize as the terse
			// canonical surface form, matching D6's round-trip rule.
			sb.write_string('"')
			sb.write_string(escape_string(path_expr_label(n)))
			sb.write_string('"')
		}
		cx.ProgramSliceAccess {
			// parser-only: emit a string placeholder noting
			// the deferral. The full structural JSON shape lands in W5c.
			sb.write_string('"<slice-pending>"')
		}
		cx.ProgramSliceLiteral {
			// first-class Slice value. Structural JSON
			// shape is informational only (round-trip lives in
			// program_emit.v); placeholder here matches the slice-access
			// arm above.
			sb.write_string('"<slice-literal>"')
		}
	}
}

// path_expr_label renders a cx.ProgramPathExpr to its canonical terse
// surface (`//step/step/...`). Per this is the round-trip
// form — the same string the parser accepts.
// Chunk-2: emits explicit `axis::` prefix only when the source used the
// explicit form (axis_explicit=true); default-axis steps (descendant-or-
// self at the head, child elsewhere) round-trip as bare steps. Predicates
// append directly after the NodeTest as `[…]` in source order.
fn path_expr_label(p cx.ProgramPathExpr) string {
	mut s := match p.leading {
		.descendant { '//' }
		.absolute   { '/' }
		.relative   { '' }
	}
	for i, step in p.steps {
		if i > 0 {
			s += '/'
		}
		if step.axis_explicit {
			s += cx.axis_to_name(step.axis) + '::'
		}
		// NodeTest surface form per grammar [131b]. The namespace-wildcard
		// forms re-assemble the source surface (`*:local`, `prefix:*`,
		// `prefix:local`) from the (name, ns_kind, ns_prefix) triple.
		match step.ns_kind {
			.none             { s += step.name }
			.any_ns           { s += '*:' + step.name }
			.prefix_any_local { s += step.ns_prefix + ':*' }
			.prefix_local     { s += step.ns_prefix + ':' + step.name }
		}
		for pred in step.predicates {
			s += '[' + path_predicate_label(pred) + ']'
		}
	}
	return s
}

// path_predicate_label renders the body of a single `[…]` predicate in
// canonical terse form. The brackets are added by the caller.
fn path_predicate_label(p cx.ProgramPathPredicate) string {
	match p.kind {
		.position {
			return p.int_index.str()
		}
		.attr_test {
			return path_predicate_attr_label(p)
		}
		.expr {
			// General PredicateExpr — emit a placeholder; full
			// round-trip of arbitrary body expressions is canonical-
			// emit territory (program_emit.v / render.v). The label
			// surface is informational (diagrams, error messages).
			return 'expr'
		}
	}
}

// path_predicate_attr_label renders the attribute-test body of a
// predicate. Shape mirrors the cx.ProgramPatternAttr label form used in
// pattern emit so the two surface forms read identically.
fn path_predicate_attr_label(p cx.ProgramPathPredicate) string {
	match p.attr_kind {
		.existence { return '@' + p.attr_name }
		.absence   { return '@!' + p.attr_name }
		.equality, .comparison {
			val := p.attr_value or { return '@' + p.attr_name }
			return '@' + p.attr_name + p.attr_op + node_label(val)
		}
		.type_test {
			// Path predicates never carry a value-kind test; the branch
			// exists for exhaustiveness over the shared attr-kind enum.
			return '@' + p.attr_name
		}
	}
}

// node_label renders a literal node value to its source-equivalent
// string for predicate round-trip. Only the literal kinds reachable from
// a predicate value position are handled — strings get quoted, numbers
// and bools emit verbatim.
fn node_label(n cx.ProgramNode) string {
	if n is cx.ProgramLiteral {
		match n.kind {
			.string_lit { return '"' + n.str_val + '"' }
			.int_lit    { return n.int_val.str() }
			.float_lit  { return n.flt_val.str() }
			.bool_lit   { return if n.bool_val { 'true' } else { 'false' } }
			else        { return n.str_val }
		}
	}
	return '?'
}

fn binding_label(b cx.ProgramBinding) string {
	mut s := '$' + b.name
	for step in b.path {
		match step.kind {
			.attr               { s += '@' + step.name }
			.child              { s += '/' + step.name }
			.member             { s += '.' + step.name }
			.wildcard_children  { s += '/*' }
			.descendant         { s += '//' + step.name }
			.descendant_wildcard { s += '//*' }
			.parent             { s += '/..' }
		}
		for pred in step.predicates {
			s += '[' + path_predicate_label(pred) + ']'
		}
	}
	return s
}

fn emit_pattern(p cx.ProgramPattern, mut sb strings.Builder, depth int) {
	mut label := match p.head.kind {
		.named       { p.head.value }
		.wildcard    { '*' }
		.deep        { '**' }
		.type_guard  { ':' + p.head.value }
	}
	if p.head.bind != '' {
		label += '\$' + p.head.bind
	}
	// children = attrs (rendered as @attr entries) + body items
	mut total := p.attrs.len + p.body.len
	if total == 0 {
		emit_object_start(mut sb, label, depth)
		emit_array_end(mut sb, depth, 0)
		emit_object_end(mut sb, depth)
		return
	}
	emit_object_start(mut sb, label, depth)
	mut i := 0
	for a in p.attrs {
		emit_array_item_prefix(mut sb, i, depth + 1)
		emit_attr(a, mut sb, depth + 1)
		i++
	}
	for b in p.body {
		emit_array_item_prefix(mut sb, i, depth + 1)
		emit_node(b, mut sb, depth + 1)
		i++
	}
	emit_array_end(mut sb, depth, total)
	emit_object_end(mut sb, depth)
}

fn emit_attr(a cx.ProgramPatternAttr, mut sb strings.Builder, depth int) {
	mut key := '@'
	if a.kind == .absence { key += '!' }
	key += a.name
	if a.op != '' { key += ' ' + a.op }
	v := a.value or {
		sb.write_string('{ "')
		sb.write_string(escape_string(key))
		sb.write_string('": "" }')
		return
	}
	emit_object_start(mut sb, key, depth)
	emit_array_item_prefix(mut sb, 0, depth + 1)
	emit_node(v, mut sb, depth + 1)
	emit_array_end(mut sb, depth, 1)
	emit_object_end(mut sb, depth)
}

fn emit_directive(d cx.ProgramDirective, mut sb strings.Builder, depth int) {
	emit_object_start(mut sb, '?' + d.name, depth)
	for i, slot in d.slots {
		emit_array_item_prefix(mut sb, i, depth + 1)
		emit_slot(slot, mut sb, depth + 1)
	}
	emit_array_end(mut sb, depth, d.slots.len)
	emit_object_end(mut sb, depth)
}

fn emit_slot(s cx.ProgramSlot, mut sb strings.Builder, depth int) {
	if s.kind == .positional {
		emit_node(s.value, mut sb, depth)
		return
	}
	emit_object_start(mut sb, ':' + s.label, depth)
	emit_array_item_prefix(mut sb, 0, depth + 1)
	emit_node(s.value, mut sb, depth + 1)
	emit_array_end(mut sb, depth, 1)
	emit_object_end(mut sb, depth)
}

fn emit_for_comp(f cx.ProgramForComp, mut sb strings.Builder, depth int) {
	// emit head per outer-container form and use the
	// matching yield-form label.
	head := match f.outer_form {
		.sequence { '?for' }
		.array    { '?for-array' }
		.map      { '?for-map' }
	}
	emit_object_start(mut sb, head, depth)
	mut idx := 0
	for c in f.clauses {
		emit_array_item_prefix(mut sb, idx, depth + 1)
		emit_for_clause(c, mut sb, depth + 1)
		idx++
	}
	emit_array_item_prefix(mut sb, idx, depth + 1)
	yield_label := match f.yield_form {
		.sequence { ':yield' }
		.array    { ':yield-array' }
		.map      { ':yield-map' }
	}
	emit_object_start(mut sb, yield_label, depth + 1)
	emit_array_item_prefix(mut sb, 0, depth + 2)
	emit_node(f.yield, mut sb, depth + 2)
	mut yield_items := 1
	if f.yield_form == .map {
		if val_expr := f.yield_value {
			emit_array_item_prefix(mut sb, 1, depth + 2)
			emit_node(val_expr, mut sb, depth + 2)
			yield_items = 2
		}
	}
	emit_array_end(mut sb, depth + 1, yield_items)
	emit_object_end(mut sb, depth + 1)
	idx++
	emit_array_end(mut sb, depth, idx)
	emit_object_end(mut sb, depth)
}

fn emit_for_clause(c cx.ProgramForClause, mut sb strings.Builder, depth int) {
	mut label := match c.kind {
		.generator { ':in \$' + c.bind }
		.filter    { ':where' }
		.binding   { ':let \$' + c.bind }
		.order_by  { ':order-by' + (if c.direction != '' { ' ' + c.direction } else { '' }) }
		.group_by  { ':group-by' }
		.limit     { ':limit' }
		.par       { ':par' }
		.stream    { ':stream' }
		.ordered   { ':ordered' }
		.take      { ':take' }
		.drop      { ':drop' }
		.takewhile { ':takewhile' }
		.dropwhile { ':dropwhile' }
	}
	// Pick the relevant payload — generator uses source, others use expr
	payload := if e := c.source { ?cx.ProgramNode(e) } else if e := c.expr { ?cx.ProgramNode(e) } else { ?cx.ProgramNode(none) }
	v := payload or {
		sb.write_string('"')
		sb.write_string(escape_string(label))
		sb.write_string('"')
		return
	}
	emit_object_start(mut sb, label, depth)
	emit_array_item_prefix(mut sb, 0, depth + 1)
	emit_node(v, mut sb, depth + 1)
	emit_array_end(mut sb, depth, 1)
	emit_object_end(mut sb, depth)
}

fn emit_literal(l cx.ProgramLiteral, mut sb strings.Builder, depth int) {
	match l.kind {
		.string_lit {
			sb.write_string('"')
			sb.write_string(escape_string(l.str_val))
			sb.write_string('"')
		}
		.int_lit {
			sb.write_string(l.int_val.str())
		}
		.bigint_lit {
			// over-i64 integer: emit the verbatim digit string (unquoted —
			// it is numeric, not a string literal).
			sb.write_string(l.str_val)
		}
		.float_lit {
			sb.write_string(l.flt_val.str())
		}
		.bool_lit {
			sb.write_string(if l.bool_val { 'true' } else { 'false' })
		}
		.duration_lit, .period_lit {
			sb.write_string('"')
			sb.write_string(escape_string(l.dur_val))
			sb.write_string('"')
		}
		.date_lit, .datetime_lit {
			sb.write_string('"')
			sb.write_string(escape_string(l.str_val))
			sb.write_string('"')
		}
		.sequence_lit, .array_lit {
			// raw JSON array of items
			if l.items.len == 0 {
				sb.write_string('[]')
				return
			}
			sb.write_string('[\n')
			for i, it in l.items {
				emit_indent(mut sb, depth + 1)
				emit_node(it, mut sb, depth + 1)
				if i < l.items.len - 1 { sb.write_string(',\n') } else { sb.write_string('\n') }
			}
			emit_indent(mut sb, depth)
			sb.write_string(']')
		}
		.map_lit {
			if l.keys.len == 0 {
				sb.write_string('{}')
				return
			}
			sb.write_string('{\n')
			for i, k in l.keys {
				emit_indent(mut sb, depth + 1)
				sb.write_string('"')
				sb.write_string(escape_string(k))
				sb.write_string('": ')
				emit_node(l.items[i], mut sb, depth + 1)
				if i < l.keys.len - 1 { sb.write_string(',\n') } else { sb.write_string('\n') }
			}
			emit_indent(mut sb, depth)
			sb.write_string('}')
		}
		.cx_element {
			total := l.items.len + l.slots.len
			emit_object_start(mut sb, l.name, depth)
			mut idx := 0
			for it in l.items {
				emit_array_item_prefix(mut sb, idx, depth + 1)
				emit_node(it, mut sb, depth + 1)
				idx++
			}
			for s in l.slots {
				emit_array_item_prefix(mut sb, idx, depth + 1)
				emit_slot(s, mut sb, depth + 1)
				idx++
			}
			emit_array_end(mut sb, depth, total)
			emit_object_end(mut sb, depth)
		}
		.block {
			// multi-statement program: emit as a top-level list
			if l.items.len == 0 {
				sb.write_string('[]')
				return
			}
			sb.write_string('[\n')
			for i, it in l.items {
				emit_indent(mut sb, depth + 1)
				emit_node(it, mut sb, depth + 1)
				if i < l.items.len - 1 { sb.write_string(',\n') } else { sb.write_string('\n') }
			}
			emit_indent(mut sb, depth)
			sb.write_string(']')
		}
		.atom_lit {
			// atom literal — emit as a tagged JSON
			// object so the kind is preserved alongside the name. Distinct
			// from `.string_lit` (which emits a bare JSON string); atoms
			// carry the discriminator at the AST surface so downstream
			// tooling can roundtrip and compare atom-vs-string distinctly.
			sb.write_string('{"kind":"atom","name":"')
			sb.write_string(escape_string(l.str_val))
			sb.write_string('"}')
		}
		.node_lit {
			// Embedded pure-DATA construct (`[#…#]` / `&…;` / `[!…]`) — tagged
			// object carrying the verbatim span source.
			sb.write_string('{"kind":"node_lit","source":"')
			sb.write_string(escape_string(l.str_val))
			sb.write_string('"}')
		}
	}
}

// ── Low-level emit helpers ────────────────────────────────────────

fn emit_object_start(mut sb strings.Builder, key string, depth int) {
	sb.write_string('{\n')
	emit_indent(mut sb, depth + 1)
	sb.write_string('"')
	sb.write_string(escape_string(key))
	sb.write_string('": [')
}

fn emit_array_item_prefix(mut sb strings.Builder, i int, depth int) {
	if i > 0 { sb.write_string(',') }
	sb.write_string('\n')
	emit_indent(mut sb, depth)
}

fn emit_array_end(mut sb strings.Builder, depth int, n int) {
	if n > 0 {
		sb.write_string('\n')
		emit_indent(mut sb, depth + 1)
	}
	sb.write_string(']')
}

fn emit_object_end(mut sb strings.Builder, depth int) {
	sb.write_string('\n')
	emit_indent(mut sb, depth)
	sb.write_string('}')
}

fn escape_string(s string) string {
	mut out := strings.new_builder(s.len + 8)
	for c in s {
		match c {
			`"`    { out.write_string('\\"') }
			`\\`   { out.write_string('\\\\') }
			`\n`   { out.write_string('\\n') }
			`\r`   { out.write_string('\\r') }
			`\t`   { out.write_string('\\t') }
			else {
				if c < 0x20 {
					out.write_string('\\u00${c:02x}')
				} else {
					out.write_u8(c)
				}
			}
		}
	}
	return out.str()
}
