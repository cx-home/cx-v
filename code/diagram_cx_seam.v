@[has_globals]
module code

import cx
import sync

// diagram_cx_seam.v — the wave-1 engine seam for the cx-stdlib/diagram
// renderer (#758, RULED DR-1…DR-11 2026-08-20; DR-7a + mini-ruling
// DRW1-1, ledger/rulings_2026_08_20_diagram_renderer.md).
//
// The renderer itself is a CX program (spec/03-approved/std-lib/
// diagram.md; code.md §10.1.1's sentence, now true for the Mermaid
// target). This seam is the INVOCATION half only — nothing here
// produces a byte of diagram text:
//
//   1. lower the parsed program to its program-XML structural image
//      (spec/ast.md §4 projection — the bijective, structure-complete
//      image; DRW1-1 rules it as the renderer ingress, since the E1
//      quote-image collapses for-comp/call/pattern nodes to the
//      <cx:expr> source hatch the pure renderer must not re-parse),
//   2. materialize that image as a CXDM data tree (engine-side XML
//      parse of the codec's own emission — no user-facing parse
//      surface, per DR-7a's "no new public parse surface"),
//   3. evaluate the bundled module through an [?eval]-context-style
//      driver: fresh env, injected `$program` / `$source` / `$detail`
//      (/ `$rendered`) bindings, `[?lib 'cx-stdlib/diagram']`, one
//      call — the L99 invocation pattern,
//   4. map an `[err code=… message=…]` result value to the EvalError
//      shape the render_diagram callers already consume.

// diagram_program_image lowers a parsed program to the injected
// program-as-data tree (step 1+2 above). The tree is BUILT DIRECTLY —
// tag-for-tag the program_to_xml image — rather than materialized by
// round-tripping the XML text through the XML reader: the reader's
// cx:* typed-scalar carry ABSORBS <cx:int>/<cx:bool> children into
// typed text content (found live — a `[?retry max=3 …]` image lost its
// <cx:max> wrapper's child), so the parse hop does not reproduce the
// §4 projection node-for-node. Consult finding C10 in the ledger.
fn diagram_program_image(prog cx.Program) !cx.Node {
	return diagram_lower(cx.ProgramNode(prog.body))
}

// ── the direct §4-image lift (structure mirrors program_xml.v emit) ──

// The #898 / DRW3-9 err-literal rename (RULED: ISW-1). A source element
// named `err` lifts under `dgi_err_literal_tag` and carries its source
// name on `dgi_renamed_from_attr`; consumers that render a node's source
// name read that attribute in preference to the tag. See dgi_element for
// why the tag is not `cx:`-prefixed and why the carrier is an attribute.
const dgi_err_literal_tag = 'cx-err-literal'
const dgi_renamed_from_attr = 'cx-renamed-from'

fn dgi_el(name string, kids []cx.Node) cx.Node {
	return cx.Node(cx.Element{ name: name, items: kids })
}

fn dgi_el_attrs(name string, attrs []cx.Attribute, kids []cx.Node) cx.Node {
	return cx.Node(cx.Element{ name: name, attrs: attrs, items: kids })
}

fn dgi_text(name string, text string) cx.Node {
	mut kids := []cx.Node{}
	kids << cx.Node(cx.TextNode{ value: text })
	return dgi_el(name, kids)
}

fn dgi_attr(name string, val string) cx.Attribute {
	return cx.Attribute{ name: name, value: cx.ScalarValue(val) }
}

// dgi_escape_hatch — the <cx:expr> source-text hatch (PathExpr,
// dynamic element names, operator-with-attrs), exactly the cases
// emit_px_escape hatches.
fn dgi_escape_hatch(node cx.ProgramNode) cx.Node {
	return dgi_text('cx:expr', program_node_to_source(node))
}

fn diagram_lower(node cx.ProgramNode) cx.Node {
	match node {
		cx.Program { return diagram_lower(node.body) }
		cx.ProgramLiteral { return dgi_literal(node) }
		cx.ProgramBinding { return dgi_binding(node) }
		cx.ProgramCall { return dgi_call(node) }
		cx.ProgramDirective { return dgi_directive(node) }
		cx.ProgramWildcard {
			if node.deep {
				mut attrs := []cx.Attribute{}
				attrs << dgi_attr('deep', 'true')
				return dgi_el_attrs('cx:wildcard', attrs, []cx.Node{})
			}
			return dgi_el('cx:wildcard', []cx.Node{})
		}
		cx.ProgramSliceLiteral {
			mut kids := []cx.Node{}
			for ax in node.axes {
				kids << dgi_axis(ax)
			}
			return dgi_el('cx:slice', kids)
		}
		cx.ProgramSliceAccess {
			mut kids := []cx.Node{}
			kids << dgi_binding(node.binding)
			for ax in node.axes {
				kids << dgi_axis(ax)
			}
			return dgi_el('cx:slice-access', kids)
		}
		cx.ProgramForComp { return dgi_for_comp(node) }
		cx.ProgramPattern { return dgi_pattern(node) }
		else { return dgi_escape_hatch(node) }
	}
}

fn dgi_axis(ax cx.SliceAxis) cx.Node {
	kind_name := match ax.kind {
		.single { 'single' }
		.range { 'range' }
		.full { 'full' }
	}
	mut attrs := []cx.Attribute{}
	attrs << dgi_attr('kind', kind_name)
	mut kids := []cx.Node{}
	if ax.kind != .full {
		if start := ax.start {
			mut sv := []cx.Node{}
			sv << diagram_lower(start)
			kids << dgi_el('cx:start', sv)
		}
		if stop := ax.stop {
			mut sv := []cx.Node{}
			sv << diagram_lower(stop)
			kids << dgi_el('cx:stop', sv)
		}
		if step := ax.step {
			mut sv := []cx.Node{}
			sv << diagram_lower(step)
			kids << dgi_el('cx:step-by', sv)
		}
	}
	return dgi_el_attrs('cx:axis', attrs, kids)
}

fn dgi_literal(n cx.ProgramLiteral) cx.Node {
	match n.kind {
		.int_lit { return dgi_text('cx:int', '${n.int_val}') }
		.bigint_lit { return dgi_text('cx:bigint', n.str_val) }
		.decimal_lit { return dgi_text('cx:decimal', n.str_val) }
		.float_lit { return dgi_text('cx:float', '${n.flt_val}') }
		.bool_lit { return dgi_text('cx:bool', '${n.bool_val}') }
		.string_lit { return dgi_text('cx:str', n.str_val) }
		.atom_lit { return dgi_text('cx:atom', n.str_val) }
		.duration_lit { return dgi_text('cx:dur', n.dur_val) }
		.period_lit { return dgi_text('cx:period', n.dur_val) }
		.date_lit { return dgi_text('cx:date', n.str_val) }
		.datetime_lit { return dgi_text('cx:datetime', n.str_val) }
		.cx_element { return dgi_element(n) }
		.sequence_lit { return dgi_items_wrapper('cx:seq', n.items) }
		.array_lit { return dgi_items_wrapper('cx:arr', n.items) }
		.map_lit { return dgi_map(n) }
		.block { return dgi_items_wrapper('cx:block', n.items) }
		.node_lit {
			// RULED: TI-1 (#914, ledger/rulings_2026_08_21_table_image.md).
			// The DATA↔PROGRAM seam ALREADY parsed this construct — the
			// program reader has no production for it, so it hands the
			// verbatim span to the data reader and carries the result on
			// `.node` (program_parser.v: the `.data_span` arm for
			// `[#…#]` / `&…;` / `[!…]`, reparse_table_element_as_node for
			// `[table[…]]` elements, parse_cx_config_directive for
			// `[?cx …]`, and the glued `::T` number ascription). Lifting
			// `str_val` DISCARDED that parse: the image said `cx:data`
			// with the source text inside, so a table-carrying document
			// drew blank in every lane (an empty erDiagram, the `<lit>`
			// envelope, an empty svg canvas) and the ascription site —
			// which sets no str_val at all — lifted an EMPTY element.
			// The program reading of these constructs IS the data
			// reading (the seam's own words), so the image says the same
			// thing: the DATA lift, structure and all. The text hatch
			// remains for a `node_lit` carrying no node.
			if node := n.node {
				return dgi_data_node(node)
			}
			return dgi_text('cx:data', n.str_val)
		}
	}
}

fn dgi_element(n cx.ProgramLiteral) cx.Node {
	if n.name_expr != none || n.name == '' {
		return dgi_escape_hatch(cx.ProgramNode(n))
	}
	if op_name := operator_xml_names[n.name] {
		if n.attrs.len > 0 || n.slots.len > 0 {
			return dgi_escape_hatch(cx.ProgramNode(n))
		}
		mut kids := []cx.Node{}
		for it in n.items {
			kids << diagram_lower(it)
		}
		mut attrs := []cx.Attribute{}
		attrs << dgi_attr('name', op_name)
		return dgi_el_attrs('cx:op', attrs, kids)
	}
	if !px_is_xml_name(n.name) {
		return dgi_escape_hatch(cx.ProgramNode(n))
	}
	mut kids := []cx.Node{}
	for a in n.attrs {
		mut av := []cx.Node{}
		av << diagram_lower(a.value)
		mut aattrs := []cx.Attribute{}
		aattrs << dgi_attr('name', a.name)
		if a.data_type != '' {
			aattrs << dgi_attr('type', a.data_type)
		}
		kids << dgi_el_attrs('cx:attr', aattrs, av)
	}
	for it in n.items {
		kids << diagram_lower(it)
	}
	for s in n.slots {
		mut sv := []cx.Node{}
		sv << diagram_lower(s.value)
		mut sattrs := []cx.Attribute{}
		sattrs << dgi_attr('label', s.label)
		kids << dgi_el_attrs('cx:slot', sattrs, sv)
	}
	if n.name == 'err' {
		// #898 / DRW3-9, RULED: ISW-1 — the image RENAMES a source element
		// named `err`.
		//
		// `is_err_value` is `name == 'err'`, so an image element named `err`
		// IS an error value to the evaluator. A pure-CX consumer of the image
		// cannot hand that node to a def or reach it through a dynamic-child
		// position without the err propagating railway-style instead of being
		// rendered — measured: `[?worker name="w" [err code="x"]]` refused the
		// whole render where the V emitter wrote `Note over w : [err]`, and
		// `[?select [case [timeout 50ms] [err code="timeout"]]]` silently
		// dropped the case body.
		//
		// This is an IMAGE-CONTRACT defect, not a renderer defect: the image
		// is engine-built, and no amount of care in a consumer can make an
		// error value stop being one. Fixing it consumer-side would mean a
		// carrier convention on every node handoff (~40 defs in the diagram
		// module alone) that no gate could enforce — and every future consumer
		// of an injected image would have to keep it too. So the rename lives
		// here, in the one place that builds the image.
		//
		// The tag is deliberately NOT `cx:`-prefixed: in this projection the
		// `cx:` locals are the §4 VALUE tags, and consumers classify on that
		// prefix. An `err` element is an ordinary element literal and must
		// keep behaving like one in every walk; only its NAME is unusable.
		// The display name rides an image-level ATTRIBUTE instead, which a
		// source element can never forge — a source element's own attributes
		// become `cx:attr` CHILDREN in this projection, so the lifted element
		// carries no attributes of its own.
		mut attrs := []cx.Attribute{}
		attrs << dgi_attr(dgi_renamed_from_attr, n.name)
		return dgi_el_attrs(dgi_err_literal_tag, attrs, kids)
	}
	return dgi_el(n.name, kids)
}

fn dgi_items_wrapper(wrapper string, items []cx.ProgramNode) cx.Node {
	mut kids := []cx.Node{}
	for it in items {
		mut iv := []cx.Node{}
		iv << diagram_lower(it)
		kids << dgi_el('item', iv)
	}
	return dgi_el(wrapper, kids)
}

fn dgi_map(n cx.ProgramLiteral) cx.Node {
	mut kids := []cx.Node{}
	for i in 0 .. n.items.len {
		key := if i < n.keys.len { n.keys[i] } else { '' }
		mut eattrs := []cx.Attribute{}
		eattrs << dgi_attr('key', key)
		// RULED: MSS-4 (#917): a declaration-only entry carries its kind
		// and NO value child — the image must say declared, never null.
		if i < n.decl_kinds.len && n.decl_kinds[i] != '' {
			eattrs << dgi_attr('decl', n.decl_kinds[i])
			kids << dgi_el_attrs('entry', eattrs, []cx.Node{})
			continue
		}
		mut ev := []cx.Node{}
		ev << diagram_lower(n.items[i])
		kids << dgi_el_attrs('entry', eattrs, ev)
	}
	return dgi_el('cx:map', kids)
}

// ── the D910-1 DATA lift (#910) ───────────────────────────────────────
// diagram_data_image lifts a DATA document to the same injected image the
// program lift produces, so the ingress can serve documents the PROGRAM
// reading refuses but the DATA reading accepts (bare-prose bodies, spaced
// annotations — the run surface's own fallback class, code.md §1.3).
// Comments are presentation and do not lift; a document with no lifting
// root returns none and the caller keeps its refusal.
fn diagram_data_image(doc cx.Document) ?cx.Node {
	mut roots := []cx.Node{}
	for el in doc.elements {
		if el is cx.CommentNode {
			continue
		}
		roots << dgi_data_node(el)
	}
	if roots.len == 0 {
		return none
	}
	if roots.len == 1 {
		return roots[0]
	}
	return dgi_items_wrapper_nodes('cx:block', roots)
}

// dgi_items_wrapper_nodes is dgi_items_wrapper for already-lifted nodes.
fn dgi_items_wrapper_nodes(wrapper string, items []cx.Node) cx.Node {
	mut kids := []cx.Node{}
	for it in items {
		mut iv := []cx.Node{}
		iv << it
		kids << dgi_el('item', iv)
	}
	return dgi_el(wrapper, kids)
}

// dgi_data_scalar maps a data scalar to the image tag the program lift
// uses for the same kind (dgi_literal); null and bytes have no literal
// tag in the image and hatch to the cx:expr source form.
fn dgi_data_scalar(t cx.ScalarType, v cx.ScalarValue) cx.Node {
	s := cx.scalar_value_str_public(v)
	return match t {
		.int_type { dgi_text('cx:int', s) }
		.float_type { dgi_text('cx:float', s) }
		.bool_type { dgi_text('cx:bool', s) }
		.string_type { dgi_text('cx:str', s) }
		.atom_type { dgi_text('cx:atom', s) }
		.date_type { dgi_text('cx:date', s) }
		.datetime_type { dgi_text('cx:datetime', s) }
		.decimal_type { dgi_text('cx:decimal', s) }
		.bigint_type { dgi_text('cx:bigint', s) }
		.duration_type { dgi_text('cx:dur', s) }
		.period_type { dgi_text('cx:period', s) }
		.null_type { dgi_text('cx:expr', 'null') }
		.bytes_type { dgi_text('cx:expr', s) }
	}
}

// dgi_data_attr_value lifts an attribute's typed value by its runtime
// variant (attributes are strictly scalar — #396 1b).
fn dgi_data_attr_value(v cx.ScalarValue) cx.Node {
	return match v {
		bool { dgi_text('cx:bool', cx.scalar_value_str_public(v)) }
		i64 { dgi_text('cx:int', cx.scalar_value_str_public(v)) }
		f64 { dgi_text('cx:float', cx.scalar_value_str_public(v)) }
		string { dgi_text('cx:str', v) }
		cx.NullValue { dgi_text('cx:expr', 'null') }
	}
}

// dgi_table_child — the TI-1 table image (#914, RULED). An element's
// `:table` payload lifts as ONE `cx:table` CHILD carrying the row
// COUNT, with one empty `cx:col name= type=` child per declared
// column — mirroring the `cx:attr` child convention directly above,
// because a table's columns are the element's declared SHAPE exactly
// as its attributes are.
//
// Rows are SHAPE, not CONTENT (ruling point 3): the count rides the
// image and the row VALUES never do. This is the pinned ERD design's
// own line — attribute values appear at `--level=full` only, child
// values never — and it keeps the golden surface from ballooning with
// fixture data. A table's cells are reachable through the data verbs;
// a diagram is a shape drawing.
//
// An empty `type_name` is the `::string` default and is spelled
// EXPLICITLY here: a consumer of the image must not have to know the
// parser's default to type a column.
fn dgi_table_child(td &cx.TableData) cx.Node {
	mut attrs := []cx.Attribute{}
	attrs << dgi_attr('rows', '${td.rows.len}')
	mut kids := []cx.Node{}
	for c in td.cols {
		mut cattrs := []cx.Attribute{}
		cattrs << dgi_attr('name', c.name)
		cattrs << dgi_attr('type', if c.type_name == '' { 'string' } else { c.type_name })
		kids << dgi_el_attrs('cx:col', cattrs, []cx.Node{})
	}
	return dgi_el_attrs('cx:table', attrs, kids)
}

fn dgi_data_node(n cx.Node) cx.Node {
	match n {
		cx.Element {
			mut kids := []cx.Node{}
			for a in n.attrs {
				mut av := []cx.Node{}
				av << dgi_data_attr_value(a.value)
				mut aattrs := []cx.Attribute{}
				aattrs << dgi_attr('name', a.name)
				if dt := a.data_type() {
					aattrs << dgi_attr('type', dt)
				}
				kids << dgi_el_attrs('cx:attr', aattrs, av)
			}
			if td := n.table_opt() {
				kids << dgi_table_child(td)
			}
			for it in n.items {
				if it is cx.CommentNode {
					continue
				}
				kids << dgi_data_node(it)
			}
			if n.name == 'err' {
				// The #898 / DRW3-9 rename — same contract as dgi_element:
				// an image element named `err` IS an error value to the
				// evaluator, so the data lift renames it identically.
				mut attrs := []cx.Attribute{}
				attrs << dgi_attr(dgi_renamed_from_attr, n.name)
				return dgi_el_attrs(dgi_err_literal_tag, attrs, kids)
			}
			return dgi_el(n.name, kids)
		}
		cx.ScalarNode {
			return dgi_data_scalar(n.data_type, n.value)
		}
		cx.TextNode {
			return dgi_text('cx:str', n.value)
		}
		cx.SequenceNode {
			mut lifted := []cx.Node{}
			for it in n.items {
				if it is cx.CommentNode {
					continue
				}
				lifted << dgi_data_node(it)
			}
			return dgi_items_wrapper_nodes('cx:seq', lifted)
		}
		cx.ArrayNode {
			mut lifted := []cx.Node{}
			for it in n.items {
				if it is cx.CommentNode {
					continue
				}
				lifted << dgi_data_node(it)
			}
			return dgi_items_wrapper_nodes('cx:arr', lifted)
		}
		cx.MapNode {
			mut kids := []cx.Node{}
			for e in n.entries {
				mut eattrs := []cx.Attribute{}
				eattrs << dgi_attr('key', cx.scalar_value_str_public(e.key_value))
				// RULED: MSS-4 (#917): declared entries carry the kind, no
				// value child (the placeholder is never the value).
				if e.decl_kind != '' {
					eattrs << dgi_attr('decl', e.decl_kind)
					kids << dgi_el_attrs('entry', eattrs, []cx.Node{})
					continue
				}
				mut ev := []cx.Node{}
				ev << dgi_data_node(e.value)
				kids << dgi_el_attrs('entry', eattrs, ev)
			}
			return dgi_el('cx:map', kids)
		}
		else {
			// Interpolations, PIs, holes, aliases, raw text — the image's
			// source-text hatch, same as the program lift's escape.
			return dgi_text('cx:expr', render_canonical(n))
		}
	}
}

fn dgi_binding(n cx.ProgramBinding) cx.Node {
	if n.path.len == 0 {
		return dgi_text('cx:var', n.name)
	}
	mut kids := []cx.Node{}
	for step in n.path {
		kids << dgi_step(step)
	}
	mut attrs := []cx.Attribute{}
	attrs << dgi_attr('name', n.name)
	return dgi_el_attrs('cx:var', attrs, kids)
}

fn dgi_step(step cx.ProgramPathStep) cx.Node {
	mut attrs := []cx.Attribute{}
	attrs << dgi_attr('kind', px_step_kind_name(step.kind))
	attrs << dgi_attr('name', step.name)
	if step.computed_name != '' {
		attrs << dgi_attr('computed', step.computed_name)
	}
	if step.kind_test != .none {
		attrs << dgi_attr('kind-test', px_step_kind_test_name(step.kind_test))
	}
	mut kids := []cx.Node{}
	for p in step.predicates {
		// The renderer's labels only COUNT predicates (`[…]` marks) —
		// carry each as an empty <cx:pred kind=…/> marker.
		mut pattrs := []cx.Attribute{}
		pattrs << dgi_attr('kind', match p.kind {
			.position { 'position' }
			.attr_test { 'attr' }
			.expr { 'expr' }
		})
		kids << dgi_el_attrs('cx:pred', pattrs, []cx.Node{})
	}
	return dgi_el_attrs('cx:step', attrs, kids)
}

fn dgi_call(n cx.ProgramCall) cx.Node {
	mut has_label := false
	for l in n.arg_labels {
		if l != '' {
			has_label = true
			break
		}
	}
	mut attrs := []cx.Attribute{}
	attrs << dgi_attr('fn', n.name)
	if n.fallible {
		attrs << dgi_attr('fallible', 'true')
	}
	if n.must_succeed {
		attrs << dgi_attr('must-succeed', 'true')
	}
	if !n.explicit_call {
		attrs << dgi_attr('explicit', 'false')
	}
	mut kids := []cx.Node{}
	if has_label {
		for i, a in n.args {
			lbl := if i < n.arg_labels.len { n.arg_labels[i] } else { '' }
			mut av := []cx.Node{}
			av << diagram_lower(a)
			mut aattrs := []cx.Attribute{}
			aattrs << dgi_attr('label', lbl)
			kids << dgi_el_attrs('cx:arg', aattrs, av)
		}
	} else {
		for a in n.args {
			kids << diagram_lower(a)
		}
	}
	for step in n.path {
		kids << dgi_step(step)
	}
	return dgi_el_attrs('cx:call', attrs, kids)
}

// dgi_directive marks the element `cx-node="directive"`. The §4 tag
// alone CONFLATES a directive with a same-named value image —
// `<cx:str>` is both a string literal and a `[?str]` directive,
// `<cx:map>` is both a map literal and `[?map]` — and a consumer that
// must know which (the DOT walk) cannot recover it from the tag or
// from the grammar registry. The mark is carried on the INJECTED
// image only; it is not part of the ast.md §4 wire projection.
fn dgi_directive(n cx.ProgramDirective) cx.Node {
	mut kids := []cx.Node{}
	for s in n.slots {
		if s.kind == .labeled {
			mut sv := []cx.Node{}
			sv << diagram_lower(s.value)
			kids << dgi_el('cx:' + s.label, sv)
		} else {
			kids << diagram_lower(s.value)
		}
	}
	mut attrs := []cx.Attribute{}
	attrs << dgi_attr('cx-node', 'directive')
	return dgi_el_attrs('cx:' + n.name, attrs, kids)
}

fn dgi_for_comp(n cx.ProgramForComp) cx.Node {
	mut kids := []cx.Node{}
	for c in n.clauses {
		mut cattrs := []cx.Attribute{}
		cattrs << dgi_attr('kind', px_clause_kind_name(c.kind))
		if c.bind != '' {
			cattrs << dgi_attr('bind', c.bind)
		}
		if c.direction != '' {
			cattrs << dgi_attr('direction', c.direction)
		}
		mut ckids := []cx.Node{}
		if s := c.source {
			mut sv := []cx.Node{}
			sv << diagram_lower(s)
			ckids << dgi_el('cx:source', sv)
		}
		if e := c.expr {
			mut ev := []cx.Node{}
			ev << diagram_lower(e)
			ckids << dgi_el('cx:expr-clause', ev)
		}
		kids << dgi_el_attrs('cx:clause', cattrs, ckids)
	}
	mut yv := []cx.Node{}
	yv << diagram_lower(n.yield)
	kids << dgi_el('cx:yield', yv)
	if yval := n.yield_value {
		mut yvv := []cx.Node{}
		yvv << diagram_lower(yval)
		kids << dgi_el('cx:yield-value', yvv)
	}
	mut attrs := []cx.Attribute{}
	attrs << dgi_attr('outer', px_for_form_name(n.outer_form))
	attrs << dgi_attr('yield-form', px_yield_form_name(n.yield_form))
	attrs << dgi_attr('cx-node', 'for-comp')
	return dgi_el_attrs('cx:for-comp', attrs, kids)
}

fn dgi_pattern(p cx.ProgramPattern) cx.Node {
	mut attrs := []cx.Attribute{}
	attrs << dgi_attr('head-kind', px_pattern_head_kind_name(p.head.kind))
	attrs << dgi_attr('value', p.head.value)
	if p.head.bind != '' {
		attrs << dgi_attr('bind', p.head.bind)
	}
	if p.direct {
		attrs << dgi_attr('direct', 'true')
	}
	mut kids := []cx.Node{}
	for a in p.attrs {
		mut pattrs := []cx.Attribute{}
		pattrs << dgi_attr('kind', px_attr_kind_name(a.kind))
		pattrs << dgi_attr('name', a.name)
		pattrs << dgi_attr('op', a.op)
		mut pv := []cx.Node{}
		if v := a.value {
			pv << diagram_lower(v)
		}
		kids << dgi_el_attrs('cx:pattr', pattrs, pv)
	}
	for it in p.body {
		kids << diagram_lower(it)
	}
	return dgi_el_attrs('cx:pattern', attrs, kids)
}

// ── the WAVE-3 image mode (DRW3-4) ──────────────────────────────────
//
// The playground renderer needs a `[?def]`'s NAME and BODY as
// structure. The parser does not give it any: `[?def …]` is captured as
// a single labeled `raw-source` STRING slot with the structural parse
// deferred to eval time (`cx.parse_def`), so the V emitter re-parsed the
// text from inside the renderer. A pure CX renderer cannot, and must
// not (DR-7a: the engine hands over the image; the renderer never
// parses). `diagram_lower_code` therefore post-walks the §4 image and
// gives every `cx:def` element a `<cx:def-image name="NAME">` child
// carrying the LOWERED body — or, when the deferred parse fails,
// `<cx:def-image error="…"/>`, which the module surfaces as the same
// refusal the V emitter raised.
//
// The walk touches the "code" mode ONLY: `diagram_lower` — the wave-1/2
// reference image — is left exactly as it was, so no wave-1/2 golden
// can move.
fn diagram_lower_code(node cx.ProgramNode) cx.Node {
	return dgc_expand_defs(diagram_lower(node), false)
}

// diagram_lower_effects — the "effects" image mode (RULED: DGX-1e,
// ledger/rulings_2026_08_21_diagram_capabilities.md). The `"code"`
// lowering (whose `[?def]` expansion the effect walk requires — a
// capability reached inside a def body is invisible without it) PLUS
// one addition: a `<cx:lib-image module=… alias=… kind=…>` child on a
// `[?lib]` directive.
//
// The parser defers a `[?lib …]` head to a `raw-source` STRING exactly
// as it defers a `[?def]` body, so the alias an import binds is not in
// the §4 image at all. Without it an aliased import
// (`[?lib 'cx-stdlib/io' as=fs]` then `[$fs:read-file …]`) resolves to
// nothing and the READ IS MISSED — a silent under-report, which DGX-1c
// forbids outright.
//
// `"ref"` and `"code"` are untouched, so no wave-1/2/3 golden can move.
fn diagram_lower_effects(node cx.ProgramNode) cx.Node {
	return dgc_expand_defs(diagram_lower(node), true)
}

fn dgc_expand_defs(n cx.Node, with_lib bool) cx.Node {
	if n is cx.Element {
		if n.name == 'cx:expr' {
			if p := dgc_path_image(n) {
				return p
			}
		}
		mut kids := []cx.Node{}
		for k in n.items {
			kids << dgc_expand_defs(k, with_lib)
		}
		if n.name == 'cx:def' {
			img := dgc_def_image(n)
			// In "effects" mode the def-image body is expanded AGAIN, so a
			// `[?def]` NESTED inside a def body gets its own def-image. The
			// body arrives from `dgc_def_image` through plain `diagram_lower`,
			// which stops at the inner def's `raw-source` string — and an
			// effect inside that inner def would then be invisible to the
			// walk. A silent under-report is exactly what DGX-1c forbids, so
			// the effects mode pays the extra pass. "code" mode is untouched:
			// the playground emitter reads only the outer def's structure and
			// re-expanding would move its goldens.
			kids << if with_lib { dgc_expand_defs(img, true) } else { img }
		}
		if with_lib && n.name == 'cx:lib' {
			kids << dgx_lib_image(n)
		}
		return cx.Node(cx.Element{
			...n
			items: kids
		})
	}
	return n
}

// dgx_lib_image — the DGX-1e `[?lib]` expansion. Reads the deferred
// `raw-source` text with the engine's own `[?lib]` parser (bytes the
// engine emitted) and projects the resolver, its kind, and the bound
// alias as structure. A refusal is carried as `error=` rather than
// dropped: an import the walk cannot read is an OPACITY SOURCE the
// renderer must show, not a node it may skip.
fn dgx_lib_image(el cx.Element) cx.Node {
	raw := dgc_raw_source(el) or {
		mut attrs := []cx.Attribute{}
		attrs << dgi_attr('absent', 'true')
		return dgi_el_attrs('cx:lib-image', attrs, []cx.Node{})
	}
	lib := cx.parse_lib(raw) or {
		mut attrs := []cx.Attribute{}
		attrs << dgi_attr('error', '[?lib] parse: ${err.msg()}')
		return dgi_el_attrs('cx:lib-image', attrs, []cx.Node{})
	}
	mut attrs := []cx.Attribute{}
	attrs << dgi_attr('module', lib.resolver_source)
	attrs << dgi_attr('kind', cx.resolver_kind_str(lib.resolver_kind))
	if alias := lib.alias {
		attrs << dgi_attr('alias', alias)
	}
	return dgi_el_attrs('cx:lib-image', attrs, []cx.Node{})
}

// dgc_path_image — the DRW3-6 structural path node. The §4 projection
// hatches a bare CXPath expression to its SOURCE TEXT (`<cx:expr>`),
// but this renderer's label for a path is the steps-joined form
// (`render_path_or_fallback`: leading marker + step NAMES, predicates
// and axes dropped) — `//users/user[1]` labels as `//users/user`. The
// text hatch cannot be turned into that label without re-parsing, and
// the renderer must not parse. The code-mode lift therefore re-reads
// the hatch's own text (the engine's parser, on bytes the engine
// itself emitted) and, when it IS a path expression, hands the
// renderer the structure: `<cx:path leading=…><cx:pstep name=…/>…`.
// Anything else (dynamic element names, operator-with-attrs) keeps the
// text hatch.
fn dgc_path_image(el cx.Element) ?cx.Node {
	mut text := ''
	for t in el.items {
		if t is cx.TextNode {
			text = t.value
			break
		}
	}
	if text == '' {
		return none
	}
	prog := cx.parse_program(text) or { return none }
	body := prog.body
	if body !is cx.ProgramPathExpr {
		return none
	}
	px := body as cx.ProgramPathExpr
	leading := match px.leading {
		.absolute { 'absolute' }
		.descendant { 'descendant' }
		.relative { 'relative' }
	}
	mut attrs := []cx.Attribute{}
	attrs << dgi_attr('leading', leading)
	mut kids := []cx.Node{}
	for st in px.steps {
		mut sattrs := []cx.Attribute{}
		sattrs << dgi_attr('name', st.name)
		kids << dgi_el_attrs('cx:pstep', sattrs, []cx.Node{})
	}
	return dgi_el_attrs('cx:path', attrs, kids)
}

// dgc_raw_source returns the text of a `cx:def`'s deferred
// `<cx:raw-source><cx:str>…</cx:str></cx:raw-source>` child.
fn dgc_raw_source(el cx.Element) ?string {
	for k in el.items {
		if k is cx.Element && k.name == 'cx:raw-source' {
			for v in k.items {
				if v is cx.Element && v.name == 'cx:str' {
					for t in v.items {
						if t is cx.TextNode {
							return t.value
						}
					}
					return ''
				}
			}
		}
	}
	return none
}

fn dgc_def_image(el cx.Element) cx.Node {
	raw := dgc_raw_source(el) or {
		// No deferred text (a synthetic directive): the module falls back
		// to the legacy positional/labeled shapes, exactly as the V
		// emitter's `def_name_and_body` did.
		mut attrs := []cx.Attribute{}
		attrs << dgi_attr('absent', 'true')
		return dgi_el_attrs('cx:def-image', attrs, []cx.Node{})
	}
	def_node := cx.parse_def(raw) or {
		mut attrs := []cx.Attribute{}
		attrs << dgi_attr('error', '[?def] parse: ${err.msg()}')
		return dgi_el_attrs('cx:def-image', attrs, []cx.Node{})
	}
	body_prog := cx.parse_program(def_node.body) or {
		mut attrs := []cx.Attribute{}
		attrs << dgi_attr('error', '[?def] body parse: ${err.msg()}')
		return dgi_el_attrs('cx:def-image', attrs, []cx.Node{})
	}
	stmts := dgc_top_level(body_prog)
	if stmts.len == 0 {
		mut attrs := []cx.Attribute{}
		attrs << dgi_attr('error', '[?def] empty body')
		return dgi_el_attrs('cx:def-image', attrs, []cx.Node{})
	}
	body_node := if stmts.len == 1 {
		stmts[0]
	} else {
		cx.ProgramNode(cx.ProgramLiteral{
			kind:  .block
			items: stmts
		})
	}
	mut attrs := []cx.Attribute{}
	attrs << dgi_attr('name', if def_node.name == '' { 'anon' } else { def_node.name })
	mut kids := []cx.Node{}
	kids << diagram_lower(body_node)
	return dgi_el_attrs('cx:def-image', attrs, kids)
}

// dgc_top_level — a program's top-level statement list (a `.block`
// literal body is its items; anything else is one statement).
fn dgc_top_level(prog cx.Program) []cx.ProgramNode {
	body := prog.body
	if body is cx.ProgramLiteral && body.kind == .block {
		return body.items
	}
	return [body]
}

// The per-process seam cache: ONE env that has loaded the module once.
// The module is pure and stateless; every call injects fresh bindings.
// Guarded by a mutex — render_diagram's callers (CLI / eval target /
// wasm ABI) are single-threaded today, but the seam does not rely on
// that. Without this cache every render re-parsed the whole bundled
// module through [?lib], putting the DR-6 budget out of reach.
__global (
	g_dgc_cache    voidptr
	g_dgc_mu       &sync.Mutex
	g_dgc_mu_ready bool
)

// DgcCache holds the one loaded-module env (heap-allocated, reached
// through the voidptr global — the error_hooks.v pattern).
struct DgcCache {
mut:
	env MatchEnv
}

fn dgc_mu() &sync.Mutex {
	if !g_dgc_mu_ready {
		g_dgc_mu = sync.new_mutex()
		g_dgc_mu_ready = true
	}
	return g_dgc_mu
}

// diagram_cx_call evaluates ONE module call with the given injected
// bindings and returns the raw result node.
fn diagram_cx_call(call_src string, binds map[string]cx.Node) !cx.Node {
	res, _ := diagram_cx_call_impl(call_src, binds, false)!
	return res
}

// diagram_cx_call_impl is diagram_cx_call with an optional WORK COUNT.
// When `count_steps` is set the call runs under an F4 evaluation budget
// (S6.2, RULED: F4) armed with NO limit on either conjunct — it counts
// eval_node entries, it never refuses — and the count is returned
// alongside the result. The budget is disarmed before the lock drops, so
// the cached module env leaves this call exactly as it entered it and no
// other caller pays the counter's branch.
fn diagram_cx_call_impl(call_src string, binds map[string]cx.Node, count_steps bool) !(cx.Node, u64) {
	mut mu := dgc_mu()
	mu.lock()
	defer {
		mu.unlock()
	}
	if g_dgc_cache == unsafe { nil } {
		lib_prog := cx.parse_program("[?lib 'cx-stdlib/diagram' as=cxdg]\n1") or {
			return error('diagram driver parse: ${err.msg()}')
		}
		mut env0 := new_env()
		body0 := lib_prog.body
		if body0 is cx.ProgramLiteral {
			if body0.kind == .block {
				for it in body0.items {
					eval(it, mut env0)!
				}
			}
		}
		c := &DgcCache{
			env: env0
		}
		g_dgc_cache = voidptr(c)
	}
	mut cache := unsafe { &DgcCache(g_dgc_cache) }
	prog := cx.parse_program(call_src) or {
		return error('diagram driver parse: ${err.msg()}')
	}
	for k, v in binds {
		cache.env.bindings[k] = v
	}
	if !count_steps {
		return eval(prog.body, mut cache.env)!, u64(0)
	}
	mut budget := arm_eval_budget(mut cache.env, 0, 0)
	res := eval(prog.body, mut cache.env) or {
		cache.env.eval_budget = unsafe { nil }
		return err
	}
	steps := budget.steps
	cache.env.eval_budget = unsafe { nil }
	return res, steps
}


// diagram_rules_value returns the module's sealed render-rules table
// (the DR-4a data value) — the completeness gate's subject.
pub fn diagram_rules_value() !cx.Node {
	return diagram_cx_call('[\$cxdg:rules]', map[string]cx.Node{})!
}

// diagram_admitted reports the module's top-level admission verdict
// for one directive local name (rows ∪ aliases ∪ scaffolding).
pub fn diagram_admitted(name string) !bool {
	res := diagram_cx_call('[\$cxdg:admitted \$dname]', {
		'dname': diagram_str_node(name)
	})!
	if res is cx.ScalarNode {
		v := res.value
		if v is bool {
			return v
		}
	}
	return error('diagram_admitted: non-bool result')
}

// diagram_cx_string maps the module result to the string the
// render/extract callers expect, or surfaces its [err] as EvalError.
fn diagram_cx_string(res cx.Node) !string {
	if res is cx.Element {
		if res.name == 'err' {
			code_s := cx_elem_attr(res, 'code') or { 'cx-err:CXER0001' }
			msg := cx_elem_attr(res, 'message') or { 'diagram renderer refused' }
			return EvalError{
				code:    code_s
				message: msg
			}
		}
	}
	if res is cx.ScalarNode {
		v := res.value
		if v is string {
			return v
		}
	}
	return EvalError{
		code:    'cx-err:CXER0001'
		message: 'diagram renderer returned a non-string result'
	}
}

fn diagram_str_node(s string) cx.Node {
	return cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	})
}

// render_mermaid_cx renders the Mermaid target through the CX module.
fn render_mermaid_cx(prog cx.Program, source_text string, detail DiagramDetail) !string {
	img := diagram_program_image(prog)!
	detail_s := match detail {
		.min { 'min' }
		.compact { 'compact' }
		.full { 'full' }
	}
	res := diagram_cx_call('[\$cxdg:render-mermaid \$program \$source \$detail]', {
		'program': img
		'source':  diagram_str_node(source_text)
		'detail':  diagram_str_node(detail_s)
	})!
	return diagram_cx_string(res)!
}

// The WAVE-3 completeness gate's two probes (DR-5, extended to the
// playground renderer): the sealed rule table as data, and the LIVE
// dispatch class the emitter takes for a directive name. The gate diffs
// them against the grammar registry and the golden corpus, so a row
// added, removed, or renamed reddens in both directions.
pub fn code_diagram_rules_value() !cx.Node {
	return diagram_cx_call('[\$cxdg:code-rules]', map[string]cx.Node{})!
}

pub fn code_diagram_class(name string) !string {
	res := diagram_cx_call('[\$cxdg:code-class \$dname]', {
		'dname': diagram_str_node(name)
	})!
	if res is cx.ScalarNode {
		v := res.value
		if v is string {
			return v
		}
	}
	return error('code_diagram_class: non-string result')
}

// ── the DGX-1 effect/capability graph ─────────────────────────────────
// (RULED: DGX-1, ledger/rulings_2026_08_21_diagram_capabilities.md)

// effect_graph_cx — the driver for the `effects` VIEW: source text in,
// a Mermaid capability-reachability graph out. Same shape as
// code_diagram_cx (a module `[err …]` surfaces as a plain error whose
// message the CLI prints verbatim), because it is the same renderer
// family reached through the same subcommand.
fn effect_graph_cx(source string, level string) !string {
	res := diagram_cx_call('[\$cxdg:effect-graph \$source \$level]', {
		'source': diagram_str_node(source)
		'level':  diagram_str_node(level)
	})!
	if res is cx.Element {
		if res.name == 'err' {
			msg := cx_elem_attr(res, 'message') or { 'effect-graph refused' }
			return error(msg)
		}
	}
	if res is cx.ScalarNode {
		v := res.value
		if v is string {
			return v
		}
	}
	return error('effect-graph returned a non-string result')
}

// The DGX-1b completeness gate's two probes: the module's sealed
// effect-rules table as DATA, and the LIVE capability verdict the
// module returns for one primitive name (which reads the engine table
// through `[$diagram-effect-table]` — DGX-1a: the prim→capability map
// is never copied into the module).
pub fn diagram_effect_rules_value() !cx.Node {
	return diagram_cx_call('[\$cxdg:effect-rules]', map[string]cx.Node{})!
}

pub fn diagram_effect_cap(prim string) !string {
	res := diagram_cx_call('[\$cxdg:effect-cap \$pname]', {
		'pname': diagram_str_node(prim)
	})!
	if res is cx.ScalarNode {
		v := res.value
		if v is string {
			return v
		}
	}
	return error('diagram_effect_cap: non-string result')
}

// code_diagram_cx — the WAVE-3 driver: the playground renderer's ONE
// entry (`cx code-diagram`, the wasm export, the golden gate) into the
// CX module. Source text in, Mermaid out; the module does the PI
// strip, the surviving DRW3-2 parser patch, the parse (through its own
// ingress primitive), the auto-detect classification, and the emit.
//
// An `[err …]` result is surfaced as a PLAIN error carrying the
// module's message verbatim, not an EvalError: `cx code-diagram`
// prints `cx code-diagram: <msg>`, and the shipped text for a
// refusing `[?def]` was exactly the message the emitter raised.
fn code_diagram_cx(source string, level string) !string {
	res := diagram_cx_call('[\$cxdg:code-diagram \$source \$level]', {
		'source': diagram_str_node(source)
		'level':  diagram_str_node(level)
	})!
	if res is cx.Element {
		if res.name == 'err' {
			msg := cx_elem_attr(res, 'message') or { 'code-diagram refused' }
			return error(msg)
		}
	}
	if res is cx.ScalarNode {
		v := res.value
		if v is string {
			return v
		}
	}
	return error('code-diagram returned a non-string result')
}

// render_of_source_cx — the ONE render path (#889, DRW3-1 deliverable
// B). Every diagram render — `cx diagram`, `cx eval --target=…`, the
// wasm export, the gates — enters the module through its caller-facing
// entry `[$diagram:of-source SRC FORMAT DETAIL]`, which performs the
// program lift internally (DRW3-3). There is no second lift: a CX
// caller and the CLI produce the same bytes because they run the same
// function.
fn render_of_source_cx(source_text string, format string, detail string) !string {
	out, _ := render_of_source_cx_counted(source_text, format, detail, false)!
	return out
}

// render_of_source_cx_counted is that one path with an optional WORK
// COUNT: when `count_steps` is set the render runs under an unlimited F4
// evaluation budget and the eval-step count comes back with the bytes.
// Instrumentation only — it is the SAME call, so a counted render and an
// uncounted one cannot produce different bytes (no twin).
fn render_of_source_cx_counted(source_text string, format string, detail string, count_steps bool) !(string, u64) {
	res, steps := diagram_cx_call_impl('[\$cxdg:of-source \$source \$format detail=\$detail]',
		{
		'source': diagram_str_node(source_text)
		'format': diagram_str_node(format)
		'detail': diagram_str_node(detail)
	}, count_steps)!
	return diagram_cx_string(res)!, steps
}

// render_svg_cx / render_png_cx — the wave-2 vector targets through
// the CX module (DR-2a/DR-9a). The `dot` hop and the capability live
// inside the module; this is invocation only.
fn render_svg_cx(prog cx.Program, source_text string) !string {
	img := diagram_program_image(prog)!
	res := diagram_cx_call('[\$cxdg:render-svg \$program \$source]', {
		'program': img
		'source':  diagram_str_node(source_text)
	})!
	return diagram_cx_string(res)!
}

fn render_png_cx(prog cx.Program, source_text string) !string {
	img := diagram_program_image(prog)!
	res := diagram_cx_call('[\$cxdg:render-png \$program \$source]', {
		'program': img
		'source':  diagram_str_node(source_text)
	})!
	return diagram_cx_string(res)!
}

// render_dot_cx exposes the pure DOT text (the wave-2 golden subject).
pub fn render_dot_cx(prog cx.Program) !string {
	img := diagram_program_image(prog)!
	res := diagram_cx_call('[\$cxdg:render-dot \$program]', {
		'program': img
	})!
	return diagram_cx_string(res)!
}

// The wave-2 golden probes: the two dot-less envelopes and the two
// splices, reachable without graphviz so the gate is hermetic.
pub fn diagram_svg_envelope_cx(source_text string) !string {
	res := diagram_cx_call('[\$cxdg:svg-envelope \$source]', {
		'source': diagram_str_node(source_text)
	})!
	return diagram_cx_string(res)!
}

pub fn diagram_png_envelope_cx(source_text string) !string {
	res := diagram_cx_call('[\$cxdg:png-envelope \$source]', {
		'source': diagram_str_node(source_text)
	})!
	return diagram_cx_string(res)!
}

pub fn diagram_svg_splice_cx(svg string, source_text string) !string {
	res := diagram_cx_call('[\$cxdg:inject-svg-metadata \$svg \$source]', {
		'svg':    diagram_str_node(svg)
		'source': diagram_str_node(source_text)
	})!
	return diagram_cx_string(res)!
}

// diagram_crc32_cx exposes the module's PNG CRC-32 for the gate's
// known-vector pins.
pub fn diagram_crc32_cx(data string) !i64 {
	res := diagram_cx_call('[\$cxdg:crc32 \$data]', {
		'data': bytes_node(data.bytes())
	})!
	if res is cx.ScalarNode {
		v := res.value
		if v is i64 {
			return v
		}
	}
	return error('diagram_crc32_cx: non-int result')
}

pub fn diagram_png_splice_cx(png string, source_text string) !string {
	res := diagram_cx_call('[\$cxdg:inject-png-chunk \$png \$source]', {
		'png':    bytes_node(png.bytes())
		'source': diagram_str_node(source_text)
	})!
	return diagram_cx_string(res)!
}

// extract_diagram_source_cx recovers the embedded source from a
// rendered diagram through the CX module (all three formats — the
// reverse-parse extractors are shared pure code, DR-9a wave 1).
fn extract_diagram_source_cx(rendered string, format string) !string {
	fn_name := match format {
		'mermaid' { 'extract-mermaid' }
		'svg' { 'extract-svg' }
		'png' { 'extract-png' }
		else {
			return EvalError{
				code:    'cx-err:CXER0100'
				message: "diagram format '${format}' not recognised"
			}
		}
	}
	arg := if format == 'png' {
		bytes_node(rendered.bytes())
	} else {
		diagram_str_node(rendered)
	}
	res := diagram_cx_call('[\$cxdg:${fn_name} \$rendered]', {
		'rendered': arg
	})!
	return diagram_cx_string(res)!
}
