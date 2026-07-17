module code
import cx

import strings

// program_xml.v — bijective cx.ProgramNode ⇄ XML codec (Phase C §4).
//
// CX's founding promise is "code is data", and strengthens it to
// "a CX program round-trips losslessly to XML" — so programs and data can
// be stored side-by-side in an XML database and queried/rewritten as XML.
//
// `program_to_xml` emits a cx.ProgramNode to the cx-namespaced XML image of
// `xml_to_program` reads it back. The two are inverse over the
// AST surface, verified by the round-trip-identity test
// (vcx/tests/v08_program_xml_codec_test.v) which asserts
//   program_node_to_source(xml_to_program(program_to_xml(cx.parse_program(src))))
//     == program_node_to_source(cx.parse_program(src))
// for a fixture corpus (the same fixed-point contract the program_emit
// suite uses, since cx.ProgramNode has no `.eq()`).
//
// image (structurally encoded here):
//   <cx:int>/<cx:float>/<cx:bool>/<cx:str>/<cx:atom>/<cx:dur>  — scalars
//   <cx:var>name</cx:var>                                       — $name (no path)
//   <cx:call fn="f"><arg/>…</cx:call>                           — [$f arg…]
//   <cx:op name="add"><arg/>…</cx:op>                           — [+ a …] (symbol ops)
//   <name>items…</name>                                         — [name items…] element
//   <cx:DIR>…children/labels…</cx:DIR>                          — [?DIR …] directive
//
// Structural coverage is now near-total: scalars, $var (+ paths, incl.
// predicate-bearing steps), [$call] (+ fallible/must-succeed/bare/labeled),
// symbol [op], bareword elements (+ attrs/slots), all literal kinds
// (seq/arr/map/block), directives, for-comprehensions (<cx:for-comp>),
// patterns (<cx:pattern>), wildcards (<cx:wildcard>), and slices
// (<cx:slice>/<cx:slice-access>) all emit their structural §4 image.
//
// Escape hatch: the few nodes not structurally encoded — cx.ProgramPathExpr
// (CXPath value-kind, e.g. `//user[@active]`; its §4 image is unspecified),
// dynamic element-name literals (name computed at eval), and the guarded
// operator-with-attrs edge — emit as
//   <cx:expr>SOURCE</cx:expr>
// carrying their `program_node_to_source` text, which `code.parse`
// reconstructs on read-back, keeping the round-trip bijective over the
// FULL corpus.

// operator_xml_name maps a CX symbol operator (a cx_element head that is not
// a valid XML name) to its `<cx:op name=…>` label. `and`/`or`/
// `not` are valid XML names and round-trip as bareword elements (eval treats
// the resulting cx_element as the operator), so they are NOT in this table.
const operator_xml_names = {
	'+':  'add'
	'-':  'sub'
	'*':  'mul'
	'/':  'div'
	'=':  'eq'
	'!=': 'ne'
	'<':  'lt'
	'<=': 'le'
	'>':  'gt'
	'>=': 'ge'
}

// ── Emit ────────────────────────────────────────────────────────────────────

// program_to_xml emits the XML image of a cx.ProgramNode.
pub fn program_to_xml(node cx.ProgramNode) string {
	mut b := strings.new_builder(128)
	emit_px_node(mut b, node)
	return b.str()
}

fn emit_px_node(mut b strings.Builder, node cx.ProgramNode) {
	match node {
		cx.Program          { emit_px_node(mut b, node.body) }
		cx.ProgramLiteral   { emit_px_literal(mut b, node) }
		cx.ProgramBinding   { emit_px_binding(mut b, node) }
		cx.ProgramCall      { emit_px_call(mut b, node) }
		cx.ProgramDirective { emit_px_directive(mut b, node) }
		cx.ProgramWildcard  { emit_px_wildcard(mut b, node) }
		cx.ProgramSliceLiteral { emit_px_slice_literal(mut b, node) }
		cx.ProgramSliceAccess  { emit_px_slice_access(mut b, node) }
		cx.ProgramForComp   { emit_px_for_comp(mut b, node) }
		cx.ProgramPattern   { emit_px_pattern(mut b, node) }
		else             { emit_px_escape(mut b, node) }
	}
}

// emit_px_escape is the bijective fallback: emit the node's canonical CX
// source inside <cx:expr>, which code.parse reconstructs on read-back.
fn emit_px_escape(mut b strings.Builder, node cx.ProgramNode) {
	b.write_string('<cx:expr>')
	b.write_string(px_escape(program_node_to_source(node)))
	b.write_string('</cx:expr>')
}

fn emit_px_literal(mut b strings.Builder, n cx.ProgramLiteral) {
	match n.kind {
		.int_lit {
			b.write_string('<cx:int>${n.int_val}</cx:int>')
		}
		.bigint_lit {
			b.write_string('<cx:bigint>${px_escape(n.str_val)}</cx:bigint>')
		}
		.float_lit {
			b.write_string('<cx:float>${n.flt_val}</cx:float>')
		}
		.bool_lit {
			b.write_string('<cx:bool>${n.bool_val}</cx:bool>')
		}
		.string_lit {
			b.write_string('<cx:str>${px_escape(n.str_val)}</cx:str>')
		}
		.atom_lit {
			b.write_string('<cx:atom>${px_escape(n.str_val)}</cx:atom>')
		}
		.duration_lit {
			b.write_string('<cx:dur>${px_escape(n.dur_val)}</cx:dur>')
		}
		.period_lit {
			b.write_string('<cx:period>${px_escape(n.dur_val)}</cx:period>')
		}
		.date_lit {
			b.write_string('<cx:date>${px_escape(n.str_val)}</cx:date>')
		}
		.datetime_lit {
			b.write_string('<cx:datetime>${px_escape(n.str_val)}</cx:datetime>')
		}
		.cx_element {
			emit_px_element(mut b, n)
		}
		.sequence_lit {
			emit_px_items_wrapper(mut b, 'cx:seq', n.items)
		}
		.array_lit {
			emit_px_items_wrapper(mut b, 'cx:arr', n.items)
		}
		.map_lit {
			emit_px_map(mut b, n)
		}
		.block {
			emit_px_items_wrapper(mut b, 'cx:block', n.items)
		}
		.node_lit {
			// Embedded pure-DATA construct — carry the verbatim span source
			// under a <cx:data> element (round-trips via program_node_to_source).
			b.write_string('<cx:data>${px_escape(n.str_val)}</cx:data>')
		}
	}
}

fn emit_px_element(mut b strings.Builder, n cx.ProgramLiteral) {
	// Dynamic element-name (name_expr) is not structurally encoded — hatch.
	if n.name_expr != none || n.name == '' {
		emit_px_escape(mut b, n)
		return
	}
	// Symbol operator head → <cx:op name="…">. Operators carry no attrs/slots;
	// if one somehow does, fall through to the bareword path (which would
	// hatch on the invalid name) — but operator symbols aren't valid XML
	// names, so guard explicitly.
	if op_name := operator_xml_names[n.name] {
		if n.attrs.len > 0 || n.slots.len > 0 {
			emit_px_escape(mut b, n)
			return
		}
		b.write_string('<cx:op name="${op_name}">')
		for it in n.items {
			emit_px_node(mut b, it)
		}
		b.write_string('</cx:op>')
		return
	}
	// Bareword element → <name attrs items slots</name>. Only valid XML
	// local-names are structurally encoded; otherwise escape-hatch.
	if !px_is_xml_name(n.name) {
		emit_px_escape(mut b, n)
		return
	}
	if n.items.len == 0 && n.attrs.len == 0 && n.slots.len == 0 {
		b.write_string('<${n.name}/>')
		return
	}
	b.write_string('<${n.name}>')
	// Element-construction attributes → <cx:attr name="…">VALUE</cx:attr>.
	// (XML attributes would lose the value's cx.ProgramNode type; the child
	// form keeps the round-trip bijective for any attr value.)
	for a in n.attrs {
		b.write_string('<cx:attr name="${px_escape_attr(a.name)}"')
		if a.data_type != '' {
			// D3 attribute ascription `name::T=value` ([L50]; #466) —
			// carried as a `type` XML attribute so the round-trip stays
			// bijective.
			b.write_string(' type="${px_escape_attr(a.data_type)}"')
		}
		b.write_string('>')
		emit_px_node(mut b, a.value)
		b.write_string('</cx:attr>')
	}
	for it in n.items {
		emit_px_node(mut b, it)
	}
	// Labeled element slots → <cx:slot label="…">VALUE</cx:slot>.
	for s in n.slots {
		b.write_string('<cx:slot label="${px_escape_attr(s.label)}">')
		emit_px_node(mut b, s.value)
		b.write_string('</cx:slot>')
	}
	b.write_string('</${n.name}>')
}

// emit_px_items_wrapper emits a `<wrapper><item>…</item>…</wrapper>` form
// for sequence/array literals (cx:seq / cx:arr; matches the
// data-side <cx:seq>/<cx:arr> item-wrapping convention).
fn emit_px_items_wrapper(mut b strings.Builder, wrapper string, items []cx.ProgramNode) {
	if items.len == 0 {
		b.write_string('<${wrapper}/>')
		return
	}
	b.write_string('<${wrapper}>')
	for it in items {
		b.write_string('<item>')
		emit_px_node(mut b, it)
		b.write_string('</item>')
	}
	b.write_string('</${wrapper}>')
}

// emit_px_map emits a map literal as `<cx:map><entry key="K">V</entry>…</cx:map>`
// (mirrors the data-side <cx:map> entry form). The key is the
// verbatim surface text the parser captured (`name` / `:ok` / `"k"`), preserved
// so program_node_to_source round-trips identically.
fn emit_px_map(mut b strings.Builder, n cx.ProgramLiteral) {
	if n.items.len == 0 {
		b.write_string('<cx:map/>')
		return
	}
	b.write_string('<cx:map>')
	for i in 0 .. n.items.len {
		key := if i < n.keys.len { n.keys[i] } else { '' }
		b.write_string('<entry key="${px_escape_attr(key)}">')
		emit_px_node(mut b, n.items[i])
		b.write_string('</entry>')
	}
	b.write_string('</cx:map>')
}

fn emit_px_binding(mut b strings.Builder, n cx.ProgramBinding) {
	if n.path.len == 0 {
		b.write_string('<cx:var>${px_escape(n.name)}</cx:var>')
		return
	}
	b.write_string('<cx:var name="${px_escape_attr(n.name)}">')
	for step in n.path {
		emit_px_step(mut b, step)
	}
	b.write_string('</cx:var>')
}

// emit_px_step emits one binding path step. A step carrying no CXPath
// predicates is self-closing; predicate-bearing steps wrap `<cx:pred>`
// children (predicate forms: position / attr-test / general expr).
fn emit_px_step(mut b strings.Builder, step cx.ProgramPathStep) {
	if step.predicates.len == 0 {
		b.write_string('<cx:step kind="${px_step_kind_name(step.kind)}" name="${px_escape_attr(step.name)}"/>')
		return
	}
	b.write_string('<cx:step kind="${px_step_kind_name(step.kind)}" name="${px_escape_attr(step.name)}">')
	for p in step.predicates {
		emit_px_predicate(mut b, p)
	}
	b.write_string('</cx:step>')
}

// emit_px_predicate emits one CXPath step predicate (cx.ProgramPathPredicate).
fn emit_px_predicate(mut b strings.Builder, p cx.ProgramPathPredicate) {
	match p.kind {
		.position {
			b.write_string('<cx:pred kind="position" index="${p.int_index}"/>')
		}
		.attr_test {
			b.write_string('<cx:pred kind="attr" attr-kind="${px_attr_kind_name(p.attr_kind)}" name="${px_escape_attr(p.attr_name)}" op="${px_escape_attr(p.attr_op)}"')
			if v := p.attr_value {
				b.write_string('>')
				emit_px_node(mut b, v)
				b.write_string('</cx:pred>')
			} else {
				b.write_string('/>')
			}
		}
		.expr {
			if body := p.body {
				b.write_string('<cx:pred kind="expr">')
				emit_px_node(mut b, body)
				b.write_string('</cx:pred>')
			} else {
				b.write_string('<cx:pred kind="expr"/>')
			}
		}
	}
}

fn px_attr_kind_name(k cx.ProgramPatternAttrKind) string {
	return match k {
		.existence { 'existence' }
		.absence { 'absence' }
		.equality { 'equality' }
		.comparison { 'comparison' }
		.type_test { 'type-test' }
	}
}

fn px_attr_kind_from(s string) !cx.ProgramPatternAttrKind {
	return match s {
		'existence' { cx.ProgramPatternAttrKind.existence }
		'absence' { cx.ProgramPatternAttrKind.absence }
		'equality' { cx.ProgramPatternAttrKind.equality }
		'comparison' { cx.ProgramPatternAttrKind.comparison }
		'type-test' { cx.ProgramPatternAttrKind.type_test }
		else { error('program_xml: unknown attr-kind `${s}`') }
	}
}

fn px_step_kind_name(k cx.PathStepKind) string {
	return match k {
		.child { 'child' }
		.attr { 'attr' }
		.member { 'member' }
		.wildcard_children { 'wildcard_children' }
		.descendant { 'descendant' }
		.descendant_wildcard { 'descendant_wildcard' }
		.parent { 'parent' }
	}
}

fn px_step_kind_from(s string) !cx.PathStepKind {
	return match s {
		'child' { cx.PathStepKind.child }
		'attr' { cx.PathStepKind.attr }
		'member' { cx.PathStepKind.member }
		'wildcard_children' { cx.PathStepKind.wildcard_children }
		'descendant' { cx.PathStepKind.descendant }
		'descendant_wildcard' { cx.PathStepKind.descendant_wildcard }
		'parent' { cx.PathStepKind.parent }
		else { error('program_xml: unknown cx:step kind `${s}`') }
	}
}

// emit_px_call emits `[$fn arg…]` (and the dual-accepted `fn(args)` legacy
// surface) as `<cx:call fn="…">`. The default total/positional/explicit form
// carries args as bare child nodes; the fallible (`?`), must-succeed (`!`),
// bare-reference (no parens — `explicit="false"`), and named-argument
// (`:label v` → `<cx:arg label="…">`) shapes are encoded via attributes /
// arg wrappers so the full cx.ProgramCall surface round-trips structurally.
fn emit_px_call(mut b strings.Builder, n cx.ProgramCall) {
	mut has_label := false
	for l in n.arg_labels {
		if l != '' {
			has_label = true
			break
		}
	}
	b.write_string('<cx:call fn="${px_escape_attr(n.name)}"')
	if n.fallible {
		b.write_string(' fallible="true"')
	}
	if n.must_succeed {
		b.write_string(' must-succeed="true"')
	}
	if !n.explicit_call {
		b.write_string(' explicit="false"')
	}
	b.write_string('>')
	if has_label {
		for i, a in n.args {
			lbl := if i < n.arg_labels.len { n.arg_labels[i] } else { '' }
			b.write_string('<cx:arg label="${px_escape_attr(lbl)}">')
			emit_px_node(mut b, a)
			b.write_string('</cx:arg>')
		}
	} else {
		for a in n.args {
			emit_px_node(mut b, a)
		}
	}
	b.write_string('</cx:call>')
}

// emit_px_wildcard emits a pattern-body wildcard `*` / `**` (cx.ProgramWildcard)
// as `<cx:wildcard deep="true"?/>`.
fn emit_px_wildcard(mut b strings.Builder, n cx.ProgramWildcard) {
	if n.deep {
		b.write_string('<cx:wildcard deep="true"/>')
	} else {
		b.write_string('<cx:wildcard/>')
	}
}

// emit_px_slice_literal emits a first-class slice value `[axes]`
// D10, cx.ProgramSliceLiteral) as `<cx:slice>` wrapping `<cx:axis>` children.
fn emit_px_slice_literal(mut b strings.Builder, n cx.ProgramSliceLiteral) {
	b.write_string('<cx:slice>')
	for ax in n.axes {
		emit_px_axis(mut b, ax)
	}
	b.write_string('</cx:slice>')
}

// emit_px_slice_access emits `$binding[axes]` (cx.ProgramSliceAccess)
// as `<cx:slice-access>` wrapping the binding (`<cx:var>`) and `<cx:axis>`
// children.
fn emit_px_slice_access(mut b strings.Builder, n cx.ProgramSliceAccess) {
	b.write_string('<cx:slice-access>')
	emit_px_binding(mut b, n.binding)
	for ax in n.axes {
		emit_px_axis(mut b, ax)
	}
	b.write_string('</cx:slice-access>')
}

// emit_px_axis emits one cx.SliceAxis as `<cx:axis kind="single|range|full">`
// with optional `<cx:start>`/`<cx:stop>`/`<cx:step>` bound children (any of
// which may be absent for a range; `single` carries only start; `full` none).
fn emit_px_axis(mut b strings.Builder, ax cx.SliceAxis) {
	kind_name := match ax.kind {
		.single { 'single' }
		.range { 'range' }
		.full { 'full' }
	}
	if ax.kind == .full {
		b.write_string('<cx:axis kind="full"/>')
		return
	}
	b.write_string('<cx:axis kind="${kind_name}">')
	if start := ax.start {
		b.write_string('<cx:start>')
		emit_px_node(mut b, start)
		b.write_string('</cx:start>')
	}
	if stop := ax.stop {
		b.write_string('<cx:stop>')
		emit_px_node(mut b, stop)
		b.write_string('</cx:stop>')
	}
	if step := ax.step {
		b.write_string('<cx:step-by>')
		emit_px_node(mut b, step)
		b.write_string('</cx:step-by>')
	}
	b.write_string('</cx:axis>')
}

// emit_px_for_comp emits a for-comprehension (cx.ProgramForComp) as
// `<cx:for-comp outer=… yield-form=…>` wrapping `<cx:clause>` children, a
// mandatory `<cx:yield>` body, and an optional `<cx:yield-value>` (the
// `:yield-map K => V` value expression).
fn emit_px_for_comp(mut b strings.Builder, n cx.ProgramForComp) {
	b.write_string('<cx:for-comp outer="${px_for_form_name(n.outer_form)}" yield-form="${px_yield_form_name(n.yield_form)}">')
	for c in n.clauses {
		emit_px_for_clause(mut b, c)
	}
	b.write_string('<cx:yield>')
	emit_px_node(mut b, n.yield)
	b.write_string('</cx:yield>')
	if yv := n.yield_value {
		b.write_string('<cx:yield-value>')
		emit_px_node(mut b, yv)
		b.write_string('</cx:yield-value>')
	}
	b.write_string('</cx:for-comp>')
}

// emit_px_for_clause emits one for-comprehension clause. Scalar fields
// (kind / bind / direction) ride as attributes; node-bearing fields
// (source / filter-or-binding expr / on-error handler) ride as the
// `<cx:source>`/`<cx:expr>`/`<cx:handler>` child wrappers.
fn emit_px_for_clause(mut b strings.Builder, c cx.ProgramForClause) {
	b.write_string('<cx:clause kind="${px_clause_kind_name(c.kind)}"')
	if c.bind != '' {
		b.write_string(' bind="${px_escape_attr(c.bind)}"')
	}
	if c.direction != '' {
		b.write_string(' direction="${px_escape_attr(c.direction)}"')
	}
	b.write_string('>')
	if s := c.source {
		b.write_string('<cx:source>')
		emit_px_node(mut b, s)
		b.write_string('</cx:source>')
	}
	if e := c.expr {
		b.write_string('<cx:expr>')
		emit_px_node(mut b, e)
		b.write_string('</cx:expr>')
	}
	b.write_string('</cx:clause>')
}

fn px_for_form_name(f cx.ProgramForCompOuterForm) string {
	return match f {
		.sequence { 'sequence' }
		.array { 'array' }
		.map { 'map' }
	}
}

fn px_yield_form_name(f cx.ProgramForCompYieldForm) string {
	return match f {
		.sequence { 'sequence' }
		.array { 'array' }
		.map { 'map' }
	}
}

fn px_for_form_from(s string) !cx.ProgramForCompOuterForm {
	return match s {
		'sequence' { cx.ProgramForCompOuterForm.sequence }
		'array' { cx.ProgramForCompOuterForm.array }
		'map' { cx.ProgramForCompOuterForm.map }
		else { error('program_xml: unknown for-comp outer form `${s}`') }
	}
}

fn px_yield_form_from(s string) !cx.ProgramForCompYieldForm {
	return match s {
		'sequence' { cx.ProgramForCompYieldForm.sequence }
		'array' { cx.ProgramForCompYieldForm.array }
		'map' { cx.ProgramForCompYieldForm.map }
		else { error('program_xml: unknown for-comp yield form `${s}`') }
	}
}

fn px_clause_kind_name(k cx.ProgramForClauseKind) string {
	return match k {
		.generator { 'generator' }
		.filter { 'filter' }
		.binding { 'binding' }
		.order_by { 'order-by' }
		.group_by { 'group-by' }
		.limit { 'limit' }
		.par { 'par' }
		.stream { 'stream' }
		.ordered { 'ordered' }
		.take { 'take' }
		.drop { 'drop' }
		.takewhile { 'takewhile' }
		.dropwhile { 'dropwhile' }
	}
}

fn px_clause_kind_from(s string) !cx.ProgramForClauseKind {
	return match s {
		'generator' { cx.ProgramForClauseKind.generator }
		'filter' { cx.ProgramForClauseKind.filter }
		'binding' { cx.ProgramForClauseKind.binding }
		'order-by' { cx.ProgramForClauseKind.order_by }
		'group-by' { cx.ProgramForClauseKind.group_by }
		'limit' { cx.ProgramForClauseKind.limit }
		'par' { cx.ProgramForClauseKind.par }
		'stream' { cx.ProgramForClauseKind.stream }
		'ordered' { cx.ProgramForClauseKind.ordered }
		'take' { cx.ProgramForClauseKind.take }
		'drop' { cx.ProgramForClauseKind.drop }
		'takewhile' { cx.ProgramForClauseKind.takewhile }
		'dropwhile' { cx.ProgramForClauseKind.dropwhile }
		else { error('program_xml: unknown for-comp clause kind `${s}`') }
	}
}

// emit_px_pattern emits a structural shape-match pattern (cx.ProgramPattern,
// spec/code.md §5) as `<cx:pattern head-kind= value= bind=? direct=?>`
// wrapping `<cx:pattr>` attribute predicates and positional body children
// (themselves cx.ProgramPattern / cx.ProgramBinding / cx.ProgramWildcard).
fn emit_px_pattern(mut b strings.Builder, p cx.ProgramPattern) {
	b.write_string('<cx:pattern head-kind="${px_pattern_head_kind_name(p.head.kind)}" value="${px_escape_attr(p.head.value)}"')
	if p.head.bind != '' {
		b.write_string(' bind="${px_escape_attr(p.head.bind)}"')
	}
	if p.direct {
		b.write_string(' direct="true"')
	}
	b.write_string('>')
	for a in p.attrs {
		emit_px_pattern_attr(mut b, a)
	}
	for it in p.body {
		emit_px_node(mut b, it)
	}
	b.write_string('</cx:pattern>')
}

// emit_px_pattern_attr emits one pattern attribute predicate
// (cx.ProgramPatternAttr) as `<cx:pattr kind= name= op=>value?</cx:pattr>`.
fn emit_px_pattern_attr(mut b strings.Builder, a cx.ProgramPatternAttr) {
	b.write_string('<cx:pattr kind="${px_attr_kind_name(a.kind)}" name="${px_escape_attr(a.name)}" op="${px_escape_attr(a.op)}"')
	if v := a.value {
		b.write_string('>')
		emit_px_node(mut b, v)
		b.write_string('</cx:pattr>')
	} else {
		b.write_string('/>')
	}
}

fn px_pattern_head_kind_name(k cx.ProgramPatternHeadKind) string {
	return match k {
		.named { 'named' }
		.wildcard { 'wildcard' }
		.deep { 'deep' }
		.type_guard { 'type-guard' }
	}
}

fn px_pattern_head_kind_from(s string) !cx.ProgramPatternHeadKind {
	return match s {
		'named' { cx.ProgramPatternHeadKind.named }
		'wildcard' { cx.ProgramPatternHeadKind.wildcard }
		'deep' { cx.ProgramPatternHeadKind.deep }
		'type-guard' { cx.ProgramPatternHeadKind.type_guard }
		else { error('program_xml: unknown pattern head-kind `${s}`') }
	}
}

fn emit_px_directive(mut b strings.Builder, n cx.ProgramDirective) {
	b.write_string('<cx:${n.name}>')
	for s in n.slots {
		if s.kind == .labeled {
			b.write_string('<cx:${s.label}>')
			emit_px_node(mut b, s.value)
			b.write_string('</cx:${s.label}>')
		} else {
			emit_px_node(mut b, s.value)
		}
	}
	b.write_string('</cx:${n.name}>')
}

// ── Read-back ─────────────────────────────────────────────────────────────────

// RawXml is the intermediate parse tree of the emitted XML: a tag name,
// its attributes, and either text content or child elements.
struct RawXml {
mut:
	tag      string
	attrs    map[string]string
	children []RawXml
	text     string
	has_text bool
}

struct PxCursor {
	src []u8
mut:
	pos int
}

// xml_to_program reads the XML image back into a cx.ProgramNode.
pub fn xml_to_program(xml string) !cx.ProgramNode {
	mut c := PxCursor{ src: xml.bytes(), pos: 0 }
	c.skip_ws()
	raw := c.read_element()!
	c.skip_ws()
	if c.pos < c.src.len {
		return error('program_xml: trailing input after root element at ${c.pos}')
	}
	return raw_to_program(raw)!
}

fn (mut c PxCursor) skip_ws() {
	for c.pos < c.src.len {
		b := c.src[c.pos]
		if b == ` ` || b == `\t` || b == `\n` || b == `\r` {
			c.pos++
		} else {
			break
		}
	}
}

// read_element parses one `<tag …>…</tag>` or `<tag …/>` element.
fn (mut c PxCursor) read_element() !RawXml {
	if c.pos >= c.src.len || c.src[c.pos] != `<` {
		return error('program_xml: expected `<` at ${c.pos}')
	}
	c.pos++ // '<'
	tag := c.read_name()
	if tag == '' {
		return error('program_xml: empty tag name at ${c.pos}')
	}
	mut node := RawXml{ tag: tag }
	// Attributes.
	for {
		c.skip_ws()
		if c.pos >= c.src.len {
			return error('program_xml: unterminated start tag `${tag}`')
		}
		b := c.src[c.pos]
		if b == `/` {
			// Self-closing.
			c.pos++
			if c.pos >= c.src.len || c.src[c.pos] != `>` {
				return error('program_xml: malformed self-closing tag `${tag}`')
			}
			c.pos++ // '>'
			return node
		}
		if b == `>` {
			c.pos++ // '>'
			break
		}
		aname := c.read_name()
		if aname == '' {
			return error('program_xml: expected attribute name in `${tag}` at ${c.pos}')
		}
		if c.pos >= c.src.len || c.src[c.pos] != `=` {
			return error('program_xml: expected `=` after attr `${aname}` in `${tag}`')
		}
		c.pos++ // '='
		if c.pos >= c.src.len || c.src[c.pos] != `"` {
			return error('program_xml: expected `"` for attr `${aname}` in `${tag}`')
		}
		c.pos++ // opening quote
		val_start := c.pos
		for c.pos < c.src.len && c.src[c.pos] != `"` {
			c.pos++
		}
		if c.pos >= c.src.len {
			return error('program_xml: unterminated attribute value for `${aname}`')
		}
		raw_val := c.src[val_start..c.pos].bytestr()
		c.pos++ // closing quote
		node.attrs[aname] = px_unescape(raw_val)
	}
	// Content: children and/or text until the matching close tag.
	mut text_b := strings.new_builder(16)
	for {
		if c.pos >= c.src.len {
			return error('program_xml: unterminated element `${tag}`')
		}
		if c.src[c.pos] == `<` {
			if c.pos + 1 < c.src.len && c.src[c.pos + 1] == `/` {
				// Close tag.
				c.pos += 2 // '</'
				close := c.read_name()
				if close != tag {
					return error('program_xml: mismatched close tag: `${close}` closes `${tag}`')
				}
				c.skip_ws()
				if c.pos >= c.src.len || c.src[c.pos] != `>` {
					return error('program_xml: malformed close tag for `${tag}`')
				}
				c.pos++ // '>'
				break
			}
			child := c.read_element()!
			node.children << child
		} else {
			// Text run.
			for c.pos < c.src.len && c.src[c.pos] != `<` {
				text_b.write_u8(c.src[c.pos])
				c.pos++
			}
		}
	}
	t := text_b.str()
	if node.children.len == 0 {
		node.text = px_unescape(t)
		node.has_text = true
	}
	return node
}

// read_name reads an XML name (letters, digits, `:`, `-`, `_`).
fn (mut c PxCursor) read_name() string {
	start := c.pos
	for c.pos < c.src.len {
		b := c.src[c.pos]
		if (b >= `a` && b <= `z`) || (b >= `A` && b <= `Z`) || (b >= `0` && b <= `9`)
		   || b == `:` || b == `-` || b == `_` || b == `.` {
			c.pos++
		} else {
			break
		}
	}
	return c.src[start..c.pos].bytestr()
}

// ── Raw → cx.ProgramNode ─────────────────────────────────────────────────────────

fn raw_to_program(r RawXml) !cx.ProgramNode {
	if !r.tag.starts_with('cx:') {
		// Bareword element `<name>attrs items slots</name>`. Children
		// partition into <cx:attr> attributes, <cx:slot> labeled slots, and
		// positional items; program_node_to_source re-emits in canonical
		// order so cross-category child order need not be preserved.
		mut attrs := []cx.ProgramAttr{}
		mut items := []cx.ProgramNode{}
		mut slots := []cx.ProgramSlot{}
		for ch in r.children {
			if ch.tag == 'cx:attr' {
				aname := ch.attrs['name'] or {
					return error('program_xml: <cx:attr> missing name attribute')
				}
				if ch.children.len != 1 {
					return error('program_xml: <cx:attr> must wrap exactly one value node')
				}
				adt := ch.attrs['type'] or { '' }
				attrs << cx.ProgramAttr{
					name:      aname
					value:     raw_to_program(ch.children[0])!
					data_type: adt
				}
			} else if ch.tag == 'cx:slot' {
				label := ch.attrs['label'] or {
					return error('program_xml: <cx:slot> missing label attribute')
				}
				if ch.children.len != 1 {
					return error('program_xml: <cx:slot> must wrap exactly one value node')
				}
				slots << cx.ProgramSlot{ kind: .labeled, label: label, value: raw_to_program(ch.children[0])! }
			} else {
				items << raw_to_program(ch)!
			}
		}
		return cx.ProgramNode(cx.ProgramLiteral{
			kind:  .cx_element
			name:  r.tag
			attrs: attrs
			items: items
			slots: slots
			pos:   cx.Position{}
		})
	}
	local := r.tag[3..]
	match local {
		'int' {
			return cx.ProgramNode(cx.ProgramLiteral{ kind: .int_lit, int_val: r.text.i64(), pos: cx.Position{} })
		}
		'float' {
			return cx.ProgramNode(cx.ProgramLiteral{ kind: .float_lit, flt_val: r.text.f64(), pos: cx.Position{} })
		}
		'bool' {
			return cx.ProgramNode(cx.ProgramLiteral{ kind: .bool_lit, bool_val: r.text == 'true', pos: cx.Position{} })
		}
		'str' {
			return cx.ProgramNode(cx.ProgramLiteral{ kind: .string_lit, str_val: r.text, pos: cx.Position{} })
		}
		'atom' {
			return cx.ProgramNode(cx.ProgramLiteral{ kind: .atom_lit, str_val: r.text, pos: cx.Position{} })
		}
		'dur' {
			return cx.ProgramNode(cx.ProgramLiteral{ kind: .duration_lit, dur_val: r.text, pos: cx.Position{} })
		}
		'var' {
			if r.children.len == 0 {
				return cx.ProgramNode(cx.ProgramBinding{ name: r.text, pos: cx.Position{} })
			}
			name := r.attrs['name'] or {
				return error('program_xml: <cx:var> with steps missing name attribute')
			}
			mut steps := []cx.ProgramPathStep{}
			for ch in r.children {
				if ch.tag != 'cx:step' {
					return error('program_xml: <cx:var> child must be <cx:step>, got <${ch.tag}>')
				}
				kind := px_step_kind_from(ch.attrs['kind'] or {
					return error('program_xml: <cx:step> missing kind attribute')
				})!
				mut preds := []cx.ProgramPathPredicate{}
				for pch in ch.children {
					preds << raw_to_predicate(pch)!
				}
				steps << cx.ProgramPathStep{ kind: kind, name: ch.attrs['name'] or { '' }, predicates: preds }
			}
			return cx.ProgramNode(cx.ProgramBinding{ name: name, path: steps, pos: cx.Position{} })
		}
		'expr' {
			prog := cx.parse_program(r.text)!
			return prog.body
		}
		'call' {
			fn_name := r.attrs['fn'] or {
				return error('program_xml: <cx:call> missing fn attribute')
			}
			fallible := (r.attrs['fallible'] or { '' }) == 'true'
			must_succeed := (r.attrs['must-succeed'] or { '' }) == 'true'
			explicit := (r.attrs['explicit'] or { 'true' }) != 'false'
			mut args := []cx.ProgramNode{}
			mut labels := []string{}
			mut has_arg_wrapper := false
			for ch in r.children {
				if ch.tag == 'cx:arg' {
					has_arg_wrapper = true
					if ch.children.len != 1 {
						return error('program_xml: <cx:arg> must wrap exactly one value node')
					}
					args << raw_to_program(ch.children[0])!
					labels << (ch.attrs['label'] or { '' })
				} else {
					args << raw_to_program(ch)!
					labels << ''
				}
			}
			return cx.ProgramNode(cx.ProgramCall{
				name:          fn_name
				args:          args
				arg_labels:    if has_arg_wrapper { labels } else { []string{} }
				fallible:      fallible
				must_succeed:  must_succeed
				explicit_call: explicit
				pos:           cx.Position{}
			})
		}
		'wildcard' {
			return cx.ProgramNode(cx.ProgramWildcard{ deep: (r.attrs['deep'] or { '' }) == 'true', pos: cx.Position{} })
		}
		'pattern' {
			hkind := px_pattern_head_kind_from(r.attrs['head-kind'] or {
				return error('program_xml: <cx:pattern> missing head-kind attribute')
			})!
			head := cx.ProgramPatternHead{
				kind:  hkind
				value: r.attrs['value'] or { '' }
				bind:  r.attrs['bind'] or { '' }
			}
			mut pattrs := []cx.ProgramPatternAttr{}
			mut body := []cx.ProgramNode{}
			for ch in r.children {
				if ch.tag == 'cx:pattr' {
					pattrs << raw_to_pattern_attr(ch)!
				} else {
					body << raw_to_program(ch)!
				}
			}
			return cx.ProgramNode(cx.ProgramPattern{
				head:   head
				attrs:  pattrs
				direct: (r.attrs['direct'] or { '' }) == 'true'
				body:   body
				pos:    cx.Position{}
			})
		}
		'slice' {
			mut axes := []cx.SliceAxis{}
			for ch in r.children {
				axes << raw_to_axis(ch)!
			}
			return cx.ProgramNode(cx.ProgramSliceLiteral{ axes: axes, pos: cx.Position{} })
		}
		'slice-access' {
			if r.children.len == 0 || r.children[0].tag != 'cx:var' {
				return error('program_xml: <cx:slice-access> first child must be <cx:var>')
			}
			binding_node := raw_to_program(r.children[0])!
			binding := binding_node as cx.ProgramBinding
			mut axes := []cx.SliceAxis{}
			for i := 1; i < r.children.len; i++ {
				axes << raw_to_axis(r.children[i])!
			}
			return cx.ProgramNode(cx.ProgramSliceAccess{ binding: binding, axes: axes, pos: cx.Position{} })
		}
		'for-comp' {
			outer := px_for_form_from(r.attrs['outer'] or { 'sequence' })!
			yform := px_yield_form_from(r.attrs['yield-form'] or { 'sequence' })!
			mut clauses := []cx.ProgramForClause{}
			mut yield_node := ?cx.ProgramNode(none)
			mut yield_value := ?cx.ProgramNode(none)
			for ch in r.children {
				match ch.tag {
					'cx:clause' {
						clauses << raw_to_clause(ch)!
					}
					'cx:yield' {
						if ch.children.len != 1 {
							return error('program_xml: <cx:yield> must wrap exactly one node')
						}
						yield_node = raw_to_program(ch.children[0])!
					}
					'cx:yield-value' {
						if ch.children.len != 1 {
							return error('program_xml: <cx:yield-value> must wrap exactly one node')
						}
						yield_value = raw_to_program(ch.children[0])!
					}
					else {
						return error('program_xml: unexpected <cx:for-comp> child <${ch.tag}>')
					}
				}
			}
			yn := yield_node or {
				return error('program_xml: <cx:for-comp> missing <cx:yield>')
			}
			return cx.ProgramNode(cx.ProgramForComp{
				clauses:     clauses
				yield:       yn
				yield_value: yield_value
				yield_form:  yform
				outer_form:  outer
				pos:         cx.Position{}
			})
		}
		'seq' {
			return cx.ProgramNode(cx.ProgramLiteral{ kind: .sequence_lit, items: raw_unwrap_items(r)!, pos: cx.Position{} })
		}
		'arr' {
			return cx.ProgramNode(cx.ProgramLiteral{ kind: .array_lit, items: raw_unwrap_items(r)!, pos: cx.Position{} })
		}
		'block' {
			return cx.ProgramNode(cx.ProgramLiteral{ kind: .block, items: raw_unwrap_items(r)!, pos: cx.Position{} })
		}
		'map' {
			mut keys := []string{}
			mut vals := []cx.ProgramNode{}
			for ch in r.children {
				if ch.tag != 'entry' {
					return error('program_xml: <cx:map> child must be <entry>, got <${ch.tag}>')
				}
				k := ch.attrs['key'] or {
					return error('program_xml: <entry> missing key attribute')
				}
				if ch.children.len != 1 {
					return error('program_xml: <entry> must wrap exactly one value node')
				}
				keys << k
				vals << raw_to_program(ch.children[0])!
			}
			return cx.ProgramNode(cx.ProgramLiteral{ kind: .map_lit, keys: keys, items: vals, pos: cx.Position{} })
		}
		'op' {
			op_name := r.attrs['name'] or {
				return error('program_xml: <cx:op> missing name attribute')
			}
			sym := operator_symbol_for(op_name) or {
				return error('program_xml: <cx:op> unknown operator name `${op_name}`')
			}
			mut items := []cx.ProgramNode{}
			for ch in r.children {
				items << raw_to_program(ch)!
			}
			return cx.ProgramNode(cx.ProgramLiteral{
				kind:  .cx_element
				name:  sym
				items: items
				pos:   cx.Position{}
			})
		}
		else {
			// Directive `<cx:DIR>…</cx:DIR>` when DIR is a directive name.
			if cx.is_directive_name(local) {
				mut slots := []cx.ProgramSlot{}
				for ch in r.children {
					if ch.tag.starts_with('cx:') && !px_is_codec_builtin(ch.tag[3..])
					   && !cx.is_directive_name(ch.tag[3..]) {
						// Labeled-slot clause `<cx:LABEL>value</cx:LABEL>`.
						label := ch.tag[3..]
						if ch.children.len != 1 {
							return error('program_xml: labeled clause `<${ch.tag}>` must wrap exactly one node')
						}
						slots << cx.ProgramSlot{
							kind:  .labeled
							label: label
							value: raw_to_program(ch.children[0])!
						}
					} else {
						slots << cx.ProgramSlot{
							kind:  .positional
							value: raw_to_program(ch)!
						}
					}
				}
				return cx.ProgramNode(cx.ProgramDirective{ name: local, slots: slots, pos: cx.Position{} })
			}
			return error('program_xml: unrecognized element `<${r.tag}>`')
		}
	}
}

// raw_unwrap_items reads the `<item>NODE</item>` children of a cx:seq /
// cx:arr wrapper, returning the inner nodes.
fn raw_unwrap_items(r RawXml) ![]cx.ProgramNode {
	mut items := []cx.ProgramNode{}
	for ch in r.children {
		if ch.tag != 'item' {
			return error('program_xml: <cx:${r.tag[3..]}> child must be <item>, got <${ch.tag}>')
		}
		if ch.children.len != 1 {
			return error('program_xml: <item> must wrap exactly one node')
		}
		items << raw_to_program(ch.children[0])!
	}
	return items
}

// raw_to_pattern_attr reads one `<cx:pattr>` element back into a
// cx.ProgramPatternAttr (the inverse of emit_px_pattern_attr).
fn raw_to_pattern_attr(r RawXml) !cx.ProgramPatternAttr {
	kind := px_attr_kind_from(r.attrs['kind'] or {
		return error('program_xml: <cx:pattr> missing kind attribute')
	})!
	mut val := ?cx.ProgramNode(none)
	if r.children.len == 1 {
		val = raw_to_program(r.children[0])!
	} else if r.children.len > 1 {
		return error('program_xml: <cx:pattr> must wrap at most one value node')
	}
	return cx.ProgramPatternAttr{
		kind:  kind
		name:  r.attrs['name'] or { '' }
		op:    r.attrs['op'] or { '' }
		value: val
	}
}

// raw_to_clause reads one `<cx:clause>` element back into a cx.ProgramForClause
// (the inverse of emit_px_for_clause).
fn raw_to_clause(r RawXml) !cx.ProgramForClause {
	kind := px_clause_kind_from(r.attrs['kind'] or {
		return error('program_xml: <cx:clause> missing kind attribute')
	})!
	mut source := ?cx.ProgramNode(none)
	mut expr := ?cx.ProgramNode(none)
	for ch in r.children {
		if ch.children.len != 1 {
			return error('program_xml: <${ch.tag}> clause field must wrap exactly one node')
		}
		v := raw_to_program(ch.children[0])!
		match ch.tag {
			'cx:source' { source = v }
			'cx:expr' { expr = v }
			else { return error('program_xml: unexpected <cx:clause> child <${ch.tag}>') }
		}
	}
	return cx.ProgramForClause{
		kind:      kind
		bind:      r.attrs['bind'] or { '' }
		source:    source
		expr:      expr
		direction: r.attrs['direction'] or { '' }
	}
}

// raw_to_axis reads one `<cx:axis>` element back into a cx.SliceAxis (the
// inverse of emit_px_axis).
fn raw_to_axis(r RawXml) !cx.SliceAxis {
	if r.tag != 'cx:axis' {
		return error('program_xml: slice child must be <cx:axis>, got <${r.tag}>')
	}
	kind_s := r.attrs['kind'] or { return error('program_xml: <cx:axis> missing kind attribute') }
	kind := match kind_s {
		'single' { cx.SliceAxisKind.single }
		'range' { cx.SliceAxisKind.range }
		'full' { cx.SliceAxisKind.full }
		else { return error('program_xml: unknown <cx:axis> kind `${kind_s}`') }
	}
	mut start := ?cx.ProgramNode(none)
	mut stop := ?cx.ProgramNode(none)
	mut step := ?cx.ProgramNode(none)
	for ch in r.children {
		if ch.children.len != 1 {
			return error('program_xml: <${ch.tag}> bound must wrap exactly one node')
		}
		v := raw_to_program(ch.children[0])!
		match ch.tag {
			'cx:start' { start = v }
			'cx:stop' { stop = v }
			'cx:step-by' { step = v }
			else { return error('program_xml: unexpected <cx:axis> child <${ch.tag}>') }
		}
	}
	return cx.SliceAxis{ kind: kind, start: start, stop: stop, step: step, pos: cx.Position{} }
}

// raw_to_predicate reads one `<cx:pred>` element back into a
// cx.ProgramPathPredicate (the inverse of emit_px_predicate).
fn raw_to_predicate(r RawXml) !cx.ProgramPathPredicate {
	if r.tag != 'cx:pred' {
		return error('program_xml: <cx:step> child must be <cx:pred>, got <${r.tag}>')
	}
	kind := r.attrs['kind'] or { return error('program_xml: <cx:pred> missing kind attribute') }
	match kind {
		'position' {
			idx := r.attrs['index'] or { return error('program_xml: position <cx:pred> missing index') }
			return cx.ProgramPathPredicate{ kind: .position, int_index: idx.i64(), pos: cx.Position{} }
		}
		'attr' {
			attr_kind := px_attr_kind_from(r.attrs['attr-kind'] or {
				return error('program_xml: attr <cx:pred> missing attr-kind')
			})!
			mut val := ?cx.ProgramNode(none)
			if r.children.len == 1 {
				val = raw_to_program(r.children[0])!
			} else if r.children.len > 1 {
				return error('program_xml: attr <cx:pred> must wrap at most one value node')
			}
			return cx.ProgramPathPredicate{
				kind:       .attr_test
				attr_kind:  attr_kind
				attr_name:  r.attrs['name'] or { '' }
				attr_op:    r.attrs['op'] or { '' }
				attr_value: val
				pos:        cx.Position{}
			}
		}
		'expr' {
			mut body := ?cx.ProgramNode(none)
			if r.children.len == 1 {
				body = raw_to_program(r.children[0])!
			} else if r.children.len > 1 {
				return error('program_xml: expr <cx:pred> must wrap at most one body node')
			}
			return cx.ProgramPathPredicate{ kind: .expr, body: body, pos: cx.Position{} }
		}
		else {
			return error('program_xml: unknown <cx:pred> kind `${kind}`')
		}
	}
}

// operator_symbol_for is the inverse of operator_xml_names.
fn operator_symbol_for(op_name string) ?string {
	for sym, name in operator_xml_names {
		if name == op_name {
			return sym
		}
	}
	return none
}

// px_is_codec_builtin reports whether a cx: local-name is one of the codec's
// reserved value/structure tags (so it is NOT a directive labeled-slot clause).
fn px_is_codec_builtin(local string) bool {
	return local in ['int', 'float', 'bool', 'str', 'atom', 'dur', 'var', 'expr',
		'call', 'op', 'seq', 'arr', 'map', 'block', 'wildcard', 'slice', 'slice-access',
		'for-comp', 'pattern']
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn px_is_xml_name(s string) bool {
	if s.len == 0 {
		return false
	}
	b0 := s[0]
	if !((b0 >= `a` && b0 <= `z`) || (b0 >= `A` && b0 <= `Z`) || b0 == `_`) {
		return false
	}
	for i := 1; i < s.len; i++ {
		b := s[i]
		if !((b >= `a` && b <= `z`) || (b >= `A` && b <= `Z`) || (b >= `0` && b <= `9`)
		   || b == `-` || b == `_` || b == `.`) {
			return false
		}
	}
	return true
}

fn px_escape(s string) string {
	mut out := s.replace('&', '&amp;')
	out = out.replace('<', '&lt;')
	out = out.replace('>', '&gt;')
	return out
}

fn px_escape_attr(s string) string {
	return px_escape(s).replace('"', '&quot;')
}

fn px_unescape(s string) string {
	mut out := s.replace('&quot;', '"')
	out = out.replace('&gt;', '>')
	out = out.replace('&lt;', '<')
	out = out.replace('&amp;', '&')
	return out
}
