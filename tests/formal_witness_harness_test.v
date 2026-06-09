module main

import cx
import os

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  FORMAL PARSE-LAYER WITNESS HARNESS                                         ║
// ╚══════════════════════════════════════════════════════════════════════════╝
// Turns the CX→XML / CX→<cx:err> witnesses in spec/02-inprogress/formal/ into
// executable conformance tests (cxparse unification "implement-against-the-
// witnesses" convergence phase).
//
// The witness corpus is vcx/tests/formal/witnesses.txt (transcribed verbatim).
// This file carries a DEDICATED conformance emitter (emit_formal_*) that maps
// the EXISTING cx parse tree to the contract's canonical XML per the M-* rules
// in parser-rules-for-cx-meaning.txt. It is intentionally SEPARATE from the
// shipping cx.emit_xml (which uses a different canonical form: <cx:arr>/<item>
// wrappers, xml:id, indentation) — the point is to test "what tree does the
// parser produce", expressed in the contract's image, WITHOUT disturbing the
// shipping serialization surface (N2).
//
// Pass 1 runs the DATA-mode witnesses; program-mode rows (calls/bindings/paths/
// slices) are deferred to the program-mode emitter pass. Each row's result is
// classified and written to a triage report; the test itself never fails (the
// report is the convergence signal — every mismatch is either an impl bug or a
// spec corner the contract got wrong, triaged by hand against the invariants).

// ── XML escaping (the contract's escape(), local to the harness) ──────────────

fn esc_text(s string) string {
	// The contract's escape() renders control whitespace as numeric character
	// references (witness LX-ESCAPE-1: '\n' decodes to a newline, imaged &#10;).
	return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('\n',
		'&#10;').replace('\r', '&#13;').replace('\t', '&#9;')
}

fn esc_attr(s string) string {
	return s.replace('&', '&amp;').replace('<', '&lt;').replace('"', '&quot;')
}

// ── render(Scalar{T,v}) — canonical scalar printer (§HELPERS) ─────────────────

fn render_scalar(n cx.ScalarNode) string {
	return cx.scalar_value_str_public(n.value)
}

// ── ximg_wrapped: a node's image in COLLECTION-ITEM / isolation position ──────
// (strings wrap as <cx:string>; this is also the node-in-isolation image used
// for kind=node witnesses and for M-DOC's wrapped roots).

fn ximg_wrapped(n cx.Node) string {
	match n {
		cx.Element {
			return emit_formal_element(n)
		}
		cx.ScalarNode {
			if n.data_type == .atom_type {
				return '<cx:atom>${esc_text(render_scalar(n))}</cx:atom>'
			}
			if n.data_type == .null_type {
				return '<cx:null/>'
			}
			if n.data_type == .string_type {
				return '<cx:string>${esc_text(render_scalar(n))}</cx:string>'
			}
			tn := cx.scalar_type_name_public(n.data_type)
			return '<cx:${tn}>${esc_text(render_scalar(n))}</cx:${tn}>'
		}
		cx.TextNode {
			return '<cx:string>${esc_text(n.value)}</cx:string>'
		}
		cx.ArrayNode {
			mut b := ''
			for it in n.items {
				b += ximg_wrapped(it)
			}
			return '<cx:array>${b}</cx:array>'
		}
		cx.SequenceNode {
			mut b := ''
			for it in n.items {
				b += ximg_wrapped(it)
			}
			return '<cx:seq>${b}</cx:seq>'
		}
		cx.MapNode {
			mut b := ''
			for e in n.entries {
				key := cx.ScalarNode{
					data_type: e.key_type
					value:     e.key_value
				}
				b += '<cx:entry><cx:key>${ximg_wrapped(key)}</cx:key><cx:val>${ximg_wrapped(e.value)}</cx:val></cx:entry>'
			}
			return '<cx:map>${b}</cx:map>'
		}
		cx.AliasNode {
			return '<cx:alias cx:name="${esc_attr(n.name)}"/>'
		}
		cx.CommentNode {
			// LX-WS: a `#` LINE comment is trivia (skipped, never a token) — it
			// is dropped from the semantic image (LX-WS-2). The impl preserves it
			// as a CommentNode{is_line:true} in the parse tree for lossless
			// `cx fmt` round-trip, but it carries no CX→XML meaning. A `[- … ]`
			// BLOCK comment is a real Comment NODE and images via M-COMMENT.
			if n.is_line {
				return ''
			}
			return comment_img(n)
		}
		cx.RawTextNode {
			return raw_img(n)
		}
		cx.EntityRefNode {
			return '<cx:entity-ref cx:name="${esc_attr(n.name)}"/>'
		}
		cx.PINode {
			return pi_img(n)
		}
		cx.XMLDeclNode {
			// M-PI: the reserved `xml` target falls back to the PI CARRIER
			// (`<?xml?>` is an illegal PI target). The data parser captures the
			// pseudo-attributes structurally as an XMLDeclNode; reconstruct the
			// source-form data string (`version=… encoding=… standalone=…`) and
			// image it through the carrier (M-PI-3).
			mut parts := ['version=${n.version}']
			if enc := n.encoding {
				parts << 'encoding=${enc}'
			}
			if sa := n.standalone {
				parts << 'standalone=${sa}'
			}
			return '<cx:pi cx:target="xml">${esc_text(parts.join(' '))}</cx:pi>'
		}
		cx.EvalDirectiveNode {
			mut b := ''
			for it in n.items {
				b += ximg_wrapped(it)
			}
			return '<cx:directive cx:head="${esc_attr(n.name)}">${b}</cx:directive>'
		}
		cx.EntityDeclNode {
			// M-DECL: ENTITY images as native XML, raw-preserved.
			marker := if n.kind == .pe { '% ' } else { '' }
			def := n.def
			ds := if def is string { "'${def}'" } else { 'EXTERNAL' }
			return '<!ENTITY ${marker}${n.name} ${ds}>'
		}
		else {
			return '<cx:UNHANDLED-NODE(${typeof(n).name})/>'
		}
	}
}

// ── ximg_body: a node's image as an ELEMENT BODY child (strings are BARE text) ─

fn ximg_body(n cx.Node) string {
	if n is cx.TextNode {
		return esc_text(n.value)
	}
	if n is cx.ScalarNode {
		if n.data_type == .string_type {
			return esc_text(render_scalar(n))
		}
	}
	return ximg_wrapped(n)
}

// ── M-COMMENT / M-RAW / M-PI images ───────────────────────────────────────────

fn comment_img(c cx.CommentNode) string {
	if c.value.contains('--') {
		return '<cx:comment>${esc_text(c.value)}</cx:comment>'
	}
	return '<!--${c.value}-->'
}

fn raw_img(r cx.RawTextNode) string {
	content := r.value.replace(']]>', ']]><![CDATA[>')
	return '<![CDATA[${content}]]>'
}

fn pi_img(p cx.PINode) string {
	data := p.data or { '' }
	if data == '' {
		return '<?${p.target}?>'
	}
	if p.target != 'xml' && !data.contains('?>') {
		return '<?${p.target} ${data}?>'
	}
	return '<cx:pi cx:target="${esc_attr(p.target)}">${esc_text(data)}</cx:pi>'
}

// ── elem_cx_type: the cx:type value for an element's A(m) (head ann OR sole) ───

fn elem_cx_type(e cx.Element) string {
	if hd := e.data_type() {
		return hd
	}
	if e.items.len == 1 {
		it := e.items[0]
		if it is cx.ScalarNode {
			if it.data_type == .string_type || it.data_type == .atom_type {
				return ''
			}
			if it.data_type == .null_type {
				return 'null'
			}
			return cx.scalar_type_name_public(it.data_type)
		}
	}
	return ''
}

// ── sidecar: the cx:attr-types value (D3 + M-NULL mandatory null) ─────────────

fn sidecar(attrs []cx.Attribute) ?string {
	mut parts := []string{}
	for a in attrs {
		if a.is_ref {
			continue
		}
		if dt := a.data_type() {
			if dt == 'null' {
				parts << '${a.name}=null'
			} else if dt == 'string' {
				if cx.cx_would_autotype(cx.scalar_value_str_public(a.value)) {
					parts << '${a.name}=string'
				}
			} else if !cx.type_name_is_auto_recoverable(dt) {
				parts << '${a.name}=${dt}'
			}
		} else {
			if cx.cx_would_autotype(cx.scalar_value_str_public(a.value)) {
				parts << '${a.name}=string'
			}
		}
	}
	if parts.len == 0 {
		return none
	}
	return parts.join(' ')
}

// ── A(m): the canonical-order attribute section ───────────────────────────────

fn attr_section(e cx.Element) string {
	mut s := ''
	if a := e.anchor() {
		s += ' cx:anchor="${esc_attr(a)}"'
	}
	if m := e.merge() {
		s += ' cx:merge="${esc_attr(m)}"'
	}
	if id := e.id() {
		s += ' cx:id="${esc_attr(id)}"'
	}
	ct := elem_cx_type(e)
	if ct != '' {
		s += ' cx:type="${ct}"'
	}
	for at in e.attrs {
		dt := at.data_type() or { '' }
		if dt == 'null' {
			continue
		}
		s += ' ${at.name}="${esc_attr(cx.scalar_value_str_public(at.value))}"'
	}
	if sc := sidecar(e.attrs) {
		s += ' cx:attr-types="${esc_attr(sc)}"'
	}
	return s
}

// ── M-ELEMENT / M-SCALAR-SOLE / M-TYPED-ARRAY ─────────────────────────────────

fn emit_formal_element(e cx.Element) string {
	a := attr_section(e)
	head_dt := e.data_type() or { '' }

	// M-TYPED-ARRAY: head ::T[] / ::[]
	if head_dt.ends_with('[]') {
		base := head_dt#[..-2]
		mut b := ''
		for it in e.items {
			if base == '' {
				// ::[] inferred array (P2-INFERARR): items keep their OWN type —
				// image each via its self type (`<cx:int>`, `<cx:float>`, …), with
				// cx:type="[]" carried in the attr section. NOT `<cx:>`.
				b += ximg_wrapped(it)
			} else if it is cx.ScalarNode {
				b += '<cx:${base}>${esc_text(render_scalar(it))}</cx:${base}>'
			} else {
				b += ximg_wrapped(it)
			}
		}
		return '<${e.name}${a}>${b}</${e.name}>'
	}

	if e.items.len == 0 {
		return '<${e.name}${a}/>'
	}

	// sole-child shapes
	if e.items.len == 1 {
		it := e.items[0]
		if it is cx.ScalarNode {
			if it.data_type == .null_type {
				return '<${e.name}${a}/>' // M-NULL (cx:type="null" in A)
			}
			if it.data_type == .atom_type {
				return '<${e.name}${a}><cx:atom>${esc_text(render_scalar(it))}</cx:atom></${e.name}>'
			}
			if it.data_type == .string_type {
				return '<${e.name}${a}>${esc_text(render_scalar(it))}</${e.name}>'
			}
			// non-string scalar sole → bare render, cx:type in A (M-SCALAR-SOLE)
			return '<${e.name}${a}>${esc_text(render_scalar(it))}</${e.name}>'
		}
	}

	// general body
	mut b := ''
	for it in e.items {
		b += ximg_body(it)
	}
	return '<${e.name}${a}>${b}</${e.name}>'
}

// ── M-DOC: whole-document image ───────────────────────────────────────────────

fn emit_formal_doc(doc cx.Document) string {
	mut roots := []cx.Node{}
	roots << doc.prolog
	roots << doc.elements
	if roots.len == 1 {
		r := roots[0]
		if r is cx.Element {
			return emit_formal_element(r)
		}
		return '<cx:docs>${ximg_wrapped(r)}</cx:docs>'
	}
	mut b := ''
	for r in roots {
		b += ximg_wrapped(r)
	}
	return '<cx:docs>${b}</cx:docs>'
}

// ── M-DOC multidoc image ('---'-separated documents) ─────────────────────────

fn emit_formal_multidoc(docs []cx.Document) string {
	mut b := ''
	for d in docs {
		mut roots := []cx.Node{}
		roots << d.prolog
		roots << d.elements
		mut inner := ''
		for r in roots {
			inner += ximg_wrapped(r)
		}
		b += '<cx:doc>${inner}</cx:doc>'
	}
	return '<cx:docs>${b}</cx:docs>'
}

// ── node-in-isolation image (kind=node) ───────────────────────────────────────

fn emit_formal_single_node(doc cx.Document) !string {
	mut roots := []cx.Node{}
	roots << doc.prolog
	roots << doc.elements
	if roots.len != 1 {
		return error('expected exactly one root node, got ${roots.len}')
	}
	return ximg_wrapped(roots[0])
}

// ── M-PROGRAM: the program-AST conformance emitter ────────────────────────────
//
// Program-mode witnesses parse with `cx.parse_program` and image the resulting
// ProgramNode tree per the M-PROGRAM rule in parser-rules-for-cx-meaning.txt:
//   Form{call,h,b}      ⇒ <cx:call cx:head="h">map(ximg,b)</cx:call>
//   Form{directive,h,b} ⇒ <cx:directive cx:head="h" A(m)>map(ximg,b)</cx:directive>
//   Binding{n}          ⇒ <cx:var cx:name="n"/>
//   Path{steps}         ⇒ <cx:path>…</cx:path>
//   Slice{axes}         ⇒ <cx:slice>…</cx:slice>
// Like the data emitter this is SEPARATE from the shipping program XML codec —
// it tests "what tree does parse_program produce", expressed in the contract image.

// program_op_heads: the OpSym ∪ reserved-word-op set whose appearance as a
// bracket head ([G-BRACKET]) makes the form a CALL, not an element construction.
// (`OpSym ::= '+'|'-'|'*'|'/'|'='|'!='|'<'|'<='|'>'|'>='`; reserved word ops
// `and|or|not|cast` per grammar.ebnf line 60.) The data parser represents these
// as a `.cx_element` ProgramLiteral whose `name` is the operator string.
const program_op_heads = ['+', '-', '*', '/', '=', '!=', '<', '<=', '>', '>=', 'and', 'or',
	'not', 'cast']

fn ximg_program(n cx.ProgramNode) string {
	match n {
		cx.Program {
			return ximg_program(n.body)
		}
		cx.ProgramCall {
			mut b := ''
			for a in n.args {
				b += ximg_program(a)
			}
			return '<cx:call cx:head="${esc_attr(n.name)}">${b}</cx:call>'
		}
		cx.ProgramBinding {
			// Binding{n} ⇒ <cx:var cx:name="n"/>. A binding carrying path steps
			// would image as <cx:path> (no witness exercises it yet).
			return '<cx:var cx:name="${esc_attr(n.name)}"/>'
		}
		cx.ProgramLiteral {
			return ximg_program_literal(n)
		}
		cx.ProgramDirective {
			mut b := ''
			for s in n.slots {
				b += ximg_program(s.value)
			}
			return '<cx:directive cx:head="${esc_attr(n.name)}">${b}</cx:directive>'
		}
		else {
			return '<cx:UNHANDLED-PROGRAM(${typeof(n).name})/>'
		}
	}
}

fn ximg_program_literal(l cx.ProgramLiteral) string {
	match l.kind {
		.int_lit {
			return '<cx:int>${l.int_val}</cx:int>'
		}
		.float_lit {
			return '<cx:float>${l.flt_val}</cx:float>'
		}
		.bool_lit {
			return '<cx:bool>${l.bool_val}</cx:bool>'
		}
		.string_lit {
			return '<cx:string>${esc_text(l.str_val)}</cx:string>'
		}
		.atom_lit {
			return '<cx:atom>${esc_text(l.str_val)}</cx:atom>'
		}
		.cx_element {
			// [G-BRACKET]: an operator / reserved-word-op head ⇒ op-Form ⇒ call.
			if l.name in program_op_heads {
				mut b := ''
				for it in l.items {
					b += ximg_program(it)
				}
				return '<cx:call cx:head="${esc_attr(l.name)}">${b}</cx:call>'
			}
			// QName head ⇒ element construction (no program-mode element witness
			// yet; image best-effort as a bare element).
			mut b := ''
			for it in l.items {
				b += ximg_program(it)
			}
			return '<${l.name}>${b}</${l.name}>'
		}
		else {
			return '<cx:UNHANDLED-LITERAL(${l.kind})/>'
		}
	}
}

fn emit_formal_program(prog cx.Program) string {
	return ximg_program(prog.body)
}

// ── error-code extraction (code token out of the CxError message) ─────────────
//
// Handles both the program `CXER…` range (`core/code.md` §9.5) and the
// data-parse `E…` range (`core/cxdm.md` §11). Both ride the `cx-err:` carrier
// in the message (e.g. `… (cx-err:E210)` / `… (cx-err:CXER0241)`); keying on
// the carrier avoids matching a stray `CXER`/`E` word in prose.
fn extract_code(msg string) string {
	if ci := msg.index('cx-err:') {
		start := ci + 'cx-err:'.len
		mut end := start
		for end < msg.len {
			c := msg[end]
			if (c >= `A` && c <= `Z`) || (c >= `0` && c <= `9`) || c == `-` {
				end++
			} else {
				break
			}
		}
		return msg[start..end]
	}
	// Fallback: a bare `CXER…` token with no `cx-err:` carrier.
	idx := msg.index('CXER') or { return '' }
	mut end := idx
	for end < msg.len {
		c := msg[end]
		if (c >= `A` && c <= `Z`) || (c >= `0` && c <= `9`) || c == `-` {
			end++
		} else {
			break
		}
	}
	return msg[idx..end]
}

fn expected_code(expect string) string {
	// expect like: <cx:err code="CXER0100" offset="4"/>
	marker := 'code="'
	idx := expect.index(marker) or { return '' }
	rest := expect[idx + marker.len..]
	q := rest.index('"') or { return rest }
	return rest[..q]
}

fn expected_offset(expect string) string {
	marker := 'offset="'
	idx := expect.index(marker) or { return '' }
	rest := expect[idx + marker.len..]
	q := rest.index('"') or { return rest }
	return rest[..q]
}

// ── the runner ────────────────────────────────────────────────────────────────

struct Row {
	id     string
	mode   string
	kind   string
	input  string
	expect string
}

fn load_rows() []Row {
	path := os.join_path(@VMODROOT, 'tests', 'formal', 'witnesses.txt')
	raw := os.read_file(path) or { panic('cannot read witness corpus: ${err}') }
	mut rows := []Row{}
	for line in raw.split_into_lines() {
		t := line.trim_space()
		if t == '' || t.starts_with('#') {
			continue
		}
		parts := line.split('\t')
		if parts.len != 5 {
			continue
		}
		rows << Row{
			id:     parts[0]
			mode:   parts[1]
			kind:   parts[2]
			input:  parts[3].replace('<NL>', '\n')
			expect: parts[4]
		}
	}
	return rows
}

fn test_formal_witnesses() {
	rows := load_rows()
	mut report := []string{}
	report << '# Formal parse-layer witness triage (cxparse implement-against-witnesses)'
	report << ''
	report << 'Generated by vcx/tests/formal_witness_harness_test.v over'
	report << 'vcx/tests/formal/witnesses.txt. PASS = the existing cx parse tree, imaged'
	report << 'through the contract emitter, matches the witness exactly.'
	report << ''

	mut n_pass := 0
	mut n_fail := 0
	n_deferred := 0 // program-mode rows now run (pass 2); none deferred
	mut fails := []string{}

	for r in rows {
		if r.mode == 'program' {
			// Program-mode pass: parse with cx.parse_program; err rows compare the
			// CXER code, node rows image the ProgramNode tree via emit_formal_program.
			if r.kind == 'err' {
				want := expected_code(r.expect)
				prog := cx.parse_program(r.input) or {
					got := extract_code(err.msg())
					if got == want {
						n_pass++
					} else {
						n_fail++
						fails << '- **${r.id}** ERR-CODE(program)  input=`${vis(r.input)}`  want=`${want}` got=`${got}`  (msg: ${err.msg()})'
					}
					continue
				}
				_ := prog
				n_fail++
				fails << '- **${r.id}** ERR-ACCEPTED(program)  input=`${vis(r.input)}`  contract rejects with `${want}` but parse_program ACCEPTED'
				continue
			}
			// node / doc
			prog := cx.parse_program(r.input) or {
				n_fail++
				fails << '- **${r.id}** PARSE-ERR(program)  input=`${vis(r.input)}`  (${err.msg()})  want=`${r.expect}`'
				continue
			}
			got := emit_formal_program(prog)
			if got == r.expect {
				n_pass++
			} else {
				n_fail++
				fails << '- **${r.id}** MISMATCH(program)  input=`${vis(r.input)}`\n    want: `${r.expect}`\n    got:  `${got}`'
			}
			continue
		}
		if r.kind == 'err' {
			want := expected_code(r.expect)
			want_off := expected_offset(r.expect)
			cx.parse(r.input) or {
				got := extract_code(err.msg())
				if got == want {
					n_pass++
				} else {
					n_fail++
					fails << '- **${r.id}** ERR-CODE  input=`${vis(r.input)}`  want=`${want}` got=`${got}`  (msg: ${err.msg()})'
				}
				continue
			}
			// parse SUCCEEDED but contract rejects
			n_fail++
			fails << '- **${r.id}** ERR-ACCEPTED  input=`${vis(r.input)}`  contract rejects with `${want}`@${want_off} but impl ACCEPTED'
			continue
		}

		// multi-document ('---'-separated) — uses the stream entry, M-DOC multidoc image
		if r.kind == 'doc' && r.input.contains('\n---') {
			docs := cx.parse_stream(r.input) or {
				n_fail++
				fails << '- **${r.id}** MULTIDOC-PARSE-ERR  input=`${vis(r.input)}`  (${err.msg()})'
				continue
			}
			got := emit_formal_multidoc(docs)
			if got == r.expect {
				n_pass++
			} else {
				n_fail++
				fails << '- **${r.id}** MISMATCH(multidoc)  input=`${vis(r.input)}`\n    want: `${r.expect}`\n    got:  `${got}`'
			}
			continue
		}

		// doc / node
		doc := cx.parse(r.input) or {
			n_fail++
			fails << '- **${r.id}** PARSE-ERR  input=`${vis(r.input)}`  (${err.msg()})  want=`${r.expect}`'
			continue
		}
		got := if r.kind == 'node' {
			emit_formal_single_node(doc) or {
				n_fail++
				fails << '- **${r.id}** NODE-EXTRACT  input=`${vis(r.input)}`  (${err.msg()})'
				continue
			}
		} else {
			emit_formal_doc(doc)
		}
		if got == r.expect {
			n_pass++
		} else {
			n_fail++
			fails << '- **${r.id}** MISMATCH  input=`${vis(r.input)}`\n    want: `${r.expect}`\n    got:  `${got}`'
		}
	}

	total_run := n_pass + n_fail
	report << '## Summary'
	report << ''
	report << '- witnesses run (data + program): **${total_run}**'
	report << '- PASS: **${n_pass}**'
	report << '- FAIL (triage): **${n_fail}**'
	report << '- program-mode deferred: **${n_deferred}**'
	report << '- total corpus rows: **${rows.len}**'
	report << ''
	report << '## Failures (each is an impl bug OR a spec corner — triaged by hand)'
	report << ''
	for f in fails {
		report << f
	}
	report << ''

	out_dir := os.join_path(@VMODROOT, '..', '_gate_evidence')
	os.mkdir_all(out_dir) or {}
	os.write_file(os.join_path(out_dir, 'formal_witness_triage.md'), report.join('\n')) or {
		panic('cannot write triage report: ${err}')
	}

	// Pass 1 is exploratory — the report is the artifact; do not fail the suite.
	// A regression guard (assert n_fail <= baseline) lands once convergence starts.
	assert n_pass + n_fail + n_deferred == rows.len
}

// vis renders control chars in an input for the report (newline → \n).
fn vis(s string) string {
	return s.replace('\n', '\\n')
}
