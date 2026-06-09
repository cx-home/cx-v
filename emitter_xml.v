module cx

// ── XML Emitter ───────────────────────────────────────────────────────────────

pub fn emit_xml(doc Document) string {
	return emit_xml_impl(doc, false)
}

// emit_xml_lossless renders the lossless XML image (conversions.md §0.2): each
// typed scalar carries its type — a single-scalar element body gets a
// `cx:type="T"` attribute, and a multi-item body emits per-item `<cx:T>`
// carriers (incl. `<cx:string>` so adjacent string items keep their boundary,
// which the idiomatic form collapses). The default (lossy) form is unchanged.
pub fn emit_xml_lossless(doc Document) string {
	return emit_xml_impl(doc, true)
}

fn emit_xml_impl(doc Document, lossless bool) string {
	mut out := []string{}
	for n in doc.prolog { emit_xml_node(n, 0, lossless, mut out) }
	if dt := doc.doctype { emit_xml_doctype(dt, lossless, mut out) }
	for n in doc.elements { emit_xml_node(n, 0, lossless, mut out) }
	result := out.join('')
	return result.trim_right('\n')
}

pub fn emit_xml_docs(docs []Document) string {
	parts := docs.map(emit_xml(it))
	return parts.join('\n---\n')
}

pub fn emit_xml_docs_lossless(docs []Document) string {
	parts := docs.map(emit_xml_lossless(it))
	return parts.join('\n---\n')
}

fn xml_indent(depth int) string {
	mut s := ''
	for _ in 0..depth { s += '  ' }
	return s
}

fn emit_xml_node(n Node, depth int, lossless bool, mut out []string) {
	match n {
		Element          { emit_xml_element(n, depth, lossless, mut out) }
		TextNode         { out << xml_escape_text(n.value) }
		ScalarNode       { out << xml_scalar_text(n) }
		CommentNode      { out << '${xml_indent(depth)}<!--${n.value}-->\n' }
		PINode           { emit_xml_pi(n, depth, mut out) }
		XMLDeclNode      { emit_xml_decl(n, mut out) }
		CXDirectiveNode  { emit_xml_cx_directive(n, mut out) }
		EntityRefNode    { out << '&${n.name};' }
		RawTextNode      { emit_xml_raw_text(n, mut out) }
		AliasNode        { out << '${xml_indent(depth)}<cx:alias name="${n.name}"/>\n' }
		EntityDeclNode   { emit_xml_entity_decl(n, depth, mut out) }
		ElementDeclNode  { out << '${xml_indent(depth)}<!ELEMENT ${n.name} ${n.contentspec}>\n' }
		AttlistDeclNode  { emit_xml_attlist_decl(n, depth, mut out) }
		NotationDeclNode { emit_xml_notation_decl(n, depth, mut out) }
		PEReferenceNode  { out << '${xml_indent(depth)}%${n.name};\n' }
		DoctypeDecl      { emit_xml_doctype(n, lossless, mut out) }
		ConditionalSectNode { emit_xml_conditional_sect(n, depth, lossless, mut out) }
		BlockContentNode {
			out << '${xml_indent(depth)}<cx:block>'
			for item in n.items { emit_xml_inline_node(item, lossless, mut out) }
			out << '</cx:block>\n'
		}
		InterpolationNode {
			// v3.5: no XML-native equivalent for CX code
			// interpolation; emit as a cx-namespaced PI carrying the
			// expression. Round-trips via xml_parser when re-read.
			out << '${xml_indent(depth)}<?cx:interp ${xml_escape_attr(n.expr)}?>\n'
		}
		EvalDirectiveNode {
			emit_xml_eval_directive(n, depth, lossless, mut out)
		}
		SequenceNode { emit_xml_sequence(n, depth, lossless, mut out) }
		ArrayNode    { emit_xml_array(n, depth, lossless, mut out) }
		MapNode      { emit_xml_map(n, depth, lossless, mut out) }
		IteratorNode {
			// materialize to Sequence form at the host
			// (XML) boundary. Renders memo as `<cx:seq>…</cx:seq>`.
			emit_xml_sequence(iterator_to_sequence(n), depth, lossless, mut out)
		}
		MatchNode    {
			// v0.8.0 — no XML-native equivalent for the
			// CX `[?match]` value kind; round-trip via a cx-namespaced
			// PI carrying the verbatim source-text snippet. Matches
			// the InterpolationNode convention above.
			src := n.source or { '' }
			out << '${xml_indent(depth)}<?cx:match ${xml_escape_attr(src)}?>\n'
		}
		ModifyNode   {
			// v0.8.0 — same PI convention as MatchNode.
			src := n.source or { '' }
			out << '${xml_indent(depth)}<?cx:modify ${xml_escape_attr(src)}?>\n'
		}
		DocumentNode {
			// D7 — transparent document carrier: emit prolog, doctype, then
			// element children at this depth (mirrors emit_xml over a Document).
			for c in n.prolog { emit_xml_node(c, depth, lossless, mut out) }
			if dt := n.doctype { emit_xml_doctype(dt, lossless, mut out) }
			for c in n.elements { emit_xml_node(c, depth, lossless, mut out) }
		}
	}
}

// emit_xml_sequence renders a SequenceNode as `<cx:seq><item>…</item>…</cx:seq>`
// per (the W015 wrapping convention). Sequences emit
// post-flatten per CXDM §1.2.
fn emit_xml_sequence(n SequenceNode, depth int, lossless bool, mut out []string) {
	ind := xml_indent(depth)
	if n.items.len == 0 {
		out << '${ind}<cx:seq/>\n'
		return
	}
	out << '${ind}<cx:seq>'
	for item in n.items {
		out << '<item>'
		emit_xml_inline_node(item, lossless, mut out)
		out << '</item>'
	}
	out << '</cx:seq>\n'
}

// emit_xml_array renders an ArrayNode as `<cx:arr><item>…</item>…</cx:arr>`.
// Nested arrays preserve structure (ArrayNode children emit recursively).
fn emit_xml_array(n ArrayNode, depth int, lossless bool, mut out []string) {
	ind := xml_indent(depth)
	if n.items.len == 0 {
		out << '${ind}<cx:arr/>\n'
		return
	}
	out << '${ind}<cx:arr>'
	for item in n.items {
		out << '<item>'
		emit_xml_inline_node(item, lossless, mut out)
		out << '</item>'
	}
	out << '</cx:arr>\n'
}

// emit_xml_map renders a MapNode as `<cx:map><entry key="…">…</entry>…</cx:map>`.
// Non-string keys carry a cx:key-type attribute alongside key for round-trip.
fn emit_xml_map(n MapNode, depth int, lossless bool, mut out []string) {
	ind := xml_indent(depth)
	if n.entries.len == 0 {
		out << '${ind}<cx:map/>\n'
		return
	}
	out << '${ind}<cx:map>'
	for entry in n.entries {
		key_str := scalar_value_str(entry.key_value)
		key_type_attr := if entry.key_type == .string_type {
			''
		} else {
			' cx:key-type="${scalar_type_name(entry.key_type)}"'
		}
		out << '<entry key="${xml_escape_attr(key_str)}"${key_type_attr}>'
		emit_xml_inline_node(entry.value, lossless, mut out)
		out << '</entry>'
	}
	out << '</cx:map>\n'
}

fn emit_xml_eval_directive(n EvalDirectiveNode, depth int, lossless bool, mut out []string) {
	ind := xml_indent(depth)
	mut attr_str := ''
	for a in n.attrs {
		if body_items := a.body() {
			mut tmp := []string{}
			for item in body_items { emit_xml_inline_node(item, lossless, mut tmp) }
			attr_str += ' ${a.name}="${xml_escape_attr(tmp.join(''))}"'
		} else {
			attr_str += ' ${a.name}="${xml_escape_attr(a.str_value())}"'
		}
	}
	if n.items.len == 0 {
		out << '${ind}<cx:eval name="${n.name}"${attr_str}/>\n'
		return
	}
	out << '${ind}<cx:eval name="${n.name}"${attr_str}>'
	for item in n.items { emit_xml_inline_node(item, lossless, mut out) }
	out << '</cx:eval>\n'
}

// xml_attr_types_sidecar builds the space-separated `name=type` map for
// the reserved `cx:attr-types` attribute (D3), in source order. It lists
// exactly the attributes whose CX type the XML→CX auto-typer would NOT
// reconstruct from the bare value alone:
//   • a non-auto-recoverable annotated type (u16/i32/f32/decimal/bigint/
//     bytes/atom) → `name=<type>`;
//   • an explicit-string value that WOULD otherwise auto-type to a scalar
//     on import (`code="007"`) → `name=string`, forcing it back to string.
// Auto-recoverable types (int/float/bool/date/datetime) and plain strings
// whose lexical form is unambiguous are omitted. Returns none when the
// list is empty (so the sidecar attribute is absent when unneeded).
fn xml_attr_types_sidecar(attrs []Attribute) ?string {
	mut parts := []string{}
	for a in attrs {
		if a.is_ref {
			continue
		}
		val := a.str_value()
		if dt := a.data_type() {
			if dt == 'string' {
				if cx_would_autotype(val) {
					parts << '${a.name}=string'
				}
			} else if !type_name_is_auto_recoverable(dt) {
				parts << '${a.name}=${dt}'
			}
		} else if cx_would_autotype(val) {
			// A default-string value that looks like a scalar would
			// mis-type on import — pin it back to string.
			parts << '${a.name}=string'
		}
	}
	if parts.len == 0 {
		return none
	}
	return parts.join(' ')
}

fn emit_xml_element(e Element, depth int, lossless bool, mut out []string) {
	ind := xml_indent(depth)

	// Build attribute string
	mut attr_str := ''
	if a := e.anchor()   { attr_str += ' cx:anchor="${a}"' }
	if m := e.merge()    { attr_str += ' cx:merge="${m}"' }
	// v3.4: #id round-trips as xml:id (XML built-in URI ns).
	if id := e.id()      { attr_str += ' xml:id="${xml_escape_attr(id)}"' }
	// GG7: body-position `[ref @id]`
	// form round-trips as a `cx:body-ref` attribute carrying the target
	// id. XML import (xml_parser.v) recognises the inverse shape and
	// reconstructs Element.body_ref.
	if br := e.body_ref() { attr_str += ' cx:body-ref="${xml_escape_attr(br)}"' }
	if dt := e.data_type() { attr_str += ' cx:type="${dt}"' }
	for a in e.attrs {
		// v3.4: xmlns / xmlns:foo declarations round-trip
		// verbatim. Names retain source form (the legacy `ns:foo`
		// translation is no longer applied; CX source uses xmlns:
		// directly).
		// v3.4: is_ref attrs emit as name="<id>" (no @);
		// XML semantics defer reference disambiguation to xs:IDREF
		// schema validation, which CX doesn't carry in-band.
		attr_str += ' ${a.name}="${xml_escape_attr(a.str_value())}"'
	}
	// D3: typed attributes whose CX type the XML→CX auto-typer cannot
	// recover from the lexical form (sized ints, decimal, bigint, bytes,
	// atom, and explicit-string-over-numeric) are listed in a reserved
	// `cx:attr-types` sidecar so the round-trip is lossless.
	if at := xml_attr_types_sidecar(e.attrs) {
		attr_str += ' cx:attr-types="${xml_escape_attr(at)}"'
	}

	if e.items.len == 0 {
		out << '${ind}<${e.name}${attr_str}/>\n'
		return
	}

	is_array := if dt := e.data_type() { dt.ends_with('[]') } else { false }
	if is_array {
		out << '${ind}<${e.name}${attr_str}>'
		for item in e.items {
			if item is ScalarNode {
				out << '<item>${xml_scalar_text(item as ScalarNode)}</item>'
			}
		}
		out << '</${e.name}>\n'
		return
	}

	// TYPED LIST / MIXED CONTENT (@CHOICE-1 §9-one-layer): a multi-item body that
	// carries a typed (non-string) scalar is a discrete typed list — NOT a `T[]`
	// array (no element cx:type) and NOT prose. Each typed scalar serializes to a
	// per-item `<cx:TYPE>value</cx:TYPE>` carrier (ruling a, 2026-06-05); string
	// scalars / text render bare, child elements nest. This is the lossless,
	// bijective form (distinct from the `<item>` array shape above) and matches
	// the formal-witness canonical XML. xml_parser decodes `<cx:T>` back to items.
	// LOSSLESS routes typed-scalar bodies through the per-item `<cx:T>` carrier
	// path so the XML→CX round-trip is faithful (conversions.md §0.2):
	//   - a sole non-string scalar → its `<cx:T>` carrier (`[x 1]` →
	//     `<x><cx:int>1</cx:int></x>` → `[x 1]`; a sole string stays bare since it
	//     re-infers), and
	//   - a multi-value body (every item a leaf scalar / text) → per-item
	//     carriers incl. `<cx:string>`, so adjacent string items keep their
	//     boundary instead of the idiomatic collapse to `ab`.
	// The default (lossy) form is unchanged.
	all_leaf_values := e.items.all(it is ScalarNode || it is TextNode)
	has_nonstring_scalar := e.items.any(it is ScalarNode && (it as ScalarNode).data_type != .string_type)
	lossless_sole_scalar := lossless && e.items.len == 1 && has_nonstring_scalar
	is_typed_list := (e.items.len >= 2 && (has_nonstring_scalar || (lossless && all_leaf_values)))
		|| lossless_sole_scalar
	if is_typed_list {
		out << '${ind}<${e.name}${attr_str}>'
		for item in e.items {
			emit_xml_cx_typed_item(item, lossless, mut out)
		}
		out << '</${e.name}>\n'
		return
	}

	has_child_elements := e.items.any(it is Element)
	has_text := e.items.any(it is TextNode || it is ScalarNode || it is EntityRefNode || it is RawTextNode)
	is_inline := !has_child_elements || has_text

	if is_inline {
		out << '${ind}<${e.name}${attr_str}>'
		for item in e.items { emit_xml_inline_node(item, lossless, mut out) }
		out << '</${e.name}>\n'
	} else {
		out << '${ind}<${e.name}${attr_str}>\n'
		for item in e.items { emit_xml_node(item, depth + 1, lossless, mut out) }
		out << '${ind}</${e.name}>\n'
	}
}

// emit_xml_cx_typed_item renders one item of a typed-list / mixed-content body
// (@CHOICE-1). A non-string scalar serializes to its `<cx:TYPE>` carrier (atom
// and null get the dedicated `<cx:atom>` / `<cx:null/>` forms); a string scalar
// and a TextNode render bare; everything else (child elements, entities, raw,
// nested collections) falls through to the standard inline render. Inverse:
// xml_parser's `<cx:T>` decode in parse_xml_element.
fn emit_xml_cx_typed_item(n Node, lossless bool, mut out []string) {
	if n is ScalarNode {
		match n.data_type {
			.string_type {
				// LOSSLESS: wrap in a `<cx:string>` carrier so an adjacent string
				// item keeps its boundary; idiomatic form renders bare (collapses).
				if lossless {
					out << '<cx:string>${xml_escape_text(n.value as string)}</cx:string>'
				} else {
					out << xml_escape_text(n.value as string)
				}
			}
			.atom_type {
				out << '<cx:atom>${xml_escape_text(n.value as string)}</cx:atom>'
			}
			.null_type {
				out << '<cx:null/>'
			}
			else {
				tn := scalar_type_name(n.data_type)
				out << '<cx:${tn}>${xml_scalar_text(n)}</cx:${tn}>'
			}
		}
		return
	}
	if n is TextNode {
		// A bare TextNode item (e.g. from a quoted-string body run) carries the
		// same boundary risk as a string scalar — give it a `<cx:string>` carrier
		// in lossless mode; bare otherwise.
		if lossless {
			out << '<cx:string>${xml_escape_text(n.value)}</cx:string>'
		} else {
			out << xml_escape_text(n.value)
		}
		return
	}
	emit_xml_inline_node(n, lossless, mut out)
}

fn emit_xml_inline_node(n Node, lossless bool, mut out []string) {
	match n {
		TextNode      { out << xml_escape_text(n.value) }
		ScalarNode    {
			// Duration/period scalars need the `<cx:T>` carrier even as a sole
			// body child: their XML image is ISO 8601 (`PT1H30M`), which the
			// XML→CX auto-typer can NOT recognize without the type tag (the
			// formal `infer` rule — these types never infer). String / numeric
			// scalars keep their bare lexical body (re-inferred on read).
			if n.data_type == .duration_type || n.data_type == .period_type {
				tn := scalar_type_name(n.data_type)
				out << '<cx:${tn}>${xml_scalar_text(n)}</cx:${tn}>'
			} else {
				out << xml_scalar_text(n)
			}
		}
		EntityRefNode { out << '&${n.name};' }
		RawTextNode   { emit_xml_raw_text(n, mut out) }
		Element       {
			mut tmp := []string{}
			emit_xml_element(n, 0, lossless, mut tmp)
			out << tmp.join('').trim_right('\n')
		}
		BlockContentNode {
			out << '<cx:block>'
			for item in n.items { emit_xml_inline_node(item, lossless, mut out) }
			out << '</cx:block>'
		}
		SequenceNode { emit_xml_sequence_inline(n, lossless, mut out) }
		ArrayNode    { emit_xml_array_inline(n, lossless, mut out) }
		MapNode      { emit_xml_map_inline(n, lossless, mut out) }
		IteratorNode { emit_xml_sequence_inline(iterator_to_sequence(n), lossless, mut out) }
		else {}
	}
}

// emit_xml_sequence_inline / _array_inline / _map_inline are the
// no-indent, no-trailing-newline variants used when a collection
// marker appears nested inside a named element body. Without these
// the inline dispatch dropped the node entirely (the `else {}` arm),
// which the programs XML renderer worked around by hoisting every
// collection to the document root. Surfaced by Phase 3.11 follow-up.
fn emit_xml_sequence_inline(n SequenceNode, lossless bool, mut out []string) {
	if n.items.len == 0 {
		out << '<cx:seq/>'
		return
	}
	out << '<cx:seq>'
	for item in n.items {
		out << '<item>'
		emit_xml_inline_node(item, lossless, mut out)
		out << '</item>'
	}
	out << '</cx:seq>'
}

fn emit_xml_array_inline(n ArrayNode, lossless bool, mut out []string) {
	if n.items.len == 0 {
		out << '<cx:arr/>'
		return
	}
	out << '<cx:arr>'
	for item in n.items {
		out << '<item>'
		emit_xml_inline_node(item, lossless, mut out)
		out << '</item>'
	}
	out << '</cx:arr>'
}

fn emit_xml_map_inline(n MapNode, lossless bool, mut out []string) {
	if n.entries.len == 0 {
		out << '<cx:map/>'
		return
	}
	out << '<cx:map>'
	for entry in n.entries {
		key_str := scalar_value_str(entry.key_value)
		key_type_attr := if entry.key_type == .string_type {
			''
		} else {
			' cx:key-type="${scalar_type_name(entry.key_type)}"'
		}
		out << '<entry key="${xml_escape_attr(key_str)}"${key_type_attr}>'
		emit_xml_inline_node(entry.value, lossless, mut out)
		out << '</entry>'
	}
	out << '</cx:map>'
}

fn emit_xml_raw_text(r RawTextNode, mut out []string) {
	// CDATA split rule: ]]> → ]]><![CDATA[>
	content := r.value.replace(']]>', ']]><![CDATA[>')
	out << '<![CDATA[${content}]]>'
}

fn xml_scalar_text(s ScalarNode) string {
	// Temporal spans render their ISO 8601 image in XML ([L25]/[L26]); the CX
	// source form (`1h30m`) stays in the value. A malformed span falls back to
	// the verbatim text (defensive — recognition already validated it).
	if s.data_type == .duration_type {
		if s.value is string {
			return duration_cx_to_iso(s.value as string) or { s.value as string }
		}
	}
	if s.data_type == .period_type {
		if s.value is string {
			return period_cx_to_iso(s.value as string) or { s.value as string }
		}
	}
	return match s.value {
		i64       { s.value.str() }
		f64       { format_float(s.value as f64) }
		bool      { if s.value as bool { 'true' } else { 'false' } }
		NullValue { 'null' }
		string    { s.value as string }
	}
}

fn xml_escape_text(s string) string {
	return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
}

fn xml_escape_attr(s string) string {
	return s.replace('&', '&amp;').replace('<', '&lt;').replace('"', '&quot;')
}

fn emit_xml_pi(p PINode, depth int, mut out []string) {
	data := p.data or { '' }
	sep := if data.len > 0 { ' ' } else { '' }
	out << '${xml_indent(depth)}<?${p.target}${sep}${data}?>\n'
}

fn emit_xml_decl(x XMLDeclNode, mut out []string) {
	mut s := '<?xml version="${x.version}"'
	if enc := x.encoding   { s += ' encoding="${enc}"' }
	if sa  := x.standalone  { s += ' standalone="${sa}"' }
	s += '?>'
	out << '${s}\n'
}

fn emit_xml_cx_directive(cx2 CXDirectiveNode, mut out []string) {
	attrs := cx2.attrs.map(' ${it.name}="${xml_escape_attr(it.str_value())}"').join('')
	out << '<?cx${attrs}?>\n'
}

fn emit_xml_doctype(d DoctypeDecl, lossless bool, mut out []string) {
	mut s := '<!DOCTYPE ${d.name}'
	if ext := d.external_id {
		if pub_id := ext.public {
			s += ' PUBLIC "${pub_id}"'
			if sys := ext.system { s += ' "${sys}"' }
		} else if sys := ext.system {
			s += ' SYSTEM "${sys}"'
		}
	}
	if d.int_subset.len == 0 {
		s += '>'
		out << '${s}\n'
	} else {
		s += ' [\n'
		out << s
		for n in d.int_subset { emit_xml_node(n, 1, lossless, mut out) }
		out << ']>\n'
	}
}

fn emit_xml_entity_decl(e EntityDeclNode, depth int, mut out []string) {
	kind_marker := if e.kind == .pe { '% ' } else { '' }
	def_str := match e.def {
		string { '"${e.def}"' }
		ExternalEntityDef {
			ext := e.def as ExternalEntityDef
			mut s := if pub_id := ext.external_id.public {
				sys := ext.external_id.system or { '' }
				'PUBLIC "${pub_id}" "${sys}"'
			} else {
				sys := ext.external_id.system or { '' }
				'SYSTEM "${sys}"'
			}
			if ndata := ext.ndata { s += ' NDATA "${ndata}"' }
			s
		}
	}
	out << '${xml_indent(depth)}<!ENTITY ${kind_marker}${e.name} ${def_str}>\n'
}

fn emit_xml_attlist_decl(a AttlistDeclNode, depth int, mut out []string) {
	defs := a.defs.map(' ${it.name} ${it.att_type} ${it.default}').join('')
	out << '${xml_indent(depth)}<!ATTLIST ${a.name}${defs}>\n'
}

fn emit_xml_notation_decl(n NotationDeclNode, depth int, mut out []string) {
	id_str := if pub_id := n.public_id {
		if sys := n.system_id { 'PUBLIC "${pub_id}" "${sys}"' } else { 'PUBLIC "${pub_id}"' }
	} else if sys := n.system_id {
		'SYSTEM "${sys}"'
	} else {
		''
	}
	sep := if id_str.len > 0 { ' ' } else { '' }
	out << '${xml_indent(depth)}<!NOTATION ${n.name}${sep}${id_str}>\n'
}

fn emit_xml_conditional_sect(c ConditionalSectNode, depth int, lossless bool, mut out []string) {
	kind := if c.kind == .include { 'INCLUDE' } else { 'IGNORE' }
	out << '${xml_indent(depth)}<![${kind}[\n'
	for n in c.subset { emit_xml_node(n, depth + 1, lossless, mut out) }
	out << '${xml_indent(depth)}]]>\n'
}
