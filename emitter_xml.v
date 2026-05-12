module cx

// ── XML Emitter ───────────────────────────────────────────────────────────────

pub fn emit_xml(doc Document) string {
	mut out := []string{}
	for n in doc.prolog { emit_xml_node(n, 0, mut out) }
	if dt := doc.doctype { emit_xml_doctype(dt, mut out) }
	for n in doc.elements { emit_xml_node(n, 0, mut out) }
	result := out.join('')
	return result.trim_right('\n')
}

pub fn emit_xml_docs(docs []Document) string {
	parts := docs.map(emit_xml(it))
	return parts.join('\n---\n')
}

fn xml_indent(depth int) string {
	mut s := ''
	for _ in 0..depth { s += '  ' }
	return s
}

fn emit_xml_node(n Node, depth int, mut out []string) {
	match n {
		Element          { emit_xml_element(n, depth, mut out) }
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
		ConditionalSectNode { emit_xml_conditional_sect(n, depth, mut out) }
		BlockContentNode {
			out << '${xml_indent(depth)}<cx:block>'
			for item in n.items { emit_xml_inline_node(item, mut out) }
			out << '</cx:block>\n'
		}
		InterpolationNode {
			// v3.5 (ADR 0016): no XML-native equivalent for CXL
			// interpolation; emit as a cx-namespaced PI carrying the
			// expression. Round-trips via xml_parser when re-read.
			out << '${xml_indent(depth)}<?cx:interp ${xml_escape_attr(n.expr)}?>\n'
		}
		EvalDirectiveNode {
			emit_xml_eval_directive(n, depth, mut out)
		}
		SequenceNode { emit_xml_sequence(n, depth, mut out) }
		ArrayNode    { emit_xml_array(n, depth, mut out) }
		MapNode      { emit_xml_map(n, depth, mut out) }
	}
}

// emit_xml_sequence renders a SequenceNode as `<cx:seq><item>…</item>…</cx:seq>`
// per ADR 0017 §D12 (the W015 wrapping convention). Sequences emit
// post-flatten per CXDM §1.2.
fn emit_xml_sequence(n SequenceNode, depth int, mut out []string) {
	ind := xml_indent(depth)
	if n.items.len == 0 {
		out << '${ind}<cx:seq/>\n'
		return
	}
	out << '${ind}<cx:seq>'
	for item in n.items {
		out << '<item>'
		emit_xml_inline_node(item, mut out)
		out << '</item>'
	}
	out << '</cx:seq>\n'
}

// emit_xml_array renders an ArrayNode as `<cx:arr><item>…</item>…</cx:arr>`.
// Nested arrays preserve structure (ArrayNode children emit recursively).
fn emit_xml_array(n ArrayNode, depth int, mut out []string) {
	ind := xml_indent(depth)
	if n.items.len == 0 {
		out << '${ind}<cx:arr/>\n'
		return
	}
	out << '${ind}<cx:arr>'
	for item in n.items {
		out << '<item>'
		emit_xml_inline_node(item, mut out)
		out << '</item>'
	}
	out << '</cx:arr>\n'
}

// emit_xml_map renders a MapNode as `<cx:map><entry key="…">…</entry>…</cx:map>`.
// Non-string keys carry a cx:key-type attribute alongside key for round-trip.
fn emit_xml_map(n MapNode, depth int, mut out []string) {
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
		emit_xml_inline_node(entry.value, mut out)
		out << '</entry>'
	}
	out << '</cx:map>\n'
}

fn emit_xml_eval_directive(n EvalDirectiveNode, depth int, mut out []string) {
	ind := xml_indent(depth)
	mut attr_str := ''
	for a in n.attrs {
		if body_items := a.body {
			mut tmp := []string{}
			for item in body_items { emit_xml_inline_node(item, mut tmp) }
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
	for item in n.items { emit_xml_inline_node(item, mut out) }
	out << '</cx:eval>\n'
}

fn emit_xml_element(e Element, depth int, mut out []string) {
	ind := xml_indent(depth)

	// Build attribute string
	mut attr_str := ''
	if a := e.anchor   { attr_str += ' cx:anchor="${a}"' }
	if m := e.merge    { attr_str += ' cx:merge="${m}"' }
	// v3.4 (ADR 0003 D6): #id round-trips as xml:id (XML built-in URI ns).
	if id := e.id      { attr_str += ' xml:id="${xml_escape_attr(id)}"' }
	if dt := e.data_type { attr_str += ' cx:type="${dt}"' }
	for a in e.attrs {
		// v3.4 (ADR 0002): xmlns / xmlns:foo declarations round-trip
		// verbatim. Names retain source form (the legacy `ns:foo`
		// translation is no longer applied; CX source uses xmlns:
		// directly).
		// v3.4 (ADR 0003 D6): is_ref attrs emit as name="<id>" (no @);
		// XML semantics defer reference disambiguation to xs:IDREF
		// schema validation, which CX doesn't carry in-band.
		attr_str += ' ${a.name}="${xml_escape_attr(a.str_value())}"'
	}

	if e.items.len == 0 {
		out << '${ind}<${e.name}${attr_str}/>\n'
		return
	}

	is_array := if dt := e.data_type { dt.ends_with('[]') } else { false }
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

	has_child_elements := e.items.any(it is Element)
	has_text := e.items.any(it is TextNode || it is ScalarNode || it is EntityRefNode || it is RawTextNode)
	is_inline := !has_child_elements || has_text

	if is_inline {
		out << '${ind}<${e.name}${attr_str}>'
		for item in e.items { emit_xml_inline_node(item, mut out) }
		out << '</${e.name}>\n'
	} else {
		out << '${ind}<${e.name}${attr_str}>\n'
		for item in e.items { emit_xml_node(item, depth + 1, mut out) }
		out << '${ind}</${e.name}>\n'
	}
}

fn emit_xml_inline_node(n Node, mut out []string) {
	match n {
		TextNode      { out << xml_escape_text(n.value) }
		ScalarNode    { out << xml_scalar_text(n) }
		EntityRefNode { out << '&${n.name};' }
		RawTextNode   { emit_xml_raw_text(n, mut out) }
		Element       {
			mut tmp := []string{}
			emit_xml_element(n, 0, mut tmp)
			out << tmp.join('').trim_right('\n')
		}
		BlockContentNode {
			out << '<cx:block>'
			for item in n.items { emit_xml_inline_node(item, mut out) }
			out << '</cx:block>'
		}
		else {}
	}
}

fn emit_xml_raw_text(r RawTextNode, mut out []string) {
	// CDATA split rule: ]]> → ]]><![CDATA[>
	content := r.value.replace(']]>', ']]><![CDATA[>')
	out << '<![CDATA[${content}]]>'
}

fn xml_scalar_text(s ScalarNode) string {
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

fn emit_xml_doctype(d DoctypeDecl, mut out []string) {
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
		for n in d.int_subset { emit_xml_node(n, 1, mut out) }
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

fn emit_xml_conditional_sect(c ConditionalSectNode, depth int, mut out []string) {
	kind := if c.kind == .include { 'INCLUDE' } else { 'IGNORE' }
	out << '${xml_indent(depth)}<![${kind}[\n'
	for n in c.subset { emit_xml_node(n, depth + 1, mut out) }
	out << '${xml_indent(depth)}]]>\n'
}
