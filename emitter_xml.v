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
	}
}

fn emit_xml_element(e Element, depth int, mut out []string) {
	ind := xml_indent(depth)

	// Build attribute string
	mut attr_str := ''
	if a := e.anchor   { attr_str += ' cx:anchor="${a}"' }
	if m := e.merge    { attr_str += ' cx:merge="${m}"' }
	if dt := e.data_type { attr_str += ' cx:type="${dt}"' }
	for a in e.attrs {
		xml_name := cx_ns_to_xmlns(a.name)
		attr_str += ' ${xml_name}="${xml_escape_attr(a.str_value())}"'
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

fn cx_ns_to_xmlns(name string) string {
	if name.starts_with('ns:') {
		suffix := name[3..]
		if suffix == 'default' { return 'xmlns' }
		return 'xmlns:${suffix}'
	}
	return name
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
