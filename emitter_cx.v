module cx

import strconv

// ── CX Emitter ────────────────────────────────────────────────────────────────

pub fn emit_cx(doc Document) string {
	return cx_emit(doc, false)
}

pub fn emit_cx_compact(doc Document) string {
	return cx_emit(doc, true)
}

pub fn emit_cx_docs(docs []Document) string {
	parts := docs.map(emit_cx(it))
	return parts.join('\n---\n')
}

pub fn emit_cx_compact_docs(docs []Document) string {
	parts := docs.map(emit_cx_compact(it))
	return parts.join('\n---\n')
}

fn cx_emit(doc Document, compact bool) string {
	mut out := []string{}
	for n in doc.prolog { cx_emit_node(n, 0, compact, mut out) }
	if dt := doc.doctype { emit_cx_doctype(dt, mut out) }
	for n in doc.elements { cx_emit_node(n, 0, compact, mut out) }
	result := out.join('')
	return result.trim_right('\n')
}

fn cx_ind(depth int, compact bool) string {
	if compact { return '' }
	mut s := ''
	for _ in 0..depth { s += '  ' }
	return s
}

fn cx_emit_node(n Node, depth int, compact bool, mut out []string) {
	nl  := if compact { '' } else { '\n' }
	ind := cx_ind(depth, compact)
	match n {
		Element          { cx_emit_element(n, depth, compact, mut out) }
		TextNode         { out << cx_quote_text_if_needed(n.value) }
		ScalarNode       { out << cx_scalar(n) }
		CommentNode      { out << '${ind}[-${n.value}]${nl}' }
		PINode           { cx_emit_pi(n, depth, compact, mut out) }
		XMLDeclNode      { emit_cx_xml_decl(n, mut out) }
		CXDirectiveNode  { emit_cx_directive(n, mut out) }
		EntityRefNode    { out << '&${n.name};' }
		RawTextNode      { out << '[#${n.value}#]${nl}' }
		AliasNode        { out << '${ind}[*${n.name}]${nl}' }
		EntityDeclNode   { cx_emit_entity_decl(n, depth, compact, mut out) }
		ElementDeclNode  { out << '${ind}[!ELEMENT ${n.name} ${n.contentspec}]${nl}' }
		AttlistDeclNode  { cx_emit_attlist_decl(n, depth, compact, mut out) }
		NotationDeclNode { cx_emit_notation_decl(n, depth, compact, mut out) }
		ConditionalSectNode { cx_emit_conditional_sect(n, depth, compact, mut out) }
		BlockContentNode { cx_emit_block_content(n, depth, compact, mut out) }
	}
}

fn cx_emit_element(e Element, depth int, compact bool, mut out []string) {
	ind := cx_ind(depth, compact)
	nl  := if compact { '' } else { '\n' }

	has_child_elements := e.items.any(it is Element)
	has_text := e.items.any(it is TextNode || it is ScalarNode || it is EntityRefNode || it is RawTextNode)
	is_multiline := !compact && has_child_elements && !has_text

	if is_multiline {
		meta := cx_build_meta(e)
		out << '${ind}[${e.name}${meta}${nl}'
		for item in e.items { cx_emit_node(item, depth + 1, compact, mut out) }
		out << '${ind}]${nl}'
	} else if e.items.len == 0 && e.attrs.len == 0 && e.anchor == none && e.merge == none && e.data_type == none {
		out << '${ind}[${e.name}]${nl}'
	} else {
		meta := cx_build_meta(e)
		body := cx_build_inline_body(e.items, compact)
		body_sep := if body.len > 0 { ' ' } else { '' }
		out << '${ind}[${e.name}${meta}${body_sep}${body}]${nl}'
	}
}

fn cx_build_meta(e Element) string {
	mut s := ''
	if a := e.anchor  { s += ' &${a}' }
	if m := e.merge   { s += ' *${m}' }
	if dt := e.data_type { s += ' :${dt}' }
	for a in e.attrs {
		val_str := a.str_value()
		emitted := if a.data_type == none && cx_would_autotype(val_str) {
			"'${val_str}'"
		} else {
			cx_quote_attr_if_needed(val_str)
		}
		s += ' ${a.name}=${emitted}'
	}
	return s
}

fn cx_build_inline_body(items []Node, compact bool) string {
	mut parts := []string{}
	for item in items {
		match item {
			TextNode {
				if item.value.trim_space().len == 0 { continue }
				parts << cx_quote_text_if_needed(item.value)
			}
			ScalarNode    { parts << cx_scalar(item) }
			EntityRefNode { parts << '&${item.name};' }
			RawTextNode   { parts << '[#${item.value}#]' }
			Element {
				mut tmp := []string{}
				cx_emit_element(item, 0, compact, mut tmp)
				parts << tmp.join('').trim_right('\n')
			}
			BlockContentNode {
				mut s := '[|'
				for bi in item.items {
					match bi {
						TextNode { s += bi.value }
						Element  {
							mut tmp := []string{}
							cx_emit_element(bi, 0, compact, mut tmp)
							s += tmp.join('').trim_right('\n')
						}
						else {}
					}
				}
				s += '|]'
				parts << s
			}
			else {}
		}
	}
	return parts.join(' ')
}

fn cx_quote_text_if_needed(s string) string {
	needs_quote := s.starts_with(' ') || s.ends_with(' ')
		|| s.contains('  ') || s.contains('\n') || s.contains('\t')
		|| s.contains('[') || s.contains(']') || s.contains('&')
		|| s.starts_with(':') || s.starts_with("'") || s.starts_with('"')
		|| cx_would_autotype(s)
	if !needs_quote { return s }
	return cx_choose_quote(s)
}

fn cx_choose_quote(s string) string {
	has_single := s.contains("'")
	has_double := s.contains('"')
	if !has_single { return "'${s}'" }
	if !has_double { return '"${s}"' }
	if !s.contains("'''") { return "'''${s}'''" }
	return '"${s}"'
}

fn cx_would_autotype(s string) bool {
	if s.contains(' ') { return false }
	if s.starts_with('0x') || s.starts_with('0X') { return true }
	if s == 'true' || s == 'false' || s == 'null' { return true }
	if _ := s.parse_int(10, 64) { return true }
	if s.contains('.') || s.contains('e') || s.contains('E') {
		if _ := strconv.atof64(s) { return true }
	}
	if is_datetime(s) { return true }
	if is_date(s) { return true }
	return false
}

fn cx_quote_attr_if_needed(s string) string {
	if s.contains(' ') || s.contains("'") || s.contains('"') || s.len == 0 {
		return "'${s}'"
	}
	return s
}

fn cx_scalar(s ScalarNode) string {
	return match s.value {
		i64       { s.value.str() }
		f64       { format_float(s.value as f64) }
		bool      { if s.value as bool { 'true' } else { 'false' } }
		NullValue { 'null' }
		string    { s.value as string }
	}
}

fn cx_emit_pi(p PINode, depth int, compact bool, mut out []string) {
	data := p.data or { '' }
	sep  := if data.len > 0 { ' ' } else { '' }
	nl   := if compact { '' } else { '\n' }
	ind  := cx_ind(depth, compact)
	out << '${ind}[?${p.target}${sep}${data}]${nl}'
}

fn emit_cx_xml_decl(x XMLDeclNode, mut out []string) {
	mut s := '[?xml version=${x.version}'
	if enc := x.encoding   { s += ' encoding=${enc}' }
	if sa  := x.standalone  { s += ' standalone=${sa}' }
	s += ']'
	out << '${s}\n'
}

fn emit_cx_directive(cx2 CXDirectiveNode, mut out []string) {
	attrs := cx2.attrs.map(' ${it.name}=${cx_quote_attr_if_needed(it.str_value())}').join('')
	out << '[?cx${attrs}]\n'
}

fn cx_emit_block_content(bc BlockContentNode, depth int, compact bool, mut out []string) {
	ind := cx_ind(depth, compact)
	nl  := if compact { '' } else { '\n' }
	out << '${ind}[|'
	for item in bc.items {
		match item {
			TextNode { out << item.value }
			Element  {
				mut tmp := []string{}
				cx_emit_element(item, 0, compact, mut tmp)
				out << tmp.join('').trim_right('\n')
			}
			else {}
		}
	}
	out << '|]${nl}'
}

fn emit_cx_doctype(d DoctypeDecl, mut out []string) {
	mut header := '[!DOCTYPE ${d.name}'
	if ext := d.external_id {
		if pub_id := ext.public {
			sys := ext.system or { '' }
			header += " PUBLIC '${pub_id}' '${sys}'"
		} else if sys := ext.system {
			header += " SYSTEM '${sys}'"
		}
	}
	if d.int_subset.len == 0 {
		header += ']'
		out << '${header}\n'
	} else {
		header += ' [\n'
		out << header
		for n in d.int_subset { cx_emit_node(n, 1, false, mut out) }
		out << ']]\n'
	}
}

fn cx_emit_entity_decl(e EntityDeclNode, depth int, compact bool, mut out []string) {
	ind         := cx_ind(depth, compact)
	nl          := if compact { '' } else { '\n' }
	kind_marker := if e.kind == .pe { '% ' } else { '' }
	def_str     := match e.def {
		string { "'${e.def}'" }
		ExternalEntityDef {
			ext := e.def as ExternalEntityDef
			mut s := if pub_id := ext.external_id.public {
				sys := ext.external_id.system or { '' }
				"PUBLIC '${pub_id}' '${sys}'"
			} else {
				sys := ext.external_id.system or { '' }
				"SYSTEM '${sys}'"
			}
			if ndata := ext.ndata { s += ' NDATA ${ndata}' }
			s
		}
	}
	out << '${ind}[!ENTITY ${kind_marker}${e.name} ${def_str}]${nl}'
}

fn cx_emit_attlist_decl(a AttlistDeclNode, depth int, compact bool, mut out []string) {
	ind  := cx_ind(depth, compact)
	nl   := if compact { '' } else { '\n' }
	defs := a.defs.map(' ${it.name} ${it.att_type} ${it.default}').join('')
	out << '${ind}[!ATTLIST ${a.name}${defs}]${nl}'
}

fn cx_emit_notation_decl(n NotationDeclNode, depth int, compact bool, mut out []string) {
	ind    := cx_ind(depth, compact)
	nl     := if compact { '' } else { '\n' }
	id_str := if pub_id := n.public_id {
		if sys := n.system_id { "PUBLIC '${pub_id}' '${sys}'" } else { "PUBLIC '${pub_id}'" }
	} else if sys := n.system_id {
		"SYSTEM '${sys}'"
	} else {
		''
	}
	out << '${ind}[!NOTATION ${n.name} ${id_str}]${nl}'
}

fn cx_emit_conditional_sect(c ConditionalSectNode, depth int, compact bool, mut out []string) {
	ind  := cx_ind(depth, compact)
	nl   := if compact { '' } else { '\n' }
	kind := if c.kind == .include { 'INCLUDE' } else { 'IGNORE' }
	out << '${ind}[![${kind}[${nl}'
	for n in c.subset { cx_emit_node(n, depth + 1, compact, mut out) }
	out << '${ind}]]]${nl}'
}
