module cx

// ── JSON AST Emitter ──────────────────────────────────────────────────────────
// Produces the canonical AST JSON representation.

pub fn emit_ast_json(doc Document) string {
	return json_document(doc)
}

pub fn emit_ast_json_docs(docs []Document) string {
	parts := docs.map(json_document(it))
	return '[${parts.join(',')}]'
}

fn json_document(doc Document) string {
	mut pairs := []string{}
	pairs << '"type":"Document"'
	if doc.prolog.len > 0 {
		nodes := doc.prolog.map(json_node(it))
		pairs << '"prolog":[${nodes.join(',')}]'
	}
	if dt := doc.doctype {
		pairs << '"doctype":${json_doctype(dt)}'
	}
	if doc.elements.len > 0 {
		nodes := doc.elements.map(json_node(it))
		pairs << '"elements":[${nodes.join(',')}]'
	}
	return '{${pairs.join(',')}}'
}

fn json_node(n Node) string {
	return match n {
		Element          { json_element(n) }
		TextNode         { '{"type":"Text","value":${json_str(n.value)}}' }
		ScalarNode       { json_scalar(n) }
		CommentNode      { '{"type":"Comment","value":${json_str(n.value)}}' }
		PINode           { json_pi(n) }
		XMLDeclNode      { json_xml_decl(n) }
		CXDirectiveNode  { '{"type":"CXDirective","attrs":${json_attrs(n.attrs)}}' }
		EntityRefNode    { '{"type":"EntityRef","name":${json_str(n.name)}}' }
		RawTextNode      { '{"type":"RawText","value":${json_str(n.value)}}' }
		AliasNode        { '{"type":"Alias","name":${json_str(n.name)}}' }
		EntityDeclNode   { json_entity_decl(n) }
		ElementDeclNode  { '{"type":"ElementDecl","name":${json_str(n.name)},"contentspec":${json_str(n.contentspec)}}' }
		AttlistDeclNode  { json_attlist_decl(n) }
		NotationDeclNode { json_notation_decl(n) }
		ConditionalSectNode { json_conditional_sect(n) }
		BlockContentNode {
			items := n.items.map(json_node(it))
			'{"type":"BlockContent","items":[${items.join(',')}]}'
		}
	}
}

fn json_element(e Element) string {
	mut pairs := []string{}
	pairs << '"type":"Element"'
	pairs << '"name":${json_str(e.name)}'
	if a := e.anchor   { pairs << '"anchor":${json_str(a)}' }
	if m := e.merge    { pairs << '"merge":${json_str(m)}' }
	if dt := e.data_type { pairs << '"dataType":${json_str(dt)}' }
	if e.attrs.len > 0  { pairs << '"attrs":${json_attrs(e.attrs)}' }
	if e.items.len > 0 || e.data_type != none {
		nodes := e.items.map(json_node(it))
		pairs << '"items":[${nodes.join(',')}]'
	}
	return '{${pairs.join(',')}}'
}

fn json_scalar(s ScalarNode) string {
	dt := scalar_type_name(s.data_type)
	v := json_scalar_value(s.value)
	return '{"type":"Scalar","dataType":"${dt}","value":${v}}'
}

fn json_scalar_value(v ScalarValue) string {
	return match v {
		i64       { v.str() }
		f64       { json_float(v as f64) }
		bool      { if v as bool { 'true' } else { 'false' } }
		NullValue { 'null' }
		string    { json_str(v as string) }
	}
}

fn json_float(f f64) string {
	// JSON floats: must be valid JSON number
	s := format_float(f)
	return s
}

fn json_pi(p PINode) string {
	mut pairs := []string{}
	pairs << '"type":"PI"'
	pairs << '"target":${json_str(p.target)}'
	if d := p.data { pairs << '"data":${json_str(d)}' }
	return '{${pairs.join(',')}}'
}

fn json_xml_decl(x XMLDeclNode) string {
	mut pairs := []string{}
	pairs << '"type":"XMLDecl"'
	pairs << '"version":${json_str(x.version)}'
	if e := x.encoding   { pairs << '"encoding":${json_str(e)}' }
	if s := x.standalone  { pairs << '"standalone":${json_str(s)}' }
	return '{${pairs.join(',')}}'
}

fn json_attrs(attrs []Attribute) string {
	items := attrs.map(json_attr(it))
	return '[${items.join(',')}]'
}

fn json_attr(a Attribute) string {
	mut pairs := []string{}
	pairs << '"name":${json_str(a.name)}'
	pairs << '"value":${json_scalar_value(a.value)}'
	if dt := a.data_type {
		pairs << '"dataType":"${scalar_type_name(dt)}"'
	}
	return '{${pairs.join(',')}}'
}

fn json_entity_decl(e EntityDeclNode) string {
	kind := if e.kind == .ge { 'GE' } else { 'PE' }
	def := match e.def {
		string { json_str(e.def as string) }
		ExternalEntityDef {
			ext := e.def as ExternalEntityDef
			mut ext_pairs := []string{}
			mut ext_id_pairs := []string{}
			if pub_id := ext.external_id.public { ext_id_pairs << '"public":${json_str(pub_id)}' }
			if sys := ext.external_id.system    { ext_id_pairs << '"system":${json_str(sys)}' }
			ext_pairs << '"externalID":{${ext_id_pairs.join(',')}}'
			if ndata := ext.ndata { ext_pairs << '"ndata":${json_str(ndata)}' }
			'{${ext_pairs.join(',')}}'
		}
	}
	return '{"type":"EntityDecl","kind":"${kind}","name":${json_str(e.name)},"def":${def}}'
}

fn json_doctype(d DoctypeDecl) string {
	mut pairs := []string{}
	pairs << '"type":"DoctypeDecl"'
	pairs << '"name":${json_str(d.name)}'
	if ext := d.external_id {
		mut ext_pairs := []string{}
		if pub_id := ext.public { ext_pairs << '"public":${json_str(pub_id)}' }
		if sys := ext.system    { ext_pairs << '"system":${json_str(sys)}' }
		pairs << '"externalID":{${ext_pairs.join(',')}}'
	}
	if d.int_subset.len > 0 {
		nodes := d.int_subset.map(json_node(it))
		pairs << '"intSubset":[${nodes.join(',')}]'
	}
	return '{${pairs.join(',')}}'
}

fn json_attlist_decl(a AttlistDeclNode) string {
	defs := a.defs.map('{"name":${json_str(it.name)},"type":${json_str(it.att_type)},"default":${json_str(it.default)}}').join(',')
	return '{"type":"AttlistDecl","name":${json_str(a.name)},"defs":[${defs}]}'
}

fn json_notation_decl(n NotationDeclNode) string {
	mut pairs := []string{}
	pairs << '"type":"NotationDecl"'
	pairs << '"name":${json_str(n.name)}'
	if pub_id := n.public_id { pairs << '"publicID":${json_str(pub_id)}' }
	if sys := n.system_id    { pairs << '"systemID":${json_str(sys)}' }
	return '{${pairs.join(',')}}'
}

fn json_conditional_sect(c ConditionalSectNode) string {
	kind := if c.kind == .include { 'include' } else { 'ignore' }
	nodes := c.subset.map(json_node(it))
	return '{"type":"ConditionalSect","kind":"${kind}","subset":[${nodes.join(',')}]}'
}

// ── JSON string escaping ──────────────────────────────────────────────────────

fn json_str(s string) string {
	mut result := '"'
	for b in s.bytes() {
		match b {
			`"` { result += '\\"' }
			`\\` { result += '\\\\' }
			`\n` { result += '\\n' }
			`\r` { result += '\\r' }
			`\t` { result += '\\t' }
			else {
				if b < 0x20 {
					result += '\\u${b:04x}'
				} else {
					result += b.ascii_str()
				}
			}
		}
	}
	result += '"'
	return result
}
