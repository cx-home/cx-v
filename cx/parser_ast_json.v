module cx

// ── AST JSON → Document ───────────────────────────────────────────────────────
// Deserialises the JSON produced by emit_ast_json back into a Document, enabling
// ast_to_cx (and any future ast_to_* converter) to round-trip through the AST.

pub fn parse_ast_json(src string) !Document {
	mut r := JReader{ src: src.bytes(), pos: 0 }
	r.skip_ws()
	if r.pos >= r.src.len { return Document{} }
	v := r.read_val()
	return ajv_to_doc(v)!
}

fn ajv_to_doc(v JV) !Document {
	obj := if v is map[string]JV { v as map[string]JV } else { return error('AST root must be an object') }
	mut doc := Document{}
	if pv := obj['prolog'] {
		if pv is []JV { for n in pv as []JV { doc.prolog << ajv_to_node(n)! } }
	}
	if ev := obj['elements'] {
		if ev is []JV { for n in ev as []JV { doc.elements << ajv_to_node(n)! } }
	}
	return doc
}

fn ajv_str(obj map[string]JV, key string) string {
	v := obj[key] or { return '' }
	return if v is string { v as string } else { '' }
}

fn ajv_opt_str(obj map[string]JV, key string) ?string {
	v := obj[key] or { return none }
	if v is string { return v as string }
	return none
}

fn ajv_to_node(v JV) !Node {
	obj := if v is map[string]JV { v as map[string]JV } else { return error('AST node must be an object') }
	return match ajv_str(obj, 'type') {
		'Element'      { ajv_to_element(obj)! }
		'Text'         { Node(TextNode{ value: ajv_str(obj, 'value') }) }
		'Scalar'       { ajv_to_scalar_node(obj)! }
		'Comment'      { Node(CommentNode{ value: ajv_str(obj, 'value') }) }
		'RawText'      { Node(RawTextNode{ value: ajv_str(obj, 'value') }) }
		'EntityRef'    { Node(EntityRefNode{ name: ajv_str(obj, 'name') }) }
		'Alias'        { Node(AliasNode{ name: ajv_str(obj, 'name') }) }
		'BlockContent' { ajv_to_block_content(obj)! }
		'PI'           { ajv_to_pi(obj)! }
		'XMLDecl'      { ajv_to_xml_decl(obj) }
		'CXDirective'  { ajv_to_cx_directive(obj)! }
		else           { return error('unknown AST node type: ${ajv_str(obj, "type")}') }
	}
}

fn ajv_to_element(obj map[string]JV) !Node {
	mut attrs := []Attribute{}
	if av := obj['attrs'] {
		if av is []JV {
			for a in av as []JV {
				if a is map[string]JV { attrs << ajv_to_attr(a as map[string]JV)! }
			}
		}
	}
	mut items := []Node{}
	if iv := obj['items'] {
		if iv is []JV { for n in iv as []JV { items << ajv_to_node(n)! } }
	}
	return Node(Element{
		name:      ajv_str(obj, 'name')
		anchor:    ajv_opt_str(obj, 'anchor')
		merge:     ajv_opt_str(obj, 'merge')
		data_type: ajv_opt_str(obj, 'dataType')
		attrs:     attrs
		items:     items
	})
}

fn ajv_to_attr(obj map[string]JV) !Attribute {
	dt     := if s := ajv_opt_str(obj, 'dataType') { ajv_scalar_type(s) } else { none }
	val_jv := obj['value'] or { JV(JVNull{}) }
	return Attribute{ name: ajv_str(obj, 'name'), value: ajv_scalar_val(val_jv), data_type: dt }
}

fn ajv_to_scalar_node(obj map[string]JV) !Node {
	dt     := ajv_scalar_type(ajv_str(obj, 'dataType')) or { ScalarType.string_type }
	val_jv := obj['value'] or { JV(JVNull{}) }
	return Node(ScalarNode{ data_type: dt, value: ajv_scalar_val(val_jv) })
}

fn ajv_scalar_type(s string) ?ScalarType {
	return match s {
		'int'      { ?ScalarType(ScalarType.int_type) }
		'float'    { ?ScalarType(ScalarType.float_type) }
		'bool'     { ?ScalarType(ScalarType.bool_type) }
		'null'     { ?ScalarType(ScalarType.null_type) }
		'string'   { ?ScalarType(ScalarType.string_type) }
		'date'     { ?ScalarType(ScalarType.date_type) }
		'datetime' { ?ScalarType(ScalarType.datetime_type) }
		'bytes'    { ?ScalarType(ScalarType.bytes_type) }
		else       { none }
	}
}

fn ajv_scalar_val(v JV) ScalarValue {
	return match v {
		JVNull { ScalarValue(NullValue{}) }
		bool   { ScalarValue(v as bool) }
		i64    { ScalarValue(v as i64) }
		f64    { ScalarValue(v as f64) }
		string { ScalarValue(v as string) }
		else   { ScalarValue(NullValue{}) }
	}
}

fn ajv_to_block_content(obj map[string]JV) !Node {
	mut items := []Node{}
	if iv := obj['items'] {
		if iv is []JV { for n in iv as []JV { items << ajv_to_node(n)! } }
	}
	return Node(BlockContentNode{ items: items })
}

fn ajv_to_pi(obj map[string]JV) !Node {
	return Node(PINode{ target: ajv_str(obj, 'target'), data: ajv_opt_str(obj, 'data') })
}

fn ajv_to_xml_decl(obj map[string]JV) Node {
	return Node(XMLDeclNode{
		version:    ajv_str(obj, 'version')
		encoding:   ajv_opt_str(obj, 'encoding')
		standalone: ajv_opt_str(obj, 'standalone')
	})
}

fn ajv_to_cx_directive(obj map[string]JV) !Node {
	mut attrs := []Attribute{}
	if av := obj['attrs'] {
		if av is []JV {
			for a in av as []JV {
				if a is map[string]JV { attrs << ajv_to_attr(a as map[string]JV)! }
			}
		}
	}
	return Node(CXDirectiveNode{ attrs: attrs })
}
