module cx

// ── JSON AST Emitter ──────────────────────────────────────────────────────────
// Produces the canonical AST JSON representation.

pub fn emit_ast_json(doc Document) string {
	return json_document(doc)
}

// emit_ast_json_element returns the AST-JSON encoding of a single
// Element. Used by the ID/IDREF C ABI (cx_id_lookup / cx_resolve_ref)
// to return a node subtree without wrapping it in a Document.
pub fn emit_ast_json_element(e Element) string {
	return json_element(e)
}

pub fn emit_ast_json_docs(docs []Document) string {
	parts := docs.map(json_document(it))
	return '[${parts.join(',')}]'
}

// emit_ast_json_node returns the AST-JSON encoding of a single Node of
// any kind. Used by the program-result renderer (code/render.v
// node_to_ast_json) for non-Element node values that cross the
// DATA↔PROGRAM `node_lit` seam — e.g. a top-level `[?cx …]`
// CXDirectiveNode preserved verbatim per code.md §13 (#421) — so the
// eval `--json` shape matches the nested-child encoding json_element
// already produces instead of degrading to `null`.
pub fn emit_ast_json_node(n Node) string {
	return json_node(n)
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
		PEReferenceNode  { '{"type":"PEReference","name":${json_str(n.name)}}' }
		DoctypeDecl      { json_doctype(n) }
		ConditionalSectNode { json_conditional_sect(n) }
		BlockContentNode {
			items := n.items.map(json_node(it))
			'{"type":"BlockContent","items":[${items.join(',')}]}'
		}
		InterpolationNode {
			'{"type":"Interpolation","expr":${json_str(n.expr)}}'
		}
		EvalDirectiveNode {
			mut pairs := []string{}
			pairs << '"type":"EvalDirective"'
			pairs << '"name":${json_str(n.name)}'
			if n.attrs.len > 0 { pairs << '"attrs":${json_attrs(n.attrs)}' }
			if n.items.len > 0 {
				items := n.items.map(json_node(it))
				pairs << '"items":[${items.join(',')}]'
			}
			'{${pairs.join(',')}}'
		}
		SequenceNode {
			items := n.items.map(json_node(it))
			'{"type":"Sequence","items":[${items.join(',')}]}'
		}
		ArrayNode {
			items := n.items.map(json_node(it))
			'{"type":"Array","items":[${items.join(',')}]}'
		}
		MapNode {
			mut entries := []string{cap: n.entries.len}
			for entry in n.entries {
				key_str := json_str(scalar_value_str(entry.key_value))
				key_type := scalar_type_name(entry.key_type)
				val_str := json_node(entry.value)
				entries << '{"key":${key_str},"keyType":"${key_type}","value":${val_str}}'
			}
			'{"type":"Map","entries":[${entries.join(',')}]}'
		}
		IteratorNode {
			// materialize to Sequence form at the host
			// (JSON) boundary. The eval pipeline pulls the iterator
			// before render; this arm serializes whatever has accumulated
			// in `memo` as a Sequence-shaped JSON object.
			seq := iterator_to_sequence(n)
			items := seq.items.map(json_node(it))
			'{"type":"Sequence","items":[${items.join(',')}]}'
		}
		MatchNode {
			// Delegate to the canonical AST-JSON
			// projection in match_node.v (`"type":"ProgramMatchExpr"`,
			// arm-kind discriminator, scrutinee + arms[]).
			match_node_to_json(n)
		}
		ModifyNode {
			// Delegate to modify_node.v's
			// AST-JSON projection (`"type":"ProgramModifyExpr"`,
			// doc + focus + action-kind discriminator).
			modify_node_to_json(n)
		}
		DocumentNode {
			// D7 — transparent document carrier: project as a Document
			// shell over its prolog/doctype/element children.
			mut pairs := []string{}
			pairs << '"type":"Document"'
			if n.prolog.len > 0 {
				pr := n.prolog.map(json_node(it))
				pairs << '"prolog":[${pr.join(',')}]'
			}
			if dt := n.doctype { pairs << '"doctype":${json_doctype(dt)}' }
			els := n.elements.map(json_node(it))
			pairs << '"elements":[${els.join(',')}]'
			'{${pairs.join(',')}}'
		}
	}
}

fn json_element(e Element) string {
	mut pairs := []string{}
	pairs << '"type":"Element"'
	pairs << '"name":${json_str(e.name)}'
	if a := e.anchor()   { pairs << '"anchor":${json_str(a)}' }
	if m := e.merge()    { pairs << '"merge":${json_str(m)}' }
	if id := e.id()      { pairs << '"id":${json_str(id)}' }
	// v3.4: body-position reference shape `[name @id]`.
	if br := e.body_ref() { pairs << '"bodyRef":${json_str(br)}' }
	if dt := e.data_type() { pairs << '"dataType":${json_str(dt)}' }
	if e.attrs.len > 0  { pairs << '"attrs":${json_attrs(e.attrs)}' }
	// `[table]` block (#443, ast.md Element §"table" / conversions.md §2.1
	// XML analogue): the table payload lives in the pooled `table` field,
	// NOT in `items` — without this arm the projection emitted a rowless
	// `"items":[]` and every column and row was silently dropped. The
	// payload projects as a "table" object (cols + rows); the redundant
	// empty "items" is suppressed for table elements. Inverse:
	// parser_ast_json.v ajv_to_table.
	mut has_table := false
	if td := e.table_opt() {
		has_table = true
		pairs << '"table":${json_table(td)}'
	}
	if e.items.len > 0 || (e.data_type() != none && !has_table) {
		nodes := e.items.map(json_node(it))
		pairs << '"items":[${nodes.join(',')}]'
	}
	return '{${pairs.join(',')}}'
}

// json_table projects the pooled TableData payload (#443, ast.md Element
// §"table"): declared columns as `{"name": …, "dataType": …}` objects
// (`dataType` omitted for undeclared / string-default columns, mirroring
// the canonical CX header where an untyped column is the bare name), and
// each row as a JSON array of cells in column order.
fn json_table(td TableData) string {
	mut cols := []string{cap: td.cols.len}
	for c in td.cols {
		if c.type_name == '' {
			cols << '{"name":${json_str(c.name)}}'
		} else {
			cols << '{"name":${json_str(c.name)},"dataType":${json_str(c.type_name)}}'
		}
	}
	mut rows := []string{cap: td.rows.len}
	for row in td.rows {
		cells := row.map(json_table_cell(it))
		rows << '[${cells.join(',')}]'
	}
	return '{"cols":[${cols.join(',')}],"rows":[${rows.join(',')}]}'
}

// json_table_cell encodes one table cell. Scalar cells use JSON-native
// values (JSON is typed, so the i64/f64/bool/string/null distinction
// round-trips without a carrier — the analogue of the XML lane's
// bare-where-recoverable rule); collection cells use the standard AST-JSON
// node encodings ({"type":"Array"|"Map"|"Sequence", …}). A cell is a JSON
// object exactly when it is a collection, so the two stay unambiguous.
fn json_table_cell(v TableCellValue) string {
	return match v {
		bool         { if v { 'true' } else { 'false' } }
		i64          { v.str() }
		f64          { json_float(v) }
		string       { json_str(v) }
		NullValue    { 'null' }
		ArrayNode    { json_node(Node(v)) }
		MapNode      { json_node(Node(v)) }
		SequenceNode { json_node(Node(v)) }
	}
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
	if dt := a.data_type() {
		pairs << '"dataType":"${dt}"'
	}
	if a.is_ref {
		pairs << '"isRef":true'
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
