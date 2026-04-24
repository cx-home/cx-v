module cx

// ── High-level public API ─────────────────────────────────────────────────────

// Parse CX source and return a Document.
// For multi-doc input, use parse_stream.
// pub fn parse(src string) !Document  — defined in parser.v

// Convert CX source to compact (single-line) CX output.
pub fn to_cx_compact(src string) !string {
	res := parse_cx(src)!
	if res.is_multi {
		docs := res.multi or { return error('no multi docs') }
		return emit_cx_compact_docs(docs)
	}
	doc := res.single or { return error('no document') }
	return emit_cx_compact(doc)
}

// Convert AST JSON (from to_ast) back to canonical CX.
pub fn ast_to_cx(src string) !string {
	doc := parse_ast_json(src)!
	return emit_cx(doc)
}

// Convert CX source to canonical CX output.
pub fn to_cx(src string) !string {
	res := parse_cx(src)!
	if res.is_multi {
		docs := res.multi or { return error('no multi docs') }
		return emit_cx_docs(docs)
	}
	doc := res.single or { return error('no document') }
	return emit_cx(doc)
}

// Convert CX source to XML.
pub fn to_xml(src string) !string {
	res := parse_cx(src)!
	if res.is_multi {
		docs := res.multi or { return error('no multi docs') }
		return emit_xml_docs(docs)
	}
	doc := res.single or { return error('no document') }
	return emit_xml(doc)
}

// Convert CX source to AST JSON.
pub fn to_ast(src string) !string {
	res := parse_cx(src)!
	if res.is_multi {
		docs := res.multi or { return error('no multi docs') }
		return emit_ast_json_docs(docs)
	}
	doc := res.single or { return error('no document') }
	return emit_ast_json(doc)
}

// Convert CX source to semantic JSON.
pub fn to_json(src string) !string {
	res := parse_cx(src)!
	if res.is_multi {
		docs := res.multi or { return error('no multi docs') }
		return emit_semantic_json_docs(docs)
	}
	doc := res.single or { return error('no document') }
	return emit_semantic_json(doc)
}

// Convert CX source to YAML.
pub fn to_yaml(src string) !string {
	res := parse_cx(src)!
	if res.is_multi {
		docs := res.multi or { return error('no multi docs') }
		return emit_yaml_docs(docs)
	}
	doc := res.single or { return error('no document') }
	return emit_yaml(doc)
}

// Convert CX source to TOML.
pub fn to_toml(src string) !string {
	res := parse_cx(src)!
	if res.is_multi {
		docs := res.multi or { return error('no multi docs') }
		return emit_toml_docs(docs)
	}
	doc := res.single or { return error('no document') }
	return emit_toml(doc)
}

// Convert CX source to Markdown.
pub fn to_md(src string) !string {
	res := parse_cx(src)!
	if res.is_multi {
		docs := res.multi or { return error('no multi docs') }
		return emit_md_docs(docs)
	}
	doc := res.single or { return error('no document') }
	return emit_md(doc)
}

// Convert Markdown source to CX.
pub fn from_md(src string) !string {
	res := parse_md_cx(src)!
	if res.is_multi {
		docs := res.multi or { return error('no multi docs') }
		return emit_cx_docs(docs)
	}
	doc := res.single or { return error('no document') }
	return emit_cx(doc)
}

// Convert XML source to CX.
pub fn from_xml(src string) !string {
	res := parse_xml_cx(src)!
	if res.is_multi {
		docs := res.multi or { return error('no multi docs') }
		return emit_cx_docs(docs)
	}
	doc := res.single or { return error('no document') }
	return emit_cx(doc)
}

// Convert any format to any other format.
pub fn convert(src string, from Format, to Format) !string {
	// Parse
	mut res := ParseResult{}
	match from {
		.cx {
			res = parse_cx(src)!
		}
		.xml {
			res = parse_xml_cx(src)!
		}
		.json {
			res = parse_json_cx(src)!
		}
		.yaml {
			res = parse_yaml_cx(src)!
		}
		.toml {
			res = parse_toml_cx(src)!
		}
		.md {
			res = parse_md_cx(src)!
		}
	}
	// Emit
	if res.is_multi {
		docs := res.multi or { return error('no multi docs') }
		return match to {
			.cx   { emit_cx_docs(docs) }
			.xml  { emit_xml_docs(docs) }
			.json { emit_semantic_json_docs(docs) }
			.yaml { emit_yaml_docs(docs) }
			.toml { emit_toml_docs(docs) }
			.md   { emit_md_docs(docs) }
		}
	}
	doc := res.single or { return error('no document') }
	return match to {
		.cx   { emit_cx(doc) }
		.xml  { emit_xml(doc) }
		.json { emit_semantic_json(doc) }
		.yaml { emit_yaml(doc) }
		.toml { emit_toml(doc) }
		.md   { emit_md(doc) }
	}
}
