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

// Convert CX source to the LOSSLESS XML image (conversions.md §0.2): typed
// scalars carry their type so the XML→CX round-trip recovers every value
// exactly. See emit_xml_lossless.
pub fn to_xml_lossless(src string) !string {
	res := parse_cx(src)!
	if res.is_multi {
		docs := res.multi or { return error('no multi docs') }
		return emit_xml_docs_lossless(docs)
	}
	doc := res.single or { return error('no document') }
	return emit_xml_lossless(doc)
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

// Convert JSON source to CX. Routes through the registry (the canonical json
// parser is the strict, lossless one registered by `code` at init) so JSON → CX
// yields the CXDM value model (maps/arrays/scalars), not synthesised elements.
pub fn json_to_cx(src string) !string {
	return convert_by_name(src, 'json', 'cx', false)
}

// Convert YAML source to CX.
pub fn yaml_to_cx(src string) !string {
	res := parse_yaml_cx(src)!
	if res.is_multi {
		docs := res.multi or { return error('no multi docs') }
		return emit_cx_docs(docs)
	}
	doc := res.single or { return error('no document') }
	return emit_cx(doc)
}

// Convert TOML source to CX.
pub fn toml_to_cx(src string) !string {
	res := parse_toml_cx(src)!
	if res.is_multi {
		docs := res.multi or { return error('no multi docs') }
		return emit_cx_docs(docs)
	}
	doc := res.single or { return error('no document') }
	return emit_cx(doc)
}

// Convert any format to any other format.
pub fn convert(src string, from Format, to Format) !string {
	return convert_opts(src, from, to, false)
}

// convert_opts is convert with a lossless flag. When lossless is true and the
// target is XML, typed scalars carry their type per conversions.md §0.2
// (emit_xml_lossless); other targets are currently unaffected (their lossless
// forms are separate work).
//
// Both axes route through the codec registry (codec.md §6): convert_opts is a
// registry lookup + compose, never a per-pair branch. The Format enum maps to
// the registry's string keys via format_name.
pub fn convert_opts(src string, from Format, to Format, lossless bool) !string {
	return convert_by_name(src, format_name(from), format_name(to), lossless)
}

// format_name maps the public Format enum to its codec-registry key.
fn format_name(f Format) string {
	return match f {
		.cx { 'cx' }
		.xml { 'xml' }
		.json { 'json' }
		.yaml { 'yaml' }
		.toml { 'toml' }
		.md { 'md' }
	}
}
