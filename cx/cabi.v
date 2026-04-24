module cx

// ── C ABI ─────────────────────────────────────────────────────────────────────
// Exports the same flat C API as the Rust libcx.so so existing C/Python/V
// consumers can switch without source changes.
//
// Build as shared library:
//   v -shared -o target/libcx.so cx/     (Linux)
//   v -shared -o target/libcx.dylib cx/  (macOS)
//
// All functions return a heap-allocated C string the caller must release with
// cx_free().  On error they return NULL and, if err_out != NULL, set *err_out
// to a heap-allocated error message (also released with cx_free()).

// ── helpers ───────────────────────────────────────────────────────────────────

fn c_string(s string) &char {
	buf := unsafe { malloc(s.len + 1) }
	unsafe { vmemcpy(buf, s.str, s.len + 1) }
	return unsafe { &char(buf) }
}

fn c_err(msg string, err_out &&char) &char {
	if err_out != unsafe { nil } {
		unsafe { *err_out = c_string(msg) }
	}
	return unsafe { nil }
}

// ── memory ────────────────────────────────────────────────────────────────────

@[export: 'cx_free']
pub fn cx_free(s &char) {
	unsafe { free(voidptr(s)) }
}

// ── version ───────────────────────────────────────────────────────────────────

const cx_version_str = '0.5.0'

@[export: 'cx_version']
pub fn cx_version() &char {
	return c_string(cx_version_str)
}

// ── CX input ──────────────────────────────────────────────────────────────────

@[export: 'cx_to_cx_compact']
pub fn cx_to_cx_compact(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := to_cx_compact(src) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

@[export: 'cx_ast_to_cx']
pub fn cx_ast_to_cx(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := ast_to_cx(src) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

@[export: 'cx_to_cx']
pub fn cx_to_cx(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := to_cx(src) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

@[export: 'cx_to_xml']
pub fn cx_to_xml(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := to_xml(src) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

@[export: 'cx_to_ast']
pub fn cx_to_ast(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := to_ast(src) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

@[export: 'cx_to_json']
pub fn cx_to_json(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := to_json(src) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

@[export: 'cx_to_yaml']
pub fn cx_to_yaml(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := to_yaml(src) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

@[export: 'cx_to_toml']
pub fn cx_to_toml(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := to_toml(src) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

// ── XML input ─────────────────────────────────────────────────────────────────

@[export: 'cx_xml_to_cx']
pub fn cx_xml_to_cx(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := from_xml(src) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

@[export: 'cx_xml_to_xml']
pub fn cx_xml_to_xml(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .xml, .xml) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

@[export: 'cx_xml_to_ast']
pub fn cx_xml_to_ast(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	res := parse_xml_cx(src) or { return c_err(err.msg(), err_out) }
	result := if res.is_multi {
		docs := res.multi or { return unsafe { nil } }
		emit_ast_json_docs(docs)
	} else {
		doc := res.single or { return unsafe { nil } }
		emit_ast_json(doc)
	}
	return c_string(result)
}

@[export: 'cx_xml_to_json']
pub fn cx_xml_to_json(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .xml, .json) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

@[export: 'cx_xml_to_yaml']
pub fn cx_xml_to_yaml(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .xml, .yaml) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

@[export: 'cx_xml_to_toml']
pub fn cx_xml_to_toml(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .xml, .toml) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

// ── JSON/YAML/TOML input (not yet implemented — return error) ─────────────────

@[export: 'cx_json_to_cx']
pub fn cx_json_to_cx(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .json, .cx) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}
@[export: 'cx_json_to_xml']
pub fn cx_json_to_xml(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .json, .xml) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}
@[export: 'cx_json_to_ast']
pub fn cx_json_to_ast(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	res := parse_json_cx(src) or { return c_err(err.msg(), err_out) }
	result := if res.is_multi {
		docs := res.multi or { return unsafe { nil } }
		emit_ast_json_docs(docs)
	} else {
		doc := res.single or { return unsafe { nil } }
		emit_ast_json(doc)
	}
	return c_string(result)
}
@[export: 'cx_json_to_json']
pub fn cx_json_to_json(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .json, .json) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}
@[export: 'cx_json_to_yaml']
pub fn cx_json_to_yaml(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .json, .yaml) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}
@[export: 'cx_json_to_toml']
pub fn cx_json_to_toml(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .json, .toml) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

@[export: 'cx_yaml_to_cx']
pub fn cx_yaml_to_cx(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .yaml, .cx) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}
@[export: 'cx_yaml_to_xml']
pub fn cx_yaml_to_xml(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .yaml, .xml) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}
@[export: 'cx_yaml_to_ast']
pub fn cx_yaml_to_ast(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	res := parse_yaml_cx(src) or { return c_err(err.msg(), err_out) }
	result := if res.is_multi {
		docs := res.multi or { return unsafe { nil } }
		emit_ast_json_docs(docs)
	} else {
		doc := res.single or { return unsafe { nil } }
		emit_ast_json(doc)
	}
	return c_string(result)
}
@[export: 'cx_yaml_to_json']
pub fn cx_yaml_to_json(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .yaml, .json) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}
@[export: 'cx_yaml_to_yaml']
pub fn cx_yaml_to_yaml(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .yaml, .yaml) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}
@[export: 'cx_yaml_to_toml']
pub fn cx_yaml_to_toml(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .yaml, .toml) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

@[export: 'cx_toml_to_cx']
pub fn cx_toml_to_cx(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .toml, .cx) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}
@[export: 'cx_toml_to_xml']
pub fn cx_toml_to_xml(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .toml, .xml) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}
@[export: 'cx_toml_to_ast']
pub fn cx_toml_to_ast(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	res := parse_toml_cx(src) or { return c_err(err.msg(), err_out) }
	result := if res.is_multi {
		docs := res.multi or { return unsafe { nil } }
		emit_ast_json_docs(docs)
	} else {
		doc := res.single or { return unsafe { nil } }
		emit_ast_json(doc)
	}
	return c_string(result)
}
@[export: 'cx_toml_to_json']
pub fn cx_toml_to_json(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .toml, .json) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}
@[export: 'cx_toml_to_yaml']
pub fn cx_toml_to_yaml(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .toml, .yaml) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}
@[export: 'cx_toml_to_toml']
pub fn cx_toml_to_toml(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .toml, .toml) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

// ── MD output from other formats ─────────────────────────────────────────────

@[export: 'cx_to_md']
pub fn cx_to_md(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := to_md(src) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

@[export: 'cx_xml_to_md']
pub fn cx_xml_to_md(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .xml, .md) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

@[export: 'cx_json_to_md']
pub fn cx_json_to_md(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .json, .md) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

@[export: 'cx_yaml_to_md']
pub fn cx_yaml_to_md(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .yaml, .md) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

@[export: 'cx_toml_to_md']
pub fn cx_toml_to_md(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .toml, .md) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

// ── MD input ──────────────────────────────────────────────────────────────────

@[export: 'cx_md_to_cx']
pub fn cx_md_to_cx(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .md, .cx) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

@[export: 'cx_md_to_xml']
pub fn cx_md_to_xml(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .md, .xml) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

@[export: 'cx_md_to_ast']
pub fn cx_md_to_ast(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	res := parse_md_cx(src) or { return c_err(err.msg(), err_out) }
	result := if res.is_multi {
		docs := res.multi or { return unsafe { nil } }
		emit_ast_json_docs(docs)
	} else {
		doc := res.single or { return unsafe { nil } }
		emit_ast_json(doc)
	}
	return c_string(result)
}

@[export: 'cx_md_to_json']
pub fn cx_md_to_json(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .md, .json) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

@[export: 'cx_md_to_yaml']
pub fn cx_md_to_yaml(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .md, .yaml) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

@[export: 'cx_md_to_toml']
pub fn cx_md_to_toml(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .md, .toml) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

@[export: 'cx_md_to_md']
pub fn cx_md_to_md(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	s := convert(src, .md, .md) or { return c_err(err.msg(), err_out) }
	return c_string(s)
}

// ── Streaming ─────────────────────────────────────────────────────────────────

@[export: 'cx_to_events']
pub fn cx_to_events(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	doc := parse(src) or { return c_err(err.msg(), err_out) }
	mut stream := new_stream_from_doc(doc)
	events := stream.collect()
	parts := events.map(event_to_json(it))
	return c_string('[${parts.join(',')}]')
}

// ── Binary protocol ───────────────────────────────────────────────────────────

@[export: 'cx_to_events_bin']
pub fn cx_to_events_bin(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	doc := parse(src) or { return c_err(err.msg(), err_out) }
	mut stream := new_stream_from_doc(doc)
	events := stream.collect()
	buf := events_to_bin(events)
	return buf.to_heap()
}

@[export: 'cx_to_ast_bin']
pub fn cx_to_ast_bin(input &char, err_out &&char) &char {
	src := unsafe { cstring_to_vstring(input) }
	doc := parse(src) or { return c_err(err.msg(), err_out) }
	buf := doc_to_bin(doc)
	return buf.to_heap()
}
