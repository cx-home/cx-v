module cx

// ── Semantic JSON Emitter ─────────────────────────────────────────────────────
// Converts CX to a data-oriented JSON (like yaml/toml mapping).

pub fn emit_semantic_json(doc Document) string {
	val := sem_document(doc)
	return json_value_pretty(val, 0)
}

pub fn emit_semantic_json_docs(docs []Document) string {
	parts := docs.map(json_value_pretty(sem_document(it), 0))
	return '[${parts.join(',')}]'
}

// ── Internal JSON value type ──────────────────────────────────────────────────

type JsonVal = JsonNull | bool | i64 | f64 | string | []JsonVal | map[string]JsonVal

struct JsonNull {}

fn sem_document(doc Document) JsonVal {
	roots := doc.elements.filter(it is Element)
	if roots.len == 0 { return JsonVal(JsonNull{}) }
	mut obj := map[string]JsonVal{}
	for n in roots {
		if n is Element {
			e := n as Element
			push_keyed(mut obj, e.name, sem_element(e))
		}
	}
	return JsonVal(obj)
}

fn sem_element(e Element) JsonVal {
	content := e.items.filter(
		!(it is CommentNode) && !(it is PINode) && !(it is XMLDeclNode) && !(it is CXDirectiveNode)
	)

	has_attrs    := e.attrs.len > 0
	has_elements := content.any(it is Element)
	all_scalars  := content.len > 0 && content.all(it is ScalarNode)
	has_text     := content.any(it is TextNode || it is RawTextNode || it is EntityRefNode || it is BlockContentNode)

	// Pure scalars, no attrs
	if !has_attrs && all_scalars {
		if content.len == 1 {
			s := content[0] as ScalarNode
			return scalar_native(s)
		}
		return JsonVal(content.map(scalar_native(it as ScalarNode)))
	}

	// Pure text, no attrs, no elements
	if !has_attrs && !has_elements && has_text {
		return JsonVal(sem_collect_text(content))
	}

	// Empty
	if !has_attrs && content.len == 0 { return JsonVal(JsonNull{}) }

	// Object
	mut obj := map[string]JsonVal{}
	for attr in e.attrs {
		obj[attr.name] = scalar_val_to_json(attr.value)
	}

	if has_elements {
		for n in content {
			match n {
				Element {
					push_keyed(mut obj, n.name, sem_element(n))
				}
				TextNode {
					if n.value.trim_space().len > 0 {
						push_text(mut obj, n.value)
					}
				}
				RawTextNode  { push_text(mut obj, n.value) }
				EntityRefNode { push_text(mut obj, entity_ref_str(n.name)) }
				ScalarNode    { push_keyed(mut obj, '_', scalar_native(n)) }
				BlockContentNode {
					for item in n.items {
						if item is TextNode {
							if (item as TextNode).value.trim_space().len > 0 {
								push_text(mut obj, (item as TextNode).value)
							}
						}
					}
				}
				else {}
			}
		}
	} else if has_attrs {
		if all_scalars && content.len == 1 {
			obj['_'] = scalar_native(content[0] as ScalarNode)
		} else if has_text {
			obj['_'] = JsonVal(sem_collect_text(content))
		}
	}

	return JsonVal(obj)
}

fn push_keyed(mut obj map[string]JsonVal, key string, val JsonVal) {
	if key in obj {
		existing := obj[key] or { JsonVal(JsonNull{}) }
		if existing is []JsonVal {
			mut arr := existing as []JsonVal
			arr << val
			obj[key] = JsonVal(arr)
		} else {
			obj[key] = JsonVal([existing, val])
		}
	} else {
		obj[key] = val
	}
}

fn push_text(mut obj map[string]JsonVal, text string) {
	if '_' in obj {
		existing := obj['_'] or { JsonVal('') }
		if existing is string {
			obj['_'] = JsonVal(existing + text)
		}
	} else {
		obj['_'] = JsonVal(text)
	}
}

fn sem_collect_text(nodes []Node) string {
	mut parts := []string{}
	for n in nodes {
		match n {
			TextNode      { parts << n.value }
			RawTextNode   { parts << n.value }
			EntityRefNode { parts << entity_ref_str(n.name) }
			BlockContentNode {
				for item in n.items {
					if item is TextNode { parts << (item as TextNode).value }
				}
			}
			else {}
		}
	}
	return parts.join('')
}

fn scalar_val_to_json(v ScalarValue) JsonVal {
	return match v {
		i64       { JsonVal(v as i64) }
		f64       { JsonVal(v as f64) }
		bool      { JsonVal(v as bool) }
		NullValue { JsonVal(JsonNull{}) }
		string    { JsonVal(v as string) }
	}
}

fn entity_ref_str(name string) string {
	return match name {
		'amp'  { '&' }
		'lt'   { '<' }
		'gt'   { '>' }
		'apos' { "'" }
		'quot' { '"' }
		else   { '&${name};' }
	}
}

fn scalar_native(s ScalarNode) JsonVal {
	return match s.value {
		i64       { JsonVal(s.value as i64) }
		f64       { JsonVal(s.value as f64) }
		bool      { JsonVal(s.value as bool) }
		NullValue { JsonVal(JsonNull{}) }
		string    { JsonVal(s.value as string) }
	}
}

// ── JSON value serialization ──────────────────────────────────────────────────

fn json_value_pretty(v JsonVal, depth int) string {
	return match v {
		JsonNull    { 'null' }
		bool        { if v as bool { 'true' } else { 'false' } }
		i64         { (v as i64).str() }
		f64         { format_float(v as f64) }
		string      { json_str(v as string) }
		[]JsonVal   { json_array_pretty(v as []JsonVal, depth) }
		map[string]JsonVal { json_object_pretty(v as map[string]JsonVal, depth) }
	}
}

fn json_array_pretty(arr []JsonVal, depth int) string {
	if arr.len == 0 { return '[]' }
	ind := '  '.repeat(depth + 1)
	close_ind := '  '.repeat(depth)
	items := arr.map('${ind}${json_value_pretty(it, depth + 1)}')
	return '[\n${items.join(',\n')}\n${close_ind}]'
}

fn json_object_pretty(obj map[string]JsonVal, depth int) string {
	if obj.len == 0 { return '{}' }
	ind := '  '.repeat(depth + 1)
	close_ind := '  '.repeat(depth)
	mut pairs := []string{}
	for k, vv in obj {
		pairs << '${ind}${json_str(k)}: ${json_value_pretty(vv, depth + 1)}'
	}
	return '{\n${pairs.join(',\n')}\n${close_ind}}'
}
