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
	// v0.7.0 (ADR 0003 D1 second bullet / GG8): body-position [ref @id]
	// projects to the semantic-emit `$ref` shape, matching the JSON
	// Pointer / JSON Schema convention. YAML / TOML / MD round-trip
	// through this shape (lossy direction — JSON Pointer-style refs
	// are the cross-format consensus). Documented in spec/conversions.md.
	if br := e.body_ref {
		mut ref_obj := map[string]JsonVal{}
		ref_obj['\$ref'] = JsonVal(br)
		return JsonVal(ref_obj)
	}

	content := e.items.filter(
		!(it is CommentNode) && !(it is PINode) && !(it is XMLDeclNode) && !(it is CXDirectiveNode)
		&& !(it is InterpolationNode) && !(it is EvalDirectiveNode)
	)

	has_attrs    := e.attrs.len > 0
	has_elements := content.any(it is Element)
	all_scalars  := content.len > 0 && content.all(it is ScalarNode)
	has_text     := content.any(it is TextNode || it is RawTextNode || it is EntityRefNode || it is BlockContentNode)
	has_collections := content.any(it is SequenceNode || it is ArrayNode || it is MapNode)
	all_collections := content.len > 0 && content.all(it is SequenceNode || it is ArrayNode || it is MapNode)

	// Pure scalars, no attrs
	if !has_attrs && all_scalars {
		if content.len == 1 {
			s := content[0] as ScalarNode
			return scalar_native(s)
		}
		return JsonVal(content.map(scalar_native(it as ScalarNode)))
	}

	// Pure collection-literal body, no attrs (ADR 0017 §D12 — element body
	// is exactly the collection's JSON shape; sequence/array → JSON array,
	// map → JSON object).
	if !has_attrs && !has_elements && !has_text && all_collections {
		if content.len == 1 {
			return collection_to_json(content[0])
		}
		return JsonVal(content.map(collection_to_json(it)))
	}

	// Pure text, no attrs, no elements
	if !has_attrs && !has_elements && !has_collections && has_text {
		return JsonVal(sem_collect_text(content))
	}

	// Empty
	if !has_attrs && content.len == 0 { return JsonVal(JsonNull{}) }

	// Object
	mut obj := map[string]JsonVal{}
	for attr in e.attrs {
		obj[attr.name] = scalar_val_to_json(attr.value)
	}

	if has_elements || has_collections {
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
				// ADR 0017 §D12 mixed-content fallback: collection literals
				// alongside elements / attrs route through synthetic keys
				// (_seq / _arr / _map). Lossy at the JSON boundary by design.
				SequenceNode  { push_keyed(mut obj, '_seq', collection_to_json(n)) }
				ArrayNode     { push_keyed(mut obj, '_arr', collection_to_json(n)) }
				MapNode       { push_keyed(mut obj, '_map', collection_to_json(n)) }
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
		} else if all_collections && content.len == 1 {
			obj['_'] = collection_to_json(content[0])
		} else if has_text {
			obj['_'] = JsonVal(sem_collect_text(content))
		}
	}

	return JsonVal(obj)
}

// collection_to_json converts a SequenceNode / ArrayNode / MapNode to its
// data-shape JsonVal per ADR 0017 §D12.
//   - SequenceNode → JSON array (parser already flattened per CXDM §1.2)
//   - ArrayNode    → JSON array (nesting preserved)
//   - MapNode      → JSON object (key stringified via canonical form)
fn collection_to_json(n Node) JsonVal {
	return match n {
		SequenceNode { JsonVal(n.items.map(node_value_to_json(it))) }
		ArrayNode    { JsonVal(n.items.map(node_value_to_json(it))) }
		MapNode {
			mut obj := map[string]JsonVal{}
			for entry in n.entries {
				obj[scalar_value_str(entry.key_value)] = node_value_to_json(entry.value)
			}
			JsonVal(obj)
		}
		else { JsonVal(JsonNull{}) }
	}
}

// node_value_to_json materializes a Node appearing inside a collection
// literal (item / map value) as a JsonVal. Scalars become native JSON
// scalars; nested collections recurse; elements route back through
// sem_element so the object/array hierarchy stays semantic.
fn node_value_to_json(n Node) JsonVal {
	return match n {
		ScalarNode    { scalar_native(n) }
		SequenceNode  { collection_to_json(n) }
		ArrayNode     { collection_to_json(n) }
		MapNode       { collection_to_json(n) }
		Element       { sem_element(n) }
		TextNode      { JsonVal(n.value) }
		RawTextNode   { JsonVal(n.value) }
		EntityRefNode { JsonVal(entity_ref_str(n.name)) }
		else          { JsonVal(JsonNull{}) }
	}
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
