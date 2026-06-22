module cx

// ── Semantic JSON Emitter ─────────────────────────────────────────────────────
// Converts CX to a data-oriented JSON (like yaml/toml mapping).

pub fn emit_semantic_json(doc Document) string {
	val := sem_document(doc)
	return json_value_pretty(val, 0)
}

// emit_semantic_json_opts is the single semantic element→JSON mapping
// (sem_document) with caller-chosen formatting: `indent` 0 = compact, >0 =
// pretty; `sort_keys` orders object keys. The cx-stdlib/json module routes
// element emit here so module and CLI share ONE element→JSON mapping (codec.md
// §6) — the module supplies compact+sorted for canonical emit, indent=2 for
// pretty.
pub fn emit_semantic_json_opts(doc Document, indent int, sort_keys bool) string {
	val := sem_document(doc)
	return json_value_fmt(val, 0, indent, sort_keys)
}

fn json_value_fmt(v JsonVal, depth int, indent int, sort_keys bool) string {
	return match v {
		JsonNull           { 'null' }
		JsonAtom           { json_str(':' + (v as JsonAtom).name) }
		bool               { if v as bool { 'true' } else { 'false' } }
		i64                { (v as i64).str() }
		f64                { format_float(v as f64) }
		string             { json_str(v as string) }
		[]JsonVal          { json_array_fmt(v as []JsonVal, depth, indent, sort_keys) }
		map[string]JsonVal { json_object_fmt(v as map[string]JsonVal, depth, indent, sort_keys) }
	}
}

fn json_array_fmt(arr []JsonVal, depth int, indent int, sort_keys bool) string {
	if arr.len == 0 {
		return '[]'
	}
	if indent == 0 {
		items := arr.map(json_value_fmt(it, depth + 1, indent, sort_keys))
		return '[${items.join(',')}]'
	}
	pad := ' '.repeat(indent)
	ind := pad.repeat(depth + 1)
	close_ind := pad.repeat(depth)
	items := arr.map('${ind}${json_value_fmt(it, depth + 1, indent, sort_keys)}')
	return '[\n${items.join(',\n')}\n${close_ind}]'
}

fn json_object_fmt(obj map[string]JsonVal, depth int, indent int, sort_keys bool) string {
	if obj.len == 0 {
		return '{}'
	}
	mut keys := obj.keys()
	if sort_keys {
		keys.sort()
	}
	if indent == 0 {
		mut pairs := []string{cap: keys.len}
		for k in keys {
			val := obj[k] or { continue }
			pairs << '${json_str(k)}:${json_value_fmt(val, depth + 1, indent, sort_keys)}'
		}
		return '{${pairs.join(',')}}'
	}
	pad := ' '.repeat(indent)
	ind := pad.repeat(depth + 1)
	close_ind := pad.repeat(depth)
	mut pairs := []string{cap: keys.len}
	for k in keys {
		val := obj[k] or { continue }
		pairs << '${ind}${json_str(k)}: ${json_value_fmt(val, depth + 1, indent, sort_keys)}'
	}
	return '{\n${pairs.join(',\n')}\n${close_ind}}'
}

pub fn emit_semantic_json_docs(docs []Document) string {
	parts := docs.map(json_value_pretty(sem_document(it), 0))
	return '[${parts.join(',')}]'
}

// ── Internal JSON value type ──────────────────────────────────────────────────

type JsonVal = JsonAtom | JsonNull | bool | i64 | f64 | string | []JsonVal | map[string]JsonVal

struct JsonNull {}

// JsonAtom carries a CX atom scalar through the semantic
// intermediate so each format emitter can render the atom row of
// spec/core/conversions.md distinctly from a plain string:
//   - JSON  → string `":NAME"` (colon-prefixed surface form)
//   - YAML  → `!!cx:atom "NAME"` native tag
//   - TOML  → string `":NAME"` (no tag protocol; lossy surface form)
// `name` is the atom's name WITHOUT the leading `:` (matching the
// ScalarNode payload and AST JSON `value` shape).
struct JsonAtom {
	name string
}

fn sem_document(doc Document) JsonVal {
	// Value-model document: a single CXDM value at top level (a Map / Array /
	// Sequence / Scalar, not a named Element). JSON → CX and the other value
	// codecs produce this shape — the lossless read — so the semantic emit
	// (and YAML / TOML, which route through here) project the value directly
	// instead of dropping it as a non-Element root.
	if doc.elements.len == 1 {
		only := doc.elements[0]
		if only !is Element {
			return node_value_to_json(only)
		}
	}
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
	// GG8: body-position [ref @id]
	// projects to the semantic-emit `$ref` shape, matching the JSON
	// Pointer / JSON Schema convention. YAML / TOML / MD round-trip
	// through this shape (lossy direction — JSON Pointer-style refs
	// are the cross-format consensus). Documented in spec/conversions.md.
	if br := e.body_ref() {
		mut ref_obj := map[string]JsonVal{}
		ref_obj['\$ref'] = JsonVal(br)
		return JsonVal(ref_obj)
	}

	// A :table element carries its rows/cols in the pooled `table`
	// (TableData), NOT in `items` (#10). Project it to a JSON array of
	// column-keyed row objects; otherwise the generic path below sees an
	// empty body and emits null. Matches CSV/canonical, which already read
	// the table payload.
	if td := e.table_opt() {
		return sem_table(td)
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

	// Pure collection-literal body, no attrs (element body
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
		obj[attr.name] = attr_scalar_to_json(attr)
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
				// mixed-content fallback: collection literals
				// alongside elements / attrs route through synthetic keys
				// (_seq / _arr / _map). Lossy at the JSON boundary by design.
				SequenceNode  { push_keyed(mut obj, '_seq', collection_to_json(n)) }
				ArrayNode     { push_keyed(mut obj, '_arr', collection_to_json(n)) }
				MapNode       { push_keyed(mut obj, '_map', collection_to_json(n)) }
				IteratorNode  {
					// materialize to Sequence form for the
					// semantic JSON projection. Same `_seq` key as the
					// SequenceNode arm; eval pulls before render.
					push_keyed(mut obj, '_seq', collection_to_json(Node(iterator_to_sequence(n))))
				}
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
// data-shape JsonVal.
//   - SequenceNode → JSON array (parser already flattened per CXDM §1.2)
//   - ArrayNode    → JSON array (nesting preserved)
//   - MapNode      → JSON object (key stringified via canonical form)
fn collection_to_json(n Node) JsonVal {
	return match n {
		SequenceNode { JsonVal(n.items.map(node_value_to_json(it))) }
		ArrayNode    { JsonVal(n.items.map(node_value_to_json(it))) }
		IteratorNode { JsonVal(iterator_to_sequence(n).items.map(node_value_to_json(it))) }
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

// sem_table projects a :table element to a JSON array of row objects, each
// keyed by column name (#10). Cell values mirror scalar_val_to_json /
// collection_to_json so typed scalars and collection cells carry through.
fn sem_table(td &TableData) JsonVal {
	mut rows := []JsonVal{cap: td.rows.len}
	for row in td.rows {
		mut obj := map[string]JsonVal{}
		for i, cell in row {
			col := if i < td.cols.len { td.cols[i].name } else { '_${i}' }
			obj[col] = table_cell_to_json(cell)
		}
		rows << JsonVal(obj)
	}
	return JsonVal(rows)
}

// table_cell_to_json converts one TableCellValue to a JsonVal. Scalar
// variants map to native JSON scalars; collection cells route through
// collection_to_json (same projection as collection-literal element bodies).
fn table_cell_to_json(c TableCellValue) JsonVal {
	return match c {
		bool         { JsonVal(c as bool) }
		i64          { JsonVal(c as i64) }
		f64          { JsonVal(c as f64) }
		string       { JsonVal(c as string) }
		NullValue    { JsonVal(JsonNull{}) }
		ArrayNode    { collection_to_json(Node(c)) }
		MapNode      { collection_to_json(Node(c)) }
		SequenceNode { collection_to_json(Node(c)) }
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
		IteratorNode  { collection_to_json(n) }
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

// attr_scalar_to_json projects an attribute's scalar value, honouring its
// data_type so atom-typed attrs (`kind=:click`) carry the atom
// marker through the intermediate rather than collapsing to a plain string.
fn attr_scalar_to_json(a Attribute) JsonVal {
	if dt := a.data_type() {
		if dt == 'atom' {
			if a.value is string {
				return JsonVal(JsonAtom{ name: a.value as string })
			}
		}
	}
	return scalar_val_to_json(a.value)
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
	// Atom: the ScalarValue payload is the name string, but the
	// atom row of conversions.md requires a distinct projection per format
	// — route it through JsonAtom rather than the plain-string arm.
	if s.data_type == .atom_type {
		if s.value is string {
			return JsonVal(JsonAtom{ name: s.value as string })
		}
	}
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
		JsonAtom    { json_str(':' + (v as JsonAtom).name) }
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
