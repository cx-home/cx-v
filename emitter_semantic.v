module cx

import encoding.base64

// ── Semantic JSON Emitter ─────────────────────────────────────────────────────
// Converts CX to a data-oriented JSON (like yaml/toml mapping).

pub fn emit_semantic_json(doc Document) string {
	val := sem_document(doc)
	return json_value_pretty(val, 0, false)
}

// emit_semantic_json_lossless is the conversions.md §0.2/§2.2.1 lossless JSON
// emit (#444, #475). Three layers stack:
//
//   • value layer (#444): every JSON object whose members carry a CX type the
//     plain representation loses (atom / date / datetime / decimal / bigint /
//     duration / period / bytes / sized numerics) gains a sibling `cx:type`
//     sidecar; typed values in ARRAY positions ride the per-item
//     `{"cx:T": payload}` carrier (§0.2, the JSON image of XML's `<cx:T>`).
//   • structure layer (#475): an ELEMENT emits as the reserved `$tag`
//     envelope (§2.2.1) — name / anchor / merge / id / type / body-ref /
//     attrs (+ `$attr-types`, D3's JSON image) / ordered children / table
//     payload — so element documents round-trip byte-identically
//     (strict-canonical eq). Multi-root documents wrap in `{"$doc": […]}`.
//   • non-collision: user map keys that look reserved (leading `$` or `cx:`)
//     escape behind the `cx:k:` prefix; non-string map keys gain the
//     `cx:key-type` sidecar.
//
// The default lane is untouched — the envelope exists only here. The CX
// importer reconstructs every reserved shape unconditionally
// (apply_lossless_structure / apply_cx_type_sidecar).
pub fn emit_semantic_json_lossless(doc Document) string {
	val := sem_document_lossless(doc)
	if val is JsonTyped {
		// a bare typed-scalar root has no enclosing object for a sidecar —
		// ride the per-item carrier so the type survives at the root too
		return json_typed_carrier(val as JsonTyped, 0)
	}
	return json_value_pretty(val, 0, true)
}

pub fn emit_semantic_json_docs_lossless(docs []Document) string {
	parts := docs.map(json_value_pretty(sem_document_lossless(it), 0, true))
	return '[${parts.join(',')}]'
}

// emit_semantic_json_opts is the single semantic element→JSON mapping
// (sem_document) with caller-chosen formatting: `indent` 0 = compact, >0 =
// pretty; `sort_keys` orders object keys. The cx-stdlib/json module routes
// element emit here so module and CLI share ONE element→JSON mapping (codec.md
// §6) — the module supplies compact+sorted for canonical emit, indent=2 for
// pretty.
pub fn emit_semantic_json_opts(doc Document, indent int, sort_keys bool) string {
	val := sem_document(doc)
	return json_value_fmt(val, 0, indent, sort_keys, false)
}

fn json_value_fmt(v JsonVal, depth int, indent int, sort_keys bool, lossless bool) string {
	return match v {
		JsonNull           { 'null' }
		JsonTyped          { json_typed_str(v as JsonTyped) }
		bool               { if v as bool { 'true' } else { 'false' } }
		i64                { (v as i64).str() }
		f64                { format_float(v as f64) }
		string             { json_str(v as string) }
		[]JsonVal          { json_array_fmt(v as []JsonVal, depth, indent, sort_keys, lossless) }
		map[string]JsonVal { json_object_fmt(v as map[string]JsonVal, depth, indent, sort_keys, lossless) }
	}
}

fn json_array_fmt(arr []JsonVal, depth int, indent int, sort_keys bool, lossless bool) string {
	if arr.len == 0 {
		return '[]'
	}
	if indent == 0 {
		items := arr.map(json_array_item_fmt(it, depth + 1, indent, sort_keys, lossless))
		return '[${items.join(',')}]'
	}
	pad := ' '.repeat(indent)
	ind := pad.repeat(depth + 1)
	close_ind := pad.repeat(depth)
	items := arr.map('${ind}${json_array_item_fmt(it, depth + 1, indent, sort_keys, lossless)}')
	return '[\n${items.join(',\n')}\n${close_ind}]'
}

// json_array_item_fmt renders one ARRAY-position item: in lossless mode a
// typed scalar rides the per-item `{"cx:T": …}` carrier (§0.2 — the sidecar
// keys by field name and cannot reach array positions); map-value positions
// keep the sidecar protocol via json_object_fmt.
fn json_array_item_fmt(v JsonVal, depth int, indent int, sort_keys bool, lossless bool) string {
	if lossless && v is JsonTyped {
		return json_typed_carrier(v as JsonTyped, depth)
	}
	return json_value_fmt(v, depth, indent, sort_keys, lossless)
}

fn json_object_fmt(obj map[string]JsonVal, depth int, indent int, sort_keys bool, lossless bool) string {
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
			pairs << '${json_str(k)}:${json_value_fmt(val, depth + 1, indent, sort_keys, lossless)}'
		}
		if lossless {
			if side := json_object_sidecar(obj, keys) {
				pairs << '"cx:type":${side}'
			}
		}
		return '{${pairs.join(',')}}'
	}
	pad := ' '.repeat(indent)
	ind := pad.repeat(depth + 1)
	close_ind := pad.repeat(depth)
	mut pairs := []string{cap: keys.len}
	for k in keys {
		val := obj[k] or { continue }
		pairs << '${ind}${json_str(k)}: ${json_value_fmt(val, depth + 1, indent, sort_keys, lossless)}'
	}
	if lossless {
		if side := json_object_sidecar(obj, keys) {
			pairs << '${ind}"cx:type": ${side}'
		}
	}
	return '{\n${pairs.join(',\n')}\n${close_ind}}'
}

// json_object_sidecar builds the §0.2 `cx:type` sidecar object for one JSON
// object: field-name → CX type name, for every member whose value is a typed
// scalar (JsonTyped). Rendered compact inline (the spec example's shape)
// regardless of the enclosing indent mode; none when no member is typed.
fn json_object_sidecar(obj map[string]JsonVal, keys []string) ?string {
	mut pairs := []string{}
	for k in keys {
		val := obj[k] or { continue }
		if val is JsonTyped {
			pairs << '${json_str(k)}: ${json_str((val as JsonTyped).typ)}'
		}
	}
	if pairs.len == 0 {
		return none
	}
	return '{${pairs.join(', ')}}'
}

// json_typed_str renders a typed scalar's VALUE image — identical in default
// and lossless modes (§0.2: the sidecar carries the type; the value stays the
// idiomatic JSON form).
fn json_typed_str(t JsonTyped) string {
	if type_name_is_sized_numeric(t.typ) {
		return t.text // sized numerics keep their native JSON number image
	}
	if t.typ == 'atom' {
		return json_str(':' + t.text) // colon-prefixed surface form (§0.2)
	}
	if t.typ == 'bytes' {
		return json_str(bytes_hex_to_base64(t.text)) // base64 string (§2.2)
	}
	return json_str(t.text)
}

// type_name_is_sized_numeric reports whether a type NAME is one of the
// storage-precision numeric refinements (grammar.ebnf [26a]) whose runtime
// value is a plain int/float — the name itself is the only extra information.
fn type_name_is_sized_numeric(name string) bool {
	return name in ['i8', 'i16', 'i32', 'i64', 'u8', 'u16', 'u32', 'u64', 'f16', 'f32', 'f64']
}

// ── bytes payload transcoding (conversions.md §0.2 bytes row, #458) ───────────
// CX stores a bytes scalar as its `0x…` hex text; the JSON / TOML / MD text
// lanes carry base64 (standard alphabet, padding kept — §2.2 "no
// padding-stripping"), YAML carries `!!binary`.

// bytes_hex_to_base64 converts a `0x…` bytes payload to its base64 image.
// A malformed payload (odd length, non-hex digit) passes through verbatim —
// emit never destroys data it cannot decode.
fn bytes_hex_to_base64(text string) string {
	raw := bytes_hex_to_raw(text) or { return text }
	return base64.encode(raw)
}

fn bytes_hex_to_raw(text string) ?[]u8 {
	mut body := text
	if body.starts_with('0x') || body.starts_with('0X') {
		body = body[2..]
	}
	if body.len % 2 != 0 {
		return none
	}
	mut raw := []u8{cap: body.len / 2}
	mut i := 0
	for i < body.len {
		hi := hex_digit_val(body[i]) // lexical.v: 0..15, or -1 if not a hex digit
		lo := hex_digit_val(body[i + 1])
		if hi < 0 || lo < 0 {
			return none
		}
		raw << u8((hi << 4) | lo)
		i += 2
	}
	return raw
}

// base64_to_bytes_hex is the import inverse: a base64 payload becomes the
// canonical `0x…` (lowercase) bytes text. none when the input is not valid
// base64 — the importer then keeps the value as a plain string.
fn base64_to_bytes_hex(b64 string) ?string {
	if b64.len == 0 {
		return none
	}
	raw := base64.decode(b64)
	if raw.len == 0 {
		return none
	}
	// Reject inputs base64.decode silently truncated / ignored: re-encode and
	// compare (padding-tolerant exactness — the emit side always pads).
	if base64.encode(raw) != b64 {
		return none
	}
	hex_chars := '0123456789abcdef'.bytes()
	mut out := []u8{cap: 2 + raw.len * 2}
	out << `0`
	out << `x`
	for b in raw {
		out << hex_chars[(b >> 4) & 0x0F]
		out << hex_chars[b & 0x0F]
	}
	return out.bytestr()
}

pub fn emit_semantic_json_docs(docs []Document) string {
	parts := docs.map(json_value_pretty(sem_document(it), 0, false))
	return '[${parts.join(',')}]'
}

// ── Internal JSON value type ──────────────────────────────────────────────────

type JsonVal = JsonTyped | JsonNull | bool | i64 | f64 | string | []JsonVal | map[string]JsonVal

struct JsonNull {}

// JsonTyped carries a type-bearing CX scalar through the semantic
// intermediate so each format emitter can render the per-type rows of
// spec/core/conversions.md §0.2 (default AND lossless columns) instead of
// collapsing everything to a plain string. Generalizes the former JsonAtom
// (#444/#458):
//   typ  — the CX type NAME: atom / date / datetime / decimal / bigint /
//          duration / period / bytes, or a sized numeric name (u16 / f32 / …)
//          rescued from the element / attribute type carrier.
//   text — the canonical payload text: the atom's name WITHOUT the leading
//          `:`; bytes as the `0x…` hex form; everything else the verbatim
//          ScalarValue text.
// Renderings: JSON → idiomatic value (+ `cx:type` sidecar entry in lossless
// mode); YAML → `!!cx:T` native tag / `!!binary` / native date forms;
// TOML/MD → lossy string image (no extension protocol, §0.2).
struct JsonTyped {
	typ  string
	text string
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
	//
	// #478: an ATTRIBUTED table element keeps its attributes in the
	// semantic projection — the same object-with-`_`-body shape every
	// other attrs+body element uses below ({attr keys…, "_": rows}).
	// Dropping them only on the table shape was the same silent-loss
	// family as the parse-side bug.
	if td := e.table_opt() {
		if e.attrs.len == 0 {
			return sem_table(td)
		}
		mut tobj := map[string]JsonVal{}
		for attr in e.attrs {
			tobj[attr.name] = attr_scalar_to_json(attr)
		}
		tobj['_'] = sem_table(td)
		return JsonVal(tobj)
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
			// Sized-numeric element annotation ([port::u16 8080]): the runtime
			// scalar collapses to int/float, so the precise name survives only
			// on the element's type carrier — rescue it into the typed
			// intermediate (§0.2 "sized name preserved").
			if dt := e.data_type() {
				if type_name_is_sized_numeric(dt) {
					return JsonVal(JsonTyped{ typ: dt, text: scalar_value_str(s.value) })
				}
			}
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
// data_type carrier (D3) so type-bearing attrs (`kind=:click`,
// `when::date=2023-01-15`, `port::u16=8080`) ride the typed intermediate
// (conversions.md §0.2 rows) rather than collapsing to plain string/number.
fn attr_scalar_to_json(a Attribute) JsonVal {
	if dt := a.data_type() {
		match dt {
			'atom', 'date', 'datetime', 'bytes', 'decimal', 'bigint', 'duration', 'period' {
				return JsonVal(JsonTyped{ typ: dt, text: scalar_value_str(a.value) })
			}
			else {
				if type_name_is_sized_numeric(dt) {
					return JsonVal(JsonTyped{ typ: dt, text: scalar_value_str(a.value) })
				}
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
	// Type-bearing scalar kinds (conversions.md §0.2 rows): their plain
	// payload alone loses the CX type, so they ride the JsonTyped carrier and
	// each format emitter renders its own row (atom tag / sidecar entry /
	// native date / …) instead of a bare string.
	match s.data_type {
		.atom_type, .date_type, .datetime_type, .bytes_type, .decimal_type, .bigint_type,
		.duration_type, .period_type {
			if s.value is string {
				return JsonVal(JsonTyped{ typ: scalar_type_name(s.data_type), text: s.value as string })
			}
		}
		else {}
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

fn json_value_pretty(v JsonVal, depth int, lossless bool) string {
	return match v {
		JsonNull    { 'null' }
		JsonTyped   { json_typed_str(v as JsonTyped) }
		bool        { if v as bool { 'true' } else { 'false' } }
		i64         { (v as i64).str() }
		f64         { format_float(v as f64) }
		string      { json_str(v as string) }
		[]JsonVal   { json_array_pretty(v as []JsonVal, depth, lossless) }
		map[string]JsonVal { json_object_pretty(v as map[string]JsonVal, depth, lossless) }
	}
}

fn json_array_pretty(arr []JsonVal, depth int, lossless bool) string {
	if arr.len == 0 { return '[]' }
	ind := '  '.repeat(depth + 1)
	close_ind := '  '.repeat(depth)
	items := arr.map('${ind}${json_array_item_pretty(it, depth + 1, lossless)}')
	return '[\n${items.join(',\n')}\n${close_ind}]'
}

// json_array_item_pretty — see json_array_item_fmt: array-position typed
// scalars ride the per-item carrier in lossless mode.
fn json_array_item_pretty(v JsonVal, depth int, lossless bool) string {
	if lossless && v is JsonTyped {
		return json_typed_carrier(v as JsonTyped, depth)
	}
	return json_value_pretty(v, depth, lossless)
}

fn json_object_pretty(obj map[string]JsonVal, depth int, lossless bool) string {
	if obj.len == 0 { return '{}' }
	ind := '  '.repeat(depth + 1)
	close_ind := '  '.repeat(depth)
	mut pairs := []string{}
	for k, vv in obj {
		pairs << '${ind}${json_str(k)}: ${json_value_pretty(vv, depth + 1, lossless)}'
	}
	if lossless {
		if side := json_object_sidecar(obj, obj.keys()) {
			pairs << '${ind}"cx:type": ${side}'
		}
	}
	return '{\n${pairs.join(',\n')}\n${close_ind}}'
}

// ── Lossless structure encoding: the `$tag` envelope (conversions.md §2.2.1, #475) ──
//
// The reserved envelope key set. An importer-side object is an envelope only
// when `$tag` is present AND every key is from this set (parser_lossless.v);
// the emitter writes keys in exactly this order.
pub const lossless_envelope_keys = ['\$tag', '\$anchor', '\$merge', '\$id', '\$type', '\$ref',
	'\$attrs', '\$attr-types', '\$children', '\$cols', '\$rows']

// lossless_escape_key hides a user map key / attribute name that would look
// reserved on re-import (leading `$` or `cx:`) behind the `cx:k:` escape
// prefix (§2.2.1 non-collision rule). Import strips one prefix,
// unconditionally (ll_unescape_key).
fn lossless_escape_key(k string) string {
	if k.starts_with('$') || k.starts_with('cx:') {
		return 'cx:k:${k}'
	}
	return k
}

// ll_single builds a reserved single-key carrier object ({"cx:seq": …},
// {"cx:raw": …}, {"cx:entity": …}).
fn ll_single(key string, val JsonVal) JsonVal {
	mut obj := map[string]JsonVal{}
	obj[key] = val
	return JsonVal(obj)
}

// sem_document_lossless projects a Document for the lossless lanes: a single
// element root becomes the `$tag` envelope; a value-model root keeps the
// §2.2/§4.1 value projection (with the lossless map/array rules); multiple
// roots wrap in the reserved `$doc` array.
fn sem_document_lossless(doc Document) JsonVal {
	roots := doc.elements.filter(!(it is CommentNode) && !(it is PINode) && !(it is XMLDeclNode)
		&& !(it is CXDirectiveNode) && !(it is InterpolationNode) && !(it is EvalDirectiveNode)
		&& !(it is MatchNode) && !(it is ModifyNode))
	if roots.len == 0 {
		return JsonVal(JsonNull{})
	}
	if roots.len == 1 {
		return node_value_ll(roots[0])
	}
	mut obj := map[string]JsonVal{}
	obj['\$doc'] = JsonVal(roots.map(node_value_ll(it)))
	return JsonVal(obj)
}

// sem_element_envelope emits one Element as its `$tag` envelope (§2.2.1).
fn sem_element_envelope(e Element) JsonVal {
	mut env := map[string]JsonVal{}
	env['\$tag'] = JsonVal(e.name)
	if a := e.anchor() {
		env['\$anchor'] = JsonVal(a)
	}
	if m := e.merge() {
		env['\$merge'] = JsonVal(m)
	}
	if id := e.id() {
		env['\$id'] = JsonVal(id)
	}
	if dt := e.data_type() {
		env['\$type'] = JsonVal(dt)
	}
	if br := e.body_ref() {
		env['\$ref'] = JsonVal(br)
	}
	if e.attrs.len > 0 {
		mut attrs := map[string]JsonVal{}
		mut atypes := map[string]JsonVal{}
		for a in e.attrs {
			key := lossless_escape_key(a.name)
			if a.is_ref {
				// reference attr (`assigned=@u-1`): bare id + `ref` pseudo-type
				attrs[key] = JsonVal(scalar_value_str(a.value))
				atypes[key] = JsonVal('ref')
				continue
			}
			if adt := a.data_type() {
				if tn := envelope_attr_type_entry(adt) {
					attrs[key] = envelope_attr_payload(adt, a.value)
					atypes[key] = JsonVal(tn)
					continue
				}
			}
			// base kinds ride JSON-native values; no `name=string` pin is
			// needed — JSON strings are typed natively (§2.2.1)
			attrs[key] = scalar_val_to_json(a.value)
		}
		env['\$attrs'] = JsonVal(attrs)
		if atypes.len > 0 {
			env['\$attr-types'] = JsonVal(atypes)
		}
	}
	if td := e.table_opt() {
		mut cols := []JsonVal{cap: td.cols.len}
		for c in td.cols {
			tok := if c.type_name == '' { c.name } else { '${c.name}::${c.type_name}' }
			cols << JsonVal(tok)
		}
		env['\$cols'] = JsonVal(cols)
		if td.rows.len > 0 {
			mut rows := []JsonVal{cap: td.rows.len}
			for row in td.rows {
				rows << JsonVal(row.map(table_cell_ll(it)))
			}
			env['\$rows'] = JsonVal(rows)
		}
	}
	mut children := []JsonVal{}
	for n in e.items {
		envelope_child_ll(n, mut children)
	}
	if children.len > 0 {
		env['\$children'] = JsonVal(children)
	}
	return JsonVal(env)
}

// envelope_attr_type_entry names the `$attr-types` entry for an attribute's
// ascribed type — exactly the types the JSON-native value image cannot carry
// (mirrors XML's cx:attr-types, D3). none for the JSON-native base kinds.
fn envelope_attr_type_entry(dt string) ?string {
	match dt {
		'atom', 'date', 'datetime', 'bytes', 'decimal', 'bigint', 'duration', 'period' {
			return dt
		}
		else {
			if type_name_is_sized_numeric(dt) {
				return dt
			}
			return none // int / float / bool / null / string — JSON-native
		}
	}
}

// envelope_attr_payload renders a typed attribute's idiomatic value image:
// sized numerics ride the native number, bytes ride base64, everything else
// the verbatim payload text (atom = bare name; canonical stores it bare).
fn envelope_attr_payload(dt string, v ScalarValue) JsonVal {
	if type_name_is_sized_numeric(dt) {
		return scalar_val_to_json(v)
	}
	if dt == 'bytes' {
		return JsonVal(bytes_hex_to_base64(scalar_value_str(v)))
	}
	return JsonVal(scalar_value_str(v))
}

// envelope_child_ll appends the lossless image(s) of one body item to the
// `$children` array (§2.2.1 items table). Comments / PIs / declarations /
// program directives are outside the lossless domain and drop; BlockContent
// dissolves into its runs (the strict-canonical reading).
fn envelope_child_ll(n Node, mut out []JsonVal) {
	match n {
		Element {
			out << sem_element_envelope(n)
		}
		TextNode {
			if n.value.trim_space().len > 0 {
				out << JsonVal(n.value)
			}
		}
		ScalarNode {
			out << scalar_native(n) // typed kinds ride JsonTyped → carrier / tag
		}
		RawTextNode {
			out << ll_single('cx:raw', JsonVal(n.value))
		}
		EntityRefNode {
			out << ll_single('cx:entity', JsonVal(n.name))
		}
		SequenceNode {
			out << ll_single('cx:seq', JsonVal(n.items.map(node_value_ll(it))))
		}
		IteratorNode {
			out << ll_single('cx:seq', JsonVal(iterator_to_sequence(n).items.map(node_value_ll(it))))
		}
		ArrayNode {
			out << JsonVal(n.items.map(node_value_ll(it)))
		}
		MapNode {
			out << map_node_ll(n)
		}
		BlockContentNode {
			for item in n.items {
				envelope_child_ll(item, mut out)
			}
		}
		else {}
	}
}

// node_value_ll is the lossless twin of node_value_to_json: values inside
// collections / at the document root. Elements route to the envelope,
// sequence-as-item / raw / entity take their reserved carriers, maps apply
// key escaping + the `cx:key-type` sidecar.
fn node_value_ll(n Node) JsonVal {
	return match n {
		ScalarNode    { scalar_native(n) }
		ArrayNode     { JsonVal(n.items.map(node_value_ll(it))) }
		SequenceNode  { ll_single('cx:seq', JsonVal(n.items.map(node_value_ll(it)))) }
		IteratorNode  { ll_single('cx:seq', JsonVal(iterator_to_sequence(n).items.map(node_value_ll(it)))) }
		MapNode       { map_node_ll(n) }
		Element       { sem_element_envelope(n) }
		TextNode      { JsonVal(n.value) }
		RawTextNode   { ll_single('cx:raw', JsonVal(n.value)) }
		EntityRefNode { ll_single('cx:entity', JsonVal(n.name)) }
		else          { JsonVal(JsonNull{}) }
	}
}

// map_node_ll projects a MapNode for the lossless lanes: entry order kept,
// reserved-looking keys escaped, non-string keys recorded in the
// `cx:key-type` sidecar (§0.2).
fn map_node_ll(n MapNode) JsonVal {
	mut obj := map[string]JsonVal{}
	mut ktypes := map[string]JsonVal{}
	for entry in n.entries {
		kstr := scalar_value_str(entry.key_value)
		key := lossless_escape_key(kstr)
		if entry.key_type != .string_type {
			ktypes[key] = JsonVal(scalar_type_name(entry.key_type))
		}
		obj[key] = node_value_ll(entry.value)
	}
	if ktypes.len > 0 {
		obj['cx:key-type'] = JsonVal(ktypes)
	}
	return JsonVal(obj)
}

// table_cell_ll projects one table cell for the lossless lanes. The scalar
// kinds are all JSON-native (a JSON string cell is unambiguous — §2.2.1);
// collection cells recurse through the lossless value projector.
fn table_cell_ll(c TableCellValue) JsonVal {
	return match c {
		bool         { JsonVal(c as bool) }
		i64          { JsonVal(c as i64) }
		f64          { JsonVal(c as f64) }
		string       { JsonVal(c as string) }
		NullValue    { JsonVal(JsonNull{}) }
		ArrayNode    { node_value_ll(Node(c)) }
		MapNode      { node_value_ll(Node(c)) }
		SequenceNode { node_value_ll(Node(c)) }
	}
}

// json_typed_carrier renders one typed scalar as its per-item carrier object
// `{"cx:T": payload}` (§0.2 array-position carrier): sized numerics ride the
// native number, bytes ride base64, atoms ride the bare name (the key names
// the type), everything else the verbatim payload text.
fn json_typed_carrier(t JsonTyped, depth int) string {
	payload := if type_name_is_sized_numeric(t.typ) {
		t.text
	} else if t.typ == 'bytes' {
		json_str(bytes_hex_to_base64(t.text))
	} else {
		json_str(t.text)
	}
	return '{"cx:${t.typ}": ${payload}}'
}
