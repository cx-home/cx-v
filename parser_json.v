module cx

import strconv

// ── JSON → CX / AST Parser ────────────────────────────────────────────────────
// Parses JSON into CX Document(s) so JSON can be used as input to any emitter.
//
// Mapping rules (mirrors the inverse of sem_document / sem_element):
//   JSON object  → Element with child elements per key
//   JSON array   → Element with :type[] annotation + scalar children (if
//                  all homogeneous scalars), or repeated child elements otherwise
//   JSON string  → ScalarNode (string) or TextNode if mixed
//   JSON number  → ScalarNode (int or float)
//   JSON bool    → ScalarNode (bool)
//   JSON null    → empty Element (or omitted, depending on context)

// ── Internal JSON value type (mirrors tests/runners/conformance/conformance_run.v) ──

type JV = JVNull | JVTyped | bool | i64 | f64 | string | []JV | map[string]JV

struct JVNull {}

// JVTyped is the import-side twin of the emit-side JsonTyped carrier
// (emitter_semantic.v): a scalar whose CX type the source format named
// explicitly — a YAML `!!cx:T` / `!!binary` tag, a TOML/JSON sidecar entry,
// or format-native typing (YAML dates, temporal spans, bigint promotion).
//   typ  — CX type NAME (atom / date / datetime / decimal / bigint /
//          duration / period / bytes / sized numerics)
//   text — canonical payload: atom name WITHOUT `:`, bytes as `0x…` hex,
//          otherwise the verbatim scalar text
struct JVTyped {
	typ  string
	text string
}

// typed_scalar_node materializes a JVTyped as the CX value-model scalar. The
// sized numeric names collapse to int/float (the runtime value model carries
// no width — scalar_type_from_name's documented collapse); a payload that
// cannot parse under the named type degrades to a plain string rather than
// inventing a zero.
fn typed_scalar_node(typ string, text string) ScalarNode {
	st := scalar_type_from_name(typ) or {
		return ScalarNode{ data_type: .string_type, value: ScalarValue(text) }
	}
	match st {
		.int_type {
			if v := text.parse_int(10, 64) {
				return ScalarNode{ data_type: .int_type, value: ScalarValue(v) }
			}
			return ScalarNode{ data_type: .string_type, value: ScalarValue(text) }
		}
		.float_type {
			if v := strconv.atof64(text) {
				return ScalarNode{ data_type: .float_type, value: ScalarValue(v) }
			}
			return ScalarNode{ data_type: .string_type, value: ScalarValue(text) }
		}
		.bool_type {
			return ScalarNode{ data_type: .bool_type, value: ScalarValue(text == 'true') }
		}
		.null_type {
			return ScalarNode{ data_type: .null_type, value: ScalarValue(NullValue{}) }
		}
		else {
			return ScalarNode{ data_type: st, value: ScalarValue(text) }
		}
	}
}

// ── JSON Reader ───────────────────────────────────────────────────────────────

struct JReader {
mut:
	src []u8
	pos int
}

fn j_is_ws(b u8) bool {
	return b == ` ` || b == `\t` || b == `\n` || b == `\r`
}

fn (mut r JReader) skip_ws() {
	for r.pos < r.src.len && j_is_ws(r.src[r.pos]) { r.pos++ }
}

fn (mut r JReader) peek() u8 {
	if r.pos < r.src.len { return r.src[r.pos] }
	return 0
}

fn (mut r JReader) read_val() JV {
	r.skip_ws()
	if r.pos >= r.src.len { return JV(JVNull{}) }
	b := r.peek()
	return match b {
		`"` { r.read_str() }
		`{` { r.read_obj() }
		`[` { r.read_arr() }
		`t` { r.pos += 4; JV(true) }
		`f` { r.pos += 5; JV(false) }
		`n` { r.pos += 4; JV(JVNull{}) }
		else { r.read_num() }
	}
}

fn (mut r JReader) read_str() JV {
	r.pos++ // '"'
	mut s := []u8{}
	for r.pos < r.src.len {
		b := r.src[r.pos]
		if b == `"` { r.pos++; break }
		if b == `\\` {
			r.pos++
			if r.pos < r.src.len {
				esc := r.src[r.pos]
				r.pos++
				match esc {
					`n`  { s << `\n` }
					`r`  { s << `\r` }
					`t`  { s << `\t` }
					`"`  { s << `"` }
					`\\` { s << `\\` }
					`/`  { s << `/` }
					`u`  {
						// read 4 hex digits
						if r.pos + 4 <= r.src.len {
							hex := r.src[r.pos..r.pos+4].bytestr()
							r.pos += 4
							cp := hex.parse_int(16, 32) or { i64(0) }
							// simple UTF-8 encode
							if cp < 0x80 {
								s << u8(cp)
							} else if cp < 0x800 {
								s << u8(0xC0 | (cp >> 6))
								s << u8(0x80 | (cp & 0x3F))
							} else {
								s << u8(0xE0 | (cp >> 12))
								s << u8(0x80 | ((cp >> 6) & 0x3F))
								s << u8(0x80 | (cp & 0x3F))
							}
						}
					}
					else { s << `\\`; s << esc }
				}
			}
		} else {
			s << b
			r.pos++
		}
	}
	return JV(s.bytestr())
}

fn (mut r JReader) read_obj() JV {
	r.pos++ // '{'
	mut obj := map[string]JV{}
	r.skip_ws()
	if r.pos < r.src.len && r.peek() == `}` { r.pos++; return JV(obj) }
	for r.pos < r.src.len {
		r.skip_ws()
		key_v := r.read_val()
		key := if key_v is string { key_v as string } else { '' }
		r.skip_ws()
		if r.peek() == `:` { r.pos++ }
		val := r.read_val()
		obj[key] = val
		r.skip_ws()
		if r.peek() == `,` { r.pos++; continue }
		if r.peek() == `}` { r.pos++; break }
		break
	}
	return JV(obj)
}

fn (mut r JReader) read_arr() JV {
	r.pos++ // '['
	mut arr := []JV{}
	r.skip_ws()
	if r.pos < r.src.len && r.peek() == `]` { r.pos++; return JV(arr) }
	for r.pos < r.src.len {
		val := r.read_val()
		arr << val
		r.skip_ws()
		if r.peek() == `,` { r.pos++; continue }
		if r.peek() == `]` { r.pos++; break }
		break
	}
	return JV(arr)
}

fn (mut r JReader) read_num() JV {
	mut s := []u8{}
	mut is_float := false
	for r.pos < r.src.len {
		b := r.src[r.pos]
		if b == `,` || b == `}` || b == `]` || j_is_ws(b) { break }
		if b == `.` || b == `e` || b == `E` { is_float = true }
		s << b
		r.pos++
	}
	num_str := s.bytestr()
	if num_str == 'null'  { return JV(JVNull{}) }
	if num_str == 'true'  { return JV(true) }
	if num_str == 'false' { return JV(false) }
	if is_float {
		fv := strconv.atof64(num_str) or { return JV(f64(0)) }
		return JV(fv)
	}
	if iv := num_str.parse_int(10, 64) {
		return JV(iv)
	}
	// fallback to float
	fv := strconv.atof64(num_str) or { return JV(f64(0)) }
	return JV(fv)
}

// ── JSON → CX AST conversion ──────────────────────────────────────────────────

fn jv_to_cx_doc(v JV) Document {
	match v {
		map[string]JV {
			mut elems := []Node{}
			for k, child in v as map[string]JV {
				elems << jv_to_nodes(k, child)
			}
			return Document{ elements: elems }
		}
		[]JV {
			// top-level array: wrap each as anonymous element
			arr := v as []JV
			mut elems := []Node{}
			for item in arr {
				elems << jv_to_nodes('item', item)
			}
			return Document{ elements: elems }
		}
		else {
			// scalar at top level: wrap in 'value'
			return Document{ elements: jv_to_nodes('value', v) }
		}
	}
}

// jv_to_value_node converts a parsed JV tree to the LOSSLESS native value
// model — MapNode / ArrayNode / ScalarNode — instead of synthesized Elements.
// This mirrors the JSON codec's map-model output ({server: {port: 8080}}) so
// the YAML (#4) and TOML (#5) codecs import losslessly: a mapping is a Map, a
// sequence is an Array, scalars keep their type. (jv_to_cx_doc / jv_to_nodes
// remain for the legacy element-synthesising parsers.)
fn jv_to_value_node(v JV) Node {
	match v {
		map[string]JV {
			obj := v as map[string]JV
			mut entries := []MapEntry{}
			for k, child in obj {
				entries << MapEntry{
					key_type:  .string_type
					key_value: ScalarValue(k)
					value:     jv_to_value_node(child)
				}
			}
			return MapNode{ entries: entries }
		}
		[]JV {
			arr := v as []JV
			mut items := []Node{}
			for item in arr {
				items << jv_to_value_node(item)
			}
			return ArrayNode{ items: items }
		}
		JVNull  { return ScalarNode{ data_type: .null_type, value: ScalarValue(NullValue{}) } }
		JVTyped { return typed_scalar_node(v.typ, v.text) }
		bool    { return ScalarNode{ data_type: .bool_type, value: ScalarValue(v as bool) } }
		i64     { return ScalarNode{ data_type: .int_type, value: ScalarValue(v as i64) } }
		f64     { return ScalarNode{ data_type: .float_type, value: ScalarValue(v as f64) } }
		string  { return ScalarNode{ data_type: .string_type, value: ScalarValue(v as string) } }
	}
}

// jv_to_value_doc wraps the top-level JV as a single-value Document (Map /
// Array / Scalar root). sem_document + emit_cx both project a single non-
// Element root directly, so the import renders `{…}` / `[…]` / a scalar — the
// lossless read shape shared with the JSON codec.
fn jv_to_value_doc(v JV) Document {
	return Document{ elements: [jv_to_value_node(v)] }
}

// Returns one or more nodes for a key+value. An array of objects becomes
// repeated elements with the same key name (like CX repeated elements).
fn jv_to_nodes(name string, v JV) []Node {
	match v {
		[]JV {
			arr := v as []JV
			if arr.len == 0 { return [Element{ name: name, items: [] }] }
			// scalar array → typed array element
			is_scalar_arr, scalar_dt := jv_arr_scalar_type(arr)
			if is_scalar_arr {
				mut items := []Node{}
				for item in arr {
					items << jv_to_scalar(item)
				}
				return [new_element(name, ElementMeta{ data_type: scalar_dt }, [], items)]
			}
			// array of objects → repeated elements with same name
			if arr.all(it is map[string]JV) {
				mut repeated := []Node{}
				for item in arr {
					repeated << jv_to_nodes(name, item)
				}
				return repeated
			}
			// mixed array → children named 'item'
			mut children := []Node{}
			for item in arr {
				children << jv_to_nodes('item', item)
			}
			return [Element{ name: name, items: children }]
		}
		else {
			return [jv_to_single_element(name, v)]
		}
	}
}

fn jv_to_single_element(name string, v JV) Node {
	match v {
		JVNull { return Element{ name: name, items: [] } }
		JVTyped {
			return Element{ name: name, items: [Node(typed_scalar_node(v.typ, v.text))] }
		}
		bool {
			val := v as bool
			return Element{
				name: name
				items: [ ScalarNode{ data_type: .bool_type, value: ScalarValue(val) } ]
			}
		}
		i64 {
			val := v as i64
			return Element{
				name: name
				items: [ ScalarNode{ data_type: .int_type, value: ScalarValue(val) } ]
			}
		}
		f64 {
			val := v as f64
			return Element{
				name: name
				items: [ ScalarNode{ data_type: .float_type, value: ScalarValue(val) } ]
			}
		}
		string {
			val := v as string
			return Element{
				name: name
				items: [ TextNode{ value: val } ]
			}
		}
		map[string]JV {
			obj := v as map[string]JV
			mut items := []Node{}
			for k, child in obj {
				items << jv_to_nodes(k, child)
			}
			return Element{ name: name, items: items }
		}
		[]JV {
			// This case handled in jv_to_nodes, shouldn't be called here
			arr := v as []JV
			mut children := []Node{}
			for item in arr {
				children << jv_to_nodes('item', item)
			}
			return Element{ name: name, items: children }
		}
	}
}

fn jv_to_scalar(v JV) Node {
	return match v {
		JVNull  { ScalarNode{ data_type: .null_type, value: ScalarValue(NullValue{}) } }
		JVTyped { typed_scalar_node(v.typ, v.text) }
		bool    { ScalarNode{ data_type: .bool_type, value: ScalarValue(v as bool) } }
		i64     { ScalarNode{ data_type: .int_type, value: ScalarValue(v as i64) } }
		f64     { ScalarNode{ data_type: .float_type, value: ScalarValue(v as f64) } }
		string  { ScalarNode{ data_type: .string_type, value: ScalarValue(v as string) } }
		else    { ScalarNode{ data_type: .null_type, value: ScalarValue(NullValue{}) } }
	}
}

// Returns (all_same_scalar, type_string) if all elements are scalars of same type
fn jv_arr_scalar_type(arr []JV) (bool, ?string) {
	if arr.len == 0 { return false, none }
	mut has_int   := false
	mut has_float := false
	mut has_bool  := false
	mut has_str   := false
	mut has_null  := false
	mut has_obj   := false
	mut has_arr   := false
	for v in arr {
		match v {
			i64     { has_int = true }
			f64     { has_float = true }
			bool    { has_bool = true }
			string  { has_str = true }
			JVNull  { has_null = true }
			JVTyped { has_obj = true } // typed scalars keep their own nodes — not a homogeneous scalar array
			map[string]JV { has_obj = true }
			[]JV    { has_arr = true }
		}
	}
	if has_obj || has_arr { return false, none }
	// int + float → float[]
	if has_int && has_float && !has_bool && !has_str && !has_null {
		return true, ?string('float[]')
	}
	// single type
	if has_int  && !has_float && !has_bool && !has_str && !has_null { return true, ?string('int[]') }
	if has_float && !has_int && !has_bool && !has_str && !has_null  { return true, ?string('float[]') }
	if has_bool  && !has_int && !has_float && !has_str && !has_null { return true, ?string('bool[]') }
	if has_str   && !has_int && !has_float && !has_bool && !has_null { return true, ?string('string[]') }
	return false, none
}

// ── JSON `cx:type` sidecar import (conversions.md §0.2, #444) ─────────────────
//
// apply_cx_type_sidecar walks an imported value tree and consumes every
// object-level `cx:type` sidecar: a Map entry whose key is exactly `cx:type`
// and whose value is a Map of field-name → CX type-name strings. The entry is
// removed and each named sibling field is re-typed:
//
//   bytes            — base64 string payload → `0x…` bytes scalar
//   atom             — ":NAME" (or bare NAME) string → atom scalar
//   date / datetime / decimal / bigint / duration / period
//                    — string payload → the typed scalar, text verbatim
//   sized numerics   — the value is already a native JSON number; the runtime
//                      value model carries no width, so it stays int/float
//                      (scalar_type_from_name's documented collapse)
//
// The sidecar is consumed UNCONDITIONALLY (no import-side mode flag), matching
// the XML importer's treatment of the reserved `cx:` namespace (xml_parser.v
// consumes cx:type attributes on every parse): `cx:` is CX's reserved protocol
// prefix at every conversion boundary. Fields the sidecar names but that are
// missing, non-scalar, or whose payload cannot decode are left untouched.
pub fn apply_cx_type_sidecar(n Node) Node {
	match n {
		MapNode {
			mut side := map[string]string{}
			mut entries := []MapEntry{cap: n.entries.len}
			for entry in n.entries {
				if entry.key_type == .string_type {
					kv := entry.key_value
					if kv is string && kv == 'cx:type' {
						if tm := sidecar_type_map(entry.value) {
							for k, tn in tm {
								side[k] = tn
							}
							continue // consume the sidecar entry
						}
					}
				}
				entries << MapEntry{
					key_type:  entry.key_type
					key_value: entry.key_value
					value:     apply_cx_type_sidecar(entry.value)
				}
			}
			if side.len > 0 {
				for i, entry in entries {
					if entry.key_type != .string_type {
						continue
					}
					kv := entry.key_value
					if kv is string {
						if tn := side[kv] {
							entries[i] = MapEntry{
								key_type:  entry.key_type
								key_value: entry.key_value
								value:     sidecar_retype(entry.value, tn)
							}
						}
					}
				}
			}
			return MapNode{ ...n, entries: entries }
		}
		ArrayNode {
			return ArrayNode{ ...n, items: n.items.map(apply_cx_type_sidecar(it)) }
		}
		SequenceNode {
			return SequenceNode{ ...n, items: n.items.map(apply_cx_type_sidecar(it)) }
		}
		Element {
			return Element{ ...n, items: n.items.map(apply_cx_type_sidecar(it)) }
		}
		else {
			return n
		}
	}
}

// sidecar_type_map reads a sidecar value node as field-name → type-name; none
// unless it is a Map whose keys and values are all plain strings.
fn sidecar_type_map(n Node) ?map[string]string {
	if n !is MapNode {
		return none
	}
	m := n as MapNode
	mut out := map[string]string{}
	for entry in m.entries {
		if entry.key_type != .string_type {
			return none
		}
		kv := entry.key_value
		if kv !is string {
			return none
		}
		val := entry.value
		if val !is ScalarNode {
			return none
		}
		sv := (val as ScalarNode).value
		if sv !is string {
			return none
		}
		out[kv as string] = sv as string
	}
	if out.len == 0 {
		return none
	}
	return out
}

// sidecar_retype applies one sidecar entry to one value node. Only a plain
// string scalar re-types (the §0.2 payloads are strings); sized-numeric names
// leave the native number as-is; anything unexpected passes through.
fn sidecar_retype(n Node, type_name string) Node {
	if type_name_is_sized_numeric(type_name) {
		return n // native JSON number already carries the runtime value
	}
	if n !is ScalarNode {
		return n
	}
	s := n as ScalarNode
	if s.data_type != .string_type {
		return n
	}
	sv := s.value
	if sv !is string {
		return n
	}
	text := sv as string
	match type_name {
		'bytes' {
			if hex := base64_to_bytes_hex(text) {
				return ScalarNode{ ...s, data_type: .bytes_type, value: ScalarValue(hex) }
			}
			return n
		}
		'atom' {
			return ScalarNode{ ...s, data_type: .atom_type, value: ScalarValue(text.trim_string_left(':')) }
		}
		'date', 'datetime', 'decimal', 'bigint', 'duration', 'period' {
			st := scalar_type_from_name(type_name) or { return n }
			return ScalarNode{ ...s, data_type: st, value: ScalarValue(text) }
		}
		else {
			return n // unknown type name — leave the value untouched
		}
	}
}

// ── Deprecated JSON entry points retired (item C, conversions.md §4.1) ───────
//
// `parse_json` / `parse_json_cx` synthesised named CX elements from JSON
// (`{"a":1}` → `[a 1]`), a lossy invention. JSON → CX is now the lossless
// map/array/scalar read performed by the strict parser in
// vcx/code/stdlib_json.v (`json_do_parse`), registered as the canonical `json`
// codec parse at init (cx.register_codec). The CLI, C ABI and convert_by_name
// all route through that one parser via the registry.
//
// The JV / JReader machinery above is RETAINED: it is shared by the YAML, TOML
// and AST-JSON parsers (parser_yaml.v / parser_toml.v / parser_ast_json.v),
// which build a JV tree and reuse jv_to_cx_doc / JReader.read_val.
