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

// ── Internal JSON value type (mirrors conformance_run.v) ─────────────────────

type JV = JVNull | bool | i64 | f64 | string | []JV | map[string]JV

struct JVNull {}

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
				return [Element{ name: name, data_type: scalar_dt, items: items }]
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
		JVNull { ScalarNode{ data_type: .null_type, value: ScalarValue(NullValue{}) } }
		bool   { ScalarNode{ data_type: .bool_type, value: ScalarValue(v as bool) } }
		i64    { ScalarNode{ data_type: .int_type, value: ScalarValue(v as i64) } }
		f64    { ScalarNode{ data_type: .float_type, value: ScalarValue(v as f64) } }
		string { ScalarNode{ data_type: .string_type, value: ScalarValue(v as string) } }
		else   { ScalarNode{ data_type: .null_type, value: ScalarValue(NullValue{}) } }
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
			i64    { has_int = true }
			f64    { has_float = true }
			bool   { has_bool = true }
			string { has_str = true }
			JVNull { has_null = true }
			map[string]JV { has_obj = true }
			[]JV   { has_arr = true }
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

// ── Public API ────────────────────────────────────────────────────────────────

pub fn parse_json(src string) !Document {
	mut r := JReader{ src: src.bytes(), pos: 0 }
	r.skip_ws()
	if r.pos >= r.src.len { return Document{} }
	v := r.read_val()
	return jv_to_cx_doc(v)
}

pub fn parse_json_cx(src string) !ParseResult {
	doc := parse_json(src)!
	return ParseResult{ is_multi: false, single: doc }
}
