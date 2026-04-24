module cx

import strconv

// ── TOML → CX / AST Parser ───────────────────────────────────────────────────
// Minimal TOML parser. Uses a reader struct to track position.

struct TReader {
mut:
	src string
	pos int
}

fn (mut r TReader) at_end() bool { return r.pos >= r.src.len }
fn (mut r TReader) peek() u8 { if r.at_end() { return 0 } return r.src[r.pos] }
fn (mut r TReader) advance() { r.pos++ }

fn (mut r TReader) skip_ws() {
	for !r.at_end() && (r.peek() == ` ` || r.peek() == `\t`) { r.advance() }
}

fn (mut r TReader) read_basic_str() string {
	r.advance() // skip '"'
	mut s := []u8{}
	for !r.at_end() {
		b := r.peek()
		if b == `"` { r.advance(); break }
		if b == `\\` {
			r.advance()
			if !r.at_end() {
				match r.peek() {
					`n`  { s << `\n`; r.advance() }
					`t`  { s << `\t`; r.advance() }
					`r`  { s << `\r`; r.advance() }
					`"`  { s << `"`; r.advance() }
					`\\` { s << `\\`; r.advance() }
					else { s << `\\`; s << r.peek(); r.advance() }
				}
			}
		} else {
			s << b
			r.advance()
		}
	}
	return s.bytestr()
}

fn (mut r TReader) read_literal_str() string {
	r.advance() // skip "'"
	mut s := []u8{}
	for !r.at_end() {
		b := r.peek()
		if b == `'` { r.advance(); break }
		s << b
		r.advance()
	}
	return s.bytestr()
}

fn (mut r TReader) read_multiline_basic_str() string {
	// already consumed '"""'
	if !r.at_end() && r.peek() == `\n` { r.advance() } // strip leading newline
	mut s := []u8{}
	for !r.at_end() {
		if r.pos + 2 < r.src.len && r.src[r.pos] == `"` && r.src[r.pos+1] == `"` && r.src[r.pos+2] == `"` {
			r.pos += 3; break
		}
		s << r.peek(); r.advance()
	}
	return s.bytestr()
}

fn (mut r TReader) read_multiline_literal_str() string {
	// already consumed "'''"
	if !r.at_end() && r.peek() == `\n` { r.advance() }
	mut s := []u8{}
	for !r.at_end() {
		if r.pos + 2 < r.src.len && r.src[r.pos] == `'` && r.src[r.pos+1] == `'` && r.src[r.pos+2] == `'` {
			r.pos += 3; break
		}
		s << r.peek(); r.advance()
	}
	return s.bytestr()
}

fn (mut r TReader) read_inline_array() JV {
	r.advance() // skip '['
	mut arr := []JV{}
	for !r.at_end() {
		r.skip_ws()
		if r.peek() == `\n` || r.peek() == `\r` { r.advance(); continue }
		if r.peek() == `#` { // skip comment
			for !r.at_end() && r.peek() != `\n` { r.advance() }
			continue
		}
		if r.peek() == `]` { r.advance(); break }
		if r.peek() == `,` { r.advance(); continue }
		val := r.read_value()
		arr << val
	}
	return JV(arr)
}

fn (mut r TReader) read_inline_table() JV {
	r.advance() // skip '{'
	mut obj := map[string]JV{}
	for !r.at_end() {
		r.skip_ws()
		if r.peek() == `}` { r.advance(); break }
		if r.peek() == `,` { r.advance(); continue }
		key := r.read_key()
		r.skip_ws()
		if r.peek() == `=` { r.advance() }
		val := r.read_value()
		obj[key] = val
	}
	return JV(obj)
}

fn (mut r TReader) read_key() string {
	r.skip_ws()
	if r.peek() == `"` { return r.read_basic_str() }
	if r.peek() == `'` { return r.read_literal_str() }
	mut s := []u8{}
	for !r.at_end() {
		b := r.peek()
		if b == `=` || b == `.` || b == `]` || b == `,` || b == ` ` || b == `\t` { break }
		s << b; r.advance()
	}
	return s.bytestr().trim_space()
}

fn (mut r TReader) read_value() JV {
	r.skip_ws()
	if r.at_end() { return JV(JVNull{}) }
	b := r.peek()
	// multiline strings
	if b == `"` && r.pos+2 < r.src.len && r.src[r.pos+1] == `"` && r.src[r.pos+2] == `"` {
		r.pos += 3
		return JV(r.read_multiline_basic_str())
	}
	if b == `'` && r.pos+2 < r.src.len && r.src[r.pos+1] == `'` && r.src[r.pos+2] == `'` {
		r.pos += 3
		return JV(r.read_multiline_literal_str())
	}
	if b == `"` { return JV(r.read_basic_str()) }
	if b == `'` { return JV(r.read_literal_str()) }
	if b == `[` { return r.read_inline_array() }
	if b == `{` { return r.read_inline_table() }
	// bare scalar
	mut s := []u8{}
	for !r.at_end() {
		c := r.peek()
		if c == `,` || c == `]` || c == `}` || c == `\n` || c == `\r` { break }
		if c == `#` { break }
		s << c; r.advance()
	}
	raw := s.bytestr().trim_space()
	if raw == 'true'  { return JV(true) }
	if raw == 'false' { return JV(false) }
	if raw == '' || raw == 'null' { return JV(JVNull{}) }
	if iv := raw.parse_int(10, 64) { return JV(iv) }
	if raw.contains('.') || raw.to_lower().contains('e') {
		fv := strconv.atof64(raw) or { return JV(raw) }
		return JV(fv)
	}
	return JV(raw)
}

// Navigate path in nested map, creating missing nodes
fn toml_navigate(root map[string]JV, path []string) map[string]JV {
	if path.len == 0 { return root }
	key := path[0]
	rest := path[1..]
	existing := root[key] or { JV(map[string]JV{}) }
	child := if existing is map[string]JV { existing as map[string]JV } else { map[string]JV{} }
	if rest.len == 0 { return child }
	return toml_navigate(child, rest)
}

// Set a value at path in a nested map (deep copy/update)
fn toml_set_path(root map[string]JV, path []string, key string, val JV) map[string]JV {
	mut result := root.clone()
	if path.len == 0 {
		result[key] = val
		return result
	}
	head := path[0]
	rest := path[1..]
	existing := result[head] or { JV(map[string]JV{}) }
	child := if existing is map[string]JV { existing as map[string]JV } else { map[string]JV{} }
	updated := toml_set_path(child, rest, key, val)
	result[head] = JV(updated)
	return result
}

// Append a table to an array-of-tables at path
fn toml_append_aot(root map[string]JV, path []string, table map[string]JV) map[string]JV {
	mut result := root.clone()
	if path.len == 0 { return result }
	if path.len == 1 {
		key := path[0]
		existing := result[key] or { JV([]JV{}) }
		mut arr := if existing is []JV { existing as []JV } else { []JV{} }
		arr << JV(table)
		result[key] = JV(arr)
		return result
	}
	head := path[0]
	rest := path[1..]
	existing := result[head] or { JV(map[string]JV{}) }
	child := if existing is map[string]JV {
		existing as map[string]JV
	} else if existing is []JV {
		// last element of array of tables
		arr := existing as []JV
		if arr.len > 0 {
			last := arr[arr.len-1]
			if last is map[string]JV { last as map[string]JV } else { map[string]JV{} }
		} else { map[string]JV{} }
	} else { map[string]JV{} }
	updated := toml_append_aot(child, rest, table)
	// If existing was an array of tables, update its last element
	if existing is []JV {
		mut arr := existing as []JV
		if arr.len > 0 {
			arr[arr.len-1] = JV(updated)
		} else {
			arr << JV(updated)
		}
		result[head] = JV(arr)
	} else {
		result[head] = JV(updated)
	}
	return result
}

// Preprocess TOML: join multi-line array values into single logical lines
fn toml_preprocess(src string) string {
	lines := src.split_into_lines()
	mut result := []string{}
	mut i := 0
	for i < lines.len {
		line := lines[i]
		trimmed := line.trim_space()
		// Skip comments and blank lines
		if trimmed.len == 0 || trimmed.starts_with('#') {
			result << line
			i++
			continue
		}
		// Check if this is a key=value with unclosed [ or {
		if ei := trimmed.index('=') {
			val_part := trimmed[ei+1..].trim_space()
			if val_part.starts_with('[') || val_part.starts_with('{') {
				// count brackets
				mut depth := 0
				mut combined := line
				for ch in val_part.bytes() {
					if ch == `[` || ch == `{` { depth++ }
					else if ch == `]` || ch == `}` { depth-- }
				}
				// accumulate continuation lines
				j := i + 1
				mut ji := j
				for ji < lines.len && depth > 0 {
					cont := lines[ji]
					combined += ' ' + cont.trim_space()
					for ch in cont.bytes() {
						if ch == `[` || ch == `{` { depth++ }
						else if ch == `]` || ch == `}` { depth-- }
					}
					ji++
				}
				result << combined
				i = ji
				continue
			}
		}
		result << line
		i++
	}
	return result.join('\n')
}

pub fn parse_toml(src string) !Document {
	preprocessed := toml_preprocess(src)
	lines := preprocessed.split_into_lines()
	mut root := map[string]JV{}
	mut current_path := []string{}
	mut aot_path := []string{} // array of tables path

	for raw_line in lines {
		line := raw_line.trim_space()
		if line.len == 0 || line.starts_with('#') { continue }

		if line.starts_with('[[') {
			// array-of-tables header
			end := line.index(']]') or { continue }
			header := line[2..end].trim_space()
			current_path = header.split('.').map(it.trim_space())
			aot_path = current_path.clone()
			root = toml_append_aot(root, current_path, map[string]JV{})
		} else if line.starts_with('[') {
			// table header (not a value line)
			// make sure this isn't a value line (has no = before the [)
			if ei := line.index('=') {
				// has = sign — it's a key=value line, not a header
				key_raw := line[..ei].trim_space()
				val_raw := line[ei+1..].trim_space()
				mut r := TReader{ src: val_raw, pos: 0 }
				val := r.read_value()
				key := key_raw.trim('"\'')
				if current_path.len == 0 {
					root[key] = val
				} else if aot_path.len > 0 {
					root = toml_set_in_aot(root, aot_path, key, val)
				} else {
					root = toml_set_path(root, current_path, key, val)
				}
			} else {
				end := line.index(']') or { continue }
				header := line[1..end].trim_space()
				current_path = header.split('.').map(it.trim_space())
				aot_path = []string{}
			}
		} else {
			// key = value
			ei := line.index('=') or { continue }
			key_raw := line[..ei].trim_space()
			val_raw := line[ei+1..].trim_space()

			mut r := TReader{ src: val_raw, pos: 0 }
			val := r.read_value()
			key := key_raw.trim('"\'')

			if current_path.len == 0 {
				root[key] = val
			} else if aot_path.len > 0 {
				// insert into last element of aot
				root = toml_set_in_aot(root, aot_path, key, val)
			} else {
				root = toml_set_path(root, current_path, key, val)
			}
		}
	}

	return jv_to_cx_doc(JV(root))
}

// Set key=val inside the last element of the array-of-tables at path
fn toml_set_in_aot(root map[string]JV, aot_path []string, key string, val JV) map[string]JV {
	mut result := root.clone()
	if aot_path.len == 0 { return result }
	if aot_path.len == 1 {
		akey := aot_path[0]
		existing := result[akey] or { JV([]JV{}) }
		if existing is []JV {
			mut arr := existing as []JV
			if arr.len > 0 {
				last := arr[arr.len-1]
				mut last_obj := if last is map[string]JV { last as map[string]JV } else { map[string]JV{} }
				last_obj[key] = val
				arr[arr.len-1] = JV(last_obj)
				result[akey] = JV(arr)
			}
		}
		return result
	}
	head := aot_path[0]
	rest := aot_path[1..]
	existing := result[head] or { JV(map[string]JV{}) }
	if existing is []JV {
		mut arr := existing as []JV
		if arr.len > 0 {
			last := arr[arr.len-1]
			mut child := if last is map[string]JV { last as map[string]JV } else { map[string]JV{} }
			child = toml_set_in_aot(child, rest, key, val)
			arr[arr.len-1] = JV(child)
			result[head] = JV(arr)
		}
	} else if existing is map[string]JV {
		child := existing as map[string]JV
		updated := toml_set_in_aot(child, rest, key, val)
		result[head] = JV(updated)
	}
	return result
}

pub fn parse_toml_cx(src string) !ParseResult {
	doc := parse_toml(src)!
	return ParseResult{ is_multi: false, single: doc }
}
