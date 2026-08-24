module cx

import strconv

// ── TOML → CX / AST Parser ───────────────────────────────────────────────────
// Minimal TOML parser. Uses a reader struct to track position.
//
// STRICT READER (conversions.md §6.1, RULED: 738-2a). Malformed input is
// REFUSED with cx-err:CXER0100 — never folded into a best-effort tree.
// Before this the reader could not fail AT ALL: every reader returned
// unconditionally and every top-level branch ended in `or { continue }`,
// so `qty = [1, 2` plus a bare `bad` line silently became
// `{qty: [1, '2 bad']}` at rc=0 (#738). A Ring-0 data-profile surface
// whose pitch is safety on untrusted input does not guess; the XML /
// JSON / YAML lanes already fail loud through this same `!Document` seam.

// toml_parse_error is the ONE refusal shape for this reader, so every
// class carries the same code and reads the same way in a diagnostic.
fn toml_parse_error(what string) IError {
	return error('cx-err:CXER0100 PARSE_ERROR: TOML — ${what}')
}

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

fn (mut r TReader) read_basic_str() !string {
	r.advance() // skip '"'
	mut s := []u8{}
	mut closed := false
	for !r.at_end() {
		b := r.peek()
		if b == `"` { r.advance(); closed = true; break }
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
	if !closed {
		return toml_parse_error('unterminated basic string (no closing double quote)')
	}
	return s.bytestr()
}

fn (mut r TReader) read_literal_str() !string {
	r.advance() // skip "'"
	mut s := []u8{}
	mut closed := false
	for !r.at_end() {
		b := r.peek()
		if b == `'` { r.advance(); closed = true; break }
		s << b
		r.advance()
	}
	if !closed {
		return toml_parse_error('unterminated literal string (no closing quote)')
	}
	return s.bytestr()
}

fn (mut r TReader) read_multiline_basic_str() !string {
	// already consumed '"""'
	if !r.at_end() && r.peek() == `\n` { r.advance() } // strip leading newline
	mut s := []u8{}
	mut closed := false
	for !r.at_end() {
		if r.pos + 2 < r.src.len && r.src[r.pos] == `"` && r.src[r.pos+1] == `"` && r.src[r.pos+2] == `"` {
			r.pos += 3; closed = true; break
		}
		s << r.peek(); r.advance()
	}
	if !closed {
		return toml_parse_error('unterminated multi-line basic string')
	}
	return s.bytestr()
}

fn (mut r TReader) read_multiline_literal_str() !string {
	// already consumed "'''"
	if !r.at_end() && r.peek() == `\n` { r.advance() }
	mut s := []u8{}
	mut closed := false
	for !r.at_end() {
		if r.pos + 2 < r.src.len && r.src[r.pos] == `'` && r.src[r.pos+1] == `'` && r.src[r.pos+2] == `'` {
			r.pos += 3; closed = true; break
		}
		s << r.peek(); r.advance()
	}
	if !closed {
		return toml_parse_error('unterminated multi-line literal string')
	}
	return s.bytestr()
}

fn (mut r TReader) read_inline_array() !JV {
	r.advance() // skip '['
	mut arr := []JV{}
	mut closed := false
	for !r.at_end() {
		r.skip_ws()
		if r.peek() == `\n` || r.peek() == `\r` { r.advance(); continue }
		if r.peek() == `#` { // skip comment
			for !r.at_end() && r.peek() != `\n` { r.advance() }
			continue
		}
		if r.peek() == `]` { r.advance(); closed = true; break }
		if r.peek() == `,` { r.advance(); continue }
		val := r.read_value()!
		arr << val
	}
	if !closed {
		return toml_parse_error('unterminated inline array (no closing `]`)')
	}
	return JV(arr)
}

fn (mut r TReader) read_inline_table() !JV {
	r.advance() // skip '{'
	mut obj := map[string]JV{}
	mut closed := false
	for !r.at_end() {
		r.skip_ws()
		if r.peek() == `}` { r.advance(); closed = true; break }
		if r.peek() == `,` { r.advance(); continue }
		key := r.read_key()!
		if key.len == 0 {
			return toml_parse_error('inline table entry has no key')
		}
		r.skip_ws()
		if r.peek() != `=` {
			return toml_parse_error('inline table key `${key}` is not followed by `=`')
		}
		r.advance()
		val := r.read_value()!
		if key in obj {
			return toml_parse_error('duplicate key `${key}` in inline table')
		}
		obj[key] = val
	}
	if !closed {
		return toml_parse_error('unterminated inline table (no closing `}`)')
	}
	return JV(obj)
}

fn (mut r TReader) read_key() !string {
	r.skip_ws()
	if r.peek() == `"` { return r.read_basic_str()! }
	if r.peek() == `'` { return r.read_literal_str()! }
	mut s := []u8{}
	for !r.at_end() {
		b := r.peek()
		if b == `=` || b == `.` || b == `]` || b == `,` || b == ` ` || b == `\t` { break }
		s << b; r.advance()
	}
	return s.bytestr().trim_space()
}

fn (mut r TReader) read_value() !JV {
	r.skip_ws()
	if r.at_end() { return JV(JVNull{}) }
	b := r.peek()
	// multiline strings
	if b == `"` && r.pos+2 < r.src.len && r.src[r.pos+1] == `"` && r.src[r.pos+2] == `"` {
		r.pos += 3
		return JV(r.read_multiline_basic_str()!)
	}
	if b == `'` && r.pos+2 < r.src.len && r.src[r.pos+1] == `'` && r.src[r.pos+2] == `'` {
		r.pos += 3
		return JV(r.read_multiline_literal_str()!)
	}
	if b == `"` { return JV(r.read_basic_str()!) }
	if b == `'` { return JV(r.read_literal_str()!) }
	if b == `[` { return r.read_inline_array()! }
	if b == `{` { return r.read_inline_table()! }
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
	// TOML date / datetime are NATIVE value kinds, and conversions.md §6.1's
	// mapping table is normative on where they land: "TOML datetime →
	// ScalarNode with `datetime` type", "TOML date → ScalarNode with `date`
	// type" (and §0.2's "dates stay native"). They arrived here as bare
	// scalars and fell through to the string arm, so `2026-08-01` imported
	// as the STRING '2026-08-01' while the YAML lane — same target model,
	// same carrier — imported it as a date (#738).
	//
	// The carrier is JVTyped, which exists for exactly this ("format-native
	// typing (YAML dates, …)"), and the classifiers are the SAME is_datetime
	// / is_date the YAML lane and the CX data scanner use — one temporal
	// grammar ([L24]), so a value that is a date in one reading cannot be a
	// string in another. Datetime is tested FIRST: a datetime token is
	// longer than 10 bytes and is_date only admits exactly 10, but the order
	// makes the precedence explicit rather than incidental.
	if is_datetime(raw) { return JV(JVTyped{ typ: 'datetime', text: raw }) }
	if is_date(raw)     { return JV(JVTyped{ typ: 'date',     text: raw }) }
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

	// seen_keys refuses a duplicate key WITHIN one table. The scope key is
	// the table path plus, for an array-of-tables, that table's ORDINAL —
	// repeating a key across two `[[items]]` entries is legal TOML and must
	// not be confused with redefining one inside a single entry.
	mut seen_keys := map[string]bool{}
	mut aot_ordinal := map[string]int{}
	for raw_line in lines {
		line := raw_line.trim_space()
		if line.len == 0 || line.starts_with('#') { continue }

		if line.starts_with('[[') {
			// array-of-tables header
			end := line.index(']]') or {
				return toml_parse_error('unterminated array-of-tables header `${line}` (no closing `]]`)')
			}
			header := line[2..end].trim_space()
			if header.len == 0 {
				return toml_parse_error('empty array-of-tables header `${line}`')
			}
			current_path = header.split('.').map(it.trim_space())
			aot_path = current_path.clone()
			aot_ordinal[header] = (aot_ordinal[header] or { 0 }) + 1
			root = toml_append_aot(root, current_path, map[string]JV{})
		} else if line.starts_with('[') {
			// table header (not a value line)
			// make sure this isn't a value line (has no = before the [)
			if ei := line.index('=') {
				// has = sign — it's a key=value line, not a header
				key_raw := line[..ei].trim_space()
				val_raw := line[ei+1..].trim_space()
				mut r := TReader{ src: val_raw, pos: 0 }
				val := r.read_value()!
				key := key_raw.trim('"\'')
				toml_claim_key(mut seen_keys, current_path, aot_path, aot_ordinal, key)!
				if current_path.len == 0 {
					root[key] = val
				} else if aot_path.len > 0 {
					root = toml_set_in_aot(root, aot_path, key, val)
				} else {
					root = toml_set_path(root, current_path, key, val)
				}
			} else {
				end := line.index(']') or {
					return toml_parse_error('unterminated table header `${line}` (no closing `]`)')
				}
				header := line[1..end].trim_space()
				if header.len == 0 {
					return toml_parse_error('empty table header `${line}`')
				}
				current_path = header.split('.').map(it.trim_space())
				aot_path = []string{}
			}
		} else {
			// key = value
			ei := line.index('=') or {
				// Neither a comment, nor a header, nor a pair — the class the
				// old reader dropped on the floor, and the one that let the
				// #738 repro's stray `bad` token vanish into a value.
				return toml_parse_error('line is neither a comment, a table header, nor a `key = value` pair: `${line}`')
			}
			key_raw := line[..ei].trim_space()
			val_raw := line[ei+1..].trim_space()

			mut r := TReader{ src: val_raw, pos: 0 }
			val := r.read_value()!
			key := key_raw.trim('"\'')
			if key.len == 0 {
				return toml_parse_error('key-value pair has no key: `${line}`')
			}
			toml_claim_key(mut seen_keys, current_path, aot_path, aot_ordinal, key)!

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

	// #5: import losslessly to the native value model (Map/Array/scalars),
	// matching JSON/YAML — TOML tables → nested maps, arrays-of-tables →
	// arrays of maps — not synthesized elements. No XML namespaces in TOML.
	return jv_to_value_doc(JV(root))
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

// toml_claim_key records a key in its table's scope and refuses a second
// claim. The scope is the table path — plus the array-of-tables ORDINAL
// when one is active, so `sku` in two successive `[[items]]` entries are
// two different keys while `sku` twice inside ONE entry is a duplicate.
// Silently taking the last value is the failure this exists to prevent:
// a config whose two `a =` lines disagree has no single correct reading.
fn toml_claim_key(mut seen map[string]bool, current_path []string, aot_path []string,
                  aot_ordinal map[string]int, key string) ! {
	mut scope := current_path.join('.')
	if aot_path.len > 0 {
		header := aot_path.join('.')
		scope = '${header}#${aot_ordinal[header] or { 0 }}'
	}
	k := '${scope}\x00${key}'
	if k in seen {
		where := if scope.len == 0 { 'the document root' } else { 'table `${scope}`' }
		return toml_parse_error('duplicate key `${key}` in ${where}')
	}
	seen[k] = true
}
