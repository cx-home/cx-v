module cx

import strconv

// ── YAML → CX / AST Parser ───────────────────────────────────────────────────
// Minimal YAML parser using a line-by-line approach.

struct YReader {
mut:
	lines []string
	pos   int
}

fn yaml_indent(line string) int {
	mut n := 0
	for n < line.len && (line[n] == ` ` || line[n] == `\t`) { n++ }
	return n
}

fn yaml_is_blank(line string) bool {
	t := line.trim_space()
	return t.len == 0 || t.starts_with('#')
}

fn yaml_parse_scalar_str(s string) JV {
	t := s.trim_space()
	if t == 'null' || t == '~' || t == '' { return JV(JVNull{}) }
	if t == 'true' || t == 'yes' || t == 'on'  { return JV(true) }
	if t == 'false' || t == 'no' || t == 'off' { return JV(false) }
	// double-quoted
	if t.len >= 2 && t[0] == `"` && t[t.len-1] == `"` {
		inner := t[1..t.len-1]
		mut result := []u8{}
		mut i := 0
		for i < inner.len {
			if inner[i] == `\\` && i+1 < inner.len {
				i++
				match inner[i] {
					`n`  { result << `\n`; i++ }
					`t`  { result << `\t`; i++ }
					`r`  { result << `\r`; i++ }
					`"`  { result << `"`; i++ }
					`\\` { result << `\\`; i++ }
					else { result << `\\`; result << inner[i]; i++ }
				}
			} else {
				result << inner[i]
				i++
			}
		}
		return JV(result.bytestr())
	}
	// single-quoted
	if t.len >= 2 && t[0] == `'` && t[t.len-1] == `'` {
		inner_s := t[1..t.len-1]
		return JV(inner_s)
	}
	// try numeric
	if iv := t.parse_int(10, 64) { return JV(iv) }
	if t.contains('.') || t.contains('e') || t.contains('E') {
		fv := strconv.atof64(t) or { return JV(t) }
		return JV(fv)
	}
	return JV(t)
}

fn (mut r YReader) parse_block(min_indent int) JV {
	// skip blanks
	for r.pos < r.lines.len && yaml_is_blank(r.lines[r.pos]) { r.pos++ }
	if r.pos >= r.lines.len { return JV(JVNull{}) }

	first_line := r.lines[r.pos]
	first_indent := yaml_indent(first_line)
	if first_indent < min_indent { return JV(JVNull{}) }

	first_trimmed := first_line.trim_space()
	// detect sequence
	if first_trimmed.starts_with('- ') || first_trimmed == '-' {
		return r.parse_seq(first_indent)
	}
	// detect mapping
	if first_trimmed.contains(': ') || first_trimmed.ends_with(':') {
		return r.parse_mapping(first_indent)
	}
	// scalar
	r.pos++
	return yaml_parse_scalar_str(first_trimmed)
}

fn (mut r YReader) parse_mapping(base_indent int) JV {
	mut obj := map[string]JV{}
	for r.pos < r.lines.len {
		// skip blanks
		for r.pos < r.lines.len && yaml_is_blank(r.lines[r.pos]) { r.pos++ }
		if r.pos >= r.lines.len { break }
		line := r.lines[r.pos]
		indent := yaml_indent(line)
		if indent < base_indent { break }
		trimmed := line.trim_space()
		if trimmed.starts_with('- ') || trimmed == '-' { break } // switch to seq
		// parse key: value
		colon_idx := trimmed.index(': ') or {
			// might be "key:" with nothing after
			if trimmed.ends_with(':') {
				ci := trimmed.len - 1
				ci
			} else {
				r.pos++
				continue
			}
		}
		key := trimmed[..colon_idx].trim_space()
		after := trimmed[colon_idx+1..].trim_space()
		r.pos++
		val := if after.len == 0 || after == '' {
			// value on next lines
			for r.pos < r.lines.len && yaml_is_blank(r.lines[r.pos]) { r.pos++ }
			if r.pos < r.lines.len {
				next_indent := yaml_indent(r.lines[r.pos])
				next_trimmed := r.lines[r.pos].trim_space()
				// YAML: sequence items can be at the same indent as the key
				if next_indent >= base_indent && (next_trimmed.starts_with('- ') || next_trimmed == '-') {
					r.parse_seq(next_indent)
				} else if next_indent > base_indent {
					r.parse_block(next_indent)
				} else {
					JV(JVNull{})
				}
			} else {
				JV(JVNull{})
			}
		} else {
			yaml_parse_scalar_str(after)
		}
		if key in obj {
			existing := obj[key] or { JV(JVNull{}) }
			if existing is []JV {
				mut arr := existing as []JV
				arr << val
				obj[key] = JV(arr)
			} else {
				obj[key] = JV([existing, val])
			}
		} else {
			obj[key] = val
		}
	}
	return JV(obj)
}

fn (mut r YReader) parse_seq(base_indent int) JV {
	mut arr := []JV{}
	for r.pos < r.lines.len {
		for r.pos < r.lines.len && yaml_is_blank(r.lines[r.pos]) { r.pos++ }
		if r.pos >= r.lines.len { break }
		line := r.lines[r.pos]
		indent := yaml_indent(line)
		if indent < base_indent { break }
		trimmed := line.trim_space()
		if !trimmed.starts_with('- ') && trimmed != '-' { break }
		item_str := if trimmed.starts_with('- ') { trimmed[2..].trim_space() } else { '' }
		r.pos++
		item := if item_str.len == 0 {
			// nested block
			for r.pos < r.lines.len && yaml_is_blank(r.lines[r.pos]) { r.pos++ }
			if r.pos < r.lines.len {
				next_indent := yaml_indent(r.lines[r.pos])
				if next_indent > base_indent {
					r.parse_block(next_indent)
				} else {
					JV(JVNull{})
				}
			} else {
				JV(JVNull{})
			}
		} else {
			yaml_parse_scalar_str(item_str)
		}
		arr << item
	}
	return JV(arr)
}

pub fn parse_yaml(src string) !Document {
	lines := src.split_into_lines()
	mut r := YReader{ lines: lines, pos: 0 }
	// skip leading doc markers and blanks
	for r.pos < r.lines.len {
		t := r.lines[r.pos].trim_space()
		if t.starts_with('---') || t.starts_with('...') || yaml_is_blank(r.lines[r.pos]) {
			r.pos++
		} else {
			break
		}
	}
	if r.pos >= r.lines.len { return Document{} }
	val := r.parse_block(0)
	return jv_to_cx_doc(val)
}

pub fn parse_yaml_cx(src string) !ParseResult {
	doc := parse_yaml(src)!
	return ParseResult{ is_multi: false, single: doc }
}
