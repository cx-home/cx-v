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

// yaml_split_key splits a trimmed line into a mapping key token and the
// remainder after the `:` separator. Quote-aware: a leading single/double
// quote is scanned to its closing quote first, so a quoted scalar containing
// `: ` (e.g. `'a: b'`) is NOT mistaken for a mapping entry, and a quoted key
// (`"items": 1` — the shape our own CX→YAML emitter produces) splits at the
// real separator. ok=false means the line is not a `key: value` / `key:`
// mapping entry.
fn yaml_split_key(t string) (string, string, bool) {
	if t.len == 0 {
		return '', '', false
	}
	if t[0] == `'` || t[0] == `"` {
		q := t[0]
		mut i := 1
		for i < t.len {
			if q == `"` && t[i] == `\\` {
				i += 2
				continue
			}
			if t[i] == q {
				if q == `'` && i + 1 < t.len && t[i + 1] == `'` {
					i += 2 // '' — escaped single quote inside a single-quoted key
					continue
				}
				break
			}
			i++
		}
		if i >= t.len {
			return '', '', false // unterminated quote — treat as scalar
		}
		rest := t[i + 1..]
		if rest == ':' {
			return t[..i + 1], '', true
		}
		if rest.starts_with(': ') {
			return t[..i + 1], rest[2..].trim_space(), true
		}
		return '', '', false
	}
	if idx := t.index(': ') {
		return t[..idx].trim_space(), t[idx + 2..].trim_space(), true
	}
	if t.ends_with(':') {
		return t[..t.len - 1].trim_space(), '', true
	}
	return '', '', false
}

// yaml_key_text resolves a key token to its map-key text: quoted keys
// unquote (with escape processing), bare keys stay verbatim.
fn yaml_key_text(tok string) string {
	if tok.len >= 2 && (tok[0] == `'` || tok[0] == `"`) {
		v := yaml_parse_scalar_str(tok)
		if v is string {
			return v
		}
	}
	return tok
}

fn yaml_parse_scalar_str(s string) JV {
	t := s.trim_space()
	if t == 'null' || t == '~' || t == '' { return JV(JVNull{}) }
	// Empty flow containers: the CX → YAML emitter's own output for an empty
	// Array / Map, so import must close the round trip (#412).
	if t == '[]' { return JV([]JV{}) }
	if t == '{}' { return JV(map[string]JV{}) }
	// Non-empty flow collections (#440): `[1, 2]` / `{k: v}` parse to a real
	// Array / Map (nested, quote-aware) — before this they imported as literal
	// strings (silent mistyping). A malformed flow body falls back to the
	// plain-scalar read below, matching the line parser's lenient posture.
	if t[0] == `[` || t[0] == `{` {
		if v := yaml_parse_flow(t) {
			return v
		}
	}
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
	// tagged scalar — `!!cx:T payload` (conversions.md §0.2 native-tag
	// protocol, #444) and `!!binary payload` (bytes row, #458)
	if t.starts_with('!!') {
		return yaml_parse_tagged(t)
	}
	// try numeric
	if iv := t.parse_int(10, 64) { return JV(iv) }
	// over-i64 digit runs auto-promote to bigint (lexicon [L20]/D-H — the
	// same promotion the CX parser applies); reached only when parse_int
	// overflowed above
	if is_v34_decimal_int(t) {
		return JV(JVTyped{ typ: 'bigint', text: t.trim_string_left('+') })
	}
	// float — requires a digit (lexicon [L20b]: a digit-less `e`/`.` token is
	// text, and atof64 leniently returns 0.0 for those); on a failed parse
	// FALL THROUGH so datetimes with fractional seconds reach the date checks
	if (t.contains('.') || t.contains('e') || t.contains('E')) && has_ascii_digit(t) {
		if fv := strconv.atof64(t) {
			return JV(fv)
		}
	}
	// YAML-native date / datetime (conversions.md §5.1: "YAML date /
	// datetime → ScalarNode with date / datetime type")
	if is_datetime(t) { return JV(JVTyped{ typ: 'datetime', text: t }) }
	if is_date(t)     { return JV(JVTyped{ typ: 'date', text: t }) }
	// temporal spans (lexicon [L25]/[L26]) — §5.1 auto-typing; the CX→YAML
	// emitter writes them as plain scalars in default mode
	if tk := temporal_span_kind(t) {
		return JV(JVTyped{ typ: scalar_type_name_public(tk), text: t })
	}
	return JV(t)
}

// yaml_parse_tagged reads a `!!TAG payload` scalar. Recognized tags:
//   !!cx:atom / !!cx:decimal / !!cx:bigint / !!cx:date / !!cx:datetime /
//   !!cx:duration / !!cx:period / !!cx:<sized-numeric>  (conversions.md §0.2)
//   !!binary                                            (bytes row)
// A quoted payload unquotes; the tag names the type, so the payload text is
// carried verbatim (no re-auto-typing). Unrecognized tags keep the WHOLE
// scalar text verbatim — "readers that don't know the tag preserve it".
fn yaml_parse_tagged(t string) JV {
	mut i := 2
	for i < t.len && t[i] != ` ` && t[i] != `\t` { i++ }
	tag := t[2..i]
	payload_raw := if i < t.len { t[i..].trim_space() } else { '' }
	// unquote a quoted payload (escape-processing via the scalar reader)
	mut payload := payload_raw
	if payload_raw.len >= 2 && (payload_raw[0] == `"` || payload_raw[0] == `'`) {
		pv := yaml_parse_scalar_str(payload_raw)
		if pv is string {
			payload = pv
		}
	}
	if tag == 'binary' {
		if hex := base64_to_bytes_hex(payload) {
			return JV(JVTyped{ typ: 'bytes', text: hex })
		}
		return JV(payload) // undecodable — keep the payload as a string
	}
	if tag.starts_with('cx:') {
		tname := tag[3..]
		match tname {
			'atom' {
				return JV(JVTyped{ typ: 'atom', text: payload.trim_string_left(':') })
			}
			'decimal', 'bigint', 'date', 'datetime', 'duration', 'period' {
				return JV(JVTyped{ typ: tname, text: payload })
			}
			else {
				if _ := scalar_type_from_name(tname) {
					return JV(JVTyped{ typ: tname, text: payload })
				}
			}
		}
	}
	return JV(t)
}

// ── Flow-style collections (#440) ─────────────────────────────────────────────
// A one-line recursive-descent reader for YAML flow syntax: `[a, b]` sequences
// and `{k: v}` mappings, nested to any depth, with single-/double-quoted
// members (commas, colons and brackets inside quotes are content, not
// structure). Plain flow scalars route through yaml_parse_scalar_str so typing
// matches the block parser. Returns none when the text is not a single
// well-formed flow collection (unterminated, trailing garbage) — the caller
// then treats the text as a plain scalar.

struct YFlowReader {
	s string
mut:
	pos int
}

fn yaml_parse_flow(t string) ?JV {
	mut r := YFlowReader{ s: t, pos: 0 }
	v := r.flow_value()?
	r.skip_flow_ws()
	if r.pos < r.s.len {
		return none // trailing garbage after the closing bracket — not pure flow
	}
	return v
}

fn (mut r YFlowReader) skip_flow_ws() {
	for r.pos < r.s.len && (r.s[r.pos] == ` ` || r.s[r.pos] == `\t`) { r.pos++ }
}

fn (r YFlowReader) peek() u8 {
	if r.pos < r.s.len { return r.s[r.pos] }
	return 0
}

fn (mut r YFlowReader) flow_value() ?JV {
	r.skip_flow_ws()
	match r.peek() {
		`[` { return r.flow_seq() }
		`{` { return r.flow_map() }
		else { return r.flow_scalar() }
	}
}

// flow_scalar scans a plain or quoted scalar member up to the next top-level
// `,` / `]` / `}` and types it via yaml_parse_scalar_str (quotes included in
// the token — the scalar reader unquotes).
fn (mut r YFlowReader) flow_scalar() ?JV {
	start := r.pos
	for r.pos < r.s.len {
		c := r.s[r.pos]
		if c == `,` || c == `]` || c == `}` {
			break
		}
		if c == `'` || c == `"` {
			r.skip_quoted()?
			continue
		}
		r.pos++
	}
	tok := r.s[start..r.pos].trim_space()
	if tok.len == 0 {
		return JV(JVNull{})
	}
	return yaml_parse_scalar_str(tok)
}

// skip_quoted advances past a quoted span starting at r.pos. Double quotes
// honor backslash escapes; single quotes honor `''` doubling. Errors (none)
// on an unterminated quote.
fn (mut r YFlowReader) skip_quoted() ? {
	q := r.s[r.pos]
	r.pos++
	for r.pos < r.s.len {
		c := r.s[r.pos]
		if q == `"` && c == `\\` {
			r.pos += 2
			continue
		}
		if c == q {
			if q == `'` && r.pos + 1 < r.s.len && r.s[r.pos + 1] == `'` {
				r.pos += 2 // '' — escaped single quote
				continue
			}
			r.pos++
			return
		}
		r.pos++
	}
	return none
}

fn (mut r YFlowReader) flow_seq() ?JV {
	r.pos++ // '['
	mut arr := []JV{}
	r.skip_flow_ws()
	if r.peek() == `]` {
		r.pos++
		return JV(arr)
	}
	for {
		arr << r.flow_value()?
		r.skip_flow_ws()
		match r.peek() {
			`,` {
				r.pos++
				continue
			}
			`]` {
				r.pos++
				return JV(arr)
			}
			else {
				return none // unterminated / malformed
			}
		}
	}
	return none
}

fn (mut r YFlowReader) flow_map() ?JV {
	r.pos++ // '{'
	mut obj := map[string]JV{}
	r.skip_flow_ws()
	if r.peek() == `}` {
		r.pos++
		return JV(obj)
	}
	for {
		r.skip_flow_ws()
		// key token: up to the `:` separator (quote-aware)
		key_start := r.pos
		for r.pos < r.s.len {
			c := r.s[r.pos]
			if c == `:` || c == `,` || c == `}` {
				break
			}
			if c == `'` || c == `"` {
				r.skip_quoted()?
				continue
			}
			r.pos++
		}
		key_tok := r.s[key_start..r.pos].trim_space()
		mut val := JV(JVNull{})
		if r.peek() == `:` {
			r.pos++
			val = r.flow_value()?
		}
		obj[yaml_key_text(key_tok)] = val
		r.skip_flow_ws()
		match r.peek() {
			`,` {
				r.pos++
				continue
			}
			`}` {
				r.pos++
				return JV(obj)
			}
			else {
				return none
			}
		}
	}
	return none
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
	// A line that IS a flow collection (`{k: v}` / `[a, b]`) is a value, not a
	// block mapping — without this, yaml_split_key would split `{k: v}` at the
	// `: ` and misread `{k` as a mapping key (#440).
	if first_trimmed[0] == `[` || first_trimmed[0] == `{` {
		if v := yaml_parse_flow(first_trimmed) {
			r.pos++
			return v
		}
	}
	// detect mapping (quote-aware — a quoted scalar containing ': ' is not a key)
	_, _, is_mapping := yaml_split_key(first_trimmed)
	if is_mapping {
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
		// parse key: value (quote-aware split; quoted keys unquote)
		key_tok, after, is_entry := yaml_split_key(trimmed)
		if !is_entry {
			r.pos++
			continue
		}
		key := yaml_key_text(key_tok)
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
		if trimmed == '-' {
			// bare dash: the item body (if any) sits on the following
			// deeper-indented lines; parse_block returns null (without
			// consuming) when the next content line is not deeper.
			r.pos++
			arr << r.parse_block(indent + 1)
			continue
		}
		// Inline content after the dash. Re-scope the item as its own block by
		// blanking the `- ` prefix in place, then let parse_block dispatch:
		// a compact mapping (`- k: v`, with continuation keys on the following
		// lines at the content column), a nested sequence (`- - x`), or a
		// plain scalar. Previously the inline content was always consumed as a
		// one-line scalar, which collapsed a block sequence of mappings to
		// `['k: v']` and leaked the continuation keys into the enclosing
		// mapping (#412).
		mut content_col := indent + 1
		for content_col < line.len && (line[content_col] == ` ` || line[content_col] == `\t`) {
			content_col++
		}
		r.lines[r.pos] = ' '.repeat(content_col) + line[content_col..]
		arr << r.parse_block(indent + 1)
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
	// #4: import losslessly to the native value model (Map/Array/scalars),
	// matching the JSON codec — not synthesized elements. No XML namespaces in
	// YAML, so resolve_namespaces is not run on the value-model doc.
	//
	// #475: then reconstruct the reserved lossless-structure shapes
	// (conversions.md §5.1) — `$tag` envelopes, `$doc`, the `cx:seq` /
	// `cx:raw` / `cx:entity` / typed `cx:T` carriers, the `cx:key-type`
	// sidecar and `cx:k:` key escapes — unconditionally, the same reserved-
	// namespace contract as the JSON importer.
	root := apply_lossless_structure(jv_to_value_node(val))
	return Document{
		elements: lossless_root_to_elements(root)
	}
}

pub fn parse_yaml_cx(src string) !ParseResult {
	doc := parse_yaml(src)!
	return ParseResult{ is_multi: false, single: doc }
}
