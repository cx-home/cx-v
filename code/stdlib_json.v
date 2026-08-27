module code

import cx
import strings
import math

// stdlib_json.v — native primitives backing the `cx-stdlib/json` module
// (spec/std-lib/json.md). JSON (RFC 8259) parse → CXDM values and emit
// CXDM values → JSON. A focused recursive-descent parser + emitter; not
// expressible as pure CX `[?def]` bodies, so the bundle bodies
// (stdlib_src_json) forward to the primitives dispatched here. See
// stdlib_dispatch.v for the registration line.
//
// ── value model (spec §2) ───────────────────────────────────────────
//   JSON null/bool/int/float/string → ScalarNode of the matching kind.
//   JSON array  → Element{ name: '__cx_arr__', items }   (renders [a, b]).
//   JSON object → Element{ name: '__cx_map__', items }    where each entry
//                 is Element{ name: key, items: [value] }  (renders {k: v}).
//   Parse NEVER synthesizes a CX element. emit on a CX element uses the
//   lossless `named` encoding {"$tag","$attrs","$children"} (§2).
//
// Errors are returned as `[err :code cx-err:CXERxxxx …]` VALUES (mk_err,
// eval.v); the renderer surfaces the code string matched by `out-err`.

// ── error codes (spec §5) ────────────────────────────────────────────
const json_err_malformed   = 'cx-err:CXER3100' // E_JSON_MALFORMED
const json_err_depth       = 'cx-err:CXER3101' // E_JSON_DEPTH_EXCEEDED
const json_err_bytes       = 'cx-err:CXER3102' // E_JSON_BYTES_EXCEEDED
const json_err_unsupported = 'cx-err:CXER3103' // E_JSON_UNSUPPORTED_VALUE
const json_err_nan         = 'cx-err:CXER3104' // E_JSON_NAN_DISALLOWED
const json_err_range       = 'cx-err:CXER3105' // E_JSON_NUMBER_OUT_OF_RANGE
const json_err_dup_key     = 'cx-err:CXER3106' // E_JSON_DUPLICATE_KEY

// ── scalar builders ──────────────────────────────────────────────────

fn jnode_str(s string) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(s), data_type: cx.ScalarType.string_type }
}

fn json_int(i i64) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(i), data_type: cx.ScalarType.int_type }
}

fn json_float(f f64) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(f), data_type: cx.ScalarType.float_type }
}

fn json_bool(b bool) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(b), data_type: cx.ScalarType.bool_type }
}

fn json_null() cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(cx.NullValue{}), data_type: cx.ScalarType.null_type }
}

fn json_bytes(s string) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(s), data_type: cx.ScalarType.bytes_type }
}

fn json_seq(items []cx.Node) cx.Node {
	return cx.Element{ name: '__cx_seq__', items: items }
}

fn json_arr(items []cx.Node) cx.Node {
	return cx.Element{ name: '__cx_arr__', items: items }
}

fn json_map(entries []cx.Node) cx.Node {
	return cx.Element{ name: '__cx_map__', items: entries }
}

// json_named_value extracts the single value node from a `__cx_map__` entry
// (Element{name: key, items: [value]}).
fn json_entry_value(en cx.Node) cx.Node {
	if en is cx.Element {
		if en.items.len > 0 {
			return en.items[0]
		}
	}
	return cx.Node(cx.TextNode{})
}

// json_maybe_named reconstructs a CX element from the lossless `named` encoding
// {"$tag","$attrs","$children"} (json.md §2) — the parse inverse of emit_named,
// completing the lossless element round-trip (`parse(emit(el)) ≡ el`). An object
// whose keys are EXACTLY a subset of {$tag,$attrs,$children} WITH $tag present
// becomes that element; any other shape returns the plain map unchanged.
fn json_maybe_named(entries []cx.Node) cx.Node {
	mut tag := ''
	mut have_tag := false
	mut attrs := cx.Node(cx.TextNode{})
	mut children := cx.Node(cx.TextNode{})
	for en in entries {
		if en !is cx.Element {
			return json_map(entries)
		}
		key := (en as cx.Element).name
		match key {
			'\$tag' {
				tag = json_arg_str(json_entry_value(en)) or { return json_map(entries) }
				have_tag = true
			}
			'\$attrs' {
				attrs = json_entry_value(en)
			}
			'\$children' {
				children = json_entry_value(en)
			}
			else {
				return json_map(entries) // extra key → ordinary data object
			}
		}
	}
	if !have_tag {
		return json_map(entries)
	}
	mut el := cx.Element{
		name: tag
	}
	if attrs is cx.Element {
		am := attrs as cx.Element
		if am.name == '__cx_map__' {
			for ae in am.items {
				if ae is cx.Element {
					av := json_entry_value(ae)
					if av is cx.ScalarNode {
						el.attrs << cx.Attribute{
							name:  ae.name
							value: av.value
						}
					} else {
						// a non-scalar `$attrs` value is outside the `named`
						// subset (json.md §2) — bail to the plain map rather
						// than silently dropping the attribute; the
						// conversion-lane envelope walk (#475) owns the
						// extended shapes.
						return json_map(entries)
					}
				}
			}
		}
	}
	if children is cx.Element {
		cm := children as cx.Element
		if cm.name in ['__cx_arr__', '__cx_seq__'] {
			el.items = cm.items.clone()
		}
	}
	return cx.Node(el)
}

// ── argument readers ─────────────────────────────────────────────────

fn json_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	note_operand_fault('json', 'json-', 'string', n)
	return none
}

fn json_seq_items(n cx.Node) ?[]cx.Node {
	if n is cx.Element {
		if n.name == '__cx_seq__' || n.name == '__cx_arr__' || n.name == '' {
			return n.items
		}
	}
	return none
}

// json_opts collects a `__cx_map__` opts element into a key→node map.
fn json_opts(n cx.Node) map[string]cx.Node {
	mut m := map[string]cx.Node{}
	if n is cx.Element && n.name == '__cx_map__' {
		for e in n.items {
			if e is cx.Element && e.items.len > 0 {
				m[e.name] = e.items[0]
			}
		}
	}
	return m
}

fn json_opt_bool(m map[string]cx.Node, key string, def bool) bool {
	n := m[key] or { return def }
	if n is cx.ScalarNode {
		v := n.value
		if v is bool {
			return v
		}
	}
	return def
}

fn json_opt_int(m map[string]cx.Node, key string, def int) int {
	n := m[key] or { return def }
	if n is cx.ScalarNode {
		v := n.value
		if v is i64 {
			return int(v)
		}
	}
	return def
}

fn json_opt_str(m map[string]cx.Node, key string, def string) string {
	n := m[key] or { return def }
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return def
}

// ── parser ───────────────────────────────────────────────────────────

struct JsonParser {
mut:
	s           string
	pos         int
	lenient     bool
	number_mode string // auto|all-float|string|all-decimal
	max_depth   int
	depth       int
	err_code    string
	err_msg     string
}

fn (mut p JsonParser) fail(ecode string, msg string) {
	if p.err_code == '' {
		p.err_code = ecode
		p.err_msg = msg
	}
}

fn (mut p JsonParser) skip_ws() {
	for p.pos < p.s.len {
		c := p.s[p.pos]
		if c == ` ` || c == `\t` || c == `\n` || c == `\r` {
			p.pos++
			continue
		}
		if p.lenient && c == `/` && p.pos + 1 < p.s.len {
			n := p.s[p.pos + 1]
			if n == `/` {
				p.pos += 2
				for p.pos < p.s.len && p.s[p.pos] != `\n` {
					p.pos++
				}
				continue
			}
			if n == `*` {
				p.pos += 2
				for p.pos + 1 < p.s.len && !(p.s[p.pos] == `*` && p.s[p.pos + 1] == `/`) {
					p.pos++
				}
				p.pos += 2
				continue
			}
		}
		break
	}
}

// parse_value parses one JSON value at the current position. Returns
// none + sets err_code on failure.
fn (mut p JsonParser) parse_value() ?cx.Node {
	p.skip_ws()
	if p.pos >= p.s.len {
		p.fail(json_err_malformed, 'E_JSON_MALFORMED: unexpected end of input')
		return none
	}
	c := p.s[p.pos]
	match c {
		`{` { return p.parse_object() }
		`[` { return p.parse_array() }
		`"` {
			str := p.parse_string()?
			return jnode_str(str)
		}
		`t`, `f` { return p.parse_bool() }
		`n` { return p.parse_null_or_nan() }
		`N` { return p.parse_nan() }
		`I` { return p.parse_infinity(false) }
		`-` {
			if p.pos + 1 < p.s.len && p.s[p.pos + 1] == `I` {
				p.pos++
				return p.parse_infinity(true)
			}
			return p.parse_number()
		}
		`0`...`9` { return p.parse_number() }
		else {
			p.fail(json_err_malformed, 'E_JSON_MALFORMED: unexpected character "${c.ascii_str()}"')
			return none
		}
	}
}

fn (mut p JsonParser) expect_lit(lit string) bool {
	if p.pos + lit.len <= p.s.len && p.s[p.pos..p.pos + lit.len] == lit {
		p.pos += lit.len
		return true
	}
	return false
}

fn (mut p JsonParser) parse_bool() ?cx.Node {
	if p.expect_lit('true') {
		return json_bool(true)
	}
	if p.expect_lit('false') {
		return json_bool(false)
	}
	p.fail(json_err_malformed, 'E_JSON_MALFORMED: invalid literal')
	return none
}

fn (mut p JsonParser) parse_null_or_nan() ?cx.Node {
	if p.expect_lit('null') {
		return json_null()
	}
	p.fail(json_err_malformed, 'E_JSON_MALFORMED: invalid literal')
	return none
}

fn (mut p JsonParser) parse_nan() ?cx.Node {
	if p.lenient && p.expect_lit('NaN') {
		return json_float(f64_nan())
	}
	p.fail(json_err_malformed, 'E_JSON_MALFORMED: NaN not allowed in strict mode')
	return none
}

fn (mut p JsonParser) parse_infinity(neg bool) ?cx.Node {
	if p.lenient && p.expect_lit('Infinity') {
		return json_float(if neg { f64_neg_inf() } else { f64_inf() })
	}
	p.fail(json_err_malformed, 'E_JSON_MALFORMED: Infinity not allowed in strict mode')
	return none
}

fn (mut p JsonParser) parse_string() ?string {
	// assumes current char is the opening quote
	p.pos++ // skip "
	mut out := []u8{}
	for p.pos < p.s.len {
		c := p.s[p.pos]
		if c == `"` {
			p.pos++
			return out.bytestr()
		}
		if c == `\\` {
			p.pos++
			if p.pos >= p.s.len {
				break
			}
			e := p.s[p.pos]
			match e {
				`"` { out << `"` }
				`\\` { out << `\\` }
				`/` { out << `/` }
				`b` { out << 0x08 }
				`f` { out << 0x0c }
				`n` { out << `\n` }
				`r` { out << `\r` }
				`t` { out << `\t` }
				`u` {
					r := p.parse_unicode_escape() or { return none }
					out << r.bytes()
				}
				else {
					p.fail(json_err_malformed, 'E_JSON_MALFORMED: invalid escape "\\${e.ascii_str()}"')
					return none
				}
			}
			p.pos++
			continue
		}
		out << c
		p.pos++
	}
	p.fail(json_err_malformed, 'E_JSON_MALFORMED: unterminated string')
	return none
}

// parse_unicode_escape parses `\uXXXX` (current pos is at `u`), handling
// surrogate pairs. Returns the decoded rune as a string (UTF-8).
fn (mut p JsonParser) parse_unicode_escape() ?string {
	hi := p.read_hex4() or { return none }
	if hi >= 0xD800 && hi <= 0xDBFF {
		// high surrogate — expect a following \uXXXX low surrogate
		if p.pos + 2 < p.s.len && p.s[p.pos + 1] == `\\` && p.s[p.pos + 2] == `u` {
			p.pos += 2
			lo := p.read_hex4() or { return none }
			if lo >= 0xDC00 && lo <= 0xDFFF {
				cp := 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
				return utf32_to_str(u32(cp))
			}
		}
		p.fail(json_err_malformed, 'E_JSON_MALFORMED: unpaired surrogate')
		return none
	}
	return utf32_to_str(u32(hi))
}

// read_hex4 reads 4 hex digits starting AFTER the `u`. Leaves pos at the
// last hex digit (caller's loop does the final p.pos++).
fn (mut p JsonParser) read_hex4() ?int {
	if p.pos + 4 >= p.s.len {
		p.fail(json_err_malformed, 'E_JSON_MALFORMED: truncated \\u escape')
		return none
	}
	mut v := 0
	for k in 1 .. 5 {
		d := hex_digit(p.s[p.pos + k]) or {
			p.fail(json_err_malformed, 'E_JSON_MALFORMED: invalid hex in \\u escape')
			return none
		}
		v = v * 16 + d
	}
	p.pos += 4
	return v
}

fn (mut p JsonParser) parse_number() ?cx.Node {
	start := p.pos
	mut is_float := false
	if p.pos < p.s.len && p.s[p.pos] == `-` {
		p.pos++
	}
	for p.pos < p.s.len && p.s[p.pos] >= `0` && p.s[p.pos] <= `9` {
		p.pos++
	}
	if p.pos < p.s.len && p.s[p.pos] == `.` {
		is_float = true
		p.pos++
		for p.pos < p.s.len && p.s[p.pos] >= `0` && p.s[p.pos] <= `9` {
			p.pos++
		}
	}
	if p.pos < p.s.len && (p.s[p.pos] == `e` || p.s[p.pos] == `E`) {
		is_float = true
		p.pos++
		if p.pos < p.s.len && (p.s[p.pos] == `+` || p.s[p.pos] == `-`) {
			p.pos++
		}
		for p.pos < p.s.len && p.s[p.pos] >= `0` && p.s[p.pos] <= `9` {
			p.pos++
		}
	}
	raw := p.s[start..p.pos]
	if raw == '' || raw == '-' {
		p.fail(json_err_malformed, 'E_JSON_MALFORMED: invalid number')
		return none
	}
	if p.number_mode == 'string' {
		return jnode_str(raw)
	}
	if p.number_mode == 'all-float' {
		return json_float(raw.f64())
	}
	if p.number_mode == 'all-decimal' {
		// I1 stream 11 (defect D): the documented EXACT mode is genuinely
		// exact — the JSON digits become a fixed-point decimal, no f64
		// round-trip (it was aliased to lossy all-float).
		img := cx.cx_decimal_image_from_json_number(raw) or {
			p.fail(json_err_malformed, 'E_JSON_MALFORMED: invalid number')
			return none
		}
		return cx.Node(cx.ScalarNode{ data_type: cx.ScalarType.decimal_type, value: cx.ScalarValue(img) })
	}
	// auto
	if is_float {
		return json_float(raw.f64())
	}
	// integer: must fit i64 or CXER3105
	iv := json_parse_i64(raw) or {
		p.fail(json_err_range, 'E_JSON_NUMBER_OUT_OF_RANGE: ${raw}')
		return none
	}
	return json_int(iv)
}

fn (mut p JsonParser) parse_array() ?cx.Node {
	p.pos++ // [
	p.depth++
	if p.depth > p.max_depth {
		p.fail(json_err_depth, 'E_JSON_DEPTH_EXCEEDED: max-depth ${p.max_depth}')
		return none
	}
	mut items := []cx.Node{}
	p.skip_ws()
	if p.pos < p.s.len && p.s[p.pos] == `]` {
		p.pos++
		p.depth--
		return json_arr(items)
	}
	for {
		v := p.parse_value() or { return none }
		items << v
		p.skip_ws()
		if p.pos >= p.s.len {
			p.fail(json_err_malformed, 'E_JSON_MALFORMED: unterminated array')
			return none
		}
		c := p.s[p.pos]
		if c == `,` {
			p.pos++
			p.skip_ws()
			if p.lenient && p.pos < p.s.len && p.s[p.pos] == `]` {
				p.pos++
				p.depth--
				return json_arr(items)
			}
			continue
		}
		if c == `]` {
			p.pos++
			p.depth--
			return json_arr(items)
		}
		p.fail(json_err_malformed, 'E_JSON_MALFORMED: expected , or ] in array')
		return none
	}
	return none
}

fn (mut p JsonParser) parse_object() ?cx.Node {
	p.pos++ // {
	p.depth++
	if p.depth > p.max_depth {
		p.fail(json_err_depth, 'E_JSON_DEPTH_EXCEEDED: max-depth ${p.max_depth}')
		return none
	}
	mut entries := []cx.Node{}
	mut seen := map[string]int{} // key -> index in entries
	p.skip_ws()
	if p.pos < p.s.len && p.s[p.pos] == `}` {
		p.pos++
		p.depth--
		return json_map(entries)
	}
	for {
		p.skip_ws()
		if p.pos >= p.s.len {
			p.fail(json_err_malformed, 'E_JSON_MALFORMED: unterminated object')
			return none
		}
		mut key := ''
		if p.s[p.pos] == `"` {
			key = p.parse_string() or { return none }
		} else if p.lenient && json_is_ident_start(p.s[p.pos]) {
			ks := p.pos
			for p.pos < p.s.len && json_is_ident_char(p.s[p.pos]) {
				p.pos++
			}
			key = p.s[ks..p.pos]
		} else {
			p.fail(json_err_malformed, 'E_JSON_MALFORMED: expected object key')
			return none
		}
		p.skip_ws()
		if p.pos >= p.s.len || p.s[p.pos] != `:` {
			p.fail(json_err_malformed, 'E_JSON_MALFORMED: expected : after key')
			return none
		}
		p.pos++ // :
		v := p.parse_value() or { return none }
		if idx := seen[key] {
			if p.lenient {
				// last-value-wins
				en := entries[idx]
				if en is cx.Element {
					entries[idx] = cx.Element{ name: en.name, items: [v] }
				}
			} else {
				p.fail(json_err_dup_key, 'E_JSON_DUPLICATE_KEY: ${key}')
				return none
			}
		} else {
			seen[key] = entries.len
			entries << cx.Element{ name: key, items: [v] }
		}
		p.skip_ws()
		if p.pos >= p.s.len {
			p.fail(json_err_malformed, 'E_JSON_MALFORMED: unterminated object')
			return none
		}
		c := p.s[p.pos]
		if c == `,` {
			p.pos++
			p.skip_ws()
			if p.lenient && p.pos < p.s.len && p.s[p.pos] == `}` {
				p.pos++
				p.depth--
				return json_maybe_named(entries)
			}
			continue
		}
		if c == `}` {
			p.pos++
			p.depth--
			return json_maybe_named(entries)
		}
		p.fail(json_err_malformed, 'E_JSON_MALFORMED: expected , or } in object')
		return none
	}
	return none
}

// parse_top parses a single value and requires no trailing content.
fn (mut p JsonParser) parse_top() ?cx.Node {
	v := p.parse_value() or { return none }
	p.skip_ws()
	if p.pos < p.s.len {
		p.fail(json_err_malformed, 'E_JSON_MALFORMED: trailing content')
		return none
	}
	return v
}

// ── emitter ──────────────────────────────────────────────────────────

struct JsonEmitter {
mut:
	sb           strings.Builder = strings.new_builder(64)
	indent       int  // 0 = compact
	sort_keys    bool
	ensure_ascii bool
	nan_handling string // null|string|error
	err_code     string
}

fn (mut e JsonEmitter) write_indent(depth int) {
	if e.indent <= 0 {
		return
	}
	e.sb.write_string('\n')
	for _ in 0 .. depth * e.indent {
		e.sb.write_string(' ')
	}
}

// emit_node writes the JSON for `n` at nesting `depth`. Sets err_code +
// returns false on a non-emittable value.
fn (mut e JsonEmitter) emit_node(n cx.Node, depth int) bool {
	match n {
		cx.ScalarNode {
			return e.emit_scalar(n)
		}
		cx.TextNode {
			// A text child emits as a JSON string (json.md §2 — element
			// $children); reuses the scalar string path.
			return e.emit_scalar(cx.ScalarNode{
				value:     cx.ScalarValue(n.value)
				data_type: cx.ScalarType.string_type
			})
		}
		cx.DocumentNode {
			// D7 transparent document carrier: single-element doc emits as
			// that element; multi-root as a JSON array of its elements.
			if n.elements.len == 1 && n.prolog.len == 0 {
				return e.emit_node(n.elements[0], depth)
			}
			return e.emit_array(n.elements, depth)
		}
		cx.Element {
			match n.name {
				'__cx_arr__', '__cx_seq__' {
					return e.emit_array(n.items, depth)
				}
				'__cx_map__' {
					return e.emit_object(n.items, depth)
				}
				else {
					return e.emit_named(n, depth)
				}
			}
		}
		else {
			e.err_code = json_err_unsupported
			return false
		}
	}
}

fn (mut e JsonEmitter) emit_scalar(n cx.ScalarNode) bool {
	dt := n.data_type
	if dt == cx.ScalarType.atom_type || dt == cx.ScalarType.bytes_type
		|| dt == cx.ScalarType.date_type || dt == cx.ScalarType.datetime_type {
		e.err_code = json_err_unsupported
		return false
	}
	v := n.value
	match v {
		string {
			e.write_json_string(v)
		}
		i64 {
			e.sb.write_string(v.str())
		}
		f64 {
			if json_is_nonfinite(v) {
				match e.nan_handling {
					'string' { e.write_json_string(v.str()) }
					'error' { e.err_code = json_err_nan return false }
					else { e.sb.write_string('null') }
				}
			} else {
				e.sb.write_string(json_format_float(v))
			}
		}
		bool {
			e.sb.write_string(v.str())
		}
		cx.NullValue {
			e.sb.write_string('null')
		}
	}
	return true
}

fn (mut e JsonEmitter) emit_array(items []cx.Node, depth int) bool {
	if items.len == 0 {
		e.sb.write_string('[]')
		return true
	}
	e.sb.write_string('[')
	for i, it in items {
		if i > 0 {
			e.sb.write_string(',')
		}
		e.write_indent(depth + 1)
		if !e.emit_node(it, depth + 1) {
			return false
		}
	}
	e.write_indent(depth)
	e.sb.write_string(']')
	return true
}

// emit_object emits a `__cx_map__` entry list (each entry Element
// name=key items[0]=value).
fn (mut e JsonEmitter) emit_object(entries []cx.Node, depth int) bool {
	mut pairs := []JsonPair{}
	for ent in entries {
		if ent is cx.Element {
			val := if ent.items.len > 0 { ent.items[0] } else { json_null() }
			pairs << JsonPair{ key: ent.name, value: val }
		}
	}
	return e.emit_pairs(pairs, depth)
}

struct JsonPair {
	key   string
	value cx.Node
}

fn (mut e JsonEmitter) emit_pairs(pairs_in []JsonPair, depth int) bool {
	mut pairs := pairs_in.clone()
	if e.sort_keys {
		pairs.sort(a.key < b.key)
	}
	if pairs.len == 0 {
		e.sb.write_string('{}')
		return true
	}
	e.sb.write_string('{')
	for i, pr in pairs {
		if i > 0 {
			e.sb.write_string(',')
		}
		e.write_indent(depth + 1)
		e.write_json_string(pr.key)
		e.sb.write_string(if e.indent > 0 { ': ' } else { ':' })
		if !e.emit_node(pr.value, depth + 1) {
			return false
		}
	}
	e.write_indent(depth)
	e.sb.write_string('}')
	return true
}

// emit_named emits a CX element via the lossless `named` encoding (§2):
// {"$tag": name, "$attrs": {...}, "$children": [...]}.
fn (mut e JsonEmitter) emit_named(el cx.Element, depth int) bool {
	mut attr_entries := []cx.Node{}
	for a in el.attrs {
		attr_entries << cx.Element{
			name:  a.name
			items: [cx.Node(scalar_value_to_node(a.value))]
		}
	}
	pairs := [
		JsonPair{ key: '\$tag', value: jnode_str(el.name) },
		JsonPair{ key: '\$attrs', value: json_map(attr_entries) },
		JsonPair{ key: '\$children', value: json_arr(el.items.clone()) },
	]
	return e.emit_pairs(pairs, depth)
}

fn (mut e JsonEmitter) write_json_string(s string) {
	e.sb.write_string('"')
	for r in s.runes() {
		c := u32(r)
		match c {
			0x22 { e.sb.write_string('\\"') }
			0x5c { e.sb.write_string('\\\\') }
			0x08 { e.sb.write_string('\\b') }
			0x0c { e.sb.write_string('\\f') }
			0x0a { e.sb.write_string('\\n') }
			0x0d { e.sb.write_string('\\r') }
			0x09 { e.sb.write_string('\\t') }
			else {
				if c < 0x20 {
					e.sb.write_string('\\u' + json_hex4(c))
				} else if c < 0x80 {
					e.sb.write_string(u8(c).ascii_str())
				} else if e.ensure_ascii {
					if c > 0xFFFF {
						cp := c - 0x10000
						hi := 0xD800 + (cp >> 10)
						lo := 0xDC00 + (cp & 0x3FF)
						e.sb.write_string('\\u' + json_hex4(hi))
						e.sb.write_string('\\u' + json_hex4(lo))
					} else {
						e.sb.write_string('\\u' + json_hex4(c))
					}
				} else {
					e.sb.write_string(r.str())
				}
			}
		}
	}
	e.sb.write_string('"')
}

// ── dispatch helpers ─────────────────────────────────────────────────

fn new_json_parser(s string, opts map[string]cx.Node) JsonParser {
	return JsonParser{
		s:           s
		lenient:     json_opt_bool(opts, 'lenient', false)
		number_mode: json_opt_str(opts, 'number-mode', 'auto')
		max_depth:   json_opt_int(opts, 'max-depth', 100)
	}
}

pub fn json_do_parse(s string, opts map[string]cx.Node) cx.Node {
	max_bytes := json_opt_int(opts, 'max-bytes', 0)
	if max_bytes > 0 && s.len > max_bytes {
		return mk_err(json_err_bytes, 'E_JSON_BYTES_EXCEEDED: ${s.len} > ${max_bytes}')
	}
	mut p := new_json_parser(s, opts)
	v := p.parse_top() or {
		return mk_err(p.err_code, p.err_msg)
	}
	return v
}

fn json_emit_with(value cx.Node, indent int, sort_keys bool, ensure_ascii bool, nan_handling string) cx.Node {
	mut e := JsonEmitter{
		indent:       indent
		sort_keys:    sort_keys
		ensure_ascii: ensure_ascii
		nan_handling: nan_handling
	}
	if !e.emit_node(value, 0) {
		return mk_err(e.err_code, json_emit_err_msg(e.err_code))
	}
	return jnode_str(e.sb.str())
}

fn json_emit_err_msg(ecode string) string {
	return match ecode {
		json_err_unsupported { 'E_JSON_UNSUPPORTED_VALUE: value kind has no JSON mapping' }
		json_err_nan { 'E_JSON_NAN_DISALLOWED: non-finite float with nan-handling=error' }
		else { 'E_JSON: emit failed' }
	}
}

// ── primitive dispatch ───────────────────────────────────────────────

// json_emit_value renders a CX value as JSON. By default (lossy, idiomatic) an
// element/document tree emits SEMANTICALLY (the shared codec.md §6 mapping,
// conversions.md §2.2 — `[a 1]` → `{"a":1}`); under `lossless` it emits via the
// `named` $tag encoding (round-trips an element tree exactly). A CXDM value
// (scalar, or `__cx_map__`/`__cx_arr__`/`__cx_seq__` marker) emits directly.
fn json_emit_value(value cx.Node, indent int, sort_keys bool, ensure_ascii bool, nan string, lossless bool) cx.Node {
	if !lossless {
		if value is cx.DocumentNode {
			return jnode_str(cx.emit_semantic_json_opts(cx.node_to_doc(value), indent, sort_keys))
		}
		if value is cx.Element {
			if value.name !in ['__cx_map__', '__cx_arr__', '__cx_seq__'] {
				return jnode_str(cx.emit_semantic_json_opts(cx.Document{ elements: [value] },
					indent, sort_keys))
			}
		}
	}
	return json_emit_with(value, indent, sort_keys, ensure_ascii, nan)
}

fn json_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		'json-parse' {
			s := json_arg_str(args[0]) or { return none }
			return json_do_parse(s, map[string]cx.Node{})
		}
		'json-parse-with-opts' {
			s := json_arg_str(args[0]) or { return none }
			opts := json_opts(args[1])
			return json_do_parse(s, opts)
		}
		'json-parse-bytes' {
			raw := json_arg_str(args[0]) or { return none }
			return json_do_parse(json_strip_bom(raw), map[string]cx.Node{})
		}
		'json-emit' {
			// canonical: compact, keys sorted
			return json_emit_value(args[0], 0, true, false, 'null', false)
		}
		'json-emit-pretty' {
			// two-space indent, insertion order preserved
			return json_emit_value(args[0], 2, false, false, 'null', false)
		}
		'json-emit-with-opts' {
			opts := json_opts(args[1])
			indent := json_opt_int(opts, 'indent', 0)
			sort_keys := json_opt_bool(opts, 'sort-keys', false)
			ensure_ascii := json_opt_bool(opts, 'ensure-ascii', false)
			trailing_nl := json_opt_bool(opts, 'trailing-newline', false)
			nan_handling := json_opt_str(opts, 'nan-handling', 'null')
			lossless := json_opt_bool(opts, 'lossless', false)
			res := json_emit_value(args[0], indent, sort_keys, ensure_ascii, nan_handling,
				lossless)
			if res is cx.ScalarNode {
				if trailing_nl {
					if sv := json_arg_str(res) {
						return jnode_str(sv + '\n')
					}
				}
			}
			return res
		}
		'json-emit-bytes' {
			res := json_emit_value(args[0], 0, true, false, 'null', false)
			if s := json_arg_str(res) {
				return json_bytes(s)
			}
			return res // err passthrough
		}
		'json-parse-stream' {
			items := json_seq_items(args[0]) or { return none }
			mut out := []cx.Node{}
			for it in items {
				s := json_arg_str(it) or {
					return mk_err(json_err_malformed, 'E_JSON_MALFORMED: stream element not a string')
				}
				mut p := new_json_parser(s, map[string]cx.Node{})
				v := p.parse_top() or {
					return mk_err(p.err_code, p.err_msg)
				}
				out << v
			}
			return json_seq(out)
		}
		'json-parse-many' {
			s := json_arg_str(args[0]) or { return none }
			mut p := new_json_parser(s, map[string]cx.Node{})
			mut out := []cx.Node{}
			for {
				p.skip_ws()
				if p.pos >= p.s.len {
					break
				}
				v := p.parse_value() or {
					return mk_err(p.err_code, p.err_msg)
				}
				out << v
			}
			return json_seq(out)
		}
		'json-emit-stream' {
			items := json_seq_items(args[0]) or { return none }
			mut out := []cx.Node{}
			for it in items {
				res := json_emit_with(it, 0, true, false, 'null')
				if s := json_arg_str(res) {
					out << jnode_str(s + '\n')
				} else {
					return res
				}
			}
			return json_seq(out)
		}
		'json-is-valid' {
			s := json_arg_str(args[0]) or { return none }
			mut p := new_json_parser(s, map[string]cx.Node{})
			p.parse_top() or {
				return json_bool(false)
			}
			return json_bool(true)
		}
		else {
			return none
		}
	}
}

// ── free helpers ─────────────────────────────────────────────────────

fn json_strip_bom(s string) string {
	if s.len >= 3 && s[0] == 0xEF && s[1] == 0xBB && s[2] == 0xBF {
		return s[3..]
	}
	// UTF-16 BOM auto-detect → decode to UTF-8
	if s.len >= 2 && s[0] == 0xFF && s[1] == 0xFE {
		return utf16le_to_utf8(s[2..])
	}
	if s.len >= 2 && s[0] == 0xFE && s[1] == 0xFF {
		return utf16be_to_utf8(s[2..])
	}
	return s
}

fn utf16le_to_utf8(s string) string {
	mut sb := strings.new_builder(s.len)
	mut i := 0
	for i + 1 < s.len {
		cp := u32(s[i]) | (u32(s[i + 1]) << 8)
		sb.write_string(utf32_to_str(cp))
		i += 2
	}
	return sb.str()
}

fn utf16be_to_utf8(s string) string {
	mut sb := strings.new_builder(s.len)
	mut i := 0
	for i + 1 < s.len {
		cp := (u32(s[i]) << 8) | u32(s[i + 1])
		sb.write_string(utf32_to_str(cp))
		i += 2
	}
	return sb.str()
}

fn json_is_ident_start(c u8) bool {
	return (c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`) || c == `_` || c == `$`
}

fn json_is_ident_char(c u8) bool {
	return json_is_ident_start(c) || (c >= `0` && c <= `9`) || c == `-`
}

fn hex_digit(c u8) ?int {
	if c >= `0` && c <= `9` {
		return int(c - `0`)
	}
	if c >= `a` && c <= `f` {
		return int(c - `a`) + 10
	}
	if c >= `A` && c <= `F` {
		return int(c - `A`) + 10
	}
	return none
}

fn json_hex4(c u32) string {
	digits := '0123456789abcdef'
	mut out := []u8{len: 4}
	out[0] = digits[(c >> 12) & 0xF]
	out[1] = digits[(c >> 8) & 0xF]
	out[2] = digits[(c >> 4) & 0xF]
	out[3] = digits[c & 0xF]
	return out.bytestr()
}

// json_parse_i64 parses a base-10 integer literal that may be negative,
// returning none on overflow (so the auto number-mode can raise CXER3105).
fn json_parse_i64(raw string) ?i64 {
	mut neg := false
	mut i := 0
	if raw.len > 0 && raw[0] == `-` {
		neg = true
		i = 1
	}
	if i >= raw.len {
		return none
	}
	mut acc := u64(0)
	limit := if neg { u64(9223372036854775808) } else { u64(9223372036854775807) }
	for j in i .. raw.len {
		c := raw[j]
		if c < `0` || c > `9` {
			return none
		}
		d := u64(c - `0`)
		// overflow guard
		if acc > (limit - d) / 10 {
			return none
		}
		acc = acc * 10 + d
	}
	if neg {
		if acc == u64(9223372036854775808) {
			return i64(-9223372036854775807 - 1)
		}
		return -i64(acc)
	}
	return i64(acc)
}

// json_format_float renders a finite f64 in JSON form.
fn json_format_float(f f64) string {
	return f.str()
}

fn json_is_nonfinite(f f64) bool {
	return math.is_nan(f) || math.is_inf(f, 0)
}

fn f64_inf() f64 {
	return math.inf(1)
}

fn f64_neg_inf() f64 {
	return math.inf(-1)
}

fn f64_nan() f64 {
	return math.nan()
}

// utf32_to_str encodes a Unicode scalar value to a UTF-8 string.
fn utf32_to_str(cp u32) string {
	mut out := []u8{}
	if cp < 0x80 {
		out << u8(cp)
	} else if cp < 0x800 {
		out << u8(0xC0 | (cp >> 6))
		out << u8(0x80 | (cp & 0x3F))
	} else if cp < 0x10000 {
		out << u8(0xE0 | (cp >> 12))
		out << u8(0x80 | ((cp >> 6) & 0x3F))
		out << u8(0x80 | (cp & 0x3F))
	} else {
		out << u8(0xF0 | (cp >> 18))
		out << u8(0x80 | ((cp >> 12) & 0x3F))
		out << u8(0x80 | ((cp >> 6) & 0x3F))
		out << u8(0x80 | (cp & 0x3F))
	}
	return out.bytestr()
}

// scalar_value_to_node lifts an attribute ScalarValue into a ScalarNode.
fn scalar_value_to_node(v cx.ScalarValue) cx.ScalarNode {
	match v {
		string { return cx.ScalarNode{ value: cx.ScalarValue(v), data_type: cx.ScalarType.string_type } }
		i64 { return cx.ScalarNode{ value: cx.ScalarValue(v), data_type: cx.ScalarType.int_type } }
		f64 { return cx.ScalarNode{ value: cx.ScalarValue(v), data_type: cx.ScalarType.float_type } }
		bool { return cx.ScalarNode{ value: cx.ScalarValue(v), data_type: cx.ScalarType.bool_type } }
		cx.NullValue { return cx.ScalarNode{ value: cx.ScalarValue(cx.NullValue{}), data_type: cx.ScalarType.null_type } }
	}
}
