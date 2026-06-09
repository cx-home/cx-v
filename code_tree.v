module cx

// ── v0.8.0 Phase 2.11 — cx_code_tree real walker ──────────────
//
// Produces the JSON contract for the playground's Tree View per
// `spec/core/ast.md`.
// Every emitted node carries `{kind, name?, value?, loc:{start,end},
// children?}`; `loc` byte offsets are into the original UTF-8 source
// and enable the bidirectional selection bridge between tree
// pane and source pane without further ABI plumbing.
//
// This file lives in `vcx/cx/` (sibling to cabi.v) rather than
// `vcx/code/` so the C ABI export composes against the host data
// model without re-opening the import cycle that drove other code-
// surface exports into `vcx/code/`. The walker therefore avoids the
// program-AST (`code.Program`) entirely — it scans the source text
// directly, tracking byte offsets as it goes. This matches the
// gate-17 §D11 "playground-input ceiling" budget (~64 KB) and keeps
// the tree walker independent of the (still-evolving) program parser.
//
// Per-kind shape (§D2 table):
//   - element   {kind:"element",   name, loc, children?}
//   - attribute {kind:"attribute", name, value, loc}
//   - text      {kind:"text",      value, loc}
//   - directive {kind:"directive", name, loc, children?}
//   - scalar    {kind:"scalar",    value, loc}
//   - path      {kind:"path",      value, loc}
//
// `value` is JSON-typed: integers emit as JSON numbers, floats as
// JSON numbers, booleans as `true`/`false`, atoms/strings as JSON
// strings (atoms keep the leading `:` to mark the scalar kind).
//
// Top-level wrapping rule: a single top-level statement returns its
// own node verbatim (per tree-001/006 fixtures). Multiple top-level
// statements wrap in a synthetic root element spanning the source.
// Empty or whitespace-only sources return an empty root with
// `loc:{start:0,end:0}`.

// code_tree is the public entry point. Returns the JSON tree as a
// UTF-8 string. Never raises — malformed sources degrade to the most
// specific tree shape the scanner can recover (typically a single
// `scalar`-or-`element`-stub spanning the input).
pub fn code_tree(source string) !string {
	bs := source.bytes()
	mut p := TreeParser{ src: bs, pos: 0 }
	p.skip_ws()
	if p.pos >= bs.len {
		// Empty / whitespace-only: empty root element at [0,0).
		return '{"kind":"element","name":"root","loc":{"start":0,"end":0},"children":[]}'
	}
	mut nodes := []TreeNode{}
	for p.pos < bs.len {
		p.skip_ws()
		if p.pos >= bs.len { break }
		// Skip stray `]` (defensive — should never happen at top level
		// with well-formed source). Treat as benign separator.
		if bs[p.pos] == `]` { p.pos++; continue }
		n := p.parse_item() or { break }
		nodes << n
	}
	if nodes.len == 0 {
		return '{"kind":"element","name":"root","loc":{"start":0,"end":${bs.len}},"children":[]}'
	}
	if nodes.len == 1 {
		return render_node(nodes[0])
	}
	// Multiple top-level statements — wrap in a synthetic root.
	root := TreeNode{
		kind:         'element'
		name:         'root'
		loc_start:    0
		loc_end:      bs.len
		children:     nodes
		has_children: true
	}
	return render_node(root)
}

// TreeNode is the in-memory representation of one node.
// All optional fields are encoded by presence — empty `name` / empty
// `value` strings flag absence per the JSON emit-time skip.
struct TreeNode {
mut:
	kind      string
	name      string
	// value_kind discriminates the scalar payload:
	//   - 'string'  → emit as JSON string (use value_str)
	//   - 'atom'    → emit as JSON string ":NAME" (use value_str)
	//   - 'int'     → emit as JSON number (use value_str verbatim)
	//   - 'float'   → emit as JSON number (use value_str verbatim)
	//   - 'bool'    → emit as JSON true/false (use value_str = "true"/"false")
	//   - ''        → no value
	value_kind string
	value_str  string
	loc_start  int
	loc_end    int
	children   []TreeNode
	has_children bool // distinguish explicit empty children list from absent
}

// ── Scanner ──────────────────────────────────────────────────────────

struct TreeParser {
mut:
	src []u8
	pos int
}

fn (mut p TreeParser) skip_ws() {
	for p.pos < p.src.len {
		c := p.src[p.pos]
		if c == ` ` || c == `\t` || c == `\n` || c == `\r` { p.pos++; continue }
		// Skip line comments `# ... \n` only when at line start (best
		// effort — the tree view does not surface comments as nodes).
		break
	}
}

fn is_ident_byte_tree(b u8) bool {
	return (b >= `a` && b <= `z`) || (b >= `A` && b <= `Z`)
	       || (b >= `0` && b <= `9`) || b == `_` || b == `-`
}

fn is_name_start_tree(b u8) bool {
	return (b >= `a` && b <= `z`) || (b >= `A` && b <= `Z`) || b == `_`
}

// parse_item reads the next top-level / sibling-level item. Returns
// the parsed node or `none` if no item can be recovered (caller
// should break out of its accumulation loop).
fn (mut p TreeParser) parse_item() !TreeNode {
	p.skip_ws()
	if p.pos >= p.src.len { return error('eof') }
	c := p.src[p.pos]
	if c == `[` {
		return p.parse_bracket()!
	}
	if c == `/` {
		return p.parse_path()
	}
	if c == `'` || c == `"` {
		return p.parse_text_or_string()
	}
	if c == `:` && p.pos + 1 < p.src.len && is_name_start_tree(p.src[p.pos+1]) {
		// Bare atom (`:name`) — emit as scalar with atom value.
		return p.parse_atom_scalar()
	}
	if c == `$` {
		// Binding reference — treat as scalar with string value
		// `$name…` (preserves the source token verbatim).
		return p.parse_binding_scalar()
	}
	if c == `-` || c == `+` || (c >= `0` && c <= `9`) {
		return p.parse_number_scalar()
	}
	if is_name_start_tree(c) {
		// Bare identifier — could be a boolean literal, a keyword,
		// or a bare call name. Emit as scalar with string value.
		return p.parse_ident_scalar()
	}
	// Unrecognized byte: skip it to make progress; surface as 1-byte
	// scalar so downstream consumers can see something occurred.
	start := p.pos
	p.pos++
	return TreeNode{
		kind:       'scalar'
		value_kind: 'string'
		value_str:  unsafe { tos(&p.src[start], 1) }.clone()
		loc_start:  start
		loc_end:    p.pos
	}
}

// parse_bracket dispatches `[...]` shapes:
//   - `[?name …]`  → directive
//   - `[?=expr]`   → directive (interpolation; named `interp`)
//   - `[?cx …]`    → directive (PI)
//   - `[name …]`   → element
fn (mut p TreeParser) parse_bracket() !TreeNode {
	start := p.pos
	if p.src[p.pos] != `[` { return error('not a bracket') }
	end := find_matching_bracket(p.src, start)
	if end < 0 {
		// Unbalanced — recover by spanning to end of source.
		p.pos = p.src.len
		return TreeNode{
			kind:      'element'
			name:      'unbalanced'
			loc_start: start
			loc_end:   p.src.len
		}
	}
	// Inspect after `[` for directive marker.
	mut inner_pos := start + 1
	if inner_pos < end && p.src[inner_pos] == `?` {
		// Directive form `[?name …]` (or `[?=expr]`).
		inner_pos++
		mut name_start := inner_pos
		mut name := ''
		if inner_pos < end && p.src[inner_pos] == `=` {
			name = 'interp'
			inner_pos++
		} else {
			for inner_pos < end && is_ident_byte_tree(p.src[inner_pos]) {
				inner_pos++
			}
			name = unsafe { tos(&p.src[name_start], inner_pos - name_start) }.clone()
		}
		// Descend into the directive body. Per grammar [59] the body uses
		// the same item grammar as element bodies — clause-child elements
		// (`[in $x S]`, `[yield E]`, `[= $x v]`, `[then …]`/`[else …]`),
		// `name=value` attributes, nested brackets, text, scalars, paths,
		// bindings, and `:NAME` atoms. Clause / attribute / bareword
		// interpretation is the program-AST layer's job ([127]), not the
		// data walker's, so this mirrors the element children-loop below.
		p.pos = inner_pos
		mut dchildren := []TreeNode{}
		for {
			p.skip_ws()
			if p.pos >= end { break }
			dc := p.src[p.pos]
			if dc == `]` { break }
			// `:NAME` is an atom literal (grammar.ebnf:319), not a colon
			// attribute — it falls through to parse_item → parse_atom_scalar.
			if is_name_start_tree(dc) && p.has_eq_attr_ahead(end) {
				if attr := p.parse_attribute_eq_form_in_element(end) {
					dchildren << attr
				} else {
					p.pos++
				}
				continue
			}
			saved := p.pos
			child := p.parse_item() or { break }
			if p.pos == saved { p.pos++; continue }
			dchildren << child
		}
		p.pos = end + 1
		mut dnode := TreeNode{
			kind:      'directive'
			name:      name
			loc_start: start
			loc_end:   end + 1
		}
		if dchildren.len > 0 {
			dnode.children = dchildren
			dnode.has_children = true
		}
		return dnode
	}
	// Element form `[name …]`. Parse name + attributes + body.
	p.pos = start + 1
	p.skip_ws()
	name_start := p.pos
	for p.pos < end && (is_ident_byte_tree(p.src[p.pos]) || p.src[p.pos] == `:`) {
		// Allow `prefix:local` element names.
		p.pos++
	}
	name := unsafe { tos(&p.src[name_start], p.pos - name_start) }.clone()
	if name == '' {
		// Anonymous element — treat as `_`.
		p.pos = end + 1
		return TreeNode{
			kind:      'element'
			name:      '_'
			loc_start: start
			loc_end:   end + 1
		}
	}
	// Parse children inside `[name … ]`.
	mut children := []TreeNode{}
	for {
		p.skip_ws()
		if p.pos >= end { break }
		c := p.src[p.pos]
		if c == `]` { break }
		// `:NAME` in an element body is an atom literal (grammar.ebnf:319),
		// NOT an attribute — it falls through to parse_item → parse_atom_scalar
		// below. (The legacy `:label value` → attribute form is removed here to
		// match the authoritative data parser. The directive-body `:slot` path
		// above is left untouched pending the directive-syntax cutover.)
		// Attribute: `name=VALUE` (standard CX `name=value` form). Peek
		// for an identifier directly followed by `=`; if found, parse as
		// a single attribute node. Otherwise fall through to parse_item
		// so bare identifiers (true/false/keywords) still emit as scalars.
		if is_name_start_tree(c) && p.has_eq_attr_ahead(end) {
			if attr := p.parse_attribute_eq_form_in_element(end) {
				children << attr
			} else {
				p.pos++
			}
			continue
		}
		// Body item (nested element / text / scalar).
		saved := p.pos
		child := p.parse_item() or { break }
		if p.pos == saved { p.pos++; continue }
		children << child
	}
	p.pos = end + 1
	mut node := TreeNode{
		kind:      'element'
		name:      name
		loc_start: start
		loc_end:   end + 1
	}
	if children.len > 0 {
		node.children = children
		node.has_children = true
	}
	return node
}

// has_eq_attr_ahead returns true if `p.pos` starts an identifier that
// is immediately (no whitespace) followed by `=` and a value byte.
// Used by the element/directive children-loop to disambiguate
// `name=value` attribute form from a bare identifier scalar.
fn (p &TreeParser) has_eq_attr_ahead(end int) bool {
	if p.pos >= end { return false }
	if !is_name_start_tree(p.src[p.pos]) { return false }
	mut j := p.pos
	for j < end && is_ident_byte_tree(p.src[j]) { j++ }
	if j == p.pos { return false }
	if j >= end { return false }
	if p.src[j] != `=` { return false }
	// Must be followed by something (not immediately `]` or whitespace).
	k := j + 1
	if k >= end { return false }
	c := p.src[k]
	if c == ` ` || c == `\t` || c == `\n` || c == `\r` || c == `]` {
		return false
	}
	return true
}

// parse_attribute_eq_form_in_element parses `name=value` starting at
// p.pos where p.src[p.pos] is an identifier start byte. The four scalar
// value shapes (quoted string, bracket, atom, bare token) emit distinct
// value_kind discriminators. `end` is the enclosing `]` index (exclusive
// bound for the inner scan).
fn (mut p TreeParser) parse_attribute_eq_form_in_element(end int) ?TreeNode {
	if p.pos >= end || !is_name_start_tree(p.src[p.pos]) { return none }
	start := p.pos
	name_start := p.pos
	for p.pos < end && is_ident_byte_tree(p.src[p.pos]) {
		p.pos++
	}
	if p.pos == name_start { return none }
	if p.pos >= end || p.src[p.pos] != `=` { return none }
	name := unsafe { tos(&p.src[name_start], p.pos - name_start) }.clone()
	p.pos++ // consume `=`
	if p.pos >= end {
		return TreeNode{
			kind:       'attribute'
			name:       name
			value_kind: 'string'
			value_str:  ''
			loc_start:  start
			loc_end:    p.pos
		}
	}
	c := p.src[p.pos]
	mut vk := ''
	mut vs := ''
	mut value_end := p.pos
	if c == `'` || c == `"` {
		qend := find_quote_end(p.src, p.pos)
		if qend < 0 || qend >= end {
			value_end = end
		} else {
			vk = 'string'
			vs = unsafe { tos(&p.src[p.pos + 1], qend - p.pos - 1) }.clone()
			value_end = qend + 1
		}
	} else if c == `[` {
		ebracket := find_matching_bracket(p.src, p.pos)
		if ebracket < 0 || ebracket >= end {
			value_end = end
		} else {
			vk = 'string'
			vs = unsafe { tos(&p.src[p.pos], ebracket - p.pos + 1) }.clone()
			value_end = ebracket + 1
		}
	} else if c == `:` && p.pos + 1 < end && is_name_start_tree(p.src[p.pos+1]) {
		mut j := p.pos + 1
		for j < end && is_ident_byte_tree(p.src[j]) { j++ }
		vk = 'atom'
		vs = unsafe { tos(&p.src[p.pos + 1], j - p.pos - 1) }.clone()
		value_end = j
	} else {
		mut j := p.pos
		for j < end && p.src[j] != ` ` && p.src[j] != `\t`
		    && p.src[j] != `\n` && p.src[j] != `\r`
		    && p.src[j] != `]` {
			j++
		}
		raw := unsafe { tos(&p.src[p.pos], j - p.pos) }.clone()
		value_end = j
		vk, vs = classify_bare_value(raw)
	}
	p.pos = value_end
	return TreeNode{
		kind:       'attribute'
		name:       name
		value_kind: vk
		value_str:  vs
		loc_start:  start
		loc_end:    value_end
	}
}

// classify_bare_value categorises a non-quoted, non-bracket attribute
// or body value token into one of the value-kind discriminators.
fn classify_bare_value(raw string) (string, string) {
	if raw == 'true' { return 'bool', 'true' }
	if raw == 'false' { return 'bool', 'false' }
	if raw == 'null' { return 'string', 'null' }
	if looks_like_int(raw) { return 'int', raw }
	if looks_like_float(raw) { return 'float', raw }
	return 'string', raw
}

fn looks_like_int(s string) bool {
	if s.len == 0 { return false }
	mut i := 0
	if s[0] == `-` || s[0] == `+` { i = 1 }
	if i >= s.len { return false }
	for ; i < s.len; i++ {
		if s[i] < `0` || s[i] > `9` { return false }
	}
	return true
}

fn looks_like_float(s string) bool {
	if s.len == 0 { return false }
	mut i := 0
	mut saw_digit := false
	mut saw_dot := false
	mut saw_exp := false
	if s[0] == `-` || s[0] == `+` { i = 1 }
	for ; i < s.len; i++ {
		c := s[i]
		if c >= `0` && c <= `9` { saw_digit = true; continue }
		if c == `.` && !saw_dot && !saw_exp { saw_dot = true; continue }
		if (c == `e` || c == `E`) && saw_digit && !saw_exp {
			saw_exp = true
			if i + 1 < s.len && (s[i+1] == `+` || s[i+1] == `-`) { i++ }
			continue
		}
		return false
	}
	return saw_digit && (saw_dot || saw_exp)
}

// parse_text_or_string parses a quoted string at p.pos as a text
// node. Returns the TreeNode spanning the whole quoted form
// (including quotes) with `value` being the unquoted payload.
fn (mut p TreeParser) parse_text_or_string() TreeNode {
	start := p.pos
	qend := find_quote_end(p.src, p.pos)
	if qend < 0 {
		// Unterminated string — span to end of source.
		end := p.src.len
		val := unsafe { tos(&p.src[start + 1], end - start - 1) }.clone()
		p.pos = end
		return TreeNode{
			kind:       'text'
			value_kind: 'string'
			value_str:  val
			loc_start:  start
			loc_end:    end
		}
	}
	val := unsafe { tos(&p.src[start + 1], qend - start - 1) }.clone()
	p.pos = qend + 1
	return TreeNode{
		kind:       'text'
		value_kind: 'string'
		value_str:  val
		loc_start:  start
		loc_end:    qend + 1
	}
}

// parse_path scans a CXPath-shaped token starting with `/` at p.pos.
// Returns a `path`-kind node whose value is the rendered path text.
fn (mut p TreeParser) parse_path() TreeNode {
	start := p.pos
	// Span: leading `/`s, then identifier/path bytes; allow `/`, `.`,
	// `@`, `*`, ident bytes, and `:` (for axis::step), and `[` for
	// predicates (matched-bracket-skip).
	mut j := p.pos
	for j < p.src.len {
		c := p.src[j]
		if c == ` ` || c == `\t` || c == `\n` || c == `\r` { break }
		if c == `]` { break }
		if c == `[` {
			eb := find_matching_bracket(p.src, j)
			if eb < 0 { j = p.src.len; break }
			j = eb + 1
			continue
		}
		if c == `/` || c == `.` || c == `@` || c == `*` || c == `:`
		   || is_ident_byte_tree(c) {
			j++
			continue
		}
		break
	}
	value := unsafe { tos(&p.src[start], j - start) }.clone()
	p.pos = j
	return TreeNode{
		kind:       'path'
		value_kind: 'string'
		value_str:  value
		loc_start:  start
		loc_end:    j
	}
}

fn (mut p TreeParser) parse_atom_scalar() TreeNode {
	start := p.pos
	p.pos++ // consume `:`
	for p.pos < p.src.len && is_ident_byte_tree(p.src[p.pos]) { p.pos++ }
	name := unsafe { tos(&p.src[start + 1], p.pos - start - 1) }.clone()
	return TreeNode{
		kind:       'scalar'
		value_kind: 'atom'
		value_str:  name
		loc_start:  start
		loc_end:    p.pos
	}
}

fn (mut p TreeParser) parse_binding_scalar() TreeNode {
	start := p.pos
	p.pos++ // consume `$`
	for p.pos < p.src.len && (is_ident_byte_tree(p.src[p.pos])
	    || p.src[p.pos] == `/` || p.src[p.pos] == `@`
	    || p.src[p.pos] == `.`) {
		p.pos++
	}
	value := unsafe { tos(&p.src[start], p.pos - start) }.clone()
	return TreeNode{
		kind:       'scalar'
		value_kind: 'string'
		value_str:  value
		loc_start:  start
		loc_end:    p.pos
	}
}

fn (mut p TreeParser) parse_number_scalar() TreeNode {
	start := p.pos
	mut j := p.pos
	if j < p.src.len && (p.src[j] == `-` || p.src[j] == `+`) { j++ }
	for j < p.src.len && p.src[j] >= `0` && p.src[j] <= `9` { j++ }
	mut is_float := false
	if j < p.src.len && p.src[j] == `.` {
		is_float = true
		j++
		for j < p.src.len && p.src[j] >= `0` && p.src[j] <= `9` { j++ }
	}
	if j < p.src.len && (p.src[j] == `e` || p.src[j] == `E`) {
		is_float = true
		j++
		if j < p.src.len && (p.src[j] == `+` || p.src[j] == `-`) { j++ }
		for j < p.src.len && p.src[j] >= `0` && p.src[j] <= `9` { j++ }
	}
	raw := unsafe { tos(&p.src[start], j - start) }.clone()
	p.pos = j
	kind := if is_float { 'float' } else { 'int' }
	return TreeNode{
		kind:       'scalar'
		value_kind: kind
		value_str:  raw
		loc_start:  start
		loc_end:    j
	}
}

fn (mut p TreeParser) parse_ident_scalar() TreeNode {
	start := p.pos
	for p.pos < p.src.len && is_ident_byte_tree(p.src[p.pos]) {
		p.pos++
	}
	raw := unsafe { tos(&p.src[start], p.pos - start) }.clone()
	vk, vs := classify_bare_value(raw)
	return TreeNode{
		kind:       'scalar'
		value_kind: vk
		value_str:  vs
		loc_start:  start
		loc_end:    p.pos
	}
}

// find_matching_bracket returns the index of the `]` that closes the
// `[` at start_idx, accounting for nested brackets and string
// literals. Returns -1 if unbalanced.
fn find_matching_bracket(bs []u8, start_idx int) int {
	mut depth := 0
	mut i := start_idx
	mut in_str := u8(0)
	for i < bs.len {
		c := bs[i]
		if in_str != 0 {
			if c == `\\` && i + 1 < bs.len {
				i += 2
				continue
			}
			if c == in_str { in_str = 0 }
			i++
			continue
		}
		if c == `'` || c == `"` { in_str = c; i++; continue }
		if c == `[` { depth++ }
		else if c == `]` {
			depth--
			if depth == 0 { return i }
		}
		i++
	}
	return -1
}

// find_quote_end returns the index of the closing quote of the string
// starting at `start` (`bs[start]` is `'` or `"`). Honors `\\` escape.
// Returns -1 if unterminated.
fn find_quote_end(bs []u8, start int) int {
	if start >= bs.len { return -1 }
	q := bs[start]
	mut i := start + 1
	for i < bs.len {
		c := bs[i]
		if c == `\\` && i + 1 < bs.len { i += 2; continue }
		if c == q { return i }
		i++
	}
	return -1
}

// ── JSON emitter ─────────────────────────────────────────────────────

fn render_node(n TreeNode) string {
	mut out := []u8{cap: 128}
	emit_node(mut out, n)
	return out.bytestr()
}

fn emit_node(mut out []u8, n TreeNode) {
	out << `{`
	out << '"kind":"'.bytes()
	out << n.kind.bytes()
	out << `"`
	if n.kind == 'element' || n.kind == 'attribute' || n.kind == 'directive' {
		out << ',"name":'.bytes()
		out << json_quote_tree(n.name).bytes()
	}
	if n.kind == 'attribute' || n.kind == 'text' || n.kind == 'scalar'
	   || n.kind == 'path' {
		out << ',"value":'.bytes()
		out << render_value(n.value_kind, n.value_str).bytes()
	}
	out << ',"loc":{"start":'.bytes()
	out << n.loc_start.str().bytes()
	out << ',"end":'.bytes()
	out << n.loc_end.str().bytes()
	out << `}`
	if n.has_children {
		out << ',"children":['.bytes()
		for i, c in n.children {
			if i > 0 { out << `,` }
			emit_node(mut out, c)
		}
		out << `]`
	}
	out << `}`
}

// render_value emits one `value` field per the
// value_kind discriminator. Unknown kinds fall back to JSON string.
fn render_value(kind string, s string) string {
	match kind {
		'int', 'float' { return s }
		'bool' { return s } // already 'true' or 'false'
		'atom' { return json_quote_tree(':' + s) }
		else { return json_quote_tree(s) }
	}
}

// json_quote_tree returns a JSON-string-encoded representation of `s`,
// surrounded by `"`. Handles the four backslash-escapes mandated by
// RFC 8259 §7 plus the \uXXXX form for C0 controls.
fn json_quote_tree(s string) string {
	mut out := []u8{cap: s.len + 2}
	out << `"`
	for c in s {
		match c {
			`\\` { out << `\\`; out << `\\` }
			`"`  { out << `\\`; out << `"` }
			`\n` { out << `\\`; out << `n` }
			`\r` { out << `\\`; out << `r` }
			`\t` { out << `\\`; out << `t` }
			`\b` { out << `\\`; out << `b` }
			`\f` { out << `\\`; out << `f` }
			else {
				if c < 0x20 {
					hex := '0123456789abcdef'
					out << `\\`
					out << `u`
					out << `0`
					out << `0`
					out << hex[int(c >> 4)]
					out << hex[int(c & 0x0f)]
				} else {
					out << c
				}
			}
		}
	}
	out << `"`
	return out.bytestr()
}
