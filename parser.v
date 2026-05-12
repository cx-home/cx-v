module cx

import strconv

// ── Parser struct ─────────────────────────────────────────────────────────────

// max_recursion_depth bounds nesting in parse_element to prevent
// stack-overflow DoS on adversarial input. Default per
// spec/policies.md §5.4. Configurable in a future minor revision.
const max_recursion_depth = 64

struct Parser {
mut:
	src   []u8
	pos   int
	line  int
	col   int
	depth int  // current element-nesting depth; tracked by parse_element
	// declared_templates tracks `?def name …` declarations seen so far
	// during parsing. Used by parse_pi_or_decl to distinguish template-
	// call invocations `[?template-name args]` (parse as EvalDirective)
	// from foreign processing instructions like `[?php …]` (parse as
	// PI). Per spec/cxl.md §3.7 templates must be declared before use;
	// this set is populated as ?def directives are encountered. ADR
	// 0020 §D3 + §D6.
	declared_templates map[string]bool
}

fn new_parser(src string) Parser {
	return Parser{
		src:   src.bytes()
		pos:   0
		line:  1
		col:   1
		depth: 0
		declared_templates: map[string]bool{}
	}
}

// ── Position tracking ─────────────────────────────────────────────────────────

fn (p &Parser) peek() u8 {
	if p.pos < p.src.len {
		return p.src[p.pos]
	}
	return 0
}

fn (p &Parser) peek2() u8 {
	if p.pos + 1 < p.src.len {
		return p.src[p.pos + 1]
	}
	return 0
}

fn (p &Parser) at_end() bool {
	return p.pos >= p.src.len
}

fn (mut p Parser) advance() {
	if p.pos >= p.src.len { return }
	b := p.src[p.pos]
	p.pos++
	if b == `\n` {
		p.line++
		p.col = 1
	} else {
		p.col++
	}
}

fn (p &Parser) make_error(msg string) string {
	return '${p.line}:${p.col}: ${msg}'
}

// ── Whitespace ────────────────────────────────────────────────────────────────

fn (mut p Parser) skip_ws() {
	for !p.at_end() {
		b := p.peek()
		if b == ` ` || b == `\t` || b == `\r` || b == `\n` {
			p.advance()
		} else {
			break
		}
	}
}

// skip_ws_and_line_comments skips whitespace AND v3.4 line comments
// (# to end-of-line). Used at comment-eligible positions only:
// document top level, prolog, between root elements, and between
// element body items.
//
// NOT used inside DTD declarations like [!ATTLIST ...] where '#' is
// a syntax sentinel for #REQUIRED, #IMPLIED, #FIXED, #PCDATA. NOT
// used inside ElementMeta where '#' could conflict with future
// extensions. The disambiguation is by call site, per spec rule
// [30b] ("at comment-eligible positions").
fn (mut p Parser) skip_ws_and_line_comments() {
	for !p.at_end() {
		b := p.peek()
		if b == ` ` || b == `\t` || b == `\r` || b == `\n` {
			p.advance()
		} else if b == `#` {
			p.skip_line_comment()
		} else {
			break
		}
	}
}

// skip_line_comment consumes a line comment from '#' through the next
// '\n' (or end of input). The leading '#' must be the current position.
fn (mut p Parser) skip_line_comment() {
	// Consume '#'
	p.advance()
	for !p.at_end() {
		b := p.peek()
		if b == `\n` {
			break
		}
		p.advance()
	}
}

// read_line_comment_value consumes a line comment from '#' through the
// next '\n' and returns the comment body (text after '#', leading space
// trimmed, no trailing newline). The leading '#' must be the current
// position. Used at positions where the comment should be preserved as
// a CommentNode (vs skip_line_comment which discards it).
fn (mut p Parser) read_line_comment_value() string {
	p.advance() // consume '#'
	// Skip one leading space if present (cosmetic: `# value` round-trips
	// without the leading space accumulating each pass).
	if !p.at_end() && p.peek() == ` ` { p.advance() }
	mut s := []u8{}
	for !p.at_end() {
		b := p.peek()
		if b == `\n` { break }
		s << b
		p.advance()
	}
	return s.bytestr()
}

fn is_ws(b u8) bool {
	return b == ` ` || b == `\t` || b == `\r` || b == `\n`
}

// ── Public parse entry points ─────────────────────────────────────────────────

pub fn parse(src string) !Document {
	if src.contains('\n---\n') {
		return error('use parse_stream for multi-doc input')
	}
	mut p := new_parser(src)
	return p.parse_document()
}

pub fn parse_stream(src string) ![]Document {
	mut p := new_parser(src)
	mut docs := []Document{}
	for {
		p.skip_ws()
		if p.at_end() { break }
		doc := p.parse_document()!
		if doc.elements.len > 0 || doc.prolog.len > 0 || doc.doctype != none {
			docs << doc
		}
		p.skip_ws()
		if p.pos + 3 <= p.src.len && p.src[p.pos] == `-` && p.src[p.pos+1] == `-` && p.src[p.pos+2] == `-` {
			p.pos += 3
			p.col += 3
			// skip rest of separator line
			for !p.at_end() && p.src[p.pos] != `\n` {
				p.pos++
				p.col++
			}
		}
	}
	return docs
}

// ── ParseResult ───────────────────────────────────────────────────────────────

pub struct ParseResult {
pub mut:
	single   ?Document
	multi    ?[]Document
	is_multi bool
}

pub fn parse_cx(src string) !ParseResult {
	if src.contains('\n---\n') {
		docs := parse_stream(src)!
		return ParseResult{ multi: docs, is_multi: true }
	}
	mut p := new_parser(src)
	doc := p.parse_document()!
	return ParseResult{ single: doc, is_multi: false }
}

// ── Document parser ───────────────────────────────────────────────────────────

fn (mut p Parser) parse_document() !Document {
	mut prolog := []Node{}
	mut doctype := ?DoctypeDecl(none)
	mut elements := []Node{}

	p.skip_ws_and_line_comments()

	for {
		p.skip_ws_and_line_comments()
		if p.at_end() { break }
		if p.peek() != `[` { break }
		if p.is_prolog_node() {
			if p.is_doctype_node() {
				p.advance() // '['
				p.advance() // '!'
				p.read_name()! // "DOCTYPE"
				dt := p.parse_doctype_inner()!
				doctype = dt
			} else {
				n := p.parse_node()!
				if is_prolog_node_type(n) {
					prolog << n
				} else {
					elements << n
					break
				}
			}
		} else {
			break
		}
	}

	// v3.4 logfmt mode: if the first token after Prolog/Doctype is
	// `Name '='`, the entire document is a sequence of top-level
	// attributes (no element brackets). Wraps into a single synthetic
	// Element named `_` (the anonymous-record convention) so the rest
	// of the codebase, which assumes Documents contain Elements,
	// works unchanged.
	//
	// Only fires when no top-level Elements have been parsed yet
	// (elements is empty). Spec: grammar.ebnf [2].
	if elements.len == 0 && p.is_logfmt_start() {
		// v3.4 §9: each top-level newline-separated logfmt record
		// produces its own synthetic Element named '_'. Earlier
		// behavior merged all records into a single element with
		// last-write-wins attributes; that lost type fidelity per
		// record and made `cx --json` produce one object instead
		// of an array. Phase 7.56.
		for {
			p.skip_logfmt_inter_record()
			if p.at_end() { break }
			attrs := p.parse_logfmt_record()!
			if attrs.len > 0 {
				elements << Node(Element{ name: '_', attrs: attrs })
			}
		}
		mut doc := Document{ prolog: prolog, doctype: doctype, elements: elements }
		resolve_namespaces(mut doc)
		resolve_ids(doc)!
		return doc
	}

	for {
		p.skip_ws_and_line_comments()
		if p.at_end() { break }
		if p.pos + 3 <= p.src.len && p.src[p.pos] == `-` && p.src[p.pos+1] == `-` && p.src[p.pos+2] == `-` {
			break
		}
		n := p.parse_node()!
		elements << n
	}

	mut doc := Document{ prolog: prolog, doctype: doctype, elements: elements }
	resolve_namespaces(mut doc)
	resolve_ids(doc)!
	return doc
}

// peek_table_block_start returns true if the parser is positioned at
// `:table[` followed by a non-`]` byte (i.e., the start of a v3.4
// TableBlock per spec/grammar.ebnf [29]). Does not consume input.
fn (p &Parser) peek_table_block_start() bool {
	// Need at least: ':' 't' 'a' 'b' 'l' 'e' '[' x — 8 bytes
	if p.pos + 8 > p.src.len { return false }
	if p.src[p.pos] != `:` { return false }
	if p.src[p.pos + 1] != `t` { return false }
	if p.src[p.pos + 2] != `a` { return false }
	if p.src[p.pos + 3] != `b` { return false }
	if p.src[p.pos + 4] != `l` { return false }
	if p.src[p.pos + 5] != `e` { return false }
	if p.src[p.pos + 6] != `[` { return false }
	// `:table[]` (immediately closed) is not a TableBlock; fall back.
	if p.src[p.pos + 7] == `]` { return false }
	return true
}

// parse_table_header parses the column declarations between '[' and
// ']' in a TableBlock header. Returns the parsed columns. Caller
// has already consumed the opening '['.
fn (mut p Parser) parse_table_header() ![]TableColumn {
	mut cols := []TableColumn{}
	for {
		p.skip_ws()
		if p.at_end() { return error('${p.line}:${p.col}: unterminated :table header') }
		if p.peek() == `]` { break }
		if !is_name_start(p.peek()) {
			return error('${p.line}:${p.col}: expected column name in :table header')
		}
		// read_name() consumes ':' as part of the name token (needed for
		// namespace-prefixed identifiers like `xmlns:foo`), so a column
		// declaration `name:string` arrives here as a single token. Split
		// on the first colon to separate name from type. A token without
		// a colon is name-only (string default).
		full := p.read_name()!
		mut col_name := full
		mut col_type := ''
		if idx := full.index(':') {
			col_name = full[..idx]
			col_type = full[idx + 1..]
		}
		cols << TableColumn{ name: col_name, type_name: col_type }
	}
	if cols.len == 0 {
		return error('${p.line}:${p.col}: :table header must declare at least one column')
	}
	return cols
}

// parse_table_rows parses the data cells of a TableBlock until the
// closing ']'. Cells are grouped into rows of `cols.len` cells each.
// Cell parsing applies type-driven coercion for scalars (bare cells
// use the column's declared type; quoted cells are always string)
// or recognizes ADR 0017 collection-literal cells (`[a, b, c]`,
// `{k: v}`, `(a, b, c)`) per ADR 0018 §D4 + ADR 0017 §D1.
fn (mut p Parser) parse_table_rows(cols []TableColumn) ![][]TableCellValue {
	mut rows := [][]TableCellValue{}
	mut current := []TableCellValue{cap: cols.len}
	for {
		p.skip_ws_and_line_comments()
		if p.at_end() {
			return error('${p.line}:${p.col}: unterminated :table block')
		}
		if p.peek() == `]` { break }
		col_idx := current.len
		if col_idx >= cols.len {
			rows << current
			current = []TableCellValue{cap: cols.len}
			continue
		}
		col_type := cols[col_idx].type_name
		val := p.read_table_cell(col_type)!
		current << val
	}
	if current.len > 0 {
		if current.len != cols.len {
			return error('${p.line}:${p.col}: :table row has ${current.len} cells; expected ${cols.len}')
		}
		rows << current
	}
	return rows
}

// read_table_cell reads one cell value. Recognizes:
//   - Quoted strings: `'text'` / `'''text'''` → string scalar
//   - Array literals: `[a, b, c]` → ArrayNode (ADR 0017 §D1; the
//     trailing-comma form `[v,]` is required for single-element
//     arrays since `[v]` would parse as Element per §D1's comma-
//     marker disambiguator)
//   - Map literals: `{k: v}` → MapNode
//   - Sequence literals: `(a, b, c)` → SequenceNode
//   - Bare scalars: auto-typed via the column's declared type
//
// Collection-cell parsing per ADR 0018 §D4: the cell's host type
// is whatever ADR 0017 §D5 admits; the column's declared type (if
// `arr[T]` / `map[K, V]` / `seq[T]` per ADR 0017 §D15) informs
// downstream emitters but is not enforced at this layer.
fn (mut p Parser) read_table_cell(col_type string) !TableCellValue {
	b := p.peek()
	if b == `'` {
		// Quoted; check for triple-quoted form first.
		if p.pos + 3 <= p.src.len && p.src[p.pos] == `'`
			&& p.src[p.pos + 1] == `'` && p.src[p.pos + 2] == `'` {
			s := p.read_triple_quoted()!
			if s is TextNode { return TableCellValue((s as TextNode).value) }
			return TableCellValue('')
		}
		s := p.read_quoted_text()!
		return TableCellValue(s)
	}
	if b == `[` {
		// :table cell `[...]` always parses as an Array literal,
		// analogous to resolution 2.i for EvalDirective ArgArrays —
		// the cell context unambiguously requires Array. This makes
		// single-element arrays `[v]` work without forcing the
		// trailing-comma form `[v,]` at the source, and lets the
		// canonical-form emit per §D14 drop trailing commas cleanly.
		// Element-form `[name body]` is not a meaningful table cell
		// shape (§D4); parse_array_literal will produce an Array node
		// from whatever it finds between the brackets.
		p.advance() // consume '['
		node := p.parse_array_literal()!
		if node is ArrayNode {
			return TableCellValue(node as ArrayNode)
		}
		return error('${p.line}:${p.col}: :table cell starts with `[...]` but parse_array_literal did not return ArrayNode')
	}
	if b == `{` && p.peek_is_map_literal_at_brace() {
		node := p.parse_map_literal()!
		if node is MapNode {
			return TableCellValue(node as MapNode)
		}
		return error('${p.line}:${p.col}: :table cell starts with `{...}` but parse_map_literal did not return MapNode')
	}
	if b == `(` && p.peek_is_sequence_literal_at_paren() {
		node := p.parse_sequence_literal()!
		if node is SequenceNode {
			return TableCellValue(node as SequenceNode)
		}
		return error('${p.line}:${p.col}: :table cell starts with `(...)` but parse_sequence_literal did not return SequenceNode')
	}
	// Bare value — read until whitespace or `]`.
	start := p.pos
	for !p.at_end() {
		c := p.peek()
		if c == ` ` || c == `\t` || c == `\r` || c == `\n` || c == `]` {
			break
		}
		p.advance()
	}
	tok := p.src[start..p.pos].bytestr()
	if tok == 'null' {
		return TableCellValue(NullValue{})
	}
	// Type-driven coercion. Empty col_type defaults to string.
	if col_type == '' || col_type == 'string' || col_type == 's' {
		return TableCellValue(tok)
	}
	scalar := coerce_scalar(expand_type_alias(col_type), tok)
	return cell_value_from_scalar(scalar.value)
}

// is_logfmt_start performs lookahead to determine whether the next
// non-whitespace token is `Name '='`, indicating logfmt mode. Does
// not consume input.
fn (p &Parser) is_logfmt_start() bool {
	mut pos := p.pos
	for pos < p.src.len {
		b := p.src[pos]
		if b == ` ` || b == `\t` || b == `\r` || b == `\n` {
			pos++
			continue
		}
		break
	}
	if pos >= p.src.len { return false }
	if !is_name_start(p.src[pos]) { return false }
	pos++
	for pos < p.src.len && is_name_char(p.src[pos]) {
		pos++
	}
	if pos >= p.src.len { return false }
	return p.src[pos] == `=`
}

// parse_logfmt_record consumes one logfmt record — a sequence of
// `Name=Value` pairs separated by intra-line whitespace, terminated
// by end-of-line or end-of-input. Per v3.4 §9, each record becomes
// its own synthetic Element.
fn (mut p Parser) parse_logfmt_record() ![]Attribute {
	mut attrs := []Attribute{}
	for {
		// Intra-record whitespace: spaces and tabs only. A newline
		// terminates the record.
		for !p.at_end() {
			b := p.peek()
			if b == ` ` || b == `\t` || b == `\r` {
				p.advance()
			} else {
				break
			}
		}
		if p.at_end() || p.peek() == `\n` { break }
		// Line comments end the record (everything after `#` is
		// ignored, including the newline marker).
		if p.peek() == `#` {
			p.skip_line_comment()
			break
		}
		if !is_name_start(p.peek()) {
			return error('${p.line}:${p.col}: expected attribute name in logfmt document')
		}
		name := p.read_name()!
		if p.at_end() || p.peek() != `=` {
			return error('${p.line}:${p.col}: expected = after attribute name `${name}`')
		}
		p.advance() // consume '='
		val, dt := p.read_attr_value_typed()!
		attrs << Attribute{ name: name, value: val, data_type: dt }
	}
	return attrs
}

// skip_logfmt_inter_record advances past blank lines and full-line
// comments between records.
fn (mut p Parser) skip_logfmt_inter_record() {
	for !p.at_end() {
		b := p.peek()
		if b == `\n` || b == `\r` || b == ` ` || b == `\t` {
			p.advance()
		} else if b == `#` {
			p.skip_line_comment()
		} else {
			break
		}
	}
}

fn (p &Parser) is_prolog_node() bool {
	if p.pos >= p.src.len || p.src[p.pos] != `[` { return false }
	if p.pos + 1 >= p.src.len { return false }
	b1 := p.src[p.pos + 1]
	if b1 == `?` || b1 == `-` { return true }
	if b1 == `!` {
		if p.pos + 9 <= p.src.len {
			return p.src[p.pos+2..p.pos+9] == 'DOCTYPE'.bytes()
		}
	}
	return false
}

fn (p &Parser) is_doctype_node() bool {
	if p.pos >= p.src.len || p.src[p.pos] != `[` { return false }
	if p.pos + 1 >= p.src.len || p.src[p.pos+1] != `!` { return false }
	if p.pos + 9 <= p.src.len {
		return p.src[p.pos+2..p.pos+9] == 'DOCTYPE'.bytes()
	}
	return false
}

fn is_prolog_node_type(n Node) bool {
	return match n {
		XMLDeclNode, CXDirectiveNode, PINode, CommentNode { true }
		else { false }
	}
}

// ── Node dispatch ─────────────────────────────────────────────────────────────

fn (mut p Parser) parse_node() !Node {
	p.skip_ws()
	if p.at_end() { return error(p.make_error('expected node')) }
	b := p.peek()
	return match b {
		`[` { p.parse_bracket_node()! }
		`&` { p.parse_entity_ref()! }
		else { error(p.make_error('expected node')) }
	}
}

fn (mut p Parser) parse_bracket_node() !Node {
	p.advance() // consume '['
	if p.at_end() { return error(p.make_error('unexpected EOF after [')) }
	b := p.peek()
	// v3.6 (ADR 0017): empty `[]` is the empty ArrayLiteral [56b] in
	// expression position. Currently invalid in Element position (Name
	// required); the grammar's [50] rule unchanged. Detect ahead of the
	// sigil dispatch so it isn't routed by accident.
	if b == `]` {
		p.advance() // consume ']'
		return Node(ArrayNode{ items: []Node{} })
	}
	// v3.6 (ADR 0017 §D1): comma-marker disambiguation wins over the
	// non-`?` sigil dispatch — e.g. `[*, None]` is an Array literal
	// with the CXPath-wildcard sentinel `*` as its first slot, not an
	// alias element. `?`-prefixed forms (EvalDirective, Interpolation,
	// PI, CXDirective) keep absolute priority because their semantics
	// are unambiguous and the parser must never reroute them as
	// arrays (per §A commit 19075a5: "[?for ...,] never routes
	// through array detection").
	//
	// Structural sigils with opaque inner content also keep absolute
	// priority: `-` (block comment), `!` (declaration), `|` (block
	// content), `#` (raw text). Otherwise a comma inside an opaque
	// span — e.g. `[- comment, with, commas ]` — would be misread as
	// an Array literal with `-` (or `!`/`|`/`#`) as the first slot.
	is_opaque_sigil := b == `-` || b == `!` || b == `|` || b == `#`
	if b != `?` && !is_opaque_sigil && p.peek_is_array_literal() {
		return p.parse_array_literal()!
	}
	return match b {
		`?` { p.parse_pi_or_decl()! }
		`-` { p.parse_comment_or_md_element()! }
		`#` { p.parse_raw_text_or_md_heading()! }
		`!` { p.parse_decl()! }
		`*` { p.parse_alias_or_md_element()! }
		`|` { p.parse_block_content()! }
		`~` { p.parse_md_tilde_element()! }
		`^` { p.parse_md_caret_element()! }
		`_` { p.parse_md_underscore_element()! }
		`\`` { p.parse_md_backtick_element()! }
		`>` { p.parse_md_blockquote_element()! }
		else {
			p.parse_element()!
		}
	}
}

// normalize_doc_element_name is kept as identity — element names are case-sensitive in CX.
fn normalize_doc_element_name(name string) string {
	return name
}

// parse_comment_or_md_element handles [-...] (comment) vs [--- ...] (hr) and [- li item]
fn (mut p Parser) parse_comment_or_md_element() !Node {
	// peek ahead to see if this is --- (hr)
	// already consumed '[', now at '-'
	if p.pos + 2 < p.src.len && p.src[p.pos] == `-` && p.src[p.pos+1] == `-` && p.src[p.pos+2] == `-` {
		p.pos += 3
		p.col += 3
		// expect ]
		p.skip_ws()
		p.expect(`]`)!
		return Element{ name: 'hr' }
	}
	return p.parse_comment()!
}

// parse_raw_text_or_md_heading handles [# raw#] vs [# heading] and [## h2] etc.
fn (mut p Parser) parse_raw_text_or_md_heading() !Node {
	// already consumed '[', now at '#'
	// Count consecutive '#' chars to determine heading level
	mut level := 0
	mut saved_pos := p.pos
	mut saved_line := p.line
	mut saved_col := p.col
	for !p.at_end() && p.peek() == `#` {
		level++
		p.advance()
	}
	// Only treat as heading if followed by a space and level 1-6
	if level >= 1 && level <= 6 && !p.at_end() && p.peek() == ` ` {
		// Disambiguate [# heading] from [# raw text #]:
		// scan ahead at bracket-depth 0 for '#]' (raw text terminator)
		// If found before the closing ']', it's raw text.
		content_start := p.pos + 1 // position after the space
		mut scan := content_start
		mut depth := 0
		mut is_raw := false
		for scan < p.src.len {
			b := p.src[scan]
			if b == `[` {
				depth++
			} else if b == `#` && depth == 0 && scan + 1 < p.src.len && p.src[scan + 1] == `]` {
				is_raw = true
				break
			} else if b == `]` {
				if depth == 0 { break }
				depth--
			}
			scan++
		}
		if !is_raw {
			p.advance() // consume space
			items := p.parse_body(none)!
			p.expect(`]`)!
			return Element{ name: 'h${level}', items: items }
		}
	}
	// Restore and parse as raw text
	p.pos = saved_pos
	p.line = saved_line
	p.col = saved_col
	return p.parse_raw_text()!
}

// parse_alias_or_md_element handles [*name] alias vs [** bold] and [* italic]
fn (mut p Parser) parse_alias_or_md_element() !Node {
	// already consumed '[', now at '*'
	// Peek at the next character to distinguish [*name] (alias) from [* italic] and [** bold]
	// [*name] alias: first '*' followed immediately by a name-start char
	// [* italic]: '*' followed by space or text
	// [** bold]: '*' followed by '*'
	// [*** bold+italic]: '*' followed by '**'

	if p.pos + 1 < p.src.len {
		next := p.src[p.pos + 1]
		if next == `*` {
			// ** or ***
			p.advance() // consume first '*'
			p.advance() // consume second '*'
			if !p.at_end() && p.peek() == `*` {
				p.advance() // consume third '*'
				items := p.parse_body(none)!
				p.expect(`]`)!
				em_elem := Element{ name: 'em', items: items }
				return Element{ name: 'strong', items: [Node(em_elem)] }
			}
			// ** = strong
			items := p.parse_body(none)!
			p.expect(`]`)!
			return Element{ name: 'strong', items: items }
		}
		if next == ` ` || next == `\t` || next == `\n` || next == `]` {
			// [* text] = em
			p.advance() // consume '*'
			items := p.parse_body(none)!
			p.expect(`]`)!
			return Element{ name: 'em', items: items }
		}
		// [*name] = alias (name follows immediately after *)
		return p.parse_alias()!
	}
	// at end — treat as alias attempt
	return p.parse_alias()!
}

// parse_md_tilde_element handles [~~ del] and [~ sub]
fn (mut p Parser) parse_md_tilde_element() !Node {
	p.advance() // consume '~'
	if !p.at_end() && p.peek() == `~` {
		p.advance() // consume second '~'
		items := p.parse_body(none)!
		p.expect(`]`)!
		return Element{ name: 'del', items: items }
	}
	// single ~ = sub
	items := p.parse_body(none)!
	p.expect(`]`)!
	return Element{ name: 'sub', items: items }
}

// parse_md_caret_element handles [^ sup]
fn (mut p Parser) parse_md_caret_element() !Node {
	p.advance() // consume '^'
	items := p.parse_body(none)!
	p.expect(`]`)!
	return Element{ name: 'sup', items: items }
}

// parse_md_underscore_element handles [__ u]
fn (mut p Parser) parse_md_underscore_element() !Node {
	p.advance() // consume '_'
	if !p.at_end() && p.peek() == `_` {
		p.advance() // consume second '_'
		items := p.parse_body(none)!
		p.expect(`]`)!
		return Element{ name: 'u', items: items }
	}
	// single _ is not a known MD shorthand — error
	return error(p.make_error('unknown element starting with _'))
}

// parse_md_backtick_element handles [` code]
fn (mut p Parser) parse_md_backtick_element() !Node {
	p.advance() // consume '`'
	if !p.at_end() && p.peek() == `\`` {
		p.advance() // consume second '`'
		if !p.at_end() && p.peek() == `\`` {
			p.advance() // consume third '`'
			// ``` fenced code block — read lang attr if present
			mut attrs := []Attribute{}
			p.skip_ws()
			// check for lang:xxx
			if !p.at_end() && p.peek() != `]` && p.peek() != `[` && p.peek() != `|` {
				if p.pos + 5 <= p.src.len && p.src[p.pos..p.pos+5] == 'lang:'.bytes() {
					p.pos += 5
					p.col += 5
					lang := p.read_token()!
					attrs << Attribute{ name: 'lang', value: ScalarValue(lang), data_type: none }
				}
			}
			// parse block content [| ... |] style or direct body
			p.skip_ws()
			items := p.parse_body(none)!
			p.expect(`]`)!
			return Element{ name: 'code', attrs: attrs, items: items }
		}
		// double backtick — not standard, treat as unknown
		return error(p.make_error('unknown element starting with ``'))
	}
	// single backtick = inline code
	items := p.parse_body(none)!
	p.expect(`]`)!
	return Element{ name: 'code', items: items }
}

// parse_md_blockquote_element handles [> blockquote]
fn (mut p Parser) parse_md_blockquote_element() !Node {
	p.advance() // consume '>'
	p.skip_ws()
	items := p.parse_body(none)!
	p.expect(`]`)!
	return Element{ name: 'blockquote', items: items }
}

// ── [?...] PI, XMLDecl, CXDirective ──────────────────────────────────────────

fn (mut p Parser) parse_pi_or_decl() !Node {
	p.advance() // consume '?'
	// v3.5 (ADR 0016): `[?=EXPR]` is the CXL Interpolation form
	// (grammar [58]). EXPR is captured opaquely with bracket
	// balancing; the CXL evaluator at v0.7.0+ parses it as CXPath.
	if !p.at_end() && p.peek() == `=` {
		p.advance() // consume '='
		return p.parse_interpolation()!
	}
	target := p.read_name()!
	if is_cxl_eval_name(target) || (target in p.declared_templates) {
		// v3.5 (ADR 0016): `[?Name ...]` for reserved EvalNames is
		// the CXL EvalDirective form (grammar [59]).
		// ADR 0020: also route declared `?def` template names so
		// invocations `[?template-name args]` parse as EvalDirective
		// rather than falling through to PI.
		return p.parse_eval_directive(target)!
	}
	return match target {
		'xml' { p.parse_xml_decl()! }
		'cx'  { p.parse_cx_directive()! }
		else  { p.parse_pi_body(target)! }
	}
}

// is_cxl_eval_name reports whether name is a CXL EvalName reserved at
// v0.6.0 (grammar [59a]). The set is closed per CXL spec version per
// ADR 0016 R4 — implementations parse all listed names as EvalDirective
// nodes; evaluators dispatch the subset their declared CXL version
// supports and error on the rest.
//
// Control-flow directives (CXL 1.0, spec/cxl.md §3): `if`, `for`,
// `with`, `cond`, `include`, `def`, `use`.
// Built-in filter directives (CXL 1.0, spec/cxl.md §4): the frozen
// filter set is reserved as EvalNames because filter invocations use
// the `?`-prefixed bracket form (`[?upper x]`, `[?trim x]`).
// CXL 3.1 control-flow (v0.9.0+): `let`, `fn`, `match`, `try`.
fn is_cxl_eval_name(name string) bool {
	return match name {
		// CXL 1.0 control-flow
		'if', 'for', 'with', 'cond', 'include', 'def', 'use',
		// CXL 1.0 string filters (§4.1)
		'upper', 'lower', 'trim', 'length', 'concat', 'join', 'replace',
		// CXL 1.0 numeric filters (§4.2)
		'abs', 'round', 'format-decimal', 'format-percent',
		// CXL 1.0 sequence filters (§4.3)
		'empty', 'first', 'last', 'rest', 'take', 'drop', 'reverse',
		'distinct', 'where',
		// CXL 1.0 temporal filters (§4.4)
		'format-date', 'format-datetime',
		// CXL 1.0 type filters (§4.5)
		'type-of', 'default',
		// CXL 1.0 encoding filters (§4.6)
		'escape-html', 'escape-url', 'raw',
		// CXL 3.1 control-flow
		'let', 'fn', 'match', 'try' { true }
		else { false }
	}
}

// parse_interpolation reads the body of `[?=EXPR]`. The expression is
// captured as opaque text with internal `[`/`]` required to balance,
// per grammar [58a] / [58b]. The captured text is parsed as CXPath by
// the CXL evaluator at v0.7.0+; the v0.6.0 parser only preserves it.
fn (mut p Parser) parse_interpolation() !Node {
	mut s := []u8{}
	mut depth := 0
	for {
		if p.at_end() { return error(p.make_error('unterminated [?= interpolation')) }
		b := p.peek()
		if b == `[` {
			depth++
			s << b
			p.advance()
		} else if b == `]` {
			if depth == 0 { break }
			depth--
			s << b
			p.advance()
		} else {
			s << b
			p.advance()
		}
	}
	p.expect(`]`)!
	return InterpolationNode{ expr: s.bytestr().trim_space() }
}

// parse_eval_directive parses a `[?Name ...]` CXL evaluation directive
// (grammar [59], post-ADR-0017 §D7 positional + §D23 labeled).
//
// Three surface forms admitted:
//
//   1. Empty body:                  `[?Name]`
//   2. Positional (D7, canonical):  `[?Name [arg1, arg2, ...]]`
//   3. Labeled (D23, parser alias): `[?Name bare-head* :slot val ...]`
//
// All three produce the same EvalDirectiveNode AST shape — items[0] is
// the ArgArray (an ArrayNode) carrying the positional slots; labeled
// form desugars to positional via desugar_labeled_to_positional. See
// ADR 0017 §D23 per-directive label tables for slot mapping.
//
// `?def` backward-compat (ADR 0020 §D4 / ADR 0017 §D7 amendment
// 2026-05-12): legacy 2-slot positional `[?def [name, body]]` auto-
// expands to 3-slot `[?def [name, [], body]]` with empty params.
//
// `[?cx …]` is NOT handled here — it's a CXDirective (config), parsed
// separately via parse_cx_directive. Filter directives (`[?upper …]`,
// `[?trim …]`, etc.) are EvalDirectives and use the same uniform
// positional shape; labeled form is not defined for filters.
fn (mut p Parser) parse_eval_directive(name string) !Node {
	mut items := []Node{}
	p.skip_ws_and_line_comments()
	if p.at_end() {
		return error(p.make_error('unterminated eval directive `[?${name}`'))
	}
	if p.peek() == `]` {
		p.advance()
		return EvalDirectiveNode{ name: name, attrs: []Attribute{}, items: items }
	}
	if p.peek() == `[` {
		// Positional form (ADR 0017 §D7)
		p.advance() // consume '['
		arr := p.parse_array_literal()!
		items << arr
		// ?def 2→3 slot backward-compat auto-expansion
		items = maybe_expand_def_2_to_3(name, items)
		p.skip_ws_and_line_comments()
		p.expect(`]`)!
		record_declared_template(mut p, name, items)
		return EvalDirectiveNode{ name: name, attrs: []Attribute{}, items: items }
	}
	// Labeled form (ADR 0017 §D23)
	arg_array := p.parse_labeled_form(name)!
	items << Node(arg_array)
	p.skip_ws_and_line_comments()
	p.expect(`]`)!
	record_declared_template(mut p, name, items)
	return EvalDirectiveNode{ name: name, attrs: []Attribute{}, items: items }
}

// record_declared_template extracts the template name from a `?def`
// directive's parsed ArgArray and registers it on the Parser so
// subsequent `[?<name> args]` invocations parse as EvalDirective
// (rather than falling through to PI). Per ADR 0020 §D3 + ADR 0017
// §D7 (?def is 3-slot [name, params, body] with legacy 2-slot
// auto-expanded). No-op for directives other than ?def.
fn record_declared_template(mut p Parser, directive_name string, items []Node) {
	if directive_name != 'def' { return }
	if items.len == 0 { return }
	arg_array := items[0]
	if arg_array !is ArrayNode { return }
	arr_items := (arg_array as ArrayNode).items
	if arr_items.len == 0 { return }
	// Slot 0 is the template name (TextNode/ScalarNode/Element-single-name).
	name_node := arr_items[0]
	tmpl_name := match name_node {
		TextNode   { (name_node as TextNode).value.trim_space() }
		ScalarNode { scalar_value_str((name_node as ScalarNode).value).trim_space() }
		Element    {
			el := name_node as Element
			if el.attrs.len == 0 && el.items.len == 0 { el.name } else { '' }
		}
		else       { '' }
	}
	if tmpl_name != '' {
		p.declared_templates[tmpl_name] = true
	}
}

// maybe_expand_def_2_to_3 implements the ADR 0017 §D7 amendment
// (2026-05-12) backward-compat rule: legacy 2-slot `[?def [name, body]]`
// auto-expands to 3-slot `[?def [name, [], body]]` with empty params.
// No-op for other directives or for already-3-slot ?def.
fn maybe_expand_def_2_to_3(name string, items []Node) []Node {
	if name != 'def' { return items }
	if items.len != 1 { return items }
	arr := items[0]
	if arr !is ArrayNode { return items }
	arr_items := (arr as ArrayNode).items
	if arr_items.len != 2 { return items }
	empty_params := Node(ArrayNode{ items: []Node{} })
	expanded := ArrayNode{ items: [arr_items[0], empty_params, arr_items[1]] }
	return [Node(expanded)]
}

// LabeledSlotEntry is one `:label value` pair within a labeled-form
// EvalDirective per ADR 0017 §D23.
struct LabeledSlotEntry {
	name  string
	value Node
}

// parse_labeled_form parses the labeled alternative to ArgArray per
// ADR 0017 §D23: zero or more bare leading items followed by zero or
// more `:label value` slots.
//
// The bare-head region is consumed by parse_labeled_slot_body, which
// handles text-buf coalescing of multi-token expressions (`@stock > 0`
// collapses to one TextNode) and emits structural nodes (quoted
// strings, array literals, nested directives) as separate items. The
// resulting flat list IS the bare-head positional-arg list — each
// item becomes one slot in the desugared ArgArray.
//
// Returns the desugared positional ArgArray (an ArrayNode) ready to
// be wrapped in EvalDirectiveNode.items.
fn (mut p Parser) parse_labeled_form(name string) !ArrayNode {
	// Parse all bare-head content as one slot-body (terminates at
	// the first `:label` or `]`). Each item in the result is one
	// positional bare-head arg per the directive's documented shape.
	bare_head := p.parse_labeled_slot_body()!
	mut labels := []LabeledSlotEntry{}
	for !p.at_end() {
		p.skip_ws_and_line_comments()
		if p.at_end() {
			return error(p.make_error('unterminated labeled directive `[?${name}`'))
		}
		if p.peek() == `]` { break }
		if p.peek_is_slot_label() {
			label_name := p.parse_slot_label()!
			p.skip_ws_and_line_comments()
			value := p.parse_labeled_slot_value()!
			labels << LabeledSlotEntry{ name: label_name, value: value }
			continue
		}
		// parse_labeled_slot_body terminates at `]` or slot-label; any
		// other content here would have been consumed by it. Reaching
		// this point means a structural error — most likely a bare
		// item appearing between two slot labels.
		return error(p.make_error('W016: bare item after labeled slot in [?${name} ...] (ADR 0017 §D23 — labeled form admits bare-head before labels only)'))
	}
	return desugar_labeled_to_positional(name, bare_head, labels) or {
		return error(p.make_error('cxl: ${err.msg()}'))
	}
}

// peek_is_slot_label reports whether the current position is a slot
// label `:` followed by a lowercase ASCII letter (per grammar [59d]
// SlotLabel rule). Used to distinguish slot labels from CXPath axis
// separators `::` and other `:` usages.
fn (p Parser) peek_is_slot_label() bool {
	if p.pos + 1 >= p.src.len { return false }
	if p.src[p.pos] != `:` { return false }
	next := p.src[p.pos+1]
	return next >= `a` && next <= `z`
}

// parse_slot_label consumes `:identifier` per grammar [59d] SlotLabel.
// Identifier is `[a-z][a-z0-9-]*` — lowercase + digits + hyphens.
// Underscores and camelCase are W020 errors.
fn (mut p Parser) parse_slot_label() !string {
	p.advance() // consume ':'
	if p.at_end() {
		return error(p.make_error('expected slot-label identifier after `:`'))
	}
	first := p.peek()
	if !(first >= `a` && first <= `z`) {
		return error(p.make_error('W020: slot label must start with lowercase letter, got `${first.ascii_str()}`'))
	}
	mut s := []u8{}
	for !p.at_end() {
		b := p.peek()
		if (b >= `a` && b <= `z`) || (b >= `0` && b <= `9`) || b == `-` {
			s << b
			p.advance()
		} else if b == `_` || (b >= `A` && b <= `Z`) {
			return error(p.make_error('W020: slot label `:${s.bytestr()}${b.ascii_str()}...` uses underscore or camelCase; use lowercase + hyphen (ADR 0017 §D25)'))
		} else {
			break
		}
	}
	if s.len == 0 {
		return error(p.make_error('expected slot-label identifier after `:`'))
	}
	return s.bytestr()
}

// parse_labeled_slot_value parses one slot value within a labeled-form
// EvalDirective. Supports the same structural items as collection
// slots (Array/Sequence/Map literals, nested directives via [?…],
// elements, quoted strings) plus bare-text expressions / scalars,
// **including mixed text + nested-bracket content** like HTML
// fragments `<li>[?=v/@sku]</li>`. Terminates at the next `:label`
// (slot boundary) or the directive's closing `]`. Single-item runs
// return their lone node; multi-item runs wrap in SequenceNode.
fn (mut p Parser) parse_labeled_slot_value() !Node {
	items := p.parse_labeled_slot_body()!
	if items.len == 0 {
		return error(p.make_error('expected slot value, got empty'))
	}
	if items.len == 1 {
		return items[0]
	}
	return Node(SequenceNode{ items: items })
}

// parse_labeled_slot_body consumes the contents of one labeled-form
// slot. Mirrors parse_collection_slot_body's structure (text-buf
// coalescing of bare tokens, structured-node dispatch on bracket /
// paren / brace / quote / ampersand introducers) but with the
// terminator set adjusted: stops at `:` followed by a lowercase
// identifier (next slot label) or `]` (end of directive).
fn (mut p Parser) parse_labeled_slot_body() ![]Node {
	mut items := []Node{}
	mut text_buf := []u8{}
	mut has_child := false
	mut after_non_text := false
	for {
		if p.at_end() { break }
		had_ws := is_ws(p.peek())
		p.skip_ws_and_line_comments()
		if p.at_end() { break }
		b := p.peek()
		if b == `]` { break }
		if b == `:` && p.peek_is_slot_label() { break }

		if b == `[` {
			has_child = true
			if had_ws && text_buf.len > 0 { text_buf << ` ` }
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			child := p.parse_bracket_node()!
			items << child
			after_non_text = true
			continue
		}

		if b == `'` || b == `"` {
			if had_ws && text_buf.len > 0 { text_buf << ` ` }
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			if p.pos + 3 <= p.src.len && p.src[p.pos] == `'`
				&& p.src[p.pos+1] == `'` && p.src[p.pos+2] == `'` {
				n := p.read_triple_quoted()!
				items << n
			} else {
				quoted := p.read_quoted_text()!
				items << TextNode{ value: quoted }
			}
			after_non_text = true
			continue
		}

		if b == `(` && p.peek_is_sequence_literal_at_paren() {
			if had_ws && text_buf.len > 0 { text_buf << ` ` }
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			items << p.parse_sequence_literal()!
			after_non_text = true
			continue
		}

		if b == `{` && p.peek_is_map_literal_at_brace() {
			if had_ws && text_buf.len > 0 { text_buf << ` ` }
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			items << p.parse_map_literal()!
			after_non_text = true
			continue
		}

		if b == `&` {
			if had_ws {
				if text_buf.len > 0 || after_non_text { text_buf << ` ` }
			}
			n := p.parse_amp_node()!
			match n {
				TextNode {
					text_buf << n.value.bytes()
					after_non_text = false
				}
				else {
					if text_buf.len > 0 {
						items << TextNode{ value: text_buf.bytestr() }
						text_buf = []u8{}
					}
					items << n
					after_non_text = true
				}
			}
			continue
		}

		tok := p.read_labeled_slot_token()!
		if text_buf.len > 0 {
			if had_ws { text_buf << ` ` }
		} else if after_non_text && had_ws {
			text_buf << ` `
		}
		text_buf << tok.bytes()
		after_non_text = false
	}

	if text_buf.len > 0 {
		text_val := text_buf.bytestr()
		// Single bare-token slot — autotype if the buffer is exactly
		// one scalar literal.
		if !has_child && items.len == 0 {
			if scalar := try_autotype(text_val) {
				items << scalar
				return items
			}
		}
		items << TextNode{ value: text_val }
	}

	return items
}

// read_labeled_slot_token reads one bare-text token inside a labeled-
// form slot. Terminates at slot boundaries (`:` followed by lowercase,
// `]`), whitespace, and at the introducers handled by the outer slot
// loop (`[` `(` `{` `'` `"` `&`).
fn (mut p Parser) read_labeled_slot_token() !string {
	mut s := []u8{}
	for !p.at_end() {
		b := p.peek()
		if is_ws(b) || b == `]` { break }
		if b == `:` && p.peek_is_slot_label() { break }
		if b == `[` || b == `'` || b == `"` || b == `&` { break }
		if b == `(` && p.peek_is_sequence_literal_at_paren() { break }
		if b == `{` && p.peek_is_map_literal_at_brace() { break }
		s << b
		p.advance()
	}
	if s.len == 0 {
		return error(p.make_error('expected token in labeled slot'))
	}
	return s.bytestr()
}

// desugar_labeled_to_positional maps a labeled-form parse result to
// the directive's canonical positional ArgArray per ADR 0017 §D23
// per-directive label tables (spec/cxl.md §3.0.1).
//
// For directives outside the known control-flow set (filters, user-
// defined templates per ADR 0020, and any names the evaluator
// dispatches dynamically), bare-head-only labeled invocations
// `[?Name arg1 arg2]` pass through as a positional ArgArray of the
// bare-head items. Labels are unknown to these directives and remain
// a parse error (W021). This makes `[?upper 'hi']` and `[?template-name
// 'a' 'b']` both parse cleanly as the parser-level alias to their
// positional `[?Name ['hi']]` / `[?Name ['a', 'b']]` form.
fn desugar_labeled_to_positional(name string, bare_head []Node, labels []LabeledSlotEntry) !ArrayNode {
	return match name {
		'if'    { desugar_if_labeled(bare_head, labels)! }
		'for'   { desugar_for_labeled(bare_head, labels)! }
		'with'  { desugar_with_labeled(bare_head, labels)! }
		'def'   { desugar_def_labeled(bare_head, labels)! }
		'use'   { desugar_use_labeled(bare_head, labels)! }
		else {
			// Generic pass-through for filters / templates / unknown.
			// Labels are W021 errors; bare-head-only becomes ArgArray.
			if labels.len > 0 {
				return error('W021: directive [?${name}] does not define labeled slots; use positional [?${name} [...]] or bare-args [?${name} arg1 arg2] (ADR 0017 §D23)')
			}
			ArrayNode{ items: bare_head.clone() }
		}
	}
}

fn desugar_if_labeled(bare_head []Node, labels []LabeledSlotEntry) !ArrayNode {
	// [?if cond :then a :else b]  →  [?if [cond, a, b]]
	// [?if cond :then a]          →  [?if [cond, a]]      (no :else)
	if bare_head.len != 1 {
		return error('[?if] labeled form requires exactly 1 bare-head item (cond), got ${bare_head.len}')
	}
	mut then_value := Node(SequenceNode{ items: []Node{} })
	mut else_value := Node(SequenceNode{ items: []Node{} })
	mut has_then := false
	mut has_else := false
	for lbl in labels {
		match lbl.name {
			'then' {
				if has_then { return error('[?if] duplicate :then slot') }
				then_value = lbl.value
				has_then = true
			}
			'else' {
				if has_else { return error('[?if] duplicate :else slot') }
				else_value = lbl.value
				has_else = true
			}
			else {
				return error('W021: unknown slot label `:${lbl.name}` on [?if]; expected :then or :else')
			}
		}
	}
	if !has_then {
		return error('W017: [?if] labeled form requires :then slot')
	}
	if has_else {
		return ArrayNode{ items: [bare_head[0], then_value, else_value] }
	}
	return ArrayNode{ items: [bare_head[0], then_value] }
}

fn desugar_for_labeled(bare_head []Node, labels []LabeledSlotEntry) !ArrayNode {
	// [?for v :in xs :return body]  →  [?for [v, xs, body]]
	if bare_head.len != 1 {
		return error('[?for] labeled form requires exactly 1 bare-head item (var), got ${bare_head.len}')
	}
	mut iter := Node(SequenceNode{ items: []Node{} })
	mut body := Node(SequenceNode{ items: []Node{} })
	mut has_in := false
	mut has_return := false
	for lbl in labels {
		match lbl.name {
			'in' {
				if has_in { return error('[?for] duplicate :in slot') }
				iter = lbl.value
				has_in = true
			}
			'return' {
				if has_return { return error('[?for] duplicate :return slot') }
				body = lbl.value
				has_return = true
			}
			else {
				return error('W021: unknown slot label `:${lbl.name}` on [?for]; expected :in or :return')
			}
		}
	}
	if !has_in    { return error('W017: [?for] labeled form requires :in slot') }
	if !has_return { return error('W017: [?for] labeled form requires :return slot') }
	return ArrayNode{ items: [bare_head[0], iter, body] }
}

fn desugar_with_labeled(bare_head []Node, labels []LabeledSlotEntry) !ArrayNode {
	// [?with ctx :return body]  →  [?with [ctx, body]]
	if bare_head.len != 1 {
		return error('[?with] labeled form requires exactly 1 bare-head item (context), got ${bare_head.len}')
	}
	mut body := Node(SequenceNode{ items: []Node{} })
	mut has_return := false
	for lbl in labels {
		match lbl.name {
			'return' {
				if has_return { return error('[?with] duplicate :return slot') }
				body = lbl.value
				has_return = true
			}
			else {
				return error('W021: unknown slot label `:${lbl.name}` on [?with]; expected :return')
			}
		}
	}
	if !has_return { return error('W017: [?with] labeled form requires :return slot') }
	return ArrayNode{ items: [bare_head[0], body] }
}

fn desugar_def_labeled(bare_head []Node, labels []LabeledSlotEntry) !ArrayNode {
	// [?def name :body body]              →  [?def [name, [], body]]
	// [?def name :params [v] :body body]  →  [?def [name, [v], body]]
	if bare_head.len != 1 {
		return error('[?def] labeled form requires exactly 1 bare-head item (name), got ${bare_head.len}')
	}
	mut params := Node(ArrayNode{ items: []Node{} })
	mut body := Node(SequenceNode{ items: []Node{} })
	mut has_body := false
	mut has_params := false
	for lbl in labels {
		match lbl.name {
			'params' {
				if has_params { return error('[?def] duplicate :params slot') }
				// Normalize :params value into an ArrayNode of identifiers.
				// Accepted shapes:
				//   :params [a, b]   → ArrayNode (canonical)
				//   :params [v,]     → ArrayNode (trailing-comma single)
				//   :params [v]      → Element (D1 disambiguator) — coerce
				//                       to 1-element ArrayNode of `v`
				//   :params v        → TextNode / ScalarNode bare name —
				//                       coerce to 1-element ArrayNode
				params = normalize_params_slot(lbl.value) or {
					return error('[?def] :params: ${err.msg()}')
				}
				has_params = true
			}
			'body' {
				if has_body { return error('[?def] duplicate :body slot') }
				body = lbl.value
				has_body = true
			}
			else {
				return error('W021: unknown slot label `:${lbl.name}` on [?def]; expected :params or :body')
			}
		}
	}
	if !has_body { return error('W017: [?def] labeled form requires :body slot') }
	return ArrayNode{ items: [bare_head[0], params, body] }
}

// normalize_params_slot coerces a `:params` slot value to a canonical
// ArrayNode of identifier nodes. Handles the natural single-element
// forms (`[v]` parses as Element, `v` parses as TextNode) so users
// aren't forced into the trailing-comma `[v,]` form for the common
// 1-param case. Multi-param uses ArrayNode directly (`[a, b]`).
fn normalize_params_slot(value Node) !Node {
	if value is ArrayNode {
		return value
	}
	if value is Element {
		el := value as Element
		// Single-name Element `[v]` — empty attrs, empty body, bare name
		if el.attrs.len == 0 && el.items.len == 0 && el.name != '' {
			return Node(ArrayNode{ items: [Node(TextNode{ value: el.name })] })
		}
		return error('[v] form expects single bare identifier; got element with body or attributes')
	}
	if value is TextNode {
		tn := value as TextNode
		t := tn.value.trim_space()
		if t == '' {
			return error('empty identifier')
		}
		return Node(ArrayNode{ items: [Node(TextNode{ value: t })] })
	}
	if value is ScalarNode {
		return Node(ArrayNode{ items: [value] })
	}
	return error('expected Array of identifiers, single identifier, or Element-form `[name]`, got ${typeof(value).name}')
}

fn desugar_use_labeled(bare_head []Node, labels []LabeledSlotEntry) !ArrayNode {
	// [?use name :ctx ctx]  →  [?use [name, ctx]]
	// [?use name]           →  [?use [name]]            (no :ctx)
	if bare_head.len != 1 {
		return error('[?use] labeled form requires exactly 1 bare-head item (name), got ${bare_head.len}')
	}
	mut ctx_value := Node(SequenceNode{ items: []Node{} })
	mut has_ctx := false
	for lbl in labels {
		match lbl.name {
			'ctx' {
				if has_ctx { return error('[?use] duplicate :ctx slot') }
				ctx_value = lbl.value
				has_ctx = true
			}
			else {
				return error('W021: unknown slot label `:${lbl.name}` on [?use]; expected :ctx')
			}
		}
	}
	if has_ctx {
		return ArrayNode{ items: [bare_head[0], ctx_value] }
	}
	return ArrayNode{ items: [bare_head[0]] }
}

// read_attr_with_optional_body reads an attribute value at the
// post-`=` position. If the value begins with `[`, the production is
// BracketBody (grammar [55c]): a parsed body sequence stored in
// `Attribute.body`. Otherwise the existing BareValue/QuotedText
// auto-typed scalar path applies via read_attr_value_typed.
fn (mut p Parser) read_attr_with_optional_body(name string) !Attribute {
	if p.at_end() { return error(p.make_error('expected attr value')) }
	if p.peek() == `[` {
		p.advance() // consume '['
		body_items := p.parse_body(none)!
		p.expect(`]`)!
		return Attribute{
			name: name
			value: ScalarValue('')
			data_type: ?ScalarType(none)
			body: ?[]Node(body_items)
		}
	}
	val, dt := p.read_attr_value_typed()!
	return Attribute{ name: name, value: val, data_type: dt }
}

fn (mut p Parser) parse_xml_decl() !Node {
	attrs := p.read_attr_list_until(`]`)!
	p.expect(`]`)!
	version := find_attr_value(attrs, 'version') or { '1.0' }
	encoding := find_attr_value(attrs, 'encoding')
	standalone := find_attr_value(attrs, 'standalone')
	return XMLDeclNode{ version: version, encoding: encoding, standalone: standalone }
}

fn find_attr_value(attrs []Attribute, name string) ?string {
	for a in attrs {
		if a.name == name {
			return a.str_value()
		}
	}
	return none
}

fn (mut p Parser) parse_cx_directive() !Node {
	attrs := p.read_directive_attr_list_until(`]`)!
	// v0.6.0 — optional `&anchor` after the attr list, then optional
	// child nodes (parsed identically to element content). Used by
	// `[?cx frag &name [body :TYPE :flags]]` per spec/schema.md §8.
	mut anchor := ?string(none)
	p.skip_ws()
	if !p.at_end() && p.peek() == `&` {
		p.advance() // consume `&`
		aname := p.read_name()!
		anchor = ?string(aname)
	}
	mut items := []Node{}
	p.skip_ws()
	for !p.at_end() && p.peek() != `]` {
		items << p.parse_node()!
		p.skip_ws()
	}
	p.expect(`]`)!
	return CXDirectiveNode{ attrs: attrs, anchor: anchor, items: items }
}

// read_directive_attr_list_until accepts both keyed (`name=value`) and
// positional (`name` alone) forms. Positional names land as Attribute
// entries with an empty value, which lets `[?cx schema-of server]` and
// `[?cx schema-mode open]` parse uniformly with `[?cx schema=path]` and
// `[?cx lint-disable=L001]`. Schema directive consumers read the first
// positional attr as the directive name and subsequent positional
// attrs as args.
fn (mut p Parser) read_directive_attr_list_until(stop u8) ![]Attribute {
	mut attrs := []Attribute{}
	for {
		p.skip_ws()
		if p.at_end() || p.peek() == stop { break }
		// v0.6.0 — stop on `&` (anchor) or `[` (nested directive body)
		// so the caller can parse them as a separate phase. Used by
		// `[?cx frag &name [body ...]]`.
		if p.peek() == `&` || p.peek() == `[` { break }
		name := p.read_name()!
		// Don't skip whitespace before `=` — `name = value` with spaces
		// around `=` isn't valid attr syntax; whitespace separates
		// positional tokens from the next directive arg.
		if !p.at_end() && p.peek() == `=` {
			p.advance()
			if !p.at_end() && p.peek() == `[` {
				// v3.5 (ADR 0016): BracketBody attribute value
				// `name=[BodyItem*]`. Grammar [55c]. Permitted on
				// any attribute (including CXDirective attrs) for
				// uniform parsing; inert outside CXL contexts.
				p.advance() // consume '['
				body_items := p.parse_body(none)!
				p.expect(`]`)!
				attrs << Attribute{
					name: name
					value: ScalarValue('')
					data_type: none
					body: ?[]Node(body_items)
				}
			} else {
				value := p.read_attr_value()!
				attrs << Attribute{ name: name, value: ScalarValue(value), data_type: none }
			}
		} else {
			attrs << Attribute{ name: name, value: ScalarValue(''), data_type: none }
		}
	}
	return attrs
}

fn (mut p Parser) parse_pi_body(target string) !Node {
	data_raw := p.read_until_close()!
	p.expect(`]`)!
	data := data_raw.trim_space()
	d := if data.len == 0 { ?string(none) } else { ?string(data) }
	return PINode{ target: target, data: d }
}

// ── [-...] comment ────────────────────────────────────────────────────────────

fn (mut p Parser) parse_comment() !Node {
	p.advance() // consume '-'
	value := p.read_until_close()!
	p.expect(`]`)!
	return CommentNode{ value: value }
}

// ── [# ... #] raw text ────────────────────────────────────────────────────────

fn (mut p Parser) parse_raw_text() !Node {
	p.advance() // consume '#'
	mut value_bytes := []u8{}
	for {
		if p.at_end() { return error(p.make_error('unterminated raw text')) }
		b := p.peek()
		p.advance()
		if b == `#` {
			if !p.at_end() && p.peek() == `]` {
				p.advance() // consume ']'
				break
			}
			value_bytes << b
		} else {
			value_bytes << b
		}
	}
	return RawTextNode{ value: value_bytes.bytestr() }
}

// ── [!...] declarations ───────────────────────────────────────────────────────

fn (mut p Parser) parse_decl() !Node {
	p.advance() // consume '!'
	if p.at_end() { return error(p.make_error('unexpected EOF in declaration')) }
	b := p.peek()
	if b == `[` {
		p.advance() // consume '['
		kw := p.read_name()!
		p.skip_ws()
		if !p.at_end() && p.peek() == `[` {
			p.advance() // consume second '['
		}
		return p.parse_conditional_sect_body(kw)!
	}
	kw := p.read_name()!
	return match kw {
		'ENTITY'   { p.parse_entity_decl()! }
		'ELEMENT'  { p.parse_element_decl()! }
		'ATTLIST'  { p.parse_attlist_decl()! }
		'NOTATION' { p.parse_notation_decl()! }
		'DOCTYPE'  { error(p.make_error('DOCTYPE not allowed here')) }
		else       { error(p.make_error('unknown declaration: ${kw}')) }
	}
}

fn (mut p Parser) parse_doctype_inner() !DoctypeDecl {
	p.skip_ws()
	name := p.read_name()!
	p.skip_ws()
	ext := p.maybe_parse_external_id()
	p.skip_ws()
	mut int_subset := []Node{}
	if !p.at_end() && p.peek() == `[` {
		p.advance()
		for {
			p.skip_ws()
			if p.at_end() { break }
			b2 := p.peek()
			if b2 == `]` {
				p.advance()
				break
			}
			if b2 == `[` {
				n := p.parse_bracket_node()!
				int_subset << n
			} else {
				break
			}
		}
	}
	p.skip_ws()
	p.expect(`]`)!
	return DoctypeDecl{ name: name, external_id: ext, int_subset: int_subset }
}

fn (mut p Parser) try_parse_external_id() !ExternalID {
	ext := p.parse_external_id_opt() or { return error(p.make_error('expected external ID')) }
	return ext
}

// Returns ExternalID or none if not present.
fn (mut p Parser) maybe_parse_external_id() ?ExternalID {
	return p.parse_external_id_opt()
}

fn (mut p Parser) parse_external_id_opt() ?ExternalID {
	if p.at_end() { return none }
	b := p.peek()
	if b == `S` && p.pos + 6 <= p.src.len && p.src[p.pos..p.pos+6] == 'SYSTEM'.bytes() {
		p.pos += 6
		p.col += 6
		p.skip_ws()
		system := p.read_quoted() or { return none }
		return ExternalID{ system: system }
	}
	if b == `P` && p.pos + 6 <= p.src.len && p.src[p.pos..p.pos+6] == 'PUBLIC'.bytes() {
		p.pos += 6
		p.col += 6
		p.skip_ws()
		public := p.read_quoted() or { return none }
		p.skip_ws()
		if !p.at_end() && (p.peek() == `'` || p.peek() == `"`) {
			system := p.read_quoted() or { return ExternalID{ public: public } }
			return ExternalID{ public: public, system: system }
		}
		return ExternalID{ public: public }
	}
	return none
}

fn (mut p Parser) parse_entity_decl() !Node {
	p.skip_ws()
	mut kind := EntityKind.ge
	if !p.at_end() && p.peek() == `%` {
		p.advance()
		p.skip_ws()
		kind = EntityKind.pe
	}
	name := p.read_name()!
	p.skip_ws()
	if p.at_end() { return error(p.make_error('expected entity def')) }
	b := p.peek()
	def := if b == `S` || b == `P` {
		ext := p.try_parse_external_id()!
		p.skip_ws()
		mut ndata := ?string(none)
		if p.pos + 5 <= p.src.len && p.src[p.pos..p.pos+5] == 'NDATA'.bytes() {
			p.pos += 5
			p.col += 5
			p.skip_ws()
			nd := p.read_name()!
			ndata = nd
		}
		EntityDef(ExternalEntityDef{ external_id: ext, ndata: ndata })
	} else {
		EntityDef(p.read_quoted()!)
	}
	p.skip_ws()
	p.expect(`]`)!
	return EntityDeclNode{ kind: kind, name: name, def: def }
}

fn (mut p Parser) parse_element_decl() !Node {
	p.skip_ws()
	name := p.read_name()!
	p.skip_ws()
	contentspec := (p.read_until_close()!).trim_space()
	p.expect(`]`)!
	return ElementDeclNode{ name: name, contentspec: contentspec }
}

fn (mut p Parser) parse_attlist_decl() !Node {
	p.skip_ws()
	name := p.read_name()!
	mut defs := []AttDef{}
	for {
		p.skip_ws()
		if p.at_end() || p.peek() == `]` { break }
		aname := p.read_name()!
		p.skip_ws()
		atype := p.read_name()!
		p.skip_ws()
		default_val := p.read_att_default()!
		defs << AttDef{ name: aname, att_type: atype, default: default_val }
	}
	p.expect(`]`)!
	return AttlistDeclNode{ name: name, defs: defs }
}

fn (mut p Parser) read_att_default() !string {
	if !p.at_end() && p.peek() == `#` {
		p.advance()
		kw := p.read_name()!
		return '#${kw}'
	}
	return p.read_quoted()!
}

fn (mut p Parser) parse_notation_decl() !Node {
	p.skip_ws()
	name := p.read_name()!
	p.skip_ws()
	ext := p.maybe_parse_external_id()
	public_id, system_id := if e := ext {
		e.public, e.system
	} else {
		?string(none), ?string(none)
	}
	p.skip_ws()
	p.expect(`]`)!
	return NotationDeclNode{ name: name, public_id: public_id, system_id: system_id }
}

fn (mut p Parser) parse_conditional_sect_body(kw string) !Node {
	kind := if kw == 'INCLUDE' { ConditionalKind.include } else { ConditionalKind.ignore }
	mut subset := []Node{}
	for {
		p.skip_ws()
		if p.at_end() { break }
		b := p.peek()
		if b == `]` {
			saved := p.pos
			p.advance()
			if !p.at_end() && p.peek() == `]` {
				p.advance()
				if !p.at_end() && p.peek() == `]` {
					p.advance()
					break
				}
			}
			p.pos = saved
			break
		}
		if b == `[` {
			n := p.parse_bracket_node()!
			subset << n
		} else {
			break
		}
	}
	return ConditionalSectNode{ kind: kind, subset: subset }
}

// ── [*name] alias ─────────────────────────────────────────────────────────────

fn (mut p Parser) parse_alias() !Node {
	p.advance() // consume '*'
	name := p.read_name()!
	p.skip_ws()
	p.expect(`]`)!
	return AliasNode{ name: name }
}

// ── Entity ref & charref ──────────────────────────────────────────────────────

fn (mut p Parser) parse_entity_ref() !Node {
	p.advance() // consume '&'
	name := p.read_name()!
	p.expect(`;`)!
	return EntityRefNode{ name: name }
}

fn (mut p Parser) parse_amp_node() !Node {
	p.advance() // consume '&'
	if !p.at_end() && p.peek() == `#` {
		p.advance()
		return p.parse_charref()!
	}
	name := p.read_name()!
	p.expect(`;`)!
	return EntityRefNode{ name: name }
}

fn (mut p Parser) parse_charref() !Node {
	codepoint := if !p.at_end() && (p.peek() == `x` || p.peek() == `X`) {
		p.advance()
		hex := p.read_hex_digits()!
		u32(strconv.parse_int(hex, 16, 64) or { return error(p.make_error('invalid hex charref')) })
	} else {
		dec := p.read_dec_digits()!
		u32(dec.u64())
	}
	p.expect(`;`)!
	value := rune_to_utf8(codepoint)
	return TextNode{ value: value }
}

fn rune_to_utf8(c u32) string {
	if c < 0x80 {
		return [u8(c)].bytestr()
	} else if c < 0x800 {
		return [u8(0xC0 | (c >> 6)), u8(0x80 | (c & 0x3F))].bytestr()
	} else if c < 0x10000 {
		return [u8(0xE0 | (c >> 12)), u8(0x80 | ((c >> 6) & 0x3F)), u8(0x80 | (c & 0x3F))].bytestr()
	} else {
		return [u8(0xF0 | (c >> 18)), u8(0x80 | ((c >> 12) & 0x3F)), u8(0x80 | ((c >> 6) & 0x3F)), u8(0x80 | (c & 0x3F))].bytestr()
	}
}

// ── Element parser ────────────────────────────────────────────────────────────

fn (mut p Parser) parse_element() !Node {
	// v3.4 adversarial defense: bound element nesting to prevent
	// stack overflow on deeply nested input. spec/policies.md §5.4.
	p.depth++
	if p.depth > max_recursion_depth {
		return error('${p.line}:${p.col}: element nesting exceeds limit (${max_recursion_depth})')
	}
	defer { p.depth-- }
	raw_name := p.read_name()!
	name := normalize_doc_element_name(raw_name)
	mut anchor := ?string(none)
	mut merge := ?string(none)
	mut id := ?string(none)
	mut data_type := ?string(none)
	mut attrs := []Attribute{}

	for {
		// ElementMeta position: skip plain whitespace only. `#` is the
		// ID-declaration sigil per ADR 0003 D1, not a line-comment
		// introducer, in this position. (The skip_ws-vs-skip_ws_and_line_comments
		// distinction is documented at the top of this file.)
		p.skip_ws()
		if p.at_end() { break }
		b := p.peek()
		if b == `]` || b == `[` { break }
		if b == `'` { break } // quoted text starts body

		if b == `&` {
			// &name (no semicolon) = anchor def
			// &name; = entity ref in body → stop
			saved_pos := p.pos
			saved_line := p.line
			saved_col := p.col
			p.advance() // consume '&'
			if aname := p.try_read_name() {
				if !p.at_end() && p.peek() != `;` {
					anchor = aname
					continue
				}
			}
			p.pos = saved_pos
			p.line = saved_line
			p.col = saved_col
			break
		}

		if b == `*` {
			saved_pos2 := p.pos
			saved_line2 := p.line
			saved_col2 := p.col
			p.advance()
			if mname := p.try_read_name() {
				merge = mname
				continue
			}
			p.pos = saved_pos2
			p.line = saved_line2
			p.col = saved_col2
			break
		}

		// v3.4 (ADR 0003): syntactic ID declaration. `#name` at
		// ElementMeta position (after element name, before attributes
		// and body) declares this element's stable ID. Distinct from
		// raw-text blocks `[#...#]` (different position) and from
		// line comments (recognized only in body / between-element
		// position via skip_ws_and_line_comments). Duplicate IDs
		// across the document are a parse error caught by the
		// resolve_ids() post-pass; here we only store the declaration.
		if b == `#` {
			saved_pos3 := p.pos
			saved_line3 := p.line
			saved_col3 := p.col
			p.advance()
			if iname := p.try_read_name() {
				if iname.contains(':') {
					return error(p.make_error("ID '${iname}' must not contain ':' (per ADR 0003 D2)"))
				}
				id = iname
				continue
			}
			p.pos = saved_pos3
			p.line = saved_line3
			p.col = saved_col3
			break
		}

		if b == `:` {
			// v3.4: ':table[' is the start of a TableBlock, not a
			// regular type annotation. Detected by lookahead: ':table'
			// followed by '[' but NOT immediately closed with ']'
			// (':table[]' would be an array of "table" type, which
			// has no defined meaning; we treat ':table[' followed by
			// non-']' as the table-block opener).
			if p.peek_table_block_start() {
				p.advance() // consume ':'
				p.read_name()! // consume 'table'
				p.advance() // consume '['
				cols := p.parse_table_header()!
				p.expect(`]`)!
				rows := p.parse_table_rows(cols)!
				// Populate the Element directly: when this branch fires,
				// we know parse_element is reading the unique TableBlock
				// alternative of grammar [50]. Body parsing is skipped.
				p.skip_ws_and_line_comments()
				p.expect(`]`)!
				return Element{
					name:  name
					anchor: anchor
					merge:  merge
					id:     id
					data_type: ?string('table')
					table: ?TableData(TableData{ cols: cols, rows: rows })
				}
			}
			p.advance()
			ta := p.read_type_annotation()!
			data_type = ta
			break
		}

		// v3.4 boolean attribute sigil: +name or -name. Recognized only
		// at ElementMeta position when sigil is immediately followed by
		// NameStartChar (no whitespace). AST-equivalent to
		// Attribute(name, value=true|false, type=bool). Spec: [55b].
		if (b == `+` || b == `-`) && p.pos + 1 < p.src.len && is_name_start(p.src[p.pos + 1]) {
			sigil_val := b == `+`
			p.advance() // consume sigil
			tok := p.read_name()!
			attrs << Attribute{
				name:      tok
				value:     ScalarValue(sigil_val)
				data_type: ?ScalarType(ScalarType.bool_type)
			}
			continue
		}

		if is_name_start(b) {
			tok := p.read_name()!
			if !p.at_end() && p.peek() == `=` {
				p.advance()
				// v3.4 (ADR 0003): bare `@id` at attribute-value
				// position is a syntactic reference, not a literal
				// string. `'@id'` (quoted) is still a literal.
				if !p.at_end() && p.peek() == `@` {
					p.advance()
					rname := p.read_name()!
					if rname.contains(':') {
						return error(p.make_error("reference '${rname}' must not contain ':' (per ADR 0003 D2)"))
					}
					attrs << Attribute{ name: tok, value: ScalarValue(rname), is_ref: true }
				} else if !p.at_end() && p.peek() == `[` {
					// v3.5 (ADR 0016): BracketBody attribute value
					// `name=[BodyItem*]`. Grammar [55c]. Inert
					// outside CXL contexts; round-trips per R5.
					p.advance() // consume '['
					body_items := p.parse_body(none)!
					p.expect(`]`)!
					attrs << Attribute{
						name: tok
						value: ScalarValue('')
						data_type: ?ScalarType(none)
						body: ?[]Node(body_items)
					}
				} else {
					val, dt := p.read_attr_value_typed()!
					attrs << Attribute{ name: tok, value: val, data_type: dt }
				}
			} else {
				p.pos -= tok.len
				break
			}
		} else {
			break
		}
	}

	mut items := p.parse_body(data_type)!
	p.expect(`]`)!

	mut final_dt := data_type
	if dt_val := data_type {
		if dt_val == '[]' {
			inferred := infer_array_type(items)
			if inferred == 'float[]' {
				promote_int_to_float(mut items)
			}
			final_dt = inferred
		}
	} else {
		if arr_nodes := try_auto_array(items) {
			dt := infer_array_type(arr_nodes)
			items = arr_nodes.clone()
			final_dt = dt
		}
	}

	// v3.4 (ADR 0003 D1 second bullet): recognize `[ref @id]` body-
	// position node form. The body parser produced a single TextNode
	// of the form '@<name>' for the bare-@id token; lift it into
	// Element.body_ref so the validator can check it and the emitter
	// can re-render the syntactic form on round-trip.
	mut body_ref := ?string(none)
	if name == 'ref' && attrs.len == 0 && items.len == 1 {
		first := items[0]
		if first is TextNode {
			tv := first.value.trim_space()
			if tv.len > 1 && tv[0] == `@` {
				rname := tv[1..]
				if rname.len > 0 && is_name_start(rname[0]) && !rname.contains(':') {
					mut all_name := true
					for i in 1 .. rname.len {
						if !is_name_char(rname[i]) {
							all_name = false
							break
						}
					}
					if all_name {
						body_ref = rname
						items = []
					}
				}
			}
		}
	}

	return Element{ name: name, anchor: anchor, merge: merge, id: id, body_ref: body_ref, data_type: final_dt, attrs: attrs, items: items }
}

fn (mut p Parser) read_type_annotation() !string {
	if p.pos + 2 <= p.src.len && p.src[p.pos] == `[` && p.src[p.pos+1] == `]` {
		p.pos += 2
		p.col += 2
		return '[]'
	}
	base := p.read_name()!
	long := expand_type_alias(base)
	if p.pos + 2 <= p.src.len && p.src[p.pos] == `[` && p.src[p.pos+1] == `]` {
		p.pos += 2
		p.col += 2
		return '${long}[]'
	}
	return long
}

fn expand_type_alias(s string) string {
	return match s {
		'i'  { 'int' }
		'f'  { 'float' }
		'b'  { 'bool' }
		's'  { 'string' }
		'd'  { 'date' }
		'dt' { 'datetime' }
		else { s }
	}
}

// ── Body parser ───────────────────────────────────────────────────────────────

fn (mut p Parser) parse_body(type_ann ?string) ![]Node {
	mut items := []Node{}
	is_inferred_array := if ta := type_ann { ta == '[]' } else { false }
	is_array := if ta := type_ann { !is_inferred_array && ta.ends_with('[]') } else { false }
	elem_type := if is_array {
		if ta := type_ann { ta[..ta.len-2] } else { 'string' }
	} else {
		'string'
	}

	mut text_buf := []u8{}
	mut has_child_element := false
	mut after_non_text := false

	for {
		if p.at_end() { break }
		had_ws := is_ws(p.peek())
		// Skip whitespace but PRESERVE line comments — they should round-trip
		// through `cx fmt` per spec/cheatsheet, not be silently dropped.
		for !p.at_end() {
			c := p.peek()
			if c == ` ` || c == `\t` || c == `\r` || c == `\n` {
				p.advance()
			} else if c == `#` {
				if text_buf.len > 0 {
					items << TextNode{ value: text_buf.bytestr() }
					text_buf = []u8{}
				}
				val := p.read_line_comment_value()
				items << CommentNode{ value: val, is_line: true }
				after_non_text = true
			} else {
				break
			}
		}

		if p.at_end() { break }
		b := p.peek()
		if b == `]` { break }

		if b == `[` {
			has_child_element = true
			if had_ws && text_buf.len > 0 { text_buf << ` ` }
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			child := p.parse_bracket_node()!
			items << child
			after_non_text = true
			continue
		}

		if b == `'` {
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			if p.pos + 3 <= p.src.len && p.src[p.pos] == `'` && p.src[p.pos+1] == `'` && p.src[p.pos+2] == `'` {
				n := p.read_triple_quoted()!
				items << n
			} else {
				quoted := p.read_quoted_text()!
				items << TextNode{ value: quoted }
			}
			after_non_text = false
			continue
		}

		if b == `&` {
			if had_ws {
				if text_buf.len > 0 {
					text_buf << ` `
				} else if after_non_text {
					text_buf << ` `
				}
			}
			n := p.parse_amp_node()!
			match n {
				TextNode {
					text_buf << n.value.bytes()
					after_non_text = false
				}
				else {
					if text_buf.len > 0 {
						items << TextNode{ value: text_buf.bytestr() }
						text_buf = []u8{}
					}
					items << n
					after_non_text = true
				}
			}
			continue
		}

		// v3.6 (ADR 0017): SequenceLiteral `( a, b )` and MapLiteral
		// `{ k: v }` introducers in body position per grammar [56a] /
		// [56c]. Disambiguated against literal text containing parens /
		// braces by the comma- / colon-marker rule (peek_is_sequence_*
		// / peek_is_map_*). Bare `(text)` and `{text}` continue to parse
		// as body text. Empty `()` and `{}` are recognized as empty
		// sequence / map respectively.
		if b == `(` && p.peek_is_sequence_literal_at_paren() {
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			items << p.parse_sequence_literal()!
			after_non_text = true
			continue
		}
		if b == `{` && p.peek_is_map_literal_at_brace() {
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			items << p.parse_map_literal()!
			after_non_text = true
			continue
		}

		tok := p.read_token()!
		if is_inferred_array {
			scalar := try_autotype(tok) or {
				ScalarNode{ data_type: .string_type, value: ScalarValue(tok) }
			}
			items << scalar
		} else if is_array {
			items << coerce_scalar(elem_type, tok)
		} else {
			if text_buf.len > 0 {
				if had_ws { text_buf << ` ` }
			} else if after_non_text && had_ws {
				text_buf << ` `
			}
			text_buf << tok.bytes()
			after_non_text = false
		}
	}

	if text_buf.len > 0 {
		text_val := text_buf.bytestr()
		if !has_child_element && items.len == 0 {
			if ta := type_ann {
				if !ta.ends_with('[]') {
					// v0.6.0 — typed-body constraint sigils. When every
					// whitespace-separated token in the body content is
					// `:`-prefixed, treat the whole buffer as a constraint
					// flag list (TextNode) rather than coercing it to the
					// declared scalar type. Schema-validate's
					// body_rule_from_element reads these as :req / :range
					// / :enum / :pat / :len. A concrete body value never
					// starts with `:`, so this rule is safe for non-schema
					// uses; only schema declarations use the sigil form.
					if all_tokens_are_sigils(text_val) {
						items << TextNode{ value: text_val }
						return items
					}
					items << coerce_scalar(ta, text_val)
					return items
				}
			}
			if scalar := try_autotype(text_val) {
				items << scalar
				return items
			}
		}
		items << TextNode{ value: text_val }
	}

	return items
}

// ── Auto-array detection ──────────────────────────────────────────────────────

fn try_auto_array(items []Node) ?[]Node {
	if items.len != 1 { return none }
	t := items[0]
	if t !is TextNode { return none }
	val := (t as TextNode).value
	if !val.contains(' ') && !val.contains('\t') { return none }
	tokens := val.split_any(' \t\r\n').filter(it.len > 0)
	if tokens.len < 2 { return none }
	return try_autotype_array(tokens)
}

fn try_autotype_array(tokens []string) ?[]Node {
	mut scalars := []ScalarNode{}
	for tok in tokens {
		s := try_autotype(tok) or { return none }
		scalars << s
	}
	if scalars.len == 0 { return none }
	first_type := scalars[0].data_type
	if scalars.all(it.data_type == first_type) {
		mut result := []Node{}
		for s in scalars { result << Node(s) }
		return result
	}
	all_numeric := scalars.all(it.data_type == .int_type || it.data_type == .float_type)
	if all_numeric {
		mut result := []Node{}
		for s in scalars {
			if s.data_type == .int_type {
				sv := s.value
			ival := if sv is i64 { i64(sv) } else { i64(0) }
				result << Node(ScalarNode{ data_type: .float_type, value: ScalarValue(f64(ival)) })
			} else {
				result << Node(s)
			}
		}
		return result
	}
	return none
}

fn infer_array_type(items []Node) string {
	mut scalars := []ScalarNode{}
	for n in items {
		if n is ScalarNode {
			scalars << n as ScalarNode
		}
	}
	if scalars.len == 0 { return 'string[]' }
	first_type := scalars[0].data_type
	if scalars.all(it.data_type == first_type) {
		return '${scalar_type_name(first_type)}[]'
	}
	all_numeric := scalars.all(it.data_type == .int_type || it.data_type == .float_type)
	if all_numeric { return 'float[]' }
	return 'string[]'
}

fn promote_int_to_float(mut items []Node) {
	for i in 0..items.len {
		n := items[i]
		if n is ScalarNode {
			s := n as ScalarNode
			if s.data_type == .int_type {
				sv := s.value
				ival := if sv is i64 { i64(sv) } else { i64(0) }
				items[i] = ScalarNode{ data_type: .float_type, value: ScalarValue(f64(ival)) }
			}
		}
	}
}

// ── Auto-typing ───────────────────────────────────────────────────────────────

// strip_underscores removes internal `_` separators from a numeric
// literal token. Returns the cleaned string, or none if underscores are
// malformed (leading, trailing, or doubled). This implements the v3.4
// numeric-underscore readability rule for grammar [20a]/[20b]/[20c].
//
// Accepts: 1_000_000, 0xDEAD_BEEF, 1.234_567, 1_000e3
// Rejects: _1000, 1000_, 1__000
fn strip_underscores(tok string) ?string {
	if tok.len == 0 { return tok }
	if tok[0] == `_` { return none }
	if tok[tok.len - 1] == `_` { return none }
	if tok.contains('__') { return none }
	if !tok.contains('_') { return tok }
	return tok.replace('_', '')
}

// is_v34_decimal_int checks the v3.4 leading-zero rule for decimal
// integer literals. Returns true if `tok` is a valid v3.4 integer
// literal (post-underscore-stripping).
//
// v3.4 rule: integer literals MUST NOT have a leading zero except for
// the literal '0' itself. '02134' is no longer auto-typed as int 2134
// — it falls through to Text. Hex integers (0x...) are exempt because
// the prefix disambiguates.
//
// `tok` may have a leading sign (`-` or `+`); the check applies to the
// digit portion.
fn is_v34_decimal_int(tok string) bool {
	mut s := tok
	if s.len > 0 && (s[0] == `-` || s[0] == `+`) {
		s = s[1..]
	}
	if s.len == 0 { return false }
	// Single '0' is fine; '0...' with more digits is not.
	if s.len == 1 { return s[0] >= `0` && s[0] <= `9` }
	if s[0] == `0` { return false }
	for c in s {
		if c < `0` || c > `9` { return false }
	}
	return true
}

fn try_autotype(tok string) ?ScalarNode {
	// hex int: 0x...
	// Underscores between hex digits permitted (0xDEAD_BEEF). Strip
	// them before parsing.
	if tok.starts_with('0x') || tok.starts_with('0X') {
		hex_body := strip_underscores(tok[2..]) or { return none }
		if v := strconv.parse_int(hex_body, 16, 64) {
			return ScalarNode{ data_type: .int_type, value: ScalarValue(v) }
		}
	}
	if tok.starts_with('-0x') || tok.starts_with('-0X') {
		hex_body := strip_underscores(tok[3..]) or { return none }
		if v := strconv.parse_int(hex_body, 16, 64) {
			neg := -v
			return ScalarNode{ data_type: .int_type, value: ScalarValue(neg) }
		}
	}
	// bool and null — checked before float to avoid 'e' in "true"/"false" triggering float path
	if tok == 'true'  { return ScalarNode{ data_type: .bool_type, value: ScalarValue(true) } }
	if tok == 'false' { return ScalarNode{ data_type: .bool_type, value: ScalarValue(false) } }
	if tok == 'null'  { return ScalarNode{ data_type: .null_type, value: ScalarValue(NullValue{}) } }
	// int (decimal): apply v3.4 leading-zero rule + underscore stripping.
	// '02134' falls through to Text; '1_000_000' parses as 1000000.
	cleaned := strip_underscores(tok) or { return none }
	if is_v34_decimal_int(cleaned) {
		if v := cleaned.parse_int(10, 64) {
			return ScalarNode{ data_type: .int_type, value: ScalarValue(v) }
		}
	}
	// float (must contain . or e/E to distinguish from int, AND parse successfully)
	if cleaned.contains('.') || cleaned.contains('e') || cleaned.contains('E') {
		fv := strconv.atof64(cleaned) or { return none }
		return ScalarNode{ data_type: .float_type, value: ScalarValue(fv) }
	}
	// datetime
	if is_datetime(tok) {
		return ScalarNode{ data_type: .datetime_type, value: ScalarValue(tok) }
	}
	// date
	if is_date(tok) {
		return ScalarNode{ data_type: .date_type, value: ScalarValue(tok) }
	}
	return none
}

// all_tokens_are_sigils returns true when every whitespace-separated
// token in `s` begins with `:`. Used by parse_body to distinguish a
// typed-body constraint-sigil list (`[body :i32 :range='1..65535' :req]`)
// from a typed-body scalar value. Empty string returns false (an
// empty body falls through to the normal coerce_scalar path).
fn all_tokens_are_sigils(s string) bool {
	t := s.trim_space()
	if t.len == 0 { return false }
	tokens := split_ws_quote_bracket(t)
	if tokens.len == 0 { return false }
	for tok in tokens {
		if !tok.starts_with(':') { return false }
	}
	return true
}

fn coerce_scalar(et string, tok string) ScalarNode {
	return match et {
		'int' {
			// v3.4: strip optional underscores. Explicit :int annotation
			// bypasses the leading-zero auto-typing rule — the user has
			// declared this is an integer.
			cleaned := strip_underscores(tok) or { tok }
			v := if cleaned.starts_with('0x') || cleaned.starts_with('0X') {
				strconv.parse_int(cleaned[2..], 16, 64) or { i64(0) }
			} else {
				cleaned.parse_int(10, 64) or { i64(0) }
			}
			ScalarNode{ data_type: .int_type, value: ScalarValue(v) }
		}
		'float' {
			cleaned := strip_underscores(tok) or { tok }
			v := strconv.atof64(cleaned) or { f64(0.0) }
			ScalarNode{ data_type: .float_type, value: ScalarValue(v) }
		}
		'bool' {
			ScalarNode{ data_type: .bool_type, value: ScalarValue(tok == 'true') }
		}
		'null' {
			ScalarNode{ data_type: .null_type, value: ScalarValue(NullValue{}) }
		}
		'date' {
			ScalarNode{ data_type: .date_type, value: ScalarValue(tok) }
		}
		'datetime' {
			ScalarNode{ data_type: .datetime_type, value: ScalarValue(tok) }
		}
		'bytes' {
			ScalarNode{ data_type: .bytes_type, value: ScalarValue(tok) }
		}
		// v3.4 sized integers — parsed as int, width validated at later
		// stages (data_bin emission, host-type marshalling). Underscores
		// stripped per v3.4.
		'i8', 'i16', 'i32', 'i64', 'u8', 'u16', 'u32', 'u64' {
			cleaned := strip_underscores(tok) or { tok }
			v := if cleaned.starts_with('0x') || cleaned.starts_with('0X') {
				strconv.parse_int(cleaned[2..], 16, 64) or { i64(0) }
			} else {
				cleaned.parse_int(10, 64) or { i64(0) }
			}
			ScalarNode{ data_type: .int_type, value: ScalarValue(v) }
		}
		// v3.4 sized floats — parsed as float; precision per host type
		// at marshalling time.
		'f16', 'f32', 'f64' {
			cleaned := strip_underscores(tok) or { tok }
			v := strconv.atof64(cleaned) or { f64(0.0) }
			ScalarNode{ data_type: .float_type, value: ScalarValue(v) }
		}
		// v3.4 arbitrary-precision decimal — stored as string, full
		// precision preserved. Host bindings convert to decimal types
		// per spec/type_mapping.md §2.
		'decimal' {
			cleaned := strip_underscores(tok) or { tok }
			ScalarNode{ data_type: .decimal_type, value: ScalarValue(cleaned) }
		}
		// v3.4 arbitrary-precision integer — stored as string; auto-
		// promoted from int when the value exceeds i64 range.
		'bigint' {
			cleaned := strip_underscores(tok) or { tok }
			ScalarNode{ data_type: .bigint_type, value: ScalarValue(cleaned) }
		}
		else {
			ScalarNode{ data_type: .string_type, value: ScalarValue(tok) }
		}
	}
}

fn is_date(s string) bool {
	if s.len != 10 { return false }
	bs := s.bytes()
	return bs[4] == `-` && bs[7] == `-`
		&& is_all_digits(s[..4])
		&& is_all_digits(s[5..7])
		&& is_all_digits(s[8..])
}

fn is_datetime(s string) bool {
	if s.len < 19 { return false }
	bs := s.bytes()
	return is_date(s[..10]) && bs[10] == `T`
}

fn is_all_digits(s string) bool {
	for b in s.bytes() {
		if b < `0` || b > `9` { return false }
	}
	return true
}

fn is_name_start(b u8) bool {
	return (b >= `a` && b <= `z`) || (b >= `A` && b <= `Z`) || b == `_`
}

fn is_name_char(b u8) bool {
	return is_name_start(b) || (b >= `0` && b <= `9`) || b == `-` || b == `.` || b == `:`
}

// ── Low-level readers ─────────────────────────────────────────────────────────

fn (mut p Parser) read_name() !string {
	mut s := []u8{}
	for !p.at_end() {
		b := p.peek()
		if is_name_char(b) {
			s << b
			p.advance()
		} else {
			break
		}
	}
	if s.len == 0 {
		return error(p.make_error('expected name'))
	}
	return s.bytestr()
}

fn (mut p Parser) try_read_name() ?string {
	mut s := []u8{}
	for !p.at_end() {
		b := p.peek()
		if is_name_char(b) {
			s << b
			p.advance()
		} else {
			break
		}
	}
	if s.len == 0 { return none }
	return s.bytestr()
}

// read_token reads a whitespace-or-`]`-terminated token from the body
// stream. Quote and bracket awareness (v0.6.0 Phase 7.74e):
//   - Inside `'...'` or `"..."` regions, embedded `]` and whitespace are
//     consumed without terminating — this is what lets
//     `:pat='[a-z]+'` parse as a single token even though the regex
//     class contains a `]`.
//   - Inside a balanced `[...]` region opened mid-token, embedded
//     whitespace is consumed and `]` only closes when depth returns to
//     zero — this is what lets `:enum=[v1 v2 v3]` parse as a single
//     token without the `,`-separator workaround.
//   - A token starting with `[` is handled by parse_bracket_node, not
//     read_token, so the bracket-depth path here only applies to
//     mid-token brackets like `:enum=[...]`.
fn (mut p Parser) read_token() !string {
	mut s := []u8{}
	mut in_quote := u8(0)
	mut bracket_depth := 0
	for !p.at_end() {
		b := p.peek()
		if in_quote != 0 {
			s << b
			p.advance()
			if b == in_quote { in_quote = 0 }
			continue
		}
		if bracket_depth > 0 {
			if b == `[` {
				bracket_depth++
			} else if b == `]` {
				bracket_depth--
				s << b
				p.advance()
				if bracket_depth == 0 { break }
				continue
			} else if b == `'` || b == `"` {
				in_quote = b
			}
			s << b
			p.advance()
			continue
		}
		if is_ws(b) || b == `]` { break }
		// v3.5 (ADR 0016): `[?` introduces a CXL evaluation form
		// (Interpolation or EvalDirective) and is never part of a
		// surrounding token. Break here so the outer parser can
		// dispatch the nested directive. Other `[` (predicate
		// brackets in CXPath expressions, `:enum=[v1 v2 v3]`, etc.)
		// continue to absorb mid-token per the bracket_depth path.
		if b == `[` && p.pos + 1 < p.src.len && p.src[p.pos + 1] == `?` {
			break
		}
		if b == `'` || b == `"` {
			in_quote = b
		} else if b == `[` {
			bracket_depth = 1
		}
		s << b
		p.advance()
	}
	if s.len == 0 {
		return error(p.make_error('expected token'))
	}
	return s.bytestr()
}

// split_ws_quote_bracket splits `s` on ASCII whitespace, treating
// `'..'` / `"..."` regions and balanced `[...]` regions as atomic so
// embedded whitespace doesn't terminate a token. Used by the
// schema-decl token analyzers to keep `:pat='a b c'` and
// `:enum=[v1 v2 v3]` as single tokens after parse_body has already
// produced a single TextNode for the body.
pub fn split_ws_quote_bracket(s string) []string {
	bytes := s.bytes()
	mut out := []string{}
	mut tok := []u8{}
	mut in_quote := u8(0)
	mut bracket_depth := 0
	for i := 0; i < bytes.len; i++ {
		b := bytes[i]
		if in_quote != 0 {
			tok << b
			if b == in_quote { in_quote = 0 }
			continue
		}
		if bracket_depth > 0 {
			if b == `[` {
				bracket_depth++
			} else if b == `]` {
				bracket_depth--
			} else if b == `'` || b == `"` {
				in_quote = b
			}
			tok << b
			continue
		}
		if b == ` ` || b == `\t` || b == `\r` || b == `\n` {
			if tok.len > 0 {
				out << tok.bytestr()
				tok = []u8{}
			}
			continue
		}
		if b == `'` || b == `"` {
			in_quote = b
		} else if b == `[` {
			bracket_depth = 1
		}
		tok << b
	}
	if tok.len > 0 {
		out << tok.bytestr()
	}
	return out
}

fn (mut p Parser) read_quoted() !string {
	if p.at_end() { return error(p.make_error('expected quote')) }
	q := p.peek()
	if q != `'` && q != `"` {
		return error(p.make_error('expected quote'))
	}
	p.advance()
	mut s := []u8{}
	for {
		if p.at_end() { return error(p.make_error('unterminated string')) }
		b := p.peek()
		p.advance()
		if b == q { break }
		s << b
	}
	return s.bytestr()
}

fn (mut p Parser) read_quoted_text() !string {
	p.expect(`'`)!
	mut s := []u8{}
	for {
		if p.at_end() { return error(p.make_error('unterminated quoted text')) }
		b := p.peek()
		p.advance()
		if b == `'` { break }
		s << b
	}
	return s.bytestr()
}

fn (mut p Parser) read_attr_list_until(stop u8) ![]Attribute {
	mut attrs := []Attribute{}
	for {
		p.skip_ws()
		if p.at_end() || p.peek() == stop { break }
		name := p.read_name()!
		p.expect(`=`)!
		value := p.read_attr_value()!
		attrs << Attribute{ name: name, value: ScalarValue(value), data_type: none }
	}
	return attrs
}

fn (mut p Parser) read_attr_value() !string {
	if p.at_end() { return error(p.make_error('expected attr value')) }
	b := p.peek()
	if b == `'` || b == `"` {
		return p.read_quoted()!
	}
	return p.read_token()!
}

fn (mut p Parser) read_attr_value_typed() !(ScalarValue, ?ScalarType) {
	if p.at_end() { return error(p.make_error('expected attr value')), none }
	b := p.peek()
	if b == `'` || b == `"` {
		s := p.read_quoted()!
		return ScalarValue(s), ?ScalarType(none)
	}
	tok := p.read_token()!
	if scalar := try_autotype(tok) {
		return scalar.value, ?ScalarType(scalar.data_type)
	}
	return ScalarValue(tok), ?ScalarType(none)
}

fn (mut p Parser) read_until_close() !string {
	mut s := []u8{}
	mut depth := 0
	for {
		if p.at_end() { return error(p.make_error('unexpected EOF')) }
		b := p.peek()
		// v3.4 fix: `[#...#]` (raw text) and `[|...|]` (block content)
		// are atomic spans — their inner content is uninterpreted, and
		// their closing requires `#]` / `|]` (not a bare `]`). When
		// encountered inside a comment body, swallow them whole rather
		// than letting depth-counting misalign on the inner `]`. The
		// equivalent fix in non-comment-body parsing is in parse_raw_text
		// / parse_block_content; this is the comment-side mirror.
		if b == `[` && p.pos + 1 < p.src.len && p.src[p.pos + 1] == `#` {
			p.advance() // [
			p.advance() // #
			s << `[`
			s << `#`
			for {
				if p.at_end() { return error(p.make_error('unterminated [# inside comment')) }
				c := p.peek()
				p.advance()
				s << c
				if c == `#` && !p.at_end() && p.peek() == `]` {
					s << p.peek()
					p.advance()
					break
				}
			}
			continue
		}
		if b == `[` && p.pos + 1 < p.src.len && p.src[p.pos + 1] == `|` {
			p.advance() // [
			p.advance() // |
			s << `[`
			s << `|`
			for {
				if p.at_end() { return error(p.make_error('unterminated [| inside comment')) }
				c := p.peek()
				p.advance()
				s << c
				if c == `|` && !p.at_end() && p.peek() == `]` {
					s << p.peek()
					p.advance()
					break
				}
			}
			continue
		}
		if b == `[` {
			depth++
			s << b
			p.advance()
		} else if b == `]` && depth == 0 {
			break
		} else if b == `]` {
			depth--
			s << b
			p.advance()
		} else {
			s << b
			p.advance()
		}
	}
	return s.bytestr()
}

fn (mut p Parser) expect(expected u8) ! {
	if p.at_end() {
		return error(p.make_error("expected '${rune(expected)}' got EOF"))
	}
	b := p.peek()
	if b != expected {
		return error(p.make_error("expected '${rune(expected)}' got '${rune(b)}'"))
	}
	p.advance()
}

fn (mut p Parser) read_hex_digits() !string {
	mut s := []u8{}
	for !p.at_end() {
		b := p.peek()
		if (b >= `0` && b <= `9`) || (b >= `a` && b <= `f`) || (b >= `A` && b <= `F`) {
			s << b
			p.advance()
		} else {
			break
		}
	}
	if s.len == 0 { return error(p.make_error('expected hex digits')) }
	return s.bytestr()
}

fn (mut p Parser) read_dec_digits() !string {
	mut s := []u8{}
	for !p.at_end() {
		b := p.peek()
		if b >= `0` && b <= `9` {
			s << b
			p.advance()
		} else {
			break
		}
	}
	if s.len == 0 { return error(p.make_error('expected decimal digits')) }
	return s.bytestr()
}

// ── [| ... |] block content ───────────────────────────────────────────────────

fn (mut p Parser) parse_block_content() !Node {
	p.advance() // consume '|'
	mut items := []Node{}
	mut text_buf := []u8{}
	for {
		if p.at_end() { return error(p.make_error('unterminated block content')) }
		b := p.peek()
		if b == `|` && p.peek2() == `]` {
			p.advance() // '|'
			p.advance() // ']'
			break
		}
		if b == `[` {
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			child := p.parse_bracket_node()!
			items << child
		} else {
			text_buf << b
			p.advance()
		}
	}
	if text_buf.len > 0 {
		items << TextNode{ value: text_buf.bytestr() }
	}
	return BlockContentNode{ items: items }
}

// ── ''' triple-quoted string ──────────────────────────────────────────────────

fn (mut p Parser) read_triple_quoted() !Node {
	p.advance() // consume first '
	p.advance() // consume second '
	p.advance() // consume third '
	mut s := []u8{}
	for {
		if p.at_end() { return error(p.make_error('unterminated triple-quoted string')) }
		b := p.peek()
		if b == `'` && p.pos + 3 <= p.src.len && p.src[p.pos] == `'` && p.src[p.pos+1] == `'` && p.src[p.pos+2] == `'` {
			p.pos += 3
			p.col += 3
			break
		}
		s << b
		p.advance()
	}
	value := strip_common_indent(s.bytestr())
	return TextNode{ value: value }
}

fn strip_common_indent(s string) string {
	lines := s.split('\n')
	// 1. Strip one leading newline
	start := if lines.len > 0 && lines[0].trim_space() == '' { 1 } else { 0 }
	// 2. Strip one trailing newline
	end := if lines.len > start && lines[lines.len-1].trim_space() == '' { lines.len - 1 } else { lines.len }
	content := lines[start..end]
	if content.len == 0 { return '' }
	// 3. Find common leading whitespace of non-blank lines
	mut min_indent := 999999
	for line in content {
		if line.trim_space().len > 0 {
			indent := line.len - line.trim_left(' \t').len
			if indent < min_indent { min_indent = indent }
		}
	}
	if min_indent == 999999 { min_indent = 0 }
	mut result := []string{}
	for line in content {
		if line.len >= min_indent {
			result << line[min_indent..]
		} else {
			result << line.trim_left(' \t')
		}
	}
	return result.join('\n')
}

// ── Collection literals (v0.6.0 / grammar v3.6 / ADR 0017) ─────────────────
//
// Source-text forms:
//   SequenceLiteral [56a]  ( item, item, … )    — parens, flat
//   ArrayLiteral    [56b]  [ item, item, … ]    — brackets, nested-preserving
//   MapLiteral      [56c]  { key: value, … }    — braces, atomic-keyed
//
// Disambiguation (grammar [50.D] for `[…]`; comma-marker / colon-marker
// for `(…)` / `{…}`):
//   - `[…]`: empty `[]` or any depth-0 `,` before `=`/`]` → ArrayLiteral;
//     `=` first → Element with attrs; `]` first with content → Element.
//   - `(…)`: empty `()` or depth-0 `,` before `)` → SequenceLiteral.
//     Without those markers, `(text)` parses as body text — no
//     incompatibility with v3.5-and-earlier parens-in-text.
//   - `{…}`: empty `{}` or depth-0 `:` before `}` → MapLiteral.
//     Without those markers, `{text}` parses as body text.
//
// Sequence-flatten (CXDM §1.2): the parser delivers SequenceNode items
// already flattened — nested `((a,b), c)` builds a 3-item SequenceNode
// `(a, b, c)`.

// peek_is_array_literal scans forward from the just-consumed `[` to
// decide between ArrayLiteral and Element. Does not consume input.
// Returns true for ArrayLiteral (including empty `[]`); false for
// Element. Tracks nested brackets / parens / braces and quoted regions
// so internal separators at non-zero depth don't confuse the scan.
fn (p &Parser) peek_is_array_literal() bool {
	mut i := p.pos
	for i < p.src.len && is_ws(p.src[i]) { i++ }
	if i >= p.src.len { return false }
	if p.src[i] == `]` { return true } // empty [] → empty array
	mut depth := 0
	mut quote := u8(0)
	for i < p.src.len {
		b := p.src[i]
		if quote != 0 {
			if b == `\\` && i + 1 < p.src.len { i += 2; continue }
			if b == quote { quote = 0 }
			i++
			continue
		}
		if b == `'` || b == `"` {
			quote = b
			i++
			continue
		}
		if depth == 0 {
			if b == `,` { return true }
			if b == `=` { return false }
			if b == `]` { return false }
		}
		if b == `[` || b == `(` || b == `{` {
			depth++
			i++
			continue
		}
		if b == `]` || b == `)` || b == `}` {
			if depth > 0 { depth-- }
			i++
			continue
		}
		i++
	}
	return false
}

// peek_is_sequence_literal_at_paren scans forward from the current `(`
// to decide between SequenceLiteral and body text. Does not consume.
// Returns true if shape is `()` (empty) or contains a depth-0 `,`
// before the matching `)`.
fn (p &Parser) peek_is_sequence_literal_at_paren() bool {
	if p.peek() != `(` { return false }
	mut i := p.pos + 1
	for i < p.src.len && is_ws(p.src[i]) { i++ }
	if i < p.src.len && p.src[i] == `)` { return true }
	mut depth := 0
	mut quote := u8(0)
	for i < p.src.len {
		b := p.src[i]
		if quote != 0 {
			if b == `\\` && i + 1 < p.src.len { i += 2; continue }
			if b == quote { quote = 0 }
			i++
			continue
		}
		if b == `'` || b == `"` {
			quote = b
			i++
			continue
		}
		if depth == 0 {
			if b == `,` { return true }
			if b == `)` { return false }
		}
		if b == `[` || b == `(` || b == `{` { depth++; i++; continue }
		if b == `]` || b == `}` { if depth > 0 { depth-- }; i++; continue }
		if b == `)` { if depth > 0 { depth-- }; i++; continue }
		i++
	}
	return false
}

// peek_is_map_literal_at_brace scans forward from the current `{` to
// decide between MapLiteral and body text. Returns true if shape is
// `{}` (empty) or contains a depth-0 `:` before the matching `}`.
fn (p &Parser) peek_is_map_literal_at_brace() bool {
	if p.peek() != `{` { return false }
	mut i := p.pos + 1
	for i < p.src.len && is_ws(p.src[i]) { i++ }
	if i < p.src.len && p.src[i] == `}` { return true }
	mut depth := 0
	mut quote := u8(0)
	for i < p.src.len {
		b := p.src[i]
		if quote != 0 {
			if b == `\\` && i + 1 < p.src.len { i += 2; continue }
			if b == quote { quote = 0 }
			i++
			continue
		}
		if b == `'` || b == `"` {
			quote = b
			i++
			continue
		}
		if depth == 0 {
			if b == `:` { return true }
			if b == `}` { return false }
		}
		if b == `[` || b == `(` || b == `{` { depth++; i++; continue }
		if b == `]` || b == `)` { if depth > 0 { depth-- }; i++; continue }
		if b == `}` { if depth > 0 { depth-- }; i++; continue }
		i++
	}
	return false
}

// parse_array_literal parses an ArrayLiteral [56b]. The opening `[`
// has already been consumed by parse_bracket_node. Comma-separated
// items, trailing comma optional, closing `]` required.
fn (mut p Parser) parse_array_literal() !Node {
	p.skip_ws_and_line_comments()
	mut items := []Node{}
	if !p.at_end() && p.peek() == `]` {
		p.advance() // consume ']'
		return Node(ArrayNode{ items: items })
	}
	for {
		p.skip_ws_and_line_comments()
		if p.at_end() { return error(p.make_error('unterminated array literal')) }
		if p.peek() == `]` { break } // trailing comma case
		items << p.parse_collection_item()!
		p.skip_ws_and_line_comments()
		if p.at_end() { return error(p.make_error('unterminated array literal')) }
		b := p.peek()
		if b == `,` { p.advance(); continue }
		if b == `]` { break }
		return error(p.make_error('expected `,` or `]` in array literal'))
	}
	p.expect(`]`)!
	return Node(ArrayNode{ items: items })
}

// parse_sequence_literal parses a SequenceLiteral [56a]. The parser is
// positioned at `(`. Nested sequences flatten per CXDM §1.2.
fn (mut p Parser) parse_sequence_literal() !Node {
	p.advance() // consume '('
	p.skip_ws_and_line_comments()
	mut items := []Node{}
	if !p.at_end() && p.peek() == `)` {
		p.advance()
		return Node(SequenceNode{ items: items })
	}
	for {
		p.skip_ws_and_line_comments()
		if p.at_end() { return error(p.make_error('unterminated sequence literal')) }
		if p.peek() == `)` { break }
		item := p.parse_collection_item()!
		if item is SequenceNode {
			inner := item as SequenceNode
			for sub in inner.items { items << sub }
		} else {
			items << item
		}
		p.skip_ws_and_line_comments()
		if p.at_end() { return error(p.make_error('unterminated sequence literal')) }
		b := p.peek()
		if b == `,` { p.advance(); continue }
		if b == `)` { break }
		return error(p.make_error('expected `,` or `)` in sequence literal'))
	}
	p.expect(`)`)!
	return Node(SequenceNode{ items: items })
}

// parse_map_literal parses a MapLiteral [56c]. The parser is positioned
// at `{`. Duplicate keys (same type-tag + canonical-string form) are
// W014 / parse error per ADR 0017 §D4.
fn (mut p Parser) parse_map_literal() !Node {
	p.advance() // consume '{'
	p.skip_ws_and_line_comments()
	mut entries := []MapEntry{}
	mut seen_keys := map[string]bool{}
	if !p.at_end() && p.peek() == `}` {
		p.advance()
		return Node(MapNode{ entries: entries })
	}
	for {
		p.skip_ws_and_line_comments()
		if p.at_end() { return error(p.make_error('unterminated map literal')) }
		if p.peek() == `}` { break }
		entry := p.parse_map_entry()!
		marker := '${scalar_type_name(entry.key_type)}:${scalar_value_str(entry.key_value)}'
		if marker in seen_keys {
			return error(p.make_error('W014: duplicate map key'))
		}
		seen_keys[marker] = true
		entries << entry
		p.skip_ws_and_line_comments()
		if p.at_end() { return error(p.make_error('unterminated map literal')) }
		b := p.peek()
		if b == `,` { p.advance(); continue }
		if b == `}` { break }
		return error(p.make_error('expected `,` or `}` in map literal'))
	}
	p.expect(`}`)!
	return Node(MapNode{ entries: entries })
}

// parse_map_entry parses one MapEntry [56f] — `MapKey : BodyItem`.
fn (mut p Parser) parse_map_entry() !MapEntry {
	p.skip_ws_and_line_comments()
	key_type, key_value := p.read_map_key()!
	p.skip_ws_and_line_comments()
	if p.at_end() || p.peek() != `:` {
		return error(p.make_error('expected `:` after map key'))
	}
	p.advance() // consume ':'
	p.skip_ws_and_line_comments()
	value := p.parse_collection_item()!
	return MapEntry{
		key_type:  key_type
		key_value: key_value
		value:     value
	}
}

// read_map_key consumes a MapKey [56g] — a Name, QuotedText, or atomic
// Scalar. Returns the resolved key type + value. Bare-name keys carry
// type-tag `string` per ADR 0017 §D4 (names sugar for string keys).
fn (mut p Parser) read_map_key() !(ScalarType, ScalarValue) {
	if p.at_end() { return error(p.make_error('expected map key')) }
	b := p.peek()
	if b == `'` || b == `"` {
		s := p.read_quoted_text()!
		return ScalarType.string_type, ScalarValue(s)
	}
	mut s := []u8{}
	for !p.at_end() {
		b2 := p.peek()
		if b2 == `:` || b2 == `,` || b2 == `}` || is_ws(b2) { break }
		s << b2
		p.advance()
	}
	if s.len == 0 {
		return error(p.make_error('expected map key'))
	}
	tok := s.bytestr()
	if scalar := try_autotype(tok) {
		if scalar.data_type == .null_type {
			return error(p.make_error('W014: null is not a valid map key'))
		}
		return scalar.data_type, scalar.value
	}
	return ScalarType.string_type, ScalarValue(tok)
}

// parse_collection_item parses one slot inside a (), [], or {}
// collection per ADR 0017 §D5 / §D7 (slot-as-body resolution 1.d,
// 2026-05-12). A slot is a body fragment — a sequence of CX body
// items terminating at the next depth-0 `,` `]` `)` `}`. Single-item
// slots return the lone item directly (with bare-token autotyping
// applied); multi-item slots wrap their items in a SequenceNode (the
// "slot encoding" for mixed content — the CXL evaluator unwraps at
// use-site to render the body in order).
//
// Examples:
//   `1` (slot of `[1, 2, 3]`)                → ScalarNode(int 1)
//   `@stock > 0` (slot of `[@stock > 0, …]`) → TextNode("@stock > 0")
//                                              (CXL evaluator parses
//                                              as CXPath at eval time)
//   `In stock: [?=@stock]`                   → SequenceNode[
//                                                TextNode("In stock: "),
//                                                InterpolationNode("@stock")
//                                              ]
//   `[a, b]` (nested array)                  → ArrayNode[a, b]
//
// Empty slots (consecutive commas) are a parse error per ADR 0017 §D5
// — trailing commas are permitted at the slot list level but empty
// slots between them are not values.
fn (mut p Parser) parse_collection_item() !Node {
	items := p.parse_collection_slot_body()!
	if items.len == 0 {
		return error(p.make_error('empty collection slot'))
	}
	if items.len == 1 {
		return items[0]
	}
	return Node(SequenceNode{ items: items })
}

// parse_collection_slot_body consumes the contents of one slot — a
// body-item run terminated by the next depth-0 `,` `)` `]` `}`. The
// loop mirrors parse_body's structure (text-buf coalescing of
// consecutive bare tokens with single-space separation, structured
// nodes pushed inline) but with the collection-slot terminator set.
// Bare-token-only single-token slots get try_autotype'd as a scalar;
// multi-token / mixed-content slots return their items unmodified.
fn (mut p Parser) parse_collection_slot_body() ![]Node {
	mut items := []Node{}
	mut text_buf := []u8{}
	mut has_child := false
	mut after_non_text := false
	for {
		if p.at_end() { break }
		had_ws := is_ws(p.peek())
		p.skip_ws_and_line_comments()
		if p.at_end() { break }
		b := p.peek()
		if b == `,` || b == `]` || b == `)` || b == `}` { break }

		if b == `[` {
			has_child = true
			if had_ws && text_buf.len > 0 { text_buf << ` ` }
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			child := p.parse_bracket_node()!
			items << child
			after_non_text = true
			continue
		}

		if b == `'` || b == `"` {
			if had_ws && text_buf.len > 0 { text_buf << ` ` }
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			if p.pos + 3 <= p.src.len && p.src[p.pos] == `'`
				&& p.src[p.pos+1] == `'` && p.src[p.pos+2] == `'` {
				n := p.read_triple_quoted()!
				items << n
			} else {
				quoted := p.read_quoted_text()!
				items << TextNode{ value: quoted }
			}
			after_non_text = true
			continue
		}

		if b == `(` && p.peek_is_sequence_literal_at_paren() {
			if had_ws && text_buf.len > 0 { text_buf << ` ` }
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			items << p.parse_sequence_literal()!
			after_non_text = true
			continue
		}

		if b == `{` && p.peek_is_map_literal_at_brace() {
			if had_ws && text_buf.len > 0 { text_buf << ` ` }
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			items << p.parse_map_literal()!
			after_non_text = true
			continue
		}

		if b == `&` {
			if had_ws {
				if text_buf.len > 0 || after_non_text { text_buf << ` ` }
			}
			n := p.parse_amp_node()!
			match n {
				TextNode {
					text_buf << n.value.bytes()
					after_non_text = false
				}
				else {
					if text_buf.len > 0 {
						items << TextNode{ value: text_buf.bytestr() }
						text_buf = []u8{}
					}
					items << n
					after_non_text = true
				}
			}
			continue
		}

		tok := p.read_slot_token()!
		if text_buf.len > 0 {
			if had_ws { text_buf << ` ` }
		} else if after_non_text && had_ws {
			text_buf << ` `
		}
		text_buf << tok.bytes()
		after_non_text = false
	}

	if text_buf.len > 0 {
		text_val := text_buf.bytestr()
		// Single bare-token slot — autotype if the buffer is exactly
		// one scalar literal. Multi-token / mixed-content slots keep
		// the raw text run (the CXL evaluator parses it as CXPath at
		// eval time per spec/cxl.md §7).
		if !has_child && items.len == 0 {
			if scalar := try_autotype(text_val) {
				items << scalar
				return items
			}
		}
		items << TextNode{ value: text_val }
	}

	return items
}

// read_slot_token reads one bare-text token inside a collection slot.
// Terminates at slot delimiters (`,` `]` `)` `}`), whitespace, and at
// the introducers handled by the outer slot loop (`[` `(` `{` `'` `"`
// `&`). Structured nodes (brackets, quotes, etc.) are dispatched by
// the outer loop rather than absorbed here, so this is a strictly
// bare-text-run reader.
fn (mut p Parser) read_slot_token() !string {
	mut s := []u8{}
	for !p.at_end() {
		b := p.peek()
		if is_ws(b) || b == `,` || b == `]` || b == `)` || b == `}` { break }
		if b == `[` || b == `'` || b == `"` || b == `&` { break }
		if b == `(` && p.peek_is_sequence_literal_at_paren() { break }
		if b == `{` && p.peek_is_map_literal_at_brace() { break }
		s << b
		p.advance()
	}
	if s.len == 0 {
		return error(p.make_error('expected token in collection slot'))
	}
	return s.bytestr()
}
