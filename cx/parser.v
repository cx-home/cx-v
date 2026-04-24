module cx

import strconv

// ── Parser struct ─────────────────────────────────────────────────────────────

struct Parser {
mut:
	src  []u8
	pos  int
	line int
	col  int
}

fn new_parser(src string) Parser {
	return Parser{
		src:  src.bytes()
		pos:  0
		line: 1
		col:  1
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

	p.skip_ws()

	for {
		p.skip_ws()
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

	for {
		p.skip_ws()
		if p.at_end() { break }
		if p.pos + 3 <= p.src.len && p.src[p.pos] == `-` && p.src[p.pos+1] == `-` && p.src[p.pos+2] == `-` {
			break
		}
		n := p.parse_node()!
		elements << n
	}

	return Document{ prolog: prolog, doctype: doctype, elements: elements }
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
		else { p.parse_element()! }
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
	target := p.read_name()!
	return match target {
		'xml' { p.parse_xml_decl()! }
		'cx'  { p.parse_cx_directive()! }
		else  { p.parse_pi_body(target)! }
	}
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
	attrs := p.read_attr_list_until(`]`)!
	p.expect(`]`)!
	return CXDirectiveNode{ attrs: attrs }
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
	raw_name := p.read_name()!
	name := normalize_doc_element_name(raw_name)
	mut anchor := ?string(none)
	mut merge := ?string(none)
	mut data_type := ?string(none)
	mut attrs := []Attribute{}

	for {
		p.skip_ws()
		if p.at_end() { break }
		b := p.peek()
		if b == `]` || b == `[` || b == `#` { break }
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

		if b == `:` {
			p.advance()
			ta := p.read_type_annotation()!
			data_type = ta
			break
		}

		if is_name_start(b) {
			tok := p.read_name()!
			if !p.at_end() && p.peek() == `=` {
				p.advance()
				val, dt := p.read_attr_value_typed()!
				attrs << Attribute{ name: tok, value: val, data_type: dt }
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

	return Element{ name: name, anchor: anchor, merge: merge, data_type: final_dt, attrs: attrs, items: items }
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
		p.skip_ws()

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

fn try_autotype(tok string) ?ScalarNode {
	// hex int: 0x...
	if tok.starts_with('0x') || tok.starts_with('0X') {
		if v := strconv.parse_int(tok[2..], 16, 64) {
			return ScalarNode{ data_type: .int_type, value: ScalarValue(v) }
		}
	}
	if tok.starts_with('-0x') || tok.starts_with('-0X') {
		if v := strconv.parse_int(tok[3..], 16, 64) {
			neg := -v
			return ScalarNode{ data_type: .int_type, value: ScalarValue(neg) }
		}
	}
	// bool and null — checked before float to avoid 'e' in "true"/"false" triggering float path
	if tok == 'true'  { return ScalarNode{ data_type: .bool_type, value: ScalarValue(true) } }
	if tok == 'false' { return ScalarNode{ data_type: .bool_type, value: ScalarValue(false) } }
	if tok == 'null'  { return ScalarNode{ data_type: .null_type, value: ScalarValue(NullValue{}) } }
	// int
	if v := tok.parse_int(10, 64) {
		return ScalarNode{ data_type: .int_type, value: ScalarValue(v) }
	}
	// float (must contain . or e/E to distinguish from int, AND parse successfully)
	if tok.contains('.') || tok.contains('e') || tok.contains('E') {
		fv := strconv.atof64(tok) or { return none }
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

fn coerce_scalar(et string, tok string) ScalarNode {
	return match et {
		'int' {
			v := if tok.starts_with('0x') || tok.starts_with('0X') {
				strconv.parse_int(tok[2..], 16, 64) or { i64(0) }
			} else {
				tok.parse_int(10, 64) or { i64(0) }
			}
			ScalarNode{ data_type: .int_type, value: ScalarValue(v) }
		}
		'float' {
			v := strconv.atof64(tok) or { f64(0.0) }
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

fn (mut p Parser) read_token() !string {
	mut s := []u8{}
	for !p.at_end() {
		b := p.peek()
		if is_ws(b) || b == `]` { break }
		s << b
		p.advance()
	}
	if s.len == 0 {
		return error(p.make_error('expected token'))
	}
	return s.bytestr()
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
