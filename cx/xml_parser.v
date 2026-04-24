module cx

import strconv

// ── XML Parser ────────────────────────────────────────────────────────────────
// Parses XML to the same AST as the CX parser.

pub fn parse_xml(src string) !Document {
	if src.contains('\n---\n') {
		return error('use parse_xml_stream for multi-doc XML input')
	}
	mut p := new_xml_parser(src)
	return p.parse_xml_document()
}

pub fn parse_xml_stream(src string) ![]Document {
	parts := src.split('\n---\n')
	mut docs := []Document{}
	for part in parts {
		trimmed := part.trim_space()
		if trimmed.len == 0 { continue }
		mut p := new_xml_parser(trimmed)
		doc := p.parse_xml_document()!
		docs << doc
	}
	return docs
}

pub fn parse_xml_cx(src string) !ParseResult {
	if src.contains('\n---\n') {
		docs := parse_xml_stream(src)!
		return ParseResult{ multi: docs, is_multi: true }
	}
	mut p := new_xml_parser(src)
	doc := p.parse_xml_document()!
	return ParseResult{ single: doc, is_multi: false }
}

struct XmlParser {
mut:
	src  []u8
	pos  int
	line int
	col  int
}

fn new_xml_parser(src string) XmlParser {
	return XmlParser{ src: src.bytes(), pos: 0, line: 1, col: 1 }
}

fn (p &XmlParser) at_end() bool { return p.pos >= p.src.len }

fn (p &XmlParser) peek() u8 {
	if p.pos < p.src.len { return p.src[p.pos] }
	return 0
}

fn (mut p XmlParser) advance() {
	if p.pos >= p.src.len { return }
	b := p.src[p.pos]
	p.pos++
	if b == `\n` { p.line++; p.col = 1 } else { p.col++ }
}

fn (mut p XmlParser) skip_ws() {
	for !p.at_end() && is_ws(p.peek()) { p.advance() }
}

fn (p &XmlParser) err(msg string) string {
	return '${p.line}:${p.col}: ${msg}'
}

fn (mut p XmlParser) parse_xml_document() !Document {
	mut prolog := []Node{}
	mut doctype := ?DoctypeDecl(none)
	mut elements := []Node{}

	for {
		p.skip_ws()
		if p.at_end() { break }
		b := p.peek()
		if b == `<` {
			p.advance()
			b2 := p.peek()
			if b2 == `?` {
				// PI or XML decl
				p.advance()
				n := p.parse_xml_pi()!
				if is_prolog_node_type(n) { prolog << n } else { elements << n }
			} else if b2 == `!` {
				p.advance()
				if p.peek() == `-` {
					// comment
					n := p.parse_xml_comment()!
					if elements.len == 0 { prolog << n } else { elements << n }
				} else if p.peek() == `[` {
					// CDATA or conditional
					elements << p.parse_xml_cdata()!
				} else {
					// DOCTYPE or other decl
					kw := p.xml_read_name()!
					if kw == 'DOCTYPE' {
						dt := p.parse_xml_doctype()!
						doctype = dt
					} else if kw == 'ENTITY' {
						elements << p.parse_xml_entity_decl()!
					} else {
						// skip unknown decl
						for !p.at_end() && p.peek() != `>` { p.advance() }
						if !p.at_end() { p.advance() }
					}
				}
			} else if b2 == `/` {
				// End tag — error at document level
				return error(p.err('unexpected end tag at document level'))
			} else {
				// Element
				n := p.parse_xml_element()!
				elements << n
			}
		} else if b == `&` {
			n := p.parse_xml_ref()!
			elements << n
		} else {
			// Skip whitespace-only text at document level
			p.advance()
		}
	}

	return Document{ prolog: prolog, doctype: doctype, elements: elements }
}

fn (mut p XmlParser) parse_xml_pi() !Node {
	name := p.xml_read_name()!
	p.skip_ws()
	mut data := []u8{}
	for !p.at_end() {
		b := p.peek()
		if b == `?` {
			p.advance()
			if p.peek() == `>` { p.advance(); break }
			data << `?`
		} else {
			data << b
			p.advance()
		}
	}
	data_str := data.bytestr().trim_space()
	if name == 'xml' {
		// parse XML declaration attributes
		mut attrs := []Attribute{}
		mut ap := new_xml_parser(data_str)
		for {
			ap.skip_ws()
			if ap.at_end() { break }
			aname := ap.xml_read_name() or { break }
			ap.skip_ws()
			ap.xml_expect(`=`) or { break }
			ap.skip_ws()
			aval := ap.xml_read_quoted() or { break }
			attrs << Attribute{ name: aname, value: ScalarValue(aval), data_type: none }
		}
		version := find_attr_value(attrs, 'version') or { '1.0' }
		encoding := find_attr_value(attrs, 'encoding')
		standalone := find_attr_value(attrs, 'standalone')
		return XMLDeclNode{ version: version, encoding: encoding, standalone: standalone }
	}
	if name == 'cx' {
		mut attrs := []Attribute{}
		mut ap := new_xml_parser(data_str)
		for {
			ap.skip_ws()
			if ap.at_end() { break }
			aname := ap.xml_read_name() or { break }
			ap.skip_ws()
			ap.xml_expect(`=`) or { break }
			ap.skip_ws()
			aval := ap.xml_read_quoted() or { break }
			attrs << Attribute{ name: aname, value: ScalarValue(aval), data_type: none }
		}
		return CXDirectiveNode{ attrs: attrs }
	}
	d := if data_str.len == 0 { ?string(none) } else { ?string(data_str) }
	return PINode{ target: name, data: d }
}

fn (mut p XmlParser) parse_xml_comment() !Node {
	// <!-- ... -->
	p.advance() // '-'
	p.advance() // '-'
	mut val := []u8{}
	for !p.at_end() {
		b := p.peek()
		if b == `-` {
			p.advance()
			if p.peek() == `-` {
				p.advance()
				if p.peek() == `>` { p.advance(); break }
				val << `-`; val << `-`
			} else {
				val << `-`
			}
		} else {
			val << b
			p.advance()
		}
	}
	return CommentNode{ value: val.bytestr() }
}

fn (mut p XmlParser) parse_xml_cdata() !Node {
	// <![CDATA[...]]>
	p.advance() // '['
	// read CDATA keyword
	for !p.at_end() && p.peek() != `[` { p.advance() }
	if !p.at_end() { p.advance() } // consume '['
	mut val := []u8{}
	for !p.at_end() {
		b := p.peek()
		if b == `]` {
			p.advance()
			if p.peek() == `]` {
				p.advance()
				if p.peek() == `>` { p.advance(); break }
				val << `]`; val << `]`
			} else {
				val << `]`
			}
		} else {
			val << b
			p.advance()
		}
	}
	return RawTextNode{ value: val.bytestr() }
}

fn (mut p XmlParser) parse_xml_doctype() !DoctypeDecl {
	p.skip_ws()
	name := p.xml_read_name()!
	p.skip_ws()
	mut ext := ?ExternalID(none)
	b := p.peek()
	if b == `S` || b == `P` {
		ext = p.parse_xml_external_id()
	}
	p.skip_ws()
	mut int_subset := []Node{}
	if !p.at_end() && p.peek() == `[` {
		p.advance()
		for {
			p.skip_ws()
			if p.at_end() { break }
			b2 := p.peek()
			if b2 == `]` { p.advance(); break }
			if b2 == `<` {
				p.advance()
				if p.peek() == `!` {
					p.advance()
					kw := p.xml_read_name() or { break }
					match kw {
						'ENTITY' { int_subset << p.parse_xml_entity_decl()! }
						'ELEMENT' {
							p.skip_ws()
							ename := p.xml_read_name() or { '' }
							p.skip_ws()
							mut spec := []u8{}
							for !p.at_end() && p.peek() != `>` { spec << p.peek(); p.advance() }
							p.advance() // '>'
							int_subset << ElementDeclNode{ name: ename, contentspec: spec.bytestr().trim_space() }
						}
						else {
							for !p.at_end() && p.peek() != `>` { p.advance() }
							if !p.at_end() { p.advance() }
						}
					}
				} else {
					for !p.at_end() && p.peek() != `>` { p.advance() }
					if !p.at_end() { p.advance() }
				}
			} else {
				p.advance()
			}
		}
	}
	p.skip_ws()
	if !p.at_end() && p.peek() == `>` { p.advance() }
	return DoctypeDecl{ name: name, external_id: ext, int_subset: int_subset }
}

fn (mut p XmlParser) parse_xml_external_id() ?ExternalID {
	if p.pos + 6 <= p.src.len && p.src[p.pos..p.pos+6] == 'SYSTEM'.bytes() {
		p.pos += 6; p.col += 6
		p.skip_ws()
		system := p.xml_read_quoted() or { return none }
		return ExternalID{ system: system }
	}
	if p.pos + 6 <= p.src.len && p.src[p.pos..p.pos+6] == 'PUBLIC'.bytes() {
		p.pos += 6; p.col += 6
		p.skip_ws()
		public := p.xml_read_quoted() or { return none }
		p.skip_ws()
		if !p.at_end() && (p.peek() == `"` || p.peek() == `'`) {
			system := p.xml_read_quoted() or { return ExternalID{ public: public } }
			return ExternalID{ public: public, system: system }
		}
		return ExternalID{ public: public }
	}
	return none
}

fn (mut p XmlParser) parse_xml_entity_decl() !Node {
	p.skip_ws()
	mut kind := EntityKind.ge
	if !p.at_end() && p.peek() == `%` {
		p.advance(); p.skip_ws()
		kind = EntityKind.pe
	}
	name := p.xml_read_name()!
	p.skip_ws()
	b := p.peek()
	def := if b == `S` || b == `P` {
		ext := p.parse_xml_external_id() or { return error(p.err('expected external ID')) }
		p.skip_ws()
		mut ndata := ?string(none)
		if p.pos + 5 <= p.src.len && p.src[p.pos..p.pos+5] == 'NDATA'.bytes() {
			p.pos += 5; p.col += 5; p.skip_ws()
			nd := p.xml_read_name()!
			ndata = nd
		}
		EntityDef(ExternalEntityDef{ external_id: ext, ndata: ndata })
	} else {
		val := p.xml_read_quoted()!
		EntityDef(val)
	}
	p.skip_ws()
	if !p.at_end() && p.peek() == `>` { p.advance() }
	return EntityDeclNode{ kind: kind, name: name, def: def }
}

fn (mut p XmlParser) parse_xml_element() !Node {
	name := p.xml_read_name()!
	mut cx_anchor := ?string(none)
	mut cx_merge := ?string(none)
	mut cx_type := ?string(none)
	mut attrs := []Attribute{}

	// Read attributes
	for {
		p.skip_ws()
		if p.at_end() { break }
		b := p.peek()
		if b == `>` || b == `/` { break }
		aname := p.xml_read_name() or { break }
		p.skip_ws()
		p.xml_expect(`=`) or { break }
		p.skip_ws()
		aval := p.xml_read_quoted() or { break }

		if aname == 'cx:anchor' { cx_anchor = aval }
		else if aname == 'cx:merge' { cx_merge = aval }
		else if aname == 'cx:type' { cx_type = aval }
		else {
			// Convert xmlns attrs back to ns: form
			cx_name := xmlns_to_cx_ns(aname)
			attrs << Attribute{ name: cx_name, value: ScalarValue(aval), data_type: none }
		}
	}

	// cx:alias → AliasNode (may appear at any level)
	if name == 'cx:alias' {
		alias_name := find_attr_value(attrs, 'name') or { '' }
		p.skip_ws()
		if !p.at_end() && p.peek() == `/` { p.advance() }
		p.xml_expect(`>`)!
		return AliasNode{ name: alias_name }
	}

	p.skip_ws()
	b := p.peek()
	if b == `/` {
		p.advance() // '/'
		p.xml_expect(`>`)!
		return Element{ name: name, anchor: cx_anchor, merge: cx_merge, data_type: cx_type, attrs: attrs, items: [] }
	}

	p.xml_expect(`>`)!

	// Parse children
	mut items := []Node{}
	p.parse_xml_content(name, cx_type, mut items)!

	// If cx_type is an array type, items should already be Scalar nodes
	return Element{ name: name, anchor: cx_anchor, merge: cx_merge, data_type: cx_type, attrs: attrs, items: items }
}

fn (mut p XmlParser) parse_xml_content(parent_name string, cx_type ?string, mut items []Node) ! {
	is_array := if cxt := cx_type { cxt.ends_with('[]') } else { false }
	arr_elem_type := if is_array {
		if cxt := cx_type { cxt[..cxt.len-2] } else { 'string' }
	} else {
		'string'
	}
	mut text_buf := []u8{}

	for {
		if p.at_end() { break }
		b := p.peek()
		if b == `<` {
			// flush text
			if text_buf.len > 0 {
				tv := text_buf.bytestr()
				text_buf = []u8{}
				if tv.trim_space().len > 0 || items.len > 0 || items.any(it is Element) {
					if is_array {
						// each token in text is a scalar
						for tok in tv.split_any(' \t\r\n').filter(it.len > 0) {
							items << coerce_scalar(arr_elem_type, tok)
						}
					} else {
						// apply explicit cx:type coerce if present
						cxt_val := cx_type or { '' }
						if cxt_val.len > 0 && !cxt_val.ends_with('[]') && items.len == 0 {
							items << coerce_scalar(cxt_val, tv.trim_space())
						} else {
							items << TextNode{ value: tv }
						}
					}
				}
			}
			p.advance()
			b2 := p.peek()
			if b2 == `/` {
				// End tag
				p.advance()
				ename := p.xml_read_name() or { '' }
				p.skip_ws()
				if !p.at_end() && p.peek() == `>` { p.advance() }
				if ename != parent_name {
					return error(p.err('end tag mismatch: expected </${parent_name}> got </${ename}>'))
				}
				break
			} else if b2 == `!` {
				p.advance()
				if p.peek() == `-` {
					n := p.parse_xml_comment()!
					items << n
				} else if p.peek() == `[` {
					n := p.parse_xml_cdata()!
					items << n
				} else {
					for !p.at_end() && p.peek() != `>` { p.advance() }
					if !p.at_end() { p.advance() }
				}
			} else if b2 == `?` {
				p.advance()
				n := p.parse_xml_pi()!
				items << n
			} else {
				// Check for cx:alias
				if p.pos + 7 < p.src.len {
					prefix := p.src[p.pos..p.pos+8].bytestr()
					if prefix == 'cx:alias' {
						// parse cx:alias element
						p.pos += 8; p.col += 8
						p.skip_ws()
						mut alias_name := ''
						for {
							p.skip_ws()
							if p.at_end() { break }
							b3 := p.peek()
							if b3 == `/` || b3 == `>` { break }
							aname := p.xml_read_name() or { break }
							p.skip_ws()
							p.xml_expect(`=`) or { break }
							p.skip_ws()
							aval := p.xml_read_quoted() or { break }
							if aname == 'name' { alias_name = aval }
						}
						if p.peek() == `/` { p.advance() }
						if p.peek() == `>` { p.advance() }
						items << AliasNode{ name: alias_name }
						continue
					}
				}
				// child element
				n := p.parse_xml_element()!
				if is_array {
					// <item>value</item> → Scalar
					if n is Element {
						ne := n as Element
						if ne.name == 'item' {
							text_val := ne.items.filter(it is TextNode).map((it as TextNode).value).join('')
							items << coerce_scalar(arr_elem_type, text_val.trim_space())
						}
					}
				} else {
					items << n
				}
			}
		} else if b == `&` {
			p.advance()
			if p.peek() == `#` {
				p.advance()
				n := p.parse_charref_xml()!
				match n {
					TextNode { text_buf << n.value.bytes() }
					else { items << n }
				}
			} else {
				ref_name := p.xml_read_name() or { '' }
				p.xml_expect(`;`) or {}
				// Preserve entity refs as EntityRefNode
				if text_buf.len > 0 {
					items << TextNode{ value: text_buf.bytestr() }
					text_buf = []u8{}
				}
				items << EntityRefNode{ name: ref_name }
			}
		} else {
			text_buf << b
			p.advance()
		}
	}

	// Flush remaining text
	if text_buf.len > 0 {
		tv := text_buf.bytestr()
		if is_array {
			for tok in tv.split_any(' \t\r\n').filter(it.len > 0) {
				items << coerce_scalar(arr_elem_type, tok)
			}
		} else {
			// Handle single-token scalar auto-type or explicit type
			cxt_val := cx_type or { '' }
			if cxt_val.len > 0 && !cxt_val.ends_with('[]') {
				items << coerce_scalar(cxt_val, tv.trim_space())
			} else if items.len == 0 {
				// try autotype
				if scalar := try_autotype(tv.trim_space()) {
					items << scalar
				} else {
					if tv.trim_space().len > 0 || tv.len > 0 {
						items << TextNode{ value: tv }
					}
				}
			} else {
				if tv.trim_space().len > 0 || tv.len > 0 {
					items << TextNode{ value: tv }
				}
			}
		}
	}
	// Strip whitespace-only text nodes when element has child elements (ignorable whitespace)
	if items.any(it is Element) {
		items = items.filter(!(it is TextNode && (it as TextNode).value.trim_space().len == 0))
	}
}

fn (mut p XmlParser) parse_charref_xml() !Node {
	codepoint := if !p.at_end() && (p.peek() == `x` || p.peek() == `X`) {
		p.advance()
		mut hex := []u8{}
		for !p.at_end() && p.peek() != `;` { hex << p.peek(); p.advance() }
		if !p.at_end() { p.advance() }
		u32(strconv.parse_int(hex.bytestr(), 16, 64) or { 63 })
	} else {
		mut dec := []u8{}
		for !p.at_end() && p.peek() != `;` { dec << p.peek(); p.advance() }
		if !p.at_end() { p.advance() }
		u32(dec.bytestr().u64())
	}
	return TextNode{ value: rune_to_utf8(codepoint) }
}

fn (mut p XmlParser) parse_xml_ref() !Node {
	p.advance() // '&'
	if p.peek() == `#` {
		p.advance()
		return p.parse_charref_xml()!
	}
	name := p.xml_read_name()!
	p.xml_expect(`;`)!
	return EntityRefNode{ name: name }
}

fn xmlns_to_cx_ns(name string) string {
	if name == 'xmlns' { return 'ns:default' }
	if name.starts_with('xmlns:') { return 'ns:${name[6..]}' }
	return name
}

fn (mut p XmlParser) xml_read_name() !string {
	mut s := []u8{}
	for !p.at_end() {
		b := p.peek()
		if is_name_char(b) { s << b; p.advance() } else { break }
	}
	if s.len == 0 { return error(p.err('expected XML name')) }
	return s.bytestr()
}

fn (mut p XmlParser) xml_read_quoted() !string {
	if p.at_end() { return error(p.err('expected quote')) }
	q := p.peek()
	if q != `"` && q != `'` { return error(p.err('expected quote')) }
	p.advance()
	mut s := []u8{}
	for !p.at_end() {
		b := p.peek()
		if b == q { p.advance(); break }
		s << b
		p.advance()
	}
	return s.bytestr()
}

fn (mut p XmlParser) xml_expect(expected u8) ! {
	if p.at_end() { return error(p.err("expected '${rune(expected)}' got EOF")) }
	b := p.peek()
	if b != expected { return error(p.err("expected '${rune(expected)}' got '${rune(b)}'")) }
	p.advance()
}
