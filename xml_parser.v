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

	mut doc := Document{ prolog: prolog, doctype: doctype, elements: elements }
	resolve_namespaces(mut doc)
	// v3.4: mark attrs whose values match a declared
	// xml:id (now hoisted to Element.id) as is_ref. Without an XML
	// schema we can't disambiguate xs:IDREF from a plain string that
	// happens to match an ID, so we adopt the conservative posture:
	// any attribute whose value matches a known ID becomes a reference.
	// Round-trip lossless against documents whose only ID-shaped
	// attribute values ARE references; would over-promote in the
	// pathological case of a plain string that collides with an ID.
	mark_ref_attrs(mut doc)
	resolve_ids(doc)!
	return doc
}

// mark_ref_attrs walks the document, builds the ID set, then walks
// again marking every attribute whose string value is in the ID set
// as is_ref. v3.4.
// apply_xml_attr_types re-types XML-imported attributes (D3). An entry in
// the `cx:attr-types` sidecar (`name=type`) is authoritative: the value is
// coerced to that type (a `string` entry pins the value to string, blocking
// auto-typing). Every other attribute is auto-typed from its bare lexical
// form — int / float / bool / null / date / datetime — exactly mirroring the
// CX-side attribute auto-typer, so `cx_to_xml → xml_to_cx` round-trips.
// Atom-shaped values are never auto-detected here; atoms arrive only via the
// sidecar (their XML value is the bare name, with no `:` sigil).
fn apply_xml_attr_types(mut attrs []Attribute, spec string) {
	mut typemap := map[string]string{}
	if spec.len > 0 {
		for pair in spec.split(' ') {
			if pair.len == 0 {
				continue
			}
			eq := pair.index('=') or { continue }
			typemap[pair[..eq]] = pair[eq + 1..]
		}
	}
	for mut a in attrs {
		if t := typemap[a.name] {
			if t == 'string' {
				// Explicit string — leave the raw value, no annotation.
				a.set_data_type(none)
			} else {
				a.value = scalar_value_from_str(a.str_value(), t)
				a.set_data_type(t)
			}
			continue
		}
		if sc := try_autotype(a.str_value()) {
			if sc.data_type != .atom_type {
				a.value = sc.value
				a.set_data_type(scalar_type_name(sc.data_type))
			}
		}
	}
}

fn mark_ref_attrs(mut doc Document) {
	mut id_set := map[string]bool{}
	collect_id_set(doc.elements, mut id_set)
	collect_id_set(doc.prolog, mut id_set)
	if id_set.len == 0 { return }
	mark_refs(mut doc.elements, id_set)
	mark_refs(mut doc.prolog, id_set)
}

fn collect_id_set(nodes []Node, mut id_set map[string]bool) {
	for n in nodes {
		if n is Element {
			if id := n.id() { id_set[id] = true }
			collect_id_set(n.items, mut id_set)
		}
	}
}

fn mark_refs(mut nodes []Node, id_set map[string]bool) {
	for mut n in nodes {
		if mut n is Element {
			for mut a in n.attrs {
				if !a.is_ref {
					vstr := scalar_value_str(a.value)
					if vstr in id_set { a.is_ref = true }
				}
			}
			mark_refs(mut n.items, id_set)
		}
	}
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
			attrs << Attribute{ name: aname, value: ScalarValue(aval) }
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
			attrs << Attribute{ name: aname, value: ScalarValue(aval) }
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
			} else if b2 == `%` {
				// PEReference `%name;` as a DeclSep — preserve it as an
				// opaque PEReferenceNode (previously dropped char-by-char).
				p.advance() // consume '%'
				mut nm := []u8{}
				for !p.at_end() && p.peek() != `;` && p.peek() != `]` && !is_ws(p.peek()) {
					nm << p.peek()
					p.advance()
				}
				if !p.at_end() && p.peek() == `;` { p.advance() }
				int_subset << PEReferenceNode{ name: nm.bytestr() }
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

// xml_cx_scalar_node builds a typed ScalarNode from a `<cx:TYPE>` carrier's
// local type name + decoded text content (the inverse of emit_xml_cx_typed_item).
// atom / null / string are handled directly; every other (auto-recoverable)
// type name routes through coerce_scalar, which reconstructs the value.
fn xml_cx_scalar_node(local string, text string) Node {
	match local {
		'null' {
			return ScalarNode{ data_type: .null_type, value: ScalarValue(NullValue{}) }
		}
		'atom' {
			return ScalarNode{ data_type: .atom_type, value: ScalarValue(text) }
		}
		'string' {
			return ScalarNode{ data_type: .string_type, value: ScalarValue(text) }
		}
		'duration' {
			// The XML body is the ISO 8601 image; parse it back to the canonical
			// CX duration form ([L25]). Fall back to verbatim text if not ISO.
			cx_form := iso_to_duration_cx(text) or { text }
			return ScalarNode{ data_type: .duration_type, value: ScalarValue(cx_form) }
		}
		'period' {
			cx_form := iso_to_period_cx(text) or { text }
			return ScalarNode{ data_type: .period_type, value: ScalarValue(cx_form) }
		}
		else {
			return coerce_scalar(local, text)
		}
	}
}

// xml_unescape_text reverses xml_escape_text (the three predefined entities the
// emitter writes). Applied to `<cx:TYPE>` text content on decode.
fn xml_unescape_text(s string) string {
	if !s.contains('&') {
		return s
	}
	return s.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
}

fn (mut p XmlParser) parse_xml_element() !Node {
	name := p.xml_read_name()!
	mut cx_anchor := ?string(none)
	mut cx_merge := ?string(none)
	mut cx_type := ?string(none)
	mut cx_id := ?string(none)
	mut cx_body_ref := ?string(none)
	mut cx_attr_types := ''
	mut cx_cols := ''
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
		else if aname == 'cx:attr-types' {
			// D3: reserved per-attribute type sidecar. Consumed here;
			// applied to the sibling attributes in a post-pass below so it
			// works regardless of source ordering.
			cx_attr_types = aval
		}
		else if aname == 'cx:cols' {
			// #413: reserved `[table]`-block column sidecar (conversions.md
			// §2.1). Consumed here; combined with cx:type="table" below to
			// reconstruct the TableData payload from <cx:row>/<cx:cell>
			// children.
			cx_cols = aval
		}
		else if aname == 'cx:body-ref' {
			// GG7: the
			// emitter writes body_ref as `cx:body-ref="<id>"`;
			// the XML import path consumes the attribute and
			// reconstructs Element.body_ref. The CX emitter
			// reproduces the `[ref @id]` body-position form from
			// the field.
			cx_body_ref = aval
		}
		else if aname == 'xml:id' {
			// v3.4: xml:id (XML built-in URI ns) hoists
			// to Element.id. The attribute is consumed; the bare CX
			// emitter writes #id from the field, never as an attribute.
			cx_id = aval
		}
		else {
			// v3.4: xmlns / xmlns:foo declarations round-trip
			// as plain attributes carrying the literal source name. The
			// post-parse resolve_namespaces() pass sees them and uses
			// them to fill Element.ns_uri / Attribute.ns_uri across the
			// scope. The legacy `ns:foo` translation is dropped.
			attrs << Attribute{ name: aname, value: ScalarValue(aval) }
		}
	}

	// D3: re-type the imported attributes — explicit types from the
	// `cx:attr-types` sidecar (overriding), else auto-type from the bare
	// lexical form. Restores CX⇄XML round-trip fidelity for typed attrs.
	apply_xml_attr_types(mut attrs, cx_attr_types)

	// cx:alias → AliasNode (may appear at any level)
	if name == 'cx:alias' {
		alias_name := find_attr_value(attrs, 'name') or { '' }
		p.skip_ws()
		if !p.at_end() && p.peek() == `/` { p.advance() }
		p.xml_expect(`>`)!
		return AliasNode{ name: alias_name }
	}

	// cx:TYPE scalar carriers (@CHOICE-1 typed-list item form, ruling a): a
	// `<cx:int>10</cx:int>` / `<cx:atom>id</cx:atom>` / `<cx:null/>` child decodes
	// back to a typed ScalarNode item (the inverse of emit_xml_cx_typed_item).
	// `cx:alias` is handled above; the collection carriers (cx:arr/cx:seq/cx:map)
	// and others fail is_valid_type_tag and fall through to normal element parsing.
	if name.starts_with('cx:') {
		local := name[3..]
		if local == 'atom' || local == 'null' || is_valid_type_tag(local) {
			p.skip_ws()
			if !p.at_end() && p.peek() == `/` {
				p.advance()
				p.xml_expect(`>`)!
				return xml_cx_scalar_node(local, '')
			}
			p.xml_expect(`>`)!
			mut tb := []u8{}
			for !p.at_end() && p.peek() != `<` {
				tb << p.peek()
				p.advance()
			}
			// consume the end tag </cx:local>
			if !p.at_end() && p.peek() == `<` {
				p.advance()
				if !p.at_end() && p.peek() == `/` { p.advance() }
				p.xml_read_name() or { '' }
				p.skip_ws()
				if !p.at_end() && p.peek() == `>` { p.advance() }
			}
			return xml_cx_scalar_node(local, xml_unescape_text(tb.bytestr()))
		}
	}

	p.skip_ws()
	b := p.peek()
	if b == `/` {
		p.advance() // '/'
		p.xml_expect(`>`)!
		mut el := new_element(name, ElementMeta{
			anchor:    cx_anchor
			merge:     cx_merge
			data_type: cx_type
			id:        cx_id
			body_ref:  cx_body_ref
		}, attrs, []Node{})
		// #413: a self-closing table image is a header-only table (zero
		// rows, valid per conversions.md §8.3). Legacy `cx:type="table"`
		// WITHOUT cx:cols (the pre-#413 emit) keeps its old reading: a bare
		// `::table`-annotated element with no payload.
		if xml_is_table_image(cx_type, cx_cols) {
			td := xml_build_table_data(cx_cols, []Node{})!
			el = el.with_table(td)
		}
		return el
	}

	p.xml_expect(`>`)!

	// Parse children
	mut items := []Node{}
	p.parse_xml_content(name, cx_type, mut items)!

	// #413: cx:type="table" + cx:cols reconstructs the TableData payload
	// from the reserved <cx:row>/<cx:cell> children (the exact inverse of
	// emit_xml_table_element). The rows live in the pooled `table` field;
	// the element body stays empty, matching the CX parse of a `[table]`
	// block.
	if xml_is_table_image(cx_type, cx_cols) {
		td := xml_build_table_data(cx_cols, items)!
		return new_element(name, ElementMeta{
			anchor:    cx_anchor
			merge:     cx_merge
			data_type: cx_type
			id:        cx_id
			body_ref:  cx_body_ref
		}, attrs, []Node{}).with_table(td)
	}

	// If cx_type is an array type, items should already be Scalar nodes
	return new_element(name, ElementMeta{
		anchor:    cx_anchor
		merge:     cx_merge
		data_type: cx_type
		id:        cx_id
		body_ref:  cx_body_ref
	}, attrs, items)
}

// xml_is_table_image reports whether the element carries the #413 table
// image markers: cx:type="table" plus a non-empty cx:cols sidecar.
fn xml_is_table_image(cx_type ?string, cx_cols string) bool {
	ct := cx_type or { return false }
	return ct == 'table' && cx_cols.trim_space().len > 0
}

// xml_build_table_data reconstructs a TableData from the reserved cx:cols
// sidecar and the parsed <cx:row> children (#413, conversions.md §2.1).
// Column tokens are the canonical CX header form: `name::type` or a bare
// (string-typed) name. Every non-whitespace child must be a <cx:row> whose
// children are <cx:cell> elements, one per declared column — anything else
// in a table body is a reserved-shape import error.
fn xml_build_table_data(cols_spec string, items []Node) !TableData {
	mut cols := []TableColumn{}
	for tok in cols_spec.split_any(' \t').filter(it.len > 0) {
		if tok.contains('::') {
			cols << TableColumn{ name: tok.all_before('::'), type_name: tok.all_after('::') }
		} else {
			cols << TableColumn{ name: tok }
		}
	}
	if cols.len == 0 {
		return error('cx:cols declares no columns')
	}
	mut rows := [][]TableCellValue{}
	for n in items {
		match n {
			TextNode {
				if n.value.trim_space().len > 0 {
					return error('cx:type="table" body must contain only <cx:row> children; found text "${n.value.trim_space()}"')
				}
			}
			CommentNode, PINode {
				// Tolerated (stripped) — matches the CX parser, which skips
				// comments between table rows.
			}
			Element {
				if n.name != 'cx:row' {
					return error('cx:type="table" body must contain only <cx:row> children; found <${n.name}> (reserved cx: shape, conversions.md §2.1)')
				}
				row := xml_table_row_cells(n, cols)!
				rows << row
			}
			else {
				return error('cx:type="table" body must contain only <cx:row> children')
			}
		}
	}
	return TableData{ cols: cols, rows: rows }
}

// xml_table_row_cells decodes one <cx:row> into its TableCellValue list.
fn xml_table_row_cells(row Element, cols []TableColumn) ![]TableCellValue {
	mut cells := []TableCellValue{cap: cols.len}
	for c in row.items {
		match c {
			TextNode {
				if c.value.trim_space().len > 0 {
					return error('<cx:row> must contain only <cx:cell> children; found text "${c.value.trim_space()}"')
				}
			}
			Element {
				if c.name != 'cx:cell' {
					return error('<cx:row> must contain only <cx:cell> children; found <${c.name}>')
				}
				col_type := if cells.len < cols.len { cols[cells.len].type_name } else { '' }
				cells << xml_decode_table_cell(c, col_type)!
			}
			else {
				return error('<cx:row> must contain only <cx:cell> children')
			}
		}
	}
	if cells.len != cols.len {
		return error('<cx:row> has ${cells.len} cells; cx:cols declares ${cols.len} columns')
	}
	return cells
}

// xml_decode_table_cell decodes one <cx:cell>. A `<cx:TYPE>` carrier child
// (already decoded to a typed ScalarNode by the element walk) is
// authoritative; a decoded collection carrier becomes a collection cell;
// bare text recovers per the column's declared type via
// xml_recover_bare_cell; an empty cell is the empty string.
fn xml_decode_table_cell(cell Element, col_type string) !TableCellValue {
	// Single decoded value (carrier or collection)?
	mut text_parts := []string{}
	mut value := ?TableCellValue(none)
	mut value_count := 0
	for it in cell.items {
		match it {
			ScalarNode {
				// A `<cx:TYPE>` carrier decode (typed) — authoritative.
				value = cell_value_from_scalar(it.value)
				value_count++
			}
			ArrayNode {
				value = TableCellValue(it)
				value_count++
			}
			MapNode {
				value = TableCellValue(it)
				value_count++
			}
			SequenceNode {
				value = TableCellValue(it)
				value_count++
			}
			TextNode {
				text_parts << it.value
			}
			EntityRefNode {
				text_parts << xml_expand_std_entity(it.name)!
			}
			else {
				return error('<cx:cell> content must be text, a <cx:TYPE> carrier, or a collection carrier')
			}
		}
	}
	if value_count > 1 || (value_count == 1 && text_parts.len > 0) {
		return error('<cx:cell> must carry exactly one value')
	}
	if v := value {
		return v
	}
	if text_parts.len == 0 {
		// <cx:cell/> — the empty string (only string cells can be empty).
		return TableCellValue('')
	}
	return xml_recover_bare_cell(text_parts.join(''), col_type)
}

// xml_expand_std_entity maps the five XML built-in entities to their
// character; anything else inside a <cx:cell> is an import error (general
// entities are not resolvable at this layer).
fn xml_expand_std_entity(name string) !string {
	return match name {
		'amp'  { '&' }
		'lt'   { '<' }
		'gt'   { '>' }
		'quot' { '"' }
		'apos' { "'" }
		else   { error('unresolvable entity &${name}; inside <cx:cell>') }
	}
}

// xml_recover_bare_cell types a bare-text cell per its column's declared
// type — mirroring the CX parser's read_table_cell bare path: the literal
// token `null` is the null cell; a string-family column keeps the text
// verbatim; any other column coerces via the same coerce_scalar the CX
// parser uses. The emitter probes this exact function
// (xml_bare_cell_roundtrips) before choosing the bare form, so emit and
// import can never disagree.
fn xml_recover_bare_cell(text string, col_type string) TableCellValue {
	if text == 'null' {
		return TableCellValue(NullValue{})
	}
	if col_type == '' || col_type == 'string' || col_type == 's' {
		return TableCellValue(text)
	}
	sc := coerce_scalar(expand_type_alias(col_type), text.trim_space())
	return cell_value_from_scalar(sc.value)
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
					// <cx:item>value</cx:item> → Scalar (conversions.md §2.1:
					// the per-item wrapper of a cx:type="T[]" array is the
					// reserved cx:item element; a bare <item> is an ordinary
					// user element, #392)
					if n is Element {
						ne := n as Element
						if ne.name == 'cx:item' {
							text_val := ne.items.filter(it is TextNode).map((it as TextNode).value).join('')
							items << coerce_scalar(arr_elem_type, text_val.trim_space())
						}
					}
				} else {
					items << xml_decode_collection_carrier(n)
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

// ── conversions.md §2.1 collection-carrier IMPORT (the exact inverse of the
// emit mapping; #392) ────────────────────────────────────────────────────────
// The reserved carriers decode back to cx-native collection nodes:
//   <cx:arr><cx:item>v</cx:item>…</cx:arr>            → ArrayNode
//   <cx:seq><cx:item>v</cx:item>…</cx:seq>            → SequenceNode
//   <cx:map><cx:entry cx:key="k">v</cx:entry>…</cx:map> → MapNode
//     (cx:key-type restores a non-string key's scalar type)
// The child loop decodes depth-first, so a nested carrier inside a cx:item /
// cx:entry value is already a collection node by the time its wrapper is
// unwrapped here. Any non-carrier node passes through unchanged.

fn xml_decode_collection_carrier(n Node) Node {
	if n is Element {
		e := n as Element
		match e.name {
			'cx:arr' {
				return ArrayNode{
					items: xml_carrier_items(e)
				}
			}
			'cx:seq' {
				return SequenceNode{
					items: xml_carrier_items(e)
				}
			}
			'cx:map' {
				mut entries := []MapEntry{cap: e.items.len}
				for it in e.items {
					if it is Element && (it as Element).name == 'cx:entry' {
						ee := it as Element
						key_str := find_attr_value(ee.attrs, 'cx:key') or { '' }
						ktype := find_attr_value(ee.attrs, 'cx:key-type') or { 'string' }
						key := coerce_scalar(ktype, key_str)
						entries << MapEntry{
							key_type:  key.data_type
							key_value: key.value
							value:     xml_wrapped_item_value(ee)
						}
					}
				}
				return MapNode{
					entries: entries
				}
			}
			else {
				return n
			}
		}
	}
	return n
}

// xml_carrier_items unwraps each <cx:item> child of a cx:arr / cx:seq carrier
// to its value. Non-cx:item children (indentation text) are skipped — cx:item
// is the ONLY legal child of a carrier per conversions.md, and an orphan
// cx:item elsewhere is already an import error at the reserved-prefix layer.
fn xml_carrier_items(e Element) []Node {
	mut out := []Node{cap: e.items.len}
	for it in e.items {
		if it is Element && (it as Element).name == 'cx:item' {
			out << xml_wrapped_item_value(it as Element)
		}
	}
	return out
}

// xml_wrapped_item_value extracts the single value a cx:item / cx:entry
// wrapper carries: a sole structural child (element / already-decoded
// collection / typed-carrier scalar) passes through; a text-only body
// auto-types exactly like other imported XML scalars, so `<cx:item>3</cx:item>`
// round-trips to int 3 the way `[3, …]` emitted it.
fn xml_wrapped_item_value(e Element) Node {
	mut structural := []Node{}
	mut text := []u8{}
	for it in e.items {
		match it {
			TextNode {
				text << it.value.bytes()
			}
			else {
				structural << it
			}
		}
	}
	if structural.len == 1 {
		return structural[0]
	}
	if structural.len > 1 {
		// A multi-node item value is an inline sequence at the item position
		// (conversions.md: `<cx:seq>…</cx:seq>` inline is the canonical form,
		// but be liberal on import — wrap what is there).
		return SequenceNode{
			items: structural
		}
	}
	tok := text.bytestr().trim_space()
	if node := try_autotype(tok) {
		return node
	}
	return ScalarNode{
		data_type: .string_type
		value:     ScalarValue(tok)
	}
}
