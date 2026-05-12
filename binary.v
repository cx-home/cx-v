module cx

// binary.v — compact binary wire format for AST and stream events.
// Used by cx_to_ast_bin and cx_to_events_bin.
//
// All integers are little-endian.
// Strings:    u32(byte_len) + raw bytes  (no null terminator)
// OptStrings: u8(0|1) + str if 1
//
// Returned buffer layout (from to_heap()):
//   [u32 LE: payload_size] [payload bytes]
// Caller reads the 4-byte size, then reads that many bytes.
// Free with cx_free().

// ── byte buffer ───────────────────────────────────────────────────────────────

struct BinBuf {
mut:
	buf []u8
}

fn (mut b BinBuf) u8_(v u8) {
	b.buf << v
}

fn (mut b BinBuf) u16_(v u16) {
	b.buf << u8(v & 0xFF)
	b.buf << u8(v >> 8)
}

fn (mut b BinBuf) u32_(v u32) {
	b.buf << u8(v & 0xFF)
	b.buf << u8((v >> 8) & 0xFF)
	b.buf << u8((v >> 16) & 0xFF)
	b.buf << u8(v >> 24)
}

fn (mut b BinBuf) str_(s string) {
	n := s.len
	b.u32_(u32(n))
	if n == 0 {
		return
	}
	old_len := b.buf.len
	unsafe {
		b.buf.grow_len(n)
		vmemcpy(&b.buf[old_len], s.str, n)
	}
}

fn (mut b BinBuf) bytes_(bs []u8) {
	n := bs.len
	b.u32_(u32(n))
	if n == 0 {
		return
	}
	old_len := b.buf.len
	unsafe {
		b.buf.grow_len(n)
		vmemcpy(&b.buf[old_len], bs.data, n)
	}
}

fn (mut b BinBuf) optstr_(s ?string) {
	if v := s {
		b.u8_(1)
		b.str_(v)
	} else {
		b.u8_(0)
	}
}

fn inferred_type(v ScalarValue) string {
	return match v {
		i64       { 'int' }
		f64       { 'float' }
		bool      { 'bool' }
		NullValue { 'null' }
		string    { 'string' }
	}
}

fn (mut b BinBuf) attr_(a Attribute) {
	b.str_(a.name)
	b.str_(scalar_value_str(a.value))
	// Always encode inferred type so decoders can reconstruct typed values.
	// Unlike JSON (which uses native types), binary stores strings + type tag.
	b.str_(inferred_type(a.value))
	// v3.4 (ADR 0003): is_ref flag — distinguishes a bare-`@id` reference
	// (round-trips as `name=@id`) from a literal string starting with `@`
	// (round-trips quoted). Format version 2 added.
	b.u8_(if a.is_ref { u8(1) } else { u8(0) })
	// v0.6.0 grammar v3.5 (ADR 0016) — BracketBody attribute value tail.
	// u8:body_flag (0 = no body, 1 = body present)
	// u16:body_count + nodes[] when flag = 1.
	// Format version 5 added.
	if body := a.body {
		b.u8_(1)
		b.u16_(u16(body.len))
		for n in body {
			encode_node(mut b, n)
		}
	} else {
		b.u8_(0)
	}
}

// to_heap returns a heap-allocated, length-prefixed buffer.
// [u32 LE: payload_size][payload bytes]
fn (b BinBuf) to_heap() &char {
	size := b.buf.len
	raw := unsafe { &u8(malloc(size + 4)) }
	unsafe {
		raw[0] = u8(size & 0xFF)
		raw[1] = u8((size >> 8) & 0xFF)
		raw[2] = u8((size >> 16) & 0xFF)
		raw[3] = u8(size >> 24)
		if size > 0 {
			vmemcpy(voidptr(usize(voidptr(raw)) + 4), voidptr(b.buf.data), size)
		}
	}
	return unsafe { &char(raw) }
}

// ── Event encoder ─────────────────────────────────────────────────────────────
//
// Type IDs (u8):
//   0x01 StartDoc     — no payload
//   0x02 EndDoc       — no payload
//   0x03 StartElement — str:name  optstr:anchor  optstr:data_type  optstr:merge  u16:attr_count  attrs[]
//   0x04 EndElement   — str:name
//   0x05 Text         — str:value
//   0x06 Scalar       — str:data_type  str:value
//   0x07 Comment      — str:value
//   0x08 PI           — str:target  optstr:data
//   0x09 EntityRef    — str:name
//   0x0A RawText      — str:value
//   0x0B Alias        — str:name
//   0x0C StartTable   — str:name  u32:col_spec_len  raw bytes (events-layer col-spec, §1.1)
//   0x0D RowGroup     — u32:row_count  u32:payload_len  raw bytes (§3.11.2 plain-body)
//   0x0E EndTable     — str:name
//
// Attr: str:name  str:value  str:inferred_type  u8:is_ref (v2+)

fn encode_event(mut b BinBuf, e StreamEvent) {
	match e {
		StreamStartDoc {
			b.u8_(0x01)
		}
		StreamEndDoc {
			b.u8_(0x02)
		}
		StreamStartElement {
			b.u8_(0x03)
			b.str_(e.name)
			b.optstr_(e.anchor)
			b.optstr_(e.data_type)
			b.optstr_(e.merge)
			b.u16_(u16(e.attrs.len))
			for a in e.attrs {
				b.attr_(a)
			}
		}
		StreamEndElement {
			b.u8_(0x04)
			b.str_(e.name)
		}
		StreamText {
			b.u8_(0x05)
			b.str_(e.value)
		}
		StreamScalar {
			b.u8_(0x06)
			b.str_(e.data_type)
			b.str_(scalar_value_str(e.value))
		}
		StreamComment {
			b.u8_(0x07)
			b.str_(e.value)
		}
		StreamPI {
			b.u8_(0x08)
			b.str_(e.target)
			b.optstr_(e.data)
		}
		StreamEntityRef {
			b.u8_(0x09)
			b.str_(e.name)
		}
		StreamRawText {
			b.u8_(0x0A)
			b.str_(e.value)
		}
		StreamAlias {
			b.u8_(0x0B)
			b.str_(e.name)
		}
		StreamStartTable {
			b.u8_(0x0C)
			b.str_(e.name)
			b.bytes_(e.col_spec)
		}
		StreamRowGroup {
			b.u8_(0x0D)
			b.u32_(e.row_count)
			b.bytes_(e.payload)
		}
		StreamEndTable {
			b.u8_(0x0E)
			b.str_(e.name)
		}
	}
}

pub fn events_to_bin(events []StreamEvent) BinBuf {
	mut b := BinBuf{}
	b.u32_(u32(events.len))
	for e in events {
		encode_event(mut b, e)
	}
	return b
}

// ── AST encoder ───────────────────────────────────────────────────────────────
//
// Document:
//   u8(version=2)  u16(prolog_count)  nodes[]  u16(element_count)  nodes[]
//
// Format version history:
//   1 — original layout (pre-2026-05).
//   2 — v3.4 ADR 0003: Element gains optstr:id after merge; Attr gains
//       u8:is_ref after inferred_type.
//   3 — v3.4 ADR 0003 D1: Element gains optstr:body_ref after id, carrying
//       the bare-ref body form `[ref @<name>]`.
//   4 — v0.6.0 schema fragments (spec/schema.md §8): CXDirective gains
//       optstr:anchor + u16:item_count + items[] after attrs[]. Used by
//       the standalone-fragment form `[?cx frag &name [body :TYPE :flags]]`
//       and any future directive that nests a body. v1-3 decoders see the
//       attrs-only shape and treat anchor/items as none/empty.
//   5 — v0.6.0 grammar v3.5 (ADR 0016): three CXL surface additions land
//       in ast_bin. New node tags 0x0D (Interpolation) and 0x0E (EvalDirective)
//       carry the [?=EXPR] and [?Name ...] forms. Attribute encoding gains
//       a body tail (u8:body_flag + u16:body_count + nodes[] when flag=1)
//       carrying the BracketBody attribute-value form `name=[BodyItem*]`.
//       v1-4 decoders treated the new nodes as 0xFF skip and never saw the
//       body tail because the producer didn't emit it.
//   6 — v0.6.0 grammar v3.6 (ADR 0017): three new container Item kinds
//       land in ast_bin. New node tags 0x0F (SequenceNode), 0x10
//       (ArrayNode), 0x11 (MapNode). MapNode entries encode a flattened
//       atomic key (key_data_type:String + key_value:String) followed by
//       a recursively-encoded value node. Capability bit 29 signals
//       support; v1-5 decoders MUST reject buffers whose version byte
//       is >= 6.
//
// Node type IDs (u8):
//   0x01 Element      — str:name  optstr:anchor  optstr:data_type  optstr:merge
//                       optstr:id (v2+)  optstr:body_ref (v3+)
//                       u16:attr_count  attrs[]  u16:child_count  nodes[]
//   0x02 Text         — str:value
//   0x03 Scalar       — str:data_type  str:value
//   0x04 Comment      — str:value
//   0x05 RawText      — str:value
//   0x06 EntityRef    — str:name
//   0x07 Alias        — str:name
//   0x08 PI           — str:target  optstr:data
//   0x09 XMLDecl      — str:version  optstr:encoding  optstr:standalone
//   0x0A CXDirective  — u16:attr_count  attrs[]
//                       optstr:anchor (v4+)  u16:child_count (v4+)  nodes[] (v4+)
//   0x0C BlockContent — u16:child_count  nodes[]
//   0x0D Interpolation (v5+) — str:expr
//   0x0E EvalDirective (v5+) — str:name  u16:attr_count  attrs[]
//                              u16:item_count  nodes[]
//   0x0F SequenceNode (v6+) — u16:item_count  nodes[]
//   0x10 ArrayNode    (v6+) — u16:item_count  nodes[]
//   0x11 MapNode      (v6+) — u16:entry_count  entries[]
//                             entry: str:key_data_type  str:key_value  node:value
//   0xFF skip         — unknown/DTD node (decoder skips, no payload follows)
//
// Attribute payload (per attr inside any node that holds attrs[]):
//   str:name  str:value  str:inferred_type
//   u8:is_ref (v2+)
//   u8:body_flag (v5+)   — 0 = absent (no further bytes)
//                          1 = present, followed by u16:body_count + nodes[]

fn encode_node(mut b BinBuf, n Node) {
	match n {
		Element {
			b.u8_(0x01)
			b.str_(n.name)
			b.optstr_(n.anchor)
			b.optstr_(n.data_type)
			b.optstr_(n.merge)
			// v3.4 (ADR 0003): syntactic ID declaration (`#name`).
			b.optstr_(n.id)
			// v3.4 (ADR 0003 D1): body-position reference `[ref @<name>]`.
			b.optstr_(n.body_ref)
			b.u16_(u16(n.attrs.len))
			for a in n.attrs {
				b.attr_(a)
			}
			b.u16_(u16(n.items.len))
			for child in n.items {
				encode_node(mut b, child)
			}
		}
		TextNode {
			b.u8_(0x02)
			b.str_(n.value)
		}
		ScalarNode {
			b.u8_(0x03)
			b.str_(scalar_type_name(n.data_type))
			b.str_(scalar_value_str(n.value))
		}
		CommentNode {
			b.u8_(0x04)
			b.str_(n.value)
		}
		RawTextNode {
			b.u8_(0x05)
			b.str_(n.value)
		}
		EntityRefNode {
			b.u8_(0x06)
			b.str_(n.name)
		}
		AliasNode {
			b.u8_(0x07)
			b.str_(n.name)
		}
		PINode {
			b.u8_(0x08)
			b.str_(n.target)
			b.optstr_(n.data)
		}
		XMLDeclNode {
			b.u8_(0x09)
			b.str_(n.version)
			b.optstr_(n.encoding)
			b.optstr_(n.standalone)
		}
		CXDirectiveNode {
			b.u8_(0x0A)
			b.u16_(u16(n.attrs.len))
			for a in n.attrs {
				b.attr_(a)
			}
			// v0.6.0 (format version 4) — directive `&anchor` + nested
			// children (spec/schema.md §8 standalone fragment form).
			b.optstr_(n.anchor)
			b.u16_(u16(n.items.len))
			for child in n.items {
				encode_node(mut b, child)
			}
		}
		BlockContentNode {
			b.u8_(0x0C)
			b.u16_(u16(n.items.len))
			for item in n.items {
				encode_node(mut b, item)
			}
		}
		InterpolationNode {
			// v3.5 (ADR 0016) [58] — `[?=EXPR]`. EXPR carried verbatim.
			b.u8_(0x0D)
			b.str_(n.expr)
		}
		EvalDirectiveNode {
			// v3.5 (ADR 0016) [59] — `[?Name ...]`. Attrs may carry
			// BracketBody values via the v5 attr tail.
			b.u8_(0x0E)
			b.str_(n.name)
			b.u16_(u16(n.attrs.len))
			for a in n.attrs {
				b.attr_(a)
			}
			b.u16_(u16(n.items.len))
			for child in n.items {
				encode_node(mut b, child)
			}
		}
		SequenceNode {
			// v6 (ADR 0017) [56a] — `(a, b, c)` flat sequence. Items
			// already flattened by the parser per CXDM §1.2.
			b.u8_(0x0F)
			b.u16_(u16(n.items.len))
			for child in n.items {
				encode_node(mut b, child)
			}
		}
		ArrayNode {
			// v6 (ADR 0017) [56b] — `[a, b, c]` nested-preserving array.
			b.u8_(0x10)
			b.u16_(u16(n.items.len))
			for child in n.items {
				encode_node(mut b, child)
			}
		}
		MapNode {
			// v6 (ADR 0017) [56c] — `{k: v, k: v}`. Keys flattened as
			// scalar-type-tag + canonical-string per ast_bin §4.3.
			b.u8_(0x11)
			b.u16_(u16(n.entries.len))
			for entry in n.entries {
				b.str_(scalar_type_name(entry.key_type))
				b.str_(scalar_value_str(entry.key_value))
				encode_node(mut b, entry.value)
			}
		}
		else {
			// DTD nodes are not used by language bindings; emit 0xFF skip.
			b.u8_(0xFF)
		}
	}
}

pub fn doc_to_bin(doc Document) BinBuf {
	mut b := BinBuf{}
	b.u8_(6) // version — bumped 5 → 6 for v0.6.0 grammar v3.6 (ADR 0017):
	         //   - SequenceNode (0x0F), ArrayNode (0x10), MapNode (0x11)
	         //     node tags for the three new container Item kinds.
	         //   - MapEntry encoding: flattened atomic key (str:type +
	         //     str:value) followed by a recursive value node.
	         // Signaled by capability bit 29 (spec/abi.md §1.5). v1-5
	         // decoders MUST reject buffers whose version byte is >= 6.
	b.u16_(u16(doc.prolog.len))
	for n in doc.prolog {
		encode_node(mut b, n)
	}
	b.u16_(u16(doc.elements.len))
	for n in doc.elements {
		encode_node(mut b, n)
	}
	return b
}

// emit_ast_bin returns a framed [u32 LE size][payload] binary AST as
// []u8. Public counterpart to bin_to_doc; test-friendly. The C ABI
// uses doc_to_bin + to_heap to return the same shape as &char.
pub fn emit_ast_bin(doc Document) []u8 {
	b := doc_to_bin(doc)
	mut out := []u8{cap: b.buf.len + 4}
	sz := u32(b.buf.len)
	out << u8(sz & 0xFF)
	out << u8((sz >> 8) & 0xFF)
	out << u8((sz >> 16) & 0xFF)
	out << u8((sz >> 24) & 0xFF)
	out << b.buf
	return out
}

// ── Binary AST decoder (Phase 2c) ────────────────────────────────────────────
//
// Symmetric inverse of doc_to_bin / encode_node. Used by cabi.v's
// cx_ast_bin_to_<format> functions to close audit finding CB-1.
// Bindings can decode binary AST bytes back to a Document and emit
// any target format without going through CX text round-trips.
//
// Input: framed [u32 LE size][payload] matching to_heap()'s output.

struct AstReader {
mut:
	buf     []u8
	pos     int
	version u8 = 6 // ast_bin format version (defaulted to current; bin_to_doc
	               // sets it explicitly from the buffer header).
}

pub fn bin_to_doc(framed []u8) !Document {
	if framed.len < 4 {
		return error('ast_bin: input too short for size header')
	}
	size := u32(framed[0]) | (u32(framed[1]) << 8)
		| (u32(framed[2]) << 16) | (u32(framed[3]) << 24)
	if 4 + int(size) > framed.len {
		return error('ast_bin: declared payload (${size}) exceeds remaining input')
	}
	mut r := AstReader{
		buf: unsafe { framed[4 .. 4 + int(size)] }
		pos: 0
	}
	version := r.read_u8()!
	if version < 1 || version > 6 {
		return error('ast_bin: unsupported version ${version}')
	}
	r.version = version
	prolog_count := r.read_u16()!
	mut prolog := []Node{cap: int(prolog_count)}
	for _ in 0 .. prolog_count {
		prolog << r.decode_node()!
	}
	elem_count := r.read_u16()!
	mut elements := []Node{cap: int(elem_count)}
	for _ in 0 .. elem_count {
		elements << r.decode_node()!
	}
	mut doc := Document{ prolog: prolog, elements: elements }
	resolve_namespaces(mut doc)
	resolve_ids(doc)!
	return doc
}

fn (mut r AstReader) read_u8() !u8 {
	if r.pos >= r.buf.len { return error('ast_bin: unexpected end of input') }
	v := r.buf[r.pos]
	r.pos++
	return v
}

fn (mut r AstReader) read_u16() !u16 {
	if r.pos + 2 > r.buf.len { return error('ast_bin: truncated u16') }
	v := u16(r.buf[r.pos]) | (u16(r.buf[r.pos + 1]) << 8)
	r.pos += 2
	return v
}

fn (mut r AstReader) read_u32() !u32 {
	if r.pos + 4 > r.buf.len { return error('ast_bin: truncated u32') }
	v := u32(r.buf[r.pos]) | (u32(r.buf[r.pos + 1]) << 8)
		| (u32(r.buf[r.pos + 2]) << 16) | (u32(r.buf[r.pos + 3]) << 24)
	r.pos += 4
	return v
}

fn (mut r AstReader) read_str() !string {
	n := r.read_u32()!
	if int(n) > r.buf.len - r.pos {
		return error('ast_bin: string length ${n} exceeds remaining input')
	}
	bs := r.buf[r.pos .. r.pos + int(n)]
	r.pos += int(n)
	return bs.bytestr()
}

// read_optstr returns a (present, value) pair. V rejects nested
// !?string returns, so we split the result-of-option into a tuple.
// Callers wrap the returned bool/string into a ?string at the use
// site.
fn (mut r AstReader) read_optstr() !(bool, string) {
	flag := r.read_u8()!
	if flag == 0 { return false, '' }
	if flag != 1 { return error('ast_bin: invalid optstr flag ${flag}') }
	s := r.read_str()!
	return true, s
}

fn (mut r AstReader) read_attr() !Attribute {
	name := r.read_str()!
	val_str := r.read_str()!
	type_str := r.read_str()!
	mut attr := decode_attribute(name, val_str, type_str)
	if r.version >= 2 {
		// v3.4 (ADR 0003): is_ref flag.
		flag := r.read_u8()!
		attr.is_ref = flag == 1
	}
	if r.version >= 5 {
		// v3.5 (ADR 0016): BracketBody attribute body tail. Flag=0 means
		// no body; flag=1 is followed by u16:body_count + nodes[].
		body_flag := r.read_u8()!
		if body_flag == 1 {
			body_count := r.read_u16()!
			mut body := []Node{cap: int(body_count)}
			for _ in 0 .. body_count {
				body << r.decode_node()!
			}
			attr.body = body
		} else if body_flag != 0 {
			return error('ast_bin: invalid attr body_flag ${body_flag}')
		}
	}
	return attr
}

fn decode_attribute(name string, val_str string, type_str string) Attribute {
	dt := match type_str {
		'int'      { ?ScalarType(ScalarType.int_type) }
		'float'    { ?ScalarType(ScalarType.float_type) }
		'bool'     { ?ScalarType(ScalarType.bool_type) }
		'null'     { ?ScalarType(ScalarType.null_type) }
		'date'     { ?ScalarType(ScalarType.date_type) }
		'datetime' { ?ScalarType(ScalarType.datetime_type) }
		'bytes'    { ?ScalarType(ScalarType.bytes_type) }
		'decimal'  { ?ScalarType(ScalarType.decimal_type) }
		'bigint'   { ?ScalarType(ScalarType.bigint_type) }
		'string'   { ?ScalarType(none) }
		else       { ?ScalarType(none) }
	}
	val := scalar_value_from_str(val_str, type_str)
	return Attribute{ name: name, value: val, data_type: dt }
}

fn scalar_value_from_str(s string, type_str string) ScalarValue {
	return match type_str {
		'int' {
			ScalarValue(s.i64())
		}
		'float' {
			ScalarValue(s.f64())
		}
		'bool' {
			ScalarValue(s == 'true')
		}
		'null' {
			ScalarValue(NullValue{})
		}
		else {
			ScalarValue(s)
		}
	}
}

fn (mut r AstReader) decode_node() !Node {
	tag := r.read_u8()!
	return match tag {
		0x01 { r.decode_element()! }
		0x02 { Node(TextNode{ value: r.read_str()! }) }
		0x03 { r.decode_scalar()! }
		0x04 { Node(CommentNode{ value: r.read_str()! }) }
		0x05 { Node(RawTextNode{ value: r.read_str()! }) }
		0x06 { Node(EntityRefNode{ name: r.read_str()! }) }
		0x07 { Node(AliasNode{ name: r.read_str()! }) }
		0x08 { r.decode_pi()! }
		0x09 { r.decode_xmldecl()! }
		0x0A { r.decode_directive()! }
		0x0C { r.decode_blockcontent()! }
		0x0D { r.decode_interpolation()! }
		0x0E { r.decode_eval_directive()! }
		0x0F { r.decode_sequence_node()! }
		0x10 { r.decode_array_node()! }
		0x11 { r.decode_map_node()! }
		0xFF { Node(TextNode{}) } // skip — unknown / DTD nodes
		else { error('ast_bin: unknown node tag 0x${tag:02x} at offset ${r.pos - 1}') }
	}
}

fn (mut r AstReader) decode_element() !Node {
	name := r.read_str()!
	a_has, a_val := r.read_optstr()!
	d_has, d_val := r.read_optstr()!
	m_has, m_val := r.read_optstr()!
	anchor    := if a_has { ?string(a_val) } else { ?string(none) }
	data_type := if d_has { ?string(d_val) } else { ?string(none) }
	merge     := if m_has { ?string(m_val) } else { ?string(none) }
	mut id := ?string(none)
	if r.version >= 2 {
		// v3.4 (ADR 0003): syntactic ID declaration.
		i_has, i_val := r.read_optstr()!
		if i_has { id = ?string(i_val) }
	}
	mut body_ref := ?string(none)
	if r.version >= 3 {
		// v3.4 (ADR 0003 D1): body-position reference.
		br_has, br_val := r.read_optstr()!
		if br_has { body_ref = ?string(br_val) }
	}
	attr_count := r.read_u16()!
	mut attrs := []Attribute{cap: int(attr_count)}
	for _ in 0 .. attr_count {
		attrs << r.read_attr()!
	}
	child_count := r.read_u16()!
	mut items := []Node{cap: int(child_count)}
	for _ in 0 .. child_count {
		items << r.decode_node()!
	}
	return Node(Element{
		name:      name
		anchor:    anchor
		merge:     merge
		data_type: data_type
		id:        id
		body_ref:  body_ref
		attrs:     attrs
		items:     items
	})
}

fn (mut r AstReader) decode_scalar() !Node {
	type_str := r.read_str()!
	val_str := r.read_str()!
	dt := match type_str {
		'int'      { ScalarType.int_type }
		'float'    { ScalarType.float_type }
		'bool'     { ScalarType.bool_type }
		'null'     { ScalarType.null_type }
		'string'   { ScalarType.string_type }
		'date'     { ScalarType.date_type }
		'datetime' { ScalarType.datetime_type }
		'bytes'    { ScalarType.bytes_type }
		'decimal'  { ScalarType.decimal_type }
		'bigint'   { ScalarType.bigint_type }
		else       { ScalarType.string_type }
	}
	return Node(ScalarNode{
		data_type: dt
		value:     scalar_value_from_str(val_str, type_str)
	})
}

fn (mut r AstReader) decode_pi() !Node {
	target := r.read_str()!
	d_has, d_val := r.read_optstr()!
	data := if d_has { ?string(d_val) } else { ?string(none) }
	return Node(PINode{ target: target, data: data })
}

fn (mut r AstReader) decode_xmldecl() !Node {
	version := r.read_str()!
	e_has, e_val := r.read_optstr()!
	s_has, s_val := r.read_optstr()!
	encoding   := if e_has { ?string(e_val) } else { ?string(none) }
	standalone := if s_has { ?string(s_val) } else { ?string(none) }
	return Node(XMLDeclNode{ version: version, encoding: encoding, standalone: standalone })
}

fn (mut r AstReader) decode_directive() !Node {
	attr_count := r.read_u16()!
	mut attrs := []Attribute{cap: int(attr_count)}
	for _ in 0 .. attr_count {
		attrs << r.read_attr()!
	}
	mut anchor := ?string(none)
	mut items := []Node{}
	if r.version >= 4 {
		// v0.6.0 — `&anchor` + nested children (spec/schema.md §8).
		a_has, a_val := r.read_optstr()!
		if a_has { anchor = ?string(a_val) }
		child_count := r.read_u16()!
		items = []Node{cap: int(child_count)}
		for _ in 0 .. child_count {
			items << r.decode_node()!
		}
	}
	return Node(CXDirectiveNode{ attrs: attrs, anchor: anchor, items: items })
}

fn (mut r AstReader) decode_blockcontent() !Node {
	child_count := r.read_u16()!
	mut items := []Node{cap: int(child_count)}
	for _ in 0 .. child_count {
		items << r.decode_node()!
	}
	return Node(BlockContentNode{ items: items })
}

fn (mut r AstReader) decode_interpolation() !Node {
	// v3.5 (ADR 0016) [58] — `[?=EXPR]`.
	expr := r.read_str()!
	return Node(InterpolationNode{ expr: expr })
}

fn (mut r AstReader) decode_eval_directive() !Node {
	// v3.5 (ADR 0016) [59] — `[?Name ...]`.
	name := r.read_str()!
	attr_count := r.read_u16()!
	mut attrs := []Attribute{cap: int(attr_count)}
	for _ in 0 .. attr_count {
		attrs << r.read_attr()!
	}
	item_count := r.read_u16()!
	mut items := []Node{cap: int(item_count)}
	for _ in 0 .. item_count {
		items << r.decode_node()!
	}
	return Node(EvalDirectiveNode{ name: name, attrs: attrs, items: items })
}

fn (mut r AstReader) decode_sequence_node() !Node {
	// v6 (ADR 0017) [56a] — `(a, b, c)`.
	item_count := r.read_u16()!
	mut items := []Node{cap: int(item_count)}
	for _ in 0 .. item_count {
		items << r.decode_node()!
	}
	return Node(SequenceNode{ items: items })
}

fn (mut r AstReader) decode_array_node() !Node {
	// v6 (ADR 0017) [56b] — `[a, b, c]`.
	item_count := r.read_u16()!
	mut items := []Node{cap: int(item_count)}
	for _ in 0 .. item_count {
		items << r.decode_node()!
	}
	return Node(ArrayNode{ items: items })
}

fn (mut r AstReader) decode_map_node() !Node {
	// v6 (ADR 0017) [56c] — `{k: v, k: v}`. Per ast_bin §4.3, each
	// entry is (str:key_data_type, str:key_value, node:value).
	entry_count := r.read_u16()!
	mut entries := []MapEntry{cap: int(entry_count)}
	for _ in 0 .. entry_count {
		key_type_str := r.read_str()!
		key_val_str := r.read_str()!
		key_value := scalar_value_from_str(key_val_str, key_type_str)
		key_type := map_key_type_from_str(key_type_str)
		val_node := r.decode_node()!
		entries << MapEntry{
			key_type:  key_type
			key_value: key_value
			value:     val_node
		}
	}
	return Node(MapNode{ entries: entries })
}

fn map_key_type_from_str(s string) ScalarType {
	return match s {
		'int'      { ScalarType.int_type }
		'float'    { ScalarType.float_type }
		'bool'     { ScalarType.bool_type }
		'date'     { ScalarType.date_type }
		'datetime' { ScalarType.datetime_type }
		'bytes'    { ScalarType.bytes_type }
		'decimal'  { ScalarType.decimal_type }
		'bigint'   { ScalarType.bigint_type }
		else       { ScalarType.string_type }
	}
}
