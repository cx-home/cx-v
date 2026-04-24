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
//
// Attr: str:name  str:value  str:inferred_type

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
//   u8(version=1)  u16(prolog_count)  nodes[]  u16(element_count)  nodes[]
//
// Node type IDs (u8):
//   0x01 Element      — str:name  optstr:anchor  optstr:data_type  optstr:merge
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
//   0x0C BlockContent — u16:child_count  nodes[]
//   0xFF skip         — unknown/DTD node (decoder skips, no payload follows)

fn encode_node(mut b BinBuf, n Node) {
	match n {
		Element {
			b.u8_(0x01)
			b.str_(n.name)
			b.optstr_(n.anchor)
			b.optstr_(n.data_type)
			b.optstr_(n.merge)
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
		}
		BlockContentNode {
			b.u8_(0x0C)
			b.u16_(u16(n.items.len))
			for item in n.items {
				encode_node(mut b, item)
			}
		}
		else {
			// DTD nodes not used by language bindings
			b.u8_(0xFF)
		}
	}
}

pub fn doc_to_bin(doc Document) BinBuf {
	mut b := BinBuf{}
	b.u8_(1) // version
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
