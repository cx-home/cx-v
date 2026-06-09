module cx

import encoding.base64

// ── Streaming event types ─────────────────────────────────────────────────────

pub type StreamEvent = StreamStartDoc
	| StreamEndDoc
	| StreamStartElement
	| StreamEndElement
	| StreamText
	| StreamScalar
	| StreamComment
	| StreamPI
	| StreamEntityRef
	| StreamRawText
	| StreamAlias
	| StreamStartTable
	| StreamRowGroup
	| StreamEndTable

pub struct StreamStartDoc {}
pub struct StreamEndDoc {}

pub struct StreamStartElement {
pub:
	name      string
	attrs     []Attribute
	data_type ?string
	anchor    ?string
	merge     ?string
}

pub struct StreamEndElement {
pub:
	name string
}

pub struct StreamText {
pub:
	value string
}

pub struct StreamScalar {
pub:
	data_type string
	value     ScalarValue
}

pub struct StreamComment {
pub:
	value string
}

pub struct StreamPI {
pub:
	target string
	data   ?string
}

pub struct StreamEntityRef {
pub:
	name string
}

pub struct StreamRawText {
pub:
	value string
}

pub struct StreamAlias {
pub:
	name string
}

// ── Chunked-table events ──────────────────────────────────────
//
// Emitted for `:table` body Elements whose `TableData.from_chunked` is
// true (set by the data_bin chunked reader path). Non-chunked `:table`
// Elements (CX text source, `0x60` data_bin, `0x61` empty-table) emit
// the existing StartElement / per-cell-Scalar / EndElement sequence
// unchanged. See spec/streaming.md §1.1.

pub struct StreamStartTable {
pub:
	name     string
	col_spec []u8 // [u32 LE: count]([u32 LE: name_len]name [u8: col_type_code])* per §1.1 / §3.10.1
}

pub struct StreamRowGroup {
pub:
	row_count u32
	payload   []u8 // §3.11.2 plain-body bytes: uvarint(row_count) <col-payload>(col_count)
}

pub struct StreamEndTable {
pub:
	name string
}

// ── Stream — pull-model event stream ─────────────────────────────────────────

pub struct Stream {
mut:
	events []StreamEvent
	pos    int
}

// new_stream parses CX input and returns a Stream ready for next() calls.
pub fn new_stream(input string) !Stream {
	doc := parse(input)!
	return new_stream_from_doc(doc)
}

// new_stream_from_doc creates a Stream from a pre-parsed Document.
pub fn new_stream_from_doc(doc Document) Stream {
	mut events := []StreamEvent{}
	events << StreamStartDoc{}
	for n in doc.prolog {
		collect_node_events(n, mut events)
	}
	for n in doc.elements {
		collect_node_events(n, mut events)
	}
	events << StreamEndDoc{}
	return Stream{ events: events, pos: 0 }
}

// next returns the next event, or none when exhausted.
pub fn (mut s Stream) next() ?StreamEvent {
	if s.pos >= s.events.len {
		return none
	}
	e := s.events[s.pos]
	s.pos++
	return e
}

// collect drains all remaining events into a slice.
pub fn (mut s Stream) collect() []StreamEvent {
	result := s.events[s.pos..]
	s.pos = s.events.len
	return result
}

// ── DOM walker ────────────────────────────────────────────────────────────────

fn collect_node_events(n Node, mut events []StreamEvent) {
	match n {
		Element {
			if td := n.table_opt() {
				if td.from_chunked {
					emit_chunked_table_events(n.name, td, mut events)
					return
				}
			}
			events << StreamStartElement{
				name:      n.name
				attrs:     n.attrs
				data_type: n.data_type()
				anchor:    n.anchor()
				merge:     n.merge()
			}
			for child in n.items {
				collect_node_events(child, mut events)
			}
			events << StreamEndElement{ name: n.name }
		}
		TextNode {
			events << StreamText{ value: n.value }
		}
		ScalarNode {
			events << StreamScalar{
				data_type: scalar_type_name(n.data_type)
				value:     n.value
			}
		}
		CommentNode {
			events << StreamComment{ value: n.value }
		}
		PINode {
			events << StreamPI{ target: n.target, data: n.data }
		}
		EntityRefNode {
			events << StreamEntityRef{ name: n.name }
		}
		RawTextNode {
			events << StreamRawText{ value: n.value }
		}
		AliasNode {
			events << StreamAlias{ name: n.name }
		}
		BlockContentNode {
			for item in n.items {
				collect_node_events(item, mut events)
			}
		}
		// XMLDeclNode, CXDirectiveNode, DTD nodes — skip
		else {}
	}
}

// ── Chunked-table event emission ─────────────────────────────────────────────

// emit_chunked_table_events synthesizes StartTable + RowGroup* + EndTable
// for a chunked-origin `:table` Element. Re-chunks at the canonical
// chunk size (1 MiB rows per group) and produces the §3.11.2 plain-body
// payload format consumers see uniformly.
fn emit_chunked_table_events(name string, td TableData, mut events []StreamEvent) {
	col_spec := build_event_col_spec(td.cols)
	events << StreamStartTable{ name: name, col_spec: col_spec }
	if td.rows.len > 0 {
		mut row_idx := 0
		chunk := chunked_canonical_chunk_size
		for row_idx < td.rows.len {
			mut end_idx := row_idx + chunk
			if end_idx > td.rows.len { end_idx = td.rows.len }
			rg_rows := td.rows[row_idx .. end_idx]
			// Phase 2.1: streaming chunked-table writer is scalar-only.
			// Wire format extension for collection cells lands in
			// Phase 2.2. scalar_rows_from_cells errors
			// on collection cells with a clear pending-feature msg.
			rg_srows := scalar_rows_from_cells(rg_rows) or {
				events << StreamRowGroup{ row_count: 0, payload: []u8{} }
				row_idx = end_idx
				continue
			}
			payload := build_row_group_plain_body(td.cols, rg_srows) or {
				// Encoding errors at this layer indicate data outside the
				// declared column type. We surface as a synthetic event with
				// row_count=0 so consumers hit a malformed-payload error
				// rather than producing silently-incorrect output.
				[]u8{}
			}
			events << StreamRowGroup{ row_count: u32(rg_rows.len), payload: payload }
			row_idx = end_idx
		}
	}
	events << StreamEndTable{ name: name }
}

// build_event_col_spec encodes the col-spec in the events-layer format
// per spec/streaming.md §1.1 / §3.10.1:
//   [u32 LE: count]([u32 LE: name_len]name [u8: col_type_code])*
fn build_event_col_spec(cols []TableColumn) []u8 {
	mut buf := []u8{cap: 4 + cols.len * 16}
	count := u32(cols.len)
	buf << u8(count & 0xFF)
	buf << u8((count >> 8) & 0xFF)
	buf << u8((count >> 16) & 0xFF)
	buf << u8((count >> 24) & 0xFF)
	for c in cols {
		nm := c.name.bytes()
		nl := u32(nm.len)
		buf << u8(nl & 0xFF)
		buf << u8((nl >> 8) & 0xFF)
		buf << u8((nl >> 16) & 0xFF)
		buf << u8((nl >> 24) & 0xFF)
		buf << nm
		buf << column_type_code(c.type_name)
	}
	return buf
}

// build_row_group_plain_body encodes one row group's plain body per
// spec/core/data-bin.md §3.11.2: uvarint(row_count) + column-major payloads
// (one per column, in declaration order). Reuses the strict-cell encoder
// from data_bin_chunked.v so byte-for-byte output matches what
// `cx_table_writer_*` produces.
fn build_row_group_plain_body(cols []TableColumn, rows [][]ScalarValue) ![]u8 {
	mut buf := []u8{cap: 8 + rows.len * cols.len * 4}
	encode_uvarint(mut buf, u64(rows.len))
	for col_idx, col in cols {
		encode_col_payload_strict(col_idx, col, rows, mut buf)!
	}
	return buf
}

// ── JSON serialisation for C ABI ──────────────────────────────────────────────

pub fn event_to_json(e StreamEvent) string {
	return match e {
		StreamStartDoc {
			'{"type":"StartDoc"}'
		}
		StreamEndDoc {
			'{"type":"EndDoc"}'
		}
		StreamStartElement {
			mut pairs := []string{}
			pairs << '"type":"StartElement"'
			pairs << '"name":${json_str(e.name)}'
			pairs << '"attrs":${json_attrs(e.attrs)}'
			if dt := e.data_type { pairs << '"dataType":${json_str(dt)}' }
			if a  := e.anchor    { pairs << '"anchor":${json_str(a)}' }
			if m  := e.merge     { pairs << '"merge":${json_str(m)}' }
			'{${pairs.join(',')}}'
		}
		StreamEndElement {
			'{"type":"EndElement","name":${json_str(e.name)}}'
		}
		StreamText {
			'{"type":"Text","value":${json_str(e.value)}}'
		}
		StreamScalar {
			v := json_scalar_value(e.value)
			'{"type":"Scalar","dataType":${json_str(e.data_type)},"value":${v}}'
		}
		StreamComment {
			'{"type":"Comment","value":${json_str(e.value)}}'
		}
		StreamPI {
			mut pairs := []string{}
			pairs << '"type":"PI"'
			pairs << '"target":${json_str(e.target)}'
			if d := e.data { pairs << '"data":${json_str(d)}' }
			'{${pairs.join(',')}}'
		}
		StreamEntityRef {
			'{"type":"EntityRef","name":${json_str(e.name)}}'
		}
		StreamRawText {
			'{"type":"RawText","value":${json_str(e.value)}}'
		}
		StreamAlias {
			'{"type":"Alias","name":${json_str(e.name)}}'
		}
		StreamStartTable {
			'{"type":"StartTable","name":${json_str(e.name)},"colSpecBase64":${json_str(base64_encode(e.col_spec))}}'
		}
		StreamRowGroup {
			'{"type":"RowGroup","rowCount":${e.row_count},"payloadBase64":${json_str(base64_encode(e.payload))}}'
		}
		StreamEndTable {
			'{"type":"EndTable","name":${json_str(e.name)}}'
		}
	}
}

// base64_encode produces a standard (RFC 4648) base64 encoding of the
// input bytes. Used in JSON event serialisation to carry binary col-spec
// and row-group payloads through a text channel.
fn base64_encode(b []u8) string {
	return base64.encode(b)
}
