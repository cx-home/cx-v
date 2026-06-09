module main

import cx

// Phase 7.74g G1 — read-side chunked-table events
// (StreamStartTable / StreamRowGroup / StreamEndTable
// + spec/streaming.md §1.1). Verifies:
//   1. CX text source `:table` Element produces existing
//      StartElement / per-cell-Scalar / EndElement (no chunked events).
//   2. Chunked data_bin source (`tag_table_chunked` = 0x63) produces
//      StartTable / RowGroup / EndTable per §1.1.
//   3. Round-trip — col_spec + plain-body bytes are well-formed and
//      decode cleanly.

const six_row_input = '[points [table[name::string score::i32]]
  alice 91
  bob 88
  carol 73
  dave 95
  eve 84
  frank 60
]'

fn test_cx_text_table_emits_start_element_not_start_table() {
	doc := cx.parse(six_row_input) or { panic('parse failed: ${err}') }
	mut s := cx.new_stream_from_doc(doc)
	events := s.collect()

	// Expect StartDoc, StartElement(points), Scalar*12 (6 rows × 2 cols),
	// EndElement, EndDoc — but the parser may produce a different shape
	// depending on how :table bodies decompose. The key invariant is:
	// no StartTable / RowGroup / EndTable events for CX text source.
	mut saw_start_table := false
	mut saw_row_group   := false
	mut saw_end_table   := false
	mut saw_start_element := false
	for e in events {
		if e is cx.StreamStartTable    { saw_start_table = true }
		if e is cx.StreamRowGroup      { saw_row_group = true }
		if e is cx.StreamEndTable      { saw_end_table = true }
		if e is cx.StreamStartElement  { saw_start_element = true }
	}
	assert !saw_start_table, 'CX text source must not emit StartTable'
	assert !saw_row_group,   'CX text source must not emit RowGroup'
	assert !saw_end_table,   'CX text source must not emit EndTable'
	assert saw_start_element, 'CX text source should still emit StartElement'
}

fn test_chunked_data_bin_source_emits_chunked_events() {
	doc := cx.parse(six_row_input) or { panic('parse failed: ${err}') }

	// Encode through the chunked emitter then re-parse via parse_data_bin.
	// The from_chunked flag flows through the chunked reader path.
	opts := cx.ChunkedEmitOptions{ chunk_size: 4, compress: .never }
	chunked_bytes := cx.emit_data_bin_chunked(doc, opts) or {
		panic('emit_data_bin_chunked failed: ${err}')
	}
	round_doc := cx.parse_data_bin(chunked_bytes) or {
		panic('parse_data_bin failed: ${err}')
	}

	mut s := cx.new_stream_from_doc(round_doc)
	events := s.collect()

	mut start_doc_count   := 0
	mut start_table_count := 0
	mut row_group_count   := 0
	mut end_table_count   := 0
	mut end_doc_count     := 0
	mut start_element_seen_for_table := false
	mut total_rows_in_groups := u32(0)
	for e in events {
		match e {
			cx.StreamStartDoc      { start_doc_count++ }
			cx.StreamEndDoc        { end_doc_count++ }
			cx.StreamStartTable    { start_table_count++ }
			cx.StreamRowGroup      { row_group_count++; total_rows_in_groups += e.row_count }
			cx.StreamEndTable      { end_table_count++ }
			cx.StreamStartElement  {
				// The chunked emitter wraps the table in a single-pair map
				// preserving the element name. After parse_data_bin, the
				// outer wrapper is the `points` element which itself owns
				// the chunked TableData — so only the StartTable triplet
				// should appear, no separate StartElement for `points`.
				if e.name == 'points' { start_element_seen_for_table = true }
			}
			else {}
		}
	}
	assert start_doc_count == 1, 'expected 1 StartDoc; got ${start_doc_count}'
	assert end_doc_count   == 1, 'expected 1 EndDoc; got ${end_doc_count}'
	assert start_table_count == 1, 'expected 1 StartTable; got ${start_table_count}'
	assert end_table_count == 1, 'expected 1 EndTable; got ${end_table_count}'
	// All 6 rows fit inside one canonical chunk (1 << 20). The reader
	// rematerialises rows into a flat TableData; the stream walker
	// re-chunks at chunked_canonical_chunk_size — so we expect 1 group.
	assert row_group_count == 1, 'expected 1 RowGroup; got ${row_group_count}'
	assert total_rows_in_groups == u32(6), 'row_count totals expected 6; got ${total_rows_in_groups}'
	assert !start_element_seen_for_table,
		'StartTable should replace StartElement for chunked-source :table'
}

fn test_chunked_event_col_spec_layout() {
	// Verifies the §1.1 col_spec wire shape:
	//   [u32 LE: count]([u32 LE: name_len]name [u8: col_type_code])*
	doc := cx.parse(six_row_input) or { panic('parse failed: ${err}') }
	opts := cx.ChunkedEmitOptions{ chunk_size: 4, compress: .never }
	chunked := cx.emit_data_bin_chunked(doc, opts) or { panic('emit: ${err}') }
	round_doc := cx.parse_data_bin(chunked) or { panic('parse_data_bin: ${err}') }
	mut s := cx.new_stream_from_doc(round_doc)
	events := s.collect()
	mut cs := []u8{}
	for e in events {
		if e is cx.StreamStartTable {
			cs = e.col_spec.clone()
			break
		}
	}
	assert cs.len >= 4, 'col_spec too short: ${cs.len} bytes'
	// count (u32 LE)
	count := u32(cs[0]) | (u32(cs[1]) << 8) | (u32(cs[2]) << 16) | (u32(cs[3]) << 24)
	assert count == u32(2), 'expected 2 columns in col_spec; got ${count}'
	// First column: name_len(u32) + name + type_code(u8). "name" = 4 bytes.
	mut p := 4
	nl1 := u32(cs[p]) | (u32(cs[p+1]) << 8) | (u32(cs[p+2]) << 16) | (u32(cs[p+3]) << 24)
	p += 4
	assert nl1 == u32(4), 'col 1 name_len expected 4; got ${nl1}'
	col1_name := cs[p .. p + int(nl1)].bytestr()
	p += int(nl1)
	assert col1_name == 'name', 'col 1 name expected "name"; got "${col1_name}"'
	col1_code := cs[p]
	p += 1
	// "string" column type code; verify it's a recognised string code
	// (currently 0x30 per data_bin tag_string).
	assert col1_code == u8(0x30), 'col 1 code expected 0x30 (string); got 0x${col1_code:02x}'
	// Second column: "score" (5 bytes) + i32 type code 0x33.
	nl2 := u32(cs[p]) | (u32(cs[p+1]) << 8) | (u32(cs[p+2]) << 16) | (u32(cs[p+3]) << 24)
	p += 4
	assert nl2 == u32(5), 'col 2 name_len expected 5; got ${nl2}'
	col2_name := cs[p .. p + int(nl2)].bytestr()
	p += int(nl2)
	assert col2_name == 'score', 'col 2 name expected "score"; got "${col2_name}"'
	col2_code := cs[p]
	assert col2_code == u8(0x12), 'col 2 code expected 0x12 (i32); got 0x${col2_code:02x}'
}
