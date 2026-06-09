module cx

import math

// CXCol v1 — strict canonical binary data format.
// Specification: spec/core/data-bin.md.
//
// This file implements the encoder (emit_data_bin) per spec/core/data-bin.md
// §3. The decoder (parse_data_bin) lives alongside in 2b.5. The C ABI
// exports (cx_to_data_bin / cx_from_data_bin) live in cabi.v.
//
// Design principles:
//   - Strict canonical: byte-identical output across implementations
//     for the same input. Minimal-width varints. Narrowest scalar
//     tag that preserves value.
//   - Walks Document → semantic-data projection (mirrors
//     emit_semantic_json's tree-shape rules) → binary bytes.
//   - One pass, no intermediate JSON.

// ── Tag bytes (spec/core/data-bin.md §3.2) ────────────────────────────────────────

const tag_null         = u8(0x00)
const tag_false        = u8(0x01)
const tag_true         = u8(0x02)
const tag_int8         = u8(0x10)
const tag_int16        = u8(0x11)
const tag_int32        = u8(0x12)
const tag_int64        = u8(0x13)
const tag_float64      = u8(0x20)
const tag_string       = u8(0x30)
const tag_date         = u8(0x31)
const tag_datetime     = u8(0x32)
const tag_bytes        = u8(0x33)
const tag_array        = u8(0x40)
const tag_array_empty  = u8(0x41)
const tag_map          = u8(0x50)
const tag_map_empty    = u8(0x51)
const tag_table        = u8(0x60)
const tag_table_empty  = u8(0x61)

// CXCol header constants. The 5-byte magic is "CXCol"; documents not
// matching this magic are rejected at header parse (no fallback).
// The header total is 12 bytes.
const cxcol_magic_len   = 5
const cxcol_magic       = [u8(0x43), 0x58, 0x43, 0x6F, 0x6C]   // "CXCol"
const cxcol_version     = u8(0x01)
const cxcol_flags_le    = u8(0x01)
const cxcol_default_depth = u32(64)

// ── Public entry points ──────────────────────────────────────────────────────

// emit_data_bin encodes a Document as CXCol v1 strict-canonical bytes.
// The output is the framing format `[u32 LE: payload_size][payload]`
// matching cx_to_ast_bin / cx_to_events_bin. The first 4 bytes give
// the payload size; payload is the CXCol document.
pub fn emit_data_bin(doc Document) []u8 {
	mut payload := []u8{cap: 256}
	encode_header(mut payload)
	encode_document_root(doc, mut payload)
	return frame_payload(payload)
}

fn frame_payload(payload []u8) []u8 {
	mut buf := []u8{cap: payload.len + 4}
	sz := u32(payload.len)
	buf << u8(sz & 0xFF)
	buf << u8((sz >> 8) & 0xFF)
	buf << u8((sz >> 16) & 0xFF)
	buf << u8((sz >> 24) & 0xFF)
	buf << payload
	return buf
}

fn encode_header(mut buf []u8) {
	buf << cxcol_magic
	buf << cxcol_version
	buf << cxcol_flags_le
	encode_u32_le(mut buf, cxcol_default_depth)
	buf << u8(0)  // reserved (1 byte — magic grew from 4→5 in v0.8.0)
}

// ── Document → semantic-data projection ──────────────────────────────────────

fn encode_document_root(doc Document, mut buf []u8) {
	// Value-model document — a single CXDM value at top level (a Map / Array /
	// Sequence / Scalar, not a named Element), as produced by the lossless
	// JSON / value-codec read. Encode the value directly so it round-trips
	// (the keyed-collection path below only sees named Elements).
	if doc.elements.len == 1 {
		only := doc.elements[0]
		if only !is Element {
			encode_dataval(node_to_dataval(only), mut buf)
			return
		}
	}
	roots := doc.elements.filter(it is Element)
	if roots.len == 0 {
		buf << tag_null
		return
	}
	encode_keyed_collection(roots, mut buf)
}

fn encode_keyed_collection(roots []Node, mut buf []u8) {
	// Build (key, value) pairs respecting same-name → array semantics
	// per emit_semantic.v's push_keyed.
	mut keys := []string{cap: roots.len}
	mut vals := []DataVal{cap: roots.len}
	for n in roots {
		if n is Element {
			e := n as Element
			v := element_to_dataval(e)
			pushed := dataval_push_keyed(mut keys, mut vals, e.name, v)
			_ = pushed
		}
	}
	if keys.len == 0 {
		buf << tag_map_empty
		return
	}
	buf << tag_map
	encode_uvarint(mut buf, u64(keys.len))
	for i, k in keys {
		encode_string_value(k, mut buf)
		encode_dataval(vals[i], mut buf)
	}
}

// ── Internal value representation ────────────────────────────────────────────
//
// DataVal is a sum type matching the on-wire shape: null/bool/int/
// float/string/date/datetime/bytes/array/map/table. The Document →
// DataVal projection happens in element_to_dataval; encoding to bytes
// happens in encode_dataval.

pub type DataVal = DataNull
	| bool
	| i64
	| f64
	| string
	| DataDate
	| DataDateTime
	| DataBytes
	| []DataVal
	| DataPairs
	| DataTable

pub struct DataNull {}

pub struct DataDate {
pub:
	year  i16
	month u8
	day   u8
}

pub struct DataDateTime {
pub:
	source string  // raw ISO-8601 source; encoder parses to canonical form
}

pub struct DataBytes {
pub:
	value []u8
}

// DataPairs preserves insertion order of map keys (string → value).
pub struct DataPairs {
pub mut:
	keys []string
	vals []DataVal
}

pub struct DataTable {
pub mut:
	cols []TableColumn
	// rows admits both scalars and collection-literal cells per
	// DataVal's `[]DataVal`
	// DataPairs variants already encode arrays and maps on the
	// wire; collection-cell support reuses these paths (Phase 2.2,
	// 2026-05-12). Pre-Phase-2.2 code that produced [][]ScalarValue
	// here now uses scalar_values_to_dataval_rows / the dataval-
	// rows-back-to-scalars helper where downstream consumers (csv,
	// chunked-table) still expect scalars.
	rows [][]DataVal
	// from_chunked: see TableData.from_chunked. Propagated from the
	// chunked-table reader (`tag_table_chunked` payload) through to the
	// AST so the streaming walker can pick the chunked event sequence.
	from_chunked bool
}

// scalar_rows_to_dataval_rows lifts the pre-collection-cells row
// shape ([][]ScalarValue used by csv parser / chunked-table reader)
// into [][]DataVal for DataTable. Cleaner than wrapping every call
// site individually; lossless since every ScalarValue has a 1:1
// DataVal mapping via scalar_value_to_dataval.
fn scalar_rows_to_dataval_rows(rows [][]ScalarValue) [][]DataVal {
	mut out := [][]DataVal{cap: rows.len}
	for row in rows {
		mut drow := []DataVal{cap: row.len}
		for s in row { drow << scalar_value_to_dataval(s) }
		out << drow
	}
	return out
}

// dataval_rows_to_scalar_rows projects DataTable.rows back to
// [][]ScalarValue for the strict-canonical chunked-table writer
// (`0x63`) and other strict scalar-only paths. Errors if any cell
// is a collection-literal — chunked format is columnar / strict
// and cannot encode variable-shape cells.
fn dataval_rows_to_scalar_rows(rows [][]DataVal) ![][]ScalarValue {
	mut out := [][]ScalarValue{cap: rows.len}
	for row_idx, row in rows {
		mut srow := []ScalarValue{cap: row.len}
		for col_idx, v in row {
			s := dataval_to_scalar_value(v) or {
				return error('row ${row_idx} col ${col_idx}: collection-literal cell not supported on strict (chunked-table / CSV-scalar) path')
			}
			srow << s
		}
		out << srow
	}
	return out
}

fn dataval_to_scalar_value(v DataVal) ?ScalarValue {
	return match v {
		i64      { ScalarValue(v) }
		f64      { ScalarValue(v) }
		bool     { ScalarValue(v) }
		string   { ScalarValue(v) }
		DataNull { ScalarValue(NullValue{}) }
		else     { none }
	}
}

fn dataval_rows_to_table_cell_rows(rows [][]DataVal) ![][]TableCellValue {
	mut out := [][]TableCellValue{cap: rows.len}
	for row in rows {
		mut crow := []TableCellValue{cap: row.len}
		for v in row {
			c := dataval_to_table_cell(v)!
			crow << c
		}
		out << crow
	}
	return out
}

fn element_to_dataval(e Element) DataVal {
	if td := e.table_opt() {
		// Phase 2.2 (collection-cell rollout): DataTable.rows
		// is [][]DataVal — each cell may be a scalar OR a collection
		// (array/map). table_cell_to_dataval handles per-cell
		// conversion including recursive node→DataVal for nested
		// collection items.
		mut drows := [][]DataVal{cap: td.rows.len}
		for row in td.rows {
			mut drow := []DataVal{cap: row.len}
			for cell in row { drow << table_cell_to_dataval(cell) }
			drows << drow
		}
		return DataVal(DataTable{ cols: td.cols, rows: drows, from_chunked: td.from_chunked })
	}
	content := e.items.filter(
		!(it is CommentNode) && !(it is PINode)
		&& !(it is XMLDeclNode) && !(it is CXDirectiveNode)
		&& !(it is InterpolationNode) && !(it is EvalDirectiveNode)
	)
	has_attrs    := e.attrs.len > 0
	has_elements := content.any(it is Element)
	all_scalars  := content.len > 0 && content.all(it is ScalarNode)
	has_text     := content.any(it is TextNode || it is RawTextNode
		|| it is EntityRefNode || it is BlockContentNode)

	if !has_attrs && all_scalars {
		if content.len == 1 {
			s := content[0] as ScalarNode
			return scalar_value_to_dataval(s.value)
		}
		mut arr := []DataVal{cap: content.len}
		for n in content {
			s := n as ScalarNode
			arr << scalar_value_to_dataval(s.value)
		}
		return arr
	}
	if !has_attrs && !has_elements && has_text {
		return DataVal(collect_text_for_dataval(content))
	}
	if !has_attrs && content.len == 0 {
		return DataVal(DataNull{})
	}
	mut keys := []string{}
	mut vals := []DataVal{}
	for attr in e.attrs {
		keys << attr.name
		vals << scalar_value_to_dataval(attr.value)
	}
	if has_elements {
		for n in content {
			match n {
				Element {
					nv := element_to_dataval(n)
					_ = dataval_push_keyed(mut keys, mut vals, n.name, nv)
				}
				TextNode {
					if n.value.trim_space().len > 0 {
						_ = dataval_push_keyed(mut keys, mut vals, '_', DataVal(n.value))
					}
				}
				RawTextNode {
					_ = dataval_push_keyed(mut keys, mut vals, '_', DataVal(n.value))
				}
				EntityRefNode {
					_ = dataval_push_keyed(mut keys, mut vals, '_', DataVal(entity_ref_string(n.name)))
				}
				ScalarNode {
					_ = dataval_push_keyed(mut keys, mut vals, '_', scalar_value_to_dataval(n.value))
				}
				BlockContentNode {
					for item in n.items {
						if item is TextNode {
							t := item as TextNode
							if t.value.trim_space().len > 0 {
								_ = dataval_push_keyed(mut keys, mut vals, '_', DataVal(t.value))
							}
						}
					}
				}
				else {}
			}
		}
	} else if has_attrs {
		if all_scalars && content.len == 1 {
			s := content[0] as ScalarNode
			keys << '_'
			vals << scalar_value_to_dataval(s.value)
		} else if has_text {
			keys << '_'
			vals << DataVal(collect_text_for_dataval(content))
		}
	}
	return DataVal(DataPairs{ keys: keys, vals: vals })
}

fn dataval_push_keyed(mut keys []string, mut vals []DataVal, key string, val DataVal) bool {
	for i, k in keys {
		if k == key {
			existing := vals[i]
			if existing is []DataVal {
				mut arr := existing as []DataVal
				arr << val
				vals[i] = DataVal(arr)
			} else {
				vals[i] = DataVal([existing, val])
			}
			return true
		}
	}
	keys << key
	vals << val
	return false
}

fn collect_text_for_dataval(nodes []Node) string {
	mut parts := []string{}
	for n in nodes {
		match n {
			TextNode      { parts << n.value }
			RawTextNode   { parts << n.value }
			EntityRefNode { parts << entity_ref_string(n.name) }
			BlockContentNode {
				for item in n.items {
					if item is TextNode { parts << (item as TextNode).value }
				}
			}
			else {}
		}
	}
	return parts.join('')
}

fn entity_ref_string(name string) string {
	return match name {
		'amp'  { '&' }
		'lt'   { '<' }
		'gt'   { '>' }
		'apos' { "'" }
		'quot' { '"' }
		else   { '&${name};' }
	}
}

fn scalar_value_to_dataval(v ScalarValue) DataVal {
	return match v {
		i64       { DataVal(v) }
		f64       { DataVal(v) }
		bool      { DataVal(v) }
		NullValue { DataVal(DataNull{}) }
		string    { DataVal(v) }
	}
}

// table_cell_to_dataval converts a TableCellValue
// collection-cell-capable cell value) to DataVal for the data_bin
// wire format. Scalars map 1:1 via the existing scalar-variant
// branches; ArrayNode and MapNode delegate to node_to_dataval which
// recursively converts their items / entries; SequenceNode flattens
// per CXDM §1.2 (a Sequence is a flat sequence-of-Items, equivalent
// to an array of its leaves post-flatten).
fn table_cell_to_dataval(c TableCellValue) DataVal {
	return match c {
		i64          { DataVal(c) }
		f64          { DataVal(c) }
		bool         { DataVal(c) }
		NullValue    { DataVal(DataNull{}) }
		string       { DataVal(c) }
		ArrayNode    { array_node_to_dataval(c) }
		MapNode      { map_node_to_dataval(c) }
		SequenceNode { sequence_node_to_dataval(c) }
	}
}

// dataval_to_table_cell converts a DataVal back to a TableCellValue
// for the data_bin decode path. Scalars 1:1; arrays / maps wrap back
// into ArrayNode / MapNode. DataTable / DataDate / DataDateTime /
// DataBytes are not table-cell types — they error or coerce per the
// path (date/datetime are scalar at the CXDM layer; bytes is a CXDM
// scalar but historically not table-cell typed).
fn dataval_to_table_cell(v DataVal) !TableCellValue {
	return match v {
		i64          { TableCellValue(v) }
		f64          { TableCellValue(v) }
		bool         { TableCellValue(v) }
		string       { TableCellValue(v) }
		DataNull     { TableCellValue(NullValue{}) }
		DataDate     { TableCellValue(scalar_value_str(scalar_value_from_date(v))) }
		DataDateTime { TableCellValue(v.source) }
		DataBytes    { TableCellValue(v.value.bytestr()) }
		[]DataVal    { TableCellValue(array_dataval_to_node(v)) }
		DataPairs    { TableCellValue(map_dataval_to_node(v)) }
		DataTable    { return error('table cell cannot itself be a DataTable (nested tables not supported at v0.6.0)') }
	}
}

// node_to_dataval converts an AST Node (typically a child of an
// ArrayNode.items or MapNode.entries) into a DataVal for binary
// encoding. Handles the AST node kinds that can appear as collection
// items: ScalarNode (typed scalar literal), TextNode
// (string literal in bare/quoted form), ArrayNode / MapNode /
// SequenceNode (nested collections). Other Node kinds (Element,
// EvalDirective, Comment, ...) are not valid collection-item shapes
// in a binary-emit context; they coerce to their canonical string
// form when reached as a fallback.
fn node_to_dataval(n Node) DataVal {
	return match n {
		ScalarNode    { scalar_value_to_dataval(n.value) }
		TextNode      { DataVal(n.value) }
		ArrayNode     { array_node_to_dataval(n) }
		MapNode       { map_node_to_dataval(n) }
		SequenceNode  { sequence_node_to_dataval(n) }
		InterpolationNode { DataVal('[?=${n.expr}]') }
		else          { DataVal(DataNull{}) }
	}
}

fn array_node_to_dataval(n ArrayNode) DataVal {
	mut out := []DataVal{cap: n.items.len}
	for item in n.items {
		out << node_to_dataval(item)
	}
	return DataVal(out)
}

fn map_node_to_dataval(n MapNode) DataVal {
	mut keys := []string{cap: n.entries.len}
	mut vals := []DataVal{cap: n.entries.len}
	for entry in n.entries {
		// Map keys are atomic; canonical-string
		// form for the wire (DataPairs uses string keys).
		keys << scalar_value_str(entry.key_value)
		vals << node_to_dataval(entry.value)
	}
	return DataVal(DataPairs{ keys: keys, vals: vals })
}

fn sequence_node_to_dataval(n SequenceNode) DataVal {
	// CXDM §1.2: sequences flatten on construction. Flatten any
	// nested sequences within items, then encode as an array.
	mut out := []DataVal{cap: n.items.len}
	for item in n.items {
		if item is SequenceNode {
			inner := item as SequenceNode
			for sub in inner.items {
				out << node_to_dataval(sub)
			}
		} else {
			out << node_to_dataval(item)
		}
	}
	return DataVal(out)
}

fn array_dataval_to_node(v []DataVal) ArrayNode {
	mut items := []Node{cap: v.len}
	for item in v {
		items << dataval_to_node(item)
	}
	return ArrayNode{ items: items }
}

fn map_dataval_to_node(v DataPairs) MapNode {
	mut entries := []MapEntry{cap: v.keys.len}
	for i, k in v.keys {
		// Re-construct as a string-keyed map entry; the wire form
		// carried only string keys per DataPairs definition.
		entries << MapEntry{
			key_type:  ScalarType.string_type
			key_value: ScalarValue(k)
			value:     dataval_to_node(v.vals[i])
		}
	}
	return MapNode{ entries: entries }
}

fn dataval_to_node(v DataVal) Node {
	return match v {
		i64          { Node(ScalarNode{ data_type: ScalarType.int_type,      value: ScalarValue(v) }) }
		f64          { Node(ScalarNode{ data_type: ScalarType.float_type,    value: ScalarValue(v) }) }
		bool         { Node(ScalarNode{ data_type: ScalarType.bool_type,     value: ScalarValue(v) }) }
		string       { Node(TextNode{ value: v }) }
		DataNull     { Node(ScalarNode{ data_type: ScalarType.null_type,     value: ScalarValue(NullValue{}) }) }
		DataDate     { Node(ScalarNode{ data_type: ScalarType.date_type,     value: scalar_value_from_date(v) }) }
		DataDateTime { Node(ScalarNode{ data_type: ScalarType.datetime_type, value: ScalarValue(v.source) }) }
		DataBytes    { Node(ScalarNode{ data_type: ScalarType.bytes_type,    value: ScalarValue(v.value.bytestr()) }) }
		[]DataVal    { Node(array_dataval_to_node(v)) }
		DataPairs    { Node(map_dataval_to_node(v)) }
		DataTable    { Node(TextNode{ value: '<DataTable nested>' }) }
	}
}

// scalar_value_from_date helper for the date → wire-string transit
// used by dataval_to_table_cell + dataval_to_node when a date arrives
// at a cell or item position. Reuses canonical date formatting.
fn scalar_value_from_date(d DataDate) ScalarValue {
	// Year is i16 (signed; supports BCE), month/day are 1-based.
	year_str := d.year.str()
	mm := if d.month < 10 { '0${d.month}' } else { d.month.str() }
	dd := if d.day < 10   { '0${d.day}'   } else { d.day.str()   }
	return ScalarValue('${year_str}-${mm}-${dd}')
}

// ── DataVal → bytes ──────────────────────────────────────────────────────────

fn encode_dataval(v DataVal, mut buf []u8) {
	match v {
		DataNull     { buf << tag_null }
		bool         { buf << if v { tag_true } else { tag_false } }
		i64          { encode_int_canonical(v, mut buf) }
		f64          { encode_float64(v, mut buf) }
		string       { encode_string_value(v, mut buf) }
		DataDate     { encode_date(v, mut buf) }
		DataDateTime { encode_datetime(v, mut buf) }
		DataBytes    { encode_bytes_value(v.value, mut buf) }
		[]DataVal    { encode_array(v, mut buf) }
		DataPairs    { encode_pairs(v, mut buf) }
		DataTable    { encode_table(v, mut buf) }
	}
}

fn encode_int_canonical(v i64, mut buf []u8) {
	// Pick the narrowest signed-int tag that preserves the value.
	if v >= -128 && v <= 127 {
		buf << tag_int8
		buf << u8(v)
		return
	}
	if v >= -32768 && v <= 32767 {
		buf << tag_int16
		x := u16(u32(v))
		buf << u8(x & 0xFF)
		buf << u8((x >> 8) & 0xFF)
		return
	}
	if v >= -2147483648 && v <= 2147483647 {
		buf << tag_int32
		encode_u32_le(mut buf, u32(v))
		return
	}
	buf << tag_int64
	encode_u64_le(mut buf, u64(v))
}

fn encode_float64(v f64, mut buf []u8) {
	// NaN / Inf rejection per spec/policies.md §1.1, §1.2.
	// Encoder treats NaN/Inf as invalid input — caller should
	// validate before calling. We emit the bits unmodified here;
	// an explicit pre-validation step in cabi will reject.
	bits := math.f64_bits(v)
	buf << tag_float64
	encode_u64_le(mut buf, bits)
}

fn encode_string_value(s string, mut buf []u8) {
	buf << tag_string
	encode_uvarint(mut buf, u64(s.len))
	buf << s.bytes()
}

fn encode_bytes_value(b []u8, mut buf []u8) {
	buf << tag_bytes
	encode_uvarint(mut buf, u64(b.len))
	buf << b
}

fn encode_date(d DataDate, mut buf []u8) {
	buf << tag_date
	yu := u16(u32(d.year))
	buf << u8(yu & 0xFF)
	buf << u8((yu >> 8) & 0xFF)
	buf << d.month
	buf << d.day
}

fn encode_datetime(d DataDateTime, mut buf []u8) {
	// Phase 7.74c-datetime-foundations: parse ISO-8601 source to
	// strict-canonical 12-byte wire form per spec/core/data-bin.md §3.6.1.
	// On parse failure, emit zeros — encoder is best-effort here; the
	// chunked strict-cell encoder (data_bin_chunked.v) returns errors
	// up to the caller via its `!` signature.
	ns, _ := parse_iso_datetime_canonical(d.source) or { i64(0), i16(0) }
	buf << tag_datetime
	encode_u64_le(mut buf, u64(ns))
	// offset_minutes = 0 in strict canonical (spec §3.6.1 normalization).
	buf << u8(0)
	buf << u8(0)
	// reserved u16 = 0
	buf << u8(0)
	buf << u8(0)
}

// parse_iso_datetime_canonical parses an ISO-8601 datetime string into
// (unix_nanos, parsed_offset_minutes). The unix_nanos is already
// normalized to UTC. parsed_offset_minutes is returned for diagnostic
// purposes only — strict canonical wire form always emits offset = 0.
//
// Accepted grammar (subset of ISO-8601 / RFC 3339):
//   YYYY-MM-DDTHH:MM:SS[.<frac>][Z|z|±HH:MM]
//
// - Fractional seconds beyond 9 digits are truncated (ns precision floor).
// - Naive datetimes (no Z / ±HH:MM) are treated as UTC (offset = 0).
// - Leap seconds (sec=60) are rejected; CXCol ns timeline ignores them.
// - i64-ns range overflow (year < 1677 or > 2262) is rejected.
pub fn parse_iso_datetime_canonical(s string) !(i64, i16) {
	if s.len < 19 {
		return error('cxcol: datetime too short: "${s}"')
	}
	bs := s.bytes()
	if bs[4] != `-` || bs[7] != `-` || bs[10] != `T` || bs[13] != `:` || bs[16] != `:` {
		return error('cxcol: malformed datetime "${s}" (expected YYYY-MM-DDTHH:MM:SS...)')
	}
	year := s[0..4].i16()
	month := s[5..7].u8()
	day := s[8..10].u8()
	hour := s[11..13].u8()
	minute := s[14..16].u8()
	sec := s[17..19].u8()
	if month < 1 || month > 12 { return error('cxcol: datetime invalid month ${month} in "${s}"') }
	if day < 1 || day > 31     { return error('cxcol: datetime invalid day ${day} in "${s}"') }
	if hour > 23               { return error('cxcol: datetime invalid hour ${hour} in "${s}"') }
	if minute > 59             { return error('cxcol: datetime invalid minute ${minute} in "${s}"') }
	if sec == 60               { return error('cxcol: datetime leap seconds not supported (sec=60) in "${s}"') }
	if sec > 59                { return error('cxcol: datetime invalid second ${sec} in "${s}"') }

	mut pos := 19
	mut frac_ns := i64(0)
	if pos < s.len && bs[pos] == `.` {
		pos++
		mut digits := 0
		for pos < s.len && bs[pos] >= `0` && bs[pos] <= `9` && digits < 9 {
			frac_ns = frac_ns * 10 + i64(bs[pos] - `0`)
			digits++
			pos++
		}
		for digits < 9 {
			frac_ns *= 10
			digits++
		}
		// truncate (don't error) excess sub-ns digits
		for pos < s.len && bs[pos] >= `0` && bs[pos] <= `9` {
			pos++
		}
	}

	mut offset_min := i16(0)
	if pos < s.len {
		ch := bs[pos]
		if ch == `Z` || ch == `z` {
			offset_min = 0
			pos++
		} else if ch == `+` || ch == `-` {
			if pos + 6 > s.len || bs[pos + 3] != `:` {
				return error('cxcol: malformed offset in datetime "${s}" (expected ±HH:MM)')
			}
			oh := s[pos + 1..pos + 3].i16()
			om := s[pos + 4..pos + 6].i16()
			if oh > 18 || om > 59 {
				return error('cxcol: offset out of range in datetime "${s}"')
			}
			signed := oh * 60 + om
			offset_min = if ch == `+` { signed } else { -signed }
			if offset_min < -1080 || offset_min > 1080 {
				return error('cxcol: offset exceeds ±18:00 in datetime "${s}"')
			}
			pos += 6
		} else {
			return error('cxcol: unexpected char in datetime "${s}" at byte ${pos}')
		}
	}
	if pos != s.len {
		return error('cxcol: trailing garbage in datetime "${s}" at byte ${pos}')
	}

	days := date_to_days_proleptic(year, month, day)
	local_secs := i64(days) * 86_400 + i64(hour) * 3_600 + i64(minute) * 60 + i64(sec)
	utc_secs := local_secs - i64(offset_min) * 60
	// i64 ns range: ±9_223_372_036.854 seconds (~292 years from epoch).
	if utc_secs > i64(9_223_372_036) || utc_secs < i64(-9_223_372_036) {
		return error('cxcol: datetime "${s}" out of i64-ns range (year ~1677..2262)')
	}
	unix_nanos := utc_secs * i64(1_000_000_000) + frac_ns
	return unix_nanos, offset_min
}

// format_iso_datetime_utc formats (unix_nanos, offset_min) as ISO-8601.
// Strict-canonical readers always pass offset_min = 0; non-canonical
// inputs preserve the original offset for round-trip on lenient reads.
// Trailing zeros in the fractional part are trimmed; sub-second 0
// emits no fractional part at all.
pub fn format_iso_datetime_utc(unix_nanos i64, offset_min i16) string {
	// Apply offset for local rendering: local_ns = unix_ns + offset*60e9
	local_ns := unix_nanos + i64(offset_min) * i64(60) * i64(1_000_000_000)
	ns_per_day := i64(86_400) * i64(1_000_000_000)
	mut days64 := local_ns / ns_per_day
	mut tod_ns := local_ns % ns_per_day
	if tod_ns < 0 {
		tod_ns += ns_per_day
		days64 -= 1
	}
	year, month, day := days_to_date_proleptic(i32(days64))
	tod_secs := tod_ns / i64(1_000_000_000)
	frac_ns  := tod_ns % i64(1_000_000_000)
	hour := u8(tod_secs / 3_600)
	minute := u8((tod_secs % 3_600) / 60)
	sec := u8(tod_secs % 60)
	mut s := '${int(year):04d}-${int(month):02d}-${int(day):02d}T${int(hour):02d}:${int(minute):02d}:${int(sec):02d}'
	if frac_ns != 0 {
		mut fs := '${frac_ns:09d}'
		mut end := fs.len
		for end > 0 && fs[end - 1] == `0` { end-- }
		s += '.' + fs[..end]
	}
	if offset_min == 0 {
		s += 'Z'
	} else {
		sign := if offset_min < 0 { '-' } else { '+' }
		ab := if offset_min < 0 { -int(offset_min) } else { int(offset_min) }
		s += '${sign}${ab / 60:02d}:${ab % 60:02d}'
	}
	return s
}

// Howard Hinnant proleptic Gregorian: (year, month, day) ↔ days since
// 1970-01-01. Range covers roughly year [-5877641, +5879610]. Mirrors
// the helpers in vcx/arrow/arrow.v::date_to_days/days_to_date so the
// cx core has no dependency on the optional arrow module.
fn date_to_days_proleptic(year i16, month u8, day u8) i32 {
	mut y := i32(year)
	if month <= 2 { y -= 1 }
	era := if y >= 0 { y / 400 } else { (y - 399) / 400 }
	yoe := y - era * 400
	mm := i32(month)
	doy := (153 * (mm + if mm > 2 { i32(-3) } else { i32(9) }) + 2) / 5 + i32(day) - 1
	doe := yoe * 365 + yoe / 4 - yoe / 100 + doy
	return era * 146097 + doe - 719468
}

fn days_to_date_proleptic(z i32) (i16, u8, u8) {
	zz := z + 719468
	era := if zz >= 0 { zz / 146097 } else { (zz - 146096) / 146097 }
	doe := zz - era * 146097
	yoe := (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
	mut y := yoe + era * 400
	doy := doe - (365 * yoe + yoe / 4 - yoe / 100)
	mp := (5 * doy + 2) / 153
	d := doy - (153 * mp + 2) / 5 + 1
	m := mp + if mp < 10 { i32(3) } else { i32(-9) }
	if m <= 2 { y += 1 }
	return i16(y), u8(m), u8(d)
}

fn encode_array(arr []DataVal, mut buf []u8) {
	if arr.len == 0 {
		buf << tag_array_empty
		return
	}
	buf << tag_array
	encode_uvarint(mut buf, u64(arr.len))
	for v in arr {
		encode_dataval(v, mut buf)
	}
}

fn encode_pairs(p DataPairs, mut buf []u8) {
	if p.keys.len == 0 {
		buf << tag_map_empty
		return
	}
	buf << tag_map
	encode_uvarint(mut buf, u64(p.keys.len))
	for i, k in p.keys {
		encode_string_value(k, mut buf)
		encode_dataval(p.vals[i], mut buf)
	}
}

fn encode_table(t DataTable, mut buf []u8) {
	if t.cols.len == 0 {
		buf << tag_table_empty
		return
	}
	buf << tag_table
	encode_uvarint(mut buf, u64(t.cols.len))
	for col in t.cols {
		encode_string_value(col.name, mut buf)
		buf << column_type_code(col.type_name)
	}
	encode_uvarint(mut buf, u64(t.rows.len))
	for col_idx, col in t.cols {
		code := column_type_code(col.type_name)
		for row in t.rows {
			if col_idx < row.len {
				encode_table_cell(row[col_idx], code, mut buf)
			} else {
				buf << tag_null
			}
		}
	}
}

fn column_type_code(type_name string) u8 {
	return match type_name {
		'int', 'i64'         { tag_int64 }
		'i8'                 { tag_int8 }
		'i16'                { tag_int16 }
		'i32'                { tag_int32 }
		'u8', 'u16', 'u32', 'u64' { tag_int64 }  // unsigned promoted to i64 in v1
		'float', 'f64'       { tag_float64 }
		'f32', 'f16'         { tag_float64 }      // promoted in v1
		'bool'               { tag_true }         // sentinel; bit-pack later
		'string', '', 's'    { tag_string }
		'date', 'd'          { tag_date }
		'datetime', 'dt'     { tag_datetime }
		'bytes'              { tag_bytes }
		else                 { tag_string }
	}
}

fn encode_table_cell(v DataVal, _col_code u8, mut buf []u8) {
	// In v1 we emit a per-cell tag for simplicity (mirrors plain
	// container encoding). The columnar-omit-tag optimization per
	// spec/core/data-bin.md §3.10.3 — where the column type is declared
	// once and per-cell tags are dropped — is reserved for v1.1.
	// _col_code is the planned input for that optimization.
	//
	// Phase 2.2: cell is DataVal (was ScalarValue),
	// admitting `[]DataVal` (array) / DataPairs (map) variants for
	// collection cells. encode_dataval already dispatches on all
	// variants — no per-variant branching needed here.
	encode_dataval(v, mut buf)
}

// ── Varint and primitive byte helpers ────────────────────────────────────────

fn encode_uvarint(mut buf []u8, v u64) {
	mut x := v
	for x >= 0x80 {
		buf << u8(u32(x) & 0x7F | 0x80)
		x >>= 7
	}
	buf << u8(x & 0x7F)
}

fn encode_u32_le(mut buf []u8, v u32) {
	buf << u8(v & 0xFF)
	buf << u8((v >> 8) & 0xFF)
	buf << u8((v >> 16) & 0xFF)
	buf << u8((v >> 24) & 0xFF)
}

fn encode_u64_le(mut buf []u8, v u64) {
	buf << u8(v & 0xFF)
	buf << u8((v >> 8) & 0xFF)
	buf << u8((v >> 16) & 0xFF)
	buf << u8((v >> 24) & 0xFF)
	buf << u8((v >> 32) & 0xFF)
	buf << u8((v >> 40) & 0xFF)
	buf << u8((v >> 48) & 0xFF)
	buf << u8((v >> 56) & 0xFF)
}

// ── CXCol v1 decoder (Phase 2b.5) ─────────────────────────────────────────────

// BinReader is a forward-only cursor over a CXCol payload. Tracks
// position and recursion depth; aborts on overflow per spec/policies.md
// §5.4.
struct BinReader {
mut:
	buf       []u8
	pos       int
	depth     int
	max_depth int
}

// parse_data_bin decodes CXCol v1 framed bytes into a Document.
// Input format: `[u32 LE: payload_size][payload bytes]` matching
// emit_data_bin's output. Returns Document for use with emit_cx.
pub fn parse_data_bin(input []u8) !Document {
	if input.len < 4 {
		return error('cxcol: input too short for size header')
	}
	payload_size := u32(input[0]) | (u32(input[1]) << 8)
		| (u32(input[2]) << 16) | (u32(input[3]) << 24)
	if 4 + int(payload_size) > input.len {
		return error('cxcol: declared payload (${payload_size}) exceeds remaining input')
	}
	// Reader views the payload as a read-only slice; no clone needed.
	mut r := BinReader{
		buf:       unsafe { input[4 .. 4 + int(payload_size)] }
		pos:       0
		depth:     0
		max_depth: int(cxcol_default_depth)
	}
	r.read_header()!
	root := r.read_dataval()!
	if r.pos != r.buf.len {
		return error('cxcol: trailing bytes after root value (${r.buf.len - r.pos} bytes)')
	}
	return dataval_to_document(root)!
}

// from_data_bin is the inverse of emit_data_bin: bytes → CX text.
pub fn from_data_bin(input []u8) !string {
	doc := parse_data_bin(input)!
	return emit_cx(doc)
}

// ── Reader primitives ────────────────────────────────────────────────────────

fn (mut r BinReader) take(n int) ![]u8 {
	if r.pos + n > r.buf.len {
		return error('cxcol: ${n} bytes requested, only ${r.buf.len - r.pos} remaining')
	}
	out := r.buf[r.pos .. r.pos + n]
	r.pos += n
	return out
}

fn (mut r BinReader) take_u8() !u8 {
	if r.pos >= r.buf.len { return error('cxcol: unexpected end of input') }
	v := r.buf[r.pos]
	r.pos++
	return v
}

fn (mut r BinReader) read_uvarint() !u64 {
	mut x := u64(0)
	mut s := u32(0)
	for i in 0 .. 5 {
		if r.pos >= r.buf.len { return error('cxcol: truncated varint') }
		b := r.buf[r.pos]
		r.pos++
		if b < 0x80 {
			if i == 4 && b > 0x0F {
				return error('cxcol: varint overflow (>2^32-1)')
			}
			if i > 0 && b == 0 {
				return error('cxcol: non-canonical varint (extra zero byte)')
			}
			x |= u64(b) << s
			return x
		}
		x |= u64(b & 0x7F) << s
		s += 7
	}
	return error('cxcol: varint exceeds 5 bytes')
}

fn (mut r BinReader) read_u32_le() !u32 {
	bs := r.take(4)!
	return u32(bs[0]) | (u32(bs[1]) << 8) | (u32(bs[2]) << 16) | (u32(bs[3]) << 24)
}

fn (mut r BinReader) read_u64_le() !u64 {
	bs := r.take(8)!
	mut v := u64(0)
	for i in 0 .. 8 {
		v |= u64(bs[i]) << (i * 8)
	}
	return v
}

fn (mut r BinReader) read_header() ! {
	if r.buf.len < 12 {
		return error('cxcol: payload too short for 12-byte header')
	}
	magic := r.take(cxcol_magic_len)!
	if magic[0] != cxcol_magic[0] || magic[1] != cxcol_magic[1]
		|| magic[2] != cxcol_magic[2] || magic[3] != cxcol_magic[3]
		|| magic[4] != cxcol_magic[4] {
		return error('cxcol: bad magic (expected "CXCol")')
	}
	version := r.take_u8()!
	if version != cxcol_version {
		return error('cxcol: unsupported version ${version} (this build supports ${cxcol_version})')
	}
	flags := r.take_u8()!
	if flags & 0xFE != 0 {
		return error('cxcol: reserved flag bits set in header')
	}
	if flags & 0x01 == 0 {
		return error('cxcol: only little-endian payloads supported in v1')
	}
	hdr_max_depth := r.read_u32_le()!
	r.max_depth = int(hdr_max_depth)
	rsv1 := r.take_u8()!
	if rsv1 != 0 {
		return error('cxcol: reserved header byte must be zero')
	}
}

// ── DataVal decoding ─────────────────────────────────────────────────────────

fn (mut r BinReader) read_dataval() !DataVal {
	r.depth++
	if r.depth > r.max_depth {
		return error('cxcol: recursion depth exceeds limit (${r.max_depth})')
	}
	defer { r.depth-- }
	tag := r.take_u8()!
	v := match tag {
		tag_null         { DataVal(DataNull{}) }
		tag_false        { DataVal(false) }
		tag_true         { DataVal(true) }
		tag_int8         { DataVal(i64(i8(r.take_u8()!))) }
		tag_int16        { DataVal(i64(r.read_i16_le()!)) }
		tag_int32        { DataVal(i64(r.read_i32_le()!)) }
		tag_int64        { DataVal(r.read_i64_le()!) }
		tag_float64      { DataVal(r.read_f64()!) }
		tag_string       { DataVal(r.read_string_payload()!) }
		tag_date         { DataVal(r.read_date_payload()!) }
		tag_datetime     { DataVal(r.read_datetime_payload()!) }
		tag_bytes        { DataVal(DataBytes{ value: r.read_bytes_payload()! }) }
		tag_array        { r.read_array_payload()! }
		tag_array_empty  { DataVal([]DataVal{}) }
		tag_map          { r.read_map_payload()! }
		tag_map_empty    { DataVal(DataPairs{ keys: []string{}, vals: []DataVal{} }) }
		tag_table        { r.read_table_payload()! }
		tag_table_empty  { DataVal(DataTable{ cols: []TableColumn{}, rows: [][]DataVal{} }) }
		tag_table_chunked { r.read_chunked_table_payload()! }
		else             { return error('cxcol: unknown tag 0x${tag:02x} at offset ${r.pos - 1}') }
	}
	return v
}

fn (mut r BinReader) read_i16_le() !i16 {
	bs := r.take(2)!
	return i16(u16(bs[0]) | (u16(bs[1]) << 8))
}

fn (mut r BinReader) read_i32_le() !i32 {
	v := r.read_u32_le()!
	return i32(v)
}

fn (mut r BinReader) read_i64_le() !i64 {
	v := r.read_u64_le()!
	return i64(v)
}

fn (mut r BinReader) read_f64() !f64 {
	bits := r.read_u64_le()!
	return math.f64_from_bits(bits)
}

fn (mut r BinReader) read_string_payload() !string {
	n := r.read_uvarint()!
	if n > u64(r.buf.len - r.pos) {
		return error('cxcol: string length ${n} exceeds remaining input')
	}
	bs := r.take(int(n))!
	return bs.bytestr()
}

fn (mut r BinReader) read_bytes_payload() ![]u8 {
	n := r.read_uvarint()!
	if n > u64(r.buf.len - r.pos) {
		return error('cxcol: bytes length ${n} exceeds remaining input')
	}
	return r.take(int(n))!.clone()
}

fn (mut r BinReader) read_date_payload() !DataDate {
	bs := r.take(4)!
	year := i16(u16(bs[0]) | (u16(bs[1]) << 8))
	month := bs[2]
	day := bs[3]
	if month < 1 || month > 12 { return error('cxcol: invalid date month ${month}') }
	if day < 1 || day > 31 { return error('cxcol: invalid date day ${day}') }
	return DataDate{ year: year, month: month, day: day }
}

fn (mut r BinReader) read_datetime_payload() !DataDateTime {
	// Wire form per spec/core/data-bin.md §3.6.1:
	// i64 unix_nanos LE (8) + i16 offset_minutes LE (2) + u16 reserved (2).
	unix_nanos := r.read_i64_le()!
	offset_min := r.read_i16_le()!
	reserved   := r.read_i16_le()!
	if reserved != 0 {
		return error('cxcol: datetime reserved bytes must be zero (got 0x${u16(reserved):04x})')
	}
	if offset_min < -1080 || offset_min > 1080 {
		return error('cxcol: datetime offset_minutes ${offset_min} exceeds ±1080 (±18:00)')
	}
	src := format_iso_datetime_utc(unix_nanos, offset_min)
	return DataDateTime{ source: src }
}

fn (mut r BinReader) read_array_payload() !DataVal {
	count := r.read_uvarint()!
	if count == 0 {
		return error('cxcol: array tag 0x40 with count=0; use 0x41 for empty arrays')
	}
	mut arr := []DataVal{cap: int(count)}
	for _ in 0 .. int(count) {
		arr << r.read_dataval()!
	}
	return DataVal(arr)
}

fn (mut r BinReader) read_map_payload() !DataVal {
	count := r.read_uvarint()!
	if count == 0 {
		return error('cxcol: map tag 0x50 with count=0; use 0x51 for empty maps')
	}
	mut keys := []string{cap: int(count)}
	mut vals := []DataVal{cap: int(count)}
	for _ in 0 .. int(count) {
		key_tag := r.take_u8()!
		if key_tag != tag_string {
			return error('cxcol: map key must be string (tag 0x30); got 0x${key_tag:02x}')
		}
		k := r.read_string_payload()!
		v := r.read_dataval()!
		keys << k
		vals << v
	}
	return DataVal(DataPairs{ keys: keys, vals: vals })
}

fn (mut r BinReader) read_table_payload() !DataVal {
	col_count := r.read_uvarint()!
	if col_count == 0 {
		return error('cxcol: table tag 0x60 with col_count=0; use 0x61 for empty tables')
	}
	mut cols := []TableColumn{cap: int(col_count)}
	for _ in 0 .. int(col_count) {
		key_tag := r.take_u8()!
		if key_tag != tag_string {
			return error('cxcol: table column name must be string (tag 0x30); got 0x${key_tag:02x}')
		}
		name := r.read_string_payload()!
		col_type_byte := r.take_u8()!
		cols << TableColumn{ name: name, type_name: column_type_name_from_code(col_type_byte) }
	}
	row_count := r.read_uvarint()!
	mut rows := [][]DataVal{cap: int(row_count)}
	for _ in 0 .. int(row_count) {
		rows << []DataVal{cap: int(col_count)}
	}
	for col_idx in 0 .. int(col_count) {
		for row_idx in 0 .. int(row_count) {
			cell := r.read_dataval()!
			// Phase 2.2: cells are DataVal — scalar
			// variants OR collection (`[]DataVal` / DataPairs). No
			// per-variant unwrapping needed; the wire format dispatch
			// already produced the right DataVal shape.
			rows[row_idx] << cell
			_ = col_idx
		}
	}
	return DataVal(DataTable{ cols: cols, rows: rows })
}

fn column_type_name_from_code(code u8) string {
	return match code {
		tag_int8     { 'i8' }
		tag_int16    { 'i16' }
		tag_int32    { 'i32' }
		tag_int64    { 'int' }
		tag_float64  { 'float' }
		tag_string   { '' }    // default — string columns dropped on emit
		tag_date     { 'date' }
		tag_datetime { 'datetime' }
		tag_bytes    { 'bytes' }
		tag_true     { 'bool' }  // sentinel byte for bool columns
		else         { '' }
	}
}

fn dataval_to_scalar(v DataVal) ScalarValue {
	if v is i64    { return ScalarValue(v as i64) }
	if v is f64    { return ScalarValue(v as f64) }
	if v is bool   { return ScalarValue(v as bool) }
	if v is string { return ScalarValue(v as string) }
	if v is DataNull { return ScalarValue(NullValue{}) }
	if v is DataBytes { return ScalarValue((v as DataBytes).value.bytestr()) }
	// Containers in a cell position are unusual; flatten via str().
	return ScalarValue('')
}

// ── DataVal → Document reconstruction ────────────────────────────────────────

// dataval_to_document reverses the projection done by
// element_to_dataval. The root must be DataPairs; each (key, value)
// pair becomes a top-level Element. Other roots (single value, array,
// table) are wrapped in a synthetic '_' element to fit the Document
// shape.
fn dataval_to_document(root DataVal) !Document {
	if root is DataPairs {
		p := root as DataPairs
		mut elements := []Node{cap: p.keys.len}
		for i, k in p.keys {
			elements << Node(dataval_to_element(k, p.vals[i]))
		}
		return Document{ elements: elements }
	}
	if root is DataNull {
		return Document{}
	}
	// Anonymous wrapper for non-map roots.
	return Document{ elements: [Node(dataval_to_element('_', root))] }
}

fn dataval_to_element(name string, v DataVal) Element {
	if v is DataTable {
		t := v as DataTable
		return Element{
			name:  name
			meta:  &ElementMeta{ data_type: ?string('table') }
			table: &TableData{
				cols: t.cols
				rows: dataval_rows_to_table_cell_rows(t.rows) or {
					panic('data_bin: decode produced unparseable cell: ${err.msg()}')
				}
				from_chunked: t.from_chunked
			}
		}
	}
	if v is DataPairs {
		p := v as DataPairs
		mut attrs := []Attribute{}
		mut items := []Node{}
		for i, k in p.keys {
			vv := p.vals[i]
			if vv is DataPairs {
				items << Node(dataval_to_element(k, vv))
			} else if vv is []DataVal {
				arr := vv as []DataVal
				for av in arr {
					items << Node(dataval_to_element(k, av))
				}
			} else if vv is DataTable {
				items << Node(dataval_to_element(k, vv))
			} else {
				attrs << new_attribute(k, dataval_to_scalar(vv), AttributeMeta{
					data_type: opt_scalar_type_name(dataval_to_scalar_type(vv))
				})
			}
		}
		return Element{ name: name, attrs: attrs, items: items }
	}
	if v is []DataVal {
		arr := v as []DataVal
		mut items := []Node{}
		for av in arr {
			items << Node(ScalarNode{
				data_type: dataval_to_scalar_type_required(av)
				value:     dataval_to_scalar(av)
			})
		}
		return Element{ name: name, items: items }
	}
	// Scalar root for this element.
	return Element{
		name:  name
		items: [Node(ScalarNode{
			data_type: dataval_to_scalar_type_required(v)
			value:     dataval_to_scalar(v)
		})]
	}
}

fn dataval_to_scalar_type(v DataVal) ?ScalarType {
	if v is i64       { return ScalarType.int_type }
	if v is f64       { return ScalarType.float_type }
	if v is bool      { return ScalarType.bool_type }
	if v is string    { return none }  // default (omitted) for strings
	if v is DataNull  { return ScalarType.null_type }
	if v is DataDate  { return ScalarType.date_type }
	if v is DataDateTime { return ScalarType.datetime_type }
	if v is DataBytes { return ScalarType.bytes_type }
	return none
}

fn dataval_to_scalar_type_required(v DataVal) ScalarType {
	t := dataval_to_scalar_type(v) or { ScalarType.string_type }
	return t
}
