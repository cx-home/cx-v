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
// I1 stream 11 (row 16, L46): bigint is a SEMANTIC KIND on the wire — an
// in-i64 bigint still encodes 0x18 (narrowing-within-kind: a kind is never
// erased by narrowing).
const tag_bigint       = u8(0x18)
const tag_float64      = u8(0x20)
const tag_decimal      = u8(0x28)
const tag_string       = u8(0x30)
const tag_date         = u8(0x31)
const tag_datetime     = u8(0x32)
const tag_bytes        = u8(0x33)
const tag_array        = u8(0x40)
const tag_array_empty  = u8(0x41)
const tag_map          = u8(0x50)
const tag_map_empty    = u8(0x51)
// #918 (RULED: MSS-4 rider): the EXTENDED map form — per-entry key TYPE
// (typed keys survive the lane; L47) and declaration kind ({k: ::T},
// value ABSENT). Emitted only when an entry needs it; plain maps stay
// 0x50 byte-identical. Valid only in a version-2 envelope.
const tag_map_ext      = u8(0x52)
const tag_table        = u8(0x60)
const tag_table_empty  = u8(0x61)
const tag_table_dict   = u8(0x62)

// §3.10.3 column-ONLY type codes (stream 17 W3, L89 — the lattice
// rise). Codes shared with the scalar tag space (ints/floats/strings/
// temporals/decimal/bigint) reuse the tag_* constants above.
const col_all_null = u8(0x00)
const col_bool     = u8(0x01) // bit-packed §3.10.4
const col_uint8    = u8(0x14)
const col_uint16   = u8(0x15)
const col_uint32   = u8(0x16)
const col_uint64   = u8(0x17)
const col_float32  = u8(0x21)
const col_float16  = u8(0x22)
const col_atom     = u8(0x70) // CXDM Item kind lane (§3.10a)
const col_nullable = u8(0x80) // wrapper §3.10.5
const col_mixed    = u8(0x81) // per-row tagged §3.10.6
const col_declared_name = u8(0x82) // col-spec declared-type-name annotation (§3.10.1; #807(c), arc-2)

// CXCol header constants. The 5-byte magic is "CXCol"; documents not
// matching this magic are rejected at header parse (no fallback).
// The header total is 12 bytes.
const cxcol_magic_len   = 5
const cxcol_magic       = [u8(0x43), 0x58, 0x43, 0x6F, 0x6C]   // "CXCol"
const cxcol_version     = u8(0x01)
// #918: version 2 = the 0x52 extended-map form is present somewhere in the
// payload. Producers emit the LOWEST version that carries the document
// (the ast_bin additive discipline); v1 readers reject v2 envelopes loud.
const cxcol_version_ext = u8(0x02)
const cxcol_flags_le    = u8(0x01)
const cxcol_default_depth = u32(64)

// ── Public entry points ──────────────────────────────────────────────────────

// emit_data_bin encodes a Document as CXCol v1 strict-canonical bytes.
// The output is the framing format `[u32 LE: payload_size][payload]`
// matching cx_to_ast_bin / cx_to_events_bin. The first 4 bytes give
// the payload size; payload is the CXCol document. Encoding REFUSES
// out-of-range integer cells loudly (#807, ruled Q4a — the wire never
// wraps a value and never silently widens a declared width).
pub fn emit_data_bin(doc Document) ![]u8 {
	mut payload := []u8{cap: 256}
	// #918 (RULED: MSS-4 rider): typed map keys and declaration-only
	// entries now CARRY (the 0x52 extended-map form, version 2) instead
	// of refusing; plain documents stay version 1 byte-identical.
	encode_header(mut payload, document_needs_databin_ext(doc))
	encode_document_root(doc, mut payload)!
	return frame_payload(payload)
}

// document_needs_databin_ext reports whether any MapNode in the document
// carries a typed (non-string) key or a declaration-only entry — the
// version-2 bump condition (#918, same additive discipline as ast_bin v10).
pub fn document_needs_databin_ext(d Document) bool {
	for n in d.prolog {
		if node_needs_databin_ext(n) {
			return true
		}
	}
	for n in d.elements {
		if node_needs_databin_ext(n) {
			return true
		}
	}
	return false
}

fn node_needs_databin_ext(n Node) bool {
	match n {
		MapNode {
			for entry in n.entries {
				if entry.key_type != .string_type || entry.decl_kind != '' {
					return true
				}
				if node_needs_databin_ext(entry.value) {
					return true
				}
			}
		}
		Element {
			if td := n.table_opt() {
				for row in td.rows {
					for cell in row {
						if cell is MapNode {
							if node_needs_databin_ext(Node(cell)) {
								return true
							}
						}
					}
				}
			}
			for it in n.items {
				if node_needs_databin_ext(it) {
					return true
				}
			}
		}
		CXDirectiveNode {
			for it in n.items {
				if node_needs_databin_ext(it) {
					return true
				}
			}
		}
		EvalDirectiveNode {
			for it in n.items {
				if node_needs_databin_ext(it) {
					return true
				}
			}
		}
		SequenceNode {
			for it in n.items {
				if node_needs_databin_ext(it) {
					return true
				}
			}
		}
		ArrayNode {
			for it in n.items {
				if node_needs_databin_ext(it) {
					return true
				}
			}
		}
		IteratorNode {
			for it in n.memo {
				if node_needs_databin_ext(it) {
					return true
				}
			}
		}
		else {}
	}
	return false
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

fn encode_header(mut buf []u8, needs_ext bool) {
	buf << cxcol_magic
	// #918: lowest version that carries the document — v2 only when the
	// 0x52 extended-map form is present somewhere in the payload.
	buf << if needs_ext { cxcol_version_ext } else { cxcol_version }
	buf << cxcol_flags_le
	encode_u32_le(mut buf, cxcol_default_depth)
	buf << u8(0)  // reserved (1 byte — magic grew from 4→5)
}

// ── Document → semantic-data projection ──────────────────────────────────────

fn encode_document_root(doc Document, mut buf []u8) ! {
	// Value-model document — a single CXDM value at top level (a Map / Array /
	// Sequence / Scalar, not a named Element), as produced by the lossless
	// JSON / value-codec read. Encode the value directly so it round-trips
	// (the keyed-collection path below only sees named Elements).
	if doc.elements.len == 1 {
		only := doc.elements[0]
		if only !is Element {
			encode_dataval(node_to_dataval(only), mut buf)!
			return
		}
	}
	roots := doc.elements.filter(it is Element)
	if roots.len == 0 {
		buf << tag_null
		return
	}
	encode_keyed_collection(roots, mut buf)!
}

fn encode_keyed_collection(roots []Node, mut buf []u8) ! {
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
		encode_dataval(vals[i], mut buf)!
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
	| DataDecimal
	| DataBigint
	| DataDate
	| DataDateTime
	| DataBytes
	| []DataVal
	| DataPairs
	| DataTable

pub struct DataNull {}

// I1 stream 11 (row 16): decimal/bigint ride the wire as their base-10
// images under their OWN tags (0x28 / 0x18) — the kind survives the
// round-trip (it erased to string before).
pub struct DataDecimal {
pub:
	image string
}

pub struct DataBigint {
pub:
	image string
}

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
// #918: key_types / decl_kinds are PARALLEL to keys when non-empty —
// key_types[i] names a non-string key's scalar kind ('' = string), and a
// non-empty decl_kinds[i] marks a DECLARATION-ONLY entry `{k: ::T}` whose
// value slot holds an inert null (the entry's value is ABSENT, never
// null — RULED: MSS-4 #917). Empty arrays = the legacy all-string form.
pub struct DataPairs {
pub mut:
	keys       []string
	vals       []DataVal
	key_types  []string
	decl_kinds []string
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
			return scalar_node_to_dataval(s)
		}
		mut arr := []DataVal{cap: content.len}
		for n in content {
			s := n as ScalarNode
			arr << scalar_node_to_dataval(s)
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
		vals << attr_to_dataval(attr)
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
					_ = dataval_push_keyed(mut keys, mut vals, '_', scalar_node_to_dataval(n))
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

// scalar_node_to_dataval is the KIND-AWARE projection (I1 row 16, L46):
// decimal/bigint scalars keep their kind on the wire via the 0x28/0x18
// tags — scalar_value_to_dataval alone erased them to string.
fn scalar_node_to_dataval(s ScalarNode) DataVal {
	v := s.value
	if v is string {
		if s.data_type == .decimal_type {
			return DataVal(DataDecimal{ image: v })
		}
		if s.data_type == .bigint_type {
			return DataVal(DataBigint{ image: v })
		}
		// #830 (RULED: 830-1a): the TEMPORAL kinds are first-class wire
		// tags too — 0x31 date, 0x32 datetime (data-bin.md §3.6/§3.6.1).
		// Falling through to scalar_value_to_dataval erased them to the
		// string tag 0x30, so V's own round trip returned a quoted STRING
		// (`[when '2026-08-16T12:34:56Z']`) and another engine writing the
		// spec form disagreed with V on the tag for the same value. Same
		// impl-rises-to-spec shape as the decimal/bigint arms above.
		if s.data_type == .date_type {
			return DataVal(parse_date_image(v))
		}
		if s.data_type == .datetime_type {
			return DataVal(DataDateTime{ source: v })
		}
	}
	return scalar_value_to_dataval(s.value)
}

// attr_to_dataval: the attribute twin of scalar_node_to_dataval.
fn attr_to_dataval(a Attribute) DataVal {
	v := a.value
	if v is string {
		if dt := a.data_type() {
			if dt == 'decimal' {
				return DataVal(DataDecimal{ image: v })
			}
			if dt == 'bigint' {
				return DataVal(DataBigint{ image: v })
			}
			// #830 (RULED: 830-1a): the temporal kinds ride their own tags
			// here too — an attribute is the same wire question as a body
			// scalar, and the two must not disagree.
			if dt == 'date' {
				return DataVal(parse_date_image(v))
			}
			if dt == 'datetime' {
				return DataVal(DataDateTime{ source: v })
			}
		}
	}
	return scalar_value_to_dataval(a.value)
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
		// I1 row 16: the M23 window — decimal/bigint COLUMN cells ride their
		// images until I5's column lattice (advisory fixtures, by design).
		DataDecimal  { TableCellValue(v.image) }
		DataBigint   { TableCellValue(v.image) }
		DataDate     { TableCellValue(scalar_value_str(scalar_value_from_date(v))) }
		DataDateTime { TableCellValue(v.source) }
		DataBytes    { TableCellValue(v.value.bytestr()) }
		[]DataVal    { TableCellValue(array_dataval_to_node(v)) }
		DataPairs    { TableCellValue(map_dataval_to_node(v)) }
		DataTable    { return error('table cell cannot itself be a DataTable (nested tables not supported)') }
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
	mut ktypes := []string{cap: n.entries.len}
	mut decls := []string{cap: n.entries.len}
	for entry in n.entries {
		// Map keys are atomic; canonical-string
		// form for the wire. #918: a non-string key records its kind and
		// a declaration-only entry records its declared kind (value slot
		// holds an inert null — the value is ABSENT, RULED: MSS-4).
		keys << scalar_value_str(entry.key_value)
		ktypes << if entry.key_type == .string_type { '' } else { scalar_type_name(entry.key_type) }
		decls << entry.decl_kind
		if entry.decl_kind != '' {
			vals << DataVal(DataNull{})
			continue
		}
		vals << node_to_dataval(entry.value)
	}
	return DataVal(DataPairs{ keys: keys, vals: vals, key_types: ktypes, decl_kinds: decls })
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
		// #918: the extended form restores the key's kind and a
		// declaration-only entry (value ABSENT — the wire null is the
		// inert placeholder, never the value; RULED: MSS-4 #917).
		mut kt := ScalarType.string_type
		mut kv := ScalarValue(k)
		if i < v.key_types.len && v.key_types[i] != '' {
			sn := coerce_scalar(v.key_types[i], k)
			kt = sn.data_type
			kv = sn.value
		}
		dk := if i < v.decl_kinds.len { v.decl_kinds[i] } else { '' }
		if dk != '' {
			entries << MapEntry{
				key_type:  kt
				key_value: kv
				value:     Node(ScalarNode{
					data_type: .null_type
					value:     ScalarValue(NullValue{})
				})
				decl_kind: dk
			}
			continue
		}
		entries << MapEntry{
			key_type:  kt
			key_value: kv
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
		DataDecimal  { Node(ScalarNode{ data_type: ScalarType.decimal_type,  value: ScalarValue(v.image) }) }
		DataBigint   { Node(ScalarNode{ data_type: ScalarType.bigint_type,   value: ScalarValue(v.image) }) }
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

fn encode_dataval(v DataVal, mut buf []u8) ! {
	match v {
		DataNull     { buf << tag_null }
		bool         { buf << if v { tag_true } else { tag_false } }
		i64          { encode_int_canonical(v, mut buf) }
		f64          { encode_float64(v, mut buf) }
		string       { encode_string_value(v, mut buf) }
		DataDecimal  {
			buf << tag_decimal
			encode_string_payload(v.image, mut buf)
		}
		DataBigint   {
			buf << tag_bigint
			encode_string_payload(v.image, mut buf)
		}
		DataDate     { encode_date(v, mut buf) }
		DataDateTime { encode_datetime(v, mut buf) }
		DataBytes    { encode_bytes_value(v.value, mut buf) }
		[]DataVal    { encode_array(v, mut buf)! }
		DataPairs    { encode_pairs(v, mut buf)! }
		DataTable    { encode_table(v, mut buf)! }
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
	// NaN / Inf rejection (canonical scalar policy, spec/03-approved/core/canonical.md).
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

// encode_string_payload writes a length-prefixed byte payload WITHOUT a
// leading tag (the caller has already written its kind tag — 0x28/0x18).
fn encode_string_payload(s string, mut buf []u8) {
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
	// Phase 7.74c-datetime-foundations: parse ISO-8601 source to the
	// 12-byte wire form per spec/core/data-bin.md §3.6.1. On parse
	// failure, emit zeros — encoder is best-effort here; the chunked
	// strict-cell encoder (data_bin_chunked.v) returns errors up to
	// the caller via its `!` signature.
	ns, off := parse_iso_datetime_canonical(d.source) or { i64(0), i16(0) }
	buf << tag_datetime
	encode_u64_le(mut buf, u64(ns))
	// Transport carries the parsed offset (#807(d), arc-2): unix_nanos
	// stays UTC-normalized; strict canonicalization (the hash basis)
	// runs through text and keeps normalizing offsets to 0.
	ou := u16(u32(off))
	buf << u8(ou & 0xFF)
	buf << u8((ou >> 8) & 0xFF)
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

fn encode_array(arr []DataVal, mut buf []u8) ! {
	if arr.len == 0 {
		buf << tag_array_empty
		return
	}
	buf << tag_array
	encode_uvarint(mut buf, u64(arr.len))
	for v in arr {
		encode_dataval(v, mut buf)!
	}
}

fn encode_pairs(p DataPairs, mut buf []u8) ! {
	if p.keys.len == 0 {
		buf << tag_map_empty
		return
	}
	// #918: the 0x52 extended form carries per-entry key type + decl kind;
	// a map needing neither stays the byte-identical legacy 0x50 form.
	mut has_ext := false
	for i, _ in p.keys {
		if (i < p.key_types.len && p.key_types[i] != '')
			|| (i < p.decl_kinds.len && p.decl_kinds[i] != '') {
			has_ext = true
			break
		}
	}
	if has_ext {
		buf << tag_map_ext
		encode_uvarint(mut buf, u64(p.keys.len))
		for i, k in p.keys {
			encode_string_value(k, mut buf)
			kt := if i < p.key_types.len { p.key_types[i] } else { '' }
			dk := if i < p.decl_kinds.len { p.decl_kinds[i] } else { '' }
			encode_string_value(kt, mut buf)
			encode_string_value(dk, mut buf)
			encode_dataval(p.vals[i], mut buf)!
		}
		return
	}
	buf << tag_map
	encode_uvarint(mut buf, u64(p.keys.len))
	for i, k in p.keys {
		encode_string_value(k, mut buf)
		encode_dataval(p.vals[i], mut buf)!
	}
}

fn encode_table(t DataTable, mut buf []u8) ! {
	if t.cols.len == 0 {
		buf << tag_table_empty
		return
	}
	// The risen §3.10.3 form (stream 17 W3, L89): TYPED per-column
	// payloads, no per-cell tags (the columnar-omit-tag optimization
	// is now THE encoding); columns with any null wrap in 0x80
	// (bitmap + packed non-nulls); collection-bearing or
	// shape-divergent columns take the 0x81 mixed escape (per-row
	// tagged — the honest totality escape, §3.10.6).
	mut codes := []u8{cap: t.cols.len}
	mut bases := []u8{cap: t.cols.len}
	mut dict_flags := []bool{cap: t.cols.len}
	mut any_dict := false
	for col_idx, col in t.cols {
		code, base := column_effective_code(col, t.rows, col_idx)
		codes << code
		bases << base
		d := column_wants_dict(code, col_idx, t.rows)
		dict_flags << d
		if d {
			any_dict = true
		}
	}
	// The 0x62 dictionary form engages when ANY column dict-encodes
	// (§3.10.2 — atoms BY CONSTRUCTION, strings by the canonical
	// byte-savings rule, evaluated per column independently); plain
	// tables stay 0x60.
	buf << if any_dict { tag_table_dict } else { tag_table }
	encode_uvarint(mut buf, u64(t.cols.len))
	for col_idx, col in t.cols {
		encode_string_value(col.name, mut buf)
		encode_col_spec_type(col.type_name, codes[col_idx], bases[col_idx], mut buf)
	}
	encode_uvarint(mut buf, u64(t.rows.len))
	for col_idx, col in t.cols {
		if any_dict {
			if dict_flags[col_idx] {
				buf << u8(0x01)
				encode_dict_column(col_idx, t.rows, mut buf)
			} else {
				buf << u8(0x00)
				encode_column_payload(codes[col_idx], bases[col_idx], col_idx, t.rows, mut buf) or {
					return error('cxcol: column `${col.name}`: ${err.msg()}')
				}
			}
		} else {
			encode_column_payload(codes[col_idx], bases[col_idx], col_idx, t.rows, mut buf) or {
				return error('cxcol: column `${col.name}`: ${err.msg()}')
			}
		}
	}
}

// column_wants_dict — §3.10.2: atom columns dictionary-encode BY
// CONSTRUCTION (L89); string columns dict-encode only when the
// dictionary actually saves bytes (distinct×avg_size + rows×index
// < rows×avg_size). Null-bearing and non-string columns stay plain
// (0x80 composes with plain payloads only in this wave).
fn column_wants_dict(code u8, col_idx int, rows [][]DataVal) bool {
	if code != col_atom && code != tag_string {
		return false
	}
	mut distinct := map[string]bool{}
	mut total_size := u64(0)
	for row in rows {
		if col_idx >= row.len {
			return false
		}
		cell := row[col_idx]
		if cell is string {
			distinct[cell] = true
			total_size += u64(cell.len) + 1
		} else {
			return false
		}
	}
	if code == col_atom {
		return true
	}
	if rows.len == 0 || distinct.len == 0 {
		return false
	}
	avg := total_size / u64(rows.len)
	dict_cost := u64(distinct.len) * (avg + 1) + u64(rows.len) // ~1B varint index
	plain_cost := u64(rows.len) * avg
	return dict_cost < plain_cost
}

// encode_dict_column — §3.10.2 dictionary payload: distinct values in
// insertion order (FULL tagged values), then one varint index per row.
fn encode_dict_column(col_idx int, rows [][]DataVal, mut buf []u8) {
	mut order := []string{}
	mut index_of := map[string]int{}
	for row in rows {
		cell := row[col_idx]
		if cell is string {
			if cell !in index_of {
				index_of[cell] = order.len
				order << cell
			}
		}
	}
	encode_uvarint(mut buf, u64(order.len))
	for v in order {
		encode_string_value(v, mut buf)
	}
	for row in rows {
		cell := row[col_idx]
		if cell is string {
			encode_uvarint(mut buf, u64(index_of[cell]))
		} else {
			encode_uvarint(mut buf, 0)
		}
	}
}

// column_effective_code resolves one column's wire code from its
// declared type + its actual cells: an undeclared column probes cell
// shapes (uniform scalar → that code; anything else → mixed); a
// declared column with collection cells falls to mixed; any null in a
// typed column wraps 0x80. Returns (effective, base) — base is the
// declared/probed scalar code the 0x80 wrapper carries as its INNER
// (#807/AF-2(b): the inner is the DECLARED width, never re-derived
// from cell values — a nullable u16 column never widens to int64).
fn column_effective_code(col TableColumn, rows [][]DataVal, col_idx int) (u8, u8) {
	mut base := column_type_code(col.type_name)
	if col.type_name == '' {
		base = column_probe_code(rows, col_idx)
	}
	if base == col_mixed || base == col_all_null {
		return base, base
	}
	mut has_null := false
	for row in rows {
		if col_idx >= row.len {
			has_null = true
			continue
		}
		cell := row[col_idx]
		if cell is DataNull {
			has_null = true
		} else if cell is []DataVal || cell is DataPairs || cell is DataTable {
			return col_mixed, col_mixed
		}
	}
	if has_null {
		return col_nullable, base
	}
	return base, base
}

// column_probe_code classifies an UNDECLARED column by its cells.
fn column_probe_code(rows [][]DataVal, col_idx int) u8 {
	mut saw_int := false
	mut saw_f64 := false
	mut saw_bool := false
	mut saw_str := false
	mut saw_other := false
	mut saw_value := false
	for row in rows {
		if col_idx >= row.len {
			continue
		}
		cell := row[col_idx]
		match cell {
			DataNull { continue }
			i64      { saw_int = true }
			f64      { saw_f64 = true }
			bool     { saw_bool = true }
			string   { saw_str = true }
			else     { saw_other = true }
		}
		saw_value = true
	}
	if !saw_value {
		return col_all_null
	}
	if saw_other {
		return col_mixed
	}
	mut kinds := 0
	if saw_int { kinds++ }
	if saw_f64 { kinds++ }
	if saw_bool { kinds++ }
	if saw_str { kinds++ }
	if kinds > 1 {
		return col_mixed
	}
	if saw_int { return tag_int64 }
	if saw_f64 { return tag_float64 }
	if saw_bool { return col_bool }
	return tag_string
}

// encode_column_payload writes one column per its wire code. The
// 0x80 wrapper writes [inner_code][null bitmap][packed non-nulls];
// mixed writes per-row tagged values; all-null writes nothing.
// `base` is the column's declared/probed scalar code — the 0x80
// wrapper's inner (#807/AF-2(b): declared width kept, all-null
// columns keep their declared type).
fn encode_column_payload(code u8, base u8, col_idx int, rows [][]DataVal, mut buf []u8) ! {
	match code {
		col_all_null {}
		col_mixed {
			for row in rows {
				if col_idx < row.len {
					encode_dataval(row[col_idx], mut buf)!
				} else {
					buf << tag_null
				}
			}
		}
		col_nullable {
			inner := base
			buf << inner
			// null bitmap: bit set = null (§3.10.5), LSB-first.
			mut bitmap := []u8{len: (rows.len + 7) / 8}
			for ri, row in rows {
				is_null := col_idx >= row.len || row[col_idx] is DataNull
				if is_null {
					bitmap[ri / 8] |= u8(1) << (ri % 8)
				}
			}
			buf << bitmap
			if inner == col_bool {
				// packed non-null bools
				mut vals := []bool{}
				for row in rows {
					if col_idx < row.len {
						c := row[col_idx]
						if c is bool {
							vals << c
						}
					}
				}
				encode_bool_bits(vals, mut buf)
				return
			}
			for row in rows {
				if col_idx >= row.len {
					continue
				}
				cell := row[col_idx]
				if cell is DataNull {
					continue
				}
				encode_typed_cell(cell, inner, mut buf)!
			}
		}
		col_bool {
			mut vals := []bool{cap: rows.len}
			for row in rows {
				mut b := false
				if col_idx < row.len {
					c := row[col_idx]
					if c is bool {
						b = c
					} else if c is i64 {
						b = c != 0
					}
				}
				vals << b
			}
			encode_bool_bits(vals, mut buf)
		}
		else {
			for row in rows {
				if col_idx < row.len {
					encode_typed_cell(row[col_idx], code, mut buf)!
				} else {
					encode_typed_cell(DataVal(string('')), code, mut buf)!
				}
			}
		}
	}
}

// (column_inner_code — the value-derived 0x80 inner picker — is
// REMOVED: it widened declared narrow widths to int64 and fell to
// string for all-null columns (AF-2 class b). The inner is the
// column's declared/probed BASE code, threaded from encode_table.)

// encode_bool_bits bit-packs bools per §3.10.4 (LSB-first).
fn encode_bool_bits(vals []bool, mut buf []u8) {
	mut bytes := []u8{len: (vals.len + 7) / 8}
	for i, b in vals {
		if b {
			bytes[i / 8] |= u8(1) << (i % 8)
		}
	}
	buf << bytes
}

// encode_typed_cell writes ONE cell's §3.10.3 payload (no tag).
// Cells arrive as the table-cell variants (i64/f64/bool/string);
// typed columns (decimal/bigint/date/datetime/bytes/atom) carry
// string images. Datetime parse failures emit zeros (the scalar
// encoder's documented best-effort — the strict chunked lane errors
// instead). Integer cells outside the declared width REFUSE loudly
// (#807, ruled Q4a — never wrap, never silently widen).
fn encode_typed_cell(v DataVal, code u8, mut buf []u8) ! {
	match code {
		tag_int8 {
			x := dataval_i64(v)
			check_int_cell_range(x, code)!
			buf << u8(x)
		}
		tag_int16 {
			n := dataval_i64(v)
			check_int_cell_range(n, code)!
			x := u16(u32(n))
			buf << u8(x & 0xFF)
			buf << u8((x >> 8) & 0xFF)
		}
		tag_int32 {
			x := dataval_i64(v)
			check_int_cell_range(x, code)!
			encode_u32_le(mut buf, u32(x))
		}
		tag_int64 {
			encode_u64_le(mut buf, u64(dataval_i64(v)))
		}
		col_uint8 {
			x := dataval_i64(v)
			check_int_cell_range(x, code)!
			buf << u8(x)
		}
		col_uint16 {
			n := dataval_i64(v)
			check_int_cell_range(n, code)!
			x := u16(n)
			buf << u8(x & 0xFF)
			buf << u8((x >> 8) & 0xFF)
		}
		col_uint32 {
			x := dataval_i64(v)
			check_int_cell_range(x, code)!
			encode_u32_le(mut buf, u32(x))
		}
		col_uint64 {
			x := dataval_i64(v)
			check_int_cell_range(x, code)!
			encode_u64_le(mut buf, u64(x))
		}
		tag_float64 {
			encode_u64_le(mut buf, math.f64_bits(dataval_f64(v)))
		}
		col_float32 {
			f := dataval_f64(v)
			check_float_cell_exact(f, code)!
			encode_u32_le(mut buf, math.f32_bits(f32(f)))
		}
		col_float16 {
			f := dataval_f64(v)
			check_float_cell_exact(f, code)!
			x := f64_to_f16_bits(f)
			buf << u8(x & 0xFF)
			buf << u8((x >> 8) & 0xFF)
		}
		tag_bigint, tag_decimal, tag_string, col_atom {
			s := dataval_str(v)
			encode_uvarint(mut buf, u64(s.len))
			buf << s.bytes()
		}
		tag_bytes {
			s := dataval_str(v)
			encode_uvarint(mut buf, u64(s.len))
			buf << s.bytes()
		}
		tag_date {
			d := parse_date_image(dataval_str(v))
			yu := u16(u32(d.year))
			buf << u8(yu & 0xFF)
			buf << u8((yu >> 8) & 0xFF)
			buf << d.month
			buf << d.day
		}
		tag_datetime {
			// Transport carries the parsed offset in the §3.6.1 field
			// (#807(d), arc-2): unix_nanos stays UTC-normalized; the
			// offset restores the local RENDER on decode. Strict
			// canonicalization (the hash basis) runs through text and
			// keeps normalizing.
			ns, off := parse_iso_datetime_canonical(dataval_str(v)) or { i64(0), i16(0) }
			encode_u64_le(mut buf, u64(ns))
			ou := u16(u32(off))
			buf << u8(ou & 0xFF)
			buf << u8((ou >> 8) & 0xFF)
			buf << u8(0)
			buf << u8(0)
		}
		else {
			// Defensive: unknown code — length-prefixed string image.
			s := dataval_str(v)
			encode_uvarint(mut buf, u64(s.len))
			buf << s.bytes()
		}
	}
}

// check_int_cell_range refuses out-of-range integer cells at encode
// (#807, ruled Q4a): the wire NEVER wraps a value into a narrower
// width and NEVER silently widens a declared width — an
// unrepresentable cell is a loud encode error on every lane (plain
// 0x60, chunked 0x63, and the Arrow export that reads them).
fn check_int_cell_range(x i64, code u8) ! {
	ok := match code {
		tag_int8   { x >= -128 && x <= 127 }
		tag_int16  { x >= -32768 && x <= 32767 }
		tag_int32  { x >= -2147483648 && x <= 2147483647 }
		col_uint8  { x >= 0 && x <= 255 }
		col_uint16 { x >= 0 && x <= 65535 }
		col_uint32 { x >= 0 && x <= 4294967295 }
		col_uint64 { x >= 0 }
		else       { true }
	}
	if !ok {
		return error('cell value ${x} out of range for ${int_code_width_name(code)} column — out-of-range cells refuse at encode (never wrap, never widen)')
	}
}

fn int_code_width_name(code u8) string {
	return match code {
		tag_int8   { 'i8' }
		tag_int16  { 'i16' }
		tag_int32  { 'i32' }
		col_uint8  { 'u8' }
		col_uint16 { 'u16' }
		col_uint32 { 'u32' }
		col_uint64 { 'u64' }
		else       { '0x${code:02x}' }
	}
}

fn dataval_i64(v DataVal) i64 {
	return match v {
		i64    { v }
		f64    { i64(v) }
		bool   { if v { i64(1) } else { i64(0) } }
		string { v.i64() }
		else   { i64(0) }
	}
}

fn dataval_f64(v DataVal) f64 {
	return match v {
		f64    { v }
		i64    { f64(v) }
		string { v.f64() }
		else   { f64(0) }
	}
}

fn dataval_str(v DataVal) string {
	return match v {
		string      { v }
		i64         { v.str() }
		f64         { v.str() }
		bool        { if v { 'true' } else { 'false' } }
		DataDecimal { v.image }
		DataBigint  { v.image }
		else        { '' }
	}
}

// parse_date_image parses 'YYYY-MM-DD'; zeros on failure (best-effort
// parity with the scalar datetime encoder).
fn parse_date_image(s string) DataDate {
	parts := s.split('-')
	if parts.len == 3 {
		return DataDate{
			year:  i16(parts[0].int())
			month: u8(parts[1].int())
			day:   u8(parts[2].int())
		}
	}
	return DataDate{}
}

// f64_to_f16_bits converts to IEEE-754 binary16 (round-to-nearest-even
// via the f32 intermediate; overflow → ±inf; subnormals flushed
// through the standard shift).
fn f64_to_f16_bits(v f64) u16 {
	bits := math.f32_bits(f32(v))
	sign := u16((bits >> 16) & 0x8000)
	mut exp := int((bits >> 23) & 0xFF) - 127 + 15
	mant := bits & 0x7FFFFF
	if exp >= 31 {
		return sign | 0x7C00 // inf
	}
	if exp <= 0 {
		if exp < -10 {
			return sign // zero
		}
		m := (mant | 0x800000) >> u32(1 - exp)
		return sign | u16((m + 0x1000) >> 13)
	}
	return sign | u16(exp << 10) | u16((mant + 0x1000) >> 13)
}

// f16_bits_to_f64 is the decoder twin.
fn f16_bits_to_f64(h u16) f64 {
	sign := u32(h & 0x8000) << 16
	exp := int((h >> 10) & 0x1F)
	mant := u32(h & 0x3FF)
	mut bits := u32(0)
	if exp == 0 {
		if mant == 0 {
			bits = sign
		} else {
			// subnormal → normalize
			mut e := -1
			mut m := mant
			for (m & 0x400) == 0 {
				m <<= 1
				e--
			}
			m &= 0x3FF
			bits = sign | u32(127 - 15 + e + 1) << 23 | (m << 13)
		}
	} else if exp == 31 {
		bits = sign | 0x7F800000 | (mant << 13)
	} else {
		bits = sign | u32(exp - 15 + 127) << 23 | (mant << 13)
	}
	return f64(math.f32_from_bits(bits))
}

// column_type_code — the RISEN §3.10.3 lattice (stream 17 W3, L89):
// unsigned and reduced-precision float widths KEPT
// (narrowest-within-kind — a kind is never erased by narrowing);
// decimal/bigint columns carry their own codes; bool is the
// bit-packed column code; atom takes the §3.10a item lane; an
// UNKNOWN declared type is the honestly-reported mixed escape,
// never a silent string.
fn column_type_code(type_name string) u8 {
	return match type_name {
		'int', 'i64'         { tag_int64 }
		'i8'                 { tag_int8 }
		'i16'                { tag_int16 }
		'i32'                { tag_int32 }
		'u8'                 { col_uint8 }
		'u16'                { col_uint16 }
		'u32'                { col_uint32 }
		'u64'                { col_uint64 }
		'bigint'             { tag_bigint }
		'float', 'f64'       { tag_float64 }
		'f32'                { col_float32 }
		'f16'                { col_float16 }
		'decimal'            { tag_decimal }
		'bool'               { col_bool }
		'string', '', 's'    { tag_string }
		'date', 'd'          { tag_date }
		'datetime', 'dt'     { tag_datetime }
		'bytes'              { tag_bytes }
		'atom'               { col_atom }
		else                 { col_mixed }
	}
}

// encode_col_spec_type writes one col-spec type entry (§3.10.1): the
// 0x82 declared-name annotation rides IFF the declared spelling
// differs from the code's default render (#807(c), arc-2 —
// minimal-annotation determinism: redundant annotations never ride,
// so alias-free col-specs are byte-identical to their pre-annotation
// form), then the type code. For the 0x80 wrapper the default render
// is the INNER code's (the reader refines from it).
fn encode_col_spec_type(declared string, code u8, base u8, mut buf []u8) {
	default_name := if code == col_nullable {
		column_type_name_from_code(base)
	} else {
		column_type_name_from_code(code)
	}
	if declared != '' && declared != default_name {
		buf << col_declared_name
		encode_string_value(declared, mut buf)
	}
	buf << code
}

// check_float_cell_exact refuses a reduced-width float cell whose
// value does not round-trip exactly through the declared width
// (#807(e), ruled arc-3: never silently approximate — the
// shortest-round-trip renderer masks the approximation behind the
// original spelling and was rejected; refuse over widen, matching
// Q4a's "never silently widen").
fn check_float_cell_exact(v f64, code u8) ! {
	exact := match code {
		col_float16 { f16_bits_to_f64(f64_to_f16_bits(v)) == v }
		col_float32 { f64(f32(v)) == v }
		else        { true }
	}
	if !exact {
		width := if code == col_float16 { 'f16' } else { 'f32' }
		return error('cell value ${v} not exactly representable as ${width} — non-representable cells refuse at encode (spell the representable value or widen the column; never silently approximated)')
	}
}

// (encode_table_cell — the pre-W3a per-cell-tag writer — is REMOVED:
// the columnar-omit-tag optimization IS the encoding since stream 17
// W3a and the fn had no callers left; it does not stay dead.)

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
// position and recursion depth; aborts on overflow
// (spec/03-approved/core/limits.md §2).
struct BinReader {
mut:
	buf       []u8
	pos       int
	depth     int
	max_depth int
	// #918: envelope version from the header — gates the 0x52
	// extended-map form (v2+).
	version   u8 = cxcol_version
	// Column projection (stream 17 W4, the §6 pushdown executor):
	// when non-empty, read_table_payload MATERIALIZES only the named
	// columns' cells — every other column's payload is cursor-skipped
	// (skip_typed_cells), never boxed. Cells of skipped columns come
	// back as DataNull placeholders so row/col indexing is stable.
	col_projection []string
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
	// #918: v1 = legacy; v2 adds the 0x52 extended-map form. Higher
	// versions reject (forward compatibility is by version, never by
	// silent tag skips).
	if version != cxcol_version && version != cxcol_version_ext {
		return error('cxcol: unsupported version ${version} (this build supports ${cxcol_version} and ${cxcol_version_ext})')
	}
	r.version = version
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
		// I1 row 16 (L46): the semantic kinds decode as themselves.
		tag_decimal      { DataVal(DataDecimal{ image: r.read_string_payload()! }) }
		tag_bigint       { DataVal(DataBigint{ image: r.read_string_payload()! }) }
		tag_string       { DataVal(r.read_string_payload()!) }
		tag_date         { DataVal(r.read_date_payload()!) }
		tag_datetime     { DataVal(r.read_datetime_payload()!) }
		tag_bytes        { DataVal(DataBytes{ value: r.read_bytes_payload()! }) }
		tag_array        { r.read_array_payload()! }
		tag_array_empty  { DataVal([]DataVal{}) }
		tag_map          { r.read_map_payload()! }
		tag_map_ext      { r.read_map_ext_payload()! }
		tag_map_empty    { DataVal(DataPairs{ keys: []string{}, vals: []DataVal{} }) }
		tag_table        { r.read_table_payload(false)! }
		tag_table_dict   { r.read_table_payload(true)! }
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

// read_col_spec_type consumes one col-spec type entry (§3.10.1):
// either a bare type code, or the 0x82 declared-name annotation
// (`0x82 <string(declared-name)> <col-type>`, #807(c)) followed by
// the code. Returns (declared_name, code) — declared_name is ''
// when no annotation rides.
fn (mut r BinReader) read_col_spec_type() !(string, u8) {
	mut col_type_byte := r.take_u8()!
	if col_type_byte != col_declared_name {
		return '', col_type_byte
	}
	name_tag := r.take_u8()!
	if name_tag != tag_string {
		return error('cxcol: declared-name annotation must carry a string (tag 0x30); got 0x${name_tag:02x}')
	}
	declared := r.read_string_payload()!
	if declared == '' {
		return error('cxcol: declared-name annotation must be non-empty')
	}
	col_type_byte = r.take_u8()!
	if col_type_byte == col_declared_name {
		return error('cxcol: duplicate declared-name annotation in col-spec')
	}
	return declared, col_type_byte
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

// read_map_ext_payload decodes the #918 0x52 extended-map form:
// per-entry (str:key, str:key_type ''=string, str:decl_kind ''=none,
// DataVal:value). Valid only in a version-2 envelope.
fn (mut r BinReader) read_map_ext_payload() !DataVal {
	if r.version < cxcol_version_ext {
		return error('cxcol: extended-map tag 0x52 in a version-${r.version} envelope (needs version 2)')
	}
	count := r.read_uvarint()!
	if count == 0 {
		return error('cxcol: map tag 0x52 with count=0; use 0x51 for empty maps')
	}
	mut keys := []string{cap: int(count)}
	mut vals := []DataVal{cap: int(count)}
	mut ktypes := []string{cap: int(count)}
	mut decls := []string{cap: int(count)}
	for _ in 0 .. int(count) {
		key_tag := r.take_u8()!
		if key_tag != tag_string {
			return error('cxcol: map key must be string (tag 0x30); got 0x${key_tag:02x}')
		}
		k := r.read_string_payload()!
		kt_tag := r.take_u8()!
		if kt_tag != tag_string {
			return error('cxcol: 0x52 key-type slot must be string (tag 0x30); got 0x${kt_tag:02x}')
		}
		kt := r.read_string_payload()!
		dk_tag := r.take_u8()!
		if dk_tag != tag_string {
			return error('cxcol: 0x52 decl-kind slot must be string (tag 0x30); got 0x${dk_tag:02x}')
		}
		dk := r.read_string_payload()!
		v := r.read_dataval()!
		keys << k
		ktypes << kt
		decls << dk
		vals << v
	}
	return DataVal(DataPairs{ keys: keys, vals: vals, key_types: ktypes, decl_kinds: decls })
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

fn (mut r BinReader) read_table_payload(dict_form bool) !DataVal {
	col_count := r.read_uvarint()!
	if col_count == 0 {
		return error('cxcol: table tag 0x60 with col_count=0; use 0x61 for empty tables')
	}
	mut cols := []TableColumn{cap: int(col_count)}
	mut col_codes := []u8{cap: int(col_count)}
	mut col_declared := []bool{cap: int(col_count)}
	for _ in 0 .. int(col_count) {
		key_tag := r.take_u8()!
		if key_tag != tag_string {
			return error('cxcol: table column name must be string (tag 0x30); got 0x${key_tag:02x}')
		}
		name := r.read_string_payload()!
		declared, col_type_byte := r.read_col_spec_type()!
		col_codes << col_type_byte
		col_declared << declared != ''
		type_name := if declared != '' { declared } else { column_type_name_from_code(col_type_byte) }
		cols << TableColumn{ name: name, type_name: type_name }
	}
	row_count := r.read_uvarint()!
	mut rows := [][]DataVal{cap: int(row_count)}
	for _ in 0 .. int(row_count) {
		rows << []DataVal{cap: int(col_count)}
	}
	// The risen §3.10.3 typed payloads (stream 17 W3): per column,
	// dispatch on the col-spec code recorded above.
	for col_idx in 0 .. int(col_count) {
		code := col_codes[col_idx]
		// The §6 projection executor (stream 17 W4): unwanted columns
		// SKIP — cursor-accurate, zero boxing.
		if r.col_projection.len > 0 && cols[col_idx].name !in r.col_projection {
			if dict_form {
				flag := r.take_u8()!
				if flag == 0x01 {
					r.skip_dict_column(int(row_count))!
				} else {
					r.skip_column_payload(code, int(row_count))!
				}
			} else {
				r.skip_column_payload(code, int(row_count))!
			}
			for row_idx in 0 .. int(row_count) {
				rows[row_idx] << DataVal(DataNull{})
			}
			continue
		}
		mut cells := []DataVal{}
		mut effective := code
		if dict_form {
			flag := r.take_u8()!
			if flag == 0x01 {
				cells = r.read_dict_column(int(row_count))!
			} else if flag == 0x00 {
				cells, effective = r.read_column_payload(code, int(row_count))!
			} else {
				return error('cxcol: dictionary column flag must be 0x00/0x01; got 0x${flag:02x}')
			}
		} else {
			cells, effective = r.read_column_payload(code, int(row_count))!
		}
		// §3.10.5 type refinement: a 0x80 column's rendered type comes
		// from its INNER code (#807/AF-2(b) — the header byte alone
		// says only "nullable"). A declared-name annotation WINS over
		// the refinement (#807(c): the declared spelling is the truth
		// the inner code only approximates).
		if code == col_nullable && !col_declared[col_idx] {
			cols[col_idx].type_name = column_type_name_from_code(effective)
		}
		for row_idx in 0 .. int(row_count) {
			rows[row_idx] << cells[row_idx]
		}
		_ = col_idx
	}
	return DataVal(DataTable{ cols: cols, rows: rows })
}

// read_dict_column — §3.10.2: uvarint distinct count, tagged values in
// insertion order, one varint index per row.
fn (mut r BinReader) read_dict_column(row_count int) ![]DataVal {
	distinct := r.read_uvarint()!
	mut values := []DataVal{cap: int(distinct)}
	for _ in 0 .. int(distinct) {
		values << r.read_dataval()!
	}
	mut cells := []DataVal{cap: row_count}
	for _ in 0 .. row_count {
		idx := r.read_uvarint()!
		if idx >= u64(values.len) {
			return error('cxcol: dictionary index ${idx} out of range (${values.len} distinct)')
		}
		cells << values[int(idx)]
	}
	return cells
}

// read_column_payload decodes one column's §3.10.3 payload into
// row_count cells. Returns (cells, effective_code) — for the 0x80
// wrapper the effective code is the INNER code just read, so the
// caller can refine the rendered column type from it (#807/AF-2(b):
// n::int with nulls decodes as n::int, never bare n).
fn (mut r BinReader) read_column_payload(code u8, row_count int) !([]DataVal, u8) {
	mut cells := []DataVal{cap: row_count}
	match code {
		col_all_null {
			for _ in 0 .. row_count {
				cells << DataVal(DataNull{})
			}
		}
		col_mixed {
			for _ in 0 .. row_count {
				cells << r.read_dataval()!
			}
		}
		col_nullable {
			inner := r.take_u8()!
			bitmap := r.take((row_count + 7) / 8)!
			mut n_nonnull := 0
			for ri in 0 .. row_count {
				if (bitmap[ri / 8] >> (ri % 8)) & 1 == 0 {
					n_nonnull++
				}
			}
			nonnull := r.read_typed_cells(inner, n_nonnull)!
			mut vi := 0
			for ri in 0 .. row_count {
				if (bitmap[ri / 8] >> (ri % 8)) & 1 == 1 {
					cells << DataVal(DataNull{})
				} else {
					cells << nonnull[vi]
					vi++
				}
			}
			return cells, inner
		}
		else {
			cells = r.read_typed_cells(code, row_count)!
		}
	}
	return cells, code
}

// read_typed_cells decodes N cells of one §3.10.3 payload code.
fn (mut r BinReader) read_typed_cells(code u8, n int) ![]DataVal {
	mut cells := []DataVal{cap: n}
	match code {
		col_bool {
			bits := r.take((n + 7) / 8)!
			for i in 0 .. n {
				cells << DataVal(((bits[i / 8] >> (i % 8)) & 1) == 1)
			}
		}
		tag_int8 {
			for _ in 0 .. n {
				b := r.take_u8()!
				cells << DataVal(i64(i8(b)))
			}
		}
		tag_int16 {
			for _ in 0 .. n {
				b := r.take(2)!
				cells << DataVal(i64(i16(u16(b[0]) | (u16(b[1]) << 8))))
			}
		}
		tag_int32 {
			for _ in 0 .. n {
				b := r.take(4)!
				cells << DataVal(i64(int(u32(b[0]) | (u32(b[1]) << 8) | (u32(b[2]) << 16) | (u32(b[3]) << 24))))
			}
		}
		tag_int64, col_uint64 {
			for _ in 0 .. n {
				cells << DataVal(i64(r.read_u64_le()!))
			}
		}
		col_uint8 {
			for _ in 0 .. n {
				cells << DataVal(i64(r.take_u8()!))
			}
		}
		col_uint16 {
			for _ in 0 .. n {
				b := r.take(2)!
				cells << DataVal(i64(u16(b[0]) | (u16(b[1]) << 8)))
			}
		}
		col_uint32 {
			for _ in 0 .. n {
				b := r.take(4)!
				cells << DataVal(i64(u32(b[0]) | (u32(b[1]) << 8) | (u32(b[2]) << 16) | (u32(b[3]) << 24)))
			}
		}
		tag_float64 {
			for _ in 0 .. n {
				cells << DataVal(math.f64_from_bits(r.read_u64_le()!))
			}
		}
		col_float32 {
			for _ in 0 .. n {
				b := r.take(4)!
				bits := u32(b[0]) | (u32(b[1]) << 8) | (u32(b[2]) << 16) | (u32(b[3]) << 24)
				cells << DataVal(f64(math.f32_from_bits(bits)))
			}
		}
		col_float16 {
			for _ in 0 .. n {
				b := r.take(2)!
				cells << DataVal(f16_bits_to_f64(u16(b[0]) | (u16(b[1]) << 8)))
			}
		}
		tag_bigint {
			for _ in 0 .. n {
				cells << DataVal(DataBigint{ image: r.read_string_payload()! })
			}
		}
		tag_decimal {
			for _ in 0 .. n {
				cells << DataVal(DataDecimal{ image: r.read_string_payload()! })
			}
		}
		tag_string, col_atom, tag_bytes {
			for _ in 0 .. n {
				cells << DataVal(r.read_string_payload()!)
			}
		}
		tag_date {
			for _ in 0 .. n {
				b := r.take(4)!
				y := i16(u16(b[0]) | (u16(b[1]) << 8))
				cells << DataVal('${int(y):04d}-${int(b[2]):02d}-${int(b[3]):02d}')
			}
		}
		tag_datetime {
			for _ in 0 .. n {
				dt := r.read_datetime_payload()!
				cells << DataVal(dt.source)
			}
		}
		else {
			return error('cxcol: unknown column type code 0x${code:02x}')
		}
	}
	return cells
}

fn column_type_name_from_code(code u8) string {
	return match code {
		tag_int8     { 'i8' }
		tag_int16    { 'i16' }
		tag_int32    { 'i32' }
		tag_int64    { 'int' }
		col_uint8    { 'u8' }
		col_uint16   { 'u16' }
		col_uint32   { 'u32' }
		col_uint64   { 'u64' }
		tag_bigint   { 'bigint' }
		tag_float64  { 'float' }
		col_float32  { 'f32' }
		col_float16  { 'f16' }
		tag_decimal  { 'decimal' }
		tag_string   { '' }    // default — string columns dropped on emit
		tag_date     { 'date' }
		tag_datetime { 'datetime' }
		tag_bytes    { 'bytes' }
		col_atom     { 'atom' }
		col_bool     { 'bool' }
		tag_true     { 'bool' }  // legacy sentinel (pre-W3 buffers)
		col_nullable { '' }    // resolved from the inner code at payload read
		col_mixed    { '' }
		col_all_null { '' }
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
	// I1 row 16: the semantic kinds carry their base-10 images.
	if v is DataDecimal { return ScalarValue((v as DataDecimal).image) }
	if v is DataBigint { return ScalarValue((v as DataBigint).image) }
	// #815-adjacent: date/datetime are CXDM SCALARS, and the type arms
	// below (dataval_to_scalar_type) already answer date_type/datetime_type
	// for them — but the VALUE arm did not, so a decoded 0x31/0x32 scalar
	// reconstructed as an EMPTY scalar: `[when]`, the value silently gone.
	// Silent loss is the worst decode failure; the image carries.
	if v is DataDate { return scalar_value_from_date(v as DataDate) }
	if v is DataDateTime { return ScalarValue((v as DataDateTime).source) }
	// Containers in a cell position are unusual; flatten via str().
	return ScalarValue('')
}

// ── DataVal → Document reconstruction ────────────────────────────────────────

// dataval_to_document reverses the projection done by
// element_to_dataval. The root must be DataPairs; each (key, value)
// pair becomes a top-level Element. Other roots (single value, array,
// table) are wrapped in a synthetic '_' element to fit the Document
// shape.
// pairs_is_ext reports whether a DataPairs came off the wire in the #918
// extended-map form (0x52) — only a genuine value-model MapNode ever
// produces it, so it disambiguates a bare-map root from the keyed-element
// projection, and a typed-key/declaration map nested in an element body
// from a child-element projection.
fn pairs_is_ext(p DataPairs) bool {
	return p.key_types.len > 0 || p.decl_kinds.len > 0
}

fn dataval_to_document(root DataVal) !Document {
	if root is DataPairs {
		p := root as DataPairs
		// #918: an extended-form root IS the value-model map — restore it
		// as a MapNode document, typed keys and declarations intact.
		if pairs_is_ext(p) {
			return Document{ elements: [Node(map_dataval_to_node(p))] }
		}
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
				// #918: an extended-form nested map restores as a MapNode
				// child under a keyed wrapper element, never the flattened
				// keyed-element projection (which would drop key types and
				// null-conflate declarations).
				if pairs_is_ext(vv) {
					items << Node(Element{ name: k, items: [Node(map_dataval_to_node(vv))] })
				} else {
					items << Node(dataval_to_element(k, vv))
				}
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
	// I1 row 16: a decimal/bigint scalar body restores its HEAD ascription
	// so the kind survives emit when the bare image would re-type
	// differently (the canonical annotation-strip pass sheds it again
	// exactly when it is redundant — the existing fixpoint).
	kind := dataval_to_scalar_type_required(v)
	mut meta_dt := ?string(none)
	if kind == .decimal_type {
		meta_dt = 'decimal'
	} else if kind == .bigint_type {
		meta_dt = 'bigint'
	}
	if dt := meta_dt {
		return Element{
			name: name
			meta: &ElementMeta{ data_type: ?string(dt) }
			items: [Node(ScalarNode{
				data_type: kind
				value:     dataval_to_scalar(v)
			})]
		}
	}
	return Element{
		name:  name
		items: [Node(ScalarNode{
			data_type: kind
			value:     dataval_to_scalar(v)
		})]
	}
}

fn dataval_to_scalar_type(v DataVal) ?ScalarType {
	if v is i64       { return ScalarType.int_type }
	if v is DataDecimal { return ScalarType.decimal_type }
	if v is DataBigint  { return ScalarType.bigint_type }
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

// skip_column_payload cursor-skips one §3.10.3 column payload
// (stream 17 W4 — the projection executor's non-materializing arm).
fn (mut r BinReader) skip_column_payload(code u8, row_count int) ! {
	match code {
		col_all_null {}
		col_mixed {
			for _ in 0 .. row_count {
				r.read_dataval()!
			}
		}
		col_nullable {
			inner := r.take_u8()!
			bitmap := r.take((row_count + 7) / 8)!
			mut n_nonnull := 0
			for ri in 0 .. row_count {
				if (bitmap[ri / 8] >> (ri % 8)) & 1 == 0 {
					n_nonnull++
				}
			}
			r.skip_typed_cells_plain(inner, n_nonnull)!
		}
		else {
			r.skip_typed_cells_plain(code, row_count)!
		}
	}
}

fn (mut r BinReader) skip_dict_column(row_count int) ! {
	distinct := r.read_uvarint()!
	for _ in 0 .. int(distinct) {
		r.read_dataval()!
	}
	for _ in 0 .. row_count {
		r.read_uvarint()!
	}
}

fn (mut r BinReader) skip_typed_cells_plain(code u8, n int) ! {
	match code {
		col_bool {
			r.take((n + 7) / 8)!
		}
		tag_int8, col_uint8 {
			r.take(n)!
		}
		tag_int16, col_uint16, col_float16 {
			r.take(2 * n)!
		}
		tag_int32, col_uint32, col_float32 {
			r.take(4 * n)!
		}
		tag_int64, col_uint64, tag_float64 {
			r.take(8 * n)!
		}
		tag_date {
			r.take(4 * n)!
		}
		tag_datetime {
			r.take(12 * n)!
		}
		tag_string, tag_bytes, tag_bigint, tag_decimal, col_atom {
			for _ in 0 .. n {
				ln := r.read_uvarint()!
				r.take(int(ln))!
			}
		}
		else {
			return error('cxcol: cannot skip unknown column code 0x${code:02x}')
		}
	}
}

// parse_data_bin_projected decodes framed CXCol bytes materializing
// ONLY the named table columns (others read as null placeholders,
// cursor-skipped — stream 17 W4, the cxstore_columnar_backend §6
// pushdown executor's projected read).
pub fn parse_data_bin_projected(input []u8, want []string) !Document {
	if input.len < 4 {
		return error('cxcol: input too short for size header')
	}
	payload_size := u32(input[0]) | (u32(input[1]) << 8)
		| (u32(input[2]) << 16) | (u32(input[3]) << 24)
	if 4 + int(payload_size) > input.len {
		return error('cxcol: declared payload (${payload_size}) exceeds remaining input')
	}
	mut r := BinReader{
		buf:            unsafe { input[4 .. 4 + int(payload_size)] }
		pos:            0
		depth:          0
		max_depth:      int(cxcol_default_depth)
		col_projection: want
	}
	r.read_header()!
	root := r.read_dataval()!
	if r.pos != r.buf.len {
		return error('cxcol: trailing bytes after root value (${r.buf.len - r.pos} bytes)')
	}
	return dataval_to_document(root)!
}
