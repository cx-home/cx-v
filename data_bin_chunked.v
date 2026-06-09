module cx

import compress.zstd

// CXCol — chunked-table (`0x63`) + page-compression wrapper
// (`0x90`, zstd v1) per spec/core/data-bin.md §§3.11-3.12.
//
// The non-chunked `0x60` emitter in data_bin.v is unchanged. This module
// adds an alternative emit path for table-bodied documents that:
//   - declares the column schema once at the head (§3.11.1)
//   - emits row groups in `chunk_size`-sized slices (§3.11.2)
//   - optionally wraps each row-group body in a zstd v1 frame (§3.12)
//
// Column payloads are encoded strict-spec column-major per §3.10.3
// (no per-value type tags). The reader for `0x63` likewise applies the
// strict layout. The pre-existing 0x60 path retains its per-cell tag
// emission for back-compat with the v2.x corpus.

// ── Tags ─────────────────────────────────────────────────────────────────────

const tag_table_chunked = u8(0x63)
const body_tag_plain    = u8(0x01)
const body_tag_zstd     = u8(0x90)
const codec_id_zstd     = u8(0x01)

// ── Defaults ─────────────────────────────────────────────────────────────────

// Strict-canonical chunk size.
pub const chunked_canonical_chunk_size = 1 << 20

// zstd level used by writers when no override is given. zstd's own
// default (3) — fast and broadly applicable.
pub const chunked_default_compress_level = 3

// Body-byte threshold above which the writer compresses a row group
// under `compress: .auto`. Below the threshold the per-row-group zstd
// frame overhead would swamp the savings.
pub const chunked_compress_threshold_bytes = 64 * 1024

// Reader-side cap on materializing a chunked table into a single
// in-memory `DataTable`. Streaming decode (cx_table_reader_*) lands in
// the next phase; this module's reader surface materializes when the
// total row count fits.
pub const chunked_reader_max_inline_rows = 8 * 1024 * 1024

pub enum CompressMode {
	never
	auto
	always
}

@[params]
pub struct ChunkedEmitOptions {
pub:
	chunk_size      int          = chunked_canonical_chunk_size
	compress        CompressMode = .auto
	compress_level  int          = chunked_default_compress_level
}

// ── Public entry points ──────────────────────────────────────────────────────

// emit_data_bin_chunked encodes a Document whose root is a single
// table-bodied Element as the chunked-table form. The element name is
// preserved by wrapping the chunked table in a single-pair map (the
// spec-correct embedding for value-position chunked tables — see
// spec/core/data-bin.md §3.11.1 col-spec layout, which carries no element
// name field). Output uses the existing 4-byte framing prefix.
pub fn emit_data_bin_chunked(doc Document, opts ChunkedEmitOptions) ![]u8 {
	name, t := single_table_root_with_name(doc) or {
		return error('cxcol chunked: ${err.msg()}')
	}
	if opts.chunk_size <= 0 {
		return error('cxcol chunked: chunk_size must be > 0')
	}
	mut payload := []u8{cap: 256}
	encode_header(mut payload)
	if name == '' {
		// Anonymous table — emit at root.
		encode_chunked_table(t, opts, mut payload)!
	} else {
		// Single-pair map wrapper: 0x50 0x01 <key> <chunked-table>.
		payload << tag_map
		encode_uvarint(mut payload, u64(1))
		encode_string_value(name, mut payload)
		encode_chunked_table(t, opts, mut payload)!
	}
	return frame_payload(payload)
}

// emit_data_bin_auto returns chunked form (`0x63`) for table-bodied
// roots, otherwise falls back to the existing in-memory emitter
// (`0x60` / `0x61` / map-of-tables). Strict-canonical writers prefer
// `0x60` for in-memory tables; this entry point exists
// so adopters who explicitly want the chunked form can opt in without
// reaching for a separate function name.
pub fn emit_data_bin_auto(doc Document, opts ChunkedEmitOptions) ![]u8 {
	if _, _ := single_table_root_with_name(doc) {
		return emit_data_bin_chunked(doc, opts)!
	}
	return emit_data_bin(doc)
}

// single_table_root inspects the Document and returns the top-level
// `:table` element's payload as a DataTable, when the Document has
// exactly one Element root and that root carries a TableData body.
fn single_table_root_with_name(doc Document) !(string, DataTable) {
	roots := doc.elements.filter(it is Element)
	if roots.len != 1 {
		return error('chunked emit requires exactly one top-level element (got ${roots.len})')
	}
	e := roots[0] as Element
	td := e.table_opt() or {
		return error('top-level element `${e.name}` is not a :table')
	}
	name := if e.name == '_' { '' } else { e.name }
	// Chunked-table format (`0x63`) is strict columnar
	// — every cell is a scalar of the column's declared type. Collection-
	// literal cells (Phase 2.2) cannot encode through
	// this path; callers that have collection cells must route through
	// the plain `0x60` non-chunked form via emit_data_bin (auto-selects).
	// Project TableCellValue rows to DataVal rows, then to ScalarValue
	// rows; the DataVal→ScalarValue step errors cleanly on collections.
	mut drows := [][]DataVal{cap: td.rows.len}
	for row in td.rows {
		mut drow := []DataVal{cap: row.len}
		for cell in row { drow << table_cell_to_dataval(cell) }
		drows << drow
	}
	return name, DataTable{ cols: td.cols, rows: drows }
}

// ── Writer ───────────────────────────────────────────────────────────────────

fn encode_chunked_table(t DataTable, opts ChunkedEmitOptions, mut buf []u8) ! {
	if t.cols.len == 0 {
		return error('cxcol chunked: empty col-spec')
	}
	buf << tag_table_chunked
	encode_uvarint(mut buf, u64(t.cols.len))
	for col in t.cols {
		encode_string_value(col.name, mut buf)
		buf << column_type_code(col.type_name)
	}
	// Chunked-table is strict columnar — project DataVal rows back to
	// ScalarValue rows; errors on any collection-literal cells with
	// a clear "use plain 0x60 form" diagnostic.
	srows := dataval_rows_to_scalar_rows(t.rows) or {
		return error('chunked-table writer (0x63): ${err.msg()} — collection-cell tables must encode through the plain `0x60` form (cx_to_data_bin auto-selects)')
	}
	mut row_idx := 0
	for row_idx < srows.len {
		mut end := row_idx + opts.chunk_size
		if end > srows.len { end = srows.len }
		encode_row_group(t.cols, srows[row_idx .. end], opts, mut buf)!
		row_idx = end
	}
	// End-of-table marker — uvarint(0).
	buf << u8(0)
}

fn encode_row_group(cols []TableColumn, rows [][]ScalarValue, opts ChunkedEmitOptions, mut buf []u8) ! {
	// Build the strict-canonical plain body: uvarint(row_count) +
	// per-column payload column-major (no per-cell tags).
	mut plain := []u8{cap: 64 + rows.len * cols.len * 4}
	encode_uvarint(mut plain, u64(rows.len))
	for col_idx, col in cols {
		encode_col_payload_strict(col_idx, col, rows, mut plain)!
	}
	use_zstd := match opts.compress {
		.never  { false }
		.always { true }
		.auto   { plain.len >= chunked_compress_threshold_bytes }
	}
	if !use_zstd {
		// body_byte_len = 1 (body-tag) + len(plain)
		encode_uvarint(mut buf, u64(1 + plain.len))
		buf << body_tag_plain
		buf << plain
		return
	}
	level := if opts.compress_level == 0 { chunked_default_compress_level } else { opts.compress_level }
	frame := zstd.compress(plain, compression_level: level) or {
		return error('cxcol chunked: zstd compress failed: ${err}')
	}
	// Build the 0x90 wrapper body: <0x01 codec> <uvarint uncomp> <uvarint comp> <frame>.
	mut wrapper := []u8{cap: frame.len + 16}
	wrapper << codec_id_zstd
	encode_uvarint(mut wrapper, u64(plain.len))
	encode_uvarint(mut wrapper, u64(frame.len))
	wrapper << frame
	encode_uvarint(mut buf, u64(1 + wrapper.len))
	buf << body_tag_zstd
	buf << wrapper
}

fn encode_col_payload_strict(col_idx int, col TableColumn, rows [][]ScalarValue, mut buf []u8) ! {
	code := column_type_code(col.type_name)
	for row in rows {
		mut v := ScalarValue('')
		if col_idx < row.len {
			v = row[col_idx]
		}
		encode_strict_cell(v, code, mut buf)!
	}
}

fn encode_strict_cell(v ScalarValue, code u8, mut buf []u8) ! {
	match code {
		tag_string {
			s := match v {
				string  { v }
				i64     { v.str() }
				f64     { v.str() }
				bool    { if v { 'true' } else { 'false' } }
				NullValue { '' }
			}
			encode_uvarint(mut buf, u64(s.len))
			buf << s.bytes()
		}
		tag_int8 {
			n := scalar_to_i64(v)
			buf << u8(n)
		}
		tag_int16 {
			n := scalar_to_i64(v)
			x := u16(u32(n))
			buf << u8(x & 0xFF)
			buf << u8((x >> 8) & 0xFF)
		}
		tag_int32 {
			n := scalar_to_i64(v)
			encode_u32_le(mut buf, u32(n))
		}
		tag_int64 {
			n := scalar_to_i64(v)
			encode_u64_le(mut buf, u64(n))
		}
		tag_float64 {
			f := scalar_to_f64(v)
			bits := math_f64_bits(f)
			encode_u64_le(mut buf, bits)
		}
		tag_date {
			// Spec §3.10.3 date column = 4 bytes/row, same wire as §3.7
			// minus the leading tag.
			d := scalar_to_date(v)
			yu := u16(u32(d.year))
			buf << u8(yu & 0xFF)
			buf << u8((yu >> 8) & 0xFF)
			buf << d.month
			buf << d.day
		}
		tag_datetime {
			// Spec §3.10.3 datetime column = 12 bytes/row, same wire as
			// §3.6.1 minus the leading tag: i64 ns LE + i16 offset LE +
			// u16 reserved (zero). Strict canonical normalizes offset
			// to 0; we error on un-parseable / out-of-range cells.
			s := scalar_to_string_for_datetime(v)
			ns, _ := parse_iso_datetime_canonical(s)!
			encode_u64_le(mut buf, u64(ns))
			buf << u8(0)
			buf << u8(0)
			buf << u8(0)
			buf << u8(0)
		}
		tag_bytes {
			b := scalar_to_bytes(v)
			encode_uvarint(mut buf, u64(b.len))
			buf << b
		}
		tag_true {
			// Bool sentinel; pack 1 bit per row downstream. v0 emits one
			// byte per row (0/1) — bit-packed columns (§3.10.4) lands
			// alongside the streaming Table API in a follow-up phase.
			b := match v {
				bool { v }
				i64  { v != 0 }
				else { false }
			}
			buf << u8(if b { 1 } else { 0 })
		}
		else {
			return error('cxcol chunked: unsupported column type code 0x${code:02x}')
		}
	}
}

fn scalar_to_i64(v ScalarValue) i64 {
	return match v {
		i64    { v }
		f64    { i64(v) }
		bool   { if v { i64(1) } else { i64(0) } }
		string { v.i64() }
		NullValue { i64(0) }
	}
}

fn scalar_to_f64(v ScalarValue) f64 {
	return match v {
		f64    { v }
		i64    { f64(v) }
		bool   { if v { f64(1) } else { f64(0) } }
		string { v.f64() }
		NullValue { f64(0) }
	}
}

fn scalar_to_date(v ScalarValue) DataDate {
	if v is string {
		// Best-effort YYYY-MM-DD parse; the parser stores dates as
		// strings before this point.
		s := v as string
		if s.len >= 10 && s[4] == `-` && s[7] == `-` {
			y := s[0..4].i16()
			mo := s[5..7].u8()
			d := s[8..10].u8()
			return DataDate{ year: y, month: mo, day: d }
		}
	}
	return DataDate{ year: 0, month: 1, day: 1 }
}

fn scalar_to_string_for_datetime(v ScalarValue) string {
	return match v {
		string    { v }
		NullValue { '' }
		i64       { v.str() }
		f64       { v.str() }
		bool      { if v { 'true' } else { 'false' } }
	}
}

fn scalar_to_bytes(v ScalarValue) []u8 {
	return match v {
		string { v.bytes() }
		else   { []u8{} }
	}
}

// math_f64_bits: indirect to math.f64_bits via a thin wrapper to keep
// this file's import surface minimal (the existing data_bin.v already
// imports math and exposes encode_float64; we reuse encode_u64_le and
// avoid double-importing math here).
fn math_f64_bits(v f64) u64 {
	return f64_to_bits(v)
}

fn f64_to_bits(v f64) u64 {
	// Matches math.f64_bits semantics. Implemented via union-bypass
	// through a u64 cast on the IEEE-754 bit pattern. V's stdlib is
	// already imported in data_bin.v; we reach into it indirectly by
	// re-encoding via the same path encode_float64 uses there. A small
	// duplication beats threading another module-level import.
	bits := unsafe { *(&u64(&v)) }
	return bits
}

// ── Reader ───────────────────────────────────────────────────────────────────

fn (mut r BinReader) read_chunked_table_payload() !DataVal {
	col_count := r.read_uvarint()!
	if col_count == 0 {
		return error('cxcol chunked: tag 0x63 with col_count=0; use 0x61 for empty tables')
	}
	mut cols := []TableColumn{cap: int(col_count)}
	for _ in 0 .. int(col_count) {
		key_tag := r.take_u8()!
		if key_tag != tag_string {
			return error('cxcol chunked: column name must be string (tag 0x30); got 0x${key_tag:02x}')
		}
		name := r.read_string_payload()!
		col_type_byte := r.take_u8()!
		cols << TableColumn{ name: name, type_name: column_type_name_from_code(col_type_byte) }
	}
	mut rows := [][]ScalarValue{}
	for {
		body_byte_len := r.read_uvarint()!
		if body_byte_len == 0 {
			break // end-of-table marker
		}
		if body_byte_len > u64(r.buf.len - r.pos) {
			return error('cxcol chunked: row-group body_byte_len ${body_byte_len} exceeds remaining input')
		}
		body_tag := r.take_u8()!
		body_bytes_remaining := int(body_byte_len) - 1
		match body_tag {
			body_tag_plain {
				body := r.take(body_bytes_remaining)!
				decode_row_group_body(body, cols, mut rows)!
			}
			body_tag_zstd {
				wrapper := r.take(body_bytes_remaining)!
				body := decompress_row_group(wrapper)!
				decode_row_group_body(body, cols, mut rows)!
			}
			else {
				return error('cxcol chunked: reserved body-tag 0x${body_tag:02x} (expected 0x01 or 0x90)')
			}
		}
		if u64(rows.len) > u64(chunked_reader_max_inline_rows) {
			return error('cxcol chunked: row count exceeds in-memory cap (${chunked_reader_max_inline_rows}); use streaming Table API')
		}
	}
	// Chunked decode produces [][]ScalarValue (strict columnar);
	// lift into [][]DataVal for DataTable per Phase 2.2 wire-format.
	return DataVal(DataTable{ cols: cols, rows: scalar_rows_to_dataval_rows(rows), from_chunked: true })
}

fn decode_row_group_body(body []u8, cols []TableColumn, mut rows [][]ScalarValue) ! {
	mut rg := BinReader{ buf: body, pos: 0, depth: 0, max_depth: int(cxcol_default_depth) }
	row_count := rg.read_uvarint()!
	mut group := [][]ScalarValue{cap: int(row_count)}
	for _ in 0 .. int(row_count) {
		group << []ScalarValue{cap: cols.len}
	}
	for col_idx, col in cols {
		code := column_type_code(col.type_name)
		for row_idx in 0 .. int(row_count) {
			val := rg.read_strict_cell(code)!
			group[row_idx] << val
			_ = col_idx
		}
	}
	if rg.pos != rg.buf.len {
		return error('cxcol chunked: trailing bytes in row-group body (${rg.buf.len - rg.pos} bytes)')
	}
	for row in group {
		rows << row
	}
}

fn (mut r BinReader) read_strict_cell(code u8) !ScalarValue {
	return match code {
		tag_string {
			n := r.read_uvarint()!
			if n > u64(r.buf.len - r.pos) {
				return error('cxcol chunked: string length ${n} exceeds remaining input')
			}
			bs := r.take(int(n))!
			ScalarValue(bs.bytestr())
		}
		tag_int8 {
			b := r.take_u8()!
			ScalarValue(i64(i8(b)))
		}
		tag_int16 {
			ScalarValue(i64(r.read_i16_le()!))
		}
		tag_int32 {
			ScalarValue(i64(r.read_i32_le()!))
		}
		tag_int64 {
			ScalarValue(r.read_i64_le()!)
		}
		tag_float64 {
			ScalarValue(r.read_f64()!)
		}
		tag_date {
			d := r.read_date_payload()!
			ScalarValue('${int(d.year):04d}-${int(d.month):02d}-${int(d.day):02d}')
		}
		tag_datetime {
			unix_nanos := r.read_i64_le()!
			offset_min := r.read_i16_le()!
			reserved   := r.read_i16_le()!
			if reserved != 0 {
				return error('cxcol chunked: datetime reserved bytes must be zero (got 0x${u16(reserved):04x})')
			}
			if offset_min < -1080 || offset_min > 1080 {
				return error('cxcol chunked: datetime offset_minutes ${offset_min} exceeds ±1080')
			}
			ScalarValue(format_iso_datetime_utc(unix_nanos, offset_min))
		}
		tag_bytes {
			b := r.read_bytes_payload()!
			ScalarValue(b.bytestr())
		}
		tag_true {
			b := r.take_u8()!
			ScalarValue(b != 0)
		}
		else {
			return error('cxcol chunked: unsupported column type code 0x${code:02x}')
		}
	}
}

// build_synthesized_plain_row_group constructs a deterministic
// plain-body row-group payload (§3.11.2 strict columnar) for HH4
// RSS-bounded-write tests. Column values are synthesized
// from the row index via the same rule synth_table_document uses
// (int/i64/i32 → row index; f32/f64 → row index as float; bool →
// i % 2 == 0; everything else → "r_<i>"). Returns the plain-body
// bytes: uvarint(row_count) + per-column payload column-major,
// suitable for direct hand-off to CxTableWriter.emit_row_group_payload.
pub fn build_synthesized_plain_row_group(cols []TableColumn, n_rows int) ![]u8 {
	if n_rows <= 0 {
		return error('build_synthesized_plain_row_group: n_rows must be > 0')
	}
	if cols.len == 0 {
		return error('build_synthesized_plain_row_group: cols must have at least one column')
	}
	mut buf := []u8{cap: 16 + n_rows * cols.len * 4}
	encode_uvarint(mut buf, u64(n_rows))
	for col in cols {
		code := column_type_code(col.type_name)
		t := col.type_name
		for i in 0 .. n_rows {
			v := if t == 'int' || t == 'i64' || t == 'i32' {
				ScalarValue(i64(i))
			} else if t == 'float' || t == 'f64' || t == 'f32' {
				ScalarValue(f64(i))
			} else if t == 'bool' {
				ScalarValue(i % 2 == 0)
			} else {
				ScalarValue('r_${i}')
			}
			encode_strict_cell(v, code, mut buf)!
		}
	}
	return buf
}

// chunked_group_row_counts walks the row-group structure of a
// chunked-table (`0x63`) byte stream and returns the row counts of
// each group in source order. Used by HH3 per-group
// inspection assertions; lets million-row corpus tests verify group
// boundaries without materialising cell contents (and without
// tripping the chunked_reader_max_inline_rows cap on the regular
// decode path).
//
// Decompresses 0x90 wrappers to read the row_count uvarint at the
// start of each group body. Skips cell payloads.
//
// Input is framed bytes (4-byte length prefix + CXCol header + payload).
// For single-root chunked-table emissions where the root is wrapped
// in a 1-entry map (`single_table_root_with_name` puts a name on the
// chunked table), the map wrapper is skipped before the 0x63 tag is
// found.
pub fn chunked_group_row_counts(framed []u8) ![]int {
	if framed.len < 4 {
		return error('cxcol chunked: input too short for size header')
	}
	payload_size := u32(framed[0]) | (u32(framed[1]) << 8)
		| (u32(framed[2]) << 16) | (u32(framed[3]) << 24)
	if 4 + int(payload_size) > framed.len {
		return error('cxcol chunked: declared payload (${payload_size}) exceeds input')
	}
	mut r := BinReader{
		buf:       unsafe { framed[4 .. 4 + int(payload_size)] }
		pos:       0
		depth:     0
		max_depth: int(cxcol_default_depth)
	}
	// CXCol header is 12 bytes (5 magic + 1 version + 1 flags + 4
	// max_depth_u32 + 1 reserved — magic grew 4→5 in v0.8.0). Validate
	// magic but skip the per-field check — chunked_group_row_counts is
	// an inspection helper, not a strict-decode entry point.
	r.read_header()!
	tag := r.take_u8()!
	// Optional single-entry map wrapper from single_table_root_with_name.
	if tag == tag_map {
		entries := r.read_uvarint()!
		if entries != 1 {
			return error('cxcol chunked: expected single-entry map wrapper, got entries=${entries}')
		}
		key_tag := r.take_u8()!
		if key_tag != tag_string {
			return error('cxcol chunked: map-key tag must be 0x30, got 0x${key_tag:02x}')
		}
		_ := r.read_string_payload()!
		// Now expect the chunked-table tag.
		inner_tag := r.take_u8()!
		if inner_tag != tag_table_chunked {
			return error('cxcol chunked: map wrapper does not contain a chunked table (got tag 0x${inner_tag:02x})')
		}
	} else if tag != tag_table_chunked {
		return error('cxcol chunked: root is not a chunked table (got tag 0x${tag:02x})')
	}
	// col-spec
	col_count := r.read_uvarint()!
	if col_count == 0 {
		return error('cxcol chunked: chunked table with col_count=0')
	}
	for _ in 0 .. int(col_count) {
		key_tag := r.take_u8()!
		if key_tag != tag_string {
			return error('cxcol chunked: column name must be string (tag 0x30); got 0x${key_tag:02x}')
		}
		_ := r.read_string_payload()!
		_ := r.take_u8()!  // col_type_byte
	}
	// row groups
	mut row_counts := []int{}
	for {
		body_byte_len := r.read_uvarint()!
		if body_byte_len == 0 {
			break // end-of-table marker
		}
		if body_byte_len > u64(r.buf.len - r.pos) {
			return error('cxcol chunked: row-group body_byte_len ${body_byte_len} exceeds remaining input')
		}
		body_tag := r.take_u8()!
		body_bytes_remaining := int(body_byte_len) - 1
		body_bytes := match body_tag {
			body_tag_plain {
				bytes := r.take(body_bytes_remaining)!
				bytes
			}
			body_tag_zstd {
				wrapper := r.take(body_bytes_remaining)!
				decompress_row_group(wrapper)!
			}
			else {
				return error('cxcol chunked: reserved body-tag 0x${body_tag:02x}')
			}
		}
		// First uvarint of the group body is the row count.
		mut br := BinReader{ buf: body_bytes, pos: 0, depth: 0, max_depth: int(cxcol_default_depth) }
		rc := br.read_uvarint()!
		row_counts << int(rc)
	}
	return row_counts
}

fn decompress_row_group(wrapper []u8) ![]u8 {
	// Layout per §3.12.1: <codec_id(1)> <uvarint uncomp_len> <uvarint comp_len> <frame>.
	if wrapper.len == 0 {
		return error('cxcol chunked: empty 0x90 wrapper')
	}
	codec := wrapper[0]
	if codec == 0x00 {
		// data-bin.md:1213 — any codec id != 0x01 is D005 (no D006 in spec);
		// 0x00 is the reserved "no compression" id (use plain body-tag 0x01).
		return error('cxcol chunked: D005: codec id 0x00 reserved; use plain body-tag 0x01 for uncompressed row groups')
	}
	if codec != codec_id_zstd {
		return error('cxcol chunked: D005: unknown compression codec id 0x${codec:02x} (zstd v1 = 0x01 expected)')
	}
	mut r := BinReader{ buf: wrapper, pos: 1, depth: 0, max_depth: int(cxcol_default_depth) }
	uncomp_len := r.read_uvarint()!
	comp_len := r.read_uvarint()!
	if u64(r.buf.len - r.pos) < comp_len {
		return error('cxcol chunked: compressed_byte_len ${comp_len} exceeds wrapper bytes')
	}
	frame := r.take(int(comp_len))!
	out := zstd.decompress(frame) or {
		return error('cxcol chunked: zstd decompress failed: ${err}')
	}
	if u64(out.len) != uncomp_len {
		return error('cxcol chunked: zstd frame decompressed to ${out.len} bytes; header declared ${uncomp_len}')
	}
	return out
}
