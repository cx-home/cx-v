module cx

import compress.zstd

// CXDB v0.6.0 — streaming Table reader / writer.
//
// Implements ADR 0015 D8 (spec/abi.md §2.10): a handle-based C ABI
// surface that pulls / pushes one row group at a time over the
// chunked-table wire format (`0x63`, spec/data_bin.md §3.11). Memory
// use is bounded by the largest single row group plus a constant
// overhead.
//
// In-memory mode (`*_open`) consumes / produces the framed
// `[u32 LE size][CXDB payload]` form used elsewhere in the C ABI.
// Fd mode (`*_open_fd`) operates on bare CXDB bytes — no framing
// prefix, since the file's length is implicit from the fd. Writers
// must operate this way: total size is unknown until end-of-table.
// Readers mirror the convention so a writer's output is directly
// consumable by a reader.
//
// The col-spec exchanged at the API boundary (reader's schema()
// output, writer's open() input) is encoded as ast_bin: a Document
// with one Element carrying a `:table` body that holds the column
// list (no rows). This matches abi.md §2.10's "ast_bin (Element with
// one Attribute per column carrying name + :type)" contract while
// reusing the existing emit_ast_bin / bin_to_doc machinery.
//
// Bit 21 of `cx_features` (0x200000) signals reader / writer
// support. Phase 7.74a lands the V core impl + 10 C ABI symbols;
// 9-binding wrappers follow in Phase 7.74b.

// ── libc fd I/O ──────────────────────────────────────────────────────────────
//
// `C.read` / `C.write` are declared in V's `builtin/cfns.c.v`; we
// reuse those signatures rather than redeclaring (which conflicts with
// the system <unistd.h> declarations on the C side).

// Read exactly `n` bytes from `fd`; short reads loop until either
// `n` bytes are read or EOF is hit. Returns the bytes actually read
// (may be < n on EOF, in which case the caller decides whether
// that's fatal).
fn fd_read_n(fd int, n int) ![]u8 {
	mut out := []u8{len: n}
	mut got := 0
	for got < n {
		need := n - got
		r := unsafe { C.read(fd, voidptr(&u8(out.data) + got), usize(need)) }
		if r == 0 { break }  // EOF
		if r < 0 {
			return error('cxdb table: read(fd) failed')
		}
		got += int(r)
	}
	if got < n { out.trim(got) }
	return out
}

// Read one byte from `fd`, surfacing EOF distinctly from error.
fn fd_read_byte(fd int) !(u8, bool) {
	mut b := u8(0)
	r := unsafe { C.read(fd, voidptr(&b), usize(1)) }
	if r == 0 { return u8(0), true }
	if r < 0 { return error('cxdb table: read(fd) failed') }
	return b, false
}

// Read a uvarint from `fd` byte-at-a-time. Returns (value, eof).
// EOF on the first byte returns eof=true with value=0; EOF mid-varint
// is an error.
fn fd_read_uvarint(fd int) !(u64, bool) {
	mut x := u64(0)
	mut s := u32(0)
	for i in 0 .. 5 {
		b, eof := fd_read_byte(fd)!
		if eof {
			if i == 0 { return u64(0), true }
			return error('cxdb table: truncated varint from fd')
		}
		if b < 0x80 {
			if i == 4 && b > 0x0F {
				return error('cxdb table: varint overflow (>2^32-1)')
			}
			if i > 0 && b == 0 {
				return error('cxdb table: non-canonical varint (extra zero byte)')
			}
			x |= u64(b) << s
			return x, false
		}
		x |= u64(b & 0x7F) << s
		s += 7
	}
	return error('cxdb table: varint exceeds 5 bytes')
}

fn fd_write_all(fd int, bytes []u8) ! {
	mut sent := 0
	for sent < bytes.len {
		need := bytes.len - sent
		r := unsafe { C.write(fd, voidptr(&u8(bytes.data) + sent), usize(need)) }
		if r < 0 { return error('cxdb table: write(fd) failed') }
		if r == 0 { return error('cxdb table: write(fd) returned 0') }
		sent += int(r)
	}
}

// ── Col-spec ↔ ast_bin bridge ────────────────────────────────────────────────

// col_spec_to_ast_bin builds a Document holding one Element named
// `table`, with one Attribute per column. The attribute name is the
// column name; its value is a string literal carrying the column's
// type name ('string', 'i32', 'i64', 'float', 'bool', 'date',
// 'datetime', 'bytes', or '' for the default-string column). This
// matches abi.md §2.10's "one Attribute per column carrying name +
// :type" contract while round-tripping cleanly through ast_bin
// (which doesn't serialize Element.table). Encodes as a framed
// ast_bin buffer.
fn col_spec_to_ast_bin(cols []TableColumn) []u8 {
	mut attrs := []Attribute{cap: cols.len}
	for c in cols {
		attrs << Attribute{
			name:  c.name
			value: ScalarValue(c.type_name)
		}
	}
	e := Element{
		name:  'table'
		attrs: attrs
	}
	doc := Document{ elements: [Node(e)] }
	return emit_ast_bin(doc)
}

// ast_bin_to_col_spec is the inverse: parse a framed ast_bin buffer,
// walk the single root Element's attributes, and reconstruct the
// TableColumn list.
fn ast_bin_to_col_spec(framed []u8) ![]TableColumn {
	doc := bin_to_doc(framed) or {
		return error('cxdb table writer: invalid col-spec ast_bin: ${err.msg()}')
	}
	roots := doc.elements.filter(it is Element)
	if roots.len != 1 {
		return error('cxdb table writer: col-spec must have exactly one Element root (got ${roots.len})')
	}
	e := roots[0] as Element
	if e.attrs.len == 0 {
		return error('cxdb table writer: empty col-spec (no attributes on root Element)')
	}
	mut cols := []TableColumn{cap: e.attrs.len}
	for a in e.attrs {
		type_name := if a.value is string { a.value as string } else { '' }
		cols << TableColumn{ name: a.name, type_name: type_name }
	}
	return cols
}

// ── Reader ───────────────────────────────────────────────────────────────────

@[heap]
pub struct CxTableReader {
mut:
	// Mode selectors. `bytes_mode` reads from an in-memory payload
	// slice; otherwise the reader pulls from `fd`.
	bytes_mode bool
	// Bytes mode: payload (post-framing-prefix), cursor, end position.
	buf []u8
	pos int
	// Fd mode.
	fd int = -1
	// Parsed col-spec.
	cols []TableColumn
	// State flags.
	header_consumed bool
	eof             bool
}

// new_table_reader_bytes opens a streaming reader over a framed
// CXDB buffer (the [u32 LE size][payload] form). The reader parses
// the header and col-spec eagerly (so schema() returns immediately);
// row groups are pulled lazily via next().
pub fn new_table_reader_bytes(framed []u8) !&CxTableReader {
	if framed.len < 4 {
		return error('cxdb table reader: input too short for size header')
	}
	payload_size := u32(framed[0]) | (u32(framed[1]) << 8)
		| (u32(framed[2]) << 16) | (u32(framed[3]) << 24)
	if 4 + int(payload_size) > framed.len {
		return error('cxdb table reader: declared payload (${payload_size}) exceeds remaining input')
	}
	payload := unsafe { framed[4 .. 4 + int(payload_size)] }
	mut r := &CxTableReader{ bytes_mode: true, buf: payload, pos: 0 }
	r.consume_header_and_col_spec_bytes()!
	return r
}

// new_table_reader_fd opens a streaming reader over an open file
// descriptor positioned at the CXDB magic (no framing prefix).
pub fn new_table_reader_fd(fd int) !&CxTableReader {
	mut r := &CxTableReader{ bytes_mode: false, fd: fd }
	r.consume_header_and_col_spec_fd()!
	return r
}

fn (mut r CxTableReader) consume_header_and_col_spec_bytes() ! {
	mut br := BinReader{ buf: r.buf, pos: r.pos, depth: 0, max_depth: int(cxdb_default_depth) }
	br.read_header()!
	// Optional outer single-pair map wrapper preserving the table's
	// element name (mirrors emit_data_bin_chunked). Accept either
	// shape: bare 0x63 at root or `0x50 0x01 <name> 0x63 ...`.
	tag := br.take_u8()!
	if tag == tag_map {
		pair_count := br.read_uvarint()!
		if pair_count != u64(1) {
			return error('cxdb table reader: outer map wrapper must have exactly one pair (got ${pair_count})')
		}
		key_tag := br.take_u8()!
		if key_tag != tag_string {
			return error('cxdb table reader: outer map key must be string')
		}
		_ = br.read_string_payload()!  // table name; not surfaced separately at v0.6.0
		next_tag := br.take_u8()!
		if next_tag != tag_table_chunked {
			return error('cxdb table reader: expected chunked-table tag 0x63; got 0x${next_tag:02x}')
		}
	} else if tag != tag_table_chunked {
		return error('cxdb table reader: expected chunked-table tag 0x63 (or 0x50 wrapper); got 0x${tag:02x}')
	}
	r.cols = read_col_spec(mut br)!
	r.pos = br.pos
	r.header_consumed = true
}

fn (mut r CxTableReader) consume_header_and_col_spec_fd() ! {
	// Header is fixed-size (12 bytes per encode_header).
	hdr := fd_read_n(r.fd, 12)!
	if hdr.len != 12 {
		return error('cxdb table reader: short read on header (got ${hdr.len} bytes)')
	}
	if hdr[0] != cxdb_magic[0] || hdr[1] != cxdb_magic[1]
		|| hdr[2] != cxdb_magic[2] || hdr[3] != cxdb_magic[3] {
		return error('cxdb table reader: bad CXDB magic')
	}
	if hdr[4] != cxdb_version {
		return error('cxdb table reader: unsupported CXDB version 0x${hdr[4]:02x}')
	}
	// Read tag byte; either chunked-table or single-pair map wrapper.
	first, eof := fd_read_byte(r.fd)!
	if eof { return error('cxdb table reader: truncated after header') }
	if first == tag_map {
		pair_count, _ := fd_read_uvarint(r.fd)!
		if pair_count != u64(1) {
			return error('cxdb table reader: outer map wrapper must have exactly one pair')
		}
		key_tag, _ := fd_read_byte(r.fd)!
		if key_tag != tag_string {
			return error('cxdb table reader: outer map key must be string')
		}
		key_len, _ := fd_read_uvarint(r.fd)!
		_ := fd_read_n(r.fd, int(key_len))!
		next_tag, _ := fd_read_byte(r.fd)!
		if next_tag != tag_table_chunked {
			return error('cxdb table reader: expected chunked-table tag 0x63 after wrapper; got 0x${next_tag:02x}')
		}
	} else if first != tag_table_chunked {
		return error('cxdb table reader: expected chunked-table tag 0x63; got 0x${first:02x}')
	}
	col_count, _ := fd_read_uvarint(r.fd)!
	if col_count == 0 {
		return error('cxdb table reader: tag 0x63 with col_count=0')
	}
	mut cols := []TableColumn{cap: int(col_count)}
	for _ in 0 .. int(col_count) {
		key_tag, _ := fd_read_byte(r.fd)!
		if key_tag != tag_string {
			return error('cxdb table reader: column name must be string (tag 0x30)')
		}
		name_len, _ := fd_read_uvarint(r.fd)!
		name_bytes := fd_read_n(r.fd, int(name_len))!
		col_type_byte, _ := fd_read_byte(r.fd)!
		cols << TableColumn{
			name:      name_bytes.bytestr()
			type_name: column_type_name_from_code(col_type_byte)
		}
	}
	r.cols = cols
	r.header_consumed = true
}

// read_col_spec consumes `uvarint(col_count) <col-spec>(col_count)`
// from the BinReader and returns the parsed TableColumn list.
fn read_col_spec(mut br BinReader) ![]TableColumn {
	col_count := br.read_uvarint()!
	if col_count == 0 {
		return error('cxdb table reader: tag 0x63 with col_count=0')
	}
	mut cols := []TableColumn{cap: int(col_count)}
	for _ in 0 .. int(col_count) {
		key_tag := br.take_u8()!
		if key_tag != tag_string {
			return error('cxdb table reader: column name must be string (tag 0x30); got 0x${key_tag:02x}')
		}
		name := br.read_string_payload()!
		col_type_byte := br.take_u8()!
		cols << TableColumn{
			name:      name
			type_name: column_type_name_from_code(col_type_byte)
		}
	}
	return cols
}

// schema_bytes returns the col-spec as a framed ast_bin buffer.
pub fn (r &CxTableReader) schema_bytes() ![]u8 {
	if !r.header_consumed {
		return error('cxdb table reader: handle uninitialized')
	}
	return col_spec_to_ast_bin(r.cols)
}

// next_row_group_framed pulls the next row group, returning its
// **decompressed** plain body (uvarint(row_count) + col-payload[col_count])
// wrapped in a [u32 LE size][body] frame, ready to hand to a binding.
// Returns an empty slice on end-of-table (a row group always has
// body_byte_len > 0, so an empty return is unambiguous).
pub fn (mut r CxTableReader) next_row_group_framed() ![]u8 {
	if r.eof {
		return []u8{}
	}
	body := if r.bytes_mode {
		r.next_body_bytes()!
	} else {
		r.next_body_fd()!
	}
	if body.len == 0 {
		r.eof = true
		return []u8{}
	}
	mut framed := []u8{cap: 4 + body.len}
	sz := u32(body.len)
	framed << u8(sz & 0xFF)
	framed << u8((sz >> 8) & 0xFF)
	framed << u8((sz >> 16) & 0xFF)
	framed << u8((sz >> 24) & 0xFF)
	framed << body
	return framed
}

// next_body_bytes returns the next plain row-group body, or an empty
// slice on end-of-table. Errors propagate normally.
fn (mut r CxTableReader) next_body_bytes() ![]u8 {
	mut br := BinReader{ buf: r.buf, pos: r.pos, depth: 0, max_depth: int(cxdb_default_depth) }
	body_byte_len := br.read_uvarint()!
	if body_byte_len == 0 {
		r.pos = br.pos
		return []u8{}
	}
	if body_byte_len > u64(br.buf.len - br.pos) {
		return error('cxdb table reader: row-group body_byte_len ${body_byte_len} exceeds remaining input')
	}
	body_tag := br.take_u8()!
	body_bytes_remaining := int(body_byte_len) - 1
	plain := match body_tag {
		body_tag_plain {
			b := br.take(body_bytes_remaining)!
			b.clone()
		}
		body_tag_zstd {
			wrapper := br.take(body_bytes_remaining)!
			decompress_row_group(wrapper)!
		}
		else {
			return error('cxdb table reader: reserved body-tag 0x${body_tag:02x} (expected 0x01 or 0x90)')
		}
	}
	r.pos = br.pos
	return plain
}

fn (mut r CxTableReader) next_body_fd() ![]u8 {
	body_byte_len, eof := fd_read_uvarint(r.fd)!
	if eof || body_byte_len == 0 {
		return []u8{}
	}
	body_tag, eof2 := fd_read_byte(r.fd)!
	if eof2 {
		return error('cxdb table reader: truncated row-group (no body-tag)')
	}
	body_bytes_remaining := int(body_byte_len) - 1
	body_raw := fd_read_n(r.fd, body_bytes_remaining)!
	if body_raw.len != body_bytes_remaining {
		return error('cxdb table reader: short read on row-group body (got ${body_raw.len}, need ${body_bytes_remaining})')
	}
	plain := match body_tag {
		body_tag_plain { body_raw }
		body_tag_zstd  { decompress_row_group(body_raw)! }
		else {
			return error('cxdb table reader: reserved body-tag 0x${body_tag:02x}')
		}
	}
	return plain
}

// reader_close exists to make C-side handle release explicit. V's GC
// reclaims the @[heap] CxTableReader once the binding releases the
// pointer; we don't own the fd (caller opened it, caller closes it).
pub fn (mut r CxTableReader) reader_close() {
	r.eof = true
}

// ── Writer ───────────────────────────────────────────────────────────────────

@[heap]
pub struct CxTableWriter {
mut:
	cols    []TableColumn
	opts    ChunkedEmitOptions
	// Bytes mode accumulates the full document (header + col-spec +
	// all row groups + trailer) into `buf`; close_get_bytes frames it.
	bytes_mode bool
	buf        []u8
	// Fd mode writes incrementally. The header + col-spec are flushed
	// at open(); each emit_row_group flushes one row-group; close
	// flushes the end-of-table marker.
	fd     int = -1
	closed bool
}

// new_table_writer_bytes opens an in-memory writer. The caller-
// supplied col-spec is taken as a framed ast_bin buffer (the same
// shape cx_table_reader_schema returns). At v0.6.0 the writer's
// chunk options are not configurable through the C ABI; the default
// auto-zstd-above-64KiB policy applies.
pub fn new_table_writer_bytes(col_spec_payload []u8) !&CxTableWriter {
	cols := ast_bin_to_col_spec(col_spec_payload)!
	mut w := &CxTableWriter{
		cols:       cols
		opts:       ChunkedEmitOptions{}
		bytes_mode: true
	}
	w.write_header_and_col_spec_bytes()
	return w
}

pub fn new_table_writer_fd(col_spec_payload []u8, fd int) !&CxTableWriter {
	cols := ast_bin_to_col_spec(col_spec_payload)!
	mut w := &CxTableWriter{
		cols:       cols
		opts:       ChunkedEmitOptions{}
		bytes_mode: false
		fd:         fd
	}
	w.write_header_and_col_spec_fd()!
	return w
}

fn (mut w CxTableWriter) write_header_and_col_spec_bytes() {
	encode_header(mut w.buf)
	w.buf << tag_table_chunked
	encode_uvarint(mut w.buf, u64(w.cols.len))
	for col in w.cols {
		encode_string_value(col.name, mut w.buf)
		w.buf << column_type_code(col.type_name)
	}
}

fn (mut w CxTableWriter) write_header_and_col_spec_fd() ! {
	mut hdr := []u8{cap: 12}
	encode_header(mut hdr)
	fd_write_all(w.fd, hdr)!
	mut spec := []u8{cap: 16 + w.cols.len * 16}
	spec << tag_table_chunked
	encode_uvarint(mut spec, u64(w.cols.len))
	for col in w.cols {
		encode_string_value(col.name, mut spec)
		spec << column_type_code(col.type_name)
	}
	fd_write_all(w.fd, spec)!
}

// emit_row_group_payload appends a row group whose body is in the
// §3.11.2 plain-body format (uvarint(row_count) + col-payload[col_count]).
// The writer wraps it in body-tag 0x01 (plain) or 0x90 (zstd) per the
// active ChunkedEmitOptions policy.
pub fn (mut w CxTableWriter) emit_row_group_payload(plain_body []u8) ! {
	if w.closed {
		return error('cxdb table writer: emit on closed writer')
	}
	if plain_body.len == 0 {
		return error('cxdb table writer: empty row-group payload')
	}
	use_zstd := match w.opts.compress {
		.never  { false }
		.always { true }
		.auto   { plain_body.len >= chunked_compress_threshold_bytes }
	}
	mut group := []u8{cap: plain_body.len + 32}
	if !use_zstd {
		encode_uvarint(mut group, u64(1 + plain_body.len))
		group << body_tag_plain
		group << plain_body
	} else {
		level := if w.opts.compress_level == 0 { chunked_default_compress_level } else { w.opts.compress_level }
		frame := zstd.compress(plain_body, compression_level: level) or {
			return error('cxdb table writer: zstd compress failed: ${err}')
		}
		mut wrapper := []u8{cap: frame.len + 16}
		wrapper << codec_id_zstd
		encode_uvarint(mut wrapper, u64(plain_body.len))
		encode_uvarint(mut wrapper, u64(frame.len))
		wrapper << frame
		encode_uvarint(mut group, u64(1 + wrapper.len))
		group << body_tag_zstd
		group << wrapper
	}
	if w.bytes_mode {
		w.buf << group
	} else {
		fd_write_all(w.fd, group)!
	}
}

// close_get_bytes emits the end-of-table marker, frames the in-memory
// buffer, and returns it. Bytes mode only — fd-mode writers return
// an empty slice (caller uses writer_close instead).
pub fn (mut w CxTableWriter) close_get_bytes() ![]u8 {
	if w.closed {
		return error('cxdb table writer: already closed')
	}
	if !w.bytes_mode {
		return error('cxdb table writer: close_get_bytes is in-memory only; use writer_close for fd writers')
	}
	w.buf << u8(0)  // end-of-table marker
	w.closed = true
	return frame_payload(w.buf)
}

// writer_close releases the writer. For fd-mode writers, flushes the
// end-of-table marker. The caller still owns the fd.
pub fn (mut w CxTableWriter) writer_close() ! {
	if w.closed {
		return
	}
	if !w.bytes_mode {
		eot := [u8(0)]
		fd_write_all(w.fd, eot)!
	}
	w.closed = true
}
