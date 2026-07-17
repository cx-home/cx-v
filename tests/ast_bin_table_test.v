module main

import cx

// #464 — the ast_bin wire carries the pooled `[table[…]]` payload
// (Element table record, tag 0x17, format version 9; ast-bin.md §4.8).
// Last member of the #413/#443 blind-spot family: encode_node's Element
// arm never read Element.table, so a table-bearing document lost every
// column and row through emit_ast_bin → bin_to_doc.

// rt round-trips src through the binary AST wire and asserts the CX
// emit identity (canonical compare per the #464 acceptance bar).
fn rt(src string) {
	doc := cx.parse(src) or { panic('parse: ${err}') }
	bytes := cx.emit_ast_bin(doc)
	doc2 := cx.bin_to_doc(bytes) or { panic('bin_to_doc: ${err}') }
	want := cx.emit_cx(doc)
	got := cx.emit_cx(doc2)
	assert got == want, 'ast_bin round-trip not identity:\n  want: ${want}\n  got:  ${got}'
}

fn test_ast_bin_table_typed_columns_round_trip() {
	rt('[users [table[name::string age::int active::bool score::float]]
  alice 30 true 1.5
  bob 25 false 2.0
]')
}

fn test_ast_bin_table_untyped_and_mixed_columns_round_trip() {
	rt('[t [table[name age::int tag]]
  alice 30 admin
  bob 25 user
]')
}

fn test_ast_bin_table_quoted_and_null_cells_round_trip() {
	rt("[users [table[name::string note]]
  'alice jones' null
  bob 'has [bracket]'
]")
}

fn test_ast_bin_table_header_only_round_trip() {
	rt('[t [table[a::int b]]]')
}

fn test_ast_bin_table_collection_cells_round_trip() {
	rt('[t [table[name value]]
  tags [admin, user]
  meta {role: admin, age: 30}
  ports (80, 443)
]')
}

// The decoded TableData is structurally exact, not just emit-equal.
fn test_ast_bin_table_payload_structural() {
	doc := cx.parse('[users [table[name::string age::int note]]
  alice 30 null
  bob 25 admin
]') or { panic(err) }
	bytes := cx.emit_ast_bin(doc)
	doc2 := cx.bin_to_doc(bytes) or { panic('bin_to_doc: ${err}') }
	root := doc2.root() or { panic('no root') }
	assert root.name == 'users'
	dt := root.data_type() or { panic('data_type lost') }
	assert dt == 'table'
	td := root.table_opt() or { panic('table payload lost through ast_bin (#464)') }
	assert td.cols.len == 3
	assert td.cols[0].name == 'name'
	assert td.cols[0].type_name == 'string'
	assert td.cols[1].name == 'age'
	assert td.cols[1].type_name == 'int'
	assert td.cols[2].name == 'note'
	assert td.cols[2].type_name == ''
	assert td.rows.len == 2
	c00 := td.rows[0][0]
	assert c00 is string
	if c00 is string { assert c00 == 'alice' }
	c01 := td.rows[0][1]
	assert c01 is i64
	if c01 is i64 { assert c01 == 30 }
	assert td.rows[0][2] is cx.NullValue
	// from_chunked is runtime provenance, NOT on the wire — restores false.
	assert !td.from_chunked
}

// A table element that ALSO carries attrs and body items (constructible
// via the AST API even though the text parser produces table-only
// bodies): the wire carries all three channels.
fn test_ast_bin_table_with_attrs_and_children() {
	base := cx.parse('[cfg region=west [child 1]]') or { panic(err) }
	root := base.root() or { panic('no root') }
	td := &cx.TableData{
		cols: [cx.TableColumn{
			name: 'k'
		}, cx.TableColumn{
			name:      'v'
			type_name: 'int'
		}]
		rows: [[cx.TableCellValue('a'), cx.TableCellValue(i64(1))],
			[cx.TableCellValue('b'), cx.TableCellValue(i64(2))]]
	}
	el := root.with_table(td)
	doc := cx.Document{
		elements: [cx.Node(el)]
	}
	bytes := cx.emit_ast_bin(doc)
	doc2 := cx.bin_to_doc(bytes) or { panic('bin_to_doc: ${err}') }
	root2 := doc2.root() or { panic('no root') }
	assert root2.attr('region') == 'west'
	assert root2.items.len == 1
	td2 := root2.table_opt() or { panic('table lost') }
	assert td2.cols.len == 2
	assert td2.rows.len == 2
	c := td2.rows[1][1]
	assert c is i64
	if c is i64 { assert c == 2 }
}

// Single-node frames (cxstore content-addressed engine) carry the
// payload too.
fn test_node_bin_table_round_trip() {
	doc := cx.parse('[t [table[a b::int]]
  x 1
]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	bytes := cx.emit_node_bin(cx.Node(root))
	n2 := cx.node_from_bin(bytes) or { panic('node_from_bin: ${err}') }
	el2 := n2 as cx.Element
	td := el2.table_opt() or { panic('table lost through node frame') }
	assert td.rows.len == 1
}

// ── version discipline ────────────────────────────────────────────────────────

// Table-bearing documents bump the envelope to v9; table-free documents
// keep their previous version byte (6 common case) so existing readers
// keep decoding every buffer they could decode before (additive rule).
fn test_ast_bin_version_bumps_only_for_tables() {
	plain := cx.parse('[a [b]]') or { panic(err) }
	plain_bytes := cx.emit_ast_bin(plain)
	assert plain_bytes[4] == 6, 'table-free doc must stay at v6, got ${plain_bytes[4]}'

	tdoc := cx.parse('[t [table[a]]
  x
]') or { panic(err) }
	tbytes := cx.emit_ast_bin(tdoc)
	assert tbytes[4] == 9, 'table-bearing doc must emit v9, got ${tbytes[4]}'
}

// ── malformed payload rejection (fail-loud, #464 acceptance) ──────────────────

// build_table_doc_bytes returns the framed v9 bytes of
// `[t [table[a b]] x y]` for byte-surgery tests.
fn build_table_doc_bytes() []u8 {
	doc := cx.parse('[t [table[a b]]
  x y
]') or { panic(err) }
	return cx.emit_ast_bin(doc)
}

fn test_ast_bin_rejects_table_tag_below_v9() {
	mut bytes := build_table_doc_bytes()
	// Rewind the version byte to 8: tag 0x17 must not decode in a <v9
	// envelope (producers never emitted it before v9).
	bytes[4] = 8
	if _ := cx.bin_to_doc(bytes) {
		assert false, 'tag 0x17 in a v8 envelope must be rejected'
	} else {
		assert err.msg().contains('0x17') || err.msg().contains('table'), 'reject must name the table tag: ${err.msg()}'
	}
}

fn test_ast_bin_rejects_table_at_top_level() {
	// Splice the table record (starts at the element's first child slot)
	// into top-level element position: version 9, 0 prolog, 1 element
	// that IS the 0x17 record. The decoder must reject 0x17 outside an
	// Element child list.
	src := build_table_doc_bytes()
	// find the 0x17 tag: it is the first child of the root element.
	mut off := -1
	for i in 4 .. src.len {
		if src[i] == 0x17 {
			off = i
			break
		}
	}
	assert off > 0, 'fixture bytes must contain a 0x17 record'
	record := src[off..]
	mut payload := []u8{}
	payload << u8(9) // version
	payload << [u8(0), 0] // prolog_count
	payload << [u8(1), 0] // element_count
	payload << record
	mut framed := []u8{}
	sz := u32(payload.len)
	framed << u8(sz & 0xFF)
	framed << u8((sz >> 8) & 0xFF)
	framed << u8((sz >> 16) & 0xFF)
	framed << u8(sz >> 24)
	framed << payload
	if _ := cx.bin_to_doc(framed) {
		assert false, 'top-level 0x17 table record must be rejected'
	} else {
		assert err.msg().contains('table'), 'reject must be loud about table position: ${err.msg()}'
	}
}

fn test_ast_bin_rejects_row_cell_count_mismatch() {
	mut bytes := build_table_doc_bytes()
	// The row record is `u16:cell_count cells[]` with cell_count == 2
	// (cols a b). Find the 0x17 record, then corrupt the row's
	// cell_count. Layout after 0x17: u16 col_count=2, col a (Str name
	// 'a' + Str type ''), col b, u32 row_count=1, u16 cell_count=2.
	mut off := -1
	for i in 4 .. bytes.len {
		if bytes[i] == 0x17 {
			off = i
			break
		}
	}
	assert off > 0
	// walk: tag(1) colcount(2) + col'a'(4+1 + 4+0) + col'b'(4+1 + 4+0) + rowcount(4)
	cc_off := off + 1 + 2 + 9 + 9 + 4
	assert bytes[cc_off] == 2 && bytes[cc_off + 1] == 0, 'cell_count not at expected offset'
	bytes[cc_off] = 3
	if _ := cx.bin_to_doc(bytes) {
		assert false, 'row cell_count != col_count must be rejected'
	} else {
		assert err.msg().contains('cell'), 'reject must name the cell-count mismatch: ${err.msg()}'
	}
}

fn test_ast_bin_rejects_non_cell_node_kind() {
	mut bytes := build_table_doc_bytes()
	// First cell is Scalar (0x03) 'string' 'x'. Rewrite its tag to 0x04
	// (Comment) — same payload shape (one String), so the decode
	// succeeds structurally and MUST fail on the cell-kind check.
	mut off := -1
	for i in 4 .. bytes.len {
		if bytes[i] == 0x17 {
			off = i
			break
		}
	}
	assert off > 0
	cell_off := off + 1 + 2 + 9 + 9 + 4 + 2
	assert bytes[cell_off] == 0x03, 'first cell tag not at expected offset'
	bytes[cell_off] = 0x04
	if _ := cx.bin_to_doc(bytes) {
		assert false, 'non-Scalar/collection cell node must be rejected'
	} else {
		assert err.msg().contains('cell'), 'reject must name the bad cell kind: ${err.msg()}'
	}
}
