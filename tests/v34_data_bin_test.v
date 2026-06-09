module main

import cx

// Round-trip tests for CXCol v1: cx -> emit_data_bin -> parse_data_bin
// -> emit_cx -> equivalent shape. Spec: spec/core/data-bin.md.

// ── Header ───────────────────────────────────────────────────────────────────

fn test_data_bin_emits_magic_and_version() {
	doc := cx.parse('[a]') or { panic(err) }
	bytes := cx.emit_data_bin(doc)
	// Frame: [u32 LE size][CXCol ...].
	assert bytes.len >= 16, 'expected at least header + framing; got ${bytes.len}'
	// Bytes 4..9 = 5-byte magic "CXCol" (spec/core/data-bin.md §3.1).
	assert bytes[4] == 0x43 && bytes[5] == 0x58 && bytes[6] == 0x43
		&& bytes[7] == 0x6F && bytes[8] == 0x6C
	// Byte 9 = version 0x01
	assert bytes[9] == 0x01
}

// ── Round-trip: scalars and shape ────────────────────────────────────────────

fn test_data_bin_round_trip_int_attrs() {
	doc := cx.parse('[server host=localhost port=8080 active=true]') or { panic(err) }
	bytes := cx.emit_data_bin(doc)
	doc2 := cx.parse_data_bin(bytes) or { panic('decode failed: ${err}') }
	root := doc2.root() or { panic('no root after round-trip') }
	assert root.name == 'server'
	assert root.attr('host') == 'localhost'
	assert root.attr('port') == '8080'
	assert root.attr('active') == 'true'
}

fn test_data_bin_preserves_int_type() {
	doc := cx.parse('[count 42]') or { panic(err) }
	bytes := cx.emit_data_bin(doc)
	doc2 := cx.parse_data_bin(bytes) or { panic(err) }
	root := doc2.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is i64 { assert s == 42 } else { assert false, 'expected i64 after round-trip' }
}

fn test_data_bin_preserves_float_type() {
	doc := cx.parse('[ratio 1.5]') or { panic(err) }
	bytes := cx.emit_data_bin(doc)
	doc2 := cx.parse_data_bin(bytes) or { panic(err) }
	root := doc2.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is f64 { assert s == 1.5 } else { assert false, 'expected f64 after round-trip' }
}

fn test_data_bin_preserves_bool() {
	doc := cx.parse('[flag true]') or { panic(err) }
	bytes := cx.emit_data_bin(doc)
	doc2 := cx.parse_data_bin(bytes) or { panic(err) }
	root := doc2.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is bool { assert s == true } else { assert false, 'expected bool after round-trip' }
}

fn test_data_bin_preserves_null() {
	doc := cx.parse('[empty null]') or { panic(err) }
	bytes := cx.emit_data_bin(doc)
	doc2 := cx.parse_data_bin(bytes) or { panic(err) }
	root := doc2.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	assert s is cx.NullValue
}

// ── Narrowest int tag selection ──────────────────────────────────────────────

fn test_data_bin_small_int_uses_int8_tag() {
	doc := cx.parse('[x 42]') or { panic(err) }
	bytes := cx.emit_data_bin(doc)
	// After header (12 bytes) + 4-byte frame prefix + map tag (1) +
	// uvarint count (1) + string tag (1) + string len (1) + 'x' (1)
	// = byte index 21 should be the int8 tag (0x10) for value 42.
	// We don't assert exact offset but verify int8 tag (0x10) is in
	// the encoded bytes and int64 tag (0x13) is NOT.
	mut has_int8 := false
	mut has_int64 := false
	for b in bytes[16..] {
		if b == 0x10 { has_int8 = true }
		if b == 0x13 { has_int64 = true }
	}
	assert has_int8, 'small int (42) should use int8 tag (0x10) for canonical encoding'
	assert !has_int64, 'small int should NOT use int64 tag — must pick narrowest'
}

fn test_data_bin_large_int_uses_int64_tag() {
	doc := cx.parse('[x 9999999999]') or { panic(err) }
	bytes := cx.emit_data_bin(doc)
	mut has_int64 := false
	for b in bytes[16..] {
		if b == 0x13 { has_int64 = true }
	}
	assert has_int64, 'large int (>i32) should use int64 tag'
}

// ── Empty container variants ─────────────────────────────────────────────────

fn test_data_bin_empty_element_emits_null_value() {
	// `[empty]` is an Element with no attributes and no body. The
	// semantic-data projection (vcx/cx/data_bin.v::element_to_dataval)
	// returns DataNull in this case, which encodes as the null tag
	// (0x00) at the value position of the parent map entry. The
	// empty-map tag (0x51) is reserved for explicit empty maps in
	// the wire format and is NOT produced by natural CX text — this
	// test pins the current "empty Element → null value" rule that
	// `cx_from_data_bin` round-trips against.
	doc := cx.parse('[empty]') or { panic(err) }
	bytes := cx.emit_data_bin(doc)
	// Value position: the byte after the key string ('empty' = 5
	// bytes preceded by string-tag 0x30 + length byte 0x05) within
	// the top-level map (0x50, count varint 0x01).
	// Expected layout from byte 16 (post-header):
	//   0x50 0x01 0x30 0x05 'e' 'm' 'p' 't' 'y' <value-tag>
	value_tag := bytes[16 + 9]
	assert value_tag == 0x00, 'expected null tag (0x00) at value position, got 0x${value_tag:02x}'

	// And the round-trip preserves the empty Element identity.
	doc2 := cx.parse_data_bin(bytes) or { panic(err) }
	root := doc2.root() or { panic('no root after round-trip') }
	assert root.name == 'empty'
	assert root.attrs.len == 0
}

// ── Round-trip: containers ───────────────────────────────────────────────────

fn test_data_bin_round_trip_array() {
	doc := cx.parse('[ports 8080 8081 8082]') or { panic(err) }
	bytes := cx.emit_data_bin(doc)
	doc2 := cx.parse_data_bin(bytes) or { panic(err) }
	root := doc2.root() or { panic('no root') }
	assert root.items.len == 3
}

fn test_data_bin_round_trip_nested_map() {
	doc := cx.parse('[server [host=localhost port=8080]]') or { panic(err) }
	bytes := cx.emit_data_bin(doc)
	doc2 := cx.parse_data_bin(bytes) or { panic(err) }
	root := doc2.root() or { panic('no root') }
	assert root.name == 'server'
}

// ── Round-trip: tables ───────────────────────────────────────────────────────

fn test_data_bin_round_trip_table() {
	src := '[users [table[name::string age::int]]
  alice 30
  bob 25
]'
	doc := cx.parse(src) or { panic(err) }
	bytes := cx.emit_data_bin(doc)
	doc2 := cx.parse_data_bin(bytes) or { panic(err) }
	root := doc2.root() or { panic('no root') }
	t := root.table_opt() or { panic('table data lost on data_bin round-trip') }
	assert t.cols.len == 2
	assert t.rows.len == 2
	assert t.cols[0].name == 'name'
	assert t.cols[1].name == 'age'
}

// ── Decoder rejects invalid input ────────────────────────────────────────────

fn test_data_bin_rejects_bad_magic() {
	mut bytes := []u8{len: 16}
	// Frame size = 12, valid prefix.
	bytes[0] = 12
	bytes[1] = 0
	bytes[2] = 0
	bytes[3] = 0
	// Invalid magic.
	bytes[4] = 0x42
	bytes[5] = 0x42
	bytes[6] = 0x42
	bytes[7] = 0x42
	if _ := cx.parse_data_bin(bytes) {
		assert false, 'decoder should reject bad magic'
	} else {
		assert err.msg().contains('magic'), 'expected magic-related error, got: ${err.msg()}'
	}
}

fn test_data_bin_rejects_truncated_size_header() {
	bytes := [u8(0x01), 0x00]  // only 2 bytes, less than the 4-byte size prefix
	if _ := cx.parse_data_bin(bytes) {
		assert false, 'decoder should reject truncated input'
	} else {
		assert err.msg().contains('short')
	}
}

// ── Idempotent canonical form ────────────────────────────────────────────────

fn test_data_bin_idempotent() {
	doc := cx.parse('[server host=localhost port=8080]') or { panic(err) }
	a := cx.emit_data_bin(doc)
	b := cx.emit_data_bin(doc)
	assert a == b, 'emit_data_bin must be deterministic for the same input'
}