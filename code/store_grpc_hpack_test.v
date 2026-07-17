module code

// store_grpc_hpack_test.v — HPACK core (brick 3b): integer + literal string +
// dynamic table + RFC 7541 Appendix C (literal) examples. Huffman is the next
// sub-brick; here we assert it fails honestly rather than guessing.

fn b(bytes ...u8) []u8 {
	return bytes
}

fn test_hpack_integer_roundtrip() {
	for prefix in [5, 7] {
		for v in [0, 1, 10, 30, 31, 127, 128, 1337, 100000] {
			mut out := []u8{}
			hpack_encode_integer(mut out, v, prefix, 0)
			got, p := hpack_decode_integer(out, 0, prefix) or { panic('decode ${v}/${prefix}') }
			assert got == v, 'int ${v} prefix ${prefix} -> ${got}'
			assert p == out.len
		}
	}
}

// RFC 7541 C.2.4 — Indexed Header Field (:method GET = static index 2 → 0x82).
fn test_hpack_indexed_static() {
	mut d := new_hpack_decoder(4096)
	hs := d.decode(b(0x82)) or { panic('decode') }
	assert hs.len == 1
	assert hs[0].name == ':method' && hs[0].value == 'GET'
}

// RFC 7541 C.2.2 — Literal without Indexing (:path /sample/path).
fn test_hpack_literal_without_indexing() {
	mut block := [u8(0x04), 0x0c] // 0x04 = literal w/o indexing, name index 4 (:path)
	block << '/sample/path'.bytes() // 12 bytes = 0x0c
	mut d := new_hpack_decoder(4096)
	hs := d.decode(block) or { panic('decode') }
	assert hs.len == 1
	assert hs[0].name == ':path' && hs[0].value == '/sample/path'
	assert d.dyn.len == 0, 'literal-without-indexing must not touch the dynamic table'
}

// RFC 7541 C.2.1 — Literal with Incremental Indexing, new name (custom-key:
// custom-header) → also inserted into the dynamic table.
fn test_hpack_literal_incremental_new_name() {
	mut block := [u8(0x40), 0x0a] // literal w/ incremental indexing, name index 0
	block << 'custom-key'.bytes() // 10
	block << u8(0x0d)
	block << 'custom-header'.bytes() // 13
	mut d := new_hpack_decoder(4096)
	hs := d.decode(block) or { panic('decode') }
	assert hs.len == 1
	assert hs[0].name == 'custom-key' && hs[0].value == 'custom-header'
	assert d.dyn.len == 1, 'incremental indexing must insert into the dynamic table'
	// the new entry is now addressable at index 62 (most recent)
	got := d.at(62) or { panic('dyn at 62') }
	assert got.name == 'custom-key' && got.value == 'custom-header'
}

// RFC 7541 C.3.1 — a full (literal, non-Huffman) request header set.
fn test_hpack_full_request_c31() {
	mut block := [u8(0x82), 0x86, 0x84, 0x41, 0x0f] // GET, http, /, :authority(idx1)+literal
	block << 'www.example.com'.bytes() // 15 = 0x0f
	mut d := new_hpack_decoder(4096)
	hs := d.decode(block) or { panic('decode') }
	assert hs.len == 4
	assert hs[0].name == ':method' && hs[0].value == 'GET'
	assert hs[1].name == ':scheme' && hs[1].value == 'http'
	assert hs[2].name == ':path' && hs[2].value == '/'
	assert hs[3].name == ':authority' && hs[3].value == 'www.example.com'
}

fn test_hpack_dynamic_table_eviction() {
	// max_size too small to hold two ~ (10+13+32)=55-byte entries → eviction.
	mut d := new_hpack_decoder(60)
	mut blk1 := [u8(0x40), 0x0a]
	blk1 << 'custom-key'.bytes()
	blk1 << u8(0x0d)
	blk1 << 'custom-header'.bytes()
	d.decode(blk1) or { panic('1') }
	assert d.dyn.len == 1
	// insert a second entry → the first is evicted (table holds only one ~55B entry)
	mut blk2 := [u8(0x40), 0x09]
	blk2 << 'other-key'.bytes() // 9
	blk2 << u8(0x05)
	blk2 << 'other'.bytes() // 5
	d.decode(blk2) or { panic('2') }
	assert d.dyn.len == 1, 'older entry must be evicted; dyn=${d.dyn.len}'
	assert (d.at(62) or { panic('x') }).name == 'other-key'
}

fn test_hpack_encode_roundtrip() {
	headers := [
		HpackHeader{':status', '200'},
		HpackHeader{'content-type', 'application/grpc'},
		HpackHeader{'grpc-status', '0'},
	]
	mut d := new_hpack_decoder(4096)
	got := d.decode(hpack_encode_header_list(headers)) or { panic('decode') }
	assert got.len == 3
	assert got[0].name == ':status' && got[0].value == '200'
	assert got[1].name == 'content-type' && got[1].value == 'application/grpc'
	assert got[2].name == 'grpc-status' && got[2].value == '0'
}

fn test_hpack_huffman_value_decodes() {
	// RFC 7541 C.4.1: literal w/ incremental indexing, name index 1 (:authority),
	// Huffman-coded value (0x8c = H-bit + len 12) "www.example.com".
	mut block := [u8(0x41), 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90,
		0xf4, 0xff]
	mut d := new_hpack_decoder(4096)
	hs := d.decode(block) or { panic('decode huffman header: ${err}') }
	assert hs.len == 1
	assert hs[0].name == ':authority'
	assert hs[0].value == 'www.example.com'
}
