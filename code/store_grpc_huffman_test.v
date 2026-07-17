module code

// store_grpc_huffman_test.v — HPACK Huffman decode (brick 3b-huffman) validated
// against the RFC 7541 Appendix C.4/C.6 examples (canonical byte sequences →
// exact strings) plus a structural prefix-free / completeness check of the trie.

fn hb(bytes ...u8) []u8 {
	return bytes
}

// The trie must be a complete, prefix-free code: exactly 256 leaves, and no
// symbol node also has children (no code is a prefix of another). This catches
// any table transcription collision regardless of the example coverage.
fn huff_first_descendant_sym(nodes []HuffNode, start int) int {
	mut stack := [start]
	for stack.len > 0 {
		i := stack.pop()
		for b in 0 .. 2 {
			c := nodes[i].child[b]
			if c != -1 {
				if nodes[c].sym >= 0 {
					return nodes[c].sym
				}
				stack << c
			}
		}
	}
	return -1
}

fn test_huffman_trie_prefix_free_and_complete() {
	t := hpack_huff_trie()
	mut leaves := 0
	for idx, n in t.nodes {
		if n.sym >= 0 {
			leaves++
			if n.child[0] != -1 || n.child[1] != -1 {
				desc := huff_first_descendant_sym(t.nodes, idx)
				assert false, 'sym ${n.sym} (code 0x${hpack_huff_code[n.sym].hex()}/${hpack_huff_nbits[n.sym]}) is a prefix of sym ${desc} (code 0x${hpack_huff_code[desc].hex()}/${hpack_huff_nbits[desc]})'
			}
		}
	}
	assert leaves == 256, 'expected 256 symbols, got ${leaves}'
}

fn test_huffman_rfc_c4_examples() {
	// C.4.1 — "www.example.com"
	assert hpack_huffman_decode(hb(0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90,
		0xf4, 0xff))? == 'www.example.com'
	// C.4.2 — "no-cache"
	assert hpack_huffman_decode(hb(0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf))? == 'no-cache'
	// C.4.3 — "custom-key" / "custom-value"
	assert hpack_huffman_decode(hb(0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f))? == 'custom-key'
	assert hpack_huffman_decode(hb(0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf))? == 'custom-value'
}

fn test_huffman_rfc_c6_examples() {
	// C.6.1 response field values
	assert hpack_huffman_decode(hb(0x64, 0x02))? == '302'
	assert hpack_huffman_decode(hb(0xae, 0xc3, 0x77, 0x1a, 0x4b))? == 'private'
	assert hpack_huffman_decode(hb(0x9d, 0x29, 0xad, 0x17, 0x18, 0x63, 0xc7, 0x8f, 0x0b, 0x97,
		0xc8, 0xe9, 0xae, 0x82, 0xae, 0x43, 0xd3))? == 'https://www.example.com'
	// the C.6.1 date value
	assert hpack_huffman_decode(hb(0xd0, 0x7a, 0xbe, 0x94, 0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20,
		0x05, 0x95, 0x04, 0x0b, 0x81, 0x66, 0xe0, 0x82, 0xa6, 0x2d, 0x1b, 0xff))? == 'Mon, 21 Oct 2013 20:13:21 GMT'
}

fn test_huffman_empty() {
	assert hpack_huffman_decode([]u8{})? == ''
}

fn test_huffman_invalid_padding_errors() {
	// all-zero bytes are not valid EOS padding (padding must be 1-bits) → error.
	if _ := hpack_huffman_decode(hb(0x00)) {
		assert false, 'zero padding must not decode'
	}
	// a full byte of 1s is >7 bits of padding → error.
	if _ := hpack_huffman_decode(hb(0xff, 0xff, 0xff, 0xff)) {
		assert false, 'over-long all-ones (EOS-ish) must not decode'
	}
}
