@[has_globals]
module platform

// store_grpc_huffman.v — HPACK Huffman decoding (RFC 7541 §5.2 + Appendix B),
// companion to store_grpc_hpack.v (#105 sub-area 2b, brick 3b). The canonical
// 256-symbol code table (Appendix B; EOS=256 is intentionally NOT a decodable
// symbol — encountering it, or any invalid/over-long trailing code, is an
// error). Decoding walks a prefix trie built once from the table; per RFC §5.2
// the trailing padding must be the most-significant bits of the EOS code (all
// 1s) and at most 7 bits — anything else is a decoding error.

// hpack_huff_code / hpack_huff_nbits — RFC 7541 Appendix B, symbols 0..255.
// Laid out 16 symbols per line (so each line is symbols 16*k .. 16*k+15) — the
// alignment is the load-bearing invariant, validated structurally by the
// prefix-free/complete trie test + the RFC C.4/C.6 decode examples.
const hpack_huff_code = [u32(0x1ff8), 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7, 0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec, // 0-15
	0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3, 0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb, // 16-31
	0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa, 0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18, // 32-47
	0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb, 0x3fc, // 48-63
	0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, // 64-79
	0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0, 0x1ffc, 0x3ffc, 0x22, // 80-95
	0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26, 0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x7, // 96-111
	0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7ffe, 0x7fc, 0x3ffd, 0x1ffd, 0xffffffc, // 112-127
	0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9, 0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf, // 128-143
	0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3, 0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef, // 144-159
	0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde, 0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec, // 160-175
	0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef, 0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1, // 176-191
	0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec, 0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5, 0xfffff1, 0x1ffffed, // 192-207
	0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7, 0x7ffffe2, 0xfffff2, 0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5, // 208-223
	0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3, 0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4, // 224-239
	0x3ffffeb, 0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea, 0x7ffffeb, 0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee] // 240-255

const hpack_huff_nbits = [13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, // 0-15
	28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28, // 16-31
	6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, // 32-47
	5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, // 48-63
	13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, // 64-79
	7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, // 80-95
	15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, // 96-111
	6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, // 112-127
	20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23, // 128-143
	24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, // 144-159
	22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, // 160-175
	21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23, // 176-191
	26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, // 192-207
	19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, // 208-223
	20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23, // 224-239
	26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26] // 240-255

struct HuffNode {
mut:
	child [2]int // child trie-node index per bit, or -1
	sym   int     // decoded symbol at a leaf, or -1 for an internal node
}

struct HuffTrie {
mut:
	nodes []HuffNode
}

__global (
	g_hpack_huff voidptr
)

// hpack_huff_trie builds (once) and returns the decode trie. Call
// hpack_huffman_init() before concurrent use so the lazy build happens on one
// thread (the gRPC listener does this at startup) — mirrors store_reg().
fn hpack_huff_trie() &HuffTrie {
	if g_hpack_huff == unsafe { nil } {
		mut t := &HuffTrie{
			nodes: [HuffNode{
				child: [-1, -1]!
				sym:   -1
			}] // root at index 0
		}
		for sym in 0 .. 256 {
			codeword := hpack_huff_code[sym]
			n := hpack_huff_nbits[sym]
			mut node := 0
			for i := n - 1; i >= 0; i-- {
				bit := int((codeword >> u32(i)) & 1)
				if t.nodes[node].child[bit] == -1 {
					t.nodes << HuffNode{
						child: [-1, -1]!
						sym:   -1
					}
					t.nodes[node].child[bit] = t.nodes.len - 1
				}
				node = t.nodes[node].child[bit]
			}
			t.nodes[node].sym = sym
		}
		g_hpack_huff = voidptr(t)
	}
	return unsafe { &HuffTrie(g_hpack_huff) }
}

// hpack_huffman_init forces the one-time trie build (call before spawning gRPC
// connection threads, so the lazy init never races).
pub fn hpack_huffman_init() {
	hpack_huff_trie()
}

// hpack_huffman_decode expands an HPACK Huffman-coded octet string. Returns none
// on a decoding error (an EOS symbol in the data, a code that walks off the
// table, or padding that is not ≤7 most-significant EOS bits).
fn hpack_huffman_decode(data []u8) ?string {
	if data.len == 0 {
		return ''
	}
	t := hpack_huff_trie()
	mut out := []u8{}
	mut node := 0
	mut cur_bits := 0
	mut cur_all_ones := true
	for octet in data {
		for bitpos := 7; bitpos >= 0; bitpos-- {
			bit := int((octet >> u8(bitpos)) & 1)
			node = t.nodes[node].child[bit]
			cur_bits++
			if bit == 0 {
				cur_all_ones = false
			}
			if node == -1 {
				return none // code walked off the table (incl. an EOS prefix)
			}
			if t.nodes[node].sym >= 0 {
				out << u8(t.nodes[node].sym)
				node = 0
				cur_bits = 0
				cur_all_ones = true
			}
		}
	}
	// trailing bits (if any) must be valid EOS-prefix padding: ≤7 bits, all ones.
	if node != 0 {
		if cur_bits > 7 || !cur_all_ones {
			return none
		}
	}
	return out.bytestr()
}
