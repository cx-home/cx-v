module code

// store_grpc_hpack.v — HPACK header compression (RFC 7541) for the HTTP/2 gRPC
// transport (#105 sub-area 2b, brick 3b). Core layer: the static table, the
// integer + string primitives, the dynamic table (with RFC §4.1 size accounting
// + eviction), header-block DECODE across all five representations, and a
// header-list ENCODE. Huffman-coded string values (the H bit) are handled by the
// companion Huffman decoder (hpack_huffman_decode); a build without it errors
// honestly rather than mis-reading a header.

pub struct HpackHeader {
pub:
	name  string
	value string
}

// hpack_static_table — RFC 7541 Appendix A (index 1..61). Index 0 is invalid.
const hpack_static_table = [
	HpackHeader{':authority', ''},
	HpackHeader{':method', 'GET'},
	HpackHeader{':method', 'POST'},
	HpackHeader{':path', '/'},
	HpackHeader{':path', '/index.html'},
	HpackHeader{':scheme', 'http'},
	HpackHeader{':scheme', 'https'},
	HpackHeader{':status', '200'},
	HpackHeader{':status', '204'},
	HpackHeader{':status', '206'},
	HpackHeader{':status', '304'},
	HpackHeader{':status', '400'},
	HpackHeader{':status', '404'},
	HpackHeader{':status', '500'},
	HpackHeader{'accept-charset', ''},
	HpackHeader{'accept-encoding', 'gzip, deflate'},
	HpackHeader{'accept-language', ''},
	HpackHeader{'accept-ranges', ''},
	HpackHeader{'accept', ''},
	HpackHeader{'access-control-allow-origin', ''},
	HpackHeader{'age', ''},
	HpackHeader{'allow', ''},
	HpackHeader{'authorization', ''},
	HpackHeader{'cache-control', ''},
	HpackHeader{'content-disposition', ''},
	HpackHeader{'content-encoding', ''},
	HpackHeader{'content-language', ''},
	HpackHeader{'content-length', ''},
	HpackHeader{'content-location', ''},
	HpackHeader{'content-range', ''},
	HpackHeader{'content-type', ''},
	HpackHeader{'cookie', ''},
	HpackHeader{'date', ''},
	HpackHeader{'etag', ''},
	HpackHeader{'expect', ''},
	HpackHeader{'expires', ''},
	HpackHeader{'from', ''},
	HpackHeader{'host', ''},
	HpackHeader{'if-match', ''},
	HpackHeader{'if-modified-since', ''},
	HpackHeader{'if-none-match', ''},
	HpackHeader{'if-range', ''},
	HpackHeader{'if-unmodified-since', ''},
	HpackHeader{'last-modified', ''},
	HpackHeader{'link', ''},
	HpackHeader{'location', ''},
	HpackHeader{'max-forwards', ''},
	HpackHeader{'proxy-authenticate', ''},
	HpackHeader{'proxy-authorization', ''},
	HpackHeader{'range', ''},
	HpackHeader{'referer', ''},
	HpackHeader{'refresh', ''},
	HpackHeader{'retry-after', ''},
	HpackHeader{'server', ''},
	HpackHeader{'set-cookie', ''},
	HpackHeader{'strict-transport-security', ''},
	HpackHeader{'transfer-encoding', ''},
	HpackHeader{'user-agent', ''},
	HpackHeader{'vary', ''},
	HpackHeader{'via', ''},
	HpackHeader{'www-authenticate', ''},
]

// ── integer primitive (RFC 7541 §5.1) ────────────────────────────────────────

// hpack_decode_integer reads an N-bit-prefix integer starting at data[pos]; the
// prefix occupies the low `prefix_bits` of data[pos]. Returns (value, new_pos).
fn hpack_decode_integer(data []u8, pos int, prefix_bits int) ?(int, int) {
	if pos >= data.len {
		return none
	}
	max_prefix := (1 << prefix_bits) - 1
	mut value := int(data[pos]) & max_prefix
	mut p := pos + 1
	if value < max_prefix {
		return value, p
	}
	mut m := 0
	for {
		if p >= data.len {
			return none
		}
		b := data[p]
		p++
		value += int(u32(b & 0x7f) << u32(m))
		m += 7
		if b & 0x80 == 0 {
			break
		}
		if m > 28 {
			return none // guard against overlong / overflow
		}
	}
	return value, p
}

// hpack_encode_integer appends an N-bit-prefix integer; `first_byte_high` holds
// the bits above the prefix in the first octet (e.g. a representation pattern).
fn hpack_encode_integer(mut out []u8, value int, prefix_bits int, first_byte_high u8) {
	max_prefix := (1 << prefix_bits) - 1
	if value < max_prefix {
		out << first_byte_high | u8(value)
		return
	}
	out << first_byte_high | u8(max_prefix)
	mut v := value - max_prefix
	for v >= 0x80 {
		out << u8((v & 0x7f) | 0x80)
		v >>= 7
	}
	out << u8(v)
}

// ── string primitive (RFC 7541 §5.2) ─────────────────────────────────────────

fn hpack_decode_string(data []u8, pos int) ?(string, int) {
	if pos >= data.len {
		return none
	}
	huffman := data[pos] & 0x80 != 0
	length, p := hpack_decode_integer(data, pos, 7)?
	if length < 0 || p + length > data.len {
		return none
	}
	raw := data[p..p + length]
	if huffman {
		decoded := hpack_huffman_decode(raw)?
		return decoded, p + length
	}
	return raw.bytestr(), p + length
}

// hpack_encode_string appends a length-prefixed literal (never Huffman — valid
// per RFC §5.2; the server does not compress its emitted header values).
fn hpack_encode_string(mut out []u8, s string) {
	hpack_encode_integer(mut out, s.len, 7, 0) // H bit 0
	out << s.bytes()
}

// ── decoder (dynamic table + header block) ────────────────────────────────────

pub struct HpackDecoder {
mut:
	dyn      []HpackHeader // most-recent first
	size     int           // current dynamic-table size (RFC §4.1)
	max_size int = 4096     // SETTINGS_HEADER_TABLE_SIZE default
}

pub fn new_hpack_decoder(max_size int) HpackDecoder {
	return HpackDecoder{
		max_size: max_size
	}
}

fn hpack_entry_size(h HpackHeader) int {
	return h.name.len + h.value.len + 32 // RFC §4.1
}

fn (mut d HpackDecoder) insert(h HpackHeader) {
	d.dyn.prepend(h)
	d.size += hpack_entry_size(h)
	d.evict()
}

fn (mut d HpackDecoder) evict() {
	for d.size > d.max_size && d.dyn.len > 0 {
		last := d.dyn.last()
		d.size -= hpack_entry_size(last)
		d.dyn.delete_last()
	}
}

fn (mut d HpackDecoder) set_max_size(n int) {
	d.max_size = n
	d.evict()
}

// at resolves an HPACK index: 1..61 static, 62.. dynamic (62 = most recent).
fn (d &HpackDecoder) at(index int) ?HpackHeader {
	if index <= 0 {
		return none
	}
	if index <= hpack_static_table.len {
		return hpack_static_table[index - 1]
	}
	di := index - hpack_static_table.len - 1
	if di < 0 || di >= d.dyn.len {
		return none
	}
	return d.dyn[di]
}

// decode expands one HEADERS/CONTINUATION header block into a header list.
pub fn (mut d HpackDecoder) decode(block []u8) ?[]HpackHeader {
	mut out := []HpackHeader{}
	mut pos := 0
	for pos < block.len {
		b := block[pos]
		if b & 0x80 != 0 {
			// 6.1 Indexed Header Field (1xxxxxxx)
			index, p := hpack_decode_integer(block, pos, 7)?
			out << d.at(index)?
			pos = p
		} else if b & 0x40 != 0 {
			// 6.2.1 Literal with Incremental Indexing (01xxxxxx)
			name_index, p := hpack_decode_integer(block, pos, 6)?
			h := d.read_literal(block, p, name_index)?
			out << h.header
			d.insert(h.header)
			pos = h.pos
		} else if b & 0x20 != 0 {
			// 6.3 Dynamic Table Size Update (001xxxxx)
			new_max, p := hpack_decode_integer(block, pos, 5)?
			d.set_max_size(new_max)
			pos = p
		} else {
			// 6.2.2 / 6.2.3 Literal without Indexing / Never Indexed (0000/0001 xxxx)
			name_index, p := hpack_decode_integer(block, pos, 4)?
			h := d.read_literal(block, p, name_index)?
			out << h.header
			pos = h.pos
		}
	}
	return out
}

struct HpackLiteral {
	header HpackHeader
	pos    int
}

// read_literal reads a literal representation's name (indexed or inline) + value
// starting at `pos` (just past the integer-encoded name index).
fn (d &HpackDecoder) read_literal(block []u8, pos int, name_index int) ?HpackLiteral {
	mut p := pos
	mut name := ''
	if name_index == 0 {
		name, p = hpack_decode_string(block, p)?
	} else {
		name = (d.at(name_index)?).name
	}
	value, p2 := hpack_decode_string(block, p)?
	return HpackLiteral{
		header: HpackHeader{
			name:  name
			value: value
		}
		pos: p2
	}
}

// ── encoder (server responses / trailers) ─────────────────────────────────────

// hpack_encode_header_list encodes headers as Literal-without-Indexing with
// literal (non-Huffman) names + values (RFC §6.2.2). Valid + decoder-agnostic;
// the server keeps no encoder dynamic table (simplicity > a few bytes).
pub fn hpack_encode_header_list(headers []HpackHeader) []u8 {
	mut out := []u8{}
	for h in headers {
		out << u8(0x00) // 0000_0000: literal w/o indexing, new name
		hpack_encode_string(mut out, h.name)
		hpack_encode_string(mut out, h.value)
	}
	return out
}
