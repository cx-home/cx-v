module cx

// Public surface used by the optional `vcx/arrow/` module
// (libcx_arrow). Core libcx remains Arrow-free; this
// file only exposes existing CXCol primitives via stable names that
// the arrow module can call without reaching into private symbols.
//
// Nothing here changes wire format or alters libcx's published C
// ABI — the symbols below are V-level helpers, not C exports.

// cols_snapshot returns the parsed col-spec for an open
// CxTableReader. The slice is a copy; mutating it doesn't affect
// the reader's internal state.
pub fn (r &CxTableReader) cols_snapshot() []TableColumn {
	mut out := []TableColumn{cap: r.cols.len}
	for c in r.cols {
		out << TableColumn{ name: c.name, type_name: c.type_name }
	}
	return out
}

// col_spec_to_ast_bin_pub builds the framed ast_bin col-spec
// payload that CxTableWriter / CxTableReader exchange at their
// API boundary.
pub fn col_spec_to_ast_bin_pub(cols []TableColumn) []u8 {
	return col_spec_to_ast_bin(cols)
}

// encode_uvarint_pub appends an LEB128-style unsigned varint to
// `buf` per spec/core/data-bin.md §3.2.
pub fn encode_uvarint_pub(mut buf []u8, v u64) {
	encode_uvarint(mut buf, v)
}

// PubBinReader is a thin wrapper over the internal BinReader,
// exposing just enough surface for libcx_arrow's row-group decoder.
pub struct PubBinReader {
mut:
	inner BinReader
}

// new_bin_reader creates a forward-only cursor over `payload`.
pub fn new_bin_reader(payload []u8) PubBinReader {
	return PubBinReader{
		inner: BinReader{
			buf:       payload
			pos:       0
			depth:     0
			max_depth: int(cxcol_default_depth)
		}
	}
}

pub fn (mut r PubBinReader) read_uvarint_pub() !u64 {
	return r.inner.read_uvarint()
}

pub fn (mut r PubBinReader) take_pub(n int) ![]u8 {
	return r.inner.take(n)
}

pub fn (r &PubBinReader) pos() int {
	return r.inner.pos
}

pub fn (r &PubBinReader) remaining() int {
	return r.inner.buf.len - r.inner.pos
}
