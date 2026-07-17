module code

// store_grpc_proto_test.v — proto3 wire codec round-trips + proto3 semantics
// (default fields omitted; unknown fields skipped) for the CXStore gRPC message
// set (#105 2b brick 1). Deterministic, pure — no transport.

fn test_proto_varint_roundtrip() {
	for v in [u64(0), 1, 127, 128, 300, 16384, 0xffffffff, u64(0x7fffffffffffffff)] {
		mut b := []u8{}
		pb_write_varint(mut b, v)
		mut r := PbReader{
			data: b
		}
		got := r.read_varint() or { panic('decode ${v}') }
		assert got == v, 'varint ${v} -> ${got}'
		assert r.eof(), 'varint ${v} left trailing bytes'
	}
}

fn test_get_request_roundtrip() {
	m := GrpcGetRequest{
		store: 'docs'
		hash:  'a'.repeat(64)
	}
	got := pb_decode_get_request(pb_encode_get_request(m)) or { panic('decode') }
	assert got.store == m.store
	assert got.hash == m.hash
}

fn test_put_request_roundtrip_binary_body() {
	// body carries raw bytes incl. a NUL and high bytes — must survive intact.
	body := [u8(0), 1, 2, 255, 254, `[`, `a`, `]`]
	m := GrpcPutRequest{
		store:    'code'
		body:     body
		encoding: 'astbin'
	}
	got := pb_decode_put_request(pb_encode_put_request(m)) or { panic('decode') }
	assert got.store == 'code'
	assert got.body == body
	assert got.encoding == 'astbin'
}

fn test_put_response_bool() {
	a := pb_decode_put_response(pb_encode_put_response(GrpcPutResponse{
		hash:   'h'
		stored: true
	})) or { panic('a') }
	assert a.hash == 'h' && a.stored == true
	b := pb_decode_put_response(pb_encode_put_response(GrpcPutResponse{
		hash:   'h'
		stored: false
	})) or { panic('b') }
	assert b.stored == false
}

fn test_proto3_defaults_omitted_but_decode_to_default() {
	// an all-default message encodes to zero bytes; decoding empty yields defaults.
	enc := pb_encode_get_request(GrpcGetRequest{})
	assert enc.len == 0, 'all-default proto3 message must be empty on the wire'
	got := pb_decode_get_request(enc) or { panic('decode empty') }
	assert got.store == '' && got.hash == ''
}

fn test_doc_and_query_roundtrip() {
	d := pb_decode_doc(pb_encode_doc(GrpcDoc{
		hash:     'abc'
		body:     '[note]'.bytes()
		encoding: 'cxd'
	})) or { panic('doc') }
	assert d.hash == 'abc' && d.body == '[note]'.bytes() && d.encoding == 'cxd'

	q := pb_decode_query_request(pb_encode_query_request(GrpcQueryRequest{
		store: 's'
		query: '//note'.bytes()
	})) or { panic('query') }
	assert q.store == 's' && q.query == '//note'.bytes()

	mod := pb_decode_modify_response(pb_encode_modify_response(GrpcModifyResponse{
		old_hash: 'o'
		new_hash: 'n'
		stored:   true
	})) or { panic('modify') }
	assert mod.old_hash == 'o' && mod.new_hash == 'n' && mod.stored
}

fn test_unknown_field_skipped() {
	// Hand-build a GetRequest body with an EXTRA unknown field (number 5,
	// len-delimited) interleaved — the decoder must skip it and still read store.
	mut b := []u8{}
	pb_write_string(mut b, 1, 'docs') // known: store
	pb_write_string(mut b, 5, 'future-field') // unknown
	pb_write_string(mut b, 2, 'thehash') // known: hash
	got := pb_decode_get_request(b) or { panic('decode with unknown field') }
	assert got.store == 'docs'
	assert got.hash == 'thehash'
}

fn test_truncated_input_errors_not_panics() {
	// a length-delimited field claiming more bytes than present must return none.
	mut b := []u8{}
	pb_write_tag(mut b, 1, pb_wt_len)
	pb_write_varint(mut b, 100) // claims 100 bytes
	b << 'short'.bytes() // only 5
	if _ := pb_decode_get_request(b) {
		assert false, 'truncated input must not decode'
	}
}
