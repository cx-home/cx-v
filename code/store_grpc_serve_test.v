module code

// store_grpc_serve_test.v — gRPC dispatch adapter (brick 4) end-to-end through
// the REAL store pipeline, socket-free: a proto-encoded GrpcCall in → store op →
// proto reply out, proving the transport adapter reuses svc_handle_request with
// no logic duplication. Errors map to gRPC status via the CXER trailer.

fn grpc_test_ctx() (&ServiceState, ServeContext) {
	mut s := new_service_state()
	s.mark_ready()
	ctx := ServeContext{
		mounts: {
			'docs': store_open_impl('mem://grpc-dispatch', '', '', false, true, map[string]string{})
		}
		auth:   AuthContext{} // open (not enforcing) — exercises the dispatch path
	}
	return s, ctx
}

fn grpc_call(method string, msg []u8) GrpcCall {
	return GrpcCall{
		stream_id: 1
		headers:   {
			':path':        '/cxstore.v1.CxStore/${method}'
			'content-type': 'application/grpc'
		}
		message:   msg
	}
}

fn test_grpc_dispatch_put_get_list_delete() {
	mut s, ctx := grpc_test_ctx()

	// Put
	put_reply := grpc_dispatch(grpc_call('Put', pb_encode_put_request(GrpcPutRequest{
		store:    'docs'
		body:     '[note [body "grpc-roundtrip"]]'.bytes()
		encoding: 'cxd'
	})), mut s, ctx)
	assert put_reply.status.code == grpc_ok, 'put status ${put_reply.status.code} ${put_reply.status.message}'
	assert put_reply.frames.len == 1
	pr := pb_decode_put_response(put_reply.frames[0]) or { panic('decode put resp') }
	assert pr.hash.len == 64, 'put hash not 64-hex: ${pr.hash}'
	hash := pr.hash

	// Get
	get_reply := grpc_dispatch(grpc_call('Get', pb_encode_get_request(GrpcGetRequest{
		store: 'docs'
		hash:  hash
	})), mut s, ctx)
	assert get_reply.status.code == grpc_ok
	gr := pb_decode_get_response(get_reply.frames[0]) or { panic('decode get resp') }
	assert gr.body.bytestr().contains('grpc-roundtrip'), 'doc did not round-trip: ${gr.body.bytestr()}'

	// List → one HashItem frame carrying the hash
	list_reply := grpc_dispatch(grpc_call('List', pb_encode_store_request(GrpcStoreRequest{
		store: 'docs'
	})), mut s, ctx)
	assert list_reply.status.code == grpc_ok
	assert list_reply.frames.len == 1, 'list should stream exactly one HashItem'
	hi := pb_decode_hash_item(list_reply.frames[0]) or { panic('decode hashitem') }
	assert hi.hash == hash

	// Delete
	del_reply := grpc_dispatch(grpc_call('Delete', pb_encode_delete_request(GrpcDeleteRequest{
		store: 'docs'
		hash:  hash
	})), mut s, ctx)
	assert del_reply.status.code == grpc_ok
	dr := pb_decode_delete_response(del_reply.frames[0]) or { panic('decode delete resp') }
	assert dr.deleted, 'delete should report true'
}

fn test_grpc_dispatch_missing_hash_maps_to_not_found() {
	mut s, ctx := grpc_test_ctx()
	reply := grpc_dispatch(grpc_call('Get', pb_encode_get_request(GrpcGetRequest{
		store: 'docs'
		hash:  '0'.repeat(64)
	})), mut s, ctx)
	// CSRP 404 CXER1721 → gRPC NOT_FOUND (5).
	assert reply.status.code == grpc_not_found, 'missing hash → ${reply.status.code}, want ${grpc_not_found}'
	assert reply.frames.len == 0
}

fn test_grpc_dispatch_query_streams_one_row_per_match() {
	mut s, ctx := grpc_test_ctx()

	// Put two docs, one with a [title], one without.
	grpc_dispatch(grpc_call('Put', pb_encode_put_request(GrpcPutRequest{
		store: 'docs'
		body:  '[note [title "grpc-query-hit"] [body "b"]]'.bytes()
	})), mut s, ctx)
	grpc_dispatch(grpc_call('Put', pb_encode_put_request(GrpcPutRequest{
		store: 'docs'
		body:  '[note [body "no-title-here"]]'.bytes()
	})), mut s, ctx)

	// Query //title — exactly one doc matches → one QueryRow frame.
	reply := grpc_dispatch(grpc_call('Query', pb_encode_query_request(GrpcQueryRequest{
		store: 'docs'
		query: '//title'.bytes()
	})), mut s, ctx)
	assert reply.status.code == grpc_ok, 'query status ${reply.status.code} ${reply.status.message}'
	assert reply.frames.len == 1, 'query //title should stream exactly one QueryRow, got ${reply.frames.len}'
	row := pb_decode_query_row(reply.frames[0]) or { panic('decode query row') }
	assert row.encoding == 'cxd'
	// The row carries the matching doc's hash + the matched [title] element.
	assert row.row.bytestr().contains('grpc-query-hit'), 'query row must carry the matched [title]: ${row.row.bytestr()}'
}

fn test_grpc_dispatch_query_empty_is_ok_zero_rows() {
	mut s, ctx := grpc_test_ctx()
	grpc_dispatch(grpc_call('Put', pb_encode_put_request(GrpcPutRequest{
		store: 'docs'
		body:  '[note [body "no-match"]]'.bytes()
	})), mut s, ctx)
	reply := grpc_dispatch(grpc_call('Query', pb_encode_query_request(GrpcQueryRequest{
		store: 'docs'
		query: '//absent'.bytes()
	})), mut s, ctx)
	// No matches is a SUCCESS with zero rows — distinct from an error / UNIMPLEMENTED.
	assert reply.status.code == grpc_ok, 'empty query → ${reply.status.code}, want OK'
	assert reply.frames.len == 0, 'no matches → zero QueryRow frames, got ${reply.frames.len}'
}

fn test_grpc_dispatch_iter_streams_one_doc_per_stored() {
	mut s, ctx := grpc_test_ctx()
	grpc_dispatch(grpc_call('Put', pb_encode_put_request(GrpcPutRequest{
		store: 'docs'
		body:  '[note [body "grpc-iter-alpha"]]'.bytes()
	})), mut s, ctx)
	grpc_dispatch(grpc_call('Put', pb_encode_put_request(GrpcPutRequest{
		store: 'docs'
		body:  '[note [body "grpc-iter-beta"]]'.bytes()
	})), mut s, ctx)

	reply := grpc_dispatch(grpc_call('Iter', pb_encode_store_request(GrpcStoreRequest{
		store: 'docs'
	})), mut s, ctx)
	assert reply.status.code == grpc_ok, 'iter status ${reply.status.code} ${reply.status.message}'
	assert reply.frames.len == 2, 'iter should stream exactly two Doc frames, got ${reply.frames.len}'
	mut bodies := ''
	for f in reply.frames {
		d := pb_decode_doc(f) or { panic('decode doc') }
		assert d.hash.len == 64, 'iter doc hash not 64-hex: ${d.hash}'
		assert d.encoding == 'cxd'
		bodies += d.body.bytestr()
	}
	assert bodies.contains('grpc-iter-alpha') && bodies.contains('grpc-iter-beta'), 'both docs must stream over iter: ${bodies}'
}

fn test_grpc_dispatch_modify_yields_new_content_address() {
	mut s, ctx := grpc_test_ctx()
	put := grpc_dispatch(grpc_call('Put', pb_encode_put_request(GrpcPutRequest{
		store: 'docs'
		body:  '[note [body "pre-grpc-modify"]]'.bytes()
	})), mut s, ctx)
	src := (pb_decode_put_response(put.frames[0]) or { panic('decode put') }).hash

	reply := grpc_dispatch(grpc_call('Modify', pb_encode_modify_request(GrpcModifyRequest{
		store:  'docs'
		hash:   src
		action: '[set-attr name=tag value="GRPC-MODIFIED"]'.bytes()
	})), mut s, ctx)
	assert reply.status.code == grpc_ok, 'modify status ${reply.status.code} ${reply.status.message}'
	mr := pb_decode_modify_response(reply.frames[0]) or { panic('decode modify resp') }
	assert mr.old_hash == src, 'modify old-hash should echo the source: ${mr.old_hash} vs ${src}'
	assert mr.new_hash.len == 64 && mr.new_hash != src, 'modify must yield a NEW content-address: ${mr.new_hash}'
	assert mr.stored, 'modify should report stored=true'

	// The modified doc is fetchable by its new hash and carries the modification.
	got := grpc_dispatch(grpc_call('Get', pb_encode_get_request(GrpcGetRequest{
		store: 'docs'
		hash:  mr.new_hash
	})), mut s, ctx)
	gr := pb_decode_get_response(got.frames[0]) or { panic('decode get') }
	assert gr.body.bytestr().contains('GRPC-MODIFIED'), 'modified doc must carry the set-attr: ${gr.body.bytestr()}'
}

fn test_grpc_dispatch_modify_missing_source_is_not_found() {
	mut s, ctx := grpc_test_ctx()
	reply := grpc_dispatch(grpc_call('Modify', pb_encode_modify_request(GrpcModifyRequest{
		store:  'docs'
		hash:   '0'.repeat(64)
		action: '[set-attr name=x value="y"]'.bytes()
	})), mut s, ctx)
	// CSRP 404 CXER1121 → gRPC NOT_FOUND (5).
	assert reply.status.code == grpc_not_found, 'modify of a missing source → ${reply.status.code}, want ${grpc_not_found}'
}

fn test_grpc_dispatch_unknown_method_is_unimplemented() {
	mut s, ctx := grpc_test_ctx()
	// A genuinely unknown gRPC method (not in the CxStore service) → UNIMPLEMENTED.
	reply := grpc_dispatch(grpc_call('Frobnicate', []u8{}), mut s, ctx)
	assert reply.status.code == 12, 'an unknown method must be UNIMPLEMENTED, got ${reply.status.code}'
}
