module code

// store_otel_e2_test.v — #129 PR-B item 6 (E2 full OTel): the two completeness gaps that
// made the object wire fully observable. (1) the gRPC adapter forwards an inbound W3C
// `traceparent` so a gRPC hop CONTINUES the distributed trace (not a fresh root); (2) the
// object-wire verbs are first-class bounded-cardinality endpoints (metrics + span names),
// not collapsed to `_other`.

fn test_grpc_synth_forwards_traceparent() {
	tp := '00-${'0'.repeat(31)}1-${'0'.repeat(15)}1-01'
	req := grpc_synth_req('objects-put', 't', '[put]', map[string]string{}, '', tp)
	// the synthesized CSRP-equivalent request must carry the traceparent header so the
	// shared pipeline (svc_trace_for_request) continues the inbound trace.
	got := svc_request_header(req, 'traceparent')
	assert got == tp, 'grpc_synth_req must forward the inbound traceparent: ${got}'
	tc := svc_trace_for_request(req, false)
	assert tc.trace_id == '${'0'.repeat(31)}1', 'gRPC hop must continue the inbound trace-id: ${tc.trace_id}'
	assert tc.parent_id == '${'0'.repeat(15)}1', 'the inbound span becomes this span\'s parent'
	assert tc.span_id.len == 16 && tc.span_id != tc.parent_id, 'a fresh server span-id is minted'
}

fn test_grpc_synth_no_traceparent_is_root() {
	// no inbound traceparent → a fresh ROOT trace (no parent), ids still minted.
	req := grpc_synth_req('get', 't', '', {
		'hash': 'h'
	}, '', '')
	assert svc_request_header(req, 'traceparent') == '', 'no traceparent header when none inbound'
	tc := svc_trace_for_request(req, false)
	assert tc.trace_id.len == 32 && !obs_all_zero_hex(tc.trace_id), 'a root trace-id is minted'
	assert tc.parent_id == '', 'a root span has no parent'
}

fn test_object_wire_endpoints_are_observable() {
	// the #129 object wire must be observable per-verb (bounded cardinality), not _other.
	for ep in ['objects-have', 'objects-get', 'objects-put', 'refs', 'refs-set'] {
		assert obs_norm_endpoint(ep) == ep, '${ep} must be a first-class metrics/trace endpoint, not _other'
	}
	// a bogus op is still bounded to _other (no cardinality blow-up).
	assert obs_norm_endpoint('objects-frobnicate') == '_other', 'unknown ops stay bounded'
}
