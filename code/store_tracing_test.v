module code

import cx

// store_tracing_test.v — BEHAVIORAL tests for W3C trace-context propagation, the
// span model, and OTLP/JSON serialization (observability O3, spec Appendix F.2).
// Deterministic: parsing/formatting/serialization are pure; id minting is checked
// for shape (length/hex), never value.

const tp_valid = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'

fn test_parse_traceparent_valid() {
	tc := parse_traceparent(tp_valid) or { panic('should parse') }
	assert tc.trace_id == '4bf92f3577b34da6a3ce929d0e0e4736'
	assert tc.parent_id == '00f067aa0ba902b7'
	assert tc.sampled == true
}

fn test_parse_traceparent_unsampled_flag() {
	tc := parse_traceparent('00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00') or {
		panic('should parse')
	}
	assert tc.sampled == false
}

fn test_parse_traceparent_rejects_malformed() {
	// empty
	if _ := parse_traceparent('') {
		assert false, 'empty should be none'
	}
	// wrong version
	if _ := parse_traceparent('ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01') {
		assert false, 'version ff should be none'
	}
	// too few fields
	if _ := parse_traceparent('00-4bf92f3577b34da6a3ce929d0e0e4736') {
		assert false, 'short should be none'
	}
	// all-zero trace-id
	if _ := parse_traceparent('00-00000000000000000000000000000000-00f067aa0ba902b7-01') {
		assert false, 'all-zero trace should be none'
	}
	// all-zero span-id
	if _ := parse_traceparent('00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01') {
		assert false, 'all-zero span should be none'
	}
	// non-hex trace-id
	if _ := parse_traceparent('00-zzf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01') {
		assert false, 'non-hex trace should be none'
	}
}

fn test_id_minting_shape() {
	tid := obs_new_trace_id()
	sid := obs_new_span_id()
	assert obs_is_lc_hex(tid, 32), tid
	assert obs_is_lc_hex(sid, 16), sid
	assert !obs_all_zero_hex(tid), 'a minted trace id should not be all-zero'
}

fn test_format_traceparent() {
	tc := TraceContext{
		trace_id: '4bf92f3577b34da6a3ce929d0e0e4736'
		span_id:  '00f067aa0ba902b7'
		sampled:  true
	}
	assert format_traceparent(tc) == '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
	tc2 := TraceContext{
		trace_id: '4bf92f3577b34da6a3ce929d0e0e4736'
		span_id:  '00f067aa0ba902b7'
		sampled:  false
	}
	assert format_traceparent(tc2).ends_with('-00')
}

fn trace_req(headers map[string]string) cx.Element {
	mut hdrs := []cx.Node{}
	for k, v in headers {
		hdrs << cx.Node(cx.Element{
			name:  'header'
			attrs: [
				cx.Attribute{
					name:  'name'
					value: cx.ScalarValue(k)
				},
				cx.Attribute{
					name:  'value'
					value: cx.ScalarValue(v)
				},
			]
		})
	}
	return cx.Element{
		name:  'request'
		items: [cx.Node(cx.Element{
			name:  'headers'
			items: hdrs
		})]
	}
}

fn test_trace_for_request_mints_root() {
	tc := svc_trace_for_request(trace_req(map[string]string{}), false)
	assert obs_is_lc_hex(tc.trace_id, 32), tc.trace_id
	assert obs_is_lc_hex(tc.span_id, 16), tc.span_id
	assert tc.parent_id == '', 'a fresh root has no parent'
}

fn test_trace_for_request_continues_inbound() {
	req := trace_req({
		'traceparent': tp_valid
	})
	tc := svc_trace_for_request(req, false)
	// same trace, NEW span, parent = the inbound span, sampled propagated
	assert tc.trace_id == '4bf92f3577b34da6a3ce929d0e0e4736'
	assert tc.parent_id == '00f067aa0ba902b7'
	assert tc.span_id != '00f067aa0ba902b7', 'server span must be a fresh id'
	assert obs_is_lc_hex(tc.span_id, 16), tc.span_id
	assert tc.sampled == true
}

fn test_otlp_status_mapping() {
	assert obs_otlp_status(200) == 1
	assert obs_otlp_status(404) == 1 // client error is not a span error
	assert obs_otlp_status(500) == 2
	assert obs_otlp_status(503) == 2
}

fn test_build_otlp_json_shape() {
	sp := Span{
		tc:       TraceContext{
			trace_id:  '4bf92f3577b34da6a3ce929d0e0e4736'
			span_id:   'a1a2a3a4a5a6a7a8'
			parent_id: '00f067aa0ba902b7'
			sampled:   true
		}
		name:     'csrp.get'
		start_ns: 1700000000000000000
		end_ns:   1700000000003000000
		status:   200
		attrs:    {
			'endpoint': 'get'
			'store':    'docs'
		}
	}
	out := build_otlp_json([sp], 'cxstore')
	assert out.contains('"resourceSpans"'), out
	assert out.contains('"service.name"'), out
	assert out.contains('"traceId":"4bf92f3577b34da6a3ce929d0e0e4736"'), out
	assert out.contains('"spanId":"a1a2a3a4a5a6a7a8"'), out
	assert out.contains('"parentSpanId":"00f067aa0ba902b7"'), out
	assert out.contains('"name":"csrp.get"'), out
	assert out.contains('"kind":2'), out
	assert out.contains('"startTimeUnixNano":"1700000000000000000"'), out
	assert out.contains('"endTimeUnixNano":"1700000000003000000"'), out
	// attributes serialized (sorted: endpoint before store)
	assert out.contains('{"key":"endpoint","value":{"stringValue":"get"}}'), out
	assert out.contains('"status":{"code":1}'), out
}

fn test_build_otlp_json_root_omits_parent() {
	sp := Span{
		tc:     TraceContext{
			trace_id: '4bf92f3577b34da6a3ce929d0e0e4736'
			span_id:  'a1a2a3a4a5a6a7a8'
		}
		name:   'csrp.put'
		status: 500
	}
	out := build_otlp_json([sp], 'cxstore')
	assert !out.contains('parentSpanId'), out
	assert out.contains('"status":{"code":2}'), out // 5xx → Error
}
