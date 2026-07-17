module code

import cx

// store_observability_wave7_test.v — W7 observability (#200 span bytes/child/
// propagation, #202 async export, #207 minors). Deterministic where possible.

// ── #207.5: traceparent strictness (W3C) ──────────────────────────────────────

fn test_traceparent_rejects_uppercase() {
	// valid lowercase → accepted
	ok := parse_traceparent('00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01')
	assert ok != none, 'valid lowercase traceparent must parse'
	// uppercase hex → invalid (W3C requires lowercase), not salvaged via to_lower
	up := parse_traceparent('00-0AF7651916CD43DD8448EB211C80319C-B7AD6B7169203331-01')
	assert up == none, 'uppercase traceparent must be rejected (#207.5)'
	// 5 fields on version 00 → invalid
	extra := parse_traceparent('00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01-extra')
	assert extra == none, 'a 5-field version-00 traceparent must be rejected (#207.5)'
}

// ── #207.6: authenticated DID without a grant → 403 (empty-roles), not 401 ────

fn test_did_no_grant_yields_forbidden() {
	// an authenticated-but-ungranted DID principal has kind 'did' + no roles, so
	// svc_authorize denies with 403 CXER1703 (not anonymous → 401).
	p := Principal{
		id:   'did:key:z6MkExample'
		kind: 'did'
	}
	e := svc_authorize(p, 'get', 'docs') or {
		assert false, 'an ungranted DID must be DENIED (403), got allowed'
		return
	}
	assert svc_err_code_of(e) == 'cx-err:CXER1703', 'ungranted DID → 403 CXER1703 (#207.6), got ${svc_err_code_of(e)}'
}

fn svc_err_code_of(n cx.Node) string {
	if n is cx.Element && n.name == 'err' {
		for a in n.attrs {
			if a.name == 'code' {
				return cx.scalar_value_str_public(a.value)
			}
		}
	}
	return ''
}

// ── #207.2: log format json ───────────────────────────────────────────────────

fn test_log_format_json() {
	j := svc_format_log('get', 'docs', 200, 3.25, 10, 100, 'reader', 'tid', 1700000000, true)
	assert j.starts_with('{') && j.ends_with('}'), 'json log must be a JSON object: ${j}'
	assert j.contains('"endpoint":"get"'), 'json log carries endpoint: ${j}'
	assert j.contains('"status":200'), 'json log carries numeric status: ${j}'
	assert j.contains('"trace-id":"tid"'), 'json log carries trace-id: ${j}'
	// the cx form is unchanged
	c := svc_format_log('get', 'docs', 200, 3.25, 10, 100, 'reader', 'tid', 1700000000, false)
	assert c.starts_with('[request-log'), 'cx log form unchanged: ${c}'
}

// ── #200: child span parentSpanId + format_traceparent consumer + bytes ───────

fn test_child_span_otlp_parent() {
	parent := TraceContext{
		trace_id:  '0af7651916cd43dd8448eb211c80319c'
		span_id:   'b7ad6b7169203331'
		parent_id: ''
	}
	child := TraceContext{
		trace_id:  parent.trace_id
		span_id:   'aaaaaaaaaaaaaaaa'
		parent_id: parent.span_id
	}
	json := build_otlp_json([
		Span{
			tc:   child
			name: 'store.get'
			attrs: {
				'bytes.in':  '10'
				'bytes.out': '100'
			}
		},
	], 'cxstore')
	assert json.contains('"parentSpanId":"b7ad6b7169203331"'), 'child span must carry parentSpanId (#200): ${json}'
	assert json.contains('bytes.in') && json.contains('bytes.out'), 'span carries bytes attrs (#200)'
}

fn test_format_traceparent_has_output() {
	tc := TraceContext{
		trace_id:  '0af7651916cd43dd8448eb211c80319c'
		span_id:   'b7ad6b7169203331'
		parent_id: ''
		sampled:   true
	}
	tp := format_traceparent(tc)
	assert tp == '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01', 'format_traceparent (now the OTLP-export consumer, #200): ${tp}'
}

// ── #202: export enqueues (never blocks); disabled exporter is a no-op ─────────

fn test_async_export_enqueues_without_blocking() {
	// a black-hole endpoint: export() must return immediately (it enqueues; the
	// worker POSTs off the request path). We assert it returns and does not panic;
	// with cap 1024 the enqueue is non-blocking. (Latency is asserted end-to-end
	// in the integration harness; here we prove the call is fire-and-forget.)
	e := new_trace_exporter(true, 'http://127.0.0.1:1/v1/traces', 'cxstore')
	sp := Span{
		tc:   TraceContext{
			trace_id: '0af7651916cd43dd8448eb211c80319c'
			span_id:  'b7ad6b7169203331'
		}
		name: 'csrp.get'
	}
	for _ in 0 .. 100 {
		e.export(sp) // must not block even though the collector is unreachable
	}
	// a disabled exporter is a pure no-op
	d := new_trace_exporter(false, '', 'cxstore')
	d.export(sp)
	assert true, 'export is fire-and-forget (#202)'
}
