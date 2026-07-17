module code

import cx

// store_observability_test.v — BEHAVIORAL tests for the metrics registry +
// Prometheus exposition (observability sub-area, spec Appendix F). Deterministic:
// durations/bytes are injected, never wall-clock. The scope-gated /metrics
// endpoint tests live in store_service_test.v (where the request/ctx fixtures are
// — V compiles each _test.v as its own binary, so helpers are not shared).

// ── registry unit: exposition shape ─────────────────────────────────────────

fn test_registry_exposition_basic() {
	mut m := new_metrics_registry('0.12.0-test')
	m.record_request('get', 200, 'docs', 10, 100, 0.003)
	m.record_request('get', 200, 'docs', 20, 200, 0.007)
	m.record_request('put', 200, 'docs', 50, 5, 0.02)
	m.record_request('get', 404, 'docs', 0, 12, 0.001)
	out := m.render_prometheus()

	// build_info always present with the version label
	assert out.contains('cxstore_build_info{version="0.12.0-test"} 1'), out
	// request counters by (endpoint,status,store)
	assert out.contains('cxstore_requests_total{endpoint="get",status="200",store="docs"} 2'), out
	assert out.contains('cxstore_requests_total{endpoint="put",status="200",store="docs"} 1'), out
	assert out.contains('cxstore_requests_total{endpoint="get",status="404",store="docs"} 1'), out
	// bytes counters (summed per endpoint,store across statuses)
	assert out.contains('cxstore_request_bytes_in_total{endpoint="get",store="docs"} 30'), out
	assert out.contains('cxstore_request_bytes_out_total{endpoint="get",store="docs"} 312'), out
	// histogram has the canonical TYPE line + a +Inf bucket + sum/count
	assert out.contains('# TYPE cxstore_request_duration_seconds histogram'), out
	assert out.contains('cxstore_request_duration_seconds_bucket{endpoint="get",store="docs",le="+Inf"} 3'), out
	assert out.contains('cxstore_request_duration_seconds_count{endpoint="get",store="docs"} 3'), out
	// inflight gauge present (0 at rest)
	assert out.contains('cxstore_inflight_requests 0'), out
}

fn test_histogram_buckets_cumulative() {
	mut m := new_metrics_registry('v')
	// three obs: 3ms, 7ms, 20ms → le=0.005 covers 1, le=0.01 covers 2, le=0.025 covers 3
	m.record_request('get', 200, 's', 0, 0, 0.003)
	m.record_request('get', 200, 's', 0, 0, 0.007)
	m.record_request('get', 200, 's', 0, 0, 0.02)
	out := m.render_prometheus()
	assert out.contains('cxstore_request_duration_seconds_bucket{endpoint="get",store="s",le="0.005"} 1'), out
	assert out.contains('cxstore_request_duration_seconds_bucket{endpoint="get",store="s",le="0.01"} 2'), out
	assert out.contains('cxstore_request_duration_seconds_bucket{endpoint="get",store="s",le="0.025"} 3'), out
	assert out.contains('cxstore_request_duration_seconds_bucket{endpoint="get",store="s",le="+Inf"} 3'), out
}

fn test_exposition_deterministic_order() {
	mut a := new_metrics_registry('v')
	mut b := new_metrics_registry('v')
	// record in different orders → identical output (keys are sorted)
	a.record_request('put', 200, 'docs', 1, 1, 0.01)
	a.record_request('get', 200, 'code', 1, 1, 0.01)
	b.record_request('get', 200, 'code', 1, 1, 0.01)
	b.record_request('put', 200, 'docs', 1, 1, 0.01)
	assert a.render_prometheus() == b.render_prometheus()
}

// ── label normalization → bounded cardinality ────────────────────────────────

fn test_label_normalization() {
	assert obs_norm_endpoint('get') == 'get'
	assert obs_norm_endpoint('metrics') == 'metrics'
	assert obs_norm_endpoint('wat') == '_other'
	assert obs_norm_endpoint('') == '_other'

	mounts := {
		'docs': cx.Node(cx.ScalarNode{})
		'code': cx.Node(cx.ScalarNode{})
	}
	assert obs_norm_store('docs', mounts) == 'docs'
	assert obs_norm_store('nope', mounts) == '_unknown'
	assert obs_norm_store('', mounts) == '_unknown'
}

// ── structured logs (F.3) ────────────────────────────────────────────────────

fn test_log_record_format() {
	// fixed inputs → exact, deterministic CX-element line
	got := svc_format_log('get', 'docs', 200, 3.25, 10, 100, 'reader', '', 1700000000, false)
	exp := '[request-log ts=1700000000 endpoint="get" store="docs" status=200 latency-ms=3.250 bytes-in=10 bytes-out=100 principal-role="reader"]'
	assert got == exp, got
}

fn test_log_record_includes_trace_id_when_present() {
	got := svc_format_log('put', 'docs', 201, 1.0, 5, 0, 'writer', 'abc123', 1700000000, false)
	assert got.contains('trace-id="abc123"'), got
	// absent trace-id omits the attribute entirely
	none_tid := svc_format_log('put', 'docs', 201, 1.0, 5, 0, 'writer', '', 1700000000, false)
	assert !none_tid.contains('trace-id'), none_tid
}

fn test_log_never_contains_secret() {
	// the formatter takes ROLE, not a token — there is no parameter through which
	// a secret could leak. Guard the property: a token-looking string never appears.
	got := svc_format_log('get', 'docs', 200, 0.5, 0, 0, 'metrics', 'tid', 1700000000, false)
	assert got.contains('principal-role="metrics"'), got
	assert !got.contains('Bearer'), got
	assert !got.to_lower().contains('secret'), got
}

fn test_log_sampling_suppresses_probes() {
	assert svc_log_sampled_out('health')
	assert svc_log_sampled_out('ready')
	assert !svc_log_sampled_out('get')
	assert !svc_log_sampled_out('metrics')
}

fn test_cardinality_bounded_under_bogus_stores() {
	mut m := new_metrics_registry('v')
	mounts := {
		'docs': cx.Node(cx.ScalarNode{})
	}
	// an attacker sprays 1000 distinct bogus store-names; normalization collapses
	// them all to `_unknown`, so the store-series count stays O(mounts)+1.
	for i in 0 .. 1000 {
		store := obs_norm_store('bogus-${i}', mounts)
		m.record_request('get', 200, store, 1, 1, 0.001)
	}
	m.record_request('get', 200, obs_norm_store('docs', mounts), 1, 1, 0.001)
	out := m.render_prometheus()
	// exactly two store label values appear: _unknown and docs
	assert out.contains('store="_unknown"'), out
	assert out.contains('store="docs"'), out
	assert m.requests.len == 2, 'expected 2 request series (docs + _unknown), got ${m.requests.len}'
}

