module platform

import cx
import sync
import crypto.sha256

// #105 Phase-2 daemon brick 1 — ServiceConfig parse + validation.

// S3 (RULED G2a): NO [auth …] section — the bearer plane is retired; operator
// grants ride [xsp [grants …]].
const valid_cfg = '[cxstore-service
  [bind addr="0.0.0.0:8443"]
  [tls cert="/etc/cxstore/tls.crt" key="/etc/cxstore/tls.key"]
  [grpc enabled=true addr="0.0.0.0:8444"]
  [stores
    [store name="docs" url="file:///var/lib/cxstore/docs"]
    [store name="code" url="file:///var/lib/cxstore/code"]]
  [observability
    [otel endpoint="http://otel:4317" enabled=true]
    [log format="json"]]
  [workers query-pool=8]]'

fn test_valid_config_parses() {
	c := parse_service_config(valid_cfg) or { panic('valid config rejected: ${err}') }
	assert c.bind == '0.0.0.0:8443'
	assert c.stores.len == 2
	assert c.stores[0].name == 'docs'
	assert c.stores[1].url == 'file:///var/lib/cxstore/code'
	assert c.grpc.enabled
	assert c.grpc.addr == '0.0.0.0:8444'
	assert c.query_pool == 8
	assert c.observability.otel_enabled
	assert c.observability.log_format == 'json'
	tls := c.tls or { panic('tls missing') }
	assert tls.cert == '/etc/cxstore/tls.crt'
}

fn test_minimal_config_parses() {
	// bind + one store is the floor; everything else defaults.
	c := parse_service_config('[cxstore-service [bind addr="127.0.0.1:9000"] [stores [store name="s" url="mem://s"]]]') or {
		panic('minimal config rejected: ${err}')
	}
	assert c.bind == '127.0.0.1:9000'
	assert c.stores.len == 1
	assert c.query_pool == 4 // default
	assert !c.grpc.enabled
	if _ := c.tls {
		assert false, 'tls should be none when absent'
	}
}

// G2a: an [auth …] section is now a HARD config error (cutover-first).
fn test_auth_section_rejected() {
	fails('[cxstore-service [bind addr="h:1"] [stores [store name="s" url="mem://s"]] [auth [static]]]',
		'the [auth')
}

fn fails(src string, want_marker string) {
	parse_service_config(src) or {
		assert err.msg().contains(want_marker), 'expected error containing "${want_marker}", got: ${err.msg()}'
		return
	}
	assert false, 'expected config to be rejected (marker: ${want_marker})'
}

fn test_wrong_root_rejected() {
	fails('[not-the-service [bind addr="x:1"]]', 'config root must be `[cxstore-service')
}

fn test_missing_bind_rejected() {
	fails('[cxstore-service [stores [store name="s" url="mem://s"]]]', 'missing required `[bind')
}

fn test_bad_bind_addr_rejected() {
	fails('[cxstore-service [bind addr="not-a-host-port"] [stores [store name="s" url="mem://s"]]]',
		'must be `host:port`')
}

fn test_bad_bind_port_rejected() {
	fails('[cxstore-service [bind addr="host:99999"] [stores [store name="s" url="mem://s"]]]',
		'must be `host:port`')
}

fn test_no_stores_rejected() {
	fails('[cxstore-service [bind addr="h:1"]]', 'at least one')
}

fn test_store_missing_url_rejected() {
	fails('[cxstore-service [bind addr="h:1"] [stores [store name="s"]]]', 'requires a `url`')
}

fn test_store_missing_name_rejected() {
	fails('[cxstore-service [bind addr="h:1"] [stores [store url="mem://s"]]]', 'requires a `name`')
}

fn test_duplicate_store_name_rejected() {
	fails('[cxstore-service [bind addr="h:1"] [stores [store name="s" url="mem://a"] [store name="s" url="mem://b"]]]',
		'duplicate store name')
}

fn test_unknown_section_rejected() {
	fails('[cxstore-service [bind addr="h:1"] [stores [store name="s" url="mem://s"]] [bogus]]',
		'unknown config section')
}

fn test_tls_partial_rejected() {
	fails('[cxstore-service [bind addr="h:1"] [stores [store name="s" url="mem://s"]] [tls cert="x"]]',
		'requires both `cert` and `key`')
}

fn test_grpc_same_addr_rejected() {
	fails('[cxstore-service [bind addr="h:1"] [grpc enabled=true addr="h:1"] [stores [store name="s" url="mem://s"]]]',
		'must differ from the CSRP bind')
}

// ── brick 2: lifecycle state + health/ready endpoints ────────────────────────

fn test_health_always_ok() {
	assert svc_health_response() == '[health [status "ok"]]'
}

fn test_ready_reflects_state() {
	mut s := new_service_state()
	// not yet ready
	assert !s.accepting()
	assert s.ready_response() == '[ready [accepting false] [draining false]]'
	// after bind+open
	s.mark_ready()
	assert s.accepting()
	assert s.ready_response() == '[ready [accepting true] [draining false]]'
	// graceful drain flips accepting false + draining true
	s.begin_drain()
	assert !s.accepting()
	assert s.ready_response() == '[ready [accepting false] [draining true]]'
}

fn test_lifecycle_path_detection() {
	assert svc_lifecycle_path('GET', '/cx-store/v1/health')
	assert svc_lifecycle_path('GET', '/cx-store/v1/ready')
	assert !svc_lifecycle_path('GET', '/cx-store/v1/get')
	assert !svc_lifecycle_path('POST', '/cx-store/v1/health')
}

fn test_route_lifecycle_health_unauth() {
	mut s := new_service_state()
	s.mark_ready()
	body := svc_route_lifecycle('GET', '/cx-store/v1/health', mut s) or { panic('health not routed') }
	assert body == '[health [status "ok"]]'
}

fn test_route_lifecycle_ready() {
	mut s := new_service_state()
	s.mark_ready()
	body := svc_route_lifecycle('GET', '/cx-store/v1/ready', mut s) or { panic('ready not routed') }
	assert body == '[ready [accepting true] [draining false]]'
}

fn test_route_lifecycle_passthrough() {
	mut s := new_service_state()
	// a non-lifecycle path → none (caller falls through to the store router)
	if _ := svc_route_lifecycle('POST', '/cx-store/v1/put', mut s) {
		assert false, 'store ops must not be handled by the lifecycle router'
	}
	if _ := svc_route_lifecycle('GET', '/cx-store/v1/capabilities', mut s) {
		assert false, 'capabilities is the store router, not lifecycle'
	}
}

// ── brick 3: graceful-drain sequence ─────────────────────────────────────────

fn test_enter_request_gated_on_accepting() {
	mut s := new_service_state()
	assert !s.enter_request() // not ready yet
	s.mark_ready()
	assert s.enter_request()
	assert s.in_flight() == 1
	s.exit_request()
	assert s.in_flight() == 0
}

fn test_drain_refuses_new_but_finishes_inflight() {
	mut s := new_service_state()
	s.mark_ready()
	assert s.enter_request() // one in flight
	s.begin_drain()
	assert !s.enter_request() // new work refused while draining
	assert s.in_flight() == 1 // the in-flight one is untouched
	assert !s.drain_complete(false) // can't exit: 1 in flight, no deadline
	s.exit_request()
	assert s.drain_complete(false) // now drained → may exit
}

fn test_drain_deadline_forces_exit() {
	mut s := new_service_state()
	s.mark_ready()
	assert s.enter_request()
	s.begin_drain()
	assert !s.drain_complete(false) // still in flight
	assert s.drain_complete(true) // deadline / second signal forces exit
}

fn test_drain_complete_false_when_not_draining() {
	mut s := new_service_state()
	s.mark_ready()
	assert !s.drain_complete(true) // not draining → never "complete"
}

fn test_exit_request_never_negative() {
	mut s := new_service_state()
	s.exit_request()
	assert s.in_flight() == 0
}

// ── brick 4: request dispatch ────────────────────────────────────────────────

fn svc_test_req(method string, path string) cx.Element {
	return cx.Element{
		name:  'request'
		attrs: [
			cx.Attribute{ name: 'method', value: cx.ScalarValue(method) },
			cx.Attribute{ name: 'path', value: cx.ScalarValue(path) },
		]
	}
}

fn svc_resp_body(n cx.Node) string {
	if n is cx.Element {
		for it in n.items {
			if it is cx.Element && it.name == 'body' {
				for b in it.items {
					if b is cx.ScalarNode {
						return sw_scalar(b)
					}
				}
			}
		}
	}
	return ''
}

fn svc_test_store(url string) cx.Node {
	return store_open_impl(url, '', '', false, true, map[string]string{})
}

fn test_dispatch_health_served_even_while_draining() {
	mut s := new_service_state()
	s.mark_ready()
	s.begin_drain() // draining
	resp := svc_handle_request(svc_test_req('GET', '/cx-store/v1/health'), mut s, ServeContext{})
	assert svc_resp_status(resp) == 200
	assert svc_resp_body(resp) == '[health [status "ok"]]'
}

fn test_dispatch_ready_reflects_drain() {
	mut s := new_service_state()
	s.mark_ready()
	s.begin_drain()
	resp := svc_handle_request(svc_test_req('GET', '/cx-store/v1/ready'), mut s, ServeContext{})
	assert svc_resp_status(resp) == 200
	assert svc_resp_body(resp) == '[ready [accepting false] [draining true]]'
}

fn test_dispatch_capabilities_always_served() {
	mut s := new_service_state() // not even ready
	resp := svc_handle_request(svc_test_req('GET', '/cx-store/v1/capabilities'), mut s, ServeContext{})
	assert svc_resp_status(resp) == 200
	assert svc_resp_body(resp).contains('[capabilities')
}

fn test_route_traversal_store_name_rejected() {
	// strict store-name validation: traversal / bad chars never select a store.
	assert !svc_valid_store_name('..')
	assert !svc_valid_store_name('a/b')
	assert !svc_valid_store_name('a..b')
	assert !svc_valid_store_name('a b')
	assert !svc_valid_store_name('%2e%2e')
	assert !svc_valid_store_name('')
	assert svc_valid_store_name('docs')
	assert svc_valid_store_name('tenant-1_store')
}

fn test_path_parts_split() {
	n1, o1 := svc_path_parts('/cx-store/v1/get') or { panic('bad') }
	assert n1 == '' && o1 == 'get'
	n2, o2 := svc_path_parts('/cx-store/v1/docs/get') or { panic('bad') }
	assert n2 == 'docs' && o2 == 'get'
	if _, _ := svc_path_parts('/other/path') {
		assert false, 'non-csrp path must be none'
	}
}

// ── brick 6: bounded worker pool ─────────────────────────────────────────────

struct PoolCounter {
mut:
	mu    &sync.Mutex = unsafe { nil }
	total int
	cur   int
	peak  int
}

fn (mut c PoolCounter) tick() {
	c.mu.lock()
	c.total++
	c.cur++
	if c.cur > c.peak {
		c.peak = c.cur
	}
	c.cur--
	c.mu.unlock()
}

fn test_serve_pool_processes_all_and_drains() {
	mut c := &PoolCounter{
		mu: sync.new_mutex()
	}
	mut pool := new_serve_pool(4, 16, fn [mut c] (job int) {
		c.tick()
	})
	for i in 0 .. 200 {
		pool.submit(i)
	}
	pool.drain() // close + join: every queued job must complete
	assert c.total == 200, 'expected all 200 jobs processed, got ${c.total}'
	assert c.peak >= 1
	assert c.peak <= 4, 'concurrency must not exceed the worker count; peak=${c.peak}'
}

fn test_serve_pool_single_worker_serializes() {
	mut c := &PoolCounter{
		mu: sync.new_mutex()
	}
	mut pool := new_serve_pool(1, 4, fn [mut c] (job int) {
		c.tick()
	})
	for i in 0 .. 50 {
		pool.submit(i)
	}
	pool.drain()
	assert c.total == 50
	assert c.peak == 1, 'a single-worker pool must never run two jobs at once'
}


// ── S3 (RULED G1a/G3a): data-op routing runs on the gRPC-synthesized
// `pipeline="profile"` requests only; a raw HTTP data op is bootstrap-404. The
// store-name RESOLUTION logic (sole-store shorthand / unknown→404 / multi→
// requires name) is what these pin — transport-independent, driven through the
// surviving profile core.

fn svc_prof_req(method string, path string) cx.Element {
	return cx.Element{
		name:  'request'
		attrs: [
			cx.Attribute{ name: 'method', value: cx.ScalarValue(method) },
			cx.Attribute{ name: 'path', value: cx.ScalarValue(path) },
			cx.Attribute{ name: 'pipeline', value: cx.ScalarValue('profile') },
		]
		items: [cx.Node(cx.Element{ name: 'headers' })]
	}
}

fn test_dispatch_data_op_refused_while_draining() {
	mut s := new_service_state()
	s.mark_ready()
	s.begin_drain()
	mounts := { 'docs': svc_test_store('mem://svc-drain') }
	resp := svc_handle_request(svc_prof_req('POST', '/cx-store/v1/list'), mut s, ServeContext{ mounts: mounts })
	assert svc_resp_status(resp) == 503, 'a data op while draining must be 503, got ${svc_resp_status(resp)}'
}

fn test_dispatch_data_op_refused_before_ready() {
	mut s := new_service_state()
	mounts := { 'docs': svc_test_store('mem://svc-notready') }
	resp := svc_handle_request(svc_prof_req('POST', '/cx-store/v1/list'), mut s, ServeContext{ mounts: mounts })
	assert svc_resp_status(resp) == 503, 'a data op before ready must be 503, got ${svc_resp_status(resp)}'
}

fn test_dispatch_sole_store_no_name() {
	mut s := new_service_state()
	s.mark_ready()
	mounts := { 'only': svc_test_store('mem://svc-sole') }
	resp := svc_handle_request(svc_prof_req('POST', '/cx-store/v1/list'), mut s, ServeContext{ mounts: mounts })
	assert svc_resp_status(resp) == 200, 'the sole-store shorthand must resolve, got ${svc_resp_status(resp)}: ${svc_resp_body(resp)}'
}

fn test_route_named_store() {
	mut s := new_service_state()
	s.mark_ready()
	mounts := { 'docs': svc_test_store('mem://svc-named-d'), 'code': svc_test_store('mem://svc-named-c') }
	resp := svc_handle_request(svc_prof_req('POST', '/cx-store/v1/docs/list'), mut s, ServeContext{ mounts: mounts })
	assert svc_resp_status(resp) == 200, 'a named store must route, got ${svc_resp_status(resp)}'
}

fn test_route_unknown_store_404() {
	mut s := new_service_state()
	s.mark_ready()
	mounts := { 'docs': svc_test_store('mem://svc-unk') }
	resp := svc_handle_request(svc_prof_req('POST', '/cx-store/v1/nope/list'), mut s, ServeContext{ mounts: mounts })
	assert svc_resp_status(resp) == 404, 'an unknown store must 404, got ${svc_resp_status(resp)}'
	assert svc_resp_body(resp).contains('CXER1710'), 'unknown store must carry CXER1710'
}

fn test_route_multi_store_requires_name_404() {
	mut s := new_service_state()
	s.mark_ready()
	mounts := { 'docs': svc_test_store('mem://svc-m-d'), 'code': svc_test_store('mem://svc-m-c') }
	resp := svc_handle_request(svc_prof_req('POST', '/cx-store/v1/list'), mut s, ServeContext{ mounts: mounts })
	assert svc_resp_status(resp) == 404, 'a multi-store daemon with no name must 404, got ${svc_resp_status(resp)}'
}

// a raw HTTP data op (no pipeline attr) is bootstrap-404 (the CSRP data router
// is retired — G3a).
fn test_http_data_op_is_bootstrap_404() {
	mut s := new_service_state()
	s.mark_ready()
	mounts := { 'docs': svc_test_store('mem://svc-http404') }
	resp := svc_handle_request(svc_test_req('POST', '/cx-store/v1/list'), mut s, ServeContext{ mounts: mounts })
	assert svc_resp_status(resp) == 404, 'a raw HTTP data op must be 404 (bootstrap-only), got ${svc_resp_status(resp)}'
	assert svc_resp_body(resp).contains('CXER1709'), 'must carry CXER1709'
}

// ── observability: /metrics is unauthenticated operator-plane (G3a) ───────────

fn test_metrics_endpoint_open() {
	mut s := new_service_state()
	s.mark_ready()
	ctx := ServeContext{
		mounts:  { 'docs': svc_test_store('mem://obs-open-docs') }
		metrics: new_metrics_registry('v')
	}
	resp := svc_handle_request(svc_test_req('GET', '/metrics'), mut s, ctx)
	assert svc_resp_status(resp) == 200, svc_resp_body(resp)
	assert svc_resp_body(resp).contains('cxstore_inflight_requests'), svc_resp_body(resp)
}

fn test_requests_recorded_with_bounded_labels() {
	mut s := new_service_state()
	s.mark_ready()
	ctx := ServeContext{
		mounts:  { 'docs': svc_test_store('mem://obs-rec-docs') }
		metrics: new_metrics_registry('v')
	}
	svc_handle_request(svc_prof_req('POST', '/cx-store/v1/docs/list'), mut s, ctx)
	svc_handle_request(svc_prof_req('POST', '/cx-store/v1/zzz-bogus/list'), mut s, ctx)
	mut m := ctx.metrics
	out := m.render_prometheus()
	assert out.contains('endpoint="list",store="docs"'), out
	assert out.contains('store="_unknown"'), out
	assert !out.contains('zzz-bogus'), out
}

fn test_store_internal_metrics_live() {
	h := svc_test_store('mem://obs-internal-metrics')
	st0 := store_mount_stats(h) or { panic('stats should resolve a local handle') }
	assert st0.backend == 'mem'
	assert st0.doc_count == 0
	store_stdlib_builtin_inner('store-put-doc-text', [h, store_str('[a [body "one"]]')]) or { panic('put: ${err}') }
	store_stdlib_builtin_inner('store-put-doc-text', [h, store_str('[b [body "two"]]')]) or { panic('put: ${err}') }
	st := store_mount_stats(h) or { panic('stats none') }
	assert st.doc_count == 2, 'expected 2 docs, got ${st.doc_count}'
	out := svc_store_internal_metrics({ 'd': h })
	assert out.contains('# TYPE cxstore_store_docs gauge'), out
	assert out.contains('cxstore_store_docs{store="d",backend="mem"} 2'), out
}

// ── DoS fairness: the pre-auth bucket (limiter survives; per-principal keys on
// the resolved store now that bearer identity is retired) ─────────────────────

fn test_pre_auth_flood_throttled() {
	mut s := new_service_state()
	s.mark_ready()
	mounts := { 'docs': store_open_impl('mem://lim-preauth', '', '', false, true, map[string]string{}) }
	lim := new_limiter(LimitConfig{
		pre_auth_rate:  0.001
		pre_auth_burst: 1.0
	})
	ctx := ServeContext{
		mounts:  mounts
		limiter: lim
	}
	assert svc_resp_status(svc_handle_request(svc_prof_req('POST', '/cx-store/v1/list'), mut s, ctx)) == 200
	assert svc_resp_status(svc_handle_request(svc_prof_req('POST', '/cx-store/v1/list'), mut s, ctx)) == 429
	// health stays exempt even when the pre-auth bucket is empty
	assert svc_resp_status(svc_handle_request(svc_test_req('GET', '/cx-store/v1/health'), mut s, ctx)) == 200
}

// the bootstrap capabilities advert carries NO [auth …] block (G2a).
fn test_capabilities_advert_no_auth_block() {
	mut s := new_service_state()
	s.mark_ready()
	mounts := { 'docs': store_open_impl('mem://cap-open', '', '', false, true, map[string]string{}) }
	ctx := ServeContext{ mounts: mounts }
	resp := svc_handle_request(svc_test_req('GET', '/cx-store/v1/capabilities'), mut s, ctx)
	body := svc_resp_body(resp)
	assert body.contains('[capabilities '), 'base capabilities preserved: ${body}'
	assert !body.contains('[auth '), 'the retired [auth] advert must be gone: ${body}'
}
