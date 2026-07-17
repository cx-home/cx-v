module code

import cx
import sync
import crypto.sha256

// #105 Phase-2 daemon brick 1 — ServiceConfig parse + validation.

const valid_cfg = '[cxstore-service
  [bind addr="0.0.0.0:8443"]
  [tls cert="/etc/cxstore/tls.crt" key="/etc/cxstore/tls.key"]
  [grpc enabled=true addr="0.0.0.0:8444"]
  [stores
    [store name="docs" url="file:///var/lib/cxstore/docs"]
    [store name="code" url="file:///var/lib/cxstore/code"]]
  [auth
    [static]
    [jwt issuer="https://idp.example" audience="api" jwks=\'{"keys":[]}\']
    [did]
    [oidc issuer="https://idp.example"]
    [scrape]]
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
	assert c.auth.providers == ['static', 'jwt', 'did', 'oidc', 'scrape']
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
	assert c.auth.providers.len == 0
	if _ := c.tls {
		assert false, 'tls should be none when absent'
	}
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

fn test_unknown_auth_provider_rejected() {
	fails('[cxstore-service [bind addr="h:1"] [stores [store name="s" url="mem://s"]] [auth [ldap]]]',
		'unknown auth provider')
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
						return csrp_scalar(b)
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

fn test_dispatch_data_op_refused_while_draining() {
	mut s := new_service_state()
	s.mark_ready()
	s.begin_drain()
	mounts := {
		'docs': svc_test_store('mem://svc-drain-test')
	}
	resp := svc_handle_request(svc_test_req('POST', '/cx-store/v1/list'), mut s, ServeContext{ mounts: mounts })
	assert svc_resp_status(resp) == 503
	assert svc_resp_body(resp).contains('CXER1708')
}

fn test_dispatch_data_op_refused_before_ready() {
	mut s := new_service_state() // never marked ready
	mounts := {
		'docs': svc_test_store('mem://svc-notready-test')
	}
	resp := svc_handle_request(svc_test_req('POST', '/cx-store/v1/list'), mut s, ServeContext{ mounts: mounts })
	assert svc_resp_status(resp) == 503
}

fn test_dispatch_sole_store_no_name() {
	mut s := new_service_state()
	s.mark_ready()
	mounts := {
		'docs': svc_test_store('mem://svc-sole-test')
	}
	// no store-name segment + a single mount → routes to the sole store
	resp := svc_handle_request(svc_test_req('POST', '/cx-store/v1/list'), mut s, ServeContext{ mounts: mounts })
	assert svc_resp_status(resp) == 200
	assert svc_resp_body(resp).contains('[list-result')
	assert s.in_flight() == 0
}

// ── store-name routing (step 1a) ─────────────────────────────────────────────

fn test_route_named_store() {
	mut s := new_service_state()
	s.mark_ready()
	mounts := {
		'docs': svc_test_store('mem://svc-named-docs')
		'code': svc_test_store('mem://svc-named-code')
	}
	// named-store path → routes to that mount (op = list, store = docs)
	resp := svc_handle_request(svc_test_req('POST', '/cx-store/v1/docs/list'), mut s, ServeContext{ mounts: mounts })
	assert svc_resp_status(resp) == 200
	assert svc_resp_body(resp).contains('[list-result')
}

fn test_route_unknown_store_404() {
	mut s := new_service_state()
	s.mark_ready()
	mounts := {
		'docs': svc_test_store('mem://svc-unknown-docs')
	}
	resp := svc_handle_request(svc_test_req('POST', '/cx-store/v1/nope/list'), mut s, ServeContext{ mounts: mounts })
	assert svc_resp_status(resp) == 404
	// #204: unknown store-name on the wire is CXER1710 E_CSRP_STORE_NOT_FOUND
	// (the std-lib CXER1121 never rides the wire).
	assert svc_resp_body(resp).contains('CXER1710'), svc_resp_body(resp)
}

fn test_route_multi_store_requires_name_404() {
	mut s := new_service_state()
	s.mark_ready()
	mounts := {
		'a': svc_test_store('mem://svc-multi-a')
		'b': svc_test_store('mem://svc-multi-b')
	}
	// no store-name + multiple mounts → ambiguous → 404 (client must name one)
	resp := svc_handle_request(svc_test_req('POST', '/cx-store/v1/list'), mut s, ServeContext{ mounts: mounts })
	assert svc_resp_status(resp) == 404
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

// ── step 2a: integrated authN/Z in svc_handle_request ────────────────────────

fn svc_test_req_auth(method string, path string, token string) cx.Element {
	mut hdrs := []cx.Node{}
	if token != '' {
		hdrs << cx.Node(cx.Element{
			name:  'header'
			attrs: [
				cx.Attribute{ name: 'name', value: cx.ScalarValue('Authorization') },
				cx.Attribute{ name: 'value', value: cx.ScalarValue('Bearer ${token}') },
			]
		})
	}
	return cx.Element{
		name:  'request'
		attrs: [
			cx.Attribute{ name: 'method', value: cx.ScalarValue(method) },
			cx.Attribute{ name: 'path', value: cx.ScalarValue(path) },
		]
		items: [cx.Node(cx.Element{ name: 'headers', items: hdrs })]
	}
}

fn enforced_ctx() ServeContext {
	return ServeContext{
		mounts: {
			'docs': svc_test_store('mem://svc-authz-docs')
			'code': svc_test_store('mem://svc-authz-code')
		}
		auth:   AuthContext{
			enforce:       true
			static_tokens: [
				StaticToken{ id: 'w', secret_hash: sha256.sum256('w-tok'.bytes()).hex(), roles: ['writer'], tenant: 'docs' },
				StaticToken{ id: 'r', secret_hash: sha256.sum256('r-tok'.bytes()).hex(), roles: ['reader'], tenant: 'docs' },
			]
		}
	}
}

// ── observability: scope-gated /metrics endpoint + request recording ─────────

fn obs_metrics_ctx() ServeContext {
	return ServeContext{
		mounts:  {
			'docs': svc_test_store('mem://obs-docs')
		}
		auth:    AuthContext{
			enforce:       true
			static_tokens: [
				StaticToken{
					id:          'prom'
					secret_hash: sha256.sum256('prom-tok'.bytes()).hex()
					roles:       ['metrics']
					tenant:      'docs'
				},
				StaticToken{
					id:          'r'
					secret_hash: sha256.sum256('r-tok'.bytes()).hex()
					roles:       ['reader']
					tenant:      'docs'
				},
			]
		}
		metrics: new_metrics_registry('0.12.0-test')
	}
}

fn test_metrics_endpoint_requires_scope() {
	mut s := new_service_state()
	s.mark_ready()
	ctx := obs_metrics_ctx()

	// metrics-scope token → 200 + exposition
	ok := svc_handle_request(svc_test_req_auth('GET', '/metrics', 'prom-tok'), mut s, ctx)
	assert svc_resp_status(ok) == 200, svc_resp_body(ok)
	assert svc_resp_body(ok).contains('cxstore_build_info'), svc_resp_body(ok)

	// reader token (no metrics permission) → 403
	forbidden := svc_handle_request(svc_test_req_auth('GET', '/metrics', 'r-tok'), mut s, ctx)
	assert svc_resp_status(forbidden) == 403, svc_resp_body(forbidden)

	// no token → 401
	unauth := svc_handle_request(svc_test_req_auth('GET', '/metrics', ''), mut s, ctx)
	assert svc_resp_status(unauth) == 401, svc_resp_body(unauth)
}

fn test_metrics_endpoint_open_when_not_enforcing() {
	mut s := new_service_state()
	s.mark_ready()
	ctx := ServeContext{
		mounts:  {
			'docs': svc_test_store('mem://obs-open-docs')
		}
		auth:    AuthContext{
			enforce: false
		}
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
		mounts:  {
			'docs': svc_test_store('mem://obs-rec-docs')
		}
		auth:    AuthContext{
			enforce: false
		}
		metrics: new_metrics_registry('v')
	}
	// a real data op against the known store, then a bogus store-name
	svc_handle_request(svc_test_req('POST', '/cx-store/v1/docs/list'), mut s, ctx)
	svc_handle_request(svc_test_req('POST', '/cx-store/v1/zzz-bogus/list'), mut s, ctx)
	mut m := ctx.metrics
	out := m.render_prometheus()
	// the list op against docs is recorded under the known store label
	assert out.contains('endpoint="list",store="docs"'), out
	// the bogus store-name is collapsed to _unknown, never a distinct series
	assert out.contains('store="_unknown"'), out
	assert !out.contains('zzz-bogus'), out
}

// store-internal metrics introspection seam (§7): the doc-count gauge is read
// live from the real backend — no fabricated zeros, remote mounts skipped.
fn test_store_internal_metrics_live() {
	h := svc_test_store('mem://obs-internal-metrics')
	// a fresh store legitimately has zero docs (a true zero, not fabricated)
	st0 := store_mount_stats(h) or { panic('stats should resolve a local handle') }
	assert st0.backend == 'mem'
	assert st0.doc_count == 0

	store_stdlib_builtin_inner('store-put-doc-text', [h, store_str('[a [body "one"]]')]) or {
		panic('put: ${err}')
	}
	store_stdlib_builtin_inner('store-put-doc-text', [h, store_str('[b [body "two"]]')]) or {
		panic('put: ${err}')
	}
	st := store_mount_stats(h) or { panic('stats none') }
	assert st.doc_count == 2, 'expected 2 docs, got ${st.doc_count}'

	out := svc_store_internal_metrics({
		'd': h
	})
	assert out.contains('# TYPE cxstore_store_docs gauge'), out
	assert out.contains('cxstore_store_docs{store="d",backend="mem"} 2'), out
}

fn test_authz_writer_can_read_own_tenant() {
	mut s := new_service_state()
	s.mark_ready()
	ctx := enforced_ctx()
	resp := svc_handle_request(svc_test_req_auth('POST', '/cx-store/v1/docs/list', 'w-tok'), mut s, ctx)
	assert svc_resp_status(resp) == 200
	assert svc_resp_body(resp).contains('[list-result')
}

fn test_authz_reader_cannot_write_403() {
	mut s := new_service_state()
	s.mark_ready()
	ctx := enforced_ctx()
	resp := svc_handle_request(svc_test_req_auth('POST', '/cx-store/v1/docs/put', 'r-tok'), mut s, ctx)
	assert svc_resp_status(resp) == 403
	assert svc_resp_body(resp).contains('CXER1703')
}

fn test_authz_no_token_401() {
	mut s := new_service_state()
	s.mark_ready()
	ctx := enforced_ctx()
	resp := svc_handle_request(svc_test_req_auth('POST', '/cx-store/v1/docs/list', ''), mut s, ctx)
	assert svc_resp_status(resp) == 401
	assert svc_resp_body(resp).contains('CXER1702')
}

fn test_authz_cross_tenant_403() {
	mut s := new_service_state()
	s.mark_ready()
	ctx := enforced_ctx()
	// writer's tenant is 'docs'; reaching store 'code' is forbidden (CXER1703)
	resp := svc_handle_request(svc_test_req_auth('POST', '/cx-store/v1/code/list', 'w-tok'), mut s, ctx)
	assert svc_resp_status(resp) == 403
	assert svc_resp_body(resp).contains('CXER1703')
}

fn test_authz_health_unauthenticated_even_when_enforcing() {
	mut s := new_service_state()
	s.mark_ready()
	ctx := enforced_ctx()
	// lifecycle + capabilities never require a credential, even with enforce on
	r1 := svc_handle_request(svc_test_req_auth('GET', '/cx-store/v1/health', ''), mut s, ctx)
	assert svc_resp_status(r1) == 200
	r2 := svc_handle_request(svc_test_req_auth('GET', '/cx-store/v1/capabilities', ''), mut s, ctx)
	assert svc_resp_status(r2) == 200
}

fn test_config_parses_static_tokens() {
	// #188: secret-hash must be a valid 64-hex sha256 digest (bare or sha256:-prefixed).
	digest := 'a'.repeat(64)
	c := parse_service_config('[cxstore-service [bind addr="h:1"] [stores [store name="docs" url="mem://docs"]] [auth [static [token id="ci" secret-hash="${digest}" roles="writer" tenant="docs"]]]]') or {
		panic('config rejected: ${err}')
	}
	assert c.auth.context.enforce
	assert c.auth.context.static_tokens.len == 1
	assert c.auth.context.static_tokens[0].id == 'ci'
	assert c.auth.context.static_tokens[0].secret_hash == digest
	assert c.auth.context.static_tokens[0].roles == ['writer']
	assert c.auth.context.static_tokens[0].tenant == 'docs'
}

fn test_config_static_token_sha256_prefix() {
	// #188: the Appendix-A sha256:<hex> form parses to the bare digest.
	digest := 'b'.repeat(64)
	c := parse_service_config('[cxstore-service [bind addr="h:1"] [stores [store name="docs" url="mem://docs"]] [auth [static [token id="ci" secret-hash="sha256:${digest}" roles="writer" tenant="docs"]]]]') or {
		panic('config rejected: ${err}')
	}
	assert c.auth.context.static_tokens[0].secret_hash == digest
}

fn test_config_static_token_bad_hash_rejected() {
	// a toy/short secret-hash is a fast-fail config error (would silently never
	// authenticate otherwise — #188).
	if _ := parse_service_config('[cxstore-service [bind addr="h:1"] [stores [store name="docs" url="mem://docs"]] [auth [static [token id="ci" secret-hash="abc123" roles="writer" tenant="docs"]]]]') {
		assert false, 'a 6-char secret-hash must be rejected at config parse'
	}
}

fn test_config_no_auth_section_is_open() {
	c := parse_service_config('[cxstore-service [bind addr="h:1"] [stores [store name="s" url="mem://s"]]]') or {
		panic('config rejected: ${err}')
	}
	assert !c.auth.context.enforce // no [auth] → open (anonymous full access)
}

fn test_config_parses_jwt_provider() {
	cfg := "[cxstore-service [bind addr=\"h:1\"] [stores [store name=\"s\" url=\"mem://s\"]] [auth [jwt issuer=\"https://idp.example\" audience=\"my-api\" jwks='{\"keys\":[]}' roles-claim=\"r\" tenant-claim=\"t\"]]]"
	c := parse_service_config(cfg) or { panic('jwt config rejected: ${err}') }
	assert c.auth.context.enforce
	assert c.auth.context.jwt.enabled
	assert c.auth.context.jwt.issuer == 'https://idp.example'
	assert c.auth.context.jwt.audience == 'my-api'
	assert c.auth.context.jwt.roles_claim == 'r'
	assert c.auth.context.jwt.tenant_claim == 't'
}

fn test_config_jwt_requires_jwks() {
	fails('[cxstore-service [bind addr="h:1"] [stores [store name="s" url="mem://s"]] [auth [jwt issuer="x"]]]',
		'[jwt] requires `jwks`')
}

fn test_config_parses_oidc_provider() {
	cfg := "[cxstore-service [bind addr=\"h:1\"] [stores [store name=\"s\" url=\"mem://s\"]] [auth [oidc issuer=\"https://idp.example\" audience=\"my-api\" cache-ttl=600]]]"
	c := parse_service_config(cfg) or { panic('oidc config rejected: ${err}') }
	assert c.auth.context.oidc.enabled
	assert c.auth.context.oidc.issuer == 'https://idp.example'
	assert c.auth.context.oidc.audience == 'my-api'
	assert c.auth.context.oidc.cache_ttl_secs == 600
}

fn test_config_oidc_requires_issuer() {
	fails('[cxstore-service [bind addr="h:1"] [stores [store name="s" url="mem://s"]] [auth [oidc audience="x"]]]',
		'[oidc] requires `issuer`')
}

// ── brick E2: DoS-fairness wiring (per-principal + pre-auth) ──────────────────

fn svc_req_bearer(method string, path string, token string) cx.Element {
	return cx.Element{
		name:  'request'
		attrs: [
			cx.Attribute{ name: 'method', value: cx.ScalarValue(method) },
			cx.Attribute{ name: 'path', value: cx.ScalarValue(path) },
		]
		items: [
			cx.Node(cx.Element{
				name:  'headers'
				items: [
					cx.Node(cx.Element{
						name:  'header'
						attrs: [
							cx.Attribute{ name: 'name', value: cx.ScalarValue('Authorization') },
							cx.Attribute{ name: 'value', value: cx.ScalarValue('Bearer ${token}') },
						]
					}),
				]
			}),
		]
	}
}

fn test_per_principal_rate_throttles_one_not_others() {
	mut s := new_service_state()
	s.mark_ready()
	mounts := {
		'docs': store_open_impl('mem://lim-rate', '', '', false, true, map[string]string{})
	}
	lim := new_limiter(LimitConfig{
		per_principal_rate:  0.001 // ~no refill in the test window
		per_principal_burst: 2.0
		per_principal_conc:  1000
		pre_auth_rate:       100000.0
		pre_auth_burst:      100000.0
	})
	auth := AuthContext{
		enforce:       true
		static_tokens: [
			StaticToken{ id: 'A', secret_hash: sha256.sum256('tokA'.bytes()).hex(), roles: ['writer'], tenant: 'docs' },
			StaticToken{ id: 'B', secret_hash: sha256.sum256('tokB'.bytes()).hex(), roles: ['writer'], tenant: 'docs' },
		]
	}
	ctx := ServeContext{
		mounts:  mounts
		auth:    auth
		limiter: lim
	}
	// principal A: burst 2 → two served, third throttled
	assert svc_resp_status(svc_handle_request(svc_req_bearer('POST', '/cx-store/v1/list', 'tokA'), mut s, ctx)) == 200
	assert svc_resp_status(svc_handle_request(svc_req_bearer('POST', '/cx-store/v1/list', 'tokA'), mut s, ctx)) == 200
	assert svc_resp_status(svc_handle_request(svc_req_bearer('POST', '/cx-store/v1/list', 'tokA'), mut s, ctx)) == 429
	// principal B has its own bucket → not starved by A's flood
	assert svc_resp_status(svc_handle_request(svc_req_bearer('POST', '/cx-store/v1/list', 'tokB'), mut s, ctx)) == 200
}

fn test_pre_auth_flood_throttled() {
	mut s := new_service_state()
	s.mark_ready()
	mounts := {
		'docs': store_open_impl('mem://lim-preauth', '', '', false, true, map[string]string{})
	}
	// open mode (no auth), tiny pre-auth bucket → 2nd request throttled at the gate
	lim := new_limiter(LimitConfig{
		pre_auth_rate:  0.001
		pre_auth_burst: 1.0
	})
	ctx := ServeContext{
		mounts:  mounts
		auth:    AuthContext{}
		limiter: lim
	}
	assert svc_resp_status(svc_handle_request(svc_test_req('POST', '/cx-store/v1/list'), mut s, ctx)) == 200
	assert svc_resp_status(svc_handle_request(svc_test_req('POST', '/cx-store/v1/list'), mut s, ctx)) == 429
	// health stays exempt (orchestration probes) even when the pre-auth bucket is empty
	assert svc_resp_status(svc_handle_request(svc_test_req('GET', '/cx-store/v1/health'), mut s, ctx)) == 200
}

// ── brick F: capabilities [auth] advert ──────────────────────────────────────

fn test_capabilities_advert_enforced() {
	mut s := new_service_state()
	s.mark_ready()
	mounts := {
		'docs': store_open_impl('mem://cap-enf', '', '', false, true, map[string]string{})
	}
	auth := AuthContext{
		enforce:       true
		static_tokens: [StaticToken{ id: 'a', secret_hash: 'x', roles: ['reader'], tenant: 'docs' }]
	}
	ctx := ServeContext{
		mounts: mounts
		auth:   auth
	}
	resp := svc_handle_request(svc_test_req('GET', '/cx-store/v1/capabilities'), mut s, ctx)
	body := svc_resp_body(resp)
	assert body.contains('[auth ')
	assert body.contains('[bearer true]')
	assert body.contains('[anonymous false]'), 'enforcing daemon advertises anonymous=false'
	assert body.contains('[capabilities '), 'base capabilities preserved'
}

fn test_capabilities_advert_open_mode() {
	mut s := new_service_state()
	s.mark_ready()
	mounts := {
		'docs': store_open_impl('mem://cap-open', '', '', false, true, map[string]string{})
	}
	ctx := ServeContext{
		mounts: mounts
		auth:   AuthContext{} // no providers → open
	}
	resp := svc_handle_request(svc_test_req('GET', '/cx-store/v1/capabilities'), mut s, ctx)
	body := svc_resp_body(resp)
	assert body.contains('[bearer false]')
	assert body.contains('[anonymous true]'), 'open daemon advertises anonymous=true'
}
