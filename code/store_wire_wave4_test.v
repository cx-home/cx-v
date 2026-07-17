module code

import cx

// store_wire_wave4_test.v — W4 wire-conformance shared-layer fixes (#190 dedup,
// #191 Retry-After, #193 per-store capabilities, #194 gRPC trailer CXER, #196
// error-code reachability, #198 config-code collision). Behavioral: drives
// store_csrp_route / svc_handle_request / parse_service_config / grpc_status_for_cxer.

fn w4_open(tag string) cx.Node {
	return store_open_impl('mem://w4-${tag}', '', '', false, true, map[string]string{})
}

fn w4_req(method string, path string, body string) cx.Element {
	return grpc_synth_req_pathonly(method, path, body)
}

// grpc_synth_req_pathonly builds a minimal [request] with method+path+body.
fn grpc_synth_req_pathonly(method string, path string, body string) cx.Element {
	mut items := [
		cx.Node(cx.Element{
			name:  'headers'
			items: []
		}),
	]
	if body != '' {
		items << cx.Node(cx.Element{
			name:  'body'
			items: [
				cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(body)
					data_type: cx.ScalarType.string_type
				}),
			]
		})
	}
	return cx.Element{
		name:  'request'
		attrs: [
			cx.Attribute{
				name:  'method'
				value: cx.ScalarValue(method)
			},
			cx.Attribute{
				name:  'path'
				value: cx.ScalarValue(path)
			},
		]
		items: items
	}
}

fn w4_status(n cx.Node) int {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'status' {
				return cx.scalar_value_str_public(a.value).int()
			}
		}
	}
	return 0
}

fn w4_body(n cx.Node) string {
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

fn w4_header(n cx.Node, name string) string {
	if n is cx.Element {
		for it in n.items {
			if it is cx.Element && it.name == 'headers' {
				for h in it.items {
					if h is cx.Element && h.name == 'header' {
						if csrp_attr(h, 'name') == name {
							return csrp_attr(h, 'value')
						}
					}
				}
			}
		}
	}
	return ''
}

// ── #190: put dedup → stored=false on the second put ──────────────────────────

fn test_put_dedup_stored_flag() {
	caps_set_all()
	local := w4_open('dedup')
	doc := '[note [title "dedup-probe"]]'
	r1 := store_csrp_route(w4_req('POST', '/cx-store/v1/put', doc), local)
	assert w4_status(r1) == 200, 'first put 200'
	assert w4_body(r1).contains('stored="true"'), 'first put must be stored=true; got ${w4_body(r1)}'
	r2 := store_csrp_route(w4_req('POST', '/cx-store/v1/put', doc), local)
	assert w4_status(r2) == 200, 'second put 200'
	assert w4_body(r2).contains('stored="false"'), 'second put of the same doc must be stored=false (content dedup, #190); got ${w4_body(r2)}'
	// hash echo is identical (content-addressed)
	assert w4_body(r1).contains('hash=') && w4_body(r2).contains('hash='), 'both carry the hash echo'
}

// ── #196: unknown op → 404 CXER1709 (not 500-class CXER1707) ──────────────────

fn test_unknown_op_404_cxer1709() {
	caps_set_all()
	local := w4_open('unknownop')
	r := store_csrp_route(w4_req('POST', '/cx-store/v1/frobnicate', '[x]'), local)
	assert w4_status(r) == 404, 'unknown op must be 404; got ${w4_status(r)}'
	assert w4_body(r).contains('CXER1709'), 'unknown op must carry CXER1709 (404-class), not CXER1707; got ${w4_body(r)}'
}

// ── #191 + #196 + #193: via svc_handle_request (the daemon router) ─────────────

fn w4_ctx(rpm f64) ServeContext {
	caps_set_all()
	mut lim := new_limiter(LimitConfig{
		per_principal_rate: rpm / 60.0
		per_principal_conc: 64
		pre_auth_rate:      rpm / 60.0
		pre_auth_burst:     1.0 // tiny burst so the 2nd pre-auth request trips
	})
	return ServeContext{
		mounts:  {
			'docs': w4_open('svc')
		}
		limiter: lim
	}
}

fn test_rate_limit_has_retry_after() {
	mut s := new_service_state()
	s.mark_ready()
	ctx := w4_ctx(60.0)
	// first request consumes the tiny pre-auth burst; the second trips 429.
	_ := svc_handle_request(w4_req('GET', '/cx-store/v1/capabilities', ''), mut s, ctx)
	mut got429 := false
	for _ in 0 .. 5 {
		r := svc_handle_request(w4_req('POST', '/cx-store/v1/docs/list', ''), mut s, ctx)
		if w4_status(r) == 429 {
			got429 = true
			assert w4_header(r, 'Retry-After') != '', '429 must carry a Retry-After header (#191); headers missing'
			break
		}
	}
	assert got429, 'expected a 429 under the tiny pre-auth burst'
}

fn test_per_store_capabilities_and_unknown_404() {
	mut s := new_service_state()
	s.mark_ready()
	caps_set_all()
	ctx := ServeContext{
		mounts: {
			'docs': w4_open('caps')
		}
	}
	// server-level: no backend fields, cxbin advertised
	srv := svc_handle_request(w4_req('GET', '/cx-store/v1/capabilities', ''), mut s, ctx)
	assert w4_status(srv) == 200
	assert w4_body(srv).contains('"cxbin"'), 'server-level caps must advertise cxbin (#193); got ${w4_body(srv)}'
	// per-store: backend-name + query-features + real flags
	per := svc_handle_request(w4_req('GET', '/cx-store/v1/docs/capabilities', ''), mut s, ctx)
	assert w4_status(per) == 200
	assert w4_body(per).contains('backend-name'), 'per-store caps must carry backend-name (#193)'
	assert w4_body(per).contains('query-features'), 'per-store caps must carry query-features (#193)'
	// unknown store → 404 CXER1710 (not an oracle-free 200)
	unk := svc_handle_request(w4_req('GET', '/cx-store/v1/nope/capabilities', ''), mut s, ctx)
	assert w4_status(unk) == 404, 'unknown-store capabilities must 404 (#193), not 200; got ${w4_status(unk)}'
	assert w4_body(unk).contains('CXER1710'), 'unknown-store 404 carries CXER1710'
}

fn test_request_size_cap_413() {
	mut s := new_service_state()
	s.mark_ready()
	caps_set_all()
	ctx := ServeContext{
		mounts: {
			'docs': w4_open('big')
		}
	}
	// a body over the 16 MiB cap → 413 CXER1705 (#196; was unreachable).
	big := '['.repeat(1) + 'x'.repeat(int(svc_max_request_bytes) + 16) + ']'
	r := svc_handle_request(w4_req('POST', '/cx-store/v1/docs/put', big), mut s, ctx)
	assert w4_status(r) == 413, 'oversized body must be 413 (#196); got ${w4_status(r)}'
	assert w4_body(r).contains('CXER1705'), '413 carries CXER1705'
}

// ── #194: gRPC status maps carry the exact cx-err:CXERnnnn ─────────────────────

fn test_grpc_trailer_cxer() {
	// 413 and 429 share RESOURCE_EXHAUSTED(8) but the cx_err disambiguates.
	s413 := grpc_status_for_cxer('cx-err:CXER1705')
	s429 := grpc_status_for_cxer('cx-err:CXER1706')
	assert s413.code == grpc_resource_exhausted && s429.code == grpc_resource_exhausted, 'both are RESOURCE_EXHAUSTED'
	assert s413.cx_err == 'cx-err:CXER1705', 'trailer must carry exact CXER1705, got ${s413.cx_err}'
	assert s429.cx_err == 'cx-err:CXER1706', 'trailer must carry exact CXER1706, got ${s429.cx_err}'
	// 1709/1710 mapped (W0 parity rows)
	assert grpc_status_for_cxer('cx-err:CXER1709').code == grpc_unimplemented
	assert grpc_status_for_cxer('cx-err:CXER1710').code == grpc_not_found
}

// ── #198: config-invalid uses CXER1711, NOT CXER1140 (handle-race) ────────────

fn test_config_error_code_distinct() {
	if _ := parse_service_config('[not-a-service-config]') {
		assert false, 'bad config must be rejected'
	} else {
		assert err.msg().contains('CXER1711'), 'config error must be CXER1711 E_SVC_CONFIG_INVALID (#198), not CXER1140; got ${err.msg()}'
		assert !err.msg().contains('CXER1140'), 'config error must NOT reuse CXER1140 (handle-race)'
	}
}
