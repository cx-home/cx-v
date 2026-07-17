module code

import cx

// store_cluster_residuals_test.v — the CODE residuals of the W0 spec-cluster
// issues #203/#204/#205 (the spec halves graduated in #225). #204 unknown-store
// wire code, #205 subtree+ reject / unsupported-param / compression fail-closed.

fn wr_req(method string, path string) cx.Element {
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
		items: [
			cx.Node(cx.Element{
				name:  'headers'
				items: []
			}),
		]
	}
}

fn wr_err_code(n cx.Node) string {
	if n is cx.Element && n.name == 'err' {
		for a in n.attrs {
			if a.name == 'code' {
				return cx.scalar_value_str_public(a.value)
			}
		}
	}
	return ''
}

fn wr_body(n cx.Node) string {
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

fn wr_status(n cx.Node) int {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'status' {
				return cx.scalar_value_str_public(a.value).int()
			}
		}
	}
	return 0
}

// ── #204: data-op on an unknown store-name → 404 CXER1710 (not std-lib 1121) ──

fn test_dataop_unknown_store_1710() {
	mut s := new_service_state()
	s.mark_ready()
	caps_set_all()
	ctx := ServeContext{
		mounts: {
			'docs': store_open_impl('mem://wr-204', '', '', false, true, map[string]string{})
		}
	}
	resp := svc_handle_request(wr_req("POST", '/cx-store/v1/nope/list'),
		mut s, ctx)
	assert wr_status(resp) == 404, 'unknown-store data op → 404'
	assert wr_body(resp).contains('CXER1710'), 'unknown-store wire code is CXER1710 (#204, not std-lib 1121): ${wr_body(resp)}'
	assert !wr_body(resp).contains('CXER1121'), 'std-lib CXER1121 must not ride the wire'
}

// ── #205.5: subtree+ is never written → hard error ────────────────────────────

fn test_subtree_prefix_rejected() {
	caps_set_all()
	r := store_open_impl('subtree+mem://wr-205-sub', '', '', false, true, map[string]string{})
	assert wr_err_code(r) == 'cx-err:CXER1100', 'subtree+ must be rejected (#205.5), got ${wr_err_code(r)}'
}

// ── #205.4: unsupported URI query param → hard error (not silently ignored) ───

fn test_unsupported_query_param_rejected() {
	caps_set_all()
	r := store_open_impl('mem://wr-205-cache?cache=file:///tmp/c', '', '', false, true,
		map[string]string{})
	assert wr_err_code(r) == 'cx-err:CXER1100', '?cache= (unimplemented) must be rejected (#205.4), got ${wr_err_code(r)}'
	// recognized params still work
	ok := store_open_impl('mem://wr-205-enc?encoding=cxbin', '', '', false, true, map[string]string{})
	assert wr_err_code(ok) == '', 'recognized ?encoding= must open: ${wr_err_code(ok)}'
}

// ── #205.2: non-none compression fail-closed on a durable substrate ───────────

fn test_compression_fail_closed() {
	caps_set_all()
	root := '/tmp/wr-205-comp-${cx.cx_text_hash('c') or { 'x' }[..8]}'
	r := store_open_impl('file://${root}', 'zst', '', false, true, map[string]string{})
	assert wr_err_code(r) == 'cx-err:CXER1100', 'non-none compression on file:// must fail-closed (#205.2), got ${wr_err_code(r)}'
	// none (and unset) open fine
	ok := store_open_impl('file://${root}-none', 'none', '', false, true, map[string]string{})
	assert wr_err_code(ok) == '', 'compression=none opens: ${wr_err_code(ok)}'
}

// ── #203.2: attr-exact config validation (unknown attr → fast-fail) ───────────

fn test_config_attr_exact() {
	// an unknown attribute in a known section is rejected (not silently dropped).
	if _ := parse_service_config('[cxstore-service [bind addr="h:1" bogus="x"] [stores [store name="s" url="mem://s"]]]') {
		assert false, 'unknown [bind] attr `bogus` must fail-fast (#203.2)'
	}
	// a well-formed config still parses
	c := parse_service_config('[cxstore-service [bind addr="h:1"] [timeouts read-ms=5000] [stores [store name="s" url="mem://s"]]]') or {
		panic('valid config rejected: ${err}')
	}
	assert c.read_timeout_ms == 5000
}

// ── #205.4: document+ftp:// no longer trips CXER1100 on the model prefix ──────
// (the prefix is stripped before store_remote_parse; ftp then needs net, absent
// here → the honest net-denial, NOT an unresolved-backend model-prefix error).

fn test_document_ftp_prefix_stripped() {
	caps_set_empty() // no net → the ftp open is net-denied, proving the prefix parsed
	r := store_open_impl('document+ftp://ftp.example.invalid/store/', '', '', false, true,
		map[string]string{})
	ec := wr_err_code(r)
	// must NOT be the model-prefix-rejection CXER1100 "unresolved backend"; it is
	// the net capability denial (CXER0271) — i.e. the prefix was accepted.
	assert ec == 'cx-err:CXER0271', 'document+ftp:// must strip the prefix and reach the net gate (#205.4), got ${ec}'
}
