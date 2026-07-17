module code

import cx

// store_csrp_conformance_test.v — #208: the CSRP §7 conformance items that a
// pure-.cxd fixture cannot express (they need raw HTTP framing / binary bodies)
// live here as V wire tests. This file covers the §7 items NOT already asserted in
// a sibling test, and documents where the rest are covered:
//
//   §7 item                          | covered by
//   ---------------------------------|--------------------------------------------
//   capabilities discovery           | store_discovery_test.v / store_keepalive_test.v
//   query pushdown                   | store_csrp_test.v (live) / store_binary_wire_test.v
//   aggregate pushdown (0x05)        | store_binary_wire_test.v (test_binary_query_frames)
//   streaming response framing       | store_binary_wire_test.v (iter/query frames)
//   cross-encoding parity            | THIS FILE (test_csrp_cross_encoding_parity)
//   auth required / rejected 401/403 | store_authz_test.v
//   not found CXER1721               | store_binary_wire_test.v (test_binary_get_miss_error_frame)
//   integrity mismatch /get 422 1720 | store_binary_wire_test.v (csrp_bin_get 422 path)
//   put dedup stored=false           | store_binary_wire_test.v (test_binary_put_get_roundtrip)
//   modify new hash                  | store_csrp_test.v (test_csrp_modify_pushdown)
//   connection reuse                 | store_keepalive_test.v
//   capability-driven fallback       | THIS FILE (test_csrp_capability_driven_fallback)
//   cross-tier portability           | store_grpc_parity_test.v (test_porcelain_cross_tier_over_http)
//   multi-store isolation            | store_authz_test.v / store_service_test.v
//   unknown store-name CXER1710      | store_cluster_residuals_test.v (#204)
//   unknown operation CXER1709       | store_csrp_test.v / store_service_test.v (#196)
//   rate limiting CXER1706 + Retry-After | store_service_test.v (limiter) — 429 body carries Retry-After
//   delete/list/capabilities + cx-err-code trailer parity | store_grpc_parity_test.v (#208.2)

fn cf_open(tag string) cx.Node {
	return store_open_impl('mem://cf-${tag}', '', '', false, true, map[string]string{})
}

// test_csrp_cross_encoding_parity — §7 "Cross-encoding parity: cxbin and cxd
// response encodings produce identical doc IDs at the client." A get over the
// binary wire returns raw ast_bin; a get over the cxd path returns canonical text.
// Both decode to the SAME doc and therefore the SAME content hash.
fn test_csrp_cross_encoding_parity() {
	caps_set_all()
	local := cf_open('xenc')
	doc_text := '[record [k "v"] [nested [a 1] [b 2]]]'
	// store it, learn the key.
	put := store_csrp_route(cf_bin_req('put', cf_astbin(doc_text)), local)
	hash := csrp_attr((cx.bin_to_doc(cf_body(put)) or { panic('d') }).elements[0] as cx.Element,
		'hash')
	assert hash.len == 64, 'put hash'

	// (a) cxbin GET — raw ast_bin doc body → decode → canonical → hash.
	gb := store_csrp_route(cf_bin_req('get', cf_astbin('[get hash="${hash}"]')), local)
	cxbin_doc := cx.bin_to_doc(cf_body(gb)) or {
		assert false, 'cxbin get body must be ast_bin'
		return
	}
	cxbin_hash := cx.cx_text_hash(render_canonical(cxbin_doc.elements[0])) or { 'x' }

	// (b) cxd GET — the negotiated text encoding; body is canonical cx text.
	gd := store_csrp_route(cf_cxd_get_req(hash), local)
	cxd_text := cf_body(gd).bytestr()
	cxd_doc := cx.parse(cxd_text) or {
		assert false, 'cxd get body must be parseable cx text; got: ${cxd_text}'
		return
	}
	cxd_hash := cx.cx_text_hash(render_canonical(cxd_doc.elements[0])) or { 'y' }

	// identical doc IDs across encodings (§7 cross-encoding parity).
	assert cxbin_hash == hash, 'cxbin get rehashes to the key'
	assert cxd_hash == hash, 'cxd get rehashes to the key'
	assert cxbin_hash == cxd_hash, 'cxbin and cxd encodings must produce identical doc IDs: cxbin=${cxbin_hash} cxd=${cxd_hash}'
}

// test_csrp_capability_driven_fallback — §7 "Capability-driven fallback: server
// reports push-down-filter=false; client falls back to list+get." The per-store
// capability advert exposes the real query flag; when a backend cannot push a query
// down, store_remote_query must surface CXER1709 (op unsupported) rather than a
// silent empty result, so the caller can fall back to a client-side list+get scan.
fn test_csrp_capability_driven_fallback() {
	caps_set_all()
	// a plain byte-source backend (no query surface) reports the unsupported op
	// distinctly (never a silent empty result) — the signal a client uses to fall
	// back to list+get. Build a RemoteBackend for a non-CSRP scheme and query it.
	rb, _, ok := store_remote_parse('s3://bucket/prefix/')
	if !ok {
		// s3 parse needs AWS env; skip the s3 arm but assert the http arm below.
		eprintln('SKIP: s3 parse (no AWS env) — http arm still asserts fallback signal')
	} else {
		q := store_remote_query(rb, '//x')
		assert is_err_value(q) && svc_err_code(q) == 'cx-err:CXER1709', 'a no-query-surface backend must report CXER1709 (fallback signal), not a silent empty result; got: ${q}'
	}
	rbh, _, okh := store_remote_parse('http://example.invalid/store/')
	assert okh, 'http parse'
	qh := store_remote_query(rbh, '//x')
	assert is_err_value(qh) && svc_err_code(qh) == 'cx-err:CXER1709', 'http byte-source query must report CXER1709 (capability-driven fallback signal); got: ${qh}'
}

// ── helpers (binary + cxd request builders, mirroring store_binary_wire_test) ──

fn cf_astbin(text string) []u8 {
	d := cx.parse(text) or { panic('parse ${text}') }
	return cx.emit_ast_bin(d)
}

fn cf_body(n cx.Node) []u8 {
	if n is cx.Element {
		for it in n.items {
			if it is cx.Element && it.name == 'body' {
				for b in it.items {
					if b is cx.ScalarNode {
						return cx.scalar_value_str_public(b.value).bytes()
					}
				}
			}
		}
	}
	return []u8{}
}

fn cf_hdr(name string, val string) cx.Node {
	return cx.Node(cx.Element{
		name:  'header'
		attrs: [
			cx.Attribute{
				name:  'name'
				value: cx.ScalarValue(name)
			},
			cx.Attribute{
				name:  'value'
				value: cx.ScalarValue(val)
			},
		]
	})
}

fn cf_bin_req(op string, body_bytes []u8) cx.Element {
	return cx.Element{
		name:  'request'
		attrs: [
			cx.Attribute{
				name:  'method'
				value: cx.ScalarValue('POST')
			},
			cx.Attribute{
				name:  'path'
				value: cx.ScalarValue('/cx-store/v1/${op}')
			},
		]
		items: [
			cx.Node(cx.Element{
				name:  'headers'
				items: [
					cf_hdr('Content-Type', csrp_ct_astbin),
					cf_hdr('Accept', csrp_ct_frame_stream),
				]
			}),
			cx.Node(cx.Element{
				name:  'body'
				items: [
					cx.Node(cx.ScalarNode{
						value:     cx.ScalarValue(body_bytes.bytestr())
						data_type: cx.ScalarType.string_type
					}),
				]
			}),
		]
	}
}

// cf_cxd_get_req builds a cxd-encoded get: NO binary negotiation headers, the op
// carried as a cxd-text body → routes down the non-binary (cxd) path.
fn cf_cxd_get_req(hash string) cx.Element {
	return cx.Element{
		name:  'request'
		attrs: [
			cx.Attribute{
				name:  'method'
				value: cx.ScalarValue('POST')
			},
			cx.Attribute{
				name:  'path'
				value: cx.ScalarValue('/cx-store/v1/get')
			},
		]
		items: [
			cx.Node(cx.Element{
				name:  'headers'
				items: [
					cf_hdr('Content-Type', csrp_ct_cxd),
				]
			}),
			// the parser separates the target's query string into query-params; the
			// non-binary (cxd) get path reads the hash from there.
			cx.Node(cx.Element{
				name:  'query-params'
				items: [
					cx.Node(cx.Element{
						name:  'hash'
						items: [
							cx.Node(cx.ScalarNode{
								value:     cx.ScalarValue(hash)
								data_type: cx.ScalarType.string_type
							}),
						]
					}),
				]
			}),
		]
	}
}
