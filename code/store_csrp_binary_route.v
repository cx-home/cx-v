module code

import cx

// store_csrp_binary_route.v — the server side of the approved CSRP binary wire
// (#182). Reads BODY-carried operation params (the approved §3.3-§3.8 form,
// replacing the retired URL query-param form) in the negotiated encoding (cxbin
// default / cxd), dispatches through the SAME store ops as the cxd path, and
// encodes responses per §3.2/§3.4/§3.6/§3.7: raw ast_bin for `/get`, ast_bin
// result elements for put/delete/list/modify, and length-prefixed streaming
// frames for `/query` and `/iter`. The frame codec lives in store_csrp_wire.v.

// csrp_body_param reads a scalar param from the request's body op-element (e.g.
// `hash` on `[get hash="…"]`), or a nested `[<name> …]` child's scalar value
// (e.g. `limit`/`cxpath` on `[query [cxpath "…"][limit 100]]`). Empty if absent.
fn csrp_body_param(op_elem cx.Element, name string) string {
	// attribute form: [get hash="…"]
	for a in op_elem.attrs {
		if a.name == name {
			return cx.scalar_value_str_public(a.value)
		}
	}
	// child-element form: [query [cxpath "…"] [limit 100]]
	for it in op_elem.items {
		if it is cx.Element && it.name == name {
			for c in it.items {
				if c is cx.ScalarNode {
					return cx.scalar_value_str_public(c.value)
				}
				if c is cx.TextNode {
					return c.value
				}
			}
		}
	}
	return ''
}

// csrp_ast_bin_of_text encodes a canonical doc TEXT as ast_bin bytes (a Document,
// decoded by cx.bin_to_doc) for a get-body / doc-pair payload. Empty on parse
// failure. Uniform Document framing so the client decodes every doc body the same
// way (§2.1: "request bodies as ast_bin … decodes to the same value").
fn csrp_ast_bin_of_text(text string) []u8 {
	doc := cx.parse(text) or { return []u8{} }
	if doc.elements.len == 0 {
		return []u8{}
	}
	return cx.emit_ast_bin(doc)
}

// csrp_ast_bin_of_node encodes a result element (e.g. [put-result …]) as ast_bin.
fn csrp_ast_bin_of_node(n cx.Node) []u8 {
	return cx.emit_node_bin(n)
}

// store_csrp_route_binary handles one data op in the approved binary wire and
// returns the response node (body = raw bytes: ast_bin or a frame stream). The
// op is taken from the path; params come from the decoded body. `local` is the
// resolved mount. Falls back to a cxd err node on a malformed body.
fn store_csrp_route_binary(req cx.Element, local cx.Node, op string) cx.Node {
	match op {
		'get' {
			return csrp_bin_get(req, local)
		}
		'put' {
			return csrp_bin_put(req, local)
		}
		'delete' {
			return csrp_bin_delete(req, local)
		}
		'list' {
			return csrp_bin_list(req, local)
		}
		'iter' {
			return csrp_bin_iter(req, local)
		}
		'query' {
			return csrp_bin_query(req, local)
		}
		'modify' {
			return csrp_bin_modify(req, local)
		}
		else {
			return csrp_resp(404, '[err code="cx-err:CXER1709" message="E_CSRP_OPERATION_UNSUPPORTED: ${csrp_msg_esc(op)}"]')
		}
	}
}

// csrp_resp_bin builds a 200 response whose body is raw bytes, with the given
// Content-Type (§2.1 media types).
fn csrp_resp_bin(content_type string, payload []u8) cx.Node {
	return csrp_resp_hdrs(200, payload.bytestr(), [['Content-Type', content_type]])
}

// csrp_bin_get: `[get hash="…"]` → raw ast_bin doc (200), or a terminal 0x03
// error frame (404 CXER1721 miss / 422 CXER1720 integrity).
fn csrp_bin_get(req cx.Element, local cx.Node) cx.Node {
	hash := csrp_bin_hash(req)
	r := store_stdlib_builtin_inner('store-get-doc-text', [local, store_str(hash)]) or {
		return csrp_resp_hdrs(422, csrp_wire_error('cx-err:CXER1720', 'E_CSRP_INTEGRITY_MISMATCH: ${csrp_msg_esc(err.msg())}').bytestr(),
			[['Content-Type', csrp_ct_frame_stream]])
	}
	if r is cx.ScalarNode {
		return csrp_resp_bin(csrp_ct_astbin, csrp_ast_bin_of_text(csrp_scalar(r)))
	}
	// absence channel → 404 not-found, as a 0x03 error frame (§3.3).
	return csrp_resp_hdrs(404, csrp_wire_error('cx-err:CXER1721', 'E_CSRP_NOT_FOUND: ${csrp_msg_esc(hash)}').bytestr(),
		[['Content-Type', csrp_ct_frame_stream]])
}

// csrp_bin_put: the body IS the raw doc (§3.4); store it, return an ast_bin
// [put-result hash stored]. The dedup flag is the real content-address signal.
fn csrp_bin_put(req cx.Element, local cx.Node) cx.Node {
	enc := csrp_req_encoding(req)
	body := http_body_octets(req)
	// decode the doc to its canonical text (the store's put-doc-text surface).
	text := if enc == 'cxbin' {
		d := cx.bin_to_doc(body) or {
			return csrp_resp(400, '[err code="cx-err:CXER1701" message="E_CSRP_REQUEST_MALFORMED: undecodable cxbin put body"]')
		}
		if d.elements.len == 0 {
			return csrp_resp(400, '[err code="cx-err:CXER1701" message="E_CSRP_REQUEST_MALFORMED: empty put body"]')
		}
		render_canonical(d.elements[0])
	} else {
		body.bytestr()
	}
	// dedup: exists-before-put (atomic under the route's op-lock).
	mut existed := false
	canonical := cx.cx_text_canonical(text) or { '' }
	if canonical != '' {
		if h := cx.cx_text_hash(canonical) {
			ex := store_stdlib_builtin_inner('store-exists', [local, store_str(h)]) or {
				store_bool(false)
			}
			existed = csrp_scalar(ex) == 'true'
		}
	}
	r := store_stdlib_builtin_inner('store-put-doc-text', [local, store_str(text)]) or {
		return csrp_resp(400, '[err code="cx-err:CXER1701"]')
	}
	if is_err_value(r) {
		if svc_err_code(r) == 'cx-err:CXER1131' {
			return csrp_resp(401, '[err code="cx-err:CXER1702" message="E_CSRP_AUTH_REQUIRED: ${csrp_msg_esc(svc_err_msg(r))}"]')
		}
		return csrp_resp(400, '[err code="cx-err:CXER1701" message="E_CSRP_REQUEST_MALFORMED: ${csrp_msg_esc(svc_err_msg(r))}"]')
	}
	stored := if existed { 'false' } else { 'true' }
	result := cx.parse('[put-result hash="${csrp_scalar(r)}" stored=${stored}]') or {
		return csrp_resp(500, '[err code="cx-err:CXER1707"]')
	}
	return csrp_resp_bin(csrp_ct_astbin, cx.emit_ast_bin(result))
}

// csrp_bin_delete: `[delete hash="…"]` → ast_bin [delete-result …].
fn csrp_bin_delete(req cx.Element, local cx.Node) cx.Node {
	hash := csrp_bin_hash(req)
	r := store_stdlib_builtin_inner('store-delete-doc', [local, store_str(hash)]) or {
		return csrp_resp(500, '[err code="cx-err:CXER1707"]')
	}
	deleted := csrp_scalar(r)
	result := cx.parse('[delete-result hash="${hash}" deleted=${deleted}]') or {
		return csrp_resp(500, '[err code="cx-err:CXER1707"]')
	}
	return csrp_resp_bin(csrp_ct_astbin, cx.emit_ast_bin(result))
}

// csrp_bin_list: `[list [limit N][cursor "…"]]` → ast_bin
// [list-result [hashes [sequence …]] [next-cursor "…"] [total-count N]] with
// limit/offset-cursor pagination (§3.6).
fn csrp_bin_list(req cx.Element, local cx.Node) cx.Node {
	limit, offset := csrp_bin_limit_offset(req, 'list')
	r := store_stdlib_builtin_inner('store-list-docs', [local]) or {
		return csrp_resp(500, '[err code="cx-err:CXER1707"]')
	}
	mut hashes := []string{}
	if r is cx.Element {
		for it in r.items {
			h := csrp_scalar(it)
			if h != '' {
				hashes << h
			}
		}
	}
	total := hashes.len
	page, next_cursor := csrp_paginate(hashes, limit, offset)
	mut seq := '[sequence'
	for h in page {
		seq += ' "${h}"'
	}
	seq += ']'
	result := cx.parse('[list-result [hashes ${seq}] [next-cursor "${next_cursor}"] [total-count ${total}]]') or {
		return csrp_resp(500, '[err code="cx-err:CXER1707"]')
	}
	return csrp_resp_bin(csrp_ct_astbin, cx.emit_ast_bin(result))
}

// csrp_bin_iter: `[iter [cursor "…"]]` → a stream of 0x01 doc-pair frames + a
// terminal 0x04 end. Cursor is the offset into the stable list order.
fn csrp_bin_iter(req cx.Element, local cx.Node) cx.Node {
	_, offset := csrp_bin_limit_offset(req, 'iter')
	r := store_stdlib_builtin_inner('store-list-docs', [local]) or {
		return csrp_resp(500, '[err code="cx-err:CXER1707"]')
	}
	mut hashes := []string{}
	if r is cx.Element {
		for it in r.items {
			h := csrp_scalar(it)
			if h != '' {
				hashes << h
			}
		}
	}
	mut stream := []u8{}
	mut n := u32(0)
	for i, h in hashes {
		if i < offset {
			continue
		}
		t := store_stdlib_builtin_inner('store-get-doc-text', [local, store_str(h)]) or { continue }
		if t is cx.ScalarNode {
			stream << csrp_wire_docframe(csrp_frame_docpair, h, csrp_ast_bin_of_text(csrp_scalar(t)))
			n++
		}
	}
	stream << csrp_wire_end(n)
	return csrp_resp_bin(csrp_ct_frame_stream, stream)
}

// csrp_bin_query: `[query [cxpath "…"][limit][offset][shape "matches|aggregate"]]`
// → a stream of 0x02 match frames + 0x04 end, OR (shape="aggregate", the cxpath
// an aggregate function-head) a single terminal 0x05 aggregate-result frame.
fn csrp_bin_query(req cx.Element, local cx.Node) cx.Node {
	op_elem := csrp_bin_op_elem(req) or { cx.Element{} }
	cxpath := csrp_body_param(op_elem, 'cxpath')
	shape := csrp_body_param(op_elem, 'shape')
	limit, offset := csrp_bin_limit_offset(req, 'query')
	if cxpath == '' {
		return csrp_resp_hdrs(400, csrp_wire_error('cx-err:CXER1701', 'E_CSRP_REQUEST_MALFORMED: query requires a cxpath').bytestr(),
			[['Content-Type', csrp_ct_frame_stream]])
	}
	r := store_stdlib_builtin_inner('store-query', [local, store_str(cxpath)]) or {
		return csrp_resp_hdrs(200, csrp_wire_error('cx-err:CXER1700', 'E_CSRP_QUERY_FAILED: ${csrp_msg_esc(err.msg())}').bytestr(),
			[['Content-Type', csrp_ct_frame_stream]])
	}
	if is_err_value(r) {
		return csrp_resp_hdrs(200, csrp_wire_error(svc_err_code_or(r, 'cx-err:CXER1700'),
			'E_CSRP_QUERY_FAILED: ${csrp_msg_esc(svc_err_msg(r))}').bytestr(), [['Content-Type', csrp_ct_frame_stream]])
	}
	// aggregate pushdown: a scalar result under shape="aggregate" → 0x05.
	if shape == 'aggregate' {
		agg := csrp_aggregate_scalar(r)
		result := cx.parse('[aggregate-result value=${agg}]') or { cx.Document{} }
		return csrp_resp_bin(csrp_ct_frame_stream, csrp_wire_aggregate(cx.emit_ast_bin(result)))
	}
	// matches: each [result hash=H [matches…]] → a 0x02 match frame, paginated.
	mut stream := []u8{}
	mut n := u32(0)
	mut idx := 0
	if r is cx.Element {
		for result in r.items {
			if result is cx.Element && result.name == 'result' {
				if idx < offset {
					idx++
					continue
				}
				idx++
				if limit > 0 && int(n) >= limit {
					break
				}
				h := csrp_attr(result, 'hash')
				stream << csrp_wire_docframe(csrp_frame_match, h, cx.emit_node_bin(result))
				n++
			}
		}
	}
	stream << csrp_wire_end(n)
	return csrp_resp_bin(csrp_ct_frame_stream, stream)
}

// csrp_bin_modify: `[modify hash="…" action=[…]]` → ast_bin [modify-result …].
fn csrp_bin_modify(req cx.Element, local cx.Node) cx.Node {
	op_elem := csrp_bin_op_elem(req) or {
		return csrp_resp(400, '[err code="cx-err:CXER1701"]')
	}
	hash := csrp_body_param(op_elem, 'hash')
	mut action := cx.Node(cx.Element{})
	for a in op_elem.attrs {
		if a.name == 'action' {
			// action carried as an attribute value string → parse it
			if av := cx.parse(cx.scalar_value_str_public(a.value)) {
				if av.elements.len > 0 {
					action = av.elements[0]
				}
			}
		}
	}
	for it in op_elem.items {
		if it is cx.Element && it.name == 'action' {
			if it.items.len > 0 {
				action = it.items[0]
			} else {
				action = it
			}
		}
	}
	r := store_stdlib_builtin_inner('store-modify-doc', [local, store_str(hash), action]) or {
		return csrp_resp(500, '[err code="cx-err:CXER1707"]')
	}
	if is_err_value(r) {
		return csrp_resp(404, '[err code="cx-err:CXER1721" message="E_CSRP_NOT_FOUND: ${csrp_msg_esc(svc_err_msg(r))}"]')
	}
	nh := csrp_scalar(r)
	result := cx.parse('[modify-result old-hash="${hash}" new-hash="${nh}" stored=true]') or {
		return csrp_resp(500, '[err code="cx-err:CXER1707"]')
	}
	return csrp_resp_bin(csrp_ct_astbin, cx.emit_ast_bin(result))
}

// ── small helpers ─────────────────────────────────────────────────────────────

fn csrp_bin_op_elem(req cx.Element) ?cx.Element {
	doc := csrp_decode_request_body(req)?
	return csrp_req_op_elem(doc)
}

// csrp_bin_hash reads the hash from the body op-element, or the legacy `?hash=`
// query-param (transition compatibility).
fn csrp_bin_hash(req cx.Element) string {
	if op_elem := csrp_bin_op_elem(req) {
		h := csrp_body_param(op_elem, 'hash')
		if h != '' {
			return h
		}
	}
	return csrp_query(req, 'hash')
}

// csrp_bin_limit_offset reads limit/offset from the body op-element (0 = unset).
fn csrp_bin_limit_offset(req cx.Element, op string) (int, int) {
	op_elem := csrp_bin_op_elem(req) or { return 0, 0 }
	limit := csrp_body_param(op_elem, 'limit').int()
	mut offset := csrp_body_param(op_elem, 'offset').int()
	if offset == 0 {
		// cursor is an opaque offset token for list/iter (§3.6/§3.7).
		offset = csrp_body_param(op_elem, 'cursor').int()
	}
	return limit, offset
}

// csrp_paginate returns the `limit`-sized page starting at `offset` and the
// next-cursor (empty when the page reaches the end).
fn csrp_paginate(all []string, limit int, offset int) ([]string, string) {
	if offset >= all.len {
		return []string{}, ''
	}
	mut end := all.len
	if limit > 0 && offset + limit < end {
		end = offset + limit
	}
	page := all[offset..end].clone()
	next := if end < all.len { end.str() } else { '' }
	return page, next
}

// csrp_aggregate_scalar extracts a scalar aggregate value from a query result
// (the store returns matches; the count is the match total for count(...)).
fn csrp_aggregate_scalar(r cx.Node) string {
	mut n := 0
	if r is cx.Element {
		for it in r.items {
			if it is cx.Element && it.name == 'result' {
				n++
			}
		}
	}
	return n.str()
}

fn svc_err_code_or(n cx.Node, dflt string) string {
	c := svc_err_code(n)
	return if c != '' { c } else { dflt }
}
