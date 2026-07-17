@[has_globals]
module code

import cx
import sync

// #234.2: process-global discovery cache. The thin bindings (Python/Go/Rust) open
// a FRESH cx-store:// handle per operation, so an eager per-open /capabilities GET
// would double the request volume (open→discover + the op) and, under concurrent
// load, trip the daemon's DoS-fairness rate limiter (429). §5.3 discovery is a
// once-per-session concern, so we validate a given base_url ONCE per process and
// cache the result: subsequent opens to the same server skip the round trip. The
// cached value is the validated csrp-version, or a `!<msg>` sentinel for an
// incompatible server (so the failure is remembered, not re-probed every op).
__global (
	g_csrp_disco_mu &sync.Mutex
	g_csrp_disco    map[string]string
)

// store_csrp_client_bin.v — the CLIENT half of the approved CSRP binary wire
// (#182). The cx-store:// backend speaks the binary wire: body-carried cxbin
// operation requests (Content-Type application/cx-astbin) and ast_bin / frame-
// stream responses. This is the live production consumer of store_csrp_wire.v +
// store_csrp_binary_route.v, and it retires the URL query-param client form
// (§3.3-§3.8): the operation params ride in the request body, never the URL.

// csrp_client_version_major is the CSRP protocol major the client speaks. A server
// advertising a different major at /capabilities is incompatible → open fails
// (§5.3 semver validation), rather than failing cryptically on the first op.
const csrp_client_version_major = 1

// csrp_client_discover performs §5.3 capability discovery at open: GET the
// server-level /capabilities, validate the advertised csrp-version's major against
// the client's, and cache the version + supported encodings on `rb`. A version
// mismatch is a hard error (open fails). An UNREACHABLE server is tolerated — open
// stays lazy (caps_discovered=false), and the first op surfaces the transport
// fault — so discovery never turns a transient blip at open into a hard failure.
fn csrp_client_discover(mut rb RemoteBackend) cx.Node {
	// once-per-process per server: a validated (or known-incompatible) base_url is
	// cached, so the thin open-per-op bindings don't re-probe /capabilities on every
	// operation (which would double request volume and trip the rate limiter).
	if g_csrp_disco_mu != unsafe { nil } {
		g_csrp_disco_mu.lock()
		cached := g_csrp_disco[rb.base_url] or { '' }
		g_csrp_disco_mu.unlock()
		if cached != '' {
			if cached.starts_with('!') {
				return mk_err('cx-err:CXER1100', cached[1..])
			}
			rb.csrp_version = cached
			rb.caps_discovered = true
			return store_null()
		}
	}
	url := '${rb.base_url}/cx-store/v1/capabilities'
	mut headers := [][]string{}
	if rb.bearer != '' {
		headers << ['Authorization', 'Bearer ${rb.bearer}']
	}
	resp, _, ok := remote_http('GET', url, headers, []u8{})
	if !ok || resp.status != 200 {
		return store_null() // unreachable / older server without discovery: lazy open (not cached — retry next open)
	}
	doc := cx.parse(resp.body.bytestr()) or { return store_null() }
	for el in doc.elements {
		if el is cx.Element && el.name == 'capabilities' {
			ver := csrp_child_text(el, 'csrp-version')
			if ver != '' {
				// §5.3 step 2: same-major compatibility. A mismatch is a client-side
				// open-time failure (no wire error frame is involved), so it carries a
				// std-lib backend code (CXER1100), not a 17xx wire-response code.
				major := ver.all_before('.').int()
				if major != csrp_client_version_major {
					msg := 'E_STORE_UNRESOLVED_BACKEND: server csrp-version ${ver} is incompatible with the client (major ${csrp_client_version_major})'
					csrp_disco_cache_put(rb.base_url, '!${msg}') // remember the incompatibility
					return mk_err('cx-err:CXER1100', msg)
				}
				rb.csrp_version = ver
				csrp_disco_cache_put(rb.base_url, ver)
			}
			// cache the server's supported body encodings (for cxbin/cxd negotiation).
			for it in el.items {
				if it is cx.Element && it.name == 'encodings' {
					for sub in it.items {
						if sub is cx.Element && sub.name == 'supported' {
							for e in sub.items {
								enc := csrp_scalar(e)
								if enc != '' {
									rb.caps_encodings << enc
								}
							}
						}
					}
				}
			}
			rb.caps_discovered = true
			return store_null()
		}
	}
	return store_null()
}

// csrp_disco_cache_put records a base_url's discovery outcome (a validated version,
// or a `!<msg>` incompatibility sentinel) so later opens skip the /capabilities GET.
fn csrp_disco_cache_put(base_url string, val string) {
	if g_csrp_disco_mu == unsafe { nil } {
		return
	}
	g_csrp_disco_mu.lock()
	g_csrp_disco[base_url] = val
	g_csrp_disco_mu.unlock()
}

// csrp_child_text returns the scalar text of a `[name "…"]` child element, or ''.
fn csrp_child_text(el cx.Element, name string) string {
	for it in el.items {
		if it is cx.Element && it.name == name {
			for c in it.items {
				s := csrp_scalar(c)
				if s != '' {
					return s
				}
			}
		}
	}
	return ''
}

// csrp_bin_headers builds the binary-wire request headers: a cxbin body and an
// Accept that opts in to the frame-stream responses, plus optional bearer auth.
fn csrp_bin_headers(rb &RemoteBackend) [][]string {
	mut h := [['Content-Type', csrp_ct_astbin], ['Accept', csrp_ct_frame_stream]]
	if rb.bearer != '' {
		h << ['Authorization', 'Bearer ${rb.bearer}']
	}
	return h
}

// csrp_bin_wrap encodes a single operation element as a cxbin (ast_bin) request
// body — the element wrapped in a one-element Document. Built programmatically so
// arbitrary cxpath / attribute values need no text-quoting.
fn csrp_bin_wrap(el cx.Element) []u8 {
	return cx.emit_ast_bin(cx.Document{
		elements: [cx.Node(el)]
	})
}

fn csrp_attr_of(name string, val string) cx.Attribute {
	return cx.Attribute{
		name:  name
		value: cx.ScalarValue(val)
	}
}

// csrp_child_scalar builds `[name "value"]` as a child element carrying a scalar.
fn csrp_child_scalar(name string, val string) cx.Node {
	return cx.Node(cx.Element{
		name:  name
		items: [
			cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(val)
				data_type: cx.ScalarType.string_type
			}),
		]
	})
}

// ── get / has ─────────────────────────────────────────────────────────────────

// csrp_bin_client_get POSTs `[get hash="…"]` as cxbin and decodes the raw ast_bin
// doc response back to canonical text. A 404 (0x03 CXER1721 frame) → CXER1121.
fn csrp_bin_client_get(rb &RemoteBackend, hash string) (string, cx.Node, bool) {
	body := csrp_bin_wrap(cx.Element{
		name:  'get'
		attrs: [csrp_attr_of('hash', hash)]
	})
	resp, errn, ok := remote_http('POST', csrp_op_url(rb, 'get', ''), csrp_bin_headers(rb),
		body)
	if !ok {
		return '', errn, false
	}
	if resp.status == 404 {
		return '', mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: ${hash}'), false
	}
	if resp.status != 200 {
		return '', csrp_bin_status_err('get', hash, resp.body, resp.status), false
	}
	doc := cx.bin_to_doc(resp.body) or {
		return '', mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: csrp get: undecodable ast_bin body'), false
	}
	if doc.elements.len == 0 {
		return '', mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: ${hash}'), false
	}
	return render_canonical(doc.elements[0]), store_null(), true
}

fn csrp_bin_client_has(rb &RemoteBackend, hash string) (bool, cx.Node, bool) {
	body := csrp_bin_wrap(cx.Element{
		name:  'get'
		attrs: [csrp_attr_of('hash', hash)]
	})
	resp, errn, ok := remote_http('POST', csrp_op_url(rb, 'get', ''), csrp_bin_headers(rb),
		body)
	if !ok {
		return false, errn, false
	}
	return resp.status == 200, store_null(), true
}

// ── put / delete / modify ───────────────────────────────────────────────────

// csrp_bin_client_put sends the doc itself as the cxbin body (§3.4) and reads the
// ast_bin [put-result …] response.
fn csrp_bin_client_put(rb &RemoteBackend, hash string, text string) cx.Node {
	d := cx.parse(text) or {
		return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: csrp put: unparseable doc')
	}
	resp, errn, ok := remote_http('POST', csrp_op_url(rb, 'put', ''), csrp_bin_headers(rb),
		cx.emit_ast_bin(d))
	if !ok {
		return errn
	}
	if resp.status != 200 {
		return csrp_bin_status_err('put', hash, resp.body, resp.status)
	}
	return store_null()
}

fn csrp_bin_client_delete(rb &RemoteBackend, hash string) (bool, cx.Node, bool) {
	body := csrp_bin_wrap(cx.Element{
		name:  'delete'
		attrs: [csrp_attr_of('hash', hash)]
	})
	resp, errn, ok := remote_http('POST', csrp_op_url(rb, 'delete', ''), csrp_bin_headers(rb),
		body)
	if !ok {
		return false, errn, false
	}
	if resp.status != 200 {
		return false, csrp_bin_status_err('delete', hash, resp.body, resp.status), false
	}
	dr := cx.bin_to_doc(resp.body) or {
		return false, mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: csrp delete: undecodable result'), false
	}
	if dr.elements.len > 0 {
		el0 := dr.elements[0]
		if el0 is cx.Element {
			return csrp_attr(el0, 'deleted') == 'true', store_null(), true
		}
	}
	return false, store_null(), true
}

// csrp_bin_client_modify sends `[modify hash="…" [action …]]` as cxbin and reads
// the new content-address from the ast_bin [modify-result new-hash="…"] response.
fn csrp_bin_client_modify(rb &RemoteBackend, hash string, action_text string) cx.Node {
	ad := cx.parse(action_text) or {
		return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: csrp modify: unparseable action')
	}
	mut action_items := []cx.Node{}
	for e in ad.elements {
		action_items << e
	}
	body := csrp_bin_wrap(cx.Element{
		name:  'modify'
		attrs: [csrp_attr_of('hash', hash)]
		items: [
			cx.Node(cx.Element{
				name:  'action'
				items: action_items
			}),
		]
	})
	resp, errn, ok := remote_http('POST', csrp_op_url(rb, 'modify', ''), csrp_bin_headers(rb),
		body)
	if !ok {
		return errn
	}
	if resp.status == 404 {
		return mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: ${hash}')
	}
	if resp.status != 200 {
		return csrp_bin_status_err('modify', hash, resp.body, resp.status)
	}
	mr := cx.bin_to_doc(resp.body) or {
		return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: csrp modify: undecodable result')
	}
	if mr.elements.len > 0 {
		el0 := mr.elements[0]
		if el0 is cx.Element {
			nh := csrp_attr(el0, 'new-hash')
			if store_is_doc_hash(nh) {
				return store_str(nh)
			}
		}
	}
	return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: csrp modify: malformed modify-result')
}

// ── list ──────────────────────────────────────────────────────────────────────

// csrp_bin_client_list POSTs `[list]` and decodes the ast_bin
// [list-result [hashes [sequence "h1" "h2" …]] …] response into the hash list.
fn csrp_bin_client_list(rb &RemoteBackend) ([]string, cx.Node, bool) {
	body := csrp_bin_wrap(cx.Element{
		name: 'list'
	})
	resp, errn, ok := remote_http('POST', csrp_op_url(rb, 'list', ''), csrp_bin_headers(rb),
		body)
	if !ok {
		return []string{}, errn, false
	}
	if resp.status != 200 {
		return []string{}, csrp_bin_status_err('list', '', resp.body, resp.status), false
	}
	doc := cx.bin_to_doc(resp.body) or {
		return []string{}, mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: csrp list: undecodable result'), false
	}
	mut out := []string{}
	for el in doc.elements {
		if el is cx.Element && el.name == 'list-result' {
			for c in el.items {
				if c is cx.Element && c.name == 'hashes' {
					// hashes carry a nested [sequence "h1" "h2" …]
					for sq in c.items {
						if sq is cx.Element && sq.name == 'sequence' {
							for hn in sq.items {
								h := csrp_scalar(hn)
								if store_is_doc_hash(h) {
									out << h
								}
							}
						} else {
							// tolerate a flat [hash "…"] shape too
							h := csrp_scalar(sq)
							if store_is_doc_hash(h) {
								out << h
							}
						}
					}
				}
			}
		}
	}
	return out, store_null(), true
}

// ── query / iter (frame streams) ──────────────────────────────────────────────

// csrp_bin_client_query POSTs `[query [cxpath "…"][shape "matches"]]`, parses the
// 0x02 match frames, and reconstructs the SAME shape store_query returns
// (store_seq of [result hash=H (matches)]). A terminal 0x03 error frame → the
// carried CXER; a 404 → CXER1709 (op unsupported — never a silent empty result).
fn csrp_bin_client_query(rb &RemoteBackend, cxpath string) cx.Node {
	body := csrp_bin_wrap(cx.Element{
		name:  'query'
		items: [
			csrp_child_scalar('cxpath', cxpath),
			csrp_child_scalar('shape', 'matches'),
		]
	})
	resp, errn, ok := remote_http('POST', csrp_op_url(rb, 'query', ''), csrp_bin_headers(rb),
		body)
	if !ok {
		return errn
	}
	if resp.status == 404 {
		return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: the cx-store:// server does not support the query op')
	}
	if resp.status != 200 {
		return csrp_bin_status_err('query', '', resp.body, resp.status)
	}
	frames := csrp_parse_frames(resp.body)
	if e := csrp_frame_error_of(frames) {
		return e
	}
	mut results := []cx.Node{}
	for f in frames {
		if f.kind == csrp_frame_match {
			rn := cx.node_from_bin(f.astbin) or { continue }
			if rn is cx.Element && rn.name == 'result' {
				mut matches := []cx.Node{}
				for m in rn.items {
					matches << m
				}
				results << cx.Element{
					name:  'result'
					attrs: [csrp_attr_of('hash', csrp_attr(rn, 'hash'))]
					items: [store_seq(matches)]
				}
			}
		}
	}
	return store_seq(results)
}

// csrp_bin_client_iter POSTs `[iter]`, parses the 0x01 doc-pair frames, and
// reconstructs the SAME shape store-iter-docs returns (store_seq of
// [entry hash="H" <doc>]). A 404 → CXER1709; a 0x03 error frame → the carried CXER.
fn csrp_bin_client_iter(rb &RemoteBackend) cx.Node {
	body := csrp_bin_wrap(cx.Element{
		name: 'iter'
	})
	resp, errn, ok := remote_http('POST', csrp_op_url(rb, 'iter', ''), csrp_bin_headers(rb),
		body)
	if !ok {
		return errn
	}
	if resp.status == 404 {
		return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: the cx-store:// server does not support the iter op')
	}
	if resp.status != 200 {
		return csrp_bin_status_err('iter', '', resp.body, resp.status)
	}
	frames := csrp_parse_frames(resp.body)
	if e := csrp_frame_error_of(frames) {
		return e
	}
	mut entries := []cx.Node{}
	for f in frames {
		if f.kind == csrp_frame_docpair {
			doc := cx.bin_to_doc(f.astbin) or { continue }
			mut inner := []cx.Node{}
			for e in doc.elements {
				inner << e
			}
			entries << cx.Element{
				name:  'entry'
				attrs: [csrp_attr_of('hash', f.hash)]
				items: inner
			}
		}
	}
	return store_seq(entries)
}

// ── shared helpers ──────────────────────────────────────────────────────────

// csrp_frame_error_of returns the store-error node for a terminal 0x03 frame in
// the stream (mapping the CSRP wire code onto the store error space), or none.
fn csrp_frame_error_of(frames []CsrpFrame) ?cx.Node {
	for f in frames {
		if f.kind == csrp_frame_error {
			ec := f.err_code.trim_string_left('cx-err:')
			mapped := match ec {
				'CXER1721' { 'cx-err:CXER1121' } // not-found → store not-found
				'CXER1720' { 'cx-err:CXER1120' } // integrity mismatch
				else { 'cx-err:CXER1700' }
			}
			return mk_err(mapped, 'E_CSRP: ${f.err_code}: ${f.message}')
		}
	}
	return none
}

// csrp_bin_status_err maps a non-2xx binary-wire response onto the store error
// space, preferring a 0x03 error frame's carried code when the body is a stream.
fn csrp_bin_status_err(op string, hash string, respbody []u8, status int) cx.Node {
	frames := csrp_parse_frames(respbody)
	if e := csrp_frame_error_of(frames) {
		return e
	}
	return csrp_status_err(op, hash, status)
}
