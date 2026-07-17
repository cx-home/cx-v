module code

import cx

// store_binary_wire_test.v — the approved CSRP binary wire (#182), server side,
// exercised hermetically through store_csrp_route: a cxbin/body-carried request
// in, ast_bin / length-prefixed frames out (§2.1/§3.2).

// bw_open a fresh mem store handle.
fn bw_open(tag string) cx.Node {
	return store_open_impl('mem://bw-${tag}', '', '', false, true, map[string]string{})
}

// bw_req builds a binary-wire request: method POST, path, Content-Type
// application/cx-astbin, Accept application/cx-frame-stream, and a cxbin body.
fn bw_req(op string, body_bytes []u8) cx.Element {
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
					bw_hdr('Content-Type', csrp_ct_astbin),
					bw_hdr('Accept', csrp_ct_frame_stream),
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

fn bw_hdr(name string, val string) cx.Node {
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

// bw_astbin encodes a cx text (op element or doc) to ast_bin bytes.
fn bw_astbin(text string) []u8 {
	d := cx.parse(text) or { panic('parse ${text}') }
	return cx.emit_ast_bin(d)
}

fn bw_resp_bytes(n cx.Node) []u8 {
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

fn bw_status(n cx.Node) int {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'status' {
				return cx.scalar_value_str_public(a.value).int()
			}
		}
	}
	return 0
}

// ── put (cxbin doc body) → ast_bin [put-result …]; get → raw ast_bin doc ──────

fn test_binary_put_get_roundtrip() {
	caps_set_all()
	local := bw_open('putget')
	doc_text := '[note [title "binwire"] [body "hello"]]'
	// PUT: the body IS the doc (cxbin) — §3.4.
	put_resp := store_csrp_route(bw_req('put', bw_astbin(doc_text)), local)
	assert bw_status(put_resp) == 200, 'binary put 200'
	put_doc := cx.bin_to_doc(bw_resp_bytes(put_resp)) or {
		assert false, 'put-result must be ast_bin-decodable'
		return
	}
	pr := put_doc.elements[0] as cx.Element
	assert pr.name == 'put-result', 'put-result element'
	hash := csrp_attr(pr, 'hash')
	assert hash.len == 64, 'put-result carries the 64-hex hash: ${hash}'
	assert csrp_attr(pr, 'stored') == 'true', 'first put stored=true'

	// re-put the same doc → stored=false (dedup, over the binary wire too)
	put2 := store_csrp_route(bw_req('put', bw_astbin(doc_text)), local)
	pr2 := (cx.bin_to_doc(bw_resp_bytes(put2)) or { panic('d') }).elements[0] as cx.Element
	assert csrp_attr(pr2, 'stored') == 'false', 'binary re-put dedup stored=false'

	// GET: [get hash="…"] cxbin body → raw ast_bin doc body (200).
	get_resp := store_csrp_route(bw_req('get', bw_astbin('[get hash="${hash}"]')), local)
	assert bw_status(get_resp) == 200, 'binary get 200'
	got := cx.bin_to_doc(bw_resp_bytes(get_resp)) or {
		assert false, 'get body must be ast_bin doc'
		return
	}
	assert (got.elements[0] as cx.Element).name == 'note', 'get round-trips the doc'
	// re-hash the returned doc to the requested key (integrity)
	rh := cx.cx_text_hash(render_canonical(got.elements[0])) or { '' }
	assert rh == hash, 'binary get doc rehashes to the key'
}

// ── get miss → 404 with a terminal 0x03 error frame CXER1721 ──────────────────

fn test_binary_get_miss_error_frame() {
	caps_set_all()
	local := bw_open('miss')
	resp := store_csrp_route(bw_req('get', bw_astbin('[get hash="${'0'.repeat(64)}"]')),
		local)
	assert bw_status(resp) == 404, 'binary get miss 404'
	frames := csrp_parse_frames(bw_resp_bytes(resp))
	assert frames.len >= 1, 'a 0x03 error frame must be present'
	assert frames[0].kind == csrp_frame_error, 'kind 0x03 error'
	assert frames[0].err_code == 'cx-err:CXER1721', 'get-miss error frame carries CXER1721 (§3.3): ${frames[0].err_code}'
}

// ── list → ast_bin [list-result [hashes [sequence …]] …] ──────────────────────

fn test_binary_list() {
	caps_set_all()
	local := bw_open('list')
	for i in 0 .. 3 {
		store_csrp_route(bw_req('put', bw_astbin('[d [n ${i}]]')), local)
	}
	resp := store_csrp_route(bw_req('list', bw_astbin('[list]')), local)
	assert bw_status(resp) == 200, 'binary list 200'
	lr := (cx.bin_to_doc(bw_resp_bytes(resp)) or { panic('list') }).elements[0] as cx.Element
	assert lr.name == 'list-result', 'list-result element'
	// total-count = 3
	mut total := ''
	for it in lr.items {
		if it is cx.Element && it.name == 'total-count' {
			for c in it.items {
				total = cx.scalar_value_str_public((c as cx.ScalarNode).value)
			}
		}
	}
	assert total == '3', 'list total-count=3, got ${total}'
}

// ── iter → 0x01 doc-pair frames + terminal 0x04 end ───────────────────────────

fn test_binary_iter_frames() {
	caps_set_all()
	local := bw_open('iter')
	for i in 0 .. 2 {
		store_csrp_route(bw_req('put', bw_astbin('[d [n ${i}]]')), local)
	}
	resp := store_csrp_route(bw_req('iter', bw_astbin('[iter]')), local)
	frames := csrp_parse_frames(bw_resp_bytes(resp))
	mut docpairs := 0
	mut ends := 0
	for f in frames {
		if f.kind == csrp_frame_docpair {
			docpairs++
			// each doc-pair carries a decodable ast_bin doc
			assert cx.bin_to_doc(f.astbin) or { cx.Document{} }.elements.len > 0, 'doc-pair ast_bin decodes'
		}
		if f.kind == csrp_frame_end {
			ends++
			assert f.total == 2, 'end frame total=2, got ${f.total}'
		}
	}
	assert docpairs == 2, 'iter emits 2 doc-pair frames, got ${docpairs}'
	assert ends == 1, 'iter emits exactly one terminal end frame'
}

// ── query matches → 0x02 match frames + 0x04 end; aggregate → 0x05 ────────────

fn test_binary_query_frames() {
	caps_set_all()
	local := bw_open('query')
	store_csrp_route(bw_req('put', bw_astbin('[users [user [name "al"]] [user [name "bo"]]]')),
		local)
	// matches shape
	resp := store_csrp_route(bw_req('query', bw_astbin('[query [cxpath "//user"] [shape "matches"]]')),
		local)
	frames := csrp_parse_frames(bw_resp_bytes(resp))
	mut matches := 0
	mut ends := 0
	for f in frames {
		if f.kind == csrp_frame_match {
			matches++
		}
		if f.kind == csrp_frame_end {
			ends++
		}
	}
	assert matches >= 1, 'query emits match frames, got ${matches}'
	assert ends == 1, 'query emits a terminal end frame'
	// aggregate shape → single 0x05
	agg := store_csrp_route(bw_req('query', bw_astbin('[query [cxpath "//user"] [shape "aggregate"]]')),
		local)
	afr := csrp_parse_frames(bw_resp_bytes(agg))
	assert afr.len == 1 && afr[0].kind == csrp_frame_aggregate, 'aggregate shape → one 0x05 frame'
}

// ── frame codec round-trips (unit) ────────────────────────────────────────────

fn test_frame_codec_roundtrip() {
	err := csrp_wire_error('cx-err:CXER1700', 'boom')
	f := csrp_parse_frames(err)
	assert f.len == 1 && f[0].kind == csrp_frame_error
	assert f[0].err_code == 'cx-err:CXER1700' && f[0].message == 'boom'
	// concatenated stream: a doc-pair then an end
	mut s := csrp_wire_docframe(csrp_frame_docpair, 'ab'.repeat(32), bw_astbin('[x]'))
	s << csrp_wire_end(1)
	fr := csrp_parse_frames(s)
	assert fr.len == 2, 'two frames in the stream'
	assert fr[0].kind == csrp_frame_docpair && fr[0].hash == 'ab'.repeat(32)
	assert fr[1].kind == csrp_frame_end && fr[1].total == 1
}
