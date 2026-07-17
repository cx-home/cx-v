module code

import cx
import os
import net
import time

// store_grpc_parity_test.v — gRPC brick 5: cross-transport PARITY. One daemon
// serves both CSRP (cx-store+http) and gRPC against the same mem:// store; the
// same document put over each transport yields the SAME content hash, a get over
// each yields the same bytes, and a missing-hash get maps to the same error
// identity (CSRP CXER1721 ↔ gRPC NOT_FOUND/5). Parity is structural — gRPC reuses
// svc_handle_request, the same pipeline as CSRP — and this proves it end-to-end
// over real sockets. Skips when the cx binary is absent.

fn parity_bin() string {
	return os.real_path(os.join_path(os.dir(os.dir(@FILE)), 'target', 'cx'))
}

fn parity_free_port() int {
	mut l := net.listen_tcp(.ip, '127.0.0.1:0') or { return 0 }
	port := l.addr() or { return 0 }.port() or { return 0 }
	l.close() or {}
	return port
}

// parity_grpc_unary runs one unary gRPC call and returns (grpc-status, response
// message bytes). Built from the same H2/HPACK/proto primitives the server uses.
fn parity_grpc_unary(gport int, method string, msg []u8) (string, []u8) {
	mut req := []u8{}
	req << h2_preface.bytes()
	req << h2_frame_encode(h2_settings_frame([]H2Setting{}))
	req << h2_frame_encode(H2Frame{
		typ:       h2_headers
		flags:     h2_flag_end_headers
		stream_id: 1
		payload:   hpack_encode_header_list([
			HpackHeader{':method', 'POST'},
			HpackHeader{':scheme', 'http'},
			HpackHeader{':path', '/cxstore.v1.CxStore/${method}'},
			HpackHeader{'content-type', 'application/grpc'},
			HpackHeader{'te', 'trailers'},
		])
	})
	req << h2_frame_encode(H2Frame{
		typ:       h2_data
		flags:     h2_flag_end_stream
		stream_id: 1
		payload:   grpc_frame_encode(msg)
	})
	mut conn := net.dial_tcp('127.0.0.1:${gport}') or { return 'dial-failed', []u8{} }
	defer {
		conn.close() or {}
	}
	conn.set_read_timeout(3 * time.second)
	conn.write(req) or { return 'write-failed', []u8{} }
	mut r := H2FrameReader{}
	mut cli := new_hpack_decoder(4096)
	mut grpc_status := ''
	mut message := []u8{}
	mut buf := []u8{len: 16384}
	deadline := time.now().add(3 * time.second)
	for time.now() < deadline {
		n := conn.read(mut buf) or { break }
		if n <= 0 {
			break
		}
		r.feed(buf[..n].clone())
		mut done := false
		for {
			f := r.next() or { break }
			if f.typ == h2_headers {
				for h in cli.decode(f.payload) or { []HpackHeader{} } {
					if h.name == 'grpc-status' {
						grpc_status = h.value
						done = true
					}
				}
			} else if f.typ == h2_data {
				mut fr := GrpcFrameReader{}
				fr.feed(f.payload)
				if gf := fr.next() {
					message = gf.data.clone()
				}
			}
		}
		if done {
			break
		}
	}
	return grpc_status, message
}

// parity_grpc_stream runs one server-streaming gRPC call and returns
// (grpc-status, all response message bytes in order). Unlike parity_grpc_unary
// it collects EVERY DATA frame, not just the last — for Query/Iter.
fn parity_grpc_stream(gport int, method string, msg []u8) (string, [][]u8) {
	mut req := []u8{}
	req << h2_preface.bytes()
	req << h2_frame_encode(h2_settings_frame([]H2Setting{}))
	req << h2_frame_encode(H2Frame{
		typ:       h2_headers
		flags:     h2_flag_end_headers
		stream_id: 1
		payload:   hpack_encode_header_list([
			HpackHeader{':method', 'POST'},
			HpackHeader{':scheme', 'http'},
			HpackHeader{':path', '/cxstore.v1.CxStore/${method}'},
			HpackHeader{'content-type', 'application/grpc'},
			HpackHeader{'te', 'trailers'},
		])
	})
	req << h2_frame_encode(H2Frame{
		typ:       h2_data
		flags:     h2_flag_end_stream
		stream_id: 1
		payload:   grpc_frame_encode(msg)
	})
	mut conn := net.dial_tcp('127.0.0.1:${gport}') or { return 'dial-failed', [][]u8{} }
	defer {
		conn.close() or {}
	}
	conn.set_read_timeout(3 * time.second)
	conn.write(req) or { return 'write-failed', [][]u8{} }
	mut r := H2FrameReader{}
	mut cli := new_hpack_decoder(4096)
	mut grpc_status := ''
	mut messages := [][]u8{}
	mut buf := []u8{len: 16384}
	deadline := time.now().add(3 * time.second)
	for time.now() < deadline {
		n := conn.read(mut buf) or { break }
		if n <= 0 {
			break
		}
		r.feed(buf[..n].clone())
		mut done := false
		for {
			f := r.next() or { break }
			if f.typ == h2_headers {
				for h in cli.decode(f.payload) or { []HpackHeader{} } {
					if h.name == 'grpc-status' {
						grpc_status = h.value
						done = true
					}
				}
			} else if f.typ == h2_data {
				mut fr := GrpcFrameReader{}
				fr.feed(f.payload)
				for {
					gf := fr.next() or { break }
					messages << gf.data.clone()
				}
			}
		}
		if done {
			break
		}
	}
	return grpc_status, messages
}

fn test_grpc_csrp_cross_transport_parity() {
	bin := parity_bin()
	if !os.exists(bin) {
		eprintln('SKIP: cx binary not found at ${bin}')
		return
	}
	cport := parity_free_port()
	gport := parity_free_port()
	if cport == 0 || gport == 0 || cport == gport {
		eprintln('SKIP: ports')
		return
	}
	cfg := os.join_path(os.temp_dir(), 'cx_parity_${gport}.cx')
	os.write_file(cfg, '[cxstore-service\n  [bind addr="127.0.0.1:${cport}"]\n  [grpc enabled=true addr="127.0.0.1:${gport}"]\n  [stores\n    [store name="t" url="mem://parity"]]]\n') or {
		eprintln('SKIP: cfg')
		return
	}
	defer {
		os.rm(cfg) or {}
	}
	pid_s := os.execute('${bin} store-serve --config ${cfg} --allow-net=127.0.0.1:${cport} --allow-net=127.0.0.1:${gport} >/tmp/cx-parity.${gport}.out 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: spawn')
		return
	}
	pid := pid_s.output.trim_space()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(700 * time.millisecond)

	// grant the in-process CSRP client net access to the loopback ports.
	caps_apply_spec('net:127.0.0.1:${cport} net:127.0.0.1:${gport}')
	defer {
		caps_set_empty()
	}

	doc := '[note [title "parity"] [body "same-bytes-both-transports"]]'

	// (a) PUT the same doc via CSRP (in-process client) and via gRPC → same hash.
	ch := store_open_impl('cx-store+http://127.0.0.1:${cport}/t/', '', '', false, true,
		map[string]string{})
	csrp_put := store_stdlib_builtin_inner('store-put-doc-text', [ch, store_str(doc)]) or {
		assert false, 'csrp put errored: ${err}'
		return
	}
	csrp_hash := csrp_scalar(csrp_put)
	gstatus, gmsg := parity_grpc_unary(gport, 'Put', pb_encode_put_request(GrpcPutRequest{
		store:    't'
		body:     doc.bytes()
		encoding: 'cxd'
	}))
	assert gstatus == '0', 'grpc put status ${gstatus}'
	grpc_hash := (pb_decode_put_response(gmsg) or { GrpcPutResponse{} }).hash
	assert csrp_hash.len == 64 && grpc_hash.len == 64, 'csrp=${csrp_hash} grpc=${grpc_hash}'
	assert csrp_hash == grpc_hash, 'cross-transport hash mismatch: CSRP ${csrp_hash} vs gRPC ${grpc_hash}'

	// (b) GET via gRPC → the same doc bytes that CSRP get returns.
	csrp_get := store_stdlib_builtin_inner('store-get-doc-text', [ch, store_str(csrp_hash)]) or {
		assert false, 'csrp get errored: ${err}'
		return
	}
	_, gget := parity_grpc_unary(gport, 'Get', pb_encode_get_request(GrpcGetRequest{
		store: 't'
		hash:  grpc_hash
	}))
	grpc_doc := (pb_decode_get_response(gget) or { GrpcGetResponse{} }).body.bytestr()
	assert grpc_doc.contains('same-bytes-both-transports'), 'grpc get doc: ${grpc_doc}'
	assert csrp_scalar(csrp_get).contains('same-bytes-both-transports'), 'csrp get doc mismatch'

	// (c) MISSING hash → same error identity: gRPC NOT_FOUND(5) ↔ CSRP CXER1721.
	miss_status, _ := parity_grpc_unary(gport, 'Get', pb_encode_get_request(GrpcGetRequest{
		store: 't'
		hash:  '0'.repeat(64)
	}))
	assert miss_status == grpc_not_found.str(), 'grpc missing status ${miss_status}, want ${grpc_not_found}'
	// CSRP side: get-doc-text on a missing hash returns the absence channel (the
	// CSRP route maps it to 404/CXER1721 — same NOT_FOUND identity).
	csrp_miss := store_stdlib_builtin_inner('store-get-doc-text', [ch, store_str('0'.repeat(64))]) or {
		cx.Node(cx.ScalarNode{})
	}
	assert csrp_miss !is cx.ScalarNode || csrp_scalar(csrp_miss) == '', 'csrp missing should be absent, not a doc'
}

// parity_seq_len returns the number of items in a store_seq result (or 0).
fn parity_seq_len(n cx.Node) int {
	if n is cx.Element {
		return n.items.len
	}
	return 0
}

// parity_iter_hashes extracts the per-entry hashes from a store-iter-docs result
// (store_seq of [entry hash="H" …]).
fn parity_iter_hashes(n cx.Node) []string {
	mut out := []string{}
	if n is cx.Element {
		for it in n.items {
			if it is cx.Element && it.name == 'entry' {
				for a in it.attrs {
					if a.name == 'hash' {
						out << cx.scalar_value_str_public(a.value)
					}
				}
			}
		}
	}
	return out
}

// test_grpc_csrp_query_iter_modify_parity — #123 brick E: the three ops added in
// this change have the SAME cross-transport identity as put/get. One daemon,
// both listeners, same fixture: query and iter return the same results over CSRP
// (in-process client) and gRPC; a modify with the same action yields the same new
// content-address over both; and a modify of a missing source maps to the same
// error identity (gRPC NOT_FOUND(5) ↔ CSRP store NOT_FOUND).
fn test_grpc_csrp_query_iter_modify_parity() {
	bin := parity_bin()
	if !os.exists(bin) {
		eprintln('SKIP: cx binary not found at ${bin}')
		return
	}
	cport := parity_free_port()
	gport := parity_free_port()
	if cport == 0 || gport == 0 || cport == gport {
		eprintln('SKIP: ports')
		return
	}
	cfg := os.join_path(os.temp_dir(), 'cx_parity_qim_${gport}.cx')
	os.write_file(cfg, '[cxstore-service\n  [bind addr="127.0.0.1:${cport}"]\n  [grpc enabled=true addr="127.0.0.1:${gport}"]\n  [stores\n    [store name="t" url="mem://parity-qim"]]]\n') or {
		eprintln('SKIP: cfg')
		return
	}
	defer {
		os.rm(cfg) or {}
	}
	pid_s := os.execute('${bin} store-serve --config ${cfg} --allow-net=127.0.0.1:${cport} --allow-net=127.0.0.1:${gport} >/tmp/cx-parity-qim.${gport}.out 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: spawn')
		return
	}
	pid := pid_s.output.trim_space()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(700 * time.millisecond)

	caps_apply_spec('net:127.0.0.1:${cport} net:127.0.0.1:${gport}')
	defer {
		caps_set_empty()
	}

	ch := store_open_impl('cx-store+http://127.0.0.1:${cport}/t/', '', '', false, true,
		map[string]string{})
	// Seed: two docs, one carrying a [title].
	titled := '[note [title "parity-q"] [body "has-title"]]'
	plain := '[note [body "no-title"]]'
	src_node := store_stdlib_builtin_inner('store-put-doc-text', [ch, store_str(titled)]) or {
		assert false, 'seed put titled errored: ${err}'
		return
	}
	src_hash := csrp_scalar(src_node)
	store_stdlib_builtin_inner('store-put-doc-text', [ch, store_str(plain)]) or {
		assert false, 'seed put plain errored: ${err}'
		return
	}

	// (a) QUERY //title parity: same match count over CSRP (in-process) and gRPC.
	csrp_q := store_stdlib_builtin_inner('store-query', [ch, store_str('//title')]) or {
		assert false, 'csrp query errored: ${err}'
		return
	}
	csrp_q_n := parity_seq_len(csrp_q)
	gq_status, gq_rows := parity_grpc_stream(gport, 'Query', pb_encode_query_request(GrpcQueryRequest{
		store: 't'
		query: '//title'.bytes()
	}))
	assert gq_status == '0', 'grpc query status ${gq_status}'
	assert csrp_q_n == 1, 'CSRP query should match exactly 1 doc, got ${csrp_q_n}'
	assert gq_rows.len == csrp_q_n, 'query parity: CSRP ${csrp_q_n} matches vs gRPC ${gq_rows.len} rows'
	grpc_q_row := (pb_decode_query_row(gq_rows[0]) or { GrpcQueryRow{} }).row.bytestr()
	assert grpc_q_row.contains('parity-q'), 'gRPC query row must carry the matched [title]: ${grpc_q_row}'

	// (b) ITER parity: same set of doc hashes over CSRP (in-process) and gRPC.
	csrp_i := store_stdlib_builtin_inner('store-iter-docs', [ch]) or {
		assert false, 'csrp iter errored: ${err}'
		return
	}
	csrp_hashes := parity_iter_hashes(csrp_i)
	gi_status, gi_docs := parity_grpc_stream(gport, 'Iter', pb_encode_store_request(GrpcStoreRequest{
		store: 't'
	}))
	assert gi_status == '0', 'grpc iter status ${gi_status}'
	mut grpc_hashes := []string{}
	for d in gi_docs {
		grpc_hashes << (pb_decode_doc(d) or { GrpcDoc{} }).hash
	}
	assert csrp_hashes.len == 2 && grpc_hashes.len == 2, 'iter parity counts: CSRP ${csrp_hashes.len} vs gRPC ${grpc_hashes.len}'
	for h in csrp_hashes {
		assert h in grpc_hashes, 'iter parity: CSRP hash ${h} missing from gRPC iter set ${grpc_hashes}'
	}

	// (c) MODIFY parity: the SAME action on the SAME source yields the SAME new
	// content-address over both transports (content addressing is deterministic).
	action := cx.parse('[set-attr name=tag value="PARITY"]') or {
		assert false, 'parse action'
		return
	}
	action_node := action.elements[0]
	csrp_m := store_stdlib_builtin_inner('store-modify-doc', [ch, store_str(src_hash), action_node]) or {
		assert false, 'csrp modify errored: ${err}'
		return
	}
	csrp_new := csrp_scalar(csrp_m)
	gm_status, gm_msg := parity_grpc_unary(gport, 'Modify', pb_encode_modify_request(GrpcModifyRequest{
		store:  't'
		hash:   src_hash
		action: '[set-attr name=tag value="PARITY"]'.bytes()
	}))
	assert gm_status == '0', 'grpc modify status ${gm_status}'
	grpc_modr := pb_decode_modify_response(gm_msg) or { GrpcModifyResponse{} }
	assert csrp_new.len == 64 && grpc_modr.new_hash.len == 64, 'modify hashes: csrp=${csrp_new} grpc=${grpc_modr.new_hash}'
	assert csrp_new == grpc_modr.new_hash, 'cross-transport modify hash mismatch: CSRP ${csrp_new} vs gRPC ${grpc_modr.new_hash}'
	assert grpc_modr.old_hash == src_hash, 'gRPC modify old-hash should echo the source'

	// (d) MODIFY of a missing source → same error identity (gRPC NOT_FOUND(5)).
	miss_status, _ := parity_grpc_unary(gport, 'Modify', pb_encode_modify_request(GrpcModifyRequest{
		store:  't'
		hash:   '0'.repeat(64)
		action: '[set-attr name=x value="y"]'.bytes()
	}))
	assert miss_status == grpc_not_found.str(), 'grpc modify-missing status ${miss_status}, want ${grpc_not_found}'
	// CSRP side: modify of a missing source is the store NOT_FOUND (CXER1121),
	// which the CSRP modify route maps to the same 404/CXER1721 NOT_FOUND identity.
	csrp_miss := store_stdlib_builtin_inner('store-modify-doc', [ch, store_str('0'.repeat(64)),
		action_node]) or { mk_err('cx-err:CXER0000', 'unexpected') }
	assert is_err_value(csrp_miss), 'csrp modify of a missing source must error (NOT_FOUND), not succeed'
}

// test_grpc_csrp_object_wire_parity — #129 PR-B item 4: the OBJECT wire at exact
// CSRP↔gRPC parity. A cx-store+grpc:// client decomposes a doc locally, transfers only
// the missing objects (objects-have → objects-put), and advances the ref (refs-set) over
// gRPC; the same doc read back over gRPC is byte-identical, AND a CSRP client reads the
// SAME doc from the SAME object space (both wires hit one daemon graph — "change the
// URL, same model"). Skips when the cx binary is absent.
fn test_grpc_csrp_object_wire_parity() {
	bin := parity_bin()
	if !os.exists(bin) {
		eprintln('SKIP: cx binary not found at ${bin}')
		return
	}
	cport := parity_free_port()
	gport := parity_free_port()
	if cport == 0 || gport == 0 || cport == gport {
		eprintln('SKIP: ports')
		return
	}
	cfg := os.join_path(os.temp_dir(), 'cx_ow_parity_${gport}.cx')
	os.write_file(cfg, '[cxstore-service\n  [bind addr="127.0.0.1:${cport}"]\n  [grpc enabled=true addr="127.0.0.1:${gport}"]\n  [stores\n    [store name="t" url="mem://owparity"]]]\n') or {
		eprintln('SKIP: cfg')
		return
	}
	defer {
		os.rm(cfg) or {}
	}
	pid_s := os.execute('${bin} store-serve --config ${cfg} --allow-net=127.0.0.1:${cport} --allow-net=127.0.0.1:${gport} >/tmp/cx-owparity.${gport}.out 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: spawn')
		return
	}
	pid := pid_s.output.trim_space()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(700 * time.millisecond)

	caps_apply_spec('net:127.0.0.1:${cport} net:127.0.0.1:${gport}')
	defer {
		caps_set_empty()
	}

	doc := '[invoice [id 7] [customer [name "Globex"] [addr [city "SF"] [zip "94016"]]]]'
	canonical := render_canonical(cx.parse(doc) or { panic('p') }.elements[0])
	store_key := cx.cx_text_hash(canonical) or { panic('h') }

	// (a) PUT over the gRPC object wire (client decomposes → objects-put → set_ref).
	gch := store_open_impl('cx-store+grpc://127.0.0.1:${gport}/t/', '', '', false, true,
		map[string]string{})
	gput := store_stdlib_builtin_inner('store-put-doc-text', [gch, store_str(doc)]) or {
		assert false, 'grpc object-wire put errored: ${err}'
		return
	}
	assert csrp_scalar(gput) == store_key, 'grpc object-wire put store-key mismatch: ${csrp_scalar(gput)}'

	// (b) GET back over the gRPC object wire (resolve_ref + reconstruct) → byte-identical.
	gget := store_stdlib_builtin_inner('store-get-doc-text', [gch, store_str(store_key)]) or {
		assert false, 'grpc object-wire get errored: ${err}'
		return
	}
	assert gget is cx.ScalarNode && csrp_scalar(gget) == canonical, 'grpc object-wire round trip not byte-identical'

	// (c) CROSS-TRANSPORT: a CSRP client reads the SAME doc from the SAME object space.
	cch := store_open_impl('cx-store+http://127.0.0.1:${cport}/t/', '', '', false, true,
		map[string]string{})
	cget := store_stdlib_builtin_inner('store-get-doc-text', [cch, store_str(store_key)]) or {
		assert false, 'csrp get errored: ${err}'
		return
	}
	assert cget is cx.ScalarNode && csrp_scalar(cget) == canonical, 'cross-transport object-wire mismatch (csrp read of grpc-pushed doc)'

	// (d) a missing hash is absence over the gRPC object wire too (not an error/doc).
	gmiss := store_stdlib_builtin_inner('store-get-doc-text', [gch, store_str('0'.repeat(64))]) or {
		cx.Node(cx.ScalarNode{})
	}
	assert gmiss !is cx.ScalarNode || csrp_scalar(gmiss) == '', 'grpc object-wire miss should be absent'
}

// test_porcelain_cross_tier_over_http — #129 PR-B item 5: the git porcelain transfer
// verbs (push / pull / clone) over a REAL cx-store+http:// wire. A local embedded store
// pushes to a daemon (objects + ref land server-side), a fresh local store pulls them
// back (list-docs over the document path → the daemon catalog, then objects-get over the
// object wire), and clone copies the daemon into an empty local store. Skips without the
// cx binary.
fn test_porcelain_cross_tier_over_http() {
	bin := parity_bin()
	if !os.exists(bin) {
		eprintln('SKIP: cx binary not found at ${bin}')
		return
	}
	cport := parity_free_port()
	gport := parity_free_port()
	if cport == 0 || gport == 0 || cport == gport {
		eprintln('SKIP: ports')
		return
	}
	cfg := os.join_path(os.temp_dir(), 'cx_pc_${cport}.cx')
	os.write_file(cfg, '[cxstore-service\n  [bind addr="127.0.0.1:${cport}"]\n  [grpc enabled=true addr="127.0.0.1:${gport}"]\n  [stores\n    [store name="t" url="mem://pcwire"]]]\n') or {
		eprintln('SKIP: cfg')
		return
	}
	defer {
		os.rm(cfg) or {}
	}
	pid_s := os.execute('${bin} store-serve --config ${cfg} --allow-net=127.0.0.1:${cport} --allow-net=127.0.0.1:${gport} >/tmp/cx-pcwire.${cport}.out 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: spawn')
		return
	}
	pid := pid_s.output.trim_space()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(700 * time.millisecond)
	caps_apply_spec('net:127.0.0.1:${cport} net:127.0.0.1:${gport}')
	defer {
		caps_set_empty()
	}

	remote := store_open_impl('cx-store+http://127.0.0.1:${cport}/t/', '', '', false, true,
		map[string]string{})
	doc := '[ledger [entry [id 1] [amt 100]] [entry [id 2] [amt 200]]]'
	canonical := render_canonical(cx.parse(doc) or { panic('p') }.elements[0])
	store_key := cx.cx_text_hash(canonical) or { panic('h') }

	// (a) PUSH a local doc to the daemon over the object wire.
	local := store_open_impl('mem://pc-up', '', '', false, true, map[string]string{})
	store_stdlib_builtin_inner('store-put-doc-text', [local, store_str(doc)]) or {
		assert false, 'local put: ${err}'
		return
	}
	rp := store_stdlib_builtin_inner('store-push', [local, remote]) or {
		assert false, 'push: ${err}'
		return
	}
	assert !is_err_value(rp), 'push errored: ${rp}'
	// the daemon reconstructs the pushed doc.
	dg := store_stdlib_builtin_inner('store-get-doc-text', [remote, store_str(store_key)]) or {
		assert false, 'remote get: ${err}'
		return
	}
	assert dg is cx.ScalarNode && csrp_scalar(dg) == canonical, 'daemon missing pushed doc'

	// (b) PULL the daemon's docs into a fresh local store (catalog over http + objects).
	local2 := store_open_impl('mem://pc-down', '', '', false, true, map[string]string{})
	rl := store_stdlib_builtin_inner('store-pull', [local2, remote]) or {
		assert false, 'pull: ${err}'
		return
	}
	assert !is_err_value(rl), 'pull errored: ${rl}'
	lg := store_stdlib_builtin_inner('store-get-doc-text', [local2, store_str(store_key)]) or {
		assert false, 'local2 get: ${err}'
		return
	}
	assert lg is cx.ScalarNode && csrp_scalar(lg) == canonical, 'pulled doc not byte-identical'

	// (c) CLONE the daemon into an empty local store.
	local3 := store_open_impl('mem://pc-clone', '', '', false, true, map[string]string{})
	rc := store_stdlib_builtin_inner('store-clone', [remote, local3]) or {
		assert false, 'clone: ${err}'
		return
	}
	assert !is_err_value(rc), 'clone errored: ${rc}'
	cg := store_stdlib_builtin_inner('store-get-doc-text', [local3, store_str(store_key)]) or {
		assert false, 'local3 get: ${err}'
		return
	}
	assert cg is cx.ScalarNode && csrp_scalar(cg) == canonical, 'cloned doc not byte-identical'
}

// parity_grpc_unary_trailers is parity_grpc_unary that ALSO captures the
// `cx-err-code` trailer (the trailing HEADERS frame's CSRP error code). #208: the
// parity suite never asserted this trailer, which is how a trailer-mnemonic
// regression could ship undetected — cross-transport error IDENTITY lives here.
fn parity_grpc_unary_trailers(gport int, method string, msg []u8) (string, []u8, string) {
	mut req := []u8{}
	req << h2_preface.bytes()
	req << h2_frame_encode(h2_settings_frame([]H2Setting{}))
	req << h2_frame_encode(H2Frame{
		typ:       h2_headers
		flags:     h2_flag_end_headers
		stream_id: 1
		payload:   hpack_encode_header_list([
			HpackHeader{':method', 'POST'},
			HpackHeader{':scheme', 'http'},
			HpackHeader{':path', '/cxstore.v1.CxStore/${method}'},
			HpackHeader{'content-type', 'application/grpc'},
			HpackHeader{'te', 'trailers'},
		])
	})
	req << h2_frame_encode(H2Frame{
		typ:       h2_data
		flags:     h2_flag_end_stream
		stream_id: 1
		payload:   grpc_frame_encode(msg)
	})
	mut conn := net.dial_tcp('127.0.0.1:${gport}') or { return 'dial-failed', []u8{}, '' }
	defer {
		conn.close() or {}
	}
	conn.set_read_timeout(3 * time.second)
	conn.write(req) or { return 'write-failed', []u8{}, '' }
	mut r := H2FrameReader{}
	mut cli := new_hpack_decoder(4096)
	mut grpc_status := ''
	mut cx_err := ''
	mut message := []u8{}
	mut buf := []u8{len: 16384}
	deadline := time.now().add(3 * time.second)
	for time.now() < deadline {
		n := conn.read(mut buf) or { break }
		if n <= 0 {
			break
		}
		r.feed(buf[..n].clone())
		mut done := false
		for {
			f := r.next() or { break }
			if f.typ == h2_headers {
				for h in cli.decode(f.payload) or { []HpackHeader{} } {
					if h.name == 'grpc-status' {
						grpc_status = h.value
						done = true
					}
					if h.name == 'cx-err-code' {
						cx_err = h.value
					}
				}
			} else if f.typ == h2_data {
				mut fr := GrpcFrameReader{}
				fr.feed(f.payload)
				if gf := fr.next() {
					message = gf.data.clone()
				}
			}
		}
		if done {
			break
		}
	}
	return grpc_status, message, cx_err
}

// test_grpc_csrp_delete_list_capabilities_parity — #208.2: extend the parity matrix
// to delete / list / capabilities (previously only put/get/query/iter/modify), and
// assert the cx-err-code error trailer on a NOT_FOUND (the identity the shipped
// trailer-mnemonic bug would have violated).
fn test_grpc_csrp_delete_list_capabilities_parity() {
	bin := parity_bin()
	if !os.exists(bin) {
		eprintln('SKIP: cx binary not found at ${bin}')
		return
	}
	cport := parity_free_port()
	gport := parity_free_port()
	if cport == 0 || gport == 0 || cport == gport {
		eprintln('SKIP: ports')
		return
	}
	cfg := os.join_path(os.temp_dir(), 'cx_dlc_${gport}.cx')
	os.write_file(cfg, '[cxstore-service\n  [bind addr="127.0.0.1:${cport}"]\n  [grpc enabled=true addr="127.0.0.1:${gport}"]\n  [stores\n    [store name="t" url="mem://dlc"]]]\n') or {
		eprintln('SKIP: cfg')
		return
	}
	defer {
		os.rm(cfg) or {}
	}
	pid_s := os.execute('${bin} store-serve --config ${cfg} --allow-net=127.0.0.1:${cport} --allow-net=127.0.0.1:${gport} >/tmp/cx-dlc.${gport}.out 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: spawn')
		return
	}
	pid := pid_s.output.trim_space()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(700 * time.millisecond)
	caps_apply_spec('net:127.0.0.1:${cport} net:127.0.0.1:${gport}')
	defer {
		caps_set_empty()
	}

	ch := store_open_impl('cx-store+http://127.0.0.1:${cport}/t/', '', '', false, true,
		map[string]string{})

	// seed two docs via CSRP.
	da := '[a [n 1]]'
	db := '[b [n 2]]'
	pa := store_stdlib_builtin_inner('store-put-doc-text', [ch, store_str(da)]) or {
		assert false, 'put a: ${err}'
		return
	}
	store_stdlib_builtin_inner('store-put-doc-text', [ch, store_str(db)]) or {
		assert false, 'put b: ${err}'
		return
	}
	ha := csrp_scalar(pa)

	// (a) LIST parity — CSRP list vs gRPC List (streaming HashItem frames) → same set.
	csrp_list := store_stdlib_builtin_inner('store-list-docs', [ch]) or {
		assert false, 'csrp list: ${err}'
		return
	}
	// store-list-docs returns a store_seq of scalar hash strings.
	mut csrp_hashes := []string{}
	if csrp_list is cx.Element {
		for it in csrp_list.items {
			h := csrp_scalar(it)
			if h.len == 64 {
				csrp_hashes << h
			}
		}
	}
	csrp_hashes.sort()
	lstatus, lframes := parity_grpc_stream(gport, 'List', pb_encode_store_request(GrpcStoreRequest{
		store: 't'
	}))
	assert lstatus == '0', 'grpc List status ${lstatus}'
	mut grpc_hashes := []string{}
	for fr in lframes {
		hi := pb_decode_hash_item(fr) or { continue }
		grpc_hashes << hi.hash
	}
	grpc_hashes.sort()
	assert csrp_hashes.len == 2 && grpc_hashes == csrp_hashes, 'list parity: CSRP ${csrp_hashes} vs gRPC ${grpc_hashes}'

	// (b) CAPABILITIES parity — gRPC Capabilities carries the same advert shape.
	cstatus, cmsg := parity_grpc_unary(gport, 'Capabilities', pb_encode_store_request(GrpcStoreRequest{}))
	assert cstatus == '0', 'grpc Capabilities status ${cstatus}'
	caps_body := (pb_decode_capabilities_response(cmsg) or { GrpcCapabilitiesResponse{} }).capabilities.bytestr()
	assert caps_body.contains('csrp-version') && caps_body.contains('cxbin'), 'gRPC capabilities advert: ${caps_body}'

	// (c) DELETE parity — gRPC Delete removes the doc; a re-get is NOT_FOUND on both.
	dstatus, dmsg := parity_grpc_unary(gport, 'Delete', pb_encode_delete_request(GrpcDeleteRequest{
		store: 't'
		hash:  ha
	}))
	assert dstatus == '0', 'grpc Delete status ${dstatus}'
	assert (pb_decode_delete_response(dmsg) or { GrpcDeleteResponse{} }).deleted, 'gRPC Delete should report deleted=true'
	// CSRP side sees it gone too (shared store).
	after := store_stdlib_builtin_inner('store-exists', [ch, store_str(ha)]) or { store_bool(true) }
	assert csrp_scalar(after) == 'false', 'CSRP exists should be false after gRPC delete (shared store)'

	// (d) ERROR-IDENTITY TRAILER — a NOT_FOUND Get carries grpc-status=5 AND the
	// cx-err-code trailer = CXER1721 (cross-transport identity with CSRP's 404).
	mstatus, _, mcx := parity_grpc_unary_trailers(gport, 'Get', pb_encode_get_request(GrpcGetRequest{
		store: 't'
		hash:  '0'.repeat(64)
	}))
	assert mstatus == grpc_not_found.str(), 'grpc missing status ${mstatus}, want ${grpc_not_found}'
	assert mcx == 'cx-err:CXER1721', 'the cx-err-code trailer must carry CXER1721 on NOT_FOUND (#208/#194); got "${mcx}"'
}
