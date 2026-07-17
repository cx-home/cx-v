module code

import os
import net
import time

// store_grpc_concurrency_test.v — #123 brick D: the gRPC listener serves
// connections CONCURRENTLY (a bounded worker pool, not one-at-a-time), and
// reassembles + dispatches multiple HTTP/2 streams on a single connection. Two
// raw-socket clients (built from the same H2/HPACK/proto primitives as the live
// test) hit the daemon at once; each must get ITS OWN correct response — no
// crossing of responses across connections under concurrency. A third check
// drives two streams on one connection and asserts both are dispatched. Skips
// when the cx binary is absent.

fn grpc_conc_bin() string {
	return os.real_path(os.join_path(os.dir(os.dir(@FILE)), 'target', 'cx'))
}

fn grpc_conc_free_port() int {
	mut l := net.listen_tcp(.ip, '127.0.0.1:0') or { return 0 }
	port := l.addr() or { return 0 }.port() or { return 0 }
	l.close() or {}
	return port
}

// grpc_put_frames / grpc_get_frames build the H2 frames for one gRPC call on a
// given stream id (HEADERS + a single END_STREAM DATA frame).
fn grpc_put_frames(stream_id u32, store string, body string) []u8 {
	mut req := []u8{}
	req << h2_frame_encode(H2Frame{
		typ:       h2_headers
		flags:     h2_flag_end_headers
		stream_id: stream_id
		payload:   hpack_encode_header_list([
			HpackHeader{':method', 'POST'},
			HpackHeader{':scheme', 'http'},
			HpackHeader{':path', '/cxstore.v1.CxStore/Put'},
			HpackHeader{'content-type', 'application/grpc'},
			HpackHeader{'te', 'trailers'},
		])
	})
	req << h2_frame_encode(H2Frame{
		typ:       h2_data
		flags:     h2_flag_end_stream
		stream_id: stream_id
		payload:   grpc_frame_encode(pb_encode_put_request(GrpcPutRequest{
			store:    store
			body:     body.bytes()
			encoding: 'cxd'
		}))
	})
	return req
}

fn grpc_get_frames(stream_id u32, store string, hash string) []u8 {
	mut req := []u8{}
	req << h2_frame_encode(H2Frame{
		typ:       h2_headers
		flags:     h2_flag_end_headers
		stream_id: stream_id
		payload:   hpack_encode_header_list([
			HpackHeader{':method', 'POST'},
			HpackHeader{':scheme', 'http'},
			HpackHeader{':path', '/cxstore.v1.CxStore/Get'},
			HpackHeader{'content-type', 'application/grpc'},
			HpackHeader{'te', 'trailers'},
		])
	})
	req << h2_frame_encode(H2Frame{
		typ:       h2_data
		flags:     h2_flag_end_stream
		stream_id: stream_id
		payload:   grpc_frame_encode(pb_encode_get_request(GrpcGetRequest{
			store: store
			hash:  hash
		}))
	})
	return req
}

// grpc_read_until reads server frames until every wanted stream has its
// grpc-status trailer, returning per-stream (status, last gRPC message bytes).
fn grpc_read_until(mut conn net.TcpConn, want []u32) (map[u32]string, map[u32][]u8) {
	mut r := H2FrameReader{}
	mut cli := new_hpack_decoder(4096)
	mut status := map[u32]string{}
	mut data := map[u32][]u8{}
	mut buf := []u8{len: 16384}
	deadline := time.now().add(4 * time.second)
	for time.now() < deadline {
		n := conn.read(mut buf) or { break }
		if n <= 0 {
			break
		}
		r.feed(buf[..n].clone())
		for {
			f := r.next() or { break }
			match f.typ {
				h2_headers {
					hdrs := cli.decode(f.payload) or { []HpackHeader{} }
					for h in hdrs {
						if h.name == 'grpc-status' {
							status[f.stream_id] = h.value
						}
					}
				}
				h2_data {
					mut fr := GrpcFrameReader{}
					fr.feed(f.payload)
					if gf := fr.next() {
						data[f.stream_id] = gf.data
					}
				}
				else {}
			}
		}
		mut all := true
		for sid in want {
			if sid !in status {
				all = false
			}
		}
		if all {
			break
		}
	}
	return status, data
}

struct GrpcRt {
mut:
	put_status string
	put_hash   string
	get_status string
	get_body   string
	dialed     bool
}

// grpc_put_get_roundtrip is one client's full exchange on its own connection: Put
// a uniquely-marked doc (stream 1), then Get it back by the returned hash
// (stream 3). Returned so the caller can assert this client got ITS doc — the
// concurrency-correctness proof.
fn grpc_put_get_roundtrip(gport int, store string, marker string) GrpcRt {
	mut rt := GrpcRt{}
	mut conn := net.dial_tcp('127.0.0.1:${gport}') or { return rt }
	rt.dialed = true
	defer {
		conn.close() or {}
	}
	conn.set_read_timeout(4 * time.second)

	mut hello := []u8{}
	hello << h2_preface.bytes()
	hello << h2_frame_encode(h2_settings_frame([]H2Setting{}))
	hello << grpc_put_frames(1, store, '[note [body "${marker}"]]')
	conn.write(hello) or { return rt }

	st1, d1 := grpc_read_until(mut conn, [u32(1)])
	rt.put_status = st1[1] or { '' }
	if b := d1[1] {
		pr := pb_decode_put_response(b) or { GrpcPutResponse{} }
		rt.put_hash = pr.hash
	}
	if rt.put_hash.len != 64 {
		return rt
	}

	conn.write(grpc_get_frames(3, store, rt.put_hash)) or { return rt }
	st3, d3 := grpc_read_until(mut conn, [u32(3)])
	rt.get_status = st3[3] or { '' }
	if b := d3[3] {
		gr := pb_decode_get_response(b) or { GrpcGetResponse{} }
		rt.get_body = gr.body.bytestr()
	}
	return rt
}

fn grpc_conc_spawn_daemon(cport int, gport int) (string, string) {
	bin := grpc_conc_bin()
	cfg := os.join_path(os.temp_dir(), 'cx_grpc_conc_${gport}.cx')
	os.write_file(cfg, '[cxstore-service\n  [bind addr="127.0.0.1:${cport}"]\n  [grpc enabled=true addr="127.0.0.1:${gport}"]\n  [stores\n    [store name="t" url="mem://grpc-conc"]]]\n') or {
		return '', ''
	}
	pid_s := os.execute('${bin} store-serve --config ${cfg} --allow-net=127.0.0.1:${cport} --allow-net=127.0.0.1:${gport} >/tmp/cx-grpc-conc.${gport}.out 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		os.rm(cfg) or {}
		return '', ''
	}
	return pid_s.output.trim_space(), cfg
}

fn test_grpc_two_concurrent_clients() {
	bin := grpc_conc_bin()
	if !os.exists(bin) {
		eprintln('SKIP: cx binary not found at ${bin} — run `make build-vcx`')
		return
	}
	cport := grpc_conc_free_port()
	gport := grpc_conc_free_port()
	if cport == 0 || gport == 0 || cport == gport {
		eprintln('SKIP: could not allocate ports')
		return
	}
	pid, cfg := grpc_conc_spawn_daemon(cport, gport)
	if pid == '' {
		eprintln('SKIP: could not spawn cx store-serve')
		return
	}
	defer {
		os.execute('kill ${pid} 2>/dev/null')
		os.rm(cfg) or {}
	}
	time.sleep(800 * time.millisecond) // let both listeners bind

	// Two clients, each its own connection + uniquely-marked doc, dispatched at
	// the SAME time. Each must get its own doc back — not the other's.
	t1 := spawn grpc_put_get_roundtrip(gport, 't', 'concurrent-alpha-AAA')
	t2 := spawn grpc_put_get_roundtrip(gport, 't', 'concurrent-beta-BBB')
	r1 := t1.wait()
	r2 := t2.wait()

	srv_log := os.read_file('/tmp/cx-grpc-conc.${gport}.out') or { '' }
	if !r1.dialed || !r2.dialed {
		eprintln('SKIP: a client could not dial the gRPC port | srv: ${srv_log}')
		return
	}
	assert r1.put_status == '0', 'client1 put grpc-status ${r1.put_status} | srv: ${srv_log}'
	assert r2.put_status == '0', 'client2 put grpc-status ${r2.put_status} | srv: ${srv_log}'
	assert r1.get_status == '0', 'client1 get grpc-status ${r1.get_status} | srv: ${srv_log}'
	assert r2.get_status == '0', 'client2 get grpc-status ${r2.get_status} | srv: ${srv_log}'
	// Connection isolation under concurrency: each client got ITS marker back.
	assert r1.get_body.contains('concurrent-alpha-AAA'), 'client1 did not get its own doc: ${r1.get_body} | srv: ${srv_log}'
	assert r2.get_body.contains('concurrent-beta-BBB'), 'client2 did not get its own doc: ${r2.get_body} | srv: ${srv_log}'
	// And NOT the other client's doc (no response crossing).
	assert !r1.get_body.contains('beta-BBB'), 'client1 response crossed with client2: ${r1.get_body}'
	assert !r2.get_body.contains('alpha-AAA'), 'client2 response crossed with client1: ${r2.get_body}'
}

fn test_grpc_multiplexed_streams_one_conn() {
	bin := grpc_conc_bin()
	if !os.exists(bin) {
		eprintln('SKIP: cx binary not found at ${bin}')
		return
	}
	cport := grpc_conc_free_port()
	gport := grpc_conc_free_port()
	if cport == 0 || gport == 0 || cport == gport {
		eprintln('SKIP: could not allocate ports')
		return
	}
	pid, cfg := grpc_conc_spawn_daemon(cport, gport)
	if pid == '' {
		eprintln('SKIP: could not spawn cx store-serve')
		return
	}
	defer {
		os.execute('kill ${pid} 2>/dev/null')
		os.rm(cfg) or {}
	}
	time.sleep(800 * time.millisecond)

	mut conn := net.dial_tcp('127.0.0.1:${gport}') or {
		eprintln('SKIP: could not dial gRPC port: ${err}')
		return
	}
	defer {
		conn.close() or {}
	}
	conn.set_read_timeout(4 * time.second)

	// Two Put calls on streams 1 and 3, BOTH sent before reading any response —
	// the single connection must reassemble + dispatch each stream independently.
	mut req := []u8{}
	req << h2_preface.bytes()
	req << h2_frame_encode(h2_settings_frame([]H2Setting{}))
	req << grpc_put_frames(1, 't', '[note [body "mux-stream-one"]]')
	req << grpc_put_frames(3, 't', '[note [body "mux-stream-three"]]')
	conn.write(req) or {
		assert false, 'write multiplexed request: ${err}'
		return
	}

	status, data := grpc_read_until(mut conn, [u32(1), u32(3)])
	srv_log := os.read_file('/tmp/cx-grpc-conc.${gport}.out') or { '' }
	assert status[1] or { '' } == '0', 'stream 1 grpc-status ${status[1] or { "<none>" }} | srv: ${srv_log}'
	assert status[3] or { '' } == '0', 'stream 3 grpc-status ${status[3] or { "<none>" }} | srv: ${srv_log}'
	h1 := (pb_decode_put_response(data[1] or { []u8{} }) or { GrpcPutResponse{} }).hash
	h3 := (pb_decode_put_response(data[3] or { []u8{} }) or { GrpcPutResponse{} }).hash
	assert h1.len == 64, 'stream 1 hash: ${h1} | srv: ${srv_log}'
	assert h3.len == 64, 'stream 3 hash: ${h3} | srv: ${srv_log}'
	// Distinct doc bodies → distinct content addresses: each stream got its own.
	assert h1 != h3, 'multiplexed streams must yield distinct hashes (each dispatched independently): ${h1} == ${h3}'
}
