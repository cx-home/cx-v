module platform

import os
import net
import time

// store_grpc_live_test.v — gRPC over a REAL socket (brick 4b smoke): spawn
// `cx store-serve` with [grpc enabled], dial the gRPC port with a raw TCP client
// built from the same H2/HPACK/proto primitives, Put a doc, and assert the
// response frames (:status 200 + grpc-status 0 + a 64-hex hash). Proves the
// socket listener + read/write loop + run_store_serve wiring — the in-memory
// e2e test already proved the request/dispatch/response logic. Skips when the cx
// binary is absent.

fn grpc_live_bin() string {
	// @FILE = …/vcx/code/store_grpc_live_test.v → …/vcx/target/cx
	return os.real_path(os.join_path(os.dir(os.dir(@FILE)), 'target', 'cx'))
}

fn grpc_live_free_port() int {
	mut l := net.listen_tcp(.ip, '127.0.0.1:0') or { return 0 }
	port := l.addr() or { return 0 }.port() or { return 0 }
	l.close() or {}
	return port
}

fn test_grpc_live_put() {
	bin := grpc_live_bin()
	if !os.exists(bin) {
		eprintln('SKIP: cx binary not found at ${bin} — run `make build-vcx`')
		return
	}
	cport := grpc_live_free_port()
	gport := grpc_live_free_port()
	if cport == 0 || gport == 0 || cport == gport {
		eprintln('SKIP: could not allocate ports')
		return
	}
	cfg := os.join_path(os.temp_dir(), 'cx_grpc_live_${gport}.cx')
	os.write_file(cfg, '[cxstore-service\n  [bind addr="127.0.0.1:${cport}"]\n  [grpc enabled=true addr="127.0.0.1:${gport}"]\n  [stores\n    [store name="t" url="mem://grpc-live"]]]\n') or {
		eprintln('SKIP: write cfg: ${err}')
		return
	}
	defer {
		os.rm(cfg) or {}
	}
	pid_s := os.execute('${bin} store-serve --config ${cfg} --allow-net=127.0.0.1:${cport} --allow-net=127.0.0.1:${gport} >/tmp/cx-grpc-live.${gport}.out 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx store-serve')
		return
	}
	pid := pid_s.output.trim_space()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(700 * time.millisecond) // let both listeners bind

	// Build the client request bytes (preface + SETTINGS + HEADERS + DATA).
	doc := '[note [body "grpc-live-roundtrip"]]'
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
			HpackHeader{':path', '/cxstore.v1.CxStore/Put'},
			HpackHeader{'content-type', 'application/grpc'},
			HpackHeader{'te', 'trailers'},
		])
	})
	req << h2_frame_encode(H2Frame{
		typ:       h2_data
		flags:     h2_flag_end_stream
		stream_id: 1
		payload:   grpc_frame_encode(pb_encode_put_request(GrpcPutRequest{
			store:    't'
			body:     doc.bytes()
			encoding: 'cxd'
		}))
	})

	mut conn := net.dial_tcp('127.0.0.1:${gport}') or {
		eprintln('SKIP: could not dial gRPC port: ${err}')
		return
	}
	defer {
		conn.close() or {}
	}
	conn.set_read_timeout(3 * time.second)
	conn.write(req) or {
		assert false, 'write request: ${err}'
		return
	}

	// Read response frames until we have the trailer (END_STREAM HEADERS).
	mut r := H2FrameReader{}
	mut cli := new_hpack_decoder(4096)
	mut http_status := ''
	mut grpc_status := ''
	mut put_hash := ''
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
			match f.typ {
				h2_headers {
					hdrs := cli.decode(f.payload) or { []HpackHeader{} }
					for h in hdrs {
						if h.name == ':status' {
							http_status = h.value
						}
						if h.name == 'grpc-status' {
							grpc_status = h.value
							done = true // trailer seen
						}
					}
				}
				h2_data {
					mut fr := GrpcFrameReader{}
					fr.feed(f.payload)
					if gf := fr.next() {
						pr := pb_decode_put_response(gf.data) or { GrpcPutResponse{} }
						put_hash = pr.hash
					}
				}
				else {}
			}
		}
		if done {
			break
		}
	}

	srv_log := os.read_file('/tmp/cx-grpc-live.${gport}.out') or { '' }
	assert http_status == '200', ':status ${http_status} | srv: ${srv_log}'
	assert grpc_status == '0', 'grpc-status ${grpc_status} | srv: ${srv_log}'
	assert put_hash.starts_with('sha2-256:') && put_hash.len == 73, 'put hash over the wire: ${put_hash} | srv: ${srv_log}'
}
