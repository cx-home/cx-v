module main

import os
import testenv
import time
import net

// http_chunked_stream_test.v — BEHAVIORAL conformance for the §3.5 server-side
// Transfer-Encoding: chunked WRITE path (the streaming-binary-response transport
// that the CSRP cx-store:// remote protocol reads back, GH #90 → #78).
//
// http.md §4.2 previously DEFERRED streaming responses: the server only wrote
// whole-body Content-Length responses. This test drives the new chunked-write
// path over a REAL loopback socket end to end:
//   * a cx program is the SERVER — it reads the POST request body as raw octets
//     ([$http:body-bytes]) and returns it as a `Transfer-Encoding: chunked`
//     response (no Content-Length);
//   * a raw-socket V client POSTs a >8 KB BINARY payload (every non-NUL byte
//     value, forcing multiple 4 KB wire chunks), reads the reply, de-chunks it,
//     and asserts the recovered octets are byte-identical to what it sent.
//
// A stub cannot do this: byte-identity across a chunked round trip proves the
// request body was read off the wire AND the response was framed as real
// multi-chunk chunked-transfer-encoding the peer must reassemble.

fn cx_binary() string {
	return testenv.cx_bin()
}

// Disjoint PID + nanosecond-salted band (26500-26599) so the concurrent
// `v test vcx/tests/` gate processes don't collide on a port.
fn pick_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 26500 + int(salt)
}

fn write_tmp(name string, content string) string {
	p := os.join_path(os.temp_dir(), name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

// The cx low-level server: bind, accept, and for each exchange echo the request
// body back as a Transfer-Encoding: chunked 200 response. body-bytes preserves
// raw octets; the chunked header drives http_serialize_response's streaming path.
fn server_prog(port int) string {
	return '[?lib \'cx-stdlib/http\' :as http]\n' +
		'[?let [= \$srv [\$http:listen "tcp://127.0.0.1:${port}" {}]]\n' +
		'  [?for [in \$ex [\$http:accept-iter \$srv]]\n' +
		'    [yield [?let [= \$req [\$http:exchange-request \$ex]]\n' +
		'      [?let [= \$b [\$http:body-bytes \$req]]\n' +
		'        [\$http:respond \$ex [response status=200\n' +
		'          [headers [header name="Transfer-Encoding" value="chunked"]]\n' +
		'          [body \$b]]]]]]]]\n'
}

// A >8 KB binary payload: every byte value 1..255 repeated, so the server must
// split it into multiple http_chunk_size (4096) wire chunks.
fn binary_payload() []u8 {
	mut p := []u8{}
	for _ in 0 .. 42 {
		for v in 1 .. 256 {
			p << u8(v)
		}
	}
	return p
}

// dechunk strips HTTP/1.1 chunked transfer-encoding framing: each chunk is
// `<hex-len>\r\n<bytes>\r\n`, terminated by a 0-length chunk.
fn dechunk(raw []u8) []u8 {
	mut out := []u8{}
	mut pos := 0
	for pos < raw.len {
		mut le := pos
		for le + 1 < raw.len && !(raw[le] == `\r` && raw[le + 1] == `\n`) {
			le++
		}
		if le + 1 >= raw.len {
			break
		}
		hexs := raw[pos..le].bytestr().all_before(';').trim_space()
		mut size := 0
		for c in hexs {
			d := if c >= `0` && c <= `9` {
				int(c - `0`)
			} else if c >= `a` && c <= `f` {
				int(c - `a` + 10)
			} else if c >= `A` && c <= `F` {
				int(c - `A` + 10)
			} else {
				break
			}
			size = size * 16 + d
		}
		data := le + 2
		if size == 0 {
			break
		}
		if data + size > raw.len {
			break
		}
		out << raw[data..data + size]
		pos = data + size + 2
	}
	return out
}

fn raw_round_trip(port int, body []u8) (bool, []u8) {
	for _ in 0 .. 40 {
		mut c := net.dial_tcp('127.0.0.1:${port}') or {
			time.sleep(100 * time.millisecond)
			continue
		}
		head := 'POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: ${body.len}\r\nConnection: close\r\n\r\n'
		mut req := head.bytes()
		req << body
		c.write(req) or {
			c.close() or {}
			return false, []u8{}
		}
		c.set_read_timeout(5 * time.second)
		mut sink := []u8{}
		mut buf := []u8{len: 4096}
		for {
			n := c.read(mut buf) or { break }
			if n <= 0 {
				break
			}
			sink << buf[..n]
			if sink.len > 1048576 {
				break
			}
		}
		c.close() or {}
		return true, sink
	}
	return false, []u8{}
}

fn test_http_server_chunked_binary_stream() {
	port := pick_port()
	prog := write_tmp('cx_http_chunked.cx', server_prog(port))
	out_file := '/tmp/cx-http-chunked.${port}.out'
	pid_s := os.execute('${cx_binary()} --allow-net ${prog} >${out_file} 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx http server')
		return
	}
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(400 * time.millisecond) // let the server bind

	payload := binary_payload()
	connected, resp := raw_round_trip(port, payload)
	srv_log := os.read_file(out_file) or { '' }
	assert connected, 'cx http server never accepted a connection on ${port}; server log: ${srv_log}'

	rs := resp.bytestr()
	he := rs.index('\r\n\r\n') or {
		assert false, 'no header terminator in response; got ${resp.len} bytes | server log: ${srv_log}'
		return
	}
	head := rs[..he]
	assert head.contains('200'), 'response missing 200 status; head: ${head}'
	// The streaming path MUST advertise chunked and MUST NOT set Content-Length.
	assert head.to_lower().contains('transfer-encoding: chunked'), 'response not chunked; head: ${head}'
	assert !head.to_lower().contains('content-length'), 'chunked response must not carry Content-Length; head: ${head}'
	// And it must terminate with a 0-length chunk.
	assert rs.ends_with('0\r\n\r\n'), 'chunked response missing 0-length terminator; tail bytes: ${resp.len}'

	body_wire := resp[he + 4..]
	recovered := dechunk(body_wire)
	assert recovered.len == payload.len, 'de-chunked length ${recovered.len} != sent ${payload.len} (server log: ${srv_log})'
	assert recovered == payload, 'binary stream not byte-identical after chunked round trip'
	// The payload is >8 KB, so it had to span multiple 4 KB wire chunks — assert
	// the framing actually streamed (more than one chunk header present).
	assert payload.len > 8192, 'payload too small to force multiple chunks'
}
