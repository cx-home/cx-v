module code

import cx
import net
import time

// store_discovery_test.v — #234.2 / §5.3: capability discovery at open. The
// cx-store:// client GETs the server-level /capabilities and validates the
// advertised csrp-version MAJOR against its own. A same-major server opens
// normally; an incompatible-major server fails the open with CXER1100 rather than
// failing cryptically on the first op. A raw V TCP responder stands in for the
// server so the advertised version is fully controlled (hermetic, no cx subprocess).

// disco_serve accepts connections and answers each with a fixed 200 capabilities
// response, until `stop` is signalled by closing the listener from the test.
fn disco_serve(port int, caps string, mut l net.TcpListener) {
	body := caps.bytes()
	for {
		mut conn := l.accept() or { return } // listener closed → exit
		// drain the request head (until CRLFCRLF) so the client's read completes.
		mut buf := []u8{len: 2048}
		for {
			n := conn.read(mut buf) or { break }
			if n <= 0 {
				break
			}
			s := buf[..n].bytestr()
			if s.contains('\r\n\r\n') {
				break
			}
		}
		resp := 'HTTP/1.1 200 OK\r\nContent-Type: text/cx\r\nContent-Length: ${body.len}\r\nConnection: close\r\n\r\n'
		conn.write(resp.bytes()) or {}
		conn.write(body) or {}
		conn.close() or {}
	}
}

fn disco_open(port int) cx.Node {
	return store_open_impl('cx-store+http://127.0.0.1:${port}/t/', '', '', false, true,
		map[string]string{})
}

fn test_discovery_incompatible_version_fails_open() {
	caps_set_all()
	mut l := net.listen_tcp(.ip, '127.0.0.1:0') or {
		assert false, 'listen: ${err}'
		return
	}
	port := l.addr() or {
		assert false, 'addr'
		return
	}.port() or {
		assert false, 'port'
		return
	}
	caps := '[capabilities [csrp-version "2.0"] [server-impl "fake"] [encodings [supported "cxbin"] [default "cxbin"]]]'
	t := spawn disco_serve(port, caps, mut l)
	time.sleep(150 * time.millisecond)

	h := disco_open(port)
	// §5.3 step 2: incompatible major → open fails with CXER1100 naming the version.
	assert is_err_value(h), 'open against a csrp-version 2.0 server must fail (#234.2); got: ${h}'
	assert svc_err_code(h) == 'cx-err:CXER1100', 'incompatible version → CXER1100; got ${svc_err_code(h)}: ${svc_err_msg(h)}'
	assert svc_err_msg(h).contains('2.0'), 'the open error should name the server version 2.0; got: ${svc_err_msg(h)}'

	l.close() or {}
	t.wait()
}

fn test_discovery_compatible_version_opens() {
	caps_set_all()
	mut l := net.listen_tcp(.ip, '127.0.0.1:0') or {
		assert false, 'listen: ${err}'
		return
	}
	port := l.addr() or {
		assert false, 'addr'
		return
	}.port() or {
		assert false, 'port'
		return
	}
	caps := '[capabilities [csrp-version "1.4"] [server-impl "fake"] [encodings [supported "cxbin" "cxd"] [default "cxbin"]]]'
	t := spawn disco_serve(port, caps, mut l)
	time.sleep(150 * time.millisecond)

	h := disco_open(port)
	// same major (1) → open succeeds (a valid store handle, not an err).
	assert !is_err_value(h), 'open against a same-major (1.4) server must succeed; got: ${h}'

	l.close() or {}
	t.wait()
}
