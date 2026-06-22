module main

import os
import net
import time

// http_handler_no_respond_test.v — #23: an accept-iter handler that returns
// WITHOUT responding (e.g. a denied capability poisons the response argument, so
// [$http:respond] short-circuits on the err-value and never writes) must NOT
// leave the connection dangling with no diagnostic. The accept loop surfaces it
// on stderr and closes the connection so the client gets EOF instead of hanging.
//
// Drives a real cx server (denied --allow-env) over a loopback socket.

fn cx_bin_h23() string {
	abs := os.real_path('vcx/target/cx')
	if !os.is_file(abs) {
		panic('vcx/target/cx not found at ${abs} — run `make build-vcx` first')
	}
	return abs
}

fn pick_port_h23() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 26500 + int(salt)
}

// Handler is a [?def] route called with a DENIED-env value as an argument.
// Under --allow-net only, [$env:var-or-default] yields a CXER0271 err-value;
// the call [$route $ex $k] then short-circuits on the err-value ARG (error-as-
// value propagation), so the route body — and its [$http:respond] — never run.
// The handler returns the err-value without responding: the #23 case.
fn server_prog_no_respond(port int) string {
	return "[?lib 'cx-stdlib/http' :as http]\n" + "[?lib 'cx-stdlib/env' :as env]\n" +
		'[?def route impure (\$ex \$k)\n' +
		'  [\$http:respond \$ex [response status=200 [body \$k]]]]\n' +
		'[?let [= \$k [\$env:var-or-default "SOME_VAR" "fallback"]]\n' +
		'      [= \$srv [\$http:listen "tcp://127.0.0.1:${port}" {}]]\n' +
		'  [?for [in \$ex [\$http:accept-iter \$srv]]\n' +
		'    [yield [\$route \$ex \$k]]]]\n'
}

fn test_handler_without_response_is_surfaced() {
	port := pick_port_h23()
	prog := os.join_path(os.temp_dir(), 'cx_h23_${os.getpid()}.cx')
	os.write_file(prog, server_prog_no_respond(port)) or { panic('write: ${err}') }
	defer { os.rm(prog) or {} }
	out_file := '/tmp/cx-h23.${port}.out'
	pid_s := os.execute('${cx_bin_h23()} --allow-net ${prog} >${out_file} 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx http server')
		return
	}
	pid := pid_s.output.trim_space()
	defer { os.execute('kill ${pid} 2>/dev/null') }

	mut connected := false
	for _ in 0 .. 40 {
		mut c := net.dial_tcp('127.0.0.1:${port}') or {
			time.sleep(100 * time.millisecond)
			continue
		}
		connected = true
		c.write_string('POST /x HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc') or {}
		// If the fix works the server CLOSES the connection, so this read
		// returns promptly with EOF rather than blocking to the timeout.
		c.set_read_timeout(3 * time.second)
		mut buf := []u8{len: 1024}
		c.read(mut buf) or {}
		c.close() or {}
		break
	}
	assert connected, 'could not connect to cx server on ${port}'
	time.sleep(200 * time.millisecond) // let the server flush its stderr
	log := os.read_file(out_file) or { '' }
	os.rm(out_file) or {}
	assert log.contains('without responding'),
		'expected the #23 fail-loud diagnostic (handler returned without responding); got: ${log}'
}
