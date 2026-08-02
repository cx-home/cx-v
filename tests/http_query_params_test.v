module main

import os
import testenv
import time

// http_query_params_test.v — #627: a GET's URL query string reaches the
// handler as parsed [query-params] (the locked §2.2 shape: one
// [<name> "<value>"] child per pair, percent-decoded, `+` = space) on the
// socket-listener lane. Pre-fix the container arrived EMPTY and the raw query
// was unrecoverable — GET parameterization was impossible.

fn qp_port() int {
	// Disjoint band (25700-25799) from http_serve_module_test (25600-25699).
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 25700 + int(salt)
}

fn test_module_serve_populates_query_params() {
	if os.execute('which curl').exit_code != 0 {
		eprintln('SKIP: curl not available')
		return
	}
	tmp := os.temp_dir()
	port := qp_port()
	prog := os.join_path(tmp, 'serve-qp-${time.now().unix_milli()}.cx')
	// the handler echoes two query params (one percent-encoded) plus the
	// count, proving the container is populated, decoded, and readable via
	// the terminal labeled-field unwrap.
	os.write_file(prog, '
[?lib \'cx-stdlib/http\']
[?def h (\$req::element)
  [response status=200
    [body [?str \'as={[?else \$req/query-params/as ""]}|role={[?else \$req/query-params/role ""]}|n={[\$count \$req/query-params/*]}\']]]]
[\$http:serve "tcp://127.0.0.1:${port}" \$h {block: true}]
') or { panic(err) }
	defer {
		os.rm(prog) or {}
	}
	cmd := '${testenv.cx_bin()} --allow-net ${prog} >/tmp/cx-serve-qp.${port}.out 2>&1 & echo $!'
	res := os.execute(cmd)
	if res.exit_code != 0 {
		panic('spawn failed: ${res.output}')
	}
	pid := res.output.trim_space().int()
	defer {
		os.execute('kill ${pid}')
	}
	mut waited := 0
	mut up := false
	for waited < 50 {
		probe := os.execute('curl -s -o /dev/null -w "%{http_code}" --max-time 1 "http://127.0.0.1:${port}/x"')
		if probe.exit_code == 0 && probe.output != '' && probe.output != '000' {
			up = true
			break
		}
		time.sleep(100 * time.millisecond)
		waited++
	}
	assert up, 'listener never bound: ${os.read_file('/tmp/cx-serve-qp.${port}.out') or { '(none)' }}'

	got := os.execute('curl -s --max-time 3 "http://127.0.0.1:${port}/pane/queue?as=amy&role=a%20e"')
	assert got.exit_code == 0, 'curl failed: ${got.output}'
	assert got.output.contains('as=amy'), 'query param `as` lost (#627): ${got.output}'
	assert got.output.contains('role=a e'), 'query param not percent-decoded: ${got.output}'
	assert got.output.contains('n=2'), 'query-params container wrong arity: ${got.output}'

	// no query → empty container, path routing unaffected
	none_got := os.execute('curl -s --max-time 3 "http://127.0.0.1:${port}/pane/queue"')
	assert none_got.output.contains('n=0'), 'query-less request must have an empty container: ${none_got.output}'
}
