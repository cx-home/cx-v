module main

import os
import time

// v08_xap_serve_cap_test.v — [$xap:serve] MUST gate `net` before binding
// (xap.md §6: serve needs net via http; the sibling http_serve_env guards
// identically). Without --allow-net it must surface CXER0271 and bind NOTHING.
// Red against the pre-fix build (which bound a real socket with no grant).

fn cx_binary() string {
	abs := os.real_path('vcx/target/cx')
	if !os.is_file(abs) {
		panic('vcx/target/cx not found at ${abs} — run `make build-vcx` first')
	}
	return abs
}

fn test_xap_serve_requires_net_grant() {
	port := 19950 + int(time.now().unix_milli() % 40)
	dir := os.temp_dir()
	prog := os.join_path(dir, 'cx_xap_serve_nonet.cx')
	os.write_file(prog, '[?lib \'cx-xap\' :as xap]\n' +
		'[\$xap:component g {bind: "/g" view: [?fn (\$s) [panel [text "hi"]]]}]\n' +
		'[?let [= \$rt [\$xap:run {tenant: "demo" components: (g)}]]\n' +
		'  [\$xap:serve "http://127.0.0.1:${port}" {runtime: \$rt}]]\n') or { panic(err) }

	// NO --allow-net: serve must deny BEFORE binding, so the program exits
	// promptly with the denial value rather than parking as a daemon.
	res := os.execute('${cx_binary()} ${prog}')
	assert res.output.contains('CXER0271'), 'xap serve without --allow-net must be denied (CXER0271); got: ${res.output}'

	// and nothing must be listening on the port.
	probe := os.execute('curl -s -o /dev/null -w "%{http_code}" --max-time 1 http://127.0.0.1:${port}/')
	assert probe.output != '200', 'xap serve bound a socket on ${port} with no net grant!'
}
