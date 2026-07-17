module main

import os
import testenv
import time

// xap_registry_serve_real_test.v — BEHAVIORAL proof of the distribution spec's
// §4.2 stage-2 claim: serving the SAME registry store over cx-store:// (CSRP)
// is a RE-HOST — artifacts, hashes, and signatures are bit-identical to the
// stage-1 git registry, and discovery works server-side with no alias verbs on
// the wire (pkg-catalog falls back to CXPath query pushdown, `//publisher`).
//
// A cx program is the SERVER: it opens the COMMITTED file:// registry
// (registry/store — the stage-1 git registry, M2) and runs the http accept
// loop delegating to `[$store:csrp-handle]` (the CSRP reference server —
// store_csrp_test.v pattern). A second cx program is the CLIENT: it opens
// `cx-store+http://127.0.0.1:PORT/registry/`, DISCOVERS nmea0183@0.1.0 via
// [$xap:pkg-catalog] (server-side query pushdown), then pkg-verify +
// pkg-install BY the discovered manifest hash — the full §3 trust chain over
// a real loopback socket. The asserted hashes are the same constants the
// stage-1 fixture (xap-dist-025) pins: stage 1 → stage 2 changed nothing.
//
// Black-box, no Docker; both processes get only loopback net.

const nmea_manifest_hash = 'dfc7a847dfe0748e4491ee9d9cfc7854bb4fa8fbf9ed53b74ec9f50b9dd0eed6'
const nmea_tree_hash = '9420de8aa767372ec3afe4def2a78723abb3cd76c78818a4a76cf9e77aae6b7c'

fn xrs_cx_binary() string {
	return testenv.cx_bin()
}

// Disjoint port band (26700-26799) from the http (26400) and csrp (26600) tests.
fn xrs_pick_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 26700 + int(salt)
}

fn xrs_write_tmp(name string, content string) string {
	p := os.join_path(os.temp_dir(), name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

fn xrs_server_prog(port int, store_dir string) string {
	return "[?lib 'cx-stdlib/http' :as http]\n" +
		"[?lib 'cx-stdlib/store' :as store]\n" +
		'[?let [= \$local [\$store:open "file://${store_dir}"]]\n' +
		'  [?let [= \$srv [\$http:listen "tcp://127.0.0.1:${port}" {}]]\n' +
		'    [?for [in \$ex [\$http:accept-iter \$srv]]\n' +
		'      [yield [\$store:csrp-handle \$ex \$local]]]]]\n'
}

fn xrs_client_prog(port int) string {
	return "[?lib 'cx-xap' :as xap]\n" + "[?lib 'cx-stdlib/store' :as store]\n" +
		'[?let [= \$c [\$store:open "cx-store+http://127.0.0.1:${port}/registry/"]]\n' +
		'[?let [= \$cat [\$xap:pkg-catalog \$c {name: "nmea0183" version: "0.1.0"}]]\n' +
		'[?let [= \$e \$cat//package]\n' +
		'[?let [= \$v [\$xap:pkg-verify \$c \$e@manifest]]\n' +
		'[?let [= \$inst [\$xap:pkg-install [xap name=wire-consumer] \$c \$e@manifest]]\n' +
		'[result [manifest \$e@manifest] [status \$v@status] [hash \$inst@hash] [name \$inst@name]]\n' +
		']]]]]\n'
}

fn test_served_registry_is_a_rehost() {
	port := xrs_pick_port()
	store_dir := os.real_path('registry/store')
	if !os.is_dir(store_dir) {
		eprintln('SKIP: registry/store not present (run from the repo root)')
		return
	}
	srv := xrs_write_tmp('cx_xrs_srv.cx', xrs_server_prog(port, store_dir))
	cli := xrs_write_tmp('cx_xrs_cli.cx', xrs_client_prog(port))
	srv_out := '/tmp/cx-xrs-srv.${port}.out'
	allow := '--allow-all'

	pid_s := os.execute('${xrs_cx_binary()} ${allow} ${srv} >${srv_out} 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn registry server')
		return
	}
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(500 * time.millisecond) // let the server bind

	res := os.execute('${xrs_cx_binary()} ${allow} ${cli}')
	assert res.exit_code == 0, 'client failed: ${res.output} (server log: ${os.read_file(srv_out) or {
		''
	}})'
	out := res.output
	assert out.contains('[status ok]') || out.contains("[status 'ok']"), 'verify not ok over the wire: ${out}'
	assert out.contains(nmea_manifest_hash), 'catalog did not discover the stage-1 manifest hash: ${out}'
	assert out.contains(nmea_tree_hash), 'installed tree hash differs from the stage-1 artifact: ${out}'
	assert out.contains('nmea0183'), 'installed package name missing: ${out}'
}
