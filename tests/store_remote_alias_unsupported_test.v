// store_remote_alias_unsupported_test.v — #264 → #645: the remote alias contract.
//
// #264 established the honest-refusal posture: never a silent empty (get/list)
// and never a silent local no-op ack (set) on a remote handle. #645 keeps that
// posture but gives CSRP handles a REAL answer: get/list/set-alias route to the
// daemon's authoritative alias table over the `aliases` / `aliases-set` wire
// ops with EXPLICIT per-name presence, so a miss is a server-asserted absence
// — not a guess, not a refusal. Byte-source remotes (http/ftp/sftp) still
// refuse with CXER1709: there is no service to ask.
//
// Real two-process lane, mirroring xap_registry_serve_real_test.v: a served
// file:// store over `[$store:csrp-handle]`, a client on a
// `cx-store+http://` handle driving the full alias family.
module main

import os
import testenv
import time

fn sra_cx_binary() string {
	return testenv.cx_bin()
}

// Disjoint port band (26800-26899) from the http/csrp/registry test bands.
fn sra_pick_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 26800 + int(salt)
}

fn sra_write_tmp(name string, content string) string {
	p := os.join_path(os.temp_dir(), name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

fn sra_server_prog(port int, store_dir string) string {
	return "[?lib 'cx-stdlib/http' :as http]\n" + "[?lib 'cx-stdlib/store' :as store]\n" +
		'[?let [= \$local [\$store:open "file://${store_dir}"]]\n' +
		'  [?let [= \$srv [\$http:listen "tcp://127.0.0.1:${port}" {}]]\n' +
		'    [?for [in \$ex [\$http:accept-iter \$srv]]\n' +
		'      [yield [\$store:csrp-handle \$ex \$local]]]]]\n'
}

// §9.2: err handling is [?match V [case [err …]]] ONLY — [?else] defaults on
// BOTH absence and err values. Each lane folds to its err code or a marker.
fn sra_client_prog(port int) string {
	probe := fn (op string) string {
		return '[?match ${op} [case [err \$e] [\$concat "" \$e@code]] [else "NO-ERR"]]'
	}
	return "[?lib 'cx-stdlib/store' :as store]\n" +
		'[?let [= \$c [\$store:open "cx-store+http://127.0.0.1:${port}/probe/"]]\n' +
		// a miss is a server-asserted absence (present="false" on the wire) → no err.
		'[?let [= \$ga-miss [?if [= [\$count [\$store:get-alias \$c "nope"]] 0] [then "ABSENT"] [else "PRESENT"]]]\n' +
		// set-alias to a hash the daemon does not hold refuses loudly (CXER1121).
		'[?let [= \$sa-dangling ' + probe('[\$store:set-alias \$c "x" "deadbeef"]') + ']\n' +
		// the live round trip: put a doc through the object wire, alias it, read it back.
		'[?let [= \$h [\$store:put-doc \$c [probe x=2]]]\n' +
		'[?let [= \$sa ' + probe('[\$store:set-alias \$c "probe" \$h]') + ']\n' +
		'[?let [= \$ga [?if [= [\$store:get-alias \$c "probe"] \$h] [then "ROUNDTRIP"] [else "MISMATCH"]]]\n' +
		'[?let [= \$la [\$count [\$store:list-aliases \$c]]]\n' +
		// a byte-source remote keeps the honest refusal — no service to ask.
		'[?let [= \$bs [\$store:open "http://127.0.0.1:1/never-dialed.cx"]]\n' +
		'[?let [= \$bs-ga ' + probe('[\$store:get-alias \$bs "x"]') + ']\n' +
		'[result [ga-miss \$ga-miss] [sa-dangling \$sa-dangling] [sa \$sa] [ga \$ga] [la \$la] [bs-ga \$bs-ga]]\n' +
		']]]]]]]]]\n'
}

fn test_remote_alias_family_wire_contract() {
	port := sra_pick_port()
	store_dir := os.join_path(os.temp_dir(), 'cx-sra-store-${port}')
	os.mkdir_all(store_dir) or { panic('mkdir ${store_dir}: ${err}') }
	defer {
		os.rmdir_all(store_dir) or {}
	}
	// seed the store so the served handle is a real, non-empty store.
	seed := sra_write_tmp('cx_sra_seed.cx', "[?lib 'cx-stdlib/store' :as store]\n" +
		'[?let [= \$s [\$store:open "file://${store_dir}"]]\n' +
		'[\$store:put-doc \$s "[probe x=1]"]]\n')
	seed_r := os.execute('${sra_cx_binary()} --allow-all ${seed}')
	assert seed_r.exit_code == 0, 'seed failed: ${seed_r.output}'

	srv := sra_write_tmp('cx_sra_srv.cx', sra_server_prog(port, store_dir))
	cli := sra_write_tmp('cx_sra_cli.cx', sra_client_prog(port))
	srv_out := '/tmp/cx-sra-srv.${port}.out'

	pid_s := os.execute('${sra_cx_binary()} --allow-all ${srv} >${srv_out} 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn store server')
		return
	}
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	// wait for the listener.
	mut up := false
	for _ in 0 .. 50 {
		r := os.execute('nc -z 127.0.0.1 ${port} 2>/dev/null')
		if r.exit_code == 0 {
			up = true
			break
		}
		time.sleep(100 * time.millisecond)
	}
	assert up, 'server never bound :${port} — ${os.read_file(srv_out) or { '' }}'

	out := os.execute('${sra_cx_binary()} --allow-net=127.0.0.1 ${cli}')
	assert out.exit_code == 0, 'client failed: ${out.output}'
	body := out.output
	lane := fn [body] (name string) string {
		return body.all_after('[${name} ').all_before(']')
	}
	// CSRP handle: a miss is a server-asserted absence, never an err/refusal.
	assert lane('ga-miss').contains('ABSENT'), 'miss must be absence: ${lane('ga-miss')}'
	// a dangling target refuses with the same CXER1121 a local set-alias raises.
	assert lane('sa-dangling').contains('CXER1121'), 'dangling set-alias must refuse: ${lane('sa-dangling')}'
	// live round trip through the daemon's authoritative table.
	assert lane('sa').contains('NO-ERR'), 'set-alias must apply: ${lane('sa')}'
	assert lane('ga').contains('ROUNDTRIP'), 'get-alias must resolve the daemon alias: ${lane('ga')}'
	assert lane('la') == '1', 'listing carries exactly the applied alias: ${lane('la')}'
	// byte-source remote: the #264 honest refusal is unchanged.
	assert lane('bs-ga').contains('CXER1709'), 'byte-source get-alias must refuse: ${lane('bs-ga')}'
}
