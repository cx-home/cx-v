// store_remote_alias_unsupported_test.v — issue #264: CSRP carries NO alias
// verbs (the M3 design decision), so the CX-level alias family on a
// remote-backed handle must refuse with CXER1709 — never a silent empty
// (get/list) or a silent local no-op ack (set). Same posture as query
// pushdown (#119): honest refusal over a lying success.
//
// Real two-process lane, mirroring xap_registry_serve_real_test.v: a served
// file:// store over `[$store:csrp-handle]`, a client on a
// `cx-store+http://` handle probing all three ops.
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
// BOTH absence and err values, so it cannot distinguish an honest CXER1709
// from the old silent-empty. Each lane folds to its err code, or a marker.
fn sra_client_prog(port int) string {
	probe := fn (op string) string {
		return '[?match ${op} [case [err \$e] [\$concat "" \$e@code]] [else "NO-ERR"]]'
	}
	return "[?lib 'cx-stdlib/store' :as store]\n" +
		'[?let [= \$c [\$store:open "cx-store+http://127.0.0.1:${port}/probe/"]]\n' +
		'[?let [= \$ga ' + probe('[\$store:get-alias \$c "x"]') + ']\n' +
		'[?let [= \$la ' + probe('[\$store:list-aliases \$c]') + ']\n' +
		'[?let [= \$sa ' + probe('[\$store:set-alias \$c "x" "deadbeef"]') + ']\n' +
		'[result [ga \$ga] [la \$la] [sa \$sa]]\n' + ']]]]\n'
}

fn test_remote_alias_ops_refuse_cxer1709() {
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
	// every lane refuses honestly; none returns the silent-empty/no-op shape.
	for lane in ['ga', 'la', 'sa'] {
		lane_txt := body.all_after('[${lane} ').all_before(']')
		assert lane_txt.contains('CXER1709'), '${lane} did not refuse: ${lane_txt}'
	}
	assert !body.contains('NO-ERR'), 'an alias op succeeded silently on a remote handle: ${body}'
}
