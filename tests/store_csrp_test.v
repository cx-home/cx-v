module main

import os
import testenv
import time

// store_csrp_test.v — BEHAVIORAL conformance for the CSRP cx-store:// round trip
// (#78, Phase 0.7). A cx program is the SERVER: it opens a local mem:// store
// and runs the §3.5 http accept loop, delegating each request to the V verb
// `[$store:csrp-handle $ex $local]`. A second cx program is the CLIENT: it opens
// `cx-store+http://127.0.0.1:PORT/teststore/` and drives the full Layer-1
// surface (put → get → exists → list → delete → exists) over a real loopback
// socket. The round trip proves cxd-text request/response framing, the hash
// echo, and the store-error mapping — none of which a stub could fake.
//
// Black-box like http_server_real_test.v. NO Docker. Both processes are granted
// only loopback net (--allow-net=127.0.0.1:PORT).

fn csrp_cx_binary() string {
	return testenv.cx_bin()
}

// Disjoint band (26600-26699) from the http server tests (26400-26499).
fn csrp_pick_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 26600 + int(salt)
}

fn csrp_write_tmp(name string, content string) string {
	p := os.join_path(os.temp_dir(), name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

// The CSRP reference server: one local mem:// store, accept loop delegating each
// exchange to the csrp-handle verb. $local is opened ONCE so doc state persists
// across the client's sequential connections.
fn csrp_server_prog(port int) string {
	return "[?lib 'cx-stdlib/http' :as http]\n" +
		"[?lib 'cx-stdlib/store' :as store]\n" + '[?let [= \$local [\$store:open "mem://"]]\n' +
		'  [?let [= \$srv [\$http:listen "tcp://127.0.0.1:${port}" {}]]\n' +
		'    [?for [in \$ex [\$http:accept-iter \$srv]]\n' +
		'      [yield [\$store:csrp-handle \$ex \$local]]]]]\n'
}

// The CSRP client: full Layer-1 CRUD against the remote store, emitting a single
// [result …] the test can assert on.
fn csrp_client_prog(port int) string {
	return "[?lib 'cx-stdlib/store' :as store]\n" +
		'[?let [= \$c [\$store:open "cx-store+http://127.0.0.1:${port}/teststore/"]]\n' +
		'[?let [= \$h [\$store:put-doc-text \$c "[note [body \\"csrp-roundtrip\\"]]"]]\n' +
		'[?let [= \$got [\$store:get-doc-text \$c \$h]]\n' +
		'[?let [= \$before [\$store:exists \$c \$h]]\n' +
		'[?let [= \$n [\$count [\$store:list-docs \$c]]]\n' +
		'[?let [= \$del [\$store:delete-doc \$c \$h]]\n' +
		'[?let [= \$after [\$store:exists \$c \$h]]\n' +
		'[result [got \$got] [before \$before] [count \$n] [deleted \$del] [after \$after]]\n' +
		']]]]]]]\n'
}

fn test_csrp_full_round_trip() {
	port := csrp_pick_port()
	srv := csrp_write_tmp('cx_csrp_srv.cx', csrp_server_prog(port))
	cli := csrp_write_tmp('cx_csrp_cli.cx', csrp_client_prog(port))
	srv_out := '/tmp/cx-csrp-srv.${port}.out'
	allow := '--allow-net=127.0.0.1:${port}'

	pid_s := os.execute('${csrp_cx_binary()} ${allow} ${srv} >${srv_out} 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx csrp server')
		return
	}
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(500 * time.millisecond) // let the server bind

	res := os.execute('${csrp_cx_binary()} ${allow} ${cli}')
	srv_log := os.read_file(srv_out) or { '' }
	out := res.output

	assert res.exit_code == 0, 'csrp client exited ${res.exit_code}; client out: ${out} | server log: ${srv_log}'
	// put → get must round-trip the doc body back over the wire.
	assert out.contains('csrp-roundtrip'), 'doc body did not round-trip through CSRP; client out: ${out} | server log: ${srv_log}'
	// exists is true before the delete, the list has exactly the one doc, the
	// delete reports success, and exists is false afterward — the full lifecycle.
	assert out.contains('[before true]'), 'exists should be true before delete; client out: ${out} | server log: ${srv_log}'
	assert out.contains('[count 1]'), 'list-docs should report exactly 1 doc; client out: ${out} | server log: ${srv_log}'
	assert out.contains('[deleted true]'), 'delete-doc should report success; client out: ${out} | server log: ${srv_log}'
	assert out.contains('[after false]'), 'exists should be false after delete; client out: ${out} | server log: ${srv_log}'
}

// test_csrp_query_pushdown — #119: `[$store:query]` over CSRP must be pushed to
// the server and return the server-side match, NOT silently scan the client's
// (empty) local doc map. Put a titled doc, query `//title` over the wire, and
// assert the match round-trips — the assertion the bug report would have caught
// (the same query against a local mem:// store returns one match).
fn csrp_query_client_prog(port int) string {
	return "[?lib 'cx-stdlib/store' :as store]\n" +
		'[?let [= \$c [\$store:open "cx-store+http://127.0.0.1:${port}/teststore/"]]\n' +
		'[?let [= \$h [\$store:put-doc \$c [note [title "csrp-query-hit"] [body "b"]]]]\n' +
		'[?let [= \$n [\$count [\$store:query \$c "//title"]]]\n' +
		'[result [count \$n] [matched [\$store:query \$c "//title"]]]\n' +
		']]]\n'
}

fn test_csrp_query_pushdown() {
	port := csrp_pick_port() + 1 // disjoint from the round-trip test's port
	srv := csrp_write_tmp('cx_csrp_q_srv.cx', csrp_server_prog(port))
	cli := csrp_write_tmp('cx_csrp_q_cli.cx', csrp_query_client_prog(port))
	srv_out := '/tmp/cx-csrp-q-srv.${port}.out'
	allow := '--allow-net=127.0.0.1:${port}'

	pid_s := os.execute('${csrp_cx_binary()} ${allow} ${srv} >${srv_out} 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx csrp server')
		return
	}
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(500 * time.millisecond)

	res := os.execute('${csrp_cx_binary()} ${allow} ${cli}')
	srv_log := os.read_file(srv_out) or { '' }
	out := res.output

	assert res.exit_code == 0, 'csrp query client exited ${res.exit_code}; out: ${out} | srv: ${srv_log}'
	// The query was executed SERVER-SIDE and the match returned over the wire —
	// not a silent empty scan of the client's local map.
	assert out.contains('[count 1]'), 'query //title should match exactly 1 doc over CSRP; out: ${out} | srv: ${srv_log}'
	assert out.contains('csrp-query-hit'), 'the matched [title] must round-trip through the CSRP query op; out: ${out} | srv: ${srv_log}'
}

// test_csrp_iter_pushdown — #123: `[$store:iter-docs $c]` over CSRP must be served
// by the server's iter op (server-authoritative enumeration), NOT scan the
// client's empty local doc map. Put two docs, iterate over the wire, and assert
// both round-trip — the count and both bodies come back from the server.
fn csrp_iter_client_prog(port int) string {
	return "[?lib 'cx-stdlib/store' :as store]\n" +
		'[?let [= \$c [\$store:open "cx-store+http://127.0.0.1:${port}/teststore/"]]\n' +
		'[?let [= \$h1 [\$store:put-doc \$c [note [body "iter-alpha"]]]]\n' +
		'[?let [= \$h2 [\$store:put-doc \$c [note [body "iter-beta"]]]]\n' +
		'[?let [= \$n [\$count [\$store:iter-docs \$c]]]\n' +
		'[result [count \$n] [docs [\$store:iter-docs \$c]]]\n' +
		']]]]\n'
}

fn test_csrp_iter_pushdown() {
	port := csrp_pick_port() + 2 // disjoint from the round-trip + query test ports
	srv := csrp_write_tmp('cx_csrp_i_srv.cx', csrp_server_prog(port))
	cli := csrp_write_tmp('cx_csrp_i_cli.cx', csrp_iter_client_prog(port))
	srv_out := '/tmp/cx-csrp-i-srv.${port}.out'
	allow := '--allow-net=127.0.0.1:${port}'

	pid_s := os.execute('${csrp_cx_binary()} ${allow} ${srv} >${srv_out} 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx csrp server')
		return
	}
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(500 * time.millisecond)

	res := os.execute('${csrp_cx_binary()} ${allow} ${cli}')
	srv_log := os.read_file(srv_out) or { '' }
	out := res.output

	assert res.exit_code == 0, 'csrp iter client exited ${res.exit_code}; out: ${out} | srv: ${srv_log}'
	// The iteration was served SERVER-SIDE and both docs returned over the wire.
	assert out.contains('[count 2]'), 'iter-docs should enumerate exactly 2 docs over CSRP; out: ${out} | srv: ${srv_log}'
	assert out.contains('iter-alpha'), 'the first doc must round-trip through the CSRP iter op; out: ${out} | srv: ${srv_log}'
	assert out.contains('iter-beta'), 'the second doc must round-trip through the CSRP iter op; out: ${out} | srv: ${srv_log}'
}

// test_csrp_modify_pushdown — #123: `[$store:modify-doc $c $h $action]` over CSRP
// must be applied SERVER-SIDE (the client's local doc map is empty for a remote
// handle, so a client-side modify would always report NOT_FOUND). Put a doc,
// modify it with set-attr over the wire, and assert the result is a NEW
// content-address whose doc carries the modification.
fn csrp_modify_client_prog(port int) string {
	return "[?lib 'cx-stdlib/store' :as store]\n" +
		'[?let [= \$c [\$store:open "cx-store+http://127.0.0.1:${port}/teststore/"]]\n' +
		'[?let [= \$h [\$store:put-doc \$c [note [body "pre-modify"]]]]\n' +
		'[?let [= \$h2 [\$store:modify-doc \$c \$h [set-attr name=tag value="MODIFIED"]]]\n' +
		'[?let [= \$got [\$store:get-doc-text \$c \$h2]]\n' +
		'[result [changed [= \$h \$h2]] [newdoc \$got]]\n' +
		']]]]\n'
}

fn test_csrp_modify_pushdown() {
	port := csrp_pick_port() + 3 // disjoint from the other CSRP test ports
	srv := csrp_write_tmp('cx_csrp_m_srv.cx', csrp_server_prog(port))
	cli := csrp_write_tmp('cx_csrp_m_cli.cx', csrp_modify_client_prog(port))
	srv_out := '/tmp/cx-csrp-m-srv.${port}.out'
	allow := '--allow-net=127.0.0.1:${port}'

	pid_s := os.execute('${csrp_cx_binary()} ${allow} ${srv} >${srv_out} 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx csrp server')
		return
	}
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(500 * time.millisecond)

	res := os.execute('${csrp_cx_binary()} ${allow} ${cli}')
	srv_log := os.read_file(srv_out) or { '' }
	out := res.output

	assert res.exit_code == 0, 'csrp modify client exited ${res.exit_code}; out: ${out} | srv: ${srv_log}'
	// modify-doc content-addresses the modified doc → a NEW hash (changed=false
	// means "$h equals $h2" — it must be false: the modification changed the hash).
	assert out.contains('[changed false]'), 'modify-doc must yield a NEW content-address over CSRP; out: ${out} | srv: ${srv_log}'
	// The modification (set-attr tag=MODIFIED) must be present in the new doc that
	// the server stored and the client fetched back by the new hash.
	assert out.contains('MODIFIED'), 'the set-attr modification must be applied server-side and round-trip; out: ${out} | srv: ${srv_log}'
}

// test_csrp_modify_using — #141: `modify-doc` with a `[using FN]` action on a
// REMOTE handle runs the lambda CLIENT-SIDE (get → transform → put; caller
// code is never shipped to the server) and stores the same new
// content-address a local store would produce.
fn csrp_using_client_prog(port int) string {
	return "[?lib 'cx-stdlib/store' :as store]\n" +
		'[?let [= \$c [\$store:open "cx-store+http://127.0.0.1:${port}/teststore/"]]\n' +
		'[?let [= \$h [\$store:put-doc \$c [targets [t mmsi="1"] [t mmsi="2"]]]]\n' +
		"[?let [= \$h2 [\$store:modify-doc \$c \$h [using [?fn (\$n) [hit \$n]] select=\"//t[= \$_@mmsi '1']\"]]]\n" +
		'[?let [= \$got [\$store:get-doc-text \$c \$h2]]\n' +
		'[result [changed [= \$h \$h2]] [newdoc \$got]]\n' +
		']]]]\n'
}

fn test_csrp_modify_using() {
	port := csrp_pick_port() + 4 // disjoint from the other CSRP test ports
	srv := csrp_write_tmp('cx_csrp_u_srv.cx', csrp_server_prog(port))
	cli := csrp_write_tmp('cx_csrp_u_cli.cx', csrp_using_client_prog(port))
	srv_out := '/tmp/cx-csrp-u-srv.${port}.out'
	allow := '--allow-net=127.0.0.1:${port}'

	pid_s := os.execute('${csrp_cx_binary()} ${allow} ${srv} >${srv_out} 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx csrp server')
		return
	}
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(500 * time.millisecond)

	res := os.execute('${csrp_cx_binary()} ${allow} ${cli}')
	srv_log := os.read_file(srv_out) or { '' }
	out := res.output

	assert res.exit_code == 0, 'csrp using client exited ${res.exit_code}; out: ${out} | srv: ${srv_log}'
	assert out.contains('[changed false]'), '[using FN] must yield a NEW content-address over CSRP; out: ${out} | srv: ${srv_log}'
	// FN received the keyed node and its return replaced it; the sibling is intact.
	assert out.contains("[hit [t mmsi='1'"), 'FN replacement missing from the round-tripped doc; out: ${out} | srv: ${srv_log}'
	assert out.contains("mmsi='2'"), 'non-matching sibling lost; out: ${out} | srv: ${srv_log}'
	assert !out.contains("[hit [t mmsi='2'"), 'FN applied to the non-matching sibling; out: ${out} | srv: ${srv_log}'
}
