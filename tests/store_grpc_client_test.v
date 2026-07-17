module main

import os
import testenv
import net
import time

// store_grpc_client_test.v — #123 follow-up: the gRPC CLIENT transport. A daemon
// (`cx store-serve` with [grpc enabled]) is the SERVER; a cx program is the
// CLIENT, opening `cx-store+grpc://127.0.0.1:PORT/t/` and driving the FULL
// Layer-1 surface (put → get → exists → list → query → iter → modify → delete)
// over a real HTTP/2 + protobuf socket. This is what makes the gRPC server
// usable: the same `[$store:open]` ops, just a different transport scheme. The
// round trip proves the client framing/decoding end-to-end — none of which a stub
// could fake. Black-box; loopback net only; skips when the cx binary is absent.

fn grpc_cli_bin() string {
	return testenv.cx_bin()
}

fn grpc_cli_free_port() int {
	mut l := net.listen_tcp(.ip, '127.0.0.1:0') or { return 0 }
	port := l.addr() or { return 0 }.port() or { return 0 }
	l.close() or {}
	return port
}

fn grpc_cli_write_tmp(name string, content string) string {
	p := os.join_path(os.temp_dir(), name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

// The gRPC client program: open the store over cx-store+grpc:// and exercise
// every op, emitting a single [result …] the test asserts on.
fn grpc_cli_client_prog(gport int) string {
	return "[?lib 'cx-stdlib/store' :as store]\n" +
		'[?let [= \$c [\$store:open "cx-store+grpc://127.0.0.1:${gport}/t/"]]\n' +
		'[?let [= \$h [\$store:put-doc \$c [note [title "grpc-client"] [body "over-grpc"]]]]\n' +
		'[?let [= \$got [\$store:get-doc-text \$c \$h]]\n' +
		'[?let [= \$ex [\$store:exists \$c \$h]]\n' +
		'[?let [= \$n [\$count [\$store:list-docs \$c]]]\n' +
		'[?let [= \$q [\$count [\$store:query \$c "//title"]]]\n' +
		'[?let [= \$it [\$count [\$store:iter-docs \$c]]]\n' +
		'[?let [= \$h2 [\$store:modify-doc \$c \$h [set-attr name=tag value="GRPCMOD"]]]\n' +
		'[?let [= \$m [\$store:get-doc-text \$c \$h2]]\n' +
		'[?let [= \$del [\$store:delete-doc \$c \$h]]\n' +
		'[result [got \$got] [exists \$ex] [count \$n] [q \$q] [iter \$it] [changed [= \$h \$h2]] [modified \$m] [deleted \$del]]\n' +
		']]]]]]]]]]\n'
}

fn grpc_cli_daemon_cfg(cport int, gport int) string {
	return '[cxstore-service\n' + '  [bind addr="127.0.0.1:${cport}"]\n' +
		'  [grpc enabled=true addr="127.0.0.1:${gport}"]\n' + '  [stores\n' +
		'    [store name="t" url="mem://grpc-client"]]]\n'
}

fn test_grpc_client_full_round_trip() {
	bin := grpc_cli_bin()
	cport := grpc_cli_free_port()
	gport := grpc_cli_free_port()
	if cport == 0 || gport == 0 || cport == gport {
		eprintln('SKIP: could not allocate ports')
		return
	}
	cfg := grpc_cli_write_tmp('cx_grpc_cli_${gport}.cx', grpc_cli_daemon_cfg(cport, gport))
	cli := grpc_cli_write_tmp('cx_grpc_cli_prog_${gport}.cx', grpc_cli_client_prog(gport))
	srv_out := '/tmp/cx-grpc-cli-srv.${gport}.out'
	defer {
		os.rm(cfg) or {}
		os.rm(cli) or {}
	}

	// SERVER: the daemon binds both CSRP (cport) + gRPC (gport).
	pid_s := os.execute('${bin} store-serve --config ${cfg} --allow-net=127.0.0.1:${cport} --allow-net=127.0.0.1:${gport} >${srv_out} 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx store-serve')
		return
	}
	pid := pid_s.output.trim_space()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(800 * time.millisecond) // let both listeners bind

	// CLIENT: only needs the gRPC port.
	res := os.execute('${bin} --allow-net=127.0.0.1:${gport} ${cli}')
	srv_log := os.read_file(srv_out) or { '' }
	out := res.output

	assert res.exit_code == 0, 'grpc client exited ${res.exit_code}; out: ${out} | srv: ${srv_log}'
	// put → get round-trips the body over gRPC.
	assert out.contains('over-grpc'), 'doc body did not round-trip over gRPC; out: ${out} | srv: ${srv_log}'
	// the full surface, each op served over gRPC:
	assert out.contains('[exists true]'), 'exists should be true; out: ${out} | srv: ${srv_log}'
	assert out.contains('[count 1]'), 'list-docs should report 1 doc; out: ${out} | srv: ${srv_log}'
	assert out.contains('[q 1]'), 'query //title should match 1 doc over gRPC; out: ${out} | srv: ${srv_log}'
	assert out.contains('[iter 1]'), 'iter-docs should enumerate 1 doc over gRPC; out: ${out} | srv: ${srv_log}'
	// modify yields a NEW content-address ([changed false] == "$h equals $h2 is false").
	assert out.contains('[changed false]'), 'modify-doc must yield a new content-address over gRPC; out: ${out} | srv: ${srv_log}'
	assert out.contains('GRPCMOD'), 'the set-attr modification must round-trip over gRPC; out: ${out} | srv: ${srv_log}'
	assert out.contains('[deleted true]'), 'delete-doc should report success over gRPC; out: ${out} | srv: ${srv_log}'
}

// test_grpc_client_not_found — a get of an absent hash over gRPC maps NOT_FOUND(5)
// back to the store absence channel (empty seq), NOT a fabricated doc or a crash.
fn grpc_cli_missing_prog(gport int) string {
	return "[?lib 'cx-stdlib/store' :as store]\n" +
		'[?let [= \$c [\$store:open "cx-store+grpc://127.0.0.1:${gport}/t/"]]\n' +
		'[result [missing [\$store:exists \$c "0000000000000000000000000000000000000000000000000000000000000000"]]]\n' +
		']\n'
}

fn test_grpc_client_not_found() {
	bin := grpc_cli_bin()
	cport := grpc_cli_free_port()
	gport := grpc_cli_free_port()
	if cport == 0 || gport == 0 || cport == gport {
		eprintln('SKIP: could not allocate ports')
		return
	}
	cfg := grpc_cli_write_tmp('cx_grpc_cli_nf_${gport}.cx', grpc_cli_daemon_cfg(cport, gport))
	cli := grpc_cli_write_tmp('cx_grpc_cli_nf_prog_${gport}.cx', grpc_cli_missing_prog(gport))
	srv_out := '/tmp/cx-grpc-cli-nf-srv.${gport}.out'
	defer {
		os.rm(cfg) or {}
		os.rm(cli) or {}
	}
	pid_s := os.execute('${bin} store-serve --config ${cfg} --allow-net=127.0.0.1:${cport} --allow-net=127.0.0.1:${gport} >${srv_out} 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx store-serve')
		return
	}
	pid := pid_s.output.trim_space()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(800 * time.millisecond)

	res := os.execute('${bin} --allow-net=127.0.0.1:${gport} ${cli}')
	srv_log := os.read_file(srv_out) or { '' }
	out := res.output
	assert res.exit_code == 0, 'grpc missing client exited ${res.exit_code}; out: ${out} | srv: ${srv_log}'
	assert out.contains('[missing false]'), 'exists of an absent hash over gRPC must be false (NOT_FOUND mapped to absence); out: ${out} | srv: ${srv_log}'
}

// test_grpc_http_client_parity — the two client transports are interchangeable:
// one daemon, one store, the SAME doc put via cx-store+http:// (CSRP) and via
// cx-store+grpc:// yields the SAME content address, and a doc put over one
// transport reads back over the other. Parity by construction — both clients
// drive the same store through different framing.
fn grpc_cli_parity_prog(cport int, gport int) string {
	return "[?lib 'cx-stdlib/store' :as store]\n" +
		'[?let [= \$hc [\$store:open "cx-store+http://127.0.0.1:${cport}/t/"]]\n' +
		'[?let [= \$gc [\$store:open "cx-store+grpc://127.0.0.1:${gport}/t/"]]\n' +
		'[?let [= \$hh [\$store:put-doc \$hc [note [body "parity-doc"]]]]\n' +
		'[?let [= \$gh [\$store:put-doc \$gc [note [body "parity-doc"]]]]\n' +
		'[?let [= \$cross [\$store:get-doc-text \$gc \$hh]]\n' +
		'[result [same [= \$hh \$gh]] [cross \$cross]]\n' +
		']]]]]\n'
}

fn test_grpc_http_client_parity() {
	bin := grpc_cli_bin()
	cport := grpc_cli_free_port()
	gport := grpc_cli_free_port()
	if cport == 0 || gport == 0 || cport == gport {
		eprintln('SKIP: could not allocate ports')
		return
	}
	cfg := grpc_cli_write_tmp('cx_grpc_cli_par_${gport}.cx', grpc_cli_daemon_cfg(cport, gport))
	cli := grpc_cli_write_tmp('cx_grpc_cli_par_prog_${gport}.cx', grpc_cli_parity_prog(cport,
		gport))
	srv_out := '/tmp/cx-grpc-cli-par-srv.${gport}.out'
	defer {
		os.rm(cfg) or {}
		os.rm(cli) or {}
	}
	pid_s := os.execute('${bin} store-serve --config ${cfg} --allow-net=127.0.0.1:${cport} --allow-net=127.0.0.1:${gport} >${srv_out} 2>&1 & echo \$!')
	if pid_s.exit_code != 0 {
		eprintln('SKIP: could not spawn cx store-serve')
		return
	}
	pid := pid_s.output.trim_space()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	time.sleep(800 * time.millisecond)

	// the client needs net to BOTH the CSRP port and the gRPC port.
	res := os.execute('${bin} --allow-net=127.0.0.1:${cport} --allow-net=127.0.0.1:${gport} ${cli}')
	srv_log := os.read_file(srv_out) or { '' }
	out := res.output
	assert res.exit_code == 0, 'grpc parity client exited ${res.exit_code}; out: ${out} | srv: ${srv_log}'
	// Same doc, same content address, regardless of transport.
	assert out.contains('[same true]'), 'CSRP-client and gRPC-client puts of the same doc must yield the same hash; out: ${out} | srv: ${srv_log}'
	// A doc put over CSRP reads back over gRPC (one store, two transports).
	assert out.contains('parity-doc'), 'a doc put over CSRP must read back over gRPC; out: ${out} | srv: ${srv_log}'
}
