module main

import os
import time

// a2a_real_test.v — BEHAVIORAL coverage for cx-x/a2a (#6 Y2). The pure layer
// is enforced in conformance/stdlib/a2a.cxd; THIS proves the effectful transport
// + the cx↔cx SYMMETRY: a cx A2A SERVER (cx-stdlib/http serve + a [?def] handler
// dispatching message/send) is driven by the cx A2A CLIENT (cx-x/a2a ask) composed
// as a cx-x/run Runnable. A real JSON-RPC message/send round-trips over a socket
// through CX on both ends — completing the agentic triad (MCP client/server + A2A).

fn cx_binary() string {
	abs := os.real_path('vcx/target/cx')
	if !os.is_file(abs) {
		panic('vcx/target/cx not found at ${abs} — run `make build-vcx` first')
	}
	return abs
}

// pick_port: a2a owns the disjoint band 23000-23799, salted with PID + the
// nanosecond clock so the concurrent `v test vcx/tests/` processes in the 12-way
// gate land on distinct ports. A collision would need both a base clash (none —
// each real-server test owns its own 800-wide band) and a salt clash (a 1-in-800
// shot between any two processes started in the same nanosecond), so the prior
// CXER3100 cross-test port collisions are eliminated.
fn pick_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 800
	return 23000 + int(salt)
}

fn curl_available() bool {
	return os.execute('curl --version').exit_code == 0
}

// run_cx_client runs the cx client command, retrying on transport flake: under
// heavy parallelism the bound-but-not-yet-warm server can hand the client a
// partial body (CXER3100) or an empty read. The server accepts many connections,
// so each retry is a fresh round-trip; a real reply returns on the first attempt.
fn run_cx_client(cmd string) string {
	mut out := ''
	for _ in 0 .. 6 {
		out = os.execute(cmd).output
		if out.trim_space() != '' && !out.contains('CXER3100')
			&& !out.contains('E_JSON_MALFORMED') {
			return out
		}
		time.sleep(150 * time.millisecond)
	}
	return out
}

// The cx A2A server: a greeter agent. The handler reads the JSON-RPC request,
// extracts the incoming message text, and replies with an agent Message echoing it.
fn server_program(port int) string {
	return "[?lib 'cx-stdlib/http' :as http]\n" +
		"[?lib 'cx-stdlib/json' :as json]\n" +
		"[?lib 'cx-stdlib/jsonrpc' :as rpc]\n" +
		"[?lib 'cx-x/a2a' :as a2a]\n" +
		'[?def handler (\$req::element)\n' +
		'  [?let [= \$rpc [\$json:parse [\$http:body-text \$req]]]\n' +
		'    [?let [= \$id \$rpc/id]\n' +
		'      [?let [= \$method \$rpc/method]\n' +
		'        [?let [= \$reply\n' +
		'          [?if [= \$method "message/send"]\n' +
		'            [then [?let [= \$params \$rpc/params]\n' +
		'                    [?let [= \$m \$params/message]\n' +
		'                      [?let [= \$p [\$first \$m/parts]]\n' +
		'                        [?let [= \$intext \$p/text]\n' +
		'                          [\$rpc:success \$id [\$a2a:message "agent" [\$concat "you said: " \$intext] "r1"]]]]]]]\n' +
		'            [else [\$rpc:error-for \$id "method-not-found"]]]]\n' +
		'          [response status=200 [body [\$json:emit \$reply]]]]]]]]\n' +
		'[\$http:serve "tcp://127.0.0.1:${port}" \$handler {block: true}]\n'
}

fn test_a2a_server_client_round_trip() {
	if !curl_available() {
		eprintln('SKIP: curl not available')
		return
	}
	tmp := os.temp_dir()
	port := pick_port()
	srv_prog := os.join_path(tmp, 'cx-a2a-srv-${time.now().unix_milli()}.cx')
	os.write_file(srv_prog, server_program(port)) or { panic(err) }
	out_file := '/tmp/cx-a2a-srv.${port}.out'
	pid_s := os.execute('${cx_binary()} --allow-net ${srv_prog} >${out_file} 2>&1 & echo \$!')
	pid := pid_s.output.trim_space().int()
	defer {
		if pid > 0 {
			os.execute('kill -9 ${pid} 2>/dev/null')
		}
		os.rm(srv_prog) or {}
	}
	mut bound := false
	for _ in 0 .. 40 {
		probe := os.execute('curl -s -o /dev/null -w "%{http_code}" --max-time 1 -X POST http://127.0.0.1:${port}/ -d "{}"')
		if probe.exit_code == 0 && probe.output != '' && probe.output != '000' {
			bound = true
			break
		}
		time.sleep(100 * time.millisecond)
	}
	if !bound {
		srv_log := os.read_file(out_file) or { '(no output)' }
		assert false, 'cx A2A server never bound on ${port}; log: ${srv_log}'
		return
	}

	cli_prog := os.join_path(tmp, 'cx-a2a-cli-${time.now().unix_milli()}.cx')
	os.write_file(cli_prog, "[?lib 'cx-x/a2a' :as a2a]\n" +
		"[?lib 'cx-x/run' :as run]\n" +
		'[\$run:invoke [?fn (\$t) [\$a2a:ask "http://127.0.0.1:${port}/" \$t]] "hello-a2a"]\n') or {
		panic(err)
	}
	defer {
		os.rm(cli_prog) or {}
	}
	out := run_cx_client('${cx_binary()} --allow-net=127.0.0.1:${port} ${cli_prog}')
	srv_log := os.read_file(out_file) or { '' }
	assert out.contains('you said: hello-a2a'), 'cx client↔cx server A2A round-trip failed; client got: ${out} | server log: ${srv_log}'
}
