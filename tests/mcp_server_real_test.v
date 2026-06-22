module main

import os
import time

// mcp_server_real_test.v — BEHAVIORAL coverage for cx-x/mcp-server (#6 Y1).
// The pure helpers are enforced in conformance/stdlib/mcp-server.cxd; THIS proves
// the full stack end-to-end and the client↔server SYMMETRY: a cx MCP SERVER
// (cx-stdlib/http serve + a [?def] handler dispatching via cx-x/mcp-server) is
// driven by the cx MCP CLIENT (cx-x/mcp call-tool) composed as a cx-x/run Runnable.
// All CX, all on the substrate (jsonrpc + json + http). It fails unless a real
// JSON-RPC tools/call round-trips over a real socket through CX on both ends.

fn cx_binary() string {
	abs := os.real_path('vcx/target/cx')
	if !os.is_file(abs) {
		panic('vcx/target/cx not found at ${abs} — run `make build-vcx` first')
	}
	return abs
}

// pick_port: mcp-server owns the disjoint band 22000-22799, salted with PID + the
// nanosecond clock so the concurrent `v test vcx/tests/` processes in the 12-way
// gate land on distinct ports. The capability-denial test uses `pick_port() + 1`,
// which stays inside the band (≤ 22800). A collision would need both a base clash
// (none — each real-server test owns its own 800-wide band) and a salt clash (a
// 1-in-800 shot between two same-nanosecond starts), so the prior CXER3100
// cross-test port collisions are eliminated.
fn pick_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 800
	return 22000 + int(salt)
}

fn curl_available() bool {
	return os.execute('curl --version').exit_code == 0
}

// The cx MCP server: two tools. `echo` returns its `text` arg. `read-secret`
// performs an io effect ([$io:read-file]) — the DIFFERENTIATOR: it is gated by the
// CX `read` capability, so under a server granted only `net` the effect is denied
// (CXER0271) and the handler maps the [err] value to an isError tool result. The
// handler reads the request body, dispatches on method+name, returns a [response].
fn server_program(port int) string {
	return "[?lib 'cx-stdlib/http' :as http]\n" +
		"[?lib 'cx-stdlib/json' :as json]\n" +
		"[?lib 'cx-stdlib/io' :as io]\n" +
		"[?lib 'cx-x/mcp-server' :as srv]\n" +
		'[?def handler impure (\$req::element)\n' +
		'  [?let [= \$rpc [\$json:parse [\$http:body-text \$req]]]\n' +
		'    [?let [= \$id [\$srv:id-of \$rpc]]\n' +
		'      [?let [= \$method [\$srv:method-of \$rpc]]\n' +
		'        [?let [= \$reply\n' +
		'          [?if [= \$method "tools/call"]\n' +
		'            [then [?let [= \$name [\$srv:tool-name-of \$rpc]]\n' +
		'                    [?let [= \$args [\$srv:tool-args-of \$rpc]]\n' +
		'                      [?if [= \$name "echo"]\n' +
		'                        [then [?let [= \$a \$args] [\$srv:tool-result \$id \$a/text]]]\n' +
		'                        [else [?if [= \$name "read-secret"]\n' +
		'                                [then [?match [\$io:read-file "/etc/hostname"]\n' +
		'                                        [case [err \$e] [\$srv:tool-error \$id [\$concat "denied: " \$e/@code]]]\n' +
		'                                        [case \$ok [\$srv:tool-result \$id \$ok]]]]\n' +
		'                                [else [\$srv:tool-error \$id "unknown tool"]]]]]]]]\n' +
		'            [else [?if [= \$method "initialize"]\n' +
		'                    [then [\$srv:initialize-result \$id "cx-demo" "0.1"]]\n' +
		'                    [else [\$srv:protocol-error \$id "method-not-found"]]]]]]\n' +
		'          [response status=200 [body [\$json:emit \$reply]]]]]]]]\n' +
		'[\$http:serve "tcp://127.0.0.1:${port}" \$handler {block: true}]\n'
}

// spawn_mcp_server starts the demo MCP server with the given capability grant and
// polls until it is bound; returns (pid, server-program-path). The grant string is
// the cx capability flag(s) — `--allow-net` alone leaves `read` UNGRANTED.
fn spawn_mcp_server(port int, grant string) (int, string) {
	tmp := os.temp_dir()
	srv_prog := os.join_path(tmp, 'cx-mcp-srv-${time.now().unix_milli()}-${port}.cx')
	os.write_file(srv_prog, server_program(port)) or { panic(err) }
	out_file := '/tmp/cx-mcp-srv.${port}.out'
	pid_s := os.execute('${cx_binary()} ${grant} ${srv_prog} >${out_file} 2>&1 & echo \$!')
	pid := pid_s.output.trim_space().int()
	for _ in 0 .. 40 {
		probe := os.execute('curl -s -o /dev/null -w "%{http_code}" --max-time 1 -X POST http://127.0.0.1:${port}/ -d "{}"')
		if probe.exit_code == 0 && probe.output != '' && probe.output != '000' {
			return pid, srv_prog
		}
		time.sleep(100 * time.millisecond)
	}
	srv_log := os.read_file(out_file) or { '(no output)' }
	panic('cx MCP server never bound on ${port} (grant=${grant}); log: ${srv_log}')
}

// client_call_tool runs the cx MCP client: compose call-tool as a cx-x/run
// Runnable, invoke it against the server, return the client's stdout.
fn client_call_tool(port int, tool string, args_literal string) string {
	tmp := os.temp_dir()
	cli_prog := os.join_path(tmp, 'cx-mcp-cli-${time.now().unix_milli()}-${port}.cx')
	os.write_file(cli_prog, "[?lib 'cx-x/mcp' :as mcp]\n" +
		"[?lib 'cx-x/run' :as run]\n" +
		'[\$run:invoke [?fn (\$a) [\$mcp:call-tool "http://127.0.0.1:${port}/" "${tool}" \$a]] ${args_literal}]\n') or {
		panic(err)
	}
	defer {
		os.rm(cli_prog) or {}
	}
	// Retry on transport flake: under heavy parallelism the bound-but-not-yet-warm
	// server can hand the client a partial body (CXER3100) or an empty read. The
	// server accepts many connections, so each retry is a fresh round-trip. A real
	// reply — including the CXER0271 capability denial — is non-3100 and non-empty,
	// so it returns on the first attempt.
	cmd := '${cx_binary()} --allow-net=127.0.0.1:${port} ${cli_prog}'
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

fn test_mcp_server_client_round_trip() {
	if !curl_available() {
		eprintln('SKIP: curl not available')
		return
	}
	port := pick_port()
	pid, srv_prog := spawn_mcp_server(port, '--allow-net')
	defer {
		if pid > 0 {
			os.execute('kill -9 ${pid} 2>/dev/null')
		}
		os.rm(srv_prog) or {}
	}
	out := client_call_tool(port, 'echo', '{text: "hello-mcp"}')
	srv_log := os.read_file('/tmp/cx-mcp-srv.${port}.out') or { '' }
	assert out.contains('hello-mcp'), 'cx client↔cx server MCP round-trip failed; client got: ${out} | server log: ${srv_log}'
}

// THE DIFFERENTIATOR (#6 Y1, ties #7 PEP): the server is granted ONLY `net`, so
// the read-secret tool's [$io:read-file] is DENIED by the CX capability layer
// (CXER0271). The handler maps that [err] to an isError tool result, and the cx
// client receives the denial — language-enforced tool sandboxing, end to end.
fn test_mcp_server_capability_denial() {
	if !curl_available() {
		eprintln('SKIP: curl not available')
		return
	}
	port := pick_port() + 1
	// Granted net only — NOT --allow-read. The read-secret tool must be denied.
	pid, srv_prog := spawn_mcp_server(port, '--allow-net')
	defer {
		if pid > 0 {
			os.execute('kill -9 ${pid} 2>/dev/null')
		}
		os.rm(srv_prog) or {}
	}
	out := client_call_tool(port, 'read-secret', '{}')
	srv_log := os.read_file('/tmp/cx-mcp-srv.${port}.out') or { '' }
	// The denial propagates through the MCP layer as the tool-error text.
	assert out.contains('CXER0271'), 'expected capability denial (CXER0271) to reach the client as an isError tool result; client got: ${out} | server log: ${srv_log}'
}
