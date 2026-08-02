module main

import os
import testenv
import time

// Tests the MODULE-level server surface `[$http:serve url $handler {block:true}]`
// (spec/02-inprogress/stdlib_http.md §3.5) — the shared picoev engine the
// `[?http-service]` directive also compiles onto (§6). Confirms that:
//   • a single CX `$handler` closure is invoked per request (no [resource]
//     routing — that is the directive's layer),
//   • the [response status=N [body …]] envelope it returns maps to the wire,
//   • `{block: true}` keeps the listener alive on the calling fiber.
// Boots `vcx/target/cx eval` in the background, curls it, asserts, kills it.
// Skipped when curl is unavailable.

fn cx_binary() string {
	return testenv.cx_bin()
}

fn curl_available() bool {
	return os.execute('which curl').exit_code == 0
}

fn pick_port() int {
	// Disjoint PID + nanosecond-salted band (25600-25699) so the concurrent
	// `v test vcx/tests/` gate processes don't collide on a port.
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 25600 + int(salt)
}

fn spawn_eval(prog_path string, port int) int {
	// --allow-net: module [$http:serve] enforces the net capability
	// (CXER0271 otherwise), unlike the directive path. Grant it.
	cmd := '${cx_binary()} eval --allow-net ${prog_path} >/tmp/cx-serve-mod.${port}.out 2>&1 & echo $!'
	res := os.execute(cmd)
	if res.exit_code != 0 {
		panic('spawn failed: ${res.output}')
	}
	pid := res.output.trim_space().int()
	mut waited := 0
	for waited < 30 {
		probe := os.execute('curl -s -o /dev/null -w "%{http_code}" --max-time 1 http://127.0.0.1:${port}/__ping__')
		if probe.exit_code == 0 && probe.output != '' && probe.output != '000' {
			return pid
		}
		time.sleep(100 * time.millisecond)
		waited++
	}
	panic('serve listener never bound on port ${port} (pid ${pid})\n${os.read_file('/tmp/cx-serve-mod.${port}.out') or {
		'(no output)'
	}}')
}

fn test_module_serve_invokes_handler() {
	if !curl_available() {
		eprintln('SKIP: curl not available')
		return
	}
	tmp := os.temp_dir()
	port := pick_port()
	// The handler echoes the request path into the body so we confirm the
	// single closure (not a resource table) handled the request.
	prog := os.join_path(tmp, 'serve-mod-${time.now().unix_milli()}.cx')
	os.write_file(prog, '
[?lib \'cx-stdlib/http\']
[?def h (\$req::element) [response status=200 [body "served-by-handler"]]]
[\$http:serve "tcp://127.0.0.1:${port}" \$h {block: true}]
') or { panic(err) }
	defer {
		os.rm(prog) or {}
	}
	pid := spawn_eval(prog, port)
	defer {
		if pid > 0 {
			os.execute('kill -9 ${pid} 2>/dev/null')
		}
	}

	res := os.execute('curl -s --max-time 3 -w "\n%{http_code}" http://127.0.0.1:${port}/anything')
	assert res.exit_code == 0, 'curl failed: ${res.output}'
	lines := res.output.split('\n')
	status := lines.last()
	body := lines[..lines.len - 1].join('\n')
	assert status == '200', 'expected 200, got ${status} (full: ${res.output})'
	assert body == 'served-by-handler', 'expected handler body, got ${body}'
}

// Regression gate for the #537(b)/#538/#539 serve-handler env reports
// (filed from the fabric P3 adapter dogfooding, not reproducible on the
// current engine — this test pins the behaviors so they stay fixed):
//   • #538(a) a program [?def] resolves inside the handler closure;
//   • #538(b) a ?let-bound MULTI-ARG closure applies (does not return its
//     last argument);
//   • #537(b) a [where …] clause sees handler-local ?let bindings AND may
//     carry a function call;
//   • #539 an INT-typed [?attr 'status' 401] maps to the wire status.
fn test_module_serve_handler_env_regressions() {
	if !curl_available() {
		eprintln('SKIP: curl not available')
		return
	}
	tmp := os.temp_dir()
	port := pick_port() + 100 // disjoint from test_module_serve_invokes_handler
	prog := os.join_path(tmp, 'serve-env-${time.now().unix_milli()}.cx')
	os.write_file(prog, "
[?lib 'cx-stdlib/http']
[?lib 'cx-stdlib/format' :as format]
[?def helper scope=public pure (\$x) [helped \$x]]
[?def make-handler scope=public impure (\$cfg)
  [?fn (\$req)
    [?let
      [= \$path [\$concat '' \$req@path]]
      [= \$mk [?fn (\$status \$node) [?element 'resp2' [?attr 's' \$status] \$node]]]
      [= \$a [helper 'x']]
      [= \$b [\$mk 7 [?element 'n' 'v']]]
      [= \$w  [\$first [?for [in \$r \$cfg/routes/webhook] [where [= \$r@path \$path]] [yield \$r]]]]
      [= \$wc [\$first [?for [in \$r \$cfg/routes/webhook] [where [= [\$concat '' \$r@path] \$path]] [yield \$r]]]]
      [?element 'response' [?attr 'status' 401]
        [?element 'body' [\$format:canonical [?element 'out'
          [?element 'a' \$a] [?element 'b' \$b]
          [?element 'w' \$w] [?element 'wc' \$wc]]]]]]]]
[?let
  [= \$cfg [?element 'cfg' [?element 'routes'
            [?element 'webhook' [?attr 'path' '/a']]
            [?element 'webhook' [?attr 'path' '/b']]]]]
  [\$http:serve 'tcp://127.0.0.1:${port}' [make-handler \$cfg] {block: true}]]
") or { panic(err) }
	defer {
		os.rm(prog) or {}
	}
	pid := spawn_eval(prog, port)
	defer {
		if pid > 0 {
			os.execute('kill -9 ${pid} 2>/dev/null')
		}
	}

	res := os.execute('curl -s --max-time 3 -w "\n%{http_code}" http://127.0.0.1:${port}/a')
	assert res.exit_code == 0, 'curl failed: ${res.output}'
	lines := res.output.split('\n')
	status := lines.last()
	body := lines[..lines.len - 1].join('\n')
	// #539 — the int-typed status attr reaches the wire.
	assert status == '401', 'expected 401 from int-typed status attr, got ${status} (full: ${res.output})'
	// #538(a) — the program def applied ([helped 'x'], not literal [helper 'x']).
	assert body.contains("[a [helped 'x']]"), '#538(a) def call did not apply: ${body}'
	// #538(b) — the 2-arg local closure applied (resp2 wrapper present).
	assert body.contains("[b [resp2 s=7 [n 'v']]]"), '#538(b) multi-arg closure did not apply: ${body}'
	// #537(b) — [where] with a handler-local comparand matched the /a route.
	assert body.contains("[w [webhook path='/a']]"), '#537(b) [where] missed handler-local binding: ${body}'
	// #537(b) cont. — [where] carrying a FUNCTION CALL matched too.
	assert body.contains("[wc [webhook path='/a']]"), '#537(b) [where] with fn-call predicate missed: ${body}'
}
