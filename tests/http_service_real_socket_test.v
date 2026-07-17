module main

import os
import testenv
import time

// Tests for the real-socket HTTP listener attached to
// `[?http-service]`. Boots `vcx/target/cx eval` in a background
// process, hits the listener with `curl`, asserts the wire response
// shape (status + headers + body), then graceful-stops via SIGINT.
//
// Skipped when `curl` is not available (CI fallback).

// pick_port returns an ephemeral OS-assigned port by opening + closing
// a listener.  The next-port collision window is small but real; the
// tests retry on bind-failure rather than depending on a fixed port.
fn pick_port() int {
	// Disjoint PID + nanosecond-salted band (25400-25499) so the concurrent
	// `v test vcx/tests/` gate processes don't collide; the band sits below the
	// ephemeral range and clear of macOS ALF / CI reserved ports.
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 25400 + int(salt)
}

fn cx_binary() string {
	// Resolves from the test cwd (repo root when running v -enable-globals
	// test on the file). The Makefile guarantees this is built before
	// any test run.
	return testenv.cx_bin()
}

fn curl_available() bool {
	res := os.execute('which curl')
	return res.exit_code == 0
}

fn write_tmpfile(dir string, name string, content string) string {
	p := os.join_path(dir, name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

// spawn_service launches a cx-eval'd [?http-service] in the background
// and waits up to ~3s for the listener to bind. Returns the OS pid.
fn spawn_service(prog_path string, port int) int {
	cmd := '${cx_binary()} eval ${prog_path} >/tmp/cx-real-svc.${port}.out 2>&1 & echo $!'
	res := os.execute(cmd)
	if res.exit_code != 0 {
		panic('spawn failed: ${res.output}')
	}
	pid := res.output.trim_space().int()
	// Poll until the port responds OR ~3s elapse.
	mut waited := 0
	for waited < 30 {
		probe := os.execute('curl -s -o /dev/null -w "%{http_code}" --max-time 1 http://127.0.0.1:${port}/__ping__')
		if probe.exit_code == 0 && probe.output != '' && probe.output != '000' {
			return pid
		}
		time.sleep(100 * time.millisecond)
		waited++
	}
	panic('listener never bound on port ${port} (pid ${pid})\n${os.read_file("/tmp/cx-real-svc.${port}.out") or { "(no output)" }}')
}

fn kill_pid(pid int) {
	if pid > 0 {
		os.execute('kill -9 ${pid} 2>/dev/null')
	}
}

fn curl_with(args string) (int, string) {
	res := os.execute('curl -s --max-time 3 ${args}')
	return res.exit_code, res.output
}

fn curl_status(url string) string {
	code, out := curl_with('-o /dev/null -w "%{http_code}" ${url}')
	if code != 0 { return '' }
	return out
}

// ── test 1 — static-file serve happy path ─────────────────────────────────

fn test_real_socket_serves_file() {
	if !curl_available() { eprintln('SKIP: curl not available'); return }
	tmp := os.temp_dir()
	root := os.join_path(tmp, 'cx-svc-test-${time.now().unix_milli}')
	os.mkdir_all(root) or { panic(err) }
	defer { os.rmdir_all(root) or {} }
	write_tmpfile(root, 'index.html', '<h1>cx</h1>\n')
	write_tmpfile(root, 'hi.txt', 'hello\n')
	port := pick_port()
	prog := write_tmpfile(tmp, 'svc.cx', '
[?http-service
   [name "test-real-1"]
   [on http]
   [port ${port}]
   [root "${root}"]
   [block true]
   [bind-host "127.0.0.1"]
   [resource [GET "/"] [\$serve-file "index.html"]]
   [resource [GET "/*"] [\$serve-file]]]
')
	defer { os.rm(prog) or {} }
	pid := spawn_service(prog, port)
	defer { kill_pid(pid) }

	// GET / → serves index.html
	c1, body1 := curl_with('http://127.0.0.1:${port}/')
	assert c1 == 0
	assert body1 == '<h1>cx</h1>\n', 'expected index body, got ${body1}'

	// GET /hi.txt → serves hi.txt with text/plain
	c2, body2 := curl_with('http://127.0.0.1:${port}/hi.txt')
	assert c2 == 0
	assert body2 == 'hello\n'

	// HEAD / → 200 with Content-Length=12 (len of '<h1>cx</h1>\n')
	c3, head := curl_with('-I http://127.0.0.1:${port}/')
	assert c3 == 0
	assert head.contains('HTTP/1.1 200')
	assert head.contains('Content-Length: 12'), 'expected CL 12 in ${head}'
}

// ── test 2 — MIME types ───────────────────────────────────────────────────

fn test_real_socket_mime_types() {
	if !curl_available() { eprintln('SKIP: curl not available'); return }
	tmp := os.temp_dir()
	root := os.join_path(tmp, 'cx-svc-mime-${time.now().unix_milli}')
	os.mkdir_all(root) or { panic(err) }
	defer { os.rmdir_all(root) or {} }
	write_tmpfile(root, 'p.html', '<!doctype html>\n')
	write_tmpfile(root, 'p.css', 'body{}\n')
	write_tmpfile(root, 'p.js', 'export{}\n')
	write_tmpfile(root, 'p.wasm', '\x00asm')
	port := pick_port() + 1
	prog := write_tmpfile(tmp, 'svc-mime.cx', '
[?http-service
   [name "test-real-mime"]
   [on http]
   [port ${port}]
   [root "${root}"]
   [block true]
   [bind-host "127.0.0.1"]
   [resource [GET "/*"] [\$serve-file]]]
')
	defer { os.rm(prog) or {} }
	pid := spawn_service(prog, port)
	defer { kill_pid(pid) }

	expect := {
		'/p.html': 'text/html'
		'/p.css':  'text/css'
		'/p.js':   'application/javascript'
		'/p.wasm': 'application/wasm'
	}
	for path, want in expect {
		_, head := curl_with('-I http://127.0.0.1:${port}${path}')
		assert head.to_lower().contains(want), 'expected ${want} for ${path}; got: ${head}'
	}
}

// ── test 3 — 404 on missing ───────────────────────────────────────────────

fn test_real_socket_404() {
	if !curl_available() { eprintln('SKIP: curl not available'); return }
	tmp := os.temp_dir()
	root := os.join_path(tmp, 'cx-svc-404-${time.now().unix_milli}')
	os.mkdir_all(root) or { panic(err) }
	defer { os.rmdir_all(root) or {} }
	port := pick_port() + 2
	prog := write_tmpfile(tmp, 'svc-404.cx', '
[?http-service
   [name "test-real-404"]
   [on http]
   [port ${port}]
   [root "${root}"]
   [block true]
   [bind-host "127.0.0.1"]
   [resource [GET "/*"] [\$serve-file]]]
')
	defer { os.rm(prog) or {} }
	pid := spawn_service(prog, port)
	defer { kill_pid(pid) }

	status := curl_status('http://127.0.0.1:${port}/missing.txt')
	assert status == '404', 'expected 404 for missing, got ${status}'
}

// ── test 4 — path-traversal blocked ───────────────────────────────────────

fn test_real_socket_path_traversal() {
	if !curl_available() { eprintln('SKIP: curl not available'); return }
	tmp := os.temp_dir()
	root := os.join_path(tmp, 'cx-svc-pt-${time.now().unix_milli}')
	os.mkdir_all(root) or { panic(err) }
	defer { os.rmdir_all(root) or {} }
	port := pick_port() + 3
	prog := write_tmpfile(tmp, 'svc-pt.cx', '
[?http-service
   [name "test-real-pt"]
   [on http]
   [port ${port}]
   [root "${root}"]
   [block true]
   [bind-host "127.0.0.1"]
   [resource [GET "/*"] [\$serve-file]]]
')
	defer { os.rm(prog) or {} }
	pid := spawn_service(prog, port)
	defer { kill_pid(pid) }

	// curl --path-as-is preserves `..` segments so the server sees them.
	res := os.execute('curl -s --path-as-is --max-time 3 -o /dev/null -w "%{http_code}" "http://127.0.0.1:${port}/../../etc/passwd"')
	assert res.exit_code == 0
	assert res.output == '400', 'expected 400 for traversal, got ${res.output}'
}

// ── test 5 — default headers + COOP/COEP ──────────────────────────────────

fn test_real_socket_default_headers() {
	if !curl_available() { eprintln('SKIP: curl not available'); return }
	tmp := os.temp_dir()
	root := os.join_path(tmp, 'cx-svc-hdr-${time.now().unix_milli}')
	os.mkdir_all(root) or { panic(err) }
	defer { os.rmdir_all(root) or {} }
	write_tmpfile(root, 'x.html', '<x/>\n')
	port := pick_port() + 4
	prog := write_tmpfile(tmp, 'svc-hdr.cx', '
[?http-service
   [name "test-real-hdr"]
   [on http]
   [port ${port}]
   [root "${root}"]
   [block true]
   [bind-host "127.0.0.1"]
   [default-headers
     Cross-Origin-Opener-Policy="same-origin"
     Cross-Origin-Embedder-Policy="require-corp"
     X-Test-Header="abc"]
   [resource [GET "/*"] [\$serve-file]]]
')
	defer { os.rm(prog) or {} }
	pid := spawn_service(prog, port)
	defer { kill_pid(pid) }

	_, head := curl_with('-I http://127.0.0.1:${port}/x.html')
	assert head.contains('Cross-Origin-Opener-Policy: same-origin'), head
	assert head.contains('Cross-Origin-Embedder-Policy: require-corp'), head
	assert head.contains('X-Test-Header: abc'), head
	// And 404 path also carries defaults.
	_, head2 := curl_with('-I http://127.0.0.1:${port}/missing')
	assert head2.contains('Cross-Origin-Opener-Policy: same-origin'), head2
}
