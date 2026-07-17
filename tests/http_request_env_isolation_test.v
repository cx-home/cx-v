module main

import net
import os
import testenv
import time

// http_request_env_isolation_test.v — BEHAVIORAL gate for cx-private #317
// (per-request template-alias env: immutable template + copy-on-write).
//
// The dispatch path no longer deep-clones the listener's bindings+closures
// per request: the request env ALIASES the immutable listener-start template
// (bindings_shared/closures_shared) and realizes a private copy only on an
// actual request-scope write (cow_bindings/cow_closures). The §10.5 isolation
// contract must hold exactly as before: concurrent requests binding the SAME
// names (here: the handler's [?let] frame + the service-mode `request`
// binding) must never observe each other's values, and the shared template
// must never be mutated by any request.
//
// Both hot shapes are gated:
//   - handler mode (`[$http:serve url $handler]`) — the env stays aliased for
//     the request's whole life (the closure call frame is built fresh);
//   - service mode (`[?http-service]` resources) — the per-request `request`
//     write is the CoW trigger.
//
// Each request carries a unique path; every response must echo BOTH the
// template binding (proves the template is intact under concurrent load) and
// its own path (proves no cross-request bleed). Handlers sleep ~80ms so all
// in-flight requests genuinely overlap on the executor pool.

const iso_handler_port = 39051
const iso_service_port = 39052
const iso_closure_port = 39053
const iso_lambda_port = 39054
const iso_concurrency = 12

fn cx_bin() string {
	return testenv.cx_bin()
}

fn write_handler_fixture(dir string) string {
	prog := "[?lib 'cx-stdlib/http' :as http]\n" +
		'[?const greeting "template-intact"]\n' +
		'[?def handler impure (\$req)\n' +
		'  [?let [= \$p [\$concat "" \$req/@path]]\n' +
		'   [?let [= \$z [?sleep 80ms]]\n' +
		'    [response status=200 [headers] [body [\$concat \$greeting ":" \$p]]]]]]\n' +
		'[\$http:serve "tcp://127.0.0.1:${iso_handler_port}" handler {block: true}]\n'
	src := os.join_path(dir, 'iso_handler.cx')
	os.write_file(src, prog) or { panic('write: ${err}') }
	return src
}

fn write_service_fixture(dir string) string {
	prog := '[?const greeting "template-intact"]\n' +
		'[?http-service\n' +
		'   [name "iso-svc"]\n' +
		'   [on http]\n' +
		'   [port ${iso_service_port}]\n' +
		'   [block true]\n' +
		'   [bind-host "127.0.0.1"]\n' +
		'   [resource [GET "/*"]\n' +
		'     [?let [= \$p [\$concat "" \$request/@path]]\n' +
		'      [?let [= \$z [?sleep 80ms]]\n' +
		'       [response status=200 [body [\$concat \$greeting ":" \$p]]]]]]]\n'
	src := os.join_path(dir, 'iso_service.cx')
	os.write_file(src, prog) or { panic('write: ${err}') }
	return src
}

// write_closure_fixture gates the #333 closure-call analog: every call frame
// built by build_param_call_env ALIASES the closure's defining-scope bindings
// (CoW on first write) instead of copying them per call. Concurrent requests
// drive closure shapes that write into aliased frames:
//   - `shadowed`: its parameter SHADOWS the defining-scope const `greeting` —
//     the param bind is the CoW trigger; it must never write through to the
//     shared defining scope;
//   - `spin`: tail-recursive — every TCO trampoline hop rebuilds an aliased
//     frame with per-request values;
//   - `defgreet`: an omitted defaulted param whose default expression READS
//     the defining scope through the aliased call env.
// Every response must echo the intact template const BEFORE and AFTER the
// shadowing call, plus its own per-request values — never another request's.
fn write_closure_fixture(dir string) string {
	prog := "[?lib 'cx-stdlib/http' :as http]\n" +
		'[?const greeting "template-intact"]\n' +
		'[?const depth 6]\n' +
		'[?def shadowed (\$greeting) [\$concat "shadow=" \$greeting]]\n' +
		'[?def spin (\$n \$acc) [?if [> \$n 0] [then [spin [- \$n 1] [\$concat \$acc "."]]] [else \$acc]]]\n' +
		'[?def defgreet (\$p \$suffix=\$greeting) [\$concat \$p "+" \$suffix]]\n' +
		'[?def handler impure (\$req)\n' +
		'  [?let [= \$p [\$concat "" \$req/@path]]\n' +
		'   [?let [= \$z [?sleep 80ms]]\n' +
		'    [response status=200 [headers] [body [\$concat \$greeting ":" \$p "|" [shadowed \$p] "|" [spin \$depth \$p] "|" [defgreet \$p] "|" \$greeting]]]]]]\n' +
		'[\$http:serve "tcp://127.0.0.1:${iso_closure_port}" handler {block: true}]\n'
	src := os.join_path(dir, 'iso_closure.cx')
	os.write_file(src, prog) or { panic('write: ${err}') }
	return src
}

// write_lambda_fixture gates the #341 [?fn]-path analog of #333: a positional
// lambda whose defining scope carries bindings gets a call frame that ALIASES
// those bindings (invoke_positional_l, CoW on first write — the alias half of
// the alias-vs-pool hybrid). Concurrent requests drive the write-through
// risks on aliased lambda frames:
//   - `$shadow`: its parameter SHADOWS the defining-scope const `greeting` —
//     the captured/param bind is the CoW trigger; it must never write through
//     to the shared program scope;
//   - `$reader`: binds its param, then reads the defining-scope const THROUGH
//     the realized CoW frame (const value must survive the private copy).
// Every response must echo the intact template const BEFORE and AFTER the
// shadowing call, plus its own per-request values — never another request's.
fn write_lambda_fixture(dir string) string {
	prog := "[?lib 'cx-stdlib/http' :as http]\n" +
		'[?const greeting "template-intact"]\n' +
		'[?const bump 3]\n' +
		'[?def handler impure (\$req)\n' +
		'  [?let [= \$p [\$concat "" \$req/@path]]\n' +
		'   [?let [= \$shadow [?fn (\$greeting) [\$concat "lshadow=" \$greeting]]]\n' +
		'    [?let [= \$reader [?fn (\$x) [\$concat \$x "+" \$greeting]]]\n' +
		'     [?let [= \$z [?sleep 80ms]]\n' +
		'      [response status=200 [headers] [body [\$concat \$greeting ":" \$p "|" [\$shadow \$p] "|" [\$reader \$p] "|" \$greeting]]]]]]]]\n' +
		'[\$http:serve "tcp://127.0.0.1:${iso_lambda_port}" handler {block: true}]\n'
	src := os.join_path(dir, 'iso_lambda.cx')
	os.write_file(src, prog) or { panic('write: ${err}') }
	return src
}

// raw_get opens a fresh connection, sends GET `path`, and returns the raw
// response, '' on failure. One read carries the whole single-segment response
// (see http_slow_handler_isolation_test.v for why we do not read to EOF).
fn raw_get(port int, path string, read_ms i64) string {
	mut c := net.dial_tcp('127.0.0.1:${port}') or { return '' }
	defer {
		c.close() or {}
	}
	c.write_string('GET ${path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n') or { return '' }
	c.set_read_timeout(read_ms * time.millisecond)
	mut buf := []u8{len: 8192}
	n := c.read(mut buf) or { return '' }
	if n <= 0 {
		return ''
	}
	return buf[..n].bytestr()
}

fn wait_up(port int, probe string) bool {
	for _ in 0 .. 60 {
		r := raw_get(port, probe, 1000)
		if r.contains('200') {
			return true
		}
		time.sleep(250 * time.millisecond)
	}
	return false
}

fn start_server(src string) &os.Process {
	log := src + '.log'
	mut p := os.new_process('/bin/sh')
	// `exec` so signal_kill reaches the SERVER, not just the sh wrapper — a
	// failing lane must not leave a stray server false-greening later runs
	// on this test's fixed ports (the #355 masking mechanism).
	p.set_args(['-c', 'exec ${cx_bin()} --allow-net=127.0.0.1 ${os.quoted_path(src)} >${os.quoted_path(log)} 2>&1'])
	p.run()
	return p
}

fn fetch_one(port int, i int) string {
	return raw_get(port, '/req-${i}', 6000)
}

// assert_isolated fires `iso_concurrency` overlapping requests with unique
// paths and asserts every response echoes the intact template binding AND its
// own path — never another request's.
fn assert_isolated(port int, label string) {
	mut threads := []thread string{}
	for i in 0 .. iso_concurrency {
		threads << spawn fetch_one(port, i)
	}
	for i, t in threads {
		r := t.wait()
		want := 'template-intact:/req-${i}'
		assert r.contains('200'), '${label}: request ${i} failed: ${r}'
		assert r.contains(want), '${label}: request ${i} response does not carry its own isolated bindings (want "${want}"): ${r}'
	}
}

fn test_handler_mode_concurrent_binding_isolation() {
	dir := os.join_path(os.temp_dir(), 'cx_317_iso_h_${os.getpid()}')
	os.mkdir_all(dir) or { panic('mkdir: ${err}') }
	src := write_handler_fixture(dir)
	mut p := start_server(src)
	defer {
		p.signal_kill()
		p.close()
	}
	assert wait_up(iso_handler_port, '/warm'), 'handler serve did not come up on :${iso_handler_port}'
	// three overlapping waves: sustained concurrent same-name rebinding
	for _ in 0 .. 3 {
		assert_isolated(iso_handler_port, 'handler-mode')
	}
	os.rmdir_all(dir) or {} // success path only — a failing run leaves the log
}

// assert_closure_isolated fires overlapping requests and asserts each
// response carries the intact template const around the shadowing call plus
// all three per-request closure results — never another request's.
fn assert_closure_isolated(port int, label string) {
	mut threads := []thread string{}
	for i in 0 .. iso_concurrency {
		threads << spawn fetch_one(port, i)
	}
	for i, t in threads {
		r := t.wait()
		p := '/req-${i}'
		want := 'template-intact:${p}|shadow=${p}|${p}......|${p}+template-intact|template-intact'
		assert r.contains('200'), '${label}: request ${i} failed: ${r}'
		assert r.contains(want), '${label}: request ${i} closure-call frames not isolated (want "${want}"): ${r}'
	}
}

fn test_closure_call_concurrent_binding_isolation() {
	dir := os.join_path(os.temp_dir(), 'cx_333_iso_c_${os.getpid()}')
	os.mkdir_all(dir) or { panic('mkdir: ${err}') }
	src := write_closure_fixture(dir)
	mut p := start_server(src)
	defer {
		p.signal_kill()
		p.close()
	}
	assert wait_up(iso_closure_port, '/warm'), 'closure serve did not come up on :${iso_closure_port}'
	for _ in 0 .. 3 {
		assert_closure_isolated(iso_closure_port, 'closure-call')
	}
	os.rmdir_all(dir) or {} // success path only — a failing run leaves the log
}

// assert_lambda_isolated fires overlapping requests and asserts each response
// carries the intact template const around the lambda calls plus both
// per-request lambda results — never another request's.
fn assert_lambda_isolated(port int, label string) {
	mut threads := []thread string{}
	for i in 0 .. iso_concurrency {
		threads << spawn fetch_one(port, i)
	}
	for i, t in threads {
		r := t.wait()
		p := '/req-${i}'
		want := 'template-intact:${p}|lshadow=${p}|${p}+template-intact|template-intact'
		assert r.contains('200'), '${label}: request ${i} failed: ${r}'
		assert r.contains(want), '${label}: request ${i} lambda-call frames not isolated (want "${want}"): ${r}'
	}
}

fn test_lambda_call_concurrent_binding_isolation() {
	dir := os.join_path(os.temp_dir(), 'cx_341_iso_l_${os.getpid()}')
	os.mkdir_all(dir) or { panic('mkdir: ${err}') }
	src := write_lambda_fixture(dir)
	mut p := start_server(src)
	defer {
		p.signal_kill()
		p.close()
	}
	assert wait_up(iso_lambda_port, '/warm'), 'lambda serve did not come up on :${iso_lambda_port}'
	for _ in 0 .. 3 {
		assert_lambda_isolated(iso_lambda_port, 'lambda-call')
	}
	os.rmdir_all(dir) or {} // success path only — a failing run leaves the log
}

fn test_service_mode_concurrent_binding_isolation() {
	dir := os.join_path(os.temp_dir(), 'cx_317_iso_s_${os.getpid()}')
	os.mkdir_all(dir) or { panic('mkdir: ${err}') }
	src := write_service_fixture(dir)
	mut p := start_server(src)
	defer {
		p.signal_kill()
		p.close()
	}
	assert wait_up(iso_service_port, '/warm'), 'service did not come up on :${iso_service_port}'
	for _ in 0 .. 3 {
		assert_isolated(iso_service_port, 'service-mode')
	}
	os.rmdir_all(dir) or {} // success path only — a failing run leaves the log
}
