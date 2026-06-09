module main

import os
import time

// v08_xap_render_test.v — the SINGLE render path (xap.md §2.5/§13.2): the served
// web (text/html) and /surface (application/cx) materializations BOTH derive from
// the one component view [?fn], not hand-built strings. Boots a real [$xap:serve]
// and asserts both media reflect the view over the live fold.

fn cx_binary() string {
	abs := os.real_path('vcx/target/cx')
	if !os.is_file(abs) {
		panic('vcx/target/cx not found at ${abs} — run `make build-vcx` first')
	}
	return abs
}

fn curl(args string) string {
	r := os.execute('curl -s --max-time 3 ${args}')
	return r.output
}

fn test_xap_single_render_path() {
	if os.execute('which curl').exit_code != 0 {
		eprintln('SKIP: curl not available')
		return
	}
	port := 18650 + int(time.now().unix_milli() % 120)
	dir := os.temp_dir()
	prog := os.join_path(dir, 'cx_xap_render.cx')
	os.write_file(prog, '[?lib \'cx-xap\' :as xap]\n' +
		'[\$xap:component guestbook\n' +
		'  {bind: "/guestbook"\n' +
		'   emits: ([do :sign [name :string]])\n' +
		'   view: [?fn (\$gs)\n' +
		'           [panel\n' +
		'             [list [?for [in \$g \$gs] [yield [item \$g/name]]]]\n' +
		'             [control :sign [label "Sign"] [input :name]]]]\n' +
		'   working-panel: :none}]\n' +
		'[?let [= \$rt [\$xap:run {tenant: "demo" components: (guestbook)}]]\n' +
		'[?let [= \$a [\$xap:emit \$rt [do :sign [name "Ada"]]]]\n' +
		'[?let [= \$b [\$xap:emit \$rt [do :sign [name "Lin"]]]]\n' +
		'  [\$xap:serve "http://127.0.0.1:${port}" {runtime: \$rt}]]]]\n') or { panic(err) }

	pid_s := os.execute('${cx_binary()} --allow-net ${prog} >/tmp/cx-xap-render.${port}.out 2>&1 & echo \$!')
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	// wait for bind
	mut up := false
	for _ in 0 .. 30 {
		if curl('-o /dev/null -w "%{http_code}" http://127.0.0.1:${port}/surface') == '200' {
			up = true
			break
		}
		time.sleep(100 * time.millisecond)
	}
	assert up, 'xap serve never bound on ${port}'

	// application/cx leg: canonical view-tree from comp.view over the live fold.
	surface := curl('http://127.0.0.1:${port}/surface').trim_space()
	expected := "[surface name=guestbook [panel [list ([item 'Ada'], [item 'Lin'])] [control :sign [label 'Sign'] [input :name]]]]"
	assert surface == expected, 'application/cx render not derived from the view; got: ${surface}'

	// text/html leg: the SAME view-tree → HTML (names from the view, not hand-built).
	page := curl('http://127.0.0.1:${port}/')
	assert page.contains('<li>Ada</li><li>Lin</li>'), 'text/html render did not derive the list from the view; got: ${page}'
	assert page.contains('<button type="submit">Sign</button>'), 'text/html control not derived from the view; got: ${page}'
}

// the 3-process topology (xap.md §16): a SEPARATE cx client process signs the
// control over the real http client (POST), and another read of the live surface
// reflects it — client → server → client over the wire, no shared in-process state.
fn test_xap_three_process_sign() {
	if os.execute('which curl').exit_code != 0 {
		eprintln('SKIP: curl not available')
		return
	}
	port := 18650 + int(time.now().unix_milli() % 120) + 200
	dir := os.temp_dir()
	srv := os.join_path(dir, 'cx_xap_3p_server.cx')
	os.write_file(srv, '[?lib \'cx-xap\' :as xap]\n' +
		'[\$xap:component guestbook\n' +
		'  {bind: "/guestbook"\n' +
		'   emits: ([do :sign [name :string]])\n' +
		'   view: [?fn (\$gs)\n' +
		'           [panel [list [?for [in \$g \$gs] [yield [item \$g/name]]]]\n' +
		'                  [control :sign [label "Sign"] [input :name]]]]\n' +
		'   working-panel: :none}]\n' +
		'[?let [= \$rt [\$xap:run {tenant: "demo" components: (guestbook)}]]\n' +
		'  [\$xap:serve "http://127.0.0.1:${port}" {runtime: \$rt}]]\n') or { panic(err) }
	// process 2: a separate cx client that POSTs the sign control over HTTP.
	signer := os.join_path(dir, 'cx_xap_3p_sign.cx')
	os.write_file(signer, '[?lib \'cx-stdlib/http\' :as http]\n' +
		'[\$http:post "http://127.0.0.1:${port}/intent/sign" "name=Zoe" {content-type: "application/x-www-form-urlencoded"}]\n') or {
		panic(err)
	}

	pid_s := os.execute('${cx_binary()} --allow-net ${srv} >/tmp/cx-xap-3p.${port}.out 2>&1 & echo \$!')
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	mut up := false
	for _ in 0 .. 30 {
		if curl('-o /dev/null -w "%{http_code}" http://127.0.0.1:${port}/surface') == '200' {
			up = true
			break
		}
		time.sleep(100 * time.millisecond)
	}
	assert up, 'xap serve never bound on ${port}'

	// process 2 signs over the wire (a real separate cx process, real http client)
	sign_res := os.execute('${cx_binary()} --allow-net=127.0.0.1:${port} ${signer}')
	assert sign_res.exit_code == 0, 'signer process failed: ${sign_res.output}'

	// the signed name is now in the server-authoritative fold — visible to any
	// client reading the surface (process 3's read).
	surface := curl('http://127.0.0.1:${port}/surface')
	assert surface.contains("[item 'Zoe']"), 'cross-process sign not reflected in the live surface; got: ${surface}'
}

// §24: the /events SSE feed holds the connection open and PUSHES a surface frame
// on each state change (event-driven, non-blocking — not polling). A held SSE
// reader sees the initial surface, then a live frame when another process signs.
fn test_xap_sse_push() {
	if os.execute('which curl').exit_code != 0 {
		eprintln('SKIP: curl not available')
		return
	}
	port := 18650 + int(time.now().unix_milli() % 120) + 400
	dir := os.temp_dir()
	srv := os.join_path(dir, 'cx_xap_sse_server.cx')
	os.write_file(srv, '[?lib \'cx-xap\' :as xap]\n' +
		'[\$xap:component guestbook\n' +
		'  {bind: "/guestbook"\n' +
		'   emits: ([do :sign [name :string]])\n' +
		'   view: [?fn (\$gs)\n' +
		'           [panel [list [?for [in \$g \$gs] [yield [item \$g/name]]]]\n' +
		'                  [control :sign [label "Sign"] [input :name]]]]\n' +
		'   working-panel: :none}]\n' +
		'[?let [= \$rt [\$xap:run {tenant: "demo" components: (guestbook)}]]\n' +
		'  [\$xap:serve "http://127.0.0.1:${port}" {runtime: \$rt}]]\n') or { panic(err) }

	pid_s := os.execute('${cx_binary()} --allow-net ${srv} >/tmp/cx-xap-sse.${port}.out 2>&1 & echo \$!')
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	mut up := false
	for _ in 0 .. 30 {
		if curl('-o /dev/null -w "%{http_code}" http://127.0.0.1:${port}/surface') == '200' {
			up = true
			break
		}
		time.sleep(100 * time.millisecond)
	}
	assert up, 'xap serve never bound on ${port}'

	// Hold an SSE reader open for ~2s (background) while a separate process signs
	// mid-stream; the feed must push the post-sign surface to the reader.
	cap_file := os.join_path(dir, 'cx_xap_sse_${port}.cap')
	os.rm(cap_file) or {}
	os.execute('curl -sN --max-time 2 http://127.0.0.1:${port}/events >${cap_file} 2>&1 & echo \$!')
	time.sleep(500 * time.millisecond) // let the reader connect + get the initial frame
	sign := os.execute('curl -s -X POST http://127.0.0.1:${port}/intent/sign -d "name=Vera"')
	assert sign.exit_code == 0, 'sign POST failed'
	time.sleep(1500 * time.millisecond) // let the push reach the held reader, then curl --max-time fires
	cap := os.read_file(cap_file) or { '' }
	assert cap.contains("[item 'Vera']"), 'SSE feed did not push the post-sign surface to the held reader; got: ${cap}'
}
