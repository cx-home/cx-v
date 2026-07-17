@[has_globals]
module code

// stdlib_xap_serve_notd_wasm32_emcc.v — the cx-xap web bridge (`[$xap:serve]`).
//
// XAP opens NO socket of its own (xap.md §9): it bootstraps the surface onto
// the core picoev/picohttpparser engine that also backs cx-stdlib/http. This
// file is the `.xap` listener mode — the request is dispatched against the
// runtime entirely in V (no CX handler closure), content-negotiated to
// text/html for the web client. It compiles only on the native build (the
// `_notd_wasm32_emcc` suffix excludes it from the emscripten target, mirroring
// services_listener_notd_wasm32_emcc.v, since picoev/net are not linked there).
//
// Routes (the medium-specific shell; the surface itself is medium-agnostic):
//   GET  /                 → the document shell with the guestbook surface
//                            spliced into its `{{surface:guestbook}}` mount.
//   GET  /static/<f>       → a static asset from <shell>/static/ (e.g. app.css).
//   POST /intent/sign      → runs the cascade for [do :sign name=…] and returns
//                            ONLY the re-rendered #guestbook-panel fragment
//                            (htmx swaps it out-of-band).

import cx
import os
import time
import transport.picoev
import sync

// ── §24: SSE subscriber registry (held-open event feeds per runtime) ─────────
//
// GET /events promotes the connection to an SSE feed: listener_callback holds
// the fd (picoev.cx_hold_fd), then registers it here while writing the prelude —
// atomically under this lock, so the prelude/initial frame is a readiness ack
// (see xap_sse_subscribe). On a state change (POST /intent/sign), xap_sse_push
// writes a surface frame to every
// subscriber fd — event-driven push, no reactor blocked. Cleanup is synchronous:
// picoev's close_conn invokes xap_sse_on_close_fd (registered via
// cx_set_sse_on_close) under this lock BEFORE the socket closes, so a push from
// another reactor never writes to a reused fd.
//
// #303: the lock is REFERENCE-typed, initialized in the module init()
// (stdlib_codec.v) — a VALUE-typed zeroed sync.Mutex global is a silently
// non-locking pthread mutex on Darwin; see cx_sse_topic_lock for the full
// mechanism (identical defect, identical barrier).
__global (
	xap_sse_subs map[int][]int
	xap_sse_lock &sync.Mutex
)

// xap_sse_subscribe writes the SSE prelude + initial frame (`ack`) to a held fd
// and adds the fd to `rt_id`'s subscriber set — atomically, under the registry
// lock, so the ack is a readiness barrier: a concurrent xap_sse_push either
// snapshots before this fd exists (and the client cannot yet have read its ack)
// or snapshots after (and its frame follows the fully-written prelude on the
// wire). Same barrier as cx_sse_topic_subscribe — see that fn for the full
// ordering argument.
fn xap_sse_subscribe(rt_id int, fd int, ack string) {
	xap_sse_lock.lock()
	send_all(fd, ack)
	xap_sse_subs[rt_id] << fd
	xap_sse_lock.unlock()
}

// xap_sse_on_close_fd drops `fd` from every runtime's subscriber set. Invoked by
// picoev's close_conn (held-fd close) and by xap_sse_push on a write failure;
// idempotent.
fn xap_sse_on_close_fd(fd int) {
	xap_sse_lock.lock()
	for rt_id, fds in xap_sse_subs {
		mut kept := []int{}
		for f in fds {
			if f != fd {
				kept << f
			}
		}
		xap_sse_subs[rt_id] = kept
	}
	xap_sse_lock.unlock()
}

// xap_sse_push writes `frame` to every subscriber of `rt_id`; a fd whose write
// fails (disconnected) is dropped from the set (picoev closes the socket itself
// on the disconnect read event).
fn xap_sse_push(rt_id int, frame string) {
	xap_sse_lock.lock()
	fds := (xap_sse_subs[rt_id] or { []int{} }).clone()
	xap_sse_lock.unlock()
	mut dead := []int{}
	for fd in fds {
		if !write_all_fd(fd, frame) {
			dead << fd
		}
	}
	for fd in dead {
		xap_sse_on_close_fd(fd)
	}
}

// xap_sse_frame renders one SSE wire frame carrying the surface value as the
// event `data` (multi-line surface → one `data:` line per LF; the cx sse-events
// client rejoins them). Terminated by the blank-line frame boundary.
fn xap_sse_frame(surface string) string {
	mut sb := []string{}
	for line in surface.trim_right('\n').split('\n') {
		sb << 'data: ${line}'
	}
	return sb.join('\n') + '\n\n'
}

// xap_serve bootstraps a runtime + binds the core http engine to serve it.
// `[$xap:serve url {tenant: … components: (…) surfaces: (…) shell: "<dir>"}]`.
// Blocks (the server runs until the process is signalled), matching a daemon.
fn xap_serve(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 1 {
		return mk_err(xap_err_arg_invalid, 'E_XAP: serve expects (url, opts?)')
	}
	url := xap_arg_name(args[0])
	opts := if args.len > 1 { args[1] } else { xap_elem('__cx_map__', [], []) }
	mut reg := xap_reg()
	// Reuse a pre-seeded runtime when one is handed in (`runtime: $rt`), so a
	// program can `run` + `emit` (seed the journal) and then `serve` the SAME
	// fold (continuity with D2). Otherwise wire a fresh single-tenant runtime.
	mut id := 0
	if rn := xap_map_get_node(opts, 'runtime') {
		if mut existing := xap_runtime_of(rn) {
			id = existing.id
			existing.shell_dir = xap_map_get_str(opts, 'shell')
		}
	}
	if id == 0 {
		reg.next_id = reg.next_id + 1
		id = reg.next_id
		reg.runtimes[id] = &XapRuntime{
			id:        id
			tenant:    xap_map_get_str(opts, 'tenant')
			state:     map[string][]cx.Node{}
			shell_dir: xap_map_get_str(opts, 'shell')
		}
	}
	// derive the bind host:port (a public http(s) URL → the tcp listener).
	host, port := xap_serve_authority(url)
	if port == 0 {
		return mk_err(xap_err_arg_invalid, 'E_XAP: serve URL needs an explicit port: ${url}')
	}
	// Gate `net` BEFORE binding the socket (§6: serve needs net via http; the
	// sibling http_serve_env guards identically). A denial surfaces the core
	// CXER0271 from the effect point — never remapped, never bypassed.
	if d := cap_guard('net', '${host}:${port}') {
		return d
	}
	// block defaults true (a daemon parks here forever). `block: false` spawns
	// the reactor threads and RETURNS the [xap-server] handle, so one program
	// can serve the web bridge AND keep running (e.g. drive an in-process TUI
	// client over the same runtime) — both share the process-global fold.
	block := xap_map_get_str(opts, 'block') != 'false'
	return start_xap_listener(id, host, port, block, mut env) or {
		return mk_err(xap_err_arg_invalid, 'E_XAP_SERVE_FAILED: ${err.msg()}')
	}
}

// xap_serve_authority extracts (host, port) from a public http(s)/tcp URL.
fn xap_serve_authority(url string) (string, int) {
	mut rest := url
	if i := rest.index('://') {
		rest = rest[i + 3..]
	}
	if sl := rest.index('/') {
		rest = rest[..sl]
	}
	if li := rest.last_index(':') {
		return rest[..li], rest[li + 1..].int()
	}
	return rest, 0
}

// start_xap_listener binds the picoev engine in `.xap` dispatch mode. Shares
// the reactor pool + wire pipeline with the http handler listener.
fn start_xap_listener(rt_id int, host string, port int, block bool, mut env MatchEnv) !cx.Node {
	mut h := &ListenerHandler{
		mode:               .xap
		service_name:       ''
		xap_rt:             rt_id
		enclosing_bindings: env.bindings.clone()
		enclosing_closures: env.closures.clone()
		enclosing_dyn:      env.dyn_context.clone()
		state:              unsafe { env.state }
	}
	// §24: drop a closing SSE fd from the subscriber set synchronously (picoev
	// invokes this just before close_socket, under the same lock pushes take).
	picoev.cx_set_sse_on_close(xap_sse_on_close_fd)
	spawn_shared_reactors(mut h, host, port)!
	bind_host := if host == '' { '0.0.0.0' } else { host }
	// A serving daemon prints nothing on stdout (the program "output" is the
	// HTTP responses); emit a one-line startup banner on stderr so the
	// blocking run is visibly alive rather than a silent hang.
	mut tenant := ''
	if rt := xap_reg().runtimes[rt_id] {
		tenant = rt.tenant
	}
	eprintln('cx-xap: serving tenant "${tenant}" on http://${bind_host}:${port}  (open it in a browser, or curl it; Ctrl-C to stop)')
	if block {
		for {
			time.sleep(time.hour)
		}
	}
	return http_server_handle('tcp://${bind_host}:${port}')
}

// ── request dispatch (text/html) ─────────────────────────────────────────────

fn xap_dispatch_http(rt_id int, method string, raw_path string, body string, xsp_hdrs XspReqHdrs, mut env MatchEnv) WireResp {
	// deployment-host mode (§6.3): a runtime booted by [$xap:host] serves the
	// standard package-driven surface instead of the component demo bridge.
	if mut h := xap_hosts[rt_id] {
		return xap_host_dispatch(mut h, method, raw_path, body, xsp_hdrs, mut env)
	}
	reg := xap_reg()
	mut rt := reg.runtimes[rt_id] or {
		return mk_wire(500, [], 'xap: unknown runtime\n')
	}
	mut path := raw_path
	if q := path.index('?') {
		path = path[..q]
	}
	if method == 'GET' && path == '/' {
		return xap_wire_html(200, xap_html_page(rt, mut env))
	}
	if method == 'GET' && path == '/surface' {
		// the SAME surface, content-negotiated to application/cx — what a CLI
		// or TUI client (or an agent) reads. The browser GETs '/' for text/html;
		// a terminal client GETs '/surface' for the view-tree value (§5/§13.2).
		return xap_wire_cx(200, xap_surface_cx(rt, mut env))
	}
	if method == 'GET' && path == '/events' {
		// §24 SSE feed: the SAME surface, pushed live. listener_callback holds
		// the fd open + subscribes it; the initial frame is the current surface,
		// and POST /intent/sign pushes each subsequent surface. A remote TUI/agent
		// reads it with [$http:sse-events] instead of polling /surface.
		return WireResp{
			status: 200
			sse:    true
			sse_rt: rt_id
			body:   xap_sse_frame(xap_surface_cx(rt, mut env))
		}
	}
	if method == 'GET' && path.starts_with('/static/') {
		return xap_serve_static(rt, path[8..])
	}
	if method == 'POST' && path == '/intent/sign' {
		name := xap_form_field(body, 'name')
		if name != '' {
			xap_commit_sign(mut rt, name)
			// §24: push the new surface to every live SSE feed on this runtime
			// (the TUI/agent clients) — the event-driven half of the §16 feed.
			xap_sse_push(rt_id, xap_sse_frame(xap_surface_cx(rt, mut env)))
		}
		return xap_wire_html(200, xap_html_fragment(rt, mut env))
	}
	if method == 'HEAD' && path == '/' {
		return xap_wire_html(200, '')
	}
	return mk_wire(404, [], 'not found: ${method} ${path}\n')
}

// xap_commit_sign runs the cascade for one web [do :sign]: append the payload
// record to the bound slice + the journal (mirrors xap_emit, §2.1/§14).
fn xap_commit_sign(mut rt XapRuntime, name string) {
	bind := xap_bind_path()
	rec := xap_elem('__cx_map__', [], [
		xap_elem('name', [], [xap_str(name)]),
	])
	if bind != '' {
		rt.state[bind] << rec
	}
	rt.log << xap_elem('do', [], [xap_elem('sign', [], []), rec])
}

// xap_names projects the bound slice to the signed names (the live fold).
fn xap_names(rt &XapRuntime) []string {
	bind := xap_bind_path()
	mut out := []string{}
	for rec in (rt.state[bind] or { []cx.Node{} }) {
		out << xap_map_get_str(rec, 'name')
	}
	return out
}

// ── HTML serialization (the web medium of the medium-agnostic surface) ───────

// xap_html_inner serializes the panel of the SINGLE view-tree (xap_runtime_surface
// — the real comp.view output) to the web medium. Mapping the view vocabulary to
// HTML (per-medium serializer, §2.5/§13.2): list→<ul>, item→<li>, control→<form>.
// htmx target/swap are the bridge binding; the endpoint + field + label all come
// from the view-tree, so changing the view changes this output (no hand-built strings).
fn xap_html_inner(rt &XapRuntime, mut env MatchEnv) string {
	surface := xap_runtime_surface(rt, mut env)
	mut parts := []string{}
	if surface is cx.Element && surface.items.len > 0 {
		panel := surface.items[0]
		if panel is cx.Element {
			for child in panel.items {
				s := xap_html_node(child)
				if s != '' {
					parts << s
				}
			}
		}
	}
	return parts.join('\n    ')
}

// xap_html_node maps one view-tree node to its HTML materialization.
fn xap_html_node(n cx.Node) string {
	if n !is cx.Element {
		return ''
	}
	e := n as cx.Element
	return match e.name {
		'list' { xap_html_list(e) }
		'control' { xap_html_control(e) }
		'text' { xap_html_escape(xap_node_text(n)) }
		else { '' }
	}
}

fn xap_html_list(e cx.Element) string {
	mut lis := ''
	for it in xap_list_item_nodes(e) {
		lis += '<li>${xap_html_escape(xap_node_text(it))}</li>'
	}
	return '<ul class="guestbook">${lis}</ul>'
}

// xap_list_item_nodes flattens a [list …] body: a `(…)` sequence (many items)
// or bare item(s) — mirrors the view's `[?for]` comprehension yield shape.
fn xap_list_item_nodes(e cx.Element) []cx.Node {
	mut out := []cx.Node{}
	for it in e.items {
		match it {
			cx.SequenceNode { out << it.items }
			cx.ArrayNode { out << it.items }
			cx.IteratorNode { out << iterate(it) } // materialize the [?for] comprehension
			cx.Element {
				// an empty-name element is the anonymous sequence wrapper the
				// [?for] comprehension yields (render prints it as `(…)`); the
				// marker-named envelopes are the other collection shapes.
				if it.name == '' || it.name == '__cx_seq__' || it.name == '__cx_arr__' {
					out << it.items
				} else {
					out << it
				}
			}
			else {
				out << it
			}
		}
	}
	return out
}

// xap_html_control maps [control :verb [label …] [input :field]] → the htmx form;
// the intent endpoint (/intent/<verb>), the field name, and the label are read
// from the view-tree (not hard-coded), so the control IS the capability (§17).
fn xap_html_control(e cx.Element) string {
	verb := xap_atom_name(e)
	mut label := 'Submit'
	mut field := 'value'
	for it in e.items {
		if it is cx.Element {
			if it.name == 'label' {
				label = xap_node_text(it)
			} else if it.name == 'input' {
				field = xap_atom_name(it)
			}
		}
	}
	return '<form hx-post="/intent/${verb}" hx-target="#guestbook-panel" hx-swap="outerHTML">\n' +
		'      <input name="${field}"><button type="submit">${xap_html_escape(label)}</button>\n' +
		'    </form>'
}

// xap_node_text reads an element's first scalar item (or a scalar itself) as text.
fn xap_node_text(n cx.Node) string {
	if n is cx.Element && n.items.len > 0 {
		t := n.items[0]
		if t is cx.ScalarNode {
			v := t.value
			if v is string {
				return v
			}
		}
	}
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return ''
}

// xap_atom_name returns the name of an element's leading atom (e.g. :sign → "sign").
fn xap_atom_name(e cx.Element) string {
	for it in e.items {
		if it is cx.ScalarNode {
			v := it.value
			if v is string {
				return v
			}
		}
	}
	return ''
}

// xap_html_fragment is the htmx swap target: the #guestbook-panel element only.
fn xap_html_fragment(rt &XapRuntime, mut env MatchEnv) string {
	return '<main id="guestbook-panel">\n    ${xap_html_inner(rt, mut env)}\n  </main>'
}

// xap_html_page splices the surface fragment into the document shell
// (layout.html, the swappable bridge layer). Falls back to a self-contained
// page when no shell dir is configured / readable.
fn xap_html_page(rt &XapRuntime, mut env MatchEnv) string {
	if rt.shell_dir != '' {
		if tpl := os.read_file('${rt.shell_dir}/layout.html') {
			// Replace the whole mount element so the surrounding markup keeps
			// the canonical #guestbook-panel wrapper htmx swaps against.
			return tpl.replace('<main id="guestbook-panel">{{surface:guestbook}}</main>',
				xap_html_fragment(rt, mut env))
		}
	}
	return '<!doctype html>\n<html lang="en">\n<head><meta charset="utf-8">' +
		'<title>Guestbook — cx-xap demo (D3)</title></head>\n<body>\n<h1>Guestbook</h1>\n' +
		'<main id="guestbook-panel">${xap_html_inner(rt, mut env)}</main>\n</body>\n</html>\n'
}

// xap_serve_static reads a static asset from <shell>/static/ (app.css, …).
fn xap_serve_static(rt &XapRuntime, rel string) WireResp {
	if rt.shell_dir == '' || rel.contains('..') {
		return mk_wire(404, [], 'not found\n')
	}
	data := os.read_file('${rt.shell_dir}/static/${rel}') or {
		return mk_wire(404, [], 'not found\n')
	}
	ct := if rel.ends_with('.css') {
		'text/css; charset=utf-8'
	} else if rel.ends_with('.js') {
		'application/javascript; charset=utf-8'
	} else {
		'application/octet-stream'
	}
	return WireResp{
		status:  200
		headers: [WireHeader{ name: 'Content-Type', value: ct }]
		body:    data
	}
}

fn xap_wire_html(status int, body string) WireResp {
	return WireResp{
		status:  status
		headers: [WireHeader{ name: 'Content-Type', value: 'text/html; charset=utf-8' }]
		body:    body
	}
}

fn xap_wire_cx(status int, body string) WireResp {
	return WireResp{
		status:  status
		headers: [WireHeader{ name: 'Content-Type', value: 'application/cx; charset=utf-8' }]
		body:    body
	}
}

// xap_surface_cx renders the SINGLE view-tree (the real comp.view output) as the
// application/cx value via the canonical printer — the same renderer the CLI uses
// for [$xap:render], so /surface, the CLI, and the agent leg are byte-identical
// and all derive from one view definition (§5/§13.2). No hand-built string.
fn xap_surface_cx(rt &XapRuntime, mut env MatchEnv) string {
	return render_canonical(xap_runtime_surface(rt, mut env)) + '\n'
}

// ── small text utilities ─────────────────────────────────────────────────────

fn xap_html_escape(s string) string {
	return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
}

// xap_form_field reads one field from an application/x-www-form-urlencoded body.
fn xap_form_field(body string, key string) string {
	for pair in body.split('&') {
		if eq := pair.index('=') {
			if xap_urldecode(pair[..eq]) == key {
				return xap_urldecode(pair[eq + 1..])
			}
		}
	}
	return ''
}

fn xap_urldecode(s string) string {
	mut out := []u8{}
	mut i := 0
	for i < s.len {
		c := s[i]
		if c == `+` {
			out << ` `
			i++
		} else if c == `%` && i + 2 < s.len {
			hi := xap_hex_val(s[i + 1])
			lo := xap_hex_val(s[i + 2])
			if hi >= 0 && lo >= 0 {
				out << u8(hi * 16 + lo)
				i += 3
			} else {
				out << c
				i++
			}
		} else {
			out << c
			i++
		}
	}
	return out.bytestr()
}

fn xap_hex_val(c u8) int {
	if c >= `0` && c <= `9` {
		return int(c - `0`)
	}
	if c >= `a` && c <= `f` {
		return int(c - `a` + 10)
	}
	if c >= `A` && c <= `F` {
		return int(c - `A` + 10)
	}
	return -1
}
