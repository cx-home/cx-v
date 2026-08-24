module platform
import code {
	MatchEnv,
	cap_guard,
	http_arg_str,
	http_attr,
	http_authority,
	http_bind_resource,
	http_body_octets,
	http_bool,
	http_elem,
	http_handle_resource,
	http_header_elems,
	http_int,
	http_is_response,
	http_map_entry_str,
	http_node_str,
	http_null,
	http_split_scheme,
	http_sse_frame_event,
	http_sse_stream_opened,
	http_sse_streams_at_cap,
	is_err_value,
	is_fn_value,
	mk_err,
	net_close_id,
	net_h_write,
	net_handle_id,
	net_lookup,
	net_mut_handle,
	net_read_exact_buf,
	net_read_line_buf,
}

import cx

// stdlib_http_serve.v — the RING-2 SERVE half of `cx-stdlib/http`
// (#651/#516 I3, seam H; spec/02-inprogress/stdlib_http.md §3.5/§3.6,
// cx_partition.md §2 "http/net serve").
//
// stdlib_http.v was a MIXED client+server file; the corpus already
// splits it per-case (http suite header ring=2, client cases ring=1).
// This file now carries the server surface: listen / accept-iter /
// exchange-request / respond / stop, the high-level [$http:serve]
// (env-aware — the picoev listener engine), the response serializers,
// and the SSE SERVER push half (sse / send-event / sse-publish /
// heartbeat / stream-open). The client surface — one-shot verbs,
// send, pooled connections, introspection, and the SSE CLIENT
// (sse-connect / sse-events / source-open / last-event-id) — stays in
// stdlib_http.v as the Ring-1 http-client pack (§4 cli profile).
//
// Dispatch: http_serve_stdlib_builtin registers on the Ring-1 registry
// via ring2_register.v (seam A); http_stdlib_builtin_env (http-serve)
// stays on the shared env chain. Everything below moved VERBATIM from
// stdlib_http.v at the split except http_sse_impl's stream-count
// bookkeeping, which now goes through the Ring-1 accessors
// http_sse_streams_at_cap / http_sse_stream_opened (the counter global
// lives beside the net handle table's close hook in Ring 1).
//
// The serve half's helpers reach DOWN into Ring-1 stdlib_http.v
// (value builders, arg readers, http_attr/http_elem, bind/handle
// resource derivation) and net_core.v (handles, buffered reads,
// net_h_write, net_close_id) — Ring 2 MAY import Rings 0–1 (§3).

// Gated network primitives of the SERVE half — every name maps to the
// `net` capability, guarded fail-closed AFTER the pure URL-shape /
// arg-shape validation but BEFORE any socket touch (same discipline as
// the client half's list in stdlib_http.v).
const http_serve_gated_prims = ['http-serve', 'http-listen', 'http-accept-iter',
	'http-exchange-request', 'http-respond', 'http-stop']

// http_serve_stdlib_builtin — the env-free dispatch slice for the serve
// half. Registered into the Ring-1 registry by ring2_register.v; name
// sets are disjoint with the client half's dispatcher, so the probe
// position is behavior-neutral (see ring_registry.v).
fn http_serve_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	// not an http primitive → let the dispatch chain continue
	if !name.starts_with('http-') {
		return none
	}
	match name {
		// ── §3.5 server (GATED on net for serve/listen/accept/respond) ───
		// `http-serve` is handled by the env-aware dispatch slice
		// (http_stdlib_builtin_env → http_serve_env, the real picoev engine)
		// tried BEFORE this env-free chain; it never reaches here.
		'http-listen' {
			return http_listen_impl(args)
		}
		'http-accept-iter' {
			// inherit the server's grant; but reaching the network to accept
			// is still a net effect — guard it.
			if d := cap_guard('net', http_handle_resource(args, 'accept-iter')) {
				return d
			}
			if args.len < 1 {
				return mk_err(code.http_err_arg_invalid, 'E_HTTP_ARG_INVALID: accept-iter expects an [http-server]')
			}
			return cx.new_iterator(.iter_http_accept, [args[0]])
		}
		'http-exchange-request' {
			if d := cap_guard('net', http_handle_resource(args, 'exchange-request')) {
				return d
			}
			return http_exchange_request_real(args)
		}
		'http-respond' {
			return http_respond_impl(args)
		}
		'http-stop' {
			if d := cap_guard('net', http_handle_resource(args, 'stop')) {
				return d
			}
			return http_stop_real(args)
		}

		// ── §3.6 SSE / streaming (server push half) ──────────────────────
		'http-sse' {
			return http_sse_impl(args)
		}
		'http-send-event' {
			return http_send_event_impl(args)
		}
		'http-sse-publish' {
			return http_sse_publish_impl(args)
		}
		'http-heartbeat' {
			return http_heartbeat_impl(args)
		}
		'http-stream-open' {
			return http_stream_open_impl(args)
		}
		else {
			return none
		}
	}
}

// ── server impls (§3.5 low-level loop, built on the real net listener) ──
//
// listen binds via net — server bind URLs are net transport URLs (tcp:// /
// tls://), NOT http:// (§3.5). Validate the bind URL shape, guard net on the
// bind host:port, then bind a REAL net listener and wrap it as an
// [http-server] whose `fd` is the net listener handle id. accept-iter pulls
// connections off that listener; exchange-request parses one request off the
// accepted connection; respond serializes + writes the response on it.
fn http_listen_impl(args []cx.Node) cx.Node {
	url := http_arg_str(args[0]) or {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_ARG_INVALID: listen expects a bind URL string')
	}
	if e := http_validate_bind_url(url) {
		return e
	}
	if d := cap_guard('net', http_bind_resource(url)) {
		return d
	}
	opts := if args.len > 1 { args[1] } else { cx.Node(cx.Element{ name: '__cx_map__' }) }
	listener := net_listen_impl('', [args[0], opts])
	if is_err_value(listener) {
		return listener
	}
	fd := net_handle_id(listener) or {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_SERVE_FAILED: net listener returned no handle')
	}
	return http_server_handle_fd(url, fd)
}

// http_exchange_request_real reads one HTTP/1.1 request off the exchange's
// connection and parses it into the server-form [request] (§2.2): method/path
// attributes + [query-params]/[headers]/[body] children. Reads the request
// line, the header block (to the blank line), and a Content-Length-framed body.
fn http_exchange_request_real(args []cx.Node) cx.Node {
	if args.len < 1 {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_ARG_INVALID: exchange-request expects an [exchange]')
	}
	mut h := net_mut_handle(args[0]) or {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_ARG_INVALID: exchange-request on a closed/unknown exchange')
	}
	req_line := net_read_line_buf(mut h) or {
		// No request line at all: a clean EOF (peer closed) or an idle-timeout on a
		// kept-alive connection. Distinct code so the serve loop closes quietly
		// rather than answering a spurious 400 (#234.1).
		return mk_err(code.http_err_no_request, 'E_HTTP_NO_REQUEST: peer sent no request line (closed or idle)')
	}
	if req_line.trim_space() == '' {
		// A bare CRLF before any request line — same clean-close signal.
		return mk_err(code.http_err_no_request, 'E_HTTP_NO_REQUEST: empty request line')
	}
	parts := req_line.split(' ')
	// #219.3: require all three request-line tokens (method, target, HTTP-version).
	// A two-token line (`POST /path`) was accepted → reject as malformed (400).
	if parts.len < 3 {
		return mk_err(code.http_err_respond_invalid, 'E_HTTP_REQUEST_INVALID: request line needs method, target, and HTTP-version: "${req_line}"')
	}
	method := parts[0].to_upper()
	target := parts[1]
	mut hdr_nodes := []cx.Node{}
	mut content_length := 0
	mut cl_seen := false
	mut cl_str := ''
	for {
		line := net_read_line_buf(mut h) or { break }
		if line == '' {
			break // end of header block
		}
		ci := line.index(':') or { continue }
		hname := line[..ci].trim_space()
		hval := line[ci + 1..].trim_space()
		if hname.to_lower() == 'content-length' {
			// #219.1/.2: RFC 9112 — a duplicate/conflicting Content-Length is a
			// request-smuggling primitive and (with no read deadline) an
			// unauthenticated worker-exhaustion hang. Reject a second Content-Length
			// whose value differs (a repeated identical value is tolerated per RFC).
			if cl_seen && hval != cl_str {
				return mk_err(code.http_err_respond_invalid, 'E_HTTP_REQUEST_INVALID: conflicting duplicate Content-Length (${cl_str} vs ${hval})')
			}
			cl_seen = true
			cl_str = hval
			content_length = hval.int()
		}
		hdr_nodes << cx.Node(cx.Element{
			name:  'header'
			attrs: [
				cx.Attribute{ name: 'name', value: cx.ScalarValue(hname) },
				cx.Attribute{ name: 'value', value: cx.ScalarValue(hval) },
			]
		})
	}
	mut body_bytes := []u8{}
	if content_length > 0 {
		body_bytes = net_read_exact_buf(mut h, content_length)
	}
	// split target into path + raw query, parse query-params (k=v&…).
	mut path := target
	mut query_nodes := []cx.Node{}
	if qi := target.index('?') {
		path = target[..qi]
		query_nodes = http_parse_query(target[qi + 1..])
	}
	body_item := cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(body_bytes.bytestr())
		data_type: cx.ScalarType.string_type
	})
	return cx.Element{
		name:  'request'
		attrs: [
			cx.Attribute{ name: 'method', value: cx.ScalarValue(method) },
			cx.Attribute{ name: 'path', value: cx.ScalarValue(path) },
		]
		items: [
			cx.Node(cx.Element{ name: 'query-params', items: query_nodes }),
			cx.Node(cx.Element{ name: 'headers', items: hdr_nodes }),
			cx.Node(cx.Element{ name: 'body', items: [body_item] }),
		]
	}
}

// http_parse_query parses a raw query string (`k=v&k2=v2…`) into the §2.2
// [query-params] children — one `[<name> "<value>"]` element per pair, names
// and values percent-decoded (`+` = space): the receive-side twin of
// [$url:query-encode]. A valueless pair (`?flag`) keeps an empty string value.
// The ONE query parser (#627): the exchange-request lane, the listener's
// handler/service lanes, and the xap host all route here so the shapes
// cannot drift.
fn http_parse_query(raw string) []cx.Node {
	mut out := []cx.Node{}
	for pair in raw.split('&') {
		if pair == '' {
			continue
		}
		eqi := pair.index('=') or {
			out << http_query_param(http_urldecode(pair), '')
			continue
		}
		out << http_query_param(http_urldecode(pair[..eqi]), http_urldecode(pair[eqi + 1..]))
	}
	return out
}

// http_urldecode percent-decodes a URL component (`%XX` bytes, `+` = space);
// malformed escapes pass through verbatim (never an error on receive).
fn http_urldecode(s string) string {
	mut out := []u8{cap: s.len}
	mut i := 0
	for i < s.len {
		c := s[i]
		if c == `+` {
			out << ` `
			i++
		} else if c == `%` && i + 2 < s.len {
			hi := http_hex_val(s[i + 1])
			lo := http_hex_val(s[i + 2])
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

fn http_hex_val(c u8) int {
	if c >= `0` && c <= `9` {
		return int(c - `0`)
	}
	if c >= `a` && c <= `f` {
		return int(c - `a`) + 10
	}
	if c >= `A` && c <= `F` {
		return int(c - `A`) + 10
	}
	return -1
}

fn http_query_param(name string, value string) cx.Node {
	return cx.Element{
		name:  name
		items: [cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(value)
			data_type: cx.ScalarType.string_type
		})]
	}
}

// http_stop_real closes the listener bound to the [http-server] handle (§3.5
// graceful stop). Idempotent via net_close_id.
fn http_stop_real(args []cx.Node) cx.Node {
	if args.len < 1 {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_ARG_INVALID: stop expects an [http-server]')
	}
	if id := net_handle_id(args[0]) {
		net_close_id(id)
	}
	return http_null()
}

// http_stdlib_builtin_env is the env-aware dispatch slice for cx-stdlib/http
// (tried before the env-free chain at the dispatch_call site, alongside
// prof/validate/test/log). `serve` needs env in scope to invoke its CX
// `$handler` closure per request, so it lives here rather than the env-free
// http_serve_stdlib_builtin chain. Returns none for every other name.
fn http_stdlib_builtin_env(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	match name {
		'http-serve' {
			return http_serve_env(args, mut env)
		}
		else {
			return none
		}
	}
}

// http_serve_env is the live `[$http:serve url $handler $opts]` — the
// engine `[?http-service]` compiles onto (§3.5/§6). It runs the shared
// picoev listener (services_listener) dispatching each request to the CX
// handler closure. Validation order matches the conformance battery:
// bad bind URL → CXER4525 (even under a grant, http-046); net not granted
// → CXER0271 (http-045); both BEFORE any socket touch.
fn http_serve_env(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 2 {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_ARG_INVALID: serve expects (url, handler)')
	}
	url := http_arg_str(args[0]) or {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_ARG_INVALID: serve expects a bind URL string')
	}
	if e := http_validate_bind_url(url) {
		return e
	}
	if d := cap_guard('net', http_bind_resource(url)) {
		return d
	}
	handler := args[1]
	if !is_fn_value(handler) {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_ARG_INVALID: serve expects a callable handler')
	}
	mut block := false
	mut tls_cert := ''
	mut tls_key := ''
	if args.len > 2 {
		bv := http_map_entry_str(args[2], 'block')
		block = bv == 'true' || bv == '1'
		// #875 (http.md §13.1): opts.tls {cert key} — TLS + ALPN
		// ("h2", "http/1.1") on the serve port. Same submap shape the net
		// listen-tls opts use.
		tls_cert = code.net_opts_tls_str(args[2], 'cert')
		tls_key = code.net_opts_tls_str(args[2], 'key')
	}
	scheme, rest := http_split_scheme(url)
	if scheme == 'tls' && (tls_cert == '' || tls_key == '') {
		// fail loud: a tls:// serve without a server identity must never
		// silently fall back to cleartext (§13.1).
		return mk_err(code.net_err_tls_config, 'E_NET_TLS_CONFIG: serve on ${url} requires opts.tls.cert + opts.tls.key')
	}
	if scheme != 'tls' {
		// [tls] config on a tcp:// bind would be surface without meaning —
		// the scheme states the transport (§3.5); ignore is not an option.
		if tls_cert != '' || tls_key != '' {
			return mk_err(code.net_err_tls_config, 'E_NET_TLS_CONFIG: opts.tls is only valid with a tls:// bind URL (got ${url})')
		}
	}
	host, port_s := http_authority(rest)
	return start_handler_listener(handler, host, port_s.int(), block, tls_cert, tls_key, mut env) or {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_SERVE_FAILED: ${err.msg()}')
	}
}

// http_respond_impl validates status ∈ 100–599 (§3.5) → CXER4541 otherwise;
// it writes on the exchange's pinned connection (a net effect) — guard net.
fn http_respond_impl(args []cx.Node) cx.Node {
	resp := http_elem(args[1]) or {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_ARG_INVALID: respond expects a [response]')
	}
	if !http_is_response(resp) {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_ARG_INVALID: respond expects a [response]')
	}
	st := http_attr(resp, 'status') or {
		return mk_err(code.http_err_respond_invalid, 'E_HTTP_RESPOND_INVALID: response missing status')
	}
	n := st.int()
	if n < 100 || n > 599 {
		return mk_err(code.http_err_respond_invalid, 'E_HTTP_RESPOND_INVALID: status ${n} not in 100-599')
	}
	if d := cap_guard('net', http_handle_resource(args, 'respond')) {
		return d
	}
	mut h := net_mut_handle(args[0]) or {
		return mk_err(code.http_err_respond_invalid, 'E_HTTP_RESPOND_INVALID: respond on a closed/unknown exchange')
	}
	wire := http_serialize_response(resp, n)
	net_h_write(mut h, wire) or {
		return mk_err(code.http_err_respond_invalid, 'E_HTTP_RESPOND_INVALID: write failed: ${err.msg()}')
	}
	// We advertise `Connection: close`; close the connection after the final
	// response so the peer observes a clean EOF (the §3.5 single-turn exchange).
	if id := net_handle_id(args[0]) {
		net_close_id(id)
	}
	return http_null()
}

// http_write_response_keepalive writes a [response] to the exchange with
// `Connection: keep-alive` and leaves the socket OPEN for the next request on the
// same connection (#234.1). Returns false on a write failure or a response that
// cannot be safely pipelined (an explicit `Connection: close`, or an unknown
// shape) — the caller then closes the connection. Unlike http_respond_impl this
// NEVER closes the fd; the serve loop owns the connection's lifetime.
pub fn http_write_response_keepalive(ex cx.Node, resp cx.Node, idle_ms i64) bool {
	re := http_elem(resp) or { return false }
	if !http_is_response(re) {
		return false
	}
	st := http_attr(re, 'status') or { return false }
	status := st.int()
	if status < 100 || status > 599 {
		return false
	}
	// honor an explicit Connection: close the handler set — cannot keep alive.
	for hdr in http_header_elems(re) {
		hn := http_attr(hdr, 'name') or { continue }
		if hn.to_lower() == 'connection' {
			hv := http_attr(hdr, 'value') or { '' }
			if hv.to_lower().contains('close') {
				return false
			}
		}
	}
	mut h := net_mut_handle(ex) or { return false }
	wire := http_serialize_response_ka(re, status, true, idle_ms)
	net_h_write(mut h, wire) or { return false }
	return true
}

// http_chunk_size bounds a single Transfer-Encoding: chunked wire frame. A
// larger binary stream is emitted as a run of these chunks rather than buffered
// behind a Content-Length — the streaming response path the CSRP transport
// (the cx-store:// remote protocol) reads back via http_dechunk.
const http_chunk_size = 4096

// http_emit_chunked frames `body` as HTTP/1.1 chunked transfer-encoding:
// each piece is `<hex-len>\r\n<piece>\r\n`, terminated by `0\r\n\r\n`. Pieces
// are at most http_chunk_size bytes, so a multi-KB binary stream produces
// multiple real wire chunks (a peer must de-chunk to recover the octets).
fn http_emit_chunked(mut sb []u8, body []u8) {
	mut off := 0
	for off < body.len {
		mut end := off + http_chunk_size
		if end > body.len {
			end = body.len
		}
		piece := body[off..end]
		sb << '${piece.len.hex()}\r\n'.bytes()
		sb << piece
		sb << '\r\n'.bytes()
		off = end
	}
	sb << '0\r\n\r\n'.bytes()
}

// http_serialize_response renders a server-side [response] to the HTTP/1.1 wire:
// status line + headers + CRLF + body. When the response carries a
// `Transfer-Encoding: chunked` header the body is streamed as chunked frames
// (Content-Length is suppressed — RFC 9112 §6.3 forbids both); otherwise the
// body is written verbatim behind a Content-Length forced from its length
// (§3.5). Connection: close is added if the handler did not set it.
fn http_serialize_response(resp cx.Element, status int) []u8 {
	return http_serialize_response_ka(resp, status, false, 0)
}

// http_serialize_response_ka is the keep-alive-aware serializer. When `keep_alive`
// and the handler set no explicit Connection header, it advertises
// `Connection: keep-alive` + `Keep-Alive: timeout=<idle_ms/1000>` so a persistent
// connection is held open between requests (#234.1 / CSRP §5.2); otherwise it
// adds `Connection: close` (the single-turn §3.5 exchange). The response always
// carries a definite length (Content-Length here, or the chunked 0-terminator),
// so a kept-alive peer knows exactly where one response ends and the next begins.
fn http_serialize_response_ka(resp cx.Element, status int, keep_alive bool, idle_ms i64) []u8 {
	body := http_body_octets(resp)
	hdrs := http_header_elems(resp)
	mut chunked := false
	mut saw_conn := false
	for hdr in hdrs {
		hn := http_attr(hdr, 'name') or { continue }
		hv := http_attr(hdr, 'value') or { '' }
		lname := hn.to_lower()
		if lname == 'transfer-encoding' && hv.to_lower().contains('chunked') {
			chunked = true
		}
		if lname == 'connection' {
			saw_conn = true
		}
	}
	mut sb := []u8{}
	reason := http_reason_phrase(status)
	sb << 'HTTP/1.1 ${status} ${reason}\r\n'.bytes()
	mut saw_clen := false
	for hdr in hdrs {
		hn := http_attr(hdr, 'name') or { continue }
		hv := http_attr(hdr, 'value') or { '' }
		lname := hn.to_lower()
		// Under chunked transfer a Content-Length is illegal; drop any the
		// handler set so the framing stays unambiguous.
		if chunked && lname == 'content-length' {
			continue
		}
		if lname == 'content-length' {
			saw_clen = true
		}
		sb << '${hn}: ${hv}\r\n'.bytes()
	}
	if !saw_conn {
		if keep_alive {
			sb << 'Connection: keep-alive\r\n'.bytes()
			secs := if idle_ms > 0 { idle_ms / 1000 } else { i64(0) }
			sb << 'Keep-Alive: timeout=${secs}\r\n'.bytes()
		} else {
			sb << 'Connection: close\r\n'.bytes()
		}
	}
	if chunked {
		sb << '\r\n'.bytes()
		http_emit_chunked(mut sb, body)
		return sb
	}
	if !saw_clen {
		sb << 'Content-Length: ${body.len}\r\n'.bytes()
	}
	sb << '\r\n'.bytes()
	sb << body
	return sb
}

// http_reason_phrase maps the common status codes to their RFC reason phrase;
// unknown codes fall back to a class-generic phrase (the reason is advisory —
// clients key on the numeric status).
fn http_reason_phrase(status int) string {
	return match status {
		200 { 'OK' }
		201 { 'Created' }
		202 { 'Accepted' }
		204 { 'No Content' }
		301 { 'Moved Permanently' }
		302 { 'Found' }
		304 { 'Not Modified' }
		400 { 'Bad Request' }
		401 { 'Unauthorized' }
		403 { 'Forbidden' }
		404 { 'Not Found' }
		405 { 'Method Not Allowed' }
		408 { 'Request Timeout' }
		409 { 'Conflict' }
		413 { 'Payload Too Large' }
		429 { 'Too Many Requests' }
		500 { 'Internal Server Error' }
		501 { 'Not Implemented' }
		502 { 'Bad Gateway' }
		503 { 'Service Unavailable' }
		504 { 'Gateway Timeout' }
		else {
			if status >= 200 && status < 300 { 'OK' }
			else if status >= 300 && status < 400 { 'Redirect' }
			else if status >= 400 && status < 500 { 'Client Error' }
			else { 'Server Error' }
		}
	}
}

// http_validate_bind_url returns CXER... for a non tcp/tls bind URL. Server
// binds are net transport URLs (§3.5); an http:// bind is invalid here.
fn http_validate_bind_url(url string) ?cx.Node {
	scheme, _ := http_split_scheme(url)
	if scheme != 'tcp' && scheme != 'tls' {
		return mk_err(code.http_err_url_invalid, 'E_HTTP_URL_INVALID: server bind URL must be tcp:// or tls://, got ${url}')
	}
	return none
}

// http_server_handle wraps a picoev-managed listener (high-level `serve`) — the
// engine owns the socket, so there is no net handle id to carry (unlike the
// low-level `listen` path, which uses http_server_handle_fd).
fn http_server_handle(url string) cx.Node {
	return cx.Element{
		name:  'http-server'
		attrs: [
			cx.Attribute{ name: 'url', value: cx.ScalarValue(url) },
			cx.Attribute{ name: 'state', value: cx.ScalarValue('listening') },
			cx.Attribute{ name: 'on-close', value: cx.ScalarValue('http/close') },
		]
	}
}

// http_server_handle_fd wraps a REAL net listener (handle id `fd`) as an
// [http-server]; the `fd` is what accept-iter/stop resolve back to the net
// listener handle (§3.5).
fn http_server_handle_fd(url string, fd int) cx.Node {
	return cx.Element{
		name:  'http-server'
		attrs: [
			cx.Attribute{ name: 'fd', value: cx.ScalarValue(i64(fd)) },
			cx.Attribute{ name: 'url', value: cx.ScalarValue(url) },
			cx.Attribute{ name: 'state', value: cx.ScalarValue('listening') },
			cx.Attribute{ name: 'on-close', value: cx.ScalarValue('http/close') },
		]
	}
}

// http_exchange_from_conn relabels an accepted net [socket fd=N] as an
// [exchange fd=N state=open] — one server-side request/response turn (§2.1).
// exchange-request reads the request off `fd`; respond writes the response on
// it. Called per accepted connection by the iter_http_accept walker (eval.v).
fn http_exchange_from_conn(conn cx.Node) cx.Node {
	if is_err_value(conn) {
		return conn
	}
	fd := net_handle_id(conn) or {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_ARG_INVALID: accepted connection has no handle')
	}
	return cx.Element{
		name:  'exchange'
		attrs: [
			cx.Attribute{ name: 'fd', value: cx.ScalarValue(i64(fd)) },
			cx.Attribute{ name: 'state', value: cx.ScalarValue('open') },
			cx.Attribute{ name: 'on-close', value: cx.ScalarValue('http/close') },
		]
	}
}

// http_finalize_unresponded_exchange — the accept-iter walker calls this after
// each per-exchange handler returns (#23). A handler that responded closed the
// connection (http_respond_impl closes on write); an SSE handler holds it open
// via is_sse_stream. So an exchange left OPEN and not-SSE means the handler
// returned WITHOUT responding — e.g. a denied capability poisoned the response
// argument, so [$http:respond] short-circuited on the err-value and never
// wrote. The connection would then dangle: the client hangs and there is NO
// diagnostic (the handler's yielded err-value sits unflushed in the server's
// streamed-stdout buffer for the lifetime of the never-ending accept loop).
// Fail loud — write the cause to STDERR (unbuffered, so it surfaces at once)
// and close the connection so the client observes EOF instead of hanging.
fn http_finalize_unresponded_exchange(ex cx.Node) {
	id := net_handle_id(ex) or { return }
	h := net_lookup(id) or { return }
	if h.is_open && !h.is_sse_stream {
		eprintln('cx http: accept-iter handler returned without responding on exchange fd=${id} — no response was written. A handler that errors (e.g. a denied capability poisoning [\$http:respond], which short-circuits on the err-value arg) must still respond. Closing the connection so the client does not hang.')
		net_close_id(id)
	}
}

// http_sse_impl — §3.6 server: promote an open [exchange] to a streaming
// response. Pure validation (already-responded → CXER4541) precedes the net
// guard. The granted path WRITES the event-stream prelude (200 + Content-Type:
// text/event-stream + Cache-Control: no-cache + Connection: keep-alive) on the
// exchange's held-open connection and returns a single-owner [sse-stream fd=N]
// write handle carrying the same connection. Over the max-streams bound →
// CXER4545.
fn http_sse_impl(args []cx.Node) cx.Node {
	ex := http_elem(args[0]) or {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_ARG_INVALID: sse expects an [exchange]')
	}
	if ex.name != 'exchange' {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_ARG_INVALID: sse expects an [exchange]')
	}
	if state := http_attr(ex, 'state') {
		if state == 'responded' {
			return mk_err(code.http_err_respond_invalid, 'E_HTTP_RESPOND_INVALID: exchange already responded')
		}
	}
	if d := cap_guard('net', http_handle_resource(args, 'sse')) {
		return d
	}
	if http_sse_streams_at_cap() {
		return mk_err(code.http_err_stream_limit, 'E_HTTP_STREAM_LIMIT: ${code.http_max_sse_streams} concurrent SSE streams reached')
	}
	fd := net_handle_id(args[0]) or {
		return mk_err(code.http_err_respond_invalid, 'E_HTTP_RESPOND_INVALID: sse on a closed/unknown exchange')
	}
	mut h := net_lookup(fd) or {
		return mk_err(code.http_err_respond_invalid, 'E_HTTP_RESPOND_INVALID: sse on a closed/unknown exchange')
	}
	// §3.6 opts: a retry: reconnect hint is the first frame the client sees.
	opts_node := if args.len > 1 { args[1] } else { http_null() }
	mut prelude := 'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n'
	retry := http_map_entry_str(opts_node, 'retry')
	if retry != '' {
		prelude += 'retry: ${retry}\n\n'
	}
	net_h_write(mut h, prelude.bytes()) or {
		return mk_err(code.http_err_stream_closed, 'E_HTTP_STREAM_CLOSED: peer disconnected before the SSE prelude: ${err.msg()}')
	}
	h.is_sse_stream = true // counts against the §3.6 max-streams bound until close
	http_sse_stream_opened()
	return cx.Element{
		name:  'sse-stream'
		attrs: [
			cx.Attribute{ name: 'fd', value: cx.ScalarValue(i64(fd)) },
			cx.Attribute{ name: 'open', value: cx.ScalarValue(true) },
			cx.Attribute{ name: 'on-close', value: cx.ScalarValue('http/close') },
		]
	}
}

// http_send_event_impl — §3.6: frame + flush one [event]. The event is
// validated (empty → CXER4539, CR/LF → CXER4531) and the stream's open
// state checked (closed → CXER4544) BEFORE the net guard, so those faults
// surface deterministically.
fn http_send_event_impl(args []cx.Node) cx.Node {
	stream := http_elem(args[0]) or {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_ARG_INVALID: send-event expects an [sse-stream]')
	}
	if stream.name != 'sse-stream' {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_ARG_INVALID: send-event expects an [sse-stream]')
	}
	ev := http_elem(args[1]) or {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_ARG_INVALID: send-event expects an [event]')
	}
	if ev.name != 'event' {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_ARG_INVALID: send-event expects an [event]')
	}
	// frame the event — surfaces CXER4539 (empty) / CXER4531 (CR/LF)
	framed := http_sse_frame_event(ev)
	if framed is cx.Element && framed.name == 'err' {
		return framed
	}
	// stream must be open (post-close send → CXER4544)
	if open := http_attr(stream, 'open') {
		if open == 'false' {
			return mk_err(code.http_err_stream_closed, 'E_HTTP_STREAM_CLOSED: send-event on a closed stream')
		}
	}
	if d := cap_guard('net', http_handle_resource(args, 'send-event')) {
		return d
	}
	mut h := net_mut_handle(args[0]) or {
		return mk_err(code.http_err_stream_closed, 'E_HTTP_STREAM_CLOSED: send-event on a closed/unknown stream')
	}
	wire := http_node_str(framed)
	net_h_write(mut h, wire.bytes()) or {
		// a disconnected peer / write fault → CXER4544 (the stream is dead).
		return mk_err(code.http_err_stream_closed, 'E_HTTP_STREAM_CLOSED: send-event peer disconnected: ${err.msg()}')
	}
	return http_null()
}

// ── SSE-1 (xsp.md §4.1): the negotiated XSP-envelope downstream carriage ─────
//
// A subscription that opted into the XSP envelope ([sse-subscribe topic="…"
// [envelope codec="xsp"]]) receives each event's `data:` field as
// base64(XSP `event` frame, binary=false) whose payload is byte-for-byte the
// text the plain lane delivers. SSE metadata fields (id/event/retry) stay
// plain lines — transport metadata, not the event. Non-opt-in subscribers
// keep today's plain frames byte-identically.

// sse_topic_key derives the registry key for a subscription: the plain lane
// keeps the bare topic; the XSP-envelope lane registers under a NUL-prefixed
// sibling key (authored topics come from parsed CX text, which never carries
// NUL — no collision is possible). One topic, two carriage lanes; a publish
// fans out to both keys.
fn sse_topic_key(topic string, xsp bool) string {
	if xsp {
		return '\x00xsp\x00' + topic
	}
	return topic
}

// sse_frame_event_xsp renders ONE [event …] in the XSP-envelope carriage.
// The event was already validated by the plain framer (http_sse_frame_event)
// at every call site, so only the framing differs here. A data-less event
// (id/retry-only) frames identically to the plain lane — there is no event
// payload to envelope. Returns none only on the frame-level payload-ceiling
// refusal (2^32-1 bytes).
fn sse_frame_event_xsp(ev cx.Element) ?string {
	id := http_attr(ev, 'id') or { '' }
	event := http_attr(ev, 'event') or { '' }
	retry := http_attr(ev, 'retry') or { '' }
	has_data := if _ := http_attr(ev, 'data') { true } else { false }
	data := http_attr(ev, 'data') or { '' }
	mut sb := []string{}
	if id != '' {
		sb << 'id: ${id}'
	}
	if event != '' {
		sb << 'event: ${event}'
	}
	if has_data {
		b64 := xsp_sse_data_b64(data)?
		sb << 'data: ${b64}'
	}
	if retry != '' {
		sb << 'retry: ${retry}'
	}
	return sb.join('\n') + '\n\n'
}

// http_sse_publish_impl — #28: fan out one SSE event to every connection
// subscribed to `topic` (held-open feeds promoted via an `[sse-subscribe]`
// response on the concurrent `[$http:serve]` path). Returns the number of
// subscribers the frame was delivered to. This is the producer half of the
// concurrent-SSE model: a handler on any reactor thread publishes; no reactor
// is blocked, unlike a producer loop on a single accept-iter exchange.
//
//   [$http:sse-publish "prices" [event data="42"]]
//
// Writing to the already-open subscriber sockets is a net effect → guard net.
fn http_sse_publish_impl(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_ARG_INVALID: sse-publish expects (topic, [event …])')
	}
	topic := http_arg_str(args[0]) or {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_ARG_INVALID: sse-publish expects a topic string')
	}
	if topic == '' {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_ARG_INVALID: sse-publish topic must be non-empty')
	}
	ev := http_elem(args[1]) or {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_ARG_INVALID: sse-publish expects an [event]')
	}
	if ev.name != 'event' {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_ARG_INVALID: sse-publish expects an [event]')
	}
	// frame the event — surfaces CXER4539 (empty) / CXER4531 (CR/LF)
	framed := http_sse_frame_event(ev)
	if framed is cx.Element && framed.name == 'err' {
		return framed
	}
	if d := cap_guard('net', 'sse-publish ${topic}') {
		return d
	}
	mut n := cx_sse_topic_publish(topic, http_node_str(framed))
	// SSE-1: the same event fans out to the topic's XSP-envelope lane in its
	// negotiated carriage — same event, base64(XSP event frame) data. The
	// only unreachable-in-practice failure (payload past the frame's 2^32-1
	// ceiling) is logged loudly rather than handing XSP subscribers a frame
	// they cannot decode.
	if xf := sse_frame_event_xsp(ev) {
		n += cx_sse_topic_publish(sse_topic_key(topic, true), xf)
	} else {
		eprintln('cx-http: sse-publish "${topic}": event exceeds the XSP frame payload ceiling — XSP-envelope subscribers skipped')
	}
	return http_int(i64(n))
}

// http_heartbeat_impl — §3.6: write one `:`-comment liveness frame.
fn http_heartbeat_impl(args []cx.Node) cx.Node {
	stream := http_elem(args[0]) or {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_ARG_INVALID: heartbeat expects an [sse-stream]')
	}
	if stream.name != 'sse-stream' {
		return mk_err(code.http_err_arg_invalid, 'E_HTTP_ARG_INVALID: heartbeat expects an [sse-stream]')
	}
	if open := http_attr(stream, 'open') {
		if open == 'false' {
			return mk_err(code.http_err_stream_closed, 'E_HTTP_STREAM_CLOSED: heartbeat on a closed stream')
		}
	}
	if d := cap_guard('net', http_handle_resource(args, 'heartbeat')) {
		return d
	}
	mut h := net_mut_handle(args[0]) or {
		return mk_err(code.http_err_stream_closed, 'E_HTTP_STREAM_CLOSED: heartbeat on a closed/unknown stream')
	}
	// one `:`-comment liveness frame (SSE comment, consumed silently by clients).
	net_h_write(mut h, ': heartbeat\n\n'.bytes()) or {
		return mk_err(code.http_err_stream_closed, 'E_HTTP_STREAM_CLOSED: heartbeat peer disconnected: ${err.msg()}')
	}
	return http_null()
}

// http_stream_open_impl — §3.6 pure producer-loop guard.
fn http_stream_open_impl(args []cx.Node) cx.Node {
	stream := http_elem(args[0]) or { return http_bool(false) }
	if stream.name != 'sse-stream' {
		return http_bool(false)
	}
	if open := http_attr(stream, 'open') {
		return http_bool(open != 'false')
	}
	return http_bool(false)
}

