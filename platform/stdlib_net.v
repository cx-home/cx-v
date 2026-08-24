module platform
import code {
	NetAddr,
	NetHandle,
	cap_guard,
	mk_err,
	net_arm_read_deadline,
	net_close_id,
	net_dial_tcp_real,
	net_dial_tls_real,
	net_err_is_timeout,
	net_h_connected,
	net_h_read_step,
	net_h_write,
	net_handle_id,
	net_join_host_port,
	net_lookup,
	net_map_get,
	net_map_get_ms,
	net_mut_handle,
	net_node_ms,
	net_opts_tls_str,
	net_opts_tls_verify,
	net_register,
	net_socket_element,
	net_spec_split,
	net_ssrf_check,
	net_strip_port,
}

import cx
import net
import net.unix
import net.mbedtls
import time

// stdlib_net.v — native primitives backing the `cx-stdlib/net` module
// (spec/02-inprogress/stdlib_net.md). L4 networking: TCP/UDP/Unix/TLS/DTLS
// dial + listen + accept, stream + datagram I/O, TLS upgrade, lifecycle.
//
// ── CAPABILITY ENFORCEMENT (the core of this module, §5) ────────────
//   net is a Tier-B, necessarily-impure module: every socket/resolver
//   function is `:impure` and every effect point is gated on the `net`
//   capability (security.md §2, deny-by-default). The FIRST thing every
//   gated primitive does is `cap_guard('net', resource)` — BEFORE any
//   socket touch or domain validation (fail-closed, §4.1). Under the
//   runner's empty capability set the guard returns the CXER0271 err
//   VALUE and the function short-circuits, so the deterministic
//   conformance suite (deny cases) sees CXER0271.
//
//   Capability-FREE (no guard, pure or local-introspection only, §5):
//     parse-addr, addr->string   — pure URL/address parse + format
//     close, is-open,             — release / inspect an already-granted
//     local-addr, remote-addr        handle; read cached snapshot, no I/O
//
//   The §5 capability table — the target is checked at the point of
//   outbound reach (dial / send-to / listen / resolve); accept, connected
//   send/recv, stream I/O, set-*, tls-*, shutdown INHERIT the handle grant
//   (the target was already checked when the handle was created).
//
// ── ERROR BAND (§8) ─────────────────────────────────────────────────
//   net owns cx-err:CXER4500–CXER4524 (E_NET_*). The rev-7 draft proposed
//   the 4400-band off a stale registry read ("registry stops 4300-4309");
//   cx-stdlib/fp subsequently took CXER4400–4409 (governance.md §9.6), so
//   net is allocated the next free 25-code block, 4500–4524. The spec text
//   + governance registry are updated to match.
//
// ── CX value model ──────────────────────────────────────────────────
//   int/string/bool/bytes/null scalars; sequence = Element{'__cx_seq__'};
//   a socket/listener/addr is an opaque element ([socket …]/[listener …]/
//   [addr …]) carrying an integer registry id (the proven io/store form).
//
//   Behind the cap guard the socket operations would perform real syscalls
//   (V's `net`/`net.unix`/`net.ssl`); the conformance harness runs under
//   the empty capability set so those paths are guarded-out. A capability-
//   granted harness (implementation-phase) exercises the live paths.




// ── value builders ──────────────────────────────────────────────────
fn net_str(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	}
}

fn net_int(i i64) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(i)
		data_type: cx.ScalarType.int_type
	}
}

fn net_bool(b bool) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bool_type
	}
}

fn net_null() cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(cx.NullValue{})
		data_type: cx.ScalarType.null_type
	}
}

fn net_seq(items []cx.Node) cx.Node {
	return cx.Element{
		name:  '__cx_seq__'
		items: items
	}
}

fn net_bytes(b []u8) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b.bytestr())
		data_type: cx.ScalarType.bytes_type
	}
}

fn net_arg_bytes(n cx.Node) ?[]u8 {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v.bytes()
		}
	}
	return none
}

// net_empty_nodeset is net's declared "nothing found" value (§0.2/§2.5):
// an empty sequence (no result). Used by remote-addr / peer-cert misses.
fn net_empty_nodeset() cx.Node {
	return net_seq([])
}

// ── argument readers ────────────────────────────────────────────────
fn net_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return none
}

fn net_arg_int(n cx.Node) ?i64 {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			i64 { return v }
			f64 { return i64(v) }
			else {}
		}
	}
	return none
}

// ── address element (§2.2) ──────────────────────────────────────────
fn net_addr_element(a NetAddr) cx.Node {
	mut attrs := []cx.Attribute{}
	if a.family == 'unix' {
		attrs << cx.Attribute{
			name:  'path'
			value: cx.ScalarValue(a.path)
		}
		attrs << cx.Attribute{
			name:  'family'
			value: cx.ScalarValue('unix')
		}
	} else {
		attrs << cx.Attribute{
			name:  'host'
			value: cx.ScalarValue(a.host)
		}
		attrs << cx.Attribute{
			name:  'port'
			value: cx.ScalarValue(i64(a.port))
		}
		attrs << cx.Attribute{
			name:  'family'
			value: cx.ScalarValue(a.family)
		}
		if a.zone != '' {
			attrs << cx.Attribute{
				name:  'zone'
				value: cx.ScalarValue(a.zone)
			}
		}
	}
	return cx.Element{
		name:  'addr'
		attrs: attrs
	}
}

// ── restricted transport-URL parse (§2.2) ───────────────────────────
//
// parse_transport_url parses the net-restricted transport URL grammar.
// Returns the NetAddr or a §8 err VALUE. PURE (no resolution / no I/O).
//   tcp://host:port  tls://host:port  udp://host:port  dtls://host:port
//   unix:/abs/path   unix-abstract:NAME   bare host:port (no scheme)
fn parse_transport_url(s string, for_listen bool) !NetAddr {
	if s == '' {
		return error(code.net_err_addr_invalid)
	}
	mut scheme := ''
	mut rest := s
	// scheme split
	if s.contains('://') {
		scheme = s.all_before('://')
		rest = s.all_after('://')
	} else if s.starts_with('unix:') {
		scheme = 'unix'
		rest = s['unix:'.len..]
	} else if s.starts_with('unix-abstract:') {
		scheme = 'unix-abstract'
		rest = s['unix-abstract:'.len..]
	}
	// reject userinfo / query / fragment on every scheme (§2.2)
	if scheme !in ['unix', 'unix-abstract'] {
		if rest.contains('@') || rest.contains('?') || rest.contains('#') {
			return error(code.net_err_addr_invalid)
		}
	}
	match scheme {
		'unix' {
			path := net_percent_decode(rest)
			if path == '' {
				return error(code.net_err_addr_invalid)
			}
			return NetAddr{
				family: 'unix'
				path:   path
				port:   -1
				scheme: 'unix'
			}
		}
		'unix-abstract' {
			if rest == '' {
				return error(code.net_err_addr_invalid)
			}
			return NetAddr{
				family: 'unix'
				path:   rest
				port:   -1
				scheme: 'unix-abstract'
			}
		}
		'tcp', 'tls', 'udp', 'dtls', '' {
			// a path component on a host scheme is rejected (§2.2)
			if rest.contains('/') {
				return error(code.net_err_addr_invalid)
			}
			eff_scheme := if scheme == '' { 'tcp' } else { scheme }
			mut host := ''
			mut zone := ''
			mut port_str := ''
			mut family := 'ipv4'
			if rest.starts_with('[') {
				// bracketed IPv6 literal: [::1]:443 or [fe80::1%en0]:443
				close := rest.index(']') or { return error(code.net_err_addr_invalid) }
				inner := rest[1..close]
				after := rest[close + 1..]
				if inner.contains('%') {
					host = inner.all_before('%')
					zone = inner.all_after('%')
				} else {
					host = inner
				}
				family = 'ipv6'
				if after.starts_with(':') {
					port_str = after[1..]
				} else if after == '' {
					port_str = ''
				} else {
					return error(code.net_err_addr_invalid)
				}
			} else {
				// host:port (IPv4 / hostname / empty wildcard)
				li := rest.last_index(':') or { -1 }
				if li < 0 {
					host = rest
					port_str = ''
				} else {
					host = rest[..li]
					port_str = rest[li + 1..]
				}
				// a bare unbracketed multi-colon token is an IPv6 missing brackets
				if host.contains(':') {
					return error(code.net_err_addr_invalid)
				}
			}
			// port mandatory for tcp/tls/udp/dtls (§2.2)
			if port_str == '' {
				return error(code.net_err_addr_invalid)
			}
			port := port_str.int()
			if port <= 0 || port > 65535 || port_str != port.str() {
				return error(code.net_err_addr_invalid)
			}
			// empty host legal only as a wildcard bind (listen); dial → invalid
			if host == '' && !for_listen {
				return error(code.net_err_addr_invalid)
			}
			return NetAddr{
				host:   host
				port:   port
				family: family
				zone:   zone
				scheme: eff_scheme
			}
		}
		else {
			return error(code.net_err_scheme_unsupported)
		}
	}
}

// net_percent_decode decodes %XX escapes (only used for unix: paths, §2.2).
fn net_percent_decode(s string) string {
	if !s.contains('%') {
		return s
	}
	mut out := []u8{}
	mut i := 0
	for i < s.len {
		if s[i] == `%` && i + 2 < s.len {
			hi := net_hex_val(s[i + 1])
			lo := net_hex_val(s[i + 2])
			if hi >= 0 && lo >= 0 {
				out << u8(hi * 16 + lo)
				i += 3
				continue
			}
		}
		out << s[i]
		i++
	}
	return out.bytestr()
}

fn net_hex_val(c u8) int {
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

// net_addr_to_string renders a NetAddr back to its canonical transport URL
// form (§2.2 round-trip: parse-addr(addr->string(a)) == a).
fn net_addr_to_string(a NetAddr) string {
	if a.family == 'unix' {
		if a.scheme == 'unix-abstract' {
			return 'unix-abstract:${a.path}'
		}
		return 'unix:${a.path}'
	}
	mut host := a.host
	if a.family == 'ipv6' {
		if a.zone != '' {
			host = '[${a.host}%${a.zone}]'
		} else {
			host = '[${a.host}]'
		}
	}
	if a.port >= 0 {
		return '${host}:${a.port}'
	}
	return host
}

// net_addr_from_element reads a NetAddr back off an [addr …] element (for
// addr->string). Returns none if the element is not a well-formed addr.
fn net_addr_from_element(n cx.Node) ?NetAddr {
	if n is cx.Element {
		if n.name != 'addr' {
			return none
		}
		mut a := NetAddr{
			port: -1
		}
		for attr in n.attrs {
			val := cx.scalar_value_str_public(attr.value)
			match attr.name {
				'host' { a.host = val }
				'port' { a.port = val.int() }
				'family' { a.family = val }
				'zone' { a.zone = val }
				'path' { a.path = val }
				else {}
			}
		}
		if a.family == 'unix' && a.scheme == '' {
			a.scheme = 'unix'
		}
		return a
	}
	return none
}

// ── primitive dispatch ──────────────────────────────────────────────
//
// Gated socket/resolver primitives — every name maps to the `net`
// capability and is guarded fail-closed BEFORE any work. The pure /
// capability-free primitives (parse-addr, addr->string, close, is-open,
// local-addr, remote-addr) are intentionally absent from this list.
const net_gated_prims = ['net-resolve', 'net-dial', 'net-dial-tcp', 'net-dial-tls',
	'net-dial-udp', 'net-dial-dtls', 'net-dial-unix', 'net-listen', 'net-listen-tcp',
	'net-listen-tls', 'net-listen-udp', 'net-listen-dtls', 'net-listen-unix', 'net-accept',
	'net-accept-iter', 'net-read-bytes', 'net-read-exact', 'net-read-line', 'net-read-all',
	'net-read-all-bytes', 'net-write-bytes', 'net-write-string', 'net-write-line', 'net-flush',
	'net-is-eof', 'net-line-iter', 'net-chunk-iter', 'net-send-to', 'net-recv-from', 'net-send',
	'net-recv', 'net-tls-wrap', 'net-tls-accept', 'net-peer-cert', 'net-tls-info',
	'net-shutdown', 'net-set-deadline', 'net-set-opt']

fn net_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	// not a net primitive → let the dispatch chain continue
	if !name.starts_with('net-') {
		return none
	}

	// ── capability gate (§5), fail-closed BEFORE any effect ─────────────
	// Every gated primitive checks `net` against the requested resource.
	// The resource is the dialed/bound/sent-to target where available, so
	// the CXER0271 names it (§4 actionable error); else the primitive name.
	if name in net_gated_prims {
		resource := net_gate_resource(name, args)
		if d := cap_guard('net', resource) {
			return d
		}
	}

	match name {
		// ── §3.1 resolution & addresses (parse-addr / addr->string PURE) ─
		'net-parse-addr' {
			s := net_arg_str(args[0]) or { return none }
			a := parse_transport_url(s, false) or {
				return mk_err(err.msg(), 'E_NET: parse-addr ${s}')
			}
			return net_addr_element(a)
		}
		'net-addr-to-string' {
			a := net_addr_from_element(args[0]) or {
				return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: addr->string expects an [addr …] element')
			}
			return net_str(net_addr_to_string(a))
		}
		'net-resolve' {
			// Behind the net guard: a real getaddrinfo. The deny-lane harness
			// never reaches here. A no-record host → CXER4502.
			host := net_arg_str(args[0]) or { return none }
			opts := if args.len > 1 { args[1] } else { cx.Node(cx.Element{ name: '__cx_map__' }) }
			fam := net_map_get_str(opts, 'family')
			return net_resolve_impl(host, fam)
		}

		// ── §3.2 dial / §3.3 listen / accept ────────────────────────────
		// Behind the net guard these perform real connect()/bind()/accept()
		// + the §4.5 SSRF guard + (for tls/dtls) the handshake. The empty
		// capability set guards them out; the granted harness exercises the
		// live paths. We validate URL shape (a pure check) so a malformed
		// URL surfaces CXER4500/4501 even under a grant.
		'net-dial', 'net-dial-tcp', 'net-dial-tls', 'net-dial-udp', 'net-dial-dtls' {
			return net_dial_impl(name, args)
		}
		'net-dial-unix' {
			path := net_arg_str(args[0]) or { return none }
			return net_dial_unix_real(path)
		}
		'net-listen', 'net-listen-tcp', 'net-listen-tls', 'net-listen-udp', 'net-listen-dtls' {
			return net_listen_impl(name, args)
		}
		'net-listen-unix' {
			path := net_arg_str(args[0]) or { return none }
			return net_listen_unix_real(path)
		}
		'net-accept' {
			// inherit the listener grant (target checked at listen). Blocks for
			// one connection, registers it as a connected socket handle.
			mut h := net_mut_handle(args[0]) or {
				return mk_err(code.net_err_handle_closed, 'E_NET_HANDLE_CLOSED: unknown listener handle')
			}
			return net_accept_real(mut h)
		}
		'net-accept-iter' {
			// a lazy connection iterator: each [?for] pull does one accept()
			// (the walk lives in eval.v::iter_net_accept_walk_streamed). The
			// listener handle is carried; it terminates when the listener closes.
			return cx.new_iterator(.iter_net_accept, [args[0]])
		}

		// ── §3.4 stream I/O / §3.5 datagram I/O ──────────────────────────
		'net-read-bytes', 'net-read-exact' {
			n := net_arg_int(args[1]) or { return none }
			if n < 1 {
				return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: n must be >= 1')
			}
			mut h := net_mut_handle(args[0]) or {
				return mk_err(code.net_err_handle_closed, 'E_NET_HANDLE_CLOSED: unknown handle')
			}
			return net_read_bytes_real(mut h, int(n), false)
		}
		'net-read-line' {
			mut h := net_mut_handle(args[0]) or {
				return mk_err(code.net_err_handle_closed, 'E_NET_HANDLE_CLOSED: unknown handle')
			}
			return net_read_line_real(mut h)
		}
		'net-read-all' {
			mut h := net_mut_handle(args[0]) or {
				return mk_err(code.net_err_handle_closed, 'E_NET_HANDLE_CLOSED: unknown handle')
			}
			return net_read_all_real(mut h)
		}
		'net-read-all-bytes' {
			mut h := net_mut_handle(args[0]) or {
				return mk_err(code.net_err_handle_closed, 'E_NET_HANDLE_CLOSED: unknown handle')
			}
			return net_read_bytes_real(mut h, 64 * 1024 * 1024, true)
		}
		'net-write-bytes', 'net-write-string', 'net-write-line', 'net-flush' {
			mut h := net_mut_handle(args[0]) or {
				return mk_err(code.net_err_handle_closed, 'E_NET_HANDLE_CLOSED: unknown handle')
			}
			return net_write_real(mut h, name, args)
		}
		'net-is-eof' {
			h := net_lookup(net_handle_id(args[0]) or { return net_bool(true) }) or {
				return net_bool(true)
			}
			return net_bool(h.eof)
		}
		'net-send' {
			mut h := net_mut_handle(args[0]) or {
				return mk_err(code.net_err_handle_closed, 'E_NET_HANDLE_CLOSED: unknown handle')
			}
			data := net_arg_bytes(args[1]) or {
				return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: send expects bytes/string')
			}
			return net_udp_send(mut h, data)
		}
		'net-recv' {
			n := net_arg_int(args[1]) or { return none }
			if n < 1 {
				return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: n must be >= 1')
			}
			mut h := net_mut_handle(args[0]) or {
				return mk_err(code.net_err_handle_closed, 'E_NET_HANDLE_CLOSED: unknown handle')
			}
			return net_udp_recv(mut h, int(n))
		}
		'net-send-to' {
			mut h := net_mut_handle(args[0]) or {
				return mk_err(code.net_err_handle_closed, 'E_NET_HANDLE_CLOSED: unknown handle')
			}
			data := net_arg_bytes(args[1]) or {
				return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: send-to expects bytes/string')
			}
			return net_udp_send_to(mut h, data, args[2])
		}
		'net-recv-from' {
			n := net_arg_int(args[1]) or { return none }
			if n < 1 {
				return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: n must be >= 1')
			}
			mut h := net_mut_handle(args[0]) or {
				return mk_err(code.net_err_handle_closed, 'E_NET_HANDLE_CLOSED: unknown handle')
			}
			return net_udp_recv_from(mut h, int(n))
		}
		'net-line-iter' {
			// §3.4 lazy line stream — yields CRLF/LF-stripped lines until EOF.
			if args.len < 1 {
				return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: line-iter expects a socket')
			}
			net_mut_handle(args[0]) or {
				return mk_err(code.net_err_handle_closed, 'E_NET_HANDLE_CLOSED: unknown handle')
			}
			return cx.new_iterator(.iter_net_line, [args[0]])
		}
		'net-chunk-iter' {
			// §3.4 lazy binary chunk stream — yields up-to-n-byte chunks until EOF.
			if args.len < 2 {
				return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: chunk-iter expects (socket, n)')
			}
			n := net_arg_int(args[1]) or {
				return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: chunk-iter size must be an int')
			}
			if n < 1 {
				return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: chunk-iter size must be >= 1')
			}
			net_mut_handle(args[0]) or {
				return mk_err(code.net_err_handle_closed, 'E_NET_HANDLE_CLOSED: unknown handle')
			}
			return cx.new_iterator(.iter_net_chunk, [args[0], net_int(n)])
		}

		// ── §3.6 TLS ─────────────────────────────────────────────────────
		'net-tls-wrap', 'net-tls-accept', 'net-peer-cert', 'net-tls-info' {
			return net_handle_op_socket(args[0])
		}

		// ── §3.7 lifecycle / introspection ───────────────────────────────
		'net-close' {
			// §5: no capability — releases an already-granted handle.
			// Idempotent (§3.7) — double close never raises CXER4515.
			id := net_handle_id(args[0]) or { return net_null() }
			net_close_id(id)
			return net_null()
		}
		'net-shutdown' {
			return net_handle_op_null(args[0])
		}
		'net-set-deadline', 'net-set-opt' {
			// Fail loud on a std-stream handle (#29): set-deadline / set-opt
			// are socket operations. A `[std-stream …]` (stdin/stdout/stderr
			// from cx-stdlib/env) was SILENTLY accepted (returned ok) yet had
			// no effect — the read still blocked past the "deadline". Reject so
			// the caller learns it now instead of debugging a phantom timeout.
			// (A timeout/non-blocking std-stream READ is a separate, not-yet-
			// available surface — see #29's deferred half.)
			if args.len > 0 {
				if args[0] is cx.Element && (args[0] as cx.Element).name == 'std-stream' {
					op := name['net-'.len..]
					return mk_err(code.net_err_arg_invalid,
						'E_NET_ARG_INVALID: ${op} is not supported on a std-stream handle (stdin/stdout/stderr have no socket deadline/options); a timeout/non-blocking std-stream read is not available')
				}
			}
			if name == 'net-set-deadline' {
				// §3.7 set-deadline (#56): wire the READ deadline so read-line /
				// read-all / line-iter honor it (`read` / `both` relative ms, or
				// `read-deadline` as a synonym of the dial opt; `:none` clears).
				// The write deadline and absolute `read-at` / `write-at` forms are
				// accepted (no error) but not yet applied to reads in this build.
				mut h := net_mut_handle(args[0]) or {
					return mk_err(code.net_err_handle_closed, 'E_NET_HANDLE_CLOSED: unknown handle')
				}
				opts := if args.len > 1 {
					args[1]
				} else {
					cx.Node(cx.Element{ name: '__cx_map__' })
				}
				for key in ['read', 'both', 'read-deadline'] {
					v := net_map_get(opts, key) or { continue }
					if net_is_none_atom(v) {
						h.read_deadline_ms = 0
						if h.conn != unsafe { nil } {
							h.conn.set_read_deadline(time.unix(0))
							h.conn.set_read_timeout(net.tcp_default_read_timeout)
						}
						if h.udp != unsafe { nil } {
							// Clearing must undo the per-op arming (timeout=0 +
							// absolute deadline), else the next recv sees a stale
							// past deadline and times out instantly. No-deadline
							// datagram semantics = block until a datagram arrives
							// (the bound-server default set at listen-udp).
							h.udp.set_read_deadline(time.unix(0))
							h.udp.set_read_timeout(net.infinite_timeout)
						}
					} else if ms := net_node_ms(v) {
						// A zero / past relative deadline lapses immediately
						// (net.md §3.7) — store a minimal positive budget so the
						// next read surfaces CXER4507 rather than blocking.
						h.read_deadline_ms = if ms > 0 { ms } else { i64(1) }
					}
				}
				return net_null()
			}
			// net-set-opt (#548): EVERY §3.7 option either APPLIES or REFUSES
			// loudly, per key — never a phantom accept. Unknown keys refuse
			// too (they were silently swallowed before).
			opts2 := if args.len > 1 {
				args[1]
			} else {
				cx.Node(cx.Element{ name: '__cx_map__' })
			}
			mut h := net_mut_handle(args[0]) or {
				return mk_err(code.net_err_handle_closed, 'E_NET_HANDLE_CLOSED: unknown handle')
			}
			if opts2 is cx.Element && (opts2.name == '__cx_map__' || opts2.name == 'map') {
				for it in opts2.items {
					if it is cx.Element && it.items.len > 0 {
						r := net_apply_sock_opt(mut h, it.name, it.items[0])
						if r_el := r {
							return r_el // an [err …] from this option
						}
					}
				}
			}
			return net_handle_op_null(args[0])
		}
		'net-is-open' {
			// §5: no capability — inspect cached handle state.
			id := net_handle_id(args[0]) or { return net_bool(false) }
			h := net_lookup(id) or { return net_bool(false) }
			return net_bool(h.is_open)
		}
		'net-local-addr' {
			// §5: no capability — cached snapshot, allowed after close.
			id := net_handle_id(args[0]) or { return net_empty_nodeset() }
			h := net_lookup(id) or { return net_empty_nodeset() }
			mut out := []cx.Node{}
			for a in h.local {
				out << net_addr_element(a)
			}
			return net_seq(out)
		}
		'net-remote-addr' {
			// §5: no capability — cached snapshot or empty node-set.
			id := net_handle_id(args[0]) or { return net_empty_nodeset() }
			h := net_lookup(id) or { return net_empty_nodeset() }
			if r := h.remote {
				return net_addr_element(r)
			}
			return net_empty_nodeset()
		}
		else {
			return none
		}
	}
}

// net_gate_resource extracts the §4 actionable resource for the CXER0271
// message: the dialed/bound/sent-to target where the first arg is a URL
// string, else the primitive name.
fn net_gate_resource(name string, args []cx.Node) string {
	if args.len > 0 {
		if s := net_arg_str(args[0]) {
			return s
		}
	}
	return name
}


// ── live-path impls (reached only behind the net grant) ─────────────
//
// These run under a granted `net` capability (implementation-phase
// granted harness). Under the conformance harness's empty set the
// cap_guard above short-circuits before any of them run. They validate
// the URL shape (a pure check that holds under a grant too) and would,
// in the granted harness, perform the real syscall + SSRF guard.

fn net_dial_impl(name string, args []cx.Node) cx.Node {
	url := net_arg_str(args[0]) or { return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: dial expects a URL string') }
	a := parse_transport_url(url, false) or {
		return mk_err(err.msg(), 'E_NET: dial ${url}')
	}
	// pinned-alias scheme mismatch (§2.3) → CXER4501. A bare host:port (no
	// scheme) parses as `tcp` and is accepted by any alias as its implied
	// scheme, so a transport-pinned alias only rejects an EXPLICIT mismatch.
	want := net_alias_scheme(name)
	had_scheme := url.contains('://')
	if want != '' && had_scheme && a.scheme != want {
		return mk_err(code.net_err_scheme_unsupported, 'E_NET_SCHEME_UNSUPPORTED: ${name} rejects scheme ${a.scheme}')
	}
	eff := if want != '' { want } else { a.scheme }
	if eff !in ['tcp', 'tls', 'udp', 'dtls'] {
		// Unix dial is handled by the dedicated net-dial-unix prim; any other
		// scheme fails honestly (no synthetic handle — the no-stub rule).
		return mk_err(code.net_err_scheme_unsupported, 'E_NET: ${eff} dial not yet implemented (TCP + TLS + UDP + DTLS in this build)')
	}
	// §4.5 SSRF / DNS-rebinding guard: resolve + canonicalize + capability host
	// match + deny-set/override, then PIN the admitted candidate. dial connects
	// to the pinned IP (no re-resolve); TLS/DTLS still SNI/verify the hostname.
	pinned, derr := net_ssrf_check(a.host, a.port)
	if e := derr {
		return e
	}
	mut pa := a
	pa.host = pinned
	opts := if args.len > 1 { args[1] } else { cx.Node(cx.Element{ name: '__cx_map__' }) }
	if eff == 'tcp' {
		return net_dial_tcp_real(pa, opts)
	}
	if eff == 'udp' {
		return net_dial_udp_real(pa, opts)
	}
	if eff == 'dtls' {
		return net_dial_dtls_real(pinned, a.host, a.port, opts, a)
	}
	return net_dial_tls_real(pinned, a.host, a.port, opts, a)
}



// net_listen_tcp_real binds a real TCP listener (§3.3) and stores it on the
// handle; accept() pulls connections from it.
fn net_listen_tcp_real(a NetAddr) cx.Node {
	saddr := '${a.host}:${a.port}'
	listener := net.listen_tcp(.ip, saddr, net.ListenOptions{}) or {
		return mk_err(code.net_err_addr_in_use, 'E_NET_ADDR_IN_USE: listen ${saddr}: ${err.msg()}')
	}
	mut h := &NetHandle{
		kind:      'listener'
		transport: 'tcp'
		state:     'listening'
		is_open:   true
		local:     [a]
		listener:  listener
	}
	id := net_register(h)
	return net_socket_element(id, h)
}

// net_listen_tls_real binds a real TLS listener (§3.3/§3.6) via mbedTLS. The
// server identity (cert/key) comes from opts.tls; accept() does the per-peer
// handshake. mTLS (require-client-cert) when a ca is configured.
fn net_listen_tls_real(a NetAddr, opts cx.Node) cx.Node {
	cert := net_opts_tls_str(opts, 'cert')
	key := net_opts_tls_str(opts, 'key')
	if cert == '' || key == '' {
		return mk_err(code.net_err_tls_config, 'E_NET_TLS_CONFIG: listen-tls requires opts.tls.cert + opts.tls.key')
	}
	ca := net_opts_tls_str(opts, 'ca')
	// `in-memory` (opts.tls.in-memory=true): cert/key/ca are PEM CONTENT, parsed in
	// memory (mbedtls_x509_crt_parse) rather than as filesystem paths
	// (mbedtls_x509_crt_parse_file). The store daemon uses this so an ${env:VAR}-
	// injected key PEM never has to touch disk (#180/#199).
	in_memory := net_opts_tls_str(opts, 'in-memory') == 'true'
	cfg := mbedtls.SSLConnectConfig{
		cert:                   cert
		cert_key:               key
		validate:               ca != '' // require a client cert only under mTLS (a configured ca)
		verify:                 ca
		in_memory_verification: in_memory
	}
	saddr := '${a.host}:${a.port}'
	listener := mbedtls.new_ssl_listener(saddr, cfg) or {
		return mk_err(code.net_err_tls_config, 'E_NET_TLS_CONFIG: listen-tls ${saddr}: ${err.msg()}')
	}
	mut h := &NetHandle{
		kind:         'listener'
		transport:    'tls'
		state:        'listening'
		is_open:      true
		secure:       true
		local:        [a]
		ssl_listener: listener
	}
	id := net_register(h)
	return net_socket_element(id, h)
}

// net_accept_real blocks for one inbound connection (§3.3) and registers it as a
// new connected socket handle (the §3.4 stream verbs then work over it). A TLS
// listener performs the per-peer handshake and yields a secure socket.
fn net_accept_real(mut h NetHandle) cx.Node {
	if h.ssl_listener != unsafe { nil } {
		conn := h.ssl_listener.accept() or {
			return mk_err(code.net_err_tls_handshake, 'E_NET_TLS_HANDSHAKE_FAILED: accept: ${err.msg()}')
		}
		mut sh := &NetHandle{
			kind:      'socket'
			transport: 'tls'
			state:     'open'
			is_open:   true
			secure:    true
			ssl:       conn
		}
		id := net_register(sh)
		return net_socket_element(id, sh)
	}
	if h.dtls_listener != unsafe { nil } {
		// §3.6a: accept runs the mandatory HelloVerifyRequest cookie exchange
		// then the per-peer DTLS handshake → a secured datagram socket.
		conn := h.dtls_listener.accept() or {
			return mk_err(code.net_err_tls_handshake, 'E_NET_TLS_HANDSHAKE_FAILED: dtls accept: ${err.msg()}')
		}
		mut sh := &NetHandle{
			kind:      'socket'
			transport: 'dtls'
			state:     'open'
			is_open:   true
			secure:    true
			dtls:      conn
		}
		id := net_register(sh)
		return net_socket_element(id, sh)
	}
	if h.unix_listener != unsafe { nil } {
		conn := h.unix_listener.accept() or {
			return mk_err(code.net_err_handle_closed, 'E_NET: accept: ${err.msg()}')
		}
		mut sh := &NetHandle{
			kind:      'socket'
			transport: 'unix'
			state:     'open'
			is_open:   true
			unix_conn: conn
		}
		id := net_register(sh)
		return net_socket_element(id, sh)
	}
	if h.listener == unsafe { nil } {
		return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: accept on a non-listener handle')
	}
	conn := h.listener.accept() or {
		return mk_err(code.net_err_handle_closed, 'E_NET: accept: ${err.msg()}')
	}
	mut sh := &NetHandle{
		kind:      'socket'
		transport: 'tcp'
		state:     'open'
		is_open:   true
		conn:      conn
	}
	id := net_register(sh)
	return net_socket_element(id, sh)
}

// net_dial_udp_real connects a datagram socket (§3.5): send/recv go to the
// pinned remote; no stream framing. The §3.2 `read-deadline` dial opt is
// honored like TCP's (stored on the handle, armed per recv — see
// net_arm_read_deadline; set-deadline can later update or clear it).
fn net_dial_udp_real(a NetAddr, opts cx.Node) cx.Node {
	raddr := net_join_host_port(a.host, a.port)
	udp := net.dial_udp(raddr) or {
		return mk_err(code.net_err_unreachable, 'E_NET: dial-udp ${raddr}: ${err.msg()}')
	}
	rd_ms := net_map_get_ms(opts, 'read-deadline') or { i64(0) }
	mut h := &NetHandle{
		kind:             'socket'
		transport:        'udp'
		state:            'open'
		is_open:          true
		local:            [a]
		udp:              udp
		read_deadline_ms: if rd_ms > 0 { rd_ms } else { 0 }
	}
	id := net_register(h)
	return net_socket_element(id, h)
}

// net_udp_send writes one datagram to the connected remote (§3.5); returns the
// datagram length.
fn net_udp_send(mut h NetHandle, data []u8) cx.Node {
	// a DTLS socket (§3.6a) is a secured datagram socket — one send = one DTLS
	// record in one datagram; route through the DTLS layer.
	if h.dtls != unsafe { nil } {
		n := h.dtls.write(data) or {
			return mk_err(code.net_err_reset, 'E_NET: dtls send: ${err.msg()}')
		}
		return net_int(n)
	}
	if h.udp == unsafe { nil } {
		return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: send needs a connected datagram socket')
	}
	n := h.udp.write(data) or {
		return mk_err(code.net_err_reset, 'E_NET: udp send: ${err.msg()}')
	}
	return net_int(n)
}

// net_udp_recv reads one datagram (up to n bytes) from the connected socket.
fn net_udp_recv(mut h NetHandle, n int) cx.Node {
	if h.dtls != unsafe { nil } {
		mut dbuf := []u8{len: n}
		rd := h.dtls.read(mut dbuf) or {
			return mk_err(code.net_err_reset, 'E_NET: dtls recv: ${err.msg()}')
		}
		return net_bytes(dbuf[..rd])
	}
	if h.udp == unsafe { nil } {
		return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: recv needs a connected datagram socket')
	}
	net_arm_read_deadline(mut h)
	mut buf := []u8{len: n}
	rd, _ := h.udp.read(mut buf) or {
		if h.read_deadline_ms > 0 && net_err_is_timeout(err) {
			return mk_err(code.net_err_timeout, 'E_NET_TIMEOUT: recv exceeded the ${h.read_deadline_ms}ms read deadline')
		}
		return mk_err(code.net_err_reset, 'E_NET: udp recv: ${err.msg()}')
	}
	return net_bytes(buf[..rd])
}

// net_listen_udp_real binds a datagram socket for recv-from/send-to (§3.3/§3.5).
fn net_listen_udp_real(a NetAddr) cx.Node {
	laddr := net_join_host_port(a.host, a.port)
	mut udp := net.listen_udp(laddr) or {
		return mk_err(code.net_err_addr_in_use, 'E_NET_ADDR_IN_USE: listen-udp ${laddr}: ${err.msg()}')
	}
	// a bound datagram server blocks on recv-from until a datagram arrives;
	// V's default 100 ms UDP read timeout would spuriously time it out.
	udp.set_read_timeout(net.infinite_timeout)
	mut h := &NetHandle{
		kind:      'socket'
		transport: 'udp'
		state:     'open'
		is_open:   true
		local:     [a]
		udp:       udp
	}
	id := net_register(h)
	return net_socket_element(id, h)
}

// net_target_host_port extracts (host, port) from a send-to $to: an [addr …]
// element or a "host:port" string.
fn net_target_host_port(to cx.Node) ?(string, int) {
	if a := net_addr_from_element(to) {
		return a.host, a.port
	}
	if s := net_arg_str(to) {
		h, p := net_spec_split(s)
		if p == '' {
			return none
		}
		return h, p.int()
	}
	return none
}

// net_udp_recv_from reads one datagram + its sender (§3.5) → [datagram [bytes …]
// [from [addr …]]].
fn net_udp_recv_from(mut h NetHandle, n int) cx.Node {
	if h.udp == unsafe { nil } {
		return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: recv-from needs a datagram socket')
	}
	net_arm_read_deadline(mut h)
	mut buf := []u8{len: n}
	rd, addr := h.udp.read(mut buf) or {
		if h.read_deadline_ms > 0 && net_err_is_timeout(err) {
			return mk_err(code.net_err_timeout, 'E_NET_TIMEOUT: recv-from exceeded the ${h.read_deadline_ms}ms read deadline')
		}
		return mk_err(code.net_err_reset, 'E_NET: udp recv-from: ${err.msg()}')
	}
	fip := net_strip_port(addr.str())
	fport := addr.port() or { u16(0) }
	from := net_addr_element(NetAddr{
		host:   fip
		port:   int(fport)
		family: if fip.contains(':') { 'ipv6' } else { 'ipv4' }
	})
	return cx.Element{
		name:  'datagram'
		items: [
			cx.Element{
				name:  'bytes'
				items: [net_bytes(buf[..rd])]
			},
			cx.Element{
				name:  'from'
				items: [from]
			},
		]
	}
}

// net_udp_send_to sends one datagram to $to (§3.5) — a §4.5-gated effect point:
// the target runs the SSRF guard (deny-set + override) before the write.
fn net_udp_send_to(mut h NetHandle, data []u8, to cx.Node) cx.Node {
	if h.udp == unsafe { nil } {
		return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: send-to needs a datagram socket')
	}
	thost, tport := net_target_host_port(to) or {
		return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: send-to $to must be an [addr] or host:port')
	}
	pinned, derr := net_ssrf_check(thost, tport)
	if e := derr {
		return e
	}
	addrs := net.resolve_addrs(net_join_host_port(pinned, tport), .unspec, .udp) or {
		return mk_err(code.net_err_resolve_nxdomain, 'E_NET_RESOLVE_NXDOMAIN: ${thost}: ${err.msg()}')
	}
	if addrs.len == 0 {
		return mk_err(code.net_err_resolve_nxdomain, 'E_NET_RESOLVE_NXDOMAIN: ${thost}')
	}
	n := h.udp.write_to(addrs[0], data) or {
		return mk_err(code.net_err_reset, 'E_NET: udp send-to: ${err.msg()}')
	}
	return net_int(n)
}

// net_dial_unix_real connects a Unix-domain stream socket (§3.2). Local +
// filesystem-permission-gated, so NOT subject to the §4.5 SSRF guard.
fn net_dial_unix_real(path string) cx.Node {
	conn := unix.connect_stream(path) or {
		return mk_err(code.net_err_unreachable, 'E_NET: dial-unix ${path}: ${err.msg()}')
	}
	mut h := &NetHandle{
		kind:      'socket'
		transport: 'unix'
		state:     'open'
		is_open:   true
		unix_conn: conn
	}
	id := net_register(h)
	return net_socket_element(id, h)
}

// net_listen_unix_real binds a Unix-domain stream listener (§3.3).
fn net_listen_unix_real(path string) cx.Node {
	listener := unix.listen_stream(path, unix.ListenOptions{}) or {
		return mk_err(code.net_err_addr_in_use, 'E_NET_ADDR_IN_USE: listen-unix ${path}: ${err.msg()}')
	}
	mut h := &NetHandle{
		kind:          'listener'
		transport:     'unix'
		state:         'listening'
		is_open:       true
		unix_listener: listener
	}
	id := net_register(h)
	return net_socket_element(id, h)
}


// net_rotate_listener_tls installs a new server identity (PEM CONTENT — the
// store daemon's in-memory posture, #180/#199: an ${env:VAR}-injected key never
// touches disk) on a live TLS listener (§2.6 config reload). New handshakes
// present the new certificate; established sessions keep the identity they
// negotiated (the mbedtls layer retains superseded generations until listener
// shutdown). Fails without touching the running identity.
fn net_rotate_listener_tls(id int, cert_pem string, key_pem string, ca_pem string) ! {
	mut h := net_lookup(id) or { return error('no listener handle ${id}') }
	if h.ssl_listener == unsafe { nil } {
		return error('handle ${id} is not a TLS listener')
	}
	h.ssl_listener.rotate_certs(mbedtls.SSLConnectConfig{
		cert:                   cert_pem
		cert_key:               key_pem
		validate:               ca_pem != ''
		verify:                 ca_pem
		in_memory_verification: true
	}) or { return error('rotate listener ${id}: ${err.msg()}') }
}




// net_dial_dtls_real performs a real DTLS client handshake (mbedTLS) over a
// connected UDP socket (§3.6a) to the §4.5-PINNED IP, SNI/verifying against the
// original hostname. The handshake is reliable (retransmission timer); the
// resulting socket is a secured datagram socket using the §3.5 send/recv verbs.
fn net_dial_dtls_real(pinned string, host string, port int, opts cx.Node, a NetAddr) cx.Node {
	verify := net_opts_tls_verify(opts)
	ca := net_opts_tls_str(opts, 'ca')
	cfg := mbedtls.SSLConnectConfig{
		validate:               verify
		in_memory_verification: ca != ''
		verify:                 ca
	}
	mut dtls := mbedtls.new_dtls_client(cfg) or {
		return mk_err(code.net_err_tls_handshake, 'E_NET_TLS_HANDSHAKE_FAILED: dtls init: ${err.msg()}')
	}
	dtls.dial(pinned, port) or {
		dtls.close() or {}
		return mk_err(code.net_err_tls_handshake, 'E_NET_TLS_HANDSHAKE_FAILED: dtls ${host}:${port}: ${err.msg()}')
	}
	mut h := &NetHandle{
		kind:      'socket'
		transport: 'dtls'
		state:     'open'
		is_open:   true
		local:     [a]
		secure:    true
		dtls:      dtls
	}
	id := net_register(h)
	return net_socket_element(id, h)
}

// net_listen_dtls_real binds a real DTLS listener (§3.3/§3.6a) via mbedTLS over a
// UDP socket. The server identity (cert/key) comes from opts.tls; accept() does
// the MANDATORY HelloVerifyRequest cookie exchange + the per-peer handshake.
fn net_listen_dtls_real(a NetAddr, opts cx.Node) cx.Node {
	cert := net_opts_tls_str(opts, 'cert')
	key := net_opts_tls_str(opts, 'key')
	if cert == '' || key == '' {
		return mk_err(code.net_err_tls_config, 'E_NET_TLS_CONFIG: listen-dtls requires opts.tls.cert + opts.tls.key')
	}
	ca := net_opts_tls_str(opts, 'ca')
	cfg := mbedtls.SSLConnectConfig{
		cert:     cert
		cert_key: key
		validate: ca != '' // require a client cert only under mTLS (a configured ca)
		verify:   ca
	}
	saddr := '${a.host}:${a.port}'
	listener := mbedtls.new_dtls_listener(saddr, cfg) or {
		return mk_err(code.net_err_tls_config, 'E_NET_TLS_CONFIG: listen-dtls ${saddr}: ${err.msg()}')
	}
	mut h := &NetHandle{
		kind:          'listener'
		transport:     'dtls'
		state:         'listening'
		is_open:       true
		secure:        true
		local:         [a]
		dtls_listener: listener
	}
	id := net_register(h)
	return net_socket_element(id, h)
}


// net_is_none_atom reports whether a value is the `:none` atom (set-deadline's
// "clear the deadline" sentinel, net.md §3.7).
fn net_is_none_atom(v cx.Node) bool {
	if v is cx.ScalarNode {
		return v.data_type == cx.ScalarType.atom_type && v.value is string
			&& (v.value as string) == 'none'
	}
	return false
}

// net_read_line_real buffers from the conn until LF; strips a trailing CRLF/LF
// (§3.4). At EOF it returns the remaining buffered bytes as the final line. If a
// configured read deadline lapses before a complete line, it raises CXER4507
// (#56) — the handle stays usable, so a retry can read more.
fn net_read_line_real(mut h NetHandle) cx.Node {
	if !net_h_connected(h) {
		return mk_err(code.net_err_handle_closed, 'E_NET_HANDLE_CLOSED: not a connected stream socket')
	}
	net_arm_read_deadline(mut h)
	for {
		for i in 0 .. h.rbuf.len {
			if h.rbuf[i] == `\n` {
				line := h.rbuf[..i].clone()
				h.rbuf = h.rbuf[i + 1..].clone()
				mut s := line.bytestr()
				if s.ends_with('\r') {
					s = s#[..-1]
				}
				return net_str(s)
			}
		}
		if h.eof {
			s := h.rbuf.bytestr()
			h.rbuf = []u8{}
			return net_str(s)
		}
		mut tmp := []u8{len: 4096}
		kind, n := net_h_read_step(mut h, mut tmp)
		if kind == .timeout {
			return mk_err(code.net_err_timeout, 'E_NET_TIMEOUT: read-line exceeded the ${h.read_deadline_ms}ms read deadline')
		}
		if kind == .eof {
			h.eof = true
			continue
		}
		h.rbuf << tmp[..n]
	}
	return net_str('')
}

// net_read_all_real drains the stream to EOF (bounded by max-bytes per §3.4 —
// the default cap is applied by the caller's opts; this build uses 64 MiB). If a
// configured read deadline lapses before EOF, it raises CXER4507 (#56) rather
// than blocking forever (the stream never closes) or silently returning a
// partial result that looks complete — the handle stays usable.
fn net_read_all_real(mut h NetHandle) cx.Node {
	if !net_h_connected(h) {
		return mk_err(code.net_err_handle_closed, 'E_NET_HANDLE_CLOSED: not a connected stream socket')
	}
	net_arm_read_deadline(mut h)
	max_bytes := 64 * 1024 * 1024
	for !h.eof {
		mut tmp := []u8{len: 4096}
		kind, n := net_h_read_step(mut h, mut tmp)
		if kind == .timeout {
			return mk_err(code.net_err_timeout, 'E_NET_TIMEOUT: read-all exceeded the ${h.read_deadline_ms}ms read deadline')
		}
		if kind == .eof {
			h.eof = true
			break
		}
		h.rbuf << tmp[..n]
		if h.rbuf.len > max_bytes {
			return mk_err('cx-err:CXER4510', 'E_NET_LIMIT_EXCEEDED: read-all over ${max_bytes} bytes')
		}
	}
	s := h.rbuf.bytestr()
	h.rbuf = []u8{}
	return net_str(s)
}

// net_read_bytes_real reads up to n bytes (may be short, §4.3 surfaces the
// actual count — never silently padded). `raise_on_deadline` distinguishes the
// two callers: read-all-bytes (true) drains toward `n`=64 MiB and raises
// CXER4507 if a configured deadline lapses first (the unbounded form, #56);
// read-bytes (false) returns the bytes read so far on a deadline lapse — a short
// read, which is the documented bounded-read contract, not a hang.
fn net_read_bytes_real(mut h NetHandle, n int, raise_on_deadline bool) cx.Node {
	if !net_h_connected(h) {
		return mk_err(code.net_err_handle_closed, 'E_NET_HANDLE_CLOSED: not a connected stream socket')
	}
	net_arm_read_deadline(mut h)
	// serve from buffer first, then the socket
	for h.rbuf.len < n && !h.eof {
		mut tmp := []u8{len: 4096}
		kind, rd := net_h_read_step(mut h, mut tmp)
		if kind == .timeout {
			if raise_on_deadline {
				return mk_err(code.net_err_timeout, 'E_NET_TIMEOUT: read-all-bytes exceeded the ${h.read_deadline_ms}ms read deadline')
			}
			break // bounded read: return what we have so far (short read)
		}
		if kind == .eof {
			h.eof = true
			break
		}
		h.rbuf << tmp[..rd]
	}
	take := if n < h.rbuf.len { n } else { h.rbuf.len }
	out := h.rbuf[..take].clone()
	h.rbuf = h.rbuf[take..].clone()
	return net_bytes(out)
}

// net_apply_sock_opt applies ONE §3.7 socket option to a handle, or
// returns the [err …] refusing it (#548 — apply or refuse, never a
// phantom). Returns none when the option applied cleanly.
//
// Honest availability map for this build (V net API + macOS):
//   line-terminator  stream framing (stored on the handle; write-line)
//   nodelay          TCP_NODELAY is set at socket creation by the V net
//                    layer and has no public toggle — `true` is verified
//                    satisfied; `false` refuses
//   keepalive        SO_KEEPALIVE enable/disable (bool, or duration>0 =
//                    on); the probe INTERVAL is not tunable in this build
//   recv-buf/send-buf SO_RCVBUF/SO_SNDBUF (stream sockets)
//   broadcast        SO_BROADCAST (datagram sockets)
//   linger, multicast-* refuse (no usable V net surface)
fn net_apply_sock_opt(mut h NetHandle, key string, v cx.Node) ?cx.Node {
	is_stream := h.kind == 'socket' && h.transport !in ['udp', 'dtls', 'unixgram']
	match key {
		'line-terminator' {
			val := net_arg_str(v) or { '' }
			if val !in ['auto', 'lf', 'crlf'] {
				return mk_err(code.net_err_arg_invalid,
					'E_NET_ARG_INVALID: line-terminator must be "auto", "lf", or "crlf"')
			}
			if !is_stream {
				return mk_err(code.net_err_arg_invalid,
					'E_NET_ARG_INVALID: line-terminator is a stream-socket option (§3.7)')
			}
			h.line_term = val
			return none
		}
		'nodelay' {
			want := net_arg_bool_val(v) or {
				return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: nodelay takes a bool')
			}
			if !is_stream || h.conn == unsafe { nil } {
				return mk_err(code.net_err_arg_invalid,
					'E_NET_ARG_INVALID: nodelay is a TCP option (§3.7)')
			}
			if want {
				return none // TCP_NODELAY is enabled at socket creation (V net layer)
			}
			return mk_err(code.net_err_arg_invalid,
				'E_NET_ARG_INVALID: nodelay=false cannot be applied — TCP_NODELAY is fixed on at socket creation in this build')
		}
		'keepalive' {
			if !is_stream || h.conn == unsafe { nil } {
				return mk_err(code.net_err_arg_invalid,
					'E_NET_ARG_INVALID: keepalive is a TCP option (§3.7)')
			}
			mut on := false
			if b := net_arg_bool_val(v) {
				on = b
			} else if ms := net_node_ms(v) {
				on = ms > 0
			} else {
				return mk_err(code.net_err_arg_invalid,
					'E_NET_ARG_INVALID: keepalive takes a duration (>0 = on) or a bool')
			}
			h.conn.sock.set_option_bool(.keep_alive, on) or {
				return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: keepalive: ${err.msg()}')
			}
			return none
		}
		'recv-buf', 'send-buf' {
			n := net_node_ms(v) or {
				return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: ${key} takes a byte count')
			}
			if !is_stream || h.conn == unsafe { nil } {
				return mk_err(code.net_err_arg_invalid,
					'E_NET_ARG_INVALID: ${key} is not settable on this transport in this build (stream sockets only)')
			}
			opt := if key == 'recv-buf' {
				net.SocketOption.receive_buf_size
			} else {
				net.SocketOption.send_buf_size
			}
			h.conn.sock.set_option_int(opt, int(n)) or {
				return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: ${key}: ${err.msg()}')
			}
			return none
		}
		'broadcast' {
			want := net_arg_bool_val(v) or {
				return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: broadcast takes a bool')
			}
			if h.transport != 'udp' || h.udp == unsafe { nil } {
				return mk_err(code.net_err_arg_invalid,
					'E_NET_ARG_INVALID: broadcast is a UDP option (§3.7)')
			}
			h.udp.sock.set_option_bool(.broadcast, want) or {
				return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: broadcast: ${err.msg()}')
			}
			return none
		}
		'linger' {
			return mk_err(code.net_err_arg_invalid,
				'E_NET_ARG_INVALID: linger is not settable in this build (SO_LINGER needs the struct form the V net API does not expose)')
		}
		else {
			if key.starts_with('multicast-') {
				return mk_err(code.net_err_arg_invalid,
					'E_NET_ARG_INVALID: ${key} is not settable in this build (no multicast surface in the V net API)')
			}
			return mk_err(code.net_err_arg_invalid,
				'E_NET_ARG_INVALID: unknown socket option "${key}" (§3.7)')
		}
	}
}

// net_arg_bool_val extracts a bool scalar.
fn net_arg_bool_val(v cx.Node) ?bool {
	if v is cx.ScalarNode {
		val := v.value
		if val is bool {
			return val
		}
	}
	return none
}

// net_write_real writes a string/bytes payload; write-line appends the
// socket's line-terminator (§3.4 — 'auto'/'lf' → LF, 'crlf' → CRLF).
fn net_write_real(mut h NetHandle, name string, args []cx.Node) cx.Node {
	if !net_h_connected(h) {
		return mk_err(code.net_err_handle_closed, 'E_NET_HANDLE_CLOSED: not a connected stream socket')
	}
	if name == 'net-flush' {
		return net_null()
	}
	mut payload := []u8{}
	if name == 'net-write-bytes' {
		payload = net_arg_bytes(args[1]) or {
			return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: write-bytes expects bytes')
		}
	} else {
		s := net_arg_str(args[1]) or {
			return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: ${name} expects a string')
		}
		payload = s.bytes()
		if name == 'net-write-line' {
			if h.line_term == 'crlf' {
				payload << `\r`
			}
			payload << `\n`
		}
	}
	net_h_write(mut h, payload) or {
		return mk_err(code.net_err_reset, 'E_NET_RESET: write failed: ${err.msg()}')
	}
	return net_null()
}

fn net_listen_impl(name string, args []cx.Node) cx.Node {
	url := net_arg_str(args[0]) or { return mk_err(code.net_err_arg_invalid, 'E_NET_ARG_INVALID: listen expects a URL string') }
	a := parse_transport_url(url, true) or {
		return mk_err(err.msg(), 'E_NET: listen ${url}')
	}
	want := net_alias_scheme(name)
	if want != '' && a.scheme != want {
		return mk_err(code.net_err_scheme_unsupported, 'E_NET_SCHEME_UNSUPPORTED: ${name} rejects scheme ${a.scheme}')
	}
	if a.scheme == 'tcp' {
		return net_listen_tcp_real(a)
	}
	if a.scheme == 'tls' {
		opts := if args.len > 1 { args[1] } else { cx.Node(cx.Element{ name: '__cx_map__' }) }
		return net_listen_tls_real(a, opts)
	}
	if a.scheme == 'udp' {
		return net_listen_udp_real(a)
	}
	if a.scheme == 'dtls' {
		opts := if args.len > 1 { args[1] } else { cx.Node(cx.Element{ name: '__cx_map__' }) }
		return net_listen_dtls_real(a, opts)
	}
	// Unix-stream listen handled separately (net-listen-unix); error honestly.
	return mk_err(code.net_err_scheme_unsupported, 'E_NET: ${a.scheme} listen not yet implemented (TCP + TLS + UDP + DTLS)')
}

// net_alias_scheme returns the transport a pinned alias requires (§2.3),
// or '' for the cross-scheme dispatchers (dial / listen).
fn net_alias_scheme(name string) string {
	return match name {
		'net-dial-tcp', 'net-listen-tcp' { 'tcp' }
		'net-dial-tls', 'net-listen-tls' { 'tls' }
		'net-dial-udp', 'net-listen-udp' { 'udp' }
		'net-dial-dtls', 'net-listen-dtls' { 'dtls' }
		else { '' }
	}
}

fn net_open_socket(transport string, local []NetAddr, secure bool) cx.Node {
	h := &NetHandle{
		kind:      'socket'
		transport: transport
		state:     'open'
		is_open:   true
		local:     local
		secure:    secure
	}
	id := net_register(h)
	return net_socket_element(id, h)
}

fn net_open_listener(transport string, local []NetAddr) cx.Node {
	h := &NetHandle{
		kind:      'listener'
		transport: transport
		state:     'listening'
		is_open:   true
		local:     local
	}
	id := net_register(h)
	return net_socket_element(id, h)
}


// net_resolve_impl performs a real getaddrinfo (§3.1). Returns a sequence of
// [addr] elements (one per resolved IP); a no-record host → CXER4502.
// `family_opt` (opts.family) narrows to ipv4/ipv6, else both.
fn net_resolve_impl(host string, family_opt string) cx.Node {
	if host == '' {
		return mk_err(code.net_err_resolve_nxdomain, 'E_NET_RESOLVE_NXDOMAIN: resolve empty host')
	}
	fam := match family_opt {
		'ipv4', 'ip', 'inet' { net.AddrFamily.ip }
		'ipv6', 'ip6', 'inet6' { net.AddrFamily.ip6 }
		else { net.AddrFamily.unspec }
	}
	addrs := net.resolve_addrs('${host}:0', fam, .tcp) or {
		return mk_err(code.net_err_resolve_nxdomain, 'E_NET_RESOLVE_NXDOMAIN: resolve ${host}: ${err.msg()}')
	}
	mut out := []cx.Node{}
	for ad in addrs {
		ip := net_strip_port(ad.str())
		f := if ip.contains(':') { 'ipv6' } else { 'ipv4' }
		out << net_addr_element(NetAddr{
			host:   ip
			port:   -1
			family: f
		})
	}
	if out.len == 0 {
		return mk_err(code.net_err_resolve_nxdomain, 'E_NET_RESOLVE_NXDOMAIN: no records for ${host}')
	}
	return net_seq(out)
}


// net_map_get_str reads a string value for a key in a `{k: v}` (__cx_map__) literal.
fn net_map_get_str(m cx.Node, key string) string {
	if v := net_map_get(m, key) {
		if v is cx.ScalarNode {
			sv := v.value
			if sv is string {
				return sv
			}
		}
	}
	return ''
}

// Handle-op shims (reached only behind the grant): resolve the handle then
// return the typed result. The conformance harness guards these out.
fn net_handle_op_socket(arg cx.Node) cx.Node {
	return arg
}

fn net_handle_op_bytes(arg cx.Node) cx.Node {
	return net_str('')
}

fn net_handle_op_str(arg cx.Node) cx.Node {
	return net_str('')
}

fn net_handle_op_null(arg cx.Node) cx.Node {
	return net_null()
}

fn net_handle_op_bool(arg cx.Node) cx.Node {
	return net_bool(false)
}

fn net_handle_op_int(arg cx.Node) cx.Node {
	return net_int(0)
}

fn net_handle_op_seq(arg cx.Node) cx.Node {
	return net_seq([])
}
