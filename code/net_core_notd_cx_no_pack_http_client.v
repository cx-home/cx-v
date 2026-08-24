@[has_globals]
module code

import cx
import net
import net.unix
import net.mbedtls
import time

// net_core.v — the Ring-1 NET TRANSPORT CORE (#651/#516 I3, seam H).
//
// Split out of stdlib_net.v so the Ring-1 http CLIENT pack (§4 cli
// profile) can reach the network without importing the Ring-2 net
// pack: the socket/listener handle registry, the §4.5 SSRF /
// DNS-rebinding guard, the client-side dial primitives (tcp/tls),
// the buffered stream reads the SSE client frames off a held-open
// connection, and the shared close path. The net VERB surface
// ([$net:…], all ring=2) plus listen/accept and the datagram/unix
// transports stay in stdlib_net.v (Ring 2, cx_partition.md §2
// "http/net serve") — Ring 2 calls down into this core (§3: Ring 2
// MAY import Rings 0–1), never the other way up.
//
// Everything here moved VERBATIM from stdlib_net.v at the seam-H
// split; behavior is identical by construction.

// ── error codes (§8) — net owns CXER4500–CXER4524 ────────────────────
pub const net_err_addr_invalid = 'cx-err:CXER4500' // E_NET_ADDR_INVALID
pub const net_err_scheme_unsupported = 'cx-err:CXER4501' // E_NET_SCHEME_UNSUPPORTED
pub const net_err_resolve_nxdomain = 'cx-err:CXER4502' // E_NET_RESOLVE_NXDOMAIN
const net_err_connect_refused = 'cx-err:CXER4505' // E_NET_CONNECT_REFUSED
pub const net_err_unreachable = 'cx-err:CXER4506' // E_NET_UNREACHABLE
pub const net_err_timeout = 'cx-err:CXER4507' // E_NET_TIMEOUT (socket deadline lapsed)
pub const net_err_reset = 'cx-err:CXER4508' // E_NET_RESET
pub const net_err_tls_handshake = 'cx-err:CXER4512' // E_NET_TLS_HANDSHAKE_FAILED
pub const net_err_tls_config = 'cx-err:CXER4514' // E_NET_TLS_CONFIG
const net_err_forbidden = 'cx-err:CXER4504' // E_NET_FORBIDDEN_ADDRESS
pub const net_err_handle_closed = 'cx-err:CXER4515' // E_NET_HANDLE_CLOSED
pub const net_err_addr_in_use = 'cx-err:CXER4517' // E_NET_ADDR_IN_USE
pub const net_err_arg_invalid = 'cx-err:CXER4522' // E_NET_ARG_INVALID

// ── socket/listener handle registry (§2.1) ──────────────────────────
@[heap]
pub struct NetHandle {
pub mut:
	kind      string // 'socket' | 'listener'
	transport string // tcp | tls | udp | dtls | unix | unixgram
	state     string
	is_open   bool
	local     []NetAddr
	remote    ?NetAddr
	secure    bool
	// real V-net resources (TCP stream core). nil until a live dial/listen
	// wires them; there is no fake-success placeholder — an unimplemented
	// transport returns an explicit error, never a fake handle (no-stub rule).
	conn         &net.TcpConn         = unsafe { nil }
	listener     &net.TcpListener     = unsafe { nil }
	ssl          &mbedtls.SSLConn     = unsafe { nil } // TLS socket (dial-tls / accepted tls conn); read/write route here when set
	ssl_listener &mbedtls.SSLListener = unsafe { nil } // TLS listener (listen-tls); accept() pulls SSLConns
	udp          &net.UdpConn         = unsafe { nil } // datagram socket (dial-udp / listen-udp); send/recv route here
	dtls          &mbedtls.DTLSConn     = unsafe { nil } // secured datagram socket (dial-dtls / accepted dtls peer); send/recv route here (§3.6a)
	dtls_listener &mbedtls.DTLSListener = unsafe { nil } // DTLS listener (listen-dtls); accept() does the cookie + per-peer handshake
	unix_conn     &unix.StreamConn     = unsafe { nil } // Unix-domain stream socket (dial-unix / accepted)
	unix_listener &unix.StreamListener = unsafe { nil } // Unix-domain listener (listen-unix)
	rbuf         []u8 // buffered bytes for read-line / read-all framing
	eof          bool // peer half-closed (read side at EOF)
	// §3.7 read deadline (#56). >0 = a configured per-read-operation budget in
	// ms, applied to the TCP conn as an absolute deadline armed at the start of
	// each read op (net_arm_read_deadline); 0 = none (block per transport
	// default). Set from dial opts `{read-deadline}` and/or set-deadline. A
	// lapse surfaces CXER4507 on the read-until-EOF forms (read-all / read-line /
	// line-iter); the bounded read-bytes / read-exact return a short read.
	read_deadline_ms i64
	timed_out        bool // transient: the last read-until-EOF pull lapsed the deadline (line-iter signal)
	// §3.4/§3.7 line-terminator (rev-4 H4 — a REAL option, not a phantom):
	// what write-line appends. 'auto'/'lf' → LF; 'crlf' → CRLF (the framing
	// the text protocols — NATS, SMTP, HTTP — require). read-line strips
	// either regardless. Stream-only; set via set-opt {line-terminator}.
	line_term string = 'auto'
	consumed     bool // single-use stream walked once (http SSE sse-events → CXER0105 on a second walk)
	is_sse_stream bool // this connection backs a server-side http SSE stream (counts against http_open_sse_streams)
}

@[heap]
struct NetRegistry {
mut:
	handles map[int]&NetHandle
	next_id int
}

__global (
	g_net_reg voidptr
)

fn net_reg() &NetRegistry {
	if g_net_reg == unsafe { nil } {
		r := &NetRegistry{
			handles: map[int]&NetHandle{}
		}
		g_net_reg = voidptr(r)
	}
	return unsafe { &NetRegistry(g_net_reg) }
}

// ── §4.5 SSRF / DNS-rebinding core (pure) ───────────────────────────
// The canonicalize + deny-set classifier the dial/send-to guard composes
// (net.md §4.5). Pure + total: classify any textual IP. The override (literal-IP
// / localhost grant bypass) and candidate pinning live in the gated dial path.

// net_canonicalize_ip normalizes a resolved candidate before classification:
// strips zone ids (%en0) + brackets, and unwraps IPv4-mapped/compatible IPv6
// (::ffff:a.b.c.d / ::a.b.c.d) to the embedded IPv4 — so ::ffff:169.254.169.254
// classifies as 169.254.169.254 (rev-4 M8).
pub fn net_canonicalize_ip(raw string) string {
	mut s := raw.trim_space()
	if z := s.index('%') {
		s = s[..z]
	}
	s = s.trim('[]')
	low := s.to_lower()
	if low.starts_with('::ffff:') {
		tail := s[7..]
		if tail.contains('.') {
			return tail
		}
	}
	if low.starts_with('::') && s.len > 2 && s[2..].contains('.') {
		return s[2..]
	}
	return s
}

// net_ipv4_in_deny classifies an IPv4 literal against the mandatory deny set
// (loopback/link-local/private/CGNAT/this-host, §4.5).
fn net_ipv4_in_deny(ip string) bool {
	parts := ip.split('.')
	if parts.len != 4 {
		return false
	}
	a := parts[0].int()
	b := parts[1].int()
	return match true {
		a == 0 { true } // 0.0.0.0/8 this-host
		a == 127 { true } // loopback 127.0.0.0/8
		a == 10 { true } // private 10.0.0.0/8
		a == 172 && b >= 16 && b <= 31 { true } // private 172.16.0.0/12
		a == 192 && b == 168 { true } // private 192.168.0.0/16
		a == 169 && b == 254 { true } // link-local 169.254.0.0/16 (incl. metadata)
		a == 100 && b >= 64 && b <= 127 { true } // CGNAT 100.64.0.0/10
		else { false }
	}
}

// net_ip_in_deny_set reports whether a (canonicalized) IP is in the mandatory
// §4.5 deny set — loopback, link-local, private, CGNAT, ULA, this-host.
pub fn net_ip_in_deny_set(raw string) bool {
	ip := net_canonicalize_ip(raw)
	if ip.contains('.') && !ip.contains(':') {
		return net_ipv4_in_deny(ip)
	}
	low := ip.to_lower()
	if low == '::1' || low == '::' {
		return true // loopback / this-host
	}
	// link-local fe80::/10 → fe80..febf
	if low.starts_with('fe8') || low.starts_with('fe9') || low.starts_with('fea')
		|| low.starts_with('feb') {
		return true
	}
	// ULA fc00::/7 → fc.. / fd..
	if low.starts_with('fc') || low.starts_with('fd') {
		return true
	}
	return false
}

pub fn net_register(h &NetHandle) int {
	mut reg := net_reg()
	reg.next_id++
	id := reg.next_id
	reg.handles[id] = h
	return id
}

pub fn net_lookup(id int) ?&NetHandle {
	reg := net_reg()
	return reg.handles[id] or { return none }
}

// net_set_read_deadline_id arms a per-read-operation deadline (ms) on the handle
// identified by `id` (the daemon's per-connection read timeout, #187). Each
// subsequent read op applies it via net_arm_read_deadline, so a client that
// trickles or stalls a body cannot hold a worker indefinitely. 0 clears it.
pub fn net_set_read_deadline_id(id int, ms i64) {
	mut h := net_lookup(id) or { return }
	h.read_deadline_ms = if ms > 0 { ms } else { 0 }
}

// ── address model (§2.2) ────────────────────────────────────────────
pub struct NetAddr {
pub mut:
	host   string // host / IP literal (empty for unix)
	port   int    // -1 when absent (unix)
	family string // ipv4 | ipv6 | unix
	zone   string // IPv6 zone id (e.g. en0), or ''
	path   string // unix / unix-abstract path (else '')
	scheme string // tcp | tls | udp | dtls | unix | unix-abstract | ''
}

// net_handle_id reads the integer handle id off a [socket …]/[listener …]
// element's `fd` (or `handle`) attribute.
pub fn net_handle_id(n cx.Node) ?int {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'fd' || a.name == 'handle' {
				return int(cx.scalar_value_str_public(a.value).int())
			}
		}
	}
	return none
}

// net_pollable_fd_id resolves a REGISTRY HANDLE ID to the OS descriptor that
// poll(2) can wait on, or `none` when the handle owns no pollable descriptor
// (closed, or a transport with no socket behind it yet).
//
// WHY THIS EXISTS (#852). Every handle this module hands to CX carries its
// REGISTRY ID in `fd=` — `net_register` returns `next_id++`, not a descriptor.
// That is true of `[socket]`, `[exchange]`, `[http-server]` and
// `[sse-source]` alike; `http_server_handle_fd`'s own comment says "handle id
// `fd`". The one exception in the tree is `[std-stream fd=0|1|2]`, which is a
// real descriptor because it never went through this registry.
//
// So a caller that wants to POLL a handle cannot use the `fd=` value. #852
// was filed against `[sse-source]` because that is where a consumer noticed,
// but `term:select` was polling the id for every source kind — with the first
// two connections in any process landing on 1 and 2, which are stdout and
// stderr. Nothing errored; the arm simply never fired.
//
// Exposing the raw descriptor in `fd=` instead was the other option and is
// worse: it would put an OS descriptor the runtime owns into the CX surface,
// invite user code to operate on it behind the runtime's back, and leave the
// same attribute name meaning a descriptor on some handles and an id on
// others. Resolving here keeps the surface as it is and keeps the descriptor
// inside the runtime.
//
// TLS CAVEAT, stated because it is real and not fixable here: for a secured
// stream, socket-readable is not the same question as frame-available —
// mbedTLS can hold already-decrypted plaintext with nothing left on the
// socket. A poll on this descriptor can therefore miss a record that is
// already buffered. A select loop with a `timeout:` recovers on the next
// tick; an untimed one can wait behind a buffered frame. Refusing TLS sources
// outright would be worse (it takes https SSE from broken-silently to
// unsupported), so the descriptor is resolved and the limit is documented.
pub fn net_pollable_fd_id(id int) ?int {
	h := net_lookup(id) or { return none }
	if !h.is_open {
		return none
	}
	if h.conn != unsafe { nil } {
		return h.conn.sock.handle
	}
	if h.ssl != unsafe { nil } {
		return h.ssl.handle
	}
	if h.udp != unsafe { nil } {
		return h.udp.sock.handle
	}
	if h.dtls != unsafe { nil } {
		return h.dtls.handle
	}
	if h.unix_conn != unsafe { nil } {
		return h.unix_conn.sock.handle
	}
	if h.listener != unsafe { nil } {
		return h.listener.sock.handle
	}
	if h.unix_listener != unsafe { nil } {
		return h.unix_listener.sock.handle
	}
	return none
}

// ── real TCP stream core (V `net`) ───────────────────────────────────
// dial/read/write/close perform real syscalls and store the live V conn on
// the handle; the conformance is the real loopback round-trip (net.md §10).

// net_join_host_port formats host:port, bracketing an IPv6 literal.
pub fn net_join_host_port(host string, port int) string {
	if host.contains(':') {
		return '[${host}]:${port}'
	}
	return '${host}:${port}'
}

// net_is_ip_literal reports whether s is a literal IPv4/IPv6 (not a hostname).
fn net_is_ip_literal(s string) bool {
	if s.contains(':') {
		return true
	}
	parts := s.split('.')
	if parts.len != 4 {
		return false
	}
	for p in parts {
		if p == '' {
			return false
		}
		for ch in p {
			if ch < `0` || ch > `9` {
				return false
			}
		}
	}
	return true
}

// net_spec_split splits a grant spec into (host, port-or-empty): "host:port",
// "[v6]:port", or bare "host".
pub fn net_spec_split(spec string) (string, string) {
	s := spec
	if s.starts_with('[') {
		if close := s.index(']') {
			host := s[1..close]
			after := s[close + 1..]
			if after.starts_with(':') {
				return host, after[1..]
			}
			return host, ''
		}
	}
	if li := s.last_index(':') {
		tail := s[li + 1..]
		mut numeric := tail.len > 0
		for ch in tail {
			if ch < `0` || ch > `9` {
				numeric = false
				break
			}
		}
		if numeric {
			return s[..li], tail
		}
	}
	return s, ''
}

// net_spec_matches reports whether a grant spec admits host:port (exact host or
// *.suffix glob; a spec without a port matches any port).
fn net_spec_matches(spec string, host string, port int) bool {
	sh, sp := net_spec_split(spec)
	if sh != host {
		if sh.starts_with('*.') {
			if !host.ends_with(sh[1..]) {
				return false
			}
		} else if sh != '*' {
			return false
		}
	}
	if sp != '' && sp != port.str() {
		return false
	}
	return true
}

// net_override_allows reports whether a grant bypasses the §4.5 deny set for a
// candidate: a spec host that is a literal IP equal to the candidate, or
// `localhost` for a loopback candidate. A hostname grant never overrides (the
// DNS-rebinding defense).
fn net_override_allows(specs []string, cand string) bool {
	cand_loopback := cand == '::1' || cand.starts_with('127.')
	for spec in specs {
		sh, _ := net_spec_split(spec)
		if net_is_ip_literal(sh) && net_canonicalize_ip(sh) == cand {
			return true
		}
		if sh == 'localhost' && cand_loopback {
			return true
		}
	}
	return false
}

// net_ssrf_check runs the §4.5 guard for an outbound connect: resolve host →
// candidates, canonicalize, (1) capability host match, (2) deny-set + literal-IP/
// localhost override, then PIN the first admitted candidate (returned to dial).
// Denial → CXER0271 (no admitting grant) or CXER4504 (resolves only into denied
// ranges with no override). The pinned IP is what dial connects to (no re-resolve).
pub fn net_ssrf_check(host string, port int) (string, ?cx.Node) {
	specs := cap_net_specs()
	bare := cap_net_is_all()
	addrs := net.resolve_addrs(net_join_host_port(host, port), .unspec, .tcp) or {
		return '', mk_err(net_err_resolve_nxdomain, 'E_NET_RESOLVE_NXDOMAIN: resolve ${host}: ${err.msg()}')
	}
	mut saw_denied := false
	private_ok := cap_private_range_allowed()
	for ad in addrs {
		cand := net_canonicalize_ip(net_strip_port(ad.str()))
		if private_ok {
			// the L104 private-range-policy field (set only by the --allow-all
			// opt-out): it bypasses the §4.5 deny-set entirely, so outbound to
			// loopback / private ranges is permitted (#47 — "--allow-all" must
			// mean all). A merely unscoped bare --allow-net does NOT bypass it
			// (below): the deny-set is the secure default for any net grant
			// absent a literal-IP scope.
			return cand, none // pinned
		}
		if !bare {
			// scoped grant — step-1 host match (program host or resolved IP)
			mut ok := false
			for spec in specs {
				if net_spec_matches(spec, host, port) || net_spec_matches(spec, cand, port) {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		// §4.5 deny-set + literal-IP/localhost override. Applies to bare
		// --allow-net (no override spec → private/loopback denied) AND to
		// scoped grants (a public-host scope cannot be rebound to a private IP).
		if net_ip_in_deny_set(cand) {
			if !net_override_allows(specs, cand) {
				saw_denied = true
				continue
			}
		}
		return cand, none // pinned
	}
	if saw_denied {
		return '', mk_err(net_err_forbidden, 'E_NET_FORBIDDEN_ADDRESS: ${host}:${port} resolves into a denied range with no admitting literal-IP/localhost grant (§4.5)')
	}
	return '', cap_deny('net', '${host}:${port}')
}

pub fn net_dial_tcp_real(a NetAddr, opts cx.Node) cx.Node {
	addr := net_join_host_port(a.host, a.port)
	conn := net.dial_tcp(addr) or {
		msg := err.msg()
		ecode := if msg.contains('refused') {
			net_err_connect_refused
		} else {
			net_err_unreachable
		}
		return mk_err(ecode, 'E_NET: connect ${addr}: ${msg}')
	}
	// §3.2 dial opt `read-deadline` (#56): a per-read-operation budget (ms),
	// honored by read-line / read-all / line-iter. Stored on the handle and
	// armed per read; set-deadline can later update or clear it.
	rd_ms := net_map_get_ms(opts, 'read-deadline') or { i64(0) }
	mut h := &NetHandle{
		kind:             'socket'
		transport:        'tcp'
		state:            'open'
		is_open:          true
		local:            [a]
		conn:             conn
		read_deadline_ms: rd_ms
	}
	id := net_register(h)
	return net_socket_element(id, h)
}

// net_mut_handle resolves the registry handle for a [socket]/[listener] arg.
pub fn net_mut_handle(n cx.Node) ?&NetHandle {
	id := net_handle_id(n) or { return none }
	return net_lookup(id)
}

// net_close_id closes the handle bound to `id` (idempotent, §3.7). Shared by
// `net-close` and by cross-module closers (the http server closes a connection
// after writing the final response). Tears down whichever transport the handle
// carries and flips it to state="closed".
pub fn net_close_id(id int) {
	mut h := net_lookup(id) or { return }
	if h.is_sse_stream && h.is_open {
		// release this stream's slot against the §3.6 max-streams bound.
		h.is_sse_stream = false
		http_sse_stream_closed()
	}
	if h.ssl != unsafe { nil } {
		h.ssl.close() or {}
		h.ssl = unsafe { nil }
	}
	if h.conn != unsafe { nil } {
		h.conn.close() or {}
		h.conn = unsafe { nil }
	}
	if h.listener != unsafe { nil } {
		h.listener.close() or {}
		h.listener = unsafe { nil }
	}
	if h.ssl_listener != unsafe { nil } {
		h.ssl_listener.shutdown() or {}
		h.ssl_listener = unsafe { nil }
	}
	if h.udp != unsafe { nil } {
		h.udp.close() or {}
		h.udp = unsafe { nil }
	}
	if h.dtls != unsafe { nil } {
		h.dtls.close() or {}
		h.dtls = unsafe { nil }
	}
	if h.dtls_listener != unsafe { nil } {
		h.dtls_listener.shutdown() or {}
		h.dtls_listener = unsafe { nil }
	}
	if h.unix_conn != unsafe { nil } {
		h.unix_conn.close() or {}
		h.unix_conn = unsafe { nil }
	}
	if h.unix_listener != unsafe { nil } {
		h.unix_listener.close() or {}
		h.unix_listener = unsafe { nil }
	}
	h.is_open = false
	h.state = 'closed'
}

// net_read_line_buf reads one CRLF/LF-terminated line off the handle's buffered
// stream, returning the line WITHOUT the terminator. Returns none either at a
// clean EOF (no buffered bytes left) OR when a configured read deadline lapsed
// before a full line — the two are distinguished by `h.timed_out`, which the
// line-iter walk reads to raise CXER4507 (#56). Shared by the http server's
// request-line/header reader (no deadline → never flags timed_out).
pub fn net_read_line_buf(mut h NetHandle) ?string {
	h.timed_out = false
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
				return s
			}
		}
		if h.eof {
			if h.rbuf.len == 0 {
				return none
			}
			s := h.rbuf.bytestr()
			h.rbuf = []u8{}
			return s
		}
		mut tmp := []u8{len: 4096}
		kind, n := net_h_read_step(mut h, mut tmp)
		if kind == .timeout {
			// Deadline lapsed before a full line — flag it (the caller surfaces
			// CXER4507) and stop. Buffered bytes, if any, remain for a later read;
			// the connection is NOT marked eof (the peer hasn't closed).
			h.timed_out = true
			return none
		}
		if kind == .eof {
			h.eof = true
			continue
		}
		h.rbuf << tmp[..n]
	}
	return none
}

// net_read_exact_buf reads exactly `n` bytes (or fewer at EOF) off the buffered
// stream. Shared by the http server's Content-Length body read.
pub fn net_read_exact_buf(mut h NetHandle, n int) []u8 {
	for h.rbuf.len < n && !h.eof {
		mut tmp := []u8{len: 4096}
		rd := net_h_read(mut h, mut tmp) or {
			h.eof = true
			break
		}
		if rd <= 0 {
			h.eof = true
			break
		}
		h.rbuf << tmp[..rd]
	}
	take := if n < h.rbuf.len { n } else { h.rbuf.len }
	out := h.rbuf[..take].clone()
	h.rbuf = h.rbuf[take..].clone()
	return out
}

// net_h_read / net_h_write route I/O through the TLS layer when the handle is
// secure (dial-tls / tls-wrap), else the plain TCP conn — so the §3.4 stream
// verbs work identically over tls:// and tcp:// (one code path, two transports).
fn net_h_read(mut h NetHandle, mut buf []u8) !int {
	if h.ssl != unsafe { nil } {
		return h.ssl.read(mut buf)!
	}
	if h.unix_conn != unsafe { nil } {
		return h.unix_conn.read(mut buf)!
	}
	if h.conn != unsafe { nil } {
		return h.conn.read(mut buf)!
	}
	return error('no connection')
}

// net_err_is_timeout reports whether a transport read error is a socket
// read-deadline lapse (V's net.err_timed_out, code errors_base+9) rather than
// a clean EOF / reset. Used to distinguish CXER4507 from EOF in the read loops.
pub fn net_err_is_timeout(e IError) bool {
	if e.code() == net.err_timed_out_code {
		return true
	}
	return e.msg().contains('timed out')
}

// net_arm_read_deadline applies the handle's configured read deadline (#56) to
// the underlying conn as an ABSOLUTE deadline for the read operation about to
// run: `set_read_timeout(0)` makes V's wait_for_read honor the absolute
// `read_deadline`, which we set to now + read_deadline_ms. Called at the start
// of each read primitive so every operation gets a fresh budget. A no-op when
// no deadline is configured (the conn keeps its transport default). Covers TCP
// streams AND datagram sockets (net.md §3.7 marks set-deadline ✅ for udp; the
// udp half was a spec-compliance gap until the marine NMEA-ingest work needed
// it — a silent gateway must surface CXER4507, not block recv forever). TLS
// deadline support remains a separate sub-layer (mbedTLS owns that read path).
pub fn net_arm_read_deadline(mut h NetHandle) {
	if h.read_deadline_ms <= 0 {
		return
	}
	if h.conn != unsafe { nil } {
		h.conn.set_read_timeout(0)
		h.conn.set_read_deadline(time.now().add(h.read_deadline_ms * time.millisecond))
		return
	}
	if h.udp != unsafe { nil } {
		h.udp.set_read_timeout(0)
		h.udp.set_read_deadline(time.now().add(h.read_deadline_ms * time.millisecond))
	}
}

// NetReadKind classifies a single transport read (net_h_read_step).
pub enum NetReadKind {
	data    // n > 0 bytes read
	eof     // clean EOF / peer half-close (or a non-timeout read error)
	timeout // armed read deadline lapsed (only when read_deadline_ms > 0)
}

// net_h_read_step performs one transport read into `tmp` and classifies the
// outcome. A read-deadline lapse is reported as `.timeout` ONLY when the handle
// carries a configured deadline (read_deadline_ms > 0) — otherwise every error
// (including the transport's own default timeout) maps to `.eof`, preserving
// the prior behavior for deadline-free reads and the http server's shared use
// of net_read_line_buf.
pub fn net_h_read_step(mut h NetHandle, mut tmp []u8) (NetReadKind, int) {
	n := net_h_read(mut h, mut tmp) or {
		if h.read_deadline_ms > 0 && net_err_is_timeout(err) {
			return NetReadKind.timeout, 0
		}
		return NetReadKind.eof, 0
	}
	if n <= 0 {
		return NetReadKind.eof, 0
	}
	return NetReadKind.data, n
}

pub fn net_h_write(mut h NetHandle, data []u8) !int {
	if h.ssl != unsafe { nil } {
		return h.ssl.write(data)!
	}
	if h.unix_conn != unsafe { nil } {
		return h.unix_conn.write(data)!
	}
	if h.conn != unsafe { nil } {
		return h.conn.write(data)!
	}
	return error('no connection')
}

pub fn net_h_connected(h &NetHandle) bool {
	return h.ssl != unsafe { nil } || h.unix_conn != unsafe { nil } || h.conn != unsafe { nil }
}

// net_dial_tls_real performs a real TLS client handshake (mbedTLS) over a fresh
// TCP connection (§3.6). `opts.tls.verify` (default true) drives cert validation;
// an in-memory `ca` PEM is honored when provided. Advanced opts (ALPN, SPKI pin,
// mTLS, DTLS) are subsequent TLS sub-layers.
// net_dial_tls_real connects TCP to the §4.5-PINNED IP, then TLS-wraps it with
// SNI/verification against the original hostname — so the pin holds (no mbedTLS
// re-resolve) AND the certificate is validated for the name, not the IP.
pub fn net_dial_tls_real(pinned string, host string, port int, opts cx.Node, a NetAddr) cx.Node {
	verify := net_opts_tls_verify(opts)
	ca := net_opts_tls_str(opts, 'ca')
	cfg := mbedtls.SSLConnectConfig{
		validate:               verify
		in_memory_verification: ca != ''
		verify:                 ca
	}
	mut tcp := net.dial_tcp(net_join_host_port(pinned, port)) or {
		msg := err.msg()
		ecode := if msg.contains('refused') { net_err_connect_refused } else { net_err_unreachable }
		return mk_err(ecode, 'E_NET: connect ${pinned}:${port}: ${msg}')
	}
	mut ssl := mbedtls.new_ssl_conn(cfg) or {
		tcp.close() or {}
		return mk_err(net_err_tls_handshake, 'E_NET_TLS_HANDSHAKE_FAILED: ssl init: ${err.msg()}')
	}
	ssl.connect(mut tcp, host) or {
		return mk_err(net_err_tls_handshake, 'E_NET_TLS_HANDSHAKE_FAILED: ${host}:${port}: ${err.msg()}')
	}
	mut h := &NetHandle{
		kind:      'socket'
		transport: 'tls'
		state:     'open'
		is_open:   true
		local:     [a]
		secure:    true
		ssl:       ssl
	}
	id := net_register(h)
	return net_socket_element(id, h)
}

// net_opts_tls_verify reads opts.tls.verify (default true per §3.6).
pub fn net_opts_tls_verify(opts cx.Node) bool {
	tls := net_opts_submap(opts, 'tls') or { return true }
	if v := net_map_get(tls, 'verify') {
		if v is cx.ScalarNode {
			sv := v.value
			if sv is bool {
				return sv
			}
			if sv is string {
				return sv != 'false'
			}
		}
	}
	return true
}

pub fn net_opts_tls_str(opts cx.Node, key string) string {
	tls := net_opts_submap(opts, 'tls') or { return '' }
	if v := net_map_get(tls, key) {
		if v is cx.ScalarNode {
			sv := v.value
			if sv is string {
				return sv
			}
		}
	}
	return ''
}

// net_map_get returns the value node for a key in a `{k: v}` (__cx_map__) literal.
pub fn net_map_get(m cx.Node, key string) ?cx.Node {
	if m is cx.Element && (m.name == '__cx_map__' || m.name == 'map') {
		for it in m.items {
			if it is cx.Element && it.name == key && it.items.len > 0 {
				return it.items[0]
			}
		}
	}
	return none
}

fn net_opts_submap(opts cx.Node, key string) ?cx.Node {
	return net_map_get(opts, key)
}

// net_node_ms reads a deadline / timeout VALUE as MILLISECONDS. Accepts a
// `::duration` scalar (stored as i64 nanoseconds → ms) or a bare numeric scalar
// (int/float, interpreted as ms — the form `{read-deadline: 2000}` in #56).
// Returns none for a non-numeric value.
pub fn net_node_ms(v cx.Node) ?i64 {
	if v is cx.ScalarNode {
		sv := v.value
		if v.data_type == cx.ScalarType.duration_type {
			if sv is i64 {
				return sv / 1_000_000 // ns → ms
			}
		}
		match sv {
			i64 { return sv }
			f64 { return i64(sv) }
			else {}
		}
	}
	return none
}

// net_map_get_ms reads a deadline / timeout option (by key) as milliseconds.
pub fn net_map_get_ms(m cx.Node, key string) ?i64 {
	v := net_map_get(m, key) or { return none }
	return net_node_ms(v)
}

pub fn net_socket_element(id int, h &NetHandle) cx.Node {
	mut attrs := [
		cx.Attribute{
			name:  'fd'
			value: cx.ScalarValue(i64(id))
		},
		cx.Attribute{
			name:  'transport'
			value: cx.ScalarValue(h.transport)
		},
		cx.Attribute{
			name:  'state'
			value: cx.ScalarValue(h.state)
		},
	]
	if h.secure {
		attrs << cx.Attribute{
			name:  'secure'
			value: cx.ScalarValue(true)
		}
	}
	attrs << cx.Attribute{
		name:  'on-close'
		value: cx.ScalarValue('net/close')
	}
	return cx.Element{
		name:  h.kind
		attrs: attrs
	}
}

// net_strip_port removes a trailing :port from an "ip:port" / "[ip6]:port" form.
pub fn net_strip_port(s string) string {
	if s.starts_with('[') {
		if close := s.index(']') {
			return s[1..close]
		}
	}
	if li := s.last_index(':') {
		return s[..li]
	}
	return s
}

