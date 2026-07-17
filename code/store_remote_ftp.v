@[has_globals]
module code

// FTP / FTPS byte-source backend for cx-stdlib/store (GH #91, Phase 0.5).
//
// A real RFC 959 client over the in-module net transport: a control connection
// (line-based command/reply) plus a per-transfer PASV data connection. Each doc
// is one file named by its SHA-256 hash under the URL directory:
//   put  = STOR <dir><hash>     get  = RETR <dir><hash>
//   has  = SIZE <dir><hash>     del  = DELE <dir><hash>     list = NLST <dir>
//
// ftps:// upgrades the control connection with AUTH TLS (RFC 4217) and protects
// the data channel with PBSZ 0 / PROT P; both channels run over mbedtls (the
// same TLS client http uses). Peer verification is on by default (OS trust
// store) and can be disabled per-open for a self-signed dev server.
//
// Security: the §4.5 SSRF guard pins the control host; the PASV data connection
// dials that SAME pinned host (never the PASV-advertised IP — anti-rebind) and
// is itself capability-checked. Because PASV uses a dynamic port, an FTP store
// needs a host-level net grant (e.g. --allow-net=host), not a single host:port.

import cx
import net
import net.mbedtls
import time

const ftp_io_timeout = 15 * time.second

// FtpConn wraps an FTP control or data connection: a raw TCP socket, optionally
// upgraded to TLS. Reads are buffered so control replies can be read by line.
struct FtpConn {
mut:
	tcp  &net.TcpConn     = unsafe { nil }
	ssl  &mbedtls.SSLConn = unsafe { nil }
	tls  bool
	rbuf []u8
	rpos int
}

fn (mut c FtpConn) write_all(data []u8) ! {
	if c.tls {
		c.ssl.write(data)!
	} else {
		c.tcp.write(data)!
	}
}

fn (mut c FtpConn) read_some(mut buf []u8) !int {
	if c.tls {
		return c.ssl.read(mut buf)!
	}
	return c.tcp.read(mut buf)!
}

fn (mut c FtpConn) close() {
	if c.tls {
		// NOTE: no close-notify here. It is sent explicitly on the DATA channel
		// after an upload (ftp_put) where the server needs it to detect EOF. On
		// the CONTROL channel a close-notify is sent only via close_control()
		// BEFORE QUIT — sending it after QUIT (when the server is already tearing
		// the connection down) crashes some vsftpd builds.
		c.ssl.close() or {}
	}
	if c.tcp != unsafe { nil } {
		c.tcp.close() or {}
	}
}

// read_line returns the next CRLF/LF-terminated control line (terminator
// stripped), refilling the buffer from the socket as needed.
fn (mut c FtpConn) read_line() !string {
	for {
		mut i := c.rpos
		for i < c.rbuf.len {
			if c.rbuf[i] == `\n` {
				line := c.rbuf[c.rpos..i].bytestr().trim_right('\r')
				c.rpos = i + 1
				return line
			}
			i++
		}
		mut tmp := []u8{len: 4096}
		n := c.read_some(mut tmp)!
		if n <= 0 {
			return error('control connection closed')
		}
		c.rbuf << tmp[..n]
	}
	return error('unreachable')
}

// read_reply reads a (possibly multi-line) FTP reply and returns (code, text).
// A multi-line reply opens with "ddd-" and closes with a line starting "ddd ".
fn (mut c FtpConn) read_reply() !(int, string) {
	first := c.read_line()!
	if first.len < 3 {
		return error('short FTP reply: ${first}')
	}
	rcode := first[..3]
	mut text := first
	if first.len >= 4 && first[3] == `-` {
		for {
			ln := c.read_line()!
			text += '\n' + ln
			if ln.len >= 4 && ln[..3] == rcode && ln[3] == ` ` {
				break
			}
		}
	}
	return rcode.int(), text
}

// cmd sends one command line and returns its reply.
fn (mut c FtpConn) cmd(line string) !(int, string) {
	c.write_all((line + '\r\n').bytes())!
	return c.read_reply()!
}

// ── error mapping ────────────────────────────────────────────────────────

fn ftp_unreachable(rb &RemoteBackend, detail string) cx.Node {
	return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: ${rb.scheme}://${rb.host}:${rb.port}: ${detail}')
}

// ftp_tls_wrap upgrades an open TCP connection to TLS (control after AUTH TLS,
// or a PROT P data channel). FTPS is capped to TLS 1.2 (0x0303): widely-deployed
// FTPS servers (vsftpd/openssl) crash or reset on a mbedTLS 1.3 handshake — the
// TLS 1.3 post-handshake (session-ticket / key-update) and close semantics differ
// from what their data-channel handling expects. TLS 1.2 is the interoperable
// FTPS norm. (http(s):// keeps the default, negotiating 1.3.)
const ftps_max_tls_version = u16(0x0303) // MBEDTLS_SSL_VERSION_TLS1_2

fn ftp_tls_wrap(mut tcp net.TcpConn, host string, verify bool) !&mbedtls.SSLConn {
	mut cfg := mbedtls.SSLConnectConfig{
		validate:        verify
		max_tls_version: ftps_max_tls_version
	}
	if verify {
		cfg = mbedtls.SSLConnectConfig{
			validate:        true
			verify:          http_os_ca_bundle()
			max_tls_version: ftps_max_tls_version
		}
	}
	mut ssl := mbedtls.new_ssl_conn(cfg)!
	ssl.connect(mut tcp, host)!
	return ssl
}

// ftp_dial opens + pins a TCP connection to host:port through the §4.5 guard.
fn ftp_dial(host string, port int) !&net.TcpConn {
	pinned, derr := net_ssrf_check(host, port)
	if _ := derr {
		return error('forbidden or ungranted address ${host}:${port} (§4.5)')
	}
	mut tcp := net.dial_tcp(net_join_host_port(pinned, port))!
	tcp.set_read_timeout(ftp_io_timeout)
	tcp.set_write_timeout(ftp_io_timeout)
	return tcp
}

// ftp_login opens the control connection, (optionally) negotiates TLS, logs in,
// and selects binary mode. Returns an open, ready FtpConn.
fn ftp_login(rb &RemoteBackend) !&FtpConn {
	mut tcp := ftp_dial(rb.host, rb.port)!
	mut ctl := &FtpConn{
		tcp: tcp
	}
	gc, gmsg := ctl.read_reply()! // 220 greeting
	if gc != 220 {
		ctl.close()
		return error('bad greeting: ${gmsg}')
	}
	if rb.scheme == 'ftps' {
		ac, am := ctl.cmd('AUTH TLS')!
		if ac != 234 {
			ctl.close()
			return error('AUTH TLS refused: ${am}')
		}
		mut ssl := ftp_tls_wrap(mut tcp, rb.host, rb.tls_verify) or {
			ctl.close()
			return error('control TLS handshake: ${err.msg()}')
		}
		ctl.ssl = ssl
		ctl.tls = true
	}
	uc, um := ctl.cmd('USER ${rb.user}')!
	if uc == 331 {
		pc, pm := ctl.cmd('PASS ${rb.pass}')!
		if pc != 230 {
			ctl.close()
			return error('login failed: ${pm}')
		}
	} else if uc != 230 {
		ctl.close()
		return error('login failed: ${um}')
	}
	if rb.scheme == 'ftps' {
		// Protect the data channel: PBSZ 0 then PROT P (RFC 4217).
		ctl.cmd('PBSZ 0')!
		ctl.cmd('PROT P')!
	}
	tc, tm := ctl.cmd('TYPE I')! // binary
	if tc != 200 {
		ctl.close()
		return error('TYPE I refused: ${tm}')
	}
	return ctl
}

// ftp_pasv issues PASV and opens the data connection to the pinned control host
// (NOT the PASV-advertised IP) at the advertised port. The connection is left
// PLAINTEXT even for ftps:// — under PROT P the server does not begin the data
// TLS handshake until it has received the transfer command (RETR/STOR/NLST), so
// the caller must send that command and only THEN call data.start_tls (else the
// two sides deadlock waiting on each other's handshake).
fn (mut ctl FtpConn) ftp_pasv(rb &RemoteBackend) !&FtpConn {
	pc, pmsg := ctl.cmd('PASV')!
	if pc != 227 {
		return error('PASV refused: ${pmsg}')
	}
	// "227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)."
	op := pmsg.index('(') or { return error('PASV no tuple: ${pmsg}') }
	cp := pmsg.index_after(')', op) or { return error('PASV no tuple: ${pmsg}') }
	nums := pmsg[op + 1..cp].split(',')
	if nums.len != 6 {
		return error('PASV bad tuple: ${pmsg}')
	}
	port := nums[4].trim_space().int() * 256 + nums[5].trim_space().int()
	mut dtcp := ftp_dial(rb.host, port)!
	return &FtpConn{
		tcp: dtcp
	}
}

// start_tls upgrades a PASV data connection to TLS (ftps:// PROT P). Must be
// called AFTER the transfer command's 1xx reply, never before (see ftp_pasv).
fn (mut data FtpConn) start_tls(rb &RemoteBackend) ! {
	if rb.scheme != 'ftps' {
		return
	}
	mut dtcp := data.tcp
	mut ssl := ftp_tls_wrap(mut dtcp, rb.host, rb.tls_verify) or {
		return error('data TLS handshake: ${err.msg()}')
	}
	data.ssl = ssl
	data.tls = true
}

// drain_all reads a data connection to EOF.
fn (mut c FtpConn) drain_all() ![]u8 {
	mut out := []u8{}
	// hand over any bytes already buffered (none expected on a fresh data conn)
	if c.rpos < c.rbuf.len {
		out << c.rbuf[c.rpos..]
	}
	for {
		mut tmp := []u8{len: 8192}
		n := c.read_some(mut tmp) or { break }
		if n <= 0 {
			break
		}
		out << tmp[..n]
	}
	return out
}

fn (rb &RemoteBackend) ftp_path(hash string) string {
	return rb.dir + hash
}

// ── op surface (called from store_remote.v dispatch) ─────────────────────

fn ftp_get(rb &RemoteBackend, hash string) (string, cx.Node, bool) {
	mut ctl := ftp_login(rb) or { return '', ftp_unreachable(rb, err.msg()), false }
	defer {
		ctl.cmd('QUIT') or {}
		ctl.close()
	}
	mut data := ctl.ftp_pasv(rb) or { return '', ftp_unreachable(rb, err.msg()), false }
	defer {
		data.close()
	}
	rc, rm := ctl.cmd('RETR ${rb.ftp_path(hash)}') or {
		return '', ftp_unreachable(rb, err.msg()), false
	}
	if rc == 550 {
		return '', mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: ${hash}'), false
	}
	if rc != 150 && rc != 125 {
		return '', mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: RETR ${hash}: ${rm}'), false
	}
	data.start_tls(rb) or { return '', ftp_unreachable(rb, err.msg()), false }
	bytes := data.drain_all() or { return '', ftp_unreachable(rb, 'RETR read: ${err.msg()}'), false }
	data.close()
	fc, fm := ctl.read_reply() or { return '', ftp_unreachable(rb, err.msg()), false }
	if fc != 226 && fc != 250 {
		return '', mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: RETR ${hash} not completed: ${fm}'), false
	}
	return bytes.bytestr(), store_null(), true
}

fn ftp_put(rb &RemoteBackend, hash string, text string) cx.Node {
	mut ctl := ftp_login(rb) or { return ftp_unreachable(rb, err.msg()) }
	defer {
		ctl.cmd('QUIT') or {}
		ctl.close()
	}
	mut data := ctl.ftp_pasv(rb) or { return ftp_unreachable(rb, err.msg()) }
	sc, sm := ctl.cmd('STOR ${rb.ftp_path(hash)}') or { return ftp_unreachable(rb, err.msg()) }
	if sc != 150 && sc != 125 {
		data.close()
		if sc == 550 || sc == 553 {
			return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: STOR ${hash} refused: ${sm}')
		}
		return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: STOR ${hash}: ${sm}')
	}
	data.start_tls(rb) or { return ftp_unreachable(rb, err.msg()) }
	data.write_all(text.bytes()) or {
		data.close()
		return ftp_unreachable(rb, 'STOR write: ${err.msg()}')
	}
	// On a TLS data channel (PROT P) the server detects end-of-file via the TLS
	// close-notify, not a bare socket FIN; without it the upload is reported
	// truncated (vsftpd "426 Failure reading network stream"). Sent here on the
	// DATA channel only (never the control channel — see close()).
	if data.tls {
		data.ssl.close_notify()
	}
	data.close()
	fc, fm := ctl.read_reply() or { return ftp_unreachable(rb, err.msg()) }
	if fc != 226 && fc != 250 {
		return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: STOR ${hash} not completed: ${fm}')
	}
	return store_null()
}

fn ftp_has(rb &RemoteBackend, hash string) (bool, cx.Node, bool) {
	mut ctl := ftp_login(rb) or { return false, ftp_unreachable(rb, err.msg()), false }
	defer {
		ctl.cmd('QUIT') or {}
		ctl.close()
	}
	// SIZE is the cheapest existence probe (213 = present, 550 = absent).
	sc, _ := ctl.cmd('SIZE ${rb.ftp_path(hash)}') or {
		return false, ftp_unreachable(rb, err.msg()), false
	}
	return sc == 213, store_null(), true
}

fn ftp_delete(rb &RemoteBackend, hash string) (bool, cx.Node, bool) {
	mut ctl := ftp_login(rb) or { return false, ftp_unreachable(rb, err.msg()), false }
	defer {
		ctl.cmd('QUIT') or {}
		ctl.close()
	}
	dc, _ := ctl.cmd('DELE ${rb.ftp_path(hash)}') or {
		return false, ftp_unreachable(rb, err.msg()), false
	}
	// 250 deleted; 550 absent → not-deleted (idempotent false, not an error).
	return dc == 250, store_null(), true
}

fn ftp_list(rb &RemoteBackend) ([]string, cx.Node, bool) {
	mut ctl := ftp_login(rb) or { return []string{}, ftp_unreachable(rb, err.msg()), false }
	defer {
		ctl.cmd('QUIT') or {}
		ctl.close()
	}
	mut data := ctl.ftp_pasv(rb) or { return []string{}, ftp_unreachable(rb, err.msg()), false }
	defer {
		data.close()
	}
	// NLST yields bare names (one per line); strip any directory component and
	// keep only 64-hex doc objects.
	nc, nm := ctl.cmd('NLST ${rb.dir}') or { return []string{}, ftp_unreachable(rb, err.msg()), false }
	if nc == 550 {
		// empty directory on some servers → no matches, not an error.
		return []string{}, store_null(), true
	}
	if nc != 150 && nc != 125 {
		return []string{}, mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: NLST: ${nm}'), false
	}
	data.start_tls(rb) or { return []string{}, ftp_unreachable(rb, err.msg()), false }
	raw := data.drain_all() or { return []string{}, ftp_unreachable(rb, 'NLST read: ${err.msg()}'), false }
	data.close()
	fc, fm := ctl.read_reply() or { return []string{}, ftp_unreachable(rb, err.msg()), false }
	if fc != 226 && fc != 250 {
		return []string{}, mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: NLST not completed: ${fm}'), false
	}
	mut out := []string{}
	for line in raw.bytestr().split('\n') {
		mut name := line.trim_space()
		if name == '' {
			continue
		}
		if sl := name.last_index('/') {
			name = name[sl + 1..]
		}
		if store_is_doc_hash(name) {
			out << name
		}
	}
	return out, store_null(), true
}
