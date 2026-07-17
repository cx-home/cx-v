@[has_globals]
module code

// SFTP byte-source backend for cx-stdlib/store (GH #106 / #91 sftp scheme).
//
// GATED: this file compiles ONLY under `-d cx_sftp`, so the default/core/wasm
// build links no SSH library (mirrors the `-d cx_db_*` engine pattern). Without
// the flag, sftp:// falls through to an honest CXER1100 in store_remote.v.
//
// A real SSH/SFTP client over libssh2 (the BSD-licensed C client used by curl /
// libgit2; decision recorded on #106 — option a). Each store op opens a fresh
// SSH session over a §4.5-guarded TCP socket, verifies the host key against a
// known-hosts file (strict by default), authenticates (key-path or password),
// runs the SFTP op, and tears the session down. Each doc is one file named by
// its SHA-256 hash under the URL directory.
//
// Capabilities: `net` for the socket (guarded at open) + `read` for a private
// key file when key-path auth is used. Errors are honest — CXER1101 unreachable,
// CXER1131 auth — never a synthetic success.

import cx
import net

#pkgconfig libssh2
#include <libssh2.h>
#include <libssh2_sftp.h>

// Opaque libssh2 handles.
struct C.LIBSSH2_SESSION {}
struct C.LIBSSH2_SFTP {}
struct C.LIBSSH2_SFTP_HANDLE {}
struct C.LIBSSH2_KNOWNHOSTS {}

fn C.libssh2_init(flags int) int
fn C.libssh2_exit()
fn C.libssh2_session_init_ex(myalloc voidptr, myfree voidptr, myrealloc voidptr, abstract voidptr) &C.LIBSSH2_SESSION
fn C.libssh2_session_set_blocking(session &C.LIBSSH2_SESSION, blocking int)
fn C.libssh2_session_handshake(session &C.LIBSSH2_SESSION, sock int) int
fn C.libssh2_session_hostkey(session &C.LIBSSH2_SESSION, len &usize, typ &int) &char
fn C.libssh2_session_disconnect_ex(session &C.LIBSSH2_SESSION, reason int, description &char, lang &char) int
fn C.libssh2_session_free(session &C.LIBSSH2_SESSION) int
fn C.libssh2_userauth_password_ex(session &C.LIBSSH2_SESSION, username &char, username_len u32, password &char, password_len u32, cb voidptr) int
fn C.libssh2_userauth_publickey_fromfile_ex(session &C.LIBSSH2_SESSION, username &char, username_len u32, publickey &char, privatekey &char, passphrase &char) int

fn C.libssh2_knownhost_init(session &C.LIBSSH2_SESSION) &C.LIBSSH2_KNOWNHOSTS
fn C.libssh2_knownhost_readfile(hosts &C.LIBSSH2_KNOWNHOSTS, filename &char, typ int) int
fn C.libssh2_knownhost_checkp(hosts &C.LIBSSH2_KNOWNHOSTS, host &char, port int, key &char, keylen usize, typemask int, knownhost voidptr) int
fn C.libssh2_knownhost_free(hosts &C.LIBSSH2_KNOWNHOSTS)

fn C.libssh2_sftp_init(session &C.LIBSSH2_SESSION) &C.LIBSSH2_SFTP
fn C.libssh2_sftp_shutdown(sftp &C.LIBSSH2_SFTP) int
fn C.libssh2_sftp_last_error(sftp &C.LIBSSH2_SFTP) u64
fn C.libssh2_sftp_open_ex(sftp &C.LIBSSH2_SFTP, filename &char, filename_len u32, flags u64, mode int, open_type int) &C.LIBSSH2_SFTP_HANDLE
fn C.libssh2_sftp_read(handle &C.LIBSSH2_SFTP_HANDLE, buffer &char, buffer_maxlen usize) i64
fn C.libssh2_sftp_write(handle &C.LIBSSH2_SFTP_HANDLE, buffer &char, count usize) i64
fn C.libssh2_sftp_close_handle(handle &C.LIBSSH2_SFTP_HANDLE) int
fn C.libssh2_sftp_unlink_ex(sftp &C.LIBSSH2_SFTP, filename &char, filename_len u32) int
fn C.libssh2_sftp_readdir_ex(handle &C.LIBSSH2_SFTP_HANDLE, buffer &char, buffer_maxlen usize, longentry &char, longentry_maxlen usize, attrs voidptr) int

const sftp_openfile = 0
const sftp_opendir = 1
const sftp_fxf_read = u64(0x00000001)
const sftp_fxf_write = u64(0x00000002)
const sftp_fxf_creat = u64(0x00000008)
const sftp_fxf_trunc = u64(0x00000010)
const sftp_fx_no_such_file = u64(2)
const sftp_kh_type_plain = 1
const sftp_kh_keyenc_raw = (1 << 16)
const sftp_kh_check_match = 0

// SftpSession bundles an authenticated SSH+SFTP session over its TCP socket.
struct SftpSession {
mut:
	tcp  &net.TcpConn = unsafe { nil }
	sess &C.LIBSSH2_SESSION = unsafe { nil }
	sftp &C.LIBSSH2_SFTP    = unsafe { nil }
}

fn (mut s SftpSession) close() {
	if s.sftp != unsafe { nil } {
		C.libssh2_sftp_shutdown(s.sftp)
	}
	if s.sess != unsafe { nil } {
		C.libssh2_session_disconnect_ex(s.sess, 11, c'shutdown', c'')
		C.libssh2_session_free(s.sess)
	}
	if s.tcp != unsafe { nil } {
		s.tcp.close() or {}
	}
}

fn sftp_err(rb &RemoteBackend, ecode string, detail string) cx.Node {
	return mk_err(ecode, '${detail} (${rb.scheme}://${rb.host}:${rb.port})')
}

// sftp_connect dials + handshakes + verifies host key + authenticates + opens
// the SFTP subsystem. Returns a ready session or an honest [err] node.
fn sftp_connect(rb &RemoteBackend) (&SftpSession, cx.Node, bool) {
	// #206.1: reading the known-hosts / private-key files is a filesystem effect
	// distinct from the `net` gate the sftp substrate holds — require `read` when
	// either is configured (networked-backends §B: sftp needs net + read).
	if rb.known_hosts != '' || rb.key_path != '' {
		if d := cap_guard('read', 'sftp key/known-hosts read for ${rb.host}') {
			return unsafe { nil }, d, false
		}
	}
	// §4.5 SSRF guard + pin (shares the http/ftp guard).
	pinned, derr := net_ssrf_check(rb.host, rb.port)
	if _ := derr {
		return unsafe { nil }, sftp_err(rb, 'cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: forbidden/ungranted address §4.5'), false
	}
	mut tcp := net.dial_tcp(net_join_host_port(pinned, rb.port)) or {
		return unsafe { nil }, sftp_err(rb, 'cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: connect: ${err.msg()}'), false
	}
	if C.libssh2_init(0) != 0 {
		tcp.close() or {}
		return unsafe { nil }, sftp_err(rb, 'cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: libssh2 init failed'), false
	}
	mut sess := C.libssh2_session_init_ex(unsafe { nil }, unsafe { nil }, unsafe { nil },
		unsafe { nil })
	if sess == unsafe { nil } {
		tcp.close() or {}
		return unsafe { nil }, sftp_err(rb, 'cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: session init failed'), false
	}
	C.libssh2_session_set_blocking(sess, 1)
	mut s := &SftpSession{
		tcp:  tcp
		sess: sess
	}
	if C.libssh2_session_handshake(sess, tcp.sock.handle) != 0 {
		s.close()
		return unsafe { nil }, sftp_err(rb, 'cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: SSH handshake failed'), false
	}
	// Host-key verification (strict by default; opts host-key-check=off skips —
	// dev/test only). When checking, a known-hosts file is required.
	if rb.host_key_check != 'off' {
		errn, ok := sftp_verify_host(rb, mut s)
		if !ok {
			s.close()
			return unsafe { nil }, errn, false
		}
	}
	// Authentication: key-path (publickey) first, else password.
	if !sftp_authenticate(rb, mut s) {
		s.close()
		return unsafe { nil }, sftp_err(rb, 'cx-err:CXER1131', 'E_STORE_AUTH_FAILED: SSH auth rejected (key-path/password)'), false
	}
	sftp := C.libssh2_sftp_init(sess)
	if sftp == unsafe { nil } {
		s.close()
		return unsafe { nil }, sftp_err(rb, 'cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: SFTP subsystem init failed'), false
	}
	s.sftp = sftp
	return s, store_null(), true
}

// sftp_verify_host checks the server's host key against the known-hosts file.
fn sftp_verify_host(rb &RemoteBackend, mut s SftpSession) (cx.Node, bool) {
	if rb.known_hosts == '' {
		return sftp_err(rb, 'cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: host-key verification needs opts.auth.known-hosts (or host-key-check=off for dev)'), false
	}
	mut klen := usize(0)
	mut ktype := 0
	key := C.libssh2_session_hostkey(s.sess, &klen, &ktype)
	if key == unsafe { nil } {
		return sftp_err(rb, 'cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: no host key presented'), false
	}
	mut kh := C.libssh2_knownhost_init(s.sess)
	if kh == unsafe { nil } {
		return sftp_err(rb, 'cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: known-hosts init failed'), false
	}
	defer {
		C.libssh2_knownhost_free(kh)
	}
	if C.libssh2_knownhost_readfile(kh, &char(rb.known_hosts.str), 1) < 0 {
		return sftp_err(rb, 'cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: cannot read known-hosts ${rb.known_hosts}'), false
	}
	typemask := sftp_kh_type_plain | sftp_kh_keyenc_raw
	check := C.libssh2_knownhost_checkp(kh, &char(rb.host.str), rb.port, key, klen, typemask,
		unsafe { nil })
	if check != sftp_kh_check_match {
		return sftp_err(rb, 'cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: host key not in known-hosts / mismatch (check=${check})'), false
	}
	return store_null(), true
}

fn sftp_authenticate(rb &RemoteBackend, mut s SftpSession) bool {
	user := if rb.user == '' { 'anonymous' } else { rb.user }
	if rb.key_path != '' {
		// publickey_fromfile derives the public key from the private key when
		// the public-key arg is empty (libssh2 >= 1.x).
		rc := C.libssh2_userauth_publickey_fromfile_ex(s.sess, &char(user.str), u32(user.len),
			&char(unsafe { nil }), &char(rb.key_path.str), &char(rb.pass.str))
		if rc == 0 {
			return true
		}
	}
	if rb.pass != '' {
		rc := C.libssh2_userauth_password_ex(s.sess, &char(user.str), u32(user.len),
			&char(rb.pass.str), u32(rb.pass.len), unsafe { nil })
		if rc == 0 {
			return true
		}
	}
	return false
}

fn (rb &RemoteBackend) sftp_path(hash string) string {
	return rb.dir + hash
}

// ── op surface (called from store_remote.v dispatch under $if cx_sftp) ───────

fn sftp_get(rb &RemoteBackend, hash string) (string, cx.Node, bool) {
	mut s, errn, ok := sftp_connect(rb)
	if !ok {
		return '', errn, false
	}
	defer {
		s.close()
	}
	path := rb.sftp_path(hash)
	h := C.libssh2_sftp_open_ex(s.sftp, &char(path.str), u32(path.len), sftp_fxf_read,
		0, sftp_openfile)
	if h == unsafe { nil } {
		if C.libssh2_sftp_last_error(s.sftp) == sftp_fx_no_such_file {
			return '', mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: ${hash}'), false
		}
		return '', sftp_err(rb, 'cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: open ${hash}'), false
	}
	mut out := []u8{}
	mut buf := []u8{len: 32768}
	for {
		n := C.libssh2_sftp_read(h, &char(unsafe { &buf[0] }), usize(buf.len))
		if n > 0 {
			out << buf[..int(n)]
		} else {
			break // 0 = EOF, <0 = error (treated as end; integrity check follows)
		}
	}
	C.libssh2_sftp_close_handle(h)
	return out.bytestr(), store_null(), true
}

fn sftp_put(rb &RemoteBackend, hash string, text string) cx.Node {
	mut s, errn, ok := sftp_connect(rb)
	if !ok {
		return errn
	}
	defer {
		s.close()
	}
	path := rb.sftp_path(hash)
	flags := sftp_fxf_write | sftp_fxf_creat | sftp_fxf_trunc
	h := C.libssh2_sftp_open_ex(s.sftp, &char(path.str), u32(path.len), flags, 0o644,
		sftp_openfile)
	if h == unsafe { nil } {
		return sftp_err(rb, 'cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: create ${hash}')
	}
	data := text.bytes()
	mut off := 0
	for off < data.len {
		n := C.libssh2_sftp_write(h, &char(unsafe { &data[off] }), usize(data.len - off))
		if n < 0 {
			C.libssh2_sftp_close_handle(h)
			return sftp_err(rb, 'cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: write ${hash}')
		}
		off += int(n)
	}
	C.libssh2_sftp_close_handle(h)
	return store_null()
}

fn sftp_has(rb &RemoteBackend, hash string) (bool, cx.Node, bool) {
	mut s, errn, ok := sftp_connect(rb)
	if !ok {
		return false, errn, false
	}
	defer {
		s.close()
	}
	path := rb.sftp_path(hash)
	h := C.libssh2_sftp_open_ex(s.sftp, &char(path.str), u32(path.len), sftp_fxf_read,
		0, sftp_openfile)
	if h == unsafe { nil } {
		return false, store_null(), true
	}
	C.libssh2_sftp_close_handle(h)
	return true, store_null(), true
}

fn sftp_delete(rb &RemoteBackend, hash string) (bool, cx.Node, bool) {
	mut s, errn, ok := sftp_connect(rb)
	if !ok {
		return false, errn, false
	}
	defer {
		s.close()
	}
	path := rb.sftp_path(hash)
	rc := C.libssh2_sftp_unlink_ex(s.sftp, &char(path.str), u32(path.len))
	// 0 = removed; otherwise treat as absent (idempotent false, not an error).
	return rc == 0, store_null(), true
}

fn sftp_list(rb &RemoteBackend) ([]string, cx.Node, bool) {
	mut s, errn, ok := sftp_connect(rb)
	if !ok {
		return []string{}, errn, false
	}
	defer {
		s.close()
	}
	dir := if rb.dir == '' { '.' } else { rb.dir }
	dh := C.libssh2_sftp_open_ex(s.sftp, &char(dir.str), u32(dir.len), 0, 0, sftp_opendir)
	if dh == unsafe { nil } {
		return []string{}, sftp_err(rb, 'cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: opendir ${dir}'), false
	}
	mut out := []string{}
	mut namebuf := []u8{len: 512}
	for {
		n := C.libssh2_sftp_readdir_ex(dh, &char(unsafe { &namebuf[0] }), usize(namebuf.len),
			&char(unsafe { nil }), 0, unsafe { nil })
		if n <= 0 {
			break
		}
		name := namebuf[..int(n)].bytestr()
		if store_is_doc_hash(name) {
			out << name
		}
	}
	C.libssh2_sftp_close_handle(dh)
	return out, store_null(), true
}
