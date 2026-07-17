module main

import os
import testenv

// store_ftp_test.v — BEHAVIORAL conformance for the ftp:// / ftps:// remote
// byte-source backend (GH #91) against a REAL FTP server. Env-gated: SKIPS
// unless CX_TEST_FTP_URL is set, so `make test` stays green without Docker.
//
// Live run (mirrors the DB-engine / MinIO verification):
//   docker run -d --name cx-ftp -p 2121:21 -p 21000-21010:21000-21010 \
//     -e USERS="cxftp|cxftppass" -e ADDRESS=127.0.0.1 delfer/alpine-ftp-server
//   CX_TEST_FTP_URL='ftp://cxftp:cxftppass@127.0.0.1:2121/' \
//     v -gc e test vcx/tests/store_ftp_test.v
//
// The round trip exercises STOR → RETR (hash round-trip) → SIZE (exists) →
// NLST (list) → DELE → SIZE-absent over a real control + PASV data channel. A
// stub cannot satisfy the hash round-trip nor the delete-then-absent
// transition. For ftps:// the test URL uses scheme ftps and the program opens
// with `tls-verify=false` (self-signed dev cert); the same code path otherwise.

fn cx_bin_ftp() string {
	return testenv.cx_bin()
}

// bare host of an ftp(s) URL, for the net grant. FTP needs a host-level grant
// (not host:port) because the PASV data channel uses a dynamic port.
fn ftp_url_host(url string) string {
	mut s := url.all_after('://')
	if at := s.last_index('@') {
		s = s[at + 1..]
	}
	if sl := s.index('/') {
		s = s[..sl]
	}
	if c := s.index(':') {
		s = s[..c]
	}
	return s
}

fn run_ftp_prog(host string, src string) os.Result {
	f := os.join_path(os.temp_dir(), 'cx_ftp_${os.getpid()}_${src.len}.cx')
	os.write_file(f, src) or { panic('write: ${err}') }
	defer {
		os.rm(f) or {}
	}
	// Host-level (portless) literal-IP grant: admits the control port AND the
	// dynamic PASV data port, and overrides the §4.5 loopback deny-set.
	return os.execute('${cx_bin_ftp()} --allow-net=${host} ${f}')
}

fn test_ftp_roundtrip() {
	url := os.getenv('CX_TEST_FTP_URL')
	if url == '' {
		eprintln('SKIP store_ftp_test: set CX_TEST_FTP_URL (e.g. ftp://cxftp:cxftppass@127.0.0.1:2121/) to run the live FTP round trip')
		return
	}
	host := ftp_url_host(url)
	// ftps:// dev servers use a self-signed cert → tls-verify=false; ftps is
	// experimental/unverified (#107) so it must be opted in via ftps-experimental
	// (this test is how it gets verified on a Linux FTPS server).
	mut open_expr := '[\$store:open "${url}"]'
	if url.starts_with('ftps://') {
		open_expr = '[\$store:open-opts "${url}" [opts tls-verify="false" ftps-experimental="true"]]'
	}

	prog := "[?lib 'cx-stdlib/store']
[?let [= \$s ${open_expr}]
  [?let [= \$h [\$store:put-doc \$s [doc [msg \"hello-ftp\"]]]]
    [results
      put=\$h
      got=[\$store:get-doc \$s \$h]
      exists=[\$store:exists \$s \$h]
      ndocs=[\$count [\$store:list-docs \$s]]
      gone=[?let [= \$_d [\$store:delete-doc \$s \$h]] [\$store:exists \$s \$h]]]]]
"
	r := run_ftp_prog(host, prog)
	assert r.exit_code == 0, 'ftp round trip failed (exit ${r.exit_code}): ${r.output}'
	assert r.output.contains('hello-ftp'), 'get-doc did not round-trip the doc over FTP: ${r.output}'
	assert r.output.contains('exists=true'), 'exists should be true after STOR: ${r.output}'
	assert r.output.contains('ndocs=1'), 'list-docs (NLST) should enumerate exactly the one stored doc: ${r.output}'
	assert r.output.contains('gone=false'), 'delete-doc (DELE) should remove the file (exists→false): ${r.output}'
}
