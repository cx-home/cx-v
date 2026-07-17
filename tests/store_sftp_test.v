module main

import os
import testenv

// store_sftp_test.v — BEHAVIORAL conformance for the sftp:// remote byte-source
// backend (GH #106 / #91) against a REAL SSH/SFTP server. Env-gated: SKIPS
// unless CX_TEST_SFTP_URL is set, so `make test` stays green without Docker AND
// without the `-d cx_sftp` build (the default cx links no SSH lib; sftp:// then
// honestly returns CXER1100).
//
// Live run (needs a cx built with -d cx_sftp + Docker atmoz/sftp):
//   docker run -d --name cx-sftp -p 2222:22 atmoz/sftp cxsftp:cxsftppass:::upload
//   CX_TEST_SFTP_URL='sftp://cxsftp:cxsftppass@127.0.0.1:2222/upload/' \
//     CX_TEST_SFTP_KNOWN_HOSTS=/path/to/known_hosts \   # optional: strict verify
//     v -gc e test vcx/tests/store_sftp_test.v
//
// Exercises put → get (hash round-trip) → exists → list → delete → absent over
// real SSH. A stub cannot satisfy the hash round-trip nor delete→absent. When
// CX_TEST_SFTP_KNOWN_HOSTS is set the open uses STRICT host-key verification
// against that file; otherwise host-key-check=off (dev).

fn cx_bin_sftp() string {
	return testenv.cx_bin()
}

fn sftp_url_host(url string) string {
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

fn run_sftp_prog(host string, src string) os.Result {
	f := os.join_path(os.temp_dir(), 'cx_sftp_${os.getpid()}_${src.len}.cx')
	os.write_file(f, src) or { panic('write: ${err}') }
	defer {
		os.rm(f) or {}
	}
	return os.execute('${cx_bin_sftp()} --allow-net=${host} --allow-read ${f}')
}

fn test_sftp_roundtrip() {
	url := os.getenv('CX_TEST_SFTP_URL')
	if url == '' {
		eprintln('SKIP store_sftp_test: set CX_TEST_SFTP_URL (needs a -d cx_sftp build + an SSH server) to run the live SFTP round trip')
		return
	}
	host := sftp_url_host(url)
	known := os.getenv('CX_TEST_SFTP_KNOWN_HOSTS')
	opts := if known != '' {
		'[opts known-hosts="${known}"]'
	} else {
		'[opts host-key-check="off"]'
	}

	prog := "[?lib 'cx-stdlib/store']
[?let [= \$s [\$store:open-opts \"${url}\" ${opts}]]
  [?let [= \$h [\$store:put-doc \$s [doc [msg \"hello-sftp\"]]]]
    [results
      put=\$h
      got=[\$store:get-doc \$s \$h]
      exists=[\$store:exists \$s \$h]
      ndocs=[\$count [\$store:list-docs \$s]]
      gone=[?let [= \$_d [\$store:delete-doc \$s \$h]] [\$store:exists \$s \$h]]]]]
"
	r := run_sftp_prog(host, prog)
	assert r.exit_code == 0, 'sftp round trip failed (exit ${r.exit_code}): ${r.output}'
	assert r.output.contains('hello-sftp'), 'get-doc did not round-trip the doc over SFTP: ${r.output}'
	assert r.output.contains('exists=true'), 'exists should be true after put: ${r.output}'
	assert r.output.contains('ndocs=1'), 'list-docs should enumerate exactly the one stored doc: ${r.output}'
	assert r.output.contains('gone=false'), 'delete-doc should remove the file (exists→false): ${r.output}'
}
