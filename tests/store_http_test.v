module main

import os
import testenv

// store_http_test.v — BEHAVIORAL conformance for the read-only http(s)://
// byte-source backend (GH #91) against a REAL HTTP server. Env-gated: SKIPS
// unless CX_TEST_HTTP_URL (the base, ending '/') and CX_TEST_HTTP_DIR (the
// directory that server serves) are set, so `make test` stays green without a
// server.
//
// Live run:
//   d=$(mktemp -d); python3 -m http.server 28080 --directory "$d" &
//   CX_TEST_HTTP_URL=http://127.0.0.1:28080/ CX_TEST_HTTP_DIR="$d" \
//     v -gc e test vcx/tests/store_http_test.v
//
// http:// is read-only, so the test provisions its own object: it asks the cx
// CLI for the strict-canonical bytes + hash of a doc, writes <dir>/<hash>, then
// opens the http:// store and reads it back. get-doc re-hashes the fetched
// bytes and fails on any mismatch, so a byte-exact round-trip over real HTTP is
// the proof. write on a read-only http store must raise CXER1110.

fn cx_bin_http() string {
	return testenv.cx_bin()
}

fn http_url_host(url string) string {
	mut s := url.all_after('://')
	if sl := s.index('/') {
		s = s[..sl]
	}
	if c := s.index(':') {
		s = s[..c]
	}
	return s
}

fn test_http_read_roundtrip() {
	base := os.getenv('CX_TEST_HTTP_URL')
	dir := os.getenv('CX_TEST_HTTP_DIR')
	if base == '' || dir == '' {
		eprintln('SKIP store_http_test: set CX_TEST_HTTP_URL + CX_TEST_HTTP_DIR to run the live HTTP read round trip')
		return
	}
	host := http_url_host(base)
	cx := cx_bin_http()

	// Strict-canonical bytes + hash of the fixture doc, straight from the CLI
	// (the same canonical that get-doc re-hashes). `cx canonical` prints the
	// bytes + one trailing newline; strip exactly that newline.
	docf := os.join_path(os.temp_dir(), 'cx_http_doc_${os.getpid()}.cx')
	os.write_file(docf, '[doc [msg "hello-http"]]') or { panic('write doc: ${err}') }
	defer {
		os.rm(docf) or {}
	}
	hash := os.execute('${cx} hash ${docf}').output.trim_space()
	canon_raw := os.execute('${cx} canonical ${docf}').output
	canon := canon_raw.trim_right('\n')
	assert hash.len == 64, 'cx hash did not return a 64-hex digest: ${hash}'

	// Provision the object into the served directory at its hash name.
	obj := os.join_path(dir, hash)
	os.write_file(obj, canon) or { panic('provision ${obj}: ${err}') }
	defer {
		os.rm(obj) or {}
	}

	read_prog := "[?lib 'cx-stdlib/store']
[?let [= \$s [\$store:open \"${base}\"]]
  [results
    got=[\$store:get-doc \$s \"${hash}\"]
    exists=[\$store:exists \$s \"${hash}\"]
    missing=[\$store:exists \$s \"0000000000000000000000000000000000000000000000000000000000000000\"]]]
"
	r := run_http_prog(cx, host, read_prog)
	assert r.exit_code == 0, 'http read program failed (exit ${r.exit_code}): ${r.output}'
	assert r.output.contains('hello-http'), 'get-doc did not round-trip the doc over HTTP: ${r.output}'
	assert r.output.contains('exists=true'), 'exists should be true for the provisioned object: ${r.output}'
	assert r.output.contains('missing=false'), 'exists should be false for an absent object: ${r.output}'

	// http:// is a read-only byte source → put-doc must raise CXER1110.
	write_prog := "[?lib 'cx-stdlib/store']
[?let [= \$s [\$store:open \"${base}\"]] [\$store:put-doc \$s [doc [x 1]]]]
"
	w := run_http_prog(cx, host, write_prog)
	assert w.output.contains('CXER1110'), 'put-doc on a read-only http store should raise CXER1110: ${w.output}'
}

fn run_http_prog(cx string, host string, src string) os.Result {
	pf := os.join_path(os.temp_dir(), 'cx_http_prog_${os.getpid()}_${src.len}.cx')
	os.write_file(pf, src) or { panic('write prog: ${err}') }
	defer {
		os.rm(pf) or {}
	}
	return os.execute('${cx} --allow-net=${host} ${pf}')
}
