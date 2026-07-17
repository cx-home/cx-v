module main

import os
import testenv

// store_s3_minio_test.v — BEHAVIORAL conformance for the s3:// remote
// byte-source backend (GH #91) against a REAL S3-compatible server (MinIO, also
// covers AWS S3 / R2 / B2 / Wasabi). Env-gated: it SKIPS unless
// CX_TEST_S3_ENDPOINT is set, so `make test` stays green without Docker; the
// SigV4 signer itself is proven network-free in store_sigv4_test.v.
//
// Live run (mirrors how the DB engines were verified):
//   docker run -d --name cx-minio -p 9100:9000 \
//     -e MINIO_ROOT_USER=cxtest -e MINIO_ROOT_PASSWORD=cxtestsecret123 \
//     minio/minio server /data
//   # create bucket "cxstore", then:
//   CX_TEST_S3_ENDPOINT=http://127.0.0.1:9100 \
//     v -gc e test vcx/tests/store_s3_minio_test.v
//
// The round trip exercises put → get (hash round-trip) → exists → list →
// delete → exists over real SigV4-signed HTTP to MinIO. A stub cannot satisfy
// the hash round-trip (the doc fetched back must reparse to the put hash) nor
// the delete-then-absent transition.

fn cx_bin_s3() string {
	return testenv.cx_bin()
}

fn env_or_s3(name string, deflt string) string {
	v := os.getenv(name)
	return if v == '' { deflt } else { v }
}

fn run_s3_prog(env string, allow_hostport string, src string) os.Result {
	f := os.join_path(os.temp_dir(), 'cx_s3_${os.getpid()}_${src.len}.cx')
	os.write_file(f, src) or { panic('write: ${err}') }
	defer {
		os.rm(f) or {}
	}
	// A literal-IP host:port grant overrides the §4.5 loopback deny set (a bare
	// --allow-net would not — that is the DNS-rebinding defense).
	return os.execute('${env} ${cx_bin_s3()} --allow-net=${allow_hostport} ${f}')
}

fn test_s3_minio_roundtrip() {
	endpoint := os.getenv('CX_TEST_S3_ENDPOINT')
	if endpoint == '' {
		eprintln('SKIP store_s3_minio_test: set CX_TEST_S3_ENDPOINT (e.g. http://127.0.0.1:9100) to run the live MinIO round trip')
		return
	}
	access := env_or_s3('CX_TEST_S3_ACCESS', 'cxtest')
	secret := env_or_s3('CX_TEST_S3_SECRET', 'cxtestsecret123')
	bucket := env_or_s3('CX_TEST_S3_BUCKET', 'cxstore')
	region := env_or_s3('CX_TEST_S3_REGION', 'us-east-1')
	// A per-process key prefix isolates this run's objects so list-docs counts
	// exactly the doc we wrote (and parallel test procs don't collide).
	prefix := 'itest-${os.getpid()}/'

	env := 'AWS_ACCESS_KEY_ID=${access} AWS_SECRET_ACCESS_KEY=${secret} ' +
		'AWS_REGION=${region} AWS_S3_ENDPOINT=${endpoint}'
	// host:port of the endpoint, for the precise net grant.
	mut hostport := endpoint.all_after('://')
	if sl := hostport.index('/') {
		hostport = hostport[..sl]
	}

	prog := "[?lib 'cx-stdlib/store']
[?let [= \$s [\$store:open \"s3://${bucket}/${prefix}\"]]
  [?let [= \$h [\$store:put-doc \$s [doc [msg \"hello-s3\"]]]]
    [results
      put=\$h
      got=[\$store:get-doc \$s \$h]
      exists=[\$store:exists \$s \$h]
      ndocs=[\$count [\$store:list-docs \$s]]
      gone=[?let [= \$_d [\$store:delete-doc \$s \$h]] [\$store:exists \$s \$h]]]]]
"
	r := run_s3_prog(env, hostport, prog)
	assert r.exit_code == 0, 's3 round trip failed (exit ${r.exit_code}): ${r.output}'
	// The doc fetched back over real SigV4-signed HTTP must contain its content
	// (proves a genuine write+read, not a synthesized success).
	assert r.output.contains('hello-s3'), 'get-doc did not round-trip the doc: ${r.output}'
	assert r.output.contains('exists=true'), 'exists should be true after put: ${r.output}'
	assert r.output.contains('ndocs=1'), 'list-docs should enumerate exactly the one written doc: ${r.output}'
	assert r.output.contains('gone=false'), 'delete-doc should remove the object (exists→false): ${r.output}'
}
