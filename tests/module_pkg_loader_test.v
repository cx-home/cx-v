module main

import os
import testenv
import time

// module_pkg_loader_test.v — BEHAVIORAL proof of the distribution spec's §6.2
// code-plane loading: `[?lib 'pkg:<name>@<version>[#<manifest-hash>]']`
// resolves a module from the CX_REGISTRY-bound store with the full §3 verify
// chain, and each refusal lane names its distribution code.
//
// Black-box like xap_registry_serve_real_test.v: a publish program (the
// registry/publish.cx pipeline in miniature) seeds a temp file:// registry
// with toylib@1.0.0 and toylib@1.1.0 (a real def, exports declared per §1.2),
// then consumer programs load via pkg: refs:
//
//   lane A  bare ref            [?lib 'pkg:toylib@1.0.0']    → def callable (42)
//   lane B  pinned ref          …#<manifest-hash of 1.0.0>   → def callable, alias unused
//   lane C  cross-version pin   …toylib@1.0.0#<hash of 1.1.0> → CXER4888 pin mismatch
//   lane D  unbound registry    CX_REGISTRY unset            → CXER4889
//   lane E  ref to nothing      pkg:absent@9.9.9             → CXER4886
//
// The tamper lane (CXER4881) is NOT retested here: a content-addressed store
// cannot carry tampered bytes under the original key; the dishonest-mirror
// lane is already fixture-covered at pkg-verify (xap-dist hash-mismatch case)
// and the loader delegates to that same chain.

fn mpl_cx_binary() string {
	return testenv.cx_bin()
}

fn mpl_write_tmp(dir string, name string, content string) string {
	p := os.join_path(dir, name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

// one publish program seeds both versions and prints the two manifest hashes.
fn mpl_publish_prog(reg_dir string) string {
	return "[?lib 'cx-xap' :as xap]\n" + "[?lib 'cx-stdlib/store' :as store]\n" +
		"[?lib 'cx-stdlib/crypto' :as crypto]\n" + "[?lib 'cx-stdlib/did' :as did]\n" +
		'[?let [= \$s [\$store:open "file://${reg_dir}"]]\n' +
		'[?let [= \$kp [\$crypto:ed25519-keypair]]\n' +
		'[?let [= \$pub [\$did:key-create \$kp@public]]\n' +
		'[?let [= \$code "[?def double scope=public (\$x) [+ \$x \$x]]"]\n' +
		'[?let [= \$t1 [\$xap:pkg-tree ([?element "entry" [?attr "path" "toylib.cx"] \$code])]]\n' +
		'[?let [= \$d1 [?element "package" [?attr "name" "toylib"] [?attr "version" "1.0.0"] [?attr "kind" "library"]\n' +
		'               [?element "publisher" [?attr "did" \$pub]]\n' +
		'               [?element "exports" [?element "def" [?attr "name" "toylib/double"]]]]]\n' +
		'[?let [= \$s1 [\$xap:pkg-seal \$s \$t1 \$d1]]\n' +
		'[?let [= \$m1 [\$store:put-doc \$s [\$xap:pkg-sign [\$store:get-doc \$s \$s1@manifest] \$kp@private]]]\n' +
		'[?let [= \$p1 [\$xap:pkg-publish \$s "toylib" "1.0.0" \$m1]]\n' +
		'[?let [= \$d2 [?element "package" [?attr "name" "toylib"] [?attr "version" "1.1.0"] [?attr "kind" "library"]\n' +
		'               [?element "publisher" [?attr "did" \$pub]]\n' +
		'               [?element "exports" [?element "def" [?attr "name" "toylib/double"]]]]]\n' +
		'[?let [= \$t2 [\$xap:pkg-tree ([?element "entry" [?attr "path" "toylib.cx"] \$code], [?element "entry" [?attr "path" "CHANGES.md"] "1.1"])]]\n' +
		'[?let [= \$s2 [\$xap:pkg-seal \$s \$t2 \$d2]]\n' +
		'[?let [= \$m2 [\$store:put-doc \$s [\$xap:pkg-sign [\$store:get-doc \$s \$s2@manifest] \$kp@private]]]\n' +
		'[?let [= \$p2 [\$xap:pkg-publish \$s "toylib" "1.1.0" \$m2]]\n' +
		'[\$concat \$m1 " " \$m2]]]]]]]]]]]]]]]\n'
}

fn mpl_consumer_prog(ref string) string {
	return "[?lib '${ref}' :as tl]\n" + '[\$tl:double 21]\n'
}

struct MplSetup {
	reg_url string
	m1      string
	m2      string
	tmp     string
}

fn mpl_setup() MplSetup {
	cxbin := mpl_cx_binary()
	tmp := os.join_path(os.temp_dir(), 'cx-mpl-test-${os.getpid()}')
	os.rmdir_all(tmp) or {}
	os.mkdir_all(tmp) or { panic('mkdir ${tmp}: ${err}') }
	reg := os.join_path(tmp, 'registry')
	os.mkdir_all(reg) or { panic('mkdir ${reg}: ${err}') }
	pub_prog := mpl_write_tmp(tmp, 'publish.cx', mpl_publish_prog(reg))
	res := os.execute('${cxbin} --allow-read --allow-write --allow-random ${pub_prog}')
	if res.exit_code != 0 {
		panic('publish program failed (${res.exit_code}): ${res.output}')
	}
	out := res.output.trim_space().trim("'")
	parts := out.split(' ')
	if parts.len != 2 || parts[0].len < 32 || parts[1].len < 32 {
		panic('unexpected publish output: ${res.output}')
	}
	return MplSetup{
		reg_url: 'file://${reg}'
		m1:      parts[0]
		m2:      parts[1]
		tmp:     tmp
	}
}

fn mpl_run(su MplSetup, ref string, bind_registry bool) os.Result {
	cxbin := mpl_cx_binary()
	prog := mpl_write_tmp(su.tmp, 'consume-${time.now().unix_nano()}.cx', mpl_consumer_prog(ref))
	if bind_registry {
		os.setenv('CX_REGISTRY', su.reg_url, true)
	} else {
		os.unsetenv('CX_REGISTRY')
	}
	res := os.execute('${cxbin} --allow-read ${prog}')
	os.unsetenv('CX_REGISTRY')
	return res
}

fn test_pkg_loader_lanes() {
	su := mpl_setup()
	defer {
		os.rmdir_all(su.tmp) or {}
	}

	// lane A — bare ref: alias-resolved, verified, def callable
	ra := mpl_run(su, 'pkg:toylib@1.0.0', true)
	assert ra.exit_code == 0, 'lane A failed: ${ra.output}'
	assert ra.output.contains('42'), 'lane A wrong result: ${ra.output}'

	// lane B — pinned ref: fetched BY manifest hash, alias table unused
	rb := mpl_run(su, 'pkg:toylib@1.0.0#${su.m1}', true)
	assert rb.exit_code == 0, 'lane B failed: ${rb.output}'
	assert rb.output.contains('42'), 'lane B wrong result: ${rb.output}'

	// lane C — pin of the OTHER version's manifest: refused, names 4888
	rc := mpl_run(su, 'pkg:toylib@1.0.0#${su.m2}', true)
	assert rc.exit_code != 0, 'lane C unexpectedly succeeded: ${rc.output}'
	assert rc.output.contains('CXER4888'), 'lane C wrong refusal: ${rc.output}'

	// lane D — no registry bound: refused, names 4889
	rd := mpl_run(su, 'pkg:toylib@1.0.0', false)
	assert rd.exit_code != 0, 'lane D unexpectedly succeeded: ${rd.output}'
	assert rd.output.contains('CXER4889'), 'lane D wrong refusal: ${rd.output}'

	// lane E — unpublished ref: refused, names 4886
	re := mpl_run(su, 'pkg:absent@9.9.9', true)
	assert re.exit_code != 0, 'lane E unexpectedly succeeded: ${re.output}'
	assert re.output.contains('CXER4886'), 'lane E wrong refusal: ${re.output}'
}
