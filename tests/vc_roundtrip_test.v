module main

import os
import testenv

// vc_roundtrip_test.v — VCs must verify OFFLINE after any emit→parse
// round-trip (file, store, wire): the market/entitlement design rests on
// committed credentials verifying without their issuing process. A parsed
// credential carries barewords as TextNodes (not ScalarNode strings), which
// vc_child_text rejected — every round-tripped VC verified as "malformed"
// while the identical claim verified fresh. M4's fixtures only covered fresh
// in-memory VCs, so the gap survived until the first committed VC
// (xap-store-console's gratis free-tier entitlements). Black-box against the
// real binary, like module_pkg_loader_test.v.

fn vcrt_cx_binary() string {
	return testenv.cx_bin()
}

fn vcrt_run(prog string) string {
	tmp := os.join_path(os.temp_dir(), 'cx-vcrt-${os.getpid()}.cx')
	os.write_file(tmp, prog) or { panic('write: ${err}') }
	defer {
		os.rm(tmp) or {}
	}
	res := os.execute('${vcrt_cx_binary()} --allow-random ${tmp}')
	if res.exit_code != 0 {
		panic('cx failed (${res.exit_code}): ${res.output}')
	}
	return res.output
}

const vcrt_perpetual = "
[?lib 'cx-xap' :as xap]
[?lib 'cx-stdlib/crypto' :as crypto]
[?lib 'cx-stdlib/did' :as did]
[?let [= \$kp [\$crypto:ed25519-keypair]]
 [= \$pub [\$did:key-create \$kp@public]]
 [= \$lic [\$xap:license-issue \$pub \$kp@private 'principal:alice' {package: 'pkg-a' versions: '0.x' kind: 'perpetual'}]]
 [= \$rt [\$cx:parse [\$cx:emit \$lic]]]
 [= \$lic2 [\$first [?for [in \$x \$rt//vc] [yield \$x]]]]
 [= \$v1 [\$xap:license-verify \$lic 'pkg-a' '0.1.0' {now: '2026-07-07T00:00:00Z'}]]
 [= \$v2 [\$xap:license-verify \$lic2 'pkg-a' '0.1.0' {now: '2026-07-07T00:00:00Z'}]]
 [\$concat 'fresh=' \$v1@status ' reparsed=' \$v2@status]]"

const vcrt_subscription = "
[?lib 'cx-xap' :as xap]
[?lib 'cx-stdlib/crypto' :as crypto]
[?lib 'cx-stdlib/did' :as did]
[?let [= \$kp [\$crypto:ed25519-keypair]]
 [= \$pub [\$did:key-create \$kp@public]]
 [= \$lic [\$xap:license-issue \$pub \$kp@private 'principal:alice' {package: 'pkg-a' versions: '0.x' expires: '2027-01-01T00:00:00Z' grace-until: '2027-02-01T00:00:00Z'}]]
 [= \$rt [\$cx:parse [\$cx:emit \$lic]]]
 [= \$lic2 [\$first [?for [in \$x \$rt//vc] [yield \$x]]]]
 [= \$v2 [\$xap:license-verify \$lic2 'pkg-a' '0.1.0' {now: '2026-07-07T00:00:00Z'}]]
 [\$concat 'reparsed=' \$v2@status]]"

fn test_vc_verifies_after_emit_parse_roundtrip() {
	out := vcrt_run(vcrt_perpetual)
	assert out.contains('fresh=ok'), 'fresh VC must verify: ${out}'
	assert out.contains('reparsed=ok'), 'ROUND-TRIPPED VC must verify (offline portability): ${out}'
}

fn test_vc_with_expiry_verifies_after_roundtrip() {
	// dates re-parse as TYPED scalars, not strings — extraction must
	// stringify those too (expires drives the grace-window logic).
	out := vcrt_run(vcrt_subscription)
	assert out.contains('reparsed=ok'), 'round-tripped subscription VC must verify: ${out}'
}
