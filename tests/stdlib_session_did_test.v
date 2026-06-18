module main

import code
import crypto.ed25519
import encoding.hex

// TDD for cx-stdlib/session attach-did (spec/std-lib/did.md §7; xap_architecture
// §9.3): establish a (principal, tenant) session by DID proof-of-control. session
// is capability-free, so these run under eval_code's deny-all caps. Keys derived
// deterministically in V.

fn session_did_keys() (string, string) {
	mut seed := []u8{len: 32}
	for i in 0 .. 32 {
		seed[i] = u8(i + 7)
	}
	priv := ed25519.new_key_from_seed(seed)
	return hex.encode(priv.public_key()), hex.encode(seed)
}

const sd_preamble = "[?lib 'cx-stdlib/session' :as s]
[?lib 'cx-stdlib/did' :as did]
[?lib 'cx-stdlib/crypto' :as c]
[?lib 'cx-stdlib/bytes' :as b]
"

// Valid proof-of-control ⇒ a session bound to (DID-principal, tenant).
fn test_session_attach_did_establishes() {
	pub_hex, seed_hex := session_did_keys()
	prog := sd_preamble +
		"[?let [= \$did-id [\$did:key-create [\$b:from-hex \"${pub_hex}\"]]]
[?let [= \$chal [\$b:from-string-utf8 \"server-nonce-1\"]]
[?let [= \$sig [\$c:ed25519-sign [\$b:from-hex \"${seed_hex}\"] \$chal]]
  [\$s:attach-did \$did-id \$chal \$sig {tenant: \"acme\" allow-insecure: true}]]]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('did:key:z6Mk'), 'session should bind the DID principal, got: ${out}'
	assert out.contains('acme'), 'session should carry the tenant, got: ${out}'
	assert !out.contains('CXER48'), 'unexpected session fault: ${out}'
}

// A signature over a DIFFERENT challenge ⇒ token-rejected (CXER4801).
fn test_session_attach_did_rejects_bad_proof() {
	pub_hex, seed_hex := session_did_keys()
	prog := sd_preamble +
		"[?let [= \$did-id [\$did:key-create [\$b:from-hex \"${pub_hex}\"]]]
[?let [= \$sig [\$c:ed25519-sign [\$b:from-hex \"${seed_hex}\"] [\$b:from-string-utf8 \"the-wrong-nonce\"]]]
  [\$s:attach-did \$did-id [\$b:from-string-utf8 \"server-nonce-1\"] \$sig {tenant: \"acme\" allow-insecure: true}]]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('CXER4801'), 'expected token-rejected on bad proof, got: ${out}'
}

// No TLS attestation ⇒ insecure-transport (CXER4806), fail-closed.
fn test_session_attach_did_requires_tls() {
	pub_hex, seed_hex := session_did_keys()
	prog := sd_preamble +
		"[?let [= \$did-id [\$did:key-create [\$b:from-hex \"${pub_hex}\"]]]
[?let [= \$chal [\$b:from-string-utf8 \"server-nonce-1\"]]
[?let [= \$sig [\$c:ed25519-sign [\$b:from-hex \"${seed_hex}\"] \$chal]]
  [\$s:attach-did \$did-id \$chal \$sig {tenant: \"acme\"}]]]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('CXER4806'), 'expected insecure-transport without TLS, got: ${out}'
}
