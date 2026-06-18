module main

import code
import crypto.ed25519
import encoding.hex

// TDD for cx-stdlib/vc (spec/std-lib/vc.md). A VC is a signed, attenuating
// §22.2 delegation issued by a DID to a DID. Keys derived deterministically in
// V (fed as hex) so the CX programs stay pure + reproducible.

fn vc_issuer_keys() (string, string) {
	mut seed := []u8{len: 32}
	for i in 0 .. 32 {
		seed[i] = u8(255 - i)
	}
	priv := ed25519.new_key_from_seed(seed)
	return hex.encode(priv.public_key()), hex.encode(seed)
}

const vc_preamble = "[?lib 'cx-stdlib/vc' :as vc]
[?lib 'cx-stdlib/did' :as did]
[?lib 'cx-stdlib/bytes' :as b]
"

// issue → verify within the validity window ⇒ status=valid.
fn test_vc_issue_then_verify_valid() {
	pub_hex, seed_hex := vc_issuer_keys()
	prog := vc_preamble +
		"[?let [= \$iss [\$did:key-create [\$b:from-hex \"${pub_hex}\"]]]
[?let [= \$claim [delegation d1 [tenant acme] [capabilities [read]]]]
[?let [= \$cred [\$vc:issue \$iss [\$b:from-hex \"${seed_hex}\"] \$iss \$claim {id: \"urn:vc:1\" issued-at: 2026-06-16T12:00:00Z expires: 2026-06-16T13:00:00Z}]]
  [\$vc:verify \$cred 2026-06-16T12:30:00Z {}]]]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('status=valid'), 'expected status=valid, got: ${out}'
}

// A bogus signature ⇒ status=bad-signature (never a crash).
fn test_vc_bad_signature() {
	pub_hex, _ := vc_issuer_keys()
	prog := vc_preamble +
		"[?let [= \$iss [\$did:key-create [\$b:from-hex \"${pub_hex}\"]]]
[?let [= \$bad [vc id=\"urn:vc:x\" [issuer \$iss] [subject \$iss] [claim [delegation d1 [capabilities [read]]]] [proof type=Ed25519Signature2020 [verification-method \"x\"] [signature \"zBADBADBAD\"]]]]
  [\$vc:verify \$bad 2026-06-16T12:30:00Z {}]]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('status=bad-signature'), 'expected status=bad-signature, got: ${out}'
}

// now past `expires` ⇒ status=expired.
fn test_vc_expired() {
	pub_hex, seed_hex := vc_issuer_keys()
	prog := vc_preamble +
		"[?let [= \$iss [\$did:key-create [\$b:from-hex \"${pub_hex}\"]]]
[?let [= \$claim [delegation d1 [capabilities [read]]]]
[?let [= \$cred [\$vc:issue \$iss [\$b:from-hex \"${seed_hex}\"] \$iss \$claim {id: \"urn:vc:2\" issued-at: 2026-06-16T12:00:00Z expires: 2026-06-16T13:00:00Z}]]
  [\$vc:verify \$cred 2026-06-16T14:00:00Z {}]]]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('status=expired'), 'expected status=expired, got: ${out}'
}

// vc id present in the revoked set ⇒ status=revoked (decision #3a).
fn test_vc_revoked() {
	pub_hex, seed_hex := vc_issuer_keys()
	prog := vc_preamble +
		"[?let [= \$iss [\$did:key-create [\$b:from-hex \"${pub_hex}\"]]]
[?let [= \$claim [delegation d1 [capabilities [read]]]]
[?let [= \$cred [\$vc:issue \$iss [\$b:from-hex \"${seed_hex}\"] \$iss \$claim {id: \"urn:vc:3\" issued-at: 2026-06-16T12:00:00Z expires: 2026-06-16T13:00:00Z}]]
  [\$vc:verify \$cred 2026-06-16T12:30:00Z {revoked: \"urn:vc:3\"}]]]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('status=revoked'), 'expected status=revoked, got: ${out}'
}
