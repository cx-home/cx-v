module main

import code
import crypto.ed25519
import encoding.hex

// TDD for cx-stdlib/did (spec/std-lib/did.md). Keys are derived
// deterministically in V from a fixed seed and fed as hex, so the whole CX
// program stays PURE (no capability grant needed) and the test is reproducible.

fn did_test_keys() (string, string) {
	mut seed := []u8{len: 32}
	for i in 0 .. 32 {
		seed[i] = u8(i + 1)
	}
	priv := ed25519.new_key_from_seed(seed)
	pubkey := priv.public_key()
	return hex.encode(pubkey), hex.encode(seed)
}

// did:key encodes an Ed25519 public key; the Ed25519 multicodec (0xed01)
// always yields the `z6Mk` multibase prefix.
fn test_did_key_create_prefix() {
	pub_hex, _ := did_test_keys()
	prog := "[?lib 'cx-stdlib/did' :as did]
[?lib 'cx-stdlib/bytes' :as b]
[\$did:key-create [\$b:from-hex \"${pub_hex}\"]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('did:key:z6Mk'), 'expected a did:key:z6Mk… string, got: ${out}'
}

// key-of(key-create(pub)) == pub  — the identifier round-trips to the key.
fn test_did_key_of_roundtrips() {
	pub_hex, _ := did_test_keys()
	prog := "[?lib 'cx-stdlib/did' :as did]
[?lib 'cx-stdlib/bytes' :as b]
[\$b:to-hex [\$did:key-of [\$did:key-create [\$b:from-hex \"${pub_hex}\"]]]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains(pub_hex), 'key-of did not round-trip to ${pub_hex}, got: ${out}'
}

// verify-control: a signature over a challenge by the key behind the DID verifies.
fn test_did_verify_control_true() {
	pub_hex, seed_hex := did_test_keys()
	prog := "[?lib 'cx-stdlib/did' :as did]
[?lib 'cx-stdlib/crypto' :as c]
[?lib 'cx-stdlib/bytes' :as b]
[?let [= \$did-id [\$did:key-create [\$b:from-hex \"${pub_hex}\"]]]
[?let [= \$chal [\$b:from-string-utf8 \"attach-nonce-42\"]]
[?let [= \$sig [\$c:ed25519-sign [\$b:from-hex \"${seed_hex}\"] \$chal]]
  [\$did:verify-control \$did-id \$chal \$sig]]]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('true'), 'expected verify-control true, got: ${out}'
}

// verify-control rejects a signature over a DIFFERENT challenge.
fn test_did_verify_control_false_on_wrong_challenge() {
	pub_hex, seed_hex := did_test_keys()
	prog := "[?lib 'cx-stdlib/did' :as did]
[?lib 'cx-stdlib/crypto' :as c]
[?lib 'cx-stdlib/bytes' :as b]
[?let [= \$did-id [\$did:key-create [\$b:from-hex \"${pub_hex}\"]]]
[?let [= \$sig [\$c:ed25519-sign [\$b:from-hex \"${seed_hex}\"] [\$b:from-string-utf8 \"the-real-nonce\"]]]
  [\$did:verify-control \$did-id [\$b:from-string-utf8 \"a-different-nonce\"] \$sig]]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('false'), 'expected verify-control false on wrong challenge, got: ${out}'
}

// document(did:key) is self-describing: its id is the DID itself.
fn test_did_document_self_describing() {
	pub_hex, _ := did_test_keys()
	prog := "[?lib 'cx-stdlib/did' :as did]
[?lib 'cx-stdlib/bytes' :as b]
[?let [= \$did-id [\$did:key-create [\$b:from-hex \"${pub_hex}\"]]]
  [\$did:document \$did-id]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('did-document'), 'expected a did-document element, got: ${out}'
	assert out.contains('did:key:z6Mk'), 'document should reference the DID, got: ${out}'
}

// did:web parses to method=web (resolution is a separate, networked path).
fn test_did_web_method() {
	prog := "[?lib 'cx-stdlib/did' :as did]
[\$did:method \"did:web:example.com:agents:radar\"]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('web'), 'expected method web, got: ${out}'
}

// A malformed DID is a typed error, not a crash.
fn test_did_malformed_errors() {
	prog := "[?lib 'cx-stdlib/did' :as did]
[\$did:method \"not-a-did\"]"
	out := code.eval_code('', prog, 'text') or {
		// throwing is also acceptable
		return
	}
	assert out.contains('CXER-DID-MALFORMED') || out.contains('err'),
		'expected a malformed-DID error, got: ${out}'
}
