module platform

import crypto.ed25519
import crypto.rand
import cx

// xsp_principal_mint.v — the OFFLINE identity mint behind `cx
// store-mint-principal` (#969, RULED: CO-5).
//
// A deny-by-default daemon (`[xsp [grants …]]` non-empty) admits exactly the
// principals the operator wrote into its config. Before this verb there was
// no shipped way to produce one, so a clean-state deployment had to conjure
// an ed25519 seed and a did:key by hand — the "provisioned out of band"
// shrug the #968 doc corrections recorded.
//
// The mint closes that gap without weakening the calculus: it generates a
// seed LOCALLY, derives the did:key from it LOCALLY, and hands the operator
// the two texts they need — the `[grant …]` row for the daemon config and
// the `xsp-did` / `xsp-seed-env` open-opts for the client. Nothing transits
// a wire, no store is opened, no trust-on-first-use registration happens,
// and no bearer is minted (G1a–G3a stand). Config remains the SOLE
// authority: minting an identity grants NOTHING until the operator splices
// the row in and the daemon reads it.

// XspMintedPrincipal is one freshly generated XSP-AUTH identity: the 32-byte
// Ed25519 seed (hex — the exact encoding `[xsp [identity seed-env=…]]` and
// the client's `xsp-seed-env` both decode) and the did:key it derives.
pub struct XspMintedPrincipal {
pub:
	seed_hex string
	did      string
}

// svc_mint_xsp_principal generates a fresh Ed25519 seed from the OS CSPRNG
// and derives its did:key. Pure-local: no network, no store, no filesystem —
// the caller owns where the seed comes to rest.
pub fn svc_mint_xsp_principal() !XspMintedPrincipal {
	seed := rand.bytes(32) or { return error('secure random generation failed: ${err.msg()}') }
	// Derivation self-check: the did MUST resolve back to the public key this
	// seed produces, because that is exactly the equality the daemon's
	// [xsp [identity]] loader and the client's open-opts loader both assert.
	// A mint that printed a did its own seed does not derive would hand the
	// operator a credential the daemon refuses.
	did := did_key_from_seed(seed)!
	declared := did_key_bytes(did)!
	derived := []u8(ed25519.new_key_from_seed(seed).public_key())
	if !xsp_auth_ct_eq(declared, derived) {
		return error('internal: minted did does not derive from the minted seed')
	}
	return XspMintedPrincipal{
		seed_hex: seed.hex()
		did:      did
	}
}

// svc_xsp_identity_attrs builds the daemon-side `[xsp [identity …]]`
// attribute row for `cx store-mint-principal --for identity` (RULED: CO-10,
// #985) — DRIVEN BY xsp_identity_attrs, the same list svc_parse_xsp
// (store_service.v) validates the row against.
//
// The loop is the point. The mint does not spell the attribute names a
// second time: it walks the parser's own list and supplies a value per name,
// so if that list ever grows a third attribute this function fails LOUDLY
// (the operator gets a refusal, not a stanza the daemon rejects at boot) and
// if it is ever renamed the mint renames with it. This is the xsp_grant_caps
// idiom applied to the identity row — mint and parser cannot drift.
pub fn svc_xsp_identity_attrs(did string, seed_env string) ![]cx.Attribute {
	mut attrs := []cx.Attribute{cap: xsp_identity_attrs.len}
	for name in xsp_identity_attrs {
		mut value := ''
		if name == 'did' {
			value = did
		} else if name == 'seed-env' {
			value = seed_env
		} else {
			return error('internal: [xsp [identity]] grew attribute "${name}" the mint does not supply')
		}
		if value == '' {
			return error('internal: [xsp [identity]] needs a non-empty ${name}')
		}
		attrs << cx.Attribute{
			name:  name
			value: cx.ScalarValue(value)
		}
	}
	return attrs
}

// svc_check_grant_caps validates a capability list against the one v1
// grammar (xsp_grant_caps) that svc_parse_xsp enforces, so the mint refuses
// to print a stanza the daemon would reject at startup.
pub fn svc_check_grant_caps(caps []string) ! {
	if caps.len == 0 {
		return error('caps must name at least one capability (${xsp_grant_caps.join(' ')})')
	}
	for c in caps {
		if c !in xsp_grant_caps {
			return error('unknown capability "${c}" (the v1 grammar: ${xsp_grant_caps.join(' ')})')
		}
	}
}
