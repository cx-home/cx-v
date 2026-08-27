module code

import cx
import crypto.sha256
import crypto.sha512
import crypto.blake3
import crypto.ed25519
import crypto.aes
import crypto.cipher
import crypto.argon2
import crypto.rand as crand
import math.big

// stdlib_crypto.v — native primitives backing the `cx-stdlib/crypto`
// module (spec/std-lib/crypto.md). Keyed / secret / authentication
// primitives are not expressible as pure CX `[?def]` bodies, so the
// bundle bodies (stdlib_bundle.v :: stdlib_src_crypto) forward to the
// `crypto-*` primitives dispatched here (see stdlib_dispatch.v).
//
// ── value model ──────────────────────────────────────────────────────
//   bytes  → ScalarType.bytes_type, raw octets carried as a string.
//   bool   → ScalarType.bool_type.   string → ScalarType.string_type.
//   hmac hasher → [hmac-hasher algo=<str> key=<bytes>] (§3.2). The
//                 hasher is observably immutable: update returns a fresh
//                 element carrying the accumulated buffer.
//   aead   → [aead algo=<str> ciphertext=<bytes> nonce=<bytes> tag=<bytes>]
//            (§3.7). Scalar bytes fields shape to ATTRIBUTES per the
//            simplest-adequate rule (eval.v append_result_field), so the
//            fixtures read `$ct@tag` / `$ct@nonce`.
//   keypair → [keypair public=<bytes> private=<bytes>] (§3.8).
//
// Errors are VALUE nodes (mk_err, eval.v) carrying the spec §5 codes
// CXER3700..CXER3707. The conformance runner matches the bare code in
// `out-err`.
//
// V provides crypto.sha256 / sha512 (digests + block size), crypto.blake3
// (sum_keyed256), crypto.ed25519 (RFC 8032), crypto.argon2 (Argon2id PHC).
// HMAC is implemented inline (ipad/opad over the V digests) so the
// streaming hasher can be observably-immutable. AES-256-GCM, ChaCha20-
// Poly1305 and X25519 are not in V's stdlib and are vendored below per
// their RFCs (no new C deps).

// ── spec §5 error codes ─────────────────────────────────────────────
const crypto_err_key      = 'cx-err:CXER3700' // E_CRYPTO_KEY_INVALID
const crypto_err_mac      = 'cx-err:CXER3701' // E_CRYPTO_MAC_VERIFY_FAILED
const crypto_err_length   = 'cx-err:CXER3703' // E_CRYPTO_LENGTH_INVALID
const crypto_err_aead     = 'cx-err:CXER3704' // E_CRYPTO_AEAD_AUTH_FAILED
const crypto_err_sig      = 'cx-err:CXER3705' // E_CRYPTO_SIGNATURE_INVALID
const crypto_err_password = 'cx-err:CXER3706' // E_CRYPTO_PASSWORD_VERIFY_FAILED
const crypto_err_nonce    = 'cx-err:CXER3707' // E_CRYPTO_NONCE_INVALID

// ── value builders ──────────────────────────────────────────────────

pub fn crypto_bytes_node(buf []u8) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(buf.bytestr())
		data_type: cx.ScalarType.bytes_type
	}
}

pub fn crypto_string_node(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	}
}

pub fn crypto_bool_node(b bool) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bool_type
	}
}

// crypto_arg_bytes extracts raw octets from a bytes/string scalar arg.
fn crypto_arg_bytes(n cx.Node) ?[]u8 {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v.bytes()
		}
	}
	note_operand_fault('crypto', 'crypto-', 'bytes', n)
	return none
}

fn crypto_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	note_operand_fault('crypto', 'crypto-', 'string', n)
	return none
}

fn crypto_arg_int(n cx.Node) ?i64 {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			i64 { return v }
			f64 { return i64(v) }
			else {}
		}
	}
	note_operand_fault('crypto', 'crypto-', 'int', n)
	return none
}

// crypto_bytes_attr builds a bytes-valued attribute. Scalar bytes shape
// to attributes per the simplest-adequate rule, so element-literal reads
// (`$x@name`) round-trip.
fn crypto_bytes_attr(name string, buf []u8) cx.Attribute {
	return cx.new_attribute(name, cx.ScalarValue(buf.bytestr()), cx.AttributeMeta{
		data_type: ?string('bytes')
	})
}

fn crypto_str_attr(name string, s string) cx.Attribute {
	return cx.new_attribute(name, cx.ScalarValue(s), cx.AttributeMeta{
		data_type: ?string(none)
	})
}

// crypto_read_field reads a named field off an element: a scalar
// attribute or a `[name value]` child element (the two simplest-adequate
// shapes). Returns the raw octets.
fn crypto_read_field_bytes(el cx.Element, name string) ?[]u8 {
	if sv := el.attr_val(name) {
		return cx.scalar_value_str_public(sv).bytes()
	}
	for it in el.items {
		if it is cx.Element && it.name == name && it.items.len > 0 {
			return crypto_arg_bytes(it.items[0])
		}
	}
	return none
}

fn crypto_read_field_str(el cx.Element, name string) ?string {
	if sv := el.attr_val(name) {
		return cx.scalar_value_str_public(sv)
	}
	for it in el.items {
		if it is cx.Element && it.name == name && it.items.len > 0 {
			return crypto_arg_str(it.items[0])
		}
	}
	return none
}

// ── HMAC (RFC 2104), inline over the V digests ──────────────────────
//
// algo → (block size, digest fn). Implementing inline (rather than via
// crypto.hmac.new) lets the streaming hasher accumulate chunks in an
// observably-immutable element value (§3.2 / §2.4).

fn crypto_hmac_params(algo string) ?(int, fn ([]u8) []u8) {
	match algo {
		'sha256' { return 64, sha256.sum256 }
		'sha384' { return 128, sha512.sum384 }
		'sha512' { return 128, sha512.sum512 }
		else { return none }
	}
}

// crypto_hmac computes HMAC(key, msg) for a supported algo.
pub fn crypto_hmac(algo string, key []u8, msg []u8) ?[]u8 {
	block_size, digest := crypto_hmac_params(algo)?
	mut k := key.clone()
	if k.len > block_size {
		k = digest(k)
	}
	if k.len < block_size {
		mut padded := []u8{len: block_size}
		for i in 0 .. k.len {
			padded[i] = k[i]
		}
		k = padded.clone()
	}
	mut ipad := []u8{len: block_size}
	mut opad := []u8{len: block_size}
	for i in 0 .. block_size {
		ipad[i] = k[i] ^ 0x36
		opad[i] = k[i] ^ 0x5c
	}
	mut inner := ipad.clone()
	inner << msg
	inner_digest := digest(inner)
	mut outer := opad.clone()
	outer << inner_digest
	return digest(outer)
}

// ── HKDF (RFC 5869) ─────────────────────────────────────────────────

pub fn crypto_hkdf_extract(algo string, salt []u8, ikm []u8) ?[]u8 {
	hash_len, _ := crypto_hmac_len(algo)?
	mut s := salt.clone()
	if s.len == 0 {
		s = []u8{len: hash_len}
	}
	return crypto_hmac(algo, s, ikm)
}

pub fn crypto_hkdf_expand(algo string, prk []u8, info []u8, length int) ?cx.Node {
	hash_len, _ := crypto_hmac_len(algo)?
	if length <= 0 || length > 255 * hash_len {
		return mk_err(crypto_err_length, 'E_CRYPTO_LENGTH_INVALID: length ${length} out of (0, ${255 * hash_len}]')
	}
	mut okm := []u8{cap: length}
	mut t := []u8{}
	mut counter := u8(1)
	for okm.len < length {
		mut input := t.clone()
		input << info
		input << counter
		t = crypto_hmac(algo, prk, input)?
		okm << t
		counter++
	}
	return crypto_bytes_node(okm[..length].clone())
}

// crypto_hmac_len returns (hash-len-bytes, block-size) for an algo.
fn crypto_hmac_len(algo string) ?(int, int) {
	match algo {
		'sha256' { return 32, 64 }
		'sha384' { return 48, 128 }
		'sha512' { return 64, 128 }
		else { return none }
	}
}

// ── dispatch ────────────────────────────────────────────────────────

// crypto_entropy_prims are the impure crypto surfaces that draw fresh
// OS/CSPRNG randomness (spec/std-lib/crypto.md §2.4) — AEAD nonce,
// Ed25519 / X25519 keypair generation, and Argon2id password hashing
// (random salt). They are gated under the `random` capability and
// denied fail-closed BEFORE any algorithm/key/cost validation (§4 /
// security.md). Every other crypto surface (HMAC, HKDF, keyed-BLAKE3,
// verify, sign, aead-decrypt, password-verify, shared-secret) is pure
// and ungated.
const crypto_entropy_prims = ['crypto-aead-encrypt', 'crypto-ed25519-keypair',
	'crypto-x25519-keypair', 'crypto-password-hash']

pub fn crypto_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	if name in crypto_entropy_prims {
		if d := cap_guard('random', name) {
			return d
		}
	}
	if name == 'crypto-jwks-fetch' {
		// §3.10: jwks-fetch GETs over cx-stdlib/http — net-gated on the URI.
		uri := crypto_arg_str(args[0]) or { '' }
		if d := cap_guard('net', uri) {
			return d
		}
	}
	match name {
		// ── §3.1 HMAC single-shot ───────────────────────────────────
		'crypto-hmac-sha256', 'crypto-hmac-sha384', 'crypto-hmac-sha512' {
			algo := name.all_after_last('-')
			key := crypto_arg_bytes(args[0]) or { return none }
			msg := crypto_arg_bytes(args[1]) or { return none }
			mac := crypto_hmac(algo, key, msg) or { return none }
			return crypto_bytes_node(mac)
		}

		// ── §3.2 HMAC streaming ─────────────────────────────────────
		'crypto-hmac-new' {
			algo := crypto_arg_str(args[0]) or { return none }
			key := crypto_arg_bytes(args[1]) or { return none }
			crypto_hmac_params(algo) or {
				return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: unknown HMAC algo "${algo}"')
			}
			return cx.Element{
				name:  'hmac-hasher'
				attrs: [
					crypto_str_attr('algo', algo),
					crypto_bytes_attr('key', key),
					crypto_bytes_attr('buffer', []u8{}),
				]
			}
		}
		'crypto-hmac-update' {
			h := args[0]
			chunk := crypto_arg_bytes(args[1]) or { return none }
			if h !is cx.Element {
				return none
			}
			el := h as cx.Element
			if el.name != 'hmac-hasher' {
				return none
			}
			algo := crypto_read_field_str(el, 'algo') or { return none }
			key := crypto_read_field_bytes(el, 'key') or { return none }
			mut buf := crypto_read_field_bytes(el, 'buffer') or { return none }
			buf << chunk
			return cx.Element{
				name:  'hmac-hasher'
				attrs: [
					crypto_str_attr('algo', algo),
					crypto_bytes_attr('key', key),
					crypto_bytes_attr('buffer', buf),
				]
			}
		}
		'crypto-hmac-finalize' {
			h := args[0]
			if h !is cx.Element {
				return none
			}
			el := h as cx.Element
			if el.name != 'hmac-hasher' {
				return none
			}
			algo := crypto_read_field_str(el, 'algo') or { return none }
			key := crypto_read_field_bytes(el, 'key') or { return none }
			buf := crypto_read_field_bytes(el, 'buffer') or { return none }
			mac := crypto_hmac(algo, key, buf) or { return none }
			return crypto_bytes_node(mac)
		}

		// ── §3.3 keyed-BLAKE3 ───────────────────────────────────────
		'crypto-blake3-keyed' {
			key := crypto_arg_bytes(args[0]) or { return none }
			msg := crypto_arg_bytes(args[1]) or { return none }
			if key.len != 32 {
				return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: BLAKE3 key must be 32 bytes, got ${key.len}')
			}
			return crypto_bytes_node(blake3.sum_keyed256(msg, key))
		}
		'crypto-blake3-mac-verify' {
			key := crypto_arg_bytes(args[0]) or { return none }
			msg := crypto_arg_bytes(args[1]) or { return none }
			expected := crypto_arg_bytes(args[2]) or { return none }
			if key.len != 32 {
				return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: BLAKE3 key must be 32 bytes, got ${key.len}')
			}
			got := blake3.sum_keyed256(msg, key)
			if !crypto_ct_equal(got, expected) {
				return mk_err(crypto_err_mac, 'E_CRYPTO_MAC_VERIFY_FAILED: BLAKE3 MAC mismatch')
			}
			return crypto_bool_node(true)
		}

		// ── §3.4 HKDF ───────────────────────────────────────────────
		'crypto-hkdf-extract', 'crypto-hkdf-extract-sha512' {
			algo := if name.ends_with('sha512') { 'sha512' } else { 'sha256' }
			salt := crypto_arg_bytes(args[0]) or { return none }
			ikm := crypto_arg_bytes(args[1]) or { return none }
			prk := crypto_hkdf_extract(algo, salt, ikm) or { return none }
			return crypto_bytes_node(prk)
		}
		'crypto-hkdf-expand', 'crypto-hkdf-expand-sha512' {
			algo := if name.ends_with('sha512') { 'sha512' } else { 'sha256' }
			prk := crypto_arg_bytes(args[0]) or { return none }
			info := crypto_arg_bytes(args[1]) or { return none }
			length := crypto_arg_int(args[2]) or { return none }
			return crypto_hkdf_expand(algo, prk, info, int(length))
		}
		'crypto-hkdf', 'crypto-hkdf-sha512' {
			algo := if name.ends_with('sha512') { 'sha512' } else { 'sha256' }
			ikm := crypto_arg_bytes(args[0]) or { return none }
			salt := crypto_arg_bytes(args[1]) or { return none }
			info := crypto_arg_bytes(args[2]) or { return none }
			length := crypto_arg_int(args[3]) or { return none }
			prk := crypto_hkdf_extract(algo, salt, ikm) or { return none }
			return crypto_hkdf_expand(algo, prk, info, int(length))
		}

		// ── §3.6 verification ───────────────────────────────────────
		'crypto-hmac-verify' {
			algo := crypto_arg_str(args[0]) or { return none }
			key := crypto_arg_bytes(args[1]) or { return none }
			msg := crypto_arg_bytes(args[2]) or { return none }
			expected := crypto_arg_bytes(args[3]) or { return none }
			crypto_hmac_params(algo) or {
				return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: unknown HMAC algo "${algo}"')
			}
			got := crypto_hmac(algo, key, msg) or { return none }
			if !crypto_ct_equal(got, expected) {
				return mk_err(crypto_err_mac, 'E_CRYPTO_MAC_VERIFY_FAILED: HMAC mismatch')
			}
			return crypto_bool_node(true)
		}

		// ── §3.7 AEAD ───────────────────────────────────────────────
		'crypto-aead-encrypt' {
			return crypto_aead_encrypt(args)
		}
		'crypto-aead-decrypt' {
			return crypto_aead_decrypt(args)
		}

		// ── §3.8 asymmetric ─────────────────────────────────────────
		'crypto-ed25519-keypair' {
			pub_key, priv := ed25519.generate_key() or {
				return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: keypair generation failed')
			}
			// `private` is the 32-byte seed (§3.8); priv is seed||public.
			seed := priv[..32].clone()
			return cx.Element{
				name:  'keypair'
				attrs: [
					crypto_bytes_attr('public', pub_key),
					crypto_bytes_attr('private', seed),
				]
			}
		}
		'crypto-ed25519-sign' {
			seed := crypto_arg_bytes(args[0]) or { return none }
			msg := crypto_arg_bytes(args[1]) or { return none }
			if seed.len != 32 {
				return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: Ed25519 seed must be 32 bytes, got ${seed.len}')
			}
			priv := ed25519.new_key_from_seed(seed)
			sig := priv.sign(msg) or {
				return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: signing failed')
			}
			return crypto_bytes_node(sig)
		}
		'crypto-ed25519-verify' {
			pub_key := crypto_arg_bytes(args[0]) or { return none }
			msg := crypto_arg_bytes(args[1]) or { return none }
			sig := crypto_arg_bytes(args[2]) or { return none }
			if pub_key.len != 32 || sig.len != 64 {
				return mk_err(crypto_err_sig, 'E_CRYPTO_SIGNATURE_INVALID: malformed key or signature')
			}
			ok := ed25519.verify(ed25519.PublicKey(pub_key), msg, sig) or {
				return mk_err(crypto_err_sig, 'E_CRYPTO_SIGNATURE_INVALID: verification error')
			}
			if !ok {
				return mk_err(crypto_err_sig, 'E_CRYPTO_SIGNATURE_INVALID: signature does not verify')
			}
			return crypto_bool_node(true)
		}
		'crypto-x25519-keypair' {
			priv := crypto_random_octets(32) or {
				return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: entropy unavailable')
			}
			mut sk := priv.clone()
			x25519_clamp(mut sk)
			pub_key := x25519_scalar_base_mult(sk)
			return cx.Element{
				name:  'keypair'
				attrs: [
					crypto_bytes_attr('public', pub_key),
					crypto_bytes_attr('private', sk),
				]
			}
		}
		'crypto-x25519-shared-secret' {
			priv := crypto_arg_bytes(args[0]) or { return none }
			peer := crypto_arg_bytes(args[1]) or { return none }
			if priv.len != 32 || peer.len != 32 {
				return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: X25519 keys must be 32 bytes')
			}
			mut sk := priv.clone()
			x25519_clamp(mut sk)
			return crypto_bytes_node(x25519_scalar_mult(sk, peer))
		}

		// ── §3.8 rsa-verify / ecdsa-verify ──────────────────────────
		'crypto-rsa-verify' {
			return crypto_rsa_verify_node(args)
		}
		'crypto-ecdsa-verify' {
			return crypto_ecdsa_verify_node(args)
		}

		// ── §3.10 JWT / JWKS ────────────────────────────────────────
		'crypto-jwt-verify' {
			return crypto_jwt_verify(args)
		}
		'crypto-jwks-fetch' {
			return crypto_jwks_fetch(args)
		}
		'crypto-jwks-parse' {
			json_text := crypto_arg_str(args[0]) or { return none }
			return crypto_jwks_parse(json_text)
		}
		'crypto-claim' {
			name_arg := crypto_arg_str(args[1]) or { return none }
			return crypto_claim(args[0], name_arg)
		}
		'crypto-jwk-by-kid' {
			kid := crypto_arg_str(args[1]) or { return none }
			return crypto_jwk_by_kid(args[0], kid)
		}

		// ── §3.9 password hashing ───────────────────────────────────
		'crypto-password-hash' {
			return crypto_password_hash(args)
		}
		'crypto-password-verify' {
			password := crypto_arg_bytes(args[0]) or { return none }
			encoded := crypto_arg_str(args[1]) or { return none }
			argon2.compare_hash_and_password(password, encoded.bytes()) or {
				return mk_err(crypto_err_password, 'E_CRYPTO_PASSWORD_VERIFY_FAILED: ${err.msg()}')
			}
			return crypto_bool_node(true)
		}

		else {
			return none
		}
	}
}

// crypto_ct_equal compares two byte buffers in constant time over the
// shorter length, with an unconditional length check (§2.2).
pub fn crypto_ct_equal(a []u8, b []u8) bool {
	if a.len != b.len {
		return false
	}
	mut diff := u8(0)
	for i in 0 .. a.len {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// crypto_password_hash implements §3.9 password-hash via Argon2id PHC.
fn crypto_password_hash(args []cx.Node) cx.Node {
	password := crypto_arg_bytes(args[0]) or {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: password must be bytes')
	}
	cost := args[1]
	if cost !is cx.Element {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: cost must be an [argon2-cost …] element')
	}
	cel := cost as cx.Element
	if cel.name != 'argon2-cost' {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: cost must be an [argon2-cost …] element')
	}
	memory := crypto_cost_field(cel, 'memory-kib')
	iterations := crypto_cost_field(cel, 'iterations')
	parallelism := crypto_cost_field(cel, 'parallelism')
	if memory <= 0 || iterations <= 0 || parallelism <= 0 {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: malformed argon2-cost (m=${memory} t=${iterations} p=${parallelism})')
	}
	params := argon2.Params{
		time:    u32(iterations)
		memory:  u32(memory)
		threads: u8(parallelism)
		key_len: 32
	}
	enc := argon2.generate_from_password_with_params(password, params) or {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: ${err.msg()}')
	}
	return crypto_string_node(enc)
}

// crypto_cost_field reads an int cost field from the [argon2-cost …]
// element (attribute or `[name value]` child); -1 when absent/malformed.
fn crypto_cost_field(el cx.Element, name string) i64 {
	if sv := el.attr_val(name) {
		return cx.scalar_value_str_public(sv).i64()
	}
	for it in el.items {
		if it is cx.Element && it.name == name && it.items.len > 0 {
			if v := crypto_arg_int(it.items[0]) {
				return v
			}
		}
	}
	return -1
}

// ── AEAD: AES-256-GCM + ChaCha20-Poly1305 ───────────────────────────

fn crypto_aead_encrypt(args []cx.Node) cx.Node {
	algo := crypto_arg_str(args[0]) or {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: algo must be a string')
	}
	key := crypto_arg_bytes(args[1]) or {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: key must be bytes')
	}
	plaintext := crypto_arg_bytes(args[2]) or {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: plaintext must be bytes')
	}
	aad := crypto_arg_bytes(args[3]) or {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: aad must be bytes')
	}
	if algo != 'aes-256-gcm' && algo != 'chacha20-poly1305' {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: unknown AEAD algo "${algo}"')
	}
	if key.len != 32 {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: AEAD key must be 32 bytes, got ${key.len}')
	}
	nonce := crypto_random_octets(12) or {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: entropy unavailable')
	}
	mut ciphertext := []u8{}
	mut tag := []u8{}
	if algo == 'aes-256-gcm' {
		ciphertext, tag = aes_gcm_seal(key, nonce, plaintext, aad) or {
			return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: AES-GCM error')
		}
	} else {
		ciphertext, tag = chacha20poly1305_seal(key, nonce, plaintext, aad)
	}
	return cx.Element{
		name:  'aead'
		attrs: [
			crypto_str_attr('algo', algo),
			crypto_bytes_attr('ciphertext', ciphertext),
			crypto_bytes_attr('nonce', nonce),
			crypto_bytes_attr('tag', tag),
		]
	}
}

fn crypto_aead_decrypt(args []cx.Node) cx.Node {
	algo := crypto_arg_str(args[0]) or {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: algo must be a string')
	}
	key := crypto_arg_bytes(args[1]) or {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: key must be bytes')
	}
	aead := args[2]
	aad := crypto_arg_bytes(args[3]) or {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: aad must be bytes')
	}
	if algo != 'aes-256-gcm' && algo != 'chacha20-poly1305' {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: unknown AEAD algo "${algo}"')
	}
	if key.len != 32 {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: AEAD key must be 32 bytes, got ${key.len}')
	}
	if aead !is cx.Element {
		return mk_err(crypto_err_aead, 'E_CRYPTO_AEAD_AUTH_FAILED: malformed aead value')
	}
	ael := aead as cx.Element
	ciphertext := crypto_read_field_bytes(ael, 'ciphertext') or {
		return mk_err(crypto_err_aead, 'E_CRYPTO_AEAD_AUTH_FAILED: missing ciphertext')
	}
	nonce := crypto_read_field_bytes(ael, 'nonce') or {
		return mk_err(crypto_err_nonce, 'E_CRYPTO_NONCE_INVALID: missing nonce')
	}
	tag := crypto_read_field_bytes(ael, 'tag') or {
		return mk_err(crypto_err_nonce, 'E_CRYPTO_NONCE_INVALID: missing tag')
	}
	if nonce.len != 12 {
		return mk_err(crypto_err_nonce, 'E_CRYPTO_NONCE_INVALID: nonce must be 12 bytes, got ${nonce.len}')
	}
	if tag.len != 16 {
		return mk_err(crypto_err_nonce, 'E_CRYPTO_NONCE_INVALID: tag must be 16 bytes, got ${tag.len}')
	}
	mut plaintext := []u8{}
	mut ok := false
	if algo == 'aes-256-gcm' {
		plaintext, ok = aes_gcm_open(key, nonce, ciphertext, tag, aad) or {
			return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: AES-GCM error')
		}
	} else {
		plaintext, ok = chacha20poly1305_open(key, nonce, ciphertext, tag, aad)
	}
	if !ok {
		return mk_err(crypto_err_aead, 'E_CRYPTO_AEAD_AUTH_FAILED: authentication tag mismatch')
	}
	return crypto_bytes_node(plaintext)
}

// random_crypto_bytes reads n fresh OS/CSPRNG bytes. Moved here from the
// random pack file (I4, #651/#516): crypto's entropy-drawing surfaces must
// survive in artifacts built with `-d cx_no_pack_random`; both files share
// this ONE definition (same module).
fn random_crypto_bytes(n int) ?string {
	if n < 0 {
		return none
	}
	if n == 0 {
		return ''
	}
	buf := crand.bytes(n) or { return none }
	return buf.bytestr()
}

// crypto_random_octets draws n fresh CSPRNG bytes (shared with the
// random module's source). Returns none on entropy failure.
pub fn crypto_random_octets(n int) ?[]u8 {
	s := random_crypto_bytes(n)?
	return s.bytes()
}

// ════════════════════════════════════════════════════════════════════
// Vendored primitives not present in V's stdlib.
// ════════════════════════════════════════════════════════════════════

// ── AES-256-GCM (NIST SP 800-38D), over crypto.aes block ────────────
//
// Counter mode with GHASH over GF(2^128). 12-byte nonce → J0 = nonce ||
// 0x00000001 (the §7.1 standard case). Tag is GHASH(AAD, C) ⊕ E(K, J0).

fn gcm_block(c cipher.Block, src []u8) []u8 {
	mut dst := []u8{len: 16}
	c.encrypt(mut dst, src)
	return dst
}

// gf_mult multiplies two 128-bit blocks in GF(2^128) (GCM bit-reflected
// polynomial x^128 + x^7 + x^2 + x + 1, reduction constant 0xe1…).
fn gf_mult(x []u8, y []u8) []u8 {
	mut z := []u8{len: 16}
	mut v := y.clone()
	for i in 0 .. 128 {
		bit := (x[i / 8] >> (7 - u8(i % 8))) & 1
		if bit == 1 {
			for j in 0 .. 16 {
				z[j] ^= v[j]
			}
		}
		// v = v >> 1, with reduction when the low bit was set.
		mut lsb := v[15] & 1
		for j := 15; j > 0; j-- {
			v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7)
		}
		v[0] = v[0] >> 1
		if lsb == 1 {
			v[0] ^= 0xe1
		}
	}
	return z
}

// ghash computes the GHASH of data under hash subkey h (zero-padded
// per 16-byte block).
fn ghash(h []u8, data []u8) []u8 {
	mut y := []u8{len: 16}
	mut i := 0
	for i < data.len {
		mut block := []u8{len: 16}
		end := if i + 16 <= data.len { i + 16 } else { data.len }
		for j in i .. end {
			block[j - i] = data[j]
		}
		for j in 0 .. 16 {
			y[j] ^= block[j]
		}
		y = gf_mult(y, h)
		i += 16
	}
	return y
}

// gcm_inc32 increments the low 32 bits of a 16-byte counter block.
fn gcm_inc32(mut ctr []u8) {
	mut n := u32(ctr[12]) << 24 | u32(ctr[13]) << 16 | u32(ctr[14]) << 8 | u32(ctr[15])
	n += 1
	ctr[12] = u8(n >> 24)
	ctr[13] = u8(n >> 16)
	ctr[14] = u8(n >> 8)
	ctr[15] = u8(n)
}

// gcm_ctr applies AES-CTR starting at counter j0+1, returning input
// xored with the keystream.
fn gcm_ctr(c cipher.Block, j0 []u8, input []u8) []u8 {
	mut ctr := j0.clone()
	mut out := []u8{cap: input.len}
	mut i := 0
	for i < input.len {
		gcm_inc32(mut ctr)
		ks := gcm_block(c, ctr)
		end := if i + 16 <= input.len { i + 16 } else { input.len }
		for j in i .. end {
			out << input[j] ^ ks[j - i]
		}
		i += 16
	}
	return out
}

// gcm_lengths builds the 16-byte trailing block: len(AAD)·8 || len(C)·8
// as 64-bit big-endian values.
fn gcm_lengths(aad_len int, c_len int) []u8 {
	mut b := []u8{len: 16}
	a_bits := u64(aad_len) * 8
	c_bits := u64(c_len) * 8
	for i in 0 .. 8 {
		b[7 - i] = u8(a_bits >> (u32(i) * 8))
		b[15 - i] = u8(c_bits >> (u32(i) * 8))
	}
	return b
}

fn gcm_tag(h []u8, ej0 []u8, aad []u8, ciphertext []u8) []u8 {
	mut s := []u8{cap: aad.len + ciphertext.len + 32}
	s << aad
	gcm_pad16(mut s)
	s << ciphertext
	gcm_pad16(mut s)
	s << gcm_lengths(aad.len, ciphertext.len)
	g := ghash(h, s)
	mut tag := []u8{len: 16}
	for i in 0 .. 16 {
		tag[i] = g[i] ^ ej0[i]
	}
	return tag
}

fn gcm_pad16(mut s []u8) {
	for s.len % 16 != 0 {
		s << u8(0)
	}
}

fn aes_gcm_seal(key []u8, nonce []u8, plaintext []u8, aad []u8) ?([]u8, []u8) {
	c := aes.new_cipher(key)
	h := gcm_block(c, []u8{len: 16})
	mut j0 := nonce.clone()
	j0 << [u8(0), 0, 0, 1]
	ciphertext := gcm_ctr(c, j0, plaintext)
	ej0 := gcm_block(c, j0)
	tag := gcm_tag(h, ej0, aad, ciphertext)
	return ciphertext, tag
}

fn aes_gcm_open(key []u8, nonce []u8, ciphertext []u8, tag []u8, aad []u8) ?([]u8, bool) {
	c := aes.new_cipher(key)
	h := gcm_block(c, []u8{len: 16})
	mut j0 := nonce.clone()
	j0 << [u8(0), 0, 0, 1]
	ej0 := gcm_block(c, j0)
	want := gcm_tag(h, ej0, aad, ciphertext)
	if !crypto_ct_equal(want, tag) {
		return []u8{}, false
	}
	plaintext := gcm_ctr(c, j0, ciphertext)
	return plaintext, true
}

// ── ChaCha20-Poly1305 AEAD (RFC 8439) ───────────────────────────────

fn chacha_rotl(x u32, n u32) u32 {
	return (x << n) | (x >> (32 - n))
}

fn chacha_quarter_round(mut s []u32, a int, b int, c int, d int) {
	s[a] += s[b]  s[d] ^= s[a]  s[d] = chacha_rotl(s[d], 16)
	s[c] += s[d]  s[b] ^= s[c]  s[b] = chacha_rotl(s[b], 12)
	s[a] += s[b]  s[d] ^= s[a]  s[d] = chacha_rotl(s[d], 8)
	s[c] += s[d]  s[b] ^= s[c]  s[b] = chacha_rotl(s[b], 7)
}

fn le32(b []u8, off int) u32 {
	return u32(b[off]) | u32(b[off + 1]) << 8 | u32(b[off + 2]) << 16 | u32(b[off + 3]) << 24
}

// chacha20_block produces the 64-byte keystream block for counter.
fn chacha20_block(key []u8, counter u32, nonce []u8) []u8 {
	mut s := []u32{len: 16}
	s[0] = 0x61707865
	s[1] = 0x3320646e
	s[2] = 0x79622d32
	s[3] = 0x6b206574
	for i in 0 .. 8 {
		s[4 + i] = le32(key, i * 4)
	}
	s[12] = counter
	s[13] = le32(nonce, 0)
	s[14] = le32(nonce, 4)
	s[15] = le32(nonce, 8)
	mut w := s.clone()
	for _ in 0 .. 10 {
		chacha_quarter_round(mut w, 0, 4, 8, 12)
		chacha_quarter_round(mut w, 1, 5, 9, 13)
		chacha_quarter_round(mut w, 2, 6, 10, 14)
		chacha_quarter_round(mut w, 3, 7, 11, 15)
		chacha_quarter_round(mut w, 0, 5, 10, 15)
		chacha_quarter_round(mut w, 1, 6, 11, 12)
		chacha_quarter_round(mut w, 2, 7, 8, 13)
		chacha_quarter_round(mut w, 3, 4, 9, 14)
	}
	mut out := []u8{len: 64}
	for i in 0 .. 16 {
		v := w[i] + s[i]
		out[i * 4] = u8(v)
		out[i * 4 + 1] = u8(v >> 8)
		out[i * 4 + 2] = u8(v >> 16)
		out[i * 4 + 3] = u8(v >> 24)
	}
	return out
}

// chacha20_xor encrypts/decrypts input under (key, nonce) starting at the
// given block counter.
fn chacha20_xor(key []u8, counter u32, nonce []u8, input []u8) []u8 {
	mut out := []u8{cap: input.len}
	mut ctr := counter
	mut i := 0
	for i < input.len {
		ks := chacha20_block(key, ctr, nonce)
		end := if i + 64 <= input.len { i + 64 } else { input.len }
		for j in i .. end {
			out << input[j] ^ ks[j - i]
		}
		ctr += 1
		i += 64
	}
	return out
}

// ── Poly1305 (RFC 8439 §2.5) over 130-bit arithmetic via u32 limbs ──

fn poly1305_mac(key []u8, msg []u8) []u8 {
	// r (clamped) + s, little-endian 16-byte halves.
	mut r := [u64(0), 0, 0, 0, 0]
	mut h := [u64(0), 0, 0, 0, 0]
	// Load r as 5 26-bit limbs with the RFC clamp.
	t0 := le32(key, 0)
	t1 := le32(key, 4)
	t2 := le32(key, 8)
	t3 := le32(key, 12)
	r[0] = u64(t0 & 0x3ffffff)
	r[1] = u64(((u64(t1) << 32 | u64(t0)) >> 26) & 0x3ffffff)
	r[2] = u64(((u64(t2) << 32 | u64(t1)) >> 20) & 0x3ffc0ff)
	r[3] = u64(((u64(t3) << 32 | u64(t2)) >> 14) & 0x3f03fff)
	r[4] = u64((u64(t3) >> 8) & 0x00fffff)
	s1 := r[1] * 5
	s2 := r[2] * 5
	s3 := r[3] * 5
	s4 := r[4] * 5
	mut i := 0
	for i < msg.len {
		end := if i + 16 <= msg.len { i + 16 } else { msg.len }
		mut block := []u8{len: 17}
		for j in i .. end {
			block[j - i] = msg[j]
		}
		block[end - i] = 1
		b0 := le32(block, 0)
		b1 := le32(block, 4)
		b2 := le32(block, 8)
		b3 := le32(block, 12)
		hibit := u64(block[16])
		h[0] += u64(b0 & 0x3ffffff)
		h[1] += u64(((u64(b1) << 32 | u64(b0)) >> 26) & 0x3ffffff)
		h[2] += u64(((u64(b2) << 32 | u64(b1)) >> 20) & 0x3ffffff)
		h[3] += u64(((u64(b3) << 32 | u64(b2)) >> 14) & 0x3ffffff)
		h[4] += u64((u64(b3) >> 8) | (hibit << 24))
		// h *= r mod (2^130 - 5)
		d0 := h[0] * r[0] + h[1] * s4 + h[2] * s3 + h[3] * s2 + h[4] * s1
		d1 := h[0] * r[1] + h[1] * r[0] + h[2] * s4 + h[3] * s3 + h[4] * s2
		d2 := h[0] * r[2] + h[1] * r[1] + h[2] * r[0] + h[3] * s4 + h[4] * s3
		d3 := h[0] * r[3] + h[1] * r[2] + h[2] * r[1] + h[3] * r[0] + h[4] * s4
		d4 := h[0] * r[4] + h[1] * r[3] + h[2] * r[2] + h[3] * r[1] + h[4] * r[0]
		mut c := u64(0)
		mut nd0 := d0
		c = nd0 >> 26
		h[0] = nd0 & 0x3ffffff
		nd1 := d1 + c
		c = nd1 >> 26
		h[1] = nd1 & 0x3ffffff
		nd2 := d2 + c
		c = nd2 >> 26
		h[2] = nd2 & 0x3ffffff
		nd3 := d3 + c
		c = nd3 >> 26
		h[3] = nd3 & 0x3ffffff
		nd4 := d4 + c
		c = nd4 >> 26
		h[4] = nd4 & 0x3ffffff
		h[0] += c * 5
		c = h[0] >> 26
		h[0] = h[0] & 0x3ffffff
		h[1] += c
		i += 16
	}
	// Final reduction / carry propagation.
	mut c := h[1] >> 26
	h[1] = h[1] & 0x3ffffff
	h[2] += c
	c = h[2] >> 26
	h[2] = h[2] & 0x3ffffff
	h[3] += c
	c = h[3] >> 26
	h[3] = h[3] & 0x3ffffff
	h[4] += c
	c = h[4] >> 26
	h[4] = h[4] & 0x3ffffff
	h[0] += c * 5
	c = h[0] >> 26
	h[0] = h[0] & 0x3ffffff
	h[1] += c
	// Compute h - p and select.
	mut g := [u64(0), 0, 0, 0, 0]
	g[0] = h[0] + 5
	c = g[0] >> 26
	g[0] = g[0] & 0x3ffffff
	g[1] = h[1] + c
	c = g[1] >> 26
	g[1] = g[1] & 0x3ffffff
	g[2] = h[2] + c
	c = g[2] >> 26
	g[2] = g[2] & 0x3ffffff
	g[3] = h[3] + c
	c = g[3] >> 26
	g[3] = g[3] & 0x3ffffff
	g[4] = h[4] + c - (u64(1) << 26)
	mask := (g[4] >> 63) - 1 // 0xff..ff if g[4] did NOT borrow → use g
	mut nmask := ~mask
	for j in 0 .. 5 {
		h[j] = (h[j] & nmask) | (g[j] & mask)
	}
	// Serialize h (26-bit limbs) to a 128-bit little-endian value.
	mut f := [u64(0), 0, 0, 0]
	f[0] = (h[0] | (h[1] << 26)) & 0xffffffff
	f[1] = ((h[1] >> 6) | (h[2] << 20)) & 0xffffffff
	f[2] = ((h[2] >> 12) | (h[3] << 14)) & 0xffffffff
	f[3] = ((h[3] >> 18) | (h[4] << 8)) & 0xffffffff
	// Add s.
	mut acc := u64(0)
	mut out := []u8{len: 16}
	for j in 0 .. 4 {
		acc += f[j] + u64(le32(key, 16 + j * 4))
		out[j * 4] = u8(acc)
		out[j * 4 + 1] = u8(acc >> 8)
		out[j * 4 + 2] = u8(acc >> 16)
		out[j * 4 + 3] = u8(acc >> 24)
		acc = acc >> 32
	}
	return out
}

// poly1305_key derives the one-time Poly1305 key from the ChaCha20
// keystream block 0 (RFC 8439 §2.6).
fn poly1305_key(key []u8, nonce []u8) []u8 {
	block := chacha20_block(key, 0, nonce)
	return block[..32].clone()
}

// chacha_aead_input builds the Poly1305 input: AAD || pad16 || C ||
// pad16 || len(AAD) || len(C) (each 8-byte little-endian).
fn chacha_aead_input(aad []u8, ciphertext []u8) []u8 {
	mut s := []u8{}
	s << aad
	for s.len % 16 != 0 {
		s << u8(0)
	}
	s << ciphertext
	for s.len % 16 != 0 {
		s << u8(0)
	}
	mut lens := []u8{len: 16}
	a := u64(aad.len)
	c := u64(ciphertext.len)
	for i in 0 .. 8 {
		lens[i] = u8(a >> (u32(i) * 8))
		lens[8 + i] = u8(c >> (u32(i) * 8))
	}
	s << lens
	return s
}

fn chacha20poly1305_seal(key []u8, nonce []u8, plaintext []u8, aad []u8) ([]u8, []u8) {
	otk := poly1305_key(key, nonce)
	ciphertext := chacha20_xor(key, 1, nonce, plaintext)
	tag := poly1305_mac(otk, chacha_aead_input(aad, ciphertext))
	return ciphertext, tag
}

fn chacha20poly1305_open(key []u8, nonce []u8, ciphertext []u8, tag []u8, aad []u8) ([]u8, bool) {
	otk := poly1305_key(key, nonce)
	want := poly1305_mac(otk, chacha_aead_input(aad, ciphertext))
	if !crypto_ct_equal(want, tag) {
		return []u8{}, false
	}
	plaintext := chacha20_xor(key, 1, nonce, ciphertext)
	return plaintext, true
}

// ── X25519 (RFC 7748) — Montgomery ladder over GF(2^255 - 19) ───────

pub fn x25519_clamp(mut k []u8) {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
}

// ── X25519 field arithmetic: radix-2^51, 5×u64 limbs (ref10 style) ──
//
// A field element is five u64 limbs h0..h4 each holding ~51 bits, value =
// h0 + h1·2^51 + h2·2^102 + h3·2^153 + h4·2^204 (mod p = 2^255 - 19).
// This representation keeps every limb well below 2^64 after a carry pass,
// giving clean, input-independent modular arithmetic.

const fe_mask51 = u64(0x7ffffffffffff) // 2^51 - 1

struct Fe {
mut:
	l [5]u64
}

fn load64_le(b []u8, off int) u64 {
	mut v := u64(0)
	for i in 0 .. 8 {
		v |= u64(b[off + i]) << (u32(i) * 8)
	}
	return v
}

fn fe_from_bytes(b []u8) Fe {
	mut f := Fe{}
	f.l[0] = load64_le(b, 0) & fe_mask51
	f.l[1] = (load64_le(b, 6) >> 3) & fe_mask51
	f.l[2] = (load64_le(b, 12) >> 6) & fe_mask51
	f.l[3] = (load64_le(b, 19) >> 1) & fe_mask51
	f.l[4] = (load64_le(b, 24) >> 12) & fe_mask51
	return f
}

// fe_carry normalizes limbs so each is < 2^51, folding the top carry ×19.
fn fe_carry(mut f Fe) {
	mut c := u64(0)
	c = f.l[0] >> 51
	f.l[0] &= fe_mask51
	f.l[1] += c
	c = f.l[1] >> 51
	f.l[1] &= fe_mask51
	f.l[2] += c
	c = f.l[2] >> 51
	f.l[2] &= fe_mask51
	f.l[3] += c
	c = f.l[3] >> 51
	f.l[3] &= fe_mask51
	f.l[4] += c
	c = f.l[4] >> 51
	f.l[4] &= fe_mask51
	f.l[0] += c * 19
	c = f.l[0] >> 51
	f.l[0] &= fe_mask51
	f.l[1] += c
}

fn fe_to_bytes(f Fe) []u8 {
	mut t := f
	fe_carry(mut t)
	// Conditionally subtract p = 2^255 - 19 to reach canonical form.
	// q = (h + 19) / 2^255 — whether h >= p.
	mut q := (t.l[0] + 19) >> 51
	q = (t.l[1] + q) >> 51
	q = (t.l[2] + q) >> 51
	q = (t.l[3] + q) >> 51
	q = (t.l[4] + q) >> 51
	t.l[0] += 19 * q
	t.l[1] += t.l[0] >> 51
	t.l[0] &= fe_mask51
	t.l[2] += t.l[1] >> 51
	t.l[1] &= fe_mask51
	t.l[3] += t.l[2] >> 51
	t.l[2] &= fe_mask51
	t.l[4] += t.l[3] >> 51
	t.l[3] &= fe_mask51
	t.l[4] &= fe_mask51
	// Pack 5×51-bit limbs into 32 little-endian bytes.
	mut acc := [u64(0), 0, 0, 0]
	acc[0] = t.l[0] | (t.l[1] << 51)
	acc[1] = (t.l[1] >> 13) | (t.l[2] << 38)
	acc[2] = (t.l[2] >> 26) | (t.l[3] << 25)
	acc[3] = (t.l[3] >> 39) | (t.l[4] << 12)
	mut out := []u8{len: 32}
	for i in 0 .. 4 {
		for j in 0 .. 8 {
			out[i * 8 + j] = u8(acc[i] >> (u32(j) * 8))
		}
	}
	return out
}

fn fe_zero() Fe {
	return Fe{}
}

fn fe_one() Fe {
	mut f := Fe{}
	f.l[0] = 1
	return f
}

fn fe_add(a Fe, b Fe) Fe {
	mut r := Fe{}
	for i in 0 .. 5 {
		r.l[i] = a.l[i] + b.l[i]
	}
	return r
}

// fe_sub computes a - b. Adds 2·p (per-limb biased) to stay non-negative
// before the subtraction, then carries.
fn fe_sub(a Fe, b Fe) Fe {
	mut r := Fe{}
	// 2p limbs: 2*(2^51-1) for low limbs, with the -19 fold on limb 0.
	r.l[0] = a.l[0] + 0xfffffffffffda - b.l[0]
	r.l[1] = a.l[1] + 0xffffffffffffe - b.l[1]
	r.l[2] = a.l[2] + 0xffffffffffffe - b.l[2]
	r.l[3] = a.l[3] + 0xffffffffffffe - b.l[3]
	r.l[4] = a.l[4] + 0xffffffffffffe - b.l[4]
	fe_carry(mut r)
	return r
}

fn mul128(a u64, b u64) (u64, u64) {
	a_lo := a & 0xffffffff
	a_hi := a >> 32
	b_lo := b & 0xffffffff
	b_hi := b >> 32
	ll := a_lo * b_lo
	lh := a_lo * b_hi
	hl := a_hi * b_lo
	hh := a_hi * b_hi
	mut lo := ll
	mut hi := hh
	mid1 := lh
	mid2 := hl
	t := lo + (mid1 << 32)
	if t < lo {
		hi += 1
	}
	lo = t
	hi += mid1 >> 32
	t2 := lo + (mid2 << 32)
	if t2 < lo {
		hi += 1
	}
	lo = t2
	hi += mid2 >> 32
	return lo, hi
}

// add128 adds (lo,hi) accumulators.
fn add128(alo u64, ahi u64, blo u64, bhi u64) (u64, u64) {
	lo := alo + blo
	mut hi := ahi + bhi
	if lo < alo {
		hi += 1
	}
	return lo, hi
}

fn fe_mul(a Fe, b Fe) Fe {
	// Schoolbook with the 2^255≡19 fold: cross terms above limb 4 are
	// pre-multiplied by 19. Accumulate each output limb in a 128-bit
	// (lo,hi) pair, then carry down through 51-bit limbs.
	b1_19 := b.l[1] * 19
	b2_19 := b.l[2] * 19
	b3_19 := b.l[3] * 19
	b4_19 := b.l[4] * 19

	mut r := [u64(0), 0, 0, 0, 0]

	// helper inline via repeated mul/add
	mut lo0, mut h0 := mul128(a.l[0], b.l[0])
	mut t1lo, mut t1hi := mul128(a.l[1], b4_19)
	lo0, h0 = add128(lo0, h0, t1lo, t1hi)
	t1lo, t1hi = mul128(a.l[2], b3_19)
	lo0, h0 = add128(lo0, h0, t1lo, t1hi)
	t1lo, t1hi = mul128(a.l[3], b2_19)
	lo0, h0 = add128(lo0, h0, t1lo, t1hi)
	t1lo, t1hi = mul128(a.l[4], b1_19)
	lo0, h0 = add128(lo0, h0, t1lo, t1hi)

	mut lo1, mut h1 := mul128(a.l[0], b.l[1])
	t1lo, t1hi = mul128(a.l[1], b.l[0])
	lo1, h1 = add128(lo1, h1, t1lo, t1hi)
	t1lo, t1hi = mul128(a.l[2], b4_19)
	lo1, h1 = add128(lo1, h1, t1lo, t1hi)
	t1lo, t1hi = mul128(a.l[3], b3_19)
	lo1, h1 = add128(lo1, h1, t1lo, t1hi)
	t1lo, t1hi = mul128(a.l[4], b2_19)
	lo1, h1 = add128(lo1, h1, t1lo, t1hi)

	mut lo2, mut h2 := mul128(a.l[0], b.l[2])
	t1lo, t1hi = mul128(a.l[1], b.l[1])
	lo2, h2 = add128(lo2, h2, t1lo, t1hi)
	t1lo, t1hi = mul128(a.l[2], b.l[0])
	lo2, h2 = add128(lo2, h2, t1lo, t1hi)
	t1lo, t1hi = mul128(a.l[3], b4_19)
	lo2, h2 = add128(lo2, h2, t1lo, t1hi)
	t1lo, t1hi = mul128(a.l[4], b3_19)
	lo2, h2 = add128(lo2, h2, t1lo, t1hi)

	mut lo3, mut h3 := mul128(a.l[0], b.l[3])
	t1lo, t1hi = mul128(a.l[1], b.l[2])
	lo3, h3 = add128(lo3, h3, t1lo, t1hi)
	t1lo, t1hi = mul128(a.l[2], b.l[1])
	lo3, h3 = add128(lo3, h3, t1lo, t1hi)
	t1lo, t1hi = mul128(a.l[3], b.l[0])
	lo3, h3 = add128(lo3, h3, t1lo, t1hi)
	t1lo, t1hi = mul128(a.l[4], b4_19)
	lo3, h3 = add128(lo3, h3, t1lo, t1hi)

	mut lo4, mut h4 := mul128(a.l[0], b.l[4])
	t1lo, t1hi = mul128(a.l[1], b.l[3])
	lo4, h4 = add128(lo4, h4, t1lo, t1hi)
	t1lo, t1hi = mul128(a.l[2], b.l[2])
	lo4, h4 = add128(lo4, h4, t1lo, t1hi)
	t1lo, t1hi = mul128(a.l[3], b.l[1])
	lo4, h4 = add128(lo4, h4, t1lo, t1hi)
	t1lo, t1hi = mul128(a.l[4], b.l[0])
	lo4, h4 = add128(lo4, h4, t1lo, t1hi)

	// Carry chain: each (lo,hi) → 51-bit limb + carry to next.
	mut c := u64(0)
	r[0] = lo0 & fe_mask51
	c = (lo0 >> 51) | (h0 << 13)
	lo1n, h1n := add128(lo1, h1, c, 0)
	r[1] = lo1n & fe_mask51
	c = (lo1n >> 51) | (h1n << 13)
	lo2n, h2n := add128(lo2, h2, c, 0)
	r[2] = lo2n & fe_mask51
	c = (lo2n >> 51) | (h2n << 13)
	lo3n, h3n := add128(lo3, h3, c, 0)
	r[3] = lo3n & fe_mask51
	c = (lo3n >> 51) | (h3n << 13)
	lo4n, h4n := add128(lo4, h4, c, 0)
	r[4] = lo4n & fe_mask51
	c = (lo4n >> 51) | (h4n << 13)
	// Fold final carry ×19 into limb 0 and propagate once.
	r[0] += c * 19
	r[1] += r[0] >> 51
	r[0] &= fe_mask51
	mut out := Fe{}
	for i in 0 .. 5 {
		out.l[i] = r[i]
	}
	return out
}

fn fe_sq(a Fe) Fe {
	return fe_mul(a, a)
}

fn fe_mul_small(a Fe, k u64) Fe {
	mut r := [u64(0), 0, 0, 0, 0]
	mut hi := [u64(0), 0, 0, 0, 0]
	for i in 0 .. 5 {
		lo, h := mul128(a.l[i], k)
		r[i] = lo
		hi[i] = h
	}
	mut c := u64(0)
	mut out := Fe{}
	for i in 0 .. 5 {
		v := r[i] + c
		out.l[i] = v & fe_mask51
		c = (v >> 51) | (hi[i] << 13)
	}
	out.l[0] += c * 19
	out.l[1] += out.l[0] >> 51
	out.l[0] &= fe_mask51
	return out
}

fn fe_cswap(swap u64, mut a Fe, mut b Fe) {
	mask := -swap
	for i in 0 .. 5 {
		t := mask & (a.l[i] ^ b.l[i])
		a.l[i] ^= t
		b.l[i] ^= t
	}
}

// fe_invert = a^(p-2) via the ref10 addition chain.
fn fe_invert(z Fe) Fe {
	z2 := fe_sq(z)
	mut t := fe_sq(z2)
	t = fe_sq(t)
	z9 := fe_mul(t, z)
	z11 := fe_mul(z9, z2)
	z2_5_0 := fe_mul(fe_sq(z11), z9)
	mut z2_10_0 := fe_sq(z2_5_0)
	for _ in 0 .. 4 {
		z2_10_0 = fe_sq(z2_10_0)
	}
	z2_10_0 = fe_mul(z2_10_0, z2_5_0)
	mut z2_20_0 := fe_sq(z2_10_0)
	for _ in 0 .. 9 {
		z2_20_0 = fe_sq(z2_20_0)
	}
	z2_20_0 = fe_mul(z2_20_0, z2_10_0)
	mut z2_40_0 := fe_sq(z2_20_0)
	for _ in 0 .. 19 {
		z2_40_0 = fe_sq(z2_40_0)
	}
	z2_40_0 = fe_mul(z2_40_0, z2_20_0)
	mut z2_50_0 := fe_sq(z2_40_0)
	for _ in 0 .. 9 {
		z2_50_0 = fe_sq(z2_50_0)
	}
	z2_50_0 = fe_mul(z2_50_0, z2_10_0)
	mut z2_100_0 := fe_sq(z2_50_0)
	for _ in 0 .. 49 {
		z2_100_0 = fe_sq(z2_100_0)
	}
	z2_100_0 = fe_mul(z2_100_0, z2_50_0)
	mut z2_200_0 := fe_sq(z2_100_0)
	for _ in 0 .. 99 {
		z2_200_0 = fe_sq(z2_200_0)
	}
	z2_200_0 = fe_mul(z2_200_0, z2_100_0)
	mut z2_250_0 := fe_sq(z2_200_0)
	for _ in 0 .. 49 {
		z2_250_0 = fe_sq(z2_250_0)
	}
	z2_250_0 = fe_mul(z2_250_0, z2_50_0)
	mut r := fe_sq(z2_250_0)
	for _ in 0 .. 4 {
		r = fe_sq(r)
	}
	return fe_mul(r, z11)
}

pub fn x25519_scalar_mult(scalar []u8, u_coord []u8) []u8 {
	mut clamped := scalar.clone()
	x25519_clamp(mut clamped)
	x1 := fe_from_bytes(u_coord)
	mut x2 := fe_one()
	mut z2 := fe_zero()
	mut x3 := x1
	mut z3 := fe_one()
	mut swap := u64(0)
	for t := 254; t >= 0; t-- {
		kt := u64((clamped[t >> 3] >> (u8(t) & 7)) & 1)
		swap ^= kt
		fe_cswap(swap, mut x2, mut x3)
		fe_cswap(swap, mut z2, mut z3)
		swap = kt
		a := fe_add(x2, z2)
		aa := fe_sq(a)
		b := fe_sub(x2, z2)
		bb := fe_sq(b)
		e := fe_sub(aa, bb)
		c := fe_add(x3, z3)
		d := fe_sub(x3, z3)
		da := fe_mul(d, a)
		cb := fe_mul(c, b)
		x3 = fe_sq(fe_add(da, cb))
		z3 = fe_mul(x1, fe_sq(fe_sub(da, cb)))
		x2 = fe_mul(aa, bb)
		z2 = fe_mul(e, fe_add(aa, fe_mul_small(e, 121665)))
	}
	fe_cswap(swap, mut x2, mut x3)
	fe_cswap(swap, mut z2, mut z3)
	return fe_to_bytes(fe_mul(x2, fe_invert(z2)))
}

pub fn x25519_scalar_base_mult(scalar []u8) []u8 {
	mut base := []u8{len: 32}
	base[0] = 9
	return x25519_scalar_mult(scalar, base)
}

// ════════════════════════════════════════════════════════════════════
// §3.8 rsa-verify / ecdsa-verify  +  §3.10 JWT / JWKS
//
// Verify-only public-key primitives (RSASSA-PKCS1-v1_5 RFC 8017 §8.2,
// ECDSA over NIST P-256 FIPS 186 / SEC1) backing the JWT RS*/ES256
// families, plus the offline JWT verification state machine and JWKS
// parsing. The big-integer arithmetic is `math.big`; no new C deps.
//
// All verification is FAIL-CLOSED: rsa-verify / ecdsa-verify follow the
// §3.6 true-or-raise contract; jwt-verify answers the composite four-
// channel question and returns a present `[claims …]` value or an `[err]`
// (never `false`, never unverified claims).
// ════════════════════════════════════════════════════════════════════

// ── §5 error codes (JWT/JWKS sub-block, CXER3709..3719) ──────────────
const crypto_err_jwt_malformed = 'cx-err:CXER3709' // E_JWT_MALFORMED
const crypto_err_jwt_sig       = 'cx-err:CXER3710' // E_JWT_SIGNATURE_INVALID
const crypto_err_jwt_expired   = 'cx-err:CXER3711' // E_JWT_EXPIRED
const crypto_err_jwt_nbf       = 'cx-err:CXER3712' // E_JWT_NOT_YET_VALID
const crypto_err_jwt_alg       = 'cx-err:CXER3713' // E_JWT_ALG_UNSUPPORTED
const crypto_err_jwt_key_nf    = 'cx-err:CXER3714' // E_JWT_KEY_NOT_FOUND
const crypto_err_jwt_claim     = 'cx-err:CXER3715' // E_JWT_CLAIM_MISMATCH
const crypto_err_jwks_fetch    = 'cx-err:CXER3716' // E_JWKS_FETCH_FAILED
const crypto_err_jwks_invalid  = 'cx-err:CXER3717' // E_JWKS_INVALID
const crypto_err_jwt_arg       = 'cx-err:CXER3718' // E_JWT_ARG_INVALID
const crypto_err_jwt_key_alg   = 'cx-err:CXER3719' // E_JWT_KEY_ALG_MISMATCH

const crypto_jwt_supported_algs = ['RS256', 'RS384', 'RS512', 'ES256', 'EdDSA']

// ── base64url (RFC 4648 §5), strict, padding-tolerant ────────────────

fn crypto_b64url_val(c u8) ?u8 {
	if c >= `A` && c <= `Z` {
		return u8(c - `A`)
	}
	if c >= `a` && c <= `z` {
		return u8(c - `a` + 26)
	}
	if c >= `0` && c <= `9` {
		return u8(c - `0` + 52)
	}
	// STRICT base64url (RFC 4648 §5): the 62/63 glyphs are `-`/`_` ONLY. The
	// standard-alphabet `+`/`/` are REJECTED — JWT/JWK material (RFC 7515/7517)
	// is base64url by mandate, and silently accepting `+`/`/` let a non-
	// conformant token/key through the "strict" path (audit MINOR). Any other
	// byte → none.
	if c == `-` {
		return u8(62)
	}
	if c == `_` {
		return u8(63)
	}
	return none
}

// crypto_b64url_decode decodes a STRICT base64url string (url-safe alphabet
// only, RFC 4648 §5), tolerating present or absent `=` padding. A standard-
// alphabet `+`/`/` or any other character → none.
pub fn crypto_b64url_decode(s string) ?[]u8 {
	mut out := []u8{}
	mut acc := u32(0)
	mut nbits := 0
	for c in s.bytes() {
		if c == `=` {
			continue
		}
		v := crypto_b64url_val(c) or { return none }
		acc = (acc << 6) | u32(v)
		nbits += 6
		if nbits >= 8 {
			nbits -= 8
			out << u8((acc >> u32(nbits)) & 0xFF)
		}
	}
	return out
}

// ── hex helpers (curve / DigestInfo constants) ───────────────────────

fn crypto_hex_nib(c u8) ?u8 {
	if c >= `0` && c <= `9` {
		return u8(c - `0`)
	}
	if c >= `a` && c <= `f` {
		return u8(c - `a` + 10)
	}
	if c >= `A` && c <= `F` {
		return u8(c - `A` + 10)
	}
	return none
}

fn crypto_hex_bytes(s string) []u8 {
	mut out := []u8{cap: s.len / 2}
	for i := 0; i + 1 < s.len; i += 2 {
		hi := crypto_hex_nib(s[i]) or { return out }
		lo := crypto_hex_nib(s[i + 1]) or { return out }
		out << u8(hi * 16 + lo)
	}
	return out
}

// ── RSASSA-PKCS1-v1_5 verify (RFC 8017 §8.2.2) ───────────────────────

// crypto_digest_info returns the ASN.1 DER DigestInfo prefix and the
// matching digest function for a PKCS#1 v1.5 hash. Unsupported → none.
fn crypto_digest_info(hash string) ?([]u8, fn ([]u8) []u8) {
	match hash {
		'sha256' {
			return crypto_hex_bytes('3031300d060960864801650304020105000420'), sha256.sum256
		}
		'sha384' {
			return crypto_hex_bytes('3041300d060960864801650304020205000430'), sha512.sum384
		}
		'sha512' {
			return crypto_hex_bytes('3051300d060960864801650304020305000440'), sha512.sum512
		}
		else {
			return none
		}
	}
}

// crypto_i2osp renders a big.Integer as a fixed-length big-endian octet
// string (RFC 8017 I2OSP), left-padding with zero bytes.
fn crypto_i2osp(n big.Integer, length int) []u8 {
	b, _ := n.bytes()
	if b.len >= length {
		return b[b.len - length..].clone()
	}
	mut out := []u8{len: length - b.len}
	out << b
	return out
}

// crypto_rsa_verify implements RSASSA-PKCS1-v1_5 verification. `n`/`e` are
// the big-endian modulus / public exponent; returns the §3.6 true node or
// CXER3705 / CXER3700.
fn crypto_rsa_verify(n []u8, e []u8, msg []u8, sig []u8, hash string) cx.Node {
	prefix, digest := crypto_digest_info(hash) or {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: unsupported RSA hash "${hash}"')
	}
	if n.len == 0 || e.len == 0 {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: empty RSA modulus/exponent')
	}
	k := n.len
	if sig.len != k {
		return mk_err(crypto_err_sig, 'E_CRYPTO_SIGNATURE_INVALID: signature length ${sig.len} != modulus length ${k}')
	}
	ni := big.integer_from_bytes(n)
	ei := big.integer_from_bytes(e)
	si := big.integer_from_bytes(sig)
	if si.abs_cmp(ni) >= 0 {
		return mk_err(crypto_err_sig, 'E_CRYPTO_SIGNATURE_INVALID: signature representative out of range')
	}
	mi := si.big_mod_pow(ei, ni) or {
		return mk_err(crypto_err_sig, 'E_CRYPTO_SIGNATURE_INVALID: RSA exponentiation failed')
	}
	em := crypto_i2osp(mi, k)
	h := digest(msg)
	ps_len := k - 3 - prefix.len - h.len
	if ps_len < 8 {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: RSA modulus too small for ${hash}')
	}
	mut expected := []u8{cap: k}
	expected << 0x00
	expected << 0x01
	for _ in 0 .. ps_len {
		expected << 0xFF
	}
	expected << 0x00
	expected << prefix
	expected << h
	if crypto_ct_equal(em, expected) {
		return crypto_bool_node(true)
	}
	return mk_err(crypto_err_sig, 'E_CRYPTO_SIGNATURE_INVALID: RSA PKCS#1 v1.5 verification failed')
}

// ── ECDSA over NIST P-256 (FIPS 186 / SEC1) ──────────────────────────

struct EcPoint {
	x   big.Integer
	y   big.Integer
	inf bool
}

fn p256_p() big.Integer {
	return big.integer_from_bytes(crypto_hex_bytes('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff'))
}

fn p256_n() big.Integer {
	return big.integer_from_bytes(crypto_hex_bytes('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'))
}

fn p256_b() big.Integer {
	return big.integer_from_bytes(crypto_hex_bytes('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b'))
}

fn p256_a(p big.Integer) big.Integer {
	// a = -3 mod p
	return (p - big.integer_from_int(3)).mod_euclid(p)
}

fn p256_g() EcPoint {
	return EcPoint{
		x: big.integer_from_bytes(crypto_hex_bytes('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'))
		y: big.integer_from_bytes(crypto_hex_bytes('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'))
	}
}

fn ec_double(pt EcPoint, p big.Integer, a big.Integer) EcPoint {
	zero := big.integer_from_int(0)
	if pt.inf || pt.y == zero {
		return EcPoint{
			inf: true
		}
	}
	two := big.integer_from_int(2)
	three := big.integer_from_int(3)
	num := (three * pt.x * pt.x + a).mod_euclid(p)
	den := (two * pt.y).mod_euclid(p)
	deninv := den.mod_inverse(p) or {
		return EcPoint{
			inf: true
		}
	}
	lam := (num * deninv).mod_euclid(p)
	xr := (lam * lam - two * pt.x).mod_euclid(p)
	yr := (lam * (pt.x - xr) - pt.y).mod_euclid(p)
	return EcPoint{
		x: xr
		y: yr
	}
}

fn ec_add(p1 EcPoint, p2 EcPoint, p big.Integer, a big.Integer) EcPoint {
	if p1.inf {
		return p2
	}
	if p2.inf {
		return p1
	}
	zero := big.integer_from_int(0)
	if p1.x == p2.x {
		if (p1.y + p2.y).mod_euclid(p) == zero {
			return EcPoint{
				inf: true
			}
		}
		return ec_double(p1, p, a)
	}
	num := (p2.y - p1.y).mod_euclid(p)
	den := (p2.x - p1.x).mod_euclid(p)
	deninv := den.mod_inverse(p) or {
		return EcPoint{
			inf: true
		}
	}
	lam := (num * deninv).mod_euclid(p)
	xr := (lam * lam - p1.x - p2.x).mod_euclid(p)
	yr := (lam * (p1.x - xr) - p1.y).mod_euclid(p)
	return EcPoint{
		x: xr
		y: yr
	}
}

fn ec_mul(k big.Integer, pt EcPoint, p big.Integer, a big.Integer) EcPoint {
	mut result := EcPoint{
		inf: true
	}
	mut addend := pt
	nbits := k.bit_len()
	for i := 0; i < nbits; i++ {
		if k.get_bit(u32(i)) {
			result = ec_add(result, addend, p, a)
		}
		addend = ec_double(addend, p, a)
	}
	return result
}

// crypto_bits2int reduces a hash to an integer per FIPS 186 / SEC1 — the
// leftmost `bit_len(n)` bits of the digest.
fn crypto_bits2int(h []u8, n big.Integer) big.Integer {
	mut e := big.integer_from_bytes(h)
	excess := h.len * 8 - n.bit_len()
	if excess > 0 {
		e = e.right_shift(u32(excess))
	}
	return e
}

// crypto_ecdsa_verify verifies an ECDSA P-256 signature in JOSE fixed-width
// raw r‖s form (RFC 7518 §3.4, 64 bytes). `xb`/`yb` are the big-endian
// affine public-key coordinates. Returns the §3.6 true node or CXER3705 /
// CXER3700.
fn crypto_ecdsa_verify(xb []u8, yb []u8, msg []u8, sig []u8, curve string, hash string) cx.Node {
	if curve != 'P-256' {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: unsupported curve "${curve}" (P-384/P-521 deferred)')
	}
	digest := match hash {
		'sha256' { sha256.sum256 }
		'sha384' { sha512.sum384 }
		'sha512' { sha512.sum512 }
		else { return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: unsupported ECDSA hash "${hash}"') }
	}
	if sig.len != 64 {
		return mk_err(crypto_err_sig, 'E_CRYPTO_SIGNATURE_INVALID: ECDSA P-256 signature must be 64-byte raw r‖s (got ${sig.len}; DER not accepted)')
	}
	p := p256_p()
	n := p256_n()
	a := p256_a(p)
	zero := big.integer_from_int(0)
	r := big.integer_from_bytes(sig[..32])
	s := big.integer_from_bytes(sig[32..])
	if r == zero || s == zero || r.abs_cmp(n) >= 0 || s.abs_cmp(n) >= 0 {
		return mk_err(crypto_err_sig, 'E_CRYPTO_SIGNATURE_INVALID: r/s out of range')
	}
	qx := big.integer_from_bytes(xb)
	qy := big.integer_from_bytes(yb)
	// public point must satisfy y^2 == x^3 - 3x + b (mod p)
	lhs := (qy * qy).mod_euclid(p)
	rhs := (qx * qx * qx + a * qx + p256_b()).mod_euclid(p)
	if lhs != rhs {
		return mk_err(crypto_err_sig, 'E_CRYPTO_SIGNATURE_INVALID: public key point not on curve')
	}
	q := EcPoint{
		x: qx
		y: qy
	}
	e := crypto_bits2int(digest(msg), n)
	sinv := s.mod_inverse(n) or {
		return mk_err(crypto_err_sig, 'E_CRYPTO_SIGNATURE_INVALID: s not invertible')
	}
	u1 := (e * sinv).mod_euclid(n)
	u2 := (r * sinv).mod_euclid(n)
	pt := ec_add(ec_mul(u1, p256_g(), p, a), ec_mul(u2, q, p, a), p, a)
	if pt.inf {
		return mk_err(crypto_err_sig, 'E_CRYPTO_SIGNATURE_INVALID: point at infinity')
	}
	v := pt.x.mod_euclid(n)
	if v == r {
		return crypto_bool_node(true)
	}
	return mk_err(crypto_err_sig, 'E_CRYPTO_SIGNATURE_INVALID: ECDSA verification failed')
}

// ── public-key element extraction (§3.8 element shapes) ──────────────

// crypto_rsa_key_from reads [rsa-public-key n=<bytes> e=<bytes>].
fn crypto_rsa_key_from(el cx.Element) ?([]u8, []u8) {
	n := crypto_read_field_bytes(el, 'n')?
	e := crypto_read_field_bytes(el, 'e')?
	return n, e
}

// crypto_ec_key_from reads [ec-public-key crv=".." x=<bytes> y=<bytes>].
fn crypto_ec_key_from(el cx.Element) ?(string, []u8, []u8) {
	crv := crypto_read_field_str(el, 'crv') or { 'P-256' }
	x := crypto_read_field_bytes(el, 'x')?
	y := crypto_read_field_bytes(el, 'y')?
	return crv, x, y
}

// ── §3.8 rsa-verify / ecdsa-verify dispatch helpers ──────────────────

fn crypto_rsa_verify_node(args []cx.Node) cx.Node {
	key := args[0]
	if key !is cx.Element {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: rsa-verify key must be an [rsa-public-key …] element')
	}
	el := key as cx.Element
	n, e := crypto_rsa_key_from(el) or {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: rsa-public-key missing n/e')
	}
	msg := crypto_arg_bytes(args[1]) or {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: rsa-verify msg must be bytes')
	}
	sig := crypto_arg_bytes(args[2]) or {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: rsa-verify sig must be bytes')
	}
	hash := crypto_opt_str(args, 3, 'hash', 'sha256')
	return crypto_rsa_verify(n, e, msg, sig, hash)
}

fn crypto_ecdsa_verify_node(args []cx.Node) cx.Node {
	key := args[0]
	if key !is cx.Element {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: ecdsa-verify key must be an [ec-public-key …] element')
	}
	el := key as cx.Element
	crv, x, y := crypto_ec_key_from(el) or {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: ec-public-key missing x/y')
	}
	msg := crypto_arg_bytes(args[1]) or {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: ecdsa-verify msg must be bytes')
	}
	sig := crypto_arg_bytes(args[2]) or {
		return mk_err(crypto_err_key, 'E_CRYPTO_KEY_INVALID: ecdsa-verify sig must be bytes')
	}
	opt_crv := crypto_opt_str(args, 3, 'curve', crv)
	hash := crypto_opt_str(args, 3, 'hash', 'sha256')
	return crypto_ecdsa_verify(x, y, msg, sig, opt_crv, hash)
}

// crypto_opt_str reads a string option from a map-node arg at index `idx`.
fn crypto_opt_str(args []cx.Node, idx int, key string, def string) string {
	if idx >= args.len {
		return def
	}
	m := crypto_opts(args[idx])
	n := m[key] or { return def }
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return def
}

// crypto_opts lifts a `__cx_map__` node into a V map (mirrors json_opts).
fn crypto_opts(n cx.Node) map[string]cx.Node {
	mut m := map[string]cx.Node{}
	if n is cx.Element && n.name == '__cx_map__' {
		for e in n.items {
			if e is cx.Element && e.items.len > 0 {
				m[e.name] = e.items[0]
			}
		}
	}
	return m
}

// crypto_opt_str_list reads a list-valued option (sequence / array / single
// scalar) into a []string. Absent → none.
fn crypto_opt_str_list(m map[string]cx.Node, key string) ?[]string {
	n := m[key] or { return none }
	return crypto_node_str_list(n)
}

pub fn crypto_node_str_list(n cx.Node) []string {
	mut out := []string{}
	if n is cx.SequenceNode {
		for it in n.items {
			if s := crypto_jstr(it) {
				out << s
			}
		}
		return out
	}
	if n is cx.Element {
		if n.name == '__cx_arr__' || n.name == '__cx_seq__' || n.name == '' {
			for it in n.items {
				if s := crypto_jstr(it) {
					out << s
				}
			}
			return out
		}
	}
	if s := crypto_jstr(n) {
		out << s
	}
	return out
}

// ── JSON map readers (over the cx-stdlib/json node model) ────────────

pub fn crypto_jmap_get(m cx.Node, key string) ?cx.Node {
	if m is cx.Element && m.name == '__cx_map__' {
		for e in m.items {
			if e is cx.Element && e.name == key && e.items.len > 0 {
				return e.items[0]
			}
		}
	}
	return none
}

pub fn crypto_jstr(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return none
}

fn crypto_jint(n cx.Node) ?i64 {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			i64 { return v }
			f64 { return i64(v) }
			else {}
		}
	}
	return none
}

// ── §3.10 jwks-parse ─────────────────────────────────────────────────

// crypto_jwks_parse parses a JWKS JSON document into [jwks [jwk …] …].
// Validates each [jwk]'s alg against its kty/crv (CXER3717 on mismatch).
pub fn crypto_jwks_parse(json_text string) cx.Node {
	root := json_do_parse(json_text, map[string]cx.Node{})
	if is_err_value(root) {
		return mk_err(crypto_err_jwks_invalid, 'E_JWKS_INVALID: JWKS is not valid JSON')
	}
	keys := crypto_jmap_get(root, 'keys') or {
		return mk_err(crypto_err_jwks_invalid, 'E_JWKS_INVALID: JWKS document missing "keys" array')
	}
	if keys !is cx.Element {
		return mk_err(crypto_err_jwks_invalid, 'E_JWKS_INVALID: "keys" is not an array')
	}
	keys_el := keys as cx.Element
	if keys_el.name != '__cx_arr__' {
		return mk_err(crypto_err_jwks_invalid, 'E_JWKS_INVALID: "keys" is not an array')
	}
	mut jwk_items := []cx.Node{}
	for jk in keys_el.items {
		jwk := crypto_jwk_from_json(jk) or {
			return mk_err(crypto_err_jwks_invalid, 'E_JWKS_INVALID: malformed or inconsistent JWK')
		}
		jwk_items << jwk
	}
	return cx.Element{
		name:  'jwks'
		items: jwk_items
	}
}

// crypto_jwk_from_json lifts one JSON JWK object into a [jwk …] element,
// validating kty↔alg↔crv consistency. b64url material is preserved as the
// string attributes (n/e/x/y) per the spec [jwks] shape.
fn crypto_jwk_from_json(jk cx.Node) ?cx.Element {
	kty := crypto_jstr(crypto_jmap_get(jk, 'kty') or { return none })?
	mut attrs := []cx.Attribute{}
	if kid := crypto_jmap_get(jk, 'kid') {
		if s := crypto_jstr(kid) {
			attrs << crypto_str_attr('kid', s)
		}
	}
	attrs << crypto_str_attr('kty', kty)
	alg := if a := crypto_jmap_get(jk, 'alg') {
		crypto_jstr(a) or { '' }
	} else {
		''
	}
	if alg != '' {
		attrs << crypto_str_attr('alg', alg)
	}
	match kty {
		'RSA' {
			n := crypto_jstr(crypto_jmap_get(jk, 'n') or { return none })?
			e := crypto_jstr(crypto_jmap_get(jk, 'e') or { return none })?
			if alg != '' && !alg.starts_with('RS') && !alg.starts_with('PS') {
				return none
			}
			attrs << crypto_str_attr('n', n)
			attrs << crypto_str_attr('e', e)
		}
		'EC' {
			crv := crypto_jstr(crypto_jmap_get(jk, 'crv') or { return none })?
			x := crypto_jstr(crypto_jmap_get(jk, 'x') or { return none })?
			y := crypto_jstr(crypto_jmap_get(jk, 'y') or { return none })?
			if alg != '' && !alg.starts_with('ES') {
				return none
			}
			attrs << crypto_str_attr('crv', crv)
			attrs << crypto_str_attr('x', x)
			attrs << crypto_str_attr('y', y)
		}
		'OKP' {
			crv := crypto_jstr(crypto_jmap_get(jk, 'crv') or { return none })?
			x := crypto_jstr(crypto_jmap_get(jk, 'x') or { return none })?
			if crv != 'Ed25519' {
				return none
			}
			if alg != '' && alg != 'EdDSA' {
				return none
			}
			attrs << crypto_str_attr('crv', crv)
			attrs << crypto_str_attr('x', x)
		}
		else {
			return none
		}
	}
	return cx.Element{
		name:  'jwk'
		attrs: attrs
	}
}

// ── §3.10 jwk-by-kid / claim ─────────────────────────────────────────

fn crypto_jwk_by_kid(jwks cx.Node, kid string) cx.Node {
	if jwks is cx.Element && jwks.name == 'jwks' {
		for it in jwks.items {
			if it is cx.Element && it.name == 'jwk' {
				if k := it.attr_val('kid') {
					if cx.scalar_value_str_public(k) == kid {
						return it
					}
				}
			}
		}
	}
	return cx.Element{} // absence channel
}

pub fn crypto_claim(claims cx.Node, name string) cx.Node {
	if claims !is cx.Element || (claims as cx.Element).name != 'claims' {
		return mk_err(crypto_err_jwt_arg, 'E_JWT_ARG_INVALID: claim expects a verified [claims …] value')
	}
	cel := claims as cx.Element
	for it in cel.items {
		if it is cx.Element && it.name == 'payload' && it.items.len > 0 {
			if v := crypto_jmap_get(it.items[0], name) {
				return v
			}
		}
	}
	return cx.Element{} // absence channel
}

// ── §3.10 jwt-verify state machine ───────────────────────────────────

// crypto_jwt_key resolves the chosen verification key into typed material.
struct CryptoJwtKey {
	kty string // 'RSA' / 'EC' / 'OKP'
	crv string
	n   []u8
	e   []u8
	x   []u8
	y   []u8
}

// crypto_jwt_select_key picks the verification key from $key for the token
// header. A [jwks] set resolves by kid; a single key element / Ed25519 key
// bytes is used directly. Errors: CXER3714 (no/ambiguous kid), CXER3718
// (unrecognised $key shape).
fn crypto_jwt_select_key(key cx.Node, kid string) cx.Node {
	if key is cx.Element {
		match key.name {
			'jwks' {
				mut hits := []cx.Element{}
				mut singleton := cx.Element{}
				mut count := 0
				for it in key.items {
					if it is cx.Element && it.name == 'jwk' {
						count++
						singleton = it
						if k := it.attr_val('kid') {
							if cx.scalar_value_str_public(k) == kid {
								hits << it
							}
						}
					}
				}
				if kid != '' {
					// header kid present → it MUST select exactly one [jwk];
					// no match / ambiguous → CXER3714 (no single-key fallback,
					// §3.10 — the kid is authoritative once supplied).
					if hits.len == 1 {
						return hits[0]
					}
					if hits.len == 0 {
						return mk_err(crypto_err_jwt_key_nf, 'E_JWT_KEY_NOT_FOUND: no JWK matches kid "${kid}"')
					}
					return mk_err(crypto_err_jwt_key_nf, 'E_JWT_KEY_NOT_FOUND: kid "${kid}" ambiguous (${hits.len} matches)')
				}
				// token carries no kid → only a single-key set is unambiguous.
				if count == 1 {
					return singleton
				}
				return mk_err(crypto_err_jwt_key_nf, 'E_JWT_KEY_NOT_FOUND: token has no kid and JWKS holds ${count} keys')
			}
			'jwk', 'rsa-public-key', 'ec-public-key' {
				return key
			}
			else {
				return mk_err(crypto_err_jwt_arg, 'E_JWT_ARG_INVALID: unrecognised key element [${key.name}]')
			}
		}
	}
	// raw bytes scalar → Ed25519 public key
	if _ := crypto_arg_bytes(key) {
		return key
	}
	return mk_err(crypto_err_jwt_arg, 'E_JWT_ARG_INVALID: key is none of [jwk]/[jwks]/[rsa-public-key]/[ec-public-key]/Ed25519 bytes')
}

// crypto_jwt_material extracts typed key material from a resolved key node.
fn crypto_jwt_material(key cx.Node) ?CryptoJwtKey {
	if key is cx.Element {
		match key.name {
			'jwk' {
				kty := crypto_read_field_str(key, 'kty') or { return none }
				match kty {
					'RSA' {
						n := crypto_b64url_decode(crypto_read_field_str(key, 'n') or { return none })?
						e := crypto_b64url_decode(crypto_read_field_str(key, 'e') or { return none })?
						return CryptoJwtKey{
							kty: 'RSA'
							n:   n
							e:   e
						}
					}
					'EC' {
						crv := crypto_read_field_str(key, 'crv') or { 'P-256' }
						x := crypto_b64url_decode(crypto_read_field_str(key, 'x') or { return none })?
						y := crypto_b64url_decode(crypto_read_field_str(key, 'y') or { return none })?
						return CryptoJwtKey{
							kty: 'EC'
							crv: crv
							x:   x
							y:   y
						}
					}
					'OKP' {
						crv := crypto_read_field_str(key, 'crv') or { 'Ed25519' }
						x := crypto_b64url_decode(crypto_read_field_str(key, 'x') or { return none })?
						return CryptoJwtKey{
							kty: 'OKP'
							crv: crv
							x:   x
						}
					}
					else {
						return none
					}
				}
			}
			'rsa-public-key' {
				n, e := crypto_rsa_key_from(key)?
				return CryptoJwtKey{
					kty: 'RSA'
					n:   n
					e:   e
				}
			}
			'ec-public-key' {
				crv, x, y := crypto_ec_key_from(key)?
				return CryptoJwtKey{
					kty: 'EC'
					crv: crv
					x:   x
					y:   y
				}
			}
			else {
				return none
			}
		}
	}
	xb := crypto_arg_bytes(key)?
	return CryptoJwtKey{
		kty: 'OKP'
		crv: 'Ed25519'
		x:   xb
	}
}

// crypto_jwt_verify is the §3.10 fail-closed verification state machine.
pub fn crypto_jwt_verify(args []cx.Node) cx.Node {
	token := crypto_arg_str(args[0]) or {
		return mk_err(crypto_err_jwt_arg, 'E_JWT_ARG_INVALID: token must be a string')
	}
	key := args[1]
	opts := if args.len > 3 { crypto_opts(args[3]) } else { map[string]cx.Node{} }

	// (1) structural — three b64url segments
	parts := token.split('.')
	if parts.len != 3 {
		return mk_err(crypto_err_jwt_malformed, 'E_JWT_MALFORMED: token is not three dot-separated segments')
	}
	header_bytes := crypto_b64url_decode(parts[0]) or {
		return mk_err(crypto_err_jwt_malformed, 'E_JWT_MALFORMED: header is not base64url')
	}
	payload_bytes := crypto_b64url_decode(parts[1]) or {
		return mk_err(crypto_err_jwt_malformed, 'E_JWT_MALFORMED: payload is not base64url')
	}
	header := json_do_parse(header_bytes.bytestr(), map[string]cx.Node{})
	if is_err_value(header) {
		return mk_err(crypto_err_jwt_malformed, 'E_JWT_MALFORMED: header is not JSON')
	}
	payload := json_do_parse(payload_bytes.bytestr(), map[string]cx.Node{})
	if is_err_value(payload) {
		return mk_err(crypto_err_jwt_malformed, 'E_JWT_MALFORMED: payload is not JSON')
	}
	// required claims present
	require := crypto_opt_str_list(opts, 'require') or { ['exp'] }
	for rc in require {
		crypto_jmap_get(payload, rc) or {
			return mk_err(crypto_err_jwt_malformed, 'E_JWT_MALFORMED: required claim "${rc}" absent')
		}
	}

	// (2) algorithm — header alg in allow-list; never "none"
	alg := if a := crypto_jmap_get(header, 'alg') {
		crypto_jstr(a) or { '' }
	} else {
		''
	}
	if alg == '' || alg == 'none' {
		return mk_err(crypto_err_jwt_alg, 'E_JWT_ALG_UNSUPPORTED: alg "${alg}" rejected')
	}
	if alg !in crypto_jwt_supported_algs {
		return mk_err(crypto_err_jwt_alg, 'E_JWT_ALG_UNSUPPORTED: alg "${alg}" unimplemented (ES384/ES512 deferred)')
	}
	allow := crypto_opt_str_list(opts, 'expected-alg') or { crypto_jwt_supported_algs.clone() }
	if alg !in allow {
		return mk_err(crypto_err_jwt_alg, 'E_JWT_ALG_UNSUPPORTED: alg "${alg}" not in expected-alg allow-list')
	}

	// (3) key resolution — kid selects the JWK; kty must match alg
	kid := if k := crypto_jmap_get(header, 'kid') {
		crypto_jstr(k) or { '' }
	} else {
		''
	}
	resolved := crypto_jwt_select_key(key, kid)
	if is_err_value(resolved) {
		return resolved
	}
	mat := crypto_jwt_material(resolved) or {
		return mk_err(crypto_err_jwt_arg, 'E_JWT_ARG_INVALID: unusable key material')
	}
	if e := crypto_jwt_alg_kty_ok(alg, mat) {
		return e
	}

	// (4) signature over the reconstructed signing input
	signing_input := (parts[0] + '.' + parts[1]).bytes()
	sig := crypto_b64url_decode(parts[2]) or {
		return mk_err(crypto_err_jwt_malformed, 'E_JWT_MALFORMED: signature is not base64url')
	}
	sig_ok := crypto_jwt_check_sig(alg, mat, signing_input, sig)
	if !sig_ok {
		return mk_err(crypto_err_jwt_sig, 'E_JWT_SIGNATURE_INVALID: signature does not verify against the resolved key')
	}

	// (5) temporal — exp / nbf with leeway
	now_secs := crypto_jwt_now_secs(args[2])
	leeway := crypto_jwt_leeway_secs(opts)
	if exp := crypto_jmap_get(payload, 'exp') {
		if exp_secs := crypto_jint(exp) {
			if now_secs > exp_secs + leeway {
				return mk_err(crypto_err_jwt_expired, 'E_JWT_EXPIRED: exp ${exp_secs} < now ${now_secs} (leeway ${leeway}s)')
			}
		}
	}
	if nbf := crypto_jmap_get(payload, 'nbf') {
		if nbf_secs := crypto_jint(nbf) {
			if now_secs < nbf_secs - leeway {
				return mk_err(crypto_err_jwt_nbf, 'E_JWT_NOT_YET_VALID: nbf ${nbf_secs} > now ${now_secs} (leeway ${leeway}s)')
			}
		}
	}

	// (6) issuer / audience
	exp_iss := crypto_opt_str(args, 3, 'expected-iss', '')
	if exp_iss != '' {
		tok_iss := if i := crypto_jmap_get(payload, 'iss') {
			crypto_jstr(i) or { '' }
		} else {
			''
		}
		if tok_iss != exp_iss {
			return mk_err(crypto_err_jwt_claim, 'E_JWT_CLAIM_MISMATCH: iss "${tok_iss}" != expected "${exp_iss}"')
		}
	}
	exp_aud := crypto_opt_str(args, 3, 'expected-aud', '')
	if exp_aud != '' {
		if aud := crypto_jmap_get(payload, 'aud') {
			auds := crypto_node_str_list(aud)
			if exp_aud !in auds {
				return mk_err(crypto_err_jwt_claim, 'E_JWT_CLAIM_MISMATCH: aud does not contain "${exp_aud}"')
			}
		} else {
			return mk_err(crypto_err_jwt_claim, 'E_JWT_CLAIM_MISMATCH: token has no aud claim')
		}
	}

	return crypto_build_claims(payload)
}

// crypto_jwt_alg_kty_ok enforces alg↔kty consistency (CXER3719).
fn crypto_jwt_alg_kty_ok(alg string, mat CryptoJwtKey) ?cx.Node {
	expected := match alg {
		'RS256', 'RS384', 'RS512' { 'RSA' }
		'ES256' { 'EC' }
		'EdDSA' { 'OKP' }
		else { '' }
	}
	if mat.kty != expected {
		return mk_err(crypto_err_jwt_key_alg, 'E_JWT_KEY_ALG_MISMATCH: alg ${alg} needs ${expected} key, got ${mat.kty}')
	}
	if alg == 'ES256' && mat.crv != 'P-256' {
		return mk_err(crypto_err_jwt_key_alg, 'E_JWT_KEY_ALG_MISMATCH: ES256 needs P-256, got ${mat.crv}')
	}
	if alg == 'EdDSA' && mat.crv != 'Ed25519' {
		return mk_err(crypto_err_jwt_key_alg, 'E_JWT_KEY_ALG_MISMATCH: EdDSA needs Ed25519, got ${mat.crv}')
	}
	return none
}

// crypto_jwt_check_sig verifies the signature for the resolved alg/key.
fn crypto_jwt_check_sig(alg string, mat CryptoJwtKey, signing_input []u8, sig []u8) bool {
	match alg {
		'RS256' {
			return !is_err_value(crypto_rsa_verify(mat.n, mat.e, signing_input, sig, 'sha256'))
		}
		'RS384' {
			return !is_err_value(crypto_rsa_verify(mat.n, mat.e, signing_input, sig, 'sha384'))
		}
		'RS512' {
			return !is_err_value(crypto_rsa_verify(mat.n, mat.e, signing_input, sig, 'sha512'))
		}
		'ES256' {
			return !is_err_value(crypto_ecdsa_verify(mat.x, mat.y, signing_input, sig, 'P-256',
				'sha256'))
		}
		'EdDSA' {
			if mat.x.len != 32 || sig.len != 64 {
				return false
			}
			return ed25519.verify(mat.x, signing_input, sig) or { false }
		}
		else {
			return false
		}
	}
}

// crypto_jwt_now_secs reads `$now` (a datetime) as Unix seconds.
fn crypto_jwt_now_secs(now cx.Node) i64 {
	dt := decode_datetime(now) or { return 0 }
	return dt.instant_ns() / ns_per_s
}

// crypto_jwt_leeway_secs reads opts.leeway (duration scalar or int seconds).
fn crypto_jwt_leeway_secs(opts map[string]cx.Node) i64 {
	n := opts['leeway'] or { return 0 }
	if n is cx.ScalarNode {
		v := n.value
		match v {
			i64 {
				return v
			}
			f64 {
				return i64(v)
			}
			string {
				ns := parse_duration_str(v) or { return 0 }
				return ns / ns_per_s
			}
			else {}
		}
	}
	return 0
}

// crypto_build_claims assembles the verified [claims …] value: registered
// scalar claims as attributes + a [payload <map>] child carrying the full
// decoded claim-set (so `claim` reaches any claim).
fn crypto_build_claims(payload cx.Node) cx.Node {
	mut attrs := []cx.Attribute{}
	for rc in ['iss', 'sub', 'aud', 'jti'] {
		if v := crypto_jmap_get(payload, rc) {
			if s := crypto_jstr(v) {
				attrs << crypto_str_attr(rc, s)
			}
		}
	}
	for rc in ['exp', 'nbf', 'iat'] {
		if v := crypto_jmap_get(payload, rc) {
			if i := crypto_jint(v) {
				attrs << cx.new_attribute(rc, cx.ScalarValue(i), cx.AttributeMeta{})
			}
		}
	}
	return cx.Element{
		name:  'claims'
		attrs: attrs
		items: [
			cx.Node(cx.Element{
				name:  'payload'
				items: [payload]
			}),
		]
	}
}

// crypto_jwks_fetch GETs a JWKS document over cx-stdlib/http (net-gated)
// and parses it. The live transport is the synthetic http client (gate
// pending for a network-granted harness); a non-2xx / transport fault /
// non-JWKS body → CXER3716 carrying the http/net [err] child.
fn crypto_jwks_fetch(args []cx.Node) cx.Node {
	// The transport is the Ring-1 http-client pack; in an artifact built
	// without it (I4, `-d cx_no_pack_http_client` — the §4 embed profile)
	// the fetch refuses by construction, same failure envelope as a
	// transport fault.
	$if cx_no_pack_http_client ? {
		return mk_err(crypto_err_jwks_fetch,
			'E_JWKS_FETCH_FAILED: the http client pack is not in this profile')
	} $else {
		uri := crypto_arg_str(args[0]) or {
			return mk_err(crypto_err_jwks_fetch, 'E_JWKS_FETCH_FAILED: jwks-uri must be a string')
		}
		resp := http_request_verb([
			crypto_string_node('get'),
			crypto_string_node(uri),
		])
		if is_err_value(resp) {
			return mk_err_with_cause(crypto_err_jwks_fetch, resp)
		}
		if resp is cx.Element {
			if st := resp.attr_val('status') {
				status_code := cx.scalar_value_str_public(st)
				if !status_code.starts_with('2') {
					return mk_err_with_cause(crypto_err_jwks_fetch, resp)
				}
			}
			body_node := http_body_text_impl([cx.Node(resp)])
			body := crypto_arg_str(body_node) or { '' }
			if body == '' {
				return mk_err(crypto_err_jwks_fetch, 'E_JWKS_FETCH_FAILED: empty JWKS body')
			}
			return crypto_jwks_parse(body)
		}
		return mk_err(crypto_err_jwks_fetch, 'E_JWKS_FETCH_FAILED: no response')
	}
}
