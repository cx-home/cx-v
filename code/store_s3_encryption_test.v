module code

import cx
import cxstore

// store_s3_encryption_test.v — #229 encryption-at-rest INTEGRATION for the S3
// substrate, run HERMETICALLY against an in-memory transport stub (same posture
// as store_s3_subtree_test.v — no live S3 in the gate). With `encrypt-key-id`,
// every object key under objects/ holds an AEAD envelope keyed by the PLAINTEXT
// hash (EncryptingWrapper over S3ObjectBackend's KeyedObjectBackend seam); the
// `.cxstore-encryption` marker key declares the at-rest mode. Mirrors the
// pack/sqlite suites: round-trip, NO plaintext at rest, dedup parity,
// wrong/absent KEK fail-closed, mode mismatch.

import os

const s3enc_test_kek = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'

// EncStubTransport — an in-memory S3 transport (PUT/GET/HEAD over a map).
@[heap]
struct EncStubTransport {
mut:
	blobs map[string][]u8
}

fn (t &EncStubTransport) fetch(method string, key string) (int, []u8, bool) {
	match method {
		'HEAD' {
			return if key in t.blobs { 200 } else { 404 }, []u8{}, true
		}
		'GET' {
			if v := t.blobs[key] {
				return 200, v, true
			}
			return 404, []u8{}, true
		}
		else {
			return 400, []u8{}, true
		}
	}
}

fn (mut t EncStubTransport) store(key string, body []u8) (int, bool) {
	t.blobs[key] = body.clone()
	return 200, true
}

fn (t &EncStubTransport) keys() []string {
	return t.blobs.keys()
}

fn s3enc_canon_hash(text string) (string, string) {
	c := render_canonical(cx.parse(text) or { panic('parse: ${err.msg()}') }.elements[0])
	h := cx.cx_text_hash(c) or { panic('hash: ${err.msg()}') }
	return c, h
}

// s3enc_store builds an s3 MemStore over `t`, wrapped for encryption when
// key_id != '' (the same wiring store_open_impl performs).
fn s3enc_store(t &EncStubTransport, key_id string) &MemStore {
	s3be := &S3ObjectBackend{
		transport: S3Transport(t)
	}
	mut ob := cxstore.ObjectBackend(s3be)
	if key_id != '' {
		kms := store_kek_kms(key_id) or { panic('kms: ${err.msg()}') }
		ob = cxstore.ObjectBackend(cxstore.new_encrypting_wrapper(s3be, key_id, kms))
	}
	return &MemStore{
		url:         's3://bucket/prefix'
		backend:     's3'
		is_open:     true
		enc_key_id:  key_id
		obj_backend: ob
	}
}

// s3enc_bucket_has_plaintext scans every stored blob for the needles.
fn s3enc_bucket_has_plaintext(t &EncStubTransport, needles []string) bool {
	for _, blob in t.blobs {
		s := blob.bytestr()
		for n in needles {
			if s.contains(n) {
				return true
			}
		}
	}
	return false
}

fn s3enc_put(mut ms MemStore, text string) string {
	c, h := s3enc_canon_hash(text)
	store_put_canonical(mut ms, h, c) or { panic('put: ${err.msg()}') }
	store_s3_flush(mut ms) or { panic('flush: ${err.msg()}') }
	return h
}

fn s3enc_load_ok(mut ms MemStore) bool {
	store_s3_load(mut ms) or { return false }
	return true
}

fn test_store_s3_encrypted_roundtrip_and_at_rest() {
	os.setenv('CX_STORE_KEK_tenant1', s3enc_test_kek, true)
	defer {
		os.unsetenv('CX_STORE_KEK_tenant1')
	}
	mut t := &EncStubTransport{}
	c, h := s3enc_canon_hash('[order [id 1] [customer [name "Acme"] [addr [city "NYC"]]]]')

	mut ms := s3enc_store(t, 'tenant1')
	assert s3enc_load_ok(mut ms), 'fresh encrypted open must succeed (stamps the marker)'
	store_put_canonical(mut ms, h, c) or { panic(err) }
	store_s3_flush(mut ms) or { panic(err) }
	ms.alias_order << 'orders/latest'
	ms.aliases['orders/latest'] = h
	store_s3_flush(mut ms) or { panic(err) }

	// marker declared, and nothing under objects/ leaks plaintext. The refs
	// manifest is hash-only (same posture as the pack/cxobj manifests), so scan
	// the OBJECT keys for doc content and alias-name bytes.
	marker := t.blobs['.cxstore-encryption'] or { panic('encryption marker missing') }
	assert marker.bytestr() == 'keyed'
	for k, blob in t.blobs {
		if !k.starts_with('objects/') {
			continue
		}
		s := blob.bytestr()
		for n in ['Acme', 'NYC', 'customer', 'orders/latest'] {
			assert !s.contains(n), 'plaintext `${n}` must not appear in object ${k}'
		}
	}

	// reopen (fresh MemStore, same bucket) with the SAME KEK → byte-identical.
	mut ms2 := s3enc_store(t, 'tenant1')
	assert s3enc_load_ok(mut ms2), 'reopen with correct KEK must succeed'
	assert store_doc_present(ms2, h), 'doc missing after reopen'
	got := store_doc_text(ms2, h) or { panic('get: ${err.msg()}') }
	assert got == c, 'decrypted reconstruct must be byte-identical'
	assert ms2.aliases['orders/latest'] == h, 'alias must survive the encrypted round-trip'
}

fn test_store_s3_encrypted_dedup_parity() {
	os.setenv('CX_STORE_KEK_tenant1', s3enc_test_kek, true)
	defer {
		os.unsetenv('CX_STORE_KEK_tenant1')
	}
	mut te := &EncStubTransport{}
	mut tp := &EncStubTransport{}

	mut mse := s3enc_store(te, 'tenant1')
	assert s3enc_load_ok(mut mse)
	s3enc_put(mut mse, '[a [shared [x 1] [y 2] [z [deep "value"]]] [only "one"]]')
	s3enc_put(mut mse, '[b [shared [x 1] [y 2] [z [deep "value"]]] [only "two"]]')

	mut msp := s3enc_store(tp, '')
	assert s3enc_load_ok(mut msp)
	s3enc_put(mut msp, '[a [shared [x 1] [y 2] [z [deep "value"]]] [only "one"]]')
	s3enc_put(mut msp, '[b [shared [x 1] [y 2] [z [deep "value"]]] [only "two"]]')

	ce := mse.obj_backend or { panic('no enc backend') }.object_count()
	cp := msp.obj_backend or { panic('no plain backend') }.object_count()
	assert ce == cp, 'encrypted s3 store must dedup exactly like plaintext (${ce} vs ${cp})'
}

fn test_store_s3_encrypted_wrong_or_absent_kek_fails_closed() {
	os.setenv('CX_STORE_KEK_tenant1', s3enc_test_kek, true)
	mut t := &EncStubTransport{}
	mut ms := s3enc_store(t, 'tenant1')
	assert s3enc_load_ok(mut ms)
	h := s3enc_put(mut ms, '[secret [token "hunter2"] [scope "admin"]]')

	// wrong KEK → envelopes do not authenticate → the eager D-record replay
	// fails the reopen (never a silent wrong doc).
	os.setenv('CX_STORE_KEK_tenant1', 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
		true)
	mut ms2 := s3enc_store(t, 'tenant1')
	assert !s3enc_load_ok(mut ms2), 'wrong KEK must fail the open (fail-closed)'
	_ := h

	// absent KEK → the wrapper cannot even be constructed (store_kek_kms fails);
	// prove it fail-closes at the same seam store_open_impl uses.
	os.unsetenv('CX_STORE_KEK_tenant1')
	if _ := store_kek_kms('tenant1') {
		panic('absent KEK must fail store_kek_kms (fail-closed)')
	}
}

fn test_store_s3_mode_mismatch_fails_closed() {
	os.setenv('CX_STORE_KEK_tenant1', s3enc_test_kek, true)
	defer {
		os.unsetenv('CX_STORE_KEK_tenant1')
	}

	// encrypted bucket reopened WITHOUT encrypt-key-id → hard error (marker).
	mut te := &EncStubTransport{}
	mut mse := s3enc_store(te, 'tenant1')
	assert s3enc_load_ok(mut mse)
	s3enc_put(mut mse, '[doc [v 1]]')
	mut plain_reopen := s3enc_store(te, '')
	assert !s3enc_load_ok(mut plain_reopen), 'encrypted s3 store opened without its key must error'

	// plaintext bucket reopened WITH encrypt-key-id → hard error (existing data).
	mut tp := &EncStubTransport{}
	mut msp := s3enc_store(tp, '')
	assert s3enc_load_ok(mut msp)
	s3enc_put(mut msp, '[doc [v 1]]')
	mut enc_reopen := s3enc_store(tp, 'tenant1')
	assert !s3enc_load_ok(mut enc_reopen), 'encrypt-key-id on an existing plaintext s3 store must error'
}
