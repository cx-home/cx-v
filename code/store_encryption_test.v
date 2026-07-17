module code

import cx
import os

// store_encryption_test.v — #114 (PR-E) encryption-at-rest INTEGRATION through the
// store object-graph: a cxobj:// store opened with `encrypt-key-id` decomposes a
// doc into the subtree object graph and AEAD-seals each object at rest (envelope:
// per-object DEK wrapped by the env-resolved KEK). The object graph keys by the
// PLAINTEXT hash, so dedup/structural-sharing are unchanged; only the bytes on disk
// are ciphertext. Proves: round-trip reconstruct, NO plaintext at rest, and
// fail-closed on a wrong KEK. (The AEAD primitive + KMS seam are unit-tested in
// vcx/cxstore/encryption_test.v; this is the live store integration.)

const enc_test_kek = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'

fn enc_canon_hash(text string) (string, string) {
	c := render_canonical(cx.parse(text) or { panic('parse: ${err.msg()}') }.elements[0])
	h := cx.cx_text_hash(c) or { panic('hash: ${err.msg()}') }
	return c, h
}

fn enc_dir_has_plaintext(objdir string, needles []string) bool {
	shards := os.ls(objdir) or { return false }
	for sh in shards {
		sub := os.join_path(objdir, sh)
		if !os.is_dir(sub) {
			continue
		}
		for f in (os.ls(sub) or { []string{} }) {
			blob := os.read_bytes(os.join_path(sub, f)) or { continue }
			s := blob.bytestr()
			for n in needles {
				if s.contains(n) {
					return true
				}
			}
		}
	}
	return false
}

fn enc_cxobj_load_ok(mut ms MemStore) bool {
	store_cxobj_load(mut ms) or { return false }
	return true
}

fn test_store_cxobj_encrypted_roundtrip_and_at_rest() {
	dir := os.join_path(os.temp_dir(), 'cx_store_enc_${os.getpid()}')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
	}
	os.setenv('CX_STORE_KEK_tenant1', enc_test_kek, true)

	c, h := enc_canon_hash('[order [id 1] [customer [name "Acme"] [addr [city "NYC"]]]]')

	mut ms := &MemStore{
		url:        'file://${dir}?encoding=object-per-key'
		backend:    'cxobj'
		root:       dir
		is_open:    true
		enc_key_id: 'tenant1'
	}
	store_put_canonical(mut ms, h, c) or { panic('put: ${err.msg()}') }
	store_cxobj_flush(mut ms) or { panic('flush: ${err.msg()}') }

	// at rest: the object files must be ciphertext — no plaintext field values.
	objdir := os.join_path(dir, cxobj_objects_dir)
	assert os.exists(objdir), 'objects dir not written'
	assert !enc_dir_has_plaintext(objdir, ['Acme', 'NYC', 'customer']), 'plaintext must not appear at rest'

	// reopen with the SAME KEK → reconstruct byte-identical (lazy resolve + decrypt).
	mut ms2 := &MemStore{
		url:        'file://${dir}?encoding=object-per-key'
		backend:    'cxobj'
		root:       dir
		is_open:    true
		enc_key_id: 'tenant1'
	}
	assert enc_cxobj_load_ok(mut ms2), 'reopen with correct KEK must succeed'
	assert store_doc_present(ms2, h), 'doc missing after reopen'
	got := store_doc_text(ms2, h) or { panic('get: ${err.msg()}') }
	assert got == c, 'decrypted reconstruct must be byte-identical'

	os.unsetenv('CX_STORE_KEK_tenant1')
}

fn test_store_cxobj_encrypted_wrong_kek_fails_closed() {
	dir := os.join_path(os.temp_dir(), 'cx_store_enc_wk_${os.getpid()}')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
	}
	os.setenv('CX_STORE_KEK_tenant1', enc_test_kek, true)
	c, h := enc_canon_hash('[secret [token "hunter2"] [scope "admin"]]')
	mut ms := &MemStore{
		url:        'file://${dir}?encoding=object-per-key'
		backend:    'cxobj'
		root:       dir
		is_open:    true
		enc_key_id: 'tenant1'
	}
	store_put_canonical(mut ms, h, c) or { panic('put: ${err.msg()}') }
	store_cxobj_flush(mut ms) or { panic('flush: ${err.msg()}') }

	// reopen with a DIFFERENT KEK → the at-rest envelopes do not authenticate, so
	// objects resolve to none → reconstruction fails (never a silent wrong doc).
	os.setenv('CX_STORE_KEK_tenant1', 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
		true)
	mut ms2 := &MemStore{
		url:        'file://${dir}?encoding=object-per-key'
		backend:    'cxobj'
		root:       dir
		is_open:    true
		enc_key_id: 'tenant1'
	}
	enc_cxobj_load_ok(mut ms2) // load may register refs regardless; the get must fail
	recovered := store_doc_text(ms2, h) or { '' }
	assert recovered != c, 'wrong KEK must NOT reconstruct the plaintext (fail-closed)'

	// absent KEK → hard open error (fail-closed, no silent ephemeral key).
	os.unsetenv('CX_STORE_KEK_tenant1')
	mut ms3 := &MemStore{
		url:        'file://${dir}?encoding=object-per-key'
		backend:    'cxobj'
		root:       dir
		is_open:    true
		enc_key_id: 'tenant1'
	}
	assert !enc_cxobj_load_ok(mut ms3), 'absent KEK must fail to open the encrypted store'
}
