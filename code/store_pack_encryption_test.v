module code

import cx
import cxstore
import os

// store_pack_encryption_test.v — #229 encryption-at-rest INTEGRATION for the PACK
// substrate: a cxpack (bare `file://`) store opened with `encrypt-key-id`
// decomposes docs into the subtree object graph and stages each object through
// the EncryptingWrapper as an AEAD envelope keyed by the PLAINTEXT hash, flushed
// into v2 KEYED packs. Dedup/structural sharing are unchanged; only the at-rest
// bytes are ciphertext. Proves: round-trip reconstruct, NO plaintext at rest
// (segments AND the compacted pack), dedup parity with a plaintext store,
// fail-closed on wrong/absent KEK, and the keyed↔plaintext mode-mismatch guards.
// (The keyed pack format + wrapper are unit-tested in
// vcx/cxstore/encryption_wrapper_test.v; this is the live store integration.)

const penc_test_kek = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'

fn penc_canon_hash(text string) (string, string) {
	c := render_canonical(cx.parse(text) or { panic('parse: ${err.msg()}') }.elements[0])
	h := cx.cx_text_hash(c) or { panic('hash: ${err.msg()}') }
	return c, h
}

// penc_dir_has_plaintext scans every pack file under `root` for the needles.
fn penc_dir_has_plaintext(root string, needles []string) bool {
	for f in (os.ls(root) or { []string{} }) {
		if !f.ends_with('.cxpack') {
			continue
		}
		blob := os.read_bytes(os.join_path(root, f)) or { continue }
		s := blob.bytestr()
		for n in needles {
			if s.contains(n) {
				return true
			}
		}
	}
	return false
}

fn penc_mem_store(dir string, key_id string) &MemStore {
	return &MemStore{
		url:        'file://${dir}'
		backend:    'cxpack'
		root:       dir
		is_open:    true
		enc_key_id: key_id
	}
}

fn penc_load_ok(mut ms MemStore) bool {
	store_cxpack_load(mut ms) or { return false }
	return true
}

fn penc_set_alias(mut ms MemStore, name string, hash string) {
	if name !in ms.aliases {
		ms.alias_order << name
	}
	ms.aliases[name] = hash
}

fn test_store_cxpack_encrypted_roundtrip_and_at_rest() {
	dir := os.join_path(os.temp_dir(), 'cx_store_penc_${os.getpid()}')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
	}
	os.setenv('CX_STORE_KEK_tenant1', penc_test_kek, true)
	defer {
		os.unsetenv('CX_STORE_KEK_tenant1')
	}

	c, h := penc_canon_hash('[order [id 1] [customer [name "Acme"] [addr [city "NYC"]]]]')

	mut ms := penc_mem_store(dir, 'tenant1')
	store_put_canonical(mut ms, h, c) or { panic('put: ${err.msg()}') }
	store_cxpack_flush(mut ms) or { panic('flush: ${err.msg()}') }
	penc_set_alias(mut ms, 'orders/latest', h)
	store_cxpack_flush(mut ms) or { panic('flush2: ${err.msg()}') }

	// at rest: pack files must be ciphertext — no plaintext field values, and no
	// plaintext alias name either (alias-name objects are sealed too).
	assert penc_dir_has_plaintext(dir, ['Acme', 'NYC', 'customer', 'orders/latest']) == false, 'plaintext must not appear in any pack at rest'

	// reopen with the SAME KEK → byte-identical reconstruct + alias resolves.
	mut ms2 := penc_mem_store(dir, 'tenant1')
	assert penc_load_ok(mut ms2), 'reopen with correct KEK must succeed'
	assert store_doc_present(ms2, h), 'doc missing after reopen'
	got := store_doc_text(ms2, h) or { panic('get: ${err.msg()}') }
	assert got == c, 'decrypted reconstruct must be byte-identical'
	assert ms2.aliases['orders/latest'] == h, 'alias must survive the encrypted round-trip'
}

fn test_store_cxpack_encrypted_dedup_parity() {
	// The object graph keys by PLAINTEXT hash, so an encrypted store must hold
	// EXACTLY as many distinct objects as a plaintext store of the same corpus
	// (structural sharing unchanged by encryption).
	dir_e := os.join_path(os.temp_dir(), 'cx_store_penc_dedup_e_${os.getpid()}')
	dir_p := os.join_path(os.temp_dir(), 'cx_store_penc_dedup_p_${os.getpid()}')
	os.rmdir_all(dir_e) or {}
	os.rmdir_all(dir_p) or {}
	defer {
		os.rmdir_all(dir_e) or {}
		os.rmdir_all(dir_p) or {}
	}
	os.setenv('CX_STORE_KEK_tenant1', penc_test_kek, true)
	defer {
		os.unsetenv('CX_STORE_KEK_tenant1')
	}

	// two docs sharing a large identical subtree
	c1, h1 := penc_canon_hash('[a [shared [x 1] [y 2] [z [deep "value"]]] [only "one"]]')
	c2, h2 := penc_canon_hash('[b [shared [x 1] [y 2] [z [deep "value"]]] [only "two"]]')

	mut mse := penc_mem_store(dir_e, 'tenant1')
	store_put_canonical(mut mse, h1, c1) or { panic(err) }
	store_put_canonical(mut mse, h2, c2) or { panic(err) }
	store_cxpack_flush(mut mse) or { panic(err) }

	mut msp := penc_mem_store(dir_p, '')
	store_put_canonical(mut msp, h1, c1) or { panic(err) }
	store_put_canonical(mut msp, h2, c2) or { panic(err) }
	store_cxpack_flush(mut msp) or { panic(err) }

	assert mse.obj_pack.object_count() == msp.obj_pack.object_count(), 'encrypted store must dedup exactly like plaintext (same distinct-object count)'
}

fn test_store_cxpack_encrypted_compaction() {
	dir := os.join_path(os.temp_dir(), 'cx_store_penc_comp_${os.getpid()}')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
	}
	os.setenv('CX_STORE_KEK_tenant1', penc_test_kek, true)
	defer {
		os.unsetenv('CX_STORE_KEK_tenant1')
	}

	mut ms := penc_mem_store(dir, 'tenant1')
	mut hashes := []string{}
	mut texts := []string{}
	for i in 0 .. 5 {
		c, h := penc_canon_hash('[doc [n ${i}] [secretfield "classified-${i}"]]')
		store_put_canonical(mut ms, h, c) or { panic(err) }
		store_cxpack_flush(mut ms) or { panic(err) }
		hashes << h
		texts << c
	}
	penc_set_alias(mut ms, 'compact/alias', hashes[0])
	store_cxpack_flush(mut ms) or { panic(err) }
	// fold everything (envelope-level compaction — never decrypts)
	store_cxpack_compact(mut ms) or { panic('compact: ${err.msg()}') }

	assert os.exists(os.join_path(dir, 'store.cxpack')), 'compacted pack must exist'
	assert penc_dir_has_plaintext(dir, ['classified-0', 'classified-4', 'secretfield',
		'compact/alias']) == false, 'compacted pack must stay ciphertext'

	// reopen: every doc reconstructs byte-identical from the compacted pack
	mut ms2 := penc_mem_store(dir, 'tenant1')
	assert penc_load_ok(mut ms2), 'reopen after compaction must succeed'
	for i, h in hashes {
		got := store_doc_text(ms2, h) or { panic('get ${i}: ${err.msg()}') }
		assert got == texts[i], 'doc ${i} must survive compaction byte-identical'
	}
	assert ms2.aliases['compact/alias'] == hashes[0]
}

fn test_store_cxpack_encrypted_wrong_or_absent_kek_fails_closed() {
	dir := os.join_path(os.temp_dir(), 'cx_store_penc_wk_${os.getpid()}')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
	}
	os.setenv('CX_STORE_KEK_tenant1', penc_test_kek, true)
	c, h := penc_canon_hash('[secret [token "hunter2"] [scope "admin"]]')
	mut ms := penc_mem_store(dir, 'tenant1')
	store_put_canonical(mut ms, h, c) or { panic(err) }
	store_cxpack_flush(mut ms) or { panic(err) }

	// wrong KEK → envelopes do not authenticate → HARD open error (the pack
	// load path decrypts eagerly, so this fails at open, never a wrong doc).
	os.setenv('CX_STORE_KEK_tenant1', 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
		true)
	mut ms2 := penc_mem_store(dir, 'tenant1')
	assert !penc_load_ok(mut ms2), 'wrong KEK must fail the open (fail-closed)'

	// absent KEK → hard open error (no silent ephemeral key).
	os.unsetenv('CX_STORE_KEK_tenant1')
	mut ms3 := penc_mem_store(dir, 'tenant1')
	assert !penc_load_ok(mut ms3), 'absent KEK must fail to open the encrypted store'
}

fn test_store_cxpack_mode_mismatch_fails_closed() {
	os.setenv('CX_STORE_KEK_tenant1', penc_test_kek, true)
	defer {
		os.unsetenv('CX_STORE_KEK_tenant1')
	}

	// encrypted store reopened WITHOUT encrypt-key-id → hard error, never
	// silently-empty / integrity-corrupt.
	dir_e := os.join_path(os.temp_dir(), 'cx_store_penc_mm_e_${os.getpid()}')
	os.rmdir_all(dir_e) or {}
	defer {
		os.rmdir_all(dir_e) or {}
	}
	c, h := penc_canon_hash('[doc [v 1]]')
	mut mse := penc_mem_store(dir_e, 'tenant1')
	store_put_canonical(mut mse, h, c) or { panic(err) }
	store_cxpack_flush(mut mse) or { panic(err) }
	mut plain_reopen := penc_mem_store(dir_e, '')
	assert !penc_load_ok(mut plain_reopen), 'encrypted store opened without its key must error'

	// plaintext store reopened WITH encrypt-key-id → hard error (encryption
	// cannot be enabled on existing data in place — that would mix modes).
	dir_p := os.join_path(os.temp_dir(), 'cx_store_penc_mm_p_${os.getpid()}')
	os.rmdir_all(dir_p) or {}
	defer {
		os.rmdir_all(dir_p) or {}
	}
	mut msp := penc_mem_store(dir_p, '')
	store_put_canonical(mut msp, h, c) or { panic(err) }
	store_cxpack_flush(mut msp) or { panic(err) }
	mut enc_reopen := penc_mem_store(dir_p, 'tenant1')
	assert !penc_load_ok(mut enc_reopen), 'encrypt-key-id on an existing plaintext store must error'
}

fn test_store_open_impl_encrypt_guard_matrix() {
	os.setenv('CX_STORE_KEK_tenant1', penc_test_kek, true)
	defer {
		os.unsetenv('CX_STORE_KEK_tenant1')
	}
	caps_set_all()
	mut auth := map[string]string{}
	auth['encrypt-key-id'] = 'tenant1'

	// mem:// cannot seal at rest → CXER1100 fail-closed (unchanged, #184).
	r_mem := store_open_impl('mem://enc-guard', '', '', false, true, auth.clone())
	assert node_err_code(r_mem) == 'cx-err:CXER1100', 'mem:// with encrypt-key-id must fail closed'

	// document model has no object graph → CXER1100 fail-closed.
	dir_d := os.join_path(os.temp_dir(), 'cx_store_penc_open_d_${os.getpid()}')
	os.rmdir_all(dir_d) or {}
	defer {
		os.rmdir_all(dir_d) or {}
	}
	r_doc := store_open_impl('document+file://${dir_d}', '', '', false, true, auth.clone())
	assert node_err_code(r_doc) == 'cx-err:CXER1100', 'document model with encrypt-key-id must fail closed'

	// bare file:// (pack, the default) now SEALS (#229): open must succeed and
	// write ciphertext-only packs through the full store surface.
	dir_k := os.join_path(os.temp_dir(), 'cx_store_penc_open_k_${os.getpid()}')
	os.rmdir_all(dir_k) or {}
	defer {
		os.rmdir_all(dir_k) or {}
	}
	r_pack := store_open_impl('file://${dir_k}', '', '', false, true, auth.clone())
	assert node_err_code(r_pack) == '', 'pack store with encrypt-key-id must open (got ${node_err_code(r_pack)})'
	sid := store_handle_id(r_pack) or { panic('no handle id') }
	mut ms := store_lookup(sid) or { panic('handle ${sid} not registered') }
	cc, hh := penc_canon_hash('[wired [via "store_open_impl"] [secretmark "open-path-classified"]]')
	store_put_canonical(mut ms, hh, cc) or { panic(err) }
	store_persist(mut ms) or { panic('persist: ${err.msg()}') }
	assert penc_dir_has_plaintext(dir_k, ['open-path-classified', 'secretmark']) == false, 'open-path writes must be sealed at rest'
}

// ── tiny node helpers (shared shape with other store tests) ──────────────────

fn node_err_code(n cx.Node) string {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'code' {
				return cx.scalar_value_str_public(a.value)
			}
		}
	}
	return ''
}

fn store_handle_id(n cx.Node) ?int {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'handle' {
				return cx.scalar_value_str_public(a.value).int()
			}
		}
	}
	return none
}
