module code

import cx
import os

// store_sqlite_encryption_test.v — #229 encryption-at-rest INTEGRATION for the
// SQLITE substrate: a sqlite:// store opened with `encrypt-key-id` stores every
// object row as an AEAD envelope keyed by the PLAINTEXT hash (EncryptingWrapper
// over the row backend's KeyedObjectBackend seam); the `cxstore_meta` encryption
// marker declares the at-rest mode so a mode mismatch is a hard error. Gated on
// `-d cxstore_sqlite` like the backend (no-op bodies without it). Mirrors
// store_pack_encryption_test.v / store_encryption_test.v: round-trip, NO
// plaintext at rest, dedup parity, wrong/absent KEK fail-closed, mode mismatch.

const senc_test_kek = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'

fn senc_canon_hash(text string) (string, string) {
	c := render_canonical(cx.parse(text) or { panic('parse: ${err.msg()}') }.elements[0])
	h := cx.cx_text_hash(c) or { panic('hash: ${err.msg()}') }
	return c, h
}

fn senc_mem_store(path string, key_id string) &MemStore {
	return &MemStore{
		url:        'sqlite://${path}'
		backend:    'sqlite'
		root:       path
		is_open:    true
		enc_key_id: key_id
	}
}

// senc_db_has_plaintext scans the raw database file bytes for the needles. The
// object rows are hex-encoded, so plaintext leaks as the hex image of the
// needle; check both the raw bytes and the hex encoding.
fn senc_db_has_plaintext(path string, needles []string) bool {
	blob := os.read_bytes(path) or { return false }
	s := blob.bytestr()
	for n in needles {
		if s.contains(n) || s.contains(n.bytes().hex()) {
			return true
		}
	}
	return false
}

fn test_store_sqlite_encrypted_roundtrip_and_at_rest() {
	$if cxstore_sqlite ? {
		path := os.join_path(os.temp_dir(), 'cxstore_sqlite_enc_${os.getpid()}.db')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		os.setenv('CX_STORE_KEK_tenant1', senc_test_kek, true)
		defer {
			os.unsetenv('CX_STORE_KEK_tenant1')
		}

		c, h := senc_canon_hash('[order [id 1] [customer [name "Acme"] [addr [city "NYC"]]]]')
		mut ms := senc_mem_store(path, 'tenant1')
		store_sqlite_attach(mut ms) or { panic('attach: ${err.msg()}') }
		store_put_canonical(mut ms, h, c) or { panic('put: ${err.msg()}') }
		store_sqlite_persist(ms) or { panic('persist: ${err.msg()}') }
		ms.alias_order << 'orders/latest'
		ms.aliases['orders/latest'] = h
		store_sqlite_persist(ms) or { panic('persist2: ${err.msg()}') }

		// at rest: no plaintext field values and no plaintext alias name (checked
		// raw AND hex-encoded, since rows are hex TEXT columns).
		assert senc_db_has_plaintext(path, ['Acme', 'NYC', 'customer', 'orders/latest']) == false, 'plaintext must not appear in the database at rest'

		// reopen with the SAME KEK → byte-identical reconstruct + alias resolves.
		mut ms2 := senc_mem_store(path, 'tenant1')
		store_sqlite_load(mut ms2) or { panic('reopen: ${err.msg()}') }
		assert store_doc_present(ms2, h), 'doc missing after reopen'
		got := store_doc_text(ms2, h) or { panic('get: ${err.msg()}') }
		assert got == c, 'decrypted reconstruct must be byte-identical'
		assert ms2.aliases['orders/latest'] == h, 'alias must survive the encrypted round-trip'
	}
}

fn test_store_sqlite_encrypted_dedup_parity() {
	$if cxstore_sqlite ? {
		// Encryption keys by PLAINTEXT hash → identical distinct-object count as a
		// plaintext store of the same corpus (structural sharing unchanged).
		path_e := os.join_path(os.temp_dir(), 'cxstore_sqlite_enc_de_${os.getpid()}.db')
		path_p := os.join_path(os.temp_dir(), 'cxstore_sqlite_enc_dp_${os.getpid()}.db')
		os.rm(path_e) or {}
		os.rm(path_p) or {}
		defer {
			os.rm(path_e) or {}
			os.rm(path_p) or {}
		}
		os.setenv('CX_STORE_KEK_tenant1', senc_test_kek, true)
		defer {
			os.unsetenv('CX_STORE_KEK_tenant1')
		}

		c1, h1 := senc_canon_hash('[a [shared [x 1] [y 2] [z [deep "value"]]] [only "one"]]')
		c2, h2 := senc_canon_hash('[b [shared [x 1] [y 2] [z [deep "value"]]] [only "two"]]')

		mut mse := senc_mem_store(path_e, 'tenant1')
		store_sqlite_attach(mut mse) or { panic(err) }
		store_put_canonical(mut mse, h1, c1) or { panic(err) }
		store_put_canonical(mut mse, h2, c2) or { panic(err) }
		store_sqlite_persist(mse) or { panic(err) }

		mut msp := senc_mem_store(path_p, '')
		store_sqlite_attach(mut msp) or { panic(err) }
		store_put_canonical(mut msp, h1, c1) or { panic(err) }
		store_put_canonical(mut msp, h2, c2) or { panic(err) }
		store_sqlite_persist(msp) or { panic(err) }

		ce := mse.obj_backend or { panic('no enc backend') }.object_count()
		cp := msp.obj_backend or { panic('no plain backend') }.object_count()
		assert ce == cp, 'encrypted sqlite store must dedup exactly like plaintext (${ce} vs ${cp})'
	}
}

fn test_store_sqlite_encrypted_wrong_or_absent_kek_fails_closed() {
	$if cxstore_sqlite ? {
		path := os.join_path(os.temp_dir(), 'cxstore_sqlite_enc_wk_${os.getpid()}.db')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		os.setenv('CX_STORE_KEK_tenant1', senc_test_kek, true)
		c, h := senc_canon_hash('[secret [token "hunter2"] [scope "admin"]]')
		mut ms := senc_mem_store(path, 'tenant1')
		store_sqlite_attach(mut ms) or { panic(err) }
		store_put_canonical(mut ms, h, c) or { panic(err) }
		store_sqlite_persist(ms) or { panic(err) }

		// wrong KEK → envelopes do not authenticate → the eager D-record replay
		// fails the open (never a silent wrong doc).
		os.setenv('CX_STORE_KEK_tenant1', 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
			true)
		mut ms2 := senc_mem_store(path, 'tenant1')
		if _ := store_sqlite_load_result(mut ms2) {
			panic('wrong KEK must fail the open (fail-closed)')
		}

		// absent KEK → hard open error (no silent ephemeral key).
		os.unsetenv('CX_STORE_KEK_tenant1')
		mut ms3 := senc_mem_store(path, 'tenant1')
		if _ := store_sqlite_load_result(mut ms3) {
			panic('absent KEK must fail to open the encrypted store')
		}
	}
}

fn test_store_sqlite_mode_mismatch_fails_closed() {
	$if cxstore_sqlite ? {
		os.setenv('CX_STORE_KEK_tenant1', senc_test_kek, true)
		defer {
			os.unsetenv('CX_STORE_KEK_tenant1')
		}
		c, h := senc_canon_hash('[doc [v 1]]')

		// encrypted store reopened WITHOUT encrypt-key-id → hard error (the
		// cxstore_meta marker declares it keyed), never silently-empty.
		path_e := os.join_path(os.temp_dir(), 'cxstore_sqlite_enc_mm_e_${os.getpid()}.db')
		os.rm(path_e) or {}
		defer {
			os.rm(path_e) or {}
		}
		mut mse := senc_mem_store(path_e, 'tenant1')
		store_sqlite_attach(mut mse) or { panic(err) }
		store_put_canonical(mut mse, h, c) or { panic(err) }
		store_sqlite_persist(mse) or { panic(err) }
		mut plain_reopen := senc_mem_store(path_e, '')
		if _ := store_sqlite_load_result(mut plain_reopen) {
			panic('encrypted sqlite store opened without its key must error')
		}

		// plaintext store reopened WITH encrypt-key-id → hard error (encryption
		// cannot be enabled on existing data in place).
		path_p := os.join_path(os.temp_dir(), 'cxstore_sqlite_enc_mm_p_${os.getpid()}.db')
		os.rm(path_p) or {}
		defer {
			os.rm(path_p) or {}
		}
		mut msp := senc_mem_store(path_p, '')
		store_sqlite_attach(mut msp) or { panic(err) }
		store_put_canonical(mut msp, h, c) or { panic(err) }
		store_sqlite_persist(msp) or { panic(err) }
		mut enc_reopen := senc_mem_store(path_p, 'tenant1')
		if _ := store_sqlite_load_result(mut enc_reopen) {
			panic('encrypt-key-id on an existing plaintext sqlite store must error')
		}
	}
}

fn test_store_sqlite_open_path_encrypted() {
	$if cxstore_sqlite ? {
		// through store_open_impl: sqlite:// + encrypt-key-id opens, writes sealed.
		os.setenv('CX_STORE_KEK_tenant1', senc_test_kek, true)
		defer {
			os.unsetenv('CX_STORE_KEK_tenant1')
		}
		caps_set_all()
		path := os.join_path(os.temp_dir(), 'cxstore_sqlite_enc_open_${os.getpid()}.db')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		mut auth := map[string]string{}
		auth['encrypt-key-id'] = 'tenant1'
		r := store_open_impl('sqlite://${path}', '', '', false, true, auth.clone())
		assert senc_err_code(r) == '', 'sqlite with encrypt-key-id must open (got ${senc_err_code(r)})'
		sid := senc_handle_id(r) or { panic('no handle id') }
		mut ms := store_lookup(sid) or { panic('handle ${sid} not registered') }
		cc, hh := senc_canon_hash('[wired [via "store_open_impl"] [secretmark "sqlite-open-classified"]]')
		store_put_canonical(mut ms, hh, cc) or { panic(err) }
		store_persist(mut ms) or { panic('persist: ${err.msg()}') }
		assert senc_db_has_plaintext(path, ['sqlite-open-classified', 'secretmark']) == false, 'open-path writes must be sealed at rest'
	}
}

fn test_store_sqlite_kek_rotation_acceptance() {
	$if cxstore_sqlite ? {
		// #287 (store.md §9.1): rotate a sqlite store KEK A → B through the full
		// `store-rotate-kek` builtin — reads/writes keep working, re-run is a
		// no-op, and after destroying KEK A everything still opens under B.
		os.setenv('CX_STORE_KEK_tenant_a', senc_test_kek, true)
		os.setenv('CX_STORE_KEK_tenant_b', 'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100',
			true)
		defer {
			os.unsetenv('CX_STORE_KEK_tenant_a')
			os.unsetenv('CX_STORE_KEK_tenant_b')
		}
		caps_set_all()
		path := os.join_path(os.temp_dir(), 'cxstore_sqlite_rot_${os.getpid()}.db')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		mut auth := map[string]string{}
		auth['encrypt-key-id'] = 'tenant_a'
		r := store_open_impl('sqlite://${path}', '', '', false, true, auth.clone())
		assert senc_err_code(r) == '', 'open under A: ${senc_err_code(r)}'
		sid := senc_handle_id(r) or { panic('no handle id') }
		mut ms := store_lookup(sid) or { panic('handle ${sid} not registered') }
		c1, h1 := senc_canon_hash('[order [id 1] [customer [name "Acme"]]]')
		store_put_canonical(mut ms, h1, c1) or { panic(err) }
		store_persist(mut ms) or { panic(err) }

		rep := store_stdlib_builtin_inner('store-rotate-kek', [r, store_str('tenant_b')]) or {
			panic('rotate returned none')
		}
		assert senc_err_code(rep) == '', 'rotate: ${senc_err_code(rep)}'
		mut rewrapped := ''
		mut objects := ''
		if rep is cx.Element {
			assert rep.name == 'rotation-report'
			rewrapped = rep.attr('rewrapped')
			objects = rep.attr('objects')
			assert rep.attr('from') == 'tenant_a'
			assert rep.attr('to') == 'tenant_b'
		}
		assert objects.int() > 0
		assert rewrapped == objects, 'first rotation must re-wrap every envelope'

		// the handle keeps serving: read + write after rotation (wraps under B).
		got := store_doc_text(ms, h1) or { panic(err.msg()) }
		assert got == c1
		c2, h2 := senc_canon_hash('[order [id 2] [customer [name "Post-rotation"]]]')
		store_put_canonical(mut ms, h2, c2) or { panic(err) }
		store_persist(mut ms) or { panic(err) }

		// re-run: resumable no-op.
		rep2 := store_stdlib_builtin_inner('store-rotate-kek', [r, store_str('tenant_b')]) or {
			panic('re-rotate returned none')
		}
		assert senc_err_code(rep2) == ''
		if rep2 is cx.Element {
			assert rep2.attr('rewrapped').int() == 0
			assert rep2.attr('already-current').int() > 0
		}
		store_stdlib_builtin_inner('store-close', [r]) or { cx.Node(cx.Element{}) }

		// destroy KEK A → reopen under B only, byte-identical.
		os.unsetenv('CX_STORE_KEK_tenant_a')
		mut msb := senc_mem_store(path, 'tenant_b')
		store_sqlite_load(mut msb) or { panic('reopen under B: ${err.msg()}') }
		g1 := store_doc_text(msb, h1) or { panic(err.msg()) }
		g2 := store_doc_text(msb, h2) or { panic(err.msg()) }
		assert g1 == c1
		assert g2 == c2
	}
}

fn senc_err_code(n cx.Node) string {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'code' {
				return cx.scalar_value_str_public(a.value)
			}
		}
	}
	return ''
}

fn senc_handle_id(n cx.Node) ?int {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'handle' {
				return cx.scalar_value_str_public(a.value).int()
			}
		}
	}
	return none
}
