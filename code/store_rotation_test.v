module code

import cx
import cxstore
import os

// store_rotation_test.v — #287 KEK rotation INTEGRATION (store.md §9.1) through
// the full `store-rotate-kek` builtin on the sealing substrates:
//
//   - the issue's acceptance flow: a store encrypted under KEK A serves reads
//     and writes through a rotation to KEK B; after completion KEK A is
//     destroyed (env unset) and everything still opens byte-identical;
//   - mixed-key coexistence: envelopes under A and B in ONE store read fine
//     while both env keys exist (what "serves throughout" rests on);
//   - resumability: re-running reports already-current, re-wraps nothing;
//   - fail-closed: an envelope under an unresolvable key-id aborts CXER1142
//     (never skipped); a plaintext store is CXER1141; read-only is CXER1110;
//   - dedup/addresses preserved: object counts and hashes unchanged by rotation.
//
// cxpack (bare file://) + cxobj (?encoding=object-per-key) run on the real
// filesystem; s3 runs hermetically over an in-memory transport (the same
// posture as store_s3_encryption_test.v). sqlite's walk is covered by the
// gated suite in store_sqlite_encryption_test.v (-d cxstore_sqlite).

const rot_kek_a = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'
const rot_kek_b = 'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100'

fn rot_canon_hash(text string) (string, string) {
	c := render_canonical(cx.parse(text) or { panic('parse: ${err.msg()}') }.elements[0])
	h := cx.cx_text_hash(c) or { panic('hash: ${err.msg()}') }
	return c, h
}

fn rot_err_code(n cx.Node) string {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'code' {
				return cx.scalar_value_str_public(a.value)
			}
		}
	}
	return ''
}

fn rot_attr(n cx.Node, name string) string {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == name {
				return cx.scalar_value_str_public(a.value)
			}
		}
	}
	return ''
}

fn rot_handle_ms(n cx.Node) &MemStore {
	id := rot_attr(n, 'handle').int()
	return store_lookup(id) or { panic('handle ${id} not registered') }
}

fn rot_call(name string, args []cx.Node) cx.Node {
	return store_stdlib_builtin_inner(name, args) or { panic('${name} returned none') }
}

fn rot_setenv_ab() {
	os.setenv('CX_STORE_KEK_tenant_a', rot_kek_a, true)
	os.setenv('CX_STORE_KEK_tenant_b', rot_kek_b, true)
}

fn rot_unsetenv_ab() {
	os.unsetenv('CX_STORE_KEK_tenant_a')
	os.unsetenv('CX_STORE_KEK_tenant_b')
}

// rot_open opens url with encrypt-key-id=key_id through the real open path.
fn rot_open(url string, key_id string) cx.Node {
	caps_set_all()
	mut auth := map[string]string{}
	if key_id != '' {
		auth['encrypt-key-id'] = key_id
	}
	return store_open_impl(url, '', '', false, true, auth)
}

// ── the issue's acceptance flow, on the pack substrate (file:// default) ──────

fn test_rotation_cxpack_acceptance_flow() {
	dir := os.join_path(os.temp_dir(), 'cx_rot_pack_${os.getpid()}')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
		rot_unsetenv_ab()
	}
	rot_setenv_ab()

	// A store encrypted under KEK A, with data.
	h := rot_open('file://${dir}', 'tenant_a')
	assert rot_err_code(h) == '', 'open under A: ${rot_err_code(h)}'
	mut ms := rot_handle_ms(h)
	c1, h1 := rot_canon_hash('[order [id 1] [customer [name "Acme"] [addr [city "NYC"]]]]')
	store_put_canonical(mut ms, h1, c1) or { panic(err) }
	store_persist(mut ms) or { panic(err) }
	objects_before := ms.obj_pack.object_count()

	// Rotate A → B on the open handle.
	rep := rot_call('store-rotate-kek', [h, store_str('tenant_b')])
	assert rot_err_code(rep) == '', 'rotate: ${rot_err_code(rep)} ${rot_attr(rep, 'message')}'
	if rep is cx.Element {
		assert rep.name == 'rotation-report'
	}
	assert rot_attr(rep, 'to') == 'tenant_b'
	assert rot_attr(rep, 'from') == 'tenant_a'
	assert rot_attr(rep, 'objects').int() > 0
	assert rot_attr(rep, 'rewrapped').int() == rot_attr(rep, 'objects').int()
	assert rot_attr(rep, 'already-current').int() == 0

	// The handle keeps serving: read doc1, write doc2 (wraps under B now).
	got1 := store_doc_text(ms, h1) or { panic('read after rotate: ${err.msg()}') }
	assert got1 == c1, 'reads must survive rotation byte-identical'
	c2, h2 := rot_canon_hash('[order [id 2] [customer [name "Post-rotation"] [addr [city "SFO"]]]]')
	store_put_canonical(mut ms, h2, c2) or { panic(err) }
	store_persist(mut ms) or { panic(err) }

	// Dedup / addresses: rotation added no objects for the pre-existing corpus.
	assert ms.obj_pack.object_count() > objects_before, 'the post-rotation write adds objects'

	rot_call('store-close', [h])

	// DESTROY KEK A. Reopen under B only → everything opens byte-identical.
	os.unsetenv('CX_STORE_KEK_tenant_a')
	h_b := rot_open('file://${dir}', 'tenant_b')
	assert rot_err_code(h_b) == '', 'reopen under B after destroying A: ${rot_err_code(h_b)} ${rot_attr(h_b,
		'message')}'

	ms_b := rot_handle_ms(h_b)
	g1 := store_doc_text(ms_b, h1) or { panic('doc1 after A destroyed: ${err.msg()}') }
	g2 := store_doc_text(ms_b, h2) or { panic('doc2 after A destroyed: ${err.msg()}') }
	assert g1 == c1
	assert g2 == c2
	assert ms_b.obj_pack.object_count() == ms.obj_pack.object_count(), 'rotation + reopen must preserve the distinct-object count'
	rot_call('store-close', [h_b])
}

// ── mixed-key coexistence + resumability, on the pack substrate ───────────────

fn test_rotation_cxpack_mixed_store_coexists_and_resumes() {
	dir := os.join_path(os.temp_dir(), 'cx_rot_mix_${os.getpid()}')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
		rot_unsetenv_ab()
	}
	rot_setenv_ab()

	// Envelopes under A…
	h_a := rot_open('file://${dir}', 'tenant_a')
	assert rot_err_code(h_a) == ''
	mut ms_a := rot_handle_ms(h_a)
	c1, h1 := rot_canon_hash('[epoch [n 1] [written-under "a"]]')
	store_put_canonical(mut ms_a, h1, c1) or { panic(err) }
	store_persist(mut ms_a) or { panic(err) }
	rot_call('store-close', [h_a])

	// …then envelopes under B in the SAME store (a mid-rotation shape).
	h_b := rot_open('file://${dir}', 'tenant_b')
	assert rot_err_code(h_b) == '', 'mixed store must open under B while both env keys exist: ${rot_attr(h_b,
		'message')}'

	mut ms_b := rot_handle_ms(h_b)
	// the A-wrapped doc reads fine through B's handle (envelope key-id wins)
	g1 := store_doc_text(ms_b, h1) or { panic('A-wrapped doc via B handle: ${err.msg()}') }
	assert g1 == c1
	c2, h2 := rot_canon_hash('[epoch [n 2] [written-under "b"]]')
	store_put_canonical(mut ms_b, h2, c2) or { panic(err) }
	store_persist(mut ms_b) or { panic(err) }

	// Rotate to B: only the A-wrapped envelopes re-wrap; B's are already-current.
	rep := rot_call('store-rotate-kek', [h_b, store_str('tenant_b')])
	assert rot_err_code(rep) == '', 'rotate mixed: ${rot_attr(rep, 'message')}'
	assert rot_attr(rep, 'from') == 'tenant_a'
	assert rot_attr(rep, 'rewrapped').int() > 0
	assert rot_attr(rep, 'already-current').int() > 0
	total := rot_attr(rep, 'objects').int()
	assert total == rot_attr(rep, 'rewrapped').int() + rot_attr(rep, 'already-current').int()

	// Re-run: pure no-op — the resumability observable.
	rep2 := rot_call('store-rotate-kek', [h_b, store_str('tenant_b')])
	assert rot_err_code(rep2) == ''
	assert rot_attr(rep2, 'rewrapped').int() == 0
	assert rot_attr(rep2, 'already-current').int() == total
	assert rot_attr(rep2, 'from') == ''
	rot_call('store-close', [h_b])

	// KEK A destroyable.
	os.unsetenv('CX_STORE_KEK_tenant_a')
	h_c := rot_open('file://${dir}', 'tenant_b')
	assert rot_err_code(h_c) == ''
	ms_c := rot_handle_ms(h_c)
	gg1 := store_doc_text(ms_c, h1) or { panic(err.msg()) }
	gg2 := store_doc_text(ms_c, h2) or { panic(err.msg()) }
	assert gg1 == c1
	assert gg2 == c2
	rot_call('store-close', [h_c])
}

// ── object-per-key substrate (cxobj) ──────────────────────────────────────────

fn test_rotation_cxobj_acceptance_flow() {
	dir := os.join_path(os.temp_dir(), 'cx_rot_obj_${os.getpid()}')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
		rot_unsetenv_ab()
	}
	rot_setenv_ab()

	h := rot_open('file://${dir}?encoding=object-per-key', 'tenant_a')
	assert rot_err_code(h) == '', 'open cxobj under A: ${rot_attr(h, 'message')}'
	mut ms := rot_handle_ms(h)
	c1, h1 := rot_canon_hash('[cfg [region "eu-1"] [secretmark "obj-classified"]]')
	store_put_canonical(mut ms, h1, c1) or { panic(err) }
	store_persist(mut ms) or { panic(err) }

	rep := rot_call('store-rotate-kek', [h, store_str('tenant_b')])
	assert rot_err_code(rep) == '', 'rotate cxobj: ${rot_attr(rep, 'message')}'
	assert rot_attr(rep, 'rewrapped').int() > 0
	assert rot_attr(rep, 'from') == 'tenant_a'

	// every at-rest envelope now records tenant_b (walk the shard dirs raw).
	objdir := os.join_path(dir, 'objects')
	for sh in (os.ls(objdir) or { panic('objects dir missing') }) {
		sub := os.join_path(objdir, sh)
		if !os.is_dir(sub) {
			continue
		}
		for f in (os.ls(sub) or { []string{} }) {
			blob := os.read_bytes(os.join_path(sub, f)) or { panic(err) }
			env := cxstore.parse_envelope(blob) or {
				panic('at-rest blob must be a v2 envelope: ${err}')
			}
			assert env.key_id == 'tenant_b', 'object ${f} still wrapped under ${env.key_id}'
		}
	}

	// handle keeps serving; then destroy A and reopen under B.
	got := store_doc_text(ms, h1) or { panic(err.msg()) }
	assert got == c1
	rot_call('store-close', [h])
	os.unsetenv('CX_STORE_KEK_tenant_a')
	h_b := rot_open('file://${dir}?encoding=object-per-key', 'tenant_b')
	assert rot_err_code(h_b) == '', 'reopen cxobj under B: ${rot_attr(h_b, 'message')}'
	ms_b := rot_handle_ms(h_b)
	g := store_doc_text(ms_b, h1) or { panic(err.msg()) }
	assert g == c1
	rot_call('store-close', [h_b])
}

fn test_rotation_cxobj_alien_envelope_fails_closed() {
	dir := os.join_path(os.temp_dir(), 'cx_rot_alien_${os.getpid()}')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
		rot_unsetenv_ab()
	}
	rot_setenv_ab()

	h := rot_open('file://${dir}?encoding=object-per-key', 'tenant_a')
	assert rot_err_code(h) == ''
	mut ms := rot_handle_ms(h)
	c1, h1 := rot_canon_hash('[doc [v 1]]')
	store_put_canonical(mut ms, h1, c1) or { panic(err) }
	store_persist(mut ms) or { panic(err) }

	// plant an envelope wrapped under a key-id with NO CX_STORE_KEK_<id> env.
	mut ghost_kms := cxstore.new_local_kms()
	mut ghost := cxstore.new_encrypting_object_backend(os.join_path(dir, 'objects'),
		'tenant_ghost', ghost_kms) or { panic(err) }
	ghost.put_object('orphaned object'.bytes()) or { panic(err) }

	rep := rot_call('store-rotate-kek', [h, store_str('tenant_b')])
	assert rot_err_code(rep) == 'cx-err:CXER1142', 'unresolvable envelope must abort CXER1142 (got ${rot_err_code(rep)})'
	assert rot_attr(rep, 'message').contains('tenant_ghost'), 'the error must name the unresolvable key-id'
	rot_call('store-close', [h])
}

// ── s3 substrate (hermetic, in-memory transport) ──────────────────────────────

@[heap]
struct RotStubTransport {
mut:
	blobs map[string][]u8
}

fn (t &RotStubTransport) fetch(method string, key string) (int, []u8, bool) {
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

fn (mut t RotStubTransport) store(key string, body []u8) (int, bool) {
	t.blobs[key] = body.clone()
	return 200, true
}

fn (t &RotStubTransport) keys() []string {
	return t.blobs.keys()
}

// rot_s3_store mirrors the store_open_impl s3 wiring over the stub transport.
fn rot_s3_store(t &RotStubTransport, key_id string) &MemStore {
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

fn test_rotation_s3_acceptance_flow() {
	defer {
		rot_unsetenv_ab()
	}
	rot_setenv_ab()
	mut t := &RotStubTransport{}

	mut ms := rot_s3_store(t, 'tenant_a')
	store_s3_load(mut ms) or { panic('fresh open: ${err.msg()}') } // stamps the at-rest marker (as open does)
	c1, h1 := rot_canon_hash('[bucket-doc [payload "sealed-on-s3"]]')
	store_put_canonical(mut ms, h1, c1) or { panic(err) }
	store_s3_flush(mut ms) or { panic(err) }
	id := store_register(ms)
	h := store_handle_element(id, ms)

	rep := rot_call('store-rotate-kek', [h, store_str('tenant_b')])
	assert rot_err_code(rep) == '', 'rotate s3: ${rot_attr(rep, 'message')}'
	assert rot_attr(rep, 'rewrapped').int() > 0
	assert rot_attr(rep, 'from') == 'tenant_a'

	// every objects/ key now holds a tenant_b envelope; markers untouched.
	mut checked := 0
	for k, blob in t.blobs {
		if !k.contains('objects/') {
			continue
		}
		env := cxstore.parse_envelope(blob) or { panic('s3 at-rest blob must parse: ${err}') }
		assert env.key_id == 'tenant_b'
		checked++
	}
	assert checked > 0
	assert t.blobs['.cxstore-encryption'].bytestr() == 'keyed', 'the at-rest mode marker must be unchanged'

	// destroy A; a fresh handle under B reads everything.
	os.unsetenv('CX_STORE_KEK_tenant_a')
	mut ms_b := rot_s3_store(t, 'tenant_b')
	store_s3_load(mut ms_b) or { panic('reopen under B: ${err.msg()}') }
	g1 := store_doc_text(ms_b, h1) or { panic(err.msg()) }
	assert g1 == c1
}

// ── refusal surfaces ──────────────────────────────────────────────────────────

fn test_rotation_plaintext_store_is_cxer1141() {
	h := rot_open('mem://', '')
	assert rot_err_code(h) == ''
	rep := rot_call('store-rotate-kek', [h, store_str('tenant_b')])
	assert rot_err_code(rep) == 'cx-err:CXER1141', 'plaintext store must refuse rotation (got ${rot_err_code(rep)})'
	rot_call('store-close', [h])
}

fn test_rotation_read_only_is_cxer1110() {
	dir := os.join_path(os.temp_dir(), 'cx_rot_ro_${os.getpid()}')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
		rot_unsetenv_ab()
	}
	rot_setenv_ab()
	// create an encrypted store, then reopen read-only.
	h := rot_open('file://${dir}', 'tenant_a')
	assert rot_err_code(h) == ''
	mut ms := rot_handle_ms(h)
	c1, h1 := rot_canon_hash('[doc [v 1]]')
	store_put_canonical(mut ms, h1, c1) or { panic(err) }
	store_persist(mut ms) or { panic(err) }
	rot_call('store-close', [h])

	caps_set_all()
	mut auth := map[string]string{}
	auth['encrypt-key-id'] = 'tenant_a'
	h_ro := store_open_impl('file://${dir}', '', '', true, true, auth)
	assert rot_err_code(h_ro) == ''
	rep := rot_call('store-rotate-kek', [h_ro, store_str('tenant_b')])
	assert rot_err_code(rep) == 'cx-err:CXER1110', 'read-only handle must refuse rotation (got ${rot_err_code(rep)})'
	rot_call('store-close', [h_ro])
}

fn test_rotation_missing_new_kek_fails_before_touching() {
	dir := os.join_path(os.temp_dir(), 'cx_rot_probe_${os.getpid()}')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
		rot_unsetenv_ab()
	}
	rot_setenv_ab()
	os.unsetenv('CX_STORE_KEK_tenant_b') // the target key is NOT resolvable

	h := rot_open('file://${dir}', 'tenant_a')
	assert rot_err_code(h) == ''
	mut ms := rot_handle_ms(h)
	c1, h1 := rot_canon_hash('[doc [v "untouched"]]')
	store_put_canonical(mut ms, h1, c1) or { panic(err) }
	store_persist(mut ms) or { panic(err) }

	rep := rot_call('store-rotate-kek', [h, store_str('tenant_b')])
	assert rot_err_code(rep) == 'cx-err:CXER1142', 'unresolvable NEW key must abort (got ${rot_err_code(rep)})'
	assert rot_attr(rep, 'message').contains('tenant_b')
	rot_call('store-close', [h])

	// nothing was touched: the store still opens under A alone.
	h2 := rot_open('file://${dir}', 'tenant_a')
	assert rot_err_code(h2) == '', 'a failed probe must leave the store fully under A'
	ms2 := rot_handle_ms(h2)
	g := store_doc_text(ms2, h1) or { panic(err.msg()) }
	assert g == c1
	rot_call('store-close', [h2])
}
