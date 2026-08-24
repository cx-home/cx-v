module platform

import code {
	caps_set_all,
	render_canonical,
}

import cx
import cxstore
import os

// store_subject_test.v — stream 20 (#692): the SEK tier + subject vocabulary
// (erasure_compliance §2/§3/§4/§9), platform-level behavior:
//
//   - a subject-bearing doc (subject= + ≥128-bit nonce=) round-trips on an
//     encrypted store, survives reopen (durable sidecar custody), and is
//     sealed under its OWN subject key (the envelope records `sek/…`);
//   - the nonce discipline refuses loudly (CXER4619): missing, short, or
//     derived-from-subject — never a warning (audit C7: the dedup/parity
//     witnesses alone pass for nonce=1, which is the trap);
//   - custody is fail-closed (CXER1144): a plaintext store refuses a subject
//     declaration it could never shred;
//   - destroying the SEK crypto-shreds exactly that subject's payloads with
//     ZERO writes to the sealed bytes: the subject doc becomes unreadable,
//     every other doc still reads, and the envelope layer reports the TYPED
//     unavailable finding (absent key), never "tampered" (audit M33);
//   - KEK rotation keeps the §9.1 balanced account with subjects present:
//     objects = rewrapped + already-current + subject-keyed; SEK-wrapped
//     envelopes never move (re-wrapping them under the tenant KEK would
//     defeat shredding); the SEK KEY MATERIAL re-wraps (subject-keys=N); a
//     subject doc still reads after rotation, and a DESTROYED subject stays
//     shredded through rotation.

fn subj_canon_hash(text string) (string, string) {
	// the STRICT canonical form — the Tier-1 identity bytes the store holds
	// for a whole-doc (subject) object.
	c := cx.cx_text_canonical(text) or { panic('canonical: ${err.msg()}') }
	h := cx.cx_text_hash(c) or { panic('hash: ${err.msg()}') }
	return c, h
}

fn subj_call(name string, args []cx.Node) cx.Node {
	return store_stdlib_builtin_inner(name, args) or { panic('${name} returned none') }
}

fn subj_err_code(n cx.Node) string {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'code' {
				return cx.scalar_value_str_public(a.value)
			}
		}
	}
	return ''
}

fn subj_attr(n cx.Node, name string) string {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == name {
				return cx.scalar_value_str_public(a.value)
			}
		}
	}
	return ''
}

fn subj_open(url string, key_id string) cx.Node {
	caps_set_all()
	mut auth := map[string]string{}
	if key_id != '' {
		auth['encrypt-key-id'] = key_id
	}
	return store_open_impl(url, '', '', false, true, auth)
}

fn subj_ms(n cx.Node) &MemStore {
	id := subj_attr(n, 'handle').int()
	return store_lookup(id) or { panic('handle ${id} not registered') }
}

const subj_nonce = 'f3a9c2e77b104d5c8e6f0a1b2c3d4e5f'

// ── the nonce discipline (CXER4619) — refusals fire before custody ───────────

fn test_subject_nonce_discipline_refusals() {
	caps_set_all()
	h := subj_call('store-open', [cx.Node(cx.ScalarNode{
		value: 'mem://'
	})])
	assert subj_err_code(h) == ''

	// no nonce → CXER4619, never a warning.
	no_nonce := cx.parse('[order subject="did:ex:dana" [item "x"]]') or { panic(err) }
	r1 := subj_call('store-put-doc', [h, no_nonce.elements[0]])
	assert subj_err_code(r1) == 'cx-err:CXER4619', 'missing nonce: ${subj_err_code(r1)}'

	// short nonce (the C7 trap: nonce=1 passes dedup/parity witnesses) → refusal.
	short := cx.parse('[order subject="did:ex:dana" nonce="1" [item "x"]]') or { panic(err) }
	r2 := subj_call('store-put-doc', [h, short.elements[0]])
	assert subj_err_code(r2) == 'cx-err:CXER4619', 'short nonce: ${subj_err_code(r2)}'

	// nonce == subject (trivially derived) → refusal.
	derived := cx.parse('[order subject="did:ex:dana-loves-long-ids" nonce="did:ex:dana-loves-long-ids" [item "x"]]') or {
		panic(err)
	}
	r3 := subj_call('store-put-doc', [h, derived.elements[0]])
	assert subj_err_code(r3) == 'cx-err:CXER4619', 'derived nonce: ${subj_err_code(r3)}'

	subj_call('store-close', [h])
}

// ── custody fail-closed (CXER1144): plaintext store refuses subject= ─────────

fn test_subject_plaintext_store_refuses() {
	caps_set_all()
	h := subj_call('store-open', [cx.Node(cx.ScalarNode{
		value: 'mem://'
	})])
	assert subj_err_code(h) == ''
	doc := cx.parse('[order subject="did:ex:dana" nonce="${subj_nonce}" [item "x"]]') or {
		panic(err)
	}
	r := subj_call('store-put-doc', [h, doc.elements[0]])
	assert subj_err_code(r) == 'cx-err:CXER1144', 'plaintext store: ${subj_err_code(r)}'
	subj_call('store-close', [h])
}

// ── sealed round-trip + reopen + shred + rotation, on the pack substrate ─────

fn test_subject_seal_shred_and_rotation_cxpack() {
	dir := os.join_path(os.temp_dir(), 'cx_subj_pack_${os.getpid()}')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
		os.unsetenv('CX_STORE_KEK_tenant_a')
		os.unsetenv('CX_STORE_KEK_tenant_b')
	}
	os.setenv('CX_STORE_KEK_tenant_a', '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
		true)
	os.setenv('CX_STORE_KEK_tenant_b', 'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100',
		true)

	h := subj_open('file://${dir}', 'tenant_a')
	assert subj_err_code(h) == '', 'open: ${subj_err_code(h)}'
	mut ms := subj_ms(h)

	// A tenant doc and a subject doc.
	tdoc := cx.parse('[order [id 1] [customer [name "Acme"]]]') or { panic(err) }
	rt := subj_call('store-put-doc', [h, tdoc.elements[0]])
	assert subj_err_code(rt) == ''
	t_hash := cx.scalar_value_str_public((rt as cx.ScalarNode).value)

	sdoc := cx.parse('[order subject="did:ex:dana" nonce="${subj_nonce}" [id 2] [customer [name "Dana"]]]') or {
		panic(err)
	}
	c_s, want_hash := subj_canon_hash('[order subject="did:ex:dana" nonce="${subj_nonce}" [id 2] [customer [name "Dana"]]]')
	rs := subj_call('store-put-doc', [h, sdoc.elements[0]])
	assert subj_err_code(rs) == '', 'subject put: ${subj_err_code(rs)} ${subj_attr(rs, 'message')}'
	s_hash := cx.scalar_value_str_public((rs as cx.ScalarNode).value)
	// address parity: encryption/SEK routing never moves the Tier-1 address.
	assert s_hash == want_hash

	// idempotent re-put (content-addressed dedup unchanged for the same bytes).
	rs2 := subj_call('store-put-doc', [h, sdoc.elements[0]])
	assert cx.scalar_value_str_public((rs2 as cx.ScalarNode).value) == s_hash

	store_persist(mut ms) or { panic(err) }

	// The at-rest envelope records a SEK id — sealed under the SUBJECT key.
	sroot := ms.obj_roots[s_hash] or { panic('subject doc root missing') }
	env_raw := ms.obj_pack.get_object_raw(sroot) or { panic('subject envelope missing') }
	env := cxstore.parse_envelope(env_raw) or { panic(err) }
	assert env.key_id.starts_with(cxstore.sek_id_prefix), 'subject doc wraps under ${env.key_id}'
	// The tenant doc's envelopes stay under the tenant key.
	troot := ms.obj_roots[t_hash] or { panic('tenant doc root missing') }
	tenv_raw := ms.obj_pack.get_object_raw(troot) or { panic('tenant envelope missing') }
	tenv := cxstore.parse_envelope(tenv_raw) or { panic(err) }
	assert tenv.key_id == 'tenant_a'

	// Round-trip pre-shred.
	got := store_doc_text(ms, s_hash) or { panic('subject read: ${err.msg()}') }
	assert got == c_s

	// Reopen (fresh process shape): sidecar custody serves the SEK.
	subj_call('store-close', [h])
	h2 := subj_open('file://${dir}', 'tenant_a')
	assert subj_err_code(h2) == ''
	mut ms2 := subj_ms(h2)
	got2 := store_doc_text(ms2, s_hash) or { panic('subject read after reopen: ${err.msg()}') }
	assert got2 == c_s

	// KEK rotation with subjects present: balanced account, SEK envelopes
	// untouched, SEK blob re-wrapped, subject doc still reads.
	rep := subj_call('store-rotate-kek', [h2, cx.Node(cx.ScalarNode{
		value: 'tenant_b'
	})])
	assert subj_err_code(rep) == '', 'rotate: ${subj_attr(rep, 'message')}'
	objects := subj_attr(rep, 'objects').int()
	rewrapped := subj_attr(rep, 'rewrapped').int()
	current := subj_attr(rep, 'already-current').int()
	subject_keyed := subj_attr(rep, 'subject-keyed').int()
	assert subject_keyed > 0, 'subject envelopes must be counted'
	assert objects == rewrapped + current + subject_keyed, 'the §9.1 balanced account'
	assert subj_attr(rep, 'subject-keys').int() == 1, 'one SEK blob re-wraps'
	got3 := store_doc_text(ms2, s_hash) or { panic('subject read after rotation: ${err.msg()}') }
	assert got3 == c_s
	// the SEK envelope's recorded key-id did NOT move to tenant_b.
	env_raw2 := ms2.obj_pack.get_object_raw(sroot) or { panic('subject envelope missing') }
	env2 := cxstore.parse_envelope(env_raw2) or { panic(err) }
	assert env2.key_id == env.key_id, 'SEK envelope must not be re-wrapped by tenant rotation'

	// CRYPTO-SHRED: destroy the subject key — zero writes to sealed bytes.
	// (The W4 erase-subject walk additionally purges the in-process plaintext
	// copies — live sink + page cache — per §7's derived-artifact reach; here
	// the raw KMS destroy is exercised, so a FRESH handle is the honest
	// observation point.)
	mut kk := store_rotation_kms(mut ms2) or { panic('no kms') }
	if mut kk is EnvKms {
		kk.destroy_key(env.key_id) or { panic('destroy: ${err.msg()}') }
	} else {
		panic('expected EnvKms')
	}
	subj_call('store-close', [h2])
	h3 := subj_open('file://${dir}', 'tenant_b')
	assert subj_err_code(h3) == '', 'reopen after shred: ${subj_err_code(h3)}'
	mut ms3 := subj_ms(h3)
	// The subject doc is gone (fail-closed) …
	if _ := store_doc_text(ms3, s_hash) {
		panic('shredded subject doc must not read')
	}
	// … with the TYPED unavailable finding at the envelope layer (absent key,
	// never "tampered" — audit M33) …
	if _ := ms3.obj_pack_enc.open_envelope(sroot, env_raw2) {
		panic('shredded envelope must not open')
	} else {
		assert cxstore.is_key_unavailable(err.msg()), 'want the typed unavailable finding, got: ${err.msg()}'
	}
	// … and every other doc still reads.
	tgot := store_doc_text(ms3, t_hash) or { panic('tenant doc after shred: ${err.msg()}') }
	assert tgot.contains('Acme')

	// The shred SURVIVES rotation (a destroyed-SEK envelope carries verbatim).
	rep2 := subj_call('store-rotate-kek', [h3, cx.Node(cx.ScalarNode{
		value: 'tenant_a'
	})])
	assert subj_err_code(rep2) == '', 'rotate after shred: ${subj_attr(rep2, 'message')}'
	assert subj_attr(rep2, 'subject-keyed').int() > 0
	assert subj_attr(rep2, 'subject-keys').int() == 0, 'a destroyed SEK has no blob to re-wrap'
	if _ := store_doc_text(ms3, s_hash) {
		panic('shredded subject doc must stay shredded through rotation')
	}

	// W5: with NO covering erasure record (this test destroys the key RAW —
	// exactly what key loss or unlawful destruction looks like), verify is
	// the typed unavailable FAULT — never valid=true, never counted among
	// the redactions (M29/M33: lawful erasure is classified from evidence,
	// not key absence) …
	sv := subj_call('store-verify', [h3])
	assert subj_err_code(sv) == 'cx-err:CXER1120', 'want the typed unavailable fault, got ${subj_err_code(sv)}: ${subj_attr(sv,
		'message')}'
	assert subj_attr(sv, 'message').contains('NO covering erasure record'), 'the fault names the missing evidence, got: ${subj_attr(sv,
		'message')}'
	subj_call('store-close', [h3])

	// … and an EAGER open refuses loud (fail-closed: an uncovered
	// unopenable subject doc must never load as clean).
	he := store_open_impl('file://${dir}', '', '', false, true, {
		'encrypt-key-id': 'tenant_a'
		'eager':          'true'
	})
	assert subj_err_code(he) != '', 'eager open must refuse an uncovered unopenable subject doc'
}

// ── journal: the coordinate-equality nonce rule (erasure_compliance §3) ──────

fn test_journal_subject_nonce_coordinate_refusal() {
	caps_set_all()
	// tenant "acme": a nonce byte-equal to the tenant coordinate refuses.
	jh := journal_stdlib_builtin('journal-open', [store_str('mem://subj-coord'),
		store_str('acme')]) or { panic('journal-open returned none') }
	assert subj_err_code(jh) == '', 'journal open: ${subj_err_code(jh)}'

	evt := cx.parse('[profile subject="did:ex:dana" nonce="acme" [name "Dana"]]') or {
		panic(err)
	}
	attribution := cx.Element{
		name:  code.map_marker_name
		items: [
			cx.Node(cx.Element{
				name:  'actor'
				items: [cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue('agent:a')
					data_type: cx.ScalarType.string_type
				})]
			}),
			cx.Node(cx.Element{
				name:  'authority'
				items: [cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue('d-1')
					data_type: cx.ScalarType.string_type
				})]
			}),
		]
	}
	r := journal_stdlib_builtin('journal-append', [jh, evt.elements[0],
		cx.Node(attribution)]) or { panic('journal-append returned none') }
	assert subj_err_code(r) == 'cx-err:CXER4619', 'coordinate nonce: ${subj_err_code(r)} ${subj_attr(r,
		'message')}'
}

// ── stream 20 W4: erase-subject + the §7 shred walk ──────────────────────────

fn subj_map(pairs map[string]string) cx.Node {
	mut items := []cx.Node{}
	mut keys := pairs.keys()
	keys.sort()
	for k in keys {
		items << cx.Node(cx.Element{
			name:  k
			items: [cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(pairs[k])
				data_type: cx.ScalarType.string_type
			})]
		})
	}
	return cx.Node(cx.Element{
		name:  code.map_marker_name
		items: items
	})
}

fn subj_jcall(name string, args []cx.Node) cx.Node {
	return journal_stdlib_builtin(name, args) or { panic('${name} returned none') }
}

fn subj_erase(jh cx.Node, subject string, request string, mut env code.MatchEnv) cx.Node {
	return journal_stdlib_builtin_env('journal-erase-subject', [jh, store_str(subject),
		subj_map({
			'actor':     'dpo'
			'authority': 'rtbf-9'
		}), subj_map({
			'request': request
		})], mut env) or { panic('erase-subject returned none') }
}

fn subj_put_text(h cx.Node, text string) string {
	doc := cx.parse(text) or { panic(err) }
	r := subj_call('store-put-doc', [h, doc.elements[0]])
	assert subj_err_code(r) == '', 'put: ${subj_err_code(r)} ${subj_attr(r, 'message')}'
	return cx.scalar_value_str_public((r as cx.ScalarNode).value)
}

const subj_nonce2 = '0badc0de0badc0de0badc0de0badc0de'
const subj_nonce3 = 'a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5'

// The full hot-store walk on the pack substrate: journaled record + hold pin,
// per-doc tombstones w/ attribution, SEK destroy + mapping removal, derived
// sweeps (computation cache hit + checkpoint purge + registration marker
// SURVIVES), in-process plaintext purge (sink + page cache), deduped replay
// (same token), a NEW token erasing RE-LANDED data, and the M29 CXER1145
// classification for the crashed-walk read.
fn test_erase_subject_walk_cxpack() {
	dir := os.join_path(os.temp_dir(), 'cx_erase_pack_${os.getpid()}')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
		os.unsetenv('CX_STORE_KEK_tenant_a')
	}
	os.setenv('CX_STORE_KEK_tenant_a', '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
		true)

	h := subj_open('file://${dir}', 'tenant_a')
	assert subj_err_code(h) == '', 'open: ${subj_err_code(h)}'
	jh := subj_jcall('journal-attach', [h, store_str('acme')])
	assert subj_err_code(jh) == '', 'attach: ${subj_err_code(jh)}'

	// dana's data: one direct store put + one journaled subject payload.
	s1 := subj_put_text(h, '[order subject="did:ex:dana" nonce="${subj_nonce}" [id 2] [customer [name "Dana"]]]')
	ev := cx.parse('[profile subject="did:ex:dana" nonce="${subj_nonce2}" [email "dana@example"]]') or {
		panic(err)
	}
	ent := subj_jcall('journal-append', [jh, ev.elements[0],
		subj_map({
			'actor':     'svc'
			'authority': 'ing-1'
		})])
	assert subj_err_code(ent) == '', 'append: ${subj_err_code(ent)} ${subj_attr(ent, 'message')}'
	s2 := subj_attr(ent, 'payload')
	assert s2 != '' && s2 != s1

	// an unaffected sibling subject + an unaffected tenant doc.
	b1 := subj_put_text(h, '[order subject="did:ex:bob" nonce="${subj_nonce3}" [id 3]]')
	t1 := subj_put_text(h, '[note [text "keep me"]]')

	// derived surfaces: a computation-cache entry whose record references
	// dana's address; a materialization checkpoint; a registration marker.
	rec_h := subj_put_text(h, '[computation [inputs "${s1}"]]')
	res_h := subj_put_text(h, '[result [sum 42]]')
	ck_h := subj_put_text(h, '[checkpoint q="q1" [row [name "Dana"]]]')
	reg_h := subj_put_text(h, '[live-materialization name="top" at="t0"]')
	mut ms := subj_ms(h)
	store_alias_set_local(mut ms, 'computation/${rec_h}', res_h)
	store_alias_set_local(mut ms, 'cx-live/materialization/acme/top', ck_h)
	store_alias_set_local(mut ms, 'cx-live/materialization/acme/regmark', reg_h)
	store_persist(mut ms) or { panic(err) }

	// warm the page cache from the DURABLE tier (fresh handle: empty sink).
	subj_call('store-close', [h])
	h2 := subj_open('file://${dir}', 'tenant_a')
	assert subj_err_code(h2) == ''
	jh2 := subj_jcall('journal-attach', [h2, store_str('acme')])
	assert subj_err_code(jh2) == ''
	mut ms2 := subj_ms(h2)
	pre := store_doc_text(ms2, s1) or { panic('warm read: ${err.msg()}') }
	assert pre.contains('Dana')
	sroot := ms2.obj_roots[s1] or { panic('root missing') }
	assert sroot.hex() in ms2.obj_cache, 'page cache must hold the decrypted whole-doc object'
	// keep the SEK-1-sealed envelope for the M29 backup-restore construction below.
	env_raw_sek1 := ms2.obj_pack.get_object_raw(sroot) or { panic('envelope missing') }

	// an in-process stream-6 dedup record whose outcome references dana.
	mut env := code.new_env()
	env.state.idem_records['d:test-dana'] = code.IdemRecord{
		outcome:    cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue('notified did:ex:dana')
			data_type: cx.ScalarType.string_type
		})
		expires_ns: 0
	}
	env.state.idem_records['d:test-other'] = code.IdemRecord{
		outcome:    cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue('unrelated')
			data_type: cx.ScalarType.string_type
		})
		expires_ns: 0
	}

	// ── the command ──
	r := subj_erase(jh2, 'did:ex:dana', 'shred-t1', mut env)
	assert subj_err_code(r) == '', 'erase: ${subj_err_code(r)} ${subj_attr(r, 'message')}'
	assert subj_attr(r, 'docs').int() == 2
	assert subj_attr(r, 'erased').int() == 2
	assert subj_attr(r, 'already-erased').int() == 0
	assert subj_attr(r, 'subject-keys').int() == 1
	assert subj_attr(r, 'derived').int() == 1
	assert subj_attr(r, 'checkpoints').int() == 1
	assert subj_attr(r, 'dedup-records').int() == 1
	assert subj_attr(r, 'stores').int() == 1
	assert subj_attr(r, 'generation').int() == 1
	assert subj_attr(r, 'request') == 'shred-t1'

	// docs = erased + already-erased (the balanced account).
	assert subj_attr(r, 'docs').int() == subj_attr(r, 'erased').int() +
		subj_attr(r, 'already-erased').int()

	// dana's docs answer the attributed [erased] tombstone (value channel,
	// the §6 ruled shape: … at= authority= actor= shred-request=).
	g1 := subj_call('store-get-doc', [h2, store_str(s1)])
	assert g1 is cx.Element && (g1 as cx.Element).name == 'erased'
	assert subj_attr(g1, 'shred-request') == 'shred-t1'
	assert subj_attr(g1, 'actor') == 'dpo'
	assert subj_attr(g1, 'authority') == 'rtbf-9'
	assert subj_attr(g1, 'subject') == '', 'the tombstone must never name the subject (§4: post-shred the substrate names it only from the journaled record)'
	g2 := subj_call('store-get-doc', [h2, store_str(s2)])
	assert g2 is cx.Element && (g2 as cx.Element).name == 'erased'

	// W5 read polish: the journal entry whose payload was tombstoned hydrates
	// with the typed [erased …] tombstone as a DIRECT child — never an
	// [event] (has-event stays false: the L119 erased= accounting and the
	// pass-through semantics are unchanged; readers get the attribution).
	ent1 := subj_jcall('journal-read', [jh2, cx.Node(jrn_int(1))])
	assert ent1 is cx.Element && (ent1 as cx.Element).name == 'entry'
	assert !jrn_entry_has_event(ent1 as cx.Element), 'a tombstone is not the entry event'
	mut tomb_child := cx.Node(cx.ScalarNode{})
	for it in (ent1 as cx.Element).items {
		if it is cx.Element && it.name == 'erased' {
			tomb_child = it
		}
	}
	assert tomb_child is cx.Element, 'the tombstone rides the entry read as a typed child'
	assert subj_attr(tomb_child, 'shred-request') == 'shred-t1'

	// W5 §3.6 verify reconciliation, evidence path 1 (the tombstone): the
	// chain stays valid=true with the payload gone, and the missing payload
	// reconciles ATTRIBUTED — redacted=1, never unattributed.
	v1 := subj_jcall('journal-verify', [jh2, subj_map(map[string]string{})])
	assert subj_attr(v1, 'valid') == 'true', 'chain verify: ${subj_attr(v1, 'message')}'
	assert subj_attr(v1, 'redacted') == '1'
	assert subj_attr(v1, 'unattributed-missing') == '0'
	assert subj_attr(v1, 'payloads-verified') == '0'

	// unaffected docs still read; the registration marker alias survives.
	assert (store_doc_text(ms2, b1) or { panic('bob: ${err.msg()}') }).contains('id')
	assert (store_doc_text(ms2, t1) or { panic('tenant: ${err.msg()}') }).contains('keep me')
	assert 'cx-live/materialization/acme/regmark' in ms2.aliases
	assert 'cx-live/materialization/acme/top' !in ms2.aliases
	assert 'computation/${rec_h}' !in ms2.aliases

	// in-process plaintext is GONE: page cache + sink hold no dana bytes.
	assert sroot.hex() !in ms2.obj_cache, 'the shredded whole-doc plaintext must leave the page cache'
	assert sroot.hex() !in ms2.obj_sink.objects, 'the shredded whole-doc plaintext must leave the sink'

	// the SEK blob + the subject mapping are gone from the sidecar.
	assert !os.exists(os.join_path(dir, 'keys', 'subjects', '6469643a65783a64616e61')), 'subject mapping must be removed'
	// the selective dedup purge: dana's record gone, the unrelated one kept.
	assert 'd:test-dana' !in env.state.idem_records
	assert 'd:test-other' in env.state.idem_records

	// deduped replay (same token): the recorded report, plus a converged walk.
	r2 := subj_erase(jh2, 'did:ex:dana', 'shred-t1', mut env)
	assert r2 is cx.Element && (r2 as cx.Element).name == 'deduped'

	// RE-LANDED data for the same subject stays erasable under a NEW token
	// (M31: the record is token-keyed, never a subject-keyed forever-absorber).
	s1b := subj_put_text(h2, '[order subject="did:ex:dana" nonce="${subj_nonce}" [id 2] [customer [name "Dana"]]]')
	assert s1b == s1, 'the re-put supersedes the tombstone at the same address'
	assert (store_doc_text(ms2, s1) or { panic('re-put read: ${err.msg()}') }).contains('Dana')
	r3 := subj_erase(jh2, 'did:ex:dana', 'shred-t2', mut env)
	assert subj_err_code(r3) == '', 're-erase: ${subj_err_code(r3)} ${subj_attr(r3, 'message')}'
	assert subj_attr(r3, 'erased').int() == 1
	assert subj_attr(r3, 'generation').int() == 2
	g3 := subj_call('store-get-doc', [h2, store_str(s1)])
	assert g3 is cx.Element && (g3 as cx.Element).name == 'erased'
	assert subj_attr(g3, 'shred-request') == 'shred-t2'

	// ── M29 read classification (the restored-from-backup shape): a stale
	//    SEK-1-sealed envelope re-lands durably (object storage restored
	//    separately from the KMS), the tombstone is absent, the SEK stays
	//    destroyed — but the journaled erase record covers the address →
	//    CXER1145 E_STORE_SHREDDED, attributed; never bare corruption, and
	//    never classified from key absence alone.
	store_lock_enter(mut ms2)
	store_erased_clear_local(mut ms2, s1)
	ms2.obj_roots[s1] = sroot.clone()
	store_lock_exit(mut ms2)
	ms2.obj_pack.put_object_keyed(sroot, env_raw_sek1) or { panic(err) }
	ms2.obj_pack.flush_segment() or { panic(err) }
	gt := subj_call('store-get-doc-text', [h2, store_str(s1)])
	assert subj_err_code(gt) == 'cx-err:CXER1145', 'want CXER1145, got ${subj_err_code(gt)}: ${subj_attr(gt,
		'message')}'
	assert subj_attr(gt, 'message').contains('shred-t'), 'the finding names the covering shred-request'

	// W5 §3.6 verify reconciliation, evidence path 2 (the journaled record):
	// drop s2's tombstone so its address reads plain-ABSENT (no tombstone to
	// attribute from) — the shred-t1 record's [docs] scope still covers it,
	// so the missing payload reconciles redacted=1, never unattributed.
	store_lock_enter(mut ms2)
	store_erased_clear_local(mut ms2, s2)
	store_lock_exit(mut ms2)
	v2 := subj_jcall('journal-verify', [jh2, subj_map(map[string]string{})])
	assert subj_attr(v2, 'valid') == 'true'
	assert subj_attr(v2, 'redacted') == '1', 'record-covered missing payload must reconcile attributed (got redacted=${subj_attr(v2,
		'redacted')} unattributed=${subj_attr(v2, 'unattributed-missing')})'
	assert subj_attr(v2, 'unattributed-missing') == '0'

	// W5: the porcelain whole-graph verify reconciles the same way — the
	// restored SEK-1 envelope (covered by the journaled records) is a
	// FINDING counted visibly, never a fault: valid=true redacted=1.
	sv := subj_call('store-verify', [h2])
	assert subj_err_code(sv) == '', 'porcelain verify: ${subj_attr(sv, 'message')}'
	assert subj_attr(sv, 'valid') == 'true'
	assert subj_attr(sv, 'redacted') == '1', 'the covered shredded whole-doc counts redacted, got ${subj_attr(sv,
		'redacted')}'

	// W5: the EAGER load-time verify reconciles too. Build the durable
	// construction: re-land dana's doc a third time (a fresh SEK seals it;
	// the D record registers the root durably), then raw-destroy that SEK
	// with NO new record — the ADDRESS stays covered by shred-t2's [docs]
	// (content-addressed: the same address IS the same plaintext the lawful
	// record already ordered destroyed). An eager reopen must OPEN (the
	// covered doc is a finding; reads answer the typed CXER1145), never
	// refuse the whole store. First undo the M29 block's in-memory root
	// restoration so the re-put is a real insert (D record + fresh seal),
	// not a dedup hit against the hand-restored root.
	store_lock_enter(mut ms2)
	ms2.obj_roots.delete(s1)
	store_lock_exit(mut ms2)
	s1c := subj_put_text(h2, '[order subject="did:ex:dana" nonce="${subj_nonce}" [id 2] [customer [name "Dana"]]]')
	assert s1c == s1
	store_persist(mut ms2) or { panic(err) }
	env_raw3 := ms2.obj_pack.get_object_raw(sroot) or { panic('re-land envelope missing') }
	env3 := cxstore.parse_envelope(env_raw3) or { panic(err) }
	assert env3.key_id.starts_with(cxstore.sek_id_prefix)
	mut kk2 := store_rotation_kms(mut ms2) or { panic('no kms') }
	if mut kk2 is EnvKms {
		kk2.destroy_key(env3.key_id) or { panic('destroy: ${err.msg()}') }
	} else {
		panic('expected EnvKms')
	}
	subj_call('store-close', [h2])
	he := store_open_impl('file://${dir}', '', '', false, true, {
		'encrypt-key-id': 'tenant_a'
		'eager':          'true'
	})
	assert subj_err_code(he) == '', 'eager open must reconcile a covered shredded whole-doc as a finding, got: ${subj_attr(he,
		'message')}'
	gt2 := subj_call('store-get-doc-text', [he, store_str(s1)])
	assert subj_err_code(gt2) == 'cx-err:CXER1145', 'want CXER1145 on the eager handle, got ${subj_err_code(gt2)}'
	sv2 := subj_call('store-verify', [he])
	assert subj_attr(sv2, 'valid') == 'true'
	assert subj_attr(sv2, 'redacted') == '1'

	subj_call('store-close', [he])
}

// The M5 proof-domain RTBF end-to-end (erasure_compliance §10, `o-5521`):
// an order aggregate stream carries personal and non-personal events; the
// customer's RTBF command with authority shreds exactly the personal
// payload; the replay is idempotent; the aggregate's chain stays green with
// the redaction attributed; and the attribution — subject, request, [docs]
// scope, pinned head-set — survives in the journaled record (§4: post-shred
// the substrate names the subject only from the record).
fn test_rtbf_o5521_end_to_end() {
	dir := os.join_path(os.temp_dir(), 'cx_rtbf_o5521_${os.getpid()}')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
		os.unsetenv('CX_STORE_KEK_tenant_m5')
	}
	os.setenv('CX_STORE_KEK_tenant_m5', 'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100',
		true)

	h := subj_open('file://${dir}', 'tenant_m5')
	assert subj_err_code(h) == '', 'open: ${subj_err_code(h)}'
	jh := subj_jcall('journal-attach', [h, store_str('acme')])
	assert subj_err_code(jh) == '', 'attach: ${subj_err_code(jh)}'

	stream_opt := subj_map({
		'actor':     'svc'
		'authority': 'ing-1'
		'stream':    'order:o-5521'
	})
	placed := cx.parse('[order-placed order="o-5521" total=129]') or { panic(err) }
	e1 := subj_jcall('journal-append', [jh, placed.elements[0], stream_opt])
	assert subj_err_code(e1) == '', 'placed: ${subj_err_code(e1)}'
	details := cx.parse('[customer-details subject="did:ex:carol" nonce="${subj_nonce}" order="o-5521" [name "Carol"] [street "9 Elm"]]') or {
		panic(err)
	}
	e2 := subj_jcall('journal-append', [jh, details.elements[0], stream_opt])
	assert subj_err_code(e2) == '', 'details: ${subj_err_code(e2)} ${subj_attr(e2, 'message')}'
	pay2 := subj_attr(e2, 'payload')
	assert pay2 != ''
	shipped := cx.parse('[order-shipped order="o-5521"]') or { panic(err) }
	e3 := subj_jcall('journal-append', [jh, shipped.elements[0], stream_opt])
	assert subj_err_code(e3) == '', 'shipped: ${subj_err_code(e3)}'

	// ── the command, with authority ──
	mut env := code.new_env()
	r := subj_erase(jh, 'did:ex:carol', 'shred-o5521', mut env)
	assert subj_err_code(r) == '', 'erase: ${subj_err_code(r)} ${subj_attr(r, 'message')}'
	assert subj_attr(r, 'request') == 'shred-o5521'
	assert subj_attr(r, 'docs').int() == 1
	assert subj_attr(r, 'erased').int() == 1
	assert subj_attr(r, 'subject-keys').int() == 1
	assert subj_attr(r, 'generation').int() == 1
	assert subj_attr(r, 'docs').int() == subj_attr(r, 'erased').int() +
		subj_attr(r, 'already-erased').int()
	// head-set scope: the hold check pinned at the hold-stream head (none here).
	assert subj_attr(r, 'holds-head') == '0'

	// idempotent replay: the same token answers the recorded report.
	r2 := subj_erase(jh, 'did:ex:carol', 'shred-o5521', mut env)
	assert r2 is cx.Element && (r2 as cx.Element).name == 'deduped'

	// chain green on the aggregate stream, the redaction attributed.
	v := subj_jcall('journal-verify', [jh, subj_map({
		'stream': 'order:o-5521'
	})])
	assert subj_attr(v, 'valid') == 'true', 'verify: ${subj_attr(v, 'message')}'
	assert subj_attr(v, 'redacted') == '1'
	assert subj_attr(v, 'unattributed-missing') == '0'
	assert subj_attr(v, 'payloads-verified') == '2'

	// attribution intact, both evidence bases: the tombstone…
	g := subj_call('store-get-doc', [h, store_str(pay2)])
	assert g is cx.Element && (g as cx.Element).name == 'erased'
	assert subj_attr(g, 'shred-request') == 'shred-o5521'
	assert subj_attr(g, 'subject') == ''
	// …and the journaled record, which alone names the subject (§4) and
	// carries the scope: the erased doc address + the pinned head-set.
	rec := subj_jcall('journal-read', [jh, cx.Node(jrn_int(1)), store_str('cx:erasure')])
	rec_name := if rec is cx.Element { rec.name } else { 'non-element' }
	assert rec_name == 'entry', 'cx:erasure read answered ${rec_name}: ${render_canonical(rec)}'
	mut rec_payload := cx.Element{}
	for it in (rec as cx.Element).items {
		if it is cx.Element && it.name == 'event' && it.items.len > 0 {
			p := it.items[0]
			if p is cx.Element {
				rec_payload = p
			}
		}
	}
	assert rec_payload.name == 'erase-subject'
	assert jrn_erase_child_text(rec_payload, 'subject') == 'did:ex:carol'
	assert jrn_erase_child_text(rec_payload, 'request') == 'shred-o5521'
	mut covered := false
	mut has_head_set := false
	for it in rec_payload.items {
		if it is cx.Element && it.name == 'docs' {
			for d in it.items {
				if d is cx.Element && d.name == 'd' && d.items.len > 0 {
					dv := d.items[0]
					mut dh := ''
					if dv is cx.ScalarNode {
						dh = cx.scalar_value_str_public(dv.value)
					} else if dv is cx.TextNode {
						dh = dv.value
					}
					if dh == pay2 {
						covered = true
					}
				}
			}
		}
		if it is cx.Element && it.name == 'head-set' {
			has_head_set = true
		}
	}
	assert covered, 'the record docs scope covers the erased address'
	assert has_head_set, 'the record carries the scope head-set'

	// the order itself survives: non-personal events read intact, and the
	// erased entry hydrates the typed tombstone as a direct child.
	o1 := subj_jcall('journal-read', [jh, cx.Node(jrn_int(1)), store_str('order:o-5521')])
	assert jrn_entry_has_event(o1 as cx.Element)
	o2 := subj_jcall('journal-read', [jh, cx.Node(jrn_int(2)), store_str('order:o-5521')])
	assert !jrn_entry_has_event(o2 as cx.Element), 'a tombstone is not the entry event'
	mut tomb := false
	for it in (o2 as cx.Element).items {
		if it is cx.Element && it.name == 'erased' {
			tomb = true
		}
	}
	assert tomb, 'the erased entry carries the typed tombstone as a direct child'
	o3 := subj_jcall('journal-read', [jh, cx.Node(jrn_int(3)), store_str('order:o-5521')])
	assert jrn_entry_has_event(o3 as cx.Element)

	subj_call('store-close', [h])
}

// Predecessor + archive reach: the walk follows the segment index (store= +
// archived-to=), destroys EACH store's own SEK, and tombstones each copy.
fn test_erase_subject_predecessor_and_archive_reach() {
	base := os.join_path(os.temp_dir(), 'cx_erase_seg_${os.getpid()}')
	os.rmdir_all(base) or {}
	defer {
		os.rmdir_all(base) or {}
		os.unsetenv('CX_STORE_KEK_tenant_a')
	}
	os.setenv('CX_STORE_KEK_tenant_a', '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
		true)
	a_dir := os.join_path(base, 'sealed-a')
	b_dir := os.join_path(base, 'hot-b')
	c_dir := os.join_path(base, 'arch-c')

	text := '[order subject="did:ex:dana" nonce="${subj_nonce}" [id 9]]'

	// sealed predecessor A with dana's doc.
	ha := subj_open('file://${a_dir}', 'tenant_a')
	assert subj_err_code(ha) == ''
	s_hash := subj_put_text(ha, text)
	mut msa := subj_ms(ha)
	store_persist(mut msa) or { panic(err) }
	sek_a := store_erase_sek_lookup(mut msa, 'did:ex:dana') or { panic('A sek missing') }

	// archive copy C (the disposition clone — custody carries: C mints its own SEK).
	hc := subj_open('file://${c_dir}', 'tenant_a')
	assert subj_err_code(hc) == ''
	cl := subj_call('store-clone', [ha, hc])
	assert subj_err_code(cl) == '', 'clone: ${subj_err_code(cl)} ${subj_attr(cl, 'message')}'
	mut msc := subj_ms(hc)
	sek_c := store_erase_sek_lookup(mut msc, 'did:ex:dana') or { panic('C sek missing') }
	assert sek_c != sek_a, 'the archive mints its OWN destroyable key'
	assert (store_doc_text(msc, s_hash) or { panic('C read: ${err.msg()}') }).contains('id')
	subj_call('store-close', [hc])
	subj_call('store-close', [ha])

	// hot store B with dana's doc + the journal + the segment index naming A.
	hb := subj_open('file://${b_dir}', 'tenant_a')
	assert subj_err_code(hb) == ''
	jh := subj_jcall('journal-attach', [hb, store_str('acme')])
	assert subj_err_code(jh) == ''
	_ := subj_put_text(hb, text)
	b_id := subj_attr(hb, 'handle').int()
	if e := jrn_set_meta_alias(b_id, jrn_segments_alias('acme'), cx.Element{
		name:  'journal-segments'
		items: [
			cx.Node(cx.Element{
				name:  'segment'
				attrs: [
					cx.Attribute{
						name:  'to'
						value: cx.ScalarValue(i64(3))
					},
					cx.Attribute{
						name:  'anchor'
						value: cx.ScalarValue('sha2-256:aa')
					},
					cx.Attribute{
						name:  'store'
						value: cx.ScalarValue('file://${a_dir}')
					},
				]
			}),
		]
	})
	{
		panic('segment index write failed: ${subj_attr(e, 'message')}')
	}
	// the disposition records WHERE the archive copy lives.
	disp := subj_jcall('journal-segment-disposed', [jh, store_str('file://${a_dir}'),
		store_str('file://${c_dir}')])
	assert disp is cx.ScalarNode, 'disposed: ${subj_attr(disp, 'message')}'

	mut env := code.new_env()
	r := subj_erase(jh, 'did:ex:dana', 'shred-seg-1', mut env)
	assert subj_err_code(r) == '', 'erase: ${subj_err_code(r)} ${subj_attr(r, 'message')}'
	assert subj_attr(r, 'stores').int() == 3
	assert subj_attr(r, 'docs').int() == 3
	assert subj_attr(r, 'erased').int() == 3
	assert subj_attr(r, 'subject-keys').int() == 3, 'each store destroys its OWN SEK'

	// every copy is tombstoned + unreadable, everywhere.
	mut msb := subj_ms(hb)
	if _ := store_doc_text(msb, s_hash) {
		panic('hot copy must be erased')
	}
	subj_call('store-close', [hb])
	ha2 := subj_open('file://${a_dir}', 'tenant_a')
	mut msa2 := subj_ms(ha2)
	assert s_hash in msa2.erased, 'the sealed predecessor carries the tombstone'
	if _ := store_doc_text(msa2, s_hash) {
		panic('predecessor copy must be erased')
	}
	subj_call('store-close', [ha2])
	hc2 := subj_open('file://${c_dir}', 'tenant_a')
	mut msc2 := subj_ms(hc2)
	assert s_hash in msc2.erased, 'the archive copy carries the tombstone'
	if _ := store_doc_text(msc2, s_hash) {
		panic('archive copy must be erased')
	}
	subj_call('store-close', [hc2])
}

// A non-disposed segment that will not open is a LOUD walk error (missing an
// enumerated surface is a compliance failure); a disposed one counts visibly
// and the command proceeds.
fn test_erase_subject_disposed_and_unreachable_segments() {
	base := os.join_path(os.temp_dir(), 'cx_erase_disp_${os.getpid()}')
	os.rmdir_all(base) or {}
	defer {
		os.rmdir_all(base) or {}
		os.unsetenv('CX_STORE_KEK_tenant_a')
	}
	os.setenv('CX_STORE_KEK_tenant_a', '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
		true)
	hot := os.join_path(base, 'hot')
	h := subj_open('file://${hot}', 'tenant_a')
	assert subj_err_code(h) == ''
	jh := subj_jcall('journal-attach', [h, store_str('acme')])
	assert subj_err_code(jh) == ''
	h_id := subj_attr(h, 'handle').int()
	gone := 'file://${os.join_path(base, 'gone')}'
	if e := jrn_set_meta_alias(h_id, jrn_segments_alias('acme'), cx.Element{
		name:  'journal-segments'
		items: [
			cx.Node(cx.Element{
				name:  'segment'
				attrs: [
					cx.Attribute{
						name:  'to'
						value: cx.ScalarValue(i64(2))
					},
					cx.Attribute{
						name:  'anchor'
						value: cx.ScalarValue('sha2-256:bb')
					},
					cx.Attribute{
						name:  'store'
						value: cx.ScalarValue(gone)
					},
				]
			}),
		]
	})
	{
		panic('segment index write failed: ${subj_attr(e, 'message')}')
	}
	mut env := code.new_env()
	r := subj_erase(jh, 'did:ex:dana', 'shred-d-1', mut env)
	assert subj_err_code(r) != '', 'an unreachable non-disposed segment must fail LOUD'
	assert subj_attr(r, 'message').contains('sealed segment')
	// the refusal committed nothing: the generation never advanced.
	g := subj_jcall('journal-shred-generation', [jh])
	assert cx.scalar_value_str_public((g as cx.ScalarNode).value).int() == 0

	// disposed (archive="none") → reported visibly, the command proceeds.
	disp := subj_jcall('journal-segment-disposed', [jh, store_str(gone), store_str('none')])
	assert disp is cx.ScalarNode
	r2 := subj_erase(jh, 'did:ex:dana', 'shred-d-1', mut env)
	assert subj_err_code(r2) == '', 'erase after disposal: ${subj_attr(r2, 'message')}'
	assert subj_attr(r2, 'disposed').int() == 1
	assert subj_attr(r2, 'stores').int() == 1
	subj_call('store-close', [h])
}

// Whole-store transfer × stream 20: clone/migrate carry BOTH subject custody
// (the destination mints its own SEK; plaintext destinations refuse) and the
// erased-map (attribution survives archival); push refuses subject sources
// (custody does not ride the wire verbs — the stream-4/9 joint surface).
fn test_erase_transfer_custody_and_carriage() {
	base := os.join_path(os.temp_dir(), 'cx_erase_xfer_${os.getpid()}')
	os.rmdir_all(base) or {}
	defer {
		os.rmdir_all(base) or {}
		os.unsetenv('CX_STORE_KEK_tenant_a')
	}
	os.setenv('CX_STORE_KEK_tenant_a', '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
		true)

	src := subj_open('file://${os.join_path(base, 'src')}', 'tenant_a')
	assert subj_err_code(src) == ''
	s_hash := subj_put_text(src, '[order subject="did:ex:dana" nonce="${subj_nonce}" [id 4]]')
	t_hash := subj_put_text(src, '[note [text "erase me"]]')
	mut mss := subj_ms(src)
	// an attributed doc-level erasure on the source (the §7b.1 funnel).
	mut troot := []u8{}
	if rr := mss.obj_roots[t_hash] {
		troot = rr.clone()
	}
	tomb := store_erase_tombstone(t_hash, troot, '2026-08-12T00:00:00Z', 'op', 'aud-1',
		'req-x1')
	assert store_erase_doc_local(mut mss, t_hash, tomb)
	store_append(mut mss, store_tombstone_record(t_hash) + store_erase_record(t_hash,
		tomb)) or { panic(err) }
	store_persist(mut mss) or { panic(err) }
	sek_src := store_erase_sek_lookup(mut mss, 'did:ex:dana') or { panic('src sek missing') }

	// clone → encrypted destination: subject doc re-seals under the DEST's own
	// SEK; the tombstone rides with its attribution.
	dst := subj_open('file://${os.join_path(base, 'dst')}', 'tenant_a')
	assert subj_err_code(dst) == ''
	cl := subj_call('store-clone', [src, dst])
	assert subj_err_code(cl) == '', 'clone: ${subj_err_code(cl)} ${subj_attr(cl, 'message')}'
	mut msd := subj_ms(dst)
	assert (store_doc_text(msd, s_hash) or { panic('dst read: ${err.msg()}') }).contains('id')
	sek_dst := store_erase_sek_lookup(mut msd, 'did:ex:dana') or { panic('dst sek missing') }
	assert sek_dst != sek_src
	droot := msd.obj_roots[s_hash] or { panic('dst root missing') }
	draw := store_raw_envelope(mut msd, droot) or { panic('dst envelope missing') }
	denv := cxstore.parse_envelope(draw) or { panic(err) }
	assert denv.key_id == sek_dst, 'the clone seals under the destination SEK, got ${denv.key_id}'
	gd := subj_call('store-get-doc', [dst, store_str(t_hash)])
	assert gd is cx.Element && (gd as cx.Element).name == 'erased'
	assert subj_attr(gd, 'shred-request') == 'req-x1'
	subj_call('store-close', [dst])

	// clone → PLAINTEXT destination refuses (never a silent plaintext landing).
	pl := subj_call('store-open', [store_str('mem://')])
	clp := subj_call('store-clone', [src, pl])
	assert subj_err_code(clp) == 'cx-err:CXER1144', 'plaintext clone: ${subj_err_code(clp)}'
	// push refuses a subject-keyed source outright.
	ph := subj_call('store-push', [src, pl])
	assert subj_err_code(ph) == 'cx-err:CXER1144', 'push: ${subj_err_code(ph)}'
	subj_call('store-close', [pl])

	// migrate → encrypted destination: the subject doc routes through the
	// subject arm (destination SEK), the erased-map carries.
	dst2 := subj_open('file://${os.join_path(base, 'dst2')}', 'tenant_a')
	assert subj_err_code(dst2) == ''
	mg := subj_call('store-migrate', [src, dst2])
	assert subj_err_code(mg) == '', 'migrate: ${subj_err_code(mg)} ${subj_attr(mg, 'message')}'
	mut msd2 := subj_ms(dst2)
	assert (store_doc_text(msd2, s_hash) or { panic('dst2 read: ${err.msg()}') }).contains('id')
	d2root := msd2.obj_roots[s_hash] or { panic('dst2 root missing') }
	store_persist(mut msd2) or { panic(err) }
	d2raw := store_raw_envelope(mut msd2, d2root) or { panic('dst2 envelope missing') }
	d2env := cxstore.parse_envelope(d2raw) or { panic(err) }
	assert d2env.key_id.starts_with(cxstore.sek_id_prefix), 'migrate must SEK-seal, got ${d2env.key_id}'
	assert t_hash in msd2.erased, 'migrate carries the erased-map'
	subj_call('store-close', [dst2])

	// migrate → plaintext destination refuses through the subject arm.
	pl2 := subj_call('store-open', [store_str('mem://')])
	mgp := subj_call('store-migrate', [src, pl2])
	assert subj_err_code(mgp) == 'cx-err:CXER1144', 'plaintext migrate: ${subj_err_code(mgp)}'
	subj_call('store-close', [pl2])
	subj_call('store-close', [src])
}
