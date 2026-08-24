module platform

import code { caps_set_all }
import cx
import os

// journal_ingest_test.v — stream 9 (#681, L173): the platform-level lanes of
// replica-local stream ingestion the mem fixture (journal-133) cannot reach:
//   - file:// durability — an ingested stream survives close/reopen (the
//     persisted stream index repopulates jrn_reload_named; entry pointers +
//     head aliases are durable);
//   - the lawfully-gone payload lane — a payload destroyed at the source
//     still lands its entry (the chain covers the ADDRESS), the report
//     carries the visible `payloads-absent=` count, and the destination's
//     verify reports the missing payload LOUD as unattributed (the evidence
//     records were not replicated here — honesty, not tolerance).

fn ing_call(name string, args []cx.Node) cx.Node {
	return journal_stdlib_builtin(name, args) or { panic('${name} returned none') }
}

fn ing_store(name string, args []cx.Node) cx.Node {
	return store_stdlib_builtin_inner(name, args) or { panic('${name} returned none') }
}

fn ing_attr(n cx.Node, name string) string {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == name {
				return cx.scalar_value_str_public(a.value)
			}
		}
	}
	return ''
}

fn ing_err(n cx.Node) string {
	if n is cx.Element && n.name == 'err' {
		return ing_attr(n, 'code')
	}
	return ''
}

fn ing_map(pairs map[string]string) cx.Node {
	mut items := []cx.Node{}
	for k, v in pairs {
		items << cx.Node(cx.Element{
			name:  k
			items: [cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(v)
				data_type: cx.ScalarType.string_type
			})]
		})
	}
	return cx.Node(cx.Element{
		name:  'map'
		items: items
	})
}

fn ing_append(j cx.Node, text string, stream string) cx.Node {
	doc := cx.parse(text) or { panic(err) }
	return ing_call('journal-append', [j, doc.elements[0],
		ing_map({
			'actor':     'clerk'
			'authority': 'tab-1'
			'stream':    stream
		})])
}

fn test_ingest_stream_file_reload() {
	caps_set_all()
	base := os.join_path(os.temp_dir(), 'cx_ingest_s9_${os.getpid()}')
	os.rmdir_all(base) or {}
	defer {
		os.rmdir_all(base) or {}
	}
	ha := ing_store('store-open', [store_str('file://${base}/rep')])
	assert ing_err(ha) == '', 'open rep: ${ing_attr(ha, 'message')}'
	ja := ing_call('journal-attach', [ha, store_str('acme')])
	assert ing_err(ja) == ''
	e1 := ing_append(ja, '[order id="o-1"]', 'order:r1')
	assert ing_err(e1) == '', 'append: ${ing_attr(e1, 'message')}'
	e2 := ing_append(ja, '[order-line id="o-1" sku="x"]', 'order:r1')
	assert ing_err(e2) == ''

	hb := ing_store('store-open', [store_str('file://${base}/origin')])
	assert ing_err(hb) == ''
	jb := ing_call('journal-attach', [hb, store_str('acme')])
	assert ing_err(jb) == ''
	r := ing_call('journal-ingest-stream', [jb, ja, store_str('order:r1')])
	assert ing_err(r) == '', 'ingest: ${ing_attr(r, 'message')}'
	assert ing_attr(r, 'ingested') == '2'
	head_hash := ing_attr(r, 'hash')
	assert head_hash != ''

	// Durability: the ingested stream survives close/reopen — the persisted
	// stream index repopulates the named map, the chain verifies, and the
	// head hash is byte-identical to the source's.
	ing_store('store-close', [hb])
	hb2 := ing_store('store-open', [store_str('file://${base}/origin')])
	assert ing_err(hb2) == ''
	jb2 := ing_call('journal-attach', [hb2, store_str('acme')])
	assert ing_err(jb2) == ''
	v := ing_call('journal-verify', [jb2, ing_map({
		'stream': 'order:r1'
	})])
	assert ing_attr(v, 'valid') == 'true', 'reloaded verify: ${ing_attr(v, 'message')}'
	assert ing_attr(v, 'head-hash') == head_hash
	h := ing_call('journal-head', [jb2, store_str('order:r1')])
	assert ing_attr(h, 'seq') == '2'
	ing_store('store-close', [hb2])
	ing_store('store-close', [ha])
}

fn test_ingest_stream_absent_payload_lands_loud() {
	caps_set_all()
	sa := ing_store('store-open', [store_str('mem://ing-abs-src')])
	ja := ing_call('journal-attach', [sa, store_str('acme')])
	e1 := ing_append(ja, '[fact a=1]', 'order:r9')
	assert ing_err(e1) == ''
	e2 := ing_append(ja, '[fact b=2]', 'order:r9')
	assert ing_err(e2) == ''
	// Destroy e1's detached payload at the source (raw delete — what a
	// lawful shred leaves behind chain-wise; the evidence records live on
	// their own stream and are deliberately NOT replicated here).
	p1 := ing_attr(e1, 'payload')
	assert p1 != ''
	del := ing_store('store-delete-doc', [sa, store_str(p1)])
	assert ing_err(del) == '', 'delete payload: ${ing_attr(del, 'message')}'

	sb := ing_store('store-open', [store_str('mem://ing-abs-dst')])
	jb := ing_call('journal-attach', [sb, store_str('acme')])
	r := ing_call('journal-ingest-stream', [jb, ja, store_str('order:r9')])
	assert ing_err(r) == '', 'ingest: ${ing_attr(r, 'message')}'
	assert ing_attr(r, 'ingested') == '2'
	assert ing_attr(r, 'payloads-absent') == '1', 'the gone payload is a VISIBLE count'

	// The chain verifies (the hash covers the ADDRESS); the missing payload
	// reports LOUD as unattributed at the destination — no erasure evidence
	// was replicated, and silence would make unlawful destruction look lawful.
	v := ing_call('journal-verify', [jb, ing_map({
		'stream': 'order:r9'
	})])
	assert ing_attr(v, 'valid') == 'true'
	assert ing_attr(v, 'unattributed-missing') == '1'
	assert ing_attr(v, 'payloads-verified') == '1'
	ing_store('store-close', [sa])
	ing_store('store-close', [sb])
}

// The custody-deep shred reach (stream 20's joint requirement, the half the
// mem fixture cannot exercise): a subject's data exists at BOTH stores under
// each store's OWN SEK; the origin's RTBF command journals the record; the
// replica's apply-erasures executes the REPLICA'S OWN walk — its SEK is
// destroyed, its doc answers the attributed [erased] tombstone, and its own
// balanced report says docs=1 erased=1.
fn test_apply_erasures_custody_deep() {
	caps_set_all()
	base := os.join_path(os.temp_dir(), 'cx_ae_deep_${os.getpid()}')
	os.rmdir_all(base) or {}
	defer {
		os.rmdir_all(base) or {}
		os.unsetenv('CX_STORE_KEK_tenant_o')
		os.unsetenv('CX_STORE_KEK_tenant_r')
	}
	os.setenv('CX_STORE_KEK_tenant_o', '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
		true)
	os.setenv('CX_STORE_KEK_tenant_r', 'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100',
		true)
	nonce := 'f3a9c2e77b104d5c8e6f0a1b2c3d4e5f'
	subject_doc := '[order subject="did:ex:dana" nonce="${nonce}" [customer [name "Dana"]]]'

	ho := store_open_impl('file://${base}/origin', '', '', false, true, {
		'encrypt-key-id': 'tenant_o'
	})
	assert ing_err(ho) == '', 'origin open: ${ing_attr(ho, 'message')}'
	jo := ing_call('journal-attach', [ho, store_str('acme')])
	assert ing_err(jo) == ''
	odoc := cx.parse(subject_doc) or { panic(err) }
	op := store_stdlib_builtin_inner('store-put-doc', [ho, cx.Node(odoc.elements[0])]) or {
		panic('put none')
	}
	assert ing_err(op) == '', 'origin put: ${ing_attr(op, 'message')}'

	hr := store_open_impl('file://${base}/replica', '', '', false, true, {
		'encrypt-key-id': 'tenant_r'
	})
	assert ing_err(hr) == '', 'replica open: ${ing_attr(hr, 'message')}'
	jr := ing_call('journal-attach', [hr, store_str('acme')])
	assert ing_err(jr) == ''
	rdoc := cx.parse(subject_doc) or { panic(err) }
	rp := store_stdlib_builtin_inner('store-put-doc', [hr, cx.Node(rdoc.elements[0])]) or {
		panic('put none')
	}
	assert ing_err(rp) == '', 'replica put: ${ing_attr(rp, 'message')}'
	rhash := if rp is cx.ScalarNode { cx.scalar_value_str_public(rp.value) } else { '' }
	assert rhash != ''

	// the origin's RTBF command (its own walk shreds the origin copy).
	mut env := code.new_env()
	ro := journal_stdlib_builtin_env('journal-erase-subject', [jo, store_str('did:ex:dana'),
		ing_map({
			'actor':     'dpo'
			'authority': 'rtbf-9'
		}), ing_map({
			'request': 'shred-deep-1'
		})], mut env) or { panic('erase none') }
	assert ing_err(ro) == '', 'origin erase: ${ing_attr(ro, 'message')}'
	assert ing_attr(ro, 'erased').int() == 1

	// the replica applies the origin's records: ITS OWN walk, ITS OWN report.
	mut env2 := code.new_env()
	ar := journal_stdlib_builtin_env('journal-apply-erasures', [jr, jo], mut env2) or {
		panic('apply none')
	}
	assert ing_err(ar) == '', 'apply: ${ing_attr(ar, 'message')}'
	assert ing_attr(ar, 'records') == '1'
	assert ing_attr(ar, 'applied') == '1'
	mut rep := cx.Node(cx.ScalarNode{})
	if ar is cx.Element {
		for it in ar.items {
			if it is cx.Element && it.name == 'shred-report' {
				rep = it
			}
		}
	}
	assert ing_attr(rep, 'docs').int() == 1
	assert ing_attr(rep, 'erased').int() == 1
	assert ing_attr(rep, 'subject-keys').int() == 1

	// the replica's copy answers the attributed tombstone.
	g := store_stdlib_builtin_inner('store-get-doc', [hr, store_str(rhash)]) or {
		panic('get none')
	}
	assert g is cx.Element && (g as cx.Element).name == 'erased'
	assert ing_attr(g, 'shred-request') == 'shred-deep-1'

	ing_store('store-close', [hr])
	ing_store('store-close', [ho])
}
