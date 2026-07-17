module code

import cx
import os

// store_open_opts_map_test.v — #259: `store-open-opts` read opts from
// opts.attrs ONLY, but a CX map literal ({"k": v}) materializes its entries
// as CHILD ELEMENTS of the __cx_map__ envelope — so every opt passed as a CX
// map was silently dropped. For `encrypt-key-id` that meant the store was
// created PLAINTEXT where the caller asked for a sealed one (fail-open,
// violating store.md §9 fail-closed). These tests drive the REAL builtin with
// both entry shapes and assert the secret bytes never rest in the clear.

const oomt_kek = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'
const oomt_secret = 'oomt-plaintext-secret-0123456789abcdef'

fn oomt_dir_has_plaintext(dir string) bool {
	entries := os.ls(dir) or { return false }
	for f in entries {
		p := os.join_path(dir, f)
		if os.is_dir(p) {
			if oomt_dir_has_plaintext(p) {
				return true
			}
			continue
		}
		blob := os.read_bytes(p) or { continue }
		if blob.bytestr().contains(oomt_secret) {
			return true
		}
	}
	return false
}

fn oomt_open(dir string, opts_text string) cx.Node {
	opts := cx.parse(opts_text) or { panic('opts parse: ${err.msg()}') }.elements[0]
	url := cx.Node(cx.ScalarNode{ value: cx.ScalarValue('file://${dir}') })
	r := store_stdlib_builtin('store-open-opts', [url, cx.Node(opts)]) or {
		panic('store-open-opts returned none')
	}
	return r
}

fn oomt_seal_case(t string, opts_text string) {
	caps_set_all()
	dir := os.join_path(os.temp_dir(), 'cx_oomt_${t}_${os.getpid()}')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
	}
	os.setenv('CX_STORE_KEK_tenc1', oomt_kek, true)
	defer {
		os.unsetenv('CX_STORE_KEK_tenc1')
	}
	h := oomt_open(dir, opts_text)
	assert !is_err_value(h), 'open failed: ${render_canonical(h)}'
	sec := cx.Node(cx.ScalarNode{ value: cx.ScalarValue(oomt_secret) })
	ph := store_stdlib_builtin('store-put-doc', [h, sec]) or { panic('put none') }
	assert !is_err_value(ph), 'put failed: ${render_canonical(ph)}'
	// round-trip through the same handle
	got := store_stdlib_builtin('store-get-doc', [h, ph]) or { panic('get none') }
	assert render_canonical(got).contains(oomt_secret), 'roundtrip lost the doc'
	// THE point: nothing at rest carries the plaintext
	assert !oomt_dir_has_plaintext(dir), '${t}: PLAINTEXT AT REST — encrypt-key-id was dropped'
}

// the CX map-literal shape: entries are child elements of __cx_map__ (#259
// regression — this shape was silently ignored).
fn test_open_opts_encrypt_key_id_via_map_children_seals() {
	oomt_seal_case('children', '[__cx_map__ [encrypt-key-id tenc1]]')
}

// the attrs shape (pre-existing path) must keep sealing too.
fn test_open_opts_encrypt_key_id_via_attrs_seals() {
	oomt_seal_case('attrs', '[opts encrypt-key-id=tenc1]')
}
