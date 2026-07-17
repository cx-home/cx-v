module code

import cx
import sync

// store_silent_partial_wave5_test.v — W5 silent-partial guards (#185/#209 non-
// object-graph porcelain must error not fabricate success; #192 query predicate/
// attribute CXPath must match or fail-closed, never a lying empty result).

fn w5_open(url string) cx.Node {
	return store_open_impl(url, '', '', false, true, map[string]string{})
}

fn w5_err_code(n cx.Node) string {
	if n is cx.Element && n.name == 'err' {
		for a in n.attrs {
			if a.name == 'code' {
				return cx.scalar_value_str_public(a.value)
			}
		}
	}
	return ''
}

// register a synthetic columnar-backed handle (the guard checks ms.backend, no
// Arrow build needed to exercise the porcelain gate).
fn w5_columnar_handle() cx.Node {
	mut ms := &MemStore{
		url:     'document+file:///tmp/w5col?encoding=parquet'
		backend: 'columnar'
		is_open: true
		op_lock: sync_new()
	}
	id := store_register(ms)
	return store_handle_element(id, ms)
}

fn sync_new() &sync.Mutex {
	return sync.new_mutex()
}

// ── #209: columnar clone/push/pull → CXER1709 "use migrate", never objects=0 ──

fn test_columnar_porcelain_errors_not_silent() {
	caps_set_all()
	col := w5_columnar_handle()
	mem := w5_open('mem://w5-col-dst')
	// clone FROM columnar → hard error (source has no object identity).
	r_clone := store_stdlib_builtin('store-clone', [col, mem]) or {
		cx.Node(cx.ScalarNode{})
	}
	assert w5_err_code(r_clone) == 'cx-err:CXER1709', 'clone from columnar must be CXER1709 (§4 use migrate), got ${w5_err_code(r_clone)}'
	// push TO columnar → hard error (dest has no object identity).
	r_push := store_stdlib_builtin('store-push', [mem, col]) or { cx.Node(cx.ScalarNode{}) }
	assert w5_err_code(r_push) == 'cx-err:CXER1709', 'push to columnar must be CXER1709, got ${w5_err_code(r_push)}'
	// crucially: NOT a fabricated objects=0 success.
	assert w5_err_code(r_clone) != '', 'columnar clone must NOT return a *-result success'
}

// ── #185: remote byte-source porcelain → CXER1709, never phantom success ──────

fn test_remote_porcelain_errors_not_phantom() {
	caps_set_all()
	// a remote byte-source handle (ftp) has no object wire → porcelain must error.
	remote := w5_open('ftp://ftp.example.invalid/store/')
	if w5_err_code(remote) != '' {
		// open itself may defer connection; if it errored, skip (can't test the guard)
		return
	}
	mem := w5_open('mem://w5-remote-src')
	r := store_stdlib_builtin('store-push', [mem, remote]) or { cx.Node(cx.ScalarNode{}) }
	assert w5_err_code(r) == 'cx-err:CXER1709', 'push to a remote byte-source must be CXER1709 (#185 no phantom success), got ${w5_err_code(r)}'
}

// ── #192: query predicate + attribute CXPath ──────────────────────────────────

fn w5_query(local cx.Node, path string) cx.Node {
	return store_stdlib_builtin('store-query', [local, store_str(path)]) or {
		cx.Node(cx.ScalarNode{})
	}
}

fn w5_result_count(n cx.Node) int {
	mut c := 0
	if n is cx.Element {
		for it in n.items {
			if it is cx.Element && it.name == 'result' {
				c++
			}
		}
	}
	return c
}

fn test_query_predicate_matches() {
	caps_set_all()
	local := w5_open('mem://w5-query')
	store_stdlib_builtin('store-put-doc-text', [local, store_str('[users [user name="al"] [user name="bo"]]')]) or {
		panic('put')
	}
	// bare name step still works (2 user elements in the one doc)
	names := w5_query(local, '//user')
	assert w5_result_count(names) == 1, '//user must match the doc'
	// predicate: only the doc containing user[@name='al'] (it does) → 1 result
	pred := w5_query(local, "//user[= $_@name 'al']")
	assert w5_err_code(pred) == '', 'predicate query must not error: ${w5_err_code(pred)}'
	assert w5_result_count(pred) == 1, "//user[= \$_@name 'al'] must match (was silently ()), got ${w5_result_count(pred)}"
	// a predicate that matches nothing → genuinely 0 results (not an error)
	nomatch := w5_query(local, "//user[= $_@name 'zz']")
	assert w5_err_code(nomatch) == '', 'non-matching predicate is empty, not an error'
	assert w5_result_count(nomatch) == 0, 'non-matching predicate → 0 results'
	// attribute axis: //user/@name → the attribute values (not silently ())
	attr := w5_query(local, '//user/@name')
	assert w5_err_code(attr) == '', 'attribute-axis query must not error'
	assert w5_result_count(attr) == 1, '//user/@name must match (was silently ()), got ${w5_result_count(attr)}'
}
