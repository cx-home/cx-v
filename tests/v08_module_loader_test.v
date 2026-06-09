module main

import cx
import code
import crypto.sha512
import encoding.base64
import os

// Tests for the Phase 2.13 + 2.14 standalone module loader
// (`vcx/code/module_loader.v`)
// spec/lockfile.md §4.4.
//
// The loader under test is `code.load_module(source, name, mut table)`
// plus `code.resolve_lib(node, mut table)` + `code.verify_sri(integ,
// content)`. Coverage targets:
//
//   - Two-pass load: single-module + multi-module + transitive.
//   - Cycle detection (cross-module A↔B) — MODULE_CYCLE_DETECTED.
//   - SRI shape validation (sha384 / sha512 well-formed + malformed).
//   - SRI digest verification (matching + mismatching content).
//   - HTTPS resolver — returns MODULE_HTTPS_FETCH_DEFERRED.
//   - Registered-name resolver — looks up in-memory map.
//   - File-path resolver — round-trips a temp file under base_dir.
//   - [?const] dependency ordering — Kahn's algorithm: a const that
//     references another const is evaluated AFTER its dep.
//   - Duplicate-name diagnostic.
//
// All fixtures are synthetic in-process strings — Phase 2.13 partial
// scope skips real on-disk fixtures (Phase 2.x graft).

// ── 1. Single-module load (no libs) → module is callable ─────────────────────

fn test_module_loader_single_module_no_libs() {
	src := '[?def double ($x) [* x 2]]
[?const FORTY-TWO [double 21]]'
	mut table := code.new_module_table()
	mod := code.load_module(src, 'm-single', mut table) or {
		panic('expected load success, got: ${err}')
	}
	assert mod.name == 'm-single'
	assert mod.defs.len == 1
	assert 'double' in mod.defs
	assert mod.consts.len == 1
	assert 'FORTY-TWO' in mod.consts
	assert mod.libs.len == 0
	// Module is registered in the table.
	assert 'm-single' in table.modules
}

// ── 2. Two-module load — A imports B (registered-name) ───────────────────────

fn test_module_loader_two_modules_a_imports_b() {
	mut table := code.new_module_table()
	src_b := '[?def helper ($x) [+ x 1]]'
	table.register_source('mod-b', src_b)
	src_a := '[?lib "mod-b"]
[?def caller ($x) [helper x]]'
	mod_a := code.load_module(src_a, 'mod-a', mut table) or {
		panic('expected load success, got: ${err}')
	}
	assert mod_a.libs.len == 1
	assert mod_a.libs[0].resolver_source == 'mod-b'
	// mod-b loaded transitively.
	assert 'mod-b' in table.modules
	mod_b := table.modules['mod-b'] or { panic('mod-b not registered') }
	assert 'helper' in mod_b.defs
}

// ── 3. Cycle detection — A imports B, B imports A → MODULE_CYCLE_DETECTED ───

fn test_module_loader_cycle_detected() {
	mut table := code.new_module_table()
	table.register_source('cycle-a', '[?lib "cycle-b"]')
	table.register_source('cycle-b', '[?lib "cycle-a"]')
	if _ := code.load_module('[?lib "cycle-b"]', 'cycle-a', mut table) {
		panic('expected cycle error, got success')
	} else {
		assert err.msg().contains('MODULE_CYCLE_DETECTED') || err.msg().contains('CXER0210')
	}
}

// ── 4. SRI sha384 well-formed shape passes shape check ───────────────────────

fn test_module_loader_sri_sha384_shape_valid() {
	// A real sha384 digest (48 bytes) of "hello" — base64-encoded.
	digest := sha512.sum384('hello'.bytes())
	encoded := base64.encode(digest)
	sri := 'sha384-${encoded}'
	shape := code.verify_sri_shape(sri) or {
		panic('expected shape valid, got: ${err}')
	}
	assert shape.algo == 'sha384'
	assert shape.expected_digest.len == 48
}

// ── 5. SRI sha512 well-formed shape passes shape check ───────────────────────

fn test_module_loader_sri_sha512_shape_valid() {
	digest := sha512.sum512('hello'.bytes())
	encoded := base64.encode(digest)
	sri := 'sha512-${encoded}'
	shape := code.verify_sri_shape(sri) or {
		panic('expected shape valid, got: ${err}')
	}
	assert shape.algo == 'sha512'
	assert shape.expected_digest.len == 64
}

// ── 6. SRI malformed prefix raises MODULE_SRI_MALFORMED ──────────────────────

fn test_module_loader_sri_malformed_prefix() {
	if _ := code.verify_sri_shape('md5-AAAA') {
		panic('expected malformed error, got success')
	} else {
		assert err.msg().contains('MODULE_SRI_MALFORMED')
		assert err.msg().contains('md5')
	}
}

// ── 7. SRI missing dash raises MODULE_SRI_MALFORMED ──────────────────────────

fn test_module_loader_sri_missing_dash() {
	if _ := code.verify_sri_shape('sha384AAAA') {
		panic('expected malformed error, got success')
	} else {
		assert err.msg().contains('MODULE_SRI_MALFORMED')
	}
}

// ── 8. SRI verify digest match returns true ──────────────────────────────────

fn test_module_loader_sri_digest_match() {
	content := 'hello world'
	digest := sha512.sum384(content.bytes())
	encoded := base64.encode(digest)
	sri := 'sha384-${encoded}'
	matched := code.verify_sri(sri, content) or {
		panic('expected verify success, got: ${err}')
	}
	assert matched == true
}

// ── 9. SRI verify digest mismatch returns false ──────────────────────────────

fn test_module_loader_sri_digest_mismatch() {
	// SRI computed over "hello" but content is "goodbye".
	digest := sha512.sum384('hello'.bytes())
	encoded := base64.encode(digest)
	sri := 'sha384-${encoded}'
	matched := code.verify_sri(sri, 'goodbye') or {
		panic('expected verify shape valid, got: ${err}')
	}
	assert matched == false
}

// ── 10. HTTPS resolver returns MODULE_HTTPS_FETCH_DEFERRED ───────────────────

fn test_module_loader_https_fetch_deferred() {
	mut table := code.new_module_table()
	node := cx.parse_lib('[?lib "https://cdn.example.com/regex-1.2.3.zip"]') or {
		panic('parse_lib failed: ${err}')
	}
	if _ := code.resolve_lib(node, mut table) {
		panic('expected HTTPS deferred error, got success')
	} else {
		assert err.msg().contains('MODULE_HTTPS_FETCH_DEFERRED')
	}
}

// ── 11. Registered-name resolver missing → MODULE_UNKNOWN_REGISTERED ─────────

fn test_module_loader_unknown_registered_name() {
	mut table := code.new_module_table()
	node := cx.parse_lib('[?lib "not-a-real-module"]') or {
		panic('parse_lib failed: ${err}')
	}
	if _ := code.resolve_lib(node, mut table) {
		panic('expected unknown-registered error, got success')
	} else {
		assert err.msg().contains('MODULE_UNKNOWN_REGISTERED')
	}
}

// ── 12. [?const] dependency ordering — A → B → C dependency chain ────────────

fn test_module_loader_const_dependency_ordering() {
	// A depends on B (refs B); B depends on C (refs C); C depends on
	// nothing. Topological evaluation order MUST be C, B, A.
	src := '[?const A [+ B 1]]
[?const B [+ C 1]]
[?const C 1]'
	mut table := code.new_module_table()
	mod := code.load_module(src, 'm-order', mut table) or {
		panic('expected load success, got: ${err}')
	}
	assert mod.const_order.len == 3
	idx_a := mod.const_order.index('A')
	idx_b := mod.const_order.index('B')
	idx_c := mod.const_order.index('C')
	assert idx_c >= 0 && idx_b >= 0 && idx_a >= 0
	assert idx_c < idx_b
	assert idx_b < idx_a
}

// ── 13. [?const] cycle → MODULE_CONST_CYCLE (CXER0214) ───────────────────────

fn test_module_loader_const_cycle() {
	src := '[?const A B]
[?const B A]'
	mut table := code.new_module_table()
	if _ := code.load_module(src, 'm-const-cycle', mut table) {
		panic('expected const-cycle error, got success')
	} else {
		assert err.msg().contains('MODULE_CONST_CYCLE') || err.msg().contains('CXER0214')
	}
}

// ── 14. Duplicate name (def + const with same identifier) → CXER0205 ─────────

fn test_module_loader_duplicate_name() {
	src := '[?def shared ($x) x]
[?const shared 42]'
	mut table := code.new_module_table()
	if _ := code.load_module(src, 'm-dup', mut table) {
		panic('expected duplicate-name error, got success')
	} else {
		assert err.msg().contains('MODULE_DUPLICATE_NAME') || err.msg().contains('CXER0205')
	}
}

// ── 15. Idempotent re-load returns same module pointer ───────────────────────

fn test_module_loader_idempotent_reload() {
	mut table := code.new_module_table()
	src := '[?def f ($x) x]'
	mod1 := code.load_module(src, 'm-idem', mut table) or {
		panic('first load failed: ${err}')
	}
	// Second call returns the cached entry.
	mod2 := code.load_module(src, 'm-idem', mut table) or {
		panic('second load failed: ${err}')
	}
	// Same name; same defs set.
	assert mod1.name == mod2.name
	assert mod1.defs.len == mod2.defs.len
}

// ── 16. Transitive resolution — A imports B imports C ────────────────────────

fn test_module_loader_transitive_three_deep() {
	mut table := code.new_module_table()
	table.register_source('lib-c', '[?def cee () "c"]')
	table.register_source('lib-b', '[?lib "lib-c"]
[?def bee () "b"]')
	src_a := '[?lib "lib-b"]
[?def aye () "a"]'
	_ := code.load_module(src_a, 'lib-a', mut table) or {
		panic('expected load success, got: ${err}')
	}
	assert 'lib-a' in table.modules
	assert 'lib-b' in table.modules
	assert 'lib-c' in table.modules
}

// ── 17. file_path resolver reads from disk under base_dir ────────────────────

fn test_module_loader_file_path_resolver() {
	// Create a temp dir + file with a tiny module source.
	tmp := os.join_path(os.temp_dir(), 'cx-v08-mod-loader-test-${os.getpid()}')
	os.mkdir_all(tmp) or { panic('mkdir tmp failed: ${err}') }
	defer {
		os.rmdir_all(tmp) or {}
	}
	mod_src := '[?def helper () "ok"]'
	mod_path := os.join_path(tmp, 'helper.cx')
	os.write_file(mod_path, mod_src) or { panic('write helper.cx failed: ${err}') }
	mut table := code.new_module_table()
	table.base_dir = tmp
	node := cx.parse_lib('[?lib "./helper.cx"]') or { panic('parse_lib failed: ${err}') }
	mod := code.resolve_lib(node, mut table) or {
		panic('file-path resolve failed: ${err}')
	}
	assert 'helper' in mod.defs
}

// ── 18. Comment + whitespace tolerant scanner ─────────────────────────────────

fn test_module_loader_scanner_skips_comments() {
	src := '[- This is a top-level comment that the scanner ignores -]

[?def f ($x) x]

[- Another comment -]

[?const C 1]'
	mut table := code.new_module_table()
	mod := code.load_module(src, 'm-comments', mut table) or {
		panic('expected load success, got: ${err}')
	}
	assert 'f' in mod.defs
	assert 'C' in mod.consts
}
