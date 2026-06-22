module main

import cx
import code

// Tests for the Phase 2.15 `:scope public/private` visibility
// enforcement surface in `vcx/code/module_loader.v`
// + spec/code.md §12.6.
//
// The visibility rule under test:
//
//   - Module-private is the default. A `[?def]` / `[?const]` with no
//     `:scope` modifier OR with `:scope private` is private.
//   - Only `:scope public` opts a symbol into the import surface.
//   - Same-module reads (Module.lookup_def / lookup_const with
//     `requesting_module == m.name`) resolve regardless of scope.
//   - Cross-module reads require `:scope public`; otherwise the
//     lookup raises MODULE_SYMBOL_NOT_PUBLIC.
//   - MODULE_SYMBOL_NOT_FOUND is the distinct "no such name" error.
//   - `:only (name …)` on `[?lib]` runs the same visibility check at
//     module-load time so a forbidden import fails fast.
//
// All fixtures are synthetic in-process strings via
// `ModuleTable.register_source`.

// ── 1. scope_is_public — none / 'private' / 'public' triage ──────────────────

fn test_visibility_scope_is_public_helper() {
	assert code.scope_is_public(none) == false
	assert code.scope_is_public(?string('private')) == false
	assert code.scope_is_public(?string('public')) == true
}

// ── 2. Public [?def] is visible to importer ──────────────────────────────────

fn test_visibility_public_def_visible_to_importer() {
	mut table := code.new_module_table()
	src_a := '[?def helper scope=public ($x) [+ x 1]]'
	table.register_source('mod-a', src_a)
	mod_a := code.load_module(src_a, 'mod-a', mut table) or {
		panic('expected load success, got: ${err}')
	}
	assert mod_a.is_def_public('helper')
	d := mod_a.lookup_def('helper', 'mod-b') or {
		panic('expected public def to resolve cross-module, got: ${err}')
	}
	assert d.name == 'helper'
}

// ── 3. Private [?def] (default) blocked from importer ────────────────────────

fn test_visibility_private_def_blocked_from_importer() {
	mut table := code.new_module_table()
	src_a := '[?def helper ($x) [+ x 1]]'
	table.register_source('mod-a', src_a)
	mod_a := code.load_module(src_a, 'mod-a', mut table) or {
		panic('expected load success, got: ${err}')
	}
	assert mod_a.is_def_public('helper') == false
	if _ := mod_a.lookup_def('helper', 'mod-b') {
		panic('expected MODULE_SYMBOL_NOT_PUBLIC, got success')
	} else {
		assert err.msg().contains('MODULE_SYMBOL_NOT_PUBLIC')
		assert err.msg().contains('helper')
		assert err.msg().contains('mod-a')
		assert err.msg().contains('mod-b')
	}
}

// ── 4. Explicit `:scope private` is also blocked ─────────────────────────────

fn test_visibility_explicit_private_def_blocked() {
	mut table := code.new_module_table()
	src_a := '[?def helper scope=private ($x) [+ x 1]]'
	table.register_source('mod-a', src_a)
	mod_a := code.load_module(src_a, 'mod-a', mut table) or {
		panic('expected load success, got: ${err}')
	}
	assert mod_a.is_def_public('helper') == false
	if _ := mod_a.lookup_def('helper', 'mod-b') {
		panic('expected MODULE_SYMBOL_NOT_PUBLIC, got success')
	} else {
		assert err.msg().contains('MODULE_SYMBOL_NOT_PUBLIC')
	}
}

// ── 5. Same-module read ignores `:scope` ─────────────────────────────────────

fn test_visibility_same_module_read_ignores_scope() {
	mut table := code.new_module_table()
	src := '[?def priv ($x) [+ x 1]]
[?def pub scope=public ($x) [+ x 2]]'
	mod := code.load_module(src, 'mod-self', mut table) or {
		panic('expected load success, got: ${err}')
	}
	// Same-module lookups should resolve regardless of `:scope`.
	d_priv := mod.lookup_def('priv', 'mod-self') or {
		panic('expected same-module private def to resolve, got: ${err}')
	}
	assert d_priv.name == 'priv'
	d_pub := mod.lookup_def('pub', 'mod-self') or {
		panic('expected same-module public def to resolve, got: ${err}')
	}
	assert d_pub.name == 'pub'
}

// ── 6. Public [?const] visible to importer ───────────────────────────────────

fn test_visibility_public_const_visible_to_importer() {
	mut table := code.new_module_table()
	src_a := '[?const scope=public VERSION "1.0"]'
	table.register_source('mod-a', src_a)
	mod_a := code.load_module(src_a, 'mod-a', mut table) or {
		panic('expected load success, got: ${err}')
	}
	assert mod_a.is_const_public('VERSION')
	c := mod_a.lookup_const('VERSION', 'mod-b') or {
		panic('expected public const to resolve cross-module, got: ${err}')
	}
	assert c.name == 'VERSION'
}

// ── 7. Private [?const] (default) blocked from importer ──────────────────────

fn test_visibility_private_const_blocked_from_importer() {
	mut table := code.new_module_table()
	src_a := '[?const VERSION "1.0"]'
	table.register_source('mod-a', src_a)
	mod_a := code.load_module(src_a, 'mod-a', mut table) or {
		panic('expected load success, got: ${err}')
	}
	assert mod_a.is_const_public('VERSION') == false
	if _ := mod_a.lookup_const('VERSION', 'mod-b') {
		panic('expected MODULE_SYMBOL_NOT_PUBLIC, got success')
	} else {
		assert err.msg().contains('MODULE_SYMBOL_NOT_PUBLIC')
		assert err.msg().contains('VERSION')
		assert err.msg().contains('mod-a')
	}
}

// ── 8. Default scope IS private — ────────────────────────────

fn test_visibility_default_scope_is_private() {
	mut table := code.new_module_table()
	// Three flavours of "no explicit public": no modifier, explicit
	// private, and a mixed module. None should leak across modules.
	src := '[?def no-modifier ($x) [+ x 1]]
[?def explicit-private scope=private ($x) [+ x 2]]
[?const NO-MODIFIER-CONST "a"]
[?const scope=private EXPLICIT-PRIVATE-CONST "b"]'
	mod := code.load_module(src, 'mod-default', mut table) or {
		panic('expected load success, got: ${err}')
	}
	assert mod.is_def_public('no-modifier') == false
	assert mod.is_def_public('explicit-private') == false
	assert mod.is_const_public('NO-MODIFIER-CONST') == false
	assert mod.is_const_public('EXPLICIT-PRIVATE-CONST') == false
	// And cross-module lookups all fail.
	if _ := mod.lookup_def('no-modifier', 'other') {
		panic('expected default-private def to block cross-module read')
	} else {
		assert err.msg().contains('MODULE_SYMBOL_NOT_PUBLIC')
	}
	if _ := mod.lookup_const('NO-MODIFIER-CONST', 'other') {
		panic('expected default-private const to block cross-module read')
	} else {
		assert err.msg().contains('MODULE_SYMBOL_NOT_PUBLIC')
	}
}

// ── 9. `:scope public` marker flips scope to public ──────────────────────────

fn test_visibility_scope_public_flips_to_public() {
	mut table := code.new_module_table()
	// Start with private, then re-load with public — verifying the
	// AST captures the marker, not just "the parser doesn't reject".
	src_priv := '[?def serve ($req) [echo req]]'
	mut t1 := code.new_module_table()
	mod_priv := code.load_module(src_priv, 'p', mut t1) or { panic('${err}') }
	assert mod_priv.is_def_public('serve') == false

	src_pub := '[?def serve scope=public ($req) [echo req]]'
	mod_pub := code.load_module(src_pub, 'p', mut table) or { panic('${err}') }
	assert mod_pub.is_def_public('serve') == true
	d := mod_pub.lookup_def('serve', 'consumer') or {
		panic('expected public flip to allow cross-module read, got: ${err}')
	}
	assert d.scope or { '' } == 'public'
}

// ── 10. Symbol-not-found distinct from not-public ────────────────────────────

fn test_visibility_symbol_not_found_distinct() {
	mut table := code.new_module_table()
	src := '[?def existing scope=public ($x) [+ x 1]]'
	mod := code.load_module(src, 'mod-a', mut table) or { panic('${err}') }
	// Absent def → MODULE_SYMBOL_NOT_FOUND, not MODULE_SYMBOL_NOT_PUBLIC.
	if _ := mod.lookup_def('nonexistent', 'mod-b') {
		panic('expected MODULE_SYMBOL_NOT_FOUND, got success')
	} else {
		assert err.msg().contains('MODULE_SYMBOL_NOT_FOUND')
		assert err.msg().contains('nonexistent')
	}
	// Absent const → MODULE_SYMBOL_NOT_FOUND.
	if _ := mod.lookup_const('NO-SUCH-CONST', 'mod-b') {
		panic('expected MODULE_SYMBOL_NOT_FOUND, got success')
	} else {
		assert err.msg().contains('MODULE_SYMBOL_NOT_FOUND')
	}
}

// ── 11. [?lib :only (priv)] blocked at load time ─────────────────────────────

fn test_visibility_lib_only_private_blocked() {
	mut table := code.new_module_table()
	src_b := '[?def priv-helper ($x) [+ x 1]]'
	table.register_source('mod-b', src_b)
	src_a := '[?lib "mod-b" :only (priv-helper)]'
	if _ := code.load_module(src_a, 'mod-a', mut table) {
		panic('expected MODULE_SYMBOL_NOT_PUBLIC from :only, got success')
	} else {
		assert err.msg().contains('MODULE_SYMBOL_NOT_PUBLIC')
		assert err.msg().contains('priv-helper')
	}
}

// ── 12. [?lib :only (pub)] allowed when symbol is public ─────────────────────

fn test_visibility_lib_only_public_allowed() {
	mut table := code.new_module_table()
	src_b := '[?def pub-helper scope=public ($x) [+ x 1]]'
	table.register_source('mod-b', src_b)
	src_a := '[?lib "mod-b" :only (pub-helper)]'
	mod_a := code.load_module(src_a, 'mod-a', mut table) or {
		panic('expected load success with public :only, got: ${err}')
	}
	assert mod_a.libs.len == 1
}

// ── 13. [?lib :only (missing)] surfaces NOT_FOUND distinctly ─────────────────

fn test_visibility_lib_only_missing_symbol() {
	mut table := code.new_module_table()
	src_b := '[?def pub-helper scope=public ($x) [+ x 1]]'
	table.register_source('mod-b', src_b)
	src_a := '[?lib "mod-b" :only (no-such-thing)]'
	if _ := code.load_module(src_a, 'mod-a', mut table) {
		panic('expected MODULE_SYMBOL_NOT_FOUND from missing :only, got success')
	} else {
		assert err.msg().contains('MODULE_SYMBOL_NOT_FOUND')
		assert err.msg().contains('no-such-thing')
	}
}

// ── 14. public_def_names / public_const_names enumeration ────────────────────

fn test_visibility_enumerate_public_names() {
	mut table := code.new_module_table()
	src := '[?def alpha scope=public ($x) x]
[?def beta ($x) x]
[?def gamma scope=public ($x) x]
[?const scope=public PUB-A "1"]
[?const PRIV-B "2"]
[?const scope=public PUB-C "3"]'
	mod := code.load_module(src, 'enum-mod', mut table) or { panic('${err}') }
	defs := mod.public_def_names()
	assert defs == ['alpha', 'gamma']
	consts := mod.public_const_names()
	assert consts == ['PUB-A', 'PUB-C']
}

// ── 15. Public const lookup from same module ignores scope (parity w/ def) ──

fn test_visibility_same_module_const_read_ignores_scope() {
	mut table := code.new_module_table()
	src := '[?const PRIV-V "1"]
[?const scope=public PUB-V "2"]'
	mod := code.load_module(src, 'mod-c', mut table) or { panic('${err}') }
	c_priv := mod.lookup_const('PRIV-V', 'mod-c') or {
		panic('expected same-module private const to resolve, got: ${err}')
	}
	assert c_priv.name == 'PRIV-V'
	c_pub := mod.lookup_const('PUB-V', 'mod-c') or {
		panic('expected same-module public const to resolve, got: ${err}')
	}
	assert c_pub.name == 'PUB-V'
}

// suppress unused-import diagnostic — cx is imported for AST types
// even when the test surface only touches the code-side wrappers.
const _visibility_test_cx_guard = cx.new_def_node('_guard', []cx.DefParam{}, '_').name
