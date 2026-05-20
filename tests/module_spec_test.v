module main

import cx

// ── ModuleSpec catalog tests (EE1, ADR 0023 §D2 revised per
// Amendment #2 R3) ────────────────────────────────────────────────────
//
// EE1 ships the parallel read-only catalog that backs inspect:,
// [?cx use-module=...], and [?cx pure-only] enforcement. These
// tests are the catalog's surface contract; DD/FF/EE2/EE4/EE7
// wiring will read through the same API.

fn test_module_catalog_has_v0_7_0_modules() {
	cat := cx.module_catalog()
	assert 'cx' in cat
	assert 'log' in cat
	assert 'inspect' in cat
	assert 'fn' in cat
	assert 'map' in cat
	assert 'array' in cat
	assert 'math' in cat
}

fn test_module_spec_returns_metadata() {
	m := cx.module_spec('cx') or { panic('cx module missing from catalog') }
	assert m.ns_prefix == 'cx'
	assert m.version == '0.7.0'
	assert m.activation == .always
	assert m.default_purity == .pure_fn
	assert m.functions.len == 22
}

fn test_module_spec_unknown_returns_none() {
	if _ := cx.module_spec('file') {
		assert false, 'file: module should not be registered at v0.7.0'
	}
}

fn test_log_module_is_side_effect_by_default() {
	m := cx.module_spec('log') or { panic('log module missing from catalog') }
	assert m.default_purity == .side_effect
	assert m.functions.len == 7
}

fn test_log_level_is_read_only_override() {
	f := cx.function_spec('log', 'level') or { panic('log:level missing from catalog') }
	assert f.local_name == 'level'
	assert f.arity_min == 0
	assert f.arity_max == 0
	assert f.purity == .read_only
}

fn test_cx_parse_is_pure_must_function() {
	f := cx.function_spec('cx', 'parse') or { panic('cx:parse missing from catalog') }
	assert f.arity_min == 1
	assert f.arity_max == 1
	assert f.purity == .pure_fn
}

fn test_cx_eval_is_side_effect_with_options_arity() {
	f := cx.function_spec('cx', 'eval') or { panic('cx:eval missing from catalog') }
	assert f.arity_min == 2
	assert f.arity_max == 3   // ADR 0023 M5 amendment: optional options map
	assert f.purity == .side_effect
}

fn test_function_spec_unlisted_inherits_module_default() {
	// math: lists no per-function specs; lookup of a known math:
	// function returns a synthetic Pure FunctionSpec inheriting from
	// the module's default_purity.
	f := cx.function_spec('math', 'sqrt') or {
		panic('math:sqrt fallthrough should produce synthetic spec')
	}
	assert f.purity == .pure_fn
	assert f.arity_max == -1   // unbounded sentinel on the synthetic record
}

fn test_function_spec_unknown_module_returns_none() {
	if _ := cx.function_spec('file', 'read-text') {
		assert false, 'unregistered module should not synthesize a function spec'
	}
}

fn test_fn_current_date_time_is_read_only() {
	// fn: module default is Pure, but clock/env/fs functions are
	// explicit ReadOnly overrides per ADR 0023 §D5.
	f := cx.function_spec('fn', 'current-dateTime') or {
		panic('fn:current-dateTime missing from catalog')
	}
	assert f.purity == .read_only
}

fn test_purity_label_round_trip() {
	assert cx.purity_label(.pure_fn) == 'pure'
	assert cx.purity_label(.read_only) == 'read-only'
	assert cx.purity_label(.side_effect) == 'side-effect'
}

fn test_is_module_active_always_modules() {
	assert cx.is_module_active('cx', []) == true
	assert cx.is_module_active('log', []) == true
	assert cx.is_module_active('math', []) == true
}

fn test_is_module_active_unknown_module_false() {
	assert cx.is_module_active('file', ['file']) == false
}
