module main

import cx
import code
import os

// Tests for the Phase 2.16 dev-strict type validator
// (vcx/code/type_strict_validator.v).
//
// Covers:
//   - is_strict_mode() reads CX_STRICT_TYPES env var.
//   - is_strict_mode() honors the CLI flag (set_strict_mode_cli).
//   - validate_def_strict raises CXER0206 when a DefParam lacks both
//     structural and verbatim type-annotation slots.
//   - validate_def_strict raises CXER0207 when a DefNode lacks both
//     structural and verbatim return-type slots AND the body is
//     non-empty.
//   - Strict mode OFF → no errors regardless of missing annotations.
//   - Properly-typed DefNodes pass in strict mode.

fn reset_strict_mode() {
	os.unsetenv('CX_STRICT_TYPES')
	code.set_strict_mode_cli(false)
}

// ── is_strict_mode predicate ──────────────────────────────────────────────────

fn test_is_strict_mode_default_off() {
	reset_strict_mode()
	assert !code.is_strict_mode()
}

fn test_is_strict_mode_env_var_1() {
	reset_strict_mode()
	os.setenv('CX_STRICT_TYPES', '1', true)
	assert code.is_strict_mode()
	reset_strict_mode()
}

fn test_is_strict_mode_env_var_true() {
	reset_strict_mode()
	os.setenv('CX_STRICT_TYPES', 'true', true)
	assert code.is_strict_mode()
	reset_strict_mode()
}

fn test_is_strict_mode_env_var_on() {
	reset_strict_mode()
	os.setenv('CX_STRICT_TYPES', 'on', true)
	assert code.is_strict_mode()
	reset_strict_mode()
}

fn test_is_strict_mode_env_var_zero_off() {
	reset_strict_mode()
	os.setenv('CX_STRICT_TYPES', '0', true)
	assert !code.is_strict_mode()
	reset_strict_mode()
}

fn test_is_strict_mode_cli_flag() {
	reset_strict_mode()
	code.set_strict_mode_cli(true)
	assert code.is_strict_mode()
	code.set_strict_mode_cli(false)
}

// ── Strict OFF — no errors ────────────────────────────────────────────────────

fn test_validate_def_strict_off_no_errors_on_untyped_def() {
	reset_strict_mode()
	n := cx.parse_def('[?def add ($a $b) [+ a b]]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	code.validate_def_strict(&n) or {
		assert false, 'strict-off should never error; got: ${err}'
		return
	}
}

fn test_validate_def_strict_off_no_errors_on_missing_returns() {
	reset_strict_mode()
	n := cx.parse_def('[?def f ($x::int) x]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	code.validate_def_strict(&n) or {
		assert false, 'strict-off should never error; got: ${err}'
		return
	}
}

// ── Strict ON — CXER0206 on missing param annotation ─────────────────────────

fn test_validate_def_strict_on_raises_0206_for_untyped_param() {
	reset_strict_mode()
	code.set_strict_mode_cli(true)
	n := cx.parse_def('[?def add ($a $b) [+ a b]]') or {
		assert false, 'parse failed: ${err}'
		code.set_strict_mode_cli(false)
		return
	}
	code.validate_def_strict(&n) or {
		assert err.msg().contains('CXER0206'), 'expected CXER0206; got: ${err.msg()}'
		code.set_strict_mode_cli(false)
		return
	}
	code.set_strict_mode_cli(false)
	assert false, 'expected CXER0206 to fire'
}

fn test_validate_def_strict_on_raises_0206_via_env_var() {
	reset_strict_mode()
	os.setenv('CX_STRICT_TYPES', '1', true)
	n := cx.parse_def('[?def f ($x) x]') or {
		assert false
		reset_strict_mode()
		return
	}
	code.validate_def_strict(&n) or {
		assert err.msg().contains('CXER0206')
		reset_strict_mode()
		return
	}
	reset_strict_mode()
	assert false, 'expected CXER0206'
}

fn test_validate_def_strict_on_passes_when_all_params_typed_with_returns() {
	reset_strict_mode()
	code.set_strict_mode_cli(true)
	defer {
		code.set_strict_mode_cli(false)
	}
	n := cx.parse_def('[?def add [returns int] ($a::int $b::int) [+ a b]]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	code.validate_def_strict(&n) or {
		assert false, 'strict-on with fully typed def should pass; got: ${err}'
		return
	}
}

fn test_validate_def_strict_on_first_untyped_param_fires() {
	// Only the first param is typed.
	reset_strict_mode()
	code.set_strict_mode_cli(true)
	defer {
		code.set_strict_mode_cli(false)
	}
	n := cx.parse_def('[?def add [returns int] ($a::int $b) [+ a b]]') or {
		assert false
		return
	}
	code.validate_def_strict(&n) or {
		assert err.msg().contains('CXER0206')
		assert err.msg().contains('parameter `b`'), 'should name the offending param `b`; got: ${err.msg()}'
		return
	}
	assert false, 'expected CXER0206'
}

// ── Strict ON — CXER0207 on missing returns ──────────────────────────────────

fn test_validate_def_strict_on_raises_0207_for_missing_returns() {
	reset_strict_mode()
	code.set_strict_mode_cli(true)
	defer {
		code.set_strict_mode_cli(false)
	}
	// Param is typed but `:returns` is missing.
	n := cx.parse_def('[?def f ($x::int) [* x 2]]') or {
		assert false
		return
	}
	code.validate_def_strict(&n) or {
		assert err.msg().contains('CXER0207'), 'expected CXER0207; got: ${err.msg()}'
		return
	}
	assert false, 'expected CXER0207'
}

fn test_validate_def_strict_on_zero_params_still_needs_returns() {
	reset_strict_mode()
	code.set_strict_mode_cli(true)
	defer {
		code.set_strict_mode_cli(false)
	}
	// Zero-param body that's non-empty — still needs `:returns` under strict.
	n := cx.parse_def('[?def magic () 42]') or {
		assert false
		return
	}
	code.validate_def_strict(&n) or {
		assert err.msg().contains('CXER0207')
		return
	}
	assert false, 'expected CXER0207'
}

fn test_validate_def_strict_on_returns_present_no_error() {
	reset_strict_mode()
	code.set_strict_mode_cli(true)
	defer {
		code.set_strict_mode_cli(false)
	}
	n := cx.parse_def('[?def f [returns int] () 42]') or {
		assert false
		return
	}
	code.validate_def_strict(&n) or {
		assert false, 'should pass with :returns; got: ${err}'
		return
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn test_param_has_type_annotation_structural_only() {
	// Manually build a DefParam with only the structural slot.
	te := cx.parse_type_expr('int') or {
		assert false
		return
	}
	p := cx.DefParam{
		name:      'x'
		type_expr: te
	}
	assert code.param_has_type_annotation(p)
}

fn test_param_has_type_annotation_source_only() {
	p := cx.DefParam{
		name:             'x'
		type_expr_source: ?string('int')
	}
	assert code.param_has_type_annotation(p)
}

fn test_param_has_type_annotation_both_none_false() {
	p := cx.DefParam{
		name: 'x'
	}
	assert !code.param_has_type_annotation(p)
}

fn test_def_has_return_annotation_structural_only() {
	te := cx.parse_type_expr('string') or {
		assert false
		return
	}
	d := cx.DefNode{
		name:              'f'
		body:              'body'
		returns_type_expr: te
	}
	assert code.def_has_return_annotation(&d)
}

fn test_def_has_return_annotation_source_only() {
	d := cx.DefNode{
		name:                'f'
		body:                'body'
		returns_type_source: ?string('int')
	}
	assert code.def_has_return_annotation(&d)
}

fn test_def_has_return_annotation_neither() {
	d := cx.DefNode{
		name: 'f'
		body: 'body'
	}
	assert !code.def_has_return_annotation(&d)
}

// ── Param-only annotation via structural-fallback path ───────────────────────

fn test_validate_def_strict_structural_only_param_passes() {
	// DefParam has only the structural slot (no verbatim source).
	// Strict mode should accept — at least one of the two slots is set.
	reset_strict_mode()
	code.set_strict_mode_cli(true)
	defer {
		code.set_strict_mode_cli(false)
	}
	te := cx.parse_type_expr('int') or {
		assert false
		return
	}
	rte := cx.parse_type_expr('int') or {
		assert false
		return
	}
	d := cx.DefNode{
		name:              'f'
		params:            [
			cx.DefParam{
				name:      'x'
				type_expr: te
			},
		]
		body:              'x'
		returns_type_expr: rte
	}
	code.validate_def_strict(&d) or {
		assert false, 'structural-only param should pass strict; got: ${err}'
		return
	}
}
