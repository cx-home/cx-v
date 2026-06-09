module code

import cx
import os

// type_strict_validator.v — dev-strict type annotation validator
// (Phase 2.16, partial).
//
// Per spec/code.md §12.7.6, type expressions are
// enforced only under **strict mode** (`--strict` CLI flag OR
// `CX_STRICT_TYPES=1` env var). In default execution the
// annotations are inert tooling input and never cost runtime.
//
// Phase 2.16 (partial) scope — declaration-time annotation
// presence check, run AT module-load time after `parse_def`
// produces the DefNode. The full runtime check (arg-vs-annotation
// at call site; return-value vs `:returns T` at call return)
// remains deferred to the Phase 2.21 evaluator graft.
//
// Wire codes raised:
//   - CXER0206 (E_TYPE_MISMATCH_ARG)    — a DefParam lacks BOTH the
//                                          structural and verbatim
//                                          type-annotation slots
//                                          (i.e. an untyped param
//                                          on a `--strict` module).
//   - CXER0207 (E_TYPE_MISMATCH_RETURN) — a DefNode with a non-
//                                          empty body lacks BOTH the
//                                          structural and verbatim
//                                          return-type slots.
//
// Cross-references:
//   - spec/code.md §12.7.6 (normative dev-strict spec)
//   - vcx/cx/type_expr.v (Phase 2.16 structural AST)
//   - vcx/cx/def_node.v / def_parser.v (Phase 2.12 + 2.16)

// ── Strict-mode predicate ────────────────────────────────────────────────────
//
// The CLI flag is held in a process-scoped marker env var so we can
// expose the same check across CLI parse + test harness without
// depending on V's `__global` (which would need `-enable-globals`
// on every test invocation). The marker var is distinct from the
// public `CX_STRICT_TYPES` toggle so a caller can independently
// drive each surface — the union of the two is the effective
// strict-mode bit.

const cli_strict_marker = '__CX_STRICT_TYPES_CLI__'

// set_strict_mode_cli is the entry point the CLI parser calls when
// it sees the `--strict` flag. The flag persists for the lifetime
// of the process (held in an env var).
pub fn set_strict_mode_cli(on bool) {
	if on {
		os.setenv(cli_strict_marker, '1', true)
	} else {
		os.unsetenv(cli_strict_marker)
	}
}

// is_strict_mode returns true iff the process is running in
// dev-strict mode (either the CLI flag was set via
// `set_strict_mode_cli` OR the `CX_STRICT_TYPES` env var is one of
// `1` / `true` / `on` / `yes`).
pub fn is_strict_mode() bool {
	if os.getenv(cli_strict_marker) == '1' {
		return true
	}
	v := os.getenv('CX_STRICT_TYPES')
	if v == '' {
		return false
	}
	lower := v.to_lower()
	return lower == '1' || lower == 'true' || lower == 'on' || lower == 'yes'
}

// ── Validator entry points ────────────────────────────────────────────────────

// validate_def_strict runs the declaration-time strict-mode checks
// on a single DefNode. When strict mode is OFF the function
// short-circuits and returns no error. When strict mode is ON the
// function raises:
//
//   - `cx-err:CXER0206 …` — if any DefParam lacks BOTH the
//     structural `type_expr` slot AND the verbatim `type_expr_source`
//     slot.
//   - `cx-err:CXER0207 …` — if the DefNode lacks BOTH the
//     structural `returns_type_expr` slot AND the verbatim
//     `returns_type_source` slot AND the body is non-empty (the
//     return-value-bearing heuristic; Phase 2.21 replaces this
//     with structural return-value analysis once the evaluator
//     grafts in).
//
// The function reports the first failure encountered and stops;
// callers that need a complete report can iterate per-param
// manually via `param_has_type_annotation`.
pub fn validate_def_strict(def &cx.DefNode) ! {
	if !is_strict_mode() {
		return
	}
	for p in def.params {
		if !param_has_type_annotation(p) {
			return error('cx-err:CXER0206 E_TYPE_MISMATCH_ARG: parameter `${p.name}` of `[?def ${def.name}]` is missing a type annotation under strict mode (per spec/code.md §12.7.6)')
		}
	}
	if !def_has_return_annotation(def) && def_body_is_value_returning(def) {
		return error('cx-err:CXER0207 E_TYPE_MISMATCH_RETURN: `[?def ${def.name}]` is missing a :returns annotation under strict mode (per spec/code.md §12.7.6)')
	}
}

// param_has_type_annotation returns true iff the DefParam carries
// at least one of the two type-annotation slots (structural or
// verbatim). Used by validate_def_strict and exported for callers
// that want a finer-grained tooling pass.
pub fn param_has_type_annotation(p cx.DefParam) bool {
	if p.type_expr != none {
		return true
	}
	if p.type_expr_source != none {
		return true
	}
	return false
}

// def_has_return_annotation returns true iff the DefNode carries
// at least one of the two return-type slots.
pub fn def_has_return_annotation(def &cx.DefNode) bool {
	if def.returns_type_expr != none {
		return true
	}
	if def.returns_type_source != none {
		return true
	}
	return false
}

// def_body_is_value_returning is the Phase 2.16 stub heuristic for
// "does this body return a value." Currently returns true iff the
// trimmed body source is non-empty. Phase 2.21 graft replaces this
// with structural cx.ProgramExpr return-value analysis once the
// evaluator wires through.
fn def_body_is_value_returning(def &cx.DefNode) bool {
	return def.body.trim_space().len > 0
}
