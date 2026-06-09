module main

import cx
import code

// Tests for the Phase 2.22 static purity checker (+
// ). Covers:
//
//   - Pure-by-default def calling another pure def (transitive) → passes.
//   - Pure def calling impure builtin → CXER0233.
//   - Pure def with `[?modify]` directive → CXER0233.
//   - Predicate body calling impure → CXER0230.
//   - `$_position` / `$_last` outside predicate body → CXER0231.
//   - `:bind _` → CXER0232.
//   - Unclassified builtin call → CXER0234.
//   - `:impure` def accepted unconditionally (annotation conservative).
//   - Recursion / self-recursion does not infinite-loop.
//   - check_all walks every def in the module.
//
// The checker reads `def.body` as verbatim source (Phase 2.16 will graft
// a structural ProgramExpr subtree). Tests construct DefNodes directly
// — no parser dependency — so each scenario is a tight, isolated unit.

// ── Helpers ───────────────────────────────────────────────────────────────────

fn mk_def_pure(name string, body string) &cx.DefNode {
	return &cx.DefNode{
		name:   name
		body:   body
		purity: .pure_
	}
}

fn mk_def_impure(name string, body string) &cx.DefNode {
	return &cx.DefNode{
		name:   name
		body:   body
		purity: .impure_
	}
}

// ── Pure-by-default passes ────────────────────────────────────────────────────

fn test_pure_def_calling_pure_def_passes() {
	add := mk_def_pure('add', '[+ a b]')
	caller := mk_def_pure('total', 'add(x, y)')
	checker := code.new_purity_checker([add, caller])
	checker.check_def(caller) or {
		assert false, 'expected pure → pure call to pass, got: ${err.msg()}'
		return
	}
}

fn test_pure_def_with_pure_builtin_passes() {
	d := mk_def_pure('shout', 'upper(text)')
	checker := code.new_purity_checker([d])
	checker.check_def(d) or {
		assert false, 'expected pure builtin call to pass, got: ${err.msg()}'
		return
	}
}

fn test_pure_def_with_no_calls_passes() {
	d := mk_def_pure('answer', '42')
	checker := code.new_purity_checker([d])
	checker.check_def(d) or {
		assert false, 'expected literal body to pass, got: ${err.msg()}'
		return
	}
}

// ── CXER0233: :pure annotation contradicts impure inferred ────────────────────

fn test_pure_def_calling_impure_builtin_raises_cxer0233() {
	d := mk_def_pure('stamp_id', 'concat("id-", uuid())')
	checker := code.new_purity_checker([d])
	checker.check_def(d) or {
		assert err.msg().contains('CXER0233'), 'expected CXER0233, got: ${err.msg()}'
		assert err.msg().contains('uuid'), 'expected callee `uuid` in message, got: ${err.msg()}'
		return
	}
	assert false, 'expected impure-builtin call to raise CXER0233'
}

fn test_pure_def_with_modify_directive_raises_cxer0233() {
	d := mk_def_pure('mut_doc', '[?modify (set @done true)]')
	checker := code.new_purity_checker([d])
	checker.check_def(d) or {
		assert err.msg().contains('CXER0233'), 'expected CXER0233, got: ${err.msg()}'
		assert err.msg().contains('?modify'), 'expected `?modify` in message, got: ${err.msg()}'
		return
	}
	assert false, 'expected [?modify] in pure body to raise CXER0233'
}

fn test_pure_def_calling_impure_def_raises_cxer0233() {
	now_iso := mk_def_impure('now-iso', 'format-instant(now())')
	caller := mk_def_pure('with-timestamp', 'concat(now-iso(), " ", msg)')
	checker := code.new_purity_checker([now_iso, caller])
	checker.check_def(caller) or {
		assert err.msg().contains('CXER0233'), 'expected CXER0233, got: ${err.msg()}'
		return
	}
	assert false, 'expected pure→impure-def call to raise CXER0233'
}

// ── :impure annotation is conservative (accepted unconditionally) ─────────────

fn test_impure_def_with_pure_body_accepted() {
	d := mk_def_impure('maybe_impure', '[+ x 1]')
	checker := code.new_purity_checker([d])
	checker.check_def(d) or {
		assert false, 'expected :impure annotation to accept pure body, got: ${err.msg()}'
		return
	}
}

fn test_impure_def_calling_impure_builtin_accepted() {
	d := mk_def_impure('log-now', 'print(now())')
	checker := code.new_purity_checker([d])
	checker.check_def(d) or {
		assert false, 'expected :impure body with impure callees to pass, got: ${err.msg()}'
		return
	}
}

// ── CXER0230: predicate-body purity ───────────────────────────────────────────

fn test_predicate_body_calling_pure_passes() {
	p := &cx.PredicateExpr{
		kind:   .generic
		source: 'upper(@name)'
	}
	checker := code.new_purity_checker([]&cx.DefNode{})
	checker.check_predicate(p) or {
		assert false, 'expected pure predicate body to pass, got: ${err.msg()}'
		return
	}
}

fn test_predicate_body_calling_impure_builtin_raises_cxer0230() {
	p := &cx.PredicateExpr{
		kind:   .generic
		source: 'eq(@stamp, now())'
	}
	checker := code.new_purity_checker([]&cx.DefNode{})
	checker.check_predicate(p) or {
		assert err.msg().contains('CXER0230'), 'expected CXER0230, got: ${err.msg()}'
		assert err.msg().contains('now'), 'expected `now` in message, got: ${err.msg()}'
		return
	}
	assert false, 'expected impure callee in predicate to raise CXER0230'
}

fn test_predicate_body_calling_impure_directive_raises_cxer0230() {
	p := &cx.PredicateExpr{
		kind:   .generic
		source: '[?send chan x]'
	}
	checker := code.new_purity_checker([]&cx.DefNode{})
	checker.check_predicate(p) or {
		assert err.msg().contains('CXER0230'), 'expected CXER0230, got: ${err.msg()}'
		return
	}
	assert false, 'expected [?send] in predicate body to raise CXER0230'
}

// ── CXER0231: reserved-binding use outside predicate body ─────────────────────

fn test_position_outside_predicate_raises_cxer0231() {
	d := mk_def_pure('weird', '[+ \$_position 1]')
	checker := code.new_purity_checker([d])
	checker.check_def(d) or {
		assert err.msg().contains('CXER0231'), 'expected CXER0231, got: ${err.msg()}'
		assert err.msg().contains('\$_position'), 'expected `\$_position` in message, got: ${err.msg()}'
		return
	}
	assert false, 'expected \$_position outside predicate to raise CXER0231'
}

fn test_last_outside_predicate_raises_cxer0231() {
	checker := code.new_purity_checker([]&cx.DefNode{})
	code.check_reserved_binding_use('[+ \$_last 0]') or {
		assert err.msg().contains('CXER0231'), 'expected CXER0231, got: ${err.msg()}'
		_ = checker
		return
	}
	assert false, 'expected \$_last outside predicate to raise CXER0231'
}

fn test_position_inside_string_literal_does_not_trip_cxer0231() {
	d := mk_def_pure('label', 'concat("position=", "\$_position")')
	checker := code.new_purity_checker([d])
	checker.check_def(d) or {
		assert false, 'expected `\$_position` inside string literal to be ignored, got: ${err.msg()}'
		return
	}
}

// ── CXER0232: reserved :bind _ ────────────────────────────────────────────────

fn test_bind_underscore_raises_cxer0232() {
	code.check_reserved_bind_name('_') or {
		assert err.msg().contains('CXER0232'), 'expected CXER0232, got: ${err.msg()}'
		return
	}
	assert false, 'expected `:bind _` to raise CXER0232'
}

fn test_bind_normal_name_passes() {
	code.check_reserved_bind_name('user') or {
		assert false, 'expected normal bind name to pass, got: ${err.msg()}'
		return
	}
}

// ── CXER0234: unclassified directive ──────────────────────────────────────────

fn test_unclassified_directive_raises_cxer0234() {
	// `?someday` is a hypothetical directive head not in either the pure
	// builtin table nor the impure-directive set; it should surface as
	// CXER0234 per the closed-list discipline.
	d := mk_def_pure('uses_unknown_dir', '[?someday x]')
	checker := code.new_purity_checker([d])
	checker.check_def(d) or {
		assert err.msg().contains('CXER0234'), 'expected CXER0234, got: ${err.msg()}'
		assert err.msg().contains('?someday'), 'expected `?someday` in message, got: ${err.msg()}'
		return
	}
	assert false, 'expected unclassified directive to raise CXER0234'
}

// ── Recursion + check_all ─────────────────────────────────────────────────────

fn test_self_recursion_terminates() {
	// `[?def fact ($n) ... fact(n - 1) ...]` — pure self-recursion must
	// not infinite-loop the walker.
	fact := mk_def_pure('fact', '[?if (eq(n, 0)) 1 [* n fact(n - 1)]]')
	checker := code.new_purity_checker([fact])
	checker.check_def(fact) or {
		assert false, 'expected pure self-recursion to pass, got: ${err.msg()}'
		return
	}
}

fn test_mutual_recursion_terminates() {
	even := mk_def_pure('even', '[?if (eq(n, 0)) true odd(n - 1)]')
	odd := mk_def_pure('odd', '[?if (eq(n, 0)) false even(n - 1)]')
	checker := code.new_purity_checker([even, odd])
	checker.check_def(even) or {
		assert false, 'expected pure mutual recursion to pass, got: ${err.msg()}'
		return
	}
	checker.check_def(odd) or {
		assert false, 'expected pure mutual recursion to pass, got: ${err.msg()}'
		return
	}
}

fn test_check_all_walks_every_def() {
	good := mk_def_pure('good', 'upper(x)')
	bad := mk_def_pure('bad', 'uuid()')
	checker := code.new_purity_checker([good, bad])
	checker.check_all() or {
		assert err.msg().contains('CXER0233'), 'expected CXER0233 from check_all, got: ${err.msg()}'
		return
	}
	assert false, 'expected check_all to surface CXER0233 from `bad`'
}

fn test_check_all_passes_when_every_def_pure() {
	a := mk_def_pure('a', '[+ x 1]')
	b := mk_def_pure('b', 'a(x)')
	checker := code.new_purity_checker([a, b])
	checker.check_all() or {
		assert false, 'expected check_all over pure defs to pass, got: ${err.msg()}'
		return
	}
}

// ── node_calls_impure_builtin — the CXLS005 §7.3 purity gate ───────────────────
// The lint warns on `[par]` only when the body actually CALLS an impure
// builtin; a pure body is safe to parallelize and gets no hint.

fn parse_body(src string) cx.ProgramNode {
	prog := cx.parse_program(src) or { panic('parse failed: ${err.msg()}') }
	return prog.body
}

fn test_node_impure_pure_body_is_pure() {
	// Pure arithmetic / string body → not impure → no CXLS005 hint.
	assert !code.node_calls_impure_builtin(parse_body('[+ 1 2]'))
	assert !code.node_calls_impure_builtin(parse_body('[upper "hi"]'))
}

fn test_node_impure_module_qualified_call_detected() {
	// `env:var` (a $-call) normalizes to the `env-var` purity-table key → impure.
	assert code.node_calls_impure_builtin(parse_body('[$env:var "HOME"]'))
}

fn test_node_impure_directive_head_detected() {
	// An impure directive head ([?async]/[?send]/…) inside the body counts.
	assert code.node_calls_impure_builtin(parse_body('[?async [+ 1 2]]'))
}

fn test_node_impure_nested_in_pure_wrapper_detected() {
	// The walk recurses through pure wrappers to find the impure $-call.
	assert code.node_calls_impure_builtin(parse_body('[?if true [then [$env:var "HOME"]] [else 0]]'))
}

fn test_node_impure_pure_call_body_is_pure() {
	// A body of only pure operator forms is pure → no CXLS005 hint.
	assert !code.node_calls_impure_builtin(parse_body('[?if true [then [+ 1 2]] [else 0]]'))
}
