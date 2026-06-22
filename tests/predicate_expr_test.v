module main

import cx

// Tests for Phase 2.19 PredicateExpr AST + path_parser integration.
//
// Coverage:
//   - PredicateExpr construction + .eq() (incl. advisory source/loc exclusion)
//   - Disjoint-domain canonical-bytes prefix + SHA-256 hash
// atomic templates parse to expected shape:
//       @name              → attr_test
//       @name OP value     → attr_compare (all 6 ops)
//       N (1-based int)    → int_position
//       count(*) [OP N]    → function_call
//       $_position/$_last  → reserved_binding
//       $_@name [OP value] → attr_test / attr_compare (explicit-$_ form)
//   - Complex bodies (`and`/`or` / nested) fail gracefully (parser errors;
//     path_parser falls back to source-only PathPredicate).
//   - Round-trip via parse_path("//user[@active]") populates both
//     PathPredicate.source AND PathPredicate.expr = some(attr_test{…}).

// ── Construction + equality ───────────────────────────────────────────────────

fn test_predicate_expr_construct_attr_test() {
	p := cx.new_predicate_expr(cx.PredicateExprKind.attr_test, '@active')
	assert p.kind == cx.PredicateExprKind.attr_test
	assert p.source == '@active'
	assert p.children.len == 0
}

fn test_predicate_expr_eq_identical() {
	p1 := &cx.PredicateExpr{
		kind:   .attr_test
		name:   'active'
		source: '@active'
	}
	p2 := &cx.PredicateExpr{
		kind:   .attr_test
		name:   'active'
		source: '@active'
	}
	assert p1.eq(p2)
	assert p2.eq(p1)
}

fn test_predicate_expr_eq_excludes_source_and_loc() {
	// Advisory fields source/loc do NOT participate in equality —
	// two PredicateExprs differing only on surface formatting compare
	// equal.
	p1 := &cx.PredicateExpr{
		kind:   .attr_compare
		name:   'active'
		op:     '='
		value:  'true'
		source: '@active=true'
	}
	p2 := &cx.PredicateExpr{
		kind:   .attr_compare
		name:   'active'
		op:     '='
		value:  'true'
		source: '@active = true'
		loc:    cx.PredicateLoc{ line: 5, col: 12 }
	}
	assert p1.eq(p2)
	assert p2.eq(p1)
}

fn test_predicate_expr_eq_differs_on_kind() {
	p1 := &cx.PredicateExpr{ kind: .attr_test, name: 'x', source: '@x' }
	p2 := &cx.PredicateExpr{ kind: .attr_compare, name: 'x', source: '@x' }
	assert !p1.eq(p2)
}

fn test_predicate_expr_eq_differs_on_name() {
	p1 := &cx.PredicateExpr{ kind: .attr_test, name: 'a', source: '@a' }
	p2 := &cx.PredicateExpr{ kind: .attr_test, name: 'b', source: '@b' }
	assert !p1.eq(p2)
}

fn test_predicate_expr_eq_differs_on_op() {
	p1 := &cx.PredicateExpr{ kind: .attr_compare, name: 'a', op: '=', value: '1', source: '@a=1' }
	p2 := &cx.PredicateExpr{ kind: .attr_compare, name: 'a', op: '!=', value: '1', source: '@a!=1' }
	assert !p1.eq(p2)
}

fn test_predicate_expr_eq_differs_on_position() {
	p1 := &cx.PredicateExpr{ kind: .int_position, position: 1, source: '1' }
	p2 := &cx.PredicateExpr{ kind: .int_position, position: 2, source: '2' }
	assert !p1.eq(p2)
}

// ── Hashing — disjoint domain ─────────────────────────────────────────────────

fn test_predicate_expr_hash_is_deterministic() {
	p1 := &cx.PredicateExpr{ kind: .attr_test, name: 'active', source: '@active' }
	p2 := &cx.PredicateExpr{ kind: .attr_test, name: 'active', source: '@active' }
	assert cx.predicate_expr_hash(p1) == cx.predicate_expr_hash(p2)
}

fn test_predicate_expr_hash_changes_on_kind() {
	p1 := &cx.PredicateExpr{ kind: .attr_test, name: 'x', source: '@x' }
	p2 := &cx.PredicateExpr{ kind: .attr_compare, name: 'x', op: '=', value: 'y', source: '@x=y' }
	assert cx.predicate_expr_hash(p1) != cx.predicate_expr_hash(p2)
}

fn test_predicate_expr_canonical_bytes_carry_domain_prefix() {
	p := &cx.PredicateExpr{ kind: .attr_test, name: 'x', source: '@x' }
	bytes := cx.predicate_expr_canonical_bytes(p)
	// Disjoint-domain prefix: bytes start with literal "PredicateExpr\x00".
	prefix := 'PredicateExpr'.bytes()
	assert bytes.len > prefix.len + 1
	for i, b in prefix {
		assert bytes[i] == b, 'canonical bytes diverge from PredicateExpr prefix at ${i}'
	}
	assert bytes[prefix.len] == u8(0x00), 'expected \x00 after PredicateExpr tag'
}

fn test_predicate_expr_hash_disjoint_from_path_node() {
	// A PredicateExpr's canonical bytes carry the `PredicateExpr\x00`
	// domain prefix; PathNode carries `PathNode\x00`. Hashes therefore
	// cannot collide across the two domains.
	pe := &cx.PredicateExpr{ kind: .attr_test, name: 'active', source: '@active' }
	pn := cx.PathNode{
		form: cx.PathForm.descendant
		steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user' }]
	}
	assert cx.predicate_expr_hash(pe) != cx.path_node_hash(pn)
	// And the canonical bytes themselves start with disjoint tags.
	pe_bytes := cx.predicate_expr_canonical_bytes(pe)
	pn_bytes := cx.path_node_canonical_bytes(pn)
	assert pe_bytes[0..'PredicateExpr'.len].bytestr() == 'PredicateExpr'
	assert pn_bytes[0..'PathNode'.len].bytestr() == 'PathNode'
}

// ── JSON projection ───────────────────────────────────────────────────────────

fn test_predicate_expr_to_json_attr_test() {
	p := &cx.PredicateExpr{ kind: .attr_test, name: 'active', source: '@active' }
	js := cx.predicate_expr_to_json(p)
	assert js.contains('"type":"PredicateExpr"')
	assert js.contains('"kind":"attr_test"')
	assert js.contains('"name":"active"')
	assert js.contains('"source":"@active"')
}

fn test_predicate_expr_to_json_attr_compare() {
	p := &cx.PredicateExpr{
		kind:   .attr_compare
		name:   'age'
		op:     '>='
		value:  '18'
		source: '@age >= 18'
	}
	js := cx.predicate_expr_to_json(p)
	assert js.contains('"kind":"attr_compare"')
	assert js.contains('"name":"age"')
	assert js.contains('"op":">="')
	assert js.contains('"value":"18"')
}

fn test_predicate_expr_to_json_int_position() {
	p := &cx.PredicateExpr{ kind: .int_position, position: 3, source: '3' }
	js := cx.predicate_expr_to_json(p)
	assert js.contains('"kind":"int_position"')
	assert js.contains('"position":3')
}

// ── Atomic template — @name ───────────────────────────────────────────────────

fn test_predicate_expr_parse_attr_test() {
	p := cx.predicate_expr_parse('@active') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.kind == cx.PredicateExprKind.attr_test
	if n := p.name { assert n == 'active' } else { assert false, 'name should be set' }
	assert p.source == '@active'
}

fn test_predicate_expr_parse_attr_test_with_whitespace() {
	p := cx.predicate_expr_parse('  @active  ') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.kind == cx.PredicateExprKind.attr_test
	if n := p.name { assert n == 'active' } else { assert false, 'name should be set' }
}

// ── Atomic template — @name OP value (all 6 ops) ──────────────────────────────

fn test_predicate_expr_parse_attr_compare_eq() {
	p := cx.predicate_expr_parse('@name="alice"') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.kind == cx.PredicateExprKind.attr_compare
	if n := p.name { assert n == 'name' } else { assert false }
	if o := p.op { assert o == '=' } else { assert false }
	if v := p.value { assert v == '"alice"' } else { assert false }
}

fn test_predicate_expr_parse_attr_compare_neq() {
	p := cx.predicate_expr_parse('@status != "deleted"') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.kind == cx.PredicateExprKind.attr_compare
	if o := p.op { assert o == '!=' } else { assert false }
}

fn test_predicate_expr_parse_attr_compare_lt() {
	p := cx.predicate_expr_parse('@age < 18') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.kind == cx.PredicateExprKind.attr_compare
	if o := p.op { assert o == '<' } else { assert false }
	if v := p.value { assert v == '18' } else { assert false }
}

fn test_predicate_expr_parse_attr_compare_le() {
	p := cx.predicate_expr_parse('@age <= 18') or {
		assert false, 'parse failed: ${err}'
		return
	}
	if o := p.op { assert o == '<=' } else { assert false }
}

fn test_predicate_expr_parse_attr_compare_gt() {
	p := cx.predicate_expr_parse('@age > 18') or {
		assert false, 'parse failed: ${err}'
		return
	}
	if o := p.op { assert o == '>' } else { assert false }
}

fn test_predicate_expr_parse_attr_compare_ge() {
	p := cx.predicate_expr_parse('@age >= 18') or {
		assert false, 'parse failed: ${err}'
		return
	}
	if o := p.op { assert o == '>=' } else { assert false }
}

// ── Atomic template — INT (1-based position) ──────────────────────────────────

fn test_predicate_expr_parse_int_position_one() {
	p := cx.predicate_expr_parse('1') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.kind == cx.PredicateExprKind.int_position
	if pos := p.position { assert pos == 1 } else { assert false, 'position should be set' }
}

fn test_predicate_expr_parse_int_position_larger() {
	p := cx.predicate_expr_parse('42') or {
		assert false, 'parse failed: ${err}'
		return
	}
	if pos := p.position { assert pos == 42 } else { assert false }
}

fn test_predicate_expr_parse_int_position_zero_rejected() {
	// Position is 1-based; 0 is not a valid atomic-template position.
	_ := cx.predicate_expr_parse('0') or { return }
	assert false, 'position 0 should error'
}

// ── Atomic template — count(*) [OP N] ─────────────────────────────────────────

fn test_predicate_expr_parse_count_bare() {
	p := cx.predicate_expr_parse('count(*)') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.kind == cx.PredicateExprKind.function_call
	if n := p.name { assert n == 'count' } else { assert false }
	if v := p.value { assert v == '*' } else { assert false }
	assert p.op == none
	assert p.position == none
}

fn test_predicate_expr_parse_count_gt() {
	p := cx.predicate_expr_parse('count(*) > 5') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.kind == cx.PredicateExprKind.function_call
	if n := p.name { assert n == 'count' } else { assert false }
	if v := p.value { assert v == '*' } else { assert false }
	if o := p.op { assert o == '>' } else { assert false }
	if pos := p.position { assert pos == 5 } else { assert false }
}

// ── Atomic template — $_position / $_last ─────────────────────────────────────

fn test_predicate_expr_parse_dollar_underscore_position() {
	p := cx.predicate_expr_parse('\$_position') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.kind == cx.PredicateExprKind.reserved_binding
	if n := p.name { assert n == '\$_position' } else { assert false }
}

fn test_predicate_expr_parse_dollar_underscore_last() {
	p := cx.predicate_expr_parse('\$_last') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.kind == cx.PredicateExprKind.reserved_binding
	if n := p.name { assert n == '\$_last' } else { assert false }
}

// ── Atomic template — $_@name (explicit-$_ form) ──────────────────────────────

fn test_predicate_expr_parse_dollar_underscore_attr_test() {
	p := cx.predicate_expr_parse('\$_@active') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.kind == cx.PredicateExprKind.attr_test
	if n := p.name { assert n == 'active' } else { assert false }
}

fn test_predicate_expr_parse_dollar_underscore_attr_compare() {
	p := cx.predicate_expr_parse('\$_@age >= 18') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.kind == cx.PredicateExprKind.attr_compare
	if n := p.name { assert n == 'age' } else { assert false }
	if o := p.op { assert o == '>=' } else { assert false }
	if v := p.value { assert v == '18' } else { assert false }
}

// ── Complex bodies fail gracefully ────────────────────────────────────────────

fn test_predicate_expr_parse_and_keyword_rejected() {
	// `and` connective is outside Phase 2.19 atomic-template scope —
	// must error so path_parser falls back to source-only.
	_ := cx.predicate_expr_parse('@active and @verified') or { return }
	assert false, 'boolean `and` body should error at Phase 2.19'
}

fn test_predicate_expr_parse_or_keyword_rejected() {
	_ := cx.predicate_expr_parse('@a or @b') or { return }
	assert false, 'boolean `or` body should error at Phase 2.19'
}

fn test_predicate_expr_parse_unknown_function_rejected() {
	_ := cx.predicate_expr_parse('lower-case(@name)') or { return }
	assert false, 'arbitrary function call should error at Phase 2.19'
}

fn test_predicate_expr_parse_empty_body_rejected() {
	_ := cx.predicate_expr_parse('') or { return }
	assert false, 'empty body should error'
}

fn test_predicate_expr_parse_garbage_rejected() {
	_ := cx.predicate_expr_parse('@@@') or { return }
	assert false, 'garbage body should error'
}

// ── Round-trip via parse_path: PathPredicate carries both source + expr ───────

fn test_parse_path_predicate_carries_structural_expr() {
	p := cx.parse_path('//user[@active]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps.len == 1
	assert p.steps[0].predicates.len == 1
	pred := p.steps[0].predicates[0]
	// Source is preserved verbatim.
	assert pred.source == '@active'
	// Expr is promoted to a structural attr_test.
	if expr := pred.expr {
		assert expr.kind == cx.PredicateExprKind.attr_test
		if n := expr.name { assert n == 'active' } else { assert false, 'expr.name should be set' }
	} else {
		assert false, 'expr should have been promoted to structural AST'
	}
}

fn test_parse_path_predicate_attr_compare_round_trip() {
	p := cx.parse_path('//user[@name="alice"]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	pred := p.steps[0].predicates[0]
	assert pred.source == '@name="alice"'
	if expr := pred.expr {
		assert expr.kind == cx.PredicateExprKind.attr_compare
		if n := expr.name { assert n == 'name' } else { assert false }
		if o := expr.op { assert o == '=' } else { assert false }
		if v := expr.value { assert v == '"alice"' } else { assert false }
	} else {
		assert false, 'expr should have been promoted'
	}
}

fn test_parse_path_predicate_int_position_round_trip() {
	p := cx.parse_path('//user[3]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	pred := p.steps[0].predicates[0]
	assert pred.source == '3'
	if expr := pred.expr {
		assert expr.kind == cx.PredicateExprKind.int_position
		if pos := expr.position { assert pos == 3 } else { assert false }
	} else {
		assert false, 'expr should have been promoted'
	}
}

fn test_parse_path_predicate_count_round_trip() {
	p := cx.parse_path('//user[count(*) > 5]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	pred := p.steps[0].predicates[0]
	assert pred.source == 'count(*) > 5'
	if expr := pred.expr {
		assert expr.kind == cx.PredicateExprKind.function_call
		if n := expr.name { assert n == 'count' } else { assert false }
		if o := expr.op { assert o == '>' } else { assert false }
		if pos := expr.position { assert pos == 5 } else { assert false }
	} else {
		assert false, 'expr should have been promoted'
	}
}

// ── Round-trip via parse_path: complex body → source-only fallback ────────────

fn test_parse_path_predicate_complex_falls_back_to_source_only() {
	// `and` connective is outside the Phase 2.19 atomic-template
	// scope — the parser MUST still produce a valid PathNode with
	// PathPredicate.source populated and .expr = none.
	p := cx.parse_path('//user[@active and @verified]') or {
		assert false, 'parse failed (should fall back gracefully): ${err}'
		return
	}
	assert p.steps.len == 1
	assert p.steps[0].predicates.len == 1
	pred := p.steps[0].predicates[0]
	assert pred.source == '@active and @verified'
	assert pred.expr == none, 'expr should be none for complex body'
}

// ── Equality interplay with PathPredicate ─────────────────────────────────────

fn test_path_predicate_eq_via_expr_ignores_source_formatting() {
	// Two paths with surface-formatting differences should compare
	// equal at the AST level when both predicates promote to the
	// same PredicateExpr structurally.
	p1 := cx.parse_path('//user[@active=true]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	p2 := cx.parse_path('//user[@active = true]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p1.eq(p2), 'whitespace-differing predicates should compare equal via expr'
}

fn test_path_predicate_eq_falls_back_to_source_when_no_expr() {
	// Hand-construct two source-only PathPredicates (no expr). Source
	// match → equal; source diverge → unequal.
	a := cx.PathNode{
		form: cx.PathForm.descendant
		steps: [cx.PathStep{
			axis: cx.PathAxis.child
			node_test: 'user'
			predicates: [cx.PathPredicate{ source: 'foo and bar' }]
		}]
	}
	b := cx.PathNode{
		form: cx.PathForm.descendant
		steps: [cx.PathStep{
			axis: cx.PathAxis.child
			node_test: 'user'
			predicates: [cx.PathPredicate{ source: 'foo and bar' }]
		}]
	}
	assert a.eq(b)
	c := cx.PathNode{
		form: cx.PathForm.descendant
		steps: [cx.PathStep{
			axis: cx.PathAxis.child
			node_test: 'user'
			predicates: [cx.PathPredicate{ source: 'foo or baz' }]
		}]
	}
	assert !a.eq(c)
}
