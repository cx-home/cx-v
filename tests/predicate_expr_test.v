module main

import cx

// Tests for the PredicateExpr AST + path_parser integration (post-#110
// CXPath-predicate cutover).
//
// Coverage:
//   - PredicateExpr construction + .eq() (incl. advisory source/loc exclusion)
//   - Disjoint-domain canonical-bytes prefix + SHA-256 hash
//   - Canonical templates parse to expected shape:
//       @name                → attr_test
//       OP $_@name value     → attr_compare (all 6 prefix ops)
//       N (1-based int)      → int_position
//       = $_position N       → int_position
//       and/or/not [..] [..] → bool_expr (children)
//       $_position/$_last    → reserved_binding
//       $_@name              → attr_test (explicit-$_ form)
//   - RETIRED surface (#110) is a HARD parse error whose message contains
//     'retired': infix attribute comparison `@a=v` (all 6 ops), paren-calls
//     `count(*)` / `last()` / `name(args)`, infix `and`/`or`.
//   - Non-template general bodies (e.g. fused head-dispatch `$fn $_`) error
//     with PREDICATE_EXPR_PARSE; path_parser falls back to source-only
//     PathPredicate (the program engine owns their structure).
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

// ── Canonical template — OP $_@name value (all 6 prefix ops) ──────────────────

fn test_predicate_expr_parse_prefix_compare_eq() {
	p := cx.predicate_expr_parse('= \$_@name "alice"') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.kind == cx.PredicateExprKind.attr_compare
	if n := p.name { assert n == 'name' } else { assert false }
	if o := p.op { assert o == '=' } else { assert false }
	if v := p.value { assert v == '"alice"' } else { assert false }
}

fn test_predicate_expr_parse_prefix_compare_neq() {
	p := cx.predicate_expr_parse('!= \$_@status "deleted"') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.kind == cx.PredicateExprKind.attr_compare
	if o := p.op { assert o == '!=' } else { assert false }
}

fn test_predicate_expr_parse_prefix_compare_lt() {
	p := cx.predicate_expr_parse('< \$_@age 18') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.kind == cx.PredicateExprKind.attr_compare
	if n := p.name { assert n == 'age' } else { assert false }
	if o := p.op { assert o == '<' } else { assert false }
	if v := p.value { assert v == '18' } else { assert false }
}

fn test_predicate_expr_parse_prefix_compare_le() {
	p := cx.predicate_expr_parse('<= \$_@age 18') or {
		assert false, 'parse failed: ${err}'
		return
	}
	if o := p.op { assert o == '<=' } else { assert false }
}

fn test_predicate_expr_parse_prefix_compare_gt() {
	p := cx.predicate_expr_parse('> \$_@age 18') or {
		assert false, 'parse failed: ${err}'
		return
	}
	if o := p.op { assert o == '>' } else { assert false }
}

fn test_predicate_expr_parse_prefix_compare_ge() {
	p := cx.predicate_expr_parse('>= \$_@age 18') or {
		assert false, 'parse failed: ${err}'
		return
	}
	if o := p.op { assert o == '>=' } else { assert false }
}

// ── Canonical template — = $_position N ───────────────────────────────────────

fn test_predicate_expr_parse_prefix_positional() {
	p := cx.predicate_expr_parse('= \$_position 3') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.kind == cx.PredicateExprKind.int_position
	if pos := p.position { assert pos == 3 } else { assert false, 'position should be set' }
}

fn test_predicate_expr_parse_prefix_positional_zero_rejected() {
	_ := cx.predicate_expr_parse('= \$_position 0') or { return }
	assert false, 'position 0 should error'
}

// ── Canonical template — and/or/not prefix connectives ────────────────────────

fn test_predicate_expr_parse_prefix_and() {
	p := cx.predicate_expr_parse('and [@active] [@verified]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.kind == cx.PredicateExprKind.bool_expr
	if o := p.op { assert o == 'and' } else { assert false }
	assert p.children.len == 2
	assert p.children[0].kind == cx.PredicateExprKind.attr_test
	assert p.children[1].kind == cx.PredicateExprKind.attr_test
}

fn test_predicate_expr_parse_prefix_or_with_compares() {
	p := cx.predicate_expr_parse('or [= \$_@a 1] [> \$_@b 2]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.kind == cx.PredicateExprKind.bool_expr
	if o := p.op { assert o == 'or' } else { assert false }
	assert p.children.len == 2
	assert p.children[0].kind == cx.PredicateExprKind.attr_compare
	if o0 := p.children[0].op { assert o0 == '=' } else { assert false }
	assert p.children[1].kind == cx.PredicateExprKind.attr_compare
	if o1 := p.children[1].op { assert o1 == '>' } else { assert false }
}

fn test_predicate_expr_parse_prefix_not() {
	p := cx.predicate_expr_parse('not [@deleted]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.kind == cx.PredicateExprKind.bool_expr
	if o := p.op { assert o == 'not' } else { assert false }
	assert p.children.len == 1
	assert p.children[0].kind == cx.PredicateExprKind.attr_test
}

fn test_predicate_expr_parse_prefix_not_arity_rejected() {
	_ := cx.predicate_expr_parse('not [@a] [@b]') or { return }
	assert false, '`not` with two operands should error'
}

fn test_predicate_expr_parse_prefix_nested_connectives() {
	p := cx.predicate_expr_parse('and [or [@a] [@b]] [not [@c]]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.kind == cx.PredicateExprKind.bool_expr
	assert p.children.len == 2
	assert p.children[0].kind == cx.PredicateExprKind.bool_expr
	if o0 := p.children[0].op { assert o0 == 'or' } else { assert false }
	assert p.children[1].kind == cx.PredicateExprKind.bool_expr
	if o1 := p.children[1].op { assert o1 == 'not' } else { assert false }
}

// ── RETIRED surface — infix attribute comparison (all 6 ops) ──────────────────

fn assert_retired_predicate_body(body string) {
	_ := cx.predicate_expr_parse(body) or {
		assert err.msg().starts_with('RETIRED_PREDICATE_SURFACE:'), 'expected RETIRED_PREDICATE_SURFACE prefix, got: ${err.msg()}'
		assert err.msg().contains('retired'), 'expected retired-surface message, got: ${err.msg()}'
		return
	}
	assert false, 'retired body `${body}` should be a hard parse error'
}

fn test_predicate_expr_parse_infix_attr_compare_eq_retired() {
	assert_retired_predicate_body('@name="alice"')
}

fn test_predicate_expr_parse_infix_attr_compare_neq_retired() {
	assert_retired_predicate_body('@status != "deleted"')
}

fn test_predicate_expr_parse_infix_attr_compare_lt_retired() {
	assert_retired_predicate_body('@age < 18')
}

fn test_predicate_expr_parse_infix_attr_compare_le_retired() {
	assert_retired_predicate_body('@age <= 18')
}

fn test_predicate_expr_parse_infix_attr_compare_gt_retired() {
	assert_retired_predicate_body('@age > 18')
}

fn test_predicate_expr_parse_infix_attr_compare_ge_retired() {
	assert_retired_predicate_body('@age >= 18')
}

fn test_predicate_expr_parse_infix_dollar_underscore_attr_compare_retired() {
	// The explicit-$_ INFIX spelling is retired too — only the prefix
	// operator form `>= $_@age 18` is canonical.
	assert_retired_predicate_body('\$_@age >= 18')
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

// ── RETIRED surface — paren-calls (count(*), last(), arbitrary fn(args)) ──────

fn test_predicate_expr_parse_count_bare_retired() {
	assert_retired_predicate_body('count(*)')
}

fn test_predicate_expr_parse_count_gt_retired() {
	assert_retired_predicate_body('count(*) > 5')
}

fn test_predicate_expr_parse_last_paren_retired() {
	assert_retired_predicate_body('last()')
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

// ── RETIRED surface — infix and/or connectives ────────────────────────────────

fn test_predicate_expr_parse_infix_and_retired() {
	// Infix `and` between operands is retired — only the prefix form
	// `and [P] [Q]` is canonical.
	assert_retired_predicate_body('@active and @verified')
}

fn test_predicate_expr_parse_infix_or_retired() {
	assert_retired_predicate_body('@a or @b')
}

fn test_predicate_expr_parse_infix_and_between_compares_retired() {
	assert_retired_predicate_body('@a=1 and @b=2')
}

fn test_predicate_expr_parse_unknown_paren_call_retired() {
	assert_retired_predicate_body('lower-case(@name)')
}

// ── Non-template general bodies error PREDICATE_EXPR_PARSE (fallback path) ────

fn test_predicate_expr_parse_fused_call_body_falls_out_of_templates() {
	// `$myfn $_` is a valid FUSED predicate at the program surface, but it
	// is not an atomic template — predicate_expr_parse must error with a
	// PREDICATE_EXPR_PARSE (not RETIRED) message so the caller keeps the
	// source-only fallback.
	_ := cx.predicate_expr_parse('\$myfn \$_') or {
		assert err.msg().starts_with('PREDICATE_EXPR_PARSE'), 'expected PREDICATE_EXPR_PARSE fallback error, got: ${err.msg()}'
		return
	}
	assert false, 'fused-call body should be outside the atomic templates'
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
	p := cx.parse_path('//user[= \$_@name "alice"]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	pred := p.steps[0].predicates[0]
	assert pred.source == '= \$_@name "alice"'
	if expr := pred.expr {
		assert expr.kind == cx.PredicateExprKind.attr_compare
		if n := expr.name { assert n == 'name' } else { assert false }
		if o := expr.op { assert o == '=' } else { assert false }
		if v := expr.value { assert v == '"alice"' } else { assert false }
	} else {
		assert false, 'expr should have been promoted'
	}
}

fn test_parse_path_infix_attr_compare_retired() {
	_ := cx.parse_path('//user[@name="alice"]') or {
		assert err.msg().starts_with('CXPATH_PARSE:'), 'expected CXPATH_PARSE error, got: ${err.msg()}'
		assert err.msg().contains('retired'), 'expected retired-surface message, got: ${err.msg()}'
		return
	}
	assert false, 'infix attribute comparison should be a hard parse error via parse_path'
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

fn test_parse_path_predicate_count_paren_retired() {
	_ := cx.parse_path('//user[count(*) > 5]') or {
		assert err.msg().starts_with('CXPATH_PARSE:'), 'expected CXPATH_PARSE error, got: ${err.msg()}'
		assert err.msg().contains('retired'), 'expected retired-surface message, got: ${err.msg()}'
		return
	}
	assert false, 'paren-call count(*) should be a hard parse error via parse_path'
}

fn test_parse_path_predicate_prefix_connective_round_trip() {
	p := cx.parse_path('//user[and [@active] [@verified]]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	pred := p.steps[0].predicates[0]
	assert pred.source == 'and [@active] [@verified]'
	if expr := pred.expr {
		assert expr.kind == cx.PredicateExprKind.bool_expr
		if o := expr.op { assert o == 'and' } else { assert false }
		assert expr.children.len == 2
	} else {
		assert false, 'expr should have been promoted'
	}
}

// ── Round-trip via parse_path: retired infix + general-body fallback ──────────

fn test_parse_path_predicate_infix_and_retired() {
	// Infix `and` between operands is retired — a HARD parse error, never
	// a source-only fallback.
	_ := cx.parse_path('//user[@active and @verified]') or {
		assert err.msg().starts_with('CXPATH_PARSE:'), 'expected CXPATH_PARSE error, got: ${err.msg()}'
		assert err.msg().contains('retired'), 'expected retired-surface message, got: ${err.msg()}'
		return
	}
	assert false, 'infix `and` should be a hard parse error via parse_path'
}

fn test_parse_path_predicate_general_body_falls_back_to_source_only() {
	// `= $_position $_last` (the canonical replacement for last()) exceeds
	// the atomic templates — the parser MUST still produce a valid PathNode
	// with PathPredicate.source populated and .expr = none (the program
	// engine owns its structure).
	p := cx.parse_path('//user[= \$_position \$_last]') or {
		assert false, 'parse failed (should fall back gracefully): ${err}'
		return
	}
	assert p.steps.len == 1
	assert p.steps[0].predicates.len == 1
	pred := p.steps[0].predicates[0]
	assert pred.source == '= \$_position \$_last'
	assert pred.expr == none, 'expr should be none for a general body'
}

fn test_parse_path_predicate_fused_call_falls_back_to_source_only() {
	// A fused call predicate `[$myfn $_]` is valid surface; the path parser
	// keeps it source-only.
	p := cx.parse_path('//user[\$myfn \$_]') or {
		assert false, 'parse failed (should fall back gracefully): ${err}'
		return
	}
	pred := p.steps[0].predicates[0]
	assert pred.source == '\$myfn \$_'
	assert pred.expr == none, 'expr should be none for a fused call body'
}

// ── Equality interplay with PathPredicate ─────────────────────────────────────

fn test_path_predicate_eq_via_expr_ignores_source_formatting() {
	// Two paths with surface-formatting differences should compare
	// equal at the AST level when both predicates promote to the
	// same PredicateExpr structurally.
	p1 := cx.parse_path('//user[= \$_@active true]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	p2 := cx.parse_path('//user[=  \$_@active   true]') or {
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
