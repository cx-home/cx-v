module main
import cx

import code

// ── program parser conformance tests ─────────────────────────────────────────────
//
// Covers every variant of cx.ProgramNode and every branch of
// vcx/code/parser.v. Spec refs: spec/code.md §§4–8, grammar.ebnf
// [120]–[129], ast.md §"program AST".

// ── Helpers ─────────────────────────────────────────────────────────────────

fn parse(src string) cx.Program {
	return cx.parse_program(src) or { panic(err) }
}

fn parse_err(src string) {
	cx.parse_program(src) or {
		assert err is cx.ParseError || err is cx.LexError
		return
	}
	assert false, 'expected parse error for: ${src}'
}

// ── Literals ────────────────────────────────────────────────────────────────

fn test_int_literal() {
	p := parse('42')
	body := p.body
	if body is cx.ProgramLiteral {
		assert body.kind == .int_lit
		assert body.int_val == 42
	} else {
		assert false, 'expected ProgramLiteral, got something else'
	}
}

fn test_float_literal() {
	p := parse('3.14')
	body := p.body
	if body is cx.ProgramLiteral {
		assert body.kind == .float_lit
		assert body.flt_val > 3.13 && body.flt_val < 3.15
	} else {
		assert false
	}
}

fn test_bool_literal() {
	p := parse('true')
	body := p.body
	if body is cx.ProgramLiteral {
		assert body.kind == .bool_lit && body.bool_val == true
	} else { assert false }
}

fn test_string_literal() {
	p := parse("'hello'")
	body := p.body
	if body is cx.ProgramLiteral {
		assert body.kind == .string_lit && body.str_val == 'hello'
	} else { assert false }
}

fn test_duration_literal() {
	p := parse('100ms')
	body := p.body
	if body is cx.ProgramLiteral {
		assert body.kind == .duration_lit && body.dur_val == '100ms'
	} else { assert false }
}

fn test_sequence_literal() {
	p := parse('(1, 2, 3)')
	body := p.body
	if body is cx.ProgramLiteral {
		assert body.kind == .sequence_lit
		assert body.items.len == 3
	} else { assert false }
}

fn test_empty_sequence() {
	p := parse('()')
	body := p.body
	if body is cx.ProgramLiteral {
		assert body.kind == .sequence_lit && body.items.len == 0
	} else { assert false }
}

fn test_array_literal() {
	p := parse('[1, 2, 3]')
	body := p.body
	if body is cx.ProgramLiteral {
		assert body.kind == .array_lit && body.items.len == 3
	} else { assert false }
}

fn test_empty_array() {
	p := parse('[]')
	body := p.body
	if body is cx.ProgramLiteral {
		assert body.kind == .array_lit && body.items.len == 0
	} else { assert false }
}

fn test_array_trailing_comma() {
	p := parse('[1, 2,]')
	body := p.body
	if body is cx.ProgramLiteral {
		assert body.kind == .array_lit && body.items.len == 2
	} else { assert false }
}

fn test_map_literal() {
	p := parse("{a: 1, 'b': 2, c: 3}")
	body := p.body
	if body is cx.ProgramLiteral {
		assert body.kind == .map_lit
		assert body.keys == ['a', 'b', 'c']
		assert body.items.len == 3
	} else { assert false }
}

fn test_cx_element_literal() {
	// CX elements at expression position; bodies are CX code expressions.
	// Bare-text body content (e.g., 'a@x.com' as raw value) requires
	// the CX-data tokenizer rather than the CX code expression tokenizer;
	// CX code MUST quote string values inside embedded elements.
	p := parse("[user [name 'Alice'] [email 'a@x.com']]")
	body := p.body
	if body is cx.ProgramLiteral {
		assert body.kind == .cx_element
		assert body.name == 'user'
		assert body.items.len == 2
	} else { assert false }
}

// ── Bindings + paths ────────────────────────────────────────────────────────

fn test_bare_binding() {
	p := parse('$x')
	body := p.body
	if body is cx.ProgramBinding {
		assert body.name == 'x' && body.path.len == 0
	} else { assert false }
}

fn test_binding_with_child_path() {
	p := parse('$u/name')
	body := p.body
	if body is cx.ProgramBinding {
		assert body.name == 'u' && body.path.len == 1
		assert body.path[0].kind == .child && body.path[0].name == 'name'
	} else { assert false }
}

fn test_binding_with_mixed_path() {
	p := parse('$u/profile@email.host')
	body := p.body
	if body is cx.ProgramBinding {
		assert body.name == 'u' && body.path.len == 3
		assert body.path[0].kind == .child && body.path[0].name == 'profile'
		assert body.path[1].kind == .attr && body.path[1].name == 'email'
		assert body.path[2].kind == .member && body.path[2].name == 'host'
	} else { assert false }
}

// ── Calls ───────────────────────────────────────────────────────────────────
//
// Head-dispatch `[$name arg …]` is the ONLY call surface (code.md §6.3);
// the paren-call form `name(args)` is RETIRED (#110) — a hard parse error.

fn test_bare_ident_is_zero_arity_call() {
	p := parse('count')
	body := p.body
	if body is cx.ProgramCall {
		assert body.name == 'count' && body.args.len == 0
		assert !body.fallible && !body.must_succeed
	} else { assert false }
}

fn test_call_with_args() {
	p := parse('[\$upper name true]')
	body := p.body
	if body is cx.ProgramCall {
		assert body.name == 'upper' && body.args.len == 2
		assert body.explicit_call
	} else { assert false }
}

fn test_call_labeled_arg() {
	p := parse('[\$fetch url="http://x" retries=3]')
	body := p.body
	if body is cx.ProgramCall {
		assert body.name == 'fetch' && body.args.len == 2
		assert body.arg_labels == ['url', 'retries']
	} else { assert false }
}

fn test_call_fallible_postfix() {
	p := parse('[\$parse x]?')
	body := p.body
	if body is cx.ProgramCall {
		assert body.fallible && !body.must_succeed
	} else { assert false }
}

fn test_call_panic_postfix() {
	p := parse('[\$parse x]!')
	body := p.body
	if body is cx.ProgramCall {
		assert body.must_succeed && !body.fallible
	} else { assert false }
}

fn test_paren_call_is_retired() {
	cx.parse_program('upper(name, true)') or {
		assert err.msg().contains('retired'), 'expected retired paren-call error, got: ${err.msg()}'
		return
	}
	assert false, 'paren-call `name(args)` must no longer parse'
}

fn test_dollar_paren_call_is_retired() {
	cx.parse_program('\$f(x)') or {
		assert err.msg().contains('retired'), 'expected retired paren-call error, got: ${err.msg()}'
		return
	}
	assert false, 'paren-call `\$f(x)` must no longer parse'
}

// ── Set operators as expression heads (union / intersect / except) ──────────

fn test_union_in_expression_position_parses() {
	p := parse('[union (1, 2) (2, 3)]')
	body := p.body
	if body is cx.ProgramLiteral {
		assert body.kind == .cx_element
		assert body.name == 'union'
		assert body.items.len == 2
	} else { assert false, 'expected cx_element operator form for [union …]' }
}

fn test_union_evaluates_with_dedup_first_occurrence_order() {
	got := code.eval_code('[doc]', '[union (1, 2) (2, 3)]', 'text') or {
		assert false, 'union eval failed: ${err}'
		return
	}
	assert got == '(1, 2, 3)', 'union: expected (1, 2, 3), got ${got}'
}

fn test_intersect_in_expression_position_evaluates() {
	got := code.eval_code('[doc]', '[intersect (1, 2, 3) (2, 3, 4)]', 'text') or {
		assert false, 'intersect eval failed: ${err}'
		return
	}
	assert got == '(2, 3)', 'intersect: expected (2, 3), got ${got}'
}

fn test_except_in_expression_position_evaluates() {
	got := code.eval_code('[doc]', '[except (1, 2, 3) (2)]', 'text') or {
		assert false, 'except eval failed: ${err}'
		return
	}
	assert got == '(1, 3)', 'except: expected (1, 3), got ${got}'
}

// ── Binding-path predicates (canonical post-#110 surface) ────────────────────

fn test_binding_path_fused_call_predicate_parses() {
	// `[$myfn $_]` — call-fused predicate body: the predicate's own
	// brackets are the call form's brackets.
	p := parse('\$u/item[\$myfn \$_]')
	body := p.body
	if body is cx.ProgramBinding {
		assert body.name == 'u'
		assert body.path.len == 1
		assert body.path[0].predicates.len == 1
	} else { assert false, 'expected ProgramBinding with predicated step' }
}

fn test_binding_path_directive_fused_predicate_parses() {
	// `[?match $_ …]` — directive-fused predicate body.
	p := parse('\$u/item[?match \$_ [case [x] true] [else false]]')
	body := p.body
	if body is cx.ProgramBinding {
		assert body.path.len == 1
		assert body.path[0].predicates.len == 1
	} else { assert false, 'expected ProgramBinding with predicated step' }
}

fn test_binding_path_infix_predicate_is_retired() {
	cx.parse_program('\$u/item[@id=1]') or {
		assert err.msg().contains('retired'), 'expected retired infix-predicate error, got: ${err.msg()}'
		return
	}
	assert false, 'infix `[@id=1]` binding-path predicate must no longer parse'
}

fn test_binding_path_bare_attr_operand_in_form_is_retired() {
	// A bare `@name` OPERAND inside a form body is retired — the error
	// must suggest the explicit `$_@name` context path.
	cx.parse_program('\$u/item[= @id 1]') or {
		assert err.msg().contains('retired'), 'expected retired bare-@ operand error, got: ${err.msg()}'
		assert err.msg().contains('\$_@'), 'error should suggest \$_@name, got: ${err.msg()}'
		return
	}
	assert false, 'bare `@name` operand must no longer parse'
}

// ── Patterns ────────────────────────────────────────────────────────────────

fn test_pattern_inside_find_named_head() {
	p := parse('[?for [user [email $e]] [yield $e]]')
	body := p.body
	if body is cx.ProgramForComp {
		assert body.clauses.len >= 1
		first := body.clauses[0]
		assert first.kind == .generator
		if src := first.source {
			if src is cx.ProgramPattern {
				assert src.head.kind == .named
				assert src.head.value == 'user'
			} else { assert false }
		} else { assert false }
	} else { assert false }
}

fn test_pattern_with_attribute_predicate() {
	p := parse('[?for [user @active=true [name $n]] [yield $n]]')
	body := p.body
	if body is cx.ProgramForComp {
		first := body.clauses[0]
		if src := first.source {
			if src is cx.ProgramPattern {
				assert src.attrs.len == 1
				assert src.attrs[0].kind == .equality
				assert src.attrs[0].name == 'active'
			} else { assert false }
		} else { assert false }
	} else { assert false }
}

fn test_pattern_with_existence_and_absence() {
	p := parse('[?for [user @verified @!banned] [yield $u]]')
	body := p.body
	if body is cx.ProgramForComp {
		first := body.clauses[0]
		if src := first.source {
			if src is cx.ProgramPattern {
				assert src.attrs.len == 2
				assert src.attrs[0].kind == .existence
				assert src.attrs[1].kind == .absence
			} else { assert false }
		} else { assert false }
	} else { assert false }
}

fn test_pattern_wildcards() {
	p := parse('[?for [* [section **$s]] [yield $s]]')
	body := p.body
	if body is cx.ProgramForComp {
		first := body.clauses[0]
		if src := first.source {
			if src is cx.ProgramPattern {
				assert src.head.kind == .wildcard
			} else { assert false }
		} else { assert false }
	} else { assert false }
}

fn test_pattern_type_guard() {
	p := parse('[?for [:User $u] [yield $u]]')
	body := p.body
	if body is cx.ProgramForComp {
		first := body.clauses[0]
		if src := first.source {
			if src is cx.ProgramPattern {
				assert src.head.kind == .type_guard
				assert src.head.value == 'User'
				assert src.head.bind == 'u'
			} else { assert false }
		} else { assert false }
	} else { assert false }
}

fn test_pattern_direct_adjacency() {
	p := parse('[?for [* direct=true [h2 $h] [p $p]] [yield $p]]')
	body := p.body
	if body is cx.ProgramForComp {
		first := body.clauses[0]
		if src := first.source {
			if src is cx.ProgramPattern {
				assert src.direct == true
			} else { assert false }
		} else { assert false }
	} else { assert false }
}

// ── Directives ──────────────────────────────────────────────────────────────

fn test_directive_unknown_name_errors() {
	parse_err('[?not-a-real-directive 1]')
}

fn test_directive_with_only_labeled_slots() {
	p := parse('[?retry max=3 delay=100ms body=[\$fetch]]')
	body := p.body
	if body is cx.ProgramDirective {
		assert body.name == 'retry'
		assert body.slots.len == 3
		for slot in body.slots {
			assert slot.kind == .labeled
		}
		assert body.slots[0].label == 'max'
		assert body.slots[1].label == 'delay'
		assert body.slots[2].label == 'body'
	} else { assert false }
}

fn test_directive_with_positional_slot() {
	p := parse('[?timeout 100ms body=[\$work]]')
	body := p.body
	if body is cx.ProgramDirective {
		assert body.name == 'timeout'
		assert body.slots.len == 2
		assert body.slots[0].kind == .positional
		assert body.slots[1].kind == .labeled
		assert body.slots[1].label == 'body'
	} else { assert false }
}

fn test_every_directive_parses_with_empty_body() {
	for name in cx.directive_names {
		// Special-forms with required body grammar/0029/0030
		// and §8.x: [?for] / [?for-array] / [?for-map] need :yield
		// [?let] needs binding + :in; [?modify] needs
		// DOC + FOCUS + Action+ slots; [?with-open] needs at least one
		// (expr) $binding opener; [?str] needs a string-literal argument
		// (§6.5). Skip those.
		if name == 'for' || name == 'for-array' || name == 'for-map'
		   || name == 'let' || name == 'modify' || name == 'with-open'
		   || name == 'with-scope' || name == 'match' || name == 'str'
		   || name == 'with-caps'
		   || name == 'element' || name == 'attr' || name == 'entry'
		   || name == 'name' || name == 'quote' || name == 'unquote'
		   || name == 'splice' || name == 'eval'
		   // [?do] needs ≥1 effect expression (grammar [127aa] `+`) and
		   // [?loop] a body (grammar [127ab]) — empty is a parse error by
		   // design, same as [?with-caps]/[?let] (spec/code.md §8.14/§8.15).
		   || name == 'do' || name == 'loop' {
			// [?with-caps] requires at least one [deny CAP] clause
			// (grammar [167]); an empty body is a parse error by design.
			// The dynamic-construction directives (spec/code.md §6.4.2-§6.4.4)
			// all require an operand: [?element NAME-EXPR …], [?attr NAME-EXPR
			// VAL], [?entry KEY-EXPR VAL], [?name NAME-EXPR], [?quote FORM],
			// [?unquote EXPR], [?splice EXPR], [?eval TREE …] — an empty body
			// is CXER0100 by design.
			continue
		}
		src := '[?${name}]'
		cx.parse_program(src) or {
			panic('directive ${name} failed: ${err}')
		}
	}
}

// ── For-comprehension ───────────────────────────────────────────────────────

fn test_for_basic_generator_yield() {
	p := parse('[?for [in $u users] [yield $u]]')
	body := p.body
	if body is cx.ProgramForComp {
		assert body.clauses.len == 1
		assert body.clauses[0].kind == .generator
		assert body.clauses[0].bind == 'u'
	} else { assert false }
}

fn test_for_where_filter() {
	p := parse('[?for [in $u users] [where $u/active] [yield $u]]')
	body := p.body
	if body is cx.ProgramForComp {
		assert body.clauses.len == 2
		assert body.clauses[0].kind == .generator
		assert body.clauses[1].kind == .filter
	} else { assert false }
}

fn test_for_let_binding() {
	p := parse('[?for [in $u users] [= $n $u/name] [yield $n]]')
	body := p.body
	if body is cx.ProgramForComp {
		assert body.clauses.len == 2
		assert body.clauses[1].kind == .binding
		assert body.clauses[1].bind == 'n'
	} else { assert false }
}

fn test_for_order_by_with_direction() {
	p := parse('[?for [in $u users] [order-by $u/age desc] [yield $u]]')
	body := p.body
	if body is cx.ProgramForComp {
		mut found := false
		for c in body.clauses {
			if c.kind == .order_by {
				assert c.direction == 'desc'
				found = true
			}
		}
		assert found
	} else { assert false }
}

fn test_for_group_by() {
	p := parse('[?for [in $u users] [group-by $u/dept] [yield $u]]')
	body := p.body
	if body is cx.ProgramForComp {
		mut found := false
		for c in body.clauses {
			if c.kind == .group_by { found = true }
		}
		assert found
	} else { assert false }
}

fn test_for_on_error_is_retired() {
	// RETIRED (SAP C3c, §9.3): the [on-error] for-clause is a tombstone
	// parse error — per-iteration recovery is a yield-body [?match].
	cx.parse_program('[?for [in \$u users] [on-error \$err skip(\$err)] [yield \$u]]') or {
		assert err.msg().contains('[on-error] is retired')
		return
	}
	assert false, '[on-error] for-clause must no longer parse'
}

fn test_where_infix_comparison_hints_prefix_form() {
	// #18: a bare infix comparison in [where] (`[where $u/@a=true]`) is a
	// common mis-reach — CX predicates are PREFIX. The error must point at the
	// prefix form, not give the low-context "expected ']'".
	cx.parse_program('[?for [in \$u users] [where \$u/@active=true] [yield \$u]]') or {
		assert err.msg().contains('PREFIX predicate'), 'expected the prefix-form hint, got: ${err.msg()}'
		return
	}
	assert false, 'infix `=` in [where] must be a parse error with the prefix-form hint'
}

fn test_for_missing_yield_errors() {
	parse_err('[?for [in $u users]]')
}

// ── Pipe ────────────────────────────────────────────────────────────────────
//
// removed the infix `|` pipe surface. Pipes are now written
// exclusively as the prefix `[?pipe SRC STAGE …]` directive with bare
// stages (§8.9); there is no infix `|` and no `[through]` wrapper.

fn test_pipe_explicit_directive_parses() {
	// Canonical bare-stage form: `[?pipe SRC stage]`.
	p := parse('[?pipe users count]')
	body := p.body
	if body is cx.ProgramDirective {
		assert body.name == 'pipe'
		assert body.slots.len == 2
	} else { assert false }
}

fn test_pipe_hole_form_parses() {
	// Hole-form stage `[$f _ ARG]` (§8.9.1): the threaded value fills the
	// `_` hole. Parses as a 2-slot `[?pipe]` (seed + stage).
	p := parse('[?pipe 5 [\$add _ 3]]')
	body := p.body
	if body is cx.ProgramDirective {
		assert body.name == 'pipe'
		assert body.slots.len == 2
	} else { assert false }
}

fn test_infix_pipe_rejected() {
	// The infix `|` arm is gone; `a | b` is now a parse error.
	parse_err('users | count')
}

// ── Select (labeled-case shape) ─────────────────────────────────────────────
//
// `[?select :case [:from CH $msg HANDLER]]` per spec/code.md §10.4.7
// uses a labeled-case body whose leading token is `:label`. The parser
// special-cases `:case` slots so the body parses to a cx-element whose
// single labeled slot carries the case head (`:from CH` / `:timeout DUR`)
// and whose positional items hold `$msg HANDLER` / `HANDLER`.

// Drop 1 — the legacy `[?select :case [:from CH $msg HANDLER]]`
// surface was removed; cases now use the split-clause form
// `[?select [case [from CH $msg] HANDLER]]` exclusively. Tests for the
// new shape live below at test_select_new_from_case_parses /
// test_select_new_timeout_case_parses.

// ── Select (5.a — split selector + handler) ───────────────────────
//
// `[?select [case [from CH $msg] HANDLER] [case [timeout DUR] HANDLER]]`
// admits the new positional clause-envelope shape. Cases parse as
// positional cx-element slots (name='case', items=[clause_elem, handler]).
// `eval_select` (vcx/code/eval.v `select_case_to_legacy`) normalises the
// shape into the legacy ProgramLiteral so the downstream walk is shared.

fn test_select_new_from_case_parses() {
	p := parse('[?select [case [from \$a \$msg] [picked ch="a" value=\$msg]]]')
	body := p.body as cx.ProgramDirective
	assert body.name == 'select'
	assert body.slots.len == 1
	assert body.slots[0].kind == .positional
	case_val := body.slots[0].value as cx.ProgramLiteral
	assert case_val.kind == .cx_element
	assert case_val.name == 'case'
	// items: [from-clause, handler]
	assert case_val.items.len == 2
	clause := case_val.items[0] as cx.ProgramLiteral
	assert clause.kind == .cx_element
	assert clause.name == 'from'
	// from-clause items: [\$a (channel ref), \$msg (binding name)]
	assert clause.items.len == 2
}

fn test_select_new_timeout_case_parses() {
	p := parse('[?select [case [timeout 50ms] [timeout-fired]]]')
	body := p.body as cx.ProgramDirective
	assert body.slots.len == 1
	assert body.slots[0].kind == .positional
	case_val := body.slots[0].value as cx.ProgramLiteral
	assert case_val.name == 'case'
	clause := case_val.items[0] as cx.ProgramLiteral
	assert clause.name == 'timeout'
	// timeout-clause items: [duration]
	assert clause.items.len == 1
}

// Drop 1 — dual-accept of legacy `[?select :case [:from ...]]`
// + new `[?select [case ...]]` mixed in one directive was removed when
// the legacy `:label V` parser arm was deleted. Only the new clause-child
// form parses now.

// ── For-comp (4.a — pattern-bind generators) ──────────────────────
//
// `[?for [in PATTERN SRC] [yield E]]` admits a pattern as the first item
// of the `[in …]` clause. Pattern destructures each item of SRC; non-
// matching items are skipped. The pattern rides on `c.expr` of the
// .generator clause; bind name '_' (anonymous — no bare-bind slot, the
// pattern provides bindings).

fn test_for_comp_pattern_bind_named_pattern() {
	p := parse('[?for [in [a \$i] \$items] [yield \$i]]')
	body := p.body as cx.ProgramForComp
	assert body.clauses.len == 1
	c := body.clauses[0]
	assert c.kind == .generator
	assert c.bind == '_'
	// Pattern rides on c.expr; source on c.source.
	if pat := c.expr {
		assert pat is cx.ProgramPattern
	} else {
		assert false, 'expected pattern in c.expr'
	}
	if src := c.source {
		assert src is cx.ProgramBinding
	} else {
		assert false, 'expected source in c.source'
	}
}

fn test_for_comp_plain_bind_still_works() {
	p := parse('[?for [in \$x \$items] [yield \$x]]')
	body := p.body as cx.ProgramForComp
	c := body.clauses[0]
	assert c.kind == .generator
	assert c.bind == 'x'
	// No pattern — plain bind.
	if _ := c.expr {
		assert false, 'unexpected pattern on plain-bind generator'
	}
}

fn test_for_comp_bracket_source_still_works() {
	// `[in [1,2,3]]` — the bracket IS the source (array literal),
	// not a pattern. Restore-on-bracket-as-source path must keep
	// this working (no SRC after the bracket → restore + re-parse).
	p := parse('[?for [in [1, 2, 3]] [yield \$_]]')
	body := p.body as cx.ProgramForComp
	c := body.clauses[0]
	assert c.kind == .generator
	assert c.bind == '_'
	if src := c.source {
		assert src is cx.ProgramLiteral
		lit := src as cx.ProgramLiteral
		assert lit.kind == .array_lit
	} else {
		assert false, 'expected array literal source'
	}
}

// ── Composite real-fixture shapes ───────────────────────────────────────────

fn test_retry_with_resilience_shape() {
	p := parse('[?retry max=3 backoff=exponential delay=100ms jitter=equal body=[\$fetch]]')
	body := p.body
	if body is cx.ProgramDirective {
		assert body.name == 'retry'
		assert body.slots.len == 5
	} else { assert false }
}

fn test_nested_directive_composition() {
	p := parse('[?retry max=3 body=[?timeout 1s body=[?circuit-breaker threshold=0.5 window=60s reset=30s body=[\$fetch]]]]')
	body := p.body
	if body is cx.ProgramDirective {
		assert body.name == 'retry'
		body_slot := body.slots[1]
		if body_slot.value is cx.ProgramDirective {
			assert body_slot.value.name == 'timeout'
		} else { assert false }
	} else { assert false }
}

fn test_multi_statement_program() {
	// Per spec/code.md §1, a program may contain multiple top-level
	// expressions; they wrap into an implicit block. The last is
	// the program value; earlier are evaluated for effect (e.g. [?def]).
	p := parse("'hello' 'world'")
	body := p.body
	if body is cx.ProgramLiteral {
		assert body.kind == .block && body.items.len == 2
	} else { assert false }
}

fn test_empty_source_error() {
	parse_err('')
}

// ── core-bug #2 (v0.8.0 stdlib audit): deep-nesting stack-overflow guard ──────
//
// A pathologically deep expression nest (the bus auditor hit it at ~3000
// chained [?let]) used to overflow the host C stack and SEGFAULT the whole
// process — no error, no diagnostic, just death. parse_program now bounds
// recursive-descent depth (max_program_parse_depth) and raises a graceful
// parse error instead. HOSTILE: a happy-path parser test never exercises
// this; only an adversarially deep input does.
fn build_deep_let(depth int) string {
	mut s := '1'
	for i := 0; i < depth; i++ {
		s = '[?let [= \$x${i} ${i}] ${s}]'
	}
	return s
}

fn test_deep_nesting_does_not_segfault() {
	// Far beyond the depth cap: must FAIL gracefully (a catchable
	// ParseError), never crash. Before the guard this segfaulted.
	parse_err(build_deep_let(3000))
}

fn test_moderate_nesting_still_parses() {
	// A nest comfortably under the cap parses cleanly — the guard does
	// not penalise real (shallow) programs. 64 is the spec floor every
	// conforming implementation MUST accept (validate.md / code.md §13.7).
	p := parse(build_deep_let(64))
	assert p.body is cx.ProgramDirective
}
