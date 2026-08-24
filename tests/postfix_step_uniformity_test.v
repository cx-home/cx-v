// postfix_step_uniformity_test.v — the PS-1 postfix-step uniformity gate (#886).
//
// RULED PS-1 (2026-08-20, owner "1a"; ledger/rulings_2026_08_20_postfix_uniformity.md):
// EVERY program-position bracketed form's closing bracket accepts the
// grammar [135a] compact-step postfix — directive results ([?let]/[?if]/
// [?match]/[?for]/…), operator forms, element literals, and collection
// literals — byte-adjacency-gated exactly like the binding step loop
// (BP-1 axis refusals inherited from the ONE shared step parser; CRS-1
// gave calls the same surface). Semantics: ZERO new — stepping any
// form's result is identical to binding the result and stepping the
// binding:
//   [?let …]/name ≡ [?let [= $t [?let …]] $t/name]      (any head)
// This gate pins, PER HEAD CLASS: the parse surface (steps land on the
// node's path), a positive step, an @attr step, the let-equivalence,
// the BP-1 axis refusal, the adjacency rule (spaced stays separate),
// and the canonical-emit round-trip.
module main

import cx
import code
import platform as _

// ── helpers ─────────────────────────────────────────────────────────

fn ps_parse(src string) cx.Program {
	return cx.parse_program(src) or { panic('parse failed for `${src}`: ${err.msg()}') }
}

fn ps_eval_canon(src string) string {
	n := code.program_parse_to_typed_node(src) or {
		assert false, 'eval failed for `${src}`'
		return ''
	}
	return code.render_canonical(n)
}

// ps_eval_any captures BOTH outcome channels — the canonical rendering of
// a value result, or the thrown error's message — so refusal equivalences
// (`@attr` on a non-element result vs on a binding of it) compare exactly.
fn ps_eval_any(src string) string {
	return code.eval_code('', src, 'text') or {
		if err is code.EvalError {
			return 'error: ${err.code}: ${err.message}'
		}
		return 'error: ${err.msg()}'
	}
}

fn ps_assert_axis_refusal(src string) {
	cx.parse_program(src) or {
		msg := err.msg()
		assert msg.contains('not binding-path surface'), 'expected the BP-1 diagnostic for `${src}`, got: ${msg}'
		assert msg.contains('135a'), 'the diagnostic names grammar [135a]: ${msg}'
		return
	}
	assert false, 'explicit axis must refuse (BP-1/PS-1): `${src}`'
}

// ── directive results: [?let] ────────────────────────────────────────

fn test_parse_step_on_let_result() {
	body := ps_parse('[?let [= \$u [user [b 1]]] \$u]/b').body
	if body is cx.ProgramDirective {
		assert body.name == 'let'
		assert body.path.len == 1, 'expected one postfix step, got ${body.path.len}'
		assert body.path[0].kind == .child
		assert body.path[0].name == 'b'
	} else {
		assert false, 'expected ProgramDirective for the stepped [?let]'
	}
}

fn test_eval_let_result_step_and_equivalence() {
	direct := ps_eval_canon('[?let [= \$u [user [name "ann"]]] \$u]/name')
	assert direct.contains('ann'), 'child step on a [?let] result: ${direct}'
	via_let := ps_eval_canon('[?let [= \$t [?let [= \$u [user [name "ann"]]] \$u]] \$t/name]')
	assert direct == via_let, '[?let]-equivalence (directive head): `${direct}` vs `${via_let}`'
}

fn test_eval_let_result_attr_step() {
	d := ps_eval_canon('[?let [= \$r [row v=9]] \$r]@v')
	v := ps_eval_canon('[?let [= \$t [?let [= \$r [row v=9]] \$r]] \$t@v]')
	assert d == v, '@attr equivalence (directive head): `${d}` vs `${v}`'
	assert d.contains('9'), 'attr step on a [?let] result: ${d}'
}

fn test_parse_axis_on_let_result_refuses() {
	ps_assert_axis_refusal('[?let [= \$x 1] \$x]/ancestor::y')
}

// ── directive results: [?if] ─────────────────────────────────────────

fn test_eval_if_result_steps() {
	d := ps_eval_canon('[?if true [then [user [b 7]]]]/b')
	v := ps_eval_canon('[?let [= \$t [?if true [then [user [b 7]]]]] \$t/b]')
	assert d == v, '[?if] equivalence: `${d}` vs `${v}`'
	assert d.contains('7'), 'child step on an [?if] result: ${d}'
	a := ps_eval_canon('[?if true [then [row v=3]]]@v')
	assert a.contains('3'), '@attr on an [?if] result: ${a}'
}

fn test_parse_axis_on_if_result_refuses() {
	ps_assert_axis_refusal('[?if true [then 1]]/following-sibling::y')
}

// ── directive results: [?match] ──────────────────────────────────────

fn test_eval_match_result_steps() {
	d := ps_eval_canon('[?match 2 [case 2 [user [b 5]]] [else [user [b 0]]]]/b')
	v := ps_eval_canon('[?let [= \$t [?match 2 [case 2 [user [b 5]]] [else [user [b 0]]]]] \$t/b]')
	assert d == v, '[?match] equivalence: `${d}` vs `${v}`'
	assert d.contains('5'), 'child step on a [?match] result: ${d}'
}

fn test_parse_axis_on_match_result_refuses() {
	ps_assert_axis_refusal('[?match 1 [else 2]]/self::y')
}

// ── directive results: [?for] (comprehension) ────────────────────────

fn test_parse_step_on_for_comp_result() {
	body := ps_parse('[?for [in \$u ([row v=1], [row v=2])] [yield \$u]]@v').body
	if body is cx.ProgramForComp {
		assert body.path.len == 1
		assert body.path[0].kind == .attr
		assert body.path[0].name == 'v'
	} else {
		assert false, 'expected ProgramForComp for the stepped [?for]'
	}
}

fn test_eval_for_comp_result_steps() {
	d := ps_eval_canon('[?for [in \$u ([row v=1], [row v=2])] [yield \$u]]@v')
	v := ps_eval_canon('[?let [= \$t [?for [in \$u ([row v=1], [row v=2])] [yield \$u]]] \$t@v]')
	assert d == v, '[?for] @attr equivalence (O4 distribution): `${d}` vs `${v}`'
	assert d.contains('1') && d.contains('2'), 'both members contribute: ${d}'
	c := ps_eval_canon('[?for [in \$u ([user [n 4]], [user [n 6]])] [yield \$u]]/n')
	cv := ps_eval_canon('[?let [= \$t [?for [in \$u ([user [n 4]], [user [n 6]])] [yield \$u]]] \$t/n]')
	assert c == cv, '[?for] child-step equivalence: `${c}` vs `${cv}`'
}

fn test_parse_axis_on_for_result_refuses() {
	ps_assert_axis_refusal('[?for [in \$u (1, 2)] [yield \$u]]/preceding::y')
}

// ── operator forms ───────────────────────────────────────────────────

fn test_parse_step_on_operator_form() {
	body := ps_parse('[+ 1 2]/x').body
	if body is cx.ProgramLiteral {
		assert body.kind == .cx_element
		assert body.name == '+'
		assert body.path.len == 1
		assert body.path[0].kind == .child
		assert body.path[0].name == 'x'
	} else {
		assert false, 'expected the operator-form literal for [+ 1 2]/x'
	}
}

fn test_eval_operator_form_steps_kind_driven() {
	// A child step on a scalar result yields empty — the same footgun
	// shape bindings already have (letter §2.1); NO error.
	d := ps_eval_canon('[report [+ 1 2]/x]')
	v := ps_eval_canon('[report [?let [= \$t [+ 1 2]] \$t/x]]')
	assert d == v, 'operator-form child-step equivalence: `${d}` vs `${v}`'
	// @attr on a non-element result refuses TYPED (CXER0001) — exactly
	// as on a binding of that scalar (both channels compared).
	a := ps_eval_any('[+ 1 2]@a')
	av := ps_eval_any('[?let [= \$t [+ 1 2]] \$t@a]')
	assert a == av, 'operator-form @attr equivalence (typed refusal): `${a}` vs `${av}`'
	assert a.contains('CXER0001'), '@attr on a scalar result refuses typed: ${a}'
}

fn test_parse_axis_on_operator_form_refuses() {
	ps_assert_axis_refusal('[+ 1 2]/ancestor::y')
}

// ── element literals ─────────────────────────────────────────────────

fn test_parse_step_on_element_literal() {
	body := ps_parse('[user [b 1] [c 2]]/c').body
	if body is cx.ProgramLiteral {
		assert body.kind == .cx_element
		assert body.name == 'user'
		assert body.path.len == 1
		assert body.path[0].name == 'c'
	} else {
		assert false, 'expected the element literal for [user …]/c'
	}
}

fn test_eval_element_literal_steps() {
	d := ps_eval_canon('[user [b 1] [c 2]]/c')
	v := ps_eval_canon('[?let [= \$t [user [b 1] [c 2]]] \$t/c]')
	assert d == v, 'element-literal child-step equivalence: `${d}` vs `${v}`'
	assert d.contains('2'), 'redundant-but-legal element step (letter §3a): ${d}'
	a := ps_eval_canon('[row v=4]@v')
	av := ps_eval_canon('[?let [= \$t [row v=4]] \$t@v]')
	assert a == av, 'element-literal @attr equivalence: `${a}` vs `${av}`'
	assert a.contains('4'), '@attr on an element literal: ${a}'
}

fn test_parse_axis_on_element_literal_refuses() {
	ps_assert_axis_refusal('[user [b 1]]/ancestor-or-self::y')
}

// ── collection literals: array / sequence / map ──────────────────────

fn test_parse_step_on_array_literal() {
	body := ps_parse('[1, 2, 3]/x').body
	if body is cx.ProgramLiteral {
		assert body.kind == .array_lit
		assert body.path.len == 1
	} else {
		assert false, 'expected the array literal for [1, 2, 3]/x'
	}
}

fn test_eval_collection_literal_steps() {
	// Array: kind-driven equivalence (child step over scalars → empty).
	d := ps_eval_canon('[report [1, 2]/x]')
	v := ps_eval_canon('[report [?let [= \$t [1, 2]] \$t/x]]')
	assert d == v, 'array-literal equivalence: `${d}` vs `${v}`'
	// Sequence of elements: @attr distributes exactly as on a binding.
	s := ps_eval_canon('([row v=1], [row v=2])@v')
	sv := ps_eval_canon('[?let [= \$t ([row v=1], [row v=2])] \$t@v]')
	assert s == sv, 'sequence-literal @attr equivalence: `${s}` vs `${sv}`'
	assert s.contains('1') && s.contains('2'), 'sequence members contribute: ${s}'
	// Map: `.key` member step.
	m := ps_eval_canon('{a: 5, b: {c: 6}}.b.c')
	mv := ps_eval_canon('[?let [= \$t {a: 5, b: {c: 6}}] \$t.b.c]')
	assert m == mv, 'map-literal member-step equivalence: `${m}` vs `${mv}`'
	assert m.contains('6'), 'nested member step on a map literal: ${m}'
}

fn test_parse_axis_on_collection_literal_refuses() {
	ps_assert_axis_refusal('[1, 2]/ancestor::y')
	ps_assert_axis_refusal('(1, 2)/ancestor::y')
}

// ── adjacency: a spaced step token keeps its current reading ─────────

fn test_whitespace_separated_step_token_stays_separate() {
	// A SPACED `/name` after a directive's `]` is a separate statement
	// (rooted PathExpr), never a result step — the program parses to a
	// block of two statements, the directive path-less.
	prog := ps_parse('[?let [= \$x 1] \$x] /y')
	body := prog.body
	if body is cx.ProgramLiteral {
		assert body.kind == .block, 'expected a two-statement block for the spaced form'
		assert body.items.len == 2
		first := body.items[0]
		if first is cx.ProgramDirective {
			assert first.path.len == 0, 'a spaced /y must not attach to the directive'
		} else {
			assert false, 'first statement must stay the directive'
		}
	} else {
		assert false, 'expected a block for the spaced form, got a single node'
	}
	// Inside an element body: `[cfg /a/b]` keeps its spaced path-operand
	// reading (the [122a] note's pin).
	el := ps_parse('[cfg /a/b]').body
	if el is cx.ProgramLiteral {
		assert el.kind == .cx_element
		assert el.path.len == 0
		assert el.items.len == 1, 'the spaced /a/b stays ONE body operand'
	} else {
		assert false, 'expected the element literal for [cfg /a/b]'
	}
}

// ── canonical emit: the steps round-trip per head class ──────────────

fn test_canonical_emit_round_trips_result_steps() {
	sources := [
		'[?let [= \$u [user [b 1]]] \$u]/b',
		'[?if true [then [row v=1]]]@v',
		'[+ 1 2]/x',
		'[user [b 1] [c 2]]/c',
		'[1, 2]/x',
		'{a: 5}.a',
	]
	for src in sources {
		body := ps_parse(src).body
		emitted := code.program_node_to_source(body)
		reparsed := ps_parse(emitted).body
		reemitted := code.program_node_to_source(reparsed)
		assert emitted == reemitted, 'canonical emit must be a fixpoint for `${src}`: `${emitted}` vs `${reemitted}`'
		assert emitted.contains(']/') || emitted.contains(']@') || emitted.contains('}.')
			|| emitted.contains(')/') || emitted.contains(')@'), 'the glued step run must survive emission of `${src}`: ${emitted}'
	}
}
