// call_result_steps_test.v — the CRS-1 call-result postfix-step gate (#862).
//
// RULED CRS-1 (2026-08-20, owner 862b; ledger/rulings_2026_08_20_call_result_steps.md):
// a head-dispatch call result carries the grammar [135a] compact-step
// subset — `[$first $h]@v`, `[$nth $xs $i]/*`, `[$paint $doc]//l` —
// byte-adjacency-gated exactly like the binding step loop, with the SAME
// BP-1 explicit-axis refusal. Stepping a call result is semantically
// identical to binding the result and stepping the binding:
//   [$string [$f …]/name] ≡ [?let [= $t [$f …]] [$string $t/name]]
// This gate pins the parse surface (both call forms, adjacency,
// refusals), the eval equivalence, and the canonical-emit round-trip.
module main

import cx
import code
import platform as _

// ── helpers ─────────────────────────────────────────────────────────

fn crs_parse(src string) cx.Program {
	return cx.parse_program(src) or { panic('parse failed for `${src}`: ${err.msg()}') }
}

fn crs_eval_canon(src string) string {
	n := code.program_parse_to_typed_node(src) or {
		assert false, 'eval failed for `${src}`'
		return ''
	}
	return code.render_canonical(n)
}

// ── parse: the [135a] steps attach to the call RESULT ───────────────

fn test_parse_attr_step_on_call_result() {
	body := crs_parse('[\$first \$h]@v').body
	if body is cx.ProgramCall {
		assert body.name == 'first'
		assert body.args.len == 1
		assert body.path.len == 1, 'expected one postfix step, got ${body.path.len}'
		assert body.path[0].kind == .attr
		assert body.path[0].name == 'v'
	} else {
		assert false, 'expected ProgramCall'
	}
}

fn test_parse_wildcard_and_descendant_on_call_result() {
	w := crs_parse('[\$nth \$xs \$i]/*').body
	if w is cx.ProgramCall {
		assert w.path.len == 1
		assert w.path[0].kind == .wildcard_children
	} else {
		assert false, 'expected ProgramCall for /*'
	}
	d := crs_parse('[\$paint \$doc]//l').body
	if d is cx.ProgramCall {
		assert d.path.len == 1
		assert d.path[0].kind == .descendant
		assert d.path[0].name == 'l'
	} else {
		assert false, 'expected ProgramCall for //l'
	}
}

fn test_parse_predicate_on_call_result_step() {
	body := crs_parse('[\$first \$h]/item[1]/name').body
	if body is cx.ProgramCall {
		assert body.path.len == 2
		assert body.path[0].kind == .child
		assert body.path[0].name == 'item'
		assert body.path[0].predicates.len == 1, 'adjacent [1] must be a step predicate'
		assert body.path[1].name == 'name'
	} else {
		assert false, 'expected ProgramCall'
	}
}

fn test_parse_chained_steps_after_postfix_marker() {
	// The step run follows the `?`/`!` postfix (grammar [125] order).
	body := crs_parse('[\$f \$x]?/name').body
	if body is cx.ProgramCall {
		assert body.fallible
		assert body.path.len == 1
		assert body.path[0].name == 'name'
	} else {
		assert false, 'expected ProgramCall'
	}
}

fn test_parse_whitespace_separated_step_token_stays_operand() {
	// `[$count //*]` is head-plus-argument (the pre-CRS-1 adjacency rule,
	// unchanged): NO postfix path on the call.
	body := crs_parse('[\$count //*]').body
	if body is cx.ProgramCall {
		assert body.name == 'count'
		assert body.args.len == 1
		assert body.path.len == 0, 'a spaced //* must stay a call argument'
	} else {
		assert false, 'expected ProgramCall'
	}
}

fn test_parse_qualified_call_carries_postfix_steps() {
	body := crs_parse('[m/f \$x]@v').body
	if body is cx.ProgramCall {
		assert body.path.len == 1
		assert body.path[0].kind == .attr
		assert body.path[0].name == 'v'
	} else {
		assert false, 'expected ProgramCall for the qualified form'
	}
}

// ── parse: refusals — one surface, the BP-1 wording ─────────────────

fn test_parse_axis_on_call_result_refuses_with_bp1_message() {
	cx.parse_program('[\$f \$x]/ancestor::y') or {
		msg := err.msg()
		assert msg.contains('not binding-path surface'), 'expected the BP-1 diagnostic, got: ${msg}'
		assert msg.contains('135a'), 'the diagnostic names grammar [135a]: ${msg}'
		return
	}
	assert false, 'explicit axis on a call result must refuse (BP-1/CRS-1)'
}

fn test_parse_call_head_steps_still_refused() {
	cx.parse_program('[\$fn/x 1]') or {
		assert err.msg().contains('bind the value first'), 'head refusal wording moved: ${err.msg()}'
		return
	}
	assert false, 'steps on a call HEAD must stay refused (a head is a name, not a value)'
}

// ── canonical emit: the steps round-trip ────────────────────────────

fn test_canonical_emit_round_trips_call_result_steps() {
	src := '[\$first \$h]@v'
	body := crs_parse(src).body
	emitted := code.program_node_to_source(body)
	assert emitted == src, 'canonical emit must re-emit the glued postfix: ${emitted}'
	reparsed := crs_parse(emitted).body
	if reparsed is cx.ProgramCall {
		assert reparsed.path.len == 1
		assert reparsed.path[0].kind == .attr
	} else {
		assert false, 'reparse of emitted source must keep the postfix'
	}
}

// ── eval: the issue repro + the [?let]-equivalence pin ──────────────

fn test_eval_attr_on_call_result_issue_repro() {
	// #862 repro: previously `unexpected token '@' in expression position`.
	out := crs_eval_canon('[?let [= \$h ([row v=1], [row v=2])] [report [\$first \$h]@v]]')
	assert out.contains('1'), 'expected the first row attr value, got: ${out}'
	assert !out.contains('err'), 'repro must evaluate cleanly: ${out}'
}

fn test_eval_let_equivalence_pin() {
	// [$string [$f …]/name] ≡ [?let [= $t [$f …]] [$string $t/name]]
	direct := crs_eval_canon('[?let [= \$h ([row v=1 [name "a"]], [row v=2 [name "b"]])] [\$string [\$first \$h]/name]]')
	via_let := crs_eval_canon('[?let [= \$h ([row v=1 [name "a"]], [row v=2 [name "b"]])] [?let [= \$t [\$first \$h]] [\$string \$t/name]]]')
	assert direct == via_let, 'call-result step must equal bind-then-step: `${direct}` vs `${via_let}`'
}

fn test_eval_equivalence_attr_and_wildcard() {
	d1 := crs_eval_canon('[?let [= \$h ([row v=1], [row v=2])] [\$last \$h]@v]')
	v1 := crs_eval_canon('[?let [= \$h ([row v=1], [row v=2])] [?let [= \$t [\$last \$h]] \$t@v]]')
	assert d1 == v1, '@attr equivalence: `${d1}` vs `${v1}`'
	d2 := crs_eval_canon('[?let [= \$h ([row [a 1] [b 2]], [row [c 3]])] [\$first \$h]/*]')
	v2 := crs_eval_canon('[?let [= \$h ([row [a 1] [b 2]], [row [c 3]])] [?let [= \$t [\$first \$h]] \$t/*]]')
	assert d2 == v2, '/* equivalence: `${d2}` vs `${v2}`'
}

fn test_eval_predicate_on_call_result_step() {
	d := crs_eval_canon('[?let [= \$h ([u [item 1] [item 2] [item 3]], [u [item 9]])] [\$first \$h]/item[2]]')
	v := crs_eval_canon('[?let [= \$h ([u [item 1] [item 2] [item 3]], [u [item 9]])] [?let [= \$t [\$first \$h]] \$t/item[2]]]')
	assert d == v, 'predicate-step equivalence: `${d}` vs `${v}`'
	assert d.contains('2'), 'positional predicate must pick the second item: ${d}'
}

fn test_eval_descendant_chain_on_call_result() {
	d := crs_eval_canon('[?let [= \$h ([u [team [member id=1]]], [u [team [member id=2]]])] [\$last \$h]//member@id]')
	v := crs_eval_canon('[?let [= \$h ([u [team [member id=1]]], [u [team [member id=2]]])] [?let [= \$t [\$last \$h]] \$t//member@id]]')
	assert d == v, 'descendant+attr equivalence: `${d}` vs `${v}`'
	assert d.contains('2'), 'the last row descendant id: ${d}'
}

fn test_eval_step_distribution_over_sequence_result() {
	// ARR-1 / O4 agreement: a step over a sequence-returning call
	// distributes over its members, exactly as over a bound sequence.
	d := crs_eval_canon('[?let [= \$h ([row v=1], [row v=2], [row v=3])] [\$tail \$h]@v]')
	v := crs_eval_canon('[?let [= \$h ([row v=1], [row v=2], [row v=3])] [?let [= \$t [\$tail \$h]] \$t@v]]')
	assert d == v, 'O4 distribution equivalence: `${d}` vs `${v}`'
	assert d.contains('2') && d.contains('3'), 'tail members must both contribute: ${d}'
}

fn test_eval_map_key_step_on_call_result() {
	d := crs_eval_canon('[?let [= \$m {name: "zed", meta: {rank: 4}}] [\$identity \$m].meta.rank]')
	assert d.contains('4'), 'map-key chain on a call result: ${d}'
}
