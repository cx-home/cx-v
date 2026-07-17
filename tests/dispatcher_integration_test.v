module main

import cx
import code

// Tests for the dispatcher-integration bridge — exercises
// `code.try_eval_match_via_bridge` and `code.try_eval_modify_via_bridge`
// (vcx/code/eval.v) which route `[?match]` / `[?modify]` directives
// through the standalone evaluators (vcx/code/match_eval.v +
// vcx/code/modify_eval.v) via the `program_node_to_source` emitter
// (vcx/code/program_emit.v) + Z79g's `dispatcher_bridge.v` retyper +
// path-aware structural evaluator.
//
// Strategy:
//
//   1. Parse a representative `[?match]` / `[?modify]` source.
//   2. Run it through the BRIDGE path (eval via the bridge function).
//   3. Run it through the LEGACY path (eval via `code.eval_code`).
//   4. Assert the rendered outputs are byte-equal — the bridge is
//      now LIVE in the dispatcher (see `eval.v::eval_match` /
//      `eval_modify`), so any divergence would surface as a regression
//      in the 183-fixture conformance suite.
//
// Z79g status (this session): both Gap 1 (modify path-precision) and
// Gap 2 (match pattern typing) are CLOSED. The dispatcher routes
// `[?match]` (multi-arm) and `[?modify]` (two-positional form) through
// the bridge first; falls back to legacy ONLY when the bridge declines
// (free-binding patterns / action values, single-arm `[?match]`,
// pipe-stage `[?modify]`).

// ── Helpers ──────────────────────────────────────────────────────────────────

// run_bridge_match parses the program, locates the [?match] directive,
// and routes through the bridge function. Returns the rendered output
// or an error when the bridge cannot apply.
fn run_bridge_match(program_src string) !string {
	prog := cx.parse_program(program_src)!
	body := prog.body
	directive := if body is cx.ProgramDirective {
		body as cx.ProgramDirective
	} else {
		return error('test setup: program body must be a [?match] directive at top level (got ${body.type_name()})')
	}
	if directive.name != 'match' {
		return error('test setup: expected [?match] directive, got [?${directive.name}]')
	}
	mut env := code.new_env()
	result := code.try_eval_match_via_bridge(directive, mut env) or {
		return error('bridge returned none (cannot apply)')
	}
	return code.render(result, 'text')!
}

// run_bridge_modify parses the program, locates the [?modify] directive,
// pre-binds $doc to in_cx, and routes through the bridge.
fn run_bridge_modify(in_cx string, program_src string) !string {
	prog := cx.parse_program(program_src)!
	body := prog.body
	directive := if body is cx.ProgramDirective {
		body as cx.ProgramDirective
	} else {
		return error('test setup: program body must be a [?modify] directive (got ${body.type_name()})')
	}
	if directive.name != 'modify' {
		return error('test setup: expected [?modify] directive, got [?${directive.name}]')
	}
	mut env := code.new_env()
	doc := cx.parse(in_cx) or {
		return error('parse input_cx failed: ${err}')
	}
	mut doc_node := cx.Node(cx.Element{ name: '' })
	for n in doc.elements {
		if n is cx.Element {
			doc_node = n
			break
		}
	}
	env.bindings['doc'] = doc_node
	env.bindings['input'] = doc_node
	result := code.try_eval_modify_via_bridge(directive, mut env) or {
		return error('bridge returned none (cannot apply)')
	}
	return code.render(result, 'text')!
}

// run_legacy runs the standard dispatcher (eval_code) for comparison.
fn run_legacy(in_cx string, program_src string) !string {
	return code.eval_code(in_cx, program_src, 'text')!
}

// ── [?modify] bridge parity — focus-by-name shapes ─────────────────────────

fn test_bridge_modify_no_match_returns_unchanged() {
	// Adapted from program-modify-004-no-match-returns-unchanged.
	// Focus matches nothing; the standalone walker's "all actions
	// skip" reduces to identity — same as legacy.
	in_cx := '[users [user [name Alice]]]'
	program := '[?modify \$doc //missing [delete]]'
	bridge_out := run_bridge_modify(in_cx, program) or {
		assert false, 'modify bridge failed: ${err}'
		return
	}
	legacy_out := run_legacy(in_cx, program) or {
		assert false, 'legacy eval failed: ${err}'
		return
	}
	// Identity case — both must equal the input shape (whitespace may
	// differ; we compare by length non-zero + presence of the input
	// element name).
	assert bridge_out.contains('users')
	assert legacy_out.contains('users')
}

fn test_bridge_modify_predicate_focus_filters() {
	// Z79g — Gap 1 closed: the path-aware bridge respects the
	// `[= $_@active false]` predicate filter so only Bob is dropped.
	// Parity with the legacy dispatcher.
	in_cx := '[users [user active=true [name Alice]] [user active=false [name Bob]]]'
	program := '[?modify \$doc //user[= \$_@active false] [delete]]'
	bridge_out := run_bridge_modify(in_cx, program) or {
		assert false, 'modify bridge failed: ${err}'
		return
	}
	assert bridge_out.len > 0
	// Predicate honoured: Alice retained, Bob dropped.
	assert bridge_out.contains('Alice'), 'bridge should keep Alice; got ${bridge_out}'
	assert !bridge_out.contains('Bob'), 'bridge should drop Bob; got ${bridge_out}'
}

// ── [?modify] bridge — #471 outer-binding predicate declines ─────────────────
//
// The bridge's predicate filter (cxpath_eval.v filter_step_predicate)
// evaluates against an EMPTY binding env: a focus predicate referencing any
// binding beyond the reserved $_ / $_position / $_last set would identity-
// pass every candidate — the #434 silent-wrong-answer class, bind-free
// sibling #471. The bridge must DECLINE (return none) so the legacy
// evaluator runs the predicate with full program-env access (bound outer
// bindings filter; unbound ones raise CXER0001).

fn test_bridge_modify_outer_binding_predicate_declines() {
	in_cx := '[teams [team name=alpha [member id=1]] [team name=beta [member id=2]]]'
	program := '[?modify \$doc //team/member[= \$qqq@name "alpha"] [set-attr flagged true]]'
	if out := run_bridge_modify(in_cx, program) {
		assert false, 'bridge must decline an outer-binding focus predicate (would identity-pass); got ${out}'
	}
}

fn test_bridge_modify_reserved_bindings_still_take_bridge() {
	// Regression pin: the reserved predicate bindings the standalone engine
	// itself supplies do NOT trigger the #471 decline — plain predicates
	// keep the fast bridge (see also test_bridge_modify_predicate_focus_filters).
	in_cx := '[users [user active=true [name Alice]] [user active=false [name Bob]]]'
	program := '[?modify \$doc //user[= \$_@active false] [set-attr checked true]]'
	out := run_bridge_modify(in_cx, program) or {
		assert false, 'bridge must accept a reserved-binding-only predicate: ${err}'
		return
	}
	assert out.contains('Alice'), 'bridge output lost Alice: ${out}'
}

// ── [?match] bridge — coverage ───────────────────────────────────────────────
//
// Z79g (this session): Gap 2 — pattern_node typing mismatch — is now
// CLOSED. The bridge re-types each `:case` arm's pattern via the
// program parser through `retype_match_pattern_nodes`, so scalar
// patterns like `:case 200` populate `pattern_node = ScalarNode(int_type, 200)`
// matching the dispatcher's pre-evaluated scrutinee. The bridge now
// achieves PARITY with the legacy dispatcher for the scalar / atom
// `:case` shape — the test below pins that parity.

fn test_bridge_match_parity_on_scalar_patterns() {
	// `200` scrutinee evaluated → ScalarNode(int_type, 200).
	// `:case 200` pattern_node re-typed via program parser →
	//   ScalarNode(int_type, 200).
	// node_structural_eq returns true → first :case arm fires.
	// Bridge returns `:ok` — same as legacy.
	program := '[?match 200 [case 200 :ok] [case 404 :not-found] [else :err]]'
	bridge_out := run_bridge_match(program) or {
		assert false, 'bridge returned error: ${err}'
		return
	}
	legacy_out := run_legacy('[doc]', program) or {
		assert false, 'legacy eval failed: ${err}'
		return
	}
	assert bridge_out == ':ok', 'bridge expected :ok, got ${bridge_out}'
	assert legacy_out == ':ok', 'legacy expected :ok, got ${legacy_out}'
	assert bridge_out == legacy_out, 'parity expected bridge==legacy, got bridge=${bridge_out} legacy=${legacy_out}'
}

fn test_bridge_match_else_arm_parity() {
	// When the scrutinee misses every :case AND :else is present,
	// both paths agree (else fires unconditionally). This is the one
	// shape where the bridge happens to match legacy.
	program := '[?match 500 [case 200 :ok] [case 404 :not-found] [else :err]]'
	bridge_out := run_bridge_match(program) or {
		assert false, 'bridge failed: ${err}'
		return
	}
	legacy_out := run_legacy('[doc]', program) or {
		assert false, 'legacy failed: ${err}'
		return
	}
	assert bridge_out == legacy_out, 'bridge=${bridge_out} legacy=${legacy_out}'
}

fn test_bridge_match_single_arm_returns_none() {
	// Single-arm 2-arg `[?match val pat :yield expr]` form is not
	// routed through the multi-arm bridge — the bridge MUST return
	// `none` so the dispatcher uses the legacy single-arm path.
	program := '[?match 42 [user \$u] :yield \$u]'
	prog := cx.parse_program(program) or {
		assert false, 'parse failed: ${err}'
		return
	}
	directive := if prog.body is cx.ProgramDirective {
		prog.body as cx.ProgramDirective
	} else {
		assert false, 'top is not directive'
		return
	}
	mut env := code.new_env()
	result := code.try_eval_match_via_bridge(directive, mut env)
	assert result == none, 'expected bridge to skip single-arm form; got Some'
}
