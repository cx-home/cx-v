module main

import cx
import code

// Tests for the Phase 2.7-standalone `[?match]` evaluator.
//
// The evaluator under test is `code.eval_match_node(node, ctx)`. It is
// STANDALONE: it does NOT integrate with the directive-evaluator
// dispatch path (which still runs `code.eval_match(d, mut env)` over
// ProgramDirective). Coverage targets:
//
//   - First-match-wins on multi-arm MatchNode (D8 evaluation order).
//   - `:case` exact match (source-string-equality at Phase 2.7-standalone).
//   - `:case … :where GUARD` — guard true → arm matches; guard false → skip.
//   - `:when PRED` predicate-only mode — EBV true → match; EBV false → skip.
//   - `:else` fallback when no prior arm matched.
//   - No `:else` + no arm matched → MatchResult{matched=false} per D7.
// Arm-kind ordering `:case → :when → :else` (the valid -D8
//     interleave; the parser also accepts arbitrary interleaving — the
//     evaluator walks them in source order).
//   - Atomic-template-driven `:where` / `:when` arms exercising
// `attr_test` + `attr_compare` (the templates).
//   - Unsupported predicate body → graceful error
//     (`MATCH_PREDICATE_EVAL_NOT_YET_IMPLEMENTED`).

// ── Helpers ──────────────────────────────────────────────────────────────────

fn ctx_with_scrutinee(s string) code.EvalContext {
	return code.new_eval_context(?string(s))
}

fn ctx_no_scrutinee() code.EvalContext {
	return code.new_eval_context(?string(none))
}

fn ctx_with_attrs(s ?string, attrs map[string]string) code.EvalContext {
	mut c := code.new_eval_context(s)
	c.attrs = attrs.clone()
	return c
}

// ── First-match-wins on 3-arm match ────────────────────────────

fn test_first_match_wins_three_arms_first_arm_wins() {
	arms := [
		cx.new_case_arm('200', ':ok'),
		cx.new_case_arm('404', ':not-found'),
		cx.new_else_arm(':err'),
	]
	n := cx.new_match_node(?string('\$s'), arms)
	r := code.eval_match_node(n, ctx_with_scrutinee('200')) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.arm_index == 0
	assert r.arm_kind == 'case'
	assert r.body == ':ok'
}

fn test_first_match_wins_three_arms_middle_arm_wins() {
	arms := [
		cx.new_case_arm('200', ':ok'),
		cx.new_case_arm('404', ':not-found'),
		cx.new_else_arm(':err'),
	]
	n := cx.new_match_node(?string('\$s'), arms)
	r := code.eval_match_node(n, ctx_with_scrutinee('404')) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.arm_index == 1
	assert r.arm_kind == 'case'
	assert r.body == ':not-found'
}

// Two arms with the same pattern — first wins (D8 ordering). Verifies
// the evaluator never falls through after a match.
fn test_first_match_wins_duplicate_patterns() {
	arms := [
		cx.new_case_arm('200', ':first'),
		cx.new_case_arm('200', ':second'),
	]
	n := cx.new_match_node(?string('\$s'), arms)
	r := code.eval_match_node(n, ctx_with_scrutinee('200')) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.arm_index == 0
	assert r.body == ':first'
}

// ── `:case` exact match (source-string-equality at Phase 2.7-standalone) ─────

fn test_case_exact_match_atom_literal() {
	arms := [
		cx.new_case_arm(':ok', ':success'),
		cx.new_case_arm(':err', ':failure'),
	]
	n := cx.new_match_node(?string('\$status'), arms)
	r := code.eval_match_node(n, ctx_with_scrutinee(':ok')) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.arm_index == 0
	assert r.body == ':success'
}

fn test_case_exact_match_wildcard_underscore() {
	arms := [
		cx.new_case_arm('_', ':any'),
	]
	n := cx.new_match_node(?string('\$x'), arms)
	r := code.eval_match_node(n, ctx_with_scrutinee('whatever-value')) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.arm_kind == 'case'
	assert r.body == ':any'
}

fn test_case_no_match_when_pattern_differs() {
	arms := [
		cx.new_case_arm('200', ':ok'),
	]
	n := cx.new_match_node(?string('\$s'), arms)
	r := code.eval_match_node(n, ctx_with_scrutinee('500')) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert !r.matched
	assert r.arm_index == -1
	assert r.arm_kind == ''
	assert r.body == ''
}

// ── `:where` guard semantics ───────────────────────────────────

fn test_where_guard_true_arm_matches() {
	arms := [
		cx.new_case_arm_guarded('_', '@active', ':active-arm'),
		cx.new_else_arm(':fallback'),
	]
	n := cx.new_match_node(?string('\$u'), arms)
	r := code.eval_match_node(n, ctx_with_attrs(?string('user-row'),
		{ 'active': 'true' })) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.arm_index == 0
	assert r.arm_kind == 'case'
	assert r.body == ':active-arm'
}

fn test_where_guard_false_skips_arm() {
	arms := [
		cx.new_case_arm_guarded('_', '@active', ':active-arm'),
		cx.new_else_arm(':fallback'),
	]
	n := cx.new_match_node(?string('\$u'), arms)
	// Empty attrs → `@active` returns false → arm skipped → :else fires.
	r := code.eval_match_node(n, ctx_with_attrs(?string('user-row'),
		map[string]string{})) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.arm_index == 1
	assert r.arm_kind == 'else'
	assert r.body == ':fallback'
}

// Guard runs only AFTER pattern matches (pattern AND guard).
fn test_where_guard_skipped_when_pattern_misses() {
	arms := [
		cx.new_case_arm_guarded('200', '@active', ':impossible-arm'),
		cx.new_else_arm(':fallback'),
	]
	n := cx.new_match_node(?string('\$s'), arms)
	// Scrutinee != '200' so pattern misses; guard would have raised an
	// error if it were evaluated against a body that doesn't parse —
	// not the test here, but the test does pin "pattern checked first".
	r := code.eval_match_node(n, ctx_with_attrs(?string('500'),
		{ 'active': 'true' })) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.arm_kind == 'else'
}

// ── `:when` predicate arm (predicate-only mode) ──────────────────

fn test_when_predicate_only_mode_true_fires() {
	arms := [
		cx.new_when_arm('@admin', ':admin-arm'),
		cx.new_else_arm(':non-admin-arm'),
	]
	n := cx.new_match_node(?string(none), arms)
	r := code.eval_match_node(n, ctx_with_attrs(?string(none),
		{ 'admin': 'true' })) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.arm_index == 0
	assert r.arm_kind == 'when'
	assert r.body == ':admin-arm'
}

fn test_when_predicate_only_mode_false_skips() {
	arms := [
		cx.new_when_arm('@admin', ':admin-arm'),
		cx.new_else_arm(':non-admin-arm'),
	]
	n := cx.new_match_node(?string(none), arms)
	r := code.eval_match_node(n, ctx_with_attrs(?string(none),
		map[string]string{})) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.arm_index == 1
	assert r.arm_kind == 'else'
	assert r.body == ':non-admin-arm'
}

// ── `:else` fallback ───────────────────────────────────────────

fn test_else_fires_when_no_case_matches() {
	arms := [
		cx.new_case_arm('200', ':ok'),
		cx.new_case_arm('404', ':not-found'),
		cx.new_else_arm(':err'),
	]
	n := cx.new_match_node(?string('\$s'), arms)
	r := code.eval_match_node(n, ctx_with_scrutinee('500')) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.arm_index == 2
	assert r.arm_kind == 'else'
	assert r.body == ':err'
}

// ── No `:else` + no match → empty-sequence ───────────────────

fn test_no_else_no_match_returns_empty_sequence() {
	arms := [
		cx.new_case_arm('200', ':ok'),
		cx.new_case_arm('404', ':not-found'),
	]
	n := cx.new_match_node(?string('\$s'), arms)
	r := code.eval_match_node(n, ctx_with_scrutinee('500')) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	// Empty sequence: matched=false, arm_index=-1, arm_kind/body empty.
	assert !r.matched
	assert r.arm_index == -1
	assert r.arm_kind == ''
	assert r.body == ''
}

// ── Arm-kind ordering `:case` → `:when` → `:else` (valid form) ───

fn test_arm_order_case_when_else_when_arm_wins() {
	arms := [
		cx.new_case_arm('200', ':ok'),
		cx.new_when_arm('@retry', ':retry-arm'),
		cx.new_else_arm(':err'),
	]
	n := cx.new_match_node(?string('\$s'), arms)
	r := code.eval_match_node(n, ctx_with_attrs(?string('503'),
		{ 'retry': 'true' })) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.arm_index == 1
	assert r.arm_kind == 'when'
	assert r.body == ':retry-arm'
}

fn test_arm_order_case_when_else_else_arm_wins() {
	arms := [
		cx.new_case_arm('200', ':ok'),
		cx.new_when_arm('@retry', ':retry-arm'),
		cx.new_else_arm(':err'),
	]
	n := cx.new_match_node(?string('\$s'), arms)
	r := code.eval_match_node(n, ctx_with_attrs(?string('503'),
		map[string]string{})) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.arm_index == 2
	assert r.arm_kind == 'else'
	assert r.body == ':err'
}

// ── `attr_compare` atomic templates ────────────────────────────

fn test_attr_compare_equal_string() {
	arms := [
		cx.new_when_arm('= \$_@role "admin"', ':admin-arm'),
		cx.new_else_arm(':non-admin-arm'),
	]
	n := cx.new_match_node(?string(none), arms)
	r := code.eval_match_node(n, ctx_with_attrs(?string(none),
		{ 'role': 'admin' })) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.arm_index == 0
	assert r.arm_kind == 'when'
}

fn test_attr_compare_greater_than_int() {
	arms := [
		cx.new_when_arm('> \$_@age 17', ':adult'),
		cx.new_else_arm(':minor'),
	]
	n := cx.new_match_node(?string(none), arms)
	// Adult path.
	r1 := code.eval_match_node(n, ctx_with_attrs(?string(none),
		{ 'age': '21' })) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r1.matched
	assert r1.arm_index == 0
	assert r1.body == ':adult'
	// Minor path.
	r2 := code.eval_match_node(n, ctx_with_attrs(?string(none),
		{ 'age': '15' })) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r2.matched
	assert r2.arm_index == 1
	assert r2.body == ':minor'
}

fn test_attr_compare_not_equal_string() {
	arms := [
		cx.new_when_arm('!= \$_@status "ok"', ':abnormal'),
		cx.new_else_arm(':normal'),
	]
	n := cx.new_match_node(?string(none), arms)
	r := code.eval_match_node(n, ctx_with_attrs(?string(none),
		{ 'status': 'fail' })) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.body == ':abnormal'
}

// `:where` guard with attr_compare against a `:case` arm — exercises
// the pattern-AND-guard composition.
fn test_case_where_attr_compare_combines() {
	arms := [
		cx.new_case_arm_guarded('_', '>= \$_@score 60', ':pass'),
		cx.new_else_arm(':fail'),
	]
	n := cx.new_match_node(?string('\$row'), arms)
	r := code.eval_match_node(n, ctx_with_attrs(?string('student-row'),
		{ 'score': '85' })) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.arm_kind == 'case'
	assert r.body == ':pass'
}

// ── Retired infix surface + unsupported predicate body → graceful error ──────

fn test_retired_infix_and_predicate_body_returns_error() {
	// `@a and @b` is the RETIRED infix boolean surface (#110). The
	// data-mode predicate parser hard-errors (RETIRED_PREDICATE_SURFACE)
	// and the standalone evaluator wraps that in its
	// MATCH_PREDICATE_EVAL_NOT_YET_IMPLEMENTED envelope.
	arms := [
		cx.new_when_arm('@a and @b', ':never'),
		cx.new_else_arm(':fallback'),
	]
	n := cx.new_match_node(?string(none), arms)
	_ := code.eval_match_node(n, ctx_with_attrs(?string(none),
		{ 'a': 'true', 'b': 'true' })) or {
		assert err.msg().contains('MATCH_PREDICATE_EVAL_NOT_YET_IMPLEMENTED')
		assert err.msg().contains('retired')
		return
	}
	assert false, 'expected retired-surface predicate parse error'
}

fn test_retired_infix_attr_compare_body_returns_error() {
	// Infix `@name OP value` is retired at predicate parse (#110); the
	// canonical spelling is the prefix `OP $_@name value` (covered by the
	// attr_compare tests above).
	arms := [
		cx.new_when_arm('@role = "admin"', ':never'),
		cx.new_else_arm(':fallback'),
	]
	n := cx.new_match_node(?string(none), arms)
	_ := code.eval_match_node(n, ctx_with_attrs(?string(none),
		{ 'role': 'admin' })) or {
		assert err.msg().contains('retired')
		return
	}
	assert false, 'expected retired-surface predicate parse error'
}

fn test_canonical_bool_expr_body_not_supported_standalone() {
	// Canonical prefix `and [@a] [@b]` PARSES (kind=bool_expr) but the
	// Phase 2.7-standalone arm evaluator does not fold it — it surfaces
	// the graceful kind-not-supported error (the dispatcher-bridge
	// evaluator in predicate_eval.v owns the EBV fold).
	arms := [
		cx.new_when_arm('and [@a] [@b]', ':never'),
		cx.new_else_arm(':fallback'),
	]
	n := cx.new_match_node(?string(none), arms)
	_ := code.eval_match_node(n, ctx_with_attrs(?string(none),
		{ 'a': 'true', 'b': 'true' })) or {
		assert err.msg().contains('MATCH_PREDICATE_EVAL_NOT_YET_IMPLEMENTED')
		return
	}
	assert false, 'expected kind-not-supported error for bool_expr arm'
}

// ── End-to-end: parse_match + eval_match_node round-trip ─────────────────────

// ── Z79b structural-graft tests (Phase 2.4 follow-up) ────────────────────────
//
// These tests exercise the structural ProgramExpr-AST graft on
// MatchArm.{pattern,guard,body}_node. They prove that:
//   - The parser populates `*_node` fields on a best-effort basis.
// `eval_match_node` consults `pattern_node` for kind
//     canonical-rep equality (whitespace-insensitive structural match)
//     when the scrutinee also parses as a Node.
//   - Verbatim-string fallback still drives bodies / guards whose
//     snippets do not parse cleanly as standalone Documents.
//   - Backward-compat: arms constructed via `new_case_arm(...)` (no
//     `*_node` slot populated) continue to use source-string equality.

// (1) Parser populates `pattern_node` + `body_node` when snippets parse.
fn test_z79b_parser_populates_node_slots_when_snippets_parse() {
	src := '[?match \$x :case [user 1] :yield [ok 1] :else :yield [err 1]]'
	n := cx.parse_match(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.arms.len == 2
	// First arm: `:case [user 1] :yield [ok 1]` — both pattern + body
	// parse as bracketed elements.
	first := n.arms[0]
	assert first.pattern_node != none, 'expected pattern_node populated'
	assert first.body_node != none, 'expected body_node populated'
	// Else arm: pattern empty (so no pattern_node), body `[err 1]`
	// parses → body_node populated.
	last := n.arms[1]
	assert last.pattern_node == none
	assert last.body_node != none, 'expected body_node populated on :else'
}

// (2) Parser leaves `*_node` as none when snippet does NOT parse as a
//     standalone Document. `cx.parse` is lenient — most snippets
//     produce some Node — so this test pins the rare hard-fail case:
//     a syntactically-malformed bracket form like `[`.
fn test_z79b_parser_leaves_node_none_when_snippet_unparseable() {
	// Hand-construct an arm with an intentionally broken pattern source
	// that won't parse. The match parser uses `try_parse_snippet_to_node`
	// which returns `none` on failure.
	bad_pattern := '['  // unclosed bracket — cx.parse fails
	n := cx.try_parse_snippet_to_node(bad_pattern)
	assert n == none, 'expected cx.parse to fail on unclosed bracket'
}

// (3) Structural `:case` pattern match — same Element kind + name +
//     items, differing internal whitespace. Without the structural
//     graft this would mis-compare under source-string equality
//     (`[user 1]` != `[user  1]` byte-wise but both parse to the
//     same Element shape).
fn test_z79b_case_structural_match_whitespace_insensitive() {
	src := '[?match \$x :case [user 1] :yield :matched :else :yield :fallback]'
	n := cx.parse_match(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	// Scrutinee `[user  1]` (double space between name and body) parses
	// to the same canonical Element as the pattern `[user 1]`.
	r := code.eval_match_node(n, ctx_with_scrutinee('[user  1]')) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	// Structural equality fires: source-string equality would have
	// missed because `[user 1]` != `[user  1]` byte-for-byte.
	assert r.matched
	assert r.arm_index == 0
	assert r.arm_kind == 'case'
	assert r.body == ':matched'
}

// (4) Structural :case pattern miss — different element name.
fn test_z79b_case_structural_miss_different_element_name() {
	src := '[?match \$x :case [user 1] :yield :u :else :yield :other]'
	n := cx.parse_match(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	r := code.eval_match_node(n, ctx_with_scrutinee('[admin 1]')) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	// Different element kind → structural miss → :else fires.
	assert r.matched
	assert r.arm_kind == 'else'
	assert r.body == ':other'
}

// (4b) Structural eq distinguishes by Element body content — pattern
//      `[user 1]` does NOT match scrutinee `[user 2]` even though both
//      are Element(user, items.len=1). Proves node_structural_eq
//      recurses into items.
fn test_z79b_case_structural_miss_different_element_body() {
	src := '[?match \$x :case [user 1] :yield :one :else :yield :other]'
	n := cx.parse_match(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	r := code.eval_match_node(n, ctx_with_scrutinee('[user 2]')) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.arm_kind == 'else'
	assert r.body == ':other'
}

// (5) Body containing a complex bracketed expression — `body_node`
//     populates; the standalone evaluator returns the verbatim body
//     string (the structural graft does NOT yet evaluate the body
//     expression — that's the v0.8.x follow-up). The point of the
//     test is to pin that the structural slot is consulted and the
//     parsed-tree shape is preserved.
fn test_z79b_body_complex_expression_node_populated() {
	src := '[?match \$x :case 1 :yield [add x 1] :else :yield [err]]'
	n := cx.parse_match(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	// `[add x 1]` parses as Element name=`add` with two body items.
	bn := n.arms[0].body_node or {
		assert false, 'expected body_node populated for `[add x 1]`'
		return
	}
	if bn is cx.Element {
		assert bn.name == 'add'
	} else {
		assert false, 'expected Element variant, got other'
	}
}

// (6) Backward-compat: arms built via `new_case_arm` (no parser hop)
//     have `*_node = none` and still source-string match.
fn test_z79b_backward_compat_handwritten_arms_use_string_equality() {
	arms := [
		cx.new_case_arm('200', ':ok'),
		cx.new_else_arm(':err'),
	]
	n := cx.new_match_node(?string('\$s'), arms)
	// Verify the structural slots are unset.
	assert n.arms[0].pattern_node == none
	assert n.arms[0].body_node == none
	// And string-equality still drives the eval.
	r := code.eval_match_node(n, ctx_with_scrutinee('200')) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.body == ':ok'
}

// ── End-to-end: parse_match + eval_match_node round-trip ─────────────────────

// One sanity round-trip that wires the Phase 2.4 parser to the Phase
// 2.7-standalone evaluator end-to-end — confirms the verbatim-source
// convention agrees across the two halves.
fn test_parse_then_eval_round_trip() {
	src := '[?match \$s :case 200 :yield :ok :case 404 :yield :not-found :else :yield :err]'
	n := cx.parse_match(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	r := code.eval_match_node(n, ctx_with_scrutinee('404')) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.arm_index == 1
	assert r.arm_kind == 'case'
	assert r.body == ':not-found'
}

// ── Z79d standalone-evaluator unfreeze tests ─────────────────────────────────
//
// These tests exercise the Z79d structural-graft consumption surface:
//   - `MatchResult.body_value` is populated from `arm.body_node` when
//     the firing arm carried a parsed body node (parser populates per
//     Z79b).
//   - `EvalContext.scrutinee_node` lets the caller hand in the actual
//     parsed `cx.Node` scrutinee (no emit→reparse round-trip required).
//     Structural `:case` match runs lossless against `arm.pattern_node`.
//   - Backward-compat: callers that don't populate `scrutinee_node`
//     still see the Z79b string-scrutinee semantics, AND callers that
//     use the legacy `new_match_result_fired(idx, kind, body, bound)`
//     style hand-build still compile cleanly via the new signature
//     (the parameter is appended, optional via ?cx.Node(none)).

// (Z79d-1) Parser populates body_node → MatchResult.body_value mirrors.
fn test_z79d_body_value_populated_from_body_node() {
	src := '[?match \$x :case 1 :yield [ok 1] :else :yield [err 1]]'
	n := cx.parse_match(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	r := code.eval_match_node(n, ctx_with_scrutinee('1')) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.arm_kind == 'case'
	// The structural body slot is populated because `[ok 1]` parses.
	bv := r.body_value or {
		assert false, 'expected body_value populated for `[ok 1]`'
		return
	}
	if bv is cx.Element {
		assert bv.name == 'ok'
	} else {
		assert false, 'expected Element variant, got other'
	}
}

// (Z79d-2) Structural scrutinee via EvalContext.scrutinee_node — lossless
// structural match against arm.pattern_node.
fn test_z79d_structural_scrutinee_matches_pattern_node() {
	src := '[?match \$x :case [user 1] :yield :ok :else :yield :fallback]'
	n := cx.parse_match(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	// Build a real cx.Node scrutinee — same structural shape as the arm
	// pattern. Whitespace doesn't matter (structural eq).
	scrut := cx.try_parse_snippet_to_node('[user 1]') or {
		assert false, 'expected scrutinee snippet to parse'
		return
	}
	ctx := code.new_eval_context_with_node(scrut)
	r := code.eval_match_node(n, ctx) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.arm_index == 0
	assert r.arm_kind == 'case'
	assert r.body == ':ok'
}

// (Z79d-3) Structural scrutinee miss — different element body content,
// :else fires.
fn test_z79d_structural_scrutinee_miss_falls_to_else() {
	src := '[?match \$x :case [user 1] :yield :match :else :yield :else-arm]'
	n := cx.parse_match(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	scrut := cx.try_parse_snippet_to_node('[user 2]') or {
		assert false, 'expected scrutinee snippet to parse'
		return
	}
	ctx := code.new_eval_context_with_node(scrut)
	r := code.eval_match_node(n, ctx) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.arm_kind == 'else'
	assert r.body == ':else-arm'
}

// (Z79d-4) Backward-compat: structural scrutinee unspecified → existing
// string-scrutinee semantics drive (Z79b path, unchanged).
fn test_z79d_no_structural_scrutinee_falls_back_to_string() {
	arms := [
		cx.new_case_arm('200', ':ok'),
		cx.new_else_arm(':err'),
	]
	n := cx.new_match_node(?string('\$s'), arms)
	r := code.eval_match_node(n, ctx_with_scrutinee('200')) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.arm_index == 0
	assert r.body == ':ok'
	// Hand-built arms have no body_node → body_value is none.
	assert r.body_value == none
}

// (Z79d-5) Structural scrutinee with wildcard pattern — wildcard fires
// regardless of the scrutinee shape. Exercises the
// wildcard short-circuit ahead of the structural pattern comparison.
fn test_z79d_structural_scrutinee_wildcard_fires() {
	arms := [
		cx.new_case_arm('_', ':any'),
	]
	n := cx.new_match_node(?string('\$x'), arms)
	scrut := cx.try_parse_snippet_to_node('[whatever 99]') or {
		assert false, 'expected snippet to parse'
		return
	}
	ctx := code.new_eval_context_with_node(scrut)
	r := code.eval_match_node(n, ctx) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.arm_index == 0
	assert r.arm_kind == 'case'
	assert r.body == ':any'
}

// (Z79d-6) :else arm body_node propagation — when the :else arm body
// parses (e.g. `[err 1]`), MatchResult.body_value is populated too.
fn test_z79d_else_arm_body_node_propagates() {
	src := '[?match \$x :case 1 :yield :one :else :yield [err 1]]'
	n := cx.parse_match(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	// Scrutinee `99` doesn't match `1` → :else fires.
	r := code.eval_match_node(n, ctx_with_scrutinee('99')) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.matched
	assert r.arm_kind == 'else'
	bv := r.body_value or {
		assert false, 'expected :else body_value populated for `[err 1]`'
		return
	}
	if bv is cx.Element {
		assert bv.name == 'err'
	} else {
		assert false, 'expected Element variant'
	}
}
