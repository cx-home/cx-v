module code

import cx

// match_eval.v — STANDALONE multi-arm `[?match]` evaluator
// Phase 2.7. This is a self-contained surface — it does NOT
// integrate with the existing directive-evaluator dispatch path in
// `eval.v` (which still uses cx.ProgramDirective + MatchEnv and threads
// ProgramState through every arm). Wiring the AST-level MatchNode
// evaluator into the dispatcher is a follow-up step that is tracked
// alongside the Phase 2.x cx.ProgramExpr-AST graft on arm bodies.
//
// What this file provides:
//
//   - `pub struct EvalContext` — a minimal context carrier (scrutinee
//     string + an optional position pair for `$_position` / `$_last`
//     resolution). Keeps the evaluator buildable without leaning
//     on the MatchEnv / ProgramState plumbing.
//   - `pub struct MatchResult` — outcome record capturing which arm
//     fired, the body source returned, the bound scrutinee (if any),
//     and a `matched` flag (so a no-match-no-else result is unambiguous
//     vs an `:else` body whose source happens to be empty).
//   - `pub fn eval_match_node(node cx.MatchNode, context EvalContext)
//     !MatchResult` — the public entry point. (Named `eval_match_node`
//     to avoid collision with the private `eval_match(d, mut env)`
//     directive-evaluator hop already in `eval.v` — that one operates
//     on `cx.ProgramDirective` + `MatchEnv` and dispatches between the
//     2-arg form and the multi-arm form. The Phase 2.7-standalone
//     surface here operates on the AST-level `cx.MatchNode` instead;
//     the dispatcher-integration follow-up will route the multi-arm
// directive path through this function.) Implements 
//     first-match-wins, no implicit EBV in `:case`, EBV in `:when` /
//     `:where`, `:else` fallback when no prior arm matched, empty
// sequence (`matched=false`) when no arm matched
//     and no `:else` is present.
//
// Semantic surface at Phase 2.7-standalone (conservative simplifications
// that match the verbatim-string convention already in place at
// `vcx/cx/match_node.v` + `vcx/cx/match_parser.v`):
//
//   - `:case PAT` arms match by SOURCE-STRING-EQUALITY between the arm's
//     verbatim pattern source and the scrutinee value's stringified form
// (per the production semantics demand kind + canonical
//     representation equality; the Phase 2.x graft replaces this with
//     a structural pattern matcher driven by cx.ProgramPattern AST).
//   - `:where GUARD` on `:case` arms — guard body is parsed as a
//     PredicateExpr (Phase 2.19 atomic-template parser) and evaluated
//     by the local boolean interpreter; the arm matches iff (pattern
//     matches) AND (guard evaluates true).
//   - `:when PRED` arms — predicate body is parsed as a PredicateExpr
//     and EBV'd by the same local boolean interpreter (no scrutinee
// equality test; SQL Searched-CASE).
//   - `:else BODY` arms — fire iff no prior arm matched.
//   - No match + no `:else` → MatchResult{ matched: false } (the empty
// sequence; the caller materialises it as a `()`
//     cx.Node when wiring this into the dispatcher).
//   - Bodies are returned as verbatim source strings (deferring full
//     cx.ProgramExpr evaluation to the Phase 2.x graft).
//
// Unsupported predicate shapes (anything beyond the Phase 2.19 atomic
// templates) surface a `MATCH_PREDICATE_EVAL_NOT_YET_IMPLEMENTED` error
// — the caller can pin the failure at the test layer until the full
// cx.ProgramExpr boolean evaluator lands.
//
// Cross-references:
//   - vcx/cx/cxdm.md §4.6 — EBV rules (boolean coercion in predicate
//     context)
//   - vcx/cx/match_node.v / match_parser.v — MatchNode + verbatim-string
//     arm-field convention
//   - vcx/cx/predicate_expr.v — PredicateExpr + predicate_expr_parse
//
// Strict scope NON-goals at Phase 2.7-standalone (deferred):
//   - Integration with the existing `eval_match_multi_arm` directive
//     evaluator path in `eval.v` — done in a follow-up that swaps the
//     directive-arm walk for a MatchNode + this function.
//   - Full structural pattern matcher (kind + canonical rep equality
// element / atom / wildcard patterns).
//   - Full cx.ProgramExpr body evaluation (Phase 2.x).
// CXPath patterns in arms — evaluated via the path
//     evaluator landing in Phase 2.6.

// ── EvalContext ──────────────────────────────────────────────────────────────

// EvalContext carries the per-call inputs the standalone evaluator
// needs to test arms. Kept intentionally narrow at Phase 2.7-standalone:
//
//   - `scrutinee`        : the stringified form of the value-being-matched
//                          (the `Value` slot in grammar [136]). Compared
//                          byte-for-byte against `MatchArm.pattern` for
//                          `:case` arms. `none` mirrors a predicate-only
//                          MatchNode (`[?match :when …]`).
//   - `scrutinee_node`   : Z79d structural-graft companion — when the
//                          caller (typically the dispatcher hop landing
//                          in Z79e) has the actual parsed `cx.Node`
//                          scrutinee in hand, supplying it here makes
//                          the `:case` structural pattern comparison
//                          LOSSLESS (no emit→reparse round-trip via the
//                          `scrutinee` string). When both are populated
//                          the node form wins for `arm.pattern_node`
//                          comparison; the string form remains the
//                          fallback for unparseable arm patterns + the
//                          wildcard short-circuit logic.
//   - `position`         : optional 1-based position for `$_position`
//                          resolution in predicate bodies. Defaults to 1.
//   - `last`             : optional 1-based final-position for `$_last`
//                          resolution. Defaults to 1.
//   - `attrs`            : attribute map for the value-under-match —
//                          keys are attribute names (no `@`), values are
//                          the stringified attribute values. Drives the
//                          `@name` / `@name OP value` atomic-template
//                          predicate forms. Empty map is safe — every
//                          `@name` test simply fails.
//
// The Phase 2.x integration step extends this struct (or swaps it for
// the production MatchEnv) without changing the public `eval_match`
// signature — callers see a transparent upgrade.
pub struct EvalContext {
pub mut:
	scrutinee      ?string
	scrutinee_node ?cx.Node
	position       int = 1
	last           int = 1
	attrs          map[string]string
}

// new_eval_context constructs an EvalContext with the given scrutinee
// and an empty attribute map. Convenience for the common test shape.
pub fn new_eval_context(scrutinee ?string) EvalContext {
	return EvalContext{
		scrutinee: scrutinee
		position:  1
		last:      1
		attrs:     map[string]string{}
	}
}

// new_eval_context_with_node constructs an EvalContext carrying a
// structural `cx.Node` scrutinee (Z79d structural-graft entry point).
// The string-scrutinee slot is left `none` — callers that want both
// forms can populate `scrutinee` after construction. Convenience for
// dispatcher / Phase 2.x integration tests + the Z79d test surface.
pub fn new_eval_context_with_node(node cx.Node) EvalContext {
	return EvalContext{
		scrutinee:      ?string(none)
		scrutinee_node: ?cx.Node(node)
		position:       1
		last:           1
		attrs:          map[string]string{}
	}
}

// ── MatchResult ──────────────────────────────────────────────────────────────

// MatchArmKindLabel mirrors `cx.ArmKind` as a string label, captured in
// MatchResult so callers / tests can verify which arm fired without
// re-importing `cx`. The three legal values are `'case'`, `'when'`,
// `'else'`. When `matched == false` the field is the empty string.
pub type MatchArmKindLabel = string

// MatchResult is the outcome of `eval_match`. Fields:
//
//   - `matched`     : true iff some arm fired (including `:else`).
//                     `false` iff no arm matched and no `:else` is
// present (the empty-sequence path).
//   - `arm_index`   : index of the arm that fired (0-based), or -1
//                     when `matched == false`.
//   - `arm_kind`    : `'case'` / `'when'` / `'else'` — the kind of arm
//                     that fired. Empty string when `matched == false`.
//   - `body`        : the verbatim body source the firing arm yielded
//                     (the `:yield` body string). Empty when
//                     `matched == false`.
//   - `bound_value` : the scrutinee value captured at the moment the
//                     arm fired (advisory — at Phase 2.7-standalone
//                     this is just the EvalContext.scrutinee passed in,
//                     since structural binding capture is deferred).
pub struct MatchResult {
pub mut:
	matched     bool
	arm_index   int = -1
	arm_kind    MatchArmKindLabel
	body        string
	bound_value ?string
	// Z79d structural-graft companion — when the firing arm carried a
	// parsed `body_node` (some), the standalone evaluator records the
	// `cx.Node` as the structural body value. The Z79e dispatcher hop
	// then surfaces this directly without re-parsing the verbatim
	// `body` string. `none` when the arm body did not parse cleanly
	// or when the firing arm was constructed via the hand-written
	// `new_*_arm` helpers (backward-compat — no parser hop, no node).
	body_value ?cx.Node
}

// new_match_result_none constructs the empty-sequence outcome — used
// when no arm matched and no `:else` was provided.
pub fn new_match_result_none() MatchResult {
	return MatchResult{
		matched:   false
		arm_index: -1
		arm_kind:  ''
		body:      ''
	}
}

// new_match_result_fired constructs a populated outcome record for an
// arm that fired. `body_value` is the Z79d structural-graft slot — set
// when the arm carried a parsed `body_node`; `none` otherwise.
pub fn new_match_result_fired(idx int, kind MatchArmKindLabel, body string,
	bound ?string, body_value ?cx.Node) MatchResult {
	return MatchResult{
		matched:     true
		arm_index:   idx
		arm_kind:    kind
		body:        body
		bound_value: bound
		body_value:  body_value
	}
}

// ── Public entry point ───────────────────────────────────────────────────────

// eval_match_node runs the Phase 2.7-standalone evaluator over a parsed
// MatchNode + EvalContext (first-match-wins). See the
// file-level comment for the full semantic contract. Named `_node` to
// disambiguate from the directive-level `eval_match(d, mut env)` hop
// in `eval.v`; the dispatcher-integration follow-up will route the
// multi-arm directive path through this function.
pub fn eval_match_node(node cx.MatchNode, context EvalContext) !MatchResult {
	mut ctx := context
	// If the MatchNode carries a scrutinee source but the caller didn't
	// pre-populate `ctx.scrutinee`, leave both as-is — the caller is
	// responsible for evaluating the scrutinee expression and threading
	// the resulting string in. The standalone evaluator only sees
	// strings; the production wiring step will replace this with the
	// full eval_node hop.
	_ = node.scrutinee
	for i, arm in node.arms {
		match arm.kind {
			.case_arm {
				if match_arm_case(arm, ctx)! {
					return new_match_result_fired(i, 'case', arm.body,
						ctx.scrutinee, arm.body_node)
				}
			}
			.when_arm {
				if match_arm_when(arm, ctx)! {
					return new_match_result_fired(i, 'when', arm.body,
						ctx.scrutinee, arm.body_node)
				}
			}
			.else_arm {
				return match_arm_else(arm, ctx, i)
			}
		}
	}
	// No arm matched, no :else present → empty-sequence.
	return new_match_result_none()
}

// ── Arm-kind helpers ─────────────────────────────────────────────────────────

// match_arm_case tests a `:case PAT (:where GUARD)?` arm. Returns true
// iff the pattern matches the scrutinee AND (when a guard is present)
// the guard's PredicateExpr evaluates true. Per there is
// NO implicit EBV on the pattern itself — the pattern is a structural
// test (kind + canonical representation equality when
// `arm.pattern_node` is populated by the parser; source-string
// equality fallback otherwise).
fn match_arm_case(arm cx.MatchArm, ctx EvalContext) !bool {
	if arm.kind != .case_arm {
		return error('match_arm_case: arm kind is not :case (got ${cx.arm_kind_name(arm.kind)})')
	}
	pat_trim := arm.pattern.trim_space()
	// Wildcard `_` and bare element-wildcard `*` match any value — these
	// short-circuit the structural test (they would never produce a
	// usable Node from `cx.parse` anyway). Honour wildcard regardless of
	// the structural scrutinee form (wildcard matches any
	// value, no scrutinee binding inspection required).
	mut pattern_matched := pat_trim == '_' || pat_trim == '*'
	if !pattern_matched {
		// Z79d structural-graft path — when the caller threaded a
		// `cx.Node` scrutinee through `EvalContext.scrutinee_node`, we
		// can do a LOSSLESS structural comparison against
		// `arm.pattern_node`. This bypasses the parse-snippet round-trip
		// in the Z79b string-scrutinee path and supports dispatcher
		// integration where the actual evaluated value Node is in hand.
		if scrut_node := ctx.scrutinee_node {
			if pat_node := arm.pattern_node {
				pattern_matched = cx.node_structural_eq(pat_node, scrut_node)
			} else {
				// No structural pattern — fall back to source-string
				// equality against an emitted form of the scrutinee node
				// (best-effort: a single Element renders via emit_cx).
				scrut_str := emit_node_compact(scrut_node)
				pattern_matched = pat_trim == scrut_str.trim_space()
			}
		} else {
			// Z79b path (string scrutinee surface — unchanged for
			// backward compat with the standalone tests).
			scrut := ctx.scrutinee or {
				return error('match_arm_case: :case arm requires a scrutinee (predicate-only mode forbids :case)')
			}
			if pat_node := arm.pattern_node {
				if scrut_node := cx.try_parse_snippet_to_node(scrut) {
					pattern_matched = cx.node_structural_eq(pat_node, scrut_node)
				} else {
					pattern_matched = pat_trim == scrut.trim_space()
				}
			} else {
				pattern_matched = pat_trim == scrut.trim_space()
			}
		}
	}
	if !pattern_matched {
		return false
	}
	// Pattern matched (or wildcard); test guard if present.
	if g := arm.guard {
		// Z79d structural-graft on guard: when the parser populated
		// `arm.guard_node` AND the guard reduces to a recognised
		// structural shape, we still funnel through the
		// PredicateExpr-source interpreter (the structural eval path
		// requires the cxpath_eval.v axis walker which is Phase 2.6
		// territory). The `guard_node` slot is consulted to short-circuit
		// "no node" pre-checks; otherwise the existing source-based
		// interpreter (`eval_arm_predicate_body`) drives. Z79e (dispatcher
		// integration) replaces this stub with the full PredicateExpr →
		// Item filter via `eval_predicate_filter`.
		_ = arm.guard_node
		return eval_arm_predicate_body(g, ctx)!
	}
	return true
}

// emit_node_compact renders a single `cx.Node` to a compact CX-source
// string via the `emit_cx_compact` round-trip over a synthetic Document.
// Used by the Z79d structural-scrutinee fallback when the arm carries
// no `pattern_node` — we serialise the Node so source-string equality
// against the arm's verbatim pattern still functions.
fn emit_node_compact(n cx.Node) string {
	doc := cx.Document{
		prolog:   []cx.Node{}
		doctype:  ?cx.DoctypeDecl(none)
		elements: [n]
	}
	return cx.emit_cx_compact(doc).trim_space()
}

// match_arm_when tests a `:when PREDICATE` arm. Per 
// predicate-only Searched-CASE the scrutinee may be `none` — the
// predicate is EBV'd in isolation. Per the predicate body
// IS evaluated in boolean context (EBV per cxdm.md §4.6) — opposite
// of the no-EBV-in-:case rule.
fn match_arm_when(arm cx.MatchArm, ctx EvalContext) !bool {
	if arm.kind != .when_arm {
		return error('match_arm_when: arm kind is not :when (got ${cx.arm_kind_name(arm.kind)})')
	}
	pred := arm.guard or {
		return error('match_arm_when: :when arm missing predicate body (parser invariant violated)')
	}
	return eval_arm_predicate_body(pred, ctx)!
}

// match_arm_else fires the `:else` fallback arm. Always matches when
// reached (the evaluator only reaches an `:else` arm after every prior
// arm has missed). `idx` is the arm's index in the MatchNode arm list,
// recorded into the MatchResult for debuggability.
fn match_arm_else(arm cx.MatchArm, ctx EvalContext, idx int) !MatchResult {
	if arm.kind != .else_arm {
		return error('match_arm_else: arm kind is not :else (got ${cx.arm_kind_name(arm.kind)})')
	}
	return new_match_result_fired(idx, 'else', arm.body, ctx.scrutinee, arm.body_node)
}

// ── Predicate-body boolean interpreter ───────────────────────────────────────

// eval_arm_predicate_body parses a verbatim predicate-body source string
// via `cx.predicate_expr_parse` and evaluates the resulting
// PredicateExpr to a bool under the EvalContext. Atomic-template
// shapes covered:
//
//   - `attr_test`        : `@name`           → ctx.attrs has key `name`
//   - `attr_compare`     : `@name OP value`  → 6 ops (= != < <= > >=)
//                          where value is a quoted string / int / bool
//                          / bare identifier.
//   - `int_position`     : `N`               → ctx.position == N
//   - `function_call`    : `count(*)`        → 0 (Phase 2.7 placeholder;
//                          there is no child sequence to count under
//                          source-string scrutinee semantics)
//                        : `count(*) OP N`   → 0 OP N
//   - `reserved_binding` : `$_position`      → boolean true iff ctx.position > 0
//                          `$_last`          → boolean true iff ctx.last  > 0
//                          (atomic-only — for compose-into-compare
//                          shapes the Phase 2.x boolean evaluator lands)
//
// Anything else surfaces `MATCH_PREDICATE_EVAL_NOT_YET_IMPLEMENTED` —
// callers (and tests) pin the failure surface deliberately so the
// follow-up phase has a clear migration target.
fn eval_arm_predicate_body(body string, ctx EvalContext) !bool {
	expr := cx.predicate_expr_parse(body) or {
		return error('MATCH_PREDICATE_EVAL_NOT_YET_IMPLEMENTED: cannot parse predicate body `${body}` (${err.msg()})')
	}
	return eval_predicate_expr(expr, ctx)!
}

// eval_predicate_expr evaluates a parsed PredicateExpr against the
// EvalContext. The atomic-template-driven Phase 2.7 surface is listed
// in `eval_arm_predicate_body`'s comment.
fn eval_predicate_expr(p &cx.PredicateExpr, ctx EvalContext) !bool {
	match p.kind {
		.attr_test, .atom_test {
			name := p.name or {
				return error('MATCH_PREDICATE_EVAL: attr_test missing name')
			}
			return name in ctx.attrs
		}
		.attr_compare {
			name := p.name or {
				return error('MATCH_PREDICATE_EVAL: attr_compare missing name')
			}
			op := p.op or {
				return error('MATCH_PREDICATE_EVAL: attr_compare missing op')
			}
			rhs := p.value or {
				return error('MATCH_PREDICATE_EVAL: attr_compare missing value')
			}
			lhs_present := name in ctx.attrs
			if !lhs_present {
				// Per spec/cxdm.md §4.6 EBV, comparing an absent
				// attribute to a value yields false (no error).
				return false
			}
			lhs := ctx.attrs[name]
			return match_compare_strings(lhs, op, rhs)
		}
		.int_position {
			n := p.position or {
				return error('MATCH_PREDICATE_EVAL: int_position missing position')
			}
			return ctx.position == n
		}
		.function_call {
			fn_name := p.name or {
				return error('MATCH_PREDICATE_EVAL: function_call missing name')
			}
			if fn_name != 'count' {
				return error('MATCH_PREDICATE_EVAL_NOT_YET_IMPLEMENTED: function `${fn_name}` not supported at Phase 2.7-standalone')
			}
			// Placeholder count — Phase 2.x replaces with structural
			// child-sequence counting. At standalone scope the scrutinee
			// is a single stringified value; the count is 0 (no
			// children).
			count := 0
			if op_str := p.op {
				rhs_pos := p.position or {
					return error('MATCH_PREDICATE_EVAL: count(*) compare missing RHS')
				}
				return compare_ints(count, op_str, rhs_pos)
			}
			// Bare `count(*)` — non-zero in boolean context. At
			// standalone scope this is always 0, so always false.
			return count != 0
		}
		.reserved_binding {
			name := p.name or {
				return error('MATCH_PREDICATE_EVAL: reserved_binding missing name')
			}
			return match name {
				'\$_position' { ctx.position > 0 }
				'\$_last'     { ctx.last > 0 }
				'\$_'         { ctx.scrutinee != none }
				else          {
					error('MATCH_PREDICATE_EVAL_NOT_YET_IMPLEMENTED: reserved binding `${name}` not supported')
				}
			}
		}
		else {
			return error('MATCH_PREDICATE_EVAL_NOT_YET_IMPLEMENTED: predicate kind `${cx.predicate_expr_kind_name(p.kind)}` not supported at Phase 2.7-standalone')
		}
	}
}

// ── Comparison helpers ───────────────────────────────────────────────────────

// match_compare_strings applies a comparison operator to two string operands
// Numeric-looking values are compared numerically (so
// `@count > 10` works the way users expect); everything else falls
// back to lexicographic string comparison. Quoted RHS values are
// unquoted before comparison.
fn match_compare_strings(lhs string, op string, rhs string) bool {
	rhs_unq := unquote_value(rhs)
	// Numeric path when both sides parse cleanly as ints.
	if l_int := parse_int(lhs) {
		if r_int := parse_int(rhs_unq) {
			return compare_ints(l_int, op, r_int)
		}
	}
	return match op {
		'='  { lhs == rhs_unq }
		'!=' { lhs != rhs_unq }
		'<'  { lhs < rhs_unq }
		'<=' { lhs <= rhs_unq }
		'>'  { lhs > rhs_unq }
		'>=' { lhs >= rhs_unq }
		else { false }
	}
}

// compare_ints applies one of the six comparison operators
// to two ints. Unknown op → false (defensive; the parser already gates
// the op set).
fn compare_ints(lhs int, op string, rhs int) bool {
	return match op {
		'='  { lhs == rhs }
		'!=' { lhs != rhs }
		'<'  { lhs < rhs }
		'<=' { lhs <= rhs }
		'>'  { lhs > rhs }
		'>=' { lhs >= rhs }
		else { false }
	}
}

// unquote_value strips matched leading/trailing `"` or `'` from a
// PredicateExpr.value verbatim source slice. RHS values that aren't
// quoted (ints, identifiers, bools) pass through unchanged.
fn unquote_value(v string) string {
	if v.len < 2 {
		return v
	}
	first := v[0]
	last := v[v.len - 1]
	if (first == `"` && last == `"`) || (first == `'` && last == `'`) {
		return v[1..v.len - 1]
	}
	return v
}

// parse_int returns the int form of a string if it parses cleanly as
// a signed decimal integer; returns none otherwise. V's `s.int()`
// returns 0 on parse failure which is ambiguous with the value `0`,
// so we re-validate the digits before returning.
fn parse_int(s string) ?int {
	t := s.trim_space()
	if t.len == 0 {
		return none
	}
	mut start := 0
	if t[0] == `-` || t[0] == `+` {
		if t.len == 1 {
			return none
		}
		start = 1
	}
	for i := start; i < t.len; i++ {
		c := t[i]
		if c < `0` || c > `9` {
			return none
		}
	}
	return t.int()
}
