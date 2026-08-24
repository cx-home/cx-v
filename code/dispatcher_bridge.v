@[has_globals]
module code

import cx

__global (
	// #850 — the match bridge's production-dispatch switch. DEFAULT OFF:
	// `eval_match` no longer routes multi-arm `[?match]` through the Z79f
	// bridge, for the same measured reason the MODIFY half of this bridge
	// retired at #803/#805. Kept as a switch rather than deleted so the
	// equivalence stays CHECKABLE: the differential in
	// code_module_umbrella_test.v runs whole programs with the bridge on and
	// off and requires byte-identical output.
	g_match_bridge_on bool
	// Engagement counter — the live witness that the bridge arm of that
	// differential actually ENGAGED. Without it a differential that silently
	// declined the bridge on every program would compare legacy to legacy and
	// pass while proving nothing (the vacuous shape #851 is about).
	g_match_bridge_engagements u64
)

// match_bridge_enabled reports whether the production `[?match]` hop should
// try the Z79f bridge. False in every shipped build — see the global above.
@[inline]
fn match_bridge_enabled() bool {
	return g_match_bridge_on
}

// set_match_bridge_on toggles the bridge back onto the production dispatch
// hop. Test/diagnostic surface only — the differential harness uses it to run
// both arms in one process.
pub fn set_match_bridge_on(on bool) {
	g_match_bridge_on = on
}

// match_bridge_engagements reports how many times the bridge has produced a
// `[?match]` result in this process. Test/diagnostic surface.
pub fn match_bridge_engagements() u64 {
	return g_match_bridge_engagements
}

// dispatcher_bridge.v — Z79g rock-solid finish of the dispatcher
// integration started in Z79a–Z79f.
//
// This file closes the two structural gaps documented at the
// `eval_match` / `eval_modify` TODO blocks in `eval.v`:
//
//   Gap 1 — `[?modify]` path-precision: standalone
//     `eval_modify_node_structural` reduces the focus path to its
//     final element-name (`target_name_for_focus`), losing multi-step
//     axis composition + predicate filters. Predicate-bearing focus
//     like `//user[@active=false]` reduces to "any user element" at
//     standalone scope, which doesn't match the dispatcher's spec.
//
//     The Gap-1 fix lived here as a path-precise structural
//     evaluator (RETIRED — see the note at the end) that used
//     `vcx/code/cxpath_eval.v::eval_cxpath` to materialise the
//     candidate-node set from a `&CxNode` adapter tree and
//     translates matches back to a positional index path so actions
// apply only to the filtered candidates. multi-match
//     semantics preserved.
//
//   Gap 2 — `[?match]` pattern typing: standalone `match_eval.v`
//     consumes `MatchNode.arms[i].pattern_node ?cx.Node` populated by
//     `cx.parse(...)` (the cx-DATA parser) — which returns
//     `TextNode("200")` for scalar literals. The dispatcher
//     pre-evaluates the scrutinee to `ScalarNode(int_type, 200)`.
//     `node_structural_eq` requires same-variant nodes, so scalar
//     `:case 200` arms never fire.
//
//     Fix here: a re-typer `retype_match_pattern_nodes` that walks
//     the parsed MatchNode, re-parses each `:case` arm's pattern
//     source via the PROGRAM parser, and replaces `pattern_node`
//     with a typed `cx.Node` produced by `eval_node(...)` against
//     an empty env. Same treatment applied to the body slot when
//     it parses cleanly (so `:yield 200` evaluates to
//     ScalarNode(int_type, 200) rather than TextNode).
//
// Live dispatch wiring: `eval.v::eval_match` invokes
// `try_eval_match_via_bridge` first and falls back to the legacy
// implementation when it returns `none`. The MODIFY twin is RETIRED
// (#803/#805 convergence — one modify engine; see the note at the
// end of this file).
//
// Cross-references:
//   - vcx/code/eval.v  — dispatcher hops + Z79f bridge entry points
//   - vcx/code/match_eval.v / modify_eval.v — standalone evaluators
//   - vcx/code/cxpath_eval.v — &CxNode axis walker (Z79e)
//   - vcx/code/program_emit.v — cx.ProgramNode → source emitter (Z79f)
//   - vcx/cx/match_parser.v / modify_parser.v — surface → AST parsers
// (match) (modify) (sharing)

// ── Gap 2 — re-type match pattern nodes via program parser ────────────────────

// program_parse_to_typed_node parses `src` via the PROGRAM parser
// (`code.parse`) and evaluates the resulting cx.ProgramNode against an
// empty MatchEnv via `eval_node`. The result is a typed `cx.Node` —
// e.g. `"200"` → ScalarNode(int_type, 200), `":ok"` → ScalarNode(atom_type, ":ok"),
// `"[user 1]"` → Element{name:"user", items:[ScalarNode(int_type, 1)]}.
//
// Returns `none` when the program parser rejects the source (e.g.
// unbalanced brackets) OR when evaluation surfaces an error (e.g.
// the source references an unbound binding). The caller falls back
// to the cx-data-parsed value or the verbatim string.
//
// The function is conservative: it only evaluates a CLOSED cx.ProgramNode
// (no free bindings). When the pattern source contains `$name`
// bindings (legitimate in `:case` element-with-bind patterns), the
// program-parser path errors out and we keep the cx-data-parsed
// pattern_node intact.
pub fn program_parse_to_typed_node(src string) ?cx.Node {
	trimmed := src.trim_space()
	if trimmed.len == 0 {
		return none
	}
	prog := cx.parse_program(trimmed) or { return none }
	mut env := new_env()
	result := eval_node(prog.body, mut env) or { return none }
	return result
}

// retype_match_pattern_nodes walks a `cx.MatchNode` and replaces each
// `:case` arm's `pattern_node` with a typed cx.Node produced by the
// program parser (when possible). The original cx-data-parsed
// pattern_node is retained as fallback if program parsing fails.
//
// Same treatment applied to arm `body_node` slots — so `:yield 200`
// resolves to a typed ScalarNode that round-trips through render.
//
// Guard slots are left untouched: guards are evaluated via the
// PredicateExpr parser path (`eval_arm_predicate_body` in
// `match_eval.v`), which already handles the typing.
//
// Returns a new MatchNode with patched arms. Source-level fields
// (`scrutinee`, `source`, `loc`) are preserved verbatim.
pub fn retype_match_pattern_nodes(m cx.MatchNode) cx.MatchNode {
	mut new_arms := []cx.MatchArm{cap: m.arms.len}
	for arm in m.arms {
		mut new_arm := arm
		// Pattern slot — only :case arms carry patterns. We try the
		// program parser; on success the typed node replaces the
		// cx-data-parsed one. On failure (e.g. element-with-bind
		// `[user $u]` references unbound $u) we keep the original.
		if arm.kind == cx.ArmKind.case_arm && arm.pattern.len > 0 {
			// First, try to detect patterns that the program parser
			// would mishandle: bind-only `$name` patterns and
			// element-with-bind shapes. These contain free bindings
			// that eval_node would error on. The cx-data-parsed
			// pattern_node is the right shape for these.
			if !pattern_has_free_bindings(arm.pattern) {
				if typed := program_parse_to_typed_node(arm.pattern) {
					new_arm.pattern_node = ?cx.Node(typed)
				}
			}
		}
		// Body slot — re-typed for all arm kinds. The dispatcher hop
		// (eval_match / try_eval_match_via_bridge) re-evaluates the
		// body via eval_node against the dispatcher's MatchEnv anyway,
		// so the structural body_node is advisory. But for arms
		// whose body is a closed literal (e.g. `:yield :ok`), the
		// typed body_node lets the bridge short-circuit the parse
		// step in the common case.
		if arm.body.len > 0 && !pattern_has_free_bindings(arm.body) {
			if typed := program_parse_to_typed_node(arm.body) {
				new_arm.body_node = ?cx.Node(typed)
			}
		}
		new_arms << new_arm
	}
	return cx.MatchNode{
		scrutinee: m.scrutinee
		arms:      new_arms
		source:    m.source
		loc:       m.loc
	}
}

// pattern_has_free_bindings returns true when the source contains a
// `$`-prefixed identifier that the program-parser path would treat
// as an unbound binding. Element-with-bind patterns like `[user $u]`
// AND bind-only patterns like `$u` AND any source containing `$`
// trigger the conservative fallback. Wildcard `_` does not trigger
// (it parses as cx.ProgramCall and evaluates fine via dispatch_call).
fn pattern_has_free_bindings(src string) bool {
	return src.contains('\$')
}

// is_bridge_compatible_case_pattern reports whether the dispatcher
// bridge can route a `:case` arm with this pattern through the
// standalone evaluator (vcx/code/match_eval.v) + Gap-2 retype. The
// bridge supports CLOSED literal patterns (scalars + element literals
// without $-bindings). It declines for shapes that need legacy
// binding-capture or wildcard semantics:
//
//   - cx.ProgramBinding (`$x`)                     — bind-only, no eq test
//   - cx.ProgramPattern (`[name $u]` / `[* …]`)    — pattern shape with
//     binding capture / wildcard heads
//   - cx.ProgramCall (`_()` / `**`)                — wildcard-call shapes
//     the standalone evaluator's wildcard short-circuit can't see
//     after the emit→reparse round-trip (the emitter produces `_()`
//     not `_`, breaking the pat_trim equality test in match_arm_case)
//   - Anything containing a free `$`-binding via the emit→reparse
//     round-trip (conservative source-scan fallback)
pub fn is_bridge_compatible_case_pattern(n cx.ProgramNode) bool {
	match n {
		cx.ProgramBinding {
			return false
		}
		cx.ProgramPattern {
			// Element-shape patterns with binding capture / wildcard
			// heads can't be handled at the standalone scope. Even a
			// "closed" pattern like `[user 1]` won't parse: the
			// program parser requires pattern body items to be `[..]`,
			// `$bind`, `*`, or `**` — it won't accept literal int
			// bodies in pattern position.
			return false
		}
		cx.ProgramCall {
			// `_()` and `**()` shapes — the emit→reparse roundtrip
			// loses the bare-name shape the standalone wildcard
			// short-circuit expects.
			if n.name == '_' || n.name == '*' || n.name == '**' {
				return false
			}
			// Conservative: any call with args might carry side-effects
			// or unbound refs. Decline.
			if n.args.len > 0 {
				return false
			}
			return false
		}
		cx.ProgramLiteral {
			// Scalar / atom literals + closed element literals are
			// bridge-compatible. Scan nested items for free bindings.
			return !has_free_binding_in_literal(n)
		}
		else {
			// PathExpr / Directive / ForComp / Wildcard / cx.Program —
			// not legal in `:case` pattern position per the grammar.
			// Conservative decline.
			return false
		}
	}
}

// has_free_binding_in_literal walks a cx.ProgramLiteral's nested items
// looking for any cx.ProgramBinding or any cx.ProgramPattern (which would
// carry its own free bindings). Returns true when the literal isn't
// fully closed.
fn has_free_binding_in_literal(l cx.ProgramLiteral) bool {
	for it in l.items {
		match it {
			cx.ProgramBinding {
				return true
			}
			cx.ProgramPattern {
				return true
			}
			cx.ProgramLiteral {
				if has_free_binding_in_literal(it) {
					return true
				}
			}
			cx.ProgramCall {
				for a in it.args {
					if a is cx.ProgramBinding {
						return true
					}
				}
			}
			else {}
		}
	}
	return false
}

// ── The modify half of this bridge is RETIRED (#803/#805, 2026-08-13,
// measured convergence) ──────────────────────────────────────────────
//
// eval_modify_node_path_aware + the CxNode adapter chain + the
// index-path applier family lived here as Gap 1's stand-in engine.
// The legacy evaluator (eval.v::eval_modify) was already the
// spec-complete modify engine — this bridge's own decline-list routed
// every hard shape to it — and the gate-30.5 envelope measured it
// LIGHTER (sharing-ratio 3,057 B/match PASS vs 10,588 FAIL). The one
// capability only the bridge carried (#436 directive-as-data
// modifies) is ported to the legacy path. The placeholder &CxNode
// axis engine (cxpath_eval/forward/reverse/misc) and the Item
// predicate evaluator (predicate_eval.v) retired with it — their own
// headers always named them stand-ins pending "the production
// graft"; the production engine IS the graft. Axis/predicate
// semantics stay pinned by the conformance corpus through the real
// walker (xpath_31_parity + the cxpath program families).
//
// ── The MATCH half is now OFF the production hop too (#850, 2026-08-18) ──
//
// It retires on the same argument and the same kind of evidence. The
// legacy evaluator (eval.v::eval_match_multi_arm) is the spec-complete
// match engine, and this bridge's own decline-list already routed every
// hard shape to it: any `:case` pattern carrying a `$` binding, a
// wildcard, or an element head declines. What was left for the bridge
// was the EASY tail — `[else]`-only and scalar-literal cases — and it
// served that tail ~10x slower than the legacy path it declines to,
// because every evaluation re-lowered the directive, re-typed every
// arm's pattern, and re-parsed the winning arm's body from SOURCE.
//
// Measured, `-prod`, per call: `[?match $el [else false]]` (bridge)
// ~14.4 µs against `[case [zzz] …]` (declines to legacy) ~1.4 µs and
// `[case [err @code=$c] …]` (declines) ~1.2 µs. Adding a case made
// `[?match]` FASTER, which is the signature of a slow fast-path.
//
// The function stays — it is still the bridge-feasibility surface its
// own tests drive — and `set_match_bridge_on` puts it back on the hop so
// the equivalence claim is checked rather than asserted.
