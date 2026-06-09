module code

import cx

// modify_eval.v — STANDALONE `[?modify]` evaluator (v0.8.0)
// Phase 2.8. Mirrors the Phase 2.7-standalone shape of `match_eval.v` —
// a self-contained surface that does NOT yet integrate with the
// directive-evaluator dispatch path in `eval.v` (which still operates on
// the cx.ProgramDirective / ProgramState surface). Wiring the
// AST-level `cx.ModifyNode` evaluator into the dispatcher is a follow-up
// step bundled with the Phase 2.x cx.ProgramExpr-AST graft on action arg
// slots + the structural sharing optimisation.
//
// What this file provides:
//
//   - `pub struct ModifyResult` — outcome record: post-modify document
//     source string + counts of actions applied / actions skipped (the
// focus-miss path — "If the path selects zero nodes
//     the document is returned unchanged (not an error)").
//   - `pub fn eval_modify_node(node cx.ModifyNode, doc_root string,
//     context EvalContext) !ModifyResult` — the public entry point.
// Walks the action list left-to-right; each action's
//     output becomes the next action's input (pipeline-like at the action
//     granularity within a single ModifyNode).
//
// Semantic surface at Phase 2.8-standalone (conservative simplifications
// per the Phase 2.5 verbatim-string action-slot convention):
//
//   - Doc-root: a CX source-text snippet (e.g. `[doc [user 1] [user 2]]`).
//     Phase 2.x replaces with structural Document-AST.
//   - Focus: the verbatim source of the CXPath focus expression is parsed
//     via `cx.parse_path`. Resolution is a stringy walk that looks for
//     a single element by node-test name (the final step's node-test).
//     If the focus references multi-step path semantics beyond the
//     Phase 2.8-standalone scope (e.g. nested step composition,
//     attribute focus distinct from element focus), the evaluator falls
//     back to a simple-name-match over the doc-root source — sufficient
//     for the Phase 2.8 test surface, deliberately limited to keep the
//     scope contained.
// Per: zero-match focus → document returned unchanged,
//     action counted as skipped (NOT an error).
//   - Actions: every action operates on the focus span in the doc-root
// string; the action produces a new doc-root string
// pure-functional semantics. Structural sharing is
//     elided — Phase 2.x graft replaces full-copy semantics with the
//     spine-copy algorithm.
//   - `:using` accepts a degraded form: the lambda body is returned
//     verbatim as the new subtree (no actual lambda evaluation). If the
//     value source contains `[?fn` (i.e. an actual function literal),
//     the evaluator surfaces `MODIFY_USING_LAMBDA_NOT_YET_IMPLEMENTED` —
//     Phase 2.x cx.ProgramExpr graft + closure evaluator close this gap.
//
// Unsupported focus / action shapes surface a `MODIFY_*_NOT_YET_IMPLEMENTED`
// error so the test layer pins the failure surface deliberately and the
// follow-up phase has a clear migration target.
//
// Pure-functional contract:
//   - `doc_root` is a `string`; V strings are immutable so the input is
//     observably unchanged after eval.
//   - `ModifyResult.result_doc` is a freshly-constructed string.
//
// Cross-references:
//   - vcx/cx/modify_node.v + modify_parser.v (Phase 2.5 AST + parser)
//   - vcx/code/match_eval.v (Phase 2.7-standalone evaluator template;
//     EvalContext defined there is reused here)
//
// Strict scope NON-goals at Phase 2.8-standalone (deferred):
//   - Integration with `eval.v` directive-evaluator dispatch.
//   - Structural sharing — full-copy at Phase 2.8; spine-copy in v0.8.x.
//   - Full cx.ProgramExpr evaluation in action arg slots (Phase 2.x).
//   - `:using` lambda evaluation — placeholder degraded form only.
// Multi-match focus ("applies to every node") — Phase 2.x
//     graft once the PathNode evaluator (Phase 2.6) lands.
//   - Attribute-axis vs child-element axis distinct resolution (D7).

// ── ModifyResult ─────────────────────────────────────────────────────────────

// ModifyResult is the outcome of `eval_modify_node`. Fields:
//
//   - `result_doc`       : the post-modify document source string. Equal
//                          to `doc_root` when every action was skipped
// (zero-match focus or no-op
//                          replace-with-self).
//   - `actions_applied`  : count of actions that produced a structural
//                          change in the doc (focus matched + action
//                          ran to completion).
//   - `actions_skipped`  : count of actions whose focus matched zero
// nodes — the doc passes through
//                          unchanged, NOT an error.
pub struct ModifyResult {
pub mut:
	result_doc       string
	actions_applied  int
	actions_skipped  int
	// Z79d structural-graft companion — when the caller invoked the
	// structural entry point `eval_modify_node_structural`, the resulting
	// doc-root `cx.Node` is recorded here. `none` for the legacy
	// string-based entry point (`eval_modify_node`). The Z79e dispatcher
	// integration consumes this directly without going through a
	// re-parse of `result_doc`.
	result_node ?cx.Node
	// Z79d structural-graft companion — number of focus matches visited
	// by the structural walker per action chain ("applies
	// to every node"). For the string-based entry point this stays 0.
	// For the structural entry point it reflects the cumulative count
	// of focus-matches across the action chain. Useful for tests that
	// pin multi-match semantics.
	focus_matches int
}

// new_modify_result_identity constructs a no-op result — used when no
// actions were applied (e.g. focus zero-match on every action). The
// `result_doc` is identical to the input `doc_root`.
fn new_modify_result_identity(doc_root string) ModifyResult {
	return ModifyResult{
		result_doc:      doc_root
		actions_applied: 0
		actions_skipped: 0
	}
}

// ── Public entry point ───────────────────────────────────────────────────────

// eval_modify_node runs the Phase 2.8-standalone evaluator over a parsed
// ModifyNode + doc-root string. Action chain runs left-to-right;
// each action's output is the next action's input.
//
// `context` is the shared `EvalContext` defined in `match_eval.v`. The
// Phase 2.8-standalone surface does not yet thread context through any
// action handler (no predicate evaluation in actions; no scrutinee /
// position lookup) — the parameter is accepted to keep the signature
// uniform with the sibling evaluators and to receive the Phase 2.x graft
// transparently.
//
// Returns `error('MODIFY_*_NOT_YET_IMPLEMENTED')` for action / focus
// shapes outside the Phase 2.8-standalone scope (see file header).
pub fn eval_modify_node(node cx.ModifyNode, doc_root string, context EvalContext) !ModifyResult {
	mut current := doc_root
	mut applied := 0
	mut skipped := 0
	_ = context
	for action in node.actions {
		focus_span := locate_focus(current, node.focus) or {
			// Zero-match focus: document unchanged,
			// action counted as skipped. NOT an error.
			skipped++
			continue
		}
		new_doc := apply_action(current, focus_span, action)!
		if new_doc == current {
			// Action recognised but no structural change (rare; e.g.
			// `:set` with identical value). Still counted as applied.
			applied++
		} else {
			applied++
			current = new_doc
		}
	}
	return ModifyResult{
		result_doc:      current
		actions_applied: applied
		actions_skipped: skipped
	}
}

// ── Focus resolution ─────────────────────────────────────────────────────────

// FocusSpan describes the byte-range slice of the focus element in the
// doc-root source, plus the element name (used by attribute-axis actions
// that need to insert into the open-tag rather than the body span).
//
// At Phase 2.8-standalone the focus model is a single contiguous span:
//   - `start` / `end` enclose the full focus subtree, INCLUDING the
//     opening `[name` and closing `]`.
//   - `body_start` / `body_end` enclose the body region between the
//     element name (and attribute block) and the closing `]` — the
//     insertion target for `:append` / `:prepend`.
//   - `name` is the element name token (drives `:rename` + `:set-attr` /
//     `:delete-attr` attribute-block rewrites).
struct FocusSpan {
mut:
	start      int
	end        int
	body_start int
	body_end   int
	name       string
}

// locate_focus parses the focus source via `cx.parse_path` and walks the
// doc-root source for a single element whose name matches the focus's
// final node-test. Returns `none` for zero-match and
// surfaces an error for parse failures / unsupported focus shapes.
//
// Phase 2.8-standalone simplifications (documented per file header):
//   - The focus is reduced to its final-step node-test name.
//   - Multi-step path semantics are not enforced — `//user/@name` and
//     `//user` both resolve to "find a `[user …]` element by name."
//   - Attribute-step focus is NOT distinct from element-step focus at
//     this layer. The Phase 2.x graft introduces the structural
// distinction.
fn locate_focus(doc_root string, focus_src string) ?FocusSpan {
	if focus_src.len == 0 {
		return none
	}
	// Best-effort: parse the focus path so future grafts can drop in.
	// Failures fall back to a literal-name extraction.
	mut target_name := extract_target_name(focus_src)
	if path := cx.parse_path(focus_src) {
		if name := path_final_node_test_name(path) {
			target_name = name
		}
	}
	if target_name.len == 0 {
		return none
	}
	return find_element_by_name(doc_root, target_name)
}

// path_final_node_test_name returns the final-step element-name node-test
// from a PathNode, when present. None for paths whose final step is a
// wildcard / kind-test / attribute-axis with no clean element-name.
fn path_final_node_test_name(p cx.PathNode) ?string {
	if p.steps.len == 0 {
		return none
	}
	last := p.steps[p.steps.len - 1]
	// Per `vcx/cx/path_node.v`, a step carries a node-test source slot.
	// The wildcard form is `*`; kind tests look like `element()` / `node()` etc.
	t := last.node_test.trim_space()
	if t.len == 0 || t == '*' {
		return none
	}
	if t.contains('(') {
		// kind-test like `element()` — name is not an element name.
		return none
	}
	// Attribute-axis steps carry the name in node_test too — strip the
	// leading `@` if it slipped through.
	if t.starts_with('@') {
		return t[1..]
	}
	return t
}

// extract_target_name pulls a bareword element-name from the focus
// source verbatim — fallback when `cx.parse_path` doesn't surface a
// usable name. Walks the source byte-by-byte and returns the LAST
// bareword token (the last step's node-test in `//user/@name` style).
fn extract_target_name(focus_src string) string {
	mut last_name := ''
	mut i := 0
	bytes := focus_src.bytes()
	for i < bytes.len {
		b := bytes[i]
		if is_name_start_byte(b) {
			start := i
			i++
			for i < bytes.len && is_name_cont_byte(bytes[i]) {
				i++
			}
			last_name = focus_src[start..i]
			continue
		}
		// Skip predicates `[...]` so `//user[@id=1]` doesn't pick up
		// `id` as the last bareword.
		if b == `[` {
			mut depth := 1
			i++
			for i < bytes.len && depth > 0 {
				if bytes[i] == `[` {
					depth++
				} else if bytes[i] == `]` {
					depth--
				}
				i++
			}
			continue
		}
		i++
	}
	return last_name
}

// find_element_by_name walks `doc` for the FIRST `[name …]` element
// matching `name`. Returns `none` when no such element is found.
// Bracket-depth aware so a nested element with the same name as a
// parent doesn't confuse the scan.
fn find_element_by_name(doc string, name string) ?FocusSpan {
	bytes := doc.bytes()
	mut i := 0
	for i < bytes.len {
		if bytes[i] != `[` {
			i++
			continue
		}
		// At an open bracket — try to read the element name.
		elem_start := i
		i++ // past `[`
		// Skip leading whitespace (rare but permitted).
		for i < bytes.len && is_ws_byte(bytes[i]) {
			i++
		}
		if i >= bytes.len || !is_name_start_byte(bytes[i]) {
			// Not an element form — continue scanning.
			i = elem_start + 1
			continue
		}
		name_start := i
		for i < bytes.len && is_name_cont_byte(bytes[i]) {
			i++
		}
		elem_name := doc[name_start..i]
		// Body region starts here (after the name).
		body_start := i
		// Walk to the matching closing `]`.
		mut depth := 1
		mut j := i
		for j < bytes.len && depth > 0 {
			if bytes[j] == `[` {
				depth++
			} else if bytes[j] == `]` {
				depth--
				if depth == 0 {
					break
				}
			}
			j++
		}
		if depth != 0 {
			// Malformed input — no matching `]`. Bail out.
			return none
		}
		body_end := j
		elem_end := j + 1
		if elem_name == name {
			return FocusSpan{
				start:      elem_start
				end:        elem_end
				body_start: body_start
				body_end:   body_end
				name:       elem_name
			}
		}
		// Not the target — descend into the element body to keep scanning
		// for a nested match (depth-first).
		i = body_start
		// Continue inner scan until we exit this element. The outer loop
		// will resume past `body_end` once we drop out.
		_ = body_end
	}
	return none
}

// ── Action dispatch ──────────────────────────────────────────────────────────

// apply_action invokes the per-action handler for the given action kind
// against the focus span in `current`. Returns the updated doc string.
// Surfaces `MODIFY_*_NOT_YET_IMPLEMENTED` for action shapes that need
// the Phase 2.x graft.
fn apply_action(current string, focus FocusSpan, action cx.ModifyAction) !string {
	return match action.kind {
		.set           { apply_set(current, focus, action.value) }
		.delete        { apply_delete(current, focus) }
		.using_fn      { apply_using(current, focus, action.value)! }
		.rename        { apply_rename(current, focus, action.name) }
		.set_attr      { apply_set_attr(current, focus, action.name, action.value) }
		.delete_attr   { apply_delete_attr(current, focus, action.name) }
		.append        { apply_append(current, focus, action.value) }
		.prepend       { apply_prepend(current, focus, action.value) }
		.insert_before { apply_insert_before(current, focus, action.value) }
		.insert_after  { apply_insert_after(current, focus, action.value) }
		.replace       { apply_replace(current, focus, action.value) }
	}
}

// ── Action helpers ───────────────────────────────────────────────────────────

// apply_set replaces the focus element's body content with `new_value`.
// Per `:set` on an element path replaces the body; the
// distinct attribute-step case (replace attribute value) is folded into
// the same handler at Phase 2.8 — see file header for the structural
// distinction deferred to Phase 2.x.
fn apply_set(doc string, focus FocusSpan, new_value string) string {
	// Replace the body region with ` new_value` — preserve the leading
	// space when the new value is non-empty so we render `[user 42]` not
	// `[user42]`.
	leading := if new_value.len > 0 { ' ' } else { '' }
	return doc[..focus.body_start] + leading + new_value + doc[focus.body_end..]
}

// apply_delete removes the entire focus subtree from the doc. Adjacent
// whitespace is collapsed so `[a [b] [c]]` minus `[b]` becomes `[a [c]]`
// (single inter-child space preserved).
fn apply_delete(doc string, focus FocusSpan) string {
	mut start := focus.start
	mut end := focus.end
	// Eat one leading whitespace byte if present (collapses inter-child
	// space). Don't eat past the element opening `[`.
	if start > 0 && is_ws_byte(doc.bytes()[start - 1]) {
		start--
	}
	return doc[..start] + doc[end..]
}

// apply_set_attr writes / overwrites attribute `name=value` on the focus
// element's open-tag. The Phase 2.8-standalone form serialises the attr
// inline at the start of the element body as `[name attr=value …]`.
// Phase 2.x graft introduces the structural attribute-block per
// `spec/canonical.md`.
fn apply_set_attr(doc string, focus FocusSpan, attr_name string, attr_value string) string {
	// Look for an existing `attr_name=…` token in the body. Replace if
	// present; otherwise insert after the element name.
	body := doc[focus.body_start..focus.body_end]
	if span := find_attr_token(body, attr_name) {
		abs_start := focus.body_start + span.start
		abs_end := focus.body_start + span.end
		new_attr := '${attr_name}=${attr_value}'
		return doc[..abs_start] + new_attr + doc[abs_end..]
	}
	// Insert ` name=value` directly after the element name.
	insertion := ' ${attr_name}=${attr_value}'
	return doc[..focus.body_start] + insertion + doc[focus.body_start..]
}

// apply_delete_attr removes the named attribute token from the focus
// element's body region. If the attribute isn't present the doc passes
// through unchanged.
fn apply_delete_attr(doc string, focus FocusSpan, attr_name string) string {
	body := doc[focus.body_start..focus.body_end]
	span := find_attr_token(body, attr_name) or { return doc }
	abs_start := focus.body_start + span.start
	mut abs_end := focus.body_start + span.end
	// Eat one leading whitespace byte so we don't leave `[user  email]`
	// after removing the middle attr.
	if abs_start > 0 && is_ws_byte(doc.bytes()[abs_start - 1]) {
		return doc[..abs_start - 1] + doc[abs_end..]
	}
	return doc[..abs_start] + doc[abs_end..]
}

// apply_append inserts `child_src` as the LAST child of the focus
// element body. Whitespace is normalised so `[a]` + `[b]` → `[a [b]]`.
fn apply_append(doc string, focus FocusSpan, child_src string) string {
	// Append before the closing `]` (= focus.body_end). Insert a leading
	// space if the body has content; otherwise just the child src.
	body := doc[focus.body_start..focus.body_end]
	prefix := if body.trim_space().len > 0 { ' ' } else { ' ' }
	return doc[..focus.body_end] + prefix + child_src + doc[focus.body_end..]
}

// apply_prepend inserts `child_src` as the FIRST child of the focus
// element body — right after the element name (and attribute block).
fn apply_prepend(doc string, focus FocusSpan, child_src string) string {
	// Insert ` child_src` right after the element name (= focus.body_start).
	insertion := ' ${child_src}'
	return doc[..focus.body_start] + insertion + doc[focus.body_start..]
}

// apply_insert_before inserts `sibling_src` as a sibling of the focus
// element, immediately before it.
fn apply_insert_before(doc string, focus FocusSpan, sibling_src string) string {
	return doc[..focus.start] + sibling_src + ' ' + doc[focus.start..]
}

// apply_insert_after inserts `sibling_src` as a sibling of the focus
// element, immediately after it.
fn apply_insert_after(doc string, focus FocusSpan, sibling_src string) string {
	return doc[..focus.end] + ' ' + sibling_src + doc[focus.end..]
}

// apply_rename renames the focus element while keeping attributes + body
// (":rename Name — rename element (keep attrs + body)").
// The Phase 2.8-standalone form scans the focus span for the original
// name token at body_start's adjacent prefix and rewrites in place.
fn apply_rename(doc string, focus FocusSpan, new_name string) string {
	// The original name span is [name_start, body_start) where name_start
	// is computed by re-walking the focus open tag — focus.body_start is
	// the byte after the element name token, and focus.start+1 is the
	// byte after the opening `[` (possibly preceded by whitespace which
	// we skip).
	bytes := doc.bytes()
	mut name_start := focus.start + 1
	for name_start < bytes.len && is_ws_byte(bytes[name_start]) {
		name_start++
	}
	return doc[..name_start] + new_name + doc[focus.body_start..]
}

// apply_replace swaps the entire focus subtree (from `[name …]` open
// through closing `]`) with `replacement_src` verbatim.
fn apply_replace(doc string, focus FocusSpan, replacement_src string) string {
	return doc[..focus.start] + replacement_src + doc[focus.end..]
}

// apply_using accepts a degraded Phase 2.8-standalone form of `:using`:
// when the source is a simple verbatim value (no `[?fn` keyword) it is
// returned as the new subtree, equivalent to `:replace`. Source that
// contains `[?fn` surfaces `MODIFY_USING_LAMBDA_NOT_YET_IMPLEMENTED` —
// Phase 2.x cx.ProgramExpr graft + closure evaluator close this gap.
fn apply_using(doc string, focus FocusSpan, fn_src string) !string {
	if fn_src.contains('[?fn') {
		return error('MODIFY_USING_LAMBDA_NOT_YET_IMPLEMENTED: :using lambda evaluation is deferred to Phase 2.x (got `${fn_src}`)')
	}
	// Degraded form: treat the source as the replacement value.
	return apply_replace(doc, focus, fn_src)
}

// ── Attribute-token helpers ──────────────────────────────────────────────────

// AttrSpan is the byte-range of an attribute token (`name=value`) inside
// an element body, relative to the body region.
struct AttrSpan {
mut:
	start int
	end   int
}

// find_attr_token scans `body` (the body region of an element) for an
// `attr_name=` token. Returns the token's span (relative to `body`) on
// success. Bracket-depth aware so child elements aren't searched.
fn find_attr_token(body string, attr_name string) ?AttrSpan {
	bytes := body.bytes()
	mut i := 0
	mut depth := 0
	target := attr_name + '='
	target_bytes := target.bytes()
	for i < bytes.len {
		b := bytes[i]
		if b == `[` {
			depth++
			i++
			continue
		}
		if b == `]` {
			if depth > 0 {
				depth--
			}
			i++
			continue
		}
		if depth != 0 {
			i++
			continue
		}
		// Match `attr_name=` at this position, gated by word-boundary
		// on the left (start-of-body or whitespace).
		if (i == 0 || is_ws_byte(bytes[i - 1])) && body.len - i >= target_bytes.len
			&& body[i..i + target_bytes.len] == target {
			start := i
			i += target_bytes.len
			// Consume the value — bareword, quoted string, or bracketed.
			val_end := consume_attr_value(bytes, i)
			return AttrSpan{
				start: start
				end:   val_end
			}
		}
		i++
	}
	return none
}

// consume_attr_value advances past an attribute value starting at `i`.
// Handles quoted strings, bracketed bodies, and bare tokens (run of
// non-whitespace, non-`]`).
fn consume_attr_value(bytes []u8, start int) int {
	mut i := start
	if i >= bytes.len {
		return i
	}
	b := bytes[i]
	if b == `"` || b == `'` {
		quote := b
		i++
		for i < bytes.len && bytes[i] != quote {
			if bytes[i] == `\\` && i + 1 < bytes.len {
				i += 2
				continue
			}
			i++
		}
		if i < bytes.len {
			i++ // closing quote
		}
		return i
	}
	if b == `[` {
		mut depth := 1
		i++
		for i < bytes.len && depth > 0 {
			if bytes[i] == `[` {
				depth++
			} else if bytes[i] == `]` {
				depth--
				if depth == 0 {
					i++
					return i
				}
			}
			i++
		}
		return i
	}
	// Bare value.
	for i < bytes.len && !is_ws_byte(bytes[i]) && bytes[i] != `]` {
		i++
	}
	return i
}

// ── Byte-class predicates ────────────────────────────────────────────────────

@[inline]
fn is_ws_byte(b u8) bool {
	return b == ` ` || b == `\t` || b == `\n` || b == `\r`
}

@[inline]
fn is_name_start_byte(b u8) bool {
	return (b >= `a` && b <= `z`) || (b >= `A` && b <= `Z`) || b == `_`
}

@[inline]
fn is_name_cont_byte(b u8) bool {
	return is_name_start_byte(b) || (b >= `0` && b <= `9`) || b == `-`
}

// ── Z79d structural-graft entry point ────────────────────────────────────────
//
// Standalone-evaluator unfreeze (Wave 21 Z79d): the string-based
// `eval_modify_node` above is preserved for backward-compat with the
// Phase 2.8 unit tests (which exercise byte-level doc-root rewrites
// and the 11-action coverage matrix). `eval_modify_node_structural`
// is the new structural variant — operates on a `cx.Node` doc-root,
// consumes `ModifyAction.value_node` when populated, and supports
// MULTI-MATCH focus "applies to every node".
//
// What this entry point unblocks (Z79e dispatcher integration):
//   - Multi-match focus: `[?modify //user :set @active true]` now
//     touches every `[user …]` element in the doc-root, not just the
//     first. The string-based path is `find_element_by_name`-first-hit
//     only; the structural path walks every Element with matching name
//     (best-effort: final node-test name; CXPath axis composition is
//     Phase 2.6 territory).
//   - Structural value-application: `action.value_node` (populated by
//     `parse_modify` per Z79b) is grafted directly into the tree for
//     `:set` / `:append` / `:prepend` / `:insert-before` /
//     `:insert-after` / `:replace`. No emit-then-reparse round-trip.
//   - Action-arg evaluation deferred: action arg slots are still
//     verbatim (Phase 2.x cx.ProgramExpr-AST graft replaces); but when
//     `value_node` is some, that parsed Node IS the new value. The
//     evaluator does not recurse into cx.ProgramExpr evaluation at the
//     standalone scope — Z79e wires the eval.v `eval_node` hop in.
//
// Backward-compat: this function is additive. The existing
// `eval_modify_node(node, doc_root_string, ctx)` continues to drive the
// 11-action Phase 2.8 coverage matrix unchanged.

// eval_modify_node_structural runs the action chain over a parsed
// `cx.Node` doc-root, returning a `ModifyResult` whose `result_node`
// slot carries the post-modify Node tree. `result_doc` is also
// populated (via `cx.emit_cx_compact` over a synthetic Document
// wrapping the result Node) so callers that want the source string
// form get it for free. zero-match semantics honoured
// the action is counted as skipped, NOT an error.
pub fn eval_modify_node_structural(node cx.ModifyNode, doc_root &cx.Node,
	context EvalContext) !ModifyResult {
	_ = context
	mut current := *doc_root
	mut applied := 0
	mut skipped := 0
	mut matches := 0
	// when focus terminates at `/@attr`, the element
	// target is the parent step's name and the action carries the
	// attribute name. `:set "X"` is rewritten to `:set-attr <attr> "X"`.
	fk := focus_kind_for(node.focus)
	target_name := if fk.element_target.len > 0 {
		fk.element_target
	} else {
		target_name_for_focus(node.focus)
	}
	if target_name.len == 0 {
		// Empty / unresolvable focus → all actions skip per D3.
		return ModifyResult{
			result_doc:      emit_node_compact_doc(current)
			result_node:     ?cx.Node(current)
			actions_applied: 0
			actions_skipped: node.actions.len
			focus_matches:   0
		}
	}
	for raw_action in node.actions {
		action := rewrite_action_for_attribute_tail(raw_action, fk.attr_name)
		matched_this_action := count_matches(current, target_name)
		if matched_this_action == 0 {
			// zero-match → identity, action skipped.
			skipped++
			continue
		}
		// Apply the action structurally to every match in document order
		// (D3 "applies to every node"). The structural rewriter returns
		// a freshly-allocated Node tree (full-copy
		// v0.8.0 ships full-copy first).
		new_root := apply_action_structural(current, target_name, action)!
		current = new_root
		matches += matched_this_action
		applied++
	}
	return ModifyResult{
		result_doc:      emit_node_compact_doc(current)
		result_node:     ?cx.Node(current)
		actions_applied: applied
		actions_skipped: skipped
		focus_matches:   matches
	}
}

// emit_node_compact_doc renders a single `cx.Node` to a compact-CX
// source string via `cx.emit_cx_compact` over a synthetic Document.
// Mirrors the helper of the same name in `match_eval.v` (the two
// evaluators each carry a local copy to avoid cross-module
// dependency churn; the canonical helper lands in `vcx/cx` when the
// dispatcher integration consolidates).
fn emit_node_compact_doc(n cx.Node) string {
	doc := cx.Document{
		prolog:   []cx.Node{}
		doctype:  ?cx.DoctypeDecl(none)
		elements: [n]
	}
	return cx.emit_cx_compact(doc).trim_space()
}

// target_name_for_focus reduces the focus source to its final-step
// element-name node-test. Reuses `cx.parse_path` for the structured
// case and `extract_target_name` for the bareword fallback. Returns
// the empty string when the focus is empty / unresolvable.
fn target_name_for_focus(focus_src string) string {
	if focus_src.len == 0 {
		return ''
	}
	mut target_name := extract_target_name(focus_src)
	if path := cx.parse_path(focus_src) {
		if name := path_final_node_test_name(path) {
			target_name = name
		}
	}
	return target_name
}

// FocusKind captures whether the focus path terminates at an Element
// step (`//user`) or an attribute-axis step (`//user/@name`). Used to
// dispatch `:set` over `/@attr` to attribute-update semantics per
struct FocusKind {
	element_target string // element-name node-test of the parent / terminal step
	attr_name      string // empty unless final step is attribute-axis
}

// focus_kind_for parses the focus source and returns (element_target,
// attr_name?). When the final step is `@attr`, element_target is the
// PARENT step's name and attr_name is set. Otherwise element_target
// is the final step's name and attr_name is empty.
fn focus_kind_for(focus_src string) FocusKind {
	if focus_src.len == 0 {
		return FocusKind{}
	}
	path := cx.parse_path(focus_src) or {
		return FocusKind{ element_target: target_name_for_focus(focus_src) }
	}
	if path.steps.len == 0 {
		return FocusKind{}
	}
	last := path.steps[path.steps.len - 1]
	final_test := last.node_test.trim_space()
	if last.axis == .attribute || final_test.starts_with('@') {
		// Attribute-axis tail. Strip @ and use parent step's name.
		mut attr := final_test
		if attr.starts_with('@') { attr = attr[1..] }
		if path.steps.len >= 2 {
			parent := path.steps[path.steps.len - 2]
			pname := parent.node_test.trim_space()
			if pname.len > 0 && pname != '*' && !pname.contains('(') {
				return FocusKind{ element_target: pname, attr_name: attr }
			}
		}
		// Single-step `@attr` — no element target available; caller falls back.
		return FocusKind{ attr_name: attr }
	}
	return FocusKind{ element_target: target_name_for_focus(focus_src) }
}

// rewrite_action_for_attribute_tail transforms `:set VAL` into
// `:set-attr <attr_name> VAL` when the focus path terminates at
// `/@attr`. Other actions pass through unchanged
// the apply-to-element dispatch handles `:set-attr` / `:delete-attr`
// natively.
fn rewrite_action_for_attribute_tail(action cx.ModifyAction, attr_name string) cx.ModifyAction {
	if attr_name.len == 0 {
		return action
	}
	if action.kind == cx.ModifyActionKind.set {
		return cx.ModifyAction{
			kind:       cx.ModifyActionKind.set_attr
			name:       attr_name
			value:      action.value
			value_node: action.value_node
			loc:        action.loc
		}
	}
	return action
}

// count_matches walks the doc tree and returns the count of Element
// nodes whose `name` matches `target`. Used by the multi-match focus
// path to drive both the zero-match detection and the
// running tally exposed on `ModifyResult.focus_matches`.
fn count_matches(root cx.Node, target string) int {
	if root is cx.Element {
		mut n := 0
		if root.name == target {
			n++
		}
		for item in root.items {
			n += count_matches(item, target)
		}
		return n
	}
	return 0
}

// apply_action_structural walks the doc-root tree and applies `action`
// to every Element whose name matches `target` (multi-match).
// Returns a freshly-allocated Node tree (full-copy).
fn apply_action_structural(root cx.Node, target string,
	action cx.ModifyAction) !cx.Node {
	if root is cx.Element {
		mut el := cx.Element{
			name:  root.name
			attrs: root.attrs.clone()
			items: []cx.Node{cap: root.items.len}
			meta:  root.meta
			table: root.table
		}
		// Recurse into children first so nested matches are applied in
		// document order.
		for item in root.items {
			el.items << apply_action_structural(item, target, action)!
		}
		if el.name == target {
			return apply_action_to_element(el, action)!
		}
		return cx.Node(el)
	}
	// Non-Element nodes: nothing to descend into; return as-is.
	return root
}

// apply_action_to_element applies one ModifyAction to a single matched
// Element. Honours the Z79b `value_node` slot when populated for the
// element-shape action kinds (:set / :append / :prepend / :replace /
// :insert-before / :insert-after); falls back to the verbatim string
// path via `try_parse_snippet_to_node` otherwise.
//
// Attribute-axis actions (`:set-attr` / `:delete-attr`) operate on the
// element's `attrs` slice directly using string ScalarValue. `:rename`
// rewrites `name`. `:delete` returns a sentinel — but at the
// single-Element scope we honour it as "empty Element with same name"
// since the structural variant operates on a single rewritten tree
// (the multi-match deletion case is intentionally simplified at the
// standalone scope; the dispatcher hop in Z79e refines this).
fn apply_action_to_element(el cx.Element, action cx.ModifyAction) !cx.Node {
	return match action.kind {
		.set {
			apply_set_structural(el, action)
		}
		.delete {
			// Standalone-scope simplification: replace body with empty
			// — a true structural deletion requires sibling-list
			// rewriting at the parent, which the dispatcher hop in Z79e
			// handles via a multi-pass walker. The string-based entry
			// point's `apply_delete` is the canonical deletion surface
			// at Phase 2.8-standalone.
			cx.Node(cx.Element{ name: el.name, attrs: el.attrs })
		}
		.using_fn {
			apply_using_structural(el, action)!
		}
		.rename {
			mut renamed := cx.Element{
				name:  action.name
				attrs: el.attrs
				items: el.items
				meta:  el.meta
				table: el.table
			}
			cx.Node(renamed)
		}
		.set_attr {
			apply_set_attr_structural(el, action)
		}
		.delete_attr {
			apply_delete_attr_structural(el, action)
		}
		.append {
			apply_append_structural(el, action)
		}
		.prepend {
			apply_prepend_structural(el, action)
		}
		.insert_before {
			// Structural sibling-insertion lives at parent scope; at
			// element scope we degrade to an append for the standalone
			// surface. Z79e refines via a parent-aware walker.
			apply_append_structural(el, action)
		}
		.insert_after {
			apply_append_structural(el, action)
		}
		.replace {
			value_node_or_parse(action) or {
				return error('MODIFY_REPLACE_STRUCTURAL: value_node unavailable + source unparseable (got `${action.value}`)')
			}
		}
	}
}

// value_node_or_parse extracts the structural value for an action,
// preferring `action.value_node` (populated by `parse_modify` per
// Z79b). Falls back to `cx.try_parse_snippet_to_node(action.value)`
// when the slot is `none` (e.g. for hand-built actions via the
// `new_modify_action_*` constructors that do not populate the slot).
// Returns `none` if neither path yields a parseable Node.
fn value_node_or_parse(action cx.ModifyAction) ?cx.Node {
	if vn := action.value_node {
		return vn
	}
	return cx.try_parse_snippet_to_node(action.value)
}

// apply_set_structural replaces the body of `el` with the action's
// structural value (consumes `value_node` when present). When the
// value parses as an Element, the body becomes a single-item slice
// containing that element; scalar / text values become single-item
// bodies too. When neither `value_node` nor `try_parse_snippet_to_node`
// yields a Node (e.g. action.value is empty), the body is cleared —
// matches the string-based `apply_set` "body replaced" semantics.
fn apply_set_structural(el cx.Element, action cx.ModifyAction) cx.Node {
	new_items := if vn := value_node_or_parse(action) {
		[vn]
	} else {
		// Empty-value :set clears body.
		[]cx.Node{}
	}
	return cx.Node(cx.Element{
		name:  el.name
		attrs: el.attrs
		items: new_items
		meta:  el.meta
		table: el.table
	})
}

// apply_using_structural — `:using` lambda is deferred at standalone
// scope. When the value source contains `[?fn`, surface the same
// MODIFY_USING_LAMBDA_NOT_YET_IMPLEMENTED error as the string path.
// Otherwise treat as `:replace`.
fn apply_using_structural(el cx.Element, action cx.ModifyAction) !cx.Node {
	if action.value.contains('[?fn') {
		return error('MODIFY_USING_LAMBDA_NOT_YET_IMPLEMENTED: :using lambda evaluation is deferred to Phase 2.x (got `${action.value}`)')
	}
	return value_node_or_parse(action) or {
		return error('MODIFY_USING_STRUCTURAL: value unparseable (got `${action.value}`)')
	}
}

// apply_set_attr_structural sets / overwrites attribute `action.name`
// with `action.value` (as a string ScalarValue). Reuses Element's
// attribute slice directly.
fn apply_set_attr_structural(el cx.Element, action cx.ModifyAction) cx.Node {
	mut new_attrs := []cx.Attribute{cap: el.attrs.len + 1}
	mut found := false
	for a in el.attrs {
		if a.name == action.name {
			new_attrs << cx.Attribute{
				name:  action.name
				value: cx.ScalarValue(action.value)
			}
			found = true
		} else {
			new_attrs << a
		}
	}
	if !found {
		new_attrs << cx.Attribute{
			name:  action.name
			value: cx.ScalarValue(action.value)
		}
	}
	return cx.Node(cx.Element{
		name:  el.name
		attrs: new_attrs
		items: el.items
		meta:  el.meta
		table: el.table
	})
}

// apply_delete_attr_structural removes the named attribute from `el`.
// No-op when the attribute is absent (mirrors the string-based path).
fn apply_delete_attr_structural(el cx.Element, action cx.ModifyAction) cx.Node {
	mut new_attrs := []cx.Attribute{cap: el.attrs.len}
	for a in el.attrs {
		if a.name != action.name {
			new_attrs << a
		}
	}
	return cx.Node(cx.Element{
		name:  el.name
		attrs: new_attrs
		items: el.items
		meta:  el.meta
		table: el.table
	})
}

// apply_append_structural appends the action's structural value as
// the LAST child of `el.items`. When `value_node` is absent and the
// fallback parse fails, the action is a no-op (returns the element
// unchanged) — matches the string-based path's tolerant behaviour.
fn apply_append_structural(el cx.Element, action cx.ModifyAction) cx.Node {
	mut new_items := el.items.clone()
	if vn := value_node_or_parse(action) {
		new_items << vn
	}
	return cx.Node(cx.Element{
		name:  el.name
		attrs: el.attrs
		items: new_items
		meta:  el.meta
		table: el.table
	})
}

// apply_prepend_structural inserts the action's structural value as
// the FIRST child of `el.items`.
fn apply_prepend_structural(el cx.Element, action cx.ModifyAction) cx.Node {
	mut new_items := []cx.Node{cap: el.items.len + 1}
	if vn := value_node_or_parse(action) {
		new_items << vn
	}
	for it in el.items {
		new_items << it
	}
	return cx.Node(cx.Element{
		name:  el.name
		attrs: el.attrs
		items: new_items
		meta:  el.meta
		table: el.table
	})
}
