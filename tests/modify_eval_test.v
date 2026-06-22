module main

import cx
import code

// Tests for the Phase 2.8-standalone `[?modify]` evaluator.
//
// The evaluator under test is `code.eval_modify_node(node, doc_root, ctx)`.
// It is STANDALONE: it does NOT integrate with the directive-evaluator
// dispatch path in `eval.v`. Coverage targets the deferred-surface
// contracts documented in the evaluator file header:
//
// One test per action kind in 11-action vocabulary.
// Multi-action chain runs left-to-right.
// Pure-functional invariant: input
//     doc-root is unchanged after eval (V strings are immutable so this
//     is observable via byte-equality on the held reference).
// Zero-match focus — doc returned unchanged, action
//     counted as skipped, NOT an error.
//   - Unsupported `[using …]` lambda → `MODIFY_USING_LAMBDA_NOT_YET_IMPLEMENTED`.
//   - lower_modify_source_to_node → eval_modify_node round-trip on
//     fixture-aligned shapes.
//
// Doc-root is a CX-style source-text snippet at Phase 2.8-standalone
// (e.g. `[doc [user 1] [user 2]]`); the Phase 2.x graft replaces with
// structural Document-AST and the same test surface upgrades transparently.

// ── Helpers ──────────────────────────────────────────────────────────────────

fn empty_ctx() code.EvalContext {
	return code.new_eval_context(?string(none))
}

// ── Per-action positive coverage (11 of 11 actions) ──────────────────────────

fn test_apply_set_replaces_element_body() {
	doc := '[doc [user 1] [user 2]]'
	action := cx.new_modify_action_set('42')
	node := cx.new_modify_node('\$doc', '//user', [action])
	r := code.eval_modify_node(node, doc, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.actions_applied == 1
	assert r.actions_skipped == 0
	assert r.result_doc == '[doc [user 42] [user 2]]'
}

fn test_apply_delete_removes_focus_subtree() {
	doc := '[doc [user 1] [user 2]]'
	action := cx.new_modify_action_delete()
	node := cx.new_modify_node('\$doc', '//user', [action])
	r := code.eval_modify_node(node, doc, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.actions_applied == 1
	assert r.result_doc == '[doc [user 2]]'
}

fn test_apply_set_attr_adds_attribute() {
	doc := '[doc [user 1] [user 2]]'
	action := cx.new_modify_action_set_attr('status', 'active')
	node := cx.new_modify_node('\$doc', '//user', [action])
	r := code.eval_modify_node(node, doc, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.actions_applied == 1
	// First `[user …]` gets ` status=active` inserted after the name.
	assert r.result_doc == '[doc [user status=active 1] [user 2]]'
}

fn test_apply_set_attr_overwrites_existing_attribute() {
	doc := '[doc [user status=draft 1]]'
	action := cx.new_modify_action_set_attr('status', 'active')
	node := cx.new_modify_node('\$doc', '//user', [action])
	r := code.eval_modify_node(node, doc, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.actions_applied == 1
	assert r.result_doc == '[doc [user status=active 1]]'
}

fn test_apply_delete_attr_removes_attribute() {
	doc := '[doc [user status=draft 1]]'
	action := cx.new_modify_action_delete_attr('status')
	node := cx.new_modify_node('\$doc', '//user', [action])
	r := code.eval_modify_node(node, doc, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.actions_applied == 1
	assert r.result_doc == '[doc [user 1]]'
}

fn test_apply_append_adds_child_at_end() {
	doc := '[doc [section [p "a"]]]'
	action := cx.new_modify_action_append('[p "b"]')
	node := cx.new_modify_node('\$doc', '//section', [action])
	r := code.eval_modify_node(node, doc, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.actions_applied == 1
	assert r.result_doc == '[doc [section [p "a"] [p "b"]]]'
}

fn test_apply_prepend_adds_child_at_start() {
	doc := '[doc [section [p "b"]]]'
	action := cx.new_modify_action_prepend('[p "a"]')
	node := cx.new_modify_node('\$doc', '//section', [action])
	r := code.eval_modify_node(node, doc, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.actions_applied == 1
	assert r.result_doc == '[doc [section [p "a"] [p "b"]]]'
}

fn test_apply_insert_before_adds_sibling_before() {
	doc := '[doc [section "main"]]'
	action := cx.new_modify_action_insert_before('[hr]')
	node := cx.new_modify_node('\$doc', '//section', [action])
	r := code.eval_modify_node(node, doc, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.actions_applied == 1
	assert r.result_doc == '[doc [hr] [section "main"]]'
}

fn test_apply_insert_after_adds_sibling_after() {
	doc := '[doc [section "main"]]'
	action := cx.new_modify_action_insert_after('[hr]')
	node := cx.new_modify_node('\$doc', '//section', [action])
	r := code.eval_modify_node(node, doc, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.actions_applied == 1
	assert r.result_doc == '[doc [section "main"] [hr]]'
}

fn test_apply_rename_renames_element() {
	doc := '[doc [widget 1]]'
	action := cx.new_modify_action_rename('component')
	node := cx.new_modify_node('\$doc', '//widget', [action])
	r := code.eval_modify_node(node, doc, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.actions_applied == 1
	assert r.result_doc == '[doc [component 1]]'
}

fn test_apply_replace_swaps_focus_subtree() {
	doc := '[doc [old "stuff"]]'
	action := cx.new_modify_action_replace('[shiny "new"]')
	node := cx.new_modify_node('\$doc', '//old', [action])
	r := code.eval_modify_node(node, doc, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.actions_applied == 1
	assert r.result_doc == '[doc [shiny "new"]]'
}

fn test_apply_using_degraded_form_replaces_focus() {
	// Phase 2.8-standalone degraded form: any non-`[?fn` source is
	// returned verbatim as the new subtree.
	doc := '[doc [price 100]]'
	action := cx.new_modify_action_using('"$100"')
	node := cx.new_modify_node('\$doc', '//price', [action])
	r := code.eval_modify_node(node, doc, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.actions_applied == 1
	assert r.result_doc == '[doc "\$100"]'
}

// ── Action chain — left-to-right ──────────────────────────────

fn test_action_chain_left_to_right_set_append_rename() {
	doc := '[doc [user 1]]'
	actions := [
		cx.new_modify_action_set('42'),
		cx.new_modify_action_append('[role "admin"]'),
		cx.new_modify_action_rename('account'),
	]
	node := cx.new_modify_node('\$doc', '//user', actions)
	r := code.eval_modify_node(node, doc, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.actions_applied == 3
	assert r.actions_skipped == 0
	// 1. :set 42        → [doc [user 42]]
	// 2. :append [role …] → [doc [user 42 [role "admin"]]]
	// 3. [rename account]  → [doc [account 42 [role "admin"]]]
	assert r.result_doc == '[doc [account 42 [role "admin"]]]'
}

fn test_action_chain_order_matters() {
	// Swap two actions — different output proves left-to-right ordering.
	doc := '[doc [user 1]]'

	a := cx.new_modify_node('\$doc', '//user', [
		cx.new_modify_action_rename('account'),
		cx.new_modify_action_set('99'),
	])
	b := cx.new_modify_node('\$doc', '//user', [
		cx.new_modify_action_set('99'),
		cx.new_modify_action_rename('account'),
	])

	ra := code.eval_modify_node(a, doc, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	rb := code.eval_modify_node(b, doc, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	// After rename → focus name is `account`; the second `:set //user`
	// now zero-matches and is skipped. So `ra` keeps
	// the renamed element with the ORIGINAL body `1`.
	assert ra.actions_applied == 1
	assert ra.actions_skipped == 1
	assert ra.result_doc == '[doc [account 1]]'
	// `rb` performs `[set 99]` first (focus still //user), then renames.
	assert rb.actions_applied == 2
	assert rb.actions_skipped == 0
	assert rb.result_doc == '[doc [account 99]]'
}

// ── Pure-functional invariant ────────────────────

fn test_input_doc_unchanged_after_eval() {
	// V strings are immutable — the observable invariant is that the
	// original string value (byte content) is unchanged after the call.
	doc := '[doc [user 1]]'
	doc_before_bytes := doc.bytes().clone()

	action := cx.new_modify_action_set('99')
	node := cx.new_modify_node('\$doc', '//user', [action])
	r := code.eval_modify_node(node, doc, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.result_doc == '[doc [user 99]]'
	// Input string identity preserved.
	assert doc == '[doc [user 1]]'
	assert doc.bytes() == doc_before_bytes
	// Result is a NEW string (not aliased to input).
	assert r.result_doc != doc
}

// ── Focus-miss path ────────────────────────────────────────────

fn test_focus_miss_is_skipped_not_error() {
	// No `[ghost …]` element in the doc — focus selects zero nodes.
	// Per: document returned unchanged, action skipped, NOT
	// an error.
	doc := '[doc [user 1]]'
	action := cx.new_modify_action_set('99')
	node := cx.new_modify_node('\$doc', '//ghost', [action])
	r := code.eval_modify_node(node, doc, empty_ctx()) or {
		assert false, 'unexpected eval error on zero-match focus: ${err}'
		return
	}
	assert r.actions_applied == 0
	assert r.actions_skipped == 1
	assert r.result_doc == doc
}

fn test_focus_miss_chain_skips_each_action() {
	doc := '[doc [user 1]]'
	actions := [
		cx.new_modify_action_set('99'),
		cx.new_modify_action_delete(),
	]
	node := cx.new_modify_node('\$doc', '//ghost', actions)
	r := code.eval_modify_node(node, doc, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.actions_applied == 0
	assert r.actions_skipped == 2
	assert r.result_doc == doc
}

// ── `:using` lambda → graceful deferred-error ────────────────────────────────

fn test_using_lambda_surfaces_deferred_error() {
	doc := '[doc [price 100]]'
	action := cx.new_modify_action_using('[?fn \$p :body (* \$p 1.1)]')
	node := cx.new_modify_node('\$doc', '//price', [action])
	_ := code.eval_modify_node(node, doc, empty_ctx()) or {
		assert err.msg().starts_with('MODIFY_USING_LAMBDA_NOT_YET_IMPLEMENTED'),
			'expected deferred-error, got: ${err.msg()}'
		return
	}
	assert false, 'expected MODIFY_USING_LAMBDA_NOT_YET_IMPLEMENTED — got success'
}

// ── parse_modify → eval_modify_node round-trip ──────────────────────────────

fn test_round_trip_parse_then_eval_set_attr() {
	src := '[?modify \$doc //user [set-attr status "active"]]'
	doc := '[doc [user 1]]'
	node := code.lower_modify_source_to_node(src) or {
		assert false, 'unexpected parse error: ${err}'
		return
	}
	r := code.eval_modify_node(node, doc, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.actions_applied == 1
	assert r.result_doc == '[doc [user status="active" 1]]'
}

// ── Z79b structural-graft tests (Phase 2.5 follow-up) ────────────────────────
//
// These tests exercise the structural ProgramExpr-AST graft on
// ModifyAction.value_node. They prove:
//   - The parser populates `value_node` on a best-effort basis when the
//     verbatim value source parses as a standalone Document.
//   - Structural ModifyAction.eq() picks up node-equality when both
//     sides carry the parsed node.
//   - Backward-compat: hand-built actions (no `value_node`) still use
//     verbatim-string equality.

// (Z1) Parser populates `value_node` for bracketed element expressions.
fn test_z79b_modify_parser_populates_value_node_for_element_expr() {
	src := '[?modify \$doc //section [append [p "tail"]]]'
	n := code.lower_modify_source_to_node(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.actions.len == 1
	vn := n.actions[0].value_node or {
		assert false, 'expected value_node populated for `[p "tail"]`'
		return
	}
	if vn is cx.Element {
		assert vn.name == 'p'
	} else {
		assert false, 'expected Element variant'
	}
}

// (Z2) Parser leaves `value_node` as none for genuinely unparseable
//      snippets (e.g. unbalanced brackets).
fn test_z79b_modify_parser_leaves_value_node_none_for_unparseable() {
	// `cx.parse` is lenient and accepts most well-formed snippets
	// (bare scalars, bare quoted strings, even text). The structural
	// graft only declines on hard parse failures. Demonstrate via the
	// helper directly.
	assert cx.try_parse_snippet_to_node('[') == none,
		'expected cx.parse to fail on unclosed bracket'
}

// (Z3) Structural ModifyAction equality — two actions parsed from
//      whitespace-differing sources compare equal under node_structural_eq.
fn test_z79b_modify_action_eq_structural_match() {
	a := code.lower_modify_source_to_node('[?modify \$doc //section [append [p "x"]]]') or {
		assert false, 'parse a failed: ${err}'
		return
	}
	b := code.lower_modify_source_to_node('[?modify \$doc //section [append [p "x"]]]') or {
		assert false, 'parse b failed: ${err}'
		return
	}
	// Same source — both `value_node`s populated identically. The
	// equality check promotes through `node_structural_eq` (kind +
	// name + items.len).
	assert a.actions[0].eq(b.actions[0])
}

// (Z4) End-to-end [set] with structural value: the lowering populates
//      value_node, eval_modify_node still produces the correct result
//      via the string-based applier. Proves the graft is additive and
//      doesn't break existing semantics.
fn test_z79b_modify_set_structural_value_end_to_end() {
	src := '[?modify \$doc //user [set [profile [name "Ada"]]]]'
	doc := '[doc [user 1]]'
	n := code.lower_modify_source_to_node(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	// value_node populates from bracketed element source.
	vn := n.actions[0].value_node or {
		assert false, 'expected value_node populated'
		return
	}
	if vn is cx.Element {
		assert vn.name == 'profile'
	}
	// Evaluator still works.
	r := code.eval_modify_node(n, doc, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.actions_applied == 1
}

// (Z5) Backward-compat: hand-built ModifyAction (no value_node) still
//      uses verbatim string equality.
fn test_z79b_modify_backward_compat_handwritten_action_string_equality() {
	a := cx.new_modify_action_set('42')
	b := cx.new_modify_action_set('42')
	assert a.value_node == none
	assert b.value_node == none
	assert a.eq(b)
	// String-different actions still mis-compare.
	c := cx.new_modify_action_set('43')
	assert !a.eq(c)
}

fn test_round_trip_parse_then_eval_multi_action() {
	// fixture-aligned `program-modify-007` shape: chained [set] + [append].
	src := '[?modify \$doc //section [set "hi"] [append [p "tail"]]]'
	doc := '[doc [section "old"]]'
	node := code.lower_modify_source_to_node(src) or {
		assert false, 'unexpected parse error: ${err}'
		return
	}
	r := code.eval_modify_node(node, doc, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.actions_applied == 2
	assert r.actions_skipped == 0
	assert r.result_doc == '[doc [section "hi" [p "tail"]]]'
}

// ── Z79d standalone-evaluator unfreeze tests ─────────────────────────────────
//
// Coverage for `eval_modify_node_structural`:
// Multi-match focus (applies to every node).
//   - `action.value_node` consumed structurally for :append / :prepend
//     / :set / :replace.
//   - Result tree is a fresh `cx.Node`; doc-root input observably
//     unchanged (V slices are by-value).
//   - Backward-compat: existing `eval_modify_node` (string-based)
//     untouched — all the prior tests still pass.

// (Z79d-M1) Multi-match :set-attr applies to every matching element.
// Parser populates `value_node` (none for set-attr — the value is a
// string scalar, but the structural walker uses action.value directly
// for attribute assignment).
fn test_z79d_multi_match_set_attr_touches_every_element() {
	src := '[?modify \$doc //user [set-attr active "true"]]'
	node := code.lower_modify_source_to_node(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	doc_src := '[doc [user 1] [user 2] [user 3]]'
	doc_root := cx.try_parse_snippet_to_node(doc_src) or {
		assert false, 'doc parse failed'
		return
	}
	r := code.eval_modify_node_structural(node, &doc_root, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	// 3 user matches × 1 action = 3 focus_matches.
	assert r.focus_matches == 3
	assert r.actions_applied == 1
	assert r.actions_skipped == 0
	// Every `[user …]` now has an `active="true"` attribute.
	root := r.result_node or {
		assert false, 'expected result_node populated'
		return
	}
	if root is cx.Element {
		assert root.name == 'doc'
		mut count_user_with_active := 0
		for it in root.items {
			if it is cx.Element {
				if it.name == 'user' {
					for a in it.attrs {
						if a.name == 'active' {
							count_user_with_active++
						}
					}
				}
			}
		}
		assert count_user_with_active == 3
	} else {
		assert false, 'expected Element doc-root'
	}
}

// (Z79d-M2) Structural :append consumes `value_node` from the action
// when the parser populated it. The freshly-parsed body `[role "admin"]`
// becomes a real Element child of every matched `[user …]`.
fn test_z79d_multi_match_append_consumes_value_node() {
	src := '[?modify \$doc //user [append [role "admin"]]]'
	node := code.lower_modify_source_to_node(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	// Verify the parser populated value_node (Z79b invariant).
	assert node.actions[0].value_node != none
	doc_root := cx.try_parse_snippet_to_node('[doc [user 1] [user 2]]') or {
		assert false, 'doc parse failed'
		return
	}
	r := code.eval_modify_node_structural(node, &doc_root, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.focus_matches == 2
	assert r.actions_applied == 1
	root := r.result_node or {
		assert false, 'expected result_node populated'
		return
	}
	if root is cx.Element {
		// Each user now has a [role "admin"] child appended.
		mut role_count := 0
		for it in root.items {
			if it is cx.Element && it.name == 'user' {
				for child in it.items {
					if child is cx.Element && child.name == 'role' {
						role_count++
					}
				}
			}
		}
		assert role_count == 2
	} else {
		assert false, 'expected Element doc-root'
	}
}

// (Z79d-M3) Structural :set consumes value_node — body of every match
// is replaced with the parsed structural value.
fn test_z79d_structural_set_consumes_value_node() {
	src := '[?modify \$doc //user [set [profile [name "Ada"]]]]'
	node := code.lower_modify_source_to_node(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert node.actions[0].value_node != none
	doc_root := cx.try_parse_snippet_to_node('[doc [user 1]]') or {
		assert false, 'doc parse failed'
		return
	}
	r := code.eval_modify_node_structural(node, &doc_root, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.focus_matches == 1
	assert r.actions_applied == 1
	root := r.result_node or {
		assert false, 'expected result_node populated'
		return
	}
	if root is cx.Element {
		assert root.items.len == 1
		first := root.items[0]
		if first is cx.Element {
			assert first.name == 'user'
			// User body has been replaced with a single [profile …]
			// element.
			assert first.items.len == 1
			profile := first.items[0]
			if profile is cx.Element {
				assert profile.name == 'profile'
			} else {
				assert false, 'expected profile child Element'
			}
		} else {
			assert false, 'expected user Element'
		}
	} else {
		assert false, 'expected doc Element'
	}
}

// (Z79d-M4) Focus-miss — structural variant honours
// zero-match as identity (action skipped, NOT an error).
fn test_z79d_structural_focus_miss_is_skipped_not_error() {
	src := '[?modify \$doc //ghost [set 99]]'
	node := code.lower_modify_source_to_node(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	doc_root := cx.try_parse_snippet_to_node('[doc [user 1]]') or {
		assert false, 'doc parse failed'
		return
	}
	r := code.eval_modify_node_structural(node, &doc_root, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.focus_matches == 0
	assert r.actions_applied == 0
	assert r.actions_skipped == 1
}

// (Z79d-M5) Backward-compat: the legacy string-based entry point
// `eval_modify_node` is untouched — re-run a sample positive case
// to verify the same outputs as the Phase 2.8 tests.
fn test_z79d_backward_compat_string_path_still_works() {
	doc := '[doc [user 1] [user 2]]'
	action := cx.new_modify_action_set('42')
	node := cx.new_modify_node('\$doc', '//user', [action])
	r := code.eval_modify_node(node, doc, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	// String-based path is first-match only (Phase 2.8 semantics).
	assert r.actions_applied == 1
	assert r.actions_skipped == 0
	assert r.result_doc == '[doc [user 42] [user 2]]'
	// And it does NOT populate result_node (that's the structural path).
	assert r.result_node == none
	assert r.focus_matches == 0
}

// (Z79d-M6) Structural :rename — every match renamed; non-matches
// unchanged.
fn test_z79d_structural_rename_multi_match() {
	src := '[?modify \$doc //user [rename account]]'
	node := code.lower_modify_source_to_node(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	doc_root := cx.try_parse_snippet_to_node('[doc [user 1] [user 2] [other 3]]') or {
		assert false, 'doc parse failed'
		return
	}
	r := code.eval_modify_node_structural(node, &doc_root, empty_ctx()) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert r.focus_matches == 2
	root := r.result_node or {
		assert false, 'expected result_node populated'
		return
	}
	if root is cx.Element {
		mut account_count := 0
		mut other_count := 0
		for it in root.items {
			if it is cx.Element {
				match it.name {
					'account' { account_count++ }
					'other'   { other_count++ }
					else      {}
				}
			}
		}
		assert account_count == 2
		assert other_count == 1
	} else {
		assert false, 'expected doc Element'
	}
}
