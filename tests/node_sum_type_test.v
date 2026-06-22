module main

import cx

// node_sum_type_test.v — Z79a structural graft tests.
//
// MatchNode + ModifyNode joined the `cx.Node` sum-type
// 0030. The standalone codecs (`match_node_codec.v` 0x14 /
// `modify_node_codec.v` 0x15) now route through `binary.v::encode_node`
// + `decode_node` dispatch so a Document carrying these variants
// round-trips via the standard `emit_ast_bin` / `bin_to_doc` envelope.
//
// Wire-format invariants:
//   - Document envelope bumps to v8 ONLY when MatchNode or ModifyNode
//     appears anywhere in the tree (recursively). Documents without
//     these variants stay at v6 — preserves binding compat for the
//     common case.
//   - PathNode wire tag 0x13 is reserved but PathNode is intentionally
//     LEFT OUT of the sum-type at this graft; its codec remains
//     standalone-only.
//
// These tests close the Phase 2.4 / 2.5 "Node sum-type integration"
// follow-up tracked in v0_8_0_status.md.

// ── Helpers ──────────────────────────────────────────────────────────────────

fn make_simple_match_node() cx.MatchNode {
	arms := [
		cx.new_case_arm('200', '[ok]'),
		cx.new_case_arm('404', '[not-found]'),
		cx.new_else_arm('[unknown]'),
	]
	return cx.new_match_node(?string('@status'), arms)
}

fn make_simple_modify_node() cx.ModifyNode {
	actions := [
		cx.new_modify_action_set('hi'),
		cx.new_modify_action_append('[p "tail"]'),
		cx.new_modify_action_rename('renamed'),
	]
	return cx.new_modify_node('doc', '//user', actions)
}

// ── MatchNode round-trip via Node sum-type ───────────────────────────────────

fn test_match_node_round_trip_via_node_sum_type() {
	mn := make_simple_match_node()
	doc := cx.Document{ elements: [cx.Node(mn)] }

	framed := cx.emit_ast_bin(doc)
	// Wire version byte is 8 (MatchNode present forces bump from v6 → v8).
	assert framed[4] == u8(8)

	decoded := cx.bin_to_doc(framed) or {
		assert false, 'bin_to_doc failed: ${err}'
		return
	}
	assert decoded.elements.len == 1
	got := decoded.elements[0]
	assert got is cx.MatchNode, 'expected MatchNode, got ${got.type_name()}'
	got_mn := got as cx.MatchNode
	assert got_mn.eq(mn), 'MatchNode mismatch: got vs original'
}

fn test_modify_node_round_trip_via_node_sum_type() {
	mn := make_simple_modify_node()
	doc := cx.Document{ elements: [cx.Node(mn)] }

	framed := cx.emit_ast_bin(doc)
	// v8 forced by ModifyNode presence.
	assert framed[4] == u8(8)

	decoded := cx.bin_to_doc(framed) or {
		assert false, 'bin_to_doc failed: ${err}'
		return
	}
	assert decoded.elements.len == 1
	got := decoded.elements[0]
	assert got is cx.ModifyNode, 'expected ModifyNode, got ${got.type_name()}'
	got_mn := got as cx.ModifyNode
	assert got_mn.eq(mn), 'ModifyNode mismatch: got vs original'
}

fn test_match_and_modify_in_same_document() {
	mn := make_simple_match_node()
	mo := make_simple_modify_node()
	doc := cx.Document{ elements: [cx.Node(mn), cx.Node(mo)] }

	framed := cx.emit_ast_bin(doc)
	assert framed[4] == u8(8)

	decoded := cx.bin_to_doc(framed) or {
		assert false, 'bin_to_doc failed: ${err}'
		return
	}
	assert decoded.elements.len == 2
	assert decoded.elements[0] is cx.MatchNode
	assert decoded.elements[1] is cx.ModifyNode

	got_mn := decoded.elements[0] as cx.MatchNode
	got_mo := decoded.elements[1] as cx.ModifyNode
	assert got_mn.eq(mn)
	assert got_mo.eq(mo)
}

// ── Version-byte invariants ──────────────────────────────────────────────────

fn test_doc_without_v8_nodes_stays_at_v6() {
	// A plain Document with only legacy Node variants must still emit
	// a v6 envelope — the v8 bump is conditional on MatchNode /
	// ModifyNode presence.
	el := cx.new_element('user', cx.ElementMeta{}, [], [
		cx.Node(cx.TextNode{ value: 'hi' }),
	])
	doc := cx.Document{ elements: [cx.Node(el)] }

	framed := cx.emit_ast_bin(doc)
	assert framed[4] == u8(6), 'expected v6 envelope for plain Document, got ${framed[4]}'

	decoded := cx.bin_to_doc(framed) or {
		assert false, 'bin_to_doc failed: ${err}'
		return
	}
	assert decoded.elements.len == 1
	assert decoded.elements[0] is cx.Element
}

fn test_v8_bump_triggers_on_nested_match_node() {
	// MatchNode nested inside an Element body should still trigger the
	// v8 bump — has_v8_node walks recursively.
	mn := make_simple_match_node()
	inner := cx.new_element('wrapper', cx.ElementMeta{}, [], [cx.Node(mn)])
	doc := cx.Document{ elements: [cx.Node(inner)] }

	framed := cx.emit_ast_bin(doc)
	assert framed[4] == u8(8), 'nested MatchNode must force v8 envelope'

	decoded := cx.bin_to_doc(framed) or {
		assert false, 'bin_to_doc failed: ${err}'
		return
	}
	// Walk into the wrapper element and confirm the MatchNode survived.
	wrapper := decoded.elements[0] as cx.Element
	assert wrapper.items.len == 1
	assert wrapper.items[0] is cx.MatchNode
}

// ── JSON projection for MatchNode / ModifyNode via sum-type dispatch ────────

fn test_match_node_json_via_emitter_dispatch() {
	mn := make_simple_match_node()
	doc := cx.Document{ elements: [cx.Node(mn)] }
	// emit_json walks Node sum-type via json_node; MatchNode now joins.
	out := cx.emit_ast_json(doc)
	assert out.contains('"type":"ProgramMatchExpr"'),
		'expected MatchNode AST-JSON projection in output, got: ${out}'
	assert out.contains('"scrutinee":"@status"')
	assert out.contains('"kind":"case"')
	assert out.contains('"kind":"else"')
}

fn test_modify_node_json_via_emitter_dispatch() {
	mo := make_simple_modify_node()
	doc := cx.Document{ elements: [cx.Node(mo)] }
	out := cx.emit_ast_json(doc)
	assert out.contains('"type":"ProgramModifyExpr"'),
		'expected ModifyNode AST-JSON projection in output, got: ${out}'
	assert out.contains('"doc":"doc"')
	assert out.contains('"focus":"//user"')
	assert out.contains('"kind":"set"')
	assert out.contains('"kind":"append"')
	assert out.contains('"kind":"rename"')
}

// ── Identity preservation across multi-element documents ────────────────────

fn test_multi_match_round_trip_preserves_arm_order() {
	// Build a MatchNode with a longer arm chain; verify decode
	// preserves order (the encode_node / decode_node path goes through
	// match_node_codec.v's `u16:arm_count` + ordered loop).
	mn := cx.new_match_node(?string('$x'), [
		cx.new_case_arm('1', '[one]'),
		cx.new_case_arm_guarded('2', '@active', '[two-active]'),
		cx.new_when_arm('@score > 50', '[high]'),
		cx.new_case_arm('3', '[three]'),
		cx.new_else_arm('[default]'),
	])
	doc := cx.Document{ elements: [cx.Node(mn)] }

	framed := cx.emit_ast_bin(doc)
	decoded := cx.bin_to_doc(framed) or {
		assert false, 'bin_to_doc failed: ${err}'
		return
	}
	got := decoded.elements[0] as cx.MatchNode
	assert got.arms.len == 5
	assert got.arms[0].kind == cx.ArmKind.case_arm
	assert got.arms[1].kind == cx.ArmKind.case_arm
	assert got.arms[2].kind == cx.ArmKind.when_arm
	assert got.arms[3].kind == cx.ArmKind.case_arm
	assert got.arms[4].kind == cx.ArmKind.else_arm
	assert got.eq(mn)
}

fn test_multi_modify_round_trip_preserves_action_order() {
	mo := cx.new_modify_node('doc', '//item', [
		cx.new_modify_action_set_attr('active', 'true'),
		cx.new_modify_action_delete_attr('legacy'),
		cx.new_modify_action_append('[tag "new"]'),
		cx.new_modify_action_replace('[replacement]'),
	])
	doc := cx.Document{ elements: [cx.Node(mo)] }

	framed := cx.emit_ast_bin(doc)
	decoded := cx.bin_to_doc(framed) or {
		assert false, 'bin_to_doc failed: ${err}'
		return
	}
	got := decoded.elements[0] as cx.ModifyNode
	assert got.actions.len == 4
	assert got.actions[0].kind == cx.ModifyActionKind.set_attr
	assert got.actions[1].kind == cx.ModifyActionKind.delete_attr
	assert got.actions[2].kind == cx.ModifyActionKind.append
	assert got.actions[3].kind == cx.ModifyActionKind.replace
	assert got.eq(mo)
}
