module main

import cx

// Tests for the Phase 2.5 follow-up ModifyNode v8 binary codec
// (spec/core/ast-bin.md §4.6, tag 0x15).
//
// Coverage:
//   - Encode-decode round-trip on a 3-action modify (the §6.7 spec
//     worked-example shape).
// Round-trip for each of the 11 action kinds (full 
//     vocabulary coverage).
//   - Round-trip with multi-action chains (5+ actions).
//   - Round-trip with pipeline-implicit doc (empty doc, only focus —
//   - Decode-failure: out-of-range action_kind, truncated buffer,
//     malformed OptString, per-action-kind name/value validity
//     violations.
//   - source / loc / action.loc are NOT preserved through the codec.
//   - Disjoint kind-byte vs PathNode (0x13) + MatchNode (0x14) —
//     different prefix.
//   - Offset advance.
//   - Byte-identical wire for .eq()-equal inputs (advisory fields
// elided by symmetry with).

// ── Helpers ──────────────────────────────────────────────────────────────────

fn round_trip(node cx.ModifyNode) !cx.ModifyNode {
	buf := cx.encode_modify_node(node)
	mut off := 0
	return cx.decode_modify_node(buf, mut off)!
}

// ── 3-action round-trip (the §6.7 spec worked example shape) ─────────────────

fn test_round_trip_three_actions_set_setattr_deleteattr() {
	m := cx.ModifyNode{
		doc:   '\$doc'
		focus: '//user[@id=1]/@name'
		actions: [
			cx.new_modify_action_set('"Alice"'),
			cx.new_modify_action_set_attr('status', '"active"'),
			cx.new_modify_action_delete_attr('stale'),
		]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m), '3-action round-trip must preserve identity'
	assert got.actions.len == 3
	assert got.actions[0].kind == cx.ModifyActionKind.set
	assert got.actions[0].value == '"Alice"'
	assert got.actions[1].kind == cx.ModifyActionKind.set_attr
	assert got.actions[1].name == 'status'
	assert got.actions[1].value == '"active"'
	assert got.actions[2].kind == cx.ModifyActionKind.delete_attr
	assert got.actions[2].name == 'stale'
	assert got.actions[2].value == ''
	assert got.doc == '\$doc'
	assert got.focus == '//user[@id=1]/@name'
}

// ── 11-action-kind coverage matrix ───────────────────────────────────────────

fn test_round_trip_action_set() {
	m := cx.ModifyNode{
		doc:     '\$d'
		focus:   '//x'
		actions: [cx.new_modify_action_set('42')]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	assert got.actions[0].kind == cx.ModifyActionKind.set
	assert got.actions[0].value == '42'
}

fn test_round_trip_action_delete() {
	m := cx.ModifyNode{
		doc:     '\$d'
		focus:   '//x'
		actions: [cx.new_modify_action_delete()]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	assert got.actions[0].kind == cx.ModifyActionKind.delete
	assert got.actions[0].name == ''
	assert got.actions[0].value == ''
}

fn test_round_trip_action_using() {
	m := cx.ModifyNode{
		doc:     '\$d'
		focus:   '//price'
		actions: [cx.new_modify_action_using('[?fn \$p :body (* \$p 1.1)]')]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	assert got.actions[0].kind == cx.ModifyActionKind.using_fn
	assert got.actions[0].value == '[?fn \$p :body (* \$p 1.1)]'
}

fn test_round_trip_action_rename() {
	m := cx.ModifyNode{
		doc:     '\$d'
		focus:   '//widget'
		actions: [cx.new_modify_action_rename('component')]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	assert got.actions[0].kind == cx.ModifyActionKind.rename
	assert got.actions[0].name == 'component'
	assert got.actions[0].value == ''
}

fn test_round_trip_action_set_attr() {
	m := cx.ModifyNode{
		doc:     '\$d'
		focus:   '//user'
		actions: [cx.new_modify_action_set_attr('verified', 'true')]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	assert got.actions[0].kind == cx.ModifyActionKind.set_attr
	assert got.actions[0].name == 'verified'
	assert got.actions[0].value == 'true'
}

fn test_round_trip_action_delete_attr() {
	m := cx.ModifyNode{
		doc:     '\$d'
		focus:   '//user'
		actions: [cx.new_modify_action_delete_attr('temp')]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	assert got.actions[0].kind == cx.ModifyActionKind.delete_attr
	assert got.actions[0].name == 'temp'
	assert got.actions[0].value == ''
}

fn test_round_trip_action_append() {
	m := cx.ModifyNode{
		doc:     '\$d'
		focus:   '//section'
		actions: [cx.new_modify_action_append('[para "tail"]')]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	assert got.actions[0].kind == cx.ModifyActionKind.append
	assert got.actions[0].value == '[para "tail"]'
}

fn test_round_trip_action_prepend() {
	m := cx.ModifyNode{
		doc:     '\$d'
		focus:   '//section'
		actions: [cx.new_modify_action_prepend('[para "head"]')]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	assert got.actions[0].kind == cx.ModifyActionKind.prepend
	assert got.actions[0].value == '[para "head"]'
}

fn test_round_trip_action_insert_before() {
	m := cx.ModifyNode{
		doc:     '\$d'
		focus:   '//item'
		actions: [cx.new_modify_action_insert_before('[item "before"]')]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	assert got.actions[0].kind == cx.ModifyActionKind.insert_before
	assert got.actions[0].value == '[item "before"]'
}

fn test_round_trip_action_insert_after() {
	m := cx.ModifyNode{
		doc:     '\$d'
		focus:   '//item'
		actions: [cx.new_modify_action_insert_after('[item "after"]')]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	assert got.actions[0].kind == cx.ModifyActionKind.insert_after
	assert got.actions[0].value == '[item "after"]'
}

fn test_round_trip_action_replace() {
	m := cx.ModifyNode{
		doc:     '\$d'
		focus:   '//widget'
		actions: [cx.new_modify_action_replace('[component]')]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	assert got.actions[0].kind == cx.ModifyActionKind.replace
	assert got.actions[0].value == '[component]'
}

// ── Multi-action chain (5+ actions) ──────────────────────────────────────────

fn test_round_trip_five_actions() {
	m := cx.ModifyNode{
		doc:   '\$doc'
		focus: '//user'
		actions: [
			cx.new_modify_action_set_attr('status', '"active"'),
			cx.new_modify_action_delete_attr('temp'),
			cx.new_modify_action_append('[note "appended"]'),
			cx.new_modify_action_rename('account'),
			cx.new_modify_action_replace('[archive]'),
		]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	assert got.actions.len == 5
	assert got.actions[0].kind == cx.ModifyActionKind.set_attr
	assert got.actions[1].kind == cx.ModifyActionKind.delete_attr
	assert got.actions[2].kind == cx.ModifyActionKind.append
	assert got.actions[3].kind == cx.ModifyActionKind.rename
	assert got.actions[4].kind == cx.ModifyActionKind.replace
}

fn test_round_trip_eleven_actions_full_vocab() {
	// One of each action kind — exhaustive vocab coverage
	// in a single payload.
	m := cx.ModifyNode{
		doc:   '\$doc'
		focus: '//x'
		actions: [
			cx.new_modify_action_set('1'),
			cx.new_modify_action_delete(),
			cx.new_modify_action_using('[?fn \$x :body \$x]'),
			cx.new_modify_action_rename('y'),
			cx.new_modify_action_set_attr('k', 'v'),
			cx.new_modify_action_delete_attr('k'),
			cx.new_modify_action_append('[a]'),
			cx.new_modify_action_prepend('[b]'),
			cx.new_modify_action_insert_before('[c]'),
			cx.new_modify_action_insert_after('[d]'),
			cx.new_modify_action_replace('[e]'),
		]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	assert got.actions.len == 11
	// Verify each action-kind round-trips to its expected variant
	// in the original source order.
	expected := [
		cx.ModifyActionKind.set,
		cx.ModifyActionKind.delete,
		cx.ModifyActionKind.using_fn,
		cx.ModifyActionKind.rename,
		cx.ModifyActionKind.set_attr,
		cx.ModifyActionKind.delete_attr,
		cx.ModifyActionKind.append,
		cx.ModifyActionKind.prepend,
		cx.ModifyActionKind.insert_before,
		cx.ModifyActionKind.insert_after,
		cx.ModifyActionKind.replace,
	]
	for i, k in expected {
		assert got.actions[i].kind == k, 'action[${i}] kind must round-trip'
	}
}

// ── Pipeline-implicit doc ──────────────────────────────────────

fn test_round_trip_pipeline_implicit_empty_doc() {
	// 1-head shape: doc is the empty string ↔ OptString-absent on wire.
	m := cx.ModifyNode{
		doc:     ''
		focus:   '//user'
		actions: [cx.new_modify_action_set_attr('status', '"verified"')]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	assert got.doc == '', 'pipeline-implicit shape must round-trip with empty doc'
	assert got.focus == '//user'

	// And verify the wire byte: first byte is OptString flag for doc
	// = 0x00 (absent), not 0x01 (present).
	buf := cx.encode_modify_node(m)
	assert buf[0] == u8(0x00), 'pipeline-implicit doc must encode as OptString-absent'
}

fn test_round_trip_canonical_2head_shape() {
	// 2-head shape: doc is non-empty ↔ OptString-present on wire.
	m := cx.ModifyNode{
		doc:     '\$mydoc'
		focus:   '//user'
		actions: [cx.new_modify_action_delete()]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	assert got.doc == '\$mydoc'

	buf := cx.encode_modify_node(m)
	assert buf[0] == u8(0x01), 'canonical 2-head doc must encode as OptString-present'
}

// ── source / loc / action.loc exclusion (by symmetry with) ──

fn test_source_and_loc_excluded_from_wire() {
	// Build a ModifyNode WITH source + loc + action.loc populated …
	m := cx.ModifyNode{
		doc:   '\$doc'
		focus: '//user'
		actions: [
			cx.ModifyAction{
				kind:  cx.ModifyActionKind.set
				value: '1'
				loc:   cx.ModifyLoc{ start: 10, end: 20 }
			},
			cx.ModifyAction{
				kind: cx.ModifyActionKind.delete
				loc:  cx.ModifyLoc{ start: 30, end: 40 }
			},
		]
		source: ?string('[?modify \$doc //user :set 1 :delete]')
		loc:    ?cx.ModifyLoc(cx.ModifyLoc{ start: 0, end: 42 })
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }

	// … and assert that after round-trip the advisory fields are
	// reset to none (per by symmetry with 
	// wire form is identity-only).
	assert got.source == none, 'source must not survive the wire'
	assert got.loc == none, 'loc must not survive the wire'
	for action in got.actions {
		assert action.loc == none, 'action.loc must not survive the wire'
	}

	// But identity-participating fields DO round-trip — .eq() ignores
	// source/loc, so the two ModifyNodes still compare equal.
	assert got.eq(m), 'identity preserved despite source/loc loss'
}

fn test_encoded_bytes_byte_identical_for_eq_inputs() {
	// Two ModifyNodes that differ ONLY in source/loc/action.loc must
	// encode to byte-identical buffers (spec/core/ast-bin.md §4.6 round-
	// trip contract — equal ModifyNodes emit identical wire bytes).
	a := cx.ModifyNode{
		doc:     '\$d'
		focus:   '//x'
		actions: [cx.new_modify_action_set('1')]
		source:  ?string('[?modify \$d //x :set 1]')
	}
	b := cx.ModifyNode{
		doc:   '\$d'
		focus: '//x'
		actions: [
			cx.ModifyAction{
				kind:  cx.ModifyActionKind.set
				value: '1'
				loc:   cx.ModifyLoc{ start: 99, end: 199 }
			},
		]
		source: ?string('  [?modify  \$d  //x  :set  1  ]  ')
		loc:    ?cx.ModifyLoc(cx.ModifyLoc{ start: 7, end: 42 })
	}
	assert a.eq(b)
	bytes_a := cx.encode_modify_node(a)
	bytes_b := cx.encode_modify_node(b)
	assert bytes_a == bytes_b, 'eq-ModifyNodes must produce byte-identical wire'
}

// ── Decode failure modes ─────────────────────────────────────────────────────

fn test_decode_rejects_out_of_range_action_kind_byte() {
	// doc absent, focus = "x", 1 action with action_kind = 0x0B (reserved).
	bad := [u8(0x00),                          // doc absent
		u8(0x01), u8(0x01), u8(0x00), u8(0x00), u8(0x00), u8(`x`), // focus = "x"
		u8(0x01), u8(0x00),                    // action_count = 1
		u8(0x0B),                              // action_kind (reserved — valid 0x00..0x0A)
		u8(0x00),                              // name absent
		u8(0x00)]                              // value absent
	mut off := 0
	res := cx.decode_modify_node(bad, mut off) or {
		assert err.msg().contains('action_kind'), 'error should mention action_kind: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject reserved action_kind byte'
}

fn test_decode_rejects_high_action_kind_byte() {
	bad := [u8(0x00),                          // doc absent
		u8(0x01), u8(0x00), u8(0x00), u8(0x00), u8(0x00), // focus = "" (present, len=0)
		u8(0x01), u8(0x00),                    // action_count = 1
		u8(0xFF),                              // action_kind = 0xFF (highest reserved)
		u8(0x00),                              // name absent
		u8(0x00)]                              // value absent
	mut off := 0
	res := cx.decode_modify_node(bad, mut off) or {
		assert err.msg().contains('action_kind'), 'error should mention action_kind: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject action_kind = 0xFF'
}

fn test_decode_rejects_truncated_buffer() {
	// doc OptString flag only — missing focus, action_count, etc.
	bad := [u8(0x00)]
	mut off := 0
	res := cx.decode_modify_node(bad, mut off) or {
		// Any error is acceptable; we just need this NOT to succeed.
		return
	}
	_ = res
	assert false, 'decode must reject truncated buffer'
}

fn test_decode_rejects_truncated_in_action() {
	// doc absent + focus = "" present + action_count = 1 + partial action.
	bad := [u8(0x00),                          // doc absent
		u8(0x01), u8(0x00), u8(0x00), u8(0x00), u8(0x00), // focus = "" (present, len=0)
		u8(0x01), u8(0x00),                    // action_count = 1
		u8(0x00)]                              // action_kind = 0x00 (set) — but no name/value follow
	mut off := 0
	res := cx.decode_modify_node(bad, mut off) or {
		return
	}
	_ = res
	assert false, 'decode must reject truncated action'
}

fn test_decode_rejects_malformed_optstr_flag() {
	// doc OptString flag 0x05 (invalid — must be 0 or 1).
	bad := [u8(0x05)]
	mut off := 0
	res := cx.decode_modify_node(bad, mut off) or {
		assert err.msg().contains('optstr'), 'error should mention optstr: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject invalid OptString flag'
}

fn test_decode_rejects_set_with_value_absent() {
	// action_kind = set (0x00) requires value present.
	bad := [u8(0x00),                          // doc absent
		u8(0x01), u8(0x00), u8(0x00), u8(0x00), u8(0x00), // focus = "" present, len=0
		u8(0x01), u8(0x00),                    // action_count = 1
		u8(0x00),                              // action_kind = set
		u8(0x00),                              // name absent
		u8(0x00)]                              // value absent (illegal for :set)
	mut off := 0
	res := cx.decode_modify_node(bad, mut off) or {
		assert err.msg().contains('value'), 'error should mention value: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject :set with value absent'
}

fn test_decode_rejects_delete_with_value_present() {
	// action_kind = delete (0x01) forbids value.
	bad := [u8(0x00),                          // doc absent
		u8(0x01), u8(0x00), u8(0x00), u8(0x00), u8(0x00), // focus = "" present, len=0
		u8(0x01), u8(0x00),                    // action_count = 1
		u8(0x01),                              // action_kind = delete
		u8(0x00),                              // name absent
		u8(0x01), u8(0x01), u8(0x00), u8(0x00), u8(0x00), u8(`v`)] // value present "v" (illegal)
	mut off := 0
	res := cx.decode_modify_node(bad, mut off) or {
		assert err.msg().contains('value'), 'error should mention value: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject :delete with value present'
}

fn test_decode_rejects_rename_with_name_absent() {
	// action_kind = rename (0x03) requires name present.
	bad := [u8(0x00),                          // doc absent
		u8(0x01), u8(0x00), u8(0x00), u8(0x00), u8(0x00), // focus = "" present, len=0
		u8(0x01), u8(0x00),                    // action_count = 1
		u8(0x03),                              // action_kind = rename
		u8(0x00),                              // name absent (illegal for :rename)
		u8(0x00)]                              // value absent
	mut off := 0
	res := cx.decode_modify_node(bad, mut off) or {
		assert err.msg().contains('name'), 'error should mention name: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject :rename with name absent'
}

fn test_decode_rejects_rename_with_value_present() {
	// action_kind = rename forbids value.
	bad := [u8(0x00),                          // doc absent
		u8(0x01), u8(0x00), u8(0x00), u8(0x00), u8(0x00), // focus = "" present, len=0
		u8(0x01), u8(0x00),                    // action_count = 1
		u8(0x03),                              // action_kind = rename
		u8(0x01), u8(0x01), u8(0x00), u8(0x00), u8(0x00), u8(`n`), // name = "n"
		u8(0x01), u8(0x01), u8(0x00), u8(0x00), u8(0x00), u8(`v`)] // value present (illegal)
	mut off := 0
	res := cx.decode_modify_node(bad, mut off) or {
		assert err.msg().contains('value'), 'error should mention value: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject :rename with value present'
}

fn test_decode_rejects_set_attr_with_name_absent() {
	// action_kind = set-attr (0x04) requires BOTH name AND value.
	bad := [u8(0x00),                          // doc absent
		u8(0x01), u8(0x00), u8(0x00), u8(0x00), u8(0x00), // focus = "" present, len=0
		u8(0x01), u8(0x00),                    // action_count = 1
		u8(0x04),                              // action_kind = set-attr
		u8(0x00),                              // name absent (illegal for :set-attr)
		u8(0x01), u8(0x01), u8(0x00), u8(0x00), u8(0x00), u8(`v`)] // value = "v"
	mut off := 0
	res := cx.decode_modify_node(bad, mut off) or {
		assert err.msg().contains('name'), 'error should mention name: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject :set-attr with name absent'
}

fn test_decode_rejects_append_with_name_present() {
	// action_kind = append (0x06) forbids name.
	bad := [u8(0x00),                          // doc absent
		u8(0x01), u8(0x00), u8(0x00), u8(0x00), u8(0x00), // focus = "" present, len=0
		u8(0x01), u8(0x00),                    // action_count = 1
		u8(0x06),                              // action_kind = append
		u8(0x01), u8(0x01), u8(0x00), u8(0x00), u8(0x00), u8(`n`), // name present (illegal)
		u8(0x01), u8(0x01), u8(0x00), u8(0x00), u8(0x00), u8(`v`)] // value = "v"
	mut off := 0
	res := cx.decode_modify_node(bad, mut off) or {
		assert err.msg().contains('name'), 'error should mention name: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject :append with name present'
}

fn test_decode_rejects_delete_attr_with_value_present() {
	// action_kind = delete-attr (0x05) requires name, forbids value.
	bad := [u8(0x00),                          // doc absent
		u8(0x01), u8(0x00), u8(0x00), u8(0x00), u8(0x00), // focus = "" present, len=0
		u8(0x01), u8(0x00),                    // action_count = 1
		u8(0x05),                              // action_kind = delete-attr
		u8(0x01), u8(0x01), u8(0x00), u8(0x00), u8(0x00), u8(`n`), // name = "n"
		u8(0x01), u8(0x01), u8(0x00), u8(0x00), u8(0x00), u8(`v`)] // value present (illegal)
	mut off := 0
	res := cx.decode_modify_node(bad, mut off) or {
		assert err.msg().contains('value'), 'error should mention value: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject :delete-attr with value present'
}

// ── Disjoint kind-byte vs PathNode (0x13) + MatchNode (0x14) ─────────────────

fn test_modify_path_match_wire_use_distinct_kind_prefixes() {
	// The wire-format spec allocates 0x13 for PathNode, 0x14 for
	// MatchNode, and 0x15 for ModifyNode. Any tag-prefixed buffer
	// produced under a Node-sum-type dispatcher starts with the kind
	// byte, so the three domains cannot collide. We verify by emitting
	// all three codecs with their kind tags prefixed and asserting
	// that the three resulting buffers differ in their FIRST byte.
	modify_node := cx.ModifyNode{
		doc:     '\$d'
		focus:   '//x'
		actions: [cx.new_modify_action_set('1')]
	}
	match_node := cx.MatchNode{
		scrutinee: ?string('\$x')
		arms: [
			cx.new_case_arm('1', 'one'),
		]
	}
	path_node := cx.PathNode{
		form: cx.PathForm.descendant
		steps: [cx.new_path_step(cx.PathAxis.child, 'user')]
	}
	mut modify_bytes := [u8(0x15)] // ModifyNode kind tag
	modify_bytes << cx.encode_modify_node(modify_node)
	mut match_bytes := [u8(0x14)] // MatchNode kind tag
	match_bytes << cx.encode_match_node(match_node)
	mut path_bytes := [u8(0x13)] // PathNode kind tag
	path_bytes << cx.encode_path_node(path_node)
	assert modify_bytes[0] == u8(0x15)
	assert match_bytes[0] == u8(0x14)
	assert path_bytes[0] == u8(0x13)
	assert modify_bytes[0] != match_bytes[0],
		'ModifyNode (0x15) and MatchNode (0x14) tag bytes must differ'
	assert modify_bytes[0] != path_bytes[0],
		'ModifyNode (0x15) and PathNode (0x13) tag bytes must differ'
	assert match_bytes[0] != path_bytes[0],
		'MatchNode (0x14) and PathNode (0x13) tag bytes must differ'
}

// ── Offset advance ───────────────────────────────────────────────────────────

fn test_decode_advances_offset() {
	m := cx.ModifyNode{
		doc:   '\$d'
		focus: '//user'
		actions: [
			cx.new_modify_action_set('1'),
			cx.new_modify_action_delete(),
		]
	}
	buf := cx.encode_modify_node(m)
	mut off := 0
	_ := cx.decode_modify_node(buf, mut off) or { panic('decode: ${err}') }
	assert off == buf.len, 'offset must advance past the entire payload (off=${off}, buf.len=${buf.len})'
}

// ── Spec §6.7 worked-example fixture ─────────────────────────────────────────

fn test_round_trip_spec_example_three_actions() {
	// spec/core/ast-bin.md §6.7 worked example: 3-action modify
	// (:set + :set-attr + :delete-attr — covers expr-only,
	// name+expr, and name-only slot-presence patterns).
	m := cx.ModifyNode{
		doc:   '\$doc'
		focus: '//user[@id=1]/@name'
		actions: [
			cx.new_modify_action_set('"Alice"'),
			cx.new_modify_action_set_attr('status', '"active"'),
			cx.new_modify_action_delete_attr('stale'),
		]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)

	// Independent shape assertions on the encoded bytes — the §6.7
	// example layout begins with doc OptString-present (0x01) + doc
	// "$doc" (len=4) + focus OptString-present (0x01) + focus
	// "//user[@id=1]/@name" (len=19) + action_count = 3 (0x03 0x00).
	buf := cx.encode_modify_node(m)
	assert buf[0] == u8(0x01), 'doc OptString flag must be 0x01 (present)'
	// doc len: 04 00 00 00 at buf[1..5].
	assert buf[1] == u8(0x04)
	assert buf[2] == u8(0x00)
	assert buf[3] == u8(0x00)
	assert buf[4] == u8(0x00)
	// Skip 4 doc bytes ("$doc") — buf[5..9].
	// focus flag at buf[9] = 0x01 (present).
	assert buf[9] == u8(0x01), 'focus OptString flag must be 0x01 (present)'
	// focus len: 13 00 00 00 (19 bytes) at buf[10..14].
	assert buf[10] == u8(0x13)
	assert buf[11] == u8(0x00)
	assert buf[12] == u8(0x00)
	assert buf[13] == u8(0x00)
	// Skip 19 focus bytes — buf[14..33].
	// action_count at buf[33..35] = 03 00.
	assert buf[33] == u8(0x03)
	assert buf[34] == u8(0x00)
	// First action starts at buf[35] — action_kind = 0x00 (set).
	assert buf[35] == u8(0x00), 'first action kind byte must be 0x00 (set)'
}

// ── Empty focus / empty value edge cases ─────────────────────────────────────

fn test_round_trip_empty_focus_present() {
	// Empty focus encodes as a length-0 OptString-present (not absent
	// — focus is always present on the wire even when empty, per
	// §4.6 "Focus slot — always present on a well-formed ModifyNode").
	m := cx.ModifyNode{
		doc:     '\$d'
		focus:   ''
		actions: [cx.new_modify_action_delete()]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	assert got.focus == ''
}

fn test_round_trip_complex_focus_and_value() {
	// CXPath with predicates + nested-bracket value — round-trips
	// verbatim despite bracket characters in the UTF-8 payload.
	m := cx.ModifyNode{
		doc:   '\$d'
		focus: '//user[@id=1 and @active=true][1]/@name'
		actions: [
			cx.new_modify_action_set('[upcase \$\$@name]'),
			cx.new_modify_action_using('[?fn \$x :body (concat "_" \$x)]'),
		]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	assert got.focus == '//user[@id=1 and @active=true][1]/@name'
	assert got.actions[0].value == '[upcase \$\$@name]'
	assert got.actions[1].value == '[?fn \$x :body (concat "_" \$x)]'
}
