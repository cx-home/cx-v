module main

import cx

// Tests for the Phase 2.4 follow-up MatchNode v8 binary codec
// (spec/core/ast-bin.md §4.5, tag 0x14).
//
// Coverage:
//   - Encode-decode round-trip for each arm-kind (case / when / else).
//   - Round-trip for each mode (scrutinee + predicate-only).
//   - Round-trip with empty guard (case arm with no `:where`).
//   - Round-trip with multi-arm chains (5+ arms).
//   - Decode-failure: out-of-range arm_kind, out-of-range mode,
//     truncated, malformed OptString, mode/scrutinee inconsistency,
//     per-arm-kind pattern/guard validity, `:else`-not-last,
//     predicate-only-with-case.
//   - source / loc / arm.loc are NOT preserved through the codec.
//   - Disjoint hash domain: MatchNode bytes start with a different
//     kind byte (0x14) than PathNode (0x13) — different leading byte
//     guarantees disjoint wire-byte domains when tag-prefixed.

// ── Helpers ──────────────────────────────────────────────────────────────────

fn round_trip(node cx.MatchNode) !cx.MatchNode {
	buf := cx.encode_match_node(node)
	mut off := 0
	return cx.decode_match_node(buf, mut off)!
}

// ── 3-arm round-trip (the §6.6 spec worked example shape) ────────────────────

fn test_round_trip_three_arms_case_when_else() {
	m := cx.MatchNode{
		scrutinee: ?string('$status')
		arms: [
			cx.new_case_arm('200', '"OK"'),
			cx.new_when_arm('$status >= 400', '"ERR"'),
			cx.new_else_arm('"UNKNOWN"'),
		]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m), '3-arm round-trip must preserve identity'
	assert got.arms.len == 3
	assert got.arms[0].kind == cx.ArmKind.case_arm
	assert got.arms[0].pattern == '200'
	assert got.arms[0].body == '"OK"'
	assert got.arms[1].kind == cx.ArmKind.when_arm
	if g := got.arms[1].guard {
		assert g == '$status >= 400'
	} else {
		assert false, 'when_arm guard must round-trip'
	}
	assert got.arms[1].body == '"ERR"'
	assert got.arms[2].kind == cx.ArmKind.else_arm
	assert got.arms[2].body == '"UNKNOWN"'
}

// ── Arm-kind coverage (each of the three variants in isolation) ──────────────

fn test_round_trip_single_case_arm() {
	m := cx.MatchNode{
		scrutinee: ?string('$x')
		arms: [
			cx.new_case_arm('1', 'one'),
		]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	assert got.arms.len == 1
	assert got.arms[0].kind == cx.ArmKind.case_arm
}

fn test_round_trip_case_arm_with_guard() {
	m := cx.MatchNode{
		scrutinee: ?string('$x')
		arms: [
			cx.new_case_arm_guarded('$y', '$y > 0', 'positive'),
		]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	if g := got.arms[0].guard {
		assert g == '$y > 0', 'case-arm guard must round-trip'
	} else {
		assert false, 'case-arm with :where must carry guard'
	}
}

fn test_round_trip_single_when_arm() {
	m := cx.MatchNode{
		arms: [
			cx.new_when_arm('$flag', 'truthy'),
		]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	assert got.arms[0].kind == cx.ArmKind.when_arm
	if g := got.arms[0].guard {
		assert g == '$flag'
	} else {
		assert false, 'when_arm guard must round-trip'
	}
}

fn test_round_trip_single_else_arm_with_when() {
	// Else cannot be the first arm in valid CX — we pair with a when
	// arm to keep the wire payload well-formed.
	m := cx.MatchNode{
		arms: [
			cx.new_when_arm('false', 'never'),
			cx.new_else_arm('fallback'),
		]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	assert got.arms[1].kind == cx.ArmKind.else_arm
	assert got.arms[1].body == 'fallback'
	assert got.arms[1].guard == none, 'else_arm guard must be none'
	assert got.arms[1].pattern == '', 'else_arm pattern slot must be empty'
}

// ── Mode coverage (scrutinee + predicate-only) ───────────────────────────────

fn test_round_trip_scrutinee_mode() {
	m := cx.MatchNode{
		scrutinee: ?string('$status')
		arms: [
			cx.new_case_arm('200', 'ok'),
			cx.new_else_arm('other'),
		]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	if s := got.scrutinee {
		assert s == '$status'
	} else {
		assert false, 'scrutinee must round-trip'
	}
}

fn test_round_trip_predicate_only_mode() {
	m := cx.MatchNode{
		// scrutinee = none (predicate-only mode)
		arms: [
			cx.new_when_arm('$x > 0', 'positive'),
			cx.new_when_arm('$x < 0', 'negative'),
			cx.new_else_arm('zero'),
		]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	assert got.scrutinee == none, 'predicate-only mode must round-trip with no scrutinee'
}

// ── Empty guard on case arm ──────────────────────────────────────────────────

fn test_round_trip_case_arm_with_empty_guard() {
	// Constructor leaves guard = none for unguarded case arms.
	m := cx.MatchNode{
		scrutinee: ?string('$v')
		arms: [
			cx.new_case_arm('1', 'one'),
			cx.new_case_arm('2', 'two'),
			cx.new_else_arm('other'),
		]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	assert got.arms[0].guard == none, 'unguarded case arm must have guard=none'
	assert got.arms[1].guard == none, 'unguarded case arm must have guard=none'
}

// ── Multi-arm chain (5+ arms) ────────────────────────────────────────────────

fn test_round_trip_five_arms() {
	m := cx.MatchNode{
		scrutinee: ?string('$n')
		arms: [
			cx.new_case_arm('1', 'one'),
			cx.new_case_arm('2', 'two'),
			cx.new_case_arm_guarded('$x', '$x > 100', 'big'),
			cx.new_when_arm('$n < 0', 'negative'),
			cx.new_else_arm('other'),
		]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	assert got.arms.len == 5
	assert got.arms[0].kind == cx.ArmKind.case_arm
	assert got.arms[2].kind == cx.ArmKind.case_arm
	if g := got.arms[2].guard {
		assert g == '$x > 100'
	} else {
		assert false, 'guarded case must carry guard'
	}
	assert got.arms[3].kind == cx.ArmKind.when_arm
	assert got.arms[4].kind == cx.ArmKind.else_arm
}

fn test_round_trip_seven_arms_no_else() {
	// Multi-arm without an :else trailer is also legal
	// (`:else` is optional; at most one).
	m := cx.MatchNode{
		scrutinee: ?string('$status')
		arms: [
			cx.new_case_arm('200', 'a'),
			cx.new_case_arm('201', 'b'),
			cx.new_case_arm('204', 'c'),
			cx.new_case_arm('301', 'd'),
			cx.new_case_arm('302', 'e'),
			cx.new_case_arm('404', 'f'),
			cx.new_case_arm('500', 'g'),
		]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)
	assert got.arms.len == 7
	for arm in got.arms {
		assert arm.kind == cx.ArmKind.case_arm
	}
}

// ── source / loc / arm.loc exclusion (by symmetry with) ──

fn test_source_and_loc_excluded_from_wire() {
	// Build a MatchNode WITH source + loc + arm.loc populated …
	m := cx.MatchNode{
		scrutinee: ?string('$x')
		arms: [
			cx.MatchArm{
				kind:    cx.ArmKind.case_arm
				pattern: '1'
				body:    'one'
				loc:     cx.MatchLoc{ start: 10, end: 20 }
			},
			cx.MatchArm{
				kind: cx.ArmKind.else_arm
				body: 'other'
				loc:  cx.MatchLoc{ start: 30, end: 40 }
			},
		]
		source: ?string('[?match $x :case 1 :yield one :else :yield other]')
		loc:    ?cx.MatchLoc(cx.MatchLoc{ start: 0, end: 49 })
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }

	// … and assert that after round-trip the advisory fields are
	// reset to none (per by symmetry with 
	// wire form is identity-only).
	assert got.source == none, 'source must not survive the wire'
	assert got.loc == none, 'loc must not survive the wire'
	for arm in got.arms {
		assert arm.loc == none, 'arm.loc must not survive the wire'
	}

	// But identity-participating fields DO round-trip — .eq() ignores
	// source/loc, so the two MatchNodes still compare equal.
	assert got.eq(m), 'identity preserved despite source/loc loss'
}

fn test_encoded_bytes_byte_identical_for_eq_inputs() {
	// Two MatchNodes that differ ONLY in source/loc/arm.loc must
	// encode to byte-identical buffers (spec/core/ast-bin.md §4.5 round-
	// trip contract — equal MatchNodes emit identical wire bytes).
	a := cx.MatchNode{
		scrutinee: ?string('$x')
		arms: [
			cx.new_case_arm('1', 'one'),
		]
		source: ?string('[?match $x :case 1 :yield one]')
	}
	b := cx.MatchNode{
		scrutinee: ?string('$x')
		arms: [
			cx.MatchArm{
				kind:    cx.ArmKind.case_arm
				pattern: '1'
				body:    'one'
				loc:     cx.MatchLoc{ start: 99, end: 199 }
			},
		]
		source: ?string('  [?match  $x  :case  1  :yield  one  ]  ')
		loc:    ?cx.MatchLoc(cx.MatchLoc{ start: 7, end: 42 })
	}
	assert a.eq(b)
	bytes_a := cx.encode_match_node(a)
	bytes_b := cx.encode_match_node(b)
	assert bytes_a == bytes_b, 'eq-MatchNodes must produce byte-identical wire'
}

// ── Decode failure modes ─────────────────────────────────────────────────────

fn test_decode_rejects_out_of_range_mode_byte() {
	// mode byte 0x02 is reserved (valid range is {0x00, 0x01}).
	bad := [u8(0x02),   // mode (reserved)
		u8(0),          // scrutinee absent
		u8(0), u8(0)]   // arm_count = 0
	mut off := 0
	res := cx.decode_match_node(bad, mut off) or {
		assert err.msg().contains('mode'), 'error should mention mode: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject reserved mode byte'
}

fn test_decode_rejects_out_of_range_arm_kind_byte() {
	// Valid mode=predicate-only, scrutinee absent, 1 arm with arm_kind 0x03 (reserved).
	bad := [u8(0x01),     // mode = predicate-only
		u8(0),            // scrutinee absent
		u8(1), u8(0),     // arm_count = 1
		u8(0x03),         // arm_kind (reserved — valid is 0x00..0x02)
		u8(0),            // pattern absent
		u8(0),            // guard absent
		u8(0), u8(0), u8(0), u8(0)] // body str len = 0
	mut off := 0
	res := cx.decode_match_node(bad, mut off) or {
		assert err.msg().contains('arm_kind'), 'error should mention arm_kind: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject reserved arm_kind byte'
}

fn test_decode_rejects_truncated_buffer() {
	// mode byte only — missing scrutinee OptString flag, arm_count, etc.
	bad := [u8(0x00)]
	mut off := 0
	res := cx.decode_match_node(bad, mut off) or {
		// Any error is acceptable; we just need this NOT to succeed.
		return
	}
	_ = res
	assert false, 'decode must reject truncated buffer'
}

fn test_decode_rejects_malformed_optstr_flag() {
	// scrutinee OptString flag 0x05 (invalid — must be 0 or 1).
	bad := [u8(0x00),     // mode = scrutinee
		u8(0x05),         // scrutinee flag (invalid)
		u8(0), u8(0)]     // arm_count = 0
	mut off := 0
	res := cx.decode_match_node(bad, mut off) or {
		assert err.msg().contains('optstr'), 'error should mention optstr: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject invalid OptString flag'
}

fn test_decode_rejects_scrutinee_mode_with_scrutinee_absent() {
	// mode = scrutinee (0x00) but scrutinee absent.
	bad := [u8(0x00),     // mode = scrutinee
		u8(0),            // scrutinee absent (illegal for mode=scrutinee)
		u8(0), u8(0)]     // arm_count = 0
	mut off := 0
	res := cx.decode_match_node(bad, mut off) or {
		assert err.msg().contains('scrutinee'), 'error should mention scrutinee: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject mode=scrutinee with scrutinee absent'
}

fn test_decode_rejects_predicate_only_mode_with_scrutinee_present() {
	// mode = predicate-only (0x01) but scrutinee present.
	bad := [u8(0x01),                          // mode = predicate-only
		u8(1),                                 // scrutinee present (illegal)
		u8(1), u8(0), u8(0), u8(0), u8(`x`),   // scrutinee = "x"
		u8(0), u8(0)]                          // arm_count = 0
	mut off := 0
	res := cx.decode_match_node(bad, mut off) or {
		assert err.msg().contains('scrutinee'), 'error should mention scrutinee: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject mode=predicate-only with scrutinee present'
}

fn test_decode_rejects_case_arm_with_pattern_absent() {
	// arm_kind = case_arm but pattern OptString absent.
	bad := [u8(0x01),               // mode = predicate-only
		u8(0),                      // scrutinee absent
		u8(1), u8(0),               // arm_count = 1
		u8(0x00),                   // arm_kind = case_arm
		u8(0),                      // pattern absent (illegal for case_arm)
		u8(0),                      // guard absent
		u8(0), u8(0), u8(0), u8(0)] // body str len = 0
	mut off := 0
	res := cx.decode_match_node(bad, mut off) or {
		assert err.msg().contains('pattern'), 'error should mention pattern: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject case_arm with pattern absent'
}

fn test_decode_rejects_when_arm_with_pattern_present() {
	// arm_kind = when_arm but pattern OptString present.
	bad := [u8(0x01),                          // mode = predicate-only
		u8(0),                                 // scrutinee absent
		u8(1), u8(0),                          // arm_count = 1
		u8(0x01),                              // arm_kind = when_arm
		u8(1), u8(1), u8(0), u8(0), u8(0), u8(`p`), // pattern present "p" (illegal)
		u8(1), u8(1), u8(0), u8(0), u8(0), u8(`g`), // guard present "g"
		u8(0), u8(0), u8(0), u8(0)]            // body str len = 0
	mut off := 0
	res := cx.decode_match_node(bad, mut off) or {
		assert err.msg().contains('pattern'), 'error should mention pattern: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject when_arm with pattern present'
}

fn test_decode_rejects_when_arm_with_guard_absent() {
	// arm_kind = when_arm requires guard present (the :when predicate body).
	bad := [u8(0x01),               // mode = predicate-only
		u8(0),                      // scrutinee absent
		u8(1), u8(0),               // arm_count = 1
		u8(0x01),                   // arm_kind = when_arm
		u8(0),                      // pattern absent
		u8(0),                      // guard absent (illegal for when_arm)
		u8(0), u8(0), u8(0), u8(0)] // body str len = 0
	mut off := 0
	res := cx.decode_match_node(bad, mut off) or {
		assert err.msg().contains('guard'), 'error should mention guard: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject when_arm with guard absent'
}

fn test_decode_rejects_else_arm_with_guard_present() {
	// arm_kind = else_arm forbids guard.
	bad := [u8(0x01),                          // mode = predicate-only
		u8(0),                                 // scrutinee absent
		u8(1), u8(0),                          // arm_count = 1
		u8(0x02),                              // arm_kind = else_arm
		u8(0),                                 // pattern absent
		u8(1), u8(1), u8(0), u8(0), u8(0), u8(`g`), // guard present (illegal)
		u8(0), u8(0), u8(0), u8(0)]            // body str len = 0
	mut off := 0
	res := cx.decode_match_node(bad, mut off) or {
		assert err.msg().contains('guard'), 'error should mention guard: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject else_arm with guard present'
}

fn test_decode_rejects_else_arm_not_last() {
	// else arm at index 0 with another arm following
	// requires :else to be the last arm.
	bad := [u8(0x01),               // mode = predicate-only
		u8(0),                      // scrutinee absent
		u8(2), u8(0),               // arm_count = 2
		// arm 0: else_arm
		u8(0x02),                   // arm_kind = else_arm
		u8(0),                      // pattern absent
		u8(0),                      // guard absent
		u8(0), u8(0), u8(0), u8(0), // body str len = 0
		// arm 1: when_arm (should be unreachable)
		u8(0x01),                   // arm_kind = when_arm
		u8(0),                      // pattern absent
		u8(1), u8(1), u8(0), u8(0), u8(0), u8(`g`), // guard present "g"
		u8(0), u8(0), u8(0), u8(0)] // body str len = 0
	mut off := 0
	res := cx.decode_match_node(bad, mut off) or {
		assert err.msg().contains('else'), 'error should mention else: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject :else arm not at the end'
}

fn test_decode_rejects_predicate_only_with_case_arm() {
	// mode = predicate-only forbids :case arms.
	bad := [u8(0x01),                          // mode = predicate-only
		u8(0),                                 // scrutinee absent
		u8(1), u8(0),                          // arm_count = 1
		u8(0x00),                              // arm_kind = case_arm (illegal)
		u8(1), u8(1), u8(0), u8(0), u8(0), u8(`1`), // pattern = "1"
		u8(0),                                 // guard absent
		u8(0), u8(0), u8(0), u8(0)]            // body str len = 0
	mut off := 0
	res := cx.decode_match_node(bad, mut off) or {
		assert err.msg().contains('case'), 'error should mention case: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject predicate-only mode with :case arm'
}

// ── Disjoint hash domain vs PathNode ─────────────────────────────────────────

fn test_match_and_path_wire_use_distinct_kind_prefixes() {
	// Even though the codecs are tag-less today (kind byte is prepended
	// only when the producer dispatches through the Node sum-type — see
	// path_node_codec.v and match_node_codec.v header comments), the
	// wire-format spec allocates 0x13 for PathNode and 0x14 for
	// MatchNode. Any tag-prefixed buffer produced under a Node-sum-type
	// dispatcher starts with the kind byte, so the two domains cannot
	// collide. We verify by emitting both codecs and prefixing the
	// reserved kind byte to each — the two resulting buffers must
	// differ in their FIRST byte (guaranteeing disjoint domain by
	// construction).
	match_node := cx.MatchNode{
		scrutinee: ?string('$x')
		arms: [
			cx.new_case_arm('1', 'one'),
		]
	}
	path_node := cx.PathNode{
		form: cx.PathForm.descendant
		steps: [cx.new_path_step(cx.PathAxis.child, 'user')]
	}
	mut match_bytes := [u8(0x14)] // MatchNode kind tag
	match_bytes << cx.encode_match_node(match_node)
	mut path_bytes := [u8(0x13)] // PathNode kind tag
	path_bytes << cx.encode_path_node(path_node)
	assert match_bytes[0] != path_bytes[0],
		'MatchNode (0x14) and PathNode (0x13) tag bytes must differ'
	assert match_bytes != path_bytes
}

// ── Offset advance ───────────────────────────────────────────────────────────

fn test_decode_advances_offset() {
	m := cx.MatchNode{
		scrutinee: ?string('$x')
		arms: [
			cx.new_case_arm('1', 'one'),
			cx.new_else_arm('other'),
		]
	}
	buf := cx.encode_match_node(m)
	mut off := 0
	_ := cx.decode_match_node(buf, mut off) or { panic('decode: ${err}') }
	assert off == buf.len, 'offset must advance past the entire payload (off=${off}, buf.len=${buf.len})'
}

// ── Spec §6.6 worked-example fixture ─────────────────────────────────────────

fn test_round_trip_spec_example_three_arms() {
	// spec/core/ast-bin.md §6.6 worked example: 3-arm match with all three
	// arm kinds + scrutinee mode.
	m := cx.MatchNode{
		scrutinee: ?string('$status')
		arms: [
			cx.new_case_arm('200', '"OK"'),
			cx.new_when_arm('$status >= 400', '"ERR"'),
			cx.new_else_arm('"UNKNOWN"'),
		]
	}
	got := round_trip(m) or { panic('round_trip: ${err}') }
	assert got.eq(m)

	// Independent shape assertions on the encoded bytes — the §6.6
	// example specifies arm_count=3 (`03 00`) and the first arm carries
	// the case_arm kind byte (0x00).
	buf := cx.encode_match_node(m)
	// Layout: u8 mode + OptString scrutinee + u16 arm_count + arms[]
	//   buf[0]            = mode byte
	//   buf[1]            = OptString flag for scrutinee
	//   buf[2..5]         = scrutinee str len (u32 LE)
	//   buf[6..6+len]     = scrutinee bytes
	//   buf[6+len..6+len+2] = arm_count (u16 LE)
	assert buf[0] == u8(0x00), 'mode byte must be 0x00 (scrutinee mode)'
	assert buf[1] == u8(0x01), 'scrutinee OptString flag must be 0x01 (present)'
	// Scrutinee = "$status" (7 bytes) — len bytes 07 00 00 00 at buf[2..6].
	assert buf[2] == u8(0x07)
	assert buf[3] == u8(0x00)
	assert buf[4] == u8(0x00)
	assert buf[5] == u8(0x00)
	// Skip 7 scrutinee bytes — buf[6..13].
	// arm_count at buf[13..15] = 03 00.
	assert buf[13] == u8(0x03)
	assert buf[14] == u8(0x00)
	// First arm starts at buf[15] — arm_kind = 0x00 (case_arm).
	assert buf[15] == u8(0x00), 'first arm kind byte must be 0x00 (case_arm)'
}
