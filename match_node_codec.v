module cx

// match_node_codec.v — v8 binary wire codec for MatchNode.
//
// Closes the Phase 2.4 TODO in match_node.v ("binary (ast_bin) codec —
// wire-format slot allocation pending, analogous to the PathNode
// follow-up tracked at Phase 1.7+"). Implements the §4.5 wire layout
// from spec/core/ast-bin.md for kind discriminator 0x14 (MatchNode),
// version-byte slot v8 (rides on the same v8 byte as PathNode — no
// version bump, additive kind allocation per spec/core/ast-bin.md §2.1
// forward-compatibility convention).
//
// Wire shape (per spec/core/ast-bin.md §4.5, v8+):
//
//   u8         : mode               (0x00 scrutinee, 0x01 predicate-only)
//   OptString  : scrutinee          (present iff mode == 0x00)
//   u16 LE     : arm_count
//   MatchArm × arm_count
//
//   MatchArm:
//     u8        : arm_kind          (0x00 case_arm, 0x01 when_arm,
//                                    0x02 else_arm)
//     OptString : pattern           (present iff arm_kind == 0x00)
//     OptString : guard             (case_arm: optional `:where` body;
//                                    when_arm: always present (the
//                                    `:when` predicate body, stored in
//                                    MatchArm.guard per match_node.v);
//                                    else_arm: always absent)
//     String    : body              (u32 LE byte length + UTF-8 verbatim
//                                    `:yield` body source — always
//                                    present for every arm kind)
//
// Endianness, OptString flag (0/1), and length-prefixed strings
// (u32 LE byte length + UTF-8) all match the existing conventions in
// binary.v + path_node_codec.v.
//
// Pattern / guard slot semantics at v0.8.0 Phase 2.4.
// Spec §4.5 says pattern / guard / body slots carry "the verbatim
// source-text snippet" — mirroring the PathPredicate `source`
// convention in §4.4. The Phase 2.x ProgramExpr-AST graft will
// replace these strings with encode_node-dispatched node bytes
// without bumping the version byte; cap-bit-36 readers MUST tolerate
// the Phase-2.4 string-shape during the v0.8.0-dev window.
//
// Advisory fields elided (per by symmetry with):
//   - MatchNode.source / MatchNode.loc (top-level advisory)
//   - MatchArm.loc                     (per-arm advisory)
// Equal MatchNodes (under .eq()) emit byte-identical buffers.
//
// Cross-references:
//   - spec/core/ast-bin.md §2.1 (v8 history — MatchNode joins v8) and §4.5
//     (MatchNode layout) and §6.6 (3-arm worked example)
//   - vcx/cx/match_node.v (MatchNode / MatchArm / ArmKind struct
//     definitions encoded here field-for-field)
//   - vcx/cx/path_node_codec.v (template — same OptString +
//     LE conventions; same standalone-codec layering)
//   - vcx/cx/binary.v (BinBuf / AstReader conventions reused here)

// ── Wire constants (mirroring spec/core/ast-bin.md §4.5 tables) ───────────────────

// Mode discriminator bytes per the MatchNode mode table.
const match_mode_scrutinee = u8(0x00)
const match_mode_predicate_only = u8(0x01)

// Arm-kind discriminator bytes per the MatchArm arm-kind table.
const match_arm_kind_case = u8(0x00)
const match_arm_kind_when = u8(0x01)
const match_arm_kind_else = u8(0x02)

// Highest legal arm-kind byte (0x03..0xFF reserved).
const match_arm_kind_byte_max = u8(0x02)

// ── ArmKind ↔ byte ────────────────────────────────────────────────────────────

fn match_arm_kind_to_byte(k ArmKind) u8 {
	return match k {
		.case_arm { match_arm_kind_case }
		.when_arm { match_arm_kind_when }
		.else_arm { match_arm_kind_else }
	}
}

fn match_arm_kind_from_byte(b u8) ?ArmKind {
	return match b {
		match_arm_kind_case { ?ArmKind(ArmKind.case_arm) }
		match_arm_kind_when { ?ArmKind(ArmKind.when_arm) }
		match_arm_kind_else { ?ArmKind(ArmKind.else_arm) }
		else                { none }
	}
}

// ── Encode ────────────────────────────────────────────────────────────────────

// encode_match_node returns the §4.5 wire payload for a MatchNode (the
// tag-0x14 byte is NOT prefixed; callers that dispatch over a Node
// sum-type prepend 0x14 themselves). Advisory fields (source / loc /
// arm.loc) are excluded (symmetric with)
// equal MatchNodes (under .eq()) emit byte-identical buffers.
pub fn encode_match_node(node MatchNode) []u8 {
	mut b := BinBuf{}
	encode_match_node_into(mut b, node)
	return b.buf
}

// encode_match_node_into appends the §4.5 payload to an existing
// BinBuf. Used when MatchNode flows under a higher-level dispatch
// (e.g. when the Phase 2.x graft adds MatchNode to the Node sum-type
// and encode_node dispatches a 0x14 tag here).
fn encode_match_node_into(mut b BinBuf, node MatchNode) {
	// Mode discriminator.
	mode_byte := if node.scrutinee == none {
		match_mode_predicate_only
	} else {
		match_mode_scrutinee
	}
	b.u8_(mode_byte)

	// Optional scrutinee source (OptString shape).
	// Producers MUST honour the mode/scrutinee consistency rule
	// (spec/core/ast-bin.md §4.5 "Mode / scrutinee consistency"). Decoder
	// enforces consistency on read; we derive mode from the option
	// presence at encode time so producers cannot violate the rule.
	b.optstr_(node.scrutinee)

	// Arm count + arms.
	b.u16_(u16(node.arms.len))
	for arm in node.arms {
		encode_match_arm_into(mut b, arm)
	}
}

fn encode_match_arm_into(mut b BinBuf, arm MatchArm) {
	b.u8_(match_arm_kind_to_byte(arm.kind))

	// Pattern slot: present only for case_arm per §4.5 validity rules.
	// We emit the field-as-stored — match_node.v keeps `pattern` as the
	// zero-value `''` for when_arm / else_arm. We honour the per-arm-
	// kind validity rule explicitly by emitting OptString-absent on
	// non-case arms, matching the spec wire shape exactly.
	if arm.kind == ArmKind.case_arm {
		// case_arm always carries a pattern slot (verbatim source —
		// may be empty when the source pattern is `""` literally).
		b.optstr_(?string(arm.pattern))
	} else {
		b.optstr_(?string(none))
	}

	// Guard slot: case_arm optional, when_arm always present, else_arm
	// always absent. We emit the field-as-stored; match_node.v keeps
	// when_arm's predicate in `arm.guard` (see MatchArm doc), so the
	// natural OptString of `arm.guard` already encodes the right shape
	// for case + when. For else, match_node.v keeps `arm.guard = none`
	// (constructor `new_else_arm` never sets it).
	if arm.kind == ArmKind.else_arm {
		b.optstr_(?string(none))
	} else {
		b.optstr_(arm.guard)
	}

	// Body slot — always present, encoded as a length-prefixed UTF-8
	// string (verbatim `:yield` body source per §4.5).
	b.str_(arm.body)
}

// ── Decode ────────────────────────────────────────────────────────────────────

// decode_match_node parses a §4.5 wire payload starting at `offset` in
// `buf` and returns the reconstructed MatchNode. On success `offset`
// advances past the consumed bytes. Validates mode byte ∈ {0x00, 0x01},
// per-arm arm_kind byte ∈ {0x00, 0x01, 0x02}, mode/scrutinee consistency,
// per-arm-kind pattern/guard validity, and the `:else`-must-be-last /
// predicate-only-forbids-:case rules. Returns an error on
// out-of-range bytes, truncated input, or rule violations.
//
// The reconstructed MatchNode has `source = none`, `loc = none`, and
// every arm's `arm.loc = none` since those advisory fields are excluded
// from the wire (by symmetry with).
pub fn decode_match_node(buf []u8, mut offset &int) !MatchNode {
	mut r := AstReader{
		buf:     buf
		pos:     offset
		version: 8 // v8+ per spec/core/ast-bin.md §2.1
	}
	node := r.decode_match_node()!
	offset = r.pos
	return node
}

fn (mut r AstReader) decode_match_node() !MatchNode {
	mode_byte := r.read_u8()!
	if mode_byte != match_mode_scrutinee && mode_byte != match_mode_predicate_only {
		return error('ast_bin: invalid MatchNode mode byte 0x${mode_byte:02x} '
			+ '(expected 0x00 scrutinee or 0x01 predicate-only)')
	}

	scrut_has, scrut_val := r.read_optstr()!
	mut scrutinee := ?string(none)
	if scrut_has {
		scrutinee = ?string(scrut_val)
	}

	// Mode / scrutinee consistency (spec/core/ast-bin.md §4.5).
	if mode_byte == match_mode_scrutinee && !scrut_has {
		return error('ast_bin: MatchNode mode=scrutinee requires scrutinee present')
	}
	if mode_byte == match_mode_predicate_only && scrut_has {
		return error('ast_bin: MatchNode mode=predicate-only forbids scrutinee '
			+ '(saw present=1)')
	}

	arm_count := r.read_u16()!
	mut arms := []MatchArm{cap: int(arm_count)}
	for i in 0 .. int(arm_count) {
		arm := r.decode_match_arm()!
		// `:else`-must-be-last rule.
		if arm.kind == ArmKind.else_arm && i != int(arm_count) - 1 {
			return error('ast_bin: MatchNode :else arm must be last '
				+ '(saw else_arm at index ${i} of ${arm_count})')
		}
		// Predicate-only forbids :case arms.
		if mode_byte == match_mode_predicate_only && arm.kind == ArmKind.case_arm {
			return error('ast_bin: MatchNode mode=predicate-only forbids '
				+ ':case arms (saw case_arm at index ${i})')
		}
		arms << arm
	}

	return MatchNode{
		scrutinee: scrutinee
		arms:      arms
		// source / loc deliberately omitted (excluded from wire payload).
	}
}

fn (mut r AstReader) decode_match_arm() !MatchArm {
	kind_byte := r.read_u8()!
	if kind_byte > match_arm_kind_byte_max {
		return error('ast_bin: invalid MatchArm arm_kind byte '
			+ '0x${kind_byte:02x} (expected 0x00..0x02)')
	}
	kind := match_arm_kind_from_byte(kind_byte) or {
		return error('ast_bin: invalid MatchArm arm_kind byte '
			+ '0x${kind_byte:02x} (expected 0x00..0x02)')
	}

	pat_has, pat_val := r.read_optstr()!
	guard_has, guard_val := r.read_optstr()!

	// Per-arm-kind pattern validity (spec/core/ast-bin.md §4.5).
	if kind == ArmKind.case_arm && !pat_has {
		return error('ast_bin: MatchArm arm_kind=case_arm requires pattern present')
	}
	if kind != ArmKind.case_arm && pat_has {
		return error('ast_bin: MatchArm arm_kind=${arm_kind_name(kind)} '
			+ 'forbids pattern (saw present=1)')
	}

	// Per-arm-kind guard validity.
	if kind == ArmKind.when_arm && !guard_has {
		return error('ast_bin: MatchArm arm_kind=when_arm requires guard present '
			+ '(the :when predicate body)')
	}
	if kind == ArmKind.else_arm && guard_has {
		return error('ast_bin: MatchArm arm_kind=else_arm forbids guard '
			+ '(saw present=1)')
	}

	body := r.read_str()!

	mut pattern := ''
	if pat_has {
		pattern = pat_val
	}
	mut guard := ?string(none)
	if guard_has {
		guard = ?string(guard_val)
	}

	return MatchArm{
		kind:    kind
		pattern: pattern
		guard:   guard
		body:    body
		// loc deliberately omitted (excluded from wire payload).
	}
}
