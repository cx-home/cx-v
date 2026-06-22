module cx

// modify_node_codec.v — v8 binary wire codec for ModifyNode.
//
// Closes the Phase 2.5 TODO in modify_node.v ("Binary (ast_bin) codec —
// wire-format slot allocation pending, analogous to the PathNode
// follow-up tracked at Phase 1.7+"). Implements the §4.6 wire layout
// from spec/core/ast-bin.md for kind discriminator 0x15 (ModifyNode),
// version-byte slot v8 (rides on the same v8 byte as PathNode and
// MatchNode — no version bump, additive kind allocation per
// spec/core/ast-bin.md §2.1 forward-compatibility convention).
//
// Wire shape (per spec/core/ast-bin.md §4.6, v8+):
//
//   OptString  : doc                (present iff canonical 2-head shape;
//                                    absent for pipeline-implicit 1-head
// [?modify FOCUS …])
//   OptString  : focus              (verbatim CXPath focus source)
//   u16 LE     : action_count
//   ModifyAction × action_count
//
//   ModifyAction:
//     u8        : action_kind       (0x00 set, 0x01 delete, 0x02 using,
//                                    0x03 rename, 0x04 set-attr,
//                                    0x05 delete-attr, 0x06 append,
//                                    0x07 prepend, 0x08 insert-before,
//                                    0x09 insert-after, 0x0A replace)
//     OptString : name              (present iff action_kind ∈ {0x03,
//                                    0x04, 0x05}; absent otherwise)
//     OptString : value             (present iff action_kind ∈ {0x00,
//                                    0x02, 0x04, 0x06, 0x07, 0x08,
//                                    0x09, 0x0A}; absent for {0x01,
//                                    0x03, 0x05})
//
// Endianness, OptString flag (0/1), and length-prefixed strings
// (u32 LE byte length + UTF-8) all match the existing conventions in
// binary.v + path_node_codec.v + match_node_codec.v.
//
// Slot semantics (Phase 2.5).
// Spec §4.6 says doc / focus / name / value slots carry "the verbatim
// source-text snippet" — mirroring the PathPredicate `source`
// convention in §4.4 and the MatchArm pattern/guard/body convention
// in §4.5. The Phase 2.x ProgramExpr-AST graft will replace these
// strings with encode_node-dispatched node bytes and the focus
// string with a nested PathNode payload (tag 0x13 / §4.4) without
// bumping the version byte; cap-bit-36 readers MUST tolerate the
// Phase-2.5 string-shape during the pre-graft window.
//
// Advisory fields elided (per by symmetry with):
//   - ModifyNode.source / ModifyNode.loc (top-level advisory)
//   - ModifyAction.loc                   (per-action advisory)
// Equal ModifyNodes (under .eq()) emit byte-identical buffers.
//
// Cross-references:
//   - spec/core/ast-bin.md §2.1 (v8 history — ModifyNode joins v8) and §4.6
//     (ModifyNode layout) and §6.7 (3-action worked example)
//   - vcx/cx/modify_node.v (ModifyNode / ModifyAction / ModifyActionKind
//     struct definitions encoded here field-for-field)
//   - vcx/cx/match_node_codec.v (template — same OptString + LE
//     conventions; same standalone-codec layering)
//   - vcx/cx/binary.v (BinBuf / AstReader conventions reused here)

// ── Wire constants (mirroring spec/core/ast-bin.md §4.6 tables) ───────────────────

// Action-kind discriminator bytes per the ModifyAction action-kind table.
const modify_action_kind_set           = u8(0x00)
const modify_action_kind_delete        = u8(0x01)
const modify_action_kind_using         = u8(0x02)
const modify_action_kind_rename        = u8(0x03)
const modify_action_kind_set_attr      = u8(0x04)
const modify_action_kind_delete_attr   = u8(0x05)
const modify_action_kind_append        = u8(0x06)
const modify_action_kind_prepend       = u8(0x07)
const modify_action_kind_insert_before = u8(0x08)
const modify_action_kind_insert_after  = u8(0x09)
const modify_action_kind_replace       = u8(0x0A)

// Highest legal action-kind byte (0x0B..0xFF reserved).
const modify_action_kind_byte_max = u8(0x0A)

// ── ModifyActionKind ↔ byte ──────────────────────────────────────────────────

fn modify_action_kind_to_byte(k ModifyActionKind) u8 {
	return match k {
		.set           { modify_action_kind_set }
		.delete        { modify_action_kind_delete }
		.using_fn      { modify_action_kind_using }
		.rename        { modify_action_kind_rename }
		.set_attr      { modify_action_kind_set_attr }
		.delete_attr   { modify_action_kind_delete_attr }
		.append        { modify_action_kind_append }
		.prepend       { modify_action_kind_prepend }
		.insert_before { modify_action_kind_insert_before }
		.insert_after  { modify_action_kind_insert_after }
		.replace       { modify_action_kind_replace }
	}
}

fn modify_action_kind_from_byte(b u8) ?ModifyActionKind {
	return match b {
		modify_action_kind_set           { ?ModifyActionKind(ModifyActionKind.set) }
		modify_action_kind_delete        { ?ModifyActionKind(ModifyActionKind.delete) }
		modify_action_kind_using         { ?ModifyActionKind(ModifyActionKind.using_fn) }
		modify_action_kind_rename        { ?ModifyActionKind(ModifyActionKind.rename) }
		modify_action_kind_set_attr      { ?ModifyActionKind(ModifyActionKind.set_attr) }
		modify_action_kind_delete_attr   { ?ModifyActionKind(ModifyActionKind.delete_attr) }
		modify_action_kind_append        { ?ModifyActionKind(ModifyActionKind.append) }
		modify_action_kind_prepend       { ?ModifyActionKind(ModifyActionKind.prepend) }
		modify_action_kind_insert_before { ?ModifyActionKind(ModifyActionKind.insert_before) }
		modify_action_kind_insert_after  { ?ModifyActionKind(ModifyActionKind.insert_after) }
		modify_action_kind_replace       { ?ModifyActionKind(ModifyActionKind.replace) }
		else                             { none }
	}
}

// Per-action-kind slot-presence rules (§4.6 validity matrix).
fn modify_action_kind_has_name(k ModifyActionKind) bool {
	return k == ModifyActionKind.rename
		|| k == ModifyActionKind.set_attr
		|| k == ModifyActionKind.delete_attr
}

fn modify_action_kind_has_value(k ModifyActionKind) bool {
	return k == ModifyActionKind.set
		|| k == ModifyActionKind.using_fn
		|| k == ModifyActionKind.set_attr
		|| k == ModifyActionKind.append
		|| k == ModifyActionKind.prepend
		|| k == ModifyActionKind.insert_before
		|| k == ModifyActionKind.insert_after
		|| k == ModifyActionKind.replace
}

// ── Encode ────────────────────────────────────────────────────────────────────

// encode_modify_node returns the §4.6 wire payload for a ModifyNode
// (the tag-0x15 byte is NOT prefixed; callers that dispatch over a
// Node sum-type prepend 0x15 themselves). Advisory fields (source /
// loc / action.loc) are excluded (symmetric with 
// D9) — equal ModifyNodes (under .eq()) emit byte-identical buffers.
//
// ModifyNode.doc is a non-optional string field in modify_node.v but
// the canonical wire form distinguishes the 2-head shape (doc
// present) from the pipeline-implicit 1-head shape (doc absent per
// ). Producers signal "1-head shape" by setting doc to
// the empty string — the codec encodes empty doc as OptString-absent
// to match the spec's presence-flag semantics for the pipeline shape.
// (Empty focus / name / value slots, in contrast, encode as
// length-0 OptString-present, since they cannot legally be omitted.)
pub fn encode_modify_node(node ModifyNode) []u8 {
	mut b := BinBuf{}
	encode_modify_node_into(mut b, node)
	return b.buf
}

// encode_modify_node_into appends the §4.6 payload to an existing
// BinBuf. Used when ModifyNode flows under a higher-level dispatch
// (e.g. when the Phase 2.x graft adds ModifyNode to the Node sum-type
// and encode_node dispatches a 0x15 tag here).
fn encode_modify_node_into(mut b BinBuf, node ModifyNode) {
	// Doc slot — OptString-absent encodes the pipeline-implicit
	// 1-head shape; OptString-present encodes
	// the canonical 2-head shape. modify_node.v stores doc as a
	// plain string; empty string ↔ 1-head shape on the wire.
	if node.doc.len == 0 {
		b.optstr_(?string(none))
	} else {
		b.optstr_(?string(node.doc))
	}

	// Focus slot — always present on a well-formed ModifyNode (the
	// parser enforces this; the codec accepts empty focus as a
	// length-0 present OptString to round-trip hand-rolled fixtures).
	b.optstr_(?string(node.focus))

	// Action count + actions.
	b.u16_(u16(node.actions.len))
	for action in node.actions {
		encode_modify_action_into(mut b, action)
	}
}

fn encode_modify_action_into(mut b BinBuf, action ModifyAction) {
	b.u8_(modify_action_kind_to_byte(action.kind))

	// Name slot — present only for rename / set-attr / delete-attr
	// per §4.6 validity matrix. We emit the field-as-stored gated by
	// the per-kind validity rule so producers cannot violate the rule.
	if modify_action_kind_has_name(action.kind) {
		b.optstr_(?string(action.name))
	} else {
		b.optstr_(?string(none))
	}

	// Value slot — present for the eight expression-bearing kinds;
	// absent for {delete, rename, delete-attr}. modify_node.v stores
	// value as a plain string (empty for the non-value kinds); we
	// honour the validity matrix explicitly on encode.
	if modify_action_kind_has_value(action.kind) {
		b.optstr_(?string(action.value))
	} else {
		b.optstr_(?string(none))
	}
}

// ── Decode ────────────────────────────────────────────────────────────────────

// decode_modify_node parses a §4.6 wire payload starting at `offset` in
// `buf` and returns the reconstructed ModifyNode. On success `offset`
// advances past the consumed bytes. Validates per-action action_kind
// byte ∈ {0x00..0x0A}, and per-action-kind name/value slot-presence
// validity (per §4.6 validity matrix). Returns an error on out-of-range
// bytes, truncated input, malformed OptString, or rule violations.
//
// The reconstructed ModifyNode has `source = none`, `loc = none`, and
// every action's `action.loc = none` since those advisory fields are
// excluded from the wire (by symmetry with).
pub fn decode_modify_node(buf []u8, mut offset &int) !ModifyNode {
	mut r := AstReader{
		buf:     buf
		pos:     offset
		version: 8 // v8+ per spec/core/ast-bin.md §2.1
	}
	node := r.decode_modify_node()!
	offset = r.pos
	return node
}

fn (mut r AstReader) decode_modify_node() !ModifyNode {
	doc_has, doc_val := r.read_optstr()!
	mut doc := ''
	if doc_has {
		doc = doc_val
	}

	focus_has, focus_val := r.read_optstr()!
	mut focus := ''
	if focus_has {
		focus = focus_val
	}

	action_count := r.read_u16()!
	mut actions := []ModifyAction{cap: int(action_count)}
	for i in 0 .. int(action_count) {
		action := r.decode_modify_action(i)!
		actions << action
	}

	return ModifyNode{
		doc:     doc
		focus:   focus
		actions: actions
		// source / loc deliberately omitted (excluded from wire payload).
	}
}

fn (mut r AstReader) decode_modify_action(index int) !ModifyAction {
	kind_byte := r.read_u8()!
	if kind_byte > modify_action_kind_byte_max {
		return error('ast_bin: invalid ModifyAction action_kind byte '
			+ '0x${kind_byte:02x} at index ${index} '
			+ '(expected 0x00..0x0A)')
	}
	kind := modify_action_kind_from_byte(kind_byte) or {
		return error('ast_bin: invalid ModifyAction action_kind byte '
			+ '0x${kind_byte:02x} at index ${index} '
			+ '(expected 0x00..0x0A)')
	}

	name_has, name_val := r.read_optstr()!
	value_has, value_val := r.read_optstr()!

	// Per-action-kind name validity (spec/core/ast-bin.md §4.6 matrix).
	expects_name := modify_action_kind_has_name(kind)
	if expects_name && !name_has {
		return error('ast_bin: ModifyAction action_kind=${modify_action_kind_name(kind)} '
			+ 'requires name present (at action index ${index})')
	}
	if !expects_name && name_has {
		return error('ast_bin: ModifyAction action_kind=${modify_action_kind_name(kind)} '
			+ 'forbids name (saw present=1 at action index ${index})')
	}

	// Per-action-kind value validity.
	expects_value := modify_action_kind_has_value(kind)
	if expects_value && !value_has {
		return error('ast_bin: ModifyAction action_kind=${modify_action_kind_name(kind)} '
			+ 'requires value present (at action index ${index})')
	}
	if !expects_value && value_has {
		return error('ast_bin: ModifyAction action_kind=${modify_action_kind_name(kind)} '
			+ 'forbids value (saw present=1 at action index ${index})')
	}

	mut name := ''
	if name_has {
		name = name_val
	}
	mut value := ''
	if value_has {
		value = value_val
	}

	return ModifyAction{
		kind:  kind
		name:  name
		value: value
		// loc deliberately omitted (excluded from wire payload).
	}
}
