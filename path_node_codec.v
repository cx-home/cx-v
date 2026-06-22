module cx

// path_node_codec.v — v8 binary wire codec for PathNode.
//
// Closes the Phase 2.1 TODO in path_node.v ("binary codec deferred to
// Phase 1.7"). Implements the §4.4 wire layout from spec/core/ast-bin.md
// for kind discriminator 0x13 (PathNode), version-byte slot v8.
//
// Wire shape (per spec/core/ast-bin.md §4.4, v8+):
//
//   u8  : form               (0x00 descendant, 0x01 absolute,
//                             0x02 relative,   0x03 binding)
//   OptString : binding      (present iff form == 0x03)
//   u16 LE : step_count
//   PathStep × step_count
//   u16 LE : predicate_count (trailing top-level predicates)
//   Predicate × predicate_count
//
//   PathStep:
//     u8  : axis              (0x00..0x0B per axis table)
//     u8  : node_test_kind    (0x00..0x07 per node-test table)
//     String : node_test_name (empty for kind-test forms 0x01, 0x04..0x07)
// OptString : binding (`:bind NCName` peer-modifier;
//                              additive v8 slot landed 2026-05-23 — absent
//                              legacy payloads collapse to a single 0x00
//                              byte and decode unchanged)
//     u16 LE : step_pred_count
//     Predicate × step_pred_count
//
// Endianness, OptString flag (0/1), and length-prefixed strings
// (u32 LE byte length + UTF-8) all match the existing conventions in
// binary.v.
//
// Predicate body encoding (Phase 2.1).
// Spec §4.4 says each predicate is "a recursively-encoded
// ProgramExpr Node (§4 envelope)" — but the ProgramExpr AST does not
// exist in V at Phase 2.1 (PathPredicate carries a verbatim `source
// string`; see path_node.v lines 78–96). Until the Phase 2.4 graft
// replaces `source` with a structural ProgramExpr subtree, we encode
// each predicate as a length-prefixed UTF-8 string of the verbatim
// predicate-body source text. The Phase 2.4 migration will replace
// this string-shaped payload with `encode_node`-dispatched node
// bytes; cap-bit-36 readers MUST tolerate this Phase-2.1 placeholder
// shape during the pre-graft window. Cross-ref: path_node.v
// "Out of scope at Phase 2.1" comment block.
//
// Cross-references:
//   - spec/core/ast-bin.md §2.1 (v7 → v8 history) and §4.4 (PathNode layout)
//   - spec/ast.md §PathNode (field definitions, D9 source/loc exclusion)
// (PathNode as a value kind)
//   - vcx/cx/binary.v (BinBuf / AstReader conventions reused here)

// ── Wire constants (mirroring spec/core/ast-bin.md §4.4 tables) ───────────────────

// Form discriminator bytes per the PathNode form table.
const path_form_descendant = u8(0x00)
const path_form_absolute   = u8(0x01)
const path_form_relative   = u8(0x02)
const path_form_binding    = u8(0x03)

// Axis byte table (12 XPath 3.1 axes; values 0x0C..0xFF reserved).
const path_axis_byte_max = u8(0x0B)

// Node-test kind table (8 forms; values 0x08..0xFF reserved).
const path_node_test_kind_max = u8(0x07)

// ── Form ↔ byte ───────────────────────────────────────────────────────────────

fn path_form_to_byte(f PathForm) u8 {
	return match f {
		.descendant { path_form_descendant }
		.absolute   { path_form_absolute }
		.relative   { path_form_relative }
		.binding    { path_form_binding }
	}
}

fn path_form_from_byte(b u8) ?PathForm {
	return match b {
		path_form_descendant { ?PathForm(PathForm.descendant) }
		path_form_absolute   { ?PathForm(PathForm.absolute) }
		path_form_relative   { ?PathForm(PathForm.relative) }
		path_form_binding    { ?PathForm(PathForm.binding) }
		else                 { none }
	}
}

// ── Axis ↔ byte ───────────────────────────────────────────────────────────────

fn path_axis_to_byte(a PathAxis) u8 {
	return match a {
		.child              { u8(0x00) }
		.descendant         { u8(0x01) }
		.descendant_or_self { u8(0x02) }
		.parent             { u8(0x03) }
		.ancestor           { u8(0x04) }
		.ancestor_or_self   { u8(0x05) }
		.following_sibling  { u8(0x06) }
		.preceding_sibling  { u8(0x07) }
		.following          { u8(0x08) }
		.preceding          { u8(0x09) }
		.self_              { u8(0x0A) }
		.attribute          { u8(0x0B) }
	}
}

fn path_axis_from_byte(b u8) ?PathAxis {
	return match b {
		u8(0x00) { ?PathAxis(PathAxis.child) }
		u8(0x01) { ?PathAxis(PathAxis.descendant) }
		u8(0x02) { ?PathAxis(PathAxis.descendant_or_self) }
		u8(0x03) { ?PathAxis(PathAxis.parent) }
		u8(0x04) { ?PathAxis(PathAxis.ancestor) }
		u8(0x05) { ?PathAxis(PathAxis.ancestor_or_self) }
		u8(0x06) { ?PathAxis(PathAxis.following_sibling) }
		u8(0x07) { ?PathAxis(PathAxis.preceding_sibling) }
		u8(0x08) { ?PathAxis(PathAxis.following) }
		u8(0x09) { ?PathAxis(PathAxis.preceding) }
		u8(0x0A) { ?PathAxis(PathAxis.self_) }
		u8(0x0B) { ?PathAxis(PathAxis.attribute) }
		else     { none }
	}
}

// ── Node-test kind classification ─────────────────────────────────────────────

// Returns (kind_byte, name_payload) for a given node_test source string.
// Mirrors the §4.4 node-test discriminator table:
//   0x00 Name                  → the NCName
//   0x01 *                     → empty
//   0x02 *:LocalName           → LocalName
//   0x03 Prefix:*              → Prefix
//   0x04 node()                → empty
//   0x05 text()                → empty
//   0x06 element()             → empty
//   0x07 attribute()           → empty
fn path_node_test_classify(node_test string) (u8, string) {
	if node_test == '*' {
		return u8(0x01), ''
	}
	if node_test == 'node()' {
		return u8(0x04), ''
	}
	if node_test == 'text()' {
		return u8(0x05), ''
	}
	if node_test == 'element()' {
		return u8(0x06), ''
	}
	if node_test == 'attribute()' {
		return u8(0x07), ''
	}
	if node_test.starts_with('*:') {
		return u8(0x02), node_test[2..]
	}
	if node_test.ends_with(':*') {
		return u8(0x03), node_test[..node_test.len - 2]
	}
	return u8(0x00), node_test
}

// Returns the canonical node_test source string for a (kind, name) pair.
// Inverse of path_node_test_classify; the result is the verbatim form
// stored in PathStep.node_test.
fn path_node_test_compose(kind u8, name string) !string {
	return match kind {
		u8(0x00) { name }                  // bare NCName
		u8(0x01) { '*' }
		u8(0x02) { '*:' + name }
		u8(0x03) { name + ':*' }
		u8(0x04) { 'node()' }
		u8(0x05) { 'text()' }
		u8(0x06) { 'element()' }
		u8(0x07) { 'attribute()' }
		else     { error('ast_bin: invalid node_test kind 0x${kind:02x}') }
	}
}

// ── Encode ────────────────────────────────────────────────────────────────────

// encode_path_node returns the §4.4 wire payload for a PathNode (the
// tag-0x13 byte is NOT prefixed; callers that dispatch over a Node
// sum-type prepend 0x13 themselves). The `source` and `loc` fields
// are excluded — equal PathNodes (under .eq()) emit
// byte-identical buffers.
pub fn encode_path_node(node PathNode) []u8 {
	mut b := BinBuf{}
	encode_path_node_into(mut b, node)
	return b.buf
}

// encode_path_node_into appends the §4.4 payload to an existing
// BinBuf. Used when PathNode flows under a higher-level dispatch
// (e.g. when the Phase 2.4 graft adds PathNode to the Node sum-type
// and encode_node dispatches a 0x13 tag here).
fn encode_path_node_into(mut b BinBuf, node PathNode) {
	// Form discriminator.
	b.u8_(path_form_to_byte(node.form))

	// Optional binding name (OptString shape: u8:present + str if 1).
	// Producers MUST set binding present iff form == 0x03 binding
	// (spec/core/ast-bin.md §4.4 "Form / binding consistency"). We honour
	// the struct as-given; decoder enforces consistency.
	b.optstr_(node.binding)

	// Step count + steps.
	b.u16_(u16(node.steps.len))
	for step in node.steps {
		encode_path_step_into(mut b, step)
	}

	// Trailing top-level predicates.
	b.u16_(u16(node.predicates.len))
	for pred in node.predicates {
		encode_path_predicate_into(mut b, pred)
	}
}

fn encode_path_step_into(mut b BinBuf, step PathStep) {
	b.u8_(path_axis_to_byte(step.axis))

	kind, name := path_node_test_classify(step.node_test)
	b.u8_(kind)
	b.str_(name)

	// `:bind NCName` peer-modifier + grammar [160].
	// Additive OptString slot in the v8 PathStep layout (spec/core/ast-bin.md
	// §4.4, allocated 2026-05-23). Absent payloads collapse to a single
	// `0x00` present-flag byte — byte-identical to the pre-slot legacy
	// shape — so existing v8 buffers that predate the field decode
	// unchanged. Reserved `_` MUST already have been filtered upstream
	// at parse time (CXER0232); the codec doesn't re-validate.
	b.optstr_(step.binding)

	b.u16_(u16(step.predicates.len))
	for pred in step.predicates {
		encode_path_predicate_into(mut b, pred)
	}
}

// At Phase 2.1 a PathPredicate is a verbatim source-text string; we
// encode it as length-prefixed UTF-8. See the file-header comment for
// the Phase 2.4 migration plan (string → encoded ProgramExpr Node).
fn encode_path_predicate_into(mut b BinBuf, pred PathPredicate) {
	b.str_(pred.source)
}

// ── Decode ────────────────────────────────────────────────────────────────────

// decode_path_node parses a §4.4 wire payload starting at `offset` in
// `buf` and returns the reconstructed PathNode. On success `offset`
// advances past the consumed bytes. Validates form byte ∈ {0x00..0x03},
// per-step axis ∈ {0x00..0x0B}, node-test kind ∈ {0x00..0x07}, and
// form/binding consistency. Returns an error on out-of-range bytes or
// truncated input.
//
// The reconstructed PathNode has `source = none` and `loc = none`
// since those advisory fields are excluded from the wire.
pub fn decode_path_node(buf []u8, mut offset &int) !PathNode {
	mut r := AstReader{
		buf:     buf
		pos:     offset
		version: 8 // v8+ per spec/core/ast-bin.md §2.1
	}
	node := r.decode_path_node()!
	offset = r.pos
	return node
}

fn (mut r AstReader) decode_path_node() !PathNode {
	form_byte := r.read_u8()!
	form := path_form_from_byte(form_byte) or {
		return error('ast_bin: invalid PathNode form byte 0x${form_byte:02x} '
			+ '(expected 0x00..0x03)')
	}

	bind_has, bind_val := r.read_optstr()!
	mut binding := ?string(none)
	if bind_has {
		binding = ?string(bind_val)
	}

	// Form / binding consistency (spec/core/ast-bin.md §4.4).
	if form == .binding && !bind_has {
		return error('ast_bin: PathNode form=binding requires binding present')
	}
	if form != .binding && bind_has {
		return error('ast_bin: PathNode form=${path_form_name(form)} forbids '
			+ 'binding (saw present=1)')
	}

	step_count := r.read_u16()!
	mut steps := []PathStep{cap: int(step_count)}
	for _ in 0 .. step_count {
		steps << r.decode_path_step()!
	}

	pred_count := r.read_u16()!
	mut preds := []PathPredicate{cap: int(pred_count)}
	for _ in 0 .. pred_count {
		preds << r.decode_path_predicate()!
	}

	return PathNode{
		form:       form
		binding:    binding
		steps:      steps
		predicates: preds
		// source / loc deliberately omitted (excluded from wire payload).
	}
}

fn (mut r AstReader) decode_path_step() !PathStep {
	axis_byte := r.read_u8()!
	axis := path_axis_from_byte(axis_byte) or {
		return error('ast_bin: invalid PathStep axis byte 0x${axis_byte:02x} '
			+ '(expected 0x00..0x0B)')
	}

	kind_byte := r.read_u8()!
	if kind_byte > path_node_test_kind_max {
		return error('ast_bin: invalid PathStep node_test_kind byte '
			+ '0x${kind_byte:02x} (expected 0x00..0x07)')
	}
	name := r.read_str()!
	node_test := path_node_test_compose(kind_byte, name)!

	// `:bind NCName` peer-modifier OptString slot (spec/core/ast-bin.md §4.4,
	// additive v8 field allocated 2026-05-23). Legacy v8 payloads that
	// predate the slot encode the absent flag as a single `0x00` byte
	// (read_optstr returns has=false, val="") — they decode unchanged.
	bind_has, bind_val := r.read_optstr()!
	mut binding := ?string(none)
	if bind_has {
		binding = ?string(bind_val)
	}

	step_pred_count := r.read_u16()!
	mut preds := []PathPredicate{cap: int(step_pred_count)}
	for _ in 0 .. step_pred_count {
		preds << r.decode_path_predicate()!
	}

	return PathStep{
		axis:       axis
		node_test:  node_test
		binding:    binding
		predicates: preds
	}
}

fn (mut r AstReader) decode_path_predicate() !PathPredicate {
	src := r.read_str()!
	return PathPredicate{ source: src }
}
