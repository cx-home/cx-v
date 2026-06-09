module cx

import crypto.sha256

// path_node.v — PathNode AST (v0.8.0).
//
// PathNode is the spec-canonical first-class AST node for CXPath value-kind
// expressions: `//user[@active=true]`, `/root/item`, `user/email`, `$u/name`,
// `$u//item`, `$u/axis::name` — collapsing grammar productions [130]–[135]
// onto a single value kind with a `form` discriminator.
//
// This file is the Phase 2.1 foundational layer:
//   - struct + helpers (construction / field access)
// structural equality (source + loc excluded)
//   - canonical hashing (disjoint-domain hash via a 'PathNode\x00'-prefixed
//     canonical-string form passed through SHA-256)
//   - JSON projection (`{"type":"ProgramPathExpr", …}`) per spec/ast.md
//
// Out of scope at Phase 2.1 (deferred):
//   - Binary (ast_bin) codec — wire-format slot pending Phase 1.7; see
//     `spec/core/ast-bin.md`. TODO marker is in this file at path_node_to_bin
//     placeholder; emitters MUST reject PathNode until allocated (CXER0290).
//   - Parser wire-up (Phase 2.3) — this file ships only the AST datum.
//   - Node sum-type integration — PathNode is intentionally NOT added to
//     the `cx.Node` sum type in this phase. Adding it cascades exhaustive
//     match arms across all emitters/decoders; that wiring lives in
//     Phase 2.4+. The Phase 2.1 contract is "datum + projection are
//     available as standalone helpers".
//
// Cross-references:
//   - spec/ast.md PathNode section
//   - spec/grammar.ebnf productions [130]–[135]

// ── Enums ─────────────────────────────────────────────────────────────────────

// PathForm discriminates the leading-token shape of a PathNode source
// surface per the spec's PathNode form table. Mirrors grammar [130]
// for the three rooted forms + [135] for the binding-rooted form.
pub enum PathForm {
	absolute   // `/root`
	descendant // `//user`
	relative   // `user/email`
	binding    // `$u/name`, `$u//item`
}

// PathAxis enumerates the 12 XPath 3.1 axes admitted at the head of a
// PathStep per grammar [131a]. The default (no `axis::` prefix in the
// source) is `.child` for non-attribute steps and `.attribute` when the
// step source began with `@`.
pub enum PathAxis {
	child
	descendant
	descendant_or_self
	parent
	ancestor
	ancestor_or_self
	following_sibling
	preceding_sibling
	following
	preceding
	self_
	attribute
}

// ── Structs ───────────────────────────────────────────────────────────────────

// PathLoc carries an optional source-position record. Advisory; not
// part of equality or hashing. Populated by the parser
// when source-location tracking is enabled; left as none otherwise.
pub struct PathLoc {
pub mut:
	line int
	col  int
}

// PathPredicate carries one predicate-body expression. Per 
// D1 each predicate body is a general ProgramExpr; at Phase 2.19 the
// structural AST is represented by PredicateExpr (`predicate_expr.v`)
// covering the atomic templates. The `source` field is
// always populated with the verbatim body text; the `expr` field is
// populated when the parser successfully promotes the body into a
// PredicateExpr AST, and left as `none` otherwise (the source-only
// fallback per the path_parser.v contract).
//
// Equality + hashing rule (Phase 2.19):
//
//   - When both predicates carry `expr.some`, equality compares the
//     structural PredicateExpr ASTs via `.eq()` (advisory source/loc
//     excluded; surface-text formatting differences don't break
//     identity).
//   - When both predicates carry `expr.none`, equality falls back to
//     the verbatim `source` string match (conservative — two bodies
//     spelled differently compare unequal, matching the matcher-cache
// contract).
//   - When one carries `expr.some` and the other does not, equality
//     falls back to source-string match — this is the bridge case
//     while one side of a comparison was produced by the parser and
//     the other was hand-constructed in test code. Hand-constructed
//     PathPredicate values that omit `expr` rely on the same `source`
//     spelling the parser produces.
//
// Canonical-bytes hashing always uses `source` (not the expr) so the
// hash stays byte-identical across the Phase 2.19 graft for predicates
// produced by the parser (which always populates `source`).
pub struct PathPredicate {
pub mut:
	source string
	expr   ?&PredicateExpr
}

// PathStep is one step of a PathNode's step list per grammar [130a].
// `axis` defaults to `.child` for bare-name steps and `.attribute`
// for `@name` source. `node_test` carries the spec's name-or-kind
// test string verbatim (`Name`, `*`, `*:LocalName`, `Prefix:*`,
// `node()`, `text()`, `element()`, `attribute()`).
//
// `binding` carries the `:bind NCName` peer-modifier
// + grammar [160]. When present, the bound identifier is visible in
// every predicate enclosed by this step and in every subsequent step
// of the same PathExpr. The identifier is stored without the `$`
// sigil — emit/parse round-trip adds/strips it. The reserved `_`
// identifier is rejected at parse time with `CXER0232`
// (RESERVED_BIND_NAME); it cannot appear in a constructed PathStep
// either (callers MUST validate before construction).
pub struct PathStep {
pub mut:
	axis       PathAxis
	node_test  string
	binding    ?string // `:bind NAME` peer-modifier
	predicates []PathPredicate
}

// PathNode is the spec-canonical first-class Path value-kind AST node
// See file-level comment + spec/ast.md PathNode for
// the full contract.
pub struct PathNode {
pub mut:
	form       PathForm
	binding    ?string         // bound identifier (no `$`) when form == .binding
	steps      []PathStep
	predicates []PathPredicate // trailing top-level predicates (rare)
	source     ?string         // verbatim source-text snippet (advisory)
	loc        ?PathLoc        // source position (advisory)
}

// ── Constructors ──────────────────────────────────────────────────────────────

// new_path_node constructs a minimal PathNode with the given form +
// steps. `binding` is left none (caller sets it for form == .binding);
// `predicates`, `source`, `loc` are empty/none.
pub fn new_path_node(form PathForm, steps []PathStep) PathNode {
	return PathNode{
		form:  form
		steps: steps
	}
}

// new_path_step constructs a PathStep with the given axis + node_test
// and no predicates. Callers append predicates via the returned value.
pub fn new_path_step(axis PathAxis, node_test string) PathStep {
	return PathStep{
		axis:      axis
		node_test: node_test
	}
}

// ── Axis ↔ string ─────────────────────────────────────────────────────────────

// path_axis_name returns the canonical spec spelling of an axis per
// grammar [131a]. Used by JSON projection and the canonical hashing
// pipeline; the inverse is path_axis_from_name.
pub fn path_axis_name(a PathAxis) string {
	return match a {
		.child              { 'child' }
		.descendant         { 'descendant' }
		.descendant_or_self { 'descendant-or-self' }
		.parent             { 'parent' }
		.ancestor           { 'ancestor' }
		.ancestor_or_self   { 'ancestor-or-self' }
		.following_sibling  { 'following-sibling' }
		.preceding_sibling  { 'preceding-sibling' }
		.following          { 'following' }
		.preceding          { 'preceding' }
		.self_              { 'self' }
		.attribute          { 'attribute' }
	}
}

// path_axis_from_name parses a canonical axis spelling back into the
// PathAxis enum. Returns none for an unknown spelling so callers can
// surface a useful parse error.
pub fn path_axis_from_name(name string) ?PathAxis {
	return match name {
		'child'              { ?PathAxis(PathAxis.child) }
		'descendant'         { ?PathAxis(PathAxis.descendant) }
		'descendant-or-self' { ?PathAxis(PathAxis.descendant_or_self) }
		'parent'             { ?PathAxis(PathAxis.parent) }
		'ancestor'           { ?PathAxis(PathAxis.ancestor) }
		'ancestor-or-self'   { ?PathAxis(PathAxis.ancestor_or_self) }
		'following-sibling'  { ?PathAxis(PathAxis.following_sibling) }
		'preceding-sibling'  { ?PathAxis(PathAxis.preceding_sibling) }
		'following'          { ?PathAxis(PathAxis.following) }
		'preceding'          { ?PathAxis(PathAxis.preceding) }
		'self'               { ?PathAxis(PathAxis.self_) }
		'attribute'          { ?PathAxis(PathAxis.attribute) }
		else                 { none }
	}
}

// path_form_name returns the spec spelling of a PathForm.
pub fn path_form_name(f PathForm) string {
	return match f {
		.absolute   { 'absolute' }
		.descendant { 'descendant' }
		.relative   { 'relative' }
		.binding    { 'binding' }
	}
}

// path_form_from_name parses a PathForm spelling back to the enum.
pub fn path_form_from_name(name string) ?PathForm {
	return match name {
		'absolute'   { ?PathForm(PathForm.absolute) }
		'descendant' { ?PathForm(PathForm.descendant) }
		'relative'   { ?PathForm(PathForm.relative) }
		'binding'    { ?PathForm(PathForm.binding) }
		else         { none }
	}
}

// ── Equality ──────────────────────────────────────────────────────────────────

// eq returns true iff two PathNode values are structurally equal under
// the CXDM §2 identity rule. The `source` and `loc`
// fields are advisory and do NOT participate in equality — two
// PathNodes parsed from differently-formatted source text (e.g.
// `//user[@active = true]` vs `//user[@active=true]`) compare equal.
// This matches the round-trip contract.
//
// V auto-generates `==` for the underlying struct shape which WOULD
// include `source` + `loc`; callers MUST use this method (or the
// canonical-bytes hash) for identity. The auto-generated
// `==` is left in place for debug-print convenience.
pub fn (p PathNode) eq(other PathNode) bool {
	if p.form != other.form {
		return false
	}
	// Compare the optional binding identifier.
	pb := p.binding or { '' }
	ob := other.binding or { '' }
	if (p.binding == none) != (other.binding == none) {
		return false
	}
	if pb != ob {
		return false
	}
	if !path_steps_eq(p.steps, other.steps) {
		return false
	}
	if !path_predicates_eq(p.predicates, other.predicates) {
		return false
	}
	return true
}

fn path_steps_eq(a []PathStep, b []PathStep) bool {
	if a.len != b.len {
		return false
	}
	for i, sa in a {
		sb := b[i]
		if sa.axis != sb.axis {
			return false
		}
		if sa.node_test != sb.node_test {
			return false
		}
		// `:bind NAME` peer-modifier — identity-relevant
		// D5 (the binding changes path semantics, not just surface
		// shape, because the bound name becomes referenceable in
		// downstream predicates).
		if (sa.binding == none) != (sb.binding == none) {
			return false
		}
		sab := sa.binding or { '' }
		sbb := sb.binding or { '' }
		if sab != sbb {
			return false
		}
		if !path_predicates_eq(sa.predicates, sb.predicates) {
			return false
		}
	}
	return true
}

fn path_predicates_eq(a []PathPredicate, b []PathPredicate) bool {
	if a.len != b.len {
		return false
	}
	for i, pa in a {
		pb := b[i]
		// Phase 2.19: when both predicates carry a structural expr
		// AST, compare structurally so surface-text formatting
		// differences (`@a=1` vs `@a = 1`) don't break identity.
		// Otherwise fall back to verbatim source-string match.
		if ea := pa.expr {
			if eb := pb.expr {
				if !ea.eq(eb) {
					return false
				}
				continue
			}
		}
		if pa.source != pb.source {
			return false
		}
	}
	return true
}

// ── Canonical bytes + hashing ─────────────────────────────────────────────────

// path_node_canonical_bytes returns the canonical byte form of a
// PathNode used as input to the disjoint-domain hash function. The
// byte form is a deterministic textual encoding of the identity-
// participating fields (form, binding, steps, predicates) ONLY —
// source and loc are excluded.
//
// Disjoint-domain prefix: the bytes start with the literal ASCII
// `PathNode\x00` followed by a `\x01` form discriminator and
// `\x02`-delimited fields. The `\x00` byte after the type tag cannot
// occur inside a CX scalar string canonical encoding (which is
// always quote-wrapped) nor inside an Element canonical CX form
// (which never contains a NUL byte at v0.8.0), so PathNode hashes
// inhabit a domain that cannot collide with element/scalar/atom
// hashes by construction.
//
// This is the hashing convention atom-vs-string disjoint-
// hash-domains pattern motivates; spec/ast.md PathNode section §
// "Equality and hashing" requires it.
pub fn path_node_canonical_bytes(p PathNode) []u8 {
	mut out := []u8{}
	out << 'PathNode'.bytes()
	out << u8(0x00)
	out << path_form_name(p.form).bytes()
	out << u8(0x01)
	if b := p.binding {
		out << b.bytes()
	}
	out << u8(0x02)
	for s in p.steps {
		out << path_axis_name(s.axis).bytes()
		out << u8(0x03)
		out << s.node_test.bytes()
		out << u8(0x04)
		// `:bind NAME` peer-modifier — identity-relevant.
		// Encoded as `\x09` + name when present; absent steps skip the
		// segment entirely (so legacy 2.1-era hashes of binding-less
		// PathNodes remain byte-identical across the Phase 2.20 graft).
		if bn := s.binding {
			out << u8(0x09)
			out << bn.bytes()
		}
		for pred in s.predicates {
			out << pred.source.bytes()
			out << u8(0x05)
		}
		out << u8(0x06) // end-of-step
	}
	out << u8(0x07) // end-of-steps
	for pred in p.predicates {
		out << pred.source.bytes()
		out << u8(0x05)
	}
	out << u8(0x08) // end-of-trailing-predicates
	return out
}

// path_node_hash returns the lowercase hex SHA-256 of the canonical
// disjoint-domain byte form. Equal PathNodes (per `.eq()`) produce
// equal hashes. The leading `PathNode\x00` prefix guarantees the
// hash cannot collide with element / scalar / atom canonical-bytes
// hashes (which start with different domain tags or contain only
// CX-source bytes that never include the in-band NUL).
pub fn path_node_hash(p PathNode) string {
	digest := sha256.sum256(path_node_canonical_bytes(p))
	return digest.hex()
}

// ── JSON projection ───────────────────────────────────────────────────────────

// path_node_to_json returns the AST-JSON projection of a PathNode
// per spec/ast.md PathNode section. The shape is:
//
//   {
//     "type":       "ProgramPathExpr",
//     "form":       "absolute" | "descendant" | "relative" | "binding",
//     "binding":    "<name>",   // present only when form == "binding"
//     "steps":      [ { "axis": ..., "node_test": ..., "predicates": [...] }, ... ],
//     "predicates": [ ... ],    // omit when empty
//     "source":     "<src>",    // omit when none
//     "loc":        { "line": N, "col": M } // omit when none
//   }
//
// "ProgramPathExpr" is the parser-internal JSON `type` tag retained
// for round-trip compatibility with the legacy parser-internal shape;
// at the AST-bin boundary (Phase 1.7+) the projection collapses to
// `"PathNode"` per the spec. The Phase 2.1 deliverable keeps the
// parser-internal tag so the existing JSON readers in the legacy
// ProgramPathExpr code path continue to load this projection.
//
// Predicate bodies project as `{"source": "<verbatim>"}` until the
// Phase 2.4 ProgramExpr-AST graft replaces `source` with a structural
// ProgramExpr subtree; the wire-shape stays stable across that
// migration (the structural form lands as an additional field).
pub fn path_node_to_json(p PathNode) string {
	mut pairs := []string{}
	pairs << '"type":"ProgramPathExpr"'
	pairs << '"form":"${path_form_name(p.form)}"'
	if b := p.binding {
		pairs << '"binding":${json_str(b)}'
	}
	mut steps_json := []string{cap: p.steps.len}
	for s in p.steps {
		steps_json << path_step_to_json(s)
	}
	pairs << '"steps":[${steps_json.join(',')}]'
	if p.predicates.len > 0 {
		mut preds_json := []string{cap: p.predicates.len}
		for pred in p.predicates {
			preds_json << path_predicate_to_json(pred)
		}
		pairs << '"predicates":[${preds_json.join(',')}]'
	}
	if src := p.source {
		pairs << '"source":${json_str(src)}'
	}
	if l := p.loc {
		pairs << '"loc":{"line":${l.line},"col":${l.col}}'
	}
	return '{${pairs.join(',')}}'
}

fn path_step_to_json(s PathStep) string {
	mut pairs := []string{}
	pairs << '"axis":"${path_axis_name(s.axis)}"'
	pairs << '"node_test":${json_str(s.node_test)}'
	// `:bind NAME` peer-modifier — emitted when present.
	if bn := s.binding {
		pairs << '"binding":${json_str(bn)}'
	}
	if s.predicates.len > 0 {
		mut preds_json := []string{cap: s.predicates.len}
		for pred in s.predicates {
			preds_json << path_predicate_to_json(pred)
		}
		pairs << '"predicates":[${preds_json.join(',')}]'
	}
	return '{${pairs.join(',')}}'
}

fn path_predicate_to_json(pred PathPredicate) string {
	return '{"source":${json_str(pred.source)}}'
}

// ── Binary codec hook (DEFERRED) ──────────────────────────────────────────────

// TODO(Phase 1.7): wire codec.
//
// PathNode wire-format slot is pending Phase 1.7 of the 
// rollout — see spec/core/ast-bin.md for the cap-bit allocation and tag
// byte. Until the slot lands:
//   - emit_ast_bin MUST reject PathNode values with CXER0290
//     (currently moot: PathNode is not yet a Node sum-type variant).
//   - parse_ast_bin MUST surface a clear error if it encounters a
//     wire byte in PathNode's pending slot range.
//
// When the slot lands this file gains:
//   - fn path_node_to_bin(p PathNode) []u8
//   - fn bin_to_path_node(bytes []u8, mut pos int) !PathNode
// plus integration into binary.v's emit/parse dispatch.
