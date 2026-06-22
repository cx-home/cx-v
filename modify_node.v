module cx

import crypto.sha256

// modify_node.v — ModifyNode AST.
//
// ModifyNode is the spec-canonical first-class AST node for the
// `[?modify]` directive — `[?modify DOC FOCUS ACTION+]`
// — collapsing grammar productions [141]–[148e] onto a single value
// kind with an ordered list of ModifyAction discriminators.
//
// This file is the Phase 2.5 foundational AST layer:
//   - structs (ModifyNode, ModifyAction, ModifyLoc) + helpers
// enum ModifyActionKind covering all 11 vocab actions
//     (`[set]`, `[delete]`, `[using]`, `[rename]`, `[set-attr]`, `[delete-attr]`,
//     `[append]`, `[prepend]`, `[insert-before]`, `[insert-after]`, `[replace]`).
// structural equality (source + loc excluded pattern
// adopted into by symmetry)
//   - canonical hashing (disjoint-domain hash via `ModifyNode\x00`-prefixed
//     canonical-string form passed through SHA-256, mirroring the
//     PathNode / MatchNode convention)
//   - JSON projection (`{"type":"ProgramModifyExpr", …}`)
//
// Out of scope at Phase 2.5 (deferred):
//   - Evaluator (pure-functional updates, structural sharing,
//     no-match → identity, multi-match left-to-right action chaining,
//     `[using]` lambda dispatch, `[rename]` attr-keep) — Phase 2.8.
//   - Binary (ast_bin) codec — wire-format slot allocation pending,
//     analogous to the PathNode follow-up tracked at Phase 1.7+.
//   - Node sum-type integration — adding ModifyNode to `cx.Node` cascades
//     exhaustive match arms across every emitter / decoder, so it lives
//     in a later Phase 2.x slice. The Phase 2.5 contract is "datum +
//     projection are available as standalone helpers".
//   - Structural ProgramExpr / PathNode subtree under the focus +
//     action-argument slots — those carry the verbatim source-text
//     snippet for now (mirrors PathPredicate.source); the Phase 2.5
//     follow-up grafts in the structural subtrees without changing the
//     projected JSON wire shape.
//
// Cross-references:
//   - spec/grammar.ebnf productions [141]–[148e]

// ── Enums ─────────────────────────────────────────────────────────────────────

// ModifyActionKind discriminates the eleven action shapes admitted by
//
//   - set            : `[set EXPR]`            — replace matched value / attr
//   - delete         : `[delete]`              — remove matched node / attr
//   - using_fn       : `[using EXPR]`          — fn($node) applied to each match
//   - rename         : `[rename NAME]`         — rename element (keep attrs + body)
//   - set_attr       : `[set-attr NAME EXPR]`  — add / overwrite attribute
//   - delete_attr    : `[delete-attr NAME]`    — remove attribute by name
//   - append         : `[append EXPR]`         — add child at end of body
//   - prepend        : `[prepend EXPR]`        — add child at start of body
//   - insert_before  : `[insert-before EXPR]`  — new sibling before matched node
//   - insert_after   : `[insert-after EXPR]`   — new sibling after matched node
//   - replace        : `[replace EXPR]`        — replace entire node with expr
//
// `using` collides with the V `using` keyword in some contexts so the
// enum variant is named `using_fn`; the canonical spec spelling
// `using` (without the suffix) flows through `modify_action_kind_name`.
pub enum ModifyActionKind {
	set
	delete
	using_fn
	rename
	set_attr
	delete_attr
	append
	prepend
	insert_before
	insert_after
	replace
}

// ── Structs ───────────────────────────────────────────────────────────────────

// ModifyLoc carries an optional source-position record. Advisory; not
// part of equality or hashing (symmetric).
// `start` / `end` are byte offsets into the original source string;
// populated by the parser when source-location tracking is enabled,
// left as 0/0 otherwise.
pub struct ModifyLoc {
pub mut:
	start int
	end   int
}

// ModifyAction carries one action of a `[?modify]` expression. Per
// each action variant has a small number of typed slots
// all captured here as verbatim source-text strings at Phase 2.5.
//
// Field meanings by `kind`:
//
//   - .set / .using_fn / .append / .prepend
//     / .insert_before / .insert_after / .replace :
//       `value` holds the verbatim ProgramExpr source-text;
//       `name` is empty.
//   - .delete :
//       no slot data — `value` and `name` both empty.
//   - .rename :
//       `name` holds the verbatim Name token (the new element name);
//       `value` is empty.
//   - .set_attr :
//       `name`  holds the attribute Name; `value` holds the
//       attribute-value ProgramExpr source.
//   - .delete_attr :
//       `name` holds the attribute Name; `value` is empty.
//
// At Phase 2.5 every slot is a verbatim source-text string (mirrors
// `PathPredicate.source`); the Phase 2.x ProgramExpr-AST graft will
// refine these into structural subtrees without changing the projected
// JSON wire shape.
//
// Equality + hashing operate on the verbatim strings at Phase 2.5 —
// this is conservative (two actions whose value-expressions evaluate
// identically but were spelled differently compare unequal). The graft
// to structural ProgramExpr equality is a follow-up.
pub struct ModifyAction {
pub mut:
	kind  ModifyActionKind
	name  string // Name token for [rename] / [set-attr] / [delete-attr]; empty otherwise
	value string // ProgramExpr source for slots that carry an expression; empty otherwise
	loc   ?ModifyLoc
	// Z79b — structural ProgramExpr-AST graft (Phase 2.5 follow-up).
	//
	// `value_node` carries the parsed `cx.Node` of the `value` source
	// snippet when `cx.parse(value)` succeeds; left `none` otherwise.
	// Populated by `parse_modify` on a best-effort basis. Additive
	// only — the verbatim string above remains the canonical
	// identity-participating data at Phase 2.5; equality + hashing
	// continue to use the string form so two ModifyNodes parsed from
	// the same source produce the same hash regardless of whether
	// `cx.parse` succeeded on the snippet.
	value_node ?Node
}

// ModifyNode is the spec-canonical first-class AST node for the
// `[?modify]` directive. See file-level comment for
// the full contract.
//
// `doc` carries the verbatim source-text of the first argument (the
// document or sub-tree to update — ProgramExpr in grammar [141]).
//
// `focus` carries the verbatim source-text of the CXPath focus
// expression (PathExpr in grammar [141]). At Phase 2.5 this is a
// string; the Phase 2.x graft replaces it with a structural PathNode
// reference.
//
// `actions` is the ordered list of ModifyAction values; 
// mandates at least one action and mandates left-to-right
// application order — the parser preserves source order.
pub struct ModifyNode {
pub mut:
	doc     string // verbatim source of document expr (first arg)
	focus   string // verbatim source of CXPath focus (second arg)
	actions []ModifyAction
	source  ?string   // verbatim source-text snippet of the full [?modify …] form (advisory)
	loc     ?ModifyLoc // source position (advisory)
}

// ── Constructors ──────────────────────────────────────────────────────────────

// new_modify_node constructs a minimal ModifyNode with the given doc /
// focus / actions. `source` and `loc` are left none.
pub fn new_modify_node(doc string, focus string, actions []ModifyAction) ModifyNode {
	return ModifyNode{
		doc:     doc
		focus:   focus
		actions: actions
	}
}

// new_modify_action_set constructs a `[set EXPR]` action.
pub fn new_modify_action_set(expr string) ModifyAction {
	return ModifyAction{
		kind:  ModifyActionKind.set
		value: expr
	}
}

// new_modify_action_delete constructs a `[delete]` action.
pub fn new_modify_action_delete() ModifyAction {
	return ModifyAction{
		kind: ModifyActionKind.delete
	}
}

// new_modify_action_using constructs a `[using EXPR]` action.
pub fn new_modify_action_using(expr string) ModifyAction {
	return ModifyAction{
		kind:  ModifyActionKind.using_fn
		value: expr
	}
}

// new_modify_action_rename constructs a `[rename NAME]` action.
pub fn new_modify_action_rename(name string) ModifyAction {
	return ModifyAction{
		kind: ModifyActionKind.rename
		name: name
	}
}

// new_modify_action_set_attr constructs a `[set-attr NAME EXPR]` action.
pub fn new_modify_action_set_attr(name string, expr string) ModifyAction {
	return ModifyAction{
		kind:  ModifyActionKind.set_attr
		name:  name
		value: expr
	}
}

// new_modify_action_delete_attr constructs a `[delete-attr NAME]` action.
pub fn new_modify_action_delete_attr(name string) ModifyAction {
	return ModifyAction{
		kind: ModifyActionKind.delete_attr
		name: name
	}
}

// new_modify_action_append constructs an `[append EXPR]` action.
pub fn new_modify_action_append(expr string) ModifyAction {
	return ModifyAction{
		kind:  ModifyActionKind.append
		value: expr
	}
}

// new_modify_action_prepend constructs a `[prepend EXPR]` action.
pub fn new_modify_action_prepend(expr string) ModifyAction {
	return ModifyAction{
		kind:  ModifyActionKind.prepend
		value: expr
	}
}

// new_modify_action_insert_before constructs an `[insert-before EXPR]` action.
pub fn new_modify_action_insert_before(expr string) ModifyAction {
	return ModifyAction{
		kind:  ModifyActionKind.insert_before
		value: expr
	}
}

// new_modify_action_insert_after constructs an `[insert-after EXPR]` action.
pub fn new_modify_action_insert_after(expr string) ModifyAction {
	return ModifyAction{
		kind:  ModifyActionKind.insert_after
		value: expr
	}
}

// new_modify_action_replace constructs a `[replace EXPR]` action.
pub fn new_modify_action_replace(expr string) ModifyAction {
	return ModifyAction{
		kind:  ModifyActionKind.replace
		value: expr
	}
}

// ── ModifyActionKind ↔ string ─────────────────────────────────────────────────

// modify_action_kind_name returns the canonical spec spelling of a
// ModifyActionKind. Used by JSON projection and the canonical hashing
// pipeline; the inverse is modify_action_kind_from_name.
pub fn modify_action_kind_name(k ModifyActionKind) string {
	return match k {
		.set           { 'set' }
		.delete        { 'delete' }
		.using_fn      { 'using' }
		.rename        { 'rename' }
		.set_attr      { 'set-attr' }
		.delete_attr   { 'delete-attr' }
		.append        { 'append' }
		.prepend       { 'prepend' }
		.insert_before { 'insert-before' }
		.insert_after  { 'insert-after' }
		.replace       { 'replace' }
	}
}

// modify_action_kind_from_name parses a canonical action-kind spelling
// back into the ModifyActionKind enum. Returns none for unknown spellings.
pub fn modify_action_kind_from_name(name string) ?ModifyActionKind {
	return match name {
		'set'           { ?ModifyActionKind(ModifyActionKind.set) }
		'delete'        { ?ModifyActionKind(ModifyActionKind.delete) }
		'using'         { ?ModifyActionKind(ModifyActionKind.using_fn) }
		'rename'        { ?ModifyActionKind(ModifyActionKind.rename) }
		'set-attr'      { ?ModifyActionKind(ModifyActionKind.set_attr) }
		'delete-attr'   { ?ModifyActionKind(ModifyActionKind.delete_attr) }
		'append'        { ?ModifyActionKind(ModifyActionKind.append) }
		'prepend'       { ?ModifyActionKind(ModifyActionKind.prepend) }
		'insert-before' { ?ModifyActionKind(ModifyActionKind.insert_before) }
		'insert-after'  { ?ModifyActionKind(ModifyActionKind.insert_after) }
		'replace'       { ?ModifyActionKind(ModifyActionKind.replace) }
		else            { none }
	}
}

// ── Equality ──────────────────────────────────────────────────────────────────

// eq returns true iff two ModifyNode values are structurally equal
// under the identity rule (adopted by by symmetry).
// The `source` and `loc` fields are advisory and do NOT participate in
// equality. Two ModifyNodes parsed from differently-formatted source
// compare equal as long as the doc / focus / action sequence match.
//
// V auto-generates `==` for the underlying struct shape which would
// include `source` + `loc`; callers MUST use this method (or the
// canonical-bytes hash) for identity.
pub fn (m ModifyNode) eq(other ModifyNode) bool {
	if m.doc != other.doc {
		return false
	}
	if m.focus != other.focus {
		return false
	}
	if !modify_actions_eq(m.actions, other.actions) {
		return false
	}
	return true
}

// eq compares two actions for structural equality (kind + name +
// value). The `loc` field is advisory and excluded.
//
// Z79b structural graft: when both sides carry a parsed `value_node`,
// the value-slot comparison promotes to `node_structural_eq`. Falls
// back to verbatim-string equality otherwise.
pub fn (a ModifyAction) eq(other ModifyAction) bool {
	if a.kind != other.kind {
		return false
	}
	if a.name != other.name {
		return false
	}
	if avn := a.value_node {
		if bvn := other.value_node {
			if !node_structural_eq(avn, bvn) {
				return false
			}
		} else if a.value != other.value {
			return false
		}
	} else if a.value != other.value {
		return false
	}
	return true
}

fn modify_actions_eq(a []ModifyAction, b []ModifyAction) bool {
	if a.len != b.len {
		return false
	}
	for i, aa in a {
		if !aa.eq(b[i]) {
			return false
		}
	}
	return true
}

// ── Canonical bytes + hashing ─────────────────────────────────────────────────

// modify_node_canonical_bytes returns the canonical byte form of a
// ModifyNode used as input to the disjoint-domain hash function. The
// byte form is a deterministic textual encoding of the identity-
// participating fields (doc + focus + actions only) — source + loc are
// excluded.
//
// Disjoint-domain prefix: the bytes start with the literal ASCII
// `ModifyNode\x00` followed by `\x01`-delimited doc / focus slots and
// per-action `\x02`-prefixed segments. The `\x00` byte after the type
// tag cannot occur inside a CX canonical surface (UTF-8 content with
// no in-band NUL), so ModifyNode hashes inhabit a domain disjoint
// from element / scalar / atom / PathNode / MatchNode / PredicateExpr
// hashes by construction.
//
// Mirrors the PathNode / MatchNode disjoint-domain hashing convention.
pub fn modify_node_canonical_bytes(m ModifyNode) []u8 {
	mut out := []u8{}
	out << 'ModifyNode'.bytes()
	out << u8(0x00)
	// Doc slot.
	out << u8(0x10)
	out << m.doc.bytes()
	out << u8(0x01)
	// Focus slot.
	out << u8(0x11)
	out << m.focus.bytes()
	out << u8(0x01)
	// Actions — per-action delimiter `\x02`, intra-action fields
	// delimited by `\x03` (kind), `\x04` (name), `\x05` (value).
	for action in m.actions {
		out << u8(0x02)
		out << modify_action_kind_name(action.kind).bytes()
		out << u8(0x03)
		out << action.name.bytes()
		out << u8(0x04)
		out << action.value.bytes()
		out << u8(0x05)
	}
	out << u8(0x06) // end-of-actions
	return out
}

// modify_node_hash returns the lowercase hex SHA-256 of the canonical
// disjoint-domain byte form. Equal ModifyNodes (per `.eq()`) produce
// equal hashes. The leading `ModifyNode\x00` prefix guarantees the
// hash cannot collide with element / scalar / atom / PathNode /
// MatchNode / PredicateExpr hashes by construction.
pub fn modify_node_hash(m ModifyNode) string {
	digest := sha256.sum256(modify_node_canonical_bytes(m))
	return digest.hex()
}

// ── JSON projection ───────────────────────────────────────────────────────────

// modify_node_to_json returns the AST-JSON projection of a ModifyNode.
// The shape:
//
//   {
//     "type":    "ProgramModifyExpr",
//     "doc":     "<src>",
//     "focus":   "<src>",
//     "actions": [ { "kind": ..., "name": ..., "value": ... }, ... ],
//     "source":  "<src>",                       // omit when none
//     "loc":     { "start": N, "end": M }      // omit when none
//   }
//
// Each action projects with:
//   - "kind"  : canonical action-kind spelling (e.g. "set-attr")
//   - "name"  : present when the action carries a Name slot
//               ([rename] / [set-attr] / [delete-attr]); omitted otherwise
//   - "value" : present when the action carries a ProgramExpr slot;
//               omitted for [delete] / [delete-attr] / [rename]
//
// "ProgramModifyExpr" is the parser-internal JSON `type` tag; at the
// AST-bin boundary the projection will collapse to `"ModifyNode"` per
// the spec when the wire slot lands.
//
// Phase 2.5 leaves doc / focus / action-slot values as verbatim source
// strings; the Phase 2.x graft replaces these with structural subtrees,
// extending the wire shape rather than breaking it.
pub fn modify_node_to_json(m ModifyNode) string {
	mut pairs := []string{}
	pairs << '"type":"ProgramModifyExpr"'
	pairs << '"doc":${json_str(m.doc)}'
	pairs << '"focus":${json_str(m.focus)}'
	mut actions_json := []string{cap: m.actions.len}
	for action in m.actions {
		actions_json << modify_action_to_json(action)
	}
	pairs << '"actions":[${actions_json.join(',')}]'
	if src := m.source {
		pairs << '"source":${json_str(src)}'
	}
	if l := m.loc {
		pairs << '"loc":{"start":${l.start},"end":${l.end}}'
	}
	return '{${pairs.join(',')}}'
}

fn modify_action_to_json(action ModifyAction) string {
	mut pairs := []string{}
	pairs << '"kind":"${modify_action_kind_name(action.kind)}"'
	// "name" key present only for Name-slot actions.
	has_name := action.kind == ModifyActionKind.rename
		|| action.kind == ModifyActionKind.set_attr
		|| action.kind == ModifyActionKind.delete_attr
	if has_name {
		pairs << '"name":${json_str(action.name)}'
	}
	// "value" key present only for expression-slot actions.
	has_value := action.kind == ModifyActionKind.set
		|| action.kind == ModifyActionKind.using_fn
		|| action.kind == ModifyActionKind.set_attr
		|| action.kind == ModifyActionKind.append
		|| action.kind == ModifyActionKind.prepend
		|| action.kind == ModifyActionKind.insert_before
		|| action.kind == ModifyActionKind.insert_after
		|| action.kind == ModifyActionKind.replace
	if has_value {
		pairs << '"value":${json_str(action.value)}'
	}
	return '{${pairs.join(',')}}'
}

// ── Binary codec hook (DEFERRED) ──────────────────────────────────────────────

// TODO(Phase 2.5 follow-up): wire codec.
//
// ModifyNode wire-format slot is pending wire-slot allocation —
// analogous to the PathNode codec landed at Phase 1.7+ and the
// MatchNode codec deferral at Phase 2.4. Until the slot lands:
//   - emit_ast_bin MUST reject ModifyNode values with the standard
//     unknown-kind error (currently moot: ModifyNode is not yet a
//     Node sum-type variant).
//   - parse_ast_bin MUST surface a clear error if it encounters a
//     wire byte in ModifyNode's pending slot range.
//
// When the slot lands this file gains:
//   - fn modify_node_to_bin(m ModifyNode) []u8
//   - fn bin_to_modify_node(bytes []u8, mut pos int) !ModifyNode
// plus integration into binary.v's emit/parse dispatch and `Node`
// sum-type integration in the matching phase.
