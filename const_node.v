module cx

import crypto.sha256

// const_node.v — ConstNode AST (v0.8.0).
//
// ConstNode is the spec-canonical first-class AST node for the
// `[?const NAME EXPR]` module-level constant directive
// D12 — collapsing grammar productions [154]–[154a] onto a single
// value kind with a verbatim value-expression source slot plus the
// `:lazy` / `:scope` modifier slots.
//
// This file is the Phase 2.12 Part 2 (Z2) foundational AST layer:
//   - structs (ConstNode, ConstLoc) + helpers
// structural equality (source + loc excluded per the 
// pattern adopted into by symmetry with DefNode)
//   - canonical hashing (disjoint-domain hash via `ConstNode\x00`-prefixed
//     canonical-string form passed through SHA-256, mirroring the
//     PathNode / MatchNode / ModifyNode / PredicateExpr / DefNode
//     convention)
//   - JSON projection (`{"type":"ProgramConstExpr", …}`)
//
// Out of scope at Phase 2.12 Part 2 (deferred):
//   - Evaluator (two-pass module load, eager vs lazy memoization,
//     cycle detection raising CXER0214, body-failure raising
//     CXER0215) — Phase 2.13.
//   - Binary (ast_bin) codec — wire-format slot allocation pending,
//     analogous to the PathNode / DefNode follow-up tracked at
//     Phase 1.7+ / 2.12 Part 1.
//   - Node sum-type integration — adding ConstNode to `cx.Node`
//     cascades exhaustive match arms across every emitter / decoder,
//     so it lives in a later Phase 2.x slice. The Phase 2.12 Part 2
//     contract is "datum + projection are available as standalone
//     helpers".
//   - Structural ProgramExpr subtree under the value slot — the
//     verbatim source-text snippet is captured for now (mirrors
//     PathPredicate.source / DefNode.body); the Phase 2.16 follow-up
//     grafts in the structural subtree without changing the projected
//     JSON wire shape.
//   - `:scope public/private` visibility enforcement (Phase 2.15).
//     At Phase 2.12 Part 2 the modifier is parsed and stored on the
//     ConstNode but no scope-rule is enforced.
//
// Cross-references:
//   - spec/grammar.ebnf productions [154]–[154a]
//   - spec/code.md §12.3 (normative semantics)
//   - vcx/cx/def_node.v (Z1 sibling — same shape conventions)

// ── Structs ───────────────────────────────────────────────────────────────────

// ConstLoc carries an optional source-position record. Advisory; not
// part of equality or hashing (symmetric
// with DefLoc). `start` / `end` are byte offsets into the
// original source string; populated by the parser when source-
// location tracking is enabled, left as 0/0 otherwise.
pub struct ConstLoc {
pub mut:
	start int
	end   int
}

// ConstNode is the spec-canonical first-class AST node for the
// `[?const NAME EXPR]` module-level constant directive
// D12. See file-level comment for the full contract.
//
// `name` is the constant identifier (required). Per the
// name is module-scoped, single-assignment, immutable.
//
// `value_source` carries the verbatim source-text of the single
// ProgramExpr that produces the constant's value. At Phase 2.12 Part 2
// this is a string; the Phase 2.16 graft replaces it with a structural
// ProgramExpr subtree.
//
// `lazy` is true when the `:lazy` modifier was present. Per 
// D12.2 a lazy const defers evaluation to first read and memoizes
// thereafter. Default (no `:lazy`) is eager — computed at module load
// per D12.1.
//
// `scope` carries the verbatim spelling of the `:scope` modifier
// (`"public"` or `"private"`). None when no `:scope` modifier
// appeared. Visibility enforcement is Phase 2.15.
pub struct ConstNode {
pub mut:
	name         string
	value_source string
	lazy         bool
	scope        ?string
	source       ?string  // verbatim source-text snippet of the full [?const …] form (advisory)
	loc          ?ConstLoc // source position (advisory)
}

// ── Constructors ──────────────────────────────────────────────────────────────

// new_const_node constructs a minimal eager ConstNode with the given
// name + value_source. `scope` / `source` / `loc` are left none; `lazy`
// defaults to false (eager).
pub fn new_const_node(name string, value_source string) ConstNode {
	return ConstNode{
		name:         name
		value_source: value_source
	}
}

// new_const_node_lazy constructs a lazy ConstNode (`:lazy` modifier
// present).
pub fn new_const_node_lazy(name string, value_source string) ConstNode {
	return ConstNode{
		name:         name
		value_source: value_source
		lazy:         true
	}
}

// ── Equality ──────────────────────────────────────────────────────────────────

// eq returns true iff two ConstNode values are structurally equal
// under the identity rule (adopted by by
// symmetry). The `source` and `loc` fields are advisory and do NOT
// participate in equality. Two ConstNodes parsed from differently-
// formatted source compare equal as long as name + value_source +
// lazy + scope match.
//
// V auto-generates `==` for the underlying struct shape which would
// include `source` + `loc`; callers MUST use this method (or the
// canonical-bytes hash) for identity.
pub fn (c ConstNode) eq(other ConstNode) bool {
	if c.name != other.name {
		return false
	}
	if c.value_source != other.value_source {
		return false
	}
	if c.lazy != other.lazy {
		return false
	}
	if !const_opt_string_eq(c.scope, other.scope) {
		return false
	}
	return true
}

fn const_opt_string_eq(a ?string, b ?string) bool {
	if (a == none) != (b == none) {
		return false
	}
	if av := a {
		bv := b or { '' }
		if av != bv {
			return false
		}
	}
	return true
}

// ── Canonical bytes + hashing ─────────────────────────────────────────────────

// const_node_canonical_bytes returns the canonical byte form of a
// ConstNode used as input to the disjoint-domain hash function. The
// byte form is a deterministic textual encoding of the identity-
// participating fields (name + value_source + lazy + scope only) —
// source + loc are excluded.
//
// Disjoint-domain prefix: the bytes start with the literal ASCII
// `ConstNode\x00` followed by `\x01`-delimited slots. The `\x00`
// byte after the type tag cannot occur inside a CX canonical surface
// (UTF-8 content with no in-band NUL), so ConstNode hashes inhabit a
// domain disjoint from element / scalar / atom / PathNode /
// MatchNode / ModifyNode / PredicateExpr / DefNode hashes by
// construction.
pub fn const_node_canonical_bytes(c ConstNode) []u8 {
	mut out := []u8{}
	out << 'ConstNode'.bytes()
	out << u8(0x00)
	// Name slot.
	out << u8(0x10)
	out << c.name.bytes()
	out << u8(0x01)
	// Value-source slot.
	out << u8(0x11)
	out << c.value_source.bytes()
	out << u8(0x01)
	// Lazy flag slot.
	out << u8(0x12)
	out << if c.lazy { u8(0x40) } else { u8(0x41) }
	out << u8(0x01)
	// Scope slot.
	if sc := c.scope {
		out << u8(0x13) // scope-present marker
		out << sc.bytes()
	} else {
		out << u8(0x14) // scope-absent marker
	}
	return out
}

// const_node_hash returns the lowercase hex SHA-256 of the canonical
// disjoint-domain byte form. Equal ConstNodes (per `.eq()`) produce
// equal hashes. The leading `ConstNode\x00` prefix guarantees the
// hash cannot collide with element / scalar / atom / PathNode /
// MatchNode / ModifyNode / PredicateExpr / DefNode hashes by
// construction.
pub fn const_node_hash(c ConstNode) string {
	digest := sha256.sum256(const_node_canonical_bytes(c))
	return digest.hex()
}

// ── JSON projection ───────────────────────────────────────────────────────────

// const_node_to_json returns the AST-JSON projection of a ConstNode.
// The shape:
//
//   {
//     "type":   "ProgramConstExpr",
//     "name":   "<NAME>",
//     "value":  "<src>",
//     "lazy":   true,                            // omit when false
//     "scope":  "public" | "private",            // omit when none
//     "source": "<src>",                         // omit when none
//     "loc":    { "start": N, "end": M }         // omit when none
//   }
//
// "ProgramConstExpr" is the parser-internal JSON `type` tag; at the
// AST-bin boundary the projection will collapse to `"ConstNode"` per
// the spec when the wire slot lands.
//
// Phase 2.12 Part 2 leaves value_source as a verbatim source string;
// the Phase 2.16 graft replaces it with a structural ProgramExpr
// subtree, extending the wire shape rather than breaking it.
pub fn const_node_to_json(c ConstNode) string {
	mut pairs := []string{}
	pairs << '"type":"ProgramConstExpr"'
	pairs << '"name":${json_str(c.name)}'
	pairs << '"value":${json_str(c.value_source)}'
	if c.lazy {
		pairs << '"lazy":true'
	}
	if sc := c.scope {
		pairs << '"scope":${json_str(sc)}'
	}
	if src := c.source {
		pairs << '"source":${json_str(src)}'
	}
	if l := c.loc {
		pairs << '"loc":{"start":${l.start},"end":${l.end}}'
	}
	return '{${pairs.join(',')}}'
}

// ── Binary codec hook (DEFERRED) ──────────────────────────────────────────────

// TODO(Phase 2.12 follow-up): wire codec.
//
// ConstNode wire-format slot is pending wire-slot allocation —
// analogous to the PathNode codec landed at Phase 1.7+ and the
// MatchNode / ModifyNode / DefNode codec deferral at Phases 2.4 /
// 2.5 / 2.12. Until the slot lands:
//   - emit_ast_bin MUST reject ConstNode values with the standard
//     unknown-kind error (currently moot: ConstNode is not yet a
//     Node sum-type variant).
//   - parse_ast_bin MUST surface a clear error if it encounters a
//     wire byte in ConstNode's pending slot range.
//
// When the slot lands this file gains:
//   - fn const_node_to_bin(c ConstNode) []u8
//   - fn bin_to_const_node(bytes []u8, mut pos int) !ConstNode
// plus integration into binary.v's emit/parse dispatch and `Node`
// sum-type integration in the matching phase.
