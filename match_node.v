module cx

import crypto.sha256

// match_node.v — MatchNode AST (v0.8.0).
//
// MatchNode is the spec-canonical first-class AST node for the multi-arm
// `[?match]` directive — heterogeneous arms of three kinds (`:case`
// pattern arm, `:when` predicate arm, `:else` fallback arm) with optional
// `:where` guards on `:case` arms — collapsing grammar productions
// [136]–[140] onto a single value kind with arm-kind discriminator.
//
// This file is the Phase 2.4 foundational AST layer:
//   - structs (MatchNode, MatchArm, MatchLoc) + helpers
// structural equality (source + loc excluded pattern
// adopted into by symmetry)
//   - canonical hashing (disjoint-domain hash via `MatchNode\x00`-prefixed
//     canonical-string form passed through SHA-256, mirroring the
//     PathNode convention)
//   - JSON projection (`{"type":"ProgramMatchExpr", …}`)
//
// Out of scope at Phase 2.4 (deferred):
//   - Evaluator (first-match-wins, no EBV in `:case`, `:else` fallback,
//     `CXER0100` raise for 2-arg no-match) — Phase 2.7.
//   - Binary (ast_bin) codec — wire-format slot allocation pending,
//     analogous to the PathNode follow-up tracked at Phase 1.7+.
//   - Node sum-type integration — adding MatchNode to `cx.Node` cascades
//     exhaustive match arms across every emitter / decoder, so it lives
//     in a later Phase 2.x slice. The Phase 2.4 contract is "datum +
//     projection are available as standalone helpers".
//   - Structural ProgramExpr subtree under arm bodies + `:where` guards
//     + pattern bodies — those carry the verbatim source-text snippet
//     for now (mirrors PathPredicate.source); the Phase 2.4 follow-up
//     grafts in the ProgramExpr AST without changing the projected
//     JSON wire shape.
//
// Cross-references:
//   - spec/grammar.ebnf productions [136]–[140]

// ── Enums ─────────────────────────────────────────────────────────────────────

// ArmKind discriminates the three arm shapes admitted.
//   - case_arm : `:case PATTERN (':where' GUARD)? :yield BODY` — pattern test
//   - when_arm : `:when PREDICATE :yield BODY` — predicate test (SQL Searched-CASE)
//   - else_arm : `:else :yield BODY` — fallback; at most one, must be last
pub enum ArmKind {
	case_arm
	when_arm
	else_arm
}

// ── Structs ───────────────────────────────────────────────────────────────────

// MatchLoc carries an optional source-position record. Advisory; not
// part of equality or hashing (symmetric).
// `start` / `end` are byte offsets into the original source string;
// populated by the parser when source-location tracking is enabled,
// left as 0/0 otherwise.
pub struct MatchLoc {
pub mut:
	start int
	end   int
}

// MatchArm carries one arm of a multi-arm `[?match]` expression. Per
// the three arm shapes share a single struct with `kind`
// discriminator. Field meanings by `kind`:
//
//   - .case_arm : `pattern` holds the verbatim pattern source-text
//                 (e.g. `[prose $p]`, `200`, `_`, `//user`);
//                 `guard` is `?string` with the verbatim `:where` body
//                 (none when no guard); `body` holds the `:yield` body.
//   - .when_arm : `pattern` is empty; `guard` holds the verbatim
//                 predicate body (the `:when` expression — stored in
//                 `guard` rather than `pattern` so the field carries
//                 a consistent semantic meaning across arm kinds —
//                 "the condition this arm tests"); `body` holds the
//                 `:yield` body.
//   - .else_arm : `pattern` is empty; `guard` is none; `body` holds
//                 the `:yield` body.
//
// At Phase 2.4 every body slot is a verbatim source-text string
// (mirrors `PathPredicate.source`); the Phase 2.x ProgramExpr-AST
// graft will refine these into structural subtrees without changing
// the projected JSON wire shape.
//
// Equality + hashing operate on the verbatim strings at Phase 2.4 —
// this is conservative (two arms whose bodies evaluate identically
// but were spelled differently compare unequal). The graft to
// structural ProgramExpr equality is a follow-up.
pub struct MatchArm {
pub mut:
	kind    ArmKind
	pattern string   // :case pattern source; empty for :when / :else
	guard   ?string  // :case :where body OR :when predicate body; none for :else
	body    string   // :yield body source — always present
	loc     ?MatchLoc
	// Z79b — structural ProgramExpr-AST graft (Phase 2.4 follow-up).
	//
	// These three slots carry the parsed cx.Node tree of the
	// pattern / guard / body strings. They are populated by
	// `parse_match` on a best-effort basis: when `cx.parse(source)`
	// succeeds the first parsed element is captured here; otherwise
	// the field is left as `none` and downstream consumers fall back
	// to the verbatim source string.
	//
	// Additive only — the verbatim string fields above remain the
	// canonical identity-participating data at Phase 2.4. The
	// structural-AST equality + hashing graft is a separate follow-up
	// (the bytes from `match_node_canonical_bytes` still use the
	// strings so two MatchNodes parsed from the same source produce
	// the same hash regardless of whether `cx.parse` succeeded on
	// the snippet).
	//
	// `?Node` stores by value — V's sum-type representation pools the
	// active variant so an absent field pays only the option-tag byte
	// plus a discriminator. Heap-pointer form (`?&Node`) would require
	// additional plumbing because `cx.Node` is a sum type that V's
	// codegen does not pointer-allocate via `&Node(value)` cleanly.
	pattern_node ?Node
	guard_node   ?Node
	body_node    ?Node
}

// MatchNode is the spec-canonical first-class AST node for the multi-arm
// `[?match]` directive. See file-level comment for the
// full contract.
//
// `scrutinee` carries the verbatim source-text of the value-being-matched
// expression (the `Value` slot in grammar [136]). It is `?string` because
// the predicate-only mode (`[?match :when … :yield …]` — SQL Searched
// CASE) admits an absent scrutinee; absent value yields
// none.
//
// `arms` is the ordered list of MatchArm values. declares
// first-match-wins semantics; the parser preserves source order, and
// `:else` arm (if present) MUST be the last entry.
pub struct MatchNode {
pub mut:
	scrutinee ?string    // verbatim source of the matched expression; none = predicate-only
	arms      []MatchArm
	source    ?string    // verbatim source-text snippet of the full [?match …] form (advisory)
	loc       ?MatchLoc  // source position (advisory)
}

// ── Constructors ──────────────────────────────────────────────────────────────

// new_match_node constructs a minimal MatchNode with the given scrutinee
// + arms. `source` and `loc` are left none.
pub fn new_match_node(scrutinee ?string, arms []MatchArm) MatchNode {
	return MatchNode{
		scrutinee: scrutinee
		arms:      arms
	}
}

// new_case_arm constructs a `:case PATTERN :yield BODY` arm with no guard.
pub fn new_case_arm(pattern string, body string) MatchArm {
	return MatchArm{
		kind:    ArmKind.case_arm
		pattern: pattern
		body:    body
	}
}

// new_case_arm_guarded constructs a `:case PATTERN :where GUARD :yield BODY` arm.
pub fn new_case_arm_guarded(pattern string, guard string, body string) MatchArm {
	return MatchArm{
		kind:    ArmKind.case_arm
		pattern: pattern
		guard:   guard
		body:    body
	}
}

// new_when_arm constructs a `:when PREDICATE :yield BODY` arm. The
// predicate body lives in the `guard` field (see MatchArm doc).
pub fn new_when_arm(predicate string, body string) MatchArm {
	return MatchArm{
		kind:  ArmKind.when_arm
		guard: predicate
		body:  body
	}
}

// new_else_arm constructs an `:else :yield BODY` arm.
pub fn new_else_arm(body string) MatchArm {
	return MatchArm{
		kind: ArmKind.else_arm
		body: body
	}
}

// ── Structural-graft helpers (Z79b) ──────────────────────────────────────────

// node_structural_eq compares two parsed cx.Node values for 
// "kind + canonical-representation equality". The comparison is
// conservative: two nodes are structurally equal iff (a) the V sum-type
// discriminator matches; AND (b) for Element variants the name + items
// length match (a deep recursive compare lands in a follow-up — the
// Phase 2.4 contract here is "kind agreement is the structural-graft
// equality surface; the verbatim-string fallback covers everything
// else").
//
// `==` on V sum types compares the active variant's auto-generated
// equality including byte-equality on string fields. Since `cx.Element`
// carries pointer fields (`meta`, `table`) that may differ between two
// parses of the same source, we cannot rely on `a == b` for structural
// equality directly. The kind-plus-name compare here is good enough to
// demonstrate the structural-graft wiring; the full canonical-bytes
// hash comparison is the v0.8.x follow-up.
pub fn node_structural_eq(a Node, b Node) bool {
	// Same variant + same canonical-name representation, recursing
	// into Element.items so `[user 1]` and `[user 2]` distinguish.
	match a {
		Element {
			if b is Element {
				if a.name != b.name {
					return false
				}
				if a.items.len != b.items.len {
					return false
				}
				for i, item in a.items {
					if !node_structural_eq(item, b.items[i]) {
						return false
					}
				}
				return true
			}
			return false
		}
		ScalarNode {
			if b is ScalarNode {
				return a.data_type == b.data_type
					&& scalar_value_str_public(a.value)
						== scalar_value_str_public(b.value)
			}
			return false
		}
		TextNode {
			if b is TextNode {
				return a.value == b.value
			}
			return false
		}
		else {
			// Fallback: same-variant + V's auto `==` (best effort). When
			// V's auto equality is unreliable (pointer fields), this still
			// disagrees safely — callers fall back to verbatim-string
			// equality for those variants at Phase 2.4.
			return a == b
		}
	}
}

// try_parse_snippet_to_node attempts to parse a verbatim source-text
// snippet (the kind that lives in `MatchArm.pattern` / `.guard` / `.body`
// or `ModifyAction.value`) into a single `cx.Node` via `cx.parse`. On
// success returns the first parsed element of the resulting Document;
// on parse failure returns `none` so callers can fall back to the
// verbatim string path.
//
// `cx.parse` is lenient — bare scalars / atom literals parse as
// TextNode or ScalarNode, bracketed forms parse as Element. Only
// genuinely-malformed inputs (e.g. unclosed brackets) return `none`.
// The structural-graft tests cover this surface plus the practical
// case where structural equality buys whitespace-insensitivity over
// byte-equality.
pub fn try_parse_snippet_to_node(src string) ?Node {
	t := src.trim_space()
	if t.len == 0 {
		return none
	}
	doc := parse(t) or { return none }
	if doc.elements.len == 0 {
		return none
	}
	return doc.elements[0]
}

// ── ArmKind ↔ string ──────────────────────────────────────────────────────────

// arm_kind_name returns the canonical spec spelling of an ArmKind.
// Used by JSON projection and the canonical hashing pipeline; the
// inverse is arm_kind_from_name.
pub fn arm_kind_name(k ArmKind) string {
	return match k {
		.case_arm { 'case' }
		.when_arm { 'when' }
		.else_arm { 'else' }
	}
}

// arm_kind_from_name parses a canonical arm-kind spelling back into the
// ArmKind enum. Returns none for unknown spellings.
pub fn arm_kind_from_name(name string) ?ArmKind {
	return match name {
		'case' { ?ArmKind(ArmKind.case_arm) }
		'when' { ?ArmKind(ArmKind.when_arm) }
		'else' { ?ArmKind(ArmKind.else_arm) }
		else   { none }
	}
}

// ── Equality ──────────────────────────────────────────────────────────────────

// eq returns true iff two MatchNode values are structurally equal under
// the identity rule (adopted by by symmetry). The
// `source` and `loc` fields are advisory and do NOT participate in
// equality. Two MatchNodes parsed from differently-formatted source
// compare equal as long as the arm order + arm shapes match.
//
// V auto-generates `==` for the underlying struct shape which would
// include `source` + `loc`; callers MUST use this method (or the
// canonical-bytes hash) for identity.
pub fn (m MatchNode) eq(other MatchNode) bool {
	// Scrutinee optional-equality.
	if (m.scrutinee == none) != (other.scrutinee == none) {
		return false
	}
	if ms := m.scrutinee {
		os := other.scrutinee or { '' }
		if ms != os {
			return false
		}
	}
	if !match_arms_eq(m.arms, other.arms) {
		return false
	}
	return true
}

// eq compares two arms for structural equality (kind + pattern + guard
// + body). The `loc` field is advisory and excluded.
//
// Z79b structural graft: per-slot, when BOTH sides carry a parsed Node
// in the corresponding `*_node` field the comparison promotes to
// `node_structural_eq` (kind + canonical-name agreement). When EITHER
// side has `none` the comparison falls back to verbatim-string
// equality — preserves backward compatibility with arms built without
// the structural graft.
pub fn (a MatchArm) eq(other MatchArm) bool {
	if a.kind != other.kind {
		return false
	}
	// Pattern slot — prefer node-comparison when both sides present.
	if an := a.pattern_node {
		if bn := other.pattern_node {
			if !node_structural_eq(an, bn) {
				return false
			}
		} else if a.pattern != other.pattern {
			return false
		}
	} else if a.pattern != other.pattern {
		return false
	}
	// Guard slot.
	if (a.guard == none) != (other.guard == none) {
		return false
	}
	if ag := a.guard {
		og := other.guard or { '' }
		if agn := a.guard_node {
			if bgn := other.guard_node {
				if !node_structural_eq(agn, bgn) {
					return false
				}
			} else if ag != og {
				return false
			}
		} else if ag != og {
			return false
		}
	}
	// Body slot.
	if abn := a.body_node {
		if bbn := other.body_node {
			if !node_structural_eq(abn, bbn) {
				return false
			}
		} else if a.body != other.body {
			return false
		}
	} else if a.body != other.body {
		return false
	}
	return true
}

fn match_arms_eq(a []MatchArm, b []MatchArm) bool {
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

// match_node_canonical_bytes returns the canonical byte form of a
// MatchNode used as input to the disjoint-domain hash function. The
// byte form is a deterministic textual encoding of the identity-
// participating fields (scrutinee + arms only) — source + loc are
// excluded.
//
// Disjoint-domain prefix: the bytes start with the literal ASCII
// `MatchNode\x00` followed by a `\x01`-delimited scrutinee slot and
// per-arm `\x02`-prefixed segments. The `\x00` byte after the type
// tag cannot occur inside a CX canonical surface (UTF-8 content with
// no in-band NUL), so MatchNode hashes inhabit a domain disjoint
// from element / scalar / atom / PathNode hashes by construction.
//
// Mirrors the PathNode disjoint-domain hashing convention in
// path_node.v; motivates the pattern.
pub fn match_node_canonical_bytes(m MatchNode) []u8 {
	mut out := []u8{}
	out << 'MatchNode'.bytes()
	out << u8(0x00)
	// Scrutinee slot.
	if s := m.scrutinee {
		out << u8(0x10) // scrutinee-present marker
		out << s.bytes()
	} else {
		out << u8(0x11) // scrutinee-absent marker
	}
	out << u8(0x01)
	// Arm list — per-arm delimiter `\x02`, intra-arm fields delimited
	// by `\x03` (kind), `\x04` (pattern), `\x05` (guard), `\x06` (body).
	for arm in m.arms {
		out << u8(0x02)
		out << arm_kind_name(arm.kind).bytes()
		out << u8(0x03)
		out << arm.pattern.bytes()
		out << u8(0x04)
		if g := arm.guard {
			out << u8(0x20) // guard-present marker
			out << g.bytes()
		} else {
			out << u8(0x21) // guard-absent marker
		}
		out << u8(0x05)
		out << arm.body.bytes()
		out << u8(0x06)
	}
	out << u8(0x07) // end-of-arms
	return out
}

// match_node_hash returns the lowercase hex SHA-256 of the canonical
// disjoint-domain byte form. Equal MatchNodes (per `.eq()`) produce
// equal hashes. The leading `MatchNode\x00` prefix guarantees the
// hash cannot collide with element / scalar / atom / PathNode hashes
// by construction.
pub fn match_node_hash(m MatchNode) string {
	digest := sha256.sum256(match_node_canonical_bytes(m))
	return digest.hex()
}

// ── JSON projection ───────────────────────────────────────────────────────────

// match_node_to_json returns the AST-JSON projection of a MatchNode.
// The shape:
//
//   {
//     "type":      "ProgramMatchExpr",
//     "scrutinee": "<src>",            // omit when none (predicate-only mode)
//     "arms":      [ { "kind": ..., "pattern": ..., "guard": ..., "body": ... }, ... ],
//     "source":    "<src>",            // omit when none
//     "loc":       { "start": N, "end": M }  // omit when none
//   }
//
// Each arm projects with:
//   - "kind"    : "case" | "when" | "else"
//   - "pattern" : present (possibly empty string) for case_arm; omitted for when_arm / else_arm
//   - "guard"   : present for case_arm with :where guard OR for when_arm (the :when predicate);
//                 omitted for else_arm and unguarded case_arm
//   - "body"    : always present (the :yield body)
//
// "ProgramMatchExpr" is the parser-internal JSON `type` tag; at the
// AST-bin boundary the projection will collapse to `"MatchNode"` per
// the spec when the wire slot lands.
//
// Phase 2.4 leaves pattern / guard / body as verbatim source strings;
// the Phase 2.x graft replaces these with structural ProgramExpr
// subtrees, extending the wire shape rather than breaking it.
pub fn match_node_to_json(m MatchNode) string {
	mut pairs := []string{}
	pairs << '"type":"ProgramMatchExpr"'
	if s := m.scrutinee {
		pairs << '"scrutinee":${json_str(s)}'
	}
	mut arms_json := []string{cap: m.arms.len}
	for arm in m.arms {
		arms_json << match_arm_to_json(arm)
	}
	pairs << '"arms":[${arms_json.join(',')}]'
	if src := m.source {
		pairs << '"source":${json_str(src)}'
	}
	if l := m.loc {
		pairs << '"loc":{"start":${l.start},"end":${l.end}}'
	}
	return '{${pairs.join(',')}}'
}

fn match_arm_to_json(arm MatchArm) string {
	mut pairs := []string{}
	pairs << '"kind":"${arm_kind_name(arm.kind)}"'
	if arm.kind == ArmKind.case_arm {
		pairs << '"pattern":${json_str(arm.pattern)}'
	}
	if g := arm.guard {
		pairs << '"guard":${json_str(g)}'
	}
	pairs << '"body":${json_str(arm.body)}'
	return '{${pairs.join(',')}}'
}

// ── Binary codec hook (DEFERRED) ──────────────────────────────────────────────

// TODO(Phase 2.4 follow-up): wire codec.
//
// MatchNode wire-format slot is pending wire-slot allocation —
// analogous to the PathNode codec landed at Phase 1.7+. Until the
// slot lands:
//   - emit_ast_bin MUST reject MatchNode values with the standard
//     unknown-kind error (currently moot: MatchNode is not yet a
//     Node sum-type variant).
//   - parse_ast_bin MUST surface a clear error if it encounters a
//     wire byte in MatchNode's pending slot range.
//
// When the slot lands this file gains:
//   - fn match_node_to_bin(m MatchNode) []u8
//   - fn bin_to_match_node(bytes []u8, mut pos int) !MatchNode
// plus integration into binary.v's emit/parse dispatch and `Node`
// sum-type integration in the matching phase.
