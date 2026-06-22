module cx

import crypto.sha256

// def_node.v — DefNode AST.
//
// DefNode is the spec-canonical first-class AST node for the
// `[?def NAME (PARAMS…) BODY]` module-level static function directive —
// per collapsing grammar productions [152]–[153f] onto a
// single value kind with an ordered list of DefParam slots.
//
// This file is the Phase 2.12 (Part 1) foundational AST layer:
//   - structs (DefNode, DefParam, DefLoc) + helpers
// structural equality (source + loc excluded per the 
// pattern adopted into by symmetry)
//   - canonical hashing (disjoint-domain hash via `DefNode\x00`-prefixed
//     canonical-string form passed through SHA-256, mirroring the
//     PathNode / MatchNode / ModifyNode / PredicateExpr convention)
//   - JSON projection (`{"type":"ProgramDefExpr", …}`)
//
// Out of scope at Phase 2.12 Part 1 (deferred):
//   - Evaluator (two-pass module load, name resolution, argument
//     binding, dev-strict type validation, mutual recursion) —
//     Phases 2.13 + 2.16.
//   - Binary (ast_bin) codec — wire-format slot allocation pending,
//     analogous to the PathNode follow-up tracked at Phase 1.7+.
//   - Node sum-type integration — adding DefNode to `cx.Node`
//     cascades exhaustive match arms across every emitter / decoder,
//     so it lives in a later Phase 2.x slice. The Phase 2.12 contract
//     is "datum + projection are available as standalone helpers".
//   - Structural ProgramExpr subtree under the body slot + structural
//     TypeExprNode under per-parameter `type_expr` / top-level
//     `returns_type` slots — those carry the verbatim source-text
//     snippet for now (mirrors PathPredicate.source); the Phase 2.16
//     follow-up grafts in the structural subtrees without changing
//     the projected JSON wire shape.
//   - `:scope public/private` modifier slot (Phase 2.15 visibility
//     enforcement). At Phase 2.12 Part 1 the modifier is parsed and
//     stored on the DefNode but no scope-rule is enforced.
//   - Static purity checker (Phase 2.22) — the `:pure` / `:impure`
//     modifier slot is parsed at Phase 2.23 (this file) and is
//     identity-relevant on the DefNode; checker enforcement (call-
//     graph inference + CXER0233 / CXER0234) lands at Phase 2.22.
//
// Cross-references:
//   - spec/grammar.ebnf productions [152]–[153f]

// ── Structs ───────────────────────────────────────────────────────────────────

// Purity tags a DefNode as `:pure` (default) or `:impure` per
// amendment. The discriminator is identity-relevant
// — a function declared `:impure` is a distinct value from a
// same-body function declared (or defaulting to) `:pure` because
// the annotation gates what calls the body may legally make
// (Phase 2.22 static checker).
//
// V keyword constraint: `pure` and `impure` are not V reserved
// words today but the trailing-underscore convention mirrors the
// safe-naming pattern used elsewhere in the cx module (e.g.
// MatchArm variants) so future-renames stay mechanical.
pub enum Purity {
	pure_
	impure_
}

// DefLoc carries an optional source-position record. Advisory; not
// part of equality or hashing (symmetric).
// `start` / `end` are byte offsets into the original source string;
// populated by the parser when source-location tracking is enabled,
// left as 0/0 otherwise.
pub struct DefLoc {
pub mut:
	start int
	end   int
}

// DefParam carries one parameter of a `[?def]` argument list. Per
// the parameter list supports three shapes:
//
//   - Positional parameter            : `name` or `name:T`
//   - Named (keyword) parameter       : `:name` (optional default)
//   - Rest parameter                  : `:rest name` (last only)
//
// Type-annotation slots — Phase 2.12 Part 1 (Z1) captured the `:T`
// annotation as a verbatim source-string only; Phase 2.16 grafted a
// structural TypeExpr alongside that source. Both slots coexist:
//
//   - `type_expr_source` — verbatim source-text of the `:T`
// annotation (e.g. `string`, `Person`,
//     `[or Person null]`, `[sequence Token]`). None when the
//     parameter is untyped. Always populated for typed params (the
//     parser writes through to it regardless of structural-parse
//     success).
//   - `type_expr` — structural TypeExpr per spec/code.md §12.7 (Phase
//     2.16). None when the parameter is untyped OR when structural
//     parsing failed (in which case `type_expr_source` remains the
//     source of truth and the dev-strict validator can still flag
//     missing annotations).
//
// At Phase 2.12 Part 1 only positional + named bareword shapes are
// captured at the AST level; `default` (NamedParam) and
// `rest_flag` (RestParam) carry the verbatim source so
// the AST round-trips losslessly even before the evaluator wires
// them in.
pub struct DefParam {
pub mut:
	name             string    // parameter identifier (bareword)
	type_expr_source ?string   // optional :T annotation (verbatim source) — Phase 2.12
	type_expr        ?TypeExpr // optional :T annotation (structural)      — Phase 2.16
	is_named         bool      // true for `:name` keyword params; false for positional
	is_rest          bool      // true for `:rest name` variadic; at most one per list
	default          ?string   // optional default-value source (named-param only)
	loc              ?DefLoc
}

// DefNode is the spec-canonical first-class AST node for the
// `[?def NAME …]` module-level function directive.
// See file-level comment for the full contract.
//
// `name` is the function identifier (required).
//
// `params` is the ordered list of DefParam values; 
// allows positional, named (with defaults), and a trailing `:rest`
// param. Source order is preserved.
//
// `body` carries the verbatim source-text of the single
// ProgramExpr that is the function's value when called. At Phase
// 2.12 Part 1 this is a string; the Phase 2.x graft replaces it
// with a structural ProgramExpr subtree.
//
// Return-type slots — Phase 2.12 Part 1 captured `:returns T` as
// verbatim source only; Phase 2.16 grafted a structural TypeExpr
// alongside that source. Both slots coexist:
//
//   - `returns_type_source` — verbatim source-text of the
// `:returns T` modifier (e.g. `string`,
//     `[or Person null]`). None when the function is untyped at the
//     boundary. Always populated when `:returns` is present.
//   - `returns_type_expr` — structural TypeExpr (Phase 2.16). None
//     when no `:returns` modifier OR when structural parsing failed
//     (verbatim source still drives identity in that case).
//
// `scope` carries the verbatim spelling of the `:scope` modifier
// (`"public"` or `"private"`). None when no `:scope` modifier
// appeared. Visibility enforcement is Phase 2.15.
//
// `purity` carries the `:pure` / `:impure` annotation
// D11. Defaults to `.pure_` when neither modifier is supplied
// (D11.1). Identity-relevant: same-body different-purity DefNodes
// are NOT equal and hash to different values.
pub struct DefNode {
pub mut:
	name                string
	params              []DefParam
	body                string
	returns_type_source ?string   // verbatim :returns T source — Phase 2.12
	returns_type_expr   ?TypeExpr // structural :returns T       — Phase 2.16
	scope               ?string
	purity              Purity = .pure_
	source              ?string // verbatim source-text snippet of the full [?def …] form (advisory)
	loc                 ?DefLoc // source position (advisory)
}

// ── Constructors ──────────────────────────────────────────────────────────────

// new_def_node constructs a minimal DefNode with the given name +
// params + body. `returns_type` / `scope` / `source` / `loc` are
// left none.
pub fn new_def_node(name string, params []DefParam, body string) DefNode {
	return DefNode{
		name:   name
		params: params
		body:   body
	}
}

// new_def_param_positional constructs a positional parameter `name`
// (optionally annotated). The `type_expr_source` argument is the
// verbatim `:T` annotation; the structural `type_expr` field is
// populated separately by the parser when `parse_type_expr` succeeds.
pub fn new_def_param_positional(name string, type_expr_source ?string) DefParam {
	return DefParam{
		name:             name
		type_expr_source: type_expr_source
	}
}

// new_def_param_named constructs a named (keyword) parameter
// `:name` with optional default value (verbatim source) and
// optional type annotation (verbatim).
pub fn new_def_param_named(name string, type_expr_source ?string, default ?string) DefParam {
	return DefParam{
		name:             name
		type_expr_source: type_expr_source
		is_named:         true
		default:          default
	}
}

// new_def_param_rest constructs a rest parameter `:rest name`
// (optionally annotated). At most one rest per parameter list; the
// parser enforces position-at-end.
pub fn new_def_param_rest(name string, type_expr_source ?string) DefParam {
	return DefParam{
		name:             name
		type_expr_source: type_expr_source
		is_rest:          true
	}
}

// ── Equality ──────────────────────────────────────────────────────────────────

// eq returns true iff two DefNode values are structurally equal
// under the identity rule (adopted by by
// symmetry). The `source` and `loc` fields are advisory and do NOT
// participate in equality. Two DefNodes parsed from differently-
// formatted source compare equal as long as name + params + body +
// returns_type + scope match.
//
// V auto-generates `==` for the underlying struct shape which would
// include `source` + `loc`; callers MUST use this method (or the
// canonical-bytes hash) for identity.
pub fn (d DefNode) eq(other DefNode) bool {
	if d.name != other.name {
		return false
	}
	if !def_params_eq(d.params, other.params) {
		return false
	}
	if d.body != other.body {
		return false
	}
	if !returns_type_eq(d.returns_type_expr, d.returns_type_source, other.returns_type_expr,
		other.returns_type_source)
	{
		return false
	}
	if !opt_string_eq(d.scope, other.scope) {
		return false
	}
	if d.purity != other.purity {
		return false
	}
	return true
}

// returns_type_eq compares the (TypeExpr, source) pair on two
// DefNodes per the Phase 2.16 fall-back rule: prefer structural
// equality when BOTH sides have a structural TypeExpr; otherwise
// compare the verbatim source strings. Mixed (one structural, one
// source-only) is reduced to source comparison via the structural
// side's `.source` field, so a verbatim-only legacy node still
// compares equal to a structurally-parsed peer with the same
// surface text.
fn returns_type_eq(ae ?TypeExpr, asrc ?string, be ?TypeExpr, bsrc ?string) bool {
	// Presence parity by source-string view (the source-string slot is
	// always populated when `:returns` was present at parse).
	a_present := asrc != none
	b_present := bsrc != none
	if a_present != b_present {
		return false
	}
	if !a_present {
		return true
	}
	// Both present. Prefer structural-vs-structural when both have it.
	if av := ae {
		if bv := be {
			return av.eq(bv)
		}
		// `a` structural, `b` source-only — fall back to source compare.
		bv := bsrc or { '' }
		return av.source == bv
	}
	if bv := be {
		av := asrc or { '' }
		return bv.source == av
	}
	// Both source-only — string compare.
	av := asrc or { '' }
	bv := bsrc or { '' }
	return av == bv
}

// eq compares two parameters for structural equality (name +
// type_expr + is_named + is_rest + default). The `loc` field is
// advisory and excluded.
pub fn (p DefParam) eq(other DefParam) bool {
	if p.name != other.name {
		return false
	}
	if !returns_type_eq(p.type_expr, p.type_expr_source, other.type_expr, other.type_expr_source) {
		return false
	}
	if p.is_named != other.is_named {
		return false
	}
	if p.is_rest != other.is_rest {
		return false
	}
	if !opt_string_eq(p.default, other.default) {
		return false
	}
	return true
}

fn def_params_eq(a []DefParam, b []DefParam) bool {
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

fn opt_string_eq(a ?string, b ?string) bool {
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

// def_node_canonical_bytes returns the canonical byte form of a
// DefNode used as input to the disjoint-domain hash function. The
// byte form is a deterministic textual encoding of the identity-
// participating fields (name + params + body + returns_type +
// scope only) — source + loc are excluded.
//
// Disjoint-domain prefix: the bytes start with the literal ASCII
// `DefNode\x00` followed by `\x01`-delimited slots and per-param
// `\x02`-prefixed segments. The `\x00` byte after the type tag
// cannot occur inside a CX canonical surface (UTF-8 content with
// no in-band NUL), so DefNode hashes inhabit a domain disjoint
// from element / scalar / atom / PathNode / MatchNode /
// ModifyNode / PredicateExpr hashes by construction.
//
// Mirrors the PathNode / MatchNode / ModifyNode disjoint-domain
// hashing convention.
pub fn def_node_canonical_bytes(d DefNode) []u8 {
	mut out := []u8{}
	out << 'DefNode'.bytes()
	out << u8(0x00)
	// Name slot.
	out << u8(0x10)
	out << d.name.bytes()
	out << u8(0x01)
	// Purity slot (after name, before params).
	out << u8(0x16)
	out << match d.purity {
		.pure_ { u8(0x70) }
		.impure_ { u8(0x71) }
	}
	out << u8(0x01)
	// Params — per-param delimiter `\x02`, intra-param fields delimited
	// by `\x03` (name), `\x04` (type_expr), `\x05` (is_named),
	// `\x06` (is_rest), `\x07` (default).
	for p in d.params {
		out << u8(0x02)
		out << p.name.bytes()
		out << u8(0x03)
		if t := p.type_expr_source {
			out << u8(0x30) // type-present marker
			out << t.bytes()
		} else {
			out << u8(0x31) // type-absent marker
		}
		out << u8(0x04)
		out << if p.is_named { u8(0x40) } else { u8(0x41) }
		out << u8(0x05)
		out << if p.is_rest { u8(0x50) } else { u8(0x51) }
		out << u8(0x06)
		if def_val := p.default {
			out << u8(0x60) // default-present marker
			out << def_val.bytes()
		} else {
			out << u8(0x61) // default-absent marker
		}
		out << u8(0x07)
	}
	out << u8(0x08) // end-of-params
	// Body slot.
	out << u8(0x11)
	out << d.body.bytes()
	out << u8(0x01)
	// Returns_type slot.
	if rt := d.returns_type_source {
		out << u8(0x12) // returns-present marker
		out << rt.bytes()
	} else {
		out << u8(0x13) // returns-absent marker
	}
	out << u8(0x01)
	// Scope slot.
	if sc := d.scope {
		out << u8(0x14) // scope-present marker
		out << sc.bytes()
	} else {
		out << u8(0x15) // scope-absent marker
	}
	return out
}

// def_node_hash returns the lowercase hex SHA-256 of the canonical
// disjoint-domain byte form. Equal DefNodes (per `.eq()`) produce
// equal hashes. The leading `DefNode\x00` prefix guarantees the
// hash cannot collide with element / scalar / atom / PathNode /
// MatchNode / ModifyNode / PredicateExpr hashes by construction.
pub fn def_node_hash(d DefNode) string {
	digest := sha256.sum256(def_node_canonical_bytes(d))
	return digest.hex()
}

// ── JSON projection ───────────────────────────────────────────────────────────

// def_node_to_json returns the AST-JSON projection of a DefNode.
// The shape:
//
//   {
//     "type":    "ProgramDefExpr",
//     "name":    "<NAME>",
//     "params":  [ { "name": ..., "type": ..., "named": bool, "rest": bool, "default": ... }, ... ],
//     "body":    "<src>",
//     "returns": "<src>",                       // omit when none
//     "scope":   "public" | "private",          // omit when none
//     "purity":  "pure" | "impure",             // always emitted
//     "source":  "<src>",                       // omit when none
//     "loc":     { "start": N, "end": M }       // omit when none
//   }
//
// Each param projects with:
//   - "name"    : always present (the parameter identifier)
//   - "type"    : present when the parameter has a `:T` annotation; omitted otherwise
//   - "named"   : present + true for `:name` keyword params; omitted for positional / rest
//   - "rest"    : present + true for `:rest name` variadic; omitted otherwise
//   - "default" : present when a named-param default is supplied; omitted otherwise
//
// "ProgramDefExpr" is the parser-internal JSON `type` tag; at the
// AST-bin boundary the projection will collapse to `"DefNode"` per
// the spec when the wire slot lands.
//
// Phase 2.12 Part 1 leaves body / type_expr / default / returns_type
// as verbatim source strings; the Phase 2.16 graft replaces these
// with structural subtrees, extending the wire shape rather than
// breaking it.
pub fn def_node_to_json(d DefNode) string {
	mut pairs := []string{}
	pairs << '"type":"ProgramDefExpr"'
	pairs << '"name":${json_str(d.name)}'
	mut params_json := []string{cap: d.params.len}
	for p in d.params {
		params_json << def_param_to_json(p)
	}
	pairs << '"params":[${params_json.join(',')}]'
	pairs << '"body":${json_str(d.body)}'
	if rt := d.returns_type_source {
		pairs << '"returns":${json_str(rt)}'
	}
	if rte := d.returns_type_expr {
		pairs << '"returns_type_expr":${type_expr_to_json(rte)}'
	}
	if sc := d.scope {
		pairs << '"scope":${json_str(sc)}'
	}
	purity_str := match d.purity {
		.pure_ { 'pure' }
		.impure_ { 'impure' }
	}
	pairs << '"purity":${json_str(purity_str)}'
	if src := d.source {
		pairs << '"source":${json_str(src)}'
	}
	if l := d.loc {
		pairs << '"loc":{"start":${l.start},"end":${l.end}}'
	}
	return '{${pairs.join(',')}}'
}

fn def_param_to_json(p DefParam) string {
	mut pairs := []string{}
	pairs << '"name":${json_str(p.name)}'
	if t := p.type_expr_source {
		pairs << '"type":${json_str(t)}'
	}
	if te := p.type_expr {
		pairs << '"type_expr":${type_expr_to_json(te)}'
	}
	if p.is_named {
		pairs << '"named":true'
	}
	if p.is_rest {
		pairs << '"rest":true'
	}
	if def_val := p.default {
		pairs << '"default":${json_str(def_val)}'
	}
	return '{${pairs.join(',')}}'
}

// ── Binary codec hook (DEFERRED) ──────────────────────────────────────────────

// TODO(Phase 2.12 follow-up): wire codec.
//
// DefNode wire-format slot is pending wire-slot allocation —
// analogous to the PathNode codec landed at Phase 1.7+ and the
// MatchNode / ModifyNode codec deferral at Phases 2.4 / 2.5. Until
// the slot lands:
//   - emit_ast_bin MUST reject DefNode values with the standard
//     unknown-kind error (currently moot: DefNode is not yet a
//     Node sum-type variant).
//   - parse_ast_bin MUST surface a clear error if it encounters a
//     wire byte in DefNode's pending slot range.
//
// When the slot lands this file gains:
//   - fn def_node_to_bin(d DefNode) []u8
//   - fn bin_to_def_node(bytes []u8, mut pos int) !DefNode
// plus integration into binary.v's emit/parse dispatch and `Node`
// sum-type integration in the matching phase.
