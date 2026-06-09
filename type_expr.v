module cx

import crypto.sha256

// type_expr.v — structural AST for type expressions (Phase 2.16).
//
// Per spec/code.md §12.7, type expressions are CX data
// values. Every compound type is a bracketed form; every atomic type
// is either a lowercase **kind name** (`string` / `int` / `float` /
// `bool` / `null` / `atom` / `element` / `array` / `map` / `sequence`
// / `function` / `path` / `bytes` / `date` / `datetime`) or a
// capitalized **element-name** (`Person`, `Token`, …).
//
// Grammar:
//
//   Type        ::= KindName | ElementName | BracketType
//   BracketType ::= '[' TypeHead Type+ ']'
//   TypeHead    ::= 'or' | 'sequence'
//
// This file is the Phase 2.16 structural graft over the verbatim-source
// type-expression slots captured by `def_parser.v` at Phase 2.12 Part 1
// (Z1, commit `57ea4565`). The graft is **additive** — DefParam /
// DefNode keep their `*_source ?string` verbatim slots, and the new
// `*_expr ?TypeExpr` structural slots populate when `parse_type_expr`
// succeeds; on failure the verbatim source path remains the source of
// truth. This preserves wire round-trip while enabling the dev-strict
// validator (Phase 2.16, see `vcx/code/type_strict_validator.v`).
//
// Cross-references:
//   - spec/code.md §12.7 (normative type-expression spec)
//   - vcx/cx/def_node.v (Phase 2.12 Part 1 DefNode + DefParam)
//   - vcx/cx/def_parser.v (Phase 2.12 Part 1 surface-text parser)

// ── Structs ───────────────────────────────────────────────────────────────────

// TypeKind discriminates the surface forms of a TypeExpr. The five
// active variants are:
//
//   - `kind_name`     — bare lowercase reserved kind (`string`, `int`, …)
//   - `element_name`  — capitalized element name (`Person`, `Token`, …)
//   - `union_`        — bracketed `[or T1 T2 …]` (≥ 2 members)
//   - `sequence_`     — bracketed `[sequence T]` (exactly 1 member)
//   - `any_`          — wildcard sentinel (reserved; not parsed at v0.8.0)
//   - `unknown_`      — fallback sentinel reserved for evaluator-side
//                       inference; never produced by `parse_type_expr`
//
// Trailing-underscore on `union_` / `sequence_` / `any_` / `unknown_`
// avoids potential V keyword collisions (same convention as
// `Purity.pure_` / `Purity.impure_` in def_node.v).
pub enum TypeKind {
	kind_name
	element_name
	union_
	sequence_
	any_
	unknown_
}

// TypeLoc carries an optional source-position record for a TypeExpr.
// Advisory; not part of equality or hashing. `start` / `end` are byte
// offsets into the original source string.
pub struct TypeLoc {
pub mut:
	start int
	end   int
}

// TypeExpr is the structural AST for a single type expression.
//
//   - `kind`     — discriminator (see TypeKind).
//   - `name`     — populated for `kind_name` + `element_name` only.
//   - `members`  — populated for `union_` (≥ 2) + `sequence_` (exactly 1).
//   - `source`   — verbatim source-text snippet (advisory; not in equality).
//   - `loc`      — source-position record (advisory; not in equality).
//
// The closed-domain field rule (per kind):
//
//   | kind         | name      | members    |
//   |--------------|-----------|------------|
//   | kind_name    | required  | empty      |
//   | element_name | required  | empty      |
//   | union_       | none      | ≥ 2 items  |
//   | sequence_    | none      | 1 item     |
//   | any_         | none      | empty      |
//   | unknown_     | none      | empty      |
pub struct TypeExpr {
pub mut:
	kind    TypeKind
	name    ?string
	members []TypeExpr
	source  string
	loc     ?TypeLoc
}

// ── Reserved kind names ───────────────────────────────────────────────────────

// kind_names lists the lowercase reserved kind names admitted at
// `kind_name` position per spec/code.md §12.7.1, plus
// the v0.8.0 extension set noted in the Phase 2.16 brief
// (`date`, `datetime`, `bytes`, `array`).
//
// The set is closed: any other bareword lowercase identifier at a
// type-expression slot reports as malformed.
const kind_names = [
	'string',
	'int',
	'float',
	'bool',
	'null',
	'atom',
	'element',
	'sequence',
	'map',
	'function',
	'path',
	'bytes',
	'date',
	'datetime',
	'array',
]

// is_reserved_kind_name returns true iff `s` is one of the reserved
// lowercase kind names per spec/code.md §12.7.1.
pub fn is_reserved_kind_name(s string) bool {
	return s in kind_names
}

// ── Equality ──────────────────────────────────────────────────────────────────

// eq returns true iff two TypeExpr values are structurally equal under
// the identity rule (source + loc excluded; kind + name
// members participate).
pub fn (t TypeExpr) eq(other TypeExpr) bool {
	if t.kind != other.kind {
		return false
	}
	if !opt_string_eq(t.name, other.name) {
		return false
	}
	if t.members.len != other.members.len {
		return false
	}
	for i, m in t.members {
		if !m.eq(other.members[i]) {
			return false
		}
	}
	return true
}

// ── Canonical bytes + hashing ─────────────────────────────────────────────────

// type_expr_canonical_bytes returns the canonical byte form of a
// TypeExpr used as input to the disjoint-domain hash function. The
// bytes begin with the literal ASCII `TypeExpr\x00` followed by a
// recursive textual encoding of kind + name + members. The `\x00`
// byte after the type tag cannot occur inside a CX type-expression
// surface (UTF-8 content, no in-band NUL), so TypeExpr hashes inhabit
// a domain disjoint from element / scalar / atom / PathNode /
// MatchNode / ModifyNode / PredicateExpr / DefNode / ConstNode /
// LibNode hashes by construction.
pub fn type_expr_canonical_bytes(t TypeExpr) []u8 {
	mut out := []u8{}
	out << 'TypeExpr'.bytes()
	out << u8(0x00)
	type_expr_canonical_bytes_into(t, mut out)
	return out
}

fn type_expr_canonical_bytes_into(t TypeExpr, mut out []u8) {
	// Kind discriminator.
	out << u8(0x10)
	out << match t.kind {
		.kind_name { u8(0x20) }
		.element_name { u8(0x21) }
		.union_ { u8(0x22) }
		.sequence_ { u8(0x23) }
		.any_ { u8(0x24) }
		.unknown_ { u8(0x25) }
	}
	out << u8(0x01)
	// Name slot.
	if n := t.name {
		out << u8(0x11) // name-present marker
		out << n.bytes()
	} else {
		out << u8(0x12) // name-absent marker
	}
	out << u8(0x01)
	// Members slot (recursive).
	out << u8(0x13)
	for m in t.members {
		out << u8(0x02) // per-member delimiter
		type_expr_canonical_bytes_into(m, mut out)
		out << u8(0x03) // per-member terminator
	}
	out << u8(0x04) // end-of-members
}

// type_expr_hash returns the lowercase hex SHA-256 of the canonical
// disjoint-domain byte form. Equal TypeExprs (per `.eq()`) produce
// equal hashes. The leading `TypeExpr\x00` prefix guarantees the
// hash cannot collide with element / scalar / atom / PathNode /
// MatchNode / ModifyNode / PredicateExpr / DefNode / ConstNode /
// LibNode / text-hash by construction.
pub fn type_expr_hash(t TypeExpr) string {
	digest := sha256.sum256(type_expr_canonical_bytes(t))
	return digest.hex()
}

// ── JSON projection ───────────────────────────────────────────────────────────

// type_expr_to_json returns the AST-JSON projection of a TypeExpr.
// The shape:
//
//   { "kind": "kind_name", "name": "string" }
//   { "kind": "element_name", "name": "Person" }
//   { "kind": "union", "members": [ ... ] }
//   { "kind": "sequence", "members": [ ... ] }
//
// `name` is omitted when not applicable; `members` is omitted when
// empty. `source` + `loc` are not projected (advisory).
pub fn type_expr_to_json(t TypeExpr) string {
	mut pairs := []string{}
	kind_str := match t.kind {
		.kind_name { 'kind_name' }
		.element_name { 'element_name' }
		.union_ { 'union' }
		.sequence_ { 'sequence' }
		.any_ { 'any' }
		.unknown_ { 'unknown' }
	}
	pairs << '"kind":${json_str(kind_str)}'
	if n := t.name {
		pairs << '"name":${json_str(n)}'
	}
	if t.members.len > 0 {
		mut member_jsons := []string{cap: t.members.len}
		for m in t.members {
			member_jsons << type_expr_to_json(m)
		}
		pairs << '"members":[${member_jsons.join(',')}]'
	}
	return '{${pairs.join(',')}}'
}

// ── Parser ────────────────────────────────────────────────────────────────────

// TypeParseCursor is a private cursor over the source string. Same
// shape as DefParseCursor / MatchParseCursor.
struct TypeParseCursor {
mut:
	src []u8
	pos int
}

@[inline]
fn (c &TypeParseCursor) at_end() bool {
	return c.pos >= c.src.len
}

@[inline]
fn (c &TypeParseCursor) peek() u8 {
	if c.pos < c.src.len {
		return c.src[c.pos]
	}
	return 0
}

@[inline]
fn (mut c TypeParseCursor) advance() {
	if c.pos < c.src.len {
		c.pos++
	}
}

@[inline]
fn type_is_space(b u8) bool {
	return b == ` ` || b == `\t` || b == `\n` || b == `\r`
}

@[inline]
fn type_is_lower(b u8) bool {
	return b >= `a` && b <= `z`
}

@[inline]
fn type_is_upper(b u8) bool {
	return b >= `A` && b <= `Z`
}

@[inline]
fn type_is_name_start(b u8) bool {
	return type_is_lower(b) || type_is_upper(b) || b == `_`
}

@[inline]
fn type_is_name_cont(b u8) bool {
	return type_is_name_start(b) || (b >= `0` && b <= `9`) || b == `-` || b == `?` || b == `!`
}

fn (mut c TypeParseCursor) skip_ws() {
	for !c.at_end() && type_is_space(c.peek()) {
		c.advance()
	}
}

fn (mut c TypeParseCursor) read_bareword() string {
	start := c.pos
	if c.at_end() || !type_is_name_start(c.peek()) {
		return ''
	}
	c.advance()
	for !c.at_end() && type_is_name_cont(c.peek()) {
		c.advance()
	}
	return c.src[start..c.pos].bytestr()
}

// parse_type_expr parses a single type expression per spec/code.md
// §12.7. The input MUST be the full type-expression
// surface — bare identifier or balanced bracketed form, possibly
// padded with whitespace.
//
// On success the returned TypeExpr has:
//   - kind populated per the surface form (kind_name / element_name /
//     union_ / sequence_).
//   - name set for kind_name + element_name; none for union_ +
//     sequence_.
//   - members populated recursively for union_ + sequence_; empty for
//     bare kinds.
//   - source set to the trimmed input.
//   - loc set to span 0..source.len.
//
// Errors (each contains a `CXTYPE_PARSE:` prefix):
//   - empty input
//   - empty bracketed form `[]`
//   - unknown bracket head (anything other than `or` / `sequence`)
//   - `[or X]` with fewer than 2 members
//   - `[sequence]` with zero members or > 1 member
//   - unknown bare lowercase kind name
//   - malformed identifier (digit-leading, etc.)
//   - unbalanced brackets
//   - trailing garbage after the type expression
pub fn parse_type_expr(source string) !TypeExpr {
	if source.len == 0 {
		return error('CXTYPE_PARSE: empty input')
	}
	mut c := TypeParseCursor{
		src: source.bytes()
		pos: 0
	}
	c.skip_ws()
	if c.at_end() {
		return error('CXTYPE_PARSE: empty input')
	}
	t := parse_type_expr_inner(mut c)!
	c.skip_ws()
	if !c.at_end() {
		return error('CXTYPE_PARSE: unexpected trailing input after type expression: `${source[c.pos..]}`')
	}
	mut out := t
	out.source = source.trim_space()
	out.loc = TypeLoc{
		start: 0
		end:   source.len
	}
	return out
}

// parse_type_expr_inner reads one Type at the current cursor position
// (no leading whitespace) and advances the cursor past it. Used both
// at the top level and recursively for bracket members.
fn parse_type_expr_inner(mut c TypeParseCursor) !TypeExpr {
	if c.at_end() {
		return error('CXTYPE_PARSE: empty input')
	}
	start := c.pos
	if c.peek() == `[` {
		return parse_bracket_type(mut c, start)!
	}
	// Bare identifier — kind_name or element_name.
	if !type_is_name_start(c.peek()) {
		return error('CXTYPE_PARSE: expected type expression at position ${c.pos}, got `${c.peek().ascii_str()}`')
	}
	name := c.read_bareword()
	if name.len == 0 {
		return error('CXTYPE_PARSE: malformed identifier at position ${start}')
	}
	first := name[0]
	if type_is_upper(first) {
		// Element-name type.
		return TypeExpr{
			kind:   TypeKind.element_name
			name:   name
			source: name
		}
	}
	if type_is_lower(first) {
		if !is_reserved_kind_name(name) {
			return error('CXTYPE_PARSE: unknown kind name `${name}` — expected one of ${kind_names.join(", ")} or a capitalized element-name')
		}
		return TypeExpr{
			kind:   TypeKind.kind_name
			name:   name
			source: name
		}
	}
	// Underscore-leading — reject as malformed at v0.8.0.
	return error('CXTYPE_PARSE: malformed identifier `${name}` — kind names start lowercase, element names start uppercase')
}

// parse_bracket_type reads a bracketed `[HEAD T1 T2 …]` type form.
// The cursor MUST be sitting on the opening `[`; it is advanced past
// the closing `]` on success.
fn parse_bracket_type(mut c TypeParseCursor, start int) !TypeExpr {
	if c.peek() != `[` {
		return error('CXTYPE_PARSE: expected `[` at position ${c.pos}')
	}
	c.advance() // consume `[`
	c.skip_ws()
	if c.at_end() {
		return error('CXTYPE_PARSE: unterminated bracket type expression')
	}
	if c.peek() == `]` {
		return error('CXTYPE_PARSE: empty bracket — expected `[or …]` or `[sequence T]`')
	}
	head := c.read_bareword()
	if head.len == 0 {
		return error('CXTYPE_PARSE: missing bracket head at position ${c.pos}')
	}
	// Members.
	mut members := []TypeExpr{}
	for {
		c.skip_ws()
		if c.at_end() {
			return error('CXTYPE_PARSE: unterminated bracket type expression')
		}
		if c.peek() == `]` {
			c.advance() // consume `]`
			break
		}
		m := parse_type_expr_inner(mut c)!
		members << m
	}
	// Source span of this bracket.
	src := c.src[start..c.pos].bytestr()
	match head {
		'or' {
			if members.len < 2 {
				return error('CXTYPE_PARSE: `[or …]` requires at least 2 members; got ${members.len}')
			}
			return TypeExpr{
				kind:    TypeKind.union_
				members: members
				source:  src
			}
		}
		'sequence' {
			if members.len != 1 {
				return error('CXTYPE_PARSE: `[sequence T]` requires exactly 1 member; got ${members.len}')
			}
			return TypeExpr{
				kind:    TypeKind.sequence_
				members: members
				source:  src
			}
		}
		else {
			return error('CXTYPE_PARSE: unknown bracket head `${head}` — expected `or` or `sequence`')
		}
	}
	return error('CXTYPE_PARSE: unreachable')
}
