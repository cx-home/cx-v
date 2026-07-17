module cx

import crypto.sha256

// predicate_expr.v — PredicateExpr AST (Phase 2.19).
//
// PredicateExpr is the structural body of a CXPath predicate `[…]` per
// grammar production [159]: `PredicateExpr ::= '[' ProgramExpr ']'`.
// At Phase 2.19 we land the AST datum + a parser for atomic
// template forms (the common cases — attribute test, attribute compare,
// integer position, bare boolean function call). Bodies that exceed those
// templates surface as a parse error so the caller (path_parser.v) can
// fall back to source-only PathPredicate per Phase 2.1's contract.
//
// atomic templates covered at Phase 2.19:
//
//   | Source form                | PredicateExprKind        | Notes |
//   |----------------------------|--------------------------|-------|
//   | `@name`                    | .attr_test               | bare attribute existence |
//   | `@name OP value`           | .attr_compare            | OP ∈ { = != < <= > >= } |
//   | INT (1-based)              | .int_position            | desugars to `$_position = N` |
//   | `count(*) OP N`            | .function_call           | atomic count-vs-int form |
//   | `count(*)`                 | .function_call           | bare count call |
//   | `$_@name`                  | .attr_test               | explicit $_ form recognised |
//   | `$_@name OP value`         | .attr_compare            | explicit $_ form recognised |
//   | `$_position`/`$_last`      | .reserved_binding (atom) | recognised but not eval-handled |
//
// Out of scope at Phase 2.19 (parser returns error → path_parser falls
// back to source-only PathPredicate; no spec divergence):
//
//   - General boolean expressions (`and`/`or` combinations)
//   - Nested predicates inside the body
//   - Arbitrary function calls beyond `count(*)`
//   - `instance of` / `cast as` / sequence-op surface
//   - `:bind` peer-modifier (Phase 2.20)
//   - `:pure` / `:impure` modifier slot (Phase 2.23)
//   - Static purity checker (Phase 2.22)
//   - Evaluator (Phase 2.21 — eager iteration)
//
// Out of scope at this file (deferred to follow-up):
//
//   - ast_bin codec extension — Phase 2.1 codec encodes ONLY the predicate
//     source string; the expr is recomputed from source on decode by the
//     parser. The optional expr field is parse-only currently; revisit
//     when the predicate-body wire layout is allocated in spec/core/ast-bin.md.
//   - path_renderer.v atomic-template recognition — the renderer continues
//     to emit verbatim source; the AST shape provided here makes the
//     atomic-template recognition table POSSIBLE but the graft is a
//     separate follow-up (so the renderer stays untouched at Phase 2.19).
//
// Cross-references:
//   - spec/grammar.ebnf production [159] PredicateExpr
//   - vcx/cx/path_node.v (PathPredicate carries the expr ?&PredicateExpr field)
//   - vcx/cx/path_parser.v (predicate-body parse → predicate_expr_parse)

// ── Enum ──────────────────────────────────────────────────────────────────────

// PredicateExprKind discriminates the recognised body shapes
// D6. At Phase 2.19 only the atomic-template kinds are exercised by the
// parser; the larger `bool_expr` / `instance_of` / `cast_as` / `sequence_op`
// / `generic` slots are reserved for the follow-up phases so the AST
// shape stays stable across rollout.
pub enum PredicateExprKind {
	atom_test         // `@name` — attribute-existence
	attr_test         // alias for atom_test in the AttrTest sense
	attr_compare      // `@name OP value`
	int_position      // `[N]` → `$_position = N`
	bool_expr         // `expr AND expr` / `expr OR expr` (Phase 2.19: reserved, not parsed)
	function_call     // `count(*)` / `count(*) > N` / etc.
	sequence_op       // (Phase 2.19: reserved)
	instance_of       // (Phase 2.19: reserved)
	cast_as           // (Phase 2.19: reserved)
	reserved_binding  // `$_` / `$_position` / `$_last`
	generic           // catch-all for non-atomic bodies (Phase 2.19: not produced)
}

// predicate_expr_kind_name returns the canonical string spelling of a
// PredicateExprKind, used by JSON projection + canonical-bytes hashing.
pub fn predicate_expr_kind_name(k PredicateExprKind) string {
	return match k {
		.atom_test        { 'atom_test' }
		.attr_test        { 'attr_test' }
		.attr_compare     { 'attr_compare' }
		.int_position     { 'int_position' }
		.bool_expr        { 'bool_expr' }
		.function_call    { 'function_call' }
		.sequence_op      { 'sequence_op' }
		.instance_of      { 'instance_of' }
		.cast_as          { 'cast_as' }
		.reserved_binding { 'reserved_binding' }
		.generic          { 'generic' }
	}
}

// ── Loc ───────────────────────────────────────────────────────────────────────

// PredicateLoc carries an advisory source-position record for the
// predicate body. Excluded from equality and hashing per the same
// rule that excludes PathLoc on PathNode (alignment).
pub struct PredicateLoc {
pub mut:
	line int
	col  int
}

// ── Struct ────────────────────────────────────────────────────────────────────

// PredicateExpr is the structural AST node for a predicate body per
// At Phase 2.19 it captures the atomic
// templates as a flat, kind-discriminated record; the `children` slot
// is present so the structure can grow into the full ProgramExpr
// surface in later phases without a shape change.
//
// Fields:
//   - kind:     discriminator (PredicateExprKind)
//   - name:     attribute name for attr_test/attr_compare; function
//               name for function_call; binding name for reserved_binding
//   - value:    RHS literal for attr_compare (verbatim source); function-
//               arg string for function_call (e.g. `"*"` for count(*))
//   - op:       comparison / boolean operator (`=`, `!=`, `<`, `<=`,
//               `>`, `>=` for attr_compare / function_call; `and`/`or`
//               for bool_expr at follow-up phases)
//   - position: 1-based int for int_position kind
//   - children: nested PredicateExpr sub-trees (e.g. bool_expr operands).
//               Empty at the atomic templates produced by Phase 2.19.
//   - source:   verbatim source text the parser saw (advisory — excluded
//               from .eq() and the disjoint-domain hash)
//   - loc:      advisory source position (excluded from .eq() / hash)
pub struct PredicateExpr {
pub mut:
	kind     PredicateExprKind
	name     ?string
	value    ?string
	op       ?string
	position ?int
	children []&PredicateExpr
	source   string
	loc      ?PredicateLoc
}

// ── Constructors ──────────────────────────────────────────────────────────────

// new_predicate_expr constructs a PredicateExpr with the given kind and
// empty optional fields. Callers populate name / value / op / position
// / children as the shape demands.
pub fn new_predicate_expr(kind PredicateExprKind, source string) &PredicateExpr {
	return &PredicateExpr{
		kind:   kind
		source: source
	}
}

// ── Equality ──────────────────────────────────────────────────────────────────

// eq returns true iff two PredicateExpr values are structurally equal
// The `source` and `loc` fields are advisory and do
// NOT participate in equality — two predicates parsed from differently-
// formatted source (e.g. `@active = true` vs `@active=true`) compare
// equal at the AST level.
pub fn (p &PredicateExpr) eq(other &PredicateExpr) bool {
	if p.kind != other.kind {
		return false
	}
	if !opt_str_eq(p.name, other.name) {
		return false
	}
	if !opt_str_eq(p.value, other.value) {
		return false
	}
	if !opt_str_eq(p.op, other.op) {
		return false
	}
	if !opt_int_eq(p.position, other.position) {
		return false
	}
	if p.children.len != other.children.len {
		return false
	}
	for i, ch in p.children {
		if !ch.eq(other.children[i]) {
			return false
		}
	}
	return true
}

@[inline]
fn opt_str_eq(a ?string, b ?string) bool {
	a_none := a == none
	b_none := b == none
	if a_none != b_none {
		return false
	}
	if a_none {
		return true
	}
	return (a or { '' }) == (b or { '' })
}

@[inline]
fn opt_int_eq(a ?int, b ?int) bool {
	a_none := a == none
	b_none := b == none
	if a_none != b_none {
		return false
	}
	if a_none {
		return true
	}
	return (a or { 0 }) == (b or { 0 })
}

// ── Canonical bytes + hashing ─────────────────────────────────────────────────

// predicate_expr_canonical_bytes returns the canonical disjoint-domain
// byte form for hashing. Layout:
//
//   "PredicateExpr" \x00 KIND \x01 NAME \x02 VALUE \x03 OP \x04 POSITION \x05
//   ( CHILD_BYTES \x06 )* \x07
//
// The leading `PredicateExpr\x00` literal places this hash in a domain
// disjoint from PathNode (`PathNode\x00`), Element, Scalar, Atom, and
// Match canonical-bytes hashes. A NUL byte after the type tag cannot
// occur inside a CX scalar or element canonical-bytes form, so the
// domains cannot collide by construction.
pub fn predicate_expr_canonical_bytes(p &PredicateExpr) []u8 {
	mut out := []u8{}
	out << 'PredicateExpr'.bytes()
	out << u8(0x00)
	out << predicate_expr_kind_name(p.kind).bytes()
	out << u8(0x01)
	if n := p.name {
		out << n.bytes()
	}
	out << u8(0x02)
	if v := p.value {
		out << v.bytes()
	}
	out << u8(0x03)
	if o := p.op {
		out << o.bytes()
	}
	out << u8(0x04)
	if pos := p.position {
		out << pos.str().bytes()
	}
	out << u8(0x05)
	for ch in p.children {
		out << predicate_expr_canonical_bytes(ch)
		out << u8(0x06)
	}
	out << u8(0x07)
	return out
}

// predicate_expr_hash returns the lowercase hex SHA-256 of the canonical
// disjoint-domain byte form. Equal PredicateExprs (per .eq()) produce
// equal hashes; the domain prefix guarantees no collision with PathNode,
// Element, Scalar, Atom, or MatchNode hashes.
pub fn predicate_expr_hash(p &PredicateExpr) string {
	digest := sha256.sum256(predicate_expr_canonical_bytes(p))
	return digest.hex()
}

// ── JSON projection ───────────────────────────────────────────────────────────

// predicate_expr_to_json returns the AST-JSON projection of a
// PredicateExpr. Shape:
//
//   {
//     "type":     "PredicateExpr",
//     "kind":     "<kind name>",
//     "name":     "<name>",       // present iff some
//     "value":    "<value>",      // present iff some
//     "op":       "<op>",         // present iff some
//     "position": N,              // present iff some
//     "children": [ … ],          // present iff non-empty
//     "source":   "<verbatim>",   // always present
//     "loc":      { "line": N, "col": M } // present iff some
//   }
pub fn predicate_expr_to_json(p &PredicateExpr) string {
	mut pairs := []string{}
	pairs << '"type":"PredicateExpr"'
	pairs << '"kind":"${predicate_expr_kind_name(p.kind)}"'
	if n := p.name {
		pairs << '"name":${json_str(n)}'
	}
	if v := p.value {
		pairs << '"value":${json_str(v)}'
	}
	if o := p.op {
		pairs << '"op":${json_str(o)}'
	}
	if pos := p.position {
		pairs << '"position":${pos}'
	}
	if p.children.len > 0 {
		mut ch_json := []string{cap: p.children.len}
		for ch in p.children {
			ch_json << predicate_expr_to_json(ch)
		}
		pairs << '"children":[${ch_json.join(',')}]'
	}
	pairs << '"source":${json_str(p.source)}'
	if l := p.loc {
		pairs << '"loc":{"line":${l.line},"col":${l.col}}'
	}
	return '{${pairs.join(',')}}'
}

// ── Parser ────────────────────────────────────────────────────────────────────

// PredicateParseCursor — small byte cursor over a predicate body source.
struct PredicateParseCursor {
mut:
	src []u8
	pos int
}

@[inline]
fn (c &PredicateParseCursor) at_end() bool {
	return c.pos >= c.src.len
}

@[inline]
fn (c &PredicateParseCursor) peek() u8 {
	if c.pos < c.src.len {
		return c.src[c.pos]
	}
	return 0
}

@[inline]
fn (c &PredicateParseCursor) peek_at(off int) u8 {
	if c.pos + off < c.src.len {
		return c.src[c.pos + off]
	}
	return 0
}

@[inline]
fn (mut c PredicateParseCursor) advance() {
	if c.pos < c.src.len {
		c.pos++
	}
}

@[inline]
fn (mut c PredicateParseCursor) skip_ws() {
	for !c.at_end() {
		b := c.peek()
		if b == ` ` || b == `\t` || b == `\n` || b == `\r` {
			c.advance()
			continue
		}
		break
	}
}

fn (mut c PredicateParseCursor) read_name() string {
	start := c.pos
	if c.at_end() || !path_is_name_start(c.peek()) {
		return ''
	}
	c.advance()
	for !c.at_end() && path_is_name_cont(c.peek()) {
		c.advance()
	}
	return c.src[start..c.pos].bytestr()
}

// read_int reads a non-negative integer literal starting at the cursor.
// Returns the parsed int and number of digits consumed.
fn (mut c PredicateParseCursor) read_int() ?int {
	start := c.pos
	if c.at_end() {
		return none
	}
	for !c.at_end() && c.peek() >= `0` && c.peek() <= `9` {
		c.advance()
	}
	if c.pos == start {
		return none
	}
	return c.src[start..c.pos].bytestr().int()
}

// read_op reads a comparison operator from the cursor. Returns the
// operator string and advances the cursor on match; returns none and
// leaves cursor untouched otherwise. Supports the 6 
// comparison operators.
fn (mut c PredicateParseCursor) read_op() ?string {
	if c.at_end() {
		return none
	}
	saved := c.pos
	b := c.peek()
	match b {
		`=` {
			c.advance()
			return '='
		}
		`!` {
			if c.peek_at(1) == `=` {
				c.advance()
				c.advance()
				return '!='
			}
			c.pos = saved
			return none
		}
		`<` {
			c.advance()
			if !c.at_end() && c.peek() == `=` {
				c.advance()
				return '<='
			}
			return '<'
		}
		`>` {
			c.advance()
			if !c.at_end() && c.peek() == `=` {
				c.advance()
				return '>='
			}
			return '>'
		}
		else {
			return none
		}
	}
}

// read_rhs_value reads the RHS of a comparison: a quoted string literal
// (`"…"` / `'…'`), an integer, a float, a boolean keyword, or a bare
// identifier. Returns the verbatim source slice including any quote
// characters so the renderer can echo it byte-identically.
fn (mut c PredicateParseCursor) read_rhs_value() ?string {
	c.skip_ws()
	if c.at_end() {
		return none
	}
	start := c.pos
	b := c.peek()
	if b == `"` || b == `'` {
		quote := b
		c.advance()
		for !c.at_end() && c.peek() != quote {
			if c.peek() == `\\` {
				c.advance()
				if !c.at_end() {
					c.advance()
				}
				continue
			}
			c.advance()
		}
		if c.at_end() {
			return none
		}
		c.advance() // closing quote
		return c.src[start..c.pos].bytestr()
	}
	if (b >= `0` && b <= `9`) || b == `-` || b == `+` {
		if b == `-` || b == `+` {
			c.advance()
		}
		mut saw_digit := false
		for !c.at_end() && c.peek() >= `0` && c.peek() <= `9` {
			c.advance()
			saw_digit = true
		}
		if !c.at_end() && c.peek() == `.` {
			c.advance()
			for !c.at_end() && c.peek() >= `0` && c.peek() <= `9` {
				c.advance()
				saw_digit = true
			}
		}
		if !saw_digit {
			return none
		}
		return c.src[start..c.pos].bytestr()
	}
	if path_is_name_start(b) {
		name := c.read_name()
		if name.len == 0 {
			return none
		}
		return name
	}
	return none
}

// predicate_expr_parse parses a predicate-body source string into a
// PredicateExpr per the atomic template table.
//
// Recognised forms (with arbitrary surrounding whitespace):
//
//   - `@name`                  → kind=attr_test,    name=<name>
//   - `@name OP value`         → kind=attr_compare, name=<name>, op=<op>, value=<verbatim>
//   - `$_@name` / `$_@name OP value`   → same as above (explicit-$_ form)
//   - `$_position` / `$_last`  → kind=reserved_binding, name=<binding>
//   - INT                      → kind=int_position, position=<N>
//   - `count(*)` [OP N]        → kind=function_call, name=count, value="*", op?=<op>, position?=<N>
//
// On any other body shape returns an error — the caller (path_parser.v)
// falls back to source-only PathPredicate. This is by design: we want
// the atomic-template AST graft to be conservative; the full
// ProgramExpr surface lands at follow-up phases.
pub fn predicate_expr_parse(source string) !&PredicateExpr {
	if source.len == 0 {
		return error('PREDICATE_EXPR_PARSE: empty body')
	}
	mut c := PredicateParseCursor{ src: source.bytes(), pos: 0 }
	c.skip_ws()

	// Infix boolean connectives are RETIRED (grammar [132]–[134]): a body
	// like `@a=1 and @b=2` is a hard parse error, never a source-only
	// fallback. Prefix forms (`and […] […]`) don't trip the scan — the
	// leading token is the connective itself, checked before this scan.
	if !predicate_body_leads_with_word_operator(source)
	   && predicate_body_has_bool_keyword(source) {
		return error('RETIRED_PREDICATE_SURFACE: infix `and`/`or` in a CXPath predicate is retired — write the prefix form `[and P Q]` (code.md §5.5.2)')
	}

	// Canonical prefix templates ([159b] fused-form interiors) — the
	// atomic subset the standalone evaluator supports:
	//   `OP $_@name RHS`   → attr_compare   (OP ∈ = != < <= > >=)
	//   `= $_position N`   → int_position
	//   `and|or BODY BODY` → bool_expr      (children are `[…]` sub-bodies)
	//   `not BODY`         → bool_expr
	if !c.at_end() && (c.peek() == `=` || c.peek() == `!` || c.peek() == `<` || c.peek() == `>`) {
		return parse_prefix_compare(mut c, source)!
	}
	if body_leads_word(source, 'and') || body_leads_word(source, 'or')
	   || body_leads_word(source, 'not') {
		return parse_prefix_connective(mut c, source)!
	}

	// `$_` family: `$_`, `$_position`, `$_last`, or `$_@name`.
	if !c.at_end() && c.peek() == `$` && c.peek_at(1) == `_` {
		return parse_dollar_underscore(mut c, source)!
	}

	// `@name` attribute test or compare.
	if !c.at_end() && c.peek() == `@` {
		return parse_attr(mut c, source)!
	}

	// Bare integer literal → int_position.
	if !c.at_end() && c.peek() >= `0` && c.peek() <= `9` {
		return parse_int_position(mut c, source)!
	}

	// Bare function call (currently only `count(*)`).
	if !c.at_end() && path_is_name_start(c.peek()) {
		return parse_function_call(mut c, source)!
	}

	return error('PREDICATE_EXPR_PARSE: unrecognised body shape: ${source}')
}

// body_leads_word reports whether the trimmed body starts with `word`
// followed by whitespace or `[` (a fused connective interior).
fn body_leads_word(source string, word string) bool {
	t := source.trim_space()
	if !t.starts_with(word) || t.len <= word.len {
		return false
	}
	nxt := t[word.len]
	return nxt == ` ` || nxt == `\t` || nxt == `\n` || nxt == `[`
}

// parse_prefix_compare parses `OP LHS RHS` where OP is a comparison
// operator, LHS is `$_@name` / `$_position`, and RHS is a literal.
// Cursor is on the operator.
fn parse_prefix_compare(mut c PredicateParseCursor, source string) !&PredicateExpr {
	op := c.read_op() or {
		return error('PREDICATE_EXPR_PARSE: expected comparison operator')
	}
	c.skip_ws()
	// LHS must be a `$_`-anchored reference for the standalone surface.
	if c.at_end() || c.peek() != `$` || c.peek_at(1) != `_` {
		return error('PREDICATE_EXPR_PARSE: prefix compare needs a `\$_`-anchored LHS (general bodies promote via the program engine)')
	}
	c.advance() // $
	c.advance() // _
	if !c.at_end() && c.peek() == `@` {
		c.advance() // @
		name := c.read_name()
		if name.len == 0 {
			return error('PREDICATE_EXPR_PARSE: expected attribute name after \$_@')
		}
		c.skip_ws()
		value := c.read_rhs_value() or {
			return error('PREDICATE_EXPR_PARSE: expected RHS value in prefix compare')
		}
		c.skip_ws()
		if !c.at_end() {
			return error('PREDICATE_EXPR_PARSE: unexpected trailing input in prefix compare: ${source}')
		}
		return &PredicateExpr{
			kind:   .attr_compare
			name:   name
			op:     op
			value:  value
			source: source
		}
	}
	suffix := c.read_name()
	if suffix == 'position' && op == '=' {
		c.skip_ws()
		n := c.read_int() or {
			return error('PREDICATE_EXPR_PARSE: expected integer after `= \$_position`')
		}
		c.skip_ws()
		if !c.at_end() {
			return error('PREDICATE_EXPR_PARSE: unexpected trailing input after positional compare: ${source}')
		}
		if n < 1 {
			return error('PREDICATE_EXPR_PARSE: position must be ≥ 1 (got ${n})')
		}
		return &PredicateExpr{
			kind:     .int_position
			position: n
			source:   source
		}
	}
	return error('PREDICATE_EXPR_PARSE: prefix compare over `\$_${suffix}` outside the atomic surface (promotes via the program engine)')
}

// parse_prefix_connective parses `and BODY BODY…` / `or BODY BODY…` /
// `not BODY` where each BODY is a bracketed sub-body `[…]` recursively
// parsed through predicate_expr_parse.
fn parse_prefix_connective(mut c PredicateParseCursor, source string) !&PredicateExpr {
	word := c.read_name()
	if word != 'and' && word != 'or' && word != 'not' {
		return error('PREDICATE_EXPR_PARSE: expected connective, got `${word}`')
	}
	mut children := []&PredicateExpr{}
	for {
		c.skip_ws()
		if c.at_end() {
			break
		}
		if c.peek() != `[` {
			return error('PREDICATE_EXPR_PARSE: connective operand must be a bracketed sub-body, got `${c.peek().ascii_str()}`')
		}
		sub := read_bracket_body(mut c) or {
			return error('PREDICATE_EXPR_PARSE: unbalanced bracket in connective operand')
		}
		children << predicate_expr_parse(sub)!
	}
	if word == 'not' && children.len != 1 {
		return error('PREDICATE_EXPR_PARSE: `not` takes exactly one operand (got ${children.len})')
	}
	if word != 'not' && children.len < 2 {
		return error('PREDICATE_EXPR_PARSE: `${word}` takes two or more operands (got ${children.len})')
	}
	return &PredicateExpr{
		kind:     .bool_expr
		op:       word
		children: children
		source:   source
	}
}

// read_bracket_body consumes a bracketed `[…]` span at the cursor and
// returns its interior, respecting nesting and quoted strings.
fn read_bracket_body(mut c PredicateParseCursor) ?string {
	if c.peek() != `[` {
		return none
	}
	start := c.pos + 1
	mut depth := 0
	for !c.at_end() {
		b := c.peek()
		if b == `"` || b == `'` {
			q := b
			c.advance()
			for !c.at_end() && c.peek() != q {
				if c.peek() == `\\` {
					c.advance()
				}
				c.advance()
			}
			c.advance()
			continue
		}
		if b == `[` {
			depth++
		} else if b == `]` {
			depth--
			if depth == 0 {
				body := c.src[start..c.pos].bytestr()
				c.advance() // ']'
				return body
			}
		}
		c.advance()
	}
	return none
}

// predicate_body_leads_with_word_operator reports whether the body's
// first token is a reserved word-operator head (`and …`, `or …`,
// `not …`, `union …`, …) — a FUSED prefix form, which legitimately
// contains connective words and must not trip the infix pre-scan.
fn predicate_body_leads_with_word_operator(source string) bool {
	t := source.trim_space()
	for w in ['and', 'or', 'not', 'cast', 'union', 'intersect', 'except'] {
		if t == w {
			return false // a lone connective word is not a form
		}
		if t.starts_with(w) && t.len > w.len {
			nxt := t[w.len]
			if nxt == ` ` || nxt == `\t` || nxt == `\n` || nxt == `[` {
				return true
			}
		}
	}
	return false
}

// predicate_body_has_bool_keyword performs a coarse pre-scan for `and`
// or `or` boolean-connective keywords outside of quoted regions. Used
// to bail out early on bodies that exceed the Phase 2.19 atomic-only
// scope. The check is conservative: false positives just lose AST
// promotion (the caller still has the source string).
fn predicate_body_has_bool_keyword(source string) bool {
	src := source.bytes()
	mut i := 0
	for i < src.len {
		b := src[i]
		if b == `"` || b == `'` {
			quote := b
			i++
			for i < src.len && src[i] != quote {
				if src[i] == `\\` && i + 1 < src.len {
					i += 2
					continue
				}
				i++
			}
			i++
			continue
		}
		// Word-boundary check: previous byte must be non-name-cont.
		if path_is_name_start(b) && (i == 0 || !path_is_name_cont(src[i - 1])) {
			mut end := i + 1
			for end < src.len && path_is_name_cont(src[end]) {
				end++
			}
			word := src[i..end].bytestr()
			if word == 'and' || word == 'or' {
				return true
			}
			i = end
			continue
		}
		i++
	}
	return false
}

// parse_dollar_underscore handles the `$_…` family of bodies:
//   - `$_`           → not a valid standalone predicate body (errors)
//   - `$_position`   → kind=reserved_binding, name="$_position"
//   - `$_last`       → kind=reserved_binding, name="$_last"
//   - `$_@name [OP V]` → desugars to attr_test / attr_compare
fn parse_dollar_underscore(mut c PredicateParseCursor, source string) !&PredicateExpr {
	// Consume `$_`.
	c.advance() // $
	c.advance() // _
	// `$_@name [OP V]` — attribute test/compare via explicit context.
	if !c.at_end() && c.peek() == `@` {
		return parse_attr(mut c, source)!
	}
	// `$_position` / `$_last` / other reserved-binding suffix.
	suffix := c.read_name()
	c.skip_ws()
	if !c.at_end() {
		return error('PREDICATE_EXPR_PARSE: unexpected trailing input after \$_${suffix}: ${source}')
	}
	full_name := '\$_' + suffix
	if suffix != 'position' && suffix != 'last' && suffix != '' {
		// Not a reserved binding — bail out for the Phase 2.19 scope.
		return error('PREDICATE_EXPR_PARSE: unknown \$_-binding ${full_name}')
	}
	return &PredicateExpr{
		kind:   .reserved_binding
		name:   full_name
		source: source
	}
}

// parse_attr handles `@name` and `@name OP value`. Cursor positioned on
// `@`. On entry the leading `$_` (if any) has been consumed.
fn parse_attr(mut c PredicateParseCursor, source string) !&PredicateExpr {
	if c.peek() != `@` {
		return error('PREDICATE_EXPR_PARSE: expected `@` at attribute test')
	}
	c.advance() // @
	name := c.read_name()
	if name.len == 0 {
		return error('PREDICATE_EXPR_PARSE: expected attribute name after `@`')
	}
	c.skip_ws()
	if c.at_end() {
		return &PredicateExpr{
			kind:   .attr_test
			name:   name
			source: source
		}
	}
	// The infix attribute comparison `@name OP value` is RETIRED
	// (grammar [132]–[134]): hard error, never a source-only fallback.
	if op := c.read_op() {
		return error('RETIRED_PREDICATE_SURFACE: infix attribute comparison `[@${name}${op}…]` is retired — write the prefix operator form `[${op} \$_@${name} …]` (code.md §5.5.2)')
	}
	return error('PREDICATE_EXPR_PARSE: unexpected trailing input after @${name}: ${source}')
}

// parse_int_position handles a bare integer literal body → desugars to
// `$_position = N`.
fn parse_int_position(mut c PredicateParseCursor, source string) !&PredicateExpr {
	n := c.read_int() or {
		return error('PREDICATE_EXPR_PARSE: expected integer literal')
	}
	c.skip_ws()
	if !c.at_end() {
		// Trailing junk after the int — not the atomic int_position
		// template. Could be `N and …` but boolean-keyword pre-scan
		// already filtered those.
		return error('PREDICATE_EXPR_PARSE: unexpected trailing input after int: ${source}')
	}
	if n < 1 {
		return error('PREDICATE_EXPR_PARSE: position must be ≥ 1 (got ${n})')
	}
	return &PredicateExpr{
		kind:     .int_position
		position: n
		source:   source
	}
}

// parse_function_call — the paren-call templates (`count(*)`,
// `count(*) OP N`, `last()`) are RETIRED (grammar [132]–[134] / code.md
// §6.3: there is no paren-call anywhere in the language). A bare
// identifier body is the step-existence notation atom, promoted by the
// caller's fallback path; an identifier followed by `(` is a hard error.
fn parse_function_call(mut c PredicateParseCursor, source string) !&PredicateExpr {
	fn_name := c.read_name()
	if fn_name.len == 0 {
		return error('PREDICATE_EXPR_PARSE: expected identifier')
	}
	c.skip_ws()
	if !c.at_end() && c.peek() == `(` {
		hint := if fn_name == 'last' {
			'write `[= \$_position \$_last]`'
		} else {
			'use the head-dispatch builtin with the context binding, e.g. `[> [\$count \$_/*] 1]`'
		}
		return error('RETIRED_PREDICATE_SURFACE: paren-call `${fn_name}(…)` in a CXPath predicate is retired — ${hint} (code.md §6.3)')
	}
	return error('PREDICATE_EXPR_PARSE: bare identifier `${fn_name}` not an atomic template (step existence promotes via the general parser)')
}
