module cx

// const_parser.v — `[?const]` surface-text → ConstNode parser (Phase 2.12 Part 2).
//
// Per (`[?const]` module-level constants) the parser produces
// the spec-canonical `ConstNode` AST defined in const_node.v. This file
// covers grammar productions [154]–[154a]:
//
//   [154]  ConstDirective ::= '[?const' ( S ConstModifier )* S Name S ProgramExpr S? ']'
//   [154a] ConstModifier  ::= ScopeAttr ('scope=public'|'scope=private')
//                          |  'lazy'
//
// The value expression is captured as a verbatim source-text snippet at
// Phase 2.12 Part 2 — mirrors the PathPredicate.source / MatchArm.body /
// ModifyAction.value / DefNode.body convention. A structural ProgramExpr
// subtree grafts in at a Phase 2.16 follow-up without changing the public
// function signature.
//
// Validation contract enforced here:
//   - `[?const]` head prefix required; trailing whitespace after `[?const`
//     required to distinguish from `[?constx …]`.
//   - Constant name required (bareword) — absent → CXCONST_PARSE.
//   - Value expression required — absent → CXCONST_PARSE.
//   - Modifiers `scope=public|private` (attribute) / `lazy` (bareword)
//     admitted in any order before the name. The retired `:scope`/`:lazy`
//     colon-slot surface is a hard parse error (D014, no dual-accept).
//   - Duplicate `lazy` modifier → CXCONST_PARSE.
//   - Duplicate `scope=` modifier → CXCONST_PARSE.
//   - `scope=` value must be `public` or `private` → CXCONST_PARSE.
//
// Out of scope at Phase 2.12 Part 2 (deferred):
//   - Module-load semantics — eager evaluation, lazy memoization,
//     two-pass cycle detection (Phase 2.13).
//   - Nested-`[?const]` detection / nesting under non-top-level forms
//     (Phase 2.13).
//   - Body evaluation + CXER0214 / CXER0215 raise (Phase 2.13).
//   - Dev-strict type validation (Phase 2.16).
//
// Cross-references:
//   - spec/grammar.ebnf productions [154]–[154a]
//   - spec/code.md §12.3 (normative semantics)
//   - vcx/cx/const_node.v (Phase 2.12 Part 2 ConstNode AST)
//   - vcx/cx/def_parser.v (Z1 sibling — cursor + shielded scan convention)

// ── Internal cursor ───────────────────────────────────────────────────────────

// ConstParseCursor is a private byte-position cursor over the source
// string. Same shape as DefParseCursor / MatchParseCursor / ModifyParseCursor.
struct ConstParseCursor {
mut:
	src []u8
	pos int
}

@[inline]
fn (c &ConstParseCursor) at_end() bool {
	return c.pos >= c.src.len
}

@[inline]
fn (c &ConstParseCursor) peek() u8 {
	if c.pos < c.src.len {
		return c.src[c.pos]
	}
	return 0
}

@[inline]
fn (mut c ConstParseCursor) advance() {
	if c.pos < c.src.len {
		c.pos++
	}
}

@[inline]
fn const_is_space(b u8) bool {
	return b == ` ` || b == `\t` || b == `\n` || b == `\r`
}

@[inline]
fn const_is_name_start(b u8) bool {
	return (b >= `a` && b <= `z`) || (b >= `A` && b <= `Z`) || b == `_`
}

@[inline]
fn const_is_name_cont(b u8) bool {
	return const_is_name_start(b) || (b >= `0` && b <= `9`) || b == `-` || b == `?`
		|| b == `!`
}

fn (mut c ConstParseCursor) skip_ws() {
	for !c.at_end() && const_is_space(c.peek()) {
		c.advance()
	}
}

// ── Public entry point ────────────────────────────────────────────────────────

// parse_const parses a `[?const …]` surface form into a ConstNode per
// The input MUST be the full directive surface — opening
// `[?const` through closing `]`.
//
// On success the returned ConstNode has:
//   - name set to the constant identifier.
//   - value_source set to the verbatim source of the value ProgramExpr.
//   - lazy = true when the `lazy` bareword modifier was present; else false.
//   - scope set when `scope=public|private` is present; none otherwise.
//   - source set to the verbatim input.
//   - loc set to span 0..source.len.
//
// Errors:
//   - "CXCONST_PARSE: missing [?const prefix"
//   - "CXCONST_PARSE: expected whitespace after [?const"
//   - "CXCONST_PARSE: missing constant name"
//   - "CXCONST_PARSE: missing value expression"
//   - "CXCONST_PARSE: missing closing ]"
//   - "CXCONST_PARSE: unexpected trailing input after ]"
//   - "CXCONST_UNKNOWN_MODIFIER: unknown attribute modifier `LABEL=…`"
//   - "CXCONST_PARSE: scope= value must be `public` or `private`"
//   - "CXCONST_PARSE: duplicate scope= modifier"
//   - "CXCONST_PARSE: duplicate lazy modifier"
pub fn parse_const(source string) !ConstNode {
	if source.len == 0 {
		return error('CXCONST_PARSE: empty input')
	}
	mut c := ConstParseCursor{
		src: source.bytes()
		pos: 0
	}

	// Opening `[?const`.
	if !const_consume_literal(mut c, '[?const') {
		return error('CXCONST_PARSE: missing [?const prefix')
	}
	// Require a separator after the prefix so we don't accept `[?constx …]`.
	if c.at_end() || (!const_is_space(c.peek()) && c.peek() != `]`) {
		return error('CXCONST_PARSE: expected whitespace after [?const')
	}

	// Modifiers (zero or more) before the constant name. Per grammar
	// [154]/[154a]: `'[?const' ( S ConstModifier )* S Name …` where
	// ConstModifier ::= ScopeAttr | 'lazy'. Modifiers precede the name;
	// they are the `scope=public|private` attribute and the bareword
	// `lazy`. Any other bareword is the constant NAME and ends the loop.
	// The retired `:scope`/`:lazy` colon-slot surface is a hard parse
	// error (D014, no dual-accept).
	mut lazy := false
	mut scope := ?string(none)
	for {
		c.skip_ws()
		if c.at_end() {
			return error('CXCONST_PARSE: unexpected end of input — missing constant name')
		}
		if c.peek() == `]` {
			return error('CXCONST_PARSE: missing constant name')
		}
		if c.peek() == `:` {
			kw_start := c.pos
			c.advance() // consume `:`
			kw := const_read_label(mut c)
			return error('CXCONST_PARSE: retired `:${kw}` colon-slot modifier on `[?const]` at position ${kw_start} — use `scope=public|private` or the `lazy` bareword (grammar [154a])')
		}
		if !const_is_name_start(c.peek()) {
			// A non-name, non-`:`, non-`]` byte where a modifier or the
			// constant name is expected — the name is missing / malformed.
			return error('CXCONST_PARSE: missing constant name (got `${c.peek().ascii_str()}` at position ${c.pos})')
		}
		mark := c.pos
		label := const_read_label(mut c)
		// `scope=public|private` attribute modifier.
		if !c.at_end() && c.peek() == `=` {
			c.advance() // consume `=`
			if label != 'scope' {
				return error('CXCONST_UNKNOWN_MODIFIER: unknown attribute modifier `${label}=…` (expected `scope`)')
			}
			if scope != none {
				return error('CXCONST_PARSE: duplicate scope= modifier')
			}
			val := const_read_label(mut c)
			if val.len == 0 {
				return error('CXCONST_PARSE: scope= missing value (expected `public` or `private`)')
			}
			if val != 'public' && val != 'private' {
				return error('CXCONST_PARSE: scope= value must be `public` or `private`, got `${val}`')
			}
			scope = val
			continue
		}
		// Bareword `lazy` modifier.
		if label == 'lazy' {
			if lazy {
				return error('CXCONST_PARSE: duplicate lazy modifier')
			}
			lazy = true
			continue
		}
		// Any other bareword is the constant NAME — rewind and break so the
		// name reader below consumes it.
		c.pos = mark
		break
	}

	// Constant name (required).
	if !const_is_name_start(c.peek()) {
		return error('CXCONST_PARSE: missing constant name')
	}
	name := const_read_name(mut c)
	if name.len == 0 {
		return error('CXCONST_PARSE: missing constant name')
	}

	// Value expression — verbatim ProgramExpr up to closing top-level `]`.
	c.skip_ws()
	if c.at_end() {
		return error('CXCONST_PARSE: missing value expression')
	}
	if c.peek() == `]` {
		return error('CXCONST_PARSE: missing value expression')
	}
	value_source := const_read_expr_until_close(mut c)!
	if value_source.len == 0 {
		return error('CXCONST_PARSE: missing value expression')
	}

	// Consume closing `]`.
	c.skip_ws()
	if c.at_end() || c.peek() != `]` {
		return error('CXCONST_PARSE: missing closing ]')
	}
	c.advance()

	// Reject trailing input past the closing `]`.
	c.skip_ws()
	if !c.at_end() {
		return error('CXCONST_PARSE: unexpected trailing input after ]: ${source[c.pos..]}')
	}

	return ConstNode{
		name:         name
		value_source: value_source
		lazy:         lazy
		scope:        scope
		source:       source
		loc:          ConstLoc{
			start: 0
			end:   source.len
		}
	}
}

// ── Sub-readers ───────────────────────────────────────────────────────────────

// const_consume_literal advances the cursor past the given literal
// string when it matches at the current position. Returns true on
// consume.
fn const_consume_literal(mut c ConstParseCursor, lit string) bool {
	lit_bytes := lit.bytes()
	if c.pos + lit_bytes.len > c.src.len {
		return false
	}
	for i, b in lit_bytes {
		if c.src[c.pos + i] != b {
			return false
		}
	}
	c.pos += lit_bytes.len
	return true
}

// const_read_label reads a `[_A-Za-z][_A-Za-z0-9-]*` identifier from
// the cursor and returns the bytes. Used for modifier-keyword
// recognition (e.g. `scope`, `lazy`).
fn const_read_label(mut c ConstParseCursor) string {
	start := c.pos
	if c.at_end() || !const_is_name_start(c.peek()) {
		return ''
	}
	c.advance()
	for !c.at_end() && const_is_name_cont(c.peek()) {
		c.advance()
	}
	return c.src[start..c.pos].bytestr()
}

// const_read_name reads a constant name (bareword identifier — same
// shape as a label). Allows `?` / `!` suffixes per CX naming
// convention.
fn const_read_name(mut c ConstParseCursor) string {
	return const_read_label(mut c)
}

// const_read_expr_until_close captures the verbatim source-text value
// expression from the current cursor position up to the top-level
// closing `]` of the `[?const …]` form. Returns the trimmed source-
// text slice. The cursor is advanced to point AT the `]` so the
// caller can consume the closer.
//
// Bracket / quote bookkeeping mirrors def_parser.v
// def_read_expr_until_close:
//   - `[` / `]` track depth.
//   - `'` / `"` open a quoted span that shields brackets + escapes.
//   - `#` line comments, `[; … ]` block comments, and `[#…#]` raw text are
//     OPAQUE spans (#289) — shared recognizers in lexical.v.
//   - top-level `]` breaks the scan (without consuming).
fn const_read_expr_until_close(mut c ConstParseCursor) !string {
	start := c.pos
	mut depth := 0
	for !c.at_end() {
		b := c.peek()
		if hash_line_comment_at(c.src, c.pos) {
			c.pos = line_comment_end(c.src, c.pos)
			continue
		}
		if block_comment_open_at(c.src, c.pos) {
			c.pos = block_comment_end(c.src, c.pos) or {
				return error('CXCONST_PARSE: unterminated `[; … ]` comment in value expression')
			}
			continue
		}
		if raw_span_open_at(c.src, c.pos) {
			c.pos = raw_span_end(c.src, c.pos) or {
				return error('CXCONST_PARSE: unterminated `[#…#]` raw text in value expression')
			}
			continue
		}
		if b == `'` || b == `"` {
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
				return error('CXCONST_PARSE: unterminated string literal in value expression')
			}
			c.advance() // closing quote
			continue
		}
		if b == `[` {
			depth++
			c.advance()
			continue
		}
		if b == `]` {
			if depth == 0 {
				break
			}
			depth--
			c.advance()
			continue
		}
		c.advance()
	}
	raw := c.src[start..c.pos].bytestr()
	return raw.trim_space()
}
