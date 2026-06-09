module cx

// match_parser.v — `[?match]` multi-arm surface-text → MatchNode parser (Phase 2.4).
//
// Per (multi-arm `[?match]`) the parser produces the spec-canonical
// `MatchNode` AST defined in match_node.v. This file covers grammar productions
// [136]–[140]:
//
//   [136] MatchExpr ::= '[?match' S ProgramExpr? S MatchArm+ S? ']'
//   [137] MatchArm  ::= CaseArm | WhenArm | ElseArm
//   [138] CaseArm   ::= ':case' S MatchPattern (S ':where' S ProgramExpr)? S ':yield' S ProgramExpr
//   [139] WhenArm   ::= ':when' S ProgramExpr S ':yield' S ProgramExpr
//   [140] ElseArm   ::= ':else' S ':yield' S ProgramExpr
//
// The scrutinee (optional ProgramExpr in [136]) and every embedded expression
// slot (pattern body, `:where` guard, `:yield` body) are captured as verbatim
// source-text snippets at Phase 2.4 — mirrors the PathPredicate.source
// convention in path_parser.v. Structural ProgramExpr subtrees graft in at a
// Phase 2.x follow-up without changing the public function signatures.
//
// Validation contract enforced here:
//   - At least one arm (no empty `[?match]`).
//   - `:else` MUST be the last arm; an `:else` followed by any further `:case`
//     / `:when` / `:else` arm is rejected.
//   - At most one `:else` arm.
//   - Predicate-only mode (no scrutinee + `:when`-only arms, SQL Searched
// CASE) is admitted; predicate-only mode forbids `:case`
//     arms — `:case` with no scrutinee is a parse error.
//   - The 2-arg `[?match value pattern :yield expr]` shape is OUT OF SCOPE
//     here — that goes through the existing slot-parsing path. This
//     parser dispatches only when the multi-arm form is recognised by the
//     presence of `:case` / `:when` / `:else` keywords.
//
// Out of scope at Phase 2.4 (deferred):
//   - Structural ProgramExpr parsing of bodies / patterns / guards.
//   - Evaluator (first-match-wins, EBV rules, no-match behaviour).
// Cross-arm reachability analysis (LSP warning).
//   - 2-arg `[?match]` form — separate code path.
//
// Cross-references:
//   - spec/grammar.ebnf productions [136]–[140]
//   - vcx/cx/match_node.v (Phase 2.4 MatchNode AST)
//   - vcx/cx/path_parser.v (sibling convention for source/loc tracking + cursor)

// ── Internal cursor ───────────────────────────────────────────────────────────

// MatchParseCursor is a private byte-position cursor over the source string.
// Kept deliberately small — same shape as PathParseCursor (path_parser.v).
struct MatchParseCursor {
mut:
	src []u8
	pos int
}

@[inline]
fn (c &MatchParseCursor) at_end() bool {
	return c.pos >= c.src.len
}

@[inline]
fn (c &MatchParseCursor) peek() u8 {
	if c.pos < c.src.len {
		return c.src[c.pos]
	}
	return 0
}

@[inline]
fn (mut c MatchParseCursor) advance() {
	if c.pos < c.src.len {
		c.pos++
	}
}

@[inline]
fn match_is_space(b u8) bool {
	return b == ` ` || b == `\t` || b == `\n` || b == `\r`
}

@[inline]
fn match_is_name_start(b u8) bool {
	return (b >= `a` && b <= `z`) || (b >= `A` && b <= `Z`) || b == `_`
}

@[inline]
fn match_is_name_cont(b u8) bool {
	return match_is_name_start(b) || (b >= `0` && b <= `9`) || b == `-`
}

// skip_ws advances past whitespace bytes.
fn (mut c MatchParseCursor) skip_ws() {
	for !c.at_end() && match_is_space(c.peek()) {
		c.advance()
	}
}

// ── Public entry point ────────────────────────────────────────────────────────

// parse_match parses a multi-arm `[?match …]` surface form into a
// MatchNode. The input MUST be the full directive surface
// — opening `[?match` through closing `]`. The 2-arg form
// `[?match value pattern :yield expr]` is NOT handled here; callers
// dispatch on the presence of a `:case` / `:when` / `:else` keyword.
//
// On success the returned MatchNode has:
//   - scrutinee set when a ProgramExpr appears between `[?match` and the
//     first `:case` / `:when` keyword; none in predicate-only mode.
// arms in source order (first-match-wins semantics).
//   - source set to the verbatim input.
//   - loc set to span 0..source.len.
//
// Errors include:
//   - "CXMATCH_PARSE: missing [?match prefix"
//   - "CXMATCH_PARSE: missing closing ]"
//   - "CXMATCH_PARSE: empty match — at least one arm required"
//   - "CXMATCH_PARSE: :else not last — found arm after :else"
//   - "CXMATCH_PARSE: multiple :else arms"
//   - "CXMATCH_PARSE: :case forbidden in predicate-only mode (no scrutinee)"
//   - "CXMATCH_PARSE: :case missing pattern"
//   - "CXMATCH_PARSE: missing :yield in arm"
//   - "CXMATCH_PARSE: unknown arm keyword"
pub fn parse_match(source string) !MatchNode {
	if source.len == 0 {
		return error('CXMATCH_PARSE: empty input')
	}
	mut c := MatchParseCursor{
		src: source.bytes()
		pos: 0
	}

	// Opening `[?match`.
	if !match_consume_literal(mut c, '[?match') {
		return error('CXMATCH_PARSE: missing [?match prefix')
	}
	// Require a separator (whitespace or `]`) after the prefix so we don't
	// accept `[?matchx …]`.
	if !c.at_end() && !match_is_space(c.peek()) && c.peek() != `]` {
		return error('CXMATCH_PARSE: expected whitespace after [?match')
	}

	c.skip_ws()

	// Read up to the first `:case` / `:when` / `:else` keyword — anything
	// before it is the optional scrutinee ProgramExpr.
	scrutinee_src := read_scrutinee(mut c)!
	scrutinee := if scrutinee_src.len > 0 {
		?string(scrutinee_src)
	} else {
		?string(none)
	}

	// Loop through arms.
	mut arms := []MatchArm{}
	mut seen_else := false
	for {
		c.skip_ws()
		if c.at_end() {
			return error('CXMATCH_PARSE: unexpected end of input — missing closing ]')
		}
		if c.peek() == `]` {
			break
		}
		if c.peek() != `:` {
			return error('CXMATCH_PARSE: expected arm keyword (:case / :when / :else) at position ${c.pos}, got ${c.peek().ascii_str()}')
		}
		// Read the arm keyword.
		kw_start := c.pos
		c.advance() // consume `:`
		kw := read_label(mut c)
		if kw.len == 0 {
			return error('CXMATCH_PARSE: malformed arm keyword at position ${kw_start}')
		}
		// :else after we've seen an :else, OR any arm after :else, is a
		// validation failure.
		if seen_else {
			if kw == 'else' {
				return error('CXMATCH_PARSE: multiple :else arms')
			}
			return error('CXMATCH_PARSE: :else not last — found :${kw} arm after :else')
		}
		mut arm_loc := MatchLoc{
			start: kw_start
			end:   0 // filled in after arm parsing
		}
		mut arm := MatchArm{}
		match kw {
			'case' {
				if scrutinee == none {
					return error('CXMATCH_PARSE: :case forbidden in predicate-only mode (no scrutinee) — use :when')
				}
				arm = parse_case_arm(mut c)!
			}
			'when' {
				arm = parse_when_arm(mut c)!
			}
			'else' {
				arm = parse_else_arm(mut c)!
				seen_else = true
			}
			else {
				return error('CXMATCH_PARSE: unknown arm keyword `:${kw}` (expected :case / :when / :else)')
			}
		}
		arm_loc.end = c.pos
		arm.loc = arm_loc
		// Z79b structural graft: best-effort populate `*_node` fields.
		// Failures leave the slot as `none` and downstream code falls
		// back to the verbatim string path.
		if arm.pattern.len > 0 {
			if pn := try_parse_snippet_to_node(arm.pattern) {
				arm.pattern_node = pn
			}
		}
		if g := arm.guard {
			if gn := try_parse_snippet_to_node(g) {
				arm.guard_node = gn
			}
		}
		if arm.body.len > 0 {
			if bn := try_parse_snippet_to_node(arm.body) {
				arm.body_node = bn
			}
		}
		arms << arm
	}

	// Consume closing `]`.
	if c.at_end() || c.peek() != `]` {
		return error('CXMATCH_PARSE: missing closing ]')
	}
	c.advance()

	if arms.len == 0 {
		return error('CXMATCH_PARSE: empty match — at least one arm required')
	}

	// Reject trailing input past the closing `]`.
	c.skip_ws()
	if !c.at_end() {
		return error('CXMATCH_PARSE: unexpected trailing input after ]: ${source[c.pos..]}')
	}

	return MatchNode{
		scrutinee: scrutinee
		arms:      arms
		source:    source
		loc:       MatchLoc{ start: 0, end: source.len }
	}
}

// ── Arm-specific parsers ──────────────────────────────────────────────────────

// parse_case_arm consumes the body of a `:case PATTERN (':where' GUARD)? :yield BODY` arm,
// assuming the leading `:case` keyword has already been consumed.
fn parse_case_arm(mut c MatchParseCursor) !MatchArm {
	c.skip_ws()
	// Read the pattern up to `:where` / `:yield`.
	pattern := read_expr_until_keyword(mut c, ['where', 'yield'])!
	if pattern.len == 0 {
		return error('CXMATCH_PARSE: :case missing pattern')
	}
	c.skip_ws()
	// Optional `:where GUARD`.
	mut guard := ?string(none)
	if c.peek() == `:` && peek_label_is(c, 'where') {
		c.advance() // `:`
		_ := read_label(mut c) // consume "where"
		c.skip_ws()
		guard_src := read_expr_until_keyword(mut c, ['yield'])!
		if guard_src.len == 0 {
			return error('CXMATCH_PARSE: :where missing guard expression')
		}
		guard = guard_src
		c.skip_ws()
	}
	// Required `:yield BODY`.
	if !(c.peek() == `:` && peek_label_is(c, 'yield')) {
		return error('CXMATCH_PARSE: missing :yield in :case arm')
	}
	c.advance() // `:`
	_ := read_label(mut c) // consume "yield"
	c.skip_ws()
	body := read_expr_until_arm_boundary(mut c)!
	if body.len == 0 {
		return error('CXMATCH_PARSE: :yield missing body expression')
	}
	return MatchArm{
		kind:    ArmKind.case_arm
		pattern: pattern
		guard:   guard
		body:    body
	}
}

// parse_when_arm consumes `:when PREDICATE :yield BODY`, assuming `:when` already eaten.
fn parse_when_arm(mut c MatchParseCursor) !MatchArm {
	c.skip_ws()
	predicate := read_expr_until_keyword(mut c, ['yield'])!
	if predicate.len == 0 {
		return error('CXMATCH_PARSE: :when missing predicate expression')
	}
	c.skip_ws()
	if !(c.peek() == `:` && peek_label_is(c, 'yield')) {
		return error('CXMATCH_PARSE: missing :yield in :when arm')
	}
	c.advance() // `:`
	_ := read_label(mut c) // "yield"
	c.skip_ws()
	body := read_expr_until_arm_boundary(mut c)!
	if body.len == 0 {
		return error('CXMATCH_PARSE: :yield missing body expression')
	}
	return MatchArm{
		kind:  ArmKind.when_arm
		guard: ?string(predicate)
		body:  body
	}
}

// parse_else_arm consumes `:else :yield BODY`, assuming `:else` already eaten.
fn parse_else_arm(mut c MatchParseCursor) !MatchArm {
	c.skip_ws()
	if !(c.peek() == `:` && peek_label_is(c, 'yield')) {
		return error('CXMATCH_PARSE: missing :yield in :else arm')
	}
	c.advance() // `:`
	_ := read_label(mut c) // "yield"
	c.skip_ws()
	body := read_expr_until_arm_boundary(mut c)!
	if body.len == 0 {
		return error('CXMATCH_PARSE: :yield missing body expression in :else arm')
	}
	return MatchArm{
		kind: ArmKind.else_arm
		body: body
	}
}

// ── Sub-readers ───────────────────────────────────────────────────────────────

// match_consume_literal advances the cursor past the given literal string
// when it matches at the current position. Returns true on consume.
fn match_consume_literal(mut c MatchParseCursor, lit string) bool {
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

// read_label reads `[_A-Za-z][_A-Za-z0-9-]*` from the cursor and returns
// the bytes. Used for arm-keyword recognition (e.g. `case`, `when`,
// `else`, `where`, `yield`).
fn read_label(mut c MatchParseCursor) string {
	start := c.pos
	if c.at_end() || !match_is_name_start(c.peek()) {
		return ''
	}
	c.advance()
	for !c.at_end() && match_is_name_cont(c.peek()) {
		c.advance()
	}
	return c.src[start..c.pos].bytestr()
}

// peek_label_is checks (non-mutating) whether the byte AT c.pos is `:`
// followed by exactly the given keyword label. The cursor MUST be sitting
// on a `:` byte; the caller has already verified that.
fn peek_label_is(c MatchParseCursor, label string) bool {
	// Position immediately after `:`.
	start := c.pos + 1
	if start >= c.src.len {
		return false
	}
	if !match_is_name_start(c.src[start]) {
		return false
	}
	mut end := start + 1
	for end < c.src.len && match_is_name_cont(c.src[end]) {
		end++
	}
	got := c.src[start..end].bytestr()
	return got == label
}

// read_scrutinee reads the optional ProgramExpr scrutinee between
// `[?match` and the first arm keyword. It captures everything up to
// the first `:case` / `:when` / `:else` keyword that appears at the
// TOP LEVEL (depth 0 with respect to brackets and quoted strings).
// Returns the verbatim source-text, with surrounding whitespace
// trimmed. An empty return signals predicate-only mode.
fn read_scrutinee(mut c MatchParseCursor) !string {
	return read_expr_until_keyword(mut c, ['case', 'when', 'else'])
}

// read_expr_until_keyword captures verbatim source-text from the
// current cursor position up to (but not including) the next `:LABEL`
// where LABEL is one of `stop_labels` AND `:LABEL` appears at the
// top level (depth 0 with respect to brackets `[ ]` and quoted
// strings). Returns the trimmed source-text slice. The cursor is
// advanced to point AT the `:` of the stopping label (so the caller
// can consume the keyword next).
//
// Bracket / quote bookkeeping mirrors path_parser.v read_predicate_body:
//   - `[` / `]` track depth.
//   - `'` / `"` open a quoted span that shields `:` and brackets;
//     escape sequences are skipped 1-char-at-a-time.
//
// Also stops at top-level `]` (without consuming) — the caller's
// outer loop closes the `[?match …]` form.
fn read_expr_until_keyword(mut c MatchParseCursor, stop_labels []string) !string {
	start := c.pos
	mut depth := 0
	for !c.at_end() {
		b := c.peek()
		// Quoted string region: shield everything until matching quote.
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
				return error('CXMATCH_PARSE: unterminated string literal in expression')
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
				// Top-level `]` — stops the expression slot.
				break
			}
			depth--
			c.advance()
			continue
		}
		if b == `:` && depth == 0 {
			// Peek the label after `:`.
			if label_after_colon_in(c, stop_labels) {
				break
			}
			// Not a stop label — could be `::` (CXPath axis), unrelated
			// modifier, or atom literal etc. Consume the `:` and continue.
			c.advance()
			continue
		}
		c.advance()
	}
	raw := c.src[start..c.pos].bytestr()
	return raw.trim_space()
}

// read_expr_until_arm_boundary reads a `:yield` body up to the next
// top-level arm keyword (`:case` / `:when` / `:else`) OR top-level `]`.
// The cursor stops at the `:` of the next arm keyword or at the `]`
// closing the `[?match …]` form. Whitespace is trimmed from the
// returned slice.
fn read_expr_until_arm_boundary(mut c MatchParseCursor) !string {
	return read_expr_until_keyword(mut c, ['case', 'when', 'else'])
}

// label_after_colon_in (non-mutating) returns true when the cursor is
// at a `:` whose immediately-following identifier is in `labels`.
fn label_after_colon_in(c MatchParseCursor, labels []string) bool {
	start := c.pos + 1
	if start >= c.src.len {
		return false
	}
	if !match_is_name_start(c.src[start]) {
		return false
	}
	mut end := start + 1
	for end < c.src.len && match_is_name_cont(c.src[end]) {
		end++
	}
	got := c.src[start..end].bytestr()
	return got in labels
}
