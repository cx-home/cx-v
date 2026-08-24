module cx

// def_parser.v — `[?def]` surface-text → DefNode parser (Phase 2.12 Part 1).
//
// Per (`[?def]` module-level static functions) the parser produces
// the spec-canonical `DefNode` AST defined in def_node.v. This file covers
// grammar productions [152]–[153f]:
//
//   [152]  DefDirective    ::= '[?def' S Name ( S DefModifier )* S ParamList S ProgramExpr S? ']'
//   [152a] DefModifier     ::= ScopeAttr ('scope=public'|'scope=private')
//                            |  Bareword  ('pure' | 'impure')
//                            |  ReturnsClause '[returns' S Type ']'
//                            |  ThrowsClause  '[throws'  S Type ']'  /* reserved (D5.2) */
//   [153]  ParamList       ::= '(' S? ( Param ( S Param )* )? ( S RestParam )? S? ')'
//   [153a] Param           ::= PositionalParam | NamedParam
//   [153b] PositionalParam ::= '$' Name TypeAnnot? ( S Default )?
//   [153c] NamedParam      ::= '$' Name '=' Default TypeAnnot?
//   [153d] Default         ::= ProgramExpr
//   [153e] RestParam       ::= '*' '$' Name TypeAnnot?
//   [153f] TypeAnnot       ::= '::' Type
//
// The body, every `:T` type annotation, and every parameter default
// expression are captured as verbatim source-text snippets at Phase 2.12
// — mirrors the PathPredicate.source / MatchArm.body / ModifyAction.value
// convention. Structural ProgramExpr / TypeExprNode subtrees graft in at
// a Phase 2.16 follow-up without changing the public function signatures.
//
// Type expressions accept:
//   - Kind names           (lowercase: string / int / float / bool / null /
//                           atom / element / sequence / map / function /
//                           path)
//   - Element names        (capitalized identifier — Person / Token / …)
//   - Bracketed composites (`[or T1 T2 …]`, `[sequence T]`) — captured as
//                          verbatim source strings at this phase; the
//                          structural TypeExprNode graft is deferred.
//
// Validation contract enforced here:
//   - `[?def]` head prefix required; trailing whitespace after `[?def`
//     required to distinguish from `[?defx …]`.
//   - Function name required (bareword) — absent → CXDEF_PARSE.
//   - Parameter list bracket `( … )` required — absent → CXDEF_PARSE.
//   - Body (single ProgramExpr) required — absent → CXDEF_PARSE.
//   - Modifiers `scope=` (attr) / `pure`/`impure` (bareword) / `[returns T]`
//     / `[throws T]` (clauses) admitted in any order before the parameter
//     list. The retired `:scope`/`:returns`/`:throws`/`:pure`/`:impure`
//     colon-slot surface is a hard parse error (D014, no dual-accept).
//   - `:rest` parameter MUST be last in the parameter list — violation →
//     CXDEF_PARSE.
//   - At most one `:rest` parameter per list — violation → CXDEF_PARSE.
//   - Malformed type annotation (`name:` with no T) → CXDEF_PARSE.
//
// Out of scope at Phase 2.12 Part 1 (deferred):
//   - Module-load semantics — registration, redeclaration check
//     (CXER0205), two-pass cycle detection (Phase 2.13).
//   - Nested-`[?def]` detection raising CXER0204 (Phase 2.13).
//   - Dev-strict type validation (Phase 2.16).
//   - Static purity checker — `:pure` / `:impure` modifier slots
//     parse at Phase 2.23 (this file); call-graph inference +
//     CXER0233 / CXER0234 land at Phase 2.22.
//   - Structural ProgramExpr parsing of body slot + structural
//     TypeExprNode parsing of `:returns T` / `name:T` slots.
//
// Cross-references:
//   - spec/grammar.ebnf productions [152]–[153f]
//   - vcx/cx/def_node.v (Phase 2.12 DefNode AST)
//   - vcx/cx/match_parser.v / vcx/cx/modify_parser.v
//     (sibling convention; cursor + shielded scan)

// ── Internal cursor ───────────────────────────────────────────────────────────

// DefParseCursor is a private byte-position cursor over the source
// string. Same shape as MatchParseCursor / ModifyParseCursor.
struct DefParseCursor {
mut:
	src []u8
	pos int
}

@[inline]
fn (c &DefParseCursor) at_end() bool {
	return c.pos >= c.src.len
}

@[inline]
fn (c &DefParseCursor) peek() u8 {
	if c.pos < c.src.len {
		return c.src[c.pos]
	}
	return 0
}

@[inline]
fn (mut c DefParseCursor) advance() {
	if c.pos < c.src.len {
		c.pos++
	}
}

@[inline]
fn def_is_space(b u8) bool {
	return b == ` ` || b == `\t` || b == `\n` || b == `\r`
}

@[inline]
fn def_is_name_start(b u8) bool {
	return (b >= `a` && b <= `z`) || (b >= `A` && b <= `Z`) || b == `_`
}

@[inline]
fn def_is_name_cont(b u8) bool {
	return def_is_name_start(b) || (b >= `0` && b <= `9`) || b == `-` || b == `?`
		|| b == `!`
}

fn (mut c DefParseCursor) skip_ws() {
	for !c.at_end() && def_is_space(c.peek()) {
		c.advance()
	}
}

// ── Public entry point ────────────────────────────────────────────────────────

// parse_def parses a `[?def …]` surface form into a DefNode per
// The input MUST be the full directive surface — opening
// `[?def` through closing `]`.
//
// On success the returned DefNode has:
//   - name set to the function identifier.
//   - params in source order; positional / named / rest variants populated.
//   - body set to the verbatim source of the function body ProgramExpr.
//   - returns_type set when `:returns T` is present; none otherwise.
//   - scope set when `:scope public/private` is present; none otherwise.
//   - source set to the verbatim input.
//   - loc set to span 0..source.len.
//
// Errors:
//   - "CXDEF_PARSE: missing [?def prefix"
//   - "CXDEF_PARSE: expected whitespace after [?def"
//   - "CXDEF_PARSE: missing function name"
//   - "CXDEF_PARSE: missing parameter list — expected `(`"
//   - "CXDEF_PARSE: missing closing `)` in parameter list"
//   - "CXDEF_PARSE: missing body expression"
//   - "CXDEF_PARSE: missing closing ]"
//   - "CXDEF_PARSE: unexpected trailing input after ]"
//   - "CXDEF_UNKNOWN_MODIFIER: unknown modifier `:LABEL`"
//   - "CXDEF_PARSE: malformed type annotation — `:` not followed by Type"
//   - "CXDEF_PARSE: :rest parameter must be last in parameter list"
//   - "CXDEF_PARSE: at most one :rest parameter per list"
//   - "CXDEF_CONFLICTING_PURITY: `:pure` and `:impure` are mutually exclusive on `[?def]`"
pub fn parse_def(source string) !DefNode {
	if source.len == 0 {
		return error('CXDEF_PARSE: empty input')
	}
	mut c := DefParseCursor{
		src: source.bytes()
		pos: 0
	}

	// Opening `[?def`.
	if !def_consume_literal(mut c, '[?def') {
		return error('CXDEF_PARSE: missing [?def prefix')
	}
	// Require a separator after the prefix so we don't accept `[?defx …]`.
	if c.at_end() || (!def_is_space(c.peek()) && c.peek() != `]`) {
		return error('CXDEF_PARSE: expected whitespace after [?def')
	}

	c.skip_ws()

	// Function name (required).
	name := def_read_name(mut c)
	if name.len == 0 {
		return error('CXDEF_PARSE: missing function name')
	}

	// Modifiers (zero or more) before the parameter list.
	mut returns_type_source := ?string(none)
	mut returns_type_expr := ?TypeExpr(none)
	mut scope := ?string(none)
	mut throws_type := ?string(none)
	// Command clauses (grammar [152d–h], stream 6 L109). At most one
	// occurrence of each clause kind per def — a repeat is a parse error.
	mut has_effects := false
	mut effects := []DefEffectItem{}
	mut requires := []string{}
	mut preconditions := []string{}
	mut is_idempotent := false
	mut has_requires_at := false
	mut requires_at_stream := ''
	mut requires_at_seq := i64(0)
	mut requires_at_hash := ''
	mut idem_window := ''
	mut compensates := ''
	// Purity tracking. Default is `.pure_` when
	// neither `:pure` nor `:impure` appears. We track which side
	// (if any) has been seen so we can reject the conflicting
	// combination explicitly.
	mut purity := Purity.pure_
	mut pure_seen := false
	mut impure_seen := false
	for {
		c.skip_ws()
		if c.at_end() {
			return error('CXDEF_PARSE: unexpected end of input — missing parameter list')
		}
		if c.peek() == `(` {
			break
		}
		if c.peek() == `]` {
			return error('CXDEF_PARSE: missing parameter list — expected `(`')
		}
		// clause-child modifier: `[returns T]` (and reserved
		// `[throws T]`). Dual-accept with the legacy `:returns T` slot.
		if c.peek() == `[` {
			c.advance() // consume `[`
			c.skip_ws()
			clause := def_read_label(mut c)
			if clause.len == 0 {
				return error('CXDEF_PARSE: malformed `[…]` modifier clause at position ${c.pos}')
			}
			c.skip_ws()
			match clause {
				'returns' {
					rt := def_read_type_expr(mut c)!
					if rt.len == 0 {
						return error('CXDEF_PARSE: [returns] missing type expression')
					}
					returns_type_source = rt
					// Stream 16 W1 (L65): a structural parse failure is a
					// LOUD diagnostic, never a silently-dropped slot.
					parsed := parse_type_expr(rt) or {
						return error('CXDEF_PARSE: [returns] type expression: ${err.msg()}')
					}
					returns_type_expr = parsed
				}
				'throws' {
					tt := def_read_type_expr(mut c)!
					if tt.len == 0 {
						return error('CXDEF_PARSE: [throws] missing type expression')
					}
					throws_type = tt
				}
				'effects' {
					// [152f] EffectsClause — THE command discriminator.
					// Zero items = an empty declared effect set (legal).
					if has_effects {
						return error('CXDEF_PARSE: duplicate [effects] clause — at most one per [?def] (grammar [152a])')
					}
					has_effects = true
					effects = def_parse_effect_items(mut c)!
				}
				'requires' {
					// [152d] RequiresClause — >=1 authority requirement.
					if requires.len > 0 {
						return error('CXDEF_PARSE: duplicate [requires] clause — at most one per [?def] (grammar [152a])')
					}
					requires = def_parse_requirements(mut c)!
					if requires.len == 0 {
						return error('CXDEF_PARSE: [requires] needs at least one requirement (grammar [152d])')
					}
				}
				'preconditions' {
					// [152e] PreconditionsClause — >=1 predicate expr,
					// captured verbatim (the PathPredicate.source convention).
					if preconditions.len > 0 {
						return error('CXDEF_PARSE: duplicate [preconditions] clause — at most one per [?def] (grammar [152a])')
					}
					preconditions = def_parse_precondition_exprs(mut c)!
					if preconditions.len == 0 {
						return error('CXDEF_PARSE: [preconditions] needs at least one predicate expression (grammar [152e])')
					}
				}
				'idempotent' {
					// [152g] IdempotentClause — optional [window DUR] child.
					if is_idempotent {
						return error('CXDEF_PARSE: duplicate [idempotent] clause — at most one per [?def] (grammar [152a])')
					}
					is_idempotent = true
					idem_window = def_parse_idempotent_window(mut c)!
				}
				'requires-at' {
					// [152i] RequiresAtClause (stream 10, L156/M26): the
					// cross-stream precondition PIN — the locator triple
					// PLUS the expected position, evaluated as a B3
					// admission read at the commit point (never a fold
					// input; the engine cannot evaluate it — Ring 1 holds
					// no journal — so an unadmitted invocation refuses).
					if has_requires_at {
						return error('CXDEF_PARSE: duplicate [requires-at] clause — at most one per [?def] (grammar [152a])')
					}
					has_requires_at = true
					for {
						c.skip_ws()
						if c.at_end() || c.peek() == `]` {
							break
						}
						key := def_read_name(mut c)
						if key.len == 0 || c.at_end() || c.peek() != `=` {
							return error('CXDEF_PARSE: [requires-at] expects stream=… seq=… hash=… attribute pairs (grammar [152i])')
						}
						c.advance() // consume `=`
						val := def_read_scope_token(mut c)!
						match key {
							'stream' { requires_at_stream = val }
							'seq' { requires_at_seq = val.i64() }
							'hash' { requires_at_hash = val }
							else {
								return error('CXDEF_PARSE: [requires-at] unknown attribute `${key}` (expected stream, seq, hash)')
							}
						}
					}
					if requires_at_stream.len == 0 || requires_at_hash.len == 0
						|| requires_at_seq < 1 {
						return error('CXDEF_PARSE: [requires-at] needs all three of stream=, seq>=1, hash= — the locator triple plus the expected position (a bare hash is not a locator)')
					}
				}
				'compensates' {
					// [152h] CompensatesClause — one target Name.
					if compensates.len > 0 {
						return error('CXDEF_PARSE: duplicate [compensates] clause — at most one per [?def] (grammar [152a])')
					}
					c.skip_ws()
					compensates = def_read_name(mut c)
					if compensates.len == 0 {
						return error('CXDEF_PARSE: [compensates] missing target command name (grammar [152h])')
					}
				}
				else {
					return error('CXDEF_UNKNOWN_MODIFIER: unknown `[${clause} …]` modifier clause (expected `returns`, `throws`, `requires`, `preconditions`, `effects`, `idempotent`, `compensates`, or `requires-at`)')
				}
			}
			c.skip_ws()
			if c.at_end() || c.peek() != `]` {
				return error('CXDEF_PARSE: missing closing `]` on `[${clause} …]` modifier clause')
			}
			c.advance() // consume `]`
			continue
		}
		// attribute modifier: `scope=public` (grammar [152a] ScopeAttr). The
		// legacy `:scope public` colon-slot was RETIRED in the surface
		// cutover (D014) — a leading `:` modifier is now a parse error (handled
		// below). A bareword followed by `=` is a scalar-modifier attribute.
		if def_is_name_start(c.peek()) {
			attr := def_read_label(mut c)
			if c.at_end() || c.peek() != `=` {
				// Reserved bareword modifiers (code.md §183-184): the
				// LABEL-less purity form `pure` / `impure`, e.g.
				// `[?def f scope=public pure (…)]` — equivalent to the
				// `:pure` / `:impure` LABEL form handled below.
				match attr {
					'pure' {
						if impure_seen {
							return error('CXDEF_CONFLICTING_PURITY: `pure` and `impure` are mutually exclusive on `[?def]`')
						}
						pure_seen = true
						purity = .pure_
						continue
					}
					'impure' {
						if pure_seen {
							return error('CXDEF_CONFLICTING_PURITY: `pure` and `impure` are mutually exclusive on `[?def]`')
						}
						impure_seen = true
						purity = .impure_
						continue
					}
					else {
						return error('CXDEF_PARSE: bareword `${attr}` is not a valid modifier — use `scope=public|private`, `pure`/`impure`, or `[returns T]`')
					}
				}
			}
			c.advance() // consume `=`
			val := def_read_label(mut c)
			match attr {
				'scope' {
					if val.len == 0 {
						return error('CXDEF_PARSE: scope= missing value (expected `public` or `private`)')
					}
					if val != 'public' && val != 'private' {
						return error('CXDEF_PARSE: scope= value must be `public` or `private`, got `${val}`')
					}
					scope = val
				}
				else {
					return error('CXDEF_UNKNOWN_MODIFIER: unknown attribute modifier `${attr}=…` (expected `scope`)')
				}
			}
			continue
		}
		// RETIRED (D014): the legacy `:scope`/`:returns`/`:throws`/
		// `:pure`/`:impure` colon-slot modifier surface. The spec (grammar
		// [152a]) admits ONLY: `scope=public|private` (attribute, above),
		// `pure`/`impure` (bareword, above), `[returns T]` / `[throws T]`
		// (clause-children, above). A leading `:` modifier is a hard parse
		// error — no dual-accept.
		if c.peek() == `:` {
			kw_start := c.pos
			c.advance() // consume `:`
			kw := def_read_label(mut c)
			return error('CXDEF_PARSE: retired `:${kw}` colon-slot modifier on `[?def]` at position ${kw_start} — use `scope=public|private`, the `pure`/`impure` bareword, or the `[returns T]` / `[throws T]` clause (grammar [152a])')
		}
		return error('CXDEF_PARSE: expected modifier `scope=…`, `pure`/`impure`, `[returns T]`, or `(` at position ${c.pos}, got `${c.peek().ascii_str()}`')
	}
	// Suppress unused-var warning when :throws slot is absent — the
	// `[throws T]` clause sets it but it is not yet on DefNode.
	_ = throws_type
	// Purity-default resolution for commands (§12.2.7, stream-6 R5): a
	// non-empty [effects] on an UNANNOTATED def implies `impure`
	// (declaring effects IS declaring impurity — requiring a redundant
	// `impure` bareword would be ceremony). An EXPLICIT `pure` is left
	// standing so the registration-site contract check can raise the
	// CXER0239 contradiction (one authority for the typed error).
	if has_effects && effects.len > 0 && !pure_seen && !impure_seen {
		purity = .impure_
	}

	// Parameter list — `(` … `)`.
	if c.peek() != `(` {
		return error('CXDEF_PARSE: missing parameter list — expected `(`')
	}
	params := def_parse_param_list(mut c)!

	// Body — verbatim ProgramExpr up to closing top-level `]`.
	c.skip_ws()
	if c.at_end() {
		return error('CXDEF_PARSE: missing body expression')
	}
	if c.peek() == `]` {
		return error('CXDEF_PARSE: missing body expression')
	}
	body := def_read_expr_until_close(mut c)!
	if body.len == 0 {
		return error('CXDEF_PARSE: missing body expression')
	}

	// Consume closing `]`.
	c.skip_ws()
	if c.at_end() || c.peek() != `]` {
		return error('CXDEF_PARSE: missing closing ]')
	}
	c.advance()

	// Reject trailing input past the closing `]`.
	c.skip_ws()
	if !c.at_end() {
		return error('CXDEF_PARSE: unexpected trailing input after ]: ${source[c.pos..]}')
	}

	return DefNode{
		name:                name
		params:              params
		body:                body
		returns_type_source: returns_type_source
		returns_type_expr:   returns_type_expr
		scope:               scope
		purity:              purity
		purity_explicit:     pure_seen || impure_seen
		source:              source
		has_effects:         has_effects
		effects:             effects
		requires:            requires
		preconditions:       preconditions
		is_idempotent:       is_idempotent
		idem_window:         idem_window
		compensates:         compensates
		has_requires_at:     has_requires_at
		requires_at_stream:  requires_at_stream
		requires_at_seq:     requires_at_seq
		requires_at_hash:    requires_at_hash
		loc:                 DefLoc{
			start: 0
			end:   source.len
		}
	}
}

// ── Command-clause sub-readers (grammar [152d–h], stream 6 L109) ─────────────

// def_read_scope_token reads one requirement / scope-literal token at the
// cursor: a quoted string (returned WITHOUT the quotes — the literal's
// content) or a bare run of non-space, non-`]` bytes (host globs /
// path roots / capability barewords — richer than an identifier Name,
// e.g. `api.example.com:443`).
fn def_read_scope_token(mut c DefParseCursor) !string {
	if c.at_end() {
		return ''
	}
	b := c.peek()
	if b == `'` || b == `"` {
		quote := b
		c.advance()
		start := c.pos
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
			return error('CXDEF_PARSE: unterminated string literal in command clause')
		}
		tok := c.src[start..c.pos].bytestr()
		c.advance() // closing quote
		return tok
	}
	start := c.pos
	for !c.at_end() {
		nb := c.peek()
		if def_is_space(nb) || nb == `]` || nb == `[` {
			break
		}
		c.advance()
	}
	return c.src[start..c.pos].bytestr()
}

// def_parse_effect_items parses the body of `[effects …]` after the
// clause label: zero or more `[CAP scope*]` items ([152f′]). The cursor
// stops AT the clause's closing `]` (consumed by the shared clause
// epilogue in parse_def).
fn def_parse_effect_items(mut c DefParseCursor) ![]DefEffectItem {
	mut items := []DefEffectItem{}
	for {
		c.skip_ws()
		if c.at_end() {
			return error('CXDEF_PARSE: unterminated [effects …] clause')
		}
		if c.peek() == `]` {
			return items
		}
		if c.peek() != `[` {
			return error('CXDEF_PARSE: [effects] items are `[CAP scope*]` elements (grammar [152f′]), got `${c.peek().ascii_str()}`')
		}
		c.advance() // consume item `[`
		c.skip_ws()
		cap := def_read_label(mut c)
		if cap.len == 0 {
			return error('CXDEF_PARSE: [effects] item missing capability name (grammar [152f″])')
		}
		mut scopes := []string{}
		for {
			c.skip_ws()
			if c.at_end() {
				return error('CXDEF_PARSE: unterminated [effects] item `[${cap} …]`')
			}
			if c.peek() == `]` {
				c.advance() // close the item
				break
			}
			tok := def_read_scope_token(mut c)!
			if tok.len == 0 {
				return error('CXDEF_PARSE: malformed scope literal in [effects] item `[${cap} …]`')
			}
			scopes << tok
		}
		items << DefEffectItem{
			cap:    cap
			scopes: scopes
		}
	}
	return items
}

// def_parse_requirements parses the body of `[requires …]` after the
// clause label: one or more requirement tokens ([152d′] — `cap:`
// address string literals or capability barewords). The cursor stops
// AT the clause's closing `]`.
fn def_parse_requirements(mut c DefParseCursor) ![]string {
	mut reqs := []string{}
	for {
		c.skip_ws()
		if c.at_end() {
			return error('CXDEF_PARSE: unterminated [requires …] clause')
		}
		if c.peek() == `]` {
			return reqs
		}
		tok := def_read_scope_token(mut c)!
		if tok.len == 0 {
			return error('CXDEF_PARSE: malformed requirement token in [requires …] (grammar [152d′])')
		}
		reqs << tok
	}
	return reqs
}

// def_parse_precondition_exprs parses the body of `[preconditions …]`
// after the clause label: one or more predicate ProgramExprs captured
// VERBATIM (the PathPredicate.source convention — structural parsing
// happens where the predicate is evaluated). The cursor stops AT the
// clause's closing `]`.
fn def_parse_precondition_exprs(mut c DefParseCursor) ![]string {
	mut exprs := []string{}
	for {
		c.skip_ws()
		if c.at_end() {
			return error('CXDEF_PARSE: unterminated [preconditions …] clause')
		}
		if c.peek() == `]` {
			return exprs
		}
		if c.peek() == `[` {
			// balanced bracket span, verbatim (def_read_type_expr's
			// capture handles nesting + string shielding).
			span := def_read_type_expr(mut c)!
			if span.len == 0 {
				return error('CXDEF_PARSE: malformed predicate expression in [preconditions …]')
			}
			exprs << span
			continue
		}
		tok := def_read_scope_token(mut c)!
		if tok.len == 0 {
			return error('CXDEF_PARSE: malformed predicate expression in [preconditions …]')
		}
		exprs << tok
	}
	return exprs
}

// def_parse_idempotent_window parses the optional `[window DUR]` child
// of `[idempotent …]` ([152g′]). Returns the verbatim duration token
// ('' when no window is declared). The cursor stops AT the clause's
// closing `]`.
fn def_parse_idempotent_window(mut c DefParseCursor) !string {
	c.skip_ws()
	if c.at_end() {
		return error('CXDEF_PARSE: unterminated [idempotent …] clause')
	}
	if c.peek() == `]` {
		return ''
	}
	if c.peek() != `[` {
		return error('CXDEF_PARSE: [idempotent] admits one optional [window DUR] child (grammar [152g]), got `${c.peek().ascii_str()}`')
	}
	c.advance() // consume `[`
	c.skip_ws()
	label := def_read_label(mut c)
	if label != 'window' {
		return error('CXDEF_PARSE: [idempotent] admits one optional [window DUR] child (grammar [152g′]), got `[${label} …]`')
	}
	c.skip_ws()
	dur := def_read_scope_token(mut c)!
	if dur.len == 0 {
		return error('CXDEF_PARSE: [window] missing duration (grammar [152g′])')
	}
	c.skip_ws()
	if c.at_end() || c.peek() != `]` {
		return error('CXDEF_PARSE: missing closing `]` on [window …]')
	}
	c.advance() // close [window …]
	c.skip_ws()
	if c.at_end() || c.peek() != `]` {
		return error('CXDEF_PARSE: [idempotent] admits ONE [window DUR] child (grammar [152g])')
	}
	return dur
}

// ── Sub-readers ───────────────────────────────────────────────────────────────

// def_consume_literal advances the cursor past the given literal
// string when it matches at the current position. Returns true on
// consume.
fn def_consume_literal(mut c DefParseCursor, lit string) bool {
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

// def_read_label reads a `[_A-Za-z][_A-Za-z0-9-]*` identifier from
// the cursor and returns the bytes. Used for modifier-keyword
// recognition (e.g. `scope`, `returns`, `throws`).
fn def_read_label(mut c DefParseCursor) string {
	start := c.pos
	if c.at_end() || !def_is_name_start(c.peek()) {
		return ''
	}
	c.advance()
	for !c.at_end() && def_is_name_cont(c.peek()) {
		c.advance()
	}
	return c.src[start..c.pos].bytestr()
}

// def_read_name reads a function / parameter name (bareword
// identifier — same shape as a label). Allows `?` / `!` suffixes
// (e.g. `even?`, `valid!`) per CX naming convention.
fn def_read_name(mut c DefParseCursor) string {
	return def_read_label(mut c)
}

// def_parse_param_list parses `( PARAM* :rest?  )` per grammar
// [153]. The cursor MUST be sitting on the opening `(`; it is
// advanced past the closing `)` on success.
fn def_parse_param_list(mut c DefParseCursor) ![]DefParam {
	if c.peek() != `(` {
		return error('CXDEF_PARSE: missing parameter list — expected `(`')
	}
	c.advance() // consume `(`

	mut params := []DefParam{}
	mut rest_seen := false
	for {
		c.skip_ws()
		if c.at_end() {
			return error('CXDEF_PARSE: missing closing `)` in parameter list')
		}
		if c.peek() == `)` {
			c.advance() // consume `)`
			return params
		}
		// [153]: every parameter carries the `$` binding sigil.
		//   PositionalParam  `$Name TypeAnnot?`             [153b]
		//   NamedParam       `$Name TypeAnnot? '=' Default` [153c]/[153f]
		//   RestParam        `*$Name TypeAnnot?`            [153e]
		param_start := c.pos
		mut param := DefParam{}
		if c.peek() == `*` {
			// RestParam `*$Name TypeAnnot?` — always last, at most one.
			c.advance() // consume `*`
			if c.at_end() || c.peek() != `$` {
				return error('CXDEF_PARSE: rest parameter must be `*\$name` at position ${param_start}')
			}
			c.advance() // consume `$`
			rest_name := def_read_name(mut c)
			if rest_name.len == 0 {
				return error('CXDEF_PARSE: rest parameter missing name after `*\$`')
			}
			if rest_seen {
				return error('CXDEF_PARSE: at most one rest parameter per list')
			}
			rest_te := def_read_optional_type_annot(mut c)!
			rest_te_source := type_annot_or_none(rest_te)
			rest_te_expr := type_annot_to_structural(rest_te_source)
			param = DefParam{
				name:             rest_name
				type_expr_source: rest_te_source
				type_expr:        rest_te_expr
				is_rest:          true
			}
			rest_seen = true
		} else if c.peek() == `$` {
			if rest_seen {
				return error('CXDEF_PARSE: rest parameter must be last in parameter list')
			}
			c.advance() // consume `$`
			pname := def_read_name(mut c)
			if pname.len == 0 {
				return error('CXDEF_PARSE: malformed `\$` parameter token at position ${param_start}')
			}
			// TypeAnnot (`::T`, glued) binds before any `=` default per
			// the [153f] examples (`\$n::string='hi'`).
			pos_te := def_read_optional_type_annot(mut c)!
			te_source := type_annot_or_none(pos_te)
			te_expr := type_annot_to_structural(te_source)
			mut is_named := false
			mut default_val := ?string(none)
			if !c.at_end() && c.peek() == `=` {
				c.advance() // consume `=`
				default_src := def_read_param_default(mut c)!
				if default_src.len == 0 {
					return error('CXDEF_PARSE: named parameter `\$${pname}=` missing default value')
				}
				default_val = default_src
				is_named = true
			} else {
				// [153b] PositionalParam ::= '$' Name TypeAnnot? ( S Default )?
				// A bare, whitespace-separated VALUE after the type is a
				// DEFAULTED POSITIONAL parameter (`$opts::map {}`), distinct
				// from the `=`-form NAMED parameter ([153c]). Disambiguation:
				// after the type annot, the next non-whitespace token begins
				// either the NEXT param (always `$` / `*`) or the list close
				// (`)`); anything else is this param's positional default.
				save := c.pos
				c.skip_ws()
				if !c.at_end() && c.pos != save && c.peek() != `)` && c.peek() != `$`
					&& c.peek() != `*` {
					default_src := def_read_param_default(mut c)!
					if default_src.len == 0 {
						return error('CXDEF_PARSE: positional parameter `\$${pname}` has an empty default value')
					}
					default_val = default_src
					// is_named stays false — this is a defaulted POSITIONAL.
				} else {
					c.pos = save // no default; restore for the loop's skip_ws
				}
			}
			param = DefParam{
				name:             pname
				type_expr_source: te_source
				type_expr:        te_expr
				is_named:         is_named
				default:          default_val
			}
		} else {
			return error('CXDEF_PARSE: expected parameter `\$name`, `\$name=default`, or `*\$rest` at position ${c.pos}, got `${c.peek().ascii_str()}`')
		}
		param.loc = DefLoc{
			start: param_start
			end:   c.pos
		}
		params << param
	}
	return params
}

// def_read_optional_type_annot reads an optional `:T` annotation at
// the current cursor position. Returns none when no annotation is
// present (the next byte is whitespace / `)` / `(` / `]` / `:` —
// keyword `:` is shielded by the trailing-context check). Returns
// the verbatim type-expression source otherwise.
//
// Per, the `:` MUST be immediately adjacent to the
// preceding Name (no whitespace) in PositionalParam shape. We
// enforce this by only consuming the `:` when it appears with no
// whitespace between the Name and the colon — at this point the
// cursor has just advanced past a Name, so c.peek() is what
// immediately follows. A type annotation only fires when c.peek()
// is literally `:` AND the byte after is a TypeStart byte (name-
// start or `[`).
// V does not support `!?T` return-type composition directly, so
// this helper returns the empty string when no annotation is present
// and a non-empty verbatim type-expression source otherwise. The
// caller wraps the result in `?string` for assignment to
// `DefParam.type_expr`.
fn def_read_optional_type_annot(mut c DefParseCursor) !string {
	if c.at_end() {
		return ''
	}
	if c.peek() != `:` {
		return ''
	}
	// Look ahead: `:` followed by `[` or a name-start ⇒ type annotation.
	// Anything else (e.g. `:rest`, `:other-keyword`) is NOT a type
	// annotation. Note that all of `:rest`, `:foo` etc. ARE name-start
	// bytes after `:`, but those are distinct positional `:label` tokens
	// (encountered at a parameter-token boundary, not inline after a
	// Name). The inline `:T` case is reached only when this function
	// is invoked immediately after consuming a Name byte — there is
	// always a separator (whitespace / `)`) before the next `:LABEL`
	// token in a fresh param.
	if c.pos + 1 >= c.src.len {
		return ''
	}
	next := c.src[c.pos + 1]
	// the canonical (and ONLY admitted) per-parameter type label is the
	// glued double-colon `::T` (grammar [153f] TypeAnnot ::= '::' Type).
	// The legacy single-colon `:T` form was RETIRED in the surface
	// cutover (D014) — a single `:` here is a hard parse error, no dual-accept.
	if next != `:` {
		return error('CXDEF_PARSE: retired single-colon `:T` parameter type — use the glued `::T` form (grammar [153f]), e.g. `(\$x::int)`')
	}
	c.advance() // first `:`
	c.advance() // second `:` of `::`
	te2 := def_read_type_expr(mut c)!
	if te2.len == 0 {
		return error('CXDEF_PARSE: malformed type annotation — `::` not followed by Type')
	}
	return te2
}

// type_annot_or_none packs the empty-string sentinel returned by
// def_read_optional_type_annot into an `?string`. (V does not support
// `!?T` composition on a function return type.)
fn type_annot_or_none(te string) ?string {
	if te.len == 0 {
		return ?string(none)
	}
	return ?string(te)
}

// type_annot_to_structural attempts to parse the verbatim type-
// annotation source into a structural TypeExpr (Phase 2.16 graft).
// Returns none when the input is none OR when structural parsing
// fails; in either case the caller keeps the verbatim source-string
// slot (`DefParam.type_expr_source`) as the source of truth, and the
// dev-strict validator (`vcx/code/type_strict_validator.v`) only
// requires that ONE of the two slots be set when the function is
// declared as typed.
fn type_annot_to_structural(src ?string) ?TypeExpr {
	s := src or { return ?TypeExpr(none) }
	if s.len == 0 {
		return ?TypeExpr(none)
	}
	parsed := parse_type_expr(s) or { return ?TypeExpr(none) }
	return parsed
}

// def_read_type_expr reads a single Type expression at the cursor.
// Type ::= KindName | ElementName | BracketType per grammar [155].
// BracketType `[ … ]` is captured as a verbatim balanced-bracket
// span (deferred structural parse — Phase 2.16 graft); KindName /
// ElementName are bare identifiers.
//
// The cursor is advanced past the Type expression on success.
// Surrounding whitespace is trimmed from the returned slice.
fn def_read_type_expr(mut c DefParseCursor) !string {
	c.skip_ws()
	if c.at_end() {
		return ''
	}
	if c.peek() == `[` {
		// Capture balanced bracket span verbatim.
		start := c.pos
		mut depth := 0
		for !c.at_end() {
			b := c.peek()
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
					return error('CXDEF_PARSE: unterminated string literal in type expression')
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
				depth--
				c.advance()
				if depth == 0 {
					break
				}
				continue
			}
			c.advance()
		}
		if depth != 0 {
			return error('CXDEF_PARSE: unbalanced brackets in type expression')
		}
		return c.src[start..c.pos].bytestr()
	}
	// Bare identifier (KindName or ElementName).
	if def_is_name_start(c.peek()) {
		return def_read_name(mut c)
	}
	return ''
}

// def_read_param_default reads a single ProgramExpr default value
// for a named parameter — captured verbatim. Stops at the next
// top-level whitespace OR `)` OR `:NAME` (signalling the next
// param token).
//
// Bracket / quote bookkeeping mirrors def_read_expr_until_close:
//   - `[` / `]` track depth; depth-0 `]` is unexpected (paramlist
//     hasn't closed) but we let the cursor proceed naturally.
//   - `'` / `"` open a quoted span that shields whitespace + `:`.
//   - comments / raw text are opaque spans, as in
//     def_read_expr_until_close (#289).
fn def_read_param_default(mut c DefParseCursor) !string {
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
				return error('CXDEF_PARSE: unterminated `[; … ]` comment in parameter default')
			}
			continue
		}
		if raw_span_open_at(c.src, c.pos) {
			c.pos = raw_span_end(c.src, c.pos) or {
				return error('CXDEF_PARSE: unterminated `[#…#]` raw text in parameter default')
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
				return error('CXDEF_PARSE: unterminated string literal in parameter default')
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
		if depth == 0 {
			if def_is_space(b) {
				break
			}
			if b == `)` {
				break
			}
			if b == `:` && c.pos != start {
				// A `:` mid-scan would signal a next param token — but param
				// tokens are always whitespace-separated, and whitespace
				// already breaks above. A `:` reached here therefore belongs
				// to the value (e.g. `::T` glued type, or an atom). A LEADING
				// `:` (c.pos == start) is an atom-literal default value such
				// as `$capture=:both` (spec/std-lib/process.md §3.1) and must
				// be consumed as part of the default.
				break
			}
		}
		c.advance()
	}
	raw := c.src[start..c.pos].bytestr()
	return raw.trim_space()
}

// def_read_expr_until_close captures the verbatim source-text body
// from the current cursor position up to the top-level closing `]`
// of the `[?def …]` form. Returns the trimmed source-text slice.
// The cursor is advanced to point AT the `]` so the caller can
// consume the closer.
//
// Bracket / quote bookkeeping mirrors match_parser.v
// read_expr_until_keyword:
//   - `[` / `]` track depth.
//   - `'` / `"` open a quoted span that shields brackets + escapes.
//   - `#` line comments, `[; … ]` block comments, and `[#…#]` raw text are
//     OPAQUE spans (#289): quotes inside them must not open string spans and
//     their bytes never shift bracket depth (shared recognizers, lexical.v).
//   - top-level `]` breaks the scan (without consuming).
fn def_read_expr_until_close(mut c DefParseCursor) !string {
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
				return error('CXDEF_PARSE: unterminated `[; … ]` comment in body')
			}
			continue
		}
		if raw_span_open_at(c.src, c.pos) {
			c.pos = raw_span_end(c.src, c.pos) or {
				return error('CXDEF_PARSE: unterminated `[#…#]` raw text in body')
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
				return error('CXDEF_PARSE: unterminated string literal in body')
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
