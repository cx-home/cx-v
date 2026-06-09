module cx

// token_cursor.v — the on-demand token cursor for the DATA parser (Phase 2 of the
// cxparse unification, spec/02-inprogress/cxparse_unification_PLAN.md).
//
// It presents a tokenize-then-parse VIEW over the existing byte scanner without
// materializing a `[]Token`: the byte position (`p.pos`/`line`/`col`) stays the
// source of truth, and each cursor call runs at the current position. This is the
// "adapter-first" step — readers migrate onto the cursor call-by-call in later
// steps, then the backing store flips to a pre-materialized stream (S10) once
// every reader goes through it.
//
// ── Why parser-DRIVEN, not a context-free `next_token` ──
// Data tokenization is context-sensitive: a bareword run is a NAME in head
// position but a VALUE_RUN in body position; `:` folds into names; inter-token
// whitespace is significant. So there is no single context-free classifier that
// decides name-vs-value. Instead `tok_peek_kind` classifies only the STRUCTURAL
// shape from the leading bytes (bracket / quote / sigil / "lexeme run"), and the
// parser — which knows its grammar slot — calls `tok_name` or `tok_value` to
// actually consume the run. Boundaries come from the shared `lex_*` readers, so
// they are byte-identical to the scannerless path (mandate N2). The three pinned
// forks (number grammar, name-char `.`/`:`, datetime strict/loose) are untouched:
// the cursor only finds boundaries; the parser's classifiers run on the bytes.

// TokSnapshot captures the byte-cursor state so a caller can peek with a `lex_*`
// reader (which advances `p.pos`) and then rewind, leaving the parser untouched.
// It does NOT snapshot `prev_tok_end`: a peek-then-rewind must not have consumed a
// token, so adjacency state is unaffected. Backtracking that crosses a real
// consume should use the parser's existing (pos,line,col[,prev_tok_end]) save —
// the cursor's save/restore is for lookahead only.
struct TokSnapshot {
	pos  int
	line int
	col  int
}

@[inline]
fn (p &Parser) tok_save() TokSnapshot {
	return TokSnapshot{
		pos:  p.pos
		line: p.line
		col:  p.col
	}
}

@[inline]
fn (mut p Parser) tok_restore(s TokSnapshot) {
	p.pos = s.pos
	p.line = s.line
	p.col = s.col
}

// tok_peek_kind classifies the STRUCTURAL kind of the token at the current
// position WITHOUT consuming and WITHOUT allocating — it inspects only the
// leading byte(s). It assumes whitespace and line comments have already been
// skipped by the caller (the parse loops do this, preserving comments as nodes);
// a `#` reaching here is therefore treated as ordinary lexeme content.
//
// Anything that is not a bracket / quote / single-char sigil is reported as
// `.value_run`, the catch-all "lexeme run" — the parser then calls `tok_name`
// (head position) or `tok_value` (body position) to consume it. Quote openers are
// split into `.triple_span` (`'''` / `"""`) vs `.quote_run` (single `'` / `"`) so
// the dispatch matches the parser's existing two-way quote branch.
fn (p &Parser) tok_peek_kind() CxTokenKind {
	if p.pos >= p.src.len {
		return .eof
	}
	b := p.src[p.pos]
	match b {
		`]` { return .rbrack }
		`,` { return .comma }
		`=` { return .eq }
		`&` { return .amp }
		`*` { return .star }
		`#` { return .hash }
		`(` { return .lparen }
		`)` { return .rparen }
		`{` { return .lbrace }
		`}` { return .rbrace }
		`[` {
			n := if p.pos + 1 < p.src.len { p.src[p.pos + 1] } else { u8(0) }
			match n {
				`?` { return .ldirective }
				`#` { return .raw_span }
				`|` { return .block_span }
				else { return .lbrack }
			}
		}
		`'`, `"` {
			if p.pos + 2 < p.src.len && p.src[p.pos + 1] == b && p.src[p.pos + 2] == b {
				return .triple_span
			}
			return .quote_run
		}
		`:` {
			if p.pos + 1 < p.src.len && p.src[p.pos + 1] == `:` {
				return .double_colon
			}
			return .colon
		}
		else {
			return .value_run
		}
	}
}

// tok_adjacent_to_prev reports whether the token at the current position is
// byte-adjacent to the previously consumed token — i.e. no whitespace (or
// comment) was skipped between them. Call it AFTER positioning on the next token
// (post ws/comment skip) and BEFORE consuming it: `had_ws == !tok_adjacent_to_prev()`.
// Mirrors the program parser's `cur_adjacent_to_prev` (code/parser.v:860), which
// reads it off materialized token offsets; here it reads off the live cursor.
// Returns false before the first consume (prev_tok_end == 0, pos > 0 after any
// leading skip) and at offset 0.
@[inline]
fn (p &Parser) tok_adjacent_to_prev() bool {
	return p.pos == p.prev_tok_end
}

// is_bracket_open reports whether the kind is one of the `[`-openers — a child
// element / collection (`.lbrack`), a directive (`.ldirective`), raw text
// (`.raw_span`), or a pipe block (`.block_span`). tok_peek_kind returns one of
// these iff the leading byte is `[`, so this is exactly the former `b == \`[\``
// test, surfaced as a kind predicate for the node-introducer dispatch.
@[inline]
fn (k CxTokenKind) is_bracket_open() bool {
	return k == .lbrack || k == .ldirective || k == .raw_span || k == .block_span
}

// ── Consume helpers ─────────────────────────────────────────────────────────
// Each consumes one token via the shared `lex_*` reader, updates `prev_tok_end`
// to the post-consume byte offset (so the NEXT `tok_adjacent_to_prev` is exact),
// and returns the token. Range-carrying tokens leave `.text` empty; the caller
// reads `src[pos.offset..end]` (zero-alloc, intern on a name-pool hit).

// tok_name consumes an `is_name_char` run (head/attribute-name position). `none`
// on an empty run. The glued-`::` type-label stop is reproduced by `lex_name`.
fn (mut p Parser) tok_name() ?Token {
	t := p.lex_name()?
	p.prev_tok_end = p.pos
	return t
}

// tok_value consumes a whitespace-/`]`-/`,`-delimited scalar run (body position),
// quote- and bracket-aware. `none` on an empty run.
fn (mut p Parser) tok_value() ?Token {
	t := p.lex_value_run()?
	p.prev_tok_end = p.pos
	return t
}

// tok_raw_span consumes a `[#…#]` raw-text span. The cursor must be positioned at
// the opening `[`; the returned token's range covers the verbatim content (the
// bytes between `[#` and `#]`). `prev_tok_end` advances past the closing `]`.
fn (mut p Parser) tok_raw_span() !Token {
	p.advance() // consume '['
	t := p.lex_raw_span()!
	p.prev_tok_end = p.pos
	return t
}

// tok_sigil consumes a single-byte structural sigil at the current position and
// returns it as a Token carrying the canonical sigil string. The caller is
// expected to have classified it via `tok_peek_kind`; this only advances and
// records the boundary. Multi-byte openers (`[?`, `[#`, `::`) are consumed by
// their dedicated helpers / the parser's existing readers, not here.
fn (mut p Parser) tok_sigil(kind CxTokenKind) Token {
	start := p.pos
	start_line := p.line
	start_col := p.col
	b := p.peek()
	p.advance()
	p.prev_tok_end = p.pos
	return Token{
		kind: kind
		text: [b].bytestr()
		pos:  TokenPos{
			offset: start
			line:   start_line
			col:    start_col
		}
		end:  p.pos
	}
}
