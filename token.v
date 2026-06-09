module cx

// token.v — the cx-native token model for the unified tokenize-then-parse engine.
//
// Phase 2 of the cxparse unification (spec/02-inprogress/cxparse_unification_PLAN.md):
// the DATA parser (parser.v), historically SCANNERLESS, becomes token-driven over
// this type. The PROGRAM side keeps `code.Token` untouched as the differential
// oracle until Phase 4 — there the module move re-points `code/lexer.v` onto this
// type, consummating the single tokenizer.
//
// The token lives in `cx` (the LOWER module) because `cx` must not import `code`
// (the dependency graph is one-way `code -> cx`, and N5 keeps `cx` standalone). A
// shared token defined in `code` would force `cx` to import `code` — a cycle.
//
// ── Zero-alloc discipline (mandate N3) ──
// The data parser's hot path never allocates a string per token today
// (intern_name_src / try_autotype_bytes read `src[start..end]` in place). To
// preserve that, the lexeme/span kinds (name, value_run, value_run_attr, and the
// *_span coarse kinds) carry a byte RANGE `[pos.offset, end)` into the parser's
// `src` and leave `.text` EMPTY. Classification reads `src[pos.offset..end]`
// directly. Only structural sigils carry a (small, interned-constant) `.text`.

// TokenPos is a token's start position: byte offset + 1-based line/col. It mirrors
// the data parser's `pos`/`line`/`col` cursor state (parser.v) so error positions
// stay byte-stable when readers move from byte-scanning to token-driving.
pub struct TokenPos {
pub:
	offset int // 0-based byte offset of the token start into `src`
	line   int // 1-based
	col    int // 1-based
}

// CxTokenKind enumerates the data-mode token kinds. The three Phase-1 forks
// (number grammar, name-char `.`/`:`, datetime strict/loose) are NOT resolved at
// this layer: the tokenizer only finds BOUNDARIES; the parser's existing
// classifiers (try_autotype, is_name_char, loose is_datetime) run unchanged on the
// byte range. Hence there is no `number`/`date`/`atom`/`bool` kind here — those all
// arrive as a coarse `value_run` the parser classifies. Convergence is Phase 3.
//
// Data-only structural surfaces (TableBlock, logfmt, XML decl, Markdown shorthands)
// get their coarse kinds added when those readers migrate (cutover step S4).
pub enum CxTokenKind {
	// ── structural sigils (carry the canonical sigil string in `.text`) ──
	lbrack       // [
	rbrack       // ]
	ldirective   // [?
	lparen       // (
	rparen       // )
	lbrace       // {
	rbrace       // }
	comma        // ,
	amp          // &
	star         // *  element-meta MERGE sigil (`*name`); in body position `*` is
	             //    ordinary lexeme content (falls to the parser's run branch)
	hash         // #  element-meta ID sigil (`#name`) / line-comment introducer
	             //    (`# …`); in body position line comments are stripped before
	             //    dispatch, so `#` here is element-meta only
	colon        // :
	double_colon // ::
	eq           // =
	// ── lexeme runs (carry a byte range; `.text` empty) ──
	name           // is_name_char run (folds `.` and `:`); element / attribute names
	value_run      // ws / `]` / `,`-delimited scalar/atom/number/bareword run (body position)
	value_run_attr // same, in attribute-value position (absorbs `[?=…]` interpolation)
	// ── coarse context-sensitive spans (carry verbatim byte range; parser expands) ──
	quote_run   // '…' or "…"  single-line quoted string
	triple_span // '''…''' or """…"""  triple-quoted string
	raw_span    // [#…#]  raw text
	block_span  // [|…|]  block content
	// ── end of input ──
	eof
}

// Token is one lexical unit produced by the data tokenizer.
//
// For lexeme/span kinds the bytes live at `src[pos.offset..end]` and `text` is
// empty (zero-alloc). For structural sigils `text` is the canonical sigil string
// and `end == pos.offset + text.len`. `eof` has `pos.offset == end == src.len`.
pub struct Token {
pub:
	kind CxTokenKind
	text string   // canonical sigil string, or '' for range-carrying kinds
	pos  TokenPos // start position
	end  int      // exclusive end byte offset into `src`
}

// span_bytes returns the token's source slice for a range-carrying token. The
// caller passes the parser's `src`; the result is a view into it (no copy), so the
// zero-alloc classifiers (try_autotype_bytes) can consume it directly.
@[inline]
pub fn (t Token) span_bytes(src []u8) []u8 {
	return src[t.pos.offset..t.end]
}
