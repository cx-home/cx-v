module cx


// ── program lexer ────────────────────────────────────────────────────────────────
//
// Tokenises CX source per spec/code.md §3 (lexical structure). The
// lexer is total: every well-formed UTF-8 input produces either a
// `[]ProgramToken` ending in `eof`, or a `LexError` with `code =
// "cx-err:CXER0100"` (PARSE_ERROR) and a `Position`.
//
// The lexer DOES NOT:
//   - parse expressions, patterns, or directives — the parser does
//     (forthcoming module vcx/code/parser.v).
//   - validate that a directive name in `[?<name>` is a registered
//     directive — the lexer emits `directive_name` tokens for any
//     identifier following `[?`; the parser checks membership against
//     `directive_names` and raises CXER0100 on miss.
//   - disambiguate `?` and `!` between postfix-on-call and standalone
//     uses — both fall to the parser per spec/code.md §6.3.
//
// Comments (`# ... EOL` line, `[# ... #]` block) are skipped silently.
// Whitespace is skipped except inside string literals.

import strings

// Lexer holds the source and cursor. Single-pass, no lookahead beyond
// one byte (handled by direct peek).
struct Lexer {
mut:
	src    []u8
	pos    int      // current byte offset (0-based)
	line   int = 1  // current line (1-based)
	col    int = 1  // current column (1-based)
}

// tokenize is the entry point. Returns the full token stream
// (terminated by an `eof` token) or a `LexError` describing the first
// lexical failure.
pub fn tokenize(source string) ![]ProgramToken {
	mut lex := Lexer{
		src: source.bytes()
	}
	// Skip BOM at start (EF BB BF) silently per spec §3.1.
	if lex.src.len >= 3 && lex.src[0] == 0xEF && lex.src[1] == 0xBB
	   && lex.src[2] == 0xBF {
		lex.pos = 3
	}
	mut toks := []ProgramToken{cap: 64}
	for {
		lex.skip_ws_and_comments()!
		if lex.pos >= lex.src.len {
			toks << ProgramToken{
				kind: .eof
				text: ''
				pos:  lex.snapshot_position()
			}
			return toks
		}
		toks << lex.next_token()!
	}
	return toks
}

// snapshot_position captures the cursor's current line/col/offset.
fn (l Lexer) snapshot_position() Position {
	return Position{
		offset: l.pos
		line:   l.line
		col:    l.col
	}
}

// advance bumps the cursor by one byte and tracks line/col.
fn (mut l Lexer) advance() {
	if l.pos >= l.src.len {
		return
	}
	c := l.src[l.pos]
	l.pos++
	if c == `\n` {
		l.line++
		l.col = 1
	} else {
		l.col++
	}
}

// peek returns the byte at `offset` ahead, or 0 if past EOF.
fn (l Lexer) peek(offset int) u8 {
	idx := l.pos + offset
	if idx >= l.src.len {
		return 0
	}
	return l.src[idx]
}

// skip_ws_and_comments consumes runs of whitespace, line comments
// (`# ... EOL`), and block comments (`[# ... #]`). Nested block
// comments are NOT supported (per spec/canonical.md §3); a `[#` inside
// a block-comment body is part of the comment body and does not start
// a new nesting level.
fn (mut l Lexer) skip_ws_and_comments() ! {
	for l.pos < l.src.len {
		c := l.src[l.pos]
		if is_ws(c) {
			// shared cxparse whitespace predicate (cx/lexical.v) — byte-identical
			// to the former `` ` ``/`\t`/`\r`/`\n` match arm.
			l.advance()
			continue
		}
		match c {
			`#` {
				// Line comment to end of line.
				for l.pos < l.src.len && l.src[l.pos] != `\n` {
					l.advance()
				}
			}
			`[` {
				next := l.peek(1)
				// `[; … ]` block comment — the single CX block-comment form.
				// `;` is unambiguous: `[- $a $b]` is the subtraction operator
				// (never a comment), so no dash-counting is needed. The body
				// runs to the MATCHING `]`, balancing nested `[`…`]` — so a
				// comment body may contain brackets (`[; A [bus] owns … ]`).
				// This mirrors the data reader's read_until_close (parser.v),
				// keeping `[; … ]` identical under both readings (data ⊂ program);
				// the prior first-`]` scan closed early on any bracketed prose.
				//
				// `[#…#]` is NOT eaten here. Per code.md §1.3 + lexicon
				// [L2]/[L3] it is RAW TEXT (not a comment); next_token captures
				// it as a `data_span` token (DATA↔PROGRAM seam). A prior version
				// wrongly skipped it as a block comment and DISCARDED the raw
				// text, so `cx file.cx` (eval) lost it vs the data reading.
				if next == `;` {
					start := l.snapshot_position()
					l.advance() // consume '['
					l.advance() // consume ';'
					mut closed := false
					mut depth := 0
					for l.pos < l.src.len {
						bc := l.src[l.pos]
						if bc == `[` {
							depth++
						} else if bc == `]` {
							if depth == 0 {
								l.advance()
								closed = true
								break
							}
							depth--
						}
						l.advance()
					}
					if !closed {
						return LexError{
							message: 'unterminated block comment'
							pos:     start
						}
					}
				} else {
					return
				}
			}
			else {
				return
			}
		}
	}
}

// next_token reads exactly one non-whitespace, non-comment token. The
// caller has already advanced past leading whitespace and comments.
fn (mut l Lexer) next_token() !ProgramToken {
	start := l.snapshot_position()
	c := l.src[l.pos]
	match c {
		`[` {
			n1 := l.peek(1)
			if n1 == `?` {
				l.advance()
				l.advance()
				return l.read_directive_name(start)
			}
			// DATA↔PROGRAM seam: `[#…#]` raw text and `[!…]` declarations are
			// pure-DATA constructs carried verbatim as one `data_span` token; the
			// parser delegates to cx.parse_data_node. `[--…--]` comments were
			// already consumed by skip_ws_and_comments; `[-` (single dash) is the
			// subtraction head and falls through to `lbrack` + `minus`.
			if n1 == `#` {
				return l.read_raw_span(start)
			}
			// `[!NAME` is a data declaration span; `[!=` is the fused
			// not-equal operator form (`[!= a b]`, [125f] OperatorForm) —
			// disambiguate on the byte after `!` (declarations always open
			// with a name character, never `=`).
			if n1 == `!` && l.peek(2) != `=` {
				return l.read_decl_span(start)
			}
			l.advance()
			return ProgramToken{
				kind: .lbrack
				text: '['
				pos:  start
			}
		}
		`&` {
			// DATA↔PROGRAM seam: an entity / character reference `&…;` /
			// `&#…;` is a pure-DATA construct (the data reader preserves entity
			// refs and resolves char refs). Captured as a `data_span`.
			return l.read_entity_span(start)
		}
		`]` {
			l.advance()
			return ProgramToken{ kind: .rbrack, text: ']', pos: start }
		}
		`(` {
			l.advance()
			return ProgramToken{ kind: .lparen, text: '(', pos: start }
		}
		`)` {
			l.advance()
			return ProgramToken{ kind: .rparen, text: ')', pos: start }
		}
		`{` {
			l.advance()
			return ProgramToken{ kind: .lbrace, text: '{', pos: start }
		}
		`}` {
			l.advance()
			return ProgramToken{ kind: .rbrace, text: '}', pos: start }
		}
		`,` {
			l.advance()
			return ProgramToken{ kind: .comma, text: ',', pos: start }
		}
		`$` {
			l.advance()
			return ProgramToken{ kind: .dollar, text: '$', pos: start }
		}
		`@` {
			l.advance()
			if l.pos < l.src.len && l.src[l.pos] == `!` {
				l.advance()
				return ProgramToken{ kind: .at_bang, text: '@!', pos: start }
			}
			return ProgramToken{ kind: .at, text: '@', pos: start }
		}
		`:` {
			// `::` is the CXPath axis separator. Emit
			// it as a single double_colon token so the parser doesn't
			// have to disambiguate at every `:` site (labeled slots,
			// atom literals, map keys). Atom literals (`:NAME`) are
			// `:` then `ident` — they never source two consecutive
			// colons, so this lookahead doesn't disturb them.
			if l.peek(1) == `:` {
				l.advance()
				l.advance()
				return ProgramToken{ kind: .double_colon, text: '::', pos: start }
			}
			l.advance()
			return ProgramToken{ kind: .colon, text: ':', pos: start }
		}
		`/` {
			// `//` is the CXPath descendant-or-self axis token.
			// Emit as a single double_slash token so the parser doesn't
			// have to disambiguate at every '/' site (binding paths,
			// arithmetic-element-head `[/ a b]`, future absolute paths).
			if l.peek(1) == `/` {
				l.advance()
				l.advance()
				return ProgramToken{ kind: .double_slash, text: '//', pos: start }
			}
			l.advance()
			return ProgramToken{ kind: .slash, text: '/', pos: start }
		}
		`.` {
			// `.` may be a path step (`.foo`) or the leading char of a
			// number (`.5`). Disambiguate by next byte.
			if l.pos + 1 < l.src.len && is_digit(l.src[l.pos + 1]) {
				return l.read_number(start)
			}
			l.advance()
			return ProgramToken{ kind: .dot, text: '.', pos: start }
		}
		`*` {
			l.advance()
			if l.pos < l.src.len && l.src[l.pos] == `*` {
				l.advance()
				return ProgramToken{ kind: .double_star, text: '**', pos: start }
			}
			return ProgramToken{ kind: .star, text: '*', pos: start }
		}
		`|` {
			l.advance()
			return ProgramToken{ kind: .pipe, text: '|', pos: start }
		}
		`=` {
			l.advance()
			return ProgramToken{ kind: .eq, text: '=', pos: start }
		}
		`!` {
			l.advance()
			if l.pos < l.src.len && l.src[l.pos] == `=` {
				l.advance()
				return ProgramToken{ kind: .neq, text: '!=', pos: start }
			}
			return ProgramToken{ kind: .bang, text: '!', pos: start }
		}
		`<` {
			l.advance()
			if l.pos < l.src.len && l.src[l.pos] == `=` {
				l.advance()
				return ProgramToken{ kind: .le, text: '<=', pos: start }
			}
			return ProgramToken{ kind: .lt, text: '<', pos: start }
		}
		`>` {
			l.advance()
			if l.pos < l.src.len && l.src[l.pos] == `=` {
				l.advance()
				return ProgramToken{ kind: .ge, text: '>=', pos: start }
			}
			return ProgramToken{ kind: .gt, text: '>', pos: start }
		}
		`?` {
			l.advance()
			return ProgramToken{ kind: .qmark, text: '?', pos: start }
		}
		`~` {
			l.advance()
			return ProgramToken{ kind: .tilde, text: '~', pos: start }
		}
		`'`, `"` {
			// Peek ahead: if the next two bytes are the same quote char,
			// enter triple-quote mode ('''…''' or """…"""). Mirrors the
			// data parser's read_triple_quoted_str_with_quote logic.
			if l.peek(1) == c && l.peek(2) == c {
				return l.read_triple_string(start, c, false)
			}
			return l.read_string(start, c)
		}
		`-` {
			// '-DIGIT' parses as a negative number; bare '-' is the
			// minus token (legal as the head of an element-style
			// arithmetic form like `[- $a $b]` per spec/code.md §8
			// worked examples).
			if l.pos + 1 < l.src.len && is_digit(l.src[l.pos + 1]) {
				return l.read_number(start)
			}
			l.advance()
			return ProgramToken{ kind: .minus, text: '-', pos: start }
		}
		`+` {
			l.advance()
			return ProgramToken{ kind: .plus, text: '+', pos: start }
		}
		else {
			if is_digit(c) {
				// lexicon §9 [L23]/[L24]: a `YYYY-MM-DD` date or
				// `YYYY-MM-DDThh:mm:ss[.fff][Z|±hh:mm]` datetime is ONE
				// token (not `2024 -1 -15`). Check the temporal pattern
				// before falling through to plain number lexing.
				if n := l.match_temporal_len() {
					return l.emit_temporal(start, n)
				}
				return l.read_number(start)
			}
			// `r'''…'''` / `r"""…"""` — raw (no-dedent) triple-quoted string
			// (#93). The `r` prefix is recognised ONLY immediately before a
			// triple quote; a bare `r` (or `r` before a single quote / name
			// char) stays an ordinary identifier.
			if c == `r` {
				q := l.peek(1)
				if (q == `'` || q == `"`) && l.peek(2) == q && l.peek(3) == q {
					l.advance() // consume the `r`; cursor now at the opening triple
					return l.read_triple_string(start, q, true)
				}
			}
			if is_name_start(c) {
				return l.read_identifier_or_duration(start)
			}
			return LexError{
				message: "unexpected character ${c.ascii_str()} (byte 0x${c:02x})"
				pos:     start
			}
		}
	}
}

// read_directive_name handles the `[?<name>` opener. The cursor is
// positioned at the byte after `[?`. The name MUST be a valid
// identifier; emptiness or invalid leading byte is an error.
fn (mut l Lexer) read_directive_name(start Position) !ProgramToken {
	name_start := l.pos
	if l.pos >= l.src.len || !is_name_start(l.src[l.pos]) {
		return LexError{
			message: "expected directive name after '[?'"
			pos:     start
		}
	}
	for l.pos < l.src.len && is_ident_part(l.src[l.pos]) {
		l.advance()
	}
	name := l.src[name_start..l.pos].bytestr()
	return ProgramToken{
		kind: .directive_name
		text: name
		pos:  start
	}
}

// read_raw_span captures a `[#…#]` raw-text span verbatim (delimiters
// included) and emits a `data_span` token. The cursor is at the opening `[`.
// Closes at the first `#]`; an unterminated span is a LexError. Mirrors the
// data parser's lex_raw_span scan so the two readings agree.
fn (mut l Lexer) read_raw_span(start Position) !ProgramToken {
	l.advance() // consume '['
	l.advance() // consume '#'
	mut closed := false
	for l.pos < l.src.len {
		if l.src[l.pos] == `#` && l.peek(1) == `]` {
			l.advance() // '#'
			l.advance() // ']'
			closed = true
			break
		}
		l.advance()
	}
	if !closed {
		return LexError{
			message: 'unterminated raw text — expected `#]`'
			pos:     start
		}
	}
	return ProgramToken{
		kind: .data_span
		text: l.src[start.offset..l.pos].bytestr()
		pos:  start
	}
}

// read_decl_span captures a `[!…]` declaration span verbatim (DTD
// declarations + `[!DOCTYPE …]` incl. an internal subset). The cursor is at
// the opening `[`. The span ends at the matching `]` tracked by bracket
// depth; quoted literals are skipped so a `]` inside a `"…"` / `'…'` literal
// (e.g. `[!ENTITY x "a]b"]`) does not close the span early. The parser
// delegates the captured text to cx.parse_data_node for full validation.
fn (mut l Lexer) read_decl_span(start Position) !ProgramToken {
	mut depth := 0
	for l.pos < l.src.len {
		c := l.src[l.pos]
		if c == `'` || c == `"` {
			// Skip a quoted literal whole (brackets inside don't affect depth).
			l.advance() // opening quote
			for l.pos < l.src.len && l.src[l.pos] != c {
				l.advance()
			}
			if l.pos < l.src.len {
				l.advance() // closing quote
			}
			continue
		}
		if c == `[` {
			depth++
		} else if c == `]` {
			depth--
			if depth == 0 {
				l.advance() // matching ']'
				return ProgramToken{
					kind: .data_span
					text: l.src[start.offset..l.pos].bytestr()
					pos:  start
				}
			}
		}
		l.advance()
	}
	return LexError{
		message: 'unterminated declaration — expected `]`'
		pos:     start
	}
}

// read_entity_span captures an entity / character reference `&…;` / `&#…;`
// verbatim and emits a `data_span` token. The cursor is at the `&`. Scans to
// the terminating `;`; whitespace, a structural bracket, or EOF before `;`
// is a LexError (a bare `&` was a hard error before this seam closure too).
// cx.parse_data_node performs the full name / codepoint validation.
fn (mut l Lexer) read_entity_span(start Position) !ProgramToken {
	l.advance() // consume '&'
	for l.pos < l.src.len {
		c := l.src[l.pos]
		if c == `;` {
			l.advance() // ';'
			return ProgramToken{
				kind: .data_span
				text: l.src[start.offset..l.pos].bytestr()
				pos:  start
			}
		}
		if is_ws(c) || c == `[` || c == `]` {
			break
		}
		l.advance()
	}
	return LexError{
		message: 'unterminated entity reference — expected `;`'
		pos:     start
	}
}

// read_identifier_or_duration consumes a name. If the name parses as
// a CX code DURATION literal (e.g. `100ms`, `1h`), it is emitted as
// `duration_lit`; otherwise as `ident` or `bool_lit`.
fn (mut l Lexer) read_identifier_or_duration(start Position) !ProgramToken {
	name_start := l.pos
	for l.pos < l.src.len && is_ident_part(l.src[l.pos]) {
		l.advance()
	}
	text := l.src[name_start..l.pos].bytestr()
	match text {
		'true', 'false' {
			return ProgramToken{ kind: .bool_lit, text: text, pos: start }
		}
		else {
			return ProgramToken{ kind: .ident, text: text, pos: start }
		}
	}
	return ProgramToken{ kind: .ident, text: text, pos: start } // unreachable
}

// match_temporal_len reports the byte length of a date or datetime token
// starting at the cursor, or `none` if the bytes there are not a complete
// temporal literal per lexicon §9 [L23]/[L24]. Pure lookahead — the cursor
// is unchanged. The matched token MUST be followed by a token boundary (not
// a name-part or digit); a trailing name char means this is some other
// bareword-ish run and we decline so plain number lexing applies (matching
// the data parser, which would read the whole run then fail date typing).
fn (l Lexer) match_temporal_len() ?int {
	// The strict [L23]/[L24] scan + the glued-name-char guard live in the one
	// shared recognizer temporal_len (cx/lexical.v). Pure lookahead — the
	// cursor is unchanged; the caller advances on a match.
	return temporal_len(l.src, l.pos)
}

// emit_temporal consumes `n` bytes from the cursor and emits a date_lit
// (10 bytes) or datetime_lit (longer, contains a 'T') token. The text is
// the verbatim source slice, classified downstream into a date/datetime
// scalar.
fn (mut l Lexer) emit_temporal(start Position, n int) ProgramToken {
	text := l.src[l.pos..l.pos + n].bytestr()
	for _ in 0 .. n {
		l.advance()
	}
	kind := if text.len > 10 { ProgramTokenKind.datetime_lit } else { ProgramTokenKind.date_lit }
	return ProgramToken{
		kind: kind
		text: text
		pos:  start
	}
}

// read_number consumes a numeric literal. Supports:
//   - integers: 0 | -?[1-9][0-9]*
//   - floats:   -?[0-9]*'.'[0-9]+([eE][+-]?[0-9]+)?
//   - durations: <integer><suffix> where suffix ∈ {us, ms, s, m, h}
// Returns `number_lit` for plain numbers, `duration_lit` when a
// duration suffix is present.
fn (mut l Lexer) read_number(start Position) !ProgramToken {
	num_start := l.pos
	if l.src[l.pos] == `-` {
		l.advance()
	}
	// [L20a] HexInt ::= '0x' HexDigit ('_'? HexDigit)* — checked before Integer.
	// Converges to the data parser's [L20] grammar (cxparse Phase 4.2): the
	// program lexer previously rejected `0xFF` (routing `xFF` into the duration
	// suffix path). `_` separators between hex digits are admitted; the
	// conversion (parse_number_literal) strips them.
	if l.pos + 1 < l.src.len && l.src[l.pos] == `0`
	   && (l.src[l.pos + 1] == `x` || l.src[l.pos + 1] == `X`) {
		l.advance() // '0'
		l.advance() // 'x'/'X'
		mut saw_hex := false
		for l.pos < l.src.len {
			c := l.src[l.pos]
			if hex_digit_val(c) >= 0 {
				l.advance()
				saw_hex = true
				continue
			}
			if c == `_` && l.pos + 1 < l.src.len && hex_digit_val(l.src[l.pos + 1]) >= 0 {
				l.advance() // separator between hex digits
				continue
			}
			break
		}
		if !saw_hex {
			return LexError{
				message: 'malformed hex integer literal'
				pos:     start
			}
		}
		return ProgramToken{
			kind: .number_lit
			text: l.src[num_start..l.pos].bytestr()
			pos:  start
		}
	}
	mut saw_digit := false
	// integer part: [0-9] ('_'? [0-9])* — `_` only between digits ([L20c]; the
	// leading-zero rule is enforced at conversion, mirroring the data parser).
	for l.pos < l.src.len {
		c := l.src[l.pos]
		if is_digit(c) {
			l.advance()
			saw_digit = true
			continue
		}
		if c == `_` && l.pos + 1 < l.src.len && is_digit(l.src[l.pos + 1]) {
			l.advance() // separator between digits
			continue
		}
		break
	}
	// fractional part: '.' [0-9] ('_'? [0-9])*   ([L20b])
	if l.pos + 1 < l.src.len && l.src[l.pos] == `.` && is_digit(l.src[l.pos + 1]) {
		l.advance() // consume '.'
		for l.pos < l.src.len {
			c := l.src[l.pos]
			if is_digit(c) {
				l.advance()
				continue
			}
			if c == `_` && l.pos + 1 < l.src.len && is_digit(l.src[l.pos + 1]) {
				l.advance()
				continue
			}
			break
		}
		saw_digit = true
	}
	// exponent: [eE] [+-]? [0-9] ('_'? [0-9])*   ([L20b])
	if l.pos < l.src.len && (l.src[l.pos] == `e` || l.src[l.pos] == `E`) {
		l.advance()
		if l.pos < l.src.len && (l.src[l.pos] == `+` || l.src[l.pos] == `-`) {
			l.advance()
		}
		mut exp_digits := false
		for l.pos < l.src.len {
			c := l.src[l.pos]
			if is_digit(c) {
				l.advance()
				exp_digits = true
				continue
			}
			if c == `_` && l.pos + 1 < l.src.len && is_digit(l.src[l.pos + 1]) {
				l.advance()
				continue
			}
			break
		}
		if !exp_digits {
			return LexError{
				message: 'malformed exponent in number literal'
				pos:     start
			}
		}
	}
	if !saw_digit {
		return LexError{
			message: 'malformed number literal'
			pos:     start
		}
	}
	num_text := l.src[num_start..l.pos].bytestr()
	// Temporal-span suffix (duration [L25] / period [L26]). Consume the whole
	// alphanumeric run from the number start and classify with the SHARED
	// recognizer so the program and data readings agree — multi-term `1h30m`,
	// longest-unit-match (`ms`/`mo` before `m`), period units `mo`/`y`.
	if l.pos < l.src.len && is_name_start(l.src[l.pos]) {
		for l.pos < l.src.len {
			c := l.src[l.pos]
			if is_digit(c) || (c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`) {
				l.advance()
				continue
			}
			break
		}
		span_text := l.src[num_start..l.pos].bytestr()
		kind := temporal_span_kind(span_text) or {
			return LexError{
				message: "invalid temporal literal '${span_text}' (duration units ns|us|ms|s|m|h|d|w; period units mo|y)"
				pos:     start
			}
		}
		return ProgramToken{
			kind: if kind == .period_type { ProgramTokenKind.period_lit } else { ProgramTokenKind.duration_lit }
			text: span_text
			pos:  start
		}
	}
	return ProgramToken{
		kind: .number_lit
		text: num_text
		pos:  start
	}
}

// read_string consumes a quoted string literal. Quote char is `'` or
// `"` (passed as `quote`). The decoded escapes are `\\`, `\'`, `\"`,
// `\n`, `\r`, `\t`, `\uXXXX`, `\UXXXXXXXX` — the unified set shared with
// the data parser (lexicon.ebnf §5 [L32]). An unknown backslash-sequence
// is kept LITERALLY (lenient pass-through): the backslash is preserved and
// the following byte falls through to normal processing, so regex shorthands
// like `\d` / `\w` / `\s` survive verbatim. Unterminated strings produce a
// LexError pointing at the opening quote.
fn (mut l Lexer) read_string(start Position, quote u8) !ProgramToken {
	l.advance() // consume opening quote
	mut buf := strings.new_builder(16)
	for l.pos < l.src.len {
		c := l.src[l.pos]
		if c == quote {
			l.advance()
			return ProgramToken{
				kind: .string_lit
				text: buf.str()
				pos:  start
			}
		}
		if c == `\\` {
			// l.pos sits on the backslash. The escape rule + lenient
			// pass-through live in the one shared decoder decode_escape
			// (cx/lexical.v); here we only emit into the builder and advance.
			// A trailing `\` at EOF emits `\` and leaves l.pos == src.len, so
			// the loop exits to the unterminated-string error below — same as
			// the prior explicit break.
			d := decode_escape(l.src, l.pos)
			if d.invalid {
				// @CHOICE-4 (converged with the data engine): a `\u`/`\U` escape
				// that is not a Unicode scalar value (surrogate / > 10FFFF) is a
				// lexical error, not a lenient pass-through.
				return LexError{
					message: 'invalid Unicode escape — surrogate or above U+10FFFF (cx-err:CXERLEX-CODEPOINT)'
					pos:     start
				}
			}
			if d.is_rune {
				buf.write_string(rune_to_utf8(d.cp))
			} else {
				buf.write_u8(u8(d.cp))
			}
			for _ in 0 .. d.consumed {
				l.advance()
			}
			continue
		}
		buf.write_u8(c)
		l.advance()
	}
	return LexError{
		message: 'unterminated string literal'
		pos:     start
	}
}

// read_triple_string consumes a triple-quoted string literal ('''…''' or
// """…"""). The cursor is positioned at the first quote of the opening
// triple. Implements the same lookahead-on-close rule as the data parser:
// when a triple-delimiter is seen, peek one byte further — if that byte
// is also the delimiter, treat the first delimiter as content and advance
// one byte; otherwise close. This makes content containing trailing
// delimiters expressible without escapes: `'''hello''''` → `hello'`.
//
// Triple-quoted strings are verbatim w.r.t. ESCAPES (no escape processing),
// but the common-indent rule (ast.md §Text / grammar [10b]) DOES apply: on
// close, the raw content is passed through strip_common_indent — strip one
// leading + one trailing blank line, then the common leading whitespace of
// the remaining lines. This is the SAME single implementation the data parser
// uses, so both parsers dedent identically (cxparse D4).
fn (mut l Lexer) read_triple_string(start Position, quote u8, raw bool) !ProgramToken {
	// l.pos is at the first opening quote. The scan + lookahead-on-close +
	// dedent live in the one shared scan_triple_quoted (cx/lexical.v); here
	// we only replay the cursor (advancing per byte keeps line/col stable).
	// `raw` (the `r'''…'''` prefix, #93) skips the common-indent dedent.
	value, n := scan_triple_quoted_opt(l.src, l.pos, quote, raw) or {
		return LexError{
			message: 'unterminated triple-quoted string literal'
			pos:     start
		}
	}
	for _ in 0 .. n {
		l.advance()
	}
	return ProgramToken{
		kind: .string_lit
		text: value
		pos:  start
	}
}

// is_digit / is_name_start / is_name_part now live in cx/lexical.v (the shared
// cxparse lexical primitives). The program lexer's identifier continuation is
// is_ident_part (ASCII `[A-Za-z0-9_-]`, excluding `.`/`:` which it tokenizes
// separately) — see the name-char fork note in cx/lexical.v.
