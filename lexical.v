module cx

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  Shared lexical primitives — the one home for the `cxparse` unification    ║
// ╚══════════════════════════════════════════════════════════════════════════╝
//
// These are the byte-level recognizers that BOTH parsers used to carry their
// own copy of (the data scannerless parser `cx/parser.v` and the program lexer
// `code/lexer.v`), kept in lockstep only by `parser_parity_test.v`. Per the
// cxparse unification plan (`spec/02-inprogress/cxparse_unification_PLAN.md`)
// Phase 1, the duplication moves HERE: `cx` is the lower module
// (`code → cx`; `cx` never imports `code`), so the program lexer delegates up.
// (D4 already landed the first shared primitive, `strip_common_indent`.)
//
// They are `pub` so `code/` can call them as `cx.<fn>`; within `cx` they are
// called unqualified. `@[inline]` keeps the per-byte hot path free (V emits a
// single C translation unit, so cross-module calls inline under -prod anyway —
// the attribute documents intent and guards non-prod builds).
//
// Spec authority: `spec/core/lexicon.ebnf` §2 (names), §3 ([L20d] HexDigit),
// §5 (escapes). Behavior here is BYTE-STABLE with the pre-unification copies
// (mandate N2); this file only removes the duplication, it changes nothing.

// rune_to_utf8 encodes a Unicode scalar value as its UTF-8 byte sequence.
// Used by both the data and program `\uXXXX`/`\UXXXXXXXX` escape decoders.
@[inline]
pub fn rune_to_utf8(c u32) string {
	if c < 0x80 {
		return [u8(c)].bytestr()
	} else if c < 0x800 {
		return [u8(0xC0 | (c >> 6)), u8(0x80 | (c & 0x3F))].bytestr()
	} else if c < 0x10000 {
		return [u8(0xE0 | (c >> 12)), u8(0x80 | ((c >> 6) & 0x3F)), u8(0x80 | (c & 0x3F))].bytestr()
	} else {
		return [u8(0xF0 | (c >> 18)), u8(0x80 | ((c >> 12) & 0x3F)), u8(0x80 | ((c >> 6) & 0x3F)),
			u8(0x80 | (c & 0x3F))].bytestr()
	}
}

// hex_digit_val returns the value (0..15) of an ASCII hex digit, or -1 if `b`
// is not a hex digit. (`lexicon.ebnf` [L20d] HexDigit.)
@[inline]
pub fn hex_digit_val(b u8) int {
	if b >= `0` && b <= `9` {
		return int(b - `0`)
	}
	if b >= `a` && b <= `f` {
		return int(b - `a`) + 10
	}
	if b >= `A` && b <= `F` {
		return int(b - `A`) + 10
	}
	return -1
}

// is_digit reports whether `b` is an ASCII decimal digit.
@[inline]
pub fn is_digit(b u8) bool {
	return b >= `0` && b <= `9`
}

// is_ws reports whether `b` is CX inter-token whitespace (space, tab, CR, LF).
// The one whitespace predicate for both parsers (cxparse Phase 4.3): the data
// parser scans on it directly; the program lexer's `skip_ws_and_comments`
// routes its whitespace arm through it. Byte-identical to the former inline
// match arms — `lexicon.ebnf` [L01] WS.
@[inline]
pub fn is_ws(b u8) bool {
	return b == ` ` || b == `\t` || b == `\r` || b == `\n`
}

// ── Opaque lexical spans (comments + raw text) — shared recognizers ─────────
//
// The verbatim-capture scanners (def/const/match body capture, the module
// loader's directive balancer) walk bytes with quote-shielding to find the
// span boundary of a form whose CONTENT is parsed later by the real program
// parser. They must skip the three opaque spans the lexers skip — a `#` line
// comment ([L2] / grammar [30b]), a `[; … ]` block comment ([L3] / [30]), and
// a `[#…#]` raw-text span ([31]) — or a quote character INSIDE such a span
// opens a phantom string and silently shifts bracket balance (#289: `cx fmt`
// and the [?lib] loader disagreed about what parses). One shared home here
// keeps every entry point byte-identical.

// hash_line_comment_at reports whether the `#` at src[i] begins a line
// comment per grammar.ebnf [30b] position rules: at input start, or preceded
// by whitespace or `]`. (A `#` preceded by `[` is the `[#…#]` raw-text opener
// [31], and a `#` glued to a bareword is content per [12a] BareChar — neither
// starts a comment.)
@[inline]
pub fn hash_line_comment_at(src []u8, i int) bool {
	if i >= src.len || src[i] != `#` {
		return false
	}
	if i == 0 {
		return true
	}
	prev := src[i - 1]
	return is_ws(prev) || prev == `]`
}

// line_comment_end returns the index of the byte that TERMINATES the line
// comment opened at src[i] — the `\n` (not consumed; it is ordinary
// whitespace to the caller) or src.len at EOF. ([L2]: `#` to end-of-line.)
@[inline]
pub fn line_comment_end(src []u8, i int) int {
	mut j := i
	for j < src.len && src[j] != `\n` {
		j++
	}
	return j
}

// block_comment_open_at reports whether src[i..] begins a `[; … ]` block
// comment ([L3]).
@[inline]
pub fn block_comment_open_at(src []u8, i int) bool {
	return i + 1 < src.len && src[i] == `[` && src[i + 1] == `;`
}

// block_comment_end returns the index just PAST the `]` that closes the block
// comment opened at src[i] (which must be at `[;`). The body is OPAQUE prose:
// nested `[`…`]` pairs balance (matching program_lexer.skip_ws_and_comments
// and the data reader), but quotes have NO meaning inside — an apostrophe in
// prose ("the draft's") must not open a string span. Returns none when the
// comment never closes.
pub fn block_comment_end(src []u8, i int) ?int {
	mut depth := 0
	mut j := i + 2
	for j < src.len {
		b := src[j]
		if b == `[` {
			depth++
		} else if b == `]` {
			if depth == 0 {
				return j + 1
			}
			depth--
		}
		j++
	}
	return none
}

// raw_span_open_at reports whether src[i..] begins a `[#…#]` raw-text span
// ([31] RawText / CDATA — NOT a comment; the content is carried verbatim).
@[inline]
pub fn raw_span_open_at(src []u8, i int) bool {
	return i + 1 < src.len && src[i] == `[` && src[i + 1] == `#`
}

// raw_span_end returns the index just past the `#]` that closes the raw-text
// span opened at src[i] (which must be at `[#`). Content is verbatim — no
// nesting, no quote semantics — matching program_lexer.read_raw_span.
// Returns none when the span never closes.
pub fn raw_span_end(src []u8, i int) ?int {
	mut j := i + 2
	for j + 1 < src.len {
		if src[j] == `#` && src[j + 1] == `]` {
			return j + 2
		}
		j++
	}
	return none
}

// is_name_start reports whether `b` may begin an identifier / element name.
// ASCII only (`lexicon.ebnf` [L10], decision 1a-as-graduated: lone `:` is its
// own token, never a name-start). Identical in both parsers.
@[inline]
pub fn is_name_start(b u8) bool {
	return (b >= `a` && b <= `z`) || (b >= `A` && b <= `Z`) || b == `_`
}

// is_name_char — the DATA-mode name continuation. Folds `.` and `:` into the
// name token: `prefix:local` reads as ONE name (QName, split downstream) and
// dotted names are admitted. A glued `::` is the type-tag separator and is
// stopped at the call site (`read_name`), not here.
//
// THE ONE DELIBERATE NAME-CHAR MODE FORK (lexicon [L11]): the program lexer
// uses `is_ident_part` instead, which EXCLUDES `.`/`:` because it tokenizes
// them as their own tokens (path step / colon). Both rules live here, each
// defined once — that is not duplication, it is the mode boundary N1 admits.
//
// This is the RATIFIED end-state, not a way-point. [L11] describes `:` as its
// own token folded by the parser; this scannerless data path realizes the SAME
// fold by accepting `:` mid-name — observably identical (`svg:rect` →
// `<svg:rect/>`; `a:b:c` → CXERLEX-QNAME; QNames render BARE, never quoted).
// Do NOT "normalize" this to the spec letter by dropping `:` here: the data
// parser has no token stream, so that move only relocates `|| b==`:`` to ~17
// other sites (renderer/XML/streaming/LSP) and a single miss renders QNames
// quoted = bijection break, for zero observable gain. The single-tokenizer
// flip was ruled architecturally unsound (PLAN §4.3). Equivalence to [L11] is
// pinned by `vcx/tests/cxparse_namechar_fork_test.v`.
@[inline]
pub fn is_name_char(b u8) bool {
	return is_name_start(b) || is_digit(b) || b == `-` || b == `.` || b == `:`
}

// is_ident_part — the PROGRAM-mode identifier continuation: ASCII
// `[A-Za-z0-9_-]`, excluding `.`/`:` (which the program tokenizer emits as
// their own tokens). See `is_name_char` for the fork rationale.
@[inline]
pub fn is_ident_part(b u8) bool {
	return is_name_start(b) || is_digit(b) || b == `-`
}

// ── Full-Unicode names (I1 L22 / wart W-9) ───────────────────────────────────
//
// The grammar has admitted full-Unicode names since [L10a]/[L10b]
// (lexicon.ebnf §2 — the XML NameStartChar/NameChar ranges minus `:`); the
// parsers were ASCII-only, so `[café]` silently degraded. The codepoint
// predicates below are the grammar's OWN fixed ranges — no Unicode database
// involved. NFC normalization of names (L23) is a separate pass layered on
// top; these predicates only decide membership.

// utf8_cp_at decodes the UTF-8 sequence starting at src[i], returning
// (codepoint, byte_length). byte_length 0 = INVALID encoding: truncated
// sequence, bad continuation byte, overlong form, encoded surrogate
// (U+D800–U+DFFF), or a value above U+10FFFF — the L23 validity set.
pub fn utf8_cp_at(src []u8, i int) (rune, int) {
	b0 := src[i]
	if b0 < 0x80 {
		return rune(b0), 1
	}
	if b0 < 0xc2 {
		// 0x80–0xBF: bare continuation; 0xC0/0xC1: always-overlong leads.
		return rune(0), 0
	}
	if b0 < 0xe0 {
		if i + 1 >= src.len || (src[i + 1] & 0xc0) != 0x80 {
			return rune(0), 0
		}
		return rune((u32(b0 & 0x1f) << 6) | u32(src[i + 1] & 0x3f)), 2
	}
	if b0 < 0xf0 {
		if i + 2 >= src.len || (src[i + 1] & 0xc0) != 0x80 || (src[i + 2] & 0xc0) != 0x80 {
			return rune(0), 0
		}
		cp := (u32(b0 & 0x0f) << 12) | (u32(src[i + 1] & 0x3f) << 6) | u32(src[i + 2] & 0x3f)
		if cp < 0x800 {
			return rune(0), 0 // overlong
		}
		if cp >= 0xd800 && cp <= 0xdfff {
			return rune(0), 0 // encoded surrogate
		}
		return rune(cp), 3
	}
	if b0 < 0xf5 {
		if i + 3 >= src.len || (src[i + 1] & 0xc0) != 0x80 || (src[i + 2] & 0xc0) != 0x80
			|| (src[i + 3] & 0xc0) != 0x80 {
			return rune(0), 0
		}
		cp := (u32(b0 & 0x07) << 18) | (u32(src[i + 1] & 0x3f) << 12) | (u32(src[i + 2] & 0x3f) << 6) | u32(src[i + 3] & 0x3f)
		if cp < 0x10000 || cp > 0x10ffff {
			return rune(0), 0 // overlong / out of range
		}
		return rune(cp), 4
	}
	return rune(0), 0 // 0xF5–0xFF: lead bytes for values above U+10FFFF
}

// is_name_start_cp — [L10a] NameStartChar for non-ASCII codepoints (the
// ASCII arm stays in the byte-level is_name_start fast path).
pub fn is_name_start_cp(cp rune) bool {
	c := u32(cp)
	return (c >= 0xc0 && c <= 0xd6) || (c >= 0xd8 && c <= 0xf6)
		|| (c >= 0xf8 && c <= 0x2ff) || (c >= 0x370 && c <= 0x37d)
		|| (c >= 0x37f && c <= 0x1fff) || (c >= 0x200c && c <= 0x200d)
		|| (c >= 0x2070 && c <= 0x218f) || (c >= 0x2c00 && c <= 0x2fef)
		|| (c >= 0x3001 && c <= 0xd7ff) || (c >= 0xf900 && c <= 0xfdcf)
		|| (c >= 0xfdf0 && c <= 0xfffd) || (c >= 0x10000 && c <= 0xeffff)
}

// is_name_char_cp — [L10b] NameChar continuation extras for non-ASCII
// codepoints: NameStartChar plus U+00B7, combining marks U+0300–U+036F,
// and U+203F–U+2040.
pub fn is_name_char_cp(cp rune) bool {
	c := u32(cp)
	return is_name_start_cp(cp) || c == 0xb7
		|| (c >= 0x300 && c <= 0x36f) || (c >= 0x203f && c <= 0x2040)
}

// validate_utf8 scans the whole input and returns the byte offset of the
// first invalid UTF-8 sequence, or none when the input is valid. L23: the
// data parse entries enforce validity up front, so no invalid byte can
// reach a name, a value, or the canonical byte stream.
pub fn validate_utf8(src []u8) ?int {
	mut i := 0
	for i < src.len {
		if src[i] < 0x80 {
			i++
			continue
		}
		_, sz := utf8_cp_at(src, i)
		if sz == 0 {
			return i
		}
		i += sz
	}
	return none
}

// is_all_digits reports whether every byte of `s` is an ASCII decimal digit.
// Helper for the date/datetime recognizers.
pub fn is_all_digits(s string) bool {
	for b in s.bytes() {
		if b < `0` || b > `9` {
			return false
		}
	}
	return true
}

// ── String-escape decoding (lexicon.ebnf §5 [L32]) ──────────────────────────────
// The one decoder for the closed, uniform escape set shared by data + program
// strings (decision 2a-as-graduated): `\\ \' \" \n \r \t` plus `\uXXXX` /
// `\UXXXXXXXX`. An unknown or malformed sequence is LENIENT — the backslash is
// emitted verbatim and only the backslash is consumed, so regex shorthands
// (`\d` `\w` `\s`) survive intact. Both `cx/parser.v read_quoted_escape_into`
// and `code/lexer.v read_string` were byte-identical copies of this; they now
// drive this single recognizer with their own cursor + buffer.

// EscapeDecode is the result of decoding ONE backslash escape via decode_escape.
// The caller emits the value into its own buffer (the two parsers use `[]u8`
// vs `strings.Builder`) so the common simple-escape path stays allocation-free,
// exactly as before — only a valid `\u`/`\U` allocates (via rune_to_utf8).
pub struct EscapeDecode {
pub:
	cp       u32  // the decoded code point (or the literal backslash byte)
	is_rune  bool // true → emit rune_to_utf8(cp) (a `\u`/`\U`); false → emit the single byte u8(cp)
	consumed int  // source bytes consumed, INCLUDING the leading backslash
	invalid  bool // true → a `\u`/`\U` escape whose code point is not a Unicode scalar
	               // value (a UTF-16 surrogate D800..DFFF or > 10FFFF). The caller
	               // raises CXERLEX-CODEPOINT (lexicon @CHOICE-4); decode_escape itself
	               // is non-failing, so the validity verdict travels on this flag.
}

// decode_escape decodes the backslash escape at `src[bs]` (`bs` points at the
// `\`). See EscapeDecode / the section note for the rule. Trailing `\` at EOF
// and every unrecognized sequence return the literal backslash with consumed=1.
pub fn decode_escape(src []u8, bs int) EscapeDecode {
	nxt := bs + 1
	if nxt >= src.len {
		return EscapeDecode{ cp: u32(`\\`), consumed: 1 } // trailing backslash at EOF
	}
	esc := src[nxt]
	match esc {
		`\\` { return EscapeDecode{ cp: u32(`\\`), consumed: 2 } }
		`'` { return EscapeDecode{ cp: u32(`'`), consumed: 2 } }
		`"` { return EscapeDecode{ cp: u32(`"`), consumed: 2 } }
		`n` { return EscapeDecode{ cp: u32(`\n`), consumed: 2 } }
		`r` { return EscapeDecode{ cp: u32(`\r`), consumed: 2 } }
		`t` { return EscapeDecode{ cp: u32(`\t`), consumed: 2 } }
		`u` { return decode_unicode_escape(src, bs, 4) }
		`U` { return decode_unicode_escape(src, bs, 8) }
		else { return EscapeDecode{ cp: u32(`\\`), consumed: 1 } } // unknown — lenient pass-through
	}
}

// decode_unicode_escape handles `\uXXXX` (n=4) / `\UXXXXXXXX` (n=8). `bs` points
// at the backslash; `src[bs+1]` is the `u`/`U`, `src[bs+2..]` the hex digits.
// Insufficient or non-hex digits → unrecognized: emit the literal backslash and
// consume ONLY it (the `u`/`U` is left for normal processing).
fn decode_unicode_escape(src []u8, bs int, n int) EscapeDecode {
	if bs + 2 + n > src.len {
		return EscapeDecode{ cp: u32(`\\`), consumed: 1 }
	}
	for i := 0; i < n; i++ {
		if hex_digit_val(src[bs + 2 + i]) < 0 {
			return EscapeDecode{ cp: u32(`\\`), consumed: 1 }
		}
	}
	mut cp := u32(0)
	for i := 0; i < n; i++ {
		cp = (cp << 4) | u32(hex_digit_val(src[bs + 2 + i]))
	}
	// @CHOICE-4: a well-formed `\u`/`\U` escape must denote a Unicode SCALAR value.
	// UTF-16 surrogates (D800..DFFF) and code points above 10FFFF are not scalar
	// values — flag them so the caller raises CXERLEX-CODEPOINT. (We still report
	// consumed=2+n so the cursor advances past the whole escape on the error path.)
	invalid := cp > u32(0x10FFFF) || (cp >= u32(0xD800) && cp <= u32(0xDFFF))
	return EscapeDecode{ cp: cp, is_rune: true, consumed: 2 + n, invalid: invalid }
}

// ── Triple-quoted string scanning (lexicon.ebnf §5 [L31] / grammar [10b]) ────────
// scan_triple_quoted scans a `'''…'''` or `"""…"""` literal. `open` is the index
// in `src` of the FIRST of the three opening delimiter quotes; `q` is the
// delimiter byte. Returns the DEDENTED value (strip_common_indent applied, the
// shared D4 rule) together with the number of source bytes consumed from `open`
// (opening triple + verbatim body + closing triple), or none if unterminated.
//
// Lookahead-on-close: when a closing triple is seen but the byte after it is
// also `q`, the first delimiter is content — one delimiter byte is kept and the
// scan advances one byte and re-scans, so `'''hello''''` → `hello'`. Escapes are
// NOT processed (triple-quoted is verbatim); only the common-indent dedent runs.
//
// The caller advances its own cursor by the returned byte count (one step per
// byte) so line/column tracking and error positions are byte-stable — this is
// why a count is returned rather than an absolute end position.
pub fn scan_triple_quoted(src []u8, open int, q u8) ?(string, int) {
	return scan_triple_quoted_opt(src, open, q, false)
}

// scan_triple_quoted_opt is the shared scanner with an explicit dedent control.
// `raw == true` (the `r'''…'''` / `r"""…"""` prefix, #93) returns the body
// VERBATIM — no strip_common_indent — so leading-whitespace-significant blocks
// (indented code, tab-aligned text) survive byte-exact for surgical edits.
// `raw == false` is the default triple-quote (dedented, grammar [10b]).
pub fn scan_triple_quoted_opt(src []u8, open int, q u8, raw bool) ?(string, int) {
	mut pos := open + 3 // past the opening triple
	mut s := []u8{}
	for pos < src.len {
		b := src[pos]
		if b == q && pos + 3 <= src.len && src[pos + 1] == q && src[pos + 2] == q {
			// Lookahead-on-close: a fourth `q` makes the first delimiter content.
			if pos + 3 < src.len && src[pos + 3] == q {
				s << b
				pos++
				continue
			}
			pos += 3 // consume the closing triple
			body := s.bytestr()
			val := if raw { body } else { strip_common_indent(body) }
			return val, pos - open
		}
		s << b
		pos++
	}
	return none // unterminated
}

// ── Date / datetime recognition (lexicon.ebnf §4 [L23] / [L24]) ──────────────────
// peek_at is a bounds-safe byte read (0 past EOF), mirroring the program lexer's
// `peek` so temporal_len can be shared without a Lexer receiver.
@[inline]
fn peek_at(src []u8, i int) u8 {
	return if i >= 0 && i < src.len { src[i] } else { u8(0) }
}

// temporal_len reports the byte length of a CLEAN date or datetime token at
// `src[pos]`, or none. This is the STRICT recognizer of the full grammar:
//   DateLiteral     [L23]  [0-9]{4} '-' [0-9]{2} '-' [0-9]{2}
//   DateTimeLiteral [L24]  …'T'[0-9]{2}':'[0-9]{2}':'[0-9]{2}('.'[0-9]+)?('Z'|±hh:mm)?
// A run immediately followed by a name-continuation byte (e.g. `2024-01-15abc`)
// is NOT a clean token → none. This single scanner is what the PROGRAM lexer
// uses to find a temporal token boundary, and what DATA `is_date` classifies a
// delimited token with. (Formerly duplicated as code/lexer.v match_temporal_len.)
pub fn temporal_len(src []u8, pos int) ?int {
	// DateLiteral [L23]
	if !(is_digit(peek_at(src, pos)) && is_digit(peek_at(src, pos + 1))
		&& is_digit(peek_at(src, pos + 2)) && is_digit(peek_at(src, pos + 3))) {
		return none
	}
	if peek_at(src, pos + 4) != `-` || !(is_digit(peek_at(src, pos + 5)) && is_digit(peek_at(src, pos + 6))) {
		return none
	}
	if peek_at(src, pos + 7) != `-` || !(is_digit(peek_at(src, pos + 8)) && is_digit(peek_at(src, pos + 9))) {
		return none
	}
	mut n := 10
	// DateTimeLiteral [L24] — the time part, all-or-nothing.
	if peek_at(src, pos + n) == `T` && is_digit(peek_at(src, pos + n + 1)) && is_digit(peek_at(src, pos + n + 2))
		&& peek_at(src, pos + n + 3) == `:` && is_digit(peek_at(src, pos + n + 4)) && is_digit(peek_at(src, pos + n + 5))
		&& peek_at(src, pos + n + 6) == `:` && is_digit(peek_at(src, pos + n + 7)) && is_digit(peek_at(src, pos + n + 8)) {
		n += 9
		// optional fractional seconds '.' [0-9]+
		if peek_at(src, pos + n) == `.` && is_digit(peek_at(src, pos + n + 1)) {
			n++ // '.'
			for is_digit(peek_at(src, pos + n)) {
				n++
			}
		}
		// optional timezone: 'Z' | [+-] [0-9]{2} ':' [0-9]{2}
		if peek_at(src, pos + n) == `Z` {
			n++
		} else if (peek_at(src, pos + n) == `+` || peek_at(src, pos + n) == `-`)
			&& is_digit(peek_at(src, pos + n + 1)) && is_digit(peek_at(src, pos + n + 2))
			&& peek_at(src, pos + n + 3) == `:` && is_digit(peek_at(src, pos + n + 4))
			&& is_digit(peek_at(src, pos + n + 5)) {
			n += 6
		}
	}
	// Reject a temporal run glued to a name-continuation byte.
	next := peek_at(src, pos + n)
	if next != 0 && (is_ident_part(next) || is_digit(next)) {
		return none
	}
	return n
}

// is_date reports whether the whole string `s` is exactly a DateLiteral token.
// Derived from temporal_len — the ONE temporal grammar — so the date rule lives
// in a single place. (A 10-byte string can only scan to a date, never a
// datetime, so a length-10 match is exactly a date.)
pub fn is_date(s string) bool {
	if s.len != 10 {
		return false
	}
	if n := temporal_len(s.bytes(), 0) {
		return n == 10 && calendar_ok(s)
	}
	return false
}

// is_datetime — DATA classification of a delimited token as a datetime.
//
// STRICT, derived from temporal_len — the ONE temporal grammar (full [L24]).
// The token is a datetime iff the WHOLE token scans as a clean temporal run of
// datetime length (>= 19: a bare DateLiteral is exactly 10, never a datetime).
// A malformed `YYYY-MM-DDT<garbage>` run fails temporal_len's all-or-nothing
// time part / glued-name guard, so it classifies as text — matching the program
// scanner exactly.
//
// (Phase 3, cxparse unification — the datetime strictness fork is CONVERGED:
// the data side was historically LOOSE here, accepting `YYYY-MM-DDT<garbage>` as
// a datetime with an unvalidated tail. That diverged from the strict program
// scanner and from [L24]; this is the lexicon-mandated convergence.)
pub fn is_datetime(s string) bool {
	if s.len < 19 {
		return false
	}
	n := temporal_len(s.bytes(), 0) or { return false }
	return n == s.len && calendar_ok(s)
}

// days_in_month returns the day count of month `mo` (1-12) in year `y`,
// accounting for Gregorian leap years (Feb = 29 on a leap year). 0 for an
// out-of-range month.
fn days_in_month(y int, mo int) int {
	match mo {
		1, 3, 5, 7, 8, 10, 12 { return 31 }
		4, 6, 9, 11 { return 30 }
		2 {
			leap := (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
			return if leap { 29 } else { 28 }
		}
		else { return 0 }
	}
}

// two_digits reads `n` decimal digits at byte `pos` as an int (-1 if out of
// bounds). The caller guarantees the bytes are digits (shape pre-validated by
// temporal_len), so no per-digit validation is needed.
fn two_digits(b []u8, pos int, n int) int {
	mut v := 0
	for i := 0; i < n; i++ {
		if pos + i >= b.len {
			return -1
		}
		v = v * 10 + int(b[pos + i] - `0`)
	}
	return v
}

// calendar_ok validates the calendar FIELDS of an already SHAPE-VALID temporal
// token (a `YYYY-MM-DD` date or `YYYY-MM-DDThh:mm:ss[.fff][Z|±hh:mm]` datetime,
// as recognized by temporal_len). Per lexicon HELPERS / @CHOICE-3:
//   1≤Mo≤12 · 1≤D≤days_in(Y,Mo) · 0≤H≤23 · 0≤Mi≤59 · 0≤Sec≤59 (no leap second) ·
//   zone HH≤23 MM≤59.
// A shape-valid token that fails this is NOT a date/datetime token — it falls
// through to a STRING (no reject; the reader stays total). This gates the
// CLASSIFICATION layer only — is_date/is_datetime (data) and the program
// parser's .date_lit/.datetime_lit arms; temporal_len (the EXTENT recognizer
// used by the program lexer to find the token boundary) is unchanged, so the
// calendar-invalid run stays ONE token rather than fragmenting.
pub fn calendar_ok(s string) bool {
	b := s.bytes()
	if b.len < 10 {
		return false
	}
	y := two_digits(b, 0, 4)
	mo := two_digits(b, 5, 2)
	d := two_digits(b, 8, 2)
	if mo < 1 || mo > 12 {
		return false
	}
	if d < 1 || d > days_in_month(y, mo) {
		return false
	}
	if b.len == 10 {
		return true
	}
	// datetime time part: 'T' at 10, hh:mm:ss at 11 / 14 / 17.
	h := two_digits(b, 11, 2)
	mi := two_digits(b, 14, 2)
	sec := two_digits(b, 17, 2)
	if h > 23 || mi > 59 || sec > 59 {
		return false
	}
	// Skip optional fractional seconds, then validate an optional ±HH:MM zone.
	mut i := 19
	if i < b.len && b[i] == `.` {
		i++
		for i < b.len && is_digit(b[i]) {
			i++
		}
	}
	if i < b.len && (b[i] == `+` || b[i] == `-`) {
		zh := two_digits(b, i + 1, 2)
		zm := two_digits(b, i + 4, 2)
		if zh > 23 || zm > 59 {
			return false
		}
	}
	return true
}

// ── Numbers: the leading-zero rule (lexicon.ebnf §3 [L20c]) ──────────────────────
// has_leading_zero_int reports whether `s` — an optionally-signed run — is a
// multi-digit decimal with a disallowed leading zero: `02134` / `-007` → true;
// `0` / `-0` / `7` / `123` → false. Per [L20c] such a token is NOT an Integer
// (it falls through to Text, preserving ZIP codes / SKUs). This is the ONE
// number-grammar rule both parsers share today (the program number-literal
// converter and the data decimal-int classifier) — it was hand-mirrored in two
// places and was a Class-D bug source (D2); it now has a single home.
//
// NOTE: the rest of number recognition is NOT unified here. The two parsers
// factor it at different layers — the data parser CLASSIFIES a delimited token
// to a typed value inline (hex `0x…`, `_` separators, atom, float digit-guard;
// full [L20]), while the program lexer LEXES a bare number token (no hex, no
// `_`) and converts it later — so they recognize different number grammars. One
// shared recognizer would change one side's behavior (mandate N2 forbids it);
// that reconciliation is Phase-2 (tokenizer) / Phase-3 (classification → one
// layer) work. Likewise `::T` type-tag and duration TOKENIZATION differ in
// structure (the TypeName SET is already shared via is_valid_type_tag; duration
// is program-only).
@[inline]
pub fn has_leading_zero_int(s string) bool {
	mut d := s
	if d.len > 0 && (d[0] == `-` || d[0] == `+`) {
		d = d[1..]
	}
	return d.len > 1 && d[0] == `0`
}

// temporal_span_kind classifies a WHOLE token as a duration or period literal
// (lexicon [L25]/[L26]), or returns none. The grammar is `[+-]? (Integer Unit)+`
// where every unit belongs to ONE family:
//   - duration (EXACT): ns, us, ms, s, m(inute), h, d(=24h), w(=7d)
//   - period   (CALENDAR): mo(nth), y(ear)
// Rules (from the [L25]/[L26] LEXING note):
//   - units match LONGEST-first (`ms`/`mo`/`ns`/`us` before `m`); `m` is always
//     minutes, months are `mo` (no collision);
//   - the WHOLE token must be integer+unit terms — `5mph` is none (→ Text);
//   - a token mixing the two families (`1y2h`) is none (write them separately).
// Shared by the data reader (try_autotype) and the program lexer so both
// readings classify these tokens identically.
pub fn temporal_span_kind(tok string) ?ScalarType {
	if tok.len == 0 {
		return none
	}
	mut i := 0
	if tok[0] == `+` || tok[0] == `-` {
		i = 1
	}
	if i >= tok.len {
		return none
	}
	mut saw_duration := false
	mut saw_period := false
	mut terms := 0
	for i < tok.len {
		// Each term begins with one or more digits.
		digit_start := i
		for i < tok.len && tok[i] >= `0` && tok[i] <= `9` {
			i++
		}
		if i == digit_start {
			return none
		}
		// Then a unit, matched longest-first.
		mut matched := false
		if i + 2 <= tok.len {
			two := tok[i..i + 2]
			if two == 'ns' || two == 'us' || two == 'ms' {
				saw_duration = true
				i += 2
				matched = true
			} else if two == 'mo' {
				saw_period = true
				i += 2
				matched = true
			}
		}
		if !matched && i + 1 <= tok.len {
			one := tok[i]
			if one == `s` || one == `m` || one == `h` || one == `d` || one == `w` {
				saw_duration = true
				i += 1
				matched = true
			} else if one == `y` {
				saw_period = true
				i += 1
				matched = true
			}
		}
		if !matched {
			return none
		}
		terms++
	}
	if terms == 0 || (saw_duration && saw_period) {
		return none
	}
	return if saw_period { ScalarType.period_type } else { ScalarType.duration_type }
}
