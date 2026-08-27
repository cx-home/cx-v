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

// source_carries_program_directive reports whether `src` carries a registered
// program directive head (`[?let]`, `[?def]`, `[?for]`, … — the closed
// `directive_names` registry) ANYWHERE in its byte stream.
//
// It answers the same question as `code.data_reading_has_program_directive`
// — "is this resource program-SHAPED?" — but LEXICALLY, so it still answers
// when the data reading itself aborted. That predicate parses a Document and
// walks it; a source the data parser REFUSES (the D2 node-valued-attribute
// reject, cx-err:E211) has no tree to walk, and the CONVERT surface needs the
// answer precisely there (cli.md §2.2 diagnostics, #1019).
//
// String- and comment-aware by construction, so a directive merely NAMED in
// prose is not a directive here: the three opaque spans this shelf recognizes
// (`#` line comment, `[; … ]` block comment, `[#…#]` raw text) are skipped
// with their own recognizers, and a `'…'` / `"…"` quoted span is shielded the
// way `value_run_end` shields one. Unterminated spans end the scan — a
// truncated document carries no further directive head we can honestly claim.
//
// The answer is a HINT, never a verdict: it decorates a diagnostic, it does
// not decide a reading. `[?cx …]` config directives and foreign PIs are not in
// `directive_names` and answer false, matching the tree-walking predicate.
pub fn source_carries_program_directive(src []u8) bool {
	mut i := 0
	for i < src.len {
		b := src[i]
		if hash_line_comment_at(src, i) {
			i = line_comment_end(src, i)
			continue
		}
		if block_comment_open_at(src, i) {
			i = block_comment_end(src, i) or { return false }
			continue
		}
		if raw_span_open_at(src, i) {
			i = raw_span_end(src, i) or { return false }
			continue
		}
		if b == `'` || b == `"` {
			mut j := i + 1
			for j < src.len && src[j] != b {
				j++
			}
			if j >= src.len {
				return false
			}
			i = j + 1
			continue
		}
		if b == `[` && i + 2 < src.len && src[i + 1] == `?` && is_name_start(src[i + 2]) {
			mut j := i + 2
			for j < src.len && is_name_char(src[j]) {
				j++
			}
			if is_directive_name(src[i + 2..j].bytestr()) {
				return true
			}
			i = j
			continue
		}
		i++
	}
	return false
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

// ── Operator element heads (#976) ────────────────────────────────────────────
//
// THE OPERATOR-HEAD ALPHABET IS THE EVALUATOR'S, NOT THE PARSER'S. `code/eval.v`
// holds the ruled set (`operator_element_heads`, 18 heads); twelve of them are
// GLYPHS and so need a lexical rule the Name production cannot supply:
//
//     one-char   + * - / % = < > ~
//     two-char   != <= >=
//
// The other six (`and or not union intersect except`) are ordinary Names and
// reach parse_element through `read_name` with no help from here.
//
// #976 (content-addressing SOUNDNESS): the data parser used to carry its own,
// SHORTER copy of this alphabet — seven one-char heads, no two-char forms — in
// two sites that had drifted apart. The heads it did not know failed in two
// different ways, and the quiet one was the dangerous one: `>=`, `!=` and `~`
// raised "expected name" (rc=1, loud), while `<=` and `%` fell through into the
// ARRAY lane and SILENTLY STRINGIFIED. So `[<= 5 3]` canonicalized to
// `['<= 5 3']` — byte-identical to the document that really is that quoted
// string, and therefore the SAME Tier-1 hash — two documents the evaluator
// gives different values sharing one content address. This function is now the
// single home of the rule; every site calls it and none re-spells it.
//
// DELIMITATION is the whole rule: the operator token is an element name only
// when the next byte is whitespace, `]`, or end-of-input. A GLUED continuation
// keeps its historical route and MUST — `[-1, 2]` is a negative-number array
// item, `[*n]` is an alias reference, `[!ENTITY …]` is a declaration, and
// `['<= 5 3']` is a quoted string in an array.
//
// LONGEST MATCH FIRST, so `<=` wins over `<`. Without that ordering `[<= …]`
// reads as an UNDELIMITED `<` and falls back to the array lane — which is
// precisely the collision above, so the ordering is load-bearing, not taste.
//
// Returns the head's LENGTH IN BYTES (1 or 2), or 0 when the bytes at `i` do
// not open a delimited operator head.
@[inline]
pub fn operator_head_len(src []u8, i int) int {
	if i < 0 || i >= src.len {
		return 0
	}
	b := src[i]
	// Two-char heads lead (longest match): `!=` `<=` `>=`.
	if (b == `!` || b == `<` || b == `>`) && i + 1 < src.len && src[i + 1] == `=` {
		return if op_head_delimited(src, i + 2) { 2 } else { 0 }
	}
	if b == `+` || b == `*` || b == `-` || b == `/` || b == `%` || b == `=`
		|| b == `<` || b == `>` || b == `~` {
		return if op_head_delimited(src, i + 1) { 1 } else { 0 }
	}
	return 0
}

// op_head_delimited — an operator head ends at whitespace, `]`, or EOF. This is
// the delimiter test `operator_head_len` applies after a head's bytes match;
// see that function for why a glued continuation must NOT be a head.
@[inline]
fn op_head_delimited(src []u8, k int) bool {
	return k >= src.len || is_ws(src[k]) || src[k] == `]`
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
//
// triple_quote_prefix_len is the OPENER half of the rule `scan_triple_quoted_opt`
// closes: it reports how many bytes sit BEFORE the opening triple delimiter of a
// triple-quoted literal starting at `src[i]` — 0 for the plain `'''…'''` /
// `"""…"""` form, 1 for the RAW `r'''…'''` / `r"""…"""` form (I1 L58) — or -1
// when `src[i]` does not open one at all. The delimiter byte is then
// `src[i + prefix]`.
//
// It exists because a CURSOR-FREE walker had no way to ask the question at all:
// every spelling of the opener test was a `Parser`/`Lexer` method reading its
// own `pos`, so `code_tree.v` did not ask, and its single-quote scanner read
// `'''body'''` as an EMPTY string followed by a fresh opener. That is #999 — the
// empty string became the attribute's value, the real body reappeared as sibling
// `text` nodes, and a body carrying an odd `'` (`'''it's'''`) desynced the
// bracket matcher into reporting the whole element `unbalanced`.
//
// EVERY opener test in the tree is now this one (#1021). `Parser.at_raw_triple`
// and `Parser.read_quoted_for_doc` ask it, as do both arms of
// `program_lexer.next_token` — the plain arm reading `== 0` and the `r`-prefixed
// arm `== 1`, since a raw opener is exactly a 1-byte prefix. Callers that need
// the delimiter read it at `src[i + prefix]` rather than re-testing the bytes;
// that is what keeps a second, drifting spelling from growing back (#976).
//
// Returns -1 rather than an option so a byte-level caller can branch on it
// without unwrapping a tuple in a hot scan loop.
@[inline]
pub fn triple_quote_prefix_len(src []u8, i int) int {
	if i < 0 || i >= src.len {
		return -1
	}
	mut j := i
	mut prefix := 0
	if src[j] == `r` {
		prefix = 1
		j++
	}
	if j + 2 >= src.len {
		return -1
	}
	q := src[j]
	if q != `'` && q != `"` {
		return -1
	}
	if src[j + 1] != q || src[j + 2] != q {
		return -1
	}
	return prefix
}

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

// ── Sequence-literal delimitation (grammar [56a], ASP-1) ─────────────────────
//
// sequence_literal_at_paren decides whether the `(` at `src[i]` opens a
// SEQUENCE LITERAL or merely a parenthesised text run. The rule is ASP-1's:
// `()` is the empty sequence, and otherwise a sequence needs a depth-0 `,`
// before its matching `)` — so `(x)` and `(see note)` stay prose. Quote regions
// are shielded so a `,` inside a string does not promote a text run, and the
// depth counter is deliberately MIXED-DELIMITER (`[`/`(`/`{` all raise it) so a
// nested node or map cannot leak its own comma to depth 0.
//
// Single home of the rule, per the `operator_head_len` precedent (#976, #992):
// `Parser.peek_is_sequence_literal_at_paren` now delegates here, and `code_tree.v`
// — which had no delimitation test of its own and therefore emitted `(`, `,` and
// `)` as scalar CHILDREN (#1000) — asks the same question the parser asks
// instead of carrying a second, drifting copy.
//
// Pure lookahead: no cursor, nothing consumed.
pub fn sequence_literal_at_paren(src []u8, i int) bool {
	if i < 0 || i >= src.len || src[i] != `(` {
		return false
	}
	mut j := i + 1
	for j < src.len && is_ws(src[j]) {
		j++
	}
	if j < src.len && src[j] == `)` {
		return true // `()` — the empty sequence
	}
	mut depth := 0
	mut quote := u8(0)
	for j < src.len {
		b := src[j]
		if quote != 0 {
			if b == `\\` && j + 1 < src.len {
				j += 2
				continue
			}
			if b == quote {
				quote = 0
			}
			j++
			continue
		}
		if b == `'` || b == `"` {
			quote = b
			j++
			continue
		}
		if depth == 0 {
			if b == `,` {
				return true
			}
			if b == `)` {
				return false
			}
		}
		if b == `[` || b == `(` || b == `{` {
			depth++
			j++
			continue
		}
		if b == `]` || b == `}` || b == `)` {
			if depth > 0 {
				depth--
			}
			j++
			continue
		}
		j++
	}
	return false
}

// ── Map-literal delimitation (grammar [56c], ASP-2) ──────────────────────────
//
// map_literal_at_brace decides whether the `{` at `src[i]` opens a MAP LITERAL
// or merely a brace-delimited text run. The rule is the same shape as its
// sequence sibling above: `{}` is the empty map, and otherwise a map needs a
// depth-0 `:` before its matching `}` — so `{text}` stays prose. Quote regions
// are shielded so a `:` inside a string does not promote a text run, and the
// depth counter is MIXED-DELIMITER (`[`/`(`/`{` all raise it) so a nested node
// or array cannot leak its own colon to depth 0.
//
// Single home of the rule. It had THREE spellings before #1020 and the walker
// could reach none of them: `Parser.peek_is_map_literal_at_brace` (cursor-bound)
// and `span_is_map_shaped` (positional, added for the typed-list detector's
// lookahead — a second copy of the identical body, the drift this shelf exists
// to prevent) both delegate here now, and `code_tree.v` — which had no
// delimitation test of its own and therefore emitted `{`, the key, `:`, the
// value and `}` as five separate scalar CHILDREN (#1020) — asks this one.
//
// Pure lookahead: no cursor, nothing consumed.
pub fn map_literal_at_brace(src []u8, i int) bool {
	if i < 0 || i >= src.len || src[i] != `{` {
		return false
	}
	mut j := i + 1
	for j < src.len && is_ws(src[j]) {
		j++
	}
	if j < src.len && src[j] == `}` {
		return true // `{}` — the empty map
	}
	mut depth := 0
	mut quote := u8(0)
	for j < src.len {
		b := src[j]
		if quote != 0 {
			if b == `\\` && j + 1 < src.len {
				j += 2
				continue
			}
			if b == quote {
				quote = 0
			}
			j++
			continue
		}
		if b == `'` || b == `"` {
			quote = b
			j++
			continue
		}
		if depth == 0 {
			if b == `:` {
				return true
			}
			if b == `}` {
				return false
			}
		}
		if b == `[` || b == `(` || b == `{` {
			depth++
			j++
			continue
		}
		if b == `]` || b == `}` || b == `)` {
			if depth > 0 {
				depth--
			}
			j++
			continue
		}
		j++
	}
	return false
}

// ── Array-literal delimitation (grammar [56b], [D1]) ─────────────────────────
//
// array_literal_at_bracket decides whether the `[` at `src[i]` opens an ARRAY
// LITERAL or an element / reserved-sigil form. It is the WHOLE answer the
// `parse_bracket_node` dispatch reaches for that `[`, in the dispatch's own
// order, so a cursor-free caller gets the parser's reading and not a subset:
//
//   1. RESERVED SIGILS keep absolute priority over the array reading — `?`
//      (EvalDirective / Interpolation / PI / CXDirective), `;` (comment), `|`
//      (block content), `#` (raw text), and `!` when it is NOT the delimited
//      operator head `!=` (declaration). Otherwise a comma inside an opaque
//      span — `[; comment, with, commas]` — reads as an array whose first item
//      is `;`.
//   2. The reserved glued `[table[` opener is ElementMeta (#484, grammar
//      [29]/[50]): it can belong to no element head at this dispatch and is
//      refused there, so it never reaches the array test.
//   3. Otherwise the [D1] FIRST-ITEM-FOLLOWED-BY-COMMA rule, which
//      `Parser.peek_is_array_literal` used to own outright and now delegates
//      here for:
//        a. Skip leading whitespace and quick-detect empty `[]` → array.
//        b. Inspect the first byte: if it is not a valid element-name start
//           (not letter / not `_`), it is an array literal. Covers `[1, 2, 3]`,
//           `['a', 'b']`, `[*, default]` (§D8 sentinel), `[(seq, lit)]`, and
//           any other shape that cannot be an element name.
//        c. Otherwise scan forward for the boundary character:
//             - `,` before any whitespace / `=` / `]` → array literal (the
//               first item is the bare-name-shaped token) — EXCEPT that a Name
//               head immediately followed by `,` is the ambiguous bare-bareword
//               array and routes to the element dispatch to be refused (see
//               below).
//             - `=` → element with attribute.
//             - `]` → element with empty body, e.g. `[name]`.
//             - whitespace → element. The first whitespace inside the bracket
//               marks the boundary between the element name and the body;
//               commas appearing AFTER the name are body content, not
//               separators.
//             - a non-name char that is also non-ws / non-`,` / non-`=` /
//               non-`]` (e.g. `*` in `[FOAR*, math]` try-catch globs, or a `:`
//               not at name-token position) → array literal: the would-be
//               element name is not a clean Name shape, so the bracket cannot
//               be an element head.
//
// Quote / bracket interiors never appear in the first-item-prefix scan: the
// rule decides on the first non-name boundary character it sees, well before
// any nested content. Strictly local — O(first-token-length) lookahead, no
// full-body scan.
//
// NOT part of this predicate, deliberately: the @CHOICE-1 / G-ARRAY-1
// WHITESPACE typed list (`typed_list_body_at`, §9 [L25a/b]) is a SEPARATE
// production that also yields an ArrayNode and is tested BEFORE this one at the
// parser's dispatch — where the two disagree the typed list wins. It stays a
// separate predicate because it is a separate rule (a whole-body token
// classifier, not this O(first-token) prefix scan), and folding them would hide
// which one answered. A cursor-free caller must therefore ask BOTH, in the
// dispatch's order; `code_tree.v` does (#1025). Asking only this one gets the
// parser's LOSING answer wherever the typed list fires alone — measured on
// `[true false]` (name-shaped first token, no comma), which read as the element
// `true` until #1025.
//
// It exists because a CURSOR-FREE walker had no way to ask: the rule was a
// `&Parser` method reading its own `pos`, so `code_tree.v` did not ask, and
// `[1, 2, 3]` fell into the element lane — an element NAMED `1` whose children
// were the commas and the remaining items (#1020). Shapes whose first byte
// cannot start a Name lost everything instead: `['x', 'y']`, `[[1,2],[3,4]]`
// and the §D8 sentinel `[*, default]` all came back as the childless
// anonymous `_`.
//
// Pure lookahead: no cursor, nothing consumed.
pub fn array_literal_at_bracket(src []u8, i int) bool {
	if i < 0 || i >= src.len || src[i] != `[` {
		return false
	}
	if bracket_head_is_reserved(src, i + 1) {
		return false
	}
	mut k := i + 1
	for k < src.len && is_ws(src[k]) {
		k++
	}
	if k >= src.len {
		return false
	}
	if src[k] == `]` {
		return true // empty [] → empty array
	}
	first := src[k]
	// Element-side sigils with dual roles: `*` (alias / operator head / §D8
	// sentinel), `>` and `~` (ruled operator heads), and `\`` / `^`, which are
	// not element heads in ANY reading. The §D8 array sentinel form
	// `[*, default]` and any literal-array shape using these glyphs as item-0
	// values must still parse as array, so the disambiguator peeks the next
	// non-ws char: a comma marks the array form, anything else (including
	// end-of-input) stays with the element-side dispatch in
	// parse_bracket_node's match.
	//
	// #983 — this comment used to call `\`` `>` `~` `^` "Markdown shorthand
	// elements". THERE IS NO SUCH THING. The grammar note that governs THIS
	// production is explicit: "CX has NO Markdown syntax — `>`, `~`, `^`, the
	// backtick, and `#` are ordinary content / operators, never head sigils"
	// (grammar.ebnf, the [D1] first-item-followed-by-comma preamble). The only
	// other "markdown shorthand" mention in the grammar is for DATA-surface
	// `~` as BareValue CONTENT — content, not a head. What the element-side
	// dispatch actually does with each glyph, measured:
	//
	//   `*`       delimited → the `*` operator head (`[* $x 2]`); glued → an
	//             alias reference (`[*n]`). Both parse.
	//   `>` `~`   delimited → the ruled OPERATOR head (`[> $x 2]`, `[~ a b]`)
	//             — both are in code/eval.v `operator_element_heads`, which
	//             #976 made the data parser's alphabet too. Glued (`[>x]`,
	//             `[~x]`) → rc=1 "expected name" (parse_element's name
	//             reader — that refusal carries no CXER code).
	//             Operators, exactly as the grammar note says; nothing
	//             markdown about them.
	//   `\`` `^`  NEVER parse as an element head, delimited or glued:
	//             `[\` code]` and `[^ footnote]` both exit rc=1 "expected
	//             name". They are absent from the ruled 18-head set and from
	//             every grammar production. Admitting either would be a
	//             SURFACE change requiring a ruling; nothing here implements
	//             one, and this comment must not imply otherwise.
	//
	// Claiming all five for the element lane is nevertheless load-bearing: it
	// is what makes their glued forms FAIL LOUD instead of stringifying
	// silently through the array lane the way glued `%` / `<=` still do
	// (oph-403/404) — the failure mode #976 was filed against.
	if first == `*` || first == `\`` || first == `>` || first == `~` || first == `^` {
		mut m := k + 1
		for m < src.len && is_ws(src[m]) {
			m++
		}
		return m < src.len && src[m] == `,`
	}
	// I1 row 8 (L80, audit C4) + #976: a DELIMITED OPERATOR HEAD is an element
	// name, never an array item. The alphabet lives in `operator_head_len`, one
	// shelf up — this rule used to re-spell a five-char subset of it, and the
	// two-char heads it therefore could not see are exactly the ones that
	// leaked: `[<= 5 3]` scanned as an undelimited `<`, fell through into the
	// array lane, and canonicalized to `['<= 5 3']` — the same bytes, and so the
	// same hash, as the document that IS that quoted string.
	//
	// The dual-role block above still runs FIRST and still owns `*` `\`` `>`
	// `~` `^`: a following comma means the §D8 array form (`[*, default]`), and
	// that reading must win over the operator reading. Everything it does not
	// claim reaches here, where a GLUED continuation falls through to the
	// name-shape checks below and lands in the array lane exactly as before
	// (`[-1, 2]` negative number, `[+1, 2]`, `[<=x]`).
	if operator_head_len(src, k) > 0 {
		return false
	}
	// First char that can't lead an element name → must be array literal (or a
	// structural sigil already claimed above). I1 L22: a non-ASCII lead byte is
	// an element head when the decoded codepoint is in [L10a] (full-Unicode
	// names).
	if first >= 0x80 {
		cp, sz := utf8_cp_at(src, k)
		if sz == 0 || !is_name_start_cp(cp) {
			return true
		}
	} else if !is_name_start(first) {
		return true
	}
	// First char IS name_start. Walk through the candidate name looking for the
	// boundary that decides element vs array.
	for k < src.len {
		b := src[k]
		// 3a (lexicon §collections [L83]): a Name head IMMEDIATELY followed by a
		// `,` is a BARE BAREWORD ARRAY — `[web, prod]` — which is ambiguous with
		// an element head and is a PARSE ERROR. It routes to the element
		// dispatch so `parse_element` raises CXER0100.
		if b == `,` { return false }
		if b == `=` { return false }
		if b == `]` { return false }
		if is_ws(b) { return false }
		// A glued `::` is the type-label separator on an element head
		// (`[port::u16 8080]`). It marks an element, so stop the scan here. A
		// single `:` stays a name char (namespace `svg:rect`).
		if b == `:` && k + 1 < src.len && src[k + 1] == `:` { return false }
		if b >= 0x80 {
			// I1 L22: multibyte name characters continue the element-head
			// candidate; a non-name codepoint routes to the array/text lane.
			cp, sz := utf8_cp_at(src, k)
			if sz == 0 || !is_name_char_cp(cp) {
				return true
			}
			k += sz
			continue
		}
		if !is_name_char(b) { return true }
		k++
	}
	return false
}

// bracket_head_is_reserved reports whether the byte at `src[i]` — the byte just
// past a `[` — belongs to a form that owns the `parse_bracket_node` dispatch
// outright, ahead of any collection-literal reading: `?` `;` `|` `#`, a `!`
// that is not the delimited operator head `!=` (#976), or the reserved glued
// `[table[` ElementMeta opener (#484).
//
// Both array-adjacent dispatch tests in `parse_bracket_node` — the typed-list
// route and `peek_is_array_literal` — were guarded by the identical
// `b != `?` && !is_opaque_sigil` conjunction spelled inline; this is that
// conjunction, once, where `array_literal_at_bracket` can also reach it
// (#1020).
pub fn bracket_head_is_reserved(src []u8, i int) bool {
	if i < 0 || i >= src.len {
		return false
	}
	b := src[i]
	if b == `?` || b == `;` || b == `|` || b == `#` {
		return true
	}
	if b == `!` && operator_head_len(src, i) == 0 {
		return true
	}
	// `[table[` — the TABLE_OPEN glued form. `[table[]` (empty) is not it.
	// Bounds and the `!= ]` test are the dispatch's own, byte for byte.
	if b == `t` && i + 7 <= src.len
		&& src[i + 1] == `a` && src[i + 2] == `b`
		&& src[i + 3] == `l` && src[i + 4] == `e`
		&& src[i + 5] == `[` && src[i + 6] != `]` {
		return true
	}
	return false
}

// ── §9 [L25a/b] whitespace typed list — @CHOICE-1 / G-ARRAY-1 ────────────────
//
// typed_list_body_at reports whether the body beginning at `src[body_start]`
// (the byte just past the opening `[`) is a §9 [L25a/b] TYPED LIST: a no-comma body of 2+
// top-level tokens in which EVERY bare scalar token auto-types to a non-string
// scalar (number / atom / bool / date) or is a quoted string, and child
// elements `[…]` may interleave (mixed content). One BAREWORD (a bare token
// that does NOT auto-type — `the`, `Version`, `it's`) makes the whole body
// PROSE instead (G-BODY-1, conformance 009/014). A top-level comma (→ the
// [L25c] comma path) or an `&` entity introducer also disqualifies it.
//
// `headless` selects the caller's POSITION, and it changes exactly one rule:
// the ASP-2 (#903) carve-out by which a name-shaped FIRST token followed by a
// `(…)`/`{…}` structure keeps the ELEMENT reading (`[true (2, 3)]` is the
// element `true`). An element BODY has no element reading to protect, and the
// ux-016 engine-output shape (`[list false (verb, …) …]`) starts with the
// name-shaped bool `false`, so ASP-3 (#909) admits it there.
//
// `body_start` is load-bearing beyond where the scan begins — hence the name,
// which also keeps it from being confused with the other shelf entries' `i`
// (they take the index OF their delimiter; this one takes the byte AFTER the
// `[`). The glued-structure test (`(1, 2)[0]`, `(1, 2)(3, 4)` keep their
// historical one-item mixed reading) asks whether the byte BEFORE the structure
// is whitespace, which is only a question when the structure is not the body's
// first token.
//
// WHY IT IS HERE (#1025). This is the SECOND array-yielding production — the
// headless dispatch tests it BEFORE the [D1] first-item rule
// (`array_literal_at_bracket`), and where the two disagree the typed list wins.
// It was a `&Parser` method reading its own `pos`, so the cursor-free
// `code_tree.v` walker could not ask it and did not: where ONLY the typed list
// fires the walker fell into the element lane and read the first token as the
// element NAME — `[true false]` is an ArrayNode to the parser and was the
// element `true` with one child to the tree (pinned as measured behavior at
// #1020, flipped here). Same class as #999 / #1000 / #1020, and the same fix:
// the rule gets a cursor-free home on this shelf, every caller delegates, and
// the walker asks the question the parser asks instead of carrying a copy that
// can drift.
//
// It SUPERSEDES the old whitespace auto-array (try_auto_array, a single
// `T[]`-typed element): a typed list is N discrete typed items with no element
// array type, per the formal witnesses (G-BODY-2/3, M-SCALAR-ITEM).
//
// Quote regions, child brackets and line comments are skipped so their
// interiors don't count. Pure lookahead: no cursor, nothing consumed.
pub fn typed_list_body_at(src []u8, body_start int, headless bool) bool {
	mut i := body_start
	mut at_tok_start := true
	mut tokens := 0
	// RULED: ASP-2 (#903) / ASP-3 (#909) — a `(…)`/`{…}` literal is a
	// discrete token, in the headless array position (ASP-2) and in element
	// bodies (ASP-3), so `[1 (2, 3)]` is two items and `[k 1 (2, 3)]` is the
	// element `k` with two children — exactly like `[1 [?=@x]]` already was.
	// Before, the bail-out below sent the run to the comma/prose path, which
	// glued it into ONE item and mangled the leading value per type (int 1 →
	// the string '1 ', trailing space and all; bools, atoms, quoted strings
	// and holes corrupted the same way) — silently, stably under
	// canonicalization, and REACHABLE FROM ENGINE OUTPUT (ux-016 renders
	// `[list false (verb, …) …]`, which failed its own re-parse, the #704
	// class). The first-token guard below is HEADLESS-ONLY: it preserves the
	// element reading of `[true (2, 3)]` (name-shaped head + structure →
	// element, per the ASP-1 scope note); an element body has no element
	// reading to protect.
	mut first_tok_namelike := false
	for i < src.len {
		c := src[i]
		if c == `]` { break } // body terminator (top level)
		if c == ` ` || c == `\t` || c == `\r` || c == `\n` {
			at_tok_start = true
			i++
			continue
		}
		if c == `#` && at_tok_start {
			i++
			for i < src.len && src[i] != `\n` { i++ }
			continue
		}
		if c == `,` { return false } // top-level comma → [L25c] comma path
		// Entity refs route to parse_body (it already images `&` correctly).
		if c == `&` { return false }
		if c == `(` || c == `{` {
			if headless && first_tok_namelike {
				return false
			}
			// The map-shape test is `map_literal_at_brace`'s, one shelf entry
			// up. `span_is_map_shaped` used to sit in `parser.v` with a
			// byte-identical body — a second copy of the rule, retired at
			// #1020 when the `code_tree.v` walker needed a cursor-free home
			// for it. This function is the same move for the same reason.
			if c == `{` && !map_literal_at_brace(src, i) {
				return false
			}
			// A structure span counts as a token only when WHITESPACE-
			// delimited on both sides — a glued span (`(1, 2)[0]`,
			// `(1, 2)(3, 4)`) keeps its historical one-item mixed reading
			// via the comma path, matching the slot rule's "glued runs are
			// one item" (the CXPath kind-test idiom depends on it).
			if i > body_start && !is_ws(src[i - 1]) {
				return false
			}
			j := skip_bracket_region(src, i)
			if j >= src.len {
				return false // unbalanced — let the comma path refuse loudly
			}
			if !is_ws(src[j]) && src[j] != `]` {
				return false
			}
			i = j
			tokens++
			at_tok_start = true
			continue
		}
		// A child element `[…]` (or `[#…#]` / `[|…|]`) is admitted as a list item
		// (mixed content, G-BODY-2). Skip its balanced span and count it.
		if c == `[` {
			i = skip_bracket_region(src, i)
			tokens++
			at_tok_start = true
			continue
		}
		// A `'`/`"` is a quoted-string token ONLY at a token start. A MID-token
		// quote is a literal apostrophe in bare prose (`it's`, `Bob's`) — read by
		// the bare-token branch, where try_autotype fails → the body is prose.
		if (c == `'` || c == `"`) && at_tok_start {
			tokens++
			i = skip_quoted_region(src, i)
			at_tok_start = true
			continue
		}
		if at_tok_start {
			tokens++
			start := i
			for i < src.len {
				cc := src[i]
				if cc == ` ` || cc == `\t` || cc == `\r` || cc == `\n` || cc == `]` || cc == `,` {
					break
				}
				i++
			}
			// The classifier tests the token as a SPAN of `src` — this is
			// pure lookahead whose result is thrown away, and materialising
			// every token as a string here was the heaviest allocation in the
			// §11.6 gate-15 profile: a body of N tokens paid N `bytestr()`
			// calls before the real parse re-read the same N tokens (#804).
			span := src[start..i]
			if try_autotype_bytes(span) == none {
				// I1 row 9 (L78): a variable-hole token `$name` is
				// SELF-DELIMITING — it joins the [L25b] discrete class
				// exactly like a quoted string, so `[+ $x 2]` is a hole
				// plus a typed int, not prose.
				if !is_hole_token_bytes(span) {
					return false // a bareword → prose, not a typed-list item
				}
			}
			if tokens == 1 && span.len > 0 && is_name_start(span[0]) {
				// ASP-2: a name-shaped first token (`true`, `false`,
				// `null`) keeps the element reading when a structure
				// follows — HEADLESS position only (see the guard above);
				// in an element body the same token is just a bool/null
				// child (ASP-3).
				first_tok_namelike = true
			}
			at_tok_start = true
			continue
		}
		at_tok_start = false
		i++
	}
	return tokens >= 2
}

// ── The element-body PROSE RUN (#1029) ───────────────────────────────────────
//
// `typed_list_body_at` above is the SECOND of the element-body dispatch's three
// lanes. The dispatch is:
//
//   1. `body_is_flat_comma_array` → §9 [L25c] comma array   — DISCRETE items
//   2. `body_is_typed_list(false)` → §9 [L25a/b] typed list — DISCRETE items
//   3. otherwise                   → `parse_body`           — the PROSE lane
//
// In the prose lane a maximal run of bare value-run tokens is ONE Text item:
// `[the quick brown]` is the element `the` with a single Text "quick brown"
// (G-BODY-1, conformance 009/014 — one bareword that does not auto-type makes
// the whole body prose). The `code_tree.v` walker read the body one ITEM at a
// time and projected two scalar children, so it reported arity 2 where the
// document has 1 — an arity lie in the tree pane and in the source↔tree bridge
// that reads its `loc`s (#1029).
//
// Every question the prose lane asks was a `&Parser` method reading its own
// `pos`, so the cursor-free walker could not ask any of them: which lane the
// body takes (`body_is_flat_comma_array`), where a bare token ENDS
// (`lex_value_run`), what STARTS at a token boundary (`tok_peek_kind`), and
// whether a `$name` is a hole or text (`peek_hole_len`). All four get a
// cursor-free home here and every caller delegates — the same discipline
// `operator_head_len` (#976/#992), `triple_quote_prefix_len` (#999),
// `sequence_literal_at_paren` (#1000), `array_literal_at_bracket` /
// `map_literal_at_brace` (#1020) and `typed_list_body_at` (#1025) established.

// flat_comma_array_body_at reports whether the element body beginning at
// `body_start` is a §9 [L25c] comma-separated scalar body: it has a top-level
// comma and contains NO child-element / collection / entity introducer
// (`[` `(` `{` `&`) outside of quotes (those route through parse_body's
// mixed-content path instead, per §9 "no child elements"). Quote regions
// (single / double / triple) and line comments are skipped so their inner
// commas and brackets do not count. Pure lookahead — nothing is consumed.
//
// This is the FIRST lane of the element-body dispatch and therefore the first
// question the walker has to ask: a body with a top-level comma is discrete
// items, not prose, and coalescing it would report `[doc a, b]` as one text
// node where the parser builds an Array. `Parser.body_is_flat_comma_array` is
// now a one-line delegation.
pub fn flat_comma_array_body_at(src []u8, body_start int) bool {
	mut i := body_start
	mut saw_comma := false
	mut at_tok_start := true
	for i < src.len {
		c := src[i]
		if c == `]` { break } // body terminator (top level)
		if c == ` ` || c == `\t` || c == `\r` || c == `\n` {
			at_tok_start = true
			i++
			continue
		}
		// `#` at a token boundary opens a line comment (grammar [30b]); a
		// mid-token `#` is an ordinary byte. Skip the comment to EOL.
		if c == `#` && at_tok_start {
			i++
			for i < src.len && src[i] != `\n` { i++ }
			continue
		}
		// Any structural introducer disqualifies the flat-array fast path —
		// child elements, collection literals, and entities are mixed content.
		if c == `[` || c == `(` || c == `{` || c == `&` { return false }
		// A quote opens a string ONLY at a token start; a mid-token `'` is a
		// bare-prose apostrophe (`it's`) and must not swallow the following
		// comma — else this scan misses the array signal.
		if (c == `'` || c == `"`) && at_tok_start {
			i = skip_quoted_region(src, i)
			at_tok_start = false
			continue
		}
		if c == `,` { saw_comma = true }
		at_tok_start = false
		i++
	}
	return saw_comma
}

// token_kind_at classifies the STRUCTURAL kind of the token at `src[i]` from the
// leading byte(s) only — no cursor, nothing consumed. It assumes whitespace and
// line comments have already been skipped by the caller (the parse loops do
// this, preserving comments as nodes); a `#` reaching here is therefore treated
// as ordinary lexeme content.
//
// Anything that is not a bracket / quote / single-char sigil is reported as
// `.value_run`, the catch-all "lexeme run" — the parser then calls `tok_name`
// (head position) or `tok_value` (body position) to consume it. Quote openers are
// split into `.triple_span` (`'''` / `"""`) vs `.quote_run` (single `'` / `"`) so
// the dispatch matches the parser's existing two-way quote branch.
//
// This is the classifier `parse_body` DISPATCHES on, so it is also the classifier
// that decides whether a body item continues a prose run or breaks it — see
// `prose_run_break_at`. `Parser.tok_peek_kind` is now a one-line delegation
// (#1029); before that it read its own `p.pos`, so `code_tree.v` had no way to
// ask the run-boundary question and instead walked the body one item at a time.
pub fn token_kind_at(src []u8, i int) CxTokenKind {
	if i >= src.len {
		return .eof
	}
	b := src[i]
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
			n := if i + 1 < src.len { src[i + 1] } else { u8(0) }
			match n {
				`?` { return .ldirective }
				`#` { return .raw_span }
				`|` { return .block_span }
				else { return .lbrack }
			}
		}
		`'`, `"` {
			if i + 2 < src.len && src[i + 1] == b && src[i + 2] == b {
				return .triple_span
			}
			return .quote_run
		}
		`r` {
			// I1 L58 (stream 13): `r` GLUED to a triple quote opens a RAW
			// triple-quoted string in data mode too (one token grammar,
			// same rule as the program lexer). A bare `r` — or `r` before
			// anything but a triple quote — stays an ordinary lexeme run.
			if i + 3 < src.len && (src[i + 1] == `'` || src[i + 1] == `"`)
				&& src[i + 2] == src[i + 1] && src[i + 3] == src[i + 1] {
				return .triple_span
			}
			return .value_run
		}
		`:` {
			if i + 1 < src.len && src[i + 1] == `:` {
				return .double_colon
			}
			return .colon
		}
		else {
			return .value_run
		}
	}
}

// value_run_end reports the index just past the whitespace-or-`]`-terminated body
// token that starts at `src[start]`, or `start` itself on an empty run. This is
// the BODY-TOKEN boundary rule — the one that decides how much of the source one
// prose token covers. Semantics (verbatim from `lex_value_run`, which now
// delegates):
//   - mid-token `'`/`"` are literal bytes (bare prose like "it's broken");
//     a `'…'` at a body-item boundary is caught upstream in parse_body before
//     this point — reaching here means the quote sits inside a token. The
//     bracket-depth path still tracks quote nesting so predicate args like
//     `//x[name='foo']` keep their `'…'` regions atomic.
//   - a balanced `[...]` opened mid-token absorbs embedded ws and `]` until
//     depth returns to zero (e.g. `:enum=[v1 v2 v3]`).
//   - `[?` introduces a program form and ALWAYS breaks the run.
// The run may span `\n` (inside brackets/quotes).
//
// The walker needs it for the same reason the parser does, and it is load-bearing
// for exactly the mid-token cases: `[doc :enum=[v1 v2] rest here]` is ONE Text to
// the parser, and a walker scanning byte kinds instead of value runs read it as
// five items — an atom, an `=`, a typed-list array image, and two barewords.
pub fn value_run_end(src []u8, start int) int {
	mut i := start
	mut in_quote := u8(0)
	mut bracket_depth := 0
	for i < src.len {
		b := src[i]
		if in_quote != 0 {
			i++
			if b == in_quote { in_quote = 0 }
			continue
		}
		if bracket_depth > 0 {
			if b == `[` {
				bracket_depth++
			} else if b == `]` {
				bracket_depth--
				i++
				if bracket_depth == 0 { break }
				continue
			} else if b == `'` || b == `"` {
				in_quote = b
			}
			i++
			continue
		}
		if is_ws(b) || b == `]` { break }
		if b == `[` && i + 1 < src.len && src[i + 1] == `?` {
			break
		}
		if b == `[` {
			bracket_depth = 1
		}
		i++
	}
	return i
}

// hole_token_len reports the byte length of an authorable variable-hole token
// `$name` at `src[i]` (I1 row 9, L78), or none. A hole is `$` + NameStart
// NameChar* ENDING at a delimiter (whitespace / `]` / `,` / `)` / `}` / EOF).
// Any other continuation — a path step (`$x.y`, `$x/y`), a glued sigil, a bare
// `$` — is NOT a hole and stays on the text lane. The returned length includes
// the `$`.
//
// It is the run-boundary question for `$`: a hole is a discrete structural node
// and BREAKS a prose run, while `$x.y` is ordinary text INSIDE one.
// `Parser.peek_hole_len` is now a one-line delegation (#1029).
pub fn hole_token_len(src []u8, i int) ?int {
	if i + 1 >= src.len {
		return none
	}
	if !is_name_start(src[i + 1]) {
		return none
	}
	mut j := i + 2
	// A hole name is a SIMPLE name — the program-binding ident shape.
	// `.` and `:` are name chars in the data lexer (dotted atoms, QNames)
	// but a `$x.y` / `$x:y` spelling is a PATH/QName form, not a hole.
	for j < src.len && is_name_char(src[j]) && src[j] != `.` && src[j] != `:` {
		j++
	}
	if j < src.len {
		d := src[j]
		if !(is_ws(d) || d == `]` || d == `,` || d == `)` || d == `}`) {
			return none
		}
	}
	return j - i
}

// prose_run_break_at reports whether the body item starting at the token start
// `i` BREAKS a prose run — i.e. whether `parse_body` FLUSHES its text buffer
// there instead of appending the token's bytes to it. It is a reading of
// parse_body's own branch table, expressed over the shared classifiers so the
// two cannot drift on which bytes are an item and which are prose:
//
//   BREAK   `]` / EOF                    the body terminator
//   BREAK   `[`, `[?`, `[#`, `[|`        a child node — and the ONE case that
//                                        also contributes the join space
//   BREAK   `'`/`"`, `'''`/`"""`, `r'''` a quoted or triple-quoted string
//   BREAK   `&`                          an entity reference
//   BREAK   `(…)` that IS a sequence literal   (`sequence_literal_at_paren`)
//   BREAK   `{…}` that IS a map literal        (`map_literal_at_brace`)
//   BREAK   `$name` that IS a hole             (`hole_token_len`)
//   CONTINUE everything else — including `,` `=` `:` `::` `*` `#` `)` `}`, a
//            comma-less `(x)`, a `{text}` run, and `$x.y`, every one of which
//            falls to parse_body's bare-token branch and joins the run.
//
// `[; … ]` is NOT a break and NOT an item: a block comment inside a bare text
// run is lexical trivia (lexicon.ebnf §1 [L2]/[L3]) and #469 forbids splitting
// the run on it in those words — the run continues across it with erasure
// semantics (`a [; c ] b` ≡ `a b`). The caller skips the span and keeps
// accumulating.
pub fn prose_run_break_at(src []u8, i int) bool {
	k := token_kind_at(src, i)
	if k == .eof || k == .rbrack {
		return true
	}
	if k.is_bracket_open() {
		if k == .lbrack && i + 1 < src.len && src[i + 1] == `;` {
			return false // `[; … ]` — trivia, see above
		}
		return true
	}
	if k == .quote_run || k == .triple_span || k == .amp {
		return true
	}
	if k == .lparen {
		return sequence_literal_at_paren(src, i)
	}
	if k == .lbrace {
		return map_literal_at_brace(src, i)
	}
	if src[i] == `$` {
		if _ := hole_token_len(src, i) { return true }
		return false
	}
	return false
}

// ── The at-token-start quote rule for BALANCED-SPAN scans (#1039) ─────────────
//
// span_token_start_at reports whether `src[i]` stands at a TOKEN START for a
// scan that began at the delimiter `span_start` — the single question a
// balanced-span scanner has to ask before it may read a `'`/`"` as a string
// OPENER.
//
// It has to ask, because a `'` is two different bytes in CX. At a token start
// it opens a quoted region; MID-token it is a literal apostrophe in bare prose
// (`it's`, `Bob's`, `don't`), which the data parser reads as ordinary Text and
// which a span scan must therefore step over as an ordinary byte. A scanner
// that takes the mid-token one as an opener runs its "string" past the span's
// own closing delimiter, miscounts depth, and reports the span UNBALANCED —
// the #1039 symptom: `[doc it's here]` recovering as
// `{"kind":"element","name":"unbalanced"}` in the tree pane while the parser
// reads the element `doc` with one Text item `it's here`.
//
// A token starts at the span's own opening delimiter, and after any bracket
// opener, any whitespace byte, a `,` or an `=` — nothing else. The predicate is
// byte-LOCAL (it reads only `src[i - 1]`), and that is exactly equivalent to
// the running `at_tok_start` flag `skip_bracket_region` carried before this
// shelf entry existed: that flag was set true on precisely those bytes and
// false on every other, INCLUDING the byte after a skipped quoted region (a
// closing quote, which is not in the set) and after a closing delimiter (also
// not in the set). A scanner never inspects a position inside a region it
// skipped whole, so no interior byte can be misread as the predecessor.
//
// Single home of the rule, per the shelf discipline above: `skip_bracket_region`
// (parser.v) is the spelling that HAD it, and `find_matching_bracket` /
// `find_matching_paren` / `find_matching_brace` (code_tree.v) are the three that
// did not — three copies of a balanced-span scan that must agree with the
// parser's byte for byte, or the walker reports an arity the document does not
// have. They all ask this one now.
//
// NOT the rule the body-DISPATCH scanners use: `flat_comma_array_body_at` and
// `typed_list_body_at` restart a token on whitespace ONLY (a `,` or `=` does not
// start one there, because those scanners are counting top-level separators, not
// walking a delimiter stack). Those are deliberately different questions and keep
// their own inline flag.
pub fn span_token_start_at(src []u8, i int, span_start int) bool {
	if i <= span_start {
		return true
	}
	if i > src.len {
		return false
	}
	p := src[i - 1]
	return p == `[` || p == `(` || p == `{` || p == ` ` || p == `\t` || p == `\r`
		|| p == `\n` || p == `,` || p == `=`
}

// ── The TOP-LEVEL text run (doc-top / mixed-text mode, #1040) ────────────────
//
// top_text_run_end scans the top-level text run starting at `start` and returns
// `(end, terminator)`: the index one past the run's last byte, and the byte that
// stopped it — `[` (node start), `&` (entity-ref start), `]` (a depth-0 stray
// close, grammar GR-STRAY-CLOSE), `-` (a `---` document separator at line
// start), or 0 for EOF.
//
// THIS IS A DIFFERENT RULE FROM THE ELEMENT-BODY PROSE LANE, in a different
// position. `parse_body`'s run coalesces a maximal sequence of bare VALUE-RUN
// tokens and breaks at every structural item (`prose_run_break_at`, #1029);
// this run is VERBATIM — it swallows quotes, `(`, `{`, `$`, `/`, `#`, `,`, `=`
// and every internal whitespace byte exactly as authored, and stops only at the
// four terminators above. `the quick brown` at top level is ONE Text whose value
// is those fifteen bytes; `a  b` keeps BOTH spaces where the body lane collapses
// them; `hello world # note` keeps the `#` as content, because a comment is only
// a comment at the comment-eligible position BEFORE a run starts.
//
// Single home of the rule: `Parser.read_top_text_run` is now the position
// bookkeeping (the `advance()` loop that keeps line/col, and the
// editor-convention strip of one trailing newline when the run reached EOF or a
// `---`) wrapped around this scan, which it delegates to provably — the retired
// loop and this one are identical after `p.src` → `src` and `p.pos` → `start`.
// `code_tree.v` could not ask the question at all, so the walker walked the top
// level one ITEM at a time and reported `the quick brown` as THREE scalar
// children where the document has one Text — the #1029 arity lie, in the
// position #1029 named and left (#1040).
pub fn top_text_run_end(src []u8, start int) (int, u8) {
	mut end := start
	mut line_start := start == 0 || (start > 0 && src[start - 1] == `\n`)
	mut terminator := u8(0)
	for end < src.len {
		b := src[end]
		if b == `[` || b == `&` {
			terminator = b
			break
		}
		if b == `]` {
			// A depth-0 `]` can never be text: BareValue [L70] excludes it,
			// so it is a structural stray close (grammar GR-STRAY-CLOSE).
			// Stop the run; the caller decides. (#289 — absorbing it here let
			// `cx fmt`'s data fallback silently accept, and mangle, program
			// files the program reader rejects.)
			terminator = b
			break
		}
		if line_start && end + 3 <= src.len
			&& src[end] == `-` && src[end + 1] == `-` && src[end + 2] == `-` {
			terminator = `-`
			break
		}
		line_start = b == `\n`
		end++
	}
	return end, terminator
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
