module cx

// lib_parser.v — `[?lib]` surface-text → LibNode parser (Phase 2.12 Part 3).
//
// Per (`[?lib]` hybrid resolver) the parser produces the
// spec-canonical `LibNode` AST defined in lib_node.v. This file covers
// grammar productions [149]–[151]:
//
//   [149] LibDirective ::= '[?lib' S Resolver ( S LibModifier )* S? ']'
//   [150] Resolver     ::= QuotedFilePath | QuotedRegisteredName | QuotedHttpsUrl
//   [151] LibModifier  ::= ':as'   S Name
//                       |  ':only' S '(' S? Name ( S Name )* S? ')'
//                       |  ':in-memory'      /* deferred — D5.2/D5.3 */
//                       |  ':version' S QuotedString  /* deferred — D8 */
//
// Resolver-kind detection:
//   - starts with `./` / `../` / `/`     → ResolverKind.file_path
//   - starts with `https://`             → ResolverKind.https_url
//   - starts with `http://`              → CXLIB_INSECURE_TRANSPORT
//                                          (raises at parse-time per D2)
//   - anything else                      → ResolverKind.registered_name
//
// Validation contract enforced here:
//   - `[?lib]` head prefix required; trailing whitespace after `[?lib`
//     required to distinguish from `[?libx …]`.
//   - Resolver MUST be a single-quoted or double-quoted string —
//     absent / malformed → CXLIB_PARSE.
//   - Resolver content MUST be non-empty.
//   - `http://` resolver → CXLIB_INSECURE_TRANSPORT
//     (informational — surfaces as `cx-err:CXER0208` at the
//     loader boundary in Phase 2.14).
//   - Modifiers `:as` / `:only` admitted in any order; duplicates
//     raise CXLIB_PARSE.
//   - Unknown `:LABEL` raises CXLIB_UNKNOWN_MODIFIER.
//   - `:as` MUST be followed by a bareword name — absent → CXLIB_PARSE.
//   - `:only` MUST be `:only ( a b c )` — empty list / unbalanced
//     parens → CXLIB_PARSE.
//   - The deferred `:in-memory` / `:version` modifiers are explicitly
//     recognised and surfaced as CXLIB_UNKNOWN_MODIFIER per Phase
//     2.12 Part 3 scope (the slot reservation is grammar-only at
//     the first release).
//
// Out of scope at Phase 2.12 Part 3 (deferred):
//   - Loader semantics — file read, registered lookup, HTTPS fetch,
//     transitive graph walk, SRI verification — Phase 2.13 / 2.14.
//   - Insecure-transport raise as CXER0208 (parser raises the
//     CXLIB_INSECURE_TRANSPORT error code; the loader maps to
//     CXER0208 at the surface).
//   - `cx.lock` consultation — Phase 2.14.
//   - `:version` body-shape parsing (semver / range) — deferred.
//
// Cross-references:
//   - spec/grammar.ebnf productions [149]–[151]
//   - spec/code.md §12.1 (normative semantics)
//   - vcx/cx/lib_node.v (Phase 2.12 Part 3 LibNode AST)
//   - vcx/cx/def_parser.v + vcx/cx/const_parser.v
//     (Z1/Z2 siblings — cursor + shielded scan convention)

// ── Internal cursor ───────────────────────────────────────────────────────────

// LibParseCursor is a private byte-position cursor over the source
// string. Same shape as DefParseCursor / ConstParseCursor /
// MatchParseCursor / ModifyParseCursor.
struct LibParseCursor {
mut:
	src []u8
	pos int
}

@[inline]
fn (c &LibParseCursor) at_end() bool {
	return c.pos >= c.src.len
}

@[inline]
fn (c &LibParseCursor) peek() u8 {
	if c.pos < c.src.len {
		return c.src[c.pos]
	}
	return 0
}

@[inline]
fn (mut c LibParseCursor) advance() {
	if c.pos < c.src.len {
		c.pos++
	}
}

@[inline]
fn lib_is_space(b u8) bool {
	return b == ` ` || b == `\t` || b == `\n` || b == `\r`
}

@[inline]
fn lib_is_name_start(b u8) bool {
	return (b >= `a` && b <= `z`) || (b >= `A` && b <= `Z`) || b == `_`
}

@[inline]
fn lib_is_name_cont(b u8) bool {
	return lib_is_name_start(b) || (b >= `0` && b <= `9`) || b == `-` || b == `?`
		|| b == `!`
}

fn (mut c LibParseCursor) skip_ws() {
	for !c.at_end() && lib_is_space(c.peek()) {
		c.advance()
	}
}

// ── Public entry point ────────────────────────────────────────────────────────

// The canonical set of modifier labels admitted on `[?lib]` per
// grammar [151]. `in-memory` / `version` are reserved slots —
// recognising them as modifier-labels
// at the parse layer is a future patch; the Phase 2.12 Part 3
// surface treats them as CXLIB_UNKNOWN_MODIFIER.
const lib_modifier_labels = ['as', 'only']

// parse_lib parses a `[?lib …]` surface form into a LibNode per
// The input MUST be the full directive surface — opening
// `[?lib` through closing `]`.
//
// On success the returned LibNode has:
// resolver_kind set detection rules.
//   - resolver_source set to the verbatim contents of the resolver
//     quoted string (bytes INSIDE the quotes).
//   - alias set when `:as ALIAS` is present; none otherwise.
//   - only_imports set when `:only ( a b c )` is present; none otherwise.
//   - source set to the verbatim input.
//   - loc set to span 0..source.len.
//
// Errors:
//   - "CXLIB_PARSE: missing [?lib prefix"
//   - "CXLIB_PARSE: expected whitespace after [?lib"
//   - "CXLIB_PARSE: missing resolver string"
//   - "CXLIB_PARSE: resolver must be a quoted string"
//   - "CXLIB_PARSE: empty resolver string"
//   - "CXLIB_PARSE: unterminated resolver string"
//   - "CXLIB_PARSE: missing closing ]"
//   - "CXLIB_PARSE: unexpected trailing input after ]"
//   - "CXLIB_PARSE: duplicate :as modifier"
//   - "CXLIB_PARSE: :as missing alias name"
//   - "CXLIB_PARSE: duplicate :only modifier"
//   - "CXLIB_PARSE: :only missing opening `(`"
//   - "CXLIB_PARSE: :only missing closing `)`"
//   - "CXLIB_PARSE: :only requires at least one name"
//   - "CXLIB_UNKNOWN_MODIFIER: unknown modifier `:LABEL`"
// "CXLIB_INSECURE_TRANSPORT: HTTP scheme refused (use https://)"
pub fn parse_lib(source string) !LibNode {
	if source.len == 0 {
		return error('CXLIB_PARSE: empty input')
	}
	mut c := LibParseCursor{
		src: source.bytes()
		pos: 0
	}

	// Opening `[?lib`.
	if !lib_consume_literal(mut c, '[?lib') {
		return error('CXLIB_PARSE: missing [?lib prefix')
	}
	// Require a separator after the prefix so we don't accept `[?libx …]`.
	if c.at_end() || (!lib_is_space(c.peek()) && c.peek() != `]`) {
		return error('CXLIB_PARSE: expected whitespace after [?lib')
	}

	c.skip_ws()
	if c.at_end() {
		return error('CXLIB_PARSE: missing resolver string')
	}
	if c.peek() == `]` {
		return error('CXLIB_PARSE: missing resolver string')
	}
	if c.peek() != `'` && c.peek() != `"` {
		return error('CXLIB_PARSE: resolver must be a quoted string at position ${c.pos}, got `${c.peek().ascii_str()}`')
	}
	resolver_source := lib_read_quoted_string(mut c)!
	if resolver_source.len == 0 {
		return error('CXLIB_PARSE: empty resolver string')
	}

	// Classify resolver-kind.
	kind := lib_classify_resolver(resolver_source)!

	// Modifiers (zero or more) before the closing `]`.
	mut alias := ?string(none)
	mut only_imports := ?[]string(none)
	for {
		c.skip_ws()
		if c.at_end() {
			return error('CXLIB_PARSE: missing closing ]')
		}
		if c.peek() == `]` {
			break
		}
		// Attribute-modifier form: `as=NAME` (dual-accept with the
		// legacy `:as NAME` slot). A bareword followed by `=` is a scalar
		// modifier attribute.
		if lib_is_name_start(c.peek()) {
			attr := lib_read_label(mut c)
			if c.at_end() || c.peek() != `=` {
				return error('CXLIB_PARSE: bareword `${attr}` is not a valid modifier — use `attr=value` or `:LABEL`')
			}
			c.advance() // consume `=`
			match attr {
				'as' {
					if alias != none {
						return error('CXLIB_PARSE: duplicate as modifier')
					}
					name := lib_read_name(mut c)
					if name.len == 0 {
						return error('CXLIB_PARSE: as= missing alias name')
					}
					alias = name
				}
				else {
					return error('CXLIB_UNKNOWN_MODIFIER: unknown attribute modifier `${attr}=…` (expected `as`)')
				}
			}
			continue
		}
		if c.peek() != `:` {
			return error('CXLIB_PARSE: expected modifier `:LABEL`, `attr=value`, or `]` at position ${c.pos}, got `${c.peek().ascii_str()}`')
		}
		kw_start := c.pos
		c.advance() // consume `:`
		kw := lib_read_label(mut c)
		if kw.len == 0 {
			return error('CXLIB_PARSE: malformed modifier keyword at position ${kw_start}')
		}
		if kw !in lib_modifier_labels {
			return error('CXLIB_UNKNOWN_MODIFIER: unknown modifier `:${kw}` (expected one of ${lib_modifier_labels.join(", ")})')
		}
		match kw {
			'as' {
				if alias != none {
					return error('CXLIB_PARSE: duplicate :as modifier')
				}
				c.skip_ws()
				name := lib_read_name(mut c)
				if name.len == 0 {
					return error('CXLIB_PARSE: :as missing alias name')
				}
				alias = name
			}
			'only' {
				if only_imports != none {
					return error('CXLIB_PARSE: duplicate :only modifier')
				}
				names := lib_parse_only_list(mut c)!
				only_imports = names.clone()
			}
			else {
				return error('CXLIB_UNKNOWN_MODIFIER: unknown modifier `:${kw}`')
			}
		}
	}

	// Consume closing `]`.
	if c.at_end() || c.peek() != `]` {
		return error('CXLIB_PARSE: missing closing ]')
	}
	c.advance()

	// Reject trailing input past the closing `]`.
	c.skip_ws()
	if !c.at_end() {
		return error('CXLIB_PARSE: unexpected trailing input after ]: ${source[c.pos..]}')
	}

	return LibNode{
		resolver_kind:   kind
		resolver_source: resolver_source
		alias:           alias
		only_imports:    only_imports
		source:          source
		loc:             LibLoc{
			start: 0
			end:   source.len
		}
	}
}

// ── Sub-readers ───────────────────────────────────────────────────────────────

// lib_consume_literal advances the cursor past the given literal
// string when it matches at the current position. Returns true on
// consume.
fn lib_consume_literal(mut c LibParseCursor, lit string) bool {
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

// lib_read_label reads a `[_A-Za-z][_A-Za-z0-9-]*` identifier from
// the cursor and returns the bytes. Used for modifier-keyword
// recognition (e.g. `as`, `only`).
fn lib_read_label(mut c LibParseCursor) string {
	start := c.pos
	if c.at_end() || !lib_is_name_start(c.peek()) {
		return ''
	}
	c.advance()
	for !c.at_end() && lib_is_name_cont(c.peek()) {
		c.advance()
	}
	return c.src[start..c.pos].bytestr()
}

// lib_read_name reads an alias / import name (bareword identifier
// — same shape as a label). Allows `?` / `!` suffixes per CX
// naming convention.
fn lib_read_name(mut c LibParseCursor) string {
	return lib_read_label(mut c)
}

// lib_read_quoted_string reads a single- or double-quoted string at
// the current cursor position and returns its decoded contents. The
// cursor MUST be sitting on the opening quote; it is advanced past
// the closing quote on success.
//
// Escape handling is minimal at this layer — `\\` and `\<quote>` are
// recognised; everything else passes through verbatim. The resolver
// string never contains structurally-significant escapes in
// practice, so this is sufficient.
fn lib_read_quoted_string(mut c LibParseCursor) !string {
	if c.at_end() {
		return error('CXLIB_PARSE: unexpected end of input — missing resolver string')
	}
	quote := c.peek()
	if quote != `'` && quote != `"` {
		return error('CXLIB_PARSE: resolver must be a quoted string')
	}
	c.advance() // consume opening quote
	start := c.pos
	mut out := []u8{}
	for !c.at_end() && c.peek() != quote {
		if c.peek() == `\\` {
			c.advance()
			if c.at_end() {
				return error('CXLIB_PARSE: unterminated resolver string')
			}
			esc := c.peek()
			match esc {
				`\\` { out << u8(`\\`) }
				`'` { out << u8(`'`) }
				`"` { out << u8(`"`) }
				`n` { out << u8(`\n`) }
				`t` { out << u8(`\t`) }
				`r` { out << u8(`\r`) }
				else { out << u8(`\\`); out << esc }
			}
			c.advance()
			continue
		}
		out << c.peek()
		c.advance()
	}
	if c.at_end() {
		return error('CXLIB_PARSE: unterminated resolver string starting at position ${start}')
	}
	c.advance() // consume closing quote
	return out.bytestr()
}

// lib_classify_resolver maps a resolver source string to a
// ResolverKind, raising CXLIB_INSECURE_TRANSPORT
// for `http://` prefixes per D2.
fn lib_classify_resolver(s string) !ResolverKind {
	if s.starts_with('./') || s.starts_with('../') || s.starts_with('/') {
		return ResolverKind.file_path
	}
	if s.starts_with('https://') {
		return ResolverKind.https_url
	}
	if s.starts_with('http://') {
		return error('CXLIB_INSECURE_TRANSPORT: HTTP scheme refused: ${s}')
	}
	if s.starts_with('pkg:') {
		return ResolverKind.pkg_url
	}
	return ResolverKind.registered_name
}

// lib_parse_only_list parses a `:only ( a b c )` list per grammar
// [151]. The cursor MUST be sitting at the byte AFTER the `only`
// keyword (i.e. on the whitespace before `(` or directly on the
// `(`). Returns the list of import names in source order.
//
// Empty lists (`:only ()`) raise CXLIB_PARSE
// the empty form has no semantically-distinct interpretation from
// "no `:only` modifier" and is treated as a likely user error.
fn lib_parse_only_list(mut c LibParseCursor) ![]string {
	c.skip_ws()
	if c.at_end() || c.peek() != `(` {
		return error('CXLIB_PARSE: :only missing opening `(`')
	}
	c.advance() // consume `(`
	mut names := []string{}
	for {
		c.skip_ws()
		if c.at_end() {
			return error('CXLIB_PARSE: :only missing closing `)`')
		}
		if c.peek() == `)` {
			c.advance()
			break
		}
		if !lib_is_name_start(c.peek()) {
			return error('CXLIB_PARSE: :only expected import name at position ${c.pos}, got `${c.peek().ascii_str()}`')
		}
		name := lib_read_name(mut c)
		if name.len == 0 {
			return error('CXLIB_PARSE: :only malformed import name')
		}
		names << name
	}
	if names.len == 0 {
		return error('CXLIB_PARSE: :only requires at least one name')
	}
	return names
}
