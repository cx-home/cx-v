module cx

import strconv

// ── Parser struct ─────────────────────────────────────────────────────────────

// max_recursion_depth bounds nesting in parse_element to prevent
// stack-overflow DoS on adversarial input. Default per
// spec/policies.md §5.4. Configurable in a future minor revision.
const max_recursion_depth = 64

struct Parser {
mut:
	src   []u8
	pos   int
	line  int
	col   int
	depth int  // current element-nesting depth; tracked by parse_element
	// declared_templates tracks `?def name …` declarations seen so far
	// during parsing. Used by parse_pi_or_decl to distinguish template-
	// call invocations `[?template-name args]` (parse as EvalDirective)
	// from foreign processing instructions like `[?php …]` (parse as
	// PI). Per spec/eval.md §3.7 templates must be declared before use;
	// this set is populated as ?def directives are encountered.
	declared_templates map[string]bool
	// quote_scratch is a parser-owned reusable byte buffer used by
	// read_quoted / read_quoted_text — every call clears its length
	// to zero (keeping capacity), writes the quoted bytes in, then
	// returns `.bytestr()`. Skips the per-call `[]u8{cap:32}` vector
	// allocation; the bench corpus on §11.6 gate-15 makes ~2.2 M such
	// calls (attribute values in JSON-shape `[user :id N :name "…"]`
	// rows), so the per-parse allocator pressure drops by that count.
	// Non-reentrant: parser is single-threaded and these functions
	// don't recursively invoke themselves.
	quote_scratch []u8
	// name_pool is a parser-local intern table for element / attribute
	// names. Per the §11.6 gate-15 JSON-shape corpus (~1.1 M records
	// × {`user`, `id`, `name`, `host`, `port`, `active`, `ratio`}),
	// `read_name` would otherwise allocate ~7.7 M short strings that
	// all dedupe to a tiny working set. The pool is a flat slice
	// (small-N case, ≤ ~50 distinct names on typical documents);
	// lookup is a linear byte-equality scan against the parser's
	// source buffer, so a hit allocates zero. On a miss we allocate
	// one canonical string and append it. Cleared per-parse via
	// `new_parser`; not reentrant across parses (no `cx.parse` re-
	// enters its own outer call). For deeply heterogeneous corpora
	// the linear scan degrades to O(N) per name; in practice CX
	// documents have few distinct names and the scan is faster than
	// a `map[string]string` lookup that has to allocate the key
	// string first.
	name_pool []string
	// attr_scratch is a parser-owned reusable byte buffer used by
	// `read_token_for_attr_into` for attribute-value tokens. The
	// §11.6 gate-15 JSON-shape corpus has ~6.6 M attribute-value
	// reads; routing the unquoted ones through this scratch avoids
	// ~4.4 M `bytestr()` allocations when the token auto-types to
	// an int / float / bool / null (the value is parsed straight
	// from the bytes; only string-valued tokens still allocate).
	attr_scratch []u8
	// in_schema marks that the current document is a schema (`.cxs`):
	// set when a `[?cx schema-of …]` / `[?cx schema-name …]` /
	// `[?cx schema-mode …]` / `[?cx frag …]` pragma is parsed. While set,
	// `:T` type-tag validation (/ CXER0107) is suspended,
	// because the schema sublanguage (spec/schema.md §51–56) deliberately
	// reuses the `:T` slot for its own content-model vocabulary
	// (`:elem`, `:mixed`, `:scalar`, `:ref`) — those are not CXDM scalar
	// types but are legitimate in schema position. The schema pragma
	// appears at the top of the document, before any element carrying a
	// `:T` slot, so this flag is set in time to gate every schema element.
	// (The `:T`-slot overload itself is slated for a schema-syntax
	// revisit; this flag is the precise context boundary in the meantime.)
	in_schema bool
	// prev_tok_end is the byte offset immediately after the last token the
	// token cursor consumed (Phase 2, cxparse unification — see token_cursor.v).
	// It backs `tok_adjacent_to_prev`: after the parser positions on the next
	// token (post ws/comment skip), adjacency holds iff `p.pos == prev_tok_end`
	// (no whitespace was skipped). This reconstructs the data parser's
	// significant-whitespace `had_ws` flag from token adjacency, mirroring the
	// program parser's `cur_adjacent_to_prev` (code/parser.v:860). Updated by
	// every cursor consume helper; 0 until the first consume.
	prev_tok_end int
}

fn new_parser(src string) Parser {
	return Parser{
		src:   src.bytes()
		pos:   0
		line:  1
		col:   1
		depth: 0
		declared_templates: map[string]bool{}
		quote_scratch: []u8{cap: 64}
		name_pool:     []string{cap: 32}
		attr_scratch:  []u8{cap: 64}
	}
}

// intern_name_bytes looks up the byte slice `[start..end]` of the parser's
// source buffer in the name_pool. On a hit, returns the canonical string
// without any allocation. On a miss, allocates one string from the source
// bytes, appends it to the pool, and returns it. The pool is a small
// flat slice: typical CX documents have ≤ ~50 distinct element /
// attribute names, so linear scan is faster than `map[string]string`
// (which would force constructing a string key before lookup, defeating
// the point). See `Parser.name_pool` docstring for rationale.
@[inline]
fn (mut p Parser) intern_name_src(start int, end int) string {
	n := end - start
	for s in p.name_pool {
		if s.len != n { continue }
		mut eq := true
		for i in 0 .. n {
			if s[i] != p.src[start + i] {
				eq = false
				break
			}
		}
		if eq { return s }
	}
	// Miss: allocate one canonical string and append to pool.
	mut buf := []u8{cap: n}
	for i in 0 .. n {
		buf << p.src[start + i]
	}
	out := buf.bytestr()
	p.name_pool << out
	return out
}

// ── Position tracking ─────────────────────────────────────────────────────────

fn (p &Parser) peek() u8 {
	if p.pos < p.src.len {
		return p.src[p.pos]
	}
	return 0
}

fn (p &Parser) peek2() u8 {
	if p.pos + 1 < p.src.len {
		return p.src[p.pos + 1]
	}
	return 0
}

fn (p &Parser) at_end() bool {
	return p.pos >= p.src.len
}

fn (mut p Parser) advance() {
	if p.pos >= p.src.len { return }
	b := p.src[p.pos]
	p.pos++
	if b == `\n` {
		p.line++
		p.col = 1
	} else {
		p.col++
	}
}

fn (p &Parser) make_error(msg string) string {
	return '${p.line}:${p.col}: ${msg}'
}

// ── Whitespace ────────────────────────────────────────────────────────────────

fn (mut p Parser) skip_ws() {
	for !p.at_end() {
		b := p.peek()
		if b == ` ` || b == `\t` || b == `\r` || b == `\n` {
			p.advance()
		} else {
			break
		}
	}
}

// peek_skip_ws returns the next non-whitespace byte without advancing
// the parser position. Returns 0 if only whitespace remains. Used to
// classify document content before deciding whether to enter node-
// parsing mode or bare-text mode (doc-top rule).
fn (mut p Parser) peek_skip_ws() u8 {
	mut i := p.pos
	for i < p.src.len {
		b := p.src[i]
		if b == ` ` || b == `\t` || b == `\r` || b == `\n` { i++ } else { return b }
	}
	return 0
}

// read_quoted_for_doc reads a top-level quoted-scalar (single, double,
// or triple-quoted in either delimiter). Position is at the opening
// quote. Returns the string value.
fn (mut p Parser) read_quoted_for_doc() !string {
	if p.pos + 2 < p.src.len && p.src[p.pos] == `'` && p.src[p.pos+1] == `'` && p.src[p.pos+2] == `'` {
		return p.read_triple_quoted_str()!
	}
	if p.pos + 2 < p.src.len && p.src[p.pos] == `"` && p.src[p.pos+1] == `"` && p.src[p.pos+2] == `"` {
		return p.read_triple_double_quoted_str()!
	}
	return p.read_quoted()!
}

// read_top_text_run consumes input verbatim from the current position
// until: a `[` (node start), `&` (entity-ref start), `---` document
// separator at line start, or EOF. Returns the bytes read and the
// terminator that stopped the read (`[`, `&`, `-`, or 0 for EOF).
//
// When the stop reason is EOF or `---`, strips exactly one trailing
// newline (editor convention — same as the legacy bare-text-document
// rule). When the stop reason is `[` or `&`, no stripping: the author
// placed those bytes as deliberate separators between text and node.
//
// Used by parse_document to support both bare-text documents (the
// doc-top rule) and CX code that interleave literal text with
// `[?=…]` / `[?Name …]` forms at the top level (spec/eval.md §2.1).
fn (mut p Parser) read_top_text_run() (string, u8) {
	start := p.pos
	mut end := p.pos
	mut line_start := p.pos == 0 || (p.pos > 0 && p.src[p.pos-1] == `\n`)
	mut terminator := u8(0)
	for end < p.src.len {
		b := p.src[end]
		if b == `[` || b == `&` {
			terminator = b
			break
		}
		if b == `]` {
			// A depth-0 `]` can never be text: BareValue [L70] excludes it,
			// so it is a structural stray close (grammar GR-STRAY-CLOSE).
			// Stop the run; the caller raises. (#289 — absorbing it here let
			// `cx fmt`'s data fallback silently accept, and mangle, program
			// files the program reader rejects.)
			terminator = b
			break
		}
		if line_start && end + 3 <= p.src.len
			&& p.src[end] == `-` && p.src[end+1] == `-` && p.src[end+2] == `-` {
			terminator = `-`
			break
		}
		line_start = b == `\n`
		end++
	}
	// Advance parser position so callers see updated line/col.
	for p.pos < end {
		p.advance()
	}
	mut out := p.src[start..end].bytestr()
	// Only strip when the run reached EOF or a doc separator. A `[`/`&`
	// terminator means more program nodes follow; preserve the trailing
	// newline so it lands in the rendered output between Text and node.
	if terminator != `[` && terminator != `&` {
		if out.len > 0 && out[out.len - 1] == `\n` {
			out = out[..out.len - 1]
		}
	}
	return out, terminator
}

// skip_ws_and_line_comments skips whitespace AND v3.4 line comments
// (# to end-of-line). Used at comment-eligible positions only:
// document top level, prolog, between root elements, and between
// element body items.
//
// NOT used inside DTD declarations like [!ATTLIST ...] where '#' is
// a syntax sentinel for #REQUIRED, #IMPLIED, #FIXED, #PCDATA. NOT
// used inside ElementMeta where '#' could conflict with future
// extensions. The disambiguation is by call site, per spec rule
// [30b] ("at comment-eligible positions").
fn (mut p Parser) skip_ws_and_line_comments() {
	for !p.at_end() {
		b := p.peek()
		if b == ` ` || b == `\t` || b == `\r` || b == `\n` {
			p.advance()
		} else if b == `#` {
			p.skip_line_comment()
		} else {
			break
		}
	}
}

// skip_ws_collecting_comments behaves exactly like skip_ws_and_line_comments
// (skip whitespace + `#`-to-EOL line comments at a comment-eligible position)
// but PRESERVES each comment as a CommentNode appended to `sink` instead of
// discarding it. Used at the positions where a comment has a stable, round-
// trippable home in canonical layout — the document top level (prolog,
// between/after root nodes) and the line-broken body of a self-delimiting /
// typed-list element. This is what makes `cx fmt` lossless for comments
// (canonical.md §2.1) while strict `cx canonical` still strips them in
// canonicalize_doc. Positions whose canonical form is a single inline line
// (element head/attrs, inline `[a, b]` / `(…)` / `{…}` collections) keep using
// the discarding skip_ws_and_line_comments — a comment there has no canonical
// home and cannot round-trip.
fn (mut p Parser) skip_ws_collecting_comments(mut sink []Node) {
	for !p.at_end() {
		b := p.peek()
		if b == ` ` || b == `\t` || b == `\r` || b == `\n` {
			p.advance()
		} else if b == `#` {
			val := p.read_line_comment_value()
			sink << CommentNode{ value: val, is_line: true }
		} else {
			break
		}
	}
}

// skip_line_comment consumes a line comment from '#' through the next
// '\n' (or end of input). The leading '#' must be the current position.
fn (mut p Parser) skip_line_comment() {
	// Consume '#'
	p.advance()
	for !p.at_end() {
		b := p.peek()
		if b == `\n` {
			break
		}
		p.advance()
	}
}

// read_line_comment_value consumes a line comment from '#' through the
// next '\n' and returns the comment body (text after '#', leading space
// trimmed, no trailing newline). The leading '#' must be the current
// position. Used at positions where the comment should be preserved as
// a CommentNode (vs skip_line_comment which discards it).
fn (mut p Parser) read_line_comment_value() string {
	p.advance() // consume '#'
	// Skip one leading space if present (cosmetic: `# value` round-trips
	// without the leading space accumulating each pass).
	if !p.at_end() && p.peek() == ` ` { p.advance() }
	mut s := []u8{}
	for !p.at_end() {
		b := p.peek()
		if b == `\n` { break }
		s << b
		p.advance()
	}
	return s.bytestr()
}

// is_ws now lives in cx/lexical.v (the shared cxparse whitespace predicate,
// used by both the data scanner and the program lexer's ws skip).

// ── Public parse entry points ─────────────────────────────────────────────────

pub fn parse(src string) !Document {
	mut p := new_parser(src)
	doc := p.parse_document()!
	// Lexer-driven multi-doc detection: parse_document consumes a `---`
	// that occurs inside an element/RawText payload (the lexer treats it
	// as content) and stops ONLY at a genuine TOP-LEVEL `---` separator,
	// leaving p positioned at it. A cheap `src.contains('\n---\n')` guard
	// would false-positive on a `---` line inside a `[# … #]` RawText
	// payload (e.g. CX multi-doc *examples* under test). So: if, after
	// skipping trailing whitespace, input remains, the stop was a
	// top-level separator → genuine multi-doc.
	p.skip_ws()
	if !p.at_end() {
		return error('use parse_stream for multi-doc input')
	}
	return doc
}

pub fn parse_stream(src string) ![]Document {
	mut p := new_parser(src)
	mut docs := []Document{}
	for {
		p.skip_ws()
		if p.at_end() { break }
		doc := p.parse_document()!
		if doc.elements.len > 0 || doc.prolog.len > 0 || doc.doctype != none {
			docs << doc
		}
		p.skip_ws()
		if p.pos + 3 <= p.src.len && p.src[p.pos] == `-` && p.src[p.pos+1] == `-` && p.src[p.pos+2] == `-` {
			p.pos += 3
			p.col += 3
			// skip rest of separator line
			for !p.at_end() && p.src[p.pos] != `\n` {
				p.pos++
				p.col++
			}
		}
	}
	return docs
}

// ── ParseResult ───────────────────────────────────────────────────────────────

pub struct ParseResult {
pub mut:
	single   ?Document
	multi    ?[]Document
	is_multi bool
}

pub fn parse_cx(src string) !ParseResult {
	// Lexer-driven multi-doc detection (see parse() for rationale): parse a
	// single document; parse_document stops only at a genuine top-level
	// `---` separator (a `---` inside RawText is consumed as content). If
	// input remains after the first document, it's true multi-doc — reparse
	// via the stream machinery.
	mut p := new_parser(src)
	doc := p.parse_document()!
	p.skip_ws()
	if p.at_end() {
		return ParseResult{ single: doc, is_multi: false }
	}
	docs := parse_stream(src)!
	return ParseResult{ multi: docs, is_multi: true }
}

// ── Document parser ───────────────────────────────────────────────────────────

fn (mut p Parser) parse_document() !Document {
	mut prolog := []Node{}
	mut doctype := ?DoctypeDecl(none)
	mut elements := []Node{}
	// Tracks whether top-level text-runs are admitted (CX code mixed mode).
	// Declared up here so the prolog loop can switch the document into
	// mixed mode when the first non-prolog node is itself a CX code marker
	// (e.g. `[?=…] AFTER` — the prolog loop captures the interpolation
	// as elements[0] then breaks; without this flag the unified loop
	// below would reject the trailing prose).
	mut allow_top_text := false

	// Leading top-level comments precede the first node — collect them into the
	// prolog so they round-trip through `cx fmt` (emit_cx renders prolog first).
	p.skip_ws_collecting_comments(mut prolog)

	for {
		p.skip_ws_collecting_comments(mut prolog)
		if p.at_end() { break }
		// Prolog nodes are bracketed (`[?…]` directives, `[!DOCTYPE]`); a
		// non-bracket introducer ends the prolog. tok_peek_kind().is_bracket_open()
		// is exactly the former `peek() != \`[\`` test (a bracket kind iff `[`).
		if !p.tok_peek_kind().is_bracket_open() { break }
		if p.is_prolog_node() {
			if p.is_doctype_node() {
				p.advance() // '['
				p.advance() // '!'
				p.read_name()! // "DOCTYPE"
				dt := p.parse_doctype_inner()!
				doctype = dt
			} else {
				n := p.parse_node()!
				if is_prolog_node_type(n) {
					prolog << n
				} else {
					elements << n
					if n is InterpolationNode || n is EvalDirectiveNode {
						allow_top_text = true
					}
					break
				}
			}
		} else {
			break
		}
	}

	// v3.4 logfmt mode: if the first token after Prolog/Doctype is
	// `Name '='`, the entire document is a sequence of top-level
	// attributes (no element brackets). Wraps into a single synthetic
	// Element named `_` (the anonymous-record convention) so the rest
	// of the codebase, which assumes Documents contain Elements,
	// works unchanged.
	//
	// Only fires when no top-level Elements have been parsed yet
	// (elements is empty). Spec: grammar.ebnf [2].
	if elements.len == 0 && p.is_logfmt_start() {
		// v3.4 §9: each top-level newline-separated logfmt record
		// produces its own synthetic Element named '_'. Earlier
		// behavior merged all records into a single element with
		// last-write-wins attributes; that lost type fidelity per
		// record and made `cx --json` produce one object instead
		// of an array. Phase 7.56.
		for {
			p.skip_logfmt_inter_record()
			if p.at_end() { break }
			attrs := p.parse_logfmt_record()!
			if attrs.len > 0 {
				elements << Node(Element{ name: '_', attrs: attrs })
			}
		}
		mut doc := Document{ prolog: prolog, doctype: doctype, elements: elements }
		resolve_namespaces(mut doc)
		resolve_ids(doc)!
		return doc
	}

	// doc-top: a document with no prolog/element content yet may
	// begin with bare text (`hello world`, `1\n2\n3`), a quoted scalar
	// (`'hi'`, `"hi"`, `'''hi'''`), `[`/`&` node-start bytes, or EOF.
	// Quoted-scalar openers produce a single-node scalar document.
	// Non-bracket prose engages "mixed-text mode" — top-level Text runs
	// may interleave with bracketed nodes per spec/eval.md §2.1.
	if elements.len == 0 && !p.at_end() {
		b := p.peek_skip_ws()
		if b == `'` || b == `"` {
			p.skip_ws()
			val := p.read_quoted_for_doc()!
			elements << Node(ScalarNode{
				data_type: ScalarType.string_type
				value: ScalarValue(val)
			})
		} else if b == `{` {
			// cxparse bucket D: a top-level `{…}` map literal is a Map node,
			// not document text (uniform [G-NODE] dispatch). Guarded by
			// peek_is_map_literal_at_brace so a non-map brace run still falls
			// through to the bare-text path unchanged.
			p.skip_ws()
			if p.peek_is_map_literal_at_brace() {
				elements << p.parse_map_literal()!
			} else {
				text, _ := p.read_top_text_run()
				if text.len > 0 {
					elements << Node(TextNode{ value: text })
				}
				allow_top_text = true
			}
		} else if b == `]` {
			// A top-level `]` with no matching opener is a stray close — a
			// structural error, not document text (grammar GR-STRAY-CLOSE).
			return error(p.make_error('stray `]` with no matching `[` (cx-err:CXER0100)'))
		} else if b != `[` && b != `&` && b != 0 {
			// Leading bare text — collect run up to first `[`/`&`/`---`/EOF.
			text, _ := p.read_top_text_run()
			if text.len > 0 {
				// doc-top [G-NODE] dispatch (@CHOICE-1): a SINGLE bare token that
				// auto-types to a scalar is that typed scalar (`42` → int,
				// `:ok` → atom), mirroring the element sole-scalar rule. A multi-
				// token run (`hello world`, `1\n2\n3`) or a bareword (`a`) stays
				// prose Text. (M-DOC-2, G-NODE-3.)
				trimmed := text.trim_space()
				if trimmed.len > 0 && !trimmed.contains(' ') && !trimmed.contains('\t')
					&& !trimmed.contains('\n') && !trimmed.contains('\r') {
					if scalar := try_autotype(trimmed) {
						elements << Node(scalar)
					} else {
						elements << Node(TextNode{ value: text })
					}
				} else {
					elements << Node(TextNode{ value: text })
				}
			}
			allow_top_text = true
		}
	}

	for {
		if p.at_end() { break }
		// `---` separator: strict mode skips leading ws first (matches
		// legacy v3.x behavior); mixed mode requires line-start (text-run
		// already would have stopped there).
		if allow_top_text {
			if p.pos + 3 <= p.src.len
				&& (p.pos == 0 || p.src[p.pos-1] == `\n`)
				&& p.src[p.pos] == `-` && p.src[p.pos+1] == `-` && p.src[p.pos+2] == `-` {
				break
			}
			// Mixed-mode node introducer: a `[`-opener or `&` entity starts a
			// node (parse_node sub-dispatches); anything else is a top-level text
			// run. kind.is_bracket_open() || .amp == the former `c == \`[\` || \`&\``.
			if p.src[p.pos] == `]` {
				// Depth-0 `]` in mixed mode is the same structural stray close
				// as at doc-top (GR-STRAY-CLOSE): BareValue [L70] excludes `]`,
				// so it can never be prose. Absorbing it as text made the data
				// reading accept — and `cx fmt` mangle — program files whose
				// program reading is rejected (#289).
				return error(p.make_error('stray `]` with no matching `[` (cx-err:CXER0100)'))
			}
			k := p.tok_peek_kind()
			if k.is_bracket_open() || k == .amp {
				n := p.parse_node()!
				elements << n
			} else {
				text, _ := p.read_top_text_run()
				if text.len > 0 {
					elements << Node(TextNode{ value: text })
				}
			}
			continue
		}
		// Strict mode: ws/comments between bracketed nodes; non-bracket
		// trailing content is a parse error (preserves data-CX invariant
		// from v3.x). Comments between/after root nodes are preserved as
		// CommentNode siblings (in document order) so `cx fmt` round-trips
		// them — a trailing `[a 1] # note` keeps its `# note`.
		p.skip_ws_collecting_comments(mut elements)
		if p.at_end() { break }
		if p.pos + 3 <= p.src.len && p.src[p.pos] == `-` && p.src[p.pos+1] == `-` && p.src[p.pos+2] == `-` {
			break
		}
		if p.src[p.pos] == `]` {
			// Same structural stray close as doc-top / mixed mode
			// (GR-STRAY-CLOSE) — raise it with the code, not the generic
			// `expected node` (#289 witness GR-STRAY-CLOSE-2).
			return error(p.make_error('stray `]` with no matching `[` (cx-err:CXER0100)'))
		}
		n := p.parse_node()!
		elements << n
		// A `[?=…]` interpolation or `[?Name …]` eval-directive at top
		// level signals a CX program; switch to mixed mode so any
		// following prose attaches as Text rather than erroring.
		if n is InterpolationNode || n is EvalDirectiveNode {
			allow_top_text = true
		}
	}

	mut doc := Document{ prolog: prolog, doctype: doctype, elements: elements }
	resolve_namespaces(mut doc)
	resolve_ids(doc)!
	return doc
}

// peek_table_block_open returns true if the parser is positioned at the
// TableBlock clause-child opener `[table[` (TABLE_OPEN per
// spec/grammar.ebnf [29] + its lexer note): a `[`, the reserved name
// `table`, then the header `[` GLUED to it — TABLE_OPEN is a single
// token (#484). `[table …]` with whitespace before the bracket is an
// ordinary element named `table` (plain composition — the whitespace-
// tolerant claim broke `[furniture [table [legs 4]]]` and silently
// diverged from the program reading, which was already glued-only).
// `[table[]` (immediately closed header) is not a TableBlock either.
// Does not consume input.
fn (p &Parser) peek_table_block_open() bool {
	// Need at least: '[' 't' 'a' 'b' 'l' 'e' '[' x — 8 bytes minimum
	if p.pos + 8 > p.src.len { return false }
	if p.src[p.pos] != `[` { return false }
	if p.src[p.pos + 1] != `t` { return false }
	if p.src[p.pos + 2] != `a` { return false }
	if p.src[p.pos + 3] != `b` { return false }
	if p.src[p.pos + 4] != `l` { return false }
	if p.src[p.pos + 5] != `e` { return false }
	// the header '[' must be byte-adjacent — TABLE_OPEN is one glued token
	if p.src[p.pos + 6] != `[` { return false }
	// `[table[]` (immediately closed header) is not a TableBlock; fall back.
	if p.src[p.pos + 7] == `]` { return false }
	return true
}

// parse_table_header parses the column declarations between '[' and
// ']' in a TableBlock header. Returns the parsed columns. Caller
// has already consumed the opening '['.
fn (mut p Parser) parse_table_header() ![]TableColumn {
	mut cols := []TableColumn{}
	for {
		p.skip_ws()
		if p.at_end() { return error('${p.line}:${p.col}: unterminated :table header') }
		if p.peek() == `]` { break }
		if !is_name_start(p.peek()) {
			return error('${p.line}:${p.col}: expected column name in :table header')
		}
		// a column type uses the glued `name::type` form (grammar [29b]
		// TableColumn ::= Name ('::' TypeName)?). `read_name` stops before a
		// glued `::`, so the typed form arrives as the bare name followed by
		// `::type`; a token with no `::` is name-only (::string default).
		full := p.read_name()!
		// RETIRED (D014): the legacy single-colon `name:type` column
		// type form. A single `:` in a column-header token is a hard parse
		// error — column types use the glued `::T` form exclusively.
		if full.contains(':') {
			return error(p.make_error("retired single-colon column type `${full}` — use the glued `::T` form (grammar [29b]), e.g. `${full.replace(':', '::')}`"))
		}
		col_name := full
		mut col_type := ''
		if !p.at_end() && p.peek() == `:` && p.pos + 1 < p.src.len
		   && p.src[p.pos + 1] == `:` {
			// glued `name::type`
			p.advance() // first ':'
			p.advance() // second ':'
			col_type = p.read_name()!
		}
		cols << TableColumn{ name: col_name, type_name: col_type }
	}
	if cols.len == 0 {
		return error('${p.line}:${p.col}: :table header must declare at least one column')
	}
	return cols
}

// parse_table_rows parses the data cells of a TableBlock until the
// closing ']'. Cells are grouped into rows of `cols.len` cells each.
// Cell parsing applies type-driven coercion for scalars (bare cells
// use the column's declared type; quoted cells are always string)
// or recognizes collection-literal cells (`[a, b, c]`,
// `{k: v}`, `(a, b, c)`).
fn (mut p Parser) parse_table_rows(cols []TableColumn) ![][]TableCellValue {
	mut rows := [][]TableCellValue{}
	mut current := []TableCellValue{cap: cols.len}
	for {
		p.skip_ws_and_line_comments()
		if p.at_end() {
			return error('${p.line}:${p.col}: unterminated :table block')
		}
		if p.peek() == `]` { break }
		col_idx := current.len
		if col_idx >= cols.len {
			rows << current
			current = []TableCellValue{cap: cols.len}
			continue
		}
		col_type := cols[col_idx].type_name
		val := p.read_table_cell(col_type)!
		current << val
	}
	if current.len > 0 {
		if current.len != cols.len {
			return error('${p.line}:${p.col}: :table row has ${current.len} cells; expected ${cols.len}')
		}
		rows << current
	}
	return rows
}

// read_table_cell reads one cell value. Recognizes:
//   - Quoted strings: `'text'` / `'''text'''` → string scalar
// Array literals: `[a, b, c]` → ArrayNode (the
//     trailing-comma form `[v,]` is required for single-element
//     arrays since `[v]` would parse as Element per §D1's comma-
//     marker disambiguator)
//   - Map literals: `{k: v}` → MapNode
//   - Sequence literals: `(a, b, c)` → SequenceNode
//   - Bare scalars: auto-typed via the column's declared type
//
// Collection-cell parsing: the cell's host type
// is whatever admits; the column's declared type (if
// `arr[T]` / `map[K, V]` / `seq[T]`) informs
// downstream emitters but is not enforced at this layer.
fn (mut p Parser) read_table_cell(col_type string) !TableCellValue {
	b := p.peek()
	if b == `'` {
		// Quoted; check for triple-quoted form first.
		if p.pos + 3 <= p.src.len && p.src[p.pos] == `'`
			&& p.src[p.pos + 1] == `'` && p.src[p.pos + 2] == `'` {
			s := p.read_triple_quoted_str()!
			return TableCellValue(s)
		}
		s := p.read_quoted_text()!
		return TableCellValue(s)
	}
	if b == `"` {
		// Double-quoted cell value (spec [29e] amendment —
		// previously only single-quoted was recognised, an asymmetry
		// with the rest of CX's QuotedText surface). Check triple-
		// double-quoted form first (symmetric with the `'''` branch).
		if p.pos + 3 <= p.src.len && p.src[p.pos] == `"`
			&& p.src[p.pos + 1] == `"` && p.src[p.pos + 2] == `"` {
			s := p.read_triple_double_quoted_str()!
			return TableCellValue(s)
		}
		s := p.read_quoted()!
		return TableCellValue(s)
	}
	// Hash-raw `[# … #]` and pipe-block `[| … |]` as cell values.
	// Both produce a string-typed cell containing the literal bytes
	// (hash-raw) or whitespace-preserved structured content (pipe-block,
	// rendered as text for cell representation). Type discipline: only
	// permitted in `:string` columns (or untyped, which defaults to
	// string). Numeric / bool columns reject these forms — the bare path
	// would auto-coerce `[# raw #]` as a literal token and fail typing.
	if b == `[` && p.pos + 1 < p.src.len && p.src[p.pos + 1] == `#`
		&& (col_type == '' || col_type == 'string' || col_type == 's') {
		s := p.read_raw_text_str()!
		return TableCellValue(s)
	}
	if b == `[` && p.pos + 1 < p.src.len && p.src[p.pos + 1] == `|`
		&& (col_type == '' || col_type == 'string' || col_type == 's') {
		p.advance() // consume '['
		node := p.parse_block_content()!
		// Render the block-content items as a single string for the
		// cell value (newlines preserved per parse_block_content's
		// whitespace policy).
		mut s := []u8{}
		for item in (node as BlockContentNode).items {
			if item is TextNode {
				s << (item as TextNode).value.bytes()
			}
		}
		return TableCellValue(s.bytestr())
	}
	if b == `[` {
		// :table cell `[...]` always parses as an Array literal,
		// analogous to resolution 2.i for EvalDirective ArgArrays —
		// the cell context unambiguously requires Array. This makes
		// single-element arrays `[v]` work without forcing the
		// trailing-comma form `[v,]` at the source, and lets the
		// canonical-form emit per §D14 drop trailing commas cleanly.
		// Element-form `[name body]` is not a meaningful table cell
		// shape (§D4); parse_array_literal will produce an Array node
		// from whatever it finds between the brackets.
		p.advance() // consume '['
		node := p.parse_array_literal()!
		if node is ArrayNode {
			return TableCellValue(node as ArrayNode)
		}
		return error('${p.line}:${p.col}: :table cell starts with `[...]` but parse_array_literal did not return ArrayNode')
	}
	if b == `{` && p.peek_is_map_literal_at_brace() {
		node := p.parse_map_literal()!
		if node is MapNode {
			return TableCellValue(node as MapNode)
		}
		return error('${p.line}:${p.col}: :table cell starts with `{...}` but parse_map_literal did not return MapNode')
	}
	if b == `(` && p.peek_is_sequence_literal_at_paren() {
		node := p.parse_sequence_literal()!
		if node is SequenceNode {
			return TableCellValue(node as SequenceNode)
		}
		return error('${p.line}:${p.col}: :table cell starts with `(...)` but parse_sequence_literal did not return SequenceNode')
	}
	// Bare value — read until whitespace or `]`.
	start := p.pos
	for !p.at_end() {
		c := p.peek()
		if c == ` ` || c == `\t` || c == `\r` || c == `\n` || c == `]` {
			break
		}
		p.advance()
	}
	tok := p.src[start..p.pos].bytestr()
	if tok == 'null' {
		return TableCellValue(NullValue{})
	}
	// Type-driven coercion. Empty col_type defaults to string.
	if col_type == '' || col_type == 'string' || col_type == 's' {
		return TableCellValue(tok)
	}
	scalar := coerce_scalar(expand_type_alias(col_type), tok)
	return cell_value_from_scalar(scalar.value)
}

// is_logfmt_start performs lookahead to determine whether the next
// non-whitespace token is `Name '='`, indicating logfmt mode. Does
// not consume input.
fn (p &Parser) is_logfmt_start() bool {
	mut pos := p.pos
	for pos < p.src.len {
		b := p.src[pos]
		if b == ` ` || b == `\t` || b == `\r` || b == `\n` {
			pos++
			continue
		}
		break
	}
	if pos >= p.src.len { return false }
	if !is_name_start(p.src[pos]) { return false }
	pos++
	for pos < p.src.len && is_name_char(p.src[pos]) {
		pos++
	}
	if pos >= p.src.len { return false }
	return p.src[pos] == `=`
}

// parse_logfmt_record consumes one logfmt record — a sequence of
// `Name=Value` pairs separated by intra-line whitespace, terminated
// by end-of-line or end-of-input. Per v3.4 §9, each record becomes
// its own synthetic Element.
fn (mut p Parser) parse_logfmt_record() ![]Attribute {
	mut attrs := []Attribute{}
	for {
		// Intra-record whitespace: spaces and tabs only. A newline
		// terminates the record.
		for !p.at_end() {
			b := p.peek()
			if b == ` ` || b == `\t` || b == `\r` {
				p.advance()
			} else {
				break
			}
		}
		if p.at_end() || p.peek() == `\n` { break }
		// Line comments end the record (everything after `#` is
		// ignored, including the newline marker).
		if p.peek() == `#` {
			p.skip_line_comment()
			break
		}
		if !is_name_start(p.peek()) {
			return error('${p.line}:${p.col}: expected attribute name in logfmt document')
		}
		name := p.read_name()!
		if p.at_end() || p.peek() != `=` {
			return error('${p.line}:${p.col}: expected = after attribute name `${name}`')
		}
		p.advance() // consume '='
		val, dt := p.read_attr_value_typed()!
		attrs << new_attribute(name, val, AttributeMeta{ data_type: dt })
	}
	return attrs
}

// skip_logfmt_inter_record advances past blank lines and full-line
// comments between records.
fn (mut p Parser) skip_logfmt_inter_record() {
	for !p.at_end() {
		b := p.peek()
		if b == `\n` || b == `\r` || b == ` ` || b == `\t` {
			p.advance()
		} else if b == `#` {
			p.skip_line_comment()
		} else {
			break
		}
	}
}

fn (p &Parser) is_prolog_node() bool {
	if p.pos >= p.src.len || p.src[p.pos] != `[` { return false }
	if p.pos + 1 >= p.src.len { return false }
	b1 := p.src[p.pos + 1]
	// `[?…]` PI/directive or `[; … ]` block comment (the `[;` comment head —
	// was `[-` before the comment-syntax change).
	if b1 == `?` || b1 == `;` { return true }
	if b1 == `!` {
		if p.pos + 9 <= p.src.len {
			return p.src[p.pos+2..p.pos+9] == 'DOCTYPE'.bytes()
		}
	}
	return false
}

fn (p &Parser) is_doctype_node() bool {
	if p.pos >= p.src.len || p.src[p.pos] != `[` { return false }
	if p.pos + 1 >= p.src.len || p.src[p.pos+1] != `!` { return false }
	if p.pos + 9 <= p.src.len {
		return p.src[p.pos+2..p.pos+9] == 'DOCTYPE'.bytes()
	}
	return false
}

fn is_prolog_node_type(n Node) bool {
	return match n {
		XMLDeclNode, CXDirectiveNode, PINode, CommentNode { true }
		else { false }
	}
}

// ── Node dispatch ─────────────────────────────────────────────────────────────

fn (mut p Parser) parse_node() !Node {
	p.skip_ws()
	if p.at_end() { return error(p.make_error('expected node')) }
	b := p.peek()
	return match b {
		`[` { p.parse_bracket_node()! }
		`&` { p.parse_entity_ref()! }
		else { error(p.make_error('expected node')) }
	}
}

// parse_data_node parses EXACTLY ONE data node from `src` and returns it.
//
// It is the DATA↔PROGRAM seam's delegation point: the program (eval) reader
// captures a pure-DATA construct's span — raw text `[#…#]`, an entity /
// character reference `&…;` / `&#…;`, or a declaration `[!…]` (the DTD
// declarations + `[!DOCTYPE …]`) — and hands the verbatim source here so the
// program reading of these constructs IS the data reading. That keeps the
// "data = a program that evaluates to itself" invariant closed BY
// CONSTRUCTION rather than by a parallel reimplementation.
//
// `src` MUST contain exactly one node; trailing non-whitespace is an error.
pub fn parse_data_node(src string) !Node {
	mut p := new_parser(src)
	p.skip_ws()
	if p.at_end() {
		return error(p.make_error('expected a data node'))
	}
	node := p.parse_one_embedded_node()!
	p.skip_ws()
	if !p.at_end() {
		return error(p.make_error('unexpected trailing content after data node'))
	}
	return node
}

// parse_one_embedded_node dispatches a single node for parse_data_node. It
// mirrors parse_node's `[`/`&` dispatch but ALSO admits a standalone
// `[!DOCTYPE …]` — which parse_document recognises only at the prolog level
// and parse_decl rejects ("DOCTYPE not allowed here") — so the program
// reader can carry a DOCTYPE as a node value via parse_doctype_inner.
fn (mut p Parser) parse_one_embedded_node() !Node {
	b := p.peek()
	if b == `&` {
		return p.parse_amp_node()!
	}
	if b == `[` {
		if p.is_doctype_node() {
			p.advance()    // '['
			p.advance()    // '!'
			p.read_name()! // "DOCTYPE"
			dt := p.parse_doctype_inner()!
			return Node(dt)
		}
		return p.parse_bracket_node()!
	}
	return error(p.make_error('expected a data node'))
}

fn (mut p Parser) parse_bracket_node() !Node {
	p.advance() // consume '['
	if p.at_end() { return error(p.make_error('unexpected EOF after [')) }
	b := p.peek()
	// v3.6: empty `[]` is the empty ArrayLiteral [56b] in
	// expression position. Currently invalid in Element position (Name
	// required); the grammar's [50] rule unchanged. Detect ahead of the
	// sigil dispatch so it isn't routed by accident.
	if b == `]` {
		p.advance() // consume ']'
		return Node(ArrayNode{ items: []Node{} })
	}
	// #484 (fail-closed): the reserved glued `[table[` opener (TABLE_OPEN)
	// is ElementMeta — it closes a NAMED element's head (grammar [29]
	// "ElementMeta position"; [50]'s tabular alternative requires a Name).
	// parse_element short-circuits the head-position case before parse_body,
	// so any occurrence reaching this dispatch — document level, or body
	// position after content has begun — can belong to no element head. It
	// previously fell through the typed-list/array-literal routes and
	// produced silent Array/Sequence garbage (no-silent-loss contract).
	if b == `t` && p.pos + 7 <= p.src.len
		&& p.src[p.pos + 1] == `a` && p.src[p.pos + 2] == `b`
		&& p.src[p.pos + 3] == `l` && p.src[p.pos + 4] == `e`
		&& p.src[p.pos + 5] == `[` && p.src[p.pos + 6] != `]` {
		return error(p.make_error('`[table[` clause-child outside ElementMeta position — the TableBlock closes a NAMED element\'s head: [users [table[…]] rows] (grammar [29]/[50]) (cx-err:CXER0100)'))
	}
	// v3.6: comma-marker disambiguation wins over the
	// non-`?` sigil dispatch — e.g. `[*, None]` is an Array literal
	// with the CXPath-wildcard sentinel `*` as its first slot, not an
	// alias element. `?`-prefixed forms (EvalDirective, Interpolation,
	// PI, CXDirective) keep absolute priority because their semantics
	// are unambiguous and the parser must never reroute them as
	// arrays (per §A commit 19075a5: "[?for ...,] never routes
	// through array detection").
	//
	// Structural sigils with opaque inner content also keep absolute
	// priority: `;` (block comment), `!` (declaration), `|` (block
	// content), `#` (raw text). Otherwise a comma inside an opaque
	// span — e.g. `[; comment, with, commas ]` — would be misread as
	// an Array literal with `;` (or `!`/`|`/`#`) as the first slot.
	is_opaque_sigil := b == `;` || b == `!` || b == `|` || b == `#`
	// Headless WS array (@CHOICE-1, G-ARRAY-1): a no-comma bracket of 2+ typed
	// scalar tokens — `[80 443]` — is an Array node of discrete typed items (the
	// node-kind twin of the element whitespace typed list, slice A). Checked before
	// the comma-array path; a top-level comma makes body_is_typed_list false, so
	// `[1, 2]` still routes through parse_array_literal. Element heads (`[a …]`)
	// never reach here — `a` is a name-start, dispatched below.
	if b != `?` && !is_opaque_sigil && p.body_is_typed_list() {
		items := p.parse_self_delim_body()!
		p.expect(`]`)!
		return Node(ArrayNode{ items: items })
	}
	if b != `?` && !is_opaque_sigil && p.peek_is_array_literal() {
		return p.parse_array_literal()!
	}
	return match b {
		`?` { p.parse_pi_or_decl()! }
		`;` { p.parse_comment()! }
		`#` { p.parse_raw_text()! }
		`!` { p.parse_decl()! }
		`*` { p.parse_alias()! }
		`|` { p.parse_block_content()! }
		else {
			p.parse_element()!
		}
	}
}

// normalize_doc_element_name is kept as identity — element names are case-sensitive in CX.
fn normalize_doc_element_name(name string) string {
	return name
}

// ── [?...] PI, XMLDecl, CXDirective ──────────────────────────────────────────

fn (mut p Parser) parse_pi_or_decl() !Node {
	p.advance() // consume '?'
	// v3.5: `[?=EXPR]` is the CX code Interpolation form
	// (grammar [58]). EXPR is captured opaquely with bracket
	// balancing; the program evaluator parses it as CXPath.
	if !p.at_end() && p.peek() == `=` {
		p.advance() // consume '='
		return p.parse_interpolation()!
	}
	target := p.read_name()!
	if is_cx_eval_name(target) || (target in p.declared_templates) {
		// v3.5: `[?Name ...]` for reserved EvalNames is
		// the CX code EvalDirective form (grammar [59]).
		// also route declared `?def` template names so
		// invocations `[?template-name args]` parse as EvalDirective
		// rather than falling through to PI.
		return p.parse_eval_directive(target)!
	}
	return match target {
		'xml' { p.parse_xml_decl()! }
		'cx'  { p.parse_cx_directive()! }
		else  { p.parse_pi_body(target)! }
	}
}

// is_cx_eval_name reports whether name is a reserved CX code EvalName
// (grammar [59a]). The set is closed per program spec version per
// R4 — implementations parse all listed names as EvalDirective
// nodes; evaluators dispatch the subset their declared CX code version
// supports and error on the rest.
//
// Control-flow directives (CX code 1.0, spec/eval.md §3): `if`, `for`,
// `with`, `cond`, `include`, `def`, `use`.
// Built-in filter directives (CX code 1.0, spec/eval.md §4): the frozen
// filter set is reserved as EvalNames because filter invocations use
// the `?`-prefixed bracket form (`[?upper x]`, `[?trim x]`).
// CX code 3.1 control-flow: `let`, `fn`, `match`, `try`.
fn is_cx_eval_name(name string) bool {
	return match name {
		// CX code 1.0 control-flow + A13/A14 FLWOR windows
		'if', 'for', 'for-tumbling', 'for-sliding',
		'with', 'cond', 'include', 'def', 'use',
		// CX code 1.0 string filters (§4.1)
		'upper', 'lower', 'trim', 'length', 'concat', 'join', 'replace',
		// CX code 1.0 numeric filters (§4.2)
		'abs', 'round', 'format-decimal', 'format-percent',
		// CX code 1.0 sequence filters (§4.3)
		'empty', 'first', 'last', 'rest', 'take', 'drop', 'reverse',
		'distinct', 'where',
		// CX code 1.0 temporal filters (§4.4) + C14/C15 date/time fns (XQuery 4.0)
		'format-date', 'format-datetime', 'format-dateTime', 'format-time',
		'current-date', 'current-dateTime', 'current-time',
		'year-from-dateTime', 'month-from-dateTime', 'day-from-dateTime',
		'hours-from-dateTime', 'minutes-from-dateTime', 'seconds-from-dateTime',
		'year-from-date', 'month-from-date', 'day-from-date',
		'hours-from-time', 'minutes-from-time', 'seconds-from-time',
		// CX code 1.0 type filters (§4.5)
		'type-of', 'default',
		// CX code 1.0 encoding filters (§4.6)
		'escape-html', 'escape-url', 'safe-url', 'raw',
		// CX code 3.1 aggregate filters
		'sum', 'count', 'min', 'max', 'avg',
		// XQuery 4.0 standard fn: namespace (per xquery_40_parity.md §C)
		'ceiling', 'floor', 'round-half-to-even',
		'contains', 'starts-with', 'ends-with', 'substring',
		'substring-before', 'substring-after', 'string-length', 'string',
		'normalize-space',
		// C5 String regex (XQuery 4.0 §F.6)
		'matches', 'tokenize', 'regex-replace',
		'string-join', 'translate',
		'distinct-values', 'exists', 'head', 'tail', 'items-at',
		'zero-or-one', 'one-or-more', 'exactly-one',
		'subsequence', 'index-of', 'insert-before', 'remove',
		'slice', 'replicate', 'characters', 'all-different', 'partition',
		'format-number',
		'codepoints-to-string', 'string-to-codepoints',
		'compare', 'codepoint-equal',
		'encode-for-uri', 'iri-to-uri', 'escape-html-uri',
		'char', 'intersperse', 'sequence-join',
		'unordered', 'sort', 'data',
		'has-children', 'innermost', 'outermost',
		'deep-equal',
		'string-pad', 'string-pad-left',
		// CX code 3.1 higher-order functions (C11,)
		'for-each', 'filter', 'fold-left', 'fold-right',
		'apply', 'function-arity', 'function-name', 'for-each-pair',
		'function-lookup', 'function-identity', 'scan-left',
		// fn:error / fn:trace (C17, error namespace-E1)
		'error',
		// A22 named function references (XQuery 3.0)
		'fn-ref',
		// A23 partial application (left-curry + middle-position `_`)
		'partial', '__partial_invoke', '_',
		// A24 focus functions — sugar for [?fn :params [_] …]
		'focus',
		// A44 node comparisons (XPath 4.0 §4.10.3)
		'node-is', 'node-before', 'node-after',
		// A39/A40 string templates + constructors (XPath 4.0 §4.9.2/§4.9.3)
		'str-template', 'str',
		// A30 quantified some/every + A41 range (XPath 1.0+)
		'some', 'every', 'range',
		// A28 simple map / A38 string concat helpers
		'simple-map', 'concat-string',
		// A26 pipeline / A27 arrow as directives (canonical operator syntax later)
		'pipe', 'arrow',
		// Misc utility functions
		'generate-id',
		// xs: constructor functions (C18, XPath 1.0+ type system)
		'xs:int', 'xs:integer', 'xs:long', 'xs:short', 'xs:byte',
		'xs:double', 'xs:float', 'xs:decimal',
		'xs:string', 'xs:boolean',
		'xs:nonNegativeInteger', 'xs:positiveInteger',
		// A32-A36 SequenceType expressions (XPath 2.0+ type system)
		'instance-of', 'cast-as', 'castable-as', 'treat-as',
		// A29 switch / A37 typeswitch (XPath 3.0+)
		'switch', 'typeswitch',
		// A43 verbose comparison operators (XPath 2.0)
		'eq', 'ne', 'lt', 'le', 'gt', 'ge',
		// A42 sequence intersect/except
		'intersect', 'except',
		// A31 otherwise
		'otherwise',
		// C19 JSON namespace (XPath 4.0)
		'parse-json', 'serialize-json',
		'json-to-xml', 'xml-to-json', 'json-doc',
		// C22 serialization
		'serialize', 'parse-xml', 'parse-xml-fragment',
		// C21 I/O
		'doc-available', 'doc',
		// C20 QName helpers
		'prefix-from-QName', 'local-name-from-QName', 'namespace-uri-from-QName',
		'boolean', 'true', 'false', 'not',
		'name', 'local-name', 'namespace-uri', 'root',
		'node-name', 'base-uri', 'document-uri', 'lang',
		'sort-by', 'normalize-unicode',
		'QName', 'namespace-uri-for-prefix', 'in-scope-prefixes',
		'collection', 'uri-collection',
		'available-environment-variables', 'environment-variable',
		'random-number-generator',
		// math: namespace (XPath 3.0)
		'math:pi', 'math:e', 'math:exp', 'math:exp10', 'math:log',
		'math:log10', 'math:sqrt', 'math:sin', 'math:cos', 'math:tan',
		'math:asin', 'math:acos', 'math:atan', 'math:atan2', 'math:pow',
		// map: namespace (XPath 3.1, D1)
		'map:get', 'map:put', 'map:keys', 'map:size', 'map:contains',
		'map:entry', 'map:merge', 'map:remove', 'map:for-each',
		// array: namespace (XPath 3.1, D2)
		'array:size', 'array:get', 'array:append', 'array:head',
		'array:tail', 'array:reverse', 'array:subarray', 'array:put',
		'array:remove', 'array:insert-before', 'array:flatten',
		'array:join', 'array:filter', 'array:for-each',
		'array:fold-left', 'array:fold-right', 'array:sort',
		// cx: self-host module (DD1–DD22)
		'cx:parse', 'cx:serialize', 'cx:canonical', 'cx:hash',
		'cx:diff', 'cx:patch', 'cx:to-format', 'cx:from-format',
		'cx:equal', 'cx:select',
		'cx:eval', 'cx:render', 'cx:schema-of', 'cx:validate',
		'cx:anchors', 'cx:ids', 'cx:references', 'cx:resolve-includes',
		'cx:merge', 'cx:strip-comments', 'cx:strip-attrs', 'cx:pretty-print',
		// log: structured-logging module (FF1–FF7)
		'log:trace', 'log:debug', 'log:info', 'log:warn', 'log:error',
		'log:level', 'log:with-context',
		// inspect: module-discovery (DD13/EE7)
		'inspect:module-available', 'inspect:module-version', 'inspect:functions',
		// CX code 3.1 control-flow
		'let', 'fn', 'match', 'try' { true }
		else { false }
	}
}

// parse_interpolation reads the body of `[?=EXPR]`. The expression is
// captured as opaque text with internal `[`/`]` required to balance,
// per grammar [58a] / [58b]. The captured text is parsed as CXPath by
// the program evaluator; the parser only preserves it.
fn (mut p Parser) parse_interpolation() !Node {
	mut s := []u8{}
	mut depth := 0
	for {
		if p.at_end() { return error(p.make_error('unterminated [?= interpolation')) }
		b := p.peek()
		if b == `[` {
			depth++
			s << b
			p.advance()
		} else if b == `]` {
			if depth == 0 { break }
			depth--
			s << b
			p.advance()
		} else {
			s << b
			p.advance()
		}
	}
	p.expect(`]`)!
	return InterpolationNode{ expr: s.bytestr().trim_space() }
}

// parse_eval_directive parses a `[?Name ...]` program evaluation directive
// (grammar [59]).
//
// The data parser treats every directive child uniformly as a BodyItem
// [53]; clause / attribute / bareword interpretation is the program-AST
// layer's job ([127] + the per-directive specialisations ForComp [129],
// MatchExpr [136], DefDirective [152], etc.). Every directive therefore
// parses its body with the same item grammar as element bodies — the
// canonical clause-child surface (`[?for [in $x S] [yield E]]`,
// `[?let [= $x v] body]`, `[?match [when P E] …]`,
// `[?def name scope=public pure ($p::T) body]`) falls out as ordinary
// child elements / attributes-as-text, the positional array form
// (`[?if [c, t, e]]`) as a single array-literal child, and atoms
// (`:lazy`) round-trip as atoms. No data-side clause interpretation;
// the data side only round-trips. (The former positional/labeled
// ArgArray machinery with per-directive `:slot` desugar tables was
// retired with the colon-slot surface cutover.)
//
// `[?cx …]` is NOT handled here — it's a CXDirective (config), parsed
// separately via parse_cx_directive.
fn (mut p Parser) parse_eval_directive(name string) !Node {
	p.skip_ws_and_line_comments()
	if p.at_end() {
		return error(p.make_error('unterminated eval directive `[?${name}`'))
	}
	children := p.parse_body(none)!
	p.skip_ws_and_line_comments()
	p.expect(`]`)!
	record_declared_template(mut p, name, children)
	return EvalDirectiveNode{ name: name, attrs: []Attribute{}, items: children }
}

// record_declared_template extracts the template name from a `?def`
// directive's parsed ArgArray and registers it on the Parser so
// subsequent `[?<name> args]` invocations parse as EvalDirective
// (rather than falling through to PI). Per 
// §D7. No-op for directives other than ?def / ?let.
fn record_declared_template(mut p Parser, directive_name string, items []Node) {
	// ?def — records the template name so subsequent [?<name> args]
	// parses as EvalDirective.
	// ?let — records the bound variable name similarly; the let-bound
	// value at runtime might be a function which the program layer
	// dispatches as a call. False positives at parse time (let-bound
	// to a non-function value) are harmless — the data side only
	// classifies, it never evaluates.
	if directive_name != 'def' && directive_name != 'let' { return }
	if items.len == 0 { return }
	first := items[0]
	// `?let` parses as uniform BodyItems per [59]; its canonical binding is
	// the clause-child `[= $name v]` element. The binding name is the first
	// token of that element's body (a `$`-prefixed reference in source).
	if directive_name == 'let' && first is Element {
		el := first as Element
		if el.name == '=' && el.items.len > 0 {
			bind_name := node_leading_token(el.items[0]).trim_left('$')
			if bind_name != '' { p.declared_templates[bind_name] = true }
		}
		return
	}
	// `?def` parses as uniform BodyItems per [59]; the current surface
	// (`[?def name modifiers… (params) body]`) carries the name as the
	// leading bare token of the first body item. The positional array
	// form (`[?def [name, params, body]]`) falls through to the
	// ArgArray path below.
	if directive_name == 'def' && first !is ArrayNode {
		def_name := node_leading_token(first)
		if def_name != '' { p.declared_templates[def_name] = true }
		return
	}
	// `?def` (and `?let`'s positional array form) carry the name in slot 0
	// of the ArgArray.
	if first !is ArrayNode { return }
	arr_items := (first as ArrayNode).items
	if arr_items.len == 0 { return }
	// Slot 0 is the template name (?def) or the let-binding name (?let).
	name_node := arr_items[0]
	tmpl_name := match name_node {
		TextNode   { (name_node as TextNode).value.trim_space() }
		ScalarNode { scalar_value_str((name_node as ScalarNode).value).trim_space() }
		Element    {
			el := name_node as Element
			if el.attrs.len == 0 && el.items.len == 0 { el.name } else { '' }
		}
		else       { '' }
	}
	if tmpl_name != '' {
		p.declared_templates[tmpl_name] = true
	}
}

// node_leading_token returns the first whitespace-delimited token of a body
// node's textual surface — used to pull the binding name out of a `[= $name v]`
// let clause-child. Returns '' for node kinds that carry no leading bare token.
fn node_leading_token(n Node) string {
	return match n {
		TextNode   { (n as TextNode).value.trim_space().all_before(' ') }
		ScalarNode { scalar_value_str((n as ScalarNode).value).trim_space().all_before(' ') }
		Element    {
			el := n as Element
			if el.attrs.len == 0 && el.items.len == 0 { el.name } else { '' }
		}
		else { '' }
	}
}

// (read_attr_with_optional_body — the grammar-[55c] BracketBody reader —
// was DELETED here (#391): D2 (lexicon §10) removed node-valued attributes
// from the spec on 2026-06-03 and the graduation sweep removed every call
// site, leaving the function dead. The scalar readers above now REJECT
// `(`/`{`/non-raw-`[` openers per D2 instead of mangling them.)

// parse_raw_text_value parses a `[# … #]` raw-text literal from the
// current position (at the opening `[`) and returns it as a RawTextNode.
// Wraps the byte-level read_raw_text_str helper. Attribute-value
// hash-raw direct path.
fn (mut p Parser) parse_raw_text_value() !Node {
	value := p.read_raw_text_str()!
	return RawTextNode{ value: value }
}

fn (mut p Parser) parse_xml_decl() !Node {
	attrs := p.read_attr_list_until(`]`)!
	p.expect(`]`)!
	version := find_attr_value(attrs, 'version') or { '1.0' }
	encoding := find_attr_value(attrs, 'encoding')
	standalone := find_attr_value(attrs, 'standalone')
	return XMLDeclNode{ version: version, encoding: encoding, standalone: standalone }
}

fn find_attr_value(attrs []Attribute, name string) ?string {
	for a in attrs {
		if a.name == name {
			return a.str_value()
		}
	}
	return none
}

fn (mut p Parser) parse_cx_directive() !Node {
	attrs := p.read_directive_attr_list_until(`]`)!
	// a schema pragma marks the whole document as a schema,
	// suspending `:T` type-tag validation for its body (see Parser.in_schema).
	// The first positional attr names the pragma verb.
	if attrs.len > 0 {
		verb := attrs[0].name
		if verb == 'schema-of' || verb == 'schema-name' || verb == 'schema-mode'
		   || verb == 'frag' {
			p.in_schema = true
		}
	}
	// Optional `&anchor` after the attr list, then optional
	// child nodes (parsed identically to element content). Used by
	// `[?cx frag &name [body :TYPE :flags]]` per spec/schema.md §8.
	mut anchor := ?string(none)
	p.skip_ws()
	if !p.at_end() && p.peek() == `&` {
		p.advance() // consume `&`
		aname := p.read_name()!
		anchor = ?string(aname)
	}
	mut items := []Node{}
	p.skip_ws()
	for !p.at_end() && p.peek() != `]` {
		items << p.parse_node()!
		p.skip_ws()
	}
	p.expect(`]`)!
	return CXDirectiveNode{ attrs: attrs, anchor: anchor, items: items }
}

// read_directive_attr_list_until accepts both keyed (`name=value`) and
// positional (`name` alone) forms. Positional names land as Attribute
// entries with an empty value, which lets `[?cx schema-of server]` and
// `[?cx schema-mode open]` parse uniformly with `[?cx schema=path]` and
// `[?cx lint-disable=L001]`. Schema directive consumers read the first
// positional attr as the directive name and subsequent positional
// attrs as args.
fn (mut p Parser) read_directive_attr_list_until(stop u8) ![]Attribute {
	mut attrs := []Attribute{}
	for {
		p.skip_ws()
		if p.at_end() || p.peek() == stop { break }
		// Stop on `&` (anchor) or `[` (nested directive body)
		// so the caller can parse them as a separate phase. Used by
		// `[?cx frag &name [body ...]]`.
		if p.peek() == `&` || p.peek() == `[` { break }
		// A quoted positional argument — e.g. the title in
		// `[?cx schema-name 'Book schema v1']` (spec/schema.md §2). Stored
		// with an empty name and the text in `value`; directive consumers
		// read it positionally via directive_arg_text, and the emitter
		// re-quotes it. Without this branch read_name fail-fasts on the
		// leading quote ("expected name") and the whole schema load aborts.
		if p.peek() == `'` || p.peek() == `"` {
			qval := p.read_quoted()!
			attrs << Attribute{ name: '', value: ScalarValue(qval) }
			continue
		}
		name := p.read_name()!
		// Don't skip whitespace before `=` — `name = value` with spaces
		// around `=` isn't valid attr syntax; whitespace separates
		// positional tokens from the next directive arg.
		if !p.at_end() && p.peek() == `=` {
			p.advance()
			// D2 applies to directive attrs too (#396 owner ruling 1b,
			// 2026-07-13): the retired grammar-[55c] BracketBody form
			// `name=[BodyItem*]` — the last surviving producer of the
			// node-valued Attribute.body channel — is gone; read_attr_value
			// admits the scalar spellings (incl. the `[#…#]` raw string)
			// and E211-rejects the bracket openers.
			value := p.read_attr_value()!
			attrs << Attribute{ name: name, value: ScalarValue(value) }
		} else {
			attrs << Attribute{ name: name, value: ScalarValue('') }
		}
	}
	return attrs
}

fn (mut p Parser) parse_pi_body(target string) !Node {
	data_raw := p.read_until_close()!
	p.expect(`]`)!
	data := data_raw.trim_space()
	d := if data.len == 0 { ?string(none) } else { ?string(data) }
	return PINode{ target: target, data: d }
}

// ── [-...] comment ────────────────────────────────────────────────────────────

// parse_comment reads a `[; … ]` block comment (the single CX block-comment
// form). The `;` head is unambiguous — `[- …]` is the minus operator / a data
// element, never a comment. Asymmetric: the body runs to the matching `]`.
fn (mut p Parser) parse_comment() !Node {
	p.advance() // consume ';'
	value := p.read_until_close()!
	p.expect(`]`)!
	return CommentNode{ value: value }
}

// ── [# ... #] raw text ────────────────────────────────────────────────────────

// lex_raw_span scans a `[#…#]` raw-text region into a `.raw_span` token. On entry
// p.pos is at the `#` immediately after `[` (the caller consumed `[`). The token's
// range is the CONTENT (between the opening `#` and the closing `#]`, exclusive); a
// lone `#` not followed by `]` is content. The closing `#]` is consumed. This is
// the single home of the raw-span boundary scan — parse_raw_text / read_raw_text_str
// delegate here (Phase 2). Byte-stable with the prior parse_raw_text loop.
fn (mut p Parser) lex_raw_span() !Token {
	p.advance() // consume '#'
	start := p.pos
	start_line := p.line
	start_col := p.col
	for {
		if p.at_end() { return error(p.make_error('unterminated raw text')) }
		b := p.peek()
		if b == `#` && p.pos + 1 < p.src.len && p.src[p.pos + 1] == `]` {
			break
		}
		p.advance()
	}
	end := p.pos // at the closing `#`
	p.advance() // consume '#'
	p.advance() // consume ']'
	return Token{
		kind: .raw_span
		pos:  TokenPos{
			offset: start
			line:   start_line
			col:    start_col
		}
		end:  end
	}
}

fn (mut p Parser) parse_raw_text() !Node {
	t := p.lex_raw_span()!
	return RawTextNode{ value: p.src[t.pos.offset..t.end].bytestr() }
}

// ── [!...] declarations ───────────────────────────────────────────────────────

fn (mut p Parser) parse_decl() !Node {
	p.advance() // consume '!'
	if p.at_end() { return error(p.make_error('unexpected EOF in declaration')) }
	b := p.peek()
	if b == `[` {
		p.advance() // consume '['
		kw := p.read_name()!
		p.skip_ws()
		if !p.at_end() && p.peek() == `[` {
			p.advance() // consume second '['
		}
		return p.parse_conditional_sect_body(kw)!
	}
	kw := p.read_name()!
	return match kw {
		'ENTITY'   { p.parse_entity_decl()! }
		'ELEMENT'  { p.parse_element_decl()! }
		'ATTLIST'  { p.parse_attlist_decl()! }
		'NOTATION' { p.parse_notation_decl()! }
		'DOCTYPE'  { error(p.make_error('DOCTYPE not allowed here')) }
		else       { error(p.make_error('unknown declaration: ${kw}')) }
	}
}

fn (mut p Parser) parse_doctype_inner() !DoctypeDecl {
	p.skip_ws()
	name := p.read_name()!
	p.skip_ws()
	ext := p.maybe_parse_external_id()
	p.skip_ws()
	mut int_subset := []Node{}
	if !p.at_end() && p.peek() == `[` {
		p.advance()
		for {
			p.skip_ws()
			if p.at_end() { break }
			b2 := p.peek()
			if b2 == `]` {
				p.advance()
				break
			}
			if b2 == `[` {
				n := p.parse_bracket_node()!
				int_subset << n
			} else if b2 == `%` {
				// PEReference [68] as a DeclSep [39]: `%name;`. Stored
				// opaque and never expanded; round-trips verbatim.
				int_subset << p.parse_pe_reference()!
			} else {
				break
			}
		}
	}
	p.skip_ws()
	p.expect(`]`)!
	return DoctypeDecl{ name: name, external_id: ext, int_subset: int_subset }
}

// parse_pe_reference consumes a parameter-entity reference `%name;`
// (grammar [68]) inside a DOCTYPE internal subset and returns an
// opaque PEReferenceNode. The reference is never expanded.
fn (mut p Parser) parse_pe_reference() !Node {
	p.advance() // consume '%'
	name := p.read_name()!
	if p.at_end() || p.peek() != `;` {
		return error(p.make_error('expected ; after parameter-entity reference %${name}'))
	}
	p.advance() // consume ';'
	return PEReferenceNode{ name: name }
}

fn (mut p Parser) try_parse_external_id() !ExternalID {
	ext := p.parse_external_id_opt() or { return error(p.make_error('expected external ID')) }
	return ext
}

// Returns ExternalID or none if not present.
fn (mut p Parser) maybe_parse_external_id() ?ExternalID {
	return p.parse_external_id_opt()
}

fn (mut p Parser) parse_external_id_opt() ?ExternalID {
	if p.at_end() { return none }
	b := p.peek()
	if b == `S` && p.pos + 6 <= p.src.len && p.src[p.pos..p.pos+6] == 'SYSTEM'.bytes() {
		p.pos += 6
		p.col += 6
		p.skip_ws()
		system := p.read_quoted() or { return none }
		return ExternalID{ system: system }
	}
	if b == `P` && p.pos + 6 <= p.src.len && p.src[p.pos..p.pos+6] == 'PUBLIC'.bytes() {
		p.pos += 6
		p.col += 6
		p.skip_ws()
		public := p.read_quoted() or { return none }
		p.skip_ws()
		if !p.at_end() && (p.peek() == `'` || p.peek() == `"`) {
			system := p.read_quoted() or { return ExternalID{ public: public } }
			return ExternalID{ public: public, system: system }
		}
		return ExternalID{ public: public }
	}
	return none
}

fn (mut p Parser) parse_entity_decl() !Node {
	p.skip_ws()
	mut kind := EntityKind.ge
	if !p.at_end() && p.peek() == `%` {
		p.advance()
		p.skip_ws()
		kind = EntityKind.pe
	}
	name := p.read_name()!
	p.skip_ws()
	if p.at_end() { return error(p.make_error('expected entity def')) }
	b := p.peek()
	def := if b == `S` || b == `P` {
		ext := p.try_parse_external_id()!
		p.skip_ws()
		mut ndata := ?string(none)
		if p.pos + 5 <= p.src.len && p.src[p.pos..p.pos+5] == 'NDATA'.bytes() {
			p.pos += 5
			p.col += 5
			p.skip_ws()
			nd := p.read_name()!
			ndata = nd
		}
		EntityDef(ExternalEntityDef{ external_id: ext, ndata: ndata })
	} else {
		EntityDef(p.read_quoted()!)
	}
	p.skip_ws()
	p.expect(`]`)!
	return EntityDeclNode{ kind: kind, name: name, def: def }
}

fn (mut p Parser) parse_element_decl() !Node {
	p.skip_ws()
	name := p.read_name()!
	p.skip_ws()
	contentspec := (p.read_until_close()!).trim_space()
	p.expect(`]`)!
	return ElementDeclNode{ name: name, contentspec: contentspec }
}

fn (mut p Parser) parse_attlist_decl() !Node {
	p.skip_ws()
	name := p.read_name()!
	mut defs := []AttDef{}
	for {
		p.skip_ws()
		if p.at_end() || p.peek() == `]` { break }
		aname := p.read_name()!
		p.skip_ws()
		atype := p.read_name()!
		p.skip_ws()
		default_val := p.read_att_default()!
		defs << AttDef{ name: aname, att_type: atype, default: default_val }
	}
	p.expect(`]`)!
	return AttlistDeclNode{ name: name, defs: defs }
}

fn (mut p Parser) read_att_default() !string {
	if !p.at_end() && p.peek() == `#` {
		p.advance()
		kw := p.read_name()!
		return '#${kw}'
	}
	return p.read_quoted()!
}

fn (mut p Parser) parse_notation_decl() !Node {
	p.skip_ws()
	name := p.read_name()!
	p.skip_ws()
	ext := p.maybe_parse_external_id()
	public_id, system_id := if e := ext {
		e.public, e.system
	} else {
		?string(none), ?string(none)
	}
	p.skip_ws()
	p.expect(`]`)!
	return NotationDeclNode{ name: name, public_id: public_id, system_id: system_id }
}

fn (mut p Parser) parse_conditional_sect_body(kw string) !Node {
	kind := if kw == 'INCLUDE' { ConditionalKind.include } else { ConditionalKind.ignore }
	mut subset := []Node{}
	for {
		p.skip_ws()
		if p.at_end() { break }
		b := p.peek()
		if b == `]` {
			saved := p.pos
			p.advance()
			if !p.at_end() && p.peek() == `]` {
				p.advance()
				if !p.at_end() && p.peek() == `]` {
					p.advance()
					break
				}
			}
			p.pos = saved
			break
		}
		if b == `[` {
			n := p.parse_bracket_node()!
			subset << n
		} else {
			break
		}
	}
	return ConditionalSectNode{ kind: kind, subset: subset }
}

// ── [*name] alias ─────────────────────────────────────────────────────────────

fn (mut p Parser) parse_alias() !Node {
	p.advance() // consume '*'
	name := p.read_name()!
	p.skip_ws()
	p.expect(`]`)!
	return AliasNode{ name: name }
}

// ── Entity ref & charref ──────────────────────────────────────────────────────

fn (mut p Parser) parse_entity_ref() !Node {
	p.advance() // consume '&'
	name := p.read_name()!
	p.expect(`;`)!
	return EntityRefNode{ name: name }
}

fn (mut p Parser) parse_amp_node() !Node {
	p.advance() // consume '&'
	if !p.at_end() && p.peek() == `#` {
		p.advance()
		return p.parse_charref()!
	}
	name := p.read_name()!
	p.expect(`;`)!
	return EntityRefNode{ name: name }
}

fn (mut p Parser) parse_charref() !Node {
	codepoint := if !p.at_end() && (p.peek() == `x` || p.peek() == `X`) {
		p.advance()
		hex := p.read_hex_digits()!
		u32(strconv.parse_int(hex, 16, 64) or { return error(p.make_error('invalid hex charref')) })
	} else {
		dec := p.read_dec_digits()!
		u32(dec.u64())
	}
	p.expect(`;`)!
	// D-K (lexicon [L32]): a char-ref must denote a valid Unicode scalar —
	// reject surrogates (D800..DFFF) and values above U+10FFFF, matching the
	// `\u`/`\U` escape rule.
	if codepoint > u32(0x10FFFF) || (codepoint >= u32(0xD800) && codepoint <= u32(0xDFFF)) {
		return error(p.make_error('invalid character reference — surrogate or above U+10FFFF (cx-err:CXERLEX-CODEPOINT)'))
	}
	value := rune_to_utf8(codepoint)
	return TextNode{ value: value }
}

// ── Element parser ────────────────────────────────────────────────────────────

fn (mut p Parser) parse_element() !Node {
	// v3.4 adversarial defense: bound element nesting to prevent
	// stack overflow on deeply nested input. spec/policies.md §5.4.
	p.depth++
	if p.depth > max_recursion_depth {
		return error('${p.line}:${p.col}: element nesting exceeds limit (${max_recursion_depth})')
	}
	defer { p.depth-- }
	raw_name := p.read_name()!
	// QName / reserved-prefix lexical rules (lexicon §2). A data-mode name folds
	// single `:` (`prefix:local`); but a QName admits AT MOST ONE colon — `a:b:c`
	// is malformed (CXERLEX-QNAME). And the `cx:` prefix is reserved entirely for
	// the serializer's canonical image — it is never authored (cx-err:E210, a
	// data-layer code per cxdm.md §11; NOT the program CXER0241 = AWAIT_TIMEOUT).
	colon_count := raw_name.count(':')
	if colon_count > 1 {
		return error(p.make_error("malformed QName `${raw_name}` — a QName admits at most one `:` (cx-err:CXERLEX-QNAME)"))
	}
	if colon_count == 1 {
		prefix := raw_name.all_before(':')
		if prefix == 'cx' {
			return error(p.make_error("reserved namespace prefix `cx:` in `${raw_name}` — the `cx:` prefix is reserved for the serializer and may not be authored (cx-err:E210)"))
		}
	}
	name := normalize_doc_element_name(raw_name)
	mut anchor := ?string(none)
	mut merge := ?string(none)
	mut id := ?string(none)
	mut data_type := ?string(none)
	// cap: 4 — typical element has 1-6 attributes; pre-sizing eliminates
	// the 0→2→4 growth churn on every element. Profile showed
	// array_ensure_cap_noscan + array_push_noscan together were ~14% of
	// parse self-time at 1 MB.
	mut attrs := []Attribute{cap: 4}
	// #455: `[; … ]` block comments encountered inside the element head.
	// Comments are lexical trivia (lexicon.ebnf §1 [L2]/[L3]: "skipped;
	// never reach the parser") and MUST NOT terminate the attribute run —
	// `[config [; c ] env=dev]` means exactly `[config env=dev]`. They are
	// retained here (not discarded) so lossless fmt round-trips them: they
	// re-emit as leading body items, mirroring how `# …` line comments are
	// already consumed without ending the run (below).
	mut head_comments := []Node{}

	for {
		// ElementMeta position: skip plain whitespace only. `#` is the
		// ID-declaration sigil, not a line-comment
		// introducer, in this position. (The skip_ws-vs-skip_ws_and_line_comments
		// distinction is documented at the top of this file.)
		p.skip_ws()
		if p.at_end() { break }
		// Token-driven element-meta dispatch (Phase 2, cxparse unification): the
		// structural sigils route through tok_peek_kind; `+`/`-`-flag and the
		// `name…`/`name::T` attribute cases still inspect the leading byte `b`
		// because they hinge on the run's CONTENT, not its structural kind. Kind
		// guards map byte-for-byte onto the former `b == …` checks: every `[`-
		// opener and both quote forms start the body (the former code reached the
		// `"` break via the trailing else — same outcome, earlier here).
		b := p.peek()
		kind := p.tok_peek_kind()
		if kind == .lbrack && p.pos + 1 < p.src.len && p.src[p.pos + 1] == `;` {
			// `[; … ]` block comment: trivia — consume, keep for lossless
			// re-emit, and CONTINUE the ElementMeta run (#455).
			p.advance() // consume '['
			head_comments << p.parse_comment()!
			continue
		}
		if kind == .rbrack || kind == .lbrack || kind == .ldirective
			|| kind == .raw_span || kind == .block_span { break }
		if kind == .quote_run || kind == .triple_span { break } // quoted text starts body

		if kind == .amp {
			// &name (no semicolon) = anchor def
			// &name; = entity ref in body → stop
			saved_pos := p.pos
			saved_line := p.line
			saved_col := p.col
			p.advance() // consume '&'
			if aname := p.try_read_name() {
				if !p.at_end() && p.peek() != `;` {
					anchor = aname
					continue
				}
			}
			p.pos = saved_pos
			p.line = saved_line
			p.col = saved_col
			break
		}

		if kind == .star {
			saved_pos2 := p.pos
			saved_line2 := p.line
			saved_col2 := p.col
			p.advance()
			if mname := p.try_read_name() {
				merge = mname
				continue
			}
			p.pos = saved_pos2
			p.line = saved_line2
			p.col = saved_col2
			break
		}

		// v3.4: syntactic ID declaration. `#name` at
		// ElementMeta position (after element name, before attributes
		// and body) declares this element's stable ID. Distinct from
		// raw-text blocks `[#...#]` (different position) and from
		// line comments. Duplicate IDs across the document are a parse
		// error caught by the resolve_ids() post-pass; here we only
		// store the declaration.
		//
		// `# ...` (hash followed by whitespace) is a line comment per
		// grammar [30b], even at ElementMeta position — the test
		// suite covers this in v34_line_comments_test.v. Disambiguation
		// is purely lookahead: `#name` → ID, `# anything` → comment.
		if kind == .hash {
			next := if p.pos + 1 < p.src.len { p.src[p.pos + 1] } else { u8(0) }
			if next == ` ` || next == `\t` || next == `\n` || next == `\r` || next == 0 {
				// #469: retained (not discarded) so lossless fmt round-trips
				// the line-comment form in ElementMeta position, exactly as
				// #455 retains the `[; … ]` block form above. Trivia still:
				// it does not end the meta run and strict canonical strips it.
				lval := p.read_line_comment_value()
				head_comments << CommentNode{ value: lval, is_line: true }
				continue
			}
			saved_pos3 := p.pos
			saved_line3 := p.line
			saved_col3 := p.col
			p.advance()
			if iname := p.try_read_name() {
				if iname.contains(':') {
					return error(p.make_error("ID '${iname}' must not contain ':'"))
				}
				id = iname
				continue
			}
			p.pos = saved_pos3
			p.line = saved_line3
			p.col = saved_col3
			break
		}

		if kind == .colon || kind == .double_colon {
			// (The TableBlock opener is the clause-child `[table[ … ]]`
			// form, detected in body position below — see peek_table_block_open.
			// The retired v0.7 `:table[ … ]` meta-slot opener was removed in the
			// table-surface cutover.)
			// The type label is the glued double-colon `name::T`.
			// `read_name` stops before `::`, so the cursor sits on the first
			// `:` here. A glued `::` is a type annotation. A spaced single `:`
			// is NOT a type annotation: per grammar.ebnf:319 a bare single-colon
			// `:NAME` in a plain data element is an atom literal [122b] — a body
			// item, not element-meta. So on a single `:` (outside schema) we
			// rewind and break to body parsing, where `parse_body`/`try_autotype`
			// reads `:NAME` as an atom ScalarNode (and [25]/[25a] then decide
			// scalar vs Text vs array). (`:table` is handled above; namespaces
			// `a:b` are glued into the name by `read_name` and never reach here.)
			// A spaced single-colon `:NAME` is an atom body item in EVERY
			// context, including schema documents. The legacy schema
			// `:slot` / `:flag` meta-label form was retired in the
			// surface cutover — schemas now use `[clause …]` children and
			// glued `name::T` ascriptions exclusively. Keeping the old
			// in_schema exemption here mis-parsed atom members such as
			// `[enum :core :extended]`, where the first `:core` was eaten as
			// a type annotation and only the trailing atom reached the body.
			save_colon_pos := p.pos
			save_colon_line := p.line
			save_colon_col := p.col
			p.advance() // consume first ':'
			mut dbl := false
			if !p.at_end() && p.peek() == `:` {
				p.advance() // consume the second ':' of `::`
				dbl = true
			}
			if !dbl {
				// spaced single-colon `:NAME` → atom body item; rewind so
				// parse_body sees the whole `:NAME` token.
				p.pos = save_colon_pos
				p.line = save_colon_line
				p.col = save_colon_col
				break
			}
			ta := p.read_type_annotation()!
			data_type = ta
			break
		}

		// RETIRED (D014, grammar [55b]): the boolean-flag sigil
		// `+name` / `-name`. In ElementMeta position a `+`/`-` immediately
		// followed by a name-start byte is the retired flag form and is a
		// hard parse error — booleans are written explicitly as `name=true` /
		// `name=false` (no dual-accept). A `-` followed by a digit (`-3`) or
		// non-name byte still falls through to body parsing (negative scalar).
		if (b == `+` || b == `-`) && p.pos + 1 < p.src.len
		   && is_name_start(p.src[p.pos + 1]) {
			sign := b
			repl := if sign == `+` { 'true' } else { 'false' }
			p.advance() // consume the sigil
			flag := p.read_name()!
			return error(p.make_error("retired boolean-flag sigil `${sign.ascii_str()}${flag}` — write the boolean explicitly as `${flag}=${repl}` (grammar [55b])"))
		}

		if is_name_start(b) {
			tok := p.read_name()!
			// D3: glued typed attribute `name::T=value`. `read_name`
			// stops before the `::` type separator. This is a typed
			// ATTRIBUTE only when an `=` follows the type; `name::T` with
			// no `=` is a typed body element / declaration (e.g. the schema
			// `[attr id::string [req]]` / `[type title::string]` forms), so
			// in that case rewind to the name and let the body parser take
			// it. Attributes are scalar-only (D2): `name::T[]=…` is an error.
			if !p.at_end() && p.peek() == `:` && p.pos + 1 < p.src.len
			   && p.src[p.pos + 1] == `:` {
				name_end_pos := p.pos
				name_end_col := p.col
				p.pos += 2
				p.col += 2
				tname := p.read_type_annotation() or {
					// not a valid type tag — hand the whole run to the body.
					p.pos = name_end_pos - tok.len
					p.col = name_end_col - tok.len
					break
				}
				if !p.at_end() && p.peek() == `=` {
					if tname.ends_with('[]') {
						return error(p.make_error("attribute `${tok}` may not carry an array type `::${tname}` — attributes are scalar-only (D2) (cx-err:CXER0100)"))
					}
					p.advance() // '='
					val_str := p.read_attr_value()!
					// The explicit ascription is coercion-CHECKED, exactly
					// like an ascribed body scalar (grammar [55]; M-ERR-2 /
					// D-H, #465/#466): a token that cannot coerce to T is
					// CXER0109 and an out-of-range sized integer is
					// CXERLEX-RANGE — never a silent 0 / clamp (the old
					// scalar_value_from_str path read `n::int=abc` as 0).
					sn := p.coerce_scalar_checked(tname, val_str)!
					attrs << new_attribute(tok, sn.value, AttributeMeta{ data_type: tname })
					continue
				}
				// `name::T` with no `=` → not a scalar attribute. Rewind.
				p.pos = name_end_pos - tok.len
				p.col = name_end_col - tok.len
				break
			}
			if !p.at_end() && p.peek() == `=` {
				p.advance()
				// v3.4: bare `@id` at attribute-value
				// position is a syntactic reference, not a literal
				// string. `'@id'` (quoted) is still a literal.
				if !p.at_end() && p.peek() == `@` {
					p.advance()
					rname := p.read_name()!
					if rname.contains(':') {
						return error(p.make_error("reference '${rname}' must not contain ':'"))
					}
					attrs << Attribute{ name: tok, value: ScalarValue(rname), is_ref: true }
				} else if !p.at_end() && p.peek() == `[`
					&& p.pos + 2 < p.src.len && p.src[p.pos + 1] == `?`
					&& p.src[p.pos + 2] == `=` {
					// J0: `attr=[?=expr]` — capture the full
					// `[?=…]` span as the attribute value string. Emitter
					// scans for `[?=…]` substrings and substitutes. This
					// branch sits before the BracketBody path because
					// BracketBody wraps content in literal `[…]`, which
					// is wrong for interpolation.
					val, dt := p.read_attr_value_typed()!
					attrs << new_attribute(tok, val, AttributeMeta{ data_type: dt })
				} else if !p.at_end() && p.peek() == `[` && p.pos + 1 < p.src.len && p.src[p.pos+1] == `#` {
					// `attr=[# … #]` — hash-raw direct as attribute value:
					// the ONE bracket-opened form D2 admits, yielding the
					// raw content as a STRING SCALAR (lexicon §10; #396
					// owner ruling 1b, 2026-07-13 — previously this parked
					// a RawTextNode in the now-retired node-valued
					// Attribute.body channel). Without this peek, the
					// scalar reader below would read `#` as a line comment
					// and run to EOF.
					s := p.read_raw_text_str()!
					attrs << new_attribute(tok, ScalarValue(s), AttributeMeta{})
				} else if !p.at_end() && p.peek() == `[` {
					// Node-valued attribute reject (D2: attributes are scalar-only;
					// GR-NODE-ATTR): the retired grammar-[55c] BracketBody form
					// `name=[BodyItem*]` AND — per the #396 owner ruling 1b
					// (2026-07-13, superseding the broad reading of ruling 1a
					// 2026-06-05) — the `[|…|]` pipe-block form. Attributes have
					// ONE value channel, a scalar; the multiline/verbatim escape
					// hatch is `[#…#]` above, and `[?=…]` interpolation is already
					// string-valued. cx-err:E211 (a data-layer code per cxdm.md
					// §11; NOT the program CXER0240 = AWAIT_ALL_FAILED).
					return error(p.make_error('node-valued attribute `${tok}=[…]` — attributes are scalar-only (D2); a `[…]` node may not be an attribute value; use the `[# … #]` raw-string form or a child element (cx-err:E211)'))
				} else {
					val, dt := p.read_attr_value_typed()!
					attrs << new_attribute(tok, val, AttributeMeta{ data_type: dt })
				}
			} else {
				p.pos -= tok.len
				break
			}
		} else {
			break
		}
	}

	// 3a (lexicon §collections [L83]): the element head is now fixed and the
	// cursor sits at the body. A body that opens with a top-level `,` means
	// the head was IMMEDIATELY followed by a comma — `[web, prod]` / `[web,]`
	// — the BARE BAREWORD ARRAY footgun that is ambiguous with an element
	// head. It is a parse error; the writer must quote the items
	// (`['web', 'prod']`) or name the list (`[tags web, prod]`).
	if !p.at_end() && p.peek() == `,` {
		return error(p.make_error("bareword followed by ',' is an ambiguous bare array — quote the items (['${name}', …]) or name the list ([list ${name}, …]) (cx-err:CXER0100)"))
	}

	// (grammar [29]/[50] + TABLE_OPEN lexer note): the TableBlock
	// clause-child form `[NAME [table[ COLS ]] ROWS]`. When the element
	// body opens with the reserved `[table[` head, the element is the
	// tabular alternative of [50]: the `[table[ … ]]` clause declares the
	// columns, the remaining body items are the rows, and no other Body
	// items apply. (The earlier `:table[ … ]` meta-slot form is
	// handled above and is being cut over to this clause-child form.)
	//
	// #478: the TableBlock occupies the TypeAnnotation slot of ElementMeta
	// ([29] "in place of TypeAnnotation [26]"), so every OTHER head meta
	// collected above — anchor, merge, id, attributes — belongs to the
	// table element and MUST be attached (this branch previously passed an
	// empty attrs list, silently dropping `region=west` in
	// `[users region=west [table[…]] …]`). An explicit glued `::T`
	// annotation is the one meta that CANNOT coexist: the table clause IS
	// the element's type, and the implied `table` would silently overwrite
	// the annotation — reject it loudly instead (no-silent-loss contract).
	// (The annotated head path breaks out of the meta loop with the cursor
	// still on the whitespace before the body, so the conflict check needs
	// its own ws-tolerant lookahead — the reserved TABLE_OPEN token would
	// otherwise fall through and misparse as a nested element named `table`.)
	if dt := data_type {
		saved_tb_pos := p.pos
		saved_tb_line := p.line
		saved_tb_col := p.col
		p.skip_ws()
		if p.peek_table_block_open() {
			return error(p.make_error('explicit type annotation `::${dt}` conflicts with the `[table[…]]` clause — the table block is the element\'s type (grammar [29]/[50], #478) (cx-err:CXER0100)'))
		}
		p.pos = saved_tb_pos
		p.line = saved_tb_line
		p.col = saved_tb_col
	}
	if p.peek_table_block_open() {
		p.expect(`[`)!                  // outer '[' of the `[table` opener
		p.read_name()!                  // 'table'
		p.skip_ws()
		p.expect(`[`)!                  // header '['
		cols := p.parse_table_header()!
		p.expect(`]`)!                  // header ']'
		p.skip_ws_and_line_comments()
		p.expect(`]`)!                  // `[table[ … ]]` clause-child ']'
		rows := p.parse_table_rows(cols)!
		p.skip_ws_and_line_comments()
		p.expect(`]`)!                  // outer element ']'
		// Head comments ride along as items (trivia — table emitters render
		// rows from the pooled table data; the nodes are retained, not lost).
		return new_element(name, ElementMeta{
			anchor:    anchor
			merge:     merge
			id:        id
			data_type: ?string('table')
		}, attrs, head_comments).with_table(&TableData{ cols: cols, rows: rows })
	}

	mut is_annotated := false
	if _ := data_type { is_annotated = true }

	mut items := []Node{}
	mut final_dt := data_type
	if !is_annotated && p.body_is_flat_comma_array() {
		// §9 [L25c]: a top-level comma is the universal list signal — an
		// unannotated, child-free body with a top-level comma is an array
		// of any item types (strings included). See lexicon.ebnf §9.
		raw := p.parse_comma_body()!
		p.expect(`]`)!
		body, dt := finalize_comma_array(raw)
		items = body.clone()
		final_dt = dt
	} else if !is_annotated && p.body_is_typed_list() {
		// §9 [L25a/b] TYPED LIST: a no-comma body of 2+ tokens whose every bare
		// scalar token auto-types (number / atom / bool / date) or is quoted,
		// with child elements interleaving as mixed content. Each token is typed
		// in place → N discrete typed children with NO element array type. This
		// is the @CHOICE-1 "one layer" replacement for the old whitespace
		// auto-array (G-BODY-2/3, M-SCALAR-ITEM). A run with any bareword stays
		// prose and routes to parse_body instead. See body_is_typed_list.
		items = p.parse_self_delim_body()!
		p.expect(`]`)!
	} else {
		items = p.parse_body(data_type)!
		p.expect(`]`)!
		// @CHOICE-1 §9-one-layer (slice C): the inferred-array annotation `::[]`
		// KEEPS its `[]` marker — each body item keeps its OWN auto-type
		// (heterogeneous, no concrete-type inference, no int→float promotion;
		// M-TYPED-ARRAY-2 / P2-INFERARR). parse_body already auto-typed each item
		// per token (is_inferred_array), so final_dt simply stays `[]`. An
		// explicit `::T[]` (handled by parse_body's is_array branch) coerces to T.
		//
		// NOTE: the old whitespace auto-array (try_auto_array → a single `T[]`
		// element) is RETIRED — a whitespace scalar run is now a typed list of
		// discrete children, classified above by body_is_typed_list (@CHOICE-1).
	}
	// #455: head comments precede every parsed body item in source order.
	if head_comments.len > 0 {
		items.prepend(head_comments)
	}

	// recognize `[ref @id]` body-position node form.
	// The body parser produced a single TextNode of the form
	// '@<name>' for the bare-@id token; lift it into Element.body_ref
	// so the validator can check it and the emitter can re-render the
	// syntactic form on round-trip. The `ref` element name is reserved
	// when used in element-body position — any `[ref ...]` shape OTHER
	// than the exact `[ref @<Name>]` body-position form is a parse
	// error (E207).
	mut body_ref := ?string(none)
	if name == 'ref' {
		mut matched := false
		if attrs.len == 0 && items.len == 1 {
			first := items[0]
			if first is TextNode {
				tv := first.value.trim_space()
				if tv.len > 1 && tv[0] == `@` {
					rname := tv[1..]
					if rname.len > 0 && is_name_start(rname[0]) && !rname.contains(':') {
						mut all_name := true
						for i in 1 .. rname.len {
							if !is_name_char(rname[i]) {
								all_name = false
								break
							}
						}
						if all_name {
							body_ref = rname
							items = []
							matched = true
						}
					}
				}
			}
		}
		if !matched {
			return error('E207: cx-err: `ref` is reserved — only `[ref @<Name>]` body-position form is admitted; migration: rename to `[reference …]` or wrap content in a non-reserved element.')
		}
	}

	return new_element(name, ElementMeta{
		anchor:    anchor
		merge:     merge
		id:        id
		body_ref:  body_ref
		data_type: final_dt
	}, attrs, items)
}

fn (mut p Parser) read_type_annotation() !string {
	if p.pos + 2 <= p.src.len && p.src[p.pos] == `[` && p.src[p.pos+1] == `]` {
		p.pos += 2
		p.col += 2
		return '[]'
	}
	base := p.read_name()!
	// validate the type tag against the closed CXDM set.
	// An unknown tag (e.g. `::name`, `::email`) is a parse error rather
	// than a silently-accepted bogus data-type. This closes the
	// unvalidated-type defect: `[x::name 'A']` no longer yields a
	// nonsense `dataType:"name"`. Type ascription now arrives only via the
	// glued `::` form (the legacy single-colon path is a parse error at the
	// meta loop), so validation is unconditional. Schema context is exempt.
	if !p.in_schema && !is_valid_type_tag(base) {
		return error(p.make_error("unknown type tag '::${base}' — not a CXDM type (cx-err:CXER0107 E_UNKNOWN_TYPE_TAG)"))
	}
	long := expand_type_alias(base)
	if p.pos + 2 <= p.src.len && p.src[p.pos] == `[` && p.src[p.pos+1] == `]` {
		p.pos += 2
		p.col += 2
		return '${long}[]'
	}
	return long
}

fn expand_type_alias(s string) string {
	return match s {
		'i'  { 'int' }
		'f'  { 'float' }
		'b'  { 'bool' }
		's'  { 'string' }
		'd'  { 'date' }
		'dt' { 'datetime' }
		else { s }
	}
}

// is_valid_type_tag reports whether `name` is a recognized CXDM scalar
// type tag usable as a `::T` element/scalar type-ascription. This is the
// closed builtin set + canonical.md §2.11.4: the base
// scalar types and sized numerics — long names only (drops the
// `:i`/`:s`/… short aliases). A trailing `[]` (array suffix) is accepted
// on any valid base. Schema-/domain-type names are NOT recognized here —
// they are validated at schema-application time, never as a bare `::T`
// ascription. An unknown tag is a parse error (CXER0107 E_UNKNOWN_TYPE_TAG).
//
// `'table'` is the internal table-block marker and is accepted so the
// `[name :table […]]` block form continues to round-trip.
pub fn is_valid_type_tag(name string) bool {
	mut base := name
	if base.ends_with('[]') {
		base = base[..base.len - 2]
	}
	return base in valid_type_tag_set
}

// valid_type_tag_set is the closed set of recognized base type names
// (long forms + sized numerics + internal markers; no short
// aliases). Mirrors the codec type mapping in binary.v::decode_attribute —
// keep the two in sync when the type system gains a new scalar kind.
const valid_type_tag_set = [
	// Base scalar kinds.
	'int', 'float', 'bool', 'string', 'date', 'datetime', 'bytes',
	'decimal', 'bigint', 'atom', 'null', 'f16',
	// Temporal-span refinements (lexicon [L25]/[L26]).
	'duration', 'period',
	// Sized numerics (long-only — no short alias).
	'u8', 'u16', 'u32', 'u64', 'i8', 'i16', 'i32', 'i64', 'f32', 'f64',
	// Internal table-block marker.
	'table',
]

// ── Body parser ───────────────────────────────────────────────────────────────

fn (mut p Parser) parse_body(type_ann ?string) ![]Node {
	// cap: 4 — typical element body has 0-5 children (mixed text + child
	// elements). Pre-sizing avoids 2-3 reallocs on most elements.
	mut items := []Node{cap: 4}
	is_inferred_array := if ta := type_ann { ta == '[]' } else { false }
	is_array := if ta := type_ann { !is_inferred_array && ta.ends_with('[]') } else { false }
	elem_type := if is_array {
		if ta := type_ann { ta[..ta.len-2] } else { 'string' }
	} else {
		'string'
	}

	mut text_buf := []u8{cap: 64}
	mut has_child_element := false
	mut after_non_text := false
	// #469: set when a mid-run `[; … ]` comment had whitespace on its left;
	// the join space is applied by the NEXT consuming branch (erasure
	// semantics — `a [; c ] b` ≡ `a b`) and never trails the run.
	mut pending_join_ws := false

	for {
		if p.at_end() { break }
		had_ws := is_ws(p.peek())
		// Skip whitespace but PRESERVE line comments — they should round-trip
		// through `cx fmt` per spec/cheatsheet, not be silently dropped.
		// #469: a line comment is lexical trivia (lexicon.ebnf §1 [L2]/[L3])
		// and must NOT flush/split a bare text run — the run continues across
		// it exactly as it would across the whitespace the comment sits in
		// (the CommentNode is retained positionally for lossless fmt).
		for !p.at_end() {
			c := p.peek()
			if c == ` ` || c == `\t` || c == `\r` || c == `\n` {
				p.advance()
			} else if c == `#` {
				val := p.read_line_comment_value()
				items << CommentNode{ value: val, is_line: true }
			} else {
				break
			}
		}

		if p.at_end() { break }
		// Token-driven dispatch (Phase 2, cxparse unification): tok_peek_kind
		// classifies the structural shape from the leading byte(s) instead of an
		// `if b == …` chain. The kind groups map byte-for-byte onto the former
		// checks — every `[`-opener (child / `[?` / `[#` / `[|`) is a bracket
		// node expanded by parse_bracket_node; `'`/`"` (single or triple) is a
		// quote; everything else (`:` `,` `=` `(`/`{` not a literal, barewords,
		// numbers) falls to the scalar-run branch — so this is byte-stable.
		// `had_ws` stays the pre-skip `is_ws(p.peek())` value above (NOT
		// tok_adjacent_to_prev): the leading-space rule must ignore a skipped
		// line comment, which adjacency would not.
		kind := p.tok_peek_kind()
		b := p.peek()
		if kind == .rbrack { break }

		// #469: a `[; … ]` block comment inside a bare text run is lexical
		// trivia (lexicon.ebnf §1 [L2]/[L3]) — it must NOT flush/split the
		// run into separate text nodes (that moved the strict-canonical
		// hash). The CommentNode is retained for lossless fmt; the run
		// continues across it with erasure semantics: only REAL whitespace
		// around the comment contributes the join space (`a [; c ] b` ≡
		// `a b`, `a[; c ]b` ≡ `ab`). The last-byte guard keeps ws on both
		// sides of the comment from doubling into two join spaces.
		if kind == .lbrack && p.pos + 1 < p.src.len && p.src[p.pos + 1] == `;` {
			// The join space is PENDING, not appended: a comment at the END
			// of the body (`[config a b [; c ]]`) must not leave a trailing
			// space on the run. The next consuming branch applies it.
			pending_join_ws = pending_join_ws || (had_ws && text_buf.len > 0)
			p.advance() // consume '['
			items << p.parse_comment()!
			continue
		}
		join_ws := had_ws || pending_join_ws
		pending_join_ws = false

		if kind == .lbrack || kind == .ldirective || kind == .raw_span || kind == .block_span {
			has_child_element = true
			if join_ws && text_buf.len > 0 && text_buf.last() != ` ` { text_buf << ` ` }
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			child := p.parse_bracket_node()!
			items << child
			after_non_text = true
			continue
		}

		if kind == .quote_run || kind == .triple_span {
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			if b == `'` && p.pos + 3 <= p.src.len && p.src[p.pos] == `'` && p.src[p.pos+1] == `'` && p.src[p.pos+2] == `'` {
				n := p.read_triple_quoted()!
				items << n
			} else if b == `"` && p.pos + 3 <= p.src.len && p.src[p.pos] == `"` && p.src[p.pos+1] == `"` && p.src[p.pos+2] == `"` {
				n := p.read_triple_double_quoted()!
				items << n
			} else if b == `"` {
				// Double-quoted in element-body position
				// (previously only single-quoted was recognised here,
				// an asymmetry with collection-literal items and
				// attribute values).
				quoted := p.read_quoted()!
				items << TextNode{ value: quoted }
			} else {
				quoted := p.read_quoted_text()!
				items << TextNode{ value: quoted }
			}
			after_non_text = false
			continue
		}

		if kind == .amp {
			if join_ws {
				if text_buf.len > 0 {
					if text_buf.last() != ` ` { text_buf << ` ` }
				} else if after_non_text {
					text_buf << ` `
				}
			}
			n := p.parse_amp_node()!
			match n {
				TextNode {
					text_buf << n.value.bytes()
					after_non_text = false
				}
				else {
					if text_buf.len > 0 {
						items << TextNode{ value: text_buf.bytestr() }
						text_buf = []u8{}
					}
					items << n
					after_non_text = true
				}
			}
			continue
		}

		// v3.6: SequenceLiteral `( a, b )` and MapLiteral
		// `{ k: v }` introducers in body position per grammar [56a] /
		// [56c]. Disambiguated against literal text containing parens /
		// braces by the comma- / colon-marker rule (peek_is_sequence_*
		// / peek_is_map_*). Bare `(text)` and `{text}` continue to parse
		// as body text. Empty `()` and `{}` are recognized as empty
		// sequence / map respectively.
		if kind == .lparen && p.peek_is_sequence_literal_at_paren() {
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			items << p.parse_sequence_literal()!
			after_non_text = true
			continue
		}
		if kind == .lbrace && p.peek_is_map_literal_at_brace() {
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			items << p.parse_map_literal()!
			after_non_text = true
			continue
		}

		if !is_inferred_array && !is_array {
			// Text-accumulation hot path: read the token's bytes
			// directly into text_buf, skipping the read_token() →
			// `[]u8 → string → []u8` round-trip (which allocated
			// twice per token + a third time for the bytes-copy into
			// text_buf). On the §11.6 gate 15 bench corpus this is
			// ~6.6 M tokens; the round-trip was dominating self-time
			// in parse_body.
			if text_buf.len > 0 {
				// (join_ws carries the ws a mid-run comment sat in —
				// #469 erasure semantics.)
				if join_ws && text_buf.last() != ` ` { text_buf << ` ` }
			} else if after_non_text && join_ws {
				text_buf << ` `
			}
			p.read_token_into(mut text_buf)!
			after_non_text = false
		} else {
			tok := p.read_token()!
			if is_inferred_array {
				scalar := try_autotype(tok) or {
					ScalarNode{ data_type: .string_type, value: ScalarValue(tok) }
				}
				items << scalar
			} else {
				items << p.coerce_scalar_checked(elem_type, tok)!
			}
		}
	}

	if text_buf.len > 0 {
		text_val := text_buf.bytestr()
		if !has_child_element && items.len == 0 {
			if ta := type_ann {
				if !ta.ends_with('[]') {
					items << p.coerce_scalar_checked(ta, text_val)!
					return items
				}
			}
			// Reserved-atom reject (lexicon §3.6 [122b]): `:true` / `:false` /
			// `:null` are not atoms — they shadow the bool/null scalar literals
			// and are a lexical error (CXERLEX-ATOM), not silently a string.
			if is_reserved_atom_token(text_val) {
				return error(p.make_error('reserved atom `${text_val}` — :true/:false/:null may not be used as atoms (cx-err:CXERLEX-ATOM)'))
			}
			if scalar := try_autotype(text_val) {
				items << scalar
				return items
			}
		}
		items << TextNode{ value: text_val }
	}

	return items
}

// (The old whitespace auto-array — try_auto_array / try_autotype_array — was
// REMOVED with @CHOICE-1 §9-one-layer slice A: a whitespace scalar run is now a
// typed list of discrete children classified by body_is_typed_list, not a single
// `T[]` element. See the §9-one-layer commits.)

// ── §9 [L25c] comma-separated body array ───────────────────────────────────

// body_is_flat_comma_array reports whether the element body beginning at
// p.pos is a §9 [L25c] comma-separated scalar body: it has a top-level
// comma and contains NO child-element / collection / entity introducer
// (`[` `(` `{` `&`) outside of quotes (those route through parse_body's
// mixed-content path instead, per §9 "no child elements"). Quote regions
// (single / double / triple) and line comments are skipped so their inner
// commas and brackets do not count. Pure lookahead — p.pos is unchanged.
fn (p &Parser) body_is_flat_comma_array() bool {
	mut i := p.pos
	mut saw_comma := false
	mut at_tok_start := true
	for i < p.src.len {
		c := p.src[i]
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
			for i < p.src.len && p.src[i] != `\n` { i++ }
			continue
		}
		// Any structural introducer disqualifies the flat-array fast path —
		// child elements, collection literals, and entities are mixed content.
		if c == `[` || c == `(` || c == `{` || c == `&` { return false }
		// A quote opens a string ONLY at a token start; a mid-token `'` is a
		// bare-prose apostrophe (`it's`) and must not swallow the following
		// comma — else this scan misses the array signal.
		if (c == `'` || c == `"`) && at_tok_start {
			i = skip_quoted_region(p.src, i)
			at_tok_start = false
			continue
		}
		if c == `,` { saw_comma = true }
		at_tok_start = false
		i++
	}
	return saw_comma
}

// body_is_typed_list reports whether the element body beginning at p.pos is a
// §9 [L25a/b] TYPED LIST: a no-comma body of 2+ top-level tokens in which EVERY
// bare scalar token auto-types to a non-string scalar (number / atom / bool /
// date) or is a quoted string, and child elements `[…]` may interleave (mixed
// content). The presence of even one BAREWORD (a bare token that does NOT
// auto-type, e.g. `the`, `Version`, `it's`) makes the whole body PROSE instead —
// it routes to parse_body and merges into a Text run (G-BODY-1, conformance
// 009/014). A top-level comma (→ [L25c] comma path) or a `(`/`{`/`&` introducer
// (collection / entity → parse_body, which handles those) also disqualifies it.
// Quote regions, child brackets and line comments are skipped so their interiors
// don't count. Pure lookahead — p.pos is unchanged.
//
// This is the @CHOICE-1 "one layer" body classifier (cxparse unification): it
// SUPERSEDES the old whitespace auto-array (try_auto_array, which produced a
// single `T[]`-typed element) — a typed list is now N discrete typed CHILDREN
// with no element array type, per the formal witnesses (G-BODY-2/3, M-SCALAR-ITEM).
fn (p &Parser) body_is_typed_list() bool {
	mut i := p.pos
	mut at_tok_start := true
	mut tokens := 0
	for i < p.src.len {
		c := p.src[i]
		if c == `]` { break } // body terminator (top level)
		if c == ` ` || c == `\t` || c == `\r` || c == `\n` {
			at_tok_start = true
			i++
			continue
		}
		if c == `#` && at_tok_start {
			i++
			for i < p.src.len && p.src[i] != `\n` { i++ }
			continue
		}
		if c == `,` { return false } // top-level comma → [L25c] comma path
		// Collection / entity introducers route to parse_body (it already images
		// `(`/`{` literals and `&` entity-refs correctly — e.g. G-MARKUP-1).
		if c == `(` || c == `{` || c == `&` { return false }
		// A child element `[…]` (or `[#…#]` / `[|…|]`) is admitted as a list item
		// (mixed content, G-BODY-2). Skip its balanced span and count it.
		if c == `[` {
			i = skip_bracket_region(p.src, i)
			tokens++
			at_tok_start = true
			continue
		}
		// A `'`/`"` is a quoted-string token ONLY at a token start. A MID-token
		// quote is a literal apostrophe in bare prose (`it's`, `Bob's`) — read by
		// the bare-token branch, where try_autotype fails → the body is prose.
		if (c == `'` || c == `"`) && at_tok_start {
			tokens++
			i = skip_quoted_region(p.src, i)
			at_tok_start = true
			continue
		}
		if at_tok_start {
			tokens++
			start := i
			for i < p.src.len {
				cc := p.src[i]
				if cc == ` ` || cc == `\t` || cc == `\r` || cc == `\n` || cc == `]` || cc == `,` {
					break
				}
				i++
			}
			tok := p.src[start..i].bytestr()
			if try_autotype(tok) == none {
				return false // a bareword → prose, not a typed-list item
			}
			at_tok_start = true
			continue
		}
		at_tok_start = false
		i++
	}
	return tokens >= 2
}

// skip_bracket_region returns the index just past the balanced bracket span that
// starts at `start` (a `[`/`(`/`{`). Quote-aware (so a `]` inside a string does
// not close the span). On an unbalanced span it returns src.len.
fn skip_bracket_region(src []u8, start int) int {
	mut i := start
	mut depth := 0
	// A `'`/`"` opens a quoted region ONLY at a token start (after the opening
	// bracket, whitespace, or a `,`/`=` separator). A MID-token quote is a
	// literal apostrophe in bare prose (`it's`, `Bob's`) and must NOT be treated
	// as a string opener — otherwise this scan runs the "string" past the
	// element's own `]`, miscounting depth and corrupting every later body
	// (symptom: a spurious "unterminated quoted text" at EOF). Mirrors the
	// at_tok_start rule the body_is_typed_list scanner already uses.
	mut at_tok_start := true
	for i < src.len {
		c := src[i]
		if (c == `'` || c == `"`) && at_tok_start {
			i = skip_quoted_region(src, i)
			at_tok_start = false
			continue
		}
		if c == `[` || c == `(` || c == `{` {
			depth++
			at_tok_start = true
			i++
			continue
		}
		if c == `]` || c == `)` || c == `}` {
			depth--
			if depth == 0 {
				return i + 1
			}
			at_tok_start = false
			i++
			continue
		}
		if c == ` ` || c == `\t` || c == `\r` || c == `\n` || c == `,` || c == `=` {
			at_tok_start = true
			i++
			continue
		}
		at_tok_start = false
		i++
	}
	return src.len
}

// parse_self_delim_body parses a §9 [L25b] self-delimiting list body — each
// whitespace-separated token becomes its own auto-typed item. Mirrors the
// item-typing of the comma path but splits on whitespace. The caller has
// confirmed via body_is_self_delim_list that there is no top-level comma and no
// structural introducer, so a token is exactly one of: a quoted string (→
// string ScalarNode, matching the program parser's evaluated string value), a
// scalar literal / `:name` atom (→ ScalarNode via try_autotype), or a bareword
// (→ TextNode, which renders bare). Stops at the closing `]` (left for caller).
fn (mut p Parser) parse_self_delim_body() ![]Node {
	mut items := []Node{}
	for {
		// Preserve line comments between/after typed-list items as CommentNode
		// siblings — this body renders one item per line (multi-line element),
		// so a comment HAS a canonical home here and must round-trip through
		// `cx fmt` (matching parse_body's mixed-content path).
		p.skip_ws_collecting_comments(mut items)
		if p.at_end() { return error(p.make_error('unterminated element body')) }
		b := p.peek()
		if b == `]` { break }
		// A child element / content node `[…]` (`[#…#]`, `[|…|]`, …) is a typed-list
		// item — mixed content (G-BODY-2). The detector guarantees `(`/`{`/`&` do
		// not reach here, so only `[`-introduced nodes appear.
		if b == `[` {
			child := p.parse_bracket_node()!
			items << child
			continue
		}
		if b == `'` || b == `"` {
			if p.pos + 3 <= p.src.len && p.src[p.pos] == `'`
				&& p.src[p.pos + 1] == `'` && p.src[p.pos + 2] == `'` {
				n := p.read_triple_quoted()!
				items << self_delim_string_node(n)
			} else if p.pos + 3 <= p.src.len && p.src[p.pos] == `"`
				&& p.src[p.pos + 1] == `"` && p.src[p.pos + 2] == `"` {
				n := p.read_triple_double_quoted()!
				items << self_delim_string_node(n)
			} else if b == `"` {
				s := p.read_quoted()!
				items << Node(ScalarNode{ data_type: .string_type, value: ScalarValue(s) })
			} else {
				s := p.read_quoted_text()!
				items << Node(ScalarNode{ data_type: .string_type, value: ScalarValue(s) })
			}
			continue
		}
		// A bare token runs to the next whitespace / `]`. It is read whole
		// (mid-token `'`/`"` apostrophes included, e.g. `it's`) — only a
		// LEADING quote (handled above) opens a quoted string. The detector
		// guarantees no `,`/`[`/`(`/`{`/`&` appears at top level here.
		tok := p.read_self_delim_token()!
		if scalar := try_autotype(tok) {
			items << Node(scalar)
		} else {
			items << Node(TextNode{ value: tok })
		}
	}
	return items
}

// read_self_delim_token reads one bare self-delimiting body token: from the
// current position to the next whitespace or `]`. Unlike read_slot_token it
// does NOT stop at `'`/`"` — a quote inside a bare token is a literal
// apostrophe (`it's`), not a new item; a token-leading quote is dispatched by
// the caller before this is reached.
fn (mut p Parser) read_self_delim_token() !string {
	mut s := []u8{}
	for !p.at_end() {
		b := p.peek()
		if is_ws(b) || b == `]` { break }
		s << b
		p.advance()
	}
	if s.len == 0 {
		return error(p.make_error('expected token in element body'))
	}
	return s.bytestr()
}

// self_delim_string_node normalizes a triple-quoted result node into a string
// ScalarNode so self-delimiting items render uniformly (quoted) and match the
// program parser's evaluated string value.
fn self_delim_string_node(n Node) Node {
	v := if n is TextNode { n.value } else { '' }
	return Node(ScalarNode{ data_type: .string_type, value: ScalarValue(v) })
}

// skip_quoted_region returns the index just past the quoted region that
// starts at `start` (a `'` or `"` byte). Handles triple-quoted (raw, no
// escapes) and single-line quoted (with `\`-escapes). On an unterminated
// quote it returns src.len.
fn skip_quoted_region(src []u8, start int) int {
	q := src[start]
	if start + 2 < src.len && src[start + 1] == q && src[start + 2] == q {
		// triple-quoted: raw, terminated by the next matching triple.
		mut i := start + 3
		for i < src.len {
			if src[i] == q && i + 2 < src.len && src[i + 1] == q && src[i + 2] == q {
				return i + 3
			}
			i++
		}
		return src.len
	}
	mut i := start + 1
	for i < src.len {
		d := src[i]
		if d == `\\` {
			i += 2
			continue
		}
		if d == q { return i + 1 }
		i++
	}
	return src.len
}

// parse_comma_body parses a §9 [L25c] comma-separated element body — a flat
// list of scalar / quoted-string items. The parser is positioned at the
// first body byte (after the head + attributes) and STOPS at the closing
// `]` (left for the caller to consume). Each slot is parsed via
// parse_collection_item (the same auto-typing the `[a, b]` array literal
// uses), so quote-awareness, scalar auto-typing, and the trailing-comma
// rule are shared. Empty slots (`[xs ,]`, `[xs a,,b]`) are a parse error.
fn (mut p Parser) parse_comma_body() ![]Node {
	mut items := []Node{}
	for {
		p.skip_ws_and_line_comments()
		if p.at_end() { return error(p.make_error('unterminated element body')) }
		if p.peek() == `]` { break } // end, or a single trailing comma
		items << p.parse_collection_item()!
		p.skip_ws_and_line_comments()
		if p.at_end() { return error(p.make_error('unterminated element body')) }
		b := p.peek()
		if b == `,` {
			p.advance()
			continue
		}
		if b == `]` { break }
		return error(p.make_error('expected `,` or `]` in element body'))
	}
	return items
}

// finalize_comma_array converts the parsed comma items into the element body
// representation: a SINGLE `<cx:array>` ArrayNode child holding the items
// (§9 [L25c] "like ArrayLiteral"). @CHOICE-1 (slice B): a comma body is ALWAYS
// a nested Array node — NOT a `T[]`-typed flat body and NOT int→float promoted
// (G-COMMABODY-1/2, M-STRING-2). This is what distinguishes a comma list
// `[xs a, b]` (→ `<xs><cx:array>…</cx:array></xs>`) from a whitespace typed list
// `[xs a b]` (→ discrete children) and from an explicit `[xs::T[] a b]` (→ a
// `T[]`-typed element). Bare / quoted text items normalize to string scalars;
// any other node kind is carried verbatim as an array item.
fn finalize_comma_array(raw []Node) ([]Node, ?string) {
	mut arr := []Node{}
	for it in raw {
		if it is TextNode {
			arr << Node(ScalarNode{ data_type: .string_type, value: ScalarValue(it.value) })
		} else {
			arr << it
		}
	}
	return [Node(ArrayNode{ items: arr })], ?string(none)
}

// (infer_array_type / promote_int_to_float were REMOVED with @CHOICE-1
// §9-one-layer slice C: `::[]` keeps its `[]` marker and per-item heterogeneous
// types — no concrete-type inference, no int→float promotion.)

// ── Auto-typing ───────────────────────────────────────────────────────────────

// strip_underscores removes internal `_` separators from a numeric
// literal token. Returns the cleaned string, or none if underscores are
// malformed (leading, trailing, or doubled). This implements the v3.4
// numeric-underscore readability rule for grammar [20a]/[20b]/[20c].
//
// Accepts: 1_000_000, 0xDEAD_BEEF, 1.234_567, 1_000e3
// Rejects: _1000, 1000_, 1__000
fn strip_underscores(tok string) ?string {
	if tok.len == 0 { return tok }
	if tok[0] == `_` { return none }
	if tok[tok.len - 1] == `_` { return none }
	if tok.contains('__') { return none }
	if !tok.contains('_') { return tok }
	return tok.replace('_', '')
}

// has_ascii_digit reports whether `s` contains at least one ASCII digit.
// Used to keep a digit-less token (e.g. bare `e`) out of the float branch.
fn has_ascii_digit(s string) bool {
	for c in s {
		if c >= `0` && c <= `9` {
			return true
		}
	}
	return false
}

// is_v34_decimal_int checks the v3.4 leading-zero rule for decimal
// integer literals. Returns true if `tok` is a valid v3.4 integer
// literal (post-underscore-stripping).
//
// v3.4 rule: integer literals MUST NOT have a leading zero except for
// the literal '0' itself. '02134' is no longer auto-typed as int 2134
// — it falls through to Text. Hex integers (0x...) are exempt because
// the prefix disambiguates.
//
// `tok` may have a leading sign (`-` or `+`); the check applies to the
// digit portion.
fn is_v34_decimal_int(tok string) bool {
	mut s := tok
	if s.len > 0 && (s[0] == `-` || s[0] == `+`) {
		s = s[1..]
	}
	if s.len == 0 { return false }
	// all digits (after the optional sign) …
	for c in s {
		if c < `0` || c > `9` { return false }
	}
	// … and not a disallowed leading-zero run (the shared [L20c] rule).
	return !has_leading_zero_int(tok)
}

// try_autotype_bytes is the byte-slice twin of `try_autotype` for the
// §11.6 gate-15 attribute-value hot path. Recognises `true` / `false`
// / `null` / decimal int (with optional underscore separators) / hex
// int / float (sign + digits + `.` or `e`/`E`). When the token shape
// matches one of these, parses the value directly from the bytes
// without ever materialising the token as a `string` — saves one
// `bytestr()` allocation per call (≈ 4.4 M on the gate-15 corpus).
// Falls back to `try_autotype(string)` for less common shapes (date /
// datetime / leading-zero ints) that already do per-char inspection
// via the string surface; the fallback's `bytestr()` is the same one
// we'd have allocated anyway.
fn try_autotype_bytes(buf []u8) ?ScalarNode {
	n := buf.len
	if n == 0 { return none }
	// bool / null — fast char-by-char compare.
	if n == 4 && buf[0] == `t` && buf[1] == `r` && buf[2] == `u` && buf[3] == `e` {
		return ScalarNode{ data_type: .bool_type, value: ScalarValue(true) }
	}
	if n == 5 && buf[0] == `f` && buf[1] == `a` && buf[2] == `l` && buf[3] == `s` && buf[4] == `e` {
		return ScalarNode{ data_type: .bool_type, value: ScalarValue(false) }
	}
	if n == 4 && buf[0] == `n` && buf[1] == `u` && buf[2] == `l` && buf[3] == `l` {
		return ScalarNode{ data_type: .null_type, value: ScalarValue(NullValue{}) }
	}
	// Decide shape with a single pass over bytes — record whether the
	// token looks like an int, a float, or something else (date / hex /
	// string fallback).
	mut start := 0
	if buf[0] == `-` || buf[0] == `+` { start = 1 }
	if start >= n { return none }
	// Hex / leading-zero / underscores → fall back to string path.
	mut has_dot := false
	mut has_exp := false
	mut has_underscore := false
	mut has_digit := false
	mut all_digit_or_sign := true
	for i in start .. n {
		c := buf[i]
		if c >= `0` && c <= `9` {
			has_digit = true
			continue
		}
		if c == `.` {
			has_dot = true
			all_digit_or_sign = false
			continue
		}
		if c == `e` || c == `E` {
			has_exp = true
			all_digit_or_sign = false
			continue
		}
		if c == `_` {
			has_underscore = true
			all_digit_or_sign = false
			continue
		}
		if (c == `-` || c == `+`) && i > start && (buf[i-1] == `e` || buf[i-1] == `E`) {
			continue
		}
		// Anything else (letter, `:`, etc.) → not a plain numeric.
		all_digit_or_sign = false
		// fall back to string-based path
		return try_autotype(buf.bytestr())
	}
	// Plain decimal int (no `.` / `e` / `_`, all digits with optional
	// sign). Apply the v3.4 leading-zero rule: tokens like `0123` are
	// not auto-typed — fall through to the string path. `0` and `-0`
	// remain valid.
	if all_digit_or_sign {
		body_start := start
		if n - body_start > 1 && buf[body_start] == `0` {
			// leading-zero rule — defer to string path
			return try_autotype(buf.bytestr())
		}
		// parse_int on bytes via bytestr — we still allocate one string
		// here on the int path, but only because strconv lives over
		// `string`. The amortised win vs. always-allocate is still ~2×
		// when bool / null / float / non-numeric paths dominate. This
		// branch only fires for plain decimal ints; on the gate-15
		// corpus that's ~1/3 of attribute tokens (`:id N`, `:port P`).
		s := buf.bytestr()
		if v := parse_i64_checked(s) {
			return ScalarNode{ data_type: .int_type, value: ScalarValue(v) }
		}
		// [L20]/D-H: over-i64 well-formed decimal int → bigint (drop a
		// redundant leading `+`), matching the string-surface try_autotype.
		bigint_str := if s.starts_with('+') { s[1..] } else { s }
		return ScalarNode{ data_type: .bigint_type, value: ScalarValue(bigint_str) }
	}
	// A float needs a digit mantissa — a digit-less token (bare `e`/`.`)
	// must NOT atof64 to 0.0; defer it to the string path → Text (D3).
	if (has_dot || has_exp) && has_digit && !has_underscore {
		s := buf.bytestr()
		fv := strconv.atof64(s) or { return none }
		return ScalarNode{ data_type: .float_type, value: ScalarValue(fv) }
	}
	// underscore-containing tokens / hex / date / etc. — defer to the
	// string-surface implementation which handles those shapes.
	return try_autotype(buf.bytestr())
}

fn try_autotype(tok string) ?ScalarNode {
	// hex int: 0x...
	// Underscores between hex digits permitted (0xDEAD_BEEF). Strip
	// them before parsing.
	if tok.starts_with('0x') || tok.starts_with('0X') {
		hex_body := strip_underscores(tok[2..]) or { return none }
		if v := strconv.parse_int(hex_body, 16, 64) {
			return ScalarNode{ data_type: .int_type, value: ScalarValue(v) }
		}
	}
	if tok.starts_with('-0x') || tok.starts_with('-0X') {
		hex_body := strip_underscores(tok[3..]) or { return none }
		if v := strconv.parse_int(hex_body, 16, 64) {
			neg := -v
			return ScalarNode{ data_type: .int_type, value: ScalarValue(neg) }
		}
	}
	// bool and null — checked before float to avoid 'e' in "true"/"false" triggering float path
	if tok == 'true'  { return ScalarNode{ data_type: .bool_type, value: ScalarValue(true) } }
	if tok == 'false' { return ScalarNode{ data_type: .bool_type, value: ScalarValue(false) } }
	if tok == 'null'  { return ScalarNode{ data_type: .null_type, value: ScalarValue(NullValue{}) } }
	// atom — `:NAME` where NAME = ident. Checked before
	// the numeric / float / date paths so that names containing the
	// letter `e` (e.g. ':debug', ':event') don't fall into the float
	// branch. Reserved names `:true` / `:false` / `:null` are
	// rejected here to prevent shadowing existing scalar literals
	// they fall through to none and round-trip as
	// plain strings.
	if tok.len >= 2 && tok[0] == `:` && is_atom_pattern_name(tok[1..]) {
		name := tok[1..]
		if name == 'true' || name == 'false' || name == 'null' {
			return none
		}
		return ScalarNode{ data_type: .atom_type, value: ScalarValue(name) }
	}
	// int (decimal): apply v3.4 leading-zero rule + underscore stripping.
	// '02134' falls through to Text; '1_000_000' parses as 1000000.
	cleaned := strip_underscores(tok) or { return none }
	if is_v34_decimal_int(cleaned) {
		if v := parse_i64_checked(cleaned) {
			return ScalarNode{ data_type: .int_type, value: ScalarValue(v) }
		}
		// [L20]/D-H: a well-formed decimal integer that OVERFLOWS i64 auto-
		// promotes to bigint (stays numeric) rather than degrading to Text. A
		// redundant leading `+` is dropped for the canonical bigint value.
		bigint_str := if cleaned.starts_with('+') { cleaned[1..] } else { cleaned }
		return ScalarNode{ data_type: .bigint_type, value: ScalarValue(bigint_str) }
	}
	// float — must contain '.' or an exponent marker to distinguish from int,
	// AND must contain at least one digit so a digit-less token (bare `e`/`E`/
	// `.`, `e+`, …) is NOT a float. `strconv.atof64` leniently returns 0.0 for
	// such tokens (the `[name e]` → 0.0 bug); lexicon [L20b] Float requires an
	// Integer mantissa, so a digit-less token falls through to Text instead.
	if cleaned.contains('.') || cleaned.contains('e') || cleaned.contains('E') {
		if !has_ascii_digit(cleaned) {
			return none
		}
		fv := strconv.atof64(cleaned) or { return none }
		return ScalarNode{ data_type: .float_type, value: ScalarValue(fv) }
	}
	// datetime
	if is_datetime(tok) {
		return ScalarNode{ data_type: .datetime_type, value: ScalarValue(tok) }
	}
	// date
	if is_date(tok) {
		return ScalarNode{ data_type: .date_type, value: ScalarValue(tok) }
	}
	// duration / period (lexicon [L25]/[L26]): a whole-token integer+unit span.
	// `100ms`/`1h30m`/`2w` → duration; `3mo`/`1y` → period. The verbatim CX
	// text is the value; the type rides on data_type.
	if tk := temporal_span_kind(tok) {
		return ScalarNode{ data_type: tk, value: ScalarValue(tok) }
	}
	return none
}

// is_atom_name reports whether `s` is a valid atom-literal name per
// lexicon.ebnf [L40] `Atom ::= ':' Ident ('.' Ident)*` — ident segments
// (`[A-Za-z_][A-Za-z0-9_-]*`, spec/code.md §3.4 / grammar [122b]) joined by
// single interior dots (#397 owner ruling 2026-07-13: hierarchical topic /
// tag namespaces, `:order.placed`). No leading/trailing dot, no `..`, and
// every segment starts like an Ident.
pub fn is_atom_name(s string) bool {
	if s.len == 0 { return false }
	mut seg_start := true
	for i in 0 .. s.len {
		c := s[i]
		if seg_start {
			if !((c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`) || c == `_`) {
				return false
			}
			seg_start = false
			continue
		}
		if (c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`) ||
		   (c >= `0` && c <= `9`) || c == `_` || c == `-` {
			continue
		}
		if c == `.` {
			seg_start = true
			continue
		}
		return false
	}
	return !seg_start // a trailing '.' leaves an empty final segment
}

// is_atom_pattern_name admits everything is_atom_name does PLUS a single
// terminal `.*` glob segment (`:order.*`) — the bus.md §2.2 prefix-glob
// spelling ([L40] `('.' '*')?`, #397). The star is legal ONLY as the entire
// final segment; it has no meaning at the atom level (one opaque name) —
// pattern consumers (bus) assign the glob semantics.
pub fn is_atom_pattern_name(s string) bool {
	if s.ends_with('.*') {
		return s.len > 2 && is_atom_name(s[..s.len - 2])
	}
	return is_atom_name(s)
}

fn coerce_scalar(et string, tok string) ScalarNode {
	return match et {
		'int' {
			// v3.4: strip optional underscores. Explicit :int annotation
			// bypasses the leading-zero auto-typing rule — the user has
			// declared this is an integer.
			cleaned := strip_underscores(tok) or { tok }
			v := if cleaned.starts_with('0x') || cleaned.starts_with('0X') {
				strconv.parse_int(cleaned[2..], 16, 64) or { i64(0) }
			} else {
				cleaned.parse_int(10, 64) or { i64(0) }
			}
			ScalarNode{ data_type: .int_type, value: ScalarValue(v) }
		}
		'float' {
			cleaned := strip_underscores(tok) or { tok }
			v := strconv.atof64(cleaned) or { f64(0.0) }
			ScalarNode{ data_type: .float_type, value: ScalarValue(v) }
		}
		'bool' {
			ScalarNode{ data_type: .bool_type, value: ScalarValue(tok == 'true') }
		}
		'null' {
			ScalarNode{ data_type: .null_type, value: ScalarValue(NullValue{}) }
		}
		'date' {
			ScalarNode{ data_type: .date_type, value: ScalarValue(tok) }
		}
		'datetime' {
			ScalarNode{ data_type: .datetime_type, value: ScalarValue(tok) }
		}
		'bytes' {
			ScalarNode{ data_type: .bytes_type, value: ScalarValue(tok) }
		}
		// v3.4 sized integers — parsed as int, width validated at later
		// stages (data_bin emission, host-type marshalling). Underscores
		// stripped per v3.4.
		'i8', 'i16', 'i32', 'i64', 'u8', 'u16', 'u32', 'u64' {
			cleaned := strip_underscores(tok) or { tok }
			v := if cleaned.starts_with('0x') || cleaned.starts_with('0X') {
				strconv.parse_int(cleaned[2..], 16, 64) or { i64(0) }
			} else {
				cleaned.parse_int(10, 64) or { i64(0) }
			}
			ScalarNode{ data_type: .int_type, value: ScalarValue(v) }
		}
		// v3.4 sized floats — parsed as float; precision per host type
		// at marshalling time.
		'f16', 'f32', 'f64' {
			cleaned := strip_underscores(tok) or { tok }
			v := strconv.atof64(cleaned) or { f64(0.0) }
			ScalarNode{ data_type: .float_type, value: ScalarValue(v) }
		}
		// v3.4 arbitrary-precision decimal — stored as string, full
		// precision preserved. Host bindings convert to decimal types
		// per spec/misc/type-mapping.md §2.
		'decimal' {
			cleaned := strip_underscores(tok) or { tok }
			ScalarNode{ data_type: .decimal_type, value: ScalarValue(cleaned) }
		}
		// v3.4 arbitrary-precision integer — stored as string; auto-
		// promoted from int when the value exceeds i64 range.
		'bigint' {
			cleaned := strip_underscores(tok) or { tok }
			ScalarNode{ data_type: .bigint_type, value: ScalarValue(cleaned) }
		}
		// Temporal spans (lexicon [L25]/[L26]) — stored verbatim; the explicit
		// annotation forces the type even when the lexical form is ambiguous.
		'duration' {
			ScalarNode{ data_type: .duration_type, value: ScalarValue(tok) }
		}
		'period' {
			ScalarNode{ data_type: .period_type, value: ScalarValue(tok) }
		}
		// An explicit `::atom` ascription yields an ATOM-typed scalar
		// (lexicon §7 [L50]: the annotation OVERRIDES auto-typing), not a
		// string riding an atom-typed carrier — the pre-#466 else-arm
		// fallthrough left `[x::atom busy]` items string-typed while the
		// program reading typed them as atoms (issue #466 item 2). A
		// leading `:` spelling (`::atom=:busy`) collapses to the bare
		// name, so the canonical render `:busy` round-trips. Name
		// VALIDITY ([L40]) is enforced only on the checked (ascribed)
		// path — coerce_scalar stays infallible for the codec importers.
		'atom' {
			mut name := tok
			if name.starts_with(':') {
				name = name[1..]
			}
			ScalarNode{ data_type: .atom_type, value: ScalarValue(name) }
		}
		else {
			ScalarNode{ data_type: .string_type, value: ScalarValue(tok) }
		}
	}
}

// coerce_scalar_checked is the fallible twin of coerce_scalar for the EXPLICITLY
// type-ascribed body path (`[n::int abc]`, `[p::u8 999]`). Where coerce_scalar
// silently fell back to 0 on a malformed numeric, this raises:
//   - CXER0109 — the token cannot be coerced to the ascribed type (M-ERR-2).
//   - CXERLEX-RANGE — a sized integer value is outside the type's range
//     (@CHOICE-5b; LR-RANGE-1).
// For every type whose coercion cannot fail (string / bool / date / atom / …)
// it delegates verbatim to coerce_scalar, so accepted values stay byte-stable.
fn (p &Parser) coerce_scalar_checked(et string, tok string) !ScalarNode {
	match et {
		'int', 'i8', 'i16', 'i32', 'i64' {
			v := parse_int_strict(tok) or {
				return error(p.make_error('cannot coerce `${tok}` to ${et} (cx-err:CXER0109)'))
			}
			if !int_in_range(v, et) {
				return error(p.make_error('integer ${v} out of range for `${et}` (cx-err:CXERLEX-RANGE)'))
			}
			return ScalarNode{ data_type: .int_type, value: ScalarValue(v) }
		}
		'u8', 'u16', 'u32', 'u64' {
			v := parse_int_strict(tok) or {
				return error(p.make_error('cannot coerce `${tok}` to ${et} (cx-err:CXER0109)'))
			}
			if !int_in_range(v, et) {
				return error(p.make_error('integer ${v} out of range for `${et}` (cx-err:CXERLEX-RANGE)'))
			}
			return ScalarNode{ data_type: .int_type, value: ScalarValue(v) }
		}
		'float', 'f16', 'f32', 'f64' {
			fv := try_coerce_float_token(tok) or {
				return error(p.make_error('cannot coerce `${tok}` to ${et} (cx-err:CXER0109)'))
			}
			return ScalarNode{ data_type: .float_type, value: ScalarValue(fv) }
		}
		'atom' {
			// M-ERR-2 composition with [L40] (#466 item 2): an explicit
			// `::atom` demands a token that IS a denotable atom name —
			// ident-start segments joined by single dots, and never the
			// reserved :true/:false/:null. `[x::atom 0x2a]` fails loud
			// instead of minting an atom the atom grammar cannot spell
			// (its render `:0x2a` would not re-parse — a bijection break).
			name := try_coerce_atom_token(tok) or {
				return error(p.make_error('cannot coerce `${tok}` to atom — not a valid atom name (lexicon [L40]) (cx-err:CXER0109)'))
			}
			return ScalarNode{ data_type: .atom_type, value: ScalarValue(name) }
		}
		'decimal', 'bigint' {
			// OWNER RULING (#466 item 3): decimal / bigint are BASE-10
			// value types — a hex token under the ascription is a mistake
			// and REJECTS loudly (M-ERR-2), never stored verbatim.
			// try_coerce_base10_verbatim_token is the single home shared
			// with the program evaluator's ascription path.
			sn := try_coerce_base10_verbatim_token(et, tok) or {
				return error(p.make_error('cannot coerce hex literal `${tok}` to ${et} — ${et} is a base-10 value type (cx-err:CXER0109)'))
			}
			return sn
		}
		else {
			return coerce_scalar(et, tok)
		}
	}
}

// try_coerce_base10_verbatim_token coerces a token under an explicit
// `::decimal` / `::bigint` ascription, returning none for a hex (`0x…`)
// token — decimal and bigint are BASE-10 value types, so hex there is a
// mistake that must fail loud (OWNER RULING, #466 item 3; M-ERR-2),
// never be stored verbatim. Any other token delegates to the infallible
// verbatim-carrier coercion (underscores stripped, type-tagged). The
// single home shared by coerce_scalar_checked and the program
// evaluator's coerce_typed_scalar_text, so both readings agree.
pub fn try_coerce_base10_verbatim_token(et string, tok string) ?ScalarNode {
	if is_hex_int_token(tok) {
		return none
	}
	return coerce_scalar(et, tok)
}

// is_hex_int_token reports whether the token is a (possibly signed,
// possibly underscore-grouped) `0x`/`0X`-prefixed hex literal.
fn is_hex_int_token(tok string) bool {
	cleaned := strip_underscores(tok) or { tok }
	mut s := cleaned
	if s.starts_with('-') || s.starts_with('+') {
		s = s[1..]
	}
	return s.starts_with('0x') || s.starts_with('0X')
}

// try_coerce_atom_token validates a token under an explicit `::atom`
// ascription, returning the bare atom NAME (leading `:` spelling
// stripped) or none when the token is not a valid atom name per lexicon
// [L40] — ident-start dotted segments, excluding the reserved
// :true/:false/:null. The single home shared by coerce_scalar_checked and
// the program evaluator's ascription path, so both readings agree (#466).
pub fn try_coerce_atom_token(tok string) ?string {
	mut name := tok
	if name.starts_with(':') {
		name = name[1..]
	}
	if !is_atom_name(name) {
		return none
	}
	if name in ['true', 'false', 'null'] {
		return none
	}
	return name
}

// coerce_scalar_public exposes the infallible data-reading coercion for
// the verbatim string-carrier types (decimal / bigint / duration /
// period, …) to the program evaluator's ascription path — the single home
// for underscore-stripping and type-tagging, so `[x::decimal 1_000.50]`
// stores '1000.50' with a decimal-typed scalar in BOTH readings (#466
// items 3/4). Never used for the checked numeric arms (those go through
// try_coerce_int_token / try_coerce_float_token).
pub fn coerce_scalar_public(et string, tok string) ScalarNode {
	return coerce_scalar(et, tok)
}

// parse_i64_checked parses a sign-prefixed decimal integer string to i64,
// returning none on OVERFLOW. Both `string.parse_int` and `strconv.parse_int`
// silently CLAMP a near-boundary overflow (`9223372036854775808` → i64 max,
// no error) and only error on far overflow — unreliable for the D-H boundary
// (over-i64 → bigint / hard error). We verify the parse by re-stringifying the
// result and comparing to the normalized input; any mismatch means the value
// did not fit i64. Input is `[+-]?` then decimal digits — callers strip `_`
// and reject leading zeros, so the canonical i64 string is a faithful compare.
fn parse_i64_checked(signed_body string) ?i64 {
	v := signed_body.parse_int(10, 64) or { return none }
	// Normalize the input to its canonical decimal form (drop sign symbol +
	// leading zeros) so the round-trip compare detects only true clamps, not
	// cosmetic differences. Leading zeros are legal under an explicit `::int`
	// (`02134` → 2134); only a magnitude that doesn't fit i64 must fail.
	neg := signed_body.starts_with('-')
	mut mag := signed_body
	if mag.starts_with('+') || mag.starts_with('-') {
		mag = mag[1..]
	}
	mag = mag.trim_left('0')
	if mag == '' {
		mag = '0'
	}
	norm := if neg && mag != '0' { '-' + mag } else { mag }
	if v.str() != norm {
		return none
	}
	return v
}

// parse_int_strict parses a CX integer token (optional sign, decimal or `0x` hex,
// `_` group separators) to an i64, returning none on ANY non-numeric byte — so a
// bareword like `abc` fails rather than silently yielding 0. (coerce_scalar's
// `parse_int … or { 0 }` masked that; coerce_scalar_checked needs the failure.)
// Overflow also returns none (D-H: an over-i64 `::int` must HARD-ERROR).
fn parse_int_strict(tok string) ?i64 {
	cleaned := strip_underscores(tok) or { return none }
	mut s := cleaned
	mut neg := false
	if s.starts_with('-') {
		neg = true
		s = s[1..]
	} else if s.starts_with('+') {
		s = s[1..]
	}
	if s.len == 0 {
		return none
	}
	if s.starts_with('0x') || s.starts_with('0X') {
		hexs := s[2..]
		if hexs.len == 0 {
			return none
		}
		for c in hexs.bytes() {
			if hex_digit_val(c) < 0 {
				return none
			}
		}
		// strconv CLAMPS hex overflow; verify by re-formatting the parsed
		// magnitude as hex and comparing (D-H over-i64 → none → hard error).
		v := strconv.parse_int(hexs, 16, 64) or { return none }
		mut want := hexs.to_lower().trim_left('0')
		if want == '' {
			want = '0'
		}
		if v < 0 || v.hex() != want {
			return none
		}
		return if neg { -v } else { v }
	}
	// Decimal: validate digits strictly, then parse with the round-trip
	// overflow check on the SIGNED string (handles the asymmetric i64 range,
	// e.g. -9223372036854775808 is valid but +9223372036854775808 overflows).
	for c in s.bytes() {
		if c < `0` || c > `9` {
			return none
		}
	}
	return parse_i64_checked(cleaned)
}

// try_coerce_int_token parses a CX integer token to i64 under an explicit
// integer annotation `et` (`int`/`i64`/sized), returning none on a malformed
// token, on i64 OVERFLOW, or on a sized value out of range — so callers can
// HARD-ERROR (D-H: an over-i64 `::int` must fail, never silently wrap). Shared
// by the program evaluator's annotated-element path so the two readings agree.
pub fn try_coerce_int_token(tok string, et string) ?i64 {
	v := parse_int_strict(tok) or { return none }
	if !int_in_range(v, et) {
		return none
	}
	return v
}

// try_coerce_float_token parses a CX float token under an explicit `::float`
// (or sized-float) ascription, returning none when the token cannot coerce
// (M-ERR-2 / CXER0109). The SINGLE home of the ascribed-float guards —
// coerce_scalar_checked's float arm and the program evaluator's annotated-
// element coercion both delegate here, so a token like `0x2a` fails
// identically in both engines (atof64 leniently returns 0.0 for a digit-less
// token; a real float needs a digit mantissa, matching try_autotype's guard).
pub fn try_coerce_float_token(tok string) ?f64 {
	cleaned := strip_underscores(tok) or { return none }
	if !has_ascii_digit(cleaned) {
		return none
	}
	return strconv.atof64(cleaned) or { return none }
}

// int_in_range reports whether `v` fits the ascribed sized-integer type `et`
// (@CHOICE-5b). `int`/`i64` are unbounded here (the i64 carrier IS the bound);
// `u64`'s upper bound exceeds i64 so only non-negativity is enforced.
fn int_in_range(v i64, et string) bool {
	return match et {
		'i8' { v >= -128 && v <= 127 }
		'i16' { v >= -32768 && v <= 32767 }
		'i32' { v >= i64(-2147483648) && v <= i64(2147483647) }
		'u8' { v >= 0 && v <= 255 }
		'u16' { v >= 0 && v <= 65535 }
		'u32' { v >= 0 && v <= i64(4294967295) }
		'u64' { v >= 0 }
		else { true } // 'int', 'i64'
	}
}

// is_reserved_atom_token reports whether `tok` is a reserved atom literal —
// `:true` / `:false` / `:null` (lexicon §3.6). These shadow the bool/null
// scalar literals and are a lexical error (CXERLEX-ATOM), never a valid atom.
fn is_reserved_atom_token(tok string) bool {
	if tok.len < 2 || tok[0] != `:` {
		return false
	}
	name := tok[1..]
	return name == 'true' || name == 'false' || name == 'null'
}

// is_date / is_datetime now live in cx/lexical.v (shared cxparse temporal
// recognizers; both derive from the one temporal grammar cx.temporal_len).
// Same module, called unqualified.

// ── Low-level readers ─────────────────────────────────────────────────────────
// NOTE: is_all_digits / is_name_start / is_name_char now live in cx/lexical.v
// (the shared cxparse lexical primitives); same module, called unqualified.

// lex_name scans an `is_name_char` run and returns a `.name` token. This is the
// SINGLE home of the name-boundary scan in the data engine — `read_name` and
// `try_read_name` delegate here (Phase 2, cxparse unification). Data-mode names
// fold `.` and `:` (is_name_char), but a glued `::` type-label separator stops
// the run, so `port::u16` reads name `port` + type `u16`. The token carries the
// byte range `src[pos.offset..end]`; callers intern via `intern_name_src` (zero
// alloc on a pool hit). `is_name_char` ranges never cross a `\n`, so the start
// position is the whole token's line/col. Returns `none` on an empty run.
//
// Byte-stable: this is the exact loop `read_name` used before Phase 2 — moved
// into token-emitting form, behavior unchanged. Pinned by the name-char fork.
fn (mut p Parser) lex_name() ?Token {
	start := p.pos
	start_line := p.line
	start_col := p.col
	for !p.at_end() {
		b := p.peek()
		// a glued `::` is the type-label separator, NOT part of the name. Stop
		// before it so `port::u16` reads name `port` + type `u16`. A single `:`
		// (namespace `prefix:local`, [87]) is still a name char and is consumed.
		if b == `:` && p.pos + 1 < p.src.len && p.src[p.pos + 1] == `:` {
			break
		}
		if is_name_char(b) {
			p.advance()
		} else {
			break
		}
	}
	end := p.pos
	if end == start {
		return none
	}
	return Token{
		kind: .name
		pos:  TokenPos{
			offset: start
			line:   start_line
			col:    start_col
		}
		end:  end
	}
}

fn (mut p Parser) read_name() !string {
	// Zero-string-alloc on intern hit: lex_name finds the span, then
	// intern_name_src looks it up in `p.name_pool` without copying on a hit.
	// See `intern_name_src` for the pool contract and the `name_pool` docstring
	// on `Parser` for the design rationale.
	t := p.lex_name() or { return error(p.make_error('expected name')) }
	return p.intern_name_src(t.pos.offset, t.end)
}

fn (mut p Parser) try_read_name() ?string {
	t := p.lex_name()?
	return p.intern_name_src(t.pos.offset, t.end)
}

// read_token reads a whitespace-or-`]`-terminated token from the body
// stream. Quote and bracket awareness (Phase 7.74e):
//   - Inside `'...'` or `"..."` regions, embedded `]` and whitespace are
//     consumed without terminating — this is what lets
//     `:pat='[a-z]+'` parse as a single token even though the regex
//     class contains a `]`.
//   - Inside a balanced `[...]` region opened mid-token, embedded
//     whitespace is consumed and `]` only closes when depth returns to
//     zero — this is what lets `:enum=[v1 v2 v3]` parse as a single
//     token without the `,`-separator workaround.
//   - A token starting with `[` is handled by parse_bracket_node, not
//     read_token, so the bracket-depth path here only applies to
//     mid-token brackets like `:enum=[...]`.
// read_token_into is the zero-string-alloc twin of `read_token` —
// it writes the token's bytes directly into the caller-supplied
// `buf`. Same scan semantics (quote / bracket awareness; the
// regex-class / enum-bracket atomicity tests pass identically); the
// difference is purely allocation. Used by parse_body's text-
// accumulation branch on the gate-15 streaming bench hot path.
// lex_value_run scans a whitespace-or-`]`-terminated body token with quote- and
// bracket-awareness into a `.value_run` token. This is the SINGLE home of the
// value-run boundary scan — `read_token` and `read_token_into` delegate here
// (Phase 2, cxparse unification). The bytes live at `src[pos.offset..end]`;
// classifiers (`try_autotype_bytes`) read them in place (zero alloc). Semantics
// (byte-stable with the pre-Phase-2 read_token loop):
//   - mid-token `'`/`"` are literal bytes (bare prose like "it's broken");
//     a `'…'` at a body-item boundary is caught upstream in parse_body before
//     this point — reaching here means the quote sits inside a token. The
//     bracket-depth path still tracks quote nesting so predicate args like
//     `//x[name='foo']` keep their `'…'` regions atomic.
//   - a balanced `[...]` opened mid-token absorbs embedded ws and `]` until
//     depth returns to zero (e.g. `:enum=[v1 v2 v3]`).
//   - `[?` introduces a program form and ALWAYS breaks the run.
// The run may span `\n` (inside brackets/quotes); `advance` keeps line/col exact.
// Returns `none` on an empty run.
fn (mut p Parser) lex_value_run() ?Token {
	start := p.pos
	start_line := p.line
	start_col := p.col
	mut in_quote := u8(0)
	mut bracket_depth := 0
	for !p.at_end() {
		b := p.peek()
		if in_quote != 0 {
			p.advance()
			if b == in_quote { in_quote = 0 }
			continue
		}
		if bracket_depth > 0 {
			if b == `[` {
				bracket_depth++
			} else if b == `]` {
				bracket_depth--
				p.advance()
				if bracket_depth == 0 { break }
				continue
			} else if b == `'` || b == `"` {
				in_quote = b
			}
			p.advance()
			continue
		}
		if is_ws(b) || b == `]` { break }
		if b == `[` && p.pos + 1 < p.src.len && p.src[p.pos + 1] == `?` {
			break
		}
		if b == `[` {
			bracket_depth = 1
		}
		p.advance()
	}
	end := p.pos
	if end == start {
		return none
	}
	return Token{
		kind: .value_run
		pos:  TokenPos{
			offset: start
			line:   start_line
			col:    start_col
		}
		end:  end
	}
}

// read_token_into is the zero-string-alloc twin of `read_token` — it appends the
// token's bytes to the caller's `buf`. The bulk slice-append is equal-or-faster
// than the former byte-by-byte loop. Used on parse_body's text-accumulation hot
// path (gate-15 streaming bench).
fn (mut p Parser) read_token_into(mut buf []u8) ! {
	t := p.lex_value_run() or { return error(p.make_error('expected token')) }
	buf << p.src[t.pos.offset..t.end]
}

fn (mut p Parser) read_token() !string {
	t := p.lex_value_run() or { return error(p.make_error('expected token')) }
	return p.src[t.pos.offset..t.end].bytestr()
}

// split_ws_quote_bracket splits `s` on ASCII whitespace, treating
// `'..'` / `"..."` regions and balanced `[...]` regions as atomic so
// embedded whitespace doesn't terminate a token. Used by the
// schema-decl token analyzers to keep `:pat='a b c'` and
// `:enum=[v1 v2 v3]` as single tokens after parse_body has already
// produced a single TextNode for the body.
pub fn split_ws_quote_bracket(s string) []string {
	bytes := s.bytes()
	mut out := []string{}
	mut tok := []u8{}
	mut in_quote := u8(0)
	mut bracket_depth := 0
	for i := 0; i < bytes.len; i++ {
		b := bytes[i]
		if in_quote != 0 {
			tok << b
			if b == in_quote { in_quote = 0 }
			continue
		}
		if bracket_depth > 0 {
			if b == `[` {
				bracket_depth++
			} else if b == `]` {
				bracket_depth--
			} else if b == `'` || b == `"` {
				in_quote = b
			}
			tok << b
			continue
		}
		if b == ` ` || b == `\t` || b == `\r` || b == `\n` {
			if tok.len > 0 {
				out << tok.bytestr()
				tok = []u8{}
			}
			continue
		}
		if b == `'` || b == `"` {
			in_quote = b
		} else if b == `[` {
			bracket_depth = 1
		}
		tok << b
	}
	if tok.len > 0 {
		out << tok.bytestr()
	}
	return out
}

// read_quoted_escape_into decodes one EscapeSeq (grammar [11]) when the
// cursor sits on a backslash inside a single- or double-quoted string.
// Recognized escapes: \' \" \\ \n \r \t and \uXXXX / \UXXXXXXXX. An
// unrecognized sequence (e.g. the regex shorthands \w \d \s or \.) keeps
// the backslash verbatim and leaves the following byte for normal
// processing — this preserves `[pattern '\w+']` and matches the prior
// pass-through behaviour for those bytes. The decoded `\'` / `\"` are
// what let an escaped quote sit inside a quoted string without
// terminating it early (the in-quoted-string sub-state of schema.md §7.1).
fn (mut p Parser) read_quoted_escape_into(mut buf []u8) ! {
	// p.pos sits on the backslash. The escape rule + lenient pass-through live
	// in the one shared decoder cx.decode_escape (cx/lexical.v); here we only
	// emit into this parser's byte buffer and advance the cursor.
	d := decode_escape(p.src, p.pos)
	if d.invalid {
		// @CHOICE-4: a `\u`/`\U` escape that is not a Unicode scalar value
		// (surrogate / > 10FFFF) is a lexical error, not a lenient pass-through.
		return error(p.make_error('invalid Unicode escape \\u${d.cp:04X} — surrogate or above U+10FFFF (cx-err:CXERLEX-CODEPOINT)'))
	}
	if d.is_rune {
		buf << rune_to_utf8(d.cp).bytes()
	} else {
		buf << u8(d.cp)
	}
	for _ in 0 .. d.consumed {
		p.advance()
	}
}

fn (mut p Parser) read_quoted() !string {
	if p.at_end() { return error(p.make_error('expected quote')) }
	q := p.peek()
	if q != `'` && q != `"` {
		return error(p.make_error('expected quote'))
	}
	p.advance()
	p.quote_scratch.clear()
	for {
		if p.at_end() { return error(p.make_error('unterminated string')) }
		b := p.peek()
		if b == `\\` {
			p.read_quoted_escape_into(mut p.quote_scratch)!
			continue
		}
		p.advance()
		if b == q { break }
		p.quote_scratch << b
	}
	return p.quote_scratch.bytestr()
}

fn (mut p Parser) read_quoted_text() !string {
	p.expect(`'`)!
	p.quote_scratch.clear()
	// escaped_closer tracks whether a backslash escape consumed what would
	// otherwise have been the closing `'` (`…\']`) or dangled at EOF (`…\`).
	// If the scan then runs off the end unterminated, THAT backslash is the
	// lexical fault (CXERLEX-ESCAPE) — distinct from a plain unterminated
	// string (`'abc]`), which is NOT retagged. Per lexicon LR-ESCAPE.
	mut escaped_closer := false
	for {
		if p.at_end() {
			if escaped_closer {
				return error(p.make_error('unterminated quoted text — a backslash escape consumed the closing quote (cx-err:CXERLEX-ESCAPE)'))
			}
			return error(p.make_error('unterminated quoted text'))
		}
		b := p.peek()
		if b == `\\` {
			// A trailing `\` at EOF, or a `\'` escaping the would-be closer,
			// marks the escaped-closer case; any other escape clears it.
			nxt := p.pos + 1
			escaped_closer = nxt >= p.src.len || p.src[nxt] == `'`
			p.read_quoted_escape_into(mut p.quote_scratch)!
			continue
		}
		p.advance()
		if b == `'` { break }
		p.quote_scratch << b
	}
	return p.quote_scratch.bytestr()
}

fn (mut p Parser) read_attr_list_until(stop u8) ![]Attribute {
	mut attrs := []Attribute{}
	for {
		p.skip_ws()
		if p.at_end() || p.peek() == stop { break }
		name := p.read_name()!
		p.expect(`=`)!
		value := p.read_attr_value()!
		attrs << Attribute{ name: name, value: ScalarValue(value) }
	}
	return attrs
}

fn (mut p Parser) read_attr_value() !string {
	if p.at_end() { return error(p.make_error('expected attr value')) }
	b := p.peek()
	// Triquote `'''…'''` is permitted in attribute value position
	// (spec [55a] amendment lifting the [10b] ban). Detect by peeking the
	// third quote BEFORE the regular quoted path so `attr='''…'''` reads
	// as one triquote scalar instead of two empty squote strings + body.
	if b == `'` && p.pos + 2 < p.src.len && p.src[p.pos+1] == `'` && p.src[p.pos+2] == `'` {
		return p.read_triple_quoted_str()!
	}
	// Symmetric `"""…"""` triple-double-quote support.
	if b == `"` && p.pos + 2 < p.src.len && p.src[p.pos+1] == `"` && p.src[p.pos+2] == `"` {
		return p.read_triple_double_quoted_str()!
	}
	if b == `'` || b == `"` {
		return p.read_quoted()!
	}
	// Hash-raw `[# … #]` is permitted directly as an attribute
	// value (spec [55a] addition). Detect `[#` so `attr=[# raw #]`
	// produces the literal content without requiring a BracketBody wrap.
	if b == `[` && p.pos + 1 < p.src.len && p.src[p.pos+1] == `#` {
		return p.read_raw_text_str()!
	}
	// D2 (lexicon.ebnf §10; #391): an attribute value is ALWAYS a single
	// scalar. A `(`/`{`-opened value, or a `[`-opened one that is not a
	// scalar form handled above, is the REMOVED node-valued-attribute
	// feature — a hard parse error (cx-err:E211, the same data-layer code
	// as the main element-attr path's bare-`[…]` reject, GR-NODE-ATTR).
	// Before this the token scan silently MANGLED such values (half
	// string, half stray child), which fmt -w would then write back.
	if b == `(` || b == `{` || b == `[` {
		return error(p.make_error('node-valued attribute value — attributes are scalar-only (D2); a `${b.ascii_str()}`-opened value may not be an attribute value; put rich/list data in a child element (cx-err:E211)'))
	}
	return p.read_token_for_attr()!
}

fn (mut p Parser) read_attr_value_typed() !(ScalarValue, ?string) {
	if p.at_end() { return error(p.make_error('expected attr value')), none }
	b := p.peek()
	// RETIRED (D014): the legacy colon-typed attribute value
	// `name=:T=value` (e.g. `port=:u16=8080`). When the value position
	// opens with `:TypeName` immediately followed by `=`, it is the retired
	// colon-type prefix — a hard parse error. Typed attributes use the
	// glued name-side form `name::T=value` (grammar [26]/[55]). A leading
	// `:atom` value with NO trailing `=` (e.g. `x=:foo`) is a normal atom
	// scalar and is left untouched.
	if b == `:` && p.pos + 1 < p.src.len && is_name_start(p.src[p.pos + 1]) {
		mut scan := p.pos + 1
		for scan < p.src.len && is_name_char(p.src[scan]) {
			scan++
		}
		if scan < p.src.len && p.src[scan] == `=` {
			tname := p.src[p.pos + 1..scan].bytestr()
			return error(p.make_error("retired colon-typed attribute value `:${tname}=…` — use the glued name-side type form `name::${tname}=value` (grammar [26]/[55])")), none
		}
	}
	// Triquote in attribute position — peek for `'''` before
	// dispatching to the normal squote path.
	if b == `'` && p.pos + 2 < p.src.len && p.src[p.pos+1] == `'` && p.src[p.pos+2] == `'` {
		s := p.read_triple_quoted_str()!
		return ScalarValue(s), ?string(none)
	}
	// Symmetric `"""…"""` triple-double-quote in attribute position.
	if b == `"` && p.pos + 2 < p.src.len && p.src[p.pos+1] == `"` && p.src[p.pos+2] == `"` {
		s := p.read_triple_double_quoted_str()!
		return ScalarValue(s), ?string(none)
	}
	if b == `'` || b == `"` {
		s := p.read_quoted()!
		return ScalarValue(s), ?string(none)
	}
	// Hash-raw direct in attribute position.
	if b == `[` && p.pos + 1 < p.src.len && p.src[p.pos+1] == `#` {
		s := p.read_raw_text_str()!
		return ScalarValue(s), ?string(none)
	}
	// D2 (lexicon.ebnf §10; #391): scalar-only attribute values — see
	// read_attr_value for the full note. Same rejection on the typed path.
	if b == `(` || b == `{` || b == `[` {
		return error(p.make_error('node-valued attribute value — attributes are scalar-only (D2); a `${b.ascii_str()}`-opened value may not be an attribute value; put rich/list data in a child element (cx-err:E211)')), none
	}
	// Hot path (§11.6 gate-15): write the token bytes into the parser-
	// owned scratch buffer rather than allocating a fresh string.
	// `try_autotype_bytes` parses int / float / bool / null directly
	// from the bytes; only when the token is a string value do we
	// allocate (via `attr_scratch.bytestr()`). On the gate-15 corpus
	// ~67% of attribute tokens are numeric / bool — those skip the
	// string allocation entirely.
	p.attr_scratch.clear()
	p.read_token_for_attr_into(mut p.attr_scratch)!
	if scalar := try_autotype_bytes(p.attr_scratch) {
		return scalar.value, ?string(scalar_type_name(scalar.data_type))
	}
	s := p.attr_scratch.bytestr()
	return ScalarValue(s), ?string(none)
}

// read_raw_text_str consumes a `[# … #]` raw-text literal from the
// current position (which must be at the opening `[`) and returns the
// literal content string. Shared between attribute-value position
// (spec [55a] addition) and other contexts that need just the
// raw bytes (vs the RawTextNode produced by parse_raw_text).
fn (mut p Parser) read_raw_text_str() !string {
	p.advance() // consume '['
	t := p.lex_raw_span()!
	return p.src[t.pos.offset..t.end].bytestr()
}

// read_token_for_attr is read_token's attribute-value sibling. Differs
// only by absorbing `[?=…]` spans into the token instead of breaking
// on them — needed so `attr=[?=expr]` parses as an attribute whose
// string value carries the interpolation marker for emit-time
// substitution (J0 / attribute-value interpolation). The
// emitter scans attribute strings for `[?=…]` substrings and evaluates
// them at output time; the parser doesn't build an AST node for them.
// read_token_for_attr_into is the zero-string-alloc twin of
// `read_token_for_attr`, writing the token's bytes into the caller-
// supplied `buf`. Same scan semantics (quote / bracket awareness;
// `[?=…]` absorbed into the token); the difference is purely
// allocation. Used by `read_attr_value_typed` on the §11.6 gate-15
// attribute-value hot path.
fn (mut p Parser) read_token_for_attr_into(mut buf []u8) ! {
	start_len := buf.len
	mut in_quote := u8(0)
	mut bracket_depth := 0
	for !p.at_end() {
		b := p.peek()
		if in_quote != 0 {
			buf << b
			p.advance()
			if b == in_quote { in_quote = 0 }
			continue
		}
		if bracket_depth > 0 {
			if b == `[` {
				bracket_depth++
			} else if b == `]` {
				bracket_depth--
				buf << b
				p.advance()
				// J0: depth-0 means the interpolation closed. Don't
				// break — keep reading so `/u/[?=cid]/p/[?=name]`
				// captures both interpolations into one token.
				continue
			} else if b == `'` || b == `"` {
				in_quote = b
			}
			buf << b
			p.advance()
			continue
		}
		if is_ws(b) || b == `]` { break }
		if b == `'` || b == `"` {
			in_quote = b
		} else if b == `[` {
			bracket_depth = 1
		}
		buf << b
		p.advance()
	}
	if buf.len == start_len {
		return error(p.make_error('expected token'))
	}
}

fn (mut p Parser) read_token_for_attr() !string {
	mut s := []u8{cap: 16}
	mut in_quote := u8(0)
	mut bracket_depth := 0
	for !p.at_end() {
		b := p.peek()
		if in_quote != 0 {
			s << b
			p.advance()
			if b == in_quote { in_quote = 0 }
			continue
		}
		if bracket_depth > 0 {
			if b == `[` {
				bracket_depth++
			} else if b == `]` {
				bracket_depth--
				s << b
				p.advance()
				// J0: depth-0 means the interpolation closed. Don't
				// break — keep reading so `/u/[?=cid]/p/[?=name]`
				// captures both interpolations into one token.
				continue
			} else if b == `'` || b == `"` {
				in_quote = b
			}
			s << b
			p.advance()
			continue
		}
		if is_ws(b) || b == `]` { break }
		// J0: unlike read_token, do NOT break on `[?`. Absorb
		// the full balanced-bracket span so `value=[?=c/@name]` reads
		// as the token `[?=c/@name]`.
		if b == `'` || b == `"` {
			in_quote = b
		} else if b == `[` {
			bracket_depth = 1
		}
		s << b
		p.advance()
	}
	if s.len == 0 {
		return error(p.make_error('expected token'))
	}
	return s.bytestr()
}

fn (mut p Parser) read_until_close() !string {
	mut s := []u8{}
	mut depth := 0
	for {
		if p.at_end() { return error(p.make_error('unexpected EOF')) }
		b := p.peek()
		// v3.4 fix: `[#...#]` (raw text) and `[|...|]` (block content)
		// are atomic spans — their inner content is uninterpreted, and
		// their closing requires `#]` / `|]` (not a bare `]`). When
		// encountered inside a comment body, swallow them whole rather
		// than letting depth-counting misalign on the inner `]`. The
		// equivalent fix in non-comment-body parsing is in parse_raw_text
		// / parse_block_content; this is the comment-side mirror.
		if b == `[` && p.pos + 1 < p.src.len && p.src[p.pos + 1] == `#` {
			p.advance() // [
			p.advance() // #
			s << `[`
			s << `#`
			for {
				if p.at_end() { return error(p.make_error('unterminated [# inside comment')) }
				c := p.peek()
				p.advance()
				s << c
				if c == `#` && !p.at_end() && p.peek() == `]` {
					s << p.peek()
					p.advance()
					break
				}
			}
			continue
		}
		if b == `[` && p.pos + 1 < p.src.len && p.src[p.pos + 1] == `|` {
			p.advance() // [
			p.advance() // |
			s << `[`
			s << `|`
			for {
				if p.at_end() { return error(p.make_error('unterminated [| inside comment')) }
				c := p.peek()
				p.advance()
				s << c
				if c == `|` && !p.at_end() && p.peek() == `]` {
					s << p.peek()
					p.advance()
					break
				}
			}
			continue
		}
		if b == `[` {
			depth++
			s << b
			p.advance()
		} else if b == `]` && depth == 0 {
			break
		} else if b == `]` {
			depth--
			s << b
			p.advance()
		} else {
			s << b
			p.advance()
		}
	}
	return s.bytestr()
}

fn (mut p Parser) expect(expected u8) ! {
	if p.at_end() {
		return error(p.make_error("expected '${rune(expected)}' got EOF (cx-err:CXER0100)"))
	}
	b := p.peek()
	if b != expected {
		return error(p.make_error("expected '${rune(expected)}' got '${rune(b)}'"))
	}
	p.advance()
}

fn (mut p Parser) read_hex_digits() !string {
	mut s := []u8{}
	for !p.at_end() {
		b := p.peek()
		if (b >= `0` && b <= `9`) || (b >= `a` && b <= `f`) || (b >= `A` && b <= `F`) {
			s << b
			p.advance()
		} else {
			break
		}
	}
	if s.len == 0 { return error(p.make_error('expected hex digits')) }
	return s.bytestr()
}

fn (mut p Parser) read_dec_digits() !string {
	mut s := []u8{}
	for !p.at_end() {
		b := p.peek()
		if b >= `0` && b <= `9` {
			s << b
			p.advance()
		} else {
			break
		}
	}
	if s.len == 0 { return error(p.make_error('expected decimal digits')) }
	return s.bytestr()
}

// ── [| ... |] block content ───────────────────────────────────────────────────

fn (mut p Parser) parse_block_content() !Node {
	p.advance() // consume '|'
	mut items := []Node{}
	mut text_buf := []u8{}
	for {
		if p.at_end() { return error(p.make_error('unterminated block content')) }
		b := p.peek()
		if b == `|` && p.peek2() == `]` {
			p.advance() // '|'
			p.advance() // ']'
			break
		}
		if b == `[` {
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			child := p.parse_bracket_node()!
			items << child
		} else {
			text_buf << b
			p.advance()
		}
	}
	if text_buf.len > 0 {
		items << TextNode{ value: text_buf.bytestr() }
	}
	return BlockContentNode{ items: items }
}

// ── ''' / """ triple-quoted strings ────────────────────────────────────────────
//
// Both forms close at the LAST occurrence of the triple-delimiter within any
// maximal run of the delimiter character (lookahead-on-close, spec/canonical.md
// §triple-quoted strings). When the scanner sees a triple-delimiter, it peeks
// one byte further: if that byte is also the delimiter, the matched triple is
// treated as content (advance one byte, continue scanning) rather than as
// close. This makes content containing trailing delimiters expressible without
// escapes — `'''hello''''` parses as `hello'`, `"""hello""""` parses as
// `hello"`. Symmetric behaviour for both quote styles.

fn (mut p Parser) read_triple_quoted() !Node {
	value := p.read_triple_quoted_str()!
	return TextNode{ value: value }
}

// read_triple_quoted_str reads a triple-single-quoted literal and returns just
// the string value (post-dedent). Position must be at the first quote of the
// opening `'''`. Used by both `read_triple_quoted` (Node-producing) and the
// doc-top scalar-doc path / AttValue triquote path / TableCell +
// CollectionItem triquote paths.
fn (mut p Parser) read_triple_quoted_str() !string {
	return p.read_triple_quoted_str_with_quote(`'`)!
}

// read_triple_double_quoted reads a `"""…"""` literal and returns a TextNode.
fn (mut p Parser) read_triple_double_quoted() !Node {
	value := p.read_triple_double_quoted_str()!
	return TextNode{ value: value }
}

// read_triple_double_quoted_str reads a `"""…"""` literal and returns the
// post-dedent string value. Position must be at the first quote of the opening
// `"""`. Symmetric to read_triple_quoted_str.
fn (mut p Parser) read_triple_double_quoted_str() !string {
	return p.read_triple_quoted_str_with_quote(`"`)!
}

// read_triple_quoted_str_with_quote is the shared scanner for both `'''…'''`
// and `"""…"""`. The `q` parameter is the active delimiter byte (either `'`
// or `"`). Implements lookahead-on-close: when a triple-delimiter is seen,
// peek the next byte; if it is also `q`, treat the first delimiter as content
// and advance one byte, otherwise close.
fn (mut p Parser) read_triple_quoted_str_with_quote(q u8) !string {
	// p.pos is at the first opening quote. The scan + lookahead-on-close +
	// dedent live in the one shared cx.scan_triple_quoted (cx/lexical.v); here
	// we only replay the cursor (advancing per byte keeps line/col + error
	// positions byte-stable).
	value, n := scan_triple_quoted(p.src, p.pos, q) or {
		return error(p.make_error('unterminated triple-quoted string'))
	}
	for _ in 0 .. n {
		p.advance()
	}
	return value
}

// strip_common_indent applies the triple-quoted / block-content whitespace
// rule (ast.md §Text / §BlockContent, grammar [10b]): strip one leading and
// one trailing blank line, then remove the common leading whitespace of all
// non-blank lines. Public so the program lexer (code/lexer.v) delegates to
// this ONE implementation instead of carrying a second copy — the unified
// cxparse engine has a single triple-quote dedent rule (cxparse D4).
pub fn strip_common_indent(s string) string {
	lines := s.split('\n')
	// 1. Strip one leading newline
	start := if lines.len > 0 && lines[0].trim_space() == '' { 1 } else { 0 }
	// 2. Strip one trailing newline
	end := if lines.len > start && lines[lines.len-1].trim_space() == '' { lines.len - 1 } else { lines.len }
	content := lines[start..end]
	if content.len == 0 { return '' }
	// 3. Find common leading whitespace of non-blank lines
	mut min_indent := 999999
	for line in content {
		if line.trim_space().len > 0 {
			indent := line.len - line.trim_left(' \t').len
			if indent < min_indent { min_indent = indent }
		}
	}
	if min_indent == 999999 { min_indent = 0 }
	mut result := []string{}
	for line in content {
		if line.len >= min_indent {
			result << line[min_indent..]
		} else {
			result << line.trim_left(' \t')
		}
	}
	return result.join('\n')
}

// ── Collection literals (grammar v3.6) ────────────────────────────
//
// Source-text forms:
//   SequenceLiteral [56a]  ( item, item, … )    — parens, flat
//   ArrayLiteral    [56b]  [ item, item, … ]    — brackets, nested-preserving
//   MapLiteral      [56c]  { key: value, … }    — braces, atomic-keyed
//
// Disambiguation (grammar [50.D] for `[…]`; comma-marker / colon-marker
// for `(…)` / `{…}`):
//   - `[…]`: empty `[]` or any depth-0 `,` before `=`/`]` → ArrayLiteral;
//     `=` first → Element with attrs; `]` first with content → Element.
//   - `(…)`: empty `()` or depth-0 `,` before `)` → SequenceLiteral.
//     Without those markers, `(text)` parses as body text — no
//     incompatibility with v3.5-and-earlier parens-in-text.
//   - `{…}`: empty `{}` or depth-0 `:` before `}` → MapLiteral.
//     Without those markers, `{text}` parses as body text.
//
// Sequence-flatten (CXDM §1.2): the parser delivers SequenceNode items
// already flattened — nested `((a,b), c)` builds a 3-item SequenceNode
// `(a, b, c)`.

// peek_is_array_literal scans forward from the just-consumed `[` to
// decide between ArrayLiteral and Element. Does not consume input.
// Returns true for ArrayLiteral (including empty `[]`); false for
// Element. Tracks nested brackets / parens / braces and quoted regions
// so internal separators at non-zero depth don't confuse the scan.
// peek_is_array_literal disambiguates `[…]` between Element and
// Array literal.
//
// Rule (first-item-followed-by-comma):
//   1. Skip leading whitespace and quick-detect empty `[]` → array.
//   2. Inspect the first byte: if it's not a valid element-name
//      start (not letter / not `_`), it's an array literal. Covers
//      `[1, 2, 3]`, `['a', 'b']`, `[*, default]` (§D8 sentinel),
//      `[(seq, lit)]`, and any other shape that can't be an
//      element name.
//   3. Otherwise scan forward looking for the boundary character:
//        - `,` before any whitespace/`=`/`]` → array literal (the
//          first item is the bare-name-shaped token).
//        - `=` → element with attribute (today's attribute form).
//        - `]` → element with empty body, e.g. `[name]`.
//        - whitespace → element. The first whitespace inside the
//          bracket marks the boundary between the element name
//          and the body; commas appearing *after* the name are
//          body content, not separators. This is the load-bearing
//          change vs. the pre-amendment rule.
//        - a non-name char that's also non-ws / non-`,` / non-`=` /
//          non-`]` (e.g. `*` in `[FOAR*, math]` try-catch globs, or
//          `:` not at name-token position) → array literal. The
//          would-be element name isn't a clean Name shape, so the
//          bracket can't be an element-head and must be an array.
//
// Quote / bracket interiors don't appear in the first-item-prefix
// scan because the rule decides on the first non-name boundary
// character it sees — well before any nested content. This is
// strictly local: O(first-token-length) lookahead, no full-body
// scan.
fn (p &Parser) peek_is_array_literal() bool {
	mut i := p.pos
	for i < p.src.len && is_ws(p.src[i]) { i++ }
	if i >= p.src.len { return false }
	if p.src[i] == `]` { return true } // empty [] → empty array
	first := p.src[i]
	// Element-side sigils with dual roles: `*` (alias / md / sentinel),
	// `\`` `>` `~` `^` (Markdown shorthand elements). The §D8 array
	// sentinel form `[*, default]` and any literal-array shape using
	// these glyphs as item-0 values must still parse as array, so the
	// disambiguator peeks the next non-ws char: a comma marks the
	// array form, anything else (including end-of-input) stays with
	// the element-side dispatch in parse_bracket_node's match.
	if first == `*` || first == `\`` || first == `>` || first == `~` || first == `^` {
		mut k := i + 1
		for k < p.src.len && is_ws(p.src[k]) { k++ }
		return k < p.src.len && p.src[k] == `,`
	}
	// First char that can't lead an element name → must be array
	// literal (or a structural sigil already handled by parse_bracket_node).
	if !is_name_start(first) { return true }
	// First char IS name_start. Walk through the candidate name
	// looking for the boundary that decides element vs array.
	for i < p.src.len {
		b := p.src[i]
		// 3a (lexicon §collections [L83]): a Name head IMMEDIATELY followed
		// by a `,` is a BARE BAREWORD ARRAY — `[web, prod]` — which is
		// ambiguous with an element head and is a PARSE ERROR. Route it to
		// the element dispatch so parse_element raises CXER0100 (the bare
		// `return true` here used to silently accept it as a string array).
		if b == `,` { return false }
		if b == `=` { return false }
		if b == `]` { return false }
		if is_ws(b) { return false }
		// a glued `::` is the type-label separator on an
		// element head (`[port::u16 8080]`, `[tags::string[] …]`). It
		// marks an element, so stop the scan here. A single `:` stays a
		// name char (namespace `svg:rect`) and the scan continues.
		if b == `:` && i + 1 < p.src.len && p.src[i + 1] == `:` { return false }
		if !is_name_char(b) { return true }
		i++
	}
	return false
}

// peek_is_sequence_literal_at_paren scans forward from the current `(`
// to decide between SequenceLiteral and body text. Does not consume.
// Returns true if shape is `()` (empty) or contains a depth-0 `,`
// before the matching `)`.
fn (p &Parser) peek_is_sequence_literal_at_paren() bool {
	if p.peek() != `(` { return false }
	mut i := p.pos + 1
	for i < p.src.len && is_ws(p.src[i]) { i++ }
	if i < p.src.len && p.src[i] == `)` { return true }
	mut depth := 0
	mut quote := u8(0)
	for i < p.src.len {
		b := p.src[i]
		if quote != 0 {
			if b == `\\` && i + 1 < p.src.len { i += 2; continue }
			if b == quote { quote = 0 }
			i++
			continue
		}
		if b == `'` || b == `"` {
			quote = b
			i++
			continue
		}
		if depth == 0 {
			if b == `,` { return true }
			if b == `)` { return false }
		}
		if b == `[` || b == `(` || b == `{` { depth++; i++; continue }
		if b == `]` || b == `}` { if depth > 0 { depth-- }; i++; continue }
		if b == `)` { if depth > 0 { depth-- }; i++; continue }
		i++
	}
	return false
}

// peek_is_map_literal_at_brace scans forward from the current `{` to
// decide between MapLiteral and body text. Returns true if shape is
// `{}` (empty) or contains a depth-0 `:` before the matching `}`.
fn (p &Parser) peek_is_map_literal_at_brace() bool {
	if p.peek() != `{` { return false }
	mut i := p.pos + 1
	for i < p.src.len && is_ws(p.src[i]) { i++ }
	if i < p.src.len && p.src[i] == `}` { return true }
	mut depth := 0
	mut quote := u8(0)
	for i < p.src.len {
		b := p.src[i]
		if quote != 0 {
			if b == `\\` && i + 1 < p.src.len { i += 2; continue }
			if b == quote { quote = 0 }
			i++
			continue
		}
		if b == `'` || b == `"` {
			quote = b
			i++
			continue
		}
		if depth == 0 {
			if b == `:` { return true }
			if b == `}` { return false }
		}
		if b == `[` || b == `(` || b == `{` { depth++; i++; continue }
		if b == `]` || b == `)` { if depth > 0 { depth-- }; i++; continue }
		if b == `}` { if depth > 0 { depth-- }; i++; continue }
		i++
	}
	return false
}

// parse_array_literal parses an ArrayLiteral [56b]. The opening `[`
// has already been consumed by parse_bracket_node. Comma-separated
// items, trailing comma optional, closing `]` required.
fn (mut p Parser) parse_array_literal() !Node {
	p.skip_ws_and_line_comments()
	mut items := []Node{}
	if !p.at_end() && p.peek() == `]` {
		p.advance() // consume ']'
		return Node(ArrayNode{ items: items })
	}
	for {
		p.skip_ws_and_line_comments()
		if p.at_end() { return error(p.make_error('unterminated array literal')) }
		if p.peek() == `]` { break } // trailing comma case
		items << p.parse_collection_item()!
		p.skip_ws_and_line_comments()
		if p.at_end() { return error(p.make_error('unterminated array literal')) }
		b := p.peek()
		if b == `,` { p.advance(); continue }
		if b == `]` { break }
		return error(p.make_error('expected `,` or `]` in array literal'))
	}
	p.expect(`]`)!
	return Node(ArrayNode{ items: items })
}

// parse_sequence_literal parses a SequenceLiteral [56a]. The parser is
// positioned at `(`. Nested sequences flatten per CXDM §1.2.
fn (mut p Parser) parse_sequence_literal() !Node {
	p.advance() // consume '('
	p.skip_ws_and_line_comments()
	mut items := []Node{}
	if !p.at_end() && p.peek() == `)` {
		p.advance()
		return Node(SequenceNode{ items: items })
	}
	for {
		p.skip_ws_and_line_comments()
		if p.at_end() { return error(p.make_error('unterminated sequence literal')) }
		if p.peek() == `)` { break }
		item := p.parse_collection_item()!
		if item is SequenceNode {
			inner := item as SequenceNode
			for sub in inner.items { items << sub }
		} else {
			items << item
		}
		p.skip_ws_and_line_comments()
		if p.at_end() { return error(p.make_error('unterminated sequence literal')) }
		b := p.peek()
		if b == `,` { p.advance(); continue }
		if b == `)` { break }
		return error(p.make_error('expected `,` or `)` in sequence literal'))
	}
	p.expect(`)`)!
	return Node(SequenceNode{ items: items })
}

// parse_map_literal parses a MapLiteral [56c]. The parser is positioned
// at `{`. Duplicate keys (same type-tag + canonical-string form) are
// W014 / parse error.
fn (mut p Parser) parse_map_literal() !Node {
	p.advance() // consume '{'
	p.skip_ws_and_line_comments()
	mut entries := []MapEntry{}
	mut seen_keys := map[string]bool{}
	if !p.at_end() && p.peek() == `}` {
		p.advance()
		return Node(MapNode{ entries: entries })
	}
	for {
		p.skip_ws_and_line_comments()
		if p.at_end() { return error(p.make_error('unterminated map literal')) }
		if p.peek() == `}` { break }
		entry := p.parse_map_entry()!
		marker := '${scalar_type_name(entry.key_type)}:${scalar_value_str(entry.key_value)}'
		if marker in seen_keys {
			return error(p.make_error('W014: duplicate map key (cx-err:CXERMAP-DUPKEY)'))
		}
		seen_keys[marker] = true
		entries << entry
		p.skip_ws_and_line_comments()
		if p.at_end() { return error(p.make_error('unterminated map literal')) }
		b := p.peek()
		if b == `,` { p.advance(); continue }
		if b == `}` { break }
		return error(p.make_error('expected `,` or `}` in map literal'))
	}
	p.expect(`}`)!
	return Node(MapNode{ entries: entries })
}

// parse_map_entry parses one MapEntry [56f] — `MapKey : BodyItem`.
fn (mut p Parser) parse_map_entry() !MapEntry {
	p.skip_ws_and_line_comments()
	key_type, key_value := p.read_map_key()!
	p.skip_ws_and_line_comments()
	if p.at_end() || p.peek() != `:` {
		return error(p.make_error('expected `:` after map key'))
	}
	p.advance() // consume ':'
	p.skip_ws_and_line_comments()
	value := p.parse_collection_item()!
	return MapEntry{
		key_type:  key_type
		key_value: key_value
		value:     value
	}
}

// read_map_key consumes a MapKey [56g] — a Name, QuotedText, or atomic
// Scalar. Returns the resolved key type + value. Bare-name keys carry
// type-tag `string` (names sugar for string keys).
fn (mut p Parser) read_map_key() !(ScalarType, ScalarValue) {
	if p.at_end() { return error(p.make_error('expected map key')) }
	b := p.peek()
	if b == `'` || b == `"` {
		s := p.read_quoted_text()!
		return ScalarType.string_type, ScalarValue(s)
	}
	mut s := []u8{}
	for !p.at_end() {
		b2 := p.peek()
		if b2 == `:` || b2 == `,` || b2 == `}` || is_ws(b2) { break }
		s << b2
		p.advance()
	}
	if s.len == 0 {
		// A leading ':' in key position is an atom-key attempt (`{:k: 1}`);
		// atoms (like null) are not valid map keys per GR-BAD-KEY → CXERMAP-BADKEY.
		if !p.at_end() && p.peek() == `:` {
			return error(p.make_error('atom is not a valid map key (cx-err:CXERMAP-BADKEY)'))
		}
		return error(p.make_error('expected map key'))
	}
	tok := s.bytestr()
	if scalar := try_autotype(tok) {
		if scalar.data_type == .null_type {
			return error(p.make_error('W014: null is not a valid map key (cx-err:CXERMAP-BADKEY)'))
		}
		return scalar.data_type, scalar.value
	}
	return ScalarType.string_type, ScalarValue(tok)
}

// parse_collection_item parses one slot inside a (), [], or {}
// collection (slot-as-body resolution 1.d,
// 2026-05-12). A slot is a body fragment — a sequence of CX body
// items terminating at the next depth-0 `,` `]` `)` `}`. Single-item
// slots return the lone item directly (with bare-token autotyping
// applied); multi-item slots wrap their items in a SequenceNode (the
// "slot encoding" for mixed content — the program evaluator unwraps at
// use-site to render the body in order).
//
// Examples:
//   `1` (slot of `[1, 2, 3]`)                → ScalarNode(int 1)
//   `@stock > 0` (slot of `[@stock > 0, …]`) → TextNode("@stock > 0")
//                                              (program evaluator parses
//                                              as CXPath at eval time)
//   `In stock: [?=@stock]`                   → SequenceNode[
//                                                TextNode("In stock: "),
//                                                InterpolationNode("@stock")
//                                              ]
//   `[a, b]` (nested array)                  → ArrayNode[a, b]
//
// Empty slots (consecutive commas) are a parse error
// — trailing commas are permitted at the slot list level but empty
// slots between them are not values.
fn (mut p Parser) parse_collection_item() !Node {
	items := p.parse_collection_slot_body()!
	if items.len == 0 {
		return error(p.make_error('empty collection slot (cx-err:CXER0100)'))
	}
	if items.len == 1 {
		return items[0]
	}
	return Node(SequenceNode{ items: items })
}

// parse_collection_slot_body consumes the contents of one slot — a
// body-item run terminated by the next depth-0 `,` `)` `]` `}`. The
// loop mirrors parse_body's structure (text-buf coalescing of
// consecutive bare tokens with single-space separation, structured
// nodes pushed inline) but with the collection-slot terminator set.
// Bare-token-only single-token slots get try_autotype'd as a scalar;
// multi-token / mixed-content slots return their items unmodified.
fn (mut p Parser) parse_collection_slot_body() ![]Node {
	mut items := []Node{}
	mut text_buf := []u8{}
	mut has_child := false
	mut after_non_text := false
	for {
		if p.at_end() { break }
		had_ws := is_ws(p.peek())
		p.skip_ws_and_line_comments()
		if p.at_end() { break }
		b := p.peek()
		if b == `,` || b == `]` || b == `)` || b == `}` { break }

		if b == `[` {
			has_child = true
			if had_ws && text_buf.len > 0 { text_buf << ` ` }
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			child := p.parse_bracket_node()!
			items << child
			after_non_text = true
			continue
		}

		if b == `'` || b == `"` {
			if had_ws && text_buf.len > 0 { text_buf << ` ` }
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			if p.pos + 3 <= p.src.len && p.src[p.pos] == `'`
				&& p.src[p.pos+1] == `'` && p.src[p.pos+2] == `'` {
				n := p.read_triple_quoted()!
				items << n
			} else if p.pos + 3 <= p.src.len && p.src[p.pos] == `"`
				&& p.src[p.pos+1] == `"` && p.src[p.pos+2] == `"` {
				n := p.read_triple_double_quoted()!
				items << n
			} else if b == `"` {
				// Double-quoted in collection-item / slot-body
				// position (previously fell through to bare-token,
				// producing the literal `"…"` characters as the value).
				quoted := p.read_quoted()!
				items << TextNode{ value: quoted }
			} else {
				quoted := p.read_quoted_text()!
				items << TextNode{ value: quoted }
			}
			after_non_text = true
			continue
		}

		if b == `(` && p.peek_is_sequence_literal_at_paren() {
			if had_ws && text_buf.len > 0 { text_buf << ` ` }
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			items << p.parse_sequence_literal()!
			after_non_text = true
			continue
		}

		if b == `{` && p.peek_is_map_literal_at_brace() {
			if had_ws && text_buf.len > 0 { text_buf << ` ` }
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			items << p.parse_map_literal()!
			after_non_text = true
			continue
		}

		if b == `&` {
			if had_ws {
				if text_buf.len > 0 || after_non_text { text_buf << ` ` }
			}
			n := p.parse_amp_node()!
			match n {
				TextNode {
					text_buf << n.value.bytes()
					after_non_text = false
				}
				else {
					if text_buf.len > 0 {
						items << TextNode{ value: text_buf.bytestr() }
						text_buf = []u8{}
					}
					items << n
					after_non_text = true
				}
			}
			continue
		}

		tok := p.read_slot_token()!
		if text_buf.len > 0 {
			if had_ws { text_buf << ` ` }
		} else if after_non_text && had_ws {
			text_buf << ` `
		}
		text_buf << tok.bytes()
		after_non_text = false
	}

	if text_buf.len > 0 {
		text_val := text_buf.bytestr()
		// Single bare-token slot — autotype if the buffer is exactly
		// one scalar literal. Multi-token / mixed-content slots keep
		// the raw text run (the program evaluator parses it as CXPath at
		// eval time per spec/eval.md §7).
		if !has_child && items.len == 0 {
			if scalar := try_autotype(text_val) {
				items << scalar
				return items
			}
		}
		items << TextNode{ value: text_val }
	}

	return items
}

// read_slot_token reads one bare-text token inside a collection slot.
// Terminates at slot delimiters (`,` `]` `)` `}`), whitespace, and at
// the introducers handled by the outer slot loop (`[` `(` `{` `'` `"`
// `&`). Structured nodes (brackets, quotes, etc.) are dispatched by
// the outer loop rather than absorbed here, so this is a strictly
// bare-text-run reader.
fn (mut p Parser) read_slot_token() !string {
	mut s := []u8{}
	for !p.at_end() {
		b := p.peek()
		if is_ws(b) || b == `,` || b == `]` || b == `)` || b == `}` { break }
		if b == `[` || b == `'` || b == `"` || b == `&` { break }
		if b == `(` && p.peek_is_sequence_literal_at_paren() { break }
		if b == `{` && p.peek_is_map_literal_at_brace() { break }
		s << b
		p.advance()
	}
	if s.len == 0 {
		return error(p.make_error('expected token in collection slot'))
	}
	return s.bytestr()
}
