module cx

import strconv

// ── Parser struct ─────────────────────────────────────────────────────────────

// max_recursion_depth bounds nesting in parse_element to prevent
// stack-overflow DoS on adversarial input. Normative home:
// spec/03-approved/core/limits.md §2 (the old spec/policies.md
// citation was a ghost — corrected at the release-cut docs audit, #876).
const max_recursion_depth = 64

struct Parser {
mut:
	src   []u8
	pos   int
	line  int
	col   int
	depth int  // current element-nesting depth; tracked by parse_element
	// track_pos — record each element's source position on its
	// ElementMeta (#792). OFF by default: meta is lazily allocated, so
	// stamping every element would cost an ElementMeta allocation per
	// element on every parse in the system. Only parse_cx_positioned
	// turns it on, for the one consumer that needs it (schema-validation
	// diagnostics, which otherwise report 0:0).
	track_pos bool
	// declared_templates tracks `?def name …` declarations seen so far
	// during parsing. Used by parse_pi_or_decl to distinguish template-
	// call invocations `[?template-name args]` (parse as EvalDirective)
	// from foreign processing instructions like `[?php …]` (parse as
	// PI). Per code.md templates must be declared before use;
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
	// set when the FIRST top-level element is the `[schema of=…]`
	// header (spec/schema.md §2, I5 stream 1 — see
	// maybe_flag_schema_header), or when one of the RETIRED
	// `[?cx schema-*]` / `[?cx frag]` pragmas is parsed (kept only so
	// legacy text parses far enough to hit the S009 retirement
	// diagnostic at schema load). While set,
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
	b := src.bytes()
	// I1 W-10 (lexicon §0): a LEADING UTF-8 BOM (EF BB BF) is an encoding
	// artifact, not content — consume it so it neither survives into
	// canonical output nor moves the document's address. A BOM anywhere
	// else in bare content is CXER0100 (see read_token / read_token_into).
	start := if b.len >= 3 && b[0] == 0xef && b[1] == 0xbb && b[2] == 0xbf { 3 } else { 0 }
	return Parser{
		src:   b
		pos:   start
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
	// I1 L23: NAMES normalize to NFC here — two spellings of one name are
	// ONE name (and one address). ASCII names return unchanged on the
	// cx_nfc_name fast path, so the hot pool path is untouched. (An NFD
	// source spelling misses the raw-byte pool compare and re-normalizes —
	// correct, merely a duplicate pool entry.)
	mut buf := []u8{cap: n}
	for i in 0 .. n {
		buf << p.src[start + i]
	}
	out := cx_nfc_name(buf.bytestr())
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
	if p.at_raw_triple() {
		return p.read_raw_triple_str()!
	}
	// The opener test is `triple_quote_prefix_len`'s (cx/lexical.v) — the single
	// home for "does a triple-quoted literal start here". The raw form was taken
	// by `at_raw_triple` above (also a delegation), so a hit here is prefix 0 and
	// the delimiter byte sits at `p.pos`; it alone picks the reader (#1021).
	if triple_quote_prefix_len(p.src, p.pos) == 0 {
		if p.src[p.pos] == `'` {
			return p.read_triple_quoted_str()!
		}
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
// `[?=…]` / `[?Name …]` forms at the top level (code.md).
fn (mut p Parser) read_top_text_run() (string, u8) {
	start := p.pos
	// The SCAN moved onto the `cx/lexical.v` shelf at #1040 and this method
	// delegates provably: the retired loop's only use of the cursor was `p.pos`
	// as the run's START (the scan origin and the line-start test's left edge),
	// which is exactly the index passed here. What stays is the position
	// bookkeeping below — the `advance()` loop that keeps line/col, and the
	// trailing-newline strip. It moved because a `&Parser` method reading its
	// own `pos` is a question the cursor-free `code_tree.v` walker could not
	// ask, so `the quick brown` at top level was THREE scalar children there
	// and ONE Text item here.
	end, terminator := top_text_run_end(p.src, start)
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

// ParseLimits — the embedding-side guard set (spec/03-approved/core/limits.md
// §2; ruling LIM-2). One member today: max_input_bytes bounds the top-level
// source so an embedder gets a typed refusal instead of an OOM mid-parse
// (parse cost is linear in input, so this is the only caller-facing bound
// with any teeth — every non-caller-controlled cost is structurally capped).
// 0 = unbounded (the default: the caller already holds the buffer).
pub struct ParseLimits {
pub:
	max_input_bytes int
}

// parse_limited — parse under an embedding-supplied guard set. Never an
// environment variable; a limits surface that varies with ambient process
// state is itself an attack surface (limits.md §1).
pub fn parse_limited(src string, limits ParseLimits) !Document {
	if limits.max_input_bytes > 0 && src.len > limits.max_input_bytes {
		return error('input exceeds max_input_bytes: ${src.len} > ${limits.max_input_bytes} (spec/03-approved/core/limits.md §2)')
	}
	return parse(src)
}

pub fn parse(src string) !Document {
	// I1 L23: UTF-8 validity is enforced up front — no invalid byte can
	// reach a name, a value, or the canonical byte stream.
	if off := validate_utf8(src.bytes()) {
		return error('invalid UTF-8 at byte offset ${off} — CX text is UTF-8 (cx-err:CXER0100)')
	}
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
	// I1 L23: same up-front UTF-8 validity as parse().
	if off := validate_utf8(src.bytes()) {
		return error('invalid UTF-8 at byte offset ${off} — CX text is UTF-8 (cx-err:CXER0100)')
	}
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

// parse_cx_positioned is parse_cx with element source positions recorded
// on ElementMeta (#792) — readable via `Element.pos()`. Same grammar,
// same tree, same canonical bytes and same Tier-1 identity: positions are
// presentation, exactly like the anchor/comment trivia, and the canonical
// emitters name the meta fields they read, so this one is inert to them.
//
// It is a SEPARATE door rather than a default because meta is lazily
// allocated: stamping every element would add an ElementMeta allocation
// per element to every parse in the system. Callers that report source
// locations to a human (schema validation) opt in; nothing else pays.
//
// Multi-document input takes the same stream path parse_cx does, which
// does not carry the flag — positions are single-document today, which
// is all `cx validate` accepts (it refuses multi-doc input outright).
pub fn parse_cx_positioned(src string) !ParseResult {
	mut p := new_parser(src)
	p.track_pos = true
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
					p.maybe_flag_schema_header(n, elements)
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
		validate_reserved_ns_bindings(doc)!
		resolve_ids(doc)!
		return doc
	}

	// doc-top: a document with no prolog/element content yet may
	// begin with bare text (`hello world`, `1\n2\n3`), a quoted scalar
	// (`'hi'`, `"hi"`, `'''hi'''`), `[`/`&` node-start bytes, or EOF.
	// Quoted-scalar openers produce a single-node scalar document.
	// Non-bracket prose engages "mixed-text mode" — top-level Text runs
	// may interleave with bracketed nodes per code.md.
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
		} else if b == `(` && p.peek_is_sequence_literal_at_paren() {
			// #906 — a top-level `(…)` sequence literal is a Sequence node,
			// not document text. Exactly the shape the `{…}` branch above
			// already gives map literals, and guarded the same way, so a
			// parenthesised run that is NOT a sequence literal still falls
			// through to the bare-text path unchanged (a comma-less `(x)`
			// stays text by the rule ASP-1 recorded).
			//
			// Without this the same bytes meant three different things:
			// `(1, 2, 3)` nested in an element body read as a sequence, the
			// PROGRAM reader evaluated it as a sequence, and the DATA reader
			// at top level returned the STRING "(1, 2, 3)" — silently, and
			// stably enough to survive canonicalization and take a content
			// address. Found via the playground rendering the string's raw
			// tokens as eleven scalars.
			elements << p.parse_sequence_literal()!
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
				p.maybe_flag_schema_header(n, elements)
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
		p.maybe_flag_schema_header(n, elements)
		// A `[?=…]` interpolation or `[?Name …]` eval-directive at top
		// level signals a CX program; switch to mixed mode so any
		// following prose attaches as Text rather than erroring.
		if n is InterpolationNode || n is EvalDirectiveNode {
			allow_top_text = true
		}
	}

	mut doc := Document{ prolog: prolog, doctype: doctype, elements: elements }
	resolve_namespaces(mut doc)
	validate_reserved_ns_bindings(doc)!
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
	if p.at_raw_triple() {
		s := p.read_raw_triple_str()!
		return TableCellValue(s)
	}
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
	//
	// #976: `!` opens a declaration EXCEPT when it is the delimited operator
	// head `!=`. Without the exemption `[!= 5 3]` reached `parse_decl`, which
	// consumed the `!`, read `=` as the declaration keyword and raised
	// "expected name" — the reason `!=` was the one head that failed loudly at
	// this dispatch rather than in `parse_element`. The head is two bytes and
	// must be DELIMITED, so real declarations (`[!ENTITY …]`, `[!ELEMENT …]`,
	// `[![CDATA[…`) are untouched: their `!` is glued to a name or a `[`.
	op_head_len := operator_head_len(p.src, p.pos)
	// The `b != `?` && !is_opaque_sigil` conjunction that used to guard both
	// array-adjacent routes below is now `bracket_head_is_reserved`
	// (cx/lexical.v) — one spelling, reachable from the cursor-free `code_tree.v`
	// walker, which needs the SAME guard before it may read a `[` as an array
	// (#1020). It also folds in the `[table[` opener the fail-closed check above
	// has already refused, so the predicate is the whole dispatch answer.
	// Headless WS array (@CHOICE-1, G-ARRAY-1): a no-comma bracket of 2+ typed
	// scalar tokens — `[80 443]` — is an Array node of discrete typed items (the
	// node-kind twin of the element whitespace typed list, slice A). Checked before
	// the comma-array path; a top-level comma makes body_is_typed_list false, so
	// `[1, 2]` still routes through parse_array_literal. Element heads (`[a …]`)
	// never reach here — `a` is a name-start, dispatched below.
	if !bracket_head_is_reserved(p.src, p.pos) && p.body_is_typed_list(true) {
		items := p.parse_self_delim_body()!
		p.expect(`]`)!
		return Node(ArrayNode{ items: items })
	}
	if p.peek_is_array_literal() {
		return p.parse_array_literal()!
	}
	return match b {
		`?` { p.parse_pi_or_decl()! }
		`;` { p.parse_comment()! }
		`#` { p.parse_raw_text()! }
		`!` {
			// #976: the delimited `!=` head, split from the declaration
			// lane by the `is_opaque_sigil` exemption above.
			if op_head_len > 0 { p.parse_element()! } else { p.parse_decl()! }
		}
		`*` {
			// I1 row 8 (L80): a DELIMITED `*` (followed by ws or `]`) is
			// the operator-head element `*`; a glued `*name` stays the
			// alias reference it has always been. #976: the delimiter test
			// is `operator_head_len`'s, not a fourth inline copy of it.
			if op_head_len > 0 { p.parse_element()! } else { p.parse_alias()! }
		}
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
// Control-flow directives (CX code 1.0, code.md): `if`, `for`,
// `include`, `def`.
// Built-in filter directives (CX code 1.0, code.md): the frozen
// filter set is reserved as EvalNames because filter invocations use
// the `?`-prefixed bracket form (`[?upper x]`, `[?trim x]`).
// CX code 3.1 control-flow: `let`, `fn`, `match`.
fn is_cx_eval_name(name string) bool {
	return match name {
		// CX code 1.0 control-flow.
		// `for-tumbling` / `for-sliding` (the A13/A14 FLWOR window heads)
		// were RESERVED here with no evaluator dispatch — stream 13 deleted
		// the implementation and L98 (planar_algebra.md, RULED 2026-08-05)
		// retires the reservation: windows are out of v1, and the future
		// form is CLAUSES under `[?for]` (`[tumbling …]`), never new heads
		// (single-surface rule). Removing them costs no loudness: an
		// unreserved `[?name …]` head raises the same "unknown directive —
		// not in §4.1 registry" CXER0100 the reserved-but-undispatched head
		// already raised (pinned, stream-2 W2).
		//
		// `with` / `cond` / `use` RETIRE here for the same reason and by the
		// same rule (RULED 760-1a). Each parsed as an EvalDirective and was
		// then refused by the §4.1 registry, so the reservation bought
		// nothing but a promise the language does not keep: a name the
		// grammar reserves and the evaluator cannot dispatch. (`try` retires
		// with them, from the CX code 3.1 group below — it is additionally a
		// deliberately-retired surface, guarded by `make
		// check-no-legacy-try`.) `include` and `def` STAY: both dispatch.
		'if', 'for',
		'include', 'def',
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
		// `sort-by` RETIRED here (RULED: VC-2, #940) by the same rule that
		// retired `with`/`cond`/`use`/`try` above: it was reserved with no
		// evaluator dispatch, so `[?sort-by …]` raised the same CXER0100
		// "unknown directive — not in §4.1 registry" an unreserved head
		// raises (measured: byte-identical to `[?nosuchname …]`), while
		// `[$sort-by …]` answered `no callable "sort-by"`. Three sessions
		// lost debugging time to the absence the reservation advertised.
		// Zero spec footprint, so nothing is owed a callable.
		'normalize-unicode',
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
		// RULED VC-6 (#940): the ten registrations below that had no callable
		// behind them are IMPLEMENTED, not retired — the spec is the only
		// truth and modules/cx.md already specified all ten. This block
		// therefore no longer carries a pending note: every name on it
		// dispatches (stdlib_cx.v's table, plus dynamic_construction.v for
		// cx:eval / cx:render, which share the cx:eval-tree sandbox).
		'cx:eval', 'cx:render', 'cx:schema-of', 'cx:validate',
		'cx:anchors', 'cx:ids', 'cx:references', 'cx:resolve-includes',
		'cx:merge', 'cx:strip-comments', 'cx:strip-attrs', 'cx:pretty-print',
		// log: structured-logging module (FF1–FF7)
		'log:trace', 'log:debug', 'log:info', 'log:warn', 'log:error',
		'log:level', 'log:with-context',
		// inspect: module-discovery (DD13/EE7)
		'inspect:module-available', 'inspect:module-version', 'inspect:functions',
		// CX code 3.1 control-flow (`try` RETIRED — RULED 760-1a; see the
		// control-flow group at the top of this match)
		'let', 'fn', 'match' { true }
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

// maybe_flag_schema_header flags the document as a schema when its FIRST
// top-level element is the `[schema …]` header carrying an `of` attribute
// (spec/schema.md §1/§2, I5 stream 1 — the header element replaced the
// retired `[?cx schema-*]` pragmas as the schema marker). Setting
// Parser.in_schema suspends `:T` type-tag validation for the schema
// sublanguage in every LATER top-level declaration; the header itself
// carries no `:T` slots, so post-append flagging is in time.
fn (mut p Parser) maybe_flag_schema_header(n Node, elements []Node) {
	if p.in_schema { return }
	if n !is Element { return }
	// Only the FIRST top-level element can be the header; bail as soon
	// as a second element exists (O(1) after that point).
	mut count := 0
	for e in elements {
		if e is Element {
			count++
			if count > 1 { return }
		}
	}
	if count != 1 { return }
	el := n as Element
	if el.name != 'schema' { return }
	for a in el.attrs {
		if a.name == 'of' {
			p.in_schema = true
			return
		}
	}
}

// cx_pragma_registry — the CLOSED [?cx] key set (grammar [34]; ruling
// CXP-1, 2026-08-20 — the historical "open by design" clause is retired:
// an unknown pragma key was the silent-acceptance class the language
// refuses everywhere else, demonstrated by [?cx output-target=html]
// passing inert while documentation taught it as escaping).
//   include      — parse-time file inclusion (core/code.md §13)
//   schema       — attach a .cxs schema (core/schema.md §13)
//   version      — declared CX language version (reader-facing metadata)
//   lint-disable / lint-enable — lint scoping (cx lint)
// The retired schema pragmas (schema-of/schema-name/schema-mode/frag)
// stay PARSE-TOLERATED so a legacy schema text reaches the targeted
// S009 diagnostic at schema load instead of dying here.
const cx_pragma_registry = ['include', 'schema', 'version', 'lint-disable', 'lint-enable']
const cx_pragma_legacy = ['schema-of', 'schema-name', 'schema-mode', 'frag']

fn (mut p Parser) parse_cx_directive() !Node {
	attrs := p.read_directive_attr_list_until(`]`)!
	// RETIRED schema pragmas (I5 stream 1): `[?cx schema-*]`/`[?cx frag]`
	// are rejected at schema load (S009 — schema metadata is body data,
	// spec/schema.md §2). They still SET the in_schema flag here so a
	// legacy schema text parses far enough to reach that targeted
	// diagnostic instead of dying on a `:T` sublanguage tag (CXER0107).
	// The live detection is the `[schema of=…]` header element — see
	// maybe_flag_schema_header.
	if attrs.len == 0 {
		return error('${p.line}:${p.col}: [?cx] carries no pragma key — the closed registry is include | schema | version | lint-disable | lint-enable (grammar [34], CXP-1)')
	}
	verb := attrs[0].name
	if verb == 'output-target' {
		return error('${p.line}:${p.col}: [?cx output-target] is reserved and NOT implemented — output is not escaped by it; remove the pragma until context-aware output escaping ships (CXP-1)')
	}
	if verb !in cx_pragma_registry && verb !in cx_pragma_legacy {
		return error('${p.line}:${p.col}: unknown [?cx] pragma key `${verb}` — the closed registry is include | schema | version | lint-disable | lint-enable (grammar [34], CXP-1)')
	}
	if verb in cx_pragma_legacy {
		p.in_schema = true
	}
	// Optional `&anchor` after the attr list, then optional
	// child nodes (parsed identically to element content). Added for
	// the retired `[?cx frag &name [body :TYPE :flags]]` form (legacy
	// texts still parse; schema load rejects them, spec/schema.md §8).
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
// entries with an empty value, so verb-style directives (e.g. the
// retired `[?cx schema-of server]`) parse uniformly with
// `[?cx schema=path]` and `[?cx lint-disable=L001]`. Directive
// consumers read the first positional attr as the directive name and
// subsequent positional attrs as args.
fn (mut p Parser) read_directive_attr_list_until(stop u8) ![]Attribute {
	mut attrs := []Attribute{}
	for {
		p.skip_ws()
		if p.at_end() || p.peek() == stop { break }
		// Stop on `&` (anchor) or `[` (nested directive body)
		// so the caller can parse them as a separate phase. Used by
		// `[?cx frag &name [body ...]]`.
		if p.peek() == `&` || p.peek() == `[` { break }
		// A quoted positional argument (e.g. `[?cx lint-disable 'why']`).
		// Stored with an empty name and the text in `value`; directive
		// consumers read it positionally, and the emitter re-quotes it.
		// Without this branch read_name fail-fasts on the leading quote
		// ("expected name") and the whole directive parse aborts.
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
	// stack overflow on deeply nested input (spec/03-approved/core/limits.md §2).
	p.depth++
	if p.depth > max_recursion_depth {
		return error('${p.line}:${p.col}: element nesting exceeds limit (${max_recursion_depth})')
	}
	defer { p.depth-- }
	// #792: the element's reported position is its NAME token — the
	// first thing a reader looks for when a diagnostic names an element.
	// Captured before the name is consumed; `none` unless tracking is on,
	// which keeps ElementMeta unallocated on the ordinary path.
	elem_pos := if p.track_pos {
		?Position(Position{ offset: p.pos, line: p.line, col: p.col })
	} else {
		?Position(none)
	}
	// I1 row 8 (L80, audit C4) + #976: a DELIMITED operator head IS the element
	// name. The alphabet is `operator_head_len`'s (lexical.v) — the evaluator's
	// ruled glyph heads, one-char AND two-char. This site used to spell its own
	// seven-char subset inline, which is how `>=`/`!=`/`~` came to raise
	// "expected name" here while `<=`/`%` stringified through the array lane;
	// see the #976 note on `operator_head_len` for why the quiet half of that
	// split was a content-addressing defect, not a papercut.
	op_len := operator_head_len(p.src, p.pos)
	raw_name := if op_len > 0 {
		op := p.src[p.pos..p.pos + op_len].bytestr()
		// Advance BYTE BY BYTE — `advance` is what keeps line/col exact, and
		// diagnostics on two-char heads would point one column short otherwise.
		for _ in 0 .. op_len {
			p.advance()
		}
		op
	} else {
		p.read_name()!
	}
	// QName / reserved-prefix lexical rules (lexicon §2). A data-mode name folds
	// single `:` (`prefix:local`); but a QName admits AT MOST ONE colon — `a:b:c`
	// is malformed (CXERLEX-QNAME). And the `cx:` prefix is reserved entirely for
	// the serializer's canonical image — it is never authored (cx-err:E210, a
	// data-layer code per cxdm.md §11; NOT the program CXER0241 = AWAIT_TIMEOUT).
	colon_count := raw_name.count(':')
	if colon_count > 1 {
		return error(p.make_error("malformed QName `${raw_name}` — a QName admits at most one `:` (cx-err:CXERLEX-QNAME)"))
	}
	if msg := reserved_prefix_refusal(raw_name) {
		return error(p.make_error(msg))
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
			// Stamp WHERE in the meta run it sat (#829 remainder) — the
			// attribute count at this point. Kept only if an attribute
			// actually follows; see the prune below.
			mut hc := p.parse_comment()!
			if mut hc is CommentNode {
				hc.meta_attr_index = ?int(attrs.len)
			}
			head_comments << hc
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
				head_comments << CommentNode{
					value:           lval
					is_line:         true
					meta_attr_index: ?int(attrs.len) // #829 remainder — see the block form above
				}
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
			// RULED: TA-1 (#911) — lexicon [L50]: a TypeAnnotation binds
			// GLUED to the token on its left. The spaced form `[port ::u16]`
			// was never a decision: skip_ws at the top of this meta loop ran
			// before the `::` check, so the DATA reader silently accepted and
			// normalized a spelling the PROGRAM reader refuses outright — two
			// readers disagreeing about a form the spec does not define (the
			// #793 silent-acceptance class, and the reader asymmetry behind
			// #910's headline error). The glued form is already the canonical
			// emit; refuse loudly, naming the one-character fix.
			if save_colon_pos > 0 && is_ws(p.src[save_colon_pos - 1]) {
				return error(p.make_error('type annotation must be glued to its name — write `${name}::${ta}`, not `${name} ::${ta}` (lexicon [L50]) (cx-err:CXER0100)'))
			}
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
					// CXER0290 and an out-of-range sized integer is
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

	// #829 remainder: drop the meta-zone stamp from any comment that no
	// attribute followed. Such a comment already re-emits correctly as a
	// leading body item — and in the multiline lane that IS its own line,
	// which round-trips today. Only a comment an attribute follows was being
	// hoisted past it, and only that one needs lifting back into the meta run.
	//
	// This sits directly after the ElementMeta loop, NOT next to the
	// items.prepend below, because the `[table[…]]` clause returns its
	// element from inside this function well before that point and would
	// otherwise carry unpruned stamps (core.cxd 048).
	for i in 0 .. head_comments.len {
		hn := head_comments[i]
		if hn is CommentNode {
			mut c := hn
			if idx := c.meta_attr_index {
				if idx >= attrs.len {
					c.meta_attr_index = none
					head_comments[i] = c
				}
			}
		}
	}

	// I1 identity epoch (stream 12, W-19/L24): duplicate attribute names on
	// one element are a PARSE ERROR (cx-err:E214) — silently-accepted
	// duplicates gave one document two meanings (last-wins vs first-wins is
	// implementation lore), and duplicate xmlns declarations created an
	// UNSTABLE canonical sort tie (nondeterministic canonical bytes, the
	// direct identity hazard). xmlns decls are attributes, so one check
	// covers both.
	if attrs.len > 1 {
		mut seen_names := map[string]bool{}
		for a in attrs {
			if a.name == '' {
				continue // positional quoted values carry no name
			}
			if a.name in seen_names {
				return error(p.make_error('duplicate attribute `${a.name}` on element `${name}` — one element declares each attribute (and each xmlns) at most once (cx-err:E214)'))
			}
			seen_names[a.name] = true
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
			pos:       elem_pos
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
	} else if !is_annotated && p.body_is_typed_list(false) {
		// §9 [L25a/b] TYPED LIST: a no-comma body of 2+ tokens whose every bare
		// scalar token auto-types (number / atom / bool / date) or is quoted,
		// with child elements interleaving as mixed content. Each token is typed
		// in place → N discrete typed children with NO element array type. This
		// is the @CHOICE-1 "one layer" replacement for the old whitespace
		// auto-array (G-BODY-2/3, M-SCALAR-ITEM). A run with any bareword stays
		// prose and routes to parse_body instead. RULED: ASP-3 (#909):
		// ws-delimited `(…)`/map-shaped `{…}` literals are discrete tokens here
		// too — `[k 1 (2, 3)]` is two children with the int intact (the prose
		// lane restringified it, and the shape is ENGINE OUTPUT via ux-016).
		// See body_is_typed_list.
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
	// (Their #829-remainder meta-zone stamps were pruned right after the
	// ElementMeta loop above.)
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
		pos:       elem_pos
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

// kind_only_tag_set holds the [157] KindName members that are NOT scalar
// ascription tags — the CXDM node/collection kinds plus the top/union kinds
// and the [157a] refinements missing from the scalar tag set. Together with
// valid_type_tag_set (minus the internal 'table' marker) they form the
// vocabulary a map-entry DECLARATION draws from (RULED: MSS-4 — a
// declaration is a kind CONSTRAINT, the [140g] bind-pattern semantics, not
// a coercion).
const kind_only_tag_set = [
	'element', 'sequence', 'map', 'iterator', 'array',
	'document', 'text', 'scalar-node', 'comment', 'pi', 'directive',
	'function', 'path', 'any', 'number',
	'instant', 'secret',
]

// is_valid_kind_tag reports whether `name` (optionally `[]`-suffixed) is
// admissible in a map-entry declaration `{k: ::T}` (RULED: MSS-4): the
// [157] KindName vocabulary. 'table' is the internal table-block marker,
// never a declarable kind.
pub fn is_valid_kind_tag(name string) bool {
	mut base := name
	if base.ends_with('[]') {
		base = base[..base.len - 2]
	}
	if base == 'table' {
		return false
	}
	return base in valid_type_tag_set || base in kind_only_tag_set
}

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
	// #829: a comment seen while a text run is still BUFFERED must not jump
	// ahead of it. text_buf flushes late (at a child element or end of body)
	// while a comment was appended to `items` immediately, so `[a text [;c]]`
	// parsed as [Comment, Text] — the comment did not move forward, the text
	// arrived late. Comments seen mid-buffer are held here and released at
	// the flush, AFTER the text node.
	//
	// If more text arrives before that flush the comment is MID-RUN, and it
	// is released immediately in its historical LEADING position: placing it
	// correctly would require splitting the run, and #469 forbids that in
	// those words — splitting moves the strict-canonical hash (Tier-1). So
	// this fixes the trailing shape and leaves the mid-run shape exactly as
	// it was, with no Tier-1 exposure.
	mut pending_comments := []Node{}

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
			mut c := p.parse_comment()!
			if text_buf.len > 0 {
				// #829 (RULED: 829-1c): remember WHERE in the run this
				// comment sat. Presentation only — canonical strips
				// comments, so the run stays ONE text node and the
				// Tier-1 hash is untouched (#469).
				if mut c is CommentNode {
					c.run_offset = ?int(text_buf.len)
				}
				pending_comments << c
			} else {
				items << c
			}
			continue
		}
		join_ws := had_ws || pending_join_ws
		pending_join_ws = false
		// Text (or anything else) resumes with a comment held → it was
		// MID-RUN. Release it now, in front of the run, exactly where it
		// landed before #829: correcting it needs a run split, and that
		// moves Tier-1 (#469).
		// #829 (RULED: 829-1c): a mid-run comment is NO LONGER released
		// in front of the run. It keeps its recorded run_offset and rides
		// the flush below, after the text node, so the lossless emitter can
		// re-place it inside the run without splitting the node.

		if kind == .lbrack || kind == .ldirective || kind == .raw_span || kind == .block_span {
			has_child_element = true
			// The separator space between a text run and a following
			// child stays IN the run's value: it is LOAD-BEARING for the
			// XML projection of mixed prose (`[p text [b bold]]` must
			// project `text <b>` — a #795-batch trim attempt regressed
			// exactly that and was reverted; the #791 schema-lane repair
			// lives in the schema reader, not here).
			if join_ws && text_buf.len > 0 && text_buf.last() != ` ` { text_buf << ` ` }
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
				if pending_comments.len > 0 {
					items << pending_comments
					pending_comments = []Node{}
				}
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
				if pending_comments.len > 0 {
					items << pending_comments
					pending_comments = []Node{}
				}
			}
			if b == `r` {
				// .triple_span with an `r` lead byte = the RAW form (I1 L58).
				s := p.read_raw_triple_str()!
				items << Node(TextNode{ value: s })
			} else if b == `'` && p.pos + 3 <= p.src.len && p.src[p.pos] == `'` && p.src[p.pos+1] == `'` && p.src[p.pos+2] == `'` {
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
						if pending_comments.len > 0 {
							items << pending_comments
							pending_comments = []Node{}
						}
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
				if pending_comments.len > 0 {
					items << pending_comments
					pending_comments = []Node{}
				}
			}
			items << p.parse_sequence_literal()!
			after_non_text = true
			continue
		}
		if kind == .lbrace && p.peek_is_map_literal_at_brace() {
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
				if pending_comments.len > 0 {
					items << pending_comments
					pending_comments = []Node{}
				}
			}
			items << p.parse_map_literal()!
			after_non_text = true
			continue
		}

		// I1 row 9 (L78): a bare delimited `$name` token is the authorable
		// variable HOLE — a discrete structural node in the self-delimiting
		// class, never part of a prose run. The STRING "$name" spells
		// '$name' (needs-quote covers $-leading images), so the two carry
		// different canonical bytes and different addresses. `$x.y` /
		// `$x/y` (path-bearing spellings) are NOT holes — they stay text.
		if !is_inferred_array && !is_array && b == `$` {
			if hole_len := p.peek_hole_len() {
				if text_buf.len > 0 {
					items << TextNode{ value: text_buf.bytestr() }
					text_buf = []u8{}
					if pending_comments.len > 0 {
						items << pending_comments
						pending_comments = []Node{}
					}
				}
				name := p.src[p.pos + 1..p.pos + hole_len].bytestr()
				for _ in 0 .. hole_len {
					p.advance()
				}
				items << HoleNode{ name: name }
				// NOT after_non_text: the emit-side sibling join supplies
				// the space between a hole and its neighbors
				// (cx_build_inline_body joins with ' '), so the following
				// text run must not carry a leading join space as VALUE.
				after_non_text = false
				continue
			}
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
	// #829: the end-of-body flush. A comment held while the run was still
	// buffered is released HERE, after the text node — this is the trailing
	// shape (`[a text [;c]]`) the issue is about. The early `return items`
	// paths above are the scalar / typed-body lanes, and each is guarded on
	// items.len == 0, so none of them can be holding a comment.
	if pending_comments.len > 0 {
		items << pending_comments
	}

	return items
}

// (The old whitespace auto-array — try_auto_array / try_autotype_array — was
// REMOVED with @CHOICE-1 §9-one-layer slice A: a whitespace scalar run is now a
// typed list of discrete children classified by body_is_typed_list, not a single
// `T[]` element. See the §9-one-layer commits.)

// ── §9 [L25c] comma-separated body array ───────────────────────────────────

// body_is_flat_comma_array reports whether the element body beginning at p.pos
// is a §9 [L25c] comma-separated scalar body. The rule itself is
// `flat_comma_array_body_at`'s (cx/lexical.v) — the single home, which carries
// its whole narrative; this is the cursor-bound spelling of the same question,
// and it delegates provably: the scan's only use of the cursor was `p.pos` as
// the BODY START, which is exactly the index passed here.
//
// It moved onto the shelf at #1029 because it is the FIRST of the element-body
// dispatch's three lanes, and a `&Parser` method reading its own `pos` is a
// question the cursor-free `code_tree.v` walker could not ask — so the walker
// could not tell a comma array (discrete items) from a prose run (ONE Text
// item), and coalesced neither.
fn (p &Parser) body_is_flat_comma_array() bool {
	return flat_comma_array_body_at(p.src, p.pos)
}

// body_is_typed_list reports whether the element body beginning at p.pos is a
// §9 [L25a/b] TYPED LIST. The rule itself is `typed_list_body_at`'s
// (cx/lexical.v) — the single home, which carries its whole narrative; this is
// the cursor-bound spelling of the same question, and it delegates provably:
// the classifier's only use of the cursor was `p.pos` as the BODY START (the
// scan origin and the glued-structure test's left edge), which is exactly the
// index passed here.
//
// It moved onto the shelf at #1025 because it is the SECOND array-yielding
// production — the headless dispatch tests it BEFORE `peek_is_array_literal` —
// and a `&Parser` method reading its own `pos` is a question the cursor-free
// `code_tree.v` walker could not ask, so `[true false]` was an ArrayNode here
// and the element `true` there.
fn (p &Parser) body_is_typed_list(headless bool) bool {
	return typed_list_body_at(p.src, p.pos, headless)
}

// skip_bracket_region returns the index just past the balanced bracket span that
// starts at `start` (a `[`/`(`/`{`). Quote-aware (so a `]` inside a string does
// not close the span). On an unbalanced span it returns src.len.
fn skip_bracket_region(src []u8, start int) int {
	mut i := start
	mut depth := 0
	for i < src.len {
		c := src[i]
		// A `'`/`"` opens a quoted region ONLY at a token start (the opening
		// bracket, or after a bracket opener / whitespace / a `,`/`=`
		// separator). A MID-token quote is a literal apostrophe in bare prose
		// (`it's`, `Bob's`) and must NOT be treated as a string opener —
		// otherwise this scan runs the "string" past the element's own `]`,
		// miscounting depth and corrupting every later body (symptom: a
		// spurious "unterminated quoted text" at EOF). The rule moved onto the
		// `cx/lexical.v` shelf at #1039, where the walker's three balanced-span
		// matchers — which lacked it, and so recovered `[doc it's here]` as
		// `unbalanced` — now ask the same question this scan asks.
		if (c == `'` || c == `"`) && span_token_start_at(src, i, start) {
			i = skip_quoted_region(src, i)
			continue
		}
		if c == `[` || c == `(` || c == `{` {
			depth++
			i++
			continue
		}
		if c == `]` || c == `)` || c == `}` {
			depth--
			if depth == 0 {
				return i + 1
			}
			i++
			continue
		}
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
		// RULED: ASP-2 (#903) / ASP-3 (#909) — a `(…)`/`{…}` literal is a
		// discrete typed-list item (a token position has no prose lane,
		// per the #810 lone-group rule for slots). Reached from BOTH
		// detector call sites: the headless-array dispatch (ASP-2) and
		// element bodies (ASP-3).
		if b == `(` {
			items << p.parse_sequence_literal()!
			continue
		}
		if b == `{` {
			items << p.parse_map_literal()!
			continue
		}
		if p.at_raw_triple() {
			// RAW triple-quoted string (I1 L58) — a quoted string in the
			// self-delimiting sense, same as the plain triple forms.
			s := p.read_raw_triple_str()!
			items << self_delim_string_node(TextNode{ value: s })
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
		// The token is classified as a SPAN and materialised only by the arm
		// that keeps its text. A typed scalar keeps a VALUE, not the token, so
		// the common case — every item of a typed list — now costs no token
		// string at all (#804).
		start, end := p.read_self_delim_span()!
		span := p.src[start..end]
		if scalar := try_autotype_bytes(span) {
			items << Node(scalar)
		} else if is_hole_token_bytes(span) {
			// I1 row 9 (L78): the variable hole is a discrete
			// self-delimiting item (`[+ $x 2]` = hole + int 2).
			items << Node(HoleNode{ name: p.src[start + 1..end].bytestr() })
		} else {
			items << Node(TextNode{ value: span.bytestr() })
		}
	}
	return items
}

// is_hole_token reports whether a whole delimited token is the authorable
// variable-hole spelling `$name` (I1 row 9, L78): `$` + NameStart +
// simple NameChars — no `.`/`:` path or QName continuation.
fn is_hole_token(tok string) bool {
	return is_hole_token_bytes(unsafe { bytes_view(tok) })
}

// is_hole_token_bytes is the implementation — the byte face exists so the
// typed-list classifier can test a span of `p.src` without materialising it
// (#804); see is_atom_name_bytes.
fn is_hole_token_bytes(tok []u8) bool {
	if tok.len < 2 || tok[0] != `$` {
		return false
	}
	if !is_name_start(tok[1]) {
		return false
	}
	for i := 2; i < tok.len; i++ {
		c := tok[i]
		if !is_name_char(c) || c == `.` || c == `:` {
			return false
		}
	}
	return true
}

// read_self_delim_token reads one bare self-delimiting body token: from the
// current position to the next whitespace or `]`. Unlike read_slot_token it
// does NOT stop at `'`/`"` — a quote inside a bare token is a literal
// apostrophe (`it's`), not a new item; a token-leading quote is dispatched by
// the caller before this is reached.
// A self-delimiting token is a CONTIGUOUS run of source bytes, so it is
// read as one slice of `src` rather than accumulated byte-by-byte into a
// growing buffer (#804). The old shape cost a realloc chain per token
// (a zero-capacity []u8 doubling 0→1→2→4→…) plus the final copy; this
// costs the copy alone. Same bytes, same stopping rule, same line/col
// bookkeeping — the loop still advances through `p.advance()`, and a
// token can never contain a newline because whitespace terminates it.
//
// Gate-15's JSON-shape corpus is dominated by exactly these tokens, and
// this reader's array growth was the single heaviest allocation site in
// the profile.
fn (mut p Parser) read_self_delim_token() !string {
	start, end := p.read_self_delim_span()!
	return p.src[start..end].bytestr()
}

// read_self_delim_span is the reader proper: it advances past the token and
// returns its `[start, end)` bounds in `p.src`, leaving the caller to decide
// whether the token's TEXT is needed at all. A typed-list item keeps a parsed
// value rather than the token, so on the gate-15 corpus almost none of them
// need it (#804).
fn (mut p Parser) read_self_delim_span() !(int, int) {
	start := p.pos
	for !p.at_end() {
		b := p.peek()
		if is_ws(b) || b == `]` { break }
		p.advance()
	}
	if p.pos == start {
		return error(p.make_error('expected token in element body'))
	}
	return start, p.pos
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
	// atom — `:NAME` (lexicon [L40]). Mirrors `try_autotype`'s arm exactly,
	// reserved-name rejection included, and sits in the same relative position
	// (a hex prefix or a numeric shape can never begin with `:`). Recognised
	// here so an atom-dominated body — the §11.6 gate-15 record shape is half
	// atoms — never materialises the token as a string just to classify it;
	// the one remaining allocation is the atom's own name, which the
	// ScalarValue has to own anyway (#804).
	if n >= 2 && buf[0] == `:` && is_atom_pattern_name_bytes(buf[1..]) {
		name := buf[1..].bytestr()
		if name == 'true' || name == 'false' || name == 'null' {
			return none
		}
		return ScalarNode{ data_type: .atom_type, value: ScalarValue(name) }
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
		// The in-range decimal int now costs NO allocation at all: the
		// checked parse reads the digits straight off the span (#804).
		// Only the over-i64 promotion below, which has to keep the literal
		// text as its value, materialises a string.
		if v := parse_i64_checked_bytes(buf) {
			return ScalarNode{ data_type: .int_type, value: ScalarValue(v) }
		}
		// [L20]/D-H: over-i64 well-formed decimal int → bigint (drop a
		// redundant leading `+`), matching the string-surface try_autotype.
		s := buf.bytestr()
		bigint_str := if s.starts_with('+') { s[1..] } else { s }
		return ScalarNode{ data_type: .bigint_type, value: ScalarValue(bigint_str) }
	}
	// A numeric fraction needs a digit mantissa — a digit-less token (bare
	// `e`/`.`) must NOT atof64 to 0.0; defer it to the string path (D3).
	if (has_dot || has_exp) && has_digit && !has_underscore {
		s := buf.bytestr()
		// I1 stream 11 (2b): fixed-point → DECIMAL (scale preserved);
		// exponent form → float. Mirrors try_autotype's arm exactly.
		if !has_exp {
			if norm := normalize_decimal_token(s) {
				return ScalarNode{ data_type: .decimal_type, value: ScalarValue(norm) }
			}
		}
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
	// datetime / date — checked BEFORE the float arm (I1 epoch, stream 12,
	// the W-7 typing companion): a fractional datetime contains '.', and the
	// float arm's atof64-failure path returned `none` (→ string) instead of
	// falling through, so `2026-08-05T10:00:00.500Z` string-typed everywhere
	// while its fraction-less sibling typed datetime — same instant, two
	// TYPES, unbounded addresses. Temporal forms are whole-token anchored,
	// calendar-validated, and always carry 'T'+':' / '-'-separated shapes no
	// valid float can, so the reorder is disjoint.
	if is_datetime(tok) {
		return ScalarNode{ data_type: .datetime_type, value: ScalarValue(tok) }
	}
	if is_date(tok) {
		return ScalarNode{ data_type: .date_type, value: ScalarValue(tok) }
	}
	// numeric fraction — must contain '.' or an exponent marker to
	// distinguish from int, AND must contain at least one digit so a
	// digit-less token (bare `e`/`E`/`.`, `e+`, …) is NOT numeric.
	// `strconv.atof64` leniently returns 0.0 for such tokens (the
	// `[name e]` → 0.0 bug); [L20b] requires an Integer mantissa.
	//
	// I1 stream 11 (OWNER RULING 2b, 2026-08-05): a bare FIXED-POINT
	// fraction is a DECIMAL — exact by default, scale preserved (`1.50`
	// keeps its cents-precision; the financial-first, SQL-literal
	// reading). Exponent-form literals are FLOATS, so the two kinds are
	// lexically self-describing (canonical floats always carry the
	// exponent — the amended §2.5).
	if cleaned.contains('.') || cleaned.contains('e') || cleaned.contains('E') {
		if !has_ascii_digit(cleaned) {
			return none
		}
		if !cleaned.contains('e') && !cleaned.contains('E') {
			if norm := normalize_decimal_token(tok) {
				return ScalarNode{ data_type: .decimal_type, value: ScalarValue(norm) }
			}
		}
		fv := strconv.atof64(cleaned) or { return none }
		return ScalarNode{ data_type: .float_type, value: ScalarValue(fv) }
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
	return is_atom_name_bytes(unsafe { bytes_view(s) })
}

// is_atom_name_bytes is the single implementation of the [L40] atom-name
// grammar; `is_atom_name` is the string face of it. The byte face exists so
// the parser can test a token that is still a span of `p.src` — the §11.6
// gate-15 corpus is atom-dominated (`:id`, `:name`, `:host`, …), and going
// through the string face cost a `bytestr()` for the token plus a `[1..]`
// substring for the name on EVERY atom (#804).
pub fn is_atom_name_bytes(s []u8) bool {
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

// bytes_view is a NON-OWNING `[]u8` over a string's bytes — no copy, no
// allocation. It exists so a `string`-faced predicate can delegate to its
// `[]u8` implementation without paying `s.bytes()`. Read-only: never append
// through it, never store it, never let it outlive `s`.
@[inline]
@[unsafe]
fn bytes_view(s string) []u8 {
	mut v := []u8{}
	unsafe {
		v.data = s.str
		v.len = s.len
		v.cap = s.len
	}
	return v
}

// is_atom_pattern_name admits everything is_atom_name does PLUS a single
// terminal `.*` glob segment (`:order.*`) — the bus.md §2.2 prefix-glob
// spelling ([L40] `('.' '*')?`, #397). The star is legal ONLY as the entire
// final segment; it has no meaning at the atom level (one opaque name) —
// pattern consumers (bus) assign the glob semantics.
pub fn is_atom_pattern_name(s string) bool {
	return is_atom_pattern_name_bytes(unsafe { bytes_view(s) })
}

// is_atom_pattern_name_bytes — the byte face of is_atom_pattern_name, for the
// same reason is_atom_name_bytes exists.
pub fn is_atom_pattern_name_bytes(s []u8) bool {
	if s.len >= 2 && s[s.len - 2] == `.` && s[s.len - 1] == `*` {
		return s.len > 2 && is_atom_name_bytes(s[..s.len - 2])
	}
	return is_atom_name_bytes(s)
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
			// I1 stream 11: normalize when the token conforms (§6 — table
			// cells and importer lanes ride this arm); verbatim fallback
			// keeps the fn infallible for the codec importers.
			norm := normalize_decimal_token(tok) or { strip_underscores(tok) or { tok } }
			ScalarNode{ data_type: .decimal_type, value: ScalarValue(norm) }
		}
		// v3.4 arbitrary-precision integer — stored as string; auto-
		// promoted from int when the value exceeds i64 range.
		'bigint' {
			norm := normalize_bigint_token(tok) or { strip_underscores(tok) or { tok } }
			ScalarNode{ data_type: .bigint_type, value: ScalarValue(norm) }
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
//   - CXER0290 — the token cannot be coerced to the ascribed type (M-ERR-2).
//   - CXERLEX-RANGE — a sized integer value is outside the type's range
//     (@CHOICE-5b; LR-RANGE-1).
// For every type whose coercion cannot fail (string / bool / date / atom / …)
// it delegates verbatim to coerce_scalar, so accepted values stay byte-stable.
//
// RULED: MSS-3 item 7 (#917): the checking core is the receiver-less
// coerce_scalar_strict, shared with the PROGRAM reader so both readings
// enforce identical ascription rules; this method adds source position.
fn (p &Parser) coerce_scalar_checked(et string, tok string) !ScalarNode {
	return coerce_scalar_strict(et, tok) or { return error(p.make_error(err.msg())) }
}

// coerce_scalar_strict is the position-free checking core — see
// coerce_scalar_checked above.
pub fn coerce_scalar_strict(et string, tok string) !ScalarNode {
	match et {
		'int', 'i8', 'i16', 'i32', 'i64' {
			v := parse_int_strict(tok) or {
				return error('cannot coerce `${tok}` to ${et} (cx-err:CXER0290)')
			}
			if !int_in_range(v, et) {
				return error('integer ${v} out of range for `${et}` (cx-err:CXERLEX-RANGE)')
			}
			return ScalarNode{ data_type: .int_type, value: ScalarValue(v) }
		}
		'u8', 'u16', 'u32', 'u64' {
			v := parse_int_strict(tok) or {
				return error('cannot coerce `${tok}` to ${et} (cx-err:CXER0290)')
			}
			if !int_in_range(v, et) {
				return error('integer ${v} out of range for `${et}` (cx-err:CXERLEX-RANGE)')
			}
			return ScalarNode{ data_type: .int_type, value: ScalarValue(v) }
		}
		'float', 'f16', 'f32', 'f64' {
			fv := try_coerce_float_token(tok) or {
				return error('cannot coerce `${tok}` to ${et} (cx-err:CXER0290)')
			}
			// I1 W-3: a literal whose value overflows to ±Inf (or is NaN)
			// has no §2.5 form — fail loud instead of minting `+inf.0`.
			if !cx_f64_is_finite(fv) {
				return error('`${tok}` overflows ${et} — non-finite floats have no canonical form (canonical.md §1.3/§2.5) (cx-err:CXER0290)')
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
				return error('cannot coerce `${tok}` to atom — not a valid atom name (lexicon [L40]) (cx-err:CXER0290)')
			}
			return ScalarNode{ data_type: .atom_type, value: ScalarValue(name) }
		}
		'decimal', 'bigint' {
			// OWNER RULING (#466 item 3): decimal / bigint are BASE-10
			// value types — a hex token under the ascription is a mistake
			// and REJECTS loudly (M-ERR-2), never stored verbatim.
			if is_hex_int_token(tok) {
				return error('cannot coerce hex literal `${tok}` to ${et} — ${et} is a base-10 value type (cx-err:CXER0290)')
			}
			// I1 stream 11 (L39 defect G + L45 §6): strict lexical
			// validation + canonical normalization. `::decimal hello-world`
			// parsed silently before; exponent-form decimals are
			// scale-ambiguous and reject; `+`/redundant leading zeros/
			// negative zero normalize away (scale preserved).
			if et == 'decimal' {
				norm := normalize_decimal_token(tok) or {
					return error('cannot coerce `${tok}` to decimal — fixed-point base-10 literal required (sign? digits (`.` digits)?; exponent form is scale-ambiguous) (cx-err:CXER0290)')
				}
				return ScalarNode{ data_type: .decimal_type, value: ScalarValue(norm) }
			}
			norm := normalize_bigint_token(tok) or {
				return error('cannot coerce `${tok}` to bigint — base-10 integer literal required (cx-err:CXER0290)')
			}
			return ScalarNode{ data_type: .bigint_type, value: ScalarValue(norm) }
		}
		'duration', 'period' {
			// I1 stream 11 (L39 defect G): typed carriers validate their
			// lexical form — `::duration hello` parsed silently before.
			kind := temporal_span_kind(tok) or {
				return error('cannot coerce `${tok}` to ${et} — not a temporal span (lexicon [L25]/[L26]) (cx-err:CXER0290)')
			}
			want := if et == 'duration' { ScalarType.duration_type } else { ScalarType.period_type }
			if kind != want {
				return error('`${tok}` is a ${scalar_type_name(kind)} span, not ${et} (cx-err:CXER0290)')
			}
			return coerce_scalar(et, tok)
		}
		// RULED: MSS-3 item 1 (#917): every remaining arm is CHECKED — the
		// old else-fallthrough let bool/date/datetime/bytes/null coerce
		// garbage silently, so whether a malformed ascription errored or
		// INVENTED a value depended on the type name ('prose ::bool' → false
		// at rc=0 while 'prose ::int' errored).
		'bool' {
			if tok != 'true' && tok != 'false' {
				return error('cannot coerce `${tok}` to bool — `true` or `false` required (cx-err:CXER0290)')
			}
			return coerce_scalar(et, tok)
		}
		'date' {
			if !is_date(tok) {
				return error('cannot coerce `${tok}` to date — `YYYY-MM-DD` required (lexicon [L23]) (cx-err:CXER0290)')
			}
			return coerce_scalar(et, tok)
		}
		'datetime' {
			if !is_datetime(tok) {
				return error('cannot coerce `${tok}` to datetime — ISO-8601 form required (lexicon [L24]) (cx-err:CXER0290)')
			}
			return coerce_scalar(et, tok)
		}
		'bytes' {
			// The shipped bytes carrier is the `0x…` hex literal (#457 —
			// the source spelling is kept verbatim); base64 is admitted as
			// the interchange spelling. Anything else refuses.
			if is_hex_int_token(tok) {
				return coerce_scalar(et, tok)
			}
			_ := base64_to_bytes_hex(tok) or {
				return error('cannot coerce `${tok}` to bytes — `0x…` hex or base64 content required (cx-err:CXER0290)')
			}
			return coerce_scalar(et, tok)
		}
		'null' {
			if tok != 'null' {
				return error('cannot coerce `${tok}` to null — only `null` itself has the null type (cx-err:CXER0290)')
			}
			return coerce_scalar(et, tok)
		}
		else {
			// 'string' and the internal 'table' marker: a single token is
			// always a valid string carrier; table rides its own block path.
			return coerce_scalar(et, tok)
		}
	}
}

// normalize_decimal_token validates + normalizes a decimal literal per
// L45/§6: fixed-point only (exponent form is scale-ambiguous → none),
// underscores stripped, no `+`, exactly one leading integer digit run with
// redundant zeros stripped (leading zero REQUIRED for fractions: `.5` →
// `0.5`), negative zero normalizes positive with its scale preserved,
// trailing fraction zeros PRESERVED (scale is data).
// decimal_token_is_canonical reports whether `tok` is ALREADY exactly
// what normalize_decimal_token would build from it (#804). The rebuild
// costs about five allocations — strip_underscores, the sign split, the
// int/frac split, the leading-zero trim, and two concatenations — and on
// an already-canonical token every one of them reproduces the input
// byte-for-byte. Gate-15's JSON-shape corpus carries a decimal per
// record, so that is a per-record tax paid to change nothing.
//
// Canonical means: no `+`, no underscores, a non-empty int part with no
// redundant leading zero, a non-empty all-digit fraction when a `.` is
// present, and no `-` on a zero value (all the rewrites the slow path
// below performs). One pass, no allocation.
fn decimal_token_is_canonical(tok string) bool {
	if tok.len == 0 {
		return false
	}
	mut i := 0
	mut neg := false
	if tok[0] == `-` {
		neg = true
		i = 1
	} else if tok[0] == `+` {
		return false // a leading '+' is always stripped
	}
	int_start := i
	mut int_len := 0
	mut frac_len := 0
	mut seen_dot := false
	mut all_zero := true
	for ; i < tok.len; i++ {
		c := tok[i]
		if c == `.` {
			if seen_dot {
				return false
			}
			seen_dot = true
			continue
		}
		if c < `0` || c > `9` {
			return false // underscore, exponent, hex, anything else
		}
		if c != `0` {
			all_zero = false
		}
		if seen_dot {
			frac_len++
		} else {
			int_len++
		}
	}
	if int_len == 0 {
		return false // '.5' gains its '0'
	}
	if int_len > 1 && tok[int_start] == `0` {
		return false // '007' loses its leading zeros
	}
	if seen_dot && frac_len == 0 {
		return false // '1.' is not a decimal token
	}
	if neg && all_zero {
		return false // '-0.0' loses its sign
	}
	return true
}

pub fn normalize_decimal_token(tok string) ?string {
	if decimal_token_is_canonical(tok) {
		return tok
	}
	cleaned := strip_underscores(tok) or { tok }
	mut s := cleaned
	mut neg := false
	if s.starts_with('+') {
		s = s[1..]
	} else if s.starts_with('-') {
		neg = true
		s = s[1..]
	}
	if s.len == 0 {
		return none
	}
	mut int_part := s
	mut frac := ''
	if idx := s.index('.') {
		int_part = s[..idx]
		frac = s[idx + 1..]
		if frac.len == 0 || !is_all_digits(frac) {
			return none
		}
	}
	if int_part.len == 0 {
		int_part = '0'
	} else if !is_all_digits(int_part) {
		return none
	}
	mut ip := int_part.trim_left('0')
	if ip.len == 0 {
		ip = '0'
	}
	mut all_zero := ip == '0'
	if all_zero {
		for c in frac {
			if c != `0` {
				all_zero = false
				break
			}
		}
	}
	mut out := if neg && !all_zero { '-' } else { '' }
	out += ip
	if frac.len > 0 {
		out += '.' + frac
	}
	return out
}

// normalize_bigint_token validates + normalizes a bigint literal per L45:
// base-10 digits only, underscores stripped, no `+`, no leading zeros,
// negative zero normalizes positive.
pub fn normalize_bigint_token(tok string) ?string {
	cleaned := strip_underscores(tok) or { tok }
	mut s := cleaned
	mut neg := false
	if s.starts_with('+') {
		s = s[1..]
	} else if s.starts_with('-') {
		neg = true
		s = s[1..]
	}
	if s.len == 0 || !is_all_digits(s) {
		return none
	}
	mut d := s.trim_left('0')
	if d.len == 0 {
		d = '0'
	}
	if neg && d != '0' {
		return '-' + d
	}
	return d
}

// try_split_postfix_ascription splits a collection-position token
// `value::T` at its LAST `::` when T is a valid non-array scalar type tag
// (I1 stream 11, L43 — #485 reversed: CX text is a complete carrier for
// its own type system in map-value / array-item / map-key positions).
// Returns none when the token carries no ascription (it stays whatever the
// bare rules say).
fn try_split_postfix_ascription(tok string) ?(string, string) {
	idx := tok.last_index('::') or { return none }
	if idx == 0 || idx + 2 >= tok.len {
		return none
	}
	typ := tok[idx + 2..]
	if typ.ends_with('[]') || typ == 'table' || !is_valid_type_tag(typ) {
		return none
	}
	return tok[..idx], typ
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
	return parse_i64_checked_bytes(unsafe { bytes_view(signed_body) })
}

// parse_i64_checked_bytes is the implementation. The magnitude accumulates in
// u64 against the signed limit, so the boundary is decided by arithmetic
// rather than by the old re-stringify compare (`v.str() != norm`), which
// allocated up to four strings per integer token — a leading-zero trim, a sign
// concatenation, and the `i64.str()` itself. On the §11.6 gate-15 corpus every
// record carries two integers, so that round trip was a per-record allocation
// cluster (#804). Same acceptance set as before: `[+-]?` then decimal digits
// only, leading zeros tolerated (legal under an explicit `::int`); any other
// byte, an empty magnitude, or an over-i64 magnitude → none.
fn parse_i64_checked_bytes(buf []u8) ?i64 {
	if buf.len == 0 {
		return none
	}
	mut i := 0
	mut neg := false
	if buf[0] == `+` || buf[0] == `-` {
		neg = buf[0] == `-`
		i = 1
	}
	if i >= buf.len {
		return none
	}
	// i64 min's magnitude is one larger than i64 max's.
	limit := if neg { u64(9223372036854775807) + 1 } else { u64(9223372036854775807) }
	mut mag := u64(0)
	for ; i < buf.len; i++ {
		c := buf[i]
		if c < `0` || c > `9` {
			return none
		}
		d := u64(c - `0`)
		// mag*10 + d <= limit, decided without ever forming the overflowing
		// product.
		if mag > (limit - d) / 10 {
			return none
		}
		mag = mag * 10 + d
	}
	if neg {
		if mag == u64(9223372036854775807) + 1 {
			return i64(-9223372036854775807 - 1)
		}
		return -i64(mag)
	}
	return i64(mag)
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
// (M-ERR-2 / CXER0290). The SINGLE home of the ascribed-float guards —
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
		} else if b >= 0x80 {
			// I1 L22 (W-9): full-Unicode names per [L10a]/[L10b] — decode
			// the codepoint and test the grammar's ranges (start-set for the
			// first character, continuation-set after). Invalid UTF-8 cannot
			// reach here (validate_utf8 runs at the parse entries).
			cp, sz := utf8_cp_at(p.src, p.pos)
			if sz == 0 {
				break
			}
			ok := if p.pos == start { is_name_start_cp(cp) } else { is_name_char_cp(cp) }
			if !ok {
				break
			}
			for _ in 0 .. sz {
				p.advance()
			}
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
// The boundary rule itself is `value_run_end`'s (cx/lexical.v) — the single
// home, which carries the semantics note above; this is the cursor-bound
// spelling. The delegation is exact in POSITION and in line/col: the retired
// loop called `advance()` once per byte of `[start, end)` in order and never
// past it, which is precisely what the loop below does. It moved onto the shelf
// at #1029 so the cursor-free `code_tree.v` walker could ask how much source one
// prose token covers instead of scanning byte kinds (`[doc :enum=[v1 v2] rest
// here]` is ONE Text to the parser and was five items to the walker).
fn (mut p Parser) lex_value_run() ?Token {
	start := p.pos
	start_line := p.line
	start_col := p.col
	end := value_run_end(p.src, p.pos)
	for p.pos < end {
		p.advance()
	}
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
	p.reject_mid_bom(t.pos.offset, t.end)!
	buf << p.src[t.pos.offset..t.end]
}

fn (mut p Parser) read_token() !string {
	t := p.lex_value_run() or { return error(p.make_error('expected token')) }
	p.reject_mid_bom(t.pos.offset, t.end)!
	return p.src[t.pos.offset..t.end].bytestr()
}

// reject_mid_bom errors on a UTF-8 BOM (EF BB BF) inside a bare content
// token — I1 W-10 (lexicon §0): only the LEADING file BOM is consumed
// (new_parser); anywhere else the invisible U+FEFF would silently join a
// bare value. Quoted values are verbatim and unaffected (their bytes never
// route through here).
fn (p &Parser) reject_mid_bom(start int, end int) ! {
	for i := start; i <= end - 3; i++ {
		if p.src[i] == 0xef && p.src[i + 1] == 0xbb && p.src[i + 2] == 0xbf {
			return error(p.make_error('byte-order mark (U+FEFF) inside content — a BOM is only recognized as the first bytes of the file (cx-err:CXER0100)'))
		}
	}
	return
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
	// RAW triquote `r'''…'''` / `r"""…"""` (I1 L58) — verbatim body.
	if p.at_raw_triple() {
		return p.read_raw_triple_str()!
	}
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
	// RAW triquote `r'''…'''` / `r"""…"""` (I1 L58) in attribute position.
	if p.at_raw_triple() {
		s := p.read_raw_triple_str()!
		return ScalarValue(s), ?string(none)
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

// peek_hole_len reports the byte length of an authorable variable-hole
// token `$name` at the cursor (I1 row 9, L78), or none. A hole is `$` +
// NameStart NameChar* ENDING at a delimiter (whitespace / `]` / `,` /
// `)` / `}` / EOF). Any other continuation — a path step (`$x.y`,
// `$x/y`), a glued sigil, a bare `$` — is NOT a hole and stays on the
// text lane. The returned length includes the `$`.
// The rule itself is `hole_token_len`'s (cx/lexical.v) — the single home, which
// carries the narrative; this is the cursor-bound spelling of the same question
// and delegates provably (the only use of the cursor was `p.pos` as the token
// start). It moved onto the shelf at #1029: a hole BREAKS a prose run while
// `$x.y` is text inside one, and the cursor-free walker had to be able to tell
// them apart.
fn (p &Parser) peek_hole_len() ?int {
	return hole_token_len(p.src, p.pos)
}

// at_raw_triple reports whether the cursor sits on an `r` GLUED to a triple
// quote — the RAW triple-quoted string opener (I1 L58, stream 13: legal in
// DATA mode too; one token grammar with the program lexer). Never true for a
// bare `r` or `r` before anything but a triple quote.
//
// The opener test itself is `triple_quote_prefix_len`'s (cx/lexical.v), which
// pairs with `scan_triple_quoted_opt`'s closing rule — a raw opener is exactly
// a 1-byte prefix. See that function for why the recognizer had to become
// cursor-free (#999).
fn (p &Parser) at_raw_triple() bool {
	return triple_quote_prefix_len(p.src, p.pos) == 1
}

// read_raw_triple_str consumes the `r` prefix plus the triple-quoted body and
// returns the VERBATIM value — raw skips the common-indent dedent
// (scan_triple_quoted_opt, the one shared scanner). Position must satisfy
// at_raw_triple. Canonical output never re-emits the triquote spelling
// (L15/L17), so the raw form is an INPUT spelling only.
fn (mut p Parser) read_raw_triple_str() !string {
	p.advance() // consume the `r`
	q := p.peek()
	value, n := scan_triple_quoted_opt(p.src, p.pos, q, true) or {
		return error(p.make_error('unterminated triple-quoted string'))
	}
	for _ in 0 .. n {
		p.advance()
	}
	return value
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

// peek_is_array_literal disambiguates `[…]` between Element and Array literal.
// Does not consume input.
//
// The rule itself — the [D1] first-item-followed-by-comma rule, plus the
// reserved-sigil and `[table[` guards this call site used to spell inline — is
// `array_literal_at_bracket`'s (cx/lexical.v), which carries its narrative. That
// is the single home it now shares with the `code_tree.v` walker, which had no
// delimitation test at all and so read `[1, 2, 3]` as an element NAMED `1`
// (#1020). This method is the cursor-bound spelling of it: `parse_bracket_node`
// has already consumed the `[`, so the bracket the rule is about sits at
// `p.pos - 1`.
fn (p &Parser) peek_is_array_literal() bool {
	return array_literal_at_bracket(p.src, p.pos - 1)
}

// peek_is_sequence_literal_at_paren scans forward from the current `(`
// to decide between SequenceLiteral and body text. Does not consume.
// Returns true if shape is `()` (empty) or contains a depth-0 `,`
// before the matching `)`.
// peek_lone_paren_group_fills_slot reports whether the `(` at the cursor
// opens a balanced paren group which — after trailing whitespace — is
// immediately followed by a slot terminator (`,` `)` `]` `}`) or EOF:
// the group IS the whole slot. Quote-shielded like its sibling above.
// (#810 RULED (a): the lone-group slot form is a sequence literal.)
fn (p &Parser) peek_lone_paren_group_fills_slot() bool {
	if p.peek() != `(` { return false }
	mut i := p.pos + 1
	mut depth := 1
	mut quote := u8(0)
	for i < p.src.len && depth > 0 {
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
		if b == `(` || b == `[` || b == `{` { depth++ }
		if b == `)` || b == `]` || b == `}` { depth-- }
		i++
	}
	if depth != 0 { return false }
	for i < p.src.len && is_ws(p.src[i]) { i++ }
	if i >= p.src.len { return true }
	nb := p.src[i]
	return nb == `,` || nb == `)` || nb == `]` || nb == `}`
}

// The rule itself is `sequence_literal_at_paren`'s (cx/lexical.v) — the single
// home it now shares with the `code_tree.v` walker, which had no delimitation
// test at all (#1000). This method is the cursor-bound spelling of it.
fn (p &Parser) peek_is_sequence_literal_at_paren() bool {
	return sequence_literal_at_paren(p.src, p.pos)
}

// peek_is_map_literal_at_brace scans forward from the current `{` to
// decide between MapLiteral and body text. Returns true if shape is
// `{}` (empty) or contains a depth-0 `:` before the matching `}`.
//
// The rule itself is `map_literal_at_brace`'s (cx/lexical.v) — the single home
// it now shares with `span_is_map_shaped`'s former call site and with the
// `code_tree.v` walker, which had no delimitation test at all and so emitted
// `{a: 1}` as five punctuation scalars (#1020). This method is the
// cursor-bound spelling of it.
fn (p &Parser) peek_is_map_literal_at_brace() bool {
	return map_literal_at_brace(p.src, p.pos)
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
		// I1 L23 (W-11): duplicate-key comparison is NFC for string keys —
		// NFC/NFD confusable spellings of one key are ONE key (the check
		// was spec'd in three places and implemented nowhere). The STORED
		// key keeps its authored bytes (keys are values; values never
		// normalize).
		mut key_img := scalar_value_str(entry.key_value)
		if entry.key_type == .string_type {
			key_img = cx_nfc_name(key_img)
		}
		marker := '${scalar_type_name(entry.key_type)}:${key_img}'
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
		// RULED: MSS-2 (#917) — whitespace separates entries exactly as a
		// comma does ([L85] amended; the 715-site shipped form). The value
		// reader enforces its own glued-tail boundary, so reaching here
		// means a ws-separated next entry begins.
	}
	p.expect(`}`)!
	return Node(MapNode{ entries: entries })
}

// parse_map_entry parses one MapEntry [56f] — `MapKey : MapValue` or the
// MSS-4 declaration `MapKey : ::Kind` (value ABSENT). The value is one
// expression-shaped item (RULED: MSS-1 — prose must be quoted), matching
// the program reading.
fn (mut p Parser) parse_map_entry() !MapEntry {
	p.skip_ws_and_line_comments()
	key_type, key_value := p.read_map_key()!
	p.skip_ws_and_line_comments()
	if p.at_end() || p.peek() != `:` {
		return error(p.make_error("expected `:` after map key — a map value is ONE item: quote multi-word prose ('two words'), and a typed value is `k: ::int 30` or `k: 30::int` (cx-err:CXER0100)"))
	}
	// RULED: MSS-3 item 3 (#917): after a key, `::` is never the entry
	// separator — the old byte scan consumed one `:` and silently read
	// `{a ::int}` as the atom entry `{a: :int}`.
	if p.pos + 1 < p.src.len && p.src[p.pos + 1] == `:` {
		return error(p.make_error('a type annotation must be glued — write `k::T: v` to type the key, `k: ::T v` or `k: v::T` to type the value, `k: ::T` to declare the field, or `k: :name` for an atom value (cx-err:CXER0100)'))
	}
	p.advance() // consume ':'
	p.skip_ws_and_line_comments()
	// RULED: MSS-4 (#917): a prefix TypeAnnotation as the SOLE value
	// declares the field — typed, value ABSENT. Typed values stay postfix
	// (`k: v::T`), so `{a: ::int 5}` remains a parse error downstream.
	if !p.at_end() && p.peek() == `:` && p.pos + 1 < p.src.len && p.src[p.pos + 1] == `:` {
		p.advance()
		p.advance()
		tag := p.read_kind_tag()!
		if !is_valid_kind_tag(tag) {
			return error(p.make_error('unknown kind `${tag}` in map-entry declaration — the vocabulary is [157] KindName (cx-err:CXER0107 E_UNKNOWN_TYPE_TAG)'))
		}
		if !p.at_end() {
			b := p.peek()
			if b != `,` && b != `}` && !is_ws(b) {
				return error(p.make_error('the `::${tag}` annotation is glued to nothing it can type — write `k: ::${tag} VALUE` or the declaration `k: ::${tag}` (cx-err:CXER0100)'))
			}
		}
		// RULED: MSS-7 (#917, owner "1a" on the playground evidence): a
		// VALUE after the prefix types it — `{age: ::int 30}` — through
		// the same checked core as the postfix form. A ws-separated token
		// that turns out to be the NEXT KEY (`{a: ::int b: 2}`) restores
		// the cursor and this entry stays a declaration.
		if p.prefixed_value_follows() {
			v := p.read_prefixed_value(tag)!
			return MapEntry{
				key_type:  key_type
				key_value: key_value
				value:     v
			}
		}
		return MapEntry{
			key_type:  key_type
			key_value: key_value
			value:     Node(ScalarNode{ data_type: .null_type, value: ScalarValue(NullValue{}) })
			decl_kind: tag
		}
	}
	value := p.parse_map_value()!
	return MapEntry{
		key_type:  key_type
		key_value: key_value
		value:     value
	}
}

// prefixed_value_follows — MSS-7 (#917) lookahead: does a scalar VALUE
// token follow the map-entry prefix `::T`? False at the map boundary, at
// a structure/atom opener (only scalars take the prefix), and when the
// ws-separated token turns out to be the NEXT ENTRY's key (its `:`
// betrays it). Cursor always restored.
fn (mut p Parser) prefixed_value_follows() bool {
	save := p.pos
	defer {
		p.pos = save
	}
	p.skip_ws_and_line_comments()
	if p.at_end() {
		return false
	}
	b := p.peek()
	if b == `,` || b == `}` {
		return false
	}
	if b == `[` || b == `(` || b == `{` || b == `&` || b == `$` || b == `:` {
		return false
	}
	if b == `'` || b == `"` {
		if b == `"` {
			p.read_quoted() or { return false }
		} else {
			p.read_quoted_text() or { return false }
		}
	} else {
		tok := p.read_slot_token() or { return false }
		// `b:` reads as ONE token (the slot reader does not break on `:`)
		// — a trailing single colon marks the NEXT ENTRY's key.
		if tok.ends_with(':') && !tok.ends_with('::') {
			return false
		}
	}
	// A `:` after the token — glued or ws-separated (`{a: ::int b : 2}`,
	// the spaced-colon key stays legal) — means it was a KEY, not a
	// value; a bare value that happens to look like a key is quoted.
	p.skip_ws_and_line_comments()
	if !p.at_end() && p.peek() == `:`
		&& !(p.pos + 1 < p.src.len && p.src[p.pos + 1] == `:`) {
		return false
	}
	return true
}

// read_prefixed_value — MSS-7 (#917): the committed read of `::T VALUE`
// (owner "1a" on the playground evidence — `{age: ::int 30}` types the
// value through the same checked core as the postfix form). One scalar
// token, bare or quoted; a kind-only tag refuses (kinds declare, they do
// not coerce); the slot then ends.
fn (mut p Parser) read_prefixed_value(tag string) !Node {
	p.skip_ws_and_line_comments()
	if !is_valid_type_tag(tag) {
		return error(p.make_error('kind `${tag}` declares only — it cannot coerce a value; scalar tags type values (`k: ::int 30`) (cx-err:CXER0290)'))
	}
	b := p.peek()
	if b == `'` || b == `"` {
		tok := if b == `"` { p.read_quoted()! } else { p.read_quoted_text()! }
		p.refuse_glued_map_value_tail()!
		if tag == 'string' {
			return Node(ScalarNode{ data_type: .string_type, value: ScalarValue(tok) })
		}
		return Node(p.coerce_scalar_checked(tag, tok)!)
	}
	tok := p.read_slot_token()!
	sn := p.coerce_scalar_checked(tag, tok)!
	p.refuse_glued_map_value_tail()!
	return Node(sn)
}

// read_kind_tag consumes a type/kind tag name at the cursor — letters,
// digits and `-` (scalar-node), with an optional glued `[]` suffix.
fn (mut p Parser) read_kind_tag() !string {
	mut s := []u8{}
	for !p.at_end() {
		b := p.peek()
		if (b >= `a` && b <= `z`) || (b >= `0` && b <= `9`) || b == `-` {
			s << b
			p.advance()
			continue
		}
		break
	}
	if s.len == 0 {
		return error(p.make_error('expected a type name after `::` (cx-err:CXER0107 E_UNKNOWN_TYPE_TAG)'))
	}
	if p.pos + 1 < p.src.len && p.src[p.pos] == `[` && p.src[p.pos + 1] == `]` {
		s << `[`
		s << `]`
		p.advance()
		p.advance()
	}
	return s.bytestr()
}

// parse_map_value parses one map VALUE as a discrete expression-shaped
// item (RULED: MSS-1 #917) — a nested collection literal, a quoted string,
// an entity reference, a `$name` hole, or one bare scalar/bareword token.
// Free prose refuses with quote guidance; glued continuations after a
// complete value refuse (they were the #917 silent-mangle lane).
fn (mut p Parser) parse_map_value() !Node {
	if p.at_end() {
		return error(p.make_error('expected map value'))
	}
	b := p.peek()
	if b == `{` {
		v := p.parse_map_literal()!
		p.refuse_glued_map_value_tail()!
		return v
	}
	if b == `(` {
		v := p.parse_sequence_literal()!
		p.refuse_glued_map_value_tail()!
		return v
	}
	if b == `[` {
		v := p.parse_bracket_node()!
		p.refuse_glued_map_value_tail()!
		return v
	}
	if b == `&` {
		v := p.parse_amp_node()!
		p.refuse_glued_map_value_tail()!
		return v
	}
	if b == `$` {
		if hole_len := p.peek_hole_len() {
			hname := p.src[p.pos + 1..p.pos + hole_len].bytestr()
			for _ in 0 .. hole_len {
				p.advance()
			}
			p.refuse_glued_map_value_tail()!
			return Node(HoleNode{ name: hname })
		}
	}
	if b == `r` && p.at_raw_triple() {
		s := p.read_raw_triple_str()!
		p.refuse_glued_map_value_tail()!
		return Node(TextNode{ value: s })
	}
	if b == `'` || b == `"` {
		mut n := Node(TextNode{})
		if p.pos + 3 <= p.src.len && p.src[p.pos] == `'` && p.src[p.pos + 1] == `'`
			&& p.src[p.pos + 2] == `'` {
			n = p.read_triple_quoted()!
		} else if p.pos + 3 <= p.src.len && p.src[p.pos] == `"` && p.src[p.pos + 1] == `"`
			&& p.src[p.pos + 2] == `"` {
			n = p.read_triple_double_quoted()!
		} else if b == `"` {
			quoted := p.read_quoted()!
			n = Node(ScalarNode{ data_type: .string_type, value: ScalarValue(quoted) })
		} else {
			quoted := p.read_quoted_text()!
			n = Node(ScalarNode{ data_type: .string_type, value: ScalarValue(quoted) })
		}
		// RULED: MSS-3 item 5: a quoted value takes no glued ascription —
		// the old slot path silently made `'5'::int` a two-item sequence.
		if !p.at_end() && p.peek() == `:` && p.pos + 1 < p.src.len && p.src[p.pos + 1] == `:` {
			return error(p.make_error('a quoted map value takes no type ascription — write the bare token (`5::int`) or keep the plain string (cx-err:CXER0100)'))
		}
		p.refuse_glued_map_value_tail()!
		return n
	}
	tok := p.read_slot_token()!
	// Postfix value ascription `v::T` (L43) — checked, all arms loud.
	if val, typ := try_split_postfix_ascription(tok) {
		sn := p.coerce_scalar_checked(typ, val)!
		p.refuse_glued_map_value_tail()!
		return Node(sn)
	}
	// RULED: MSS-3 item 4: a bare `::`-carrying token either ascribes or
	// refuses — it never silently becomes text (`5::bogus`, `std::vector`).
	if tok.contains('::') {
		return error(p.make_error('unknown or misplaced type ascription in `${tok}` — quote the value if it is text (cx-err:CXER0107 E_UNKNOWN_TYPE_TAG)'))
	}
	if scalar := try_autotype(tok) {
		p.refuse_glued_map_value_tail()!
		return Node(scalar)
	}
	// A single `:`-carrying bareword that is not an atom/date/datetime is
	// colon-bearing prose (`warning:`, `http://x`) — quote it (MSS-1).
	if tok.contains(':') {
		return error(p.make_error("a bare map value cannot carry `:` — quote it ('${tok}') (cx-err:CXER0100)"))
	}
	p.refuse_glued_map_value_tail()!
	return Node(TextNode{ value: tok })
}

// refuse_glued_map_value_tail enforces the MSS-1 boundary: after a complete
// map value the next byte must be a separator (`,`), the closer (`}`), or
// whitespace — glued continuations were the silent-mangle lane (#917).
fn (mut p Parser) refuse_glued_map_value_tail() ! {
	if p.at_end() {
		return
	}
	b := p.peek()
	if b == `,` || b == `}` || b == `]` || b == `)` || is_ws(b) {
		return
	}
	return error(p.make_error('a map value is one item — separate entries with `,` or whitespace, or quote prose (cx-err:CXER0100)'))
}

// read_map_key consumes a MapKey [56g] — a Name, QuotedText, or atomic
// Scalar. Returns the resolved key type + value. Bare-name keys carry
// type-tag `string` (names sugar for string keys).
fn (mut p Parser) read_map_key() !(ScalarType, ScalarValue) {
	if p.at_end() { return error(p.make_error('expected map key')) }
	b := p.peek()
	// RULED: MSS-1/MSS-2 (#917): a structured opener can never be a map
	// KEY — reaching one here means a ws-separated literal followed a
	// complete value ({m: 1 (2, 3)}). Refuse naming the two fixes, the
	// ASP-2 guidance carried into the map-entry read.
	if b == `(` || b == `{` || b == `[` {
		return error(p.make_error('a collection literal cannot open a map key — a map value fills its whole collection slot: make it ONE item (`{m: (1, (2, 3))}`) or separate entries with `,` (cx-err:CXER0100)'))
	}
	if b == `'` || b == `"` {
		// RULED: MSS-3 item 7 (#917): both quote forms are QuotedText [L87]
		// — the data reader used to refuse `{"k": 1}` while the program
		// reader accepted it.
		s := if b == `"` { p.read_quoted()! } else { p.read_quoted_text()! }
		// RULED: MSS-3 item 5: a glued `::` after a quoted key is the key's
		// own ascription, same rules as a bare key (identity is (kind,
		// image)) — the old path silently mangled `{'k'::int: 5}` into
		// `{k: ':int: 5'}`.
		if !p.at_end() && p.peek() == `:` && p.pos + 1 < p.src.len && p.src[p.pos + 1] == `:` {
			p.advance()
			p.advance()
			tag := p.read_kind_tag()!
			if !is_valid_type_tag(tag) {
				return error(p.make_error('unknown type tag `::${tag}` on map key (cx-err:CXER0107 E_UNKNOWN_TYPE_TAG)'))
			}
			sn := p.coerce_scalar_checked(tag, s)!
			if sn.data_type !in [.int_type, .float_type, .string_type, .bool_type, .date_type,
				.datetime_type, .bytes_type, .decimal_type, .bigint_type] {
				return error(p.make_error('${scalar_type_name(sn.data_type)} is not a valid map key (cx-err:CXERMAP-BADKEY)'))
			}
			return sn.data_type, sn.value
		}
		return ScalarType.string_type, ScalarValue(s)
	}
	mut s := []u8{}
	for !p.at_end() {
		b2 := p.peek()
		if b2 == `:` {
			// I1 stream 11 (L43/L47): a glued `::` is the key's postfix
			// type ascription (`{1.10::decimal: x}`) and stays in the key
			// token; a single `:` ends the key as before.
			if p.pos + 1 < p.src.len && p.src[p.pos + 1] == `:` {
				s << `:`
				s << `:`
				p.advance()
				p.advance()
				continue
			}
			break
		}
		if b2 == `,` || b2 == `}` || is_ws(b2) { break }
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
	// I1 stream 11 (L47): ascribed keys — decimal and bigint are admitted
	// (total order + canonical form); atoms, null, and the temporal spans
	// stay barred (cxdm §5.5 / data-bin D004).
	if val, typ := try_split_postfix_ascription(tok) {
		sn := coerce_scalar_strict(typ, val) or {
			// The commonest slip is meaning a TYPED FIELD ({age::int: 30})
			// — a key ascription types the KEY, so teach all three forms
			// rather than reporting the coercion alone (#917 UX, playground
			// report 2026-08-22).
			return error(p.make_error('${err.msg()} — a key ascription types the KEY (`{1.10::decimal: x}`); to type this field\'s VALUE write `${val}: ::${typ} 30` (or `${val}: 30::${typ}`), to declare it valueless write `${val}: ::${typ}`'))
		}
		if sn.data_type !in [.int_type, .float_type, .string_type, .bool_type, .date_type,
			.datetime_type, .bytes_type, .decimal_type, .bigint_type] {
			return error(p.make_error('${scalar_type_name(sn.data_type)} is not a valid map key (cx-err:CXERMAP-BADKEY)'))
		}
		return sn.data_type, sn.value
	}
	// RULED: MSS-3 item 4 (#917): a `::`-carrying key token either ascribes
	// or refuses — it never silently becomes a string key.
	if tok.contains('::') {
		return error(p.make_error('unknown or misplaced type ascription in map key `${tok}` — quote the key if it is text (cx-err:CXER0107 E_UNKNOWN_TYPE_TAG)'))
	}
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
	// RULED: ASP-2 (#903) — set when a sequence/map literal opens the slot
	// as its sole content so far: whitespace-separated content after it
	// refuses (a literal fills its slot; glued continuations stay mixed,
	// which the CXPath kind-test idiom `$c/node()` depends on).
	mut saw_ws_literal := false
	for {
		if p.at_end() { break }
		had_ws := is_ws(p.peek())
		p.skip_ws_and_line_comments()
		if p.at_end() { break }
		b := p.peek()
		if b == `,` || b == `]` || b == `)` || b == `}` { break }
		if saw_ws_literal && had_ws {
			return error(p.make_error('whitespace-separated content after a sequence or map literal in one collection slot — separate items with `,`, or quote prose (cx-err:CXER0100)'))
		}
		saw_ws_literal = false

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

		// I1 row 9 (L78): the variable hole in collection-item / slot-body
		// position — same rule as the element body (`($x, 2)` carries a
		// hole item; `('$x', 2)` a string item).
		if b == `$` {
			if hole_len := p.peek_hole_len() {
				if text_buf.len > 0 {
					items << TextNode{ value: text_buf.bytestr() }
					text_buf = []u8{}
				}
				hname := p.src[p.pos + 1..p.pos + hole_len].bytestr()
				for _ in 0 .. hole_len {
					p.advance()
				}
				items << HoleNode{ name: hname }
				continue
			}
		}
		if b == `r` && p.at_raw_triple() {
			// RAW triple-quoted string (I1 L58) in collection-item /
			// slot-body position — verbatim body, no dedent.
			if had_ws && text_buf.len > 0 { text_buf << ` ` }
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			s := p.read_raw_triple_str()!
			items << Node(TextNode{ value: s })
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
				// #790 (RULED: 1a, the #795 batch): a QUOTED item in a
				// collection slot is a string SCALAR — the code parser
				// has always typed it so, while this lane made it Text
				// whose canonical render dropped the quotes (`("a", 2)`
				// → `(a, 2)`), colliding with the genuinely-bare Text
				// spelling at one Tier-1 address across two kinds. Bare
				// tokens stay Text.
				quoted := p.read_quoted()!
				items << ScalarNode{ data_type: .string_type, value: ScalarValue(quoted) }
			} else {
				quoted := p.read_quoted_text()!
				items << ScalarNode{ data_type: .string_type, value: ScalarValue(quoted) }
			}
			// #934 (MSS-3 item 5 parity): a quoted value followed by a glued
			// `::` REFUSES in array/sequence slots exactly as it does in
			// map-value position — the old path silently split `['x'::int]`
			// into a nested two-item sequence (the string plus the ascription
			// as TEXT) at rc=0.
			if !p.at_end() && p.peek() == `:` && p.pos + 1 < p.src.len && p.src[p.pos + 1] == `:` {
				return error(p.make_error('a quoted collection item takes no type ascription — write the bare token (`5::int`) or keep the plain string (cx-err:CXER0100)'))
			}
			after_non_text = true
			continue
		}

		if b == `(` && (p.peek_is_sequence_literal_at_paren()
			|| (items.len == 0 && text_buf.len == 0 && p.peek_lone_paren_group_fills_slot())
) {
			// #810 RULED (a): in a collection SLOT (map value / array or
			// sequence item) a lone paren group that fills the whole slot is
			// a SEQUENCE LITERAL even without a comma — a slot has no prose
			// lane, so the body-text comma disambiguator does not apply here.
			// Completes the #587 fidelity invariant in its last position:
			// the canonical singleton emission `(x)` now re-parses to the
			// singleton sequence it came from. Zero canonical bytes move.
			// RULED: ASP-2 (#903) — a WHITESPACE-SEPARATED sequence literal
			// after other slot content refuses loudly instead of silently
			// gluing into a nested sequence that mangled the leading value
			// per type (int 1 → the string '1 '). GLUED runs stay one item —
			// CXPath kind tests (`$c/node()`, fmt-013) and call shapes live
			// mid-slot glued and must keep parsing byte-identically.
			if had_ws && (items.len > 0 || text_buf.len > 0) {
				return error(p.make_error('a whitespace-separated sequence literal cannot join other content in one collection slot — separate items with `,` (write `[1, (2, 3)]`), or quote prose (cx-err:CXER0100)'))
			}
			if had_ws && text_buf.len > 0 { text_buf << ` ` }
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			items << p.parse_sequence_literal()!
			after_non_text = true
			saw_ws_literal = items.len == 1 && text_buf.len == 0
			continue
		}

		if b == `{` && p.peek_is_map_literal_at_brace() {
			// ASP-2 (#903): same whitespace-adjacency rule for map literals.
			if had_ws && (items.len > 0 || text_buf.len > 0) {
				return error(p.make_error('a whitespace-separated map literal cannot join other content in one collection slot — separate items with `,` (write `[1, {a: 1}]`), or quote prose (cx-err:CXER0100)'))
			}
			if had_ws && text_buf.len > 0 { text_buf << ` ` }
			if text_buf.len > 0 {
				items << TextNode{ value: text_buf.bytestr() }
				text_buf = []u8{}
			}
			items << p.parse_map_literal()!
			after_non_text = true
			saw_ws_literal = items.len == 1 && text_buf.len == 0
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
		// RULED: MSS-7 (#917): a slot-INITIAL `::T` commits the slot to one
		// prefixed scalar value (`[1, ::int 30]`), same rule as map values.
		// A valueless `::T` in an array/sequence slot stays a refusal
		// (declarations are map-entry-only, MSS-4).
		if items.len == 0 && text_buf.len == 0 && !has_child && tok.starts_with('::')
			&& tok.len > 2 && !tok[2..].contains(':') {
			ptag := tok[2..]
			if is_valid_type_tag(ptag) {
				items << Node(p.read_prefixed_value(ptag)!)
				return items
			}
			if is_valid_kind_tag(ptag) {
				return error(p.make_error('kind `${ptag}` declares only, and declarations are map-entry-only — an array/sequence slot needs a value (`::int 30`) (cx-err:CXER0290)'))
			}
			return error(p.make_error('unknown type tag `${tok}` opening a collection slot (cx-err:CXER0107 E_UNKNOWN_TYPE_TAG)'))
		}
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
		// eval time per code.md).
		if !has_child && items.len == 0 {
			// RULED: MSS-3 item 2 (#917): the ascription split applies to a
			// single ws-free token ONLY — the old last-`::` split over a
			// coalesced prose run invented values (':ref compact ::bool' →
			// bool false at rc=0).
			if !text_val.contains(' ') {
				// I1 stream 11 (L43): postfix value ascription `value::T` in
				// collection positions — `[1::int, 2.5::decimal]`. A valid
				// type tag makes this an ascription; its payload must conform
				// (loud CXER0290), it never falls back to text.
				if val, typ := try_split_postfix_ascription(text_val) {
					items << p.coerce_scalar_checked(typ, val)!
					return items
				}
				// RULED: MSS-3 item 4: a bare `::`-carrying token either
				// ascribes or refuses — never silently text ('5::bogus',
				// 'std::vector').
				if text_val.contains('::') {
					return error(p.make_error('unknown or misplaced type ascription in `${text_val}` — quote the value if it is text (cx-err:CXER0107 E_UNKNOWN_TYPE_TAG)'))
				}
				if scalar := try_autotype(text_val) {
					items << scalar
					return items
				}
			} else if text_val.contains('::') {
				// A prose run carrying a `::` token is the invention lane —
				// refuse with quote guidance rather than keeping text that a
				// re-parse would try to ascribe (MSS-3 items 2+4).
				return error(p.make_error("prose containing `::` in a collection slot must be quoted ('${text_val}') (cx-err:CXER0100)"))
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


// reserved_prefix_refusal returns the E210 refusal message for an element
// name in the reserved `cx:` namespace, or none when the name is fine.
//
// THE ONE AUTHORITY for the reservation, read by BOTH readers (#820). It
// used to live inline in this data-mode parser only, so the PROGRAM
// reader happily constructed `[cx:x 1]` — and the resulting document
// could not be read back by the data reader that had just refused to
// parse it. "Output fails its own re-parse", the #704 class, through a
// door next to the wall.
//
// E210 is reused on both sides deliberately (RULED: 820-1a) rather than
// minting a program-band code: it is ONE reservation, and two codes would
// teach a reader that authoring `cx:foo` is two different mistakes
// depending on which reader saw it first.
//
// Scope is the `cx:` prefix on an ELEMENT NAME. Neither reader reserves
// `xml:`, and neither reserves either prefix on an ATTRIBUTE name — those
// are not asymmetries to close but reservations that do not exist, and
// creating one is a ruling, not an implementation detail.
pub fn reserved_prefix_refusal(raw_name string) ?string {
	if raw_name.count(':') != 1 {
		return none
	}
	if raw_name.all_before(':') != 'cx' {
		return none
	}
	return 'reserved namespace prefix `cx:` in `${raw_name}` — the `cx:` prefix is reserved for the serializer and may not be authored (cx-err:E210)'
}
