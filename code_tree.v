module cx

// ── Phase 2.11 — cx_code_tree real walker ──────────────
//
// Produces the JSON contract for the playground's Tree View per
// `spec/core/ast.md`.
// Every emitted node carries `{kind, name?, value?, loc:{start,end},
// children?}`; `loc` byte offsets are into the original UTF-8 source
// and enable the bidirectional selection bridge between tree
// pane and source pane without further ABI plumbing.
//
// This file lives in `vcx/cx/` (sibling to cabi.v) rather than
// `vcx/code/` so the C ABI export composes against the host data
// model without re-opening the import cycle that drove other code-
// surface exports into `vcx/code/`. The walker therefore avoids the
// program-AST (`code.Program`) entirely — it scans the source text
// directly, tracking byte offsets as it goes. This matches the
// gate-17 §D11 "playground-input ceiling" budget (~64 KB) and keeps
// the tree walker independent of the (still-evolving) program parser.
//
// Per-kind shape (§D2 table):
//   - element   {kind:"element",   name, loc, children?}
//   - attribute {kind:"attribute", name, value, loc}
//   - text      {kind:"text",      value, loc}
//   - directive {kind:"directive", name, loc, children?}
//   - scalar    {kind:"scalar",    value, loc}
//   - path      {kind:"path",      value, loc}
//
// `value` is JSON-typed: integers emit as JSON numbers, floats as
// JSON numbers, booleans as `true`/`false`, atoms/strings as JSON
// strings (atoms keep the leading `:` to mark the scalar kind).
//
// Top-level wrapping rule: a single top-level statement returns its
// own node verbatim (per tree-001/006 fixtures). Multiple top-level
// statements wrap in a synthetic root element spanning the source.
// Empty or whitespace-only sources return an empty root with
// `loc:{start:0,end:0}`.
//
// Sequence literals (#1000): a `(a, b, c)` literal contributes its ITEMS to
// the enclosing children list; the `(`, `,` and `)` are syntax and are not
// emitted. That is the value the source denotes — a sequence in top-level or
// element-body position flattens into the enclosing sequence (CXDM §1) — and
// it is the only shape available, since the `kind` vocabulary above is closed
// by the D2 contract (`core/abi.md` §2.16.3). See `parse_item_run`.
//
// Array and map literals (#1020, #1025): `[1, 2, 3]`, `[true false]` and
// `{k: v}` each contribute ONE node — a `scalar` whose value is the literal's
// IMAGE (the authored bytes) and whose `loc` spans it. They do NOT flatten the
// way a sequence does: an Array and a Map are container Items that preserve
// structure (CXDM §2.5 / §2.6), so each is one item in the enclosing sequence.
// BOTH of the dispatch's array-yielding productions reach that projection — the
// [D1] comma rule and the §9 whitespace typed list. See
// `parse_array_literal_image` for the full derivation and for the shapes
// deliberately left alone.
//
// Element bodies (#1029): the body takes one of THREE lanes, chosen with the
// parser's own predicates at the position the element's meta/attribute run ends
// — the [L25c] comma array and the §9 typed list contribute one node per ITEM,
// and everything else is the PROSE lane, where a maximal run of bare tokens is
// ONE `text` node whose `loc` spans it. See `parse_element_head` and
// `parse_prose_body`.
//
// Top-level prose (#1040): the same arity contract in the OTHER position, under
// a DIFFERENT rule. `read_top_text_run`'s run is VERBATIM — it stops only at
// `[`, `&`, a depth-0 `]`, a line-start `---` and EOF — so a top-level run is
// ONE `text` node carrying the authored bytes, separator whitespace included,
// where the walker used to emit one node per token. A doc-top run that is a
// single whitespace-free auto-typing token is that scalar instead (@CHOICE-1,
// the rule tree-005 pins). See `top_text_run_end` and `parse_top_text_run`.

// code_tree is the public entry point. Returns the JSON tree as a
// UTF-8 string. Never raises — malformed sources degrade to the most
// specific tree shape the scanner can recover (typically a single
// `scalar`-or-`element`-stub spanning the input).
pub fn code_tree(source string) !string {
	bs := source.bytes()
	mut p := TreeParser{ src: bs, pos: 0 }
	p.skip_ws()
	if p.pos >= bs.len {
		// Empty / whitespace-only: empty root element at [0,0).
		return '{"kind":"element","name":"root","loc":{"start":0,"end":0},"children":[]}'
	}
	mut nodes := []TreeNode{}
	// Document-LEADING trivia is not part of any run (the parser's prolog loop
	// consumes it before the doc-top dispatch is asked).
	p.skip_top_trivia()
	for p.pos < bs.len {
		// The bytes between the previous node and this one. In mixed-text mode
		// the parser's run STARTS here — the separator is IN the Text value —
		// so the run below claims them, unless a comment was erased out of them
		// (#469: erased trivia contributes no join space of its own).
		sep_start := p.pos
		erased := p.skip_top_trivia()
		if p.pos >= bs.len { break }
		// Skip stray `]` (defensive — should never happen at top level
		// with well-formed source). Treat as benign separator.
		if bs[p.pos] == `]` { p.pos++; continue }
		// A `---` at line start is the multi-document separator: the parser
		// ENDS the document there and starts another. This walker projects ONE
		// tree, so it consumes the separator and keeps walking — which also
		// keeps the three `-` bytes out of `parse_number_scalar`, whose
		// one-byte recovery emitted `"value":-` and made the whole projection
		// invalid JSON.
		if p.at_doc_separator() { p.skip_doc_separator(); continue }
		if p.top_is_item_start() {
			saved := p.pos
			run := p.parse_item_run() or { break }
			if p.pos == saved { p.pos++; continue }
			for n in run { nodes << n }
			continue
		}
		val_start := if nodes.len > 0 && !erased { sep_start } else { p.pos }
		if r := p.parse_top_text_run(val_start, nodes.len == 0) {
			nodes << r
			continue
		}
		if p.pos == sep_start { p.pos++ }
	}
	if nodes.len == 0 {
		return '{"kind":"element","name":"root","loc":{"start":0,"end":${bs.len}},"children":[]}'
	}
	if nodes.len == 1 {
		return render_node(nodes[0])
	}
	// Multiple top-level statements — wrap in a synthetic root.
	root := TreeNode{
		kind:         'element'
		name:         'root'
		loc_start:    0
		loc_end:      bs.len
		children:     nodes
		has_children: true
	}
	return render_node(root)
}

// TreeNode is the in-memory representation of one node.
// All optional fields are encoded by presence — empty `name` / empty
// `value` strings flag absence per the JSON emit-time skip.
struct TreeNode {
mut:
	kind      string
	name      string
	// value_kind discriminates the scalar payload:
	//   - 'string'  → emit as JSON string (use value_str)
	//   - 'atom'    → emit as JSON string ":NAME" (use value_str)
	//   - 'int'     → emit as JSON number (use value_str verbatim)
	//   - 'float'   → emit as JSON number (use value_str verbatim)
	//   - 'bool'    → emit as JSON true/false (use value_str = "true"/"false")
	//   - ''        → no value
	value_kind string
	value_str  string
	loc_start  int
	loc_end    int
	children   []TreeNode
	has_children bool // distinguish explicit empty children list from absent
}

// ── Scanner ──────────────────────────────────────────────────────────

struct TreeParser {
mut:
	src []u8
	pos int
	// prose_trivia records that `parse_prose_run` erased comment trivia while
	// producing NO text node. Trivia occupies `items` in the parser, so it
	// blocks the sole-item auto-type (#1029) whether or not a run came with it.
	prose_trivia bool
}

fn (mut p TreeParser) skip_ws() {
	for p.pos < p.src.len {
		c := p.src[p.pos]
		if c == ` ` || c == `\t` || c == `\n` || c == `\r` { p.pos++; continue }
		// Skip line comments `# ... \n` only when at line start (best
		// effort — the tree view does not surface comments as nodes).
		break
	}
}

// skip_top_trivia consumes whitespace AND `#` line comments at a top-level
// COMMENT-ELIGIBLE position (grammar [30b]: document top level, between root
// nodes), returning whether a comment was erased.
//
// The eligibility is what makes the two `#` readings agree with the parser: a
// `#` HERE — before a run starts — is a comment (the parser's
// `skip_ws_collecting_comments` takes it as a prolog / sibling CommentNode),
// while a `#` reached once a run is under way is ordinary content, because
// `top_text_run_end` is verbatim (`hello world # note` is ONE Text ending in
// `# note`). The walker cannot PROJECT the comment — the D2 `kind` vocabulary
// is closed at element / attribute / text / directive / scalar / path
// (`core/abi.md` §2.16.3) — so it erases it, the same disposition
// `parse_prose_run` gives `[; … ]` trivia inside a body run (#469).
fn (mut p TreeParser) skip_top_trivia() bool {
	mut erased := false
	for p.pos < p.src.len {
		c := p.src[p.pos]
		if c == ` ` || c == `\t` || c == `\n` || c == `\r` { p.pos++; continue }
		if c == `#` {
			erased = true
			p.pos++
			for p.pos < p.src.len && p.src[p.pos] != `\n` { p.pos++ }
			continue
		}
		break
	}
	return erased
}

// at_doc_separator reports whether p.pos stands on a `---` document separator
// at line start — `top_text_run_end`'s `-` terminator, asked from the other
// side so the caller can consume it.
fn (p &TreeParser) at_doc_separator() bool {
	if p.pos + 3 > p.src.len { return false }
	if !(p.pos == 0 || p.src[p.pos - 1] == `\n`) { return false }
	return p.src[p.pos] == `-` && p.src[p.pos + 1] == `-` && p.src[p.pos + 2] == `-`
}

// skip_doc_separator consumes the `---` line.
fn (mut p TreeParser) skip_doc_separator() {
	for p.pos < p.src.len && p.src[p.pos] != `\n` { p.pos++ }
	if p.pos < p.src.len { p.pos++ }
}

// top_is_item_start reports whether the byte at p.pos opens a top-level ITEM
// rather than a text run — the walker's doc-top dispatch.
//
// It mirrors `parse_document`'s own doc-top dispatch (a `{` that
// `map_literal_at_brace` rules a Map, a `(` that `sequence_literal_at_paren`
// rules a Sequence, a quote / triple-quote opening a scalar, and `[` / `&`
// node-start bytes), plus the walker's TWO named contract kinds that the data
// parser reads as ordinary text:
//
//   - a `/`-led token is a `path` — a D2 kind the data AST has no node for at
//     all, projected because this walker serves CODE sources too and pinned in
//     THIS position by the tree-006 conformance fixture. The same named
//     exception #1029 made in body position. Residual, measured:
//     `/users/user more words` is a path + a run here and ONE Text there.
//   - a `$name` stays the `scalar "$name"` #1029 left alone beside the
//     parser's Hole. The kind question is its own; swallowing the token into a
//     run would answer it by accident.
//
// Unlike the parser, the walker applies this dispatch at EVERY top-level
// position, not only at doc-top. After a node the parser is in strict mode and
// simply RAISES on a non-bracket byte (`[x 1] {a: 1}` → "expected node"), so
// there is no reading to match; keeping the container kinds there is #1020's
// projection, and retiring them would be a contract change.
fn (p &TreeParser) top_is_item_start() bool {
	if p.pos >= p.src.len { return false }
	c := p.src[p.pos]
	if c == `[` || c == `&` || c == `/` || c == `$` { return true }
	if c == `{` { return map_literal_at_brace(p.src, p.pos) }
	if c == `(` { return sequence_literal_at_paren(p.src, p.pos) }
	if triple_quote_prefix_len(p.src, p.pos) >= 0 { return true }
	return c == `'` || c == `"`
}

fn is_ident_byte_tree(b u8) bool {
	return (b >= `a` && b <= `z`) || (b >= `A` && b <= `Z`)
	       || (b >= `0` && b <= `9`) || b == `_` || b == `-`
}

fn is_name_start_tree(b u8) bool {
	return (b >= `a` && b <= `z`) || (b >= `A` && b <= `Z`) || b == `_`
}

// parse_item reads the next top-level / sibling-level item. Returns
// the parsed node or `none` if no item can be recovered (caller
// should break out of its accumulation loop).
fn (mut p TreeParser) parse_item() !TreeNode {
	p.skip_ws()
	if p.pos >= p.src.len { return error('eof') }
	c := p.src[p.pos]
	if c == `[` {
		return p.parse_bracket()!
	}
	// MAP LITERAL (#1020). A Map is a container Item (CXDM §2.6) and, like the
	// Array above, contributes exactly ONE node. `map_literal_at_brace`
	// (cx/lexical.v) is the parser's own delimitation rule, so a brace-delimited
	// TEXT run (`{text}`, no depth-0 `:`) is deliberately left on the
	// unrecognized-byte path it has always taken.
	if c == `{` && map_literal_at_brace(p.src, p.pos) {
		return p.parse_map_literal_image()
	}
	if c == `/` {
		return p.parse_path()
	}
	// A TRIPLE-quoted literal (`'''…'''`, `"""…"""`, or either raw form) is one
	// text node, checked before the single-delimiter arm below and before the
	// bare-identifier arm that would otherwise read the raw form's `r` as a
	// one-letter scalar (#999).
	if triple_quote_prefix_len(p.src, p.pos) >= 0 {
		return p.parse_triple_quoted_text()
	}
	if c == `'` || c == `"` {
		return p.parse_text_or_string()
	}
	if c == `:` && p.pos + 1 < p.src.len && is_name_start_tree(p.src[p.pos+1]) {
		// Bare atom (`:name`) — emit as scalar with atom value.
		return p.parse_atom_scalar()
	}
	if c == `$` {
		// Binding reference — treat as scalar with string value
		// `$name…` (preserves the source token verbatim).
		return p.parse_binding_scalar()
	}
	if c == `-` || c == `+` || (c >= `0` && c <= `9`) {
		return p.parse_number_scalar()
	}
	if is_name_start_tree(c) {
		// Bare identifier — could be a boolean literal, a keyword,
		// or a bare call name. Emit as scalar with string value.
		return p.parse_ident_scalar()
	}
	// Unrecognized byte: skip it to make progress; surface as 1-byte
	// scalar so downstream consumers can see something occurred.
	start := p.pos
	p.pos++
	return TreeNode{
		kind:       'scalar'
		value_kind: 'string'
		value_str:  unsafe { tos(&p.src[start], 1) }.clone()
		loc_start:  start
		loc_end:    p.pos
	}
}

// parse_bracket dispatches `[...]` shapes:
//   - `[?name …]`  → directive
//   - `[?=expr]`   → directive (interpolation; named `interp`)
//   - `[?cx …]`    → directive (PI)
//   - `[name …]`   → element
fn (mut p TreeParser) parse_bracket() !TreeNode {
	start := p.pos
	if p.src[p.pos] != `[` { return error('not a bracket') }
	end := find_matching_bracket(p.src, start)
	if end < 0 {
		// Unbalanced — recover by spanning to end of source.
		p.pos = p.src.len
		return TreeNode{
			kind:      'element'
			name:      'unbalanced'
			loc_start: start
			loc_end:   p.src.len
		}
	}
	// ARRAY LITERAL (#1020, #1025). Asked before every element / directive
	// reading below, exactly where `parse_bracket_node` asks it and in ITS
	// order — both array-yielding productions, both through the shared
	// cursor-free predicates on the `cx/lexical.v` shelf.
	//
	// ONE node, not a flatten. An Array is a CONTAINER Item that does not
	// flatten (CXDM §2.5): `(arr)` is a one-item Sequence holding one Array,
	// DISTINCT from that Array's items. So #1000's sequence-flatten reading does
	// not carry here — flattening would report `[doc [1, 2, 3] x]` as four
	// children where the document has two items, and would collapse
	// `[[1,2],[3,4]]` to four scalars where CXDM says a 2-item Array of 2-item
	// Arrays. See `parse_array_literal_image` for why the one node is a `scalar`
	// carrying the literal's image.
	//
	// FIRST the §9 [L25a/b] WHITESPACE TYPED LIST (`typed_list_body_at`,
	// @CHOICE-1 / G-ARRAY-1) — the dispatch tests it ahead of the [D1]
	// first-item rule, and where the two disagree the typed list wins, so
	// asking in the other order would give the parser's LOSING answer.
	// `headless: true` is this position: a bracket with no element head, where
	// ASP-2 (#903) keeps the element reading for a name-shaped first token
	// followed by a structure (`[true (2, 3)]`). The `bracket_head_is_reserved`
	// guard is the dispatch's own — it stands in for the `?`/sigil precedence
	// and the `[table[` refusal (#484) that run ahead of this test there.
	//
	// #1025: this is what the walker could not ask while the classifier was a
	// `&Parser` method reading its own `pos`. `[true false]` — name-shaped
	// first token, no comma, so the [D1] rule alone says "element" — is an
	// ArrayNode to the parser and was the element `true` with one child here.
	if !bracket_head_is_reserved(p.src, start + 1)
		&& typed_list_body_at(p.src, start + 1, true) {
		return p.parse_array_literal_image(start, end)
	}
	// THEN the [D1] first-item rule. `array_literal_at_bracket` (cx/lexical.v)
	// already refuses the reserved sigils itself, so `[?…]`, `[; …]`, `[! …]`,
	// `[| …]` and `[# …]` reach their own arms untouched.
	if array_literal_at_bracket(p.src, start) {
		return p.parse_array_literal_image(start, end)
	}
	// Inspect after `[` for directive marker.
	mut inner_pos := start + 1
	if inner_pos < end && p.src[inner_pos] == `?` {
		// Directive form `[?name …]` (or `[?=expr]`).
		inner_pos++
		mut name_start := inner_pos
		mut name := ''
		if inner_pos < end && p.src[inner_pos] == `=` {
			name = 'interp'
			inner_pos++
		} else {
			for inner_pos < end && is_ident_byte_tree(p.src[inner_pos]) {
				inner_pos++
			}
			name = unsafe { tos(&p.src[name_start], inner_pos - name_start) }.clone()
		}
		// Descend into the directive body. Per grammar [59] the body uses
		// the same item grammar as element bodies — clause-child elements
		// (`[in $x S]`, `[yield E]`, `[= $x v]`, `[then …]`/`[else …]`),
		// `name=value` attributes, nested brackets, text, scalars, paths,
		// bindings, and `:NAME` atoms. Clause / attribute / bareword
		// interpretation is the program-AST layer's job ([127]), not the
		// data walker's, so this mirrors the element children-loop below.
		p.pos = inner_pos
		mut dchildren := []TreeNode{}
		for {
			p.skip_ws()
			if p.pos >= end { break }
			dc := p.src[p.pos]
			if dc == `]` { break }
			// `:NAME` is an atom literal (grammar.ebnf:319), not a colon
			// attribute — it falls through to parse_item → parse_atom_scalar.
			if is_name_start_tree(dc) && p.has_eq_attr_ahead(end) {
				if attr := p.parse_attribute_eq_form_in_element(end) {
					dchildren << attr
				} else {
					p.pos++
				}
				continue
			}
			saved := p.pos
			run := p.parse_item_run() or { break }
			if p.pos == saved { p.pos++; continue }
			for child in run { dchildren << child }
		}
		p.pos = end + 1
		mut dnode := TreeNode{
			kind:      'directive'
			name:      name
			loc_start: start
			loc_end:   end + 1
		}
		if dchildren.len > 0 {
			dnode.children = dchildren
			dnode.has_children = true
		}
		return dnode
	}
	// Element form `[name …]`. Parse name + attributes + body.
	p.pos = start + 1
	p.skip_ws()
	name_start := p.pos
	for p.pos < end && (is_ident_byte_tree(p.src[p.pos]) || p.src[p.pos] == `:`) {
		// Allow `prefix:local` element names.
		p.pos++
	}
	mut name := unsafe { tos(&p.src[name_start], p.pos - name_start) }.clone()
	if name == '' {
		// OPERATOR-HEADED ELEMENT (#976, #992). `=`, `>=`, `!=`, `+` and the
		// rest of the ruled 18 heads are first-class element NAMES — twelve
		// of them are GLYPHS, which the Name production above cannot spell,
		// so this walker fell straight through to the anonymous `_` case.
		// That lost BOTH halves of the node: the head AND, because the `_`
		// arm skips to `end + 1`, every operand. So `[= $score 87]` reached
		// the playground's Tree and instance Graph as a childless box named
		// `_` — nothing to read, and nothing downstream could rebuild the
		// label either, because the arguments were never emitted at all.
		//
		// `operator_head_len` is the single home of the alphabet and of the
		// delimitation rule (#976): a head counts only when the next byte is
		// whitespace, `]`, or end-of-input — so `[-1, 2]` stays a negative
		// number in an array and `[*n]` stays an alias reference. Six of the
		// eighteen (`and or not union intersect except`) are ordinary Names
		// and already arrive through the loop above.
		//
		// `_` survives for what it actually means: a genuinely nameless shape.
		op_len := operator_head_len(p.src, name_start)
		if op_len > 0 && name_start + op_len <= end {
			name = unsafe { tos(&p.src[name_start], op_len) }.clone()
			p.pos = name_start + op_len
		}
	}
	if name == '' {
		// Anonymous element — treat as `_`.
		p.pos = end + 1
		return TreeNode{
			kind:      'element'
			name:      '_'
			loc_start: start
			loc_end:   end + 1
		}
	}
	// ── The element HEAD ZONE, then the BODY DISPATCH (#1029) ────────────
	// The parser reads an element in two phases and the body's SHAPE is
	// decided at the position where the first phase ENDS: `parse_bracket_node`
	// runs the ElementMeta + attribute loop, then asks which of THREE lanes
	// the remaining body takes. The walker ran one loop that took attributes
	// and body items in any order, so it asked the body question nowhere and
	// at the wrong position — see `parse_element_head` and `parse_prose_body`.
	mut children := []TreeNode{}
	p.parse_element_head(end, mut children)
	p.skip_ws()
	body_start := p.pos
	// LANE 1 — §9 [L25c] comma array (`flat_comma_array_body_at`); LANE 2 —
	// §9 [L25a/b] whitespace typed list (`typed_list_body_at`, headless:false
	// because this IS the element-body position). Both contribute one node per
	// ITEM, which is what the walker's item loop already produces. Anything
	// else is LANE 3, the PROSE lane, where a maximal run of bare tokens is
	// ONE Text item to the parser.
	if flat_comma_array_body_at(p.src, body_start)
		|| typed_list_body_at(p.src, body_start, false) {
		p.parse_body_items(end, mut children)
	} else {
		p.parse_prose_body(end, mut children)
	}
	p.pos = end + 1
	mut node := TreeNode{
		kind:      'element'
		name:      name
		loc_start: start
		loc_end:   end + 1
	}
	if children.len > 0 {
		node.children = children
		node.has_children = true
	}
	return node
}

// parse_element_head consumes the ElementMeta + attribute PREFIX of an element
// and appends one `attribute` node per `name=value` it finds, leaving the cursor
// on the first byte of the BODY. `end` is the enclosing `]` index.
//
// WHY A PREFIX AND NOT A LOOP (#1029). The walker used to take attributes and
// body items in any order, one interleaved loop. That is not the element's
// shape: the parser's meta/attribute run ENDS at the first body item and never
// resumes, so `[doc hello world x=1]` is ONE Text item `"hello world x=1"` — the
// `x=1` is prose, because the attribute run already ended at `hello` — while
// `[doc x=1 hello world]` next door is the attribute plus Text `"hello world"`.
// The walker read an attribute in both. It also has to end HERE for the body
// dispatch to be asked at the parser's position: `[doc *ref 1 2]` is a merge
// marker plus a two-item TYPED LIST, and a dispatch asked before the marker sees
// a bareword and reads prose.
//
// The meta sigils are CONSUMED, not projected. `*name` (merge), `&name`
// (anchor), `#name` (ID) and the `[; … ]` / `# …` comment trivia have no `kind`
// in the D2 vocabulary — closed at element / attribute / text / directive /
// scalar / path (`core/abi.md` §2.16.3) — so a walker cannot emit them without a
// contract change. Skipping them is strictly better than what they did before,
// which was to arrive as a one-byte junk scalar plus a stray bareword.
fn (mut p TreeParser) parse_element_head(end int, mut children []TreeNode) {
	for {
		p.skip_ws()
		if p.pos >= end { return }
		c := p.src[p.pos]
		k := token_kind_at(p.src, p.pos)
		// `[; … ]` in the meta run is trivia and does NOT end it (#455):
		// `[config [; c ] env=dev]` means exactly `[config env=dev]`.
		if k == .lbrack && p.pos + 1 < end && p.src[p.pos + 1] == `;` {
			close := find_matching_bracket(p.src, p.pos)
			p.pos = if close < 0 || close >= end { end } else { close + 1 }
			continue
		}
		if k == .hash {
			// `# …` is a line comment even in meta position; `#name` is the
			// syntactic ID declaration. Disambiguation is pure lookahead.
			p.pos++
			if p.pos < end && is_ws(p.src[p.pos]) {
				for p.pos < end && p.src[p.pos] != `\n` { p.pos++ }
				continue
			}
			if p.skip_meta_name(end) { continue }
			p.pos-- // no name followed — rewind and start the body
			return
		}
		if k == .amp || k == .star {
			saved := p.pos
			p.pos++
			if p.skip_meta_name(end) {
				// `&name` is an anchor DEFINITION; `&name;` is an entity ref,
				// which is a body item and ends the meta run.
				if k == .amp && p.pos < end && p.src[p.pos] == `;` {
					p.pos = saved
					return
				}
				continue
			}
			p.pos = saved
			return
		}
		// `name=VALUE`. A `:NAME` is an atom literal (grammar.ebnf:319), not a
		// colon attribute, and a bare identifier is a body item — both end the
		// run and are read by the body lanes below.
		if is_name_start_tree(c) && p.has_eq_attr_ahead(end) {
			if attr := p.parse_attribute_eq_form_in_element(end) {
				children << attr
				continue
			}
			return
		}
		return
	}
}

// skip_meta_name consumes an identifier run at p.pos, reporting whether one was
// there. The meta sigils above are `sigil + Name`; a sigil with no name is not a
// meta declaration and the caller rewinds.
fn (mut p TreeParser) skip_meta_name(end int) bool {
	if p.pos >= end || !is_name_start_tree(p.src[p.pos]) { return false }
	for p.pos < end && (is_ident_byte_tree(p.src[p.pos]) || p.src[p.pos] == `:`) {
		p.pos++
	}
	return true
}

// parse_body_items is the walker's per-ITEM body loop — LANE 1 (the [L25c] comma
// array) and LANE 2 (the §9 [L25a/b] typed list), where the parser really does
// contribute one node per item. Unchanged from the loop that used to serve every
// body; the attribute test stays in it because those lanes admit an `x=1` token
// the head zone did not claim.
fn (mut p TreeParser) parse_body_items(end int, mut children []TreeNode) {
	for {
		p.skip_ws()
		if p.pos >= end { break }
		c := p.src[p.pos]
		if c == `]` { break }
		if is_name_start_tree(c) && p.has_eq_attr_ahead(end) {
			if attr := p.parse_attribute_eq_form_in_element(end) {
				children << attr
			} else {
				p.pos++
			}
			continue
		}
		// Body item (nested element / text / scalar / sequence-literal items).
		saved := p.pos
		run := p.parse_item_run() or { break }
		if p.pos == saved { p.pos++; continue }
		for child in run { children << child }
	}
}

// ProseRun is one prose run plus whether comment trivia was erased inside it —
// which the caller needs because a body holding a CommentNode is no longer a
// SOLE-item body to the parser, and so is not auto-typed.
struct ProseRun {
	node        TreeNode
	saw_comment bool
}

// parse_prose_body is LANE 3 — the element-body PROSE lane, `parse_body`'s
// reading (#1029).
//
// THE LIE IT FIXES. `[the quick brown]` is the element `the` with ONE Text item
// `"quick brown"`: one bareword that does not auto-type makes the whole body
// prose (G-BODY-1, conformance 009/014), and in the prose lane a maximal run of
// bare value-run tokens coalesces into a single Text. The walker read the body
// one ITEM at a time and projected TWO scalar children `quick` / `brown` — arity
// 2 where the document has 1, in the tree pane and in every consumer of the
// `loc`s (the source↔tree bridge). The class is wide, and measured on the binary
// at 71c31f461 it reached well past whitespace-separated barewords:
//
//   [the quick brown]                → 2 scalars, parser: 1 Text
//   [the 42 brown]                   → 2 (an int + a string), parser: 1 Text
//   [doc a:b c]                      → 3 (a scalar, an atom, a scalar)
//   [doc :enum=[v1 v2] rest here]    → 5, one of them an ARRAY IMAGE
//   [doc 2024-01-15]                 → 3 (int 2024, int -1, int -15)
//   [doc hello world x=1]            → 3, one of them a spurious ATTRIBUTE
//   [doc quick brown [b x] y z]      → 5, where the parser has 3 items
//
// WHERE THE RUN ENDS is `prose_run_break_at`'s (cx/lexical.v), which reads
// parse_body's branch table over the shared classifiers. HOW FAR ONE TOKEN
// REACHES is `value_run_end`'s — load-bearing for the mid-token cases, since a
// `[…]` opened inside a token absorbs whitespace and `]` (`:enum=[v1 v2]` is ONE
// token, and a walker scanning byte kinds read a typed-list array in the middle
// of it).
//
// THE VALUE IS WHAT THE PARSER BINDS, join spaces included: internal whitespace
// runs collapse to a single space (so `[doc a  b]` is `"a b"`), and the
// SEPARATOR space beside a child node stays IN the run — it is load-bearing for
// the XML projection of mixed prose (`[p text [b bold]]` must project
// `text <b>`), which is why `[doc quick brown [b x] y z]` is `"quick brown "`
// and `" y z"`, with the spaces, and not two trimmed runs.
//
// THE `loc` SPANS THE RUN'S AUTHORED TOKENS — first token's first byte to last
// token's last byte. That is the prose the bridge should select; the join space
// and any collapsed whitespace are the parser's value, not authored extent, so
// `loc` and `value` can differ in edge whitespace exactly as #999's
// triple-quoted node has a `loc` wider than its dedented value.
fn (mut p TreeParser) parse_prose_body(end int, mut children []TreeNode) {
	base := children.len // the head zone's attributes are not body items
	mut after_non_text := false
	mut saw_comment := false
	mut runs := 0
	mut others := 0
	for {
		if r := p.parse_prose_run(end, after_non_text) {
			children << r.node
			saw_comment = saw_comment || r.saw_comment
			after_non_text = false
			runs++
		} else {
			saw_comment = saw_comment || p.prose_trivia
		}
		p.skip_ws()
		if p.pos >= end { break }
		if p.src[p.pos] == `]` { break }
		saved := p.pos
		k := token_kind_at(p.src, saved)
		run := p.parse_item_run() or { break }
		if p.pos == saved { p.pos++; continue }
		for child in run { children << child }
		others += run.len
		// parse_body's `after_non_text` table: a child node / collection
		// literal / entity ref owns the join space to its RIGHT, so the next
		// run opens with one. A quoted string, a triple-quoted string and a
		// `$name` hole do NOT — the emit-side sibling join supplies theirs, so
		// a leading space in the VALUE would double it.
		is_hole := p.src[saved] == `$` && hole_token_len(p.src, saved) != none
		after_non_text = !(k == .quote_run || k == .triple_span || is_hole)
	}
	// SOLE-ITEM AUTO-TYPE. parse_body's end-of-body flush: when the run is the
	// body's ONLY item it is auto-typed in place — `[Version 2]` is the int 2,
	// `[doc :ok]` the atom, `[doc 2024-01-15]` the date — and stays TEXT when
	// it does not auto-type (`[doc hello]`, `[doc a]`). `try_autotype_bytes` is
	// the parser's own test, asked on the same bytes. A body holding erased
	// comment trivia is NOT sole-item to the parser (the CommentNode occupies
	// `items`), so the promotion is withheld there.
	if runs == 1 && others == 0 && !saw_comment && children.len == base + 1 {
		if _ := try_autotype_bytes(children[base].value_str.bytes()) {
			vk, vs := classify_bare_value(children[base].value_str)
			children[base].kind = 'scalar'
			children[base].value_kind = vk
			children[base].value_str = vs
		}
	}
}

// parse_prose_run accumulates ONE prose run and returns it as a single `text`
// node, or `none` when the cursor is already on a structural item (having
// consumed any trivia in between). `after_non_text` says whether the PREVIOUS
// sibling owns the join space to its right. See `parse_prose_body` for the
// derivation; this is the mechanical mirror of parse_body's `text_buf`.
fn (mut p TreeParser) parse_prose_run(limit int, after_non_text bool) ?ProseRun {
	p.prose_trivia = false
	mut buf := []u8{cap: 32}
	mut tok_start := -1
	mut tok_end := -1
	mut pending_join_ws := false
	mut saw_comment := false
	for p.pos < limit {
		// parse_body reads `had_ws` off the byte AT the cursor, BEFORE the
		// whitespace / line-comment skip — so a comment contributes no join
		// space of its own (#469 erasure: `a [; c ] b` ≡ `a b`).
		had_ws := is_ws(p.src[p.pos])
		for p.pos < limit {
			c := p.src[p.pos]
			if c == ` ` || c == `\t` || c == `\r` || c == `\n` { p.pos++; continue }
			if c == `#` {
				// A `#` at a token start opens a line comment (grammar [30b];
				// a mid-token `#` is an ordinary byte and never reaches here).
				// parse_body appends the CommentNode and KEEPS ACCUMULATING —
				// the run does not split. The walker cannot project the
				// comment (no `comment` kind in the closed D2 vocabulary), so
				// it only records that one was erased. The scan is bounded by
				// `limit`: an unterminated comment makes the parser raise, and
				// the walker never raises.
				saw_comment = true
				p.pos++
				for p.pos < limit && p.src[p.pos] != `\n` { p.pos++ }
				continue
			}
			break
		}
		if p.pos >= limit { break }
		if prose_run_break_at(p.src, p.pos) {
			// The break that also contributes the run's TRAILING join space: a
			// child node (or an entity ref) keeps the separator space in the
			// run to its left. Every other break flushes the run as it stands.
			k := token_kind_at(p.src, p.pos)
			if (k.is_bracket_open() || k == .amp) && (had_ws || pending_join_ws)
				&& buf.len > 0 && buf.last() != ` ` {
				buf << ` `
			}
			break
		}
		if p.src[p.pos] == `[` {
			// `[; … ]` — trivia INSIDE the run (`prose_run_break_at` refused it
			// for exactly this reason). The join space is PENDING, not
			// appended: a comment at the END of the body must not leave the run
			// with a trailing space.
			saw_comment = true
			close := find_matching_bracket(p.src, p.pos)
			pending_join_ws = pending_join_ws || (had_ws && buf.len > 0)
			p.pos = if close < 0 || close >= limit { limit } else { close + 1 }
			continue
		}
		if p.src[p.pos] == `/` {
			// THE ONE NAMED EXCEPTION to parse_body's branch table. A `/`-led
			// token at a token start is a CXPath to this walker and reaches
			// `parse_path`; to the DATA parser it is an ordinary value run and
			// joins the prose (`[doc /a b]` is the single Text "/a b", and even
			// a top-level `/users/user` is Text there). `path` is nonetheless a
			// kind of the D2 vocabulary (`core/abi.md` §2.16.3) that the data
			// AST has no node for at all — the walker projects it because it
			// serves CODE sources too, which is pinned at top level by the
			// tree-006 conformance fixture and in bodies by the clause-child
			// surface (`[?for [in $x /a] …]`). Swallowing it into a run would
			// RETIRE a contract kind from body position, which is a contract
			// change and not a bug fix — the same line #1020/#1025 drew. The
			// residual is named and measured: `[doc go /home now]` stays three
			// items where the parser has one Text.
			break
		}
		e := value_run_end(p.src, p.pos)
		if e <= p.pos { break }
		join_ws := had_ws || pending_join_ws
		pending_join_ws = false
		if buf.len > 0 {
			if join_ws && buf.last() != ` ` { buf << ` ` }
		} else if after_non_text && join_ws {
			buf << ` `
		}
		if tok_start < 0 { tok_start = p.pos }
		buf << p.src[p.pos..e]
		tok_end = e
		p.pos = e
	}
	if tok_start < 0 {
		// No token: the trivia (if any) still has to be reported, because it
		// blocks the sole-item auto-type just as a buffered one does.
		p.prose_trivia = saw_comment
		return none
	}
	return ProseRun{
		node:        TreeNode{
			kind:       'text'
			value_kind: 'string'
			value_str:  buf.bytestr()
			loc_start:  tok_start
			loc_end:    tok_end
		}
		saw_comment: saw_comment
	}
}

// ── The TOP-LEVEL text run (#1040) ───────────────────────────────────────────
//
// parse_top_text_run consumes ONE top-level text run starting at p.pos and
// returns it as a single node, or `none` when the run holds no authored token
// (whitespace only). `val_start` is where the VALUE begins — p.pos for the
// document's first run, and the separator byte after the previous sibling
// otherwise. `doc_top` says whether this is the document's FIRST node.
//
// A DIFFERENT RULE FROM `parse_prose_run`, IN A DIFFERENT POSITION. #1029 fixed
// the element-body prose lane, where a maximal run of bare VALUE-RUN tokens
// coalesces and every structural item breaks it, and named this one as left
// behind: `the quick brown` at top level is one Text to the parser and was
// THREE scalar children here. The top-level rule is `read_top_text_run`'s and it
// is VERBATIM — quotes, `(`, `{`, `,`, `=`, `#` and every internal whitespace
// byte are content, and only `[`, `&`, `]`, a line-start `---` and EOF stop the
// run (`top_text_run_end`, cx/lexical.v). So `a  b` keeps BOTH spaces here where
// the body lane collapses them to one.
//
// THE VALUE IS WHAT THE PARSER BINDS, separator whitespace included. In
// mixed-text mode the parser's run starts at the byte after the previous node,
// so `prose [b x] more prose` is `"prose "` / `" more prose"` — spaces and all,
// load-bearing for the XML projection of mixed prose exactly as #1029's body
// join spaces are. One trailing newline is stripped when the run reached EOF or
// a `---` (read_top_text_run's editor convention); a `[`/`&` terminator strips
// nothing, because the author placed that byte as a deliberate separator.
//
// THE `loc` SPANS THE RUN'S AUTHORED TOKENS — first non-whitespace byte to last
// — so the source↔tree bridge selects the prose and not the separator. `loc`
// and `value` can therefore differ in edge whitespace, exactly as #999's
// triple-quoted node and #1029's body runs do.
//
// THE SOLE-TOKEN AUTO-TYPE is parse_document's own doc-top rule (@CHOICE-1,
// M-DOC-2 / G-NODE-3): a run whose trimmed form is a SINGLE whitespace-free
// token that auto-types is that typed scalar — `42` is the int (tree-005),
// `:ok` the atom, `2024-01-15` the date, `true` the bool — and anything else,
// `hello` and `a` included, is TEXT. It fires at doc-top ONLY: the parser does
// not auto-type mixed-mode runs, so `[?= 1] 42` is the Text `" 42"` on both
// sides. This is also what retires two INVALID-JSON emissions the per-token
// walk produced, `2024-01-15` → `"value":-01` and a bare `-` → `"value":-`.
// has_ws_byte reports whether `[lo, hi)` holds a whitespace byte — the
// parser's "a MULTI-token run stays prose" test, asked on the same bytes.
fn has_ws_byte(src []u8, lo int, hi int) bool {
	for i := lo; i < hi; i++ {
		if is_ws(src[i]) { return true }
	}
	return false
}

fn (mut p TreeParser) parse_top_text_run(val_start int, doc_top bool) ?TreeNode {
	start := p.pos
	end, terminator := top_text_run_end(p.src, start)
	if end <= start { return none }
	p.pos = end
	// The authored extent: the `loc` the bridge selects.
	mut tok_end := end
	for tok_end > start && is_ws(p.src[tok_end - 1]) { tok_end-- }
	if tok_end <= start { return none } // whitespace only — nothing to select
	mut value_end := end
	if terminator != `[` && terminator != `&` {
		if value_end > val_start && p.src[value_end - 1] == `\n` { value_end-- }
	}
	value := p.src[val_start..value_end].bytestr()
	if doc_top && !has_ws_byte(p.src, start, tok_end) {
		trimmed := p.src[start..tok_end].bytestr()
		if _ := try_autotype_bytes(trimmed.bytes()) {
			vk, vs := classify_bare_value(trimmed)
			return TreeNode{
				kind:       'scalar'
				value_kind: vk
				value_str:  vs
				loc_start:  start
				loc_end:    tok_end
			}
		}
	}
	return TreeNode{
		kind:       'text'
		value_kind: 'string'
		value_str:  value
		loc_start:  start
		loc_end:    tok_end
	}
}

// has_eq_attr_ahead returns true if `p.pos` starts an identifier that
// is immediately (no whitespace) followed by `=` and a value byte.
// Used by the element/directive children-loop to disambiguate
// `name=value` attribute form from a bare identifier scalar.
fn (p &TreeParser) has_eq_attr_ahead(end int) bool {
	if p.pos >= end { return false }
	if !is_name_start_tree(p.src[p.pos]) { return false }
	mut j := p.pos
	for j < end && is_ident_byte_tree(p.src[j]) { j++ }
	if j == p.pos { return false }
	if j >= end { return false }
	if p.src[j] != `=` { return false }
	// Must be followed by something (not immediately `]` or whitespace).
	k := j + 1
	if k >= end { return false }
	c := p.src[k]
	if c == ` ` || c == `\t` || c == `\n` || c == `\r` || c == `]` {
		return false
	}
	return true
}

// parse_attribute_eq_form_in_element parses `name=value` starting at
// p.pos where p.src[p.pos] is an identifier start byte. The four scalar
// value shapes (quoted string, bracket, atom, bare token) emit distinct
// value_kind discriminators. `end` is the enclosing `]` index (exclusive
// bound for the inner scan).
fn (mut p TreeParser) parse_attribute_eq_form_in_element(end int) ?TreeNode {
	if p.pos >= end || !is_name_start_tree(p.src[p.pos]) { return none }
	start := p.pos
	name_start := p.pos
	for p.pos < end && is_ident_byte_tree(p.src[p.pos]) {
		p.pos++
	}
	if p.pos == name_start { return none }
	if p.pos >= end || p.src[p.pos] != `=` { return none }
	name := unsafe { tos(&p.src[name_start], p.pos - name_start) }.clone()
	p.pos++ // consume `=`
	if p.pos >= end {
		return TreeNode{
			kind:       'attribute'
			name:       name
			value_kind: 'string'
			value_str:  ''
			loc_start:  start
			loc_end:    p.pos
		}
	}
	c := p.src[p.pos]
	mut vk := ''
	mut vs := ''
	mut value_end := p.pos
	tq_prefix := triple_quote_prefix_len(p.src, p.pos)
	if tq_prefix >= 0 {
		// TRIPLE-QUOTED ATTRIBUTE VALUE (#999). This arm has to lead: the
		// single-delimiter arm below closed `'''` on its own second byte, so
		// the attribute took the EMPTY string as its value and the real body
		// fell out into the element body as sibling `text` nodes — the value
		// detached from the attribute it belongs to. Attributes are scalar-only
		// (D2), and a triple-quoted string is a scalar, so it belongs here
		// whole. Dedent (or, for the raw `r` form, its absence) is
		// `scan_triple_quoted_opt`'s rule, not a second copy.
		q := p.src[p.pos + tq_prefix]
		val, n := scan_triple_quoted_opt(p.src, p.pos + tq_prefix, q, tq_prefix == 1) or {
			// Unterminated inside the element — bound the value at the `]`.
			p.pos = end
			return TreeNode{
				kind:       'attribute'
				name:       name
				value_kind: 'string'
				value_str:  ''
				loc_start:  start
				loc_end:    end
			}
		}
		vk = 'string'
		vs = val
		value_end = p.pos + tq_prefix + n
	} else if c == `'` || c == `"` {
		qend := find_quote_end(p.src, p.pos)
		if qend < 0 || qend >= end {
			value_end = end
		} else {
			vk = 'string'
			vs = unsafe { tos(&p.src[p.pos + 1], qend - p.pos - 1) }.clone()
			value_end = qend + 1
		}
	} else if c == `[` {
		ebracket := find_matching_bracket(p.src, p.pos)
		if ebracket < 0 || ebracket >= end {
			value_end = end
		} else {
			vk = 'string'
			vs = unsafe { tos(&p.src[p.pos], ebracket - p.pos + 1) }.clone()
			value_end = ebracket + 1
		}
	} else if c == `:` && p.pos + 1 < end && is_name_start_tree(p.src[p.pos+1]) {
		mut j := p.pos + 1
		for j < end && is_ident_byte_tree(p.src[j]) { j++ }
		vk = 'atom'
		vs = unsafe { tos(&p.src[p.pos + 1], j - p.pos - 1) }.clone()
		value_end = j
	} else {
		mut j := p.pos
		for j < end && p.src[j] != ` ` && p.src[j] != `\t`
		    && p.src[j] != `\n` && p.src[j] != `\r`
		    && p.src[j] != `]` {
			j++
		}
		raw := unsafe { tos(&p.src[p.pos], j - p.pos) }.clone()
		value_end = j
		vk, vs = classify_bare_value(raw)
	}
	p.pos = value_end
	return TreeNode{
		kind:       'attribute'
		name:       name
		value_kind: vk
		value_str:  vs
		loc_start:  start
		loc_end:    value_end
	}
}

// classify_bare_value categorises a non-quoted, non-bracket attribute
// or body value token into one of the value-kind discriminators.
fn classify_bare_value(raw string) (string, string) {
	if raw == 'true' { return 'bool', 'true' }
	if raw == 'false' { return 'bool', 'false' }
	if raw == 'null' { return 'string', 'null' }
	if looks_like_int(raw) { return 'int', raw }
	if looks_like_float(raw) { return 'float', raw }
	return 'string', raw
}

fn looks_like_int(s string) bool {
	if s.len == 0 { return false }
	mut i := 0
	if s[0] == `-` || s[0] == `+` { i = 1 }
	if i >= s.len { return false }
	for ; i < s.len; i++ {
		if s[i] < `0` || s[i] > `9` { return false }
	}
	return true
}

fn looks_like_float(s string) bool {
	if s.len == 0 { return false }
	mut i := 0
	mut saw_digit := false
	mut saw_dot := false
	mut saw_exp := false
	if s[0] == `-` || s[0] == `+` { i = 1 }
	for ; i < s.len; i++ {
		c := s[i]
		if c >= `0` && c <= `9` { saw_digit = true; continue }
		if c == `.` && !saw_dot && !saw_exp { saw_dot = true; continue }
		if (c == `e` || c == `E`) && saw_digit && !saw_exp {
			saw_exp = true
			if i + 1 < s.len && (s[i+1] == `+` || s[i+1] == `-`) { i++ }
			continue
		}
		return false
	}
	return saw_digit && (saw_dot || saw_exp)
}

// parse_text_or_string parses a quoted string at p.pos as a text
// node. Returns the TreeNode spanning the whole quoted form
// (including quotes) with `value` being the unquoted payload.
fn (mut p TreeParser) parse_text_or_string() TreeNode {
	start := p.pos
	qend := find_quote_end(p.src, p.pos)
	if qend < 0 {
		// Unterminated string — span to end of source.
		end := p.src.len
		val := unsafe { tos(&p.src[start + 1], end - start - 1) }.clone()
		p.pos = end
		return TreeNode{
			kind:       'text'
			value_kind: 'string'
			value_str:  val
			loc_start:  start
			loc_end:    end
		}
	}
	val := unsafe { tos(&p.src[start + 1], qend - start - 1) }.clone()
	p.pos = qend + 1
	return TreeNode{
		kind:       'text'
		value_kind: 'string'
		value_str:  val
		loc_start:  start
		loc_end:    qend + 1
	}
}

// parse_triple_quoted_text parses a triple-quoted literal at p.pos as ONE text
// node whose `value` is the literal's value and whose `loc` spans the whole
// literal — the `r` prefix and both delimiter triples included, so the
// source↔tree bridge selects the authored form and not just its interior.
//
// The value is what the DATA parser would bind: dedented for the plain form
// (`strip_common_indent`, grammar [10b]) and VERBATIM for the raw `r'''…'''`
// form (I1 L58). Both come out of `scan_triple_quoted_opt` — the one shared
// scanner — rather than a second dedent rule living here (#999).
fn (mut p TreeParser) parse_triple_quoted_text() TreeNode {
	start := p.pos
	prefix := triple_quote_prefix_len(p.src, start)
	q := p.src[start + prefix]
	raw := prefix == 1
	val, n := scan_triple_quoted_opt(p.src, start + prefix, q, raw) or {
		// Unterminated — span to end of source, carrying the body read so far
		// so the pane shows the text the author is in the middle of typing.
		body_start := start + prefix + 3
		p.pos = p.src.len
		body := if body_start < p.src.len {
			unsafe { tos(&p.src[body_start], p.src.len - body_start) }.clone()
		} else {
			''
		}
		return TreeNode{
			kind:       'text'
			value_kind: 'string'
			value_str:  body
			loc_start:  start
			loc_end:    p.src.len
		}
	}
	p.pos = start + prefix + n
	return TreeNode{
		kind:       'text'
		value_kind: 'string'
		value_str:  val
		loc_start:  start
		loc_end:    p.pos
	}
}

// parse_array_literal_image emits the array literal spanning `start`..`end`
// (`end` is the index of the closing `]`, which `find_matching_bracket` — the
// same scanner the element arm uses, so the two agree byte for byte on the
// span — has already located) as ONE node, and leaves the cursor one past it.
//
// WHY ONE `scalar` CARRYING THE LITERAL'S IMAGE, decided from the contract and
// from the consumers (#1020):
//
//   - It cannot be more than one node. An Array is a container Item that
//     preserves structure and does not flatten (CXDM §2.5), so an array literal
//     in top-level or element-body position contributes exactly ONE item to the
//     enclosing sequence. #1000's flatten was right for sequences precisely
//     because sequences DO flatten (CXDM §1); the rationale stops at the
//     container boundary.
//   - It cannot be a new kind. The `kind` vocabulary is closed at element /
//     attribute / text / directive / scalar / path by the D2 contract
//     (`core/abi.md` §2.16.3) — an `array` / `map` kind is a CONTRACT change,
//     not a bug fix.
//   - Of the six, `scalar` is the walker's "a VALUE sits here" slot, the one it
//     already uses for every non-Node item (numbers, bools, atoms, bindings).
//     `element` would have to invent a name — `[1, 2, 3]` would arrive
//     indistinguishable from the element `[array …]`; `text` means character
//     data, which an Array is not.
//   - The payload is the literal's IMAGE: the authored bytes, verbatim. This is
//     not a new convention — the attribute-value arm has emitted exactly this
//     for `tags=[1, 2]` since the walker shipped, and extending it to body and
//     top-level position makes the walker self-consistent instead of carrying
//     two answers for one shape. It also keeps what the consumers need: the
//     source↔tree bridge gets one `loc` spanning the authored literal (so
//     selecting the node highlights `[1, 2, 3]`, as #999's triple-quoted text
//     node spans its authored form), and the playground instance view gets one
//     honest row instead of a box of commas.
//
// A JSON-ARRAY `value` (`"value":[1,2,3]`) was considered and refused. It
// widens `value` from a JSON scalar to arbitrary JSON, which is the same weight
// of contract change as a new kind; every consumer stringifies a non
// string/number/boolean value, so `[1, 2, 3]` would reach the pane as `1,2,3` —
// brackets gone and indistinguishable from the string `'1,2,3'`, which is the
// very ambiguity #1000 was filed against; and re-typing the items into JSON
// discards their `loc`s, which is what the bridge exists for.
//
// BOTH ARRAY-YIELDING PRODUCTIONS LAND HERE (#1025). The dispatch has two: the
// [D1] first-item rule (`array_literal_at_bracket`) and the @CHOICE-1 /
// G-ARRAY-1 whitespace typed list (`typed_list_body_at`, §9 [L25a/b]), tested
// first. `parse_bracket` asks both, in that order, and routes either to this
// one arm — the projection is a property of the VALUE (an Array is one
// container Item), not of which production recognized it, so `[1, 2, 3]`,
// `[80 443]` and `[true false]` are all one `scalar` carrying the authored
// image. The typed list's ITEMS are not emitted for the same reason the comma
// form's are not: a container does not flatten.
fn (mut p TreeParser) parse_array_literal_image(start int, end int) TreeNode {
	p.pos = end + 1
	return TreeNode{
		kind:       'scalar'
		value_kind: 'string'
		value_str:  unsafe { tos(&p.src[start], p.pos - start) }.clone()
		loc_start:  start
		loc_end:    p.pos
	}
}

// parse_map_literal_image emits the map literal at p.pos (which
// `map_literal_at_brace` has already ruled a literal) as ONE node carrying the
// literal's image, on the same reasoning as `parse_array_literal_image` above:
// a Map is a container Item (CXDM §2.6), and the D2 kind vocabulary has no
// `map`. Before this, `{` reached `parse_item`'s unrecognized-byte recovery one
// byte at a time, so `{a: 1}` arrived as FIVE scalar children — `{`, `a`, `:`,
// 1, `}` — three of them punctuation standing where values belong (#1020).
fn (mut p TreeParser) parse_map_literal_image() TreeNode {
	start := p.pos
	close := find_matching_brace(p.src, start)
	if close < 0 {
		// Unbalanced `{` — keep the walker's one-byte recovery so the caller
		// still makes progress and the byte is visible downstream.
		p.pos = start + 1
		return TreeNode{
			kind:       'scalar'
			value_kind: 'string'
			value_str:  '{'
			loc_start:  start
			loc_end:    p.pos
		}
	}
	p.pos = close + 1
	return TreeNode{
		kind:       'scalar'
		value_kind: 'string'
		value_str:  unsafe { tos(&p.src[start], p.pos - start) }.clone()
		loc_start:  start
		loc_end:    p.pos
	}
}

// parse_item_run reads the next sibling-level item and returns the node(s) it
// contributes to the enclosing children list. Every shape contributes exactly
// one node EXCEPT a sequence literal, which contributes its ITEMS.
//
// #1000: `(1, 2, 3)` used to reach `parse_item`'s unrecognized-byte recovery
// one byte at a time, so the literal arrived as SEVEN scalar children — `(`,
// 1, `,`, 2, `,`, 3, `)` — with the delimiters indistinguishable from a string
// item that genuinely is `","`. Punctuation is syntax, not a value, and a
// consumer counting `children` saw 2n+1 items instead of n.
//
// The items land in the ENCLOSING list rather than under a node of their own
// because that is the value the source denotes: a sequence in top-level or
// element-body position flattens into the enclosing sequence (CXDM §1
// sequence-flat, the same rule `parse_sequence_literal` applies when it splices
// a nested SequenceNode's items into its own). It is also the only shape open
// to this walker — the `kind` vocabulary is closed at element / attribute /
// text / directive / scalar / path by the D2 contract (`core/abi.md` §2.16.3),
// and a `sequence` kind would be a contract change, not a bug fix.
fn (mut p TreeParser) parse_item_run() ![]TreeNode {
	p.skip_ws()
	if p.pos >= p.src.len { return error('eof') }
	if p.src[p.pos] == `(` && sequence_literal_at_paren(p.src, p.pos) {
		return p.parse_sequence_items()
	}
	return [p.parse_item()!]
}

// parse_sequence_items parses the sequence literal at p.pos (p.src[p.pos] is a
// `(` that `sequence_literal_at_paren` has ruled a literal) and returns its
// items, leaving the cursor one past the closing `)`. Item separators are
// consumed, never emitted. A nested sequence flattens through
// `parse_item_run`, matching `parse_sequence_literal`'s CXDM §1.2 splice.
fn (mut p TreeParser) parse_sequence_items() []TreeNode {
	start := p.pos
	close := find_matching_paren(p.src, start)
	if close < 0 {
		// Unbalanced `(` — keep the walker's existing one-byte recovery so the
		// caller still makes progress and the byte is visible downstream.
		p.pos = start + 1
		return [TreeNode{
			kind:       'scalar'
			value_kind: 'string'
			value_str:  '('
			loc_start:  start
			loc_end:    p.pos
		}]
	}
	p.pos = start + 1
	mut items := []TreeNode{}
	for {
		p.skip_ws()
		if p.pos >= close { break }
		c := p.src[p.pos]
		if c == `,` { p.pos++; continue }
		saved := p.pos
		run := p.parse_item_run() or { break }
		if p.pos == saved { p.pos++; continue }
		for it in run { items << it }
	}
	p.pos = close + 1
	return items
}

// parse_path scans a CXPath-shaped token starting with `/` at p.pos.
// Returns a `path`-kind node whose value is the rendered path text.
fn (mut p TreeParser) parse_path() TreeNode {
	start := p.pos
	// Span: leading `/`s, then identifier/path bytes; allow `/`, `.`,
	// `@`, `*`, ident bytes, and `:` (for axis::step), and `[` for
	// predicates (matched-bracket-skip).
	mut j := p.pos
	for j < p.src.len {
		c := p.src[j]
		if c == ` ` || c == `\t` || c == `\n` || c == `\r` { break }
		if c == `]` { break }
		if c == `[` {
			eb := find_matching_bracket(p.src, j)
			if eb < 0 { j = p.src.len; break }
			j = eb + 1
			continue
		}
		if c == `/` || c == `.` || c == `@` || c == `*` || c == `:`
		   || is_ident_byte_tree(c) {
			j++
			continue
		}
		break
	}
	value := unsafe { tos(&p.src[start], j - start) }.clone()
	p.pos = j
	return TreeNode{
		kind:       'path'
		value_kind: 'string'
		value_str:  value
		loc_start:  start
		loc_end:    j
	}
}

fn (mut p TreeParser) parse_atom_scalar() TreeNode {
	start := p.pos
	p.pos++ // consume `:`
	for p.pos < p.src.len && is_ident_byte_tree(p.src[p.pos]) { p.pos++ }
	name := unsafe { tos(&p.src[start + 1], p.pos - start - 1) }.clone()
	return TreeNode{
		kind:       'scalar'
		value_kind: 'atom'
		value_str:  name
		loc_start:  start
		loc_end:    p.pos
	}
}

fn (mut p TreeParser) parse_binding_scalar() TreeNode {
	start := p.pos
	p.pos++ // consume `$`
	for p.pos < p.src.len && (is_ident_byte_tree(p.src[p.pos])
	    || p.src[p.pos] == `/` || p.src[p.pos] == `@`
	    || p.src[p.pos] == `.`) {
		p.pos++
	}
	value := unsafe { tos(&p.src[start], p.pos - start) }.clone()
	return TreeNode{
		kind:       'scalar'
		value_kind: 'string'
		value_str:  value
		loc_start:  start
		loc_end:    p.pos
	}
}

fn (mut p TreeParser) parse_number_scalar() TreeNode {
	start := p.pos
	mut j := p.pos
	if j < p.src.len && (p.src[j] == `-` || p.src[j] == `+`) { j++ }
	for j < p.src.len && p.src[j] >= `0` && p.src[j] <= `9` { j++ }
	mut is_float := false
	if j < p.src.len && p.src[j] == `.` {
		is_float = true
		j++
		for j < p.src.len && p.src[j] >= `0` && p.src[j] <= `9` { j++ }
	}
	if j < p.src.len && (p.src[j] == `e` || p.src[j] == `E`) {
		is_float = true
		j++
		if j < p.src.len && (p.src[j] == `+` || p.src[j] == `-`) { j++ }
		for j < p.src.len && p.src[j] >= `0` && p.src[j] <= `9` { j++ }
	}
	raw := unsafe { tos(&p.src[start], j - start) }.clone()
	p.pos = j
	kind := if is_float { 'float' } else { 'int' }
	return TreeNode{
		kind:       'scalar'
		value_kind: kind
		value_str:  raw
		loc_start:  start
		loc_end:    j
	}
}

fn (mut p TreeParser) parse_ident_scalar() TreeNode {
	start := p.pos
	for p.pos < p.src.len && is_ident_byte_tree(p.src[p.pos]) {
		p.pos++
	}
	raw := unsafe { tos(&p.src[start], p.pos - start) }.clone()
	vk, vs := classify_bare_value(raw)
	return TreeNode{
		kind:       'scalar'
		value_kind: vk
		value_str:  vs
		loc_start:  start
		loc_end:    p.pos
	}
}

// skip_string_literal_tree reports what the byte at `bs[i]` opens:
//   - an index GREATER than `i` — a string literal that ends there (exclusive);
//   - `i` itself — no string literal opens here (e.g. a bare `r`);
//   - -1 — a literal opens here but is UNTERMINATED.
// It covers all three authorable spellings: the RAW triple (`r'''…'''` /
// `r"""…"""`), the plain triple (`'''…'''` / `"""…"""`), and the
// single-delimiter form.
//
// The triple arm is #999. The delimiter-matching scanners below used to know
// only the single-delimiter form, so `'''body'''` read as an EMPTY string
// (`''`) immediately followed by a fresh opener. Two things followed: an
// attribute's value came back empty with the real body re-emitted as sibling
// `text` nodes, and a body carrying an odd number of delimiter bytes
// (`'''it's'''`) left the bracket walker inside a phantom string, which
// swallowed the closing `]` and reported the whole element `unbalanced`.
// The opener test and the closing/lookahead rule are both the shared
// primitives' (`triple_quote_prefix_len` / `scan_triple_quoted_opt`,
// cx/lexical.v) — this walker does not re-spell either.
fn skip_string_literal_tree(bs []u8, i int) int {
	if i < 0 || i >= bs.len { return i }
	prefix := triple_quote_prefix_len(bs, i)
	if prefix < 0 {
		if bs[i] != `'` && bs[i] != `"` { return i }
		qend := find_quote_end(bs, i)
		return if qend < 0 { -1 } else { qend + 1 }
	}
	q := bs[i + prefix]
	// `raw: true` — this call only needs the CONSUMED BYTE COUNT, and the
	// dedent is irrelevant to (and slower for) a span skip.
	_, n := scan_triple_quoted_opt(bs, i + prefix, q, true) or { return -1 }
	return i + prefix + n
}

// find_matching_bracket returns the index of the `]` that closes the
// `[` at start_idx, accounting for nested brackets and string
// literals. Returns -1 if unbalanced.
//
// A quote is a string opener ONLY at a token start (`span_token_start_at`,
// cx/lexical.v) — the rule `skip_bracket_region` has always carried and this
// matcher lacked until #1039. Without it the apostrophe in a contraction opened
// a "string" that ran past the element's own `]`, so EVERY element body with an
// odd number of apostrophes recovered as `unbalanced` and never reached the
// prose lane #1029 built: `[doc it's here]` was a nameless stub where the parser
// reads the element `doc` with one Text item `it's here`.
fn find_matching_bracket(bs []u8, start_idx int) int {
	mut depth := 0
	mut i := start_idx
	for i < bs.len {
		c := bs[i]
		if (c == `'` || c == `"` || c == `r`) && span_token_start_at(bs, i, start_idx) {
			nxt := skip_string_literal_tree(bs, i)
			if nxt < 0 { return -1 } // unterminated — the `]` can never be found
			if nxt > i { i = nxt; continue }
			// nxt == i — a bare `r`, an ordinary byte. Fall through.
		}
		if c == `[` { depth++ }
		else if c == `]` {
			depth--
			if depth == 0 { return i }
		}
		i++
	}
	return -1
}

// find_matching_paren returns the index of the `)` that closes the `(` at
// start_idx, or -1 if unbalanced. The depth counter is MIXED-DELIMITER —
// `[`/`(`/`{` all raise it — so it agrees byte-for-byte with the span
// `sequence_literal_at_paren` (cx/lexical.v) tested when it ruled this `(` a
// sequence literal. String literals are skipped whole, triples included — and
// only at a token start (`span_token_start_at`, #1039), so a contraction inside
// a sequence (`(1, [doc it's], 2)`) no longer makes the literal unbalanced and
// drops the walker back to emitting a bare `(` as a scalar CHILD.
fn find_matching_paren(bs []u8, start_idx int) int {
	mut depth := 0
	mut i := start_idx
	for i < bs.len {
		c := bs[i]
		if (c == `'` || c == `"` || c == `r`) && span_token_start_at(bs, i, start_idx) {
			nxt := skip_string_literal_tree(bs, i)
			if nxt < 0 { return -1 }
			if nxt > i { i = nxt; continue }
		}
		if c == `[` || c == `(` || c == `{` { depth++ }
		else if c == `]` || c == `}` {
			if depth > 0 { depth-- }
		} else if c == `)` {
			depth--
			if depth == 0 { return i }
		}
		i++
	}
	return -1
}

// find_matching_brace returns the index of the `}` that closes the `{` at
// start_idx, or -1 if unbalanced. The depth counter is MIXED-DELIMITER —
// `[`/`(`/`{` all raise it — so it agrees byte-for-byte with the span
// `map_literal_at_brace` (cx/lexical.v) tested when it ruled this `{` a map
// literal. String literals are skipped whole, triples included (#1020) — and
// only at a token start (`span_token_start_at`, #1039), so a contraction inside
// a map (`{k: 1, j: [p Bob's dog]}`) no longer makes the literal unbalanced and
// drops the walker back to emitting `{`, the key, `:` and the value as separate
// scalar children.
fn find_matching_brace(bs []u8, start_idx int) int {
	mut depth := 0
	mut i := start_idx
	for i < bs.len {
		c := bs[i]
		if (c == `'` || c == `"` || c == `r`) && span_token_start_at(bs, i, start_idx) {
			nxt := skip_string_literal_tree(bs, i)
			if nxt < 0 { return -1 }
			if nxt > i { i = nxt; continue }
		}
		if c == `[` || c == `(` || c == `{` { depth++ }
		else if c == `]` || c == `)` {
			if depth > 0 { depth-- }
		} else if c == `}` {
			depth--
			if depth == 0 { return i }
		}
		i++
	}
	return -1
}

// find_quote_end returns the index of the closing quote of the string
// starting at `start` (`bs[start]` is `'` or `"`). Honors `\\` escape.
// Returns -1 if unterminated.
fn find_quote_end(bs []u8, start int) int {
	if start >= bs.len { return -1 }
	q := bs[start]
	mut i := start + 1
	for i < bs.len {
		c := bs[i]
		if c == `\\` && i + 1 < bs.len { i += 2; continue }
		if c == q { return i }
		i++
	}
	return -1
}

// ── JSON emitter ─────────────────────────────────────────────────────

fn render_node(n TreeNode) string {
	mut out := []u8{cap: 128}
	emit_node(mut out, n)
	return out.bytestr()
}

fn emit_node(mut out []u8, n TreeNode) {
	out << `{`
	out << '"kind":"'.bytes()
	out << n.kind.bytes()
	out << `"`
	if n.kind == 'element' || n.kind == 'attribute' || n.kind == 'directive' {
		out << ',"name":'.bytes()
		out << json_quote_tree(n.name).bytes()
	}
	if n.kind == 'attribute' || n.kind == 'text' || n.kind == 'scalar'
	   || n.kind == 'path' {
		out << ',"value":'.bytes()
		out << render_value(n.value_kind, n.value_str).bytes()
	}
	out << ',"loc":{"start":'.bytes()
	out << n.loc_start.str().bytes()
	out << ',"end":'.bytes()
	out << n.loc_end.str().bytes()
	out << `}`
	if n.has_children {
		out << ',"children":['.bytes()
		for i, c in n.children {
			if i > 0 { out << `,` }
			emit_node(mut out, c)
		}
		out << `]`
	}
	out << `}`
}

// render_value emits one `value` field per the
// value_kind discriminator. Unknown kinds fall back to JSON string.
fn render_value(kind string, s string) string {
	match kind {
		'int', 'float' { return s }
		'bool' { return s } // already 'true' or 'false'
		'atom' { return json_quote_tree(':' + s) }
		else { return json_quote_tree(s) }
	}
}

// json_quote_tree returns a JSON-string-encoded representation of `s`,
// surrounded by `"`. Handles the four backslash-escapes mandated by
// RFC 8259 §7 plus the \uXXXX form for C0 controls.
fn json_quote_tree(s string) string {
	mut out := []u8{cap: s.len + 2}
	out << `"`
	for c in s {
		match c {
			`\\` { out << `\\`; out << `\\` }
			`"`  { out << `\\`; out << `"` }
			`\n` { out << `\\`; out << `n` }
			`\r` { out << `\\`; out << `r` }
			`\t` { out << `\\`; out << `t` }
			`\b` { out << `\\`; out << `b` }
			`\f` { out << `\\`; out << `f` }
			else {
				if c < 0x20 {
					hex := '0123456789abcdef'
					out << `\\`
					out << `u`
					out << `0`
					out << `0`
					out << hex[int(c >> 4)]
					out << hex[int(c & 0x0f)]
				} else {
					out << c
				}
			}
		}
	}
	out << `"`
	return out.bytestr()
}
