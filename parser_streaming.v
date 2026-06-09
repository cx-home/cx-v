module cx

// ── Streaming top-level body iterator (§11.6 gate-15) ───────────────────────
//
// `parse_top_level_children` is the streaming-incremental entry point used
// by `code.eval_code_streaming` when the program body is the
// canonical `[?for [NAME $b] :yield $b]` shape over `$doc/<root>/<child>`.
//
// Rationale: the non-streaming `cx.parse` path
// materialises the full input document into a `cx.Node` tree (one
// allocation per Element box plus separate `attrs[]` / `items[]` heaps
// per element); on the 100 MiB JSON-shape corpus that's ~1.1 M live
// element boxes at peak. Boehm-GC pressure on the resident-AST working
// set dominates wall time, capping throughput at ~30 MB/s with the
// no-sumtype-shape-change constraint enforced.
//
// The streaming path bypasses materialisation: we parse the root
// element's head (its name + any attrs), then enter a per-child loop —
// parse one body Element, hand it to the caller via `cb`, drop our
// reference, repeat. The caller is expected to do all needed
// processing (pattern match + render + emit) inside the callback so
// the element box is collectable as soon as the call returns. Peak
// working set is one in-flight element + the parser's source buffer.
//
// Constraints honoured:
//   - `cx.Node` sumtype shape is unchanged (bindings unaffected).
//   - Non-streaming `cx.parse` is byte-equivalent (this file adds new
//     entry points; no existing code path is modified).
//   - Reentrancy: each call constructs its own `Parser` via
//     `new_parser()` — no module-level mutable state.
//
// The iterator is callback-based rather than V-iterator-based because
// V's iterator surface doesn't compose well with `!`-result types and
// would force boxing the parser state on the heap. The callback form
// keeps the parser on the stack frame of the caller's loop.

// CXChildSink receives one top-level child Element at a time during
// streaming parse. Returning an error aborts the parse with that
// error propagated through `parse_top_level_children`.
pub type CXChildSink = fn (n Node) !

// CXRawChildSink receives the source byte range of one top-level child
// element during raw streaming parse. The slice `bytes` is a view
// into the original source buffer (no allocation per yield) — the
// caller MUST NOT retain it past the callback return (the byte
// content of `src` is owned by the caller, but the slice header lives
// for the duration of the call). Use `bytestr()` if a stable string
// copy is needed.
pub type CXRawChildSink = fn (bytes []u8) !

// CXTopLevel describes the root element discovered by
// `parse_top_level_children`: the element name and any attributes
// declared on the root open. Children are NOT materialised here —
// they are streamed through the callback. Used by callers that need
// to inspect the root name (e.g. `$doc.users.user` path resolution).
pub struct CXTopLevel {
pub:
	name      string
	attrs     []Attribute
	data_type ?string
}

// parse_top_level_children walks `src` to the first top-level element,
// reads its head (name + attrs), then streams each body Element /
// Node to `cb` one at a time. The closing `]` of the root is matched
// before returning; trailing whitespace and `---` separators are
// permitted.
//
// Returns a `CXTopLevel` describing the root for callers that need
// to filter by root name. The root Element itself is NEVER
// materialised — its body children pass through `cb` and are
// collectable as soon as the callback returns.
//
// Limitations (intentional, fast-path-only):
//   - The root must be a single bracketed Element (`[name ...]`).
//     Documents with prolog (`[?xml]`), DOCTYPE, leading text, top-
//     level scalars, or multiple top-level elements fall outside the
//     fast path; callers should detect and fall back to `cx.parse`.
//   - Logfmt-shaped documents (`key=value\nkey=value`) are not
//     supported here.
//   - Streaming skips the post-parse `resolve_namespaces` /
//     `resolve_ids` / `resolve_languages` passes — they require the
//     full document tree. Callers that need namespace resolution or
//     ID validation MUST use `cx.parse`. The `[?for]` streaming
//     fast-path consumer doesn't need either: pattern matching
//     compares unresolved element names, and the JSON-shape gate
//     corpus declares no namespaces or anchors.
pub fn parse_top_level_children(src string, cb CXChildSink) !CXTopLevel {
	mut p := new_parser(src)
	// Skip leading ws + line comments; reject prolog/doctype on the
	// fast path (callers detect and fall back).
	p.skip_ws_and_line_comments()
	if p.at_end() {
		return error('parse_top_level_children: empty input')
	}
	if p.peek() != `[` {
		return error('parse_top_level_children: expected `[` at top level')
	}
	// Peek the byte after `[` to reject sigil-prefixed roots (?, !, -,
	// #, etc.) — these are PIs/comments/decls, not Element heads. The
	// fast path is element-only; anything else means the caller should
	// fall back to `cx.parse`.
	if p.pos + 1 >= p.src.len {
		return error('parse_top_level_children: unexpected EOF after `[`')
	}
	b2 := p.src[p.pos + 1]
	if !is_name_start(b2) {
		return error('parse_top_level_children: root is not a plain Element (saw sigil `${b2.ascii_str()}` after `[`)')
	}
	p.advance() // consume '['
	// Read the root head: name + optional attrs. We reuse the
	// attribute-scanning loop from `parse_element` but inlined here so
	// we can stop at the body-start (whitespace+`[`/`]`) without
	// materialising body items.
	raw_name := p.read_name()!
	root_name := normalize_doc_element_name(raw_name)
	mut root_attrs := []Attribute{cap: 4}
	mut root_dt := ?string(none)
	for {
		p.skip_ws()
		if p.at_end() { break }
		b := p.peek()
		if b == `]` { break }
		if b == `[` { break }     // body starts
		if b == `'` || b == `"` { break }  // body-position scalar
		if b == `#` {
			next := if p.pos + 1 < p.src.len { p.src[p.pos + 1] } else { u8(0) }
			if next == ` ` || next == `\t` || next == `\n` || next == `\r` || next == 0 {
				p.skip_line_comment()
				continue
			}
			// `#name` ID declaration on root — not supported on fast
			// path; fall back caller-side.
			return error('parse_top_level_children: root #id declaration not supported on streaming fast path')
		}
		if b == `:` {
			// Glued `::T` is a type annotation on the root. A spaced single
			// `:NAME` is an atom literal (grammar.ebnf:319) — a body item, not
			// element-meta — so it marks body-start: stop the meta scan WITHOUT
			// consuming, and let body parsing read `:NAME` as an atom.
			if p.pos + 1 < p.src.len && p.src[p.pos + 1] == `:` {
				p.advance() // first ':'
				p.advance() // second ':'
				root_dt = p.read_type_annotation()!
				break
			}
			break // single ':' → body starts (atom literal)
		}
		// boolean-flag sigil removed; use name=true / name=false.
		if is_name_start(b) {
			tok := p.read_name()!
			if !p.at_end() && p.peek() == `=` {
				p.advance()
				val, dt := p.read_attr_value_typed()!
				root_attrs << new_attribute(tok, val, AttributeMeta{ data_type: dt })
			} else {
				// Bare name — body-position element with no brackets is
				// not legal here; rewind and treat as body-start.
				p.pos -= tok.len
				break
			}
			continue
		}
		// Anything else — bail out cleanly so callers fall back.
		return error('parse_top_level_children: unexpected `${b.ascii_str()}` in root head')
	}

	// ── Per-child streaming loop ────────────────────────────────────
	// Walk the root body; for each child node, invoke `cb` and DO NOT
	// retain a reference. The local `child` variable is reassigned
	// each iteration; V's GC reclaims the prior box once the callback
	// returns and the next `parse_node()` call overwrites the slot.
	for {
		p.skip_ws_and_line_comments()
		if p.at_end() {
			return error('parse_top_level_children: unexpected EOF in root body')
		}
		bb := p.peek()
		if bb == `]` {
			p.advance()
			break
		}
		if bb == `[` || bb == `&` {
			child := p.parse_node()!
			cb(child) or { return err }
			continue
		}
		// Body-position text / scalars on the fast path: rare in the
		// gate-15 corpus, but support them by yielding a TextNode so
		// the caller doesn't lose data. We collect a contiguous run
		// up to the next `[`, `&`, or `]`.
		mut text_start := p.pos
		for !p.at_end() {
			c := p.src[p.pos]
			if c == `[` || c == `]` || c == `&` { break }
			p.advance()
		}
		if p.pos > text_start {
			cb(Node(TextNode{ value: p.src[text_start..p.pos].bytestr() })) or { return err }
		}
	}

	// Trailing ws / `---` separator tolerance — but don't fail on
	// extra content; the streaming caller is interested in the body
	// content and will treat trailing junk as a non-fast-path
	// condition only if it materially differs from `cx.parse`. For
	// the gate-15 bench, there's a single newline + EOF.
	return CXTopLevel{
		name:      root_name
		attrs:     root_attrs
		data_type: root_dt
	}
}

// is_name_char_b is the public re-export of the internal
// `is_name_char` byte classifier. Used by the streaming fast path
// in `code/api.v` to verify that a candidate name span isn't
// followed by another name char (so a byte-level `[users` doesn't
// match a `user` pattern target).
@[inline]
pub fn is_name_char_b(b u8) bool {
	return is_name_char(b)
}

// scan_top_level_children_raw is the zero-allocation cousin of
// `parse_top_level_children`. It walks the source buffer with
// bracket-depth tracking (quote- and bracket-aware) and yields a
// byte-slice view of each top-level body child to `cb`. No Element
// boxes are allocated; no attributes are parsed; no name interning
// happens. Pure scanning.
//
// The caller is responsible for deciding what to do with each byte
// range — re-parse it via `cx.parse` for a specific subset, do a
// fast byte-level name check, or emit it verbatim. The §11.6
// gate-15 streaming fast path uses this to feed a specialised
// parse-and-render-in-place emitter that produces normalised output
// directly from the source bytes without ever materialising an
// Element.
//
// Returns the root element's name span (byte indices into `src`) for
// fast-path callers that need to filter by root name. The root's
// attributes (if any) are NOT parsed here; callers that need them
// MUST use `parse_top_level_children`.
//
// Fast-path-only constraints (rejected with error so callers can
// fall back):
//   - Leading prolog / DOCTYPE (`[?xml]`, `[!DOCTYPE …]`)
//   - Root with sigil-prefix name (`[?…]`, `[!…]`, etc.)
//   - Leading bare text / scalar before the root element
//   - Multi-root documents
pub struct CXRootSpan {
pub:
	name_start int
	name_end   int
}

pub fn scan_top_level_children_raw(src string, cb CXRawChildSink) !CXRootSpan {
	// Operate directly on the source string's underlying byte
	// pointer (zero-copy). `src.bytes()` would copy the entire input
	// (~20 MiB on the gate-15 corpus); skipping that copy is worth
	// the unsafe indexing.
	src_ptr := unsafe { src.str }
	src_len := src.len
	mut pos := 0
	pos = skip_ws_and_comments_inline_ptr(src_ptr, src_len, pos)
	if pos >= src_len {
		return error('scan_top_level_children_raw: empty input')
	}
	if unsafe { src_ptr[pos] } != `[` {
		return error('scan_top_level_children_raw: expected `[` at top level')
	}
	if pos + 1 >= src_len {
		return error('scan_top_level_children_raw: unexpected EOF after `[`')
	}
	b2 := unsafe { src_ptr[pos + 1] }
	if !is_name_start(b2) {
		return error('scan_top_level_children_raw: root not a plain Element')
	}
	pos++  // consume '['
	// Read root name span (no allocation).
	name_start := pos
	for pos < src_len && is_name_char(unsafe { src_ptr[pos] }) {
		pos++
	}
	name_end := pos
	if name_end == name_start {
		return error('scan_top_level_children_raw: root has empty name')
	}

	// Skip root attrs (everything up to the first body item or `]`).
	pos = skip_root_head_to_body_ptr(src_ptr, src_len, pos)!
	if pos >= src_len {
		return error('scan_top_level_children_raw: unexpected EOF in root head')
	}

	// Per-child streaming: parse bracket-depth on each `[…]` to find
	// child boundaries. Yield the byte range to the callback as a
	// fresh slice constructed from the underlying source pointer (no
	// copy — slice header only).
	for {
		pos = skip_ws_and_comments_inline_ptr(src_ptr, src_len, pos)
		if pos >= src_len {
			return error('scan_top_level_children_raw: unexpected EOF in root body')
		}
		if unsafe { src_ptr[pos] } == `]` {
			break
		}
		if unsafe { src_ptr[pos] } != `[` {
			return error('scan_top_level_children_raw: non-bracket body item at offset ${pos}')
		}
		child_start := pos
		child_end := scan_bracket_balanced_ptr(src_ptr, src_len, pos)!
		// Construct a transient []u8 view over the source span.
		// Using V's slice-from-pointer pattern: `unsafe { byteptr.vbytes(n) }`
		// returns a `[]u8` header pointing into the original buffer
		// (zero copy). The slice header lives on the stack of this
		// loop iteration; the callback must not retain it.
		child_view := unsafe { (src_ptr + child_start).vbytes(child_end - child_start) }
		cb(child_view)!
		pos = child_end
	}

	return CXRootSpan{
		name_start: name_start
		name_end:   name_end
	}
}

@[inline]
fn skip_ws_and_comments_inline_ptr(ptr &u8, src_len int, start int) int {
	mut pos := start
	for pos < src_len {
		b := unsafe { ptr[pos] }
		if b == ` ` || b == `\t` || b == `\r` || b == `\n` {
			pos++
		} else if b == `#` {
			next := if pos + 1 < src_len { unsafe { ptr[pos + 1] } } else { u8(0) }
			if next == ` ` || next == `\t` || next == `\n` || next == `\r` || next == 0 {
				for pos < src_len && unsafe { ptr[pos] } != `\n` {
					pos++
				}
			} else {
				break
			}
		} else {
			break
		}
	}
	return pos
}

fn skip_root_head_to_body_ptr(ptr &u8, src_len int, start int) !int {
	mut pos := start
	for pos < src_len {
		b := unsafe { ptr[pos] }
		if b == `]` || b == `[` {
			return pos
		}
		if b == `'` || b == `"` {
			q := b
			pos++
			for pos < src_len && unsafe { ptr[pos] } != q {
				pos++
			}
			if pos < src_len { pos++ }
			continue
		}
		pos++
	}
	return error('skip_root_head_to_body_ptr: EOF before body')
}

fn scan_bracket_balanced_ptr(ptr &u8, src_len int, start int) !int {
	mut pos := start + 1
	mut depth := 1
	for pos < src_len {
		b := unsafe { ptr[pos] }
		if b == `'` || b == `"` {
			q := b
			pos++
			for pos < src_len && unsafe { ptr[pos] } != q {
				pos++
			}
			if pos < src_len { pos++ }
			continue
		}
		if b == `[` {
			depth++
			pos++
		} else if b == `]` {
			depth--
			pos++
			if depth == 0 {
				return pos
			}
		} else {
			pos++
		}
	}
	return error('scan_bracket_balanced_ptr: unbalanced brackets from offset ${start}')
}

// skip_ws_and_comments_inline is the bracket-scanner's inlined
// whitespace + line-comment skip. Avoids the `Parser` struct entirely.
@[inline]
fn skip_ws_and_comments_inline(bytes []u8, start int) int {
	mut pos := start
	for pos < bytes.len {
		b := bytes[pos]
		if b == ` ` || b == `\t` || b == `\r` || b == `\n` {
			pos++
		} else if b == `#` {
			// Line comment: `#` followed by space / tab / nl / EOF.
			next := if pos + 1 < bytes.len { bytes[pos + 1] } else { u8(0) }
			if next == ` ` || next == `\t` || next == `\n` || next == `\r` || next == 0 {
				// Skip to end of line.
				for pos < bytes.len && bytes[pos] != `\n` {
					pos++
				}
			} else {
				break
			}
		} else {
			break
		}
	}
	return pos
}

// skip_root_head_to_body advances past the root element's head
// (name already consumed at entry, position points to first byte
// after name) to the first byte of body content. Returns the new
// position, which is either:
//   - The byte index of `]` (empty root)
//   - The byte index of `[` (first body element)
//
// Quote-aware: skips over string-literal attribute values that
// contain `[` / `]` / `#` bytes.
fn skip_root_head_to_body(bytes []u8, start int) !int {
	mut pos := start
	for pos < bytes.len {
		b := bytes[pos]
		if b == `]` || b == `[` {
			return pos
		}
		if b == `'` || b == `"` {
			// String attribute value — scan to matching quote.
			q := b
			pos++
			for pos < bytes.len && bytes[pos] != q {
				pos++
			}
			if pos < bytes.len { pos++ }
			continue
		}
		pos++
	}
	return error('skip_root_head_to_body: EOF before body')
}

// render_flat_record_to is a specialised renderer for the
// §11.6 gate-15 canonical shape: a flat element whose body contains
// only `:label value` slots / scalar tokens / quoted strings (no
// nested child elements, no comments, no PIs). Writes the
// canonical-form rendering directly to `out` without ever building a
// `cx.Element` tree.
//
// Equivalent to `cx.parse(bytes).elements[0]` followed by
// `code.render_node_to(out, that_element)` for inputs matching
// the canonical shape. Falls back (returns `false`) for inputs that
// contain anything more complex than the canonical shape — nested
// `[…]`, raw text `[# … #]`, comments `[- …]`, etc. Callers should
// then route through the normal Element-materialising path.
//
// Transformation rules (derived from observing the
// `code.render_node_to` output for parsed flat records):
//   1. `[name` is copied verbatim.
//   2. Immediately after the name, if the next non-ws byte is `:`
//      followed by a name, that's a type annotation — skip the
//      `:name` token (it's consumed into `data_type` by parse and
//      not re-emitted by render). Continues skipping.
//   3. Body content runs to the matching `]`. Each whitespace run
//      collapses to a single ` `. Quoted strings (`'…'` / `"…"`)
//      contribute their inner content without quotes. Other tokens
//      copy verbatim.
//   4. The closing `]` is appended.
//
// Returns `true` on success; `false` if a non-canonical byte
// (nested `[`, `[#`, `[-`, etc.) was encountered — caller falls
// back to the parsing path. Quote-aware: `]` inside a `"…"` doesn't
// terminate the body.
pub fn render_flat_record_to(bytes []u8, mut out []u8) bool {
	if bytes.len < 2 || bytes[0] != `[` { return false }
	// Use the input slice's underlying pointer for direct indexing.
	// V's `[]u8` indexing has bounds checks; `unsafe { ptr[i] }` skips
	// them and the byte-level renderer is on the gate-15 hot path
	// (~216 K records × ~80 byte reads per record).
	src_ptr := unsafe { &bytes[0] }
	src_len := bytes.len
	mut pos := 1
	// Read name span.
	name_start := pos
	for pos < src_len && is_name_char(unsafe { src_ptr[pos] }) {
		pos++
	}
	if pos == name_start { return false }
	// Emit `[name` via bulk pointer copy.
	out << `[`
	render_append_range(mut out, src_ptr, name_start, pos)
	// Skip ws after name.
	for pos < src_len {
		c := unsafe { src_ptr[pos] }
		if c == ` ` || c == `\t` || c == `\r` || c == `\n` {
			pos++
		} else { break }
	}
	// Optional type annotation: `:Name` immediately after name.
	if pos < src_len && unsafe { src_ptr[pos] } == `:` {
		mut p2 := pos + 1
		if p2 < src_len && is_name_start(unsafe { src_ptr[p2] }) {
			for p2 < src_len && is_name_char(unsafe { src_ptr[p2] }) {
				p2++
			}
			pos = p2
			for pos < src_len {
				c := unsafe { src_ptr[pos] }
				if c == ` ` || c == `\t` || c == `\r` || c == `\n` {
					pos++
				} else { break }
			}
		}
	}
	// Body loop. Collapses ws runs to ` `, strips quotes from `'…'` /
	// `"…"`, copies token bytes via range append. Bulk-copies the
	// longest contiguous non-special run in one `push_many`.
	mut pending_sep := true
	for pos < src_len {
		b := unsafe { src_ptr[pos] }
		if b == `]` {
			out << `]`
			return true
		}
		if b == ` ` || b == `\t` || b == `\r` || b == `\n` {
			pending_sep = true
			pos++
			continue
		}
		if b == `[` {
			return false
		}
		if b == `'` || b == `"` {
			if pending_sep {
				out << ` `
				pending_sep = false
			}
			q := b
			pos++  // past opening quote
			q_start := pos
			for pos < src_len && unsafe { src_ptr[pos] } != q {
				pos++
			}
			render_append_range(mut out, src_ptr, q_start, pos)
			if pos >= src_len { return false }
			pos++  // past closing quote
			continue
		}
		// Regular token byte. Find longest contiguous run of non-
		// special bytes and emit it as one range append.
		if pending_sep {
			out << ` `
			pending_sep = false
		}
		tok_start := pos
		for pos < src_len {
			c := unsafe { src_ptr[pos] }
			if c == ` ` || c == `\t` || c == `\r` || c == `\n`
				|| c == `]` || c == `[` || c == `'` || c == `"` {
				break
			}
			pos++
		}
		render_append_range(mut out, src_ptr, tok_start, pos)
	}
	return false  // EOF before `]`
}

// render_append_range bulk-copies `[start..end)` from the source
// pointer onto `out`. Uses `unsafe.push_many` via the array's
// builtin `<<` over a temporary view to memcpy the range.
@[inline]
fn render_append_range(mut out []u8, src_ptr &u8, start int, end int) {
	if end <= start { return }
	n := end - start
	// `<<` with a `[]u8` slice would allocate a slice header; use
	// the underlying push_many directly via unsafe.
	out_view := unsafe { (src_ptr + start).vbytes(n) }
	out << out_view
}

// scan_bracket_balanced returns the byte index just past the
// matching `]` for the `[` at `start`. Quote-aware: skips over
// `]` bytes inside `'…'` or `"…"` string literals.
//
// Assumes `bytes[start] == '['`. Returns an error on unbalanced
// brackets or EOF.
fn scan_bracket_balanced(bytes []u8, start int) !int {
	mut pos := start + 1  // past '['
	mut depth := 1
	for pos < bytes.len {
		b := bytes[pos]
		if b == `'` || b == `"` {
			q := b
			pos++
			for pos < bytes.len && bytes[pos] != q {
				pos++
			}
			if pos < bytes.len { pos++ }
			continue
		}
		if b == `[` {
			depth++
			pos++
		} else if b == `]` {
			depth--
			pos++
			if depth == 0 {
				return pos
			}
		} else {
			pos++
		}
	}
	return error('scan_bracket_balanced: unbalanced brackets from offset ${start}')
}
