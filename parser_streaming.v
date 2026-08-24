module cx

// ── Streaming top-level body reader (§11.6 gate-15; stream 17 W5) ────
//
// `open_top_level_children` / `CXChildStream.next` is the
// streaming-incremental input entry point consumed by the code
// module's [?for] streamed-input fast path (code/streamed_input.v —
// the gate-15 lane): when the program body is the canonical
// `[?for [in $u $doc/user] [yield $u]]` shape, the evaluator PULLS
// top-level children one at a time instead of materializing the whole
// input document.
//
// Rationale: the non-streaming `cx.parse` path materializes the full
// input into a `cx.Node` tree (one allocation per Element box plus
// separate `attrs[]` / `items[]` heaps per element); on a 100 MiB
// JSON-shape corpus that is ~1.1 M live element boxes at peak, and
// GC pressure on the resident working set dominates wall time. The
// streaming reader parses the root head, then hands out each body
// child on demand — peak working set is one in-flight child plus the
// source buffer. Every child goes through the REAL parser
// (`parse_node`), so per-child bytes-to-AST semantics are `cx.parse`'s
// own — transparency by construction, never a parallel parser.
//
// Constraints honoured:
//   - `cx.Node` sumtype shape is unchanged (bindings unaffected).
//   - Non-streaming `cx.parse` is untouched.
//   - Reentrancy: each stream owns its Parser — no module-level
//     mutable state.
//
// STRICTNESS (W5): the reader is deliberately narrow so that a
// completed walk is provably equivalent to `cx.parse` +
// first-element selection; anything outside the narrow shape errors
// and the caller falls back to the materializing path:
//   - The root must be a single plain bracketed Element. Prolog,
//     DOCTYPE, sigil roots (`[?…]`, `[!…]`, `[-…]`), leading text,
//     top-level scalars, and logfmt shapes all error at open.
//   - The root HEAD (name + attrs + optional `::T`) is re-parsed via
//     `cx.parse` on the head's source slice, so head-level validation
//     (duplicate attrs, typed attr reads, reserved-namespace checks
//     on the root) is byte-identical to the materializing path — the
//     reader's `top` carries THAT parse's element meta, never a
//     hand-scanned approximation.
//   - The tail after the root's closing `]` must be whitespace /
//     line comments only, verified when `next` reaches the end.
//     Multi-doc `---` inputs error (the materializing path selects
//     the FIRST document's element; a streaming walk cannot validate
//     the remaining documents without parsing them, so it declines).
//
// NOT resolved here (the caller's contract — see
// code/streamed_input.v): `resolve_ids` is document-global (anchors
// and `#id` declarations cross children), so callers must decline
// inputs that can carry them; namespace + language resolution are
// lexical and downward, so callers resolve each yielded child under
// the root's context (available in `top` BEFORE the first `next`) to
// get results identical to a whole-document `resolve_namespaces`.

// CXTopLevel describes the root element: name, attributes, and the
// optional `::T` annotation — taken from a real `cx.parse` of the
// head slice. Children are NOT materialised here.
pub struct CXTopLevel {
pub:
	name      string
	attrs     []Attribute
	data_type ?string
}

// CXChildStream is the open reader. `top` is valid from open;
// children arrive via `next`.
pub struct CXChildStream {
pub:
	top CXTopLevel
mut:
	p    Parser
	done bool
}

// open_top_level_children walks `src` to the first top-level element
// and validates + reads its head. Children are then pulled with
// `next`.
pub fn open_top_level_children(src string) !CXChildStream {
	mut p := new_parser(src)
	p.skip_ws_and_line_comments()
	if p.at_end() {
		return error('open_top_level_children: empty input')
	}
	if p.peek() != `[` {
		return error('open_top_level_children: expected `[` at top level')
	}
	if p.pos + 1 >= p.src.len {
		return error('open_top_level_children: unexpected EOF after `[`')
	}
	b2 := p.src[p.pos + 1]
	if !is_name_start(b2) {
		return error('open_top_level_children: root is not a plain Element (saw sigil `${b2.ascii_str()}` after `[`)')
	}
	root_open := p.pos
	p.advance() // consume '['
	// Scan past the root head (name + attrs + optional `::T`) to find
	// the body start. This scan locates POSITIONS only — the head's
	// semantics come from the validating re-parse below, so any head
	// the scan cannot split correctly simply fails that parse and the
	// caller falls back.
	p.read_name()!
	for {
		p.skip_ws()
		if p.at_end() {
			break
		}
		b := p.peek()
		if b == `]` {
			break
		}
		if b == `[` {
			break // body starts
		}
		if b == `'` || b == `"` {
			break // body-position scalar
		}
		if b == `#` {
			next_b := if p.pos + 1 < p.src.len { p.src[p.pos + 1] } else { u8(0) }
			if next_b == ` ` || next_b == `\t` || next_b == `\n` || next_b == `\r` || next_b == 0 {
				p.skip_line_comment()
				continue
			}
			// `#name` ID declaration on root — IDs are doc-global;
			// not supported on the streaming path.
			return error('open_top_level_children: root #id declaration not supported on the streaming path')
		}
		if b == `:` {
			if p.pos + 1 < p.src.len && p.src[p.pos + 1] == `:` {
				p.advance() // first ':'
				p.advance() // second ':'
				p.read_type_annotation()!
				break
			}
			break // single ':' → body starts (atom literal)
		}
		if is_name_start(b) {
			tok := p.read_name()!
			if !p.at_end() && p.peek() == `=` {
				p.advance()
				p.read_attr_value_typed()!
			} else {
				// Bare name — body-start; rewind so the body loop
				// (and the head slice) exclude it.
				p.pos -= tok.len
				break
			}
			continue
		}
		return error('open_top_level_children: unexpected `${b.ascii_str()}` in root head')
	}
	// Validate the head through the REAL parser: `[<head>]` must parse
	// to exactly one element. Duplicate attrs, malformed values, and
	// reserved-namespace violations on the root surface here exactly
	// as they would on the materializing path.
	head_src := src[root_open..p.pos] + ']'
	head_doc := parse(head_src) or {
		return error('open_top_level_children: root head does not parse standalone: ${err.msg()}')
	}
	if head_doc.elements.len != 1 {
		return error('open_top_level_children: root head parsed to ${head_doc.elements.len} nodes')
	}
	head_el_node := head_doc.elements[0]
	if head_el_node !is Element {
		return error('open_top_level_children: root head is not an Element')
	}
	head_el := head_el_node as Element
	return CXChildStream{
		top: CXTopLevel{
			name:      head_el.name
			attrs:     head_el.attrs
			data_type: head_el.data_type()
		}
		p:    p
		done: false
	}
}

// next pulls one body child through the real parser. Returns
// (child, true) for each child and (_, false) at the (verified) end
// of the root body; errors on malformed content or a non-empty tail.
// Calling next after the end keeps returning (_, false).
pub fn (mut s CXChildStream) next() !(Node, bool) {
	end_filler := Node(TextNode{})
	if s.done {
		return end_filler, false
	}
	s.p.skip_ws_and_line_comments()
	if s.p.at_end() {
		return error('CXChildStream.next: unexpected EOF in root body')
	}
	bb := s.p.peek()
	if bb == `]` {
		s.p.advance()
		// Strict tail: whitespace / line comments only. Anything else
		// — including a `---` document separator — declines the fast
		// path.
		s.p.skip_ws_and_line_comments()
		if !s.p.at_end() {
			return error('CXChildStream.next: trailing content after root close (multi-doc / junk tail) — streaming declines')
		}
		s.done = true
		return end_filler, false
	}
	if bb == `[` || bb == `&` {
		child := s.p.parse_node()!
		return child, true
	}
	// Body-position text / scalar runs yield a TextNode so the caller
	// does not lose data. Contiguous up to the next `[`, `&`, or `]`.
	text_start := s.p.pos
	for !s.p.at_end() {
		c := s.p.src[s.p.pos]
		if c == `[` || c == `]` || c == `&` {
			break
		}
		s.p.advance()
	}
	if s.p.pos > text_start {
		return Node(TextNode{
			value: s.p.src[text_start..s.p.pos].bytestr()
		}), true
	}
	return error('CXChildStream.next: no progress in root body')
}

// ChildValidation is one step of a VALIDATION-ONLY walk (the caller's
// PASS 1). `certified` means the validating span scan recognised the
// child outright — it is well-formed and its per-child resolve is a
// provable no-op, so no node was built and `node` is meaningless.
// Otherwise `node` carries the real parser's result and the caller must
// resolve it exactly as before.
pub struct ChildValidation {
pub:
	has       bool
	certified bool
	node      Node
}

// next_lazy advances past one body child for the EVALUATION walk (#804
// leg 2), returning a `LazyRecord` when the child is inside the certified
// subset and the real parser's node otherwise. It returns `has: false` at
// the end of the root body exactly as `next` does.
//
// The verdict it reaches is IDENTICAL to `next`'s in every case: a
// certified child is one the parser accepts (pinned differentially by
// `child_scan_differential_test.v`), and every other child goes through
// `next`'s own code path.
//
// `allow_scan` is the caller's per-stream gate, and it must be false
// whenever the root can contribute a namespace or language binding
// downward (see `CXTopLevel.top_is_namespace_free`) — a lazy record skips
// the per-child resolve on the strength of that resolve being a provable
// no-op, which is what the namespace-free root buys.
//
// It once had a twin, `next_validated`, which certified a child and
// discarded it: leg 1 built it for PASS 1's validation walk, and leg 3
// deleted PASS 1. It was retired at leg 9 rather than kept as a public
// seam with no consumer. Its own profile is the reason it is worth
// recording that it existed: because it returned a `ChildValidation` with
// the `node` field DEFAULTED, and `Node`'s first variant is `Element`, V
// emitted three heap allocations per record — the boxed zero Element plus
// empty `attrs` and `items` arrays — for a field its caller never read.
// That is a general hazard, not a fact about this function: a `cx.Node`
// field left unset in a struct literal is not free.
pub fn (mut s CXChildStream) next_lazy(allow_scan bool) !ChildValidation {
	if s.done {
		return ChildValidation{}
	}
	if allow_scan {
		s.p.skip_ws_and_line_comments()
		if !s.p.at_end() && s.p.peek() == `[` {
			at := s.p.pos
			if sc := scan_child_canonical(s.p.src, at) {
				// #804 leg 10 — O(1) position update, not a second byte walk.
				// `skip_span_to` re-read every byte of the span to keep
				// line/col accurate for a later error message; the scan now
				// reports the tally it collected for free, so the same
				// line/col falls out of arithmetic.
				s.p.jump_span_to(sc.end, sc.newlines, sc.last_nl)
				return ChildValidation{
					has:       true
					certified: true
					node:      new_lazy_record(s.p.src, at, sc)
				}
			}
			// Declined — position untouched, so `next` re-reads the bytes.
		}
	}
	node, has := s.next()!
	return ChildValidation{
		has:  has
		node: node
	}
}

// is_name_char_b / is_name_start_b are the public re-exports of the
// internal byte classifiers, used by the code module's streamed-input
// precondition scans (code/streamed_input.v).
@[inline]
pub fn is_name_char_b(b u8) bool {
	return is_name_char(b)
}

@[inline]
pub fn is_name_start_b(b u8) bool {
	return is_name_start(b)
}
