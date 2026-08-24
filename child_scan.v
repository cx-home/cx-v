module cx

// ── The validating span scan (#804 leg 1, architecture 804-1c) ────────
//
// `scan_child_certified` walks the bytes of ONE top-level body child and
// answers a single question: is this child well-formed, WITHOUT building
// any part of its typed AST? It returns the offset just past the child's
// closing `]`, or `none`.
//
// WHY THIS IS NOT A SECOND PARSER. A complete second acceptor for the CX
// grammar would be exactly the duplication 804-1c declined for the fused
// renderer — two readings of one language that must agree forever. This
// is not that. The scan is a SOUND RECOGNIZER FOR A SUBSET: it certifies
// only shapes it fully understands and declines everything else, and a
// declined child is handed to the REAL parser verbatim. So the set of
// inputs the engine accepts is unchanged by construction — the scan can
// only move work off the parser, never change the verdict.
//
// The correctness obligation is therefore one-directional and total:
//
//     scan certifies span  ⇒  parse(span) succeeds
//
// The converse is explicitly NOT required (a parseable child the scan
// declines is merely slower). That asymmetry is what makes the subset
// safely extensible, and it is pinned differentially in
// `vcx/tests/child_scan_differential_test.v`, which runs the scan and
// the parser against every conformance input, the gate-15 corpus, and a
// mutation corpus, and fails on any certified-but-unparseable span.
//
// WHY IT EXISTS. `code/streamed_input.v` PASS 1 is a full validation
// walk that parses and resolves every child and retains nothing — a
// stated correctness property (an input the materializing path would
// refuse must decline PRE-EMISSION), and measured at ~42% of gate-15's
// total samples. The scan keeps the property and deletes the
// materialization: certified children are validated by the walk alone.
//
// THE SUBSET (v1) is deliberately narrow — the JSON-record shape that
// gate 15 and the common adopter workload actually carry:
//
//     child   := '[' name ( ws item )* ws? ']'
//     item    := child | slot | attr | value
//     slot    := ':' name ws value
//     attr    := name '=' value
//     value   := int | decimal | 'true' | 'false' | 'null' | qstring
//
// with these conservative restrictions, each of which exists to keep a
// subtle parser behaviour OUT of the subset rather than to re-implement
// it:
//
//   - Names are ASCII `[A-Za-z_][A-Za-z0-9_-]*`. A `:` or `.` in a name
//     position declines — that keeps QNames, the `::T` type-tag
//     separator, and every namespace question outside the subset.
//   - Attribute names may not be `xmlns`, and the stream's ROOT must be
//     namespace-free (`top_is_namespace_free`). Together these make the
//     caller's per-child `resolve_namespaces` +
//     `validate_reserved_ns_bindings` a provable no-op for a certified
//     child, which is why the scan may stand in for it.
//   - Quoted strings carry no backslash and no newline. Escape decoding
//     is the one place where "well-formed" and "what it means" are not
//     the same question, so it is excluded.
//   - Bare body tokens decline. The parser folds contiguous bare text
//     into a TextNode under boundary rules that are genuinely subtle;
//     `true` / `false` / `null` are admitted as the three keyword
//     scalars only when a separator follows.
//   - `&`, `#`, `*`, `$`, `@`, `,`, `(`, `)`, `{`, `}`, `<`, `!`, `?`
//     at item position decline — anchors, ids, merges, holes, sequence
//     / array / map literals, declarations and directives all leave the
//     subset.
//
// Widening the subset later is a safe, incremental move: each addition
// is a new arm plus its rows in the differential gate.

// max_scan_depth caps nesting so a pathological input cannot drive the
// scan into unbounded recursion. Deeper children simply decline to the
// real parser, which carries its own depth handling.
const max_scan_depth = 64

// top_is_namespace_free reports whether the stream's root element can
// contribute NO namespace or language binding to its children. When it
// answers false the caller must not certify any child of that stream:
// an inherited default namespace or `cx:lang` scope means the per-child
// resolve is no longer a no-op.
pub fn (t CXTopLevel) top_is_namespace_free() bool {
	if t.name.contains(':') {
		return false
	}
	for a in t.attrs {
		if a.name == 'xmlns' || a.name.contains(':') {
			return false
		}
	}
	return true
}

// scan_child_certified attempts to recognise ONE element of the
// certified subset beginning at `src[start]`, which MUST be `[`.
// Returns the offset just past its closing `]`, or `none` when the
// child falls outside the subset. Allocation-free and side-effect-free:
// on `none` the caller simply re-reads the same bytes with the real
// parser.
pub fn scan_child_certified(src []u8, start int) ?int {
	if start >= src.len || src[start] != `[` {
		return none
	}
	mut st := ScanState{
		want_canonical: false
	}
	i := scan_element(src, start, 0, mut st) or { return none }
	return i
}

// ── canonicality (804-1d, ruled 1a) ───────────────────────────────────
//
// The same walk that certifies a child also decides whether its SOURCE
// BYTES are already the canonical image, so render can emit the span
// instead of materialising. The predicate is CONSERVATIVE by ruling:
// any uncertainty answers "not canonical". A false negative costs
// throughput; a false positive corrupts canonical output, and Tier-1
// addresses with it.
//
// One rewrite is admitted, and only one: the STRING DELIMITER. Canonical
// CX prefers `'…'` (cx_choose_quote, owner-ruled L16/W-13) while
// JSON-shape input — the workload §11.4.4 exists to measure — spells
// strings `"…"`. Measured on the gate corpus: 0% of records are
// strictly byte-canonical and 100% are canonical after that swap, so a
// strict-identity predicate would claim none of the architecture's win.
// Ruled 1a: the scan records the delimiter offsets and render emits the
// span through them.
//
// This is a narrow second reading of ONE canonicalization rule, and the
// thing that makes it safe is that it is TOTALLY checkable rather than
// checkable-in-the-cases-we-thought-of: for every span the scan calls
// canonical, `apply_rewrites(span) == render_canonical(parse(span))` is
// asserted over the conformance corpus, the gate workload and a
// mutation corpus. That is the property a fused renderer could not
// offer, and the reason 804-1c declined one.
//
// The rules below are measured against the real renderer, not assumed:
//   - Spacing is exactly one space between items and none before `]`
//     (`[k ]` renders `[k]`).
//   - Integers are fixed points for `-?(0|[1-9][0-9]*)` at ANY precision
//     (bigint renders its digits verbatim). Negative zero is not.
//   - Decimals are carried VERBATIM, trailing zeros included — `10.50`
//     renders `10.50`. So this is a syntax check, not a float
//     round-trip.
//   - A `'…'` string is already canonical. A `"…"` string is canonical
//     as-is when its content contains a `'` (the renderer would pick
//     `"` too), and otherwise needs the two delimiter bytes rewritten.
//     Empty content is never canonical — it renders as nothing.
//   - Attributes are conservatively excluded: the renderer emits
//     attribute values BARE when safe (`a="x"` → `a=x`), which is a
//     second normalisation this predicate does not model.

// rewrites_inline_cap is how many rewrite offsets a record carries WITHOUT
// touching the heap. Each rewritten string contributes two (its opening and
// closing delimiter), so 8 covers a record with four quoted strings — the
// §11.4.4 gate record carries two. Wider records spill and stay correct.
pub const rewrites_inline_cap = 8

// RewriteSet is the record's list of `"`-offsets-to-emit-as-`'`, held INLINE
// (#804 leg 8).
//
// It used to be a plain `[]int` grown by `<<`, which cost one or more heap
// allocations PER RECORD — and the cost was not just the allocation. Profiling
// the for-shape after leg 7 put `array_push → array_ensure_cap → vgc_malloc`
// at ~6% of samples directly, while the collector those allocations feed was a
// further ~22% attributed across every site that happened to trip the pacer.
// Per-record allocation is the thing this leg is removing; the array was the
// last easy one.
//
// WHY INLINE RATHER THAN A REUSED BUFFER. A single scratch buffer reused
// across children would be cheaper still and is UNSOUND: deferred commit holds
// a record in `pending` across an iteration, so its slice would alias a buffer
// the next child's scan overwrites — a wrong ANSWER, silently, on a
// well-formed input. A value-typed inline array cannot alias, because it is
// copied with the struct that holds it. Soundness by construction beats
// soundness by argument here, and the argument was already available and
// already wrong once.
pub struct RewriteSet {
pub mut:
	buf [rewrites_inline_cap]int
	// len counts ALL offsets, inline plus spilled.
	len int
	// spill holds offsets past the inline capacity — allocated only for a
	// record with more than `rewrites_inline_cap` of them, which the gate
	// corpus never produces and a wide record legitimately does.
	spill []int
}

@[inline]
pub fn (mut r RewriteSet) push(v int) {
	if r.len < rewrites_inline_cap {
		r.buf[r.len] = v
		r.len++
		return
	}
	r.spill << v
	r.len++
}

// get returns the i-th offset in scan order, inline then spilled.
@[inline]
pub fn (r RewriteSet) get(i int) int {
	if i < rewrites_inline_cap {
		return r.buf[i]
	}
	return r.spill[i - rewrites_inline_cap]
}

// CanonicalScan is the result of a canonicality-computing scan.
pub struct CanonicalScan {
pub:
	// end is the offset just past the child's closing `]`.
	end int
	// canonical reports that the span, with `rewrites` applied, is
	// exactly what the canonical renderer would produce.
	canonical bool
	// rewrites holds absolute offsets of `"` bytes that must be emitted
	// as `'`. Empty means the span is emittable verbatim.
	rewrites RewriteSet
	// name_start / name_end delimit the element's NAME within the source
	// buffer. The scan walks the name anyway to certify it, so reporting
	// where it was costs nothing — and it is what lets a lazy record
	// answer the streamed walk's `el.name != step1.name` compare without
	// materialising (#804 leg 2).
	name_start int
	name_end   int
	// #804 leg 10 — the span's newline tally and the offset of its last
	// newline, so a caller can update line/col in O(1) instead of re-walking
	// every byte of a span this scan just read. See ScanState.newlines for why
	// counting only the whitespace runs is exact inside a certified span.
	newlines int
	last_nl  int
}

// name_eq compares a scanned name against a literal without allocating.
// The streamed walk runs this once per child on the hot path.
@[inline]
pub fn (c CanonicalScan) name_eq(src []u8, lit string) bool {
	return span_eq(src, c.name_start, c.name_end, lit)
}

// name_str materialises the scanned name. Off the hot path — the walk
// uses `name_eq`; this is for building the lazy record once a child has
// already been selected.
@[inline]
pub fn (c CanonicalScan) name_str(src []u8) string {
	return src[c.name_start..c.name_end].bytestr()
}

// scan_child_canonical certifies a child AND decides canonicality.
// Returns none when the child is outside the certified subset.
pub fn scan_child_canonical(src []u8, start int) ?CanonicalScan {
	if start >= src.len || src[start] != `[` {
		return none
	}
	mut st := ScanState{
		want_canonical: true
	}
	end := scan_element(src, start, 0, mut st) or { return none }
	return CanonicalScan{
		end:        end
		canonical:  st.canonical
		rewrites:   st.rewrites
		name_start: st.name_start
		name_end:   st.name_end
		newlines:   st.newlines
		last_nl:    st.last_nl
	}
}

// apply_rewrites renders the canonical image of a certified-canonical
// span: the source bytes with each recorded offset emitted as `'`.
// `offset` is where `span` starts in the buffer the rewrites index.
pub fn apply_rewrites(span []u8, offset int, rewrites RewriteSet) string {
	if rewrites.len == 0 {
		return span.bytestr()
	}
	mut out := span.clone()
	for i in 0 .. rewrites.len {
		k := rewrites.get(i) - offset
		if k >= 0 && k < out.len {
			out[k] = `'`
		}
	}
	return out.bytestr()
}

// ScanState carries the canonicality verdict through the walk. When
// `want_canonical` is false the scan does no canonicality work and
// never allocates — that is the mode PASS 1's validation walk uses.
struct ScanState {
	want_canonical bool
mut:
	canonical bool = true
	rewrites  RewriteSet
	// #804 leg 10 — the span's NEWLINE TALLY, accumulated by the whitespace
	// walk this scan already performs.
	//
	// `Parser.skip_span_to` used to re-walk every byte of the certified span
	// purely to keep `line`/`col` accurate for a LATER error message — a second
	// full pass over bytes this scan had just read. The scan can count them for
	// free, so the position update becomes O(1).
	//
	// WHY THE WHITESPACE WALK IS SUFFICIENT, which is what makes the tally
	// exact rather than approximate: inside a CERTIFIED span a newline cannot
	// occur anywhere else. `scan_qstring_v` declines a string containing a
	// newline, a `#` comment declines the whole child, and names / numbers /
	// keyword scalars cannot contain one. So every newline in the span is in a
	// run that `skip_scan_ws` walks.
	newlines int
	// last_nl is the ABSOLUTE offset of the last newline seen, or -1. `col`
	// after the jump is `end - last_nl` when one was seen (bytes following it,
	// 1-based), which is what the byte loop computed.
	last_nl int = -1
	// The OUTERMOST element's name span, recorded by the first
	// `scan_element` to run (depth 0). Nested children overwrite nothing
	// — the record's own name is the one a lazy node needs.
	name_start int
	name_end   int
}

@[inline]
fn (mut s ScanState) not_canonical() {
	s.canonical = false
}

// scan_element scans one `[...]` element and returns the offset just
// past its `]`.
fn scan_element(src []u8, at int, depth int, mut st ScanState) ?int {
	if depth > max_scan_depth {
		return none
	}
	mut i := at
	if i >= src.len || src[i] != `[` {
		return none
	}
	i++
	// Element name.
	name_at := i
	i = scan_plain_name(src, i)?
	if depth == 0 {
		st.name_start = name_at
		st.name_end = i
	}
	// Body items.
	for {
		ws_start := i
		i = skip_scan_ws(src, i, mut st)
		if i >= src.len {
			return none // unterminated element
		}
		b := src[i]
		if b == `]` {
			// Canonical form has no space before the close: `[k ]`
			// renders `[k]`.
			if i != ws_start {
				st.not_canonical()
			}
			return i + 1
		}
		// Every item after the name must be whitespace-separated from
		// what precedes it. Without this, `[k a=1b=2]` would scan as two
		// items where the parser reads one malformed attribute value.
		if i == ws_start {
			return none
		}
		// Canonical form separates items by exactly one space.
		if i != ws_start + 1 || src[ws_start] != ` ` {
			st.not_canonical()
		}
		if b == `[` {
			i = scan_element(src, i, depth + 1, mut st)?
			continue
		}
		if b == `:` {
			i = scan_slot(src, i, depth, mut st)?
			continue
		}
		if is_name_start(b) {
			i = scan_attr_or_keyword(src, i, mut st)?
			continue
		}
		if b == `'` || b == `"` {
			i = scan_qstring_v(src, i, mut st)?
			continue
		}
		if b == `-` || is_digit(b) {
			i = scan_number(src, i, mut st)?
			continue
		}
		return none // outside the subset
	}
	return none
}

// scan_plain_name scans an ASCII `[A-Za-z_][A-Za-z0-9_-]*` name and
// returns the offset just past it. A `:` or `.` immediately following
// the name declines — that is a QName, a `::T` type tag, or a dotted
// name, all outside the subset.
fn scan_plain_name(src []u8, at int) ?int {
	mut i := at
	if i >= src.len || !is_name_start(src[i]) {
		return none
	}
	i++
	for i < src.len && is_ident_part(src[i]) {
		i++
	}
	if i < src.len && (src[i] == `:` || src[i] == `.`) {
		return none
	}
	return i
}

// scan_slot scans `:name value` — the slot form the JSON-record shape
// uses for every field. An atom (`:name` with no value following) is
// NOT in the subset: distinguishing a slot from a bare atom needs the
// parser's lookahead, so both decline.
fn scan_slot(src []u8, at int, depth int, mut st ScanState) ?int {
	mut i := at + 1 // past ':'
	i = scan_plain_name(src, i)?
	// A value MUST follow, whitespace-separated.
	ws_start := i
	i = skip_scan_ws(src, i, mut st)
	if i == ws_start || i >= src.len {
		return none
	}
	// Canonical form is `:name value` — exactly one space.
	if i != ws_start + 1 || src[ws_start] != ` ` {
		st.not_canonical()
	}
	b := src[i]
	if b == `[` {
		return scan_element(src, i, depth + 1, mut st)
	}
	return scan_value(src, i, mut st)
}

// scan_attr_or_keyword scans either `name=value` or one of the three
// bare keyword scalars (`true` / `false` / `null`). Any other bare
// name-led token declines — bare body text is outside the subset.
fn scan_attr_or_keyword(src []u8, at int, mut st ScanState) ?int {
	end := scan_plain_name(src, at)?
	if end < src.len && src[end] == `=` {
		if span_eq(src, at, end, 'xmlns') {
			return none // a namespace binding — outside the subset
		}
		// Attributes are conservatively outside the CANONICAL subset:
		// the renderer emits attribute values bare when safe
		// (`a="x"` → `a=x`), a normalisation this predicate does not
		// model. Certification is unaffected.
		st.not_canonical()
		return scan_value(src, end + 1, mut st)
	}
	// Bare token: only the three keyword scalars, and only when the
	// token ends at a real separator.
	if !ends_at_separator(src, end) {
		return none
	}
	if span_eq(src, at, end, 'true') || span_eq(src, at, end, 'false')
		|| span_eq(src, at, end, 'null') {
		return end
	}
	return none
}

// span_eq compares `src[from..to]` with an ASCII literal without
// allocating the slice as a string — the scan runs once per child on
// the gate-15 hot path, so it may not allocate.
@[inline]
fn span_eq(src []u8, from int, to int, lit string) bool {
	if to - from != lit.len {
		return false
	}
	for k in 0 .. lit.len {
		if src[from + k] != lit[k] {
			return false
		}
	}
	return true
}

// ends_at_separator reports whether the token ending at `at` is
// followed by whitespace or the element's closing `]`. A token that
// runs straight into another character (`123abc`, `truthy`) is not the
// token the scan thought it was reading.
@[inline]
fn ends_at_separator(src []u8, at int) bool {
	if at >= src.len {
		return false
	}
	c := src[at]
	return c == ` ` || c == `\t` || c == `\r` || c == `\n` || c == `]`
}

// scan_value scans one scalar value and returns the offset past it.
fn scan_value(src []u8, at int, mut st ScanState) ?int {
	if at >= src.len {
		return none
	}
	b := src[at]
	if b == `'` || b == `"` {
		return scan_qstring_v(src, at, mut st)
	}
	if b == `-` || is_digit(b) {
		return scan_number(src, at, mut st)
	}
	if is_name_start(b) {
		end := scan_plain_name(src, at)?
		if !ends_at_separator(src, end) {
			return none
		}
		if span_eq(src, at, end, 'true') || span_eq(src, at, end, 'false')
			|| span_eq(src, at, end, 'null') {
			return end
		}
		return none
	}
	return none
}

// scan_qstring scans a `'…'` or `"…"` string containing no backslash
// and no newline, and returns the offset past the closing delimiter.
// Escape-bearing and multi-line strings decline: decoding an escape is
// where well-formedness stops being a purely syntactic question.
fn scan_qstring_v(src []u8, at int, mut st ScanState) ?int {
	q := src[at]
	mut i := at + 1
	mut has_single := false
	mut has_control := false
	for i < src.len {
		c := src[i]
		if c == q {
			if st.want_canonical {
				st.judge_string(q, at, i, has_single, has_control)
			}
			return i + 1
		}
		if c == `\\` || c == `\n` || c == `\r` {
			return none
		}
		if c == `'` {
			has_single = true
		}
		// Canonical quoted text NEVER carries a raw control byte —
		// `cx_escape_quoted` emits `\t` and `\u00xx` for the whole C0
		// range plus DEL (§2.4, I1 L15/W-12). Such content still PARSES,
		// so it stays certified; it just is not its own image. Found by
		// the mutation corpus, not by reading the escaper.
		if c < 0x20 || c == 0x7f {
			has_control = true
		}
		i++
	}
	return none // unterminated
}

// judge_string applies `cx_choose_quote`'s rule to the string delimited
// by `q` whose quotes sit at `open` and `close`.
//
// The renderer picks `'…'` when the content has no `'`, and `"…"`
// otherwise. Escapes have already declined, so the content cannot
// contain the delimiter itself — which means a `'…'` source is always
// already canonical, and only a `"…"` source can need the swap.
fn (mut st ScanState) judge_string(q u8, open int, close int, has_single bool, has_control bool) {
	if close == open + 1 {
		// Empty content renders as NOTHING in body position, not as a
		// pair of quotes.
		st.not_canonical()
		return
	}
	if has_control {
		st.not_canonical()
		return
	}
	if q == `'` {
		return // no `'` can be inside, so this is the renderer's choice
	}
	if has_single {
		return // content carries a `'`, so `"…"` IS the canonical form
	}
	// A `"…"` source whose content has no `'`: canonical form is the
	// same bytes with both delimiters swapped.
	st.rewrites.push(open)
	st.rewrites.push(close)
}

// scan_number scans an integer or a fixed-point decimal — `-?` digits,
// optionally `.` digits — and returns the offset past it. Leading
// zeros, `+`, `_` separators, radix prefixes and exponents all decline;
// so does any token that does not end at a separator (`123abc`,
// `2024-01-15`, `1h30m`).
fn scan_number(src []u8, at int, mut st ScanState) ?int {
	mut i := at
	negative := i < src.len && src[i] == `-`
	if negative {
		i++
	}
	int_start := i
	mut all_zero := true
	for i < src.len && is_digit(src[i]) {
		if src[i] != `0` {
			all_zero = false
		}
		i++
	}
	if i == int_start {
		return none // no digits
	}
	// No leading zeros: `0` alone is fine, `007` is not.
	if src[int_start] == `0` && i - int_start > 1 {
		return none
	}
	if i < src.len && src[i] == `.` {
		i++
		frac_start := i
		for i < src.len && is_digit(src[i]) {
			if src[i] != `0` {
				all_zero = false
			}
			i++
		}
		if i == frac_start {
			return none // `5.` is not in the subset
		}
	}
	if !ends_at_separator(src, i) {
		return none
	}
	// NEGATIVE ZERO is well-formed but not canonical: `-0` renders `0`
	// and `-0.0` renders `0.0`. Everything else in this shape is a fixed
	// point of the renderer, decimals verbatim (`10.50` stays `10.50`).
	if negative && all_zero {
		st.not_canonical()
	}
	return i
}

// skip_span_to moves the parser to `end` — a position the span scan has
// already proved is the far side of a well-formed child — keeping
// `line` / `col` accurate so any LATER error in the same walk still
// reports a true position.
//
// It is a byte loop rather than a bare `pos = end` for exactly that
// reason. The cost is one branch per byte of an already-hot span with
// no allocation and no bounds re-check; folding the newline count into
// the scan itself would save that pass, and is worth doing only if a
// profile ever shows it.
// jump_span_to moves `pos` to `end` in O(1), given the newline tally the scan
// already collected (#804 leg 10).
//
// It computes exactly what `skip_span_to`'s byte loop computed: each newline
// advances `line` and resets `col` to 1, each other byte advances `col`. So
// with `n` newlines whose last one sits at absolute offset `last_nl`, the
// result is `line + n` and `col = end - last_nl` (the bytes following that
// newline, 1-based). With no newline, `col` simply advances by the span width.
//
// `skip_span_to` stays: it is the honest fallback for any caller that does not
// have a tally, and its loop is the definition this arithmetic must match.
@[inline]
fn (mut p Parser) jump_span_to(end int, newlines int, last_nl int) {
	if end <= p.pos {
		return
	}
	if newlines > 0 && last_nl >= p.pos {
		p.line += newlines
		p.col = end - last_nl
	} else {
		p.col += end - p.pos
	}
	p.pos = if end < p.src.len { end } else { p.src.len }
}

fn (mut p Parser) skip_span_to(end int) {
	for p.pos < end && p.pos < p.src.len {
		if p.src[p.pos] == `\n` {
			p.line++
			p.col = 1
		} else {
			p.col++
		}
		p.pos++
	}
}

// skip_scan_ws advances past spaces, tabs, CR and LF. It deliberately
// does NOT skip line comments: a `#` anywhere inside a child declines
// the whole child, so comment-boundary handling stays with the parser.
@[inline]
fn skip_scan_ws(src []u8, at int, mut st ScanState) int {
	mut i := at
	for i < src.len {
		c := src[i]
		if c == ` ` || c == `\t` || c == `\r` || c == `\n` {
			if c == `\n` {
				// #804 leg 10 — free: this loop is already reading the byte.
				st.newlines++
				st.last_nl = i
			}
			i++
		} else {
			break
		}
	}
	return i
}
