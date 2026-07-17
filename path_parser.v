module cx

// path_parser.v — CXPath surface-text → PathNode parser (Phase 2.3 complete).
//
// Per (CXPath as value-kind) the parser produces the spec-canonical
// `PathNode` AST defined in path_node.v. Phase 2.3 covers grammar productions
// [130]–[131b] + [135]:
//
//   - PathExpr form discriminator (//, /, bare-name, $NAME/) per [130] + [135]
//   - Multi-step paths            per [130a]    `( '/' Step )*`
//   - Interior `//` descendant shorthand per [130a] — interior `//` lowers to
//     a step on the `descendant-or-self` axis with NodeTest `node()` followed
//     by the next explicit step (we represent this as one step with
//     `axis=.descendant_or_self`)
//   - AxisSpecifier prefix (12 axes) per [131a]
//   - NodeTest: bare Name + wildcard `*` + kind-tests
//     (`node()` / `text()` / `element()` / `attribute()`) + prefixed QName
//     (`prefix:local`) per [131b]
//   - Multi-predicate steps       per [132]   `Predicate*`
//   - BindingPath descendant `$u//item` per [135]  (interior `//` flavour)
//   - Trailing top-level predicates per [135] tail `Predicate*`
// step-terminator rule: a Step-trailing `:` followed by
//     a closed-set modifier keyword terminates the path WITHOUT being
//     consumed; a bare `:` also terminates (parser leaves the byte alone).
//
// Out of scope at this slice (returns explicit deferred-feature errors):
//   - Namespace-wildcard NodeTest `*:Local` and `Prefix:*` — deferred until
//     the namespace resolution hook lands; these surface as
//     CXPATH_NODETEST_NOT_YET_IMPLEMENTED.
//   - Predicate body parsing into a structural ProgramExpr (Phase 2.4 graft).
//
// Cross-references:
//   - spec/grammar.ebnf productions [130]–[135]
//   - vcx/cx/path_node.v (Phase 2.1 PathNode AST)

// ── Closed modifier-keyword set ───────────────────────────────
//
// Step-trailing `:LABEL` where LABEL is one of these names terminates the
// path; the `:LABEL` belongs to the enclosing directive (e.g., `[?modify]`
// action, `[?for]` clause). The list mirrors the
// spec/grammar.ebnf [131b] disambiguation note.
//
// NOTE: the spec calls this list authoritative in spec/code.md. The V
// reference implementation embeds the list here; any spec addition cascades
// to this constant in lockstep.
const path_step_terminator_labels = [
	'append', 'as', 'bind', 'case', 'delete', 'delete-attr', 'direct',
	'else', 'group-by', 'impure', 'in', 'in-memory', 'insert-after',
	'insert-before', 'lazy', 'let', 'on-error', 'only', 'order-by',
	'prepend', 'pure', 'rename', 'replace', 'rest', 'returns', 'scope',
	'set', 'set-attr', 'table', 'throws', 'using', 'version', 'when',
	'where', 'yield',
]

// ── Internal cursor ───────────────────────────────────────────────────────────

// PathParseCursor is a private byte-position cursor over the source string.
// Kept deliberately small — the Phase 2.3 scope doesn't need the line/col
// tracking the main Parser does.
struct PathParseCursor {
mut:
	src []u8
	pos int
}

@[inline]
fn (c &PathParseCursor) at_end() bool {
	return c.pos >= c.src.len
}

@[inline]
fn (c &PathParseCursor) peek() u8 {
	if c.pos < c.src.len {
		return c.src[c.pos]
	}
	return 0
}

@[inline]
fn (c &PathParseCursor) peek_at(off int) u8 {
	if c.pos + off < c.src.len {
		return c.src[c.pos + off]
	}
	return 0
}

@[inline]
fn (mut c PathParseCursor) advance() {
	if c.pos < c.src.len {
		c.pos++
	}
}

@[inline]
fn path_is_name_start(b u8) bool {
	return (b >= `a` && b <= `z`) || (b >= `A` && b <= `Z`) || b == `_`
}

@[inline]
fn path_is_name_cont(b u8) bool {
	return path_is_name_start(b) || (b >= `0` && b <= `9`) || b == `-`
}

@[inline]
fn path_is_space(b u8) bool {
	return b == ` ` || b == `\t` || b == `\n` || b == `\r`
}

// read_name reads a [_A-Za-z][_A-Za-z0-9-]* identifier from the cursor.
// Returns the start..end byte range as a string. Caller checks for empty.
fn (mut c PathParseCursor) read_name() string {
	start := c.pos
	if c.at_end() || !path_is_name_start(c.peek()) {
		return ''
	}
	c.advance()
	for !c.at_end() && path_is_name_cont(c.peek()) {
		c.advance()
	}
	return c.src[start..c.pos].bytestr()
}

// ── Public entry points ───────────────────────────────────────────────────────

// parse_path parses a CXPath fragment (the value-kind surface text from
// ) into a PathNode. Phase 2.3 covers form discriminator + multi-step
// multi-predicate + wildcard `*` NodeTest step-terminator
// rule. See file header for the deferred-feature error contract.
//
// On success the returned PathNode has:
//   - form set per the leading-token shape ([130] discriminator + [135])
//   - binding set when form == .binding (the identifier with no `$`)
//   - one-or-more PathStep in `steps`
//   - source set to the verbatim input
//   - loc set to span 0..source.len (col=1 origin)
//
// The parser REQUIRES all input bytes to be consumed unless the trailing
// remainder begins at a §D12 step-terminator boundary. Callers that need
// to recover the unconsumed tail (e.g., a directive parser pulling the
// path out of `[?modify $d //foo :using …]`) use `parse_path_consumed`.
pub fn parse_path(source string) !PathNode {
	node, consumed := parse_path_consumed(source)!
	if consumed != source.len {
		return error('CXPATH_PARSE: unexpected trailing input at position ${consumed}: ${source[consumed..]}')
	}
	return node
}

// parse_path_consumed is the variant that returns the byte count consumed
// off the input. It is the right entry point for callers that embed a
// CXPath fragment inside a wider directive surface (per 
// step-terminator) — the unconsumed remainder starts at `source[consumed..]`
// and belongs to the enclosing directive parser.
pub fn parse_path_consumed(source string) !(PathNode, int) {
	if source.len == 0 {
		return error('CXPATH_PARSE: empty input')
	}
	mut c := PathParseCursor{ src: source.bytes(), pos: 0 }

	// Form discriminator: $NAME/ → binding | // → descendant
	//                     / → absolute | otherwise → relative
	mut form := PathForm.relative
	mut binding := ?string(none)

	if c.peek() == `$` {
		c.advance()
		name := c.read_name()
		if name.len == 0 {
			return error('CXPATH_PARSE: expected binding identifier after \$')
		}
		// `$name` MUST be followed by `/` or `//` (binding paths require a
		// step list per [135]).
		if c.at_end() || c.peek() != `/` {
			return error('CXPATH_PARSE: expected "/" or "//" after \$${name}')
		}
		form = PathForm.binding
		binding = name
		// Fall through; the leading-slash handler below classifies the step.
		// For binding form the leading `/` does NOT change `form` —
		// it just indicates which kind of step follows.
	}

	// Slash handling. For non-binding paths, `//` vs `/` sets the form.
	// For binding paths, the leading `/` is consumed before the first step;
	// the descendant flavour `$u//item` is still deferred at this slice.
	mut leading_slashes := 0
	if !c.at_end() && c.peek() == `/` {
		c.advance()
		leading_slashes = 1
		if !c.at_end() && c.peek() == `/` {
			c.advance()
			leading_slashes = 2
		}
	}

	// `leading_descendant_or_self` carries the binding-form `$u//…` flavour
	// down to the first step so it can be tagged with the
	// `descendant-or-self` axis (the interior-`//` shorthand from [130a]).
	mut leading_descendant_or_self := false
	if form != PathForm.binding {
		match leading_slashes {
			0 { form = PathForm.relative }
			1 { form = PathForm.absolute }
			2 { form = PathForm.descendant }
			else {}
		}
	} else {
		// Binding form: `$u/…` keeps form=.binding; `$u//…` keeps form=.binding
		// AND marks the first step with the descendant-or-self axis.
		if leading_slashes == 2 {
			leading_descendant_or_self = true
		}
		if leading_slashes == 0 {
			// Shouldn't happen — we required `/` above — but guard anyway.
			return error('CXPATH_PARSE: expected "/" after binding identifier')
		}
	}

	// Parse the StepList: at least one Step, followed by zero-or-more
	// `'/' Step` or `'//' Step` continuations (grammar [130a]). The
	// loop terminates BEFORE consuming a Step-trailing
	// `:`-modifier-keyword. Interior `//` lowers to an axis modifier on
	// the next step (descendant-or-self), per [130a]'s `//` shorthand.
	mut steps := []PathStep{}
	first_step := parse_one_step(mut c)!
	if leading_descendant_or_self {
		// Override the first step's axis with descendant-or-self iff the
		// step has no explicit axis prefix (which would have set a
		// non-default axis already). Per grammar [131], an explicit
		// AxisSpecifier on the head step composes WITH the leading `//`
		// shorthand — but that composition lowers to two AST steps in
		// XPath semantics. We take the simpler reading currently: the
		// leading `//` only re-axes a default-axis (.child) head step;
		// an explicit axis prefix on the head step takes precedence and
		// the `//` is treated as no-op (since the cursor only saw one
		// `/` before `axis::`, which can't happen in practice — `$u//`
		// guarantees no `axis::` immediately follows).
		mut s := first_step
		if s.axis == PathAxis.child {
			s.axis = PathAxis.descendant_or_self
		}
		steps << s
	} else {
		steps << first_step
	}
	for {
		if c.at_end() {
			break
		}
		b := c.peek()
		if b == `/` {
			// Look ahead for `//` — interior descendant-or-self shorthand.
			if c.peek_at(1) == `/` {
				c.advance() // consume first `/`
				c.advance() // consume second `/`
				// Tolerate inter-step whitespace (introduced by Phase
				// 2.20 to support `... :bind u / member` and similar).
				for !c.at_end() && path_is_space(c.peek()) {
					c.advance()
				}
				mut s := parse_one_step(mut c)!
				if s.axis == PathAxis.child {
					s.axis = PathAxis.descendant_or_self
				}
				steps << s
				continue
			}
			c.advance() // consume `/`
			// Tolerate inter-step whitespace (Phase 2.20).
			for !c.at_end() && path_is_space(c.peek()) {
				c.advance()
			}
			steps << parse_one_step(mut c)!
			continue
		}
		// §D12: a step-trailing `:` terminates the path. We do NOT consume
		// the `:` — the enclosing directive parser handles the modifier.
		// This catches both modifier-keyword case (`:bind`, `:using`, …)
		// and the bare-`:` case (the spec says "a `:` that is NOT part
		// of a known modifier keyword should terminate the path too").
		if b == `:` {
			break
		}
		// Whitespace immediately followed by a `:` (with-or-without
		// modifier keyword) also terminates the path — whitespace is the
		// natural separator between a path and the next directive token.
		// Whitespace followed by a `/` is tolerated as inter-step spacing
		// (notably after a `:bind NAME` peer-modifier,);
		// we consume the whitespace and continue at the `/`.
		if path_is_space(b) {
			// Peek past any run of whitespace.
			mut j := c.pos + 1
			for j < c.src.len && path_is_space(c.src[j]) {
				j++
			}
			if j < c.src.len && c.src[j] == `:` {
				// Stop here; leave the whitespace + `:` for the caller.
				break
			}
			if j < c.src.len && c.src[j] == `/` {
				// Inter-step whitespace — consume it and re-loop so the
				// `/` is handled by the step-separator branch above.
				c.pos = j
				continue
			}
			// Any other token after whitespace is unexpected at this slice —
			// fall through to the trailing-input error.
		}
		// Anything else is genuinely unexpected.
		return error('CXPATH_PARSE: unexpected trailing input at position ${c.pos}: ${source[c.pos..]}')
	}

	mut node := PathNode{
		form:    form
		binding: binding
		steps:   steps
		source:  source
		loc:     PathLoc{ line: 1, col: 1 }
	}
	return node, c.pos
}

// parse_one_step parses a single Step per grammar [131]:
//
//   Step ::= ( AxisSpecifier '::' )? NodeTest Predicate*
//
// NodeTest admits bare Name or `*` wildcard at this slice; kind-test /
// prefixed-QName / prefix:* forms surface as CXPATH_NODETEST_NOT_YET_IMPLEMENTED.
// Predicates accumulate — multi-predicate is admitted.
//
// `@name` attribute sugar is recognised: it desugars to
// `attribute::<name>` per spec/grammar.ebnf [131] note about the
// shorthand axis. (Not currently in [131] verbatim, but the current surface
// admits `@name` everywhere `attribute::name` is admitted — see
// spec/code.md §6.2.)
fn parse_one_step(mut c PathParseCursor) !PathStep {
	mut axis := PathAxis.child

	// `@name` attribute sugar (no `::` needed).
	if !c.at_end() && c.peek() == `@` {
		c.advance()
		name := c.read_name()
		if name.len == 0 {
			return error('CXPATH_PARSE: expected attribute name after `@`')
		}
		return finish_step(mut c, PathAxis.attribute, name)!
	}

	// Try an AxisSpecifier '::' prefix per [131a]. The grammar's axis list is
	// a closed set of 12 names; we read the leading identifier (allowing
	// hyphens to admit `descendant-or-self` etc.) and check if it's
	// followed by `::`. If not, the identifier is the NodeTest itself.
	saved_pos := c.pos
	first := c.read_name()
	if first.len == 0 {
		// No axis prefix possible — delegate the NodeTest dispatch, which
		// handles wildcard / kind-test / bare-name uniformly (and surfaces
		// the appropriate deferred-feature error for `node()`, etc).
		return finish_node_test(mut c, axis)!
	}
	// AxisSpecifier '::' marker?
	if !c.at_end() && c.peek() == `:` && c.peek_at(1) == `:` {
		ax := path_axis_from_name(first) or {
			return error('CXPATH_PARSE: unknown axis "${first}" (valid axes are the 12-axis set per spec/grammar.ebnf [131a])')
		}
		axis = ax
		c.advance() // first `:`
		c.advance() // second `:`
		// Node test follows.
		return finish_node_test(mut c, axis)!
	}

	// Not an axis prefix — `first` IS the node test. Reset cursor to the
	// start of the identifier so finish_node_test can re-read it uniformly
	// with the explicit-axis branch (centralising wildcard / kind-test
	// rejection in one place).
	c.pos = saved_pos
	return finish_node_test(mut c, axis)!
}

// path_kind_test_names lists the four kind-test names admitted by [131b].
// Each parses as `Name '(' ')'` and is recorded in `node_test` verbatim
// including the parens (e.g., `node()`). Per the kind-test
// surface stays narrow — no `element(QName)` / `attribute(QName)`
// parametric forms; those are deferred.
const path_kind_test_names = ['node', 'text', 'element', 'attribute']

// finish_node_test reads the NodeTest portion of a step (after any
// AxisSpecifier `::` has already been consumed) and dispatches to
// finish_step. Admits bare Name, `*` wildcard, the four kind-tests
// (`node() / text() / element() / attribute()`), and prefixed QName
// (`prefix:local`). Namespace-wildcard forms (`*:Local`, `Prefix:*`)
// remain deferred pending the namespace resolution hook.
fn finish_node_test(mut c PathParseCursor, axis PathAxis) !PathStep {
	if c.at_end() {
		return error('CXPATH_PARSE: expected node test')
	}
	b := c.peek()
	// Wildcard `*` — admitted as a bare star NodeTest. The prefixed
	// wildcard shapes `*:Local` and `Prefix:*` are still deferred.
	if b == `*` {
		// Look one ahead — `*:Local` is the namespace-wildcard-with-local
		// form which is still deferred until the namespace resolution
		// hook lands (Phase 2.x follow-up).
		if c.peek_at(1) == `:` {
			return error('CXPATH_NODETEST_NOT_YET_IMPLEMENTED: namespace-wildcard `*:Local` node test deferred (Phase 2.x follow-up; needs namespace resolution hook)')
		}
		c.advance()
		return finish_step(mut c, axis, '*')!
	}
	if !path_is_name_start(b) {
		return error('CXPATH_PARSE: expected node-test name (got ${b.ascii_str()})')
	}
	name := c.read_name()
	// Kind-test: `node()` / `text()` / `element()` / `attribute()`.
	// Per [131b] only these four names accept the parametric `()` form;
	// any other Name followed by `(` is a parse error (callers wanting a
	// function call use the predicate body, not the NodeTest).
	if !c.at_end() && c.peek() == `(` {
		if name !in path_kind_test_names {
			return error('CXPATH_PARSE: unknown kind-test `${name}()` (admitted: node, text, element, attribute)')
		}
		c.advance() // `(`
		if c.at_end() || c.peek() != `)` {
			return error('CXPATH_PARSE: expected `)` after kind-test `${name}(`')
		}
		c.advance() // `)`
		// Record verbatim including parens — matches spec/canonical.md §2.12.4
		// node-test emit (kind-tests round-trip with parens intact).
		return finish_step(mut c, axis, '${name}()')!
	}
	// Prefix wildcard `Prefix:*` (deferred) or QName `prefix:local` (admitted).
	// §D12: do NOT consume the `:` here if the next-after-`:` identifier is
	// in the closed modifier-keyword set — that `:LABEL` belongs to the
	// enclosing directive parser, not the NodeTest.
	if !c.at_end() && c.peek() == `:` && c.peek_at(1) != `:` {
		// `Prefix:*` (deferred) is checked BEFORE the §D12 terminator rule:
		// `*` is not a name-start so the terminator rule would otherwise
		// short-circuit and leave `:*` as trailing input.
		if c.peek_at(1) == `*` {
			return error('CXPATH_NODETEST_NOT_YET_IMPLEMENTED: namespace-prefix wildcard `Prefix:*` deferred (Phase 2.x follow-up; needs namespace resolution hook)')
		}
		if path_step_colon_terminates(c) {
			// Path ends here with a bare-name NodeTest; the `:LABEL`
			// (or bare `:`) is left for the caller.
			return finish_step(mut c, axis, name)!
		}
		// Prefixed QName: consume `:` then the local name. Per
		// spec/namespaces.md the prefix is recorded verbatim in the
		// node_test string (e.g., `xml:lang`); resolution into a
		// `(ns_uri, local)` pair happens at evaluation time against
		// the document's in-scope xmlns map (no hook currently — we
		// only record the source form, which is what canonical emit
		// and AST equality compare on).
		c.advance() // `:`
		local := c.read_name()
		if local.len == 0 {
			return error('CXPATH_PARSE: expected local name after `${name}:`')
		}
		return finish_step(mut c, axis, '${name}:${local}')!
	}
	return finish_step(mut c, axis, name)!
}

// path_step_colon_terminates returns true when the cursor sits on a `:`
// that should be treated as a §D12 step-terminator rather than a QName
// separator. The cursor is NOT advanced. The rule: peek the identifier
// immediately after the `:` (no whitespace allowed between `:` and the
// label — per spec/code.md the modifier-keyword tokens are written as
// a single `:label` lexeme); if that identifier is in
// `path_step_terminator_labels`, OR if there is no identifier at all
// (bare `:`), the `:` is a terminator.
fn path_step_colon_terminates(c PathParseCursor) bool {
	// Cursor sits on `:`. Read a candidate label starting at pos+1
	// using a non-mutating local copy.
	start := c.pos + 1
	if start >= c.src.len {
		// Bare trailing `:` — treat as terminator (path ends, caller
		// reports its own error if it wants to).
		return true
	}
	if !path_is_name_start(c.src[start]) {
		// `:` not followed by an identifier — terminator (e.g., `:` then
		// space, or `:` then `[`).
		return true
	}
	mut end := start + 1
	for end < c.src.len && path_is_name_cont(c.src[end]) {
		end++
	}
	label := c.src[start..end].bytestr()
	return label in path_step_terminator_labels
}

// finish_step parses an optional `:bind NCName` peer-modifier (per
// grammar [160]) and zero-or-more trailing Predicates after a
// NodeTest and returns the assembled PathStep. Multi-predicate is admitted
// at this slice — predicates accumulate into `step.predicates` until a
// non-`[` byte ends the run.
//
// `:bind` consumption rules:
//   - Position: immediately after the NodeTest (optionally with leading
//     whitespace), strictly BEFORE the first predicate `[`.
//   - Identifier: an NCName per [7a] (alphanumerics + `_` + `-`).
//   - `:bind _` is rejected with `CXER0232` (RESERVED_BIND_NAME) — `_` is
// reserved for the implicit `$_` context binding.
//   - At most one `:bind` per step.
//   - `:bind` occurring AFTER predicates (e.g., `//user[@active] :bind u`)
//     is left for the enclosing directive parser via the §D12 step-
//     terminator rule; the peer-modifier slot in the grammar [160] is
//     strictly between NodeTest and Predicates.
fn finish_step(mut c PathParseCursor, axis PathAxis, node_test string) !PathStep {
	mut step := PathStep{
		axis:      axis
		node_test: node_test
	}
	// Optional `:bind NCName` peer-modifier.
	has_bind, bind_name := parse_step_bind_modifier(mut c)!
	if has_bind {
		step.binding = bind_name
		// After consuming `:bind NAME`, tolerate optional whitespace
		// before the first predicate `[` (the grammar separates the
		// peer-modifier from predicates with whitespace; this match
		// the natural surface `//user :bind u [@active]`). Whitespace
		// is NOT consumed if the next non-space byte is not `[`, so
		// the outer step-loop's terminator/`/` handling stays intact.
		mut peek_pos := c.pos
		for peek_pos < c.src.len && path_is_space(c.src[peek_pos]) {
			peek_pos++
		}
		if peek_pos < c.src.len && c.src[peek_pos] == `[` {
			c.pos = peek_pos
		}
	}
	for !c.at_end() && c.peek() == `[` {
		body := read_predicate_body(mut c)!
		// Attempt to promote the body into a structural PredicateExpr
		// AST (the notation atoms). General prefix bodies fall back to
		// source-only mode (the program parser owns their structure).
		// The RETIRED infix/paren surface (grammar [132]–[134]) is a
		// HARD error — it must never survive via the source-only
		// fallback.
		mut pred := PathPredicate{ source: body }
		if expr := predicate_expr_parse(body) {
			pred.expr = expr
		} else {
			if err.msg().starts_with('RETIRED_PREDICATE_SURFACE') {
				return error('CXPATH_PARSE: ${err.msg().all_after('RETIRED_PREDICATE_SURFACE: ')}')
			}
		}
		step.predicates << pred
	}
	return step
}

// parse_step_bind_modifier attempts to consume an optional `:bind NCName`
// peer-modifier at the cursor's current position. The cursor MAY be sitting
// on whitespace preceding the `:bind` token; we tolerate one run of whitespace
// before the `:` and consume it iff we end up consuming the `:bind NAME`
// triplet. On no-match the cursor is restored exactly to its entry position
// (i.e., no whitespace consumed) so the outer step/path loops see the same
// byte they would have seen otherwise.
//
// Errors:
// `:bind _` → `CXER0232` (RESERVED_BIND_NAME) + gate 36.6.
//   - `:bind` with no following identifier → CXPATH_PARSE error.
//
// Returns `(true, name)` when consumed, `(false, '')` when no `:bind` was
// at this position. The Result channel carries errors (`:bind _` rejected
// with `CXER0232`; `:bind` with no following identifier).
fn parse_step_bind_modifier(mut c PathParseCursor) !(bool, string) {
	saved := c.pos
	// Optional leading whitespace (between NodeTest and `:bind`).
	for !c.at_end() && path_is_space(c.peek()) {
		c.advance()
	}
	// Must be `:bind` literally — peek the `:` then read a name and check.
	if c.at_end() || c.peek() != `:` {
		c.pos = saved
		return false, ''
	}
	// Look one byte past the `:` — must be a name-start byte to be `:bind`.
	if !path_is_name_start(c.peek_at(1)) {
		c.pos = saved
		return false, ''
	}
	// Peek the label name without committing — use a local scan.
	label_start := c.pos + 1
	mut label_end := label_start + 1
	for label_end < c.src.len && path_is_name_cont(c.src[label_end]) {
		label_end++
	}
	label := c.src[label_start..label_end].bytestr()
	if label != 'bind' {
		// Not `:bind` — leave the entire region for outer handling
		// (might be `:using`, `:case`, or a non-modifier `:` that the
		// outer path-loop's §D12 terminator rule will dispatch).
		c.pos = saved
		return false, ''
	}
	// Commit: consume `:bind`.
	c.pos = label_end
	// Whitespace between `:bind` and the NCName (optional but typical).
	for !c.at_end() && path_is_space(c.peek()) {
		c.advance()
	}
	if c.at_end() || !path_is_name_start(c.peek()) {
		return error('CXPATH_PARSE: expected NCName after `:bind` (at position ${c.pos})')
	}
	name := c.read_name()
	if name == '_' {
		// gate 36.6: `_` is reserved for the implicit `$_`
		// context binding.
		return error('CXER0232: RESERVED_BIND_NAME — `:bind _` is reserved (the `_` identifier is the implicit `\$_` context binding)')
	}
	return true, name
}

// read_predicate_body consumes a `[ … ]` predicate body and returns the
// verbatim inner text (everything between the brackets, excluding the
// brackets themselves). Brackets nest; quoted strings (single + double)
// shield bracket bytes inside them so `[@name = "alice"]` reads back
// `@name = "alice"` cleanly. Backslash escapes inside the quoted regions
// are not interpreted here — the predicate body is handed verbatim to
// the Phase 2.4 ProgramExpr parser.
fn read_predicate_body(mut c PathParseCursor) !string {
	// Consume opening `[`.
	if c.at_end() || c.peek() != `[` {
		return error('CXPATH_PARSE: expected `[` at predicate start')
	}
	c.advance()
	start := c.pos
	mut depth := 1
	for !c.at_end() {
		b := c.peek()
		if b == `'` || b == `"` {
			quote := b
			c.advance()
			for !c.at_end() && c.peek() != quote {
				// Skip escape sequences cheaply (1-char lookahead).
				if c.peek() == `\\` && !c.at_end() {
					c.advance()
					if !c.at_end() {
						c.advance()
					}
					continue
				}
				c.advance()
			}
			if c.at_end() {
				return error('CXPATH_PARSE: unterminated string literal inside predicate body')
			}
			c.advance() // closing quote
			continue
		}
		if b == `[` {
			depth++
			c.advance()
			continue
		}
		if b == `]` {
			depth--
			if depth == 0 {
				body := c.src[start..c.pos].bytestr()
				c.advance() // consume closing `]`
				return body
			}
			c.advance()
			continue
		}
		c.advance()
	}
	return error('CXPATH_PARSE: unterminated predicate body (missing `]`)')
}
