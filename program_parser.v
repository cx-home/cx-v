module cx

import strconv

// ── program parser ───────────────────────────────────────────────────────────────
//
// Consumes the token stream from `tokenize()` (vcx/code/lexer.v) and
// produces a Program populated with the AST nodes declared in
// vcx/code/ast.v. Hand-written recursive descent; no lookahead beyond
// one token (peek_kind / peek_kind_at). Position-rewindable via the
// `cursor` save/restore pattern where the grammar genuinely needs it
// (only inside parse_bracket — element vs array vs pattern disambig).
//
// Spec refs:
//   - spec/code.md §§4–8 (grammar + directives reference)
//   - spec/grammar.ebnf [120]–[129] (productions)
// spec/ast.md §"program AST" (node shapes)
//
// Every parse error returns ParseError with code = cx-err:CXER0100
// (PARSE_ERROR) per spec/code.md §4.1 and a Position pointing at the
// offending token.

// ParseError is the structured error a parser produces. `code` is
// always 'cx-err:CXER0100' (PARSE_ERROR); `message` is human-readable;
// `pos` locates the offending token.
pub struct ParseError {
	Error
pub:
	code    string = 'cx-err:CXER0100'
	message string
	pos     Position
	// `unknown_directive` marks the one parse failure that is a SEMANTIC
	// rejection of an unregistered / retired `[?name]` directive (vs a syntactic
	// failure on data/prose that merely fails to parse as a program). The eval
	// boundary's data-fallback (#11) consults this: an unknown directive is
	// program intent and MUST stay fail-loud, never silently re-read as data.
	unknown_directive bool
}

pub fn (e ParseError) msg() string {
	return '${e.code}: ${e.message} at line ${e.pos.line}:${e.pos.col}'
}

// ProgramParser is the cursor over the token stream.
struct ProgramParser {
mut:
	tokens []ProgramToken
	pos    int
	// source is the verbatim program text, retained so special-form
	// parsers that delegate to a sibling parser (e.g. [?lib] / [?const],
	// which re-parse via parse_lib / parse_const) can recover the
	// exact directive source span by byte offset. Empty when the parser
	// was constructed without source (legacy token-only callers).
	source string
	// predicate_depth tracks the nesting depth of CXPath predicate
	// bodies. When > 0, bare `@name` and bare `*` in expression
	// position desugar to `$_@name` and `$_/*` respectively per
	// (general-predicate context-item sugar).
	predicate_depth int
	// no_descendant_in_binding_path suppresses the `//` step
	// extension on $binding paths. Used by parse_modify_body so
	// `[?modify $doc //user ...]` parses as
	//   ProgramBinding($doc) + PathExpr(//user)
	// rather than greedily consuming the `//user` into the
	// $doc binding-path. Set/cleared by callers around the doc-
	// expression parse only.
	no_descendant_in_binding_path bool
	// in_modify_focus is set while parse_modify_body parses the FOCUS
	// PathExpr. When set, a trailing `[NAME …]` whose head is a known
	// modify-action name is NOT consumed as a CXPath predicate — it is
	// the start of an action clause (`//user [set-attr …]`).
	// Without this, the predicate loop greedily eats the action clause
	// (whitespace is insignificant to the tokenizer), leaving zero
	// actions. Set/cleared by parse_modify_body around the focus parse.
	in_modify_focus bool
	// expr_depth tracks the live recursive-descent nesting depth of
	// parse_expr (the universal expression choke point). A pathologically
	// deep nest (e.g. ~2000 chained `[?let]`) otherwise overflows the host
	// C stack and SEGFAULTs the process; the guard below converts that into
	// a graceful parse error well before any real-world program is affected.
	expr_depth int
}

// max_program_parse_depth caps recursive-descent expression nesting. Chosen
// far above any hand-written CX (the deepest conformance fixture nests well
// under 100; the spec floor is ≥64, validate.md / §13.7) yet comfortably
// below the host-stack overflow point (the unoptimised dev/test build
// overflows around ~600 live parse_expr frames — each level also drags
// parse_atom / parse_directive / clause frames). 256 keeps a ~2× margin under
// that ceiling and gives the SAME limit on every build, so a program that
// parses on the optimised binary also parses under the test build. Exceeding
// it raises a parse error (surfaced as cx-err:CXER0100 PARSE_ERROR, like the
// data parser's element-nesting bound, parser.v `max_recursion_depth`)
// instead of segfaulting — core-bug #2 of the stdlib audit
// remediation. Mirrors the §13.7 element-nesting `max_depth` defense for code.
const max_program_parse_depth = 256

// parse is the public entry point. Tokenises source, then parses one
// or more top-level CX code expressions. A program with multiple top-level
// expressions wraps them in an implicit sequence_lit literal per
// spec/code.md §1 (a program is a sequence of expressions evaluated in
// order; the final expression's value is the program's value, with
// earlier ones evaluated for effect e.g. `[?def]` bindings).
pub fn parse_program(source string) !Program {
	tokens := tokenize(source)!
	mut p := ProgramParser{ tokens: tokens, source: source }
	if p.peek_kind() == .eof {
		return ParseError{
			message: 'empty source — CX program requires at least one expression'
			pos:     p.peek().pos
		}
	}
	start := p.peek().pos
	mut exprs := []ProgramNode{}
	for p.peek_kind() != .eof {
		exprs << p.parse_expr()!
	}
	body := if exprs.len == 1 {
		exprs[0]
	} else {
		// Multi-expression top-level: a `block` literal. Evaluator runs
		// each expression in order, sharing the env (so [?def] registers
		// closures visible to subsequent expressions), and returns the
		// LAST value. Distinguished from `sequence_lit` so nested
		// sequences in expression position keep `(a, b, c)` semantics.
		ProgramLiteral{
			kind:  .block
			items: exprs
			pos:   start
		}
	}
	return Program{
		body: body
		pos:  start
	}
}

// ── Cursor helpers ──────────────────────────────────────────────────────────

fn (p ProgramParser) peek() ProgramToken {
	return p.tokens[p.pos]
}

fn (p ProgramParser) peek_kind() ProgramTokenKind {
	return p.tokens[p.pos].kind
}

fn (p ProgramParser) peek_kind_at(offset int) ProgramTokenKind {
	idx := p.pos + offset
	if idx >= p.tokens.len {
		return .eof
	}
	return p.tokens[idx].kind
}

fn (mut p ProgramParser) advance() ProgramToken {
	t := p.tokens[p.pos]
	if p.pos < p.tokens.len - 1 {
		p.pos++
	}
	return t
}

fn (mut p ProgramParser) expect(kind ProgramTokenKind, what string) !ProgramToken {
	if p.peek_kind() != kind {
		return ParseError{
			message: "expected ${what}, got ${p.peek().text}"
			pos:     p.peek().pos
		}
	}
	return p.advance()
}

fn (p ProgramParser) save() int {
	return p.pos
}

fn (mut p ProgramParser) restore(saved int) {
	p.pos = saved
}

// ── Expression entry ────────────────────────────────────────────────────────
//
// infix pipe surface `stage0 | stage1 | …` is REMOVED. Pipes are
// now written exclusively as the prefix directive `[?pipe SRC STAGE …]`
// with bare stages (§8.9): the threaded value fills a single `_` hole
// (hole-form) or is appended as the final positional arg (no-hole form).
// There is no infix `|` and no `[through]` wrapper (both retired — §8.9
// tombstones). All conformance fixtures + stdlib have been migrated.

fn (mut p ProgramParser) parse_expr() !ProgramNode {
	p.expr_depth++
	defer { p.expr_depth-- }
	if p.expr_depth > max_program_parse_depth {
		return ParseError{
			message: 'expression nesting exceeds limit (${max_program_parse_depth}) — refactor or bind sub-expressions to flatten the tree'
			pos:     p.peek().pos
		}
	}
	return p.parse_atom()!
}

// ── Atom: a single non-pipe expression ──────────────────────────────────────

fn (mut p ProgramParser) parse_atom() !ProgramNode {
	k := p.peek_kind()
	match k {
		.directive_name {
			return p.parse_directive()!
		}
		.dollar {
			binding := p.parse_binding_with_path()!
			// Call on a path-less binding: `$f(x)`. The binding's name
			// resolves to a callable at evaluation time. Path-bearing
			// binding-calls (`$obj/method(x)`) are not yet supported
			// at the parser level; spec/code.md §6.3 leaves the surface
			// underspecified.
			//
			// the `(` must be byte-adjacent to the binding to
			// read as a paren-call; a space-separated `(` is a separate
			// operand (a sequence literal). Without this, `[= $xs (1,2,3)]`
			// is mis-parsed as `[= $xs(1,2,3)]` (a 1-item `=` element with a
			// paren-call) and `binding_clause` rejects it.
			if p.peek_kind() == .lparen && binding.path.len == 0
			   && p.cur_adjacent_to_prev() {
				return p.parse_call_after_callee(binding.name, binding.pos)!
			}
			// BindingPostfix: `$binding[SliceAxes]`. Positional
			// disambiguation per the disambiguation table — the
			// preceding token decides. Here the preceding token is the
			// binding-with-path; if a `[` follows AND its body has slice
			// shape (leading `:`, top-level `:` between exprs, leading
			// `*`, or top-level `,`), promote to `ProgramSliceAccess`.
			// Otherwise leave the `[` alone — it isn't currently a valid
			// postfix and the outer parser will error / position-recover
			// per usual.
			if p.peek_kind() == .lbrack && p.lbrack_adjacent_to_prev()
			   && is_slice_postfix_after_binding(p) {
				return p.parse_slice_postfix(binding)!
			}
			return binding
		}
		.lbrack {
			return p.parse_bracket(.expression)!
		}
		.lparen {
			return p.parse_paren_or_sequence()!
		}
		.lbrace {
			return p.parse_map_literal()!
		}
		.string_lit {
			t := p.advance()
			return ProgramLiteral{
				kind:    .string_lit
				str_val: t.text
				pos:     t.pos
			}
		}
		.number_lit {
			t := p.advance()
			return parse_number_literal(t)!
		}
		.bool_lit {
			t := p.advance()
			return ProgramLiteral{
				kind:     .bool_lit
				bool_val: t.text == 'true'
				pos:      t.pos
			}
		}
		.duration_lit {
			t := p.advance()
			return ProgramLiteral{
				kind:    .duration_lit
				dur_val: t.text
				pos:     t.pos
			}
		}
		.period_lit {
			t := p.advance()
			return ProgramLiteral{
				kind:    .period_lit
				dur_val: t.text
				pos:     t.pos
			}
		}
		.date_lit {
			t := p.advance()
			// @CHOICE-3: the lexer recognizes the SHAPE (temporal_len) and emits
			// the whole extent as one token; a calendar-invalid date is NOT a
			// date — it reclassifies to a string here (mirrors data is_date's
			// calendar_ok gate; keeps the run one token rather than fragmenting).
			kind := if calendar_ok(t.text) { ProgramLiteralKind.date_lit } else { ProgramLiteralKind.string_lit }
			return ProgramLiteral{
				kind:    kind
				str_val: t.text
				pos:     t.pos
			}
		}
		.datetime_lit {
			t := p.advance()
			kind := if calendar_ok(t.text) {
				ProgramLiteralKind.datetime_lit
			} else {
				ProgramLiteralKind.string_lit
			}
			return ProgramLiteral{
				kind:    kind
				str_val: t.text
				pos:     t.pos
			}
		}
		.colon {
			// Atom literal: `:NAME` in expression position
			// parses as ProgramLiteral{ kind: .atom_lit, str_val: NAME }.
			// Labeled-slot prefixes consume `:label value` pairs BEFORE
			// recursing into parse_atom (parse_directive_slot at line
			// ~750; parse_cx_element_from_inside at line ~498), so the
			// colon reaches this arm only when no contextual rule
			// claimed it — i.e. as a bare expression position or as a
			// slot value following a label. Reserved names `:true` /
			// `:false` / `:null` raise CXER0100.
			return p.parse_atom_literal()!
		}
		.data_span {
			// DATA↔PROGRAM seam: a pure-DATA construct captured verbatim by the
			// lexer (`[#…#]` raw / `&…;` entity / `[!…]` declaration). Delegate to
			// the proven data reader and carry the parsed node as a `node_lit`
			// literal so eval returns it as-is — the program reading of these
			// constructs IS the data reading.
			t := p.advance()
			node := parse_data_node(t.text) or {
				return ParseError{
					message: 'invalid embedded data construct: ${err.msg()}'
					pos:     t.pos
				}
			}
			return ProgramLiteral{
				kind:    .node_lit
				node:    node
				str_val: t.text
				pos:     t.pos
			}
		}
		.double_slash {
			// CXPath descendant-rooted path expression:
			// `//name`, `//name/name`, etc. Chunk-1 covers element-name
			// node tests on descendant-or-self + child axes; predicates
			// and the remaining 10 axes land in subsequent chunks.
			return p.parse_path_expr()!
		}
		.ident {
			return p.parse_call_or_ident_value()!
		}
		.at {
			// Inside a CXPath predicate body, bare `@name` desugars to
			// `$_@name` (general-predicate context-item
			// sugar). Outside predicate bodies, `@name` in expression
			// position is a parse error.
			if p.predicate_depth > 0 {
				at_pos := p.peek().pos
				p.advance() // '@'
				name_tok := p.expect(.ident, 'name after @ in predicate body')!
				return ProgramBinding{
					name: '_'
					path: [ProgramPathStep{ kind: .attr, name: name_tok.text }]
					pos:  at_pos
				}
			}
			return ParseError{
				message: "unexpected token '${p.peek().text}' in expression position"
				pos:     p.peek().pos
			}
		}
		else {
			return ParseError{
				message: "unexpected token '${p.peek().text}' in expression position"
				pos:     p.peek().pos
			}
		}
	}
}

// parse_atom_literal consumes a `:NAME` atom literal at the current
// position (cursor at the colon). Validates that the next token is an
// identifier and that the name is not one of the three reserved atom
// names. Returns a ProgramLiteral with kind=.atom_lit.
fn (mut p ProgramParser) parse_atom_literal() !ProgramLiteral {
	colon_tok := p.advance() // consume ':'
	if p.peek_kind() != .ident {
		return ParseError{
			message: "expected identifier after ':' in atom literal, got '${p.peek().text}'"
			pos:     p.peek().pos
		}
	}
	name_tok := p.advance()
	// reserved atom names rejected at lex time.
	if name_tok.text == 'true' || name_tok.text == 'false' || name_tok.text == 'null' {
		return ParseError{
			message: "atom literal ':${name_tok.text}' is reserved; use bare '${name_tok.text}' for the bool/null scalar"
			pos:     colon_tok.pos
		}
	}
	return ProgramLiteral{
		kind:    .atom_lit
		str_val: name_tok.text
		pos:     colon_tok.pos
	}
}

// parse_path_expr parses a descendant-rooted CXPath expression.
// Chunk-1 grammar: '//' Step ('/' Step)* — where Step is a name
// (element NodeTest) or '*' (any-element wildcard). The leading '//'
// makes the first step's axis descendant-or-self; subsequent steps
// default to the child axis (per spec/code.md §5.5.1 desugar table).
// Explicit axis prefixes (`axis::name`), predicates (`[...]`), and the
// absolute '/'-rooted form land in later chunks.
fn (mut p ProgramParser) parse_path_expr() !ProgramPathExpr {
	start := p.peek().pos
	p.expect(.double_slash, "'//'")!
	first := p.parse_path_step(ProgramPathAxis.descendant_or_self)!
	mut steps := [first]
	for p.peek_kind() == .slash {
		p.advance() // consume '/'
		steps << p.parse_path_step(ProgramPathAxis.child)!
	}
	return ProgramPathExpr{
		leading: .descendant
		steps:   steps
		pos:     start
	}
}

// program_path_step_terminator_labels is the closed set of `:label` keywords
// that, when seen after a NodeTest's bare Name in PathExpr step-trailing
// position, terminate the path step rather than starting a
// `Prefix:LocalName` namespace step. See and spec/grammar.ebnf
// [131b] disambiguation note.
//
// Membership = union of directive `:label` keywords across grammar
// productions [129]–[154a]. Update this list whenever a new directive
// adds modifier `:labels`. The list is kept here (not in tokens.v)
// because it is consumed exclusively by parse_path_step's lookahead;
// no lexer or evaluator needs it.
//
// Static union (not per-directive context-aware) was chosen because:
//   1. The set is small (~32 entries) and stable; per-directive
//      narrowing would yield false negatives (e.g. `:in` legal only
//      inside [?for]/[?let] would mis-parse `//foo :in …` outside
//      those directives, but the path is inside a directive whose
//      slot grammar will reject the bad `:in` with a better diagnostic).
//   2. Threading directive-context down to parse_path_step would
//      require a parser-state field touched by every directive parser;
//      static set avoids that cross-cutting plumbing.
//   3. The false-positive cost (a namespace prefix `xxx` where `xxx`
//      is a CX-reserved keyword — `//set:foo`, `//in:bar`, etc.) is
// bounded and has a documented workaround (edge
//      case: use `//set:*` + predicate, or rename the prefix).
const program_path_step_terminator_labels = [
	'append', 'as', 'case', 'delete', 'delete-attr', 'direct', 'else',
	'group-by', 'in', 'in-memory', 'insert-after', 'insert-before',
	'lazy', 'let', 'on-error', 'only', 'order-by', 'prepend', 'rename',
	'replace', 'rest', 'returns', 'scope', 'set', 'set-attr', 'table',
	'throws', 'using', 'version', 'when', 'where', 'yield',
]

fn is_path_step_terminator(s string) bool {
	for n in program_path_step_terminator_labels {
		if n == s {
			return true
		}
	}
	return false
}

// parse_path_step parses one Step of a PathExpr per grammar [131]:
//   Step ::= (AxisSpecifier '::')? NodeTest Predicate*
// Chunk-1 accepted a bare NodeTest only. Chunk-2 adds explicit axis
// prefixes (`ancestor::doc`, `following-sibling::p`, etc.) and any
// number of trailing predicates (`[INT]`, `[@attr]`, `[@attr=val]`).
// The caller supplies the implicit axis (descendant-or-self for the
// head step under '//', child for subsequent steps); an explicit
// prefix overrides it.
fn (mut p ProgramParser) parse_path_step(implicit_axis ProgramPathAxis) !ProgramPathExprStep {
	start := p.peek().pos
	// Axis prefix: `ident '::'`. Identifiers in this position carry an
	// axis name from the 12-axis vocabulary. If the next
	// token after the ident is NOT `::`, fall through to the NodeTest
	// rule (which consumes the ident as an element name).
	mut axis := implicit_axis
	mut axis_explicit := false
	if p.peek_kind() == .ident && p.peek_kind_at(1) == .double_colon {
		axis_tok := p.advance()
		p.advance() // consume '::'
		axis = axis_from_name(axis_tok.text) or {
			return ParseError{
				message: "unknown CXPath axis '${axis_tok.text}'; valid axes: child, descendant, descendant-or-self, parent, ancestor, ancestor-or-self, following, preceding, following-sibling, preceding-sibling, self, attribute"
				pos:     axis_tok.pos
			}
		}
		axis_explicit = true
	} else if p.peek_kind() == .at {
		// Attribute-axis shorthand: `@name` is sugar for
		// `attribute::name`. Used in focus paths like `//user/@name`.
		p.advance() // consume '@'
		axis = .attribute
		axis_explicit = false  // canonical emit keeps the `@name` sugar
	}
	// NodeTest per grammar [131b]:
	//   Name | '*' | '*:' LocalName | Prefix ':*'
	//   | 'node()' | 'text()' | 'element()' | 'attribute()'
	// Disambiguation note: the lexer emits '::' as a single double_colon
	// token (axis separator), so a single `colon` here unambiguously means
	// a QName / namespace-wildcard separator — not an axis.
	mut name := ''
	mut ns_kind := ProgramPathNsKind.none
	mut ns_prefix := ''
	if p.peek_kind() == .star {
		p.advance()
		if p.peek_kind() == .colon {
			// '*:' LocalName — match any namespace, specific local name.
			// '*:*' is also accepted: the any-ns + any-local form; it
			// degenerates to plain '*' (every element) since the matcher's
			// any_ns branch reduces to local-name equality and `name='*'`
			// makes that universal.
			p.advance() // consume ':'
			if p.peek_kind() == .star {
				p.advance()
				name = '*'
			} else {
				local_tok := p.expect(.ident, "local name or '*' after '*:' in CXPath NodeTest (namespace-wildcard form [131b])")!
				name = local_tok.text
			}
			ns_kind = .any_ns
		} else {
			name = '*'
		}
	} else {
		name_tok := p.expect(.ident, "element name or '*' in CXPath step")!
		// Disambiguation / grammar [131b]: a ':' here
		// might start `Prefix ':' LocalName` (genuine namespace step) OR
		// might be the ':label' of an enclosing directive's modifier slot
		// (e.g. `[?modify $d //foo :using …]`). The rule: if the NCName
		// after ':' is in the closed modifier-keyword set, the ':' is NOT
		// consumed — the Step terminates with the bare Name and the
		// `:label` is left for the directive parser to handle.
		//
		// '*' after ':' is never ambiguous (it's the `Prefix:*`
		// namespace-wildcard form), so that path is taken unconditionally.
		if p.peek_kind() == .colon
		   && !(p.peek_kind_at(1) == .ident
		        && is_path_step_terminator(p.peek_at(1).text)) {
			// `Prefix:*` or `Prefix:LocalName` — namespace-prefixed
			// NodeTest. Prefix resolves against the in-scope xmlns map
			// at eval time (first-occurrence wins per spec/namespaces.md).
			p.advance() // consume ':'
			ns_prefix = name_tok.text
			if p.peek_kind() == .star {
				p.advance()
				name = '*'
				ns_kind = .prefix_any_local
			} else {
				local_tok := p.expect(.ident, "local name or '*' after prefix ':' in CXPath NodeTest")!
				name = local_tok.text
				ns_kind = .prefix_local
			}
		} else {
			name = name_tok.text
		}
	}
	// Bind annotation `(bind $NAME)` [160a] — a parenthesised postfix on
	// the step, between the NodeTest and any predicates. Binds the step's
	// match under `$NAME`. The reserved-name rejection ($_/$_position/
	// $_last → CXER0232) is enforced at eval, not parse.
	mut step_bind := ''
	if p.peek_kind() == .lparen && p.peek_kind_at(1) == .ident
	   && p.peek_at(1).text == 'bind' {
		p.advance() // '('
		p.advance() // 'bind'
		p.expect(.dollar, "'\$' in (bind \$name)")!
		nm := p.expect(.ident, 'name after (bind \$')!
		p.expect(.rparen, "')' closing (bind …)")!
		step_bind = nm.text
	}
	// Predicates: zero or more `[…]` immediately following the NodeTest.
	// A predicate `[…]` MUST be byte-adjacent (no whitespace) to the step,
	// mirroring the binding-path rule (line ~890): a space-separated `[`
	// is a separate operand/clause (e.g. `[?if //admin [then …] [else …]]`),
	// not a predicate on the path step.
	mut preds := []ProgramPathPredicate{}
	for p.peek_kind() == .lbrack && p.lbrack_adjacent_to_prev() {
		// in a [?modify] focus path, a `[NAME …]` whose head is a
		// modify-action name begins an action clause, not a predicate.
		if p.in_modify_focus && p.peek_kind_at(1) == .ident
		   && is_modify_action_name(p.peek_at(1).text) {
			break
		}
		preds << p.parse_path_predicate()!
	}
	return ProgramPathExprStep{
		axis:          axis
		axis_explicit: axis_explicit
		name:          name
		ns_kind:       ns_kind
		ns_prefix:     ns_prefix
		predicates:    preds
		bind:          step_bind
		pos:           start
	}
}

// axis_from_name maps the surface axis name (per grammar [131a]) to the
// ProgramPathAxis enum. Returns none on unknown name — the caller raises
// CXER0100 with the full vocabulary. Note `self` maps to `.self_axis`
// (V's `self` is reserved).
fn axis_from_name(s string) ?ProgramPathAxis {
	return match s {
		'child'              { ProgramPathAxis.child }
		'descendant'         { ProgramPathAxis.descendant }
		'descendant-or-self' { ProgramPathAxis.descendant_or_self }
		'parent'             { ProgramPathAxis.parent }
		'ancestor'           { ProgramPathAxis.ancestor }
		'ancestor-or-self'   { ProgramPathAxis.ancestor_or_self }
		'following-sibling'  { ProgramPathAxis.following_sibling }
		'preceding-sibling'  { ProgramPathAxis.preceding_sibling }
		'following'          { ProgramPathAxis.following }
		'preceding'          { ProgramPathAxis.preceding }
		'self'               { ProgramPathAxis.self_axis }
		'attribute'          { ProgramPathAxis.attribute }
		else                 { none }
	}
}

// axis_to_name is the inverse of axis_from_name; used by ast_json to
// round-trip explicit-axis steps back to their canonical surface form.
pub fn axis_to_name(a ProgramPathAxis) string {
	return match a {
		.child              { 'child' }
		.descendant         { 'descendant' }
		.descendant_or_self { 'descendant-or-self' }
		.parent             { 'parent' }
		.ancestor           { 'ancestor' }
		.ancestor_or_self   { 'ancestor-or-self' }
		.following_sibling  { 'following-sibling' }
		.preceding_sibling  { 'preceding-sibling' }
		.following          { 'following' }
		.preceding          { 'preceding' }
		.self_axis          { 'self' }
		.attribute          { 'attribute' }
	}
}

// parse_path_predicate parses one `[…]` predicate appearing after a
// NodeTest in a PathExpr step. Cursor is at '['. Chunk-2 supports two
// forms per grammar [132]–[133]:
//   - `[INT]`    — 1-indexed positional filter (.position)
//   - `[@…]`     — attribute test (.attr_test) — same shape as
//                  ProgramPatternAttr (existence / absence / equality /
//                  comparison). Reuses parse_pattern_attr.
// The general `.expr` form (XPath 3.1 truthy-EBV predicate) is parsed
// nowhere yet: the spec-side context-item binding inside predicate
// bodies needs spec clarification before we can land it cleanly. Until
// then, predicate sources that aren't `[INT]` or `[@…]` raise CXER0100
// with an explicit deferral note — matching the no-stubs/no-partial-impl
// gate from the design lock.
fn (mut p ProgramParser) parse_path_predicate() !ProgramPathPredicate {
	start := p.peek().pos
	p.expect(.lbrack, "'[' opening CXPath predicate")!
	// Atomic templates first (sugar), then general expression
	// body. The atomic-template fast paths preserve canonical-render
	// fidelity; the general expression fallback covers
	// every other shape (`[and …]`, `[last()]`, `[$_position = …]`, etc.).
	match p.peek_kind() {
		.number_lit {
			// `[N]` positional predicate — only when the bracket
			// content is *just* an integer (no trailing operator).
			// `[5 > 2]` would otherwise be mis-parsed; check the
			// post-number token to disambiguate.
			next1 := p.peek_kind_at(1)
			if next1 == .rbrack {
				tok := p.advance()
				if tok.text.contains('.') || tok.text.contains('e') || tok.text.contains('E') {
					return ParseError{
						message: 'CXPath positional predicate must be an integer; got float `${tok.text}`'
						pos:     tok.pos
					}
				}
				idx := tok.text.i64()
				if idx <= 0 {
					return ParseError{
						message: 'CXPath positional predicate must be a 1-indexed positive integer (XPath 3.1); got ${idx}'
						pos:     tok.pos
					}
				}
				p.expect(.rbrack, "']' closing CXPath positional predicate")!
				return ProgramPathPredicate{
					kind:      .position
					int_index: idx
					pos:       start
				}
			}
			// Numeric expression body — fall through to general.
			return p.parse_path_predicate_general(start)!
		}
		.at, .at_bang {
			// `[@…]` attribute test — but if it's `[@a op v and …]`
			// (compound), defer to general parsing. The atomic
			// fast-path requires the bracket body to be *just* an
			// attribute test, so check after parse_pattern_attr
			// whether the next token is `]`.
			save_pos := p.pos
			pa := p.parse_pattern_attr() or {
				p.pos = save_pos
				return p.parse_path_predicate_general(start)!
			}
			if p.peek_kind() == .rbrack {
				p.advance() // consume ']'
				return ProgramPathPredicate{
					kind:       .attr_test
					attr_kind:  pa.kind
					attr_name:  pa.name
					attr_op:    pa.op
					attr_value: pa.value
					pos:        start
				}
			}
			// Compound — rewind and re-parse as a general expression.
			// This only matters for forms like `[@a=true and @b=false]`
			// which use infix `and`; the atomic path can't represent
			// them. The rewind is safe because parse_pattern_attr only
			// consumed atoms; no side effects.
			p.pos = save_pos
			return p.parse_path_predicate_general(start)!
		}
		else {
			return p.parse_path_predicate_general(start)!
		}
	}
}

// parse_path_predicate_general parses a non-atomic predicate body as
// a general ProgramExpr. Special-cases the XPath sugar
// `[last()]` → `[$_position = $_last]`. The body parses with `$_`,
// `$_position`, `$_last` available as ordinary bindings (the evaluator
// injects them on entry to the predicate body).
fn (mut p ProgramParser) parse_path_predicate_general(start Position) !ProgramPathPredicate {
	// `[last()]` sugar (amendment): a bare `last()` call
	// inside a predicate body means "the last position" (XPath 3.1).
	// The bare ident `last` outside predicate context remains a normal
	// user-callable; the desugaring is predicate-only.
	if p.peek_kind() == .ident && p.peek().text == 'last'
	   && p.peek_kind_at(1) == .lparen && p.peek_kind_at(2) == .rparen
	   && p.peek_kind_at(3) == .rbrack {
		p.advance() // 'last'
		p.advance() // '('
		p.advance() // ')'
		p.advance() // ']'
		// Synthetic marker the evaluator recognizes. The body is a
		// ProgramCall named '__pred_last' with no args; eval handles
		// it as "keep only the final candidate".
		marker := ProgramCall{
			name:         '__pred_last'
			args:         []
			fallible:     false
			must_succeed: false
			pos:          start
		}
		return ProgramPathPredicate{
			kind: .expr
			body: ProgramNode(marker)
			pos:  start
		}
	}
	p.predicate_depth++
	// Element-literal-as-predicate-body shape: when the predicate body
	// starts with an element-head token (ident, operator like `=`, `<`,
	// `+`), the predicate brackets do double-duty as element-literal
	// brackets. The body is parsed via parse_cx_element_from_inside,
	// which consumes through the matching `]`. This admits the directive
	// form `[and [= @a v] [> @b w]]` directly without requiring nested
	// brackets `[[and ...]]`.
	if is_element_head_token(p.peek_kind()) {
		// Distinguish from the `[fn(args)]` general-call shape: when
		// an ident is followed by `(`, parse as a bare function call
		// (`[count(*) > 0]` etc.). Otherwise treat as element-literal
		// (e.g. `[and ...]`, `[= a b]`).
		if p.peek_kind() == .ident && p.peek_kind_at(1) == .lparen {
			// `count(...) >= N` etc. — a FunctionCall primary that may be
			// the LHS of an infix comparison. Route through the infix
			// parser so the trailing CompOp / `and` / `or` is consumed.
			body := p.parse_pred_infix() or {
				p.predicate_depth--
				return err
			}
			p.predicate_depth--
			p.expect(.rbrack, "']' closing CXPath predicate")!
			return ProgramPathPredicate{
				kind: .expr
				body: body
				pos:  start
			}
		}
		body_lit := p.parse_cx_element_from_inside(start) or {
			p.predicate_depth--
			return err
		}
		p.predicate_depth--
		// parse_cx_element_from_inside consumed the closing ']'
		return ProgramPathPredicate{
			kind: .expr
			body: ProgramNode(body_lit)
			pos:  start
		}
	}
	body := p.parse_pred_infix() or {
		p.predicate_depth--
		return err
	}
	p.predicate_depth--
	p.expect(.rbrack, "']' closing CXPath predicate")!
	return ProgramPathPredicate{
		kind: .expr
		body: body
		pos:  start
	}
}

// parse_pred_infix parses a CXPath predicate body using XPath-style
// INFIX surface, a deliberate parity exception to CX's prefix element
// form (grammar [132a]/[133]; code.md §5.5.2 + §6.3). The body grammar:
//
//   OrExpr   ::= AndExpr ('or' AndExpr)*
//   AndExpr  ::= CmpExpr ('and' CmpExpr)*
//   CmpExpr  ::= Primary (CompOp Primary)?        CompOp ∈ = != < <= > >=
//   Primary  ::= parse_atom  (bindings w/ @attr + path, literals,
//                FunctionCall `count(...)`, bare `@name`/`$_` sugar,
//                nested prefix elements `[and …]`)
//
// Each infix node desugars to the prefix operator-headed element
// (`[>= $_@age 18]`, `[and …]`, `[= $_position 1]`) that
// `eval_operator_element` already dispatches — a `.cx_element`
// ProgramLiteral whose `name` is the operator string. So eval_node /
// filter_path_predicates_idx need no new arms. Comparison is
// non-associative (single CompOp per CmpExpr); `and` binds tighter than
// `or`, both left-associative.
fn (mut p ProgramParser) parse_pred_infix() !ProgramNode {
	return p.parse_pred_or()!
}

fn pred_op_element(op string, left ProgramNode, right ProgramNode, pos Position) ProgramNode {
	return ProgramNode(ProgramLiteral{
		kind:  .cx_element
		name:  op
		items: [left, right]
		pos:   pos
	})
}

fn (mut p ProgramParser) parse_pred_or() !ProgramNode {
	mut left := p.parse_pred_and()!
	for p.peek_kind() == .ident && p.peek().text == 'or' {
		op_pos := p.advance().pos
		right := p.parse_pred_and()!
		left = pred_op_element('or', left, right, op_pos)
	}
	return left
}

fn (mut p ProgramParser) parse_pred_and() !ProgramNode {
	mut left := p.parse_pred_cmp()!
	for p.peek_kind() == .ident && p.peek().text == 'and' {
		op_pos := p.advance().pos
		right := p.parse_pred_cmp()!
		left = pred_op_element('and', left, right, op_pos)
	}
	return left
}

fn (mut p ProgramParser) parse_pred_cmp() !ProgramNode {
	left := p.parse_atom()!
	k := p.peek_kind()
	if k == .eq || k == .neq || k == .lt || k == .le || k == .gt || k == .ge {
		op_tok := p.advance()
		right := p.parse_atom()!
		return pred_op_element(op_tok.text, left, right, op_tok.pos)
	}
	return left
}

// parse_number_literal turns a `number_lit` token into an int_lit or
// float_lit ProgramLiteral, depending on the literal's textual shape.
fn parse_number_literal(t ProgramToken) !ProgramLiteral {
	// §9 [L20] — converged with the data parser's try_autotype (cxparse Phase
	// 4.2). Hex ints (`0x…`), `_` separators, and the [L20c] leading-zero rule
	// are all handled identically on both sides. A token that fails to parse as
	// the recognised number falls through to a string literal (its bare source
	// text), matching the data side's Text fallback.
	// [L20a] hex int, with optional `_` separators between hex digits.
	if t.text.starts_with('0x') || t.text.starts_with('0X') {
		body := strip_underscores(t.text[2..]) or { return number_literal_as_string(t) }
		if v := strconv.parse_int(body, 16, 64) {
			return ProgramLiteral{
				kind:    .int_lit
				int_val: v
				pos:     t.pos
			}
		}
		return number_literal_as_string(t)
	}
	if t.text.starts_with('-0x') || t.text.starts_with('-0X') {
		body := strip_underscores(t.text[3..]) or { return number_literal_as_string(t) }
		if v := strconv.parse_int(body, 16, 64) {
			return ProgramLiteral{
				kind:    .int_lit
				int_val: -v
				pos:     t.pos
			}
		}
		return number_literal_as_string(t)
	}
	// Decimal int / float — strip `_` separators ([L20b]/[L20c]) before parsing.
	cleaned := strip_underscores(t.text) or { return number_literal_as_string(t) }
	if cleaned.contains('.') || cleaned.contains('e') || cleaned.contains('E') {
		return ProgramLiteral{
			kind:    .float_lit
			flt_val: cleaned.f64()
			pos:     t.pos
		}
	}
	// Leading-zero rule (lexicon [L20c]): a plain integer with a leading zero
	// (`02134`) is NOT an Integer — it falls through to a string, preserving ZIP
	// codes / SKUs. Mirrors the data parser's is_v34_decimal_int. The lone `0`
	// (and `-0`) stays an int. The string keeps the ORIGINAL token text (with
	// any underscores), matching the data side's Text value.
	if has_leading_zero_int(cleaned) {
		return number_literal_as_string(t)
	}
	// In-range decimal int → int_lit. A well-formed integer that OVERFLOWS
	// i64 AUTO-PROMOTES to a bigint literal (D-H) — staying numeric, mirroring
	// the data reading's try_autotype bigint fallback — rather than silently
	// wrapping/clamping via `cleaned.i64()`. parse_i64_checked round-trips the
	// parse to catch the near-boundary clamp that .parse_int / strconv hide.
	if v := parse_i64_checked(cleaned) {
		return ProgramLiteral{
			kind:    .int_lit
			int_val: v
			pos:     t.pos
		}
	}
	return ProgramLiteral{
		kind:    .bigint_lit
		str_val: normalize_bigint_digits(cleaned)
		pos:     t.pos
	}
}

// normalize_bigint_digits canonicalizes a decimal integer string for storage
// as a bigint value: a redundant leading `+` is dropped (`+12…` → `12…`),
// matching the canonical render rule for numbers ([L20]). A leading `-` is
// preserved.
fn normalize_bigint_digits(s string) string {
	if s.starts_with('+') {
		return s[1..]
	}
	return s
}

// number_literal_as_string is the [L20] fallback: a numeric-shaped token that
// is not a recognised Integer / Float / HexInt (leading zero, malformed
// underscores, hex overflow) becomes a string literal carrying its original
// source text — the program-side mirror of the data parser's Text fallback.
fn number_literal_as_string(t ProgramToken) ProgramLiteral {
	return ProgramLiteral{
		kind:    .string_lit
		str_val: t.text
		pos:     t.pos
	}
}

// ── Bindings + paths ────────────────────────────────────────────────────────

// lbrack_adjacent_to_prev reports whether the current token (expected to be
// `[`) is byte-adjacent to the immediately preceding token — i.e. no
// whitespace separates them in source. Used to distinguish a binding/slice
// postfix `$x[…]` (touching) from a separate operand `$x [ot]` (spaced),
// per whitespace-significant postfix rule (the same adjacency
// test `fold_qualified_name` uses for `/`).
fn (p ProgramParser) lbrack_adjacent_to_prev() bool {
	return p.cur_adjacent_to_prev()
}

// cur_adjacent_to_prev reports whether the current token is byte-adjacent to
// the immediately preceding token (no whitespace between them in source).
fn (p ProgramParser) cur_adjacent_to_prev() bool {
	if p.pos == 0 || p.pos >= p.tokens.len {
		return false
	}
	cur := p.tokens[p.pos]
	prev := p.tokens[p.pos - 1]
	return cur.pos.offset == prev.pos.offset + prev.text.len
}

// fold_binding_step_prefix takes the bare name already consumed for a
// binding-path step's NodeTest and, when a `Prefix ':' LocalName`
// namespace step follows, consumes the `:local` and returns the literal
// qualified name `prefix:local`. This mirrors parse_path_step's
// `Prefix ':' LocalName` handling (parser.v ~460) so the binding-path
// engine matches namespace-prefixed element names the same way the
// standalone PathExpr and [?modify] focus-path engines do.
//
// CX element names carry the prefix literally (first-occurrence namespace
// model per spec/namespaces.md), so the literal qualified name is the
// match key — the walker's `el.name == step.name` equality then matches
// an element named exactly `prefix:local` (decision (a), commit 57e064f7).
//
// The terminator guard (is_path_step_terminator) is replicated so a
// trailing `:label` modifier keyword (`:in`, `:using`, …) is NOT swallowed
// as a namespace local-name; in that case the bare name is returned and
// the `:label` is left for the enclosing directive parser.
fn (mut p ProgramParser) fold_binding_step_prefix(name string) !string {
	if p.peek_kind() == .colon
	   && !(p.peek_kind_at(1) == .ident
	        && is_path_step_terminator(p.peek_at(1).text)) {
		p.advance() // consume ':'
		local_tok := p.expect(.ident, "local name after prefix ':' in binding-path namespace step")!
		return '${name}:${local_tok.text}'
	}
	return name
}

fn (mut p ProgramParser) parse_binding_with_path() !ProgramBinding {
	dollar := p.expect(.dollar, "'$'")!
	name_tok := p.expect(.ident, 'binding name after $')!
	// QName fold (§12.1.1): a byte-adjacent `:local` after the prefix
	// makes `$prefix:local` a single module-qualified member reference
	// (e.g. `$math:sqrt`). Single `:` only — the glued `::` type
	// annotation is a distinct token (double_colon).
	mut bname := name_tok.text
	if p.peek_kind() == .colon {
		colon := p.peek()
		if colon.pos.offset == name_tok.pos.offset + name_tok.text.len
		   && p.peek_kind_at(1) == .ident {
			local := p.peek_at(1)
			if local.pos.offset == colon.pos.offset + 1 {
				p.advance() // ':'
				p.advance() // local
				bname = '${name_tok.text}:${local.text}'
			}
		}
	}
	mut steps := []ProgramPathStep{}
	for {
		// PROTOTYPE (gap-α): a path-step token (`/`, `//`, `@`, `.`) binds to
		// the binding ONLY when byte-adjacent (no whitespace) to the preceding
		// token — mirroring the predicate-`[` and qualified-`/` adjacency
		// rules. A space-separated step token is a separate operand, so
		// `[$count //*]` parses as head `$count` + arg `//*`.
		sk0 := p.peek_kind()
		if (sk0 == .slash || sk0 == .double_slash || sk0 == .at || sk0 == .dot)
		   && !p.cur_adjacent_to_prev() {
			break
		}
		// Per-step parse: choose the step kind based on the leading
		// token. After the step kind is determined, harvest any
		// trailing `[…]` predicates.
		mut step_kind := PathStepKind.child
		mut step_name := ''
		mut have_step := true
		match p.peek_kind() {
			.double_slash {
				// `//name` or `//*` — descendant axis (G1).
				// Suppressed when no_descendant_in_binding_path is set
				// (e.g. inside [?modify] doc-expr parsing where the
				// trailing `//` belongs to the focus PathExpr, not
				// the doc binding's path).
				if p.no_descendant_in_binding_path {
					have_step = false
					// fall through to break the step loop
				} else {
					p.advance()
					if p.peek_kind() == .star {
						p.advance()
						step_kind = .descendant_wildcard
						step_name = '*'
					} else {
						n := p.expect(.ident, 'name after //')!
						step_kind = .descendant
						step_name = p.fold_binding_step_prefix(n.text)!
					}
				}
			}
			.slash {
				p.advance()
				if p.peek_kind() == .star {
					p.advance()
					step_kind = .wildcard_children
					step_name = '*'
				} else if p.peek_kind() == .at {
					// `/@name` — XPath 3.1 attribute-axis short form.
					p.advance()
					n := p.expect(.ident, 'name after /@')!
					step_kind = .attr
					step_name = p.fold_binding_step_prefix(n.text)!
				} else if p.peek_kind() == .dot && p.peek_kind_at(1) == .dot {
					// `/..` — parent axis (G2). Lexer emits
					// `.dot` per byte, so two consecutive `.dot` tokens
					// after `/` is the parent shorthand.
					p.advance() // first dot
					p.advance() // second dot
					step_kind = .parent
					step_name = ''
				} else {
					n := p.expect(.ident, 'name after /')!
					step_kind = .child
					step_name = p.fold_binding_step_prefix(n.text)!
				}
			}
			.at {
				// `@name` is a path step EXCEPT when followed by a
				// comparison operator: in pattern-body position
				// `[elem $bind @attr=$x]`, the `@attr=$x` is a peer
				// pattern-attr predicate, not a binding path step.
				//
				// Inside a CXPath predicate body (predicate_depth > 0),
				// the comparison belongs to the predicate's INFIX surface
				// (`$_@age >= 18` per code.md §5.5.2): the `@age` is the
				// attribute path step on `$_`, and the `>=` is the
				// predicate comparator parsed by parse_pred_infix. So the
				// peer-attr break only applies outside predicate bodies.
				if p.predicate_depth == 0 && p.peek_kind_at(1) == .ident {
					next := p.peek_kind_at(2)
					if next == .eq || next == .neq || next == .lt
					   || next == .le || next == .gt || next == .ge {
						break
					}
				}
				p.advance()
				n := p.expect(.ident, 'name after @')!
				step_kind = .attr
				step_name = p.fold_binding_step_prefix(n.text)!
			}
			.dot {
				// `.foo` path step — distinguished from member access in
				// other contexts by the absence of a leading number;
				// the lexer guarantees `.5` lexes as a number, so `.` here
				// is unambiguously a path step.
				p.advance()
				n := p.expect(.ident, 'name after .')!
				step_kind = .member
				step_name = n.text
			}
			else {
				have_step = false
			}
		}
		if !have_step {
			break
		}
		// Trailing predicates on this step. Reuse
		// parse_path_predicate which now also handles general `expr`
		// bodies.
		//
		// a predicate `[…]` binds to the step ONLY when it is
		// byte-adjacent (no whitespace) to the preceding token, mirroring
		// the `/`-adjacency rule for qualified names (`fold_qualified_name`).
		// A space-separated `[…]` is a separate operand — e.g. in a call
		// arg list `[$f $x [g]]`, `[g]` is the second argument, not a
		// predicate on `$x`. The existing corpus writes every predicate
		// adjacent (`$x/item[1]`, `$u/user[@active]`), so this is a
		// near-zero-regression tightening.
		mut preds := []ProgramPathPredicate{}
		for p.peek_kind() == .lbrack && p.lbrack_adjacent_to_prev() {
			preds << p.parse_path_predicate()!
		}
		steps << ProgramPathStep{
			kind:       step_kind
			name:       step_name
			predicates: preds
		}
	}
	return ProgramBinding{
		name: bname
		path: steps
		pos:  dollar.pos
	}
}

// ── slice-postfix on $binding ────────────────────────────────────
//
// `is_slice_postfix_after_binding` performs the positional lookahead
// required by disambiguation table for the `$binding[…]`
// case. The cursor MUST be sitting on the opening `[`. We scan the
// bracket body at top level (not descending into nested `[]`, `()`, or
// `{}`) and look for any of:
//   - a leading `:`          — open-start range form, e.g. `[:5]`
//   - a top-level `:`        — explicit range separator, e.g. `[2:5]`
//   - a leading `*`          — full-axis marker, e.g. `[*]` / `[*, …]`
//   - a top-level `,`        — multi-axis form (parsed but evaluated
//                              in a later milestone, W6-E)
//
// When any of the above is present the `[…]` is a `SliceAxes` list
// and the outer parser routes through
// `parse_slice_postfix`. When none is present the bracket is left for
// outer handling — `$xs[2]` with a single-Expr body falls back to the
// predicate semantics on the existing parsing path (which at
// There is currently no rule for a `[Expr]` postfix on a bare binding; that
// arm is currently unreachable and will surface as a parse error
// upstream).
//
// The function is `pure` w.r.t. parser state — it inspects tokens
// starting at `p.pos` without advancing.
fn is_slice_postfix_after_binding(p ProgramParser) bool {
	// Sanity: caller asserts the lbrack peek, but we don't depend on it.
	if p.peek_kind() != .lbrack {
		return false
	}
	mut i := p.pos + 1 // one past `[`
	if i >= p.tokens.len {
		return false
	}
	head_kind := p.tokens[i].kind
	// Leading `:` or `::` — open-start range. The lexer emits `::` as a
	// single `double_colon` token (CXPath axis separator); inside a
	// slice axis we treat it as the start:stop:step "no start, no stop"
	// pair, e.g. `[::2]` → step=2.
	if head_kind == .colon || head_kind == .double_colon {
		return true
	}
	// Leading `*` followed by `]` or `,` — full-axis form. We
	// deliberately do NOT treat a leading `*` followed by an operator
	// (e.g. `* 2`) as slice: that would be an expression body and the
	// grammar reserves `*` as the full-axis marker only when
	// it stands alone in its axis slot.
	if head_kind == .star {
		next := if i + 1 < p.tokens.len { p.tokens[i + 1].kind } else { ProgramTokenKind.eof }
		if next == .rbrack || next == .comma {
			return true
		}
	}
	// Element-head guard. When `$NCName` is followed by a `[…]` whose
	// first token is an element-head token (an `ident` or one of the
	// operator heads `* + - / = != < <= > >=`), the bracket is an
	// element literal that just *happens* to follow a $binding — it's a
	// separate expression, not a postfix. The two surfaces collide in
	// whitespace-insensitive CX (`$err [fallback ...]` lexes identically
	// to `$err[fallback ...]`), and the positional disambiguation
	// rule "after $NCName → BindingPostfix" must be tightened to "after
	// $NCName, when the bracket head is NOT an element-head token". The
	// new gate keeps the surface congruent with prior behavior — every existing
	// `$x [elem ...]` shape continues to parse as two adjacent
	// expressions.
	if is_element_head_token(head_kind) {
		return false
	}
	// Scan for top-level `:` / `::` / `,` before the matching `]`. Any
	// of these makes the bracket a slice surface (range or multi-axis).
	// Otherwise — single-expression body — also route to the slice
	// surface as the single-index axis (`$xs[3]`). The
	// element-head guard above already prevents `$err [fallback ...]`
	// from being misclassified. W5c (the evaluation milestone) closed
	// the W5b "predicate-fallback" comment by tightening single-index
	// to a structured `ProgramSliceAccess` AST node.
	mut depth := 0
	for j := i; j < p.tokens.len; j++ {
		k := p.tokens[j].kind
		match k {
			.lbrack, .ldirective, .directive_name, .lparen, .lbrace { depth++ }
			.rbrack, .rparen, .rbrace {
				if depth == 0 {
					// Reached the matching `]` without seeing slice
					// markers. Body is a single expression — route as
					// a single-axis slice.
					return true
				}
				depth--
			}
			.colon {
				// `prefix:local` qualified-name colon is not a slice marker.
				if depth == 0 && !p.colon_is_qualified_name(j) {
					return true
				}
			}
			.double_colon {
				if depth == 0 {
					return true
				}
			}
			.comma {
				if depth == 0 {
					return true
				}
			}
			.eof { return false }
			else {}
		}
	}
	return false
}

// is_slice_literal_body_here detects a standalone Slice literal sitting
// inside a bracket (cursor JUST PAST `[`). Used by parse_bracket to
// recognise the `[2:5]` / `[::-1]` / `[*]` shapes. The
// detection rules mirror `is_slice_postfix_after_binding` but are
// tightened on three counts:
//
//   1. Single-expression bodies (`[3]`) do NOT route to Slice — they
//      stay array literals to preserve `[1, 2, 3]` and `[42]` shapes.
//   2. Multi-axis bodies (top-level `,`) do NOT route to Slice — they
//      stay array literals; multi-axis only appears after a binding
//      postfix.
//   3. The element-head guard rejects `[+ 1 2]` / `[name body…]`.
//
// What DOES route to Slice (returns true):
//   - leading `:` / `::` — open-start range
//   - leading lone `*` followed by `]` — full-axis literal
//   - top-level `:` / `::` between expressions — closed-form range
fn is_slice_literal_body_here(p ProgramParser) bool {
	// Cursor sits ON the first token of the body (just past `[`).
	if p.pos >= p.tokens.len {
		return false
	}
	head := p.tokens[p.pos].kind
	// Leading `:` / `::` — unambiguously a range form.
	if head == .colon || head == .double_colon {
		return true
	}
	// a `$`-headed bracket is unambiguously a call form
	// `[$fn arg…]` (or array `[$x, $y]` when a top-level `,` is present);
	// never a slice literal. Without this guard, `[$cast "42" :int]` is
	// misread as a slice because of the top-level `:` before the atom
	// literal `:int` (the `:` predates the dollar-call dispatch in
	// `parse_bracket`).
	if head == .dollar {
		return false
	}
	// Leading lone `*` followed by `]` — full-axis literal `[*]`. A
	// lone `*` followed by `,` is multi-axis (rejected here). A `*`
	// followed by an operator is the multiplication element head.
	if head == .star {
		next := if p.pos + 1 < p.tokens.len {
			p.tokens[p.pos + 1].kind
		} else {
			ProgramTokenKind.eof
		}
		if next == .rbrack {
			return true
		}
		return false
	}
	// Element-head guard — `[+ 1 2]`, `[name body]`, etc. stay as elements.
	if is_element_head_token(head) {
		return false
	}
	// Scan for top-level `:` / `::` before the matching `]`. Any of
	// these makes the bracket a range-form Slice literal. A top-level
	// `,` or no slice-marker tokens at all routes the bracket to the
	// array-literal arm (single-expression bracket bodies stay arrays
	// of one element so existing code that builds `[42]` keeps working).
	mut depth := 0
	for j := p.pos; j < p.tokens.len; j++ {
		k := p.tokens[j].kind
		match k {
			.lbrack, .ldirective, .directive_name, .lparen, .lbrace { depth++ }
			.rbrack, .rparen, .rbrace {
				if depth == 0 {
					return false
				}
				depth--
			}
			.colon {
				// A `prefix:local` qualified-name colon (ident:ident,
				// byte-adjacent) is NOT a slice separator — e.g. the `:` in
				// a CXPath nodetest `//svg:circle`. Without this skip a
				// `[$fn //svg:circle]` call body is misread as a slice
				// literal.
				if depth == 0 && !p.colon_is_qualified_name(j) {
					return true
				}
			}
			.double_colon {
				if depth == 0 {
					return true
				}
			}
			.comma {
				if depth == 0 {
					return false
				}
			}
			.eof { return false }
			else {}
		}
	}
	return false
}

// colon_is_qualified_name reports whether the `.colon` token at index `j` is
// the separator of a `prefix:local` NCName (an ident on each side, all three
// byte-adjacent) rather than a slice-range `:`. CXPath nodetests like
// `svg:circle` use this form; slice ranges (`2:5`, `$a:$b`) do not.
fn (p ProgramParser) colon_is_qualified_name(j int) bool {
	if j == 0 || j + 1 >= p.tokens.len {
		return false
	}
	prev := p.tokens[j - 1]
	col := p.tokens[j]
	nxt := p.tokens[j + 1]
	if prev.kind != .ident || nxt.kind != .ident {
		return false
	}
	return col.pos.offset == prev.pos.offset + prev.text.len
		&& nxt.pos.offset == col.pos.offset + 1
}

// parse_slice_literal_from_inside parses a single-axis Slice literal
// body. Cursor sits just past `[`; the closing `]` is consumed here.
//
// Per multi-axis literals are NOT admitted in standalone
// expression position (they collide with array literals). A surface
// `[1:3, 2:4]` outside a $binding postfix routes to array-literal
// parsing upstream; the comma never reaches here.
fn (mut p ProgramParser) parse_slice_literal_from_inside(start Position) !ProgramNode {
	axis := p.parse_slice_axis()!
	p.expect(.rbrack, "']' closing slice literal")!
	return ProgramSliceLiteral{
		axes: [axis]
		pos:  start
	}
}

// parse_slice_postfix consumes a `$binding[SliceAxes]` postfix per
// BindingPostfix. The cursor is on `[`; the caller has
// already constructed `binding` for the underlying `$NCName(/path)?`.
// Constructs and returns a `ProgramSliceAccess`. The slice axes are
// parsed (single index, range, full); evaluation is deferred to W5c.
fn (mut p ProgramParser) parse_slice_postfix(binding ProgramBinding) !ProgramNode {
	start := p.peek().pos
	p.expect(.lbrack, "'[' opening slice postfix")!
	mut axes := []SliceAxis{}
	for {
		axes << p.parse_slice_axis()!
		if p.peek_kind() == .comma {
			p.advance()
			continue
		}
		break
	}
	p.expect(.rbrack, "']' closing slice postfix")!
	return ProgramSliceAccess{
		binding: binding
		axes:    axes
		pos:     start
	}
}

// parse_slice_axis consumes one axis inside a `SliceAxes` list. The
// cursor is on the first token of the axis (one of `:`, `::`, `*`, or
// an expression token). Returns a `SliceAxis` with the appropriate
// `kind` and bound expressions.
//
// Lexer note: `::` is emitted as a single `double_colon` token (it's
// the CXPath axis separator at the data layer). Inside a
// slice axis we treat `::` as a pair of `:` — first colon ends the
// start segment, second colon enters the step segment.
fn (mut p ProgramParser) parse_slice_axis() !SliceAxis {
	start := p.peek().pos
	// `*` — full-axis marker (only when followed by `]` or `,`; the
	// upstream disambiguator already enforces this, but we re-check here
	// so the axis parser is robust to direct callers).
	if p.peek_kind() == .star {
		next := p.peek_kind_at(1)
		if next == .rbrack || next == .comma {
			p.advance() // consume `*`
			return SliceAxis{ kind: .full, pos: start }
		}
	}
	// Leading `::` — open-start range, second colon already in hand;
	// step segment may follow. Examples: `[::]`, `[::2]`, `[::-1]`.
	if p.peek_kind() == .double_colon {
		p.advance() // consume `::`
		return p.parse_slice_axis_after_second_colon(start, ?ProgramNode(none),
			?ProgramNode(none))!
	}
	// Leading `:` — open-start range with one colon consumed. `[:STOP]`
	// or `[:STOP:STEP]`.
	if p.peek_kind() == .colon {
		p.advance() // consume `:`
		return p.parse_slice_axis_after_first_colon(start, ?ProgramNode(none))!
	}
	// Otherwise parse an expression for `start` (or the lone single
	// index). After the expression, `:` or `::` puts us in range
	// territory; otherwise it's a single-index axis.
	first := p.parse_expr()!
	if p.peek_kind() == .double_colon {
		p.advance() // consume `::`
		return p.parse_slice_axis_after_second_colon(start, ?ProgramNode(first),
			?ProgramNode(none))!
	}
	if p.peek_kind() == .colon {
		p.advance() // consume `:`
		return p.parse_slice_axis_after_first_colon(start, ?ProgramNode(first))!
	}
	return SliceAxis{ kind: .single, start: ?ProgramNode(first), pos: start }
}

// zero_step_literal_pos returns the source position of a slice STEP that is
// the literal integer `0` — the D21 step-of-zero reject. Per the formal
// contract (grammar.ebnf GR-SLICE-STEP-ZERO) a literal `0` step is rejected at
// PARSE time (CXER0100). A computed step (`[::$n]` with $n==0) is not visible
// here and stays the eval-time D21 check (apply_range_slice). Returns `none`
// for any non-literal or non-zero step.
fn zero_step_literal_pos(step ?ProgramNode) ?Position {
	s := step or { return none }
	if s is ProgramLiteral {
		if s.kind == .int_lit && s.int_val == 0 {
			return s.pos
		}
	}
	return none
}

// parse_slice_axis_after_first_colon completes a range-form axis after
// the first `:` has already been consumed. `start_expr` carries the
// pre-`:` expression (possibly `none` for `[:STOP]`-style forms).
//
// Grammar inside this helper (with cursor just past the first `:`):
//   ε              → `START:`             — open stop
//   ]              → `START:`             — open stop (alt rep)
//   ,              → `START:`             — open stop in multi-axis
//   EXPR           → `START:STOP`         — closed stop
//   :              → `START::STEP`        — open stop, explicit step
//   ::             → `START::STEP`        — alt lexing of the same
//   EXPR ':' EXPR  → `START:STOP:STEP`
fn (mut p ProgramParser) parse_slice_axis_after_first_colon(start Position, start_expr ?ProgramNode) !SliceAxis {
	// Try to read STOP. Empty STOP is signalled by `]`, `,`, `:`, or `::`.
	mut stop_expr := ?ProgramNode(none)
	k := p.peek_kind()
	if k != .rbrack && k != .comma && k != .colon && k != .double_colon {
		stop_expr = ?ProgramNode(p.parse_expr()!)
	}
	// Optional STEP after the second `:`. Lexer may emit it as either
	// `:` (alone) or `::` (when STOP was absent and the second colon
	// glued to the first); both are normalised here.
	mut step_expr := ?ProgramNode(none)
	k2 := p.peek_kind()
	if k2 == .colon {
		p.advance() // consume second `:`
		k3 := p.peek_kind()
		if k3 != .rbrack && k3 != .comma {
			step_expr = ?ProgramNode(p.parse_expr()!)
		}
	} else if k2 == .double_colon {
		// Reached when STOP was present and the next two colons glued
		// into `::`. By the lexer's longest-match this only happens
		// when STOP is absent — i.e. when we've already consumed the
		// first colon and the lexer saw `::` then. In practice the
		// stop branch above won't have consumed anything, so the
		// double_colon survives here and means "second colon + step
		// is open" — equivalent to `:` with a follow-on step parse.
		p.advance() // consume `::`
		k3 := p.peek_kind()
		if k3 != .rbrack && k3 != .comma {
			step_expr = ?ProgramNode(p.parse_expr()!)
		}
	}
	if zpos := zero_step_literal_pos(step_expr) {
		return ParseError{
			code:    'cx-err:CXER0100'
			message: 'slice step cannot be zero'
			pos:     zpos
		}
	}
	return SliceAxis{
		kind:  .range
		start: start_expr
		stop:  stop_expr
		step:  step_expr
		pos:   start
	}
}

// parse_slice_axis_after_second_colon completes a range-form axis
// after `::` has been consumed (start is optional, stop is implicitly
// `none`). An optional step expression may follow before the closing
// `]` / `,`.
fn (mut p ProgramParser) parse_slice_axis_after_second_colon(start Position, start_expr ?ProgramNode, stop_expr ?ProgramNode) !SliceAxis {
	mut step_expr := ?ProgramNode(none)
	k := p.peek_kind()
	if k != .rbrack && k != .comma {
		step_expr = ?ProgramNode(p.parse_expr()!)
	}
	if zpos := zero_step_literal_pos(step_expr) {
		return ParseError{
			code:    'cx-err:CXER0100'
			message: 'slice step cannot be zero'
			pos:     zpos
		}
	}
	return SliceAxis{
		kind:  .range
		start: start_expr
		stop:  stop_expr
		step:  step_expr
		pos:   start
	}
}

// ── Calls / bare idents ─────────────────────────────────────────────────────

// fold_qualified_name folds a module-qualified call name `prefix/fn`
// (spec/code.md §12.1.1) into a single name string. It fires only when
// the `/` and the trailing ident are *byte-adjacent* to the preceding
// ident (no intervening whitespace) — that adjacency is what
// distinguishes the qualified-call surface `math/abs` from a path body
// item like `[cfg /a/b]` (where a space separates the head from `/a`).
// Non-ident heads and non-adjacent `/` return the bare name unchanged.
fn (mut p ProgramParser) fold_qualified_name(name_tok ProgramToken) string {
	if name_tok.kind != .ident {
		return name_tok.text
	}
	if p.peek_kind() != .slash {
		return name_tok.text
	}
	slash := p.peek()
	if slash.pos.offset != name_tok.pos.offset + name_tok.text.len {
		return name_tok.text
	}
	if p.peek_kind_at(1) != .ident {
		return name_tok.text
	}
	fn_tok := p.peek_at(1)
	if fn_tok.pos.offset != slash.pos.offset + 1 {
		return name_tok.text
	}
	p.advance() // '/'
	p.advance() // fn ident
	return '${name_tok.text}/${fn_tok.text}'
}

// fold_qualified_colon_name folds a namespace-qualified element head
// `prefix:local` (lexicon §2 [L11] QName, grammar [7a]) into a single name
// string. It fires only when the `:` and the trailing ident are *byte-
// adjacent* to the head ident (no intervening whitespace) — that adjacency
// is what distinguishes the head qualifier `svg:rect` from a space-separated
// `:rect` atom child (`[svg :rect]`). `current` is the name produced so far
// (after the slash fold); when it differs from the raw head text a slash
// fold already claimed the head, so the colon fold declines. Non-ident heads
// and non-adjacent `:` return `current` unchanged.
fn (mut p ProgramParser) fold_qualified_colon_name(name_tok ProgramToken, current string) string {
	if name_tok.kind != .ident || current != name_tok.text {
		return current
	}
	if p.peek_kind() != .colon {
		return current
	}
	colon := p.peek()
	if colon.pos.offset != name_tok.pos.offset + name_tok.text.len {
		return current
	}
	if p.peek_kind_at(1) != .ident {
		return current
	}
	local := p.peek_at(1)
	if local.pos.offset != colon.pos.offset + 1 {
		return current
	}
	p.advance() // ':'
	p.advance() // local ident
	return '${name_tok.text}:${local.text}'
}

fn (mut p ProgramParser) parse_call_or_ident_value() !ProgramNode {
	name_tok := p.advance()
	qname := p.fold_qualified_name(name_tok)
	if p.peek_kind() != .lparen {
		return ProgramCall{
			name:         qname
			args:         []
			fallible:     false
			must_succeed: false
			pos:          name_tok.pos
		}
	}
	return p.parse_call_after_callee(qname, name_tok.pos)!
}

// parse_call_after_callee handles `(args) ['?'|'!']?` after the callee
// has already been resolved (either an ident or a $-binding). Shared
// by parse_call_or_ident_value and the dollar branch of parse_atom.
// program_hole_name marks an partial-application hole `_` in
// a call-argument position. Emitted as a sentinel ProgramCall; eval_call
// detects it and builds a partial instead of calling.
pub const program_hole_name = '__cx_hole__'

// parse_call_arg parses one call argument, recognising a bare `_` (an
// ident `_` immediately before `,` or `)`) as a partial-application hole
// `_` keeps its pattern-wildcard meaning everywhere else;
// the hole reading applies only in call-argument position.
fn (mut p ProgramParser) parse_call_arg() !ProgramNode {
	if p.peek_kind() == .ident && p.peek().text == '_'
	   && (p.peek_kind_at(1) == .comma || p.peek_kind_at(1) == .rparen) {
		hole_pos := p.peek().pos
		p.advance()
		return ProgramCall{ name: program_hole_name, args: [], explicit_call: false, pos: hole_pos }
	}
	return p.parse_expr()!
}

// parse_call_arg_labeled parses one call argument, returning its value
// node and its label ('' for positional). A `:label value` form
// (named argument) is recognised when `:ident` is followed by a
// value token; `:atom` directly before `,`/`)` stays a positional atom
// literal. Positional args go through parse_call_arg (hole-aware);
// named-arg values use parse_expr (holes are positional-only, D4).
fn (mut p ProgramParser) parse_call_arg_labeled() !(ProgramNode, string) {
	if p.peek_kind() == .colon && p.peek_kind_at(1) == .ident {
		next2 := p.peek_kind_at(2)
		if next2 != .comma && next2 != .rparen && next2 != .eof {
			p.advance() // ':'
			label_tok := p.advance()
			value := p.parse_expr()!
			return value, label_tok.text
		}
	}
	return p.parse_call_arg()!, ''
}

fn (mut p ProgramParser) parse_call_after_callee(name string, pos Position) !ProgramNode {
	p.expect(.lparen, "'('")!
	mut args := []ProgramNode{}
	mut arg_labels := []string{}
	if p.peek_kind() != .rparen {
		node0, lbl0 := p.parse_call_arg_labeled()!
		args << node0
		arg_labels << lbl0
		for p.peek_kind() == .comma {
			p.advance()
			node, lbl := p.parse_call_arg_labeled()!
			args << node
			arg_labels << lbl
		}
	}
	p.expect(.rparen, "')'")!
	mut fallible := false
	mut must_succeed := false
	match p.peek_kind() {
		.qmark { fallible = true; p.advance() }
		.bang  { must_succeed = true; p.advance() }
		else   {}
	}
	return ProgramCall{
		name:         name
		args:         args
		arg_labels:   arg_labels
		fallible:     fallible
		must_succeed: must_succeed
		explicit_call: true
		pos:          pos
	}
}

// parse_dollar_call_from_inside parses the head-dispatch call
// form `[$fn arg…]`: a path-less `$name` head (the function value to
// apply) followed by zero or more positional argument expressions, closed
// by `]`. The cursor is just past the opening `[`; the leading token is
// `.dollar`. Produces a ProgramCall (explicit_call) so eval_call's
// binding→closure dispatch resolves the bound function value. A trailing
// `?` / `!` postfix carries the same fallible / must-succeed semantics as
// the paren-call form (spec/code.md §9.2).
fn (mut p ProgramParser) parse_dollar_call_from_inside(start Position) !ProgramNode {
	head := p.parse_binding_with_path()!
	if head.path.len > 0 {
		return ParseError{
			message: 'call head `[$fn …]` may not carry path steps; bind the value first'
			pos:     head.pos
		}
	}
	mut args := []ProgramNode{}
	mut arg_labels := []string{}
	for p.peek_kind() != .rbrack && p.peek_kind() != .eof {
		// Open-end range bound ([125d]/[125e], C-gen-3): `*` is legal ONLY as
		// the `hi` (2nd positional) argument of `[$range lo *]` — it marks an
		// open-ended/lazy progression. The parser substitutes the `_open_end_`
		// atom sentinel that the range builtin recognizes. `*` in ANY other
		// position (or any other call) falls through to parse_expr and is a
		// parse error (cx-err:CXER0100), per the position restriction.
		if head.name == 'range' && args.len == 1 && p.peek_kind() == .star {
			star := p.advance()
			args << ProgramNode(ProgramLiteral{
				kind:    .atom_lit
				str_val: '_open_end_'
				pos:     star.pos
			})
			arg_labels << ''
			continue
		}
		// Partial-application hole: a bare `_` in call-argument position
		// (element form `[$fn … _ …]`) is the placeholder, matching the
		// paren-call form's parse_call_arg reading.
		if p.peek_kind() == .ident && p.peek().text == '_' {
			hpos := p.advance().pos
			args << ProgramNode(ProgramCall{ name: program_hole_name, args: [], explicit_call: false, pos: hpos })
			arg_labels << ''
			continue
		}
		// Named argument `name=value` ([125c]): an ident immediately
		// followed by `=` binds the named (keyword) parameter [153c].
		if p.peek_kind() == .ident && p.peek_kind_at(1) == .eq {
			arg_name_tok := p.advance()
			p.advance() // '='
			args << p.parse_expr()!
			arg_labels << arg_name_tok.text
		} else {
			args << p.parse_expr()!
			arg_labels << ''
		}
	}
	p.expect(.rbrack, "']' (closing call)")!
	mut fallible := false
	mut must_succeed := false
	match p.peek_kind() {
		.qmark { fallible = true; p.advance() }
		.bang { must_succeed = true; p.advance() }
		else {}
	}
	return ProgramCall{
		name:          head.name
		args:          args
		arg_labels:    arg_labels
		fallible:      fallible
		must_succeed:  must_succeed
		explicit_call: true
		pos:           start
	}
}

// is_qualified_call_head reports whether the cursor (just past `[`) is at a
// byte-adjacent module-qualified call head `prefix/fn …` — i.e. an ident
// immediately followed (no whitespace) by `/` and another ident. This is
// the same adjacency test `fold_qualified_name` applies; it is read-only
// (no token consumed).
fn (p ProgramParser) is_qualified_call_head() bool {
	if p.peek_kind() != .ident {
		return false
	}
	prefix := p.peek()
	if p.peek_kind_at(1) != .slash {
		return false
	}
	slash := p.peek_at(1)
	if slash.pos.offset != prefix.pos.offset + prefix.text.len {
		return false
	}
	if p.peek_kind_at(2) != .ident {
		return false
	}
	fn_tok := p.peek_at(2)
	return fn_tok.pos.offset == slash.pos.offset + 1
}

// parse_qualified_call_from_inside parses the head-dispatch
// qualified call `[prefix/fn arg…]` (spec/code.md §12.1.1): the folded
// `prefix/fn` name followed by zero or more positional argument
// expressions, closed by `]`, with an optional `?` / `!` postfix. Produces
// a ProgramCall (explicit_call) — the same node the `prefix/fn(args)` paren
// surface produces, so eval is unchanged. Positional-only (named call args
// stay on the paren form during dual-accept).
fn (mut p ProgramParser) parse_qualified_call_from_inside(start Position) !ProgramNode {
	name_tok := p.advance()
	head_name := p.fold_qualified_name(name_tok)
	mut args := []ProgramNode{}
	mut arg_labels := []string{}
	for p.peek_kind() != .rbrack && p.peek_kind() != .eof {
		// Partial-application hole `_` (element form), as above.
		if p.peek_kind() == .ident && p.peek().text == '_' {
			hpos := p.advance().pos
			args << ProgramNode(ProgramCall{ name: program_hole_name, args: [], explicit_call: false, pos: hpos })
			arg_labels << ''
			continue
		}
		// Named argument `name=value` ([125c]): an ident immediately
		// followed by `=` binds the named (keyword) parameter [153c].
		if p.peek_kind() == .ident && p.peek_kind_at(1) == .eq {
			arg_name_tok := p.advance()
			p.advance() // '='
			args << p.parse_expr()!
			arg_labels << arg_name_tok.text
		} else {
			args << p.parse_expr()!
			arg_labels << ''
		}
	}
	p.expect(.rbrack, "']' (closing call)")!
	mut fallible := false
	mut must_succeed := false
	match p.peek_kind() {
		.qmark { fallible = true; p.advance() }
		.bang { must_succeed = true; p.advance() }
		else {}
	}
	return ProgramCall{
		name:          head_name
		args:          args
		arg_labels:    arg_labels
		fallible:      fallible
		must_succeed:  must_succeed
		explicit_call: true
		pos:           start
	}
}

// ── Bracket disambiguation (element / array / pattern) ──────────────────────

enum BracketMode {
	expression  // [...] is element or array literal
	pattern     // [...] is a pattern (parses head + attrs + body)
}

// parse_bracket disambiguates `[…]` based on context + token lookahead:
//
//   pattern mode  → always parses as a ProgramPattern.
//   expression mode + first inner token is one of {dollar, star,
//                    double_star, colon_typeguard} → parses as
//                    ProgramPattern (rare-but-legal: top-level pattern
//                    outside [?match] is a value).
//   expression mode + commas before closing ] → array_lit.
//   expression mode + ident head + body items → cx_element (CX literal).
//   expression mode + empty []                  → array_lit (empty array).
fn (mut p ProgramParser) parse_bracket(mode BracketMode) !ProgramNode {
	start := p.peek().pos
	p.expect(.lbrack, "'['")!
	if mode == .pattern {
		return p.parse_pattern_body_from_inside(start)!
	}
	// Empty []
	if p.peek_kind() == .rbrack {
		p.advance()
		return ProgramLiteral{
			kind:  .array_lit
			items: []
			pos:   start
		}
	}
	// first-class Slice literal. A bracketed body with
	// unambiguously slice-shape (leading `:` / `::`, leading lone `*`,
	// or a top-level `:` between expressions) is a standalone Slice
	// value, not an element / array / pattern. The element-head guard
	// (ident or arithmetic head) is checked inside
	// `is_slice_literal_body_here` so `[+ 1 2]` stays an element.
	//
	// Multi-axis slice literals (`[1:3, 2:4]` standalone) are NOT
	// admitted here — top-level `,` routes to the array-literal arm
	// below. Multi-axis only appears after a `$binding` postfix
	// (ProgramSliceAccess),.
	if is_slice_literal_body_here(p) {
		return p.parse_slice_literal_from_inside(start)!
	}
	// Pattern-shape leading tokens (only in expression mode if the
	// leading token is unambiguously a pattern marker — $, **, or
	// :Type. Lone `*` is pattern-only in pattern context; in
	// expression context it's the multiplication-element head.)
	//
	// disambiguation refinement: `[$x, ...]` with a
	// top-level comma is an array literal whose first item is the
	// binding `$x`, not a pattern. Patterns use juxtaposition (no
	// commas); the comma disambiguates the two surfaces.
	k0 := p.peek_kind()
	if k0 == .dollar {
		// head-dispatch: a `$name`-headed bracket in expression
		// position is a CALL — apply the bound function value to the
		// positional arguments: `[$fn a b]`. A top-level comma still marks
		// an array literal whose first item is the binding (`[$x, $y]`),
		if p.contains_top_level_comma_before_rbrack() {
			return p.parse_array_or_element_with_commas(start)!
		}
		return p.parse_dollar_call_from_inside(start)!
	}
	if k0 == .double_star {
		if !p.contains_top_level_comma_before_rbrack() {
			return p.parse_pattern_body_from_inside(start)!
		}
		// Comma present → array literal containing binding/expr items.
		return p.parse_array_or_element_with_commas(start)!
	}
	if k0 == .colon && p.peek_kind_at(1) == .ident {
		return p.parse_pattern_body_from_inside(start)!
	}
	// The legacy dynamic element-name micro-syntax `[(:atom EXPR) …]` is
	// RETIRED (spec/code.md §6.4.1): the sole
	// computed-name surface is now the `[?element NAME-EXPR …]` directive
	// (parse_computed_element_body, dispatched from parse_directive). A
	// leading `(:atom …)` head now falls through to the array/sequence parse
	// and errors as a structural misuse — no dual-accept.
	// Element vs array disambiguation based on the first token shape:
	//   ident or operator → cx-element with that name
	//   '[' (nested array/element)
	//   '(' / '{' (sequence / map literal)
	//   any literal token → array
	// head-dispatch (spec/code.md §12.1.1): a bracket whose head
	// is a *byte-adjacent* module-qualified name `[prefix/fn …]` is a CALL
	// (the element-form counterpart of the `prefix/fn(args)` paren surface),
	// not a data element. The byte-adjacency rule (no space between
	// `prefix`, `/`, and `fn`) is what distinguishes the qualified-call head
	// from a path body item like `[cfg /a/b]` — see `fold_qualified_name`.
	if p.is_qualified_call_head() {
		return p.parse_qualified_call_from_inside(start)!
	}
	if is_element_head_token(k0) {
		// Element-shape head; the cx-element parser handles body
		// items including commas (the body is a sequence of
		// expressions, not a comma-separated array).
		return p.parse_cx_element_from_inside(start)!
	}
	// Heuristic: scan ahead for an unenclosed comma before the closing
	// `]`. Commas inside nested brackets/parens/braces don't count.
	if p.contains_top_level_comma_before_rbrack() {
		return p.parse_array_or_element_with_commas(start)!
	}
	// Single-item bracket with non-element-head first token:
	// treat as a one-element array.
	return p.parse_array_or_element_with_commas(start)!
}

// is_element_head_token reports whether a token kind is admissible as
// the head (first token) of a `[name body...]` element literal. Names
// are idents or arithmetic / comparison operators per the CX program surface
// (spec/code.md §8 worked examples use `[+ $a $b]`, `[* $x 2]`,
// `[> $x 2]` — operator-as-head element form).
fn is_element_head_token(k ProgramTokenKind) bool {
	return k == .ident || k == .star || k == .plus || k == .minus
	   || k == .slash || k == .eq || k == .neq
	   || k == .lt || k == .le || k == .gt || k == .ge
}

// contains_top_level_comma_before_rbrack scans from the current
// position (just past `[`) and looks for a top-level `,` before the
// matching `]`. Stops at EOF.
fn (p ProgramParser) contains_top_level_comma_before_rbrack() bool {
	mut depth := 0
	mut i := p.pos
	for i < p.tokens.len {
		k := p.tokens[i].kind
		match k {
			.lbrack, .ldirective, .directive_name, .lparen, .lbrace { depth++ }
			.rbrack, .rparen, .rbrace {
				if depth == 0 {
					return false
				}
				depth--
			}
			.comma {
				if depth == 0 {
					return true
				}
			}
			.eof { return false }
			else {}
		}
		i++
	}
	return false
}

// parse_array_or_element_with_commas handles a comma-bearing bracket
// body. Per spec/grammar.ebnf [56b], `[a, b, c]` is an array literal;
// every CX code value is parseable as such.
fn (mut p ProgramParser) parse_array_or_element_with_commas(start Position) !ProgramNode {
	mut items := []ProgramNode{}
	items << p.parse_expr()!
	for p.peek_kind() == .comma {
		p.advance()
		// Trailing-comma tolerance: `[a, b,]` is permitted (the
		// trailing-comma form marks ambiguous-shape
		// arrays); parse_expr would error on `]`, so we check.
		if p.peek_kind() == .rbrack {
			break
		}
		items << p.parse_expr()!
	}
	p.expect(.rbrack, "']'")!
	return ProgramLiteral{
		kind:  .array_lit
		items: items
		pos:   start
	}
}

// bare_attr_value_literal builds the value node for a BARE (unquoted,
// non-paren) attribute value `name=VALUE`. Per lexicon §10 / [L25a] a bare
// attribute value auto-types via the scalar priority: `null` → the null
// scalar (not the string "null"); every other bareword stays a string
// (homoiconicity — `name=pizza` is the string "pizza", never a zero-arg
// call). int/float/bool/date/datetime arrive as their own literal tokens and
// never reach this ident path. (true/false are bool_lit tokens.)
fn bare_attr_value_literal(ident_tok ProgramToken) ProgramNode {
	if ident_tok.text == 'null' {
		return ProgramCall{
			name:          'null'
			args:          []
			explicit_call: false
			pos:           ident_tok.pos
		}
	}
	return ProgramLiteral{
		kind:    .string_lit
		str_val: ident_tok.text
		pos:     ident_tok.pos
	}
}

// fold_bare_attr_value reads a bare (unquoted) attribute value that begins
// at `first` (an ident the caller has already advanced). Per lexicon §10
// [L70] a BareValue admits `:` (`xmlns=urn:example`, `kind=svg:rect`), so a
// byte-adjacent `:local` QName tail (one or more segments) is FOLDED into a
// single string value rather than being re-read as a separate `:atom` body
// item — the latter was the cxparse Class-D D1 split. The leading `null`
// keyword still yields the null scalar (homoiconic bare-value rule), since a
// lone `null` has no colon tail to fold.
fn (mut p ProgramParser) fold_bare_attr_value(first ProgramToken) ProgramNode {
	mut text := first.text
	mut end_off := first.pos.offset + first.text.len
	// Byte-adjacency (next offset == running end) proves there was no
	// whitespace between tokens, i.e. they are one BareValue run.
	for p.peek_kind() == .colon && p.peek().pos.offset == end_off
		&& p.peek_kind_at(1) == .ident
		&& p.peek_at(1).pos.offset == p.peek().pos.offset + 1 {
		p.advance() // ':'
		local := p.advance()
		text = '${text}:${local.text}'
		end_off = local.pos.offset + local.text.len
	}
	if text == first.text {
		return bare_attr_value_literal(first)
	}
	return ProgramLiteral{
		kind:    .string_lit
		str_val: text
		pos:     first.pos
	}
}

// parse_cx_element_from_inside parses `[name body…]` as a CX literal
// element. The cursor is just past the opening `[`; the leading
// token MUST be an ident (the element name). Element bodies admit
// the labeled-slot form `:label value` per ast.v ProgramLiteral.slots —
// labeled slots and positional body items may interleave; the AST
// stores them in separate `slots` and `items` lists, preserving
// source order within each list.
fn (mut p ProgramParser) parse_cx_element_from_inside(start Position) !ProgramLiteral {
	if !is_element_head_token(p.peek_kind()) {
		return ParseError{
			message: "expected element name, got '${p.peek().text}'"
			pos:     p.peek().pos
		}
	}
	name_tok := p.advance()
	// Fold a module-qualified call head `[prefix/fn …]` (spec §12.1.1)
	// into a single name when `/fn` is byte-adjacent (no space) — the
	// element-call counterpart of the `prefix/fn(args)` form.
	mut head_name := p.fold_qualified_name(name_tok)
	// Namespace-qualified head `prefix:local` ([L11]/[7a]) — fold a byte-
	// adjacent `:local` into the head (not an atom child).
	head_name = p.fold_qualified_colon_name(name_tok, head_name)
	// Glued head TypeAnnotation `::T` / `::T[]` / `::[]` (lexicon §7 [L50],
	// §9 [L25d]). Must be byte-adjacent to the head (no space before `::`).
	mut head_dt := ''
	if p.peek_kind() == .double_colon
	   && p.peek().pos.offset == name_tok.pos.offset + name_tok.text.len {
		head_dt = p.read_head_type_annotation()!
	}
	// `:table` block — a DATA-only construct with its own header grammar
	// (`[col::T col::T …]`) that the program-expression grammar has no
	// production for (the second `col::T` errors as `::` in expression
	// position). When this element IS a TableBlock — either the head is
	// `table` glued to its header `[` (`[table[…] …]`) or the body opens with
	// the `[table[` clause-child (`[users [table[…]] …]`) — re-parse the
	// element's full source span with the proven data reader and carry the
	// result as a `node_lit` (the same DATA↔PROGRAM seam used for `[#…#]` /
	// `&…;` / `[!…]`). Eval returns the parsed Element (with its TableData)
	// verbatim, so a pure-data table evaluates to itself.
	if p.source.len > 0 && p.at_table_block_body(head_name, name_tok) {
		return p.reparse_table_element_as_node(start)!
	}
	mut items := []ProgramNode{}
	mut slots := []ProgramSlot{}
	mut attrs := []ProgramAttr{}
	for p.peek_kind() != .rbrack && p.peek_kind() != .eof {
		if p.peek_kind() == .colon && p.peek_kind_at(1) == .ident {
			// A `:NAME` token in element-literal body position is ALWAYS an
			// atom literal — a positional body item (`[cast $p :int]`,
			// `[= :ok "ok"]`, `[err :code "x"]` → atoms `:code` + string).
			// The retired `:label value` element-literal slot surface (e.g.
			// `[err :code "x"]` read as a `code`-labeled slot) was RETIRED in
			// the surface cutover (D014): element construction uses
			// attributes (`code="x"`) and positional body only — no colon
			// slots. No dual-accept; the slot reshape is gone.
			atom := p.parse_atom_literal()!
			items << ProgramNode(atom)
			continue
		}
		// Element-construction attribute: `name=value`. The value is
		// any atom (literal, binding, paren expr). Detected via the
		// ident-then-eq pair; positional body items that happen to
		// start with an ident (e.g. `[code "hello"]`) don't satisfy
		// the lookahead. Spec dual of ProgramPatternAttr (§5.2 rule 6).
		//
		// Homoiconicity rule: a bare identifier in attribute-value
		// position (`name=pizza` with no following `(`) parses as a
		// string scalar, matching the CX data-parser convention.
		// An explicit `name=pizza()` is still a zero-arg call.
		if p.peek_kind() == .ident && p.peek_kind_at(1) == .eq {
			attr_name := p.advance()
			p.advance() // '='
			value := if p.peek_kind() == .ident && p.peek_kind_at(1) != .lparen {
				ident_tok := p.advance()
				p.fold_bare_attr_value(ident_tok)
			} else {
				p.parse_atom()!
			}
			attrs << ProgramAttr{
				name:  attr_name.text
				value: value
			}
			continue
		}
		items << p.parse_expr()!
	}
	p.expect(.rbrack, "']' (closing element)")!
	return ProgramLiteral{
		kind:      .cx_element
		name:      head_name
		items:     items
		slots:     slots
		attrs:     attrs
		data_type: head_dt
		pos:       start
	}
}

// at_table_block_body reports whether the cursor (positioned just past an
// element head + optional glued `::T`) is at a `:table` block — mirroring the
// data parser's `peek_table_block_open` (reserved name `table`, then a `[`
// byte-adjacent to it). Two shapes:
//   • standalone — the head itself is `table` glued to its header `[`
//     (`[table[id::int …] …]`); the header `[` is byte-adjacent to the head.
//   • named — the body's first child is the `[table[` clause-child opener
//     (`[users [table[…]] …]`).
// A regular element named `table` with a SPACE before its `[` (`[table foo]`,
// `[doc [table …]]`) is NOT a table block — the byte-adjacency check excludes
// it, matching the data reader.
fn (p &ProgramParser) at_table_block_body(head_name string, head_tok ProgramToken) bool {
	// standalone: `[table[…]…]`
	if head_name == 'table' && p.peek_kind() == .lbrack
	   && p.peek().pos.offset == head_tok.pos.offset + head_tok.text.len {
		return true
	}
	// named: body opens with `[table[…]]`
	if p.peek_kind() == .lbrack && p.peek_kind_at(1) == .ident
	   && p.pos + 2 < p.tokens.len && p.tokens[p.pos + 1].text == 'table'
	   && p.peek_kind_at(2) == .lbrack
	   && p.tokens[p.pos + 2].pos.offset == p.tokens[p.pos + 1].pos.offset + 'table'.len {
		return true
	}
	return false
}

// reparse_table_element_as_node delegates the whole element opened at `start`
// (cursor is INSIDE it, one `[` already consumed) to the proven data reader.
// Scans tokens for the matching `]`, slices the verbatim source span, and
// builds a `node_lit` carrying the parsed Element (with its TableData). The
// cursor is left just past the closing `]`.
fn (mut p ProgramParser) reparse_table_element_as_node(start Position) !ProgramLiteral {
	mut depth := 1
	mut i := p.pos
	for i < p.tokens.len {
		k := p.tokens[i].kind
		if k == .lbrack {
			depth++
		} else if k == .rbrack {
			depth--
			if depth == 0 { break }
		} else if k == .eof {
			break
		}
		i++
	}
	if i >= p.tokens.len || p.tokens[i].kind != .rbrack {
		return ParseError{
			message: 'unterminated :table block'
			pos:     start
		}
	}
	end_off := p.tokens[i].pos.offset + 1
	if start.offset < 0 || end_off > p.source.len || end_off <= start.offset {
		return ParseError{
			message: 'invalid :table block span'
			pos:     start
		}
	}
	span := p.source[start.offset..end_off]
	node := parse_data_node(span) or {
		return ParseError{
			message: 'invalid :table block: ${err.msg()}'
			pos:     start
		}
	}
	p.pos = i + 1
	return ProgramLiteral{
		kind:    .node_lit
		node:    node
		str_val: span
		pos:     start
	}
}

// read_head_type_annotation reads a glued head TypeAnnotation after the
// element head (lexicon §7 [L50]): `::T`, `::T[]`, or `::[]`. The cursor is
// ON the `::` (double_colon) token. Returns the type string ('u16', 'int[]',
// '[]', …). The base TypeName is validated against the CXDM type set; the
// trailing `[]` must be byte-adjacent (glued) to the base / the `::`. An
// unknown type tag is CXER0107; a malformed annotation is CXER0100.
fn (mut p ProgramParser) read_head_type_annotation() !string {
	dc := p.advance() // '::'
	after_dc := dc.pos.offset + 2
	// `::[]` — inferred-type array.
	if p.peek_kind() == .lbrack {
		lb := p.peek()
		if lb.pos.offset == after_dc && p.peek_kind_at(1) == .rbrack
		   && p.peek_at(1).pos.offset == lb.pos.offset + 1 {
			p.advance() // '['
			p.advance() // ']'
			return '[]'
		}
		return ParseError{
			code:    'cx-err:CXER0100'
			message: 'malformed type annotation after `::`'
			pos:     dc.pos
		}
	}
	if p.peek_kind() != .ident {
		return ParseError{
			code:    'cx-err:CXER0100'
			message: 'expected a type name after `::`'
			pos:     dc.pos
		}
	}
	tname := p.peek()
	if tname.pos.offset != after_dc {
		return ParseError{
			code:    'cx-err:CXER0100'
			message: 'type annotation `::T` must be glued to the head (no space)'
			pos:     dc.pos
		}
	}
	if !is_valid_type_tag(tname.text) {
		return ParseError{
			code:    'cx-err:CXER0107'
			message: "unknown type tag `::${tname.text}` — not a CXDM type (E_UNKNOWN_TYPE_TAG)"
			pos:     tname.pos
		}
	}
	p.advance() // type name ident
	// optional glued `[]` → array type
	if p.peek_kind() == .lbrack {
		lb := p.peek()
		if lb.pos.offset == tname.pos.offset + tname.text.len
		   && p.peek_kind_at(1) == .rbrack
		   && p.peek_at(1).pos.offset == lb.pos.offset + 1 {
			p.advance() // '['
			p.advance() // ']'
			return '${tname.text}[]'
		}
	}
	return tname.text
}

// parse_computed_element_body parses the body of a `[?element NAME-EXPR
// attr=v … body …]` directive (grammar [127s]; spec/code.md §6.4.2). The
// cursor is positioned just AFTER the `element` directive-name token; the
// caller (parse_directive) handles the closing `]`. The result is a
// `cx_element` ProgramLiteral with `name_expr` set — the same AST the
// retired `(:atom EXPR)` form produced — so eval_cx_element's computed-name
// path and the bijective codec handle it uniformly. The body grammar is
// identical to the static `[NAME …]` element body (attrs interleaved with
// positional items; no `:label` slots, retired D014).
fn (mut p ProgramParser) parse_computed_element_body(start Position) !ProgramNode {
	if p.peek_kind() == .rbrack {
		return ParseError{
			code:    'cx-err:CXER0100'
			message: '[?element] requires a NAME-EXPR'
			pos:     p.peek().pos
		}
	}
	name_expr := p.parse_atom()!
	mut items := []ProgramNode{}
	mut attrs := []ProgramAttr{}
	for p.peek_kind() != .rbrack && p.peek_kind() != .eof {
		if p.peek_kind() == .colon && p.peek_kind_at(1) == .ident {
			atom := p.parse_atom_literal()!
			items << ProgramNode(atom)
			continue
		}
		if p.peek_kind() == .ident && p.peek_kind_at(1) == .eq {
			attr_name := p.advance()
			p.advance() // '='
			value := if p.peek_kind() == .ident && p.peek_kind_at(1) != .lparen {
				ident_tok := p.advance()
				p.fold_bare_attr_value(ident_tok)
			} else {
				p.parse_atom()!
			}
			attrs << ProgramAttr{
				name:  attr_name.text
				value: value
			}
			continue
		}
		items << p.parse_expr()!
	}
	p.expect(.rbrack, "']' (closing [?element])")!
	return ProgramNode(ProgramLiteral{
		kind:      .cx_element
		name:      ''
		name_expr: ProgramNode(name_expr)
		items:     items
		attrs:     attrs
		pos:       start
	})
}

// parse_computed_name_subform parses the `[?name NAME-EXPR]` sub-form
// (grammar [127v]; spec/code.md §6.4.2) used in the name slot of [set-attr]
// / [rename]. Cursor is AT the `name` directive_name token (the lexer
// consumed the `[?` opener). Returns a ProgramDirective{name:'name'} whose
// single positional slot is NAME-EXPR; eval_modify resolves it via the shared
// name-coercion rule.
fn (mut p ProgramParser) parse_computed_name_subform() !ProgramNode {
	name_tok := p.expect(.directive_name, "'name' directive")!
	if name_tok.text != 'name' {
		return ParseError{
			code:    'cx-err:CXER0100'
			message: "expected [?name …] in modify name slot, got '[?${name_tok.text}]'"
			pos:     name_tok.pos
		}
	}
	name_expr := p.parse_atom()!
	p.expect(.rbrack, "']' (closing [?name])")!
	return ProgramNode(ProgramDirective{
		name:  'name'
		slots: [ProgramSlot{ kind: .positional, value: name_expr }]
		pos:   name_tok.pos
	})
}

// parse_eval_tree_body parses `[?eval TREE [context MAP]? [opts MAP]?]`
// (grammar [127z]; spec/code.md §6.4.4). Cursor is just AFTER the `eval`
// directive-name token. Encoding: positional slot 0 = TREE; optional labeled
// slots 'context' / 'opts' carry the clause-child MAP exprs. The `[context …]`
// and `[opts …]` clauses are bracketed (not generic exprs), distinguished by a
// `[` head whose first token is the clause keyword.
fn (mut p ProgramParser) parse_eval_tree_body(start Position) !ProgramNode {
	if p.peek_kind() == .rbrack {
		return ParseError{
			code:    'cx-err:CXER0100'
			message: '[?eval] requires a TREE expression'
			pos:     p.peek().pos
		}
	}
	mut slots := []ProgramSlot{}
	// Positional TREE.
	slots << ProgramSlot{
		kind:  .positional
		value: p.parse_atom()!
	}
	// Optional [context MAP] / [opts MAP] clause-children, any order.
	for p.peek_kind() == .lbrack && p.peek_kind_at(1) == .ident
	    && (p.peek_at(1).text == 'context' || p.peek_at(1).text == 'opts') {
		p.advance() // '['
		kw := p.advance() // 'context' | 'opts'
		val := p.parse_atom()!
		p.expect(.rbrack, "']' (closing [${kw.text} …] clause)")!
		slots << ProgramSlot{
			kind:  .labeled
			label: kw.text
			value: val
		}
	}
	p.expect(.rbrack, "']' (closing [?eval])")!
	return ProgramNode(ProgramDirective{
		name:  'eval'
		slots: slots
		pos:   start
	})
}

// ── Patterns ────────────────────────────────────────────────────────────────

fn (mut p ProgramParser) parse_pattern_body_from_inside(start Position) !ProgramPattern {
	head := p.parse_pattern_head()!
	mut attrs := []ProgramPatternAttr{}
	mut direct := false
	mut body := []ProgramNode{}
	for p.peek_kind() != .rbrack && p.peek_kind() != .eof {
		if p.peek_kind() == .at || p.peek_kind() == .at_bang {
			attrs << p.parse_pattern_attr()!
			continue
		}
		// `direct=true` adjacency modifier ([126f]); the current surface
		// (replacing the retired `:direct` colon slot).
		if p.peek_kind() == .ident && p.peek().text == 'direct'
		   && p.peek_kind_at(1) == .eq {
			p.advance() // 'direct'
			p.advance() // '='
			val_tok := p.advance() // 'true' / 'false'
			direct = val_tok.text == 'true'
			continue
		}
		// Plain attribute equality test `name=VALUE` (spec/code.md §5.2
		// rule 9): the pattern-position dual of the `name=value`
		// element-construction surface — a structural-equality test on the
		// candidate's `name` attribute. Detected by the ident-then-`=`
		// pair; positional body items that start with a bare ident don't
		// satisfy the lookahead.
		if p.peek_kind() == .ident && p.peek_kind_at(1) == .eq {
			attrs << p.parse_plain_pattern_attr()!
			continue
		}
		body << p.parse_pattern_body_item()!
	}
	p.expect(.rbrack, "']' (closing pattern)")!
	return ProgramPattern{
		head:   head
		attrs:  attrs
		direct: direct
		body:   body
		pos:    start
	}
}

fn (p ProgramParser) peek_at(offset int) ProgramToken {
	idx := p.pos + offset
	if idx >= p.tokens.len {
		return p.tokens[p.tokens.len - 1]
	}
	return p.tokens[idx]
}

fn (mut p ProgramParser) parse_pattern_head() !ProgramPatternHead {
	match p.peek_kind() {
		.double_star {
			p.advance()
			bind := p.parse_optional_bind()!
			return ProgramPatternHead{ kind: .deep, value: '**', bind: bind }
		}
		.star {
			p.advance()
			bind := p.parse_optional_bind()!
			return ProgramPatternHead{ kind: .wildcard, value: '*', bind: bind }
		}
		.colon {
			p.advance()
			name := p.expect(.ident, 'type-guard name after :')!
			bind := p.parse_optional_bind()!
			return ProgramPatternHead{ kind: .type_guard, value: name.text, bind: bind }
		}
		.ident {
			n := p.advance()
			// Named heads do NOT eagerly consume a trailing `$bind` —
			// the lexer can't distinguish `[NAME$x]` (head-bind glued
			// per spec §5.2 line 372 "where supported by the parser")
			// from `[NAME $x]` (body-position bind, §5.2 rule 5).
			// Consuming greedily mis-parses `[user $a $b]` as
			// head-bind=$a + body=[$b] — short-circuiting before $b
			// matches. The matcher's body-position auto-unwrap at
			// matcher.v `bind_name` short-circuit covers the
			// single-body-bind case (`[name $n]`); multi-body-bind
			// patterns reach `match_body` and bind positionally.
			return ProgramPatternHead{ kind: .named, value: n.text, bind: '' }
		}
		.dollar {
			// Bare `$bind` head: per §5, when the head slot is purely a
			// binding (no name), it matches any element and binds it.
			// Treat as `*$bind`.
			bind_tok := p.parse_binding_with_path()!
			if bind_tok.path.len > 0 {
				return ParseError{
					message: 'pattern head binding may not include path steps'
					pos:     bind_tok.pos
				}
			}
			return ProgramPatternHead{ kind: .wildcard, value: '*', bind: bind_tok.name }
		}
		else {
			return ParseError{
				message: "expected pattern head (Name, *, **, :Type, or \$bind), got '${p.peek().text}'"
				pos:     p.peek().pos
			}
		}
	}
}

fn (mut p ProgramParser) parse_optional_bind() !string {
	if p.peek_kind() != .dollar {
		return ''
	}
	p.advance()
	t := p.expect(.ident, 'binding name after $')!
	return t.text
}

fn (mut p ProgramParser) parse_pattern_attr() !ProgramPatternAttr {
	if p.peek_kind() == .at_bang {
		p.advance()
		n := p.expect(.ident, 'attribute name after @!')!
		return ProgramPatternAttr{
			kind: .absence
			name: n.text
			op:   ''
		}
	}
	p.expect(.at, "'@'")!
	n := p.expect(.ident, 'attribute name after @')!
	// Attribute value-kind test `@name::T` (spec/code.md §5.2 rule 14,
	// attribute position): tests the attribute value's CXDM kind.
	if p.peek_kind() == .double_colon {
		p.advance()
		tt := p.parse_type_kind_name()!
		return ProgramPatternAttr{
			kind:      .type_test
			name:      n.text
			op:        ''
			type_name: tt
		}
	}
	match p.peek_kind() {
		.eq, .neq, .lt, .le, .gt, .ge {
			op_tok := p.advance()
			// Bareword RHS in `@attr=VALUE` (pattern attrs + path
			// predicates) is a STRING literal, matching how attribute
			// values are written bare in CX data (`[foo v=keep]` is the
			// string "keep"). So `[@v=keep]` matches the string-valued
			// attribute, not a binding/call named `keep`. Typed and
			// referenced RHS forms ($binding, number, bool, quoted string,
			// paren-group) keep their normal expression parse.
			val := if p.peek_kind() == .ident {
				tok := p.advance()
				ProgramNode(ProgramLiteral{
					kind:    .string_lit
					str_val: tok.text
					pos:     tok.pos
				})
			} else {
				p.parse_atom()!
			}
			kind := if op_tok.kind == .eq {
				ProgramPatternAttrKind.equality
			} else {
				ProgramPatternAttrKind.comparison
			}
			return ProgramPatternAttr{
				kind:  kind
				name:  n.text
				op:    op_tok.text
				value: val
			}
		}
		else {
			return ProgramPatternAttr{
				kind: .existence
				name: n.text
				op:   ''
			}
		}
	}
}

// parse_plain_pattern_attr parses a plain (non-`@`) attribute-equality
// test `name=VALUE` in pattern body position (spec/code.md §5.2 rule 9).
// The cursor is on the attribute-name ident. A bareword RHS is a string
// literal (matching the CX data convention `[foo v=keep]` ⇒ "keep");
// typed / quoted / referenced RHS forms keep their normal expression
// parse. Emits a `.equality` `ProgramPatternAttr` — identical to the
// `@name=VALUE` form (rule 6 equality), so the matcher path is shared.
fn (mut p ProgramParser) parse_plain_pattern_attr() !ProgramPatternAttr {
	n := p.expect(.ident, 'plain attribute name')!
	p.expect(.eq, "'=' after plain attribute name")!
	val := if p.peek_kind() == .ident {
		tok := p.advance()
		ProgramNode(ProgramLiteral{
			kind:    .string_lit
			str_val: tok.text
			pos:     tok.pos
		})
	} else {
		p.parse_atom()!
	}
	return ProgramPatternAttr{
		kind:  .equality
		name:  n.text
		op:    '='
		value: val
	}
}

fn (mut p ProgramParser) parse_pattern_body_item() !ProgramNode {
	match p.peek_kind() {
		.lbrack {
			return p.parse_bracket(.pattern)!
		}
		.dollar {
			return p.parse_binding_with_path()!
		}
		.star {
			t := p.advance()
			return ProgramWildcard{ deep: false, pos: t.pos }
		}
		.double_star {
			t := p.advance()
			return ProgramWildcard{ deep: true, pos: t.pos }
		}
		else {
			return ParseError{
				message: "expected pattern body item ([..], \$bind, *, **), got '${p.peek().text}'"
				pos:     p.peek().pos
			}
		}
	}
}

// parse_match_pattern parses one MatchPattern (grammar [140a]) — the
// pattern surface of a `[?match]` `[case …]` arm. It dispatches across the
// full §5.2 pattern vocabulary: element patterns (`[head …]`), scalar
// literals (rule 8), map / sequence / array patterns (rules 11–13), typed
// binds (`$n::T`) and anonymous type-tests (`_::T`, rule 14), the `_`
// wildcard, and bare `$bind`. Collection patterns recurse through this same
// entry point for their item / value patterns.
fn (mut p ProgramParser) parse_match_pattern() !ProgramNode {
	match p.peek_kind() {
		.lbrack {
			// Array pattern `[1, $x, 3]` vs element pattern `[head …]`
			// (grammar [140e]): the array form is a comma-separated,
			// head-less item list. A top-level comma OR a non-element-head
			// first token signals the array form.
			if p.array_pattern_ahead() {
				return p.parse_array_pattern()!
			}
			return p.parse_bracket(.pattern)!
		}
		.lparen {
			return p.parse_seq_pattern()!
		}
		.lbrace {
			return p.parse_map_pattern()!
		}
		.dollar {
			return p.parse_binding_pattern()!
		}
		.ident {
			// `_::T` anonymous value-kind test (rule 14). Bare `_` and all
			// other barewords (atoms / string scalars) fall through to
			// parse_atom, preserving the existing wildcard / scalar parse.
			if p.peek().text == '_' && p.peek_kind_at(1) == .double_colon {
				return p.parse_underscore_typetest()!
			}
			return p.parse_atom()!
		}
		else {
			return p.parse_atom()!
		}
	}
}

// array_pattern_ahead decides whether a `[`-led pattern is an array
// pattern (grammar [140e]) or an element pattern. The cursor is on the
// opening `[`.
fn (p ProgramParser) array_pattern_ahead() bool {
	if p.top_level_comma_in_bracket() {
		return true
	}
	first := p.peek_kind_at(1)
	// Element-head starters: Name / * / ** / :Type / $bind, plus the
	// operator-head element forms (`[+ …]`).
	if first == .ident || first == .star || first == .double_star
	   || first == .colon || first == .dollar {
		return false
	}
	if is_element_head_token(first) {
		return false
	}
	// Anything else as the first inner token (number / string / bool /
	// nested `(` `{` `[`) — a head-less item, so an array pattern.
	return true
}

// top_level_comma_in_bracket scans from the opening `[` (current token)
// for a comma directly inside this bracket (depth 1).
fn (p ProgramParser) top_level_comma_in_bracket() bool {
	mut depth := 0
	mut i := p.pos
	for i < p.tokens.len {
		k := p.tokens[i].kind
		match k {
			.lbrack, .ldirective, .directive_name, .lparen, .lbrace { depth++ }
			.rbrack, .rparen, .rbrace {
				depth--
				if depth == 0 {
					return false
				}
			}
			.comma {
				if depth == 1 {
					return true
				}
			}
			.eof { return false }
			else {}
		}
		i++
	}
	return false
}

// parse_seq_pattern parses a sequence pattern `(p1, p2, …, *$rest)`
// (grammar [140d]). Closed (exact arity) unless a trailing `*$rest` is
// present.
fn (mut p ProgramParser) parse_seq_pattern() !ProgramNode {
	start := p.peek().pos
	p.expect(.lparen, "'(' (opening sequence pattern)")!
	mut items := []ProgramNode{}
	for p.peek_kind() != .rparen && p.peek_kind() != .eof {
		if items.len > 0 {
			p.expect(.comma, "',' (sequence pattern separator)")!
		}
		if p.peek_kind() == .star {
			items << p.parse_rest_bind()!
		} else {
			items << p.parse_match_pattern()!
		}
	}
	p.expect(.rparen, "')' (closing sequence pattern)")!
	return ProgramLiteral{
		kind:  .sequence_lit
		items: items
		pos:   start
	}
}

// parse_array_pattern parses an array pattern `[p1, p2, …, *$rest]`
// (grammar [140e]). Closed unless a trailing `*$rest` is present.
fn (mut p ProgramParser) parse_array_pattern() !ProgramNode {
	start := p.peek().pos
	p.expect(.lbrack, "'[' (opening array pattern)")!
	mut items := []ProgramNode{}
	for p.peek_kind() != .rbrack && p.peek_kind() != .eof {
		if items.len > 0 {
			p.expect(.comma, "',' (array pattern separator)")!
		}
		if p.peek_kind() == .star {
			items << p.parse_rest_bind()!
		} else {
			items << p.parse_match_pattern()!
		}
	}
	p.expect(.rbrack, "']' (closing array pattern)")!
	return ProgramLiteral{
		kind:  .array_lit
		items: items
		pos:   start
	}
}

// parse_map_pattern parses a map pattern `{k: p, …, *$rest}`
// (grammar [140c]). Open (subset) match by key; an optional trailing
// `*$rest` binds the unmatched pairs as a Map. The rest entry is stored
// with an empty-string key and a `ProgramBinding{is_rest: true}` value.
fn (mut p ProgramParser) parse_map_pattern() !ProgramNode {
	start := p.peek().pos
	p.expect(.lbrace, "'{' (opening map pattern)")!
	mut keys := []string{}
	mut items := []ProgramNode{}
	for p.peek_kind() != .rbrace && p.peek_kind() != .eof {
		if keys.len > 0 {
			p.expect(.comma, "',' (map pattern separator)")!
		}
		if p.peek_kind() == .star {
			keys << ''
			items << p.parse_rest_bind()!
			continue
		}
		key_tok := p.peek()
		key := match key_tok.kind {
			.string_lit { p.advance().text }
			.ident      { p.advance().text }
			.number_lit { p.advance().text }
			else {
				return ParseError{
					message: "expected map pattern key (string/ident/number), got '${key_tok.text}'"
					pos:     key_tok.pos
				}
			}
		}
		p.expect(.colon, "':' after map pattern key")!
		val := p.parse_match_pattern()!
		keys << key
		items << val
	}
	p.expect(.rbrace, "'}' (closing map pattern)")!
	return ProgramLiteral{
		kind:  .map_lit
		keys:  keys
		items: items
		pos:   start
	}
}

// parse_rest_bind parses a rest-capture `*$name` (grammar [140f]) into a
// `ProgramBinding{is_rest: true}`. The cursor is on the `*`.
fn (mut p ProgramParser) parse_rest_bind() !ProgramNode {
	start := p.peek().pos
	p.expect(.star, "'*' (rest-bind)")!
	bind := p.parse_binding_with_path()!
	if bind.path.len > 0 {
		return ParseError{
			message: 'rest-bind `*\$name` may not include path steps'
			pos:     bind.pos
		}
	}
	return ProgramBinding{
		name:    bind.name
		is_rest: true
		pos:     start
	}
}

// parse_binding_pattern parses a `$name` bind pattern, optionally a typed
// bind `$name::T` (grammar [140g]). Path steps are illegal in pattern
// position.
fn (mut p ProgramParser) parse_binding_pattern() !ProgramNode {
	start := p.peek().pos
	bind := p.parse_binding_with_path()!
	if bind.path.len > 0 {
		return ParseError{
			message: 'pattern binding `\$name` may not include path steps'
			pos:     bind.pos
		}
	}
	mut tt := ''
	if p.peek_kind() == .double_colon {
		p.advance()
		tt = p.parse_type_kind_name()!
	}
	return ProgramBinding{
		name:      bind.name
		type_test: tt
		pos:       start
	}
}

// parse_underscore_typetest parses an anonymous value-kind test `_::T`
// (grammar [140g]) into `ProgramBinding{name: "_", type_test: T}`. The
// cursor is on the `_` ident; the following `::` is confirmed by the
// caller.
fn (mut p ProgramParser) parse_underscore_typetest() !ProgramNode {
	start := p.peek().pos
	p.advance() // '_'
	p.advance() // '::'
	tt := p.parse_type_kind_name()!
	return ProgramBinding{
		name:      '_'
		type_test: tt
		pos:       start
	}
}

// parse_type_kind_name parses the KindName after a `::` value-kind test
// (grammar [26] / [140g]). A single identifier — the CXDM kind name.
fn (mut p ProgramParser) parse_type_kind_name() !string {
	t := p.expect(.ident, 'value-kind name after ::')!
	return t.text
}

// ── Directives ──────────────────────────────────────────────────────────────

fn (mut p ProgramParser) parse_directive() !ProgramNode {
	// The lexer consumed `[?` and emitted a `directive_name` token
	// carrying the name verbatim; the parser does not see a separate
	// `ldirective` opener. The closing `]` is a normal rbrack.
	name_tok := p.expect(.directive_name, 'directive name')!
	// Registry membership check per spec/code.md §4.1. The 'test-*'
	// prefix is reserved for fixture-only helpers per conformance/
	// code.txt §Format (the "Fixture-only test helpers" subsection);
	// the parser accepts them so conformance fixtures parse cleanly.
	// The evaluator then dispatches them via the conformance-mode
	// helper table; outside that mode the evaluator rejects them.
	if !is_directive_name(name_tok.text) && !name_tok.text.starts_with('test-') {
		return ParseError{
			message:           "unknown directive '[?${name_tok.text}]' — not in §4.1 registry"
			pos:               name_tok.pos
			unknown_directive: true
		}
	}
	// Special-form: for-comprehension has its own clause grammar.
	// three outer-container heads:
	//   `[?for]`       → outer .sequence (default)
	//   `[?for-array]` → outer .array (preserves Array outer)
	//   `[?for-map]`   → outer .map (requires `:yield-map`)
	if name_tok.text == 'for' {
		return p.parse_for_comp_body(name_tok.pos, ProgramForCompOuterForm.sequence)!
	}
	if name_tok.text == 'for-array' {
		return p.parse_for_comp_body(name_tok.pos, ProgramForCompOuterForm.array)!
	}
	if name_tok.text == 'for-map' {
		return p.parse_for_comp_body(name_tok.pos, ProgramForCompOuterForm.map)!
	}
	// Special-form: [?let $name = expr :in body] uses the
	// canonical surface from spec/code.md §8.5 with structural `=`.
	if name_tok.text == 'let' {
		return p.parse_let_body(name_tok.pos)!
	}
	// Special-form: [?match] accepts ONLY the clause-child form
	// `[?match X [case P R] … [else R]]` (and the 2-arg single-arm
	// `[?match X [pat] [yield E]]`). The legacy `:case/:when/:else/:where/
	// :yield` colon-slot SOURCE surface is RETIRED (D014) — no dual-accept:
	// a `:NAME` token parses as an atom positional and fails the arm
	// validators. Clause children are reshaped into the labeled-slot
	// ENCODING `eval_match_*` consumes (that internal encoding stays — only
	// user-written colon-slot source is gone). The case clause's first item
	// is a PATTERN (pattern-mode parse).
	if name_tok.text == 'match' {
		return p.parse_match_body(name_tok.pos)!
	}
	// Special-form: [?modify Expr PathExpr Action+]
	// (productions [141]-[148e]). The second positional slot MUST be a
	// PathExpr (CXPath focus); action clauses have heterogeneous arities
	// (`[delete]` carries nothing; `[set-attr …]` carries two operands)
	// so they're handled by parse_modify_action rather than the generic
	// labeled-slot path. See spec/code.md §8.10.
	if name_tok.text == 'modify' {
		return p.parse_modify_body(name_tok.pos)!
	}
	// Special-form: [?with-open (expr) $binding ... body+]
	// (production [127f]). Opener `(expr) $binding` pairs precede a
	// non-empty body; openers and body are distinguished by lookahead
	// (an expr immediately followed by `$` is an opener).
	if name_tok.text == 'with-open' {
		return p.parse_with_open_body(name_tok.pos)!
	}
	// Special-form: [?with-scope {fields} :do body+]
	// (production [127g]). A leading fields expr, the `:do` keyword, then
	// a non-empty body.
	if name_tok.text == 'with-scope' {
		return p.parse_with_scope_body(name_tok.pos)!
	}
	// Special-form: [?with-caps [deny CAP (resource)?]+ BODY] (production
	// [167], spec/core/security.md §3). One-or-more `[deny …]` clauses
	// (bracketed, NOT normal exprs) precede a single body expr; encoded as
	// labeled 'deny' / 'deny-resource' slots + the positional body.
	if name_tok.text == 'with-caps' {
		return p.parse_with_caps_body(name_tok.pos)!
	}
	// Special-form: [?str "…"] compile-time string interpolation
	// (production [127r] StrDirective). The single child is a string
	// literal whose content the program parser scans for `{…}` holes —
	// the literal text is opaque to the [10a] string lexer, so the
	// brace-hole scan lives here (same opaque-body pattern as
	// Interpolation [58]). See parse_str_body / spec/code.md §8.12.
	if name_tok.text == 'str' {
		return p.parse_str_body(name_tok.pos)!
	}
	// Special-form: [?element NAME-EXPR attr=v … body …] (grammar [127s]).
	// Produces a cx_element literal with name_expr — the body grammar is the
	// element body (attrs interleaved with items), not generic directive slots.
	if name_tok.text == 'element' {
		return p.parse_computed_element_body(name_tok.pos)!
	}
	// Special-form: [?eval TREE [context MAP]? [opts MAP]?] (grammar [127z]).
	// The optional [context …] / [opts …] clauses are bracketed clause-children
	// (like [?modify] actions), encoded as labeled 'context' / 'opts' slots so
	// eval reads them uniformly; the leading TREE is a positional slot.
	if name_tok.text == 'eval' {
		return p.parse_eval_tree_body(name_tok.pos)!
	}
	// Special-form: [?fn (params) body] / [?fn $x body]. The paren parameter
	// list `($a $b …)` is space-separated `$`-bindings (NOT a comma-sequence),
	// so it cannot go through the generic positional-slot path
	// (parse_paren_or_sequence expects commas). See parse_fn_body.
	if name_tok.text == 'fn' {
		return p.parse_fn_body(name_tok.pos)!
	}
	// Module directives [?lib] / [?const] / [?def] (spec/code.md §12):
	// capture the raw directive source span and defer structural parsing
	// to parse_lib / parse_const / parse_def at eval time. Per
	// the program-level [?def] uses the single §12.2 surface
	// (`[?def name (params) body]`) — the same parser the module loader
	// uses — so there is one [?def] surface, not two. ([?fn] lambdas keep
	// their own structural parse.)
	if name_tok.text == 'lib' || name_tok.text == 'const' || name_tok.text == 'def' {
		return p.parse_module_directive(name_tok)!
	}
	mut slots := []ProgramSlot{}
	for p.peek_kind() != .rbrack && p.peek_kind() != .eof {
		slots << p.parse_directive_slot(name_tok.text)!
	}
	p.expect(.rbrack, "']' (closing directive)")!
	return ProgramDirective{
		name:  name_tok.text
		slots: slots
		pos:   name_tok.pos
	}
}

// parse_directive_slot reads one slot. surface: every directive
// modifier is either a scalar attribute (`name=value`) or a clause-child
// element (`[name …]`); the legacy `:label V` surface was removed.
// `find` and `match` directives switch the first positional
// slot into pattern mode per spec/code.md §5.
fn (mut p ProgramParser) parse_directive_slot(directive_name string) !ProgramSlot {
	// scalar modifier as attribute: `name=value` in directive
	// position is equivalent to the legacy `:name value` labeled slot
	// (e.g. `[?retry max=3 …]` ≡ `[?retry :max 3 …]`). Mapped to a labeled
	// slot so directive eval reads it unchanged. A bare ident value
	// (not followed by `(`) is a string scalar, matching element-attr
	// homoiconicity; otherwise the value is any atom.
	if p.peek_kind() == .ident && p.peek_kind_at(1) == .eq {
		name_tok := p.advance()
		p.advance() // '='
		value := if p.peek_kind() == .ident && p.peek_kind_at(1) != .lparen {
			ident_tok := p.advance()
			ProgramNode(ProgramLiteral{
				kind:    .string_lit
				str_val: ident_tok.text
				pos:     ident_tok.pos
			})
		} else {
			p.parse_atom()!
		}
		return ProgramSlot{
			kind:  .labeled
			label: name_tok.text
			value: value
		}
	}
	// Positional. For find/match, the first positional slot uses
	// pattern mode if and only if the body starts with `[`.
	value := if (directive_name == 'find' || directive_name == 'match')
	         && p.peek_kind() == .lbrack {
		p.parse_bracket(.pattern)!
	} else {
		p.parse_atom()!
	}
	return ProgramSlot{
		kind:  .positional
		label: ''
		value: value
	}
}

// parse_fn_body parses `[?fn (params) body]` and `[?fn $x body]`. The
// parameter list `($a $b …)` is a paren-wrapped, space-separated list of
// `$`-bindings (NOT a comma-sequence), so it needs dedicated parsing; the
// single-arg `$x` form and the body expression go through the generic
// positional-slot loop. The slot shape produced is exactly what
// extract_params_and_body()/extract_param_names() already consume: first
// positional slot = parameter list (sequence_lit of $bindings), then the
// positional body slot.
fn (mut p ProgramParser) parse_fn_body(pos Position) !ProgramNode {
	mut slots := []ProgramSlot{}
	if p.peek_kind() == .lparen {
		slots << ProgramSlot{
			kind:  .positional
			label: ''
			value: p.parse_fn_param_list()!
		}
	}
	for p.peek_kind() != .rbrack && p.peek_kind() != .eof {
		slots << p.parse_directive_slot('fn')!
	}
	p.expect(.rbrack, "']' (closing [?fn])")!
	return ProgramDirective{
		name:  'fn'
		slots: slots
		pos:   pos
	}
}

// parse_fn_param_list parses `($a $b …)` into a sequence_lit of ProgramBinding
// items. Empty `()` is the zero-parameter list. Each item is a `$`-binding.
fn (mut p ProgramParser) parse_fn_param_list() !ProgramNode {
	start := p.peek().pos
	p.expect(.lparen, "'(' (parameter list)")!
	mut items := []ProgramNode{}
	for p.peek_kind() != .rparen && p.peek_kind() != .eof {
		items << p.parse_atom()!
	}
	p.expect(.rparen, "')' (parameter list)")!
	return ProgramLiteral{
		kind:  .sequence_lit
		items: items
		pos:   start
	}
}

// ── Let-binding ─────────────────────────────────────────────────────────────

// parse_let_body handles `[?let $name = expr :in body]` per spec/code.md
// §8.5. The structural `=` and `:in` keyword aren't directive slots in
// the general sense — they're part of the let surface. Stored as a
// ProgramDirective with three labeled slots ('bind', 'value', 'body') so
// the AST stays uniform under the ProgramDirective shape per ast.md.
fn (mut p ProgramParser) parse_let_body(start Position) !ProgramDirective {
	// form: `[?let [= $x v] … BODY]` — positional `[= …]` binding
	// clauses followed by a trailing body expression. Detected by a `[`
	// head (the legacy form leads with `$name`). Stored as positional
	// slots; eval_let extracts the bindings and the body.
	if p.peek_kind() == .lbrack {
		mut slots := []ProgramSlot{}
		for p.peek_kind() != .rbrack && p.peek_kind() != .eof {
			slots << ProgramSlot{
				kind:  .positional
				value: p.parse_expr()!
			}
		}
		p.expect(.rbrack, "']' (closing [?let])")!
		return ProgramDirective{
			name:  'let'
			slots: slots
			pos:   start
		}
	}
	// The legacy `[?let $name = expr :in body]` colon surface was retired;
	// only the clause-child form above is accepted.
	return ParseError{
		message: "[?let] requires a `[= \$name value]` binding clause then a body (spec/code.md §8.5); the `\$name = expr :in body` colon form is no longer accepted"
		pos:     p.peek().pos
	}
}

// parse_match_body parses `[?match]` in the clause-child form ONLY:
//
//   [?match X [case P R] [case P [where G] R] … [when PRED R] [else R]]
//   [?match X [pat] [yield E]]                  ; 2-arg single-arm
//
// The legacy `:case/:where/:when/:else/:yield` colon-slot SOURCE surface is
// RETIRED (D014): a `:NAME` token here parses as an atom positional and is
// rejected by the arm validators — no dual-accept. Clause children are
// reshaped into the internal labeled-slot ENCODING `eval_match_single_arm`
// / `eval_match_multi_arm` consume (that encoding stays — only user-written
// colon-slot source is gone). The first item of a `[case …]` clause is a
// PATTERN (parsed in pattern mode).
fn (mut p ProgramParser) parse_match_body(start Position) !ProgramDirective {
	mut slots := []ProgramSlot{}
	mut positional_count := 0
	for p.peek_kind() != .rbrack && p.peek_kind() != .eof {
		// clause child `[case …]` / `[when …]` / `[else …]`
		// `[yield …]` — disambiguated from a scrutinee / single-arm pattern
		// bracket by the head bareword.
		if p.peek_kind() == .lbrack && p.peek_kind_at(1) == .ident {
			head := p.peek_at(1).text
			if head in ['case', 'when', 'else', 'yield'] {
				p.parse_match_clause(mut slots)!
				continue
			}
		}
		// Positional: the FIRST positional is the scrutinee — an
		// EXPRESSION (V1a, spec §8.2: `[?match [/ 10 0] …]` evaluates the
		// inline scrutinee; an err outcome flows to the arms as a matchable
		// value). A SECOND positional is the single-arm form's pattern
		// (pattern mode, the legacy match positional path).
		value := if p.peek_kind() == .lbrack {
			if positional_count == 0 {
				p.parse_bracket(.expression)!
			} else {
				p.parse_bracket(.pattern)!
			}
		} else {
			p.parse_atom()!
		}
		positional_count++
		slots << ProgramSlot{
			kind:  .positional
			label: ''
			value: value
		}
	}
	p.expect(.rbrack, "']' (closing [?match])")!
	return ProgramDirective{
		name:  'match'
		slots: slots
		pos:   start
	}
}

// parse_match_clause reshapes one `[?match]` clause child into the
// legacy labeled-slot pair(s) and appends them to `slots`. Cursor is at the
// opening `[` on entry; consumes through the matching `]`.
fn (mut p ProgramParser) parse_match_clause(mut slots []ProgramSlot) ! {
	p.expect(.lbrack, "'[' (opening [?match] clause)")!
	head_tok := p.expect(.ident, '[?match] clause head')!
	match head_tok.text {
		'case' {
			// `[case P R]` or `[case P [where G] R]`. P is a MatchPattern
			// (grammar [140a]) — element / scalar / map / sequence / array /
			// typed-bind / wildcard / bind.
			pat := p.parse_match_pattern()!
			slots << ProgramSlot{ kind: .labeled, label: 'case', value: pat }
			if p.peek_kind() == .lbrack && p.peek_kind_at(1) == .ident
			   && p.peek_at(1).text == 'where' {
				p.advance() // '['
				p.advance() // 'where'
				guard := p.parse_expr()!
				// #18: a bare infix comparison (`[where $x/@a=v]`) is a common
				// mis-reach — CX predicates are PREFIX. Point at the prefix form
				// instead of the low-context "expected ']'".
				if p.peek_kind() in [ProgramTokenKind.eq, .neq, .lt, .le, .gt, .ge] {
					op := p.peek().text
					return ParseError{
						message: '[where] takes a PREFIX predicate — write `[where [${op} LHS RHS]]` (e.g. `[where [= \$x/@attr value]]`), not infix `LHS ${op} RHS`'
						pos:     p.peek().pos
					}
				}
				p.expect(.rbrack, "']' (closing [where] clause)")!
				slots << ProgramSlot{ kind: .labeled, label: 'where', value: guard }
			}
			result := p.parse_expr()!
			slots << ProgramSlot{ kind: .labeled, label: 'yield', value: result }
		}
		'when' {
			// `[when PRED R]`.
			pred := p.parse_expr()!
			result := p.parse_expr()!
			slots << ProgramSlot{ kind: .labeled, label: 'when', value: pred }
			slots << ProgramSlot{ kind: .labeled, label: 'yield', value: result }
		}
		'else' {
			// `[else R]` — `:else` carries a placeholder value (ignored by eval).
			result := p.parse_expr()!
			slots << ProgramSlot{
				kind:  .labeled
				label: 'else'
				value: ProgramLiteral{ kind: .bool_lit, bool_val: true, pos: head_tok.pos }
			}
			slots << ProgramSlot{ kind: .labeled, label: 'yield', value: result }
		}
		'yield' {
			// `[yield E]` — single-arm 2-arg result clause.
			result := p.parse_expr()!
			slots << ProgramSlot{ kind: .labeled, label: 'yield', value: result }
		}
		else {
			return ParseError{
				message: "unexpected [?match] clause '[${head_tok.text} …]'"
				pos:     head_tok.pos
			}
		}
	}
	p.expect(.rbrack, "']' (closing [?match] clause)")!
}

// parse_with_open_body parses `[?with-open (expr) $binding ... body+]`
// per production [127f]. Encoding: leading paired labeled
// slots ('open-expr' = opener expr, 'open-bind' = binding name literal)
// in source order, then the body as positional slots. Openers and body
// are distinguished by lookahead — an expr immediately followed by `$`
// is an opener; the first expr NOT followed by `$` begins the body, and
// every remaining expr is body. At least one opener and one body expr
// are required; otherwise CXER0100.
fn (mut p ProgramParser) parse_with_open_body(start Position) !ProgramDirective {
	mut openers := []ProgramSlot{}
	mut body := []ProgramSlot{}
	for p.peek_kind() != .rbrack && p.peek_kind() != .eof {
		// form: `[?with-open [= $f OPENER] … BODY]` — each opener
		// is a `[= $bind OPENER]` binding clause; the rest is positional
		// body. Encoded as the same open-expr/open-bind labeled pairs the
		// legacy `(OPENER) $bind` form produces, so eval is unchanged.
		if body.len == 0 && p.peek_kind() == .lbrack && p.peek_kind_at(1) == .eq {
			p.advance() // '['
			p.advance() // '='
			bind := p.parse_binding_with_path()!
			if bind.path.len > 0 {
				return ParseError{
					message: '[?with-open] [= …] binding may not have path steps'
					pos:     bind.pos
				}
			}
			opener := p.parse_expr()!
			p.expect(.rbrack, "']' (closing [= …] opener)")!
			openers << ProgramSlot{ kind: .labeled, label: 'open-expr', value: opener }
			openers << ProgramSlot{
				kind:  .labeled
				label: 'open-bind'
				value: ProgramLiteral{ kind: .string_lit, str_val: bind.name, pos: bind.pos }
			}
			continue
		}
		e := p.parse_expr()!
		if body.len == 0 && p.peek_kind() == .dollar {
			bind := p.parse_binding_with_path()!
			if bind.path.len > 0 {
				return ParseError{
					message: '[?with-open] binding site may not have path steps'
					pos:     bind.pos
				}
			}
			openers << ProgramSlot{ kind: .labeled, label: 'open-expr', value: e }
			openers << ProgramSlot{
				kind:  .labeled
				label: 'open-bind'
				value: ProgramLiteral{ kind: .string_lit, str_val: bind.name, pos: bind.pos }
			}
		} else {
			body << ProgramSlot{ kind: .positional, value: e }
		}
	}
	p.expect(.rbrack, "']' (closing [?with-open])")!
	if openers.len == 0 {
		return ParseError{
			message: '[?with-open] requires at least one `(expr) \$binding` opener'
			pos:     start
		}
	}
	if body.len == 0 {
		return ParseError{
			message: '[?with-open] requires a non-empty body'
			pos:     start
		}
	}
	mut slots := openers.clone()
	slots << body
	return ProgramDirective{
		name:  'with-open'
		slots: slots
		pos:   start
	}
}

// parse_module_directive captures the verbatim source span of a
// `[?lib …]` / `[?const …]` program directive and wraps it in a
// ProgramDirective with a single labeled `raw-source` slot. The
// structural parse (resolver kind / :as / :only for lib; name / value /
// scope for const) is deferred to eval time via parse_lib /
// parse_const — reusing the module-loader's parsers verbatim rather
// than re-implementing them in the program grammar. The directive_name
// token's `pos.offset` points at the opening `[` (lexer
// read_directive_name), so the span runs from there to the matching
// `]`. Bracket depth starts at 1 for the directive's own opener.
fn (mut p ProgramParser) parse_module_directive(name_tok ProgramToken) !ProgramNode {
	if p.source.len == 0 {
		return ParseError{
			message: '[?${name_tok.text}] requires source text (token-only parse unsupported)'
			pos:     name_tok.pos
		}
	}
	start_off := name_tok.pos.offset
	mut depth := 1
	mut end_off := -1
	for p.peek_kind() != .eof {
		t := p.advance()
		match t.kind {
			.lbrack { depth++ }
			.directive_name { depth++ }
			.rbrack {
				depth--
				if depth == 0 {
					end_off = t.pos.offset + 1
					break
				}
			}
			else {}
		}
	}
	if end_off < 0 {
		return ParseError{
			message: "[?${name_tok.text}] unterminated (missing ']')"
			pos:     name_tok.pos
		}
	}
	raw := p.source[start_off..end_off]
	return ProgramDirective{
		name:  name_tok.text
		slots: [
			ProgramSlot{
				kind:  .labeled
				label: 'raw-source'
				value: ProgramLiteral{ kind: .string_lit, str_val: raw, pos: name_tok.pos }
			},
		]
		pos: name_tok.pos
	}
}

// parse_with_scope_body parses `[?with-scope {fields} :do body+]` per
// production [127g]. Encoding: a labeled 'scope-fields' slot
// carrying the fields expression, then the body as positional slots. A
// non-empty body is required; otherwise CXER0100. The map-ness of the
// fields expr is a runtime (CXER0001) check, not a parse check.
fn (mut p ProgramParser) parse_with_scope_body(start Position) !ProgramDirective {
	fields := p.parse_expr()!
	// `:do` is optional under the body is the positional tail
	// after the fields expression (`[?with-scope {…} BODY]`). The legacy
	// `:do BODY` separator is still accepted.
	if p.peek_kind() == .colon && p.peek_kind_at(1) == .ident
	   && p.peek_at(1).text == 'do' {
		p.advance() // ':'
		p.advance() // 'do'
	}
	mut body := []ProgramSlot{}
	for p.peek_kind() != .rbrack && p.peek_kind() != .eof {
		body << ProgramSlot{ kind: .positional, value: p.parse_expr()! }
	}
	p.expect(.rbrack, "']' (closing [?with-scope])")!
	if body.len == 0 {
		return ParseError{
			message: '[?with-scope] requires a non-empty body after :do'
			pos:     start
		}
	}
	mut slots := [ProgramSlot{ kind: .labeled, label: 'scope-fields', value: fields }]
	slots << body
	return ProgramDirective{
		name:  'with-scope'
		slots: slots
		pos:   start
	}
}

// with_caps_capabilities is the closed capability vocabulary (grammar
// [167b], spec/core/security.md). A `[deny …]` clause naming anything
// else is a malformed shape → CXER0100.
const with_caps_capabilities = ['read', 'write', 'net', 'env', 'clock', 'random',
	'subprocess', 'eval', 'secret-reveal']

// parse_with_caps_body parses `[?with-caps [deny CAP (resource)?]+ BODY]`
// (production [167], spec/core/security.md §3). Each `[deny …]` clause is a
// bracketed shape (not a normal expr), so it cannot go through the generic
// positional-slot path; we hand-parse the clauses by token, then parse one
// body expr. Encoding: a labeled 'deny' slot per clause carrying the
// capability name as a string literal (+ an optional 'deny-resource' slot),
// then the body as a single positional slot. ≥1 deny clause and exactly one
// body are required; any other shape is CXER0100.
fn (mut p ProgramParser) parse_with_caps_body(start Position) !ProgramDirective {
	mut slots := []ProgramSlot{}
	mut deny_count := 0
	for p.peek_kind() == .lbrack && p.peek_kind_at(1) == .ident
		&& p.peek_at(1).text == 'deny' {
		p.advance() // '['
		p.advance() // 'deny'
		if p.peek_kind() != .ident {
			return ParseError{
				message: '[?with-caps] [deny …] requires a capability name'
				pos:     start
			}
		}
		cap_name := p.advance().text
		if cap_name !in with_caps_capabilities {
			return ParseError{
				message: '[?with-caps] unknown capability "${cap_name}" (grammar [167b])'
				pos:     start
			}
		}
		slots << ProgramSlot{
			kind:  .labeled
			label: 'deny'
			value: ProgramLiteral{
				kind:    .string_lit
				str_val: cap_name
				pos:     start
			}
		}
		// Optional resource scope (a single ident or string before ']').
		if p.peek_kind() != .rbrack {
			res_tok := p.advance()
			slots << ProgramSlot{
				kind:  .labeled
				label: 'deny-resource'
				value: ProgramLiteral{
					kind:    .string_lit
					str_val: res_tok.text
					pos:     start
				}
			}
		}
		p.expect(.rbrack, "']' (closing [deny …])")!
		deny_count++
	}
	if deny_count == 0 {
		return ParseError{
			message: '[?with-caps] requires at least one [deny CAP] clause (grammar [167])'
			pos:     start
		}
	}
	body := p.parse_expr()!
	slots << ProgramSlot{
		kind:  .positional
		value: body
	}
	p.expect(.rbrack, "']' (closing [?with-caps])")!
	return ProgramDirective{
		name:  'with-caps'
		slots: slots
		pos:   start
	}
}

// ── Str (compile-time string interpolation) ──────────────────────
//
// `[?str "…"]` (production [127r] StrDirective; spec/code.md §8.12).
// The single child MUST be a string literal. Its content is scanned here
// for `{…}` interpolation holes — the literal text is opaque to the
// [10a] string lexer, so the brace-hole scan belongs in the program
// parser (same opaque-body pattern as Interpolation [58]). The result is
// a ProgramDirective named 'str' whose slots are the alternating literal /
// hole stream consumed by eval_str:
//   - `[lit  V]`  — a verbatim text segment (ProgramLiteral string_lit)
//   - `[hole E]`  — a binding-path expression (ProgramBinding / ProgramPathExpr)
//
// `{{` / `}}` denote literal `{` / `}`. An unbalanced brace, an empty
// hole `{}`, or a hole body that is not a binding-path (e.g. a program
// call or `1 to 3`) raises CXER0100 (PARSE_ERROR) at parse time.
fn (mut p ProgramParser) parse_str_body(start Position) !ProgramDirective {
	if p.peek_kind() != .string_lit {
		return ParseError{
			message: '[?str] requires a single string-literal argument'
			pos:     p.peek().pos
		}
	}
	tmpl_tok := p.advance()
	p.expect(.rbrack, "']' (closing [?str])")!
	slots := scan_str_template(tmpl_tok.text, tmpl_tok.pos)!
	return ProgramDirective{
		name:  'str'
		slots: slots
		pos:   start
	}
}

// scan_str_template scans a [?str] template's literal content for `{…}`
// interpolation holes and emits the alternating literal / hole slot
// stream consumed by eval_str. See parse_str_body / spec/code.md §8.12.
fn scan_str_template(tmpl string, pos Position) ![]ProgramSlot {
	mut slots := []ProgramSlot{}
	mut lit := []u8{}
	bytes := tmpl.bytes()
	mut i := 0
	for i < bytes.len {
		c := bytes[i]
		if c == `{` {
			// `{{` → literal `{`.
			if i + 1 < bytes.len && bytes[i + 1] == `{` {
				lit << `{`
				i += 2
				continue
			}
			// Interpolation hole: scan to the matching `}`.
			mut j := i + 1
			for j < bytes.len && bytes[j] != `}` {
				j++
			}
			if j >= bytes.len {
				return ParseError{
					message: '[?str] unbalanced `{` — interpolation hole has no closing `}`'
					pos:     pos
				}
			}
			hole_src := tmpl[i + 1..j]
			// Flush the literal segment accumulated before the hole.
			if lit.len > 0 {
				slots << ProgramSlot{
					kind:  .labeled
					label: 'lit'
					value: ProgramLiteral{ kind: .string_lit, str_val: lit.bytestr(), pos: pos }
				}
				lit = []u8{}
			}
			slots << ProgramSlot{
				kind:  .labeled
				label: 'hole'
				value: parse_str_hole(hole_src, pos)!
			}
			i = j + 1
			continue
		}
		if c == `}` {
			// `}}` → literal `}`.
			if i + 1 < bytes.len && bytes[i + 1] == `}` {
				lit << `}`
				i += 2
				continue
			}
			// A bare `}` with no opening `{` is unbalanced.
			return ParseError{
				message: '[?str] unbalanced `}` — a literal `}` must be written `}}`'
				pos:     pos
			}
		}
		lit << c
		i++
	}
	if lit.len > 0 {
		slots << ProgramSlot{
			kind:  .labeled
			label: 'lit'
			value: ProgramLiteral{ kind: .string_lit, str_val: lit.bytestr(), pos: pos }
		}
	}
	return slots
}

// parse_str_hole parses one `{…}` interpolation-hole body. Per
// spec/code.md §8.12 the body is a CXPath binding-path expression ONLY —
// a `$binding`, a path navigation (`$x/child`), or a filtered query
// (`$x//y[@pred]`). A program call, a non-path expression (e.g. `1 to
// 3`), or an empty hole raises CXER0100 (PARSE_ERROR).
fn parse_str_hole(src string, pos Position) !ProgramNode {
	if src.trim_space() == '' {
		return ParseError{
			message: '[?str] empty interpolation hole `{}` — a binding-path is required'
			pos:     pos
		}
	}
	// Re-parse the hole body through the full program parser. A parse
	// failure (or any non-binding-path shape) is a malformed hole.
	prog := parse_program(src) or {
		return ParseError{
			message: '[?str] malformed interpolation hole `{${src}}`: not a binding-path expression'
			pos:     pos
		}
	}
	body := prog.body
	if body is ProgramBinding {
		return body
	}
	if body is ProgramPathExpr {
		return body
	}
	return ParseError{
		message: '[?str] interpolation hole `{${src}}` is not a binding-path expression — only `\$binding`, `\$x/child`, and `\$x//y[@pred]` holes are admitted (calls and other expressions are not; bind first, then interpolate)'
		pos:     pos
	}
}

// ── Modify ───────────────────────────────────────────────────────
//
// `[?modify doc focus action+]` — parse_modify_body handles the full
// shape because actions have heterogeneous arities: `:delete` has no
// operand, `:rename`/`:delete-attr` take a bare Name, `:set-attr`
// takes a Name AND an Expr. Encoded as a ProgramDirective named
// 'modify' with slot conventions documented at each action below.

// modify_action_names is the closed set of action labels per
// spec/grammar.ebnf [142]. Order is documentation-only; membership
// is what parse_modify_body checks.
const modify_action_names = [
	'set', 'delete', 'using', 'rename',
	'set-attr', 'delete-attr',
	'append', 'prepend',
	'insert-before', 'insert-after', 'replace',
]

pub fn is_modify_action_name(s string) bool {
	for n in modify_action_names {
		if n == s {
			return true
		}
	}
	return false
}

// parse_modify_body parses `[?modify Expr PathExpr Action+]` per
// grammar [141]–[148e]. The two positional slots are doc + focus;
// the focus MUST be a PathExpr (raises CXER0100 otherwise per
// §8.10 'Errors'). Actions are parsed by parse_modify_action
// and appended as labeled slots in source order. Returns the
// ProgramDirective shape so eval_directive can dispatch via
// eval_modify.
fn (mut p ProgramParser) parse_modify_body(start Position) !ProgramDirective {
	// Two surface forms accepted:
	//   [?modify DOC FOCUS Action+]   — explicit doc binding
	//   [?modify FOCUS Action+]       — pipe-stage form; doc supplied
	//                                    by the upstream pipe stage at
	//                                    evaluation time. The pipe shim
	//                                    in eval_modify reads the
	//                                    threaded value from the
	//                                    `__pipe_input__` env binding.
	// Disambiguate by peeking: a leading `//` is the pipe-stage form;
	// anything else starts with the doc expression.
	mut doc_expr := ?ProgramNode(none)
	if p.peek_kind() != .double_slash {
		// Suppress `//` binding-path step consumption while parsing
		// the doc expression — the immediate trailing `//` belongs
		// to the focus PathExpr per the modify grammar [?modify DOC
		// PathExpr Actions]. Without this guard, `[?modify $doc
		// //user [delete]]` would parse as ProgramBinding($doc//user)
		// + `[delete]` (and choke on the missing focus PathExpr).
		p.no_descendant_in_binding_path = true
		doc_expr = p.parse_atom() or {
			p.no_descendant_in_binding_path = false
			return err
		}
		p.no_descendant_in_binding_path = false
		if p.peek_kind() != .double_slash {
			return ParseError{
				code:    'cx-err:CXER0100'
				message: "[?modify] focus slot must be a CXPath '//…'; got '${p.peek().text}'"
				pos:     p.peek().pos
			}
		}
	}
	p.in_modify_focus = true
	focus := p.parse_path_expr() or {
		p.in_modify_focus = false
		return err
	}
	p.in_modify_focus = false
	mut slots := []ProgramSlot{}
	if d := doc_expr {
		slots << ProgramSlot{ kind: .positional, label: '', value: d }
	}
	slots << ProgramSlot{ kind: .positional, label: '', value: ProgramNode(focus) }
	// Actions — at least one required per [141].
	mut action_count := 0
	for p.peek_kind() != .rbrack && p.peek_kind() != .eof {
		slots << p.parse_modify_action()!
		action_count++
	}
	if action_count == 0 {
		return ParseError{
			code:    'cx-err:CXER0100'
			message: '[?modify] requires at least one action clause ([set …], [delete], [using …], [rename …], [set-attr …], [delete-attr …], [append …], [prepend …], [insert-before …], [insert-after …], [replace …])'
			pos:     start
		}
	}
	// `[set-attr …]` / `[delete-attr …]` are element-focused.
	// If the focus PathExpr ends in an attribute step (either explicit
	// `attribute::name` or the `@name` shorthand parsed to .attribute
	// axis), those two actions raise a STATIC error per the spec
	// "ProgramParser raises a static error" wording. Catching at parse means
	// the diagnostic fires even when the [?modify] sits inside an
	// untaken branch (e.g. an [?if] false-branch), per the spec intent.
	if focus.steps.len > 0
	   && focus.steps[focus.steps.len - 1].axis == ProgramPathAxis.attribute {
		for slot in slots {
			if slot.kind == .labeled
			   && (slot.label == 'set-attr' || slot.label == 'delete-attr') {
				return ParseError{
					code:    'cx-err:CXER0100'
					message: "[?modify] action '[${slot.label} …]' requires an element-step focus path; got a path ending in attribute step"
					pos:     start
				}
			}
		}
	}
	p.expect(.rbrack, "']' (closing [?modify])")!
	return ProgramDirective{
		name:  'modify'
		slots: slots
		pos:   start
	}
}

// parse_modify_action parses one action clause per grammar [142]–[148e].
// Cursor enters at '['; the head ident selects the action.
// Encoding (uniform shape — every action becomes one labeled slot):
//   [set EXPR]             → slot 'set'           value=EXPR
//   [delete]               → slot 'delete'        value=bool true (placeholder)
//   [using EXPR]           → slot 'using'         value=EXPR
//   [rename NAME]          → slot 'rename'        value=string_lit NAME
//   [set-attr NAME EXPR]   → slot 'set-attr'      value=sequence_lit (NAME, EXPR)
//   [delete-attr NAME]     → slot 'delete-attr'   value=string_lit NAME
//   [append EXPR]/…        → corresponding label, value=EXPR
//   [replace EXPR]         → slot 'replace'       value=EXPR
fn (mut p ProgramParser) parse_modify_action() !ProgramSlot {
	// Action clauses are disambiguated by a `[` head whose first token
	// is a known action name (the FOCUS path is already parsed before
	// the action loop, so an EXPR operand bracket cannot reach this
	// action-position parse).
	if p.peek_kind() == .lbrack && p.peek_kind_at(1) == .ident
	   && is_modify_action_name(p.peek_at(1).text) {
		p.advance() // '['
		label_tok := p.advance() // action name ident
		slot := p.parse_modify_action_operands(label_tok)!
		p.expect(.rbrack, "']' (closing [?modify] action clause)")!
		return slot
	}
	return ParseError{
		code:    'cx-err:CXER0100'
		message: "expected a [?modify] action clause ([set …], [delete], [using …], [rename …], [set-attr …], [delete-attr …], [append …], [prepend …], [insert-before …], [insert-after …], [replace …]), got '${p.peek().text}'"
		pos:     p.peek().pos
	}
}

// parse_modify_action_operands reads the operands for a single [?modify]
// action clause and produces its labeled slot. The cursor is positioned
// just AFTER the action-name token (`[NAME …`); the caller handles the
// closing `]`.
fn (mut p ProgramParser) parse_modify_action_operands(label_tok ProgramToken) !ProgramSlot {
	label := label_tok.text
	match label {
		'delete' {
			// No operand. Synthesize a placeholder value so the slot
			// has a uniform shape (mirrors how [else …] is encoded for
			// multi-arm match).
			return ProgramSlot{
				kind:  .labeled
				label: 'delete'
				value: ProgramNode(ProgramLiteral{
					kind:     .bool_lit
					bool_val: true
					pos:      label_tok.pos
				})
			}
		}
		'rename' {
			// :rename NAME — bare element name, OR the computed-name sub-form
			// [?name NAME-EXPR] (grammar [146]/[127v]; spec/code.md §6.4.2).
			if p.peek_kind() == .directive_name && p.peek().text == 'name' {
				return ProgramSlot{
					kind:  .labeled
					label: 'rename'
					value: p.parse_computed_name_subform()!
				}
			}
			if p.peek_kind() != .ident {
				return ParseError{
					code:    'cx-err:CXER0100'
					message: "expected element name in [rename …], got '${p.peek().text}'"
					pos:     p.peek().pos
				}
			}
			n := p.advance()
			return ProgramSlot{
				kind:  .labeled
				label: 'rename'
				value: ProgramNode(ProgramLiteral{
					kind:    .string_lit
					str_val: n.text
					pos:     n.pos
				})
			}
		}
		'delete-attr' {
			// :delete-attr NAME — attribute name.
			if p.peek_kind() != .ident {
				return ParseError{
					code:    'cx-err:CXER0100'
					message: "expected attribute name in [delete-attr …], got '${p.peek().text}'"
					pos:     p.peek().pos
				}
			}
			n := p.advance()
			return ProgramSlot{
				kind:  .labeled
				label: 'delete-attr'
				value: ProgramNode(ProgramLiteral{
					kind:    .string_lit
					str_val: n.text
					pos:     n.pos
				})
			}
		}
		'set-attr' {
			// :set-attr NAME EXPR — encoded as a sequence_lit of the
			// name (string literal) followed by the value expression. NAME may
			// be a bare ident OR the computed-name sub-form [?name NAME-EXPR]
			// (grammar [147]/[127v]; spec/code.md §6.4.2).
			name_node := if p.peek_kind() == .directive_name && p.peek().text == 'name' {
				p.parse_computed_name_subform()!
			} else if p.peek_kind() == .ident {
				n := p.advance()
				ProgramNode(ProgramLiteral{
					kind:    .string_lit
					str_val: n.text
					pos:     n.pos
				})
			} else {
				return ParseError{
					code:    'cx-err:CXER0100'
					message: "expected attribute name in [set-attr …], got '${p.peek().text}'"
					pos:     p.peek().pos
				}
			}
			value_expr := p.parse_atom()!
			seq := ProgramLiteral{
				kind: .sequence_lit
				items: [
					name_node,
					value_expr,
				]
				pos: label_tok.pos
			}
			return ProgramSlot{
				kind:  .labeled
				label: 'set-attr'
				value: ProgramNode(seq)
			}
		}
		else {
			// Single-Expr actions: [set …], [using …], [append …],
			// [prepend …], [insert-before …], [insert-after …],
			// [replace …].
			value_expr := p.parse_atom()!
			return ProgramSlot{
				kind:  .labeled
				label: label
				value: value_expr
			}
		}
	}
}

// ── For-comprehension ───────────────────────────────────────────────────────

// for_clause_keywords is the closed set of head keywords that mark an
// head-dispatch for-comprehension clause child (`[in …]`,
// `[where …]`, `[yield …]`, …). A `[`-headed token whose head is one of
// these is a clause; any other bareword head (e.g. `[user $u]`) is a
// pattern-generator. The `[= …]` binding clause is detected separately
// (an `=` head, not a keyword).
const for_clause_keywords = [
	'in', 'where', 'yield', 'yield-array', 'yield-map', 'order-by',
	'group-by', 'limit', 'take', 'drop', 'takewhile', 'dropwhile',
	'on-error', 'par', 'stream', 'ordered',
]

fn is_for_clause_keyword(s string) bool {
	for k in for_clause_keywords {
		if k == s {
			return true
		}
	}
	return false
}


fn (mut p ProgramParser) parse_for_comp_body(start Position, outer_form ProgramForCompOuterForm) !ProgramForComp {
	mut clauses := []ProgramForClause{}
	mut yield_expr := ?ProgramNode(none)
	mut yield_value_expr := ?ProgramNode(none)
	mut yield_form := ProgramForCompYieldForm.sequence
	for p.peek_kind() != .rbrack && p.peek_kind() != .eof {
		match p.peek_kind() {
			.lbrack {
				// head-dispatch for-clause children: `[in …]`,
				// `[where …]`, `[= $x v]`, `[yield …]`, `[order-by …]`,
				// etc. Disambiguated from pattern-generators (`[user $u]`)
				// by the bracket head: an `=` head is a `:let`-binding
				// clause; a clause-keyword head is the matching clause.
				if p.peek_kind_at(1) == .eq {
					p.advance() // '['
					p.advance() // '='
					b := p.parse_binding_with_path()!
					if b.path.len > 0 {
						return ParseError{
							message: '[= $x v] binding clause may not have path steps'
							pos:     b.pos
						}
					}
					e := p.parse_expr()!
					p.expect(.rbrack, "']' (closing [= …] clause)")!
					clauses << ProgramForClause{
						kind: .binding
						bind: b.name
						expr: e
					}
					continue
				}
				if p.peek_kind_at(1) == .ident && is_for_clause_keyword(p.peek_at(1).text) {
					p.advance() // '['
					kw := p.advance() // clause keyword
					match kw.text {
						'in' {
							// (4.a) — pattern-bind generator:
							// `[in PATTERN SRC]` where PATTERN is a
							// `[head $bind … ]` shape-match pattern that
							// destructures each item of SRC. Equivalent to
							// the legacy `[PATTERN] :in SRC` form below at
							// line ~3428, but moved INSIDE the `[in …]`
							// clause to unify with the plain
							// `[in $name SRC]` form. The pattern's bindings
							// (head bind, body binds, attr binds) flow into
							// the per-iteration env; non-matching items are
							// skipped (semantics: generator + filter in one).
							// Disambiguated from `[in $name SRC]` by the
							// leading `[` (vs `$`). A bare `[in [array-or-elem]]`
							// (where the bracket IS the source, no pattern)
							// would be a clash, but pattern-shape bodies
							// always include at least a `$bind` or attr-pred —
							// a bare `[item]` element-literal source is
							// already rare; if needed, users can write
							// `[in $_ [item]]` (anonymous bind, explicit source).
							// (4.a) pattern-bind generator vs
							// bare bracketed source: try parse_bracket(.pattern).
							// If pattern-parse succeeds AND there's a SRC
							// expression after, this is the new form
							// `[in PATTERN SRC]`. If pattern-parse succeeds
							// but the bracket was the WHOLE clause body
							// (next token is `]`), restore and re-parse the
							// bracket in expression mode as the bare source.
							// If pattern-parse FAILS, restore and parse the
							// bracket in expression mode.
							mut handled_pattern_form := false
							if p.peek_kind() == .lbrack {
								saved := p.save()
								pat_node := p.parse_bracket(.pattern) or {
									p.restore(saved)
									ProgramNode(ProgramLiteral{ kind: .bool_lit, bool_val: false, pos: p.peek().pos })
								}
								if pat_node is ProgramPattern && p.peek_kind() != .rbrack {
									src := p.parse_expr()!
									p.expect(.rbrack, "']' (closing [in PATTERN SRC])")!
									clauses << ProgramForClause{
										kind:   .generator
										bind:   '_'
										source: src
										expr:   pat_node
									}
									handled_pattern_form = true
								} else {
									// Restore for the bare-source path below.
									p.restore(saved)
								}
							}
							// `[in $bind SRC]` (explicit var) vs `[in SRC]`
							// (anonymous, implicit $_). A leading `$name`
							// followed by a further source token is the
							// explicit form; otherwise the binding (or any
							// other expression) IS the source. The bind is
							// parsed via parse_binding_with_path (NOT
							// parse_expr) so a following `(…)`/`[…]` isn't
							// greedily consumed as a call/slice on the var.
							if handled_pattern_form {
								// already pushed
							} else if p.peek_kind() == .dollar {
								bind := p.parse_binding_with_path()!
								// A byte-adjacent `[…]` of slice shape is a postfix ON the
								// binding (`$xs[2:5]`), so the binding is the source. Anything
								// else after a path-less `$bind` (a whitespace-separated
								// `[$range …]`/`[$call]` or any value token) is the EXPLICIT
								// loop-var form `[in $bind SRC]` — the F11 fix that admits a
								// prefix `[$range …]` (or any ProgramExpr) as the source.
								adjacent_slice := p.peek_kind() == .lbrack
								   && p.lbrack_adjacent_to_prev()
								   && is_slice_postfix_after_binding(p)
								explicit := bind.path.len == 0
								   && p.peek_kind() != .rbrack
								   && !adjacent_slice
								if explicit {
									src := p.parse_expr()!
									p.expect(.rbrack, "']' (closing [in …])")!
									clauses << ProgramForClause{
										kind:   .generator
										bind:   bind.name
										source: src
									}
								} else {
									// `[in $xs]` / `[in $xs[slice]]` — the binding is the
									// source, optionally with a byte-adjacent slice postfix.
									src := if adjacent_slice {
										p.parse_slice_postfix(bind)!
									} else {
										ProgramNode(bind)
									}
									p.expect(.rbrack, "']' (closing [in …])")!
									clauses << ProgramForClause{
										kind:   .generator
										bind:   '_'
										source: src
									}
								}
							} else {
								src := p.parse_expr()!
								p.expect(.rbrack, "']' (closing [in …])")!
								clauses << ProgramForClause{
									kind:   .generator
									bind:   '_'
									source: src
								}
							}
						}
						'where' {
							e := p.parse_expr()!
							// #18: a bare infix comparison (`[where $x/@a=v]`) is a common
							// mis-reach — CX predicates are PREFIX. Point at the prefix form.
							if p.peek_kind() in [ProgramTokenKind.eq, .neq, .lt, .le, .gt, .ge] {
								op := p.peek().text
								return ParseError{
									message: '[where] takes a PREFIX predicate — write `[where [${op} LHS RHS]]` (e.g. `[where [= \$x/@attr value]]`), not infix `LHS ${op} RHS`'
									pos:     p.peek().pos
								}
							}
							p.expect(.rbrack, "']' (closing [where …])")!
							clauses << ProgramForClause{ kind: .filter, expr: e }
						}
						'yield' {
							yield_expr = p.parse_expr()!
							yield_form = .sequence
							p.expect(.rbrack, "']' (closing [yield …])")!
						}
						'yield-array' {
							yield_expr = p.parse_expr()!
							yield_form = .array
							p.expect(.rbrack, "']' (closing [yield-array …])")!
						}
						'yield-map' {
							// `[yield-map K V]` — positional key then value.
							key_expr := p.parse_expr()!
							val_expr := p.parse_expr()!
							yield_expr = key_expr
							yield_value_expr = val_expr
							yield_form = .map
							p.expect(.rbrack, "']' (closing [yield-map …])")!
						}
						'order-by' {
							e := p.parse_expr()!
							mut dir := ''
							if p.peek_kind() == .ident
							   && (p.peek().text == 'asc' || p.peek().text == 'desc') {
								dir = p.advance().text
							}
							p.expect(.rbrack, "']' (closing [order-by …])")!
							clauses << ProgramForClause{
								kind:      .order_by
								expr:      e
								direction: dir
							}
						}
						'group-by' {
							e := p.parse_expr()!
							p.expect(.rbrack, "']' (closing [group-by …])")!
							clauses << ProgramForClause{ kind: .group_by, expr: e }
						}
						'limit' {
							e := p.parse_expr()!
							p.expect(.rbrack, "']' (closing [limit …])")!
							clauses << ProgramForClause{ kind: .limit, expr: e }
						}
						'take' {
							e := p.parse_expr()!
							p.expect(.rbrack, "']' (closing [take …])")!
							clauses << ProgramForClause{ kind: .take, expr: e }
						}
						'drop' {
							e := p.parse_expr()!
							p.expect(.rbrack, "']' (closing [drop …])")!
							clauses << ProgramForClause{ kind: .drop, expr: e }
						}
						'takewhile' {
							e := p.parse_expr()!
							p.expect(.rbrack, "']' (closing [takewhile …])")!
							clauses << ProgramForClause{ kind: .takewhile, expr: e }
						}
						'dropwhile' {
							e := p.parse_expr()!
							p.expect(.rbrack, "']' (closing [dropwhile …])")!
							clauses << ProgramForClause{ kind: .dropwhile, expr: e }
						}
						'on-error' {
							// RETIRED (SAP C3c, spec §9.3): per-iteration
							// recovery is a yield-body [?match]. Tombstone
							// error, no dual-accept.
							return ParseError{
								message: '[on-error] is retired (§9.3) — per-iteration recovery is a yield-body [?match]: [?for … [yield [?match F [case [err \$e] H] [else \$v]]]]'
								pos:     p.peek().pos
							}
						}
						'par' {
							p.expect(.rbrack, "']' (closing [par])")!
							clauses << ProgramForClause{ kind: .par }
						}
						'stream' {
							p.expect(.rbrack, "']' (closing [stream])")!
							clauses << ProgramForClause{ kind: .stream }
						}
						'ordered' {
							p.expect(.rbrack, "']' (closing [ordered])")!
							clauses << ProgramForClause{ kind: .ordered }
						}
						else {
							return ParseError{
								message: "unknown for-comprehension clause '[${kw.text} …]'"
								pos:     kw.pos
							}
						}
					}
					continue
				}
				// Pattern-generator shortcut (grammar [129b1]): a bare
				// `[pattern]` at a generator position is a document-wide
				// search — sugar for `[in $_ <doc>]` filtered by the pattern.
				// Bind = '_'. The destructuring `[in [PATTERN] SRC]` form is
				// handled inside the `[in …]` clause above; the retired
				// `[pattern] :in SRC` colon form is no longer accepted.
				pat := p.parse_bracket(.pattern)!
				clauses << ProgramForClause{
					kind:   .generator
					bind:   '_'
					source: pat
				}
			}
			else {
				return ParseError{
					message: "unexpected token '${p.peek().text}' in for-comprehension"
					pos:     p.peek().pos
				}
			}
		}
	}
	p.expect(.rbrack, "']' (closing [?for])")!
	yield_node := yield_expr or {
		return ParseError{
			message: "[?for] requires a [yield …] clause"
			pos:     start
		}
	}
	// outer-form / yield-form compatibility rules.
	//   * `:yield-map` REQUIRES `[?for-map]` outer.
	//   * `[?for-map]` REQUIRES `:yield-map` (other yield forms would
	//     have no key/value pair to emit).
	if yield_form == .map && outer_form != .map {
		return ParseError{
			message: '`[?for] [yield-map K V]` requires `[?for-map]` outer'
			pos:     start
		}
	}
	if outer_form == .map && yield_form != .map {
		return ParseError{
			message: '`[?for-map]` requires `[yield-map K V]` clause'
			pos:     start
		}
	}
	// Spec §7.4: `:stream` MUST NOT be combined with `:order-by` or
	// `:group-by`. Materialising clauses contradict lazy evaluation;
	// the spec mandates a parse-time `cx-err:CXER0100`.
	mut has_stream := false
	mut has_materialiser := false
	for c in clauses {
		match c.kind {
			.stream                { has_stream = true }
			.order_by, .group_by   { has_materialiser = true }
			else                   {}
		}
	}
	if has_stream && has_materialiser {
		return ParseError{
			message: "cx-err:CXER0100 — `:stream` MUST NOT be combined with `:order-by` or `:group-by` (spec/code.md §7.4)"
			pos:     start
		}
	}
	return ProgramForComp{
		clauses:     clauses
		yield:       yield_node
		yield_value: yield_value_expr
		yield_form:  yield_form
		outer_form:  outer_form
		pos:         start
	}
}

// ── Paren / sequence + map literals ─────────────────────────────────────────

fn (mut p ProgramParser) parse_paren_or_sequence() !ProgramLiteral {
	start := p.peek().pos
	p.expect(.lparen, "'('")!
	if p.peek_kind() == .rparen {
		p.advance()
		return ProgramLiteral{
			kind:  .sequence_lit
			items: []
			pos:   start
		}
	}
	mut items := []ProgramNode{}
	items << p.parse_expr()!
	for p.peek_kind() == .comma {
		p.advance()
		if p.peek_kind() == .rparen {
			break
		}
		items << p.parse_expr()!
	}
	p.expect(.rparen, "')'")!
	return ProgramLiteral{
		kind:  .sequence_lit
		items: items
		pos:   start
	}
}

// computed_entry_key_marker is the sentinel `keys[i]` value flagging that
// `items[i]` is a `[?entry KEY-EXPR VAL]` directive (computed map key,
// spec/code.md §6.4.2) rather than a statically-keyed value. eval_map resolves
// the directive's KEY-EXPR via the shared name-coercion rule.
pub const computed_entry_key_marker = '__cx_computed_entry__'

// parse_computed_entry_subform parses `[?entry KEY-EXPR VAL]` inside a `{…}`
// map literal. Cursor is AT the `entry` directive_name token (the lexer
// consumed the `[?` opener). Returns a ProgramDirective{name:'entry'} with two
// positional slots (KEY-EXPR, VAL).
fn (mut p ProgramParser) parse_computed_entry_subform() !ProgramNode {
	name_tok := p.expect(.directive_name, "'entry' directive")!
	key_expr := p.parse_atom()!
	val_expr := p.parse_atom()!
	p.expect(.rbrack, "']' (closing [?entry])")!
	return ProgramNode(ProgramDirective{
		name: 'entry'
		slots: [
			ProgramSlot{ kind: .positional, value: key_expr },
			ProgramSlot{ kind: .positional, value: val_expr },
		]
		pos: name_tok.pos
	})
}

fn (mut p ProgramParser) parse_map_literal() !ProgramLiteral {
	start := p.peek().pos
	p.expect(.lbrace, "'{'")!
	mut keys := []string{}
	mut items := []ProgramNode{}
	for p.peek_kind() != .rbrace && p.peek_kind() != .eof {
		// Computed-key map entry `[?entry KEY-EXPR VAL]` (grammar [127u];
		// spec/code.md §6.4.2). Stored as an item carrying the [?entry]
		// directive (two positional slots), with the sentinel key marker
		// `__cx_computed_entry__` so eval_map resolves it via name coercion.
		if p.peek_kind() == .directive_name && p.peek().text == 'entry' {
			ent := p.parse_computed_entry_subform()!
			keys << computed_entry_key_marker
			items << ent
			if p.peek_kind() == .comma {
				p.advance()
			}
			continue
		}
		key_tok := p.peek()
		key := match key_tok.kind {
			.string_lit { p.advance().text }
			.ident      { p.advance().text }
			.number_lit { p.advance().text }
			else {
				return ParseError{
					message: "expected map key (string/ident/number), got '${key_tok.text}'"
					pos:     key_tok.pos
				}
			}
		}
		p.expect(.colon, "':' after map key")!
		val := p.parse_expr()!
		keys << key
		items << val
		if p.peek_kind() == .comma {
			p.advance()
		}
	}
	p.expect(.rbrace, "'}'")!
	return ProgramLiteral{
		kind:  .map_lit
		keys:  keys
		items: items
		pos:   start
	}
}
