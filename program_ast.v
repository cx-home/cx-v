module cx

// ── program AST ──────────────────────────────────────────────────────────────────
//
// Mirrors the seven program AST node types in spec/ast.md §"program AST".
// Gate 3 of the §11.6 release gates verifies
// set-equality between this module's exported node types and spec/ast.md.
//
// Pattern surface (spec/code.md §5) and directive slots (§8 / §10) are
// captured here; the evaluator (Phases 3.2 onward) walks these nodes.

// ProgramNode is the universal program AST sum type. Every CX code expression
// parses to one variant.
//
// Note: the surface infix pipe `expr | expr | …` desugars at parse time
// to a `ProgramDirective{name: 'pipe', …}` per spec/code.md §6.4
// there is no distinct pipe node type.
pub type ProgramNode = Program
	| ProgramBinding
	| ProgramCall
	| ProgramPattern
	| ProgramDirective
	| ProgramForComp
	| ProgramLiteral
	| ProgramPathExpr
	| ProgramSliceAccess
	| ProgramSliceLiteral
	| ProgramWildcard

// Program is the top-level wrapper around a single ProgramNode body.
// A `.cx` source file parses to exactly one Program.
pub struct Program {
pub:
	body ProgramNode @[required]
	pos  Position
}

// ProgramBinding represents `$ident` followed by zero or more path steps.
// `path` is empty for a bare binding (`$x`). Used in both pattern
// position (bind site) and expression position (read site).
pub struct ProgramBinding {
pub:
	name string @[required]
	path []ProgramPathStep
	pos  Position
	// type_test (pattern-position only, spec/code.md §5.2 rule 14) carries
	// the `::T` value-kind tag of a typed-bind pattern `$name::T`. Empty for
	// an ordinary binding. When `name == "_"` the bind is anonymous
	// (`_::T` — tests the kind, binds nothing). Erased in expression
	// position.
	type_test string
	// is_rest (pattern-position only, spec/code.md §5.2 rules 11–13) marks a
	// rest-capture `*$name` inside a map / sequence / array pattern: it binds
	// the unmatched trailing items as a value of the surrounding kind. Only
	// legal as the final item of a collection pattern.
	is_rest bool
}

// ProgramPathStep is one element of a binding's path. `kind` selects
// between child (`/`), attr (`@`), member (`.`), descendant (`//`),
// parent (`/..`), and wildcard_children (`/*`). Each step may carry
// zero or more trailing `[…]` predicates (general
// PredicateExpr).
pub struct ProgramPathStep {
pub:
	kind PathStepKind @[required]
	name string @[required]
	predicates []ProgramPathPredicate
}

pub enum PathStepKind {
	child  // /name
	attr   // @name or /@name
	member // .name (map-key access)
	wildcard_children // /*  — all child elements
	descendant        // /name — descendant-or-self::node()/child::name (G1)
	descendant_wildcard // /* — every descendant element (G1)
	parent            // .. — parent axis (G2)
}

// ProgramCall represents `name(args) [? | !]?`. `fallible` corresponds to
// the `?` postfix, `must_succeed` to `!`; both false is the default
// total form. The two are mutually exclusive — the parser enforces this.
pub struct ProgramCall {
pub:
	name         string @[required]
	args         []ProgramNode
	fallible     bool
	must_succeed bool
	// explicit_call is true when the source used the call form `name(...)`
	// (parens present), false for a bare reference `name`. Per 
	// D1, a bare reference to a function in value position yields a
	// first-class function VALUE rather than calling it; a 0-arg call is
	// written `name()`. A bare name resolving to a non-function binding is
	// the ordinary variable reference.
	explicit_call bool
	// arg_labels is parallel to args: a non-empty entry is
	// the `:label` of a named call-argument `name(:label v)`; an empty
	// entry marks a positional argument. Empty/absent for all-positional
	// calls.
	arg_labels   []string
	pos          Position
}

// ProgramPatternHeadKind selects between named, wildcard, deep-wildcard,
// and type-guard heads per spec/code.md §5.
pub enum ProgramPatternHeadKind {
	named       // element name
	wildcard    // *
	deep        // **
	type_guard  // :User
}

// ProgramPatternHead carries the pattern's head selector and optional
// `$bind` binding for the matched node.
pub struct ProgramPatternHead {
pub:
	kind  ProgramPatternHeadKind @[required]
	value string  // element name, or '*', or '**', or 'User' (type-guard)
	bind  string  // empty if no $bind
}

// ProgramPatternAttrKind selects between attribute predicate forms.
pub enum ProgramPatternAttrKind {
	existence  // @name
	absence    // @!name
	equality   // @name=expr
	comparison // @name relop expr
	type_test  // @name::T  (spec/code.md §5.2 rule 14, attribute position)
}

// ProgramPatternAttr is one attribute predicate on a pattern.
pub struct ProgramPatternAttr {
pub:
	kind  ProgramPatternAttrKind @[required]
	name  string @[required]
	op    string             // '=', '!=', '<', '<=', '>', '>=', or '' for existence/absence
	value ?ProgramNode           // None for existence/absence
	// type_name carries the `::T` value-kind tag for a `type_test` attr
	// predicate (`@age::int`); empty for the other kinds.
	type_name string
}

// ProgramPattern is the structural shape match per spec/code.md §5.
// `direct: true` activates :direct adjacency-strict child matching.
pub struct ProgramPattern {
pub:
	head   ProgramPatternHead @[required]
	attrs  []ProgramPatternAttr
	direct bool
	body   []ProgramNode  // children: ProgramPattern | ProgramBinding | ProgramWildcard
	pos    Position
}

// ProgramWildcard represents `*` or `**` appearing as a child matcher
// inside a ProgramPattern body. Distinguished from ProgramPatternHead's
// wildcard/deep kinds (which are head selectors, not children).
pub struct ProgramWildcard {
pub:
	deep bool  // false for *, true for **
	pos  Position
}

// ProgramSlotKind distinguishes labeled (`:label expr`) and positional
// (bare expr) directive slots.
pub enum ProgramSlotKind {
	labeled
	positional
}

// ProgramSlot carries one directive argument slot.
pub struct ProgramSlot {
pub:
	kind  ProgramSlotKind @[required]
	label string      // empty for positional
	value ProgramNode @[required]
}

// ProgramAttr carries one element-construction attribute clause —
// `name=value` on the head of a CX element literal, where `value` is
// evaluated at the call site (so `[code lang=$l $s]` evaluates `$l`
// in scope and stores its stringified value as the attribute's value
// on the constructed Element). This is the expression-position
// dual of pattern attribute predicates (`ProgramPatternAttr`); the
// pattern form filters/binds, the literal form constructs.
pub struct ProgramAttr {
pub:
	name  string      @[required]
	value ProgramNode @[required]
}

// ProgramDirective is the universal directive AST shape. `name` is one of
// the 39 directive names per directive_names; the parser
// enforces membership and raises CXER0100 on miss.
pub struct ProgramDirective {
pub:
	name  string @[required]
	slots []ProgramSlot
	pos   Position
}

// ProgramForClauseKind enumerates the for-comprehension clause vocabulary
// per spec/code.md §7.
pub enum ProgramForClauseKind {
	generator   // $bind :in source
	filter      // :where expr
	binding     // :let $bind = expr
	order_by    // :order-by expr [asc|desc]
	group_by    // :group-by expr
	limit       // :limit expr
	par         // :par         — parallel generator evaluation (§7.3)
	stream      // :stream      — lazy / streaming evaluation (§7.4)
	ordered     // :ordered     — preserve input order under :par (§7.3)
	take        // take N, short-circuit after N yields
	drop        // drop N, skip first N candidates
	takewhile   // takewhile P, yield until predicate first fails
	dropwhile   // dropwhile P, skip while predicate holds, then yield
}

// ProgramForClause is one clause of a for-comprehension.
pub struct ProgramForClause {
pub:
	kind      ProgramForClauseKind @[required]
	bind      string       // generator / binding
	source    ?ProgramNode     // generator
	expr      ?ProgramNode     // filter / binding / order-by / group-by
	direction string       // order-by: 'asc' | 'desc' | ''
}

// ProgramForCompYieldForm — per-iteration result shape.
//   - sequence : `:yield X`         (X is a scalar / element / inline
//                                   sequence; inner sequences flatten
//   - array    : `:yield-array X`   (each yield wraps as an Array;
//                                   arrays do NOT flatten)
//   - map      : `:yield-map K => V` (each yield is a (key, value)
//                                   pair; requires `[?for-map]` outer)
pub enum ProgramForCompYieldForm {
	sequence
	array
	map
}

// ProgramForCompOuterForm — outer container of the for-comp result
//   - sequence : `[?for]`        — default, Sequence-shaped result
//   - array    : `[?for-array]`  — preserves Array outer structure
//   - map      : `[?for-map]`    — Map outer; requires `:yield-map`
pub enum ProgramForCompOuterForm {
	sequence
	array
	map
}

// ProgramForComp is the for-comprehension specialisation of ProgramDirective
// with name='for' / 'for-array' / 'for-map'. AST consumers MAY treat as a
// ProgramDirective; the explicit shape exists for evaluator and renderer
// ergonomics per spec/ast.md §"ProgramForComp".
//
// `yield` carries the body of the yield clause (or, for `:yield-map`, the
// key expression). `yield_value` carries the value expression for
// `:yield-map K => V`; it is `none` for the scalar / array yield forms.
pub struct ProgramForComp {
pub:
	clauses     []ProgramForClause
	yield       ProgramNode @[required]
	yield_value ?ProgramNode  // populated only when yield_form == .map
	yield_form  ProgramForCompYieldForm = .sequence
	outer_form  ProgramForCompOuterForm = .sequence
	pos         Position
}

// ── ProgramPathExpr (CXPath as value kind) ──────────────────────
//
// A CXPath surface like `//user[@active=true]/name` parses to a
// ProgramPathExpr. Per grammar [130]-[135], this is a
// value-kind AST node: at eval time it produces a sequence of matching
// nodes from the document. The terse `//step/step/...` form is canonical
// per D6.
//
// Chunk-1 foundation (this commit) covers descendant-rooted simple
// paths: `//name` and `//name/name` with implicit child axis on the
// trailing steps. Predicates `[…]`, the full 12-axis enumeration,
// absolute `/`-rooted paths, relative paths, sequence operators
// (union/intersect/except), and BindingPath `$x/step+` are subsequent
// chunks.

// ProgramPathExpr is one CXPath value-kind expression.
pub struct ProgramPathExpr {
pub:
	leading ProgramPathLeading @[required]
	steps   []ProgramPathExprStep
	pos     Position
}

// ProgramPathLeading selects how the path is anchored.
pub enum ProgramPathLeading {
	descendant   // '//' — search at any depth (descendant-or-self axis)
	absolute     // '/'  — anchored at the document root
	relative     // bare step — relative to context item (Chunk N)
}

// ProgramPathExprStep is one step in a PathExpr's step list per grammar [131]:
//   Step ::= (AxisSpecifier '::')? NodeTest Predicate*
// Named distinctly from ProgramPathStep (which is the BindingPath step
// shape used by `$x/foo`) — the two surface forms share conceptual
// kinship but differ in axis vocabulary and predicate scope; keeping
// them separate avoids cross-form leakage.
// Chunk-1 set the axis from leading ('/'/'//') + step position. Chunk-2
// adds explicit axis prefixes (`axis::name`) and predicates (`[…]`); the
// `axis_explicit` flag controls canonical emit so default axes round-trip
// as bare steps while explicit ones emit `axis::`.
pub struct ProgramPathExprStep {
pub:
	axis          ProgramPathAxis @[required]
	axis_explicit bool   // true when source used `axis::name` form
	name          string // element name; '*' for wildcard NodeTest.
	                     // For ns_kind == .any_ns this carries the local
	                     // name (e.g. `*:user` → name='user', ns_kind=.any_ns).
	                     // For ns_kind == .prefix_any_local this is '*'.
	                     // For ns_kind == .prefix_local this is the local
	                     // name; ns_prefix carries the prefix.
	ns_kind       ProgramPathNsKind // namespace-test shape
	ns_prefix     string // populated when ns_kind ∈ {prefix_local, prefix_any_local}
	predicates    []ProgramPathPredicate
	bind          string // `(bind $NAME)` step annotation [160a]; '' if absent
	pos           Position
}

// ProgramPathNsKind selects the namespace-test shape for a NodeTest per
// grammar [131b]. Default `.none` means "no namespace constraint": the
// existing `name` matches by source / expanded name as before. The other
// three forms are the namespace-wildcard NodeTests added.
pub enum ProgramPathNsKind {
	none              // bare `Name` or `*` — no namespace test
	any_ns            // `*:LocalName` — any namespace, specific local
	prefix_any_local  // `Prefix:*` — specific namespace, any local
	prefix_local      // `Prefix:LocalName` — fully qualified
}

// ProgramPathPredicateKind selects between the predicate forms a Step can
// carry per grammar [132]–[133].
//   - .position  : `[INT]` 1-indexed positional filter (sugar over
// `[$_position = INT]`)
//   - .attr_test : `[@name]` / `[@!name]` / `[@name=val]` / `[@name op val]`
// (sugar over `[$_@name op val]`)
//   - .expr      : general PredicateExpr — any ProgramExpr coerced via EBV
//                  with `$_` / `$_position` / `$_last` in scope
pub enum ProgramPathPredicateKind {
	position
	attr_test
	expr
}

// ProgramPathPredicate is one `[…]` predicate on a Step. Multiple
// predicates on a Step are conjunctive (all must hold; applied
// left-to-right). Carries the shape needed for each kind via tagged
// fields; only the fields relevant to `kind` are populated.
//
// For `.attr_test`, the same enum / op grammar as ProgramPatternAttr
// applies — eval reuses `match_attr` (matcher.v) verbatim for spec
// equivalence with `[?match]` attribute predicates.
//
// For `.expr`, `body` is the parsed ProgramNode of the predicate body.
// At eval time, `$_` / `$_position` / `$_last` are bound in the env
// before evaluating `body`; the result is coerced via EBV.
pub struct ProgramPathPredicate {
pub:
	kind ProgramPathPredicateKind @[required]
	// .position
	int_index i64
	// .attr_test
	attr_kind  ProgramPatternAttrKind
	attr_name  string
	attr_op    string
	attr_value ?ProgramNode
	// .expr
	body       ?ProgramNode
	pos        Position
}

// ProgramPathAxis enumerates the 12 XPath 3.1 axes.
// Chunk-1 implements child + descendant_or_self; the remaining ten are
// declared here so subsequent chunks plug in without enum churn.
pub enum ProgramPathAxis {
	child
	descendant
	descendant_or_self
	parent
	ancestor
	ancestor_or_self
	following_sibling
	preceding_sibling
	following
	preceding
	self_axis     // 'self' — V keyword, renamed
	attribute
}

// ProgramLiteralKind selects between literal kinds.
pub enum ProgramLiteralKind {
	string_lit
	int_lit
	// v0.8.0 D-H: a bare decimal integer literal that OVERFLOWS i64 auto-
	// promotes to bigint (stays numeric) rather than degrading to a string.
	// The verbatim digit text (sign-normalized, `_` stripped) is carried in
	// `str_val`; eval produces a ScalarNode with data_type=.bigint_type.
	// Mirrors the data reading's try_autotype bigint fallback so the two
	// readings agree on over-i64 integers.
	bigint_lit
	float_lit
	bool_lit
	duration_lit
	// v0.8.0 [L26]: calendar-span literal `3mo`/`1y`. Verbatim text in
	// `dur_val` (shared field with duration_lit); eval → ScalarNode of
	// data_type=.period_type.
	period_lit
	// v0.8.0 lexicon §9 [L23]/[L24]: temporal scalars. The verbatim
	// source text is carried in `str_val`; eval produces a ScalarNode
	// with data_type=.date_type / .datetime_type and value=the source.
	date_lit
	datetime_lit
	sequence_lit  // (a, b, c)
	array_lit     // [a, b, c]
	map_lit       // {k: v, …}
	cx_element    // [name body...]  — element-shaped CX literal
	block         // implicit top-level multi-statement program (eval
	              // each in order; return last value). Parsers emit this
	              // ONLY at program root with multiple statements.
	// v0.8.0: atom literal — surface `:NAME`. Carries the
	// atom name in `str_val` (without the leading colon). At eval
	// time produces a ScalarNode with data_type=.atom_type and
	// value=ScalarValue(name). Equality is name-equality, type-
	// strict (atom never equals string of same characters).
	atom_lit
	// v0.8.0 DATA↔PROGRAM SEAM: an embedded pure-DATA construct the program
	// surface carries verbatim — raw text `[#…#]`, an entity / character
	// reference `&…;` / `&#…;`, or a declaration `[!…]` (DTD declarations +
	// `[!DOCTYPE …]`). The program lexer captures the construct's SPAN and the
	// parser delegates to the proven data reader (`cx.parse_data_node`), storing
	// the resulting `cx.Node` in `node`; eval returns it as-is. This keeps the
	// "data = a program that evaluates to itself" seam closed BY CONSTRUCTION —
	// the program (eval) reading of these constructs IS the data reading. The
	// verbatim span source is also kept in `str_val` for program-AST
	// re-emission (program_emit / program_xml / ast_json).
	node_lit
}

// ProgramLiteral carries a literal value. `kind` selects which of the
// optional fields is populated.
pub struct ProgramLiteral {
pub:
	kind    ProgramLiteralKind @[required]
	str_val string         // string_lit
	int_val i64            // int_lit
	flt_val f64            // float_lit
	bool_val bool          // bool_lit
	dur_val string         // duration_lit — preserved verbatim ('100ms')
	items   []ProgramNode      // sequence_lit / array_lit / map_lit values / cx_element body
	keys    []string       // map_lit keys (parallel to items)
	name    string         // cx_element head (empty when name_expr is set)
	// name_expr dynamic element-name form. When set on a
	// cx_element ProgramLiteral, the element's name is computed at
	// evaluation time by evaluating this expression, coercing to a
	// string / atom name. `name` is empty when `name_expr` is set; the
	// two are mutually exclusive.
	name_expr ?ProgramNode
	// node — the parsed data node for a `node_lit` literal (DATA↔PROGRAM seam).
	// Populated ONLY for kind=.node_lit; carries the `cx.parse_data_node` result
	// for a `[#…#]` raw / `&…;` entity / `[!…]` declaration span. Eval returns it
	// verbatim. None for every other kind.
	node ?Node
	// slots — RETIRED (v0.8.0 / D014). The `[name … :label value]`
	// element-literal colon-slot SOURCE surface no longer parses: element
	// construction uses attributes (`code="x"`) and positional body only
	// (spec/core/code.md §9.1: `[ok VALUE]`, `[err code= message= …]`). The
	// parser never populates this list for cx_element kinds now; the field +
	// the eval reshape that consumed it remain as inert internal encoding
	// (slot-child path reads) and are always empty in practice.
	slots   []ProgramSlot
	// attrs — element-construction attributes `name=value` on a
	// cx_element. Each attr's value is a ProgramNode evaluated at
	// call time. Empty for non-cx_element kinds. See ProgramAttr for
	// the full rationale (pattern dual: ProgramPatternAttr).
	attrs   []ProgramAttr
	// data_type — a glued head TypeAnnotation `::T` / `::T[]` / `::[]` on a
	// cx_element (lexicon §7 [L50], §9 [L25d]). Empty when absent. `'T'` →
	// the body is ONE scalar of T; `'T[]'` → a typed array of T; `'[]'` →
	// an inferred-type array. An annotation OVERRIDES §9 auto-typing.
	data_type string
	pos     Position
}

// ── slice / multi-axis postfix on a $binding ─────────────────────
//
// `ProgramSliceAccess` represents a slice / multi-axis index expression
// on a `$binding`, BindingPostfix production:
//
//     $xs[2:5]            — single-axis closed range
//     $xs[:5]             — open start, closed stop=5
//     $xs[-3:]            — closed start=-3, open stop (negative index)
//     $xs[::2]            — strided (every other element)
//     $xs[::-1]           — reversed walk (step=-1)
//     $xs[*]              — full axis (rare on 1-D, common on multi-axis)
//     $matrix[1:3, 2:4]   — multi-axis (N axes, N = source rank)
//
// Disambiguation from the existing CXPath predicate `[Expr]`:
// the choice is positional — the token preceding the `[` decides. After
// `$NCName` (a binding), the parser performs a slice-shape lookahead
// (leading `:`, top-level `:` between exprs, leading `*`, or top-level
// `,`) and routes to this node when any of those tokens are seen;
// otherwise the bracket parses as a single-expression predicate per
// locks the rule. The W5b implementation
// constructs the AST only — `eval_slice_access` is deferred to W5c.
pub struct ProgramSliceAccess {
pub:
	// binding — the underlying `$NCName` reference the slice applies
	// to. Path steps on the binding (`$obj/x[2:5]`) are admitted by
	// re-using the existing ProgramBinding shape; the slice always sits
	// at the postfix of the binding-with-path.
	binding ProgramBinding @[required]
	// axes — one or more SliceAxis values. Single-axis form is the
	// common case; multi-axis (comma-separated) is parsed for forward
	// compatibility with W6's `$matrix[1:3, 2:4]` surface but is not
	// evaluable yet.
	axes []SliceAxis @[required]
	pos  Position
}

// SliceAxisKind selects the shape of one axis index.
pub enum SliceAxisKind {
	single   // single expression — `[N]` form ; semantics deferred to W5c
	range    // start:stop[:step] — any/all components may be absent
	full     // `*` — full axis (no slicing on this dimension)
}

// SliceAxis is one comma-separated axis inside a `ProgramSliceAccess`.
//
// For `.range` axes, any of `start` / `stop` / `step` may be absent
// (`none`), e.g.:
//   - `[2:5]`     → start=2,  stop=5,    step=none
//   - `[:5]`      → start=none, stop=5,  step=none
//   - `[-3:]`     → start=-3, stop=none, step=none
//   - `[::2]`     → all bounds open, step=2
//   - `[::-1]`    → all bounds open, step=-1 (reverse walk)
//
// Per the stop value is INCLUSIVE; W5b parses only.
// Step semantics (D21: parse-time error on step-of-zero) is handled by
// W5c at evaluation time — the W5b parser preserves the literal AST.
pub struct SliceAxis {
pub:
	kind  SliceAxisKind @[required]
	// For `.single`: `start` carries the single index expression;
	// `stop` and `step` are `none`.
	// For `.range`: any of `start` / `stop` / `step` may be `none`.
	// For `.full` (`*`): all three are `none`.
	start ?ProgramNode
	stop  ?ProgramNode
	step  ?ProgramNode
	pos   Position
}

// ── Slice as a first-class value ─────────────────────────────
//
// `ProgramSliceLiteral` represents a bracketed slice expression in
// expression position (NOT after a $binding postfix), e.g.:
//
//     [?def $w [2:$_last-1]]
//     [?let $s = [::2] :in $xs[$s]]
//
// Per the slice evaluates to a first-class `Slice` value
// that can be bound and re-applied to multiple receivers. Per D11 the
// `$_last` sigil resolves at APPLICATION time (against the receiver's
// length), not at construction — so the unevaluated SliceAxis AST is
// what we hand around, parked in `ProgramState.slice_literals` and
// reachable through a `__cx_slice__` element wrapper.
//
// Grammar (parser disambiguation in parse_bracket):
//
//   SliceLiteral ::= '[' SliceAxes ']'    (single-axis only; multi-axis
//                                           slice literals defer to a
//                                           future slot — they would
//                                           collide with array literals
//                                           and need a stronger guard).
//
// Disambiguation from `[name body…]` element literal: the slice-literal
// surface admits exactly the shapes that the binding-postfix disambig-
// uator already recognises (leading `:` / `::`, leading `*` alone, or a
// top-level `:` between expressions). The element-head guard (ident or
// arithmetic head) takes precedence — so `[+ 1 2]` stays an element.
pub struct ProgramSliceLiteral {
pub:
	axes []SliceAxis @[required]
	pos  Position
}
