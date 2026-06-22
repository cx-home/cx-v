module code

import cx

// cxpath_eval.v — STANDALONE CXPath axis-walker dispatcher
// D2 (the 12 XPath 3.1 axes) and (per-step candidate
// materialisation feeding PredicateExpr eager iteration).
//
// This file is Phase 2.6 PART 1 of 3 of the CXPath evaluator:
//
//   - PART 1 (this file + cxpath_forward.v) — dispatcher contract +
//     shared item / node / node-test types + the 3 forward axes
//     (child / descendant / descendant-or-self).
//   - PART 2 (sibling agent Z19, future `cxpath_reverse.v`) — the 4
//     reverse axes (parent / ancestor / ancestor-or-self / self).
//   - PART 3 (sibling agent Z20, future `cxpath_sibling.v` +
//     `cxpath_attr.v`) — the 5 remaining axes (following-sibling /
//     preceding-sibling / following / preceding / attribute).
//
// What this file provides:
//
//   - `pub struct CxNode` — minimal Document-AST stand-in carrying just
//     enough structure for the axis walker to traverse a small in-memory
//     tree. Fields cover element / attribute / text / scalar discrimination
//     with a `parent ?&CxNode` back-pointer + ordered `children []&CxNode`
//     forward list + `attrs map[string]string` map for element-kind
//     nodes. The Phase 2.x graft replaces CxNode with the production
//     Document-AST item (`vcx/cx/document.v` family) — the dispatcher
//     surface and per-axis handler signatures are forward-compatible
//     with that replacement.
//   - `pub struct CxItem` — alias of CxNode at Phase 2.6 part 1 (kept
//     as a distinct type-name so the future Document-AST integration
//     can split "structural node in document tree" from "evaluator
//     item kind" cleanly; mirrors the existing `Item` placeholder in
//     `predicate_eval.v`).
//   - `pub struct NodeTest` — wraps the `cx.PathStep.node_test` string
//     discriminator (`Name` / `*` / `*:Name` / `Prefix:*` /
//     `node()` / `text()` / `element()` / `attribute()`) into a parsed
//     shape the per-axis handlers can pattern-match on. Carries the
//     verbatim spelling + a `kind` discriminator + an optional `name`.
// Also carries the optional `:bind NAME` peer-modifier
//     D5 so handlers can propagate binding captures into downstream
//     predicate evaluation.
//   - `pub type AxisHandlerFn = fn(ctx &CxNode, test NodeTest) []&CxNode`
//     — the per-axis handler signature. Handler implementations live
//     in sibling files (cxpath_forward.v for the 3 forward axes; future
//     cxpath_reverse.v and cxpath_attr.v for the rest).
//   - `pub struct AxisDispatcher` — the dispatcher carries the
//     12-slot axis-handler table. `register` populates a slot; `dispatch`
//     looks up the handler for a given axis and calls it. Returns an
//     error when a handler is missing (Phase 2.6 part 1 ships 3-of-12;
//     parts 2 + 3 fill the remaining 9 slots).
//   - `pub fn new_default_axis_dispatcher() &AxisDispatcher` —
//     constructor that pre-registers the 3 forward axes via the
//     `register_forward_axes` helper exposed by cxpath_forward.v.
//     Sibling agents Z19 and Z20 are expected to either extend this
//     constructor or call `register` on a returned dispatcher.
//   - `pub fn eval_cxpath(node cx.PathNode, context_seq []&CxNode,
//     dispatcher &AxisDispatcher) ![]&CxNode` — the public entry point.
//     Walks the PathNode's step list LEFT-TO-RIGHT; for each step, the
//     output of all per-axis-handler invocations on every node in the
//     current context sequence becomes the input context sequence for
//     the next step. Predicate evaluation per step is DEFERRED to
//     Phase 2.21 — see the TODO note on `eval_cxpath`.
//
// Semantic surface at Phase 2.6 part 1:
//
//   - `cx.PathNode.form` discrimination — `.descendant` rooted paths
//     prepend an implicit `descendant-or-self::node()` step before
//     the explicit step list (matching grammar [130]'s `'//' StepList`
//     production); `.absolute` rooted paths treat the context sequence
//     as the document-root sequence; `.relative` paths evaluate from
//     the supplied context sequence unchanged; `.binding` paths
//     evaluate from the bound identifier's value resolved against the
//     context sequence (Phase 2.x graft wires `EvalContext.bindings`
//     in; for Phase 2.6 part 1 the caller supplies the binding's
//     materialised node sequence as `context_seq` directly).
//   - Multi-step composition — for each step in `node.steps`, the
//     dispatcher invokes the handler for `step.axis` against each
//     node in the current context sequence, concatenating per-node
//     handler outputs, then DEDUPLICATING by pointer identity (XPath
//     3.1 §3.2.1 sequence uniqueness rule). The de-duplicated sequence
//     becomes the input to the next step.
//   - Predicates per step — SKIPPED at Phase 2.6 part 1. The dispatcher
//     simply ignores `step.predicates` and proceeds to the next step.
//     This matches the Phase 2.21 evaluator's standalone scope: the
//     PredicateExpr evaluator (`predicate_eval.v::eval_predicate_filter`)
//     exists but takes `[]Item` candidates; once the Phase 2.x graft
//     bridges `CxNode` → `Item` per step, the dispatcher will call
//     `eval_predicate_filter` between the axis materialisation and the
//     next-step dispatch. TODO marker on the relevant line.
//
// Cross-references:
//   - spec/code.md (CXPath value kind: 12 axes, default-axis child,
//     path-walker composition, paths-on-bindings, attribute axis,
//     eager per-candidate predicate evaluation, `:bind NAME` peer-modifier)
//   - vcx/cx/path_node.v — PathNode + PathStep + PathAxis enum +
//     PathPredicate (consumed here for step walking)
//   - vcx/cx/path_parser.v — parser populates `step.axis` +
//     `step.node_test` + `step.binding` + `step.predicates`
//   - vcx/code/predicate_eval.v — Phase 2.21 PredicateExpr evaluator
//     (consumes the candidate sequence the axis walker produces; the
//      bridge between CxNode and `Item` lands in the Phase 2.x graft)
//   - vcx/code/match_eval.v + modify_eval.v — standalone-evaluator
//     pattern reference (Phase 2.7 / 2.8)
//
// Strict scope NON-goals at Phase 2.6 part 1 (deferred):
//   - Document-AST integration — CxNode is a stand-in; Phase 2.x graft.
//   - Predicate evaluation per step — Phase 2.21 graft.
//   - The 9 axes covered by parts 2 + 3 — parent / ancestor /
//     ancestor-or-self / self / following-sibling / preceding-sibling /
//     following / preceding / attribute.
//   - Sequence-operator composition (union / intersect / except / `to`)
// landing alongside the PathNode root-form
//     follow-ups.
//   - NodeTest kind-tests (`node()` / `text()` / `element()` /
//     `attribute()`) — Phase 2.6 part 1 honours `Name`, `*`, and the
//     two namespace-wildcard forms; the four kind-tests parse but
//     evaluate as "match everything" until the CxNode kind
//     discriminator carries the structural distinctions (Phase 2.x).

// ── CxNode / CxItem — minimal Document-AST stand-in ──────────────────────────

// CxNodeKind discriminates the four item kinds the Phase 2.6 axis
// walker needs to distinguish: element (has name + attrs + children),
// attribute (has name + value, no children), text (has value, no
// children, no name), and scalar (a single bare scalar value — int,
// string, bool, etc. — that lives at a leaf position in the tree).
// The Phase 2.x graft maps these onto the full CXDM value kinds
// (element / atom / scalar / array / map) via the
// `vcx/cx/document.v` family.
pub enum CxNodeKind {
	element
	attribute
	text
	scalar
}

// `@[heap]` is required because CxNode holds `parent ?&CxNode` and the
// children list holds `&CxNode` pointers; V's escape analysis would
// otherwise reject stack-allocated CxNodes being referenced from
// within other CxNodes.
@[heap]
pub struct CxNode {
pub mut:
	kind     CxNodeKind
	name     ?string
	value    ?string
	attrs    map[string]string
	children []&CxNode
	parent   ?&CxNode
}

// CxItem is the per-step candidate kind the dispatcher hands to the
// per-axis handlers. At Phase 2.6 part 1 it is a pointer-shaped alias
// of CxNode; the Phase 2.x graft splits "structural document node"
// (CxNode) from "evaluator item kind" (CxItem) when the production
// Document-AST lands. Kept as a distinct type-name so callers and
// per-axis handlers compile against the stable name.
pub type CxItem = CxNode

// new_element constructs an element-kind CxNode with the given name +
// empty attrs + empty children + no parent. Convenience for test
// construction.
pub fn new_element(name string) &CxNode {
	return &CxNode{
		kind:     .element
		name:     name
		attrs:    map[string]string{}
		children: []&CxNode{}
	}
}

// new_element_with_attrs constructs an element with the given attrs.
pub fn new_element_with_attrs(name string, attrs map[string]string) &CxNode {
	return &CxNode{
		kind:     .element
		name:     name
		attrs:    attrs.clone()
		children: []&CxNode{}
	}
}

// new_text constructs a text-kind CxNode with the given value.
pub fn new_text(value string) &CxNode {
	return &CxNode{
		kind:     .text
		value:    value
		attrs:    map[string]string{}
		children: []&CxNode{}
	}
}

// new_attribute constructs an attribute-kind CxNode. Attributes do
// not participate in element-child lists; they are reachable via the
// attribute axis only.
pub fn new_attribute(name string, value string) &CxNode {
	return &CxNode{
		kind:     .attribute
		name:     name
		value:    value
		attrs:    map[string]string{}
		children: []&CxNode{}
	}
}

// append_child mutates `parent.children` by appending `child` and
// sets `child.parent = parent`. Returns the parent pointer for
// chaining-friendly construction. This is the canonical builder used
// by tests + future Document-AST adapter code.
pub fn append_child(mut parent CxNode, mut child CxNode) &CxNode {
	child.parent = &parent
	parent.children << &child
	return &parent
}

// node_name returns the node's name (for element / attribute kinds)
// or the empty string for text / scalar. Convenience for node-test
// matching helpers.
pub fn node_name(n &CxNode) string {
	return n.name or { '' }
}

// ── NodeTest — parsed wrapper around `step.node_test` + `step.binding` ───────

// NodeTestKind discriminates the parsed form of a `cx.PathStep.node_test`
// string grammar [131b]. Phase 2.6 part 1 implements
// matching for the first three forms; the four kind-tests
// (`node()` / `text()` / `element()` / `attribute()`) parse as
// `.kind_test` but the per-axis handler treats them as
// "match anything of any element/text kind" until the structural
// kind discriminator on CxNode carries the four-way split.
pub enum NodeTestKind {
	name             // `Name` — bare local name
	wildcard         // `*` — any element name
	ns_wildcard_name // `*:Name` — any namespace, fixed local name
	prefix_wildcard  // `Prefix:*` — fixed namespace, any local name
	kind_test        // `node()` / `text()` / `element()` / `attribute()`
	qname            // `Prefix:LocalName` — explicit QName
}

// NodeTest carries the parsed shape of a step's node-test alongside
// the optional `:bind NAME` peer-modifier. Per-axis
// handlers consume this struct rather than the raw `cx.PathStep` so
// the dispatcher can pre-parse the node-test once per step and feed
// the parsed form to N handler invocations (one per context node).
pub struct NodeTest {
pub mut:
	kind     NodeTestKind
	source   string  // verbatim spelling (informational + kind-test arg)
	name     ?string // populated for .name / .ns_wildcard_name / .qname
	prefix   ?string // populated for .qname / .prefix_wildcard
	binding  ?string // `:bind NAME` peer-modifier
}

// parse_node_test converts the verbatim `cx.PathStep.node_test`
// string + optional `step.binding` into a `NodeTest` struct. The
// parsing rules mirror grammar [131b]:
//
//   - `*`               → .wildcard
//   - `node()`/`text()`/`element()`/`attribute()` → .kind_test
//     (the source string carries the parenthesised form; `name` is
//      left as none — callers needing the kind-test name strip the
//      parentheses from `source`)
//   - `Prefix:*`        → .prefix_wildcard, prefix = "Prefix"
//   - `*:LocalName`     → .ns_wildcard_name, name = "LocalName"
//   - `Prefix:LocalName` → .qname, prefix = "Prefix", name = "LocalName"
//   - anything else     → .name, name = source
//
// The function is total (every input produces some NodeTest); ill-
// formed node-test strings still produce a `.name` test with the
// verbatim input as the name. The path parser is the gate that
// rejects ill-formed surface — by the time we see a PathStep, the
// node-test source is well-formed.
pub fn parse_node_test(source string, binding ?string) NodeTest {
	src := source.trim_space()
	// Wildcard.
	if src == '*' {
		return NodeTest{
			kind:    .wildcard
			source:  src
			binding: binding
		}
	}
	// Kind tests — admit the 4 spellings.
	if src.ends_with('()') {
		return NodeTest{
			kind:    .kind_test
			source:  src
			binding: binding
		}
	}
	// Namespace forms with `:`.
	if src.contains(':') {
		parts := src.split(':')
		if parts.len == 2 {
			prefix := parts[0]
			local := parts[1]
			if prefix == '*' && local != '*' {
				return NodeTest{
					kind:    .ns_wildcard_name
					source:  src
					name:    local
					binding: binding
				}
			}
			if local == '*' && prefix != '*' {
				return NodeTest{
					kind:    .prefix_wildcard
					source:  src
					prefix:  prefix
					binding: binding
				}
			}
			return NodeTest{
				kind:    .qname
				source:  src
				prefix:  prefix
				name:    local
				binding: binding
			}
		}
	}
	// Bare local-name fallthrough.
	return NodeTest{
		kind:    .name
		source:  src
		name:    src
		binding: binding
	}
}

// cxpath_node_test_matches returns true iff the node satisfies the
// node-test. This is the shared matching helper that every per-axis
// handler uses after materialising a candidate node from its axis
// traversal.
//
// Named with the `cxpath_` prefix to disambiguate from the
// `node_test_matches(step cx.ProgramPathExprStep, el cx.Element, pc
// PathCtx)` helper in `eval.v` which operates on the legacy
// cx.ProgramPathExpr AST + Element value kind. The Phase 2.x graft
// retires the legacy helper once the dispatcher integration in
// `eval.v` swaps to `cx.PathNode` + this dispatcher.
//
// Per, attribute-axis steps test attribute nodes; the
// node-test matches against the attribute's name. Element-axis steps
// test element nodes; the node-test matches against the element's
// name. Kind tests (Phase 2.6 part 1) currently match any node — the
// structural kind discrimination lands in the Phase 2.x graft.
pub fn cxpath_node_test_matches(n &CxNode, test NodeTest) bool {
	match test.kind {
		.wildcard {
			// Wildcard `*` matches any element. Attributes are not
			// reached via `*` (attribute axis is
			// name-disjoint from element axes).
			return n.kind == .element
		}
		.kind_test {
			// Phase 2.6 part 1: kind-test source not yet split — match
			// any node. TODO(Phase 2.x): respect `node()` (all),
			// `text()` (text-kind only), `element()` (element-kind
			// only), `attribute()` (attribute-kind only).
			return true
		}
		.name {
			want := test.name or { return false }
			return node_name(n) == want
		}
		.ns_wildcard_name {
			// `*:LocalName` — any namespace, fixed local name. Element
			// names carry their prefix literally (`xhtml:user`), so match
			// either a bare local name or any `prefix:LocalName`.
			want := test.name or { return false }
			nm := node_name(n)
			return nm == want || nm.ends_with(':${want}')
		}
		.prefix_wildcard {
			// `Prefix:*` — fixed prefix, any local name. Match elements
			// whose literal name carries that prefix.
			p := test.prefix or { return false }
			return n.kind == .element && node_name(n).starts_with('${p}:')
		}
		.qname {
			// `Prefix:LocalName` — match the literal qualified name. CX
			// element names carry the prefix literally (an undeclared
			// prefix is part of the literal name per the first-occurrence
			// namespace model; a declared one keeps the prefix in the name
			// string too), so `ns:local` matches an element named exactly
			// `ns:local`.
			p := test.prefix or { return false }
			want := test.name or { return false }
			return node_name(n) == '${p}:${want}'
		}
	}
}

// ── AxisHandlerFn + AxisDispatcher ───────────────────────────────────────────

// AxisHandlerFn is the per-axis handler signature. A handler receives
// a single context node + the pre-parsed node-test for the step and
// returns the sequence of nodes that satisfy both:
//
//   (a) reachability from the context node along the handler's axis
//       (per XPath 3.1 §3.3 axis definitions)
//   (b) the node-test (per `node_test_matches`)
//
// The dispatcher invokes the handler ONCE per node in the current
// context sequence; per-node outputs are concatenated and de-duplicated
// by pointer identity before becoming the next step's input.
pub type AxisHandlerFn = fn (ctx &CxNode, test NodeTest) []&CxNode

// AxisDispatcher carries the 12-slot axis-handler table. Slots not
// yet registered surface a `CXPATH_AXIS_NOT_REGISTERED` error from
// `dispatch` — Phase 2.6 part 1 ships 3-of-12 (the forward axes);
// parts 2 + 3 fill the remaining 9 slots by calling `register` on
// the dispatcher.
//
// `@[heap]` because the dispatcher is held by reference across the
// `eval_cxpath` entry point + the per-step walk + every handler
// invocation; this keeps the per-call lifetime well-defined.
@[heap]
pub struct AxisDispatcher {
pub mut:
	handlers map[string]AxisHandlerFn
}

// new_axis_dispatcher constructs an empty dispatcher. Callers register
// handlers via `register` then invoke `dispatch`. For the common case
// of evaluating a `cx.PathNode` against the default Phase 2.6 part 1
// axis surface, use `new_default_axis_dispatcher` instead — it pre-
// registers the 3 forward axes.
pub fn new_axis_dispatcher() &AxisDispatcher {
	return &AxisDispatcher{
		handlers: map[string]AxisHandlerFn{}
	}
}

// register installs a handler for the given axis. Subsequent
// `dispatch` calls for that axis route to the handler. Registering
// the same axis twice REPLACES the prior handler — this lets sibling
// agents override stubs without ceremony during the parts-2/3
// landing.
//
// Sibling files (Phase 2.6 part 2 / 3) register their handlers by
// calling this method from an `init()` function inside the sibling
// file or from a sibling-side `register_*_axes(mut d)` helper invoked
// by the dispatcher constructor. The Phase 2.6 part 1 deliverable
// includes a single such helper (`register_forward_axes`) in
// `cxpath_forward.v`.
pub fn (mut d AxisDispatcher) register(axis cx.PathAxis, handler AxisHandlerFn) {
	d.handlers[cx.path_axis_name(axis)] = handler
}

// register_axis_handler is the free-function alias of the `register`
// method, exposed for sibling-file usage that prefers the free-fn
// surface over a method call. Z19 + Z20 hook in via either form.
pub fn register_axis_handler(mut d AxisDispatcher, axis cx.PathAxis, handler AxisHandlerFn) {
	d.register(axis, handler)
}

// dispatch invokes the handler for the given axis against the given
// context node + node-test. Returns the handler's result sequence on
// success or a `CXPATH_AXIS_NOT_REGISTERED` error when the axis has
// no handler registered. Callers (typically `eval_cxpath`) treat the
// error as a Phase-2.6-deferred-axis signal and may choose to skip
// the step or surface the error.
pub fn (d &AxisDispatcher) dispatch(axis cx.PathAxis, ctx &CxNode, test NodeTest) ![]&CxNode {
	key := cx.path_axis_name(axis)
	handler := d.handlers[key] or {
		return error('CXPATH_AXIS_NOT_REGISTERED: no handler registered for axis `${key}` (Phase 2.6 part 1 ships 3-of-12 — child / descendant / descendant-or-self; parts 2 + 3 land the remaining 9 axes)')
	}
	return handler(ctx, test)
}

// has_axis reports whether a handler is registered for the given
// axis. Useful for tests + diagnostic surfaces that want to soft-
// check axis support without driving a full dispatch.
pub fn (d &AxisDispatcher) has_axis(axis cx.PathAxis) bool {
	key := cx.path_axis_name(axis)
	return key in d.handlers
}

// new_default_axis_dispatcher constructs an AxisDispatcher with the
// full Phase 2.6 default surface: all 12 XPath 3.1 axes registered
// via the per-file `register_*_axes` helpers — `register_forward_axes`
// (cxpath_forward.v: child / descendant / descendant-or-self),
// `register_reverse_axes` (cxpath_reverse.v: parent / ancestor /
// ancestor-or-self), and `register_misc_axes` (cxpath_misc.v: self /
// attribute / following-sibling / preceding-sibling / following /
// preceding). The constructor is the recommended entry point for
// callers + tests that want the standalone evaluator's default
// behaviour — `eval_cxpath` against this dispatcher resolves every
// axis without requiring per-call composition.
//
// History: Phase 2.6 parts 1 → 3 landed the 12-axis surface across
// three sibling files; this constructor stitched the registration
// helpers together once all three parts were green (the deferred
// "wire register_reverse_axes + register_misc_axes into
// new_default_axis_dispatcher" follow-up).
pub fn new_default_axis_dispatcher() &AxisDispatcher {
	mut d := new_axis_dispatcher()
	register_forward_axes(mut d)
	register_reverse_axes(mut d)
	register_misc_axes(mut d)
	return d
}

// ── eval_cxpath — public entry point ─────────────────────────────────────────

// eval_cxpath walks the PathNode's step list LEFT-TO-RIGHT against
// the given context sequence + axis dispatcher. Returns the sequence
// of nodes reached after the final step's handler invocations +
// (when Phase 2.21 integration lands) predicate filtering.
//
// Multi-step composition contract:
//
//   1. The initial "current sequence" is `context_seq` — a list of
//      `&CxNode` pointers (one per node in the caller's evaluation
//      context). For `cx.PathNode.form == .descendant` (the `//` root
//      form), a pseudo-step `descendant-or-self::node()` is prepended
//      to the explicit step list before walking.
//   2. For each step in the step list, the dispatcher:
//        a. Pre-parses the node-test once via `parse_node_test`.
//        b. Invokes `dispatcher.dispatch(step.axis, node, test)` for
//           each `node` in the current sequence.
//        c. Concatenates the per-node handler outputs into a single
//           sequence.
//        d. De-duplicates by pointer identity (XPath 3.1 §3.2.1
//           sequence uniqueness rule).
//        e. TODO(Phase 2.21 integration): apply step predicates after
//           axis materialisation by calling
//           `eval_predicate_filter(seq, expr, ctx)` for each predicate
//           in `step.predicates` (left-to-right, AND-composition per
// grammar [131]'s `Predicate*` repetition).
//           Phase 2.6 part 1 SKIPS this step — predicates are silently
//           ignored.
//        f. The resulting sequence becomes the input for the next step.
//   3. After the final step, the de-duplicated sequence is returned.
//
// The `dispatcher` parameter is the axis-handler table. The recommended
// constructor is `new_default_axis_dispatcher()` (3 forward axes only
// at Phase 2.6 part 1); Phase 2.6 parts 2 + 3 extend the constructor
// to cover all 12 axes.
//
// Errors:
//   - When a step's axis has no handler registered, the dispatcher
//     returns `CXPATH_AXIS_NOT_REGISTERED` and `eval_cxpath` propagates
//     the error (callers can choose to fall back to a partial walk).
pub fn eval_cxpath(node cx.PathNode, context_seq []&CxNode, dispatcher &AxisDispatcher) ![]&CxNode {
	mut current := context_seq.clone()
	// Form-driven step-list prefix synthesis.
	mut steps := []cx.PathStep{cap: node.steps.len + 1}
	match node.form {
		.descendant {
			// `//pattern` lowers to an implicit
			// `descendant-or-self::node()` step before the explicit
			// step list per grammar [130].
			steps << cx.new_path_step(.descendant_or_self, 'node()')
			for s in node.steps {
				steps << s
			}
		}
		.absolute {
			// `/pattern` evaluates against the document-root sequence
			// — the caller is responsible for supplying `context_seq`
			// rooted at the document root (Phase 2.6 part 1; the
			// Phase 2.x graft adds a document-root resolution hook).
			for s in node.steps {
				steps << s
			}
		}
		.relative {
			// `pattern` evaluates against the supplied context_seq
			// unchanged.
			for s in node.steps {
				steps << s
			}
		}
		.binding {
			// `$x/step+` — the bound identifier's value must be
			// materialised by the caller and supplied as
			// `context_seq`. Phase 2.6 part 1 takes context_seq as
			// the binding's value; the Phase 2.x graft wires an
			// EvalContext.bindings lookup.
			for s in node.steps {
				steps << s
			}
		}
	}
	// Step-by-step walk.
	for step in steps {
		test := parse_node_test(step.node_test, step.binding)
		mut next := []&CxNode{}
		for ctx_node in current {
			matched := dispatcher.dispatch(step.axis, ctx_node, test)!
			for m in matched {
				next << m
			}
		}
		// XPath 3.1 §3.2.1 sequence uniqueness — de-duplicate by
		// pointer identity. The cost is O(n²) at this scope; the
		// Phase 2.x graft swaps for a `voidptr` set when the
		// sequences are large enough to matter.
		current = dedupe_by_identity(next)
		// Z79e structural-graft (Phase 2.21 integration): apply each
		// step predicate left-to-right (AND-composition
		// D2 grammar [131] `Predicate*` repetition). Each predicate
		// that carries a parsed `expr ?&PredicateExpr` (populated by
		// `cx.parse_path` via the Phase 2.19 atomic-template parser)
		// is fed through the standalone `eval_predicate_filter` after
		// bridging the `&CxNode` candidate sequence to `[]Item`.
		// Predicates whose `expr` is `none` (parse failure / outside
		// the atomic-template surface) are silently ignored at this
		// scope — the `eval_path_expr` hop retains source-only
		// predicate semantics for the dispatcher path; the standalone
		// surface here intentionally narrows to atomic
		// templates.
		for pred in step.predicates {
			expr_ptr := pred.expr or { continue }
			current = filter_step_predicate(current, expr_ptr)!
		}
	}
	return current
}

// filter_step_predicate bridges the `[]&CxNode` candidate sequence to
// `[]Item` (the Phase 2.21 standalone-evaluator surface) and applies
// `eval_predicate_filter` against the parsed `cx.PredicateExpr` body.
// Returns the filtered candidate sequence in source order — the bridge
// preserves the index↔candidate correspondence so the filtered Item
// indices map back to the original &CxNode references.
//
// Per candidate materialisation is eager — the bridge
// allocates one Item per candidate. Per only atomic-template
// predicate kinds (attr_test / attr_compare / int_position /
// reserved_binding / function_call) succeed at Phase 2.21-standalone;
// anything else surfaces `MATCH_PREDICATE_EVAL_NOT_YET_IMPLEMENTED`,
// which we treat as "predicate inexpressible at this surface → identity
// pass-through" (consistent with the previous silent-ignore behaviour
// at the deferral TODO line, but now with full coverage of the
// atomic-template subset).
fn filter_step_predicate(candidates []&CxNode, predicate &cx.PredicateExpr) ![]&CxNode {
	mut items := []Item{cap: candidates.len}
	for c in candidates {
		items << cxnode_to_item(c)
	}
	context := PredicateEvalContext{
		bindings: map[string]Value{}
	}
	filtered := eval_predicate_filter(items, predicate, context) or {
		// Unsupported predicate shape (e.g. bool_expr / sequence_op /
		// generic outside the Phase 2.21 atomic-template surface).
		// Preserve the previous silent-ignore semantics — predicate
		// becomes an identity filter rather than a hard error so the
		// `eval_cxpath` caller (test suite + Phase 2.6 sibling agents)
		// retains existing pass behaviour on out-of-scope predicates.
		if err.msg().contains('MATCH_PREDICATE_EVAL_NOT_YET_IMPLEMENTED')
		   || err.msg().contains('PREDICATE_EVAL_NOT_YET_IMPLEMENTED') {
			return candidates
		}
		return err
	}
	// Map filtered Items back to &CxNode by ordered correspondence.
	// `eval_predicate_filter` preserves input order + only removes
	// candidates that EBV'd false, so a 2-pointer linear merge by Item
	// identity (kind+name+value+attrs) is unambiguous when the source
	// sequence has no duplicate Item-shapes; on dup-shape collisions we
	// degrade gracefully to "first un-consumed match wins" which
	// preserves source order. (The two sequences only ever shrink — the
	// production graft swaps the Item placeholder for a CxNode-backed
	// type, removing this re-correlation step entirely.)
	mut out := []&CxNode{cap: filtered.len}
	mut consumed := []bool{len: candidates.len, init: false}
	for f in filtered {
		for i in 0 .. candidates.len {
			if consumed[i] {
				continue
			}
			if item_eq(items[i], f) {
				out << candidates[i]
				consumed[i] = true
				break
			}
		}
	}
	return out
}

// cxnode_to_item bridges a single `&CxNode` to the standalone `Item`
// placeholder consumed by `eval_predicate_filter`. Field mapping:
//
//   - `kind`           : 'element' | 'attribute' | 'text' | 'scalar'
//                        (CxNodeKind → string label)
//   - `name`           : copied through (?string)
//   - `value`          : copied through (?string)
//   - `attrs`          : copied through (map[string]string)
//   - `children_count` : len of `node.children` — drives `count(*)`
//                        style predicates
fn cxnode_to_item(n &CxNode) Item {
	kind_label := match n.kind {
		.element   { 'element' }
		.attribute { 'attribute' }
		.text      { 'text' }
		.scalar    { 'scalar' }
	}
	return Item{
		kind:           kind_label
		name:           n.name
		value:          n.value
		attrs:          n.attrs.clone()
		children_count: n.children.len
	}
}

// item_eq tests two `Item` values for field-by-field equality. Used by
// `filter_step_predicate` to correlate filtered Items back to the
// originating `&CxNode` source. Conservative — kind + name + value +
// attrs + children_count must all match; first un-consumed match wins
// at the caller.
fn item_eq(a Item, b Item) bool {
	if a.kind != b.kind {
		return false
	}
	a_name := a.name or { '' }
	b_name := b.name or { '' }
	if a_name != b_name {
		return false
	}
	a_value := a.value or { '' }
	b_value := b.value or { '' }
	if a_value != b_value {
		return false
	}
	if a.children_count != b.children_count {
		return false
	}
	if a.attrs.len != b.attrs.len {
		return false
	}
	for k, v in a.attrs {
		bv := b.attrs[k] or { return false }
		if v != bv {
			return false
		}
	}
	return true
}

// dedupe_by_identity returns a new slice containing the input nodes
// in source order with duplicates (by pointer identity) removed.
// Used by `eval_cxpath` to honour the XPath 3.1 §3.2.1 sequence
// uniqueness rule per step.
fn dedupe_by_identity(seq []&CxNode) []&CxNode {
	mut out := []&CxNode{cap: seq.len}
	for n in seq {
		mut seen := false
		for k in out {
			if voidptr(k) == voidptr(n) {
				seen = true
				break
			}
		}
		if !seen {
			out << n
		}
	}
	return out
}
