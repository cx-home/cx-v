module code

import cx

// cxpath_forward.v — Phase 2.6 PART 1 of 3: the 3 forward CXPath axes
// per (child / descendant / descendant-or-self).
//
// What this file provides:
//
//   - `pub fn axis_child(ctx &CxNode, test NodeTest) []&CxNode` —
//     XPath 3.1 §3.3.1.1 child axis: direct children of the context
//     node, in document order, filtered by `cxpath_node_test_matches`.
//   - `pub fn axis_descendant(ctx &CxNode, test NodeTest) []&CxNode` —
//     XPath 3.1 §3.3.1.2 descendant axis: every node reachable by
//     following the child axis 1+ times from the context node, in
//     depth-first document order, filtered by `cxpath_node_test_matches`.
//     EXCLUDES the context node itself.
//   - `pub fn axis_descendant_or_self(ctx &CxNode, test NodeTest) []&CxNode` —
//     XPath 3.1 §3.3.1.3 descendant-or-self axis: the context node
//     plus all descendants, in depth-first document order, filtered
//     by `cxpath_node_test_matches`. This is the semantic backing the `//`
// root-form prefix grammar [130].
//   - `pub fn register_forward_axes(mut d AxisDispatcher)` — registers
//     all 3 forward handlers with the supplied dispatcher. Called by
//     `cxpath_eval.v::new_default_axis_dispatcher`.
//
// Document-order invariant:
//
//   "Document order" at Phase 2.6 part 1 means the order produced by
//   a depth-first pre-order traversal of the CxNode tree, following
//   the `children` list left-to-right. Attribute nodes are NOT
// reached by the 3 forward axes — the attribute
//   axis is name-disjoint from element axes and is delivered by
//   Phase 2.6 part 3 (cxpath_attr.v).
//
// Filtering semantics (per `cxpath_node_test_matches` in cxpath_eval.v):
//
//   - `Name`                → kind == .element AND node_name == Name
//   - `*`                   → kind == .element (any element name)
//   - `*:Local`             → kind == .element AND node_name == Local
//                             (namespace-agnostic at Phase 2.6 part 1)
//   - `Prefix:*`            → kind == .element
//                             (namespace-agnostic at Phase 2.6 part 1)
//   - `Prefix:LocalName`    → kind == .element AND node_name == Local
//                             (namespace-agnostic at Phase 2.6 part 1)
//   - `node()`/`text()`/    → match any (Phase 2.6 part 1 stub;
//     `element()`/...           kind-test discrimination lands in Phase 2.x)
//
// Cross-references:
//   - XPath 3.1 §3.3.1 (axis definitions for child / descendant /
//     descendant-or-self)
//   - vcx/code/cxpath_eval.v — dispatcher contract + CxNode type
//   - vcx/cx/path_node.v — PathAxis enum
//
// Strict scope NON-goals at Phase 2.6 part 1 (deferred):
//   - The 9 axes covered by parts 2 + 3 — handled by sibling files.
//   - Kind-test discrimination (`text()` / `element()` / etc.) — the
//     four kind-test spellings parse but match every node.
//   - Namespace-aware matching — `Prefix:*` / `*:Local` / `Prefix:Local`
//     ignore the namespace at Phase 2.6 part 1.

// ── axis_child ───────────────────────────────────────────────────────────────

// axis_child returns the direct children of `ctx` (one tree-edge away)
// that satisfy the node test, in document order. Per XPath 3.1
// §3.3.1.1 the child axis contains only the node's children — it does
// NOT include the node itself.
//
// Attributes are excluded from the child axis — they
// are reachable only via the attribute axis. The CxNode tree honours
// this by never storing attribute-kind nodes in `children`; tests
// that need attribute-name children must use the attribute axis
// (Phase 2.6 part 3).
pub fn axis_child(ctx &CxNode, test NodeTest) []&CxNode {
	mut out := []&CxNode{cap: ctx.children.len}
	for child in ctx.children {
		if cxpath_node_test_matches(child, test) {
			out << child
		}
	}
	return out
}

// ── axis_descendant ──────────────────────────────────────────────────────────

// axis_descendant returns every descendant of `ctx` reachable by
// following the child axis 1+ times, in depth-first document order,
// that satisfies the node test. Per XPath 3.1 §3.3.1.2 the descendant
// axis EXCLUDES the context node itself.
//
// Implementation: depth-first pre-order walk over `ctx.children` and
// their transitive children. Visit order matches XPath document
// order for element / text trees.
pub fn axis_descendant(ctx &CxNode, test NodeTest) []&CxNode {
	mut out := []&CxNode{}
	for child in ctx.children {
		collect_descendants(child, test, mut out)
	}
	return out
}

// collect_descendants is the depth-first pre-order helper that
// `axis_descendant` + `axis_descendant_or_self` both call. Visits
// `n` first (testing + appending on match) then recurses into each
// child in order.
fn collect_descendants(n &CxNode, test NodeTest, mut out []&CxNode) {
	if cxpath_node_test_matches(n, test) {
		out << n
	}
	for c in n.children {
		collect_descendants(c, test, mut out)
	}
}

// ── axis_descendant_or_self ──────────────────────────────────────────────────

// axis_descendant_or_self returns the context node itself plus every
// descendant of `ctx`, in depth-first document order, that satisfies
// the node test. Per XPath 3.1 §3.3.1.3 the descendant-or-self axis
// includes the context node — this is what makes the `//` root-form
// prefix work grammar [130] (`//pattern` lowers to an
// implicit `descendant-or-self::node()` step before the explicit step
// list, which then matches the document root + every descendant).
pub fn axis_descendant_or_self(ctx &CxNode, test NodeTest) []&CxNode {
	mut out := []&CxNode{}
	collect_descendants(ctx, test, mut out)
	return out
}

// ── register_forward_axes ────────────────────────────────────────────────────

// register_forward_axes installs the 3 forward axis handlers
// (child / descendant / descendant-or-self) on the supplied
// dispatcher. Called by `new_default_axis_dispatcher` in
// `cxpath_eval.v` to assemble the Phase 2.6 part 1 default surface.
//
// Sibling Phase 2.6 parts (Z19 reverse axes; Z20 attr + sibling axes)
// add their own `register_*_axes` helpers in their own files and the
// part-3 landing extends `new_default_axis_dispatcher` to call them
// alongside this one.
pub fn register_forward_axes(mut d AxisDispatcher) {
	d.register(cx.PathAxis.child, axis_child)
	d.register(cx.PathAxis.descendant, axis_descendant)
	d.register(cx.PathAxis.descendant_or_self, axis_descendant_or_self)
}
