module code

import cx

// cxpath_reverse.v — Phase 2.6 PART 2 of 3: the 3 reverse CXPath axes
// per (parent / ancestor / ancestor-or-self).
//
// What this file provides:
//
//   - `pub fn axis_parent(ctx &CxNode, test NodeTest) []&CxNode` —
//     XPath 3.1 §3.3.1.4 parent axis: the immediate parent of the
//     context node (or empty if the context node is the document root),
//     filtered by `cxpath_node_test_matches`. The result is at most one
//     node — order-trivial.
//   - `pub fn axis_ancestor(ctx &CxNode, test NodeTest) []&CxNode` —
//     XPath 3.1 §3.3.1.5 ancestor axis: every node reachable by
//     following the `parent` back-pointer 1+ times from the context
//     node, filtered by `cxpath_node_test_matches`. EXCLUDES the
//     context node itself. Yields in REVERSE document order per
//     XPath 3.1 §3.2.4 (the closest ancestor first, document root last).
//   - `pub fn axis_ancestor_or_self(ctx &CxNode, test NodeTest) []&CxNode` —
//     XPath 3.1 §3.3.1.6 ancestor-or-self axis: the context node plus
//     every ancestor, filtered by `cxpath_node_test_matches`. Yields in
//     REVERSE document order (context node first, then closest ancestor,
//     …, then document root last).
//   - `pub fn register_reverse_axes(mut d AxisDispatcher)` — registers
//     all 3 reverse handlers with the supplied dispatcher. Sibling-file
//     registration helper following the same pattern as
//     `register_forward_axes` (cxpath_forward.v). Phase 2.6 part 3
//     (Z20) extends `new_default_axis_dispatcher` in cxpath_eval.v to
//     call this alongside `register_forward_axes`; callers that want
//     the reverse axes before the part-3 landing can invoke this helper
//     directly on a dispatcher returned from `new_default_axis_dispatcher`.
//
// Reverse-document-order invariant:
//
//   Reverse axes per XPath 3.1 §3.2.4 yield their result sequence in
//   REVERSE document order. For ancestor / ancestor-or-self this means
//   the closest ancestor (parent) appears first; the document root
//   appears last. `axis_parent` returns at most one node so the order
//   discussion is moot.
//
//   Do NOT accidentally yield forward order. The natural traversal
//   (walk `.parent` chain upward, appending as you go) already
//   produces reverse document order — append-as-you-walk is the
//   correct shape. `axis_ancestor_or_self` prepends the context node
//   (still first in reverse document order) before the walk.
//
// Filtering semantics (per `cxpath_node_test_matches` in cxpath_eval.v):
//
//   - `Name`                → kind == .element AND node_name == Name
//   - `*`                   → kind == .element (any element name)
//   - `*:Local`             → kind == .element AND node_name == Local
//                             (namespace-agnostic at Phase 2.6 part 2)
//   - `Prefix:*`            → kind == .element
//                             (namespace-agnostic at Phase 2.6 part 2)
//   - `Prefix:LocalName`    → kind == .element AND node_name == Local
//                             (namespace-agnostic at Phase 2.6 part 2)
//   - `node()`/`text()`/    → match any (Phase 2.6 part 2 stub;
//     `element()`/...           kind-test discrimination lands in Phase 2.x)
//
// Cross-references:
//   - XPath 3.1 §3.3.1.4 / §3.3.1.5 / §3.3.1.6 (axis definitions for
//     parent / ancestor / ancestor-or-self)
//   - XPath 3.1 §3.2.4 (reverse-axis document-order rule)
//   - vcx/code/cxpath_eval.v — dispatcher contract + CxNode type +
//     parent back-pointer field
//   - vcx/code/cxpath_forward.v — the sibling part-1 helper this file
//     mirrors structurally (`register_*_axes` shape)
//   - vcx/cx/path_node.v — PathAxis enum
//
// Strict scope NON-goals at Phase 2.6 part 2 (deferred):
//   - `self` axis — listed in part-1's deferred section as a part-2
//     scope item but reassigned to part 3 (Z20) per the active brief.
//     Part 2 is the 3-axis cut: parent / ancestor / ancestor-or-self.
//   - The 5 axes covered by part 3 — handled by sibling files.
//   - Kind-test discrimination (`text()` / `element()` / etc.) — the
//     four kind-test spellings parse but match every node.
//   - Namespace-aware matching — `Prefix:*` / `*:Local` / `Prefix:Local`
//     ignore the namespace at Phase 2.6 part 2.

// ── axis_parent ──────────────────────────────────────────────────────────────

// axis_parent returns the immediate parent of `ctx` (one tree-edge
// up the parent chain) filtered by the node test. Per XPath 3.1
// §3.3.1.4 the parent axis contains at most one node — the parent
// element of the context node, or the empty sequence when the context
// node is the document root (no parent).
//
// The CxNode `parent` field is the option-pointer back-link populated
// by the test-side tree-construction helpers (test fixture builders
// in `vcx/tests/v08_cxpath_*_test.v` wire `.parent = parent_ref` after
// `children << child_ref`). The Phase 2.x graft replaces this with the
// production Document-AST's structural-sharing parent walker.
pub fn axis_parent(ctx &CxNode, test NodeTest) []&CxNode {
	parent := ctx.parent or { return []&CxNode{} }
	if cxpath_node_test_matches(parent, test) {
		return [parent]
	}
	return []&CxNode{}
}

// ── axis_ancestor ────────────────────────────────────────────────────────────

// axis_ancestor returns every ancestor of `ctx` reachable by walking
// the `.parent` chain 1+ times, filtered by the node test. Per
// XPath 3.1 §3.3.1.5 the ancestor axis EXCLUDES the context node
// itself.
//
// Order: REVERSE document order per XPath 3.1 §3.2.4 — the closest
// ancestor (parent) appears first; the document root appears last.
// Append-as-you-walk is the correct shape since we walk root-ward from
// the context node, hitting the closest ancestor first.
pub fn axis_ancestor(ctx &CxNode, test NodeTest) []&CxNode {
	mut out := []&CxNode{}
	mut cursor := ctx.parent or { return out }
	for {
		if cxpath_node_test_matches(cursor, test) {
			out << cursor
		}
		cursor = cursor.parent or { break }
	}
	return out
}

// ── axis_ancestor_or_self ────────────────────────────────────────────────────

// axis_ancestor_or_self returns the context node itself plus every
// ancestor of `ctx`, filtered by the node test. Per XPath 3.1
// §3.3.1.6 the ancestor-or-self axis includes the context node.
//
// Order: REVERSE document order per XPath 3.1 §3.2.4 — the context
// node comes first (its own position in document order is later than
// every ancestor, so it leads in reverse order), then the closest
// ancestor (parent), …, then the document root last.
pub fn axis_ancestor_or_self(ctx &CxNode, test NodeTest) []&CxNode {
	mut out := []&CxNode{}
	if cxpath_node_test_matches(ctx, test) {
		out << ctx
	}
	mut cursor := ctx.parent or { return out }
	for {
		if cxpath_node_test_matches(cursor, test) {
			out << cursor
		}
		cursor = cursor.parent or { break }
	}
	return out
}

// ── register_reverse_axes ────────────────────────────────────────────────────

// register_reverse_axes installs the 3 reverse axis handlers
// (parent / ancestor / ancestor-or-self) on the supplied dispatcher.
// Mirrors the `register_forward_axes` shape in cxpath_forward.v.
//
// Sibling Phase 2.6 part 3 (Z20 — attr + sibling + `self` axes) adds
// its own `register_*_axes` helper in its own file; the part-3 landing
// extends `new_default_axis_dispatcher` in cxpath_eval.v to call this
// helper + the part-3 helper alongside `register_forward_axes`.
// Until that landing, callers that want the reverse axes available on
// a default dispatcher invoke this helper directly:
//
//   mut d := code.new_default_axis_dispatcher()
//   code.register_reverse_axes(mut d)
//
// after which `d.has_axis(cx.PathAxis.parent)` etc. return true.
pub fn register_reverse_axes(mut d AxisDispatcher) {
	d.register(cx.PathAxis.parent, axis_parent)
	d.register(cx.PathAxis.ancestor, axis_ancestor)
	d.register(cx.PathAxis.ancestor_or_self, axis_ancestor_or_self)
}
