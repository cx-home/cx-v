module code

import cx

// cxpath_misc.v — Phase 2.6 PART 3 of 3: the 6 remaining CXPath axes per
// (self / attribute / following-sibling / preceding-sibling
// following / preceding).
//
// This file complements `cxpath_forward.v` (part 1 — child / descendant /
// descendant-or-self) and `cxpath_reverse.v` (part 2 — parent / ancestor /
// ancestor-or-self; sibling agent Z19 landing). Together the three files
// implement the full 12-axis surface for the Phase 2.6 axis walker
// dispatched from `cxpath_eval.v::eval_cxpath`.
//
// What this file provides:
//
//   - `pub fn axis_self(ctx &CxNode, test NodeTest) []&CxNode` —
//     XPath 3.1 §3.3.1.5: singleton sequence containing `ctx` iff the
//     node-test matches, else empty.
//   - `pub fn axis_attribute(ctx &CxNode, test NodeTest) []&CxNode` —
//     XPath 3.1 §3.3.2: attributes of `ctx`. The CxNode stand-in stores
//     element attributes in `attrs map[string]string`; this handler
//     materialises each entry into a fresh attribute-kind CxNode per
// (name-disjoint from element axes). Order of
//     materialisation follows V's `map[string]string` iteration order
//     (insertion order for V's built-in map); XPath spec leaves
//     attribute order implementation-defined.
//   - `pub fn axis_following_sibling(ctx &CxNode, test NodeTest) []&CxNode` —
//     XPath 3.1 §3.3.1.7: siblings appearing AFTER `ctx` in the parent's
//     child list, in forward document order. Returns empty when `ctx`
//     has no parent (e.g. the document root).
//   - `pub fn axis_preceding_sibling(ctx &CxNode, test NodeTest) []&CxNode` —
//     XPath 3.1 §3.3.1.8: siblings appearing BEFORE `ctx` in the
//     parent's child list, in REVERSE document order (closest sibling
//     first). Returns empty when `ctx` has no parent.
//   - `pub fn axis_following(ctx &CxNode, test NodeTest) []&CxNode` —
//     XPath 3.1 §3.3.1.9: every node appearing AFTER `ctx` in document
//     order, EXCLUDING `ctx`'s descendants. Implemented by climbing the
//     parent chain and, at each level, collecting the forward-siblings
//     and their full subtrees in pre-order. Forward document order.
//   - `pub fn axis_preceding(ctx &CxNode, test NodeTest) []&CxNode` —
//     XPath 3.1 §3.3.1.10: every node appearing BEFORE `ctx` in document
//     order, EXCLUDING `ctx`'s ancestors. Implemented by climbing the
//     parent chain and, at each level, collecting the backward-siblings
//     and their full subtrees in REVERSE pre-order. Reverse document
//     order overall (closest preceding node first).
//   - `pub fn register_misc_axes(mut d AxisDispatcher)` — registers the
//     6 handlers above on the supplied dispatcher. Mirrors the
//     `register_forward_axes(mut d)` pattern from cxpath_forward.v.
//
// Cross-references:
//   - XPath 3.1 §3.3 axis definitions, especially §3.3.1.9 (following) +
//     §3.3.1.10 (preceding) which define "excluding descendants" and
//     "excluding ancestors" as the structural carve-outs distinguishing
//     these axes from raw document-order traversal.
//   - vcx/code/cxpath_eval.v — dispatcher contract + CxNode + NodeTest
//   - vcx/code/cxpath_forward.v — sibling part 1 (forward axes)
//
// Strict scope NON-goals at Phase 2.6 part 3 (same as parts 1 + 2):
//   - Document-AST integration — CxNode is the part-1 stand-in.
//   - Predicate evaluation per step — Phase 2.21 graft.
//   - Kind-test discrimination (`text()` / `element()` / etc.) —
//     `cxpath_node_test_matches` Phase 2.6 part 1 stub still applies.
//   - Namespace-aware QName matching — same caveat as parts 1 + 2.

// ── axis_self ────────────────────────────────────────────────────────────────

// axis_self returns `[ctx]` iff the node-test matches `ctx`, else `[]`.
// Per XPath 3.1 §3.3.1.5 the self axis contains exactly the context
// node. Most commonly used as the lowering of the `.` step abbreviation.
pub fn axis_self(ctx &CxNode, test NodeTest) []&CxNode {
	if cxpath_node_test_matches(ctx, test) {
		return [ctx]
	}
	return []&CxNode{}
}

// ── axis_attribute ───────────────────────────────────────────────────────────

// axis_attribute returns the attributes of `ctx` matching the node-test.
// Per the attribute axis is name-disjoint from element
// axes: attribute-axis steps select attribute-kind nodes only, never
// same-name child elements.
//
// CxNode stores element attributes in `attrs map[string]string`. The
// handler materialises each entry into a fresh `new_attribute(name,
// value)` CxNode and applies the node-test against it. The materialised
// nodes do NOT have their `parent` backpointer set — attribute-kind
// nodes are leaves with respect to subsequent axis traversal, and the
// attribute axis itself is the only way to reach them.
//
// The wildcard `*` does NOT match attributes per
// `cxpath_node_test_matches` (which gates wildcard on `kind == .element`).
// Attribute-axis wildcards use the `attribute::*` source syntax which
// parses as a NodeTest with `.wildcard` kind but flows through the
// attribute axis — to keep wildcard usable here at part 3, the handler
// short-circuits the wildcard test as "match any attribute" since the
// element-vs-attribute kind discrimination is delivered by the axis
// itself.
//
// Bare-name tests match the attribute whose name equals the test name;
// kind-tests (`attribute()` / `node()`) match every attribute.
pub fn axis_attribute(ctx &CxNode, test NodeTest) []&CxNode {
	mut out := []&CxNode{cap: ctx.attrs.len}
	for name, value in ctx.attrs {
		attr_node := new_attribute(name, value)
		if axis_attribute_node_matches(attr_node, test) {
			out << attr_node
		}
	}
	return out
}

// axis_attribute_node_matches is the attribute-axis variant of
// `cxpath_node_test_matches`. Per the attribute axis
// carries its own name-disjoint kind discrimination — the wildcard `*`
// at this axis means "any attribute" (not "any element"), and kind-tests
// `attribute()` / `node()` match every attribute. Bare names match the
// attribute whose name equals the test name.
fn axis_attribute_node_matches(attr_node &CxNode, test NodeTest) bool {
	match test.kind {
		.wildcard {
			// At the attribute axis `*` is "any attribute"
			// D13 — the axis itself supplies the kind discrimination.
			return attr_node.kind == .attribute
		}
		.kind_test {
			// `attribute()` / `node()` — match every attribute. The
			// part-1 stub doesn't yet split kind-test sources, so this
			// is consistent with the element-axis stub behaviour.
			return true
		}
		.name {
			want := test.name or { return false }
			return node_name(attr_node) == want
		}
		.ns_wildcard_name {
			// `*:LocalName` — namespace-agnostic at Phase 2.6.
			want := test.name or { return false }
			return node_name(attr_node) == want
		}
		.prefix_wildcard {
			// `Prefix:*` — namespace-agnostic at Phase 2.6 — any attr.
			return attr_node.kind == .attribute
		}
		.qname {
			// `Prefix:LocalName` — Phase 2.6 honours local name only.
			want := test.name or { return false }
			return node_name(attr_node) == want
		}
	}
}

// ── axis_following_sibling ───────────────────────────────────────────────────

// axis_following_sibling returns the siblings of `ctx` that appear
// AFTER `ctx` in the parent's child list, in forward document order,
// filtered by the node-test. Per XPath 3.1 §3.3.1.7. Returns `[]` when
// `ctx` has no parent.
pub fn axis_following_sibling(ctx &CxNode, test NodeTest) []&CxNode {
	parent := ctx.parent or { return []&CxNode{} }
	mut out := []&CxNode{}
	mut saw_ctx := false
	for sib in parent.children {
		if saw_ctx {
			if cxpath_node_test_matches(sib, test) {
				out << sib
			}
		} else if voidptr(sib) == voidptr(ctx) {
			saw_ctx = true
		}
	}
	return out
}

// ── axis_preceding_sibling ───────────────────────────────────────────────────

// axis_preceding_sibling returns the siblings of `ctx` that appear
// BEFORE `ctx` in the parent's child list, in REVERSE document order
// (closest preceding sibling first), filtered by the node-test. Per
// XPath 3.1 §3.3.1.8 reverse-axis ordering. Returns `[]` when `ctx`
// has no parent.
pub fn axis_preceding_sibling(ctx &CxNode, test NodeTest) []&CxNode {
	parent := ctx.parent or { return []&CxNode{} }
	mut forward := []&CxNode{}
	for sib in parent.children {
		if voidptr(sib) == voidptr(ctx) {
			break
		}
		if cxpath_node_test_matches(sib, test) {
			forward << sib
		}
	}
	// Reverse for XPath 3.1 reverse-axis order.
	mut out := []&CxNode{cap: forward.len}
	for i := forward.len - 1; i >= 0; i-- {
		out << forward[i]
	}
	return out
}

// ── axis_following ───────────────────────────────────────────────────────────

// axis_following returns every node appearing AFTER `ctx` in document
// order that is NOT a descendant of `ctx`, filtered by the node-test.
// Per XPath 3.1 §3.3.1.9.
//
// Algorithm: climb the parent chain from `ctx`. At each level, enumerate
// the parent's children that appear AFTER the current frame's anchor
// (initially `ctx`, then the previous ancestor). For each such sibling,
// emit the sibling itself (if it matches) followed by every descendant
// in depth-first pre-order (if it matches). The full forward subtree
// of each forward-sibling is reached before moving up to the next
// ancestor level; this matches XPath document order because document
// order on the tree is "pre-order of the depth-first walk", and the
// "following" axis is precisely the suffix of that walk starting from
// the node just past `ctx`'s subtree.
pub fn axis_following(ctx &CxNode, test NodeTest) []&CxNode {
	mut out := []&CxNode{}
	mut anchor := ctx
	for {
		parent := anchor.parent or { break }
		mut saw_anchor := false
		for sib in parent.children {
			if saw_anchor {
				// Emit sib + sib's full pre-order subtree.
				collect_descendants(sib, test, mut out)
			} else if voidptr(sib) == voidptr(anchor) {
				saw_anchor = true
			}
		}
		anchor = parent
	}
	return out
}

// ── axis_preceding ───────────────────────────────────────────────────────────

// axis_preceding returns every node appearing BEFORE `ctx` in document
// order that is NOT an ancestor of `ctx`, filtered by the node-test, in
// REVERSE document order (closest preceding node first). Per XPath 3.1
// §3.3.1.10.
//
// Algorithm: climb the parent chain from `ctx`. At each level, enumerate
// the parent's children that appear BEFORE the current frame's anchor
// (initially `ctx`, then the previous ancestor), in REVERSE order. For
// each such sibling, emit the sibling's subtree in REVERSE pre-order
// (i.e. for each subtree, emit in pre-order then reverse the resulting
// slice — equivalent to producing the closest-first reading of the
// subtree). The reverse-axis ordering rule of XPath 3.1 means the
// closest preceding node (sibling immediately before `ctx`, or its
// deepest last descendant) comes first.
//
// Document-order vs reverse-order subtlety: the "preceding" axis as a
// SET is well-defined; XPath 3.1 §3.3 specifies that reverse axes are
// produced in REVERSE document order. The implementation here builds
// per-level slices and concatenates outermost-frame-last; within each
// frame, sibling subtrees are reverse-pre-order'd. The net effect is
// that the first emitted node is the immediately-preceding node in
// document order, and the last is the document's first node (excluding
// ancestors of `ctx`).
pub fn axis_preceding(ctx &CxNode, test NodeTest) []&CxNode {
	mut out := []&CxNode{}
	mut anchor := ctx
	for {
		parent := anchor.parent or { break }
		// Collect the preceding-sibling subtrees at this level, in
		// reverse document order.
		mut forward_sibs := []&CxNode{}
		for sib in parent.children {
			if voidptr(sib) == voidptr(anchor) {
				break
			}
			forward_sibs << sib
		}
		// Walk preceding siblings from CLOSEST to FARTHEST (reverse of
		// child-list order). For each, build the subtree pre-order then
		// reverse it so the deepest-last node comes first — this gives
		// XPath 3.1 reverse document order within the frame.
		for i := forward_sibs.len - 1; i >= 0; i-- {
			sib := forward_sibs[i]
			mut subtree := []&CxNode{}
			collect_descendants(sib, test, mut subtree)
			for j := subtree.len - 1; j >= 0; j-- {
				out << subtree[j]
			}
		}
		anchor = parent
	}
	return out
}

// ── register_misc_axes ───────────────────────────────────────────────────────

// register_misc_axes installs the 6 part-3 axis handlers on the
// supplied dispatcher: self / attribute / following-sibling /
// preceding-sibling / following / preceding. Mirrors the
// `register_forward_axes` pattern from cxpath_forward.v.
//
// Sibling part-2 file `cxpath_reverse.v` (agent Z19) is expected to
// expose a `register_reverse_axes(mut d)` helper covering parent /
// ancestor / ancestor-or-self. When all three helpers are wired into
// `new_default_axis_dispatcher` (in cxpath_eval.v) the dispatcher has
// the full 12-axis surface.
pub fn register_misc_axes(mut d AxisDispatcher) {
	d.register(cx.PathAxis.self_, axis_self)
	d.register(cx.PathAxis.attribute, axis_attribute)
	d.register(cx.PathAxis.following_sibling, axis_following_sibling)
	d.register(cx.PathAxis.preceding_sibling, axis_preceding_sibling)
	d.register(cx.PathAxis.following, axis_following)
	d.register(cx.PathAxis.preceding, axis_preceding)
}
