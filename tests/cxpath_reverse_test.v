module main

import cx
import code

// Tests for the Phase 2.6 part 2 CXPath reverse axes (parent / ancestor /
// ancestor-or-self). See `vcx/code/cxpath_reverse.v` for
// the implementation under test.
//
// Coverage map:
//
//   - axis_parent: positive (parent name matches), miss (parent name
//     does not match), wildcard (parent is any element).
//   - axis_parent: root-node fallback (parent chain is empty → empty
//     result).
//   - axis_ancestor: positive (named ancestor 2 levels up), miss
//     (unknown name), wildcard (lists every ancestor in reverse order).
//   - axis_ancestor_or_self: positive self-match (context's own name),
//     miss, wildcard (context + ancestors in reverse order).
//   - Multi-step composition via `eval_cxpath`: `child::a / parent::root`
//     reaches a then walks back; `descendant::leaf / ancestor::root`
//     covers reverse-step composition after a forward descent.
//   - Dispatcher: `register_reverse_axes` installs all 3 on a fresh
//     dispatcher; combined with `new_default_axis_dispatcher` it covers
//     forward + reverse axes simultaneously.
//
// Tree-construction helpers below build a small 3-level fixture tree:
//
//   <root>
//     <a>
//       <leaf>x</leaf>
//       <leaf>y</leaf>
//     </a>
//     <b>
//       <leaf>z</leaf>
//     </b>
//   </root>
//
// Parents are wired explicitly via `.parent = parent_ref` after each
// `children << child_ref` to keep the back-pointer well-defined
// (matches the cxpath_forward_test.v fixture convention).

// ── Fixture handle ───────────────────────────────────────────────────────────

// TreeRefs carries the named handles for the fixture tree so tests can
// drive axis handlers from any node without re-walking the tree by
// name. Mirrors the build_doc + multi-handle pattern from
// `cxpath_forward_test.v` but exposes deeper interior nodes since
// reverse-axis tests need to start from descendants.
struct TreeRefs {
mut:
	root      &code.CxNode = unsafe { nil }
	a         &code.CxNode = unsafe { nil }
	b         &code.CxNode = unsafe { nil }
	a_leaf1   &code.CxNode = unsafe { nil }
	a_leaf2   &code.CxNode = unsafe { nil }
	b_leaf    &code.CxNode = unsafe { nil }
}

// build_tree constructs the shared fixture tree described above and
// returns a TreeRefs holding every interior handle. Each test calls
// this anew so trees don't leak mutations between tests.
fn build_tree() TreeRefs {
	mut root := code.new_element('root')

	mut a := code.new_element('a')
	mut a_leaf1 := code.new_element('leaf')
	a_leaf1.children << code.new_text('x')
	a_leaf1.parent = a
	mut a_leaf2 := code.new_element('leaf')
	a_leaf2.children << code.new_text('y')
	a_leaf2.parent = a
	a.children << a_leaf1
	a.children << a_leaf2
	a.parent = root

	mut b := code.new_element('b')
	mut b_leaf := code.new_element('leaf')
	b_leaf.children << code.new_text('z')
	b_leaf.parent = b
	b.children << b_leaf
	b.parent = root

	root.children << a
	root.children << b
	return TreeRefs{
		root:    root
		a:       a
		b:       b
		a_leaf1: a_leaf1
		a_leaf2: a_leaf2
		b_leaf:  b_leaf
	}
}

// name_test wraps a bare-name node-test for handler invocation.
fn name_test(name string) code.NodeTest {
	return code.parse_node_test(name, ?string(none))
}

// wildcard_test wraps the `*` wildcard node-test.
fn wildcard_test() code.NodeTest {
	return code.parse_node_test('*', ?string(none))
}

// names extracts the names of every node in a result sequence (empty
// string for text/scalar). Used to assert handler outputs.
fn names(seq []&code.CxNode) []string {
	mut out := []string{cap: seq.len}
	for n in seq {
		out << code.node_name(n)
	}
	return out
}

// ── axis_parent ──────────────────────────────────────────────────────────────

fn test_axis_parent_positive_match() {
	t := build_tree()
	// `a`'s parent is `root` — match against the name `root`.
	out := code.axis_parent(t.a, name_test('root'))
	assert out.len == 1, 'expected 1 parent match, got ${out.len}'
	assert code.node_name(out[0]) == 'root'
}

fn test_axis_parent_miss_wrong_name() {
	t := build_tree()
	// `a`'s parent is `root`, not `a`.
	out := code.axis_parent(t.a, name_test('a'))
	assert out.len == 0
}

fn test_axis_parent_wildcard_matches_any_element_parent() {
	t := build_tree()
	out := code.axis_parent(t.a_leaf1, wildcard_test())
	assert out.len == 1
	assert code.node_name(out[0]) == 'a'
}

fn test_axis_parent_root_node_returns_empty() {
	t := build_tree()
	// root has no parent → empty sequence even with wildcard.
	out := code.axis_parent(t.root, wildcard_test())
	assert out.len == 0
}

// ── axis_ancestor ────────────────────────────────────────────────────────────

fn test_axis_ancestor_positive_two_levels_up() {
	t := build_tree()
	// `a_leaf1`'s ancestors are `a`, then `root` (reverse doc order).
	// Match against `root` — must find exactly one.
	out := code.axis_ancestor(t.a_leaf1, name_test('root'))
	assert out.len == 1
	assert code.node_name(out[0]) == 'root'
}

fn test_axis_ancestor_miss_unknown_name() {
	t := build_tree()
	out := code.axis_ancestor(t.a_leaf1, name_test('nonexistent'))
	assert out.len == 0
}

fn test_axis_ancestor_wildcard_reverse_document_order() {
	t := build_tree()
	// `a_leaf1` ancestors via wildcard: `a` first (closest), then `root`
	// last (document root). Reverse document order per XPath 3.1 §3.2.4.
	out := code.axis_ancestor(t.a_leaf1, wildcard_test())
	assert out.len == 2, 'expected 2 ancestors, got ${out.len}'
	assert names(out) == ['a', 'root'], 'expected reverse-order [a, root], got ${names(out)}'
}

fn test_axis_ancestor_excludes_context_node() {
	t := build_tree()
	// `ancestor` axis excludes the context node itself per XPath 3.1
	// §3.3.1.5. An `a` node-test from `a` via the ancestor axis must
	// miss.
	out := code.axis_ancestor(t.a, name_test('a'))
	assert out.len == 0
}

fn test_axis_ancestor_root_node_returns_empty() {
	t := build_tree()
	// root has no parent → no ancestors.
	out := code.axis_ancestor(t.root, wildcard_test())
	assert out.len == 0
}

// ── axis_ancestor_or_self ────────────────────────────────────────────────────

fn test_axis_ancestor_or_self_includes_context() {
	t := build_tree()
	// Per XPath 3.1 §3.3.1.6 ancestor-or-self INCLUDES the context node.
	// `a`'s ancestor-or-self with name-test `a` matches the context
	// itself.
	out := code.axis_ancestor_or_self(t.a, name_test('a'))
	assert out.len == 1
	assert code.node_name(out[0]) == 'a'
}

fn test_axis_ancestor_or_self_miss() {
	t := build_tree()
	out := code.axis_ancestor_or_self(t.a_leaf1, name_test('absent'))
	assert out.len == 0
}

fn test_axis_ancestor_or_self_wildcard_reverse_order_with_self() {
	t := build_tree()
	// From `a_leaf1` with wildcard: self (`leaf`) first, then `a`
	// (closest ancestor), then `root` (document root last). Reverse
	// document order per §3.2.4 with self leading.
	out := code.axis_ancestor_or_self(t.a_leaf1, wildcard_test())
	assert out.len == 3, 'expected 3 results, got ${out.len}'
	assert names(out) == ['leaf', 'a', 'root'], 'expected [leaf, a, root], got ${names(out)}'
}

fn test_axis_ancestor_or_self_root_returns_only_self() {
	t := build_tree()
	// From the document root, ancestor-or-self with wildcard returns
	// just the root itself (no ancestors).
	out := code.axis_ancestor_or_self(t.root, wildcard_test())
	assert out.len == 1
	assert code.node_name(out[0]) == 'root'
}

// ── Multi-step paths via eval_cxpath ─────────────────────────────────────────

fn test_eval_cxpath_child_a_then_parent_root() {
	// `child::a / parent::root` — descend to `a`, then walk back to
	// `root`. End-to-end forward + reverse composition.
	t := build_tree()
	mut d := code.new_default_axis_dispatcher()
	code.register_reverse_axes(mut d)

	a_step := cx.new_path_step(cx.PathAxis.child, 'a')
	root_step := cx.new_path_step(cx.PathAxis.parent, 'root')
	pn := cx.new_path_node(.relative, [a_step, root_step])

	out := code.eval_cxpath(pn, [t.root], d) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert out.len == 1
	assert code.node_name(out[0]) == 'root'
}

fn test_eval_cxpath_descendant_leaf_then_ancestor_root() {
	// `//leaf / ancestor::root` — every leaf descends from the doc
	// root; the ancestor axis walks back to `root` from each leaf.
	// After dedup-by-pointer-identity (XPath 3.1 §3.2.1) the result
	// is exactly `[root]` even though three leaves contributed.
	t := build_tree()
	mut d := code.new_default_axis_dispatcher()
	code.register_reverse_axes(mut d)

	leaf_step := cx.new_path_step(cx.PathAxis.descendant_or_self, 'leaf')
	anc_root_step := cx.new_path_step(cx.PathAxis.ancestor, 'root')
	pn := cx.new_path_node(.relative, [leaf_step, anc_root_step])

	out := code.eval_cxpath(pn, [t.root], d) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert out.len == 1, 'expected 1 root (deduped), got ${out.len}'
	assert code.node_name(out[0]) == 'root'
}

// ── Dispatcher ───────────────────────────────────────────────────────────────

fn test_register_reverse_axes_installs_3_axes() {
	mut d := code.new_axis_dispatcher()
	code.register_reverse_axes(mut d)
	assert d.has_axis(cx.PathAxis.parent)
	assert d.has_axis(cx.PathAxis.ancestor)
	assert d.has_axis(cx.PathAxis.ancestor_or_self)
}

fn test_register_reverse_axes_composes_with_default_dispatcher() {
	// After the Phase 2.6 part-3 follow-up wired register_reverse_axes
	// + register_misc_axes into new_default_axis_dispatcher, the
	// default dispatcher already carries all 12 axes; an extra
	// register_reverse_axes call is a no-op (idempotent map writes
	// replace the same handlers under the same axis keys).
	mut d := code.new_default_axis_dispatcher()
	code.register_reverse_axes(mut d)
	assert d.has_axis(cx.PathAxis.child)
	assert d.has_axis(cx.PathAxis.descendant)
	assert d.has_axis(cx.PathAxis.descendant_or_self)
	assert d.has_axis(cx.PathAxis.parent)
	assert d.has_axis(cx.PathAxis.ancestor)
	assert d.has_axis(cx.PathAxis.ancestor_or_self)
	// Part 3 misc axes also come in via the default dispatcher now.
	assert d.has_axis(cx.PathAxis.attribute)
	assert d.has_axis(cx.PathAxis.following_sibling)
}
