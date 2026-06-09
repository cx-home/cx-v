module main

import cx
import code

// Tests for the Phase 2.6 part-3 follow-up landing: wiring
// `register_reverse_axes` + `register_misc_axes` into
// `new_default_axis_dispatcher` so the constructor exposes the full
// 12-axis surface in a single call. See
// `vcx/code/cxpath_eval.v::new_default_axis_dispatcher` for the
// implementation under test.
//
// Coverage map:
//
//   - test_default_dispatcher_has_all_12_axes: dispatcher introspection
// across every axis name (the 3 forward + 3 reverse
//     6 misc axes).
//   - test_default_dispatcher_eval_reverse_path: end-to-end
//     `eval_cxpath` against the default dispatcher with a reverse-axis
//     step (parent::root) — the axis must resolve through the default
//     surface without an explicit `register_reverse_axes(mut d)` call.
//   - test_default_dispatcher_eval_attribute_axis: end-to-end
//     `eval_cxpath` against the default dispatcher with an attribute-
//     axis step (`@id`-shaped path) — the axis must resolve through the
//     default surface without an explicit `register_misc_axes(mut d)`
//     call.
//
// Fixture tree (mirrors the build_tree shapes from sibling cxpath
// tests but stays local to this file to keep the test compilation unit
// self-contained):
//
//   <root id="r1">
//     <child>leaf</child>
//   </root>

// build_doc constructs the fixture tree and returns the root + child
// handles so reverse-axis tests can start from the child and walk
// back up.
struct Fixture {
mut:
	root  &code.CxNode = unsafe { nil }
	child &code.CxNode = unsafe { nil }
}

fn build_doc() Fixture {
	mut root := code.new_element_with_attrs('root', {
		'id': 'r1'
	})
	mut child := code.new_element('child')
	child.children << code.new_text('leaf')
	child.parent = root
	root.children << child
	return Fixture{
		root:  root
		child: child
	}
}

// ── test_default_dispatcher_has_all_12_axes ──────────────────────────────────

fn test_default_dispatcher_has_all_12_axes() {
	d := code.new_default_axis_dispatcher()
	// 3 forward axes (cxpath_forward.v).
	assert d.has_axis(cx.PathAxis.child)
	assert d.has_axis(cx.PathAxis.descendant)
	assert d.has_axis(cx.PathAxis.descendant_or_self)
	// 3 reverse axes (cxpath_reverse.v).
	assert d.has_axis(cx.PathAxis.parent)
	assert d.has_axis(cx.PathAxis.ancestor)
	assert d.has_axis(cx.PathAxis.ancestor_or_self)
	// 6 misc axes (cxpath_misc.v).
	assert d.has_axis(cx.PathAxis.self_)
	assert d.has_axis(cx.PathAxis.attribute)
	assert d.has_axis(cx.PathAxis.following_sibling)
	assert d.has_axis(cx.PathAxis.preceding_sibling)
	assert d.has_axis(cx.PathAxis.following)
	assert d.has_axis(cx.PathAxis.preceding)
}

// ── test_default_dispatcher_eval_reverse_path ────────────────────────────────

fn test_default_dispatcher_eval_reverse_path() {
	// `/root/child/parent::root` — descend from root → child via two
	// child:: steps, then walk back via parent::root. End-to-end check
	// that the default dispatcher resolves a reverse-axis step without
	// any per-caller register_reverse_axes composition.
	mut f := build_doc()
	d := code.new_default_axis_dispatcher()

	root_step := cx.new_path_step(cx.PathAxis.child, 'root')
	child_step := cx.new_path_step(cx.PathAxis.child, 'child')
	parent_step := cx.new_path_step(cx.PathAxis.parent, 'root')
	pn := cx.new_path_node(.relative, [root_step, child_step, parent_step])

	// Context sequence: the fixture's outer scope (a synthetic parent
	// sequence containing `root` as its sole element-child).
	mut outer := code.new_element('doc')
	outer.children << f.root
	f.root.parent = outer

	out := code.eval_cxpath(pn, [&code.CxNode(outer)], d) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert out.len == 1, 'expected 1 root node, got ${out.len}'
	assert code.node_name(out[0]) == 'root'
}

// ── test_default_dispatcher_eval_attribute_axis ──────────────────────────────

fn test_default_dispatcher_eval_attribute_axis() {
	// `/root/@id` — child::root then attribute::id. End-to-end check
	// that the default dispatcher resolves an attribute-axis step
	// without any per-caller register_misc_axes composition.
	mut f := build_doc()
	d := code.new_default_axis_dispatcher()

	// Synthetic outer scope so child::root reaches `f.root`.
	mut outer := code.new_element('doc')
	outer.children << f.root
	f.root.parent = outer

	root_step := cx.new_path_step(cx.PathAxis.child, 'root')
	id_step := cx.new_path_step(cx.PathAxis.attribute, 'id')
	pn := cx.new_path_node(.relative, [root_step, id_step])

	out := code.eval_cxpath(pn, [&code.CxNode(outer)], d) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert out.len == 1, 'expected 1 attribute node, got ${out.len}'
	assert out[0].kind == .attribute, 'expected attribute-kind node'
	assert code.node_name(out[0]) == 'id'
}
