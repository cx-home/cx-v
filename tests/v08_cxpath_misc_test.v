module main

import cx
import code

// Tests for the Phase 2.6 part 3 CXPath axis handlers — the 6 remaining
// axes (self / attribute / following-sibling
// preceding-sibling / following / preceding). See
// `vcx/code/cxpath_misc.v` for the implementation under test.
//
// Fixture tree (3 levels, siblings + attributes):
//
//   <doc id="root">
//     <user role="admin" id="u1">
//       <name>Alice</name>
//       <email>alice@example.com</email>
//     </user>
//     <user role="member" id="u2">
//       <name>Bob</name>
//     </user>
//     <post status="draft">
//       <title>Hello</title>
//     </post>
//   </doc>

// ── Tree-construction helpers ────────────────────────────────────────────────

// Globals shared across tests so we can hand parent-attached pointers
// out to per-axis assertions. Each test reconstructs via `build_doc()`
// so trees don't leak mutations between cases.

struct Tree {
mut:
	doc      &code.CxNode
	u1       &code.CxNode
	u2       &code.CxNode
	post     &code.CxNode
	u1_name  &code.CxNode
	u1_email &code.CxNode
	u2_name  &code.CxNode
	p_title  &code.CxNode
}

fn build_tree() Tree {
	mut doc := code.new_element_with_attrs('doc', {
		'id': 'root'
	})

	mut u1 := code.new_element_with_attrs('user', {
		'role': 'admin'
		'id':   'u1'
	})
	mut u1_name := code.new_element('name')
	u1_name.children << code.new_text('Alice')
	u1_name.parent = u1
	mut u1_email := code.new_element('email')
	u1_email.children << code.new_text('alice@example.com')
	u1_email.parent = u1
	u1.children << u1_name
	u1.children << u1_email
	u1.parent = doc

	mut u2 := code.new_element_with_attrs('user', {
		'role': 'member'
		'id':   'u2'
	})
	mut u2_name := code.new_element('name')
	u2_name.children << code.new_text('Bob')
	u2_name.parent = u2
	u2.children << u2_name
	u2.parent = doc

	mut p := code.new_element_with_attrs('post', {
		'status': 'draft'
	})
	mut p_title := code.new_element('title')
	p_title.children << code.new_text('Hello')
	p_title.parent = p
	p.children << p_title
	p.parent = doc

	doc.children << u1
	doc.children << u2
	doc.children << p

	return Tree{
		doc:      doc
		u1:       u1
		u2:       u2
		post:     p
		u1_name:  u1_name
		u1_email: u1_email
		u2_name:  u2_name
		p_title:  p_title
	}
}

fn name_test(name string) code.NodeTest {
	return code.parse_node_test(name, ?string(none))
}

fn wildcard_test() code.NodeTest {
	return code.parse_node_test('*', ?string(none))
}

fn names_of(seq []&code.CxNode) []string {
	mut out := []string{cap: seq.len}
	for n in seq {
		out << code.node_name(n)
	}
	return out
}

// ── axis_self ────────────────────────────────────────────────────────────────

fn test_axis_self_positive_match() {
	t := build_tree()
	out := code.axis_self(t.u1, name_test('user'))
	assert out.len == 1, 'expected 1 self, got ${out.len}'
	assert code.node_name(out[0]) == 'user'
}

fn test_axis_self_miss() {
	t := build_tree()
	out := code.axis_self(t.u1, name_test('post'))
	assert out.len == 0
}

fn test_axis_self_wildcard_matches_element() {
	t := build_tree()
	out := code.axis_self(t.doc, wildcard_test())
	assert out.len == 1
	assert code.node_name(out[0]) == 'doc'
}

// ── axis_attribute ───────────────────────────────────────────────────────────

fn test_axis_attribute_named_hit() {
	t := build_tree()
	out := code.axis_attribute(t.u1, name_test('role'))
	assert out.len == 1, 'expected 1 attr `role`, got ${out.len}'
	assert code.node_name(out[0]) == 'role'
	assert (out[0].value or { '' }) == 'admin'
}

fn test_axis_attribute_named_miss() {
	t := build_tree()
	out := code.axis_attribute(t.u1, name_test('absent'))
	assert out.len == 0
}

fn test_axis_attribute_wildcard_returns_all_attrs() {
	t := build_tree()
	out := code.axis_attribute(t.u1, wildcard_test())
	// u1 has role + id = 2 attrs.
	assert out.len == 2, 'expected 2 attrs on u1, got ${out.len}'
}

fn test_axis_attribute_returns_attribute_kind_nodes() {
	t := build_tree()
	out := code.axis_attribute(t.doc, name_test('id'))
	assert out.len == 1
	assert out[0].kind == .attribute, 'expected attribute-kind node'
}

fn test_axis_attribute_no_element_children_returned() {
	// attribute axis is name-disjoint from element axes.
	// u1 has no attribute named `name` even though it has a child
	// ELEMENT named `name`.
	t := build_tree()
	out := code.axis_attribute(t.u1, name_test('name'))
	assert out.len == 0, 'attribute axis must not return same-name child elements'
}

// ── axis_following_sibling ───────────────────────────────────────────────────

fn test_axis_following_sibling_forward_order() {
	t := build_tree()
	// u1's following siblings are [u2, post] in forward doc order.
	out := code.axis_following_sibling(t.u1, wildcard_test())
	assert out.len == 2
	assert names_of(out) == ['user', 'post']
	assert voidptr(out[0]) == voidptr(t.u2)
	assert voidptr(out[1]) == voidptr(t.post)
}

fn test_axis_following_sibling_last_child_empty() {
	t := build_tree()
	out := code.axis_following_sibling(t.post, wildcard_test())
	assert out.len == 0
}

fn test_axis_following_sibling_root_has_none() {
	t := build_tree()
	out := code.axis_following_sibling(t.doc, wildcard_test())
	assert out.len == 0, 'doc root has no parent → no following siblings'
}

// ── axis_preceding_sibling ───────────────────────────────────────────────────

fn test_axis_preceding_sibling_reverse_order() {
	t := build_tree()
	// post's preceding siblings in REVERSE doc order: u2 (closest),
	// then u1 (farthest).
	out := code.axis_preceding_sibling(t.post, wildcard_test())
	assert out.len == 2
	assert voidptr(out[0]) == voidptr(t.u2), 'closest preceding first'
	assert voidptr(out[1]) == voidptr(t.u1), 'farthest preceding last'
}

fn test_axis_preceding_sibling_first_child_empty() {
	t := build_tree()
	out := code.axis_preceding_sibling(t.u1, wildcard_test())
	assert out.len == 0
}

// ── axis_following ───────────────────────────────────────────────────────────

fn test_axis_following_from_u1_excludes_descendants() {
	t := build_tree()
	// From u1, the "following" axis must include u2 + u2's subtree +
	// post + post's subtree; it must NOT include u1's descendants
	// (name, email).
	out := code.axis_following(t.u1, wildcard_test())
	// Elements after u1 (excluding u1's subtree): u2, u2_name, post,
	// p_title = 4 element nodes.
	assert out.len == 4, 'expected 4, got ${out.len}: ${names_of(out)}'
	got_names := names_of(out)
	assert got_names == ['user', 'name', 'post', 'title']
	// Sanity: u1_name / u1_email never appear.
	for n in out {
		assert voidptr(n) != voidptr(t.u1_name)
		assert voidptr(n) != voidptr(t.u1_email)
	}
}

fn test_axis_following_from_deep_node_climbs_to_ancestor_siblings() {
	t := build_tree()
	// From u1_name (deep under u1), following must include u1_email
	// (sibling at deeper level), then u2 + u2's subtree, then post +
	// p_title.
	out := code.axis_following(t.u1_name, wildcard_test())
	// elements after u1_name (excluding u1_name's subtree, which is
	// only its text child): u1_email, u2, u2_name, post, p_title = 5.
	assert out.len == 5, 'expected 5, got ${out.len}: ${names_of(out)}'
	assert names_of(out) == ['email', 'user', 'name', 'post', 'title']
}

fn test_axis_following_from_last_node_in_doc_empty() {
	t := build_tree()
	// p_title is the last element in document order. Nothing follows.
	out := code.axis_following(t.p_title, wildcard_test())
	assert out.len == 0
}

// ── axis_preceding ───────────────────────────────────────────────────────────

fn test_axis_preceding_from_post_excludes_ancestors() {
	t := build_tree()
	// From post, preceding (in REVERSE doc order) is everything in u2's
	// subtree + everything in u1's subtree, excluding ancestors (doc).
	// Reverse doc order = closest preceding first: u2_name, u2,
	// u1_email, u1_name, u1.
	out := code.axis_preceding(t.post, wildcard_test())
	assert out.len == 5, 'expected 5, got ${out.len}: ${names_of(out)}'
	// First emitted = closest preceding in doc order = u2_name.
	assert voidptr(out[0]) == voidptr(t.u2_name), 'closest preceding first'
	// Last emitted = farthest preceding (excluding ancestors) = u1.
	assert voidptr(out[out.len - 1]) == voidptr(t.u1), 'farthest preceding last'
	// Sanity: doc (ancestor) never appears.
	for n in out {
		assert voidptr(n) != voidptr(t.doc), 'ancestor must not appear in preceding axis'
	}
}

fn test_axis_preceding_from_first_node_empty() {
	t := build_tree()
	// u1 is the first element child of doc. Nothing precedes it
	// (excluding doc, which is an ancestor).
	out := code.axis_preceding(t.u1, wildcard_test())
	assert out.len == 0
}

fn test_axis_preceding_from_root_empty() {
	t := build_tree()
	// doc has no parent — preceding axis is empty.
	out := code.axis_preceding(t.doc, wildcard_test())
	assert out.len == 0
}

// ── register_misc_axes / dispatcher integration ──────────────────────────────

fn test_register_misc_axes_installs_all_6_handlers() {
	mut d := code.new_axis_dispatcher()
	code.register_misc_axes(mut d)
	assert d.has_axis(cx.PathAxis.self_)
	assert d.has_axis(cx.PathAxis.attribute)
	assert d.has_axis(cx.PathAxis.following_sibling)
	assert d.has_axis(cx.PathAxis.preceding_sibling)
	assert d.has_axis(cx.PathAxis.following)
	assert d.has_axis(cx.PathAxis.preceding)
}

fn test_register_misc_axes_dispatches_attribute_step() {
	t := build_tree()
	mut d := code.new_default_axis_dispatcher()
	code.register_misc_axes(mut d)
	// Build path: descendant-or-self::user / attribute::role
	user_step := cx.new_path_step(cx.PathAxis.descendant_or_self, 'user')
	attr_step := cx.new_path_step(cx.PathAxis.attribute, 'role')
	pn := cx.new_path_node(.relative, [user_step, attr_step])

	out := code.eval_cxpath(pn, [t.doc], d) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	// Both users have a `role` attr.
	assert out.len == 2, 'expected 2 role attrs, got ${out.len}'
	for n in out {
		assert n.kind == .attribute
		assert code.node_name(n) == 'role'
	}
}
