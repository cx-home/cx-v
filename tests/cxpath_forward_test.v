module main

import cx
import code

// Tests for the Phase 2.6 part 1 CXPath axis-walker — dispatcher contract
// 3 forward axes (child / descendant / descendant-or-self)
// D2. See `vcx/code/cxpath_eval.v` + `vcx/code/cxpath_forward.v` for the
// implementation under test.
//
// Coverage map:
//
//   - axis_child: positive (matching child name), miss (no children
//     match), wildcard (`*` matches all elements).
//   - axis_descendant: positive (named match somewhere in subtree),
//     miss (name absent), wildcard (`*` lists all element descendants).
//   - axis_descendant_or_self: positive (context node matches), miss,
//     wildcard (context + descendants).
//   - Multi-step composition via `eval_cxpath`: `//user/email` (uses
//     descendant + child); `//user/*` (descendant + child wildcard).
//   - Dispatcher: `new_default_axis_dispatcher` registers 3 forward
//     axes; reverse axis returns CXPATH_AXIS_NOT_REGISTERED.
//
// Tree-construction helpers below build a small fixture tree:
//
//   <doc>
//     <user>
//       <name>Alice</name>
//       <email>alice@example.com</email>
//     </user>
//     <user>
//       <name>Bob</name>
//     </user>
//     <post>
//       <title>Hello</title>
//     </post>
//   </doc>

// ── Tree-construction helpers ────────────────────────────────────────────────

// build_doc constructs the shared fixture tree described above and
// returns its root. Each test calls this anew so trees don't leak
// mutations between tests.
fn build_doc() &code.CxNode {
	mut doc := code.new_element('doc')

	mut u1 := code.new_element('user')
	mut u1_name := code.new_element('name')
	u1_name.children << code.new_text('Alice')
	u1_name.parent = u1
	mut u1_email := code.new_element('email')
	u1_email.children << code.new_text('alice@example.com')
	u1_email.parent = u1
	u1.children << u1_name
	u1.children << u1_email
	u1.parent = doc

	mut u2 := code.new_element('user')
	mut u2_name := code.new_element('name')
	u2_name.children << code.new_text('Bob')
	u2_name.parent = u2
	u2.children << u2_name
	u2.parent = doc

	mut p := code.new_element('post')
	mut p_title := code.new_element('title')
	p_title.children << code.new_text('Hello')
	p_title.parent = p
	p.children << p_title
	p.parent = doc

	doc.children << u1
	doc.children << u2
	doc.children << p
	return doc
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

// ── axis_child ───────────────────────────────────────────────────────────────

fn test_axis_child_positive_match() {
	doc := build_doc()
	out := code.axis_child(doc, name_test('user'))
	assert out.len == 2, 'expected 2 user children, got ${out.len}'
	assert names(out) == ['user', 'user']
}

fn test_axis_child_miss_unknown_name() {
	doc := build_doc()
	out := code.axis_child(doc, name_test('nonexistent'))
	assert out.len == 0
}

fn test_axis_child_wildcard_lists_all_element_children() {
	doc := build_doc()
	out := code.axis_child(doc, wildcard_test())
	// doc has 3 element children: 2 users + 1 post.
	assert out.len == 3
	assert names(out) == ['user', 'user', 'post']
}

// ── axis_descendant ──────────────────────────────────────────────────────────

fn test_axis_descendant_positive_named() {
	doc := build_doc()
	out := code.axis_descendant(doc, name_test('email'))
	assert out.len == 1, 'expected 1 email descendant, got ${out.len}'
	assert code.node_name(out[0]) == 'email'
}

fn test_axis_descendant_miss_absent_name() {
	doc := build_doc()
	out := code.axis_descendant(doc, name_test('comment'))
	assert out.len == 0
}

fn test_axis_descendant_wildcard_lists_all_element_descendants() {
	doc := build_doc()
	out := code.axis_descendant(doc, wildcard_test())
	// element descendants: user, name, email (under u1), user, name
	// (under u2), post, title (under p). 7 elements total. Text nodes
	// are excluded by the `*` wildcard + the wildcard
	// element-kind filter.
	assert out.len == 7, 'expected 7 element descendants, got ${out.len}'
}

fn test_axis_descendant_excludes_context_node() {
	doc := build_doc()
	// `descendant` axis excludes the context node itself per XPath 3.1
	// §3.3.1.2. A `doc` node-test against the doc root via the
	// descendant axis must miss.
	out := code.axis_descendant(doc, name_test('doc'))
	assert out.len == 0
}

// ── axis_descendant_or_self ──────────────────────────────────────────────────

fn test_axis_descendant_or_self_includes_self() {
	doc := build_doc()
	// Per XPath 3.1 §3.3.1.3 descendant-or-self INCLUDES the context
	// node. A `doc` node-test from the doc root MUST match.
	out := code.axis_descendant_or_self(doc, name_test('doc'))
	assert out.len == 1
	assert code.node_name(out[0]) == 'doc'
}

fn test_axis_descendant_or_self_miss() {
	doc := build_doc()
	out := code.axis_descendant_or_self(doc, name_test('absent'))
	assert out.len == 0
}

fn test_axis_descendant_or_self_wildcard_includes_self_plus_descendants() {
	doc := build_doc()
	out := code.axis_descendant_or_self(doc, wildcard_test())
	// 1 (doc) + 7 element descendants = 8.
	assert out.len == 8, 'expected 8 (self + descendants), got ${out.len}'
}

// ── Multi-step paths via eval_cxpath ─────────────────────────────────────────

fn test_eval_cxpath_descendant_user_child_email() {
	// `//user/email` — descendant `user`, then child `email`.
	// Construct PathNode manually (parser integration not in scope at
	// Phase 2.6 part 1 — eval_cxpath consumes the AST directly).
	doc := build_doc()
	dispatcher := code.new_default_axis_dispatcher()

	user_step := cx.new_path_step(cx.PathAxis.descendant_or_self, 'user')
	email_step := cx.new_path_step(cx.PathAxis.child, 'email')
	// Per grammar [130], `//user/email` form is `.descendant` and the
	// first step is `descendant-or-self::user`. We build the lowered
	// shape directly: form=.relative + steps=[descendant-or-self::user,
	// child::email] — eval_cxpath then walks the steps as-supplied.
	pn := cx.new_path_node(.relative, [user_step, email_step])

	out := code.eval_cxpath(pn, [doc], dispatcher) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	assert out.len == 1, 'expected 1 email node, got ${out.len}'
	assert code.node_name(out[0]) == 'email'
}

fn test_eval_cxpath_descendant_form_prepends_descendant_or_self() {
	// `.descendant` form on the PathNode prepends an implicit
	// `descendant-or-self::node()` step before the explicit step list
	// per grammar [130]. Verify that with form=.descendant +
	// steps=[child::email] we still reach the email node from the doc
	// root.
	doc := build_doc()
	dispatcher := code.new_default_axis_dispatcher()

	email_step := cx.new_path_step(cx.PathAxis.child, 'email')
	pn := cx.new_path_node(.descendant, [email_step])

	out := code.eval_cxpath(pn, [doc], dispatcher) or {
		assert false, 'unexpected eval error: ${err}'
		return
	}
	// The implicit `descendant-or-self::node()` step lands on every
	// element (since kind-tests are stubbed to match everything at
	// Phase 2.6 part 1). The subsequent `child::email` step then
	// produces the email child of u1. There may be duplicates if
	// multiple descendants have an `email` child — here only u1 does,
	// so the result is exactly [email].
	assert out.len == 1
	assert code.node_name(out[0]) == 'email'
}

fn test_eval_cxpath_descendant_user_child_wildcard() {
	// `//user/*` — descendant user, then child wildcard.
	doc := build_doc()
	dispatcher := code.new_default_axis_dispatcher()

	user_step := cx.new_path_step(cx.PathAxis.descendant_or_self, 'user')
	star_step := cx.new_path_step(cx.PathAxis.child, '*')
	pn := cx.new_path_node(.relative, [user_step, star_step])

	out := code.eval_cxpath(pn, [doc], dispatcher) or {
		assert false, '${err}'
		return
	}
	// u1 has 2 element children (name, email); u2 has 1 (name).
	// 2 + 1 = 3.
	assert out.len == 3, 'expected 3 user children, got ${out.len}'
}

// ── Dispatcher ───────────────────────────────────────────────────────────────

fn test_default_dispatcher_registers_3_forward_axes() {
	d := code.new_default_axis_dispatcher()
	assert d.has_axis(cx.PathAxis.child)
	assert d.has_axis(cx.PathAxis.descendant)
	assert d.has_axis(cx.PathAxis.descendant_or_self)
}

fn test_default_dispatcher_registers_all_12_axes_after_wireup() {
	// Phase 2.6 part-3 follow-up landed: new_default_axis_dispatcher
	// now wires register_forward_axes + register_reverse_axes +
	// register_misc_axes so the default surface covers all 12 
	// D2 axes in a single call (no per-caller composition required).
	d := code.new_default_axis_dispatcher()
	assert d.has_axis(cx.PathAxis.parent)
	assert d.has_axis(cx.PathAxis.ancestor)
	assert d.has_axis(cx.PathAxis.ancestor_or_self)
	assert d.has_axis(cx.PathAxis.self_)
	assert d.has_axis(cx.PathAxis.attribute)
	assert d.has_axis(cx.PathAxis.following_sibling)
	assert d.has_axis(cx.PathAxis.preceding_sibling)
	assert d.has_axis(cx.PathAxis.following)
	assert d.has_axis(cx.PathAxis.preceding)
}

fn test_dispatch_unregistered_axis_surfaces_error() {
	doc := build_doc()
	// Drive against a fresh empty dispatcher so EVERY axis is
	// unregistered — the default dispatcher now carries all 12, so
	// any axis-not-registered surface check has to go through a
	// dispatcher that has not been pre-populated.
	d := code.new_axis_dispatcher()
	d.dispatch(cx.PathAxis.parent, doc, name_test('doc')) or {
		assert err.msg().contains('CXPATH_AXIS_NOT_REGISTERED')
		return
	}
	assert false, 'expected CXPATH_AXIS_NOT_REGISTERED error'
}

fn test_register_axis_handler_free_fn_installs_handler() {
	// The free-fn form of `register` exposed for sibling-file usage.
	mut d := code.new_axis_dispatcher()
	code.register_axis_handler(mut d, cx.PathAxis.child, code.axis_child)
	assert d.has_axis(cx.PathAxis.child)
}

// ── parse_node_test ──────────────────────────────────────────────────────────

fn test_parse_node_test_recognises_wildcard() {
	t := code.parse_node_test('*', ?string(none))
	assert t.kind == .wildcard
}

fn test_parse_node_test_recognises_bare_name() {
	t := code.parse_node_test('user', ?string(none))
	assert t.kind == .name
	assert (t.name or { '' }) == 'user'
}

fn test_parse_node_test_recognises_kind_test() {
	t := code.parse_node_test('node()', ?string(none))
	assert t.kind == .kind_test
}

fn test_parse_node_test_propagates_binding() {
	t := code.parse_node_test('user', ?string('u'))
	assert (t.binding or { '' }) == 'u'
}
