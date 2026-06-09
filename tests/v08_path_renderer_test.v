module main

import cx

// Tests for the Phase 2.9 PathNode canonical renderer
// (`vcx/cx/path_renderer.v`) per `spec/canonical.md §2.12`.
//
// Coverage map:
//   §2.12.2 form discriminator (absolute / descendant / relative /
//           binding)            — test_render_form_*
//   §2.12.3 axis emit (child omitted, attribute → @, others
//           `axis::`)           — test_render_axis_*
//   §2.12.4 node-test verbatim  — test_render_node_test_*
//   §2.12.5 predicate `[BODY]`  — test_render_predicate_*
//   §2.12.6 zero whitespace     — test_render_no_whitespace
//   §2.12.7 identity round-trip — test_identity_round_trip_*
//   §2.12.8 worked examples     — test_worked_example_*
//
// The worked-example suite (test_worked_example_*) covers all eight
// rows of the §2.12.8 table.

// ── §2.12.8 worked examples ───────────────────────────────────────────────────

fn test_worked_example_1_descendant_bare() {
	// `form=descendant`, step `(child, user, [])` → `//user`
	node := cx.PathNode{
		form:  cx.PathForm.descendant
		steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user' }]
	}
	assert cx.render_path(node) == '//user'
}

fn test_worked_example_2_descendant_attr_pred() {
	// `form=descendant`, step `(child, user, [pred:@active])` → `//user[@active]`
	node := cx.PathNode{
		form:  cx.PathForm.descendant
		steps: [
			cx.PathStep{
				axis:       cx.PathAxis.child
				node_test:  'user'
				predicates: [cx.PathPredicate{ source: '@active' }]
			},
		]
	}
	assert cx.render_path(node) == '//user[@active]'
}

fn test_worked_example_3_descendant_or_self_collapse() {
	// `form=absolute`, steps `[(descendant-or-self, node(), []), (child, user, [])]`
	// → `//user` (the renderer collapses the canonical desugaring back to `//`).
	node := cx.PathNode{
		form:  cx.PathForm.absolute
		steps: [
			cx.PathStep{ axis: cx.PathAxis.descendant_or_self, node_test: 'node()' },
			cx.PathStep{ axis: cx.PathAxis.child,              node_test: 'user'   },
		]
	}
	assert cx.render_path(node) == '//user'
}

fn test_worked_example_4_binding() {
	// `form=binding`, binding="u", step `(child, email, [])` → `$u/email`
	node := cx.PathNode{
		form:    cx.PathForm.binding
		binding: 'u'
		steps:   [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'email' }]
	}
	assert cx.render_path(node) == '\$u/email'
}

fn test_worked_example_5_absolute_multi_step_int_pred() {
	// `form=absolute`, steps `[(child, root, []), (child, item, [pred:3])]`
	// → `/root/item[3]`
	node := cx.PathNode{
		form:  cx.PathForm.absolute
		steps: [
			cx.PathStep{ axis: cx.PathAxis.child, node_test: 'root' },
			cx.PathStep{
				axis:       cx.PathAxis.child
				node_test:  'item'
				predicates: [cx.PathPredicate{ source: '3' }]
			},
		]
	}
	assert cx.render_path(node) == '/root/item[3]'
}

fn test_worked_example_6_descendant_attribute() {
	// `form=descendant`, step `(attribute, name, [])` → `//@name`
	node := cx.PathNode{
		form:  cx.PathForm.descendant
		steps: [cx.PathStep{ axis: cx.PathAxis.attribute, node_test: 'name' }]
	}
	assert cx.render_path(node) == '//@name'
}

fn test_worked_example_7_descendant_general_predicate() {
	// `form=descendant`, step `(child, user, [pred:`$_@active and $_@verified`])`
	// → `//user[$_@active and $_@verified]` (general-form fall-through; no
	// atomic-template match).
	body := '\$_@active and \$_@verified'
	node := cx.PathNode{
		form:  cx.PathForm.descendant
		steps: [
			cx.PathStep{
				axis:       cx.PathAxis.child
				node_test:  'user'
				predicates: [cx.PathPredicate{ source: body }]
			},
		]
	}
	assert cx.render_path(node) == '//user[${body}]'
}

fn test_worked_example_8_binding_with_general_predicate() {
	// `form=binding`, binding="t", steps `[(child, member, [pred:`$_@role = "lead"`])]`
	// → `$t/member[$_@role = "lead"]`
	// (atomic-template match becomes the terse `@role = "lead"` form once
	// Phase 2.4 grafts AST recognition; at Phase 2.9 the source body is
	// emitted verbatim per the TODO marker in path_renderer.v).
	body := '\$_@role = "lead"'
	node := cx.PathNode{
		form:    cx.PathForm.binding
		binding: 't'
		steps:   [
			cx.PathStep{
				axis:       cx.PathAxis.child
				node_test:  'member'
				predicates: [cx.PathPredicate{ source: body }]
			},
		]
	}
	assert cx.render_path(node) == '\$t/member[${body}]'
}

// ── §2.12.2 form discriminator ────────────────────────────────────────────────

fn test_render_form_relative() {
	node := cx.PathNode{
		form:  cx.PathForm.relative
		steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user' }]
	}
	assert cx.render_path(node) == 'user'
}

fn test_render_form_absolute() {
	node := cx.PathNode{
		form:  cx.PathForm.absolute
		steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user' }]
	}
	assert cx.render_path(node) == '/user'
}

fn test_render_form_descendant() {
	node := cx.PathNode{
		form:  cx.PathForm.descendant
		steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user' }]
	}
	assert cx.render_path(node) == '//user'
}

fn test_render_form_binding() {
	node := cx.PathNode{
		form:    cx.PathForm.binding
		binding: 'u'
		steps:   [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'name' }]
	}
	assert cx.render_path(node) == '\$u/name'
}

// ── §2.12.3 axis emit rules ───────────────────────────────────────────────────

fn test_render_axis_child_omitted() {
	// `child::user` PathNode renders as `user` (axis is the default).
	node := cx.PathNode{
		form:  cx.PathForm.relative
		steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user' }]
	}
	assert cx.render_path(node) == 'user'
}

fn test_render_axis_attribute_sugar() {
	// `attribute::name` renders as `@name`.
	node := cx.PathNode{
		form:  cx.PathForm.relative
		steps: [cx.PathStep{ axis: cx.PathAxis.attribute, node_test: 'name' }]
	}
	assert cx.render_path(node) == '@name'
}

fn test_render_axis_descendant_explicit() {
	// `descendant::user` renders as `descendant::user`.
	node := cx.PathNode{
		form:  cx.PathForm.relative
		steps: [cx.PathStep{ axis: cx.PathAxis.descendant, node_test: 'user' }]
	}
	assert cx.render_path(node) == 'descendant::user'
}

fn test_render_axis_descendant_or_self_explicit() {
	// `descendant-or-self::user` renders verbatim.
	node := cx.PathNode{
		form:  cx.PathForm.relative
		steps: [cx.PathStep{ axis: cx.PathAxis.descendant_or_self, node_test: 'user' }]
	}
	assert cx.render_path(node) == 'descendant-or-self::user'
}

fn check_axis_emit(ax cx.PathAxis, name string) {
	node := cx.PathNode{
		form:  cx.PathForm.relative
		steps: [cx.PathStep{ axis: ax, node_test: 'x' }]
	}
	assert cx.render_path(node) == '${name}::x'
}

fn test_render_axis_all_ten_non_default() {
	// Each of the ten non-default, non-attribute axes renders as `axis::name`.
	check_axis_emit(cx.PathAxis.descendant,         'descendant')
	check_axis_emit(cx.PathAxis.descendant_or_self, 'descendant-or-self')
	check_axis_emit(cx.PathAxis.parent,             'parent')
	check_axis_emit(cx.PathAxis.ancestor,           'ancestor')
	check_axis_emit(cx.PathAxis.ancestor_or_self,   'ancestor-or-self')
	check_axis_emit(cx.PathAxis.following_sibling,  'following-sibling')
	check_axis_emit(cx.PathAxis.preceding_sibling,  'preceding-sibling')
	check_axis_emit(cx.PathAxis.following,          'following')
	check_axis_emit(cx.PathAxis.preceding,          'preceding')
	check_axis_emit(cx.PathAxis.self_,              'self')
}

// ── §2.12.4 node-test verbatim ────────────────────────────────────────────────

fn test_render_node_test_wildcard() {
	node := cx.PathNode{
		form:  cx.PathForm.descendant
		steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: '*' }]
	}
	assert cx.render_path(node) == '//*'
}

fn test_render_node_test_kind_tests() {
	kinds := ['node()', 'text()', 'element()', 'attribute()']
	for k in kinds {
		node := cx.PathNode{
			form:  cx.PathForm.descendant
			steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: k }]
		}
		assert cx.render_path(node) == '//${k}'
	}
}

fn test_render_node_test_prefixed() {
	// `Prefix:Local` QName + `Prefix:*` + `*:Local` emit verbatim.
	cases := ['xml:lang', 'xml:*', '*:lang']
	for nt in cases {
		node := cx.PathNode{
			form:  cx.PathForm.relative
			steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: nt }]
		}
		assert cx.render_path(node) == nt
	}
}

// ── §2.12.5 predicate emit ────────────────────────────────────────────────────

fn test_render_predicate_attribute_existence() {
	node := cx.PathNode{
		form:  cx.PathForm.descendant
		steps: [
			cx.PathStep{
				axis:       cx.PathAxis.child
				node_test:  'user'
				predicates: [cx.PathPredicate{ source: '@active' }]
			},
		]
	}
	assert cx.render_path(node) == '//user[@active]'
}

fn test_render_multi_predicate() {
	// Hand-build a multi-predicate step (parser still rejects this shape
	// at Phase 2.3, but the renderer must handle the AST).
	node := cx.PathNode{
		form:  cx.PathForm.descendant
		steps: [
			cx.PathStep{
				axis:       cx.PathAxis.child
				node_test:  'user'
				predicates: [
					cx.PathPredicate{ source: '@active' },
					cx.PathPredicate{ source: '3' },
				]
			},
		]
	}
	assert cx.render_path(node) == '//user[@active][3]'
}

fn test_render_top_level_trailing_predicate() {
	// Trailing PathNode.predicates (rare) emit after the last step.
	node := cx.PathNode{
		form:       cx.PathForm.descendant
		steps:      [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user' }]
		predicates: [cx.PathPredicate{ source: '@verified' }]
	}
	assert cx.render_path(node) == '//user[@verified]'
}

// ── §2.12.6 zero whitespace ───────────────────────────────────────────────────

fn test_render_no_whitespace() {
	// Even when the predicate body contains spaces (general form), the
	// PathNode token stream itself never injects whitespace.
	body := '@name = "alice"'
	node := cx.PathNode{
		form:  cx.PathForm.descendant
		steps: [
			cx.PathStep{
				axis:       cx.PathAxis.child
				node_test:  'user'
				predicates: [cx.PathPredicate{ source: body }]
			},
		]
	}
	out := cx.render_path(node)
	// Confirm the only whitespace in the output lives inside the
	// predicate body, not at PathNode-token boundaries (§2.12.6).
	assert out == '//user[${body}]'
	// Specifically, the PathNode-level scaffolding `//user[…]` carries
	// no spaces:
	prefix := out[..7] // `//user[`
	assert prefix == '//user['
	for b in prefix.bytes() {
		assert b != ` `
	}
}

// ── Multi-step rendering (hand-built; parser deferred) ────────────────────────

fn test_render_multi_step_relative() {
	node := cx.PathNode{
		form:  cx.PathForm.relative
		steps: [
			cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user'  },
			cx.PathStep{ axis: cx.PathAxis.child, node_test: 'email' },
		]
	}
	assert cx.render_path(node) == 'user/email'
}

fn test_render_multi_step_absolute() {
	node := cx.PathNode{
		form:  cx.PathForm.absolute
		steps: [
			cx.PathStep{ axis: cx.PathAxis.child, node_test: 'root' },
			cx.PathStep{ axis: cx.PathAxis.child, node_test: 'item' },
		]
	}
	assert cx.render_path(node) == '/root/item'
}

fn test_render_multi_step_descendant_then_attribute() {
	node := cx.PathNode{
		form:  cx.PathForm.descendant
		steps: [
			cx.PathStep{ axis: cx.PathAxis.child,     node_test: 'user' },
			cx.PathStep{ axis: cx.PathAxis.attribute, node_test: 'id'   },
		]
	}
	assert cx.render_path(node) == '//user/@id'
}

// ── §2.12.7 identity round-trip ───────────────────────────────────────────────

fn assert_identity_round_trip(node cx.PathNode) {
	// Build a sibling AST that is structurally equal to `node` but
	// differs in advisory fields (source/loc). Per §2.12.7 their
	// renders MUST be byte-identical.
	mut sibling := cx.PathNode{
		form:       node.form
		binding:    node.binding
		steps:      node.steps.clone()
		predicates: node.predicates.clone()
		source:     'IGNORED ADVISORY SOURCE'
		loc:        cx.PathLoc{ line: 999, col: 42 }
	}
	assert node.eq(sibling)
	assert sibling.eq(node)
	r1 := cx.render_path(node)
	r2 := cx.render_path(sibling)
	assert r1 == r2, 'identity round-trip failed: ${r1} != ${r2}'
}

fn test_identity_round_trip_descendant_bare() {
	node := cx.PathNode{
		form:  cx.PathForm.descendant
		steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user' }]
	}
	assert_identity_round_trip(node)
}

fn test_identity_round_trip_with_predicate() {
	node := cx.PathNode{
		form:  cx.PathForm.descendant
		steps: [
			cx.PathStep{
				axis:       cx.PathAxis.child
				node_test:  'user'
				predicates: [cx.PathPredicate{ source: '@active' }]
			},
		]
	}
	assert_identity_round_trip(node)
}

fn test_identity_round_trip_binding() {
	node := cx.PathNode{
		form:    cx.PathForm.binding
		binding: 'u'
		steps:   [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'email' }]
	}
	assert_identity_round_trip(node)
}

fn test_identity_round_trip_absolute_multi_step() {
	node := cx.PathNode{
		form:  cx.PathForm.absolute
		steps: [
			cx.PathStep{ axis: cx.PathAxis.child, node_test: 'root' },
			cx.PathStep{
				axis:       cx.PathAxis.child
				node_test:  'item'
				predicates: [cx.PathPredicate{ source: '3' }]
			},
		]
	}
	assert_identity_round_trip(node)
}

fn test_identity_round_trip_explicit_axis() {
	node := cx.PathNode{
		form:  cx.PathForm.relative
		steps: [cx.PathStep{ axis: cx.PathAxis.ancestor, node_test: 'section' }]
	}
	assert_identity_round_trip(node)
}

// ── Render → parse → render round-trip ────────────────────────────────────────

fn test_parse_render_round_trip_descendant() {
	src := '//user'
	parsed := cx.parse_path(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert cx.render_path(parsed) == src
}

fn test_parse_render_round_trip_absolute() {
	src := '/user'
	parsed := cx.parse_path(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert cx.render_path(parsed) == src
}

fn test_parse_render_round_trip_relative() {
	src := 'user'
	parsed := cx.parse_path(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert cx.render_path(parsed) == src
}

fn test_parse_render_round_trip_binding() {
	src := '\$u/email'
	parsed := cx.parse_path(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert cx.render_path(parsed) == src
}

fn test_parse_render_round_trip_attribute_sugar() {
	src := '//@name'
	parsed := cx.parse_path(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert cx.render_path(parsed) == src
}

fn test_parse_render_round_trip_explicit_axis() {
	src := '//descendant::user'
	parsed := cx.parse_path(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	// Note: `descendant::` is the explicit non-default form; the canonical
	// emit preserves it as-is (we don't collapse it into the leading-`//`
	// shorthand because the AST shape doesn't carry the leading
	// `descendant-or-self::node()` synthetic step — only the absolute-
	// form-with-shorthand-prefix collapse from §2.12.8 example 3 fires).
	assert cx.render_path(parsed) == src
}

fn test_parse_render_round_trip_with_predicate() {
	src := '//user[@active]'
	parsed := cx.parse_path(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert cx.render_path(parsed) == src
}

// Render → parse → render: the second render must byte-equal the first.
fn test_render_parse_render_byte_identical() {
	// Build a PathNode by hand, render once, parse, render again — the
	// second render byte-equals the first per §2.12.7.
	nodes := [
		cx.PathNode{
			form:  cx.PathForm.descendant
			steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user' }]
		},
		cx.PathNode{
			form:  cx.PathForm.absolute
			steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'root' }]
		},
		cx.PathNode{
			form:  cx.PathForm.relative
			steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user' }]
		},
		cx.PathNode{
			form:    cx.PathForm.binding
			binding: 'u'
			steps:   [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'email' }]
		},
		cx.PathNode{
			form:  cx.PathForm.descendant
			steps: [cx.PathStep{ axis: cx.PathAxis.attribute, node_test: 'id' }]
		},
	]
	for n in nodes {
		first := cx.render_path(n)
		parsed := cx.parse_path(first) or {
			assert false, 'parse of rendered "${first}" failed: ${err}'
			return
		}
		second := cx.render_path(parsed)
		assert first == second, 'render-parse-render drift: "${first}" != "${second}"'
	}
}

// ── Helper-level coverage ─────────────────────────────────────────────────────

fn test_render_step_helper_isolation() {
	step := cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user' }
	assert cx.render_step(step) == 'user'
	step2 := cx.PathStep{ axis: cx.PathAxis.attribute, node_test: 'name' }
	assert cx.render_step(step2) == '@name'
	step3 := cx.PathStep{ axis: cx.PathAxis.parent, node_test: '*' }
	assert cx.render_step(step3) == 'parent::*'
}

fn test_render_node_test_helper_isolation() {
	assert cx.render_node_test(cx.PathAxis.child, 'user') == 'user'
	assert cx.render_node_test(cx.PathAxis.attribute, 'name') == '@name'
	assert cx.render_node_test(cx.PathAxis.descendant, 'x') == 'descendant::x'
	assert cx.render_node_test(cx.PathAxis.self_, 'node()') == 'self::node()'
}

fn test_render_predicate_helper_isolation() {
	pred := cx.PathPredicate{ source: '@active' }
	assert cx.render_predicate(pred) == '[@active]'
	pred2 := cx.PathPredicate{ source: '3' }
	assert cx.render_predicate(pred2) == '[3]'
}
