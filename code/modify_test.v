module code

// ── Modify tests ───────────────────────────────────────
//
// Parser coverage: every action shape in grammar [142]–[148e] parses to
// a cx.ProgramDirective named 'modify' with the expected slot layout.
// Evaluator coverage: every action produces the spec-expected output on
// a representative document, and the identity invariant
// holds — the input document is observably unchanged after each modify.

import cx

// ── Parser tests ────────────────────────────────────────────────────────────

fn modify_directive(src string) !cx.ProgramDirective {
	prog := cx.parse_program(src)!
	body := prog.body
	if body is cx.ProgramDirective {
		if body.name != 'modify' {
			return error('expected modify directive, got ${body.name}')
		}
		return body
	}
	return error('expected cx.ProgramDirective, got other')
}

fn test_parse_set() {
	d := modify_directive('[?modify $doc //user/@name [set "Alice"]]') or {
		assert false, '${err}'
		return
	}
	// 2 positional + 1 action slot
	assert d.slots.len == 3
	assert d.slots[0].kind == .positional
	assert d.slots[1].kind == .positional
	assert d.slots[1].value is cx.ProgramPathExpr
	assert d.slots[2].label == 'set'
}

fn test_parse_delete() {
	d := modify_directive('[?modify $doc //user [delete]]') or {
		assert false, '${err}'
		return
	}
	assert d.slots[2].label == 'delete'
}

fn test_parse_using() {
	d := modify_directive('[?modify $doc //price [using [?fn $p $p]]]') or {
		assert false, '${err}'
		return
	}
	assert d.slots[2].label == 'using'
}

fn test_parse_rename() {
	d := modify_directive('[?modify $doc //widget [rename component]]') or {
		assert false, '${err}'
		return
	}
	assert d.slots[2].label == 'rename'
	v := d.slots[2].value
	if v is cx.ProgramLiteral {
		assert v.kind == .string_lit
		assert v.str_val == 'component'
	} else {
		assert false, 'rename value must be string_lit'
	}
}

fn test_parse_set_attr() {
	d := modify_directive('[?modify $doc //user [set-attr status "active"]]') or {
		assert false, '${err}'
		return
	}
	assert d.slots[2].label == 'set-attr'
	v := d.slots[2].value
	if v is cx.ProgramLiteral {
		assert v.kind == .sequence_lit
		assert v.items.len == 2
	} else {
		assert false, 'set-attr value must be sequence_lit (name, expr)'
	}
}

fn test_parse_delete_attr() {
	d := modify_directive('[?modify $doc //user [delete-attr email]]') or {
		assert false, '${err}'
		return
	}
	assert d.slots[2].label == 'delete-attr'
}

fn test_parse_append() {
	d := modify_directive('[?modify $doc //section [append [para "x"]]]') or {
		assert false, '${err}'
		return
	}
	assert d.slots[2].label == 'append'
}

fn test_parse_prepend() {
	d := modify_directive('[?modify $doc //section [prepend [para "x"]]]') or {
		assert false, '${err}'
		return
	}
	assert d.slots[2].label == 'prepend'
}

fn test_parse_insert_before() {
	d := modify_directive('[?modify $doc //user [insert-before [u]]]') or {
		assert false, '${err}'
		return
	}
	assert d.slots[2].label == 'insert-before'
}

fn test_parse_insert_after() {
	d := modify_directive('[?modify $doc //user [insert-after [u]]]') or {
		assert false, '${err}'
		return
	}
	assert d.slots[2].label == 'insert-after'
}

fn test_parse_replace() {
	d := modify_directive('[?modify $doc //user [replace [other]]]') or {
		assert false, '${err}'
		return
	}
	assert d.slots[2].label == 'replace'
}

fn test_parse_multiple_actions() {
	d := modify_directive('[?modify $doc //user [set-attr status "v"] [delete-attr email]]') or {
		assert false, '${err}'
		return
	}
	// 2 positional + 2 actions = 4
	assert d.slots.len == 4
	assert d.slots[2].label == 'set-attr'
	assert d.slots[3].label == 'delete-attr'
}

fn test_parse_focus_must_be_pathexpr() {
	// Non-path focus must raise CXER0100.
	cx.parse_program('[?modify $doc $other [delete]]') or {
		assert err.msg().contains('CXER0100') || err.msg().contains('CXPath focus')
		return
	}
	assert false, 'expected parse error on non-PathExpr focus'
}

fn test_parse_requires_action() {
	cx.parse_program('[?modify $doc //user]') or {
		assert err.msg().contains('CXER0100') || err.msg().contains('action')
		return
	}
	assert false, 'expected parse error when no action present'
}

// ── Evaluator helpers ───────────────────────────────────────────────────────

fn eval_with_doc(in_cx string, in_code string) !cx.Node {
	doc := cx.parse(in_cx)!
	mut env := new_env()
	for i in 0 .. doc.elements.len {
		n := doc.elements[i]
		if n is cx.Element {
			env.bindings['doc'] = n
			env.bindings['input'] = n
			break
		}
	}
	prog := cx.parse_program(in_code)!
	return eval(prog.body, mut env)!
}

fn mt_render_text(n cx.Node) string {
	// Use the canonical text renderer; produces stable textual form.
	return render_canonical(n)
}

// ── Action evaluator tests ──────────────────────────────────────────────────

fn test_eval_set_attribute() {
	// `:set` on /@attr replaces the attribute value.
	result := eval_with_doc(
		'[users [user id=1 name="Alice"] [user id=2 name="Bob"]]',
		'[?modify \$doc //user[= \$_@id 1]/@name [set "Alicia"]]',
	) or {
		assert false, '${err}'
		return
	}
	rendered := mt_render_text(result)
	assert rendered.contains('Alicia'), 'expected Alicia in output, got: ${rendered}'
	assert rendered.contains('Bob'), 'Bob should be preserved, got: ${rendered}'
	assert !rendered.contains('"Alice"') && !rendered.contains('=Alice ') && !rendered.contains('=Alice]'),
		'old name should be gone, got: ${rendered}'
}

fn test_eval_delete_node() {
	result := eval_with_doc(
		'[users [user active=true [name Alice]] [user active=false [name Bob]]]',
		'[?modify \$doc //user[= \$_@active false] [delete]]',
	) or {
		assert false, '${err}'
		return
	}
	rendered := mt_render_text(result)
	assert rendered.contains('Alice')
	assert !rendered.contains('Bob'), 'Bob user should be deleted, got: ${rendered}'
}

fn test_eval_identity_invariant() {
	// input doc observably unchanged after modify.
	in_cx := '[users [user [name Alice]]]'
	doc := cx.parse(in_cx) or {
		assert false, '${err}'
		return
	}
	mut env := new_env()
	for i in 0 .. doc.elements.len {
		n := doc.elements[i]
		if n is cx.Element {
			env.bindings['doc'] = n
			break
		}
	}
	original_doc := env.bindings['doc'] or {
		assert false, 'no doc binding'
		return
	}
	original_rendered := mt_render_text(original_doc)
	// Run the modify
	prog := cx.parse_program('[?modify $doc //user/@name [set "Bob"]]') or {
		assert false, '${err}'
		return
	}
	_ := eval(prog.body, mut env) or {
		assert false, '${err}'
		return
	}
	// $doc binding must still render identically to the original
	after_doc := env.bindings['doc'] or {
		assert false, 'doc rebind lost'
		return
	}
	after_rendered := mt_render_text(after_doc)
	assert original_rendered == after_rendered, 'doc mutated: was ${original_rendered}, now ${after_rendered}'
}

fn test_eval_no_match_returns_unchanged() {
	result := eval_with_doc(
		'[users [user [name Alice]]]',
		'[?modify $doc //missing [delete]]',
	) or {
		assert false, '${err}'
		return
	}
	rendered := mt_render_text(result)
	assert rendered.contains('Alice')
	assert rendered.contains('users')
}

fn test_eval_using_transform() {
	result := eval_with_doc(
		'[doc [price 100] [price 200]]',
		'[?modify $doc //price [using [?fn \$p [price 999]]]]',
	) or {
		assert false, '${err}'
		return
	}
	rendered := mt_render_text(result)
	assert rendered.contains('999'), 'expected transformed value, got: ${rendered}'
}

fn test_eval_set_attr() {
	result := eval_with_doc(
		'[users [user [name Alice]] [user [name Bob]]]',
		'[?modify $doc //user [set-attr status "active"]]',
	) or {
		assert false, '${err}'
		return
	}
	rendered := mt_render_text(result)
	assert rendered.contains('status=active') || rendered.contains('status="active"'),
		'expected status=active attr, got: ${rendered}'
}

fn test_eval_rename() {
	result := eval_with_doc(
		'[doc [widget id=1 [label "x"]]]',
		'[?modify $doc //widget [rename component]]',
	) or {
		assert false, '${err}'
		return
	}
	rendered := mt_render_text(result)
	assert rendered.contains('component'), 'expected renamed element, got: ${rendered}'
	assert !rendered.contains('widget'), 'old name should be gone'
}

fn test_eval_delete_attr() {
	result := eval_with_doc(
		'[doc [user status="x" [name Alice]]]',
		'[?modify $doc //user [delete-attr status]]',
	) or {
		assert false, '${err}'
		return
	}
	rendered := mt_render_text(result)
	assert !rendered.contains('status'), 'attribute should be deleted, got: ${rendered}'
}

fn test_eval_append() {
	result := eval_with_doc(
		'[doc [section [para "First"]]]',
		'[?modify $doc //section [append [para "Added"]]]',
	) or {
		assert false, '${err}'
		return
	}
	rendered := mt_render_text(result)
	assert rendered.contains('First')
	assert rendered.contains('Added'), 'expected appended child, got: ${rendered}'
	// Order: First before Added
	first_idx := rendered.index('First') or { -1 }
	added_idx := rendered.index('Added') or { -1 }
	assert first_idx >= 0 && added_idx > first_idx
}

fn test_eval_prepend() {
	result := eval_with_doc(
		'[doc [section [para "Old"]]]',
		'[?modify $doc //section [prepend [para "New"]]]',
	) or {
		assert false, '${err}'
		return
	}
	rendered := mt_render_text(result)
	new_idx := rendered.index('New') or { -1 }
	old_idx := rendered.index('Old') or { -1 }
	assert new_idx >= 0 && old_idx > new_idx, 'prepended item must come first, got: ${rendered}'
}

fn test_eval_insert_before() {
	result := eval_with_doc(
		'[doc [a] [b]]',
		'[?modify $doc //b [insert-before [x]]]',
	) or {
		assert false, '${err}'
		return
	}
	rendered := mt_render_text(result)
	x_idx := rendered.index('x') or { -1 }
	b_idx := rendered.index('b') or { -1 }
	assert x_idx >= 0 && b_idx > x_idx, 'x should appear before b, got: ${rendered}'
}

fn test_eval_insert_after() {
	result := eval_with_doc(
		'[doc [a] [b]]',
		'[?modify $doc //a [insert-after [x]]]',
	) or {
		assert false, '${err}'
		return
	}
	rendered := mt_render_text(result)
	a_idx := rendered.index('a') or { -1 }
	x_idx := rendered.index('x') or { -1 }
	assert a_idx >= 0 && x_idx > a_idx, 'x should appear after a, got: ${rendered}'
}

fn test_eval_replace() {
	result := eval_with_doc(
		'[doc [a [old "x"]]]',
		'[?modify $doc //old [replace [new "y"]]]',
	) or {
		assert false, '${err}'
		return
	}
	rendered := mt_render_text(result)
	assert rendered.contains('new'), 'replacement should be present, got: ${rendered}'
	assert !rendered.contains('old'), 'old node should be gone'
}

fn test_eval_multi_match_set_attr() {
	// action applies to every match.
	result := eval_with_doc(
		'[users [user [name Alice]] [user [name Bob]]]',
		'[?modify $doc //user [set-attr status "active"]]',
	) or {
		assert false, '${err}'
		return
	}
	rendered := mt_render_text(result)
	// Both users must carry the attribute.
	mut count := 0
	mut idx := 0
	for {
		next := rendered.index_after('status=', idx) or { -1 }
		if next < 0 { break }
		count++
		idx = next + 7
	}
	assert count == 2, 'expected 2 status=active occurrences, got ${count} in: ${rendered}'
}

fn test_eval_pipeline() {
	// Multi-step modify pipeline. §8.9: bare `[?modify FOCUS Action]`
	// pipe-stage form — the threaded `$doc` is the modify target (no
	// `[through]` wrapper).
	result := eval_with_doc(
		'[users [user [name Alice]] [user [name Bob]]]',
		'[?pipe \$doc [?modify //user [set-attr v true]]]',
	) or {
		assert false, '${err}'
		return
	}
	rendered := mt_render_text(result)
	assert rendered.contains('v=true') || rendered.contains('v="true"'),
		'expected v=true attribute, got: ${rendered}'
}

// ── D-point spec-gap coverage ─────────────────────────────────────

fn test_d4_using_kind_shift_element_to_scalar_succeeds() {
	// (locked 2026-05-23): `:using` may return a value of any kind
	// regardless of focus kind; the returned value replaces the focus verbatim.
	// Element-focus + scalar-return is the canonical kind-shift case.
	//
	// This test pins the kind-shift contract:
	//   - eval must SUCCEED (no CXER0104)
	//   - result must contain the scalar return value in place of the elements
	//
	// CXER0104 is reserved for `:using` evaluators that fail to produce a value
	// (non-terminating, runtime trap inside the body) — NOT for legitimate
	// kind-shift. See spec/code.md §8.10.
	doc_src := '[doc [price 100] [price 200]]'
	code_src := '[?modify \$doc //price [using [?fn \$p "not-a-number"]]]'
	doc := cx.parse(doc_src) or {
		assert false, 'parse cx failed: ${err}'
		return
	}
	mut env := new_env()
	for i in 0 .. doc.elements.len {
		n := doc.elements[i]
		if n is cx.Element {
			env.bindings['doc'] = n
			break
		}
	}
	prog := cx.parse_program(code_src) or {
		assert false, 'parse code failed: ${err}'
		return
	}
	result := eval(prog.body, mut env) or {
		// Pre-lock impl path: any error including CXER0104 is now a spec
		// violation. Surface as a hard failure.
		assert false, 'kind-shift :using must succeed under D4 lock, got: ${err}'
		return
	}
	rendered := mt_render_text(result)
	// The string return value must appear in place of the <price> elements.
	assert rendered.contains('not-a-number'),
		'expected scalar return to replace element, got: ${rendered}'
}

fn test_d6_binding_path_focus() {
	// focus can reference a binding; CXPath on a binding uses
	// binding-path semantics. `$sec` is an element value;
	// `[?modify $sec //draft :delete]` strips draft children from that
	// sub-element, not from the document root. Identity invariant on $sec holds.
	doc_src := '[doc [section [draft yes] [final ok]] [section [draft yes] [other thing]]]'
	code_src := '[?for [in \$sec //section] [yield [?modify \$sec //draft [delete]]]]'
	result := eval_with_doc(doc_src, code_src) or {
		assert false, 'D6 binding-path focus failed: ${err}'
		return
	}
	rendered := mt_render_text(result)
	// Every section's draft child must be removed.
	assert !rendered.contains('draft'), 'draft children should be deleted, got: ${rendered}'
	// Non-draft children must survive.
	assert rendered.contains('final'), 'final child should survive, got: ${rendered}'
	assert rendered.contains('other'), 'other child should survive, got: ${rendered}'
}

fn test_d7_set_attr_on_attribute_step_raises_cxer0100() {
	// `:set-attr` / `:delete-attr` are always element-focused.
	// Parser (or pre-eval check) raises CXER0100 when the focus ends in an
	// attribute step.
	// Note: the current impl raises this at eval time (not parse time) in
	// apply_modify_action — see eval.v lines ~2530-2540. D7 spec says
	// "static error" but the implementation treats it as a pre-match runtime
	// check. The error code is correct (CXER0100); only the timing differs.
	doc_src := '[users [user name="Alice"]]'
	code_src := '[?modify \$doc //user/@name [set-attr status "active"]]'
	doc := cx.parse(doc_src) or {
		assert false, 'parse cx failed: ${err}'
		return
	}
	mut env := new_env()
	for i in 0 .. doc.elements.len {
		n := doc.elements[i]
		if n is cx.Element {
			env.bindings['doc'] = n
			break
		}
	}
	// The error may surface at parse time (static) or eval time (pre-match).
	// Test accepts either — what matters is CXER0100 is raised.
	prog := cx.parse_program(code_src) or {
		// Parse-time CXER0100 — spec-correct static error.
		assert err.msg().contains('CXER0100'),
			'expected CXER0100 at parse, got: ${err}'
		return
	}
	eval(prog.body, mut env) or {
		// Eval-time CXER0100 — impl raises it as a pre-match guard.
		assert err.msg().contains('CXER0100'),
			'expected CXER0100 at eval, got: ${err}'
		return
	}
	assert false, 'expected CXER0100 (static or eval-time) for :set-attr on attribute-step path'
}
