module main

import cx

// Tests for the Phase 2.3 CXPath parser entry point.
//
// Covers grammar productions [130]–[131b] + [135]:
//   - Form discriminator (absolute / descendant / relative / binding)
//   - Multi-step paths per [130a] including interior `//` shorthand
//   - AxisSpecifier prefix per [131a]
//   - NodeTest: bare Name, `*` wildcard, kind-tests, prefixed QName per [131b]
//   - Multi-predicate steps per [132]
//   - BindingPath descendant `$u//item` per [135]
//   - Trailing predicates surface at last step (greedy [131] per spec)
//   - §D12 step-terminator rule — path ends at `:LABEL` modifier-keyword
//     boundary without consuming the `:`
//
// Still deferred (covered by explicit error assertions):
//   - Namespace-wildcard `*:Local` / `Prefix:*` → CXPATH_NODETEST_*
//     (deferred pending namespace resolution hook; Phase 2.x follow-up)

// ── Form discriminator ────────────────────────────────────────────────────────

fn test_parse_path_form_descendant() {
	p := cx.parse_path('//user') or {
		assert false, 'parse_path("//user") failed: ${err}'
		return
	}
	assert p.form == cx.PathForm.descendant
	assert p.binding == none
	assert p.steps.len == 1
	assert p.steps[0].axis == cx.PathAxis.child
	assert p.steps[0].node_test == 'user'
	assert p.steps[0].predicates.len == 0
}

fn test_parse_path_form_absolute() {
	p := cx.parse_path('/user') or {
		assert false, 'parse_path("/user") failed: ${err}'
		return
	}
	assert p.form == cx.PathForm.absolute
	assert p.binding == none
	assert p.steps.len == 1
	assert p.steps[0].node_test == 'user'
}

fn test_parse_path_form_relative() {
	p := cx.parse_path('user') or {
		assert false, 'parse_path("user") failed: ${err}'
		return
	}
	assert p.form == cx.PathForm.relative
	assert p.binding == none
	assert p.steps.len == 1
	assert p.steps[0].node_test == 'user'
}

fn test_parse_path_form_binding() {
	p := cx.parse_path('\$u/email') or {
		assert false, 'parse_path("\$u/email") failed: ${err}'
		return
	}
	assert p.form == cx.PathForm.binding
	if b := p.binding {
		assert b == 'u'
	} else {
		assert false, 'expected binding name set'
	}
	assert p.steps.len == 1
	assert p.steps[0].axis == cx.PathAxis.child
	assert p.steps[0].node_test == 'email'
}

// ── Axis variants ─────────────────────────────────────────────────────────────

fn test_parse_path_axis_descendant() {
	p := cx.parse_path('//descendant::user') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.form == cx.PathForm.descendant
	assert p.steps[0].axis == cx.PathAxis.descendant
	assert p.steps[0].node_test == 'user'
}

fn test_parse_path_axis_child_explicit() {
	p := cx.parse_path('//child::user') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps[0].axis == cx.PathAxis.child
	assert p.steps[0].node_test == 'user'
}

fn test_parse_path_axis_parent() {
	p := cx.parse_path('//parent::user') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps[0].axis == cx.PathAxis.parent
}

fn test_parse_path_axis_attribute_explicit() {
	p := cx.parse_path('//attribute::name') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps[0].axis == cx.PathAxis.attribute
	assert p.steps[0].node_test == 'name'
}

fn test_parse_path_axis_descendant_or_self() {
	p := cx.parse_path('//descendant-or-self::node_name') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps[0].axis == cx.PathAxis.descendant_or_self
}

fn test_parse_path_attribute_sugar() {
	p := cx.parse_path('//@name') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps[0].axis == cx.PathAxis.attribute
	assert p.steps[0].node_test == 'name'
}

// ── Predicate variants ────────────────────────────────────────────────────────

fn test_parse_path_predicate_attrtest() {
	p := cx.parse_path('//user[@active]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps[0].node_test == 'user'
	assert p.steps[0].predicates.len == 1
	assert p.steps[0].predicates[0].source == '@active'
}

fn test_parse_path_predicate_with_quoted_string() {
	src := '//user[@name = "alice"]'
	p := cx.parse_path(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps[0].predicates.len == 1
	assert p.steps[0].predicates[0].source == '@name = "alice"'
}

fn test_parse_path_predicate_with_nested_brackets() {
	// Predicate body may contain nested brackets (e.g. a sequence literal).
	// Reader must depth-track to find the matching `]`.
	src := '//user[[1, 2, 3]]'
	p := cx.parse_path(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps[0].predicates.len == 1
	assert p.steps[0].predicates[0].source == '[1, 2, 3]'
}

// ── Source + loc set ──────────────────────────────────────────────────────────

fn test_parse_path_sets_source_and_loc() {
	src := '//user[@active]'
	p := cx.parse_path(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	if s := p.source {
		assert s == src
	} else {
		assert false, 'source should be set'
	}
	if l := p.loc {
		assert l.line == 1
		assert l.col == 1
	} else {
		assert false, 'loc should be set'
	}
}

// ── Round-trip with hand-constructed PathNode (eq excludes source/loc) ────────

fn test_parse_path_round_trip_eq_hand_constructed() {
	parsed := cx.parse_path('//user[@active=true]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	hand := cx.PathNode{
		form: cx.PathForm.descendant
		steps: [
			cx.PathStep{
				axis:       cx.PathAxis.child
				node_test:  'user'
				predicates: [cx.PathPredicate{ source: '@active=true' }]
			},
		]
	}
	assert parsed.eq(hand)
	// Symmetric.
	assert hand.eq(parsed)
}

fn test_parse_path_round_trip_binding_eq() {
	parsed := cx.parse_path('\$u/email') or {
		assert false, 'parse failed: ${err}'
		return
	}
	hand := cx.PathNode{
		form:    cx.PathForm.binding
		binding: 'u'
		steps:   [
			cx.PathStep{
				axis:      cx.PathAxis.child
				node_test: 'email'
			},
		]
	}
	assert parsed.eq(hand)
}

// ── Multi-step paths ([130a]) ─────────────────────────────────────────────────

fn test_parse_path_multi_step_descendant_two() {
	p := cx.parse_path('//user/email') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.form == cx.PathForm.descendant
	assert p.steps.len == 2
	assert p.steps[0].node_test == 'user'
	assert p.steps[0].axis == cx.PathAxis.child
	assert p.steps[1].node_test == 'email'
	assert p.steps[1].axis == cx.PathAxis.child
}

fn test_parse_path_multi_step_absolute_three() {
	p := cx.parse_path('/users/user/name') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.form == cx.PathForm.absolute
	assert p.steps.len == 3
	assert p.steps[0].node_test == 'users'
	assert p.steps[1].node_test == 'user'
	assert p.steps[2].node_test == 'name'
}

fn test_parse_path_multi_step_relative_three() {
	p := cx.parse_path('parent/child/grandchild') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.form == cx.PathForm.relative
	assert p.steps.len == 3
	assert p.steps[0].node_test == 'parent'
	assert p.steps[1].node_test == 'child'
	assert p.steps[2].node_test == 'grandchild'
}

fn test_parse_path_multi_step_binding() {
	p := cx.parse_path('\$u/email/text') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.form == cx.PathForm.binding
	if b := p.binding {
		assert b == 'u'
	} else {
		assert false, 'expected binding name set'
	}
	assert p.steps.len == 2
	assert p.steps[0].node_test == 'email'
	assert p.steps[1].node_test == 'text'
}

fn test_parse_path_multi_step_mixed_axes() {
	p := cx.parse_path('/root/child::user/@name') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps.len == 3
	assert p.steps[0].axis == cx.PathAxis.child
	assert p.steps[0].node_test == 'root'
	assert p.steps[1].axis == cx.PathAxis.child
	assert p.steps[1].node_test == 'user'
	assert p.steps[2].axis == cx.PathAxis.attribute
	assert p.steps[2].node_test == 'name'
}

// ── Multi-predicate steps ([132] `Predicate*`) ────────────────────────────────

fn test_parse_path_multi_predicate_two_attrtests() {
	p := cx.parse_path('//user[@active][@verified]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps.len == 1
	assert p.steps[0].node_test == 'user'
	assert p.steps[0].predicates.len == 2
	assert p.steps[0].predicates[0].source == '@active'
	assert p.steps[0].predicates[1].source == '@verified'
}

fn test_parse_path_multi_predicate_index_then_attr() {
	p := cx.parse_path('//user[1][@name="alice"]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps[0].predicates.len == 2
	assert p.steps[0].predicates[0].source == '1'
	assert p.steps[0].predicates[1].source == '@name="alice"'
}

fn test_parse_path_multi_predicate_three_bare() {
	p := cx.parse_path('//user[a][b][c]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps[0].predicates.len == 3
	assert p.steps[0].predicates[0].source == 'a'
	assert p.steps[0].predicates[1].source == 'b'
	assert p.steps[0].predicates[2].source == 'c'
}

// ── Wildcard `*` NodeTest ([131b]) ────────────────────────────────────────────

fn test_parse_path_wildcard_descendant() {
	p := cx.parse_path('//*') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.form == cx.PathForm.descendant
	assert p.steps.len == 1
	assert p.steps[0].node_test == '*'
	assert p.steps[0].axis == cx.PathAxis.child
}

fn test_parse_path_wildcard_step_after_name() {
	p := cx.parse_path('//user/*') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps.len == 2
	assert p.steps[0].node_test == 'user'
	assert p.steps[1].node_test == '*'
}

fn test_parse_path_wildcard_mid_path() {
	p := cx.parse_path('/users/*/name') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.form == cx.PathForm.absolute
	assert p.steps.len == 3
	assert p.steps[0].node_test == 'users'
	assert p.steps[1].node_test == '*'
	assert p.steps[2].node_test == 'name'
}

fn test_parse_path_wildcard_with_predicate() {
	p := cx.parse_path('*[@active]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.form == cx.PathForm.relative
	assert p.steps.len == 1
	assert p.steps[0].node_test == '*'
	assert p.steps[0].predicates.len == 1
	assert p.steps[0].predicates[0].source == '@active'
}

// ── step-terminator (modifier-keyword boundary) ─────────────────

fn test_parse_path_consumed_stops_at_modifier_keyword() {
	src := '//user :using rest'
	node, consumed := cx.parse_path_consumed(src) or {
		assert false, 'parse_path_consumed failed: ${err}'
		return
	}
	assert node.form == cx.PathForm.descendant
	assert node.steps.len == 1
	assert node.steps[0].node_test == 'user'
	// `consumed` should point at the space before `:using` — the caller
	// (e.g., `[?modify]` parser) handles the modifier.
	assert consumed < src.len
	assert src[consumed..] == ' :using rest', 'expected " :using rest", got "${src[consumed..]}"'
}

fn test_parse_path_consumed_stops_at_step_trailing_modifier() {
	// §D12 worked example: `//foo :using …` — the `:using`
	// belongs to the enclosing directive (e.g. `[?modify]` action), not
	// the NodeTest. The `:` is preceded by whitespace here.
	src := '//foo :using [?fn]'
	node, consumed := cx.parse_path_consumed(src) or {
		assert false, 'parse_path_consumed failed: ${err}'
		return
	}
	assert node.steps.len == 1
	assert node.steps[0].node_test == 'foo'
	assert src[consumed..] == ' :using [?fn]', 'expected " :using [?fn]", got "${src[consumed..]}"'
}

fn test_parse_path_consumed_no_space_modifier_terminates() {
	// §D12: the `:` immediately after a NodeTest, when the next-after-`:`
	// label is in the closed set, is ALSO a terminator (no whitespace
	// required between NodeTest and `:LABEL`).
	src := '//foo:using rest'
	node, consumed := cx.parse_path_consumed(src) or {
		assert false, 'parse_path_consumed failed: ${err}'
		return
	}
	assert node.steps.len == 1
	assert node.steps[0].node_test == 'foo'
	assert src[consumed..] == ':using rest', 'expected ":using rest", got "${src[consumed..]}"'
}

fn test_parse_path_consumed_full_consume_no_modifier() {
	src := '//user/email'
	node, consumed := cx.parse_path_consumed(src) or {
		assert false, 'parse_path_consumed failed: ${err}'
		return
	}
	assert node.steps.len == 2
	assert consumed == src.len, 'expected full consume, got consumed=${consumed} src.len=${src.len}'
}

fn test_parse_path_rejects_empty_nodetest_before_modifier() {
	// `// :bind u` — no node test before the modifier; this is genuinely
	// malformed (the path slot is empty), not a §D12 step-terminator.
	_ := cx.parse_path('// :bind u') or {
		// Any error is acceptable; just assert it's not a successful parse.
		return
	}
	assert false, '`// :bind u` should have errored (empty node test)'
}

// ── Kind-tests ([131b]: node() / text() / element() / attribute()) ───────────

fn test_parse_path_kindtest_node() {
	p := cx.parse_path('//node()') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.form == cx.PathForm.descendant
	assert p.steps.len == 1
	assert p.steps[0].axis == cx.PathAxis.child
	assert p.steps[0].node_test == 'node()'
	assert p.steps[0].predicates.len == 0
}

fn test_parse_path_kindtest_text() {
	p := cx.parse_path('//text()') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps[0].node_test == 'text()'
}

fn test_parse_path_kindtest_element() {
	p := cx.parse_path('/element()') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.form == cx.PathForm.absolute
	assert p.steps[0].node_test == 'element()'
}

fn test_parse_path_kindtest_attribute() {
	// `attribute()` (parens, no name) is the kind-test variant, distinct
	// from the `attribute::` axis prefix or the `@name` sugar.
	p := cx.parse_path('//attribute()') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps[0].axis == cx.PathAxis.child
	assert p.steps[0].node_test == 'attribute()'
}

fn test_parse_path_kindtest_mid_path_with_predicate() {
	p := cx.parse_path('//user/text()[1]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps.len == 2
	assert p.steps[0].node_test == 'user'
	assert p.steps[1].node_test == 'text()'
	assert p.steps[1].predicates.len == 1
	assert p.steps[1].predicates[0].source == '1'
}

fn test_parse_path_unknown_kindtest_errors() {
	// Only the four canonical kind-tests are admitted; arbitrary
	// `Name '('` is a parse error (callers wanting a function call use
	// the predicate body, not the NodeTest).
	_ := cx.parse_path('//bogus()') or {
		assert err.msg().contains('unknown kind-test'),
			'expected unknown-kind-test error, got: ${err}'
		return
	}
	assert false, '`//bogus()` should have errored'
}

// ── Prefixed QName NodeTest ([131b]: prefix:local) ───────────────────────────

fn test_parse_path_qname_xml_lang() {
	// `xml:lang` is the canonical XML-namespace example. At v0.8.0 the
	// prefix is recorded verbatim in `node_test`; namespace resolution
	// against an in-scope xmlns map is a Phase 2.x follow-up.
	p := cx.parse_path('//xml:lang') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.form == cx.PathForm.descendant
	assert p.steps.len == 1
	assert p.steps[0].axis == cx.PathAxis.child
	assert p.steps[0].node_test == 'xml:lang'
}

fn test_parse_path_qname_xsi_type() {
	p := cx.parse_path('/xsi:type') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.form == cx.PathForm.absolute
	assert p.steps[0].node_test == 'xsi:type'
}

fn test_parse_path_qname_with_axis() {
	p := cx.parse_path('//attribute::xml:lang') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps[0].axis == cx.PathAxis.attribute
	assert p.steps[0].node_test == 'xml:lang'
}

fn test_parse_path_qname_with_predicate() {
	p := cx.parse_path('//ns:user[@active]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps[0].node_test == 'ns:user'
	assert p.steps[0].predicates.len == 1
	assert p.steps[0].predicates[0].source == '@active'
}

fn test_parse_path_qname_step_terminator_modifier_kw() {
	// §D12: when the local-name slot is a modifier keyword (`using`),
	// the `:` is NOT consumed by the QName rule — the step terminates
	// at the bare `prefix` NodeTest and the `:using` belongs to the
	// enclosing directive.
	src := '//foo:using rest'
	// `foo` is NOT a modifier keyword, but `using` IS — so `:using`
	// terminates the path with node_test=`foo`.
	node, consumed := cx.parse_path_consumed(src) or {
		assert false, 'parse_path_consumed failed: ${err}'
		return
	}
	assert node.steps[0].node_test == 'foo'
	assert src[consumed..] == ':using rest'
}

fn test_parse_path_qname_missing_local_errors() {
	_ := cx.parse_path('//xml:') or {
		// `xml:` with no local name and nothing after → empty input after `:`
		// is handled by `path_step_colon_terminates` (bare `:` terminates),
		// so this actually succeeds with node_test=`xml` and consumed<len.
		// Use parse_path (full-consume entry) to ensure error.
		return
	}
	// If we got here without erroring, the trailing `:` would have been
	// consumed as a §D12 terminator and parse_path's full-consume check
	// should fail. Either way, the result is an error.
	assert false, '`//xml:` should have errored on full-consume'
}

// ── Interior `//` descendant shorthand ([130a]) ──────────────────────────────

fn test_parse_path_interior_descendant_two_steps() {
	// `//a//b` — leading `//` sets form=.descendant; interior `//`
	// lowers to axis=.descendant_or_self on the next step.
	p := cx.parse_path('//a//b') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.form == cx.PathForm.descendant
	assert p.steps.len == 2
	assert p.steps[0].axis == cx.PathAxis.child
	assert p.steps[0].node_test == 'a'
	assert p.steps[1].axis == cx.PathAxis.descendant_or_self
	assert p.steps[1].node_test == 'b'
}

fn test_parse_path_interior_descendant_absolute() {
	// `/a//b` — leading `/` sets form=.absolute; interior `//` re-axes
	// the second step.
	p := cx.parse_path('/a//b') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.form == cx.PathForm.absolute
	assert p.steps.len == 2
	assert p.steps[0].axis == cx.PathAxis.child
	assert p.steps[1].axis == cx.PathAxis.descendant_or_self
	assert p.steps[1].node_test == 'b'
}

fn test_parse_path_interior_descendant_three_steps() {
	p := cx.parse_path('/a/b//c') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps.len == 3
	assert p.steps[0].node_test == 'a'
	assert p.steps[0].axis == cx.PathAxis.child
	assert p.steps[1].node_test == 'b'
	assert p.steps[1].axis == cx.PathAxis.child
	assert p.steps[2].node_test == 'c'
	assert p.steps[2].axis == cx.PathAxis.descendant_or_self
}

fn test_parse_path_interior_descendant_with_predicate() {
	p := cx.parse_path('//a//b[@x]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps.len == 2
	assert p.steps[1].axis == cx.PathAxis.descendant_or_self
	assert p.steps[1].node_test == 'b'
	assert p.steps[1].predicates.len == 1
	assert p.steps[1].predicates[0].source == '@x'
}

// ── BindingPath descendant `$u//item` ([135]) ────────────────────────────────

fn test_parse_path_binding_descendant() {
	p := cx.parse_path('\$u//item') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.form == cx.PathForm.binding
	if b := p.binding {
		assert b == 'u'
	} else {
		assert false, 'expected binding name set'
	}
	assert p.steps.len == 1
	assert p.steps[0].axis == cx.PathAxis.descendant_or_self
	assert p.steps[0].node_test == 'item'
}

fn test_parse_path_binding_descendant_multi_step() {
	p := cx.parse_path('\$u//item/name') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.form == cx.PathForm.binding
	assert p.steps.len == 2
	assert p.steps[0].axis == cx.PathAxis.descendant_or_self
	assert p.steps[0].node_test == 'item'
	assert p.steps[1].axis == cx.PathAxis.child
	assert p.steps[1].node_test == 'name'
}

fn test_parse_path_binding_descendant_with_predicate() {
	p := cx.parse_path('\$u//item[@active]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.form == cx.PathForm.binding
	assert p.steps.len == 1
	assert p.steps[0].axis == cx.PathAxis.descendant_or_self
	assert p.steps[0].predicates.len == 1
	assert p.steps[0].predicates[0].source == '@active'
}

// ── Trailing predicates greedy-attach to last step per [131] ─────────────────
//
// The PathNode AST exposes a top-level `predicates` slot for trailing
// predicates per [135]'s `Predicate*` tail (used by Phase 2.4 evaluator
// and programmatic AST manipulation). At the surface grammar level there
// is no syntactic distinguisher between step-predicates and top-level
// predicates — both spell `[…]` immediately after a NodeTest — so the
// parser greedily attaches all `[…]` to the last step per [131]'s
// `Predicate*`. This is spec-correct: top-level predicates are only
// reachable via hand-constructed PathNodes at v0.8.0.
//
// TODO(Phase 2.x): if/when a parenthesised path-expression surface lands
// (e.g., `(//user)[1]` per future grammar amendment) the parser will
// route predicates following `)` to `node.predicates`.

fn test_parse_path_trailing_predicates_attach_to_last_step() {
	// `//user[1][2]` — both predicates attach to the `user` step per
	// [131] greedy `Predicate*`. Top-level node.predicates remains empty.
	p := cx.parse_path('//user[1][2]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps.len == 1
	assert p.steps[0].node_test == 'user'
	assert p.steps[0].predicates.len == 2
	assert p.steps[0].predicates[0].source == '1'
	assert p.steps[0].predicates[1].source == '2'
	// Verify the top-level slot is reachable on the AST but empty
	// (programmatic construction sets it; the surface parser doesn't).
	assert p.predicates.len == 0
}

fn test_parse_path_binding_trailing_predicates_attach_to_last_step() {
	// Per [135] BindingPath ::= '$' Name ( '/' Step )+ Predicate* — the
	// tail Predicate* is syntactically indistinguishable from the last
	// step's Predicate* and greedy-attaches there. AST round-trip with
	// a hand-constructed top-level-predicate node remains supported.
	p := cx.parse_path('\$u/item[1]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps.len == 1
	assert p.steps[0].predicates.len == 1
	assert p.predicates.len == 0
}

fn test_parse_path_hand_constructed_top_level_predicates_round_trip_eq() {
	// A hand-constructed PathNode with top-level predicates compares
	// equal under .eq() — verifying the AST slot is fully wired even
	// though the parser doesn't surface it.
	parsed := cx.parse_path('//user[1]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	hand_step_pred := cx.PathNode{
		form: cx.PathForm.descendant
		steps: [
			cx.PathStep{
				axis:       cx.PathAxis.child
				node_test:  'user'
				predicates: [cx.PathPredicate{ source: '1' }]
			},
		]
	}
	assert parsed.eq(hand_step_pred)
	// And the top-level-predicate variant compares UNEQUAL — both
	// shapes are AST-distinct even though source surface coincides.
	hand_top_pred := cx.PathNode{
		form:       cx.PathForm.descendant
		steps:      [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user' }]
		predicates: [cx.PathPredicate{ source: '1' }]
	}
	assert !parsed.eq(hand_top_pred)
}

// ── Still-deferred features (namespace-wildcards) ────────────────────────────

fn test_parse_path_namespace_wildcard_local_deferred() {
	// `*:Local` — namespace-wildcard-with-local-name; still deferred
	// pending the namespace resolution hook.
	_ := cx.parse_path('//*:local') or {
		assert err.msg().contains('CXPATH_NODETEST_NOT_YET_IMPLEMENTED'),
			'expected namespace-wildcard deferred error, got: ${err}'
		return
	}
	assert false, 'namespace-wildcard `//*:local` should have errored'
}

fn test_parse_path_namespace_prefix_wildcard_deferred() {
	// `Prefix:*` — namespace-prefix-with-wildcard-local; still deferred.
	_ := cx.parse_path('//xml:*') or {
		assert err.msg().contains('CXPATH_NODETEST_NOT_YET_IMPLEMENTED'),
			'expected namespace-prefix-wildcard deferred error, got: ${err}'
		return
	}
	assert false, 'namespace-prefix-wildcard `//xml:*` should have errored'
}

// ── Hard parse-error cases (not deferred — genuinely malformed) ───────────────

fn test_parse_path_empty_input_errors() {
	_ := cx.parse_path('') or { return }
	assert false, 'empty input should error'
}

fn test_parse_path_unknown_axis_errors() {
	_ := cx.parse_path('//bogus::user') or {
		assert err.msg().contains('unknown axis'),
			'expected unknown-axis error, got: ${err}'
		return
	}
	assert false, 'unknown axis should error'
}

// ── `:bind NCName` peer-modifier on PathStep (Phase 2.20) ────────

fn test_parse_path_bind_single_step() {
	// `//user :bind u` — step's binding captured as "u".
	p := cx.parse_path('//user :bind u') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.form == cx.PathForm.descendant
	assert p.steps.len == 1
	assert p.steps[0].node_test == 'user'
	if b := p.steps[0].binding {
		assert b == 'u'
	} else {
		assert false, 'expected step.binding=u, got none'
	}
	assert p.steps[0].predicates.len == 0
}

fn test_parse_path_bind_then_step_separator() {
	// `//user :bind u / member` — step 1 binds "u"; step 2 has no binding.
	p := cx.parse_path('//user :bind u / member') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps.len == 2
	assert p.steps[0].node_test == 'user'
	if b := p.steps[0].binding {
		assert b == 'u'
	} else {
		assert false, 'expected step[0].binding=u'
	}
	assert p.steps[1].node_test == 'member'
	assert p.steps[1].binding == none
}

fn test_parse_path_bind_then_predicate() {
	// `//user :bind u [@active]` — step's binding + one trailing predicate.
	p := cx.parse_path('//user :bind u [@active]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps.len == 1
	assert p.steps[0].node_test == 'user'
	if b := p.steps[0].binding {
		assert b == 'u'
	} else {
		assert false, 'expected step.binding=u'
	}
	assert p.steps[0].predicates.len == 1
	assert p.steps[0].predicates[0].source == '@active'
}

fn test_parse_path_bind_no_whitespace_after_colon_bind() {
	// `//user:bind u` — `:bind` consumed at NodeTest QName-disambiguation
	// boundary (`bind` is in the closed terminator set), then the peer-
	// modifier slot picks it up from there. End result: step.binding=u.
	p := cx.parse_path('//user:bind u') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps.len == 1
	assert p.steps[0].node_test == 'user'
	if b := p.steps[0].binding {
		assert b == 'u'
	} else {
		assert false, 'expected step.binding=u'
	}
}

fn test_parse_path_bind_underscore_rejected() {
	// `:bind _` — `_` is reserved for the implicit `$_` context binding
	// gate 36.6 requires CXER0232.
	_ := cx.parse_path('//user :bind _') or {
		assert err.msg().contains('CXER0232'),
			'expected CXER0232 RESERVED_BIND_NAME error, got: ${err}'
		return
	}
	assert false, '`:bind _` should have errored'
}

fn test_parse_path_bind_missing_name_rejected() {
	// `:bind` with no following identifier — parse error.
	_ := cx.parse_path('//user :bind') or {
		// Any parse error is acceptable; assert it mentions NCName / bind.
		assert err.msg().contains('NCName') || err.msg().contains(':bind'),
			'expected NCName-after-:bind error, got: ${err}'
		return
	}
	assert false, '`:bind` without identifier should have errored'
}

fn test_parse_path_bind_relative_form() {
	// `:bind` works on a relative path too — the grammar [160] doesn't
	// care about the form discriminator.
	p := cx.parse_path('user :bind u') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.form == cx.PathForm.relative
	assert p.steps.len == 1
	if b := p.steps[0].binding {
		assert b == 'u'
	} else {
		assert false, 'expected step.binding=u'
	}
}

fn test_parse_path_bind_binding_form_cross_step() {
	// worked example 4 shape: `//team :bind t / member`
	// the outer step binds the team focus under `t`; downstream
	// predicates (Phase 2.21) can reference `$t`.
	p := cx.parse_path('//team :bind t / member') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert p.steps.len == 2
	assert p.steps[0].node_test == 'team'
	if b := p.steps[0].binding {
		assert b == 't'
	} else {
		assert false, 'expected step[0].binding=t'
	}
	assert p.steps[1].node_test == 'member'
	assert p.steps[1].binding == none
}

// ── `:bind` round-trip via renderer (PathNode → text → PathNode) ──────────────

fn test_parse_path_bind_round_trip_render() {
	// parse → render → parse → .eq() — the peer-modifier survives a
	// canonical-text round-trip.
	parsed := cx.parse_path('//user :bind u') or {
		assert false, 'parse failed: ${err}'
		return
	}
	rendered := cx.render_path(parsed)
	reparsed := cx.parse_path(rendered) or {
		assert false, 're-parse of "${rendered}" failed: ${err}'
		return
	}
	assert parsed.eq(reparsed), 'round-trip failed: rendered=${rendered}'
}

fn test_parse_path_bind_round_trip_with_predicate() {
	parsed := cx.parse_path('//user :bind u [@active]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	rendered := cx.render_path(parsed)
	reparsed := cx.parse_path(rendered) or {
		assert false, 're-parse of "${rendered}" failed: ${err}'
		return
	}
	assert parsed.eq(reparsed), 'round-trip failed: rendered=${rendered}'
}

fn test_parse_path_bind_round_trip_cross_step() {
	parsed := cx.parse_path('//team :bind t / member') or {
		assert false, 'parse failed: ${err}'
		return
	}
	rendered := cx.render_path(parsed)
	reparsed := cx.parse_path(rendered) or {
		assert false, 're-parse of "${rendered}" failed: ${err}'
		return
	}
	assert parsed.eq(reparsed), 'round-trip failed: rendered=${rendered}'
}

// ── `:bind` equality + hashing (identity-relevant) ────────────

fn test_parse_path_bind_eq_distinguishes_bindings() {
	// Two PathNodes differing ONLY in the `:bind NAME` should compare
	// unequal under .eq() — the binding is identity-relevant because it
	// changes the path's downstream visible names.
	a := cx.PathNode{
		form:  cx.PathForm.descendant
		steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user',
		                     binding: 'u' }]
	}
	b := cx.PathNode{
		form:  cx.PathForm.descendant
		steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user',
		                     binding: 'v' }]
	}
	assert !a.eq(b)
	// And vs. a no-binding step:
	c := cx.PathNode{
		form:  cx.PathForm.descendant
		steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user' }]
	}
	assert !a.eq(c)
}

fn test_parse_path_bind_hash_distinguishes_bindings() {
	// Canonical-bytes hashing includes step.binding when present, so
	// two otherwise-equal paths with different bindings hash distinct.
	a := cx.PathNode{
		form:  cx.PathForm.descendant
		steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user',
		                     binding: 'u' }]
	}
	b := cx.PathNode{
		form:  cx.PathForm.descendant
		steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user',
		                     binding: 'v' }]
	}
	assert cx.path_node_hash(a) != cx.path_node_hash(b)
	// A binding-less step also hashes distinct from a binding-bearing one.
	c := cx.PathNode{
		form:  cx.PathForm.descendant
		steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user' }]
	}
	assert cx.path_node_hash(a) != cx.path_node_hash(c)
}

fn test_parse_path_bind_parsed_eq_hand_constructed() {
	// Parser-produced PathNode with `:bind` compares equal to a hand-
	// constructed shape carrying the same binding.
	parsed := cx.parse_path('//user :bind u') or {
		assert false, 'parse failed: ${err}'
		return
	}
	hand := cx.PathNode{
		form:  cx.PathForm.descendant
		steps: [cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user',
		                     binding: 'u' }]
	}
	assert parsed.eq(hand)
	assert hand.eq(parsed)
}
