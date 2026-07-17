module code

// let_collapse_test.v — unit coverage for the #361 cascading-let collapse
// (see let_collapse.v). Each case exercises one edge from the issue's
// checklist; the semantic backstop is the conformance suite run over the
// swept fixtures.

fn test_basic_two_level_collapse() {
	src := '[?let [= \$a 1]\n  [?let [= \$b 2]\n    [+ \$a \$b]]]\n'
	out := collapse_nested_lets(src) or { panic(err) }
	assert out == '[?let [= \$a 1]\n  [= \$b 2]\n  [+ \$a \$b]]\n'
}

fn test_three_level_chain_single_pass() {
	src := '[?let [= \$a 1]\n [?let [= \$b 2]\n  [?let [= \$c 3]\n   [+ \$a [+ \$b \$c]]]]]\n'
	out := collapse_nested_lets(src) or { panic(err) }
	assert out == '[?let [= \$a 1]\n [= \$b 2]\n [= \$c 3]\n [+ \$a [+ \$b \$c]]]\n'
}

fn test_comment_between_bindings_preserved() {
	src := '[?let [= \$a 1]\n  # picks the port\n  [?let [= \$b 2]\n    [+ \$a \$b]]]\n'
	out := collapse_nested_lets(src) or { panic(err) }
	assert out.contains('# picks the port')
	assert out == '[?let [= \$a 1]\n  # picks the port\n  [= \$b 2]\n  [+ \$a \$b]]\n'
}

fn test_block_comment_inside_inner_preserved() {
	src := '[?let [= \$a 1]\n  [?let [= \$b 2] [; owner note ]\n    [+ \$a \$b]]]\n'
	out := collapse_nested_lets(src) or { panic(err) }
	assert out.contains('[; owner note ]')
}

fn test_inner_let_not_sole_body_untouched() {
	// The inner let is a BINDING VALUE, not the body — no site.
	src := '[?let [= \$a [?let [= \$x 1] \$x]] [+ \$a 1]]\n'
	out := collapse_nested_lets(src) or { panic(err) }
	assert out == src
}

fn test_equality_shaped_body_not_swallowed() {
	// `[= $a $b]` in LAST position is the body (equality), not a binding;
	// there is no inner let, so nothing changes.
	src := '[?let [= \$a 1] [= \$b 1] [= \$a \$b]]\n'
	out := collapse_nested_lets(src) or { panic(err) }
	assert out == src
}

fn test_let_inside_string_untouched() {
	src := '[?let [= \$s "[?let [= \$x 1] \$x]"] \$s]\n'
	out := collapse_nested_lets(src) or { panic(err) }
	assert out == src
}

fn test_bindingless_outer_wrapper_is_a_parse_error() {
	// `[?let [?let …]]` does not parse: parse_let_body requires the first
	// child to be a `[…]` clause opened by a plain `[` (a directive opener
	// `[?` is the retired-legacy error branch). Such a site cannot exist in
	// a valid file, and the tool must surface the parse failure rather than
	// rewrite unparseable text.
	if _ := collapse_nested_lets('[?let [?let [= \$a 1] \$a]]\n') {
		panic('expected parse error for bindingless [?let [?let …]] wrapper')
	}
}

fn test_multiline_string_indentation_untouched() {
	// The dedent pass must not strip spaces inside a multi-line string that
	// spans the pulled-up region.
	src := '[?let [= \$a 1]\n  [?let [= \$b "x\n    keep-these-spaces\n"]\n    [\$concat \$b [\$text \$a]]]]\n'
	out := collapse_nested_lets(src) or { panic(err) }
	assert out.contains('\n    keep-these-spaces\n')
}

fn test_postfix_bang_body_untouched() {
	src := '[?let [= \$a 1] [\$f \$a]!]\n'
	out := collapse_nested_lets(src) or { panic(err) }
	assert out == src
}

fn test_non_binding_preceding_child_skips_site() {
	// A malformed let (non-binding clause before the body) is left alone.
	src := '[?let [\$side-effect] [?let [= \$b 2] \$b]]\n'
	out := collapse_nested_lets(src) or { panic(err) }
	assert out == src
}

fn test_cxd_in_code_blocks_only() {
	src := '[test-suite name=t\n [case id=001\n  [in-code [#\n[?let [= \$a 1]\n [?let [= \$b 2]\n  [+ \$a \$b]]]\n#]]\n  [in-cx [#\n[?let [= \$a 1]\n [?let [= \$b 2]\n  [+ \$a \$b]]]\n#]]\n  [out-cx [#\n[?let [= \$a 1]\n [?let [= \$b 2]\n  [+ \$a \$b]]]\n#]]\n ]\n]\n'
	out := collapse_nested_lets_cxd(src) or { panic(err) }
	// in-code (the program) collapsed…
	assert out.contains('[in-code [#\n[?let [= \$a 1]\n [= \$b 2]\n [+ \$a \$b]]\n#]]')
	// …in-cx (the input DOCUMENT — test data) byte-identical…
	assert out.contains('[in-cx [#\n[?let [= \$a 1]\n [?let [= \$b 2]\n  [+ \$a \$b]]]\n#]]')
	// …expected-output block byte-identical.
	assert out.contains('[out-cx [#\n[?let [= \$a 1]\n [?let [= \$b 2]\n  [+ \$a \$b]]]\n#]]')
}

fn test_unparseable_input_errors_not_corrupts() {
	if _ := collapse_nested_lets('[?let [= $a') {
		panic('expected error on unparseable input')
	}
}

fn test_md_cx_fences_only() {
	src := '# Title\n\nProse with [?let untouched.\n\n```cx\n[?let [= \$a 1]\n [?let [= \$b 2]\n  [+ \$a \$b]]]\n```\n\n```json\n{"not": "[?let [?let]]"}\n```\n'
	out := collapse_nested_lets_md(src) or { panic(err) }
	assert out.contains('```cx\n[?let [= \$a 1]\n [= \$b 2]\n [+ \$a \$b]]\n```')
	assert out.contains('Prose with [?let untouched.')
	assert out.contains('{"not": "[?let [?let]]"}')
}
