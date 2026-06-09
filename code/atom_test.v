module code

import cx

// atom_test.v — unit tests for atom literal in the CX code
// surface. Mirrors gates 33.1 (parse) + 33.2 (equality) + 33.4 (render)
// + 33.5 (reserved-name rejection) at the code layer.

fn test_atom_lit_parses_to_program_literal() {
	prog := cx.parse_program(':ok') or {
		assert false, 'parse :ok failed: $err'
		return
	}
	body := prog.body
	if body is cx.ProgramLiteral {
		assert body.kind == .atom_lit, 'expected atom_lit, got ${body.kind}'
		assert body.str_val == 'ok', 'expected name "ok", got "${body.str_val}"'
	} else {
		assert false, 'expected cx.ProgramLiteral, got ${body.type_name()}'
	}
}

fn test_atom_lit_evaluates_to_atom_scalar_node() {
	prog := cx.parse_program(':ok') or {
		assert false, 'parse failed: $err'
		return
	}
	mut env := new_env()
	result := eval(prog.body, mut env) or {
		assert false, 'eval failed: $err'
		return
	}
	assert result is cx.ScalarNode
	s := result as cx.ScalarNode
	assert s.data_type == .atom_type, 'expected atom_type, got ${s.data_type}'
	v := s.value as string
	assert v == 'ok'
}

fn test_atom_lit_with_kebab_name() {
	prog := cx.parse_program(':not-found') or {
		assert false, 'parse failed: $err'
		return
	}
	mut env := new_env()
	result := eval(prog.body, mut env) or {
		assert false, 'eval failed: $err'
		return
	}
	s := result as cx.ScalarNode
	assert s.data_type == .atom_type
	v := s.value as string
	assert v == 'not-found'
}

fn test_atom_lit_reserved_true_raises_parse_error() {
	_ := cx.parse_program(':true') or {
		// Expected — reserved.
		assert err.msg().contains('CXER0100'), 'expected CXER0100, got: ${err.msg()}'
		return
	}
	assert false, ':true should not parse as atom literal'
}

fn test_atom_lit_reserved_false_raises_parse_error() {
	_ := cx.parse_program(':false') or {
		assert err.msg().contains('CXER0100')
		return
	}
	assert false, ':false should not parse as atom literal'
}

fn test_atom_lit_reserved_null_raises_parse_error() {
	_ := cx.parse_program(':null') or {
		assert err.msg().contains('CXER0100')
		return
	}
	assert false, ':null should not parse as atom literal'
}

fn test_atom_lit_in_let_binding() {
	prog := cx.parse_program('[?let [= $status :ok] $status]') or {
		assert false, 'parse failed: $err'
		return
	}
	mut env := new_env()
	result := eval(prog.body, mut env) or {
		assert false, 'eval failed: $err'
		return
	}
	s := result as cx.ScalarNode
	assert s.data_type == .atom_type
	v := s.value as string
	assert v == 'ok'
}

fn test_atom_lit_renders_with_colon_prefix() {
	// gap 3: render(eval(:ok)) MUST emit `:ok`, not
	// `"ok"`. Without atom-aware render_scalar(), program output drops
	// the data_type discriminator and round-trips break.
	prog := cx.parse_program(':ok') or {
		assert false, 'parse failed: $err'
		return
	}
	mut env := new_env()
	result := eval(prog.body, mut env) or {
		assert false, 'eval failed: $err'
		return
	}
	rendered := render_canonical(result)
	assert rendered == ':ok', 'expected ":ok", got "${rendered}"'
}

fn test_atom_lit_renders_kebab_with_colon_prefix() {
	prog := cx.parse_program(':not-found') or {
		assert false, 'parse failed: $err'
		return
	}
	mut env := new_env()
	result := eval(prog.body, mut env) or {
		assert false, 'eval failed: $err'
		return
	}
	rendered := render_canonical(result)
	assert rendered == ':not-found', 'expected ":not-found", got "${rendered}"'
}

fn test_colon_for_let_surface_retired() {
	// v0.8.0 capstone: the legacy colon for-comprehension / let-binding
	// surface is retired. `[?for $x :in seq :yield $x]` and
	// `[?let $x = 1 :in $x]` MUST now be rejected; only the clause-child
	// form parses (`[?for [in $x seq] [yield $x]]`, `[?let [= $x 1] $x]`).
	// Regression-guards the parser-side colon-arm deletion.
	if _ := cx.parse_program('[?let $x = 1 :in $x]') {
		assert false, 'retired colon `[?let … :in …]` must be rejected'
	}
	if _ := cx.parse_program('[?for $x :in (1, 2, 3) :yield $x]') {
		assert false, 'retired colon `[?for … :in … :yield …]` must be rejected'
	}
	// The canonical clause-child forms still parse + eval.
	cc_let := cx.parse_program('[?let [= $x 1] $x]') or {
		assert false, 'clause-child [?let] must parse: $err'
		return
	}
	mut env := new_env()
	r := eval(cc_let.body, mut env) or {
		assert false, 'clause-child [?let] eval failed: $err'
		return
	}
	s := r as cx.ScalarNode
	assert s.data_type == .int_type, 'expected int_type, got ${s.data_type}'
}
