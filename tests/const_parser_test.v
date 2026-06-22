module main

import cx

// Tests for the Phase 2.12 Part 2 `[?const]` parser.
//
// Covers grammar productions [154]–[154a]:
//   - Bare `[?const NAME EXPR]` (eager, no scope).
//   - `:lazy` modifier (lazy const).
//   - `:scope public/private` modifier slot.
//   - Both `:lazy` + `:scope` together (order-independent).
//   - Multi-line / bracket-shielded value expressions.
//   - Quoted-string value capture.
//   - Error paths: missing name, missing value, missing prefix,
//     malformed `:` modifier, unknown modifier, invalid scope value,
//     duplicate `:lazy`, duplicate `:scope`, unclosed bracket,
//     trailing input.
//   - Fixture-aligned coverage drawn from
//     `conformance/code.txt module-const-*` + `module-load-*`.
//
// Out of scope at Phase 2.12 Part 2:
//   - Eager evaluation / lazy memoization — Phase 2.13.
//   - Cycle detection (CXER0214) / body failure (CXER0215) — Phase 2.13.
//   - `:scope` visibility enforcement — Phase 2.15.

// ── Positive parses ──────────────────────────────────────────────────────────

fn test_parse_const_minimal() {
	// Fixture-aligned: module-const-eager (`[?const GREETING "hello"]`).
	n := cx.parse_const('[?const GREETING "hello"]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.name == 'GREETING'
	assert n.value_source == '"hello"'
	assert n.lazy == false
	assert n.scope == none
}

fn test_parse_const_numeric() {
	// Fixture-aligned: module-load-order-independent (`[?const A 5]`).
	n := cx.parse_const('[?const A 5]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.name == 'A'
	assert n.value_source == '5'
}

fn test_parse_const_with_bracket_expr_value() {
	// Fixture-aligned: module-load-order-independent (`[?const B [* A 10]]`).
	n := cx.parse_const('[?const B [* A 10]]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.name == 'B'
	assert n.value_source == '[* A 10]'
}

fn test_parse_const_with_def_reference_value() {
	// Fixture-aligned: program-def-ref-via-const (`[?const TRIPLER triple]`).
	n := cx.parse_const('[?const TRIPLER triple]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.name == 'TRIPLER'
	assert n.value_source == 'triple'
}

fn test_parse_const_with_lazy_modifier() {
	// Fixture-aligned: module-const-lazy (`[?const lazy BIG-TABLE [load-big-table]]`).
	n := cx.parse_const('[?const lazy BIG-TABLE [load-big-table]]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.name == 'BIG-TABLE'
	assert n.lazy == true
	assert n.value_source == '[load-big-table]'
	assert n.scope == none
}

fn test_parse_const_with_lazy_complex_value() {
	// Fixture-aligned: module-const-lazy-forced
	// (`[?const lazy COUNTER [test-counter name="lazy" op=inc]]`).
	src := '[?const lazy COUNTER [test-counter name="lazy" op=inc]]'
	n := cx.parse_const(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.name == 'COUNTER'
	assert n.lazy == true
	assert n.value_source == '[test-counter name="lazy" op=inc]'
}

fn test_parse_const_with_scope_public() {
	// example: `[?const scope=public PUBLIC-VERSION "1.0"]`.
	n := cx.parse_const('[?const scope=public PUBLIC-VERSION "1.0"]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.name == 'PUBLIC-VERSION'
	assert n.value_source == '"1.0"'
	if sc := n.scope {
		assert sc == 'public'
	} else {
		assert false, 'scope should be `public`'
	}
	assert n.lazy == false
}

fn test_parse_const_with_scope_private() {
	n := cx.parse_const('[?const scope=private VERSION "1.0"]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	if sc := n.scope {
		assert sc == 'private'
	} else {
		assert false, 'scope should be `private`'
	}
}

fn test_parse_const_with_both_modifiers_scope_first() {
	n := cx.parse_const('[?const scope=public lazy BIG-TABLE [load]]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.name == 'BIG-TABLE'
	assert n.lazy == true
	if sc := n.scope {
		assert sc == 'public'
	} else {
		assert false, 'scope should be `public`'
	}
}

fn test_parse_const_with_both_modifiers_lazy_first() {
	// Order-independent modifier ordering per grammar [154].
	n := cx.parse_const('[?const lazy scope=public BIG-TABLE [load]]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.name == 'BIG-TABLE'
	assert n.lazy == true
	if sc := n.scope {
		assert sc == 'public'
	} else {
		assert false, 'scope should be `public`'
	}
}

fn test_parse_const_multiline_value() {
	src := '[?const TABLE
  [build-table
    rows=100
    cols=20]]'
	n := cx.parse_const(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.name == 'TABLE'
	assert n.value_source.contains('[build-table')
	assert n.value_source.contains('rows=100')
}

fn test_parse_const_source_and_loc_set() {
	src := '[?const A 5]'
	n := cx.parse_const(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	if s := n.source {
		assert s == src
	} else {
		assert false, 'source should be set'
	}
	if l := n.loc {
		assert l.start == 0
		assert l.end == src.len
	} else {
		assert false, 'loc should be set'
	}
}

fn test_parse_const_string_with_brackets_inside_quotes() {
	// Quoted-string brackets MUST NOT increment bracket depth.
	n := cx.parse_const('[?const RE "[a-z]+"]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.name == 'RE'
	assert n.value_source == '"[a-z]+"'
}

// ── Error paths ──────────────────────────────────────────────────────────────

fn test_parse_const_error_missing_prefix() {
	cx.parse_const('[?def add () 1]') or {
		assert err.msg().contains('missing [?const prefix'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_const_error_no_separator() {
	cx.parse_const('[?constx FOO 1]') or {
		assert err.msg().contains('expected whitespace after [?const'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_const_error_missing_name() {
	cx.parse_const('[?const 5]') or {
		assert err.msg().contains('missing constant name'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_const_error_missing_value() {
	cx.parse_const('[?const FOO]') or {
		assert err.msg().contains('missing value expression'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_const_error_unknown_modifier() {
	// An unknown `attr=` modifier (the spec-surface unknown case).
	cx.parse_const('[?const bogus=1 FOO 1]') or {
		assert err.msg().contains('CXCONST_UNKNOWN_MODIFIER')
			|| err.msg().contains('unknown attribute modifier'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_const_error_invalid_scope_value() {
	cx.parse_const('[?const scope=wrong FOO 1]') or {
		assert err.msg().contains('scope') && err.msg().contains('public'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_const_error_duplicate_lazy() {
	cx.parse_const('[?const lazy lazy FOO 1]') or {
		assert err.msg().contains('duplicate lazy'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_const_error_duplicate_scope() {
	cx.parse_const('[?const scope=public scope=private FOO 1]') or {
		assert err.msg().contains('duplicate scope'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_const_error_retired_colon_slot_modifier() {
	// RETIRED (D014): the legacy `:scope`/`:lazy` colon-slot modifiers.
	cx.parse_const('[?const :lazy FOO 1]') or {
		assert err.msg().contains('retired') && err.msg().contains('colon-slot'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error for retired colon-slot modifier'
}

fn test_parse_const_error_unclosed_bracket() {
	cx.parse_const('[?const A [+ 1 2]') or {
		assert err.msg().contains('missing closing ]'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_const_error_trailing_input() {
	cx.parse_const('[?const A 5] junk') or {
		assert err.msg().contains('unexpected trailing input'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_const_error_empty_input() {
	cx.parse_const('') or {
		assert err.msg().contains('empty input'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

// ── Cross-shape: parse → ConstNode → equality stable ──────────────────────────

fn test_parse_const_round_trip_equality() {
	a := cx.parse_const('[?const A 5]') or {
		assert false, 'a parse failed: ${err}'
		return
	}
	b := cx.parse_const('[?const A  5]') or {
		assert false, 'b parse failed: ${err}'
		return
	}
	// Differently-formatted input ⇒ same ConstNode shape.
	assert a.eq(b), 'equivalently-shaped ConstNodes must compare eq'
	assert cx.const_node_hash(a) == cx.const_node_hash(b)
}

fn test_parse_const_round_trip_lazy_equality() {
	a := cx.parse_const('[?const lazy COUNTER [test-counter]]') or {
		assert false, 'a parse failed: ${err}'
		return
	}
	b := cx.parse_const('[?const lazy  COUNTER  [test-counter]]') or {
		assert false, 'b parse failed: ${err}'
		return
	}
	assert a.eq(b)
	assert cx.const_node_hash(a) == cx.const_node_hash(b)
}
