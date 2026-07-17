module main

import cx

// Tests for the Phase 2.12 Part 1 `[?def]` parser.
//
// Covers grammar productions [152]–[153f]:
//   - Function name + zero-param body.
//   - Positional / named / rest parameter shapes.
//   - Per-parameter type annotations + `:returns T` modifier.
//   - `:scope public/private` modifier slot.
//   - Multi-line bodies + verbatim source capture (bracket-shielded).
//   - Error paths (missing prefix, missing name, missing params,
//     missing body, malformed annotation, unknown modifier,
//     unclosed bracket, :rest-not-last, double-:rest).
//   - Fixture-aligned coverage drawn from
//     `conformance/code.txt program-def-*` (commit `4b15bbe2` et seq.).
//
// Phase 2.23 extension: `:pure` / `:impure` modifier slot parses
// per amendment. Default `:pure` when neither
// modifier present. Conflicting both-supplied raises
// CXDEF_CONFLICTING_PURITY.
//
// Out of scope at Phase 2.12 Part 1 (deferred to Phases 2.13 / 2.16 /
// 2.22):
//   - Module-load semantics + redeclaration check (CXER0205).
//   - Nested-`[?def]` rejection (CXER0204).
//   - Dev-strict type validation (CXER0206 / CXER0207).
//   - Static purity checker enforcement (CXER0233 / CXER0234) —
//     Phase 2.22.

// ── Positive parses ──────────────────────────────────────────────────────────

fn test_parse_def_zero_param() {
	n := cx.parse_def('[?def now-iso () [now]]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.name == 'now-iso'
	assert n.params.len == 0
	assert n.body == '[now]'
	assert n.returns_type_source == none
	assert n.scope == none
}

fn test_parse_def_single_param() {
	// Fixture-aligned: program-def-args-positional-ish shape.
	n := cx.parse_def('[?def double ($x) [* x 2]]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.name == 'double'
	assert n.params.len == 1
	assert n.params[0].name == 'x'
	assert n.params[0].type_expr_source == none
	assert n.params[0].is_named == false
	assert n.params[0].is_rest == false
	assert n.body == '[* x 2]'
}

fn test_parse_def_multi_param() {
	// Fixture-aligned: program-def-001-parse-basic.
	n := cx.parse_def('[?def add ($a $b) [+ a b]]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.name == 'add'
	assert n.params.len == 2
	assert n.params[0].name == 'a'
	assert n.params[1].name == 'b'
	assert n.body == '[+ a b]'
}

fn test_parse_def_with_type_annotations() {
	// Fixture-aligned: program-def-type-kinds.
	n := cx.parse_def('[?def echo-string [returns string] ($s::string) s]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.name == 'echo-string'
	assert n.params.len == 1
	assert n.params[0].name == 's'
	if t := n.params[0].type_expr_source {
		assert t == 'string'
	} else {
		assert false, 'param type_expr should be `string`'
	}
	if rt := n.returns_type_source {
		assert rt == 'string'
	} else {
		assert false, 'returns_type should be `string`'
	}
	assert n.body == 's'
}

fn test_parse_def_with_returns_only() {
	n := cx.parse_def('[?def make-x [returns int] () 42]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	if rt := n.returns_type_source {
		assert rt == 'int'
	} else {
		assert false, 'returns_type should be set'
	}
	assert n.params.len == 0
	assert n.body == '42'
}

fn test_parse_def_with_scope_public() {
	// Fixture-aligned: program-def-002-parse-with-returns.
	src := '[?def greet
  scope=public
  [returns string]
  ($name::string)
  [+ "hello, " name]]'
	n := cx.parse_def(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.name == 'greet'
	if sc := n.scope {
		assert sc == 'public'
	} else {
		assert false, 'scope should be `public`'
	}
	if rt := n.returns_type_source {
		assert rt == 'string'
	} else {
		assert false, 'returns should be `string`'
	}
	assert n.params.len == 1
	assert n.params[0].name == 'name'
	if t := n.params[0].type_expr_source {
		assert t == 'string'
	} else {
		assert false, 'param type should be `string`'
	}
}

fn test_parse_def_attr_and_clause_modifiers() {
	// modifier surface: `scope=public` attribute + `[returns T]`
	// clause child (the ONLY admitted forms; the legacy `:scope`/`:returns`
	// colon-slot surface is retired — D014).
	src := '[?def greet scope=public [returns string] ($name::string) [+ "hello, " name]]'
	n := cx.parse_def(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.name == 'greet'
	if sc := n.scope {
		assert sc == 'public'
	} else {
		assert false, 'scope should be `public`'
	}
	if rt := n.returns_type_source {
		assert rt == 'string'
	} else {
		assert false, 'returns should be `string`'
	}
	assert n.params.len == 1
	assert n.params[0].name == 'name'
}

fn test_parse_def_returns_bracket_type_clause() {
	// `[returns [or Person null]]` — bracketed composite captured verbatim.
	src := '[?def find-user [returns [or Person null]] ($id::string) null]'
	n := cx.parse_def(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	if rt := n.returns_type_source {
		assert rt == '[or Person null]'
	} else {
		assert false, 'returns_type should be `[or Person null]`'
	}
}

fn test_parse_def_unknown_attr_modifier_errors() {
	cx.parse_def('[?def f bogus=1 ($x) x]') or {
		assert err.msg().contains('unknown attribute modifier'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_def_with_scope_private() {
	n := cx.parse_def('[?def helper scope=private ($x) [* x 2]]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	if sc := n.scope {
		assert sc == 'private'
	} else {
		assert false, 'scope should be `private`'
	}
}

fn test_parse_def_bracket_type_union_verbatim() {
	// Fixture-aligned: program-def-type-union.
	// `[or Person null]` should be captured verbatim (deferred structural).
	src := '[?def find-user [returns [or Person null]] ($id::string) null]'
	n := cx.parse_def(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	if rt := n.returns_type_source {
		assert rt == '[or Person null]'
	} else {
		assert false, 'returns_type should be `[or Person null]`'
	}
}

fn test_parse_def_bracket_type_sequence_verbatim() {
	// Fixture-aligned: program-def-type-sequence.
	src := '[?def list-users [returns [sequence Person]] () []]'
	n := cx.parse_def(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	if rt := n.returns_type_source {
		assert rt == '[sequence Person]'
	} else {
		assert false, 'returns_type should be `[sequence Person]`'
	}
}

fn test_parse_def_named_param_with_default() {
	// Fixture-aligned: program-def-args-defaults.
	src := '[?def greet ($greeting="hi" $name="world") [+ greeting ", " name]]'
	n := cx.parse_def(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.params.len == 2
	assert n.params[0].name == 'greeting'
	assert n.params[0].is_named == true
	if d := n.params[0].default {
		assert d == '"hi"'
	} else {
		assert false, 'first named param should have default "hi"'
	}
	assert n.params[1].name == 'name'
	assert n.params[1].is_named == true
	if d := n.params[1].default {
		assert d == '"world"'
	} else {
		assert false, 'second named param should have default "world"'
	}
}

fn test_parse_def_rest_param() {
	// Fixture-aligned: program-def-args-rest.
	n := cx.parse_def('[?def sum-all (*$nums) [reduce + 0 nums]]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.params.len == 1
	assert n.params[0].name == 'nums'
	assert n.params[0].is_rest == true
	assert n.params[0].is_named == false
}

fn test_parse_def_mixed_param_shapes() {
	// Fixture-aligned: program-def-args-mixed.
	src := '[?def http-get ($url::string $timeout=30 *$extra-headers) [request]]'
	n := cx.parse_def(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.params.len == 3
	assert n.params[0].name == 'url'
	assert n.params[0].is_named == false
	assert n.params[0].is_rest == false
	if t := n.params[0].type_expr_source {
		assert t == 'string'
	} else {
		assert false, 'url should have type string'
	}
	assert n.params[1].name == 'timeout'
	assert n.params[1].is_named == true
	if d := n.params[1].default {
		assert d == '30'
	} else {
		assert false, 'timeout should have default 30'
	}
	assert n.params[2].name == 'extra-headers'
	assert n.params[2].is_rest == true
}

fn test_parse_def_multiline_body() {
	src := '[?def even? ($n)
  [?if [= n 0] true
                [odd? [- n 1]]]]'
	n := cx.parse_def(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.name == 'even?'
	assert n.params.len == 1
	assert n.params[0].name == 'n'
	assert n.body.contains('[?if [= n 0] true')
	assert n.body.contains('[odd? [- n 1]]')
}

fn test_parse_def_source_and_loc_set() {
	src := '[?def add ($a $b) [+ a b]]'
	n := cx.parse_def(src) or {
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

// ── Error paths ──────────────────────────────────────────────────────────────

fn test_parse_def_error_missing_prefix() {
	cx.parse_def('[?match $x :else :yield :ok]') or {
		assert err.msg().contains('missing [?def prefix')
		return
	}
	assert false, 'expected error'
}

fn test_parse_def_error_def_with_no_separator() {
	cx.parse_def('[?defx add () 1]') or {
		assert err.msg().contains('expected whitespace after [?def')
		return
	}
	assert false, 'expected error'
}

fn test_parse_def_error_missing_name() {
	cx.parse_def('[?def () 1]') or {
		assert err.msg().contains('missing function name'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_def_error_missing_param_list() {
	cx.parse_def('[?def add [+ a b]]') or {
		// Body slot can't open with `(` omitted. Under a leading
		// `[` is read as a `[returns]`/`[throws]` modifier clause; `[+ a b]`
		// is neither, so it errors as a malformed/unknown modifier clause.
		assert err.msg().contains('missing parameter list')
			|| err.msg().contains('expected modifier')
			|| err.msg().contains('modifier clause'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_def_error_missing_body() {
	cx.parse_def('[?def add ($a $b)]') or {
		assert err.msg().contains('missing body expression'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_def_error_malformed_type_annotation() {
	// `$x::)` — glued `::` immediately followed by `)` is a malformed type
	// annotation (no Type after `::`).
	cx.parse_def('[?def f ($x::) body]') or {
		assert err.msg().contains('malformed type annotation'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_def_error_retired_single_colon_param_type() {
	// RETIRED (D014): single-colon `:T` parameter type → hard parse error.
	cx.parse_def('[?def f ($x:int) x]') or {
		assert err.msg().contains('retired single-colon') || err.msg().contains('::T'),
			'got: ${err.msg()}'
		return
	}
	assert false, 'expected error for retired single-colon param type'
}

fn test_parse_def_error_unknown_modifier() {
	// A bareword that is neither `pure`/`impure` nor an `attr=` is rejected.
	cx.parse_def('[?def f bogus () 1]') or {
		assert err.msg().contains('not a valid modifier') || err.msg().contains('unknown'),
			'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_def_error_retired_colon_slot_modifier() {
	// RETIRED (D014): any `:LABEL` modifier slot → hard parse error.
	cx.parse_def('[?def f :bogus int () 1]') or {
		assert err.msg().contains('retired') && err.msg().contains('colon-slot'),
			'got: ${err.msg()}'
		return
	}
	assert false, 'expected error for retired colon-slot modifier'
}

fn test_parse_def_error_unclosed_bracket() {
	cx.parse_def('[?def add ($a $b) [+ a b]') or {
		assert err.msg().contains('missing closing ]'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_def_error_rest_not_last() {
	cx.parse_def('[?def f (*$xs $y) body]') or {
		assert err.msg().contains('rest parameter must be last'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_def_error_double_rest() {
	cx.parse_def('[?def f (*$xs *$ys) body]') or {
		assert err.msg().contains('at most one rest parameter'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_def_error_invalid_scope_value() {
	cx.parse_def('[?def f scope=wrong () 1]') or {
		assert err.msg().contains('scope') && err.msg().contains('public'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_def_error_trailing_input() {
	cx.parse_def('[?def add ($a $b) [+ a b]] junk') or {
		assert err.msg().contains('unexpected trailing input'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

// ── Cross-shape: parse → DefNode → equality stable ────────────────────────────

fn test_parse_def_round_trip_equality() {
	a := cx.parse_def('[?def add ($a $b) [+ a b]]') or {
		assert false, 'a parse failed: ${err}'
		return
	}
	b := cx.parse_def('[?def add  ($a $b) [+ a b]]') or {
		assert false, 'b parse failed: ${err}'
		return
	}
	// Differently-formatted input ⇒ same DefNode shape.
	assert a.eq(b), 'equivalently-shaped DefNodes must compare eq'
	assert cx.def_node_hash(a) == cx.def_node_hash(b)
}

// ── Purity modifier slot (Phase 2.23) ─────────────────────────

fn test_parse_def_purity_default_is_pure() {
	// No modifier ⇒ default to `.pure_` per D11.1.
	n := cx.parse_def('[?def add ($a $b) [+ a b]]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.purity == cx.Purity.pure_
}

fn test_parse_def_purity_explicit_pure() {
	n := cx.parse_def('[?def add pure ($a $b) [+ a b]]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.purity == cx.Purity.pure_
}

fn test_parse_def_purity_explicit_impure() {
	// D11.2 worked example shape.
	n := cx.parse_def('[?def now-iso impure () [now]]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.purity == cx.Purity.impure_
}

fn test_parse_def_purity_with_other_modifiers() {
	// `pure` stacks with `scope=` and `[returns]` in any order.
	src := '[?def add scope=public pure [returns int] ($a::int $b::int) [+ a b]]'
	n := cx.parse_def(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.purity == cx.Purity.pure_
	if sc := n.scope {
		assert sc == 'public'
	} else {
		assert false, 'scope should be set'
	}
	if rt := n.returns_type_source {
		assert rt == 'int'
	} else {
		assert false, 'returns_type should be set'
	}
}

fn test_parse_def_purity_impure_with_full_modifier_chain() {
	// D11.2 worked example — scope=, impure, [returns] all present.
	src := '[?def now-iso scope=public impure [returns string] () [format-instant [now]]]'
	n := cx.parse_def(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.purity == cx.Purity.impure_
	if sc := n.scope {
		assert sc == 'public'
	} else {
		assert false, 'scope should be set'
	}
	if rt := n.returns_type_source {
		assert rt == 'string'
	} else {
		assert false, 'returns_type should be set'
	}
}

fn test_parse_def_purity_round_trip_default_eq_explicit_pure() {
	// Default-pure and explicit-:pure must compare equal at the
	// DefNode level (purity field is identical) — surface text
	// differs but the identity-relevant fields match.
	a := cx.parse_def('[?def f () body]') or {
		assert false, 'a parse failed: ${err}'
		return
	}
	b := cx.parse_def('[?def f pure () body]') or {
		assert false, 'b parse failed: ${err}'
		return
	}
	assert a.eq(b), 'default-pure and explicit `pure` should match'
	assert cx.def_node_hash(a) == cx.def_node_hash(b)
}

fn test_parse_def_purity_pure_and_impure_differ() {
	a := cx.parse_def('[?def f pure () body]') or {
		assert false, 'a parse failed: ${err}'
		return
	}
	b := cx.parse_def('[?def f impure () body]') or {
		assert false, 'b parse failed: ${err}'
		return
	}
	assert !a.eq(b), 'pure vs impure same-body must NOT compare equal'
	assert cx.def_node_hash(a) != cx.def_node_hash(b)
}

fn test_parse_def_error_conflicting_purity_pure_then_impure() {
	cx.parse_def('[?def f pure impure () body]') or {
		assert err.msg().contains('CXDEF_CONFLICTING_PURITY')
			|| err.msg().contains('mutually exclusive'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}

fn test_parse_def_error_conflicting_purity_impure_then_pure() {
	cx.parse_def('[?def f impure pure () body]') or {
		assert err.msg().contains('CXDEF_CONFLICTING_PURITY')
			|| err.msg().contains('mutually exclusive'), 'got: ${err.msg()}'
		return
	}
	assert false, 'expected error'
}
