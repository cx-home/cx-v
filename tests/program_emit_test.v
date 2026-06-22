module main
import cx

import code

// Tests for `code.program_node_to_source` — the ProgramNode → CX-source
// emitter introduced in Phase 2.13 (Z79f) to bridge the legacy
// ProgramDirective dispatcher to the v0.8.0 standalone `[?match]` /
// `[?modify]` evaluators.
//
// The round-trip identity is verified at the *emit-idempotency* level:
//
//   source₀ → parse → AST₁ → emit → source₁ → parse → AST₂ → emit → source₂
//
//   The contract: source₁ == source₂ (the emit is a fixed point of
//   parse-then-emit). Since ProgramNode has no `.eq()` method at
//   Phase 2.13, emit-idempotency is the stand-in: two ASTs that emit
//   byte-identical source are observationally equivalent through the
//   AST surface that `cx.parse_match` / `cx.parse_modify` see.
//
// Coverage targets:
//   - Every variant of ProgramNode reachable in `[?match]` / `[?modify]`
//     slot positions.
//   - Edge cases: empty bodies, nested directives, quoted strings with
//     embedded quotes, atom literals, sequence/array/map literals.
//   - The realistic conformance shapes the dispatcher integration will
//     route through.

// ── Helpers ──────────────────────────────────────────────────────────────────

fn assert_roundtrip(src string) {
	prog1 := cx.parse_program(src) or {
		assert false, 'parse failed: ${src} — ${err}'
		return
	}
	emit1 := code.program_node_to_source(cx.ProgramNode(prog1.body))
	prog2 := cx.parse_program(emit1) or {
		assert false, 'reparse of emit failed: src=${src} emit=${emit1} — ${err}'
		return
	}
	emit2 := code.program_node_to_source(cx.ProgramNode(prog2.body))
	assert emit1 == emit2, 'round-trip drift: src=`${src}` emit1=`${emit1}` emit2=`${emit2}`'
}

// ── Literals ─────────────────────────────────────────────────────────────────

fn test_literal_int() {
	assert_roundtrip('42')
}

fn test_literal_negative_int() {
	assert_roundtrip('-7')
}

fn test_literal_string() {
	assert_roundtrip('"hello"')
}

fn test_literal_string_with_single_quote() {
	assert_roundtrip('"it\'s"')
}

fn test_literal_bool_true() {
	assert_roundtrip('true')
}

fn test_literal_bool_false() {
	assert_roundtrip('false')
}

fn test_literal_atom() {
	assert_roundtrip(':ok')
}

fn test_literal_atom_with_hyphen() {
	assert_roundtrip(':not-found')
}

fn test_literal_sequence() {
	assert_roundtrip('(1, 2, 3)')
}

fn test_literal_array() {
	assert_roundtrip('[1, 2, 3]')
}

// ── Bindings ─────────────────────────────────────────────────────────────────

fn test_binding_bare() {
	assert_roundtrip('\$x')
}

fn test_binding_with_child_path() {
	assert_roundtrip('\$user/name')
}

fn test_binding_with_attr_path() {
	assert_roundtrip('\$user@id')
}

// ── Calls ────────────────────────────────────────────────────────────────────

fn test_call_zero_args() {
	assert_roundtrip('now()')
}

fn test_call_one_arg() {
	assert_roundtrip('count(42)')
}

fn test_call_multi_args() {
	assert_roundtrip('plus(1, 2)')
}

fn test_call_fallible() {
	assert_roundtrip('parse-int("42")?')
}

fn test_call_must_succeed() {
	assert_roundtrip('parse-int("42")!')
}

// ── Path expressions ────────────────────────────────────────────────────────

fn test_path_descendant() {
	assert_roundtrip('//user')
}

fn test_path_descendant_two_steps() {
	assert_roundtrip('//users/user')
}

fn test_path_with_attr_predicate() {
	assert_roundtrip('//user[@active]')
}

fn test_path_with_attr_eq_predicate() {
	assert_roundtrip('//user[@id=1]')
}

fn test_path_attr_axis() {
	assert_roundtrip('//user/@name')
}

// ── `[?match]` realistic shapes ──────────────────────────────────────────────

fn test_match_single_arm() {
	assert_roundtrip('[?match \$s [user \$u] :yield :ok]')
}

fn test_match_multi_arm_scalar() {
	assert_roundtrip('[?match \$s :case 200 :yield :ok :case 404 :yield :not-found :else :yield :err]')
}

fn test_match_multi_arm_with_else() {
	assert_roundtrip('[?match \$s :case 200 :yield :ok :else :yield :err]')
}

fn test_match_no_else() {
	assert_roundtrip('[?match \$s :case 200 :yield :ok :case 404 :yield :not-found]')
}

fn test_match_wildcard() {
	assert_roundtrip('[?match \$v :case 200 :yield :http-ok :case _ :yield :other]')
}

fn test_match_element_pattern_with_bind() {
	assert_roundtrip('[?match \$n :case [prose \$p] :yield [p \$p] :else :yield ()]')
}

fn test_match_when_arm() {
	// Simple atom predicate — full `(expr > N)` form is parser-limited
	// at v0.8.0 (comparisons inside parens are not yet supported by the
	// program parser; see `program_emit_test.v` notes).
	assert_roundtrip('[?match \$x :when true :yield :big :else :yield :small]')
}

// ── `[?modify]` realistic shapes ─────────────────────────────────────────────

fn test_modify_set_attr() {
	assert_roundtrip('[?modify \$doc //user [set-attr status "active"]]')
}

fn test_modify_delete() {
	assert_roundtrip('[?modify \$doc //user[@active=false] [delete]]')
}

fn test_modify_set() {
	assert_roundtrip('[?modify \$doc //user/@name [set "Alicia"]]')
}

fn test_modify_rename() {
	assert_roundtrip('[?modify \$doc //widget [rename component]]')
}

fn test_modify_append() {
	assert_roundtrip('[?modify \$doc //section [append [para "Hi"]]]')
}

// ── For-comprehension ───────────────────────────────────────────────────────

fn test_for_simple() {
	assert_roundtrip('[?for [in \$u //user] [yield \$u]]')
}

fn test_for_where() {
	// Simple where atom — see test_match_when_arm note on comparison
	// parser limit.
	assert_roundtrip('[?for [in \$u //user] [where true] [yield \$u]]')
}

// ── Directives with nested expressions ──────────────────────────────────────

fn test_let_directive() {
	assert_roundtrip('[?let [= \$x 42] \$x]')
}

fn test_if_directive() {
	assert_roundtrip('[?if true :then 1 :else 2]')
}

fn test_nested_match_in_let() {
	assert_roundtrip('[?let [= \$s 200] [?match \$s :case 200 :yield :ok :else :yield :err]]')
}

// ── Element literals ────────────────────────────────────────────────────────

fn test_element_literal_simple() {
	assert_roundtrip('[user [name Alice]]')
}

fn test_element_literal_with_attr() {
	assert_roundtrip('[user id=1 [name Alice]]')
}

// ── Edge cases ──────────────────────────────────────────────────────────────

fn test_empty_pattern_body() {
	// Pattern with bare bind only.
	assert_roundtrip('[?match \$n :case [user \$u] :yield \$u]')
}

fn test_atom_inside_yield() {
	assert_roundtrip('[?match \$v :case _ :yield :unknown]')
}

// ── Dynamic construction (§6.4.2–§6.4.4) ──────────────────────────────────────
// Bijection / emit-idempotency for every dynamic-construction directive: the
// program source is a fixed point of parse-then-emit, so the constructed-code
// tree round-trips losslessly (the §6.4.3 "fully bijective" claim at the
// program-surface level).

fn test_dc_element_computed_name() {
	assert_roundtrip('[?element \$n size=large "hi"]')
}

fn test_dc_element_with_computed_attr() {
	assert_roundtrip('[?element "box" [?attr \$k \$v]]')
}

fn test_dc_attr_standalone() {
	assert_roundtrip('[?attr \$k \$v]')
}

fn test_dc_entry_in_map() {
	assert_roundtrip('{[?entry \$k \$v]}')
}

fn test_dc_name_in_rename() {
	assert_roundtrip('[?modify \$doc //user [rename [?name \$x]]]')
}

fn test_dc_name_in_set_attr() {
	assert_roundtrip('[?modify \$doc //user [set-attr [?name \$k] \$v]]')
}

fn test_dc_quote_unquote() {
	assert_roundtrip('[?quote [a [?unquote \$x]]]')
}

fn test_dc_quote_splice() {
	assert_roundtrip('[?quote [list [?splice \$xs]]]')
}

fn test_dc_eval_bare() {
	assert_roundtrip('[?eval \$code]')
}

fn test_dc_eval_with_context_and_opts() {
	assert_roundtrip('[?eval \$code [context {}] [opts {max-depth: 8}]]')
}
