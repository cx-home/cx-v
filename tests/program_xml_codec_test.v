module main
import cx

import code

// Tests for the bijective ProgramNode ⇄ XML codec (Phase C §4):
// `code.program_to_xml` / `code.xml_to_program`.
//
// Round-trip identity, verified at the canonical-source level (ProgramNode
// has no `.eq()`, so two ASTs that emit byte-identical `program_node_to_source`
// are observationally equivalent — the same contract the program_emit suite
// uses):
//
//   src → parse → AST → program_to_xml → xml → xml_to_program → AST'
//   assert program_node_to_source(AST) == program_node_to_source(AST')
//
// The structural §4 forms (scalars, $var, [$call], [op], elements,
// directives with clause/labeled children) are exercised directly; the
// <cx:expr> escape hatch carries everything else, so the round-trip holds
// over the full corpus.

fn assert_xml_roundtrip(src string) {
	prog := cx.parse_program(src) or {
		assert false, 'parse failed: ${src} — ${err}'
		return
	}
	canon0 := code.program_node_to_source(cx.ProgramNode(prog.body))
	xml := code.program_to_xml(cx.ProgramNode(prog.body))
	back := code.xml_to_program(xml) or {
		assert false, 'xml_to_program failed: src=`${src}` xml=`${xml}` — ${err}'
		return
	}
	canon1 := code.program_node_to_source(back)
	assert canon0 == canon1, 'round-trip drift:\n  src   = `${src}`\n  xml   = `${xml}`\n  canon0= `${canon0}`\n  canon1= `${canon1}`'
}

// ── Scalars ───────────────────────────────────────────────────────────────────

fn test_xml_int() {
	assert_xml_roundtrip('42')
}

fn test_xml_negative_int() {
	assert_xml_roundtrip('-7')
}

fn test_xml_string() {
	assert_xml_roundtrip('"hello"')
}

fn test_xml_string_with_angle_brackets() {
	assert_xml_roundtrip('"a < b && c > d"')
}

fn test_xml_bool_true() {
	assert_xml_roundtrip('true')
}

fn test_xml_bool_false() {
	assert_xml_roundtrip('false')
}

fn test_xml_atom() {
	assert_xml_roundtrip(':ok')
}

fn test_xml_atom_hyphen() {
	assert_xml_roundtrip(':not-found')
}

// ── Variables ─────────────────────────────────────────────────────────────────

fn test_xml_var() {
	assert_xml_roundtrip('$x')
}

// ── Operators (symbol heads → <cx:op>) ─────────────────────────────────────────

fn test_xml_op_add() {
	assert_xml_roundtrip('[+ $a $b]')
}

fn test_xml_op_gt() {
	assert_xml_roundtrip('[> $n 0]')
}

fn test_xml_op_nested() {
	assert_xml_roundtrip('[* [+ $a 1] 2]')
}

fn test_xml_op_eq() {
	assert_xml_roundtrip('[= $x 5]')
}

// ── Calls ([$fn …] → <cx:call>) ────────────────────────────────────────────────

fn test_xml_call_positional() {
	assert_xml_roundtrip('[$dbl 21]')
}

fn test_xml_call_multi_arg() {
	assert_xml_roundtrip('[$add 1 2]')
}

// ── Bareword elements ─────────────────────────────────────────────────────────

fn test_xml_element_empty() {
	assert_xml_roundtrip('[doc]')
}

fn test_xml_element_with_items() {
	assert_xml_roundtrip('[pair 1 2]')
}

fn test_xml_element_with_attrs() {
	assert_xml_roundtrip('[user id=1 [name "Alice"]]')
}

fn test_xml_element_attr_expr_value() {
	assert_xml_roundtrip('[code lang=$l $s]')
}

fn test_xml_element_with_labeled_slots() {
	assert_xml_roundtrip('[response status=200 :body $b]')
}

fn test_xml_element_attr_string_value() {
	assert_xml_roundtrip('[meta key="a < b"]')
}

// ── Directives ────────────────────────────────────────────────────────────────

fn test_xml_directive_if_clause_children() {
	assert_xml_roundtrip("[?if [> $n 0] [then 'pos'] [else 'neg']]")
}

fn test_xml_directive_if_labeled_slots() {
	// Legacy labeled-slot form → <cx:then>/<cx:else>.
	assert_xml_roundtrip("[?if [> $n 0] :then 'pos' :else 'neg']")
}

// ── Map literals (structural: cx:map) ──────────────────────────────────────────

fn test_xml_map_literal() {
	assert_xml_roundtrip('{a: 1, b: 2}')
}

fn test_xml_map_empty() {
	assert_xml_roundtrip('{}')
}

fn test_xml_map_nested_value() {
	assert_xml_roundtrip('{k: [+ $x 1]}')
}

// ── Binding with path (structural: cx:var + cx:step) ───────────────────────────

fn test_xml_binding_child_path() {
	assert_xml_roundtrip('$u/name')
}

fn test_xml_binding_attr_path() {
	assert_xml_roundtrip('$u@id')
}

fn test_xml_binding_multi_step() {
	assert_xml_roundtrip('$doc/user/name')
}

fn test_xml_binding_descendant() {
	assert_xml_roundtrip('$doc//item')
}

// ── Multi-statement block (structural: cx:block) ───────────────────────────────

fn test_xml_block_multi_statement() {
	assert_xml_roundtrip('[?def dbl (x) [* x 2]]\n[$dbl 21]')
}

// ── Binding path predicates (structural: cx:step + cx:pred) ────────────────────

fn test_xml_binding_position_predicate() {
	assert_xml_roundtrip('$u/item[1]')
}

fn test_xml_binding_attr_eq_predicate() {
	assert_xml_roundtrip('$u/item[@id=1]')
}

fn test_xml_binding_attr_existence_predicate() {
	assert_xml_roundtrip('$u/item[@active]')
}

fn test_xml_binding_attr_comparison_predicate() {
	assert_xml_roundtrip('$doc/item[@n>=5]')
}

// ── Sequence / array literals (structural: cx:seq / cx:arr) ────────────────────

fn test_xml_sequence_literal() {
	assert_xml_roundtrip('(1, 2, 3)')
}

fn test_xml_sequence_empty() {
	assert_xml_roundtrip('()')
}

fn test_xml_array_literal() {
	assert_xml_roundtrip('[1, 2, 3]')
}

fn test_xml_sequence_nested_exprs() {
	assert_xml_roundtrip('([+ $a 1], :ok, "x")')
}

fn test_xml_escape_let_directive() {
	assert_xml_roundtrip('[?let [= $x 5] [+ $x 1]]')
}

// ── Patterns (structural: cx:pattern / cx:pattr) ───────────────────────────────

fn test_xml_pattern_named_bind() {
	assert_xml_roundtrip('[?match $x [case [user $u] $u]]')
}

fn test_xml_pattern_attr_equality() {
	assert_xml_roundtrip('[?match $x [case [user @active=true] :ok]]')
}

fn test_xml_pattern_attr_existence() {
	assert_xml_roundtrip('[?match $x [case [user @id] :ok]]')
}

fn test_xml_pattern_attr_absence() {
	assert_xml_roundtrip('[?match $x [case [user @!deleted] :ok]]')
}

fn test_xml_pattern_attr_comparison() {
	assert_xml_roundtrip('[?match $x [case [user @n>=5] :ok]]')
}

fn test_xml_pattern_nested_body() {
	assert_xml_roundtrip('[?match $x [case [user $u [name $n]] $n]]')
}

fn test_xml_pattern_type_guard() {
	assert_xml_roundtrip('[?match $x [case [:User $u] $u]]')
}

fn test_xml_pattern_wildcard_body() {
	assert_xml_roundtrip('[?match $x [case [user $u *] $u]]')
}

// ── For-comprehensions (structural: cx:for-comp / cx:clause) ───────────────────

fn test_xml_for_comp_basic() {
	assert_xml_roundtrip('[?for [in $i $xs] [yield [* $i 2]]]')
}

fn test_xml_for_comp_anonymous() {
	// clause-child form supports the anonymous generator [in SRC].
	assert_xml_roundtrip('[?for [in $xs] [yield [* $_ 2]]]')
}

fn test_xml_for_comp_where() {
	assert_xml_roundtrip('[?for [in $i $xs] [where [> $i 0]] [yield $i]]')
}

fn test_xml_for_comp_let() {
	assert_xml_roundtrip('[?for [in $i $xs] [= $d [* $i 2]] [yield $d]]')
}

fn test_xml_for_comp_order_by() {
	assert_xml_roundtrip('[?for [in $i $xs] [order-by $i desc] [yield $i]]')
}

fn test_xml_for_comp_limit_par() {
	assert_xml_roundtrip('[?for [in $i $xs] [par] [limit 10] [yield $i]]')
}

fn test_xml_for_comp_array() {
	assert_xml_roundtrip('[?for-array [in $i $xs] [yield-array $i]]')
}

fn test_xml_for_comp_map() {
	assert_xml_roundtrip('[?for-map [in $i $xs] [yield-map $i [* $i 2]]]')
}


// ── Slice access / slice literal (structural: cx:slice / cx:slice-access) ──────

fn test_xml_slice_access_range() {
	assert_xml_roundtrip('$xs[2:5]')
}

fn test_xml_slice_access_open_start() {
	assert_xml_roundtrip('$xs[:5]')
}

fn test_xml_slice_access_strided() {
	assert_xml_roundtrip('$xs[::2]')
}

fn test_xml_slice_access_reversed() {
	assert_xml_roundtrip('$xs[::-1]')
}

fn test_xml_slice_access_full() {
	assert_xml_roundtrip('$xs[*]')
}

fn test_xml_slice_access_multi_axis() {
	assert_xml_roundtrip('$matrix[1:3, 2:4]')
}

fn test_xml_slice_literal_range() {
	assert_xml_roundtrip('[2:5]')
}

fn test_xml_slice_literal_strided() {
	assert_xml_roundtrip('[::2]')
}

// ── Calls: fallible / must-succeed / bare-ref / labeled (structural) ───────────

fn test_xml_call_fallible() {
	assert_xml_roundtrip('[$foo 1]?')
}

fn test_xml_call_must_succeed() {
	assert_xml_roundtrip('[$foo 1]!')
}

fn test_xml_call_bare_reference() {
	assert_xml_roundtrip('foo')
}

fn test_xml_call_labeled_arg() {
	assert_xml_roundtrip('foo(:limit 10, $x)')
}

fn test_xml_call_fallible_paren() {
	assert_xml_roundtrip('bar(1, 2)?')
}
