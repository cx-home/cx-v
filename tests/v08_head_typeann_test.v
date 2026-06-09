module main

import code
import cx

// v08_head_typeann_test — cluster 3 (TYPE-ANN) of the parser-parity
// convergence. The PROGRAM parser must accept a glued head TypeAnnotation
// `::T` / `::T[]` / `::[]` (lexicon §7 [L50], §9 [L25d]); code.parse used to
// REJECT it. The annotation OVERRIDES §9 auto-typing. Convergence target is
// cx.parse; both render identically through code.render_canonical.

fn cc(src string) string {
	n := code.program_parse_to_typed_node(src) or { return 'REJECT' }
	return code.render_canonical(n)
}

fn xc(src string) string {
	doc := cx.parse(src) or { return 'REJECT: ${err}' }
	if doc.elements.len != 1 {
		return 'REJECT: ${doc.elements.len} elements'
	}
	return code.render_canonical(doc.elements[0])
}

fn test_scalar_sized_int() {
	assert cc('[port::u16 8080]') == '[port::u16 8080]'
	assert cc('[port::u16 8080]') == xc('[port::u16 8080]')
}

fn test_scalar_int() {
	assert cc('[count::int 5]') == '[count::int 5]'
	assert cc('[count::int 5]') == xc('[count::int 5]')
}

fn test_typed_int_array() {
	// decision-(a) drops the redundant ::int[] annotation.
	assert cc('[xs::int[] 1 2 3]') == '[xs 1 2 3]'
	assert cc('[xs::int[] 1 2 3]') == xc('[xs::int[] 1 2 3]')
}

fn test_typed_string_array() {
	// string array renders comma-separated, annotation dropped.
	assert cc('[tags::string[] admin user]') == '[tags admin, user]'
	assert cc('[tags::string[] admin user]') == xc('[tags::string[] admin user]')
}

fn test_inferred_array() {
	// @CHOICE-1 §9-one-layer (slice C): `::[]` KEEPS its `[]` marker and per-item
	// types (heterogeneous, no promotion) — distinct from a whitespace typed list
	// `[xs 1 2 3]` and from an explicit `::T[]`. The annotation is retained on
	// render (it carries the array-vs-mixed-content distinction).
	assert cc('[xs::[] 1 2 3]') == '[xs::[] 1 2 3]'
	assert cc('[xs::[] 1 2 3]') == xc('[xs::[] 1 2 3]')
	// heterogeneous: int + float preserved, no promotion.
	assert cc('[ns::[] 1 2.0 3]') == '[ns::[] 1 2.0 3]'
	assert cc('[ns::[] 1 2.0 3]') == xc('[ns::[] 1 2.0 3]')
}

fn test_unknown_type_tag_rejected() {
	// An unknown tag is a parse error, not a silently-accepted bogus type.
	if _ := code.program_parse_to_typed_node('[x::bogus 1]') {
		assert false, 'expected reject for ::bogus'
	}
}
