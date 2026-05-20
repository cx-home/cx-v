module main

import cx

// ── ADR 0017 §D6/§D7 directive-arg-array shapes (parser tests) ───────────────
//
// Covers the §F-parser landing of resolutions 1.d (slot-as-body) and
// 2.i (first-`[…]`-in-`[?Name …]`-is-always-Array). These tests pin
// the parse-level expectations of the new uniform directive shape
// before the CXL evaluator rewrite (§F-evaluator) ratifies them
// behaviorally.
//
// Companion specs: ADR 0017 §D5/§D6/§D7, spec/eval.md §3.0.

fn parse_one(src string) cx.Node {
	d := cx.parse(src) or { panic('parse: ${err}') }
	assert d.elements.len > 0
	return d.elements[0]
}

// ── 2.i: single-slot `[?Name [arg]]` forces the body `[…]` to Array ──────────

fn test_include_single_slot() {
	// `[?include [path]]` — no comma in arg array; parser must still
	// route the inner `[…]` to Array (not Element named "path") per
	// resolution 2.i (2026-05-12) which implements ADR 0017 §D6.
	n := parse_one("[?include ['partials/card.cxl']]")
	assert n is cx.EvalDirectiveNode
	d := n as cx.EvalDirectiveNode
	assert d.name == 'include'
	assert d.items.len == 1
	arg := d.items[0]
	assert arg is cx.ArrayNode
	arr := arg as cx.ArrayNode
	assert arr.items.len == 1
	slot0 := arr.items[0]
	assert slot0 is cx.TextNode
	assert (slot0 as cx.TextNode).value == 'partials/card.cxl'
}

fn test_use_single_slot_bare_name() {
	// Bare-name single slot — same disambiguation rule applies.
	n := parse_one('[?use [card-row]]')
	d := n as cx.EvalDirectiveNode
	arg := d.items[0] as cx.ArrayNode
	assert arg.items.len == 1
	slot0 := arg.items[0] as cx.TextNode
	assert slot0.value == 'card-row'
}

fn test_empty_arg_array() {
	// `[?if []]` — explicit empty arg array. Distinct from `[?if]`
	// (no arg array at all).
	n := parse_one('[?if []]')
	d := n as cx.EvalDirectiveNode
	assert d.items.len == 1
	arg := d.items[0] as cx.ArrayNode
	assert arg.items.len == 0
}

fn test_no_arg_array() {
	// `[?if]` — ε ArgArray case. EvalDirective.items is empty.
	n := parse_one('[?if]')
	d := n as cx.EvalDirectiveNode
	assert d.items.len == 0
}

// ── 1.d: whitespace-bearing slot bodies (expression text) ────────────────────

fn test_whitespace_expr_slot() {
	// `[?if [@stock > 0, in stock, out]]` — slot 0 is a CXPath
	// comparison with internal whitespace. Pre-1.d the slot parser
	// stopped at whitespace; 1.d coalesces consecutive bare tokens
	// into a single TextNode preserving CXPath shape for evaluator
	// re-parse at eval time.
	n := parse_one('[?if [@stock > 0, in stock, out]]')
	d := n as cx.EvalDirectiveNode
	arr := d.items[0] as cx.ArrayNode
	assert arr.items.len == 3
	assert (arr.items[0] as cx.TextNode).value == '@stock > 0'
	assert (arr.items[1] as cx.TextNode).value == 'in stock'
	assert (arr.items[2] as cx.TextNode).value == 'out'
}

fn test_quoted_string_slots() {
	// Quoted strings remain valid slot content; quotes are stripped
	// at parse time per existing read_quoted_text behavior.
	n := parse_one("[?if [@stock > 0, 'in stock', 'out']]")
	d := n as cx.EvalDirectiveNode
	arr := d.items[0] as cx.ArrayNode
	assert arr.items.len == 3
	assert (arr.items[1] as cx.TextNode).value == 'in stock'
	assert (arr.items[2] as cx.TextNode).value == 'out'
}

// ── 1.d: mixed-content body slots wrap in SequenceNode ───────────────────────

fn test_mixed_content_slot_wraps_sequence() {
	// Slot 2 is mixed text + interpolation. Per 1.d, multi-item
	// slots wrap in SequenceNode (the "slot encoding" for mixed
	// content). The evaluator unwraps at use-site.
	n := parse_one('[?if [@stock > 0, In stock: [?=@stock], out of stock]]')
	d := n as cx.EvalDirectiveNode
	arr := d.items[0] as cx.ArrayNode
	assert arr.items.len == 3
	// Slot 1: mixed body → SequenceNode.
	slot1 := arr.items[1]
	assert slot1 is cx.SequenceNode
	seq := slot1 as cx.SequenceNode
	assert seq.items.len == 2
	assert seq.items[0] is cx.TextNode
	assert (seq.items[0] as cx.TextNode).value == 'In stock: '
	assert seq.items[1] is cx.InterpolationNode
	assert (seq.items[1] as cx.InterpolationNode).expr == '@stock'
	// Slot 2: single-token body stays unwrapped.
	assert arr.items[2] is cx.TextNode
}

fn test_for_three_slot_with_body_element() {
	// `[?for [var, iterable, body]]` — body slot is a single Element.
	// Single-item slots keep their natural Item kind without wrapping.
	n := parse_one('[?for [v, //variant, [?=v/@sku]]]')
	d := n as cx.EvalDirectiveNode
	arr := d.items[0] as cx.ArrayNode
	assert arr.items.len == 3
	assert (arr.items[0] as cx.TextNode).value == 'v'
	assert (arr.items[1] as cx.TextNode).value == '//variant'
	assert arr.items[2] is cx.InterpolationNode
	assert (arr.items[2] as cx.InterpolationNode).expr == 'v/@sku'
}

fn test_with_two_slot_mixed_body() {
	// `[?with [context, body]]` — body is mixed interp + literal.
	n := parse_one('[?with [//meta, [?=@owner]/[?=@region]]]')
	d := n as cx.EvalDirectiveNode
	arr := d.items[0] as cx.ArrayNode
	assert arr.items.len == 2
	assert (arr.items[0] as cx.TextNode).value == '//meta'
	slot1 := arr.items[1]
	assert slot1 is cx.SequenceNode
	seq := slot1 as cx.SequenceNode
	// Sequence: Interp, Text("/"), Interp
	assert seq.items.len == 3
	assert seq.items[0] is cx.InterpolationNode
	assert (seq.items[1] as cx.TextNode).value == '/'
	assert seq.items[2] is cx.InterpolationNode
}

// ── §D8 wildcard sentinel `*` in array slot ──────────────────────────────────

fn test_multi_branch_if_with_wildcard() {
	// `[?if [[c1, b1], [c2, b2], [*, default]]]` — multi-branch
	// form. Each inner pair is itself an array (comma-marker
	// disambiguates). The `*` sentinel parses as a CXPath wildcard
	// per §D8 — the parse_bracket_node sigil reorder ensures the
	// comma-marker rule wins over the `*` alias-element sigil.
	n := parse_one('[?if [[@stock > 100, Plenty], [@stock > 10, Some], [*, None]]]')
	d := n as cx.EvalDirectiveNode
	arr := d.items[0] as cx.ArrayNode
	assert arr.items.len == 3
	// Each item is a pair-array.
	for i in 0 .. 3 {
		pair := arr.items[i]
		assert pair is cx.ArrayNode
		p := pair as cx.ArrayNode
		assert p.items.len == 2
	}
	// Third pair: condition is `*`, body is `None`.
	last_pair := arr.items[2] as cx.ArrayNode
	assert (last_pair.items[0] as cx.TextNode).value == '*'
	assert (last_pair.items[1] as cx.TextNode).value == 'None'
}

// ── Atomic-array baseline: 1.d must NOT regress data-array semantics ─────────

fn test_atomic_array_scalars_preserved() {
	// `[1, 2, 3]` outside a directive — scalar autotyping still
	// applies per 1.d "single bare-token slot autotypes" rule.
	n := parse_one('[1, 2, 3]')
	arr := n as cx.ArrayNode
	assert arr.items.len == 3
	for i in 0 .. 3 {
		s := arr.items[i] as cx.ScalarNode
		assert s.data_type == .int_type
	}
}

fn test_atomic_array_nested_preserves_shape() {
	n := parse_one('[[1, 2], [3, 4]]')
	arr := n as cx.ArrayNode
	assert arr.items.len == 2
	inner0 := arr.items[0] as cx.ArrayNode
	assert inner0.items.len == 2
	assert (inner0.items[0] as cx.ScalarNode).data_type == .int_type
}

// ── Old syntax must error cleanly ────────────────────────────────────────────

fn test_old_attribute_slot_form_rejected() {
	// `[?if cond :then=[…]]` — the pre-ADR-0017 attribute-slot form
	// is no longer accepted under the new uniform shape. Parser
	// should surface a clear error pointing at ADR 0017 §D6.
	cx.parse('[?if cond :then=[yes] :else=[no]]') or {
		assert err.msg().contains('ADR 0017 §D6') || err.msg().contains('argument array')
		return
	}
	assert false, 'old attribute-slot form must reject'
}

fn test_old_positional_for_form_rejected() {
	// `[?for v in expr body]` — pre-ADR-0017 positional-text form.
	// Now invalid; arg array required.
	cx.parse('[?for v in //variant [card [?=v/@sku]]]') or {
		assert err.msg().contains('ADR 0017 §D6') || err.msg().contains('argument array')
		return
	}
	assert false, 'old positional-text for form must reject'
}

// ── Round-trip: parse → emit_cx → re-parse → identical AST ───────────────────

fn test_round_trip_three_slot_if() {
	src := '[?if [cond, [yes], [no]]]'
	d := cx.parse(src) or { panic(err) }
	out := cx.emit_cx(d).trim_right('\n')
	assert out == src, 'round-trip mismatch: got "${out}"'
}

fn test_round_trip_for_with_interp_body() {
	src := '[?for [v, //variant, [?=v/@sku]]]'
	d := cx.parse(src) or { panic(err) }
	out := cx.emit_cx(d).trim_right('\n')
	assert out == src, 'round-trip mismatch: got "${out}"'
}
