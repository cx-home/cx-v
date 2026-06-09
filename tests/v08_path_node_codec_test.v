module main

import cx

// Tests for the Phase 2.1 follow-up PathNode v8 binary codec
// (spec/core/ast-bin.md §4.4, tag 0x13).
//
// Coverage:
//   - Encode-decode round-trip for each PathForm (descendant /
//     absolute / relative / binding).
//   - Round-trip for a spread of axes (child, descendant, parent,
//     ancestor, attribute, self, descendant_or_self).
//   - Round-trip for each NodeTest discriminator form (Name,
//     wildcard, *:LocalName, Prefix:*, node(), text(), element(),
//     attribute()).
//   - Empty + multi predicate lists, per-step + trailing top-level.
//   - Decode failure modes (truncated, out-of-range form / axis /
//     node-test byte, form/binding mismatch).
//   - source / loc are NOT preserved through the codec (encode
//     discards them; decode returns empty values).

// ── Helpers ──────────────────────────────────────────────────────────────────

fn round_trip(node cx.PathNode) !cx.PathNode {
	buf := cx.encode_path_node(node)
	mut off := 0
	return cx.decode_path_node(buf, mut off)!
}

// ── Form coverage (4 cases) ──────────────────────────────────────────────────

fn test_round_trip_form_descendant() {
	p := cx.PathNode{
		form: cx.PathForm.descendant
		steps: [
			cx.PathStep{
				axis:       cx.PathAxis.child
				node_test:  'user'
				predicates: [cx.PathPredicate{ source: '@active=true' }]
			},
		]
	}
	got := round_trip(p) or { panic('round_trip: ${err}') }
	assert got.eq(p), 'descendant round-trip must preserve identity'
}

fn test_round_trip_form_absolute() {
	p := cx.PathNode{
		form: cx.PathForm.absolute
		steps: [
			cx.new_path_step(cx.PathAxis.child, 'root'),
			cx.new_path_step(cx.PathAxis.child, 'item'),
		]
	}
	got := round_trip(p) or { panic('round_trip: ${err}') }
	assert got.eq(p)
}

fn test_round_trip_form_relative() {
	p := cx.PathNode{
		form: cx.PathForm.relative
		steps: [
			cx.new_path_step(cx.PathAxis.child, 'user'),
			cx.new_path_step(cx.PathAxis.child, 'email'),
		]
	}
	got := round_trip(p) or { panic('round_trip: ${err}') }
	assert got.eq(p)
}

fn test_round_trip_form_binding() {
	mut p := cx.PathNode{
		form: cx.PathForm.binding
		binding: 'u'
		steps: [
			cx.new_path_step(cx.PathAxis.child, 'name'),
		]
	}
	got := round_trip(p) or { panic('round_trip: ${err}') }
	assert got.eq(p)
	if b := got.binding {
		assert b == 'u'
	} else {
		assert false, 'binding must round-trip'
	}
}

// ── Axis coverage (7 axes spread across the 12-row table) ────────────────────

fn axis_round_trip(axis cx.PathAxis) {
	p := cx.PathNode{
		form: cx.PathForm.relative
		steps: [cx.new_path_step(axis, 'x')]
	}
	got := round_trip(p) or { panic('round_trip: ${err}') }
	assert got.steps.len == 1
	assert got.steps[0].axis == axis, 'axis ${cx.path_axis_name(axis)} must round-trip'
}

fn test_round_trip_axis_child()              { axis_round_trip(cx.PathAxis.child) }
fn test_round_trip_axis_descendant()         { axis_round_trip(cx.PathAxis.descendant) }
fn test_round_trip_axis_descendant_or_self() { axis_round_trip(cx.PathAxis.descendant_or_self) }
fn test_round_trip_axis_parent()             { axis_round_trip(cx.PathAxis.parent) }
fn test_round_trip_axis_ancestor()           { axis_round_trip(cx.PathAxis.ancestor) }
fn test_round_trip_axis_self()               { axis_round_trip(cx.PathAxis.self_) }
fn test_round_trip_axis_attribute()          { axis_round_trip(cx.PathAxis.attribute) }

// ── NodeTest-form coverage (all 8 discriminator forms) ───────────────────────

fn node_test_round_trip(node_test string) {
	p := cx.PathNode{
		form: cx.PathForm.relative
		steps: [cx.new_path_step(cx.PathAxis.child, node_test)]
	}
	got := round_trip(p) or { panic('round_trip: ${err}') }
	assert got.steps.len == 1
	assert got.steps[0].node_test == node_test,
		'node_test ${node_test} must round-trip verbatim'
}

fn test_node_test_bare_name()         { node_test_round_trip('user') }
fn test_node_test_wildcard()          { node_test_round_trip('*') }
fn test_node_test_namespace_wildcard() { node_test_round_trip('*:LocalName') }
fn test_node_test_local_wildcard()    { node_test_round_trip('Prefix:*') }
fn test_node_test_node_kind()         { node_test_round_trip('node()') }
fn test_node_test_text_kind()         { node_test_round_trip('text()') }
fn test_node_test_element_kind()      { node_test_round_trip('element()') }
fn test_node_test_attribute_kind()    { node_test_round_trip('attribute()') }

// ── Predicate count coverage ─────────────────────────────────────────────────

fn test_empty_predicates() {
	p := cx.PathNode{
		form: cx.PathForm.relative
		steps: [
			cx.PathStep{ axis: cx.PathAxis.child, node_test: 'user' },
		]
	}
	got := round_trip(p) or { panic('round_trip: ${err}') }
	assert got.eq(p)
	assert got.steps[0].predicates.len == 0
	assert got.predicates.len == 0
}

fn test_multi_predicates_per_step() {
	p := cx.PathNode{
		form: cx.PathForm.relative
		steps: [
			cx.PathStep{
				axis:      cx.PathAxis.child
				node_test: 'user'
				predicates: [
					cx.PathPredicate{ source: '@active=true' },
					cx.PathPredicate{ source: 'position()=1' },
					cx.PathPredicate{ source: '@role="admin"' },
				]
			},
		]
	}
	got := round_trip(p) or { panic('round_trip: ${err}') }
	assert got.eq(p)
	assert got.steps[0].predicates.len == 3
	assert got.steps[0].predicates[0].source == '@active=true'
	assert got.steps[0].predicates[1].source == 'position()=1'
	assert got.steps[0].predicates[2].source == '@role="admin"'
}

fn test_top_level_trailing_predicates() {
	p := cx.PathNode{
		form: cx.PathForm.descendant
		steps: [cx.new_path_step(cx.PathAxis.child, 'user')]
		predicates: [
			cx.PathPredicate{ source: '@active=true' },
			cx.PathPredicate{ source: '@deleted=false' },
		]
	}
	got := round_trip(p) or { panic('round_trip: ${err}') }
	assert got.eq(p)
	assert got.predicates.len == 2
	assert got.predicates[0].source == '@active=true'
	assert got.predicates[1].source == '@deleted=false'
}

// ── source / loc exclusion ─────────────────────────────────────

fn test_source_and_loc_excluded_from_wire() {
	// Build a PathNode WITH source + loc populated …
	p := cx.PathNode{
		form: cx.PathForm.descendant
		steps: [cx.new_path_step(cx.PathAxis.child, 'user')]
		source: '//user'
		loc: cx.PathLoc{ line: 42, col: 7 }
	}
	got := round_trip(p) or { panic('round_trip: ${err}') }

	// … and assert that after round-trip the advisory fields are
	// reset to none (per wire form is identity-only).
	assert got.source == none, 'source must not survive the wire'
	assert got.loc == none, 'loc must not survive the wire'

	// But identity-participating fields DO round-trip — .eq() ignores
	// source/loc, so the two PathNodes still compare equal.
	assert got.eq(p), 'identity preserved despite source/loc loss'
}

fn test_encoded_bytes_byte_identical_for_eq_inputs() {
	// Two PathNodes that differ ONLY in source/loc must encode to
	// byte-identical buffers (spec/core/ast-bin.md §4.4: "Two PathNode
	// values that compare equal under the §D9 equality rule MUST
	// produce byte-identical ast_bin payloads").
	a := cx.PathNode{
		form: cx.PathForm.descendant
		steps: [cx.new_path_step(cx.PathAxis.child, 'user')]
		source: '//user'
	}
	b := cx.PathNode{
		form: cx.PathForm.descendant
		steps: [cx.new_path_step(cx.PathAxis.child, 'user')]
		source: '// user'
		loc: cx.PathLoc{ line: 99, col: 1 }
	}
	assert a.eq(b)
	bytes_a := cx.encode_path_node(a)
	bytes_b := cx.encode_path_node(b)
	assert bytes_a == bytes_b, 'eq-PathNodes must produce byte-identical wire'
}

// ── Decode failure modes ─────────────────────────────────────────────────────

fn test_decode_rejects_out_of_range_form_byte() {
	// form byte 0x04 is reserved (valid range is 0x00..0x03).
	bad := [u8(0x04),  // form (reserved)
		u8(0),         // binding absent
		u8(0), u8(0),  // step_count = 0
		u8(0), u8(0)]  // predicate_count = 0
	mut off := 0
	res := cx.decode_path_node(bad, mut off) or {
		assert err.msg().contains('form'), 'error should mention form: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject reserved form byte'
}

fn test_decode_rejects_out_of_range_axis_byte() {
	// Valid form + binding absent + 1 step with axis byte 0x0C (reserved).
	bad := [u8(0x02), // form = relative
		u8(0),        // binding absent
		u8(1), u8(0), // step_count = 1
		u8(0x0C),     // axis (reserved — valid is 0x00..0x0B)
		u8(0x00),     // node_test_kind = Name
		u8(1), u8(0), u8(0), u8(0), u8(`a`), // node_test_name "a"
		u8(0), u8(0)] // step_pred_count = 0
	mut off := 0
	res := cx.decode_path_node(bad, mut off) or {
		assert err.msg().contains('axis'), 'error should mention axis: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject reserved axis byte'
}

fn test_decode_rejects_out_of_range_node_test_kind() {
	bad := [u8(0x02), // form = relative
		u8(0),
		u8(1), u8(0), // step_count = 1
		u8(0x00),     // axis = child
		u8(0x08),     // node_test_kind (reserved — valid is 0x00..0x07)
		u8(0), u8(0), u8(0), u8(0), // empty name
		u8(0), u8(0)] // step_pred_count = 0
	mut off := 0
	res := cx.decode_path_node(bad, mut off) or {
		assert err.msg().contains('node_test_kind'),
			'error should mention node_test_kind: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject reserved node_test_kind'
}

fn test_decode_rejects_truncated_buffer() {
	// form byte only — missing optstr flag, step_count, etc.
	bad := [u8(0x00)]
	mut off := 0
	res := cx.decode_path_node(bad, mut off) or {
		// Any error is acceptable; we just need this NOT to succeed.
		return
	}
	_ = res
	assert false, 'decode must reject truncated buffer'
}

fn test_decode_rejects_binding_present_with_non_binding_form() {
	// form = relative (0x02) but binding present — spec §4.4
	// "Form / binding consistency" forbids this.
	bad := [u8(0x02),                 // form = relative
		u8(1),                        // binding present (illegal)
		u8(1), u8(0), u8(0), u8(0), u8(`u`), // binding name "u"
		u8(0), u8(0),                 // step_count = 0
		u8(0), u8(0)]                 // predicate_count = 0
	mut off := 0
	res := cx.decode_path_node(bad, mut off) or {
		assert err.msg().contains('binding'), 'error should mention binding: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject binding-present with non-binding form'
}

fn test_decode_rejects_binding_absent_with_binding_form() {
	// form = binding (0x03) but binding absent.
	bad := [u8(0x03),
		u8(0),        // binding absent (illegal for form=binding)
		u8(0), u8(0), // step_count = 0
		u8(0), u8(0)] // predicate_count = 0
	mut off := 0
	res := cx.decode_path_node(bad, mut off) or {
		assert err.msg().contains('binding'), 'error should mention binding: ${err}'
		return
	}
	_ = res
	assert false, 'decode must reject form=binding with binding absent'
}

// ── Spec example fixtures (spec/core/ast-bin.md §6.5) ─────────────────────────────

fn test_round_trip_spec_example_descendant_user() {
	// `//user[@active=true]` — §6.5 first example.
	p := cx.PathNode{
		form: cx.PathForm.descendant
		steps: [
			cx.PathStep{
				axis:       cx.PathAxis.child
				node_test:  'user'
				predicates: [cx.PathPredicate{ source: '@active=true' }]
			},
		]
	}
	got := round_trip(p) or { panic('round_trip: ${err}') }
	assert got.eq(p)
}

fn test_round_trip_spec_example_binding_email() {
	// `$u/email` — §6.5 second example.
	mut p := cx.PathNode{
		form:    cx.PathForm.binding
		binding: 'u'
		steps: [
			cx.new_path_step(cx.PathAxis.child, 'email'),
		]
	}
	got := round_trip(p) or { panic('round_trip: ${err}') }
	assert got.eq(p)
	if b := got.binding {
		assert b == 'u'
	} else {
		assert false, 'binding must round-trip'
	}
}

// ── Offset advance ───────────────────────────────────────────────────────────

fn test_decode_advances_offset() {
	p := cx.PathNode{
		form: cx.PathForm.descendant
		steps: [cx.new_path_step(cx.PathAxis.child, 'user')]
	}
	buf := cx.encode_path_node(p)
	mut off := 0
	_ := cx.decode_path_node(buf, mut off) or { panic('decode: ${err}') }
	assert off == buf.len, 'offset must advance past the entire payload (off=${off}, buf.len=${buf.len})'
}

// ── PathStep `:bind NCName` peer-modifier wire slot (Phase 2.20 codec) ───────
//
// Closes the Phase 2.20 wire-format gap (spec/core/ast-bin.md §4.4 PathStep
// OptString:binding slot, additive within v8, allocated 2026-05-23).
// PathStep.binding now round-trips through the §4.4 codec — previously
// it survived only in the in-memory AST + JSON projection + text
// renderer.

fn test_round_trip_step_binding_some() {
	// Single step carrying `:bind u`.
	p := cx.PathNode{
		form: cx.PathForm.relative
		steps: [
			cx.PathStep{
				axis:      cx.PathAxis.child
				node_test: 'team'
				binding:   ?string('u')
			},
		]
	}
	got := round_trip(p) or { panic('round_trip: ${err}') }
	assert got.eq(p), 'step :bind must round-trip identity'
	assert got.steps.len == 1
	if b := got.steps[0].binding {
		assert b == 'u', 'step binding name must round-trip verbatim'
	} else {
		assert false, 'step binding must survive the wire'
	}
}

fn test_round_trip_step_binding_all_none() {
	// All steps explicitly unbound — the absent OptString collapses to
	// a single 0x00 byte per step, preserving the legacy v8 shape.
	p := cx.PathNode{
		form: cx.PathForm.relative
		steps: [
			cx.new_path_step(cx.PathAxis.child, 'a'),
			cx.new_path_step(cx.PathAxis.child, 'b'),
			cx.new_path_step(cx.PathAxis.child, 'c'),
		]
	}
	got := round_trip(p) or { panic('round_trip: ${err}') }
	assert got.eq(p), 'all-unbound path must round-trip identity'
	for s in got.steps {
		assert s.binding == none, 'unbound step must round-trip as binding=none'
	}
}

fn test_round_trip_step_binding_mixed() {
	// Multi-step path with a mix of bound and unbound steps. Mirrors
	// worked example 4 shape:
	//   /team :bind t / member
	p := cx.PathNode{
		form: cx.PathForm.absolute
		steps: [
			cx.PathStep{
				axis:      cx.PathAxis.child
				node_test: 'team'
				binding:   ?string('t')
			},
			cx.PathStep{
				axis:      cx.PathAxis.child
				node_test: 'member'
			},
		]
	}
	got := round_trip(p) or { panic('round_trip: ${err}') }
	assert got.eq(p), 'mixed-binding path must round-trip identity'
	assert got.steps.len == 2
	if b := got.steps[0].binding {
		assert b == 't', 'first step :bind t must survive'
	} else {
		assert false, 'first step must keep its :bind t'
	}
	assert got.steps[1].binding == none, 'second step must remain unbound'
}

fn test_round_trip_step_binding_with_predicates() {
	// `:bind` peer-modifier coexists with per-step predicates — the
	// wire layout interleaves OptString:binding BEFORE step_pred_count.
	p := cx.PathNode{
		form: cx.PathForm.descendant
		steps: [
			cx.PathStep{
				axis:      cx.PathAxis.child
				node_test: 'user'
				binding:   ?string('u')
				predicates: [
					cx.PathPredicate{ source: '@active=true' },
					cx.PathPredicate{ source: 'position()=1' },
				]
			},
		]
	}
	got := round_trip(p) or { panic('round_trip: ${err}') }
	assert got.eq(p), 'bound step with predicates must round-trip'
	assert got.steps[0].predicates.len == 2
	if b := got.steps[0].binding {
		assert b == 'u'
	} else {
		assert false, 'step binding must coexist with predicates'
	}
}

fn test_backward_compat_legacy_payload_decodes() {
	// Hand-construct a v8 payload using the post-slot wire format with
	// every step's binding-present flag set to 0 — this is byte-identical
	// to a pre-slot legacy v8 payload (the OptString collapses to a
	// single 0x00 byte). The new decoder MUST read it unchanged.
	//
	// Payload: form=descendant, no top-level binding, 1 step
	//   { axis=child, node_test_kind=Name, name="user", binding=absent,
	//     step_pred_count=0 }
	//   predicate_count=0
	legacy := [
		u8(0x00),                                     // form = descendant
		u8(0),                                        // top-level binding absent
		u8(1), u8(0),                                 // step_count = 1 (u16 LE)
		u8(0x00),                                     // step[0].axis = child
		u8(0x00),                                     // step[0].node_test_kind = Name
		u8(4), u8(0), u8(0), u8(0),                   // node_test_name len = 4
		u8(`u`), u8(`s`), u8(`e`), u8(`r`),           // "user"
		u8(0),                                        // step[0].binding absent (legacy 0x00)
		u8(0), u8(0),                                 // step[0].step_pred_count = 0
		u8(0), u8(0),                                 // top-level predicate_count = 0
	]
	mut off := 0
	got := cx.decode_path_node(legacy, mut off) or {
		panic('legacy payload must decode: ${err}')
	}
	assert off == legacy.len, 'decode must consume all bytes (off=${off}, len=${legacy.len})'
	assert got.form == cx.PathForm.descendant
	assert got.steps.len == 1
	assert got.steps[0].node_test == 'user'
	assert got.steps[0].binding == none,
		'legacy payload step must decode with binding=none'
}

fn test_step_binding_changes_canonical_bytes() {
	// Two PathNodes that differ ONLY in step binding (some "u" vs none)
	// MUST produce different wire payloads — the OptString slot is
	// identity-relevant (the binding changes path
	// semantics, not just surface shape).
	bound := cx.PathNode{
		form: cx.PathForm.relative
		steps: [
			cx.PathStep{
				axis:      cx.PathAxis.child
				node_test: 'team'
				binding:   ?string('u')
			},
		]
	}
	unbound := cx.PathNode{
		form: cx.PathForm.relative
		steps: [
			cx.PathStep{
				axis:      cx.PathAxis.child
				node_test: 'team'
			},
		]
	}
	assert !bound.eq(unbound), '.eq() must distinguish bound from unbound step'
	bytes_bound := cx.encode_path_node(bound)
	bytes_unbound := cx.encode_path_node(unbound)
	assert bytes_bound != bytes_unbound,
		'different bindings must produce different wire payloads'
	// And the bound buffer must be longer by exactly the OptString
	// delta: present flag flips 0x00 → 0x01 (no byte added) and the
	// String body (4 length bytes + 1 utf-8 byte for "u") = +5 bytes.
	assert bytes_bound.len == bytes_unbound.len + 5,
		'bound wire = unbound wire + String("u") body = +5 bytes ' +
		'(bound=${bytes_bound.len}, unbound=${bytes_unbound.len})'
}
