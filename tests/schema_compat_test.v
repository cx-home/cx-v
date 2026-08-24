module main

import cx

// schema_compat_test — the RULED: SEA-1 compat-classification matrix
// (spec/03-approved/core/schema.md §16.5): every change class classifies
// to its ruled verdict — the derivable classes derive their translator
// (the Lane-2 [schema-lineage] claim carrying [derived] rules, §16.5.2),
// the reinterpreting classes REFUSE with a specific prompt naming the
// missing rule. Renames are declared, never guessed (SEA-1a); removal
// refuses by default and derives only under the explicit acknowledgment
// (SEA-1c); the translator is deterministic (content-addressable).
//
// The seam-side behavior of the derived translator (lossless rewrite,
// chain-wise discriminator, CXER4641/4610 refusals) is pinned by
// conformance/stdlib/journal.cxd journal-155/156; the publish/install
// consumers by conformance/stdlib/xap-dist.cxd xap-dist-051/052.

const v1 = "[schema of=order name='v1']
[order
 [attr id::string [req]]
 [attr total::int [req]]
 [attr note::string [opt]]
 [attr status::atom [opt] [enum :new :sent]]
 [attr qty::i16 [opt] [range 1 10]]
 [elem line [card \"0..3\"]]]
[type line::string]"

fn compat(new_schema string, opts cx.SchemaCompatOpts) cx.SchemaCompatReport {
	return cx.schema_compat(v1, new_schema, opts) or {
		assert false, 'schema_compat errored: ${err}'
		cx.SchemaCompatReport{}
	}
}

fn classes_of(rep cx.SchemaCompatReport) []string {
	mut out := []string{}
	for c in rep.changes {
		out << c.class
	}
	return out
}

// ── the derivable classes ────────────────────────────────────────────────────

fn test_additive_optional_and_default_derive() {
	rep := compat("[schema of=order name='v2']
[order
 [attr id::string [req]]
 [attr total::int [req]]
 [attr note::string [opt]]
 [attr status::atom [opt] [enum :new :sent]]
 [attr qty::i16 [opt] [range 1 10]]
 [attr channel::string [default 'web']]
 [attr priority::int [opt]]
 [elem line [card \"0..3\"]]]
[type line::string]", cx.SchemaCompatOpts{})
	assert rep.verdict == 'derivable'
	assert 'additive-default' in classes_of(rep)
	assert 'additive-optional' in classes_of(rep)
	// the translator is the claim-with-derived-rules document (SEA-1g).
	assert rep.translator.contains('[schema-lineage')
	assert rep.translator.contains('[relation :additive]')
	assert rep.translator.contains("[set-default attr=channel value='web' vtype=string]")
	assert rep.translator.contains('[derived root=order')
	assert !rep.translator.contains('[?def') // data, never a generated def
	// determinism: same pair + same declarations → byte-identical translator.
	rep2 := compat("[schema of=order name='v2']
[order
 [attr id::string [req]]
 [attr total::int [req]]
 [attr note::string [opt]]
 [attr status::atom [opt] [enum :new :sent]]
 [attr qty::i16 [opt] [range 1 10]]
 [attr channel::string [default 'web']]
 [attr priority::int [opt]]
 [elem line [card \"0..3\"]]]
[type line::string]", cx.SchemaCompatOpts{})
	assert rep2.translator == rep.translator
	assert rep.upcaster_name.starts_with('upcast-')
}

fn test_widen_classes_derive_with_identity_translator() {
	rep := compat("[schema of=order name='v2']
[order
 [attr id::string [req]]
 [attr total::i64 [req]]
 [attr note::string [opt]]
 [attr status::atom [opt] [enum :new :sent :held]]
 [attr qty::i32 [opt] [range 0 20]]
 [elem line [card \"0..*\"]]]
[type line::string]", cx.SchemaCompatOpts{})
	assert rep.verdict == 'derivable'
	for c in rep.changes {
		assert c.class == 'widen', 'expected only widen, got ${c.class}: ${c.detail}'
	}
	// widen-only: no field rules — the claim restamps only.
	assert rep.translator.contains('[derived root=order]')
}

fn test_int_to_float_join_widens() {
	rep := compat("[schema of=order name='v2']
[order
 [attr id::string [req]]
 [attr total::float [req]]
 [attr note::string [opt]]
 [attr status::atom [opt] [enum :new :sent]]
 [attr qty::i16 [opt] [range 1 10]]
 [elem line [card \"0..3\"]]]
[type line::string]", cx.SchemaCompatOpts{})
	assert rep.verdict == 'derivable'
	assert classes_of(rep) == ['widen']
}

fn test_declared_rename_derives_undeclared_refuses_naming_candidate() {
	new_s := "[schema of=order name='v2']
[order
 [attr id::string [req]]
 [attr total::int [req]]
 [attr memo::string [opt]]
 [attr status::atom [opt] [enum :new :sent]]
 [attr qty::i16 [opt] [range 1 10]]
 [elem line [card \"0..3\"]]]
[type line::string]"
	// SEA-1a: undeclared → refusal naming the candidate pair + the declaration.
	rep := compat(new_s, cx.SchemaCompatOpts{})
	assert rep.verdict == 'refused'
	mut named := false
	for c in rep.changes {
		if c.class == 'remove' && c.prompt.contains('--rename order/note=memo') {
			named = true
		}
	}
	assert named, 'the refusal must name the rename declaration'
	// declared → derives the rename rule.
	rep2 := compat(new_s, cx.SchemaCompatOpts{
		renames: {
			'order/note': 'memo'
		}
	})
	assert rep2.verdict == 'derivable'
	assert 'rename' in classes_of(rep2)
	assert rep2.translator.contains('[rename-attr from=note to=memo]')
}

fn test_default_changed_materializes_the_old_default() {
	old := "[schema of=server]
[server
 [attr host::string [req]]
 [attr port::u16 [default 8080]]]"
	new_s := "[schema of=server]
[server
 [attr host::string [req]]
 [attr port::u16 [default 9090]]]"
	rep := cx.schema_compat(old, new_s, cx.SchemaCompatOpts{}) or {
		assert false, '${err}'
		return
	}
	assert rep.verdict == 'derivable'
	assert classes_of(rep) == ['default-changed']
	// the OLD default materializes on old data — old meaning preserved.
	assert rep.translator.contains("[set-default attr=port value='8080' vtype=u16]")
}

fn test_allow_remove_acknowledgment_derives_the_drop() {
	new_s := "[schema of=order name='v2']
[order
 [attr id::string [req]]
 [attr total::int [req]]
 [attr status::atom [opt] [enum :new :sent]]
 [attr qty::i16 [opt] [range 1 10]]
 [elem line [card \"0..3\"]]]
[type line::string]"
	// SEA-1c: default refuses.
	rep := compat(new_s, cx.SchemaCompatOpts{})
	assert rep.verdict == 'refused'
	// acknowledged → derives the dropping rule.
	rep2 := compat(new_s, cx.SchemaCompatOpts{ allow_remove: ['order/note'] })
	assert rep2.verdict == 'derivable'
	assert rep2.translator.contains('[drop-attr attr=note]')
}

// ── the refusal classes: each names its missing rule ─────────────────────────

fn refusal_prompts(rep cx.SchemaCompatReport) string {
	mut out := ''
	for c in rep.changes {
		if c.prompt != '' {
			out += c.prompt + '\n'
		}
	}
	return out
}

fn test_req_addition_refuses_even_in_open_mode() {
	rep := compat("[schema of=order name='v2']
[order
 [attr id::string [req]]
 [attr total::int [req]]
 [attr note::string [req]]
 [attr status::atom [opt] [enum :new :sent]]
 [attr qty::i16 [opt] [range 1 10]]
 [elem line [card \"0..3\"]]]
[type line::string]", cx.SchemaCompatOpts{})
	assert rep.verdict == 'refused'
	assert refusal_prompts(rep).contains('breaking even in open mode')
	assert rep.translator == '' // nothing derives on a refusal
}

fn test_enum_narrowing_names_the_dropped_values() {
	rep := compat("[schema of=order name='v2']
[order
 [attr id::string [req]]
 [attr total::int [req]]
 [attr note::string [opt]]
 [attr status::atom [opt] [enum :new]]
 [attr qty::i16 [opt] [range 1 10]]
 [elem line [card \"0..3\"]]]
[type line::string]", cx.SchemaCompatOpts{})
	assert rep.verdict == 'refused'
	assert refusal_prompts(rep).contains('{sent}')
}

fn test_range_and_card_narrowing_refuse() {
	rep := compat("[schema of=order name='v2']
[order
 [attr id::string [req]]
 [attr total::int [req]]
 [attr note::string [opt]]
 [attr status::atom [opt] [enum :new :sent]]
 [attr qty::i16 [opt] [range 2 5]]
 [elem line [card \"1..2\"]]]
[type line::string]", cx.SchemaCompatOpts{})
	assert rep.verdict == 'refused'
	prompts := refusal_prompts(rep)
	assert prompts.contains('narrowed its range')
	assert prompts.contains('narrowed its cardinality')
}

fn test_type_reinterpretation_refuses() {
	rep := compat("[schema of=order name='v2']
[order
 [attr id::string [req]]
 [attr total::string [req]]
 [attr note::string [opt]]
 [attr status::atom [opt] [enum :new :sent]]
 [attr qty::i16 [opt] [range 1 10]]
 [elem line [card \"0..3\"]]]
[type line::string]", cx.SchemaCompatOpts{})
	assert rep.verdict == 'refused'
	mut found := false
	for c in rep.changes {
		if c.class == 'reinterpret' && c.field == 'total' {
			found = true
			assert c.prompt.contains('int -> string')
		}
	}
	assert found
}

fn test_root_change_refuses_and_identical_is_identical() {
	rep := cx.schema_compat(v1, "[schema of=invoice]
[invoice [attr id::string [req]]]", cx.SchemaCompatOpts{}) or {
		assert false, '${err}'
		return
	}
	assert rep.verdict == 'refused'
	assert 'reinterpret' in classes_of(rep)
	// identical (comment/whitespace differences normalize away).
	same := cx.schema_compat(v1, v1 + '\n# a comment\n', cx.SchemaCompatOpts{}) or {
		assert false, '${err}'
		return
	}
	assert same.verdict == 'identical'
	assert same.changes.len == 0
}

fn test_pattern_change_refuses_pattern_removal_widens() {
	old := "[schema of=doc]
[doc [attr slug::string [req] [pattern '[a-z]+']]]"
	changed := "[schema of=doc]
[doc [attr slug::string [req] [pattern '[a-z0-9]+']]]"
	removed := "[schema of=doc]
[doc [attr slug::string [req]]]"
	rep := cx.schema_compat(old, changed, cx.SchemaCompatOpts{}) or {
		assert false, '${err}'
		return
	}
	assert rep.verdict == 'refused' // containment is not mechanically provable
	rep2 := cx.schema_compat(old, removed, cx.SchemaCompatOpts{}) or {
		assert false, '${err}'
		return
	}
	assert rep2.verdict == 'derivable'
	assert classes_of(rep2) == ['widen']
}

fn test_report_text_carries_missing_rules() {
	rep := compat("[schema of=order name='v2']
[order
 [attr id::string [req]]
 [attr total::string [req]]
 [attr note::string [opt]]
 [attr status::atom [opt] [enum :new :sent]]
 [attr qty::i16 [opt] [range 1 10]]
 [elem line [card \"0..3\"]]]
[type line::string]", cx.SchemaCompatOpts{})
	txt := cx.schema_compat_report_text(rep)
	assert txt.contains('verdict=refused')
	assert txt.contains('[missing-rule class=reinterpret type=order')
	assert txt.contains('prompt=')
}
