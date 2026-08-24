// code_diagram_completeness_gate_test.v — the DR-5 bidirectional
// completeness gate, extended to the SECOND renderer (#889, RULED
// DRW3-1; ledger/rulings_2026_08_20_diagram_wave3.md). Normative
// statement: spec/03-approved/std-lib/diagram.md §wave-3 rule table.
//
// The wave-1 gate polices the §10.1.2 locked table against the
// reference renderer. This one polices the playground renderer's own
// sealed table (`[$diagram:code-rules]`, stdlib/diagram.cx §9.0) —
// which the emitters READ, so the table is the set, not a comment about
// it. Five clauses, red on drift in either direction:
//
//   (i)   every table row names a LIVE grammar-registry directive (a
//         retired name reddens here);
//   (ii)  the LIVE dispatch class equals the table's class for every
//         registry directive, and every class is drawn from the closed
//         set the emitter implements — a row whose class the emitter
//         does not handle reddens;
//   (iii) every `seq`, `trigger` and `breaks-block` row is exercised by
//         at least one source in the golden corpus;
//   (iv)  the `erd-type` rows are exactly the scalar value tags the
//         ast.md §4 projection can hand the renderer — a new scalar
//         kind in the image reddens here instead of silently reporting
//         `string`;
//   (v)   a directive OUTSIDE the table renders through the declared
//         generic paths (a `Note over` note in SEQ, a basic-block line
//         in CFG) rather than vanishing;
//   (vi)  the module's table and the NORMATIVE tables in
//         spec/03-approved/std-lib/diagram.md §10.2 are SET-EQUAL in
//         both directions — this is the clause that reddens when a row
//         is simply deleted from one side (clauses i-v stay consistent
//         under a matched deletion, because the emitters read the
//         table).

module main

import os
import cx
import code
import platform as _

struct CodeRules {
mut:
	triggers []string
	breaks   []string
	seq      map[string]string // directive → class
	erd      []string          // erd-type kinds
}

fn code_rules() CodeRules {
	val := code.code_diagram_rules_value() or {
		assert false, 'code_diagram_rules_value: ${err}'
		return CodeRules{}
	}
	mut t := CodeRules{}
	if val is cx.Element {
		for it in val.items {
			if it is cx.Element {
				mut dname := ''
				mut cls := ''
				mut kind := ''
				for a in it.attrs {
					match a.name {
						'directive' { dname = cx.scalar_value_str_public(a.value) }
						'class' { cls = cx.scalar_value_str_public(a.value) }
						'kind' { kind = cx.scalar_value_str_public(a.value) }
						else {}
					}
				}
				match it.name {
					'trigger' { t.triggers << dname }
					'breaks-block' { t.breaks << dname }
					'seq' { t.seq[dname] = cls }
					'erd-type' { t.erd << kind }
					else {}
				}
			}
		}
	}
	return t
}

// The classes the SEQ emitter implements (cd-seq-inner's arms).
const seq_classes = ['send', 'receive', 'select', 'async', 'await', 'cancel', 'resilience',
	'let', 'branch', 'for']

// Emitter twins — a row whose emitter a sibling row already exercises.
const code_emitter_twins = {
	'await-any':  'await'
	'await-race': 'await'
}

// The scalar value tags the ast.md §4 projection emits for a literal
// (vcx/code/diagram_cx_seam.v :: dgi_literal) — the ERD type map's
// domain. `cx:data` (a node literal) and the container tags are not
// scalar rows.
const image_scalar_tags = ['int', 'bigint', 'decimal', 'float', 'bool', 'str', 'atom', 'dur',
	'period', 'date', 'datetime']

fn test_clause_i_every_row_is_a_live_registry_directive() {
	t := code_rules()
	assert t.triggers.len == 5, 'trigger rows: ${t.triggers}'
	assert t.breaks.len == 6, 'breaks-block rows: ${t.breaks}'
	assert t.seq.len >= 20, 'seq rows: ${t.seq.len}'
	mut stale := []string{}
	for d in t.triggers {
		if !cx.is_directive_name(d) {
			stale << 'trigger:${d}'
		}
	}
	for d in t.breaks {
		if !cx.is_directive_name(d) {
			stale << 'breaks-block:${d}'
		}
	}
	for d, _ in t.seq {
		if !cx.is_directive_name(d) {
			stale << 'seq:${d}'
		}
	}
	assert stale.len == 0, 'wave-3 rule-table names not in the grammar registry: ${stale}'
}

fn test_clause_ii_live_dispatch_equals_the_table() {
	t := code_rules()
	for d, cls in t.seq {
		assert cls in seq_classes, 'seq row [?${d}] declares class `${cls}`, which no emitter arm implements'
	}
	// Total over the registry: the module's own dispatch answers the
	// table's class for a named directive and `generic` for every other.
	for d in cx.directive_names {
		live := code.code_diagram_class(d) or {
			assert false, 'code_diagram_class(${d}): ${err}'
			return
		}
		expected := t.seq[d] or { 'generic' }
		assert live == expected, 'dispatch drift for [?${d}]: live=${live}, table=${expected}'
	}
}

fn corpus_sources() []string {
	dir := os.real_path(os.join_path(os.dir(@FILE), 'testdata', 'code_diagram_golden'))
	mut files := os.ls(dir) or {
		assert false, 'golden dir missing: ${dir}'
		return []
	}
	files.sort()
	mut out := []string{}
	for f in files {
		if !f.ends_with('.source') {
			continue
		}
		out << os.read_file(os.join_path(dir, f)) or { continue }
	}
	return out
}

fn test_clause_iii_every_row_is_exercised_by_the_corpus() {
	sources := corpus_sources()
	assert sources.len >= 80, 'expected the 88-source corpus, saw ${sources.len}'
	t := code_rules()
	mut names := []string{}
	names << t.triggers
	names << t.breaks
	for d, _ in t.seq {
		if d !in names {
			names << d
		}
	}
	mut unexercised := []string{}
	for d in names {
		mut hit := false
		for s in sources {
			if s.contains('[?${d}') {
				hit = true
				break
			}
		}
		if !hit {
			// Emitter twins: the await family shares ONE emitter whose
			// label is the directive name, so an exercised sibling proves
			// the rule (the wave-1 gate's precedent, kept explicit).
			if twin := code_emitter_twins[d] {
				for s in sources {
					if s.contains('[?${twin}') {
						hit = true
						break
					}
				}
			}
		}
		if !hit {
			unexercised << d
		}
	}
	assert unexercised.len == 0, 'wave-3 rule rows with no exercising corpus source: ${unexercised}'
}

fn test_clause_iv_erd_type_rows_cover_the_image_scalar_tags() {
	t := code_rules()
	mut missing := []string{}
	for tag in image_scalar_tags {
		if tag !in t.erd {
			missing << tag
		}
	}
	mut extra := []string{}
	for k in t.erd {
		if k !in image_scalar_tags {
			extra << k
		}
	}
	assert missing.len == 0, 'image scalar tags with no ERD type row: ${missing}'
	assert extra.len == 0, 'ERD type rows for tags the §4 image never emits: ${extra}'
}

fn test_clause_v_untabled_directive_takes_the_generic_paths() {
	// SEQ: an inner directive outside the table renders as a note.
	seq_out := code.code_diagram('[?worker name="w" [?const [c 1]]]') or {
		assert false, 'render seq probe: ${err}'
		return
	}
	assert seq_out.contains('Note over w : [?const]'), 'untabled inner directive lost its generic note:\n${seq_out}'
	// CFG: an untabled directive composes into a basic block instead of
	// breaking it.
	cfg_out := code.code_diagram('[?const [c 1]]\n[?const [d 2]]') or {
		assert false, 'render cfg probe: ${err}'
		return
	}
	assert cfg_out.contains('flowchart TD'), 'expected a CFG for a code source:\n${cfg_out}'
	assert cfg_out.contains('b["[?const]\\n[?const]"]'), 'untabled directives did not compose into ONE basic block:\n${cfg_out}'
}

// ── clause (vi): the spec §10.2 tables ↔ the module's table ──────────
//
// The module's table drives the emitters, so deleting a row from it
// keeps the module SELF-consistent (the goldens catch the behavior
// change, but the completeness gate would not). The spec section is
// the independent side of the bidirectional check: §10.2's three
// tables and the module's rows must agree exactly, in both directions.

struct SpecRules {
mut:
	triggers []string
	breaks   []string
	seq      []string
}

fn spec_wave3_rules() SpecRules {
	spec_path := os.real_path(os.join_path(os.dir(@FILE), '..', '..', 'spec', '03-approved',
		'std-lib', 'diagram.md'))
	text := os.read_file(spec_path) or {
		assert false, 'read ${spec_path}: ${err}'
		return SpecRules{}
	}
	start := text.index('### §10.2 The sealed wave-3 rule table') or {
		assert false, '§10.2 heading not found in std-lib/diagram.md'
		return SpecRules{}
	}
	rest := text[start..]
	end := rest.index('### §10.3') or { rest.len }
	body := rest[..end]
	// Three labelled table blocks, each a run of `| … |` rows after its
	// bold caption. Directive cells carry `[?name]` tokens.
	mut out := SpecRules{}
	trig_at := body.index('**Sequence triggers**') or { 0 }
	brk_at := body.index('**Block breakers**') or { 0 }
	seq_at := body.index('**SEQ inner-dispatch classes**') or { 0 }
	erd_at := body.index('**ERD scalar types**') or { body.len }
	out.triggers = directive_tokens(body[trig_at..brk_at])
	out.breaks = directive_tokens(body[brk_at..seq_at])
	out.seq = directive_tokens(body[seq_at..erd_at])
	return out
}

fn directive_tokens(chunk string) []string {
	mut out := []string{}
	// Only the FIRST cell of a table row names directives; the Render /
	// Class cell is prose and may mention other directives.
	for line in chunk.split('\n') {
		if !line.starts_with('| `[?') {
			continue
		}
		cell := line[1..].all_before('|')
		mut i := 0
		for {
			j := cell.index_after('[?', i) or { break }
			mut k := j + 2
			for k < cell.len && ((cell[k] >= `a` && cell[k] <= `z`) || cell[k] == `-`) {
				k++
			}
			name := cell[j + 2..k]
			if name.len > 0 && name !in out {
				out << name
			}
			i = k
		}
	}
	return out
}

fn assert_set_equal(spec []string, module_ []string, what string) {
	mut missing_in_module := []string{}
	for d in spec {
		if d !in module_ {
			missing_in_module << d
		}
	}
	mut missing_in_spec := []string{}
	for d in module_ {
		if d !in spec {
			missing_in_spec << d
		}
	}
	assert missing_in_module.len == 0, '${what}: spec §10.2 rows with no module row: ${missing_in_module}'
	assert missing_in_spec.len == 0, '${what}: module rows with no spec §10.2 row: ${missing_in_spec}'
}

fn test_clause_vi_spec_tables_and_module_table_are_set_equal() {
	spec := spec_wave3_rules()
	t := code_rules()
	assert spec.triggers.len == 5, 'spec trigger rows: ${spec.triggers}'
	assert spec.breaks.len == 6, 'spec block-breaker rows: ${spec.breaks}'
	assert spec.seq.len >= 20, 'spec SEQ rows: ${spec.seq.len}'
	mut module_seq := []string{}
	for d, _ in t.seq {
		module_seq << d
	}
	assert_set_equal(spec.triggers, t.triggers, 'sequence triggers')
	assert_set_equal(spec.breaks, t.breaks, 'block breakers')
	assert_set_equal(spec.seq, module_seq, 'SEQ inner-dispatch classes')
}
