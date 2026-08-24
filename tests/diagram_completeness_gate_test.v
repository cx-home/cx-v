// diagram_completeness_gate_test.v — the DR-5 bidirectional
// completeness gate (#758, RULED 2026-08-20;
// ledger/rulings_2026_08_20_diagram_renderer.md). Normative statement:
// spec/03-approved/std-lib/diagram.md §completeness + code.md §10.1.2.
//
// Four clauses, red on synthetic drift in any direction:
//   (i)   the code.md §10.1.2 locked table's directive set and the
//         module's sealed rules rows are SET-EQUAL (both directions —
//         finding 6's one-way drift dies here),
//   (ii)  every rules row is exercised by the golden corpus — by its
//         own [?name in an embedded source, or by its EMITTER TWIN
//         (send/try-send, receive/try-receive, await family share one
//         emitter; the twin map is explicit below),
//   (iii) a synthetic registry directive OUTSIDE the table refuses
//         CXER0281 at top level (beside the corpus fixture
//         program-viz-021's [?secret], enforced by the round-trip
//         harness),
//   (iv)  the classification over the FULL grammar registry is total
//         and disjoint: every table name (row / alias / scaffold /
//         nested) is a live registry directive (a retired name — the
//         old `try` row — reddens here), the module's admission
//         verdict equals rows ∪ aliases ∪ scaffolding exactly, and the
//         nested-only emitters refuse at top level.

module main

import os
import cx
import code
import platform as _

fn spec_table_directives() []string {
	spec_path := os.real_path(os.join_path(os.dir(@FILE), '..', '..', 'spec', '03-approved',
		'core', 'code.md'))
	text := os.read_file(spec_path) or {
		assert false, 'read ${spec_path}: ${err}'
		return []
	}
	// The §10.1.2 locked table: rows between the table header and the
	// next section heading; directive cells carry `[?name]` tokens.
	start := text.index('| Directive | Render |') or {
		assert false, '§10.1.2 table header not found in code.md'
		return []
	}
	rest := text[start..]
	end := rest.index('####') or { rest.len }
	table := rest[..end]
	mut out := []string{}
	mut i := 0
	for {
		j := table.index_after('[?', i) or { break }
		mut k := j + 2
		for k < table.len && ((table[k] >= `a` && table[k] <= `z`) || table[k] == `-`) {
			k++
		}
		name := table[j + 2..k]
		if name.len > 0 && name !in out {
			out << name
		}
		i = k
	}
	return out
}

struct RulesTable {
mut:
	rows     []string
	aliases  []string
	scaffold []string
	nested   []string
}

fn module_rules() RulesTable {
	val := code.diagram_rules_value() or {
		assert false, 'diagram_rules_value: ${err}'
		return RulesTable{}
	}
	mut t := RulesTable{}
	if val is cx.Element {
		for it in val.items {
			if it is cx.Element {
				mut dname := ''
				for a in it.attrs {
					if a.name == 'directive' {
						dname = cx.scalar_value_str_public(a.value)
					}
				}
				if dname == '' {
					continue
				}
				match it.name {
					'row' { t.rows << dname }
					'alias' { t.aliases << dname }
					'scaffold' { t.scaffold << dname }
					'nested' { t.nested << dname }
					else {}
				}
			}
		}
	}
	return t
}

fn test_clause_i_spec_table_and_module_rows_are_set_equal() {
	spec := spec_table_directives()
	t := module_rules()
	assert spec.len > 0
	assert t.rows.len > 0
	mut missing_in_module := []string{}
	for d in spec {
		if d !in t.rows {
			missing_in_module << d
		}
	}
	mut missing_in_spec := []string{}
	for d in t.rows {
		if d !in spec {
			missing_in_spec << d
		}
	}
	assert missing_in_module.len == 0, 'spec §10.1.2 rows with no module rule: ${missing_in_module}'
	assert missing_in_spec.len == 0, 'module rules with no spec §10.1.2 row: ${missing_in_spec}'
}

// Emitter twins: directives sharing ONE emitter with an exercised
// sibling (the rule text is per-directive; the emitter is shared).
const emitter_twins = {
	'try-send':    'send'
	'try-receive': 'receive'
	'await-all':   'await'
	'await-any':   'await'
	'await-race':  'await'
	'await':       'await-all'
}

fn test_clause_ii_every_rule_is_exercised_by_the_corpus() {
	dir := os.real_path(os.join_path(os.dir(@FILE), 'testdata', 'diagram_mermaid_golden'))
	mut files := os.ls(dir) or {
		assert false, 'golden dir missing'
		return
	}
	mut sources := []string{}
	for f in files {
		if !f.ends_with('.min.golden') {
			continue
		}
		g := os.read_file(os.join_path(dir, f)) or { continue }
		src := code.reverse_parse_diagram(g, 'mermaid') or { continue }
		sources << src
	}
	assert sources.len >= 40
	t := module_rules()
	mut unexercised := []string{}
	for d in t.rows {
		mut hit := false
		for s in sources {
			if s.contains('[?${d}') {
				hit = true
				break
			}
		}
		if !hit {
			if twin := emitter_twins[d] {
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
	assert unexercised.len == 0, 'rules rows with no exercising corpus source (nor emitter twin): ${unexercised}'
}

fn test_clause_iii_outside_table_directive_refuses_cxer0281() {
	// [?quote] is a live registry directive with NO render rule.
	src := '[?quote [x]]'
	if _ := code.render_diagram(src, 'mermaid') {
		assert false, 'expected CXER0281 for top-level [?quote]'
	} else {
		assert err.msg().contains('cx-err:CXER0281'), 'expected CXER0281, got: ${err.msg()}'
	}
}

fn test_clause_iv_registry_classification_is_total_and_disjoint() {
	t := module_rules()
	// Every table name is a LIVE registry directive (a retired name —
	// e.g. the deleted `try` entry — reddens here).
	mut stale := []string{}
	for d in t.rows {
		if !cx.is_directive_name(d) {
			stale << 'row:${d}'
		}
	}
	for d in t.aliases {
		if !cx.is_directive_name(d) {
			stale << 'alias:${d}'
		}
	}
	for d in t.scaffold {
		if !cx.is_directive_name(d) {
			stale << 'scaffold:${d}'
		}
	}
	for d in t.nested {
		if !cx.is_directive_name(d) {
			stale << 'nested:${d}'
		}
	}
	assert stale.len == 0, 'rules-table names not in the grammar registry: ${stale}'
	// Disjointness of the classes.
	for d in t.aliases {
		assert d !in t.rows, 'alias ${d} duplicates a row'
	}
	for d in t.scaffold {
		assert d !in t.rows, 'scaffold ${d} duplicates a row'
	}
	for d in t.nested {
		assert d !in t.rows, 'nested ${d} duplicates a row'
		assert d !in t.scaffold, 'nested ${d} duplicates scaffolding'
	}
	// The module's admission verdict is EXACTLY rows ∪ aliases ∪
	// scaffolding over the whole registry — every registry directive is
	// therefore exactly one of: admitted (row/alias/scaffold), nested
	// (emitter without top-level admission), or CXER0281-refused.
	for d in cx.directive_names {
		admitted := code.diagram_admitted(d) or {
			assert false, 'diagram_admitted(${d}): ${err}'
			return
		}
		expected := d in t.rows || d in t.aliases || d in t.scaffold
		assert admitted == expected, 'admission drift for [?${d}]: module says ${admitted}, table says ${expected}'
	}
	// The nested-only emitters refuse at top level.
	nested_sources := {
		'http-client': '[?http-client get="https://example.com/x"]'
		'fn':          '[?fn (\$x) \$x]'
	}
	for d, src in nested_sources {
		assert d in t.nested, '${d} expected in the nested class'
		if _ := code.render_diagram(src, 'mermaid') {
			assert false, 'expected CXER0281 for top-level [?${d}]'
		} else {
			assert err.msg().contains('cx-err:CXER0281'), '[?${d}]: expected CXER0281, got ${err.msg()}'
		}
	}
}
