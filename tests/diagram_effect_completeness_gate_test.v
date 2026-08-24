// diagram_effect_completeness_gate_test.v — the DR-5 bidirectional
// completeness gate for the THIRD renderable kind, the effect/capability
// graph (RULED: DGX-1b,
// ledger/rulings_2026_08_21_diagram_capabilities.md). Normative
// statement: spec/03-approved/std-lib/diagram.md §12.
//
// The subject is the module's sealed `[$diagram:effect-rules]` table —
// what is RENDERING POLICY. What is a FACT ABOUT THE ENGINE (the
// primitive→capability map) is deliberately NOT in that table: the
// module reads it live through `[$diagram-effect-table]`, because a
// stale copy could only ever fail by omitting a newly-gated effect
// point, and a capability diagram that quietly under-reports is worse
// than none. Clause (vii) is what holds that live read honest.
//
// Seven clauses, red on drift in either direction:
//
//   (i)   the roster rows are SET-EQUAL to the engine's
//         capability_names() — a capability added to the language and
//         not to this table reddens, and vice versa;
//   (ii)  every `dir` row names a LIVE §4.1 registry directive and a
//         capability in the roster;
//   (iii) every `arm` row's `under` names a live registry directive and
//         its carrier is a real image tag;
//   (iv)  every opacity class is produced by at least one source in the
//         golden corpus — a class that cannot be demonstrated is not a
//         class, and DGX-1c makes rendering them normative;
//   (v)   every roster capability is REACHED by at least one corpus
//         source, so no capability can lose its emitter silently;
//   (vi)  the tables in spec §12 and the module's `effect-rules` value
//         are SET-EQUAL in both directions — the clause that stays red
//         under a MATCHED deletion, because (i)-(v) go on agreeing with
//         themselves when the emitters read the table;
//   (vii) the module's live `effect-cap` verdict equals the engine's own
//         capability_gated_prims() map for every gated primitive.

module main

import os
import cx
import code
import platform as _

struct EffectRules {
mut:
	caps  []string          // roster, in order
	flags map[string]string // capability → grant flag
	dirs  map[string]string // directive → capability
	arms  [][]string        // [carrier, under]
	opaqu []string          // opacity kinds
}

fn effect_rules() EffectRules {
	val := code.diagram_effect_rules_value() or {
		assert false, 'diagram_effect_rules_value: ${err}'
		return EffectRules{}
	}
	mut t := EffectRules{}
	if val is cx.Element {
		for it in val.items {
			if it is cx.Element {
				mut a := map[string]string{}
				for at in it.attrs {
					a[at.name] = cx.scalar_value_str_public(at.value)
				}
				match it.name {
					'cap' {
						t.caps << a['name'] or { '' }
						t.flags[a['name'] or { '' }] = a['flag'] or { '' }
					}
					'dir' {
						t.dirs[a['directive'] or { '' }] = a['cap'] or { '' }
					}
					'arm' {
						t.arms << [a['carrier'] or { '' }, a['under'] or { '' }]
					}
					'opaque' {
						t.opaqu << a['kind'] or { '' }
					}
					else {}
				}
			}
		}
	}
	return t
}

fn deg_corpus_dir() string {
	return os.real_path(os.join_path(os.dir(@FILE), 'testdata', 'diagram_effect_golden'))
}

// Every rendered byte of the corpus, at every rung, concatenated — the
// coverage clauses' subject.
fn corpus_renders() string {
	dir := deg_corpus_dir()
	mut files := os.ls(dir) or { return '' }
	files.sort()
	mut all := []string{}
	for f in files {
		if !f.ends_with('.golden') {
			continue
		}
		all << os.read_file(os.join_path(dir, f)) or { '' }
	}
	return all.join('\n')
}

fn test_clause_i_roster_is_set_equal_to_the_engine_capability_names() {
	t := effect_rules()
	engine := code.capability_names()
	assert t.caps.len == 9, 'roster rows: ${t.caps}'
	mut missing_in_module := []string{}
	for c in engine {
		if c !in t.caps {
			missing_in_module << c
		}
	}
	mut missing_in_engine := []string{}
	for c in t.caps {
		if c !in engine {
			missing_in_engine << c
		}
	}
	assert missing_in_module.len == 0, 'engine capabilities with no table row: ${missing_in_module}'
	assert missing_in_engine.len == 0, 'table rows naming no engine capability: ${missing_in_engine}'
	// Order is load-bearing: §11.3 pins the capability node order to the
	// roster order, and the goldens are byte-pinned to it.
	assert t.caps == engine, 'roster order must equal capability_names(): ${t.caps} vs ${engine}'
	// Every row must carry the grant flag the CLI actually accepts.
	for c in t.caps {
		assert t.flags[c] == '--allow-${c}', 'capability ${c}: flag ${t.flags[c]}'
	}
}

fn test_clause_ii_dir_rows_are_live_directives_charging_roster_capabilities() {
	t := effect_rules()
	assert t.dirs.len == 5, 'dir rows: ${t.dirs}'
	for d, capname in t.dirs {
		assert cx.is_directive_name(d), 'dir row `${d}` is not a live §4.1 registry directive'
		assert capname in t.caps, 'dir row `${d}` charges `${capname}`, which is not in the roster'
	}
}

// The image tags an arm carrier can wear. A carrier rides EITHER as a
// bareword positional child (`[then …]`, `[case …]`, `[recover-with …]`)
// or as a `cx:`-prefixed labeled slot (`then=`, `else=`), and the walk
// compares the LOCAL name, so one row covers both.
const arm_carrier_tags = ['then', 'else', 'case', 'default', 'yield', 'recover-with']

fn test_clause_iii_arm_rows_name_live_branch_directives() {
	t := effect_rules()
	assert t.arms.len == 8, 'arm rows: ${t.arms}'
	for a in t.arms {
		carrier := a[0]
		under := a[1]
		assert carrier in arm_carrier_tags, 'arm carrier `${carrier}` is not an image arm tag'
		assert cx.is_directive_name(under), 'arm row under `${under}` is not a live §4.1 registry directive'
	}
	// `yield` is an arm ONLY under [?match]; under a for-comprehension it
	// is an iteration body, and conflating them would mark every loop
	// body conditional. The `under` column exists for this.
	mut yield_unders := []string{}
	for a in t.arms {
		if a[0] == 'yield' {
			yield_unders << a[1]
		}
	}
	assert yield_unders == ['match'], 'yield arm rows: ${yield_unders}'
}

fn test_clause_iv_every_opacity_class_is_corpus_exercised() {
	t := effect_rules()
	assert t.opaqu.len == 5, 'opacity rows: ${t.opaqu}'
	rendered := corpus_renders()
	mut unexercised := []string{}
	for k in t.opaqu {
		if !rendered.contains('unk_${k}[/') {
			unexercised << k
		}
	}
	assert unexercised.len == 0, 'opacity classes no corpus source produces: ${unexercised}'
}

fn test_clause_v_every_capability_is_corpus_reached() {
	t := effect_rules()
	rendered := corpus_renders()
	mut unreached := []string{}
	for c in t.caps {
		id := 'cap_' + c.replace('-', '_')
		if !rendered.contains('${id}{{') {
			unreached << c
		}
	}
	assert unreached.len == 0, 'capabilities no corpus source reaches: ${unreached}'
}

// ── clause (vi): spec §12 ↔ the module table, both directions ──────────

struct SpecEffectRules {
mut:
	caps  []string
	dirs  []string
	arms  [][]string
	opaqu []string
}

fn spec_effect_rules() SpecEffectRules {
	spec_path := os.real_path(os.join_path(os.dir(@FILE), '..', '..', 'spec', '03-approved',
		'std-lib', 'diagram.md'))
	text := os.read_file(spec_path) or {
		assert false, 'read ${spec_path}: ${err}'
		return SpecEffectRules{}
	}
	start := text.index('## §12. The sealed effect-rules table') or {
		assert false, '§12 heading not found in std-lib/diagram.md'
		return SpecEffectRules{}
	}
	body := text[start..]
	mut out := SpecEffectRules{}
	roster_at := body.index('**Capability roster**') or { 0 }
	dirs_at := body.index('**Charging directive heads**') or { 0 }
	arms_at := body.index('**Branch-arm carriers**') or { 0 }
	opaq_at := body.index('**Opacity classes**') or { body.len }
	for line in body[roster_at..dirs_at].split('\n') {
		if c := first_code_cell(line) {
			out.caps << c
		}
	}
	for line in body[dirs_at..arms_at].split('\n') {
		if c := first_code_cell(line) {
			out.dirs << strip_directive(c)
		}
	}
	for line in body[arms_at..opaq_at].split('\n') {
		cells := code_cells(line)
		if cells.len >= 2 {
			out.arms << [cells[0], strip_directive(cells[1])]
		}
	}
	// The opacity classes are a prose list of backticked names.
	tail := body[opaq_at..]
	stop := tail.index('###') or { tail.len }
	for c in backticked(tail[..stop]) {
		if c !in out.opaqu {
			out.opaqu << c
		}
	}
	return out
}

// first_code_cell returns the backticked token in a table row's FIRST
// cell, skipping the header and separator rows.
fn first_code_cell(line string) ?string {
	if !line.starts_with('| `') {
		return none
	}
	cell := line[1..].all_before('|')
	toks := backticked(cell)
	if toks.len == 0 {
		return none
	}
	return toks[0]
}

fn code_cells(line string) []string {
	if !line.starts_with('| `') {
		return []
	}
	mut out := []string{}
	for cell in line.trim('|').split('|') {
		toks := backticked(cell)
		if toks.len > 0 {
			out << toks[0]
		}
	}
	return out
}

fn backticked(s string) []string {
	mut out := []string{}
	mut i := 0
	for {
		a := s.index_after('`', i) or { break }
		b := s.index_after('`', a + 1) or { break }
		tok := s[a + 1..b]
		if tok.len > 0 {
			out << tok
		}
		i = b + 1
	}
	return out
}

fn strip_directive(s string) string {
	if s.starts_with('[?') && s.ends_with(']') {
		return s[2..s.len - 1]
	}
	return s
}

fn assert_effect_set_equal(spec []string, module_ []string, what string) {
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
	assert missing_in_module.len == 0, '${what}: spec §12 rows with no module row: ${missing_in_module}'
	assert missing_in_spec.len == 0, '${what}: module rows with no spec §12 row: ${missing_in_spec}'
}

fn test_clause_vi_spec_tables_and_module_table_are_set_equal() {
	spec := spec_effect_rules()
	t := effect_rules()
	assert spec.caps.len == 9, 'spec roster rows: ${spec.caps}'
	assert spec.dirs.len == 5, 'spec dir rows: ${spec.dirs}'
	assert spec.arms.len == 8, 'spec arm rows: ${spec.arms}'
	assert spec.opaqu.len == 5, 'spec opacity classes: ${spec.opaqu}'
	mut module_dirs := []string{}
	for d, _ in t.dirs {
		module_dirs << d
	}
	assert_effect_set_equal(spec.caps, t.caps, 'capability roster')
	assert_effect_set_equal(spec.dirs, module_dirs, 'charging directive heads')
	assert_effect_set_equal(spec.opaqu, t.opaqu, 'opacity classes')
	mut spec_arms := []string{}
	for a in spec.arms {
		spec_arms << '${a[0]}/${a[1]}'
	}
	mut mod_arms := []string{}
	for a in t.arms {
		mod_arms << '${a[0]}/${a[1]}'
	}
	assert_effect_set_equal(spec_arms, mod_arms, 'branch-arm carriers')
}

fn test_clause_vii_the_module_reads_the_engine_map_live() {
	gated := code.capability_gated_prims()
	mut names := gated.keys()
	names.sort()
	mut wrong := []string{}
	for n in names {
		got := code.diagram_effect_cap(n) or {
			wrong << '${n}: ${err}'
			continue
		}
		if got != gated[n] {
			wrong << '${n}: module says `${got}`, engine says `${gated[n]}`'
		}
	}
	assert wrong.len == 0, 'the module is not reading the live engine map: ${wrong}'
	// And a name the engine charges nothing for must come back empty —
	// not guessed.
	empty := code.diagram_effect_cap('concat') or {
		assert false, 'diagram_effect_cap(concat): ${err}'
		return
	}
	assert empty == '', 'concat charges nothing; module said `${empty}`'
}
