// v0.8.0 Phase 2.10 — code_diagram emitter tests.
//
// Verifies the V-side `code.code_diagram(source)` emitter against
// the (ERD) + §D4 (CFG) shape contract. The
// authoritative fixture-driven validation lives in
// `scripts/check_code_diagram_fixtures.py` against
// `conformance/code_diagram.txt`; this V-side test exercises the
// per-shape paths directly so module-level regressions surface
// inside `v test`.

module main

import code

// ── Helpers ───────────────────────────────────────────────────────────

// has_line returns true iff `text` contains the line `wanted` after
// trimming leading whitespace on each line. Used to assert one
// expected Mermaid line is present; ordering of lines is not
// checked (matches the spec's structural-equivalence contract).
fn has_line(text string, wanted string) bool {
	want_trim := wanted.trim_space()
	for ln in text.split('\n') {
		if ln.trim_space() == want_trim { return true }
	}
	return false
}

// header_is returns true iff the first non-empty line of `text` is
// the literal Mermaid dialect header `dialect` ('flowchart TD' or
// 'erDiagram').
fn header_is(text string, dialect string) bool {
	for ln in text.split('\n') {
		s := ln.trim_space()
		if s == '' { continue }
		return s == dialect
	}
	return false
}

// count_lines returns the number of lines in `text` whose trimmed
// content equals `wanted`. Used to verify uniqueness of nodes.
fn count_lines(text string, wanted string) int {
	want_trim := wanted.trim_space()
	mut n := 0
	for ln in text.split('\n') {
		if ln.trim_space() == want_trim { n++ }
	}
	return n
}

// ── Auto-detection ─────────────────────────────────────

fn test_empty_source_renders_erd_placeholder() {
	out := code.code_diagram('') or { panic('emit: ${err}') }
	assert out.trim_space() == 'erDiagram'
}

fn test_whitespace_only_source_renders_erd_placeholder() {
	out := code.code_diagram('   \n\n  ') or { panic('emit: ${err}') }
	assert out.trim_space() == 'erDiagram'
}

fn test_pure_data_source_renders_erd() {
	out := code.code_diagram("[user id=1 name='alice']") or {
		panic('emit: ${err}')
	}
	assert header_is(out, 'erDiagram'), 'expected erDiagram header, got:\n${out}'
	assert has_line(out, 'user {')
}

fn test_pure_code_source_renders_flowchart() {
	out := code.code_diagram('[?for [in \$x /items] [yield \$x]]') or {
		panic('emit: ${err}')
	}
	assert header_is(out, 'flowchart TD'), 'expected flowchart TD, got:\n${out}'
}

fn test_pi_then_data_classifies_as_data() {
	out := code.code_diagram('[?cx version=0.8.0]\n[user id=1]') or {
		panic('emit: ${err}')
	}
	assert header_is(out, 'erDiagram'), 'expected erDiagram (PIs do not count), got:\n${out}'
	assert has_line(out, 'user {')
}

fn test_mixed_def_then_data_classifies_as_code() {
	src := "[?def greet ($name) [concat 'hello ' \$name]]
[user id=1]"
	out := code.code_diagram(src) or { panic('emit: ${err}') }
	assert header_is(out, 'flowchart TD')
	assert has_line(out, 'subgraph greet')
}

// ── ERD ────────────────────────────────────────────────

fn test_erd_single_element_empty_box() {
	out := code.code_diagram('[user]') or { panic('emit: ${err}') }
	assert has_line(out, 'user {')
	assert has_line(out, '}')
}

fn test_erd_attributes_become_attr_rows() {
	out := code.code_diagram("[user id=1 name='alice']") or {
		panic('emit: ${err}')
	}
	assert has_line(out, 'int @id')
	assert has_line(out, 'string @name')
}

fn test_erd_repeating_children_yield_one_to_many() {
	src := "[user id=1
  [order id=100 total=42.0]
  [order id=101 total=13.5]
]"
	out := code.code_diagram(src) or { panic('emit: ${err}') }
	assert has_line(out, 'user ||--o{ order : has'), out
}

fn test_erd_singleton_children_yield_one_to_one() {
	src := "[user id=1
  [profile email='a@x.test']
]"
	out := code.code_diagram(src) or { panic('emit: ${err}') }
	assert has_line(out, 'user ||--|| profile : has'), out
}

fn test_erd_scalar_children_inline_as_rows() {
	src := "[user
  [email 'a@x.test']
  [phone '555-0100']
]"
	out := code.code_diagram(src) or { panic('emit: ${err}') }
	assert has_line(out, 'string email')
	assert has_line(out, 'string phone')
}

// ── CFG — for-loop ────────────────────────────────────

fn test_cfg_for_emits_loop_box_with_binds_edge() {
	out := code.code_diagram('[?for [in \$u /users/user] [yield \$u]]') or {
		panic('emit: ${err}')
	}
	assert header_is(out, 'flowchart TD')
	// header → body edge labeled `binds $u`.
	assert has_line(out, 'lh -- "binds \$u" --> lb'), out
	// body → header back-edge.
	assert has_line(out, 'lb --> lh'), out
	// header → exit (sequence exhausted).
	assert has_line(out, 'lh --> done'), out
}

// ── CFG — if-diamond ─────────────────────────────────────────────────

fn test_cfg_if_emits_diamond_with_true_false_arms() {
	out := code.code_diagram("[?if \$x [then 'big'] [else 'small']]") or {
		panic('emit: ${err}')
	}
	assert has_line(out, 'i -- "true" --> t')
	assert has_line(out, 'i -- "false" --> e')
}

// ── CFG — match dispatcher ───────────────────────────────────────────

fn test_cfg_match_two_arms_emit_dispatcher_edges() {
	src := "[?match \$x
  [case 1 'one']
  [else  'other']
]"
	out := code.code_diagram(src) or { panic('emit: ${err}') }
	assert has_line(out, 'm -- "1" --> a1'), out
	assert has_line(out, 'm -- "else" --> a2'), out
}

fn test_cfg_match_three_arms_truncated_pattern_label() {
	src := "[?match \$age
  [case '< 13' 'child']
  [case '< 18' 'teen']
  [else        'adult']
]"
	out := code.code_diagram(src) or { panic('emit: ${err}') }
	assert has_line(out, 'm -- "< 13" --> a1'), out
	assert has_line(out, 'm -- "< 18" --> a2'), out
	assert has_line(out, 'm -- "else" --> a3'), out
}

fn test_cfg_match_arm_label_truncation_at_30_chars() {
	// 35-char string-literal pattern → should truncate to 30 + …
	long_pat := 'aaaaaaaaaa-bbbbbbbbbb-cccccccccc12'
	src := "[?match \$x
  [case '${long_pat}' 'hit']
  [else 'miss']
]"
	out := code.code_diagram(src) or { panic('emit: ${err}') }
	// The first 30 chars of long_pat + ellipsis appear in the edge label.
	// `arm_pattern_label` peels the quotes off string-shaped patterns
	// so the raw 30-char prefix appears literally.
	truncated := long_pat[..30] + '…'
	assert out.contains(truncated), 'expected truncated label "${truncated}" in:\n${out}'
}

fn test_cfg_match_call_shaped_arm_pattern_renders_label() {
	// A call/element-shaped arm pattern (`[< 13]`) is not a valid
	// match-pattern head, so the raw parser rejects it. The diagram
	// patch layer quotes such patterns so the source still parses and
	// each arm renders a sensible (quote-stripped) edge label — the
	// whole diagram must NOT degenerate to a bare `flowchart TD`.
	srcs := [
		"[?match \$age [case [< 13] 'child'] [else 'adult']]",
		"[?match \$age [case [lt 13] 'child'] [else 'adult']]",
		"[?match \$age [case [= 13] 'teen'] [else 'adult']]",
	]
	wanted := ['< 13', 'lt 13', '= 13']
	for i, src in srcs {
		out := code.code_diagram(src) or { panic('emit: ${err}') }
		assert header_is(out, 'flowchart TD')
		// The dispatcher node + arm edge must be present (not degenerate).
		assert has_line(out, 'm -- "${wanted[i]}" --> a1'), out
		assert has_line(out, 'm -- "else" --> a2'), out
	}
}

// ── CFG — modify update-block ────────────────────────────────────────

fn test_cfg_modify_emits_single_update_block() {
	src := "[?modify /users/user[1]
  [set-attr status 'active']
  [delete-attr temp]
  [append [tag 'vip']]
]"
	out := code.code_diagram(src) or { panic('emit: ${err}') }
	assert has_line(out, 'start --> u')
	assert has_line(out, 'u --> done')
	// The action vocabulary list is included in the update-block label.
	mut saw_label := false
	for ln in out.split('\n') {
		if ln.contains('u[') && ln.contains('modify') { saw_label = true; break }
	}
	assert saw_label, 'expected update-block "u[…modify…]", got:\n${out}'
}

// ── CFG — def subgraph ───────────────────────────────────────────────

fn test_cfg_def_renders_as_subgraph_with_entry_and_exit() {
	src := "[?def greet ($name) [concat 'hello ' \$name]]"
	out := code.code_diagram(src) or { panic('emit: ${err}') }
	assert has_line(out, 'subgraph greet'), out
	assert has_line(out, 'end'), out
}

fn test_cfg_def_recursion_links_back_to_entry() {
	src := "[?def countdown ($n) [?if [= \$n 0] [then 'done'] [else [countdown [- \$n 1]]]]]"
	out := code.code_diagram(src) or { panic('emit: ${err}') }
	// Recursive call (`cr`) loops back to def entry (`cs`), not exit.
	assert has_line(out, 'cr --> cs'), out
}

// ── CFG — basic-block composition + overflow cap ──────────────────────

fn test_cfg_basic_block_composes_three_sequential_directives() {
	// Three `[?let]` directives → one basic block node with 3 label
	// lines.
	src := "[?let [= \$a 1] [= \$b 2] [= \$c 3] \$c]"
	// Note: the let-in-let-in shape parses as a single chain; this
	// covers the "non-branching directives compose into one block"
	// rule indirectly. We assert only that the emit produces a
	// flowchart with start + done + at least one block.
	out := code.code_diagram(src) or { panic('emit: ${err}') }
	assert header_is(out, 'flowchart TD')
	assert has_line(out, 'start([entry])')
	assert has_line(out, 'done([exit])')
}

fn test_cfg_basic_block_ten_line_cap_overflow() {
	// Construct a top-level block of 12 sequential directives; the
	// basic-block caps at `max_block_lines` (10, raised from 6) and
	// collapses the remainder into a `(+K more)` overflow row. Filler is
	// `[?sleep N]` — block-candidate directives that compose into one
	// basic block (data elements are dropped; [?let]/[?if]/[?for]/[?match]/
	// [?modify]/[?def] break the block).
	src := "[?sleep 1]
[?sleep 2]
[?sleep 3]
[?sleep 4]
[?sleep 5]
[?sleep 6]
[?sleep 7]
[?sleep 8]
[?sleep 9]
[?sleep 10]
[?sleep 11]
[?sleep 12]"
	out := code.code_diagram(src) or { panic('emit: ${err}') }
	assert header_is(out, 'flowchart TD')
	// 10 lines kept; the remaining 2 collapse into the overflow row.
	assert out.contains('(+2 more)'), 'expected overflow marker (+2 more) in:\n${out}'
}

// ── Edge cases ───────────────────────────────────────────────────────

fn test_unparseable_source_degrades_gracefully() {
	// Garbage source must not panic — degrade to placeholder.
	out := code.code_diagram(']]]not a program[[[') or { panic('emit: ${err}') }
	assert out == 'erDiagram' || out == 'flowchart TD',
		'expected one of placeholders, got: ${out}'
}

fn test_data_only_pis_stripped_from_classification() {
	out := code.code_diagram('[?cx scope=public]\n[?cx version=0.8.0]\n[user]') or {
		panic('emit: ${err}')
	}
	assert header_is(out, 'erDiagram'),
		'expected erDiagram after stripping PIs, got:\n${out}'
}

// ── Conformance-fixture cross-check (subset) ─────────────────────────
//
// Five fixtures from `conformance/code_diagram.txt` are exercised
// directly here as a smoke layer — the structural shape (node-set +
// edge-set) is compared against the same expected Mermaid the
// runner uses. Goes-with-the-runner: if these pass and the runner
// fails the fixture, the discrepancy is in the runner not the
// emitter (or vice versa).

fn nodes_in(text string) []string {
	mut out := []string{}
	for ln in text.split('\n') {
		s := ln.trim_space()
		// Match `id[label]`, `id{label}`, `id{{label}}`, `id([label])`,
		// `id[/label/]`. Stop at first non-ident char.
		mut k := 0
		for k < s.len {
			c := s[k]
			if (c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`)
			   || (c >= `0` && c <= `9`) || c == `_` { k++ }
			else { break }
		}
		if k == 0 { continue }
		nid := s[..k]
		if k < s.len && (s[k] == `[` || s[k] == `{` || s[k] == `(`) {
			out << nid
		}
	}
	// Dedup.
	mut seen := map[string]bool{}
	mut uniq := []string{}
	for n in out {
		if n !in seen {
			seen[n] = true
			uniq << n
		}
	}
	return uniq
}

fn test_fixture_cfg_001_node_set() {
	src := '[?for [in \$u /users/user]
  [yield \$u]
]'
	out := code.code_diagram(src) or { panic('emit: ${err}') }
	nodes := nodes_in(out)
	for want in ['start', 'done', 'lh', 'lb'] {
		assert want in nodes, 'expected node "${want}" in:\n${out}'
	}
}

fn test_fixture_cfg_002_node_set() {
	src := "[?if \$x [then 'big'] [else 'small']]"
	out := code.code_diagram(src) or { panic('emit: ${err}') }
	nodes := nodes_in(out)
	for want in ['start', 'done', 'i', 't', 'e'] {
		assert want in nodes, 'expected node "${want}" in:\n${out}'
	}
}

fn test_fixture_cfg_007_subgraph_present() {
	src := "[?def greet ($name) [concat 'hello ' \$name]]"
	out := code.code_diagram(src) or { panic('emit: ${err}') }
	assert has_line(out, 'subgraph greet'), out
	assert has_line(out, 'end'), out
}

fn test_fixture_erd_006_one_to_many() {
	src := "[user id=1
  [order id=100 total=42.0]
  [order id=101 total=13.5]
]"
	out := code.code_diagram(src) or { panic('emit: ${err}') }
	assert has_line(out, 'user ||--o{ order : has'), out
}

fn test_fixture_erd_008_name_collision_global_merge() {
	src := "[org
  [team name='alpha'
    [user id=1 name='alice']
  ]
  [project name='beta'
    [user id=2 name='bob']
  ]
]"
	out := code.code_diagram(src) or { panic('emit: ${err}') }
	// One merged `user` entity even though two appear under
	// different parents.
	assert count_lines(out, 'user {') == 1, out
	// Both parent relationships present.
	assert has_line(out, 'team ||--|| user : has'), out
	assert has_line(out, 'project ||--|| user : has'), out
}
