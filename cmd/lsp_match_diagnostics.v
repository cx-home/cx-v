// Q5 / Phase 5.5: `cx lsp` — [?match] arm diagnostics + CXPath
// focus hover.
//
// Implements the four diagnostic / hover affordances reserved by
// tooling/lsp/diagnostics.md (CXLS001 / CXLS002 / CXLS003) plus
// the CXPath focus-hover surface.
//
// Approach: full-AST. The LSP server calls `cx.parse_program(source)` (the
// same parser libcx evaluators use), walks the resulting ProgramNode
// tree, and emits diagnostics keyed off `ProgramDirective{name:
// 'match'}` slots and `ProgramPathExpr` nodes. When parse fails (mid-
// edit / syntactic error), the analyser returns an empty diagnostic
// list and publish_diagnostics falls back to the parse-error emit
// path — same graceful-degradation pattern as
// `atom_positions_from_parse` in lsp_content.v.
//
// CXLS001 — unreachable [?match] arm
//   Severity warning. Trigger: a `[case …]` or `[when …]` arm appears
//   after an `[else …]` arm (`[else …]` is final by grammar; the
//   parser tolerates trailing arms for error recovery, but they are
//   dead code). Also fires when two `[case …]` arms carry byte-identical
//   pattern text — the second is unreachable under
//   first-match semantics.
//
// CXLS002 — missing `[else …]` arm
//   Severity hint. Trigger: a `[?match]` directive with no `[else …]`
//   arm. Non-matching values silently yield `()`; the
//   hint reminds authors to add an `[else …]` arm when total coverage
//   matters.
//
// CXLS003 — sibling `[when …]` consolidation suggestion
//   Severity hint. Trigger: 2+ `[when …]` arms whose predicate source-
//   text is byte-identical. The recogniser is intentionally narrow
//   (no semantic equivalence); the hint cites the duplicates so the
//   author can refactor manually. Auto-fix is out of scope
//   per diagnostics.md "Out-of-scope".
//
// CXPath focus hover (reservation)
//   When the cursor is over any byte range covered by a
//   ProgramPathExpr node, the hover provider returns a markdown
//   tooltip describing the path: leading-axis ('//' / '/' / 'relative'),
//   step count, and a focus-type placeholder ('any' currently, until full
//   CXPath type-inference lands). This is the "hover
//   affordance ships today, type-inference fills in later" deliverable.

module main
import cx

import code
import x.json2

// match_arm groups one `[case …]` / `[when …]` / `[else …]` clause
// (surfaced to this analyser as a labeled slot with label 'case' /
// 'when' / 'else'). Mid-edit sources that fail the clause shape
// parse-fail upstream and never reach this analyser.
struct MatchArm {
	kind        string      // 'case' | 'when' | 'else'
	key_text    string      // case pattern source text or when predicate source text
	key_pos     cx.Position
}

// match_diagnostics walks the parsed program AST and returns LSP
// diagnostics for CXLS001 / CXLS002 / CXLS003.
fn match_diagnostics(source string) []json2.Any {
	mut diags := []json2.Any{}
	prog := cx.parse_program(source) or { return diags }
	walk_for_match(prog.body, source, mut diags)
	return diags
}

fn walk_for_match(node cx.ProgramNode, source string, mut diags []json2.Any) {
	match node {
		cx.ProgramDirective {
			if node.name == 'match' {
				analyse_match_directive(node, source, mut diags)
			}
			for slot in node.slots {
				walk_for_match(slot.value, source, mut diags)
			}
		}
		cx.Program {
			walk_for_match(node.body, source, mut diags)
		}
		cx.ProgramLiteral {
			for child in node.items {
				walk_for_match(child, source, mut diags)
			}
			for slot in node.slots {
				walk_for_match(slot.value, source, mut diags)
			}
			for attr in node.attrs {
				walk_for_match(attr.value, source, mut diags)
			}
		}
		cx.ProgramCall {
			for arg in node.args {
				walk_for_match(arg, source, mut diags)
			}
		}
		cx.ProgramForComp {
			// L100: THE ONE traversal (was blind to the `[yield-map K V]`
			// value node).
			for item in cx.for_comp_children(node) {
				walk_for_match(item.node, source, mut diags)
			}
		}
		cx.ProgramPattern {
			for child in node.body {
				walk_for_match(child, source, mut diags)
			}
		}
		else {
			// ProgramBinding / ProgramPathExpr / ProgramWildcard — no
			// nested directive children at the levels we care about.
		}
	}
}

// analyse_match_directive emits CXLS001/002/003 diagnostics for one
// `?match` directive's slot list. Clause-children `[case PAT EXPR]`,
// `[when PRED EXPR]`, `[else EXPR]` reach this analyser as labeled
// slots ('case' / 'when' / 'else') in source order (per parser.v +
// spec/core/code.md §8.2).
fn analyse_match_directive(m cx.ProgramDirective, source string, mut diags []json2.Any) {
	mut arms := []MatchArm{}
	mut seen_else := false
	mut else_pos := cx.Position{}
	mut unreachable_arms := []cx.Position{}
	mut case_keys := map[string]cx.Position{}
	mut when_keys := map[string]int{}     // predicate text → first arm index in arms
	mut has_else := false
	// A bare-binding (`$v`) or anonymous (`_`) `[case …]` pattern is a
	// catch-all: it matches every value, giving total coverage exactly like an
	// `[else …]` arm. It therefore suppresses CXLS002 (no point recommending an
	// `[else]` when coverage is already total). A TYPED bind (`$v::int`), a
	// path-bound pattern (`$v/@x`), or a rest-capture is NOT a catch-all.
	mut has_catchall := false
	mut directive_end_pos := m.pos

	for slot in m.slots {
		if slot.kind != .labeled {
			continue
		}
		label := slot.label
		if label != 'case' && label != 'when' && label != 'else' {
			continue
		}

		key_pos := slot_value_pos(slot.value, m.pos)
		key_text := source_slice_around(source, key_pos)

		// Bump directive_end_pos so the CXLS002 range lands at the last
		// known interior position.
		if key_pos.offset > directive_end_pos.offset {
			directive_end_pos = key_pos
		}

		if seen_else {
			unreachable_arms << key_pos
			continue
		}

		match label {
			'else' {
				seen_else = true
				has_else = true
				else_pos = key_pos
				arms << MatchArm{kind: 'else', key_text: '', key_pos: key_pos}
			}
			'case' {
				// Same-pattern-text reuse → unreachable per D2.
				if existing := case_keys[key_text] {
					_ := existing
					if key_text != '' {
						unreachable_arms << key_pos
					}
				} else if key_text != '' {
					case_keys[key_text] = key_pos
				}
				if is_catchall_pattern(slot.value) {
					has_catchall = true
				}
				arms << MatchArm{kind: 'case', key_text: key_text, key_pos: key_pos}
			}
			'when' {
				if key_text != '' {
					when_keys[key_text] = arms.len
				}
				arms << MatchArm{kind: 'when', key_text: key_text, key_pos: key_pos}
			}
			else {}
		}
	}

	// CXLS001 — unreachable arms.
	for arm_pos in unreachable_arms {
		diags << json2.Any(make_diagnostic('CXLS001', 2 /* warning */,
			arm_pos, key_pos_end_estimate(arm_pos, 4),
			'unreachable [?match] arm — preceding arm is a catch-all ([else …]) or duplicates an earlier [case …] pattern'))
	}
	_ = else_pos // currently unused beyond seen_else gate; reserved for a future refinement

	// CXLS002 — missing [else …]. Suppressed when a catch-all `[case …]`
	// already gives total coverage (a bare `$v` / `_` bind).
	if !has_else && !has_catchall && arms.len > 0 {
		diags << json2.Any(make_diagnostic('CXLS002', 4 /* hint */,
			m.pos, key_pos_end_estimate(directive_end_pos, 1),
			'[?match] has no [else …] arm — non-matching values silently yield ()'))
	}

	// CXLS003 — sibling [when …] predicates with byte-identical source text.
	mut when_dup_groups := map[string][]cx.Position{}
	for a in arms {
		if a.kind == 'when' && a.key_text != '' {
			when_dup_groups[a.key_text] << a.key_pos
		}
	}
	for _, positions in when_dup_groups {
		if positions.len < 2 {
			continue
		}
		first := positions[0]
		diags << json2.Any(make_diagnostic('CXLS003', 4 /* hint */,
			first, key_pos_end_estimate(first, 5),
			'[when …] predicate appears in ${positions.len} sibling arms with identical source text — consider consolidating into one arm'))
	}
}

// slot_value_pos returns the source position of a slot value, falling
// back to the directive's own position when the value carries no
// position (e.g. the synthesized [else …] placeholder literal).
// is_catchall_pattern reports whether a `[case …]` pattern matches every value
// (total coverage), making an `[else …]` arm redundant. True for:
//   - a bare binding `$name` (no type-test, no path steps, not a rest-capture)
//   - the bare wildcard `_`, which parses as a 0-arg call named "_" (the hole
//     form) and matches any value at runtime — verified `[?match 5 [case _ x]]`
//     → x.
// NOT a catch-all: a typed bind (`$v::int`), a path-bound pattern (`$v/@x`), a
// rest-capture, a quoted `"_"` (a ProgramLiteral — a real literal match), or any
// other literal / structured pattern.
fn is_catchall_pattern(node cx.ProgramNode) bool {
	match node {
		cx.ProgramBinding {
			return node.type_test == '' && node.path.len == 0 && !node.is_rest
		}
		cx.ProgramCall {
			return node.name == '_' && node.args.len == 0
		}
		else {
			return false
		}
	}
}

fn slot_value_pos(node cx.ProgramNode, fallback cx.Position) cx.Position {
	match node {
		cx.ProgramDirective    { return node.pos }
		cx.ProgramLiteral      { return node.pos }
		cx.ProgramBinding      { return node.pos }
		cx.ProgramCall         { return node.pos }
		cx.ProgramPattern      { return node.pos }
		cx.ProgramPathExpr     { return node.pos }
		cx.ProgramForComp      { return node.pos }
		cx.ProgramSliceAccess  { return node.pos }
		cx.ProgramSliceLiteral { return node.pos }
		cx.ProgramWildcard     { return fallback }
		cx.Program             { return node.pos }
	}
}

// source_slice_around extracts a stable byte-identical text key for a
// slot value, so that two arms with the same `[case PATTERN …]` (or
// `[when PREDICATE …]`) source text get the same key. We walk forward
// from `pos.offset` to the next top-level `:` or `]` at the same
// bracket depth, then trim trailing whitespace.
//
// This is a heuristic (not semantically perfect) but matches the
// "byte-identical source text" contract documented in
// diagnostics.md for CXLS003 and the same-pattern-reuse half
// of CXLS001.
fn source_slice_around(source string, pos cx.Position) string {
	if pos.offset < 0 || pos.offset >= source.len {
		return ''
	}
	mut depth := 0
	mut i := pos.offset
	for i < source.len {
		c := source[i]
		if c == `[` || c == `{` || c == `(` {
			depth++
		} else if c == `]` || c == `}` || c == `)` {
			if depth == 0 {
				break
			}
			depth--
		} else if depth == 0 && c == `:` {
			// Hit the next labeled slot; stop before the colon.
			break
		}
		i++
	}
	mut end := i
	// Trim trailing whitespace.
	for end > pos.offset && source[end - 1] in [u8(` `), `\t`, `\n`, `\r`] {
		end--
	}
	return source[pos.offset..end]
}

// key_pos_end_estimate returns a position N bytes / cols past `pos`,
// so diagnostic ranges always span at least one visible glyph. We do
// not multi-line span; CXLS warnings target the slot keyword
// position alone.
fn key_pos_end_estimate(pos cx.Position, n int) cx.Position {
	return cx.Position{
		offset: pos.offset + n
		line:   pos.line
		col:    pos.col + n
	}
}

// make_diagnostic builds an LSP Diagnostic JSON object. `severity` per
// LSP spec §6: 1=error, 2=warning, 3=information, 4=hint.
fn make_diagnostic(code_str string, severity int, start cx.Position, end cx.Position, message string) map[string]json2.Any {
	mut start_obj := map[string]json2.Any{}
	// Parser positions are 1-based; LSP positions are 0-based.
	start_line := if start.line > 0 { start.line - 1 } else { 0 }
	start_col  := if start.col  > 0 { start.col  - 1 } else { 0 }
	end_line   := if end.line   > 0 { end.line   - 1 } else { 0 }
	end_col    := if end.col    > 0 { end.col    - 1 } else { 0 }
	start_obj['line'] = json2.Any(i64(start_line))
	start_obj['character'] = json2.Any(i64(start_col))
	mut end_obj := map[string]json2.Any{}
	end_obj['line'] = json2.Any(i64(end_line))
	end_obj['character'] = json2.Any(i64(end_col))
	mut range_obj := map[string]json2.Any{}
	range_obj['start'] = json2.Any(start_obj)
	range_obj['end'] = json2.Any(end_obj)

	mut diag := map[string]json2.Any{}
	diag['range'] = json2.Any(range_obj)
	diag['severity'] = json2.Any(i64(severity))
	diag['code'] = json2.Any(code_str)
	diag['source'] = json2.Any('cx-lsp')
	diag['message'] = json2.Any(message)
	return diag
}

// ── CXPath focus hover ─────────────────────────────────────────────────
//
// Walks the parsed AST to find any ProgramPathExpr whose source range
// covers the (line, col) of the hover request. Returns a markdown
// hover body describing the path; returns '' when no path expression
// covers the position (the caller falls back to identifier hover).

// cxpath_hover_md is the Option-returning façade used by handle_hover
// in lsp.v. Returns `none` when the cursor doesn't sit inside a
// CXPath expression so the caller can fall through to per-word docs.
fn cxpath_hover_md(source string, line int, col int) ?string {
	md := cxpath_hover_at(source, line, col)
	if md == '' {
		return none
	}
	return md
}

fn cxpath_hover_at(source string, line int, col int) string {
	prog := cx.parse_program(source) or { return '' }
	target_offset := offset_for_line_col(source, line, col)
	if target_offset < 0 {
		return ''
	}
	found := find_pathexpr_at(prog.body, source, target_offset) or { return '' }
	return render_pathexpr_hover(found)
}

// offset_for_line_col converts 0-based LSP (line, character) into a
// 0-based byte offset into `source`. Returns -1 on out-of-range.
fn offset_for_line_col(source string, line int, col int) int {
	mut cur_line := 0
	mut cur_col := 0
	for i := 0; i < source.len; i++ {
		if cur_line == line && cur_col == col {
			return i
		}
		c := source[i]
		if c == `\n` {
			cur_line++
			cur_col = 0
		} else {
			cur_col++
		}
	}
	if cur_line == line && cur_col == col {
		return source.len
	}
	return -1
}

// find_pathexpr_at walks the AST and returns the innermost
// ProgramPathExpr whose source range contains `offset`. The match is
// inclusive on the start byte and exclusive on the end byte (one byte
// past the last NodeTest).
fn find_pathexpr_at(node cx.ProgramNode, source string, offset int) ?cx.ProgramPathExpr {
	match node {
		cx.ProgramPathExpr {
			start := node.pos.offset
			end := pathexpr_end_offset(node, source)
			if offset >= start && offset < end {
				return node
			}
			return none
		}
		cx.Program {
			return find_pathexpr_at(node.body, source, offset)
		}
		cx.ProgramDirective {
			for slot in node.slots {
				if hit := find_pathexpr_at(slot.value, source, offset) {
					return hit
				}
			}
			return none
		}
		cx.ProgramLiteral {
			for child in node.items {
				if hit := find_pathexpr_at(child, source, offset) {
					return hit
				}
			}
			for slot in node.slots {
				if hit := find_pathexpr_at(slot.value, source, offset) {
					return hit
				}
			}
			for attr in node.attrs {
				if hit := find_pathexpr_at(attr.value, source, offset) {
					return hit
				}
			}
			return none
		}
		cx.ProgramCall {
			for arg in node.args {
				if hit := find_pathexpr_at(arg, source, offset) {
					return hit
				}
			}
			return none
		}
		cx.ProgramForComp {
			// L100: THE ONE traversal. The hand-rolled walk this replaces
			// stopped at `yield` — hover / go-to-definition over a path
			// expression inside a `[yield-map K V]` value found nothing.
			for item in cx.for_comp_children(node) {
				if hit := find_pathexpr_at(item.node, source, offset) { return hit }
			}
			return none
		}
		cx.ProgramPattern {
			for child in node.body {
				if hit := find_pathexpr_at(child, source, offset) {
					return hit
				}
			}
			return none
		}
		else {
			return none
		}
	}
}

// pathexpr_end_offset estimates the source-end offset for a path
// expression. Paths terminate at the next top-level whitespace, `]`,
// `)`, `}`, or `:` at depth 0. We never cross a newline (paths are
// single-line currently; multi-line path-expression layout is not in
// the grammar).
fn pathexpr_end_offset(p cx.ProgramPathExpr, source string) int {
	start := p.pos.offset
	if start < 0 || start >= source.len {
		return start
	}
	mut i := start
	mut depth := 0
	for i < source.len {
		c := source[i]
		if c == `\n` {
			break
		}
		if c == `[` || c == `(` || c == `{` {
			depth++
		} else if c == `]` || c == `)` || c == `}` {
			if depth == 0 {
				break
			}
			depth--
		} else if depth == 0 && (c == ` ` || c == `\t`) {
			break
		}
		i++
	}
	return i
}

// render_pathexpr_hover returns the markdown body for a CXPath hover
// tooltip. Lines:
//   1. The path source text (header)
//   2. Anchor kind ('//', '/', or 'relative')
//   3. Step count
//   4. Static focus type — `any` when no declaration is in scope
//      (the Layer-B rule, shape_inference.md §2: declarations are the
//      contract, inference is modular and stops at [?def] boundaries;
//      a document-anchored path carries no declaration, so `any` IS
//      the declared answer, not a placeholder).
fn render_pathexpr_hover(p cx.ProgramPathExpr) string {
	anchor := match p.leading {
		.descendant { '`//` (descendant-or-self)' }
		.absolute   { '`/` (absolute, anchored at document root)' }
		.relative   { '(relative, anchored at context item)' }
	}
	step_count := p.steps.len
	mut step_summary := ''
	if step_count > 0 {
		mut bits := []string{}
		for s in p.steps {
			bits << if s.name != '' { s.name } else { '*' }
		}
		step_summary = '\n\n**Steps:** `${bits.join('/')}`'
	}
	return '**CXPath expression**\n\n**Anchor:** ${anchor}\n\n**Step count:** ${step_count}${step_summary}\n\n**Focus type (declared):** `any`\n\n*Shape flow is declaration-driven (modular — declarations are the contract); a document-anchored path carries no declared shape, so `any` is the answer, not a gap. Declared [?pipe]-stage flow renders as inlay hints.*'
}
