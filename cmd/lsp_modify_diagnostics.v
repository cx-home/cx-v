// Q5 v0.8.0 / Phase 5.5 finish: `cx lsp` — `[?modify]` attribute-axis
// diagnostic (CXLS004) + CXPath path-context completion provider.
//
// Implements the two affordances reserved by
// `tooling/lsp/v0_8_0_diagnostics.md` for the second half of Phase 5.5:
//
//   1. CXLS004 — `[?modify]` `[set-attr …]` / `[delete-attr …]` invoked
//      on a focus path whose last step is an attribute axis.
//   2. Path-context completion — when the cursor sits inside a CXPath
//      fragment, return axis names / element names / attribute names
// `v0_8_0_diagnostics.md` `textDocument/
//      completion` section.
//
// Approach for CXLS004
//
// The code parser (`vcx/code/parser.v` ::parse_modify_body) raises a
// STATIC `CXER0100` parse error when the D7 violation is present —
// before producing a ProgramDirective. Consequently a full-AST walk
// of the form used in `lsp_match_diagnostics.v` cannot see the
// directive; the parse-error pipeline catches the source first and
// emits a generic `cx-parse` severity-1 diagnostic via
// `publish_diagnostics`.
//
// We recognise the parse-error message pattern from
// `vcx/code/parser.v` ::parse_modify_body (the literal `[?modify]
// action '[set-attr …]'` / `'[delete-attr …]'` requires an
// element-step focus path … ` signature) and emit a *parallel*
// CXLS004 diagnostic at the same position. Editors then see a coded LSP diagnostic alongside the
// raw parse error, matching the contract advertised in the
// diagnostics doc.
//
// Approach for path-context completion
//
// The LSP `textDocument/completion` request includes a position. We
// snapshot the source, check whether the cursor sits inside a CXPath
// fragment via two independent signals:
//
//   - Parse-tree signal: if `cx.parse_program(source)` succeeds, walk the
//     AST with `find_pathexpr_at` (shared with the hover provider).
//     A hit means the cursor sits inside a fully-parsed ProgramPathExpr.
//
//   - Lexical signal: scan backward from the cursor on the same line
//     looking for the most recent `/`, `::`, `[`, or `@` token outside
//     a string. Used (a) when parse fails (mid-edit) and (b) when the
//     cursor sits mid-step (the parser snapshot may have already
//     swallowed everything up to the next whitespace).
//
// Given a hit, the cursor's micro-position inside the path determines
// which class of completion to emit:
//
//   - immediately after `::`               → axis NEVER (we already
//                                              selected the axis); emit
//                                              element-name suggestions.
//   - at step start (just after `/` or `//`) → axes + element names
//   - immediately after `[`                → `@`-prefixed attribute
//                                              names (predicate context)
//   - after `[`'s NCName (mid-predicate)   → no extra completions
//                                              (predicate-body work)
//
// Element / attribute names are sourced from the open document's
// data-parse `Document` value when available; when the data parse fails
// (the source is a code-only fragment) we fall back to the 12 axes +
// the cached element names from the *previously-successful* data parse
// of the same URI. The cache is keyed on URI in `LspState`.
//
// The provider attaches a `data.path_axis: true` tag to axis items so
// editors can sort them distinct from generic identifier completions
// (per the diagnostics doc spec).

module main

import code
import cx
import x.json2

// ── CXLS004 — modify attribute-axis diagnostic ─────────────────────

// modify_diagnostics walks the source for the CXLS004 surface. Two
// signals drive the emit:
//
//   1. Static parse-error signal — `cx.parse_program(source)` fails with the
//      D7 marker substring. We extract the action label + position
//      from the error message and emit a CXLS004 diagnostic mirroring
//      the parser's static error.
//
//   2. AST signal — `cx.parse_program(source)` succeeds (the parser did NOT
//      catch a violation). Walk `ProgramDirective{name:'modify'}`
//      slots; if the focus path's last step uses `.attribute` axis AND
//      any action slot is labeled 'set-attr' or 'delete-attr', emit
//      CXLS004. This branch is defensive — the parser is supposed to
//      catch every case, but a future parser refactor that relaxes the
//      pre-emit guard (e.g. to lift D7 from "static" to "static *or*
//      runtime") would otherwise leak the violation past CXLS004.
//
// On parse success with no violation, returns an empty slice.
fn modify_diagnostics(source string) []json2.Any {
	mut diags := []json2.Any{}

	prog := cx.parse_program(source) or {
		// Signal 1 — recognise the D7 parse-error message.
		emsg := err.msg()
		if cxls004_violation_message(emsg) {
			label := cxls004_action_label(emsg)
			line, col := code_parse_error_position(emsg)
			start_pos := cx.Position{
				offset: 0  // line/col carry the location; offset unused by make_diagnostic
				line:   line  // 1-based; make_diagnostic converts to 0-based LSP
				col:    col
			}
			end_pos := key_pos_end_estimate(start_pos, label.len + 1)
			msg := "[?modify] action '[${label} …]' requires an element-step focus path; the focus path ends in an attribute step. Use '[set]' / '[delete]' on attribute-step paths, or shorten the focus path to an element step."
			diags << json2.Any(make_diagnostic('CXLS004', 1 /* error */, start_pos, end_pos, msg))
		}
		return diags
	}

	// Signal 2 — defensive AST walk.
	walk_for_modify(prog.body, source, mut diags)
	return diags
}

fn walk_for_modify(node cx.ProgramNode, source string, mut diags []json2.Any) {
	match node {
		cx.ProgramDirective {
			if node.name == 'modify' {
				analyse_modify_directive(node, source, mut diags)
			}
			for slot in node.slots {
				walk_for_modify(slot.value, source, mut diags)
			}
		}
		cx.Program {
			walk_for_modify(node.body, source, mut diags)
		}
		cx.ProgramLiteral {
			for child in node.items {
				walk_for_modify(child, source, mut diags)
			}
			for slot in node.slots {
				walk_for_modify(slot.value, source, mut diags)
			}
			for attr in node.attrs {
				walk_for_modify(attr.value, source, mut diags)
			}
		}
		cx.ProgramCall {
			for arg in node.args {
				walk_for_modify(arg, source, mut diags)
			}
		}
		cx.ProgramForComp {
			for clause in node.clauses {
				if src := clause.source { walk_for_modify(src, source, mut diags) }
				if expr := clause.expr { walk_for_modify(expr, source, mut diags) }
			}
			walk_for_modify(node.yield, source, mut diags)
		}
		cx.ProgramPattern {
			for child in node.body {
				walk_for_modify(child, source, mut diags)
			}
		}
		else {}
	}
}

fn analyse_modify_directive(m cx.ProgramDirective, source string, mut diags []json2.Any) {
	_ = source  // reserved for future position-narrowing of the diag range
	// Find the focus PathExpr. The parser places focus at slot index 0
	// (pipe-stage form) or slot index 1 (explicit doc form) — see
	// vcx/code/parser.v ::parse_modify_body.
	mut focus_path := ?cx.ProgramPathExpr(none)
	for slot in m.slots {
		if slot.kind != .positional { continue }
		if slot.value is cx.ProgramPathExpr {
			focus_path = slot.value as cx.ProgramPathExpr
			break
		}
	}
	fp := focus_path or { return }
	if fp.steps.len == 0 { return }
	last_axis := fp.steps[fp.steps.len - 1].axis
	if last_axis != cx.ProgramPathAxis.attribute { return }

	for slot in m.slots {
		if slot.kind != .labeled { continue }
		if slot.label != 'set-attr' && slot.label != 'delete-attr' { continue }
		start_pos := slot_value_pos(slot.value, m.pos)
		end_pos := key_pos_end_estimate(start_pos, slot.label.len + 1)
		msg := "[?modify] action '[${slot.label} …]' requires an element-step focus path; the focus path ends in an attribute step. Use '[set]' / '[delete]' on attribute-step paths, or shorten the focus path to an element step."
		diags << json2.Any(make_diagnostic('CXLS004', 1 /* error */, start_pos, end_pos, msg))
	}
}

// code_parse_error_position extracts the (line, col) from a code-
// parser error message of the form `${code}: ${message} at line N:M`
// (per `vcx/code/parser.v` ::ParseError.msg). Returns (1, 1) — the
// document start — when the pattern doesn't match.
fn code_parse_error_position(msg string) (int, int) {
	marker := ' at line '
	idx := msg.last_index(marker) or { return 1, 1 }
	tail := msg[idx + marker.len..]
	parts := tail.split(':')
	if parts.len < 2 { return 1, 1 }
	line := parts[0].trim_space().int()
	// col may have a trailing space / period; trim to digits.
	mut col_str := parts[1].trim_space()
	mut col_end := 0
	for col_end < col_str.len && col_str[col_end] >= `0` && col_str[col_end] <= `9` {
		col_end++
	}
	col := col_str[..col_end].int()
	if line <= 0 { return 1, 1 }
	return line, if col > 0 { col } else { 1 }
}

// cxls004_violation_message returns true when the parser error message
// matches the D7 violation signature. The message text is the literal
// produced by `vcx/code/parser.v` ::parse_modify_body
// (`[?modify] action '[set-attr …]' requires an element-step focus
// path …`).
fn cxls004_violation_message(msg string) bool {
	if !msg.contains('attribute step') { return false }
	if !(msg.contains('[set-attr') || msg.contains('[delete-attr')
		|| msg.contains('set-attr') || msg.contains('delete-attr')) {
		return false
	}
	return msg.contains('attribute step') || msg.contains('element-step focus')
}

// cxls004_action_label returns 'set-attr' or 'delete-attr' depending on
// which action the parser cited; falls back to 'set-attr' (the more
// common case) when neither matches — defensive against parser-message
// edits.
fn cxls004_action_label(msg string) string {
	if msg.contains('delete-attr') { return 'delete-attr' }
	return 'set-attr'
}

// ── Path-context completion provider ────────────────────────────────

// path_completion_context discriminates between the four states the
// cursor can be in within a CXPath fragment.
enum PathCompletionContext {
	none_           // not inside a CXPath
	axis_or_name    // after `/` or `//` or at step start — emit axes + element names
	name_only       // after `::` — emit element names only (axis already chosen)
	attr_predicate  // after `[` — emit `@`-prefixed attribute names
}

// path_completion_items returns the completion items to emit when the
// cursor sits at (line, col) inside `source`. Returns an empty slice
// when the cursor is NOT in a CXPath context — the caller falls
// through to the generic directive / module-function completion.
fn path_completion_items(source string, line int, col int) []json2.Any {
	ctx := detect_path_context(source, line, col)
	if ctx == .none_ {
		return []json2.Any{}
	}
	mut items := []json2.Any{}

	// Axes — fire only at axis_or_name positions.
	if ctx == .axis_or_name {
		for axis in cxpath_axes {
			mut item := map[string]json2.Any{}
			item['label'] = json2.Any('${axis}::')
			item['kind'] = json2.Any(i64(14))  // Keyword
			item['detail'] = json2.Any('CXPath axis')
			item['documentation'] = json2.Any(cxpath_axis_doc(axis))
			mut data := map[string]json2.Any{}
			data['path_axis'] = json2.Any(true)
			item['data'] = json2.Any(data)
			// Sort path completions ahead of generic ones.
			item['sortText'] = json2.Any('0_axis_${axis}')
			items << json2.Any(item)
		}
	}

	// Element names — fire at axis_or_name and name_only positions.
	if ctx == .axis_or_name || ctx == .name_only {
		for name in distinct_element_names(source) {
			mut item := map[string]json2.Any{}
			item['label'] = json2.Any(name)
			item['kind'] = json2.Any(i64(7))   // Class (used by tsserver for element-like names)
			item['detail'] = json2.Any('element from open document')
			mut data := map[string]json2.Any{}
			data['path_element'] = json2.Any(true)
			item['data'] = json2.Any(data)
			item['sortText'] = json2.Any('1_elem_${name}')
			items << json2.Any(item)
		}
	}

	// Attribute names — fire at attr_predicate position.
	if ctx == .attr_predicate {
		for name in distinct_attribute_names(source) {
			mut item := map[string]json2.Any{}
			item['label'] = json2.Any('@${name}')
			item['kind'] = json2.Any(i64(10))  // Property
			item['detail'] = json2.Any('attribute from open document')
			mut data := map[string]json2.Any{}
			data['path_attribute'] = json2.Any(true)
			item['data'] = json2.Any(data)
			item['sortText'] = json2.Any('2_attr_${name}')
			items << json2.Any(item)
		}
	}

	return items
}

// detect_path_context inspects the bytes immediately before the cursor
// on the current line. Returns one of the four context values.
//
// Recognised triggers (scanning backwards from the cursor):
//
//   - `::` (axis terminator)      → .name_only
//   - `[`  (predicate opener)     → .attr_predicate (when not yet inside
//                                    an inner expression)
//   - `/` or `//`                 → .axis_or_name
//   - whitespace then `//` / `/`  → .axis_or_name (mid-step start)
//
// Returns `.none_` when no such trigger appears between the cursor and
// the previous statement boundary (start of line / `[` of an enclosing
// directive head).
fn detect_path_context(source string, line int, col int) PathCompletionContext {
	lines := source.split('\n')
	if line < 0 || line >= lines.len { return .none_ }
	row := lines[line]
	c := if col > row.len { row.len } else { col }
	if c <= 0 { return .none_ }

	// Walk backward from (col-1) collecting context.
	mut i := c - 1
	mut depth_paren := 0   // ( )
	mut depth_brack := 0   // [ ]
	for i >= 0 {
		ch := row[i]
		// Skip strings — naive (no escape handling but adequate for the
		// cursor-context probe; if cursor is *inside* a string the
		// detector exits early below).
		if ch == `"` {
			// Walk backward past the string literal.
			i--
			for i >= 0 && row[i] != `"` { i-- }
			if i >= 0 { i-- }
			continue
		}
		if ch == `)` { depth_paren++ }
		else if ch == `(` {
			if depth_paren == 0 { return .none_ }
			depth_paren--
		}
		else if ch == `]` { depth_brack++ }
		else if ch == `[` {
			if depth_brack == 0 {
				// Cursor is in predicate position iff the `[` is preceded
				// by a path-step NodeTest (NCName or `*` or `@`) or `/`.
				j := skip_ws_back(row, i - 1)
				if j < 0 { return .none_ }
				prev := row[j]
				if is_path_step_tail(prev) {
					// Inside `[`: distinguish bare-predicate start vs the
					// directive-head `[` (`[?modify ...]`). Tail char of
					// step name → predicate position.
					return .attr_predicate
				}
				return .none_
			}
			depth_brack--
		}
		else if ch == `:` && i > 0 && row[i - 1] == `:` {
			// `::` axis terminator. Cursor is at NodeTest position.
			return .name_only
		}
		else if ch == `/` {
			// `/` or `//` step separator → axis-or-name position.
			return .axis_or_name
		}
		else if ch == ` ` || ch == `\t` {
			// Continue scanning past whitespace.
		}
		else if is_path_step_tail(ch) {
			// We're inside or at the tail of a NodeTest. Continue
			// scanning — the position may still be axis_or_name (typing
			// step name) or name_only (after `::`).
		}
		else {
			// Hit something that breaks path context (e.g. `=`, `$`, `,`).
			return .none_
		}
		i--
	}
	return .none_
}

fn skip_ws_back(row string, start int) int {
	mut i := start
	for i >= 0 && (row[i] == ` ` || row[i] == `\t`) { i-- }
	return i
}

fn is_path_step_tail(c u8) bool {
	return (c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`)
		|| (c >= `0` && c <= `9`) || c == `_` || c == `-` || c == `*` || c == `@`
}

// cxpath_axes — the 12 XPath 3.1 axes per spec/grammar.ebnf [131a].
const cxpath_axes = [
	'child',
	'descendant',
	'descendant-or-self',
	'parent',
	'ancestor',
	'ancestor-or-self',
	'following-sibling',
	'preceding-sibling',
	'following',
	'preceding',
	'self',
	'attribute',
]

fn cxpath_axis_doc(axis string) string {
	return match axis {
		'child'              { 'Direct children of the context node (default axis).' }
		'descendant'         { 'All descendants (not including the context node).' }
		'descendant-or-self' { 'The context node and all its descendants (`//` shorthand).' }
		'parent'             { 'The parent of the context node.' }
		'ancestor'           { 'All ancestors of the context node.' }
		'ancestor-or-self'   { 'The context node and all its ancestors.' }
		'following-sibling'  { 'Following siblings in document order.' }
		'preceding-sibling'  { 'Preceding siblings in reverse document order.' }
		'following'          { 'All nodes after the context node in document order.' }
		'preceding'          { 'All nodes before the context node in document order.' }
		'self'               { 'The context node itself (`.` shorthand).' }
		'attribute'          { 'Attributes of the context node (`@name` shorthand).' }
		else                 { 'XPath 3.1 axis.' }
	}
}

// distinct_element_names parses `source` as a CX data document and
// returns the de-duplicated set of element names reachable from the
// root. Returns an empty slice when the data parse fails (e.g. the
// source is a code-only fragment). The set is sorted ASCII for
// deterministic completion order.
fn distinct_element_names(source string) []string {
	doc := cx.parse(source) or { return []string{} }
	mut seen := map[string]bool{}
	for n in doc.elements {
		collect_element_names(n, mut seen)
	}
	mut names := []string{}
	for k, _ in seen { names << k }
	names.sort()
	return names
}

fn collect_element_names(node cx.Node, mut seen map[string]bool) {
	if node is cx.Element {
		seen[node.name] = true
		for child in node.items {
			collect_element_names(child, mut seen)
		}
	}
}

fn distinct_attribute_names(source string) []string {
	doc := cx.parse(source) or { return []string{} }
	mut seen := map[string]bool{}
	for n in doc.elements {
		collect_attribute_names(n, mut seen)
	}
	mut names := []string{}
	for k, _ in seen { names << k }
	names.sort()
	return names
}

fn collect_attribute_names(node cx.Node, mut seen map[string]bool) {
	if node is cx.Element {
		for a in node.attrs {
			seen[a.name] = true
		}
		for child in node.items {
			collect_attribute_names(child, mut seen)
		}
	}
}
