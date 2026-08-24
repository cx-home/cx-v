// Q5: `cx lsp` — extended LSP features for full editor support.
//
// Round-out capabilities beyond the minimum (didOpen / didChange
// / hover / completion / semanticTokens / formatting / definition):
//
//   - documentSymbol     → outline view + Go-to-symbol
//   - foldingRange       → fold elements + directives
//   - selectionRange     → smart structural selection (replaces
//                          tree-sitter textobjects)
//   - references         → find all uses of `#id`
//   - prepareRename      → validate rename position
//   - rename             → cross-document `#id` rename
//   - codeAction         → quick fixes for diagnostics (placeholder
//                          — populated as canonical fixes land)
//   - inlayHint          → type / value hints (placeholder — wired
//                          to cx-eval inference later)
//   - signatureHelp      → param list inside `[?fn ...]` bodies
//
// All handlers parse the document source with libcx where possible.
// When the source doesn't parse (most likely while the user is typing),
// they fall back to lightweight source-scanning so editor features
// don't blink off mid-edit.

module main
import cx

import x.json2

// ── documentSymbol ───────────────────────────────────────────────────
//
// Source-scan based. Walks `[name ... ]` brackets and emits a nested
// SymbolKind tree. Works mid-edit (no parse dependency) and is fast
// enough to recompute on every request.

fn handle_document_symbol(msg LspMessage, mut state LspState) {
	params := msg.params as map[string]json2.Any
	td := params['textDocument'] or { return } as map[string]json2.Any
	uri := td['uri'] or { return }.str()
	source := state.doc_source(uri) or {
		write_lsp_response(msg.id, json2.Any([]json2.Any{}))
		return
	}
	symbols := scan_symbols_from_source(source)
	write_lsp_response(msg.id, json2.Any(symbols))
}

fn symbol_kind_for(name string) int {
	// LSP SymbolKind enum (1-based).
	// 5=Class, 6=Method, 12=Function, 13=Variable, 15=String, 22=Struct.
	if name.starts_with('?') { return 6 }  // directive → Method
	if name in ['p', 'doc', 'article', 'section'] { return 22 }
	if name in ['ul', 'ol', 'li', 'table', 'tr', 'td'] { return 5 }
	return 13
}

// scan_symbols_from_source walks `[name ... ]` brackets and returns
// a nested DocumentSymbol tree mirroring the document structure.
// Names are extracted, IDs (`#id` attribute) populate `detail` so
// the outline shows e.g. `section [#intro]`.

struct SymFrame {
mut:
	name        string
	id_detail   string
	start_line  int
	start_col   int
	name_end_col int
	children    []json2.Any
}

fn scan_symbols_from_source(source string) []json2.Any {
	mut stack := []SymFrame{}
	mut top_level := []json2.Any{}
	mut line := 0
	mut col := 0
	mut i := 0
	mut in_string := false
	mut sq := u8(0)
	for i < source.len {
		c := source[i]
		if c == `\n` { line++; col = 0; i++; continue }
		if in_string {
			if c == `\\` && i + 1 < source.len { col += 2; i += 2; continue }
			if c == sq { in_string = false }
			col++; i++; continue
		}
		if c == `"` || c == `'` { in_string = true; sq = c; col++; i++; continue }
		if c == `[` && i + 1 < source.len {
			next := source[i + 1]
			if (next >= `a` && next <= `z`) || (next >= `A` && next <= `Z`) || next == `?` {
				name_start := i + 1
				mut j := name_start
				for j < source.len && is_name_char(source[j]) { j++ }
				name := source[name_start..j]
				if name.len > 0 {
					stack << SymFrame{
						name: name
						start_line: line
						start_col: col
						name_end_col: col + (j - i)
					}
					col += j - i
					i = j
					continue
				}
			}
		}
		if c == `]` && stack.len > 0 {
			frame := stack[stack.len - 1]
			stack = stack[..stack.len - 1]
			mut sym := map[string]json2.Any{}
			sym['name'] = json2.Any(frame.name)
			if frame.id_detail.len > 0 { sym['detail'] = json2.Any(frame.id_detail) }
			sym['kind'] = json2.Any(i64(symbol_kind_for(frame.name)))
			sym['range'] = json2.Any(make_range(frame.start_line, frame.start_col, line, col + 1))
			sym['selectionRange'] = json2.Any(make_range(frame.start_line, frame.start_col, frame.start_line, frame.name_end_col))
			if frame.children.len > 0 { sym['children'] = json2.Any(frame.children) }
			if stack.len > 0 {
				stack[stack.len - 1].children << json2.Any(sym)
			} else {
				top_level << json2.Any(sym)
			}
			col++; i++; continue
		}
		// `#id` attribute pickup — set detail on the innermost frame.
		if c == `#` && stack.len > 0 && i + 1 < source.len && is_name_char(source[i + 1]) {
			id_start := i + 1
			mut j := id_start
			for j < source.len && is_name_char(source[j]) { j++ }
			if stack[stack.len - 1].id_detail.len == 0 {
				stack[stack.len - 1].id_detail = '#' + source[id_start..j]
			}
			col += j - i
			i = j
			continue
		}
		col++
		i++
	}
	// Unbalanced [ — flush remaining frames as best-effort symbols.
	for stack.len > 0 {
		frame := stack[stack.len - 1]
		stack = stack[..stack.len - 1]
		mut sym := map[string]json2.Any{}
		sym['name'] = json2.Any(frame.name)
		sym['kind'] = json2.Any(i64(symbol_kind_for(frame.name)))
		sym['range'] = json2.Any(make_range(frame.start_line, frame.start_col, line, col))
		sym['selectionRange'] = json2.Any(make_range(frame.start_line, frame.start_col, frame.start_line, frame.name_end_col))
		if stack.len > 0 {
			stack[stack.len - 1].children << json2.Any(sym)
		} else {
			top_level << json2.Any(sym)
		}
	}
	return top_level
}

fn is_name_char(c u8) bool {
	return (c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`)
		|| (c >= `0` && c <= `9`) || c == `_` || c == `-` || c == `.`
		|| c == `:` || c == `?`
}

// ── foldingRange ─────────────────────────────────────────────────────
//
// Fold every `[...]` region that spans more than one line. Implemented
// as a bracket-balanced scan so we don't need an AST for the common
// fold case (works mid-edit when the parser fails).

fn handle_folding_range(msg LspMessage, mut state LspState) {
	params := msg.params as map[string]json2.Any
	td := params['textDocument'] or { return } as map[string]json2.Any
	uri := td['uri'] or { return }.str()
	source := state.doc_source(uri) or {
		write_lsp_response(msg.id, json2.Any([]json2.Any{}))
		return
	}
	ranges := compute_folding_ranges(source)
	write_lsp_response(msg.id, json2.Any(ranges))
}

fn compute_folding_ranges(source string) []json2.Any {
	mut out := []json2.Any{}
	mut stack := []FoldStart{}
	mut line := 0
	mut col := 0
	mut i := 0
	mut in_string := false
	mut string_quote := u8(0)
	for i < source.len {
		c := source[i]
		if c == `\n` { line++; col = 0; i++; continue }
		if in_string {
			if c == `\\` && i + 1 < source.len { i += 2; col += 2; continue }
			if c == string_quote { in_string = false }
			col++; i++; continue
		}
		if c == `"` || c == `'` { in_string = true; string_quote = c; col++; i++; continue }
		if c == `[` { stack << FoldStart{line: line, col: col}; col++; i++; continue }
		if c == `]` && stack.len > 0 {
			start := stack[stack.len - 1]
			stack = stack[..stack.len - 1]
			if line > start.line {
				mut r := map[string]json2.Any{}
				r['startLine'] = json2.Any(i64(start.line))
				r['startCharacter'] = json2.Any(i64(start.col))
				r['endLine'] = json2.Any(i64(line - 1))
				r['kind'] = json2.Any('region')
				out << json2.Any(r)
			}
			col++; i++; continue
		}
		col++; i++
	}
	return out
}

struct FoldStart {
	line int
	col  int
}

// ── selectionRange ───────────────────────────────────────────────────
//
// For each cursor position, return a chain of nested selection ranges
// from innermost token outward to the enclosing element. Editors bind
// this to "expand selection" (alt-shift-→ in VS Code, gn in Neovim).

fn handle_selection_range(msg LspMessage, mut state LspState) {
	params := msg.params as map[string]json2.Any
	td := params['textDocument'] or { return } as map[string]json2.Any
	uri := td['uri'] or { return }.str()
	positions := params['positions'] or {
		write_lsp_response(msg.id, json2.Any([]json2.Any{}))
		return
	} as []json2.Any
	source := state.doc_source(uri) or {
		write_lsp_response(msg.id, json2.Any([]json2.Any{}))
		return
	}
	mut out := []json2.Any{}
	for p in positions {
		pos := p as map[string]json2.Any
		line := json_int(pos['line'] or { continue })
		col := json_int(pos['character'] or { continue })
		out << build_selection_chain(source, line, col)
	}
	write_lsp_response(msg.id, json2.Any(out))
}

fn build_selection_chain(source string, line int, col int) json2.Any {
	// Compute byte offset for (line, col).
	offset := line_col_to_offset(source, line, col)
	// Walk outward through enclosing [...] brackets.
	mut ranges := [][4]int{}
	// Innermost: the word at cursor.
	word_start, word_end := word_span_at(source, offset)
	if word_end > word_start {
		ws_line, ws_col := offset_to_line_col(source, word_start)
		we_line, we_col := offset_to_line_col(source, word_end)
		ranges << [ws_line, ws_col, we_line, we_col]!
	}
	// Walk outward bracket pairs.
	for depth_start in find_enclosing_brackets(source, offset) {
		depth_end := find_matching_close(source, depth_start)
		if depth_end > depth_start {
			s_line, s_col := offset_to_line_col(source, depth_start)
			e_line, e_col := offset_to_line_col(source, depth_end + 1)
			ranges << [s_line, s_col, e_line, e_col]!
		}
	}
	// Build nested SelectionRange chain from innermost.
	return build_nested_range(ranges, 0)
}

fn build_nested_range(ranges [][4]int, i int) json2.Any {
	if i >= ranges.len {
		return json2.Any(json2.Null{})
	}
	r := ranges[i]
	mut node := map[string]json2.Any{}
	node['range'] = json2.Any(make_range(r[0], r[1], r[2], r[3]))
	if i + 1 < ranges.len {
		node['parent'] = build_nested_range(ranges, i + 1)
	}
	return json2.Any(node)
}

fn line_col_to_offset(source string, target_line int, target_col int) int {
	mut line := 0
	mut col := 0
	mut i := 0
	for i < source.len {
		if line == target_line && col == target_col { return i }
		if source[i] == `\n` { line++; col = 0 } else { col++ }
		i++
	}
	return source.len
}

fn offset_to_line_col(source string, target_offset int) (int, int) {
	mut line := 0
	mut col := 0
	mut i := 0
	for i < target_offset && i < source.len {
		if source[i] == `\n` { line++; col = 0 } else { col++ }
		i++
	}
	return line, col
}

fn word_span_at(source string, offset int) (int, int) {
	mut s := offset
	for s > 0 && is_name_char(source[s - 1]) { s-- }
	mut e := offset
	for e < source.len && is_name_char(source[e]) { e++ }
	return s, e
}

fn find_enclosing_brackets(source string, offset int) []int {
	mut starts := []int{}
	mut stack := []int{}
	mut i := 0
	for i < source.len {
		if i == offset { starts = stack.clone() }
		c := source[i]
		if c == `[` { stack << i }
		else if c == `]` && stack.len > 0 { stack = stack[..stack.len - 1] }
		i++
	}
	// Return from innermost outward (V's reverse() is non-mutating).
	return starts.reverse()
}

fn find_matching_close(source string, open_pos int) int {
	mut depth := 0
	mut i := open_pos
	for i < source.len {
		if source[i] == `[` { depth++ }
		else if source[i] == `]` {
			depth--
			if depth == 0 { return i }
		}
		i++
	}
	return source.len
}

// ── references ───────────────────────────────────────────────────────
//
// Find all positions where an identifier is referenced. Current scope:
// `#id` declarations + `@id` references in the open document.

fn handle_references(msg LspMessage, mut state LspState) {
	params := msg.params as map[string]json2.Any
	td := params['textDocument'] or { return } as map[string]json2.Any
	uri := td['uri'] or { return }.str()
	pos := params['position'] or {
		write_lsp_response(msg.id, json2.Any([]json2.Any{}))
		return
	} as map[string]json2.Any
	line := json_int(pos['line'] or { return })
	col := json_int(pos['character'] or { return })
	source := state.doc_source(uri) or {
		write_lsp_response(msg.id, json2.Any([]json2.Any{}))
		return
	}
	word := word_at_position(source, line, col)
	if word.len < 2 || !(word.starts_with('@') || word.starts_with('#')) {
		write_lsp_response(msg.id, json2.Any([]json2.Any{}))
		return
	}
	target := word[1..]
	locations := find_all_id_uses(source, target, uri)
	write_lsp_response(msg.id, json2.Any(locations))
}

fn find_all_id_uses(source string, name string, uri string) []json2.Any {
	mut out := []json2.Any{}
	mut line := 0
	mut col := 0
	mut i := 0
	for i < source.len {
		c := source[i]
		if c == `\n` { line++; col = 0; i++; continue }
		if (c == `#` || c == `@`) && i + 1 < source.len && is_name_char(source[i + 1]) {
			name_start := i + 1
			mut j := name_start
			for j < source.len && is_name_char(source[j]) { j++ }
			if source[name_start..j] == name {
				mut loc := map[string]json2.Any{}
				loc['uri'] = json2.Any(uri)
				loc['range'] = json2.Any(make_range(line, col, line, col + (j - i)))
				out << json2.Any(loc)
			}
			col += j - i
			i = j
			continue
		}
		col++
		i++
	}
	return out
}

// ── prepareRename ────────────────────────────────────────────────────

fn handle_prepare_rename(msg LspMessage, mut state LspState) {
	params := msg.params as map[string]json2.Any
	td := params['textDocument'] or { return } as map[string]json2.Any
	uri := td['uri'] or { return }.str()
	pos := params['position'] or { return } as map[string]json2.Any
	line := json_int(pos['line'] or { return })
	col := json_int(pos['character'] or { return })
	source := state.doc_source(uri) or {
		write_lsp_response(msg.id, json2.Any(json2.Null{}))
		return
	}
	word := word_at_position(source, line, col)
	if word.len < 2 || !(word.starts_with('@') || word.starts_with('#')) {
		write_lsp_response(msg.id, json2.Any(json2.Null{}))
		return
	}
	// Return the range of the identifier (excluding the sigil) so the
	// editor's rename UI pre-selects the right token.
	lines := source.split('\n')
	row := lines[line] or { '' }
	mut start := col
	for start > 0 && is_name_char(row[start - 1]) { start-- }
	mut end := col
	for end < row.len && is_name_char(row[end]) { end++ }
	placeholder := word[1..]
	mut result := map[string]json2.Any{}
	result['range'] = json2.Any(make_range(line, start, line, end))
	result['placeholder'] = json2.Any(placeholder)
	write_lsp_response(msg.id, json2.Any(result))
}

// ── rename ───────────────────────────────────────────────────────────

fn handle_rename(msg LspMessage, mut state LspState) {
	params := msg.params as map[string]json2.Any
	td := params['textDocument'] or { return } as map[string]json2.Any
	uri := td['uri'] or { return }.str()
	pos := params['position'] or { return } as map[string]json2.Any
	new_name := params['newName'] or { return }.str()
	line := json_int(pos['line'] or { return })
	col := json_int(pos['character'] or { return })
	source := state.doc_source(uri) or {
		write_lsp_response(msg.id, json2.Any(json2.Null{}))
		return
	}
	word := word_at_position(source, line, col)
	if word.len < 2 || !(word.starts_with('@') || word.starts_with('#')) {
		write_lsp_response(msg.id, json2.Any(json2.Null{}))
		return
	}
	old_name := word[1..]
	// Build per-use TextEdits: replace just the identifier portion,
	// leaving the sigil untouched so `#x` stays a decl and `@x` stays
	// a ref.
	mut edits := []json2.Any{}
	mut scan_line := 0
	mut scan_col := 0
	mut i := 0
	for i < source.len {
		c := source[i]
		if c == `\n` { scan_line++; scan_col = 0; i++; continue }
		if (c == `#` || c == `@`) && i + 1 < source.len && is_name_char(source[i + 1]) {
			name_start := i + 1
			mut j := name_start
			for j < source.len && is_name_char(source[j]) { j++ }
			if source[name_start..j] == old_name {
				mut edit := map[string]json2.Any{}
				edit['range'] = json2.Any(make_range(scan_line, scan_col + 1, scan_line, scan_col + 1 + (j - name_start)))
				edit['newText'] = json2.Any(new_name)
				edits << json2.Any(edit)
			}
			scan_col += j - i
			i = j
			continue
		}
		scan_col++
		i++
	}
	mut changes := map[string]json2.Any{}
	changes[uri] = json2.Any(edits)
	mut workspace_edit := map[string]json2.Any{}
	workspace_edit['changes'] = json2.Any(changes)
	write_lsp_response(msg.id, json2.Any(workspace_edit))
}

// ── codeAction ───────────────────────────────────────────────────────
//
// Return an empty list (well-formed) so editors don't break.
// Quick-fix synthesis is wired later once canonical fix recipes
// land for the common parse / lint diagnostics.

fn handle_code_action(msg LspMessage, mut state LspState) {
	write_lsp_response(msg.id, json2.Any([]json2.Any{}))
}

// ── codeLens ─────────────────────────────────────────────────────────
//
// Phase 4.5: each top-level program directive (`[?for …]`,
// `[?match …]`, `[?modify …]`, `[?def …]`, `[?service …]`, `[?retry …]`,
// etc.) in the document
// gets a "View diagram" CodeLens above it. Activating the lens
// invokes the `cx.diagram` workspace command — the editor extension
// is expected to handle the command by spawning `cx diagram <file>
// --format=mermaid` and rendering the result in a side panel.
//
// The lens is computed via a simple lexical scan over the document
// text: any line beginning (after whitespace) with `[?<name>` where
// <name> is one of the 39 spec/code.md §4.1 directives produces
// a lens at column 0 of that line.

fn handle_code_lens(msg LspMessage, mut state LspState) {
	params := msg.params as map[string]json2.Any
	td := params['textDocument'] or {
		write_lsp_response(msg.id, json2.Any([]json2.Any{}))
		return
	} as map[string]json2.Any
	uri := td['uri'] or {
		write_lsp_response(msg.id, json2.Any([]json2.Any{}))
		return
	}.str()
	doc_text := state.docs[uri] or {
		write_lsp_response(msg.id, json2.Any([]json2.Any{}))
		return
	}
	lines := doc_text.split_into_lines()
	mut lenses := []json2.Any{}
	for line_idx, line in lines {
		// Find the first non-whitespace column.
		mut col := 0
		for col < line.len && (line[col] == ` ` || line[col] == `\t`) { col++ }
		if col + 2 >= line.len { continue }
		if line[col] != `[` || line[col + 1] != `?` { continue }
		// Read the directive name.
		mut name_end := col + 2
		for name_end < line.len {
			c := line[name_end]
			if !((c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`)
			     || (c >= `0` && c <= `9`) || c == `-`) { break }
			name_end++
		}
		name := line[col + 2 .. name_end]
		if !is_cx_code_directive(name) { continue }
		// Build the lens (one per top-level directive line).
		mut range_obj := map[string]json2.Any{}
		mut start := map[string]json2.Any{}
		start['line'] = json2.Any(i64(line_idx))
		start['character'] = json2.Any(i64(col))
		mut end := map[string]json2.Any{}
		end['line'] = json2.Any(i64(line_idx))
		end['character'] = json2.Any(i64(name_end))
		range_obj['start'] = json2.Any(start)
		range_obj['end'] = json2.Any(end)
		mut cmd := map[string]json2.Any{}
		cmd['title'] = json2.Any('▸ View diagram')
		cmd['command'] = json2.Any('cx.diagram')
		cmd['arguments'] = json2.Any([json2.Any(uri), json2.Any('mermaid')])
		mut lens := map[string]json2.Any{}
		lens['range'] = json2.Any(range_obj)
		lens['command'] = json2.Any(cmd)
		lenses << json2.Any(lens)
	}
	write_lsp_response(msg.id, json2.Any(lenses))
}

fn is_cx_code_directive(name string) bool {
	// The FULL closed registry per spec/code.md §4.1 (80 directives) —
	// found stale at the release-cut docs audit (2026-08-20): this list carried only the
	// pre-reshape 37 names, so semantic tokens missed [?modify], the
	// quote family, every iterator combinator, and the module/security
	// directives. Kept in the registry's own order for diffability.
	directives := [
		'match', 'modify', 'with-open', 'with-scope', 'str', 'element',
		'attr', 'entry', 'name', 'quote', 'unquote', 'splice', 'eval',
		'for', 'for-array', 'for-map', 'let', 'fn', 'def', 'lib', 'const',
		'do', 'loop', 'if', 'else', 'pipe', 'map', 'reduce', 'filter',
		'take', 'drop', 'zip', 'enumerate', 'chunks', 'concat', 'cycle',
		'scan', 'flatten', 'partition', 'group-by', 'to-sequence',
		'to-array', 'to-map', 'view', 'views',
		'retry', 'timeout', 'circuit-breaker', 'fallback', 'rate-limit',
		'bulkhead',
		'http-service', 'service-handle', 'http-client',
		'worker', 'worker-handle', 'subscribe', 'monitor',
		'channel', 'send', 'receive', 'try-send', 'try-receive', 'close',
		'select', 'stop', 'wait-for',
		'async', 'await', 'await-all', 'await-any', 'await-race',
		'cancel', 'check-cancel', 'sleep',
		'with-error-hook', 'with-caps', 'secret', 'reveal', 'meta',
	]
	for d in directives {
		if d == name { return true }
	}
	return false
}

// ── inlayHint ────────────────────────────────────────────────────────
//
// Declared-flow type hints across [?pipe] stages (stream 16 W5 — the
// Layer-B surface at the LSP dial): before each stage whose PREVIOUS
// stage is an in-file [?def] with a declared [returns T], render
// `«T»` — the declared type of the value flowing INTO the stage.
// Declarations are the contract (modular; no inference beyond them).

fn handle_inlay_hint(msg LspMessage, mut state LspState) {
	params := msg.params as map[string]json2.Any
	td := params['textDocument'] or {
		write_lsp_response(msg.id, json2.Any([]json2.Any{}))
		return
	} as map[string]json2.Any
	uri := td['uri'] or {
		write_lsp_response(msg.id, json2.Any([]json2.Any{}))
		return
	}.str()
	doc_text := state.docs[uri] or {
		write_lsp_response(msg.id, json2.Any([]json2.Any{}))
		return
	}
	prog := cx.parse_program(doc_text) or {
		write_lsp_response(msg.id, json2.Any([]json2.Any{}))
		return
	}
	mut returns_of := map[string]string{}
	inlay_collect_def_returns(prog.body, mut returns_of)
	mut hints := []json2.Any{}
	inlay_walk_pipes(prog.body, returns_of, mut hints)
	write_lsp_response(msg.id, json2.Any(hints))
}

fn inlay_collect_def_returns(node cx.ProgramNode, mut returns_of map[string]string) {
	if node is cx.ProgramDirective {
		if node.name == 'def' {
			for sl in node.slots {
				if sl.label == 'raw-source' {
					v := sl.value
					if v is cx.ProgramLiteral && v.kind == .string_lit {
						if def := cx.parse_def(v.str_val) {
							returns_of[def.name] = def.returns_type_source or { '' }
						}
					}
				}
			}
		}
		for sl in node.slots {
			inlay_collect_def_returns(sl.value, mut returns_of)
		}
	} else if node is cx.ProgramLiteral {
		for it in node.items {
			inlay_collect_def_returns(it, mut returns_of)
		}
	} else if node is cx.Program {
		inlay_collect_def_returns(node.body, mut returns_of)
	}
}

fn inlay_walk_pipes(node cx.ProgramNode, returns_of map[string]string, mut hints []json2.Any) {
	if node is cx.ProgramDirective {
		if node.name == 'pipe' && node.slots.len >= 3 {
			mut prev_ret := ''
			for i in 1 .. node.slots.len {
				stage := node.slots[i].value
				mut cur_ret := ''
				if stage is cx.ProgramCall {
					if prev_ret != '' {
						hints << inlay_hint_at(stage.pos, '«${prev_ret}» ')
					}
					cur_ret = returns_of[stage.name] or { '' }
				}
				prev_ret = cur_ret
			}
		}
		for sl in node.slots {
			inlay_walk_pipes(sl.value, returns_of, mut hints)
		}
	} else if node is cx.ProgramLiteral {
		for it in node.items {
			inlay_walk_pipes(it, returns_of, mut hints)
		}
	} else if node is cx.ProgramCall {
		for a in node.args {
			inlay_walk_pipes(a, returns_of, mut hints)
		}
	} else if node is cx.Program {
		inlay_walk_pipes(node.body, returns_of, mut hints)
	}
}

fn inlay_hint_at(pos cx.Position, label string) json2.Any {
	mut position := map[string]json2.Any{}
	// Parser positions are 1-based; LSP positions are 0-based.
	hl := if pos.line > 0 { pos.line - 1 } else { 0 }
	hc := if pos.col > 0 { pos.col - 1 } else { 0 }
	position['line'] = json2.Any(i64(hl))
	position['character'] = json2.Any(i64(hc))
	mut h := map[string]json2.Any{}
	h['position'] = json2.Any(position)
	h['label'] = json2.Any(label)
	h['kind'] = json2.Any(i64(1)) // Type
	h['paddingRight'] = json2.Any(false)
	return json2.Any(h)
}

// ── signatureHelp ────────────────────────────────────────────────────

fn handle_signature_help(msg LspMessage, mut state LspState) {
	params := msg.params as map[string]json2.Any
	td := params['textDocument'] or { return } as map[string]json2.Any
	uri := td['uri'] or { return }.str()
	pos := params['position'] or { return } as map[string]json2.Any
	line := json_int(pos['line'] or { return })
	col := json_int(pos['character'] or { return })
	source := state.doc_source(uri) or {
		write_lsp_response(msg.id, json2.Any(json2.Null{}))
		return
	}
	// Find enclosing `[?<name>` directive and serve its signature.
	directive := enclosing_directive_name(source, line, col)
	if directive == '' {
		write_lsp_response(msg.id, json2.Any(json2.Null{}))
		return
	}
	sig := signature_for_directive(directive) or {
		write_lsp_response(msg.id, json2.Any(json2.Null{}))
		return
	}
	mut sig_obj := map[string]json2.Any{}
	sig_obj['label'] = json2.Any(sig.label)
	sig_obj['documentation'] = json2.Any(sig.doc)
	mut params_arr := []json2.Any{}
	for p in sig.params {
		mut pi := map[string]json2.Any{}
		pi['label'] = json2.Any(p)
		params_arr << json2.Any(pi)
	}
	sig_obj['parameters'] = json2.Any(params_arr)
	mut result := map[string]json2.Any{}
	result['signatures'] = json2.Any([json2.Any(sig_obj)])
	result['activeSignature'] = json2.Any(i64(0))
	write_lsp_response(msg.id, json2.Any(result))
}

struct DirectiveSignature {
	label  string
	doc    string
	params []string
}

fn signature_for_directive(name string) ?DirectiveSignature {
	return match name {
		// Clause-child forms — the colon-slot signatures these replace
		// advertised syntax the parser REJECTS (#711 item 5, stream-2 W2).
		'if'      { DirectiveSignature{label: '[?if cond [then expr] [else expr]]', doc: 'Conditional', params: ['cond', '[then expr]', '[else expr]']} }
		'for'     { DirectiveSignature{label: '[?for [in \$x coll] [where P] [yield E]]', doc: 'Comprehension (§7.2)', params: ['[in \$x coll]', '[= \$y E]', '[where P]', '[order-by E]', '[group-by E]', '[take N]', '[par]', '[yield E]']} }
		'let'     { DirectiveSignature{label: '[?let [= \$name value] body]', doc: 'Lexical binding (flat multi-binding)', params: ['[= \$name value]', 'body']} }
		'fn'      { DirectiveSignature{label: '[?fn (\$x \$y) body]', doc: 'First-class function', params: ['(\$params)', 'body']} }
		'match'   { DirectiveSignature{label: '[?match value [case P R] [when PRED R] [else R]]', doc: 'Pattern matching', params: ['value', '[case P R]', '[when PRED R]', '[else R]']} }
		'def'     { DirectiveSignature{label: '[?def name (\$params) body]', doc: 'Module-level function (§8.7)', params: ['name', '(\$params)', 'body']} }
		// `[?include …]` is the DATA-document parse-time form (code.md
		// §13); the CODE-program form is `[?cx include "path"]`. The old
		// signature named only the first and called it file inclusion
		// generally, which is wrong in a code buffer.
		'include' { DirectiveSignature{label: '[?include [\'path.cx\']]', doc: 'Parse-time inclusion in a DATA document (spec/include.md)', params: ['[\'path\']']} }
		'cx'      { DirectiveSignature{label: '[?cx include "path.cx"]', doc: 'Self-host directive (code-program inclusion, cx:* module fns)', params: ['include "path"', 'cx:hash VALUE', 'cx:parse SOURCE']} }
		'eval'    { DirectiveSignature{label: '[?eval TREE [context MAP] [opts {...}]]', doc: 'Sandboxed nested evaluation (§6.4.4)', params: ['TREE', '[context MAP]', '[opts MAP]']} }
		else      { none }
	}
}

fn enclosing_directive_name(source string, line int, col int) string {
	offset := line_col_to_offset(source, line, col)
	starts := find_enclosing_brackets(source, offset)
	for start in starts {
		if start + 1 < source.len && source[start + 1] == `?` {
			name_start := start + 2
			mut j := name_start
			for j < source.len && is_name_char(source[j]) { j++ }
			return source[name_start..j]
		}
	}
	return ''
}

// ── Range helpers ────────────────────────────────────────────────────

fn make_range(start_line int, start_col int, end_line int, end_col int) json2.Any {
	mut start := map[string]json2.Any{}
	start['line'] = json2.Any(i64(start_line))
	start['character'] = json2.Any(i64(start_col))
	mut end_pos := map[string]json2.Any{}
	end_pos['line'] = json2.Any(i64(end_line))
	end_pos['character'] = json2.Any(i64(end_col))
	mut r := map[string]json2.Any{}
	r['start'] = json2.Any(start)
	r['end'] = json2.Any(end_pos)
	return json2.Any(r)
}
