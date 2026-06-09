// LSP advisory: an ambiguous whitespace-separated quoted-string body.
//
// `[x "a" "b"]` — two or more ADJACENT quoted-string items with no comma — is a
// self-delimiting string list that does NOT round-trip through idiomatic XML or
// CX: the items collapse (XML `<x>ab</x>`; CX re-emits `[x a b]`, which re-parses
// as the single prose string "a b"). The unambiguous forms are a comma array
// (`[x "a", "b"]`) or one quoted run (`[x 'a b']`); `--lossless` XML preserves
// the items (`<cx:string>` carriers) but the source shape stays ambiguous.
//
// Emits a warning-severity CXLS007 at the first item of each such run. Numbers
// and a SINGLE quoted string are fine (they carry their own boundary), so only
// runs of ≥2 adjacent quoted strings are flagged.
//
// Suppression: standard editor diagnostic-disable comments / per-file config.

module main

import cx
import x.json2

fn string_list_diagnostics(source string) []json2.Any {
	mut diags := []json2.Any{}
	prog := cx.parse_program(source) or { return diags }
	walk_string_list(prog.body, source, mut diags)
	return diags
}

fn walk_string_list(node cx.ProgramNode, source string, mut diags []json2.Any) {
	match node {
		cx.ProgramDirective {
			for slot in node.slots {
				walk_string_list(slot.value, source, mut diags)
			}
		}
		cx.Program {
			walk_string_list(node.body, source, mut diags)
		}
		cx.ProgramLiteral {
			if node.kind == .cx_element {
				analyse_string_list(node, source, mut diags)
			}
			for child in node.items {
				walk_string_list(child, source, mut diags)
			}
			for slot in node.slots {
				walk_string_list(slot.value, source, mut diags)
			}
			for attr in node.attrs {
				walk_string_list(attr.value, source, mut diags)
			}
		}
		cx.ProgramCall {
			for arg in node.args {
				walk_string_list(arg, source, mut diags)
			}
		}
		cx.ProgramForComp {
			for clause in node.clauses {
				if src := clause.source { walk_string_list(src, source, mut diags) }
				if expr := clause.expr { walk_string_list(expr, source, mut diags) }
			}
			walk_string_list(node.yield, source, mut diags)
		}
		cx.ProgramPattern {
			for child in node.body {
				walk_string_list(child, source, mut diags)
			}
		}
		else {}
	}
}

// analyse_string_list flags each maximal run of ≥2 adjacent quoted-string items
// in a cx_element body (the lossy self-delimiting string-list shape).
fn analyse_string_list(lit cx.ProgramLiteral, source string, mut diags []json2.Any) {
	mut run_start := -1
	mut run_len := 0
	for i, item in lit.items {
		if is_quoted_string_item(item, source) {
			if run_len == 0 {
				run_start = i
			}
			run_len++
		} else {
			if run_len >= 2 {
				emit_string_list_warning(lit.items[run_start], source, mut diags)
			}
			run_len = 0
		}
	}
	if run_len >= 2 {
		emit_string_list_warning(lit.items[run_start], source, mut diags)
	}
}

// is_quoted_string_item reports whether a body item is a string literal whose
// SOURCE form is quoted (`"…"` / `'…'`) — distinguishing it from a bareword
// (which merges into one prose string and carries no boundary risk).
fn is_quoted_string_item(item cx.ProgramNode, source string) bool {
	if item is cx.ProgramLiteral {
		if item.kind == .string_lit {
			off := item.pos.offset
			if off >= 0 && off < source.len {
				c := source[off]
				return c == `"` || c == `'`
			}
		}
	}
	return false
}

fn emit_string_list_warning(item cx.ProgramNode, source string, mut diags []json2.Any) {
	pos := program_node_pos(item)
	end := cx.Position{
		offset: pos.offset
		line:   pos.line
		col:    pos.col + 2
	}
	diags << json2.Any(make_diagnostic('CXLS007', 2 /* warning */, pos, end,
		'ambiguous whitespace-separated string list — adjacent quoted strings do not round-trip in idiomatic XML/CX. Use commas for a list ([x "a", "b"]) or quote the whole body for one string ([x \'a b\']).'))
}

// program_node_pos returns the source Position of a program node (the position
// of its first token), for diagnostic ranges.
fn program_node_pos(node cx.ProgramNode) cx.Position {
	return match node {
		cx.ProgramLiteral { node.pos }
		cx.ProgramCall { node.pos }
		cx.ProgramBinding { node.pos }
		cx.ProgramDirective { node.pos }
		else { cx.Position{} }
	}
}
