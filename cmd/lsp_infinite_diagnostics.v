// LSP advisory: `[?for]` source is an infinite generator
// (`[$range N *]` / iter_range_open) without a terminating
// `[take]` / `[take-while]` clause.
//
// Triggers a hint-severity CXLS006 diagnostic when a [?for] / [?for-array] /
// [?for-map] comprehension's first generator source is the open-end form
// `[$range N *]` (parser substitutes the `_open_end_` atom for the `*`) AND
// none of its clauses are `[take]` / `[take-while]`. Without a terminating
// modifier the for-comp will fail at runtime with CXER0100 per D19; we
// surface that statically so the user sees it in the editor *before*
// eval rather than at eval time.
//
// Diagnostic emits at the position of the open-end source (the `*`
// substituted by the parser carries the literal's pos). The message
// suggests the canonical fix — add `[take N]` or `[take-while P]`.
//
// Suppression: standard editor diagnostic-disable comments / per-file
// configuration apply. No directive-level opt-out is defined.

module main
import cx

import code
import x.json2

fn infinite_diagnostics(source string) []json2.Any {
	mut diags := []json2.Any{}
	prog := cx.parse_program(source) or { return diags }
	walk_for_infinite(prog.body, source, mut diags)
	return diags
}

fn walk_for_infinite(node cx.ProgramNode, source string, mut diags []json2.Any) {
	match node {
		cx.ProgramDirective {
			for slot in node.slots {
				walk_for_infinite(slot.value, source, mut diags)
			}
		}
		cx.Program {
			walk_for_infinite(node.body, source, mut diags)
		}
		cx.ProgramLiteral {
			for child in node.items {
				walk_for_infinite(child, source, mut diags)
			}
			for slot in node.slots {
				walk_for_infinite(slot.value, source, mut diags)
			}
			for attr in node.attrs {
				walk_for_infinite(attr.value, source, mut diags)
			}
		}
		cx.ProgramCall {
			for arg in node.args {
				walk_for_infinite(arg, source, mut diags)
			}
		}
		cx.ProgramForComp {
			analyse_for_comp(node, source, mut diags)
			// L100: THE ONE traversal. The hand-rolled walk this replaces
			// stopped at `yield` — an unbounded comprehension nested in a
			// `[yield-map K V]` value went undiagnosed.
			for item in cx.for_comp_children(node) {
				walk_for_infinite(item.node, source, mut diags)
			}
		}
		cx.ProgramPattern {
			for child in node.body {
				walk_for_infinite(child, source, mut diags)
			}
		}
		else {}
	}
}

// analyse_for_comp emits CXLS006 when the comprehension's first generator
// source is an open-end range (`range(start, _open_end_, step?)` —
// ProgramCall name='range' with arg[1] being the `_open_end_` atom-literal)
// AND no `[take]` / `[take-while]` clause is present. Other terminators
// (`[limit]`, `[drop]`) do not bound an unbounded source, so they don't
// suppress the advisory.
fn analyse_for_comp(f cx.ProgramForComp, source string, mut diags []json2.Any) {
	// Find first generator clause + its source position.
	mut found_open := false
	mut open_pos := cx.Position{}
	for c in f.clauses {
		if c.kind != .generator { continue }
		src := c.source or { continue }
		if is_open_end_range_call(src) {
			found_open = true
			open_pos = open_end_source_pos(src, f.pos)
		}
		break // only inspect the first generator (the leading source)
	}
	if !found_open {
		return
	}
	// Look for a terminator that bounds the unbounded source.
	for c in f.clauses {
		if c.kind == .take || c.kind == .takewhile {
			return
		}
	}
	end := key_pos_end_estimate(open_pos, 1)
	diags << json2.Any(make_diagnostic('CXLS006', 4, // hint
		open_pos, end,
		'[?for] source `[\$range N *]` is an infinite range with no `[take]` / `[take-while]` terminator — at runtime this will raise CXER0100. Add `[take N]` or `[take-while P]` before the `[yield …]` clause to bound the comprehension.'))
}

// is_open_end_range_call returns true when `n` is a `range(start, *, ...)`
// builtin call — the parser substitutes the atom literal `_open_end_`
// for the `*` token (see vcx/code/parser.v `parse_atom`'s `to *` branch).
fn is_open_end_range_call(n cx.ProgramNode) bool {
	if n is cx.ProgramCall {
		if n.name != 'range' { return false }
		if n.args.len < 2 { return false }
		end_arg := n.args[1]
		if end_arg is cx.ProgramLiteral {
			return end_arg.kind == .atom_lit && end_arg.str_val == '_open_end_'
		}
	}
	return false
}

// open_end_source_pos returns the position of the open-end marker (the
// `*` token); falls back to the for-comp pos when the AST lacks a
// useful literal position.
fn open_end_source_pos(n cx.ProgramNode, fallback cx.Position) cx.Position {
	if n is cx.ProgramCall {
		if n.args.len >= 2 {
			end_arg := n.args[1]
			if end_arg is cx.ProgramLiteral {
				if end_arg.pos.line > 0 {
					return end_arg.pos
				}
			}
		}
		if n.pos.line > 0 { return n.pos }
	}
	return fallback
}
