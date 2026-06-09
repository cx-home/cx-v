// LSP advisory: missing [?bulkhead] wrap inside [?map :par] / [?reduce :par]
//
// Triggers a hint-severity CXLS005 diagnostic when a [?map] or
// [?reduce] directive carries `:par`, its `:using` closure body CALLS AN
// IMPURE BUILTIN (spec/code.md §7.3), AND that body does not transitively
// contain a [?bulkhead] directive. Per §7.3 a PURE body is safe to evaluate
// in parallel and to reorder (no effect races), so an unbounded pure `:par`
// is no footgun and gets no hint; the hint is reserved for an impure body
// whose uncapped fan-out (HTTP fetches, expensive compute, queue consumers)
// can race or exhaust resources. The composition idiom is to wrap the worker
// body in `[?bulkhead :max-concurrent K]`.
//
// Diagnostic emits at the position of the `:par` slot keyword. The
// suggested fix (markdown) is included in the diagnostic message;
// LSP clients can surface it as a quick-fix or hover detail.
//
// Suppression: standard editor diagnostic-disable comments / per-file
// configuration apply. No directive-level opt-out is defined at the
// language level — the hint is purely advisory.

module main
import cx

import code
import x.json2

fn par_diagnostics(source string) []json2.Any {
	mut diags := []json2.Any{}
	prog := cx.parse_program(source) or { return diags }
	walk_for_par(prog.body, source, mut diags)
	return diags
}

fn walk_for_par(node cx.ProgramNode, source string, mut diags []json2.Any) {
	match node {
		cx.ProgramDirective {
			if node.name == 'map' || node.name == 'reduce' {
				analyse_par_directive(node, source, mut diags)
			}
			for slot in node.slots {
				walk_for_par(slot.value, source, mut diags)
			}
		}
		cx.Program {
			walk_for_par(node.body, source, mut diags)
		}
		cx.ProgramLiteral {
			for child in node.items {
				walk_for_par(child, source, mut diags)
			}
			for slot in node.slots {
				walk_for_par(slot.value, source, mut diags)
			}
			for attr in node.attrs {
				walk_for_par(attr.value, source, mut diags)
			}
		}
		cx.ProgramCall {
			for arg in node.args {
				walk_for_par(arg, source, mut diags)
			}
		}
		cx.ProgramForComp {
			for clause in node.clauses {
				if src := clause.source { walk_for_par(src, source, mut diags) }
				if expr := clause.expr { walk_for_par(expr, source, mut diags) }
			}
			walk_for_par(node.yield, source, mut diags)
		}
		cx.ProgramPattern {
			for child in node.body {
				walk_for_par(child, source, mut diags)
			}
		}
		else {}
	}
}

fn analyse_par_directive(d cx.ProgramDirective, source string, mut diags []json2.Any) {
	mut par_pos := cx.Position{}
	mut has_par := false
	mut using_node := cx.ProgramNode(cx.ProgramLiteral{ kind: .bool_lit })
	mut have_using := false
	for slot in d.slots {
		if slot.kind != .labeled {
			continue
		}
		match slot.label {
			'par' {
				has_par = true
				par_pos = slot_value_pos(slot.value, d.pos)
			}
			'using' {
				using_node = slot.value
				have_using = true
			}
			else {}
		}
	}
	if !has_par || !have_using {
		return
	}
	if contains_bulkhead(using_node) {
		return
	}
	// §7.3: the hint fires only when the [par] body actually CALLS an impure
	// builtin (without a [?bulkhead] wrap or explicit ordering). A pure body
	// is safe to evaluate in parallel and to reorder — no effect races — so a
	// missing [?bulkhead] is no footgun and warrants no diagnostic.
	if !code.node_calls_impure_builtin(using_node) {
		return
	}
	// Diagnostic range — start at the :par keyword position. Slot
	// labels are stored without the leading `:`, so the pos points
	// at the `p` of `par`. Span 4 chars to cover `:par`.
	start := if par_pos.col > 0 {
		cx.Position{
			offset: par_pos.offset - 1
			line:   par_pos.line
			col:    par_pos.col - 1
		}
	} else {
		par_pos
	}
	end := key_pos_end_estimate(start, 4)
	diags << json2.Any(make_diagnostic('CXLS005', 4, // hint
		start, end,
		'[?${d.name} :par] body calls an impure builtin with no [?bulkhead] wrap — workers spawn one-per-item (unbounded). For bounded concurrency wrap the body in [?bulkhead :max-concurrent K] (spec/code.md §7.3)'))
}

fn contains_bulkhead(node cx.ProgramNode) bool {
	match node {
		cx.ProgramDirective {
			if node.name == 'bulkhead' {
				return true
			}
			for slot in node.slots {
				if contains_bulkhead(slot.value) {
					return true
				}
			}
		}
		cx.ProgramLiteral {
			for child in node.items {
				if contains_bulkhead(child) {
					return true
				}
			}
			for slot in node.slots {
				if contains_bulkhead(slot.value) {
					return true
				}
			}
			for attr in node.attrs {
				if contains_bulkhead(attr.value) {
					return true
				}
			}
		}
		cx.ProgramCall {
			for arg in node.args {
				if contains_bulkhead(arg) {
					return true
				}
			}
		}
		cx.ProgramForComp {
			for clause in node.clauses {
				if src := clause.source {
					if contains_bulkhead(src) { return true }
				}
				if expr := clause.expr {
					if contains_bulkhead(expr) { return true }
				}
			}
			if contains_bulkhead(node.yield) {
				return true
			}
		}
		cx.Program {
			if contains_bulkhead(node.body) {
				return true
			}
		}
		else {}
	}
	return false
}
