module code

import cx

// ── `cx select` engine seam (#462; spec/misc/cli.md §3.8) ────────────────────
//
// select_path evaluates ONE CXPath value expression against a data document
// and reports the match set plus its cardinality — the engine half of
// `cx select 'PATH' [FILE]`. It routes through the SAME program evaluator
// (`eval`, `render`) the run surface uses, so path semantics (axes,
// predicates, the §6.2 terminal-attribute unwrap, document order) can never
// drift between `cx select` and an inline `$doc/…` read; the retired narrow
// CXPath ABI (`cx_select` / `cx_select_all`) stays retired.
//
// The count is derived from the VALUE SHAPE, not the rendered text: the path
// evaluator materializes multi-match / node-set results as a name-less
// wrapper element (`cx.Element{ name: '' }` — the same shape the multi-value
// program output uses), an empty match set as that wrapper with zero items,
// and single plain-chain matches as the node itself. Deriving the count from
// the rendering would mis-count matches that legitimately render empty (an
// empty text node).

// SelectResult carries the canonical-CX rendering of the match set (one
// match per line, document order) and the number of matched nodes.
pub struct SelectResult {
pub:
	rendered string
	count    int
}

// select_path parses `path_src` as a single CXPath value expression
// (spec/code.md §5.5 — `$doc`-anchored, document-rooted `/…`, or descendant
// `//…`), binds the data reading of `doc_src` as `$doc` / `$input`, evaluates,
// and returns the match set. A `path_src` that parses but is NOT a path
// expression (an arithmetic call, a directive, a literal…) is rejected:
// `cx select` is a pure query surface, not a second program-eval entry point
// — it is capability-neutral by construction because a path read touches no
// effect point.
pub fn select_path(doc_src string, path_src string) !SelectResult {
	if path_src.trim_space().len == 0 {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: 'select: PATH must be non-empty'
		}
	}
	prog := cx.parse_program(path_src) or {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: 'path parse: ${err.msg()}'
		}
	}
	body := prog.body
	is_path := match body {
		cx.ProgramPathExpr { true }
		// `$doc`, `$doc/user@name`, … — a binding read with (or without)
		// BindingPath steps; only $doc / $input are bound, so anything else
		// surfaces the evaluator's unbound-variable error.
		cx.ProgramBinding { body.type_test == '' && !body.is_rest }
		else { false }
	}
	if !is_path {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: 'PATH must be a CXPath path expression (\$doc/…, /… or //…), got: ${path_src}'
		}
	}
	doc_node := parse_input_doc(doc_src) or {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: 'parse input: ${err.msg()}'
		}
	}
	mut env := new_env()
	env.bindings['doc'] = doc_node
	env.bindings['input'] = doc_node
	result := eval(body, mut env)!
	count := match result {
		cx.Element {
			// The name-less wrapper is the node-set materialization; its
			// item count IS the match count (0 for the empty set). Named
			// elements are single matches.
			if result.name == '' { result.items.len } else { 1 }
		}
		else { 1 }
	}
	rendered := render(result, 'cx')!
	return SelectResult{
		rendered: rendered
		count:    count
	}
}
