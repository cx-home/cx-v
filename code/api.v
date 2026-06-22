module code

import cx

// ── Public API for the program evaluator (Phase 3.11) ───────────────────────
//
// `eval_code` and `eval_code_streaming` are the single-call
// entry points the C ABI (`cx_code_eval*` per
// `spec/audits/code_abi_v1.md`) routes through. They wrap the
// existing lexer / parser / matcher / evaluator into one composable
// surface so callers do not need to assemble a `MatchEnv` themselves.
//
// The streaming variant currently single-flushes the rendered output
// to the sink at completion. Functional equivalence with the one-shot
// variant is preserved per the sketch's §3.3 contract; per-yield
// incremental flushing lands with the §11.6 gate 15 throughput work.

// CXStreamSink receives output chunks during streaming evaluation. It
// MUST return on every call; raising blocks the calling thread until
// the sink resumes (sinks that swallow errors leak no state — the
// evaluator never retries a failed chunk).
pub type CXStreamSink = fn (chunk string) !

// eval_code parses `program_src` and `input` (when non-empty),
// evaluates the program against the input, and renders the result per
// `output_target`. Returns the rendered output string or an
// EvalError / cx.ParseError. The `$doc` binding is set when `input` is
// non-empty.
//
// `output_target == ''` is treated as `'text'` (the spec default at
// `spec/audits/code_abi_v1.md §3.1`).
pub fn eval_code(input string, program_src string, output_target string) !string {
	if program_src.len == 0 {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: 'eval_code: program source must be non-empty'
		}
	}
	prog := cx.parse_program(program_src) or {
		// Spec invariant (code.md §1.3): "a pure-data resource evaluates to
		// itself." The program reader is tokenized and cannot lex free-text
		// element-body prose — em-dash, `;`, `,`, bullets, … — that the
		// scannerless DATA reader accepts (#11; the data ⊂ program seam from the
		// cxparse unification). When the program parse fails AND there is no
		// `$doc` input AND the target is a value-render target, fall back to the
		// data reading: a resource that is valid DATA but not a valid PROGRAM
		// evaluates to itself. We route through the SAME data pipeline as
		// `cx --from=cx --to=<target>` (convert_by_name) so the output is
		// byte-identical to the documented data path — a faithful, semantic
		// conversion of the data document, not the eval-result renderer. A
		// genuine program syntax error that ALSO fails to parse as data surfaces
		// the ORIGINAL program error below.
		//
		// #11 regression fix: the fallback is for prose/markup/scalars the PROGRAM
		// reader can't read but the DATA reader accepts (em-dash, `;`, `,`,
		// bullets, `5mph`, …) — these fail either in `tokenize()` (LexError) or at
		// the parse level with a syntactic error (e.g. "unexpected token ','").
		// The ONE failure that must NOT fall back is a semantic rejection of an
		// unknown / retired `[?name]` directive: that is unambiguous PROGRAM
		// intent, so it stays fail-loud (CXER0100) rather than being silently
		// re-read as the data element `[?name]` (which it also happens to be).
		is_unknown_directive := if err is cx.ParseError { err.unknown_directive } else { false }
		if !is_unknown_directive && input.len == 0
		   && output_target !in ['mermaid', 'svg', 'png'] {
			to_codec := if output_target in ['', 'text'] { 'cx' } else { output_target }
			if out := cx.convert_by_name(program_src, 'cx', to_codec, false) {
				return out
			}
		}
		return EvalError{
			code:    'cx-err:CXER0100'
			message: 'parse: ${err.msg()}'
		}
	}
	// Phase 4 diagram targets render the PROGRAM AST (not the evaluation
	// result). This is a documented surface departure from the value-
	// rendering targets (text / cx / json / yaml / xml / csv / tsv);
	// the diagram visualizes the program structure, not what it
	// computes. Per spec/code.md §10.1.2 + the gate-9 hybrid
	// embed-source round-trip contract (`render_diagram` carries the
	// source verbatim in metadata so `reverse_parse_diagram` recovers
	// it byte-for-byte).
	if output_target == 'mermaid' || output_target == 'svg' || output_target == 'png' {
		return render_diagram(prog, program_src, output_target)!
	}
	mut env := new_env()
	if input.len > 0 {
		doc_node := parse_input_doc(input) or {
			return EvalError{
				code:    'cx-err:CXER0100'
				message: 'parse input: ${err.msg()}'
			}
		}
		env.bindings['doc'] = doc_node
		env.bindings['input'] = doc_node
	}
	// Multi-form top-level program: render EACH top-level form's result
	// (declaration directives omitted), agreeing with the data reading's
	// multi-root emit, rather than silently dropping all but the last (#16).
	// A single-form program keeps the scalar one-shot path below.
	if prog.body is cx.ProgramLiteral {
		if prog.body.kind == .block {
			results := eval_top_level_each(prog.body.items, mut env)!
			mut parts := []string{}
			for r in results {
				if r is cx.Element && r.name == closure_sentinel_name {
					return EvalError{
						code:    'cx-err:CXER0291'
						message: 'a function value is not serialisable (cx-err:CXER0291 E_FN_NOT_SERIALIZABLE)'
					}
				}
				rendered := render(r, output_target)!
				if rendered.trim_space().len > 0 {
					parts << rendered
				}
			}
			return parts.join('\n')
		}
	}
	result := eval(prog.body, mut env)!
	// A function value is opaque and not data-serialisable; reaching a
	// data-emit boundary (program result here) raises CXER0291
	// (E_FN_NOT_SERIALIZABLE, §8.6). (CXER0260 is CANCELLED — an unrelated
	// async code; the prior use of it here was a bug.)
	if result is cx.Element && result.name == closure_sentinel_name {
		return EvalError{
			code:    'cx-err:CXER0291'
			message: 'a function value is not serialisable (cx-err:CXER0291 E_FN_NOT_SERIALIZABLE)'
		}
	}
	return render(result, output_target)!
}

// eval_code_streaming is the streaming counterpart. The render
// output is delivered to `sink` as one or more chunks; concatenating
// all chunks yields the same byte sequence `eval_code` would
// return.
//
// When the top-level program body is `[?for ...]` and the output target
// is 'text' / 'cx' / '' (default), the evaluator routes through
// `eval_for_comp_streamed`: each yielded value is rendered + buffered
// into a 32 KiB chunk and flushed to the sink incrementally. This avoids
// materialising the full result list and the full output string — a
// §11.6 gate 15 throughput requirement.
//
// All other shapes fall back to the one-shot path (`eval_code` →
// single-flush). Adding additional streaming top-levels (labeled-output
// formats) is a follow-up.
//
// A non-zero error returned by `sink` aborts the call with that
// error wrapped as an EvalError(CXER0001) — matching the
// `write_cb != 0` contract in the C ABI sketch §3.3.
pub fn eval_code_streaming(input string, program_src string,
                                output_target string, sink CXStreamSink) ! {
	eval_code_streaming_opts(input, program_src, output_target, sink, false)!
}

// eval_code_streaming_opts adds an `unbuffered` flag: when true, the
// streaming context flushes after every [?for] :yield emit instead of
// batching into 32 KiB chunks. Useful for interactive playgrounds
// where per-item visibility matters more than throughput; not what
// you want for high-volume gate-15 streaming.
pub fn eval_code_streaming_opts(input string, program_src string,
                                output_target string, sink CXStreamSink,
                                unbuffered bool) ! {
	if program_src.len == 0 {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: 'eval_code_streaming: program source must be non-empty'
		}
	}
	target := if output_target == '' { 'text' } else { output_target }
	streamable := target == 'text' || target == 'cx'
	if streamable {
		prog := cx.parse_program(program_src) or {
			return EvalError{
				code:    'cx-err:CXER0100'
				message: 'parse: ${err.msg()}'
			}
		}
		body := prog.body
		if body is cx.ProgramForComp && for_comp_streamable(body.clauses) {
			mut env := new_env()
			if input.len > 0 {
				doc_node := parse_input_doc(input) or {
					return EvalError{
						code:    'cx-err:CXER0100'
						message: 'parse input: ${err.msg()}'
					}
				}
				env.bindings['doc'] = doc_node
		env.bindings['input'] = doc_node
			}
			mut ctx := new_stream_ctx(target, sink)
			if unbuffered {
				ctx.threshold = 1
			}
			eval_for_comp_streamed(body, mut env, mut ctx)!
			ctx.flush()!
			return
		}
		// streaming: top-level [?map] (with or without
		// :par) emits each result via the StreamCtx as workers complete.
		// Gives the playground per-item progress visibility for parallel
		// map demos. [?reduce] is excluded — it yields a single value;
		// streaming gains nothing.
		//
		// cx.Programs with sibling top-level expressions (e.g. a trailing
		// `[# comment #]` block — the playground inlines per-example
		// notes this way) parse to a `block` literal; we route through
		// the streaming path when the LAST top-level statement is a
		// map directive, evaluating earlier statements eagerly for
		// their effects (matching the standard "last expression's
		// value is the program's value" rule from parser.v).
		mut map_directive := ?cx.ProgramDirective(none)
		if body is cx.ProgramDirective && body.name == 'map' {
			map_directive = body
		} else if body is cx.ProgramLiteral && body.kind == .block && body.items.len > 0 {
			last := body.items[body.items.len - 1]
			if last is cx.ProgramDirective && last.name == 'map' {
				map_directive = last
			}
		}
		if md := map_directive {
			mut env := new_env()
			if input.len > 0 {
				doc_node := parse_input_doc(input) or {
					return EvalError{
						code:    'cx-err:CXER0100'
						message: 'parse input: ${err.msg()}'
					}
				}
				env.bindings['doc'] = doc_node
				env.bindings['input'] = doc_node
			}
			// Evaluate any earlier sibling top-level expressions for
			// their effects (closure / def registration, mutations).
			// The map directive is the program's value and gets the
			// streaming treatment.
			if body is cx.ProgramLiteral && body.kind == .block {
				for i, sibling in body.items {
					if i == body.items.len - 1 {
						break
					}
					eval_node(sibling, mut env)!
				}
			}
			mut ctx := new_stream_ctx(target, sink)
			if unbuffered {
				ctx.threshold = 1
			}
			eval_map_directive_streamed(md, mut env, mut ctx)!
			ctx.flush()!
			return
		}
	}
	// Fallback: one-shot, single-flush.
	out := eval_code(input, program_src, output_target)!
	sink(out) or {
		return EvalError{
			code:    'cx-err:CXER0001'
			message: 'eval_code_streaming: sink callback failed: ${err.msg()}'
		}
	}
}

// parse_input_doc parses the `$doc` input. The implicit doc-binding
// is the first top-level element from `input` — matching the
// `code_eval_fixtures_test.v` convention. If the input parses
// but contains no element (only text / comments / processing
// instructions), the doc-binding is left unset.
fn parse_input_doc(input string) !cx.Node {
	doc := cx.parse(input) or { return error(err.msg()) }
	for n in doc.elements {
		if n is cx.Element {
			return n
		}
	}
	return error('input document contains no element')
}

