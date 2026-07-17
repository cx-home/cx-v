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
		// Three failure classes are unambiguous PROGRAM intent and MUST stay
		// fail-loud (never silently re-read as data): an unknown/retired `[?name]`
		// directive; a syntax error after the parser committed to a program
		// construct — e.g. infix `=` inside a `[where …]` clause (#18), where the
		// data-fallback would echo the source as data and bury the helpful "use
		// the prefix form" diagnostic; and a resource whose DATA reading carries a
		// registered `[?directive]` — a program-SHAPED resource whose program
		// parse failed for any other reason (e.g. a lexer error the flags above
		// never see, because tokenize() fails before the parser runs). Without
		// the third guard a broken `[?let]`/`[?for]` program silently echoed
		// itself as data with exit 0 — in a make target or CI that reads as
		// success. The data-reading scan is string-aware by construction: a
		// directive mentioned inside quoted prose parses as text, not as a
		// directive node, so prose ABOUT directives still falls back.
		no_data_fallback := if err is cx.ParseError {
			err.unknown_directive || err.program_committed
		} else {
			false
		}
		if !no_data_fallback && input.len == 0
		   && output_target !in ['mermaid', 'svg', 'png']
		   && !data_reading_has_program_directive(program_src) {
			to_codec := if output_target in ['', 'text'] { 'cx' } else { output_target }
			// Split parse from emit (#416): when the resource IS valid data
			// but the TARGET rejects it (e.g. csv of a non-tabular
			// document), the emit diagnostic is the real error — before
			// this, the fallback swallowed it and surfaced the unrelated
			// program-parse error instead.
			if _ := cx.parse_cx(program_src) {
				out := cx.convert_by_name(program_src, 'cx', to_codec, false) or {
					return EvalError{
						code:    'cx-err:CXER0100'
						message: err.msg()
					}
				}
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

// data_reading_has_program_directive reports whether the DATA reading of
// `src` carries a registered program directive — a node the data parser
// classified as an eval directive (`[?let]`, `[?for]`, `[?def]`, …) or a
// processing instruction whose target is in the program directive registry
// (`cx.directive_names`). The eval boundary's data-fallback consults this: a
// resource whose data reading carries program directives is program-SHAPED,
// so a program-parse failure must surface loud (spec code.md, the data /
// program reading) instead of silently echoing the source back as data.
//
// String-aware by construction — a directive mentioned inside quoted prose
// parses as text content, not as a directive node, so documentation ABOUT
// directives keeps the prose fallback. `[?cx …]` config directives and
// foreign PIs (e.g. `[?xml-stylesheet …]` from an XML ingest) are NOT
// program directives and do not suppress the fallback.
fn data_reading_has_program_directive(src string) bool {
	doc := cx.parse(src) or { return false }
	for n in doc.prolog {
		if node_carries_program_directive(n) {
			return true
		}
	}
	for n in doc.elements {
		if node_carries_program_directive(n) {
			return true
		}
	}
	return false
}

fn node_carries_program_directive(n cx.Node) bool {
	match n {
		cx.EvalDirectiveNode {
			if n.name in cx.directive_names {
				return true
			}
			for c in n.items {
				if node_carries_program_directive(c) {
					return true
				}
			}
		}
		cx.PINode {
			return n.target in cx.directive_names
		}
		cx.Element {
			for c in n.items {
				if node_carries_program_directive(c) {
					return true
				}
			}
		}
		cx.CXDirectiveNode {
			for c in n.items {
				if node_carries_program_directive(c) {
					return true
				}
			}
		}
		cx.DocumentNode {
			for c in n.elements {
				if node_carries_program_directive(c) {
					return true
				}
			}
		}
		else {}
	}
	return false
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
			eval_for_comp_streamed(body, mut env, mut ctx) or {
				// §9.2 / #348(a): an err-valued [?for] guard unwinds as the
				// internal passthrough; in the streaming mode the err value
				// becomes the stream's (remaining) output — the closest
				// streaming analog of "the err is the form's result".
				if err is EvalError && err.code == err_guard_passthrough_code
				   && err.cause_set {
					ctx.emit_node(err.cause)!
					ctx.flush()!
					return
				}
				return err
			}
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

