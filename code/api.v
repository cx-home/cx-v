@[has_globals]
// R5.13 latches a top-level err RESULT for the run surface's exit mapping;
// the module already carries globals for the error hooks and effects trace.
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

// RULED R5.13 (register; owner 2026-08-18 "1a") — a top-level err RESULT is a
// FAILING program, and the run surface exits non-zero for it (cli.md §3.x).
//
// Why this needs a channel at all: the rendered result is TEXT by the time the
// CLI sees it, and on the streaming path it is text in chunks, so the shape of
// the result is gone at the exit-code decision point. The evaluator knows it
// and nothing downstream does.
//
// THE DISCRIMINATOR IS POSITION, NOT VALUE — inherited from #853's §6.4.1 rule
// rather than invented here, and it is the whole reason this is not simply
// `is_err_value(result)`. A SOURCE-LITERAL `[err …]` written as the program's
// own top-level form is DATA and exits 0, exactly as it stays data in element
// child position; every other route to an err result — a call, a directive, a
// binding read, a computed-name construction, a propagation from any depth — is
// a failure. Keying on the value alone would make every err-shaped DATA
// document a failing program, which is the same mistake #853 declined.
//
// Single-shot in the CLI, but the flag is RESET at each eval entry rather than
// written once, because the C ABI, the python binding and the playground all
// call the eval entries repeatedly in one process — a sticky flag there would
// report the previous program's failure.
// Declared in the block form WITHOUT an initializer, matching this module's
// existing globals (error_hooks.v, effects_trace.v). A top-level
// `__global x = false` compiled clean but SEGFAULTED
// code_module_umbrella_test.v under the 12-parallel-job `test-vcx-code`
// run while passing in isolation — attributed by stashing this change and
// re-running the target green. V zero-initializes, so `false` is the
// starting value either way, and every eval entry resets it regardless.
__global (
	cx_top_level_err_failure bool
)

// last_result_was_failure reports whether the most recent eval in this process
// produced a top-level err RESULT that R5.13 classifies as a failure. Read it
// AFTER the eval returns successfully — a raised EvalError is already a
// non-zero exit on its own path and does not set this.
pub fn last_result_was_failure() bool {
	return cx_top_level_err_failure
}

// note_top_level_result — the R5.13 classifier — lives in `eval.v`, beside
// `eval_top_level_each`, NOT here. That is its natural home (it classifies an
// eval result against its source form), and it is also REQUIRED: see the
// V-cgen hazard note on the function itself. It is called from BOTH result
// boundaries — the single-form path in eval_code below and the multi-form loop
// in eval_top_level_each — because a program is either shape and the run
// surface must not depend on which.

// eval_code parses `program_src` and `input` (when non-empty),
// evaluates the program against the input, and renders the result per
// `output_target`. Returns the rendered output string or an
// EvalError / cx.ParseError. The `$doc` binding is set when `input` is
// non-empty.
//
// `output_target == ''` is treated as `'text'` (the spec default at
// `spec/audits/code_abi_v1.md §3.1`).
pub fn eval_code(input string, program_src string, output_target string) !string {
	// R5.13 — reset per eval, not per process (see the global's note).
	cx_top_level_err_failure = false
	if program_src.len == 0 {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: 'eval_code: program source must be non-empty'
		}
	}
	// RULED: DGF-1 (#912) — the diagram-target checks below match on the
	// BASE format (everything before a `:`), and the FULL target string
	// passes through to render_diagram, whose parse_diagram_format owns the
	// detail suffix. Before this, `cx diagram F --format=mermaid:full`
	// cleared run_diagram's own base-split capability check and then failed
	// these exact-match lists, falling to the value-conversion path — a
	// refusal of a rung the layer below already implements (of-source, the
	// wasm export and the gates all take the suffixed spelling today).
	diagram_base := output_target.all_before(':')
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
		// RULED: D910-1 (#910) — the diagram targets take the SAME guarded
		// fallback: the ingress primitive lifts the DATA tree (see
		// diagram_program_image_prim), so a pure-data document `cx diagram`
		// used to refuse with a token-level error now renders the same
		// diagram a CX caller of `[$diagram:of-source]` gets. A source BOTH
		// readings refuse keeps the original program error below.
		if !no_data_fallback && input.len == 0
		   && diagram_base in ['mermaid', 'svg', 'png']
		   && !data_reading_has_program_directive(program_src) {
			if _ := cx.parse_cx(program_src) {
				return render_diagram(program_src, output_target)!
			}
		}
		if !no_data_fallback && input.len == 0
		   && diagram_base !in ['mermaid', 'svg', 'png']
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
		// ParseError.msg() already renders 'cx-err:CXER0100: …'; wrapping it
		// verbatim doubled the code in the CLI line ('error: cx-err:CXER0100:
		// parse: cx-err:CXER0100: …' — #880). Strip the inner prefix once.
		mut pmsg := err.msg()
		if pmsg.starts_with('cx-err:CXER0100: ') {
			pmsg = pmsg['cx-err:CXER0100: '.len..]
		}
		return EvalError{
			code:    'cx-err:CXER0100'
			message: 'parse: ${pmsg}'
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
	if diagram_base in ['mermaid', 'svg', 'png'] {
		return render_diagram(program_src, output_target)!
	}
	mut env := new_env()
	// The two top-level-return contracts, in the order their strengths
	// demand — the defer covers every exit edge (value, err).
	//
	// Futures FIRST and JOINED: §10.5.1 guarantees a fire-and-forget body
	// runs to a terminal state before top-level program return. Cancelling
	// them would break the case the spec names by name.
	// Workers second and CANCEL-and-drained: EV-WORKER-EXIT (code.md §14.4,
	// stream 22 W4) rules that weaker contract deliberately.
	defer {
		env.state.drain_futures_at_exit()
		env.state.drain_workers_at_exit()
	}
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
			mut results, forms := eval_top_level_each(prog.body.items, mut env)!
			// EV-PULL (stream 17 W1): the program-result boundary is
			// where laziness ends — force with the env still alive
			// (err-terminal iterators unwrap to their bare §9.2 err).
			for i in 0 .. results.len {
				results[i] = force_lazy_result(results[i], mut env)
				// R5.13 — classify each result against its OWN form, after
				// forcing. ANY failing top-level form fails the program: a
				// multi-form document that refuses halfway has refused.
				note_top_level_result(results[i], forms[i])
			}
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
	mut result := eval(prog.body, mut env)!
	// EV-PULL (stream 17 W1): force at the result boundary (env alive).
	result = force_lazy_result(result, mut env)
	// R5.13 — classify AFTER forcing: an err-terminal iterator unwraps to its
	// bare §9.2 err here, so checking before the force would miss exactly the
	// lazy shapes stream 17 introduced.
	note_top_level_result(result, prog.body)
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

// CXStreamMode names which path eval_code_streaming takes for a given
// (program, target) pair — see eval_code_stream_mode (#821).
pub enum CXStreamMode {
	for_comp      // top-level [?for] comprehension — streamed per yield
	map_directive // top-level (or block-tail) [?map] — streamed per item
	buffered      // no streaming path applies: one-shot, single flush
}

// stream_map_directive extracts the [?map] that the streaming path
// would drive: the whole body, or the LAST statement of a block body
// (the "last expression is the program's value" rule).
fn stream_map_directive(body cx.ProgramNode) ?cx.ProgramDirective {
	// PS-1: a STEPPED [?map] (`[?map …]/x`) is a READ over the whole
	// result — never streamable; decline so the one-shot path applies
	// the step run.
	if body is cx.ProgramDirective && body.name == 'map' && body.path.len == 0 {
		return body
	}
	if body is cx.ProgramLiteral && body.kind == .block && body.items.len > 0 {
		last := body.items[body.items.len - 1]
		if last is cx.ProgramDirective && last.name == 'map' && last.path.len == 0 {
			return last
		}
	}
	return none
}

// stream_mode_of is THE authority on whether streaming engages. Both
// eval_code_streaming_opts (which takes the path) and
// eval_code_streamable (which answers the question) read it, so a
// caller's answer can never drift from the path actually taken — the
// two-spellings class that bit the def-registration sites (#780).
//
// `target` must already be defaulted ('' → 'text').
fn stream_mode_of(body cx.ProgramNode, target string) CXStreamMode {
	if target != 'text' && target != 'cx' {
		return .buffered
	}
	// Array/map yield or outer forms wrap the WHOLE result (`[…]` /
	// `{…}`); the streamed renderer writes items and (since #823) a
	// sequence wrapper — nothing else. Claiming these shapes emitted
	// per-item lines where the one-shot answer is the wrapped
	// collection (profile-gate [bin]: program-for-yield-map-001-basic,
	// program-for-array-outer-001-preserves). Decline them honestly.
	// PS-1: a STEPPED for-comp (`[?for …]/x`) is a READ over the
	// materialized result — decline streaming so eval_for_comp applies
	// the step run on the one-shot path.
	if body is cx.ProgramForComp && for_comp_streamable(body.clauses)
		&& body.yield_form == .sequence && body.outer_form == .sequence
		&& body.path.len == 0 {
		return .for_comp
	}
	// [?map] streams again (#823). It was excluded while its streamed path
	// emitted `[?for]`-style items (`1\n4\n9\n16`) for a program whose
	// one-shot answer is the sequence literal `(1, 4, 9, 16)` — different
	// bytes for the same program, which breaks the contract this surface
	// rests on. The StreamCtx now carries the result's SHAPE, so the
	// sequence wrapper is written by the streaming renderer itself
	// (StreamShape.sequence) and the two paths agree byte for byte. The
	// exclusion's cost went with it: incremental delivery is back,
	// `map-streamed` in par_eval.v is live again, and a 10 MB pass-through
	// no longer buffers the whole result (the #822 memory profile).
	if _ := stream_map_directive(body) {
		return .map_directive
	}
	return .buffered
}

// eval_code_stream_mode reports which path eval_code_streaming WILL
// take for this (program, target), without evaluating anything (#821).
//
// The streaming surface silently falls back to full materialization for
// every shape it cannot stream — correct output, but the whole result
// buffered in memory, which is exactly what a caller reaching for the
// streaming API is trying to avoid. A caller handing over a large input
// can ask FIRST and choose a different program or target instead of
// discovering the cost after paying it.
//
// A program that does not parse reports `.buffered`: the streaming call
// would surface the parse error on the one-shot path.
pub fn eval_code_stream_mode(program_src string, output_target string) CXStreamMode {
	target := if output_target == '' { 'text' } else { output_target }
	if target != 'text' && target != 'cx' {
		return .buffered
	}
	prog := cx.parse_program(program_src) or { return .buffered }
	return stream_mode_of(prog.body, target)
}

// eval_code_streamable is the boolean form of eval_code_stream_mode:
// true when the output will actually be delivered incrementally.
pub fn eval_code_streamable(program_src string, output_target string) bool {
	return eval_code_stream_mode(program_src, output_target) != .buffered
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
	// The guards below consult stream_mode_of — the same authority
	// eval_code_stream_mode answers callers with (#821), so the mode a
	// caller is told can never disagree with the path taken here.
	if target == 'text' || target == 'cx' {
		// A program that does not PARSE falls through to the one-shot
		// path rather than erroring here (#822). That path owns the §1.3
		// data-fallback — "a pure-data resource evaluates to itself" —
		// so prose and markup that the program reader cannot lex still
		// evaluate to their data reading.
		//
		// Erroring here broke this function's own byte-equivalence
		// contract: eval_code returned the data reading while
		// eval_code_streaming returned CXER0100 for the same input. It
		// also disagreed with eval_code_stream_mode, which already
		// reports `.buffered` for an unparseable program. Found by
		// routing the CLI through this call — the run surface depends on
		// the fallback for every prose document.
		if prog := cx.parse_program(program_src) {
				body := prog.body
				mode := stream_mode_of(body, target)
			if mode == .for_comp && body is cx.ProgramForComp {
				mut env := new_env()
				defer {
					env.state.drain_futures_at_exit()
					env.state.drain_workers_at_exit()
				}
				// The streamed-INPUT fast path (§11.6 gate-15; stream 17 W5):
				// for the canonical `[?for [in $u $doc/user] [yield $u]]`
				// shape over a safe input, pull top-level children one at a
				// time instead of materializing the whole document. Declines
				// (pre-emission, losslessly) fall through to the materializing
				// path below — see code/streamed_input.v for the posture.
				if input.len > 0 {
					if plan := streamed_input_plan(body, program_src) {
						if streamed_input_safe(input) {
							mut sctx := new_stream_ctx(target, sink)
							if unbuffered {
								sctx.threshold = 1
							}
							finished := eval_for_comp_streamed_input(body, plan, input, mut env, mut sctx) or {
								// §9.2 / #348(a): err-valued guard → the err value
								// becomes the stream's remaining output (the same
								// unwind the materializing arm performs below).
								if err is EvalError && err.code == err_guard_passthrough_code
									&& err.cause_set {
									sctx.emit_node(err.cause)!
									sctx.finish()!
									return
								}
								return err
							}
							if finished {
								sctx.finish()!
								return
							}
						}
					}
				}
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
						ctx.finish()!
						return
					}
					return err
				}
				ctx.finish()!
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
			// Gated on the MODE, not just on the shape, so the dispatch and
			// the predicate can never disagree about which path a program
			// takes — the two-spellings drift this whole authority exists to
			// prevent.
			if mode == .map_directive {
				if md := stream_map_directive(body) {
					mut env := new_env()
					defer {
						env.state.drain_futures_at_exit()
						env.state.drain_workers_at_exit()
					}
					// The streamed-INPUT fast path for the map shape (#845).
					// `[?map $doc/user [using …]]` is the same access shape as
					// `[?for [in $u $doc/user] …]`, so it qualifies under the
					// same preconditions and declines (pre-emission, losslessly)
					// to the materializing path below. Without this the source
					// expression materialized the whole document while the
					// results streamed — a growing live set that decayed
					// 2.0 → 0.8 MB/s within a single process and failed the
					// §11.4.4 jitter clamp for a different reason than #804's.
					// ONLY when the [?map] IS the whole program body. A BLOCK body's
					// earlier siblings are evaluated for their effects (def /
					// closure registration, mutations) BELOW this point, so a fast
					// path taken here would resolve `:using` against an
					// environment those siblings had not populated yet —
					// measured: `[?def bump …] [?map … [using [?fn ($u) [$bump
					// $u]]]]` yielded three `no callable "bump"` errs instead of
					// three `[bumped …]`. Hoisting the sibling loop above the fast
					// path is NOT the fix either: a walk that then DECLINES would
					// leave the materializing path to run those effects a second
					// time, and a mutation is not idempotent. So the lane declines
					// the shape outright — it is the conservative direction, and
					// the shape gate 15 measures is a bare [?map].
					if input.len > 0 && body is cx.ProgramDirective {
						if plan := streamed_map_plan(md, program_src, mut env) {
							if streamed_input_safe(input) {
								mut sctx := new_stream_ctx(target, sink)
								sctx.shape = .sequence
								if unbuffered {
									sctx.threshold = 1
								}
								finished := eval_map_directive_streamed_input(md, plan,
									input, mut env, mut sctx)!
								if finished {
									sctx.finish()!
									return
								}
							}
						}
					}
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
					// A [?map] result is an iterator, which renders as a
					// SEQUENCE LITERAL one-shot — so the streaming renderer
					// writes that container too (#823).
					ctx.shape = .sequence
					if unbuffered {
						ctx.threshold = 1
					}
					eval_map_directive_streamed(md, mut env, mut ctx)!
					ctx.finish()!
					return
				}
			}
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
	// ANC-1: `$doc` is the SEMANTIC reading — resolve aliases/merges before
	// binding, so CXPath over the input agrees with strict canonical (an
	// alias child counts as its referent, a merge host carries its
	// inherited attrs/items).
	parsed := cx.parse(input) or { return error(err.msg()) }
	doc := cx.resolve_document(parsed) or { return error(err.msg()) }
	for n in doc.elements {
		if n is cx.Element {
			return n
		}
	}
	return error('input document contains no element')
}

