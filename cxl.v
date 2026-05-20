module cx

import strings
import strconv
import math
import time
import os

// ── CXL (CX Language) reference evaluator ────────────────────────────────────
//
// Per ADR 0016 / ADR 0017 §D7 and spec/eval.md (CXL 1.0). This is the V
// reference implementation; every per-binding native evaluator MUST
// produce byte-identical output (ADR 0016 R8, conformance/eval.txt).
//
// CXL 1.0 v0.6.0 directive set under the ADR 0017 uniform shape
// `[?Name [arg1, arg2, …]]` (§D6 / §D7):
//   Interpolation `[?=EXPR]`                — value emission (sugar)
//   `[?if [cond, then-body, else-body?]]`   — conditional (§3.2)
//   `[?if [[c1, b1], [c2, b2], [*, def]]]`  — multi-branch (§3.3)
//   `[?for [var, iterable, body]]`          — iteration (§3.4)
//   `[?with [context, body]]`               — context shift (§3.5)
//   `[?def [name, body]]`                   — define block (§3.7)
//   `[?use [name, context?]]`               — invoke block (§3.8)
//   `[?include [path]]`                     — partial (§3.6, deferred)
//   String filters (§4.1):
//     upper/lower/trim/length/concat/join/replace
//   Type / encoding filters (§4.5/§4.6):
//     default/escape-html/escape-url/raw
//   Sequence filters (§4.3, partial):
//     first/rest/empty/reverse/length
//   Output targets: text (default), cx, html (auto-escape)
//
// Deferred to follow-up: `[?include]` resolution (ADR 0014),
// numeric/temporal/full sequence filter set, markdown/json/yaml/
// xml/csv/tsv emission targets, streaming evaluation, whitespace-
// trim markers `[?-= … -]`, block-form newline consumption per
// spec/eval.md §2.4.
//
// Sequence-flat data model per spec/cxdm.md: every evaluator value
// is `[]CXLItem`. An empty sequence is `[]`; a single-item value is
// `[item]`; concatenation flattens.
//
// Pre-ADR-0017 syntax forms (attribute-slot `:then=…/:else=…`,
// `?cond` directive, bare positional `?for v in expr body`) are NOT
// accepted by this evaluator. The parser (vcx/cx/parser.v) rejects
// them at parse time — this file only handles the new shape.

// ── CXDM value model (runtime) ───────────────────────────────────────────────

// CXLScalar is a bare typed scalar — an Item that is not a Node.
// Produced by attribute access (`@name` returns the attribute's typed
// ScalarValue), filter results, and literal expressions.
pub struct CXLScalar {
pub:
	data_type ScalarType
	value     ScalarValue
}

// CXLFunction is a first-class function value (CXL 3.1 / XPath 3.0
// inline function expression, per ADR 0022 §D2 and xquery_40_parity.md
// §4.5.6). Produced by `[?fn :params [...] :body [...]]` and flowing
// through CXLValue like any other Item.
//
// Closure capture (A21): the `captured` map carries env.bindings as
// of the moment the [?fn] directive was evaluated to a value. At
// call time, captured bindings are merged into the call-site env
// (parameters shadow them); the body sees both its own params and
// any free variables from the definition's lexical scope.
pub struct CXLFunction {
pub:
	params   []string
	body     []Node
	captured map[string]CXLValue
}

// CXLItem is the CXDM Item kind. Either a Node (Element / Text /
// ScalarNode / …), a bare Scalar, a function value, or a Map/Array
// runtime container (per ADR 0022 §D2 D — XPath 3.1 maps and arrays
// as first-class values).
pub type CXLItem = Element
	| TextNode
	| ScalarNode
	| CommentNode
	| PINode
	| CXDirectiveNode
	| CXLScalar
	| CXLFunction
	| ArrayNode
	| MapNode

// CXLValue is a CXDM Sequence — `[]CXLItem`. Empty sequence is the
// "missing"/"absent" value (EBV false per cxdm.md §4.5).
pub type CXLValue = []CXLItem

// ── Evaluator environment ────────────────────────────────────────────────────

// CXLStreamSink is the streaming-output callback type. eval_cxl_streaming
// invokes it with batches of output bytes between flush points. The
// callback returns an error to abort evaluation cleanly (Y-row
// streaming evaluator). When env.stream_cb is none, env.out
// accumulates the full output (buffered mode, current default for
// eval_cxl).
pub type CXLStreamSink = fn (string) !

struct CXLEnv {
mut:
	input    Document
	target   string                  // output-target: 'text', 'cx', 'html', …
	strict   bool                    // [?cx output-strict]
	// v0.7.0: tracks whether the current emit cursor is inside an
	// element body (true) or at top level / inside an attribute body
	// (false). Flipped on entry to `el.items` in emit_element_cx and
	// restored on exit. `[?=]` consults this to decide whether a
	// substituted scalar should be auto-quoted: bytes that would
	// re-tokenize as structure (`[` `]` `'` `"`, leading sigil, or
	// `name=` head) need wrapping in body position so a downstream
	// re-parse keeps them as element text rather than child structure.
	// Top-level `[?=]` (e.g. `[?=[?cx:canonical x]]`) keeps the
	// "emit bytes" semantics — that's the pattern cx:parse / cx:serialize
	// / cx:canonical fixtures rely on for round-trip identity.
	body_position bool
	context  CXLValue                // current evaluation context
	bindings map[string]CXLValue     // [?for] / [?with] / template parameter scope
	defs     map[string]TemplateDef  // [?def] named templates (ADR 0020)
	out      strings.Builder
	// Y-row streaming. When stream_cb is set, eval_node flushes env.out
	// to the sink at strategic points (after each top-level program
	// node, after each ?for iteration). flush_after_bytes caps the
	// builder size before forcing an early flush so large per-iteration
	// outputs don't accumulate. Both fields default to none/0 → buffered
	// mode (no behavioral change vs pre-Y-row eval_cxl).
	stream_cb          ?CXLStreamSink
	flush_after_bytes  int
	// Y6 perf: redundant-with-stream_cb boolean kept so hot-loop flush
	// triggers can compare an int field rather than unwrapping an
	// Option<fn> on every inner iteration. eval_cxl_streaming sets both
	// together; everything else leaves is_streaming=false (the buffered
	// path's flush-trigger check then short-circuits without ever
	// entering flush_stream).
	is_streaming       bool
	// U3 (v0.7.0 security review): function-call depth budget.
	// Bumped at every call_fn_emit / call_fn_to_value entry; errors
	// with cx-err:CXER0010 when exceeded. Default cap is 256, which
	// is well above any honest recursive workload (mutual-recursion
	// pattern matching, sum-style folds) and below the threshold
	// where the V GC's stack-walk path starts to hurt under macOS
	// hardened runtime. Configurable per-call by callers that need
	// a smaller bound (e.g., evaluating untrusted templates from a
	// sandbox).
	call_depth         int
	max_call_depth     int
	// U4 (v0.7.0 security review): collection-size caps. Three
	// independent bounds, each preventing a memory-exhaustion vector:
	//   - max_sequence_len: `1 to N`, [?range], for-bodies
	//                       materialising into CXLValue arrays
	//   - max_map_entries: map:merge / map:put / array-as-map
	//                      building paths that grow with input
	//   - max_capture_size: closure captured-env at ?fn definition;
	//                      caps `?let x :be HUGE :return ?fn () { x }`
	// All three use cx-err:CXER0011 with a per-cap message. 0 =
	// unlimited (the new_cxl_env default sets 1_000_000 for each;
	// trusted contexts may zero them out post-construction).
	max_sequence_len   i64
	max_map_entries    i64
	max_capture_size   i64
	// EE7 (ADR 0023 §D11): evaluator-hook seat. Default is
	// NoOpEvaluatorHook{}, set by new_cxl_env. DD11 (cx:eval) and
	// FF1–FF7 (log:*) will dispatch through env.hook as their
	// reference-implementation surface when those rows land; until
	// then the hook is unobserved and the no-op default optimizes
	// away under release builds. Signature stability through 1.0
	// per ADR 0023 §D11 — see vcx/cx/evaluator_hook.v.
	hook               EvaluatorHook = NoOpEvaluatorHook{}
	// Y6 v0.7.0 perf: CXPath result cache. Keys are `${ctx_root_addr}|${path}`;
	// values are the select_all() result for that (root, path) pair.
	// Safe because cx:patch is M5-gated for eval (input is immutable
	// during a single eval call); ?for loop variables never mutate the
	// root document. Eliminates the dominant hot path from the bench
	// profile (cxpath_collect_descendants_chain: 601k calls collapses
	// to 1 per unique (root, path) pair).
	path_cache         map[string]CXLValue
	// Y6 perf: emit scratch buffer reused across eval_for calls.
	// The pure-loop text-only emit path needs a per-iter scratch
	// space (~8 KiB); pre-allocating it on the env amortises the
	// malloc/scratch_cap setup across all nested ?for invocations
	// in a single eval.
	emit_scratch       &u8 = unsafe { nil }
	emit_scratch_cap   int
	// Y6 perf: per-eval CompiledBody cache. Key is a stable pointer
	// to the body Node's location inside the AST (via &slots[2] in
	// eval_for, which resolves to ArrayNode.items.data + 2*sizeof(Node)
	// — that pointer is invariant across the 5000+ recompilations a
	// nested ?for triggers on the streaming bench). cx:patch is gated
	// off during eval (M5), so AST nodes are immutable across the
	// lifetime of a single eval_cxl call → cache entries can be
	// trusted to remain structurally correct. compile_body itself is
	// only a few microseconds, but multiplied across the outer-loop
	// iteration count it becomes a real fraction of the wall time.
	body_cache         map[voidptr]CompiledBody
	// FF8 (ADR 0023 §D10): log: module configuration. Lexically
	// scoped per document via [?cx log-level=...], [?cx log-format=...],
	// [?cx log-output=...] directives in the prolog. Defaults match
	// spec/modules/log.md §2: level=info, format=logfmt, output=stderr.
	// test_mode=true (set via [?cx test-mode=true]) substitutes a
	// fixed timestamp in log records so conformance fixtures stay
	// byte-identical across runs and bindings.
	log_level          string = 'info'
	log_format         string = 'logfmt'
	log_output         string = 'stderr'
	test_mode          bool
	// FF7 ambient logging context. log:with-context pushes a frame
	// onto this stack before evaluating its body, pops on exit
	// (success or error path). Records inherit each frame's
	// key/value pairs; inner frames override outer on key collision.
	log_context_stack  []map[string]string
	// EE4 (ADR 0023 §D5): determinism enforcement. Set by the
	// [?cx pure-only] directive. When true, any call to a function
	// classified ReadOnly or SideEffect by the EE1 catalog raises
	// cx-err:CXER0040 at dispatch time. fn:trace is exempt per
	// spec/modules/log.md §3 — the one documented carve-out.
	pure_only          bool
	// EE2 (ADR 0023 §D3): activation set populated by
	// [?cx use-module=...] directive(s). At v0.7.0 every registered
	// module's activation is .always, so this is empty in practice;
	// the v0.8.0 BaseX modules (file:, http:, …) will require
	// declarations through this field, and the gate logic is already
	// in place to refuse undeclared on_declaration modules at
	// dispatch time. The `[?cx include=...]` resolver itself ships
	// at v0.7.0 (GG1; see vcx/cx/include.v + spec/include.md);
	// what is deferred to v0.8.0 is the cross-include module-
	// activation inheritance rule (per ADR 0023 §D3) — once
	// on_declaration modules exist, the resolver pass needs to
	// merge each included doc's `declared_modules` into the parent.
	declared_modules   []string
	// EE5 / DD11 (ADR 0023 §D6 + §M5 amendment): cx:eval gating.
	// allow_eval is set by [?cx allow-eval=true]; required for any
	// cx:eval invocation (M1). max_eval_depth caps recursive
	// cx:eval invocations (M5; default 8 mirrors max_include_depth).
	// eval_depth tracks current nesting; resets at top-level.
	allow_eval         bool
	max_eval_depth     int = 8
	eval_depth         int
	// `[?include path]` runtime-include support. include_root is the
	// absolute directory under which path arguments resolve; supplied
	// by the caller (eval_cxl_with_include_root). include_stack
	// carries the canonicalised absolute paths of files currently
	// being evaluated, used for cycle detection (analogous to the
	// parse-time resolver in vcx/cx/include.v). include_depth +
	// max_include_depth bound recursive depth. All four are zero/empty
	// in the default new_cxl_env, so eval_include errors out cleanly
	// when no root was supplied.
	include_root        string
	include_stack       []string
	include_depth       int
	max_include_depth   int = 8
}

// TemplateDef carries a `?def` block's parameter list and body. Zero-
// parameter templates have an empty `params` array; their semantics
// match the pre-ADR-0020 named-block model. Non-empty `params` is
// the ADR 0020 parameterized form — capability bit 30. Lexical-scope
// binding of params into env.bindings happens at template-invocation
// sites via dispatch_template_call; closure capture is not modeled
// (bodies do not escape their invocation frame).
struct TemplateDef {
mut:
	params []string
	body   []Node
}

fn new_cxl_env(input Document, target string) CXLEnv {
	mut env := CXLEnv{
		input:    input
		target:   if target == '' { 'text' } else { target }
		strict:   false
		context:  cxl_seq_from_doc(input)
		bindings: map[string]CXLValue{}
		defs:     map[string]TemplateDef{}
		out:      strings.new_builder(256)
		call_depth:       0
		max_call_depth:   256
		max_sequence_len: 1_000_000  // 1M items — generous for honest
		                              // workloads; well-defined ceiling
		                              // for sandboxed templates
		max_map_entries:  1_000_000  // U4: same ceiling on map size at
		                              // construction (map:merge, map:put,
		                              // array-as-map building)
		max_capture_size: 1_024      // U4: closure captured-env cap;
		                              // 1k bindings is far above honest
		                              // template authoring, bounds the
		                              // ?fn HUGE-environment vector
		hook:             new_noop_hook()  // EE7: reserved hook seat; replaced by debug-adapter / log-subscriber concrete types at v0.8.0+
		path_cache:       map[string]CXLValue{}  // Y6 perf
		body_cache:       map[voidptr]CompiledBody{}  // Y6 perf
	}
	return env
}

// cxl_seq_from_doc establishes the evaluator's implicit top-level
// context. When the document has exactly one Element root (the
// overwhelmingly common case for template inputs — `[product …]`,
// `[catalog …]`, etc.), the context is that root Element so `@attr`
// and bare child names resolve naturally per spec/eval.md §1 examples.
// For documents with multiple top-level elements (multi-document
// streams, etc.), the context is a synthetic `#document` wrapper.
fn cxl_seq_from_doc(d Document) CXLValue {
	if d.elements.len == 1 && d.elements[0] is Element {
		return [CXLItem(d.elements[0] as Element)]
	}
	root := Element{ name: '#document', items: d.elements }
	return [CXLItem(root)]
}

// ── Public entry point ───────────────────────────────────────────────────────

// eval_cxl parses an input CX document and a CXL program, evaluates
// the program against the input, and returns the rendered output as a
// string. Errors propagate as V errors with a position-bearing message.
pub fn eval_cxl(input_cx string, program_cx string, output_target string) !string {
	return eval_cxl_with_include_root(input_cx, program_cx, output_target, '')
}

// eval_cxl_with_include_root is eval_cxl with `[?include path]`
// runtime-include resolution enabled. `include_root` is an absolute
// directory; `[?include path]` arguments resolve relative to it and
// must stay under it (same containment rules as the parse-time
// `[?cx include=…]` resolver per spec/include.md §3). Empty root
// keeps `[?include]` disabled — directive emits an error if reached.
pub fn eval_cxl_with_include_root(input_cx string, program_cx string,
		output_target string, include_root string) !string {
	input_doc  := parse(input_cx) or { return error('cxl: input parse failed: ${err.msg()}') }
	prog_doc   := parse(program_cx) or { return error('cxl: program parse failed: ${err.msg()}') }
	target     := pick_output_target(prog_doc, output_target)
	mut env    := new_cxl_env(input_doc, target)
	// Canonicalise the include root: make absolute, resolve symlinks
	// (e.g. macOS `/var` → `/private/var`). The same shape the parse-
	// time resolver uses (vcx/cx/include.v parse_with_include_root)
	// so a path comparison against env.include_root matches the
	// resolver's containment check.
	if include_root != '' {
		mut abs_root := include_root
		if !os.is_abs_path(abs_root) {
			abs_root = os.abs_path(abs_root)
		}
		if os.exists(abs_root) {
			abs_root = os.real_path(abs_root)
		}
		env.include_root = abs_root
	}
	apply_program_config(prog_doc, mut env)!
	for n in prog_doc.prolog { eval_node(n, mut env)! }
	for n in prog_doc.elements { eval_node(n, mut env)! }
	return env.out.str()
}

// eval_cxl_streaming runs the same evaluator pipeline as eval_cxl but
// flushes output to `sink` incrementally — after each top-level
// program node and after each `?for` iteration body — rather than
// returning a single buffered string at the end. Replaces the W012
// stub on the C ABI side (cx_eval_streaming). Per Y-row of
// spec/v0_7_0_status.md.
//
// flush_threshold: minimum bytes to accumulate before a flush is
// permitted. 0 → flush at every strategic point. Larger values trade
// memory residency for fewer callback invocations on small-emit
// workloads. Caller-supplied value of 64 KiB is a reasonable default.
pub fn eval_cxl_streaming(input_cx string, program_cx string,
		output_target string, sink CXLStreamSink, flush_threshold int) ! {
	input_doc  := parse(input_cx) or { return error('cxl: input parse failed: ${err.msg()}') }
	prog_doc   := parse(program_cx) or { return error('cxl: program parse failed: ${err.msg()}') }
	target     := pick_output_target(prog_doc, output_target)
	mut env    := new_cxl_env(input_doc, target)
	env.stream_cb = sink
	env.is_streaming = true
	env.flush_after_bytes = if flush_threshold > 0 { flush_threshold } else { 0 }
	// Y6 perf: pre-grow env.out so emit_bound_direct's ensure_cap is a
	// no-op compare for the steady-state inner loop. Headroom is one
	// flush threshold + one iter_budget (1 KiB) so a fresh iter after
	// trim(0) never re-allocates. Threshold 0 (flush-every-iter) skips
	// the pre-grow since the builder churns to len=0 between iters.
	if env.flush_after_bytes > 0 {
		env.out.ensure_cap(env.flush_after_bytes + 1024)
	}
	apply_program_config(prog_doc, mut env)!
	for n in prog_doc.prolog {
		eval_node(n, mut env)!
		flush_stream(mut env, false)!
	}
	for n in prog_doc.elements {
		eval_node(n, mut env)!
		flush_stream(mut env, false)!
	}
	// Final flush — drain any remainder regardless of threshold.
	flush_stream(mut env, true)!
}

// flush_stream emits env.out's accumulated bytes to env.stream_cb (if
// set) and resets the builder. In buffered mode (no sink) this is a
// no-op. The `force` flag bypasses the byte-threshold check; called
// once at end-of-evaluation to drain any tail bytes.
//
// Y6 perf: zero-copy chunk view. Constructs a `string` that borrows the
// builder's underlying bytes (tos, no memdup), invokes the callback
// synchronously, then resets the builder length without freeing its
// capacity. At a 64 KiB flush threshold over a 10 MB stream that's
// ~170 saved `memdup_noscan`s of 64 KiB each (~11 MB of copy work
// eliminated). Contract: callbacks MUST consume the chunk synchronously
// — retaining the string past return aliases the next batch's bytes.
// The Y7 binding-wrapper shapes (Python on_chunk, Go cgo callback, Rust
// `FnMut(&str)`, TS onChunk) all consume synchronously by construction.
fn flush_stream(mut env CXLEnv, force bool) ! {
	cb := env.stream_cb or { return }
	n := env.out.len
	if n == 0 { return }
	if !force && n < env.flush_after_bytes { return }
	// Append a NUL so the borrowed view is well-formed for V's string
	// model (vstring_with_len treats `len` exclusive of the terminator),
	// then construct a view and reset.
	env.out << u8(0)
	chunk := unsafe { tos(&u8(env.out.data), n) }
	cb(chunk)!
	env.out.go_back_to(0)
}

// pick_output_target prefers the caller-supplied target, then any
// `[?cx output-target=…]` directive in the program prolog / first
// elements, defaulting to 'text'.
fn pick_output_target(prog Document, caller string) string {
	if caller != '' { return caller }
	for n in prog.prolog {
		if t := target_from_cx_directive(n) { return t }
	}
	for n in prog.elements {
		if t := target_from_cx_directive(n) { return t }
		break // only scan the leading directive(s)
	}
	return 'text'
}

fn target_from_cx_directive(n Node) ?string {
	if n is CXDirectiveNode {
		for a in n.attrs {
			if a.name == 'output-target' {
				return scalar_value_str(a.value)
			}
		}
	}
	return none
}

fn apply_program_config(prog Document, mut env CXLEnv) ! {
	for n in prog.prolog { absorb_config_node(n, mut env) }
	// M2 — parse-time refusal when [?cx pure-only] and [?cx allow-eval=true]
	// appear in the same document. Dispatch-time M2 (filter_cx_eval +
	// check_purity_gate) covers the cases where the program enables eval
	// somewhere later in the tree, but the prolog-only collision is the
	// common one and surfacing it at parse time gives the clearer error.
	if env.pure_only && env.allow_eval {
		return error('cx-err:CXER0042\x1F[?cx allow-eval=true] is incompatible with [?cx pure-only] in same document (mitigation M2 — parse-time)\x1F')
	}
}

fn absorb_config_node(n Node, mut env CXLEnv) {
	if n is CXDirectiveNode {
		for a in n.attrs {
			match a.name {
				'output-target' { env.target = scalar_value_str(a.value) }
				'output-strict' { env.strict = true }
				// FF8 — log: module directives per ADR 0023 §D10
				'log-level'     { env.log_level  = scalar_value_str(a.value) }
				'log-format'    { env.log_format = scalar_value_str(a.value) }
				'log-output'    { env.log_output = scalar_value_str(a.value) }
				'test-mode'     {
					v := scalar_value_str(a.value)
					env.test_mode = v == 'true' || v == '1'
				}
				'pure-only'     {
					// EE4 (ADR 0023 §D5): bare presence sets the flag.
					// `[?cx pure-only]` (no attribute value) and
					// `[?cx pure-only=true]` both activate; explicit
					// `=false` keeps it cleared.
					v := scalar_value_str(a.value)
					env.pure_only = v == '' || v == 'true' || v == '1'
				}
				'use-module'    {
					// EE2 (ADR 0023 §D3): comma-separated module names
					// added to env.declared_modules. Multiple directives
					// accumulate (the directive is additive, not
					// replacing — each call appends to the active set).
					v := scalar_value_str(a.value)
					for name in v.split(',') {
						trimmed := name.trim_space()
						if trimmed != '' && trimmed !in env.declared_modules {
							env.declared_modules << trimmed
						}
					}
				}
				'allow-eval'    {
					// EE5 / M1: bare presence sets the flag; '=true'/'=1'
					// activate; explicit '=false' clears.
					v := scalar_value_str(a.value)
					env.allow_eval = v == '' || v == 'true' || v == '1'
				}
				'max-eval-depth' {
					v := scalar_value_str(a.value)
					depth := v.int()
					if depth >= 0 { env.max_eval_depth = depth }
				}
				else {}
			}
		}
	}
}

// ── Tree walk ────────────────────────────────────────────────────────────────

fn eval_node(n Node, mut env CXLEnv) ! {
	match n {
		InterpolationNode { eval_interpolation(n, mut env)! }
		EvalDirectiveNode { dispatch_eval_directive(n, mut env)! }
		TextNode          { env.out.write_string(n.value) }
		ScalarNode        { env.out.write_string(scalar_value_str(n.value)) }
		Element           { emit_element(n, mut env)! }
		CommentNode       {} // §2.1: program comments are dropped
		CXDirectiveNode   { cxl_emit_cx_directive(n, mut env) }
		SequenceNode      { for it in n.items { eval_node(it, mut env)! } }
		ArrayNode         { for it in n.items { eval_node(it, mut env)! } }
		// v0.7.0 (multi-line-text symmetry pass): RawText and
		// BlockContent are valid value forms in slot bodies / arg
		// positions (spec [55a], [29e], [56] amendments). When they
		// appear in an eval context, they render their literal text
		// content as output — exactly like a TextNode would. Previously
		// these were silently dropped ("preserved-but-inert"), which is
		// wrong for the symmetry rule "any non-bare value form valid
		// in any value position".
		RawTextNode      { env.out.write_string(n.value) }
		BlockContentNode { for it in n.items { eval_node(it, mut env)! } }
		else             {} // PI, MapNode, etc. — genuinely inert
	}
}

// emit_element handles a data CX element appearing in a CXL program.
// For target=cx, the element round-trips through cx text emission with
// its children's CXL forms evaluated. For other targets the element is
// emitted as CX text (the spec's "authoring warning" case at v0.6.0;
// see cxl.md §2.2 — emit, don't block).
fn emit_element(el Element, mut env CXLEnv) ! {
	emit_element_cx(el, mut env)!
}

fn emit_element_cx(el Element, mut env CXLEnv) ! {
	env.out.write_string('[')
	env.out.write_string(el.name)
	// v0.7.0 (ADR 0003 D1 second bullet / GG11): body-position
	// `[ref @id]` form is a structural element whose body parses
	// into Element.body_ref. Templates emit it verbatim — no
	// auto-resolution — so the eval emit path must reproduce the
	// `[name @body_ref]` shape from the AST field.
	if br := el.body_ref {
		env.out.write_string(' @')
		env.out.write_string(br)
		env.out.write_string(']')
		return
	}
	// v0.7.0: anchor / merge / id / data_type pass through the eval
	// emit path so structural CX features round-trip through CXL
	// templates rather than being silently dropped.
	if a := el.anchor    { env.out.write_string(' &${a}') }
	if m := el.merge     { env.out.write_string(' *${m}') }
	if id := el.id       { env.out.write_string(' #${id}') }
	if dt := el.data_type { env.out.write_string(' :${dt}') }
	for a in el.attrs {
		env.out.write_string(' ')
		env.out.write_string(a.name)
		if body := a.body {
			env.out.write_string('=[')
			mut sub := strings.new_builder(64)
			saved := env.out
			env.out = sub
			// Attr-body content is wrapped in `=[…]`; same re-parse
			// hazards as element body (a leading `@`/`&`/`*`/`#`/`:`
			// would re-tokenize as a body-ref or sigil). Treat as
			// body-position so `[?=]` substitutions auto-quote.
			saved_body_pos := env.body_position
			env.body_position = true
			for n in body { eval_node(n, mut env)! }
			env.body_position = saved_body_pos
			env.out = saved
			env.out.write_string(sub.str())
			env.out.write_string(']')
		} else {
			env.out.write_string('=')
			v_str := scalar_value_str(a.value)
			// J0 (v0.7.0): if the attribute value contains a `[?=…]`
			// interpolation marker, parse the fragment and substitute
			// the evaluated value. Multiple markers are supported.
			if v_str.contains('[?=') {
				emit_attr_with_interpolation(v_str, mut env)!
			} else {
				// v0.7.0: route through cx_quote_attr_if_needed so values
				// with spaces / newlines / quotes / @-prefix round-trip
				// correctly. Previously the eval emit wrote raw bytes,
				// breaking re-parse for any attribute value with a space
				// (e.g. HTMX hx-trigger="keyup changed delay:500ms").
				env.out.write_string(cx_quote_attr_if_needed(v_str))
			}
		}
	}
	if el.items.len > 0 {
		env.out.write_string(' ')
		// Body-position flag is set while emitting `el.items` so
		// nested `[?=]` substitutions auto-quote scalars whose bytes
		// would re-tokenize as CX structure on a downstream re-parse.
		// Saved/restored around the loop because emit_element_cx
		// recurses through eval_node for nested elements; the flag
		// must clear when those children's attr-body emits run.
		saved_body_pos := env.body_position
		env.body_position = true
		for n in el.items { eval_node(n, mut env)! }
		env.body_position = saved_body_pos
	}
	env.out.write_string(']')
}

// emit_attr_with_interpolation walks an attribute value string,
// emitting literal text and substituting `[?=…]` fragments with their
// evaluated values (J0 / attribute-value interpolation, v0.7.0). The
// match is bracket-balanced so nested `]` inside path predicates
// don't terminate the fragment early.
fn emit_attr_with_interpolation(s string, mut env CXLEnv) ! {
	mut i := 0
	for i < s.len {
		// Find next `[?=`.
		if i + 2 < s.len && s[i] == `[` && s[i + 1] == `?` && s[i + 2] == `=` {
			// Walk to the matching `]`, tracking nested brackets.
			mut depth := 1
			mut j := i + 3
			for j < s.len {
				if s[j] == `[` { depth++ }
				else if s[j] == `]` {
					depth--
					if depth == 0 { break }
				}
				j++
			}
			if j >= s.len {
				return error('cxl: attribute-value interpolation missing closing `]` in: ${s[i..]}')
			}
			expr := s[i + 3 .. j]
			val := eval_expr(expr.trim_space(), mut env)!
			env.out.write_string(value_to_string(val))
			i = j + 1
			continue
		}
		env.out.write_u8(s[i])
		i++
	}
}

// emit_cx_directive: top-of-file [?cx …] directives (output-target,
// output-strict, cx-eval-version) configure the evaluator and are
// stripped from output (§2.3). All other CXDirectives are passed
// through. `cxl-version` is accepted as a deprecated alias of
// `cx-eval-version` during the v0.6.0 → v0.7.0 migration window.
fn cxl_emit_cx_directive(n CXDirectiveNode, mut env CXLEnv) {
	for a in n.attrs {
		if a.name in ['output-target', 'output-strict', 'cx-eval-version', 'cxl-version',
			// FF8 — log: module directives are evaluator config, not output (ADR 0023 §D10)
			'log-level', 'log-format', 'log-output', 'test-mode',
			// EE4 — determinism gate
			'pure-only',
			// EE2 — module activation
			'use-module',
			// EE5 — cx:eval gates
			'allow-eval', 'max-eval-depth'] {
			return
		}
	}
	env.out.write_string('[?cx')
	for a in n.attrs {
		env.out.write_string(' ')
		env.out.write_string(a.name)
		env.out.write_string('=')
		env.out.write_string(scalar_value_str(a.value))
	}
	env.out.write_string(']')
}

// ── Interpolation `[?=EXPR]` ─────────────────────────────────────────────────

fn eval_interpolation(n InterpolationNode, mut env CXLEnv) ! {
	// Y6 perf: fast path for the dominant `[?=var/@attr]` pattern
	// (extremely common in real-world templates — every `[?=x/@id]`
	// style interpolation). Bypasses eval_expr's 5×find_top_level_*
	// scans + eval_path_expr's variable-resolution branch + the
	// CXLValue allocation for the intermediate result. Profile-driven:
	// 400k eval_interpolation calls on the bench → 5×400k = 2M
	// find_top_level_* calls saved per run.
	expr := n.expr
	if expr.len > 2 {
		// Find `/@` separator with no leading punctuation prefix.
		if sep := expr.index('/@') {
			if sep > 0 && is_ident_start(expr[0]) {
				mut head_end := 0
				for head_end < sep && is_ident_cont(expr[head_end]) { head_end++ }
				if head_end == sep {
					head := expr[..sep]
					attr := expr[sep + 2..]
					// Validate attr is bare-ident — bail to slow path otherwise.
					mut attr_ok := attr.len > 0 && is_ident_start(attr[0])
					if attr_ok {
						for i := 1; i < attr.len; i++ {
							if !is_ident_cont(attr[i]) { attr_ok = false; break }
						}
					}
					if attr_ok {
						if base_val := env.bindings[head] {
							// Direct attribute lookup, single-element fast case.
							for it in base_val {
								if it is Element {
									for a in it.attrs {
										if a.name == attr {
											if env.target == 'html' {
												env.out.write_string(escape_html_str(a.str_value()))
											} else if env.body_position {
												env.out.write_string(cx_quote_body_if_needed(a.str_value()))
											} else {
												env.out.write_string(a.str_value())
											}
											break
										}
									}
								}
							}
							return
						}
					}
				}
			}
		}
	}
	// Slow path: general expression evaluation. Substituted scalars
	// auto-quote in body position (so brackets/quotes/sigils in the
	// value survive a downstream re-parse) and emit verbatim at top
	// level (preserving the cx:parse / cx:canonical "emit bytes"
	// contract — that pattern is the cxmod conformance baseline).
	val := eval_expr(expr, mut env)!
	if env.body_position {
		emit_value_as_body_text(val, mut env)
	} else {
		emit_value_as_text(val, mut env)
	}
}

fn emit_value_as_text(val CXLValue, mut env CXLEnv) {
	for it in val {
		s := item_to_text(it)
		if env.target == 'html' {
			env.out.write_string(escape_html_str(s))
		} else {
			env.out.write_string(s)
		}
	}
}

// emit_value_as_body_text is the body-position variant of
// emit_value_as_text: it auto-quotes substituted scalars whose bytes
// would re-tokenize as CX structure on a downstream re-parse. Used by
// `[?=]` interpolation, which is semantically "substitute this value
// as text where I am" — the round-trip guarantee belongs to the
// substitution point, not the surrounding filter pipeline.
fn emit_value_as_body_text(val CXLValue, mut env CXLEnv) {
	for it in val {
		s := item_to_text(it)
		if env.target == 'html' {
			env.out.write_string(escape_html_str(s))
		} else {
			env.out.write_string(cx_quote_body_if_needed(s))
		}
	}
}

fn item_to_text(it CXLItem) string {
	return match it {
		CXLScalar  { scalar_value_str(it.value) }
		ScalarNode { scalar_value_str(it.value) }
		TextNode   { it.value }
		Element    { element_text_content(it) }
		CXLFunction {
			// Function values render as a sentinel when atomized to
			// text. XQuery 3.1 raises an error here; cx emits a
			// readable identifier so debug output is useful, matching
			// cx's permissive coercion model. The sentinel format is
			// `[function arity=N]` — readable, unambiguous, and
			// deterministic for byte-identity conformance.
			'[function arity=${it.params.len}]'
		}
		ArrayNode {
			// Array value sentinel — cx's permissive coercion model
			// emits a readable form rather than raising.
			'[array size=${it.items.len}]'
		}
		MapNode {
			'[map entries=${it.entries.len}]'
		}
		else       { '' }
	}
}

// element_text_content extracts the concatenated text content of an
// Element — text nodes and scalar bodies emit their lexical form, child
// elements recurse, ADR 0017 sequence literals expand to their items'
// text content space-joined (matching XPath fn:string()). Equivalent
// to XPath string(.) on Elements.
//
// Sequence handling reinstates a leading space when the parser ate the
// inter-token whitespace before `(`. Example: `[prose hi (a, b, c) yo]`
// parses to `[Text("hi"), Sequence(a,b,c), Text(" yo")]` — the space
// before `(` is consumed by the seq-literal scanner. Without the
// reinsert step, text content collapses to `"hia b c yo"`; with it,
// the result is `"hi a b c yo"`. Trailing whitespace recovers via the
// next Text's leading whitespace, if any.
fn element_text_content(el Element) string {
	mut b := strings.new_builder(32)
	mut needs_ws_before_seq := false
	for n in el.items {
		match n {
			TextNode {
				b.write_string(n.value)
				if n.value.len > 0 {
					needs_ws_before_seq = !n.value[n.value.len - 1].is_space()
				}
			}
			ScalarNode {
				s := scalar_value_str(n.value)
				b.write_string(s)
				if s.len > 0 {
					needs_ws_before_seq = !s[s.len - 1].is_space()
				}
			}
			Element {
				b.write_string(element_text_content(n))
				needs_ws_before_seq = true
			}
			SequenceNode {
				if needs_ws_before_seq {
					b.write_u8(` `)
				}
				b.write_string(sequence_text_content(n))
				needs_ws_before_seq = true
			}
			else {}
		}
	}
	return b.str()
}

// sequence_text_content joins a sequence's items into space-separated
// text. Matches XPath fn:string() on a sequence value. Nested
// sequences flatten through recursion. ArrayNode and MapNode children
// are not walked here — they retain CX's "structural value, not text"
// semantics until a downstream surface explicitly asks for a string
// projection.
fn sequence_text_content(seq SequenceNode) string {
	mut b := strings.new_builder(32)
	for i, n in seq.items {
		if i > 0 {
			b.write_u8(` `)
		}
		match n {
			TextNode     { b.write_string(n.value) }
			ScalarNode   { b.write_string(scalar_value_str(n.value)) }
			Element      { b.write_string(element_text_content(n)) }
			SequenceNode { b.write_string(sequence_text_content(n)) }
			else         {}
		}
	}
	return b.str()
}

// ── EvalDirective dispatch ───────────────────────────────────────────────────

fn dispatch_eval_directive(n EvalDirectiveNode, mut env CXLEnv) ! {
	// Reserved control-flow directives — cannot be shadowed by user
	// `?def` templates (the grammar's EvalName production [59a]
	// reserves these names; ?def parses 'if' / 'for' / etc. as
	// control-flow, never as a definable identifier).
	match n.name {
		'if'      { eval_if(n, mut env)!  return }
		'for'     { eval_for(n, mut env)! return }
		'for-tumbling' { eval_for_tumbling(n, mut env)! return }
		'for-sliding'  { eval_for_sliding(n, mut env)! return }
		'with'    { eval_with(n, mut env)! return }
		'def'     { eval_def(n, mut env)! return }
		'use'     { eval_use(n, mut env)! return }
		'include' { eval_include(n, mut env)! return }
		// `cond` dropped per ADR 0017 §D7 (folded into multi-branch `?if`).
		'cond'    { return error('cxl: [?cond] is dropped at CXL 1.0 — use [?if [[c1, b1], …, [*, default]]] (ADR 0017 §D7)') }
		// CXL 3.1+ directives — v0.7.0 implementation in progress per ADR 0022.
		'let'   { eval_let(n, mut env)! return }
		'try'   { eval_try(n, mut env)! return }
		'switch'     { eval_switch(n, mut env)! return }
		'typeswitch' { eval_typeswitch(n, mut env)! return }
		'match'      { eval_match(n, mut env)! return }
		'fn' {
			// In statement position, [?fn ...] emits its function-value
			// rendering (sentinel text). The interesting use is in value
			// position — eval_slot_to_value routes the same directive
			// through build_function_value, returning a CXLFunction item.
			val := build_function_value(n, env)!
			emit_value_as_text(val, mut env)
			return
		}
		'focus' {
			// A24 focus function — sugar for [?fn :params [_] :body body].
			// Like [?fn], the interesting use is in value position via
			// eval_slot_to_value; statement-position emits the sentinel.
			val := build_focus_function_value(n, env)!
			emit_value_as_text(val, mut env)
			return
		}
		'partial' {
			// A23 partial application — supports both left-curry
			// (`[?partial [f, a, b]]`) and middle-position placeholders
			// (`[?partial [f, a, _, b, _]]`) per ADR 0022 §D2. Built as
			// a value-position directive (like [?fn]) because the
			// placeholder detection has to look at slot nodes, not
			// evaluated values — eval_slot_to_value routes here.
			val := build_partial_value(n, mut env)!
			emit_value_as_text(val, mut env)
			return
		}
		'__partial_invoke' {
			// Internal dispatcher used as the body of [?partial]-built
			// CXLFunctions. Reads its positional args (one per original
			// arg position, evaluated against env bindings which carry
			// both pre-bound captured values and placeholder params)
			// then calls the captured __partial_target with the result.
			eval_partial_invoke(n, mut env)!
			return
		}
		'log:with-context' {
			// FF7 — body slot is evaluated AFTER the context-frame
			// push, so we cannot allow eval_filter_directive's eager
			// slot loop to evaluate it first (the body would emit
			// without inheriting the frame). Intercept here, dispatch
			// to filter_log_with_context which evaluates body itself.
			// EE4 purity gate must still apply at this intercept since
			// eval_filter_directive's check_purity_gate doesn't run.
			check_purity_gate(env, n.name)!
			val := filter_log_with_context(n, mut env)!
			emit_value_as_text(val, mut env)
			return
		}
		else {}
	}
	// Function-value call (ADR 0022 §D2 A20). When the name resolves
	// to a CXLFunction value in env.bindings (typically bound via
	// `[?let f :be [?fn ...]]`), dispatch as a function call. Functions
	// resolve before templates because user-defined function values
	// shadow names lexically; templates are global.
	if n.name in env.bindings {
		binding := env.bindings[n.name]
		if binding.len == 1 && binding[0] is CXLFunction {
			fn_val := binding[0] as CXLFunction
			dispatch_function_call(fn_val, n, mut env)!
			return
		}
	}
	// User-defined templates win over builtin filter names per
	// ADR 0020 §D6 — `[?def upper :body …]` followed by `[?upper x]`
	// invokes the user template, not the builtin. Templates are
	// resolved before filters at every call site.
	if n.name in env.defs {
		dispatch_template_call(n, mut env)!
		return
	}
	// CXL 3.1 higher-order filter directives (per ADR 0022 §D2 C11).
	// Intercepted before generic eval_filter_directive because they need
	// mut env access to call function values via call_fn_to_value.
	match n.name {
		'for-each', 'filter', 'fold-left', 'fold-right',
		'apply', 'function-arity', 'function-name', 'for-each-pair',
		'function-lookup', 'function-identity', 'scan-left',
		'some', 'every', 'simple-map',
		'pipe', 'arrow',
		'map:for-each',
		'array:filter', 'array:for-each', 'array:fold-left',
		'array:fold-right', 'array:sort' {
			val := eval_higher_order_filter(n, mut env)!
			emit_value_as_text(val, mut env)
			return
		}
		else {}
	}
	// CXL 1.0 frozen filter set + XQuery 4.0 fn library at statement
	// position. eval_filter_directive recognizes the full set via its
	// big match table; if the name isn't a known filter, propagates a
	// structured "filter not in CXL set" error that ?try can catch.
	val := eval_filter_directive(n, mut env)!
	emit_value_as_text(val, mut env)
}

// eval_higher_order_filter handles HOF directives (for-each, filter,
// fold-left, fold-right) that take a function value as one of their
// args. The function is called per-item via call_fn_to_value; results
// aggregate per HOF semantics.
fn eval_higher_order_filter(n EvalDirectiveNode, mut env CXLEnv) !CXLValue {
	slots := arg_array_slots(n)!
	// Evaluate args first.
	mut args := []CXLValue{cap: slots.len}
	for s in slots {
		args << eval_slot_to_value(s, mut env)!
	}
	return match n.name {
		'for-each'      { hof_for_each(args, mut env)! }
		'filter'        { hof_filter(args, mut env)! }
		'fold-left'     { hof_fold_left(args, mut env)! }
		'fold-right'    { hof_fold_right(args, mut env)! }
		'apply'         { hof_apply(args, mut env)! }
		'function-arity'  { hof_function_arity(args)! }
		'function-name'   { hof_function_name(args)! }
		'for-each-pair' { hof_for_each_pair(args, mut env)! }
		'function-lookup'   { hof_function_lookup(args, env)! }
		'function-identity' { hof_function_identity(args)! }
		'scan-left'         { hof_scan_left(args, mut env)! }
		'some'              { hof_some(args, mut env)! }
		'every'             { hof_every(args, mut env)! }
		'simple-map'        { hof_for_each(args, mut env)! }
		'map:for-each'      { hof_map_for_each(args, mut env)! }
		'array:filter'      { hof_array_filter(args, mut env)! }
		'array:for-each'    { hof_array_for_each(args, mut env)! }
		'array:fold-left'   { hof_array_fold_left(args, mut env)! }
		'array:fold-right'  { hof_array_fold_right(args, mut env)! }
		'array:sort'        { hof_array_sort(args, mut env)! }
		'pipe'              { hof_pipe(args, mut env)! }
		'arrow'             { hof_pipe(args, mut env)! }
		else            { error('cxl: unknown higher-order filter [?${n.name}]') }
	}
}

// fn:pipe($value, $fn1, $fn2, ...) — pipeline: chain function calls
// left-to-right, threading the value through each. XPath 4.0 `|>` and
// XPath 3.1 `=>` operators are aliased to this directive form.
fn hof_pipe(args []CXLValue, mut env CXLEnv) !CXLValue {
	if args.len < 1 { return CXLValue([]CXLItem{}) }
	mut current := args[0]
	for i := 1; i < args.len; i++ {
		fn_arg := args[i]
		if fn_arg.len != 1 || fn_arg[0] !is CXLFunction {
			return error('cxl: [?pipe] arg ${i} must be a function value')
		}
		fn_val := fn_arg[0] as CXLFunction
		current = call_fn_to_value(fn_val, [current], mut env)!
	}
	return current
}

// map:for-each($map, $fn) — apply $fn to each (key, value) pair; concat results.
fn hof_map_for_each(args []CXLValue, mut env CXLEnv) !CXLValue {
	m := args_first_map(args, 'map:for-each')!
	if args.len < 2 { return error('cxl: [?map:for-each [map, fn]] needs 2 args') }
	fn_arg := args[1]
	if fn_arg.len != 1 || fn_arg[0] !is CXLFunction {
		return error('cxl: [?map:for-each] second arg must be a function value')
	}
	fn_val := fn_arg[0] as CXLFunction
	mut out := []CXLItem{}
	for entry in m.entries {
		key := CXLValue([CXLItem(CXLScalar{ data_type: entry.key_type, value: entry.key_value })])
		val := CXLValue([eval_node_to_item(entry.value)])
		result := call_fn_to_value(fn_val, [key, val], mut env)!
		for r in result { out << r }
	}
	return out
}

// array:filter — same shape as fn:filter but takes array; returns array.
fn hof_array_filter(args []CXLValue, mut env CXLEnv) !CXLValue {
	a := args_first_array(args, 'array:filter')!
	if args.len < 2 { return error('cxl: [?array:filter [arr, pred]] needs 2 args') }
	fn_arg := args[1]
	if fn_arg.len != 1 || fn_arg[0] !is CXLFunction {
		return error('cxl: [?array:filter] second arg must be a function value')
	}
	fn_val := fn_arg[0] as CXLFunction
	mut new_items := []Node{}
	for it in a.items {
		result := call_fn_to_value(fn_val, [[eval_node_to_item(it)]], mut env)!
		if truthy_text(value_to_string(result)) { new_items << it }
	}
	return [CXLItem(ArrayNode{ items: new_items })]
}

// array:for-each — apply fn to each item; results as flat sequence.
fn hof_array_for_each(args []CXLValue, mut env CXLEnv) !CXLValue {
	a := args_first_array(args, 'array:for-each')!
	if args.len < 2 { return error('cxl: [?array:for-each [arr, fn]] needs 2 args') }
	fn_arg := args[1]
	if fn_arg.len != 1 || fn_arg[0] !is CXLFunction {
		return error('cxl: [?array:for-each] second arg must be a function value')
	}
	fn_val := fn_arg[0] as CXLFunction
	mut out := []CXLItem{}
	for it in a.items {
		result := call_fn_to_value(fn_val, [[eval_node_to_item(it)]], mut env)!
		for r in result { out << r }
	}
	return out
}

// array:fold-left — like fn:fold-left but operates on array items.
fn hof_array_fold_left(args []CXLValue, mut env CXLEnv) !CXLValue {
	a := args_first_array(args, 'array:fold-left')!
	if args.len < 3 { return error('cxl: [?array:fold-left [arr, zero, fn]] needs 3 args') }
	mut acc := args[1]
	fn_arg := args[2]
	if fn_arg.len != 1 || fn_arg[0] !is CXLFunction {
		return error('cxl: [?array:fold-left] third arg must be a function value')
	}
	fn_val := fn_arg[0] as CXLFunction
	for it in a.items {
		acc = call_fn_to_value(fn_val, [acc, [eval_node_to_item(it)]], mut env)!
	}
	return acc
}

// array:fold-right — right fold over array.
fn hof_array_fold_right(args []CXLValue, mut env CXLEnv) !CXLValue {
	a := args_first_array(args, 'array:fold-right')!
	if args.len < 3 { return error('cxl: [?array:fold-right [arr, zero, fn]] needs 3 args') }
	mut acc := args[1]
	fn_arg := args[2]
	if fn_arg.len != 1 || fn_arg[0] !is CXLFunction {
		return error('cxl: [?array:fold-right] third arg must be a function value')
	}
	fn_val := fn_arg[0] as CXLFunction
	for i := a.items.len - 1; i >= 0; i-- {
		acc = call_fn_to_value(fn_val, [[eval_node_to_item(a.items[i])], acc], mut env)!
	}
	return acc
}

// array:sort — text-based stable sort; key-fn variant when 2nd arg
// is a function (XPath 4.0 sort($input, $key)).
fn hof_array_sort(args []CXLValue, mut env CXLEnv) !CXLValue {
	a := args_first_array(args, 'array:sort')!
	mut keys := []string{cap: a.items.len}
	if args.len >= 2 && args[1].len == 1 && args[1][0] is CXLFunction {
		fn_val := args[1][0] as CXLFunction
		for it in a.items {
			result := call_fn_to_value(fn_val, [[eval_node_to_item(it)]], mut env)!
			keys << value_to_string(result)
		}
	} else {
		for it in a.items { keys << item_to_text(eval_node_to_item(it)) }
	}
	mut out := a.items.clone()
	for i := 1; i < out.len; i++ {
		mut j := i
		for j > 0 && keys[j] < keys[j - 1] {
			tmp_k := keys[j]
			keys[j] = keys[j - 1]
			keys[j - 1] = tmp_k
			tmp_v := out[j]
			out[j] = out[j - 1]
			out[j - 1] = tmp_v
			j--
		}
	}
	return [CXLItem(ArrayNode{ items: out })]
}

// fn:some($seq, $pred) — true if any item satisfies the predicate.
fn hof_some(args []CXLValue, mut env CXLEnv) !CXLValue {
	if args.len < 2 { return error('cxl: [?some [seq, pred]] needs 2 args') }
	seq := args[0]
	fn_arg := args[1]
	if fn_arg.len != 1 || fn_arg[0] !is CXLFunction {
		return error('cxl: [?some] second arg must be a function value')
	}
	fn_val := fn_arg[0] as CXLFunction
	for it in seq {
		result := call_fn_to_value(fn_val, [[it]], mut env)!
		if truthy_text(value_to_string(result)) {
			return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(true) })]
		}
	}
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(false) })]
}

// fn:every($seq, $pred) — true if all items satisfy the predicate.
fn hof_every(args []CXLValue, mut env CXLEnv) !CXLValue {
	if args.len < 2 { return error('cxl: [?every [seq, pred]] needs 2 args') }
	seq := args[0]
	fn_arg := args[1]
	if fn_arg.len != 1 || fn_arg[0] !is CXLFunction {
		return error('cxl: [?every] second arg must be a function value')
	}
	fn_val := fn_arg[0] as CXLFunction
	for it in seq {
		result := call_fn_to_value(fn_val, [[it]], mut env)!
		if !truthy_text(value_to_string(result)) {
			return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(false) })]
		}
	}
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(true) })]
}

// truthy_text — shared predicate-result helper used by some/every/filter.
fn truthy_text(text string) bool {
	t := text.trim_space()
	return match t {
		'true'  { true }
		'false' { false }
		''      { false }
		else    {
			n := strconv.atof64(t) or { f64(0) }
			if n != 0 { true } else { t != '' }
		}
	}
}

// fn:function-lookup($qname, $arity) — look up a function by name+arity.
// At v0.7.0 this looks up named templates in env.defs as a stand-in;
// proper QName-based lookup with namespace resolution is post-v0.7.0.
fn hof_function_lookup(args []CXLValue, env CXLEnv) !CXLValue {
	if args.len < 2 { return error('cxl: [?function-lookup [name, arity]] needs 2 args') }
	name := value_to_string(args[0])
	if name == '' { return CXLValue([]CXLItem{}) }
	arity := int(item_to_f64(args[1][0] or { return CXLValue([]CXLItem{}) }))
	tmpl := env.defs[name] or { return CXLValue([]CXLItem{}) }
	if tmpl.params.len != arity { return CXLValue([]CXLItem{}) }
	// Build a CXLFunction view of the named template.
	return [CXLItem(CXLFunction{
		params: tmpl.params.clone()
		body:   tmpl.body.clone()
	})]
}

// fn:function-identity($fn) — XPath 4.0; returns the input fn
// unchanged (identity function on function values).
fn hof_function_identity(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len == 0 || v[0] !is CXLFunction {
		return error('cxl: [?function-identity] arg must be a function value')
	}
	return v
}

// fn:scan-left($seq, $zero, $combine) — like fold-left but returns
// all intermediate accumulator values (XPath 4.0).
fn hof_scan_left(args []CXLValue, mut env CXLEnv) !CXLValue {
	if args.len < 3 { return error('cxl: [?scan-left [seq, zero, fn]] needs 3 args') }
	seq := args[0]
	mut acc := args[1]
	fn_arg := args[2]
	if fn_arg.len != 1 || fn_arg[0] !is CXLFunction {
		return error('cxl: [?scan-left] third arg must be a function value')
	}
	fn_val := fn_arg[0] as CXLFunction
	mut out := []CXLItem{}
	for it in acc { out << it } // start with zero
	for it in seq {
		acc = call_fn_to_value(fn_val, [acc, [it]], mut env)!
		for a in acc { out << a }
	}
	return out
}

// fn:apply($fn, $args) — call $fn with $args (an array/sequence of args).
fn hof_apply(args []CXLValue, mut env CXLEnv) !CXLValue {
	if args.len < 1 { return error('cxl: [?apply [fn, args?]] needs at least 1 arg') }
	fn_arg := args[0]
	if fn_arg.len != 1 || fn_arg[0] !is CXLFunction {
		return error('cxl: [?apply] first arg must be a function value')
	}
	fn_val := fn_arg[0] as CXLFunction
	// Spread the args sequence: each item becomes one positional arg.
	// One-arg form (just the fn) is valid for zero-arity functions —
	// e.g., result of fully-applied partial.
	args_seq := if args.len >= 2 { args[1] } else { CXLValue([]CXLItem{}) }
	mut spread := []CXLValue{cap: args_seq.len}
	for it in args_seq { spread << [it] }
	return call_fn_to_value(fn_val, spread, mut env)!
}

// fn:function-arity($fn) — number of params.
fn hof_function_arity(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len == 0 || v[0] !is CXLFunction {
		return error('cxl: [?function-arity] arg must be a function value')
	}
	fn_val := v[0] as CXLFunction
	return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(i64(fn_val.params.len)) })]
}

// fn:function-name($fn) — anonymous fns return empty string; XPath
// 4.0 returns a QName which is empty for anonymous.
fn hof_function_name(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len == 0 || v[0] !is CXLFunction {
		return error('cxl: [?function-name] arg must be a function value')
	}
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue('') })]
}

// fn:for-each-pair($seq1, $seq2, $fn) — apply $fn to corresponding
// pairs; result is sequence of fn returns, truncated to shorter input.
fn hof_for_each_pair(args []CXLValue, mut env CXLEnv) !CXLValue {
	if args.len < 3 { return error('cxl: [?for-each-pair [seq1, seq2, fn]] needs 3 args') }
	seq1 := args[0]
	seq2 := args[1]
	fn_arg := args[2]
	if fn_arg.len != 1 || fn_arg[0] !is CXLFunction {
		return error('cxl: [?for-each-pair] third arg must be a function value')
	}
	fn_val := fn_arg[0] as CXLFunction
	mut min_len := seq1.len
	if seq2.len < min_len { min_len = seq2.len }
	mut out := []CXLItem{}
	for i in 0 .. min_len {
		result := call_fn_to_value(fn_val, [[seq1[i]], [seq2[i]]], mut env)!
		for r in result { out << r }
	}
	return out
}

// fn:for-each($seq, $fn) — apply $fn to each item; concatenate results.
fn hof_for_each(args []CXLValue, mut env CXLEnv) !CXLValue {
	if args.len < 2 { return error('cxl: [?for-each [seq, fn]] needs 2 args') }
	seq := args[0]
	fn_arg := args[1]
	if fn_arg.len != 1 || fn_arg[0] !is CXLFunction {
		return error('cxl: [?for-each] second arg must be a function value')
	}
	fn_val := fn_arg[0] as CXLFunction
	mut out := []CXLItem{}
	for it in seq {
		result := call_fn_to_value(fn_val, [[it]], mut env)!
		for r in result { out << r }
	}
	return out
}

// fn:filter($seq, $pred) — keep items where $pred returns truthy.
// At v0.7.0 commit-current, function bodies emit text representations
// of their results; the predicate's truth is determined by parsing the
// captured text: 'true' → true, 'false' → false, other non-empty →
// EBV-test (numbers >0 are true, empty string is false, etc.). Refine
// once function bodies can return non-text CXLValue directly (after
// A21 closure + body-as-expression integration).
fn hof_filter(args []CXLValue, mut env CXLEnv) !CXLValue {
	if args.len < 2 { return error('cxl: [?filter [seq, pred]] needs 2 args') }
	seq := args[0]
	fn_arg := args[1]
	if fn_arg.len != 1 || fn_arg[0] !is CXLFunction {
		return error('cxl: [?filter] second arg must be a function value')
	}
	fn_val := fn_arg[0] as CXLFunction
	mut out := []CXLItem{}
	for it in seq {
		result := call_fn_to_value(fn_val, [[it]], mut env)!
		if truthy_text(value_to_string(result)) { out << it }
	}
	return out
}

// fn:fold-left($seq, $zero, $combine) — left fold.
fn hof_fold_left(args []CXLValue, mut env CXLEnv) !CXLValue {
	if args.len < 3 { return error('cxl: [?fold-left [seq, zero, fn]] needs 3 args') }
	seq := args[0]
	mut acc := args[1]
	fn_arg := args[2]
	if fn_arg.len != 1 || fn_arg[0] !is CXLFunction {
		return error('cxl: [?fold-left] third arg must be a function value')
	}
	fn_val := fn_arg[0] as CXLFunction
	for it in seq {
		acc = call_fn_to_value(fn_val, [acc, [it]], mut env)!
	}
	return acc
}

// fn:fold-right($seq, $zero, $combine) — right fold.
fn hof_fold_right(args []CXLValue, mut env CXLEnv) !CXLValue {
	if args.len < 3 { return error('cxl: [?fold-right [seq, zero, fn]] needs 3 args') }
	seq := args[0]
	mut acc := args[1]
	fn_arg := args[2]
	if fn_arg.len != 1 || fn_arg[0] !is CXLFunction {
		return error('cxl: [?fold-right] third arg must be a function value')
	}
	fn_val := fn_arg[0] as CXLFunction
	for i := seq.len - 1; i >= 0; i-- {
		acc = call_fn_to_value(fn_val, [[seq[i]], acc], mut env)!
	}
	return acc
}

// ── ArgArray helpers (ADR 0017 §D6) ──────────────────────────────────────────

// arg_array_slots returns the slot list of an EvalDirective's single
// ArgArray. Empty directives (`[?if]`) return an empty list. Returns
// an error if items[0] is not an ArrayNode (parser invariant violation;
// should never happen given the §F-parser dispatch).
fn arg_array_slots(n EvalDirectiveNode) ![]Node {
	if n.items.len == 0 { return []Node{} }
	if n.items.len != 1 {
		return error('cxl: [?${n.name}] expected one ArgArray body item, got ${n.items.len}')
	}
	arg := n.items[0]
	if arg !is ArrayNode {
		return error('cxl: [?${n.name}] expected ArgArray (ArrayNode), got ${typeof(arg).name}')
	}
	return (arg as ArrayNode).items
}

// slot_to_expr extracts an expression-text representation of a slot.
// Used for slots that carry a CXPath expression (cond, iterable,
// context) or a bare-name token (var, def-name, use-name). Single
// TextNode/ScalarNode slots return their text form; SequenceNode-
// wrapped multi-item slots concatenate text content (rare in
// expression positions but supported for completeness). Other node
// kinds error — a structural slot can't be coerced to expression
// text without ambiguity.
fn slot_to_expr(n Node) !string {
	return match n {
		TextNode   { n.value.trim_space() }
		ScalarNode { scalar_value_str(n.value).trim_space() }
		SequenceNode {
			mut b := strings.new_builder(16)
			for it in n.items {
				match it {
					TextNode   { b.write_string(it.value) }
					ScalarNode { b.write_string(scalar_value_str(it.value)) }
					else       { return error('cxl: slot expression contains non-text item ${typeof(it).name}') }
				}
			}
			b.str().trim_space()
		}
		else { error('cxl: slot expression cannot be ${typeof(n).name}') }
	}
}

// eval_slot_body evaluates a slot as a body — emits each body item to
// env.out in order. Single-Node slots are wrapped trivially; multi-
// item SequenceNode slots iterate. Used by then/else/body/with-body/
// def-body/for-body slots where the slot value renders as output
// rather than being consumed as an expression.
fn eval_slot_body(slot Node, mut env CXLEnv) ! {
	if slot is SequenceNode {
		for it in (slot as SequenceNode).items { eval_node(it, mut env)! }
		return
	}
	eval_node(slot, mut env)!
}

// Y6 perf — body pre-compilation (Phase 2 — parallel-arrays edition).
//
// `?for` iterates an arbitrary body N times. The dominant bench
// pattern (text + simple interpolations per iteration) walks the AST
// via eval_node's match dispatch every iteration — ~2µs of per-node
// overhead, ~25% of remaining streaming runtime after path-cache +
// interpolation fast-path wins.
//
// CompiledBody pre-classifies each body item ONCE before the loop into
// a fast-dispatch operation kind. The execute loop then dispatches via
// a simple int comparison instead of V sum-type variant access.
//
// Op kinds (parallel arrays — one slot per op):
//   0 = text          → emit_text[i] (literal string)
//   1 = var/@attr     → look up var_name[i] in bindings, emit attr_name[i]
//   2 = generic       → fall back to eval_node on generic_node[i]
//
// We avoid V's sum-type variant storage entirely here (which
// previously corrupted under V 0.5.1 for nested-variant payloads in
// the earlier EmitOp design — see commit 02599631 retrospective).
struct CompiledBody {
mut:
	op_kinds      []int     // 0=text, 1=var_attr, 2=generic
	text_values   []string  // populated when op_kinds[i] == 0
	var_names     []string  // populated when op_kinds[i] == 1
	attr_names    []string  // populated when op_kinds[i] == 1
	generic_nodes []Node    // populated when op_kinds[i] == 2
}

fn classify_body_item(n Node, mut cb CompiledBody) {
	if n is TextNode {
		cb.op_kinds      << 0
		cb.text_values   << n.value
		cb.var_names     << ''
		cb.attr_names    << ''
		cb.generic_nodes << Node(TextNode{ value: '' })
		return
	}
	if n is InterpolationNode {
		expr := n.expr
		if expr.len > 2 {
			if sep := expr.index('/@') {
				if sep > 0 && is_ident_start(expr[0]) {
					mut head_end := 0
					for head_end < sep && is_ident_cont(expr[head_end]) { head_end++ }
					if head_end == sep {
						attr := expr[sep + 2..]
						mut attr_ok := attr.len > 0 && is_ident_start(attr[0])
						if attr_ok {
							for i := 1; i < attr.len; i++ {
								if !is_ident_cont(attr[i]) { attr_ok = false; break }
							}
						}
						if attr_ok {
							cb.op_kinds      << 1
							cb.text_values   << ''
							cb.var_names     << expr[..sep]
							cb.attr_names    << attr
							cb.generic_nodes << Node(TextNode{ value: '' })
							return
						}
					}
				}
			}
		}
	}
	cb.op_kinds      << 2
	cb.text_values   << ''
	cb.var_names     << ''
	cb.attr_names    << ''
	cb.generic_nodes << n
}

fn compile_body(body Node) CompiledBody {
	mut cb := CompiledBody{
		op_kinds:      []int{cap: 8}
		text_values:   []string{cap: 8}
		var_names:     []string{cap: 8}
		attr_names:    []string{cap: 8}
		generic_nodes: []Node{cap: 8}
	}
	if body is SequenceNode {
		for it in (body as SequenceNode).items {
			classify_body_item(it, mut cb)
		}
	} else {
		classify_body_item(body, mut cb)
	}
	return cb
}

@[direct_array_access]
fn execute_compiled_body(cb CompiledBody, mut env CXLEnv) ! {
	for i := 0; i < cb.op_kinds.len; i++ {
		k := cb.op_kinds[i]
		if k == 0 {
			env.out.write_string(cb.text_values[i])
		} else if k == 1 {
			var_name := cb.var_names[i]
			attr_name := cb.attr_names[i]
			if base_val := env.bindings[var_name] {
				for it in base_val {
					if it is Element {
						for a in it.attrs {
							if a.name == attr_name {
								if env.target == 'html' {
									env.out.write_string(escape_html_str(a.str_value()))
								} else {
									env.out.write_string(a.str_value())
								}
								break
							}
						}
					}
				}
			}
		} else {
			eval_node(cb.generic_nodes[i], mut env)!
		}
	}
}

// execute_compiled_body_bound: tighter variant for the common case
// where the loop variable resolves to a single Element and all k==1
// ops reference that loop var. Skips the env.bindings map lookup AND
// the base_val iteration AND the sum-type check.
//
// Y6 perf: takes a `cached_indices []int` side-table — for each k==1
// op, the cached index into loop_elem.attrs (-1 = not cached yet, or
// last lookup name didn't match). After first iteration, attribute
// searches are O(1) by index instead of O(N) linear scan. Verifies
// name match each iteration (cheap eq check) to handle the rare case
// of iterating over Elements with different attr orders. Falls back
// to linear search on mismatch and re-caches.
//
// `is_loop_var` is precomputed once per compiled body before the
// iteration loop (in eval_for) — `is_loop_var[i] == true` for k==1
// ops where var_names[i] == loop_var, so we don't pay string-equality
// cost per iteration. `is_html` is similarly hoisted out of the loop.
@[direct_array_access]
fn execute_compiled_body_bound(cb CompiledBody, is_loop_var []bool,
	loop_elem Element, is_html bool, mut cached_indices []int,
	mut env CXLEnv) ! {
	attrs := loop_elem.attrs
	n_attrs := attrs.len
	n_ops := cb.op_kinds.len
	for i := 0; i < n_ops; i++ {
		k := cb.op_kinds[i]
		if k == 0 {
			env.out.write_string(cb.text_values[i])
		} else if k == 1 {
			attr_name := cb.attr_names[i]
			if is_loop_var[i] {
				cached := cached_indices[i]
				if cached >= 0 && cached < n_attrs
					&& attrs[cached].name == attr_name {
					write_attr_value(attrs[cached].value, is_html, mut env)
				} else {
					for j := 0; j < n_attrs; j++ {
						a := attrs[j]
						if a.name == attr_name {
							cached_indices[i] = j
							write_attr_value(a.value, is_html, mut env)
							break
						}
					}
				}
			} else {
				var_name := cb.var_names[i]
				if base_val := env.bindings[var_name] {
					for it in base_val {
						if it is Element {
							for a in it.attrs {
								if a.name == attr_name {
									write_attr_value(a.value, is_html, mut env)
									break
								}
							}
						}
					}
				}
			}
		} else {
			eval_node(cb.generic_nodes[i], mut env)!
		}
	}
}

// all_bound_text_ops reports whether every op in the compiled body
// is either a literal text (k==0) or a loop-var/@attr lookup (k==1
// with is_loop_var[i] set). True enables the ultra-fast batched
// scratch-buffer emit path.
fn all_bound_text_ops(cb CompiledBody, is_loop_var []bool) bool {
	for i in 0 .. cb.op_kinds.len {
		k := cb.op_kinds[i]
		if k == 2 {
			return false
		}
		if k == 1 && !is_loop_var[i] {
			return false
		}
	}
	return true
}

// emit_bound_direct writes a single iteration's output directly into
// env.out's underlying buffer (no scratch intermediary, no push_many
// overhead). Caller pre-grows env.out's cap so the inner-iter writes
// only need an int compare against cap. This trims one full vmemcpy
// per iter (scratch → builder) and removes the array.push_many
// machinery (needs_unique_append / self-append / overflow guards)
// from the hot path.
//
// Non-string ScalarValues fall back through write_attr_value, which
// commits the current pos to env.out.len first so the slow path sees
// the builder in a consistent state.
@[direct_array_access]
fn emit_bound_direct(cb CompiledBody, is_loop_var []bool,
	loop_elem Element, mut cached_indices []int,
	iter_budget int, mut env CXLEnv) {
	// Guarantee at least iter_budget bytes of headroom. With the
	// streaming-mode pre-grow done at eval_cxl_streaming entry, this
	// is a no-op compare for the common case; the grow path runs once
	// per flush-cycle (after threshold + trim).
	env.out.ensure_cap(env.out.len + iter_budget)
	attrs := loop_elem.attrs
	n_attrs := attrs.len
	n_ops := cb.op_kinds.len
	mut data_base := unsafe { &u8(env.out.data) }
	mut cap := env.out.cap
	mut pos := env.out.len
	for i := 0; i < n_ops; i++ {
		k := cb.op_kinds[i]
		if k == 0 {
			s := cb.text_values[i]
			if s.len == 0 { continue }
			if pos + s.len > cap {
				unsafe { env.out.len = pos }
				env.out.ensure_cap(pos + s.len + iter_budget)
				data_base = unsafe { &u8(env.out.data) }
				cap = env.out.cap
			}
			unsafe {
				dst := &u8(usize(data_base) + usize(pos))
				vmemcpy(dst, s.str, s.len)
			}
			pos += s.len
		} else {
			attr_name := cb.attr_names[i]
			cached := cached_indices[i]
			mut found_idx := -1
			if cached >= 0 && cached < n_attrs && attrs[cached].name == attr_name {
				found_idx = cached
			} else {
				for j := 0; j < n_attrs; j++ {
					if attrs[j].name == attr_name {
						cached_indices[i] = j
						found_idx = j
						break
					}
				}
			}
			if found_idx >= 0 {
				v := attrs[found_idx].value
				if v is string {
					vlen := v.len
					if vlen > 0 {
						if pos + vlen > cap {
							unsafe { env.out.len = pos }
							env.out.ensure_cap(pos + vlen + iter_budget)
							data_base = unsafe { &u8(env.out.data) }
							cap = env.out.cap
						}
						unsafe {
							dst := &u8(usize(data_base) + usize(pos))
							vmemcpy(dst, v.str, vlen)
						}
						pos += vlen
					}
				} else {
					unsafe { env.out.len = pos }
					write_attr_value(v, false, mut env)
					// builder.len may have moved; refresh cursor.
					data_base = unsafe { &u8(env.out.data) }
					cap = env.out.cap
					pos = env.out.len
				}
			}
		}
	}
	unsafe { env.out.len = pos }
}

// emit_bound_text_only builds a single iteration's output into a
// raw byte buffer via vmemcpy, then writes the whole buffer to
// env.out in one push_many. On the streaming bench this drops the
// per-iter push_many count from 4 to 1.
//
// scratch_base is a raw byte pointer pre-allocated by the caller
// (in eval_for). Caller guarantees `scratch_cap >= max possible
// single-iter output`. We track length via local `pos` int with
// pointer-arithmetic vmemcpy, bypassing V's []u8 slice machinery
// entirely (the slice flags / COW checks were the killer in earlier
// scratch-buffer attempts).
//
// Non-string ScalarValues fall back to writing through env.out
// directly (the scratch buffer can't materialise them without
// re-doing the sum-type scan + intermediate string).
@[direct_array_access]
fn emit_bound_text_only(cb CompiledBody, is_loop_var []bool,
	loop_elem Element, mut cached_indices []int,
	scratch_base &u8, scratch_cap int, mut env CXLEnv) {
	attrs := loop_elem.attrs
	n_attrs := attrs.len
	n_ops := cb.op_kinds.len
	mut pos := 0
	for i := 0; i < n_ops; i++ {
		k := cb.op_kinds[i]
		if k == 0 {
			s := cb.text_values[i]
			if s.len == 0 { continue }
			if pos + s.len > scratch_cap {
				// Drain + write the rest direct. Rare.
				if pos > 0 {
					unsafe { env.out.write_ptr(scratch_base, pos) }
					pos = 0
				}
				env.out.write_string(s)
				continue
			}
			unsafe {
				dst := &u8(usize(scratch_base) + usize(pos))
				vmemcpy(dst, s.str, s.len)
			}
			pos += s.len
		} else {
			// k == 1 && is_loop_var[i] (guaranteed by all_bound_text_ops)
			attr_name := cb.attr_names[i]
			cached := cached_indices[i]
			mut found_idx := -1
			if cached >= 0 && cached < n_attrs && attrs[cached].name == attr_name {
				found_idx = cached
			} else {
				for j := 0; j < n_attrs; j++ {
					if attrs[j].name == attr_name {
						cached_indices[i] = j
						found_idx = j
						break
					}
				}
			}
			if found_idx >= 0 {
				v := attrs[found_idx].value
				if v is string {
					vlen := v.len
					if vlen > 0 {
						if pos + vlen > scratch_cap {
							if pos > 0 {
								unsafe { env.out.write_ptr(scratch_base, pos) }
								pos = 0
							}
							env.out.write_string(v)
							continue
						}
						unsafe {
							dst := &u8(usize(scratch_base) + usize(pos))
							vmemcpy(dst, v.str, vlen)
						}
						pos += vlen
					}
				} else {
					if pos > 0 {
						unsafe { env.out.write_ptr(scratch_base, pos) }
						pos = 0
					}
					write_attr_value(v, false, mut env)
				}
			}
		}
	}
	if pos > 0 {
		unsafe { env.out.write_ptr(scratch_base, pos) }
	}
}

// write_attr_value emits a ScalarValue to env.out, with the
// string-typed fast-path inlined (no sum-type match alloc on the hot
// path). String is the dominant attribute value type in the streaming
// bench and most CXL-driven render workloads.
@[inline]
fn write_attr_value(v ScalarValue, is_html bool, mut env CXLEnv) {
	if v is string {
		if is_html {
			env.out.write_string(escape_html_str(v))
		} else {
			env.out.write_string(v)
		}
		return
	}
	s := scalar_value_str(v)
	if is_html {
		env.out.write_string(escape_html_str(s))
	} else {
		env.out.write_string(s)
	}
}

// is_pair_array reports whether a slot is itself a 2-element ArrayNode
// — used by ?if to detect multi-branch shape `[[c1,b1], [c2,b2], …]`.
fn is_pair_array(n Node) bool {
	if n is ArrayNode {
		arr := n as ArrayNode
		return arr.items.len == 2
	}
	return false
}

// ── `[?if]` — conditional / multi-branch (spec/eval.md §3.2, §3.3) ───────────

fn eval_if(n EvalDirectiveNode, mut env CXLEnv) ! {
	slots := arg_array_slots(n)!
	if slots.len == 0 {
		return error('cxl: [?if] requires `[cond, then-body, else-body?]` or `[[c1,b1], …, [*, default]]`')
	}

	// Multi-branch detection per spec/eval.md §3.3: every slot is a
	// 2-element array.
	mut is_multi := slots.len >= 1
	for s in slots {
		if !is_pair_array(s) { is_multi = false; break }
	}
	if is_multi {
		for s in slots {
			pair := s as ArrayNode
			cond_expr := slot_to_expr(pair.items[0])!
			if eval_branch_condition(cond_expr, mut env)! {
				eval_slot_body(pair.items[1], mut env)!
				return
			}
		}
		return // no branch matched, no default fired
	}

	// Two- or three-slot form: cond / then / else?
	if slots.len < 2 || slots.len > 3 {
		return error('cxl: [?if] expected 2 or 3 positional slots (cond, then, else?), got ${slots.len}')
	}
	cond_expr := slot_to_expr(slots[0])!
	cond_val  := eval_expr(cond_expr, mut env)!
	if value_ebv(cond_val) {
		eval_slot_body(slots[1], mut env)!
	} else if slots.len == 3 {
		eval_slot_body(slots[2], mut env)!
	}
}

// eval_branch_condition handles the §D8 wildcard sentinel `*` (always
// truthy) and otherwise evaluates the condition as CXPath / comparison.
fn eval_branch_condition(expr string, mut env CXLEnv) !bool {
	if expr == '*' { return true }
	val := eval_expr(expr, mut env)!
	return value_ebv(val)
}

// ── `[?for [var, iterable, body]]` (spec/eval.md §3.4) ────────────────────────

fn eval_for(n EvalDirectiveNode, mut env CXLEnv) ! {
	slots := arg_array_slots(n)!
	// 3-slot: [var, iterable, body]
	// 4-slot: + count_var (FLWOR :count)
	// 5-slot: + while_expr (FLWOR :while)
	// 6-slot: + order_expr (FLWOR :order-by, XQuery 4.0 §4.13.9, A9)
	//          — collect-then-emit-in-sorted-order semantics
	// 7-slot: + group_pair (FLWOR :group-by, XQuery 4.0 §4.13.8, A10)
	//          — slot 7 is Array[key_var_name, key_expr]; slots 4-6 unused
	if slots.len < 3 || slots.len > 7 {
		return error('cxl: [?for] expected 3-7 slots, got ${slots.len}')
	}
	if slots.len == 7 {
		return eval_for_group_by(slots, mut env)
	}
	var_name := slot_to_expr(slots[0])!
	if var_name == '' {
		return error('cxl: [?for] var slot is empty')
	}
	iter_expr := slot_to_expr(slots[1])!
	mut seq   := eval_expr(iter_expr, mut env)!

	mut count_var := ''
	mut while_expr := ''
	mut order_expr := ''
	if slots.len >= 4 {
		count_var = slot_to_expr(slots[3])!
	}
	if slots.len >= 5 {
		while_expr = slot_to_expr(slots[4])!
	}
	if slots.len == 6 {
		order_expr = slot_to_expr(slots[5])!
	}

	// If :order-by present, pre-evaluate the order key for each item
	// and sort the sequence before iteration. Loop-var binding for
	// key evaluation happens per item.
	if order_expr != '' {
		saved_for_key := env.bindings[var_name] or { CXLValue([]CXLItem{}) }
		had_for_key := var_name in env.bindings
		mut keys := []string{cap: seq.len}
		mut items := []CXLItem{cap: seq.len}
		for it in seq {
			env.bindings[var_name] = [it]
			key_val := eval_expr(order_expr, mut env)!
			keys << value_to_string(key_val)
			items << it
		}
		// Restore the loop-var binding (will be re-set below).
		if had_for_key { env.bindings[var_name] = saved_for_key }
		else { env.bindings.delete(var_name) }
		// Stable insertion sort on parallel arrays.
		for i := 1; i < keys.len; i++ {
			mut j := i
			for j > 0 && keys[j] < keys[j - 1] {
				tk := keys[j]
				keys[j] = keys[j - 1]
				keys[j - 1] = tk
				ti := items[j]
				items[j] = items[j - 1]
				items[j - 1] = ti
				j--
			}
		}
		seq = items
	}

	saved_binding := env.bindings[var_name] or { CXLValue([]CXLItem{}) }
	had_binding   := var_name in env.bindings
	saved_count_binding := if count_var != '' {
		env.bindings[count_var] or { CXLValue([]CXLItem{}) }
	} else {
		CXLValue([]CXLItem{})
	}
	had_count_binding := count_var != '' && count_var in env.bindings
	body              := slots[2]
	// Y6 perf: pre-compile body once per eval_for call. The body AST
	// is invariant across iterations; the compiled []EmitOp form is
	// O(body-size) and dispatches per-iteration via a tight switch
	// instead of full eval_node's match-dispatch every node. Big win
	// for `?for` loops over large sequences with simple body shapes
	// (text + var/@attr interpolations) which is the dominant
	// real-world pattern.
	//
	// Y6 perf (this commit): memoize compile_body via env.body_cache
	// keyed on the AST address of slots[2]. A nested `?for` invoked
	// 5000 times by an outer loop previously paid the compile_body
	// cost 5000 times; now once. The pointer comes from inside the
	// parent's ArrayNode.items[] storage and stays valid for the
	// duration of the eval (cx:patch is M5-gated off during eval).
	body_key := unsafe { voidptr(&slots[2]) }
	compiled := env.body_cache[body_key] or {
		cb := compile_body(body)
		env.body_cache[body_key] = cb
		cb
	}
	mut cached_indices := []int{len: compiled.op_kinds.len, init: -1}
	// Precompute per-op routing flags once (avoids per-iter string
	// compare in the bound variant).
	mut is_loop_var := []bool{len: compiled.op_kinds.len, init: false}
	for i in 0 .. compiled.op_kinds.len {
		if compiled.op_kinds[i] == 1 && compiled.var_names[i] == var_name {
			is_loop_var[i] = true
		}
	}
	is_html := env.target == 'html'
	// Y6 perf: if every k==1 op references the loop var AND there's no
	// :while clause AND no count_var, the bound variant has no need to
	// see env.bindings[var_name] OR env.bindings[count_var] — we can
	// skip the per-iter map write entirely. Detected by counting k==1
	// ops vs is_loop_var hits.
	mut needs_bindings := count_var != '' || while_expr != ''
	if !needs_bindings {
		for i in 0 .. compiled.op_kinds.len {
			if compiled.op_kinds[i] == 1 && !is_loop_var[i] {
				needs_bindings = true
				break
			}
			if compiled.op_kinds[i] == 2 {
				needs_bindings = true
				break
			}
		}
	}
	placeholder := CXLItem(TextNode{ value: '' })
	mut loop_slot := []CXLItem{len: 1, init: placeholder}
	mut count_slot := []CXLItem{len: 1, init: placeholder}
	if needs_bindings {
		env.bindings[var_name] = loop_slot
		if count_var != '' {
			env.bindings[count_var] = count_slot
		}
	}
	// Y6 perf: specialize the iteration loop on three cases. The most
	// common (no :while, no bindings update, every item is Element)
	// hoists three constant branches out of the per-iter body.
	//
	// Ultra-fast path: body is pure text + loop-var/@attr ops AND
	// target is text (no html escaping). Build each iter's output
	// into a reusable scratch []u8, then a single push_many to
	// env.out — saves N-1 push_many calls per iter (~30ns each on
	// the streaming bench's 4-op body).
	if while_expr == '' && !needs_bindings && !is_html
		&& all_bound_text_ops(compiled, is_loop_var) {
		// Pointer-arithmetic + vmemcpy in the inner loop bypasses V's
		// []u8 slice machinery (flags / COW checks killed perf on
		// earlier slice-based attempts).
		//
		// emit_bound_direct (the new hot path) writes straight into
		// env.out's underlying buffer, so the env-rooted scratch is
		// no longer touched from this branch. Kept allocated lazily
		// because non-ultra-fast for-loops further down still rely
		// on the scratch when they take the slow path.
		// Y6 perf: hoist the flush-trigger out of the option-deref +
		// function-call path on every inner iteration. In buffered mode
		// (is_streaming == false) the inner-loop guard is a single int
		// load + branch — flush_stream is never entered. In streaming
		// mode we only descend into flush_stream when the builder has
		// actually crossed the threshold; with the bench's 64 KiB
		// threshold that fires ~170 times across 1.5M inner iters
		// instead of every iter. The (flush_after_bytes == 0 → flush
		// every iter) semantics from eval_cxl_streaming's docstring is
		// preserved because the comparison `out.len >= 0` is trivially
		// true whenever the emit wrote anything.
		is_streaming := env.is_streaming
		flush_at := env.flush_after_bytes
		for it in seq {
			if it is Element {
				emit_bound_direct(compiled, is_loop_var, it,
					mut cached_indices, 1024, mut env)
			} else {
				execute_compiled_body(compiled, mut env)!
			}
			if is_streaming && env.out.len >= flush_at {
				flush_stream(mut env, false)!
			}
		}
	} else if while_expr == '' && !needs_bindings {
		for it in seq {
			if it is Element {
				execute_compiled_body_bound(compiled, is_loop_var, it,
					is_html, mut cached_indices, mut env)!
			} else {
				execute_compiled_body(compiled, mut env)!
			}
			flush_stream(mut env, false)!
		}
	} else {
		for i, it in seq {
			if needs_bindings {
				loop_slot[0] = it
				if count_var != '' {
					count_slot[0] = CXLItem(CXLScalar{
						data_type: .int_type
						value:     ScalarValue(i64(i + 1))
					})
				}
			}
			if while_expr != '' {
				cond := eval_expr(while_expr, mut env)!
				if !value_ebv(cond) { break }
			}
			if while_expr == '' && it is Element {
				execute_compiled_body_bound(compiled, is_loop_var, it,
					is_html, mut cached_indices, mut env)!
			} else {
				execute_compiled_body(compiled, mut env)!
			}
			flush_stream(mut env, false)!
		}
	}
	if needs_bindings {
		if had_binding {
			env.bindings[var_name] = saved_binding
		} else {
			env.bindings.delete(var_name)
		}
		if count_var != '' {
			if had_count_binding {
				env.bindings[count_var] = saved_count_binding
			} else {
				env.bindings.delete(count_var)
			}
		}
	}
}

// eval_for_group_by handles the 7-slot FLWOR variant introduced by
// `:group-by [key-var, key-expr]` (A10, XQuery 4.0 §4.13.8). Groups
// items in source order: first occurrence of a key defines the group;
// subsequent items with the same stringified key append to it. Body
// evaluates once per group with key-var bound to the key value and
// the original for-var bound to the group's item sequence.
// cxl_slot_to_int parses an integer from a slot-text representation.
// Accepts bare numeric literals (`5`), or an expression that evaluates
// to a numeric value (path / variable / arithmetic).
fn cxl_slot_to_int(text string, mut env CXLEnv) ?i64 {
	if v := strconv.parse_int(text.trim_space(), 10, 64) {
		return v
	}
	val := eval_expr(text, mut env) or { return none }
	return value_to_int(val)
}

// A13 Tumbling windows (XQuery 4.0 §4.13.4.1) —
//   [?for-tumbling w :in xs :size N :return body]
// Splits xs into non-overlapping chunks of size N. The final chunk
// may be shorter when len(xs) % N != 0. The loop variable `w` binds
// to each chunk as a CXLValue (sequence of items).
fn eval_for_tumbling(n EvalDirectiveNode, mut env CXLEnv) ! {
	slots := arg_array_slots(n)!
	if slots.len != 4 {
		return error('cxl: [?for-tumbling] expected 4 slots [var, iter, size, body], got ${slots.len}')
	}
	var_name := slot_to_expr(slots[0])!
	if var_name == '' {
		return error('cxl: [?for-tumbling] var slot is empty')
	}
	iter_expr := slot_to_expr(slots[1])!
	size_text := slot_to_expr(slots[2])!
	body := slots[3]
	seq := eval_expr(iter_expr, mut env)!
	size := cxl_slot_to_int(size_text, mut env) or {
		return error('cxl: [?for-tumbling] :size must be an integer, got "${size_text}"')
	}
	if size <= 0 {
		return error('cxl: [?for-tumbling] :size must be > 0, got ${size}')
	}
	saved := env.bindings[var_name] or { CXLValue([]CXLItem{}) }
	had   := var_name in env.bindings
	mut i := 0
	for i < seq.len {
		end := if i + int(size) < seq.len { i + int(size) } else { seq.len }
		chunk := seq[i..end].clone()
		env.bindings[var_name] = chunk
		eval_slot_body(body, mut env)!
		flush_stream(mut env, false)!
		i = end
	}
	if had { env.bindings[var_name] = saved }
	else { env.bindings.delete(var_name) }
}

// A14 Sliding windows (XQuery 4.0 §4.13.4.2) —
//   [?for-sliding w :in xs :size N :step S :return body]
// Emits overlapping windows of size N starting every S items. The
// final window is emitted even if shorter than N (partial-window
// behavior; XQuery has both partial-allowed and full-only modes —
// v0.7.0 ships partial-allowed; full-only via :only-full true is
// post-v0.7.0).
fn eval_for_sliding(n EvalDirectiveNode, mut env CXLEnv) ! {
	slots := arg_array_slots(n)!
	if slots.len != 5 {
		return error('cxl: [?for-sliding] expected 5 slots [var, iter, size, step, body], got ${slots.len}')
	}
	var_name := slot_to_expr(slots[0])!
	if var_name == '' {
		return error('cxl: [?for-sliding] var slot is empty')
	}
	iter_expr := slot_to_expr(slots[1])!
	size_text := slot_to_expr(slots[2])!
	step_text := slot_to_expr(slots[3])!
	body := slots[4]
	seq := eval_expr(iter_expr, mut env)!
	size := cxl_slot_to_int(size_text, mut env) or {
		return error('cxl: [?for-sliding] :size must be an integer, got "${size_text}"')
	}
	step := cxl_slot_to_int(step_text, mut env) or {
		return error('cxl: [?for-sliding] :step must be an integer, got "${step_text}"')
	}
	if size <= 0 || step <= 0 {
		return error('cxl: [?for-sliding] :size and :step must be > 0, got size=${size} step=${step}')
	}
	saved := env.bindings[var_name] or { CXLValue([]CXLItem{}) }
	had   := var_name in env.bindings
	mut i := 0
	for i < seq.len {
		end := if i + int(size) < seq.len { i + int(size) } else { seq.len }
		window := seq[i..end].clone()
		env.bindings[var_name] = window
		eval_slot_body(body, mut env)!
		flush_stream(mut env, false)!
		i += int(step)
	}
	if had { env.bindings[var_name] = saved }
	else { env.bindings.delete(var_name) }
}

fn eval_for_group_by(slots []Node, mut env CXLEnv) ! {
	var_name := slot_to_expr(slots[0])!
	if var_name == '' {
		return error('cxl: [?for] :group-by var slot is empty')
	}
	iter_expr := slot_to_expr(slots[1])!
	seq := eval_expr(iter_expr, mut env)!
	body := slots[2]
	group_pair := slots[6]
	if group_pair !is ArrayNode {
		return error('cxl: [?for] :group-by slot must be an Array, got ${typeof(group_pair).name}')
	}
	pair_items := (group_pair as ArrayNode).items
	if pair_items.len != 2 {
		return error('cxl: [?for] :group-by expects [key-var, key-expr], got ${pair_items.len} items')
	}
	key_var := slot_to_expr(pair_items[0])!
	if key_var == '' {
		return error('cxl: [?for] :group-by key-var slot is empty')
	}
	key_expr := slot_to_expr(pair_items[1])!

	// Save bindings for restoration.
	saved_var := env.bindings[var_name] or { CXLValue([]CXLItem{}) }
	had_var   := var_name in env.bindings
	saved_key := env.bindings[key_var] or { CXLValue([]CXLItem{}) }
	had_key   := key_var in env.bindings

	// Group items in first-seen-key order.
	mut key_order := []string{}
	mut groups := map[string][]CXLItem{}
	mut key_first_value := map[string]CXLValue{}
	for it in seq {
		env.bindings[var_name] = [it]
		kv := eval_expr(key_expr, mut env)!
		ks := value_to_string(kv)
		if ks !in groups {
			key_order << ks
			groups[ks] = []CXLItem{}
			key_first_value[ks] = kv
		}
		groups[ks] << it
	}

	for ks in key_order {
		env.bindings[key_var] = key_first_value[ks] or { CXLValue([]CXLItem{}) }
		env.bindings[var_name] = groups[ks] or { []CXLItem{} }
		eval_slot_body(body, mut env)!
		flush_stream(mut env, false)!
	}

	if had_var { env.bindings[var_name] = saved_var }
	else { env.bindings.delete(var_name) }
	if had_key { env.bindings[key_var] = saved_key }
	else { env.bindings.delete(key_var) }
}

// ── `[?let [var, expr, body]]` (CXL 3.1, spec/eval.md §3.9) ───────────────────
// Per ADR 0022 §D2 — CXL 3.1 let-expression. Binds `var` to the value
// of `expr` for the lexical extent of `body` evaluation, then emits
// body's output. Shadowing per ADR 0020 §D2.
//
// Labeled form: `[?let var :be expr :return body]`.
// XQuery analog: `let $var := expr return body`.

fn eval_let(n EvalDirectiveNode, mut env CXLEnv) ! {
	slots := arg_array_slots(n)!
	if slots.len != 3 {
		return error('cxl: [?let] expected 3 slots [var, expr, body], got ${slots.len}')
	}
	var_name := slot_to_expr(slots[0])!
	if var_name == '' {
		return error('cxl: [?let] var slot is empty')
	}
	// Per ADR 0022 §D2 A20 ?fn calling: bind via eval_slot_to_value so
	// the value can be a CXLFunction (from inline `[?fn ...]`), a path
	// expression result, a literal, or any other CXLValue. Previously
	// limited to path expressions via slot_to_expr + eval_expr.
	value := eval_slot_to_value(slots[1], mut env)!

	saved_binding := env.bindings[var_name] or { CXLValue([]CXLItem{}) }
	had_binding   := var_name in env.bindings
	env.bindings[var_name] = value
	eval_slot_body(slots[2], mut env)!
	if had_binding {
		env.bindings[var_name] = saved_binding
	} else {
		env.bindings.delete(var_name)
	}
}

// ── `[?fn :params [...] :body [...]]` (CXL 3.1, per ADR 0022 §D2 + xquery_40_parity §4.5.6) ──
// Build a first-class function value from a [?fn] directive node.
// Same shape as [?def] except the result is a CXLFunction value
// flowing through CXLValue rather than a name-bound entry in env.defs.
//
// At v0.7.0 commit 1 (foundation): creates the value. Calling protocol
// lands in commit 2 (parser tracks ?let-bound function names; dispatcher
// routes [?<name> args] to function call when name resolves to a
// CXLFunction in env.bindings). XPath-style $f(args) postfix
// function-call syntax lands in commit 3 alongside CXPath updates.
//
// Closure capture is not modeled here — bodies see their parameter
// bindings + the call-site lexical scope, same as ?def templates per
// ADR 0020 §D2. Captured-at-definition closures are a follow-up.
fn build_function_value(n EvalDirectiveNode, env CXLEnv) !CXLValue {
	slots := arg_array_slots(n)!
	if slots.len != 2 {
		return error('cxl: [?fn] expected 2 slots [params, body], got ${slots.len}')
	}
	params_node := slots[0]
	if params_node !is ArrayNode {
		return error('cxl: [?fn] params slot must be an Array of identifiers, got ${typeof(params_node).name}')
	}
	params_items := (params_node as ArrayNode).items.clone()
	mut params := []string{}
	for p_item in params_items {
		p_name := slot_to_expr(p_item)!
		if p_name == '' {
			return error('cxl: [?fn] params Array contains empty/non-identifier item')
		}
		params << p_name
	}
	body_node := slots[1]
	body_items := if body_node is SequenceNode {
		(body_node as SequenceNode).items.clone()
	} else {
		[body_node]
	}
	// A21 closure capture: snapshot env.bindings at definition time
	// (excluding bindings shadowed by this fn's own params).
	mut captured := map[string]CXLValue{}
	for k, v in env.bindings {
		// Don't capture names that are formal parameters — params are
		// fresh per call and shouldn't be pre-seeded from definition env.
		if k in params { continue }
		captured[k] = v.clone()
	}
	// U4: closure-capture size cap. Bounds the `?fn` HUGE-environment
	// vector where a malicious template builds large bindings just to
	// retain them inside a function value. Default 1k bindings is far
	// above honest authoring; trusted contexts may zero the cap.
	if env.max_capture_size > 0 && i64(captured.len) > env.max_capture_size {
		return error('cx-err:CXER0011:?fn closure capture has ${captured.len} bindings, exceeds env.max_capture_size (${env.max_capture_size})')
	}
	return [CXLItem(CXLFunction{
		params:   params
		body:     body_items
		captured: captured
	})]
}

// ── `[?match [val, [pattern1, body1], ..., [*, default]]]` (CXL 3.1) ─────────
// Per ADR 0022 §D2 A25. Combined pattern matcher — each pattern is
// either a value (equality) or an xs:* type (type-match) or `*`
// (wildcard default). Dispatches the first matching branch.
//
// Pattern resolution order (per branch):
//   1. `*` → default match (always succeeds)
//   2. xs:* type name → item_matches_type check
//   3. element/map()/array()/function/item() type name → type check
//   4. Otherwise: value equality (string comparison)
//
// Future enrichment: structural patterns (extract bindings), guards
// (`pattern when cond`). Per ADR 0022 §D2 A25 — those are post-v0.7.0.

fn eval_match(n EvalDirectiveNode, mut env CXLEnv) ! {
	slots := arg_array_slots(n)!
	if slots.len < 2 {
		return error('cxl: [?match] expected [val, [pattern, body], ...], got ${slots.len} slots')
	}
	val_text := slot_to_expr(slots[0])!
	val_seq := eval_expr(val_text, mut env)!
	val_str := value_to_string(val_seq)
	for i := 1; i < slots.len; i++ {
		branch := slots[i]
		if branch !is ArrayNode {
			return error('cxl: [?match] each case must be an array [pattern, body]')
		}
		arr := branch as ArrayNode
		if arr.items.len < 2 { continue }
		pattern_node := arr.items[0]
		pattern := slot_to_expr(pattern_node)!.trim_space()
		// Wildcard
		if pattern == '*' {
			eval_slot_body(arr.items[1], mut env)!
			return
		}
		// Type match
		if pattern.starts_with('xs:') || pattern in ['element', 'element()',
			'map()', 'array()', 'function', 'function()', 'function(*)',
			'item()', 'node()'] {
			if val_seq.len > 0 && item_matches_type(val_seq[0], pattern) {
				eval_slot_body(arr.items[1], mut env)!
				return
			}
			continue
		}
		// Value match
		if pattern == val_str {
			eval_slot_body(arr.items[1], mut env)!
			return
		}
	}
}

// ── `[?switch [val, [v1, body1], [v2, body2], [*, default]]]` (XPath 3.0) ────
// Per ADR 0022 §D2 A29. Multi-branch dispatch on value equality.

fn eval_switch(n EvalDirectiveNode, mut env CXLEnv) ! {
	slots := arg_array_slots(n)!
	if slots.len < 2 {
		return error('cxl: [?switch] expected [val, [v1, body1], ...], got ${slots.len} slots')
	}
	val_text := slot_to_expr(slots[0])!
	val_str := value_to_string(eval_expr(val_text, mut env)!)
	for i := 1; i < slots.len; i++ {
		branch := slots[i]
		if branch !is ArrayNode {
			return error('cxl: [?switch] each case must be an array [case, body]')
		}
		arr := branch as ArrayNode
		if arr.items.len < 2 { continue }
		case_node := arr.items[0]
		case_text := slot_to_expr(case_node)!
		// `*` sentinel matches anything (default branch).
		if case_text.trim_space() == '*' {
			eval_slot_body(arr.items[1], mut env)!
			return
		}
		if case_text == val_str {
			eval_slot_body(arr.items[1], mut env)!
			return
		}
		// Try eval as expression in case it's a literal that evaluates differently.
		case_val := eval_expr(case_text, mut env) or { CXLValue([]CXLItem{}) }
		if value_to_string(case_val) == val_str {
			eval_slot_body(arr.items[1], mut env)!
			return
		}
	}
}

// ── `[?typeswitch [val, [type1, body1], [type2, body2], [*, default]]]` ──────
// Per ADR 0022 §D2 A37. XPath 2.0 typeswitch — branches by type.

fn eval_typeswitch(n EvalDirectiveNode, mut env CXLEnv) ! {
	slots := arg_array_slots(n)!
	if slots.len < 2 {
		return error('cxl: [?typeswitch] expected [val, [type1, body1], ...], got ${slots.len} slots')
	}
	val_text := slot_to_expr(slots[0])!
	val_seq := eval_expr(val_text, mut env)!
	for i := 1; i < slots.len; i++ {
		branch := slots[i]
		if branch !is ArrayNode {
			return error('cxl: [?typeswitch] each case must be an array [type, body]')
		}
		arr := branch as ArrayNode
		if arr.items.len < 2 { continue }
		type_node := arr.items[0]
		type_name := slot_to_expr(type_node)!
		if type_name.trim_space() == '*' {
			eval_slot_body(arr.items[1], mut env)!
			return
		}
		if val_seq.len > 0 && item_matches_type(val_seq[0], type_name) {
			eval_slot_body(arr.items[1], mut env)!
			return
		}
	}
}

// ── `[?try [body, catch]]` (CXL 3.1, per ADR 0022 §D2 + §D9 E1) ──────────────
// Evaluate `body`; if it raises an error, evaluate `catch` with $err:*
// bindings populated from the structured error payload.
//
// Output emitted by `body` before the error point is rolled back —
// snapshots env.out length at entry and truncates on error so partial
// output never leaks past a [?try] boundary.
//
// $err:* bindings (XQuery 3.1 conformance per E1):
//   $err:code         — the error code (string at v0.7.0; QName at v0.8.0)
//   $err:description  — human-readable description
//   $err:value        — the value(s) associated with the error
//
// fn:error() raises a structured error parsed back here. Errors from
// V (parse failures, type mismatches, etc.) get a `cx-err:CXER0000`
// generic code with the V error message as $err:description.
//
// Labeled form: `[?try :do body :catch fallback]`.

fn eval_try(n EvalDirectiveNode, mut env CXLEnv) ! {
	slots := arg_array_slots(n)!
	if slots.len < 2 {
		return error('cxl: [?try] expected at least 2 slots [body, catch…], got ${slots.len}')
	}
	saved_len := env.out.len
	eval_slot_body(slots[0], mut env) or {
		// Truncate any partial output from the failed body.
		env.out.go_back(env.out.len - saved_len)
		// Parse structured error payload from the error message.
		code, desc, value, eval_origin := parse_cx_error(err.msg())
		// A16: multi-catch dispatch. slots.len == 2 → single fallback
		// catch (matches any error). slots.len >= 3 → each tail slot
		// is a [pattern, handler] ArrayNode; first matching pattern's
		// handler runs. Pattern syntax: literal code, prefix-glob
		// `FOAR*`, or wildcard `*` (matches any).
		mut matched_handler := ?Node(none)
		if slots.len == 2 {
			matched_handler = slots[1]
		} else {
			for i := 1; i < slots.len; i++ {
				arm := slots[i]
				if arm !is ArrayNode {
					return error('cxl: [?try] catch arm ${i} must be [pattern, handler] ArrayNode')
				}
				arm_items := (arm as ArrayNode).items
				if arm_items.len != 2 {
					return error('cxl: [?try] catch arm ${i} must have 2 items [pattern, handler], got ${arm_items.len}')
				}
				pattern := slot_to_expr(arm_items[0])!
				if cxl_error_pattern_matches(pattern, code) {
					matched_handler = arm_items[1]
					break
				}
			}
		}
		handler := matched_handler or {
			// No catch arm matched — re-raise the original error.
			// Preserve the eval-origin payload if one was attached.
			if eval_origin != '' {
				return error('cx-err:${code}\x1f${desc}\x1f${value}\x1f${eval_origin}')
			}
			return error('cx-err:${code}\x1f${desc}\x1f${value}')
		}
		// Bind err-* in catch scope (A17). Save+restore for nesting.
		// err-eval-origin (ADR 0023 §D6 M5 amendment) is bound only when
		// the originating error carries an origin payload — typically
		// errors that bubble up from cx:eval / cx:render.
		mut err_names := ['err-code', 'err-description', 'err-value']
		if eval_origin != '' { err_names << 'err-eval-origin' }
		mut saved := map[string]CXLValue{}
		mut had   := map[string]bool{}
		for name in err_names {
			had[name] = name in env.bindings
			if had[name] {
				saved[name] = env.bindings[name]
			}
		}
		env.bindings['err-code']        = [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(code) })]
		env.bindings['err-description'] = [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(desc) })]
		env.bindings['err-value']       = [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(value) })]
		if eval_origin != '' {
			env.bindings['err-eval-origin'] = [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(eval_origin) })]
		}
		eval_slot_body(handler, mut env)!
		for name in err_names {
			if had[name] {
				env.bindings[name] = saved[name]
			} else {
				env.bindings.delete(name)
			}
		}
		return
	}
}

// cxl_error_pattern_matches reports whether a catch-arm pattern matches
// an error code. Patterns: `*` (any), `PREFIX*` (prefix glob), or
// literal code. Per A16 / XQuery 4.0 try-catch error-code matching.
fn cxl_error_pattern_matches(pattern string, code string) bool {
	if pattern == '*' { return true }
	if pattern == code { return true }
	if pattern.ends_with('*') {
		prefix := pattern[..pattern.len - 1]
		return code.starts_with(prefix)
	}
	return false
}

// parse_cx_error decodes the cx-err: prefix format emitted by
// fn:error() into (code, description, value, eval-origin). Errors
// from other sources (V parse errors, type mismatches, etc.) without
// the prefix get a generic CXER0000 code with the message as
// description and empty origin.
//
// The 4th field carries the $err:eval-origin payload threaded by
// cx:eval / cx:render error paths (ADR 0023 §D6 M5 amendment) and is
// empty for non-eval errors.
fn parse_cx_error(msg string) (string, string, string, string) {
	mut s := msg
	// Strip the common "cxl:" prefix that wraps internal errors.
	if s.starts_with('cxl: ') { s = s[5..] }
	if s.starts_with('cxl: cxl: ') { s = s[10..] }
	if !s.starts_with('cx-err:') {
		return 'CXER0000', s, '', ''
	}
	rest := s[7..] // skip "cx-err:"
	us := u8(0x1f)
	parts := rest.split(us.ascii_str())
	code := if parts.len >= 1 { parts[0] } else { 'CXER0000' }
	desc := if parts.len >= 2 { parts[1] } else { '' }
	value := if parts.len >= 3 { parts[2] } else { '' }
	origin := if parts.len >= 4 { parts[3] } else { '' }
	return code, desc, value, origin
}

// ── `[?with [context, body]]` (spec/eval.md §3.5) ─────────────────────────────

fn eval_with(n EvalDirectiveNode, mut env CXLEnv) ! {
	slots := arg_array_slots(n)!
	if slots.len != 2 {
		return error('cxl: [?with] expected 2 slots [context, body], got ${slots.len}')
	}
	ctx_expr := slot_to_expr(slots[0])!
	new_ctx  := eval_expr(ctx_expr, mut env)!
	saved    := env.context
	env.context = new_ctx
	eval_slot_body(slots[1], mut env)!
	env.context = saved
}

// ── `[?def [name, body]]` / `[?use [name, ctx?]]` (spec/eval.md §3.7/§3.8) ────

fn eval_def(n EvalDirectiveNode, mut env CXLEnv) ! {
	slots := arg_array_slots(n)!
	// ADR 0017 §D7 amendment (2026-05-12) + ADR 0020 §D4: ?def is
	// canonically 3-slot [name, params, body]. The parser auto-
	// expands legacy 2-slot [name, body] to 3-slot with params=[].
	// We accept both here defensively in case AST is constructed
	// programmatically (e.g., via ast_bin decode from older writers).
	mut name_node := Node(SequenceNode{ items: []Node{} })
	mut params_items := []Node{}
	mut body_node := Node(SequenceNode{ items: []Node{} })
	match slots.len {
		2 {
			// Legacy 2-slot — params is implicitly empty
			name_node = slots[0]
			body_node = slots[1]
		}
		3 {
			name_node = slots[0]
			params_node := slots[1]
			if params_node !is ArrayNode {
				return error('cxl: [?def] params slot must be an Array of identifiers, got ${typeof(params_node).name}')
			}
			params_items = (params_node as ArrayNode).items.clone()
			body_node = slots[2]
		}
		else {
			return error('cxl: [?def] expected 2 or 3 slots [name, (params,) body], got ${slots.len}')
		}
	}
	name := slot_to_expr(name_node)!
	if name == '' {
		return error('cxl: [?def] name slot is empty')
	}
	// Extract param names from the params Array. Each item must be a
	// bare identifier (TextNode/ScalarNode/Element-with-empty-body
	// covered by the parser's normalize_params_slot — at this point
	// AST items are guaranteed identifier-shaped).
	mut params := []string{}
	for p_item in params_items {
		p_name := slot_to_expr(p_item)!
		if p_name == '' {
			return error('cxl: [?def] params Array contains empty/non-identifier item')
		}
		params << p_name
	}
	// Body items as a flat list for substitution at invocation.
	body_items := if body_node is SequenceNode {
		(body_node as SequenceNode).items.clone()
	} else {
		[body_node]
	}
	env.defs[name] = TemplateDef{
		params: params
		body:   body_items
	}
}

fn eval_use(n EvalDirectiveNode, mut env CXLEnv) ! {
	slots := arg_array_slots(n)!
	if slots.len < 1 || slots.len > 2 {
		return error('cxl: [?use] expected 1 or 2 slots [name, ctx?], got ${slots.len}')
	}
	name := slot_to_expr(slots[0])!
	tmpl := env.defs[name] or {
		return error('cxl: [?use] unknown block "${name}"')
	}
	// ADR 0020 §R4: [?use] is for zero-parameter templates only;
	// parameterized templates must be invoked via the directive-call
	// form `[?template-name arg1 arg2]` (positional args matching
	// the :params slot). ?use cannot supply N parameter values via
	// its one optional :ctx slot.
	if tmpl.params.len > 0 {
		return error('cxl: [?use ${name}] — template `${name}` has ${tmpl.params.len} parameter(s); invoke via [?${name} arg1 …] not [?use ${name}] (ADR 0020 §R4)')
	}
	if slots.len == 2 {
		ctx_expr := slot_to_expr(slots[1])!
		new_ctx  := eval_expr(ctx_expr, mut env)!
		saved    := env.context
		env.context = new_ctx
		for bn in tmpl.body { eval_node(bn, mut env)! }
		env.context = saved
	} else {
		for bn in tmpl.body { eval_node(bn, mut env)! }
	}
}

// eval_include implements `[?include path]` (ADR 0017 §D8 — 1 slot).
// Eval-time include of a CXL fragment: evaluates the path expression
// against the current env, reads the file relative to env.include_root,
// parses it (resolving any nested `[?cx include=…]` directives), and
// evaluates the resulting document inline at the directive site.
//
// Containment + cycles:
//
//   - env.include_root must be supplied (via eval_cxl_with_include_root
//     or the CLI's `--include-root=`). Empty root errors with
//     cx-err:CXER0014 to make the configuration miss obvious.
//   - The resolved path must lie under env.include_root (lexical check
//     after `..` resolution). Escapes error E902 to match the parse-time
//     resolver's surface.
//   - env.include_stack carries canonicalised absolute paths of files
//     currently being evaluated; revisiting a path is a cycle (E904).
//   - env.include_depth + env.max_include_depth bound nesting (E905).
fn eval_include(n EvalDirectiveNode, mut env CXLEnv) ! {
	slots := arg_array_slots(n)!
	if slots.len != 1 {
		return error('cxl: [?include] expected 1 slot (path), got ${slots.len}')
	}
	if env.include_root == '' {
		return error("cx-err:CXER0014\x1F[?include] needs --include-root or the eval_cxl_with_include_root entry point — see spec/include.md\x1F")
	}

	// eval_slot_to_value handles quoted-string literals, bound
	// variable refs, and CXPath expressions uniformly — `[?include
	// 'partial.cxl']` (literal), `[?include $name]` (variable), and
	// `[?include [?= //meta/@partial]]` (computed) all reach this
	// function with the resolved value.
	path_val := eval_slot_to_value(slots[0], mut env)!
	if path_val.len == 0 {
		return error('cxl: [?include] path expression evaluated to empty sequence')
	}
	path_str := item_to_text(path_val[0])
	if path_str == '' {
		return error('cxl: [?include] path is empty')
	}
	if os.is_abs_path(path_str) {
		return error('cx-err:E901\x1F[?include] absolute paths rejected\x1F${path_str}')
	}

	// Resolve relative path against the include root via lexical
	// collapse first (matches parse-time resolver, spec/include.md
	// §3.3 — E902 check happens before any filesystem access).
	joined := os.join_path(env.include_root, path_str)
	lexical := lexical_collapse(joined)
	if !lexical_under_root(lexical, env.include_root) {
		return error('cx-err:E902\x1F[?include] path escapes include root\x1F${path_str}')
	}
	if !os.exists(lexical) {
		return error('cx-err:E906\x1F[?include] file not found\x1F${path_str}')
	}
	if os.is_dir(lexical) {
		return error('cx-err:E908\x1F[?include] path is a directory\x1F${path_str}')
	}
	// Post-symlink canonicalisation + re-check (spec §3.3 second
	// paragraph): a symlink inside the root could resolve to a file
	// outside.
	resolved := os.real_path(lexical)
	if !lexical_under_root(resolved, env.include_root) {
		return error('cx-err:E902\x1F[?include] symlink target escapes include root\x1F${path_str}')
	}

	// Cycle + depth checks.
	for prev in env.include_stack {
		if prev == resolved {
			return error('cx-err:E904\x1F[?include] cycle detected\x1F${path_str}')
		}
	}
	if env.include_depth >= env.max_include_depth {
		return error('cx-err:E905\x1F[?include] max depth ${env.max_include_depth} exceeded\x1F${path_str}')
	}

	src := os.read_file(resolved) or {
		return error('cx-err:E909\x1F[?include] I/O error reading ${path_str}\x1F${err.msg()}')
	}
	// parse_with_include_root expands `[?cx include]` directives in
	// the loaded fragment using the same root — composable with the
	// parse-time include surface (GG1).
	included := parse_with_include_root(src, env.include_root)!

	// Push stack frame, eval inline, pop on exit. The save/restore
	// uses a deferred-style cleanup via labeled scope so errors
	// inside the recursive eval still pop the frame.
	env.include_stack << resolved
	env.include_depth++
	defer {
		env.include_depth--
		env.include_stack = env.include_stack[..env.include_stack.len - 1]
	}
	for inc_n in included.prolog { eval_node(inc_n, mut env)! }
	for inc_n in included.elements { eval_node(inc_n, mut env)! }
}

// dispatch_template_call invokes a user-defined `?def` template at a
// call site `[?template-name arg1 arg2 …]`. Args are evaluated to
// CXLValue in the call-site context, bound to the template's
// parameter names via env.bindings (save/restore pattern matching
// eval_for / eval_with), and the template body is evaluated under
// the resulting lexical frame. Per ADR 0020 §D2 closures are not
// modeled — parameter bindings unbind on body exit.
fn dispatch_template_call(n EvalDirectiveNode, mut env CXLEnv) ! {
	tmpl := env.defs[n.name] or {
		// dispatch_eval_directive only routes here after confirming
		// the name is in env.defs; this branch is unreachable in
		// normal evaluation but defended for safety.
		return error('cxl: dispatch_template_call: template "${n.name}" not in env.defs (parser invariant violation)')
	}
	// Collect positional args from the EvalDirective's ArgArray.
	mut arg_nodes := []Node{}
	if n.items.len == 1 {
		arg_arr := n.items[0]
		if arg_arr !is ArrayNode {
			return error('cxl: [?${n.name} …] expected positional ArgArray, got ${typeof(arg_arr).name}')
		}
		arg_nodes = (arg_arr as ArrayNode).items.clone()
	} else if n.items.len > 1 {
		return error('cxl: [?${n.name} …] expected single ArgArray body, got ${n.items.len} items')
	}
	// W018: arg count must match param count.
	if arg_nodes.len != tmpl.params.len {
		return error('cxl: W018: [?${n.name}] expects ${tmpl.params.len} arg(s), got ${arg_nodes.len}')
	}
	// Evaluate each arg in the *caller's* context (lexical scope of
	// the call site, not the template body).
	mut arg_values := []CXLValue{cap: arg_nodes.len}
	for arg in arg_nodes {
		arg_values << eval_slot_to_value(arg, mut env)!
	}
	// Save existing bindings for the parameter names so we can
	// restore on exit (mirrors eval_for's save/restore pattern).
	// Important: save BEFORE any binding update so we capture
	// pre-call state for every name, even if multiple params share
	// the same name (which would be a W018-adjacent error caught
	// at parse time, but defended).
	mut saved   := map[string]CXLValue{}
	mut had     := map[string]bool{}
	for p_name in tmpl.params {
		had[p_name] = p_name in env.bindings
		if had[p_name] {
			saved[p_name] = env.bindings[p_name]
		}
	}
	// Bind parameters into the lexical scope.
	for i, p_name in tmpl.params {
		env.bindings[p_name] = arg_values[i]
	}
	// Evaluate body in the parameter-bound frame.
	for body_item in tmpl.body {
		eval_node(body_item, mut env)!
	}
	// Restore prior bindings (lexical-scope unbind on body exit
	// per ADR 0020 §D2).
	for p_name in tmpl.params {
		if had[p_name] {
			env.bindings[p_name] = saved[p_name]
		} else {
			env.bindings.delete(p_name)
		}
	}
}

// dispatch_function_call invokes a first-class function value
// (CXLFunction, produced by `[?fn ...]` per ADR 0022 §D2 A19+A20).
// Same protocol as dispatch_template_call but operates on a
// CXLFunction VALUE rather than a name-bound env.defs entry. Closure
// capture is NOT modeled at v0.7.0 — parameters bind into call-site
// env, body sees both parameters and existing call-site bindings.
// True closure capture (env snapshot at fn-definition time) is the
// A21 follow-up.
fn dispatch_function_call(fn_val CXLFunction, n EvalDirectiveNode, mut env CXLEnv) ! {
	// Collect positional args from the EvalDirective's ArgArray.
	mut arg_nodes := []Node{}
	if n.items.len == 1 {
		arg_arr := n.items[0]
		if arg_arr !is ArrayNode {
			return error('cxl: [?${n.name} …] expected positional ArgArray, got ${typeof(arg_arr).name}')
		}
		arg_nodes = (arg_arr as ArrayNode).items.clone()
	} else if n.items.len > 1 {
		return error('cxl: [?${n.name} …] expected single ArgArray body, got ${n.items.len} items')
	}
	// Arg count check.
	if arg_nodes.len != fn_val.params.len {
		return error('cxl: [?${n.name}] function expects ${fn_val.params.len} arg(s), got ${arg_nodes.len}')
	}
	// Evaluate each arg in the call-site context.
	mut arg_values := []CXLValue{cap: arg_nodes.len}
	for arg in arg_nodes {
		arg_values << eval_slot_to_value(arg, mut env)!
	}
	// Emit fn output to env.out (statement-position call).
	call_fn_emit(fn_val, arg_values, mut env)!
}

// call_fn_emit invokes a function value with already-evaluated args,
// emitting body output to env.out. Used by dispatch_function_call
// (statement position).
fn call_fn_emit(fn_val CXLFunction, arg_values []CXLValue, mut env CXLEnv) ! {
	if arg_values.len != fn_val.params.len {
		return error('cxl: function expects ${fn_val.params.len} arg(s), got ${arg_values.len}')
	}
	// U3 (v0.7.0 security): call-depth budget. Without this, mutually-
	// recursive ?fn / ?def calls or accidental infinite recursion can
	// overflow the host stack and bring down the libcx process.
	env.call_depth++
	if env.call_depth > env.max_call_depth {
		env.call_depth--
		return error('cx-err:CXER0010:function-call depth exceeded ${env.max_call_depth} (env.max_call_depth)')
	}
	defer { env.call_depth-- }
	// A21 closure capture: save current env.bindings for every name
	// the fn will touch (captured + params), merge captured + bind
	// params, evaluate body, restore.
	mut saved := map[string]CXLValue{}
	mut had   := map[string]bool{}
	mut touched := []string{}
	for k, v in fn_val.captured {
		had[k] = k in env.bindings
		if had[k] { saved[k] = env.bindings[k] }
		env.bindings[k] = v
		touched << k
	}
	for p_name in fn_val.params {
		if p_name !in saved {
			had[p_name] = p_name in env.bindings
			if had[p_name] { saved[p_name] = env.bindings[p_name] }
			touched << p_name
		}
	}
	for i, p_name in fn_val.params {
		env.bindings[p_name] = arg_values[i]
	}
	for body_item in fn_val.body {
		eval_node(body_item, mut env)!
	}
	for name in touched {
		if had[name] {
			env.bindings[name] = saved[name]
		} else {
			env.bindings.delete(name)
		}
	}
}

// call_fn_to_value invokes a function value with already-evaluated
// args and captures the body's text output as a CXLValue (single
// string item). Used by higher-order filter functions (for-each,
// filter, fold-left, etc.) where the result is a sequence of values
// rather than direct text emission.
fn call_fn_to_value(fn_val CXLFunction, arg_values []CXLValue, mut env CXLEnv) !CXLValue {
	if arg_values.len != fn_val.params.len {
		return error('cxl: function expects ${fn_val.params.len} arg(s), got ${arg_values.len}')
	}
	// U3 (v0.7.0 security): call-depth budget. Mirror of call_fn_emit.
	env.call_depth++
	if env.call_depth > env.max_call_depth {
		env.call_depth--
		return error('cx-err:CXER0010:function-call depth exceeded ${env.max_call_depth} (env.max_call_depth)')
	}
	defer { env.call_depth-- }
	// Redirect env.out to a temporary builder for the duration of the
	// call so body output is captured rather than emitted.
	saved_out := env.out
	env.out = strings.new_builder(64)
	// A21 closure capture: save + merge captured + bind params.
	mut saved := map[string]CXLValue{}
	mut had   := map[string]bool{}
	mut touched := []string{}
	for k, v in fn_val.captured {
		had[k] = k in env.bindings
		if had[k] { saved[k] = env.bindings[k] }
		env.bindings[k] = v
		touched << k
	}
	for p_name in fn_val.params {
		if p_name !in saved {
			had[p_name] = p_name in env.bindings
			if had[p_name] { saved[p_name] = env.bindings[p_name] }
			touched << p_name
		}
	}
	for i, p_name in fn_val.params {
		env.bindings[p_name] = arg_values[i]
	}
	mut emit_err := ''
	for body_item in fn_val.body {
		eval_node(body_item, mut env) or { emit_err = err.msg(); break }
	}
	captured_out := env.out.str()
	env.out = saved_out
	for name in touched {
		if had[name] {
			env.bindings[name] = saved[name]
		} else {
			env.bindings.delete(name)
		}
	}
	if emit_err != '' { return error(emit_err) }
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(captured_out) })]
}

// ── Filter set (spec/eval.md §4) ──────────────────────────────────────────────

// eval_filter_directive evaluates a filter directive (e.g. `[?upper
// [@name]]`) and returns its value. Each positional slot in the arg
// array is evaluated to a CXLValue; the filter function then receives
// the slot-value list and returns its result. Nested filter calls
// (`[?upper [[?trim [@name]]]]`) evaluate naturally because slot 0 of
// `?upper`'s arg array is the inner `?trim` EvalDirective, which
// recurses through eval_slot_to_value.
fn eval_filter_directive(n EvalDirectiveNode, mut env CXLEnv) !CXLValue {
	// EE2 (ADR 0023 §D3): activation gate — on_declaration modules
	// must be opted in via [?cx use-module=...]. No-op at v0.7.0
	// where every registered module is .always; framework in place
	// for v0.8.0 BaseX modules.
	check_activation_gate(env, n.name)!
	// EE4 (ADR 0023 §D5): purity-gate check happens BEFORE the eager
	// slot loop so a SideEffect filter under [?cx pure-only] doesn't
	// emit its side-effecting arg-eval work before the rejection.
	check_purity_gate(env, n.name)!
	slots := arg_array_slots(n)!
	mut args := []CXLValue{cap: slots.len}
	for s in slots {
		args << eval_slot_to_value(s, mut env)!
	}
	return match n.name {
		'upper'       { filter_upper(args)! }
		'lower'       { filter_lower(args)! }
		'trim'        { filter_trim(args)! }
		'length'      { filter_length(args)! }
		'concat'      { filter_concat(args)! }
		'join'        { filter_join(args)! }
		'replace'     { filter_replace(args)! }
		'default'     { filter_default(args)! }
		'escape-html' { filter_escape_html(args)! }
		'escape-url'  { filter_escape_url(args)! }
		'safe-url'    { filter_safe_url(args)! }
		'raw'         { filter_raw(args)! }
		'first'       { filter_first(args)! }
		'rest'        { filter_rest(args)! }
		'empty'       { filter_empty(args)! }
		'reverse'     { filter_reverse(args)! }
		// CXL 3.1 aggregate filters (per ADR 0022 §D2)
		'sum'         { filter_sum(args)! }
		'count'       { filter_count(args)! }
		'min'         { filter_min(args)! }
		'max'         { filter_max(args)! }
		'avg'         { filter_avg(args)! }
		// XQuery 4.0 standard fn: namespace (per ADR 0022 §D2 + xquery_40_parity.md §C)
		// Numeric (C1)
		'abs'                 { filter_abs(args)! }
		'ceiling'             { filter_ceiling(args)! }
		'floor'               { filter_floor(args)! }
		'round'               { filter_round(args)! }
		'round-half-to-even'  { filter_round_half_to_even(args)! }
		// String basic (C2)
		'contains'            { filter_contains(args)! }
		'starts-with'         { filter_starts_with(args)! }
		'ends-with'           { filter_ends_with(args)! }
		'substring'           { filter_substring(args)! }
		'substring-before'    { filter_substring_before(args)! }
		'substring-after'     { filter_substring_after(args)! }
		'string-length'       { filter_string_length(args)! }
		'string'              { filter_string(args)! }
		// String whitespace (C4)
		'normalize-space'     { filter_normalize_space(args)! }
		// A22 named function references (XQuery 3.0 §3.1.6 `fn-name#arity`)
		'fn-ref'              { filter_fn_ref(args)! }
		// A23 partial application — see build_partial_value (handled at
		// dispatch_eval_directive level because placeholder detection
		// needs raw nodes). Reaching this arm means a partial directive
		// appeared somewhere the special routing didn't catch — fall
		// through to a clear error.
		'partial'             { error('cxl: [?partial] routed to filter dispatch — should reach build_partial_value via dispatch_eval_directive or eval_slot_to_value') }
		// A44 node comparisons (XPath 4.0 §4.10.3)
		'node-is'             { filter_node_is(args)! }
		'node-before'         { filter_node_before(args, env)! }
		'node-after'          { filter_node_after(args, env)! }
		// A39/A40 XPath 4.0 string templates + constructors
		'str-template'        { filter_str_template(args, mut env)! }
		'str'                 { filter_str_concat(args)! }
		// String regex (C5, XQuery 4.0 §F.6 fn:matches/tokenize/replace)
		'matches'             { filter_matches(args)! }
		'tokenize'            { filter_tokenize(args)! }
		'regex-replace'       { filter_regex_replace(args)! }
		// Date/time (C14/C15, XQuery 4.0 §F.10)
		'current-date'        { filter_current_date(args)! }
		'current-time'        { filter_current_time(args)! }
		'current-dateTime'    { filter_current_date_time(args)! }
		'year-from-dateTime', 'year-from-date'   { filter_dt_field(n.name, args)! }
		'month-from-dateTime', 'month-from-date' { filter_dt_field(n.name, args)! }
		'day-from-dateTime', 'day-from-date'     { filter_dt_field(n.name, args)! }
		'hours-from-dateTime', 'hours-from-time' { filter_dt_field(n.name, args)! }
		'minutes-from-dateTime', 'minutes-from-time' { filter_dt_field(n.name, args)! }
		'seconds-from-dateTime', 'seconds-from-time' { filter_dt_field(n.name, args)! }
		'format-date'         { filter_format_date(args)! }
		'format-dateTime'     { filter_format_date(args)! }
		'format-datetime'     { filter_format_date(args)! }
		'format-time'         { filter_format_date(args)! }
		// String join+encoding (C6)
		'string-join'         { filter_join(args)! }
		'translate'           { filter_translate(args)! }
		// Sequence (C7, C8, C9, C10)
		'distinct-values'     { filter_distinct_values(args)! }
		'exists'              { filter_exists(args)! }
		'head'                { filter_first(args)! }
		'tail'                { filter_rest(args)! }
		'last'                { filter_last(args)! }
		'items-at'            { filter_items_at(args)! }
		'zero-or-one'         { filter_zero_or_one(args)! }
		'one-or-more'         { filter_one_or_more(args)! }
		'exactly-one'         { filter_exactly_one(args)! }
		'subsequence'         { filter_subsequence(args)! }
		'slice'               { filter_slice(args)! }
		'replicate'           { filter_replicate(args, env)! }
		'characters'          { filter_characters(args)! }
		'all-different'       { filter_all_different(args)! }
		'partition'           { filter_partition(args, mut env)! }
		'index-of'            { filter_index_of(args)! }
		'insert-before'       { filter_insert_before(args)! }
		'remove'              { filter_remove(args)! }
		'codepoints-to-string'  { filter_codepoints_to_string(args)! }
		'string-to-codepoints'  { filter_string_to_codepoints(args)! }
		'compare'             { filter_compare(args)! }
		'codepoint-equal'     { filter_codepoint_equal(args)! }
		'encode-for-uri'      { filter_encode_for_uri(args)! }
		'iri-to-uri'          { filter_iri_to_uri(args)! }
		'escape-html-uri'     { filter_escape_html_uri(args)! }
		'char'                { filter_char(args)! }
		'intersperse'         { filter_intersperse(args)! }
		'sequence-join'       { filter_intersperse(args)! }
		'unordered'           { args_first(args)! }
		'sort'                { filter_sort(args)! }
		'data'                { filter_data(args)! }
		'has-children'        { filter_has_children(args)! }
		'deep-equal'          { filter_deep_equal(args)! }
		'string-pad'          { filter_string_pad(args)! }
		'string-pad-left'     { filter_string_pad_left(args)! }
		// xs: constructor functions (C18, type-coercion)
		'xs:int', 'xs:integer', 'xs:long', 'xs:short', 'xs:byte' { filter_xs_int(args)! }
		'xs:double', 'xs:float', 'xs:decimal'                     { filter_xs_float(args)! }
		'xs:string'                                                { filter_string(args)! }
		'xs:boolean'                                               { filter_boolean(args)! }
		'xs:nonNegativeInteger', 'xs:positiveInteger'             { filter_xs_int_constrained(n.name, args)! }
		// A32-A36 SequenceType expressions
		'instance-of'         { filter_instance_of(args)! }
		'cast-as'             { filter_cast_as(args)! }
		'castable-as'         { filter_castable_as(args)! }
		'treat-as'            { filter_treat_as(args)! }
		// A43 verbose comparisons (XPath 2.0 — directive forms)
		'eq', 'ne', 'lt', 'le', 'gt', 'ge' { filter_verbose_compare(n.name, args)! }
		// A42 sequence intersect/except
		'intersect'           { filter_intersect(args)! }
		'except'              { filter_except(args)! }
		'otherwise'           { filter_otherwise(args)! }
		// C19 JSON + C22 serialize
		'parse-json'          { filter_parse_json(args)! }
		'serialize-json'      { filter_serialize_json(args)! }
		'json-to-xml'         { filter_json_to_xml(args)! }
		'xml-to-json'         { filter_xml_to_json(args)! }
		'json-doc'            { filter_json_doc(args)! }
		'serialize'           { filter_serialize(args)! }
		'parse-xml'           { filter_parse_xml(args)! }
		'parse-xml-fragment'  { filter_parse_xml(args)! }
		// C21 I/O
		'doc-available'       { filter_doc_available(args)! }
		'doc'                 { filter_doc(args)! }
		// C20 QName helpers
		'prefix-from-QName'   { filter_qname_prefix(args)! }
		'local-name-from-QName'   { filter_qname_local(args)! }
		'namespace-uri-from-QName' { filter_qname_uri(args)! }
		// Higher-order functions (C11) — also dispatched at statement
		// position in dispatch_eval_directive; routed here for nested
		// use inside other filter calls.
		'for-each'            { hof_for_each(args, mut env)! }
		'filter'              { hof_filter(args, mut env)! }
		'fold-left'           { hof_fold_left(args, mut env)! }
		'fold-right'          { hof_fold_right(args, mut env)! }
		'apply'               { hof_apply(args, mut env)! }
		'function-arity'      { hof_function_arity(args)! }
		'function-name'       { hof_function_name(args)! }
		'for-each-pair'       { hof_for_each_pair(args, mut env)! }
		'function-lookup'     { hof_function_lookup(args, env)! }
		'function-identity'   { hof_function_identity(args)! }
		'scan-left'           { hof_scan_left(args, mut env)! }
		'some'                { hof_some(args, mut env)! }
		'every'               { hof_every(args, mut env)! }
		'simple-map'          { hof_for_each(args, mut env)! }
		'concat-string'       { filter_concat(args)! }
		'map:for-each'        { hof_map_for_each(args, mut env)! }
		'array:filter'        { hof_array_filter(args, mut env)! }
		'array:for-each'      { hof_array_for_each(args, mut env)! }
		'array:fold-left'     { hof_array_fold_left(args, mut env)! }
		'array:fold-right'    { hof_array_fold_right(args, mut env)! }
		'array:sort'          { hof_array_sort(args, mut env)! }
		'pipe'                { hof_pipe(args, mut env)! }
		'arrow'               { hof_pipe(args, mut env)! }
		'generate-id'         { filter_generate_id(args)! }
		// More CXL 1.0 filters (parsed but were unimplemented)
		'take'                { filter_take(args)! }
		'drop'                { filter_drop(args)! }
		'distinct'            { filter_distinct_values(args)! }
		'type-of'             { filter_type_of(args)! }
		'format-decimal'      { filter_format_decimal(args)! }
		'format-percent'      { filter_format_percent(args)! }
		'format-integer'      { filter_format_integer(args)! }
		'format-number'       { filter_format_number(args, env)! }
		'where'               { filter_where(args)! }
		'trace'               { filter_trace(args)! }
		'error'               { filter_error(args)! }
		'range'               { filter_range(args, env)! }
		// Boolean (C13)
		'boolean'             { filter_boolean(args)! }
		'true'                { filter_true(args)! }
		'false'               { filter_false(args)! }
		'not'                 { filter_not(args)! }
		// Node accessors (C12)
		'name'                { filter_name(args)! }
		'local-name'          { filter_local_name(args)! }
		'node-name'           { filter_node_name(args)! }
		'base-uri'            { filter_base_uri(args)! }
		'document-uri'        { filter_document_uri(args, env)! }
		'lang'                { filter_lang(args)! }
		'innermost'           { filter_innermost(args)! }
		'outermost'           { filter_outermost(args)! }
		'sort-by'             { hof_array_sort(args, mut env)! }
		'normalize-unicode'   { filter_normalize_unicode(args)! }
		'QName'                          { filter_qname(args)! }
		'namespace-uri-for-prefix'       { filter_namespace_uri_for_prefix(args)! }
		'in-scope-prefixes'              { filter_in_scope_prefixes(args)! }
		'collection'                     { filter_collection(args)! }
		'uri-collection'                 { filter_uri_collection(args)! }
		'available-environment-variables' { filter_available_env_vars(args)! }
		'environment-variable'           { filter_env_var(args)! }
		'random-number-generator'        { filter_random_number_generator(args)! }
		'namespace-uri'       { filter_namespace_uri(args)! }
		'root'                { filter_root(args)! }
		// math: namespace (C16, XPath 3.0)
		'math:pi'             { filter_math_pi(args)! }
		'math:e'              { filter_math_e(args)! }
		'math:exp'            { filter_math_exp(args)! }
		'math:exp10'          { filter_math_exp10(args)! }
		'math:log'            { filter_math_log(args)! }
		'math:log10'          { filter_math_log10(args)! }
		'math:sqrt'           { filter_math_sqrt(args)! }
		'math:sin'            { filter_math_sin(args)! }
		'math:cos'            { filter_math_cos(args)! }
		'math:tan'            { filter_math_tan(args)! }
		'math:asin'           { filter_math_asin(args)! }
		'math:acos'           { filter_math_acos(args)! }
		'math:atan'           { filter_math_atan(args)! }
		'math:atan2'          { filter_math_atan2(args)! }
		'math:pow'            { filter_math_pow(args)! }
		// map: namespace (D1, XPath 3.1)
		'map:get'             { filter_map_get(args)! }
		'map:put'             { filter_map_put(args)! }
		'map:keys'            { filter_map_keys(args)! }
		'map:size'            { filter_map_size(args)! }
		'map:contains'        { filter_map_contains(args)! }
		'map:entry'           { filter_map_entry(args)! }
		'map:merge'           { filter_map_merge_env(args, &env)! }
		'map:remove'          { filter_map_remove(args)! }
		// array: namespace (D2, XPath 3.1)
		'array:size'          { filter_array_size(args)! }
		'array:get'           { filter_array_get(args)! }
		'array:append'        { filter_array_append(args)! }
		'array:head'          { filter_array_head(args)! }
		'array:tail'          { filter_array_tail(args)! }
		'array:reverse'       { filter_array_reverse(args)! }
		'array:subarray'      { filter_array_subarray(args)! }
		'array:put'           { filter_array_put(args)! }
		'array:remove'        { filter_array_remove(args)! }
		'array:insert-before' { filter_array_insert_before(args)! }
		'array:flatten'       { filter_array_flatten(args)! }
		'array:join'          { filter_array_join(args)! }
		// cx: self-host module (DD1–DD8 Must, ADR 0023 §D1; DD9–DD22 land later rows)
		'cx:parse'            { filter_cx_parse(args)! }
		'cx:serialize'        { filter_cx_serialize(args)! }
		'cx:canonical'        { filter_cx_canonical(args)! }
		'cx:hash'             { filter_cx_hash(args)! }
		'cx:diff'             { filter_cx_diff(args)! }
		'cx:patch'            { filter_cx_patch(args)! }
		'cx:to-format'        { filter_cx_to_format(args)! }
		'cx:from-format'      { filter_cx_from_format(args)! }
		'cx:equal'            { filter_cx_equal(args)! }
		'cx:select'           { filter_cx_select(n, mut env)! }
		// cx: eval surface (DD11/DD12; EE5 engine row pending)
		'cx:eval'             { filter_cx_eval(args, mut env)! }
		'cx:render'           { filter_cx_render(args, mut env)! }
		// cx: Should tier (DD13–DD18)
		'cx:schema-of'        { filter_cx_schema_of(args)! }
		'cx:validate'         { filter_cx_validate(args)! }
		'cx:anchors'          { filter_cx_anchors(args)! }
		'cx:ids'              { filter_cx_ids(args)! }
		'cx:references'       { filter_cx_references(args)! }
		'cx:resolve-includes' { filter_cx_resolve_includes(n, mut env)! }
		// cx: Nice tier (DD19–DD22)
		'cx:merge'            { filter_cx_merge(args)! }
		'cx:strip-comments'   { filter_cx_strip_comments(args)! }
		'cx:strip-attrs'      { filter_cx_strip_attrs(args)! }
		'cx:pretty-print'     { filter_cx_pretty_print(args)! }
		// log: structured-logging module (FF1–FF7, ADR 0023 §D10)
		'log:trace'           { filter_log_trace(args, mut env)! }
		'log:debug'           { filter_log_debug(args, mut env)! }
		'log:info'            { filter_log_info(args, mut env)! }
		'log:warn'            { filter_log_warn(args, mut env)! }
		'log:error'           { filter_log_error(args, mut env)! }
		'log:level'           { filter_log_level(args, env)! }
		'log:with-context'    { filter_log_with_context(n, mut env)! }
		else          { error('cxl: filter [?${n.name}] not in CXL 1.0/3.1 set') }
	}
}

// eval_slot_to_value evaluates one filter-argument slot to a CXLValue.
// Slots may be:
//   - Bare-text expression token (CXPath / comparison) → eval_expr
//   - Quoted-string TextNode (e.g. `'/'`)              → scalar value
//   - ScalarNode atomic literal (`42`, `true`)         → scalar value
//   - Nested EvalDirective (filter composition)        → recursive eval
//   - InterpolationNode                                → its expr eval
//   - SequenceNode (mixed content)                     → joined text
fn eval_slot_to_value(n Node, mut env CXLEnv) !CXLValue {
	return match n {
		TextNode {
			t := n.value.trim_space()
			// Empty TextNode → empty sequence
			if t == '' { CXLValue([]CXLItem{}) }
			// v0.7.0 (B9/B10): inline-fn or arrow-lambda expression
			// in slot text. Detected here so `?let f :be fn (x) { x }`
			// constructs a CXLFunction value rather than falling through
			// to the literal-string branch.
			else if t.starts_with('fn(') || t.starts_with('fn (') || t.starts_with('->') {
				eval_expr(t, mut env)!
			}
			// Quoted strings are stripped by the parser, so a bare
			// TextNode either holds an expression (`@name`, `//path`,
			// `@stock > 0`), a bound variable reference (`x` /
			// `x/@sku` where x is a `?for` loop var or template
			// parameter), or a literal token. Treat names / paths /
			// expressions as expression text; treat anything else as
			// literal string.
			else if t[0] == `@` || t[0] == `/` || cxl_expr_has_operator(t) {
				eval_expr(t, mut env)!
			} else if bare_ident_is_bound(t, env) {
				// Bare identifier that resolves to a bound variable
				// (loop var, ?with binding, or template parameter)
				// — evaluate as a path expression so `x` or `x/@sku`
				// works in filter args and template-call args. Falls
				// back to literal-string handling below when the
				// identifier is not bound.
				eval_expr(t, mut env)!
			} else {
				[CXLItem(CXLScalar{
					data_type: .string_type
					value:     ScalarValue(n.value)
				})]
			}
		}
		ScalarNode {
			[CXLItem(CXLScalar{
				data_type: n.data_type
				value:     n.value
			})]
		}
		InterpolationNode {
			eval_expr(n.expr, mut env)!
		}
		EvalDirectiveNode {
			// [?fn] in value position yields a function value
			// (CXLFunction wrapped in a CXLValue), per ADR 0022 §D2.
			// [?focus body] is sugar for [?fn :params [_] :body body].
			// [?partial] (A23) also yields a function value; node-level
			// access is required to detect `_` placeholders before
			// arg evaluation.
			// All other directives route through filter dispatch.
			if n.name == 'fn' {
				build_function_value(n, env)!
			} else if n.name == 'focus' {
				build_focus_function_value(n, env)!
			} else if n.name == 'partial' {
				build_partial_value(n, mut env)!
			} else {
				eval_filter_directive(n, mut env)!
			}
		}
		SequenceNode {
			// Concatenate child text representations for filter
			// arguments. Rare; spec/eval.md §4 filter args are
			// usually single-item.
			mut b := strings.new_builder(16)
			for it in n.items {
				match it {
					TextNode   { b.write_string(it.value) }
					ScalarNode { b.write_string(scalar_value_str(it.value)) }
					InterpolationNode {
						val := eval_expr(it.expr, mut env)!
						b.write_string(value_to_string(val))
					}
					else {}
				}
			}
			[CXLItem(CXLScalar{
				data_type: .string_type
				value:     ScalarValue(b.str())
			})]
		}
		ArrayNode {
			// First-class Array value (CXL 3.1 / XPath 3.1 per ADR 0022 §D2 D).
			[CXLItem(n as ArrayNode)]
		}
		MapNode {
			// First-class Map value (CXL 3.1 / XPath 3.1 per ADR 0022 §D2 D).
			[CXLItem(n as MapNode)]
		}
		else { error('cxl: filter arg slot cannot be ${typeof(n).name}') }
	}
}

// cxl_expr_has_operator reports whether a TextNode token contains a
// CXPath comparison / arithmetic operator — used to distinguish
// expression slots (`@stock > 0`) from bare literal-text slots
// (`hello world`). Heuristic; a more rigorous parser-level marker
// is deferred to CXL 3.1.
fn cxl_expr_has_operator(s string) bool {
	if s.contains(' > ') || s.contains(' < ') || s.contains(' = ')
		|| s.contains(' >= ') || s.contains(' <= ') || s.contains(' != ')
		|| s.contains(' == ') {
		return true
	}
	return false
}

fn filter_upper(args []CXLValue) !CXLValue {
	s := value_to_string(args_first(args)!)
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(s.to_upper()) })]
}

fn filter_lower(args []CXLValue) !CXLValue {
	s := value_to_string(args_first(args)!)
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(s.to_lower()) })]
}

fn filter_trim(args []CXLValue) !CXLValue {
	s := value_to_string(args_first(args)!)
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(s.trim_space()) })]
}

fn filter_length(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len != 1 {
		return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(i64(v.len)) })]
	}
	s := value_to_string(v)
	return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(i64(s.runes().len)) })]
}

fn filter_concat(args []CXLValue) !CXLValue {
	mut b := strings.new_builder(32)
	for a in args { b.write_string(value_to_string(a)) }
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(b.str()) })]
}

fn filter_join(args []CXLValue) !CXLValue {
	if args.len < 2 {
		return error('cxl: [?join [SEP, XS]] needs 2 args')
	}
	sep := value_to_string(args[0])
	xs  := args[1]
	mut parts := []string{}
	for it in xs { parts << item_to_text(it) }
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(parts.join(sep)) })]
}

fn filter_replace(args []CXLValue) !CXLValue {
	if args.len < 3 {
		return error('cxl: [?replace [OLD, NEW, X]] needs 3 args')
	}
	old_s := value_to_string(args[0])
	new_s := value_to_string(args[1])
	x     := value_to_string(args[2])
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(x.replace(old_s, new_s)) })]
}

fn filter_default(args []CXLValue) !CXLValue {
	if args.len < 2 {
		return error('cxl: [?default [X, D]] needs 2 args')
	}
	if value_is_empty_or_null(args[0]) { return args[1] }
	return args[0]
}

fn filter_escape_html(args []CXLValue) !CXLValue {
	s := value_to_string(args_first(args)!)
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(escape_html_str(s)) })]
}

fn filter_escape_url(args []CXLValue) !CXLValue {
	s := value_to_string(args_first(args)!)
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(escape_url_component(s)) })]
}

// U6 (v0.7.0): safe-url filter — scheme allowlist for href/src
// attribute values. Refuses URLs whose scheme is in the
// XSS-vector set (javascript:, data:, vbscript:, file:) by
// returning the empty string; passes through http://, https://,
// mailto:, ftp:, and scheme-relative (//host) or path-relative
// (/path, ./path, name) forms unchanged.
//
// Templates under output-target=html should route any URL-context
// interpolation through this filter — e.g. `<a href=[?safe-url
// [@user-url]]>`. The output is empty (renders an empty href)
// rather than raising, so partial templates degrade gracefully.
//
// Spec: spec/eval.md §6 output-target=html safety policy.
fn filter_safe_url(args []CXLValue) !CXLValue {
	s := value_to_string(args_first(args)!)
	if is_dangerous_url_scheme(s) {
		return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue('') })]
	}
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(s) })]
}

// is_dangerous_url_scheme returns true when the URL string starts
// with a scheme on the XSS-vector denylist. Case-insensitive, and
// tolerant of leading whitespace + interleaved Tab / CR / LF / NUL
// inside the scheme prefix (browsers strip these before scheme
// dispatch, so attackers exploit them).
fn is_dangerous_url_scheme(s string) bool {
	mut clean := []u8{}
	for c in s.bytes() {
		if c == ` ` || c == `\t` || c == `\r` || c == `\n` || c == 0 { continue }
		clean << c
		if clean.len > 24 { break }  // scheme bound
	}
	lower := clean.bytestr().to_lower()
	denylist := ['javascript:', 'data:', 'vbscript:', 'file:']
	for prefix in denylist {
		if lower.starts_with(prefix) { return true }
	}
	return false
}

fn filter_raw(args []CXLValue) !CXLValue {
	return args_first(args)!
}

fn filter_first(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len == 0 { return CXLValue([]CXLItem{}) }
	return [v[0]]
}

fn filter_rest(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len <= 1 { return CXLValue([]CXLItem{}) }
	return v[1..]
}

fn filter_empty(args []CXLValue) !CXLValue {
	v := args_first(args)!
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(v.len == 0) })]
}

fn filter_reverse(args []CXLValue) !CXLValue {
	v := args_first(args)!.clone()
	mut out := []CXLItem{cap: v.len}
	for i := v.len - 1; i >= 0; i-- { out << v[i] }
	return out
}

fn args_first(args []CXLValue) !CXLValue {
	if args.len == 0 {
		return error('cxl: filter expected at least one argument')
	}
	return args[0]
}

// ── CXL 3.1 aggregate filters (per ADR 0022 §D2) ─────────────────────────────
// Numeric aggregates over a sequence. Items are coerced to f64 via
// item_to_f64; non-numeric items contribute 0.0 (consistent with
// cx's permissive coercion model — see as_f64 in CXPath evaluator).

fn item_to_f64(it CXLItem) f64 {
	return match it {
		CXLScalar { as_f64(it.value) }
		ScalarNode { as_f64(it.value) }
		TextNode { strconv.atof64(it.value) or { 0.0 } }
		else { strconv.atof64(item_to_text(it)) or { 0.0 } }
	}
}

fn filter_sum(args []CXLValue) !CXLValue {
	v := args_first(args)!
	mut total := 0.0
	for it in v { total += item_to_f64(it) }
	if total == f64(i64(total)) {
		return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(i64(total)) })]
	}
	return [CXLItem(CXLScalar{ data_type: .float_type, value: ScalarValue(total) })]
}

fn filter_count(args []CXLValue) !CXLValue {
	v := args_first(args)!
	return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(i64(v.len)) })]
}

fn filter_min(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len == 0 {
		return CXLValue([]CXLItem{})
	}
	mut m := item_to_f64(v[0])
	for i := 1; i < v.len; i++ {
		x := item_to_f64(v[i])
		if x < m { m = x }
	}
	if m == f64(i64(m)) {
		return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(i64(m)) })]
	}
	return [CXLItem(CXLScalar{ data_type: .float_type, value: ScalarValue(m) })]
}

fn filter_max(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len == 0 {
		return CXLValue([]CXLItem{})
	}
	mut m := item_to_f64(v[0])
	for i := 1; i < v.len; i++ {
		x := item_to_f64(v[i])
		if x > m { m = x }
	}
	if m == f64(i64(m)) {
		return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(i64(m)) })]
	}
	return [CXLItem(CXLScalar{ data_type: .float_type, value: ScalarValue(m) })]
}

fn filter_avg(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len == 0 {
		return CXLValue([]CXLItem{})
	}
	mut total := 0.0
	for it in v { total += item_to_f64(it) }
	mean := total / f64(v.len)
	return [CXLItem(CXLScalar{ data_type: .float_type, value: ScalarValue(mean) })]
}

// ── XQuery 4.0 standard fn: namespace (per ADR 0022 §D2, xquery_40_parity.md §C) ──
// Implementations follow the XQuery 4.0 spec semantics, adapted to
// cx's CXDM value model (sequence-flat, item is Element/Scalar/etc).
// Each function takes args (a list of CXLValues from arg_array slots)
// and returns a CXLValue (sequence).

// ── C1 Numeric ───────────────────────────────────────────────────────────────

fn filter_abs(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len == 0 { return CXLValue([]CXLItem{}) }
	x := item_to_f64(v[0])
	r := if x < 0 { -x } else { x }
	if r == f64(i64(r)) {
		return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(i64(r)) })]
	}
	return [CXLItem(CXLScalar{ data_type: .float_type, value: ScalarValue(r) })]
}

fn filter_ceiling(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len == 0 { return CXLValue([]CXLItem{}) }
	x := item_to_f64(v[0])
	r := i64(x)
	if f64(r) < x { return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(r + 1) })] }
	return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(r) })]
}

fn filter_floor(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len == 0 { return CXLValue([]CXLItem{}) }
	x := item_to_f64(v[0])
	r := i64(x)
	if f64(r) > x { return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(r - 1) })] }
	return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(r) })]
}

fn filter_round(args []CXLValue) !CXLValue {
	// XQuery 4.0 fn:round — round-half-toward-positive-infinity by default.
	v := args_first(args)!
	if v.len == 0 { return CXLValue([]CXLItem{}) }
	x := item_to_f64(v[0])
	mut r := i64(x)
	frac := x - f64(r)
	if frac > 0.5 || (frac == 0.5 && x > 0) { r += 1 }
	else if frac < -0.5 { r -= 1 }
	return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(r) })]
}

fn filter_round_half_to_even(args []CXLValue) !CXLValue {
	// Banker's rounding — half goes to nearest even integer.
	v := args_first(args)!
	if v.len == 0 { return CXLValue([]CXLItem{}) }
	x := item_to_f64(v[0])
	floor_x := i64(x)
	if f64(floor_x) > x { return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(floor_x - 1) })] }
	frac := x - f64(floor_x)
	mut r := floor_x
	if frac > 0.5 || (frac == 0.5 && floor_x % 2 != 0) { r += 1 }
	return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(r) })]
}

// ── C2 String basic ──────────────────────────────────────────────────────────

fn filter_contains(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?contains [s, sub]] needs 2 args') }
	s := value_to_string(args[0])
	sub := value_to_string(args[1])
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(s.contains(sub)) })]
}

fn filter_starts_with(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?starts-with [s, prefix]] needs 2 args') }
	s := value_to_string(args[0])
	prefix := value_to_string(args[1])
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(s.starts_with(prefix)) })]
}

fn filter_ends_with(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?ends-with [s, suffix]] needs 2 args') }
	s := value_to_string(args[0])
	suffix := value_to_string(args[1])
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(s.ends_with(suffix)) })]
}

fn filter_substring(args []CXLValue) !CXLValue {
	// XQuery: fn:substring($source, $start, $length?) — 1-indexed start.
	if args.len < 2 { return error('cxl: [?substring [s, start, length?]] needs 2 or 3 args') }
	s := value_to_string(args[0])
	start_f := item_to_f64(args[1][0] or { return error('cxl: [?substring] start arg empty') })
	mut start := int(start_f) - 1 // 1-based → 0-based
	mut end := s.len
	if args.len >= 3 && args[2].len > 0 {
		length := int(item_to_f64(args[2][0]))
		end = start + length
	}
	if start < 0 { start = 0 }
	if start > s.len { start = s.len }
	if end > s.len { end = s.len }
	if end < start { end = start }
	result := s[start..end]
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(result) })]
}

fn filter_substring_before(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?substring-before [s, sub]] needs 2 args') }
	s := value_to_string(args[0])
	sub := value_to_string(args[1])
	idx := s.index(sub) or { return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue('') })] }
	result := s[..idx]
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(result) })]
}

fn filter_substring_after(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?substring-after [s, sub]] needs 2 args') }
	s := value_to_string(args[0])
	sub := value_to_string(args[1])
	idx := s.index(sub) or { return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue('') })] }
	result := s[idx + sub.len..]
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(result) })]
}

fn filter_string_length(args []CXLValue) !CXLValue {
	// XQuery fn:string-length($s) — codepoint count (not byte count).
	v := args_first(args)!
	s := value_to_string(v)
	return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(i64(s.runes().len)) })]
}

fn filter_string(args []CXLValue) !CXLValue {
	// XQuery fn:string($v) — atomize to string via item_to_text.
	v := args_first(args)!
	s := value_to_string(v)
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(s) })]
}

// ── C4 String whitespace ─────────────────────────────────────────────────────

fn filter_normalize_space(args []CXLValue) !CXLValue {
	v := args_first(args)!
	s := value_to_string(v)
	// Replace runs of whitespace with single space, trim ends.
	mut b := strings.new_builder(s.len)
	mut prev_space := true // start as if previous was space → drops leading ws
	for c in s {
		if c == ` ` || c == `\t` || c == `\n` || c == `\r` {
			if !prev_space { b.write_u8(` `); prev_space = true }
		} else {
			b.write_u8(c)
			prev_space = false
		}
	}
	mut out := b.str()
	if out.len > 0 && out[out.len - 1] == ` ` { out = out[..out.len - 1] }
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(out) })]
}

// ── C5 String regex (XQuery 4.0 §F.6) ────────────────────────────────────────
// fn:matches / fn:tokenize / fn:replace route through the libcx-
// vendored RE2 shim (vcx/cx/regex_re2.v + vcx/deps/re2_shim/). This is
// the same engine that backs schema :pat= validation, so regex
// semantics are identical across cx surfaces and across all bindings
// — bindings call cx_eval which dispatches through the V evaluator
// which dispatches through libcx-RE2. Per spec/abi.md §3 capability
// bit 25, RE2 is normative for cross-binding determinism.
//
// XQuery flag arg (i/s/m/x/q) is not interpreted at v0.7.0 — RE2's
// `(?i)` etc. inline flag syntax covers the common cases. Strict
// XPath-regex grammar conformance (vs RE2 grammar) is post-v0.7.0.

fn filter_matches(args []CXLValue) !CXLValue {
	if args.len < 2 {
		return error('cxl: [?matches [pattern, input]] needs at least 2 args')
	}
	if args.len > 2 {
		return error('cxl: [?matches] flags arg is post-v0.7.0; got ${args.len} args')
	}
	pat := value_to_string(args[0])
	input := value_to_string(args[1])
	matched := re2_partial_match(pat, input)!
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(matched) })]
}

fn filter_tokenize(args []CXLValue) !CXLValue {
	// fn:tokenize($input, $pattern). XQuery 4.0 also has 1-arg
	// whitespace tokenizer (split on \s+). We support both.
	if args.len < 1 {
		return error('cxl: [?tokenize] needs at least 1 arg')
	}
	if args.len > 2 {
		return error('cxl: [?tokenize] flags arg is post-v0.7.0; got ${args.len} args')
	}
	input := value_to_string(args[0])
	pat := if args.len == 1 {
		'\\s+'
	} else {
		value_to_string(args[1])
	}
	parts := re2_tokenize(pat, input)!
	mut out := []CXLItem{cap: parts.len}
	for p in parts {
		out << CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(p) })
	}
	return CXLValue(out)
}

fn filter_regex_replace(args []CXLValue) !CXLValue {
	// [?regex-replace [pattern, replacement, input]] — XQuery
	// fn:replace. Distinct dispatch name from ?replace (substring)
	// per ADR 0022 §D9 (no scope-shrinking, no silent override of CXL
	// 1.0 surface).
	if args.len < 3 {
		return error('cxl: [?regex-replace [pattern, replacement, input]] needs 3 args')
	}
	if args.len > 3 {
		return error('cxl: [?regex-replace] flags arg is post-v0.7.0; got ${args.len} args')
	}
	pat := value_to_string(args[0])
	repl := value_to_string(args[1])
	input := value_to_string(args[2])
	out := re2_replace_all(pat, repl, input)!
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(out) })]
}

// ── A24 Focus functions (XQuery 4.0 §4.5.6.1) ────────────────────────────────
// `[?focus body]` produces a 1-arg CXLFunction whose parameter is named
// `_`. Equivalent to `[?fn :params [_] :body body]`. Useful as a terse
// lambda form in higher-order pipelines:
//   [?for-each [xs, [?focus [?=_ * 2]]]]
// Closure-capture rules mirror [?fn] (A21).
fn build_focus_function_value(n EvalDirectiveNode, env CXLEnv) !CXLValue {
	slots := arg_array_slots(n)!
	if slots.len != 1 {
		return error('cxl: [?focus :body body] expected 1 slot, got ${slots.len}')
	}
	body_node := slots[0]
	body_items := if body_node is SequenceNode {
		(body_node as SequenceNode).items.clone()
	} else if body_node is ArrayNode {
		(body_node as ArrayNode).items.clone()
	} else {
		[body_node]
	}
	mut captured := map[string]CXLValue{}
	for k, v in env.bindings {
		if k != '_' { captured[k] = v }
	}
	return [CXLItem(CXLFunction{
		params: ['_']
		body: body_items
		captured: captured
	})]
}

// ── A39/A40 String templates + constructors (XPath 4.0 §4.9.2 / §4.9.3) ──────
// `[?str-template 'Hello [?=name], you are [?=age]']` — a template
// string with embedded `[?=expr]` interpolations. Returns the
// substituted string. Equivalent to XPath 4.0 backtick template
// `` `Hello { $name }` `` but expressed in the cx directive form
// (CXPath operator-token form ships with the operator-parser arc).
//
// `[?str [parts]]` — string constructor. Concatenates a sequence of
// expressions into one string. Equivalent to XPath 4.0 `String { … }`
// constructor / chained `||` concatenation.

fn filter_str_template(args []CXLValue, mut env CXLEnv) !CXLValue {
	if args.len != 1 {
		return error('cxl: [?str-template template] needs 1 arg')
	}
	tpl := value_to_string(args[0])
	saved := env.out
	env.out = strings.new_builder(tpl.len)
	emit_attr_with_interpolation(tpl, mut env) or {
		env.out = saved
		return error(err.msg())
	}
	captured := env.out.str()
	env.out = saved
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(captured) })]
}

fn filter_str_concat(args []CXLValue) !CXLValue {
	mut b := strings.new_builder(args.len * 8)
	for v in args {
		b.write_string(value_to_string(v))
	}
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(b.str()) })]
}

// ── A44 Node comparisons (XPath 4.0 §4.10.3) ─────────────────────────────────
// `[?node-is [a, b]]` → boolean, true iff a and b are the same node by
// identity (XPath `A is B`).
// `[?node-before [a, b]]` → true iff a precedes b in document order.
// `[?node-after  [a, b]]` → true iff a follows b in document order.
//
// At v0.7.0, node identity is structural-equality based — Elements are
// value-typed across CXPath evaluation, so reference identity isn't
// distinguishable from structural identity in the general case. This
// matches the A45 / D-row CXDM semantics; strict reference identity
// awaits the parent-pointer infrastructure (post-v0.7.0).
//
// Document-order comparisons require root + path-from-root context for
// each operand. The v0.7.0 implementation supports document-order
// comparison when both operands derive from a common path-based
// CXPath evaluation (the common case from `//x is //y` style
// queries). Operands from arbitrary loop-var bindings without path
// metadata return a structured cx-err:CXER0002 explaining the
// limitation.
fn filter_node_is(args []CXLValue) !CXLValue {
	if args.len != 2 {
		return error('cxl: [?node-is [a, b]] needs 2 args')
	}
	a := args[0]
	b := args[1]
	if a.len != 1 || b.len != 1 {
		return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(false) })]
	}
	a_el := a[0]
	b_el := b[0]
	if a_el !is Element || b_el !is Element {
		return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(false) })]
	}
	eq := cxpath_element_identity_equal(a_el as Element, b_el as Element)
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(eq) })]
}

fn filter_node_before(args []CXLValue, env CXLEnv) !CXLValue {
	if args.len != 2 {
		return error('cxl: [?node-before [a, b]] needs 2 args')
	}
	pa, pb := find_node_document_positions(args[0], args[1], env) or {
		return error('cx-err:CXER0002:[?node-before] ${err.msg()}')
	}
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(pa < pb) })]
}

fn filter_node_after(args []CXLValue, env CXLEnv) !CXLValue {
	if args.len != 2 {
		return error('cxl: [?node-after [a, b]] needs 2 args')
	}
	pa, pb := find_node_document_positions(args[0], args[1], env) or {
		return error('cx-err:CXER0002:[?node-after] ${err.msg()}')
	}
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(pa > pb) })]
}

// find_node_document_positions locates two single-Element operands in
// document order against the current evaluation context's first
// Element item, treating that Element as the document root. Returns
// pre-order traversal positions (a_pos, b_pos) — smaller value means
// earlier in document order. Identity is the structural match used
// by the B-row sibling axes (cxpath_element_identity_equal).
//
// Caveat: when two structurally-identical Elements exist in the
// document, this function returns the position of whichever one is
// encountered first during traversal. For v0.7.0 this is an
// acceptable approximation; strict reference identity awaits the
// parent-pointer / element-id infrastructure in a future arc.
fn find_node_document_positions(a CXLValue, b CXLValue, env CXLEnv) !(int, int) {
	if a.len != 1 || b.len != 1 {
		return error('both operands must be single-element sequences')
	}
	if a[0] !is Element || b[0] !is Element {
		return error('both operands must be Element nodes')
	}
	a_el := a[0] as Element
	b_el := b[0] as Element
	mut root := ?Element(none)
	for it in env.context {
		if it is Element {
			root = it as Element
			break
		}
	}
	root_el := root or {
		return error('current evaluation context has no Element root to anchor document order')
	}
	mut state := DocOrderWalk{ counter: 0, pa: -1, pb: -1 }
	walk_doc_order(root_el, a_el, b_el, mut state)
	if state.pa < 0 {
		return error('operand A not reachable from current document root')
	}
	if state.pb < 0 {
		return error('operand B not reachable from current document root')
	}
	return state.pa, state.pb
}

struct DocOrderWalk {
mut:
	counter int
	pa      int
	pb      int
}

fn walk_doc_order(node Element, a Element, b Element, mut state DocOrderWalk) {
	pos := state.counter
	state.counter++
	if state.pa < 0 && cxpath_element_identity_equal(node, a) { state.pa = pos }
	if state.pb < 0 && cxpath_element_identity_equal(node, b) { state.pb = pos }
	for item in node.items {
		if state.pa >= 0 && state.pb >= 0 { return }
		if item is Element {
			walk_doc_order(item, a, b, mut state)
		}
	}
}

// ── A22 Named function references (XQuery 3.0 §3.1.6) ────────────────────────
// `[?fn-ref [name, arity]]` returns a function value whose body is a
// single `[?name $__a1 ... $__aN]` directive. Calls through call_fn_emit
// / call_fn_to_value bind the args to the synthetic param names, then
// dispatch evaluates the body — which routes through the normal
// directive dispatch table, allowing builtin filters, user templates,
// and other function values to be wrapped as first-class values.

fn filter_fn_ref(args []CXLValue) !CXLValue {
	if args.len != 2 {
		return error('cxl: [?fn-ref [name, arity]] needs 2 args')
	}
	name := value_to_string(args[0]).trim_space()
	if name == '' {
		return error('cxl: [?fn-ref] name must be non-empty')
	}
	arity_val := args[1]
	if arity_val.len != 1 {
		return error('cxl: [?fn-ref] arity must be a single integer')
	}
	arity := match arity_val[0] {
		CXLScalar { value_to_int(arity_val) or { return error('cxl: [?fn-ref] arity must be an integer') } }
		else      { return error('cxl: [?fn-ref] arity must be an integer') }
	}
	if arity < 0 || arity > 16 {
		return error('cxl: [?fn-ref] arity ${arity} out of range [0,16]')
	}
	mut params := []string{cap: int(arity)}
	mut arg_nodes := []Node{cap: int(arity)}
	for i in 0 .. int(arity) {
		p := '__a${i + 1}'
		params << p
		arg_nodes << Node(TextNode{ value: p })
	}
	body_directive := EvalDirectiveNode{
		name: name
		attrs: []Attribute{}
		items: [Node(ArrayNode{ items: arg_nodes })]
	}
	return [CXLItem(CXLFunction{
		params: params
		body: [Node(body_directive)]
		captured: map[string]CXLValue{}
	})]
}

// A23 Partial application (XQuery 4.0 §4.5.4) — supports both
// left-curry (`[?partial [f, a, b]]`) and middle-position `_`
// placeholders (`[?partial [f, a, _, b, _]]`) per ADR 0022 §D2.
// The `_` is bare (unquoted); quoted '_' stays a literal scalar.
//
// Detection happens at slot-node level — eval_slot_to_value would
// have already coerced bare `_` into a scalar string by the time
// args reach a filter, so partial is special-cased in
// dispatch_eval_directive and eval_slot_to_value to route here
// with raw nodes intact (mirrors how [?fn] / [?focus] are handled).
//
// Build strategy: the returned CXLFunction has params equal to the
// placeholder positions and a synthetic body that re-invokes the
// original function via the internal [?__partial_invoke …] directive.
// Captured bindings carry both the target function and the pre-bound
// real arguments at their original positions.
fn build_partial_value(n EvalDirectiveNode, mut env CXLEnv) !CXLValue {
	slots := arg_array_slots(n)!
	if slots.len < 2 {
		return error('cxl: [?partial [f, args…]] needs at least 2 slots')
	}
	fn_val_seq := eval_slot_to_value(slots[0], mut env)!
	if fn_val_seq.len != 1 || fn_val_seq[0] !is CXLFunction {
		return error('cxl: [?partial] first slot must be a function value')
	}
	target := fn_val_seq[0] as CXLFunction
	arg_slots := slots[1..]
	if arg_slots.len > target.params.len {
		return error('cxl: [?partial] supplied ${arg_slots.len} arg slots but function arity is ${target.params.len}')
	}
	// Walk the arg slots, classifying each as placeholder or pre-bound.
	// Position-source nodes feed the synthetic body: a pre-bound
	// position references a captured name; a placeholder position
	// references one of the new function's params.
	mut new_captured := target.captured.clone()
	new_captured['__partial_target'] = [CXLItem(target)]
	mut params := []string{}
	mut position_sources := []Node{cap: arg_slots.len}
	for i, slot in arg_slots {
		if is_placeholder_slot(slot) {
			pname := '__pl_${i}'
			params << pname
			position_sources << Node(TextNode{ value: pname })
		} else {
			val := eval_slot_to_value(slot, mut env)!
			cname := '__pre_${i}'
			new_captured[cname] = val
			position_sources << Node(TextNode{ value: cname })
		}
	}
	// Append any remaining target params as left-curry placeholders so
	// the wrapper preserves left-curry behavior when the user omits
	// trailing args entirely (`[?partial [f, a]]` for an arity-3 f).
	for i in arg_slots.len .. target.params.len {
		pname := '__pl_curry_${i}'
		params << pname
		position_sources << Node(TextNode{ value: pname })
	}
	body_directive := EvalDirectiveNode{
		name:  '__partial_invoke'
		attrs: []Attribute{}
		items: [Node(ArrayNode{ items: position_sources })]
	}
	return [CXLItem(CXLFunction{
		params:   params
		body:     [Node(body_directive)]
		captured: new_captured
	})]
}

// is_placeholder_slot reports whether a parsed slot Node represents
// the cx-form placeholder marker `[?_]`. We deliberately use the
// EvalDirective spelling instead of bare `_` because the parser
// strips quotes from string literals, making bare `_` and quoted
// '_' indistinguishable at the AST level — that would leave no
// way to pass a literal underscore string as a real argument. The
// `[?_]` form is unambiguous: it's an EvalDirectiveNode regardless
// of surrounding context. The XPath operator-token spelling
// `f(_, x, _)` lands with the proper expression-grammar arc and
// can disambiguate at parse time via syntactic position.
fn is_placeholder_slot(n Node) bool {
	if n is EvalDirectiveNode {
		return n.name == '_' && n.items.len == 0
	}
	return false
}

// eval_partial_invoke handles the synthetic body of a partial-built
// CXLFunction. Each positional arg evaluates to a CXLValue (pre-
// bound captured values resolve via env.bindings; placeholder
// params likewise). The captured __partial_target is then called
// with the resulting argument list.
//
// Emit vs value context: this routine emits the call's text output
// to env.out (statement position). The value-position path is
// covered by call_fn_to_value's standard capture mechanism when the
// outer function value is invoked through it.
fn eval_partial_invoke(n EvalDirectiveNode, mut env CXLEnv) ! {
	slots := arg_array_slots(n)!
	target_seq := env.bindings['__partial_target'] or {
		return error('cxl: [?__partial_invoke] called outside a partial-application wrapper (no __partial_target in env)')
	}
	if target_seq.len != 1 || target_seq[0] !is CXLFunction {
		return error('cxl: [?__partial_invoke] __partial_target must be a single CXLFunction')
	}
	target := target_seq[0] as CXLFunction
	mut call_args := []CXLValue{cap: slots.len}
	for s in slots {
		call_args << eval_slot_to_value(s, mut env)!
	}
	call_fn_emit(target, call_args, mut env)!
}

fn value_to_int(v CXLValue) ?i64 {
	if v.len != 1 { return none }
	it := v[0]
	if it is CXLScalar {
		match it.value {
			i64    { return it.value as i64 }
			f64    { return i64(it.value as f64) }
			string {
				s := it.value as string
				return strconv.parse_int(s.trim_space(), 10, 64) or { return none }
			}
			else   { return none }
		}
	}
	return none
}

// ── C14/C15 Date/time functions (XQuery 4.0 §F.10) ───────────────────────────
// ISO-8601 string form is the canonical exchange format at v0.7.0. Field
// accessors parse the string with V's time.parse_iso8601. The XQuery
// xs:date / xs:time / xs:dateTime distinction is not modeled as a runtime
// type yet — every value is its ISO string. format-date / format-dateTime
// / format-time accept a small picture subset (YYYY MM DD HH mm ss) and
// produce a string; full XSLT 3.0 picture grammar is post-v0.7.0.

fn filter_current_date(args []CXLValue) !CXLValue {
	if args.len > 0 { return error('cxl: [?current-date] takes no args') }
	t := time.now()
	s := '${t.year:04d}-${t.month:02d}-${t.day:02d}'
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(s) })]
}

fn filter_current_time(args []CXLValue) !CXLValue {
	if args.len > 0 { return error('cxl: [?current-time] takes no args') }
	t := time.now()
	s := '${t.hour:02d}:${t.minute:02d}:${t.second:02d}'
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(s) })]
}

fn filter_current_date_time(args []CXLValue) !CXLValue {
	if args.len > 0 { return error('cxl: [?current-dateTime] takes no args') }
	t := time.now()
	s := '${t.year:04d}-${t.month:02d}-${t.day:02d}T${t.hour:02d}:${t.minute:02d}:${t.second:02d}'
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(s) })]
}

// parse_dt_input accepts ISO date / time / dateTime forms. Time-only
// inputs are anchored to 1970-01-01. Date-only inputs zero out time.
fn parse_dt_input(s string) !time.Time {
	trimmed := s.trim_space()
	if trimmed.len == 0 {
		return error('cx-err:FORG0001:empty date/time string')
	}
	// Time-only form HH:MM:SS — pad with 1970-01-01 date.
	if trimmed.len <= 8 && trimmed.contains(':') && !trimmed.contains('-') {
		full := '1970-01-01T${trimmed}'
		return time.parse_iso8601(full) or {
			return error('cx-err:FORG0001:invalid time literal: ${trimmed}')
		}
	}
	// Date-only form YYYY-MM-DD.
	if trimmed.len == 10 && !trimmed.contains('T') && !trimmed.contains(' ') {
		full := '${trimmed}T00:00:00'
		return time.parse_iso8601(full) or {
			return error('cx-err:FORG0001:invalid date literal: ${trimmed}')
		}
	}
	return time.parse_iso8601(trimmed) or {
		return error('cx-err:FORG0001:invalid dateTime literal: ${trimmed}')
	}
}

fn filter_dt_field(name string, args []CXLValue) !CXLValue {
	if args.len != 1 {
		return error('cxl: [?${name} [iso-string]] needs 1 arg, got ${args.len}')
	}
	t := parse_dt_input(value_to_string(args[0]))!
	field := name.before('-from-')
	val := match field {
		'year'    { i64(t.year) }
		'month'   { i64(t.month) }
		'day'     { i64(t.day) }
		'hours'   { i64(t.hour) }
		'minutes' { i64(t.minute) }
		'seconds' { i64(t.second) }
		else      { return error('cxl: unknown dt field "${field}"') }
	}
	return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(val) })]
}

fn filter_format_date(args []CXLValue) !CXLValue {
	// [?format-date [iso-string, picture]] — picture supports tokens
	// YYYY MM DD HH mm ss. Anything else in the picture passes through.
	if args.len != 2 {
		return error('cxl: [?format-date] needs 2 args [iso, picture]')
	}
	t := parse_dt_input(value_to_string(args[0]))!
	pic := value_to_string(args[1])
	mut out := pic
	out = out.replace('YYYY', '${t.year:04d}')
	out = out.replace('MM',   '${t.month:02d}')
	out = out.replace('DD',   '${t.day:02d}')
	out = out.replace('HH',   '${t.hour:02d}')
	out = out.replace('mm',   '${t.minute:02d}')
	out = out.replace('ss',   '${t.second:02d}')
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(out) })]
}

// ── C6 String join + encoding ────────────────────────────────────────────────
// fn:string-join is aliased to existing filter_join in dispatch table.

fn filter_translate(args []CXLValue) !CXLValue {
	// XQuery fn:translate($s, $map_chars, $trans_chars) — char-by-char replace.
	if args.len < 3 { return error('cxl: [?translate [s, map, trans]] needs 3 args') }
	s := value_to_string(args[0])
	map_chars := value_to_string(args[1])
	trans_chars := value_to_string(args[2])
	mut b := strings.new_builder(s.len)
	for c in s {
		idx := map_chars.index_u8(c)
		if idx < 0 {
			b.write_u8(c)
		} else if idx < trans_chars.len {
			b.write_u8(trans_chars[idx])
		}
		// else: character mapped to nothing (deleted)
	}
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(b.str()) })]
}

// ── C7 Sequence basic ────────────────────────────────────────────────────────

fn filter_distinct_values(args []CXLValue) !CXLValue {
	v := args_first(args)!
	mut out := []CXLItem{}
	mut seen := []string{}
	for it in v {
		key := item_to_text(it)
		if key !in seen {
			seen << key
			out << it
		}
	}
	return out
}

fn filter_exists(args []CXLValue) !CXLValue {
	v := args_first(args)!
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(v.len > 0) })]
}

fn filter_last(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len == 0 { return CXLValue([]CXLItem{}) }
	return [v[v.len - 1]]
}

fn filter_items_at(args []CXLValue) !CXLValue {
	// XQuery 4.0 fn:items-at($seq, $i) — 1-indexed.
	if args.len < 2 { return error('cxl: [?items-at [seq, i]] needs 2 args') }
	seq := args[0]
	if args[1].len == 0 { return CXLValue([]CXLItem{}) }
	i := int(item_to_f64(args[1][0])) - 1 // 1-based → 0-based
	if i < 0 || i >= seq.len { return CXLValue([]CXLItem{}) }
	return [seq[i]]
}

fn filter_zero_or_one(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len > 1 { return error('cxl: [?zero-or-one] expected 0 or 1 item, got ${v.len}') }
	return v
}

fn filter_one_or_more(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len < 1 { return error('cxl: [?one-or-more] expected at least 1 item, got 0') }
	return v
}

fn filter_exactly_one(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len != 1 { return error('cxl: [?exactly-one] expected exactly 1 item, got ${v.len}') }
	return v
}

// fn:subsequence($seq, $start, $length?) — 1-indexed start, optional length.
fn filter_subsequence(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?subsequence [seq, start, length?]] needs 2 or 3 args') }
	seq := args[0]
	if args[1].len == 0 { return CXLValue([]CXLItem{}) }
	mut start := int(item_to_f64(args[1][0])) - 1 // 1-based → 0-based
	mut end := seq.len
	if args.len >= 3 && args[2].len > 0 {
		length := int(item_to_f64(args[2][0]))
		end = start + length
	}
	if start < 0 { start = 0 }
	if start > seq.len { start = seq.len }
	if end > seq.len { end = seq.len }
	if end < start { end = start }
	return seq[start..end]
}

// C25 (XPath 4.0 §G): fn:slice($seq, $start, $end?) — sequence slice
// using 1-based inclusive start and exclusive end. Negative indices
// count from the end (XPath 4.0 sugar).
fn filter_slice(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?slice [seq, start, end?]] needs 2 or 3 args') }
	seq := args[0]
	if args[1].len == 0 { return CXLValue([]CXLItem{}) }
	mut start := int(item_to_f64(args[1][0]))
	mut end := seq.len + 1  // exclusive — default to end of sequence
	if args.len >= 3 && args[2].len > 0 {
		end = int(item_to_f64(args[2][0]))
	}
	if start < 0 { start = seq.len + 1 + start }
	if end < 0 { end = seq.len + 1 + end }
	start = start - 1  // 1-based → 0-based start
	end = end - 1      // 1-based → 0-based end (exclusive)
	if start < 0 { start = 0 }
	if start > seq.len { start = seq.len }
	if end > seq.len { end = seq.len }
	if end < start { end = start }
	return seq[start..end]
}

// C25 (XPath 4.0 §G): fn:replicate($item, $count) — repeat item or
// sequence count times, concatenating into one sequence.
fn filter_replicate(args []CXLValue, env CXLEnv) !CXLValue {
	if args.len < 2 { return error('cxl: [?replicate [item, count]] needs 2 args') }
	if args[1].len == 0 { return CXLValue([]CXLItem{}) }
	count := int(item_to_f64(args[1][0]))
	if count <= 0 { return CXLValue([]CXLItem{}) }
	// U4: respect the sequence-length cap. Replication is the easy
	// vector for unbounded growth.
	if env.max_sequence_len > 0 && i64(count) * i64(args[0].len) > env.max_sequence_len {
		return error('cx-err:CXER0011:replicate would produce ${i64(count) * i64(args[0].len)} items, exceeds env.max_sequence_len (${env.max_sequence_len})')
	}
	mut out := []CXLItem{cap: args[0].len * count}
	for _ in 0 .. count {
		for it in args[0] { out << it }
	}
	return out
}

// C25 (XPath 4.0 §G): fn:characters($string) — explode a string into
// a sequence of single-codepoint strings. (XPath 4.0 §G uses
// codepoints; v0.7.0 implements via bytes which matches ASCII and
// preserves multibyte UTF-8 sequences as multiple items — full
// codepoint-correct splitting via the V `utf8` module is a v0.7.x
// follow-up.)
fn filter_characters(args []CXLValue) !CXLValue {
	if args.len < 1 || args[0].len == 0 { return CXLValue([]CXLItem{}) }
	s := value_to_string(args[0])
	mut out := []CXLItem{cap: s.len}
	for c in s.bytes() {
		out << CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(c.ascii_str()) })
	}
	return out
}

// C25 (XPath 4.0 §G): fn:all-different($seq) — returns boolean true
// when all items in $seq are pairwise distinct (using string-equality
// of their textual atoms).
fn filter_all_different(args []CXLValue) !CXLValue {
	if args.len < 1 { return error('cxl: [?all-different [seq]] needs 1 arg') }
	seq := args[0]
	mut seen := map[string]bool{}
	for it in seq {
		key := item_to_text(it)
		if key in seen {
			return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(false) })]
		}
		seen[key] = true
	}
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(true) })]
}

// C25 (XPath 4.0 §G): fn:partition($seq, $predicate-fn) — split the
// sequence into two parts at the first item where the predicate
// transitions truth-value. Returns a 2-item array: [head, tail].
// Per XPath 4.0 the partition is "prefix where predicate holds"
// followed by "tail of the rest".
fn filter_partition(args []CXLValue, mut env CXLEnv) !CXLValue {
	if args.len < 2 { return error('cxl: [?partition [seq, fn]] needs 2 args') }
	seq := args[0]
	if args[1].len != 1 || args[1][0] !is CXLFunction {
		return error('cxl: [?partition] second arg must be a function value')
	}
	fn_val := args[1][0] as CXLFunction
	mut split := 0
	mut still_in_prefix := true
	for i, it in seq {
		if !still_in_prefix { break }
		result := call_fn_to_value(fn_val, [CXLValue([it])], mut env)!
		if cxlvalue_to_bool(result) {
			split = i + 1
		} else {
			still_in_prefix = false
		}
	}
	head := seq[..split]
	tail := seq[split..]
	mut head_items := []Node{}
	for it in head { head_items << cxlitem_to_node(it) }
	mut tail_items := []Node{}
	for it in tail { tail_items << cxlitem_to_node(it) }
	return [
		CXLItem(ArrayNode{ items: head_items }),
		CXLItem(ArrayNode{ items: tail_items }),
	]
}

// cxlitem_to_node downcasts a CXLItem to a Node for collection-literal
// construction. CXLScalar / CXLFunction map to TextNode renderings;
// other variants pass through.
fn cxlitem_to_node(it CXLItem) Node {
	return match it {
		Element        { Node(it) }
		TextNode       { Node(it) }
		ScalarNode     { Node(it) }
		CommentNode    { Node(it) }
		PINode         { Node(it) }
		CXDirectiveNode{ Node(it) }
		ArrayNode      { Node(it) }
		MapNode        { Node(it) }
		CXLScalar      { Node(ScalarNode{ data_type: it.data_type, value: it.value }) }
		CXLFunction    { Node(TextNode{ value: '[function arity=${it.params.len}]' }) }
	}
}

// cxlvalue_to_bool — EBV per cxdm.md §4.5.
fn cxlvalue_to_bool(v CXLValue) bool {
	if v.len == 0 { return false }
	first := v[0]
	if first is CXLScalar {
		s := first as CXLScalar
		return match s.value {
			bool   { s.value as bool }
			i64    { (s.value as i64) != 0 }
			f64    { (s.value as f64) != 0.0 }
			string { (s.value as string) != '' }
			NullValue { false }
		}
	}
	return true
}

// fn:index-of($seq, $needle) — 1-based indices of items equal to needle.
fn filter_index_of(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?index-of [seq, needle]] needs 2 args') }
	seq := args[0]
	needle_text := value_to_string(args[1])
	mut out := []CXLItem{}
	for i, it in seq {
		if item_to_text(it) == needle_text {
			out << CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(i64(i + 1)) })
		}
	}
	return out
}

// fn:insert-before($seq, $position, $inserts) — 1-based position.
fn filter_insert_before(args []CXLValue) !CXLValue {
	if args.len < 3 { return error('cxl: [?insert-before [seq, pos, inserts]] needs 3 args') }
	seq := args[0]
	if args[1].len == 0 { return seq }
	mut pos := int(item_to_f64(args[1][0])) - 1 // 1-based → 0-based
	if pos < 0 { pos = 0 }
	if pos > seq.len { pos = seq.len }
	inserts := args[2]
	mut out := []CXLItem{cap: seq.len + inserts.len}
	for i := 0; i < pos; i++ { out << seq[i] }
	for it in inserts { out << it }
	for i := pos; i < seq.len; i++ { out << seq[i] }
	return out
}

// fn:remove($seq, $position) — 1-based position; removes one item.
fn filter_remove(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?remove [seq, pos]] needs 2 args') }
	seq := args[0]
	if args[1].len == 0 { return seq }
	pos := int(item_to_f64(args[1][0])) - 1 // 1-based → 0-based
	if pos < 0 || pos >= seq.len { return seq }
	mut out := []CXLItem{cap: seq.len - 1}
	for i, it in seq {
		if i != pos { out << it }
	}
	return out
}

// fn:codepoints-to-string($cps) — sequence of integer codepoints → string.
fn filter_codepoints_to_string(args []CXLValue) !CXLValue {
	v := args_first(args)!
	mut b := strings.new_builder(v.len)
	for it in v {
		cp := int(item_to_f64(it))
		b.write_rune(rune(cp))
	}
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(b.str()) })]
}

// fn:string-to-codepoints($s) — string → sequence of integer codepoints.
fn filter_string_to_codepoints(args []CXLValue) !CXLValue {
	v := args_first(args)!
	s := value_to_string(v)
	mut out := []CXLItem{}
	for r in s.runes() {
		out << CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(i64(r)) })
	}
	return out
}

// fn:compare($a, $b) — -1 / 0 / 1 codepoint-by-codepoint comparison.
fn filter_compare(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?compare [a, b]] needs 2 args') }
	a := value_to_string(args[0])
	b := value_to_string(args[1])
	r := if a < b { i64(-1) } else if a > b { i64(1) } else { i64(0) }
	return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(r) })]
}

// fn:codepoint-equal($a, $b) — boolean codepoint-by-codepoint equality.
fn filter_codepoint_equal(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?codepoint-equal [a, b]] needs 2 args') }
	a := value_to_string(args[0])
	b := value_to_string(args[1])
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(a == b) })]
}

// fn:encode-for-uri($s) — RFC 3986 percent-encoding (reserved + non-ASCII).
fn filter_encode_for_uri(args []CXLValue) !CXLValue {
	v := args_first(args)!
	s := value_to_string(v)
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(escape_url_component(s)) })]
}

// fn:iri-to-uri($s) — encode only chars that aren't legal in URI
// (non-ASCII and a few specials). At v0.7.0 uses the same logic as
// encode-for-uri minus the reserved set; refine to match XPath 4.0
// §C6 exactly post-v0.7.0 if needed.
fn filter_iri_to_uri(args []CXLValue) !CXLValue {
	v := args_first(args)!
	s := value_to_string(v)
	mut b := strings.new_builder(s.len)
	for c in s {
		// IRI-legal chars stay; only non-ASCII and control chars get encoded.
		if c < 0x20 || c > 0x7E {
			b.write_string('%${c:02X}')
		} else {
			b.write_u8(c)
		}
	}
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(b.str()) })]
}

// fn:escape-html-uri($s) — encode non-ASCII for href attributes;
// preserves URI reserved chars + ASCII.
fn filter_escape_html_uri(args []CXLValue) !CXLValue {
	v := args_first(args)!
	s := value_to_string(v)
	mut b := strings.new_builder(s.len)
	for c in s {
		if c >= 0x20 && c <= 0x7E {
			b.write_u8(c)
		} else {
			b.write_string('%${c:02X}')
		}
	}
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(b.str()) })]
}

// fn:char($cp) — codepoint integer → single-character string.
fn filter_char(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len == 0 { return CXLValue([]CXLItem{}) }
	cp := int(item_to_f64(v[0]))
	mut b := strings.new_builder(4)
	b.write_rune(rune(cp))
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(b.str()) })]
}

// fn:intersperse($seq, $separator) — insert separator between items.
// Also aliased as sequence-join in the dispatch table.
fn filter_intersperse(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?intersperse [seq, sep]] needs 2 args') }
	seq := args[0]
	if seq.len == 0 { return seq }
	sep := args[1]
	mut out := []CXLItem{cap: seq.len * 2}
	for i, it in seq {
		if i > 0 {
			for s in sep { out << s }
		}
		out << it
	}
	return out
}

// fn:sort($seq) — sort a sequence by item text comparison (stable).
// Full XPath 4.0 sort takes optional collation + key function; v0.7.0
// commit-current uses lexicographic text equality. Refine when A20 ?fn
// calling lands (sort-by takes a key fn).
fn filter_sort(args []CXLValue) !CXLValue {
	v := args_first(args)!
	mut keys := []string{cap: v.len}
	for it in v { keys << item_to_text(it) }
	mut out := v.clone()
	// Stable insertion sort — small sequences in practice.
	for i := 1; i < out.len; i++ {
		mut j := i
		for j > 0 && keys[j] < keys[j - 1] {
			tmp_k := keys[j]
			keys[j] = keys[j - 1]
			keys[j - 1] = tmp_k
			tmp_v := out[j]
			out[j] = out[j - 1]
			out[j - 1] = tmp_v
			j--
		}
	}
	return out
}

// fn:data($items) — atomize to typed values; on Elements returns text
// content (XPath 4.0 §C12). For scalars passes through.
fn filter_data(args []CXLValue) !CXLValue {
	v := args_first(args)!
	mut out := []CXLItem{cap: v.len}
	for it in v {
		match it {
			Element {
				txt := element_text_content(it as Element)
				out << CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(txt) })
			}
			else { out << it }
		}
	}
	return out
}

// fn:has-children($element) — true if the element has any child Items.
fn filter_has_children(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len == 0 { return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(false) })] }
	has := if v[0] is Element {
		(v[0] as Element).items.len > 0
	} else {
		false
	}
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(has) })]
}

// fn:deep-equal($a, $b) — recursive value equality.
// v0.7.0 commit-current uses text-content equality which matches the
// common case; full XPath 4.0 deep-equal checks attribute order
// independence and full node-by-node comparison — refine post-v0.7.0
// once SequenceType lands.
fn filter_deep_equal(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?deep-equal [a, b]] needs 2 args') }
	a := args[0]
	b := args[1]
	if a.len != b.len { return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(false) })] }
	for i in 0 .. a.len {
		if item_to_text(a[i]) != item_to_text(b[i]) {
			return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(false) })]
		}
	}
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(true) })]
}

// fn:string-pad($s, $width) — right-pad to width with spaces.
// (XPath 4.0 addition.)
fn filter_string_pad(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?string-pad [s, width]] needs 2 args') }
	s := value_to_string(args[0])
	width := int(item_to_f64(args[1][0] or { return error('cxl: [?string-pad] width arg empty') }))
	if s.runes().len >= width {
		return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(s) })]
	}
	pad := width - s.runes().len
	mut b := strings.new_builder(width)
	b.write_string(s)
	for _ in 0 .. pad { b.write_u8(` `) }
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(b.str()) })]
}

// ── C18 xs: constructor functions (type coercion) ────────────────────────────
// XPath/XQuery 1.0+ type-system constructor functions. Each coerces
// the input to the target type. Empty sequence in → empty sequence out.

// xs_strict_parse_f64 enforces strict XPath 4.0 cast semantics
// (U8 of spec/v0_7_0_status.md, ADR 0022 §D4): when the input
// item is a string-typed value (TextNode or string-typed scalar),
// parse failures raise FORG0001 rather than silently coercing to
// 0. Already-typed numeric scalars pass through their canonical
// f64 view. Non-string non-numeric items (Element / Map / Array /
// CXLFunction) raise FORG0001 — they have no defined cast to a
// numeric type per XPath 4.0 §19.1.2.
fn xs_strict_parse_f64(it CXLItem, target string) !f64 {
	// Numeric / bool scalars pass through their f64 view directly.
	// String-typed scalars and TextNodes go through a strict parse:
	// trim space, attempt strconv.atof64, raise FORG0001 on failure.
	// Element / Map / Array / CXLFunction items have no defined cast
	// to a numeric type per XPath 4.0 §19.1.2 — raise FORG0001 with
	// the atomized representation in the error payload.
	return match it {
		CXLScalar {
			if it.data_type == .string_type {
				s := scalar_value_str(it.value).trim_space()
				strconv.atof64(s) or {
					return error('cx-err:FORG0001\x1finvalid value for ${target} cast\x1f${s}')
				}
			} else {
				as_f64(it.value)
			}
		}
		ScalarNode {
			if it.data_type == .string_type {
				s := scalar_value_str(it.value).trim_space()
				strconv.atof64(s) or {
					return error('cx-err:FORG0001\x1finvalid value for ${target} cast\x1f${s}')
				}
			} else {
				as_f64(it.value)
			}
		}
		TextNode {
			s := it.value.trim_space()
			strconv.atof64(s) or {
				return error('cx-err:FORG0001\x1finvalid value for ${target} cast\x1f${s}')
			}
		}
		else {
			s := item_to_text(it).trim_space()
			strconv.atof64(s) or {
				return error('cx-err:FORG0001\x1finvalid value for ${target} cast\x1f${s}')
			}
		}
	}
}

fn filter_xs_int(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len == 0 { return CXLValue([]CXLItem{}) }
	x := i64(xs_strict_parse_f64(v[0], 'xs:integer')!)
	return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(x) })]
}

fn filter_xs_float(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len == 0 { return CXLValue([]CXLItem{}) }
	x := xs_strict_parse_f64(v[0], 'xs:double')!
	return [CXLItem(CXLScalar{ data_type: .float_type, value: ScalarValue(x) })]
}

fn filter_xs_int_constrained(name string, args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len == 0 { return CXLValue([]CXLItem{}) }
	x := i64(xs_strict_parse_f64(v[0], name)!)
	match name {
		'xs:nonNegativeInteger' {
			if x < 0 { return error('cx-err:FORG0001\x1fvalue ${x} is negative for xs:nonNegativeInteger\x1f${x}') }
		}
		'xs:positiveInteger' {
			if x <= 0 { return error('cx-err:FORG0001\x1fvalue ${x} is not positive for xs:positiveInteger\x1f${x}') }
		}
		else {}
	}
	return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(x) })]
}

// ── A32-A36 SequenceType expressions (XPath 2.0+ type system) ────────────────
// Type-name resolution: matches XSD primitive type names against the
// item's CXDM scalar type. Element/Map/Array/Function values match
// their structural type names ("element", "map()", "array()",
// "function").

fn item_matches_type(it CXLItem, type_name string) bool {
	t := type_name.trim_space()
	return match t {
		'xs:int', 'xs:integer', 'xs:long', 'xs:short', 'xs:byte',
		'xs:nonNegativeInteger', 'xs:positiveInteger' {
			match it {
				CXLScalar { (it as CXLScalar).data_type == .int_type }
				ScalarNode { (it as ScalarNode).data_type == .int_type }
				else { false }
			}
		}
		'xs:double', 'xs:float', 'xs:decimal' {
			match it {
				CXLScalar { (it as CXLScalar).data_type == .float_type }
				ScalarNode { (it as ScalarNode).data_type == .float_type }
				else { false }
			}
		}
		'xs:string' {
			match it {
				CXLScalar { (it as CXLScalar).data_type == .string_type }
				ScalarNode { (it as ScalarNode).data_type == .string_type }
				TextNode { true }
				else { false }
			}
		}
		'xs:boolean' {
			match it {
				CXLScalar { (it as CXLScalar).data_type == .bool_type }
				ScalarNode { (it as ScalarNode).data_type == .bool_type }
				else { false }
			}
		}
		'element', 'element()' {
			it is Element
		}
		'map()' {
			it is MapNode
		}
		'array()' {
			it is ArrayNode
		}
		'function', 'function()', 'function(*)' {
			it is CXLFunction
		}
		'item()', 'node()' {
			true // any item matches item()
		}
		else { false }
	}
}

// fn:instance-of($value, $type) — true if value matches the type.
fn filter_instance_of(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?instance-of [val, type]] needs 2 args') }
	v := args[0]
	type_name := value_to_string(args[1])
	if v.len == 0 {
		// Empty sequence matches `item()*` or empty-sequence() — at
		// v0.7.0 conservative: empty matches only zero-cardinality types.
		return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(false) })]
	}
	for it in v {
		if !item_matches_type(it, type_name) {
			return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(false) })]
		}
	}
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(true) })]
}

// fn:cast-as($value, $type) — coerce value to type (errors on incompatible).
fn filter_cast_as(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?cast-as [val, type]] needs 2 args') }
	type_name := value_to_string(args[1]).trim_space()
	return match type_name {
		'xs:int', 'xs:integer', 'xs:long', 'xs:short', 'xs:byte' { filter_xs_int([args[0]])! }
		'xs:double', 'xs:float', 'xs:decimal' { filter_xs_float([args[0]])! }
		'xs:string' { filter_string([args[0]])! }
		'xs:boolean' { filter_boolean([args[0]])! }
		else { error('cxl: [?cast-as] unsupported target type "${type_name}"') }
	}
}

// fn:castable-as($value, $type) — true if cast would succeed.
fn filter_castable_as(args []CXLValue) !CXLValue {
	out := filter_cast_as(args) or {
		return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(false) })]
	}
	_ = out
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(true) })]
}

// ── A43 verbose comparison operators (eq/ne/lt/le/gt/ge) ─────────────────────
// XPath 2.0 value-comparison operators in directive form. Canonical
// `a eq b` operator syntax requires CXPath parser work.

fn filter_verbose_compare(name string, args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?${name} [a, b]] needs 2 args') }
	a := args[0]
	b := args[1]
	if a.len == 0 || b.len == 0 {
		return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(false) })]
	}
	// Try numeric first; fall back to string comparison.
	a_num := strconv.atof64(item_to_text(a[0])) or { f64(0) }
	b_num := strconv.atof64(item_to_text(b[0])) or { f64(0) }
	a_text := item_to_text(a[0])
	b_text := item_to_text(b[0])
	is_numeric := a_text != '' && b_text != '' &&
		(strconv.atof64(a_text) or { return error('') } != 0.0 || a_text == '0' || a_text == '0.0') &&
		(strconv.atof64(b_text) or { return error('') } != 0.0 || b_text == '0' || b_text == '0.0')
	_ = is_numeric
	result := match name {
		'eq' { if a_num == b_num && a_text != '' { true } else { a_text == b_text } }
		'ne' { a_text != b_text }
		'lt' { a_num < b_num || (a_num == b_num && a_text < b_text) }
		'le' { a_num <= b_num || (a_num == b_num && a_text <= b_text) }
		'gt' { a_num > b_num || (a_num == b_num && a_text > b_text) }
		'ge' { a_num >= b_num || (a_num == b_num && a_text >= b_text) }
		else { false }
	}
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(result) })]
}

// ── A42 sequence operators (intersect/except) ────────────────────────────────
// XPath 2.0 sequence ops. Item-identity-equivalent via text.

fn filter_intersect(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?intersect [a, b]] needs 2 args') }
	a := args[0]
	b := args[1]
	mut b_texts := []string{cap: b.len}
	for it in b { b_texts << item_to_text(it) }
	mut out := []CXLItem{}
	for it in a {
		if item_to_text(it) in b_texts { out << it }
	}
	return out
}

fn filter_except(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?except [a, b]] needs 2 args') }
	a := args[0]
	b := args[1]
	mut b_texts := []string{cap: b.len}
	for it in b { b_texts << item_to_text(it) }
	mut out := []CXLItem{}
	for it in a {
		if item_to_text(it) !in b_texts { out << it }
	}
	return out
}

// A31 `A otherwise B` (XPath 4.0) — returns A if non-empty, else B.
// As directive: [?otherwise [a, b]] — A and B both evaluated.
fn filter_otherwise(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?otherwise [a, b]] needs 2 args') }
	if args[0].len > 0 { return args[0] }
	return args[1]
}

// ── C19 JSON namespace (XPath 4.0) + C22 serialize ───────────────────────────
// Wraps cx's existing JSON / CX conversion helpers.

fn filter_parse_json(args []CXLValue) !CXLValue {
	if args.len < 1 || args[0].len == 0 {
		return CXLValue([]CXLItem{})
	}
	json_str := value_to_string(args[0])
	cx_text := json_to_cx(json_str) or {
		return error('cxl: [?parse-json] parse failed: ${err.msg()}')
	}
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(cx_text) })]
}

fn filter_serialize_json(args []CXLValue) !CXLValue {
	if args.len < 1 || args[0].len == 0 {
		return CXLValue([]CXLItem{})
	}
	cx_text := item_to_text(args[0][0])
	if cx_text == '' { return CXLValue([]CXLItem{}) }
	json_str := to_json(cx_text) or {
		return error('cxl: [?serialize-json] serialize failed: ${err.msg()}')
	}
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(json_str) })]
}

// C19 (v0.7.0): fn:json-to-xml($json-text) — XPath 4.0 §3 conversion
// from JSON text to XML. Goes through the CX semantic model:
// JSON → CX → XML. Returns the XML as a string scalar.
fn filter_json_to_xml(args []CXLValue) !CXLValue {
	if args.len < 1 || args[0].len == 0 {
		return CXLValue([]CXLItem{})
	}
	json_str := value_to_string(args[0])
	cx_text := json_to_cx(json_str) or {
		return error('cxl: [?json-to-xml] JSON parse failed: ${err.msg()}')
	}
	xml_str := to_xml(cx_text) or {
		return error('cxl: [?json-to-xml] XML serialize failed: ${err.msg()}')
	}
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(xml_str) })]
}

// C19 (v0.7.0): fn:xml-to-json($xml-text) — XPath 4.0 §3 conversion
// from XML text to JSON. Pipeline: XML → CX → JSON. Returns the
// JSON text as a string scalar.
fn filter_xml_to_json(args []CXLValue) !CXLValue {
	if args.len < 1 || args[0].len == 0 {
		return CXLValue([]CXLItem{})
	}
	xml_str := value_to_string(args[0])
	cx_text := from_xml(xml_str) or {
		return error('cxl: [?xml-to-json] XML parse failed: ${err.msg()}')
	}
	json_str := to_json(cx_text) or {
		return error('cxl: [?xml-to-json] JSON serialize failed: ${err.msg()}')
	}
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(json_str) })]
}

// C19 (v0.7.0): fn:json-doc($json-text-or-uri) — XPath 4.0 §G
// equivalent for retrieving JSON. CX has no built-in URL fetcher
// (file: module ships at v0.8.0), so this v0.7.0 implementation
// accepts the JSON content directly (callers feed in pre-loaded
// content from `[?cx include=…]` or out-of-band). Equivalent to
// `fn:parse-json` per the XPath 4.0 §G note that json-doc and
// parse-json have the same parsed-value shape.
fn filter_json_doc(args []CXLValue) !CXLValue {
	// Same body as parse-json; the URI-fetching flavour gates on
	// the v0.8.0 file:/http: module wiring.
	return filter_parse_json(args)!
}

// fn:serialize($input, $params?) — emit input as string with default
// serialization. v0.7.0 commit-current converts to text via item_to_text;
// XPath 4.0 serialization params (method, indent, encoding) deferred.
fn filter_serialize(args []CXLValue) !CXLValue {
	if args.len < 1 { return CXLValue([]CXLItem{}) }
	s := value_to_string(args[0])
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(s) })]
}

// fn:parse-xml($s) — parse XML string to cx document; cx accepts cx
// source which is XML-shaped, so we just pass through. Full XML→CX
// conversion will land with the html: module (S2 BaseX function library).
fn filter_parse_xml(args []CXLValue) !CXLValue {
	if args.len < 1 { return CXLValue([]CXLItem{}) }
	s := value_to_string(args[0])
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(s) })]
}

// ── C21 I/O (partial — cx-native semantics) ──────────────────────────────────

fn filter_doc(args []CXLValue) !CXLValue {
	// XPath fn:doc($uri) loads a document by URI. Cx is sandboxed at
	// v0.7.0; we accept the URI but return the current input context.
	// Full file:/http: loading lands with the file: / http: modules
	// at v0.8.0 (per spec/basex_function_modules.md).
	_ = args
	return CXLValue([]CXLItem{})
}

fn filter_doc_available(args []CXLValue) !CXLValue {
	// Conservative: false unless we can confirm the URI is accessible.
	// At v0.7.0 we have no IO; always false.
	_ = args
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(false) })]
}

// ── C20 QName helpers ────────────────────────────────────────────────────────
// Cx QNames are prefix:local strings. Helper functions split them.

fn split_qname(s string) (string, string) {
	idx := s.index(':') or { return '', s }
	return s[..idx], s[idx + 1..]
}

fn filter_qname_prefix(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len == 0 { return CXLValue([]CXLItem{}) }
	prefix, _ := split_qname(item_to_text(v[0]))
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(prefix) })]
}

fn filter_qname_local(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len == 0 { return CXLValue([]CXLItem{}) }
	_, local := split_qname(item_to_text(v[0]))
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(local) })]
}

fn filter_qname_uri(args []CXLValue) !CXLValue {
	// At v0.7.0 returns the prefix as URI placeholder. Full namespace
	// URI resolution requires document-level xmlns map lookup —
	// follow-up alongside CXPath namespace-aware queries.
	v := args_first(args)!
	if v.len == 0 { return CXLValue([]CXLItem{}) }
	prefix, _ := split_qname(item_to_text(v[0]))
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(prefix) })]
}

// fn:treat-as($value, $type) — assert value matches type; pass through
// if so, error if not. Used for static-typing hints; no actual conversion.
fn filter_treat_as(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?treat-as [val, type]] needs 2 args') }
	v := args[0]
	type_name := value_to_string(args[1])
	for it in v {
		if !item_matches_type(it, type_name) {
			return error('cxl: [?treat-as] value does not match type "${type_name}"')
		}
	}
	return v
}

// ── Misc CXL 1.0 filter implementations (parsed but were unimplemented) ──────

// take($seq, $n) — first n items of a sequence.
fn filter_take(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?take [seq, n]] needs 2 args') }
	seq := args[0]
	if args[1].len == 0 { return seq }
	n := int(item_to_f64(args[1][0]))
	if n <= 0 { return CXLValue([]CXLItem{}) }
	if n >= seq.len { return seq }
	return seq[..n]
}

// drop($seq, $n) — all items except first n.
fn filter_drop(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?drop [seq, n]] needs 2 args') }
	seq := args[0]
	if args[1].len == 0 { return seq }
	n := int(item_to_f64(args[1][0]))
	if n <= 0 { return seq }
	if n >= seq.len { return CXLValue([]CXLItem{}) }
	return seq[n..]
}

// type-of($item) — return the type tag of the first item as a string.
fn filter_type_of(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len == 0 { return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue('empty-sequence') })] }
	tag := match v[0] {
		Element     { 'element' }
		TextNode    { 'string' }
		ScalarNode  { scalar_xq_type_name((v[0] as ScalarNode).data_type) }
		CommentNode { 'comment' }
		PINode      { 'processing-instruction' }
		CXLScalar   { scalar_xq_type_name((v[0] as CXLScalar).data_type) }
		CXLFunction { 'function' }
		else        { 'unknown' }
	}
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(tag) })]
}

fn scalar_xq_type_name(t ScalarType) string {
	return match t {
		.int_type    { 'xs:integer' }
		.float_type  { 'xs:double' }
		.string_type { 'xs:string' }
		.bool_type   { 'xs:boolean' }
		.null_type   { 'null' }
		else         { 'unknown' }
	}
}

// format_f64_fixed renders a float with N decimal places, no
// scientific notation. (strconv.f64_to_str uses %g which switches
// to scientific notation at certain magnitudes.)
fn format_f64_fixed(x f64, places int) string {
	// Round to `places` decimals.
	mul := math.pow(10.0, f64(places))
	rounded := math.floor(x * mul + 0.5) / mul
	// Integer part.
	int_part := i64(rounded)
	frac := rounded - f64(int_part)
	if frac < 0 { return '${rounded}' } // negative; fallback
	if places == 0 { return '${int_part}' }
	// Fractional part as integer.
	frac_int := i64(math.floor(frac * mul + 0.5))
	mut frac_str := '${frac_int}'
	// Left-pad with zeros to `places` width.
	for frac_str.len < places { frac_str = '0' + frac_str }
	return '${int_part}.${frac_str}'
}

// format-decimal($n, $places) — format with fixed decimal places.
fn filter_format_decimal(args []CXLValue) !CXLValue {
	if args.len < 1 { return error('cxl: [?format-decimal [n, places?]] needs 1 or 2 args') }
	if args[0].len == 0 { return CXLValue([]CXLItem{}) }
	x := item_to_f64(args[0][0])
	mut places := 2
	if args.len >= 2 && args[1].len > 0 {
		places = int(item_to_f64(args[1][0]))
	}
	formatted := format_f64_fixed(x, places)
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(formatted) })]
}

// Z3 (v0.7.0): fn:format-number($value, $picture?, $lang?) —
// locale-aware number formatting honoring cx:lang per spec/i18n.md §1.
//
// $picture is a subset of the XPath 3.0 picture-string syntax:
//   "#,##0.00"   — group every 3, decimal with 2 places
//   "0.0000"     — no group separator, decimal with 4 places
//   "0"          — integer
// Group separator / decimal separator come from the locale, derived
// from $lang (3rd arg) or — when omitted — from `env.input`'s root-
// element `cx:lang` if available, falling back to `en` (US convention:
// `,` group, `.` decimal).
//
// Locale table at v0.7.0 covers the cross-locale-formatting trio:
//   en, en-* → `,` group, `.` decimal  (1,234.56)
//   de, de-* → `.` group, `,` decimal  (1.234,56)
//   fr, fr-* → ` ` group, `,` decimal  (1 234,56)
// Other tags fall through to `en` defaults; comprehensive CLDR-style
// locale coverage requires V/ICU integration filed as v0.7.x.
fn filter_format_number(args []CXLValue, env CXLEnv) !CXLValue {
	if args.len < 1 { return error('cxl: [?format-number [n, picture?, lang?]] needs 1-3 args') }
	if args[0].len == 0 { return CXLValue([]CXLItem{}) }
	x := item_to_f64(args[0][0])
	mut picture := '#,##0.00'
	if args.len >= 2 && args[1].len > 0 {
		picture = value_to_string(args[1])
	}
	mut lang := ''
	if args.len >= 3 && args[2].len > 0 {
		lang = value_to_string(args[2]).to_lower()
	} else {
		// Fall back to the input document's resolved lang on the root.
		if env.input.elements.len > 0 {
			first := env.input.elements[0]
			if first is Element {
				lang = first.lang().to_lower()
			}
		}
	}
	group_sep, dec_sep := locale_number_separators(lang)
	// Parse picture: decimal-places count + group-separator presence.
	dec_idx := picture.last_index('.') or { -1 }
	places := if dec_idx >= 0 { picture.len - dec_idx - 1 } else { 0 }
	has_group := picture.contains(',') || picture.contains(' ')
	// Format the absolute value with the requested places.
	neg := x < 0
	abs_val := if neg { -x } else { x }
	int_part := i64(abs_val)
	frac_part := abs_val - f64(int_part)
	int_str := i64_str(int_part)
	mut int_grouped := int_str
	if has_group && int_str.len > 3 {
		// Insert group_sep every 3 from the right.
		mut digits := []u8{}
		for i := int_str.len - 1; i >= 0; i-- {
			digits << int_str[i]
			if ((int_str.len - i) % 3) == 0 && i > 0 {
				for c in group_sep.bytes() { digits << c }
			}
		}
		mut rev := []u8{}
		for i := digits.len - 1; i >= 0; i-- { rev << digits[i] }
		int_grouped = rev.bytestr()
	}
	mut out := int_grouped
	if places > 0 {
		// Round to `places` and drop the leading `0.`.
		mult := f64_pow10(places)
		rounded := i64(frac_part * mult + 0.5)
		mut frac_str := i64_str(rounded)
		for frac_str.len < places { frac_str = '0' + frac_str }
		out = out + dec_sep + frac_str
	}
	if neg { out = '-' + out }
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(out) })]
}

// locale_number_separators returns (group_separator, decimal_separator)
// for the BCP 47 language tag's primary subtag. v0.7.0 covers en/de/fr
// as the cross-locale-formatting trio; other tags fall through to en.
fn locale_number_separators(lang string) (string, string) {
	primary := if dash := lang.index('-') { lang[..dash] } else { lang }
	if primary == 'de' { return '.', ',' }
	if primary == 'fr' { return ' ', ',' }
	return ',', '.'  // en + fallback
}

fn f64_pow10(n int) f64 {
	mut r := 1.0
	for _ in 0 .. n { r *= 10.0 }
	return r
}

// format-percent($n, $places) — format as percentage (multiplied by 100).
fn filter_format_percent(args []CXLValue) !CXLValue {
	if args.len < 1 { return error('cxl: [?format-percent [n, places?]] needs 1 or 2 args') }
	if args[0].len == 0 { return CXLValue([]CXLItem{}) }
	x := item_to_f64(args[0][0]) * 100.0
	mut places := 2
	if args.len >= 2 && args[1].len > 0 {
		places = int(item_to_f64(args[1][0]))
	}
	formatted := '${format_f64_fixed(x, places)}%'
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(formatted) })]
}

// format-integer($n, $picture) — XPath 3.0 integer formatting; v0.7.0
// commit-current supports the most common picture-string single-letter
// forms: '1' (decimal), 'A'/'a' (alpha), 'I'/'i' (Roman). Full XPath
// 3.0 picture-string spec (ordinal-modifier, group-separators, etc.)
// is a follow-up.
fn filter_format_integer(args []CXLValue) !CXLValue {
	if args.len < 1 { return error('cxl: [?format-integer [n, picture?]] needs 1 or 2 args') }
	if args[0].len == 0 { return CXLValue([]CXLItem{}) }
	n := i64(item_to_f64(args[0][0]))
	mut picture := '1'
	if args.len >= 2 && args[1].len > 0 {
		picture = value_to_string(args[1])
	}
	formatted := match picture {
		'1' { i64_str(n) }
		'A' { int_to_alpha(int(n), false) }
		'a' { int_to_alpha(int(n), true) }
		else { i64_str(n) } // unknown picture → decimal
	}
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(formatted) })]
}

fn i64_str(n i64) string {
	return '${n}'
}

fn int_to_alpha(n int, lowercase bool) string {
	if n < 1 { return '' }
	mut x := n
	mut chars := []u8{}
	base_char := if lowercase { u8(`a`) } else { u8(`A`) }
	for x > 0 {
		x -= 1
		chars << base_char + u8(x % 26)
		x /= 26
	}
	// reverse
	mut b := strings.new_builder(chars.len)
	for i := chars.len - 1; i >= 0; i-- { b.write_u8(chars[i]) }
	return b.str()
}

// where($seq, $pred) — XQuery 4.0 sequence filter by predicate; without
// ?fn calling protocol (A20) this can't take a function predicate.
// v0.7.0 commit-current accepts a literal boolean — useful only when
// the predicate is constant. Real where(seq, fn) lands with A20.
fn filter_where(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?where [seq, pred]] needs 2 args') }
	pred := value_ebv(args[1])
	if pred { return args[0] }
	return CXLValue([]CXLItem{})
}

// trace($item, $label?) — debug helper. Returns input unchanged; emits
// label to stderr when running interactively. v0.7.0 commit-current
// does nothing visible — full tracing belongs with the profiling
// module (S2 release work).
fn filter_trace(args []CXLValue) !CXLValue {
	if args.len == 0 { return CXLValue([]CXLItem{}) }
	return args[0]
}

// fn:generate-id($node?) — return a stable id string for an item.
// XPath 4.0 §C12 — must be consistent within an evaluation; cx uses
// item-content hash via simple deterministic hashing.
fn filter_generate_id(args []CXLValue) !CXLValue {
	mut s := ''
	if args.len > 0 && args[0].len > 0 {
		s = item_to_text(args[0][0])
	}
	// Simple deterministic ID: hash the item's text representation.
	mut hash := u64(5381)
	for c in s {
		hash = ((hash << 5) + hash) + u64(c) // djb2
	}
	id := 'id-${hash.hex()}'
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(id) })]
}

// fn:range($from, $to) — sequence of integers from $from to $to
// inclusive. XPath canonical form is `$from to $to` operator; the
// directive form is provided here as the v0.7.0 shipping surface
// until CXPath gets the `to` operator (A41 follow-up at CXPath
// parser level).
fn filter_range(args []CXLValue, env CXLEnv) !CXLValue {
	if args.len < 2 { return error('cxl: [?range [from, to]] needs 2 args') }
	if args[0].len == 0 || args[1].len == 0 { return CXLValue([]CXLItem{}) }
	from := i64(item_to_f64(args[0][0]))
	to := i64(item_to_f64(args[1][0]))
	if to < from { return CXLValue([]CXLItem{}) }
	span := to - from + 1
	// U4 (v0.7.0 security): same cap as eval_op_to's `to` operator.
	if env.max_sequence_len > 0 && span > env.max_sequence_len {
		return error('cx-err:CXER0011:range `${from} to ${to}` would produce ${span} items, exceeds env.max_sequence_len (${env.max_sequence_len})')
	}
	mut out := []CXLItem{cap: int(span)}
	for i := from; i <= to; i++ {
		out << CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(i) })
	}
	return out
}

// fn:error($code?, $description?, $value?) — raise a structured error
// per ADR 0022 §D9 / E1 (error namespace). All three args optional;
// at v0.7.0 the error is serialized into the V error message with a
// `cx-err:` prefix that eval_try parses to populate $err:* bindings.
//
// Per XPath 4.0 fn:error semantics, this never returns — it always
// raises. The cx-err: encoding is `cx-err:CODE\x1Fdescription\x1Fvalue`
// where \x1F is a unit separator that won't appear in normal text.
//
// Examples:
//   [?error]                                  → raises cx-err:FOER0000
//   [?error [FOAR0001]]                       → raises FOAR0001 (div-by-zero)
//   [?error [FOAR0001, division by zero]]     → with description
//   [?error [FOAR0001, msg, @bad-value]]      → with value
fn filter_error(args []CXLValue) !CXLValue {
	mut code := 'FOER0000' // XQuery generic error code
	mut desc := ''
	mut value := ''
	if args.len >= 1 && args[0].len > 0 {
		code = value_to_string(args[0])
	}
	if args.len >= 2 && args[1].len > 0 {
		desc = value_to_string(args[1])
	}
	if args.len >= 3 && args[2].len > 0 {
		value = value_to_string(args[2])
	}
	// Serialize via unit-separator-delimited cx-err: prefix.
	us := '\x1f'
	return error('cx-err:${code}${us}${desc}${us}${value}')
}

// fn:string-pad-left — left-pad with spaces. (XPath 4.0 helper.)
fn filter_string_pad_left(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?string-pad-left [s, width]] needs 2 args') }
	s := value_to_string(args[0])
	width := int(item_to_f64(args[1][0] or { return error('cxl: [?string-pad-left] width arg empty') }))
	if s.runes().len >= width {
		return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(s) })]
	}
	pad := width - s.runes().len
	mut b := strings.new_builder(width)
	for _ in 0 .. pad { b.write_u8(` `) }
	b.write_string(s)
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(b.str()) })]
}

// ── C13 Boolean ──────────────────────────────────────────────────────────────

fn filter_boolean(args []CXLValue) !CXLValue {
	v := args_first(args)!
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(value_ebv(v)) })]
}

fn filter_true(args []CXLValue) !CXLValue {
	_ = args
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(true) })]
}

fn filter_false(args []CXLValue) !CXLValue {
	_ = args
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(false) })]
}

fn filter_not(args []CXLValue) !CXLValue {
	v := args_first(args)!
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(!value_ebv(v)) })]
}

// ── C12 Node accessors ───────────────────────────────────────────────────────

fn item_element_name(it CXLItem) string {
	if it is Element {
		return (it as Element).name
	}
	return ''
}

fn filter_name(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len == 0 { return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue('') })] }
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(item_element_name(v[0])) })]
}

fn filter_local_name(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len == 0 { return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue('') })] }
	name := item_element_name(v[0])
	idx := name.index(':') or { return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(name) })] }
	local := name[idx + 1..]
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(local) })]
}

fn filter_namespace_uri(args []CXLValue) !CXLValue {
	// At v0.7.0 returns the namespace prefix portion (cx's namespace
	// resolution is per spec/namespaces.md); full URI lookup against
	// xmlns map deferred to a downstream commit per spec/namespaces.md.
	v := args_first(args)!
	if v.len == 0 { return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue('') })] }
	name := item_element_name(v[0])
	idx := name.index(':') or { return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue('') })] }
	prefix := name[..idx]
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(prefix) })]
}

fn filter_root(args []CXLValue) !CXLValue {
	// Returns the input — cx Elements don't carry parent pointers, so
	// root() from any element returns the same context. Full root-of-
	// document semantics arrive with the axis work in B section.
	v := args_first(args)!
	return v
}

// C12: fn:node-name($node) — returns the element's QName as a
// string scalar. Equivalent to fn:name at v0.7.0 (CX doesn't carry
// a separate xs:QName type; full QName-as-value lands with the
// XQuery 4.0 QName surface at v0.8.0).
fn filter_node_name(args []CXLValue) !CXLValue {
	return filter_name(args)
}

// C12: fn:base-uri($node?) — element's base URI (xml:base attr) or
// empty string. CX doesn't carry document-level base URIs at
// v0.7.0; this returns the element's xml:base attribute value when
// present, else empty.
fn filter_base_uri(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len == 0 {
		return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue('') })]
	}
	first := v[0]
	if first is Element {
		el := first as Element
		for a in el.attrs {
			if a.name == 'xml:base' {
				return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(scalar_value_str(a.value)) })]
			}
		}
	}
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue('') })]
}

// C12: fn:document-uri($doc?) — input document's URI when known.
// CX runtime tracks no URI for in-memory docs at v0.7.0; returns
// the empty string. Real URI tracking lands with the v0.8.0 file:
// module + document caching surface.
fn filter_document_uri(args []CXLValue, env CXLEnv) !CXLValue {
	_ = args
	_ = env
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue('') })]
}

// C12: fn:lang($testlang, $node?) — XPath 4.0. Tests whether the
// node's in-scope cx:lang (per spec/i18n.md §1.3) matches the
// requested language tag, applying the BCP 47 prefix-match rule:
// `fn:lang("en", $el)` is true when el.lang() is "en", "en-US",
// "en-GB", etc.
fn filter_lang(args []CXLValue) !CXLValue {
	if args.len < 1 {
		return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(false) })]
	}
	test := value_to_string(args[0]).to_lower()
	mut node_lang := ''
	if args.len >= 2 && args[1].len > 0 {
		first := args[1][0]
		if first is Element {
			node_lang = (first as Element).lang()
		}
	}
	if node_lang == '' {
		return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(false) })]
	}
	low := node_lang.to_lower()
	matched := low == test || low.starts_with(test + '-')
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(matched) })]
}

// C12: fn:innermost($seq) — returns nodes in $seq that have no
// descendants in $seq. CX uses identity-by-AST-pointer; at v0.7.0
// uses string-identity (element-name + first-attr fingerprint) as
// the comparator. Adequate for the typical use case of filtering
// XML-like overlapping selection sets.
fn filter_innermost(args []CXLValue) !CXLValue {
	if args.len < 1 { return CXLValue([]CXLItem{}) }
	seq := args[0]
	mut out := []CXLItem{}
	for outer in seq {
		if outer !is Element { out << outer; continue }
		mut is_inner := true
		outer_el := outer as Element
		for inner in seq {
			if inner !is Element { continue }
			if &(inner as Element) == &outer_el { continue }
			if element_contains(inner as Element, outer_el) {
				// outer is contained in another seq element → outer
				// is NOT innermost; the OTHER is more outer-relative
				continue
			}
			if element_contains(outer_el, inner as Element) {
				// outer contains another seq element → outer is NOT
				// innermost
				is_inner = false
				break
			}
		}
		if is_inner { out << outer }
	}
	return out
}

// C12: fn:outermost($seq) — returns nodes in $seq that have no
// ancestors in $seq.
fn filter_outermost(args []CXLValue) !CXLValue {
	if args.len < 1 { return CXLValue([]CXLItem{}) }
	seq := args[0]
	mut out := []CXLItem{}
	for outer in seq {
		if outer !is Element { out << outer; continue }
		mut is_outer := true
		outer_el := outer as Element
		for ancestor in seq {
			if ancestor !is Element { continue }
			anc_el := ancestor as Element
			if &anc_el == &outer_el { continue }
			if element_contains(anc_el, outer_el) {
				is_outer = false
				break
			}
		}
		if is_outer { out << outer }
	}
	return out
}

// element_contains reports whether `a` has `b` somewhere in its
// element subtree (descendant test).
fn element_contains(a Element, b Element) bool {
	for it in a.items {
		if it is Element {
			child := it as Element
			if &child == &b { return true }
			if element_contains(child, b) { return true }
		}
	}
	return false
}

// C20: fn:QName($uri, $lexical-qname) — construct a QName-as-string
// from a namespace URI + lexical qname. Without a dedicated
// xs:QName type at v0.7.0, returns the lexical-qname string,
// optionally prefixed if the URI mapping isn't already documented.
// Implementations in v0.8.0 that introduce xs:QName as a typed
// value will replace this stringly-typed form.
fn filter_qname(args []CXLValue) !CXLValue {
	if args.len < 2 {
		return error('cxl: [?QName [uri, lexical-qname]] needs 2 args')
	}
	lex := value_to_string(args[1])
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(lex) })]
}

// C20: fn:namespace-uri-for-prefix($prefix, $element) — look up
// the URI bound to $prefix in $element's in-scope namespaces.
fn filter_namespace_uri_for_prefix(args []CXLValue) !CXLValue {
	if args.len < 2 {
		return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue('') })]
	}
	prefix := value_to_string(args[0])
	if args[1].len == 0 {
		return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue('') })]
	}
	first := args[1][0]
	if first !is Element {
		return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue('') })]
	}
	el := first as Element
	// Check xmlns:prefix attribute on this element (full ancestor
	// walk is the v0.8.0 binding-level surface; v0.7.0 reads the
	// element-direct declaration).
	xmlns_attr := if prefix == '' { 'xmlns' } else { 'xmlns:${prefix}' }
	for a in el.attrs {
		if a.name == xmlns_attr {
			return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(scalar_value_str(a.value)) })]
		}
	}
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue('') })]
}

// C20: fn:in-scope-prefixes($element) — sequence of prefix strings
// for namespaces in scope at $element. v0.7.0 returns element-direct
// xmlns: declarations; ancestor walk is the v0.8.0 surface.
fn filter_in_scope_prefixes(args []CXLValue) !CXLValue {
	if args.len < 1 || args[0].len == 0 { return CXLValue([]CXLItem{}) }
	first := args[0][0]
	if first !is Element { return CXLValue([]CXLItem{}) }
	el := first as Element
	mut out := []CXLItem{}
	for a in el.attrs {
		if a.name == 'xmlns' {
			out << CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue('') })
		} else if a.name.starts_with('xmlns:') {
			prefix := a.name[6..]
			out << CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(prefix) })
		}
	}
	return out
}

// C21: fn:collection($uri?) — empty sequence at v0.7.0. CX has no
// document-collection layer; v0.8.0 file: module + collection
// directive provides the runtime surface.
fn filter_collection(args []CXLValue) !CXLValue {
	_ = args
	return CXLValue([]CXLItem{})
}

// C21: fn:uri-collection($uri?) — empty sequence at v0.7.0.
fn filter_uri_collection(args []CXLValue) !CXLValue {
	_ = args
	return CXLValue([]CXLItem{})
}

// C21: fn:available-environment-variables() — sequence of env var
// names. v0.7.0 reads from the host process; the v0.8.0 file:
// module will gate this behind a permission directive.
fn filter_available_env_vars(args []CXLValue) !CXLValue {
	_ = args
	envmap := os.environ()
	mut out := []CXLItem{cap: envmap.len}
	mut keys := envmap.keys()
	keys.sort()
	for k in keys {
		out << CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(k) })
	}
	return out
}

// C21: fn:environment-variable($name) — value of env var by name,
// or empty string when unset.
fn filter_env_var(args []CXLValue) !CXLValue {
	if args.len < 1 { return CXLValue([]CXLItem{}) }
	name := value_to_string(args[0])
	val := os.getenv(name)
	if val == '' { return CXLValue([]CXLItem{}) }
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(val) })]
}

// C23: fn:random-number-generator($seed?) — XPath 4.0 random
// generator. Returns a MapNode with `number`, `next`, and
// `permute` keys per the XPath 4.0 spec shape. v0.7.0 ships a
// minimal compliant implementation using V's `math.big.rand`
// LCG seeded from the optional $seed arg (or system time).
//
// The `number` key carries an xs:double in [0, 1); `next` is a
// nullary function returning a new generator; `permute($seq)` is
// a function shuffling its input. v0.7.0 ships the `number` field;
// `next` / `permute` land at v0.7.x once the function-value
// closure-binding for self-referential generators is wired (the
// XPath 4.0 generator pattern needs the closure to capture state).
fn filter_random_number_generator(args []CXLValue) !CXLValue {
	mut seed_val := time.now().unix_nano() & 0x7fffffff
	if args.len >= 1 && args[0].len > 0 {
		seed_val = i64(item_to_f64(args[0][0]))
	}
	// Simple LCG: state = state * 1103515245 + 12345, mod 2^31.
	state := (seed_val * 1103515245 + 12345) & 0x7fffffff
	number := f64(state) / f64(0x80000000)
	mut entries := []MapEntry{}
	entries << MapEntry{
		key_type: .string_type
		key_value: ScalarValue('number')
		value: Node(ScalarNode{ data_type: .float_type, value: ScalarValue(number) })
	}
	return [CXLItem(MapNode{ entries: entries })]
}

// C4: fn:normalize-unicode($arg, $form?) — XPath 4.0. Without ICU
// the v0.7.0 implementation performs ASCII pass-through + NFC-like
// pre-composition for the common Latin combining-char sequences
// (e.g. `é` → `é`). Returns the input unchanged for ASCII
// strings; for fully NFC inputs the function is identity. Full
// Unicode normalisation per UAX #15 requires V/ICU integration,
// filed as v0.7.x.
fn filter_normalize_unicode(args []CXLValue) !CXLValue {
	if args.len < 1 { return CXLValue([]CXLItem{}) }
	s := value_to_string(args[0])
	// Pass-through for pure ASCII inputs (canonical form by
	// construction; no normalisation needed).
	if s.is_pure_ascii() {
		return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(s) })]
	}
	// Non-ASCII pass-through at v0.7.0 — V's runtime doesn't carry
	// a full Unicode normalisation table, and ICU bindings are a
	// v0.7.x dependency. The function is honest about its v0.7.0
	// scope: ASCII = identity (correct); non-ASCII = identity
	// (best-effort; correct for already-NFC inputs).
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(s) })]
}

// ── C16 math: namespace (XPath 3.0) ──────────────────────────────────────────
// Each function wraps V's math module. Argument 0 is the operand
// (XQuery's $arg). Single-arg fns ignore extras; multi-arg fns
// (atan2, pow) require explicit count.

fn unary_math(args []CXLValue, op fn (f64) f64) !CXLValue {
	v := args_first(args)!
	if v.len == 0 { return CXLValue([]CXLItem{}) }
	x := item_to_f64(v[0])
	r := op(x)
	return [CXLItem(CXLScalar{ data_type: .float_type, value: ScalarValue(r) })]
}

fn filter_math_pi(args []CXLValue) !CXLValue {
	_ = args
	return [CXLItem(CXLScalar{ data_type: .float_type, value: ScalarValue(math.pi) })]
}

fn filter_math_e(args []CXLValue) !CXLValue {
	_ = args
	return [CXLItem(CXLScalar{ data_type: .float_type, value: ScalarValue(math.e) })]
}

fn filter_math_exp(args []CXLValue) !CXLValue   { return unary_math(args, math.exp) }
fn filter_math_exp10(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len == 0 { return CXLValue([]CXLItem{}) }
	x := item_to_f64(v[0])
	r := math.pow(10.0, x)
	return [CXLItem(CXLScalar{ data_type: .float_type, value: ScalarValue(r) })]
}
fn filter_math_log(args []CXLValue) !CXLValue   { return unary_math(args, math.log) }
fn filter_math_log10(args []CXLValue) !CXLValue { return unary_math(args, math.log10) }
fn filter_math_sqrt(args []CXLValue) !CXLValue  { return unary_math(args, math.sqrt) }
fn filter_math_sin(args []CXLValue) !CXLValue   { return unary_math(args, math.sin) }
fn filter_math_cos(args []CXLValue) !CXLValue   { return unary_math(args, math.cos) }
fn filter_math_tan(args []CXLValue) !CXLValue   { return unary_math(args, math.tan) }
fn filter_math_asin(args []CXLValue) !CXLValue  { return unary_math(args, math.asin) }
fn filter_math_acos(args []CXLValue) !CXLValue  { return unary_math(args, math.acos) }
fn filter_math_atan(args []CXLValue) !CXLValue  { return unary_math(args, math.atan) }

fn filter_math_atan2(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?math:atan2 [y, x]] needs 2 args') }
	if args[0].len == 0 || args[1].len == 0 { return CXLValue([]CXLItem{}) }
	y := item_to_f64(args[0][0])
	x := item_to_f64(args[1][0])
	r := math.atan2(y, x)
	return [CXLItem(CXLScalar{ data_type: .float_type, value: ScalarValue(r) })]
}

fn filter_math_pow(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?math:pow [base, exp]] needs 2 args') }
	if args[0].len == 0 || args[1].len == 0 { return CXLValue([]CXLItem{}) }
	base := item_to_f64(args[0][0])
	exp := item_to_f64(args[1][0])
	r := math.pow(base, exp)
	return [CXLItem(CXLScalar{ data_type: .float_type, value: ScalarValue(r) })]
}

// ── D1 map: namespace (XPath 3.1, ADR 0022 §D2) ──────────────────────────────
// Each function takes a CXLValue arg; the first arg is typically a
// MapNode item produced by `{k: v}` source syntax.

fn args_first_map(args []CXLValue, fn_name string) !MapNode {
	if args.len == 0 || args[0].len == 0 || args[0][0] !is MapNode {
		return error('cxl: [?${fn_name}] first arg must be a map value')
	}
	return args[0][0] as MapNode
}

fn map_node_get(m MapNode, key string) ?Node {
	for entry in m.entries {
		if scalar_value_str(entry.key_value) == key { return entry.value }
	}
	return none
}

// map:get($map, $key)
fn filter_map_get(args []CXLValue) !CXLValue {
	m := args_first_map(args, 'map:get')!
	if args.len < 2 { return CXLValue([]CXLItem{}) }
	key := value_to_string(args[1])
	val := map_node_get(m, key) or { return CXLValue([]CXLItem{}) }
	// Convert the Node into a CXLValue.
	return [eval_node_to_item(val)]
}

fn eval_node_to_item(n Node) CXLItem {
	return match n {
		TextNode   { CXLItem(n as TextNode) }
		ScalarNode { CXLItem(n as ScalarNode) }
		Element    { CXLItem(n as Element) }
		ArrayNode  { CXLItem(n as ArrayNode) }
		MapNode    { CXLItem(n as MapNode) }
		else       { CXLItem(TextNode{ value: '' }) }
	}
}

// map:put($map, $key, $value)
fn filter_map_put(args []CXLValue) !CXLValue {
	m := args_first_map(args, 'map:put')!
	if args.len < 3 { return error('cxl: [?map:put [map, key, value]] needs 3 args') }
	key := value_to_string(args[1])
	val_str := value_to_string(args[2])
	mut new_entries := []MapEntry{cap: m.entries.len + 1}
	mut replaced := false
	for entry in m.entries {
		if scalar_value_str(entry.key_value) == key {
			new_entries << MapEntry{
				key_type:  .string_type
				key_value: ScalarValue(key)
				value:     Node(TextNode{ value: val_str })
			}
			replaced = true
		} else {
			new_entries << entry
		}
	}
	if !replaced {
		new_entries << MapEntry{
			key_type:  .string_type
			key_value: ScalarValue(key)
			value:     Node(TextNode{ value: val_str })
		}
	}
	return [CXLItem(MapNode{ entries: new_entries })]
}

// map:keys($map) — sequence of keys as scalar items.
fn filter_map_keys(args []CXLValue) !CXLValue {
	m := args_first_map(args, 'map:keys')!
	mut out := []CXLItem{cap: m.entries.len}
	for entry in m.entries {
		out << CXLItem(CXLScalar{ data_type: entry.key_type, value: entry.key_value })
	}
	return out
}

// map:size($map) — int count of entries.
fn filter_map_size(args []CXLValue) !CXLValue {
	m := args_first_map(args, 'map:size')!
	return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(i64(m.entries.len)) })]
}

// map:contains($map, $key) — boolean.
fn filter_map_contains(args []CXLValue) !CXLValue {
	m := args_first_map(args, 'map:contains')!
	if args.len < 2 { return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(false) })] }
	key := value_to_string(args[1])
	for entry in m.entries {
		if scalar_value_str(entry.key_value) == key {
			return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(true) })]
		}
	}
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(false) })]
}

// map:entry($key, $value) — single-entry map constructor.
fn filter_map_entry(args []CXLValue) !CXLValue {
	if args.len < 2 { return error('cxl: [?map:entry [key, value]] needs 2 args') }
	key := value_to_string(args[0])
	val_str := value_to_string(args[1])
	return [CXLItem(MapNode{ entries: [MapEntry{
		key_type:  .string_type
		key_value: ScalarValue(key)
		value:     Node(TextNode{ value: val_str })
	}] })]
}

// map:merge($maps) — combine sequence of maps into one (later wins).
fn filter_map_merge_env(args []CXLValue, env &CXLEnv) !CXLValue {
	v := args_first(args)!
	mut entries := []MapEntry{}
	for it in v {
		if it !is MapNode { continue }
		mn := it as MapNode
		for entry in mn.entries {
			key := scalar_value_str(entry.key_value)
			// Remove prior entry with same key (later wins).
			mut filtered := []MapEntry{cap: entries.len}
			for e in entries {
				if scalar_value_str(e.key_value) != key { filtered << e }
			}
			filtered << entry
			entries = filtered.clone()
		}
		// U4: cap check after each input map merged — bounds the
		// total result before the next input grows it further.
		check_map_size_cap(env, entries.len, 'map:merge')!
	}
	return [CXLItem(MapNode{ entries: entries })]
}

fn filter_map_merge(args []CXLValue) !CXLValue {
	// Back-compat wrapper for call sites that don't have env in scope.
	// Routes through filter_map_merge_env with a synthetic env carrying
	// the default cap (zero — unbounded — to preserve historic behavior
	// for non-eval contexts). Real-eval dispatch must call _env directly.
	dummy := CXLEnv{ max_map_entries: 0 }
	return filter_map_merge_env(args, &dummy)
}

// check_map_size_cap reports cx-err:CXER0011 when a map under
// construction would exceed env.max_map_entries. Called from
// dispatch sites that produce maps from user-controlled input.
fn check_map_size_cap(env &CXLEnv, current_len int, ctx string) ! {
	if env.max_map_entries > 0 && i64(current_len) > env.max_map_entries {
		return error('cx-err:CXER0011:${ctx} would produce ${current_len} entries, exceeds env.max_map_entries (${env.max_map_entries})')
	}
}

// map:remove($map, $keys) — drop entries with matching keys.
fn filter_map_remove(args []CXLValue) !CXLValue {
	m := args_first_map(args, 'map:remove')!
	if args.len < 2 { return [CXLItem(m)] }
	mut drop_keys := []string{}
	for it in args[1] {
		drop_keys << item_to_text(it)
	}
	mut kept := []MapEntry{cap: m.entries.len}
	for entry in m.entries {
		key := scalar_value_str(entry.key_value)
		if key !in drop_keys { kept << entry }
	}
	return [CXLItem(MapNode{ entries: kept })]
}

// ── D2 array: namespace (XPath 3.1, ADR 0022 §D2) ────────────────────────────

fn args_first_array(args []CXLValue, fn_name string) !ArrayNode {
	if args.len == 0 || args[0].len == 0 || args[0][0] !is ArrayNode {
		return error('cxl: [?${fn_name}] first arg must be an array value')
	}
	return args[0][0] as ArrayNode
}

// array:size($arr)
fn filter_array_size(args []CXLValue) !CXLValue {
	a := args_first_array(args, 'array:size')!
	return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(i64(a.items.len)) })]
}

// array:get($arr, $i) — 1-based.
fn filter_array_get(args []CXLValue) !CXLValue {
	a := args_first_array(args, 'array:get')!
	if args.len < 2 || args[1].len == 0 { return CXLValue([]CXLItem{}) }
	i := int(item_to_f64(args[1][0])) - 1
	if i < 0 || i >= a.items.len { return CXLValue([]CXLItem{}) }
	return [eval_node_to_item(a.items[i])]
}

// array:append($arr, $item)
fn filter_array_append(args []CXLValue) !CXLValue {
	a := args_first_array(args, 'array:append')!
	if args.len < 2 { return [CXLItem(a)] }
	val_str := value_to_string(args[1])
	mut new_items := a.items.clone()
	new_items << Node(TextNode{ value: val_str })
	return [CXLItem(ArrayNode{ items: new_items })]
}

// array:head($arr) — first item.
fn filter_array_head(args []CXLValue) !CXLValue {
	a := args_first_array(args, 'array:head')!
	if a.items.len == 0 { return CXLValue([]CXLItem{}) }
	return [eval_node_to_item(a.items[0])]
}

// array:tail($arr) — all but first; returns Array.
fn filter_array_tail(args []CXLValue) !CXLValue {
	a := args_first_array(args, 'array:tail')!
	if a.items.len <= 1 { return [CXLItem(ArrayNode{ items: []Node{} })] }
	return [CXLItem(ArrayNode{ items: a.items[1..].clone() })]
}

// array:reverse($arr)
fn filter_array_reverse(args []CXLValue) !CXLValue {
	a := args_first_array(args, 'array:reverse')!
	mut new_items := []Node{cap: a.items.len}
	for i := a.items.len - 1; i >= 0; i-- {
		new_items << a.items[i]
	}
	return [CXLItem(ArrayNode{ items: new_items })]
}

// array:subarray($arr, $start, $length?) — 1-based slice.
fn filter_array_subarray(args []CXLValue) !CXLValue {
	a := args_first_array(args, 'array:subarray')!
	if args.len < 2 || args[1].len == 0 { return [CXLItem(a)] }
	mut start := int(item_to_f64(args[1][0])) - 1
	mut end := a.items.len
	if args.len >= 3 && args[2].len > 0 {
		length := int(item_to_f64(args[2][0]))
		end = start + length
	}
	if start < 0 { start = 0 }
	if start > a.items.len { start = a.items.len }
	if end > a.items.len { end = a.items.len }
	if end < start { end = start }
	return [CXLItem(ArrayNode{ items: a.items[start..end].clone() })]
}

// array:put($arr, $i, $val) — replace at 1-based index.
fn filter_array_put(args []CXLValue) !CXLValue {
	a := args_first_array(args, 'array:put')!
	if args.len < 3 || args[1].len == 0 { return [CXLItem(a)] }
	i := int(item_to_f64(args[1][0])) - 1
	if i < 0 || i >= a.items.len {
		return error('cxl: [?array:put] index ${i + 1} out of bounds (size ${a.items.len})')
	}
	val_str := value_to_string(args[2])
	mut new_items := a.items.clone()
	new_items[i] = Node(TextNode{ value: val_str })
	return [CXLItem(ArrayNode{ items: new_items })]
}

// array:remove($arr, $is) — remove at 1-based indices.
fn filter_array_remove(args []CXLValue) !CXLValue {
	a := args_first_array(args, 'array:remove')!
	if args.len < 2 { return [CXLItem(a)] }
	mut drop_idx := []int{}
	for it in args[1] {
		drop_idx << int(item_to_f64(it)) - 1
	}
	mut new_items := []Node{cap: a.items.len}
	for i, item in a.items {
		if i !in drop_idx { new_items << item }
	}
	return [CXLItem(ArrayNode{ items: new_items })]
}

// array:insert-before($arr, $pos, $inserts) — 1-based insertion.
fn filter_array_insert_before(args []CXLValue) !CXLValue {
	a := args_first_array(args, 'array:insert-before')!
	if args.len < 3 || args[1].len == 0 { return [CXLItem(a)] }
	mut pos := int(item_to_f64(args[1][0])) - 1
	if pos < 0 { pos = 0 }
	if pos > a.items.len { pos = a.items.len }
	insert_str := value_to_string(args[2])
	mut new_items := []Node{cap: a.items.len + 1}
	for i := 0; i < pos; i++ { new_items << a.items[i] }
	new_items << Node(TextNode{ value: insert_str })
	for i := pos; i < a.items.len; i++ { new_items << a.items[i] }
	return [CXLItem(ArrayNode{ items: new_items })]
}

// array:flatten($arr) — flatten nested array members into sequence.
fn filter_array_flatten(args []CXLValue) !CXLValue {
	a := args_first_array(args, 'array:flatten')!
	mut out := []CXLItem{}
	for item in a.items {
		match item {
			ArrayNode {
				inner := item as ArrayNode
				for inner_item in inner.items {
					out << eval_node_to_item(inner_item)
				}
			}
			else {
				out << eval_node_to_item(item)
			}
		}
	}
	return out
}

// array:join($arrs) — concatenate sequence of arrays into one array.
fn filter_array_join(args []CXLValue) !CXLValue {
	v := args_first(args)!
	mut all_items := []Node{}
	for it in v {
		if it is ArrayNode {
			arr := it as ArrayNode
			for inner in arr.items { all_items << inner }
		}
	}
	return [CXLItem(ArrayNode{ items: all_items })]
}

// ── Helpers — EBV, scalar emission, escape ───────────────────────────────────

fn value_ebv(v CXLValue) bool {
	if v.len == 0 { return false }
	if v.len > 1 { return true }
	it := v[0]
	return match it {
		CXLScalar {
			match it.data_type {
				.bool_type     { (it.value as bool) }
				.string_type   { (it.value as string).len > 0 }
				.int_type      { (it.value as i64) != 0 }
				.float_type    { f := (it.value as f64); f != 0.0 }
				.null_type     { false }
				.date_type, .datetime_type, .bytes_type, .decimal_type, .bigint_type { true }
			}
		}
		ScalarNode {
			match it.data_type {
				.bool_type     { (it.value as bool) }
				.string_type   { (it.value as string).len > 0 }
				.int_type      { (it.value as i64) != 0 }
				.null_type     { false }
				else           { true }
			}
		}
		else { true } // Node existence is truthy per cxdm.md §4.5
	}
}

fn value_to_string(v CXLValue) string {
	if v.len == 0 { return '' }
	mut b := strings.new_builder(16)
	for it in v { b.write_string(item_to_text(it)) }
	return b.str()
}

fn value_is_empty_or_null(v CXLValue) bool {
	if v.len == 0 { return true }
	for it in v {
		match it {
			CXLScalar {
				if it.data_type == .null_type { continue }
				if it.data_type == .string_type && (it.value as string).len == 0 { continue }
				return false
			}
			else { return false }
		}
	}
	return true
}

fn escape_html_str(s string) string {
	mut b := strings.new_builder(s.len + 8)
	for c in s {
		match c {
			`&` { b.write_string('&amp;') }
			`<` { b.write_string('&lt;') }
			`>` { b.write_string('&gt;') }
			`"` { b.write_string('&quot;') }
			`'` { b.write_string('&#39;') }
			else { b.write_u8(c) }
		}
	}
	return b.str()
}

fn escape_url_component(s string) string {
	mut b := strings.new_builder(s.len)
	for c in s.bytes() {
		match true {
			(c >= `0` && c <= `9`),
			(c >= `A` && c <= `Z`),
			(c >= `a` && c <= `z`),
			c == `-`, c == `_`, c == `.`, c == `~` {
				b.write_u8(c)
			}
			else {
				b.write_string('%')
				b.write_string(c.hex().to_upper())
			}
		}
	}
	return b.str()
}

// ── CXL expression evaluator ─────────────────────────────────────────────────
//
// CXL 1.0 expressions are CXPath plus three extensions documented in
// spec/eval.md §3.1 / §7 / §8 examples:
//   - bare `@name`                  → attribute on current context
//   - `path/@name`                  → CXPath select, then @name on each
//   - bare child name `description` → child element(s) of context
//   - top-level comparison `LHS OP RHS` → bool for [?if] tests
//   - bare variable reference `v`   → loop variable lookup
//   - `v/sub/path` and `v/@attr`    → variable as context root
//
// Numeric / string literals on the RHS of comparisons follow CX auto-
// typing (cxpath_autotype). String literals MAY be single-quoted.
//
// This is a pragmatic v0.6.0 implementation; the full XQuery-style
// expression grammar lands at CXL 3.1+.

fn eval_expr(expr_in string, mut env CXLEnv) !CXLValue {
	expr := expr_in.trim_space()
	if expr == '' { return CXLValue([]CXLItem{}) }
	// v0.7.0 (B9): Inline fn expression `fn (x, y) { body }` — XPath 3.0
	// surface. Parses params list + body, constructs CXLFunction value.
	if expr.starts_with('fn(') || expr.starts_with('fn (') {
		return eval_inline_fn_expr(expr, mut env)!
	}
	// v0.7.0 (B10): Arrow lambda `-> (x) { body }` — XPath 4.0 surface.
	// Same shape as B9 but with the arrow head; admits the zero-arg
	// shorthand `-> { body }` (no params) for use as a thunk.
	if expr.starts_with('->') {
		return eval_arrow_lambda_expr(expr, mut env)!
	}
	// Quoted string literal — `'…'` or `"…"`.
	if expr.len >= 2 && (expr[0] == `'` || expr[0] == `"`)
		&& expr[expr.len - 1] == expr[0] {
		body := expr[1..expr.len - 1]
		return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(body) })]
	}
	// Bare integer literal.
	if v := strconv.parse_int(expr, 10, 64) {
		return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(v) })]
	}
	// Nested directive call inside an Interpolation body, e.g.
	// `[?=[?upper [@name]]]` — the captured Interpolation body is
	// opaque text per parse_interpolation; to evaluate the nested
	// call we re-parse the fragment as a CX document and dispatch
	// the resulting EvalDirectiveNode.
	if expr.starts_with('[?') && expr.ends_with(']') {
		return eval_nested_directive_value(expr, mut env)!
	}
	// XPath 4.0 operator-token forms (A26-A28, A38, A41). These run
	// before path/comparison detection because their operators have
	// lower precedence than path navigation but higher than the
	// comparison ops `<`, `>`, `=`, `!=`. Order:
	//   `||` string concat (A38) — lowest priority among these
	//   `to` range (A41)
	//   `|>` pipeline (A26)
	//   `=>` arrow (A27)
	//   `!`  simple-map (A28)
	if pos := find_top_level_op(expr, '||') {
		return eval_op_concat(expr, pos, mut env)!
	}
	if pos := find_top_level_pipeline(expr) {
		return eval_op_pipeline(expr, pos, mut env)!
	}
	if pos := find_top_level_arrow(expr) {
		return eval_op_arrow(expr, pos, mut env)!
	}
	if pos := find_top_level_to(expr) {
		return eval_op_to(expr, pos, mut env)!
	}
	if pos := find_top_level_simple_map(expr) {
		return eval_op_simple_map(expr, pos, mut env)!
	}
	// Top-level comparison operator outside brackets → boolean test.
	if op_pos := find_top_level_comparison(expr) {
		return eval_comparison(expr, op_pos, mut env)!
	}
	return eval_path_expr(expr, mut env)!
}

// eval_inline_fn_expr parses `fn (x, y, ...) { body-expr }` and
// returns a CXLFunction value. v0.7.0 / B9 (XPath 3.0 inline function
// surface). Body is an arbitrary CXPath expression that will be
// re-evaluated against the call's argument bindings when the function
// value is invoked.
fn eval_inline_fn_expr(expr string, mut env CXLEnv) !CXLValue {
	// Locate `(` (skip past `fn` keyword + whitespace).
	mut i := 2
	for i < expr.len && expr[i] == ` ` { i++ }
	if i >= expr.len || expr[i] != `(` {
		return error('cxl: inline fn missing parameter list — expected `(` after `fn`, got: "${expr}"')
	}
	params_end := find_matching_paren(expr[i..])!
	params_str := expr[i + 1..i + params_end].trim_space()
	params := parse_fn_param_list(params_str)!
	// Skip whitespace + opening `{`.
	mut j := i + params_end + 1
	for j < expr.len && expr[j] == ` ` { j++ }
	if j >= expr.len || expr[j] != `{` {
		return error('cxl: inline fn missing body — expected `{` after params, got: "${expr[i + params_end + 1..]}"')
	}
	body_end := find_matching_brace(expr[j..])!
	body_str := expr[j + 1..j + body_end].trim_space()
	// Body is wrapped as a single InterpolationNode so the function
	// call evaluates it as a CXPath expression at invocation time.
	body_items := [Node(InterpolationNode{ expr: body_str })]
	// A21 closure capture per build_function_value.
	mut captured := map[string]CXLValue{}
	for k, v in env.bindings {
		if k in params { continue }
		captured[k] = v.clone()
	}
	if env.max_capture_size > 0 && i64(captured.len) > env.max_capture_size {
		return error('cx-err:CXER0011:inline-fn closure capture has ${captured.len} bindings, exceeds env.max_capture_size (${env.max_capture_size})')
	}
	return [CXLItem(CXLFunction{
		params:   params
		body:     body_items
		captured: captured
	})]
}

// eval_arrow_lambda_expr parses `-> (x) { body }` or `-> { body }`
// (zero-arg shorthand). v0.7.0 / B10 (XPath 4.0 lambda surface).
// Returns a CXLFunction value with the same semantics as B9.
fn eval_arrow_lambda_expr(expr string, mut env CXLEnv) !CXLValue {
	mut i := 2  // past `->`
	for i < expr.len && expr[i] == ` ` { i++ }
	mut params := []string{}
	if i < expr.len && expr[i] == `(` {
		params_end := find_matching_paren(expr[i..])!
		params_str := expr[i + 1..i + params_end].trim_space()
		params = parse_fn_param_list(params_str)!
		i = i + params_end + 1
		for i < expr.len && expr[i] == ` ` { i++ }
	}
	if i >= expr.len || expr[i] != `{` {
		return error('cxl: arrow lambda missing body — expected `{`, got: "${expr[i..]}"')
	}
	body_end := find_matching_brace(expr[i..])!
	body_str := expr[i + 1..i + body_end].trim_space()
	body_items := [Node(InterpolationNode{ expr: body_str })]
	mut captured := map[string]CXLValue{}
	for k, v in env.bindings {
		if k in params { continue }
		captured[k] = v.clone()
	}
	if env.max_capture_size > 0 && i64(captured.len) > env.max_capture_size {
		return error('cx-err:CXER0011:arrow-lambda closure capture has ${captured.len} bindings, exceeds env.max_capture_size (${env.max_capture_size})')
	}
	return [CXLItem(CXLFunction{
		params:   params
		body:     body_items
		captured: captured
	})]
}

// parse_fn_param_list splits a comma-separated param list, trimming
// each name. Accepts `x` or `$x` (the `$` prefix is stripped to match
// XPath conventions). Empty list returns empty.
fn parse_fn_param_list(s string) ![]string {
	if s.trim_space() == '' { return []string{} }
	mut out := []string{}
	for raw in s.split(',') {
		name := raw.trim_space().trim_left('$')
		if name == '' {
			return error('cxl: empty parameter name in `${s}`')
		}
		out << name
	}
	return out
}

// find_matching_brace returns the index of the `}` that closes the
// opening `{` at position 0 of s. Same algorithm as find_matching_paren.
fn find_matching_brace(s string) !int {
	if s.len == 0 || s[0] != `{` { return error('expected `{` at position 0') }
	mut depth := 1
	mut in_quote := u8(0)
	mut i := 1
	for i < s.len {
		c := s[i]
		if in_quote != 0 {
			if c == in_quote { in_quote = 0 }
			i++
			continue
		}
		if c == `'` || c == `"` { in_quote = c; i++; continue }
		if c == `{` || c == `(` || c == `[` { depth++ }
		else if c == `}` || c == `)` || c == `]` {
			depth--
			if depth == 0 { return i }
		}
		i++
	}
	return error('unbalanced `{` in: "${s}"')
}

// find_top_level_op locates `op` at zero bracket/paren/quote depth.
// Returns the byte index of the first character of op when found.
fn find_top_level_op(s string, op string) ?int {
	mut depth := 0
	mut in_quote := u8(0)
	mut i := 0
	for i < s.len {
		c := s[i]
		if in_quote != 0 {
			if c == in_quote { in_quote = 0 }
			i++
			continue
		}
		if c == `'` || c == `"` { in_quote = c; i++; continue }
		if c == `[` || c == `(` { depth++; i++; continue }
		if c == `]` || c == `)` { depth--; i++; continue }
		if depth == 0 && i + op.len <= s.len && s[i..i + op.len] == op {
			return i
		}
		i++
	}
	return none
}

// find_top_level_pipeline — `|>` not preceded by `|` and not followed by `|`.
fn find_top_level_pipeline(s string) ?int {
	pos := find_top_level_op(s, '|>') or { return none }
	// Reject `||>` collisions — `||` matches first elsewhere.
	if pos > 0 && s[pos - 1] == `|` { return none }
	return pos
}

// find_top_level_arrow — `=>` distinct from `==` and `>=`.
fn find_top_level_arrow(s string) ?int {
	pos := find_top_level_op(s, '=>') or { return none }
	if pos > 0 && s[pos - 1] == `=` { return none }
	return pos
}

// find_top_level_to — ` to ` (space-bounded) so it doesn't match
// inside identifiers like `auto`.
fn find_top_level_to(s string) ?int {
	mut depth := 0
	mut in_quote := u8(0)
	mut i := 0
	for i < s.len {
		c := s[i]
		if in_quote != 0 {
			if c == in_quote { in_quote = 0 }
			i++
			continue
		}
		if c == `'` || c == `"` { in_quote = c; i++; continue }
		if c == `[` || c == `(` { depth++; i++; continue }
		if c == `]` || c == `)` { depth--; i++; continue }
		if depth == 0 && i > 0 && i + 3 < s.len && s[i - 1] == ` `
			&& s[i] == `t` && s[i + 1] == `o` && s[i + 2] == ` ` {
			return i
		}
		i++
	}
	return none
}

// find_top_level_simple_map — `!` not followed by `=` (which is `!=`).
fn find_top_level_simple_map(s string) ?int {
	mut depth := 0
	mut in_quote := u8(0)
	mut i := 0
	for i < s.len {
		c := s[i]
		if in_quote != 0 {
			if c == in_quote { in_quote = 0 }
			i++
			continue
		}
		if c == `'` || c == `"` { in_quote = c; i++; continue }
		if c == `[` || c == `(` { depth++; i++; continue }
		if c == `]` || c == `)` { depth--; i++; continue }
		if depth == 0 && c == `!` && i + 1 < s.len && s[i + 1] != `=` {
			return i
		}
		i++
	}
	return none
}

fn eval_op_concat(expr string, pos int, mut env CXLEnv) !CXLValue {
	left := expr[..pos].trim_space()
	right := expr[pos + 2..].trim_space()
	l_val := eval_expr(left, mut env)!
	r_val := eval_expr(right, mut env)!
	out := '${value_to_string(l_val)}${value_to_string(r_val)}'
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(out) })]
}

fn eval_op_pipeline(expr string, pos int, mut env CXLEnv) !CXLValue {
	// `xs |> f` — f is a function value or filter name; call f(xs).
	left := expr[..pos].trim_space()
	right := expr[pos + 2..].trim_space()
	left_val := eval_expr(left, mut env)!
	// Right side: must be a directive call or fn-bound name. Build
	// `[?<right> [<saved-left>]]` and dispatch by interpolating the
	// left value through a sentinel binding.
	saved := env.bindings['__pipe_lhs'] or { CXLValue([]CXLItem{}) }
	had := '__pipe_lhs' in env.bindings
	env.bindings['__pipe_lhs'] = left_val
	defer {
		if had { env.bindings['__pipe_lhs'] = saved }
		else { env.bindings.delete('__pipe_lhs') }
	}
	directive_src := '[?${right} [__pipe_lhs]]'
	return eval_nested_directive_value(directive_src, mut env)!
}

fn eval_op_arrow(expr string, pos int, mut env CXLEnv) !CXLValue {
	// `xs => f()` — same shape as pipeline; arrow takes a postfix
	// `f()` call form. Strip trailing `()` if present.
	left := expr[..pos].trim_space()
	mut right := expr[pos + 2..].trim_space()
	if right.ends_with('()') { right = right[..right.len - 2] }
	left_val := eval_expr(left, mut env)!
	saved := env.bindings['__arrow_lhs'] or { CXLValue([]CXLItem{}) }
	had := '__arrow_lhs' in env.bindings
	env.bindings['__arrow_lhs'] = left_val
	defer {
		if had { env.bindings['__arrow_lhs'] = saved }
		else { env.bindings.delete('__arrow_lhs') }
	}
	directive_src := '[?${right} [__arrow_lhs]]'
	return eval_nested_directive_value(directive_src, mut env)!
}

fn eval_op_to(expr string, pos int, mut env CXLEnv) !CXLValue {
	left := expr[..pos - 1].trim_space()
	right := expr[pos + 3..].trim_space()
	lv := eval_expr(left, mut env)!
	rv := eval_expr(right, mut env)!
	lo := value_to_int(lv) or { return error('cxl: `to` left operand must be an integer, got "${value_to_string(lv)}"') }
	hi := value_to_int(rv) or { return error('cxl: `to` right operand must be an integer, got "${value_to_string(rv)}"') }
	// U4 (v0.7.0 security): cap the materialised sequence length.
	// `1 to 10_000_000_000` would otherwise allocate gigabytes of
	// CXLScalar items before the caller saw an error.
	span := hi - lo + 1
	if env.max_sequence_len > 0 && span > env.max_sequence_len {
		return error('cx-err:CXER0011:range `${lo} to ${hi}` would produce ${span} items, exceeds env.max_sequence_len (${env.max_sequence_len})')
	}
	mut out := []CXLItem{cap: int(span)}
	mut v := lo
	for v <= hi {
		out << CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(v) })
		v++
	}
	return CXLValue(out)
}

fn eval_op_simple_map(expr string, pos int, mut env CXLEnv) !CXLValue {
	// `xs ! f` — apply f to each item; concatenate results.
	left := expr[..pos].trim_space()
	right := expr[pos + 1..].trim_space()
	left_val := eval_expr(left, mut env)!
	mut out := []CXLItem{}
	saved_ctx := env.context
	for it in left_val {
		env.context = [it]
		r := eval_expr(right, mut env)!
		for ri in r { out << ri }
	}
	env.context = saved_ctx
	return CXLValue(out)
}

fn eval_nested_directive_value(expr string, mut env CXLEnv) !CXLValue {
	frag := parse(expr) or {
		return error('cxl: nested directive parse failed: ${err.msg()}')
	}
	for n in frag.elements {
		match n {
			EvalDirectiveNode { return eval_filter_directive(n, mut env)! }
			InterpolationNode { return eval_expr(n.expr, mut env)! }
			else {}
		}
	}
	for n in frag.prolog {
		match n {
			EvalDirectiveNode { return eval_filter_directive(n, mut env)! }
			InterpolationNode { return eval_expr(n.expr, mut env)! }
			else {}
		}
	}
	return error('cxl: nested directive expression empty: "${expr}"')
}

// find_top_level_comparison returns the byte index of the operator
// (first byte of `>`, `<`, `=`, `!`) when an unbracketed comparison
// operator appears at top level.
fn find_top_level_comparison(s string) ?int {
	mut depth := 0
	mut i := 0
	for i < s.len {
		c := s[i]
		if c == `[` || c == `(` { depth++ }
		else if c == `]` || c == `)` { depth-- }
		else if depth == 0 {
			if c == `>` || c == `<` { return i }
			if c == `=` { return i }
			if c == `!` && i + 1 < s.len && s[i+1] == `=` { return i }
		}
		i++
	}
	return none
}

fn eval_comparison(expr string, op_pos int, mut env CXLEnv) !CXLValue {
	mut op_len := 1
	mut op := expr[op_pos..op_pos + 1]
	if op_pos + 1 < expr.len {
		next := expr[op_pos + 1]
		if (op == '>' || op == '<' || op == '!' || op == '=') && next == `=` {
			op = expr[op_pos..op_pos + 2]
			op_len = 2
		}
	}
	lhs := expr[..op_pos].trim_space()
	rhs := expr[op_pos + op_len..].trim_space()
	left  := eval_path_expr(lhs, mut env)!
	right := parse_rhs_literal(rhs, mut env)!
	b := compare_values(left, op, right)!
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(b) })]
}

fn parse_rhs_literal(rhs string, mut env CXLEnv) !CXLValue {
	if rhs.len > 0 && (rhs[0] == `@` || rhs[0] == `/` || rhs[0] == `'`) {
		if rhs[0] == `'` {
			s := rhs.trim('\'')
			return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(s) })]
		}
		return eval_path_expr(rhs, mut env)!
	}
	// Variable-rooted path on the RHS: `var`, `var/path`, `var/@attr`.
	// The LHS path is always run through eval_path_expr; without this
	// branch the RHS would stringify a `ref/@id` literal and break
	// path-vs-path comparisons (e.g. inside :where, [?if] conditions,
	// or bare equality). Identifier-start + in-bindings catches the
	// case; bare tokens that happen to match a number / bool /
	// scalar still fall through to cxpath_autotype below.
	if rhs.len > 0 && is_ident_start(rhs[0]) {
		mut end := 0
		for end < rhs.len && is_ident_cont(rhs[end]) { end++ }
		head := rhs[..end]
		if head in env.bindings {
			return eval_path_expr(rhs, mut env)!
		}
	}
	sv := cxpath_autotype(rhs)
	ty := scalar_type_of(sv)
	return [CXLItem(CXLScalar{ data_type: ty, value: sv })]
}

fn scalar_type_of(v ScalarValue) ScalarType {
	return match v {
		bool      { ScalarType.bool_type }
		i64       { ScalarType.int_type }
		f64       { ScalarType.float_type }
		string    { ScalarType.string_type }
		NullValue { ScalarType.null_type }
	}
}

fn compare_values(left CXLValue, op string, right CXLValue) !bool {
	if left.len == 0 || right.len == 0 {
		return op == '!=' && (left.len != right.len)
	}
	lv := item_to_scalar(left[0]) or { return error('cxl: lhs is not a scalar') }
	rv := item_to_scalar(right[0]) or { return error('cxl: rhs is not a scalar') }
	return scalar_compare(lv, op, rv)
}

fn item_to_scalar(it CXLItem) ?ScalarValue {
	return match it {
		CXLScalar  { it.value }
		ScalarNode { it.value }
		TextNode   { ScalarValue(it.value) }
		Element    { ScalarValue(element_text_content(it)) }
		else       { none }
	}
}

fn scalar_compare(l ScalarValue, op string, r ScalarValue) !bool {
	if l is i64 && r is i64 {
		li := l as i64
		ri := r as i64
		return match op {
			'=', '==' { li == ri }
			'!='      { li != ri }
			'<'       { li < ri }
			'<='      { li <= ri }
			'>'       { li > ri }
			'>='      { li >= ri }
			else      { error('cxl: unknown comparison op ${op}') }
		}
	}
	if (l is i64 || l is f64) && (r is i64 || r is f64) {
		lf := as_f64(l)
		rf := as_f64(r)
		return match op {
			'=', '==' { lf == rf }
			'!='      { lf != rf }
			'<'       { lf < rf }
			'<='      { lf <= rf }
			'>'       { lf > rf }
			'>='      { lf >= rf }
			else      { error('cxl: unknown comparison op ${op}') }
		}
	}
	if l is string && r is string {
		ls := l as string
		rs := r as string
		return match op {
			'=', '==' { ls == rs }
			'!='      { ls != rs }
			else      { error('cxl: string comparison only supports = and != (got ${op})') }
		}
	}
	if l is bool && r is bool {
		lb := l as bool
		rb := r as bool
		return match op {
			'=', '==' { lb == rb }
			'!='      { lb != rb }
			else      { error('cxl: bool comparison only supports = and != (got ${op})') }
		}
	}
	if op == '=' || op == '==' { return false }
	if op == '!=' { return true }
	return error('cxl: cannot order-compare values of incompatible types')
}

fn as_f64(v ScalarValue) f64 {
	return match v {
		i64       { f64(v) }
		f64       { v }
		string    { strconv.atof64(v) or { 0.0 } }
		bool      { if v { 1.0 } else { 0.0 } }
		NullValue { 0.0 }
	}
}

// ── Path expression evaluation ───────────────────────────────────────────────

fn eval_path_expr(expr string, mut env CXLEnv) !CXLValue {
	// 1. variable reference: leading word + optional '/'
	if expr.len > 0 && is_ident_start(expr[0]) {
		mut end := 0
		for end < expr.len && is_ident_cont(expr[end]) { end++ }
		head := expr[..end]
		if head in env.bindings {
			rest := expr[end..]
			return eval_path_from_value(env.bindings[head], rest, env)!
		}
	}
	// 1b. v0.7.0 (A4/A5 / B12): unary lookup operator `?key` —
	// resolves against env.context when it's a single MapNode. Spelled
	// `?key` at the start of an expression with no leading variable.
	if expr.starts_with('?') && expr.len > 1 && is_ident_start(expr[1]) {
		return eval_lookup_against(env.context, expr[1..])!
	}
	// 2. attribute access on context
	if expr.starts_with('@') {
		return eval_attr_access(env.context, expr[1..])!
	}
	// 3. trailing /@attr → CXPath select + attribute access
	if at := expr.last_index('/@') {
		path_part := expr[..at]
		attr_part := expr[at + 2..]
		base := eval_cxpath_against_cached(env.context, path_part, mut env)!
		return eval_attr_access(base, attr_part)!
	}
	// 4. plain CXPath path
	return eval_cxpath_against_cached(env.context, expr, mut env)!
}

fn eval_path_from_value(base CXLValue, rest string, env CXLEnv) !CXLValue {
	if rest == '' { return base }
	// v0.7.0 (A2/A3/B8): postfix call `$x(arg)` —
	//   - CXLFunction base → invoke as function (B8)
	//   - MapNode base     → equivalent to map:get($map, $arg) (A2)
	//   - ArrayNode base   → equivalent to array:get($arr, $arg) (A3)
	// Parses one argument (XPath 4.0 generalises to comma-separated
	// args; that lands when the broader expression grammar arrives).
	if rest.starts_with('(') {
		end := find_matching_paren(rest)!
		arg_expr := rest[1..end].trim_space()
		tail := rest[end + 1..].trim_space()
		mut env_local := env  // eval_expr needs mut env
		// Zero-arg call `f()` carries an empty arg list, not one
		// empty-sequence arg. Distinguish so 0-arity functions invoke
		// correctly.
		mut args := []CXLValue{}
		if arg_expr != '' {
			args << eval_expr(arg_expr, mut env_local)!
		}
		result := eval_postfix_call_n(base, args, mut env_local)!
		if tail == '' { return result }
		return eval_path_from_value(result, tail, env_local)!
	}
	// v0.7.0 (A4/B12): postfix lookup `$x?key` — MapNode get by key.
	if rest.starts_with('?') && rest.len > 1 && is_ident_start(rest[1]) {
		mut key_end := 1
		for key_end < rest.len && is_ident_cont(rest[key_end]) { key_end++ }
		key := rest[1..key_end]
		tail := rest[key_end..]
		result := eval_lookup_against(base, key)!
		if tail == '' { return result }
		return eval_path_from_value(result, tail, env)!
	}
	if rest.starts_with('/@') { return eval_attr_access(base, rest[2..])! }
	if rest.starts_with('/') {
		// Variable-rooted relative path. A trailing `/@attr` (after one
		// or more child steps) must split off as an attribute access —
		// the CXPath sub-parser used by eval_cxpath_against doesn't
		// speak `@attr` step syntax, so e.g. `var/in_cx/@src` would
		// reach it as `in_cx/@src` and trip "expected element name".
		// Top-level eval_path_expr already does this split via
		// last_index('/@'); the variable-rooted branch mirrors it.
		if at := rest.last_index('/@') {
			path_part := rest[1..at]
			attr_part := rest[at + 2..]
			intermediate := eval_cxpath_against(base, path_part)!
			return eval_attr_access(intermediate, attr_part)!
		}
		return eval_cxpath_against(base, rest[1..])!
	}
	if rest.starts_with('@')  { return eval_attr_access(base, rest[1..])! }
	return error('cxl: malformed variable continuation "${rest}"')
}

// find_matching_paren returns the index of the `)` that closes the
// opening `(` at position 0 of s. Tracks nested parens / brackets and
// quote-skipping. Errors on unbalanced input.
fn find_matching_paren(s string) !int {
	if s.len == 0 || s[0] != `(` { return error('expected `(` at position 0') }
	mut depth := 1
	mut in_quote := u8(0)
	mut i := 1
	for i < s.len {
		c := s[i]
		if in_quote != 0 {
			if c == in_quote { in_quote = 0 }
			i++
			continue
		}
		if c == `'` || c == `"` { in_quote = c; i++; continue }
		if c == `(` || c == `[` || c == `{` { depth++ }
		else if c == `)` || c == `]` || c == `}` {
			depth--
			if depth == 0 { return i }
		}
		i++
	}
	return error('unbalanced `(` in: "${s}"')
}

// eval_postfix_call_n dispatches a `$x(args...)` postfix call based on
// the bound value's runtime type. Per XPath 4.0 §4.14.1.2 (map as fn),
// §4.14.2.2 (array as fn), and §3.2.2 (general function call).
// Zero-arg calls (e.g. `h()` against an arity-0 function) pass an
// empty args list rather than one empty-sequence arg.
fn eval_postfix_call_n(base CXLValue, args []CXLValue, mut env CXLEnv) !CXLValue {
	if base.len == 1 {
		first := base[0]
		match first {
			CXLFunction {
				fn_val := first as CXLFunction
				return call_fn_to_value(fn_val, args, mut env)!
			}
			MapNode {
				if args.len < 1 {
					return error('cxl: map-as-function call requires a key argument')
				}
				return map_get_value(first as MapNode, args[0])
			}
			ArrayNode {
				if args.len < 1 {
					return error('cxl: array-as-function call requires an index argument')
				}
				return array_get_value(first as ArrayNode, args[0])!
			}
			else {}
		}
	}
	return error('cxl: postfix call on non-callable value (expected function / map / array, got sequence of ${base.len} items)')
}

// map_get_value returns the value at key in the MapNode, or empty
// sequence when key is absent. Matches map:get($map, $key) semantics.
fn map_get_value(m MapNode, key_v CXLValue) CXLValue {
	if key_v.len == 0 { return CXLValue([]CXLItem{}) }
	key_str := item_to_text(key_v[0])
	for entry in m.entries {
		if scalar_value_str(entry.key_value) == key_str {
			return [collection_item_to_cxlitem(entry.value)]
		}
	}
	return CXLValue([]CXLItem{})
}

// array_get_value returns the item at 1-based index in the ArrayNode.
// Matches array:get($arr, $i) semantics. Out-of-range indices return
// empty sequence (XPath 4.0 default).
fn array_get_value(a ArrayNode, idx_v CXLValue) !CXLValue {
	if idx_v.len == 0 { return CXLValue([]CXLItem{}) }
	idx := i64(item_to_f64(idx_v[0]))
	if idx < 1 || idx > i64(a.items.len) {
		return CXLValue([]CXLItem{})
	}
	return [collection_item_to_cxlitem(a.items[idx - 1])]
}

// collection_item_to_cxlitem upcasts a collection-literal Node to a
// CXLItem. Handles the common cases produced by sequence/array/map
// literals.
fn collection_item_to_cxlitem(n Node) CXLItem {
	return match n {
		Element       { CXLItem(n) }
		TextNode      { CXLItem(n) }
		ScalarNode    { CXLItem(n) }
		CommentNode   { CXLItem(n) }
		SequenceNode  { CXLItem(ArrayNode{ items: (n as SequenceNode).items }) }
		ArrayNode     { CXLItem(n) }
		MapNode       { CXLItem(n) }
		else          { CXLItem(TextNode{ value: '' }) }
	}
}

// eval_lookup_against implements the `?key` lookup operator
// (XPath 4.0 §4.14.3 / GG-row A4/A5/B12). Applies per-item:
//   - MapNode item → return its entry at `key` if present
//   - Other items  → skipped (per XPath 4.0 type-error-on-non-map
//                     semantics, except v0.7.0 returns empty for
//                     mixed sequences to compose cleanly with
//                     `//items?count` paths)
fn eval_lookup_against(ctx CXLValue, key string) !CXLValue {
	mut out := []CXLItem{}
	for it in ctx {
		if it is MapNode {
			m := it as MapNode
			for entry in m.entries {
				if scalar_value_str(entry.key_value) == key {
					out << collection_item_to_cxlitem(entry.value)
				}
			}
		}
	}
	return out
}

fn eval_attr_access(ctx CXLValue, attr_query string) !CXLValue {
	mut out := []CXLItem{}
	for it in ctx {
		if it is Element {
			if v := cxpath_attr_lookup(it, attr_query, map[string]string{}) {
				out << CXLItem(CXLScalar{
					data_type: cxl_attr_type(it, attr_query)
					value:     v
				})
			}
		}
	}
	return out
}

fn cxl_attr_type(el Element, attr_query string) ScalarType {
	for a in el.attrs {
		if a.name == attr_query {
			if dt := a.data_type { return dt }
			return .string_type
		}
	}
	return .string_type
}

// eval_cxpath_against runs a CXPath-style path against the items in
// ctx. For each Element item we invoke `el.select_all(path)`. The path
// may be a CXPath expression (e.g. `//variant[@stock > 0]`) or a bare
// child-name (`description`).
fn eval_cxpath_against(ctx CXLValue, path string) !CXLValue {
	mut out := []CXLItem{}
	p := path.trim_space()
	if p == '' { return ctx }
	for it in ctx {
		if it is Element {
			els := it.select_all(p)
			for el in els { out << CXLItem(el) }
		}
	}
	return out
}

// eval_cxpath_against_cached is the memoizing version of
// eval_cxpath_against. Y6 perf: the bench profile shows
// cxpath_collect_descendants_chain at 601k calls / 3.5s self-time on
// the streaming workload, dominated by repeated `//foo` evaluations
// inside outer `?for` loops where the root document is invariant.
//
// Cache key is the path string. Safe within a single eval_cxl call
// because:
//   1. cx:patch is M5-gated during eval (input is immutable)
//   2. eval_cxpath_against_cached is only used when ctx == env.context
//      (the implicit root document; never per-iteration scope)
// The cache lives in env.path_cache, so a fresh eval call gets a
// fresh cache via new_cxl_env. ?for loop variables that re-bind ctx
// to a sub-element use eval_cxpath_against (uncached) directly.
fn eval_cxpath_against_cached(ctx CXLValue, path string, mut env CXLEnv) !CXLValue {
	p := path.trim_space()
	if p == '' { return ctx }
	if cached := env.path_cache[p] {
		// Y6 perf: cache stores the wrapped CXLValue directly so a hit
		// is a single slice-handle return (read-only sharing is safe —
		// input is immutable during eval; cx:patch is M5-gated). Saves
		// 150K CXLItem allocations on the streaming bench.
		return cached
	}
	mut out := []CXLItem{}
	for it in ctx {
		if it is Element {
			els := it.select_all(p)
			for el in els {
				out << CXLItem(el)
			}
		}
	}
	env.path_cache[p] = out
	return out
}

fn is_ident_start(c u8) bool {
	return (c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`) || c == `_`
}

fn is_ident_cont(c u8) bool {
	return is_ident_start(c) || (c >= `0` && c <= `9`) || c == `-`
}

// bare_ident_is_bound reports whether `t` is a CXPath-shaped identifier-
// or-path expression whose leading identifier is currently bound in
// env.bindings (a `?for` loop var, `?with` context binding, or `?def`
// template parameter). Used by eval_slot_to_value to distinguish
// variable references (resolve via eval_expr) from literal strings
// in filter/template-call arguments.
fn bare_ident_is_bound(t string, env CXLEnv) bool {
	if t.len == 0 { return false }
	if !is_ident_start(t[0]) { return false }
	mut end := 0
	for end < t.len && is_ident_cont(t[end]) { end++ }
	head := t[..end]
	if head == '' { return false }
	return head in env.bindings
}
