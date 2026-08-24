module code

import cx
import crypto.sha256
import os
import strconv
import strings
import sync
import time
import math

// declared so [?sleep DUR]'s wall-clock path can invoke
// emscripten_sleep directly under the ASYNCIFY-instrumented playground
// wasm build (see scripts/wasm/build_libcx_wasm.sh `ASYNCIFY=1`). The
// symbol is provided by emscripten's runtime; on native builds the
// `$if wasm32_emcc { $if asyncify_build` guards keep this branch
// unreachable so the linker never sees the reference.
fn C.emscripten_sleep(ms int)

// ── program evaluator (pure-functional core) ─────────────────────────────────────
//
// Phase 3.3 + 3.4. Implements:
//   - Expression evaluation: literals, bindings with paths, calls.
//   - For-comprehension: generators (binding + pattern-destructuring),
//     filters, let-bindings, order-by, group-by, on-error, limit, yield.
//   - Directive dispatch for the core pure-functional surface:
//       [?match], [?if], [?let], [?try], [?pipe].
//
// Pure: no I/O, no time, no concurrency, no networking. Resilience
// directives, services, workers, async, and visualization are evaluated
// elsewhere (Phases 3.7–3.10).
//
// Spec refs:
//   - spec/md §6 (bindings / paths / function calls)
//   - spec/md §7 (for-comprehension)
//   - spec/md §8 (directives reference — core)
//   - spec/md §9 (errors)

// EvalError is raised when an evaluator branch encounters a runtime
// fault that isn't catchable via the err-value-propagation mechanism
// (e.g. unknown identifier in a binding lookup). Catchable errors are
// returned as [err …] cx.Node values per spec/md §9.
pub struct EvalError {
	Error
pub:
	code    string
	message string
	// cause carries an underlying err-value (cx.Element) when the error
	// was triggered by a `!`-postfix on a call that returned an err-value
	// rather than thrown. Boundary converters (eval_match_scrutinee,
	// eval_with_error_hook, eval_fallback) wrap it as the new err's
	// `:cause` slot so the cause chain survives the conversion per
	// spec/code.md §9.2 panic-postfix semantics. When `cause_set`
	// is false, the field is unset (V can't store an `?cx.Node` cleanly
	// in an Error-embedding struct, so we use a parallel boolean flag).
	cause     cx.Node
	cause_set bool
}

pub fn (e EvalError) msg() string {
	return '${e.code}: ${e.message}'
}

// eval is the public entry point. Evaluates `node` in the given env
// and returns the resulting CX value, or an EvalError on hard failure.
pub fn eval(node cx.ProgramNode, mut env MatchEnv) !cx.Node {
	result := eval_node(node, mut env)!
	// Finalize a returned closure-driven generator (the only iterators whose
	// realization needs the live env to apply `f`). [$unfold] MAY terminate, so
	// force-realize it to a finite Sequence (budget-backstopped). [$iterate] is
	// statically infinite — a bare result cannot be materialized whole (§1.5).
	if result is cx.IteratorNode {
		if result.source_kind == .iter_unfold {
			return realize_unfold(result, mut env)
		}
		if result.source_kind == .iter_iterate {
			return mk_err('cx-err:CXER0100',
				'infinite generator cannot be fully materialised — use [take] / [take-while]')
		}
	}
	return result
}

pub fn eval_node(node cx.ProgramNode, mut env MatchEnv) !cx.Node {
	// #319 stack guard: every evaluation shape funnels through here, so one
	// probe per node bounds non-tail recursion (only tail calls are
	// trampolined — #60). Raising the catchable value-form err while ~1 MiB
	// of stack remains turns the former SIGSEGV into `cx-err:CXER0272`
	// (E_STACK_EXHAUSTED) that railway-propagates out — recoverable by
	// [?fallback]/[?match] like any other err. See eval_stack_guard.c.v.
	if eval_stack_low() {
		return mk_err_stack_exhausted()
	}
	// F4 evaluation budget (S6.2, RULED: F4): the same single-funnel property
	// the stack guard rides — one probe per node bounds every evaluation
	// shape. steps = eval_node entries; memory = monotone allocated bytes
	// (gc_total_allocated) against the arm-time baseline, sampled every 64
	// steps. The trip LATCHES (tripped_conjunct): after the first refusal
	// every subsequent step re-refuses, so the budgeted evaluation cannot
	// absorb CXER0273 and resume. nil budget = the unbudgeted default.
	// The refusal rides the THROWN V-error channel (EvalError), not an err
	// VALUE: value-form errs railway-propagate only where callers check
	// err-ness, and the streamed iterator/yield hot paths collect result
	// nodes without introspection — a value-form refusal was measured being
	// COLLECTED (an armed 100-iteration count answered 100 with the latch
	// tripped at step 6). A thrown error short-circuits mechanically.
	if env.eval_budget != unsafe { nil } {
		mut b := unsafe { env.eval_budget }
		if b.tripped_conjunct.len > 0 {
			return err_eval_budget(b.tripped_conjunct, if b.tripped_conjunct == 'steps' {
				b.step_limit
			} else {
				b.mem_limit
			})
		}
		b.steps++
		if b.step_limit > 0 && b.steps > b.step_limit {
			b.tripped_conjunct = 'steps'
			return err_eval_budget('steps', b.step_limit)
		}
		if b.mem_limit > 0 && (b.steps & 63) == 0 {
			used := u64(gc_total_allocated())
			if used > b.mem_base && used - b.mem_base > b.mem_limit {
				b.tripped_conjunct = 'memory'
				return err_eval_budget('memory', b.mem_limit)
			}
		}
	}
	$if cx_envcheck ? {
		// Sampled 1-in-256: the full check on this ultra-hot path made rounds
		// ~20x slower; a dead env evaluates thousands of nodes so sampling only
		// bounds first-report latency, not coverage.
		if vgc_envcheck_sample() {
			envcheck_probe('eval_node', &env)
		}
	}
	match node {
		// Direct result returns (no `!`): identical propagation semantics,
		// but V emits a plain C `return f(…)` with ZERO result-struct
		// temporaries where `return f(…)!` burns three per arm — this
		// function runs twice per non-tail recursion level (#319 frame diet).
		cx.ProgramLiteral   { return eval_literal(node, mut env) }
		cx.ProgramBinding   { return eval_binding(node, mut env) }
		cx.ProgramCall      { return eval_call(node, mut env) }
		cx.ProgramDirective { return eval_directive(node, mut env) }
		cx.ProgramForComp   { return eval_for_comp(node, mut env) }
		cx.ProgramPathExpr  { return eval_path_expr(node, mut env) }
		cx.ProgramSliceAccess { return eval_slice_access(node, mut env) }
		cx.ProgramSliceLiteral { return eval_slice_literal(node, mut env) }
		cx.ProgramPattern, cx.ProgramWildcard, cx.Program {
			return EvalError{
				code:    'cx-err:CXER0001'
				message: 'evaluator reached a structural-only AST node'
			}
		}
	}
}

// ── Literals ────────────────────────────────────────────────────────────────

fn eval_literal(l cx.ProgramLiteral, mut env MatchEnv) !cx.Node {
	// Literal-result postfix steps (RULED PS-1, #886): `[user [b 1]]/b`,
	// `[+ 1 2]/x`, `[1, 2]/x`, `(1, 2)/x`, `{a: 1}.a` — the literal
	// evaluates exactly as the step-less form, then the step run
	// destructures the RESULT VALUE through apply_value_path, THE
	// machinery the binding read uses (the CRS-1 pattern; the
	// [?let]-equivalence holds by construction).
	if l.path.len > 0 {
		base := eval_literal(cx.ProgramLiteral{ ...l, path: []cx.ProgramPathStep{} }, mut env)!
		return apply_value_path(base, l.path, mut env, true)
	}
	// Match STATEMENT with direct returns, not a `return match` expression:
	// expression arms force a result-temp per `!` arm, direct returns emit
	// none — this function runs twice per non-tail recursion level (#319
	// frame diet; same propagation semantics).
	match l.kind {
		.string_lit { return scalar(cx.ScalarValue(l.str_val), cx.ScalarType.string_type) }
		.int_lit    { return scalar(cx.ScalarValue(l.int_val), cx.ScalarType.int_type) }
		.bigint_lit { return scalar(cx.ScalarValue(l.str_val), cx.ScalarType.bigint_type) }
		.decimal_lit { return scalar(cx.ScalarValue(l.str_val), cx.ScalarType.decimal_type) }
		.float_lit  { return scalar(cx.ScalarValue(l.flt_val), cx.ScalarType.float_type) }
		.bool_lit   { return scalar(cx.ScalarValue(l.bool_val), cx.ScalarType.bool_type) }
		.duration_lit { return scalar(cx.ScalarValue(l.dur_val), cx.ScalarType.duration_type) }
		.period_lit   { return scalar(cx.ScalarValue(l.dur_val), cx.ScalarType.period_type) }
		.date_lit     { return scalar(cx.ScalarValue(l.str_val), cx.ScalarType.date_type) }
		.datetime_lit { return scalar(cx.ScalarValue(l.str_val), cx.ScalarType.datetime_type) }
		.sequence_lit { return eval_sequence(l.items, mut env) }
		.array_lit    { return eval_array(l.items, mut env) }
		.map_lit    { return eval_map(l.keys, l.key_kinds, l.decl_kinds, l.items, mut env) }
		.cx_element { return eval_cx_element(l, mut env) }
		.block      { return eval_block(l.items, mut env) }
		// atom literal — evaluates to a typed atom
		// scalar value carrying the name. Equality is type-strict
		// per cxdm.md §4.1 (atom never coerces with string).
		.atom_lit   { return scalar(cx.ScalarValue(l.str_val), cx.ScalarType.atom_type) }
		// DATA↔PROGRAM seam: an embedded pure-DATA construct (`[#…#]` raw /
		// `&…;` entity / `[!…]` declaration / `[!DOCTYPE …]`) evaluates to the
		// node the data reader produced, verbatim. The "data = a program that
		// evaluates to itself" invariant holds by construction: this node IS
		// the data reading, so `cx file.cx` (eval) renders identically to
		// `cx --from=cx --to=cx file.cx` (data).
		.node_lit {
			return l.node or {
				return EvalError{
					code:    'cx-err:CXER0001'
					message: 'node_lit literal carries no node'
				}
			}
		}
	}
}

// eval_block evaluates a multi-expression top-level program: each
// expression runs in order, sharing the env (so [?def] / [?let]
// registrations are visible to subsequent expressions), and the LAST
// expression's value is returned. Earlier expressions are side-effects.
fn eval_block(items []cx.ProgramNode, mut env MatchEnv) !cx.Node {
	if items.len == 0 {
		return cx.Element{ name: '' }
	}
	// ── Two-pass top-level `[?const]` (spec/code.md §12.5) ──────────────
	// When the program block carries top-level `[?const]` declarations we
	// honour the §12.5 module-load order: Pass 1 — register declarations,
	// resolving `[?lib]` imports first so a const body may call an imported
	// member (`[?const SHOUT [$strings:upper GREETING]]`); Pass 2 —
	// evaluate consts in topological dependency order (forward refs OK;
	// cyclic → CXER0214); Pass 3 — evaluate the remaining expressions in
	// source order, skipping the already-evaluated `[?lib]` / `[?const]`
	// directives. Blocks with NO top-level const skip this entirely — they
	// retain the plain in-source-order evaluation (zero behaviour change
	// for non-module programs).
	mut has_top_const := false
	for it in items {
		if it is cx.ProgramDirective && it.name == 'const' {
			has_top_const = true
			break
		}
	}
	if has_top_const {
		// Pass 1: register declarations. Resolve [?lib] imports (registers
		// module members) and [?def]s (self-register their closures) so a
		// const body may call an imported member or reference a def value
		// (`[?const TRIPLER $triple]`) declared anywhere in the block.
		for it in items {
			if it is cx.ProgramDirective && (it.name == 'lib' || it.name == 'def') {
				eval_node(it, mut env)!
			}
		}
		// Pass 2: topological const evaluation.
		prepare_top_level_consts(items, mut env)!
	}
	mut last := cx.Node(cx.Element{ name: '' })
	for it in items {
		// Skip [?const] / [?lib] / [?def] directives already handled by the
		// §12.5 two-pass above (only engaged when has_top_const). Skipping
		// [?def] re-evaluation also avoids the CXER0205 redeclaration trip.
		if has_top_const && it is cx.ProgramDirective
		   && (it.name == 'const' || it.name == 'lib' || it.name == 'def') {
			continue
		}
		last = eval_node(it, mut env)!
		// Homoiconic 1-source case: a program may carry inert data
		// alongside directives at the same top level. When $doc has
		// not been bound by the caller (no `input` argument to
		// eval_code), bind it to the first DATA root — the first
		// top-level form that is an element literal — so downstream
		// pattern-as-source [?for] etc. resolve against the document
		// right there in the source. The selection is by the SOURCE
		// form, not the evaluated value: a program-directive root
		// ([?lib]/[?def]/…) evaluates to a program-internal status
		// element ([result status=ok …]) that must never capture the
		// document binding, whatever its position (#435; code.md §1.3).
		if _ := env.bindings['doc'] {
			// already bound — first data root wins
		} else {
			if is_data_root(it) && last is cx.Element {
				env.cow_bindings()
				env.bindings['doc'] = last
				env.bindings['input'] = last
			}
		}
	}
	return last
}

// top_level_decl_names are the declaration directives whose evaluation
// yields a program-internal status element ([result status=ok …]) rather
// than user-facing output. The CLI/program emit boundary omits their result
// when rendering each top-level form (#16).
const top_level_decl_names = ['def', 'const', 'lib', 'import']

fn is_top_level_decl(n cx.ProgramNode) bool {
	if n is cx.ProgramDirective {
		return n.name in top_level_decl_names
	}
	return false
}

// is_data_root reports whether a top-level program form is a DATA root —
// an element literal (the program surface of the data reading's element
// production) — as opposed to a program root (directive, call, binding,
// path expression, …). Only a data root may become the implicit $doc
// (code.md §1.3): a directive's status element and a call's element-valued
// result are program values, not the document, whatever their position
// among the roots (#435). The classification is per SOURCE form, so every
// program directive — known or future — behaves identically here.
fn is_data_root(n cx.ProgramNode) bool {
	if n is cx.ProgramLiteral {
		return n.kind == .cx_element
	}
	return false
}

// note_top_level_result classifies one top-level result against its own source
// form and latches the R5.13 failure flag (declared in api.v). Called from BOTH
// result boundaries — the single-form path in eval_code and the multi-form loop
// in eval_top_level_each below — because a program is either shape and the run
// surface must not depend on which.
//
// HISTORY (#864, CLOSED): this function's placement was once load-bearing —
// under the pre-b3d0da670d compiler, `-usecache` linked the vcx/code cached
// layer and the program TU with DISAGREEING sumtype `_typ` tables, and this
// signature in api.v (the module's first file) re-rolled the routing so a
// generated str walker crashed on a four-line AST. The fork compiler now
// type-table-validates every cached layer before linking (mismatches emit
// inline), so placement is free again; it stays here because beside
// eval_top_level_each is its natural home. Full story: #864 and the R5.13
// row of ledger/partition_remediation_register.md.
fn note_top_level_result(result cx.Node, form cx.ProgramNode) {
	if is_err_value(result) && !is_literal_err_head(form) {
		cx_top_level_err_failure = true
	}
}

// eval_top_level_each evaluates a multi-form top-level program block exactly
// as eval_block does — shared env, §12.5 two-pass const handling, $doc
// auto-binding — but returns the result of EACH non-declaration top-level
// form in source order rather than only the last. The CLI/program emit
// boundary (eval_code) renders each, so a leading data value no longer
// silently vanishes; this realigns the program reading with the DATA
// reading, which already emits every top-level root (#16; code.md §2 — the
// two readings agree on values absent an explicit MODE fork, and multi-root
// emit is not such a fork). eval_block (last-value) is unchanged, so in-
// program block semantics and the conformance eval harness are unaffected.
// R5.13 — the FORMS are returned alongside their results so the caller can
// classify each top-level result against its OWN source form after forcing.
// Results are not index-aligned with `items`: declaration directives are
// evaluated but contribute no user output, so pairing by index would
// misattribute every form after the first [?lib]/[?def]/[?const].
fn eval_top_level_each(items []cx.ProgramNode, mut env MatchEnv) !([]cx.Node, []cx.ProgramNode) {
	mut out := []cx.Node{}
	mut forms := []cx.ProgramNode{}
	if items.len == 0 {
		return out, forms
	}
	mut has_top_const := false
	for it in items {
		if it is cx.ProgramDirective && it.name == 'const' {
			has_top_const = true
			break
		}
	}
	if has_top_const {
		for it in items {
			if it is cx.ProgramDirective && (it.name == 'lib' || it.name == 'def') {
				eval_node(it, mut env)!
			}
		}
		prepare_top_level_consts(items, mut env)!
	}
	for it in items {
		// Skip [?const]/[?lib]/[?def] already evaluated by the two-pass.
		if has_top_const && it is cx.ProgramDirective
		   && (it.name == 'const' || it.name == 'lib' || it.name == 'def') {
			continue
		}
		mut res := eval_node(it, mut env)!
		// Finalize a closure-driven generator in each top-level VALUE position,
		// exactly as eval() does for a program result (R3.11 / audit F-18: the
		// multi-form run surface diverged — a top-level [$unfold f seed] worked
		// in-process but errored through `cx <file>`; value context is value
		// context on every surface).
		if res is cx.IteratorNode {
			if res.source_kind == .iter_unfold {
				res = realize_unfold(res, mut env)
			} else if res.source_kind == .iter_iterate {
				res = mk_err('cx-err:CXER0100',
					'infinite generator cannot be fully materialised — use [take] / [take-while]')
			}
		}
		// Implicit $doc: first DATA root only (see eval_block; #435).
		if _ := env.bindings['doc'] {
			// already bound — first data root wins
		} else {
			if is_data_root(it) && res is cx.Element {
				env.cow_bindings()
				env.bindings['doc'] = res
				env.bindings['input'] = res
			}
		}
		// Declaration directives are evaluated (for their registrations /
		// side effects) but their status result is not user output.
		if !is_top_level_decl(it) {
			out << res
			forms << it
		}
	}
	return out, forms
}

fn scalar(v cx.ScalarValue, t cx.ScalarType) cx.Node {
	return cx.ScalarNode{ value: v, data_type: t }
}

// prepare_top_level_consts implements the §12.5.2 two-pass `[?const]`
// load at the top-level program block: it collects every top-level
// `[?const]` directive, builds the const→const reference graph,
// topologically sorts it (cyclic dependency → CXER0214), and evaluates
// each const's body in dependency order, binding the result so a const
// may reference another declared later in source. A const-body eval
// failure surfaces as CXER0215. Lazy consts (`:lazy`) are evaluated here
// once and memoized (eval-on-first-use is observationally equivalent for
// the conformance contract: the body fires exactly once); their bound
// value is the memoized result. When no top-level const directive is
// present this is a no-op (the loop body never runs), so non-module
// programs are unaffected.
fn prepare_top_level_consts(items []cx.ProgramNode, mut env MatchEnv) ! {
	mut consts := map[string]cx.ConstNode{}
	for it in items {
		if it is cx.ProgramDirective && it.name == 'const' {
			raw := module_raw_source(it) or { continue }
			cn := cx.parse_const(raw) or {
				return EvalError{ code: 'cx-err:CXER0212', message: '[?const] parse: ${err.msg()}' }
			}
			if cn.name in consts {
				return EvalError{
					code:    'cx-err:CXER0205'
					message: 'cx-err:CXER0205 E_CONST_REDECLARED: `${cn.name}` declared more than once'
				}
			}
			consts[cn.name] = cn
		}
	}
	if consts.len == 0 {
		return
	}
	order := module_loader_toposort_consts(consts) or {
		// Cyclic [?const] dependency — §12.5.2 / §12.5.6 → CXER0214.
		return EvalError{ code: 'cx-err:CXER0214', message: 'cx-err:CXER0214 E_CONST_CYCLE: ${err.msg()}' }
	}
	for cname in order {
		cn := consts[cname] or { continue }
		cbody := cx.parse_program(cn.value_source) or {
			return EvalError{ code: 'cx-err:CXER0212', message: '[?const] `${cname}` body parse: ${err.msg()}' }
		}
		cval := eval_node(cbody.body, mut env) or {
			// Const-body initializer raised — §12.5.2 → CXER0215.
			return EvalError{ code: 'cx-err:CXER0215', message: 'cx-err:CXER0215 E_CONST_BODY_FAILED: const `${cname}`: ${err.msg()}' }
		}
		env.cow_bindings()
		env.bindings[cname] = cval
		// Mirror into the program scope so [?def] bodies resolve the const (#22).
		if env.scope != unsafe { nil } {
			env.scope.bindings[cname] = cval
		}
	}
}

// Sequence-marker name used by eval_sequence; render-side recognises
// this and emits paren form `(a, b, c)`. Top-level program output uses
// the empty name '' (renderers emit newline-separated to match fixture
// out_text shape for multi-result evaluation like [?for]).
// generator_force_budget caps how many pulls a force-realized lazy generator
// ([$unfold], and the for-comp incremental walkers) may take before raising
// CXER0100 ("generator exceeded force budget") — a backstop against a runaway,
// never a hang (code.md §1.5 / §6.7).
const generator_force_budget = 1_000_000

pub const seq_marker_name = '__cx_seq__'

// eval_directive_view returns an Element VIEW of a directive-as-data node
// (an EvalDirectiveNode reached as a value, e.g. from `[$cx:parse]` of
// directive-bearing source, #436) for path descent and modify focus
// resolution. Same attrs/items; the name is prefixed `?` so an element
// NodeTest never aliases a directive (a directive is not an element —
// paths descend THROUGH it, they do not match it by element name).
fn eval_directive_view(n cx.EvalDirectiveNode) cx.Element {
	return cx.Element{
		name:  '?' + n.name
		attrs: n.attrs
		items: n.items
	}
}

// Array marker (distinct from sequence — arrays use
// `[a, b, c]` square-bracket surface, sequences use `(a, b, c)` paren
// surface). Renderers emit bracketed form.
const arr_marker_name = '__cx_arr__'

// Map marker — `{k: v}` surface. Child elements
// carry name=key and body=[value]; render-side `map_marker_to_node`
// rebuilds a `cx.MapNode` at the top-level emit boundary.
pub const map_marker_name = '__cx_map__'

// secret_marker_name wraps a `[?secret EXPR]` value (cxdm.md §12). The
// underlying value is the wrapper's single child; computation that needs
// the real value unwraps it, while output boundaries redact it to the
// `‹redacted›` marker (render.v::redact_secrets + render_element). v1
// IMPLEMENTS redaction at every emit boundary (canonical/cx/text, JSON,
// YAML, XML, CSV/TSV, `[err]` structured slots, cx-stdlib/log message +
// record) and gates `[?reveal]` declassification on the `secret-reveal`
// capability. Best-effort taint propagation (§12.3 derived-value
// secret-ness) and `::secret` type-annotation enforcement (grammar [26a])
// are follow-ups (see SPEC-FINDINGS §AO).
const secret_marker_name = '__cx_secret__'

// meta_marker_name wraps a `[?meta {…} FORM]` value (D5 /
// code.md §4.2). The wrapper is a reserved-name element carrying
// the inner value as `items[0]` and the annotation MapNode as `items[1]`.
// It is an INERT side-band: rendering is transparent (the inner value's
// surface), structural equality and EBV unwrap it, and arithmetic /
// comparison operators read through it — so `[?meta {…} V]` behaves
// exactly as `V`. Only `[meta-of EXPR]` observes the map. The map rides
// with the value through bindings / returns; TEXT serialization is
// transparent (I1 #708/L85: Lane 1 is excluded from identity — the codec
// lane unwraps at cx_mod_lower_value exactly as the display renderer
// does; XML remains the one lossless target via `<cx:meta>`, D5).
const meta_marker_name = '__cx_meta__'

// is_meta_wrapper reports whether `n` is a `[?meta]` metadata wrapper.
fn is_meta_wrapper(n cx.Node) bool {
	return n is cx.Element && (n as cx.Element).name == meta_marker_name
}

// meta_inner returns the value carried by a `[?meta]` wrapper (or `n`
// itself if it carries none).
fn meta_inner(n cx.Node) cx.Node {
	if n is cx.Element {
		if n.name == meta_marker_name && n.items.len >= 1 {
			return n.items[0]
		}
	}
	return n
}

// meta_unwrap strips a single `[?meta]` wrapper, yielding the inner value
// — the chokepoint used by operators / equality / EBV so the wrapper is
// transparent to computation.
fn meta_unwrap(n cx.Node) cx.Node {
	return meta_inner(n)
}

// empty_meta_map returns the empty annotation map in the program-layer
// `__cx_map__` marker representation (renders as `{}`).
fn empty_meta_map() cx.Node {
	return cx.Node(cx.Element{ name: map_marker_name })
}

// meta_map_node returns the annotation map carried by a `[?meta]` wrapper
// (a `__cx_map__` marker element), or the empty map when `n` carries none.
fn meta_map_node(n cx.Node) cx.Node {
	if n is cx.Element {
		if n.name == meta_marker_name && n.items.len >= 2 {
			return n.items[1]
		}
	}
	return empty_meta_map()
}

// is_map_marker reports whether `n` is a program-layer `{…}` map value.
fn is_map_marker(n cx.Node) bool {
	return n is cx.Element && (n as cx.Element).name == map_marker_name
}

// merge_meta_maps merges two `__cx_map__` annotation maps, last(outer)-wins
// per key — the rule for stacked `[?meta]` wrappers (D5 §3). Map entries
// are child elements whose `name` is the (stringified) key.
fn merge_meta_maps(inner cx.Element, outer cx.Element) cx.Node {
	mut items := inner.items.clone()
	for oc in outer.items {
		okey := if oc is cx.Element { (oc as cx.Element).name } else { '' }
		mut replaced := false
		for i, ic in items {
			ikey := if ic is cx.Element { (ic as cx.Element).name } else { '' }
			if ikey == okey {
				items[i] = oc
				replaced = true
				break
			}
		}
		if !replaced {
			items << oc
		}
	}
	return cx.Node(cx.Element{ name: map_marker_name, items: items })
}

// eval_meta evaluates `[?meta {MAP} FORM]` (D5). It attaches MAP to FORM's
// value as an inert side-band and returns the wrapped value unchanged.
// Stacking merges maps last(outer)-wins. The annotation must be a map.
fn eval_meta(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	slots := positional_slots(d)
	if slots.len != 2 {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: '[?meta] requires a metadata map and exactly one form: [?meta {…} FORM]'
		}
	}
	map_val := eval_node(slots[0], mut env)!
	if is_err_node(map_val) {
		return map_val
	}
	if !is_map_marker(map_val) {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: '[?meta] annotation must be a map literal {…}'
		}
	}
	form_val := eval_node(slots[1], mut env)!
	if is_err_node(form_val) {
		return form_val
	}
	if is_meta_wrapper(form_val) {
		// Stacked wraps merge into one flat map (outer wins).
		inner_map := meta_map_node(form_val)
		merged := if inner_map is cx.Element {
			merge_meta_maps(inner_map, map_val as cx.Element)
		} else {
			cx.Node(map_val)
		}
		return cx.Element{
			name:  meta_marker_name
			items: [meta_inner(form_val), merged]
		}
	}
	return cx.Element{
		name:  meta_marker_name
		items: [form_val, map_val]
	}
}

// eval_meta_of evaluates `[meta-of EXPR]` (D5) — the reflection builtin.
// It returns EXPR's attached metadata map, or an empty map when EXPR
// carries no metadata.
fn eval_meta_of(args []cx.Node) cx.Node {
	if args.len != 1 {
		return mk_err('cx-err:CXER0100', '[meta-of] expects exactly one argument')
	}
	return meta_map_node(args[0])
}

fn eval_sequence(items []cx.ProgramNode, mut env MatchEnv) !cx.Node {
	mut nodes := []cx.Node{}
	for it in items {
		nodes << eval_node(it, mut env)!
	}
	// NOTE: the program layer deliberately does NOT apply [L80] data-layer
	// sequence-flattening here. In a program a sequence is a FIRST-CLASS
	// structured value: nested sequences carry rank (multi-axis slices,
	// `[?to-map]` 2-tuples, geo polygon rings all rely on `((…),(…))` staying
	// nested). The cx DATA parser flattens literal `(1, (2, 3))` per
	// CXDM §1.2 (a document-shape convention); the program layer preserves it.
	// This is a legitimate data-vs-program difference (parser_parity SEQ-NEST),
	// not drift — unlike §9 [L25b] body classification, which both layers share.
	return cx.Element{
		name:  seq_marker_name
		items: nodes
	}
}

fn eval_array(items []cx.ProgramNode, mut env MatchEnv) !cx.Node {
	mut nodes := []cx.Node{}
	for it in items {
		nodes << eval_node(it, mut env)!
	}
	return cx.Element{
		name:  arr_marker_name
		items: nodes
	}
}

// eval_map builds the `__cx_map__` envelope: each entry is a child element
// whose NAME is the key's image and whose body is the value.
//
// #777 (RULED: 777-1a): the entry also carries the key's CXDM KIND, in the
// entry element's `meta.data_type`. The entry element is SYNTHETIC — it is
// never emitted as an element, only as `k: v` — so that slot has no other
// reading, and stamping it is what lets the renderer emit a spelling that
// re-parses to the SAME key. Only a key whose kind does not follow from its
// image is stamped (`key_kinds[i]` empty ⇒ self-identifying), so every
// stdlib-constructed option map is byte-identical to before.
fn eval_map(keys []string, key_kinds []string, decl_kinds []string, vals []cx.ProgramNode, mut env MatchEnv) !cx.Node {
	mut entries := []cx.Node{}
	// #920 (W014 parity): literal-key duplicates refuse at PARSE now, but a
	// COMPUTED `[?entry]` key resolves here — check it against every key
	// already in the map (identity = (kind, image), NFC strings) so
	// `{a: 1 [?entry $k 2]}` with $k = "a" refuses instead of silently
	// minting a duplicate.
	mut seen := map[string]bool{}
	for i, k in keys {
		kind := if i < key_kinds.len { key_kinds[i] } else { '' }
		// RULED: MSS-4 (#917): a declaration-only entry `{k: ::T}` carries
		// its kind on the envelope entry's meta and NO evaluated value —
		// the null item is an inert guard for unaudited item reads, never
		// the entry's value (value reads are ABSENT).
		decl := if i < decl_kinds.len { decl_kinds[i] } else { '' }
		if decl != '' {
			dkind_eff := if kind != '' { kind } else { cx.cx_autotype_kind_name(k) }
			dmarker := if dkind_eff == 'string' {
				'string:' + cx.cx_nfc_name(k)
			} else {
				'${dkind_eff}:${k}'
			}
			if dmarker in seen {
				return EvalError{
					code:    'cx-err:CXER0100'
					message: 'W014: duplicate map key `${k}` (cx-err:CXERMAP-DUPKEY)'
				}
			}
			seen[dmarker] = true
			mut dmeta := &cx.ElementMeta{
				decl_kind: ?string(decl)
			}
			if kind != '' {
				dmeta.key_kind = ?string(kind)
			}
			entries << cx.Element{
				name:  k
				meta:  dmeta
				items: [
					cx.Node(cx.ScalarNode{
						data_type: .null_type
						value:     cx.ScalarValue(cx.NullValue{})
					}),
				]
			}
			continue
		}
		// Computed-key entry `[?entry KEY-EXPR VAL]` (spec/code.md §6.4.2):
		// resolve the key via name coercion. Empty key → entry omitted
		// (absence); non-scalar key → CXER0235; err → railway-propagate.
		if k == cx.computed_entry_key_marker {
			ent := vals[i]
			if ent is cx.ProgramDirective {
				key_v := eval_node(ent.slots[0].value, mut env)!
				if is_err_node(key_v) {
					return key_v
				}
				resolved_key, key_err, has_err := coerce_entry_key(key_v)
				if has_err {
					return key_err
				}
				if is_empty_seq_node(key_v) {
					continue // absence: entry omitted
				}
				cmarker := 'string:' + cx.cx_nfc_name(resolved_key)
				if cmarker in seen {
					return EvalError{
						code:    'cx-err:CXER0100'
						message: 'W014: duplicate map key `${resolved_key}` from [?entry] (cx-err:CXERMAP-DUPKEY)'
					}
				}
				seen[cmarker] = true
				val_v := eval_node(ent.slots[1].value, mut env)!
				if is_err_node(val_v) {
					return val_v
				}
				entries << cx.Element{
					name:  resolved_key
					items: [val_v]
				}
			}
			continue
		}
		kind_eff := if kind != '' { kind } else { cx.cx_autotype_kind_name(k) }
		lmarker := if kind_eff == 'string' {
			'string:' + cx.cx_nfc_name(k)
		} else {
			'${kind_eff}:${k}'
		}
		if lmarker in seen {
			return EvalError{
				code:    'cx-err:CXER0100'
				message: 'W014: duplicate map key `${k}` (cx-err:CXERMAP-DUPKEY)'
			}
		}
		seen[lmarker] = true
		v := eval_node(vals[i], mut env)!
		if kind != '' {
			entries << cx.Element{
				name:  k
				meta:  &cx.ElementMeta{
					key_kind: ?string(kind)
				}
				items: [v]
			}
		} else {
			entries << cx.Element{
				name:  k
				items: [v]
			}
		}
	}
	return cx.Element{
		name:  '__cx_map__'
		items: entries
	}
}

// step_key_norm canonicalizes a key image within its kind so two spellings
// of one value share one identity for computed-step member lookup (#925):
// hex ints, decimal scale, NFC strings — the same normalization the map
// literal reader applies at parse.
fn step_key_norm(kind string, image string) string {
	if kind == 'string' {
		return cx.cx_nfc_name(image)
	}
	sn := cx.coerce_scalar_strict(kind, image) or { return image }
	return cx.scalar_value_str_public(sn.value)
}

// map_entry_key_kind reads the KEY kind an envelope entry CARRIES (#777).
// Absent on every entry whose kind follows from its image and on every
// directly-constructed stdlib entry — the renderer then falls back to the
// historical image heuristic.
pub fn map_entry_key_kind(e cx.Element) ?string {
	if e.meta == unsafe { nil } {
		return none
	}
	dt := e.meta.key_kind or { return none }
	if dt == '' {
		return none
	}
	return dt
}

// map_entry_decl_kind reads the DECLARATION kind an envelope entry carries
// (RULED: MSS-4 #917) — `{k: ::T}`, value ABSENT. None on ordinary entries.
pub fn map_entry_decl_kind(e cx.Element) ?string {
	if e.meta == unsafe { nil } {
		return none
	}
	dk := e.meta.decl_kind or { return none }
	if dk == '' {
		return none
	}
	return dk
}

// map_entry_effective_key_kind answers the kind a key HAS, stamped or not —
// the normalizer key IDENTITY compares on (#777, RULED: 777-1a). An
// unstamped entry still has a kind: a stdlib option map's `name` is a STRING
// key and a bare `7` is an INT key, so the kind is read off what the image
// auto-types to. Comparing the raw stamp instead would split every
// directly-constructed stdlib map away from the ident-keyed patterns that
// match it.
pub fn map_entry_effective_key_kind(e cx.Element) string {
	if k := map_entry_key_kind(e) {
		return k
	}
	return cx.cx_autotype_kind_name(e.name)
}

// Slot child names use this prefix so renderers (vcx/code/eval.v
// render_value, and downstream emitters) can distinguish elements
// that came from labeled-slot syntax (`[name :label value]`) from
// elements that came from positional body items (`[name [child]]`).
// The prefix is reserved: user element names MUST NOT start with
// `__cx_slot:` per the lex rules (identifier chars don't
// include `:`, so this is impossible by construction).
const slot_child_prefix = '__cx_slot:'

// eval_computed_name_element evaluates the dynamic element-name form
// `[(:atom EXPR) ...]` / `[?element NAME-EXPR …]` (spec/code.md §6.4.2).
// Resolve `name_expr` to a string / atom name via the shared coercion rule
// (§6.4.2.1): empty/() routes to absence (element → ()); non-scalar →
// CXER0235; non-NCName scalar → CXER0236. Call-dispatch is disabled for
// dynamic-name elements (the surface is for construction; dispatch would
// conflate with [(:atom name) (args)] which has no source-syntax shape).
// Split out of eval_cx_element so the hot call-dispatch path does not carry
// this branch's construction locals on its frame (#326 frame diet).
fn eval_computed_name_element(l cx.ProgramLiteral, expr cx.ProgramNode, mut env MatchEnv) !cx.Node {
	name_val := eval_node(expr, mut env)!
	if is_err_node(name_val) {
		return name_val
	}
	coerced := coerce_computed_name(name_val, 'element')
	if coerced is cx.Element {
		// empty/() → absence: the element is omitted.
		if is_empty_seq_node(coerced) {
			return empty_seq_node()
		}
	}
	if is_err_node(coerced) {
		return coerced
	}
	effective_name := (coerced as cx.ScalarNode).value as string
	// Materialise the body via the shared DC body evaluator so nested
	// [?attr] / [?splice] / [?unquote] holes route correctly. No call
	// dispatch for computed-name elements (the user is constructing).
	mut items := []cx.Node{}
	mut cx_attrs := []cx.Attribute{}
	sc_a := eval_construction_attrs(l.attrs, mut cx_attrs, mut env)!
	if !is_dc_ok_sentinel(sc_a) {
		return sc_a
	}
	sc := eval_dc_body_items(l.items, mut items, mut cx_attrs, mut env)!
	if !is_dc_ok_sentinel(sc) {
		return sc
	}
	return cx.Element{
		name:  effective_name
		attrs: cx_attrs
		items: items
	}
}

fn eval_cx_element(l cx.ProgramLiteral, mut env MatchEnv) !cx.Node {
	// dynamic element-name form `[(:atom EXPR) ...]` — see
	// eval_computed_name_element.
	if expr := l.name_expr {
		return eval_computed_name_element(l, expr, mut env)
	}
	// Glued head TypeAnnotation `::T` / `::T[]` / `::[]` (lexicon §9 [L25d]):
	// the annotation OVERRIDES §9 auto-typing and forces pure-data
	// construction — no call dispatch, no operator-element evaluation.
	if l.data_type != '' {
		return eval_annotated_element(l, mut env)
	}
	// Call-shape elements: `[name (arg, arg, …)]` where `name` resolves
	// to a registered closure dispatches as a call. This is the surface
	// used by spec/code.md §6.3 worked examples like `[depth($n)]`
	// at top-level. Plain element construction continues to work for
	// non-callable names (since dispatch returns none, we fall through).
	//
	// Note: only the explicit `(args)` form dispatches — `[first "a"]`
	// without parens stays as element construction (the data element
	// named `first` with body "a"). To call a builtin in prefix form
	// use one of:
	//
	//   [name (arg1, arg2)]    — explicit call shape (this branch)
	//   name(arg1, arg2)       — top-level function-call surface
	//   expr | name(arg)       — pipe sugar
	//
	// Comparison operators use the operator-element form `[= a b]` /
	// `[> a b]` / etc. (per eval_operator_element below) — the prefix
	// builtin call form is reserved for unambiguous identifier calls.
	// (supersedes) — the element-form named call
	// `[fn :a 1 :b 2]` is REMOVED. Named calls are paren-only: `fn(:a 1, :b 2)`.
	// On a plain element, `:label` is no longer a call-arg slot, so a head
	// that names a closure does NOT dispatch from element-construction form.
	if l.name != '' && l.slots.len == 0 && l.items.len == 1 {
		first := l.items[0]
		if first is cx.ProgramLiteral && first.kind == .sequence_lit {
			// Only dispatch when the name is a registered callable
			// (closure or builtin). Avoid hijacking ordinary element
			// construction like `[row ($x, $y)]`.
			if l.name in env.closures {
				mut args := []cx.Node{}
				for it in first.items {
					args << eval_call_arg(it, mut env)!
				}
				// Confirmed closure + call shape: resolve to its result or
				// PROPAGATE its error (#46) — never fall through to data
				// construction, which silently masked the runtime error.
				return dispatch_call(l.name, args, mut env) or { return err }
			}
		}
		// Bare-binding form `[head $xs]` — when the sole body item is
		// a $binding, treat the element as a one-arg call on `name`.
		// Same dispatch gate as the `(args)` shape above; lets
		// pipeline-less builtin calls work alongside `$xs | head`.
		//
		// Trade-off: this dispatch hijacks `[NAME $binding]` element
		// construction patterns where NAME collides with a known
		// builtin / closure. Conformance fixtures that previously
		// wrote `[first $err]` / `[second $err]` etc. as data tags
		// have been renamed to non-builtin-colliding labels (`r1`,
		// `r2`, `arm-first`, etc.) — see program-cb-004 and
		// program-conc-004. The builtin-call meaning wins because the
		// user explicitly requested `[head $xs]` work as a call in
		// this position (2026-05-25).
		if first is cx.ProgramBinding {
			if l.name in env.closures {
				args := [eval_node(first, mut env)!]
				// Confirmed closure: resolve or propagate its error (#46).
				return dispatch_call(l.name, args, mut env) or { return err }
			}
		}
		// single-scalar-literal directive form
		// `[floor 4.7]` / `[abs -3]`. Without this arm the body is a
		// single cx.ProgramLiteral (int_lit / float_lit / string_lit) and
		// falls through to literal-element construction, silently
		// failing to dispatch the builtin (the original 
		// motivation per §D3). Gated on `builtin_is_numeric_scalar`
		// to keep sequence- / element-shaped builtins (`[first "a"]`,
		// `[head "x"]`) as literal-element construction per the
		// regression-2026-05-22 fixture; user closures still dispatch
		// uniformly.
		if first is cx.ProgramLiteral {
			if builtin_is_scalar_literal_arg(first.kind) {
				dispatch_ok := (l.name in env.closures)
				if dispatch_ok {
					args := [eval_node(first, mut env)!]
					// Confirmed closure: resolve or propagate its error (#46).
					return dispatch_call(l.name, args, mut env) or { return err }
				}
			}
		}
	}
	// Multi-arg whitespace-form builtin call: `[name arg1 arg2 arg3]`
	// where `name` is in builtin_dispatchable AND every body item is an
	// expression-position value (scalar literal, binding, paren-sequence,
	// etc. — NOT a nested cx_element).
	//
	// Dispatch shape depends on the builtin's arity convention:
	// - Sequence-shaped builtins (min/max/sum/count/avg/distinct/…) take a
	//   single sequence argument; body items are packed into one seq.
	// Fixed-arity builtins (mod/div/idiv, plus the
	//   numeric scalars when called with 2+ args) take separate args;
	//   body items are passed positionally.
	//
	// Conservative gating: no :label slots, no attr=val pairs, no nested
	// `[...]` element items. If any gate fails, fall through to the
	// existing element-construction semantics so data shapes like
	// `[user id=1 name="Alice"]` and `[sum [a 1] [b 2]]` round-trip
	// unchanged. See program-builtin-multiarg-004/005 fixtures.
	// Multi-arg whitespace-form CLOSURE call: a bare head `[name a b c]`
	// where `name` is a registered closure. Args pass positionally; a
	// variadic (`:rest`) closure collects the trailing ones
	// (invoke_closure). Gated identically to the builtin arm below (no
	// slots / attrs / nested elements) so data shapes still round-trip.
	// NOTE: module members are NOT reachable here — they are QNames called
	// as `[$prefix:local …]` (a `$`-headed cx.ProgramCall, §12.1.1), never a
	// bare slash head; the retired `prefix/local` slash surface was cut
	// over 2026-05-31 (no dual-accept).
	// A bareword `[name args…]` whose head is a registered closure dispatches as
	// a CALL (args pass positionally; a variadic `:rest` closure collects the
	// trailing ones). `l.items.len >= 0` has no lower bound: a ZERO-item `[f]`
	// dispatches as a zero-arg call (#55) — `[?def f () "hi"]` then `[f]` runs
	// `f`, it does not construct the data element `[f]`. Calls win over element
	// construction precisely when the head names a def; a bareword that is NOT a
	// def (`[primary]`) falls through and self-evaluates as a data word (the
	// homoiconic rule). Gated on no slots / attrs / non-operator nested elements.
	if l.name != '' && l.slots.len == 0 && l.attrs.len == 0
	   && l.items.len >= 0 && l.name in env.closures
	   && all_items_are_expr_position(l.items, env.closures) {
		mut arg_items := []cx.Node{}
		for it in l.items {
			arg_items << eval_node(it, mut env)!
		}
		// Confirmed closure (multi-arg whitespace form): resolve or propagate
		// its error (#46) — never fall through to data construction.
		return dispatch_call(l.name, arg_items, mut env) or { return err }
	}
	// NOTE: a bare ident-headed element `[name a b]` is DATA construction,
	// never a built-in call — per code.md §6.5 (named built-ins are reached
	// ONLY via `[$name …]`; symbolic/reserved operator heads are handled by
	// eval_operator_element above). So `[mod 7 3]` / `[min 5 3 8]` construct
	// data elements; the built-in forms are `[$mod 7 3]` / `[$min …]`. The
	// former bare-ident→built-in dispatch arm was removed (it contradicted
	// §6.5 and shadowed data elements like `[div interruption]`).
	// cast builtin — element-positional form `[cast value :tag]`
	// dispatches when name is exactly `cast` and the body is value +
	// atom-literal tag. This is the user-facing form per the locked
	// design 2026-05-23 (alternative to a to-int / to-float family).
	// The paren-call form `cast(value, :tag)` continues to work via the
	// generic dispatch above.
	if l.name == 'cast' && l.slots.len == 0 && l.attrs.len == 0
	   && l.items.len == 2 {
		// Second item must be an atom literal (the type-tag) so we
		// don't hijack a hypothetical `[cast x y]` data element.
		second := l.items[1]
		is_tag := if second is cx.ProgramLiteral { second.kind == .atom_lit } else { false }
		if is_tag {
			val := eval_node(l.items[0], mut env)!
			tag := eval_node(l.items[1], mut env)!
			return cast_value(val, tag)
		}
	}
	// `[meta-of EXPR]` — D5 reflection builtin (bareword head). Returns
	// EXPR's attached `[?meta]` map, or an empty map. A user binding /
	// closure of the same name wins (homoiconic shadow).
	if l.name == 'meta-of' && l.slots.len == 0 && l.attrs.len == 0
	   && l.items.len == 1 && l.name !in env.bindings && l.name !in env.closures {
		arg := eval_node(l.items[0], mut env)!
		if is_err_node(arg) {
			return arg
		}
		return eval_meta_of([arg])
	}
	// Operator-headed elements `[+ a b]`, `[* x 2]`, `[> n 0]`, etc.
	// evaluate as arithmetic / comparison expressions per the
	// spec/code.md §8 worked examples. Operator heads carry no [?attr] /
	// [?splice] body holes (their items are operands), so evaluate them
	// straight. Kept INLINE (not split out like the construction tail): an
	// extra C call here cost a consistent ~1.4% on the 1M-iteration tail
	// loop (two operator evals per hop), while the branch's own locals are
	// small — the #326 frame diet moves only the construction tail out.
	if l.slots.len == 0 && l.attrs.len == 0 && l.name in operator_element_heads {
		// Pre-size to the operand count: an operator head's items are all
		// operands, so the final length is known. Avoids the grow-from-zero
		// realloc chain (cap 0→1→2…) on every operator eval — the dominant
		// per-step heap churn in a tight arithmetic fold (lever 2, -gc e).
		mut op_items := []cx.Node{cap: l.items.len}
		for it in l.items {
			op_items << eval_node(it, mut env)!
		}
		if result := eval_operator_element(l.name, op_items) {
			return result
		}
	}
	// Plain data construction lives in its own frame (#326 frame diet) so
	// the call-dispatch arms above — the per-level hot recursion path —
	// never carry the construction locals.
	return eval_element_construct(l, mut env)
}

// eval_element_construct is eval_cx_element's plain data-construction tail:
// attributes, DC body items, the post-body operator fall-through, labeled
// slots, and the §9 body-value classification. Split out of eval_cx_element
// (#326 frame diet).
fn eval_element_construct(l cx.ProgramLiteral, mut env MatchEnv) !cx.Node {
	mut items := []cx.Node{}
	mut cx_attrs := []cx.Attribute{}
	// Element-construction attributes `name=value` / `name::T=value`. The
	// attr value must reduce to a scalar (cx.Attribute.value); a
	// non-scalar result raises cx-err:CXER0100 per spec/code.md §6.4.1.
	sc_a := eval_construction_attrs(l.attrs, mut cx_attrs, mut env)!
	if !is_dc_ok_sentinel(sc_a) {
		return sc_a
	}
	sc := eval_dc_body_items(l.items, mut items, mut cx_attrs, mut env)!
	if !is_dc_ok_sentinel(sc) {
		return sc
	}
	// Fall-through operator dispatch for the rare operator head reached with
	// no attrs after body evaluation (e.g. via a slot-bearing shape guard).
	if l.slots.len == 0 && cx_attrs.len == 0 {
		if result := eval_operator_element(l.name, items) {
			return result
		}
	}
	for slot in l.slots {
		val := eval_node(slot.value, mut env)!
		items << cx.Element{
			name:  '${slot_child_prefix}${slot.label}'
			items: [val]
		}
	}
	// §9 body-value classification (lexicon §9 [L25a-b], the "cx flavor"
	// rule). Applies ONLY to a slot-free, child-element-free body of 2+
	// scalar leaves with no head annotation: a homogeneous non-string run
	// auto-arrays (int+float promote to float); any string / mixed run is
	// PROSE — one Text run. Single-item and child-bearing bodies are left
	// untouched. Reached only after every call / operator dispatch declined.
	if l.slots.len == 0 {
		body, body_dt := classify_body_value(items)
		if dt := body_dt {
			return cx.new_element(l.name, cx.ElementMeta{ data_type: dt }, cx_attrs,
				body)
		}
		return cx.Element{
			name:  l.name
			attrs: cx_attrs
			items: body
		}
	}
	return cx.Element{
		name:  l.name
		attrs: cx_attrs
		items: items
	}
}

// classify_body_value applies the §9 [L25a-b] body-value rule to an
// evaluated, slot-free element body. Returns the (possibly rewritten) body
// items plus an optional element data_type (`T[]`) when the body auto-arrays.
//   • <2 items, or any non-leaf (child Element) item → unchanged, no type.
//   • all non-string non-atom scalars, homogeneous (or int+float) → typed
//     ARRAY: items kept (ints promoted on a numeric mix), data_type `T[]`.
//   • otherwise → PROSE: one Text run joining the items' source text.
//
// SELF-DELIMITING LIST (§9 [L25b], second clause): a body containing a QUOTED
// string or an ATOM is a heterogeneous list — left as separate typed items, NOT
// prose-joined. Quotes and atoms are self-delimiting, so the body reads as a
// list without commas (commas stay required to list BARE tokens). This is the
// ratified rule; cx.parse converges to it (parser_parity CONTENT). The PROSE
// join below therefore applies ONLY to a fully reconstructable bare run —
// barewords (TextNode) and non-string non-atom scalars (int/float/bool/date/
// datetime), whose source text equals their value text.
fn classify_body_value(items []cx.Node) ([]cx.Node, ?string) {
	if items.len < 2 {
		return items, none
	}
	mut types := []cx.ScalarType{} // ScalarNode data_types (parallel to scalar items)
	mut has_textnode := false      // a bareword item
	mut has_string_scalar := false // a quoted-string item
	mut has_atom := false          // an atom item
	for it in items {
		if it is cx.ScalarNode {
			t := it.data_type
			types << t
			if t == cx.ScalarType.string_type {
				has_string_scalar = true
			} else if t == cx.ScalarType.atom_type {
				has_atom = true
			}
		} else if it is cx.TextNode {
			has_textnode = true
		} else {
			return items, none // child element / other → mixed content, leave as-is
		}
	}
	// TYPED LIST (§9 [L25a/b], @CHOICE-1 "one layer"): a whitespace run whose every
	// item is a non-bareword scalar (number / atom / quoted) is a list of DISCRETE
	// typed items — NOT an auto-array. No `T[]` element type and NO int→float
	// promotion: heterogeneous per-item types are preserved (M-SCALAR-ITEM,
	// G-BODY-2/3). This converges with the data parser's body_is_typed_list (slice
	// A) — the old whitespace auto-array + promotion is retired on both engines.
	if !has_textnode && !has_string_scalar && !has_atom && types.len == items.len {
		return items, none
	}
	// PROSE — only when faithfully reconstructable (no quoted strings / atoms).
	if has_string_scalar || has_atom {
		return items, none
	}
	mut toks := []string{cap: items.len}
	for it in items {
		toks << node_source_text(it)
	}
	return [cx.Node(cx.TextNode{ value: toks.join(' ') })], none
}

// eval_annotated_element constructs a `[head::T …]` / `[head::T[] …]` /
// `[head::[] …]` element (lexicon §9 [L25d]). The annotation OVERRIDES §9
// auto-typing: an ARRAY type coerces every body item to a scalar of the
// element type (inferred for `::[]`); a SCALAR type coerces the body to a
// single scalar of T. The resulting cx.Element carries the data_type so the
// renderer's decision-(a) array logic re-derives the canonical surface.
fn eval_annotated_element(l cx.ProgramLiteral, mut env MatchEnv) !cx.Node {
	mut cx_attrs := []cx.Attribute{}
	sc_a := eval_construction_attrs(l.attrs, mut cx_attrs, mut env)!
	if !is_dc_ok_sentinel(sc_a) {
		return sc_a
	}
	mut raw := []cx.Node{}
	// srcs — per-item ORIGINAL source token, parallel to raw ('' when the
	// item is not a number-shaped literal). The ascription coerces from THIS
	// text when available: §9 auto-typing already ran inside eval_node (a
	// `0x…` body token arrives as an int ScalarNode), but lexicon §7 [L50]
	// says the annotation OVERRIDES auto-typing — so `[hash::bytes
	// 0x3a7bd3e2]` must coerce the token `0x3a7bd3e2`, not the decimal
	// re-rendering of its int auto-type (#457). Mirrors the data reading,
	// where coerce_scalar_checked always receives the raw token.
	mut srcs := []string{cap: l.items.len}
	for it in l.items {
		v := eval_node(it, mut env)!
		if is_err_node(v) {
			return v
		}
		raw << v
		srcs << literal_source_text(it)
	}
	ann := l.data_type
	if ann.ends_with('[]') {
		base := ann#[..-2]
		if base == '' {
			// `::[]` inferred array (@CHOICE-1 slice C): KEEP the `[]` marker; each
			// item keeps its own auto-type (heterogeneous, no concrete inference,
			// no int→float promotion; M-TYPED-ARRAY-2). The evaluated `raw` items
			// are already auto-typed, so they pass through unchanged. Converges
			// with the data parser's `::[]` handling.
			return cx.new_element(l.name, cx.ElementMeta{ data_type: '[]' }, cx_attrs,
				raw)
		}
		// Explicit `::T[]`: coerce every body item to a scalar of T.
		mut body := []cx.Node{}
		for i, v in raw {
			body << cx.Node(coerce_typed_scalar_text(coercion_source_text(v, srcs[i]),
				base)!)
		}
		return cx.new_element(l.name, cx.ElementMeta{ data_type: '${base}[]' },
			cx_attrs, body)
	}
	// Scalar type T → the body coerces to ONE scalar of T.
	mut body := []cx.Node{}
	if raw.len == 1 {
		body << cx.Node(coerce_typed_scalar_text(coercion_source_text(raw[0], srcs[0]),
			ann)!)
	} else if raw.len > 1 {
		// Multi-token body under a SCALAR annotation (§9 [L25d]: the whole
		// body text coerces to one scalar of T; whitespace becomes literal).
		mut toks := []string{cap: raw.len}
		for i, v in raw {
			toks << coercion_source_text(v, srcs[i])
		}
		joined := toks.join(' ')
		body << cx.Node(coerce_typed_scalar_text(joined, ann)!)
	}
	return cx.new_element(l.name, cx.ElementMeta{ data_type: ann }, cx_attrs, body)
}

// literal_source_text returns the preserved source token of a number-shaped
// scalar literal ('' for every other program node) — see ProgramLiteral.src.
fn literal_source_text(n cx.ProgramNode) string {
	if n is cx.ProgramLiteral {
		return n.src
	}
	return ''
}

// coercion_source_text picks the text an ascription coerces: the literal's
// preserved source token when the body item was a number-shaped literal
// (spelling intact — `0x3a7bd3e2`, `1_000`, `1.50`), else the evaluated
// node's textual form (computed values have no source spelling to preserve).
fn coercion_source_text(n cx.Node, src string) string {
	if src != '' {
		return src
	}
	return node_source_text(n)
}

// coerce_typed_scalar_text converts an ascribed body text into a ScalarNode
// of the named CXDM type. `txt` is the ORIGINAL source token when the body
// item was a literal (coercion_source_text), else the evaluated node's
// textual form. Sized numerics map to int/float at the data model; their
// declared width rides on the element data_type for rendering / host
// marshalling.
// node_source_text returns a node's textual form for type coercion: a
// TextNode's value verbatim, or a ScalarNode's canonical value string
// (handles non-string scalars, unlike scalar_string which only yields
// string-typed values).
fn node_source_text(n cx.Node) string {
	if n is cx.TextNode {
		return n.value
	}
	if n is cx.ScalarNode {
		return cx.scalar_value_str_public(n.value)
	}
	return ''
}

fn coerce_typed_scalar_text(txt string, t string) !cx.ScalarNode {
	return match t {
		'int', 'i8', 'i16', 'i32', 'i64', 'u8', 'u16', 'u32', 'u64' {
			// D-H: an explicit integer annotation HARD-ERRORS on a value that
			// overflows i64 or falls outside a sized type's range — it never
			// silently clamps via `txt.i64()`. Mirrors the data reading's
			// coerce_scalar_checked (CXER0290 / CXERLEX-RANGE).
			v := cx.try_coerce_int_token(txt, t) or {
				return EvalError{
					code:    'cx-err:CXER0290'
					message: 'cannot coerce `${txt}` to ${t} (cx-err:CXER0290)'
				}
			}
			cx.ScalarNode{ value: cx.ScalarValue(v), data_type: .int_type }
		}
		'float', 'f16', 'f32', 'f64' {
			// M-ERR-2: a token that cannot coerce to the ascribed float type
			// fails loud — never a silent 0.0 (or a hex token's int reading).
			// Same guards as the data reading (cx.try_coerce_float_token is
			// the single home shared with coerce_scalar_checked).
			fv := cx.try_coerce_float_token(txt) or {
				return EvalError{
					code:    'cx-err:CXER0290'
					message: 'cannot coerce `${txt}` to ${t} (cx-err:CXER0290)'
				}
			}
			cx.ScalarNode{ value: cx.ScalarValue(fv), data_type: .float_type }
		}
		'bytes' {
			// An explicit `::bytes` ascription types the token as bytes
			// REGARDLESS of its lexical shape or magnitude — a short `0x…`
			// hex literal must never int-coerce (#457). The token text is
			// the bytes carrier, verbatim, exactly as the data reading's
			// coerce_scalar bytes arm stores it.
			cx.ScalarNode{ value: cx.ScalarValue(txt), data_type: .bytes_type }
		}
		'bool' {
			cx.ScalarNode{ value: cx.ScalarValue(txt == 'true'), data_type: .bool_type }
		}
		'null' {
			cx.ScalarNode{ value: cx.ScalarValue(cx.NullValue{}), data_type: .null_type }
		}
		'date' {
			cx.ScalarNode{ value: cx.ScalarValue(txt), data_type: .date_type }
		}
		'datetime' {
			cx.ScalarNode{ value: cx.ScalarValue(txt), data_type: .datetime_type }
		}
		'atom' {
			// M-ERR-2 composition with [L40] (#466 item 2): an explicit
			// `::atom` demands a denotable atom name; `0x2a` / the
			// reserved true/false/null fail loud instead of minting an
			// atom whose render `:0x2a` would not re-parse. Single home
			// with the data reading's coerce_scalar_checked atom arm.
			name := cx.try_coerce_atom_token(txt) or {
				return EvalError{
					code:    'cx-err:CXER0290'
					message: 'cannot coerce `${txt}` to atom — not a valid atom name (lexicon [L40]) (cx-err:CXER0290)'
				}
			}
			cx.ScalarNode{ value: cx.ScalarValue(name), data_type: .atom_type }
		}
		'decimal', 'bigint' {
			// #466 item 4: delegate to the data reading's coercion so both
			// engines produce the same ScalarNode (underscores stripped,
			// type-tagged). OWNER RULING (#466 item 3): a hex token under
			// `::decimal`/`::bigint` REJECTS loudly — decimal/bigint are
			// base-10 value types (single home:
			// cx.try_coerce_base10_verbatim_token, shared with the data
			// reading's coerce_scalar_checked).
			sn := cx.try_coerce_base10_verbatim_token(t, txt) or {
				return EvalError{
					code:    'cx-err:CXER0290'
					message: 'cannot coerce hex literal `${txt}` to ${t} — ${t} is a base-10 value type (cx-err:CXER0290)'
				}
			}
			sn
		}
		'duration', 'period' {
			// #466 item 4: these carried string-typed scalars in eval while
			// the DATA reading typed them (verbatim) — delegate to the data
			// reading's coercion so both engines produce the same
			// ScalarNode.
			cx.coerce_scalar_public(t, txt)
		}
		else {
			cx.ScalarNode{ value: cx.ScalarValue(txt), data_type: .string_type }
		}
	}
}

// (infer_scalar_base / scalar_base_name were REMOVED with @CHOICE-1
// §9-one-layer slice C: `::[]` no longer infers a single concrete element type —
// each item keeps its own auto-type, heterogeneous, no promotion.)

// attr_scalar_node materializes an attribute's value as a typed
// ScalarNode per cxdm.md §2.4: the `@name` axis produces "the
// attribute's typed value". The ScalarValue passes through unchanged;
// the ScalarType is recovered from the attribute's ascribed type name
// when present (the D3 string carrier — `atom`, `date`, `datetime`,
// `decimal`, sized ints, …), falling back to the type implied by the
// ScalarValue variant. Without the ascription lookup, string-carried
// kinds collapsed to plain strings on read — so on `[x kind=:active]`
// the read `[= $e@kind :active]` was false and `[= $e@kind "active"]`
// true, violating cxdm.md §5.1 (no atom↔string coercion) while int /
// bool attributes (whose ScalarValue variant carries the type) already
// read back typed.
fn attr_scalar_node(a cx.Attribute) cx.ScalarNode {
	mut dt := match a.value {
		bool         { cx.ScalarType.bool_type }
		i64          { cx.ScalarType.int_type }
		f64          { cx.ScalarType.float_type }
		cx.NullValue { cx.ScalarType.null_type }
		string       { cx.ScalarType.string_type }
	}
	if tname := a.data_type() {
		if t := cx.scalar_type_from_name(tname) {
			dt = t
		}
	}
	return cx.ScalarNode{ value: a.value, data_type: dt }
}

// node_to_attr_value coerces an evaluated attr-value Node into the
// (ScalarValue, ScalarType?) pair required by cx.Attribute. Scalars
// pass through with their declared type; non-scalar values
// stringify via the canonical printer. Used by the [?modify] attribute
// actions (§8.10), whose [using] kind-shift rule admits any return kind.
// Element CONSTRUCTION goes through construction_attr_value below, which
// rejects the silently-lossy shapes (PathExpr values, empty sequences).
fn node_to_attr_value(n cx.Node) (cx.ScalarValue, ?string) {
	match n {
		cx.ScalarNode {
			// `string` carries no annotation on the attribute carrier (D3);
			// every other kind keeps its canonical type name.
			if n.data_type == .string_type {
				return n.value, ?string(none)
			}
			return n.value, ?string(cx.scalar_type_name_public(n.data_type))
		}
		cx.TextNode {
			return cx.ScalarValue(n.value), ?string(none)
		}
		else {
			return cx.ScalarValue(render_canonical(n)), ?string(none)
		}
	}
}

// eval_construction_attrs materializes every element-construction
// attribute of a cx_element ProgramLiteral into `cx_attrs` — the single
// home shared by the plain, head-annotated, and computed-name element
// paths. Untyped `name=value` attrs route through
// construction_attr_value; typed `name::T=value` attrs (D3; lexicon §7
// [L50]; #466) route through ascribed_attr_value, which coercion-checks
// the value against T. Returns the dc-ok sentinel on success, or the err
// NODE produced by an attr value expression (propagated as a value,
// mirroring eval_dc_body_items' contract).
fn eval_construction_attrs(attrs []cx.ProgramAttr, mut cx_attrs []cx.Attribute, mut env MatchEnv) !cx.Node {
	for a in attrs {
		val := eval_node(a.value, mut env)!
		if is_err_node(val) {
			return val
		}
		mut sv := cx.ScalarValue('')
		mut dt := ?string(none)
		if a.data_type != '' {
			sv, dt = ascribed_attr_value(a, val)!
		} else {
			sv, dt = construction_attr_value(a.name, a.value, val)!
		}
		cx_attrs << cx.new_attribute(a.name, sv, cx.AttributeMeta{ data_type: dt })
	}
	// I1 stream 15 (#704): reserved-namespace bindings reject in the
	// program reading exactly as in the data reading — the two engines
	// must agree on every document (E213; cx_check_reserved_ns_attrs is
	// the one shared rule). Dynamically-built elements that bypass the
	// literal lane are caught at the text/identity boundary, where
	// cx.parse re-runs the Document-level validation.
	cx.cx_check_reserved_ns_attrs(cx_attrs) or {
		return EvalError{
			code:    'cx-err:E213'
			message: err.msg()
		}
	}
	return dc_ok_sentinel()
}

// ascribed_attr_value materializes one TYPED element-construction
// attribute `name::T=value` (#466): the value coerces to T from its
// ORIGINAL source spelling (ascription_source_text), exactly like the
// DATA reading's typed-attribute arm coerces the raw token — so
// `[e h::bytes=0x3a7bd3e2]` keeps its hex spelling instead of
// int-coercing first (lexicon §7 [L50]: the annotation OVERRIDES §9
// auto-typing; #457). `T` rides on the attribute's data-type carrier.
// Non-scalar values keep the untyped path's specific CXER0100
// rejections (PathExpr / empty sequence), then fail the coercion loud —
// an ascription demands a scalar-coercible value (CXER0290).
fn ascribed_attr_value(a cx.ProgramAttr, val cx.Node) !(cx.ScalarValue, ?string) {
	if !(val is cx.ScalarNode || val is cx.TextNode || val is cx.RawTextNode) {
		// Delegate to the untyped path, which rejects EVERY non-scalar
		// attr value with the specific CXER0100 diagnostics (PathExpr /
		// empty-sequence / rich-data-goes-in-a-child-element) — attributes
		// are strictly scalar (§6.4.1), ascribed or not.
		_, _ := construction_attr_value(a.name, a.value, val)!
		// Unreachable (the strict rule above always errors for
		// non-scalars); kept as a defensive backstop.
		return EvalError{
			code:    'cx-err:CXER0290'
			message: "cannot coerce attribute '${a.name}' value to ${a.data_type} — the value is not a scalar (cx-err:CXER0290)"
		}
	}
	txt := ascription_source_text(a.value, val)
	sn := coerce_typed_scalar_text(txt, a.data_type)!
	return sn.value, ?string(a.data_type)
}

// ascription_source_text picks the text a typed-attribute ascription
// coerces: the value literal's ORIGINAL source spelling when the program
// AST preserved one (number tokens via ProgramLiteral.src, string
// literals' content, the `:name` atom spelling, duration tokens), else
// the evaluated node's textual form (computed values have no source
// spelling to preserve). The literal arms mirror what the DATA reading's
// read_attr_value hands its coercion: quotes stripped, everything else
// verbatim.
fn ascription_source_text(expr cx.ProgramNode, val cx.Node) string {
	if expr is cx.ProgramLiteral {
		match expr.kind {
			.string_lit { return expr.str_val }
			.atom_lit { return ':' + expr.str_val }
			.duration_lit { return expr.dur_val }
			else {
				if expr.src != '' {
					return expr.src
				}
			}
		}
	}
	if val is cx.RawTextNode {
		return val.value
	}
	return node_source_text(val)
}

// construction_attr_value materializes one element-construction attribute
// value. Attributes are STRICTLY SCALAR (spec/code.md §6.4.1; D2 lexicon
// §10; #466/#268 owner ruling): scalars pass through, ANY non-scalar
// evaluated value fails loud with cx-err:CXER0100 — never the former
// canonical stringify, which silently degraded structure to text:
//   • a PathExpr-valued attr (`attr=//a/b`, grammar [130] — a first-class
//     ProgramExpr) is a QUERY evaluated at construction time; its node-set
//     result depends on the bound context and with no `$doc` it is the
//     empty sequence — which pre-fix stringified to attr='' (silent data
//     loss of the path text). Dedicated quote-the-value hint.
//   • ANY value expression that evaluates to the empty sequence — '' is
//     not a faithful rendering of ().
//   • literal / $-bound element / array / map / sequence values — the
//     stringify seam that once backed the retired validate.md attr
//     vocabulary (`enum=[v …]`, `schema=[schema …]`, `extends=$Base`) is
//     REMOVED; rich data belongs in a child element (`[field [enum v …]]`).
// This is the program-reading dual of the data reading's E211 reject
// (read_attr_value) — both readings refuse node-valued attributes.
fn construction_attr_value(attr_name string, value_expr cx.ProgramNode, val cx.Node) !(cx.ScalarValue, ?string) {
	if val is cx.ScalarNode || val is cx.TextNode {
		sv, dt := node_to_attr_value(val)
		return sv, dt
	}
	// `attr=[# … #]` in program element construction: the raw span reaches
	// eval as a node_lit RawTextNode. D2/lexicon §10 (#396 ruling 1b) reads
	// the hash-raw attr form as a STRING scalar carrying the CONTENT — the
	// same reading the data parser gives the identical bytes.
	if val is cx.RawTextNode {
		return cx.ScalarValue(val.value), ?string(none)
	}
	if value_expr is cx.ProgramPathExpr {
		src := program_node_to_source(value_expr)
		return EvalError{
			code:    'cx-err:CXER0100'
			message: "attribute '${attr_name}' value must reduce to a scalar: a bare `${attr_name}=${src}` is a CXPath query evaluated at construction time; quote it (`${attr_name}='${src}'`) to carry a literal path string (cx-err:CXER0100)"
		}
	}
	if is_empty_seq_node(val) {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: "attribute '${attr_name}' value evaluated to the empty sequence (); refusing to write ${attr_name}='' silently — supply a scalar value (cx-err:CXER0100)"
		}
	}
	return EvalError{
		code:    'cx-err:CXER0100'
		message: "attribute '${attr_name}' value must reduce to a scalar — attributes are scalar-only (code.md §6.4.1); put rich/list data in a child element ([e [${attr_name} …]]) instead of ${attr_name}=… (cx-err:CXER0100)"
	}
}

// ── result-field shaping (the "simplest adequate" rule) ──────
//
// A labeled field on a plain (non-directive) result element follows the
// simplest form that can hold its value: a SCALAR field becomes an
// ATTRIBUTE (`name=value`), a STRUCTURED field (element / sequence /
// array / map) becomes a CHILD ELEMENT (`[name value]`). These helpers
// are the single source of truth for that decision so every builder
// (err / response / handles / …) shapes results identically and reads
// round-trip through both parsers. Reads follow the axis: `@name` for a
// scalar field, `/name` for a structured one.

// append_result_field classifies one labeled field per the rule and
// appends it to the element's attribute or child-item list.
pub fn append_result_field(name string, val cx.Node, mut attrs []cx.Attribute, mut items []cx.Node) {
	match val {
		cx.ScalarNode {
			dt := if val.data_type == .string_type {
				?string(none)
			} else {
				?string(cx.scalar_type_name_public(val.data_type))
			}
			attrs << cx.new_attribute(name, val.value, cx.AttributeMeta{
				data_type: dt
			})
		}
		cx.TextNode {
			attrs << cx.new_attribute(name, cx.ScalarValue(val.value), cx.AttributeMeta{})
		}
		else {
			// element / sequence / array / map / err / … → child element.
			items << cx.Node(cx.Element{ name: name, items: [val] })
		}
	}
}

// read_result_field reads a labeled field from a result element, honoring
// the simplest-adequate shaping: it returns the scalar attribute value as
// a ScalarNode when present, else the body of a `[name …]` child element,
// else none. Transitional: it also falls back to a legacy `__cx_slot:name`
// child so un-migrated builders/fixtures keep reading until fully moved.
pub fn read_result_field(el cx.Element, name string) ?cx.Node {
	if sv := el.attr_val(name) {
		return cx.Node(cx.ScalarNode{ value: sv })
	}
	for it in el.items {
		if it is cx.Element && it.name == name && it.items.len > 0 {
			return it.items[0]
		}
	}
	// legacy slot fallback
	slot := '${slot_child_prefix}${name}'
	for it in el.items {
		if it is cx.Element && it.name == slot && it.items.len > 0 {
			return it.items[0]
		}
	}
	return none
}

// operator_element_heads is the set of heads eval_operator_element handles
// (mirror its match arms). It gates §9.2 err-value propagation below: a failed
// operand to any of these must surface the err — NOT for an unrecognized head,
// which falls through to data-element construction.
const operator_element_heads = ['+', '*', '-', '/', '%', '=', '!=', '<', '<=', '>',
	'>=', '~', 'and', 'or', 'not', 'union', 'intersect', 'except']

// eval_operator_element dispatches the operator-headed S-expression
// form. Returns `none` when the element head is not a recognised
// operator (the caller falls through to plain element construction).
fn eval_operator_element(op string, args_in []cx.Node) ?cx.Node {
	// D5: operators read THROUGH a `[?meta]` wrapper — `[?meta {…} V]`
	// behaves exactly as `V` in arithmetic / comparison / logic. Only
	// clone when a wrapper is actually present (the common case is none).
	args := if args_in.any(is_meta_wrapper(it)) {
		args_in.map(meta_unwrap(it))
	} else {
		args_in
	}
	// Error-value propagation (§9.2), uniform with eval_call's arg loop: an
	// operator cannot proceed on a failed operand, so an `[err …]` argument
	// short-circuits and surfaces the err instead of being compared
	// (`[= [err] x]`), atomized (`[+ [err] 1]`), or silently dropped to a data
	// element (`[< [err] 0]`). Only fires for recognized operator heads;
	// `[?try]` / `[?match]` still catch the propagated err. The `[= $x V]`
	// BINDING form never reaches here (binding_clause handles it upstream), so
	// bindings still bind err values for inspection.
	if op in operator_element_heads {
		for a in args {
			if a is cx.Element && is_err_value(a) {
				return a
			}
		}
	}
	match op {
		// N-ary prefix arithmetic (code.md §6.5). Each operand must atomize
		// to a SINGLE numeric scalar (a numeric scalar, or a single
		// text/attribute node / numeric string — XPath untyped-atomic →
		// number); a non-numeric or MULTI-item sequence/node-set operand
		// raises CXER0100 (strict — never skipped; sequence aggregation is
		// the separate `$sum`/`$max`/`$min`/`$avg` surface). Result is int
		// iff every operand is int and the result is whole.
		'+' {
			if args.len < 1 { return op_arity_err('+', 'one or more') }
			// I1 stream 11 (L44): any decimal/bigint operand routes the whole
			// fold through EXACT digit arithmetic (scale max(s₁,s₂) for +/−,
			// s₁+s₂ for ×); a float in the mix is the unbridged error.
			if args_have_decimal_bigint(args) {
				return exact_fold_op('+', args)
			}
			// Checked int64 path (math.md §4.1): all-int operands fold in i64
			// with overflow → CXER3000. Any float operand → f64 path below.
			if operands_all_int(args) {
				mut acc := i64(0)
				for a in args {
					v := atomize_int(a) or { return arith_operand_err('+') }
					acc = checked_add_i64(acc, v) or { return math_overflow_err('+') }
				}
				return int_scalar_node(acc)
			}
			mut acc := f64(0)
			for a in args {
				val, _ := atomize_numeric(a) or { return arith_operand_err('+') }
				acc += val
			}
			return num_result(acc, false)
		}
		'*' {
			if args.len < 1 { return op_arity_err('*', 'one or more') }
			if args_have_decimal_bigint(args) {
				return exact_fold_op('*', args)
			}
			if operands_all_int(args) {
				mut acc := i64(1)
				for a in args {
					v := atomize_int(a) or { return arith_operand_err('*') }
					acc = checked_mul_i64(acc, v) or { return math_overflow_err('*') }
				}
				return int_scalar_node(acc)
			}
			mut acc := f64(1)
			for a in args {
				val, _ := atomize_numeric(a) or { return arith_operand_err('*') }
				acc *= val
			}
			return num_result(acc, false)
		}
		'-' {
			// unary = negate; n-ary = left-fold subtract `(a-b)-c`.
			if args.len < 1 { return op_arity_err('-', 'one or more') }
			if args_have_decimal_bigint(args) {
				return exact_fold_op('-', args)
			}
			if operands_all_int(args) {
				first := atomize_int(args[0]) or { return arith_operand_err('-') }
				if args.len == 1 {
					neg := checked_sub_i64(0, first) or { return math_overflow_err('-') }
					return int_scalar_node(neg)
				}
				mut acc := first
				for i := 1; i < args.len; i++ {
					v := atomize_int(args[i]) or { return arith_operand_err('-') }
					acc = checked_sub_i64(acc, v) or { return math_overflow_err('-') }
				}
				return int_scalar_node(acc)
			}
			first, _ := atomize_numeric(args[0]) or { return arith_operand_err('-') }
			if args.len == 1 {
				return num_result(-first, false)
			}
			mut acc := first
			for i := 1; i < args.len; i++ {
				val, _ := atomize_numeric(args[i]) or { return arith_operand_err('-') }
				acc -= val
			}
			return num_result(acc, false)
		}
		'%' {
			// modulo operator head (#598, owner ruling a): `[% a b]`
			// aliases the §6.5 `mod` builtin exactly — binary, sign of
			// dividend (XPath 3.1 §3.5), int-only when both args int,
			// divide-by-zero CXER0101. One implementation, two spellings.
			return invoke_builtin('mod', args) or {
				return op_arity_err('%', 'two')
			}
		}
		'/' {
			// unary = reciprocal (float); n-ary = left-fold divide
			// `(a/b)/c`. Divide-by-zero traps as CXER0101, as for `[$div]`
			// (§6.5 / pure-arithmetic finite-only rule).
			if args.len < 1 { return op_arity_err('/', 'one or more') }
			if args_have_decimal_bigint(args) {
				return exact_fold_op('/', args)
			}
			first, fint := atomize_numeric(args[0]) or { return arith_operand_err('/') }
			if args.len == 1 {
				if first == 0 { return div_zero_err() }
				return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(1.0 / first), data_type: cx.ScalarType.float_type })
			}
			mut acc := first
			mut all_int := fint
			for i := 1; i < args.len; i++ {
				val, isi := atomize_numeric(args[i]) or { return arith_operand_err('/') }
				if val == 0 { return div_zero_err() }
				acc /= val
				all_int = all_int && isi
			}
			return num_result(acc, all_int)
		}
		'=', '!=' {
			// Comparisons are EXACTLY binary (§6.5); chained comparison is
			// not n-ary.
			if args.len != 2 { return op_arity_err(op, 'exactly two') }
			// Absence guard (code.md §6.2 O4 / §9.1.2.1): a comparison with
			// an absent operand is NEVER satisfied — `[= () v]` and
			// `[!= () v]` are both false (absence is "unknown", not
			// "different"), mirroring XPath's empty-sequence comparisons.
			if is_absence_node(args[0]) || is_absence_node(args[1]) {
				return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(false), data_type: cx.ScalarType.bool_type })
			}
			eq := nodes_equal(args[0], args[1])
			val := if op == '=' { eq } else { !eq }
			return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(val), data_type: cx.ScalarType.bool_type })
		}
		'~' {
			// Graded similarity — the cognate of `=` (similar.md §2.1/§3.1).
			// 2-ary uses the default predicate; the 3rd operand supplies a
			// tuned [similar-predicate …] built by [$similar:predicate …].
			// Result is a [similar score= band= …] element, NOT a boolean;
			// node_ebv reads it truthy iff band=:match. Null/absent operands
			// resolve to the absence channel — "unknown", never 0 (rule 6).
			if args.len != 2 && args.len != 3 { return op_arity_err(op, 'two or three') }
			pred := if args.len == 3 { args[2] } else { cx.Node(cx.Element{ name: '' }) }
			return similar_compare(args[0], args[1], pred)
		}
		'<', '<=', '>', '>=' {
			if args.len != 2 { return op_arity_err(op, 'exactly two') }
			// Absence guard — same rule as `=`/`!=` above: never satisfied,
			// never an error, never a data-element fall-through.
			if is_absence_node(args[0]) || is_absence_node(args[1]) {
				return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(false), data_type: cx.ScalarType.bool_type })
			}
			// I1 stream 11 (L40/L42): exact-family ordering — when either
			// operand is decimal/bigint and BOTH are in the int/bigint/
			// decimal family, compare mathematically on the digit images
			// (no f64 round-trip: bigint stays exact beyond 2^53, decimal
			// keeps its scale digits). int×int stays on the legacy path;
			// decimal×float falls through to atomize_numeric, which rejects
			// the decimal operand → CXER0100 (cast is the only bridge, L44).
			if a_ex := atomize_exact_num(args[0]) {
				if b_ex := atomize_exact_num(args[1]) {
					if a_ex.data_type != cx.ScalarType.int_type
						|| b_ex.data_type != cx.ScalarType.int_type {
						ai := cx.cx_exact_num_image(a_ex) or { '' }
						bi := cx.cx_exact_num_image(b_ex) or { '' }
						c := cx.cx_exact_num_cmp(ai, bi)
						res_ex := match op {
							'<'  { c < 0 }
							'<=' { c <= 0 }
							'>'  { c > 0 }
							'>=' { c >= 0 }
							else { false }
						}
						return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(res_ex), data_type: cx.ScalarType.bool_type })
					}
				}
			}
			// Ordered comparison is numeric-strict (code.md §6.5, #405):
			// operands admit exactly what bare arithmetic admits — a single
			// int/float scalar or a single node atomizing to one. Anything
			// else is CXER0100, NEVER a data-element fall-through (which
			// reads truthy and silently passes every [?for] guard).
			a_n, _ := atomize_numeric(args[0]) or {
				return ordered_cmp_operand_err(op, args[0])
			}
			b_n, _ := atomize_numeric(args[1]) or {
				return ordered_cmp_operand_err(op, args[1])
			}
			res := match op {
				'<'  { a_n < b_n }
				'<=' { a_n <= b_n }
				'>'  { a_n > b_n }
				'>=' { a_n >= b_n }
				else { false }
			}
			return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(res), data_type: cx.ScalarType.bool_type })
		}
		'and' {
			// Element-body-position `and`: `[and EXPR1 EXPR2 ...]`
			// evaluates each child expression to a CX value and
			// applies EBV; result is true iff all children EBV-true.
			// Mirrors the `and` builtin used via the call surface.
			if args.len < 1 { return op_arity_err('and', 'one or more') }
			mut all := true
			for a in args {
				ebv := node_ebv(a) or { return iterator_ebv_err() }
				if !ebv { all = false; break }
			}
			return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(all), data_type: cx.ScalarType.bool_type })
		}
		'or' {
			if args.len < 1 { return op_arity_err('or', 'one or more') }
			mut any := false
			for a in args {
				ebv := node_ebv(a) or { return iterator_ebv_err() }
				if ebv { any = true; break }
			}
			return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(any), data_type: cx.ScalarType.bool_type })
		}
		'not' {
			if args.len != 1 { return op_arity_err('not', 'exactly one') }
			ebv := node_ebv(args[0]) or { return iterator_ebv_err() }
			negated := !ebv
			return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(negated), data_type: cx.ScalarType.bool_type })
		}
		// Set/sequence combinators (code.md §6.5) — reserved prefix heads
		// valid in every expression position, n-ary ≥ 2, left-fold,
		// structural equality (nodes_equal), first-occurrence order.
		'union' {
			if args.len < 2 { return op_arity_err('union', 'two or more') }
			mut all := []cx.Node{}
			for a in args {
				all << iterate(a)
			}
			return cx.Node(cx.Element{ name: seq_marker_name, items: set_op_dedup(all) })
		}
		'intersect' {
			if args.len < 2 { return op_arity_err('intersect', 'two or more') }
			mut acc := set_op_dedup(iterate(args[0]))
			for a in args[1..] {
				other := iterate(a)
				acc = acc.filter(fn [other] (it cx.Node) bool {
					for o in other {
						if nodes_equal(it, o) { return true }
					}
					return false
				})
			}
			return cx.Node(cx.Element{ name: seq_marker_name, items: acc })
		}
		'except' {
			if args.len < 2 { return op_arity_err('except', 'two or more') }
			mut acc := set_op_dedup(iterate(args[0]))
			for a in args[1..] {
				other := iterate(a)
				acc = acc.filter(fn [other] (it cx.Node) bool {
					for o in other {
						if nodes_equal(it, o) { return false }
					}
					return true
				})
			}
			return cx.Node(cx.Element{ name: seq_marker_name, items: acc })
		}
		else {
			return none
		}
	}
}

// set_op_dedup removes structural duplicates preserving first-occurrence
// order — the shared dedup step of the union/intersect/except operators.
fn set_op_dedup(items []cx.Node) []cx.Node {
	mut seen := []cx.Node{}
	for it in items {
		mut dup := false
		for s in seen {
			if nodes_equal(it, s) { dup = true; break }
		}
		if !dup { seen << it }
	}
	return seen
}

// is_absence_node reports whether a node is the absence channel — the
// empty sequence `()` (a bare or seq-marker Element with no items and
// no attributes). Comparisons treat absence as never-satisfied
// (code.md §6.2 O4 / §9.1.2.1 null-totality posture).
fn is_absence_node(n cx.Node) bool {
	if n is cx.Element {
		return (n.name == '' || n.name == seq_marker_name)
		    && n.items.len == 0 && n.attrs.len == 0
	}
	return false
}

// arith_operand_err returns the canonical CXER0100 err-VALUE for an
// invalid `+ - * /` operand (non-numeric, or a multi-item sequence /
// node-set) — strict, never skipped (code.md §6.5). It is a value (not a
// V-error) so it propagates like the other arithmetic traps and can be
// caught with the `?` postfix.
fn arith_operand_err(op string) cx.Node {
	return mk_err('cx-err:CXER0100',
		'[${op}] operand is not a single numeric scalar (a non-numeric value or a multi-item sequence/node-set); scalar arithmetic is strict — use [\$sum …] for sequence aggregation')
}

// ordered_cmp_operand_err returns the canonical CXER0100 err-VALUE for a
// non-numeric `< <= > >=` operand (code.md §6.5 "Ordered comparison —
// numeric-strict", #405). Names the operator and the offending operand
// kind; a value (not a V-error) so it propagates and `?` can catch it.
fn ordered_cmp_operand_err(op string, n cx.Node) cx.Node {
	return mk_err('cx-err:CXER0100',
		'[${op}] operand is not a single numeric scalar (got ${ordered_operand_kind(n)}); ordered comparison is strict — convert with [cast \$s :int] / [cast \$s :float]')
}

// ordered_operand_kind describes the rejected operand for the error
// message above — the scalar TYPE name when it is a scalar (string/bool/
// atom/datetime/…), else the node shape.
fn ordered_operand_kind(n cx.Node) string {
	if n is cx.ScalarNode {
		name := cx.scalar_type_name_public(n.data_type)
		art := if name[0] in [`a`, `e`, `i`, `o`, `u`] { 'an' } else { 'a' }
		return '${art} ${name}-typed scalar'
	}
	if n is cx.Element {
		if n.name == '' || n.name == seq_marker_name || n.name == arr_marker_name {
			return 'a multi-item sequence/array/node-set'
		}
		return 'an element'
	}
	if n is cx.TextNode {
		return 'untyped text'
	}
	return 'a non-scalar node'
}

// op_arity_err returns the CXER0100 err-VALUE for a reserved operator
// head invoked with the wrong number of operands (§6.5). Once a reserved
// operator head is recognized, wrong arity is an ERROR — it never falls
// through to data-element construction (the head is never a data element).
fn op_arity_err(op string, expected string) cx.Node {
	return mk_err('cx-err:CXER0100',
		'[${op}] wrong arity — expected ${expected} operand(s)')
}

// div_zero_err returns the CXER0101 err-VALUE for division by zero,
// matching the `[$div]` / `[$idiv]` / `[$mod]` arithmetic trap (§6.5;
// CX floats are finite-only).
fn div_zero_err() cx.Node {
	return mk_err('cx-err:CXER0101', 'division by zero')
}

// num_result builds the scalar result of an arithmetic fold: int when
// every operand was int AND the value is whole, else float.
fn num_result(acc f64, all_int bool) cx.Node {
	if all_int && acc == f64(i64(acc)) {
		return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(i64(acc)), data_type: cx.ScalarType.int_type })
	}
	return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(acc), data_type: cx.ScalarType.float_type })
}

// ── checked int64 arithmetic (math.md §4.1) ──────────────────────────
// Bare `+` / `-` / `*` are checked-by-default over int64: when EVERY operand
// is int-typed the fold runs in i64 (NOT f64 — f64 loses precision above 2^53
// and cannot detect overflow), raising CXER3000 on overflow. A float operand
// anywhere routes to the f64 path (float overflow → ±inf, IEEE-754). The
// `wrapping-*` module functions are the explicit modular escape hatch.
const eval_i64_min = i64(-9223372036854775807 - 1)

// atomize_int reads the ORIGINAL i64 of an int-typed operand (mirrors
// atomize_numeric's unwrapping of single-item sequence/array/synthetic
// wrappers) WITHOUT the lossy f64 conversion. none for a float / non-numeric.
fn atomize_int(n cx.Node) ?i64 {
	if n is cx.ScalarNode {
		v := n.value
		if v is i64 {
			return v
		}
		return none
	}
	if n is cx.Element {
		if n.name == '' || n.name == seq_marker_name || n.name == arr_marker_name {
			if n.items.len == 1 {
				return atomize_int(n.items[0])
			}
			return none
		}
		if n.items.len == 1 {
			return atomize_int(n.items[0])
		}
		return none
	}
	return none
}

// operands_all_int reports whether every operand atomizes to an int (so the
// fold runs checked-i64). A non-numeric / float operand → false (the caller's
// f64 path then computes in float or re-raises the operand err).
fn operands_all_int(args []cx.Node) bool {
	for a in args {
		atomize_int(a) or { return false }
	}
	return true
}

fn checked_add_i64(a i64, b i64) ?i64 {
	r := a + b
	if (b > 0 && r < a) || (b < 0 && r > a) {
		return none
	}
	return r
}

fn checked_sub_i64(a i64, b i64) ?i64 {
	r := a - b
	if (b < 0 && r < a) || (b > 0 && r > a) {
		return none
	}
	return r
}

fn checked_mul_i64(a i64, b i64) ?i64 {
	if a == 0 || b == 0 {
		return i64(0)
	}
	if (a == -1 && b == eval_i64_min) || (b == -1 && a == eval_i64_min) {
		return none
	}
	r := a * b
	if r / a != b {
		return none
	}
	return r
}

fn int_scalar_node(v i64) cx.Node {
	return cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(v)
		data_type: cx.ScalarType.int_type
	})
}

fn op_word(op string) string {
	return match op {
		'+' { 'add' }
		'-' { 'sub' }
		'*' { 'mul' }
		else { op }
	}
}

fn math_overflow_err(op string) cx.Node {
	return mk_err('cx-err:CXER3000',
		'E_MATH_OVERFLOW: int64 overflow in `${op}` (checked by default; use wrapping-${op_word(op)} for modular arithmetic)')
}

// atomize_numeric atomizes a single `+ - * /` operand to (value, is_int)
// per code.md §6.5: an int/float-TYPED scalar passes through; a
// single-child node (attribute axis / labeled field) or single-item
// sequence/array wrapper unwraps to its lone item, which must itself be
// numerically typed. CX is type-strict — a string-typed scalar or a bare
// TextNode is NON-numeric (no string parsing; `[cast]` to convert).
// Returns none for a non-numeric value or a MULTI-item sequence/array/
// node-set (the caller raises CXER0100) — bare arithmetic NEVER
// aggregates a sequence (that is `$sum` etc.).
fn atomize_numeric(n cx.Node) ?(f64, bool) {
	if n is cx.ScalarNode {
		v := n.value
		// Only numerically-TYPED scalars atomize. CX is type-strict
		// (§6.5 / cxdm §5.1): a string-typed scalar is NOT numeric and is
		// NOT parsed (`[+ "5" 3]` errors — use `[cast … :int]`). String
		// leniency (XPath fn:number) is the `$sum`-family's job, not bare
		// arithmetic's.
		if v is i64 { return f64(v), true }
		if v is f64 { return v, false }
		return none
	}
	if n is cx.Element {
		// A single-item sequence/array wrapper or a single-child synthetic
		// node (attribute axis / labeled field) atomizes to its lone item;
		// a multi-item wrapper is a node-set → none (CXER0100). A numeric
		// child/attr auto-types to an int/float scalar (handled above), so
		// no string-parsing is needed here.
		if n.name == '' || n.name == seq_marker_name || n.name == arr_marker_name {
			if n.items.len == 1 { return atomize_numeric(n.items[0]) }
			return none
		}
		if n.items.len == 1 {
			return atomize_numeric(n.items[0])
		}
		return none
	}
	// A TextNode is untyped text (a numeric body auto-types to an int/float
	// scalar, handled above), so a bare TextNode operand is non-numeric.
	return none
}

// args_have_decimal_bigint reports whether any operand atomizes to a
// decimal- or bigint-typed scalar — the trigger for the L44 exact lane.
fn args_have_decimal_bigint(args []cx.Node) bool {
	for a in args {
		if sn := atomize_exact_num(a) {
			if sn.data_type == cx.ScalarType.decimal_type
				|| sn.data_type == cx.ScalarType.bigint_type {
				return true
			}
		}
	}
	return false
}

// exact_fold_op folds `+ - * /` over exact-family operands with digit
// arithmetic (I1 stream 11, L44): decimal ⊕ decimal/int/bigint is EXACT
// (scale max(s₁,s₂) for +/−, s₁+s₂ for ×); division computes the exact
// quotient when it terminates and errors CXER3002 otherwise (a rounding
// context is the only way to divide non-terminating quotients); a float
// operand in the mix is unbridged — `[cast]` is the only decimal↔float
// bridge. Result kind: decimal when any operand is decimal or the result
// carries a fraction; bigint otherwise.
fn exact_fold_op(op string, args []cx.Node) cx.Node {
	mut imgs := []string{cap: args.len}
	mut any_decimal := false
	for a in args {
		sn := atomize_exact_num(a) or {
			return mk_err('cx-err:CXER0100',
				'${op}: decimal/bigint arithmetic admits only int/bigint/decimal operands — [cast] is the only decimal↔float bridge (L44)')
		}
		if sn.data_type == cx.ScalarType.decimal_type {
			any_decimal = true
		}
		imgs << cx.cx_exact_num_image(sn) or { '0' }
	}
	mut acc := imgs[0]
	match op {
		'+' {
			for i := 1; i < imgs.len; i++ {
				acc = cx.cx_exact_add(acc, imgs[i])
			}
		}
		'*' {
			for i := 1; i < imgs.len; i++ {
				acc = cx.cx_exact_mul(acc, imgs[i])
			}
		}
		'-' {
			if imgs.len == 1 {
				acc = cx.cx_exact_sub('0', acc)
			} else {
				for i := 1; i < imgs.len; i++ {
					acc = cx.cx_exact_sub(acc, imgs[i])
				}
			}
		}
		'/' {
			if imgs.len == 1 {
				acc = cx.cx_exact_div('1', acc) or { return exact_div_err(err) }
			} else {
				for i := 1; i < imgs.len; i++ {
					acc = cx.cx_exact_div(acc, imgs[i]) or { return exact_div_err(err) }
				}
			}
		}
		else {
			return mk_err('cx-err:CXER0100', 'exact arithmetic: unsupported op ${op}')
		}
	}
	if any_decimal || acc.contains('.') {
		return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(acc), data_type: cx.ScalarType.decimal_type })
	}
	return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(acc), data_type: cx.ScalarType.bigint_type })
}

// exact_integral_result implements floor/ceiling/round for the exact
// family (I1 stream 11): decimal → exact integral (int when it fits i64,
// bigint otherwise); bigint passes through unchanged. none → the caller's
// legacy int/float arms take over.
fn exact_integral_result(a0 cx.ScalarNode, op string) ?cx.Node {
	if a0.data_type == cx.ScalarType.bigint_type {
		return cx.Node(a0)
	}
	if a0.data_type != cx.ScalarType.decimal_type {
		return none
	}
	img := cx.cx_exact_num_image(a0) or { return none }
	res := match op {
		'floor'   { cx.cx_exact_floor(img) }
		'ceiling' { cx.cx_exact_ceiling(img) }
		else      { cx.cx_exact_round_half_away(img) }
	}
	if v := strconv.parse_int(res, 10, 64) {
		return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(v), data_type: cx.ScalarType.int_type })
	}
	return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(res), data_type: cx.ScalarType.bigint_type })
}

fn exact_div_err(err IError) cx.Node {
	msg := err.msg()
	if msg.contains('division by zero') {
		return mk_err('cx-err:CXER0101', 'division by zero')
	}
	return mk_err('cx-err:CXER3002', msg)
}

// atomize_exact_num unwraps to a single EXACT-FAMILY scalar (int / bigint /
// decimal), mirroring atomize_numeric's wrapper rules (I1 stream 11,
// L40/L42). Float is deliberately outside the family — `[cast]` is the only
// decimal↔float bridge (L44).
fn atomize_exact_num(n cx.Node) ?cx.ScalarNode {
	if n is cx.ScalarNode {
		if _ := cx.cx_exact_num_image(n) {
			return n
		}
		return none
	}
	if n is cx.Element {
		if n.name == '' || n.name == seq_marker_name || n.name == arr_marker_name {
			if n.items.len == 1 {
				return atomize_exact_num(n.items[0])
			}
			return none
		}
		if n.items.len == 1 {
			return atomize_exact_num(n.items[0])
		}
		return none
	}
	return none
}

fn scalar_to_f64_either(n cx.Node) ?f64 {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			i64 { return f64(v) }
			f64 { return v }
			else { return none }
		}
	}
	return none
}

fn both_int(a cx.Node, b cx.Node) bool {
	if a is cx.ScalarNode && b is cx.ScalarNode {
		av := a.value
		bv := b.value
		if av is i64 && bv is i64 { return true }
	}
	return false
}

// value_matches_type reports whether `n` satisfies a `::T` / `[returns T]`
// annotation under --strict (§12.7 / §26a TypeName). Covers the scalar
// vocabulary the strict checker validates; UNRECOGNISED / compound type
// expressions (`[or …]`, `[sequence …]` — the documented follow-on)
// return true (unchecked) so strict never false-rejects a type it cannot
// yet validate.
fn value_matches_type(n cx.Node, typ string) bool {
	t := typ.trim_space()
	if t == '' || t == 'any' {
		return true
	}
	// Stream 16 W1 (L65/#706): the STRUCTURAL form crosses into evaluation —
	// parse the type expression and check structurally. An unparseable
	// source (pre-repair defs carry verbatim slots) stays accepting here;
	// registration is where malformed sources now refuse loudly.
	te := cx.parse_type_expr(t) or { return true }
	return value_matches_type_expr(n, te)
}

// value_matches_type_expr is the completed §12.7 checker (stream 16 W1):
// bracketed types check structurally, element-name types head-match,
// temporals and the node family check by kind — nothing silently passes.
fn value_matches_type_expr(n cx.Node, t cx.TypeExpr) bool {
	match t.kind {
		.any_ {
			return true
		}
		.unknown_ {
			return true
		}
		.union_ {
			for m in t.members {
				if value_matches_type_expr(n, m) {
					return true
				}
			}
			return false
		}
		.sequence_ {
			// a sequence-of-T: every item matches T; a single non-sequence
			// value is the one-item sequence (CXDM §1). Runtime sequences
			// materialize as the seq-marker element OR a SequenceNode —
			// treat both (the same duality m_key_values reads).
			if n is cx.Element && n.name == seq_marker_name {
				for it in n.items {
					if !value_matches_type_expr(it, t.members[0]) {
						return false
					}
				}
				return true
			}
			if n is cx.SequenceNode {
				for it in n.items {
					if !value_matches_type_expr(it, t.members[0]) {
						return false
					}
				}
				return true
			}
			return value_matches_type_expr(n, t.members[0])
		}
		.iterator_ {
			// [iterator T]: the value must BE an iterator; item typing is
			// observable only on consumption (lazy — never forced here).
			return n is cx.IteratorNode
		}
		.element_name {
			if n is cx.Element {
				return n.name == (t.name or { '' })
			}
			return false
		}
		.kind_name {
			name := t.name or { return true }
			match name {
				'any' {
					return true
				}
				'number' {
					if n is cx.ScalarNode {
						return n.value is i64 || n.value is f64
					}
					return false
				}
				'int', 'i8', 'i16', 'i32', 'i64', 'u8', 'u16', 'u32', 'u64' {
					if n is cx.ScalarNode {
						return n.value is i64
					}
					return false
				}
				'bigint' {
					if n is cx.ScalarNode {
						return n.data_type == cx.ScalarType.bigint_type
					}
					return false
				}
				'decimal' {
					if n is cx.ScalarNode {
						return n.data_type == cx.ScalarType.decimal_type
					}
					return false
				}
				'float', 'f16', 'f32', 'f64' {
					if n is cx.ScalarNode {
						return n.value is f64
					}
					return false
				}
				'bool' {
					if n is cx.ScalarNode {
						return n.value is bool
					}
					return false
				}
				'string', 'secret' {
					if n is cx.ScalarNode {
						return n.value is string && n.data_type != cx.ScalarType.atom_type
							&& n.data_type != cx.ScalarType.bigint_type
							&& n.data_type != cx.ScalarType.decimal_type
							&& n.data_type != cx.ScalarType.date_type
							&& n.data_type != cx.ScalarType.datetime_type
							&& n.data_type != cx.ScalarType.bytes_type
					}
					return false
				}
				'null' {
					if n is cx.ScalarNode {
						return n.value is cx.NullValue
					}
					return false
				}
				'atom' {
					if n is cx.ScalarNode {
						return n.data_type == cx.ScalarType.atom_type
					}
					return false
				}
				'date' {
					if n is cx.ScalarNode {
						return n.data_type == cx.ScalarType.date_type
					}
					return false
				}
				'datetime', 'instant' {
					if n is cx.ScalarNode {
						return n.data_type == cx.ScalarType.datetime_type
					}
					return false
				}
				'bytes' {
					if n is cx.ScalarNode {
						return n.data_type == cx.ScalarType.bytes_type
					}
					return false
				}
				'duration', 'period' {
					// refinements of int (signed nanosecond count / calendar
					// period encoding) — the kind is what a VALUE carries.
					if n is cx.ScalarNode {
						return n.value is i64
					}
					return false
				}
				'element' {
					return n is cx.Element
				}
				'sequence' {
					return n is cx.SequenceNode
						|| (n is cx.Element && (n as cx.Element).name == seq_marker_name)
				}
				'iterator' {
					return n is cx.IteratorNode
				}
				'array' {
					return n is cx.ArrayNode
				}
				'map' {
					return n is cx.MapNode
				}
				'function' {
					return closure_id_of(n) != none
				}
				'path' {
					// Real kind check since the I5-s17 W6 graft (PathNode
					// joined the Node sum type) — the accept-always residual
					// this arm carried validated ANY value as ::path.
					return n is cx.PathNode
				}
				'document' {
					return n is cx.DocumentNode
				}
				'text' {
					return n is cx.TextNode
				}
				'scalar-node' {
					return n is cx.ScalarNode
				}
				'comment' {
					return n is cx.CommentNode
				}
				'pi' {
					return n is cx.PINode
				}
				'directive' {
					return n is cx.CXDirectiveNode
				}
				else {
					// an unlisted lowercase name never parses ([157] is
					// closed) — unreachable; accept defensively.
					return true
				}
			}
		}
	}
	return true
}

// is_int_node reports whether `n` is an integer-typed scalar — used by
// the n-ary arithmetic fold to decide whether to keep an int result.
fn is_int_node(n cx.Node) bool {
	if n is cx.ScalarNode {
		return n.value is i64
	}
	return false
}

// ── Bindings + paths ────────────────────────────────────────────────────────

fn eval_binding(b cx.ProgramBinding, mut env MatchEnv) !cx.Node {
	return eval_binding_opt(b, mut env, true)!
}

// eval_call_arg evaluates one function-call argument, FORCING a lazy record
// (#804 leg 2).
//
// The rule is: passing a value to a function is a structural read. The callee
// may inspect it — `[$count $u]` asks for its item count, `[$json $u]` walks
// it — and the caller cannot know which callee it has, so the conservative
// answer is the only sound one. This is the choke point for all five places
// arguments are evaluated, so a new builtin cannot forget it.
//
// It is NOT the same as carrying the value. `[yield $u]` and `[wrapped $u]`
// hold the record without asking anything of it, and stay lazy — which is
// where the architecture's win lives.
//
// This site was found by the differential, not by reading: `[$count $u]`
// answered 1 (one opaque node) where the materialising path answered 8. It is
// exactly the unbounded escape the leg-2 audit predicted from a path-less
// binding read, and it is the reason ruling 1a put an instrument in front of
// the mechanism rather than an argument.
@[inline]
fn eval_call_arg(a cx.ProgramNode, mut env MatchEnv) !cx.Node {
	v := eval_node(a, mut env)!
	if v is cx.LazyRecord {
		return cx.Node(v.force()!)
	}
	return v
}

// eval_for_source evaluates a [?for] `[in $x SOURCE]` generator source.
// A binding-path source iterates a NODE-SET, so the §6.2 terminal-field
// unwrap must NOT fire (a single-match `/name` terminal step must stay
// an element, not collapse to its inner scalar — program-for-011 binding
// `[in $e $u/emails/email]` over a one-email user). Non-binding sources
// (CXPath `//…`, sequences, ranges) evaluate normally.
fn eval_for_source(src cx.ProgramNode, mut env MatchEnv) !cx.Node {
	if src is cx.ProgramBinding {
		res := eval_binding_opt(src, mut env, false)!
		// #21: a path-access source landing on a map/element member whose
		// value is a COLLECTION (sequence/array) must iterate the
		// collection's MEMBERS — consistent with [$count $m/key] and with
		// binding the same path to a var first. unwrap_terminal=false keeps
		// single-match ELEMENT node-sets whole (program-for-011), but a lone
		// named wrapper holding exactly one collection is NOT an element
		// node-set — it is that collection. Expose it so iterate() sees the
		// members (the read path already unwraps it; this realigns [?for]).
		// Restricted to path access (src.path.len > 0) so a bare `$var`
		// for-source still iterates whatever value the var holds. A sequence/
		// array materializes as a seq/arr-marker Element (not a bare
		// SequenceNode), so detect both shapes.
		if src.path.len > 0 && res is cx.Element {
			if res.name != '' && res.name != seq_marker_name && res.name != arr_marker_name
				&& res.items.len == 1 {
				inner := res.items[0]
				if inner is cx.Element {
					if inner.name == seq_marker_name || inner.name == arr_marker_name {
						return inner
					}
				} else if inner is cx.SequenceNode || inner is cx.ArrayNode {
					return inner
				}
			}
		}
		return res
	}
	return eval_node(src, mut env)!
}

// eval_binding_opt is eval_binding with an explicit terminal-unwrap
// switch. `unwrap_terminal = true` is the §6.2 simple-field-accessor
// read behaviour (`$r/value` → inner value); `false` keeps the full
// node-set (used by [?for] `[in $x PATH]` generator sources, which
// iterate a node-set and must NOT collapse a single-match terminal
// `/name` step to its inner scalar — program-for-011).
fn eval_binding_opt(b cx.ProgramBinding, mut env MatchEnv, unwrap_terminal bool) !cx.Node {
	mut val := env.bindings[b.name] or {
		// First-class function reference (D1): a path-less `$name` that
		// is not a bound variable but names a closure or builtin yields
		// that function as a VALUE (e.g. `[?map … [using $floor]]`).
		if b.path.len == 0 {
			if fv := resolve_fn_value(b.name, mut env) {
				return fv
			}
		}
		// E_RESERVED_BINDING_USE (code.md registry): the reserved predicate
		// bindings referenced OUTSIDE a predicate body are the spec'd
		// CXER0231, never the generic unbound-variable 0001 (R3.12; inside a
		// predicate they are bound, so reaching here means outside).
		if b.name in ['_position', '_last'] {
			return EvalError{
				code:    'cx-err:CXER0231'
				message: 'reserved predicate binding $${b.name} referenced outside a predicate body (E_RESERVED_BINDING_USE)'
			}
		}
		return EvalError{
			code:    'cx-err:CXER0001'
			message: 'unbound variable $${b.name}'
		}
	}
	if b.path.len == 0 {
		return val
	}
	// #804 leg 2 — THE FORCING POINT for the streamed-input fast path.
	//
	// A path step is a structural read by definition, so a lazy record
	// materialises here and every line below sees an ordinary Element. A
	// PATH-LESS read above returns the value untouched, which is where the
	// architecture's win comes from and also the one way an unforced record
	// escapes into general expression context — the reason ruling 1a carries
	// soundness with the `-d cx_no_lazy_record` dual-build differential
	// rather than with an audit. See `cx/lazy_record.v`.
	if val is cx.LazyRecord {
		val = cx.Node(val.force()!)
		// MEMOISE BY WRITING BACK OVER THE BINDING (#804 leg 4). The record
		// carried a shared heap cell for this; profiling showed it cost one
		// allocation per record for a memo that a pass-through workload
		// never reads, and allocation is ~50% of samples on this path. The
		// binding table already exists and holds exactly the same fact, so
		// `$u/a` then `$u/b` still parses once — it just stopped paying for
		// the privilege on every record that is never forced at all.
		env.cow_bindings()
		env.bindings[b.name] = val
	}
	return apply_value_path(val, b.path, mut env, unwrap_terminal)
}

// apply_value_path applies a [135a] step run to an already-resolved VALUE —
// THE shared machinery behind `$x/steps` (eval_binding_opt above) and the
// CRS-1 call-result postfix `[$f …]/steps` (eval_call): stepping a call
// result is semantically identical to binding the result and stepping the
// binding, so both surfaces route through this one function (fast path /
// walk_binding_path_seq pair, terminal unwraps, node-set distribution, the
// err-inspection lane — all inherited, never re-implemented).
fn apply_value_path(v cx.Node, path_in []cx.ProgramPathStep, mut env MatchEnv, unwrap_terminal bool) !cx.Node {
	// #925 (RULED: PYE-1a/PYE-1b): computed step names resolve HERE, once,
	// before any walker sees the steps.
	path := resolve_computed_steps(path_in, mut env)!
	mut val := v
	// A lazy record reaching here through a non-binding producer forces
	// exactly as at the binding forcing point (no memo target — the value
	// has no binding cell to write back to).
	if val is cx.LazyRecord {
		val = cx.Node(val.force()!)
	}
	// Future-handle attribute access (§10.5.1). A `$f@state` / `$f@value`
	// / `$f@cause` / `$f@id` reads the LIVE future record from env.state
	// rather than the stale handle captured at [?async] time. Only a
	// single `.attr` step on a future-handle element is intercepted; any
	// other path shape falls through to ordinary resolution.
	if path.len == 1 && path[0].kind == .attr && path[0].predicates.len == 0 {
		if val is cx.Element && val.name == 'future-handle' {
			if fv := future_handle_attr(val, path[0].name, mut env) {
				return fv
			}
		}
	}
	// Fast path: every step is a single-result kind with no predicates.
	// This preserves the walker semantics + perf for the common
	// case (~90% of binding-path uses).
	//
	// `.child` is **not** fast-path eligible: per XPath 3.1 / CXPath
	// child-axis semantics it returns *all* matching children, but
	// `walk_path_step` for `.child` returns only the first. Routing
	// through `walk_binding_path_seq` materializes the multi-result
	// shape via the synthetic `Element{ name: '', items: [...] }` wrapper
	// — same shape the descendant axis already produces, which the
	// downstream emitter handles. Closes the hypothesis-register
	// confirmed gap (cookbook ex. 115).
	mut fast_eligible := true
	// A node-set-wrapper value (`Element{name:''}` — a bound CXPath /
	// binding-path query result, e.g. `[= $u $d//a]`) is a SET of context
	// nodes: every step must apply per member with node-set semantics
	// (root expansion, terminal-attr unwrap, per-match materialization).
	// The fast path's walk_path_step has no node-set awareness — route to
	// the sequence walker. Real sequences (seq/arr markers) stay on the
	// fast path for the O4 value-distribution behaviour.
	if val is cx.Element && val.name == '' {
		fast_eligible = false
	}
	for step in path {
		if step.predicates.len > 0 {
			fast_eligible = false
			break
		}
		match step.kind {
			.attr, .member, .wildcard_children {}
			.child, .descendant, .descendant_wildcard, .parent {
				fast_eligible = false
				break
			}
		}
	}
	if fast_eligible {
		mut cur := val
		for step in path {
			cur = walk_path_step(cur, step)!
		}
		return cur
	}
	// Slow path: any descendant/parent/predicate step in the path.
	// Lift to sequence-walking semantics with ancestor tracking.
	// The result is either a single node (single-result
	// terminal step) or a synthetic Element wrapper { name: '', items
	// }: matches the eval_path_expr sequence-as-element convention.
	return walk_binding_path_seq(val, path, mut env, unwrap_terminal)!
}

// ── Slice as first-class value ───────────────────────────────
//
// `eval_slice_literal` parks the unresolved axes in
// `env.state.slice_literals` keyed by a fresh integer id and returns a
// `cx.Element{ name: '__cx_slice__' }` whose `:id` attribute carries
// the key. Per `$_last` is NOT resolved here — the axes
// remain unevaluated so application against any receiver picks up that
// receiver's length at apply time.
//
// The Slice value is opaque at the data layer (no surface render) — it
// is intended for indirection (`[?def $w SLICE] ... $xs[$w]`). The
// marker name `__cx_slice__` follows the same `__cx_X__` convention
// as `__cx_seq__` / `__cx_arr__` / `__cx_map__`.
const slice_marker_name = '__cx_slice__'

fn eval_slice_literal(s cx.ProgramSliceLiteral, mut env MatchEnv) !cx.Node {
	// Slice-literal postfix steps (RULED PS-1, #886): kind-driven like any
	// stepped value — steps apply to the slice VALUE (the marker element).
	if s.path.len > 0 {
		base := eval_slice_literal(cx.ProgramSliceLiteral{ ...s, path: []cx.ProgramPathStep{} }, mut env)!
		return apply_value_path(base, s.path, mut env, true)
	}
	mut state := env.state
	if state == unsafe { nil } {
		return EvalError{
			code:    'cx-err:CXER0001'
			message: 'slice literal: no program state'
		}
	}
	id := 'slice-${state.next_slice_id}'
	state.next_slice_id++
	state.slice_literals[id] = s.axes.clone()
	return cx.Element{
		name:  slice_marker_name
		attrs: [cx.Attribute{ name: 'id', value: cx.ScalarValue(id) }]
	}
}

// slice_value_axes recovers the stashed axes for a Slice value. Returns
// `none` when the node is not a Slice or the registry key has been
// dropped (shouldn't happen during a single eval pass).
fn slice_value_axes(n cx.Node, env MatchEnv) ?[]cx.SliceAxis {
	if n !is cx.Element {
		return none
	}
	el := n as cx.Element
	if el.name != slice_marker_name {
		return none
	}
	mut id := ''
	for a in el.attrs {
		if a.name == 'id' {
			v := a.value
			if v is string {
				id = v
				break
			}
		}
	}
	if id == '' {
		return none
	}
	if env.state == unsafe { nil } {
		return none
	}
	axes := env.state.slice_literals[id] or { return none }
	return axes
}

// ── slice / multi-axis evaluation (W5c) ──────────────────────────
//
// `eval_slice_access` resolves a `cx.ProgramSliceAccess` against the
// underlying `$binding`'s current value. The receiver is materialized
// to a flat `[]cx.Node` sequence; the single axis is then applied
// (single index, range, or full).
//
// Per:
//   - D4 indexing base: 1-based (`$xs[1]` → first element).
//   - D5 endpoints: STOP is INCLUSIVE for range axes.
//   - D9 negative indices: `-1` → last; `-2` → second-to-last; etc.
//   - D6/D11 `$_last` sigil: resolves to `receiver.len - 1` at apply
//     time, NOT at slice-construction time.
//   - D20 empty-slice semantics: out-of-range / wrong-direction slices
//     return the empty sequence rather than erroring.
//   - D21 step-of-zero: raises CXER0100 at evaluation time.
//   - D12 multi-axis: W5c is single-axis only — a SliceAxes list with
//     two-or-more axes defers to W6-E with CXER0100.
fn eval_slice_access(s cx.ProgramSliceAccess, mut env MatchEnv) !cx.Node {
	bind_val := env.bindings[s.binding.name] or {
		return EvalError{
			code:    'cx-err:CXER0001'
			message: 'unbound variable \$${s.binding.name}'
		}
	}
	// Walk any path steps on the binding (e.g. `$obj/xs[2:5]`) before
	// applying the slice. The binding's path semantics match
	// `eval_binding` exactly so we reuse it by re-eval-ing the inner
	// cx.ProgramBinding with a fresh local env (cheap — path walks are
	// purely functional).
	receiver := if s.binding.path.len == 0 {
		bind_val
	} else {
		eval_binding(s.binding, mut env)!
	}
	// slicing is defined only for positional sequences.
	// A Map (whether a materialised `cx.MapNode` or the in-pipeline
	// `__cx_map__` envelope) has no positional axis, so reject it rather
	// than silently iterating its entries in arbitrary order.
	if receiver is cx.MapNode {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: 'slice on map requires positional sequence; got map'
		}
	}
	if receiver is cx.Element && receiver.name == map_marker_name {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: 'slice on map requires positional sequence; got map'
		}
	}
	if s.axes.len == 0 {
		// Defensive — parser never emits a zero-axis slice.
		return receiver
	}
	// Slice as first-class value. When the single axis's
	// start expression is a `$binding` resolving to a Slice value,
	// expand its stashed axes in place. This is what makes `$xs[$w]`
	// work when `$w` was bound via `[?let $w = [2:5] :in …]`.
	//
	// Restricted to bare `cx.ProgramBinding` start exprs so we don't
	// evaluate `$_last` / arithmetic expressions outside the normal
	// `eval_slice_index_expr` path (which installs the `_last` sigil).
	// Any other start shape falls through to the single-axis dispatch
	// below.
	mut effective_axes := s.axes.clone()
	if effective_axes.len == 1 && effective_axes[0].kind == .single {
		if expr := effective_axes[0].start {
			if expr is cx.ProgramBinding && expr.path.len == 0 {
				if v := env.bindings[expr.name] {
					if expanded := slice_value_axes(v, env) {
						effective_axes = expanded.clone()
					}
				}
			}
		}
	}
	items := iterate(receiver)
	if effective_axes.len > 1 {
		return apply_multi_axis(items, effective_axes, mut env)!
	}
	axis := effective_axes[0]
	return apply_one_axis(items, axis, mut env)!
}

// apply_one_axis dispatches a single axis (`.single`, `.range`, or
// `.full`) over the materialised receiver `items`. Pulled out as a
// helper so multi-axis (D12) can recurse over rows.
fn apply_one_axis(items []cx.Node, axis cx.SliceAxis, mut env MatchEnv) !cx.Node {
	match axis.kind {
		.single { return apply_single_index(items, axis, mut env)! }
		.range  { return apply_range_slice(items, axis, mut env)! }
		.full   { return cx.Element{ name: seq_marker_name, items: items } }
	}
}

// is_row_like reports whether a node has nested-iterable shape (i.e.
// whether it can serve as a "row" for the multi-axis recursion). A
// row must be a Sequence / Array / Iterator / `__cx_seq__` envelope
// or a non-scalar Element. Bare scalar nodes are NOT row-like —
// `iterate(scalar)` returns `[scalar]` which would silently degrade
// to a 1-element row.
fn is_row_like(n cx.Node) bool {
	if n is cx.ScalarNode {
		return false
	}
	if n is cx.SequenceNode || n is cx.ArrayNode || n is cx.IteratorNode {
		return true
	}
	if n is cx.Element {
		// `__cx_seq__` envelope is row-like by construction.
		if n.name == seq_marker_name || n.name == '' {
			return true
		}
		// Element with child items is row-like (e.g. matrix rows
		// modelled as `[row 1 2 3]`).
		return n.items.len > 0 || n.attrs.len > 0
	}
	return false
}

// apply_multi_axis evaluates a multi-axis slice access
// D12. Conservative scope at W6-E:
//
//   - The receiver must be a Sequence-of-Sequence (matrix shape) —
//     each top-level item is itself iterable via `iterate()`. Plain
//     Elements with attribute "columns" do NOT satisfy this; column-
//     label D13 selection on attribute-axes is left for a follow-on.
//   - Any number of axes ≥ 2 is admitted by recursion: the first axis
//     selects rows (or one row if `.single`), each surviving row has
//     the remaining axes applied, and the per-row results are wrapped
//     into a fresh `__cx_seq__` envelope to preserve outer shape.
//
// Shape rules (matches numpy/Julia intuition):
//   - `.single` first axis + remaining axes → result has rank one
//     less than the input (the single row's result, NOT a sequence
//     of one).
//   - `.range` or `.full` first axis + remaining axes → result is a
//     sequence whose items each carry the remaining-axes' result for
//     that row.
fn apply_multi_axis(items []cx.Node, axes []cx.SliceAxis, mut env MatchEnv) !cx.Node {
	if axes.len == 0 {
		return cx.Element{ name: seq_marker_name, items: items }
	}
	first := axes[0]
	rest := axes[1..]
	// column-label second axis. When the (single) remaining
	// axis carries STRING-valued bound(s) it selects a named column from
	// each row rather than a positional one. Detect it once here; the
	// per-row dispatch below routes to `apply_col_axis_to_row` instead of
	// the positional `apply_one_axis(iterate(row), …)`. Restricted to the
	// 2-axis `[rows, "label"]` / `[rows, "lo":"hi"]` shape (rest.len == 1).
	col_label_axis := rest.len == 1 && is_col_label_axis(rest[0], mut env)!
	if first.kind == .single {
		// Pick exactly one row, then recurse with the remaining axes.
		row := apply_single_index(items, first, mut env)!
		if !is_row_like(row) {
			return EvalError{
				code:    'cx-err:CXER0100'
				message: 'multi-axis slice: source rank (1) is less than axis arity (${axes.len}) — receiver is a flat sequence'
			}
		}
		if col_label_axis {
			return apply_col_axis_to_row(row, rest[0], mut env)!
		}
		// Map record row (D22): label axes only. The full axis `*`
		// yields the whole row map (`$t[2, *]` ≡ `$t[2]`); a positional
		// axis is the OQ2 rejection (maps have no positional axis).
		if is_map_row(row) {
			if rest.len == 1 && rest[0].kind == .full {
				return row
			}
			return EvalError{
				code:    'cx-err:CXER0100'
				message: 'slice on map requires positional sequence; got map'
			}
		}
		row_items := iterate(row)
		if rest.len == 1 {
			return apply_one_axis(row_items, rest[0], mut env)!
		}
		return apply_multi_axis(row_items, rest, mut env)!
	}
	// Range / full first axis → select rows, map remaining axes over
	// each row, collect results.
	row_set := apply_one_axis(items, first, mut env)!
	rows := iterate(row_set)
	// Empty row set after first-axis selection → empty result. We do
	// NOT raise the rank-mismatch error for legitimately-empty first
	// axes (D20 says out-of-range slices return empty, not error).
	if rows.len > 0 && !col_label_axis {
		// Sample-check the first row to enforce the rank contract.
		// Scalars don't iterate beyond `[scalar]` and would silently
		// degrade — surface CXER0100 instead. Skipped for column-label
		// axes: `apply_col_axis_to_row` raises the D13-specific CXER0100
		// (`column-label slice requires a table or attributed-row source`)
		// for non-column-addressable rows.
		if !is_row_like(rows[0]) {
			return EvalError{
				code:    'cx-err:CXER0100'
				message: 'multi-axis slice: source rank (1) is less than axis arity (${axes.len}) — receiver is a flat sequence'
			}
		}
	}
	mut out := []cx.Node{cap: rows.len}
	for row in rows {
		if col_label_axis {
			out << apply_col_axis_to_row(row, rest[0], mut env)!
			continue
		}
		// Map record rows (D22): same rule as the single-row branch
		// above — `*` keeps the row map, positional axes are rejected.
		if is_map_row(row) {
			if rest.len == 1 && rest[0].kind == .full {
				out << row
				continue
			}
			return EvalError{
				code:    'cx-err:CXER0100'
				message: 'slice on map requires positional sequence; got map'
			}
		}
		row_items := iterate(row)
		mapped := if rest.len == 1 {
			apply_one_axis(row_items, rest[0], mut env)!
		} else {
			apply_multi_axis(row_items, rest, mut env)!
		}
		out << mapped
	}
	return cx.Element{ name: seq_marker_name, items: out }
}

// ── column-label slicing ─────────────────────────────────────
//
// The second axis of a multi-axis slice may carry STRING-valued bounds
// (`$table[*, "name"]`, `$table[2:5, "name":"email"]`) — a *column label*
// rather than a positional index. `is_col_label_axis` reports whether an
// axis's start (and, for ranges, stop) evaluates to a string scalar, so
// `apply_multi_axis` can route it to `apply_col_axis_to_row`.
//
// Column resolution is attribute-first (the W6-F implementation targets
// attributed-row sources, e.g. `[row name="A" email="a@x"]`): a row's
// columns are its attributes in declaration order, and a label selects the
// matching attribute's value. When no attribute matches, child elements
// named by the label are tried. Non-column-addressable rows (flat scalar
// sequences) raise CXER0100.
//
// String-range `"lo":"hi"` resolves both labels to column positions via the
// row's ordered attribute list and slices inclusively between them.
fn is_col_label_axis(axis cx.SliceAxis, mut env MatchEnv) !bool {
	match axis.kind {
		.full {
			return false
		}
		.single {
			start := axis.start or { return false }
			return expr_is_string_scalar(start, mut env)!
		}
		.range {
			// A column-range needs at least one string endpoint to be a
			// label range; require the start to be a string (the parser
			// always emits a start for `"lo":"hi"`).
			start := axis.start or { return false }
			return expr_is_string_scalar(start, mut env)!
		}
	}
}

// expr_is_string_scalar evaluates `expr` and reports whether the result is
// a string scalar. Used purely for axis-shape classification; the value is
// re-evaluated by the column resolver (both calls are pure).
fn expr_is_string_scalar(expr cx.ProgramNode, mut env MatchEnv) !bool {
	v := eval_node(expr, mut env)!
	return scalar_string(v) != none
}

// RowColumn pairs a column label with its value for D13 resolution.
struct RowColumn {
	label string
	value cx.Node
}

// ── table sequence view (D22, #404) ──────────────────────────────
//
// A `:table`-bearing element atomizes to its ROW SEQUENCE wherever a
// surface takes the sequence view of a value (code.md §6.6 D22): [?for]
// generator sources, slice receivers, and the §6.5 sequence built-ins
// all route through `iterate()` / `materialize_to_items()`, which
// expand the TableData payload via `table_row_maps`. Each row is an
// ordered `__cx_map__` — one entry per declared column, in declaration
// order, cells as their typed scalars — the same record shape the
// bindings' Table API and [$csv:parse] produce. CXPath does NOT
// navigate into rows (they are not CXDM children); the read projection
// here changes no construction, serialization, EBV, or equality path.

// table_cell_node lifts one TableCellValue into a cx.Node. Scalar
// variants keep their stored type (an `age::int` cell compares
// numerically with no conversion); collection cells are already
// Node variants and pass through.
fn table_cell_node(c cx.TableCellValue) cx.Node {
	return match c {
		bool         { cx.Node(cx.ScalarNode{ data_type: .bool_type, value: cx.ScalarValue(c) }) }
		i64          { cx.Node(cx.ScalarNode{ data_type: .int_type, value: cx.ScalarValue(c) }) }
		f64          { cx.Node(cx.ScalarNode{ data_type: .float_type, value: cx.ScalarValue(c) }) }
		string       { cx.Node(cx.ScalarNode{ data_type: .string_type, value: cx.ScalarValue(c) }) }
		cx.NullValue { cx.Node(cx.ScalarNode{ data_type: .null_type, value: cx.ScalarValue(c) }) }
		cx.ArrayNode    { cx.Node(c) }
		cx.MapNode      { cx.Node(c) }
		cx.SequenceNode { cx.Node(c) }
	}
}

// table_row_maps materialises a TableData payload as its D22 row
// sequence: one `__cx_map__` element per row, entries in column
// declaration order. A short row (defensive — the parser enforces
// per-row arity) null-pads to the declared column count.
fn table_row_maps(td &cx.TableData) []cx.Node {
	mut out := []cx.Node{cap: td.rows.len}
	for row_idx in 0 .. td.rows.len {
		out << table_row_map_at(td, row_idx)
	}
	return out
}

// table_row_map_at builds ONE row's D22 map view — the per-row unit
// the batch [?for] walk constructs on demand (stream 17 W2, #710
// item 7) instead of paying N(1+2M) boxes up front.
fn table_row_map_at(td &cx.TableData, row_idx int) cx.Node {
	r := td.rows[row_idx]
	mut entries := []cx.Node{cap: td.cols.len}
	for ci, col in td.cols {
		val := if ci < r.len {
			table_cell_node(r[ci])
		} else {
			cx.Node(cx.ScalarNode{ data_type: .null_type, value: cx.ScalarValue(cx.NullValue{}) })
		}
		entries << cx.Element{
			name:  col.name
			items: [val]
		}
	}
	return cx.Node(cx.Element{
		name:  map_marker_name
		items: entries
	})
}

// is_map_row reports whether a multi-axis slice row is a Map record —
// a `__cx_map__` envelope (table/csv row per D22) or a materialised
// `cx.MapNode` (e.g. a [?to-map] result). Map rows are
// column-addressable by LABEL only; a positional second axis is the
// OQ2 rejection (maps have no positional axis).
fn is_map_row(n cx.Node) bool {
	if n is cx.MapNode {
		return true
	}
	return n is cx.Element && (n as cx.Element).name == map_marker_name
}

// row_columns returns a row's ordered (label, value) column list. For an
// attributed-row Element the columns are its attributes in declaration
// order. Returns `none` when the row carries no addressable columns.
fn row_columns(row cx.Node) ?[]RowColumn {
	// Materialised Map row (`cx.MapNode`, e.g. a [?to-map] result):
	// same D13 rule as the `__cx_map__` envelope below — columns are
	// the entries in entry order, label selects the entry's value.
	if row is cx.MapNode {
		mut cols := []RowColumn{cap: row.entries.len}
		for e in row.entries {
			cols << RowColumn{
				label: cx.scalar_value_str_public(e.key_value)
				value: e.value
			}
		}
		return cols
	}
	if row !is cx.Element {
		return none
	}
	el := row as cx.Element
	// Map record row (`__cx_map__` — a D22 table row or a [$csv:parse]
	// row): columns are the entries in entry order, and a label selects
	// the entry's VALUE (the typed cell), not the entry wrapper. An
	// empty map row is column-addressable with zero columns (an unknown
	// single label yields the empty sequence, per D13).
	if el.name == map_marker_name {
		mut cols := []RowColumn{cap: el.items.len}
		for it in el.items {
			if it is cx.Element && it.name != '' {
				val := if it.items.len == 1 {
					it.items[0]
				} else if it.items.len == 0 {
					cx.Node(cx.ScalarNode{ data_type: .null_type, value: cx.ScalarValue(cx.NullValue{}) })
				} else {
					cx.Node(cx.Element{ name: seq_marker_name, items: it.items })
				}
				cols << RowColumn{
					label: it.name
					value: val
				}
			}
		}
		return cols
	}
	if el.attrs.len > 0 {
		mut cols := []RowColumn{cap: el.attrs.len}
		for a in el.attrs {
			dt := match a.value {
				bool { cx.ScalarType.bool_type }
				i64 { cx.ScalarType.int_type }
				f64 { cx.ScalarType.float_type }
				cx.NullValue { cx.ScalarType.null_type }
				string { cx.ScalarType.string_type }
			}
			cols << RowColumn{
				label: a.name
				value: cx.Node(cx.ScalarNode{ data_type: dt, value: a.value })
			}
		}
		return cols
	}
	// No attributes — fall back to named child elements (each child's name
	// is its label; the child element itself is the value).
	if el.items.len > 0 {
		mut cols := []RowColumn{cap: el.items.len}
		for it in el.items {
			if it is cx.Element && it.name != '' {
				cols << RowColumn{
					label: it.name
					value: it
				}
			}
		}
		if cols.len > 0 {
			return cols
		}
	}
	return none
}

// apply_col_axis_to_row resolves a column-label axis (single label or label
// range) against one row. Single-label → the matching column's value.
// Label-range → a `__cx_seq__` of the columns between the two labels
// inclusive, in column order.
fn apply_col_axis_to_row(row cx.Node, axis cx.SliceAxis, mut env MatchEnv) !cx.Node {
	cols := row_columns(row) or {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: 'column-label slice requires a table or attributed-row source'
		}
	}
	if axis.kind == .single {
		start := axis.start or {
			return EvalError{
				code:    'cx-err:CXER0001'
				message: 'column-label slice: missing label expression'
			}
		}
		label := scalar_string(eval_node(start, mut env)!) or {
			return EvalError{
				code:    'cx-err:CXER0001'
				message: 'column-label slice: label must be a string'
			}
		}
		for c in cols {
			if c.label == label {
				return c.value
			}
		}
		// Unknown label → empty (D20-style miss; no such column in row).
		return cx.Element{ name: seq_marker_name, items: []cx.Node{} }
	}
	// Range form: "lo":"hi". Resolve both labels to column positions, then
	// slice inclusively (D5). A missing endpoint label raises CXER0100 —
	// unlike positional ranges, a named bound that doesn't exist is a
	// shape error, not an empty slice.
	lo_expr := axis.start or {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: 'column-label range requires both endpoints'
		}
	}
	hi_expr := axis.stop or {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: 'column-label range requires both endpoints'
		}
	}
	lo := scalar_string(eval_node(lo_expr, mut env)!) or {
		return EvalError{
			code:    'cx-err:CXER0001'
			message: 'column-label range: bounds must be strings'
		}
	}
	hi := scalar_string(eval_node(hi_expr, mut env)!) or {
		return EvalError{
			code:    'cx-err:CXER0001'
			message: 'column-label range: bounds must be strings'
		}
	}
	mut lo_idx := -1
	mut hi_idx := -1
	for i, c in cols {
		if c.label == lo && lo_idx < 0 {
			lo_idx = i
		}
		if c.label == hi {
			hi_idx = i
		}
	}
	if lo_idx < 0 || hi_idx < 0 {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: 'column-label range: unknown column "${if lo_idx < 0 { lo } else { hi }}"'
		}
	}
	if hi_idx < lo_idx {
		// Reversed bounds → empty (D20 direction-mismatch convention).
		return cx.Element{ name: seq_marker_name, items: []cx.Node{} }
	}
	mut out := []cx.Node{cap: hi_idx - lo_idx + 1}
	for i := lo_idx; i <= hi_idx; i++ {
		out << cols[i].value
	}
	return cx.Element{ name: seq_marker_name, items: out }
}

// apply_single_index — `$xs[N]` form. Per the index is
// 1-based; D9 admits negative-from-end. Out-of-range yields the empty
// sequence (D20) rather than an error.
fn apply_single_index(items []cx.Node, axis cx.SliceAxis, mut env MatchEnv) !cx.Node {
	expr := axis.start or {
		return EvalError{
			code:    'cx-err:CXER0001'
			message: 'slice: single-index axis missing start expression'
		}
	}
	idx := eval_slice_index_expr(expr, items.len, mut env)!
	resolved := resolve_index(idx, items.len)
	if resolved < 0 || resolved >= items.len {
		return cx.Element{ name: seq_marker_name, items: []cx.Node{} }
	}
	return items[resolved]
}

// apply_range_slice — `$xs[start:stop]` / `[::step]` / etc. Walks the
// receiver with the requested stride, inclusive of `stop` (D5). When
// step disagrees with start/stop direction the result is empty (D20).
// Step-of-zero raises CXER0100 (D21).
fn apply_range_slice(items []cx.Node, axis cx.SliceAxis, mut env MatchEnv) !cx.Node {
	n := items.len
	// Step first — needed to compute default open-stop value (D5 +
	// negative-stride convention: open stop on a negative stride means
	// "walk to index 0").
	mut step := i64(1)
	if step_expr := axis.step {
		raw := eval_node(step_expr, mut env)!
		step = scalar_int(raw) or {
			return EvalError{
				code:    'cx-err:CXER0001'
				message: 'slice step must be an integer'
			}
		}
		if step == 0 {
			return EvalError{
				code:    'cx-err:CXER0100'
				message: 'slice step cannot be zero'
			}
		}
	}
	// Defaults for open bounds. With step > 0: start=0, stop=n-1.
	// With step < 0: start=n-1, stop=0 (walk backwards from the last
	// element to the first, inclusive at both ends).
	mut start_idx := if step > 0 { 0 } else { n - 1 }
	mut stop_idx := if step > 0 { n - 1 } else { 0 }
	if start_expr := axis.start {
		raw := eval_slice_index_expr(start_expr, n, mut env)!
		start_idx = resolve_index(raw, n)
	}
	if stop_expr := axis.stop {
		raw := eval_slice_index_expr(stop_expr, n, mut env)!
		stop_idx = resolve_index(raw, n)
	}
	// Direction mismatch → empty (D20).
	if step > 0 && stop_idx < start_idx {
		return cx.Element{ name: seq_marker_name, items: []cx.Node{} }
	}
	if step < 0 && stop_idx > start_idx {
		return cx.Element{ name: seq_marker_name, items: []cx.Node{} }
	}
	mut out := []cx.Node{}
	mut i := start_idx
	if step > 0 {
		for i <= stop_idx && i < n {
			if i >= 0 {
				out << items[i]
			}
			i += int(step)
		}
	} else {
		for i >= stop_idx && i >= 0 {
			if i < n {
				out << items[i]
			}
			i += int(step)
		}
	}
	return cx.Element{ name: seq_marker_name, items: out }
}

// resolve_index converts a CX-surface index (1-based, negative-from-end)
// to a 0-based slot into the receiver. Returns a negative value when
// the index is out of range (idx == 0 is invalid under 1-based
// numbering and routed here as a sentinel "miss").
fn resolve_index(idx i64, n int) int {
	if idx > 0 {
		return int(idx - 1)
	}
	if idx < 0 {
		return n + int(idx)
	}
	return -1 // idx == 0 — invalid under 1-based; treat as miss
}

// eval_slice_index_expr evaluates a slice-position expression. The
// reserved `$_last` sigil resolves to the 1-based index
// of the LAST element — `n`, so that `resolve_index($_last, n)` yields
// `n - 1` (the 0-based slot of the last item). All other expressions
// evaluate as ordinary integer expressions.
//
// The implementation installs `_last` as a transient binding in env
// before delegating to the standard evaluator. This lets expressions
// like `[- $_last 1]` (the CX prefix-arithmetic form for `last-1`)
// reuse the existing call machinery without a slice-specific evaluator
// branch.
fn eval_slice_index_expr(expr cx.ProgramNode, n int, mut env MatchEnv) !i64 {
	// Save and install `_last` (1-based: matches D4 — `$_last` is the
	// 1-based last index, i.e. the cardinality of the receiver).
	had_last := '_last' in env.bindings
	saved_last := env.bindings['_last'] or { cx.Node(cx.Element{}) }
	env.cow_bindings()
	env.bindings['_last'] = cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(i64(n))
		data_type: cx.ScalarType.int_type
	})
	defer {
		if had_last {
			env.bindings['_last'] = saved_last
		} else {
			env.bindings.delete('_last')
		}
	}
	v := eval_node(expr, mut env)!
	return scalar_int(v) or {
		return EvalError{
			code:    'cx-err:CXER0001'
			message: 'slice index must be an integer'
		}
	}
}

// FocusedNode is the internal walker tuple — a focus value plus the
// ancestor chain (deepest-last) from the binding's root to that focus.
// `ancestors` has length 0 for the binding's root value, length 1 for
// direct children, etc. Parent-axis (G2) consumes the last element of
// `ancestors`.
struct FocusedNode {
	node      cx.Node
	ancestors []cx.Node
}

// walk_binding_path_seq applies the binding-path steps to a focus
// sequence. Returns a single node when the result is unambiguously
// singular, or a synthetic Element { name: '' } carrying the sequence
// when multi-result steps (descendant, predicates) widen the focus.
// resolve_computed_steps (#925, RULED: PYE-1a/PYE-1b) materializes every
// COMPUTED step name (`$m.$k`, `$x/$k`, `$x//$k`, `$x@$k`) from the
// environment before a walk. Returns the input unchanged (no copy) when no
// step is computed. The rules, refuse-never-invent throughout:
//   - the binding must exist and resolve to a SCALAR (TextNode included);
//     unbound / empty-sequence / node-valued names refuse loudly;
//   - a MEMBER step admits every map-key kind and looks up by the full
//     (kind, image) identity — $k = int 1 finds the int key, never the
//     string '1' (name_kind carries the kind to the walker);
//   - child / descendant / attr step names are element/attribute NAMES:
//     only a string resolution is admissible.
fn resolve_computed_steps(steps []cx.ProgramPathStep, mut env MatchEnv) ![]cx.ProgramPathStep {
	mut needs := false
	for s in steps {
		if s.computed_name != '' {
			needs = true
			break
		}
	}
	if !needs {
		return steps
	}
	mut out := []cx.ProgramPathStep{cap: steps.len}
	for s in steps {
		if s.computed_name == '' {
			out << s
			continue
		}
		v := env.bindings[s.computed_name] or {
			return EvalError{
				code:    'cx-err:CXER0001'
				message: 'computed step name `\$${s.computed_name}` is unbound — a computed step (PYE-1a/1b) resolves from a bound scalar (cx-err:CXER0001)'
			}
		}
		u := meta_unwrap(v)
		if is_empty_seq_node(u) {
			return EvalError{
				code:    'cx-err:CXER0001'
				message: 'computed step name `\$${s.computed_name}` resolved to the empty sequence — refusing to select nothing silently (cx-err:CXER0001)'
			}
		}
		uc := coerce_text_to_scalar(u)
		if uc !is cx.ScalarNode {
			return EvalError{
				code:    'cx-err:CXER0001'
				message: 'computed step name `\$${s.computed_name}` resolved to a non-scalar — a step name is one scalar (cx-err:CXER0001)'
			}
		}
		sn := uc as cx.ScalarNode
		kind := cx.scalar_type_name_public(sn.data_type)
		image := cx.scalar_value_str_public(sn.value)
		if s.kind == .member {
			if kind in ['atom', 'null', 'duration', 'period'] {
				return EvalError{
					code:    'cx-err:CXER0001'
					message: 'computed member key `\$${s.computed_name}` resolved to a ${kind} — not an admissible map-key kind (cxdm §2.6) (cx-err:CXER0001)'
				}
			}
		} else if kind != 'string' {
			return EvalError{
				code:    'cx-err:CXER0001'
				message: 'computed step name `\$${s.computed_name}` resolved to a ${kind} — element/attribute names are strings (cx-err:CXER0001)'
			}
		}
		out << cx.ProgramPathStep{
			kind:       s.kind
			name:       image
			name_kind:  kind
			kind_test:  s.kind_test
			predicates: s.predicates
		}
	}
	return out
}

fn walk_binding_path_seq(root cx.Node, steps_in []cx.ProgramPathStep, mut env MatchEnv, unwrap_terminal bool) !cx.Node {
	steps := resolve_computed_steps(steps_in, mut env)!
	mut focus := [FocusedNode{ node: root, ancestors: []cx.Node{} }]
	// A node-set root (sequence wrapper, name == '' / seq marker — e.g. the
	// result of a `//u` CXPath bound via `[= $u //u]`) is a SET of context
	// nodes: `$u/child` applies the step to each member per XPath / CXPath
	// node-set navigation (§6.2), NOT a lookup for a child named `child` on
	// the wrapper itself. Expand the wrapper into its member nodes so the
	// subsequent step descends into the matched element(s).
	if root is cx.Element {
		if root.name == '' || root.name == seq_marker_name {
			focus = []FocusedNode{}
			for it in root.items {
				focus << FocusedNode{ node: it, ancestors: []cx.Node{} }
			}
		}
	}
	// A transparent DocumentNode root (e.g. the result of `[$cx:parse]`, D7)
	// is the whole-document carrier; its top-level elements are the context
	// node-set, exactly as `--data` binds the parsed root element and as
	// `[?modify $doc //x]` already unwraps it. Without this, `$doc//section` /
	// `$doc/section` over an in-program parse find nothing — the in-program
	// read→CXPath pipeline (codec.md §1 / Cap A) would be unusable.
	if root is cx.DocumentNode {
		focus = []FocusedNode{}
		for it in root.elements {
			focus << FocusedNode{ node: it, ancestors: []cx.Node{} }
		}
	}
	last_idx := steps.len - 1
	// terminal labeled-field unwrap applies only to a "pure
	// child chain": every step is a plain `/name` child step with no
	// predicate (a simple field accessor like `$r/value`, NOT a CXPath
	// node-set query such as `$doc/user[@active=true]/name`, which must
	// return elements). Predicate / descendant / wildcard / parent steps
	// disqualify the whole path.
	pure_child_chain := unwrap_terminal && steps.all(it.kind == .child && it.predicates.len == 0)
	mut terminal_attr_step := ?cx.ProgramPathStep(none)
	for i, step in steps {
		// Defer the terminal attribute step: when the final step is
		// an attribute axis (`/@name`), materialize each focus's
		// attributes as synthetic `[name "value"]` Elements (matching
		// `eval_path_expr`'s attribute-axis terminal convention).
		// Without this deferral, walk_path_step would convert each
		// focus to a raw ScalarNode at the first focus and lose the
		// per-focus iteration shape.
		if i == last_idx && step.kind == .attr && step.predicates.len == 0 {
			terminal_attr_step = step
			break
		}
		if step.kind == .parent {
			focus = apply_parent_step(focus, env)
		} else {
			focus = apply_binding_step(focus, step, i == last_idx && pure_child_chain)!
		}
		if step.predicates.len > 0 {
			focus = apply_step_predicates(focus, step.predicates, mut env)!
		}
	}
	if t := terminal_attr_step {
		// Materialize attribute axis: each focus contributes its
		// matching attribute as a `[name "value"]` synthetic
		// Element. Empty result when no focus has a matching attr.
		mut items := []cx.Node{}
		for f in focus {
			mut fattrs := []cx.Attribute{}
			if f.node is cx.Element {
				fattrs = (f.node as cx.Element).attrs.clone()
			} else if f.node is cx.EvalDirectiveNode {
				// #436: directive-as-data attributes materialize like
				// element attributes.
				fattrs = (f.node as cx.EvalDirectiveNode).attrs.clone()
			}
			for a in fattrs {
				if a.name == t.name {
					items << cx.Node(cx.Element{
						name:  a.name
						items: [cx.Node(attr_scalar_node(a))]
					})
				}
			}
		}
		// Terminal-attribute unwrap (§6.2): a *simple field accessor* —
		// a pure `/name` child-chain prefix (no predicates) resolving to a
		// single focus with a single matching attribute — yields the
		// attribute's typed value scalar (cxdm.md §2.4), per the `$x@attr`
		// table entry. This mirrors the terminal
		// labeled-field unwrap for child steps. Node-set queries (any
		// predicate step, or multiple matching foci such as
		// `$doc/item/@q`) keep the per-attribute `[name "value"]`
		// materialization.
		prefix_pure_child := steps[..last_idx].all(it.kind == .child && it.predicates.len == 0)
		if prefix_pure_child && focus.len == 1 && items.len == 1 {
			attr_el := items[0] as cx.Element
			return attr_el.items[0]
		}
		return cx.Element{ name: '', items: items }
	}
	// Materialize the focus list to a CXDM result.
	if focus.len == 0 {
		return cx.Element{ name: '' }
	}
	// A node-set query — any predicate step, or a descendant / wildcard /
	// parent axis (code.md §6.2) — yields a SEQUENCE regardless of match
	// cardinality: a single match keeps the sequence wrapper so `[$count]`
	// / `[$empty]` see one item rather than the matched element's own
	// arity (container count). Plain child/attr/member chains keep the
	// single-node field-read semantics per the §6.2 table.
	mut node_set_query := false
	for step in steps {
		if step.predicates.len > 0 {
			node_set_query = true
			break
		}
		// A [131b] kind test is a node-set test like `*` — it admits
		// every child of a kind, so its result keeps the sequence
		// wrapper even at cardinality one.
		if step.kind_test != .none {
			node_set_query = true
			break
		}
		match step.kind {
			.descendant, .descendant_wildcard, .wildcard_children, .parent {
				node_set_query = true
				break
			}
			else {}
		}
	}
	if focus.len == 1 && !node_set_query {
		return focus[0].node
	}
	mut items := []cx.Node{}
	for f in focus {
		items << f.node
	}
	return cx.Element{ name: '', items: items }
}

// apply_binding_step expands the focus list under one step's kind.
// Single-result step kinds (child/attr/member/wildcard_children on
// each focus) preserve focus shape; descendant/descendant_wildcard
// widen each focus to its full subtree; parent consumes the last
// ancestor of each focus.
fn apply_binding_step(focus []FocusedNode, step cx.ProgramPathStep, terminal_field bool) ![]FocusedNode {
	mut out := []FocusedNode{}
	// [131b] kind test in binding-step NodeTest position (`$x/node()`,
	// `$x//text()`). It selects by node KIND, so it bypasses the
	// name-test machinery entirely (labeled-slot fallback, terminal
	// field unwrap) — those exist to resolve a NAME, and a kind test has
	// none. `step.kind` still supplies the axis.
	if step.kind_test != .none {
		for f in focus {
			match step.kind {
				.descendant {
					collect_descendant_kind_focus(f.node, f.ancestors.clone(),
						step.kind_test, mut out)
				}
				else {
					// Child axis. `attribute()` selects nothing here: an
					// element's items hold no attribute nodes (see
					// kind_test_matches).
					items := binding_container_items(f.node) or { continue }
					for c in items {
						if kind_test_matches(step.kind_test, c) {
							mut anc := f.ancestors.clone()
							anc << f.node
							out << FocusedNode{ node: c, ancestors: anc }
						}
					}
				}
			}
		}
		return out
	}
	match step.kind {
		.child, .attr, .member, .wildcard_children {
			for f in focus {
				match step.kind {
					.child {
						// In sequence-walker semantics (slow path),
						// `/name` is "every direct child element whose
						// name is `name`" — distinct from the fast-path
						// walker's first-match return. This is required
						// so trailing predicates filter the full
						// candidate set per XPath 3.1.
						//
						// Labeled-slot fallback mirrors the fast-path
						// walker (`walk_path_step .child`): when no
						// bare-named child matches but a `__cx_slot:NAME`
						// child exists, expose its inner value (the same
						// unwrap rules as the fast path). Keeps
						// `$request/body` / `$c | post(...)` slot-shaped
						// access working when `.child` routes through
						// the slow path (now the default for child steps
						// per multi-match fix).
						parent_node := f.node
						mut has_container := false
						mut el := cx.Element{}
						if parent_node is cx.Element {
							el = parent_node as cx.Element
							has_container = true
						} else if parent_node is cx.EvalDirectiveNode {
							// #436: child steps descend through a
							// directive-as-data node via its Element view.
							el = eval_directive_view(parent_node as cx.EvalDirectiveNode)
							has_container = true
						} else if parent_node is cx.MapNode {
							// #618: parsed maps walk through their marker view.
							el = map_node_view(parent_node as cx.MapNode)
							has_container = true
						}
						if has_container {
							mut matched := []cx.Node{}
							for c in el.items {
								if c is cx.Element && (c as cx.Element).name == step.name {
									matched << c
								}
							}
							if matched.len > 0 {
								// terminal labeled-field unwrap.
								// When the FINAL path step selects exactly one
								// plain child holding a single item, expose that
								// item directly so `$r/value` reads the value
								// (mirroring the legacy slot-fallback unwrap).
								// Non-terminal steps keep the element for further
								// descent; multi-match keeps every element for
								// XPath node-set / predicate semantics.
								unwrap := terminal_field && focus.len == 1
									&& matched.len == 1
									&& (matched[0] as cx.Element).items.len == 1
								if unwrap {
									mut anc := f.ancestors.clone()
									anc << parent_node
									out << FocusedNode{
										node:      (matched[0] as cx.Element).items[0]
										ancestors: anc
									}
								} else {
									for m in matched {
										mut anc := f.ancestors.clone()
										anc << parent_node
										out << FocusedNode{ node: m, ancestors: anc }
									}
								}
							} else {
								slot_name := '${slot_child_prefix}${step.name}'
								for c in el.items {
									if c is cx.Element && c.name == slot_name {
										mut anc := f.ancestors.clone()
										anc << parent_node
										// Mirror fast-path unwrap rules.
										if c.items.len == 1 {
											inner := c.items[0]
											if inner is cx.Element
											   && inner.name.starts_with(slot_child_prefix) {
												out << FocusedNode{
													node:      cx.Element{ name: '', items: c.items }
													ancestors: anc
												}
											} else {
												out << FocusedNode{ node: inner, ancestors: anc }
											}
										} else {
											out << FocusedNode{
												node:      cx.Element{ name: '', items: c.items }
												ancestors: anc
											}
										}
										break
									}
								}
							}
						}
					}
					.attr {
						// Attribute step is single-valued — at most
						// one match per focus element. Reuse the
						// fast-path walker for behaviour parity
						// (handles labeled-slot attribute fallback,
						// etc.).
						next := walk_path_step(f.node, step) or { continue }
						mut anc := f.ancestors.clone()
						anc << f.node
						out << FocusedNode{ node: next, ancestors: anc }
					}
					.member {
						next := walk_path_step(f.node, step) or { continue }
						mut anc := f.ancestors.clone()
						anc << f.node
						out << FocusedNode{ node: next, ancestors: anc }
					}
					.wildcard_children {
						parent_node := f.node
						mut has_container := false
						mut el := cx.Element{}
						if parent_node is cx.Element {
							el = parent_node as cx.Element
							has_container = true
						} else if parent_node is cx.EvalDirectiveNode {
							// #436: `/*` descends through a directive-as-data
							// node via its Element view.
							el = eval_directive_view(parent_node as cx.EvalDirectiveNode)
							has_container = true
						} else if parent_node is cx.MapNode {
							// #618 parity with the `.child` arm: a parsed map
							// focus exposes its entries through the marker view
							// for `/*` exactly as it does for `/name`.
							el = map_node_view(parent_node as cx.MapNode)
							has_container = true
						}
						if has_container {
							for c in el.items {
								if c is cx.Element {
									mut anc := f.ancestors.clone()
									anc << parent_node
									out << FocusedNode{ node: c, ancestors: anc }
								} else if c is cx.SequenceNode {
									// #847: a PARSED paren-sequence body arrives as a
									// bare SequenceNode where the runtime lane carries
									// the __cx_seq__ marker element — which `*` matches
									// as ONE child. Two $cx:equal values must navigate
									// identically on EVERY axis (#587 fixed `//`; this
									// is the residual `*` case), so the wildcard matches
									// the collection through its marker VIEW: same count,
									// and downstream steps see the marker topology the
									// runtime lane already has.
									mut anc := f.ancestors.clone()
									anc << parent_node
									out << FocusedNode{
										node:      cx.Node(cx.Element{ name: seq_marker_name, items: c.items })
										ancestors: anc
									}
								} else if c is cx.ArrayNode {
									// #847: the __cx_arr__ twin, same fidelity.
									mut anc := f.ancestors.clone()
									anc << parent_node
									out << FocusedNode{
										node:      cx.Node(cx.Element{ name: arr_marker_name, items: c.items })
										ancestors: anc
									}
								} else if c is cx.MapNode {
									// #847/#618: parsed map child through its marker view.
									mut anc := f.ancestors.clone()
									anc << parent_node
									out << FocusedNode{
										node:      cx.Node(map_node_view(c))
										ancestors: anc
									}
								}
							}
						}
					}
					else {}
				}
			}
		}
		.descendant, .descendant_wildcard {
			// Descendant axis: every Element at any depth in the
			// focus's subtree whose name matches the step's
			// NodeTest. The focus itself is included only if it
			// matches (descendant-or-self semantics).
			target := step.name // '*' for descendant_wildcard
			for f in focus {
				collect_descendant_focus(f.node, f.ancestors.clone(), target, mut out)
			}
		}
		.parent {
			// Parent axis (G2) — handled in
			// walk_binding_path_seq.apply_parent_step which has env
			// access for the $doc-scan fallback. apply_binding_step is
			// never called with a parent-kind step.
			return EvalError{
				code:    'cx-err:CXER0001'
				message: 'internal: parent step routed through apply_binding_step; should be apply_parent_step'
			}
		}
	}
	return out
}

// apply_parent_step handles the `/..` step (G2). Resolution
// order for each focus:
//   1. Use the last entry of focus.ancestors when present (walked
//      down through descendant/child/wildcard_children steps in this
//      walk).
//   2. Otherwise scan $doc / $input (whichever is bound) for the
//      Element whose items contain the focus. This recovers the
//      parent for foci bound by `[?for]` / `[?let]` over a detached
//      sub-element (the common pattern `[?for $u :in $doc/user
//      :yield $u/..]`).
//   3. Drop the focus (XPath root-parent-is-empty rule per
fn apply_parent_step(focus []FocusedNode, env MatchEnv) []FocusedNode {
	mut out := []FocusedNode{}
	for f in focus {
		if f.ancestors.len > 0 {
			parent := f.ancestors[f.ancestors.len - 1]
			mut anc := f.ancestors[..f.ancestors.len - 1].clone()
			out << FocusedNode{ node: parent, ancestors: anc }
			continue
		}
		// Doc-scan fallback. Check $doc first, then $input. The scan
		// returns the parent Element AND its own ancestor chain (so
		// further `/..` steps continue to work).
		mut root := cx.Node(cx.Element{})
		mut have_root := false
		if d := env.bindings['doc'] {
			root = d
			have_root = true
		} else if i := env.bindings['input'] {
			root = i
			have_root = true
		}
		if !have_root {
			continue
		}
		if found := find_parent_in_tree(root, f.node, []cx.Node{}) {
			out << found
		}
		// else: focus is the root or not present in $doc — drop.
	}
	return out
}

// find_parent_in_tree returns the FocusedNode (parent + ancestor chain)
// of `target` within `tree`, or none. Identity is structural: a node
// in `tree.items` is considered the target when its source structure
// matches the target's. CXDM elements are value-typed so we use a
// shallow shape comparison (`elements_structurally_equal`).
fn find_parent_in_tree(tree cx.Node, target cx.Node, ancestors []cx.Node) ?FocusedNode {
	if tree !is cx.Element {
		return none
	}
	el := tree as cx.Element
	for c in el.items {
		if c !is cx.Element {
			continue
		}
		if structurally_same_element(c, target) {
			return FocusedNode{ node: tree, ancestors: ancestors.clone() }
		}
		mut child_anc := ancestors.clone()
		child_anc << tree
		if found := find_parent_in_tree(c, target, child_anc) {
			return found
		}
	}
	return none
}

// structurally_same_element compares two CXDM nodes shape-wise for the
// parent-search path-walk fallback. Both arguments must be Elements;
// returns false otherwise.
fn structurally_same_element(a cx.Node, b cx.Node) bool {
	if a !is cx.Element { return false }
	if b !is cx.Element { return false }
	ae := a as cx.Element
	be := b as cx.Element
	if ae.name != be.name { return false }
	if ae.attrs.len != be.attrs.len { return false }
	if ae.items.len != be.items.len { return false }
	for i, at in ae.attrs {
		bt := be.attrs[i]
		if at.name != bt.name { return false }
		av := cx.scalar_value_str_public(at.value)
		bv := cx.scalar_value_str_public(bt.value)
		if av != bv { return false }
	}
	return true
}

// map_node_view is a MapNode's __cx_map__-marker Element view (#618): the
// exact topology runtime map literals evaluate to, so every path walker
// sees ONE map representation regardless of which lane produced the value.
fn map_node_view(m cx.MapNode) cx.Element {
	mut items := []cx.Node{cap: m.entries.len}
	for e in m.entries {
		// #925/#927: the view STAMPS each key's kind (and MSS-4 decl kind)
		// — without the stamp a data-lane STRING key '1' viewed as an
		// unstamped entry whose image auto-types INT, flipping its identity
		// across the view seam.
		mut meta := &cx.ElementMeta{
			key_kind: ?string(cx.scalar_type_name_public(e.key_type))
		}
		if e.decl_kind != '' {
			meta.decl_kind = ?string(e.decl_kind)
		}
		items << cx.Node(cx.Element{
			name:  cx.scalar_value_str_public(e.key_value)
			meta:  meta
			items: [e.value]
		})
	}
	return cx.Element{
		name:  map_marker_name
		items: items
	}
}

// collect_descendant_focus walks the focus's subtree appending each
// Element (in document order) whose name matches `target`. Ancestors
// are extended as the walk descends; non-element children are walked
// through but never emitted (CXPath element NodeTest semantics).
fn collect_descendant_focus(n cx.Node, ancestors []cx.Node, target string, mut out []FocusedNode) {
	if n is cx.Element {
		el := n as cx.Element
		// Self-or-descendant: include n itself if it matches the
		// target. The wildcard target '*' matches every element.
		if target == '*' || el.name == target {
			out << FocusedNode{ node: n, ancestors: ancestors.clone() }
		}
		mut child_anc := ancestors.clone()
		child_anc << n
		for child in el.items {
			collect_descendant_focus(child, child_anc, target, mut out)
		}
	} else if n is cx.EvalDirectiveNode {
		// #436: a directive-as-data node is not an element — an element
		// NodeTest never matches it — but the descendant axis walks
		// THROUGH it into its body items.
		mut child_anc := ancestors.clone()
		child_anc << n
		for child in n.items {
			collect_descendant_focus(child, child_anc, target, mut out)
		}
	} else if n is cx.SequenceNode {
		// #587: a PARSED paren-sequence body arrives as a bare SequenceNode
		// where the runtime lane carries the __cx_seq__ marker element. Two
		// $cx:equal values must navigate identically, so the walker sees the
		// SAME topology: wrap and recurse exactly as the marker would walk.
		collect_descendant_focus(cx.Node(cx.Element{ name: seq_marker_name, items: n.items }),
			ancestors, target, mut out)
	} else if n is cx.ArrayNode {
		// same fidelity for array-valued bodies (the __cx_arr__ twin).
		collect_descendant_focus(cx.Node(cx.Element{ name: arr_marker_name, items: n.items }),
			ancestors, target, mut out)
	} else if n is cx.MapNode {
		// #618: parsed maps walk through the marker view (same fidelity).
		collect_descendant_focus(cx.Node(map_node_view(n)), ancestors, target, mut out)
	}
}

// binding_container_items returns the child items a binding step walks
// for a focus node — the same container views the name-test arms use
// (element body, a directive-as-data node's body per #436, a parsed
// map's marker view per #618). None for a leaf, which has no children.
fn binding_container_items(n cx.Node) ?[]cx.Node {
	if n is cx.Element {
		return n.items
	}
	if n is cx.EvalDirectiveNode {
		return eval_directive_view(n).items
	}
	if n is cx.MapNode {
		return map_node_view(n).items
	}
	if n is cx.SequenceNode {
		return n.items
	}
	if n is cx.ArrayNode {
		return n.items
	}
	return none
}

// collect_descendant_kind_focus is collect_descendant_focus's kind-test
// twin: descendant-or-self over the subtree, keeping every node whose
// KIND the test admits rather than every element whose NAME matches. The
// two share the same topology rules (walk through directive / sequence /
// array / map bodies via their marker views) so `$x//node()` and
// `$x//name` traverse identically.
fn collect_descendant_kind_focus(n cx.Node, ancestors []cx.Node, kt cx.ProgramPathKindTest,
                                 mut out []FocusedNode) {
	// Collection bodies are tested and walked through their MARKER views,
	// exactly as the rooted walker indexes them (#587 / #618) — so the
	// substitution happens before the test, never in addition to it.
	view := if n is cx.SequenceNode {
		cx.Node(cx.Element{ name: seq_marker_name, items: n.items })
	} else if n is cx.ArrayNode {
		cx.Node(cx.Element{ name: arr_marker_name, items: n.items })
	} else if n is cx.MapNode {
		cx.Node(map_node_view(n))
	} else {
		n
	}
	if kind_test_matches(kt, view) {
		out << FocusedNode{ node: view, ancestors: ancestors.clone() }
	}
	items := binding_container_items(view) or { return }
	mut child_anc := ancestors.clone()
	child_anc << view
	for child in items {
		collect_descendant_kind_focus(child, child_anc, kt, mut out)
	}
}

// program_node_impure_callee returns the name of the first known-impure
// builtin/stdlib primitive *called* within a predicate-body AST, or none
// if the body is pure. Used to enforce CXER0230 (predicate-not-pure).
// Only call nodes matter; bindings/literals are inert. Recurses into call
// arguments so `contains(now(), …)` surfaces the inner `now`.
fn program_node_impure_callee(n cx.ProgramNode) ?string {
	if n is cx.ProgramCall {
		if builtin_is_impure(n.name) {
			return n.name
		}
		for a in n.args {
			if c := program_node_impure_callee(a) {
				return c
			}
		}
	}
	return none
}

// apply_step_predicates filters the focus list through each predicate
// left-to-right. Predicate kinds:
//   - .position  : keep the candidate at the 1-based index
//   - .attr_test : keep when match_attr returns true on the focus element
//   - .expr      : bind $_/$_position/$_last; evaluate body; EBV-coerce
fn apply_step_predicates(focus []FocusedNode, preds []cx.ProgramPathPredicate, mut env MatchEnv) ![]FocusedNode {
	mut current := focus.clone()
	for pred in preds {
		mut next := []FocusedNode{}
		match pred.kind {
			.position {
				idx := int(pred.int_index)
				if idx >= 1 && idx <= current.len {
					next << current[idx - 1]
				}
			}
			.attr_test {
				ap := cx.ProgramPatternAttr{
					kind:      pred.attr_kind
					name:      pred.attr_name
					op:        pred.attr_op
					value:     pred.attr_value
					type_name: pred.type_name
				}
				for f in current {
					if f.node is cx.Element {
						if match_attr(ap, f.node as cx.Element, mut env) {
							next << f
						}
					}
				}
			}
			.expr {
				body := pred.body or {
					return EvalError{
						code:    'cx-err:CXER0001'
						message: 'predicate body missing in .expr kind'
					}
				}
				// Static purity (§6.5.x): a path predicate calling a
				// known-impure builtin/primitive (e.g. `now()`) is rejected
				// with CXER0230 — predicate bodies MUST be pure.
				if callee := program_node_impure_callee(body) {
					return EvalError{
						code:    'cx-err:CXER0230'
						message: 'cx-err:CXER0230 E_PREDICATE_NOT_PURE: predicate calls impure `${callee}`'
					}
				}
				total := current.len
				// Detect the __pred_last sugar marker (last() →
				// $_position = $_last). When seen, keep only the
				// final candidate.
				if body is cx.ProgramCall && (body as cx.ProgramCall).name == '__pred_last' {
					if total >= 1 {
						next << current[total - 1]
					}
				} else {
					for i, f in current {
						saved_underscore := env.bindings['_'] or { cx.Node(cx.Element{}) }
						had_underscore := '_' in env.bindings
						saved_pos := env.bindings['_position'] or { cx.Node(cx.Element{}) }
						had_pos := '_position' in env.bindings
						saved_last := env.bindings['_last'] or { cx.Node(cx.Element{}) }
						had_last := '_last' in env.bindings
						env.cow_bindings()
						env.bindings['_'] = f.node
						env.bindings['_position'] = cx.Node(cx.ScalarNode{
							value:     cx.ScalarValue(i64(i + 1))
							data_type: cx.ScalarType.int_type
						})
						env.bindings['_last'] = cx.Node(cx.ScalarNode{
							value:     cx.ScalarValue(i64(total))
							data_type: cx.ScalarType.int_type
						})
						result := eval_node(body, mut env) or {
							// Restore bindings on error before propagating
							if had_underscore { env.bindings['_'] = saved_underscore } else { env.bindings.delete('_') }
							if had_pos { env.bindings['_position'] = saved_pos } else { env.bindings.delete('_position') }
							if had_last { env.bindings['_last'] = saved_last } else { env.bindings.delete('_last') }
							return err
						}
						// Restore bindings
						if had_underscore { env.bindings['_'] = saved_underscore } else { env.bindings.delete('_') }
						if had_pos { env.bindings['_position'] = saved_pos } else { env.bindings.delete('_position') }
						if had_last { env.bindings['_last'] = saved_last } else { env.bindings.delete('_last') }
						ebv := node_ebv(result) or { return iterator_ebv_eval_error() }
						if ebv {
							next << f
						}
					}
				}
			}
		}
		current = next.clone()
	}
	return current
}

// node_ebv computes the Effective Boolean Value of a CXDM node per
// (the EBV table in spec/cxpath.md §5.3). Implements only
// the kinds reachable from predicate body evaluation currently; future
// kinds (date, datetime, bytes, atom-with-payload) extend this table.
// node_ebv is THE Effective Boolean Value fn — the single truthiness
// authority for every boolean position (bare `not/and/or` dispatch,
// `$`-head logical builtins, `[?if]`, `[?match]`/`[?for]` guards, filter
// and CXPath predicates). #383 owner ruling 2026-07-13: the cxdm.md EBV
// table wins wholesale — a present named element is truthy by presence
// (node rule), a singleton sequence wrapper recurses into its item, and
// containers stay empty-is-falsy. The former second site (`scalar_bool`,
// which read elements as "no items and no attrs → false" and wrappers as
// "non-empty → true") is gone, so bare and `$`-head forms agree by
// construction.
// It is FALLIBLE for exactly one kind: an Iterator in a boolean position
// raises (#388 owner ruling 2026-07-13) — EBV never forces a lazy stream
// (network-backed kinds would block on accept or consume frames inside a
// condition; combinator kinds run user closures per pull), so the caller
// converts the V error to the catchable CXER0100 err VALUE via
// iterator_ebv_err() and short-circuits, same posture as an err-valued
// condition (§9.2).
fn node_ebv(n_in cx.Node) !bool {
	// D5: truthiness reads through a `[?meta]` wrapper.
	n := meta_unwrap(n_in)
	// The absence channel is the empty sequence — EBV false (cxdm.md §6
	// rule 1). Checked before the Element arm because absence carrying the
	// `__cx_seq__` marker spelling would otherwise read as a present named
	// element, i.e. truthy — #384: `//pair[$_@score]` kept attr-less pairs.
	if is_absence_node(n) {
		return false
	}
	if n is cx.ScalarNode {
		v := n.value
		if v is bool { return v }
		if v is i64 { return v != 0 }
		if v is f64 { return v != 0.0 && !(v != v) }
		if v is string {
			// I1 stream 11 (2b): decimal/bigint are NUMERIC — zero is falsy
			// (a bare `0.0` is a decimal now; the string arm read it truthy).
			if n.data_type == cx.ScalarType.decimal_type
				|| n.data_type == cx.ScalarType.bigint_type {
				return cx.cx_exact_num_cmp(v, '0') != 0
			}
			return v.len > 0
		}
		if v is cx.NullValue { return false }
		return true
	}
	if n is cx.Element {
		// Synthetic sequence-wrapper (bare or seq-marker spelling) — empty
		// is falsy, a singleton recurses on the wrapped item (cxdm rules
		// 2/6: wrapping a value in a `(…)` singleton never changes its
		// truth), longer sequences are truthy.
		if n.name == '' || n.name == seq_marker_name {
			if n.items.len == 0 { return false }
			if n.items.len == 1 { return node_ebv(n.items[0])! }
			return true
		}
		// Array / Map markers keep the container convention: truthy iff
		// non-empty. (Without these arms the named-element presence rule
		// below would make `[]` / `{}` truthy.)
		if n.name == arr_marker_name || n.name == map_marker_name {
			return n.items.len > 0
		}
		// A [similar …] comparison report (the `~` operator's result) is
		// truthy iff band=:match — similar.md §2.1: "in a boolean position
		// a result reads truthy iff band=:match". A report with no band
		// (predicate built without a decide policy) is falsy.
		if n.name == similar_report_name {
			return similar_report_band(n) == 'match'
		}
		// A present, named element is truthy regardless of contents —
		// presence, not emptiness (#383; keeps `[?if //flag]` existence
		// tests true for empty marker elements).
		return true
	}
	// First-class container value kinds mirror the marker-element arms.
	if n is cx.SequenceNode {
		if n.items.len == 0 { return false }
		if n.items.len == 1 { return node_ebv(n.items[0])! }
		return true
	}
	if n is cx.ArrayNode { return n.items.len > 0 }
	if n is cx.MapNode { return n.entries.len > 0 }
	// An Iterator has NO EBV (#388): a lazy stream may be unbounded or
	// effectful, and EBV must never force one. Raise; every boolean-
	// position caller converts this to the catchable CXER0100 err value.
	if n is cx.IteratorNode {
		return error('iterator has no EBV')
	}
	// Every remaining kind is a present node (text / comment / PI /
	// directive / opaque) — truthy by presence, cxdm's node rule.
	return true
}

// The #388 boolean-position message, shared by both error channels. Same
// CXER0100 family as the materialize-without-bound raise — both are
// forcing-boundary misuses of a lazy stream.
const iterator_ebv_msg = 'an Iterator in a boolean position has no EBV — a lazy stream may be unbounded or effectful (net/sse); force it explicitly ([take N ...], [\$count ...], a [?for] bound) and test the realized value'

// iterator_ebv_err is the catchable err VALUE a boolean position returns
// when its condition is an Iterator (#388 owner ruling) — used where the
// context yields a cx.Node result (flows per §9.2, [?fallback]-catchable).
fn iterator_ebv_err() cx.Node {
	return mk_err('cx-err:CXER0100', iterator_ebv_msg)
}

// iterator_ebv_eval_error is the hard-channel flavor for contexts that
// propagate V errors (predicate walks and other non-Node returns).
// [?fallback] converts it back to the same-code err value, so it stays
// catchable.
fn iterator_ebv_eval_error() EvalError {
	return EvalError{ code: 'cx-err:CXER0100', message: iterator_ebv_msg }
}

fn walk_path_step(val cx.Node, step cx.ProgramPathStep) !cx.Node {
	// #436: a directive-as-data value (EvalDirectiveNode from `[$cx:parse]`)
	// is walked through its Element view — same attrs/items, so `/child`,
	// `/@attr`, `.member` and `/*` descend into the directive's body exactly
	// as they do for an element.
	if val is cx.EvalDirectiveNode {
		return walk_path_step(cx.Node(eval_directive_view(val)), step)!
	}
	// #618: a PARSED map (cx.MapNode from $cx:parse / store reads / journal
	// replay) walks through its __cx_map__-marker Element view — the SAME
	// topology runtime maps carry, so $m/key and $m.key read identically on
	// both lanes (the #587 equal-values-navigate-identically invariant,
	// extended to maps).
	if val is cx.MapNode {
		return walk_path_step(cx.Node(map_node_view(val)), step)!
	}
	// O4 (spec/code.md §6.2): a `/child`, `/@attr`, or `.member` read step
	// applied to a Sequence / Array DISTRIBUTES over the items, mapping the
	// step across each and collecting the results into a Sequence. Items
	// that are non-elements, or where the step does not resolve, are
	// SKIPPED (not an error); empty in → empty out. This is the
	// optional-read projection the SAP pins (missing/non-element skipped).
	if val is cx.Element && (val.name == seq_marker_name || val.name == arr_marker_name) {
		if step.kind == .attr || step.kind == .child || step.kind == .member {
			mut projected := []cx.Node{}
			for item in val.items {
				r := walk_path_step(item, step) or { continue }
				// Optional-read skip: a member where the step resolves to
				// ABSENCE contributes nothing (O4 row 3 — "no [err], no
				// null stand-in"), same as the error-skip above.
				if is_absence_node(r) {
					continue
				}
				projected << r
			}
			return cx.Element{ name: seq_marker_name, items: projected }
		}
	}
	match step.kind {
		.child {
			// Find a child element with the matching name. Two shapes:
			//   1. bare child  [parent [name body]]
			//   2. labeled slot [parent :name body]  → stored as
			//      `__cx_slot:name` per the slot_child_prefix
			//      convention; the walker unwraps the wrapper so
			//      `$x/name` returns the inner body either way (matches
			//      §6.2 path semantics + §10.3 `$request/body`).
			// Single-scalar singletons are auto-unwrapped so labeled
			// values render inline (`:id "7"` rather than `:id [id "7"]`).
			if val is cx.Element {
				for c in val.items {
					if c is cx.Element && c.name == step.name {
						return c
					}
				}
				// Labeled-slot fallback. Children built from
				// `[name :label value]` literals (e.g. §10.3 `$request`,
				// §6.4 pipe stages) live under `__cx_slot:LABEL`. The
				// wrapper element only exists for shape preservation; the
				// path semantics walk through it so `$x/label` returns
				// the inner value directly.
				//
				// Two unwrap cases per the §6.2 path semantics:
				//   - items.len == 1 + items[0] is bare element/scalar →
				//     unwrap to the inner value (terminal-step ergonomics:
				//     `$req/body` reads as the body element/scalar).
				//   - items.len > 1 OR items[0] is itself slot-prefixed
				//     (composite container like path-params) → return a
				//     synthetic naked element so the next `/` step can
				//     descend into the labeled children.
				slot_name := '${slot_child_prefix}${step.name}'
				for c in val.items {
					if c is cx.Element && c.name == slot_name {
						if c.items.len == 1 {
							inner := c.items[0]
							if inner is cx.Element
							   && inner.name.starts_with(slot_child_prefix) {
								return cx.Element{ name: '', items: c.items }
							}
							return inner
						}
						return cx.Element{ name: '', items: c.items }
					}
				}
				return EvalError{
					code:    'cx-err:CXER0001'
					message: 'no child element "${step.name}" on path'
				}
			}
			return EvalError{
				code:    'cx-err:CXER0001'
				message: 'child path step on non-element value'
			}
		}
		.attr {
			if val is cx.Element {
				// 1. Real attributes
				for a in val.attrs {
					if a.name == step.name {
						return attr_scalar_node(a)
					}
				}
				// 2. Labeled-slot children — produced by [name :label
				//    value] literals; path semantics treats them as
				//    accessible via the @ sigil because the spec example
				//    bodies use :code, :message etc. as attribute-like
				//    slots (spec/code.md §9.5 err shapes + §10 directive
				//    response shapes).
				slot_name := '${slot_child_prefix}${step.name}'
				for c in val.items {
					if c is cx.Element && c.name == slot_name {
						if c.items.len > 0 {
							return c.items[0]
						}
					}
				}
				// Railway (§9.2): a read THROUGH an [err] value propagates
				// the err — `$ct@tag` on `[err code=…]` yields the err
				// itself, never absence. Present err attrs (`$e@code`)
				// were already served by the loop above.
				if is_err_value(cx.Node(val)) {
					return cx.Node(val)
				}
				// Missing attribute → ABSENCE, never an error: `/@x` is an
				// optional read per code.md §6.2 O4 ("absence-yielding,
				// never crashing"), on a single element exactly as on a
				// sequence. Comparisons treat absence as never-satisfied
				// (eval_operator_element absence guard); EBV(()) is false.
				return cx.Element{ name: seq_marker_name }
			}
			return EvalError{
				code:    'cx-err:CXER0001'
				message: 'attribute path step on non-element value'
			}
		}
		.member {
			// Map-key access: look up by element name inside a
			// synthetic-map element body or generic element body.
			// #925 (RULED: PYE-1a): a RESOLVED computed step carries
			// name_kind and looks up by the full (kind, image) key identity
			// — `$m.$k` with $k = int 1 finds the int key `1`, never the
			// string key '1' (cxdm §2.6; the literal `.name` surface is
			// string-only by its grammar and keeps the image match).
			if val is cx.Element && step.name_kind != '' && val.name == map_marker_name {
				want := step_key_norm(step.name_kind, step.name)
				for c in val.items {
					if c is cx.Element && map_entry_effective_key_kind(c) == step.name_kind
						&& step_key_norm(step.name_kind, c.name) == want {
						if dk := map_entry_decl_kind(c) {
							return EvalError{
								code:    'cx-err:CXER0001'
								message: 'member "${step.name}" is declared (::${dk}) but carries no value — a declaration-only entry reads as ABSENT'
							}
						}
						if c.items.len == 1 {
							return c.items[0]
						}
						return cx.Node(c)
					}
				}
				return EvalError{
					code:    'cx-err:CXER0001'
					message: 'no member (${step.name_kind}) "${step.name}"'
				}
			}
			if val is cx.Element {
				for c in val.items {
					if c is cx.Element && c.name == step.name {
						// RULED: MSS-4 (#917): a declaration-only entry's
						// value is ABSENT — the read refuses like a missing
						// member (never yields the null placeholder), with
						// the declaration named.
						if dk := map_entry_decl_kind(c) {
							return EvalError{
								code:    'cx-err:CXER0001'
								message: 'member "${step.name}" is declared (::${dk}) but carries no value — a declaration-only entry reads as ABSENT'
							}
						}
						if c.items.len == 1 {
							return c.items[0]
						}
						return c
					}
				}
				return EvalError{
					code:    'cx-err:CXER0001'
					message: 'no member "${step.name}"'
				}
			}
			return EvalError{
				code:    'cx-err:CXER0001'
				message: 'member path step on non-element value'
			}
		}
		.wildcard_children {
			// `/*` — return all child Element items as a sequence-like
			// container. Used by for-comp generators (`$c :in $n/*`)
			// and by builtins like `empty()` / `count()`.
			// #847: collection-valued children (a PARSED paren-sequence /
			// array / map body arrives as a bare SequenceNode / ArrayNode /
			// MapNode where the runtime lane carries a marker element) match
			// through their marker VIEWS, so both lanes count and navigate
			// identically — same rule as the slow-path arm and #587's `//`.
			if val is cx.Element {
				mut kids := []cx.Node{}
				for c in val.items {
					if c is cx.Element {
						kids << c
					} else if c is cx.SequenceNode {
						kids << cx.Node(cx.Element{ name: seq_marker_name, items: c.items })
					} else if c is cx.ArrayNode {
						kids << cx.Node(cx.Element{ name: arr_marker_name, items: c.items })
					} else if c is cx.MapNode {
						kids << cx.Node(map_node_view(c))
					}
				}
				return cx.Element{ name: '', items: kids }
			}
			return EvalError{
				code:    'cx-err:CXER0001'
				message: '/* path step on non-element value'
			}
		}
		.descendant, .descendant_wildcard, .parent {
			// Slow-path step kinds (G1/G2). The
			// fast-path walker should never see them — eval_binding
			// routes any path containing these through
			// walk_binding_path_seq. Defensive error if somehow
			// reached.
			return EvalError{
				code:    'cx-err:CXER0001'
				message: 'internal: descendant/parent step reached single-value walker; should have routed to sequence walker'
			}
		}
	}
}

// ── Calls (builtins + user-defined deferred) ────────────────────────────────

fn eval_call(c cx.ProgramCall, mut env MatchEnv) !cx.Node {
	// Call-result postfix steps (RULED CRS-1, #862): `[$first $h]@v` — the
	// call evaluates exactly as the step-less form, then the step run
	// destructures the RESULT VALUE through apply_value_path, THE machinery
	// the binding read uses. This is the [?let]-equivalence by construction:
	// `[$string [$f …]/name]` ≡ `[?let [= $t [$f …]] [$string $t/name]]` —
	// including the err-inspection lane (navigating an err result reads its
	// structure, code.md §6.2) and ARR-1 collection destructuring.
	if c.path.len > 0 {
		base := eval_call(cx.ProgramCall{
			name:          c.name
			args:          c.args
			arg_labels:    c.arg_labels
			fallible:      c.fallible
			must_succeed:  c.must_succeed
			explicit_call: c.explicit_call
			pos:           c.pos
		}, mut env)!
		return apply_value_path(base, c.path, mut env, true)
	}
	// #341 item 3 frame diet: this is the hottest non-tail recursion frame in
	// the evaluator, and at -O0 V allocates stack for EVERY branch's locals
	// whether or not they run (the #326 invoke_closure_l lesson). Each
	// alternate shape therefore lives in its own frame — special heads
	// (eval_call_special_head), the rare `!`-postfix wrap (eval_call_strict),
	// and the undefined-call fallback (eval_call_undefined) — and every
	// delegation is a BARE return (#325 direct-return, #327 zero-temp `f()!`
	// forwarding): no result/dispatched temporaries on this frame.
	//
	// bare reference (no parens, no args) in value position
	// yields a first-class VALUE, never an implicit call: a bound name
	// resolves to its value (a closure sentinel is itself the function
	// value); an unbound name that is a defined function resolves to a
	// closure sentinel reference. An explicit `name()` (explicit_call) or
	// any args fall through to the call path below.
	// A bare (`$`-less) name is DATA, never a function value: per the
	// the surface only `$name` produces a first-class function
	// reference (closure / builtin). A bare name that resolves to a bound
	// value is still the ordinary un-sigiled variable read (e.g. a bare
	// param ref in a def body); a bare name that resolves to nothing
	// self-evaluates to a data element further below.
	// #342-style by-ref probe: one lookup, no option temp holding a full
	// cx.Node copy; the deref copy happens at the return boundary (nothing
	// can rehash env.bindings between probe and copy — verified read-only
	// map_get_check in the fork, no insert-on-miss).
	if !c.explicit_call && c.args.len == 0 {
		pbare := unsafe { env.bindings.value_ptr(c.name) }
		if pbare != unsafe { nil } {
			return unsafe { *pbare }
		}
	}
	// placeholder partial application. If any argument is a
	// `_` hole, capture the non-hole args (eagerly) and yield a partial
	// function value awaiting the holes, instead of calling now.
	mut has_hole := false
	for a in c.args {
		if a is cx.ProgramCall && a.name == cx.program_hole_name {
			has_hole = true
			break
		}
	}
	if has_hole {
		return build_partial_value(c, mut env)
	}
	mut args := []cx.Node{}
	for a in c.args {
		args << eval_call_arg(a, mut env)!
	}
	// Error-value propagation (error-as-value model + security.md §4): if any
	// evaluated argument is an err-value, the call cannot proceed on a bad
	// operand — surface the error instead of dispatching. This lets a denied
	// inner effect (e.g. `[$uuid:validate [$uuid:v4]]` with no `random` grant)
	// propagate CXER0271 through the outer call. `[?try]`/`[?catch]` still
	// catch it: they eval their body via eval_node and inspect the returned
	// err-value, rather than receiving it as a plain call argument.
	for a in args {
		if a is cx.Element && is_err_value(a) {
			return a
		}
	}
	// Special heads — higher-order built-ins (`filter`/`map`/`reduce`),
	// `meta-of`, and the `fp-*` combinator primitives. The gate here is
	// name-shape + the homoiconic-shadow check only (cheap, no locals); the
	// per-head sub-conditions and their temporaries live in
	// eval_call_special_head, which falls through to the normal dispatch
	// tail itself when the head turns out not to be special after all
	// (bare `map` facet word, unknown `fp-*` name).
	if (c.name == 'filter' || c.name == 'map' || c.name == 'reduce' || c.name == 'meta-of'
		|| c.name.starts_with('fp-') || c.name.starts_with('map-')
		|| c.name.starts_with('arr-')) && c.name !in env.closures && c.name !in env.bindings {
		return eval_call_special_head(c, args, mut env)
	}
	// Postfix semantics per spec/code.md §9.2: `!` panics on an [err …]
	// result — rare, and the wrap needs an EvalError + err_summary locals,
	// so it gets its own frame; `?` (fallible-propagate) is the default
	// behavior and needs no check at all, so the common path bare-returns
	// the dispatch result untouched.
	if c.must_succeed {
		return eval_call_strict(c, args, mut env)
	}
	return eval_call_dispatch(c, args, mut env)
}

// eval_call_special_head handles the special-head calls split out of
// eval_call (#341 item 3): higher-order built-ins, `meta-of`, and the
// `fp-*` primitives. Reached only when the name matches a special shape
// AND is not shadowed by a user closure/binding; re-discriminates the
// per-head sub-conditions here and falls through to the ordinary dispatch
// tail when the head is not actually special.
fn eval_call_special_head(c cx.ProgramCall, args []cx.Node, mut env MatchEnv) !cx.Node {
	// Higher-order built-ins: `filter` / `map` / `reduce` are core
	// built-ins reachable via head-dispatch `[$name seq fn]` (§6.5).
	// Handled here (not in dispatch_call_l) so a predicate/mapper closure
	// that raises propagates as an eval error rather than degrading to
	// "no callable".
	// Bare 0-arg reference `!explicit_call && args.len==0` is EXCLUDED: a
	// standalone `map`/`filter`/`reduce` token in value position (e.g. a
	// `[tags ... map ...]` facet word) is DATA per the bareword rule and
	// self-evaluates via the dispatch fallback, not a nullary `[$map]`
	// raising CXER0100. `[$map seq fn]` (args present) still dispatches here.
	if c.name == 'filter' || c.name == 'map' || c.name == 'reduce' {
		if !(!c.explicit_call && args.len == 0) {
			return eval_hof_builtin(c.name, args, mut env)
		}
	} else if c.name == 'meta-of' {
		// `[meta-of EXPR]` — D5 reflection builtin: return EXPR's attached
		// metadata map (empty map if none).
		return eval_meta_of(args)
	} else {
		// cx-stdlib/fp combinator primitives (`fp-map` / `fp-flat-map` /
		// `fp-pure` / `fp-fold` / `fp-sequence` / `fp-traverse`). They apply a
		// CX callable to interior values, so they need the live env (closure
		// table) and are dispatched here rather than via the env-less
		// `stdlib_builtin` chain. The bundle bodies forward the qualified
		// `[$fp:map …]` surface to these primitives.
		if r := eval_fp_builtin(c.name, args, mut env) {
			return r
		}
		// cx-stdlib/map + cx-stdlib/array primitives (#925, RULED: PYE-1):
		// same shape as the fp family — for-each/filter/fold apply a CX
		// callable, so they dispatch with the live env.
		if r := eval_map_builtin(c.name, args, mut env) {
			return r
		}
		if r := eval_arr_builtin(c.name, args, mut env) {
			return r
		}
	}
	// Not actually special (bare HOF facet word / unknown fp-* name):
	// ordinary dispatch, same as eval_call's tail.
	if c.must_succeed {
		return eval_call_strict(c, args, mut env)
	}
	return eval_call_dispatch(c, args, mut env)
}

// eval_call_dispatch is the shared dispatch tail (#341 item 3): closure-call
// fast path with error PROPAGATION, then the builtin/stdlib dispatch chain.
// A name that resolves to a closure (a `[?def]` registered directly, or a
// `$`-bound `[?fn]` sentinel) is invoked directly so a closure-body eval
// error (e.g. CXER0204 from a nested `[?def]`) propagates — rather than
// being swallowed to "no callable" by dispatch_call_l's optional
// `or { return none }`. dispatch_call_l remains the path for builtins,
// http-client postfix, stdlib, and non-closure bindings. Every arm is a
// bare return; err-values flow through untouched (`?` default semantics —
// the `!`-postfix wrap is eval_call_strict's job).
fn eval_call_dispatch(c cx.ProgramCall, args []cx.Node, mut env MatchEnv) !cx.Node {
	// #342: by-ref closure lookup (`value_ptr`) — one probe, no 400-500 B
	// Closure copy into an option temp. The deref copy happens at the call
	// boundary, BEFORE the body evaluates (a body can register closures,
	// which may rehash env.closures and invalidate the ref).
	pcl := unsafe { env.closures.value_ptr(c.name) }
	if pcl != unsafe { nil } {
		return invoke_closure_l(unsafe { *pcl }, args, c.arg_labels, mut env)
	}
	// Same by-ref discipline for the bound-value closure resolve: the deref
	// copy into resolve_closure's parameter happens before any body runs.
	pbv := unsafe { env.bindings.value_ptr(c.name) }
	if pbv != unsafe { nil } {
		if cl := resolve_closure(unsafe { *pbv }, env) {
			return invoke_closure_l(cl, args, c.arg_labels, mut env)
		}
	}
	return dispatch_call_l(c.name, args, c.arg_labels, mut env) or {
		return eval_call_undefined(c, args, mut env)
	}
}

// eval_call_strict wraps the dispatch tail with the `!`-postfix semantics
// (spec/code.md §9.2): an [err …] RESULT becomes a CXER0001 panic carrying
// the err-value as its cause. Split out of eval_call (#341 item 3) so the
// EvalError construction + err_summary locals cost nothing on the hot frame.
fn eval_call_strict(c cx.ProgramCall, args []cx.Node, mut env MatchEnv) !cx.Node {
	result := eval_call_dispatch(c, args, mut env)!
	if is_err_value(result) {
		return EvalError{
			code:      'cx-err:CXER0001'
			message:   'call "${c.name}!" returned err: ${err_diagnostic(result)}'
			cause:     result
			cause_set: true
		}
	}
	return result
}

// eval_call_undefined is the dispatch-fallback split out of eval_call
// (#341 item 3): everything that happens when no closure/builtin/binding
// answers the call. Cold by construction; carries the EvalError and node
// materialisation temporaries the hot frame no longer pays for.
fn eval_call_undefined(c cx.ProgramCall, args []cx.Node, mut env MatchEnv) !cx.Node {
	if c.must_succeed {
		// !-postfix on an undefined call: chain a code-only
		// `[err :code "<name>"]` as the panic's cause per
		// spec/code.md §9.2 (err-004 fixture).
		return EvalError{
			code:      'cx-err:CXER0001'
			message:   'unknown function "${c.name}" with !-postfix'
			cause:     mk_err_code_only(c.name)
			cause_set: true
		}
	}
	// QName `prefix:member` head naming a member that EXISTS in an
	// imported module but is module-private (or not entry-file
	// re-exported, §12.4.4) raises CXER0216 (E_VISIBILITY) — a
	// distinct diagnostic from "resolver matches no module"
	// (CXER0213) and from a plain undefined call. Checked here in
	// the dispatch fallback so public members (registered as
	// closures) never reach this path.
	if verr := module_member_visibility_error(c.name, mut env) {
		return verr // EvalError (CXER0216) propagated as the call result
	}
	// A bareword head (`$`-less, no parens, no args) that resolves
	// to no binding / closure / builtin is DATA, not a failed call:
	// per the homoiconic surface a bareword self-evaluates to a
	// scalar of its own name (`primary` -> `primary`). Only `$name`
	// references raise unbound-variable; barewords never do.
	if !c.explicit_call && args.len == 0 {
		// `true`/`false` are lexed as bool_lit; `null` is the one
		// reserved scalar word the lexer leaves as an ident (no
		// null_lit token). Per parser.v's reserved-atom guard, bare
		// `null` IS the null scalar — materialise it here so it is a
		// typed null, not a TextNode that merely renders "null".
		if c.name == 'null' {
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(cx.NullValue{})
				data_type: cx.ScalarType.null_type
			})
		}
		return cx.Node(cx.TextNode{ value: c.name })
	}
	// A CALL of a recognized §6.5 builtin name that fell through the whole
	// dispatch chain did so because its ARGUMENTS are unusable (absence /
	// multi-item sequence in a scalar slot, arity, scalar typing) — every
	// name-resolution path was already tried. Surface a real CXER0100
	// diagnostic naming the argument, never the misleading
	// `no callable "<name>"` (#536). Placed AFTER the bareword-data arm so
	// a bare `first` in value position stays data, and at the chain END so
	// stdlib modules claiming the same bare name with another signature
	// (similar's `distinct`/`contains`) keep winning first.
	if builtin_dispatchable(c.name) {
		return builtin_args_diagnostic(c.name, args)
	}
	return mk_err('user-undefined', 'no callable "${c.name}"')
}

// eval_hof_builtin implements the higher-order core built-ins reachable
// via head-dispatch (§6.3 example `[$filter $users [?fn …]]`, §6.5):
//   [$filter seq pred]   → items where EBV(pred item) is true
//   [$map seq fn]        → fn applied to each item
//   [$reduce seq fn init]→ left fold; fn is (acc, item) → acc
// The function argument is a function VALUE (closure sentinel / builtin
// wrapper); it is applied via apply_fn_value. filter/map return an eager
// iterator (paren-sequence at the host boundary), matching the
// `[?filter]`/`[?map]` directives; reduce returns the folded value.
fn eval_hof_builtin(name string, args []cx.Node, mut env MatchEnv) !cx.Node {
	match name {
		'filter' {
			if args.len != 2 {
				return EvalError{ code: 'cx-err:CXER0100',
					message: '[$filter] expects (sequence, predicate); got ${args.len} arg(s)' }
			}
			seq := args[0]
			fn_val := args[1]
			items := iterate(seq)
			mut results := []cx.Node{}
			for it in items {
				keep := apply_fn_value(fn_val, [it], mut env)!
				// §9.2 / #348(a): [$filter] is the head-dispatch surface of
				// the same filter operation — an err-valued predicate result
				// propagates identically to [?filter].
				if keep is cx.Element && is_err_value(keep) {
					return keep
				}
				ebv := node_ebv(keep) or { return iterator_ebv_err() }
				if ebv {
					results << it
				}
			}
			return mk_eager_iterator(.iter_filter, [seq, fn_val], results)
		}
		'map' {
			if args.len != 2 {
				return EvalError{ code: 'cx-err:CXER0100',
					message: '[$map] expects (sequence, fn); got ${args.len} arg(s)' }
			}
			seq := args[0]
			fn_val := args[1]
			items := iterate(seq)
			mut results := []cx.Node{}
			for it in items {
				results << apply_fn_value(fn_val, [it], mut env)!
			}
			return mk_eager_iterator(.iter_map, [seq, fn_val], results)
		}
		'reduce' {
			if args.len != 3 {
				return EvalError{ code: 'cx-err:CXER0100',
					message: '[$reduce] expects (sequence, fn, init); got ${args.len} arg(s)' }
			}
			seq := args[0]
			fn_val := args[1]
			mut acc := args[2]
			items := iterate(seq)
			for it in items {
				acc = apply_fn_value(fn_val, [acc, it], mut env)!
			}
			return acc
		}
		else {
			return EvalError{ code: 'cx-err:CXER0001',
				message: 'eval_hof_builtin: unhandled "${name}"' }
		}
	}
}

// dispatch_call routes to closures (program-global table) then
// call-on-$binding (sentinel→closure_id) then http-client postfix
// (get / post / put / delete / patch / head / options / request when
// args[0] is a http-client element) then builtins.
// dispatch_call resolves a positional call (no named args). Thin wrapper
// over dispatch_call_l for the element-form call sites that never carry
// labels.
fn dispatch_call(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	return dispatch_call_l(name, args, []string{}, mut env)
}

// closure_err_to_value converts a raised invocation error into an err-VALUE
// node (error-as-value model), preserving the original code / message / cause
// (#46). Used at the closure-dispatch boundary so a [?def] body that raises
// surfaces as `[err code=… message=…]` at the call site instead of being
// swallowed to a silent data literal. Mirrors error_hooks.v's converter.
fn closure_err_to_value(err IError) cx.Node {
	if err is EvalError {
		if err.cause_set {
			return mk_err_with_cause(err.code, err.cause)
		}
		return mk_err(err.code, err.msg())
	}
	return mk_err('cx-err:CXER0001', err.msg())
}

// dispatch_call_l resolves a call, threading named-argument `labels`
// (parallel to args, '' = positional) into the closure binding
// D6). Builtins ignore labels (positional only).
fn dispatch_call_l(name string, args []cx.Node, labels []string, mut env MatchEnv) ?cx.Node {
	// #342: by-ref closure lookup — see eval_call. The deref copy happens at
	// the call boundary, before the body can write env.closures.
	pcl := unsafe { env.closures.value_ptr(name) }
	if pcl != unsafe { nil } {
		// A registered closure whose body raises must SURFACE the error
		// (#46) — not return none, which made element-form callers fall
		// through to data-element construction (`[fn args]`), masking the
		// real runtime error as a silent "function not registered" data
		// literal. The name is a confirmed callable; invocation failure is a
		// genuine error. Convert the raise to an err-VALUE (error-as-value
		// model) — the same shape an err-returning body already produces —
		// so it propagates as the call result instead of vanishing.
		val := invoke_closure_l(unsafe { *pcl }, args, labels, mut env) or {
			return closure_err_to_value(err)
		}
		return val
	}
	// Everything past the registered-closure fast path lives in its own
	// frame (#326 frame diet): at -O0 V allocates stack for every branch's
	// locals whether or not it runs — the bound-function-value path carries a
	// second by-value Closure and the builtin / stdlib chain ~5 KB of option
	// temps — so keeping them inline taxed EVERY recursive closure call per
	// level.
	return dispatch_call_binding(name, args, labels, mut env)
}

// dispatch_call_binding is dispatch_call_l's bound-value path: a `$name`
// binding holding a function value (closure sentinel) is applied; a plain
// bound value with no args yields the value. Split out of dispatch_call_l
// (#326).
fn dispatch_call_binding(name string, args []cx.Node, labels []string, mut env MatchEnv) ?cx.Node {
	if val := env.bindings[name] {
		if closure := resolve_closure(val, env) {
			ret := invoke_closure_l(closure, args, labels, mut env) or {
				return closure_err_to_value(err)
			}
			return ret
		}
		// un-sigiled variable reference. A bare name with no
		// call arguments that resolves to a bound value (a [?def] / [?fn]
		// parameter, a [?let] / [?const] binding) yields that value.
		// Without this, a parameter referenced bare in a non-arithmetic
		// call position (e.g. the `x` in a `[?def] … [abs x]` body) parsed
		// as a zero-arity cx.ProgramCall and fell through to the builtin
		// lookup, raising `no callable "x"`. The sentinel-closure case is
		// handled just above; this is the plain-value case.
		if args.len == 0 {
			return val
		}
	}
	// Labels are not threaded past this point — builtins are positional-only.
	return dispatch_call_fallback(name, args, mut env)
}

// dispatch_call_fallback is dispatch_call_l's non-closure tail: core
// builtins, env-aware stdlib surfaces, and the env-free stdlib chain.
// Split out so the hot recursive-call path (a registered closure) never
// carries this chain's option temporaries on its frame (#326).
fn dispatch_call_fallback(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len > 0 {
		first := args[0]
		if first is cx.Element && first.name == 'http-client' {
			rest := args[1..]
			// I3: the [http-client] postfix-call dispatcher is Ring 2
			// (services.v); probed via the registry slot.
			for cc in g_ring2_client_call {
				if ret := cc(name, first, rest, mut env) {
					return ret
				}
			}
		}
	}
	if r := invoke_builtin(name, args) {
		return r
	}
	// [$serve-file] is an env-touching builtin (reads
	// $request from bindings + service root from dyn_context). Tried
	// after the pure-functional core but before the stdlib chain so a
	// core builtin always wins on a name clash.
	// Ring-2 env-aware packs (serve-file, http serve, bus emit/match,
	// journal folds, fabric receive, xap runtime, store modify-doc)
	// dispatch through the I3 registry — registered at init by
	// ring2_register.v, probed once here in the pre-split chain order
	// (entries are name-gated with disjoint name-sets, so the collapsed
	// position is behavior-identical; see ring_registry.v).
	if r := ring2_stdlib_builtin_env_main(name, args, mut env) {
		return r
	}
	// cx-stdlib/ft custom-tokenizer path: index-with-opts carrying a
	// closure must apply it with the evaluator env in scope. Tried before
	// the env-free chain so the tokenizer is applied; returns none for the
	// non-tokenizer path, which then falls to stdlib_builtin below.
	// cx:eval-tree — tree-eval module function (spec/modules/cx.md §3.4), the
	// function-form dual of [?eval]. Env-aware (capability gate + shared depth
	// counter + context isolation). Tried before the env-free chain.
	if name == 'cx:eval-tree' {
		return eval_tree_fn(args, mut env)!
	}
	// cx: self-host core surface (spec/modules/cx.md §2.1, #437) — always
	// available, no [?lib] required. Env-aware so cx:select runs its runtime
	// CXPath through the SAME inline binding-path engine as `$v//x`.
	if r := cx_module_stdlib_builtin_env(name, args, mut env) {
		return r
	}
	if r := ft_stdlib_builtin_env(name, args, mut env) {
		return r
	}
	// cx-stdlib/log scope introspection: `[$log:current-scope]` reads the
	// active [?with-scope] dynamic context off env. Tried before the
	// env-free chain; returns none for every other name.
	$if !cx_no_pack_log ? {
		if r := log_stdlib_builtin_env(name, args, mut env) {
			return r
		}
	}
	// cx-stdlib/test env-aware surfaces: assert-throws applies a [?fn]
	// thunk and inspects its raised / returned error; lifecycle hooks accept
	// a closure thunk. Tried before the env-free chain so the closure arg is
	// applied with env in scope; returns none for non-test names.
	if r := test_stdlib_builtin_env(name, args, mut env) {
		return r
	}
	// cx-stdlib/validate env-aware path: validate-shape resolves
	// `extends=<const>` and applies `validate-with=` custom validators — both
	// need env to look up a [?const] / invoke a user [?def]. Tried before the
	// env-free chain; returns none for non-validate-shape names.
	if r := validate_stdlib_builtin_env(name, args, mut env) {
		return r
	}
	// cx-stdlib/prof env-aware path: time-fn / time-and-trace apply a [?fn]
	// thunk with env in scope (both clock-gated, so they short-circuit to
	// CXER0271 before touching the thunk under deny-by-default). Tried
	// before the env-free chain; returns none for non-prof-thunk names.
	if r := prof_stdlib_builtin_env(name, args, mut env) {
		return r
	}
	// cx-stdlib/sched env-aware path: test-clock-advance / restore fire the
	// timer `$ev` callables, and the arming verbs stamp the [timer]
	// closeable for [?with-open] — all need env in scope.
	$if !cx_no_pack_sched ? {
		if r := sched_stdlib_builtin_env(name, args, mut env) {
			return r
		}
	}
	// cx-stdlib/similar env-aware path: `sort` with a CLOSURE "by" key
	// function applies it per item with env in scope. Every other similar
	// surface (predicates are data) runs env-free in the chain below.
	if r := similar_stdlib_builtin_env(name, args, mut env) {
		return r
	}
	// cx-stdlib native primitives (vcx/code/stdlib_*.v) backing module
	// [?def] bodies that can't be pure CX (regex, hashing, time, random,
	// path/glob, …). Tried after the core builtin set so a core builtin
	// always wins on a name clash.
	return stdlib_builtin(name, args)
}

// ── function values, partial application ─────────────────────────

// mk_hole_marker / is_hole_marker represent a captured `_` hole inside a
// partial's argument template.
fn mk_hole_marker() cx.Node {
	return cx.Element{ name: cx.program_hole_name }
}

fn is_hole_marker(n cx.Node) bool {
	return n is cx.Element && (n as cx.Element).name == cx.program_hole_name
}

// resolve_fn_value resolves a name to a first-class function VALUE (a
// closure sentinel): a bound function value, a defined
// closure, or a builtin (lazily wrapped). Returns none for a name that
// is not a function.
fn resolve_fn_value(name string, mut env MatchEnv) ?cx.Node {
	if val := env.bindings[name] {
		if is_fn_value(val) {
			return val
		}
		return none
	}
	if name in env.closures {
		return mk_closure_sentinel(name)
	}
	if env.scope != unsafe { nil } && name in env.scope.closures {
		return mk_closure_sentinel(name)
	}
	if builtin_fn_name(name) {
		env.cow_closures()
		env.closures[name] = Closure{ builtin_name: name }
		return mk_closure_sentinel(name)
	}
	return none
}

// lookup_closure resolves a closure id to its Closure, checking the current
// env's closures THEN the program scope (a function VALUE passed across a module
// boundary lives in the defining/program scope, not the lib member's scope —
// #19 higher-order). Returns none if neither has it.
fn lookup_closure(id string, env MatchEnv) ?Closure {
	if cl := env.closures[id] {
		return cl
	}
	if env.scope != unsafe { nil } {
		if cl := env.scope.closures[id] {
			return cl
		}
	}
	return none
}

// apply_fn_value applies a function VALUE (closure sentinel — including
// builtin-wrapping and partial closures) to args. The single uniform
// "call a function value" entry point.
pub fn apply_fn_value(fv cx.Node, args []cx.Node, mut env MatchEnv) !cx.Node {
	cl := resolve_closure(fv, env) or {
		if is_fn_value(fv) {
			return EvalError{ code: 'cx-err:CXER0001', message: 'function value not found' }
		}
		return EvalError{ code: 'cx-err:CXER0001', message: 'value is not a function' }
	}
	return invoke_closure(cl, args, mut env)!
}

// build_partial_value constructs a partial-application function value
// from a call whose argument list contains `_` holes. The
// non-hole arguments are evaluated eagerly (capture-at-construction); the
// holes are recorded positionally and filled when the partial is applied.
fn build_partial_value(c cx.ProgramCall, mut env MatchEnv) !cx.Node {
	target := resolve_fn_value(c.name, mut env) or {
		return EvalError{
			code:    'cx-err:CXER0001'
			message: 'cannot partially apply non-function "${c.name}"'
		}
	}
	// a `_` hole may only occupy a fixed positional
	// parameter, not a `:rest` tail. Validate against the target's
	// param_specs (when known) and raise CXER0102 (E_PARTIAL_APP) otherwise.
	if cl := resolve_closure(target, env) {
		if cl.param_specs.len > 0 {
			mut fixed_pos := 0
			for sp in cl.param_specs {
				if !sp.is_named && !sp.is_rest {
					fixed_pos++
				}
			}
			for i, a in c.args {
				if a is cx.ProgramCall && a.name == cx.program_hole_name && i >= fixed_pos {
					return EvalError{
						// E_PARTIAL_APP (code.md §6.3a / registry row): a hole in
						// a rest position is the spec'd CXER0102, not the 0261
						// band (cancellation growth) it was mis-assigned to (R3.12).
						code:    'cx-err:CXER0102'
						message: 'partial-application hole `_` cannot occupy a :rest position (E_PARTIAL_APP)'
					}
				}
			}
		}
	}
	mut template := []cx.Node{}
	for a in c.args {
		if a is cx.ProgramCall && a.name == cx.program_hole_name {
			template << mk_hole_marker()
		} else {
			template << eval_node(a, mut env)!
		}
	}
	// The partial rides ON its sentinel value (#45) — like an escaping `[?fn]`,
	// it has no stable scope-table home — so it travels with the value and needs
	// no env.closures registration.
	return mk_closure_value(Closure{
		partial_target:   [target]
		partial_template: template
	})
}

// bind_specs_and_eval binds a call's arguments against a closure's
// param_specs and evaluates the body. Positional args fill
// positional params left-to-right; named call-args (labels) fill named
// params; omitted params with a default get it (evaluated in the call
// env); a `:rest` param collects the trailing positional args into a
// `__cx_seq__`. Missing required params / surplus positionals → CXER0100
// (arity is a call-shape error; CXER0001 is reserved for `!`-panics — D002).
// build_param_call_env builds the call environment for a param-spec closure
// `c` applied to `args`/`labels`: free names resolve in the closure's defining
// scope (#19/#22); positional / named / default / rest params bind per the
// spec list; --strict param typing (CXER0206) is enforced. Extracted from
// bind_specs_and_eval so the TCO trampoline (run_closure_body) can rebuild a
// fresh frame for each tail call (#60).
fn build_param_call_env(c Closure, args []cx.Node, labels []string, mut enclosing MatchEnv) !MatchEnv {
	mut pos := []cx.Node{}
	mut named := map[string]cx.Node{}
	for i, a in args {
		lbl := if i < labels.len { labels[i] } else { '' }
		if lbl == '' {
			pos << a
		} else {
			named[lbl] = a
		}
	}
	mut call_env := MatchEnv{
		// CoW alias (#333, the per-call analog of the #317 request env): the
		// closure's defining-scope bindings are ALIASED read-only instead of
		// copied per call. The first in-place write below (captured bindings /
		// param binds) realizes a private copy via cow_bindings() — one bulk
		// map.clone() instead of a per-key insert loop — and a call that never
		// writes (zero params, zero captures) pays nothing. The defining scope's
		// owner frame is suspended for the duration of the call (single-threaded
		// eval; workers/async get deep snapshots at spawn), so the alias can
		// never observe a concurrent defining-scope mutation.
		bindings:        if c.defining_scope != unsafe { nil } {
			c.defining_scope.bindings
		} else {
			map[string]cx.Node{}
		}
		bindings_shared: c.defining_scope != unsafe { nil }
		// Uniform lexical scoping (#19/#22): free names resolve in the closure's
		// DEFINING scope, not the caller's. See invoke_closure_l.
		closures:        if c.defining_scope != unsafe { nil } {
			c.defining_scope.closures
		} else {
			enclosing.closures // aliased; cow_closures() before any write (B17)
		}
		closures_shared: true
		state:           enclosing.state
		anon_counter:    enclosing.anon_counter
		dyn_context:     if enclosing.dyn_context.len > 0 { enclosing.dyn_context.clone() } else { enclosing.dyn_context }
		scope:           enclosing.scope
		// An in-body `[?fn]` captures this executing closure's defining_scope as its
		// own (eval_fn), and `[?def]` nested in a body is rejected (CXER0204) — both
		// require in_function_body=true here (the param-spec path; #45 Bug-2).
		in_function_body:   true
		cur_defining_scope: c.defining_scope
		current_worker:     enclosing.current_worker // same-thread call chain keeps the §10.5.4 cancel signal
		eval_budget:        enclosing.eval_budget // same-thread call chain keeps the F4 budget (S6.2)
	}
	if c.captured_bindings.len > 0 {
		call_env.cow_bindings()
		for k, v in c.captured_bindings {
			call_env.bindings[k] = v
		}
	}
	if c.param_specs.len > 0 {
		// Every spec iteration binds a name (or errors out) — realize the
		// private copy once, ahead of the loop's write sites (incl. default
		// bodies evaluated in call_env).
		call_env.cow_bindings()
	}
	mut pi := 0
	for spec in c.param_specs {
		if spec.is_rest {
			mut rest := []cx.Node{}
			for pi < pos.len {
				rest << pos[pi]
				pi++
			}
			call_env.bindings[spec.name] = cx.Element{ name: seq_marker_name, items: rest }
			continue
		}
		if spec.is_named {
			if v := named[spec.name] {
				call_env.bindings[spec.name] = v
			} else if spec.default_src != '' {
				dp := cx.parse_program(spec.default_src) or {
					return EvalError{ code: 'cx-err:CXER0001', message: 'bad default for :${spec.name}' }
				}
				call_env.bindings[spec.name] = eval_node(dp.body, mut call_env)!
			} else {
				return EvalError{ code: 'cx-err:CXER0100', message: 'missing required named argument :${spec.name}' }
			}
		} else {
			if pi < pos.len {
				call_env.bindings[spec.name] = pos[pi]
				pi++
			} else if spec.default_src != '' {
				dp := cx.parse_program(spec.default_src) or {
					return EvalError{ code: 'cx-err:CXER0001', message: 'bad default for ${spec.name}' }
				}
				call_env.bindings[spec.name] = eval_node(dp.body, mut call_env)!
			} else {
				return EvalError{ code: 'cx-err:CXER0100', message: 'missing required argument ${spec.name}' }
			}
		}
	}
	if pi < pos.len {
		return EvalError{ code: 'cx-err:CXER0100', message: 'too many positional arguments (${pos.len} for ${pi})' }
	}
	// --strict argument typing (§12.7, CXER0206): each bound parameter
	// carrying a `::T` annotation must hold a value of that type. Default
	// mode erases annotations (this whole block is skipped).
	if enclosing.state.strict {
		for spec in c.param_specs {
			if spec.type_src == '' || spec.is_rest {
				continue
			}
			bound := call_env.bindings[spec.name] or { continue }
			if !value_matches_type_env(bound, spec.type_src, mut enclosing) {
				return EvalError{
					code:    'cx-err:CXER0206'
					message: 'cx-err:CXER0206 E_TYPE_ARG_MISMATCH: argument for `${spec.name}` does not match declared type `${spec.type_src}`'
				}
			}
		}
	}
	return call_env
}

// build_param_call_env_record binds a NAME-KEYED argument record (the
// commands_effects §5 "normalized arg record" — what a proposal's [args {…}]
// map and an MCP tools/call `arguments` object carry) against a command
// closure's param list. Unlike the general call surface (labels bind NAMED
// params only; positionals bind by position), the record is name-keyed over
// ALL params: each spec, in declaration order, binds record[name], else its
// default, else refuses loud. Unknown record keys refuse loud (a mis-spelled
// param must never silently vanish — the closed-args posture the projection's
// additionalProperties:false mirrors). A rest param collects nothing here:
// a record has no positional overflow (extras land on the unknown-key
// refusal); rest-param commands accept their named prefix only.
// Stream 18 W2 — the propose/commit seam's binding; the general call path
// (build_param_call_env) is deliberately untouched.
pub fn build_param_call_env_record(c Closure, record map[string]cx.Node, mut enclosing MatchEnv) !MatchEnv {
	mut known := map[string]bool{}
	for spec in c.param_specs {
		known[spec.name] = true
	}
	for k, _ in record {
		if !known[k] {
			return EvalError{ code: 'cx-err:CXER0100', message: 'unknown argument `${k}` — the record binds the parameter list only' }
		}
	}
	mut call_env := MatchEnv{
		bindings:        if c.defining_scope != unsafe { nil } {
			c.defining_scope.bindings
		} else {
			map[string]cx.Node{}
		}
		bindings_shared: c.defining_scope != unsafe { nil }
		closures:        if c.defining_scope != unsafe { nil } {
			c.defining_scope.closures
		} else {
			enclosing.closures
		}
		closures_shared: true
		state:           enclosing.state
		anon_counter:    enclosing.anon_counter
		dyn_context:     if enclosing.dyn_context.len > 0 { enclosing.dyn_context.clone() } else { enclosing.dyn_context }
		scope:           enclosing.scope
		in_function_body:   true
		cur_defining_scope: c.defining_scope
		current_worker:     enclosing.current_worker
		eval_budget:        enclosing.eval_budget
	}
	if c.captured_bindings.len > 0 {
		call_env.cow_bindings()
		for k, v in c.captured_bindings {
			call_env.bindings[k] = v
		}
	}
	if c.param_specs.len > 0 {
		call_env.cow_bindings()
	}
	for spec in c.param_specs {
		if spec.is_rest {
			// A record carries no positional overflow; the rest binds empty.
			call_env.bindings[spec.name] = cx.Element{ name: seq_marker_name, items: []cx.Node{} }
			continue
		}
		if v := record[spec.name] {
			call_env.bindings[spec.name] = v
		} else if spec.default_src != '' {
			dp := cx.parse_program(spec.default_src) or {
				return EvalError{ code: 'cx-err:CXER0001', message: 'bad default for ${spec.name}' }
			}
			call_env.bindings[spec.name] = eval_node(dp.body, mut call_env)!
		} else {
			return EvalError{ code: 'cx-err:CXER0100', message: 'missing required argument ${spec.name}' }
		}
	}
	if enclosing.state.strict {
		for spec in c.param_specs {
			if spec.type_src == '' || spec.is_rest {
				continue
			}
			bound := call_env.bindings[spec.name] or { continue }
			if !value_matches_type_env(bound, spec.type_src, mut enclosing) {
				return EvalError{
					code:    'cx-err:CXER0206'
					message: 'cx-err:CXER0206 E_TYPE_ARG_MISMATCH: argument for `${spec.name}` does not match declared type `${spec.type_src}`'
				}
			}
		}
	}
	return call_env
}

// run_closure_body evaluates closure `c`'s body in TAIL position and
// trampolines tail self/closure-calls (#60): when the body's tail position is
// a call to a param-spec [?def] closure, it rebinds a fresh frame and LOOPS
// instead of recursing the native C stack. A tail-recursive cx loop therefore
// runs in O(1) native stack rather than SIGSEGV-ing at ~190 deep. `call_env`
// is the frame already built for `c` (by the caller); it is replaced in place
// on each tail hop, using the just-completed frame as the new enclosing scope.
fn run_closure_body(c Closure, mut call_env MatchEnv) !cx.Node {
	mut cur := c
	for {
		tr := eval_tail(cur.body_node(), mut call_env)!
		if !tr.is_tail {
			return tr.value
		}
		call_env = build_param_call_env(tr.closure, tr.args, tr.labels, mut call_env)!
		cur = tr.closure
	}
	return cx.Element{}
}

// bind_specs_and_eval applies a param-spec closure: build the frame, run the
// body (TCO-trampolined), then enforce --strict return typing (§12.7).
fn bind_specs_and_eval(c Closure, args []cx.Node, labels []string, mut enclosing MatchEnv) !cx.Node {
	return bind_specs_and_eval_k(c, args, labels, '', mut enclosing)
}

// bind_specs_and_eval_k is bind_specs_and_eval carrying an already-
// resolved explicit idempotency key ('' = derive; stream 6 W5, L111).
// The dedup consult/record wraps the body run so the DERIVED key reads
// the post-default bindings out of the call frame — the one place the
// normalized param-name → value record exists without a second spelling
// of the binding rules (R12: positional vs named spelling of the same
// call is ONE key by construction).
fn bind_specs_and_eval_k(c Closure, args []cx.Node, labels []string, idem_key string, mut enclosing MatchEnv) !cx.Node {
	mut call_env := build_param_call_env(c, args, labels, mut enclosing)!
	mut key := idem_key
	if c.is_idempotent {
		if key == '' {
			key = idem_derive_key(c, call_env)
		}
		if hit := idem_lookup(mut enclosing, key) {
			return hit
		}
	}
	// Common path (no --strict return check): direct result return — same
	// propagation, zero result-struct temporaries on this per-recursion-level
	// frame (#319 frame diet).
	if !enclosing.state.strict || c.returns_type == '' {
		if !c.is_idempotent {
			return run_closure_body(c, mut call_env)
		}
		res := run_closure_body(c, mut call_env)!
		idem_record_success(mut enclosing, key, res, c.idem_window_ns)
		return res
	}
	res := run_closure_body(c, mut call_env)!
	// --strict return typing (§12.7, CXER0207).
	if !value_matches_type_env(res, c.returns_type, mut enclosing) {
		return EvalError{
			code:    'cx-err:CXER0207'
			message: 'cx-err:CXER0207 E_TYPE_RETURN_MISMATCH: return value does not match declared type `${c.returns_type}`'
		}
	}
	if c.is_idempotent {
		idem_record_success(mut enclosing, key, res, c.idem_window_ns)
	}
	return res
}

// ── effect-boundary idempotency (code.md §12.2.7, stream 6 L111 — W5) ────────

// command_idem_fields resolves the [idempotent] clause's registration
// facts for a Closure: (window_ns, tier2_addr). The Tier-2 address is
// the derived key's fn component (R12) — computed here once, idempotent
// commands only. A malformed [window] duration is the static contract
// violation CXER0239 (one authority posture: both registration sites
// call this).
fn command_idem_fields(def &cx.DefNode, raw string) !(i64, string) {
	mut win := i64(0)
	if def.idem_window != '' {
		win = duration_to_ns(def.idem_window) or {
			return error('cx-err:CXER0239 E_COMMAND_CONTRACT: `${def.name}` declares [idempotent [window ${def.idem_window}]] but `${def.idem_window}` is not a valid duration (grammar [152g′]; cx-err:CXER0239)')
		}
	}
	t2 := cx_code_tier2_hash(raw) or {
		return error('cx-err:CXER0239 E_COMMAND_CONTRACT: `${def.name}` [idempotent] key basis unavailable — Tier-2 identity failed: ${err.msg()} (cx-err:CXER0239)')
	}
	return win, t2
}

// command_meta_build constructs a command def's propose/commit metadata
// (stream 6 W6, R16): src_addr = Tier-1 tagged address of the RAW def
// text bytes (the L139 trust key — byte-exact version binding, the F1′
// blob-address form); code_addr = the Tier-2 computes-as: claim (rides
// for cache/equivalence only). Computed once at registration.
fn command_meta_build(def &cx.DefNode, raw string) &CommandMeta {
	code_addr := cx_code_tier2_hash(raw) or { '' }
	return &CommandMeta{
		compensates:        def.compensates
		has_requires_at:    def.has_requires_at
		requires_at_stream: def.requires_at_stream
		requires_at_seq:    def.requires_at_seq
		requires_at_hash:   def.requires_at_hash
		requires:      def.requires
		preconditions: def.preconditions
		effects_items: def.effects
		src_addr:      cx.cx_tag_address(cx.cx_default_hash_algo, sha256.sum256(raw.bytes()).hex())
		code_addr:     code_addr
	}
}

// idem_strip_explicit_key extracts the reserved `idempotency-key=`
// call-site named argument (R12 — the caller key that WINS over the
// derived key; the [?rate-limit] name= precedent). Returns the pruned
// (args, labels) plus the key text ('' when absent). The argument never
// binds a parameter.
fn idem_strip_explicit_key(args []cx.Node, labels []string) ([]cx.Node, []string, string) {
	mut key := ''
	mut idx := -1
	for i, lbl in labels {
		if lbl == 'idempotency-key' {
			idx = i
			if i < args.len {
				v := args[i]
				if v is cx.ScalarNode {
					key = cx.scalar_value_str_public(v.value)
				}
			}
			break
		}
	}
	if idx < 0 {
		return args, labels, ''
	}
	mut a2 := []cx.Node{cap: args.len - 1}
	mut l2 := []string{cap: labels.len - 1}
	for i, a in args {
		if i == idx {
			continue
		}
		a2 << a
		l2 << if i < labels.len { labels[i] } else { '' }
	}
	return a2, l2, key
}

// idem_derive_key builds the DERIVED idempotency key (R12): sha-256 over
// `idem \x00 <Tier-2 command address> \x00 <tenant> \x00` + the
// post-default param-name → canonical-value record, iterated in PARAM
// ORDER (the def's own order — deterministic regardless of call
// spelling). Dropped from the key, by rule: the cap-set and the
// authority basis (recorded, not keyed). Tenant at the direct-call
// boundary is '' (the session/commit boundary supplies the real one).
fn idem_derive_key(c Closure, call_env MatchEnv) string {
	mut b := strings.new_builder(128)
	b.write_string('idem\x00')
	b.write_string(c.tier2_addr)
	b.write_string('\x00\x00') // tenant '' at the direct-call boundary
	for spec in c.param_specs {
		v := call_env.bindings[spec.name] or { continue }
		b.write_string(spec.name)
		b.write_u8(`=`)
		b.write_string(cx_mod_value_source(v) or { render_value_diag(v) })
		b.write_u8(0)
	}
	return 'd:' + sha256.sum256(b.str().bytes()).hex()
}

// idem_derive_key_zero is the zero-param variant (no call frame needed).
fn idem_derive_key_zero(c Closure) string {
	return 'd:' + sha256.sum256(('idem\x00' + c.tier2_addr + '\x00\x00').bytes()).hex()
}

// idem_lookup consults the per-program dedup registry: a live record is
// the PRESENT `[deduped <original outcome>]` wrapper (R13 — "already
// done, here's what happened", never the absence channel); an expired
// record (declared window passed on the engine clock) is dropped.
fn idem_lookup(mut env MatchEnv, key string) ?cx.Node {
	rec := env.state.idem_records[key] or { return none }
	if rec.expires_ns > 0 && env.state.clock_now() >= rec.expires_ns {
		env.state.idem_records.delete(key)
		return none
	}
	return cx.Element{
		name:  'deduped'
		items: [rec.outcome]
	}
}

// idem_matching_keys returns the in-process dedup-registry keys whose
// recorded outcome references any needle (stream 20, erasure_compliance §7:
// shred reach beats the retention window for every dedup record EXCEPT the
// erase-subject command's own journaled record — which lives in the journal,
// never here). Over-matching is safe: a dropped record only means a replay
// re-executes, the consequence §7 explicitly accepts.
pub fn idem_matching_keys(env &MatchEnv, needles []string) []string {
	mut keys := []string{}
	for key, rec in env.state.idem_records {
		txt := render_value_diag(rec.outcome)
		for n in needles {
			if n != '' && txt.contains(n) {
				keys << key
				break
			}
		}
	}
	keys.sort()
	return keys
}

// idem_drop_keys removes the named dedup records — the erase walk's apply
// half (the scan runs pre-commit for the recorded count; the drop is
// post-commit with the rest of the walk).
pub fn idem_drop_keys(mut env MatchEnv, keys []string) {
	for k in keys {
		env.state.idem_records.delete(k)
	}
}

// idem_record_success records a SUCCESSFUL outcome (R13: a failed
// attempt leaves no record, so [?retry] re-executes — recording
// failures would make the first crash permanent). Err VALUES do not
// record; thrown errors never reach here.
fn idem_record_success(mut env MatchEnv, key string, outcome cx.Node, window_ns i64) {
	if is_err_value(outcome) {
		return
	}
	expires := if window_ns > 0 { env.state.clock_now() + window_ns } else { i64(0) }
	env.state.idem_records[key] = IdemRecord{
		outcome:    outcome
		expires_ns: expires
	}
}

// render_value_diag is the key-derivation fallback for a value the
// canonical codec refuses (closures etc.) — diagnostic-stable text.
fn render_value_diag(n cx.Node) string {
	if n is cx.ScalarNode {
		return scalar_to_text(n.value)
	}
	return '<opaque>'
}

// err_summary extracts a short string description of an err-value
// for diagnostic messages.
// err_summary returns an err value's CODE alone.
//
// Deliberately code-only, and it must stay that way: `pipe_tap_propagates`
// dispatches on this string (§8.9.2 propagates a tap's err iff its code is
// CXER0001 or CXER0260), so appending a message here would silently break
// that comparison. For anything a HUMAN reads, use `err_diagnostic`.
pub fn err_summary(n cx.Node) string {
	if n is cx.Element && is_err_value(n) {
		for a in n.attrs {
			if a.name == 'code' {
				v := a.value
				if v is string { return v }
			}
		}
	}
	return '<err>'
}

// err_diagnostic renders an err value for a person: `CODE: MESSAGE`, or the
// code alone when it carries no message.
//
// #848 — every wrapping surface used `err_summary` and so reported the code
// while DISCARDING the message. For `[$io:read-file F]!` that meant the user
// saw `cx-err:CXER3401` and not
// `E_IO_NOT_FOUND: read-file thing.feature.cxd` — the filename, the one fact
// that makes the failure actionable, is exactly what was dropped, and the
// symbolic name that would let someone search for it went with it.
//
// It matters more than a cosmetic defect because `!` is the operator the spec
// PRESCRIBES for guarding a fallible binding (§6.2, "guard the BINDING, not
// the query"). Following that advice cost you the diagnosis: an unguarded read
// gives a wrong answer with no message, and a guarded one gave a right refusal
// with no message either.
//
// The wrapping is the operator's CONTRIBUTION, not a replacement for what it
// wrapped.
pub fn err_diagnostic(n cx.Node) string {
	if n is cx.Element && is_err_value(n) {
		// `code` would shadow the module name, which V rejects outright.
		mut ecode := ''
		mut msg := ''
		for a in n.attrs {
			v := a.value
			if v is string {
				if a.name == 'code' {
					ecode = v
				} else if a.name == 'message' {
					msg = v
				}
			}
		}
		if ecode != '' && msg != '' {
			return '${ecode}: ${msg}'
		}
		if ecode != '' {
			return ecode
		}
	}
	return '<err>'
}

// all_items_are_expr_position reports whether every node in `items` is
// suitable as a positional argument to a builtin call — i.e. NOT a
// nested cx_element literal (which would indicate data construction,
// e.g. `[sum [a 1] [b 2]]`). Scalar literals, bindings, paren-sequence
// literals, and other expression-position program nodes all pass.
fn all_items_are_expr_position(items []cx.ProgramNode, closures map[string]Closure) bool {
	for it in items {
		if it is cx.ProgramLiteral {
			if it.kind == cx.ProgramLiteralKind.cx_element {
				// The computed-name constructor `[?element NAME-EXPR …]` parses
				// as a cx_element literal with `name_expr` set and `name` empty
				// (parse_computed_element_body). It is an EXPRESSION that
				// evaluates to an element value, never a data child — so it is a
				// valid positional argument. Without this an inline constructor
				// in a bareword call (`[render 'cx' [?element 'batch' …]]`)
				// failed the gate and fell through to data construction (#540):
				// the call silently became a literal element instead of applying.
				if it.name_expr != none {
					continue
				}
				// An OPERATOR-headed element (`[- $n 1]`, `[+ …]`, `[> …]`) is an
				// EXPRESSION that evaluates to a value, not a data child — so it is
				// a valid positional argument. Without this a recursive / sibling
				// call whose args do arithmetic, e.g. `[loop [- $n 1] [$concat …]]`,
				// failed the gate and fell through to data construction (#53):
				// `[loop …]` became a literal `[loop 1 'x']` instead of recursing.
				// A plain bareword data element (`[a 1]`) still signals construction.
				if it.name in operator_element_heads {
					continue
				}
				// A bareword element whose head names a registered CLOSURE is a
				// value-producing CALL (`[f "a"]`), not a data child — so it is a
				// valid positional argument too. Without this a nested user-def call
				// in argument position (`[g [f "a"]]`) failed the gate and fell
				// through to data construction (#59): the OUTER call became a literal
				// `[g 'F(a)']` instead of applying `g`. Nested BUILTIN / `$`-calls
				// (cx.ProgramCall) already pass; this restores the same for user
				// defs. A plain bareword data element (`[a 1]`) still constructs.
				if it.name in closures {
					continue
				}
				return false
			}
		}
		// #858 — A CONSTRUCTION HOLE PROVES THE BODY IS AN ELEMENT BODY.
		//
		// `[?splice]`, `[?attr]` and `[?entry]` are only VALID where an element
		// body, a multi-sibling slot or a map-entry list is admitted (§6.4.2 /
		// §6.4.3). So one appearing among these items is proof that the caller
		// wrote a body, not an argument list — exactly as a plain bareword data
		// child is, and this check already treats that as proof.
		//
		// It used to inspect `cx.ProgramLiteral` nodes only. A hole is a
		// `ProgramDirective`, so it fell straight through, the bareword-call arm
		// at eval_cx_element fired, and the splice landed in an ARGUMENT slot.
		// The report (#858) is what that costs: with `[?def categories …]` in
		// scope, `[categories [?splice …]]` failed with "[?splice …] is valid
		// only in a multi-sibling slot" — a true statement naming the wrong
		// thing, because the body was a body until the call arm took it. Rename
		// either side and it worked, so the capture acted AT A DISTANCE.
		//
		// This deliberately does NOT touch bare-head-as-call, which is
		// load-bearing (#55: `[?def f () "hi"]` then `[f]` runs `f`). No call
		// form can legitimately carry one of these three as an argument, so
		// declining here cannot cost a real call.
		//
		// `[?unquote]` is deliberately NOT in the set: it yields a single node
		// and is meaningful in an expression slot, so it is not proof of
		// construction the way the other three are.
		if it is cx.ProgramDirective {
			if it.name in ['splice', 'attr', 'entry'] {
				return false
			}
		}
	}
	return true
}

// builtin_dispatchable reports whether `name` is recognised as a pure-
// functional builtin (used to gate `[name (args)]` element-shaped call
// dispatch in eval_cx_element).
fn builtin_dispatchable(name string) bool {
	match name {
		'count', 'length', 'empty', 'exists', 'first', 'last', 'identity',
		'upper', 'lower', 'eq', 'max', 'min', 'sum', 'text',
		'range', 'iterate', 'unfold', 'validate-item',
		// §6.5 P1 — string predicates
		'contains', 'starts-with', 'ends-with', 'substring',
		'string-length', 'normalize-space', 'concat', 'string',
		// §6.5 P2 — sequence operations
		'distinct', 'reverse', 'head', 'tail', 'nth', 'position',
		// §6.5 P3 — numeric
		'avg', 'abs', 'floor', 'ceiling', 'round',
		// cx-stdlib/math §3.2 — powers / logs / roots (native primitives
		// backing the math module's [?def] bodies). Domain errors return
		// NaN (IEEE 754) per spec/stdlib_math.md §4.2; never raise.
		'sqrt', 'cbrt', 'exp', 'log', 'log2', 'log10', 'pow',
		// §6.5 P3 cont. — integer parity
		'odd', 'even',
		// math operators (mod / div / idiv) in all four call
		// surfaces: operator-element `[mod a b]`, paren-sequence `[mod (a, b)]`,
		// XPath-call `mod(a, b)`, and (deferred) XPath infix `a mod b`.
		'mod', 'div', 'idiv',
		// §6.5 P4 — logical
		'not', 'and', 'or',
		// §6.5 P5 — node accessors
		'name', 'local-name',
		// §6.5 P6 — type coercion (cast builtin)
		'cast' { return true }
		else { return false }
	}
}

// builtin_fn_name reports whether `name` denotes a builtin that may be
// referenced as a first-class function value. Scoped to the
// pure-functional builtin set (builtin_dispatchable); internal stdlib
// primitives reached only via module bodies are not bare-referenceable.
fn builtin_fn_name(name string) bool {
	return builtin_dispatchable(name)
}

// builtin_takes_seq_arg reports whether a multi-arg whitespace-form
// directive call `[name a b c]` should pack its body items into a
// single sequence-shaped argument (true) or pass them as positional
// arguments (false). Sequence-shaped builtins (min/max/sum/avg/…)
// take a single sequence; fixed-arity numeric / logical / call-shaped
// builtins (mod/div/idiv, lt/gt/eq pairs, …) take positional args.
// Per closure of directive-form dispatch.
fn builtin_takes_seq_arg(name string) bool {
	match name {
		// Sequence-aggregate / sequence-operation builtins: receive one
		// sequence argument.
		'count', 'length', 'empty', 'exists', 'first', 'last',
		'max', 'min', 'sum', 'avg',
		'distinct', 'reverse', 'head', 'tail',
		'and', 'or' { return true }
		else { return false }
	}
}

// builtin_is_scalar_literal_arg reports whether a single-item directive
// body of `cx.ProgramLiteralKind` is eligible to dispatch as a builtin
// call (one scalar argument). Excludes the structural literals
// (sequence/array/map/cx_element/block) which keep their normal
// expression-eval semantics, and `atom_lit` which is its own evaluation
// path.
fn builtin_is_scalar_literal_arg(k cx.ProgramLiteralKind) bool {
	match k {
		.int_lit, .float_lit, .decimal_lit, .bigint_lit, .string_lit, .bool_lit, .duration_lit,
		.date_lit, .datetime_lit { return true }
		else { return false }
	}
}

// builtin_is_numeric_scalar reports whether `name` is in 
// scalar-arg numeric whitelist — builtins that take a single scalar
// argument (rather than a sequence). Used to gate the single-scalar-
// literal directive-form dispatch (`[floor 4.7]`) so that sequence- /
// element-shaped builtins like `[first "a"]` keep their literal-
// element interpretation per the regression-2026-05-22 fixture.
fn builtin_is_numeric_scalar(name string) bool {
	match name {
		'abs', 'floor', 'ceiling', 'round', 'odd', 'even' { return true }
		else { return false }
	}
}

// builtin_arity returns the spec'd argument-count range (min, max) for a
// name in the closed §6.5 builtin set; max -1 means variadic (no upper
// bound). Mirrors the arity column of the code.md §6.5 tables. Used ONLY
// to word the #536 diagnostic (invoke_builtin's arms remain the dispatch
// authority) — a drift here mis-words a message, never changes dispatch.
fn builtin_arity(name string) (int, int) {
	match name {
		'contains', 'starts-with', 'ends-with', 'nth', 'position',
		'mod', 'div', 'idiv', 'pow', 'iterate', 'unfold', 'eq', 'cast' {
			return 2, 2
		}
		'substring', 'range' { return 2, 3 }
		// concat / logical folds / numeric aggregates take either one
		// sequence argument or an n-ary scalar spread (both §6.5 surfaces).
		'concat', 'and', 'or', 'sum', 'max', 'min', 'avg' { return 1, -1 }
		else { return 1, 1 }
	}
}

// builtin_scalar_slot_problem describes an argument that can never
// satisfy a SCALAR argument slot — the two #536 silent-wrong-answer
// classes: absence (the empty sequence / empty node-set) and a
// multi-item sequence / node-set. Returns '' for scalar-shaped values
// and singleton wrappers (those atomize; they are not the problem).
fn builtin_scalar_slot_problem(a cx.Node) string {
	if a is cx.Element {
		if a.name == '' || a.name == seq_marker_name {
			if a.items.len == 0 {
				return 'absence (the empty sequence)'
			}
			if a.items.len > 1 {
				return 'a ${a.items.len}-item sequence'
			}
		}
	}
	return ''
}

// builtin_args_diagnostic composes the CXER0100 err-value for a call to
// a RECOGNIZED §6.5 builtin whose arm rejected the arguments (#536).
// Arity mismatches are named as such; otherwise the message names the
// first structurally-unusable argument (absence / multi-item sequence);
// failing both, the mismatch is scalar typing and the message says so.
// Returned as an err-VALUE (error-as-value model) — it propagates as the
// call result per §9.2.
fn builtin_args_diagnostic(name string, args []cx.Node) cx.Node {
	min_a, max_a := builtin_arity(name)
	if args.len < min_a || (max_a >= 0 && args.len > max_a) {
		want := if max_a < 0 {
			'at least ${min_a}'
		} else if min_a == max_a {
			'${min_a}'
		} else {
			'${min_a}–${max_a}'
		}
		return mk_err('cx-err:CXER0100',
			'${name}: expected ${want} argument(s), got ${args.len} (code.md §6.5)')
	}
	for i, a in args {
		problem := builtin_scalar_slot_problem(a)
		if problem != '' {
			return mk_err('cx-err:CXER0100',
				'${name}: argument ${i + 1} is ${problem} — a single scalar (or a node atomizing to one) is required; bind it or default it with [?else] first (code.md §6.5)')
		}
	}
	// I1 stream 11 (math.md §4.4): a TRANSCENDENTAL over decimal/bigint is
	// its own refusal — CXER3002, cast is the bridge. (Exactness cannot
	// survive an irrational result; the generic signature message hid the
	// actionable fix.)
	if name in ['sqrt', 'cbrt', 'exp', 'log', 'log2', 'log10', 'pow'] {
		for a in args {
			if sn := atomize_exact_num(a) {
				if sn.data_type == cx.ScalarType.decimal_type
					|| sn.data_type == cx.ScalarType.bigint_type {
					return mk_err('cx-err:CXER3002',
						'${name}: transcendental functions are not defined over the exact kinds (decimal/bigint) — [cast … :float] first (math.md §4.4)')
				}
			}
		}
	}
	return mk_err('cx-err:CXER0100',
		'${name}: an argument does not satisfy the builtin signature (scalar kind/type — code.md §6.5)')
}

// builtin_collection_items expands the NON-Element collection kinds —
// IteratorNode (what $filter/$map and the fp combinators return),
// SequenceNode, ArrayNode — to their items via iterate() (#529). Element
// shapes return none so each arm keeps its existing Element readings
// (marker unwrap / table view / plain-element digging) unchanged; only
// the kinds that previously fell through to the scalar pass-through —
// silently returning the WHOLE collection — are captured here.
fn builtin_collection_items(a cx.Node) ?[]cx.Node {
	if a is cx.IteratorNode || a is cx.SequenceNode || a is cx.ArrayNode {
		return iterate(a)
	}
	return none
}

// invoke_builtin implements the closed set of pure-functional
// built-ins the evaluator ships per spec/md §6.3. An arm that bails on
// its arguments returns none so the DISPATCH CHAIN keeps going — a
// stdlib module may legitimately claim the same bare name with another
// signature (similar's 2-arg `distinct`, its 3-arg `contains`). The
// #536 misdiagnosis fix therefore lives at the chain TERMINALS
// (eval_call_undefined / invoke_builtin_closure_l), which convert an
// end-of-chain miss on a recognized §6.5 name into a CXER0100
// diagnostic naming the argument via builtin_args_diagnostic.
fn invoke_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		'caps' {
			// security.md C4 (L104, stream 5): the ACTIVE capability set as
			// an introspectable canonical CX map value. Zero-arg; classified
			// IMPURE (§6.5.x) — a pure body reading the grant set would break
			// the §6.5.1 cap-set-invariance the pure ⇒ deterministic theorem
			// rests on. Impure-without-capability (exception table): a program
			// can only OBSERVE its own authority, never exceed it (§3
			// narrow-only invariant), so introspection is not a gated effect.
			if args.len != 0 { return none }
			return caps_to_cx_value()
		}
		'sqrt', 'cbrt', 'exp', 'log', 'log2', 'log10' {
			// cx-stdlib/math powers/logs/roots: single-arg transcendentals.
			// Int or float input promotes to float; result is always float.
			// Domain errors (sqrt(-1), log(0)) yield NaN / -Inf per IEEE 754
			// (spec/stdlib_math.md §4.2) rather than raising.
			if args.len != 1 { return none }
			x := scalar_to_f64_either(args[0]) or { return none }
			out := match name {
				'sqrt'  { math.sqrt(x) }
				'cbrt'  { math.cbrt(x) }
				'exp'   { math.exp(x) }
				'log'   { math.log(x) }
				'log2'  { math.log2(x) }
				'log10' { math.log10(x) }
				else    { f64(0) }
			}
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(out)
				data_type: cx.ScalarType.float_type
			})
		}
		'pow' {
			// cx-stdlib/math pow(base, exp); always returns float.
			if args.len != 2 { return none }
			base := scalar_to_f64_either(args[0]) or { return none }
			expo := scalar_to_f64_either(args[1]) or { return none }
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(math.pow(base, expo))
				data_type: cx.ScalarType.float_type
			})
		}
		'count', 'length' {
			if args.len != 1 { return none }
			// Force-guard / railway (code.md §1.5/§6.7): count is a force op, so
			// forcing a statically-infinite generator ([$range lo *]/[$iterate])
			// whole surfaces the CXER0100 force-error rather than a bogus finite
			// count. iterate() yields the err as a single item; propagate it.
			if args[0] is cx.IteratorNode {
				forced := iterate(args[0])
				if forced.len == 1 && is_err_value(forced[0]) {
					return forced[0]
				}
				return cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(i64(forced.len))
					data_type: cx.ScalarType.int_type
				})
			}
			n := count_items(args[0])
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(i64(n))
				data_type: cx.ScalarType.int_type
			})
		}
		'empty' {
			if args.len != 1 { return none }
			if args[0] is cx.IteratorNode {
				forced := iterate(args[0])
				if forced.len == 1 && is_err_value(forced[0]) {
					return forced[0]
				}
				return cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(forced.len == 0)
					data_type: cx.ScalarType.bool_type
				})
			}
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(count_items(args[0]) == 0)
				data_type: cx.ScalarType.bool_type
			})
		}
		'exists' {
			// exists(seq) — true iff count(seq) > 0; inverse of empty
			// (code.md §6.5 P1). Backs the `[name]` / `[@name]`
			// step-existence notation atoms ([159a]).
			if args.len != 1 { return none }
			if args[0] is cx.IteratorNode {
				forced := iterate(args[0])
				if forced.len == 1 && is_err_value(forced[0]) {
					return forced[0]
				}
				return cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(forced.len > 0)
					data_type: cx.ScalarType.bool_type
				})
			}
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(count_items(args[0]) > 0)
				data_type: cx.ScalarType.bool_type
			})
		}
		'present' {
			// present(value) — true iff `value` is PRESENT; false ONLY for
			// the absence channel (code.md §6.5, §9.1.2.1 (1)): the empty
			// sequence `()` / an empty node-set, including a lazy Iterator
			// that yields no items. The builtin form of the "some vs none"
			// test of §9.1.2.3.
			//
			// It is NOT `exists`, and the difference is the point (#854,
			// #849): exists/count/empty ask CONTENT ARITY, so over an
			// element they answer that element's own child count — a
			// childless `[input]` reads as exists=false, which made every
			// "did this step match" test wrong on leaf elements. `present`
			// does not look inside at all: a childless element, `""`,
			// `null` and an empty Array are all present. count_items is
			// deliberately NOT consulted here (its content-arity meaning is
			// owner-ruled, #584, and unchanged).
			if args.len != 1 { return none }
			if args[0] is cx.IteratorNode {
				forced := iterate(args[0])
				if forced.len == 1 && is_err_value(forced[0]) {
					return forced[0]
				}
				return cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(forced.len > 0)
					data_type: cx.ScalarType.bool_type
				})
			}
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(!is_absence_node(args[0]))
				data_type: cx.ScalarType.bool_type
			})
		}
		'first' {
			if args.len != 1 { return none }
			a0 := args[0]
			// #529: the non-Element collection kinds ($filter/$map return an
			// eager IteratorNode; SequenceNode/ArrayNode arrive from range and
			// array sources) destructure via iterate(), exactly like nth/count
			// — orderedness is a property, not a representation. Without this
			// the arm fell to the scalar pass-through and returned the WHOLE
			// collection (silent wrong answer).
			if items := builtin_collection_items(a0) {
				if items.len > 0 {
					return items[0]
				}
				return cx.Node(cx.Element{ name: seq_marker_name })
			}
			if a0 is cx.Element {
				// Table sequence view (D22, #404): first row map.
				if td := a0.table_opt() {
					rows := table_row_maps(td)
					if rows.len > 0 {
						return rows[0]
					}
					return cx.Node(cx.Element{ name: seq_marker_name })
				}
			}
			if a0 is cx.Element && a0.items.len > 0 {
				return a0.items[0]
			}
			return args[0]
		}
		'last' {
			// last(seq) — return the final item of a sequence-shaped
			// argument; scalar input passes through. Mirrors first()
			// at the other end of the sequence.
			if args.len != 1 { return none }
			a0 := args[0]
			// #529: non-Element collection kinds — see 'first'.
			if items := builtin_collection_items(a0) {
				if items.len > 0 {
					return items[items.len - 1]
				}
				return cx.Node(cx.Element{ name: seq_marker_name })
			}
			if a0 is cx.Element {
				// Table sequence view (D22, #404): last row map.
				if td := a0.table_opt() {
					rows := table_row_maps(td)
					if rows.len > 0 {
						return rows[rows.len - 1]
					}
					return cx.Node(cx.Element{ name: seq_marker_name })
				}
			}
			if a0 is cx.Element && a0.items.len > 0 {
				return a0.items[a0.items.len - 1]
			}
			return args[0]
		}
		'identity' {
			if args.len != 1 { return none }
			return args[0]
		}
		'upper', 'lower' {
			if args.len != 1 { return none }
			// §6.5 string-builtin argument rule: non-string SCALARS stringify
			// via the canonical scalar printer (scalar_to_string), same as the
			// sibling contains/starts-with/ends-with arms — `[$upper 5]` is
			// '5', not an argument error (#536 sweep).
			s := scalar_to_string(args[0]) or { return none }
			out := if name == 'upper' { s.to_upper() } else { s.to_lower() }
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(out)
				data_type: cx.ScalarType.string_type
			})
		}
		'eq' {
			if args.len != 2 { return none }
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(nodes_equal(args[0], args[1]))
				data_type: cx.ScalarType.bool_type
			})
		}
		'range' {
			// `range(start, end)` / `range(start, end, step)` returns the
			// inclusive integer sequence start..end (optionally strided)
			// as a SequenceNode. Per spec/code.md §6.3 builtin-call set
			// Used by `:in N to M [by S]` sugar
			// and by program-svc-019-style streaming-body fixtures.
			if args.len != 2 && args.len != 3 { return none }
			// `to *` open-end sentinel (the prefix `[$range lo *]` substitutes
			// the atom `:_open_end_` for the upper bound). Returns an unbounded
			// IteratorNode (iter_range_open); forcing it without a terminator
			// (`[take]`/`[take-while]`) raises CXER0100 per D19.
			if is_open_end_marker(args[1]) {
				mut iter_args := [args[0]]
				if args.len == 3 {
					iter_args << args[2]
					// D21 mirror — step-of-zero rejected up front so
					// the error surfaces at construction, not at the
					// (deferred) materialisation guard.
					step := scalar_int(args[2]) or { return none }
					if step == 0 {
						return mk_err('cx-err:CXER0100', 'range: step cannot be zero')
					}
				}
				return cx.new_iterator(.iter_range_open, iter_args)
			}
			// ── Numeric-domain dispatch (C-gen-2, code.md §6.3) ──
			// datetime: lo or hi is a datetime scalar → duration-stepped range.
			if scalar_is_datetime(args[0]) || scalar_is_datetime(args[1]) {
				return eval_range_datetime(args)
			}
			// int (default): every numeric arg is an int.
			lo_i := scalar_int(args[0])
			hi_i := scalar_int(args[1])
			step_int_ok := args.len < 3 || scalar_int(args[2]) != none
			if lo_i != none && hi_i != none && step_int_ok {
				start := lo_i
				end := hi_i
				mut step := i64(1)
				if args.len == 3 {
					step = scalar_int(args[2]) or { return none }
					if step == 0 {
						// D21 — step-of-zero is an evaluation error.
						return mk_err('cx-err:CXER0100', 'range: step cannot be zero')
					}
				}
				// D20 — empty-range when direction disagrees with step.
				if step > 0 && end < start {
					return cx.Node(cx.Element{ name: seq_marker_name })
				}
				if step < 0 && end > start {
					return cx.Node(cx.Element{ name: seq_marker_name })
				}
				mut cap := if step > 0 { int((end - start) / step + 1) }
				             else { int((start - end) / (-step) + 1) }
				if cap < 0 { cap = 0 }
				mut items := []cx.Node{cap: cap}
				mut i := start
				if step > 0 {
					for i <= end {
						items << cx.Node(cx.ScalarNode{
							value:     cx.ScalarValue(i)
							data_type: cx.ScalarType.int_type
						})
						i += step
					}
				} else {
					for i >= end {
						items << cx.Node(cx.ScalarNode{
							value:     cx.ScalarValue(i)
							data_type: cx.ScalarType.int_type
						})
						i += step
					}
				}
				return cx.Node(cx.Element{ name: seq_marker_name, items: items })
			}
			// float (count-based; step REQUIRED, no implicit 1.0).
			return eval_range_float(args)
		}
		'iterate' {
			// [$iterate f seed] — functional progression seed, f(seed), …
			// (always lazy/infinite). Validate f is callable up front
			// (N-GEN-4: non-callable -> CXER0100); the closure applies per
			// pull in the for-comp walker. Forcing whole -> CXER0100 (§1.5).
			if args.len != 2 { return none }
			if !is_fn_value(args[0]) {
				return mk_err('cx-err:CXER0100', 'iterate: f must be callable')
			}
			return cx.new_iterator(.iter_iterate, [args[0], args[1]])
		}
		'unfold' {
			// [$unfold f seed] — general anamorphism. f returns () (stop) or a
			// 2-element [value, next-state] Array. Lazy Iterator, force-
			// realizable (eval finalize / the for-comp walker run it, budget-
			// backstopped). Validate f callable up front (N-GEN-4).
			if args.len != 2 { return none }
			if !is_fn_value(args[0]) {
				return mk_err('cx-err:CXER0100', 'unfold: f must be callable')
			}
			return cx.new_iterator(.iter_unfold, [args[0], args[1]])
		}
		'max', 'min' {
			// max(seq) / min(seq) over a sequence-shaped argument (or a
			// single scalar). Numeric only — non-numeric values are
			// skipped silently per spec/code.md §6.3 numeric-builtin
			// semantics. Empty sequence yields 0 (consistent with
			// count(empty) → 0).
			if args.len == 0 { return none }
			mut best_i := i64(0)
			mut best_f := f64(0)
			mut use_float := false
			mut seen := false
			// Two surfaces (§6.3): a single sequence argument
			// (`[$min (5,3,8)]`) iterates that sequence; multiple scalar
			// arguments (`[$min 5 3 8]`) fold over the argument list.
			items := if args.len == 1 { iterate(args[0]) } else { args }
			for raw in items {
				// Atomize attribute-shaped Elements (single ScalarNode body)
				// to their scalar value — same convention as `sum`.
				mut it := raw
				if raw is cx.Element {
					if raw.items.len == 1 {
						only := raw.items[0]
						if only is cx.ScalarNode {
							it = cx.Node(only)
						}
					}
				}
				if it is cx.ScalarNode {
					v := it.value
					mut as_i := i64(0)
					mut as_f := f64(0)
					mut got_int := false
					mut got_float := false
					match v {
						i64 { as_i = v; got_int = true }
						f64 { as_f = v; got_float = true }
						string {
							t := v.trim_space()
							if t.len > 0 && parses_as_i64(t) {
								as_i = t.i64(); got_int = true
							} else if t.len > 0 && parses_as_f64(t) {
								as_f = t.f64(); got_float = true
							}
						}
						else {}
					}
					if got_int {
						if !seen {
							best_i = as_i
							seen = true
						} else if use_float {
							f := f64(as_i)
							if (name == 'max' && f > best_f) || (name == 'min' && f < best_f) {
								best_f = f
							}
						} else {
							if (name == 'max' && as_i > best_i) || (name == 'min' && as_i < best_i) {
								best_i = as_i
							}
						}
					} else if got_float {
						if !seen {
							best_f = as_f
							use_float = true
							seen = true
						} else {
							if !use_float {
								best_f = f64(best_i)
								use_float = true
							}
							if (name == 'max' && as_f > best_f) || (name == 'min' && as_f < best_f) {
								best_f = as_f
							}
						}
					}
				}
			}
			if !seen {
				return cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(i64(0))
					data_type: cx.ScalarType.int_type
				})
			}
			if use_float {
				return cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(best_f)
					data_type: cx.ScalarType.float_type
				})
			}
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(best_i)
				data_type: cx.ScalarType.int_type
			})
		}
		'sum' {
			// sum(seq) — total numeric scalars in a sequence. Non-
			// numeric items are skipped (matching max/min). Empty
			// sequence yields 0. Integer-only inputs return an
			// integer; any float promotes the result to float.
			//
			// Attribute-shaped Elements (single ScalarNode body, as
			// materialised by the `@name` / `attribute::name` path
			// step) atomize to their scalar value per XPath 3.1
			// §14.4.4. Numeric strings parse as numbers (XPath fn:sum
			// applies fn:number to non-numeric atomized values).
			if args.len == 0 { return none }
			mut total_i := i64(0)
			mut total_f := f64(0)
			mut use_float := false
			// Single sequence argument iterates that sequence; multiple
			// scalar arguments fold over the argument list (see max/min).
			items := if args.len == 1 { iterate(args[0]) } else { args }
			for raw in items {
				// Atomize: attribute-shaped Elements (single scalar
				// body) flatten to their scalar; everything else passes
				// through as-is.
				mut it := raw
				if raw is cx.Element {
					if raw.items.len == 1 {
						only := raw.items[0]
						if only is cx.ScalarNode {
							it = cx.Node(only)
						}
					}
				}
				if it is cx.ScalarNode {
					v := it.value
					match v {
						i64 {
							if use_float { total_f += f64(v) } else { total_i = checked_add_i64(total_i, v) or { return math_overflow_err('sum') } }
						}
						f64 {
							if !use_float {
								total_f = f64(total_i)
								use_float = true
							}
							total_f += v
						}
						string {
							// XPath fn:sum applies fn:number() to
							// non-numeric atomized values. Try i64 first
							// (preserves integer-only sum result type),
							// then f64; on parse failure the value is
							// skipped (matches max/min's non-numeric
							// skip).
							trimmed := v.trim_space()
							if trimmed.len > 0 && parses_as_i64(trimmed) {
								v_int := trimmed.i64()
								if use_float { total_f += f64(v_int) } else { total_i = checked_add_i64(total_i, v_int) or { return math_overflow_err('sum') } }
							} else if trimmed.len > 0 && parses_as_f64(trimmed) {
								v_f := trimmed.f64()
								if !use_float {
									total_f = f64(total_i)
									use_float = true
								}
								total_f += v_f
							}
						}
						else {}
					}
				}
			}
			if use_float {
				return cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(total_f)
					data_type: cx.ScalarType.float_type
				})
			}
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(total_i)
				data_type: cx.ScalarType.int_type
			})
		}
		'text' {
			// text(elem) — return the body text of an element as a
			// string scalar. Concatenates text nodes; scalars are
			// stringified; empty bodies yield "". The natural
			// complement to body-position binding when the user
			// wants the *value* rather than the element wrapper.
			if args.len != 1 { return none }
			a0 := args[0]
			if a0 is cx.Element {
				mut out := ''
				for c in a0.items {
					match c {
						cx.TextNode { out += c.value }
						cx.ScalarNode { out += cx.scalar_value_str_public(c.value) }
						else {}
					}
				}
				return cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(out)
					data_type: cx.ScalarType.string_type
				})
			}
			if a0 is cx.ScalarNode {
				return cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(cx.scalar_value_str_public(a0.value))
					data_type: cx.ScalarType.string_type
				})
			}
			if a0 is cx.TextNode {
				return cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(a0.value)
					data_type: cx.ScalarType.string_type
				})
			}
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue('')
				data_type: cx.ScalarType.string_type
			})
		}
		'validate-item' {
			// Fixture-only validator (spec/code.md §11.6 gate-4 helper):
			// returns `[ok id=<id-attr>]` for items without a `bad=true`
			// attribute; returns `[err …]` otherwise. Used by
			// program-err-003-on-error-recovery. (the invalid
			// marker is a `bad=true` attribute, not a `:bad` type-sigil or
			// labeled slot, both of which are removed.)
			if args.len != 1 { return none }
			it := args[0]
			if it is cx.Element {
				mut has_bad := false
				mut id_val := cx.ScalarValue(i64(0))
				for a in it.attrs {
					if a.name == 'bad' && a.value == cx.ScalarValue(true) {
						has_bad = true
					}
					if a.name == 'id' {
						id_val = a.value
					}
				}
				if has_bad {
					return mk_err('cx-err:CXER0100', 'validate-item rejected')
				}
				return cx.Node(cx.Element{
					name:  'ok'
					attrs: [
						cx.Attribute{ name: 'id', value: id_val },
					]
				})
			}
			return none
		}
		// ── §6.5 P1 — string built-ins ──────────────────────────────
		'contains' {
			if args.len != 2 { return none }
			s := scalar_to_string(args[0]) or { return none }
			sub := scalar_to_string(args[1]) or { return none }
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(s.contains(sub))
				data_type: cx.ScalarType.bool_type
			})
		}
		'starts-with' {
			if args.len != 2 { return none }
			s := scalar_to_string(args[0]) or { return none }
			pre := scalar_to_string(args[1]) or { return none }
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(s.starts_with(pre))
				data_type: cx.ScalarType.bool_type
			})
		}
		'ends-with' {
			if args.len != 2 { return none }
			s := scalar_to_string(args[0]) or { return none }
			suf := scalar_to_string(args[1]) or { return none }
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(s.ends_with(suf))
				data_type: cx.ScalarType.bool_type
			})
		}
		'substring' {
			// substring(s, start, len?) — 1-indexed start, XPath
			// fn:substring semantics. Out-of-range positions clamp.
			if args.len != 2 && args.len != 3 { return none }
			s := scalar_to_string(args[0]) or { return none }
			start_i := scalar_int(args[1]) or { return none }
			runes := s.runes()
			// XPath: substring("hello", 1) yields "hello"; start clamps to 1.
			mut from := int(start_i) - 1
			if from < 0 { from = 0 }
			if from > runes.len { from = runes.len }
			mut to := runes.len
			if args.len == 3 {
				len_i := scalar_int(args[2]) or { return none }
				want := int(len_i)
				if want < 0 { to = from } else {
					to = from + want
					if to > runes.len { to = runes.len }
				}
			}
			out := runes[from..to].string()
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(out)
				data_type: cx.ScalarType.string_type
			})
		}
		'string-length' {
			// fn:string-length(s) accepts both string scalars and
			// node/path arguments (XPath 3.1 §14.5.6) — non-scalar
			// arguments use the fn:string() string-value coercion.
			if args.len != 1 { return none }
			s := xpath_string_value(args[0])
			n := s.runes().len
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(i64(n))
				data_type: cx.ScalarType.int_type
			})
		}
		'normalize-space' {
			// Strip leading + trailing whitespace, collapse internal
			// whitespace runs to a single ASCII space — XPath
			// fn:normalize-space semantics.
			if args.len != 1 { return none }
			s := scalar_to_string(args[0]) or { return none }
			mut out := []u8{cap: s.len}
			mut in_ws := true   // start: skip leading
			for c in s {
				is_ws := c == ` ` || c == `\t` || c == `\n` || c == `\r`
				if is_ws {
					if !in_ws {
						out << u8(` `)
						in_ws = true
					}
				} else {
					out << c
					in_ws = false
				}
			}
			// strip trailing space if present
			if out.len > 0 && out[out.len - 1] == ` ` {
				out.delete_last()
			}
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(out.bytestr())
				data_type: cx.ScalarType.string_type
			})
		}
		'concat' {
			if args.len < 1 { return none }
			mut out := ''
			for a in args {
				out += scalar_to_string(a) or { return none }
			}
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(out)
				data_type: cx.ScalarType.string_type
			})
		}
		// ── §6.5 P2 — sequence operations ───────────────────────────
		'head' {
			if args.len != 1 { return none }
			a0 := args[0]
			// #529: non-Element collection kinds — see 'first' (head is its
			// synonym, XQuery fn:head parity).
			if citems := builtin_collection_items(a0) {
				if citems.len > 0 {
					return citems[0]
				}
				return cx.Node(cx.Element{ name: seq_marker_name })
			}
			if a0 is cx.Element && a0.items.len > 0 {
				return a0.items[0]
			}
			return args[0]
		}
		'tail' {
			if args.len != 1 { return none }
			a0 := args[0]
			// #529: non-Element collection kinds — an iterator's tail was
			// silently the EMPTY sequence before this.
			if citems := builtin_collection_items(a0) {
				if citems.len > 1 {
					return cx.Node(cx.Element{ name: seq_marker_name, items: citems[1..].clone() })
				}
				return cx.Node(cx.Element{ name: seq_marker_name })
			}
			if a0 is cx.Element && a0.items.len > 0 {
				rest := a0.items[1..]
				mut items := []cx.Node{cap: rest.len}
				for it in rest { items << it }
				return cx.Node(cx.Element{ name: seq_marker_name, items: items })
			}
			return cx.Node(cx.Element{ name: seq_marker_name })
		}
		'reverse' {
			if args.len != 1 { return none }
			a0 := args[0]
			// #529: non-Element collection kinds — an iterator previously
			// passed through UNREVERSED.
			if citems := builtin_collection_items(a0) {
				mut ritems := []cx.Node{cap: citems.len}
				for i := citems.len - 1; i >= 0; i-- {
					ritems << citems[i]
				}
				return cx.Node(cx.Element{ name: seq_marker_name, items: ritems })
			}
			if a0 is cx.Element && (a0.name == '' || a0.name == seq_marker_name) {
				mut items := []cx.Node{cap: a0.items.len}
				for i := a0.items.len - 1; i >= 0; i-- {
					items << a0.items[i]
				}
				return cx.Node(cx.Element{ name: seq_marker_name, items: items })
			}
			return args[0]
		}
		'distinct' {
			if args.len != 1 { return none }
			items := iterate(args[0])
			mut seen := []cx.Node{}
			for it in items {
				mut dup := false
				for s in seen {
					if nodes_equal(it, s) { dup = true; break }
				}
				if !dup { seen << it }
			}
			return cx.Node(cx.Element{ name: seq_marker_name, items: seen })
		}
		'nth' {
			// nth(seq, n) — 1-indexed access; out-of-range raises
			// cx-err:CXER0100 per §6.5.
			if args.len != 2 { return none }
			n := scalar_int(args[1]) or { return none }
			items := iterate(args[0])
			idx := int(n) - 1
			if idx < 0 || idx >= items.len {
				return mk_err('cx-err:CXER0100',
					'nth: index ${n} out of range (1..${items.len})')
			}
			return items[idx]
		}
		'position' {
			// position(seq, item) — 1-based index of first match (or 0
			// if no match). Uses nodes_equal for structural compare.
			if args.len != 2 { return none }
			items := iterate(args[0])
			target := args[1]
			mut found := i64(0)
			for i, it in items {
				if nodes_equal(it, target) {
					found = i64(i + 1)
					break
				}
			}
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(found)
				data_type: cx.ScalarType.int_type
			})
		}
		// ── §6.5 P3 — numeric ───────────────────────────────────────
		'avg' {
			if args.len != 1 { return none }
			arg := args[0]
			mut total := f64(0)
			mut count := 0
			items := iterate(arg)
			for raw in items {
				// Atomize attribute-shaped Elements (matches `sum` / `min` / `max`).
				mut it := raw
				if raw is cx.Element {
					if raw.items.len == 1 {
						only := raw.items[0]
						if only is cx.ScalarNode {
							it = cx.Node(only)
						}
					}
				}
				if it is cx.ScalarNode {
					v := it.value
					match v {
						i64 { total += f64(v); count++ }
						f64 { total += v; count++ }
						string {
							t := v.trim_space()
							if t.len > 0 && parses_as_i64(t) {
								total += f64(t.i64()); count++
							} else if t.len > 0 && parses_as_f64(t) {
								total += t.f64(); count++
							}
						}
						else {}
					}
				}
			}
			if count == 0 {
				return cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(f64(0.0))
					data_type: cx.ScalarType.float_type
				})
			}
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(total / f64(count))
				data_type: cx.ScalarType.float_type
			})
		}
		'abs' {
			if args.len != 1 { return none }
			a0 := args[0]
			if a0 is cx.ScalarNode {
				// I1 stream 11: exact-family arms — abs keeps the kind (and
				// a decimal's scale); math.md §4.4 non-transcendentals are
				// exact over decimal/bigint.
				if a0.data_type == cx.ScalarType.decimal_type
					|| a0.data_type == cx.ScalarType.bigint_type {
					img := cx.cx_exact_num_image(a0) or { return none }
					return cx.Node(cx.ScalarNode{
						value:     cx.ScalarValue(cx.cx_exact_abs(img))
						data_type: a0.data_type
					})
				}
				v := a0.value
				match v {
					i64 {
						out := if v < 0 { -v } else { v }
						return cx.Node(cx.ScalarNode{
							value:     cx.ScalarValue(out)
							data_type: cx.ScalarType.int_type
						})
					}
					f64 {
						out := if v < 0 { -v } else { v }
						return cx.Node(cx.ScalarNode{
							value:     cx.ScalarValue(out)
							data_type: cx.ScalarType.float_type
						})
					}
					else { return none }
				}
			}
			return none
		}
		'floor' {
			if args.len != 1 { return none }
			a0 := args[0]
			if a0 is cx.ScalarNode {
				if fixed := exact_integral_result(a0, 'floor') { return fixed }
				v := a0.value
				match v {
					i64 { return a0 }
					f64 {
						mut out := i64(v)
						if v < 0 && f64(out) != v { out -= 1 }
						return cx.Node(cx.ScalarNode{
							value:     cx.ScalarValue(out)
							data_type: cx.ScalarType.int_type
						})
					}
					else { return none }
				}
			}
			return none
		}
		'ceiling' {
			if args.len != 1 { return none }
			a0 := args[0]
			if a0 is cx.ScalarNode {
				if fixed := exact_integral_result(a0, 'ceiling') { return fixed }
				v := a0.value
				match v {
					i64 { return a0 }
					f64 {
						mut out := i64(v)
						if v > 0 && f64(out) != v { out += 1 }
						return cx.Node(cx.ScalarNode{
							value:     cx.ScalarValue(out)
							data_type: cx.ScalarType.int_type
						})
					}
					else { return none }
				}
			}
			return none
		}
		'round' {
			// Half-away-from-zero rounding (XPath fn:round convention).
			if args.len != 1 { return none }
			a0 := args[0]
			if a0 is cx.ScalarNode {
				if fixed := exact_integral_result(a0, 'round') { return fixed }
				v := a0.value
				match v {
					i64 { return a0 }
					f64 {
						out := if v >= 0 {
							i64(v + 0.5)
						} else {
							-i64(-v + 0.5)
						}
						return cx.Node(cx.ScalarNode{
							value:     cx.ScalarValue(out)
							data_type: cx.ScalarType.int_type
						})
					}
					else { return none }
				}
			}
			return none
		}
		'odd', 'even' {
			// Integer parity. Spelled without the `?` suffix because the
			// lexer's `?` token belongs to the directive-marker namespace
			// (`[?for]`, `[?let]`, …); naming the builtin `odd?` would
			// collide. `[odd n]` / `[even n]` are the surface forms.
			if args.len != 1 { return none }
			a0 := args[0]
			if a0 is cx.ScalarNode {
				v := a0.value
				if v is i64 {
					is_even := (v % 2) == 0
					out := if name == 'even' { is_even } else { !is_even }
					return cx.Node(cx.ScalarNode{
						value:     cx.ScalarValue(out)
						data_type: cx.ScalarType.bool_type
					})
				}
			}
			return none
		}
		// ── math operators: mod / div / idiv ──────────────
		'mod' {
			// mod(a, b): remainder with sign of dividend per XPath 3.1
			// §3.5. Integer-only when both args are int; promotes to float
			// when either arg is float (OQ3 of).
			if args.len != 2 {
				return mk_err('cx-err:CXER0100',
					'mod takes 2 arguments, got ${args.len}')
			}
			// Strict numeric atomization — same contract as [+]/[-]/[*]
			// (atomize_numeric): only i64/f64-TYPED scalars qualify. A
			// bigint or decimal (string-stored, NOT f64-representable) and a
			// string-typed scalar all reject here rather than silently
			// lossy-converting (#38: idiv/mod were i64-wrapping a bigint).
			a_f, a_is_int := atomize_numeric(args[0]) or {
				return mk_err('cx-err:CXER0100',
					'mod: argument 1 is not numeric')
			}
			b_f, b_is_int := atomize_numeric(args[1]) or {
				return mk_err('cx-err:CXER0100',
					'mod: argument 2 is not numeric')
			}
			if b_f == 0.0 {
				return mk_err('cx-err:CXER0101', 'division by zero')
			}
			if a_is_int && b_is_int {
				a_i := i64(a_f)
				b_i := i64(b_f)
				// V's `%` matches XPath sign-of-dividend semantics
				// (-7 mod 3 → -1).
				return cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(a_i % b_i)
					data_type: cx.ScalarType.int_type
				})
			}
			// Float modulo via fmod-equivalent (sign of dividend per
			// IEEE 754, matching XPath 3.1 §3.5).
			q := i64(a_f / b_f)
			r := a_f - f64(q) * b_f
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(r)
				data_type: cx.ScalarType.float_type
			})
		}
		'div' {
			// div(a, b) per code.md §6.5: TRUE division (float result) when
			// either operand is a float; INTEGER division (truncated toward
			// zero, int result) when BOTH operands are integers. (`idiv` is
			// always-integer regardless of operand kinds.)
			if args.len != 2 {
				return mk_err('cx-err:CXER0100',
					'div takes 2 arguments, got ${args.len}')
			}
			// Strict numeric atomization (see mod, above): bigint/decimal/
			// string operands reject instead of lossy-converting (#38).
			a_f, a_int := atomize_numeric(args[0]) or {
				return mk_err('cx-err:CXER0100',
					'div: argument 1 is not numeric')
			}
			b_f, b_int := atomize_numeric(args[1]) or {
				return mk_err('cx-err:CXER0100',
					'div: argument 2 is not numeric')
			}
			if b_f == 0.0 {
				return mk_err('cx-err:CXER0101', 'division by zero')
			}
			if a_int && b_int {
				// V's i64 cast truncates toward zero.
				return cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(i64(a_f / b_f))
					data_type: cx.ScalarType.int_type
				})
			}
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(a_f / b_f)
				data_type: cx.ScalarType.float_type
			})
		}
		'idiv' {
			// idiv(a, b): integer division truncating toward zero per
			// XPath 3.1 §3.5 (OQ1 of). Inputs must both be
			// numeric; result is int.
			if args.len != 2 {
				return mk_err('cx-err:CXER0100',
					'idiv takes 2 arguments, got ${args.len}')
			}
			// Strict numeric atomization (see mod, above): bigint/decimal/
			// string operands reject instead of lossy-converting (#38).
			a_f, _ := atomize_numeric(args[0]) or {
				return mk_err('cx-err:CXER0100',
					'idiv: argument 1 is not numeric')
			}
			b_f, _ := atomize_numeric(args[1]) or {
				return mk_err('cx-err:CXER0100',
					'idiv: argument 2 is not numeric')
			}
			if b_f == 0.0 {
				return mk_err('cx-err:CXER0101', 'division by zero')
			}
			// V's i64 cast already truncates toward zero.
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(i64(a_f / b_f))
				data_type: cx.ScalarType.int_type
			})
		}
		// ── §6.5 P4 — logical ───────────────────────────────────────
		'not' {
			if args.len != 1 { return none }
			ebv := node_ebv(args[0]) or { return iterator_ebv_err() }
			negated := !ebv
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(negated)
				data_type: cx.ScalarType.bool_type
			})
		}
		'and' {
			if args.len < 1 { return none }
			mut all := true
			for a in args {
				ebv := node_ebv(a) or { return iterator_ebv_err() }
				if !ebv { all = false; break }
			}
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(all)
				data_type: cx.ScalarType.bool_type
			})
		}
		'or' {
			if args.len < 1 { return none }
			mut any := false
			for a in args {
				ebv := node_ebv(a) or { return iterator_ebv_err() }
				if ebv { any = true; break }
			}
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(any)
				data_type: cx.ScalarType.bool_type
			})
		}
		// ── §6.5 P5 — node accessors ────────────────────────────────
		// name() / local-name() per XPath 3.1 §14.5.3 / §14.5.4 — return
		// the QName or local part of the argument node. For path-shaped
		// arguments the singleton-sequence wrapper is unwrapped first
		// (spec/cxpath.md §1.1 / §8.5 worked examples).
		'name' {
			if args.len != 1 { return none }
			el := element_for_node_accessor(args[0]) or {
				return mk_err('cx-err:CXER0100',
					'name(): expected single element argument, got empty or multi-item sequence')
			}
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(el.name)
				data_type: cx.ScalarType.string_type
			})
		}
		'local-name' {
			if args.len != 1 { return none }
			el := element_for_node_accessor(args[0]) or {
				return mk_err('cx-err:CXER0100',
					'local-name(): expected single element argument, got empty or multi-item sequence')
			}
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(local_name_of(el.name))
				data_type: cx.ScalarType.string_type
			})
		}
		// fn:string() per XPath 3.1 §14.5.1 — the string-value of the
		// argument. Accepts scalars, elements, attribute-shaped path
		// results, and sequence wrappers.
		'string' {
			if args.len != 1 { return none }
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(xpath_string_value(args[0]))
				data_type: cx.ScalarType.string_type
			})
		}
		// ── §6.5 P6 — type coercion (cast builtin) ────────────────────
		'cast' {
			// `cast(value, :type-tag)` — explicit kind coercion. The
			// type-tag MUST be an atom literal whose name is one of the
			// scalar kinds: int, float, string, bool, atom.
			// Compound type expressions (`[or T1 T2]`, `[sequence T]`)
			// from are reserved for a follow-on iteration;
			// the slot is held by accepting only kind-name atoms here.
			//
			// On invalid coercion (e.g. cast "abc" :int), returns an
			// `[err :code "cx-err:CXER0290" :message ...]` value rather
			// than raising EvalError — matches the err-value-propagation
			// convention so callers can [?try] / [?fallback] over it.
			if args.len != 2 { return none }
			return cast_value(args[0], args[1])
		}
		else {
			return none
		}
	}
}

// cast_value implements the cast builtin per spec/code.md §6.5 P6.
// Returns a CX scalar of the target kind, or an err-value (CXER0290)
// when the coercion is not defined / fails to parse.
fn cast_value(v cx.Node, target cx.Node) cx.Node {
	// Extract the type-tag — must be an atom-typed scalar.
	tag := match target {
		cx.ScalarNode {
			if target.data_type == cx.ScalarType.atom_type {
				tv := target.value
				if tv is string { tv } else { '' }
			} else { '' }
		}
		else { '' }
	}
	if tag == '' {
		return mk_err('cx-err:CXER0290',
			'cast: target must be an atom-literal type-tag (e.g. :int, :float, :string, :bool, :atom)')
	}
	// Dispatch on target kind. Accepted kinds: int, float,
	// string, bool, atom. (Future: date, datetime, bytes; compound
	// type expressions via.)
	return match tag {
		'string'  { cast_to_string(v) }
		'int'     { cast_to_int(v) }
		'float'   { cast_to_float(v) }
		'bool'    { cast_to_bool(v) }
		'atom'    { cast_to_atom(v) }
		// I1 stream 11 (L44): decimal/bigint cast arms — the ONLY bridge
		// between the exact family and float.
		'decimal' { cast_to_decimal(v) }
		'bigint'  { cast_to_bigint(v) }
		else {
			mk_err('cx-err:CXER0290',
				'cast: unknown target kind :${tag} (supported target kinds: :int, :float, :string, :bool, :atom, :decimal, :bigint)')
		}
	}
}

// cast_to_decimal (L44): string → strict fixed-point parse; int/bigint
// embed; float → shortest-round-trip digits (Ryū) as a fixed-point image;
// non-finite floats and non-conforming strings are CXER0290.
fn cast_to_decimal(v cx.Node) cx.Node {
	n := if v is cx.Element && v.items.len == 1 { v.items[0] } else { v }
	if n is cx.ScalarNode {
		sv := n.value
		match n.data_type {
			.decimal_type {
				return n
			}
			.int_type {
				if sv is i64 {
					return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(sv.str()), data_type: cx.ScalarType.decimal_type })
				}
			}
			.bigint_type {
				if sv is string {
					return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(sv), data_type: cx.ScalarType.decimal_type })
				}
			}
			.float_type {
				if sv is f64 {
					img := cx.cx_decimal_image_from_float(sv) or {
						return mk_err('cx-err:CXER0290', 'cast: non-finite float has no decimal value')
					}
					return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(img), data_type: cx.ScalarType.decimal_type })
				}
			}
			.string_type {
				if sv is string {
					norm := cx.normalize_decimal_token(sv) or {
						return mk_err('cx-err:CXER0290', 'cast: `${sv}` is not a fixed-point decimal literal')
					}
					return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(norm), data_type: cx.ScalarType.decimal_type })
				}
			}
			else {}
		}
	}
	if n is cx.TextNode {
		norm := cx.normalize_decimal_token(n.value) or {
			return mk_err('cx-err:CXER0290', 'cast: `${n.value}` is not a fixed-point decimal literal')
		}
		return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(norm), data_type: cx.ScalarType.decimal_type })
	}
	return mk_err('cx-err:CXER0290', 'cast: value is not coercible to :decimal')
}

// cast_to_bigint (L44): string → strict base-10 integer parse; int embeds;
// decimal → integral-only (fraction digits must all be zero).
fn cast_to_bigint(v cx.Node) cx.Node {
	n := if v is cx.Element && v.items.len == 1 { v.items[0] } else { v }
	if n is cx.ScalarNode {
		sv := n.value
		match n.data_type {
			.bigint_type {
				return n
			}
			.int_type {
				if sv is i64 {
					return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(sv.str()), data_type: cx.ScalarType.bigint_type })
				}
			}
			.decimal_type {
				if sv is string {
					norm := cx.normalize_bigint_token(sv.all_before('.')) or {
						return mk_err('cx-err:CXER0290', 'cast: `${sv}` is not integral')
					}
					frac := sv.all_after('.')
					if frac != sv {
						for c in frac {
							if c != `0` {
								return mk_err('cx-err:CXER0290', 'cast: `${sv}` is not integral — :bigint requires a whole value')
							}
						}
					}
					return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(norm), data_type: cx.ScalarType.bigint_type })
				}
			}
			.string_type {
				if sv is string {
					norm := cx.normalize_bigint_token(sv) or {
						return mk_err('cx-err:CXER0290', 'cast: `${sv}` is not a base-10 integer literal')
					}
					return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(norm), data_type: cx.ScalarType.bigint_type })
				}
			}
			else {}
		}
	}
	if n is cx.TextNode {
		norm := cx.normalize_bigint_token(n.value) or {
			return mk_err('cx-err:CXER0290', 'cast: `${n.value}` is not a base-10 integer literal')
		}
		return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(norm), data_type: cx.ScalarType.bigint_type })
	}
	return mk_err('cx-err:CXER0290', 'cast: value is not coercible to :bigint')
}

// cast_to_string renders any source value to its canonical string form.
// - element → body text via the same rule as `text(elem)`
// - scalars → canonical printer (string passes through; null → "null";
//   bool → "true"/"false"; numeric → decimal repr; atom → name without
//   leading colon)
// - text-node → its raw text
// - null → CXER0290 (null is not coercible per the rule "null → any =
//   error; users must check first").
fn cast_to_string(v cx.Node) cx.Node {
	if v is cx.ScalarNode {
		sv := v.value
		if sv is cx.NullValue {
			return mk_err('cx-err:CXER0290',
				'cast: cannot cast null to :string — check for null explicitly first')
		}
		if sv is string {
			return cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(sv)
				data_type: cx.ScalarType.string_type
			})
		}
		return cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(cx.scalar_value_str_public(sv))
			data_type: cx.ScalarType.string_type
		})
	}
	if v is cx.TextNode {
		return cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(v.value)
			data_type: cx.ScalarType.string_type
		})
	}
	if v is cx.Element {
		// element-to-string renders the body text (concat of children).
		// Same logic as the `text` builtin so cast and text are
		// consistent for element bodies.
		mut out := ''
		for c in v.items {
			match c {
				cx.TextNode { out += c.value }
				cx.ScalarNode {
					sv := c.value
					if sv is string { out += sv }
					else { out += cx.scalar_value_str_public(sv) }
				}
				else {}
			}
		}
		return cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(out)
			data_type: cx.ScalarType.string_type
		})
	}
	return mk_err('cx-err:CXER0290',
		'cast: cannot cast ${typeof(v).name} to :string')
}

// cast_to_int extracts an integer from a scalar / element body. Float
// inputs truncate toward zero (documented). String inputs parse as a
// decimal integer; on parse failure CXER0290.
fn cast_to_int(v cx.Node) cx.Node {
	// Element: cast the body-text representation (same path as text()).
	if v is cx.Element {
		body := cast_to_string(v)
		return cast_to_int(body)
	}
	if v is cx.TextNode {
		return parse_int_string(v.value)
	}
	if v is cx.ScalarNode {
		sv := v.value
		match sv {
			i64 {
				return cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(sv)
					data_type: cx.ScalarType.int_type
				})
			}
			f64 {
				// Truncate toward zero per the coercion table.
				return cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(i64(sv))
					data_type: cx.ScalarType.int_type
				})
			}
			bool {
				return cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(if sv { i64(1) } else { i64(0) })
					data_type: cx.ScalarType.int_type
				})
			}
			string {
				if v.data_type == cx.ScalarType.atom_type {
					return mk_err('cx-err:CXER0290',
						'cast: cannot cast atom :${sv} to :int — atoms are not numeric (use a [?match] arm)')
				}
				// I1 L44: decimal → int only when INTEGRAL (fraction digits
				// all zero) — truncation would silently destroy exactness.
				if v.data_type == cx.ScalarType.decimal_type {
					if sv.contains('.') {
						frac := sv.all_after('.')
						for c in frac {
							if c != `0` {
								return mk_err('cx-err:CXER0290',
									'cast: decimal `${sv}` is not integral — :int requires a whole value (L44)')
							}
						}
					}
					return parse_int_string(sv.all_before('.'))
				}
				return parse_int_string(sv)
			}
			cx.NullValue {
				return mk_err('cx-err:CXER0290',
					'cast: cannot cast null to :int — check for null explicitly first')
			}
		}
	}
	return mk_err('cx-err:CXER0290',
		'cast: cannot cast ${typeof(v).name} to :int')
}

fn parse_int_string(s string) cx.Node {
	trimmed := s.trim_space()
	if trimmed == '' {
		return mk_err('cx-err:CXER0290',
			'cast: cannot parse empty string as :int')
	}
	n := trimmed.i64()
	// V's .i64() returns 0 on parse failure — distinguish by re-rendering.
	if n == 0 && trimmed != '0' && trimmed != '-0' && trimmed != '+0' {
		return mk_err('cx-err:CXER0290',
			'cast: cannot parse string as :int (got ${s})')
	}
	return cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(n)
		data_type: cx.ScalarType.int_type
	})
}

// cast_to_float — int promotes losslessly; string parses; bool → 1.0/0.0.
fn cast_to_float(v cx.Node) cx.Node {
	if v is cx.Element {
		body := cast_to_string(v)
		return cast_to_float(body)
	}
	if v is cx.TextNode {
		return parse_float_string(v.value)
	}
	if v is cx.ScalarNode {
		sv := v.value
		match sv {
			i64 {
				return cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(f64(sv))
					data_type: cx.ScalarType.float_type
				})
			}
			f64 {
				return cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(sv)
					data_type: cx.ScalarType.float_type
				})
			}
			bool {
				return cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(if sv { f64(1.0) } else { f64(0.0) })
					data_type: cx.ScalarType.float_type
				})
			}
			string {
				if v.data_type == cx.ScalarType.atom_type {
					return mk_err('cx-err:CXER0290',
						'cast: cannot cast atom :${sv} to :float')
				}
				return parse_float_string(sv)
			}
			cx.NullValue {
				return mk_err('cx-err:CXER0290',
					'cast: cannot cast null to :float')
			}
		}
	}
	return mk_err('cx-err:CXER0290',
		'cast: cannot cast ${typeof(v).name} to :float')
}

fn parse_float_string(s string) cx.Node {
	trimmed := s.trim_space()
	if trimmed == '' {
		return mk_err('cx-err:CXER0290',
			'cast: cannot parse empty string as :float')
	}
	f := trimmed.f64()
	// V's .f64() returns 0.0 on parse failure — best-effort detection.
	if f == 0.0 && trimmed != '0' && trimmed != '0.0' && trimmed != '-0'
	   && trimmed != '-0.0' && trimmed != '+0' && trimmed != '+0.0' {
		return mk_err('cx-err:CXER0290',
			'cast: cannot parse string as :float (got ${s})')
	}
	return cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(f)
		data_type: cx.ScalarType.float_type
	})
}

// cast_to_bool — "true"/"false" strings only (case-sensitive per
// canonical-form rules); numeric 0/0.0 → false, anything else → true.
fn cast_to_bool(v cx.Node) cx.Node {
	if v is cx.Element {
		body := cast_to_string(v)
		return cast_to_bool(body)
	}
	if v is cx.TextNode {
		return parse_bool_string(v.value)
	}
	if v is cx.ScalarNode {
		sv := v.value
		match sv {
			bool {
				return cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(sv)
					data_type: cx.ScalarType.bool_type
				})
			}
			i64 {
				return cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(sv != 0)
					data_type: cx.ScalarType.bool_type
				})
			}
			f64 {
				return cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(sv != 0.0)
					data_type: cx.ScalarType.bool_type
				})
			}
			string {
				if v.data_type == cx.ScalarType.atom_type {
					return mk_err('cx-err:CXER0290',
						'cast: cannot cast atom :${sv} to :bool')
				}
				return parse_bool_string(sv)
			}
			cx.NullValue {
				return mk_err('cx-err:CXER0290',
					'cast: cannot cast null to :bool')
			}
		}
	}
	return mk_err('cx-err:CXER0290',
		'cast: cannot cast ${typeof(v).name} to :bool')
}

fn parse_bool_string(s string) cx.Node {
	t := s.trim_space()
	if t == 'true' {
		return cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(true)
			data_type: cx.ScalarType.bool_type
		})
	}
	if t == 'false' {
		return cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(false)
			data_type: cx.ScalarType.bool_type
		})
	}
	return mk_err('cx-err:CXER0290',
		'cast: cannot parse string as :bool (expected true or false; got ${s})')
}

// cast_to_atom — validates the value as an atom name (NCName shape per
// ) and rejects reserved names (true/false/null per
// §D8). Numeric / bool / null inputs are rejected — atom names cannot
// start with a digit.
fn cast_to_atom(v cx.Node) cx.Node {
	// element → body text → recurse
	if v is cx.Element {
		body := cast_to_string(v)
		return cast_to_atom(body)
	}
	mut name := ''
	if v is cx.TextNode {
		name = v.value.trim_space()
	} else if v is cx.ScalarNode {
		sv := v.value
		match sv {
			string {
				if v.data_type == cx.ScalarType.atom_type {
					// idempotent
					return cx.Node(v)
				}
				name = sv.trim_space()
			}
			cx.NullValue {
				return mk_err('cx-err:CXER0290',
					'cast: cannot cast null to :atom')
			}
			else {
				return mk_err('cx-err:CXER0290',
					'cast: cannot cast numeric / bool scalar to :atom — atom names cannot start with a digit')
			}
		}
	} else {
		return mk_err('cx-err:CXER0290',
			'cast: cannot cast ${typeof(v).name} to :atom')
	}
	if !is_valid_atom_name(name) {
		return mk_err('cx-err:CXER0290',
			'cast: "${name}" is not a valid atom name (NCName shape)')
	}
	if name == 'true' || name == 'false' || name == 'null' {
		return mk_err('cx-err:CXER0290',
			'cast: atom name :${name} is reserved')
	}
	return cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(name)
		data_type: cx.ScalarType.atom_type
	})
}

// is_valid_atom_name applies a relaxed NCName check sufficient for the
// atom name set: first char alpha or underscore; subsequent
// chars alphanumeric, underscore, or hyphen. Full XML NCName (including
// Unicode letter ranges) is a future expansion.
fn is_valid_atom_name(s string) bool {
	if s.len == 0 { return false }
	c0 := s[0]
	if !((c0 >= `a` && c0 <= `z`) || (c0 >= `A` && c0 <= `Z`) || c0 == `_`) {
		return false
	}
	for i := 1; i < s.len; i++ {
		c := s[i]
		if !((c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`)
		     || (c >= `0` && c <= `9`) || c == `_` || c == `-`) {
			return false
		}
	}
	return true
}

// scalar_to_string returns the canonical string form of any scalar
// value — strings pass through unchanged, other scalars are rendered
// via cx.scalar_value_str_public. Returns none for non-scalar inputs
// (element / textnode etc.), so callers can decide whether to raise
// CXER0100 or treat as a domain error.
fn scalar_to_string(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string { return v }
		return cx.scalar_value_str_public(v)
	}
	if n is cx.TextNode {
		return n.value
	}
	return none
}

// is_sequence_wrapper reports whether `n` is the empty-name / seq-marker
// Element that the path evaluator materialises as a sequence. Used to
// distinguish "path returned 0/1/N items" from a genuine Element value.
pub fn is_sequence_wrapper(n cx.Node) bool {
	if n is cx.Element {
		return n.name == '' || n.name == seq_marker_name
	}
	return false
}

// unwrap_single_item — XPath atomization-on-singleton: when `n` is a
// sequence wrapper of length 1, return its single item; otherwise return
// `n` unchanged. Empty sequences pass through (caller decides whether
// empty is meaningful).
pub fn unwrap_single_item(n cx.Node) cx.Node {
	if n is cx.Element {
		if (n.name == '' || n.name == seq_marker_name) && n.items.len == 1 {
			return n.items[0]
		}
	}
	return n
}

// xpath_string_value computes XPath fn:string() semantics for a path
// or value node. Rules per XPath 3.1 §2.5.4 / §14.5.1, narrowed to the
// CX-side surface:
//   - ScalarNode → its lexical string form
//   - TextNode   → its text value
//   - Attribute-shaped Element (single ScalarNode body, as materialised
//     by the attribute-axis path step) → the inner scalar's string form
//   - Element    → concatenation of its descendant TextNode / ScalarNode
//     content (depth-first, document order)
//   - Sequence wrapper of length 1 → string-value of its item
//   - Empty sequence → ""
//   - Multi-item sequence → string-value of first item (caller may
//     atomize differently; matches XPath's single-item-string-value rule
//     and the existing CX rendering convention for path heads)
fn xpath_string_value(n cx.Node) string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string { return v }
		return cx.scalar_value_str_public(v)
	}
	if n is cx.TextNode {
		return n.value
	}
	if n is cx.Element {
		// Sequence wrapper → recurse on first non-empty item.
		if n.name == '' || n.name == seq_marker_name {
			if n.items.len == 0 { return '' }
			return xpath_string_value(n.items[0])
		}
		// Attribute-shaped Element (single scalar body — produced by the
		// `@name` / `attribute::name` path step at vcx/code/eval.v
		// path-eval tail).
		if n.items.len == 1 {
			only := n.items[0]
			if only is cx.ScalarNode {
				v := only.value
				if v is string { return v }
				return cx.scalar_value_str_public(v)
			}
		}
		// Generic element: concatenate text-leaves depth-first.
		mut out := ''
		for c in n.items {
			match c {
				cx.TextNode { out += c.value }
				cx.ScalarNode {
					v := c.value
					if v is string { out += v } else { out += cx.scalar_value_str_public(v) }
				}
				cx.Element { out += xpath_string_value(c) }
				else {}
			}
		}
		return out
	}
	return ''
}

// element_for_node_accessor returns the underlying Element when a node
// accessor (name() / local-name()) is invoked on a path result that
// wraps a singleton sequence. Returns none for empty sequences,
// multi-item sequences (XPath cardinality error), or non-element
// values. Used by name() / local-name() to align with XPath fn:name()
// semantics over path heads.
fn element_for_node_accessor(n cx.Node) ?cx.Element {
	unwrapped := unwrap_single_item(n)
	if unwrapped is cx.Element {
		if unwrapped.name == '' || unwrapped.name == seq_marker_name {
			// Still a sequence wrapper after unwrap → empty or multi-item.
			return none
		}
		return unwrapped
	}
	return none
}

// local_name_of strips the optional `prefix:` from a QName, returning
// the local part. Matches XPath fn:local-name() — for unprefixed names,
// the whole name IS the local name.
fn local_name_of(qname string) string {
	idx := qname.index(':') or { return qname }
	return qname[idx + 1..]
}

// parses_as_i64 / parses_as_f64 are guard predicates for fn:sum
// atomization of stringified attribute values. V's `.i64()` /
// `.f64()` return zero on parse failure rather than an option, so we
// pre-classify the input to avoid silently counting "abc" as 0.
fn parses_as_i64(s string) bool {
	if s.len == 0 { return false }
	mut i := 0
	if s[0] == `-` || s[0] == `+` {
		i = 1
		if i >= s.len { return false }
	}
	for i < s.len {
		c := s[i]
		if !(c >= `0` && c <= `9`) { return false }
		i++
	}
	return true
}

fn parses_as_f64(s string) bool {
	if s.len == 0 { return false }
	mut i := 0
	if s[0] == `-` || s[0] == `+` { i = 1 }
	mut seen_digit := false
	mut seen_dot := false
	mut seen_exp := false
	for i < s.len {
		c := s[i]
		if c >= `0` && c <= `9` {
			seen_digit = true
		} else if c == `.` && !seen_dot && !seen_exp {
			seen_dot = true
		} else if (c == `e` || c == `E`) && seen_digit && !seen_exp {
			seen_exp = true
			if i + 1 < s.len && (s[i + 1] == `+` || s[i + 1] == `-`) { i++ }
		} else {
			return false
		}
		i++
	}
	return seen_digit
}

fn count_items(n cx.Node) int {
	// An IteratorNode is a sequence — count its materialized items, not 1.
	// Without this `[$count [$filter …]]` / `[$count [?map …]]` counted the
	// iterator as a single value (program-for-014).
	if n is cx.IteratorNode {
		return iterate(n).len
	}
	if n is cx.Element {
		// Table sequence view (D22, #404): count rows, not (absent)
		// CXDM children.
		if td := n.table_opt() {
			return td.rows.len
		}
		return n.items.len
	}
	return 1
}

pub fn scalar_string(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return none
}

// coerce_text_to_scalar maps a TextNode to an equivalent string-typed
// ScalarNode so value comparison treats text content as a string value.
// All other node kinds pass through unchanged.
fn coerce_text_to_scalar(n cx.Node) cx.Node {
	if n is cx.TextNode {
		return cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(n.value)
			data_type: cx.ScalarType.string_type
		})
	}
	return n
}

pub fn nodes_equal(a_in cx.Node, b_in cx.Node) bool {
	// D5: metadata is not identity-participating — two values that differ
	// ONLY in their `[?meta]` annotation are equal. Unwrap before comparing.
	a := meta_unwrap(a_in)
	b := meta_unwrap(b_in)
	// §6.2 terminal-field unwrap yields the inner item of a labeled field
	// `[role lead]` — a TextNode for bare text content. Value comparison
	// (`[= $m/role "lead"]`) must see the TextNode's text as a string
	// value, so coerce TextNode → string scalar before the scalar compare.
	// This also makes a TextNode equal to itself (it otherwise fell
	// through to the final `return false`).
	a_c := coerce_text_to_scalar(a)
	b_c := coerce_text_to_scalar(b)
	if a_c is cx.ScalarNode && b_c is cx.ScalarNode {
		// I1 stream 11 (L40/L42): when either side is decimal/bigint,
		// equality is MATHEMATICAL across the exact family (int/bigint/
		// decimal — `bigint 99 = int 99`, `1.10 = 1.1` by value) and
		// type-strict FALSE against everything outside it (string, float,
		// atom — the pre-epoch string arm said decimal "1.10" = string
		// "1.10"; `[cast]` is the only decimal↔float bridge, L44).
		a_num := a_c.data_type == cx.ScalarType.decimal_type
			|| a_c.data_type == cx.ScalarType.bigint_type
		b_num := b_c.data_type == cx.ScalarType.decimal_type
			|| b_c.data_type == cx.ScalarType.bigint_type
		if a_num || b_num {
			if ai := cx.cx_exact_num_image(a_c) {
				if bi := cx.cx_exact_num_image(b_c) {
					return cx.cx_exact_num_cmp(ai, bi) == 0
				}
			}
			return false
		}
		match a_c.value {
			bool {
				if b_c.value is bool { return a_c.value == b_c.value }
			}
			i64 {
				if b_c.value is i64 { return a_c.value == b_c.value }
			}
			f64 {
				if b_c.value is f64 { return a_c.value == b_c.value }
			}
			string {
				if b_c.value is string {
					// Atoms are type-strict (§3.6 / cxdm §5.1): an atom
					// equals only another atom of byte-identical name, and
					// never a plain string of the same characters. So an
					// atom-typed scalar and a string-typed scalar are
					// unequal even when their text matches.
					a_atom := a_c.data_type == cx.ScalarType.atom_type
					b_atom := b_c.data_type == cx.ScalarType.atom_type
					if a_atom != b_atom { return false }
					return a_c.value == b_c.value
				}
			}
			cx.NullValue {
				if b_c.value is cx.NullValue { return true }
			}
		}
		return false
	}
	if a is cx.Element && b is cx.Element {
		// #927: MAP envelopes take cxdm §5.3 map equality, not element
		// equality — same key set (key identity = (kind, image), type-strict
		// per §2.6) and values pairwise equal, ORDER-INDEPENDENT. The generic
		// element arm below compares entry images in document order, which is
		// both kind-blind ([= {1: 'x'} {'1': 'x'}] was true) and
		// order-sensitive ([= {a: 1, b: 2} {b: 2, a: 1}] was false) — each a
		// direct §5.3 violation.
		if a.name == map_marker_name && b.name == map_marker_name {
			return map_envelopes_equal(a, b)
		}
		// #753 (stream-2 W1): VALUE equality on elements is STRUCTURAL.
		// The earlier arm compared name + child COUNT only, so
		// [= [x 1] [x 3]] was TRUE across every consumer ([=]/[!=], $eq,
		// membership, $distinct, $position, group-by keys — a direct L94
		// violation for element-valued γ keys). Now: names equal;
		// attributes as a NAME-KEYED SET (order-insensitive — attr names
		// are unique by grammar) under scalar-value equality; children
		// pairwise in document order, recursing (TextNodes coerce in the
		// scalar arm above). Deliberately NOT canonical-byte compare:
		// value equality keeps the scalar semantics (decimal 1.10 = 1.1
		// inside an element), which byte comparison would break.
		if a.name != b.name || a.items.len != b.items.len || a.attrs.len != b.attrs.len {
			return false
		}
		for aa in a.attrs {
			mut matched := false
			for bb in b.attrs {
				if bb.name == aa.name {
					if !attr_values_equal(aa.value, bb.value) {
						return false
					}
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
		for i, ai in a.items {
			if !nodes_equal(ai, b.items[i]) {
				return false
			}
		}
		return true
	}
	// IteratorNode identity-only equality. Compare the
	// backing heap pointers; two iterators are equal iff they share
	// the same allocation.
	if a is cx.IteratorNode && b is cx.IteratorNode {
		return unsafe { voidptr(&a) == voidptr(&b) }
	}
	return false
}

// map_envelopes_equal — cxdm §5.3 map equality over `__cx_map__` envelopes
// (#927): equal iff same key set and values pairwise equal by key,
// order-independent. Key identity is the (kind, image) pair (§2.6/§5.1,
// RULED: 777-1a); string images compare NFC-normalized, matching eval_map's
// own duplicate-key identity. Keys are unique within a map (duplicates
// refuse at parse/eval), so equal length plus every a-entry finding a
// b-match is a bijection. A declaration-only entry (MSS-4) equals a
// declaration of the same key and kind; its placeholder value never
// participates (value reads of a declared entry are ABSENT).
fn map_envelopes_equal(a cx.Element, b cx.Element) bool {
	if a.items.len != b.items.len {
		return false
	}
	outer: for ai in a.items {
		if ai is cx.Element {
			a_kind := map_entry_effective_key_kind(ai)
			a_image := if a_kind == 'string' { cx.cx_nfc_name(ai.name) } else { ai.name }
			a_id := map_pattern_key_id(a_kind, a_image)
			a_decl := map_entry_decl_kind(ai) or { '' }
			for bi in b.items {
				if bi is cx.Element {
					b_kind := map_entry_effective_key_kind(bi)
					b_image := if b_kind == 'string' { cx.cx_nfc_name(bi.name) } else { bi.name }
					if map_pattern_key_id(b_kind, b_image) != a_id {
						continue
					}
					b_decl := map_entry_decl_kind(bi) or { '' }
					if a_decl != b_decl {
						return false
					}
					if a_decl == '' {
						a_val := if ai.items.len > 0 {
							ai.items[0]
						} else {
							cx.Node(cx.ScalarNode{ data_type: .null_type, value: cx.ScalarValue(cx.NullValue{}) })
						}
						b_val := if bi.items.len > 0 {
							bi.items[0]
						} else {
							cx.Node(cx.ScalarNode{ data_type: .null_type, value: cx.ScalarValue(cx.NullValue{}) })
						}
						if !nodes_equal(a_val, b_val) {
							return false
						}
					}
					continue outer
				}
			}
			return false
		}
	}
	return true
}

// attr_values_equal — scalar-value equality for attribute values (#753):
// same-variant strict, mirroring the scalar arm's per-type matches (the
// atom/decimal data_type nuances live on ScalarNode, not the raw value —
// attribute carriage is the raw ScalarValue, so variant+value is the whole
// comparable surface here).
fn attr_values_equal(a cx.ScalarValue, b cx.ScalarValue) bool {
	match a {
		bool {
			if b is bool {
				return a == b
			}
		}
		i64 {
			if b is i64 {
				return a == b
			}
		}
		f64 {
			if b is f64 {
				return a == b
			}
		}
		string {
			if b is string {
				return a == b
			}
		}
		cx.NullValue {
			if b is cx.NullValue {
				return true
			}
		}
	}
	return false
}

pub fn mk_err(err_code string, message string) cx.Node {
	// draft-3 — a failure outcome is `[result status=err …]`.
	// Scalar fields (status, code, message, where) are attributes;
	// structured fields (cause, errors, context) are child elements. Read
	// via $r@code / $r@message (attribute axis), $r/cause (child).
	e := cx.Node(cx.Element{
		name: 'err'
		attrs: [
			cx.Attribute{ name: 'code', value: cx.ScalarValue(err_code) },
			cx.Attribute{ name: 'message', value: cx.ScalarValue(message) },
		]
	})
	// §9.6 raise-stage observe: a runtime err-value is being born; any
	// active [?with-error-hook] observe FNs see it now, independent of
	// later recovery (error_hooks.v). Zero-cost when no hook is active.
	fire_raise_observe(e)
	return e
}

// mk_err_quiet is mk_err WITHOUT the §9.6 raise-stage observation. For
// placeholder/sentinel errs that are constructed eagerly but may never
// flow (e.g. [?retry]'s loop-local "no attempts" seed) — observing those
// would be a phantom raise.
pub fn mk_err_quiet(err_code string, message string) cx.Node {
	return cx.Element{
		name: 'err'
		attrs: [
			cx.Attribute{ name: 'code', value: cx.ScalarValue(err_code) },
			cx.Attribute{ name: 'message', value: cx.ScalarValue(message) },
		]
	}
}

// ── CXPath evaluation (value-kind path expressions) ──────────────
//
// Chunk-1 foundation: descendant-rooted simple paths.
//
//   //name           → all descendant-or-self elements with name `name`
//   //*              → all descendant-or-self elements (any name)
//   //name/child     → for each //name match, its direct `child` children
//   //name/*         → for each //name match, all direct children
//
// Result is a `cx.Element { name: '', items: [...] }` wrapper carrying
// the matched node sequence — same shape the `[?for]` path uses for
// multi-value yields. Per spec
// §5.5, paths against a bound `$doc` walk that document; when no
// `$doc` is in scope a doc-rooted path raises `cx-err:CXER0001`
// (code.md §1.3 implicit-`$doc` rule; XPath XPDY0002 parity, #454) —
// consistent with reading `$doc` directly and with the `[?for]`
// pattern-as-source generator. A bound `$doc` with NO matching nodes
// still yields the empty sequence (absence), which is what the
// truthiness semantics §5.5.1 D4 relies on.
//
// Predicates `[…]`, the remaining 10 axes, absolute `/`-rooted paths,
// relative paths, sequence operators (union/intersect/except), and
// BindingPath `$x/step+` are subsequent chunks.

fn eval_path_expr(p cx.ProgramPathExpr, mut env MatchEnv) !cx.Node {
	// Reserved bind-name guard [160a]: a step `(bind $_)` is rejected with
	// CXER0232 — `$_` is the implicit context binding, not a user bind
	// target. (Non-reserved binds are accepted; full bind semantics land
	// with the step-scoped binding feature.)
	for st in p.steps {
		if st.bind != '' {
			check_reserved_bind_name(st.bind) or {
				return EvalError{ code: err.msg().all_before(' '), message: err.msg() }
			}
		}
	}
	// Resolve the context document. Descendant-rooted '//' and absolute
	// '/' (grammar [130], #391) evaluate against `$doc`. The bare relative
	// StepList form lands in a subsequent chunk; it raises CXER0001 here so
	// callers see a clear deferral note rather than silent empty-sequence
	// return.
	if p.leading == .relative {
		return EvalError{
			code:    'cx-err:CXER0001'
			message: 'CXPath ${path_leading_name(p.leading)}-rooted form not yet implemented'
		}
	}
	doc := env.bindings['doc'] or {
		// Unbound $doc → loud error, not silent empty (code.md §1.3;
		// XPath XPDY0002 parity, #454). Mirrors the direct `$doc` read
		// and the [?for] pattern-as-source generator.
		return EvalError{
			code:    'cx-err:CXER0001'
			message: 'CXPath document-rooted query requires $doc; no data input or data root supplied'
		}
	}
	if p.steps.len == 0 {
		return cx.Element{ name: '' }
	}
	// Build the doc-order index + parent-index map once per query. All
	// axis evaluations operate on int indices into pc.doc_order rather
	// than &cx.Element pointers; Element is a value type and items[]
	// inlines Nodes (the union variant), so pointer-identity to a
	// child-Element is unreliable. Indexing into the once-walked
	// doc_order list is the stable identity strategy for chunk-2.
	pc := new_path_ctx(doc, path_needs_non_element_index(p.steps))
	// Initial sequence for '//' is the document plus all its descendants
	// (descendant-or-self axis applied to the first step's NodeTest); for
	// absolute '/' it is the document node's own axis view (child = the
	// root element only).
	first_step := p.steps[0]
	// Walk every step except a trailing attribute axis (which produces
	// synthetic attribute-wrapper Elements outside the indexed tree —
	// handled below). walk_path_steps_bound honors per-step `(bind $NAME)`
	// annotations (code.md §5.5, grammar [160]/[160a]).
	last_idx := p.steps.len - 1
	attribute_tail := p.steps[last_idx].axis == .attribute
	mut current := []int{}
	if attribute_tail && p.steps.len == 1 {
		// HEAD-POSITION attribute axis — `//@id`, `//@*`,
		// `//attribute::attribute()` (#824). There are no preceding steps,
		// so the context set is the leading axis's own node set rather than
		// anything a walk produces; routing it through the ordinary walker
		// hit apply_path_step_idx's `.attribute` arm, which is a documented
		// no-op because the materialization lives here — so the path parsed,
		// evaluated, and returned the empty sequence with no diagnostic.
		if p.leading == .descendant {
			// `//@id` desugars to descendant-or-self::node()/attribute::id,
			// so every node in the document is a context node.
			for i, _ in pc.doc_order {
				current << i
			}
		}
		// Absolute `/@id` stays empty: `/` is the document node, and a
		// document node carries no attributes (XPath 3.1 §3.3.2).
	} else {
		head := if p.leading == .absolute {
			apply_absolute_first_step(first_step, pc)
		} else {
			apply_first_step(first_step, pc)
		}
		stop := if attribute_tail { last_idx } else { p.steps.len }
		current = walk_path_steps_bound(p.steps, 0, stop, head, pc, mut env)!
	}
	// Trailing attribute axis: materialize each context Element's
	// matching attributes as synthetic [name "value"] Elements. The
	// `@name` shorthand (CXPath surface) is parser-equivalent to
	// `attribute::name`, so this is also the eval path for `@name`
	// once that surface lands.
	last_step := p.steps[last_idx]
	if attribute_tail {
		mut items := []cx.Node{}
		for idx in current {
			el := path_ctx_element(pc, idx) or { continue }
			for a in el.attrs {
				if attr_node_test_matches(last_step, a.name) {
					items << cx.Node(cx.Element{
						name:  a.name
						items: [cx.Node(attr_scalar_node(a))]
					})
				}
			}
		}
		return cx.Element{ name: '', items: items }
	}
	// Materialize the final index list back into a Node sequence.
	mut items := []cx.Node{}
	for idx in current {
		items << pc.doc_order[idx]
	}
	return cx.Element{
		name:  ''
		items: items
	}
}

// PathCtx carries the per-query document-order list and parent-index
// map. The structural-identity strategy: every Element in $doc gets a
// stable int index assigned in document-order; the parent map is keyed
// by child index with value = parent index (or -1 for the root). All
// axis logic operates in this int domain to sidestep V's value-type
// copy semantics on sum-type fields.
struct PathCtx {
	// doc_order holds NODES, not only Elements: a [131b] kind test
	// (`node()`, `text()`) tests node KINDS, so the index has to contain
	// the kinds it can match. Non-element nodes are indexed only when the
	// query actually carries such a step (see path_needs_non_element_index)
	// — every other NodeTest form is element-only, so their candidate sets
	// are identical either way and the common path pays nothing.
	doc_order   []cx.Node
	parents     []int   // parents[i] = parent index of doc_order[i], or -1
	children    [][]int // children[i] = doc-order indices of i's direct child nodes
	// ns_map carries the document's xmlns prefix → URI bindings used to
	// resolve CXPath namespace-wildcard NodeTests (`prefix:*`, `prefix:local`).
	// First-occurrence wins per spec/namespaces.md §5. Reserved prefixes
	// ('xml', 'cx') are seeded unconditionally. Empty when the document has
	// no namespace declarations (apart from reserved).
	ns_map      map[string]string
}

// path_needs_non_element_index reports whether any step of the query can
// match a node that is not an Element. Only the `node()` and `text()`
// kind tests can: every other NodeTest form (Name, `*`, the two
// namespace-wildcards, `element()`) is element-only, and `attribute()`
// matches attribute nodes, which never enter the doc-order index at all
// (the attribute axis materializes them separately). So when this is
// false the index built below is exactly the pre-kind-test index and
// every candidate set is unchanged.
fn path_needs_non_element_index(steps []cx.ProgramPathExprStep) bool {
	for s in steps {
		if s.kind_test == .any_node || s.kind_test == .text {
			return true
		}
	}
	return false
}

fn new_path_ctx(doc cx.Node, index_non_elements bool) PathCtx {
	mut order := []cx.Node{}
	mut parents := []int{}
	mut children := [][]int{}
	mut ns_map := map[string]string{}
	// Reserved prefixes always resolve per spec/namespaces.md §1.4.
	ns_map['xml'] = cx.xml_namespace_uri
	ns_map['cx']  = cx.cx_namespace_uri
	if doc is cx.Element {
		walk_for_path_ctx(doc, -1, index_non_elements, mut order, mut parents, mut children, mut ns_map)
	}
	return PathCtx{ doc_order: order, parents: parents, children: children, ns_map: ns_map }
}

// path_ctx_element returns the Element at a doc-order index, or none when
// that index holds a non-element node. Every element-shaped operation
// (name tests, attribute reads, attr predicates) routes through this so a
// text node in the index can never be read as an element.
fn path_ctx_element(pc PathCtx, idx int) ?cx.Element {
	n := pc.doc_order[idx]
	if n is cx.Element {
		return n
	}
	return none
}

// path_ctx_indexable reports whether a non-element child node takes a
// doc-order slot. The admitted set is exactly cxdm.md §2.2's first-class
// Node kinds minus Element (Text, ScalarNode, Comment, PI, Directive);
// BlockContent / Alias / RawText / EntityRef / the DTD family are
// preserved in the AST but are NOT CXDM Nodes ("expressions cannot match
// against them"), so no NodeTest may select them.
fn path_ctx_indexable(n cx.Node) bool {
	return n is cx.TextNode || n is cx.ScalarNode || n is cx.CommentNode
		|| n is cx.PINode || n is cx.CXDirectiveNode
}

fn walk_for_path_ctx(el cx.Element, parent_idx int, index_non_elements bool, mut order []cx.Node, mut parents []int, mut children [][]int, mut ns_map map[string]string) {
	my_idx := order.len
	order << el
	parents << parent_idx
	children << []int{}
	if parent_idx >= 0 {
		children[parent_idx] << my_idx
	}
	// Harvest xmlns / xmlns:prefix declarations on this element; first
	// occurrence wins per spec/namespaces.md CXPath note. Reserved prefixes
	// are immutable (xml / cx cannot be redeclared per §1.4).
	for a in el.attrs {
		if a.name == 'xmlns' {
			if '' !in ns_map {
				ns_map[''] = cx.scalar_value_str_public(a.value)
			}
		} else if a.name.starts_with('xmlns:') {
			pfx := a.name[6..]
			if pfx == 'xml' || pfx == 'cx' { continue }
			if pfx !in ns_map {
				ns_map[pfx] = cx.scalar_value_str_public(a.value)
			}
		}
	}
	for ch in el.items {
		if ch is cx.Element {
			walk_for_path_ctx(ch, my_idx, index_non_elements, mut order, mut parents, mut children, mut ns_map)
		} else if ch is cx.SequenceNode {
			// #587: a parsed paren-sequence body must build the SAME doc-order
			// topology the runtime lane's __cx_seq__ marker element builds —
			// $cx:equal values navigate identically under every axis.
			walk_for_path_ctx(cx.Element{ name: seq_marker_name, items: ch.items },
				my_idx, index_non_elements, mut order, mut parents, mut children, mut ns_map)
		} else if ch is cx.ArrayNode {
			walk_for_path_ctx(cx.Element{ name: arr_marker_name, items: ch.items },
				my_idx, index_non_elements, mut order, mut parents, mut children, mut ns_map)
		} else if ch is cx.MapNode {
			// #618: parsed maps build the marker-view topology.
			walk_for_path_ctx(map_node_view(ch), my_idx, index_non_elements, mut order, mut parents,
				mut children, mut ns_map)
		} else if index_non_elements && path_ctx_indexable(ch) {
			// Leaf node kinds (text, scalar, comment, PI, directive). They
			// take doc-order slots INLINE, so the index stays a preorder
			// walk with contiguous subtrees — which is what subtree_size()
			// and the following/preceding axes depend on.
			leaf_idx := order.len
			order << ch
			parents << my_idx
			children << []int{}
			children[my_idx] << leaf_idx
		}
	}
}

// apply_first_step handles the head step under '//'. Per spec/code.md
// §5.5.1 the leading `//` desugars to descendant-or-self at the root,
// so the candidate set is every Element in document order (which is
// exactly pc.doc_order), filtered by the step's NodeTest.
// apply_absolute_first_step evaluates the head step of an absolute
// ('/'-rooted, grammar [130] `'/' StepList`) path from the DOCUMENT node
// (#391). XPath axis semantics from the document node: child holds
// exactly the root element (doc_order[0]); descendant / descendant-or-
// self cover the root and everything below it (a document node never
// matches an element NodeTest, so -or-self adds nothing); every other
// axis (parent, ancestor*, sibling*, following/preceding, self,
// attribute) is empty at the document node for an element test.
fn apply_absolute_first_step(step cx.ProgramPathExprStep, pc PathCtx) []int {
	if pc.doc_order.len == 0 {
		return []int{}
	}
	match step.axis {
		.child {
			if node_test_matches(step, pc.doc_order[0], pc) {
				return [0]
			}
			return []int{}
		}
		.descendant, .descendant_or_self {
			mut out := []int{}
			for i, el in pc.doc_order {
				if node_test_matches(step, el, pc) {
					out << i
				}
			}
			return out
		}
		else {
			return []int{}
		}
	}
}

fn apply_first_step(step cx.ProgramPathExprStep, pc PathCtx) []int {
	mut out := []int{}
	match step.axis {
		.descendant_or_self {
			for i, el in pc.doc_order {
				if node_test_matches(step, el, pc) {
					out << i
				}
			}
		}
		.self_axis {
			// `//self::name` desugars to descendant-or-self::node()/self::name
			// — in this implementation we collapse it to the same set as
			// descendant-or-self with the name test.
			for i, el in pc.doc_order {
				if node_test_matches(step, el, pc) {
					out << i
				}
			}
		}
		else {
			// Explicit axes at the head step under '//' apply *to each
			// node in descendant-or-self set* per XPath semantics. Build
			// the full d-o-s set first, then apply the axis.
			mut all := []int{}
			for i, _ in pc.doc_order { all << i }
			return apply_path_step_idx(step, all, pc)
		}
	}
	return out
}

// apply_path_step_idx expands a context-index sequence under the step's
// axis, applying the NodeTest filter. Result preserves document order
// and is duplicate-free per XPath 3.1 §3.3.5 axis semantics.
fn apply_path_step_idx(step cx.ProgramPathExprStep, ctxs []int, pc PathCtx) []int {
	mut out := []int{}
	mut seen := []bool{len: pc.doc_order.len, init: false}
	match step.axis {
		.child {
			for ci in ctxs {
				for chi in pc.children[ci] {
					if !seen[chi] && node_test_matches(step, pc.doc_order[chi], pc) {
						seen[chi] = true
						out << chi
					}
				}
			}
		}
		.descendant_or_self {
			for ci in ctxs {
				collect_subtree_idx(ci, step, pc, mut seen, mut out)
			}
		}
		.descendant {
			for ci in ctxs {
				for chi in pc.children[ci] {
					collect_subtree_idx(chi, step, pc, mut seen, mut out)
				}
			}
		}
		.self_axis {
			for ci in ctxs {
				if !seen[ci] && node_test_matches(step, pc.doc_order[ci], pc) {
					seen[ci] = true
					out << ci
				}
			}
		}
		.parent {
			for ci in ctxs {
				pi := pc.parents[ci]
				if pi >= 0 && !seen[pi] && node_test_matches(step, pc.doc_order[pi], pc) {
					seen[pi] = true
					out << pi
				}
			}
		}
		.ancestor {
			mut collected := []int{}
			for ci in ctxs {
				mut cur := pc.parents[ci]
				for cur >= 0 {
					if !seen[cur] {
						seen[cur] = true
						if node_test_matches(step, pc.doc_order[cur], pc) {
							collected << cur
						}
					}
					cur = pc.parents[cur]
				}
			}
			collected.sort()
			out = collected.clone()
		}
		.ancestor_or_self {
			mut collected := []int{}
			for ci in ctxs {
				mut cur := ci
				for cur >= 0 {
					if !seen[cur] {
						seen[cur] = true
						if node_test_matches(step, pc.doc_order[cur], pc) {
							collected << cur
						}
					}
					cur = pc.parents[cur]
				}
			}
			collected.sort()
			out = collected.clone()
		}
		.following_sibling {
			for ci in ctxs {
				pi := pc.parents[ci]
				if pi < 0 { continue }
				mut after := false
				for sib in pc.children[pi] {
					if sib == ci {
						after = true
						continue
					}
					if after && !seen[sib] && node_test_matches(step, pc.doc_order[sib], pc) {
						seen[sib] = true
						out << sib
					}
				}
			}
		}
		.preceding_sibling {
			mut collected := []int{}
			for ci in ctxs {
				pi := pc.parents[ci]
				if pi < 0 { continue }
				for sib in pc.children[pi] {
					if sib == ci { break }
					if !seen[sib] && node_test_matches(step, pc.doc_order[sib], pc) {
						seen[sib] = true
						collected << sib
					}
				}
			}
			collected.sort()
			out = collected.clone()
		}
		.following {
			// "following" = every node in document order after the
			// context node, excluding the context node's descendants.
			mut collected := []int{}
			for ci in ctxs {
				skip_until := ci + subtree_size(ci, pc)
				for j := skip_until; j < pc.doc_order.len; j++ {
					if !seen[j] && node_test_matches(step, pc.doc_order[j], pc) {
						seen[j] = true
						collected << j
					}
				}
			}
			collected.sort()
			out = collected.clone()
		}
		.preceding {
			// "preceding" = every node in document order before the
			// context node, excluding the context node's ancestors.
			mut collected := []int{}
			for ci in ctxs {
				mut anc := map[int]bool{}
				mut cur := pc.parents[ci]
				for cur >= 0 {
					anc[cur] = true
					cur = pc.parents[cur]
				}
				for j := 0; j < ci; j++ {
					if j in anc { continue }
					if !seen[j] && node_test_matches(step, pc.doc_order[j], pc) {
						seen[j] = true
						collected << j
					}
				}
			}
			collected.sort()
			out = collected.clone()
		}
		.attribute {
			// The attribute axis emits synthetic indices outside the
			// doc_order tree, so we materialize directly into a side
			// channel — but for chunk-2 the cleanest move is to detect
			// the attribute axis in eval_path_expr and route to a
			// dedicated emit path. Here we no-op; the special-case is
			// applied in eval_path_expr_with_attribute_tail below.
			// Falling through means an `attribute::` step inside a
			// longer path (e.g. `//user/attribute::name/foo`) produces
			// no results — matching XPath's "attribute axis terminates
			// element navigation" rule.
		}
	}
	return out
}

// subtree_size returns 1 (self) + count of descendant Elements of the
// node at index `i`. Equivalently, the next "after-subtree" doc-order
// index is `i + subtree_size(i, pc)`.
fn subtree_size(i int, pc PathCtx) int {
	mut n := 1
	for chi in pc.children[i] {
		n += subtree_size(chi, pc)
	}
	return n
}

fn collect_subtree_idx(root int, step cx.ProgramPathExprStep, pc PathCtx, mut seen []bool, mut out []int) {
	if !seen[root] && node_test_matches(step, pc.doc_order[root], pc) {
		seen[root] = true
		out << root
	}
	for chi in pc.children[root] {
		collect_subtree_idx(chi, step, pc, mut seen, mut out)
	}
}

// kind_test_matches is THE authority on what each [131b] kind test
// admits, for every axis and both path surfaces (rooted PathExpr and
// $binding path). Semantics per ast.md's node-test table:
//
//   node()      any node
//   text()      character-data nodes only
//   element()   element nodes only
//   attribute() attribute nodes only — and attribute nodes never appear
//               in a doc-order index or in an element's items, so this
//               is false here by construction. The attribute axis has
//               its own materialization, which routes through
//               attr_node_test_matches below.
//
// `text()` takes BOTH character-data node kinds — Text and ScalarNode
// (RULED: 809-1a). cxdm.md §2.2 keeps them distinct Node KINDS, but which
// one a body lands in is decided by AUTO-TYPING, not by the author:
// `[port eight]` holds a Text and `[port 8080]` a ScalarNode from the
// same authorial act. Separating them here would make a query's result
// set depend on whether a value happened to auto-type, and `node()` is
// no substitute since it also takes elements. #809 shipped the narrow
// reading with the divergence pinned both ways so the ruling had a
// fixture to move; this is the one function that moved.
fn kind_test_matches(k cx.ProgramPathKindTest, n cx.Node) bool {
	return match k {
		.none      { false }
		.any_node  { true }
		.text      { n is cx.TextNode || n is cx.ScalarNode }
		.element   { n is cx.Element }
		.attribute { false }
	}
}

// attr_node_test_matches applies a step's NodeTest to an ATTRIBUTE node
// reached over the attribute axis. Attributes have a name but no items,
// so the name/wildcard forms test the name and the kind tests test the
// kind: `attribute::attribute()` and `attribute::node()` take every
// attribute, while `text()` / `element()` take none.
fn attr_node_test_matches(step cx.ProgramPathExprStep, attr_name string) bool {
	return match step.kind_test {
		.none                 { name_matches(step.name, attr_name) }
		.any_node, .attribute { true }
		.text, .element       { false }
	}
}

// name_matches handles the `*` wildcard NodeTest plus element-name
// equality. Element-only by caller construction. Used by the
// collect_subtree_idx descendant-walk recursion which carries only the
// `step.name` for the no-namespace case.
fn name_matches(test string, actual string) bool {
	return test == '*' || test == actual
}

// node_test_matches evaluates a CXPath NodeTest against an element per
// grammar [131b]. Handles all five surface forms:
//
//   bare Name / '*'        — step.ns_kind == .none; match by step.name
//                            against the source `name` (or '*' for any).
//   '*:' LocalName         — step.ns_kind == .any_ns; match by local
//                            name regardless of namespace.
//   Prefix ':*'            — step.ns_kind == .prefix_any_local; match
//                            elements whose ns_uri equals the URI bound
//                            by `ns_prefix` in pc.ns_map.
//   Prefix ':' LocalName   — step.ns_kind == .prefix_local; both ns_uri
//                            equality and local-name equality must hold.
//
// Prefix resolution is first-occurrence-wins across the document plus
// the reserved xml/cx prefixes (seeded in new_path_ctx).
fn node_test_matches(step cx.ProgramPathExprStep, n cx.Node, pc PathCtx) bool {
	// A [131b] kind test is the WHOLE NodeTest — the name / namespace
	// fields are empty when it is set, so it is answered first.
	if step.kind_test != .none {
		return kind_test_matches(step.kind_test, n)
	}
	// Every remaining NodeTest form is element-only.
	if n !is cx.Element {
		return false
	}
	el := n as cx.Element
	match step.ns_kind {
		.none {
			return step.name == '*' || step.name == el.name
		}
		.any_ns {
			// `*:LocalName` — local-name match, any namespace. The
			// `*:*` surface (any-ns + any-local) lands here with
			// name='*' and degenerates to "match every element" per
			// edge case (equivalent to plain `*`).
			return step.name == '*' || el.local() == step.name
		}
		.prefix_any_local {
			// `Prefix:*` — namespace match, any local name.
			if uri := pc.ns_map[step.ns_prefix] {
				el_uri := el.ns_uri() or { return false }
				return el_uri == uri
			}
			// Undeclared prefix → no xmlns binding in scope. CX infers
			// namespaces first-occurrence; an undeclared `Prefix:` is just
			// a literal part of the element name, so match any element
			// whose literal name carries that bare prefix.
			return el.name.starts_with('${step.ns_prefix}:')
		}
		.prefix_local {
			// `Prefix:LocalName` — both ns_uri and local name must match
			// when the prefix is DECLARED.
			if uri := pc.ns_map[step.ns_prefix] {
				el_uri := el.ns_uri() or { return false }
				return el_uri == uri && el.local() == step.name
			}
			// Undeclared prefix → literal qualified-name match: treat the
			// colon-name as the element's literal name (`ns:local`), per
			// CX's first-occurrence namespace model where an undeclared
			// prefix is part of the literal name, not a resolved URI.
			return el.name == '${step.ns_prefix}:${step.name}'
		}
	}
}

// filter_path_predicates_idx applies a step's predicates conjunctively
// (left-to-right) to a candidate index sequence. Per XPath 3.1 §3.3.5
// the positional predicate `[N]` is 1-indexed against the post-axis
// sequence AT EACH PREDICATE LEVEL — `[@a][1]` is "the first node with
// @a", not "node #1 if it has @a".
// filter_path_predicates_idx is the production dispatch hop for path-
// step predicates on the `eval_path_expr` walker. Operates on
// `cx.ProgramPathPredicate` (position + attr_test) against doc_order
// element indices in the PathCtx.
//
// TODO(Phase 2.21 integration — Z79e DELIVERED the right integration
// point in cxpath_eval.v (NOT this hop)): wire the standalone
// `eval_predicate_filter` (predicate_eval.v — the store row-scan's
// ![]Item` (vcx/code/predicate_eval.v, Phase 2.21-standalone) into the
// PATH WALKER, not the eval.v-side `filter_path_predicates_idx` hop.
// Z79e landed that integration at `cxpath_eval.v::eval_cxpath` (see
// the per-step predicate loop calling `filter_step_predicate` which
// fail-closed predicate engine; the CXPath placeholder that once fed it is retired).
//
// This eval.v-side hop remains source-driven on `cx.ProgramPathPredicate`
// for the dispatcher (`eval_path_expr`) — it covers exactly the
// atomic-template surface inline already, so routing
// through that Item engine here would be a code-duplication
// refactor with zero semantic gain. The Phase 2.6 part 4 follow-up
// (cxpath_eval.v eventually replaces eval_path_expr as THE path
// evaluator) will retire this hop entirely; until then the inline
// implementation is the right surface for the dispatcher path.
// walk_path_steps_bound walks `steps[i..stop)` where `candidates` is the
// axis-expanded (NodeTest-matched, not yet predicate-filtered) index set
// for step `i`. It applies each step's predicates, expands the next step's
// axis, and honors the `(bind $NAME)` step annotation per code.md §5.5 /
// grammar [160]/[160a]: the step's focus is bound under `$NAME`, visible
// in every predicate enclosed by the step and in every subsequent step of
// the same PathExpr. Because the binding is PER FOCUS, a bind step forks
// the remainder of the walk once per surviving candidate so each branch
// sees ITS OWN focus under `$NAME`; branch results are merged
// duplicate-free in document order. The binding shadows any outer binding
// of the same name for the duration of the walk and is restored after —
// it is never visible outside the PathExpr.
fn walk_path_steps_bound(steps []cx.ProgramPathExprStep, i int, stop int, candidates []int, pc PathCtx, mut env MatchEnv) ![]int {
	step := steps[i]
	filtered := filter_path_predicates_idx(candidates, step.predicates, step.bind, pc, mut env)!
	if i + 1 >= stop {
		return filtered
	}
	if step.bind == '' {
		next := apply_path_step_idx(steps[i + 1], filtered, pc)
		return walk_path_steps_bound(steps, i + 1, stop, next, pc, mut env)
	}
	// Bind step: fork the remaining walk per bound focus.
	saved := env.bindings[step.bind] or { cx.Node(cx.Element{}) }
	had := step.bind in env.bindings
	mut seen := []bool{len: pc.doc_order.len, init: false}
	mut merged := []int{}
	for c in filtered {
		env.cow_bindings()
		env.bindings[step.bind] = cx.Node(pc.doc_order[c])
		next := apply_path_step_idx(steps[i + 1], [c], pc)
		sub := walk_path_steps_bound(steps, i + 1, stop, next, pc, mut env) or {
			if had { env.bindings[step.bind] = saved } else { env.bindings.delete(step.bind) }
			return err
		}
		for idx in sub {
			if !seen[idx] {
				seen[idx] = true
				merged << idx
			}
		}
	}
	env.cow_bindings()
	if had { env.bindings[step.bind] = saved } else { env.bindings.delete(step.bind) }
	merged.sort()
	return merged
}

fn filter_path_predicates_idx(seq []int, preds []cx.ProgramPathPredicate, bind string, pc PathCtx, mut env MatchEnv) ![]int {
	mut current := seq.clone()
	// `(bind $NAME)` same-step visibility (code.md §5.5): the step's focus
	// is bound under `$NAME` while ITS OWN predicates evaluate — for the
	// candidate under test, `$NAME` and `$_` denote the same node. Saved /
	// restored around each candidate so the bind shadows (never clobbers)
	// any outer binding of the same name.
	saved_bind := env.bindings[bind] or { cx.Node(cx.Element{}) }
	had_bind := bind != '' && bind in env.bindings
	defer {
		if bind != '' {
			if had_bind { env.bindings[bind] = saved_bind } else { env.bindings.delete(bind) }
		}
	}
	for pred in preds {
		mut next := []int{}
		match pred.kind {
			.position {
				one_based := int(pred.int_index)
				if one_based >= 1 && one_based <= current.len {
					next << current[one_based - 1]
				}
			}
			.attr_test {
				ap := cx.ProgramPatternAttr{
					kind:      pred.attr_kind
					name:      pred.attr_name
					op:        pred.attr_op
					value:     pred.attr_value
					type_name: pred.type_name
				}
				for idx in current {
					if bind != '' {
						env.cow_bindings()
						env.bindings[bind] = pc.doc_order[idx]
					}
					// An attribute predicate on a non-element node can
					// never hold — only elements carry attributes.
					el := path_ctx_element(pc, idx) or { continue }
					if match_attr(ap, el, mut env) {
						next << idx
					}
				}
			}
			.expr {
				body := pred.body or {
					return EvalError{
						code:    'cx-err:CXER0001'
						message: 'predicate body missing in .expr kind'
					}
				}
				// Static purity (§6.5.x): a path predicate calling a
				// known-impure builtin/primitive (e.g. `now()`) is rejected
				// with CXER0230 — predicate bodies MUST be pure.
				if callee := program_node_impure_callee(body) {
					return EvalError{
						code:    'cx-err:CXER0230'
						message: 'cx-err:CXER0230 E_PREDICATE_NOT_PURE: predicate calls impure `${callee}`'
					}
				}
				total := current.len
				if body is cx.ProgramCall && (body as cx.ProgramCall).name == '__pred_last' {
					if total >= 1 {
						next << current[total - 1]
					}
				} else {
					for i, idx in current {
						el := pc.doc_order[idx]
						saved_underscore := env.bindings['_'] or { cx.Node(cx.Element{}) }
						// (`el` is the context NODE — an element for every
						// name test, possibly a text/scalar/comment node
						// under a node()/text() step.)
						had_underscore := '_' in env.bindings
						saved_pos := env.bindings['_position'] or { cx.Node(cx.Element{}) }
						had_pos := '_position' in env.bindings
						saved_last := env.bindings['_last'] or { cx.Node(cx.Element{}) }
						had_last := '_last' in env.bindings
						env.cow_bindings()
						if bind != '' {
							env.bindings[bind] = el
						}
						env.bindings['_'] = el
						env.bindings['_position'] = cx.Node(cx.ScalarNode{
							value:     cx.ScalarValue(i64(i + 1))
							data_type: cx.ScalarType.int_type
						})
						env.bindings['_last'] = cx.Node(cx.ScalarNode{
							value:     cx.ScalarValue(i64(total))
							data_type: cx.ScalarType.int_type
						})
						result := eval_node(body, mut env) or {
							if had_underscore { env.bindings['_'] = saved_underscore } else { env.bindings.delete('_') }
							if had_pos { env.bindings['_position'] = saved_pos } else { env.bindings.delete('_position') }
							if had_last { env.bindings['_last'] = saved_last } else { env.bindings.delete('_last') }
							return err
						}
						if had_underscore { env.bindings['_'] = saved_underscore } else { env.bindings.delete('_') }
						if had_pos { env.bindings['_position'] = saved_pos } else { env.bindings.delete('_position') }
						if had_last { env.bindings['_last'] = saved_last } else { env.bindings.delete('_last') }
						ebv := node_ebv(result) or { return iterator_ebv_eval_error() }
						if ebv {
							next << idx
						}
					}
				}
			}
		}
		current = next.clone()
	}
	return current
}

// collect_descendant_or_self appends every element at or below `n`
// whose name matches `target`. A `*` target matches any element name.
// Non-element children (text, scalar) are walked through but never
// emitted — CXPath element NodeTests are element-only per [131b].
fn collect_descendant_or_self(n cx.Node, target string, mut out []cx.Node) {
	if n is cx.Element {
		el := n as cx.Element
		if target == '*' || el.name == target {
			out << n
		}
		for child in el.items {
			collect_descendant_or_self(child, target, mut out)
		}
	}
}

// apply_child_step appends each direct-child element of `n` whose name
// matches `target` (or all children when `target == '*'`).
fn apply_child_step(n cx.Node, target string, mut out []cx.Node) {
	if n is cx.Element {
		el := n as cx.Element
		for child in el.items {
			if child is cx.Element {
				ch := child as cx.Element
				if target == '*' || ch.name == target {
					out << child
				}
			}
		}
	}
}

// path_leading_name renders the leading-kind enum value for error
// messages. Stable identifiers for spec / fixture cross-reference.
fn path_leading_name(l cx.ProgramPathLeading) string {
	return match l {
		.descendant { 'descendant (\'//\')' }
		.absolute   { 'absolute (\'/\')' }
		.relative   { 'relative' }
	}
}

// ── Directives (pure-functional subset) ─────────────────────────────────────

fn eval_directive(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	// Directive-result postfix steps (RULED PS-1, #886): `[?let …]/name`,
	// `[?if …]@attr` — the directive evaluates exactly as the step-less
	// form, then the step run destructures the RESULT through
	// apply_value_path (the CRS-1 pattern; zero new semantics).
	if d.path.len > 0 {
		base := eval_directive(cx.ProgramDirective{ ...d, path: []cx.ProgramPathStep{} }, mut env)!
		return apply_value_path(base, d.path, mut env, true)
	}
	match d.name {
		'match' { return eval_match(d, mut env) }
		'if'    { return eval_if(d, mut env) }
		'else'  { return eval_else(d, mut env) }
		'let'   { return eval_let(d, mut env) }
		'loop'  { return eval_loop(d, mut env) }
		'do'    { return eval_do(d, mut env) }
		'pipe'  { return eval_pipe_directive(d, mut env) }
		'modify' { return eval_modify(d, mut env) }
		'with-open'  { return eval_with_open(d, mut env) }
		'with-scope' { return eval_with_scope(d, mut env) }
		'with-caps'  { return eval_with_caps(d, mut env) }
		'secret'     { return eval_secret(d, mut env) }
		'reveal'     { return eval_reveal(d, mut env) }
		'meta'       { return eval_meta(d, mut env) }
		'str'        { return eval_str(d, mut env) }
		// Homoiconic dynamic construction (spec/code.md §6.4.2-§6.4.4).
		// `[?element]` is parsed as a cx_element literal (eval_cx_element), so
		// it never reaches here. `[?name]` standalone is only meaningful in a
		// modify name slot (eval_modify handles it); a standalone `[?name]` is
		// not evaluable on its own.
		'attr'       { return eval_computed_attr(d, mut env) }
		'entry'      { return eval_computed_entry(d, mut env) }
		'quote'      { return eval_quote(d, mut env) }
		'unquote'    { return eval_unquote_misplaced(d, mut env) }
		'splice'     { return eval_splice_misplaced(d, mut env) }
		'eval'       { return eval_tree(d, mut env) }
		'name'       { return eval_name_misplaced(d, mut env) }
		'lib'        { return eval_lib(d, mut env) }
		'const'      { return eval_const(d, mut env) }
		'map'    { return eval_map_directive(d, mut env) }
		'reduce' { return eval_reduce_directive(d, mut env) }
		// Iterator-returning combinator stdlib (W3c).
		'filter'      { return eval_filter_directive(d, mut env) }
		'take'        { return eval_take_directive(d, mut env) }
		'drop'        { return eval_drop_directive(d, mut env) }
		'zip'         { return eval_zip_directive(d, mut env) }
		'enumerate'   { return eval_enumerate_directive(d, mut env) }
		'chunks'      { return eval_chunks_directive(d, mut env) }
		'concat'      { return eval_concat_directive(d, mut env) }
		// 'chain' RETIRED (stream 13, L55): the registry's only alias is
		// gone — [?concat] is the one name. The head no longer lexes as a
		// directive (program_tokens.v), so no arm exists here.
		'cycle'       { return eval_cycle_directive(d, mut env) }
		'scan'        { return eval_scan_directive(d, mut env) }
		'flatten'     { return eval_flatten_directive(d, mut env) }
		'partition'   { return eval_partition_directive(d, mut env) }
		'group-by'    { return eval_group_by_directive(d, mut env) }
		// explicit force-materialization directives.
		'to-sequence' { return eval_to_sequence_directive(d, mut env) }
		'to-array'    { return eval_to_array_directive(d, mut env) }
		'to-map'      { return eval_to_map_directive(d, mut env) }
		// view opt-in (zero-copy slice intent).
		'view'        { return eval_view_directive(d, mut env) }
		'views'       { return eval_views_directive(d, mut env) }
		'fn'              { return eval_fn(d, mut env) }
		'def'             { return eval_def(d, mut env) }
		'fallback'        { return eval_fallback(d, mut env) }
		'retry'           { return eval_retry(d, mut env) }
		'timeout'         { return eval_timeout(d, mut env) }
		'circuit-breaker' { return eval_circuit_breaker(d, mut env) }
		'rate-limit'      { return eval_rate_limit(d, mut env) }
		'bulkhead'        { return eval_bulkhead(d, mut env) }
		'sleep'           { return eval_sleep(d, mut env) }
		'channel'         { return eval_channel(d, mut env) }
		'subscribe'       { return eval_subscribe(d, mut env) }
		'monitor'         { return eval_monitor(d, mut env) }
		'send'            { return eval_send(d, mut env) }
		'receive'         { return eval_receive(d, mut env) }
		'try-send'        { return eval_try_send(d, mut env) }
		'try-receive'     { return eval_try_receive(d, mut env) }
		'close'           { return eval_close(d, mut env) }
		'worker'          { return eval_worker(d, mut env) }
		'worker-handle'   { return eval_worker_handle(d, mut env) }
		'wait-for'        { return eval_wait_for(d, mut env) }
		'cancel'          { return eval_cancel(d, mut env) }
		'check-cancel'    { return eval_check_cancel(d, mut env) }
		'select'          { return eval_select(d, mut env) }
		'async'           { return eval_async(d, mut env) }
		'await'           { return eval_await(d, mut env) }
		'await-all'       { return eval_await_all(d, mut env) }
		'await-any'       { return eval_await_any(d, mut env) }
		'await-race'      { return eval_await_race(d, mut env) }
		'with-error-hook' { return eval_with_error_hook(d, mut env) }
		'test-clock'         { return eval_test_clock(d, mut env) }
		'test-counter'       { return eval_test_counter(d, mut env) }
		'test-always-err'    { return eval_test_always_err() }
		'test-err-then-ok'   { return eval_test_err_then_ok(d, mut env) }
		'test-cb-open'       { return eval_test_cb_open() }
		'test-rate-limited'  { return eval_test_rate_limited() }
		'test-bulkhead-full' { return eval_test_bulkhead_full() }
		'test-concurrent'    { return eval_test_concurrent(d, mut env) }
		'test-single-use-iter' { return eval_test_single_use_iter(d, mut env) }
		'test-closeable'       { return eval_test_closeable(d, mut env) }
		'test-close-log'       { return eval_test_close_log(d, mut env) }
		'test-current-scope'   { return eval_test_current_scope(d, mut env) }
		else {
			// I3: Ring-2 directive handlers (the services family —
			// http-service, service-handle, stop, http-client,
			// test-service-client, test-tls-config) register into the
			// registry (ring2_register.v) and are probed here rather
			// than carried as match arms.
			if h := g_ring2_directives[d.name] {
				return h(d, mut env)!
			}
			return EvalError{
				code:    'cx-err:CXER0001'
				message: '[?${d.name}] not in pure-functional evaluator subset'
			}
		}
	}
}

// ── Streaming output buffer ─────────────────────────────────────────────────
//
// `StreamCtx` is the per-yield rendering buffer used by `eval_code_streaming`
// (currently consumed by `eval_for_comp_streamed` for top-level `[?for]`
// bodies). Each matched yield is rendered + buffered into the context and
// flushed to the sink once it exceeds the chunk threshold, avoiding the
// full N-result accumulator and the single output string the one-shot path
// materialises.

// stream_chunk_threshold caps the in-flight buffer before the streaming
// path flushes to the sink. 32 KiB is a balance between per-yield overhead
// (smaller chunks → more sink calls) and peak resident bytes; tunable per
// workload but baseline-good for the §11.6 gate 15 JSON-shape corpus.
pub const stream_chunk_threshold = 32 * 1024

// StreamShape is the SHAPE of the result being streamed — the streaming
// renderer's counterpart to the container the one-shot path would have
// rendered. It exists because byte-equivalence is per-shape, not universal:
// a `[?for]` comprehension renders its yields newline-separated, while a
// `[?map]` result renders as a SEQUENCE LITERAL `(a, b, c)`. Streaming a
// sequence with the item pipe emitted `a\nb\nc` for a program whose one-shot
// answer was `(a, b, c)` — different bytes for the same program, which is
// exactly the contract this surface rests on (#823).
pub enum StreamShape {
	// items: newline-separated values — the `[?for]` :yield lane.
	items
	// sequence: a sequence literal — `(` before the first item, `, ` between,
	// `)` at finish, items rendered in COLLECTION-ITEM position. Mirrors
	// render_node_to's IteratorNode arm byte for byte, which is what a
	// `[?map]` result (an eager or lazy iterator) renders through one-shot.
	sequence
}

pub struct StreamCtx {
mut:
	buf       strings.Builder
	target    string  // 'text' or 'cx' at this phase
	sink      CXStreamSink
	first     bool = true
	threshold int  = stream_chunk_threshold
	// shape selects the container the emitted items belong to; see
	// StreamShape. Set by the dispatch that knows which directive is being
	// streamed, alongside the CXStreamMode it reports to callers.
	shape     StreamShape = .items
	// count of items emitted so far, so the streamed
	// for-comp path can resolve `$_position` to the 1-based OUTPUT index
	// (`n_emitted + 1`) the same way the buffered path uses `out.len + 1`.
	n_emitted int
}

pub fn new_stream_ctx(target string, sink CXStreamSink) StreamCtx {
	return StreamCtx{
		buf:       strings.new_builder(stream_chunk_threshold * 2)
		target:    target
		sink:      sink
		first:     true
		threshold: stream_chunk_threshold
		shape:     .items
	}
}

pub fn (mut ctx StreamCtx) emit_node(n cx.Node) ! {
	match ctx.shape {
		.items {
			// One-level sequence splice — the streamed twin of the
			// buffered yield collection (`.sequence` yield_form flattens
			// inner sequences into the result, eval_for_comp ~§12963).
			// Without it a `[yield ($x, $y)]` printed `(x, y)` per item
			// where the one-shot answer is the spliced flat lines —
			// different bytes for the same program, the exact contract
			// break the #823 map exclusion existed for (found by the
			// profile gate's [bin] lane: program-for-yield-flat-baseline).
			// An empty sequence splices to NOTHING: no newline, `first`
			// untouched.
			if n is cx.Element && n.name == seq_marker_name {
				for it in n.items {
					if !ctx.first {
						ctx.buf.write_string('\n')
					}
					render_node_to(mut ctx.buf, it)
					ctx.first = false
				}
				// ONE yield, however many items it spliced — n_emitted
				// mirrors the buffered `out.len` (yields collected), which
				// is what `$_position` binds from; splice happens at the
				// buffered SHAPING stage, after positions are assigned.
				ctx.n_emitted++
				if ctx.buf.len >= ctx.threshold {
					ctx.flush()!
				}
				return
			}
			if !ctx.first {
				ctx.buf.write_string('\n')
			}
			render_node_to(mut ctx.buf, n)
		}
		.sequence {
			// The opening delimiter is written with the FIRST item, not at
			// construction: a stream that turns out to be empty must render
			// `()` as one piece (see finish), and a context that is built but
			// never emitted into must stay byte-empty.
			ctx.buf.write_string(if ctx.first { '(' } else { ', ' })
			render_seq_item_to(mut ctx.buf, n)
		}
	}
	ctx.first = false
	ctx.n_emitted++
	if ctx.buf.len >= ctx.threshold {
		ctx.flush()!
	}
}

// finish closes whatever container the shape opened and flushes the tail.
// Every streaming path calls this at COMPLETION; `flush` alone is the
// mid-stream operation and must never write a closing delimiter, or a
// threshold crossing would close the sequence in the middle of it.
pub fn (mut ctx StreamCtx) finish() ! {
	if ctx.shape == .sequence {
		// An iterator with no items renders `()` one-shot; `first` still
		// standing means nothing opened it.
		ctx.buf.write_string(if ctx.first { '()' } else { ')' })
	}
	ctx.flush()!
}

// (The former emit_raw_bytes — the raw-byte lane of the retired
// parser_streaming zero-materialization pipeline — was removed with
// its producer, cx.render_flat_record_to, at stream 17 W5: a
// caller-less parallel renderer of identity-bearing canonical forms
// does not stay dead. The streamed-input fast path renders through
// emit_node like every other lane.)

pub fn (mut ctx StreamCtx) flush() ! {
	if ctx.buf.len == 0 {
		return
	}
	// #804 leg 9 — the buffer is REUSED, not replaced.
	//
	// `Builder.str()` memdups the accumulated bytes and then `clear()`s the
	// builder, so on return it is already empty with its capacity intact.
	// Replacing it here allocated a fresh 64 KiB on every flush and threw
	// away a 64 KiB buffer that was ready to use.
	//
	// MEASURED, because leg 8's lesson was that an allocation's cost is not
	// guessable: over the §11.4.4 corpus at 64 MiB the streamed `[?for]`
	// shape flushes 2004 times, so this line alone allocated 125 MiB per
	// evaluation — against 286 MiB of TOTAL per-record allocation, and 352
	// MiB including the parser's one whole-buffer copy. It was the single
	// largest allocator on the path and it produced nothing.
	// `vcx/tests/runners/streamed_for_alloc_probe.v` is the census.
	//
	// SOUND BY CONSTRUCTION, not by argument: `str()` returns a COPY
	// (`memdup_noscan`), so the chunk handed to the sink does not alias the
	// buffer and cannot be disturbed by anything written into it afterwards.
	// Both halves of that were verified directly rather than read: a builder
	// driven through four `str()` cycles keeps the SAME `data` pointer and
	// its full capacity (so the reuse is real and the writes after it
	// allocate nothing), and each `str()` allocates exactly chunk+1 bytes
	// (so the chunk is its own memory).
	//
	// NO UNIT TEST GUARDS THE ALIASING HALF, and that is deliberate rather
	// than an omission. A test would have to retain the delivered chunks and
	// compare them after the stream continued — but V DEEP-COPIES a string
	// pushed into a `[]string`, so the retention itself copies the bytes and
	// the comparison can never fail. Written and then broken on purpose
	// twice — once with a zero-copy `str()`, once with a zero-copy `str()`
	// over a deliberately stable buffer — it stayed green through both. An
	// instrument that survives the break it exists to catch is not evidence,
	// so it was deleted instead of shipped.
	//
	// What DOES guard this line is the allocation census
	// (`vcx/tests/runners/streamed_for_alloc_probe.v`): reinstating the
	// buffer replacement moves the `yield-u` rung by 190.6 bytes/record.
	// That cannot live in a unit test either — vgc folds allocation into its
	// global counter only every 1 MiB, and a test-sized corpus allocates
	// less than that, so the meter reads zero.
	chunk := ctx.buf.str()
	ctx.sink(chunk) or {
		return EvalError{
			code:    'cx-err:CXER0001'
			message: 'eval_code_streaming: sink callback failed: ${err.msg()}'
		}
	}
}

// eval_match dispatches between the single-arm (2-arg) form and the
// multi-arm form. Recognition rule: any `:case`
// `:when` / `:else` labeled slot present → multi-arm; otherwise the
// legacy 2-arg `[?match value pattern :yield expr]` form.
//
// Z79g (rock-solid finish): the multi-arm form ROUTES through
// `try_eval_match_via_bridge` first (vcx/code/eval.v near bottom of
// file, backed by `vcx/code/dispatcher_bridge.v`'s
// `retype_match_pattern_nodes` Gap-2 fix). The bridge handles
// closed scalar / atom / string / element-literal `:case` patterns
// against a pre-evaluated `cx.Node` scrutinee via the standalone
// `eval_match_node` (vcx/code/match_eval.v). When the bridge
// declines (single-arm form, `:case` with $-binding capture, wildcard
// `_`, element-with-bind patterns), the legacy
// `eval_match_multi_arm` / `eval_match_single_arm` path handles it.
fn eval_match(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	mut is_multi := false
	for slot in d.slots {
		if slot.kind == .labeled
		   && (slot.label == 'case' || slot.label == 'when' || slot.label == 'else') {
			is_multi = true
			break
		}
	}
	if is_multi {
		// #850 — the Z79f bridge is OFF this hop by default.
		//
		// It used to run FIRST for every multi-arm `[?match]`, and that was
		// the whole of this directive's fixed per-call overhead: the bridge
		// re-lowered the directive to a MatchNode, re-typed every arm's
		// pattern, and re-parsed the winning arm's body from SOURCE TEXT — all
		// three pure functions of an immutable program AST, all three redone
		// on every evaluation.
		//
		// What makes removal (rather than memoisation) the right answer is
		// what the bridge was actually still serving. Its own decline-list
		// sends every hard shape to the legacy engine: any `:case` pattern
		// with a `$` binding, a wildcard, or an element head. So the bridge
		// only ever handled the EASY tail — `[else]`-only and scalar-literal
		// cases — and it handled that tail ~10x slower than the path it
		// declines to. Measured `-prod`: `[else]`-only ~14.4 µs/call via the
		// bridge; `[case [zzz] …]` ~1.4 µs and `[case [err @code=$c] …]`
		// ~1.2 µs, both by declining. Adding a case made `[?match]` faster.
		//
		// This is the same retirement the MODIFY half of this bridge already
		// took at #803/#805, on the same reasoning and the same kind of
		// measurement — see the note at the bottom of dispatcher_bridge.v.
		//
		// `set_match_bridge_on(true)` restores the old routing, which is how
		// test_match_bridge_differential proves the two agree byte-for-byte
		// instead of this comment asserting it.
		if match_bridge_enabled() {
			if result := try_eval_match_via_bridge(d, mut env) {
				return result
			}
		}
		return eval_match_multi_arm(d, mut env)!
	}
	return eval_match_single_arm(d, mut env)!
}

// eval_match_single_arm runs the original 2-arg form:
//   [?match value pattern :yield expr]
// Per (and the existing `program-err-001` fixture), a miss
// on the single-arm form raises `cx-err:CXER0100` (NO_MATCH). The
// previous implementation returned an empty element on miss — that
// silently swallowed the assertion failure and is the bug
// `program-match-multi-009-single-arm-no-match-raises` was written to
// pin.
// eval_match_scrutinee evaluates the [?match] scrutinee slot. The slot is
// the §9.2-EXEMPT boundary (spec §8.2, V1a): a thrown condition converts
// to a value-form err (code preserved) so it reaches the arms as a
// matchable value rather than unwinding past the directive. An err-VALUE
// produced by the scrutinee already flows through unchanged.
fn eval_match_scrutinee(n cx.ProgramNode, mut env MatchEnv) cx.Node {
	return eval_node(n, mut env) or {
		if err is EvalError {
			if err.cause_set {
				return mk_err_with_cause(err.code, err.cause)
			}
			return mk_err(err.code, err.msg())
		}
		return mk_err('cx-err:CXER0001', err.msg())
	}
}

fn eval_match_single_arm(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	if d.slots.len < 2 {
		return EvalError{
			code: 'cx-err:CXER0100', message: '[?match] requires value + pattern slots'
		}
	}
	val := eval_match_scrutinee(d.slots[0].value, mut env)
	pat_node := d.slots[1].value
	pat := if pat_node is cx.ProgramPattern {
		pat_node
	} else {
		return EvalError{
			code: 'cx-err:CXER0100', message: '[?match] second slot must be a pattern'
		}
	}
	yield_expr := labeled_slot(d, 'yield') or {
		return EvalError{
			code: 'cx-err:CXER0001', message: '[?match] requires :yield'
		}
	}
	mut snap := env.clone_sharing_closures() // #871 — closures aliased (COW)
	if matched := match_pattern(pat, val) {
		for k, v in matched.bindings {
			snap.bindings[k] = v
		}
		return eval_node(yield_expr, mut snap)!
	}
	// single-arm form raises CXER0100 on miss.
	return EvalError{
		code:    'cx-err:CXER0100'
		message: '[?match] no match for value (single-arm form)'
	}
}

// eval_match_multi_arm runs the multi-arm form:
//
//   [?match value?
//     :case  PAT (:where GUARD)? :yield EXPR
//     :when  PRED                :yield EXPR
//     :else                      :yield EXPR
//   ]
//
// Arms are evaluated top-down; first match wins, no fall-through. On
// no match: returns empty sequence `()` if no `:else`, else `:else`
// fires. Value is optional (predicate-only / SQL Searched-CASE) when
// only `:when`/`:else` arms are present; `:case` arms without a value
// raise CXER0100.
fn eval_match_multi_arm(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	// Optional positional value (first positional slot, if any).
	mut has_value := false
	mut value := cx.Node(cx.Element{ name: '' })
	mut i := 0
	if d.slots.len > 0 && d.slots[0].kind == .positional {
		value = eval_match_scrutinee(d.slots[0].value, mut env)
		has_value = true
		i = 1
	}
	for i < d.slots.len {
		slot := d.slots[i]
		if slot.kind != .labeled {
			return EvalError{
				code:    'cx-err:CXER0100'
				message: '[?match] unexpected positional slot in multi-arm form'
			}
		}
		match slot.label {
			'case' {
				pat_node := slot.value
				mut has_where := false
				mut where_cond := cx.ProgramNode(cx.ProgramLiteral{
					kind: .bool_lit, bool_val: true
				})
				i++
				if i < d.slots.len && d.slots[i].kind == .labeled
				   && d.slots[i].label == 'where' {
					where_cond = d.slots[i].value
					has_where = true
					i++
				}
				if i >= d.slots.len || d.slots[i].kind != .labeled
				   || d.slots[i].label != 'yield' {
					return EvalError{
						code:    'cx-err:CXER0100'
						message: '[?match] :case must be followed by :yield (with optional :where in between)'
					}
				}
				yield_expr := d.slots[i].value
				i++
				if !has_value {
					return EvalError{
						code:    'cx-err:CXER0100'
						message: '[?match] :case requires a value; use :when for predicate-only (SQL Searched-CASE)'
					}
				}
				// `[case //path …]` — the pattern is a CXPath PREDICATE on
				// `value` (§8.2): evaluate the path against `value` as the
				// context document; the arm matches iff it resolves to
				// exactly one node. A multi-valued operand raises CXER0103
				// (MULTI_VALUED_PREDICATE); empty → no match (next arm).
				mut path_matched := ?MatchEnv(none)
				mut is_path_case := false
				if pat_node is cx.ProgramPathExpr {
					is_path_case = true
					mut penv := env.clone_sharing_closures() // #871
					penv.bindings['doc'] = value
					pres := eval_path_expr(pat_node, mut penv)!
					cnt := if pres is cx.Element && pres.name == '' {
						pres.items.len
					} else {
						1
					}
					if cnt > 1 {
						return EvalError{
							code:    'cx-err:CXER0103'
							message: 'cx-err:CXER0103 E_MULTI_VALUED_PREDICATE: `[case //path …]` operand resolved to ${cnt} nodes; a case-path predicate must be single-valued (§8.2)'
						}
					}
					if cnt == 1 {
						path_matched = env.clone_sharing_closures() // #871
					}
				}
				matched := if is_path_case {
					path_matched
				} else {
					match_arm_pattern(pat_node, value, env)
				}
				if matched_env := matched {
					mut snap := matched_env
					if has_where {
						guard := eval_node(where_cond, mut snap)!
						// §9.2 / #348(a): an err-valued :where guard
						// short-circuits the whole [?match] and IS its
						// result — never EBV-coerced (an err reads truthy).
						if is_err_value(guard) {
							return guard
						}
						gebv := node_ebv(guard) or { return iterator_ebv_err() }
						if !gebv {
							continue
						}
					}
					return eval_node(yield_expr, mut snap)!
				}
			}
			'when' {
				cond_expr := slot.value
				i++
				if i >= d.slots.len || d.slots[i].kind != .labeled
				   || d.slots[i].label != 'yield' {
					return EvalError{
						code:    'cx-err:CXER0100'
						message: '[?match] :when must be followed by :yield'
					}
				}
				yield_expr := d.slots[i].value
				i++
				cond_val := eval_node(cond_expr, mut env)!
				// §9.2 / #348(a): an err-valued :when condition propagates —
				// mirrors eval_if's condition slot (#346).
				if is_err_value(cond_val) {
					return cond_val
				}
				webv := node_ebv(cond_val) or { return iterator_ebv_err() }
				if webv {
					return eval_node(yield_expr, mut env)!
				}
			}
			'else' {
				i++
				if i >= d.slots.len || d.slots[i].kind != .labeled
				   || d.slots[i].label != 'yield' {
					return EvalError{
						code:    'cx-err:CXER0100'
						message: '[?match] :else must be followed by :yield'
					}
				}
				yield_expr := d.slots[i].value
				i++
				return eval_node(yield_expr, mut env)!
			}
			else {
				return EvalError{
					code:    'cx-err:CXER0100'
					message: "[?match] unexpected slot label ':${slot.label}' in multi-arm form"
				}
			}
		}
	}
	// No arm matched; multi-arm without :else → empty sequence.
	return cx.Element{ name: '' }
}

fn eval_if(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	// Fail-closed body validation (code.md §8.4, #406): after the cond
	// position, every body child MUST be a [then …] / [else …] clause
	// (or a legacy :then/:else labeled slot). A bare positional branch
	// expression (`[?if C 'a' 'b']` — the shape every Lisp user types
	// first) or a typo'd clause name (`[thn …]`) previously vanished
	// into a silent (), indistinguishable from falsy-with-no-else.
	for i := 1; i < d.slots.len; i++ {
		s := d.slots[i]
		if s.kind == .labeled {
			if s.label != 'then' && s.label != 'else' {
				return EvalError{
					code:    'cx-err:CXER0001'
					message: '[?if] expects [then …] / [else …] clause children — unrecognized :${s.label} slot'
				}
			}
			continue
		}
		if s.kind != .positional {
			continue
		}
		v := s.value
		mut offending := ''
		if v is cx.ProgramLiteral {
			if v.kind == .cx_element && (v.name == 'then' || v.name == 'else') {
				continue
			}
			if v.kind == .cx_element {
				offending = '[${v.name} …]'
			}
		}
		if offending == '' {
			offending = 'a bare positional branch expression'
		}
		return EvalError{
			code:    'cx-err:CXER0001'
			message: '[?if] expects [then …] / [else …] clause children after the condition — got ${offending}; write [?if cond [then thenExpr] [else elseExpr]?]'
		}
	}
	cond_slot := d.slots[0].value
	cond := eval_node(cond_slot, mut env)!
	// §9.2 implicit operand propagation: an [err] condition short-circuits
	// the conditional and IS its result — never EBV-coerced (an err element
	// would read truthy: items.len > 0). #346's "-O1 miscompile" was this
	// hole surfacing wherever the #319 stack-guard err happened to land on
	// a condition slot; which probe point fires first is frame-layout- and
	// build-mode-dependent, so the symptom moved with the optimizer level.
	if is_err_value(cond) {
		return cond
	}
	// #388: an Iterator condition has no EBV — catchable CXER0100.
	truthy := node_ebv(cond) or { return iterator_ebv_err() }
	if truthy {
		then_expr := directive_clause(d, 'then') or { return cx.Element{ name: '' } }
		return eval_node(then_expr, mut env)!
	}
	else_expr := directive_clause(d, 'else') or { return cx.Element{ name: '' } }
	return eval_node(else_expr, mut env)!
}

// is_empty_absence reports whether n is the §9.1.2 absence channel — the empty
// node-set / empty sequence ONLY. NOT a present null, false/0/''/[]/{}, an
// [invalid], or a named (e.g. [user]) element. The canonical empty result is a
// nameless Element with no items/attrs (eval_if's no-branch, the seq wrapper) or
// an empty SequenceNode.
pub fn is_empty_absence(n cx.Node) bool {
	if n is cx.SequenceNode {
		return n.items.len == 0
	}
	if n is cx.Element {
		if n.items.len != 0 || n.attrs.len != 0 {
			return false
		}
		// The empty node-set is the nameless wrapper (eval_if no-branch) or the
		// empty sequence envelope `()` (seq_marker_name). An empty array `[]`
		// (arr_marker_name) or empty map `{}` (__cx_map__) is a present VALUE,
		// not absence — it passes through.
		return n.name == '' || n.name == seq_marker_name
	}
	return false
}

// eval_else implements [?else EXPR DEFAULT] (code.md §8.13): the value-or-default
// coalesce / getOrElse. EXPR is a §9.2-exempt boundary — an [err] from EXPR is
// captured (not auto-propagated) and triggers DEFAULT. DEFAULT is LAZY (evaluated
// only on the err/absence path). Default fires ONLY on [err] or the empty
// node-set/sequence; null / false / 0 / '' / [] / {} / [invalid] / any value pass
// through.
fn eval_else(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	mut pos := []cx.ProgramNode{}
	for s in d.slots {
		if s.kind == .positional {
			pos << s.value
		}
	}
	if pos.len < 2 {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: '[?else] requires EXPR and DEFAULT (got ${pos.len} positional arg(s))'
		}
	}
	result := eval_node(pos[0], mut env) or {
		// Thrown EvalError from EXPR → captured at this boundary; take DEFAULT.
		return eval_node(pos[1], mut env)!
	}
	if is_err_value(result) || is_empty_absence(result) {
		return eval_node(pos[1], mut env)!
	}
	return result
}

// binding_clause recognises an binding clause `[= $x v]` and
// returns (var-name, value-expr). Used by [?let]/[?with-open]/[?for] etc.
// to read declare+init bindings carried as `=`-headed clause children.
fn binding_clause(n cx.ProgramNode) ?(string, cx.ProgramNode) {
	if n is cx.ProgramLiteral {
		if n.kind == .cx_element && n.name == '=' && n.items.len == 2 {
			head := n.items[0]
			if head is cx.ProgramBinding && head.path.len == 0 {
				return head.name, n.items[1]
			}
		}
	}
	return none
}

// envcheck_probe (#58, gated -d cx_envcheck): catch a live env whose bindings
// map BACKING ARRAY has been swept — the sweep-while-live UAF at its source,
// BEFORE the imminent clone reads freed key structs. Prints only on the
// anomaly (never in the healthy hot path) => non-masking.
fn envcheck_probe(site string, env &MatchEnv) {
	$if cx_envcheck ? {
		st := vgc_map_backing_status(voidptr(unsafe { &env.bindings }))
		ks := st & 0xff
		// vgc_envcheck_dedupe: a dead env fires once, not on every node it evaluates.
		if ks != 0xff && (ks & 1) == 0 && vgc_envcheck_dedupe(usize(voidptr(env))) {
			envp := u64(usize(voidptr(env)))
			cidx, lo, hi, dcyc, parked := vgc_spchk_self()
			in_win := if usize(voidptr(env)) >= lo && usize(voidptr(env)) < hi {
				'IN-WINDOW'
			} else {
				'OUT-OF-WINDOW'
			}
			kp := vgc_map_keys_ptr(voidptr(unsafe { &env.bindings }))
			fra := vgc_explicit_free_ra(kp)
			freed_by := if fra != 0 { 'EXPLICIT ra1=0x${fra.hex()}' } else { 'SWEPT' }
			// Dangling-frame discriminator: compare the env address against the REAL
			// current SP (C-level register read — a V `&local` probe gets heap-boxed
			// by escape analysis and yields a meaningless arena address). An env
			// BELOW the current SP (deeper on a downward stack) can only be a DEAD
			// frame — the env pointer is dangling and its swept subtree was
			// CORRECTLY collected. ABOVE it = a live ancestor frame (the scan
			// should have kept its subtree alive).
			here := u64(vgc_current_sp())
			rel := if envp < here { 'ENV-BELOW-SP(DANGLING-FRAME)' } else { 'ENV-ABOVE(LIVE-ANCESTOR)' }
			bd := vgc_birth_delta(kp)
			// Span-descriptor identity: birth-time carver vs current resolver. A
			// mismatch = two descriptors over one address range (span aliasing) —
			// the memory was served twice and every downstream symptom follows.
			bspan := vgc_birth_span_of(kp)
			cspan := vgc_find_span_addr(kp)
			alias := if bspan != 0 && bspan != cspan { 'SPAN-ALIASED' } else { 'span-same' }
			eprintln('cx#58 envcheck DEAD-KEYS site=${site} env=0x${envp.hex()} frame=0x${here.hex()} ${rel} env_arena=0x${vgc_addr_status(voidptr(env)).hex()} status=0x${st.hex()} len=${(st >> 16) & 0xffffffff} keys=0x${u64(usize(kp)).hex()} ${freed_by} birth_dcyc=${bd} ${alias} bspan=0x${u64(bspan).hex()} cspan=0x${u64(cspan).hex()} tid=${cidx} scanwin=[0x${u64(lo).hex()},0x${u64(hi).hex()}] ${in_win} dcyc=${dcyc} parked=${parked}')
		}
	}
}

fn eval_let(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	// Legacy form: :bind / :value / :in(body) labeled slots.
	if bind_slot := labeled_slot(d, 'bind') {
		value_slot := labeled_slot(d, 'value') or {
			return EvalError{ code: 'cx-err:CXER0001', message: '[?let] missing value slot' }
		}
		body_slot := labeled_slot(d, 'body') or {
			return EvalError{ code: 'cx-err:CXER0001', message: '[?let] missing body slot' }
		}
		bind_name := if bind_slot is cx.ProgramLiteral && bind_slot.kind == .string_lit {
			bind_slot.str_val
		} else {
			return EvalError{ code: 'cx-err:CXER0001', message: '[?let] bind slot malformed' }
		}
		value := eval_node(value_slot, mut env)!
		envcheck_probe('let_bind', &env)
		// Frame-sharing clone (#272): a [?let] frame only ever writes bindings,
		// so the closures table is aliased read-only (cow_closures guards every
		// write site) instead of deep-copied. Deep-copying here was the dominant
		// per-request allocation on served render paths — every let in every
		// closure body cloned the whole program closure table (540+ entries on
		// a [$xap:host] deployment), and the resulting multi-GB/s churn drove
		// the GC collect storm that wedged the HTTP plane.
		mut extended := env.clone_frame_sharing_closures()
		extended.bindings[bind_name] = value
		return eval_node(body_slot, mut extended)!
	}
	// form: zero or more `[= $x v]` binding clauses followed by a
	// trailing positional body. The LAST positional slot is the
	// body regardless of shape — without this rule a body like `[= $a $b]`
	// (equality) is indistinguishable from a binding clause by shape alone
	// and gets swallowed as another binding, leaving no body.
	envcheck_probe('let_pos', &env)
	// Frame-sharing clone (#272) — see the :bind form above.
	mut extended := env.clone_frame_sharing_closures()
	mut positionals := []cx.ProgramNode{}
	for s in d.slots {
		if s.kind == .positional {
			positionals << s.value
		}
	}
	if positionals.len == 0 {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?let] missing body expression' }
	}
	for i := 0; i < positionals.len - 1; i++ {
		name, vexpr := binding_clause(positionals[i]) or {
			return EvalError{
				code:    'cx-err:CXER0001'
				message: '[?let] expected [= \$x V] binding clause before the body'
			}
		}
		val := eval_node(vexpr, mut extended)!
		extended.bindings[name] = val
	}
	return eval_node(positionals[positionals.len - 1], mut extended)!
}

// eval_loop — `[?loop [= $x INIT]… BODY]` with the `[break V?]` /
// `[continue V…?]` clause-heads (spec/code.md §8.15; #550, owner ruling
// 2026-07-21). THE condition-driven loop: anonymous tail recursion driven
// as a V-level loop (O(1) native stack, the #60 trampoline's semantics
// without the named def / threaded params / marker returns). No mutation:
// `[continue V…]` REBINDS the declared loop bindings for the next pass —
// positionally, arity-checked — exactly like the tail call it replaces; a
// bare `[continue]` repeats with unchanged state.
//
// ALL-EXPLICIT tail contract: each pass's body value must be a
// `[break …]` (exit; the loop's value is its single item, `null` when
// bare) or a `[continue …]` element — anything else raises CXER0100.
// Clojure's implicit exit (any non-recur value) is deliberately rejected:
// a branch that forgets its exit word is a diagnostic, never a silent
// wrong answer. An `[err …]` body value propagates as itself (§9.2 —
// the fault channel outranks the tail contract).
fn eval_loop(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	mut positionals := []cx.ProgramNode{}
	for s in d.slots {
		if s.kind == .positional {
			positionals << s.value
		}
	}
	if positionals.len == 0 {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?loop] missing body expression' }
	}
	// Leading `[= $x INIT]` clauses declare the loop bindings; the LAST
	// positional is the body (the [?let] rule — a `[= a b]` equality body
	// is still a body).
	mut names := []string{}
	mut extended := env.clone_frame_sharing_closures()
	for i := 0; i < positionals.len - 1; i++ {
		name, vexpr := binding_clause(positionals[i]) or {
			return EvalError{
				code:    'cx-err:CXER0100'
				message: '[?loop] expected [= \$x INIT] binding clauses before the body (spec/code.md §8.15)'
			}
		}
		val := eval_node(vexpr, mut extended)!
		extended.bindings[name] = val
		names << name
	}
	body := positionals[positionals.len - 1]
	for {
		result := eval_node(body, mut extended)!
		if result is cx.Element {
			if is_err_value(result) {
				return result
			}
			if result.name == 'break' {
				if result.items.len == 0 {
					// bare [break] — unit exit (a present null, §9.1.2.1 2b)
					return cx.Node(cx.ScalarNode{
						value:     cx.ScalarValue(cx.NullValue{})
						data_type: cx.ScalarType.null_type
					})
				}
				if result.items.len == 1 {
					return result.items[0]
				}
				return cx.Node(cx.Element{ name: seq_marker_name, items: result.items })
			}
			if result.name == 'continue' {
				if result.items.len == 0 {
					continue // unchanged state
				}
				if result.items.len != names.len {
					return EvalError{
						code:    'cx-err:CXER0100'
						message: '[?loop] [continue …] carries ${result.items.len} value(s) for ${names.len} loop binding(s) — rebind all declared bindings positionally, or none (spec/code.md §8.15)'
					}
				}
				for i, nm in names {
					extended.bindings[nm] = result.items[i]
				}
				continue
			}
		}
		return EvalError{
			code:    'cx-err:CXER0100'
			message: '[?loop] body must end in [break …] or [continue …] — every exit is explicit (spec/code.md §8.15)'
		}
	}
	return cx.Node(cx.Element{})
}

// eval_do — `[?do E …]` (spec/code.md §8.14; #550, resolves #530's ask):
// the blessed evaluate-FOR-EFFECT sequencing form. Expressions evaluate in
// order; their values are DISCARDED — except the first `[err …]` result,
// which propagates immediately per §9.2 instead of vanishing in an
// unobserved dummy [?let] binding. Success yields `null` (a present
// unit, §9.1.2.1 role 2b — never absence, which would read as "nothing
// happened").
fn eval_do(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	mut ran := 0
	for s in d.slots {
		if s.kind != .positional {
			continue
		}
		v := eval_node(s.value, mut env)!
		if v is cx.Element && is_err_value(v) {
			return v
		}
		ran++
	}
	if ran == 0 {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?do] requires at least one expression (spec/code.md §8.14)' }
	}
	return cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(cx.NullValue{})
		data_type: cx.ScalarType.null_type
	})
}

// ── Tail-call optimization (#60) ─────────────────────────────────────────────
//
// cx forever-loops / long-running loops are written as tail recursion (the only
// looping idiom — there is no imperative loop primitive yet, see #61). The
// tree-walking evaluator has no TCO, so a tail-recursive loop recurses the
// native C stack ~42 KB per level and SIGSEGVs at ~190 deep. The trampoline
// below fixes this at the root, semantics-preserving and with no surface change.
//
// eval_tail evaluates `node` in TAIL position. Tail position threads through
// the chosen branch of [?if] and the body of [?let] — the forms a loop nests
// its self-call inside. When evaluation bottoms out at a call to a param-spec
// [?def] closure, eval_tail returns it PENDING (is_tail=true) WITHOUT invoking,
// so run_closure_body can loop instead of recursing. Any other shape (including
// multi-expression .block bodies, [?else], builtins, lambdas) is evaluated
// fully and returned as a value (is_tail=false) — always correct, just not
// trampolined. The applied tail call takes exactly the binding+eval path
// invoke_closure_l/bind_specs_and_eval would have taken, so behavior is
// identical to the recursive evaluation it replaces.
struct TailResult {
mut:
	is_tail bool
	value   cx.Node = cx.Element{}
	// closure stays EMBEDDED by value. Heap-boxing it (length-1 []Closure,
	// the Closure.body idiom) was studied for #326 — it shrinks every
	// !TailResult result temp ~4x, but the per-trampoline-hop allocation
	// cost a consistent ~3% on the 1M-iteration tail loop (3.63s -> 3.75s,
	// 12 interleaved rounds, dev build), so it was measured and REJECTED:
	// tail throughput wins over frame width here (the frame diet took the
	// per-level cycle down 33% without it).
	closure Closure
	args    []cx.Node
	labels  []string
}

fn eval_tail(node cx.ProgramNode, mut env MatchEnv) !TailResult {
	match node {
		cx.ProgramDirective {
			// PS-1: a STEPPED directive (`[?if …]/x` in tail position) is a
			// READ over the directive result, never a tail-threaded branch —
			// route through eval_directive, which applies the step run.
			if node.path.len > 0 {
				return TailResult{ value: eval_directive(node, mut env)! }
			}
			// [?if]: evaluate the condition (not tail), then the chosen branch
			// in tail position. Mirrors eval_if.
			if node.name == 'if' && node.slots.len > 0 {
				cond := eval_node(node.slots[0].value, mut env)!
				// §9.2: err condition propagates — mirrors eval_if.
				if is_err_value(cond) {
					return TailResult{ value: cond }
				}
				cebv := node_ebv(cond) or { return TailResult{ value: iterator_ebv_err() } }
				if cebv {
					then_expr := directive_clause(node, 'then') or {
						return TailResult{ value: cx.Element{ name: '' } }
					}
					return eval_tail(then_expr, mut env)
				}
				else_expr := directive_clause(node, 'else') or {
					return TailResult{ value: cx.Element{ name: '' } }
				}
				return eval_tail(else_expr, mut env)
			}
			// [?let]: bind the clauses (not tail), then the body in tail position.
			if node.name == 'let' {
				return eval_let_tail(node, mut env)
			}
			return TailResult{ value: eval_directive(node, mut env)! }
		}
		cx.ProgramCall {
			return eval_call_tail(node, mut env)
		}
		cx.ProgramLiteral {
			// A bracket-form call `[loop arg]` is parsed as a cx_element
			// LITERAL, not a ProgramCall — it is the dominant tail-call shape.
			if node.kind == .cx_element {
				return cx_element_as_tail_call(node, mut env)
			}
			return TailResult{ value: eval_node(node, mut env)! }
		}
		else {
			return TailResult{ value: eval_node(node, mut env)! }
		}
	}
}

// tco_trampolinable reports whether a tail call to `cl` can be looped by
// run_closure_body. Restricted to plain param-spec [?def] closures (the
// forever-loop case): no builtin wrapper, no partial application, not variadic.
// Lambdas / variadic / simple-positional closures fall back to ordinary
// (recursive) application — they are not the long-running-loop idiom.
fn tco_trampolinable(cl &Closure) bool {
	return cl.builtin_name == '' && cl.partial_target.len == 0
		&& cl.param_specs.len > 0 && !cl.is_variadic
}

// cx_element_as_tail_call recognises a bracket-form closure call in tail
// position and returns it PENDING (#60), mirroring the closure-dispatch shapes
// of eval_cx_element (paren-sequence args, and the bare whitespace form
// `[name a b …]` whose head is a registered closure). Any cx_element that is
// NOT one of those call shapes — data construction, a builtin head, an
// operator element, a dynamic/typed element — is evaluated normally. Keep the
// gates in sync with eval_cx_element.
// value_tail evaluates `n` as a plain (non-tail) expression and wraps the
// result in a value TailResult. Callers `return value_tail(…)` BARE (#325
// direct-return): each inline `return TailResult{ value: eval_node(…)! }`
// carried a ~456 B result-struct temporary (TailResult embeds a by-value
// Closure) that V does not coalesce at -O0 — cx_element_as_tail_call had six
// of them on the per-level recursion frame (#326 frame diet).
fn value_tail(n cx.ProgramNode, mut env MatchEnv) !TailResult {
	return TailResult{ value: eval_node(n, mut env)! }
}

fn cx_element_as_tail_call(l cx.ProgramLiteral, mut env MatchEnv) !TailResult {
	// PS-1: a STEPPED element form (`[loop $x]/y` in tail position) is a
	// READ over the result, never a trampolinable tail call — evaluate
	// normally (eval_literal applies the step run).
	if l.path.len > 0 {
		return value_tail(cx.ProgramNode(l), mut env)
	}
	// Dynamic-name (`[?element …]`) and glued-`::T` typed elements never
	// dispatch as calls — construct normally.
	if l.data_type != '' {
		return value_tail(cx.ProgramNode(l), mut env)
	}
	if _ := l.name_expr {
		return value_tail(cx.ProgramNode(l), mut env)
	}
	if l.name == '' {
		return value_tail(cx.ProgramNode(l), mut env)
	}
	// #342: one by-ref lookup replaces the `!in` probe + the copying `or {}`
	// get. Trampolinability is checked through the ref (no copy); the
	// closure is copied out BEFORE any argument evaluation (which can
	// register closures, rehash env.closures, and invalidate the ref).
	pcl := unsafe { env.closures.value_ptr(l.name) }
	if pcl == unsafe { nil } || !tco_trampolinable(pcl) {
		return value_tail(cx.ProgramNode(l), mut env)
	}
	cl := unsafe { *pcl }
	mut args := []cx.Node{}
	if l.slots.len == 0 && l.items.len == 1 && l.items[0] is cx.ProgramLiteral
		&& (l.items[0] as cx.ProgramLiteral).kind == .sequence_lit {
		// `[name (a, b, …)]` — paren-sequence arg shape.
		seq := l.items[0] as cx.ProgramLiteral
		for it in seq.items {
			args << eval_call_arg(it, mut env)!
		}
	} else if l.slots.len == 0 && l.attrs.len == 0 && all_items_are_expr_position(l.items, env.closures) {
		// `[name a b …]` — bare whitespace call shape (covers single-arg
		// binding / scalar / nested-element forms too).
		for it in l.items {
			args << eval_call_arg(it, mut env)!
		}
	} else {
		// Not a recognised call shape → construct / evaluate normally.
		return value_tail(cx.ProgramNode(l), mut env)
	}
	for a in args {
		if a is cx.Element && is_err_value(a) {
			return TailResult{ value: a }
		}
	}
	return TailResult{
		is_tail: true
		closure: cl
		args:    args
		labels:  []string{}
	}
}

// eval_let_tail mirrors eval_let but evaluates the trailing body in TAIL
// position (#60). Keep in sync with eval_let.
fn eval_let_tail(d cx.ProgramDirective, mut env MatchEnv) !TailResult {
	if bind_slot := labeled_slot(d, 'bind') {
		value_slot := labeled_slot(d, 'value') or {
			return EvalError{ code: 'cx-err:CXER0001', message: '[?let] missing value slot' }
		}
		body_slot := labeled_slot(d, 'body') or {
			return EvalError{ code: 'cx-err:CXER0001', message: '[?let] missing body slot' }
		}
		bind_name := if bind_slot is cx.ProgramLiteral && bind_slot.kind == .string_lit {
			bind_slot.str_val
		} else {
			return EvalError{ code: 'cx-err:CXER0001', message: '[?let] bind slot malformed' }
		}
		value := eval_node(value_slot, mut env)!
		envcheck_probe('lett_bind', &env)
		// Frame-sharing clone (#272) — see eval_let. The tail form is the hot
		// one: served readout/view bodies are nested let-chains, so this ran
		// hundreds of times per HTTP request.
		mut extended := env.clone_frame_sharing_closures()
		extended.bindings[bind_name] = value
		return eval_tail(body_slot, mut extended)
	}
	envcheck_probe('lett_pos', &env)
	// Frame-sharing clone (#272) — see eval_let.
	mut extended := env.clone_frame_sharing_closures()
	mut positionals := []cx.ProgramNode{}
	for s in d.slots {
		if s.kind == .positional {
			positionals << s.value
		}
	}
	if positionals.len == 0 {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?let] missing body expression' }
	}
	for i := 0; i < positionals.len - 1; i++ {
		name, vexpr := binding_clause(positionals[i]) or {
			return EvalError{
				code:    'cx-err:CXER0001'
				message: '[?let] expected [= \$x V] binding clause before the body'
			}
		}
		val := eval_node(vexpr, mut extended)!
		extended.bindings[name] = val
	}
	return eval_tail(positionals[positionals.len - 1], mut extended)
}

// eval_call_tail decides whether a call in tail position is a trampolinable
// tail call to a plain param-spec [?def] closure (#60). If so it evaluates the
// arguments and returns the pending call without dispatching; otherwise it
// falls back to eval_call unchanged. The callee is resolved by a side-effect-
// free table lookup BEFORE the arguments are evaluated (args cannot legitimately
// rebind the callee mid-call); every fallback path returns before any argument
// is evaluated, so eval_call never double-evaluates them. Mirrors eval_call's
// dispatch guards (bare-ref, holes, hof/meta/fp shadow, !-postfix).
// call_value_tail evaluates `c` as a plain (non-tail) call and wraps the
// result — the eval_call twin of value_tail (#326 frame diet): callers
// `return call_value_tail(…)` BARE so eval_call_tail's per-level frame
// carries no ~456 B TailResult result-struct temporaries.
fn call_value_tail(c cx.ProgramCall, mut env MatchEnv) !TailResult {
	return TailResult{ value: eval_call(c, mut env)! }
}

fn eval_call_tail(c cx.ProgramCall, mut env MatchEnv) !TailResult {
	// CRS-1: a stepped call (`[$f …]/name` in tail position) is a value
	// READ over the call result, never a trampolinable tail call — route
	// through eval_call, which applies the postfix path.
	if c.path.len > 0 {
		return call_value_tail(c, mut env)
	}
	if !c.explicit_call && c.args.len == 0 {
		return call_value_tail(c, mut env)
	}
	for a in c.args {
		if a is cx.ProgramCall && a.name == cx.program_hole_name {
			return call_value_tail(c, mut env)
		}
	}
	if (c.name in ['filter', 'map', 'reduce'] || c.name == 'meta-of' || c.name.starts_with('fp-'))
		&& c.name !in env.closures && c.name !in env.bindings {
		return call_value_tail(c, mut env)
	}
	if c.must_succeed {
		return call_value_tail(c, mut env)
	}
	// #342: by-ref closure lookup — trampolinability is checked through the
	// ref (no copy on the reject path); the closure is copied out only when
	// the call will actually trampoline, and BEFORE argument evaluation
	// (which can register closures and invalidate the ref).
	mut cl := Closure{}
	pcl := unsafe { env.closures.value_ptr(c.name) }
	if pcl != unsafe { nil } {
		if !tco_trampolinable(pcl) {
			return call_value_tail(c, mut env)
		}
		cl = unsafe { *pcl }
	} else if bval := env.bindings[c.name] {
		rc := resolve_closure(bval, env) or {
			return call_value_tail(c, mut env)
		}
		if !tco_trampolinable(&rc) {
			return call_value_tail(c, mut env)
		}
		cl = rc
	} else {
		return call_value_tail(c, mut env)
	}
	// Evaluate args (eager, source order, matching eval_call). An err-value
	// argument is itself the call result (error-as-value model); return it
	// without dispatching, exactly as eval_call does.
	mut args := []cx.Node{}
	for a in c.args {
		args << eval_call_arg(a, mut env)!
	}
	for a in args {
		if a is cx.Element && is_err_value(a) {
			return TailResult{ value: a }
		}
	}
	return TailResult{
		is_tail: true
		closure: cl
		args:    args
		labels:  c.arg_labels
	}
}

// mk_err_code_only builds an [err :code <code>] node (no :message slot).
// Used as the inner cause node for chained errors (err-004 fixture).
fn mk_err_code_only(err_code string) cx.Node {
	// `[err code=<code> message=<§9.5.1>]` — used for inner cause errs.
	mut attrs := [
		cx.Attribute{ name: 'code', value: cx.ScalarValue(err_code) },
	]
	msg := canonical_message(err_code, [])
	if msg != '' {
		attrs << cx.Attribute{ name: 'message', value: cx.ScalarValue(msg) }
	}
	return cx.Element{ name: 'err', attrs: attrs }
}

// mk_err_with_cause builds `[err code=<code> message='panic' [cause <cause>]]`.
// Used by the boundary converters when the upstream EvalError carries a structured
// cause from a `!`-postfix panic; the canonical §9.2 panic message is
// 'panic' and the original failure is chained as the `[cause …]` child.
pub fn mk_err_with_cause(err_code string, cause cx.Node) cx.Node {
	e := cx.Node(cx.Element{
		name: 'err'
		attrs: [
			cx.Attribute{ name: 'code', value: cx.ScalarValue(err_code) },
			cx.Attribute{ name: 'message', value: cx.ScalarValue('panic') },
		]
		items: [
			cx.Node(cx.Element{ name: 'cause', items: [cause] }),
		]
	})
	fire_raise_observe(e) // §9.6 raise-stage observe (error_hooks.v)
	return e
}

// is_err_value reports whether a value is a failure outcome. 
// draft-3: the sole canonical shape is `[result status=err …]` (the
// legacy `[err …]` element-name form is fully retired).
pub fn is_err_value(n cx.Node) bool {
	if n is cx.Element {
		return n.name == 'err'
	}
	return false
}

// is_ok_value reports whether a value is the status-only success
// sentinel `[ok]` (§9.1.1). Value-bearing successes return the raw
// value, not an envelope, so they are not is_ok_value.
fn is_ok_value(n cx.Node) bool {
	if n is cx.Element {
		return n.name == 'ok'
	}
	return false
}

// ── [?with-scope] — dynamic-scoped context (§8.10.8) ───────────────

// entry_key returns the key of a `__cx_map__` entry element (its name).
fn entry_key(n cx.Node) string {
	if n is cx.Element {
		return n.name
	}
	return ''
}

// merge_dyn_context produces merge(outer, inner) with the inner map
// winning for shared keys (shallow, key-level). Entries
// are `__cx_map__` child elements keyed by element name.
fn merge_dyn_context(outer []cx.Node, inner []cx.Node) []cx.Node {
	mut result := outer.clone()
	for ie in inner {
		k := entry_key(ie)
		mut found := false
		for i, oe in result {
			if entry_key(oe) == k {
				result[i] = ie
				found = true
				break
			}
		}
		if !found {
			result << ie
		}
	}
	return result
}

fn eval_with_scope(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	fields_slot := labeled_slot(d, 'scope-fields') or {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?with-scope] missing fields map' }
	}
	body := positional_slots(d)
	if body.len == 0 {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?with-scope] empty body' }
	}
	fields_val := eval_node(fields_slot, mut env)!
	// A map value is the `__cx_map__` envelope element (see eval_map);
	// anything else is a type error.
	if fields_val !is cx.Element || (fields_val as cx.Element).name != map_marker_name {
		return EvalError{
			// code.md §8.10.8 / registry: E_SCOPE_NOT_MAP. (code.md:1918 —
			// no directive raises CXER0001 directly.)
			code:    'cx-err:CXER0109'
			message: '[?with-scope] context expression must evaluate to a map'
		}
	}
	fields_el := fields_val as cx.Element
	// Merge over the active context and run the body in a clone whose
	// dyn_context carries the merge. Restore-on-exit is automatic: the
	// merged context lives only on `extended`; the caller's env keeps the
	// prior context on both normal return and error unwind (the `!`
	// propagation below discards `extended`).
	mut extended := env.clone()
	extended.dyn_context = merge_dyn_context(env.dyn_context, fields_el.items)
	mut result := cx.Node(cx.ScalarNode{ value: cx.ScalarValue(cx.NullValue{}), data_type: .null_type })
	for s in body {
		result = eval_node(s, mut extended)!
	}
	return result
}

// ── [?with-caps] — capability narrowing (security.md §3, grammar [167]) ─
//
// `[?with-caps [deny CAP (resource)?]+ BODY]` drops the named capabilities
// for BODY's dynamic extent. Narrow-only: a program can never widen its
// set (the host grant is the ceiling). The narrowed set is installed for
// the body and restored on exit — including error unwind — via `defer`.
// A denied effect reached inside BODY raises CXER0271 at its effect point.
fn eval_with_caps(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	mut denied := []string{}
	for s in d.slots {
		if s.kind == .labeled && s.label == 'deny' {
			if s.value is cx.ProgramLiteral {
				lit := s.value as cx.ProgramLiteral
				if lit.kind == .string_lit {
					denied << lit.str_val
				}
			}
		}
	}
	body := positional_slots(d)
	if denied.len == 0 || body.len == 0 {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: '[?with-caps] requires >=1 [deny CAP] clause and a body expression'
		}
	}
	saved := caps_push_narrowed(denied)
	defer {
		caps_restore(saved)
	}
	mut result := cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(cx.NullValue{})
		data_type: .null_type
	})
	for s in body {
		result = eval_node(s, mut env)!
	}
	return result
}

// ── [?secret] / [?reveal] — secret values (cxdm.md §12) ────────────────
//
// `[?secret EXPR]` wraps a value as secret (exactly one expr, else
// CXER0100). The wrapper is a `__cx_secret__` element holding the value as
// its single child; computation unwraps it, output boundaries redact it.
// `[?reveal EXPR]` declassifies — gated by the `secret-reveal` capability
// (deny-first: the gate is checked before the inner expression is
// evaluated), returning CXER0271 as an err-value when not granted.
fn eval_secret(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	body := positional_slots(d)
	if body.len != 1 {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: '[?secret] requires exactly one expression'
		}
	}
	val := eval_node(body[0], mut env)!
	return cx.Element{
		name:  secret_marker_name
		items: [val]
	}
}

fn eval_reveal(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	body := positional_slots(d)
	if body.len != 1 {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: '[?reveal] requires exactly one expression'
		}
	}
	// Deny-first (security.md §4): gate the declassification before
	// producing any cleartext. CXER0271 is returned as an err-value.
	if denial := cap_guard('secret-reveal', 'reveal') {
		return denial
	}
	val := eval_node(body[0], mut env)!
	if val is cx.Element {
		el := val as cx.Element
		if el.name == secret_marker_name && el.items.len == 1 {
			return el.items[0]
		}
	}
	return val
}

// ── [?str] — compile-time string interpolation (§8.12) ─────────────
//
// Walks the alternating literal / hole slot stream built by
// parse_str_body. Literal segments (`[lit V]`) are appended verbatim;
// hole segments (`[hole E]`) evaluate the binding-path expression in the
// enclosing lexical environment and render its scalar value to text. A
// hole resolving to a non-scalar (element / sequence / map) raises
// CXER0100; an unbound `$binding` surfaces the ordinary unbound-binding
// error. `[?str]` requires no capability and is pure.
fn eval_str(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	mut buf := []u8{}
	for s in d.slots {
		match s.label {
			'lit' {
				lit := s.value
				if lit is cx.ProgramLiteral {
					buf << lit.str_val.bytes()
				}
			}
			'hole' {
				val := eval_node(s.value, mut env)!
				buf << render_str_hole_value(val)!.bytes()
			}
			else {}
		}
	}
	return cx.ScalarNode{
		value:     cx.ScalarValue(buf.bytestr())
		data_type: cx.ScalarType.string_type
	}
}

// render_str_hole_value renders a [?str] interpolation hole's value to
// text per spec/code.md §8.12: a `string` is its characters, other
// scalars their canonical lexical form (an atom renders `:name`). A
// non-scalar (element / sequence / map) raises CXER0100. A singleton
// sequence wrapper is XPath-atomized to its sole item first.
fn render_str_hole_value(n cx.Node) !string {
	v := unwrap_single_item(n)
	if v is cx.ScalarNode {
		// Atoms carry their name in a string ScalarValue but render `:name`.
		if v.data_type == cx.ScalarType.atom_type {
			if v.value is string {
				return ':${v.value as string}'
			}
		}
		sv := v.value
		match sv {
			string { return sv }
			i64    { return sv.str() }
			f64    { return sv.str() }
			bool   { return sv.str() }
			cx.NullValue { return 'null' }
		}
	}
	if v is cx.TextNode {
		return v.value
	}
	return EvalError{
		code:    'cx-err:CXER0100'
		message: '[?str] interpolation hole resolves to a non-scalar value (element / sequence / map); only scalars can be rendered'
	}
}

// ── [?with-open] — scoped-resource RAII (§8.10.7) ──────────────────

pub const close_id_attr = '__cx_close_id__'

// closeable_close_id returns the close-id stamped on a handle element
// iff the value carries the nominal close-contract — i.e.
// it is a cx.Element with a `__cx_close_id__` attribute whose id is a
// live entry in the runtime closeable registry. Returns none otherwise
// (the value is not [?with-open]-able → CXER0001 at the call site).
fn closeable_close_id(n cx.Node, mut env MatchEnv) ?string {
	if n !is cx.Element {
		return none
	}
	el := n as cx.Element
	id := el.attr(close_id_attr)
	if id == '' {
		return none
	}
	if id !in env.state.closeables {
		return none
	}
	return id
}

// fire_close invokes a registered close exactly once (idempotent):
// a second close on an already-closed handle is a silent
// no-op. The fired label is appended to state.close_log for fixture
// observability. A close that itself raises is returned as an err so the
// caller can apply D7 surfacing.
fn fire_close(id string, mut env MatchEnv) ! {
	mut rec := env.state.closeables[id] or { return }
	if rec.closed {
		return
	}
	rec.closed = true
	// Concurrency-handle close (§10.5.7.1): a future/worker handle's close
	// CANCELS-AND-JOINS the task. Cancelling-then-joining a not-yet-terminal
	// task is the requested outcome and is a CLEAN close (no error). The
	// close-result precedence (child/body fault > cancellation > close fault)
	// means a task that genuinely FAILED surfaces its [err] as the close
	// error; a cancelled or done task closes cleanly.
	if rec.handle_kind != '' {
		close_concurrency_handle(rec.handle_kind, rec.handle_id, mut env) or {
			env.state.close_log << '${rec.label}!err'
			return err
		}
		env.state.close_log << rec.label
		return
	}
	rec.close_fn() or {
		env.state.close_log << '${rec.label}!err'
		return err
	}
	env.state.close_log << rec.label
}

// close_concurrency_handle implements the cancel-and-join close for an
// [?async] future / [?worker] handle (spec/code.md §10.5.7.1). It requests
// cancellation, then joins (drives the future to a terminal state). Per the
// close-result precedence table, a task that genuinely FAILED surfaces its
// [err] (priority 1/2 — child/body fault); a CANCELLED or DONE task closes
// cleanly (cancellation is the requested outcome, never reported as a
// close-time error masking nothing).
fn close_concurrency_handle(kind string, hid string, mut env MatchEnv) ! {
	match kind {
		'future' {
			mut fut := env.state.future_get(hid) or { return }
			future_request_cancel(mut fut)
			// Join: drive a lazy future to terminal; a concurrent one joins
			// at its await barrier (#541 — the parked/running body observes
			// the flag at its next cancellation point).
			// EV-ASYNC-SPAWN (W3): every future is concurrent — the
			// lazy driver is retired; the barrier joins terminals too.
			await_concurrent(mut fut, i64(0), mut env)
			if fut.state == 'failed' {
				// A genuine body fault surfaces as the close error (§10.5.7.1
				// close-result precedence — child/body fault is priority 1/2).
				return EvalError{ code: err_code_of(fut.cause), message: 'future close joined a failed task' }
			}
		}
		'worker' {
			mut wrec := env.state.worker_get(hid) or { return }
			// Closing requests cancellation (idempotent, locked — §10.5.4
			// request semantics: a completed worker keeps its value) and
			// joins with the same exit condition as [?wait-for]'s spin. A
			// worker that genuinely FAILED surfaces its fault; a cancelled
			// worker closes cleanly (cancellation is the requested outcome).
			env.state.worker_request_cancel(wrec)
			for !wrec.done && !wrec.cancelled {
				time.sleep(time.millisecond)
			}
			if wrec.done && !wrec.cancelled && is_err_value(wrec.result) {
				return EvalError{ code: err_code_of(wrec.result), message: 'worker close joined a failed task' }
			}
		}
		else {}
	}
}

// close_opened_lifo closes every still-open binding innermost-first.
// Returns the FIRST close error encountered (for D7 surfacing on normal
// completion); all bindings are still attempted regardless.
fn close_opened_lifo(ids []string, mut env MatchEnv) ?cx.Node {
	mut first_err := ?cx.Node(none)
	for i := ids.len - 1; i >= 0; i-- {
		fire_close(ids[i], mut env) or {
			if first_err == none {
				if err is EvalError {
					first_err = mk_err(err.code, err.msg())
				} else {
					first_err = mk_err('cx-err:CXER0001', err.msg())
				}
			}
		}
	}
	return first_err
}

fn eval_with_open(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	// Collect opener (expr, bind-name) pairs and the positional body.
	mut open_exprs := []cx.ProgramNode{}
	mut open_names := []string{}
	for s in d.slots {
		if s.kind == .labeled && s.label == 'open-expr' {
			open_exprs << s.value
		} else if s.kind == .labeled && s.label == 'open-bind' {
			if s.value is cx.ProgramLiteral && s.value.kind == .string_lit {
				open_names << s.value.str_val
			} else {
				return EvalError{ code: 'cx-err:CXER0100', message: '[?with-open] malformed binding' }
			}
		}
	}
	body := positional_slots(d)
	if open_exprs.len == 0 || open_exprs.len != open_names.len {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?with-open] requires opener pairs' }
	}
	if body.len == 0 {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?with-open] empty body' }
	}
	// Open left-to-right; each opener evaluates with earlier bindings in
	// scope. `opened` tracks live close-ids for LIFO close on every exit.
	mut ext := env.clone()
	mut opened := []string{}
	for i, oexpr in open_exprs {
		val := eval_node(oexpr, mut ext) or {
			// Open raised: close earlier bindings LIFO, then re-propagate
			// the open error unchanged (final bullet).
			close_opened_lifo(opened, mut env)
			return err
		}
		if is_err_value(val) {
			// Open yielded an [err] value: same handling as a raise.
			close_opened_lifo(opened, mut env)
			return val
		}
		cid := closeable_close_id(val, mut env) or {
			close_opened_lifo(opened, mut env)
			return EvalError{
				// code.md §8.10.7 / registry: E_NOT_CLOSEABLE. (code.md:1918 —
				// no directive raises CXER0001 directly.)
				code:    'cx-err:CXER0108'
				message: '[?with-open] binding `\$${open_names[i]}` is not a closeable resource'
			}
		}
		ext.bindings[open_names[i]] = val
		opened << cid
	}
	// Evaluate the body; the last expression is the result.
	mut result := cx.Node(cx.ScalarNode{ value: cx.ScalarValue(cx.NullValue{}), data_type: .null_type })
	for s in body {
		result = eval_node(s, mut ext) or {
			// Body raised (V-level error / `!` panic / `?` propagation):
			// close all opened LIFO, then re-propagate the in-flight error
			// UNCHANGED — the in-flight error takes priority over any
			// close failure. Close failures are recorded in
			// close_log (with an `!err` suffix) as a diagnostic.
			close_opened_lifo(opened, mut env)
			return err
		}
		if is_err_value(result) {
			// Body produced an [err] value: close LIFO, return it unchanged.
			close_opened_lifo(opened, mut env)
			return result
		}
	}
	// Normal completion: close LIFO. A close failure here becomes the
	// directive's result error (normal-completion branch).
	if ce := close_opened_lifo(opened, mut env) {
		return ce
	}
	return result
}

// ── Module imports: [?lib] / [?const] (spec/code.md §12) ─────────────────────

// module_raw_source pulls the verbatim directive text captured by
// parse_module_directive's 'raw-source' slot.
fn module_raw_source(d cx.ProgramDirective) ?string {
	node := labeled_slot(d, 'raw-source') or { return none }
	if node is cx.ProgramLiteral && node.kind == .string_lit {
		return node.str_val
	}
	return none
}

// module_call_prefix returns the name under which an import's symbols are
// qualified inside the importing program (spec/code.md §12.1.1): the
// `:as ALIAS` when present, else the last `/`-segment of the resolver
// source with any `.cx` extension stripped (`cx-stdlib/math` → `math`,
// `'./helpers.cx'` → `helpers`).
fn module_call_prefix(lib cx.LibNode) string {
	if a := lib.alias {
		return a
	}
	mut seg := lib.resolver_source
	if idx := seg.last_index('/') {
		seg = seg[idx + 1..]
	}
	if seg.ends_with('.cx') {
		seg = seg[..seg.len - 3]
	}
	return seg.trim_right("'\"")
}

// def_param_names returns the positional parameter-name list of a module
// [?def] for closure binding. (Named / rest / default parameters are
// carried by name here; the positional invoke_closure path binds them in
// order — modules exercising named/rest call shapes extend this when
// they land.)
fn def_param_names(def cx.DefNode) []string {
	mut out := []string{}
	for p in def.params {
		out << p.name
	}
	return out
}

// def_param_specs maps a [?def]'s DefParam list to the closure ParamSpec
// model — name, named/rest flags, and default-value source.
fn def_param_specs(def cx.DefNode) []ParamSpec {
	mut out := []ParamSpec{}
	for p in def.params {
		out << ParamSpec{
			name:        p.name
			is_named:    p.is_named
			is_rest:     p.is_rest
			default_src: p.default or { '' }
			type_src:    p.type_expr_source or { '' }
		}
	}
	return out
}

// def_is_variadic reports whether the [?def]'s final parameter is a
// `:rest` variadic. The variadic invoke_closure path
// collects trailing call args into a sequence bound to that name.
fn def_is_variadic(def cx.DefNode) bool {
	if def.params.len == 0 {
		return false
	}
	return def.params[def.params.len - 1].is_rest
}

// module_member_visibility_error returns a CXER0216 (E_VISIBILITY) error
// when `name` is a `prefix:member` QName whose prefix names an imported
// module in which `member` EXISTS but is module-private (no scope=public)
// or otherwise not exported on the entry-file surface (§12.4.4 / §12.6).
// Returns none when name is not a QName, the prefix is not an imported
// module, or the member is absent (the latter falls through to the
// ordinary undefined-call / CXER0213 paths). The check mirrors the
// loader's lookup_def/lookup_const visibility rule but yields the
// canonical wire code (CXER0216) at the call boundary.
fn module_member_visibility_error(name string, mut env MatchEnv) ?EvalError {
	idx := name.index(':') or { return none }
	prefix := name[..idx]
	member := name[idx + 1..]
	if prefix == '' || member == '' {
		return none
	}
	mod := env.state.module_table.alias_modules[prefix] or { return none }
	// Member must exist in the module to be a visibility (vs unresolvable)
	// error; a public member would already have dispatched as a closure.
	has_def := member in mod.defs
	has_const := member in mod.consts
	if !has_def && !has_const {
		return none
	}
	return EvalError{
		code:    'cx-err:CXER0216'
		message: 'access to non-exported member `${member}` of module `${mod.name}` (private — add scope=public to export, or re-export it on the entry file)'
	}
}

fn eval_lib(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	raw := module_raw_source(d) or {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?lib] missing source' }
	}
	libnode := cx.parse_lib(raw) or {
		// E_LIB_INSECURE_TRANSPORT (code.md registry): the lib parser raises
		// CXLIB_INSECURE_TRANSPORT for an http:// source; the spec'd surface
		// code is CXER0208 (the mapping lib_parser.v documents — made TRUE
		// here, R3.12). Every OTHER shape rejection is the spec'd
		// E_LIB_MALFORMED_DIRECTIVE CXER0212; CXER0210 stays the
		// resolve-failure code (audit F-19 surfaced the drift).
		if err.msg().contains('CXLIB_INSECURE_TRANSPORT') {
			return EvalError{ code: 'cx-err:CXER0208', message: '[?lib] parse: ${err.msg()}' }
		}
		return EvalError{ code: 'cx-err:CXER0212', message: '[?lib] parse: ${err.msg()}' }
	}
	mod := resolve_lib(libnode, mut env.state.module_table) or {
		return module_resolve_eval_error(err.msg())
	}
	prefix := module_call_prefix(libnode)
	// §6.4.4 module non-widening (#808): inside a tree-eval the `[?lib]` set
	// may NARROW but not widen. A prefix the caller already holds is a
	// re-declaration and passes; anything else is refused. Checked AFTER
	// resolve so a malformed / unresolvable lib still reports its own
	// error, and BEFORE the alias registration below — which writes into
	// the SHARED module_table, i.e. the widening this rule exists to stop.
	if allowed := env.state.tree_eval_lib_allow {
		if prefix !in allowed {
			return EvalError{
				code:    'cx-err:CXER4113'
				message: 'cx-err:CXER4113: tree-eval may not widen the module set — `[?lib]` introducing `${prefix}` is not in the caller\'s [?lib] set (code.md §6.4.4: inherits the caller\'s set; may narrow, not widen)'
			}
		}
	}
	// Record alias → module so the QName call path can distinguish a
	// reference to a private/non-re-exported member (CXER0216) from a
	// reference to an unimported prefix (§12.6). Pointer-shared via state.
	env.state.module_table.alias_modules[prefix] = mod
	register_module_members(mod, prefix, libnode.only_imports, mut env)!
	return module_lib_ok(prefix)
}

// module_resolve_eval_error maps loader MODULE_* failures onto the spec'd
// wire codes (code.md §12.1.5 / lockfile.md §8; the Phase-2.14 graft,
// register R3.12 RULED (b)): sri mismatch → 0209, unpinned → 0211,
// malformed lockfile → 0212; everything else (cycles, unresolvable
// registrations, transport faults) keeps 0210 as the resolve-failure
// code (the R3.12/audit-F-19 allocation).
fn module_resolve_eval_error(m string) EvalError {
	wire := if m.contains('MODULE_SRI_MISMATCH') {
		'cx-err:CXER0209'
	} else if m.contains('MODULE_UNPINNED') {
		'cx-err:CXER0211'
	} else if m.contains('MODULE_LOCKFILE_MALFORMED') {
		'cx-err:CXER0212'
	} else {
		'cx-err:CXER0210'
	}
	return EvalError{
		code:    wire
		message: '[?lib] resolve: ${m}'
	}
}

fn module_lib_ok(prefix string) cx.Node {
	return cx.Element{
		name:  'result'
		attrs: [
			cx.Attribute{ name: 'status', value: cx.ScalarValue('ok') },
			cx.Attribute{ name: 'imported', value: cx.ScalarValue(prefix) },
		]
	}
}

// register_module_members registers `mod`'s public `[?def]` / `[?const]`
// members as `prefix:name` closures / bindings in the program env, and
// recursively registers the members of every module `mod` itself imports
// under that import's LOCAL alias — so a transitive call chain
// (`[$a:call-through]` → level-a body calls `[$b:call-through]` → …)
// resolves at every depth (§12.5 transitive resolution). Registration is
// under the canonical `prefix:name` QName form only (§12.1.1); the `/`
// operator is data-path navigation, never a module ref (the retired slash
// call surface was cut over 2026-05-31, no dual-accept). `only` applies the
// importing `[?lib … :only (…)]` selective-import filter at the top level;
// transitive imports carry their own (`none`) filter.
// ensure_module_scope builds (once, cached on the module table) a module's
// lexical Scope: its OWN defs + consts under bare names (a member body resolves
// a sibling unqualified, #19), plus the PUBLIC members of the modules IT imports
// under their local alias prefix (a member body resolving `[$alias:member]`,
// transitive). Every closure in the scope captures `defining_scope = scope`, so a
// member resolves its free names here regardless of who calls it (not the
// caller's table — that was the bug). Read-only after build; shared across
// importers. The import graph is a DAG (cycles rejected by the loader), so the
// recursion terminates; caching before recursing makes diamonds idempotent.
// is_self_builtin_forward reports whether a def body is a pure forward to a
// SAME-NAMED callable — its head is exactly `[$<name> …]`. Such a def is a thin
// alias for the builtin `<name>` (core or stdlib): a pure self-forward with no
// underlying builtin would be unconditional infinite recursion, so treating it
// as a builtin-wrapper is correct either way — and it must NOT be registered as
// a body closure that shadows the builtin in its own body (lexical self-recursion
// → stack overflow). The dispatch resolves the builtin at call time
// (invoke_builtin / stdlib_builtin), covering builtins `builtin_fn_name` doesn't
// enumerate (e.g. the stdlib `validate-shape`). Purely syntactic on the raw body.
fn is_self_builtin_forward(name string, raw_body string) bool {
	b := raw_body.trim_space()
	// head must be `[$<name>` followed by a space (args) or `]` (0-arg) — so a
	// forward to a DIFFERENTLY-named builtin (`round`→`[$math-round …]`) and a
	// recursive `[?if …]` body do NOT match.
	prefix := '[\$${name}'
	if !b.starts_with(prefix) {
		return false
	}
	rest := b[prefix.len..]
	return rest.starts_with(' ') || rest.starts_with(']')
}

fn ensure_module_scope(mod &Module, mut env MatchEnv) !&Scope {
	key := mod.source
	if s := env.state.module_table.module_scopes[key] {
		return s
	}
	mut s := &Scope{
		closures: map[string]Closure{}
		bindings: map[string]cx.Node{}
	}
	env.state.module_table.module_scopes[key] = s // cache before recursing (diamonds)
	// 1. the module's own defs (bare names; private siblings are callable within
	// the module, so register ALL defs, not just public ones).
	for name, def in mod.defs {
		// A def that trivially forwards to a SAME-NAMED builtin — `[?def abs ($x)
		// [$abs $x]]` — is an ALIAS for that builtin, not a recursive call. Under
		// lexical scoping the sibling-visible def would otherwise shadow the builtin
		// in its own body and self-recurse. Register it as a builtin-wrapper so
		// `[$abs]` (here or in a sibling) dispatches to the builtin. (Defs that
		// forward to a DIFFERENTLY-named builtin — `round`→`[$math-round]` — do not
		// collide and stay normal body closures.)
		if is_self_builtin_forward(name, def.body) {
			s.closures[name] = Closure{
				builtin_name:   name
				defining_scope: s
			}
			continue
		}
		body_prog := cx.parse_program(def.body) or {
			return EvalError{
				code:    'cx-err:CXER0210'
				message: '[?lib] def `${name}` body parse: ${err.msg()}'
			}
		}
		// Command-contract checks (§12.2.7, stream 6 — the SAME authority
		// eval_def calls, R3): unknown [effects] cap → CXER0274; explicit
		// pure + non-empty [effects] → CXER0239; [compensates] resolves
		// against the module's FULL def table (order-independent, §12.5).
		if e := command_contract_check_local(&def) {
			return e
		}
		if def.compensates.len > 0 {
			mut target_is_command := false
			target_exists := def.compensates in mod.defs
			if target := mod.defs[def.compensates] {
				target_is_command = target.has_effects
			}
			if e := command_compensates_check(&def, target_exists, target_is_command) {
				return e
			}
		}
		mut mod_closure := Closure{
			params:         def_param_names(def)
			is_variadic:    def_is_variadic(def)
			param_specs:    def_param_specs(def)
			body:           [body_prog.body]
			defining_scope: s
			returns_type:   def.returns_type_source or { '' }
			has_effects:    def.has_effects
			effects_caps:   def_effect_caps(&def)
			// #780: carry the DECLARED purity, exactly as eval_def does at
			// the program-level registration site. Omitting it left every
			// module-defined def looking undeclared to the flag's
			// consumers — so validate.md §3.6's purity gate (an impure
			// `validate-with=` validator is a malformed schema, CXER1603)
			// refused a program-level impure validator and ADMITTED the
			// identical module-defined one: two registration sites, two
			// trust postures.
			declared_impure: def.purity == .impure_
		}
		if def.is_idempotent {
			raw_src := def.source or { '' }
			win, t2 := command_idem_fields(&def, raw_src) or {
				m := err.msg()
				return EvalError{ code: m.all_before(' '), message: m }
			}
			mod_closure = Closure{
				...mod_closure
				is_idempotent:  true
				idem_window_ns: win
				tier2_addr:     t2
			}
		}
		if def.has_effects {
			mod_closure = Closure{
				...mod_closure
				cmd_meta: command_meta_build(&def, def.source or { '' })
			}
		}
		s.closures[name] = mod_closure
	}
	// 2. the module's own imports — expose their PUBLIC members under the local
	// alias prefix so a member body's `[$alias:member]` resolves in this scope.
	for lib in mod.libs {
		sub := env.state.module_table.modules[lib.resolver_source] or { continue }
		sub_scope := ensure_module_scope(sub, mut env)!
		sub_prefix := module_call_prefix(lib)
		for name, def in sub.defs {
			if !scope_is_public(def.scope) {
				continue
			}
			if o := lib.only_imports {
				if name !in o {
					continue
				}
			}
			if c := sub_scope.closures[name] {
				s.closures['${sub_prefix}:${name}'] = c
			}
		}
		for cname in sub.const_order {
			cst := sub.consts[cname] or { continue }
			if !scope_is_public(cst.scope) {
				continue
			}
			if o := lib.only_imports {
				if cname !in o {
					continue
				}
			}
			if v := sub_scope.bindings[cname] {
				s.bindings['${sub_prefix}:${cname}'] = v
			}
		}
	}
	// 3. the module's own consts (bare), evaluated in an env scoped to THIS module
	// (so a const body resolves module defs + imported members + prior consts),
	// in topological order.
	mut cenv := MatchEnv{
		bindings:        map[string]cx.Node{}
		closures:        s.closures
		closures_shared: true
		state:           env.state
		scope:           env.scope
		eval_budget:     env.eval_budget // module-const eval stays budgeted (F4/S6.2)
	}
	for k, v in s.bindings {
		cenv.bindings[k] = v
	}
	for cname in mod.const_order {
		cst := mod.consts[cname] or { continue }
		cbody := cx.parse_program(cst.value_source) or {
			return EvalError{
				code:    'cx-err:CXER0210'
				message: '[?lib] const `${cname}` body parse: ${err.msg()}'
			}
		}
		cval := eval_node(cbody.body, mut cenv)!
		s.bindings[cname] = cval
		cenv.bindings[cname] = cval
	}
	return s
}

pub fn register_module_members(mod &Module, prefix string, only ?[]string, mut env MatchEnv) ! {
	s := ensure_module_scope(mod, mut env)!
	for name, def in mod.defs {
		if !scope_is_public(def.scope) {
			continue
		}
		if o := only {
			if name !in o {
				continue
			}
		}
		if c := s.closures[name] {
			env.cow_closures()
			env.closures['${prefix}:${name}'] = c
			if env.scope != unsafe { nil } {
				env.scope.closures['${prefix}:${name}'] = c
			}
		}
	}
	for cname in mod.const_order {
		cst := mod.consts[cname] or { continue }
		if !scope_is_public(cst.scope) {
			continue
		}
		if o := only {
			if cname !in o {
				continue
			}
		}
		if v := s.bindings[cname] {
			env.cow_bindings()
			env.bindings['${prefix}:${cname}'] = v
			if env.scope != unsafe { nil } {
				env.scope.bindings['${prefix}:${cname}'] = v
			}
		}
	}
	// Transitive imports: also expose each lib `mod` declares under its local
	// alias in the IMPORTER env (back-compat for the QName resolution path /
	// alias_modules visibility). Member bodies themselves now resolve via the
	// module scope (above), not this registration.
	for lib in mod.libs {
		sub := env.state.module_table.modules[lib.resolver_source] or { continue }
		sub_prefix := module_call_prefix(lib)
		env.state.module_table.alias_modules[sub_prefix] = sub
		register_module_members(sub, sub_prefix, lib.only_imports, mut env)!
	}
}

fn eval_const(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	raw := module_raw_source(d) or {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?const] missing source' }
	}
	cnode := cx.parse_const(raw) or {
		return EvalError{ code: 'cx-err:CXER0210', message: '[?const] parse: ${err.msg()}' }
	}
	cbody := cx.parse_program(cnode.value_source) or {
		return EvalError{
			code:    'cx-err:CXER0210'
			message: '[?const] `${cnode.name}` body parse: ${err.msg()}'
		}
	}
	val := eval_node(cbody.body, mut env)!
	env.cow_bindings()
	env.bindings[cnode.name] = val
	// Mirror into the program scope so a [?def] body (captured defining_scope)
	// resolves this const by its bare name (#22).
	if env.scope != unsafe { nil } {
		env.scope.bindings[cnode.name] = val
	}
	return cx.Element{
		name:  'result'
		attrs: [
			cx.Attribute{ name: 'status', value: cx.ScalarValue('ok') },
			cx.Attribute{ name: 'const', value: cx.ScalarValue(cnode.name) },
		]
	}
}

// eval_pipe_directive — `[?pipe seed STAGE …]` (§8.9). Threads `seed`
// left-to-right through each STAGE. Stages are bare transforms (§8.9.1):
// the threaded value fills a single partial-application hole `_` if the
// stage carries one (hole-form), else is appended as the final positional
// argument (no-hole form). A non-callable stage is `cx-err:CXER0100`. The
// reserved clause `[tap f]` (§8.9.2) runs `f` for its side effect and
// passes the value through unchanged. The pipe is a single-channel failure
// railway (§8.9.3): the first `[err]` short-circuits the rest (taps
// included) and becomes the result. There is no infix `|` and no
// `[through]` wrapper (both retired — §8.9 tombstones).
fn eval_pipe_directive(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	if d.slots.len == 0 {
		return cx.Element{ name: '' }
	}
	if env.state.strict {
		// The Layer-B minimum (stream 16 W5, L62B): declared
		// [returns]/::T flow across stages, checked PRE-EXECUTION —
		// no stage runs when adjacent declared types cannot compose.
		pipe_precheck_stage_flow(d, mut env)!
	}
	mut current := eval_node(d.slots[0].value, mut env)!
	for i in 1 .. d.slots.len {
		// Railway short-circuit (§8.9.3): an [err]-value skips every
		// remaining stage — taps included — and is the result.
		if is_err_value(current) {
			return current
		}
		current = apply_pipe_stage(d.slots[i].value, current, mut env)!
	}
	return current
}

// pipe_precheck_stage_flow is the strict-mode Layer-B pre-execution
// pass (shape_inference.md §2, L62B — modular: declarations are the
// contract; inference stops at [?def] boundaries). It walks the stage
// list BEFORE any evaluation and, for each adjacent pair of no-hole
// simple-call stages resolving to [?def] closures, compares stage i's
// declared [returns T] against the receiving parameter's declared ::T
// on stage i+1 (the no-hole form appends the piped value as the LAST
// positional argument, so the receiving param is the last declared
// non-rest param). Both must be DECLARED and PARSEABLE to participate
// — an undeclared boundary is silent (annotations are optional), and
// compatibility is conservative: canonical-text equality, `any` on
// either side, or the int⊔float numeric family. Hole-form / `_`-
// referencing / fn-value stages are runtime-shaped and skip the pass.
fn pipe_precheck_stage_flow(d cx.ProgramDirective, mut env MatchEnv) ! {
	mut prev_ret := ''
	mut prev_name := ''
	for i in 1 .. d.slots.len {
		stage := d.slots[i].value
		mut cur_param := ''
		mut cur_ret := ''
		mut cur_name := ''
		mut participates := false
		if stage is cx.ProgramCall {
			mut nholes := 0
			for a in stage.args {
				if a is cx.ProgramCall && a.name == cx.program_hole_name {
					nholes++
				}
			}
			if nholes == 0 && !references_underscore_value(stage) {
				if cl := lookup_closure(stage.name, env) {
					cur_name = stage.name
					cur_ret = cl.returns_type
					// receiving param = last declared non-rest param.
					for j := cl.param_specs.len - 1; j >= 0; j-- {
						if !cl.param_specs[j].is_rest {
							cur_param = cl.param_specs[j].type_src
							break
						}
					}
					participates = true
				}
			}
		}
		if participates && prev_ret != '' && cur_param != '' {
			if !type_texts_compose(prev_ret, cur_param) {
				return EvalError{
					code:    'cx-err:CXER0206'
					message: 'cx-err:CXER0206 E_TYPE_ARG_MISMATCH: [?pipe] stage flow — `${prev_name}` declares [returns ${prev_ret}] but `${cur_name}` receives `::${cur_param}` (pre-execution, spec/code.md §12.7 strict)'
				}
			}
		}
		if participates {
			prev_ret = cur_ret
			prev_name = cur_name
		} else {
			prev_ret = ''
			prev_name = ''
		}
	}
}

// type_texts_compose is the conservative declared-boundary
// compatibility: equal canonical type text, `any` on either side, or
// int flowing into the float family (the validator's own admission).
// Unparseable text composes (the checker never fails open INTO a
// refusal on malformed annotations — those are lint's domain, CX-L008).
fn type_texts_compose(produced string, consumed string) bool {
	p := produced.trim_space()
	c := consumed.trim_space()
	if p == '' || c == '' || p == 'any' || c == 'any' {
		return true
	}
	if p == c {
		return true
	}
	_ = cx.parse_type_expr(p) or { return true }
	_ = cx.parse_type_expr(c) or { return true }
	if p == 'int' && (c == 'float' || c == 'number') {
		return true
	}
	if (p == 'int' || p == 'float' || p == 'decimal' || p == 'bigint') && c == 'number' {
		return true
	}
	return false
}

// pipe_tap_propagates reports whether a tap observing an [err] with the
// given code propagates it (vs discards it for data flow). Per §8.9.2 a
// tap propagates ONLY a CX_PANIC (CXER0001) or a cancellation (CXER0260);
// every other error is discarded for data flow (the error-hook still
// observes it at raise, §9.6).
fn pipe_tap_propagates(err_code string) bool {
	return err_code == 'cx-err:CXER0001' || err_code == 'cx-err:CXER0260'
}

// apply_pipe_stage dispatches one `[?pipe]` stage: the reserved `[tap …]`
// clause (§8.9.2), the retired `[through …]` wrapper (NO-LEGACY-PIPE →
// CXER0100), or a bare transform (§8.9.1, apply_pipe_transform).
fn apply_pipe_stage(stage cx.ProgramNode, input cx.Node, mut env MatchEnv) !cx.Node {
	if stage is cx.ProgramLiteral && stage.kind == .cx_element {
		if stage.name == 'through' {
			// NO-LEGACY-PIPE: `[through F]` is retired (§8.9 tombstone);
			// a bare stage is the transform.
			return EvalError{
				code:    'cx-err:CXER0100'
				message: '[?pipe] `[through …]` is retired — use a bare stage (`F`, `[\$f …]`, or hole-form `[\$f _ …]`)'
			}
		}
		if stage.name == 'tap' {
			return eval_pipe_tap(stage, input, mut env)!
		}
	}
	return apply_pipe_transform(stage, input, mut env)!
}

// eval_pipe_tap runs a `[tap f]` clause (§8.9.2): `f` is invoked on the
// current value by the §8.9.1 stage rule for its side effect; the value
// passes through unchanged and f's return is discarded. Error scope: a
// tap propagates an [err] iff its code ∈ {CXER0001, CXER0260}, and
// discards every other [err] (the error-hook still observes at raise,
// §9.6 — discarding affects data flow only).
fn eval_pipe_tap(tap cx.ProgramLiteral, input cx.Node, mut env MatchEnv) !cx.Node {
	if tap.items.len == 0 {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: '[tap] requires a stage expression'
		}
	}
	res := apply_pipe_transform(tap.items[0], input, mut env) or {
		// Thrown EvalError: propagate only CX_PANIC / cancellation.
		thrown_code := if err is EvalError { err.code } else { 'cx-err:CXER0001' }
		if pipe_tap_propagates(thrown_code) {
			return err
		}
		return input
	}
	if is_err_value(res) {
		if pipe_tap_propagates(err_summary(res)) {
			return res
		}
		return input
	}
	return input
}

// references_underscore_value reports whether `node` references the
// threaded value `_` as a VALUE (a bare `_` ident or `_`-based binding,
// `name == "_"`) anywhere in its subtree. `[?pipe]` uses this to suppress
// the no-hole append when the author already places the value via `_`
// (e.g. `[tap [$log:info "saw" {v: _}]]`, `_/@id`). The partial-
// application hole SENTINEL (cx.program_hole_name) is NOT a value reference —
// a nested sentinel builds an inner partial, not a pipe-value placement —
// so it is excluded here; top-level sentinels are counted separately as
// fillable holes (§8.9.1).
fn references_underscore_value(node cx.ProgramNode) bool {
	match node {
		cx.ProgramBinding {
			return node.name == '_'
		}
		cx.ProgramCall {
			if node.name == '_' {
				return true
			}
			for a in node.args {
				if references_underscore_value(a) {
					return true
				}
			}
			return false
		}
		cx.ProgramLiteral {
			if e := node.name_expr {
				if references_underscore_value(e) {
					return true
				}
			}
			for it in node.items {
				if references_underscore_value(it) {
					return true
				}
			}
			for s in node.slots {
				if references_underscore_value(s.value) {
					return true
				}
			}
			for at in node.attrs {
				if references_underscore_value(at.value) {
					return true
				}
			}
			return false
		}
		else {
			return false
		}
	}
}

// apply_pipe_transform applies a bare pipe stage to `input` per §8.9.1.
// The threaded value is bound to `_` for the stage's duration (so map /
// path references like `{v: _}` and `_/@id` resolve), then:
//   - hole-form: a single top-level partial-application hole `_` is filled
//     by the value; two or more holes → CXER0100 (a pipe threads exactly
//     one value);
//   - no-hole form: the value is appended as the final positional argument
//     (`add1` ≡ `[$add1 _]`);
//   - non-callable stage (literal / data element / map / sequence, or a
//     name not resolving to a function) → CXER0100.
fn apply_pipe_transform(stage cx.ProgramNode, input cx.Node, mut env MatchEnv) !cx.Node {
	// Bind the threaded value to `_` and the synthetic `__pipe_input__`
	// for the stage eval; restore on return (correct under nesting).
	saved_underscore := env.bindings['_'] or { cx.Node(cx.Element{}) }
	had_underscore := '_' in env.bindings
	saved_pipe_in := env.bindings['__pipe_input__'] or { cx.Node(cx.Element{}) }
	had_pipe_in := '__pipe_input__' in env.bindings
	env.cow_bindings()
	env.bindings['_'] = input
	env.bindings['__pipe_input__'] = input
	defer {
		if had_underscore {
			env.bindings['_'] = saved_underscore
		} else {
			env.bindings.delete('_')
		}
		if had_pipe_in {
			env.bindings['__pipe_input__'] = saved_pipe_in
		} else {
			env.bindings.delete('__pipe_input__')
		}
	}
	match stage {
		cx.ProgramDirective {
			// Directive stages: `[?modify FOCUS Action+]` reads the
			// threaded value via __pipe_input__; `[?fn …]` (and any
			// directive producing a function value) is applied to the
			// value as a unary transform.
			val := eval_node(stage, mut env)!
			if is_fn_value(val) {
				return apply_fn_value(val, [input], mut env)!
			}
			return val
		}
		cx.ProgramCall {
			mut nholes := 0
			mut hole_idx := -1
			for ai, a in stage.args {
				if a is cx.ProgramCall && a.name == cx.program_hole_name {
					nholes++
					if hole_idx < 0 {
						hole_idx = ai
					}
				}
			}
			if nholes >= 2 {
				return EvalError{
					code:    'cx-err:CXER0100'
					message: '[?pipe] stage carries ${nholes} holes `_`; a pipe threads exactly one value (at most one `_` per stage)'
				}
			}
			if nholes == 1 {
				// hole-form: fill the single hole with the threaded value.
				mut new_args := stage.args.clone()
				new_args[hole_idx] = cx.ProgramBinding{
					name: '__pipe_input__'
					path: []
					pos:  stage.pos
				}
				synth := cx.ProgramCall{
					name:          stage.name
					args:          new_args
					fallible:      stage.fallible
					must_succeed:  stage.must_succeed
					explicit_call: stage.explicit_call
					arg_labels:    stage.arg_labels.clone()
					pos:           stage.pos
				}
				return eval_node(synth, mut env)!
			}
			// If the stage already places the value via a `_` reference
			// (e.g. `{v: _}` / `_/@id`), the author has supplied it — eval
			// as-is (the `_` binding carries the value); no append.
			if references_underscore_value(stage) {
				return eval_node(stage, mut env)!
			}
			// no-hole form: the stage head MUST resolve to a callable
			// (§8.9.1 non-callable → CXER0100), then append the value as
			// the final positional argument.
			resolve_fn_value(stage.name, mut env) or {
				return EvalError{
					code:    'cx-err:CXER0100'
					message: '[?pipe] stage `${stage.name}` is not callable (a pipe stage must be a transform)'
				}
			}
			mut new_args := stage.args.clone()
			new_args << cx.ProgramBinding{
				name: '__pipe_input__'
				path: []
				pos:  stage.pos
			}
			mut new_labels := stage.arg_labels.clone()
			for new_labels.len < new_args.len {
				new_labels << ''
			}
			synth := cx.ProgramCall{
				name:          stage.name
				args:          new_args
				fallible:      stage.fallible
				must_succeed:  stage.must_succeed
				explicit_call: stage.explicit_call
				arg_labels:    new_labels
				pos:           stage.pos
			}
			return eval_node(synth, mut env)!
		}
		cx.ProgramBinding {
			if stage.path.len == 0 {
				if fv := resolve_fn_value(stage.name, mut env) {
					return apply_fn_value(fv, [input], mut env)!
				}
				return EvalError{
					code:    'cx-err:CXER0100'
					message: '[?pipe] stage `\$${stage.name}` is not callable'
				}
			}
			val := eval_node(stage, mut env)!
			if is_fn_value(val) {
				return apply_fn_value(val, [input], mut env)!
			}
			return EvalError{
				code:    'cx-err:CXER0100'
				message: '[?pipe] stage is not callable'
			}
		}
		else {
			return EvalError{
				code:    'cx-err:CXER0100'
				message: '[?pipe] non-callable stage (a literal / data element / map / sequence is not a transform)'
			}
		}
	}
}

// ── [?modify] — pure-functional updates with spine-copy (+0031) ────
//
// `[?modify DOC FOCUS Action+]` (or the pipe-stage form `[?modify FOCUS
// Action+]`) locates nodes by CXPath focus, applies actions left-to-
// right, and returns a new document. The original document is
// observably unchanged; structural sharing is achieved
// via spine-copy:
//
//   - For each focused match, walk from doc root down to the match,
//     materialising a fresh Element header at each step on the spine.
//   - The new Element's `items []Node` slice is a freshly-allocated
//     buffer of length N (parent's child count); the slot at the
//     descended child's index points to the next spine-copy, all OTHER
//     slots are the original Node values (V's slice clone is shallow
//     for sum-type variants — inner Element items[] slices share
//     storage with the originals).
//   - Attributes are copied to a fresh []Attribute slice ONLY at the
//     deepest spine element when the action touches attrs; intermediate
//     spine elements share the parent's attrs slice header.
//
// Multi-match: processed sequentially. Each match's spine-copy
// operates on the previous match's result, so spine paths sharing a
// common prefix end up with one fresh header per (level × match) but
// the children outside the prefix remain shared. Bottom-up batching
// (a perf optimisation noted) is a follow-up.
// eval_modify — the ONE modify engine (#803/#805 convergence,
// 2026-08-13): the dispatcher-bridge lane and its placeholder CxNode
// chain are RETIRED (see dispatcher_bridge.v's retirement note); the
// spec-complete legacy evaluator below measured LIGHTER at the
// gate-30.5 envelope and now serves every shape, incl. the ported
// #436 directive-as-data arm.
fn eval_modify(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	// #803/#805 CONVERGENCE (measured, 2026-08-13): the modify-side
	// dispatcher bridge is RETIRED — the legacy evaluator below is
	// both the spec-complete engine (the bridge's own decline-list
	// routed every hard shape here already: [using], free bindings,
	// graded/bound/outer-ref predicates) AND the lighter one at the
	// gate-30.5 envelope (sharing-ratio 3,057 B/match PASS vs the
	// bridge's 10,588 FAIL; thousand-attr 200 MB vs 694 MB). One
	// modify engine; the placeholder CxNode/adapter chain the bridge
	// dragged (its own header always called it a stand-in) dies with
	// it.
	// Resolve the doc: explicit positional[0] if two positionals
	// (DOC + FOCUS) are present; pipe-input fallback otherwise.
	mut doc_idx := -1
	mut focus_idx := -1
	mut positional_count := 0
	for i, s in d.slots {
		if s.kind == .positional {
			if positional_count == 0 { doc_idx = i }
			else if positional_count == 1 { focus_idx = i }
			positional_count++
		}
	}
	mut doc_val := cx.Node(cx.Element{ name: '' })
	if positional_count >= 2 {
		doc_val = eval_node(d.slots[doc_idx].value, mut env)!
	} else if positional_count == 1 {
		// Pipe-stage form. The upstream pipe stage threaded the input
		// into env.bindings['__pipe_input__']; consume it.
		focus_idx = doc_idx
		doc_val = env.bindings['__pipe_input__'] or {
			return EvalError{
				code:    'cx-err:CXER0001'
				message: '[?modify] pipe-stage form requires upstream pipe input; none found'
			}
		}
	} else {
		return EvalError{
			code:    'cx-err:CXER0001'
			message: '[?modify] requires doc + focus positional slots'
		}
	}
	focus_expr := d.slots[focus_idx].value
	focus_path := match focus_expr {
		cx.ProgramPathExpr { focus_expr }
		else {
			return EvalError{
				code:    'cx-err:CXER0100'
				message: '[?modify] focus slot must be a CXPath PathExpr'
			}
		}
	}
	// Collect action slots in source order.
	mut actions := []cx.ProgramSlot{}
	for s in d.slots {
		if s.kind == .labeled && cx.is_modify_action_name(s.label) {
			actions << s
		}
	}
	if actions.len == 0 {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: '[?modify] requires at least one action slot'
		}
	}
	// #436 (ported from the retired modify bridge with it): a
	// directive-as-data doc walks through its Element view and
	// re-wraps as the directive after the actions — new_path_ctx
	// indexes Elements only, so an unwrapped EvalDirectiveNode root
	// would silently identity out.
	mut wrap_directive_name := ''
	mut doc_current := doc_val
	if doc_val is cx.EvalDirectiveNode {
		wrap_directive_name = doc_val.name
		doc_current = cx.Node(eval_directive_view(doc_val))
	}
	// Apply each action in source order, threading the result of one
	// into the input of the next.
	mut current := doc_current
	for a in actions {
		current = apply_modify_action(current, focus_path, a, mut env)!
	}
	if wrap_directive_name.len > 0 {
		if current is cx.Element {
			return cx.Node(cx.EvalDirectiveNode{
				name:  wrap_directive_name
				attrs: current.attrs
				items: current.items
			})
		}
	}
	return current
}

// apply_modify_action runs one action against `doc` for every node the
// focus path selects. Spine-copy builds a new tree per match; sharing
// follows from V's shallow slice/struct copy semantics on Node sum-type
// variants. Zero matches → doc returned unchanged.
fn apply_modify_action(doc cx.Node, focus cx.ProgramPathExpr, action cx.ProgramSlot,
                       mut env MatchEnv) !cx.Node {
	// Build the path context against the current doc.
	pc := new_path_ctx(doc, path_needs_non_element_index(focus.steps))
	if pc.doc_order.len == 0 {
		return doc
	}
	// Compute focus indices using the same logic as eval_path_expr but
	// without materialising the result as a sequence. Detect a trailing
	// attribute-axis step and run it specially.
	last_idx := focus.steps.len - 1
	attribute_tail := focus.steps[last_idx].axis == .attribute && focus.steps.len >= 1
	mut element_matches := []int{}
	mut attr_target := ''  // populated when attribute_tail
	// Walk the element steps (all but a trailing attribute step) via the
	// shared bound walker so `(bind $NAME)` step annotations (code.md §5.5)
	// behave identically in [?modify] focus paths and value-position paths.
	head := apply_first_step(focus.steps[0], pc)
	stop := if attribute_tail {
		attr_target = focus.steps[last_idx].name
		if last_idx == 0 { 1 } else { last_idx }
	} else {
		focus.steps.len
	}
	element_matches = walk_path_steps_bound(focus.steps, 0, stop, head, pc, mut env)!
	if element_matches.len == 0 {
		return doc  // no matches → identity
	}
	// Every [?modify] action mutates an ELEMENT (or its attributes), so a
	// focus that selects other node kinds — reachable since the [131b]
	// kind tests landed (`//text()`, `//node()`) — is refused HERE with
	// the user-facing code. Without this the non-element match falls
	// through to index_path, which cannot place it and reports an
	// internal out-of-range instead of the real mistake.
	for m in element_matches {
		if _ := path_ctx_element(pc, m) {
			continue
		}
		return EvalError{
			code:    'cx-err:CXER0100'
			message: '[?modify] requires an element focus; the focus path selects a non-element node (a `node()` / `text()` kind test on a modify focus must be narrowed — `element()` selects elements)'
		}
	}
	// Each action has specific element/attribute focus expectations
	// :set-attr / :delete-attr / :rename / :append
	// :prepend / :insert-* must target an element focus; targeting an
	// attribute axis raises CXER0100.
	if attribute_tail {
		match action.label {
			'set-attr', 'delete-attr', 'rename', 'append', 'prepend',
			'insert-before', 'insert-after', 'replace' {
				return EvalError{
					code:    'cx-err:CXER0100'
					message: '[?modify] :${action.label} requires an element focus (got attribute path)'
				}
			}
			else {}
		}
	}
	// Process matches in REVERSE document order so earlier matches'
	// positions stay stable across structural changes (:delete /
	// :insert-* / :replace), and attribute-only mutations leave the
	// doc_order pre-order walk intact at every index regardless of
	// direction. This sidesteps the alternative bottom-up batched
	// rebuild — simpler to verify, equivalent in heap profile because
	// shared-prefix Elements still end up pointer-equal via slice-
	// header sharing on the unchanged-side children.
	//
	// We translate each doc_order match index to a "path of child
	// positions" rooted at the document. After each modify the new
	// doc_order indices change, so we re-resolve the path inside
	// apply_action_at_position using the most recent tree. The path
	// is stable across attribute-only and sibling-only structural
	// changes happening at OTHER positions in the tree.
	mut path_list := [][]int{}
	for m in element_matches {
		path_list << index_path(m, pc)
	}
	// Sort path_list by document-order DESCENDING so we apply
	// modifications bottom-up (rightmost path lex order is deepest +
	// latest).
	path_list.sort_with_compare(fn (a &[]int, b &[]int) int {
		// Lex compare; reversed for descending.
		la := a.len
		lb := b.len
		mut i := 0
		for i < la && i < lb {
			if a[i] != b[i] {
				return if a[i] < b[i] { 1 } else { -1 }
			}
			i++
		}
		if la == lb { return 0 }
		return if la < lb { 1 } else { -1 }
	})
	mut current_doc := doc
	for p in path_list {
		current_doc = apply_action_at_path(current_doc, p, attr_target,
			attribute_tail, action, mut env)!
	}
	return current_doc
}

// index_path returns the sequence of child-position indices in each
// element's items[] that leads from doc root (path[0]=0 implicitly)
// down to the target. The path is empty for the root match; otherwise
// path[k] = position in spine[k]'s items[] of spine[k+1].
fn index_path(target_idx int, pc PathCtx) []int {
	// Build the spine of doc_order indices root-to-target.
	mut spine := []int{}
	mut cur := target_idx
	for cur >= 0 {
		spine.prepend(cur)
		cur = pc.parents[cur]
	}
	mut path := []int{}
	for i := 1; i < spine.len; i++ {
		parent_idx := spine[i - 1]
		child_doc_idx := spine[i]
		// Find child_doc_idx's position in parent's items[]. Both ends of
		// a [?modify] spine are elements by construction (a modify focus
		// never selects a text node), so a non-element on either side
		// leaves the position unresolved — same `-1` the no-match branch
		// below already produces.
		parent_el := path_ctx_element(pc, parent_idx) or {
			path << -1
			continue
		}
		child_el := path_ctx_element(pc, child_doc_idx) or {
			path << -1
			continue
		}
		mut pos := -1
		for j, it in parent_el.items {
			if it is cx.Element && elements_identical(it, child_el) {
				pos = j
				break
			}
		}
		path << pos
	}
	return path
}

// apply_action_at_path locates the element at `path` (sequence of
// child positions in items[]) in the current `doc` and applies the
// action via spine-copy. Returns the new doc.
fn apply_action_at_path(doc cx.Node, path []int, attr_target string,
                        attribute_tail bool, action cx.ProgramSlot,
                        mut env MatchEnv) !cx.Node {
	// Walk the spine, collecting each Element node in order.
	mut spine := []cx.Element{}
	if doc !is cx.Element {
		return doc
	}
	mut cur_el := doc as cx.Element
	spine << cur_el
	for pos in path {
		if pos < 0 || pos >= cur_el.items.len {
			return EvalError{
				code:    'cx-err:CXER0001'
				message: '[?modify] path index ${pos} out of range (internal)'
			}
		}
		next := cur_el.items[pos]
		if next !is cx.Element {
			return EvalError{
				code:    'cx-err:CXER0001'
				message: '[?modify] path traverses non-Element at position ${pos} (internal)'
			}
		}
		cur_el = next as cx.Element
		spine << cur_el
	}
	// Sibling-mutating actions modify the parent's items[] slice.
	sibling_action := !attribute_tail && (action.label in ['insert-before',
		'insert-after', 'replace'] || action.label == 'delete')
	if sibling_action {
		if spine.len < 2 {
			match action.label {
				'delete' { return cx.Element{ name: '' } }
				'replace' { return eval_node(action.value, mut env)! }
				else {
					return EvalError{
						code:    'cx-err:CXER0100'
						message: '[?modify] :${action.label} cannot target the document root'
					}
				}
			}
		}
		parent := spine[spine.len - 2]
		child_pos := path[path.len - 1]
		new_items := apply_sibling_action(parent.items, child_pos, action, mut env)!
		new_parent := cx.Element{
			name:  parent.name
			attrs: parent.attrs
			items: new_items
			meta:  parent.meta
			table: parent.table
		}
		return rebuild_spine_path_up(spine, path, spine.len - 2, new_parent)
	}
	// Element/attribute action at deepest spine entry.
	target := spine[spine.len - 1]
	new_target := apply_element_or_attr_action(target, attribute_tail,
		attr_target, action, mut env)!
	if spine.len == 1 {
		return new_target
	}
	parent := spine[spine.len - 2]
	child_pos := path[path.len - 1]
	mut new_items := parent.items.clone()
	new_items[child_pos] = new_target
	new_parent := cx.Element{
		name:  parent.name
		attrs: parent.attrs
		items: new_items
		meta:  parent.meta
		table: parent.table
	}
	return rebuild_spine_path_up(spine, path, spine.len - 2, new_parent)
}

// rebuild_spine_path_up rebuilds spine[level-1], spine[level-2], ...,
// spine[0] each with a fresh items[] slice whose descended-child slot
// points to the new_child. `path` provides the child positions per
// level. Returns the new doc root.
fn rebuild_spine_path_up(spine []cx.Element, path []int, level int,
                         new_child cx.Element) cx.Node {
	mut child_node := cx.Node(new_child)
	for i := level - 1; i >= 0; i-- {
		parent := spine[i]
		child_pos := path[i]
		mut new_items := parent.items.clone()
		new_items[child_pos] = child_node
		new_parent := cx.Element{
			name:  parent.name
			attrs: parent.attrs
			items: new_items
			meta:  parent.meta
			table: parent.table
		}
		child_node = cx.Node(new_parent)
	}
	return child_node
}


// elements_identical compares two cx.Element values by structural
// equality on the fields that matter for child-slot identification.
// Element pointer-identity is unreliable in V's sum-type semantics; we
// rely on the spine-walk having built the doc_order in pre-order, so
// the original child at a given parent's items[i] is uniquely the one
// whose canonical render matches.
//
// Caveat: two structurally-identical siblings collide on this check.
// That's acceptable currently: applying an action to "the
// first sibling matching the focus" is the spec-mandated semantic on
// :delete / :replace etc. when multiple siblings would satisfy the
// path. For multi-match runs, the sequential-application loop in
// apply_modify_action re-runs the focus walk against the updated tree
// after each action, so the second iteration picks up the next sibling
// (the previous having been consumed by the action).
fn elements_identical(a cx.Element, b cx.Element) bool {
	// Cheap pointer-identity check on the items[] slice header's
	// data pointer. Two Element values built from the SAME source
	// (PathCtx's `doc_order` pre-walk + the original doc walk in
	// apply_action_at_path) share the same underlying items buffer,
	// so this is the exact identity test we want. Independently-
	// constructed Elements with identical content do NOT match —
	// which is the correct behaviour, since two distinct nodes in
	// the document have distinct items buffers.
	//
	// Fallback for edge cases (e.g. zero-length items): include
	// name + attrs.len + items.len so empty-element siblings remain
	// distinguishable when buffers are zero-pointer aliased.
	if a.name != b.name { return false }
	if a.attrs.len != b.attrs.len { return false }
	if a.items.len != b.items.len { return false }
	if a.items.len > 0 || b.items.len > 0 {
		return voidptr(a.items.data) == voidptr(b.items.data)
	}
	if a.attrs.len > 0 {
		return voidptr(a.attrs.data) == voidptr(b.attrs.data)
	}
	// Both empty — fall back to attr-by-attr scan plus shallow
	// scalar-value compare; safe because there's nothing else to
	// distinguish them by.
	for i, at in a.attrs {
		bt := b.attrs[i]
		if at.name != bt.name { return false }
		if !scalar_value_eq(at.value, bt.value) { return false }
	}
	return true
}

fn scalar_value_eq(a cx.ScalarValue, b cx.ScalarValue) bool {
	match a {
		string {
			if b is string { return a == b }
			return false
		}
		i64 {
			if b is i64 { return a == b }
			return false
		}
		f64 {
			if b is f64 { return a == b }
			return false
		}
		bool {
			if b is bool { return a == b }
			return false
		}
		cx.NullValue {
			return b is cx.NullValue
		}
	}
}

// apply_sibling_action produces a fresh items slice with the
// sibling-level action applied at index `child_idx`. Caller has
// already verified the action is one of :delete/:insert-before/
// :insert-after/:replace.
fn apply_sibling_action(items []cx.Node, child_idx int, action cx.ProgramSlot,
                        mut env MatchEnv) ![]cx.Node {
	mut out := []cx.Node{}
	match action.label {
		'delete' {
			for i, it in items {
				if i == child_idx { continue }
				out << it
			}
		}
		'insert-before' {
			new_val := eval_node(action.value, mut env)!
			for i, it in items {
				if i == child_idx {
					out << new_val
				}
				out << it
			}
		}
		'insert-after' {
			new_val := eval_node(action.value, mut env)!
			for i, it in items {
				out << it
				if i == child_idx {
					out << new_val
				}
			}
		}
		'replace' {
			new_val := eval_node(action.value, mut env)!
			for i, it in items {
				if i == child_idx {
					out << new_val
				} else {
					out << it
				}
			}
		}
		else {
			return EvalError{
				code:    'cx-err:CXER0001'
				message: '[?modify] internal: unexpected sibling action ${action.label}'
			}
		}
	}
	return out
}

// update_attr_value builds a new Attribute that replaces only the
// scalar (value, data_type) while preserving the original
// `local`, `ns_uri`, `is_ref`, and `body` metadata. Allocates a
// fresh AttributeMeta only when the source carried any cold-field
// metadata; the common metadata-free attribute pays no allocation.
// Used by `:set` / `:set-attr` / `:using` on attribute targets under
// [?modify]. Centralised here so the spine-copy hot
// path constructs Attributes without leaking the post-diet meta
// pointer-aliasing rules through every call site.
fn update_attr_value(orig cx.Attribute, sv cx.ScalarValue, dt ?string) cx.Attribute {
	// Fast path: original carries no cold metadata. We only need
	// data_type (which is itself in meta when set). When dt is none
	// the result has no meta either.
	if isnil(orig.meta) {
		mut a := cx.new_attribute(orig.name, sv, cx.AttributeMeta{ data_type: dt })
		a.is_ref = orig.is_ref
		return a
	}
	// Slow path: copy preserved cold metadata (local, ns_uri) from the
	// original and override data_type. Allocates one fresh AttributeMeta;
	// the original meta stays referenced from any other spine frame that
	// shares the unmutated attribute.
	mut m := cx.AttributeMeta{
		data_type: dt
		local:     orig.local()
		ns_uri:    orig.ns_uri()
	}
	mut a := cx.new_attribute(orig.name, sv, m)
	a.is_ref = orig.is_ref
	return a
}

// apply_element_or_attr_action handles actions whose effect is local
// to a single element: :set, :using, :rename, :set-attr, :delete-attr,
// :append, :prepend. (Sibling-level actions are routed through
// apply_sibling_action by apply_action_at_index.) Returns the new
// Element (or scalar Node when :using produces a scalar against an
// element focus,).
fn apply_element_or_attr_action(el cx.Element, attribute_tail bool,
                                attr_target string, action cx.ProgramSlot,
                                mut env MatchEnv) !cx.Node {
	match action.label {
		'set' {
			if attribute_tail {
				// :set on /@attr — replace the attribute's value.
				new_val := eval_node(action.value, mut env)!
				sv, dt := node_to_attr_value(new_val)
				mut new_attrs := el.attrs.clone()
				mut found := false
				for i, a in new_attrs {
					if a.name == attr_target {
						new_attrs[i] = update_attr_value(a, sv, dt)
						found = true
						break
					}
				}
				if !found {
					new_attrs << cx.new_attribute(attr_target, sv, cx.AttributeMeta{ data_type: dt })
				}
				return cx.Node(cx.Element{
					name:  el.name
					attrs: new_attrs
					items: el.items
					meta:  el.meta
					table: el.table
				})
			}
			// :set on element focus — replace the element's body
			// with the evaluated value.
			new_val := eval_node(action.value, mut env)!
			return cx.Node(cx.Element{
				name:  el.name
				attrs: el.attrs
				items: [new_val]
				meta:  el.meta
				table: el.table
			})
		}
		'using' {
			// :using FN — apply closure to the matched node.
			fn_val := eval_node(action.value, mut env)!
			closure := resolve_closure(fn_val, env) or {
				return EvalError{
					code:    'cx-err:CXER0104'
					message: '[?modify] :using must be a [?fn] lambda'
				}
			}
			input := if attribute_tail {
				// Attribute value passed as scalar.
				mut found := cx.Node(cx.Element{ name: '' })
				for a in el.attrs {
					if a.name == attr_target {
						found = cx.Node(cx.ScalarNode{
							value: a.value
							data_type: cx.scalar_type_from_name(a.data_type() or { 'string' }) or { cx.ScalarType.string_type }
						})
						break
					}
				}
				found
			} else {
				cx.Node(el)
			}
			result := invoke_closure(closure, [input], mut env)!
			// §8.10: a `:using` body that traps at runtime (here the
			// closure yields an [err …] value, e.g. `[$idiv 1 0]` →
			// CXER0101) FAILED to produce a value — raise CXER0104
			// (USING_FAILED) with the trap as cause, rather than embedding
			// the err as a document node. (Not raised on a legitimate
			// kind-shift, which yields a non-err value.)
			if is_err_value(result) {
				return EvalError{
					code:      'cx-err:CXER0104'
					message:   'cx-err:CXER0104 E_USING_FAILED: [?modify] :using body trapped: ${err_diagnostic(result)}'
					cause:     result
					cause_set: true
				}
			}
			if attribute_tail {
				sv, dt := node_to_attr_value(result)
				mut new_attrs := el.attrs.clone()
				for i, a in new_attrs {
					if a.name == attr_target {
						new_attrs[i] = update_attr_value(a, sv, dt)
						break
					}
				}
				return cx.Node(cx.Element{
					name:  el.name
					attrs: new_attrs
					items: el.items
					meta:  el.meta
					table: el.table
				})
			}
			return result
		}
		'rename' {
			mut new_name := ''
			av := action.value
			if av is cx.ProgramDirective && av.name == 'name' {
				// Computed-name sub-form [?name NAME-EXPR] (spec/code.md §6.4.2).
				coerced := resolve_name_subform(av, 'rename', mut env)!
				if is_err_node(coerced) {
					return coerced
				}
				new_name = (coerced as cx.ScalarNode).value as string
			} else if av is cx.ProgramLiteral && av.kind == .string_lit {
				new_name = av.str_val
			}
			if new_name == '' {
				return EvalError{
					code:    'cx-err:CXER0100'
					message: '[?modify] :rename requires a name'
				}
			}
			return cx.Node(cx.Element{
				name:  new_name
				attrs: el.attrs
				items: el.items
				meta:  el.meta
				table: el.table
			})
		}
		'set-attr' {
			// Encoded as sequence_lit (name_lit, value_expr).
			seq := action.value
			if seq !is cx.ProgramLiteral {
				return EvalError{
					code:    'cx-err:CXER0001'
					message: '[?modify] :set-attr encoding error'
				}
			}
			seq_lit := seq as cx.ProgramLiteral
			if seq_lit.items.len != 2 {
				return EvalError{
					code:    'cx-err:CXER0001'
					message: '[?modify] :set-attr expects (name, expr)'
				}
			}
			name_node := seq_lit.items[0]
			mut attr_name := ''
			if name_node is cx.ProgramDirective && name_node.name == 'name' {
				// Computed-name sub-form [?name NAME-EXPR] (spec/code.md §6.4.2).
				coerced := resolve_name_subform(name_node, 'name', mut env)!
				if is_err_node(coerced) {
					return coerced
				}
				if is_empty_seq_node(coerced) {
					// Absence → no-op: return the element unchanged.
					return cx.Node(el)
				}
				attr_name = (coerced as cx.ScalarNode).value as string
			} else if name_node is cx.ProgramLiteral && name_node.kind == .string_lit {
				attr_name = name_node.str_val
			}
			if attr_name == '' {
				return EvalError{
					code:    'cx-err:CXER0100'
					message: '[?modify] :set-attr requires an attribute name'
				}
			}
			new_val := eval_node(seq_lit.items[1], mut env)!
			sv, dt := node_to_attr_value(new_val)
			mut new_attrs := el.attrs.clone()
			mut found := false
			for i, a in new_attrs {
				if a.name == attr_name {
					new_attrs[i] = update_attr_value(a, sv, dt)
					found = true
					break
				}
			}
			if !found {
				new_attrs << cx.new_attribute(attr_name, sv, cx.AttributeMeta{ data_type: dt })
			}
			return cx.Node(cx.Element{
				name:  el.name
				attrs: new_attrs
				items: el.items
				meta:  el.meta
				table: el.table
			})
		}
		'delete-attr' {
			attr_name := match action.value {
				cx.ProgramLiteral {
					if (action.value as cx.ProgramLiteral).kind == .string_lit {
						(action.value as cx.ProgramLiteral).str_val
					} else { '' }
				}
				else { '' }
			}
			if attr_name == '' {
				return EvalError{
					code:    'cx-err:CXER0100'
					message: '[?modify] :delete-attr requires an attribute name'
				}
			}
			mut new_attrs := []cx.Attribute{}
			for a in el.attrs {
				if a.name == attr_name { continue }
				new_attrs << a
			}
			return cx.Node(cx.Element{
				name:  el.name
				attrs: new_attrs
				items: el.items
				meta:  el.meta
				table: el.table
			})
		}
		'delete' {
			// Attribute-tail :delete removes the attribute. Element
			// :delete is routed through apply_sibling_action by
			// apply_action_at_index, so this branch only runs for the
			// attribute case.
			if !attribute_tail {
				return EvalError{
					code:    'cx-err:CXER0001'
					message: '[?modify] :delete on element focus must route through sibling-action'
				}
			}
			mut new_attrs := []cx.Attribute{}
			for a in el.attrs {
				if a.name == attr_target { continue }
				new_attrs << a
			}
			return cx.Node(cx.Element{
				name:  el.name
				attrs: new_attrs
				items: el.items
				meta:  el.meta
				table: el.table
			})
		}
		'append' {
			new_val := eval_node(action.value, mut env)!
			mut new_items := el.items.clone()
			new_items << new_val
			return cx.Node(cx.Element{
				name:  el.name
				attrs: el.attrs
				items: new_items
				meta:  el.meta
				table: el.table
			})
		}
		'prepend' {
			new_val := eval_node(action.value, mut env)!
			mut new_items := []cx.Node{}
			new_items << new_val
			for it in el.items { new_items << it }
			return cx.Node(cx.Element{
				name:  el.name
				attrs: el.attrs
				items: new_items
				meta:  el.meta
				table: el.table
			})
		}
		else {
			return EvalError{
				code:    'cx-err:CXER0001'
				message: '[?modify] internal: unexpected action ${action.label}'
			}
		}
	}
}

// ── map / reduce ──────────────────────────────────────────
//
// Per spec/code.md §8.10.5 + §8.10.6, [?map] and [?reduce] are the
// higher-order forms for "apply fn to each item" and "fold xs into
// one value". `:using` carries the worker closure (a unary fn for
// map, binary for reduce). `[par]` enables parallel evaluation.
// Output order under `[par]` is SOURCE order ALWAYS (code.md §6.5.1
// `pure ⇒ deterministic`, stream-5 ruling L105) — `[ordered]` is a
// tombstoned no-op, still accepted where it was valid (paired with
// `[par]`; without `[par]` it stays CXER0100).

fn eval_map_directive(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	if d.slots.len == 0 {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?map] requires positional source slot' }
	}
	mut source_node := d.slots[0].value
	mut using_slot := cx.ProgramNode(cx.ProgramLiteral{ kind: .bool_lit })
	mut have_using := false
	mut par_flag := false
	mut ordered_flag := false
	mut par_width := 0
	mut par_max := false
	mut have_source := false
	for slot in d.slots {
		if slot.kind == .labeled {
			match slot.label {
				'using' {
					using_slot = slot.value
					have_using = true
				}
				'par' { par_flag = true }
				'ordered' { ordered_flag = true }
				else {
					return EvalError{ code: 'cx-err:CXER0100',
						message: "[?map] unknown slot ':${slot.label}'" }
				}
			}
			continue
		}
		// positional dual-accept: a `[label …]` clause child
		// is treated as its labeled-slot equivalent. The source is the
		// only positional that ISN'T a recognized clause child.
		v := slot.value
		if v is cx.ProgramLiteral && v.kind == .cx_element {
			match v.name {
				'using' {
					using_slot = if v.items.len == 1 {
						v.items[0]
					} else {
						cx.ProgramNode(cx.ProgramLiteral{ kind: .block, items: v.items, pos: v.pos })
					}
					have_using = true
					continue
				}
				'par' {
					par_flag = true
					par_width, par_max = par_width_from_items(v.items, mut env)!
					continue
				}
				'ordered' { ordered_flag = true; continue }
				else {}
			}
		}
		if have_source {
			return EvalError{ code: 'cx-err:CXER0100',
				message: '[?map] takes a single positional source slot' }
		}
		source_node = slot.value
		have_source = true
	}
	if !have_source {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?map] requires positional source slot' }
	}
	if !have_using {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?map] requires :using slot' }
	}
	if ordered_flag && !par_flag {
		return EvalError{ code: 'cx-err:CXER0100',
			message: '[?map] [ordered] requires [par] (a tombstoned no-op when paired — L105)' }
	}
	source_val := eval_node(source_node, mut env)!
	using_val := eval_node(using_slot, mut env)!
	closure := resolve_closure(using_val, env) or {
		return EvalError{ code: 'cx-err:CXER0106', message: '[?map] :using must evaluate to a closure (E_USING_NOT_CLOSURE)' }
	}
	if par_flag {
		// True parallel evaluation via V `spawn`.
		// par_map fans the closure over a BOUNDED pool of `width` workers
		// (#94), reassembling by source position ALWAYS (L105). [par] is
		// eager BY REQUEST — parallel fan-out IS full consumption
		// (documented; EV-PULL governs the serial path).
		items := iterate_env(source_val, mut env)
		width := resolve_par_width(par_width, par_max)!
		results := par_map(closure, items, width, mut env)!
		return mk_eager_iterator(.iter_map, [source_val, using_val], results)
	}
	// EV-PULL (stream 17 W1): [?map] is LAZY — the transform parks in
	// the state registry and runs once per PULLED item, never per
	// source item.
	cl_id := iter_park_closure(using_val, mut env)!
	src := iter_wrap_source(source_val, mut env)
	return mk_lazy_iterator(.iter_map, [src, mk_scalar_string(cl_id)])
}

// StreamRangeBounds carries the resolved (start,end,step) of a bounded
// integer range, for the streaming reduce fast-path below.
struct StreamRangeBounds {
	start i64
	end   i64
	step  i64
}

// stream_int_range_bounds returns the (start,end,step) of a bounded
// integer `[$range lo hi step?]` *source expression*, or none for any
// other source shape (non-range call, open-end, datetime, float,
// step-0). It is used by `[?reduce]` to fold a range by generating each
// integer inline (generate→fold→drop) instead of materialising the whole
// sequence — a 4M-int range otherwise costs ~4.3GB RSS and is memory-
// bandwidth bound (lever 1, -gc e). The int-domain guards mirror
// invoke_builtin's 'range' arm exactly so the folded value is identical
// to the eager path; any case it rejects falls through to that path
// (preserving its errors, e.g. step-0 → CXER0100).
fn stream_int_range_bounds(node cx.ProgramNode, mut env MatchEnv) ?StreamRangeBounds {
	if node is cx.ProgramCall {
		if node.name != 'range' || !node.explicit_call {
			return none
		}
		if node.args.len != 2 && node.args.len != 3 {
			return none
		}
		lo_node := eval_node(node.args[0], mut env) or { return none }
		hi_node := eval_node(node.args[1], mut env) or { return none }
		if is_open_end_marker(hi_node) {
			return none
		}
		if scalar_is_datetime(lo_node) || scalar_is_datetime(hi_node) {
			return none
		}
		start := scalar_int(lo_node) or { return none }
		end := scalar_int(hi_node) or { return none }
		mut step := i64(1)
		if node.args.len == 3 {
			step_node := eval_node(node.args[2], mut env) or { return none }
			step = scalar_int(step_node) or { return none }
			if step == 0 {
				return none
			}
		}
		return StreamRangeBounds{
			start: start
			end:   end
			step:  step
		}
	}
	return none
}

fn eval_reduce_directive(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	if d.slots.len == 0 {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?reduce] requires positional source slot' }
	}
	mut source_node := d.slots[0].value
	mut using_slot := cx.ProgramNode(cx.ProgramLiteral{ kind: .bool_lit })
	mut init_slot := cx.ProgramNode(cx.ProgramLiteral{ kind: .bool_lit })
	mut have_using := false
	mut have_init := false
	mut par_flag := false
	mut par_width := 0
	mut par_max := false
	mut have_source := false
	for slot in d.slots {
		if slot.kind == .labeled {
			match slot.label {
				'using' {
					using_slot = slot.value
					have_using = true
				}
				'init' {
					init_slot = slot.value
					have_init = true
				}
				'par' { par_flag = true }
				'ordered' {
					return EvalError{ code: 'cx-err:CXER0100',
						message: '[?reduce] :ordered is not accepted — reduce output is a single value; ordering is unobservable when :using is associative' }
				}
				else {
					return EvalError{ code: 'cx-err:CXER0100',
						message: "[?reduce] unknown slot ':${slot.label}'" }
				}
			}
			continue
		}
		// positional dual-accept clause children.
		v := slot.value
		if v is cx.ProgramLiteral && v.kind == .cx_element {
			match v.name {
				'using' {
					using_slot = if v.items.len == 1 {
						v.items[0]
					} else {
						cx.ProgramNode(cx.ProgramLiteral{ kind: .block, items: v.items, pos: v.pos })
					}
					have_using = true
					continue
				}
				'init' {
					init_slot = if v.items.len == 1 {
						v.items[0]
					} else {
						cx.ProgramNode(cx.ProgramLiteral{ kind: .block, items: v.items, pos: v.pos })
					}
					have_init = true
					continue
				}
				'par' {
					par_flag = true
					par_width, par_max = par_width_from_items(v.items, mut env)!
					continue
				}
				else {}
			}
		}
		if have_source {
			return EvalError{ code: 'cx-err:CXER0100',
				message: '[?reduce] takes a single positional source slot' }
		}
		source_node = slot.value
		have_source = true
	}
	if !have_source {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?reduce] requires positional source slot' }
	}
	if !have_using {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?reduce] requires :using slot' }
	}
	if !have_init {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?reduce] requires :init slot' }
	}
	// Streaming integer-range fold fast-path (lever 1, -gc e). When the
	// source is a bounded integer `[$range lo hi step?]`, fold by generating
	// each integer inline (generate→fold→drop) so the live set is O(1) —
	// never materialising the range. Detection runs in source position (only
	// the bound args are evaluated) so `:using`/`:init` still evaluate after
	// the source, matching the eager path's order. Covers both the serial
	// path and the `:par` path: the parallel form chunks the integer domain
	// and streams each sub-range (par_reduce_range), so a parallel reduce
	// over a large range never materialises it either.
	if bounds := stream_int_range_bounds(source_node, mut env) {
		using_val := eval_node(using_slot, mut env)!
		closure := resolve_closure(using_val, env) or {
			return EvalError{ code: 'cx-err:CXER0106', message: '[?reduce] :using must evaluate to a closure (E_USING_NOT_CLOSURE)' }
		}
		init_val := eval_node(init_slot, mut env)!
		if par_flag {
			// Chunked streaming parallel fold (§8.10.6 associativity, same
			// contract as par_reduce): :init is the per-chunk seed and the
			// combine identity.
			width := resolve_par_width(par_width, par_max)!
			return par_reduce_range(closure, bounds.start, bounds.end, bounds.step,
				init_val, width, mut env)!
		}
		mut acc := init_val
		// Single reusable 2-element args buffer (same invariant as the
		// eager fold below); the int scalar is rebuilt per step but the
		// previous one is dropped immediately, keeping the live set O(1).
		mut argbuf := [init_val, init_val]
		mut i := bounds.start
		if bounds.step > 0 {
			for i <= bounds.end {
				argbuf[0] = acc
				argbuf[1] = cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(i)
					data_type: cx.ScalarType.int_type
				})
				acc = invoke_closure(closure, argbuf, mut env)!
				i += bounds.step
			}
		} else {
			for i >= bounds.end {
				argbuf[0] = acc
				argbuf[1] = cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(i)
					data_type: cx.ScalarType.int_type
				})
				acc = invoke_closure(closure, argbuf, mut env)!
				i += bounds.step
			}
		}
		return acc
	}
	source_val := eval_node(source_node, mut env)!
	using_val := eval_node(using_slot, mut env)!
	closure := resolve_closure(using_val, env) or {
		return EvalError{ code: 'cx-err:CXER0106', message: '[?reduce] :using must evaluate to a closure (E_USING_NOT_CLOSURE)' }
	}
	init_val := eval_node(init_slot, mut env)!
	items := iterate(source_val)
	if par_flag {
		// Parallel chunked fold. Each worker
		// folds one contiguous chunk sequentially with `:init` as
		// the seed; the K partial results are then combined on the
		// caller thread. Requires `:using` associative + `:init`
		// identity (spec/code.md §8.10.6); not validated at runtime.
		width := resolve_par_width(par_width, par_max)!
		return par_reduce(closure, items, init_val, width, mut env)!
	}
	mut acc := init_val
	// Reuse a single 2-element args buffer across the fold instead of allocating a
	// fresh [acc, item] per step (#36/B19 follow-up). Safe: invoke_closure_l copies the
	// arg *values* into the call frame's bindings and no path retains the args slice
	// (verified — only pipeline stages clone args), and the call completes before the
	// next iteration overwrites the buffer.
	mut argbuf := [init_val, init_val] // 2-element buffer, allocated once; contents overwritten per step
	for item in items {
		argbuf[0] = acc
		argbuf[1] = item
		acc = invoke_closure(closure, argbuf, mut env)!
	}
	return acc
}

// ── Iterator-returning combinator stdlib (W3c) ───────────────
//
// Each non-terminal combinator returns an IteratorNode whose `memo` is
// pre-populated (eager directive-time evaluation). The Iterator type
// shell is what satisfies the D23 contract — host emitters force-
// materialise via `iterator_to_sequence()` so external observation is
// identical to the previous SequenceNode-returning forms. End-to-end
// laziness across combinator chains is a follow-up milestone (requires
// threading the closure table through `iterate()`).

// collect_positional_values evaluates every positional slot of `d`
// and returns the resulting Node list in source order. Rejects any
// labeled slot with a CXER0100 error unless the label appears in
// `allowed_labels` (in which case the labeled slot is ignored — the
// caller is expected to extract it via `labeled_slot`).
fn collect_positional_values(d cx.ProgramDirective, mut env MatchEnv, dname string, allowed_labels []string) ![]cx.Node {
	mut out := []cx.Node{}
	for slot in d.slots {
		if slot.kind == .labeled {
			if slot.label !in allowed_labels {
				return EvalError{
					code: 'cx-err:CXER0100'
					message: "[?${dname}] unknown slot ':${slot.label}'"
				}
			}
			continue
		}
		// dual-accept: a positional `[label …]` cx_element whose
		// head is one of `allowed_labels` is a clause-child slot, not a
		// positional source — skip (the directive reads it via
		// `directive_clause`).
		v := slot.value
		if v is cx.ProgramLiteral && v.kind == .cx_element && v.name in allowed_labels {
			continue
		}
		out << eval_node(slot.value, mut env)!
	}
	return out
}

fn eval_filter_directive(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	using_slot := directive_clause(d, 'using') or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?filter] requires :using / [using …] slot' }
	}
	srcs := collect_positional_values(d, mut env, 'filter', ['using'])!
	if srcs.len != 1 {
		return EvalError{
			code: 'cx-err:CXER0001'
			message: '[?filter] requires a single positional source slot'
		}
	}
	using_val := eval_node(using_slot, mut env)!
	// callable validation stays EAGER (a non-closure :using refuses at
	// the directive, never at first pull); the resolved value itself is
	// parked below.
	resolve_closure(using_val, env) or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?filter] :using must evaluate to a closure' }
	}
	// EV-PULL (stream 17 W1): [?filter] is LAZY — the predicate runs
	// once per pulled source item. (§9.2 err-valued-predicate
	// short-circuit now surfaces at PULL time through the pull error
	// channel.)
	cl_id := iter_park_closure(using_val, mut env)!
	src := iter_wrap_source(srcs[0], mut env)
	return mk_lazy_iterator(.iter_filter, [src, mk_scalar_string(cl_id)])
}

fn eval_take_directive(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	vals := collect_positional_values(d, mut env, 'take', [])!
	if vals.len != 2 {
		return EvalError{
			code: 'cx-err:CXER0001'
			message: '[?take] requires two positional slots: count, source'
		}
	}
	n := scalar_int(vals[0]) or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?take] count must be an integer' }
	}
	if n < 0 {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?take] count must be non-negative' }
	}
	// EV-PULL (stream 17 W1): [?take n] is the BOUNDED consumer — it
	// pulls exactly n through the chain when forced, never the source's
	// full length.
	src := iter_wrap_source(vals[1], mut env)
	return mk_lazy_iterator(.iter_take, [src, vals[0]])
}

fn eval_drop_directive(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	vals := collect_positional_values(d, mut env, 'drop', [])!
	if vals.len != 2 {
		return EvalError{
			code: 'cx-err:CXER0001'
			message: '[?drop] requires two positional slots: count, source'
		}
	}
	n := scalar_int(vals[0]) or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?drop] count must be an integer' }
	}
	// EV-PULL (stream 17 W1): lazy — the skip happens at pull time.
	if n < 0 {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?drop] count must be non-negative' }
	}
	src := iter_wrap_source(vals[1], mut env)
	return mk_lazy_iterator(.iter_drop, [src, vals[0]])
}

fn eval_zip_directive(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	srcs := collect_positional_values(d, mut env, 'zip', [])!
	if srcs.len < 2 {
		return EvalError{
			code: 'cx-err:CXER0001'
			message: '[?zip] requires at least two positional source slots'
		}
	}
	mut item_lists := [][]cx.Node{cap: srcs.len}
	mut shortest := -1
	for s in srcs {
		items := iterate(s)
		if shortest < 0 || items.len < shortest { shortest = items.len }
		item_lists << items
	}
	mut out := []cx.Node{}
	if shortest > 0 {
		for i in 0 .. shortest {
			mut tup := []cx.Node{cap: item_lists.len}
			for lst in item_lists {
				tup << lst[i]
			}
			out << cx.Node(cx.Element{
				name: seq_marker_name
				items: tup
			})
		}
	}
	return mk_eager_iterator(.iter_zip, srcs, out)
}

fn eval_enumerate_directive(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	srcs := collect_positional_values(d, mut env, 'enumerate', [])!
	if srcs.len != 1 {
		return EvalError{
			code: 'cx-err:CXER0001'
			message: '[?enumerate] requires a single positional source slot'
		}
	}
	items := iterate(srcs[0])
	mut out := []cx.Node{cap: items.len}
	for i, it in items {
		out << cx.Node(cx.Element{
			name: seq_marker_name
			items: [
				cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(i64(i))
					data_type: cx.ScalarType.int_type
				}),
				it,
			]
		})
	}
	return mk_eager_iterator(.iter_enumerate, srcs, out)
}

fn eval_chunks_directive(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	vals := collect_positional_values(d, mut env, 'chunks', [])!
	if vals.len != 2 {
		return EvalError{
			code: 'cx-err:CXER0001'
			message: '[?chunks] requires two positional slots: count, source'
		}
	}
	n := scalar_int(vals[0]) or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?chunks] count must be an integer' }
	}
	if n <= 0 {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?chunks] count must be positive' }
	}
	items := iterate(vals[1])
	mut out := []cx.Node{}
	mut i := 0
	for i < items.len {
		end := if i + int(n) > items.len { items.len } else { i + int(n) }
		mut chunk := []cx.Node{cap: end - i}
		for j in i .. end {
			chunk << items[j]
		}
		out << cx.Node(cx.Element{
			name: seq_marker_name
			items: chunk
		})
		i = end
	}
	return mk_eager_iterator(.iter_chunks, [vals[1], vals[0]], out)
}

fn eval_concat_directive(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	srcs := collect_positional_values(d, mut env, 'concat', [])!
	if srcs.len < 1 {
		return EvalError{
			code: 'cx-err:CXER0001'
			message: '[?concat] requires at least one positional source slot'
		}
	}
	mut out := []cx.Node{}
	for s in srcs {
		for it in iterate(s) {
			out << it
		}
	}
	return mk_eager_iterator(.iter_concat, srcs, out)
}

fn eval_cycle_directive(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	max_slot := labeled_slot(d, 'max') or {
		return EvalError{
			code: 'cx-err:CXER0001'
			message: '[?cycle] requires :max slot'
		}
	}
	srcs := collect_positional_values(d, mut env, 'cycle', ['max'])!
	if srcs.len != 1 {
		return EvalError{
			code: 'cx-err:CXER0001'
			message: '[?cycle] requires a single positional source slot'
		}
	}
	max_val := eval_node(max_slot, mut env)!
	max := scalar_int(max_val) or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?cycle] :max must be an integer' }
	}
	if max < 0 {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?cycle] :max must be non-negative' }
	}
	items := iterate(srcs[0])
	mut out := []cx.Node{cap: int(max)}
	if items.len > 0 {
		for out.len < int(max) {
			out << items[out.len % items.len]
		}
	}
	return mk_eager_iterator(.iter_cycle, [srcs[0], max_val], out)
}

fn eval_scan_directive(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	using_slot := directive_clause(d, 'using') or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?scan] requires :using / [using …] slot' }
	}
	init_slot := directive_clause(d, 'init') or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?scan] requires :init slot' }
	}
	srcs := collect_positional_values(d, mut env, 'scan', ['using', 'init'])!
	if srcs.len != 1 {
		return EvalError{
			code: 'cx-err:CXER0001'
			message: '[?scan] requires a single positional source slot'
		}
	}
	using_val := eval_node(using_slot, mut env)!
	closure := resolve_closure(using_val, env) or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?scan] :using must evaluate to a closure' }
	}
	init_val := eval_node(init_slot, mut env)!
	items := iterate(srcs[0])
	mut out := []cx.Node{cap: items.len + 1}
	mut acc := init_val
	out << acc
	for it in items {
		acc = invoke_closure(closure, [acc, it], mut env)!
		out << acc
	}
	return mk_eager_iterator(.iter_scan, [srcs[0], using_val, init_val], out)
}

fn eval_flatten_directive(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	srcs := collect_positional_values(d, mut env, 'flatten', [])!
	if srcs.len != 1 {
		return EvalError{
			code: 'cx-err:CXER0001'
			message: '[?flatten] requires a single positional source slot'
		}
	}
	items := iterate(srcs[0])
	mut out := []cx.Node{}
	for it in items {
		if it is cx.Element && (it.name == '' || it.name == seq_marker_name) {
			for inner in it.items {
				out << inner
			}
		} else if it is cx.SequenceNode {
			for inner in it.items {
				out << inner
			}
		} else if it is cx.IteratorNode {
			for inner in iterate(it) {
				out << inner
			}
		} else {
			out << it
		}
	}
	return mk_eager_iterator(.iter_flatten, srcs, out)
}

fn eval_partition_directive(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	using_slot := directive_clause(d, 'using') or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?partition] requires :using / [using …] slot' }
	}
	srcs := collect_positional_values(d, mut env, 'partition', ['using'])!
	if srcs.len != 1 {
		return EvalError{
			code: 'cx-err:CXER0001'
			message: '[?partition] requires a single positional source slot'
		}
	}
	using_val := eval_node(using_slot, mut env)!
	closure := resolve_closure(using_val, env) or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?partition] :using must evaluate to a closure' }
	}
	items := iterate(srcs[0])
	mut truthy_items := []cx.Node{}
	mut falsy_items := []cx.Node{}
	for it in items {
		keep := invoke_closure(closure, [it], mut env)!
		// §9.2 / #348(a): an err-valued predicate short-circuits the whole
		// [?partition] and IS its result (see eval_filter_directive).
		if is_err_value(keep) {
			return keep
		}
		ebv := node_ebv(keep) or { return iterator_ebv_err() }
		if ebv {
			truthy_items << it
		} else {
			falsy_items << it
		}
	}
	pair := [
		cx.Node(cx.Element{ name: seq_marker_name, items: truthy_items }),
		cx.Node(cx.Element{ name: seq_marker_name, items: falsy_items }),
	]
	return mk_eager_iterator(.iter_partition, [srcs[0], using_val], pair)
}

fn eval_group_by_directive(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	using_slot := directive_clause(d, 'using') or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?group-by] requires :using / [using …] slot' }
	}
	srcs := collect_positional_values(d, mut env, 'group-by', ['using'])!
	if srcs.len != 1 {
		return EvalError{
			code: 'cx-err:CXER0001'
			message: '[?group-by] requires a single positional source slot'
		}
	}
	using_val := eval_node(using_slot, mut env)!
	closure := resolve_closure(using_val, env) or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?group-by] :using must evaluate to a closure' }
	}
	items := iterate(srcs[0])
	mut keys_in_order := []string{}
	mut groups := map[string][]cx.Node{}
	for it in items {
		key_node := invoke_closure(closure, [it], mut env)!
		key := scalar_to_string(key_node) or { '${key_node}' }
		if key !in groups {
			keys_in_order << key
			groups[key] = []cx.Node{}
		}
		groups[key] << it
	}
	// Emit as a sequence of (key, sub-sequence) pairs — preserves first-
	// seen key order; downstream `[?to-map]` lifts to MapNode.
	mut out := []cx.Node{cap: keys_in_order.len}
	for k in keys_in_order {
		out << cx.Node(cx.Element{
			name: seq_marker_name
			items: [
				cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(k)
					data_type: cx.ScalarType.string_type
				}),
				cx.Node(cx.Element{ name: seq_marker_name, items: groups[k] }),
			]
		})
	}
	return mk_eager_iterator(.iter_group_by, [srcs[0], using_val], out)
}

// ── Force-materialization directives ──────────────────────────

fn eval_to_sequence_directive(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	vals := collect_positional_values(d, mut env, 'to-sequence', [])!
	if vals.len != 1 {
		return EvalError{
			code: 'cx-err:CXER0001'
			message: '[?to-sequence] requires a single positional source slot'
		}
	}
	items := materialize_to_items(vals[0])
	return cx.Node(cx.Element{
		name: seq_marker_name
		items: items
	})
}

// materialize_to_items extracts the inner items list from any sequence-
// shaped value — Iterator, Sequence, Array marker, Map marker, or
// SequenceNode / ArrayNode value-kind. Used by the `[?to-*]` directives
// so the cross-shape conversion is straightforward.
fn materialize_to_items(n cx.Node) []cx.Node {
	if n is cx.Element {
		if n.name == '' || n.name == seq_marker_name
		   || n.name == arr_marker_name || n.name == map_marker_name {
			return n.items.clone()
		}
		// Table sequence view (D22, #404) — same expansion as iterate().
		if td := n.table_opt() {
			return table_row_maps(td)
		}
		return [n]
	}
	if n is cx.SequenceNode { return n.items.clone() }
	if n is cx.ArrayNode    { return n.items.clone() }
	if n is cx.IteratorNode {
		return iterate(n)
	}
	return [n]
}

fn eval_to_array_directive(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	vals := collect_positional_values(d, mut env, 'to-array', [])!
	if vals.len != 1 {
		return EvalError{
			code: 'cx-err:CXER0001'
			message: '[?to-array] requires a single positional source slot'
		}
	}
	items := materialize_to_items(vals[0])
	return cx.Node(cx.Element{
		name: arr_marker_name
		items: items
	})
}

fn eval_to_map_directive(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	vals := collect_positional_values(d, mut env, 'to-map', [])!
	if vals.len != 1 {
		return EvalError{
			code: 'cx-err:CXER0001'
			message: '[?to-map] requires a single positional source slot (sequence of (key, value) pairs)'
		}
	}
	items := materialize_to_items(vals[0])
	mut entries := []cx.MapEntry{cap: items.len}
	for it in items {
		// Accept (key, value) paren-comma pair OR a 2-item sequence /
		// array marker.
		mut pair_items := []cx.Node{}
		if it is cx.Element && (it.name == '' || it.name == seq_marker_name || it.name == arr_marker_name) {
			pair_items = it.items.clone()
		} else if it is cx.SequenceNode {
			pair_items = it.items.clone()
		} else if it is cx.ArrayNode {
			pair_items = it.items.clone()
		} else {
			return EvalError{
				code: 'cx-err:CXER0001'
				message: '[?to-map] entries must be 2-tuples (key, value)'
			}
		}
		if pair_items.len != 2 {
			return EvalError{
				code: 'cx-err:CXER0001'
				message: '[?to-map] each entry must have exactly two elements (key, value)'
			}
		}
		key_str := scalar_to_string(pair_items[0]) or { '${pair_items[0]}' }
		entries << cx.MapEntry{
			key_type:  cx.ScalarType.string_type
			key_value: cx.ScalarValue(key_str)
			value:     pair_items[1]
		}
	}
	return cx.Node(cx.MapNode{ entries: entries })
}

// ── view opt-in ───────────────────────────────────────────────
//
// `[?view EXPR]` flips a slice expression's result from copy (the default
// slice semantics) to a zero-copy *view*. CX values are immutable
// so a view is OBSERVATIONALLY IDENTICAL to a copy — it yields
// the same value. Currently the directive is therefore a
// **semantic no-op that documents intent**: it evaluates its single operand
// and returns the result unchanged. `[= [?view $xs[2:4]] $xs[2:4]]` is `true`
// by construction.
//
// `[?views BLOCK]` is the scoped form — every slice inside BLOCK is
// view-flavored. With the no-op-but-documented semantics this is identical
// to evaluating the block: there is no observable difference between a
// copying slice and a view slice while the source is immutable.
//
// Source-mutation rejection (/ the EBNF `View` production note)
// is trivially satisfied: CX has no mutation, so the static "source not
// mutated for the view's lifetime" check can never fail.
//
// DEFERRED (a future revision): true zero-copy walking — having the view return an
// Iterator-flavored value that strides the source array in place rather than
// materialising a fresh sequence — is a runtime memory optimisation, not a
// surface/semantics concern. It is intentionally NOT implemented here; the
// this revision ships the surface + semantics only.
fn eval_view_directive(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	vals := collect_positional_values(d, mut env, 'view', [])!
	if vals.len != 1 {
		return EvalError{
			code:    'cx-err:CXER0001'
			message: '[?view] requires a single positional expression (the slice to view)'
		}
	}
	return vals[0]
}

fn eval_views_directive(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	// Scoped form. Each positional slot inside the block is a slice/expr;
	// the view flip is a documented no-op, so every operand
	// yields its own value. A single operand returns that value directly;
	// multiple operands collect into a `__cx_seq__` envelope (matching the
	// sequence-of-values shape produced elsewhere).
	vals := collect_positional_values(d, mut env, 'views', [])!
	if vals.len == 0 {
		return EvalError{
			code:    'cx-err:CXER0001'
			message: '[?views] requires at least one slice/expr in its block'
		}
	}
	if vals.len == 1 {
		return vals[0]
	}
	return cx.Element{ name: seq_marker_name, items: vals }
}

// ── For-comprehension ───────────────────────────────────────────────────────

// err_guard_passthrough_code is the INTERNAL unwind marker for an err-VALUED
// [?for] guard/predicate result (§9.2 uniform propagation, #348 ruling (a)):
// the !-typed clause runners cannot return a value, so the err value rides
// VERBATIM in EvalError.cause up to the comprehension boundary
// (eval_for_comp / the api.v streaming boundary), where it is re-materialised
// as the form's RESULT. It must never escape to user code — every [?for]
// entry point unwraps it.
const err_guard_passthrough_code = 'cx-err:__guard_passthrough__'

@[inline]
fn mk_guard_passthrough(errv cx.Node) EvalError {
	return EvalError{
		code:      err_guard_passthrough_code
		message:   'err-valued guard/predicate propagates (§9.2)'
		cause:     errv
		cause_set: true
	}
}

// unwrap_guard_err converts the internal guard-passthrough unwind back into
// the err VALUE it carries (the comprehension's result); every other error
// propagates unchanged.
fn unwrap_guard_err(e IError) !cx.Node {
	if e is EvalError {
		if e.code == err_guard_passthrough_code && e.cause_set {
			return e.cause
		}
	}
	return e
}

fn eval_for_comp(f cx.ProgramForComp, mut env MatchEnv) !cx.Node {
	// Comprehension-result postfix steps (RULED PS-1, #886): `[?for …]/x`
	// materializes the comprehension, then steps the RESULT — a stepped
	// for-comp is a READ (never streamed; stream_mode_of declines it).
	if f.path.len > 0 {
		base := eval_for_comp(cx.ProgramForComp{ ...f, path: []cx.ProgramPathStep{} }, mut env)!
		return apply_value_path(base, f.path, mut env, true)
	}
	mut results := []cx.Node{}
	// Frame-sharing clone (#272): the comprehension frame only ever writes
	// bindings (loop vars / :let clauses); closure registration cows first.
	// Entry + buffered + generator-emit paths were still deep-cloning the
	// whole program closure table after #57 converted the per-item walker —
	// on served render paths that made every [?for] (and every generated ITEM
	// on the range/iterate/unfold paths) copy 540+ closures.
	mut frame := env.clone_frame_sharing_closures()
	// thread :take / :drop counters through the
	// recursion so generators short-circuit on :take and skip the
	// first N candidates on :drop, BEFORE the yield boundary. Counts
	// (incl. [limit], folded into the take bound — the ruled L93
	// collapse) are evaluated once here, in the enclosing scope.
	mut limit_state := build_for_limit_state(f.clauses, mut frame) or {
		return unwrap_guard_err(err)
	}
	// bundle the yield-side configuration so the
	// recursive pipeline can dispatch per-yield-form at the leaf.
	spec := YieldSpec{
		expr:       f.yield
		value_expr: f.yield_value
		form:       f.yield_form
	}
	// If any clause is order_by or group_by, route through the
	// materialise-and-resume path (see eval_for_comp_buffered). Plain
	// generator / filter / binding / limit pipelines stream through
	// the natural recursion.
	mut did_par := false
	// Real for-par (#94 Stage 2): `[?for … [par]]` runs the outermost
	// generator's items across a bounded worker pool. Taken only when the
	// shape is semantics-safe (no order-by/group-by buffering, no
	// takewhile/dropwhile, a materialised-sequence source, no `$_position`
	// reference); otherwise fall through to the sequential walk (the prior
	// no-op behaviour). take/drop/limit are post-applied on the assembled list.
	if pc := for_par_clause(f.clauses) {
		if !has_buffered_clause(f.clauses) && !for_has_ordered_terminator(f.clauses)
			&& !comp_refs_position(f) {
			// #348: an err-valued guard unwinds as the internal passthrough
			// (incl. out of par workers, whose channel carries the cause
			// verbatim) — unwrap it into the comprehension's RESULT here.
			par_results, ran := eval_for_comp_par(f, pc, spec, mut frame) or {
				return unwrap_guard_err(err)
			}
			if ran {
				results = par_results.clone()
				apply_take_drop_post(limit_state, mut results)
				did_par = true
			}
		}
	}
	if !did_par {
		if has_buffered_clause(f.clauses) {
			eval_for_comp_buffered(f.clauses, 0, spec, mut frame, mut results) or {
				return unwrap_guard_err(err)
			}
			// :order-by/:group-by buffer first; :take/:drop are applied
			// after the sort/partition completes.
			apply_take_drop_post(limit_state, mut results)
		} else {
			run_for_clauses(f.clauses, 0, spec, mut frame, mut results, mut limit_state) or {
				return unwrap_guard_err(err)
			}
		}
	}
	// shape per-iteration results and outer container.
	//   * sequence yield (default): inner sequences flatten per
	//   * array yield: each result wraps as `__cx_arr__`; arrays do
	//     NOT flatten.
	//   * map yield: each result is a key/value pair (handled at
	//     run_for_clauses by passing `yield_value` through env);
	//     accumulated as `__cx_map__` outer.
	yield_form := f.yield_form
	outer_form := f.outer_form
	mut shaped := []cx.Node{}
	match yield_form {
		.sequence {
			// inner-sequence flatten.
			for r in results {
				if r is cx.Element && r.name == seq_marker_name {
					for it in r.items {
						shaped << it
					}
				} else {
					shaped << r
				}
			}
		}
		.array {
			// Each yield wraps as an Array marker. The yield body
			// already evaluates to an array literal in the W6 examples
			// (`[$x, $y]` — bare-bracket-with-comma form parses as
			// cx.ProgramLiteral .array_lit); we preserve it as-is so that
			// the outer accumulator sees a sequence of arrays. If the
			// yield body produced a non-array node (scalar / element),
			// we still wrap it so the per-iteration shape is uniform.
			for r in results {
				if r is cx.Element && r.name == arr_marker_name {
					shaped << r
				} else {
					shaped << cx.Element{ name: arr_marker_name, items: [r] }
				}
			}
		}
		.map {
			// Map results are already key/value-paired entries built
			// at the yield boundary in run_for_clauses; pass through.
			shaped = results.clone()
		}
	}
	match outer_form {
		.sequence {
			// Top-level rendering joins items with newlines.
			return cx.Element{ name: '', items: shaped }
		}
		.array {
			// `[?for-array]` — preserve outer Array container.
			return cx.Element{ name: arr_marker_name, items: shaped }
		}
		.map {
			// `[?for-map]` — outer Map container; entries are the
			// key/value pair child elements built by the yield-map
			// branch in run_for_clauses (name = stringified key,
			// items = [value]).
			return cx.Element{ name: map_marker_name, items: shaped }
		}
	}
}

fn has_buffered_clause(clauses []cx.ProgramForClause) bool {
	for c in clauses {
		match c.kind {
			.order_by, .group_by { return true }
			else {}
		}
	}
	return false
}

// for_par_clause returns the `.par` clause of a for-comprehension, if present
// (so its resolved width drives the parallel path).
fn for_par_clause(clauses []cx.ProgramForClause) ?cx.ProgramForClause {
	for c in clauses {
		if c.kind == .par {
			return c
		}
	}
	return none
}

// for_has_ordered_terminator reports whether the comprehension has an
// order-dependent terminating clause (takewhile / dropwhile) that cannot be
// post-applied to a parallel-collected list — forcing the sequential fallback.
fn for_has_ordered_terminator(clauses []cx.ProgramForClause) bool {
	for c in clauses {
		match c.kind {
			.takewhile, .dropwhile { return true }
			else {}
		}
	}
	return false
}


// comp_refs_position reports whether a for-comprehension references `$_position`
// (the 1-based OUTPUT index), which is order-dependent and therefore unsafe to
// evaluate in parallel — those comprehensions take the sequential fallback.
fn comp_refs_position(f cx.ProgramForComp) bool {
	if prog_refs_position(f.yield) {
		return true
	}
	if yv := f.yield_value {
		if prog_refs_position(yv) {
			return true
		}
	}
	for c in f.clauses {
		if e := c.expr {
			if prog_refs_position(e) {
				return true
			}
		}
		if s := c.source {
			if prog_refs_position(s) {
				return true
			}
		}
	}
	return false
}

// prog_refs_position recursively reports whether `node` references the
// `$_position` binding anywhere in the realistic expression containers (yield
// bodies, call args, element items/attrs, directive slots, nested for-comps).
fn prog_refs_position(node cx.ProgramNode) bool {
	match node {
		cx.ProgramBinding {
			return node.name == '_position'
		}
		cx.ProgramCall {
			for a in node.args {
				if prog_refs_position(a) {
					return true
				}
			}
			return false
		}
		cx.ProgramLiteral {
			if ne := node.name_expr {
				if prog_refs_position(ne) {
					return true
				}
			}
			for it in node.items {
				if prog_refs_position(it) {
					return true
				}
			}
			for a in node.attrs {
				if prog_refs_position(a.value) {
					return true
				}
			}
			return false
		}
		cx.ProgramDirective {
			for s in node.slots {
				if prog_refs_position(s.value) {
					return true
				}
			}
			return false
		}
		cx.ProgramForComp {
			return comp_refs_position(node)
		}
		else {
			return false
		}
	}
}

// eval_for_comp_par runs the for-par bounded-pool path. Returns (results, true)
// when it parallelized; (_, false) when the source shape isn't parallelizable
// (no generator, a pattern-as-source, or a special/streaming IteratorNode
// source) and the caller must use the sequential walk.
fn eval_for_comp_par(f cx.ProgramForComp, par_clause cx.ProgramForClause, spec YieldSpec, mut env MatchEnv) !([]cx.Node, bool) {
	mut gen_idx := -1
	for i, c in f.clauses {
		if c.kind == .generator {
			gen_idx = i
			break
		}
	}
	if gen_idx < 0 {
		return []cx.Node{}, false
	}
	gen := f.clauses[gen_idx]
	src_node := gen.source or { return []cx.Node{}, false }
	// pattern-as-source walks the implicit doc — not the simple-sequence shape.
	if src_node is cx.ProgramPattern {
		return []cx.Node{}, false
	}
	source_val := eval_for_source(src_node, mut env)!
	// Special / streaming iterator sources (ranges, net/http/sse accept,
	// unfold/iterate) are not the materialised-sequence shape; run sequentially.
	if source_val is cx.IteratorNode {
		return []cx.Node{}, false
	}
	items := iterate(source_val)
	width := resolve_par_width(par_clause.par_width, par_clause.par_max)!
	mut ff := false
	for c in f.clauses {
		if c.kind == .fail_fast {
			ff = true
			break
		}
	}
	results := par_for_run(f.clauses, gen, gen_idx, spec, items, width, ff, mut env)!
	return results, true
}

// eval_for_comp_buffered handles for-comprehensions containing
// :order-by or :group-by clauses. Each such clause acts as a barrier:
// upstream frames are materialised, then downstream clauses (including
// :yield) run per sorted/grouped frame.
//
// Strategy: walk the clause list; when we hit order_by or group_by,
// re-run the upstream pipeline collecting frames into a buffer, sort
// or partition, then continue downstream. We do this by splitting at
// the first order_by/group_by, recursing buffered for the prefix, then
// resuming the suffix.
fn eval_for_comp_buffered(clauses []cx.ProgramForClause, idx int, spec YieldSpec,
                           mut env MatchEnv, mut out []cx.Node) ! {
	mut frames := [env.clone_frame_sharing_closures()]
	eval_for_buffered_frames(clauses, idx, spec, mut frames, mut out)!
}

// eval_for_buffered_frames — the barrier pipeline over a FRAME SET (stream-2
// W1, with #753's structural keys). The earlier shape recursed per-frame
// after each barrier, so a second barrier saw ONE frame at a time —
// `[group-by …] [order-by AGG]` could never order across groups (top-SKU,
// the spec §4 skeleton) and `[order-by …] [group-by …]` made every item its
// own group. Here every barrier operates on the WHOLE surviving frame set:
// flow all frames through the prefix, apply the barrier set-wide (sort /
// partition), recurse with the resulting set. Single-barrier behavior is
// byte-identical to the old walk (one frame in → the same flow).
fn eval_for_buffered_frames(clauses []cx.ProgramForClause, idx int, spec YieldSpec,
                             mut frames []MatchEnv, mut out []cx.Node) ! {
	// Find the next order_by / group_by barrier from idx.
	mut barrier := -1
	for j := idx; j < clauses.len; j++ {
		k := clauses[j].kind
		if k == .order_by || k == .group_by {
			barrier = j
			break
		}
	}
	if barrier < 0 {
		// No more barriers — the natural recursion per surviving frame.
		// Buffered path applies :take/:drop post-collect (see
		// apply_take_drop_post); inner recursion runs unbounded.
		for i in 0 .. frames.len {
			mut fenv := frames[i]
			mut inner_state := ForLimitState{ remaining: -1, drop_remaining: 0 }
			run_for_clauses(clauses, idx, spec, mut fenv, mut out, mut inner_state)!
		}
		return
	}
	// Flow EVERY frame through the prefix pipeline into the barrier
	// (generation order within each frame, frame order across — stable).
	mut flowed := []MatchEnv{}
	for i in 0 .. frames.len {
		mut fenv := frames[i]
		collect_frames(clauses, idx, barrier, mut fenv, mut flowed)!
	}
	bc := clauses[barrier]
	match bc.kind {
		.order_by {
			expr := bc.expr or {
				return EvalError{ code: 'cx-err:CXER0001', message: ':order-by missing expr' }
			}
			// Compute key per frame, set-wide.
			mut keyed := []KeyedFrame{}
			for fr in flowed {
				mut fenv := fr
				key := eval_node(expr, mut fenv)!
				keyed << KeyedFrame{ frame: fr, key: key }
			}
			// Sort: asc by default. Stable on string/int comparison.
			desc := bc.direction == 'desc'
			sort_keyed_frames(mut keyed, desc)
			mut sorted := []MatchEnv{}
			for kf in keyed {
				sorted << kf.frame
			}
			eval_for_buffered_frames(clauses, barrier + 1, spec, mut sorted, mut out)!
		}
		.group_by {
			expr := bc.expr or {
				return EvalError{ code: 'cx-err:CXER0001', message: ':group-by missing expr' }
			}
			// Partition the WHOLE flowed set by key (structural value
			// equality, #753); group order = first appearance, pinned (L94).
			mut keys := []cx.Node{}
			mut groups := [][]MatchEnv{}
			for fr in flowed {
				mut fenv := fr
				key := eval_node(expr, mut fenv)!
				mut found := -1
				for ki, kk in keys {
					if nodes_equal(kk, key) {
						found = ki
						break
					}
				}
				if found < 0 {
					keys << key
					groups << [fr]
				} else {
					groups[found] << fr
				}
			}
			// L94 (stream 2, W1): the FULL γ binding set per code.md §7.2 —
			// $key (the partition key), $count (cardinality), and $group:
			// one [item …] element per grouped frame carrying the
			// comprehension's generator + [= …] binder values as named
			// children in clause order, so aggregates navigate $group/NAME
			// and atomize in arithmetic ([$sum $group/r] — the ruled M5
			// shape). $group was the spec'd-but-unimplemented only-COUNT
			// blocker (#711).
			mut binders := []string{}
			for j := 0; j < barrier; j++ {
				ck := clauses[j]
				if (ck.kind == .generator || ck.kind == .binding) && ck.bind != ''
					&& ck.bind !in binders {
					binders << ck.bind
				}
			}
			mut reps := []MatchEnv{}
			for gi, _ in keys {
				rep := groups[gi][0]
				mut fenv := rep
				fenv.bindings['count'] = cx.ScalarNode{
					value: cx.ScalarValue(i64(groups[gi].len))
					data_type: cx.ScalarType.int_type
				}
				fenv.bindings['key'] = keys[gi]
				mut gitems := []cx.Node{}
				for fr in groups[gi] {
					mut children := []cx.Node{}
					for b in binders {
						if v := fr.bindings[b] {
							children << cx.Node(cx.Element{
								name:  b
								items: [v]
							})
						}
					}
					gitems << cx.Node(cx.Element{
						name:  'item'
						items: children
					})
				}
				fenv.bindings['group'] = cx.Node(cx.Element{
					name:  seq_marker_name
					items: gitems
				})
				reps << fenv
			}
			eval_for_buffered_frames(clauses, barrier + 1, spec, mut reps, mut out)!
		}
		else {}
	}
}

struct KeyedFrame {
	frame MatchEnv
	key   cx.Node
}

// collect_frames runs clauses[idx..barrier] and pushes a copy of each
// resulting environment into `frames`. Reuses the same generator /
// filter / binding semantics as run_for_clauses but stops at `barrier`.
fn collect_frames(clauses []cx.ProgramForClause, idx int, barrier int,
                  mut env MatchEnv, mut frames []MatchEnv) ! {
	if idx == barrier {
		// Frame-sharing (#272): buffered frames only carry bindings deltas.
		frames << env.clone_frame_sharing_closures()
		return
	}
	c := clauses[idx]
	match c.kind {
		.generator {
			src_node := c.source or {
				return EvalError{ code: 'cx-err:CXER0001', message: 'generator missing source' }
			}
			if src_node is cx.ProgramPattern {
				doc := env.bindings['doc'] or {
					return EvalError{
						code:    'cx-err:CXER0001'
						message: '[?for] pattern-as-source requires $doc'
					}
				}
				collect_frames_pattern_walk(src_node, doc, clauses, idx, barrier,
				                              mut env, mut frames)!
				return
			}
			source_val := eval_for_source(src_node, mut env)!
			for item in iterate(source_val) {
				mut next := env.clone_frame_sharing_closures() // #272 frame-sharing
				if expr_pat := c.expr {
					if expr_pat is cx.ProgramPattern {
						matched := match_pattern(expr_pat, item) or { continue }
						for k, v in matched.bindings {
							next.bindings[k] = v
						}
					}
				} else {
					next.bindings[c.bind] = item
				}
				collect_frames(clauses, idx + 1, barrier, mut next, mut frames)!
			}
		}
		.filter {
			expr := c.expr or {
				return EvalError{ code: 'cx-err:CXER0001', message: ':where missing expr' }
			}
			pred := eval_node(expr, mut env)!
			// §9.2 / #348(a): an err-valued [where] guard unwinds as the
			// internal passthrough; eval_for_comp re-materialises it as the
			// comprehension's result.
			if is_err_value(pred) {
				return mk_guard_passthrough(pred)
			}
			ebv := node_ebv(pred) or { return mk_guard_passthrough(iterator_ebv_err()) }
			if ebv {
				collect_frames(clauses, idx + 1, barrier, mut env, mut frames)!
			}
		}
		.binding {
			expr := c.expr or {
				return EvalError{ code: 'cx-err:CXER0001', message: ':let missing expr' }
			}
			v := eval_node(expr, mut env)!
			mut next := env.clone_frame_sharing_closures() // #272 frame-sharing
			next.bindings[c.bind] = v
			collect_frames(clauses, idx + 1, barrier, mut next, mut frames)!
		}
		.limit, .par, .lazy, .ordered, .fail_fast {
			collect_frames(clauses, idx + 1, barrier, mut env, mut frames)!
		}
		.order_by, .group_by {
			// Nested barrier — bail; the outer loop handles this case
			// by re-finding barriers post-resume.
			collect_frames(clauses, idx + 1, barrier, mut env, mut frames)!
		}
		.take, .drop, .takewhile, .dropwhile {
			// applied post-collect in the buffered
			// path via apply_take_drop_post (count-based) or skipped
			// (predicated forms degrade to no-op in buffered path; if
			// users hit this combo the doc-gen catches it). No-op during
			// frame collection.
			collect_frames(clauses, idx + 1, barrier, mut env, mut frames)!
		}
	}
}

fn sort_keyed_frames(mut keyed []KeyedFrame, desc bool) {
	// Stable insertion sort — sizes are small (≤ source cardinality);
	// preserves source order on key ties.
	for i := 1; i < keyed.len; i++ {
		cur := keyed[i]
		mut j := i - 1
		for j >= 0 && frame_key_lt(cur.key, keyed[j].key, desc) {
			keyed[j + 1] = keyed[j]
			j--
		}
		keyed[j + 1] = cur
	}
}

fn frame_key_lt(a cx.Node, b cx.Node, desc bool) bool {
	res := node_compare(a, b)
	if desc { return res > 0 }
	return res < 0
}

// node_compare returns -1 / 0 / +1 ordering between two cx.Node values
// for sort purposes. Element values are compared by their canonical
// string render (stable, deterministic) when neither side is a scalar.
fn node_compare(a cx.Node, b cx.Node) int {
	if a is cx.ScalarNode && b is cx.ScalarNode {
		av := a.value
		bv := b.value
		match av {
			i64 {
				if bv is i64 {
					if av < bv { return -1 }
					if av > bv { return 1 }
					return 0
				}
				if bv is f64 {
					af := f64(av)
					if af < bv { return -1 }
					if af > bv { return 1 }
					return 0
				}
			}
			f64 {
				if bv is i64 {
					bf := f64(bv)
					if av < bf { return -1 }
					if av > bf { return 1 }
					return 0
				}
				if bv is f64 {
					if av < bv { return -1 }
					if av > bv { return 1 }
					return 0
				}
			}
			string {
				if bv is string {
					if av < bv { return -1 }
					if av > bv { return 1 }
					return 0
				}
			}
			bool {
				if bv is bool {
					if !av && bv { return -1 }
					if av && !bv { return 1 }
					return 0
				}
			}
			else {}
		}
	}
	// Element-vs-element or mixed: lift to string-form via the
	// element's first-child name/text, falling back to "" so ordering
	// stays total even on heterogeneous inputs.
	as_ := node_sort_key(a)
	bs := node_sort_key(b)
	if as_ < bs { return -1 }
	if as_ > bs { return 1 }
	return 0
}

fn node_sort_key(n cx.Node) string {
	// A §6.2 terminal-field unwrap of `[name Alice]` yields a TextNode;
	// `[order-by $u/name]` keys on it. Without this arm the key collapses
	// to '' for every frame and the sort is a no-op (program-for-005).
	if n is cx.TextNode {
		return n.value
	}
	if n is cx.ScalarNode {
		v := n.value
		match v {
			string { return v }
			i64    { return v.str() }
			f64    { return v.str() }
			bool   { return v.str() }
			else   { return '' }
		}
	}
	if n is cx.Element {
		// Use the first textual / scalar child as the sort key (e.g.
		// `[name Alice]` sorts on "Alice"). Falls back to element name.
		for it in n.items {
			if it is cx.ScalarNode {
				v := it.value
				if v is string { return v }
				if v is i64    { return v.str() }
				if v is f64    { return v.str() }
				if v is bool   { return v.str() }
			}
			if it is cx.TextNode {
				return it.value
			}
		}
		return n.name
	}
	return ''
}

// for_comp_streamable reports whether a top-level for-comprehension's
// clauses are all stream-friendly. Generator / filter / binding / limit
// stream naturally; the no-op concurrency clauses (par / stream /
// ordered) pass through. order_by / group_by require the
// full result list to apply (sort key extraction and group folding), so
// any for-comp containing those
// clauses falls back to one-shot evaluation in eval_code_streaming.
fn for_comp_streamable(clauses []cx.ProgramForClause) bool {
	for c in clauses {
		match c.kind {
			// order-by / group-by must see the whole result set before
			// emitting anything, so they can never stream.
			.order_by, .group_by { return false }
			// [par] is not a BUFFERING clause — it is a clause the
			// streamed evaluator does not implement. eval_for_comp
			// consults for_par_clause and runs the parallel walk;
			// eval_for_comp_streamed has no such branch and would run
			// the comprehension SEQUENTIALLY while reporting success.
			// The output bytes match, so the loss is silent: the
			// parallelism the author asked for simply does not happen
			// (and the CX_PAR_PEAK instrumentation disappears with it,
			// which is how this surfaced — routing the CLI through the
			// streaming call, #822).
			//
			// Claiming a shape the streamed path cannot honour is the
			// bug; refusing to claim it is the fix. These comprehensions
			// take the buffered path, keep their parallelism, and
			// eval_code_streamable reports them honestly as buffered.
			.par { return false }
			// Pattern-as-source (`[?for [user [email $e]] …]`): the
			// buffered path walks the implicit $doc via
			// generator_pattern_walk; run_for_clauses_streamed has no
			// such branch — its generator arm EVALUATES the source, and
			// eval_node on a ProgramPattern is CXER0001 by construction.
			// Every pattern-form comprehension crashed on the CLI once
			// #822 routed the run surface through the streaming call
			// (found by the profile gate's [bin] lane, 134 cases).
			// The walk is over an already-materialized $doc, so
			// streaming buys nothing here; decline honestly.
			.generator {
				if src := c.source {
					if src is cx.ProgramPattern { return false }
				}
			}
			else {}
		}
	}
	return true
}

// eval_for_comp_streamed mirrors `eval_for_comp` but routes each
// yielded value through `ctx` rather than accumulating into a result
// slice. The caller must have verified `for_comp_streamable(f.clauses)`
// — order_by / group_by are not handled here.
pub fn eval_for_comp_streamed(f cx.ProgramForComp, mut env MatchEnv, mut ctx StreamCtx) ! {
	// Frame-sharing clone (#272) — see eval_for_comp.
	mut frame := env.clone_frame_sharing_closures()
	// [limit] folds into the take bound inside build_for_limit_state (the
	// ruled L93 collapse, minimum wins) — the streamed path pre-W4 let a
	// [take] shadow every [limit], diverging from the buffered path.
	mut limit_state := build_for_limit_state(f.clauses, mut frame)!
	// bundle the yield-side configuration for the
	// streamed leaf evaluator. Outer shaping (sequence flatten / array
	// wrap / map entries) is replayed in the host's stream consumer; at
	// the leaf we emit one node per iteration shaped per yield form.
	spec := YieldSpec{
		expr:       f.yield
		value_expr: f.yield_value
		form:       f.yield_form
	}
	run_for_clauses_streamed(f.clauses, 0, spec, mut frame, mut ctx, mut limit_state)!
}

pub struct ForLimitState {
pub mut:
	remaining        int // -1 = unbounded; otherwise yields-left counter (take)
	drop_remaining   int // 0 = no skip; otherwise candidates-to-skip counter (drop)
	// predicated take/drop.
	takewhile_active bool          // true while :take-while predicate still holds (governs short-circuit)
	takewhile_pred   ?cx.ProgramNode  // predicate to evaluate per candidate (when active)
	dropwhile_active bool          // true while :drop-while predicate still skipping
	dropwhile_pred   ?cx.ProgramNode  // predicate to evaluate while active
}

// build_for_limit_state extracts take_n + drop_n + takewhile/dropwhile
// predicates from a clause list at for-comp entry. Used by both buffered
// and streamed paths.
//
// λ counts are EVALUATED here, once, in the enclosing scope (grammar
// [129j-l] admits any ProgramExpr as the count; the pre-W4 engine honored
// int literals only and silently no-opped every other count — a silent
// meaning change). A count must evaluate to a non-negative integer;
// anything else — non-integer, negative (previously a silent no-op via
// the n>=0 guard), err — is loud. [limit] folds into the take bound (the
// ruled L93 collapse: both truncate the relation, minimum wins;
// program-for-lambda-004/005/010 pin the composition), which also heals
// the streamed path's pre-W4 take-shadows-limit divergence.
fn build_for_limit_state(clauses []cx.ProgramForClause, mut env MatchEnv) !ForLimitState {
	mut s := ForLimitState{ remaining: -1, drop_remaining: 0 }
	for c in clauses {
		match c.kind {
			.take, .limit {
				expr := c.expr or { continue }
				clause_name := if c.kind == .limit { 'limit' } else { 'take' }
				n := eval_for_lambda_count(expr, clause_name, mut env)!
				// λ clauses COMPOSE (code.md §7.9, stream-2 W4): each
				// [take]/[limit] truncates the relation, so repeated
				// counts reduce to the MINIMUM — the pre-W4 last-wins
				// overwrite broke the ruled limit≡take collapse
				// (program-for-lambda-001/002 pin the composition).
				if s.remaining < 0 || n < s.remaining {
					s.remaining = n
				}
			}
			.drop {
				expr := c.expr or { continue }
				// Repeated [drop] skips SUM (composition —
				// program-for-lambda-003).
				s.drop_remaining += eval_for_lambda_count(expr, 'drop', mut env)!
			}
			.takewhile {
				// yield while predicate holds; stop at first failure.
				if expr := c.expr {
					s.takewhile_active = true
					s.takewhile_pred = expr
				}
			}
			.dropwhile {
				// skip while predicate holds; yield from first failure onward.
				if expr := c.expr {
					s.dropwhile_active = true
					s.dropwhile_pred = expr
				}
			}
			else {}
		}
	}
	return s
}

// eval_for_lambda_count evaluates one λ clause count expression to a
// non-negative int. An err value unwinds as the guard passthrough (the
// whole comprehension's err, §7.2); any other non-conforming value is a
// typed CXER0100 (the runtime clause-contract band, like §6.7's
// non-callable-f) — never a silent no-op.
fn eval_for_lambda_count(expr cx.ProgramNode, clause_name string, mut env MatchEnv) !int {
	// Int-literal fast path — the overwhelmingly common spelling.
	if expr is cx.ProgramLiteral && expr.kind == .int_lit {
		n := int(expr.int_val)
		if n < 0 {
			return EvalError{
				code:    'cx-err:CXER0100'
				message: 'a [${clause_name}] count must be a non-negative integer (got ${n})'
			}
		}
		return n
	}
	v := eval_node(expr, mut env)!
	if is_err_value(v) {
		return mk_guard_passthrough(v)
	}
	if v is cx.ScalarNode {
		val := v.value
		if val is i64 {
			if val < 0 {
				return EvalError{
					code:    'cx-err:CXER0100'
					message: 'a [${clause_name}] count must be a non-negative integer (got ${val})'
				}
			}
			return int(val)
		}
	}
	return EvalError{
		code:    'cx-err:CXER0100'
		message: 'a [${clause_name}] count must evaluate to a non-negative integer'
	}
}

fn run_for_clauses_streamed(clauses []cx.ProgramForClause, idx int, spec YieldSpec,
                             mut env MatchEnv, mut ctx StreamCtx,
                             mut limit_state ForLimitState) ! {
	// §10.5.4 iteration-boundary cancellation point — see run_for_clauses.
	if worker_cancel_pending(env) {
		return EvalError{ code: 'cx-err:CXER0260',
			message: 'cancellation observed at [?for] iteration boundary' }
	}
	if limit_state.remaining == 0 { return }
	if idx == clauses.len {
		// dropwhile skips candidates while predicate
		// holds; once it fails, flip off permanently.
		if limit_state.dropwhile_active {
			if dpred := limit_state.dropwhile_pred {
				pred_val := eval_node(dpred, mut env)!
				// §9.2 / #348(a): err-valued [drop-while] predicate → internal
				// passthrough (unwrapped at the streaming boundary).
				if is_err_value(pred_val) {
					return mk_guard_passthrough(pred_val)
				}
				debv := node_ebv(pred_val) or { return mk_guard_passthrough(iterator_ebv_err()) }
				if debv {
					return
				}
				limit_state.dropwhile_active = false
			}
		}
		// takewhile short-circuits at first predicate failure.
		if limit_state.takewhile_active {
			if tpred := limit_state.takewhile_pred {
				pred_val := eval_node(tpred, mut env)!
				// §9.2 / #348(a): err-valued [take-while] predicate propagates.
				if is_err_value(pred_val) {
					return mk_guard_passthrough(pred_val)
				}
				tebv := node_ebv(pred_val) or { return mk_guard_passthrough(iterator_ebv_err()) }
				if !tebv {
					limit_state.remaining = 0
					return
				}
			}
		}
		// drop skips first N candidates BEFORE :take counts.
		if limit_state.drop_remaining > 0 {
			limit_state.drop_remaining--
			return
		}
		// bind `$_position` to the 1-based OUTPUT index of
		// this surviving candidate before evaluating the yield body
		// (mirrors the buffered path; `ctx.n_emitted` counts items already
		// emitted, so `+ 1` is this item's position).
		if spec.needs_position {
			env.cow_bindings()
			env.bindings['_position'] = cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(i64(ctx.n_emitted + 1))
				data_type: .int_type
			})
		}
		result := eval_yield_leaf(spec, mut env)!
		ctx.emit_node(result)!
		if limit_state.remaining > 0 { limit_state.remaining-- }
		return
	}
	c := clauses[idx]
	match c.kind {
		.generator {
			src_node := c.source or {
				return EvalError{ code: 'cx-err:CXER0001', message: 'generator missing source' }
			}
			source_val := eval_for_source(src_node, mut env)!
			// open-end range incremental walk
			// (see run_for_clauses for the buffered-path twin).
			if source_val is cx.IteratorNode
				&& source_val.source_kind == .iter_range_open {
				has_terminator := limit_state.remaining >= 0
					|| limit_state.takewhile_active
				if has_terminator {
					iter_open_range_walk_streamed(source_val, c, clauses, idx,
					                               spec, mut env, mut ctx,
					                               mut limit_state)!
					return
				}
			}
			// Closure-driven generators (gen-reshape): iterate is known-infinite
			// (needs a terminator); unfold may stop on `()`.
			if source_val is cx.IteratorNode
				&& source_val.source_kind == .iter_iterate {
				if limit_state.remaining >= 0 || limit_state.takewhile_active {
					iter_iterate_walk_streamed(source_val, c, clauses, idx, spec,
					                            mut env, mut ctx, mut limit_state)!
					return
				}
			}
			if source_val is cx.IteratorNode
				&& source_val.source_kind == .iter_unfold {
				iter_unfold_walk_streamed(source_val, c, clauses, idx, spec,
				                           mut env, mut ctx, mut limit_state)!
				return
			}
			// SSE-client frames are the Ring-1 http-client pack's walk
			// (stdlib_http.v, seam H) — direct like iterate/unfold. Compiled
			// out with the pack (I4): the frame then falls through to the
			// registry probe below and refuses like any absent walker.
			$if !cx_no_pack_http_client ? {
				if source_val is cx.IteratorNode
					&& source_val.source_kind == .iter_sse_events {
					iter_sse_events_walk_streamed(source_val, c, clauses, idx, spec,
					                               mut env, mut ctx, mut limit_state)!
					return
				}
			}
			// I3: the live-source walkers (net accept / http accept /
			// net lines / chunks) are Ring 2 (iter_walks_net_http.v),
			// probed by source kind through the registry
			// (ring2_register.v).
			if source_val is cx.IteratorNode {
				if w := g_ring2_iter_walks_streamed[int(source_val.source_kind)] {
					w(source_val, c, clauses, idx, spec,
						mut env, mut ctx, mut limit_state)!
					return
				}
			}
			items := iterate(source_val)
			for item in items {
				if limit_state.remaining == 0 { return }
				mut next := env.clone_frame_sharing_closures()
				if expr_pat := c.expr {
					if expr_pat is cx.ProgramPattern {
						matched := match_pattern(expr_pat, item) or { continue }
						for k, v in matched.bindings {
							next.bindings[k] = v
						}
					}
				} else {
					next.bindings[c.bind] = item
				}
				run_for_clauses_streamed(clauses, idx + 1, spec, mut next,
				                          mut ctx, mut limit_state)!
			}
		}
		.filter {
			expr := c.expr or { return EvalError{ code: 'cx-err:CXER0001', message: ':where missing expr' } }
			pred := eval_node(expr, mut env)!
			// §9.2 / #348(a): err-valued [where] guard → internal passthrough
			// (unwrapped at the streaming boundary in api.v).
			if is_err_value(pred) {
				return mk_guard_passthrough(pred)
			}
			ebv := node_ebv(pred) or { return mk_guard_passthrough(iterator_ebv_err()) }
			if ebv {
				run_for_clauses_streamed(clauses, idx + 1, spec, mut env,
				                          mut ctx, mut limit_state)!
			}
		}
		.binding {
			expr := c.expr or { return EvalError{ code: 'cx-err:CXER0001', message: ':let missing expr' } }
			v := eval_node(expr, mut env)!
			mut next := env.clone_frame_sharing_closures()
			next.bindings[c.bind] = v
			run_for_clauses_streamed(clauses, idx + 1, spec, mut next,
			                          mut ctx, mut limit_state)!
		}
		.limit, .par, .lazy, .ordered, .take, .drop, .takewhile, .dropwhile, .fail_fast {
			// :take / :drop / :take-while / :drop-while semantics applied
			// at the yield boundary (see top of fn) via
			// build_for_limit_state's pre-pass. :fail-fast is a sequential
			// no-op by contract (§7.3).
			run_for_clauses_streamed(clauses, idx + 1, spec, mut env,
			                          mut ctx, mut limit_state)!
		}
		.order_by, .group_by {
			// Should have been routed to the materialising path by
			// for_comp_streamable; defensive fallthrough.
			run_for_clauses_streamed(clauses, idx + 1, spec, mut env,
			                          mut ctx, mut limit_state)!
		}
	}
}

// YieldSpec carries the yield-side configuration of a for-comp through
// the recursive pipeline. The `expr` is always present
// (sequence / array yield: the value; map yield: the key expression).
// `value_expr` is set only for `:yield-map K => V`.
//
// `form` controls how the leaf evaluator shapes the yielded result:
//   * .sequence : append the value directly (outer-flatten happens in
//                 eval_for_comp's post-shape pass).
//   * .array    : leaf result wrapped as a `__cx_arr__` element so the
//                 outer post-shape pass preserves Array semantics.
//   * .map      : leaf builds a map-entry element
//                 `Element{ name: <stringified-key>, items: [<value>] }`
//                 matching eval_map's representation.
pub struct YieldSpec {
	expr       cx.ProgramNode
	value_expr ?cx.ProgramNode
	form       cx.ProgramForCompYieldForm
	// needs_position gates the per-item `$_position` binding (#804 leg 6).
	//
	// Binding it costs a ScalarNode allocation plus a map insert on EVERY
	// surviving candidate, and `$_position` is only observable if the
	// program mentions it — it is a reserved binding that raises CXER0231
	// outside a predicate body, so it cannot arrive from anywhere else.
	//
	// DEFAULT TRUE so every existing caller keeps binding it unconditionally.
	// Only the streamed-input fast path lowers it, and only after the same
	// conservative whole-source scan it already uses for `$doc`/`$input`:
	// if the spelling appears anywhere in the program text we bind, so an
	// over-match costs an allocation and never an answer.
	needs_position bool = true
}

// eval_yield_leaf computes the yielded cx.Node for one for-comp
// iteration per the YieldSpec form.
fn eval_yield_leaf(spec YieldSpec, mut env MatchEnv) !cx.Node {
	if spec.form == .map {
		ve := spec.value_expr or {
			return EvalError{
				code:    'cx-err:CXER0001'
				message: ':yield-map missing value expression'
			}
		}
		key := eval_node(spec.expr, mut env)!
		val := eval_node(ve, mut env)!
		key_str := xpath_string_value(key)
		return cx.Element{
			name:  key_str
			items: [val]
		}
	}
	return eval_node(spec.expr, mut env)!
}

// apply_take_drop_post applies :take / :drop to a pre-collected result
// list. Used by the buffered path (after :order-by / :group-by).
fn apply_take_drop_post(state ForLimitState, mut out []cx.Node) {
	if state.drop_remaining > 0 && out.len > 0 {
		mut to_drop := state.drop_remaining
		if to_drop > out.len { to_drop = out.len }
		out = out[to_drop..].clone()
	}
	if state.remaining >= 0 && out.len > state.remaining {
		for out.len > state.remaining { out.delete_last() }
	}
}

fn run_for_clauses(clauses []cx.ProgramForClause, idx int, spec YieldSpec,
                    mut env MatchEnv, mut out []cx.Node, mut limit_state ForLimitState) ! {
	// §10.5.4: [?for] observes cancellation at every iteration boundary.
	// Every generator walk (materialised items, open-range, iterate, unfold,
	// net-accept, …) re-enters run_for_clauses once per item, so this single
	// check covers them all. Only a concurrent [?worker] body carries the
	// signal (env.current_worker); everywhere else this is a nil-check no-op.
	if worker_cancel_pending(env) {
		return EvalError{ code: 'cx-err:CXER0260',
			message: 'cancellation observed at [?for] iteration boundary' }
	}
	// short-circuit when :take quota is reached.
	if limit_state.remaining == 0 { return }
	if idx == clauses.len {
		// `$_position` inside a `[?for]` yield body names
		// the 1-based OUTPUT index of the item being yielded. `out` holds
		// the items emitted so far (post-:where, post-:drop, post-:take),
		// so `out.len + 1` is the position this item WILL occupy. Bind it
		// before any yield path runs; filtered/dropped candidates return
		// earlier (below) and never reach here, so they don't advance the
		// counter — exactly the OUTPUT-index semantics OQ1 requires.
		// NOTE: the :drop-while / :take-while / :drop short-circuits below
		// may still return before the yield, so we bind only once we know
		// this candidate survives — see the bind site just before
		// eval_yield_leaf. (Binding early would over-count if a later
		// guard rejects.)
		// dropwhile skips candidates while predicate
		// holds; once it fails, flip off permanently and yield this AND
		// all subsequent candidates.
		if limit_state.dropwhile_active {
			if dpred := limit_state.dropwhile_pred {
				pred_val := eval_node(dpred, mut env)!
				// §9.2 / #348(a): err-valued [drop-while] predicate → internal
				// passthrough (unwrapped at eval_for_comp).
				if is_err_value(pred_val) {
					return mk_guard_passthrough(pred_val)
				}
				debv := node_ebv(pred_val) or { return mk_guard_passthrough(iterator_ebv_err()) }
				if debv {
					return
				}
				limit_state.dropwhile_active = false
			}
		}
		// takewhile yields while predicate holds; at
		// first failure, short-circuit the entire comprehension.
		if limit_state.takewhile_active {
			if tpred := limit_state.takewhile_pred {
				pred_val := eval_node(tpred, mut env)!
				// §9.2 / #348(a): err-valued [take-while] predicate propagates.
				if is_err_value(pred_val) {
					return mk_guard_passthrough(pred_val)
				}
				tebv := node_ebv(pred_val) or { return mk_guard_passthrough(iterator_ebv_err()) }
				if !tebv {
					limit_state.remaining = 0
					return
				}
			}
		}
		// drop skips first N candidates BEFORE :take counts.
		if limit_state.drop_remaining > 0 {
			limit_state.drop_remaining--
			return
		}
		// this candidate has survived every guard and WILL
		// be emitted, so `$_position` now resolves to its 1-based OUTPUT
		// index: `out.len + 1` (out holds the items emitted before this
		// one). `env` here is the terminal per-iteration frame, so mutating
		// it in place is safe — the caller re-clones per generator item.
		env.cow_bindings()
		env.bindings['_position'] = cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(i64(out.len + 1))
			data_type: .int_type
		})
		// Per-iteration error handling is a yield-body [?match]
		// (spec §9.3; [on-error] retired — SAP C3c).
		out << eval_yield_leaf(spec, mut env)!
		if limit_state.remaining > 0 { limit_state.remaining-- }
		return
	}
	c := clauses[idx]
	match c.kind {
		.generator {
			src_node := c.source or {
				return EvalError{ code: 'cx-err:CXER0001', message: 'generator missing source' }
			}
			// Pattern-as-source form: `[?for [pattern] :yield X]` — sugar
			// for "walk the implicit doc, match-and-bind per pattern,
			// continue downstream per match". Spec §7 multi-source +
			// pattern-generator semantics.
			if src_node is cx.ProgramPattern {
				doc := env.bindings['doc'] or {
					return EvalError{
						code:    'cx-err:CXER0001'
						message: '[?for] pattern-as-source requires $doc'
					}
				}
				generator_pattern_walk(src_node, doc, clauses, idx, spec,
				                       mut env, mut out, mut limit_state)!
				return
			}
			source_val := eval_for_source(src_node, mut env)!
			// open-end range needs an incremental
			// walk gated by a terminator (`:take` / `:take-while`). The
			// usual `iterate(source_val)` path would force the
			// iterator to full materialisation; pull_iterator_to_end
			// then surfaces a CXER0100 err-element. When the for-comp
			// HAS a terminator we instead emit one item at a time and
			// let the downstream clauses + limit_state short-circuit.
			if source_val is cx.IteratorNode
				&& source_val.source_kind == .iter_range_open {
				has_terminator := limit_state.remaining >= 0
					|| limit_state.takewhile_active
				if has_terminator {
					iter_open_range_walk(source_val, c, clauses, idx, spec,
					                      mut env, mut out, mut limit_state)!
					return
				}
				// No terminator — fall through to the iterate() path
				// so the CXER0100 err-element flows through the normal
				// yield pipeline (matches `range(_, _, 0)` step-zero
				// emit pattern).
			}
			if source_val is cx.IteratorNode
				&& source_val.source_kind == .iter_iterate {
				if limit_state.remaining >= 0 || limit_state.takewhile_active {
					iter_iterate_walk(source_val, c, clauses, idx, spec,
					                   mut env, mut out, mut limit_state)!
					return
				}
			}
			if source_val is cx.IteratorNode
				&& source_val.source_kind == .iter_unfold {
				iter_unfold_walk(source_val, c, clauses, idx, spec,
				                  mut env, mut out, mut limit_state)!
				return
			}
			// SSE-client frames are the Ring-1 http-client pack's walk
			// (stdlib_http.v, seam H) — direct like iterate/unfold. Compiled
			// out with the pack (I4): the frame then falls through to the
			// registry probe below and refuses like any absent walker.
			$if !cx_no_pack_http_client ? {
				if source_val is cx.IteratorNode
					&& source_val.source_kind == .iter_sse_events {
					iter_sse_events_walk(source_val, c, clauses, idx, spec,
					                      mut env, mut out, mut limit_state)!
					return
				}
			}
			// I3: the live-source walkers (net accept / http accept /
			// net lines / chunks) are Ring 2 (iter_walks_net_http.v),
			// probed by source kind through the registry
			// (ring2_register.v).
			if source_val is cx.IteratorNode {
				if w := g_ring2_iter_walks[int(source_val.source_kind)] {
					w(source_val, c, clauses, idx, spec,
						mut env, mut out, mut limit_state)!
					return
				}
			}
			// Batch [?for] over tables (stream 17 W2, #710 item 7): a
			// :table source walks its rows ONE AT A TIME — each row map
			// (the D22 view, 1+2M boxes) is built only when its
			// iteration runs, so a :take/:where short-circuit stops
			// construction instead of paying N(1+2M) up front. The row
			// SHAPE is byte-identical to table_row_maps (transparency).
			if source_val is cx.Element {
				if td := source_val.table_opt() {
					for row_idx in 0 .. td.rows.len {
						if limit_state.remaining == 0 { return }
						item := table_row_map_at(td, row_idx)
						mut next := env.clone_frame_sharing_closures()
						if expr_pat := c.expr {
							if expr_pat is cx.ProgramPattern {
								matched := match_pattern(expr_pat, item) or { continue }
								for k, v in matched.bindings {
									next.bindings[k] = v
								}
							}
						} else {
							next.bindings[c.bind] = item
						}
						run_for_clauses(clauses, idx + 1, spec, mut next, mut out, mut limit_state)!
					}
					return
				}
			}
			// (iterate() itself forces combinator chains through the
			// EV-PULL state hook; statically-infinite unterminated
			// sources keep their classic refusal shape through it.)
			items := iterate(source_val)
			for item in items {
				mut next := env.clone_frame_sharing_closures()
				if expr_pat := c.expr {
					// Destructuring generator: pattern-match each item.
					if expr_pat is cx.ProgramPattern {
						matched := match_pattern(expr_pat, item) or { continue }
						for k, v in matched.bindings {
							next.bindings[k] = v
						}
					}
				} else {
					next.bindings[c.bind] = item
				}
				run_for_clauses(clauses, idx + 1, spec, mut next, mut out, mut limit_state)!
				if limit_state.remaining == 0 { return }
			}
		}
		.filter {
			expr := c.expr or { return EvalError{ code: 'cx-err:CXER0001', message: ':where missing expr' } }
			pred := eval_node(expr, mut env)!
			// §9.2 / #348(a): err-valued [where] guard → internal passthrough
			// (unwrapped at eval_for_comp; par workers forward the cause
			// verbatim over the ParListResult channel).
			if is_err_value(pred) {
				return mk_guard_passthrough(pred)
			}
			ebv := node_ebv(pred) or { return mk_guard_passthrough(iterator_ebv_err()) }
			if ebv {
				run_for_clauses(clauses, idx + 1, spec, mut env, mut out, mut limit_state)!
			}
		}
		.binding {
			expr := c.expr or { return EvalError{ code: 'cx-err:CXER0001', message: ':let missing expr' } }
			v := eval_node(expr, mut env)!
			mut next := env.clone_frame_sharing_closures()
			next.bindings[c.bind] = v
			run_for_clauses(clauses, idx + 1, spec, mut next, mut out, mut limit_state)!
		}
		.order_by {
			// Materialise: collect frames from the upstream pipeline
			// (sub-clauses 0..idx have already populated `env` for this
			// invocation, but the generator above re-invokes us per
			// item — so we shunt each incoming frame into a buffer via
			// the order_by accumulator routed by eval_for_comp_buffered).
			// At this point we're already past the generator; the simplest
			// path is to use a thread-side accumulator. See the order_by
			// frame-buffer machinery in run_order_by_collect.
			// Sentinel: this branch is only reached when neither order_by
			// nor group_by has been routed via the buffered path. We
			// preserve source order as fallback.
			run_for_clauses(clauses, idx + 1, spec, mut env, mut out, mut limit_state)!
		}
		.group_by {
			run_for_clauses(clauses, idx + 1, spec, mut env, mut out, mut limit_state)!
		}
		.limit {
			// folded into the take bound at build_for_limit_state (the
			// ruled L93 collapse); the clause itself is a no-op in
			// pipeline order.
			run_for_clauses(clauses, idx + 1, spec, mut env, mut out, mut limit_state)!
		}
		.par, .lazy, .ordered, .fail_fast {
			// Phase 3 cooperative-scheduler substrate does not provide
			// real parallelism or lazy materialisation; we honour the
			// surface grammar (so visualization fixtures parse + render
			// round-trip) and fall through to sequential evaluation.
			// Real `:par` / `:stream` semantics land behind
			// `[?test-concurrent]` (deterministic harness) or
			// the production runtime. See spec/code.md §7.3-7.4.
			run_for_clauses(clauses, idx + 1, spec, mut env, mut out, mut limit_state)!
		}
		.take, .drop, .takewhile, .dropwhile {
			// applied at the yield boundary via
			// build_for_limit_state's pre-pass + generator-loop
			// short-circuit. The clause itself is a no-op in pipeline
			// order.
			run_for_clauses(clauses, idx + 1, spec, mut env, mut out, mut limit_state)!
		}
	}
}

// generator_pattern_walk recursively walks `val` matching `pat`. Each
// match contributes its bindings to a fresh frame and the for-comp
// continues with the next clause.
fn generator_pattern_walk(pat cx.ProgramPattern, val cx.Node,
                           clauses []cx.ProgramForClause, idx int,
                           spec YieldSpec,
                           mut env MatchEnv, mut out []cx.Node,
                           mut limit_state ForLimitState) ! {
	if limit_state.remaining == 0 { return }
	if matched := match_pattern(pat, val) {
		mut snap := env.clone_frame_sharing_closures()
		for k, v in matched.bindings {
			snap.bindings[k] = v
		}
		run_for_clauses(clauses, idx + 1, spec, mut snap, mut out, mut limit_state)!
	}
	if val is cx.Element {
		for child in val.items {
			if limit_state.remaining == 0 { return }
			generator_pattern_walk(pat, child, clauses, idx, spec,
			                        mut env, mut out, mut limit_state)!
		}
	}
}

fn collect_frames_pattern_walk(pat cx.ProgramPattern, val cx.Node,
                                clauses []cx.ProgramForClause, idx int, barrier int,
                                mut env MatchEnv, mut frames []MatchEnv) ! {
	if matched := match_pattern(pat, val) {
		mut snap := env.clone_frame_sharing_closures() // #272 frame-sharing
		for k, v in matched.bindings {
			snap.bindings[k] = v
		}
		collect_frames(clauses, idx + 1, barrier, mut snap, mut frames)!
	}
	if val is cx.Element {
		for child in val.items {
			collect_frames_pattern_walk(pat, child, clauses, idx, barrier,
			                              mut env, mut frames)!
		}
	}
}

// iterate_pub is the public wrapper around the private `iterate()`
// helper. Exported so unit tests (and W3c follow-up combinators
// hosted in sibling modules) can drive iterator materialization
// without pulling the entire eval/match machinery..
pub fn iterate_pub(n cx.Node) []cx.Node {
	return iterate(n)
}

// nodes_equal_pub is the public wrapper around `nodes_equal()`. Used
// by unit tests asserting (IteratorNode identity-only
// equality) without forcing tests to reimplement the predicate.
pub fn nodes_equal_pub(a cx.Node, b cx.Node) bool {
	return nodes_equal(a, b)
}

// render_node_pub is the public surface for `render_node()`. Lets
// unit tests render an arbitrary Node to canonical string form
// (paren-comma sequences, bracket-comma arrays, etc.) without
// recreating the renderer.
pub fn render_node_pub(n cx.Node) string {
	return render_node(n)
}

pub fn iterate(n cx.Node) []cx.Node {
	if n is cx.Element {
		// Sequence / Array envelopes expand to their items: positional
		// access and the §6.5 sequence built-ins are properties of
		// orderedness, not representation — an `__cx_arr__` source is
		// iterated transparently (code.md §6.6 "Array sources work
		// transparently"), matching `materialize_to_items` and the
		// `cx.ArrayNode` branch below. Maps are NOT expanded here (no
		// positional axis; slice/nth over a map is rejected upstream).
		if n.name == '' || n.name == seq_marker_name || n.name == arr_marker_name {
			return n.items
		}
		// Table sequence view (D22, #404): a `:table`-bearing element
		// iterates as its ROW SEQUENCE — one ordered `__cx_map__` per row.
		// This is what makes `[in $r $t]`, `$t[…]`, and `[$count $t]` see
		// rows instead of one opaque leaf. CXPath is untouched (rows are
		// not CXDM children).
		if td := n.table_opt() {
			return table_row_maps(td)
		}
		return [n]
	}
	// SequenceNode / ArrayNode are already eager — iterate over their items.
	if n is cx.SequenceNode {
		return n.items
	}
	if n is cx.ArrayNode {
		return n.items
	}
	// IteratorNode — lazy + memoized. If already exhausted,
	// return the memo as-is. Otherwise pull from the source generator
	// (W3a supports `iter_range`; W3c grafts the combinator family).
	// Mutation through the IteratorNode reference relies on V's heap-
	// allocated sum-variant semantics (`@[heap]` IteratorNode); the
	// memo grows in place so subsequent pulls return the same items.
	if n is cx.IteratorNode {
		if n.exhausted {
			// single-use iterator second-walk guard.
			// `single_use = true` marks intrinsically non-rewindable
			// sources (future: HTTP response bodies, file lines, channel
			// reads); once the first consumer drained the source the memo
			// snapshot is no longer a valid replay target for a second
			// walker. Surface CXER0105 as a renderable err-element so the
			// caller sees the violation in-band. Multi-use iterators
			// (all current sources except the [?test-single-use-iter]
			// scaffold) skip this branch — their exhausted memo replays
			// freely. See; W4-C wiring.
			if n.single_use {
				return [mk_err('cx-err:CXER0105',
					'single-use iterator already walked — second walk is not permitted')]
			}
			return n.memo.clone()
		}
		mut iter := unsafe { &cx.IteratorNode(&n) }
		// EV-PULL (stream 17 W1): combinator kinds force through the
		// demand-driven pull core with a state-built env (their
		// transform closures are parked in the state registry) — the
		// env-free classic walker keeps the generator/live kinds.
		if iter_is_pull_kind(iter.source_kind) && g_iter_pull_state != unsafe { nil } {
			state := unsafe { &ProgramState(g_iter_pull_state) }
			if pulled := iter_force_via_state(mut iter, state) {
				return pulled
			}
			return iter.memo.clone()
		}
		pulled := pull_iterator_to_end(mut iter) or {
			// On pull failure return whatever the memo already holds
			// (typically empty for a never-pulled iterator).
			return iter.memo.clone()
		}
		return pulled
	}
	return [n]
}

// mk_eager_iterator constructs an IteratorNode pre-populated with the
// supplied items and marks it exhausted. Combinator directives
// ([?map] / [?filter] / [?take] / [?drop] / [?zip] / [?enumerate] /
// [?chunks] / [?concat] / [?chain] / [?cycle] / [?scan] / [?flatten] /
// [?partition] / [?group-by]) use this to satisfy 
// "combinators return Iterator" type contract while preserving the
// directive-time evaluation that gives closures access to the live
// MatchEnv.
//
// True end-to-end laziness across combinator chains (e.g. `[?take 5
// [?map ...]]` pulling only 5 items from the source) requires
// threading the closure table through `iterate()` — that lives in a
// follow-up milestone. For W3c the contract is honoured at the value-
// kind level: every combinator returns an IteratorNode, host-boundary
// emitters materialise via `iterator_to_sequence()`, and downstream
// consumers see the items via the standard `iterate()` path.
fn mk_eager_iterator(source_kind cx.IteratorSourceKind, source_args []cx.Node, items []cx.Node) cx.Node {
	return cx.Node(cx.IteratorNode{
		source_kind: source_kind
		source_args: source_args
		memo:        items.clone()
		exhausted:   true
		single_use:  false
	})
}

// iter_open_range_walk incremental walker for
// `iter_range_open` sources inside a `[?for]` comprehension that
// carries a `:take` / `:take-while` terminator. Emits one integer at
// a time, binding the for-comp's loop variable and re-entering the
// clause pipeline; the existing `limit_state` short-circuits on
// `:take N` (decrements `remaining`) and on `:take-while P`
// (downstream clause flips `remaining = 0` at first failure). Per
// D19 the caller has already verified a terminator exists.
//
// `source_val.source_args` is [start] or [start, step]; defaults to
// step=1. Step-of-zero was rejected at range-builtin construction
// time (mirrors D21) so this walker may assume non-zero step.
fn iter_open_range_walk(source_val cx.IteratorNode, c cx.ProgramForClause,
                         clauses []cx.ProgramForClause, idx int, spec YieldSpec,
                         mut env MatchEnv, mut out []cx.Node,
                         mut limit_state ForLimitState) ! {
	if source_val.source_args.len < 1 || source_val.source_args.len > 2 {
		return
	}
	start := scalar_int(source_val.source_args[0]) or { return }
	mut step := i64(1)
	if source_val.source_args.len == 2 {
		step = scalar_int(source_val.source_args[1]) or { return }
		if step == 0 { return }
	}
	mut i := start
	for {
		if limit_state.remaining == 0 { return }
		item := cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(i)
			data_type: cx.ScalarType.int_type
		})
		mut next := env.clone_frame_sharing_closures() // #272 frame-sharing
		if expr_pat := c.expr {
			if expr_pat is cx.ProgramPattern {
				if matched := match_pattern(expr_pat, item) {
					for k, v in matched.bindings {
						next.bindings[k] = v
					}
					run_for_clauses(clauses, idx + 1, spec, mut next, mut out, mut limit_state)!
				}
			}
		} else {
			next.bindings[c.bind] = item
			run_for_clauses(clauses, idx + 1, spec, mut next, mut out, mut limit_state)!
		}
		i += step
	}
}

// iter_open_range_walk_streamed — twin of iter_open_range_walk for
// the streaming for-comp path. See iter_open_range_walk for the
// rationale; behaviour differs only in that yields flow through
// `ctx.emit_node` via run_for_clauses_streamed.
fn iter_open_range_walk_streamed(source_val cx.IteratorNode, c cx.ProgramForClause,
                                  clauses []cx.ProgramForClause, idx int, spec YieldSpec,
                                  mut env MatchEnv, mut ctx StreamCtx,
                                  mut limit_state ForLimitState) ! {
	if source_val.source_args.len < 1 || source_val.source_args.len > 2 {
		return
	}
	start := scalar_int(source_val.source_args[0]) or { return }
	mut step := i64(1)
	if source_val.source_args.len == 2 {
		step = scalar_int(source_val.source_args[1]) or { return }
		if step == 0 { return }
	}
	mut i := start
	for {
		if limit_state.remaining == 0 { return }
		item := cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(i)
			data_type: cx.ScalarType.int_type
		})
		mut next := env.clone_frame_sharing_closures() // #272 frame-sharing
		if expr_pat := c.expr {
			if expr_pat is cx.ProgramPattern {
				if matched := match_pattern(expr_pat, item) {
					for k, v in matched.bindings {
						next.bindings[k] = v
					}
					run_for_clauses_streamed(clauses, idx + 1, spec, mut next,
					                          mut ctx, mut limit_state)!
				}
			}
		} else {
			next.bindings[c.bind] = item
			run_for_clauses_streamed(clauses, idx + 1, spec, mut next,
			                          mut ctx, mut limit_state)!
		}
		i += step
	}
}

// ── Closure-driven generator walkers (gen-reshape: iterate / unfold) ──
// gen_emit_item binds one generated item into the for-comp frame and runs the
// downstream clause pipeline (non-streamed path). Mirrors the inline emit in
// iter_open_range_walk; factored out for the iterate / unfold walkers.
pub fn gen_emit_item(c cx.ProgramForClause, item cx.Node, clauses []cx.ProgramForClause,
                  idx int, spec YieldSpec, mut env MatchEnv, mut out []cx.Node,
                  mut limit_state ForLimitState) ! {
	mut next := env.clone_frame_sharing_closures() // #272 frame-sharing
	if expr_pat := c.expr {
		if expr_pat is cx.ProgramPattern {
			if matched := match_pattern(expr_pat, item) {
				for k, v in matched.bindings {
					next.bindings[k] = v
				}
				run_for_clauses(clauses, idx + 1, spec, mut next, mut out, mut limit_state)!
			}
		}
	} else {
		next.bindings[c.bind] = item
		run_for_clauses(clauses, idx + 1, spec, mut next, mut out, mut limit_state)!
	}
}

// gen_emit_item_streamed — streamed twin of gen_emit_item.
pub fn gen_emit_item_streamed(c cx.ProgramForClause, item cx.Node, clauses []cx.ProgramForClause,
                           idx int, spec YieldSpec, mut env MatchEnv, mut ctx StreamCtx,
                           mut limit_state ForLimitState) ! {
	mut next := env.clone_frame_sharing_closures() // #272 frame-sharing
	if expr_pat := c.expr {
		if expr_pat is cx.ProgramPattern {
			if matched := match_pattern(expr_pat, item) {
				for k, v in matched.bindings {
					next.bindings[k] = v
				}
				run_for_clauses_streamed(clauses, idx + 1, spec, mut next, mut ctx, mut limit_state)!
			}
		}
	} else {
		next.bindings[c.bind] = item
		run_for_clauses_streamed(clauses, idx + 1, spec, mut next, mut ctx, mut limit_state)!
	}
}

// iter_iterate_walk — incremental walker for [$iterate f seed] inside a [?for]
// carrying a [take]/[take-while] terminator. Emits seed, f(seed), f(f(seed)),
// … applying the closure once per pull. The terminator (limit_state) bounds it;
// the force budget is a runaway backstop. f is validated callable at the
// builtin handler, so an err only arises from a body raise (its err value
// becomes that element, then iteration stops — railway, §1.4).
fn iter_iterate_walk(source_val cx.IteratorNode, c cx.ProgramForClause,
                      clauses []cx.ProgramForClause, idx int, spec YieldSpec,
                      mut env MatchEnv, mut out []cx.Node,
                      mut limit_state ForLimitState) ! {
	if source_val.source_args.len != 2 { return }
	f_val := source_val.source_args[0]
	mut cur := source_val.source_args[1]
	for _ in 0 .. generator_force_budget {
		if limit_state.remaining == 0 { return }
		gen_emit_item(c, cur, clauses, idx, spec, mut env, mut out, mut limit_state)!
		if is_err_value(cur) { return }
		cur = apply_fn_value(f_val, [cur], mut env)!
	}
}

fn iter_iterate_walk_streamed(source_val cx.IteratorNode, c cx.ProgramForClause,
                               clauses []cx.ProgramForClause, idx int, spec YieldSpec,
                               mut env MatchEnv, mut ctx StreamCtx,
                               mut limit_state ForLimitState) ! {
	if source_val.source_args.len != 2 { return }
	f_val := source_val.source_args[0]
	mut cur := source_val.source_args[1]
	for _ in 0 .. generator_force_budget {
		if limit_state.remaining == 0 { return }
		gen_emit_item_streamed(c, cur, clauses, idx, spec, mut env, mut ctx, mut limit_state)!
		if is_err_value(cur) { return }
		cur = apply_fn_value(f_val, [cur], mut env)!
	}
}

// iter_unfold_walk — incremental walker for [$unfold f seed] inside a [?for].
// f is applied to the current state and returns () (stop) or a 2-element
// [value, next-state] Array; emit value, recurse on next-state. The budget
// backstops an unbounded unfold; [take] bounds it earlier.
fn iter_unfold_walk(source_val cx.IteratorNode, c cx.ProgramForClause,
                     clauses []cx.ProgramForClause, idx int, spec YieldSpec,
                     mut env MatchEnv, mut out []cx.Node,
                     mut limit_state ForLimitState) ! {
	if source_val.source_args.len != 2 { return }
	f_val := source_val.source_args[0]
	mut state := source_val.source_args[1]
	for _ in 0 .. generator_force_budget {
		if limit_state.remaining == 0 { return }
		res := apply_fn_value(f_val, [state], mut env)!
		if is_err_value(res) {
			gen_emit_item(c, res, clauses, idx, spec, mut env, mut out, mut limit_state)!
			return
		}
		if is_empty_seq(res) { return }
		val, nxt := unfold_pair(res) or {
			gen_emit_item(c, mk_err('cx-err:CXER0100',
				'unfold: f must return () or a 2-element [value, next-state] array'),
				clauses, idx, spec, mut env, mut out, mut limit_state)!
			return
		}
		gen_emit_item(c, val, clauses, idx, spec, mut env, mut out, mut limit_state)!
		state = nxt
	}
}

fn iter_unfold_walk_streamed(source_val cx.IteratorNode, c cx.ProgramForClause,
                              clauses []cx.ProgramForClause, idx int, spec YieldSpec,
                              mut env MatchEnv, mut ctx StreamCtx,
                              mut limit_state ForLimitState) ! {
	if source_val.source_args.len != 2 { return }
	f_val := source_val.source_args[0]
	mut state := source_val.source_args[1]
	for _ in 0 .. generator_force_budget {
		if limit_state.remaining == 0 { return }
		res := apply_fn_value(f_val, [state], mut env)!
		if is_err_value(res) {
			gen_emit_item_streamed(c, res, clauses, idx, spec, mut env, mut ctx, mut limit_state)!
			return
		}
		if is_empty_seq(res) { return }
		val, nxt := unfold_pair(res) or {
			gen_emit_item_streamed(c, mk_err('cx-err:CXER0100',
				'unfold: f must return () or a 2-element [value, next-state] array'),
				clauses, idx, spec, mut env, mut ctx, mut limit_state)!
			return
		}
		gen_emit_item_streamed(c, val, clauses, idx, spec, mut env, mut ctx, mut limit_state)!
		state = nxt
	}
}

// realize_unfold force-realizes a standalone [$unfold f seed] to a finite
// Sequence (eval()'s finalize path, where the live env is available). Runs f
// until it returns () (stop), bounded by the host force budget (CXER0100 on
// exhaustion — never a hang). An err returned by f becomes the last element
// (railway, §1.4); a malformed result is CXER0100.
fn realize_unfold(iter cx.IteratorNode, mut env MatchEnv) cx.Node {
	if iter.source_args.len != 2 {
		return mk_err('cx-err:CXER0100', 'unfold: malformed generator')
	}
	f_val := iter.source_args[0]
	mut state := iter.source_args[1]
	mut items := []cx.Node{}
	for _ in 0 .. generator_force_budget {
		res := apply_fn_value(f_val, [state], mut env) or {
			return mk_err('cx-err:CXER0100', 'unfold: ${err.msg()}')
		}
		if is_err_value(res) {
			items << res
			return cx.Node(cx.Element{ name: seq_marker_name, items: items })
		}
		if is_empty_seq(res) {
			return cx.Node(cx.Element{ name: seq_marker_name, items: items })
		}
		val, nxt := unfold_pair(res) or {
			return mk_err('cx-err:CXER0100',
				'unfold: f must return () or a 2-element [value, next-state] array')
		}
		items << val
		state = nxt
	}
	return mk_err('cx-err:CXER0100', 'generator exceeded force budget')
}

// is_empty_seq reports whether `n` is the empty sequence `()` — the [$unfold]
// stop signal (the absence channel; CXDM §1).
fn is_empty_seq(n cx.Node) bool {
	if n is cx.Element {
		return (n.name == '' || n.name == seq_marker_name) && n.items.len == 0
	}
	if n is cx.SequenceNode {
		return n.items.len == 0
	}
	return false
}

// unfold_pair destructures an [$unfold] step result: a 2-element Array
// [value, next-state] (N-GEN-2 — an Array, never a sequence). Returns none for
// any other shape (caller raises CXER0100 malformed-step).
fn unfold_pair(n cx.Node) ?(cx.Node, cx.Node) {
	if n is cx.Element {
		if n.name == arr_marker_name && n.items.len == 2 {
			return n.items[0], n.items[1]
		}
	}
	if n is cx.ArrayNode {
		if n.items.len == 2 {
			return n.items[0], n.items[1]
		}
	}
	return none
}

// pull_iterator_to_end exhausts the iterator's source generator,
// appending every produced item to `iter.memo` and flipping
// `iter.exhausted = true`. Returns the freshly-pulled item list (a
// clone of memo) on success. Returns `none` if the source kind is
// not yet supported (W3a only handles `iter_range`; the combinator
// kinds land in W3c).
//
// Per the materialization is force-eager — the iterator
// fully drains its source rather than yielding incrementally. W3c
// pivots to incremental pull for combinator chains (so a `[?take 5]`
// over an infinite source doesn't loop), but W3a's only source kind
// (`range`) is bounded so eager pull is correct.
//
// single-use capability is enforced at the `iterate()`
// wrapper rather than here, because `iterate()` short-circuits exhausted
// iterators before reaching this dispatch (so the second walk never
// makes it to `pull_iterator_to_end`). See the `single_use` branch
// inside `iterate()` for the CXER0105 surface.
fn pull_iterator_to_end(mut iter cx.IteratorNode) ?[]cx.Node {
	match iter.source_kind {
		.iter_range {
			// `iter_range` source_args is [start, end, step] — already
			// evaluated to ScalarNodes at construction time. Reuse the
			// `range` builtin's expansion logic so step / direction /
			// inclusive-end semantics stay identical.
			if iter.source_args.len < 2 || iter.source_args.len > 3 {
				return none
			}
			start := scalar_int(iter.source_args[0]) or { return none }
			end := scalar_int(iter.source_args[1]) or { return none }
			mut step := i64(1)
			if iter.source_args.len == 3 {
				step = scalar_int(iter.source_args[2]) or { return none }
				if step == 0 { return none }
			}
			// D20 — empty when direction disagrees with step.
			if step > 0 && end < start {
				iter.exhausted = true
				return iter.memo.clone()
			}
			if step < 0 && end > start {
				iter.exhausted = true
				return iter.memo.clone()
			}
			mut i := start
			if step > 0 {
				for i <= end {
					iter.memo << cx.Node(cx.ScalarNode{
						value:     cx.ScalarValue(i)
						data_type: cx.ScalarType.int_type
					})
					i += step
				}
			} else {
				for i >= end {
					iter.memo << cx.Node(cx.ScalarNode{
						value:     cx.ScalarValue(i)
						data_type: cx.ScalarType.int_type
					})
					i += step
				}
			}
			iter.exhausted = true
			return iter.memo.clone()
		}
		.iter_range_open {
			// unbounded range materialised without
			// a terminator. The for-comp generator branch short-
			// circuits this kind incrementally when `:take` /
			// `:take-while` is present; reaching pull_iterator_to_end
			// means a consumer asked for the full materialisation,
			// which is invalid. Surface a CXER0100 err-element.
			iter.memo << mk_err('cx-err:CXER0100',
				'infinite range cannot be fully materialised — use [take] / [take-while]')
			iter.exhausted = true
			return iter.memo.clone()
		}
		.iter_iterate {
			// [$iterate f seed] — statically infinite. Like iter_range_open,
			// reaching the full-materialisation path means no bounding
			// combinator is present (the for-comp walker handles [take] /
			// [take-while]); surface the CXER0100 force-error (§1.5).
			iter.memo << mk_err('cx-err:CXER0100',
				'infinite generator cannot be fully materialised — use [take] / [take-while]')
			iter.exhausted = true
			return iter.memo.clone()
		}
		.iter_net_accept, .iter_http_accept {
			// [$net:accept-iter L] / [$http:accept-iter S] — a server accept
			// loop, never eagerly materialised; consumed only by the [?for]
			// streamed/buffered walk.
			iter.memo << mk_err('cx-err:CXER0100',
				'accept-iter is a streamed server loop — consume it with [?for], not full materialisation')
			iter.exhausted = true
			return iter.memo.clone()
		}
		.iter_sse_events {
			// [$http:sse-events S] — a live held-open client stream, consumed
			// only by the [?for] streamed/buffered walk (never eagerly forced).
			iter.memo << mk_err('cx-err:CXER0100',
				'sse-events is a live stream — consume it with [?for], not full materialisation')
			iter.exhausted = true
			return iter.memo.clone()
		}
		.iter_net_line, .iter_net_chunk {
			// [$net:line-iter S] / [$net:chunk-iter S n] — a live socket stream,
			// consumed only by the [?for] streamed/buffered walk.
			iter.memo << mk_err('cx-err:CXER0100',
				'net stream iterator is live — consume it with [?for], not full materialisation')
			iter.exhausted = true
			return iter.memo.clone()
		}
		.iter_unfold {
			// [$unfold f seed] is force-realizable, but realization needs the
			// live env to apply `f` (done in eval()'s finalize / the for-comp
			// walker). Reaching the env-less pull path means an unsupported
			// consumer forced it; surface CXER0100 rather than silently empty.
			iter.memo << mk_err('cx-err:CXER0100',
				'unfold: generator must be consumed in a value or [?for] context')
			iter.exhausted = true
			return iter.memo.clone()
		}
		.iter_take {
			// `iter_take` source_args is [source_iter, count]. The take
			// combinator's primary value is short-circuiting the source —
			// for a recursive Iterator chain we pull lazily up to `count`
			// items. For a SequenceNode / ArrayNode source we still slice
			// to `count`..
			if iter.source_args.len != 2 { return none }
			n := scalar_int(iter.source_args[1]) or { return none }
			if n <= 0 {
				iter.exhausted = true
				return iter.memo.clone()
			}
			src_items := iterate(iter.source_args[0])
			limit := if int(n) < src_items.len { int(n) } else { src_items.len }
			for i in 0 .. limit {
				iter.memo << src_items[i]
			}
			iter.exhausted = true
			return iter.memo.clone()
		}
		.iter_drop {
			// `iter_drop` source_args is [source_iter, count]. Skip the
			// first `count` items, emit the rest..
			if iter.source_args.len != 2 { return none }
			n := scalar_int(iter.source_args[1]) or { return none }
			src_items := iterate(iter.source_args[0])
			start := if int(n) > src_items.len { src_items.len } else if n < 0 { 0 } else { int(n) }
			for i in start .. src_items.len {
				iter.memo << src_items[i]
			}
			iter.exhausted = true
			return iter.memo.clone()
		}
		.iter_concat, .iter_chain {
			// Concat / chain — flatten all source iterators / sequences
			// into a single eager memo..
			for src in iter.source_args {
				for it in iterate(src) {
					iter.memo << it
				}
			}
			iter.exhausted = true
			return iter.memo.clone()
		}
		.iter_enumerate {
			// Enumerate — emit (i, item) paren-comma pairs..
			if iter.source_args.len != 1 { return none }
			src_items := iterate(iter.source_args[0])
			for i, it in src_items {
				iter.memo << cx.Node(cx.Element{
					name: seq_marker_name
					items: [
						cx.Node(cx.ScalarNode{
							value:     cx.ScalarValue(i64(i))
							data_type: cx.ScalarType.int_type
						}),
						it,
					]
				})
			}
			iter.exhausted = true
			return iter.memo.clone()
		}
		.iter_zip {
			// Zip — emit per-position tuples up to the shortest source's
			// length..
			if iter.source_args.len == 0 { return none }
			mut srcs := [][]cx.Node{cap: iter.source_args.len}
			mut shortest := -1
			for src in iter.source_args {
				items := iterate(src)
				if shortest < 0 || items.len < shortest {
					shortest = items.len
				}
				srcs << items
			}
			if shortest <= 0 {
				iter.exhausted = true
				return iter.memo.clone()
			}
			for i in 0 .. shortest {
				mut tup := []cx.Node{cap: srcs.len}
				for s in srcs {
					tup << s[i]
				}
				iter.memo << cx.Node(cx.Element{
					name: seq_marker_name
					items: tup
				})
			}
			iter.exhausted = true
			return iter.memo.clone()
		}
		.iter_chunks {
			// Chunks — group source into sub-sequences of `count` items
			// each (final chunk may be short)..
			if iter.source_args.len != 2 { return none }
			n := scalar_int(iter.source_args[1]) or { return none }
			if n <= 0 { return none }
			src_items := iterate(iter.source_args[0])
			mut i := 0
			for i < src_items.len {
				end := if i + int(n) > src_items.len { src_items.len } else { i + int(n) }
				mut chunk := []cx.Node{cap: end - i}
				for j in i .. end {
					chunk << src_items[j]
				}
				iter.memo << cx.Node(cx.Element{
					name: seq_marker_name
					items: chunk
				})
				i = end
			}
			iter.exhausted = true
			return iter.memo.clone()
		}
		.iter_flatten {
			// Flatten one level of sequence nesting..
			if iter.source_args.len != 1 { return none }
			src_items := iterate(iter.source_args[0])
			for it in src_items {
				if it is cx.Element && (it.name == '' || it.name == seq_marker_name) {
					for inner in it.items {
						iter.memo << inner
					}
				} else if it is cx.SequenceNode {
					for inner in it.items {
						iter.memo << inner
					}
				} else {
					iter.memo << it
				}
			}
			iter.exhausted = true
			return iter.memo.clone()
		}
		.iter_map, .iter_filter, .iter_scan, .iter_partition, .iter_group_by, .iter_cycle, .iter_reduce {
			// Closure-bearing combinators: the directive-time evaluator
			// materialises into `memo` eagerly (env / closure table is
			// not threaded through the `iterate()` codepath at W3c).
			// If we reach pull_iterator_to_end with these source kinds
			// AND an empty memo, it means the iterator was constructed
			// without a directive (e.g. via `cx.new_iterator()` from a
			// unit test) and cannot be evaluated without env context.
			// Return the current memo defensively.
			return iter.memo.clone()
		}
		.iter_none {
			return none
		}
	}
}

// ── Resilience: [?fallback] and [?retry] ───────────────────────────────────
//
// Phase 3.7 partial (stateless variants). [?circuit-breaker],
// [?rate-limit], and [?bulkhead] require a persistent state store
// keyed by `:name` (or lexical position per spec §10.2.7) plus the
// mock-clock; they land in the Phase 3.7 follow-up.
//
// Backoff-delay computation is recognised but skipped — the
// evaluator's wall-clock semantics for `:delay` / `:backoff` /
// `:jitter` parameters are pure parameter validation here; the
// actual sleep / time-advance integration happens in Phase 3.10
// (async + cooperative cancellation pipeline) where the mock-clock
// helper interacts with the evaluator.

fn eval_fallback(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	body := directive_body_excluding(d, ['recover-with', 'on']) or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?fallback] requires :body / positional body' }
	}
	secondary := directive_clause(d, 'recover-with') or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?fallback] requires :recover-with / [recover-with …]' }
	}
	result := eval_node(body, mut env) or {
		// Hard EvalError from primary → secondary path. Convert the thrown
		// condition to a propagating err-value (preserving its code) and
		// bind it as `$err` so the [recover-with] body can read its slots
		// (spec/code.md §10.2 — O2: `[?fallback]` binds `$err`).
		err_val := if err is EvalError {
			if err.cause_set {
				mk_err_with_cause(err.code, err.cause)
			} else {
				mk_err(err.code, err.msg())
			}
		} else {
			mk_err('cx-err:CXER0001', err.msg())
		}
		return eval_fallback_recover(secondary, err_val, mut env)!
	}
	if is_err_value(result) {
		// Returned err-value → recover, binding it as `$err`.
		return eval_fallback_recover(secondary, result, mut env)!
	}
	return result
}

// eval_fallback_recover evaluates the [recover-with] body with the caught
// err-value bound as `$err` (spec/code.md §10.2). The binding is scoped to
// the recovery evaluation via a clone so it does not leak to siblings.
fn eval_fallback_recover(secondary cx.ProgramNode, err_val cx.Node, mut env MatchEnv) !cx.Node {
	mut local := env.clone()
	local.bindings['err'] = err_val
	return eval_node(secondary, mut local)!
}

fn eval_retry(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	max_slot := labeled_slot(d, 'max') or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?retry] requires :max' }
	}
	body := directive_body_excluding(d, ['on']) or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?retry] requires :body / positional body' }
	}
	max_val := eval_node(max_slot, mut env)!
	max_n := scalar_int(max_val) or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?retry] :max must evaluate to an integer' }
	}
	if max_n <= 0 {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: '[?retry] :max must be > 0 (got ${max_n})'
		}
	}
	on_pred := directive_clause(d, 'on') or { cx.ProgramNode(cx.ProgramLiteral{ kind: .bool_lit, bool_val: true, pos: d.pos }) }
	mut attempts := i64(0)
	mut last_err := cx.Node(mk_err_quiet('cx-err:CXER0140', 'no attempts'))
	for attempts < max_n {
		attempts++
		result := eval_node(body, mut env) or {
			last_err = mk_err('cx-err:CXER0001', err.msg())
			if !should_retry(on_pred, last_err, mut env) {
				return last_err
			}
			continue
		}
		if !is_err_value(result) {
			return result
		}
		last_err = result
		if !should_retry(on_pred, last_err, mut env) {
			return last_err
		}
	}
	// Exhausted — wrap as CXER0140 (§10.2.7).: scalar fields
	// (code, attempts) are attributes; cause (an err element) is a child.
	return mk_err_with_slots('cx-err:CXER0140', [
		Slot{ label: 'attempts', value: cx.ScalarNode{ value: cx.ScalarValue(attempts), data_type: cx.ScalarType.int_type } },
		Slot{ label: 'cause', value: last_err },
	])
}

// should_retry evaluates the user-supplied `:on` predicate against
// the last err. The predicate is invoked as a closure-of-one-arg
// (the err value); a truthy return permits another attempt.
fn should_retry(pred_node cx.ProgramNode, err_val cx.Node, mut env MatchEnv) bool {
	// Bind the err under '__retry_err__' and evaluate the predicate as
	// a one-arg call against it. The default predicate is `true` (a
	// literal); user predicates are typically [?fn $e [?if …]].
	if pred_node is cx.ProgramLiteral && pred_node.kind == .bool_lit {
		return pred_node.bool_val
	}
	// User predicate — invoke as a closure if we can.
	mut local := env.clone()
	if pred_node is cx.ProgramDirective && pred_node.name == 'fn' {
		// Evaluate the [?fn] to get a sentinel, then invoke with err.
		sentinel := eval_node(pred_node, mut local) or { return true }
		if closure := resolve_closure(sentinel, local) {
			rv := invoke_closure(closure, [err_val], mut local) or { return true }
			// Iterator-valued predicate: this helper's error posture is
			// retry (every failure path above returns true) — keep it.
			return node_ebv(rv) or { true }
		}
	}
	// Fallback: evaluate the predicate node with __retry_err__ in scope.
	local.bindings['__retry_err__'] = err_val
	rv := eval_node(pred_node, mut local) or { return true }
	return node_ebv(rv) or { true }
}

pub fn scalar_int(n cx.Node) ?i64 {
	if n is cx.ScalarNode {
		v := n.value
		if v is i64 { return v }
	}
	return none
}

// scalar_is_datetime reports whether `n` is (or atomizes to) a datetime
// scalar — used by the `range` builtin to route to the datetime domain.
fn scalar_is_datetime(n cx.Node) bool {
	if n is cx.ScalarNode {
		return n.data_type == cx.ScalarType.datetime_type
	}
	if n is cx.Element {
		if n.items.len == 1 {
			only := n.items[0]
			if only is cx.ScalarNode {
				return only.data_type == cx.ScalarType.datetime_type
			}
		}
	}
	return false
}

// eval_range_float builds a float arithmetic progression (code.md §6.3,
// C-gen-2). Count-based to avoid accumulated drift: n = floor((hi-lo)/step + ε)
// intervals, then lo + i·step for i in 0..=n. The float `step` is REQUIRED
// (no implicit 1.0). A sign-mismatched step yields the empty sequence; a zero
// step is cx-err:CXER0100.
fn eval_range_float(args []cx.Node) cx.Node {
	lo, _ := math_arg_as_float(args[0]) or {
		return mk_err('cx-err:CXER0100', 'range: non-numeric bound')
	}
	hi, _ := math_arg_as_float(args[1]) or {
		return mk_err('cx-err:CXER0100', 'range: non-numeric bound')
	}
	if args.len != 3 {
		return mk_err('cx-err:CXER0100', 'range: float range requires an explicit step')
	}
	step, _ := math_arg_as_float(args[2]) or {
		return mk_err('cx-err:CXER0100', 'range: non-numeric step')
	}
	if step == 0.0 {
		return mk_err('cx-err:CXER0100', 'range: step cannot be zero')
	}
	if (step > 0 && hi < lo) || (step < 0 && hi > lo) {
		return cx.Node(cx.Element{ name: seq_marker_name })
	}
	eps := 1e-9
	n := int(math.floor((hi - lo) / step + eps))
	mut items := []cx.Node{cap: n + 1}
	for k := 0; k <= n; k++ {
		v := lo + f64(k) * step
		items << cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(v)
			data_type: cx.ScalarType.float_type
		})
	}
	return cx.Node(cx.Element{ name: seq_marker_name, items: items })
}

// eval_range_datetime builds an exact-time datetime progression stepped by a
// `duration` literal (code.md §6.3, C-gen-2). Bounds must both be datetimes;
// the step must be a duration string (e.g. `24h`) — a numeric step is
// cx-err:CXER0100. Calendar `date` ranges stay RESERVE (no Period value type).
fn eval_range_datetime(args []cx.Node) cx.Node {
	if args.len != 3 {
		return mk_err('cx-err:CXER0100', 'range: datetime range requires a duration step')
	}
	if !(scalar_is_datetime(args[0]) && scalar_is_datetime(args[1])) {
		return mk_err('cx-err:CXER0100', 'range: datetime range requires datetime bounds')
	}
	lo := decode_datetime(args[0]) or {
		return mk_err('cx-err:CXER0100', 'range: invalid datetime bound')
	}
	hi := decode_datetime(args[1]) or {
		return mk_err('cx-err:CXER0100', 'range: invalid datetime bound')
	}
	// Step MUST be a duration literal (string like `24h`); a numeric step is an
	// error (N-RANGE datetime rule). duration_to_ns rejects non-duration strings.
	mut step_str := ''
	step_node := args[2]
	if step_node is cx.ScalarNode {
		sv := step_node.value
		// A datetime step is a duration value (now a typed .duration_type
		// scalar; older paths may still carry it as a bare string).
		if (step_node.data_type == cx.ScalarType.duration_type
			|| step_node.data_type == cx.ScalarType.string_type) && sv is string {
			step_str = sv
		}
	}
	if step_str == '' {
		return mk_err('cx-err:CXER0100', 'range: datetime range requires a duration step')
	}
	step_ns := duration_to_ns(step_str) or {
		return mk_err('cx-err:CXER0100', 'range: invalid duration step')
	}
	if step_ns == 0 {
		return mk_err('cx-err:CXER0100', 'range: step cannot be zero')
	}
	lo_ns := lo.instant_ns()
	hi_ns := hi.instant_ns()
	offset := lo.offset
	if (step_ns > 0 && hi_ns < lo_ns) || (step_ns < 0 && hi_ns > lo_ns) {
		return cx.Node(cx.Element{ name: seq_marker_name })
	}
	mut items := []cx.Node{}
	mut t := lo_ns
	if step_ns > 0 {
		for t <= hi_ns {
			items << time_datetime_node(dt_from_instant(t, offset).datetime_string())
			t += step_ns
		}
	} else {
		for t >= hi_ns {
			items << time_datetime_node(dt_from_instant(t, offset).datetime_string())
			t += step_ns
		}
	}
	return cx.Node(cx.Element{ name: seq_marker_name, items: items })
}

// is_open_end_marker. Detects the `:_open_end_` atom
// sentinel that the parser substitutes for `*` in the `to *` form.
// Used by the `range` builtin to distinguish bounded `range(a, b)`
// from unbounded `range(a, *)` (which produces iter_range_open).
fn is_open_end_marker(n cx.Node) bool {
	if n is cx.ScalarNode {
		if n.data_type == cx.ScalarType.atom_type {
			v := n.value
			if v is string {
				return v == '_open_end_'
			}
		}
	}
	return false
}

// math_arg_as_float converts a numeric argument to (f64, was_int) for the
// math operators (mod / div / idiv). Atomizes attribute-shaped
// elements (single ScalarNode body) the same way sum / max / min do. The
// `was_int` flag lets `mod` preserve the int-when-both-ints type contract
// (OQ3 of).
fn math_arg_as_float(n cx.Node) ?(f64, bool) {
	mut raw := n
	if n is cx.Element {
		if n.items.len == 1 {
			only := n.items[0]
			if only is cx.ScalarNode {
				raw = cx.Node(only)
			}
		}
	}
	if raw is cx.ScalarNode {
		v := raw.value
		match v {
			i64 { return f64(v), true }
			f64 { return v, false }
			string {
				t := v.trim_space()
				if t.len > 0 && parses_as_i64(t) {
					return f64(t.i64()), true
				}
				if t.len > 0 && parses_as_f64(t) {
					return t.f64(), false
				}
				return none
			}
			else { return none }
		}
	}
	return none
}


// ── Stateful resilience: [?timeout], [?circuit-breaker], [?rate-limit] ─────
//
// Phase 3.7 completion. State machines use the program-global
// ProgramState (matcher.v) keyed by `:name` or, when absent, by the
// directive's source-text position rendered as "L:C". The mock-clock
// (state.now_ns) drives all time-dependent transitions, so fixtures
// remain deterministic.

fn state_key(d cx.ProgramDirective) string {
	if name_slot := labeled_slot(d, 'name') {
		if name_slot is cx.ProgramLiteral && name_slot.kind == .string_lit {
			return name_slot.str_val
		}
	}
	// Lexical-position fallback: render line:col verbatim.
	return '${d.pos.line}:${d.pos.col}'
}

// format_duration_ns renders a nanosecond count back to a duration
// literal using the largest exact unit (h → m → s → ms → us → ns).
// Used by eval_circuit_breaker to render `:until [instant <dur>]`
// as the absolute clock instant the breaker will close.
fn format_duration_ns(ns i64) string {
	if ns == 0 {
		return '0s'
	}
	if ns % (3600 * 1_000_000_000) == 0 {
		return '${ns / (3600 * 1_000_000_000)}h'
	}
	if ns % (60 * 1_000_000_000) == 0 {
		return '${ns / (60 * 1_000_000_000)}m'
	}
	if ns % 1_000_000_000 == 0 {
		return '${ns / 1_000_000_000}s'
	}
	if ns % 1_000_000 == 0 {
		return '${ns / 1_000_000}ms'
	}
	if ns % 1_000 == 0 {
		return '${ns / 1_000}us'
	}
	return '${ns}ns'
}

// duration_to_ns converts a duration literal (lexicon [L25]) to nanoseconds,
// summing one or more integer+unit terms (`1h30m` → 5400e9). Units are the
// EXACT set ns/us/ms/s/m/h/d(=24h)/w(=7d), matched longest-first (ms before m).
// Returns none for a non-duration string (incl. period units mo/y, which have
// no fixed length). Total per the [L25] contract.
pub fn duration_to_ns(s string) ?i64 {
	if s.len == 0 {
		return none
	}
	mut i := 0
	mut neg := false
	if s[0] == `+` {
		i = 1
	} else if s[0] == `-` {
		neg = true
		i = 1
	}
	if i >= s.len {
		return none
	}
	mut total := i64(0)
	for i < s.len {
		dstart := i
		for i < s.len && s[i] >= `0` && s[i] <= `9` {
			i++
		}
		if i == dstart {
			return none
		}
		n := s[dstart..i].i64()
		mut unit_ns := i64(0)
		mut ulen := 0
		if i + 2 <= s.len {
			match s[i..i + 2] {
				'ns' { unit_ns = 1; ulen = 2 }
				'us' { unit_ns = 1_000; ulen = 2 }
				'ms' { unit_ns = 1_000_000; ulen = 2 }
				else {}
			}
		}
		if ulen == 0 {
			match s[i] {
				`s` { unit_ns = i64(1_000_000_000); ulen = 1 }
				`m` { unit_ns = i64(60) * 1_000_000_000; ulen = 1 }
				`h` { unit_ns = i64(3600) * 1_000_000_000; ulen = 1 }
				`d` { unit_ns = i64(86_400) * 1_000_000_000; ulen = 1 }
				`w` { unit_ns = i64(604_800) * 1_000_000_000; ulen = 1 }
				else {}
			}
		}
		if ulen == 0 {
			return none
		}
		total += n * unit_ns
		i += ulen
	}
	return if neg { -total } else { total }
}

// eval_timeout enforces a deadline against the body's evaluated
// duration. Because the evaluator is sequential, "duration" means
// "mock-clock ns elapsed during body evaluation" (driven by [?sleep]
// and [?test-clock]). If the body runs past the deadline, return
// [err :code "cx-err:CXER0141" :elapsed DUR]; if :on-timeout is
// present, evaluate it instead.
fn eval_timeout(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	if d.slots.len == 0 {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?timeout] requires DURATION' }
	}
	dur_node := d.slots[0].value
	dur_text := extract_duration_text(dur_node) or {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?timeout] DURATION must be a duration literal' }
	}
	deadline_ns := duration_to_ns(dur_text) or {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?timeout] invalid DURATION "${dur_text}"' }
	}
	if deadline_ns <= 0 {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?timeout] DURATION must be positive (got "${dur_text}")' }
	}
	body := directive_body_excluding(d, ['on-timeout']) or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?timeout] requires :body / positional body' }
	}
	start_ns := env.state.clock_now()
	deadline_instant := start_ns + deadline_ns
	result := eval_node(body, mut env)!
	if env.state.clock_now() > deadline_instant {
		if on_timeout := directive_clause(d, 'on-timeout') {
			return eval_node(on_timeout, mut env)!
		}
		return mk_err_with_slots('cx-err:CXER0141', [
			Slot{ label: 'elapsed', value: cx.Node(cx.ScalarNode{
				value: cx.ScalarValue(dur_text), data_type: cx.ScalarType.string_type,
			}) },
		])
	}
	return result
}

// Slot is a private helper struct for mk_err_with_slots.
struct Slot {
	label string
	value cx.Node @[required]
}

// slot_text returns the scalar text of the named slot, or '' if absent.
fn slot_text(extra []Slot, label string) string {
	for s in extra {
		if s.label == label {
			return scalar_to_string(s.value) or { '' }
		}
	}
	return ''
}

// canonical_message returns the spec/code.md §9.5.1 canonical message for an
// err code, filling ‹placeholder› segments from the err's attribute slots.
// Returns '' for (site-specific) codes (CXER0001/0100/0104) and codes with no
// fixed message — the raising site supplies those.
pub fn canonical_message(code_str string, extra []Slot) string {
	return match code_str {
		'cx-err:CXER0101' { 'division by zero' }
		'cx-err:CXER0102' { 'invalid partial application: hole in rest position or over-application' }
		'cx-err:CXER0103' { 'predicate operand is multi-valued' }
		'cx-err:CXER0105' { 'single-use iterator already walked — second walk is not permitted' }
		'cx-err:CXER0106' { '[using] clause missing or not a closure' }
		'cx-err:CXER0108' { 'value has no close contract' }
		'cx-err:CXER0109' { '[?with-scope] argument is not a map' }
		'cx-err:CXER0110' { 'enrich hook returned a non-error value' }
		'cx-err:CXER0140' {
			att := slot_text(extra, 'attempts')
			'retry budget exhausted after ${att} attempts'
		}
		'cx-err:CXER0141' {
			el := slot_text(extra, 'elapsed')
			'operation timed out after ${el}'
		}
		'cx-err:CXER0150' { 'circuit breaker open' }
		'cx-err:CXER0151' { 'rate limit exceeded' }
		'cx-err:CXER0152' { 'bulkhead saturated' }
		'cx-err:CXER0160' { 'bad request' }
		'cx-err:CXER0161' { 'unauthorized' }
		'cx-err:CXER0162' { 'not found' }
		'cx-err:CXER0163' { 'request timeout' }
		'cx-err:CXER0164' { 'payload too large' }
		'cx-err:CXER0165' { 'internal server error' }
		'cx-err:CXER0166' { 'service shutting down' }
		'cx-err:CXER0180' { 'connection refused' }
		'cx-err:CXER0181' { 'TLS handshake failed' }
		'cx-err:CXER0182' { 'invalid response' }
		'cx-err:CXER0200' { 'channel closed' }
		'cx-err:CXER0201' { 'send timed out' }
		'cx-err:CXER0202' { 'receive timed out' }
		'cx-err:CXER0203' { 'channel already closed' }
		'cx-err:CXER0220' { 'worker panicked' }
		'cx-err:CXER0221' { 'worker cancelled' }
		'cx-err:CXER0222' { 'worker not found' }
		'cx-err:CXER0240' { '[?await-all] saw a non-done future' }
		'cx-err:CXER0241' {
			to := slot_text(extra, 'timeout')
			if to == '' { 'await timed out' } else { 'await timed out after ${to}' }
		}
		'cx-err:CXER0260' { 'operation cancelled' }
		'test-failure' { 'test failure' }
		'parse-fail' { 'parse failed' }
		else { '' }
	}
}

// mk_err_with_slots builds an err element with :code plus any
// additional labeled slots.
pub fn mk_err_with_slots(err_code string, extra []Slot) cx.Node {
	// `[err code=… message=… …]`. code + scalar extras are attributes;
	// structured extras (element / sequence / map values) are child elements.
	// message is the §9.5.1 canonical message unless the caller supplied one.
	mut attrs := [
		cx.Attribute{ name: 'code', value: cx.ScalarValue(err_code) },
	]
	mut has_msg := false
	for s in extra {
		if s.label == 'message' {
			has_msg = true
		}
	}
	if !has_msg {
		msg := canonical_message(err_code, extra)
		if msg != '' {
			attrs << cx.Attribute{ name: 'message', value: cx.ScalarValue(msg) }
		}
	}
	mut items := []cx.Node{}
	for s in extra {
		if s.value is cx.ScalarNode {
			attrs << cx.Attribute{ name: s.label, value: (s.value as cx.ScalarNode).value }
		} else {
			// Redact any secret in a structured slot (message / where /
			// custom attrs) BEFORE the err is built (cxdm.md §12.2) so a
			// `report` sink shipping the err to a remote tracker cannot
			// leak a token in scope at the failure site (§12.4).
			items << cx.Element{ name: s.label, items: [redact_secrets(s.value)] }
		}
	}
	e := cx.Node(cx.Element{ name: 'err', attrs: attrs, items: items })
	fire_raise_observe(e) // §9.6 raise-stage observe (error_hooks.v)
	return e
}

fn extract_duration_text(n cx.ProgramNode) ?string {
	if n is cx.ProgramLiteral && n.kind == .duration_lit {
		return n.dur_val
	}
	return none
}

// eval_circuit_breaker implements the closed/open/half-open state
// machine. Per spec §10.2.3: trips when failure ratio in the rolling
// window exceeds :threshold with at least :min-samples samples;
// returns to half-open after :reset; one probe in half-open then
// closes or re-opens.
fn eval_circuit_breaker(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	threshold_v := eval_required_labeled(d, 'threshold', mut env)!
	threshold := scalar_f64(threshold_v) or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?circuit-breaker] :threshold must be numeric' }
	}
	if threshold < 0.0 || threshold > 1.0 {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?circuit-breaker] :threshold out of [0,1] (got ${threshold})' }
	}
	window_text := duration_label_text(d, 'window')!
	window_ns := duration_to_ns(window_text) or {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?circuit-breaker] :window invalid' }
	}
	reset_text := duration_label_text(d, 'reset')!
	reset_ns := duration_to_ns(reset_text) or {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?circuit-breaker] :reset invalid' }
	}
	min_samples := i64(10)
	if ms_node := labeled_slot(d, 'min-samples') {
		mv := eval_node(ms_node, mut env)!
		if v := scalar_int(mv) {
			_ = min_samples
			_ = mv
			_ = v
		}
	}
	body := directive_body(d) or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?circuit-breaker] requires :body' }
	}
	key := state_key(d)
	// Pre-body phase: snapshot + early-return on open breaker, then
	// publish the partial update with sample++ so concurrent workers
	// see the in-flight call. We release cb_state_lock before
	// eval_node(body) to avoid deadlock if the body recurses into
	// another `[?circuit-breaker]` (different key, same lock; POSIX
	// rwlock is non-recursive).
	now1 := env.state.clock_now()
	mut rec := env.state.cb_get(key) or {
		CbStateRecord{
			open_until_ns: 0
			samples: 0
			failures: 0
			window_start_ns: now1
		}
	}
	if now1 - rec.window_start_ns > window_ns {
		rec.samples = 0
		rec.failures = 0
		rec.window_start_ns = now1
	}
	if rec.open_until_ns > 0 && now1 < rec.open_until_ns {
		env.state.cb_set(key, rec)
		until_text := format_duration_ns(rec.open_until_ns)
		return mk_cb_open_err(until_text)
	}
	if rec.open_until_ns > 0 && now1 >= rec.open_until_ns {
		rec.open_until_ns = 0
	}
	rec.samples++
	env.state.cb_set(key, rec)

	result := eval_node(body, mut env)!

	// Post-body phase: re-read latest state (another worker may have
	// updated samples/failures since), apply this invocation's
	// outcome (failure increment + trip check), write back.
	mut rec2 := env.state.cb_get(key) or { rec }
	if is_err_value(result) {
		rec2.failures++
		ratio := if rec2.samples > 0 { f64(rec2.failures) / f64(rec2.samples) } else { 0.0 }
		ms := if ms_node := labeled_slot(d, 'min-samples') {
			mv := eval_node(ms_node, mut env)!
			scalar_int(mv) or { i64(10) }
		} else {
			i64(10)
		}
		if rec2.samples >= ms && ratio >= threshold {
			rec2.open_until_ns = env.state.clock_now() + reset_ns
		}
	}
	env.state.cb_set(key, rec2)
	return result
}

// mk_cb_open_err emits the canonical breaker-open err shape with
// `:until` as a `[instant DUR]` element (matching the spec's example
// and conformance fixtures).
fn mk_cb_open_err(dur_text string) cx.Node {
	instant_el := cx.Element{
		name:  'instant'
		items: [cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(dur_text)
			data_type: cx.ScalarType.string_type
		})]
	}
	return mk_err_with_slots('cx-err:CXER0150', [
		Slot{ label: 'until', value: cx.Node(instant_el) },
	])
}

fn duration_label_text(d cx.ProgramDirective, label string) !string {
	n := labeled_slot(d, label) or {
		return error('[?<directive>] requires :${label}')
	}
	t := extract_duration_text(n) or {
		return error(':${label} must be a DURATION literal')
	}
	return t
}

fn eval_required_labeled(d cx.ProgramDirective, label string, mut env MatchEnv) !cx.Node {
	n := labeled_slot(d, label) or {
		return EvalError{ code: 'cx-err:CXER0001', message: 'missing :${label}' }
	}
	return eval_node(n, mut env)!
}

fn scalar_f64(n cx.Node) ?f64 {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			f64 { return v }
			i64 { return f64(v) }
			string {
				// I1 stream 11 (2b): CONFIG scalars (thresholds, ranges —
				// not identity or exactness surfaces) accept decimal/bigint
				// images; a bare `0.5` option is a decimal now.
				if n.data_type == cx.ScalarType.decimal_type
					|| n.data_type == cx.ScalarType.bigint_type {
					if fv := strconv.atof64(v) {
						return fv
					}
				}
			}
			else {}
		}
	}
	return none
}

// eval_rate_limit implements a token-bucket per spec §10.2.5.
fn eval_rate_limit(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	max_node := labeled_slot(d, 'max') or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?rate-limit] requires :max' }
	}
	max_val := eval_node(max_node, mut env)!
	max_n := scalar_int(max_val) or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?rate-limit] :max must be integer' }
	}
	if max_n <= 0 {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?rate-limit] :max must be > 0' }
	}
	per_text := duration_label_text(d, 'per')!
	per_ns := duration_to_ns(per_text) or {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?rate-limit] :per invalid' }
	}
	body := directive_body(d) or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?rate-limit] requires :body' }
	}
	key := state_key(d)
	now := env.state.clock_now()
	mut rec := env.state.rate_get(key) or {
		RateStateRecord{
			tokens_remaining: max_n
			window_start_ns:  now
		}
	}
	// Window replenishment
	if now - rec.window_start_ns >= per_ns {
		rec.tokens_remaining = max_n
		rec.window_start_ns = now
	}
	if rec.tokens_remaining <= 0 {
		env.state.rate_set(key, rec)
		return mk_err_with_slots('cx-err:CXER0151', [
			Slot{ label: 'retry-after', value: cx.Node(cx.ScalarNode{
				value: cx.ScalarValue(per_text), data_type: cx.ScalarType.string_type,
			}) },
		])
	}
	rec.tokens_remaining--
	env.state.rate_set(key, rec)
	return eval_node(body, mut env)!
}

// eval_bulkhead implements [?bulkhead :max-concurrent N :queue Q :name S
// :body EXPR] per spec/code.md §10.2.6.
//
// State machine: name-keyed `in_flight` (currently-running slot count)
// and `queued` (FIFO wait-list size). On entry:
//
//   in_flight < max-concurrent  → acquire slot, run body, release
//   in_flight == max-concurrent
//      ∧ queued < queue          → wait for a slot to free (scheduler-
//                                  driven; see vcx/code/scheduler.v
//                                  in Phase 3.7 commit B)
//      ∧ queued == queue         → return [err :code "cx-err:CXER0152"
//                                  :max N]
//
// Outside a cooperative-scheduler context (the common case — every
// fixture that does not use [?test-concurrent]) the wait-for-slot
// path is unreachable in practice: a single-threaded caller cannot be
// in-flight on the same bulkhead concurrently with itself. Phase 3.7
// commit B will widen the saturated branch to suspend the current
// task and resume it when a slot frees.
fn eval_bulkhead(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	max_node := labeled_slot(d, 'max-concurrent') or {
		return EvalError{ code: 'cx-err:CXER0001',
			message: '[?bulkhead] requires :max-concurrent' }
	}
	max_val := eval_node(max_node, mut env)!
	max_n := scalar_int(max_val) or {
		return EvalError{ code: 'cx-err:CXER0001',
			message: '[?bulkhead] :max-concurrent must be integer' }
	}
	if max_n <= 0 {
		return EvalError{ code: 'cx-err:CXER0100',
			message: '[?bulkhead] :max-concurrent must be > 0' }
	}
	mut queue_n := i64(0)
	if queue_node := labeled_slot(d, 'queue') {
		queue_val := eval_node(queue_node, mut env)!
		queue_n = scalar_int(queue_val) or {
			return EvalError{ code: 'cx-err:CXER0001',
				message: '[?bulkhead] :queue must be integer' }
		}
		if queue_n < 0 {
			return EvalError{ code: 'cx-err:CXER0100',
				message: '[?bulkhead] :queue must be >= 0' }
		}
	}
	body := directive_body(d) or {
		return EvalError{ code: 'cx-err:CXER0001',
			message: '[?bulkhead] requires :body' }
	}
	key := state_key(d)
	mut bh := env.state.bh_get(key)
	// Record max + queue cap so the cooperative scheduler's settle phase
	// (scheduler.v `settle`) can detect "slot freed → wake first
	// queued waiter" without reaching back into the originating
	// directive's AST.
	bh.max_concurrent = int(max_n)
	bh.queue_cap = int(queue_n)
	env.state.bh_set(key, bh)

	if i64(bh.in_flight) < max_n {
		bh.in_flight++
		env.state.bh_set(key, bh)
		result := eval_node(body, mut env) or {
			mut after_err := env.state.bh_get(key)
			after_err.in_flight--
			env.state.bh_set(key, after_err)
			return err
		}
		mut after_ok := env.state.bh_get(key)
		after_ok.in_flight--
		env.state.bh_set(key, after_ok)
		return result
	}

	// Saturated. Under a cooperative-scheduler task, park on the
	// bulkhead's FIFO wait queue and yield; the scheduler will grant
	// the slot (incrementing in_flight, decrementing queued) when one
	// frees. Outside a task context, saturated means immediate
	// CXER0152 — Phase A semantics preserved.
	tid := env.state.current_task_get()
	if i64(bh.queued) < queue_n && tid != 0
	   && env.state.scheduler_task_has(tid) {
		bh.queued++
		bh.wait_queue << tid
		env.state.bh_set(key, bh)
		t := env.state.scheduler_task_get(tid) or {
			return EvalError{ code: 'cx-err:CXER0001',
				message: '[?bulkhead] internal: current_task_id has no record' }
		}
		mut tr := unsafe { t }
		tr.queued_bulkhead = key
		task_yield(tr, TaskYieldKind.bulkhead_queue)
		// On resume, scheduler has already done in_flight++ /
		// queued-- on our behalf. Run body, then release the slot.
		result := eval_node(body, mut env) or {
			mut after_err := env.state.bh_get(key)
			after_err.in_flight--
			env.state.bh_set(key, after_err)
			return err
		}
		mut after_ok := env.state.bh_get(key)
		after_ok.in_flight--
		env.state.bh_set(key, after_ok)
		return result
	}

	return mk_err_with_slots('cx-err:CXER0152', [
		Slot{ label: 'max', value: cx.Node(cx.ScalarNode{
			value: cx.ScalarValue(max_n), data_type: cx.ScalarType.int_type,
		}) },
	])
}

fn eval_sleep(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	// [?sleep DUR] is wall-clock by default; [?sleep DUR :mock] is the
	// explicit mock-clock form (advance now_ns, return instantly).
	// Slot layout: one positional DURATION + optional bare :mock flag.
	if d.slots.len == 0 {
		// Missing required arg is a grammar/parse error (PARSE_ERROR), not the
		// retired CXER0001 (code.md:1918 — no directive raises CXER0001 directly).
		return EvalError{ code: 'cx-err:CXER0100', message: '[?sleep] requires a DURATION' }
	}
	mut dur_node := cx.ProgramNode(cx.ProgramLiteral{ kind: .bool_lit })
	mut mock_flag := false
	mut have_dur := false
	for slot in d.slots {
		if slot.kind == .labeled {
			if slot.label == 'mock' {
				if mock_flag {
					return EvalError{ code: 'cx-err:CXER0100',
						message: '[?sleep] duplicate [mock] flag' }
				}
				mock_flag = true
				continue
			}
			return EvalError{ code: 'cx-err:CXER0100',
				message: "[?sleep] unknown slot ':${slot.label}'" }
		}
		// The `mock` modifier (§10.5.3 `[?sleep DUR mock]`) is a bareword.
		// A bare ident with no args parses to cx.ProgramCall{name:'mock'} (the
		// canonical spec form); a `[mock]` clause child parses to a cx_element
		// cx.ProgramLiteral. Accept both shapes.
		v := slot.value
		mut is_mock := false
		if v is cx.ProgramLiteral {
			is_mock = v.kind == .cx_element && v.name == 'mock'
		} else if v is cx.ProgramCall {
			is_mock = v.name == 'mock' && v.args.len == 0
		}
		if is_mock {
			if mock_flag {
				return EvalError{ code: 'cx-err:CXER0100',
					message: '[?sleep] duplicate mock flag' }
			}
			mock_flag = true
			continue
		}
		if have_dur {
			return EvalError{ code: 'cx-err:CXER0100',
				message: '[?sleep] takes a single positional DURATION' }
		}
		dur_node = slot.value
		have_dur = true
	}
	if !have_dur {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?sleep] requires a DURATION' }
	}
	dur_text := extract_duration_text(dur_node) or {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?sleep] argument must be a DURATION literal' }
	}
	ns := duration_to_ns(dur_text) or {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?sleep] invalid DURATION "${dur_text}"' }
	}
	// Cancellation contract (§10.5.4): if [?sleep] runs inside an
	// async-future body or a concurrent [?worker] body whose [?cancel] was
	// requested, immediately short-circuit with EvalError(CXER0260) so the
	// cancellation propagates up through any enclosing directives (a
	// returned err-value would otherwise be swallowed by [?let] etc.).
	// drive_future / run_worker_thread catch this and mark the task cancelled.
	if active_future_cancelled(env) || worker_cancel_pending(env) {
		return EvalError{ code: 'cx-err:CXER0260',
			message: 'cancellation observed at sleep' }
	}
	if would_exceed_await_deadline(env, ns) {
		return EvalError{ code: 'cx-err:CXER0241',
			message: 'await deadline exceeded' }
	}
	// Eager-future PARK (#541): a mock sleep inside a SPAWNED [?async]
	// body must not self-advance the shared logical clock (the lazy
	// substrate's move) — with real threads that would race every other
	// clock reader. Instead the body PARKS: it publishes its wake time on
	// the record and polls until the await barrier advances the clock to
	// it (await_concurrent moves time only when every runnable future is
	// parked) or its cancellation flag is raised — cancel-wake observes
	// the flag FIRST (§10.5.7.2 precedence: cancel-check ▷ everything).
	if mock_flag && env.current_future != unsafe { nil } {
		mut cf := env.current_future
		wake := env.state.clock_now() + ns
		cf.parked_until_ns = wake
		for {
			if cf.cancel_requested {
				cf.parked_until_ns = 0
				return EvalError{ code: 'cx-err:CXER0260',
					message: 'cancellation observed at sleep' }
			}
			if env.state.clock_now() >= wake {
				cf.parked_until_ns = 0
				return cx.Element{ name: 'ok' }
			}
			time.sleep(time.millisecond)
		}
	}
	// Cooperative-scheduler yield. When this [?sleep] runs inside a
	// [?test-concurrent] task body (mock-clock-only by design per
	// scheduler.v), hand control back to the scheduler instead of
	// advancing the clock locally. The scheduler advances `now_ns` to
	// the task's sleep_until_ns before resuming us; from the task
	// body's POV the sleep appears to have advanced exactly `ns`
	// nanoseconds. Auto-mock.
	tid := env.state.current_task_get()
	if tid != 0 && env.state.scheduler_task_has(tid) {
		t := env.state.scheduler_task_get(tid) or {
			return EvalError{ code: 'cx-err:CXER0001',
				message: '[?sleep] internal: current_task_id has no record' }
		}
		mut tr := unsafe { t }
		tr.sleep_until_ns = env.state.clock_now() + ns
		task_yield(tr, TaskYieldKind.sleep)
		return cx.Element{ name: 'ok' }
	}
	// Mock-clock path: explicit :mock flag.
	if mock_flag {
		env.state.clock_advance(ns)
		return cx.Element{ name: 'ok' }
	}
	// Wasm host capability check. On wasm builds where
	// the host hasn't opted into blocking sleep (browser main thread
	// default), bare wall-clock [?sleep] would freeze the UI — raise
	// CXER0270 so authors get a clear pointer to :mock. The
	// `wasm_wall_sleep_allowed` flag stays false on native builds and
	// is irrelevant — the wall-clock path runs below.
	$if wasm32_emcc ? {
		if !env.state.wasm_wall_sleep_allowed {
			return EvalError{ code: 'cx-err:CXER0270',
				message: '[?sleep DUR] is unsupported in this wasm host; use [?sleep DUR :mock] or opt into blocking sleep via _cx_wasm_set_wall_sleep(true)' }
		}
	}
	// Wall-clock path. Sleep for DUR with cancel-flag
	// polling. Cooperative cancellation honored within one polling
	// window per §10.5.4.
	$if wasm32_emcc ? {
		$if asyncify_build ? {
			// ASYNCIFY-instrumented build: emcc rewrites the wasm so
			// `emscripten_sleep` yields back to the JS event loop, JS
			// schedules setTimeout, then resumes the wasm frame. The
			// browser main thread stays responsive (rAF + UI events
			// keep firing) while the eval suspends. Single sleep call
			// (no 50ms cancel-poll loop) because each Asyncify
			// suspend/resume round-trip costs ~50-100ms of setTimeout
			// + stack-management overhead; chunking a 500ms sleep
			// into 10×50ms turns it into multiple seconds end-to-end.
			// Cancellation latency under Asyncify is therefore bounded
			// by the sleep duration itself, not by a 50ms poll. Cancel
			// check at directive entry already handled above.
			C.emscripten_sleep(int(ns / 1_000_000))
			if active_future_cancelled(env) || worker_cancel_pending(env) {
				return EvalError{ code: 'cx-err:CXER0260',
					message: 'cancellation observed at sleep' }
			}
			return cx.Element{ name: 'ok' }
		} $else {
			// Non-Asyncify wasm: Worker-context busy-wait. Reached
			// only when the host has set wasm_wall_sleep_allowed=true
			// (Web-Worker host opted in via cx_wasm_set_wall_sleep),
			// so spinning here burns only the worker thread — the
			// browser main thread / UI stays responsive. emscripten's
			// POSIX `usleep` without Asyncify is async-only and would
			// either no-op or abort, so a `time.now()` polling loop
			// is the portable substitute.
			deadline_ns := time.now().unix_nano() + ns
			for time.now().unix_nano() < deadline_ns {
				if active_future_cancelled(env) || worker_cancel_pending(env) {
					return EvalError{ code: 'cx-err:CXER0260',
						message: 'cancellation observed at sleep' }
				}
			}
			return cx.Element{ name: 'ok' }
		}
	} $else {
		// Native: real time.sleep with 50ms cancel-poll window.
		mut remaining_ms := ns / 1_000_000
		poll_ms := i64(50)
		for remaining_ms > 0 {
			step_ms := if remaining_ms > poll_ms { poll_ms } else { remaining_ms }
			time.sleep(step_ms * time.millisecond)
			if active_future_cancelled(env) || worker_cancel_pending(env) {
				return EvalError{ code: 'cx-err:CXER0260',
					message: 'cancellation observed at sleep' }
			}
			remaining_ms -= step_ms
		}
		return cx.Element{ name: 'ok' }
	}
}

// ── Fixture-only test helpers ───────────────────────────────────────────────

// eval_test_single_use_iter test scaffold. Constructs a
// single-use IteratorNode whose first walk pulls the positional items
// into memo (via the iter_concat dispatch in `pull_iterator_to_end`)
// and flips `exhausted = true`; the second walk hits the
// `single_use && exhausted` guard in `iterate()` and returns a
// CXER0105 err-element. No spec/code.md exposure — this directive
// exists only to drive the D25 conformance fixtures (no production
// single-use source kind ships currently; HTTP body / file lines /
// channel reads arrive in a follow-up milestone). Naming convention:
// the `test-` prefix marks this as a fixture-only helper — the parser
// admits `test-*` directives (spec/code.md §4.1) and the evaluator
// dispatches them through the conformance helper table.
//
// Usage:
//   `[?test-single-use-iter 1 2 3]`           — a fresh, never-walked
//       single-use iterator; the first materialisation yields 1, 2, 3.
//   `[?test-single-use-iter 1 2 3 :walked]`   — an ALREADY-exhausted
//       single-use iterator; materialising it hits the CXER0105 guard
//       in `iterate()` immediately.
//
// ENV-COPY LIMITATION (W4-C scope note): re-walking the
// *same bound iterator* twice via two `[?to-sequence $it]` calls does
// NOT surface CXER0105 today. The `env.bindings` map stores the
// IteratorNode sum value, and the binding-lookup path
// (eval_binding → env.bindings[name]) hands each consumer a fresh copy
// of the sum variant rather than the shared heap object; the
// `exhausted = true` flip the first walk performs in `iterate()` does
// not propagate back to the bound value, so the second walk re-pulls
// from a pristine copy. Threading the heap identity through env
// binding-lookup is a follow-up (it touches the env representation,
// out of scope for this milestone). The `:walked` form drives the
// enforcement fixture in the meantime by constructing the
// post-exhaustion state directly.
fn eval_test_single_use_iter(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	items := collect_positional_values(d, mut env, 'test-single-use-iter', ['walked'])!
	walked := labeled_slot(d, 'walked') != none || clause_child(d, 'walked') != none
	// Wrap the items as a SequenceNode so iter_concat sees a single
	// "source" to iterate (iter_concat's source_args are themselves
	// iterables; a sequence-shaped Element flattens correctly).
	src := cx.Node(cx.Element{
		name: seq_marker_name
		items: items.clone()
	})
	if walked {
		// Already-exhausted single-use iterator: memo carries the items,
		// exhausted = true. iterate() sees single_use && exhausted and
		// returns the CXER0105 err directly (no re-pull).
		return cx.Node(cx.IteratorNode{
			source_kind: cx.IteratorSourceKind.iter_concat
			source_args: [src]
			memo:        items.clone()
			exhausted:   true
			single_use:  true
		})
	}
	return cx.Node(cx.IteratorNode{
		source_kind: cx.IteratorSourceKind.iter_concat
		source_args: [src]
		memo:        []
		exhausted:   false
		single_use:  true
	})
}

// scalar_to_text renders a scalar value to its canonical textual form
// for the [?with-*] fixture helpers' deterministic string outputs.
pub fn scalar_to_text(v cx.ScalarValue) string {
	return match v {
		bool      { v.str() }
		i64       { v.str() }
		f64       { v.str() }
		string    { v }
		cx.NullValue { 'null' }
	}
}

// [?test-closeable :label "f1"] — fixture-only helper that mints a
// closeable handle registered against the [?with-open] close-contract
// Closing it appends :label to state.close_log;
// :fail-on-close true makes its close raise (exercises D7 surfacing).
fn eval_test_closeable(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	label_node := labeled_slot(d, 'label') or {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?test-closeable] requires :label' }
	}
	label_val := eval_node(label_node, mut env)!
	label := if label_val is cx.ScalarNode { scalar_to_text(label_val.value) } else { 'handle' }
	fail := labeled_slot(d, 'fail-on-close') != none
	id := '${env.state.next_close_id}'
	env.state.next_close_id++
	close_fn := if fail {
		fn () ! {
			return EvalError{ code: 'cx-err:CXER3408', message: 'close failed' }
		}
	} else {
		fn () ! {}
	}
	env.state.closeables[id] = &CloseableRecord{
		label:    label
		closed:   false
		close_fn: close_fn
	}
	return cx.Element{
		name:  'handle'
		attrs: [
			cx.Attribute{ name: close_id_attr, value: cx.ScalarValue(id) },
			cx.Attribute{ name: 'label', value: cx.ScalarValue(label) },
		]
	}
}

// [?test-close-log] — fixture-only helper returning the comma-joined
// close-invocation order recorded so far (innermost-first across a
// [?with-open] scope exit). A failing close appends `<label>!err`.
fn eval_test_close_log(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(env.state.close_log.join(','))
		data_type: cx.ScalarType.string_type
	}
}

// [?test-current-scope] — fixture-only helper returning the active
// dynamic context (the [?with-scope] stack top) as a deterministic
// key-sorted `k=v,k=v` string, so fixtures can assert merge / restore /
// nesting without cx-stdlib/log (the production reader).
fn eval_test_current_scope(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	mut parts := []string{}
	for e in env.dyn_context {
		if e is cx.Element {
			val := if e.items.len > 0 { node_to_scope_text(e.items[0]) } else { '' }
			parts << '${e.name}=${val}'
		}
	}
	parts.sort()
	return cx.ScalarNode{
		value:     cx.ScalarValue(parts.join(','))
		data_type: cx.ScalarType.string_type
	}
}

fn node_to_scope_text(n cx.Node) string {
	if n is cx.ScalarNode {
		return scalar_to_text(n.value)
	}
	return '?'
}

fn eval_test_clock(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	if advance_node := labeled_slot(d, 'advance') {
		dur_text := extract_duration_text(advance_node) or {
			return EvalError{ code: 'cx-err:CXER0100', message: '[?test-clock] :advance must be a DURATION' }
		}
		ns := duration_to_ns(dur_text) or {
			return EvalError{ code: 'cx-err:CXER0100', message: '[?test-clock] invalid DURATION' }
		}
		env.state.clock_advance(ns)
		return cx.Element{ name: 'ok' }
	}
	// No :advance — return current mock instant as opaque scalar.
	return cx.ScalarNode{
		value:     cx.ScalarValue(env.state.clock_now())
		data_type: cx.ScalarType.int_type
	}
}

// eval_test_counter implements the fixture-only `[?test-counter name=STR
// op=(read | inc)]` helper documented in conformance/code.cxd §11: a named
// integer counter. `inc` increments the named counter and returns the new
// value; `read` (default) returns the current value (0 if never
// incremented). Used by the module const-lazy fixtures to observe that a
// lazy `[?const]` body fires exactly once under memoization.
// node_text_or_scalar extracts a string from a TextNode (bareword
// self-eval) or a string-typed ScalarNode (quoted literal); none otherwise.
fn node_text_or_scalar(n cx.Node) ?string {
	if n is cx.TextNode {
		return n.value
	}
	return scalar_string(n)
}

fn eval_test_counter(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	name_node := labeled_slot(d, 'name') or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?test-counter] requires name=' }
	}
	nv := eval_node(name_node, mut env)!
	cname := node_text_or_scalar(nv) or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?test-counter] name= must be a string' }
	}
	mut op := 'read'
	if op_node := labeled_slot(d, 'op') {
		ov := eval_node(op_node, mut env)!
		op = node_text_or_scalar(ov) or { 'read' }
	}
	key := 'test-counter:${cname}'
	mut cur := env.state.test_counter_get(key)
	if op == 'inc' {
		cur++
		env.state.test_counter_set(key, cur)
	}
	return cx.ScalarNode{
		value:     cx.ScalarValue(cur)
		data_type: cx.ScalarType.int_type
	}
}

fn eval_test_always_err() !cx.Node {
	return mk_err_with_slots('test-failure', [])
}

fn eval_test_err_then_ok(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	count_node := labeled_slot(d, 'err-count') or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?test-err-then-ok] requires :err-count' }
	}
	ok_node := labeled_slot(d, 'ok-value') or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?test-err-then-ok] requires :ok-value' }
	}
	cv := eval_node(count_node, mut env)!
	threshold := scalar_int(cv) or {
		return EvalError{ code: 'cx-err:CXER0001', message: ':err-count must be integer' }
	}
	// State key — prefer the directive's explicit `:name`; else fall
	// back to the rendered `:ok-value` content so two textually-identical
	// test-err-then-ok bodies at different lexical positions share state
	// (canonical use case: cb-003 / cb-004 half-open probes wrap the
	// same test-err-then-ok body inside two separate circuit-breaker
	// invocations and rely on the per-:ok-value seen-counter persisting
	// across the two calls so the second invocation observes a non-zero
	// `seen` and returns ok).
	mut key := state_key(d)
	if labeled_slot(d, 'name') == none {
		// No `:name` — derive a stable key from the rendered ok-value so
		// textually-identical bodies share state across lexical positions.
		ok_val := eval_node(ok_node, mut env) or { cx.Node(cx.Element{ name: '' }) }
		key = 'tetok:${node_sort_key(ok_val)}'
	}
	mut seen := env.state.test_err_count_get(key)
	if seen < threshold {
		seen++
		env.state.test_err_count_set(key, seen)
		return mk_err_with_slots('test-failure', [])
	}
	return eval_node(ok_node, mut env)!
}

fn eval_test_cb_open() !cx.Node {
	// Per conformance/code.txt line 76, the canonical test-cb-open
	// shape is `[err :code "cx-err:CXER0150" :until [instant 0]]` — the
	// `0` is a bare integer, not the duration text "0s". Composition-
	// matrix fixtures pin this shape verbatim, so synthesise the
	// instant element directly with an i64-typed scalar (mk_cb_open_err
	// goes through a string-typed scalar to round-trip real durations
	// like "30s" which the renderer recognises via looks_like_duration).
	instant_el := cx.Element{
		name:  'instant'
		items: [cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(i64(0))
			data_type: cx.ScalarType.int_type
		})]
	}
	return mk_err_with_slots('cx-err:CXER0150', [
		Slot{ label: 'until', value: cx.Node(instant_el) },
	])
}

fn eval_test_rate_limited() !cx.Node {
	return mk_err_with_slots('cx-err:CXER0151', [
		Slot{ label: 'retry-after', value: cx.Node(cx.ScalarNode{
			value: cx.ScalarValue('100ms'), data_type: cx.ScalarType.string_type,
		}) },
	])
}

fn eval_test_bulkhead_full() !cx.Node {
	return mk_err_with_slots('cx-err:CXER0152', [
		Slot{ label: 'max', value: cx.Node(cx.ScalarNode{
			value: cx.ScalarValue(i64(1)), data_type: cx.ScalarType.int_type,
		}) },
	])
}

// eval_test_concurrent drives the cooperative scheduler (scheduler.v)
// over a sequence of task ASTs supplied via `:tasks`. The fixture-
// format declares this as a fixture-only helper outside the
// spec/code.md §4.1 registry; it exists so resilience fixtures can
// observe interleaving without depending on real concurrency. Returns
// a `__cx_seq__` element whose items are each task's terminal value
// in *completion order*.
fn eval_test_concurrent(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	tasks_node := labeled_slot(d, 'tasks') or {
		return EvalError{ code: 'cx-err:CXER0001',
			message: '[?test-concurrent] requires :tasks' }
	}
	task_bodies := extract_concurrent_task_bodies(tasks_node) or {
		return EvalError{ code: 'cx-err:CXER0001',
			message: '[?test-concurrent] :tasks must be a sequence literal of task bodies' }
	}
	if task_bodies.len == 0 {
		return cx.Element{ name: '__cx_seq__' }
	}
	mut tasks := []&TaskRecord{cap: task_bodies.len}
	for i, body in task_bodies {
		t := &TaskRecord{
			id:                i + 1
			body:              body
			bindings_snapshot: env.bindings.clone()
			state:             'pending'
			result:            cx.Element{ name: '' }
			run_gate:          chan bool{}
			yield_gate:        chan TaskYieldKind{}
		}
		tasks << t
		env.state.scheduler_task_set(t.id, t)
	}
	closures_snapshot := env.closures.clone()
	for t in tasks {
		spawn run_task_thread(t, env.state, closures_snapshot)
	}
	results := drive_scheduler(mut tasks, mut env)
	for t in tasks {
		env.state.scheduler_task_delete(t.id)
	}
	return cx.Element{ name: '__cx_seq__', items: results }
}

// extract_concurrent_task_bodies normalises the `:tasks` slot into a
// slice of body ASTs. Accepts a parenthesised sequence literal
// `(t1, t2, …)` (the spec'd surface) and falls back to a single-task
// passthrough when an unwrapped expression is supplied.
fn extract_concurrent_task_bodies(node cx.ProgramNode) ?[]cx.ProgramNode {
	if node is cx.ProgramLiteral && node.kind == .sequence_lit {
		return node.items
	}
	return [node]
}

// ── Concurrency: channels, workers, select (Phase 3.9) ─────────────────────
//
// Channels are FIFO queues with a configurable buffer per §10.4.1.
// In the reference impl they live as ChannelRecord values in
// ProgramState.channels keyed by name, shared across the main thread and
// the concurrent [?worker] threads (§10.4.6 default) — every queue access
// serialises through the ch_* helpers above.
//
// Blocking semantics are context-split:
//   * INSIDE a concurrent [?worker] body (env.current_worker set), [?send]
//     and [?receive] carry the real §10.4.2/§10.4.3 semantics — an
//     unbuffered send blocks until a receiver consumes the value
//     (rendezvous), a full buffered send blocks for space, a receive
//     blocks on empty-open — and every blocked pass observes the §10.5.4
//     cancel signal first (CXER0260). This is what makes cancelling a
//     blocked worker deterministic (program-conc-016/017).
//   * On the MAIN program thread no sibling thread is guaranteed to
//     exist, so blocking would deadlock a single-threaded program: send
//     enqueues unconditionally, receive returns the RECV_TIMEOUT-
//     equivalent CXER0202 on empty-open. Real main-thread blocking ships
//     with the production scheduler (Phase 3.10 follow-up).

fn channel_name(d cx.ProgramDirective, mut env MatchEnv) !string {
	if name_slot := labeled_slot(d, 'name') {
		ns := eval_node(name_slot, mut env)!
		if ns is cx.ScalarNode {
			v := ns.value
			if v is string { return v }
		}
		if ns is cx.Element {
			// Channel handle: an element with name="channel" and a :name child
			return read_channel_name_from_handle(ns)
		}
	}
	return error('expected channel :name')
}

fn read_channel_name_from_handle(el cx.Element) !string {
	nm := el.attr('name')
	if nm != '' {
		return nm
	}
	return error('channel handle missing name')
}

fn eval_channel(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	name := channel_name(d, mut env) or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?channel] requires :name' }
	}
	mut buffer := 0
	mut has_buffer := false
	if buf_node := labeled_slot(d, 'buffer') {
		bv := eval_node(buf_node, mut env)!
		if v := scalar_int(bv) {
			buffer = int(v)
			has_buffer = true
		}
	}
	// the U1.11a fan-out axes (§10.4.1): sharing= / retention= / keep=.
	// The default point (sharing=group, retention=none, blocking buffer)
	// is spelled exactly as before; invalid combinations refuse CXER0217
	// (CHANNEL_POLICY) at declaration.
	mut sharing := ''
	mut retention := ''
	mut keep := 0
	mut has_keep := false
	if sn := labeled_slot(d, 'sharing') {
		sv := eval_node(sn, mut env)!
		sharing = scalar_or_atom_str(sv)
	}
	if rn := labeled_slot(d, 'retention') {
		rv := eval_node(rn, mut env)!
		retention = scalar_or_atom_str(rv)
	}
	if kn := labeled_slot(d, 'keep') {
		kv := eval_node(kn, mut env)!
		if v := scalar_int(kv) {
			keep = int(v)
			has_keep = true
		}
	}
	if sharing !in ['', 'group', 'independent'] {
		return mk_err_msg('cx-err:CXER0217', 'CHANNEL_POLICY: sharing=`${sharing}` is not an axis point (group | independent)')
	}
	if sharing == 'independent' {
		if retention !in ['latest', 'window'] {
			return mk_err_msg('cx-err:CXER0217', 'CHANNEL_POLICY: sharing=independent requires retention=latest or retention=window keep=K (got retention=`${retention}`)')
		}
		if has_buffer {
			return mk_err_msg('cx-err:CXER0217', 'CHANNEL_POLICY: buffer= is not accepted on a fan-out stream (the window is retention, not flow)')
		}
		if retention == 'window' && keep < 1 {
			return mk_err_msg('cx-err:CXER0217', 'CHANNEL_POLICY: retention=window requires keep=K (K >= 1)')
		}
		if retention == 'latest' {
			if has_keep {
				return mk_err_msg('cx-err:CXER0217', 'CHANNEL_POLICY: retention=latest holds exactly the newest value — keep= is not a point with it')
			}
			keep = 1
		}
	} else {
		if retention != '' || has_keep {
			return mk_err_msg('cx-err:CXER0217', 'CHANNEL_POLICY: retention=/keep= require sharing=independent (group consumers receive directly)')
		}
	}
	if ch := env.state.channel_get(name) {
		// Re-declaring a channel returns the existing handle — fixtures
		// often re-eval [?channel] inside a [?let] chain. A CONFLICTING
		// re-declaration (different axes) refuses at the handle floor.
		if ch.sharing != sharing || ch.retention != retention
			|| (sharing == 'independent' && ch.keep != keep)
			|| (sharing != 'independent' && ch.buffer != buffer && has_buffer) {
			return mk_err_msg('cx-err:CXER0217', 'CHANNEL_POLICY: channel `${name}` is already declared with different axes — a conflicting re-declaration is refused')
		}
		return mk_channel_handle_axes(ch.name, ch.buffer, ch.sharing, ch.retention)
	}
	rec := &ChannelRecord{
		name: name, buffer: buffer, closed: false, queue: []cx.Node{}
		mu: sync.new_rwmutex()
		sharing: sharing, retention: retention, keep: keep
		sub_pos: map[int]i64{}, sub_closed: map[int]bool{}
	}
	env.state.channel_set(name, rec)
	return mk_channel_handle_axes(name, buffer, sharing, retention)
}

// scalar_or_atom_str reads a string OR atom scalar (axis opts accept both
// spellings: retention=window / retention=:window).
fn scalar_or_atom_str(n cx.Node) string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v.trim_left(':')
		}
	}
	if n is cx.Element {
		return ''
	}
	return ''
}

// mk_err_msg builds a coded err VALUE with a message attribute.
fn mk_err_msg(ecode string, message string) cx.Node {
	return cx.Element{
		name:  'err'
		attrs: [
			cx.Attribute{
				name:  'code'
				value: cx.ScalarValue(ecode)
			},
			cx.Attribute{
				name:  'message'
				value: cx.ScalarValue(message)
			},
		]
	}
}

fn mk_channel_handle(name string, buffer int) cx.Node {
	// scalar handle fields are attributes.
	return cx.Element{
		name:  'channel-handle'
		attrs: [
			cx.Attribute{ name: 'name', value: cx.ScalarValue(name) },
			cx.Attribute{ name: 'buffer', value: cx.ScalarValue(i64(buffer)) },
		]
	}
}

// mk_channel_handle_axes — the classic handle for the default point
// (byte-identical), gaining sharing=/retention= attrs only on a fan-out
// declaration (additive; RULED: U1.11a).
fn mk_channel_handle_axes(name string, buffer int, sharing string, retention string) cx.Node {
	if sharing != 'independent' {
		return mk_channel_handle(name, buffer)
	}
	return cx.Element{
		name:  'channel-handle'
		attrs: [
			cx.Attribute{ name: 'name', value: cx.ScalarValue(name) },
			cx.Attribute{ name: 'sharing', value: cx.ScalarValue(sharing) },
			cx.Attribute{ name: 'retention', value: cx.ScalarValue(retention) },
		]
	}
}

// ── fan-out stream helpers (U1.11a; every access under the channel mu) ──────

// ch_fan_send appends to the retained window; NEVER blocks (the window is
// retention, not flow) — trimming advances the floor, and a lagging
// consumer meets the CXER0218 gap instead of stalling the producer.
fn ch_fan_send(mut ch ChannelRecord, value cx.Node) {
	ch.mu.lock()
	defer { ch.mu.unlock() }
	ch.log << value
	for ch.log.len > ch.keep {
		ch.log.delete(0)
		ch.base++
	}
}

// ch_subscribe registers a consumer cursor. from_pos < 0 = the head (live).
// (id, floor, head, state): state is 'ok' | 'gap' | 'high'.
fn ch_subscribe(mut ch ChannelRecord, from_pos i64) (int, i64, i64, string) {
	ch.mu.lock()
	defer { ch.mu.unlock() }
	head := ch.base + i64(ch.log.len)
	mut cur := head
	if from_pos >= 0 {
		if from_pos < ch.base {
			return 0, ch.base, head, 'gap'
		}
		if from_pos > head {
			return 0, ch.base, head, 'high'
		}
		cur = from_pos
	}
	ch.next_sub++
	ch.sub_pos[ch.next_sub] = cur
	return ch.next_sub, ch.base, head, 'ok'
}

// ch_sub_next advances one subscription cursor. (value, floor, state):
// state ∈ 'ok' | 'gap' | 'empty' | 'drained' | 'closed-sub' | 'unknown'.
fn ch_sub_next(mut ch ChannelRecord, id int) (cx.Node, i64, string) {
	ch.mu.lock()
	defer { ch.mu.unlock() }
	null := cx.Node(cx.ScalarNode{ value: cx.ScalarValue(cx.NullValue{}), data_type: .null_type })
	if ch.sub_closed[id] or { false } {
		return null, ch.base, 'closed-sub'
	}
	cur := ch.sub_pos[id] or { return null, ch.base, 'unknown' }
	if cur < ch.base {
		if ch.retention == 'latest' {
			// retention=latest IS the sanctioned in-process coalescing
			// point (delivery §6, §10.4.1): a lagging consumer drops the
			// missed values and gets the newest — never a gap fault.
			if ch.log.len > 0 {
				v := ch.log[ch.log.len - 1]
				ch.sub_pos[id] = ch.base + i64(ch.log.len)
				return v, ch.base, 'ok'
			}
			ch.sub_pos[id] = ch.base
			return null, ch.base, if ch.closed { 'drained' } else { 'empty' }
		}
		return null, ch.base, 'gap'
	}
	if cur < ch.base + i64(ch.log.len) {
		v := ch.log[int(cur - ch.base)]
		ch.sub_pos[id] = cur + 1
		return v, ch.base, 'ok'
	}
	if ch.closed {
		return null, ch.base, 'drained'
	}
	return null, ch.base, 'empty'
}

// ch_sub_ready — the non-consuming readiness probe: a pending message OR a
// surfaced-on-receive condition (gap / drained) counts as ready.
fn ch_sub_ready(mut ch ChannelRecord, id int) bool {
	ch.mu.rlock()
	defer { ch.mu.runlock() }
	if ch.sub_closed[id] or { false } {
		return false
	}
	cur := ch.sub_pos[id] or { return false }
	if cur < ch.base {
		return true // the gap surfaces loud on receive
	}
	if cur < ch.base + i64(ch.log.len) {
		return true
	}
	return ch.closed
}

// ch_sub_close marks one subscription closed; reports whether it was open.
fn ch_sub_close(mut ch ChannelRecord, id int) bool {
	ch.mu.lock()
	defer { ch.mu.unlock() }
	if (ch.sub_closed[id] or { false }) || id !in ch.sub_pos {
		return false
	}
	ch.sub_closed[id] = true
	return true
}

const channel_sub_name = 'channel-sub'

fn mk_channel_sub(ch_name string, id int, retention string) cx.Node {
	return cx.Element{
		name:  channel_sub_name
		attrs: [
			cx.Attribute{ name: 'channel', value: cx.ScalarValue(ch_name) },
			cx.Attribute{ name: 'id', value: cx.ScalarValue(i64(id)) },
			cx.Attribute{ name: 'rung', value: cx.ScalarValue(':complete-ordered') },
			cx.Attribute{ name: 'sharing', value: cx.ScalarValue('independent') },
			cx.Attribute{ name: 'flow', value: cx.ScalarValue('pull') },
			cx.Attribute{ name: 'retention', value: cx.ScalarValue(retention) },
			cx.Attribute{ name: 'on-close', value: cx.ScalarValue('channel-unsubscribe') },
		]
	}
}

// resolve_channel_sub reads a [channel-sub] value back to (channel, id).
fn resolve_channel_sub(val cx.Node, mut env MatchEnv) ?(&ChannelRecord, int) {
	if val is cx.Element {
		if val.name == channel_sub_name {
			name := val.attr('channel')
			id := val.attr('id').int()
			if ch := env.state.channel_get(name) {
				return ch, id
			}
		}
	}
	return none
}

// eval_subscribe — `[?subscribe from=CH from-pos=INT]` (§10.4.1; RULED:
// U1.11a): a delivery-contract subscription on a fan-out channel. A group
// channel refuses CXER0217; an anchor below the retained window refuses
// CXER0218 carrying the floor; above head refuses CXER0217.
fn eval_subscribe(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	from_node := labeled_slot(d, 'from') or {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?subscribe] requires from=' }
	}
	fval := eval_node(from_node, mut env)!
	mut ch := resolve_channel_value(fval, mut env, 'from=') or {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?subscribe] from= expects a channel handle' }
	}
	if ch.sharing != 'independent' {
		return mk_err_msg('cx-err:CXER0217', 'CHANNEL_POLICY: [?subscribe] needs a sharing=independent channel (group consumers receive directly)')
	}
	mut from_pos := i64(-1)
	if pn := labeled_slot(d, 'from-pos') {
		pv := eval_node(pn, mut env)!
		if v := scalar_int(pv) {
			from_pos = v
		}
	}
	id, floor, head, st := ch_subscribe(mut ch, from_pos)
	if st == 'gap' {
		return cx.Element{
			name:  'err'
			attrs: [
				cx.Attribute{ name: 'code', value: cx.ScalarValue('cx-err:CXER0218') },
				cx.Attribute{ name: 'message', value: cx.ScalarValue('STREAM_GAP: from-pos=${from_pos} is below the retained window; re-subscribe within it') },
				cx.Attribute{ name: 'floor', value: cx.ScalarValue(floor) },
			]
		}
	}
	if st == 'high' {
		return mk_err_msg('cx-err:CXER0217', 'CHANNEL_POLICY: from-pos=${from_pos} is beyond the stream head (${head})')
	}
	sub := mk_channel_sub(ch.name, id, ch.retention)
	// closeable (SAP §5.1): [?with-open] composes; the shared close
	// contract marks the cursor closed, idempotently.
	mut chp := unsafe { ch }
	return closeable_stamp_core(sub, 'channel-unsubscribe', fn [mut chp, id] () ! {
		mut c := unsafe { chp }
		ch_sub_close(mut c, id)
	}, mut env)
}

// closeable_stamp_core registers a CloseableRecord for a core handle and
// stamps the `__cx_close_id__` attr (the bus_stamp_closeable pattern,
// Ring-1-side): [?with-open] and [?close] share one close state.
fn closeable_stamp_core(el cx.Node, label string, close_fn fn () !, mut env MatchEnv) cx.Node {
	if el !is cx.Element {
		return el
	}
	mut e := el as cx.Element
	id := '${env.state.next_close_id}'
	env.state.next_close_id++
	env.state.closeables[id] = &CloseableRecord{
		label:    label
		closed:   false
		close_fn: close_fn
	}
	e.attrs << cx.Attribute{
		name:  close_id_attr
		value: cx.ScalarValue(id)
	}
	return cx.Node(e)
}

// resolve_channel finds the ChannelRecord referenced by an expression.
// The expression is either a $binding holding a channel-handle or a
// direct evaluated channel-handle element.
fn resolve_channel(node cx.ProgramNode, mut env MatchEnv, slot_label string) !&ChannelRecord {
	val := eval_node(node, mut env)!
	return resolve_channel_value(val, mut env, slot_label)
}

// resolve_channel_value is resolve_channel over an ALREADY-evaluated value —
// the consumption verbs evaluate their handle expression once so the
// delivery.md §4 subscription probe and the channel path share one
// evaluation.
fn resolve_channel_value(val cx.Node, mut env MatchEnv, slot_label string) !&ChannelRecord {
	mut name := ''
	if val is cx.Element && val.name == 'channel-handle' {
		name = read_channel_name_from_handle(val)!
	} else {
		return error('${slot_label} expected channel handle')
	}
	ch := env.state.channel_get(name) or {
		return error('channel "${name}" not found')
	}
	return ch
}

// ── Channel access helpers — the ONLY code that touches queue/tokens/closed ──
//
// Concurrent [?worker] threads and the main thread share ChannelRecords, so
// every access serialises on the per-channel mutex (ch.mu, initialised at the
// eval_channel construction site). `tokens` mirrors `queue` index-for-index;
// see the ChannelRecord field docs (matcher.v) for the rendezvous/retract
// rationale.

// ch_enqueue appends `value` and returns its send-token (never 0).
fn ch_enqueue(mut ch ChannelRecord, value cx.Node) u64 {
	ch.mu.lock()
	defer { ch.mu.unlock() }
	ch.next_token++
	ch.queue << value
	ch.tokens << ch.next_token
	return ch.next_token
}

// ch_enqueue_if_space appends only when a buffered channel has capacity;
// reports whether the value was enqueued. (buffer == 0 always has "space"
// here — rendezvous blocking is the SENDER's loop, not a capacity bound.)
fn ch_enqueue_if_space(mut ch ChannelRecord, value cx.Node) bool {
	ch.mu.lock()
	defer { ch.mu.unlock() }
	if ch.buffer > 0 && ch.queue.len >= ch.buffer {
		return false
	}
	ch.next_token++
	ch.queue << value
	ch.tokens << ch.next_token
	return true
}

// ch_try_dequeue pops the FIFO head, or none when the queue is empty.
fn ch_try_dequeue(mut ch ChannelRecord) ?cx.Node {
	ch.mu.lock()
	defer { ch.mu.unlock() }
	if ch.queue.len == 0 {
		return none
	}
	val := ch.queue[0]
	ch.queue.delete(0)
	ch.tokens.delete(0)
	return val
}

// ch_token_pending reports whether the send with token `tok` is still queued
// (false = a receiver consumed it → the rendezvous completed).
fn ch_token_pending(mut ch ChannelRecord, tok u64) bool {
	ch.mu.rlock()
	defer { ch.mu.runlock() }
	return tok in ch.tokens
}

// ch_retract removes the still-queued send with token `tok`; reports whether
// it was found (false = consumed concurrently — the send already completed).
fn ch_retract(mut ch ChannelRecord, tok u64) bool {
	ch.mu.lock()
	defer { ch.mu.unlock() }
	for i, t in ch.tokens {
		if t == tok {
			ch.queue.delete(i)
			ch.tokens.delete(i)
			return true
		}
	}
	return false
}

fn ch_queue_len(mut ch ChannelRecord) int {
	ch.mu.rlock()
	defer { ch.mu.runlock() }
	return ch.queue.len
}

fn ch_is_closed(mut ch ChannelRecord) bool {
	ch.mu.rlock()
	defer { ch.mu.runlock() }
	return ch.closed
}

// ch_mark_closed flips `closed`; reports false when already closed
// (the CXER0203 CHANNEL_ALREADY_CLOSED case).
fn ch_mark_closed(mut ch ChannelRecord) bool {
	ch.mu.lock()
	defer { ch.mu.unlock() }
	if ch.closed {
		return false
	}
	ch.closed = true
	return true
}

// worker_cancel_pending reports whether this evaluation runs inside a
// concurrent [?worker] whose cancellation was requested — the §10.5.4
// signal every worker-side cancellation point checks FIRST (§10.5.7.2
// precedence: cancel-check ▷ everything else).
fn worker_cancel_pending(env MatchEnv) bool {
	if env.current_worker == unsafe { nil } {
		return false
	}
	return env.current_worker.cancelled
}

// chan_poll_interval is the blocked-channel-op polling window (same
// discipline as the [?wait-for] spin).
const chan_poll_interval = time.millisecond

fn eval_send(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	if d.slots.len == 0 {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?send] requires a value' }
	}
	value := eval_node(d.slots[0].value, mut env)!
	to_node := labeled_slot(d, 'to') or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?send] requires :to' }
	}
	mut ch := resolve_channel(to_node, mut env, ':to')!
	// §10.5.4 cancellation point: observed at entry, before any channel state.
	if worker_cancel_pending(env) {
		return EvalError{ code: 'cx-err:CXER0260', message: 'cancellation observed at send' }
	}
	if ch.sharing == 'independent' {
		// a fan-out send NEVER blocks on consumers (U1.11a — the window is
		// retention, not flow; a laggard meets the CXER0218 gap instead).
		if ch_is_closed(mut ch) {
			return mk_err_with_slots('cx-err:CXER0200', [])
		}
		ch_fan_send(mut ch, value)
		return cx.Element{ name: 'ok' }
	}
	if env.current_worker != unsafe { nil } {
		// Worker context: real §10.4.2 blocking semantics. The block is safe
		// here because the main thread (or a sibling worker) keeps running
		// and can receive / close / cancel.
		if ch.buffer == 0 {
			// Rendezvous (§10.4.1): enqueue, then block until a receiver
			// consumes the value — or cancellation/close wins, in which case
			// the value is RETRACTED (a send that did not complete must not
			// leave its value behind).
			if ch_is_closed(mut ch) {
				return mk_err_with_slots('cx-err:CXER0200', [])
			}
			tok := ch_enqueue(mut ch, value)
			for {
				if worker_cancel_pending(env) {
					if ch_retract(mut ch, tok) {
						return EvalError{ code: 'cx-err:CXER0260', message: 'cancellation observed at send' }
					}
					return cx.Element{ name: 'ok' } // consumed concurrently: rendezvous completed first
				}
				if !ch_token_pending(mut ch, tok) {
					return cx.Element{ name: 'ok' }
				}
				if ch_is_closed(mut ch) {
					if ch_retract(mut ch, tok) {
						return mk_err_with_slots('cx-err:CXER0200', [])
					}
					return cx.Element{ name: 'ok' }
				}
				time.sleep(chan_poll_interval)
			}
		}
		// Buffered: block while the buffer is full (§10.4.2), re-checking
		// cancellation first each pass (§10.5.7.2 precedence).
		for {
			if worker_cancel_pending(env) {
				return EvalError{ code: 'cx-err:CXER0260', message: 'cancellation observed at send' }
			}
			if ch_is_closed(mut ch) {
				return mk_err_with_slots('cx-err:CXER0200', [])
			}
			if ch_enqueue_if_space(mut ch, value) {
				return cx.Element{ name: 'ok' }
			}
			time.sleep(chan_poll_interval)
		}
	}
	// Main-thread substrate path: no other thread is guaranteed to exist, so
	// blocking would deadlock a single-threaded program. The historical
	// simplification stands — enqueue unconditionally, return [ok]. Real
	// main-thread blocking ships with the production scheduler.
	if ch_is_closed(mut ch) {
		return mk_err_with_slots('cx-err:CXER0200', [])
	}
	ch_enqueue(mut ch, value)
	return cx.Element{ name: 'ok' }
}

fn eval_receive(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	from_node := labeled_slot(d, 'from') or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?receive] requires :from' }
	}
	from_val := eval_node(from_node, mut env)!
	// the U1.12a batch form (§10.4.3): `max=N` returns the SEQUENCE of
	// messages that arrived (an empty batch after deadline expiry is a
	// value, not a fault); `deadline=` requires `max=` — the
	// single-message timeout fault stays [?try-receive]'s.
	mut max := 0
	if mn := labeled_slot(d, 'max') {
		mv := eval_node(mn, mut env)!
		iv := scalar_int(mv) or { i64(0) }
		if iv < 1 {
			return EvalError{ code: 'cx-err:CXER0108', message: '[?receive] max= must be a positive int' }
		}
		max = int(iv)
	}
	mut deadline := i64(-1)
	if dn := labeled_slot(d, 'deadline') {
		dv := eval_node(dn, mut env)!
		iv := scalar_int(dv) or { i64(-1) }
		if iv < 0 {
			return EvalError{ code: 'cx-err:CXER0108', message: '[?receive] deadline= must be a non-negative int (milliseconds)' }
		}
		deadline = iv
	}
	if deadline >= 0 && max == 0 {
		return EvalError{ code: 'cx-err:CXER0108', message: '[?receive] deadline= requires max= (the batched form); the single-message wait with a timeout fault is [?try-receive]' }
	}
	if worker_cancel_pending(env) {
		return EvalError{ code: 'cx-err:CXER0260', message: 'cancellation observed at receive' }
	}
	// delivery.md §4: the operand is ANY subscription-contract value —
	// a registered Ring-2 subscription (live-sub first; #762 widens)…
	if ops := ring2_sub_ops_for(from_val) {
		return ops.receive(from_val, max, deadline, mut env)
	}
	// …a fan-out channel subscription (U1.11a)…
	if chs, sid := resolve_channel_sub(from_val, mut env) {
		mut chp := unsafe { chs }
		if max > 0 {
			return channel_sub_receive_batch(mut chp, sid, max, deadline, mut env)
		}
		return channel_sub_receive_single(mut chp, sid, mut env)
	}
	// …a worker-lifecycle monitor (U2.1a)…
	if mkey, mw := monitor_sub_key(from_val) {
		if max > 0 {
			mut out := []cx.Node{}
			for out.len < max {
				ev := monitor_receive_single(mkey, mw, mut env)
				if is_err_value(ev) {
					break
				}
				out << ev
			}
			return cx.Element{
				name:  seq_marker_name
				items: out
			}
		}
		return monitor_receive_single(mkey, mw, mut env)
	}
	// …an SSE client stream (http.md §3.6; U1.8a — the sse-connect handle
	// satisfies the delivery.md §4 subscription contract, so the general
	// receive accepts it; `sse-events` stays the module's whole-stream
	// iterator spelling). Pack-gated like every http call site in this
	// file: an embed (CX_PACKS_OFF) build has no sse machinery, and a
	// handle that would need it cannot exist there.
	$if !cx_no_pack_http_client ? {
		if http_sse_is_source(from_val) {
			return http_sse_receive(from_val, max, deadline)
		}
	}
	// …or the classic channel.
	mut ch := resolve_channel_value(from_val, mut env, ':from') or {
		// §10.4.3: a value not satisfying the contract is a typed
		// call-shape refusal, never a stray internal error.
		return EvalError{ code: 'cx-err:CXER0100', message: '[?receive] from= expects a subscription-contract value (a channel, a subscription handle): ${err.msg()}' }
	}
	if ch.sharing == 'independent' {
		return mk_err_msg('cx-err:CXER0217', 'CHANNEL_POLICY: a fan-out channel is consumed through [?subscribe] (group consumers receive directly; independent consumers hold cursors)')
	}
	if max > 0 {
		return channel_group_receive_batch(mut ch, max, deadline, mut env)
	}
	// §10.5.4 cancellation point: observed at entry, before any channel state
	// (§10.5.7.2 — a cancelled task reports CXER0260 even when a value is ready).
	if worker_cancel_pending(env) {
		return EvalError{ code: 'cx-err:CXER0260', message: 'cancellation observed at receive' }
	}
	if env.current_worker != unsafe { nil } {
		// Worker context: real §10.4.3 blocking semantics — drain buffered
		// values, then CHANNEL_CLOSED once closed, else block until a value
		// arrives or cancellation wins.
		for {
			if worker_cancel_pending(env) {
				return EvalError{ code: 'cx-err:CXER0260', message: 'cancellation observed at receive' }
			}
			if val := ch_try_dequeue(mut ch) {
				return val
			}
			if ch_is_closed(mut ch) {
				return mk_err_with_slots('cx-err:CXER0200', [])
			}
			time.sleep(chan_poll_interval)
		}
	}
	// Main-thread substrate path (see eval_send): empty + open would
	// deadlock a single-threaded program; return the RECV_TIMEOUT-equivalent
	// err so tests make progress. Real blocking ships with the scheduler.
	if val := ch_try_dequeue(mut ch) {
		return val
	}
	if ch_is_closed(mut ch) {
		return mk_err_with_slots('cx-err:CXER0200', [])
	}
	return mk_err_with_slots('cx-err:CXER0202', [])
}

// channel_sub_receive_single — one delivery from a fan-out subscription:
// the next retained message past the cursor; a cursor below the window is
// the loud CXER0218 gap (carrying the floor); closed-and-drained (or a
// closed subscription) is CHANNEL_CLOSED; empty-but-open blocks in a
// worker (cancel-aware) and answers RECV_TIMEOUT on the main-thread
// substrate (the documented §10.4.3 deviation).
fn channel_sub_receive_single(mut ch ChannelRecord, sid int, mut env MatchEnv) cx.Node {
	for {
		v, floor, st := ch_sub_next(mut ch, sid)
		match st {
			'ok' {
				return v
			}
			'gap' {
				return cx.Element{
					name:  'err'
					attrs: [
						cx.Attribute{ name: 'code', value: cx.ScalarValue('cx-err:CXER0218') },
						cx.Attribute{ name: 'message', value: cx.ScalarValue('STREAM_GAP: the subscription lagged below the retained window (keep=${ch.keep}); re-subscribe to re-seed') },
						cx.Attribute{ name: 'floor', value: cx.ScalarValue(floor) },
					]
				}
			}
			'drained', 'closed-sub' {
				return mk_err_with_slots('cx-err:CXER0200', [])
			}
			'unknown' {
				return mk_err_msg('cx-err:CXER0100', '[?receive] — unknown channel subscription')
			}
			else { // 'empty'
				if env.current_worker == unsafe { nil } {
					return mk_err_with_slots('cx-err:CXER0202', [])
				}
				if worker_cancel_pending(env) {
					return mk_err_msg('cx-err:CXER0260', 'cancellation observed at receive')
				}
				time.sleep(chan_poll_interval)
			}
		}
	}
	return mk_err_with_slots('cx-err:CXER0202', [])
}

// channel_sub_receive_batch — the U1.12a batch form over a fan-out
// subscription: up to `max` messages; with `deadline=` whatever arrived
// by expiry (empty allowed); without one, a worker waits for the first
// message (the main thread answers what is available now).
fn channel_sub_receive_batch(mut ch ChannelRecord, sid int, max int, deadline_ms i64, mut env MatchEnv) cx.Node {
	mut out := []cx.Node{}
	sw := time.new_stopwatch()
	for {
		v, floor, st := ch_sub_next(mut ch, sid)
		if st == 'ok' {
			out << v
			if out.len >= max {
				break
			}
			continue
		}
		if st == 'gap' {
			if out.len > 0 {
				break // the gap surfaces on the next receive
			}
			return cx.Element{
				name:  'err'
				attrs: [
					cx.Attribute{ name: 'code', value: cx.ScalarValue('cx-err:CXER0218') },
					cx.Attribute{ name: 'message', value: cx.ScalarValue('STREAM_GAP: the subscription lagged below the retained window (keep=${ch.keep}); re-subscribe to re-seed') },
					cx.Attribute{ name: 'floor', value: cx.ScalarValue(floor) },
				]
			}
		}
		if st in ['drained', 'closed-sub'] {
			if out.len > 0 {
				break
			}
			return mk_err_with_slots('cx-err:CXER0200', [])
		}
		// 'empty'
		if deadline_ms >= 0 {
			if sw.elapsed().milliseconds() >= deadline_ms {
				break
			}
			if worker_cancel_pending(env) {
				return mk_err_msg('cx-err:CXER0260', 'cancellation observed at receive')
			}
			time.sleep(chan_poll_interval)
			continue
		}
		if env.current_worker == unsafe { nil } || out.len > 0 {
			break
		}
		if worker_cancel_pending(env) {
			return mk_err_msg('cx-err:CXER0260', 'cancellation observed at receive')
		}
		time.sleep(chan_poll_interval)
	}
	return cx.Element{
		name:  seq_marker_name
		items: out
	}
}

// channel_group_receive_batch — the batch form over a classic channel.
fn channel_group_receive_batch(mut ch ChannelRecord, max int, deadline_ms i64, mut env MatchEnv) cx.Node {
	mut out := []cx.Node{}
	sw := time.new_stopwatch()
	for {
		if val := ch_try_dequeue(mut ch) {
			out << val
			if out.len >= max {
				break
			}
			continue
		}
		if ch_is_closed(mut ch) {
			if out.len > 0 {
				break
			}
			return mk_err_with_slots('cx-err:CXER0200', [])
		}
		if deadline_ms >= 0 {
			if sw.elapsed().milliseconds() >= deadline_ms {
				break
			}
			if worker_cancel_pending(env) {
				return mk_err_msg('cx-err:CXER0260', 'cancellation observed at receive')
			}
			time.sleep(chan_poll_interval)
			continue
		}
		if env.current_worker == unsafe { nil } || out.len > 0 {
			break
		}
		if worker_cancel_pending(env) {
			return mk_err_msg('cx-err:CXER0260', 'cancellation observed at receive')
		}
		time.sleep(chan_poll_interval)
	}
	return cx.Element{
		name:  seq_marker_name
		items: out
	}
}

// try_timeout_ns reads the OPTIONAL `timeout=DURATION` label the
// code.md §10.4.2 try-variants carry, in nanoseconds. 0 when absent —
// the zero-wait poll, which stays the default. The duration is read by
// the same extract_duration_text / duration_to_ns pair [?timeout] uses,
// so one spelling of a duration cannot mean two things (#816).
//
// A malformed or non-positive duration is REFUSED rather than silently
// treated as zero-wait: silently dropping a spec-defined argument is the
// #793 class this issue belongs to, and answering it with a second
// silent drop would be no fix at all.
fn try_timeout_ns(d cx.ProgramDirective, verb string) !i64 {
	tn := labeled_slot(d, 'timeout') or { return i64(0) }
	dur_text := extract_duration_text(tn) or {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: '${verb} timeout= must be a DURATION literal (e.g. 5s, 250ms)'
		}
	}
	ns := duration_to_ns(dur_text) or {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: '${verb} invalid timeout= duration "${dur_text}"'
		}
	}
	if ns < 0 {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: '${verb} timeout= must not be negative (got "${dur_text}")'
		}
	}
	return ns
}

fn eval_try_send(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	if d.slots.len == 0 {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?try-send] requires a value' }
	}
	value := eval_node(d.slots[0].value, mut env)!
	to_node := labeled_slot(d, 'to') or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?try-send] requires :to' }
	}
	wait_ns := try_timeout_ns(d, '[?try-send]')!
	mut ch := resolve_channel(to_node, mut env, ':to')!
	// §10.5.4: try-variants observe cancellation immediately too.
	if worker_cancel_pending(env) {
		return EvalError{ code: 'cx-err:CXER0260', message: 'cancellation observed at try-send' }
	}
	if ch_is_closed(mut ch) {
		return mk_err_with_slots('cx-err:CXER0200', [])
	}
	// Fan-out (sharing=independent, U1.11a) delivers through the retention
	// window, NOT the group queue — same split `[?send]` makes above and the
	// `[?select]` send-case makes below. Without this branch a try-send onto a
	// fan-out stream answered [ok] while the value sat in the group queue
	// where no subscriber ever looks: a SILENT LOSS, which is the worse half
	// of the class SUP-1e found in the scheduler's tick delivery (that one was
	// merely a dead wire). A fan-out send never blocks and is never
	// buffer-bound — the window is retention, not flow — so there is no
	// timeout path to take here.
	if ch.sharing == 'independent' {
		ch_fan_send(mut ch, value)
		return cx.Element{ name: 'ok' }
	}
	// Buffer-full check: if the queue is at capacity (buffer>0), wait up to
	// `timeout=` for space and only then return SEND_TIMEOUT. With no
	// timeout= the loop body runs exactly once — the zero-wait poll this
	// verb has always been.
	if ch_enqueue_if_space(mut ch, value) {
		return cx.Element{ name: 'ok' }
	}
	if wait_ns > 0 {
		// WALL CLOCK, via the stopwatch the [?receive] batch deadline and
		// the live-subscription receive already use. NOT env.state.clock_now()
		// — that is the VIRTUAL clock, advanced only by explicit
		// clock_advance calls, so a loop waiting on it never terminates.
		// (That is also why [?timeout] reads as it does: it measures
		// LOGICAL time across the body, not a wall-clock wait.)
		sw := time.new_stopwatch()
		for sw.elapsed().nanoseconds() < wait_ns {
			time.sleep(chan_poll_interval)
			// Cancellation and close outrank the deadline (§10.5.7.2
			// precedence), same order the blocking [?send] loop uses.
			if worker_cancel_pending(env) {
				return EvalError{ code: 'cx-err:CXER0260', message: 'cancellation observed at try-send' }
			}
			if ch_is_closed(mut ch) {
				return mk_err_with_slots('cx-err:CXER0200', [])
			}
			if ch_enqueue_if_space(mut ch, value) {
				return cx.Element{ name: 'ok' }
			}
		}
	}
	return mk_err_with_slots('cx-err:CXER0201', [])
}

fn eval_try_receive(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	from_node := labeled_slot(d, 'from') or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?try-receive] requires :from' }
	}
	from_val := eval_node(from_node, mut env)!
	wait_ns := try_timeout_ns(d, '[?try-receive]')!
	// §10.5.4: try-variants observe cancellation immediately too.
	if worker_cancel_pending(env) {
		return EvalError{ code: 'cx-err:CXER0260', message: 'cancellation observed at try-receive' }
	}
	// `timeout=` (§10.4.2) waits for a message instead of polling once.
	// The wait wraps the WHOLE attempt rather than being threaded into
	// each of the four operand kinds below: the retry condition is the
	// single-message empty answer (RECV_TIMEOUT / CXER0202), which every
	// one of them already reports the same way, so one loop keeps all
	// four honest and none of them grows a private notion of waiting.
	// Every other outcome — a value, a closed channel, a stream gap, a
	// policy refusal — is FINAL and returns on the first attempt.
	first := try_receive_once(from_val, mut env)!
	if wait_ns <= 0 || err_code_of(first) != 'cx-err:CXER0202' {
		return first
	}
	// Wall clock — see the note in [?try-send]: env.state.clock_now() is
	// the VIRTUAL clock and would never reach the deadline on its own.
	sw := time.new_stopwatch()
	for sw.elapsed().nanoseconds() < wait_ns {
		time.sleep(chan_poll_interval)
		// Cancellation outranks the deadline (§10.5.7.2), same precedence
		// the blocking [?receive] loop applies.
		if worker_cancel_pending(env) {
			return EvalError{ code: 'cx-err:CXER0260', message: 'cancellation observed at try-receive' }
		}
		again := try_receive_once(from_val, mut env)!
		if err_code_of(again) != 'cx-err:CXER0202' {
			return again
		}
	}
	return mk_err_with_slots('cx-err:CXER0202', [])
}

// try_receive_once is ONE non-blocking delivery attempt over any
// subscription-contract operand — the whole of [?try-receive]'s original
// body, lifted so the `timeout=` wait above can retry it without
// duplicating any operand's semantics.
fn try_receive_once(from_val cx.Node, mut env MatchEnv) !cx.Node {
	// §10.4.3 (RULED: U1.2a/U1.5a): the operand is ANY
	// subscription-contract value — non-blocking single delivery.
	if ops := ring2_sub_ops_for(from_val) {
		return ops.receive(from_val, 0, i64(-1), mut env)
	}
	if mkey, mw := monitor_sub_key(from_val) {
		return monitor_receive_single(mkey, mw, mut env)
	}
	if chs, sid := resolve_channel_sub(from_val, mut env) {
		mut chp := unsafe { chs }
		v, floor, st := ch_sub_next(mut chp, sid)
		match st {
			'ok' { return v }
			'gap' {
				return cx.Element{
					name:  'err'
					attrs: [
						cx.Attribute{ name: 'code', value: cx.ScalarValue('cx-err:CXER0218') },
						cx.Attribute{ name: 'message', value: cx.ScalarValue('STREAM_GAP: the subscription lagged below the retained window; re-subscribe to re-seed') },
						cx.Attribute{ name: 'floor', value: cx.ScalarValue(floor) },
					]
				}
			}
			'drained', 'closed-sub' { return mk_err_with_slots('cx-err:CXER0200', []) }
			'unknown' { return mk_err_msg('cx-err:CXER0100', '[?try-receive] — unknown channel subscription') }
			else { return mk_err_with_slots('cx-err:CXER0202', []) }
		}
	}
	mut ch := resolve_channel_value(from_val, mut env, ':from') or {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?try-receive] from= expects a subscription-contract value: ${err.msg()}' }
	}
	if ch.sharing == 'independent' {
		return mk_err_msg('cx-err:CXER0217', 'CHANNEL_POLICY: a fan-out channel is consumed through [?subscribe]')
	}
	if val := ch_try_dequeue(mut ch) {
		return val
	}
	if ch_is_closed(mut ch) {
		return mk_err_with_slots('cx-err:CXER0200', [])
	}
	return mk_err_with_slots('cx-err:CXER0202', [])
}

fn eval_close(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	if d.slots.len == 0 {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?close] requires a channel' }
	}
	close_val := eval_node(d.slots[0].value, mut env)!
	// delivery.md §4: [?close] closes any registered subscription. The
	// handle's `__cx_close_id__` stamp IS the close contract — firing it
	// here shares state with [?with-open], so neither path double-closes
	// (fire_close is idempotent; SAP §5.1).
	if _ := ring2_sub_ops_for(close_val) {
		if cid := closeable_close_id(close_val, mut env) {
			fire_close(cid, mut env)!
			return cx.Element{ name: 'ok' }
		}
	}
	if chs, sid := resolve_channel_sub(close_val, mut env) {
		mut chp := unsafe { chs }
		if !ch_sub_close(mut chp, sid) {
			return mk_err_with_slots('cx-err:CXER0203', [])
		}
		return cx.Element{ name: 'ok' }
	}
	if _, _ := monitor_sub_key(close_val) {
		if cid := closeable_close_id(close_val, mut env) {
			fire_close(cid, mut env)!
			return cx.Element{ name: 'ok' }
		}
		return cx.Element{ name: 'ok' } // already closed — idempotent (SAP §5.1)
	}
	mut ch := resolve_channel_value(close_val, mut env, '[?close]') or {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?close] expects a channel or subscription handle: ${err.msg()}' }
	}
	if !ch_mark_closed(mut ch) {
		return mk_err_with_slots('cx-err:CXER0203', [])
	}
	return cx.Element{ name: 'ok' }
}

// (run_worker_body — the synchronous [?worker] body runner — RETIRED
// with the sync tail; EV-ASYNC-SPAWN, stream 22 W3.)

// ── [?monitor] — the worker-lifecycle subscription (§10.4.6a; U2.1a) ─────────

const monitor_sub_name = 'monitor-sub'

// eval_monitor returns a delivery-contract subscription of one worker's
// lifecycle events: [spawned] first, then the terminal ([cancelled] /
// [panicked] / [done]) — derived from the worker record, so monitoring an
// already-terminated worker delivers its terminal immediately (supervision
// is race-free by construction) and multiple monitors each replay the full
// sequence (fan-out).
fn eval_monitor(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	if d.slots.len == 0 {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?monitor] expects a worker handle' }
	}
	hval := eval_node(d.slots[0].value, mut env)!
	mut wname := ''
	if hval is cx.Element {
		if hval.name == 'worker-handle' {
			wname = hval.attr('name')
		}
	}
	if wname == '' || env.state.worker_get(wname) == none {
		return mk_err_with_slots('cx-err:CXER0222', [])
	}
	env.state.next_monitor++
	mid := env.state.next_monitor
	key := wname + '\x00' + mid.str()
	env.state.monitor_pos[key] = 0
	sub := cx.Element{
		name:  monitor_sub_name
		attrs: [
			cx.Attribute{ name: 'worker', value: cx.ScalarValue(wname) },
			cx.Attribute{ name: 'id', value: cx.ScalarValue(i64(mid)) },
			cx.Attribute{ name: 'rung', value: cx.ScalarValue(':complete-ordered') },
			cx.Attribute{ name: 'sharing', value: cx.ScalarValue('independent') },
			cx.Attribute{ name: 'flow', value: cx.ScalarValue('pull') },
			cx.Attribute{ name: 'retention', value: cx.ScalarValue('full') },
			cx.Attribute{ name: 'on-close', value: cx.ScalarValue('monitor-close') },
		]
	}
	st := env.state
	return closeable_stamp_core(cx.Node(sub), 'monitor-close', fn [st, key] () ! {
		mut s := unsafe { st }
		s.monitor_pos.delete(key)
	}, mut env)
}

// monitor_sub_key reads a [monitor-sub] back to its cursor key + worker.
fn monitor_sub_key(val cx.Node) ?(string, string) {
	if val is cx.Element {
		if val.name == monitor_sub_name {
			w := val.attr('worker')
			id := val.attr('id')
			if w != '' && id != '' {
				return w + '\x00' + id, w
			}
		}
	}
	return none
}

// monitor_terminal derives the worker's terminal event, or none while it
// runs. Precedence mirrors §10.5.7.1: cancellation is the requested
// outcome; a failed body is [panicked] carrying the err.
fn monitor_terminal(rec &WorkerRecord) ?cx.Node {
	if rec.cancelled {
		return cx.Node(cx.Element{
			name:  'cancelled'
			attrs: [cx.Attribute{ name: 'name', value: cx.ScalarValue(rec.name) }]
		})
	}
	if !rec.done {
		return none
	}
	if is_err_value(rec.result) {
		return cx.Node(cx.Element{
			name:  'panicked'
			attrs: [cx.Attribute{ name: 'name', value: cx.ScalarValue(rec.name) }]
			items: [rec.result]
		})
	}
	return cx.Node(cx.Element{
		name:  'done'
		attrs: [cx.Attribute{ name: 'name', value: cx.ScalarValue(rec.name) }]
		items: [rec.result]
	})
}

// monitor_receive_single delivers the next lifecycle event; after the
// terminal, closed-and-drained (the channel-family terminal, CXER0200).
fn monitor_receive_single(key string, wname string, mut env MatchEnv) cx.Node {
	pos := env.state.monitor_pos[key] or {
		return mk_err_with_slots('cx-err:CXER0200', []) // closed monitor
	}
	rec := env.state.worker_get(wname) or {
		return mk_err_with_slots('cx-err:CXER0222', [])
	}
	if pos == 0 {
		env.state.monitor_pos[key] = 1
		return cx.Element{
			name:  'spawned'
			attrs: [cx.Attribute{ name: 'name', value: cx.ScalarValue(wname) }]
		}
	}
	if pos >= 2 {
		return mk_err_with_slots('cx-err:CXER0200', []) // terminal delivered — drained
	}
	for {
		if t := monitor_terminal(rec) {
			env.state.monitor_pos[key] = 2
			return t
		}
		if env.current_worker == unsafe { nil } {
			return mk_err_with_slots('cx-err:CXER0202', [])
		}
		if worker_cancel_pending(env) {
			return mk_err_msg('cx-err:CXER0260', 'cancellation observed at receive')
		}
		time.sleep(chan_poll_interval)
	}
	return mk_err_with_slots('cx-err:CXER0202', [])
}

// monitor_ready — non-consuming readiness: [spawned] undelivered, or the
// terminal available and undelivered.
fn monitor_ready(key string, wname string, mut env MatchEnv) bool {
	pos := env.state.monitor_pos[key] or { return false }
	if pos == 0 {
		return true
	}
	if pos >= 2 {
		return false
	}
	rec := env.state.worker_get(wname) or { return false }
	if _ := monitor_terminal(rec) {
		return true
	}
	return false
}

// (worker_threads_enabled — the CX_WORKER_THREADS=0 semantics dial —
// RETIRED at stream 22 W3: spawn is unconditional per EV-ASYNC-SPAWN;
// the env var is thread-pool sizing only, misc/cli.md.)

// run_worker_thread is the spawned-thread body for a concurrent [?worker]
// (#58). It evaluates the worker body against a private env (cloned
// bindings/closures + shared &ProgramState + the program scope) and publishes
// the terminal result through the locked worker_publish* helpers
// (state_locks.v), which arbitrate against a racing [?cancel] — the cancel
// stamp is never clobbered by a later body completion (§10.5.4). A body
// terminal of CXER0260 (a cancellation point fired, §10.5.4) maps to the
// cancelled state, mirroring drive_future's handling for futures. Concurrent
// map mutations on the shared state are covered by state_locks.v (same
// discipline as the HTTP reactor workers).
fn run_worker_thread(rec_ptr &WorkerRecord, state_ptr &ProgramState, binds map[string]cx.Node, closures_snap map[string]Closure, scope_ptr &Scope, dyn []cx.Node, body cx.ProgramNode) {
	mut rec := unsafe { rec_ptr }
	mut wenv := MatchEnv{
		bindings:     binds
		closures:     closures_snap
		state:        unsafe { state_ptr }
		scope:        unsafe { scope_ptr }
		dyn_context:  dyn
		anon_counter: 0
		frame_pool:   &FramePool{}
		// §10.5.4 cancel signal for this body's cancellation points
		// ([?send]/[?receive]/[?check-cancel]/[?sleep]/[?for] boundary).
		current_worker: rec
	}
	$if cx_wstackcheck ? {
		// #58/#63: is THIS worker thread's live stack frame within the bounds vgc's STW
		// scan covers? Allocate first (touch wenv) so the thread is auto-registered, then
		// read its registered [lo,hi]. idx<0 => UNREGISTERED (whole stack unscanned);
		// &wenv outside [lo,hi] => MIS-BOUNDED registration. Either => the root miss.
		mut wsc_touch := binds.clone()
		wsc_touch['__wsc'] = cx.Node(cx.ScalarNode{ value: cx.ScalarValue('x'), data_type: cx.ScalarType.string_type })
		eprintln('cx#58 wsc_touch_len=${wsc_touch.len}') // force use + alloc before reading stack info
		idx, lo, hi := vgc_my_stack_info()
		waddr := usize(voidptr(&wenv))
		verdict := if idx < 0 {
			'UNREGISTERED (whole worker stack unscanned by STW)'
		} else if waddr >= lo && waddr < hi {
			'in-range OK (not a stack-bounds miss)'
		} else {
			'MIS-BOUNDED (&wenv outside registered [lo,hi])'
		}
		eprintln('cx#58 wstackcheck idx=${idx} lo=0x${u64(lo).hex()} hi=0x${u64(hi).hex()} &wenv=0x${u64(waddr).hex()} -> ${verdict}')
	}
	mut st := unsafe { state_ptr }
	result := eval_node(body, mut wenv) or {
		// Hard EvalError. The cancellation sentinel (a §10.5.4 cancellation
		// point observed the cancel and raised CXER0260) is the CANCELLED
		// terminal, not a worker panic — mirrors drive_future.
		if err.msg().contains('cx-err:CXER0260') {
			st.worker_publish_cancelled(rec)
			return
		}
		st.worker_publish(rec, mk_err_with_slots('cx-err:CXER0220', [
			Slot{ label: 'cause', value: mk_err('inner', err.msg()) },
		]))
		return
	}
	if is_err_value(result) {
		// A CXER0260 err VALUE means the body observed cancellation and
		// returned it as data (e.g. [?check-cancel]'s result) — CANCELLED.
		if err_code_of(result) == 'cx-err:CXER0260' {
			st.worker_publish_cancelled(rec)
			return
		}
		st.worker_publish(rec, mk_err_with_slots('cx-err:CXER0220', [
			Slot{ label: 'cause', value: result },
		]))
		return
	}
	st.worker_publish(rec, result)
}

// eval_worker runs `:body` synchronously and stores the result so
// `[?wait-for :worker $h]` can observe it. True concurrent execution
// (V `spawn`) lands with the Phase 3.10 scheduler alongside async
// futures; the single-threaded substrate satisfies §10.4.6 semantics
// for body-runs-to-completion + observable terminal state.
fn eval_worker(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	name_slot := labeled_slot(d, 'name') or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?worker] requires :name' }
	}
	body := directive_body(d) or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?worker] requires :body' }
	}
	name_val := eval_node(name_slot, mut env)!
	mut name := ''
	if name_val is cx.ScalarNode {
		v := name_val.value
		if v is string { name = v }
	}
	if name == '' {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?worker] :name must evaluate to a non-empty string' }
	}
	mut rec := &WorkerRecord{ name: name, done: false, cancelled: false, result: cx.Node(cx.Element{ name: 'pending' }) }
	env.state.worker_set(name, rec)
	// Register the close-contract (§10.5.7.1): closing the worker handle in
	// a [?with-open] scope cancels-and-joins it. fire_close dispatches on
	// handle_kind; the generic close_fn is a no-op.
	wclose_id := 'worker:${name}'
	env.state.closeables[wclose_id] = &CloseableRecord{
		label:       'worker:${name}'
		closed:      false
		close_fn:    fn () ! {}
		handle_kind: 'worker'
		handle_id:   name
	}
	// #58: concurrent path (the §10.4.6 DEFAULT) — spawn the body on its own V
	// thread so it runs alongside a blocking `[$http:serve {block:true}]`
	// sibling (which the synchronous fallback below would never reach, since
	// it runs the body — possibly a forever-loop — to completion first).
	// [?wait-for] spin-waits on rec.done. UNCONDITIONAL — rule
	// EV-ASYNC-SPAWN (code.md §14.4, stream 22 W3): the synchronous
	// run-to-completion fallback (CX_WORKER_THREADS=0) is RETIRED;
	// the env var is thread-pool sizing only, never a semantics dial.
	rec.concurrent = true
	spawn run_worker_thread(rec, unsafe { env.state }, env.bindings.clone(),
		env.closures.clone(), env.scope, env.dyn_context.clone(), body)
	return mk_worker_handle(name)
}

// (the pre-W3 synchronous [?worker] tail — RETIRED with the lazy
// substrate; EV-ASYNC-SPAWN, stream 22 W3.)

fn mk_worker_handle(name string) cx.Node {
	// The worker handle carries the nominal close-contract marker
	// (`__cx_close_id__`, §10.5.7.1) so [?with-open] recognizes it as
	// closeable and its close cancels-and-joins the worker.
	return cx.Element{
		name:  'worker-handle'
		attrs: [
			cx.Attribute{ name: 'name', value: cx.ScalarValue(name) },
			cx.Attribute{ name: close_id_attr, value: cx.ScalarValue('worker:${name}') },
		]
	}
}

fn read_worker_name_from_handle(el cx.Element) !string {
	nm := el.attr('name')
	if nm != '' {
		return nm
	}
	return error('worker handle missing name')
}

fn eval_worker_handle(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	name_slot := labeled_slot(d, 'name') or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?worker-handle] requires :name' }
	}
	nv := eval_node(name_slot, mut env)!
	mut name := ''
	if nv is cx.ScalarNode {
		v := nv.value
		if v is string { name = v }
	}
	if !env.state.worker_has(name) {
		return mk_err_with_slots('cx-err:CXER0222', [])
	}
	return mk_worker_handle(name)
}

fn eval_wait_for(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	// Two shapes per §10.3.5 / §10.4.6: `:worker $h` or `:service $h`.
	// also `[worker $h]` / `[service $h]` clause-child.
	if w_node := directive_clause(d, 'worker') {
		hv := eval_node(w_node, mut env)!
		if hv is cx.Element && hv.name == 'worker-handle' {
			name := read_worker_name_from_handle(hv)!
			rec := env.state.worker_get(name) or {
				return mk_err_with_slots('cx-err:CXER0222', [])
			}
			// #58 concurrent worker: the body runs on its own thread; block
			// until it finishes (or is cancelled). A forever-worker never sets
			// done → wait-for blocks indefinitely, which is exactly the
			// process-keepalive the non-blocking-serve idiom relies on
			// (main-thread callers: worker_cancel_pending is false there).
			//
			// The join is a §10.5.4 cancellation point ("[?await] / join" in
			// the code.md table) for the CALLING worker too. Without the
			// check below, a worker parked here never observes its own
			// cancellation stamp, so EV-WORKER-EXIT's cancel-and-drain joins
			// it forever: measured 2026-08-23 (supervise sup-012 under the
			// cli profile, full-parallel suite) — main sat in
			// drain_workers_at_exit and the subfn worker sat HERE for 3.5
			// hours, 2187/2187 sample ticks in this spin, while [$sup:stop]'s
			// cascade and the exit drain had both stamped it cancelled.
			if rec.concurrent {
				for !rec.done && !rec.cancelled {
					if worker_cancel_pending(env) {
						return EvalError{ code: 'cx-err:CXER0260', message: 'cancellation observed at wait-for' }
					}
					time.sleep(time.millisecond)
				}
			}
			return rec.result
		}
		return EvalError{ code: 'cx-err:CXER0001', message: '[?wait-for :worker] expects a worker handle' }
	}
	if s_node := directive_clause(d, 'service') {
		// I3: the :service arm belongs to the Ring-2 services substrate;
		// probed via the registry slot (unregistered ⇒ the profile has no
		// service substrate — refuse rather than hang).
		if g_ring2_wait_for_service.len > 0 {
			return g_ring2_wait_for_service[0](s_node, mut env)!
		}
		return EvalError{ code: 'cx-err:CXER0001', message: '[?wait-for :service] requires the platform services substrate (not in this profile)' }
	}
	return EvalError{ code: 'cx-err:CXER0001', message: '[?wait-for] requires :worker / :service / [worker …] / [service …]' }
}

fn eval_cancel(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	// Dual-accept: legacy `:worker $h` AND `[worker $h]`.
	if w_node := directive_clause(d, 'worker') {
		hv := eval_node(w_node, mut env)!
		if hv is cx.Element && hv.name == 'worker-handle' {
			name := read_worker_name_from_handle(hv)!
			mut rec := env.state.worker_get(name) or {
				return mk_err_with_slots('cx-err:CXER0222', [])
			}
			// §10.5.4: [?cancel] REQUESTS cancellation. A worker that already
			// ran to completion stays completed — its terminal value is not
			// retroactively replaced. A still-running worker is marked
			// cancelled; [?wait-for]'s spin exits on the flag and surfaces
			// WORKER_CANCELLED per §10.4.8. The done-check + stamp is one
			// locked transition (worker_request_cancel) so it cannot
			// interleave with the worker thread's terminal publish.
			env.state.worker_request_cancel(rec)
			return cx.Element{ name: 'ok' }
		}
	}
	// Positional handle dispatch — `[?cancel $f]` where $f is a future
	// or worker handle. Distinguish by handle's name attribute.
	if d.slots.len > 0 && d.slots[0].kind == .positional {
		hv := eval_node(d.slots[0].value, mut env)!
		if hv is cx.Element {
			if hv.name == 'future-handle' {
				id := read_future_id(hv) or {
					return EvalError{ code: 'cx-err:CXER0001',
						message: '[?cancel] future-handle missing :id' }
				}
				mut fut := env.state.future_get(id) or {
					return EvalError{ code: 'cx-err:CXER0001',
						message: '[?cancel] no future "${id}"' }
				}
				future_request_cancel(mut fut)
				return cx.Element{ name: 'ok' }
			}
			if hv.name == 'worker-handle' {
				name := read_worker_name_from_handle(hv)!
				mut rec := env.state.worker_get(name) or {
					return mk_err_with_slots('cx-err:CXER0222', [])
				}
				// §10.5.4 request semantics — see the clause-form branch above.
				env.state.worker_request_cancel(rec)
				return cx.Element{ name: 'ok' }
			}
		}
	}
	return EvalError{ code: 'cx-err:CXER0001', message: '[?cancel] requires :worker or future handle' }
}

fn eval_check_cancel(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	// Reads the cancel-flag from the active future (set by drive_future
	// during lazy [?await] eval) OR from the enclosing concurrent [?worker]
	// (set by [?cancel worker=…]). Outside any cancellable context returns
	// ok; where [?cancel] was issued returns CXER0260 (as a VALUE — the
	// §10.5.4 cooperative form a hot loop inspects to short-circuit).
	if active_future_cancelled(env) || worker_cancel_pending(env) {
		return mk_err_with_slots('cx-err:CXER0260', [])
	}
	return cx.Element{ name: 'ok' }
}

fn eval_select(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	// Walk :case slots in source order. The first ready channel case
	// wins (per spec/code.md §10.4.7 "first to become ready";
	// uniform-random tiebreak among simultaneously-ready cases
	// degenerates to source-order on the single-threaded substrate).
	// :timeout cases fire only when no channel case is ready at entry.
	//
	// (5.a) — dual-accepts two case-envelope shapes:
	//   Legacy:  `:case [:from CH $msg HANDLER]`
	//            (labeled slot, label='case', value=cx.ProgramLiteral
	//            cx_element with slots=[label='from'/'timeout', value=…]
	//            and items=[msg-bind?, …, handler])
	//   New:     `[case [from CH $msg] HANDLER]`
	//            (positional slot, value=cx.ProgramLiteral cx_element
	//            name='case' items=[clause_elem, handler] where
	//            clause_elem is cx_element name='from'/'timeout'
	//            items=[channel-or-duration, msg-bind?])
	// `select_case_to_legacy` normalises the new shape into the legacy
	// cx.ProgramLiteral so the downstream walk reads one structure.
	mut timeout_handler := ?cx.ProgramNode(none)
	// EV-SELECT-FAIR (code.md §14.4, stream 22 W2): selection among
	// simultaneously-ready cases MUST NOT be deterministically biased
	// toward source order. Two passes: probe every case's readiness
	// WITHOUT consuming (every probe below is non-consuming), then pick
	// ONE ready case with the scheduler's tiebreak RNG and consume it.
	// (The pre-W2 walk returned the first ready case in source order —
	// exactly the foreclosed divergence.)
	mut ready_cases := []SelReadyCase{}
	for slot in d.slots {
		mut case_lit := cx.ProgramLiteral{ kind: .bool_lit }
		if slot.kind == .labeled && slot.label == 'case' {
			cv := slot.value
			if cv !is cx.ProgramLiteral { continue }
			case_lit = cv as cx.ProgramLiteral
		} else if slot.kind == .positional {
			pv := slot.value
			if pv !is cx.ProgramLiteral { continue }
			pl := pv as cx.ProgramLiteral
			if pl.kind != .cx_element || pl.name != 'case' { continue }
			case_lit = select_case_to_legacy(pl) or { continue }
		} else {
			continue
		}
		if case_lit.kind != .cx_element || case_lit.slots.len == 0 {
			continue
		}
		head := case_lit.slots[0]
		match head.label {
			'from' {
				fval := eval_node(head.value, mut env) or { continue }
				// delivery.md §4: a [?select] from-case accepts any mix of
				// subscriptions and channels (RULED: U1.5a/U1.15a).
				// Readiness is the contract's non-consuming probe.
				if sops := ring2_sub_ops_for(fval) {
					if sops.ready(fval, mut env) {
						ready_cases << SelReadyCase{ kind: .sub, fval: fval, case_lit: case_lit }
					}
					continue
				}
				if chs, sid := resolve_channel_sub(fval, mut env) {
					mut chp := unsafe { chs }
					if ch_sub_ready(mut chp, sid) {
						ready_cases << SelReadyCase{ kind: .chsub, fval: fval, case_lit: case_lit }
					}
					continue
				}
				if mkey, mw := monitor_sub_key(fval) {
					if monitor_ready(mkey, mw, mut env) {
						ready_cases << SelReadyCase{ kind: .monitor, fval: fval, case_lit: case_lit }
					}
					continue
				}
				mut ch := resolve_channel_value(fval, mut env, ':from') or { continue }
				if ch_queue_len(mut ch) > 0 {
					ready_cases << SelReadyCase{ kind: .plain, fval: fval, case_lit: case_lit }
				}
			}
			'to' {
				// the send case (§10.4.7; RULED: U1.15a): ready when the
				// send would not block — a fan-out stream (never blocks),
				// a buffered channel with space, the main-thread substrate
				// (whose sends never block), or a CLOSED channel (whose
				// selection yields the CHANNEL_CLOSED err).
				fval := eval_node(head.value, mut env) or { continue }
				mut ch := resolve_channel_value(fval, mut env, ':to') or { continue }
				closed := ch_is_closed(mut ch)
				ready := closed || ch.sharing == 'independent'
					|| env.current_worker == unsafe { nil }
					|| (ch.buffer > 0 && ch_queue_len(mut ch) < ch.buffer)
				if !ready {
					continue
				}
				if case_lit.items.len < 2 {
					continue
				}
				ready_cases << SelReadyCase{ kind: .send, fval: fval, case_lit: case_lit }
			}
			'timeout' {
				// First timeout case wins as the fallback handler.
				if timeout_handler == none && case_lit.items.len > 0 {
					timeout_handler = case_lit.items[case_lit.items.len - 1]
				}
			}
			else {}
		}
	}
	if ready_cases.len > 0 {
		chosen := ready_cases[select_tiebreak_index(ready_cases.len)]
		case_lit := chosen.case_lit
		match chosen.kind {
			.sub {
				sops := ring2_sub_ops_for(chosen.fval) or {
					return mk_err_with_slots('cx-err:CXER0202', [])
				}
				return run_select_sub_case(chosen.fval, sops, case_lit, mut env)!
			}
			.chsub {
				chs, sid := resolve_channel_sub(chosen.fval, mut env) or {
					return mk_err_with_slots('cx-err:CXER0202', [])
				}
				mut chp := unsafe { chs }
				msg := channel_sub_receive_single(mut chp, sid, mut env)
				return run_select_bound_case(msg, case_lit, mut env)!
			}
			.monitor {
				mkey, mw := monitor_sub_key(chosen.fval) or {
					return mk_err_with_slots('cx-err:CXER0202', [])
				}
				msg := monitor_receive_single(mkey, mw, mut env)
				return run_select_bound_case(msg, case_lit, mut env)!
			}
			.plain {
				return run_select_case(case_lit, mut env)!
			}
			.send {
				mut ch := resolve_channel_value(chosen.fval, mut env, ':to') or {
					return mk_err_with_slots('cx-err:CXER0202', [])
				}
				sval := eval_node(case_lit.items[0], mut env)!
				if ch_is_closed(mut ch) {
					return mk_err_with_slots('cx-err:CXER0200', [])
				}
				if ch.sharing == 'independent' {
					ch_fan_send(mut ch, sval)
				} else {
					ch_enqueue(mut ch, sval)
				}
				handler := case_lit.items[case_lit.items.len - 1]
				return eval_node(handler, mut env)!
			}
		}
	}
	if h := timeout_handler {
		return eval_node(h, mut env)!
	}
	return mk_err_with_slots('cx-err:CXER0202', [])
}

// SelReadyCase records one ready [?select] case between the probe pass
// and the consume pass (EV-SELECT-FAIR).
enum SelReadyKind {
	sub
	chsub
	monitor
	plain
	send
}

struct SelReadyCase {
	kind     SelReadyKind
	fval     cx.Node
	case_lit cx.ProgramLiteral
}

// select_tiebreak_index picks among N simultaneously-ready cases with
// a scheduler-internal xorshift PRNG (seeded once per process from the
// monotonic clock). This is SCHEDULING nondeterminism, not a program
// random capability — no grant is consulted, exactly as no grant
// gates which worker a thread scheduler runs first. The reference
// lane's uniform-distribution check rides §11.4; the conformance bar
// is only MUST-NOT-be-deterministically-source-order-biased.
fn select_tiebreak_index(n int) int {
	if n <= 1 {
		return 0
	}
	mut mu := effects_trace_mu()
	mu.lock()
	if g_select_rng_state == 0 {
		g_select_rng_state = u64(time.sys_mono_now()) | 1
	}
	mut x := g_select_rng_state
	x ^= x << 13
	x ^= x >> 7
	x ^= x << 17
	g_select_rng_state = x
	mu.unlock()
	return int(x % u64(n))
}

// select_case_to_legacy converts the (5.a) clause-envelope
// `[case [from CH $msg] HANDLER]` / `[case [timeout DUR] HANDLER]` into
// the legacy `:case [:from CH $msg HANDLER]` cx.ProgramLiteral shape so
// eval_select / run_select_case can read one structure. Returns `none`
// (via the optional contract) when the case shape is malformed.
//
// Input: `case_lit.name == 'case'`, items = [clause_elem, handler_node]
// where clause_elem.name is 'from' or 'timeout'.
//   `from` clause items: [channel_expr, msg_binding]
//   `timeout` clause items: [duration_expr]
//
// Output: cx.ProgramLiteral{
//   kind=cx_element, name='',
//   slots=[{label: 'from'|'timeout', value: channel_or_duration}],
//   items=[msg_binding?, handler_node]
// }
fn select_case_to_legacy(case_lit cx.ProgramLiteral) ?cx.ProgramLiteral {
	if case_lit.items.len < 2 { return none }
	clause_node := case_lit.items[0]
	if clause_node !is cx.ProgramLiteral { return none }
	clause := clause_node as cx.ProgramLiteral
	if clause.kind != .cx_element { return none }
	handler := case_lit.items[case_lit.items.len - 1]
	match clause.name {
		'from' {
			if clause.items.len < 1 { return none }
			ch_node := clause.items[0]
			mut legacy_items := []cx.ProgramNode{}
			// msg binding (optional — `[from $a]` with no $msg is OK)
			if clause.items.len >= 2 {
				legacy_items << clause.items[1]
			}
			legacy_items << handler
			return cx.ProgramLiteral{
				kind:  .cx_element
				name:  ''
				items: legacy_items
				slots: [cx.ProgramSlot{
					kind:  .labeled
					label: 'from'
					value: ch_node
				}]
				pos: case_lit.pos
			}
		}
		'timeout' {
			if clause.items.len < 1 { return none }
			dur_node := clause.items[0]
			return cx.ProgramLiteral{
				kind:  .cx_element
				name:  ''
				items: [handler]
				slots: [cx.ProgramSlot{
					kind:  .labeled
					label: 'timeout'
					value: dur_node
				}]
				pos: case_lit.pos
			}
		}
		'to' {
			// the send case (§10.4.7; RULED: U1.15a): [case [to CH EXPR] H]
			// — clause items [channel, send-expr].
			if clause.items.len < 2 { return none }
			ch_node := clause.items[0]
			return cx.ProgramLiteral{
				kind:  .cx_element
				name:  ''
				items: [clause.items[1], handler]
				slots: [cx.ProgramSlot{
					kind:  .labeled
					label: 'to'
					value: ch_node
				}]
				pos: case_lit.pos
			}
		}
		else { return none }
	}
}

// run_select_sub_case fires a ready subscription from-case: one unbatched
// receive, the delivery bound to the case's $msg binding (same body shape
// as the channel case).
fn run_select_sub_case(sub cx.Node, ops Ring2SubOps, case_lit cx.ProgramLiteral, mut env MatchEnv) !cx.Node {
	msg := ops.receive(sub, 0, i64(-1), mut env)
	return run_select_bound_case(msg, case_lit, mut env)!
}

// run_select_bound_case runs a from-case handler with an already-received
// delivery bound to its $msg binding.
fn run_select_bound_case(msg cx.Node, case_lit cx.ProgramLiteral, mut env MatchEnv) !cx.Node {
	mut msg_name := ''
	if case_lit.items.len >= 2 {
		first := case_lit.items[0]
		if first is cx.ProgramBinding {
			msg_name = first.name
		}
	}
	mut extended := env.clone()
	if msg_name != '' {
		extended.bindings[msg_name] = msg
	}
	handler := case_lit.items[case_lit.items.len - 1]
	return eval_node(handler, mut extended)!
}

fn run_select_case(case_lit cx.ProgramLiteral, mut env MatchEnv) !cx.Node {
	mut ch_ref := ?&ChannelRecord(none)
	mut msg_name := ''
	for slot in case_lit.slots {
		if slot.label == 'from' {
			ch_ref = resolve_channel(slot.value, mut env, ':from') or { return err }
		}
	}
	if mch := ch_ref {
		mut local_ch := unsafe { mch }
		// Body items: $msg binding + handler expression.
		if case_lit.items.len >= 2 {
			first := case_lit.items[0]
			if first is cx.ProgramBinding {
				msg_name = first.name
			}
		}
		if val := ch_try_dequeue(mut local_ch) {
			mut extended := env.clone()
			if msg_name != '' { extended.bindings[msg_name] = val }
			handler := case_lit.items[case_lit.items.len - 1]
			return eval_node(handler, mut extended)!
		}
	}
	return mk_err_with_slots('cx-err:CXER0202', [])
}

// ── Closures: [?fn] and [?def] ──────────────────────────────────────────────
//
// `[?fn (params) :body expr]` (or `[?fn $x :body expr]` for single-arg
// sugar) creates an anonymous closure. The env captures the current
// lexical scope; calls invoke the body with parameters bound to
// argument values.
//
// `[?def :name foo (params) :body expr]` binds a named closure into
// the current env so subsequent expressions can call it by name.
//
// Closure values flow as cx.Element sentinels with name
// `__cx_closure__` and an attribute `closure_id` carrying the
// closure's identifier. The closure body itself lives in env.closures
// keyed by that identifier.

const closure_sentinel_name = '__cx_closure__'

pub fn mk_closure_sentinel(id string) cx.Node {
	return cx.Element{
		name: closure_sentinel_name
		attrs: [
			cx.Attribute{
				name:  'closure_id'
				value: cx.ScalarValue(id)
			},
		]
	}
}

// is_fn_value reports whether `n` is an opaque function value (closure
// sentinel). Such a value reaching a data-serialization boundary raises
// CXER0291 (§8.6); exposed so the conformance harness can mirror that
// boundary check the canonical `render()` enforces.
pub fn is_fn_value(n cx.Node) bool {
	return n is cx.Element && (n as cx.Element).name == closure_sentinel_name
}

fn closure_id_of(n cx.Node) ?string {
	if n is cx.Element && n.name == closure_sentinel_name {
		for a in n.attrs {
			if a.name == 'closure_id' {
				v := a.value
				if v is string { return v }
			}
		}
	}
	return none
}

// mk_closure_value builds a function-value sentinel that CARRIES its Closure
// (#45). Used for ESCAPING closures — `[?fn]` lambdas and partials — whose
// lifetime / defining scope cannot be a stable scope-table id: the Closure rides
// on the sentinel (cx.OpaqueValue) and travels WITH the value, so it resolves
// wherever applied with no registry. Named `[?def]`s and builtins keep the
// id-only sentinel (mk_closure_sentinel) — their id is durable in the scope tables.
fn mk_closure_value(cl Closure) cx.Node {
	mut el := cx.Element{ name: closure_sentinel_name }
	el.set_opaque(cx.OpaqueValue(ClosureBox{ cl: cl }))
	return el
}

// closure_of returns the Closure embedded on a function-value sentinel, if any
// (an escaping `[?fn]` / partial built by mk_closure_value). none for an id-only
// sentinel (named def / builtin) or a non-sentinel node.
fn closure_of(n cx.Node) ?Closure {
	if n is cx.Element && n.name == closure_sentinel_name {
		if ov := n.opaque() {
			if ov is ClosureBox {
				return ov.cl
			}
		}
	}
	return none
}

// resolve_closure is the single uniform "function-value sentinel → Closure"
// resolver: the EMBEDDED payload first (escaping `[?fn]` / partial — #45), else
// the id → scope-table lookup (named `[?def]` / builtin, durable in env.closures /
// env.scope.closures). Returns none for a non-callable value.
pub fn resolve_closure(n cx.Node, env MatchEnv) ?Closure {
	if cl := closure_of(n) {
		return cl
	}
	if id := closure_id_of(n) {
		return lookup_closure(id, env)
	}
	return none
}

// eval_fn collects parameter names + body from the directive's slots,
// snapshots the env, registers the closure under a synthetic id, and
// returns the sentinel value.
fn eval_fn(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	params, body := extract_params_and_body(d)!
	// Defining scope of this `[?fn]` (uniform lexical scoping, #19/#22/#45):
	//   - TOP-LEVEL `[?fn]` (not in a function body): the program scope (env.scope).
	//     When applied inside a lib member (a predicate/handler/mapper callback to
	//     `[$bus:matches]` / `[$re:replace-fn]` / `[$http:serve]`), its body's free
	//     names resolve where it was DEFINED (the program), not the lib's scope.
	//   - IN-BODY `[?fn]` (created while a `[?def]`/closure body runs): the ENCLOSING
	//     callable's defining_scope (its module / the program), threaded as
	//     env.cur_defining_scope. So a lambda RETURNED from a module def resolves
	//     that module's siblings + consts when later applied (#45 Bug-2). A plain
	//     `[?fn]`-in-`[?fn]` with no enclosing def has cur_defining_scope=nil and
	//     keeps the captured_bindings + caller-closures behavior.
	mut lam_scope := &Scope(unsafe { nil })
	if env.in_function_body {
		lam_scope = env.cur_defining_scope
	} else {
		lam_scope = env.scope
	}
	anon := Closure{
		params:            params
		body:              [body]
		captured_bindings: snapshot_bindings(env)
		defining_scope:    lam_scope
	}
	// The Closure rides ON the sentinel value (#45): no env.closures registration,
	// no program-scope mirror. An escaping lambda thus travels WITH its value and
	// resolves via its embedded payload wherever applied — fixing the lost-anon
	// (Bug-1), wrong-defining-scope (Bug-2), and nested-recapture (Bug-3) failures
	// of the old top-level-mirror scheme, with no registry growth.
	return mk_closure_value(anon)
}

fn snapshot_bindings(env MatchEnv) map[string]cx.Node {
	mut out := map[string]cx.Node{}
	for k, v in env.bindings {
		out[k] = v
	}
	return out
}

// eval_def is the named form: parameter list + body + required :name.
// The closure is registered in env.closures and a sentinel bound under
// the same name in env.bindings so the function name resolves both via
// direct call lookup and via `$name(...)` call-on-binding.
// eval_def registers a program-level [?def] using the single §12.2
// surface: `[?def name (params) body]` with bare params,
// optional `:T` annotations, named/default/`:rest` params, and `:scope`/
// `:pure` modifiers — parsed by the same cx.parse_def the module loader
// uses. The closure carries the full ParamSpec model (D6); a sentinel is
// bound under the name so the function is first-class (D1) and callable
// (recursion sees its own name live via the closures-table fallback).
fn eval_def(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	raw := module_raw_source(d) or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?def] missing source' }
	}
	def := cx.parse_def(raw) or {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?def] parse: ${err.msg()}' }
	}
	// CXER0204 (§12.2): definitions are top/module-level only — a `[?def]`
	// nested inside a `[?fn]` / closure / `[?def]` body is rejected.
	if env.in_function_body {
		return EvalError{
			code:    'cx-err:CXER0204'
			message: 'cx-err:CXER0204 E_NESTED_DEF: `[?def ${def.name}]` is not permitted inside a function body (definitions are top/module-level only)'
		}
	}
	// CXER0205 (§12.2): redeclaring an existing program-level `[?def]`
	// name is rejected. A pre-existing builtin-wrapper closure (lazily
	// registered when a builtin is used as a value) is not a user def, so
	// it does not trip this — only a prior `[?def]` body does.
	if existing := env.closures[def.name] {
		if existing.builtin_name == '' && existing.body.len > 0 {
			return EvalError{
				code:    'cx-err:CXER0205'
				message: 'cx-err:CXER0205 E_DEF_REDECLARED: `${def.name}` is already defined'
			}
		}
	}
	// Static purity check (§6.5.x / D11): a `:pure` (explicit or default)
	// def whose body calls a known-impure builtin / stdlib primitive raises
	// CXER0233; reserved $_position/$_last use raises CXER0231. The impure
	// stdlib primitives are classified in purity_checker.v (derived from the
	// stdlib defs' own purity annotations); all other callees default to
	// pure (param refs / pure primitives). A residual CXER0234 can only come
	// from an unknown DIRECTIVE head in the body — swallowed here as a
	// non-purity concern (the dev-strict validator flags unknown heads).
	pc := new_purity_checker([&def])
	pc.check_def(&def) or {
		m := err.msg()
		if m.contains('CXER0233') || m.contains('CXER0231') {
			return EvalError{ code: m.all_before(' '), message: m }
		}
		// #859: an UNCLASSIFIED BUILTIN 0234 is a real spec violation
		// (§6.5.x closed-list) and propagates; the directive-head 0234
		// stays swallowed as a non-purity concern (the dev-strict
		// validator flags unknown heads). This swallow is what made the
		// checker's builtin branch measure as "not firing" while it was
		// in fact raising.
		if m.contains('CXER0234') && m.contains('unclassified builtin') {
			return EvalError{ code: m.all_before(' '), message: m }
		}
	}
	// Command-contract checks (§12.2.7, stream 6 L109/L110): unknown
	// [effects] capability name → CXER0274 (fail-closed); explicit pure
	// + non-empty [effects] → CXER0239; [compensates NAME] must resolve
	// to an ALREADY-REGISTERED sibling command (script declarations are
	// sequential — module level is order-independent via §12.5).
	if e := command_contract_check_local(&def) {
		return e
	}
	if def.compensates.len > 0 {
		mut target_exists := false
		mut target_is_command := false
		if target := env.closures[def.compensates] {
			if target.builtin_name == '' && target.body.len > 0 {
				target_exists = true
				target_is_command = target.has_effects
			}
		}
		if e := command_compensates_check(&def, target_exists, target_is_command) {
			return e
		}
	}
	body_prog := cx.parse_program(def.body) or {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?def] body parse: ${err.msg()}' }
	}
	env.cow_closures()
	mut new_closure := Closure{
		params:         def_param_names(def)
		is_variadic:    def_is_variadic(def)
		param_specs:    def_param_specs(def)
		body:           [body_prog.body]
		// NO captured_bindings (#341): per §12.2.2 a [?def] body sees its
		// module's siblings + consts + imports by LIVE reference ("Nothing
		// else"), exactly like a module-loaded def (ensure_module_scope).
		// Everything the old def-time snapshot_bindings(env) carried is
		// resolvable live: consts via the defining-scope bindings alias,
		// sibling/self def values via the resolve_fn_value closures fallback.
		// Dropping it also drops the per-call captured-bindings insert loop —
		// the residual closure-call cost — and removes the spec-violating
		// capture of top-level $doc/$input into def bodies.
		// Capture the top-level program scope (#19/#22): the body resolves sibling
		// defs + consts here. The scope is a live reference, so consts loaded later
		// in the §12.5 two-pass are visible at call time.
		defining_scope: env.scope
		declared_impure: def.purity == .impure_
		returns_type:   def.returns_type_source or { '' }
		has_effects:    def.has_effects
		effects_caps:   def_effect_caps(&def)
	}
	if def.is_idempotent {
		win, t2 := command_idem_fields(&def, raw) or {
			m := err.msg()
			return EvalError{ code: m.all_before(' '), message: m }
		}
		new_closure = Closure{
			...new_closure
			is_idempotent:  true
			idem_window_ns: win
			tier2_addr:     t2
		}
	}
	if def.has_effects {
		new_closure = Closure{
			...new_closure
			cmd_meta: command_meta_build(&def, raw)
		}
	}
	env.closures[def.name] = new_closure
	// Mirror into the program scope so a sibling def's body (whose defining_scope
	// is this same scope) can resolve this def by its bare name.
	if env.scope != unsafe { nil } {
		env.scope.closures[def.name] = new_closure
	}
	env.cow_bindings()
	env.bindings[def.name] = mk_closure_sentinel(def.name)
	return cx.Element{
		name: 'result'
		attrs: [
			cx.Attribute{ name: 'status', value: cx.ScalarValue('ok') },
			cx.Attribute{ name: 'defined', value: cx.ScalarValue(def.name) },
		]
	}
}

// extract_params_and_body pulls the parameter list and :body slot
// from a [?fn] / [?def] directive. Parameter forms accepted:
//   $x                — single-arg sugar (positional slot is a binding)
//   ($x, $y, $z)      — paren-list (positional slot is a sequence
//                       literal of bindings)
// params — labeled-slot form (per for ?def)
// The first positional slot (when present) carries the params.
fn extract_params_and_body(d cx.ProgramDirective) !([]string, cx.ProgramNode) {
	mut params := []string{}
	mut body := ?cx.ProgramNode(none)
	mut saw_params := false
	for s in d.slots {
		if s.kind == cx.ProgramSlotKind.labeled {
			if s.label == 'body' {
				body = s.value
			} else if s.label == 'params' {
				params = extract_param_names(s.value)!
				saw_params = true
			} else if s.label == 'name' {
				// handled by caller (eval_def)
			}
			continue
		}
		// First positional slot is the params source unless we already
		// have a labeled :params. Subsequent positional slot is the
		// body (per the spec/code.md §8.3 short form `[?fn $x BODY]`).
		if !saw_params {
			params = extract_param_names(s.value)!
			saw_params = true
			continue
		}
		if body == none {
			body = s.value
		}
	}
	body_node := body or {
		return error('[?fn]/[?def] requires a body (positional or :body slot)')
	}
	return params, body_node
}

// extract_param_names converts a cx.ProgramNode that describes the parameter
// list into a list of strings.
fn extract_param_names(n cx.ProgramNode) ![]string {
	match n {
		cx.ProgramBinding {
			return [n.name]
		}
		cx.ProgramLiteral {
			if n.kind == cx.ProgramLiteralKind.sequence_lit
			   || n.kind == cx.ProgramLiteralKind.array_lit {
				mut out := []string{}
				for it in n.items {
					if it is cx.ProgramBinding {
						out << it.name
					} else {
						return error('parameter list must contain $bindings')
					}
				}
				return out
			}
			return error('parameter list must be a $binding or paren-list of $bindings')
		}
		else {
			return error('parameter list must be a $binding or paren-list of $bindings')
		}
	}
}

fn extract_name(n cx.ProgramNode) ?string {
	match n {
		cx.ProgramLiteral {
			if n.kind == cx.ProgramLiteralKind.string_lit { return n.str_val }
		}
		cx.ProgramCall {
			// Bare ident in expression position parses as zero-arity
			// call; treat its name as the literal name. e.g.
			// `:name foo` parses with foo as a cx.ProgramCall.
			if n.args.len == 0 && !n.fallible && !n.must_succeed {
				return n.name
			}
		}
		else {}
	}
	return none
}

// invoke_closure dispatches to a registered closure. `args` are the
// already-evaluated argument values. Returns the closure body's
// evaluation result in the closure's captured env extended with the
// parameter bindings.
// invoke_closure applies a closure to positional args (no named args).
// Thin wrapper over invoke_closure_l for the many HOF / positional call
// sites that never carry labels.
// try_stdlib_builtin_env runs the env-aware stdlib dispatch chain (the same
// dispatchers dispatch_call_l consults) so a builtin that must apply a CX
// callback or read env — validate's custom-validator, bus emit/match, journal
// fold, sched timers, http/xap handlers — works when reached via a builtin-
// wrapper closure (a same-named self-forward def, is_self_builtin_forward). The
// env-LESS stdlib_builtin cannot resolve a callback. Returns none if no env-aware
// dispatcher claims the name.
fn try_stdlib_builtin_env(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	if r := ft_stdlib_builtin_env(name, args, mut env) { return r }
	$if !cx_no_pack_log ? {
		if r := log_stdlib_builtin_env(name, args, mut env) { return r }
	}
	if r := test_stdlib_builtin_env(name, args, mut env) { return r }
	if r := validate_stdlib_builtin_env(name, args, mut env) { return r }
	if r := prof_stdlib_builtin_env(name, args, mut env) { return r }
	// Ring-2 env packs (http/bus/journal/fabric/xap — the SHARED list;
	// serve-file + store stay main-chain-only, matching the pre-split
	// membership of this chain exactly): I3 registry, ring_registry.v.
	if r := ring2_stdlib_builtin_env_shared(name, args, mut env) { return r }
	$if !cx_no_pack_sched ? {
		if r := sched_stdlib_builtin_env(name, args, mut env) { return r }
	}
	if r := similar_stdlib_builtin_env(name, args, mut env) { return r }
	return none
}

pub fn invoke_closure(c Closure, args []cx.Node, mut enclosing MatchEnv) !cx.Node {
	return invoke_closure_l(c, args, []string{}, mut enclosing)!
}

// invoke_closure_l applies a closure, honoring named call-arguments
// (`labels` parallel to `args`, '' = positional) and the closure's
// param_specs (named / default / rest). Closures without
// param_specs ([?fn] lambdas) use the simple positional / variadic path
// and reject any named args.
const frame_pool_cap = 256

// borrow_frame_map returns a cleared binding map for a closure call frame — reused from
// the per-thread pool when available, else freshly allocated (#36). See FramePool.
@[inline]
fn borrow_frame_map(p &FramePool) map[string]cx.Node {
	if p != unsafe { nil } {
		mut mp := unsafe { p }
		if mp.free.len > 0 {
			return mp.free.pop()
		}
	}
	return map[string]cx.Node{}
}

// return_frame_map hands a finished call frame's binding map back to the per-thread pool
// for reuse (#36). Sound because no live alias of the frame outlives the call (captures
// snapshot/clone). Under -d cx_frame_poison it instead CLEARS without pooling, turning
// any escaped live alias into an empty frame whose missing bindings break the test suite
// — the escape-safety detector.
@[inline]
fn return_frame_map(p &FramePool, mut m map[string]cx.Node) {
	$if cx_frame_poison ? {
		m.clear() // escape detector: an aliased frame now reads empty; do not reuse
		return
	}
	if p == unsafe { nil } {
		return
	}
	mut mp := unsafe { p }
	if mp.free.len >= frame_pool_cap {
		return
	}
	m.clear()
	mp.free << m
}

fn invoke_closure_l(c Closure, args []cx.Node, labels []string, mut enclosing MatchEnv) !cx.Node {
	// Each alternate application shape lives in its own frame (#326 frame
	// diet): at -O0 V allocates stack for every branch's locals whether or
	// not it runs, so the hot [?def] path (param_specs → bind_specs_and_eval)
	// carried the partial-template array, the builtin-chain option temps, and
	// the whole pooled lambda call-env construction per recursion level.
	// Every delegation is a BARE return (#325 direct-return): zero
	// result-struct temporaries on this frame.
	if c.partial_target.len > 0 {
		return invoke_partial_l(c, args, mut enclosing)
	}
	if c.builtin_name != '' {
		return invoke_builtin_closure_l(c, args, mut enclosing)
	}
	if c.has_effects {
		// [requires-at] (stream 10, L156/M26): the pin is an ADMISSION
		// input only a journal-bound runner can evaluate (Ring 1 holds no
		// journal) — an invocation whose pin was not admitted for this
		// commit refuses FAIL-CLOSED, never silently skipped.
		if c.cmd_meta != unsafe { nil } && c.cmd_meta.has_requires_at {
			if !(enclosing.state.pin_admitted[c.cmd_meta.src_addr] or { false }) {
				return mk_err('cx-err:CXER4951', 'E_COORD_PIN_UNEVALUATED: this command carries [requires-at stream="${c.cmd_meta.requires_at_stream}" seq=${c.cmd_meta.requires_at_seq}] — the admission read runs only under a journal-bound commit (authz commit / the saga runner); a direct invocation cannot evaluate the pin (cross_stream_coordination §2)')
			}
		}
		// Command body (code.md §12.2.7, stream 6 L110): narrow the
		// active capability set to (caller's grant ∩ declared [effects])
		// for the body's dynamic extent — [?with-caps]-like, restored on
		// every exit path including error unwind. An effect point outside
		// the declaration raises CXER0271 AT the effect point (checked
		// and enforced, never advisory). Zero cost on the non-command
		// hot path (this branch).
		saved := caps_push_effects_narrowed(c.effects_caps)
		defer {
			caps_restore(saved)
		}
		if c.is_idempotent {
			// Effect-boundary dedup (§12.2.7 / L111, W5): the reserved
			// idempotency-key= caller argument is stripped BEFORE binding
			// (it never binds a parameter); an explicit key wins over the
			// derived one (R12).
			a2, l2, ek := idem_strip_explicit_key(args, labels)
			key0 := if ek != '' { 'x:' + ek } else { '' }
			if c.param_specs.len > 0 {
				return bind_specs_and_eval_k(c, a2, l2, key0, mut enclosing)
			}
			// zero-param command: no frame needed for the derived key.
			key := if key0 != '' { key0 } else { idem_derive_key_zero(c) }
			if hit := idem_lookup(mut enclosing, key) {
				return hit
			}
			res := invoke_positional_l(c, a2, mut enclosing)!
			idem_record_success(mut enclosing, key, res, c.idem_window_ns)
			return res
		}
		if c.param_specs.len > 0 {
			return bind_specs_and_eval(c, args, labels, mut enclosing)
		}
		return invoke_positional_l(c, args, mut enclosing)
	}
	if c.param_specs.len > 0 {
		return bind_specs_and_eval(c, args, labels, mut enclosing)
	}
	return invoke_positional_l(c, args, mut enclosing)
}

// invoke_partial_l applies a partial-application closure: fill the
// template's holes left-to-right with the incoming args, then apply the
// target. Split out of invoke_closure_l (#326).
fn invoke_partial_l(c Closure, args []cx.Node, mut enclosing MatchEnv) !cx.Node {
	mut full := []cx.Node{}
	mut ai := 0
	for t in c.partial_template {
		if is_hole_marker(t) {
			if ai >= args.len {
				return EvalError{ code: 'cx-err:CXER0001', message: 'partial application under-applied' }
			}
			full << args[ai]
			ai++
		} else {
			full << t
		}
	}
	if ai < args.len {
		// E_PARTIAL_APP (code.md §6.3a: over-application is CXER0102, R3.12)
	return EvalError{ code: 'cx-err:CXER0102', message: 'partial application over-applied (E_PARTIAL_APP)' }
	}
	return apply_fn_value(c.partial_target[0], full, mut enclosing)
}

// invoke_builtin_closure_l applies a builtin-wrapping function value:
// dispatch directly to the builtin layer (NOT dispatch_call, which would
// re-enter the lazily-registered builtin closure and loop). Split out of
// invoke_closure_l (#326).
fn invoke_builtin_closure_l(c Closure, args []cx.Node, mut enclosing MatchEnv) !cx.Node {
	if r := invoke_builtin(c.builtin_name, args) {
		return r
	}
	// env-aware stdlib builtins (validate custom-validator, bus/journal/sched
	// callbacks, …) must be reached WITH env — else a wrapper for a same-named
	// self-forward def (is_self_builtin_forward) can't apply its callback.
	if r := try_stdlib_builtin_env(c.builtin_name, args, mut enclosing) {
		return r
	}
	if r := stdlib_builtin(c.builtin_name, args) {
		return r
	}
	// End-of-chain miss for a first-class §6.5 builtin value: same #536
	// argument-naming diagnostic as eval_call_undefined (an err-VALUE, not
	// a raise — error-as-value model), so `[$map $xs $upper]`-style
	// applications report the bad argument rather than a generic shrug.
	if builtin_dispatchable(c.builtin_name) {
		return builtin_args_diagnostic(c.builtin_name, args)
	}
	return EvalError{
		code:    'cx-err:CXER0001'
		message: 'builtin "${c.builtin_name}" not applicable to ${args.len} arg(s)'
	}
}

// invoke_positional_l applies a plain [?fn] lambda (no param_specs) via the
// simple positional / variadic path with the pooled call-frame binding map.
// Split out of invoke_closure_l (#326).
fn invoke_positional_l(c Closure, args []cx.Node, mut enclosing MatchEnv) !cx.Node {
	if c.is_variadic {
		// The last parameter is a `:rest` variadic: the n-1 leading
		// params bind one-to-one; every trailing arg collects into a
		// `__cx_seq__` envelope bound to the last param name
		// D4). At least the leading params must be supplied.
		fixed := c.params.len - 1
		if args.len < fixed {
			return EvalError{
				code:    'cx-err:CXER0001'
				message: 'variadic closure expected at least ${fixed} args, got ${args.len}'
			}
		}
	} else if args.len != c.params.len {
		return EvalError{
			code:    'cx-err:CXER0001'
			message: 'closure expected ${c.params.len} args, got ${args.len}'
		}
	}
	// Build the call env: captured bindings + parameter bindings.
	// The closures table is taken from the *enclosing* env (program-
	// global), so nested closure references resolve correctly. The
	// ProgramState pointer is also threaded through so directives
	// inside the closure body (e.g. [?sleep], [?check-cancel],
	// [?async]) can observe and mutate the program-global state —
	// without this, closure bodies that invoke any state-touching
	// directive dereferenced a nil state pointer and SIGSEGV'd
	// (prerequisite — historical par-map / par-reduce
	// + sleep crash).
	// Alias-vs-pool hybrid (#341, measured on the PR #340 microbench): a
	// defining scope WITH bindings is ALIASED read-only (the #333 CoW — the
	// first in-place write below realizes a private copy via cow_bindings(),
	// one bulk map.clone() instead of the per-key insert loop; 1.94× on the
	// K=200 scope-heavy shape). A lambda with NO defining-scope bindings —
	// the lean HOF-callback case — keeps the #36 pooled frame map: aliasing
	// an empty map there only added a fresh-map alloc per call through
	// cow_bindings (a consistent ~1.4% loss on the reduce shape). Soundness
	// of the alias matches build_param_call_env: the defining scope's owner
	// frame is suspended for the duration of the call (single-threaded eval;
	// workers/async/error-hooks snapshot-or-clone at spawn), so the alias
	// never observes a concurrent defining-scope mutation and never escapes
	// the call. `borrowed` is tracked separately from call_env.bindings so
	// that if the body reassigns call_env.bindings to a foreign map, we still
	// pool only the map we took (never a map aliased elsewhere).
	use_alias := c.defining_scope != unsafe { nil } && c.defining_scope.bindings.len > 0
	mut borrowed := if use_alias {
		map[string]cx.Node{}
	} else {
		borrow_frame_map(enclosing.frame_pool)
	}
	defer {
		if !use_alias {
			return_frame_map(enclosing.frame_pool, mut borrowed)
		}
	}
	mut call_env := MatchEnv{
		bindings:        if use_alias {
			c.defining_scope.bindings
		} else {
			borrowed
		}
		bindings_shared: use_alias
		// Uniform lexical scoping (#19/#22): a callable resolves its free names in
		// its DEFINING scope (its module / the top-level program), not the
		// caller's table. The Scope is built at load and read-only at call time,
		// so this is a single aliased pointer — no per-call clone (B17 preserved).
		// Plain [?fn] lambdas (no defining_scope) keep the prior caller-aliased
		// behavior (they capture local lets via captured_bindings).
		closures:        if c.defining_scope != unsafe { nil } {
			c.defining_scope.closures
		} else {
			enclosing.closures
		}
		closures_shared: true
		scope:           enclosing.scope
		state:           enclosing.state
		anon_counter:    enclosing.anon_counter
		// The active [?with-scope] dynamic context (§8.10.8) reaches
		// transitively into called functions; propagate it so a callee
		// (e.g. [$log:current-scope]) reads the caller's scope. Mirrors
		// bind_specs_and_eval's propagation for the param-spec path.
		dyn_context:      if enclosing.dyn_context.len > 0 { enclosing.dyn_context.clone() } else { enclosing.dyn_context }
		in_function_body: true
		// An in-body `[?fn]` captures this executing closure's defining_scope as its
		// own (eval_fn) — a lambda returned from a module def then resolves that
		// module's siblings when applied (#45 Bug-2).
		cur_defining_scope: c.defining_scope
		frame_pool:       enclosing.frame_pool // propagate within this thread's call chain
		current_worker:   enclosing.current_worker // same-thread call chain keeps the §10.5.4 cancel signal
		eval_budget:      enclosing.eval_budget // same-thread call chain keeps the F4 budget (S6.2)
	}
	// Module consts (the defining scope's value bindings) resolve as free names in
	// the body (aliased above); lexical let-captures (captured_bindings) layer over
	// them; params win. Each write block realizes the private CoW copy first.
	if c.captured_bindings.len > 0 {
		call_env.cow_bindings()
		for k, v in c.captured_bindings {
			call_env.bindings[k] = v
		}
	}
	if c.is_variadic {
		call_env.cow_bindings()
		fixed := c.params.len - 1
		for i in 0 .. fixed {
			call_env.bindings[c.params[i]] = args[i]
		}
		mut rest_items := []cx.Node{}
		for i in fixed .. args.len {
			rest_items << args[i]
		}
		call_env.bindings[c.params[fixed]] = cx.Element{
			name:  seq_marker_name
			items: rest_items
		}
	} else if c.params.len > 0 {
		call_env.cow_bindings()
		for i, p in c.params {
			call_env.bindings[p] = args[i]
		}
	}
	return run_closure_body(c, mut call_env)!
}

// ── Slot helpers ────────────────────────────────────────────────────────────

fn slot_value(d cx.ProgramDirective, _ string, positional_idx int) ?cx.ProgramNode {
	mut count := 0
	for s in d.slots {
		if s.kind == .positional {
			if count == positional_idx {
				return s.value
			}
			count++
		}
	}
	return none
}

pub fn labeled_slot(d cx.ProgramDirective, label string) ?cx.ProgramNode {
	for s in d.slots {
		if s.kind == .labeled && s.label == label {
			return s.value
		}
	}
	return none
}

// clause_child returns the body of an clause child `[label …]`
// carried as a positional slot, or none. A single-item clause body
// returns that item; multiple items return a block literal evaluated in
// order. Complements labeled_slot for the dual-accept transition from
// `:label value` slots to `[label …]` clause children.
fn clause_child(d cx.ProgramDirective, label string) ?cx.ProgramNode {
	for s in d.slots {
		if s.kind != .positional {
			continue
		}
		v := s.value
		if v is cx.ProgramLiteral {
			if v.kind == .cx_element && v.name == label {
				if v.items.len == 1 {
					return v.items[0]
				}
				return cx.ProgramNode(cx.ProgramLiteral{
					kind:  .block
					items: v.items
					pos:   v.pos
				})
			}
		}
	}
	return none
}

// directive_clause returns a directive sub-expression by label, accepting
// both the legacy `:label value` slot and the `[label …]` clause
// child (dual-accept during the surface-reshape transition).
pub fn directive_clause(d cx.ProgramDirective, label string) ?cx.ProgramNode {
	if v := labeled_slot(d, label) {
		return v
	}
	return clause_child(d, label)
}

// directive_body returns the directive's body expression, accepting both
// the legacy `:body E` labeled slot and the trailing positional
// body (`[?retry max=3 E]`). When neither is present, none. The last
// positional slot wins so a single trailing body expression reads
// correctly regardless of any preceding positional clause children.
fn directive_body(d cx.ProgramDirective) ?cx.ProgramNode {
	return directive_body_excluding(d, [])
}

// directive_body_excluding is directive_body with a list of clause-child
// labels to skip. Used by directives whose positional slot list mixes the
// body with clause-children (e.g. `[?fallback BODY [recover-with FN] [on P]]`
// — without the skip, the body extractor picks the last `[on …]` clause
// instead of BODY).
fn directive_body_excluding(d cx.ProgramDirective, clause_labels []string) ?cx.ProgramNode {
	if b := labeled_slot(d, 'body') {
		return b
	}
	// clause-child form: `[body EXPR]` carries the body. When
	// present, return its inner expression and ignore any sibling
	// positionals (the legacy fallback below would otherwise pick the
	// last positional even when an explicit body clause is set).
	if b := clause_child(d, 'body') {
		return b
	}
	mut last := ?cx.ProgramNode(none)
	for s in d.slots {
		if s.kind != .positional {
			continue
		}
		v := s.value
		if v is cx.ProgramLiteral && v.kind == .cx_element {
			// Body-clause already handled above; sibling clause-children
			// (recover-with, on, on-timeout, …) are skipped so the
			// fallback "last positional is body" still reads correctly
			// for the trailing-body form (`[?fallback E [recover-with R]]`).
			if v.name == 'body' || v.name in clause_labels {
				continue
			}
		}
		last = v
	}
	return last
}

// positional_slots returns the directive's positional slot expressions
// in source order. Used by the block-scoping directives ([?with-open] /
// [?with-scope]) whose body is encoded as trailing positional slots.
fn positional_slots(d cx.ProgramDirective) []cx.ProgramNode {
	mut out := []cx.ProgramNode{}
	for s in d.slots {
		if s.kind == .positional {
			out << s.value
		}
	}
	return out
}

// ── Z79f dispatcher-integration bridge ──────────────────────────────────────
//
// `try_eval_match_via_bridge` routes a (the modify twin is retired — one engine)
// `[?match]` / `[?modify]` `cx.ProgramDirective` through the standalone
// evaluators (vcx/code/match_eval.v, vcx/code/modify_eval.v) by way of
// the source round-trip: directive → `program_node_to_source` →
// `cx.parse_match` / `cx.parse_modify` → standalone evaluator. The
// scrutinee / doc are pre-evaluated in the dispatcher's MatchEnv so
// bindings resolve before the bridge hop.
//
// HISTORY, because this comment has been wrong in both directions.
// Originally these were not on the production hop at all. Z79g flipped
// `eval_match` to try the bridge FIRST for multi-arm form and left this
// paragraph stale, so the file claimed the opposite of what it did.
// #850 took it back off the hop — not as a revert but because the bridge
// was measured ~10x slower than the legacy engine it declines to for
// every hard shape (see the note at the bottom of dispatcher_bridge.v).
//
// So today: NOT on the production hop unless `set_match_bridge_on(true)`.
// This remains the bridge-feasibility surface, driven directly by the
// dispatcher-integration tests, and by the #850 differential which turns
// it back on to check that both paths answer identically.

// try_eval_match_via_bridge runs the standalone `eval_match_node`
// pipeline for a multi-arm `[?match]` directive. Returns the result
// node (text-form of the firing arm's body, evaluated via `eval_node`
// against `env`) on success, or `none` when the bridge cannot apply
// (scrutinee structural eval fails, parse-match fails, or no arm
// fires and no `:else` is present — the empty-sequence outcome).
//
// The bridge is intentionally restricted to multi-arm form (presence
// of `:case` / `:when` / `:else` slot labels). Single-arm 2-arg form
// stays on the legacy path.
//
// Z79g: Gap 2 closed — `retype_match_pattern_nodes` re-types each
// `:case` arm's pattern_node via the PROGRAM parser so scalar
// patterns like `:case 200` populate ScalarNode(int_type, 200)
// instead of the cx-data parser's TextNode("200"). Arms that
// contain free `$`-bindings (element-with-bind patterns) fall back
// to the cx-data-parsed shape, but the dispatcher then declines the
// bridge (returns none) because the bridge cannot capture pattern
// bindings — see comment below.
pub fn try_eval_match_via_bridge(d cx.ProgramDirective, mut env MatchEnv) ?cx.Node {
	// Recognise multi-arm shape.
	mut is_multi := false
	for slot in d.slots {
		if slot.kind == .labeled
		   && (slot.label == 'case' || slot.label == 'when' || slot.label == 'else') {
			is_multi = true
			break
		}
	}
	if !is_multi {
		return none
	}
	// Bridge cannot handle pattern shapes that need binding capture
	// (cx.ProgramBinding, cx.ProgramPattern with $bindings) OR wildcard /
	// element-pattern shapes (cx.ProgramCall `_`, cx.ProgramPattern with
	// wildcard / deep heads) — these need the legacy `match_arm_pattern`
	// path. Decline on any `:case` arm whose pattern is one of these
	// shapes.
	for slot in d.slots {
		if slot.kind == .labeled && slot.label == 'case' {
			if !is_bridge_compatible_case_pattern(slot.value) {
				return none
			}
		}
	}
	// Consolidation step 2: lower the cx.ProgramDirective directly to a
	// cx.MatchNode instead of re-parsing emitted source through
	// cx.parse_match (the bridge double-parse that D014 broke). Proven
	// hash-identical to the re-parse by the parser-parity gate. The
	// pattern/body typed-node graft still runs via retype_match_pattern_nodes.
	lowered := lower_program_directive_to_match_node(d) or { return none }
	match_node := retype_match_pattern_nodes(lowered)
	// Pre-evaluate the scrutinee (if any) to a cx.Node.
	mut scrut_node := ?cx.Node(none)
	if d.slots.len > 0 && d.slots[0].kind == .positional {
		val := eval_node(d.slots[0].value, mut env) or { return none }
		scrut_node = ?cx.Node(val)
	}
	mut ctx := EvalContext{
		scrutinee:      ?string(none)
		scrutinee_node: scrut_node
		position:       1
		last:           1
		attrs:          map[string]string{}
	}
	result := eval_match_node(match_node, ctx) or { return none }
	if !result.matched {
		// Empty-sequence outcome. Match legacy's behaviour:
		// the production dispatch returns `cx.Element{name:''}` for no-match
		// multi-arm without :else.
		g_match_bridge_engagements++
		return cx.Node(cx.Element{ name: '' })
	}
	// Always re-parse the body source via `code.parse` and evaluate it
	// against the dispatcher env. The `result.body_value` fast path used
	// to shortcut here, returning the `cx.parse`-data-parsed body node
	// (populated by the parser via `try_parse_snippet_to_node`). That
	// shortcut was semantically wrong for expression bodies — e.g.
	// `$users//u[@name="A"]/@email` parses via `cx.parse` as a TextNode
	// of just `$users//u` (the data parser truncates at the `[@…]`
	// opening bracket because `@name` is not a legal element name), so
	// the bridge returned a wrong-and-truncated literal instead of
	// evaluating the path expression. confirmed gap (B), fixed
	// here: bodies always go through the program-parse + eval_node hop
	// so path expressions, bindings, predicates, directive nests all
	// resolve against the dispatcher env's bindings. The `body_value`
	// slot on `MatchResult` stays populated for standalone-evaluator
	// consumers (see `vcx/tests/v08_match_eval_test.v` Z79d coverage).
	$if cx_debug_match_bridge ? {
		eprintln('BRIDGE body=`${result.body}`')
	}
	body_prog := cx.parse_program(result.body) or {
		$if cx_debug_match_bridge ? {
			eprintln('BRIDGE parse fail: ${err}')
		}
		return none
	}
	val := eval_node(body_prog.body, mut env) or {
		$if cx_debug_match_bridge ? {
			eprintln('BRIDGE eval fail: ${err}')
		}
		return none
	}
	g_match_bridge_engagements++
	return val
}

// has_free_binding_in_program_node returns true when the cx.ProgramNode
// (typically a `:case` slot value) references a `$`-prefixed binding
// anywhere in the AST. The bridge declines to handle such arms
// because the standalone evaluator's pattern matcher does not capture
// bindings — only the legacy `match_arm_pattern` in matcher.v does.
fn has_free_binding_in_program_node(n cx.ProgramNode) bool {
	match n {
		cx.ProgramBinding {
			return true
		}
		cx.ProgramPattern {
			// Pattern body may carry $bindings; conservative check via
			// emitted source.
			return program_node_to_source(n).contains('\$')
		}
		cx.ProgramLiteral {
			for it in n.items {
				if has_free_binding_in_program_node(it) {
					return true
				}
			}
			return false
		}
		cx.ProgramCall {
			for a in n.args {
				if has_free_binding_in_program_node(a) {
					return true
				}
			}
			return false
		}
		else {
			// Conservative: scan emitted source for `$` to catch any
			// shape we don't explicitly handle.
			return program_node_to_source(n).contains('\$')
		}
	}
}

fn program_path_expr_step_predicates_reference_outer_binding(step cx.ProgramPathExprStep) bool {
	for pred in step.predicates {
		if program_path_predicate_references_outer_binding(pred) {
			return true
		}
	}
	return false
}

fn program_path_predicate_references_outer_binding(pred cx.ProgramPathPredicate) bool {
	if body := pred.body {
		if program_node_references_outer_binding(body) {
			return true
		}
	}
	if av := pred.attr_value {
		if program_node_references_outer_binding(av) {
			return true
		}
	}
	return false
}

// program_node_references_outer_binding walks a predicate-body AST and
// reports whether it reads any binding outside the reserved predicate
// set ($_ / $_position / $_last). Bindings nested inside a $_-relative
// path's own predicates count too ($_/member[= $qqq@x 1]).
fn program_node_references_outer_binding(n cx.ProgramNode) bool {
	match n {
		cx.Program {
			return program_node_references_outer_binding(n.body)
		}
		cx.ProgramBinding {
			if n.name !in ['_', '_position', '_last'] {
				return true
			}
			// A reserved-binding read may still carry path steps whose
			// predicates reference outer bindings.
			for step in n.path {
				for pred in step.predicates {
					if program_path_predicate_references_outer_binding(pred) {
						return true
					}
				}
			}
			return false
		}
		cx.ProgramCall {
			for a in n.args {
				if program_node_references_outer_binding(a) {
					return true
				}
			}
			return false
		}
		cx.ProgramDirective {
			for s in n.slots {
				if program_node_references_outer_binding(s.value) {
					return true
				}
			}
			return false
		}
		cx.ProgramForComp {
			for c in n.clauses {
				if src := c.source {
					if program_node_references_outer_binding(src) {
						return true
					}
				}
				if e := c.expr {
					if program_node_references_outer_binding(e) {
						return true
					}
				}
			}
			if program_node_references_outer_binding(n.yield) {
				return true
			}
			if yv := n.yield_value {
				if program_node_references_outer_binding(yv) {
					return true
				}
			}
			return false
		}
		cx.ProgramLiteral {
			for it in n.items {
				if program_node_references_outer_binding(it) {
					return true
				}
			}
			for a in n.attrs {
				if program_node_references_outer_binding(a.value) {
					return true
				}
			}
			if ne := n.name_expr {
				if program_node_references_outer_binding(ne) {
					return true
				}
			}
			return false
		}
		cx.ProgramPathExpr {
			for step in n.steps {
				if program_path_expr_step_predicates_reference_outer_binding(step) {
					return true
				}
			}
			return false
		}
		cx.ProgramPattern {
			// Pattern bodies may carry $bindings; conservative check via
			// emitted source (same posture as has_free_binding_in_program_node).
			return program_node_to_source(n).contains('\$')
		}
		cx.ProgramSliceAccess {
			if program_node_references_outer_binding(n.binding) {
				return true
			}
			for ax in n.axes {
				if program_slice_axis_references_outer_binding(ax) {
					return true
				}
			}
			return false
		}
		cx.ProgramSliceLiteral {
			for ax in n.axes {
				if program_slice_axis_references_outer_binding(ax) {
					return true
				}
			}
			return false
		}
		cx.ProgramWildcard {
			return false
		}
	}
}

fn program_slice_axis_references_outer_binding(ax cx.SliceAxis) bool {
	if s := ax.start {
		if program_node_references_outer_binding(s) {
			return true
		}
	}
	if s := ax.stop {
		if program_node_references_outer_binding(s) {
			return true
		}
	}
	if s := ax.step {
		if program_node_references_outer_binding(s) {
			return true
		}
	}
	return false
}

fn program_path_has_graded_predicate(p cx.ProgramPathExpr) bool {
	for step in p.steps {
		for pred in step.predicates {
			if body := pred.body {
				if program_node_contains_tilde(body) {
					return true
				}
			}
		}
	}
	return false
}

fn program_node_contains_tilde(n cx.ProgramNode) bool {
	match n {
		cx.ProgramLiteral {
			if n.kind == cx.ProgramLiteralKind.cx_element && n.name == '~' {
				return true
			}
			for it in n.items {
				if program_node_contains_tilde(it) {
					return true
				}
			}
		}
		cx.ProgramCall {
			for a in n.args {
				if program_node_contains_tilde(a) {
					return true
				}
			}
		}
		cx.ProgramDirective {
			for s in n.slots {
				if program_node_contains_tilde(s.value) {
					return true
				}
			}
		}
		cx.ProgramPathExpr {
			return program_path_has_graded_predicate(n)
		}
		else {}
	}
	return false
}

// ── stream 10: the [requires-at] pin accessors (the admission seam) ──────────

// command_pin_of answers a command closure's [requires-at] pin
// (stream, seq, hash) — none when the value is not a pinned command.
pub fn command_pin_of(fnv cx.Node, mut env MatchEnv) ?(string, i64, string) {
	id := closure_id_of(fnv) or { return none }
	cl := lookup_closure(id, env) or { return none }
	if cl.cmd_meta == unsafe { nil } || !cl.cmd_meta.has_requires_at {
		return none
	}
	return cl.cmd_meta.requires_at_stream, cl.cmd_meta.requires_at_seq, cl.cmd_meta.requires_at_hash
}

// command_pin_src_addr answers the pinned command's Tier-1 src address
// (the pin_admitted key).
pub fn command_pin_src_addr(fnv cx.Node, mut env MatchEnv) ?string {
	id := closure_id_of(fnv) or { return none }
	cl := lookup_closure(id, env) or { return none }
	if cl.cmd_meta == unsafe { nil } || !cl.cmd_meta.has_requires_at {
		return none
	}
	return cl.cmd_meta.src_addr
}

// command_pin_admit / command_pin_clear bracket ONE admitted commit:
// the journal-bound runner evaluates the admission read, admits, runs
// the body, clears — the flag never outlives the commit.
pub fn command_pin_admit(mut env MatchEnv, src_addr string) {
	env.state.pin_admitted[src_addr] = true
}

pub fn command_pin_clear(mut env MatchEnv, src_addr string) {
	env.state.pin_admitted.delete(src_addr)
}

// command_invoke_labeled invokes a command closure VALUE with labeled
// args — the stream-10 saga runner's step-invocation entry (the full
// invoke path applies: effects narrowing, [idempotent] dedup, and the
// [requires-at] admission check).
pub fn command_invoke_labeled(fnv cx.Node, labels []string, vals []cx.Node, mut env MatchEnv) !cx.Node {
	id := closure_id_of(fnv) or { return error('not a function value') }
	cl := lookup_closure(id, env) or { return error('unknown closure') }
	return invoke_closure_l(cl, vals, labels, mut env)
}

// command_compensator_name answers the [compensates] pairing of a command
// value ('' = none) — the stream-10 runner's reverse-compensation input.
pub fn command_compensator_name(fnv cx.Node, mut env MatchEnv) string {
	id := closure_id_of(fnv) or { return '' }
	cl := lookup_closure(id, env) or { return '' }
	if cl.cmd_meta == unsafe { nil } {
		return ''
	}
	return cl.cmd_meta.compensates
}

// command_invoke_named invokes a registered command by def NAME with
// labeled args (the compensator's invocation — the full invoke path).
pub fn command_invoke_named(name string, labels []string, vals []cx.Node, mut env MatchEnv) !cx.Node {
	cl := lookup_closure(name, env) or { return error('unknown command `${name}`') }
	return invoke_closure_l(cl, vals, labels, mut env)
}
