module cx

// ── Evaluator hook signature ─────────────────────────────────────────────────
//
// Per ADR 0023 §D11 (Amendment #1, 2026-05-18): v0.7.0 reserves a
// minimal hook surface so v0.8.0+ debug adapters (DAP / LSP debug-
// protocol integrations, per-binding profilers, log/trace
// subscribers) can layer onto the evaluator without breaking
// changes. The v0.7.0 commitment is signature stability through 1.0:
// the four hook methods and the HookFrame field set defined here do
// not change except by additive extension (new optional fields, new
// hook methods with no-op defaults).
//
// What v0.7.0 ships:
//   * The EvaluatorHook interface (the four methods)
//   * The HookFrame and EvalOrigin payload structs
//   * NoOpEvaluatorHook concrete implementation as the default that
//     CXLEnv carries — fn:trace and log:* (DD/FF rows) will wire to
//     the real interface when they land, replacing the no-op default
//     in env.hook with a logger-aware implementation
//
// What v0.7.0 does NOT ship (per ADR 0023 §D11 "Out of scope"):
//   * External hook registration through the C ABI (no
//     cx_register_evaluator_hook symbol at v0.7.0)
//   * Pause / resume / step-over / step-into primitives
//   * Watch expressions or call-stack capture beyond per-frame context
//   * Multi-hook composition or ordering rules
//
// Those land at v0.8.0 or v0.9.0 behind their own ADR. The
// commitment here is API shape, not wiring depth.

// EvalOrigin records the provenance of a cx:eval invocation per the
// ADR 0023 §M5 amendment options-map keys. When the caller threaded
// origin-uri / origin-line / origin-col through cx:eval's third
// argument, the resulting frame's eval_origin is Some(EvalOrigin{...});
// otherwise eval_origin is none and consumers should treat it as
// synthetic ($err:eval-origin surfaces { synthetic: true } in that
// case per the ADR).
pub struct EvalOrigin {
pub:
	uri        string  // file:// or other scheme; empty string permitted on synthetic frames
	line       int     // 1-based line within the eval-source string
	column     int     // 1-based column within the eval-source string
	eval_depth int     // 0 at top-level cx:eval, increments on nested invocation
}

// HookFrame is the per-callsite context passed to every EvaluatorHook
// method. Layout is stable through 1.0 except by additive extension.
// Fields not yet populated by a given callsite carry their zero
// values (empty string / 0 / none) — no panic on partial population.
pub struct HookFrame {
pub:
	fn_name     string       // qualified name of the called function (e.g. 'cx:parse', 'log:info', 'upper'); empty for synthetic frames
	arity       int          // number of arguments at this callsite; matches args.len when args is populated
	args        []CXLValue   // evaluated argument values; may be empty for hooks called before argument evaluation
	source_line int          // 1-based line of the call site in its source document
	source_col  int          // 1-based column of the call site in its source document
	eval_depth  int          // current cx:eval recursion depth; 0 at top-level (non-eval) callsites
	eval_origin ?EvalOrigin  // present iff this frame is inside a cx:eval invocation per §M5 amendment
}

// EvaluatorHook is the v0.7.0-reserved interface that v0.8.0+ debug
// adapters and profilers will implement. The four methods correspond
// to the lifecycle of a single callable invocation plus a per-emit
// channel for streaming-output observation. Implementations may
// short-circuit (return early), record state for later inspection,
// or forward to external sinks (DAP server, log file, trace span).
//
// Method semantics:
//   * on_eval_enter — invoked once at the entry of every callable
//     invocation (?fn, ?def, cx:eval, filter call). HookFrame.args is
//     populated with already-evaluated argument values.
//   * on_eval_exit — matched exit on the success path. The result
//     CXLValue is the value the callable returned. Always paired with
//     a prior on_eval_enter for the same frame.
//   * on_eval_error — matched exit on the error path. err is the
//     error message (V's `string` form of the `IError`). Always paired
//     with a prior on_eval_enter for the same frame.
//   * on_value_emit — invoked once per emitted output value, in both
//     buffered (env.out) and streaming (env.stream_cb) modes. Called
//     between on_eval_enter and the matching on_eval_exit. Used by
//     log:* and fn:trace as their reference-implementation surface.
//
// Default behavior: NoOpEvaluatorHook does nothing for all four; this
// is what CXLEnv carries by default and is the v0.7.0 wire-format
// equivalent of "no debugger attached, no trace listener registered."
pub interface EvaluatorHook {
mut:
	on_eval_enter(env &CXLEnv, frame HookFrame)
	on_eval_exit(env &CXLEnv, frame HookFrame, result CXLValue)
	on_eval_error(env &CXLEnv, frame HookFrame, err string)
	on_value_emit(env &CXLEnv, frame HookFrame, value CXLValue)
}

// NoOpEvaluatorHook is the default EvaluatorHook implementation
// CXLEnv carries when no debugger / profiler / log subscriber is
// attached. Every method is a no-op; the compiler optimizes the
// indirect calls away on the hot path under release builds (when
// the concrete type is known statically). All v0.7.0 eval entry
// points (eval_cxl / eval_cxl_streaming / future eval_cxl_with_context)
// initialize env.hook to NoOpEvaluatorHook{} via new_cxl_env so the
// invariant "env.hook is non-nil and callable" holds everywhere the
// hook is dispatched from.
pub struct NoOpEvaluatorHook {}

pub fn (mut h NoOpEvaluatorHook) on_eval_enter(env &CXLEnv, frame HookFrame) {}

pub fn (mut h NoOpEvaluatorHook) on_eval_exit(env &CXLEnv, frame HookFrame, result CXLValue) {}

pub fn (mut h NoOpEvaluatorHook) on_eval_error(env &CXLEnv, frame HookFrame, err string) {}

pub fn (mut h NoOpEvaluatorHook) on_value_emit(env &CXLEnv, frame HookFrame, value CXLValue) {}

// new_noop_hook returns a freshly-allocated NoOpEvaluatorHook value.
// Used by new_cxl_env when initializing CXLEnv.hook to the no-op
// default. Callers that need to swap in a real hook implementation
// at v0.8.0+ (debug adapter, log subscriber, trace span emitter)
// assign their own concrete value to env.hook after construction;
// the no-op default is the only thing v0.7.0 commits to shipping.
pub fn new_noop_hook() NoOpEvaluatorHook {
	return NoOpEvaluatorHook{}
}
