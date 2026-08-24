@[has_globals]
module code

import cx

// ── §9.6 error hooks — observe / enrich / report (SAP C3z) ─────────────────
//
//   [?with-error-hook ([observe FN] | [enrich FN] | [report …])+ BODY]
//
// `observe` fires at the **raise** stage — the moment a runtime err-value is
// built (mk_err family) within the body's dynamic extent — INDEPENDENT of
// recovery: an err that an inner `[?else]`/`[?match]` recovers immediately is
// still seen (spec/code.md §9.6, the no-"drop-to-a-handler-to-log" guarantee
// the C3c retirement leans on). `enrich` fires at the **propagate** stage —
// when an err crosses this directive's boundary outward — and MUST return an
// err (a non-err return raises cx-err:CXER0110, E_ENRICH_NOT_ERR). `report`
// is the unhandled-at-host terminal; its registration is validated here, but
// host-boundary firing belongs to the program-wide `cx-errors.cx`
// error-pipeline work (see MIGRATION_DECISIONS D007).
//
// O3 sugar: `[observe FN]` ≡ `[observe [using FN]]` (and the same for
// `[enrich]`) — the `[using …]` wrapper is optional; both surfaces are
// normalised at the clause-unwrap below, so behaviour is identical.
//
// Hook frames are PROGRAM-GLOBAL (the stdlib_prof pattern): mk_err runs deep
// inside eval with no env access, so raise-stage observation reaches the
// active frames through a module global. Reset per program (new_env);
// pushed/popped LIFO by eval_with_error_hook. Nested hooks compose
// most-recently-entered-first (§9.6).
//
// Concurrency note: hook frames are not synchronised across `[?map :par]`
// workers; hooks observing errs raised inside parallel workers are
// best-effort (same stance as the prof counters).

@[heap]
pub struct ErrorHookFrame {
pub mut:
	observe_fns []Closure
	enrich_fns  []Closure
	has_report  bool
	// env is the registration-time snapshot (closures table + shared
	// ProgramState pointer) the hook FNs are invoked against.
	env MatchEnv
}

// ErrorHookState is the process-global hook registry, held behind a
// nil-default voidptr (the proven stdlib_caps/store/random pattern —
// `@[has_globals]` enables module-level state without -enable-globals).
@[heap]
struct ErrorHookState {
mut:
	frames []&ErrorHookFrame
	firing bool
}

__global (
	g_error_hooks voidptr
)

fn error_hook_state() &ErrorHookState {
	if g_error_hooks == unsafe { nil } {
		s := &ErrorHookState{}
		g_error_hooks = voidptr(s)
	}
	return unsafe { &ErrorHookState(g_error_hooks) }
}

// error_hooks_reset clears the program-global hook state. Called from
// new_env() so frames never leak across independent programs.
pub fn error_hooks_reset() {
	s := &ErrorHookState{}
	g_error_hooks = voidptr(s)
}

// fire_raise_observe runs every active frame's observe FNs (LIFO across
// frames) against a freshly constructed err-value. Pure side-effect: the
// err is unchanged and keeps flowing exactly as if the hook were absent.
// Reentrancy guard: an observe FN that itself raises/constructs an err does
// NOT re-fire hooks (hook-fault isolation); an observe failure is discarded.
pub fn fire_raise_observe(err_val cx.Node) {
	mut st := error_hook_state()
	if st.frames.len == 0 || st.firing {
		return
	}
	st.firing = true
	defer {
		st.firing = false
	}
	for i := st.frames.len - 1; i >= 0; i-- {
		frame := st.frames[i]
		for f in frame.observe_fns {
			mut call_env := frame.env.clone()
			invoke_closure(f, [err_val], mut call_env) or { continue }
		}
	}
}

// unwrap_using_clause normalises the O3 sugar: `[observe FN]` carries FN
// directly; `[observe [using FN]]` wraps it. Both yield the same FN node.
fn unwrap_using_clause(n cx.ProgramNode) cx.ProgramNode {
	if n is cx.ProgramLiteral {
		if n.kind == .cx_element && n.name == 'using' && n.items.len == 1 {
			return n.items[0]
		}
	}
	return n
}

// eval_with_error_hook implements `[?with-error-hook CLAUSE+ BODY]`.
fn eval_with_error_hook(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	mut observe_fns := []Closure{}
	mut enrich_fns := []Closure{}
	mut has_report := false
	mut clause_count := 0
	for slot in d.slots {
		v := slot.value
		if v is cx.ProgramLiteral {
			if v.kind == .cx_element && v.name in ['observe', 'enrich', 'report'] {
				clause_count++
				if v.name == 'report' {
					// Registration accepted; host-boundary firing is the
					// program-wide error-pipeline phase (D007).
					has_report = true
					continue
				}
				if v.items.len != 1 {
					return EvalError{
						code:    'cx-err:CXER0100'
						message: '[?with-error-hook] [${v.name}] takes exactly one FN (or [using FN])'
					}
				}
				fn_node := unwrap_using_clause(v.items[0])
				sentinel := eval_node(fn_node, mut env)!
				closure := resolve_closure(sentinel, env) or {
					return EvalError{
						code:    'cx-err:CXER0100'
						message: '[?with-error-hook] [${v.name}] requires a function value ([?fn] / [?def] reference)'
					}
				}
				if v.name == 'observe' {
					observe_fns << closure
				} else {
					enrich_fns << closure
				}
			}
		}
	}
	if clause_count == 0 {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: '[?with-error-hook] requires at least one [observe]/[enrich]/[report] clause'
		}
	}
	body := directive_body_excluding(d, ['observe', 'enrich', 'report']) or {
		return EvalError{
			code:    'cx-err:CXER0001'
			message: '[?with-error-hook] requires a body'
		}
	}
	// Snapshot AFTER clause registration so the frame's closures table
	// carries the hook FNs.
	frame := &ErrorHookFrame{
		observe_fns: observe_fns
		enrich_fns:  enrich_fns
		has_report:  has_report
		env:         env.clone()
	}
	mut st := error_hook_state()
	st.frames << frame
	result := eval_node(body, mut env) or {
		// Thrown condition crossing the boundary: pop the frame (the err is
		// leaving this extent), convert to a propagating err-value with the
		// code preserved, and run the propagate-stage enrich chain. (Thrown
		// conditions are NOT observed at raise until C3c's §9.2 propagation
		// rewrite converts them to err-values at the raise site — D007.)
		pop_error_hook_frame()
		err_val := if err is EvalError {
			if err.cause_set {
				mk_err_with_cause(err.code, err.cause)
			} else {
				mk_err(err.code, err.msg())
			}
		} else {
			mk_err('cx-err:CXER0001', err.msg())
		}
		return apply_enrich_chain(frame, err_val, mut env)!
	}
	pop_error_hook_frame()
	if is_err_value(result) {
		return apply_enrich_chain(frame, result, mut env)!
	}
	return result
}

fn pop_error_hook_frame() {
	mut st := error_hook_state()
	if st.frames.len > 0 {
		st.frames.delete(st.frames.len - 1)
	}
}

// apply_enrich_chain runs the frame's enrich FNs in declaration order
// against an err-value crossing the directive boundary. Each FN MUST
// return an err; the derived err keeps propagating (enrich never
// recovers — recovery is [?match]/[?else]/[?fallback], §9.6).
fn apply_enrich_chain(frame &ErrorHookFrame, e cx.Node, mut env MatchEnv) !cx.Node {
	mut cur := e
	for f in frame.enrich_fns {
		mut call_env := env.clone()
		derived := invoke_closure(f, [cur], mut call_env) or {
			return EvalError{
				code:    'cx-err:CXER0001'
				message: '[?with-error-hook] [enrich] hook failed: ${err.msg()}'
			}
		}
		if !is_err_value(derived) {
			return EvalError{
				code:    'cx-err:CXER0110'
				message: 'cx-err:CXER0110 E_ENRICH_NOT_ERR: [enrich [using FN]] returned a non-err value — enrich MUST return an err (§9.6)'
			}
		}
		cur = derived
	}
	return cur
}
