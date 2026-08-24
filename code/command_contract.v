module code

import cx

// command_contract.v — the ONE authority for declaration-level command-
// contract validation (spec/core/code.md §12.2.7; commands_effects
// stream 6, L109/L110). Called from BOTH def registration sites — the
// program-level `eval_def` and the module loader's `ensure_module_scope`
// — so the contract can never have two spellings (R3, stream-6 ledger).
//
// The checks:
//   - `[effects]` capability names come from the closed security.md §2
//     nine-name list — an unknown name is the fail-closed E_CAP_UNKNOWN
//     (CXER0274), the same refusal a typo'd host grant gets (#713/L114).
//   - EXPLICIT `pure` + a non-empty `[effects]` is the static
//     contradiction E_COMMAND_CONTRACT (CXER0239) by the §6.5.1
//     effect-totality theorem. (An UNANNOTATED def with non-empty
//     `[effects]` is impure by implication — the parser resolves the
//     purity default; declaring effects IS declaring impurity.)
//   - `[compensates NAME]` must resolve to a sibling [?def] that is
//     itself a command (has `[effects]`) — violation is CXER0239. The
//     lookup facts are supplied by the registration site (module table
//     vs program closures); the refusal text lives here.

const command_contract_code = 'cx-err:CXER0239'

// command_contract_check_local validates the sibling-independent half
// of the command contract on one parsed DefNode. Returns the typed
// EvalError, or none when the declaration is sound.
pub fn command_contract_check_local(def &cx.DefNode) ?EvalError {
	if !def.has_effects {
		return none
	}
	// Unknown capability name → CXER0274 (fail-closed, C2 posture).
	for item in def.effects {
		if item.cap !in capability_names() {
			return EvalError{
				code:    'cx-err:CXER0274'
				message: 'E_CAP_UNKNOWN: unknown capability `${item.cap}` declared in [effects …] of `${def.name}` — accepted: ${capability_names().join(', ')} (security.md §2; cx-err:CXER0274)'
			}
		}
	}
	// Explicit `pure` + non-empty [effects] → CXER0239 (effect totality).
	if def.purity == .pure_ && def.purity_explicit && def.effects.len > 0 {
		return EvalError{
			code:    command_contract_code
			message: 'E_COMMAND_CONTRACT: `${def.name}` is declared pure with a non-empty [effects …] declaration — a checker-accepted pure body provably reaches no capability-gated effect point (code.md §6.5.1 effect totality), so the declaration is unsatisfiable (cx-err:CXER0239)'
		}
	}
	return none
}

// command_compensates_check validates the `[compensates NAME]` pairing
// with the lookup facts resolved by the registration site:
// `target_exists` — a sibling [?def] of that name exists;
// `target_is_command` — that sibling carries an `[effects]` clause.
pub fn command_compensates_check(def &cx.DefNode, target_exists bool, target_is_command bool) ?EvalError {
	if def.compensates.len == 0 {
		return none
	}
	if !target_exists {
		return EvalError{
			code:    command_contract_code
			message: 'E_COMMAND_CONTRACT: `${def.name}` declares [compensates ${def.compensates}] but no sibling [?def ${def.compensates}] exists (code.md §12.2.7; cx-err:CXER0239)'
		}
	}
	if !target_is_command {
		return EvalError{
			code:    command_contract_code
			message: 'E_COMMAND_CONTRACT: `${def.name}` declares [compensates ${def.compensates}] but `${def.compensates}` is not a command (no [effects …] clause) — a compensating action must itself be a command (code.md §12.2.7; cx-err:CXER0239)'
		}
	}
	return none
}

// def_effect_caps extracts the declared capability names of a command
// def for the runtime narrowing (invoke_closure_l): the closure carries
// this list so the body's dynamic extent runs under
// (caller's grant ∩ declared set). Scope literals are carried on the
// DefNode (v1: carried, enforced per-domain as each scoping domain
// lands — security.md §6 C1).
pub fn def_effect_caps(def &cx.DefNode) []string {
	mut caps := []string{cap: def.effects.len}
	for item in def.effects {
		if item.cap !in caps {
			caps << item.cap
		}
	}
	return caps
}
