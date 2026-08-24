module code

import os

// ── Strict types — the ONE dial (spec/code.md §12.7; stream 16 W5,
// L64) ───────────────────────────────────────────────────────────────
//
// `--strict` on `cx run`/`cx eval` is the single entry point: the CLI
// calls set_strict_mode_cli(true) and new_env() seeds
// ProgramState.strict from is_strict_mode(). Under strict, declared
// `::T` param annotations and `[returns T]` clauses ENFORCE at the
// value level (CXER0206/0207, build_param_call_env /
// bind_specs_and_eval_k), E2-pinned element-name types validate
// against their pinned schemas, and [?pipe] stage flow pre-checks
// declared types before execution. Default (off) ERASES annotations —
// they are documentation only.
//
// The legacy CX_STRICT_TYPES env var and the declaration-PRESENCE
// validator (validate_def_strict — "every param must carry ::T") are
// RETIRED into this dial (W5): presence-of-annotation was never the
// contract; VALUE conformance under the declared annotations is.
// The marker rides an env var (not a __global) so plain `v test`
// invocations need no -enable-globals.

const cli_strict_marker = '__CX_STRICT_CLI__'

// set_strict_mode_cli is the entry point the CLI parser calls when it
// sees `--strict`. Persists for the process lifetime.
pub fn set_strict_mode_cli(on bool) {
	if on {
		os.setenv(cli_strict_marker, '1', true)
	} else {
		os.unsetenv(cli_strict_marker)
	}
}

// is_strict_mode reports the process-wide strict dial — exactly the
// CLI flag. (CX_STRICT_TYPES retired at W5.)
pub fn is_strict_mode() bool {
	return os.getenv(cli_strict_marker) == '1'
}
