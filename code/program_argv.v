@[has_globals]
module code

import os

// Program argument vector (#926, RULED: PYE-2 / PYE-3).
//
// The run surface is `cx [cx-flags] RESOURCE [program-args...]` — the
// interpreter convention (python / node / ruby). Everything after the
// resource is the PROGRAM's argv, never cx's. The CLI installs it here
// before evaluation as `[resource-path, ...program-args]` (the sys.argv
// shape, env.md §3.2):
//
//   cx tool.cx a b        → ['tool.cx', 'a', 'b']
//   ./tool.cx a b         → ['/abs/tool.cx', 'a', 'b']   (shebang — the
//                            kernel passes the script path + args to cx,
//                            so the two spellings are IDENTICAL here)
//   cx -e 'PROG' a        → ['-e', 'a']
//   cx - a  /  echo P|cx  → ['stdin', 'a'] / ['stdin']
//
// INVARIANT (PYE-2): a program's view of its arguments is independent of
// how it was launched. argv[0] names the resource being run — for the
// sourceless launch modes it is the conventional placeholder ('-e' for an
// inline expression, 'stdin' for a stdin-fed program).
//
// PYE-3: reading program args takes NO capability grant — the caller
// already exercised the authority by typing them at the invocation site,
// exactly as the FILE path itself is supplied without a grant.
// `$env:argv` / `$env:parse-args` read THIS vector; `$env:var`
// (environment — ambient process state) stays behind --allow-env.
//
// State pattern: nil-default `voidptr` box behind `@[has_globals]` — the
// proven caps/store/random pattern (stdlib_caps.v).

__global (
	g_program_argv voidptr
)

struct ProgramArgvBox {
	argv []string
}

// set_program_argv installs the program's argument vector
// ([resource, ...program-args]). Called by the CLI (run surface and
// `cx eval`) after argv parsing, before evaluation. An empty slice
// clears it back to the embedded-host fallback.
pub fn set_program_argv(argv []string) {
	if argv.len == 0 {
		g_program_argv = unsafe { nil }
		return
	}
	b := &ProgramArgvBox{
		argv: argv.clone()
	}
	g_program_argv = voidptr(b)
}

// program_argv returns the installed program argument vector. When no
// launcher installed one (an embedded libcx host, an in-process test
// runner), it falls back to the raw process args — the embedded host IS
// the process, so its os.args are the closest honest answer.
pub fn program_argv() []string {
	if g_program_argv == unsafe { nil } {
		return os.args.clone()
	}
	b := unsafe { &ProgramArgvBox(g_program_argv) }
	return b.argv.clone()
}
