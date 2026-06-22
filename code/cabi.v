@[has_globals]
module code
import cx

// ── C ABI: cx_code_eval* family (Phase 3.11) ─────────────────────────────
//
// The cx_code_eval* family is the entry-point surface for
// the CX code evaluator. It coexists with the legacy cx_eval*
// family in vcx/cx/cabi.v until Phase 7 deletes the POC.
//
// Routing rationale (why this file lives in vcx/code/ rather
// than alongside cx_eval* in vcx/cx/cabi.v): the programs module
// imports vcx/cx for the host data model (cx.Node / cx.Element /
// cx.ScalarNode) so the cx → programs → cx import cycle is closed
// here, in the leaf module. Putting these exports in vcx/cx/cabi.v
// would re-open the cycle (cx → programs → cx). The exports are
// still part of the single libcx ABI surface; symbol export goes
// through the linker, not through V's module boundary.
//
// Three exports (one per row of spec/audits/code_abi_v1.md §3):
//   cx_code_eval              — NUL-terminated one-shot
//   cx_code_eval_with_len     — explicit-length one-shot
//   cx_code_eval_streaming    — length-bearing streaming via cb
//
// Error wire format per D3: `CXERnnnn:msg`. EvalError-bearing
// failures (CXER0100 parse / CXER0001 internal) are reformatted by
// `code_err` below so binding callers see a uniform colon-
// separated prefix regardless of which sub-system raised.

// c_string copies an owned V string into a freshly-malloc'd C buffer
// the caller must release via cx_free (spec/abi.md §1.4). Duplicated
// from vcx/cx/cabi.v's identical helper to keep this file
// import-cycle-free; the two definitions stay in lockstep by
// inspection (3 lines each).
fn code_c_string(s string) &char {
	buf := unsafe { malloc(s.len + 1) }
	unsafe { vmemcpy(buf, s.str, s.len + 1) }
	return unsafe { &char(buf) }
}

fn code_c_err(msg string, err_out &&char) &char {
	if err_out != unsafe { nil } {
		unsafe { *err_out = code_c_string(msg) }
	}
	return unsafe { nil }
}

// code_err strips the EvalError `cx-err:` namespace prefix from
// `msg` so the on-the-wire error shape matches `CXERnnnn:msg` per
// D3 of code_abi_v1.md. Non-EvalError messages pass through
// unchanged.
fn code_err(msg string, err_out &&char) &char {
	wire := if msg.starts_with('cx-err:') {
		msg['cx-err:'.len..]
	} else {
		msg
	}
	return code_c_err(wire, err_out)
}

@[export: 'cx_code_eval']
pub fn cx_code_eval(input &char, program &char,
		output_target &char, err_out &&char) &char {
	if program == unsafe { nil } {
		return code_err('CXER0100:cx_code_eval: program must be non-NULL', err_out)
	}
	in_v := if input == unsafe { nil } { '' } else {
		unsafe { cstring_to_vstring(input) }
	}
	prog_v := unsafe { cstring_to_vstring(program) }
	target_v := if output_target == unsafe { nil } { '' } else {
		unsafe { cstring_to_vstring(output_target) }
	}
	out := eval_code(in_v, prog_v, target_v) or {
		return code_err(err.msg(), err_out)
	}
	return code_c_string(out)
}

@[export: 'cx_code_eval_with_len']
pub fn cx_code_eval_with_len(input &char, input_len usize,
		program &char, program_len usize,
		output_target &char, err_out &&char) &char {
	if program == unsafe { nil } || program_len == 0 {
		return code_err('CXER0100:cx_code_eval_with_len: program must be non-NULL and non-empty', err_out)
	}
	in_v := if input == unsafe { nil } || input_len == 0 { '' } else {
		unsafe { tos(&u8(input), int(input_len)) }
	}
	prog_v := unsafe { tos(&u8(program), int(program_len)) }
	target_v := if output_target == unsafe { nil } { '' } else {
		unsafe { cstring_to_vstring(output_target) }
	}
	out := eval_code(in_v, prog_v, target_v) or {
		return code_err(err.msg(), err_out)
	}
	return code_c_string(out)
}

// cx_code_eval_caps is the capability-aware member of the cx_code_eval*
// family (abi.md §3 capability bit 38, spec/core/security.md). It is
// ADDITIVE: `cx_code_eval` / `cx_code_eval_with_len` are unchanged and
// continue to run under the empty (pure-only) default, so existing
// bindings keep working without recompilation. A cap-aware host calls
// this symbol to grant a set explicitly.
//
// `caps` is a NUL-terminated spec string (host grant, deny-by-default):
//   - NULL or "" ⇒ empty set (pure-only) — the spec default
//   - "all" or "*" ⇒ full grant (the --allow-all opt-out)
//   - otherwise a comma/space/tab-separated capability list, e.g.
//     "read,write,net" (resource scoping like "net:host:443" is parsed
//     to the bare capability; per-resource enforcement is a v1 follow-up).
// The process-global set is RESET to empty after the call (success or
// error) so a grant never leaks into a subsequent evaluation.
@[export: 'cx_code_eval_caps']
pub fn cx_code_eval_caps(input &char, program &char,
		output_target &char, caps &char, err_out &&char) &char {
	if program == unsafe { nil } {
		return code_err('CXER0100:cx_code_eval_caps: program must be non-NULL', err_out)
	}
	in_v := if input == unsafe { nil } { '' } else {
		unsafe { cstring_to_vstring(input) }
	}
	prog_v := unsafe { cstring_to_vstring(program) }
	target_v := if output_target == unsafe { nil } { '' } else {
		unsafe { cstring_to_vstring(output_target) }
	}
	caps_v := if caps == unsafe { nil } { '' } else {
		unsafe { cstring_to_vstring(caps) }
	}
	caps_apply_spec(caps_v)
	out := eval_code(in_v, prog_v, target_v) or {
		caps_set_empty()
		return code_err(err.msg(), err_out)
	}
	caps_set_empty()
	return code_c_string(out)
}

// CxProgramWriteCb mirrors include/cx.h `cx_code_write_cb`:
//   typedef int (*cx_code_write_cb)(const char* bytes,
//                                       size_t n, void* user);
type CxProgramWriteCb = fn (bytes &char, n usize, user voidptr) int

// ── cx_code_diagram (Phase 9.1, gate 17) ─────────────────────────────────
//
// Wasm-callable visualization C ABI per spec/abi.md §2.16.2 +
// spec/audits/playground_gate17_design_v1.md §D5. Routes through
// code.parse + code.render_diagram. Mermaid is the only
// format exposed here; SVG / PNG remain CLI-only because graphviz
// is not linked into the wasm build.
//
// Error wire format: an in-band `CXERnnnn:msg`-prefixed string
// (the diagram surface has no semantically distinct soft-error
// channel; every failure is terminal).

@[export: 'cx_code_diagram']
pub fn cx_code_diagram(source &char, source_len usize,
		format &char, format_len usize) &char {
	if source == unsafe { nil } || source_len == 0 {
		return code_c_string('CXER0100:cx_code_diagram: source must be non-NULL and non-empty')
	}
	if format == unsafe { nil } || format_len == 0 {
		return code_c_string('CXER0100:cx_code_diagram: format must be non-NULL and non-empty')
	}
	src_v := unsafe { tos(&u8(source), int(source_len)) }
	fmt_v := unsafe { tos(&u8(format), int(format_len)) }
	// `format` accepts `mermaid` with an optional `:detail` suffix
	// (e.g. `mermaid:compact`, `mermaid:full`, `mermaid:min`); the
	// base must be `mermaid` since SVG/PNG require graphviz on PATH.
	fmt_base := if i := fmt_v.index(':') { fmt_v[..i] } else { fmt_v }
	if fmt_base != 'mermaid' {
		return code_c_string('CXER0100:cx_code_diagram: format \'${fmt_v}\' not supported in wasm (only \'mermaid[:detail]\' is browser-safe; SVG/PNG require graphviz on PATH)')
	}
	prog := cx.parse_program(src_v) or {
		wire := if err.msg().starts_with('cx-err:') {
			err.msg()['cx-err:'.len..]
		} else {
			'CXER0100:parse: ${err.msg()}'
		}
		return code_c_string(wire)
	}
	out := render_diagram(prog, src_v, fmt_v) or {
		wire := if err.msg().starts_with('cx-err:') {
			err.msg()['cx-err:'.len..]
		} else {
			'CXER0001:render: ${err.msg()}'
		}
		return code_c_string(wire)
	}
	return code_c_string(out)
}

// ── cx_code_diagram_with_level ─────────────────────────
//
// New ABI export that delegates to the §D4 / §D13 emitter
// (`code.code_diagram_with_level`) rather than the legacy
// `render_diagram` path. Returns Mermaid text matching 
// auto-detection rule (ERD / CFG / SEQ) at the requested verbosity
// level (0=min, 1=compact, 2=full).
//
// `cx_code_diagram` (the legacy export above) stays as-is for now to
// preserve the wasm playground's existing surface; binding drivers
// migrate to `cx_code_diagram_with_level` per gate 37.13.
@[export: 'cx_code_diagram_with_level']
pub fn cx_code_diagram_with_level(source &char, source_len usize, level i32) &char {
	if source == unsafe { nil } || source_len == 0 {
		return code_c_string('CXER0100:cx_code_diagram_with_level: source must be non-NULL and non-empty')
	}
	src_v := unsafe { tos(&u8(source), int(source_len)) }
	lvl := match level {
		0 { CodeDiagramLevel.min }
		2 { CodeDiagramLevel.full }
		else { CodeDiagramLevel.compact }
	}
	out := code_diagram_with_level(src_v, lvl) or {
		wire := if err.msg().starts_with('cx-err:') {
			err.msg()['cx-err:'.len..]
		} else {
			'CXER0001:code_diagram: ${err.msg()}'
		}
		return code_c_string(wire)
	}
	return code_c_string(out)
}

// Module-global stream callback state. Threading a V closure (the
// natural shape) trips V's runtime-generated mprotect(PROT_EXEC)
// trampolines, which wasm32 can't honour — see the comment in
// cxlib.js's evalCodeStreaming. So we stash the C callback in
// globals and use a plain (non-closure) V sink that reads them.
// Single-threaded model: cx_code_eval_streaming is the only writer;
// it sets / clears the globals across each call. Concurrent streaming
// evaluations within one process are NOT currently supported (the
// streaming eval path carries additional shared state); making the
// streaming evaluator fully re-entrant is tracked in the
// concurrency work (readiness-rubric §15, ROADMAP "jobs:"). Callers
// that need parallel streaming use separate processes today.
__global (
	stream_cb_ptr  voidptr
	stream_cb_user voidptr
)

fn global_stream_sink(chunk string) ! {
	cb := stream_cb_ptr
	if cb == unsafe { nil } { return }
	typed_cb := unsafe { CxProgramWriteCb(cb) }
	rc := unsafe { typed_cb(&char(chunk.str), usize(chunk.len), stream_cb_user) }
	if rc != 0 {
		return error('write_cb returned ${rc}')
	}
}

@[export: 'cx_code_eval_streaming']
pub fn cx_code_eval_streaming(input &char, input_len usize,
		program &char, program_len usize,
		output_target &char,
		write_cb voidptr, user voidptr, err_out &&char) &char {
	if program == unsafe { nil } || program_len == 0 {
		return code_err('CXER0100:cx_code_eval_streaming: program must be non-NULL and non-empty', err_out)
	}
	if write_cb == unsafe { nil } {
		return code_err('CXER0001:cx_code_eval_streaming: write_cb must be non-NULL', err_out)
	}
	in_v := if input == unsafe { nil } || input_len == 0 { '' } else {
		unsafe { tos(&u8(input), int(input_len)) }
	}
	prog_v := unsafe { tos(&u8(program), int(program_len)) }
	target_v := if output_target == unsafe { nil } { '' } else {
		unsafe { cstring_to_vstring(output_target) }
	}
	stream_cb_ptr = write_cb
	stream_cb_user = user
	// The `user` pointer's lowest bit doubles as a per-yield-flush
	// flag (CX_STREAM_UNBUFFERED). Wasm callers that need interactive
	// per-yield chunk delivery (playground streaming output) pass 1;
	// throughput consumers (gate-15 corpus) pass 0 / NULL and keep the
	// default 32 KiB buffer threshold. The bit-folding is safe because
	// the JS callback ignores its `user` argument; non-wasm callers
	// that genuinely use `user` should not touch the low bit.
	unbuffered := (usize(user) & 1) == 1
	eval_code_streaming_opts(in_v, prog_v, target_v, global_stream_sink, unbuffered) or {
		stream_cb_ptr = unsafe { nil }
		stream_cb_user = unsafe { nil }
		return code_err(err.msg(), err_out)
	}
	stream_cb_ptr = unsafe { nil }
	stream_cb_user = unsafe { nil }
	return unsafe { nil }
}

// ── cx_code_ast_json (playground Source Tree view) ───────────────────────
// Parse a CX program and return its structural AST as JSON (UTF-8,
// indented). Differs from cx_to_json (which projects a CX value as
// data-shape JSON and returns null for directive PIs): this entry
// walks the parsed cx.ProgramNode tree so the playground
// can render the program structure — directives, patterns, bindings,
// for-comprehension clauses — in its tree-view. Error wire is in-band
// `CXERnnnn:msg` per the diagram entry.
@[export: 'cx_code_ast_json']
pub fn cx_code_ast_json(source &char, source_len usize) &char {
	if source == unsafe { nil } || source_len == 0 {
		return code_c_string('CXER0100:cx_code_ast_json: source must be non-NULL and non-empty')
	}
	src_v := unsafe { tos(&u8(source), int(source_len)) }
	json := program_ast_json(src_v) or {
		wire := if err.msg().starts_with('cx-err:') {
			err.msg()['cx-err:'.len..]
		} else {
			'CXER0100:program_ast_json: ${err.msg()}'
		}
		return code_c_string(wire)
	}
	return code_c_string(json)
}

// ── cx_wasm_set_wall_sleep ────────────────────────────────────
//
// Wasm host opt-in for blocking [?sleep DUR]. Default: bare wall-clock
// sleep in a wasm build raises CXER0270 (WALL_SLEEP_UNSUPPORTED_IN_HOST)
// to keep browser-main-thread playgrounds responsive. A Web-Worker host
// that can safely block its own thread calls this at init to enable
// real wall-clock [?sleep] semantics; the playground's worker.js does
// exactly this so the demo examples can show observable parallel
// speedup with bare [?sleep DUR] alongside `:mock`.
//
// Process-global flag: set before invoking cx_code_eval* and consumed
// by new_env() when constructing the per-eval ProgramState. Setting
// after an eval has started has no effect on that eval.
//
// Native builds export the symbol for ABI uniformity but the flag is
// ignored — native wall-clock sleep always works.

__global wasm_wall_sleep_opt_in = false

@[export: 'cx_wasm_set_wall_sleep']
pub fn cx_wasm_set_wall_sleep(enabled int) int {
	wasm_wall_sleep_opt_in = enabled != 0
	return 0
}

// wasm_wall_sleep_default returns the current opt-in flag for
// new_env() to seed ProgramState.wasm_wall_sleep_allowed. Kept as a
// thin accessor so the module-global stays private to this file.
pub fn wasm_wall_sleep_default() bool {
	return wasm_wall_sleep_opt_in
}

// cx_wasm_is_asyncify reports whether the wasm build was instrumented
// with emscripten's Asyncify pass — i.e. whether bare wall-clock
// [?sleep DUR] can yield cooperatively on the main browser thread.
// The flag is set at V-build time via `-d asyncify_build` from the
// emcc wrapper script when ASYNCIFY=1. JS callers (cxlib.js) probe
// this symbol to decide whether to opt the main thread into
// wasm_wall_sleep_allowed automatically. Native builds always return
// 0 — the flag has no meaning outside wasm..
@[export: 'cx_wasm_is_asyncify']
pub fn cx_wasm_is_asyncify() int {
	$if asyncify_build ? {
		return 1
	} $else {
		return 0
	}
}
