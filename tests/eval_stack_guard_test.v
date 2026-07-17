module main

import os
import testenv

// eval_stack_guard_test.v — deep NON-tail cx recursion must never SIGSEGV (#319).
//
// The failure this pins: the evaluator is a tree-walker and only TAIL calls
// are trampolined (#60), so every non-tail recursion level is a real C-stack
// cycle (eval_node → eval_cx_element → dispatch → run_closure_body →
// eval_tail; ~63 KB/level dev -O0, ~28 KB/level -Os). ~120 levels overflowed
// the default 8 MB stack and died by SIGSEGV — shallow for real programs
// (tree walks over deep docs). The #282 arena test only survived its 120
// non-tail levels by raising the stack rlimit first.
//
// The fix (cx_stack_guard.c + eval_stack_guard.c.v): a per-thread stack
// watermark probed at every eval_node entry. Under ~1 MiB of remaining
// headroom (size/4 on tiny stacks) eval returns the CATCHABLE value-form err
// `cx-err:CXER0272` (E_STACK_EXHAUSTED, spec/core/code.md §9.4/§9.5) instead
// of crashing. Watermark, not a depth counter: the per-level footprint varies
// ~8x between build modes, so only measuring the live stack pointer holds
// across all of them.
//
// Child-process shape (the vgc_oom_loud_test precedent): a SIGSEGV must be
// observable as the child's exit status, never kill the harness. In-process
// happy-path fixtures live in conformance/code.cxd (program-stack-guard-*).

const guard_depth = 1_000_000 // levels; unreachable on any plausible stack

fn cx_bin_guard() string {
	return testenv.cx_bin()
}

fn write_prog(name string, src string) string {
	prog := os.join_path(os.temp_dir(), '${name}_${os.getpid()}.cx')
	os.write_file(prog, src) or { panic(err) }
	return prog
}

// The canonical non-tail shape: the `[+ 1 …]` wrapper makes every recursive
// call non-tail, so each level holds a real C frame until unwind.
fn non_tail_def() string {
	return '[?def sum1 (\$n)\n' + '  [?if [= \$n 0]\n' + '    [then 0]\n' +
		'    [else [+ 1 [sum1 [- \$n 1]]]]]]\n'
}

fn run_child(prefix string, prog string) os.Result {
	return os.execute('${prefix}VNOBUGREPORT=1 ${cx_bin_guard()} ${prog} 2>&1')
}

fn test_deep_non_tail_raises_coded_err_never_segv() {
	prog := write_prog('stack_guard_deep', non_tail_def() + '[sum1 ${guard_depth}]\n')
	defer {
		os.rm(prog) or {}
	}
	res := run_child('', prog)
	// 139 = the shell reporting death by SIGSEGV — the exact pre-#319 shape.
	assert res.exit_code != 139, 'deep non-tail recursion still segfaults (pre-#319 shape):\n${res.output.limit(2000)}'
	assert res.output.contains('cx-err:CXER0272'), 'expected the E_STACK_EXHAUSTED err, got:\n${res.output.limit(2000)}'
}

fn test_deep_non_tail_is_recoverable_by_fallback() {
	// Errors are values (§9.1): CXER0272 railway-propagates and MUST be
	// catchable like any other err — the program recovers and exits clean.
	prog := write_prog('stack_guard_fallback', non_tail_def() +
		'[?fallback [sum1 ${guard_depth}] [recover-with "recovered"]]\n')
	defer {
		os.rm(prog) or {}
	}
	res := run_child('', prog)
	assert res.exit_code == 0, 'fallback-recovered run must exit 0:\n${res.output.limit(2000)}'
	assert res.output.contains('recovered'), 'expected the recover-with value, got:\n${res.output.limit(2000)}'
	assert !res.output.contains('CXER0272'), 'err leaked past [?fallback]:\n${res.output.limit(2000)}'
}

fn test_tail_call_at_same_depth_still_completes() {
	// TCO regression guard (#60): the SAME depth tail-recursively runs in
	// O(1) native stack — the guard must never fire on the trampoline.
	prog := write_prog('stack_guard_tail', '[?def loop (\$n \$acc)\n' +
		'  [?if [= \$n 0]\n' + '    [then \$acc]\n' +
		'    [else [loop [- \$n 1] [+ \$acc 1]]]]]\n' + '[loop ${guard_depth} 0]\n')
	defer {
		os.rm(prog) or {}
	}
	res := run_child('', prog)
	assert res.exit_code == 0, 'tail recursion at guard depth must complete:\n${res.output.limit(2000)}'
	assert res.output.contains('${guard_depth}'), 'wrong tail-loop result:\n${res.output.limit(2000)}'
}

fn test_worker_thread_deep_non_tail_never_crashes() {
	// [?worker] bodies run on their own V thread (8 MB default via V spawn,
	// NOT the main thread's rlimit) — the guard arms per thread, so the
	// worker's own bounds gate it. The stack err surfaces through the
	// §10.4.8 worker-panic wrap: CXER0220 with the CXER0272 cause inside.
	prog := write_prog('stack_guard_worker', non_tail_def() +
		'[?let [= \$w [?worker name="wdeep" [body [sum1 ${guard_depth}]]]] [?wait-for worker=\$w]]\n')
	defer {
		os.rm(prog) or {}
	}
	res := run_child('', prog)
	assert res.exit_code != 139, 'worker-thread deep recursion segfaulted:\n${res.output.limit(2000)}'
	assert res.output.contains('cx-err:CXER0272'), 'worker result must carry the E_STACK_EXHAUSTED cause:\n${res.output.limit(2000)}'
}

fn test_past_old_crash_depth_completes_or_raises_never_segv() {
	// The issue's contract at the old crash depth (~120 levels on 8 MB dev):
	// depth 200 either completes (small frames / big stack) or raises the
	// coded err (big frames / default stack) — NEVER a signal. Both outcomes
	// are legal; the crash is not.
	prog := write_prog('stack_guard_200', non_tail_def() + '[sum1 200]\n')
	defer {
		os.rm(prog) or {}
	}
	res := run_child('', prog)
	assert res.exit_code != 139, 'depth-200 non-tail recursion segfaulted (pre-#319 shape):\n${res.output.limit(2000)}'
	completed := res.output.trim_space() == '200'
	raised := res.output.contains('cx-err:CXER0272')
	assert completed || raised, 'depth 200 must complete or raise CXER0272, got:\n${res.output.limit(2000)}'
}

fn test_raised_rlimit_extends_depth() {
	// The guard measures the REAL stack (macOS main thread: exec-time
	// rlimit, not pthread's 8 MB default) — the #282 arena test depends on
	// exactly this: under `ulimit -s 65520` its 120 non-tail levels must
	// complete instead of tripping a guard pinned to the default size.
	prog := write_prog('stack_guard_rlimit', non_tail_def() + '[sum1 200]\n')
	defer {
		os.rm(prog) or {}
	}
	res := os.execute('ulimit -s unlimited 2>/dev/null || ulimit -s 65520 2>/dev/null; ' +
		'VNOBUGREPORT=1 exec ${cx_bin_guard()} ${prog} 2>&1')
	assert res.exit_code == 0, 'depth 200 under a raised stack rlimit must complete:\n${res.output.limit(2000)}'
	assert res.output.trim_space() == '200', 'wrong result under raised rlimit:\n${res.output.limit(2000)}'
}

fn test_tiny_stack_scaled_margin_keeps_shallow_eval_usable() {
	// Threads with < 4 MiB stacks get a proportional margin (size/4) instead
	// of the fixed 1 MiB — a 2 MB-ulimit run must still evaluate shallow
	// programs, and deep ones must raise the coded err, not crash.
	shallow := write_prog('stack_guard_tiny_ok', non_tail_def() + '[sum1 10]\n')
	deep := write_prog('stack_guard_tiny_deep', non_tail_def() + '[sum1 ${guard_depth}]\n')
	defer {
		os.rm(shallow) or {}
		os.rm(deep) or {}
	}
	res_ok := os.execute('ulimit -s 2048 2>/dev/null; VNOBUGREPORT=1 exec ${cx_bin_guard()} ${shallow} 2>&1')
	assert res_ok.exit_code == 0, 'shallow eval on a 2 MB stack must work:\n${res_ok.output.limit(2000)}'
	assert res_ok.output.trim_space() == '10', 'wrong shallow result on 2 MB stack:\n${res_ok.output.limit(2000)}'
	res_deep := os.execute('ulimit -s 2048 2>/dev/null; VNOBUGREPORT=1 exec ${cx_bin_guard()} ${deep} 2>&1')
	assert res_deep.exit_code != 139, 'deep recursion on a 2 MB stack segfaulted:\n${res_deep.output.limit(2000)}'
	assert res_deep.output.contains('cx-err:CXER0272'), 'expected E_STACK_EXHAUSTED on the 2 MB stack:\n${res_deep.output.limit(2000)}'
}
