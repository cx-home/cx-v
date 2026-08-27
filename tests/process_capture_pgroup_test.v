module main

import os
import time as vtime
import testenv

// process_capture_pgroup_test.v — BEHAVIORAL conformance for process.md §3.1's
// `$capture` and `$new-process-group` on the ONE-SHOT RUN path, plus §4.5's
// timeout escalation (#956, RULED: VC-26).
//
// Both parameters were spec-declared, accepted, and never read on the run path
// — the #793 silent-acceptance shape. The harm was measured, not theoretical:
// a timeout signalled only the direct child, so a surviving GRANDCHILD kept the
// captured pipe open and the post-kill stdout_slurp() blocked on it. A 60,000 ms
// budget ran 5m07s, and the same hang was sampled at 9m40s (9.7x) before a
// manual kill. A bound that cannot be enforced is the vacuous-gate class one
// layer down: the gate reads as bounded and is not.
//
// Every assertion here is behavioral — a real child is spawned and the observed
// effect is compared — so no particular implementation can satisfy it, only a
// conforming one.
//
// EVERY probe is itself BOUNDED (run_bounded below). A regression in the code
// under test is precisely a hang, and a test that hangs would take the whole
// gate with it instead of reporting a failure.

const probe_budget_ms = 20000

struct Bounded {
	out     string
	elapsed i64
	killed  bool
}

// run_bounded executes argv with its own wall-clock bound, so a regression
// fails loudly instead of hanging the suite. Uses a fresh process group and
// kills the GROUP — the very property under test, applied to the harness so a
// stuck grandchild here cannot outlive the probe either.
fn run_bounded(argv []string, budget_ms i64) Bounded {
	mut p := os.new_process(argv[0])
	p.set_args(argv[1..])
	p.set_redirect_stdio()
	p.use_pgroup = true
	t0 := vtime.ticks()
	p.run()
	mut killed := false
	for p.is_alive() {
		if vtime.ticks() - t0 > budget_ms {
			p.signal_pgkill()
			killed = true
			break
		}
		vtime.sleep(5 * vtime.millisecond)
	}
	mut out := ''
	if !killed {
		out = p.stdout_slurp() + p.stderr_slurp()
	}
	p.wait()
	return Bounded{
		out:     out
		elapsed: vtime.ticks() - t0
		killed:  killed
	}
}

fn write_prog(name string, body string) string {
	p := os.join_path(os.temp_dir(), name)
	os.write_file(p, body) or { panic('write ${p}: ${err}') }
	return p
}

fn run_cx(name string, body string) Bounded {
	prog := write_prog(name, body)
	return run_bounded([testenv.cx_bin(), '--allow-all', prog], probe_budget_ms)
}

// §3.1 default: `$capture=:both` captures stdout into the result element.
// Regression guard for the behaviour that already worked, so the new arg
// handling cannot quietly break the default path.
fn test_run_capture_both_is_the_default() {
	r := run_cx('cx_cap_both.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		'[$p:run ("echo", "captured-both")]\n')
	assert !r.killed, 'capture=:both probe exceeded ${probe_budget_ms}ms'
	assert r.out.contains('captured-both'), 'default capture did not carry stdout; got: ${r.out}'
}

// §3.1: ":both / :stdout / :stderr / :none. Uncaptured streams inherit the
// parent's." So with `:none` the child's output must reach the PARENT's stdout
// — it is not captured, and it is not swallowed either.
fn test_run_capture_none_inherits_parent_streams() {
	r := run_cx('cx_cap_none.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		'[$p:run ("echo", "inherited-marker") capture=:none]\n')
	assert !r.killed, 'capture=:none probe exceeded ${probe_budget_ms}ms'
	// The marker reaches us because the child inherited OUR stdout.
	assert r.out.contains('inherited-marker'), 'capture=:none did not let the child inherit the parent stdout (output swallowed); got: ${r.out}'
	// And it must NOT be reported as captured output. Attributing an
	// uncaptured stream as captured-and-empty asserts a non-fact (the #908
	// rule: never default to "" when nothing was observed), so the attribute
	// is absent rather than empty.
	// NOTE: match the serializer's ACTUAL quoting (single quotes, e.g.
	// `stdout='x\n'`). This assertion was first written with a double quote
	// and passed vacuously against the unfixed code — the exact vacuous-check
	// class the corpus gates guard against, caught by running the test red.
	assert !r.out.contains("stdout='inherited-marker"), 'capture=:none reported the stream as captured; got: ${r.out}'
}

// §3.1 `:stdout` — capture stdout, and "uncaptured streams inherit the
// parent's", so the child's stderr must reach the PARENT's stderr rather than
// a result attribute. Both halves are asserted: without the second one, an
// implementation that quietly captured both streams and reported only one
// would pass.
//
// RED-PROVEN against the pre-#972 code, where V's os.Process had a single
// all-or-nothing use_stdio_ctl and this value REFUSED by name: the refusal
// printed `CXER4000 … per-stream stdio control` and carried no `stdout=` at
// all, so the first assertion below failed on the refusal text. The refusal
// was correct for its time — silent acceptance was the #956 defect — and the
// fork API (p.set_redirect_pipe, cx-private#972) is what removes it.
fn test_run_capture_stdout_only() {
	r := run_cx('cx_cap_stdout.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		'[$p:run ("sh", "-c", "echo out-marker; echo err-marker 1>&2") capture=:stdout]\n')
	assert !r.killed, 'capture=:stdout probe exceeded ${probe_budget_ms}ms'
	assert r.out.contains("stdout='out-marker"), 'capture=:stdout did not report the captured stdout; got: ${r.out}'
	// stderr was NOT captured, so it inherited ours and arrived as raw text —
	// never as an attribute. Absent, not empty (the #908 rule).
	assert r.out.contains('err-marker'), 'capture=:stdout swallowed the uncaptured stderr instead of letting it inherit the parent (spec §3.1); got: ${r.out}'
	assert !r.out.contains('stderr='), 'capture=:stdout reported an uncaptured stderr attribute; got: ${r.out}'
	// ... and the captured stream must NOT also have reached our stdout.
	assert r.out.count('out-marker') == 1, 'capture=:stdout let the captured stream reach the parent too; got: ${r.out}'
}

// The mirror image: capture stderr, let stdout through.
fn test_run_capture_stderr_only() {
	r := run_cx('cx_cap_stderr.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		'[$p:run ("sh", "-c", "echo out-marker; echo err-marker 1>&2") capture=:stderr]\n')
	assert !r.killed, 'capture=:stderr probe exceeded ${probe_budget_ms}ms'
	assert r.out.contains("stderr='err-marker"), 'capture=:stderr did not report the captured stderr; got: ${r.out}'
	assert r.out.contains('out-marker'), 'capture=:stderr swallowed the uncaptured stdout instead of letting it inherit the parent (spec §3.1); got: ${r.out}'
	assert !r.out.contains('stdout='), 'capture=:stderr reported an uncaptured stdout attribute; got: ${r.out}'
	assert r.out.count('err-marker') == 1, 'capture=:stderr let the captured stream reach the parent too; got: ${r.out}'
}

// `$stdin` is orthogonal to `$capture`: the stdin pipe is its own decision, so
// feeding a child while capturing NEITHER output stream is an ordinary
// combination. Pre-#972 this refused by name for the same all-or-nothing
// reason (a stdin pipe forced pipes on stdout and stderr too), which is what
// makes this red-proven rather than merely green.
fn test_run_stdin_with_capture_none() {
	r := run_cx('cx_stdin_cap_none.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		'[$p:run ("cat", "-") stdin="fed-through-stdin\\n" capture=:none]\n')
	assert !r.killed, 'stdin + capture=:none probe exceeded ${probe_budget_ms}ms'
	assert !r.out.contains('CXER4000'), 'stdin with capture=:none was refused; got: ${r.out}'
	// `cat` echoes onto the stdout it INHERITED from us, so the payload arrives
	// as raw text and not as an attribute.
	assert r.out.contains('fed-through-stdin'), 'the stdin payload never reached the child, or its inherited stdout was swallowed; got: ${r.out}'
	assert !r.out.contains('stdout='), 'capture=:none reported a captured stdout; got: ${r.out}'
}

// §3.5 + §4.5, the measured harm: a grandchild inherits the captured pipe, so
// killing only the direct child leaves the pipe held open and the post-kill
// slurp blocks — the budget becomes unenforceable. With
// `$new-process-group=true` the escalation targets the whole GROUP, so the
// grandchild dies too and `run` returns near its budget.
//
// `sh -c 'sleep 30 & sleep 30'` is the shape: the backgrounded grandchild
// outlives a single-pid kill and holds stdout.
fn test_run_new_process_group_timeout_reaches_grandchild() {
	$if windows {
		eprintln('SKIP: POSIX process-group semantics; Windows uses Job Objects (§3.5)')
		return
	}
	r := run_cx('cx_pgroup_timeout.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		'[$p:run ("sh", "-c", "sleep 30 & sleep 30") timeout-ms=400 new-process-group=true]\n')
	assert !r.killed, 'the group timeout probe exceeded ${probe_budget_ms}ms — the budget is STILL unenforceable: a grandchild is holding the captured pipe open past the kill (#956)'
	assert r.out.contains('timed-out=true'), 'timeout did not report timed-out=true; got: ${r.out}'
	// Generous bound: the point is orders of magnitude (400 ms budget vs the
	// measured 5m07s hang), not millisecond precision on a loaded gate box.
	assert r.elapsed < 15000, 'a 400ms budget took ${r.elapsed}ms — the timeout is not reaching the process group'
}

// Without the group, the same shape must still terminate rather than hang:
// the direct child is killed and `run` returns. This pins that the escalation
// itself works on the default (no-group) path, so the group test above cannot
// pass merely because everything got faster.
fn test_run_timeout_without_group_still_returns() {
	$if windows {
		eprintln('SKIP: POSIX process-group semantics (§3.5)')
		return
	}
	r := run_cx('cx_nogroup_timeout.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		'[$p:run ("sleep", "30") timeout-ms=400]\n')
	assert !r.killed, 'the no-group timeout probe exceeded ${probe_budget_ms}ms'
	assert r.out.contains('timed-out=true'), 'no-group timeout did not report timed-out=true; got: ${r.out}'
	assert r.elapsed < 15000, 'a 400ms budget took ${r.elapsed}ms on the no-group path'
}

// ── §3.1 capture is not bounded by the PIPE (#1002) ──────────────────────────
//
// A captured stream had to fit in the OS pipe buffer or the call broke, because
// `run` read neither pipe until after its wait loop: the child blocked in
// write(), stayed alive with nobody reading, burned the entire budget, and the
// call then reported BOTH non-facts at once — `timed-out=true` about a child
// that had finished its work, and a stdout truncated at the pipe capacity
// presented as the whole answer.
//
// Measured before the fix, on this platform: 262,144 bytes under a 3,000 ms
// budget gave timed-out=true with 65,536 bytes captured — the pipe capacity to
// the byte. That ceiling is what an idle machine grants; under pipe-memory
// pressure XNU hands out 512-byte buffers instead (#993 measured that figure
// here), which is how #1002's five `full-code-cfg-*` diagram fixtures went red
// together and only together: their renders are 802-889 bytes, the sixth-largest
// in that corpus is 451, and all 52 render in 0.08 s.
//
// So the size is chosen to exceed EVERY plausible pipe buffer, and both halves
// are asserted: nothing timed out, and every byte arrived. The probe reports
// only the length — echoing 256 KB would deadlock run_bounded above on exactly
// the bug under test.
fn test_run_capture_exceeds_pipe_buffer_without_timing_out() {
	$if windows {
		eprintln('SKIP: POSIX pipe-buffer semantics')
		return
	}
	r := run_cx('cx_big_capture.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[?lib 'cx-stdlib/io' :as io]\n[?lib 'cx-stdlib/env' :as env]\n" +
		"[?lib 'cx-stdlib/strings' :as strings]\n" +
		'[?let [= \$r [\$p:run ("/bin/sh", "-c",\n' +
		'        "awk \'BEGIN{for(i=0;i<262144;i++)printf \\"x\\"}\'") timeout-ms=20000]]\n' +
		'  [\$io:write-line [\$env:stdout]\n' +
		'    [\$concat "timed-out=" [\$string \$r@timed-out]\n' +
		'             " got=" [\$string [\$strings:length [\$string \$r@stdout]]]]]]\n')
	assert !r.killed, 'the large-capture probe exceeded ${probe_budget_ms}ms — a captured stream bigger than the pipe is still deadlocking (#1002)'
	assert r.out.contains('timed-out=false'), 'a child that finished its work was reported as timed out — the capture pipes are not being drained while it runs (#1002); got: ${r.out}'
	assert r.out.contains('got=262144'), 'the captured stdout was truncated at the pipe buffer instead of carrying every byte the child wrote (#1002); got: ${r.out}'
}

// The other half of the same guarantee, and the reason draining cannot simply
// replace the budget: a child that writes NOTHING and never exits must still be
// caught. Draining a silent hang yields nothing to read, so only the deadline
// ends it — which is also why a CPU-time budget could never have fixed #1002 (a
// child blocked in write() accrues no CPU, so the deadlock would be permanent).
//
// The shape is the one that used to escape the budget through the back door,
// with NO $new-process-group: SIGKILL reaches the shell, its `sleep 3600`
// grandchild survives holding the captured stdout, and the tail read then had
// nothing to end it — a 400 ms budget waited an hour (measured 2026-08-26). The
// group escalation is not the fix here, deliberately: this pins that the
// post-timeout tail read is itself BOUNDED, so the budget holds even when the
// caller did not ask for a process group.
fn test_run_silent_hang_with_surviving_grandchild_still_hits_the_budget() {
	$if windows {
		eprintln('SKIP: POSIX process semantics')
		return
	}
	r := run_cx('cx_silent_hang.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		'[$p:run ("/bin/sh", "-c", "sleep 3600 & wait") timeout-ms=400]\n')
	assert !r.killed, 'the silent-hang probe exceeded ${probe_budget_ms}ms — a grandchild holding the captured pipe is STILL escaping the budget past the kill'
	assert r.out.contains('timed-out=true'), 'a silent non-terminating child escaped the budget — draining must not have replaced it; got: ${r.out}'
	assert r.elapsed < 15000, 'a 400ms budget took ${r.elapsed}ms with a grandchild holding stdout — the tail read is not bounded'
}
