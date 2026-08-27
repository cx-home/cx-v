module main

import os
import time as vtime
import testenv

// process_stdio_streaming_test.v — BEHAVIORAL conformance for process.md §3.2's
// per-stream stdio dispositions and §4.3's pipe-capacity rule (#1014, from
// #1003 / RULED: CO-13), and for the WRITE direction of the same obligation at
// all three entry points that owe a child a payload: `pipeline`'s inter-stage
// feed (#1022, #1027) and `run`'s `$stdin` (#1030).
//
// THE MEASURED HARM. `spawn` used to call set_redirect_stdio() unconditionally:
// all three of the child's streams became pipes of ours, there was no way to say
// otherwise, and a pipe nobody drains fills and stops the child dead. The
// boundary is exact, bisected on darwin against this very shape: a child writing
// 65536 bytes to an undrained stderr completes, 65537 blocks forever. The
// parent, blocked in read() on the OTHER stream, never gets to drain it —
// sampled at io_drain_child -> io_h_read -> os__fd_read -> read — and there is no
// timeout anywhere on that read path, so `spawn` had NO safe primitive for a
// child that talks on two streams. §4.3 now says so normatively, and this file
// is what keeps that warning from being decorative.
//
// The exact 65536/65537 numbers are NOT pinned here: pipe capacity is a platform
// constant, and pinning it would fail on a platform with a smaller buffer for a
// reason that has nothing to do with this module. What IS pinned is the class —
// a 100,000-byte writer on an undrained pipe deadlocks, and each of the three
// non-`:pipe` dispositions makes the same child complete.
//
// EVERY probe is BOUNDED (run_bounded below). A regression here IS a hang, and
// an unbounded test would take the whole gate down instead of reporting.

// A probe that is expected to finish gets the roomy budget; a probe whose POINT
// is the deadlock gets a short one, since the child fills the pipe instantly and
// waiting longer only spends gate wall-clock (#700's dead-ends register).
const probe_budget_ms = 20000
const deadlock_budget_ms = 6000

// The child writes this many bytes to stderr before saying anything on stdout.
// Comfortably past every platform's pipe capacity.
const stderr_flood_bytes = 100000

struct Bounded {
	out     string
	elapsed i64
	killed  bool
}

// run_bounded executes argv with its own wall-clock bound. Uses a fresh process
// group and kills the GROUP, so a stuck grandchild cannot outlive the probe.
//
// It drains BOTH streams INSIDE the wait loop, non-blockingly (is_pending +
// stdout_read/stderr_read), and only slurps the remainder after exit. Draining
// after wait — the shape `process/run` is stuck with, and the shape this harness
// had first — is the very defect under test: the `:inherit` probe pushes 100,000
// bytes through the cx process's stderr, that stderr is a pipe of OURS, and the
// first version of this file deadlocked at the same 64 KiB boundary one level up.
// A harness that cannot survive the fixture it feeds cannot judge the fix.
fn run_bounded(argv []string, budget_ms i64) Bounded {
	mut p := os.new_process(argv[0])
	p.set_args(argv[1..])
	p.set_redirect_stdio()
	p.use_pgroup = true
	t0 := vtime.ticks()
	p.run()
	mut killed := false
	mut out := ''
	for p.is_alive() {
		if vtime.ticks() - t0 > budget_ms {
			p.signal_pgkill()
			killed = true
			break
		}
		out += p.stdout_read()
		out += p.stderr_read()
		vtime.sleep(5 * vtime.millisecond)
	}
	if !killed {
		out += p.stdout_slurp() + p.stderr_slurp()
	}
	p.wait()
	return Bounded{
		out:     out
		elapsed: vtime.ticks() - t0
		killed:  killed
	}
}

fn run_cx(name string, body string, budget_ms i64) Bounded {
	prog := os.join_path(os.temp_dir(), name)
	os.write_file(prog, body) or { panic('write ${prog}: ${err}') }
	return run_bounded([testenv.cx_bin(), '--allow-all', prog], budget_ms)
}

// probe_dir is a fresh directory per probe for the file-redirect targets, so a
// leftover file from an earlier run can never make an assertion pass.
fn probe_dir(tag string) string {
	d := os.join_path(os.temp_dir(), 'cx-1014-${tag}-${os.getpid()}-${vtime.ticks()}')
	os.mkdir_all(d) or { panic('mkdir ${d}: ${err}') }
	return d
}

const preamble = "[?lib 'cx-stdlib/process' :as p]\n[?lib 'cx-stdlib/io' :as io]\n"

// flood_child is the two-stream shape: stderr_flood_bytes bytes onto stderr
// FIRST, then a marker on stdout. A caller draining only stdout cannot reach the
// marker until the child is past its stderr write.
const flood_child = "('sh', '-c', \"printf '%0${stderr_flood_bytes}d' 1 1>&2; echo OUT-MARKER\")"

// ── the hazard §4.3 warns about ─────────────────────────────────────

// The DEFAULT (all three streams `:pipe`) still deadlocks on this shape — that
// is deliberate: #1014 changed no default, it added a way to say something else.
// This probe is the red-proof anchor for every green one below: the same child,
// the same drain, and only the stderr disposition differs.
//
// It is also what makes §4.3's normative warning non-vacuous. If a later change
// makes the default safe, THIS assertion is the one that must be revisited
// together with the spec paragraph — not silently outlived.
fn test_default_all_pipes_undrained_stderr_deadlocks() {
	$if windows {
		eprintln('SKIP: POSIX pipe-capacity semantics (§4.9)')
		return
	}
	r := run_cx('cx_1014_default_deadlock.cx', preamble + '[?let\n' +
		'  [= $h [$p:spawn ${flood_child}]]\n' +
		'  [= $out [$io:read-all [$p:stdout $h]]]\n' + '  [= $rc [$p:wait $h]]\n' +
		'  [= $done [$p:close $h]]\n' + '  $out]\n', deadlock_budget_ms)
	assert r.killed, 'the all-pipes default did NOT deadlock on ${stderr_flood_bytes} undrained stderr bytes — the §4.3 pipe-capacity warning has become decorative, and the red-proof for every probe below is gone; got: ${r.out}'
}

// ── the three ways out (§3.2) ───────────────────────────────────────

// `:discard` — the child's stderr goes to the null device, so nothing of ours
// can fill and the child runs to completion. Red-proven by the probe above:
// same child, same single-stream drain, `:pipe` hangs.
fn test_stderr_discard_completes() {
	$if windows {
		eprintln('SKIP: POSIX descriptor staging (§4.9)')
		return
	}
	r := run_cx('cx_1014_discard.cx', preamble + '[?let\n' +
		'  [= $h [$p:spawn ${flood_child} stderr=:discard]]\n' +
		'  [= $out [$io:read-all [$p:stdout $h]]]\n' + '  [= $rc [$p:wait $h]]\n' +
		'  [= $done [$p:close $h]]\n' + '  ($out, $rc)]\n', probe_budget_ms)
	assert !r.killed, 'stderr=:discard still deadlocked on ${stderr_flood_bytes} stderr bytes; the disposition is not reaching the spawn'
	assert r.out.contains('OUT-MARKER'), 'stderr=:discard lost the stdout the caller DID drain; got: ${r.out}'
	assert r.out.contains(', 0)'), 'stderr=:discard did not report a clean exit; got: ${r.out}'
	// Discarded means discarded: the flood must not have leaked to our stderr.
	assert !r.out.contains('000000000000000000000000'), 'stderr=:discard let the child stderr reach the parent instead of the null device; captured ${r.out.len} bytes'
}

// `:inherit` — the stream is not redirected at all, so the child writes to OUR
// descriptor. Observed TWO levels deep (the #972 pin idiom): the flood is not
// merely absent from the result, it arrives in the bytes this harness captured
// from the cx process, which is exactly "the parent's stderr".
fn test_stderr_inherit_reaches_the_parents_fd() {
	$if windows {
		eprintln('SKIP: POSIX descriptor semantics (§4.9)')
		return
	}
	r := run_cx('cx_1014_inherit.cx', preamble + '[?let\n' +
		'  [= $h [$p:spawn ${flood_child} stderr=:inherit]]\n' +
		'  [= $out [$io:read-all [$p:stdout $h]]]\n' + '  [= $rc [$p:wait $h]]\n' +
		'  [= $done [$p:close $h]]\n' + '  ($out, $rc)]\n', probe_budget_ms)
	assert !r.killed, 'stderr=:inherit still deadlocked; the disposition is not reaching the spawn'
	assert r.out.contains('OUT-MARKER'), 'stderr=:inherit lost the drained stdout; got ${r.out.len} bytes'
	// The grandchild's stderr → the cx process's stderr → our captured bytes.
	// Without this half, an implementation that quietly discarded the stream
	// would pass the completion assertion.
	assert r.out.len > stderr_flood_bytes, 'stderr=:inherit swallowed the stream instead of letting it through to the parent fd: captured only ${r.out.len} bytes, expected more than ${stderr_flood_bytes}'
}

// A file path — the same escape from the deadlock, and the bytes are KEPT. The
// size is asserted exactly: a redirect that truncated, appended to a stale
// file, or interleaved with the parent's own output would not land on the nose.
fn test_stderr_file_captures_the_bytes() {
	$if windows {
		eprintln('SKIP: POSIX descriptor staging (§4.9)')
		return
	}
	dir := probe_dir('errfile')
	errf := os.join_path(dir, 'err.log')
	r := run_cx('cx_1014_errfile.cx', preamble + '[?let\n' +
		"  [= \$h [\$p:spawn ${flood_child} stderr='${errf}']]\n" +
		'  [= $out [$io:read-all [$p:stdout $h]]]\n' + '  [= $rc [$p:wait $h]]\n' +
		'  [= $done [$p:close $h]]\n' + '  ($out, $rc)]\n', probe_budget_ms)
	assert !r.killed, 'a file-redirected stderr still deadlocked; the redirect is not reaching the spawn'
	assert r.out.contains('OUT-MARKER'), 'the file redirect lost the drained stdout; got: ${r.out}'
	assert os.exists(errf), 'stderr=<path> never created ${errf}'
	sz := os.file_size(errf)
	assert sz == u64(stderr_flood_bytes), 'stderr=<path> captured ${sz} bytes, expected exactly ${stderr_flood_bytes}'
	// And the parent's own stderr was PUT BACK: the staging replaces our
	// descriptor only across the fork. If it leaked, the flood would also be in
	// what this harness captured.
	assert r.out.len < stderr_flood_bytes, 'the redirect leaked into the parent stderr as well (captured ${r.out.len} bytes) — the descriptor staging did not unwind'
	os.rmdir_all(dir) or {}
}

// stdin from a file and stdout to a file, in one spawn: the child reads to EOF
// with no caller writing the pipe, and its output lands in the file. This is the
// shape a caller needs when it wants neither stream in memory.
fn test_stdin_from_file_and_stdout_to_file() {
	$if windows {
		eprintln('SKIP: POSIX descriptor staging (§4.9)')
		return
	}
	dir := probe_dir('iofile')
	inf := os.join_path(dir, 'in.txt')
	outf := os.join_path(dir, 'out.txt')
	os.write_file(inf, 'FED-FROM-FILE\n') or { panic('write ${inf}: ${err}') }
	r := run_cx('cx_1014_iofile.cx', preamble + '[?let\n' +
		"  [= \$h [\$p:spawn ('cat', '-') stdin='${inf}' stdout='${outf}']]\n" +
		'  [= $rc [$p:wait $h]]\n' + '  [= $done [$p:close $h]]\n' + '  $rc]\n',
		probe_budget_ms)
	assert !r.killed, 'stdin=<path> + stdout=<path> did not finish — the child never saw EOF on its stdin'
	assert os.exists(outf), 'stdout=<path> never created ${outf}'
	got := os.read_file(outf) or { '' }
	assert got == 'FED-FROM-FILE\n', 'the file-fed stdin did not round-trip through the file-redirected stdout; got: ${got}'
	os.rmdir_all(dir) or {}
}

// ── the accessor contract (§3.2) ────────────────────────────────────

// Only a `:pipe` stream has a parent-side descriptor. Asking for a handle on a
// stream the caller explicitly sent somewhere else must REFUSE BY NAME — the
// alternative (a handle over the -1 that stdio_fd carries) read as an empty
// stream, which asserts a non-fact about a child that may have written plenty.
fn test_stdio_accessor_refuses_a_non_piped_stream() {
	$if windows {
		eprintln('SKIP: POSIX descriptor staging (§4.9)')
		return
	}
	r := run_cx('cx_1014_accessor.cx', preamble + '[?let\n' +
		"  [= \$h [\$p:spawn ('echo', 'hi') stderr=:discard]]\n" +
		'  [= $bad [$p:stderr $h]]\n' + '  [= $rc [$p:wait $h]]\n' +
		'  [= $done [$p:close $h]]\n' + '  $bad]\n', probe_budget_ms)
	assert !r.killed, 'the accessor probe exceeded ${probe_budget_ms}ms'
	assert r.out.contains('CXER4013'), 'stderr on a :discard stream did not raise CXER4013; got: ${r.out}'
	assert r.out.contains(':discard'), 'the CXER4013 refusal does not say WHICH disposition the stream got; got: ${r.out}'
}

// A misspelled disposition is an operand fault naming the stream and the
// accepted set — never a silent fall back to `:pipe`, which would hand the
// caller the very deadlock they were trying to avoid (the #793 class).
fn test_unknown_disposition_refuses_by_name() {
	r := run_cx('cx_1014_baddisp.cx', preamble +
		"[\$p:spawn ('echo', 'hi') stderr=:devnull]\n", probe_budget_ms)
	assert !r.killed, 'the bad-disposition probe exceeded ${probe_budget_ms}ms'
	assert r.out.contains('CXER0100'), 'stderr=:devnull was accepted silently instead of refused; got: ${r.out}'
	assert r.out.contains('stderr'), 'the refusal does not name the stream; got: ${r.out}'
	assert r.out.contains(':discard'), 'the refusal does not name the accepted set; got: ${r.out}'
}

// `:null` is NOT the spelling, and the reason is measured rather than assumed:
// CX reserves the `:null` atom literal, so the parser rejects it before this
// module ever sees a value. The pack spells the null device `:discard`; this pins
// that the reserved spelling stays a parse-time refusal, so nobody "restores" it
// from the issue text and gets a confusing fault at runtime instead.
fn test_null_atom_is_reserved_so_discard_is_the_spelling() {
	r := run_cx('cx_1014_nullatom.cx', preamble +
		"[\$p:spawn ('echo', 'hi') stderr=:null]\n", probe_budget_ms)
	assert !r.killed, 'the :null probe exceeded ${probe_budget_ms}ms'
	assert r.out.contains('reserved'), 'the reserved :null atom no longer refuses at parse time — reconsider the :discard spelling (§3.2); got: ${r.out}'
}

// ── defaults untouched (§3.2) ───────────────────────────────────────

// The ordinary streaming case — spawn, read stdout, read stderr, wait — with no
// disposition given at all. The whole point of the defaults is that the three
// new options moved nothing, so this must behave exactly as before.
fn test_defaults_still_pipe_all_three_streams() {
	r := run_cx('cx_1014_defaults.cx', preamble + '[?let\n' +
		'  [= $h [$p:spawn (\'sh\', \'-c\', "echo D-OUT; echo D-ERR 1>&2")]]\n' +
		'  [= $out [$io:read-all [$p:stdout $h]]]\n' +
		'  [= $errs [$io:read-all [$p:stderr $h]]]\n' + '  [= $rc [$p:wait $h]]\n' +
		'  [= $done [$p:close $h]]\n' + '  ($out, $errs, $rc)]\n', probe_budget_ms)
	assert !r.killed, 'the default streaming probe exceeded ${probe_budget_ms}ms'
	assert r.out.contains('D-OUT'), 'the default stdout pipe stopped delivering; got: ${r.out}'
	assert r.out.contains('D-ERR'), 'the default stderr pipe stopped delivering; got: ${r.out}'
	// Both came back through the HANDLES, not by leaking to our streams: the
	// result tuple carries them as values.
	assert r.out.contains("('D-OUT"), 'the default stdout arrived as raw text rather than through the handle; got: ${r.out}'
}

// stdin is a pipe by default too, so closing it is still how a reader gets EOF
// (§4.6). Pins that the new stdin option did not disturb the existing EOF path.
fn test_default_stdin_pipe_still_signals_eof_on_close() {
	r := run_cx('cx_1014_stdin_eof.cx', preamble + '[?let\n' +
		"  [= \$h [\$p:spawn ('cat', '-')]]\n" +
		"  [= \$w [\$io:write-string [\$p:stdin \$h] 'EOF-ROUNDTRIP\\n']]\n" +
		'  [= $c [$io:close [$p:stdin $h]]]\n' +
		'  [= $out [$io:read-all [$p:stdout $h]]]\n' + '  [= $rc [$p:wait $h]]\n' +
		'  [= $done [$p:close $h]]\n' + '  ($out, $rc)]\n', probe_budget_ms)
	assert !r.killed, 'the default stdin/EOF probe exceeded ${probe_budget_ms}ms — closing stdin no longer signals EOF (§4.6)'
	assert r.out.contains('EOF-ROUNDTRIP'), 'the default stdin pipe stopped delivering; got: ${r.out}'
}

// ── §3.3 pipeline — the THIRD entry point (#1022) ────────────────────
//
// `spawn` (§3.2, above) and `run` (§3.1, process_capture_pgroup_test.v) both got
// their drain. `proc_pipeline` was the one left: it called set_redirect_stdio()
// per stage, slurped stdout, and NEVER READ STDERR AT ALL — so a stage that says
// more than the pipe holds on stderr blocks in write(), never exits, never closes
// stdout, and the slurp waiting on that stdout never reaches EOF. Nothing in the
// module ended it, because `$timeout-ms` was forwarded by stdlib/process.cx and
// never read here either. Measured against the shipped binary at 27a028cdb: both
// probes below ran past 12 s and were killed.
//
// Unlike §3.2 there is no disposition to choose here. §3.3 gives the pipeline
// `$stdin` and `$capture` — they "are not per-stage keys" — so there is no caller
// to hand §4.3's drain obligation to. It is the pipeline's, on every stage.

// (a) THE CHATTY-STDERR STAGE. Same flood as the §3.2 probes, inside a two-stage
// pipeline, so the mechanism is identical and only the entry point differs. Three
// things are asserted, because a fix that merely stops hanging is not the fix:
// the pipeline completes, the downstream stage still received the upstream
// stdout (draining must not have eaten the chaining), and the flood is REPORTED
// on the offending stage's row rather than dropped on the floor — §4.3's "a
// dropped stderr is a dropped diagnostic".
fn test_pipeline_chatty_stderr_stage_completes_and_reports_it() {
	$if windows {
		eprintln('SKIP: POSIX pipe-capacity semantics (§4.9)')
		return
	}
	r := run_cx('cx_1022_pipeline_stderr.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		'[$p:pipeline ([stage [argv \'sh\' \'-c\' "printf \'%0${stderr_flood_bytes}d\' 1 1>&2; echo OUT-MARKER"]], [stage [argv \'cat\']])]\n',
		probe_budget_ms)
	assert !r.killed, 'a pipeline stage writing ${stderr_flood_bytes} bytes to stderr still deadlocked the pipeline (#1022) — stderr is not being drained per stage'
	assert r.out.contains("stdout='OUT-MARKER"), 'the pipeline lost the last stage stdout while draining stderr — the stdout→stdin chaining broke; got: ${r.out}'
	// The captured flood must be ON THE STAGE THAT WROTE IT. A pipeline that
	// drained stderr into nowhere would pass the first two assertions.
	assert r.out.contains("stderr='0000"), 'the flooded stderr was drained and then DISCARDED — the stage row reports no stderr at all (§4.3: a dropped stderr is a dropped diagnostic); got: ${r.out}'
}

// (b) THE HUNG STAGE. `$timeout-ms` was read-and-unused, which is worse than a
// no-op: it made every pipeline unbounded, so the deadlock above had nothing to
// end it and an ordinary `sleep`-forever stage hung the caller for good.
//
// The shape deliberately has NO surviving-grandchild escape hatch of its own and
// deliberately does NOT ask for a process group — §3.3 offers the pipeline no
// `$new-process-group`, so the escalation signals the stage leader directly and
// the bounded tail read is what keeps a grandchild from handing the budget back
// (the division #1002 settled for `run`). The budget is 600 ms against a 3600 s
// sleep: any elapsed time in the same order as the sleep is a failure, and the
// bound asserted here (15 s) is loose enough that a parallel build cannot trip it
// while still being 240x under the child's own lifetime.
//
// Both halves of the report are pinned. `timed-out=true` on the stage row is the
// per-stage accounting; a pipeline that killed the stage but reported nothing
// would leave the caller unable to tell a timeout from a crash.
fn test_pipeline_hung_stage_is_killed_at_the_budget() {
	$if windows {
		eprintln('SKIP: POSIX process semantics (§4.9)')
		return
	}
	r := run_cx('cx_1022_pipeline_timeout.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[\$p:pipeline ([stage [argv 'sh' '-c' 'sleep 3600']], [stage [argv 'cat']]) timeout-ms=600]\n",
		probe_budget_ms)
	assert !r.killed, 'a pipeline stage that never exits still ran past ${probe_budget_ms}ms under a 600ms budget — $timeout-ms is still not honored (#1022)'
	assert r.elapsed < 15000, 'a 600ms pipeline budget took ${r.elapsed}ms — the timeout fires but the post-kill read is not bounded'
	assert r.out.contains('timed-out=true'), 'the killed stage was not reported as timed out, so the caller cannot tell a budget kill from a crash; got: ${r.out}'
	// The stages AFTER the timed-out one must not have run: starting a stage with
	// no budget left reports a timeout against a stage that never had a chance.
	assert r.out.contains('[exit-codes 143]') || r.out.contains('[exit-codes 137]'), 'the pipeline continued past the stage that spent the budget — exit-codes should carry only the stages that actually ran; got: ${r.out}'
}

// The other side of the same option: `$kill-on-timeout=false` selects the §5
// error VALUE over a `timed-out=true` result, exactly as `run` does. The stage is
// killed either way — leaving a runaway `sleep 3600` behind on the way out would
// be a worse defect than the one being fixed — so this pins the REPORT, and the
// harness bound pins that the kill happened.
fn test_pipeline_timeout_without_kill_reports_cxer4003() {
	$if windows {
		eprintln('SKIP: POSIX process semantics (§4.9)')
		return
	}
	r := run_cx('cx_1022_pipeline_timeout_err.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[\$p:pipeline ([stage [argv 'sh' '-c' 'sleep 3600']]) timeout-ms=600 kill-on-timeout=false]\n",
		probe_budget_ms)
	assert !r.killed, 'kill-on-timeout=false hung the pipeline instead of erroring at the budget'
	assert r.elapsed < 15000, 'kill-on-timeout=false took ${r.elapsed}ms on a 600ms budget'
	assert r.out.contains('CXER4003'), 'kill-on-timeout=false did not raise E_PROC_TIMED_OUT; got: ${r.out}'
}

// A budget that is NOT exceeded must not be spent by the drain loop itself, and
// the pipefail aggregate must survive the rewrite. Without this, an implementation
// that reported `timed-out=true` for every pipeline would pass both probes above.
fn test_pipeline_under_budget_is_untouched() {
	r := run_cx('cx_1022_pipeline_ok.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[\$p:pipeline ([stage [argv 'printf' 'a\\nb\\nERROR\\n']], [stage [argv 'grep' 'ERROR']]) timeout-ms=20000]\n",
		probe_budget_ms)
	assert !r.killed, 'a fast two-stage pipeline exceeded ${probe_budget_ms}ms'
	assert r.out.contains("stdout='ERROR"), 'the pipeline stopped chaining stdout→stdin; got: ${r.out}'
	assert r.out.contains('[exit-codes 0 0]'), 'the pipefail aggregate lost a stage row; got: ${r.out}'
	assert !r.out.contains('timed-out=true'), 'a pipeline well inside its budget was reported as timed out; got: ${r.out}'
}

// ── §4.3 the OTHER direction: the inter-stage FEED (#1027) ───────────
//
// #1022 (above) drained every stage's OUTPUT streams and made `$timeout-ms` a
// real bound. It left the fourth blocking site in the same function standing:
// the feed of stage N's stdout into stage N+1's stdin was one BLOCKING
// `p.stdin_write(feed)` of the whole payload, issued BEFORE the drain loop
// started. Same mutual deadlock, roles reversed — the parent blocks in write()
// once the stage's stdin pipe is full, the stage blocks in write() once its own
// stdout pipe is full — and strictly worse to diagnose, because the block sat
// inside the module's OWN write() rather than in the wait loop, so #1022's
// newly-honored budget structurally COULD NOT FIRE on it. Measured against
// 27a028cdb and re-measured against 73b3187d3 (i.e. with #1022 landed): probes
// (a) and (c) below ran past a 12 s bound and were killed, having printed nothing;
// probe (b) did not hang at all — it killed the interpreter with SIGPIPE.
//
// The payload is 200,000 bytes for the same reason §4.3 refuses to pin 65536:
// it is comfortably past every platform's pipe capacity, and the capacity itself
// is a platform variable (64 KiB on an idle darwin, 512 bytes under pipe-memory
// pressure). What is pinned is the class — an over-capacity inter-stage payload —
// never the number that makes it over-capacity.
const feed_flood_bytes = 200000

// The first stage of every feed probe: 200,000 bytes onto stdout and nothing
// else, so the payload handed to the NEXT stage is over capacity by construction.
const feed_flood_stage = "[stage [argv 'sh' '-c' \"printf '%0${feed_flood_bytes}d' 1\"]]"

// (a) THE MEASURED HANG. `printf … | cat` is the most ordinary large-payload
// pipeline imaginable and it never returned. The third stage counts bytes rather
// than the probe asserting on a 200,000-character attribute: it makes the
// probe's own output small, and it proves the payload survived TWO inter-stage
// feeds instead of one — a fix that delivered the first feed and truncated the
// second would pass a two-stage probe.
//
// The count is asserted as `stdout='200000` and NOT as a bare `200000` anywhere
// in the output, which would be vacuous: the stage rows echo their own argv, and
// `printf '%0200000d'` carries the number. Hence the `tr -d " "` — darwin's
// `wc -c` pads its count, and a padded count cannot be anchored to `stdout='`.
fn test_pipeline_over_capacity_feed_completes_intact() {
	$if windows {
		eprintln('SKIP: POSIX pipe-capacity semantics (§4.9)')
		return
	}
	r := run_cx('cx_1027_feed_intact.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[\$p:pipeline (${feed_flood_stage}, [stage [argv 'cat']], [stage [argv 'sh' '-c' 'wc -c | tr -d \" \"']]) timeout-ms=20000]\n",
		probe_budget_ms)
	assert !r.killed, 'a ${feed_flood_bytes}-byte inter-stage payload still deadlocked the pipeline (#1027) — the feed is a blocking write again'
	assert r.out.contains("stdout='${feed_flood_bytes}"), 'the ${feed_flood_bytes}-byte payload did not arrive intact at the last stage — the byte count disagrees; got: ${r.out}'
	assert r.out.contains('[exit-codes 0 0 0]'), 'a stage of the feed probe failed or was dropped; got: ${r.out}'
	assert !r.out.contains('timed-out=true'), 'the feed spent the budget instead of being delivered; got: ${r.out}'
}

// (b) THE STAGE THAT STOPS READING — and the SECOND defect at the same site.
// `head -c 10` takes ten bytes of a 200,000-byte payload and exits: a legitimate
// pipeline stage, not a fault. The parent's next write lands on a pipe with no
// reader, which raises SIGPIPE, whose DEFAULT ACTION TERMINATES THE PROCESS
// SILENTLY — and the cx binary only takes SIGPIPE off its default inside the
// picoev serve plane (transport/picoev/picoev.v new()), which a `cx` script run
// never enters.
//
// So this shape did NOT hang pre-fix. MEASURED against 73b3187d3: it exited
// **141** (128 + SIGPIPE) in 1 s having printed ZERO BYTES — no result, no error,
// no diagnostic. `printf | head` killed the interpreter. That is worse than the
// deadlock the issue is named for, because a hang at least announces itself, and
// it is why the non-blocking feed cannot ship without the signal discipline.
//
// Three things are asserted, and the SURVIVAL marker is the load-bearing one: a
// process killed by SIGPIPE prints nothing, which an assertion on the result
// alone could not tell from a hang that got killed. The marker is a form AFTER
// the pipeline, so it can only appear if the interpreter outlived the feed.
//
// `head -c 10` and not `head -1`: the payload is 200,000 digits with no newline
// in it, so `head -1` would consume the WHOLE feed looking for one and never
// exercise EPIPE at all.
fn test_pipeline_stage_closing_stdin_early_ends_the_feed() {
	$if windows {
		eprintln('SKIP: POSIX pipe-capacity semantics (§4.9)')
		return
	}
	r := run_cx('cx_1027_feed_epipe.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[\$p:pipeline (${feed_flood_stage}, [stage [argv 'head' '-c' '10']]) timeout-ms=20000]\n" +
		"'SURVIVED-1027'\n", probe_budget_ms)
	assert !r.killed, 'a stage that closes stdin early hung the pipeline instead of ending the feed at EPIPE'
	assert r.out.contains('SURVIVED-1027'), 'the cx process did not outlive the feed — the write to a reader-less pipe killed it (SIGPIPE default action); got: ${r.out}'
	// The stage succeeded, so the PIPELINE succeeded: an unfinished feed is not a
	// failure, and the stage's own exit status is the verdict (§4.3).
	assert r.out.contains('[exit-codes 0 0]'), 'a stage that read what it wanted and exited 0 was reported as a pipeline failure; got: ${r.out}'
	assert r.out.contains("stdout='0000000000"), "the head stage's ten bytes did not reach the pipeline stdout; got: ${r.out}"
	assert !r.out.contains('timed-out=true'), 'ending the feed at EPIPE was reported as a timeout — the caller cannot tell an early-exiting stage from a runaway one; got: ${r.out}'
}

// (c) THE HUNG STAGE, MID-FEED. This is the assertion #1022's budget could not
// make: `sleep 3600` reads nothing, the 200,000-byte feed fills its stdin pipe,
// and pre-fix the parent blocked in write() BEFORE ever reaching the loop that
// checks the deadline — so `timeout-ms=600` was defeated on this one shape while
// the shipped #1022 probe (same sleep, NO payload) passed. Same budget, same
// child, one added payload: that difference is exactly the defect.
fn test_pipeline_hung_stage_mid_feed_is_killed_at_the_budget() {
	$if windows {
		eprintln('SKIP: POSIX process semantics (§4.9)')
		return
	}
	r := run_cx('cx_1027_feed_timeout.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[\$p:pipeline (${feed_flood_stage}, [stage [argv 'sh' '-c' 'sleep 3600']]) timeout-ms=600]\n",
		probe_budget_ms)
	assert !r.killed, 'a stage that reads nothing mid-feed ran past ${probe_budget_ms}ms under a 600ms budget — the feed is still outside the deadline (#1027)'
	assert r.elapsed < 15000, 'a 600ms budget spent ${r.elapsed}ms once a feed was in flight'
	assert r.out.contains('timed-out=true'), 'the stage killed mid-feed was not reported as timed out; got: ${r.out}'
}

// ── §3.1 `run`'s $stdin feed: THE SAME TWO DEFECTS (#1030) ───────────
//
// `run` carried BOTH of #1027's defects at its own `p.stdin_write(stdin_payload)`
// — the other blocking write in this module, sitting in front of #1002's drain
// loop exactly as the pipeline's sat in front of #1022's. These pins live beside
// #1027's rather than with the other `run` probes precisely BECAUSE it is one
// mechanism with one set of helpers (proc_nb_arm / proc_feed_pass /
// proc_feed_arm): a regression that breaks the feed breaks both entry points, and
// they should go red together where a reader can see it.
//
// MEASURED against the pre-fix binary at ab7f9b6d9 (2026-08-26), at the issue's
// three named shapes — and post-fix on the same box:
//
//   (d) run ('cat') stdin=<200 KB> timeout-ms=5000
//         pre:  killed at a 15 s EXTERNAL bound, 0 bytes.   post: 0.33 s, intact.
//   (e) run ('head' '-c' '10') stdin=<200 KB>
//         pre:  exit 141, 0.065 s, ZERO bytes.              post: 0.07 s, rc 0.
//   (f) run ('sh' '-c' 'sleep 3600') stdin=<200 KB> timeout-ms=600
//         pre:  killed at the same 15 s bound.              post: 0.83 s.
//
// The control that makes (f) attributable to the PAYLOAD and not to #1002's
// remainder: the SAME child with NO payload already returned timed-out=true in
// 0.834 s pre-fix. One added payload is the whole difference — and
// test_run_timeout_without_group_still_returns (process_capture_pgroup_test.v) is
// the shipped pin on that no-payload half, so the pair is already in the gate.
//
// The payload is built with `strings:repeat` rather than a `printf` stage because
// §3.1's `$stdin` is a payload STRING, not a stream: `run` has no upstream stage
// to produce it. Same 200,000 bytes, same reason as feed_flood_bytes above.
const run_feed_payload = '[\$s:repeat "0" ${feed_flood_bytes}]'
const run_feed_preamble = "[?lib 'cx-stdlib/process' :as p]\n[?lib 'cx-stdlib/strings' :as s]\n"

// (d) THE MEASURED HANG, and the shape the issue names. `[$run ('cat')
// stdin=<200 KB>]` is the most ordinary large-payload `run` imaginable and it
// never returned.
//
// `cat` and not `wc -c` is load-bearing here, and it is what a first draft of this
// pin got wrong: the deadlock needs BOTH halves blocked, so the child must flood
// its own CAPTURED stdout while we are blocked writing its stdin. A child that
// reduces the payload (`cat | wc -c`) keeps its stdout tiny, drains our write, and
// COMPLETES pre-fix — measured, a green probe over a live defect. So the captured
// stdout is necessarily over capacity too, and the assertion pays that price
// rather than dodging it: every one of the 200,000 bytes is checked, exactly,
// which is the strongest form available and also the only one that would catch a
// feed that delivered a prefix and closed.
fn test_run_over_capacity_stdin_feed_completes_intact() {
	$if windows {
		eprintln('SKIP: POSIX pipe-capacity semantics (§4.9)')
		return
	}
	r := run_cx('cx_1030_run_feed_intact.cx', run_feed_preamble +
		"[\$p:run (\"cat\") stdin=${run_feed_payload} timeout-ms=5000]\n", probe_budget_ms)
	assert !r.killed, 'a ${feed_flood_bytes}-byte \$stdin payload deadlocked run (#1030) — the feed is a blocking write in front of the drain loop again'
	// Not interpolated into the message: r.out is >200 KB on this probe by
	// construction, and an assertion that dumps it is unreadable where it matters.
	assert r.out.contains("stdout='" + '0'.repeat(feed_flood_bytes) + "'"), 'the ${feed_flood_bytes}-byte payload did not round-trip through cat intact — got ${r.out.len} bytes of output'
	assert r.out.contains('exit-code=0'), 'cat failed on the fed payload; got ${r.out.len} bytes of output'
	assert !r.out.contains('timed-out=true'), 'the feed spent the 5000ms budget instead of being delivered — got ${r.out.len} bytes of output'
}

// (e) THE CHILD THAT STOPS READING — the SIGPIPE death, at `run`. Pre-fix this
// did not hang: it exited 141 in 0.065 s having printed ZERO BYTES. No result, no
// error, no exit code that says why. `printf | head` killed the interpreter, and
// that is worse than the deadlock the issue is named for, because a hang at least
// announces itself.
//
// The SURVIVAL marker is the load-bearing assertion, for the same reason it is in
// #1027's (b): a process killed by SIGPIPE prints nothing, which an assertion on
// the result alone cannot tell from a hang that got killed. The marker is a form
// AFTER the call, so it can only appear if the interpreter outlived the feed.
//
// `head -c 10` and not `head -1`: the payload is 200,000 zeros with no newline in
// it, so `head -1` would consume the WHOLE feed looking for one and never exercise
// EPIPE at all.
fn test_run_child_closing_stdin_early_ends_the_feed() {
	$if windows {
		eprintln('SKIP: POSIX pipe-capacity semantics (§4.9)')
		return
	}
	r := run_cx('cx_1030_run_feed_epipe.cx', run_feed_preamble +
		"[\$p:run (\"head\", \"-c\", \"10\") stdin=${run_feed_payload} timeout-ms=20000]\n" +
		"'SURVIVED-1030'\n", probe_budget_ms)
	assert !r.killed, 'a child that stops reading hung run instead of ending the feed at EPIPE'
	assert r.out.contains('SURVIVED-1030'), 'the cx process did not outlive the feed — the write to a reader-less pipe killed it (SIGPIPE default action); got: ${r.out}'
	// The child succeeded, so the RUN succeeded: an unfinished feed is not a
	// failure, and the child's own exit status is the verdict (§3.1 / §4.3).
	assert r.out.contains('exit-code=0'), 'a child that read what it wanted and exited 0 was reported as a failure; got: ${r.out}'
	assert r.out.contains("stdout='0000000000'"), "the head child's ten bytes did not reach the run stdout; got: ${r.out}"
	assert !r.out.contains('timed-out=true'), 'ending the feed at EPIPE was reported as a timeout — the caller cannot tell an early-exiting child from a runaway one; got: ${r.out}'
	// No second, weaker account of the same fact (§3.1): the exit status already
	// says it, and for `head` a truncation flag would be misleading.
	assert !r.out.contains('stdin-truncated'), 'the unfinished feed grew an attribute that duplicates what exit-code already says; got: ${r.out}'
}

// (f) THE HUNG CHILD, MID-FEED. This is the assertion #1002's budget could not
// make: `sleep 3600` reads nothing, the 200,000-byte payload fills its stdin
// pipe, and pre-fix we blocked in write() BEFORE ever reaching the loop that
// checks the deadline — so `timeout-ms=600` was defeated on this one shape while
// the same child with no payload was bounded in 0.834 s.
fn test_run_hung_child_mid_feed_is_killed_at_the_budget() {
	$if windows {
		eprintln('SKIP: POSIX process semantics (§4.9)')
		return
	}
	r := run_cx('cx_1030_run_feed_timeout.cx', run_feed_preamble +
		"[\$p:run (\"sh\", \"-c\", \"sleep 3600\") stdin=${run_feed_payload} timeout-ms=600]\n",
		probe_budget_ms)
	assert !r.killed, 'a child that reads nothing mid-feed ran past ${probe_budget_ms}ms under a 600ms budget — the feed is still outside the deadline (#1030)'
	assert r.elapsed < 15000, 'a 600ms budget spent ${r.elapsed}ms once a \$stdin payload was in flight'
	assert r.out.contains('timed-out=true'), 'the child killed mid-feed was not reported as timed out; got: ${r.out}'
}

// The WIDENED LOOP GUARD (#1030). The drain loop used to run only when something
// was captured or a budget was set; it is now also where the payload is
// DELIVERED, so `capture=:none` with a payload and NO `$timeout-ms` — the one
// combination that previously had no loop at all — has to keep working. Both
// halves are pinned: the small payload that the shipped
// test_run_stdin_with_capture_none already covers via the pipe, and an
// over-capacity one whose bytes land on an INHERITED stderr, so the count is
// proof the whole feed was delivered with no captured stream to interleave with.
fn test_run_capture_none_still_delivers_an_over_capacity_feed() {
	$if windows {
		eprintln('SKIP: POSIX pipe-capacity semantics (§4.9)')
		return
	}
	r := run_cx('cx_1030_run_feed_capnone.cx', run_feed_preamble +
		"[\$p:run (\"sh\", \"-c\", \"wc -c | tr -d ' ' 1>&2\") stdin=${run_feed_payload} capture=:none]\n" +
		"'SURVIVED-CAPNONE-1030'\n", probe_budget_ms)
	assert !r.killed, 'a payload with nothing captured and no budget hung run — the drain loop no longer runs on the one path that has only a feed to do (#1030)'
	assert r.out.contains('SURVIVED-CAPNONE-1030'), 'the cx process did not outlive a capture=:none feed; got: ${r.out}'
	assert r.out.contains('${feed_flood_bytes}'), 'the child counted something other than ${feed_flood_bytes} bytes — the feed was truncated on the uncaptured path; got: ${r.out}'
	assert !r.out.contains('stdout='), 'capture=:none reported a captured stdout; got: ${r.out}'
}

// THE SHARED HANDLER DISCIPLINE, composed. `run` and `pipeline` now both move the
// process's SIGPIPE disposition for their own duration and restore what they
// found (proc_feed_arm, one enactment site). A shared save/restore is exactly the
// kind of thing that decays silently — a restore that puts back the wrong handler,
// or an exit path that forgets to restore at all, leaves the NEXT call in the
// program to discover it — so the sequence is pinned rather than assumed.
//
// Four feeding calls in one program, alternating entry points, three of them
// ending at EPIPE: run → pipeline → run → run. Every one must produce its result
// and the marker must print. Pre-fix this died at the FIRST form with rc=141 (that
// is (e)'s red-proof); what it protects going forward is the composition — if
// `run` left the absorber installed, or restored a stale handler, the pipeline
// form or the later `run` is where it would show.
//
// The trailing `cat` with a small payload is deliberate: it is the one call here
// that runs the feed to `.done` rather than `.gone`, so a restore bug that only
// bites the normal completion path cannot hide behind three EPIPE endings.
fn test_run_and_pipeline_feeds_compose_in_one_program() {
	$if windows {
		eprintln('SKIP: POSIX signal-disposition semantics (§4.9)')
		return
	}
	r := run_cx('cx_1030_mixed_feeds.cx', run_feed_preamble +
		"[\$p:run (\"head\", \"-c\", \"10\") stdin=${run_feed_payload} timeout-ms=20000]\n" +
		"[\$p:pipeline (${feed_flood_stage}, [stage [argv 'head' '-c' '10']]) timeout-ms=20000]\n" +
		"[\$p:run (\"head\", \"-c\", \"10\") stdin=${run_feed_payload} timeout-ms=20000]\n" +
		"[\$p:run (\"cat\") stdin=\"tail-payload\" timeout-ms=20000]\n" +
		"'SURVIVED-MIXED-1030'\n", probe_budget_ms)
	assert !r.killed, 'mixing run and pipeline feeds in one program hung (#1030)'
	assert r.out.contains('SURVIVED-MIXED-1030'), 'the cx process did not outlive four sequential feeds — a SIGPIPE disposition was left wrong by an earlier call; got: ${r.out}'
	// Three EPIPE endings and one clean completion, each reported.
	assert r.out.count("stdout='0000000000'") == 3, 'expected three ten-byte EPIPE results (two run, one pipeline), got ${r.out.count("stdout=\'0000000000\'")}; out: ${r.out}'
	assert r.out.contains('stdout=tail-payload'), 'the trailing run — the only feed here that reaches end-of-payload — lost its bytes; got: ${r.out}'
	assert !r.out.contains('timed-out=true'), 'a composed feed was reported as a timeout; got: ${r.out}'
}

// ── §3.3's remaining pipeline surface: env / env-clear / cwd / encoding
//    and the per-stage `[opts …]` element (#1028) ──────────────────────
//
// #1022 made `$timeout-ms` / `$kill-on-timeout` real on this entry point. Four
// more §3.3 options and an entire §3.3 ELEMENT were still accepted-and-inert:
// `stdlib/process.cx` forwarded nine arguments and `proc_pipeline` read five of
// them. `run` already honored env/env-clear/cwd, so the two entry points
// diverged silently — a pipeline written to §3.3 ran in the parent's cwd with
// the parent's environment and said nothing (#793's class).
//
// It stayed invisible because the ONLY fixture covering the per-stage element,
// conformance process-019, is a capability-DENY case: it asserts CXER0271 at
// the guard, so the stage loop it was written to exercise never runs. The
// vacuous-gate shape — a fixture whose subject is unreachable. The conformance
// twins added with these pins are the positive half; process-019 stays as the
// deny pin it correctly is.
//
// Every probe below is wall-bounded through run_cx: these all spawn real
// children, and a regression in the drain loop they share with #1022 IS a hang.

// `/` rather than a temp directory on purpose: darwin's /tmp is a symlink to
// /private/tmp, so `pwd` under cwd='/tmp' reports the PHYSICAL path and an
// assertion written against the literal '/tmp' would pass or fail by platform
// rather than by behavior. `/` and `/usr` are the same string on both.
fn test_pipeline_cwd_reaches_the_stage() {
	$if windows {
		eprintln('SKIP: POSIX process semantics (§4.9)')
		return
	}
	r := run_cx('cx_1028_pipeline_cwd.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[\$p:pipeline ([stage [argv 'pwd']]) cwd='/']\n", probe_budget_ms)
	assert !r.killed, 'the pipeline cwd probe exceeded ${probe_budget_ms}ms'
	assert r.out.contains("stdout='/\\n'"), 'pipeline-level \$cwd did not reach the stage — it ran in the parent working directory (#1028); got: ${r.out}'
}

// Same pipeline-level `cwd`, ONE per-stage option changed. This is the override
// proof AND the proof that `[opts …]` is read at all: pre-#1028 the stage loop
// found the `argv` child, broke, and dropped `[opts …]` on the floor, so both
// this probe and the one above returned the parent's directory.
fn test_pipeline_stage_opts_cwd_overrides_pipeline_level() {
	$if windows {
		eprintln('SKIP: POSIX process semantics (§4.9)')
		return
	}
	r := run_cx('cx_1028_stage_cwd.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[\$p:pipeline ([stage [argv 'pwd'] [opts cwd='/usr']]) cwd='/']\n", probe_budget_ms)
	assert !r.killed, 'the stage-opts cwd probe exceeded ${probe_budget_ms}ms'
	assert r.out.contains("stdout='/usr\\n'"), 'a per-stage [opts cwd=…] did not override pipeline-level \$cwd; got: ${r.out}'
}

fn test_pipeline_env_reaches_the_child() {
	$if windows {
		eprintln('SKIP: POSIX process semantics (§4.9)')
		return
	}
	r := run_cx('cx_1028_pipeline_env.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[\$p:pipeline ([stage [argv 'printenv' 'CXPROBE1028']]) env=[map CXPROBE1028='reached']]\n",
		probe_budget_ms)
	assert !r.killed, 'the pipeline env probe exceeded ${probe_budget_ms}ms'
	assert r.out.contains("stdout='reached\\n'"), 'pipeline-level \$env never reached the stage — printenv found no such variable (#1028); got: ${r.out}'
}

// §4.2's hermetic form: `$env-clear=true` + `$env` is the COMPLETE set. Asserted
// as an exact single line, which is what makes it an isolation proof rather than
// a presence proof — an implementation that merely overlaid ONLY onto the
// inherited environment would emit PATH and dozens of others alongside it.
fn test_pipeline_env_clear_isolates() {
	$if windows {
		eprintln('SKIP: POSIX process semantics (§4.9)')
		return
	}
	r := run_cx('cx_1028_pipeline_env_clear.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[\$p:pipeline ([stage [argv 'env']]) env-clear=true env=[map ONLY='x']]\n",
		probe_budget_ms)
	assert !r.killed, 'the pipeline env-clear probe exceeded ${probe_budget_ms}ms'
	assert r.out.contains("stdout='ONLY=x\\n'"), 'env-clear=true did not give the stage a hermetic environment; got: ${r.out}'
	assert !r.out.contains('PATH='), 'env-clear=true still leaked the parent environment into the stage; got: ${r.out}'
}

// The same isolation asked for by ONE STAGE while the pipeline stays on §4.2's
// augment default. Pins the per-stage half of `env-clear`. (Per-stage `env` is
// honored too since #1047 / CO-15, but as a CHILD ELEMENT — an attribute is
// scalar-only, so `env=` has no attribute form here; see proc_stage_opts_refusal
// and the [env {…}] probes below.)
fn test_pipeline_stage_opts_env_clear_overrides_pipeline_level() {
	$if windows {
		eprintln('SKIP: POSIX process semantics (§4.9)')
		return
	}
	r := run_cx('cx_1028_stage_env_clear.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[\$p:pipeline ([stage [argv 'env'] [opts env-clear=true]]) env=[map ONLY='x']]\n",
		probe_budget_ms)
	assert !r.killed, 'the stage env-clear probe exceeded ${probe_budget_ms}ms'
	assert r.out.contains("stdout='ONLY=x\\n'"), 'a per-stage [opts env-clear=true] did not isolate the stage; got: ${r.out}'
	assert !r.out.contains('PATH='), 'a per-stage [opts env-clear=true] still leaked the parent environment; got: ${r.out}'
}

// Per-stage overriding is decided per KEY, not per stage: a stage that names
// only `cwd` must still receive the pipeline's `$env`. Without this an
// implementation could pass every probe above by treating any `[opts …]` as a
// full replacement of the pipeline-level set.
fn test_pipeline_stage_opts_override_is_per_key() {
	$if windows {
		eprintln('SKIP: POSIX process semantics (§4.9)')
		return
	}
	r := run_cx('cx_1028_per_key.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[\$p:pipeline ([stage [argv 'sh' '-c' 'pwd; printenv CXPROBE1028'] [opts cwd='/usr']]) env=[map CXPROBE1028='reached']]\n",
		probe_budget_ms)
	assert !r.killed, 'the per-key composition probe exceeded ${probe_budget_ms}ms'
	assert r.out.contains("stdout='/usr\\nreached\\n'"), 'a stage that overrode only \$cwd lost the pipeline-level \$env — the override is being applied per STAGE instead of per KEY; got: ${r.out}'
}

// §4.1: `$search-path=false` makes argv[0] a path literal. Two probes, one
// option changed — a bare name stops resolving, an absolute path still runs.
// Without the second half an implementation that simply failed every
// search-path=false stage would pass the first.
fn test_pipeline_stage_opts_search_path_changes_resolution() {
	$if windows {
		eprintln('SKIP: POSIX process semantics (§4.9)')
		return
	}
	bare := run_cx('cx_1028_sp_bare.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[\$p:pipeline ([stage [argv 'echo' 'hi'] [opts search-path=false]])]\n",
		probe_budget_ms)
	assert !bare.killed, 'the search-path=false probe exceeded ${probe_budget_ms}ms'
	assert bare.out.contains('CXER4005'), 'search-path=false still resolved a separator-free argv[0] against PATH — the per-stage option is inert; got: ${bare.out}'
	abs := run_cx('cx_1028_sp_abs.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[\$p:pipeline ([stage [argv '/bin/echo' 'hi'] [opts search-path=false]])]\n",
		probe_budget_ms)
	assert !abs.killed, 'the search-path=false absolute-path probe exceeded ${probe_budget_ms}ms'
	assert abs.out.contains("stdout='hi\\n'"), 'search-path=false refused an absolute argv[0] as well — it is failing every stage rather than changing resolution; got: ${abs.out}'
}

// §4.7. `$encoding` was read by NO entry point in the module before #1028, so
// CXER4008 was raised nowhere in the tree and `encoding=:bytes` handed back a
// `string`. Both halves are pinned: the default DECODES (and faults on invalid
// input) while `:bytes` carries the same bytes through untouched.
fn test_pipeline_encoding_bytes_carries_binary_and_utf8_faults() {
	$if windows {
		eprintln('SKIP: POSIX process semantics (§4.9)')
		return
	}
	// 0xFF 0xFE is not a valid UTF-8 sequence in any position.
	dflt := run_cx('cx_1028_enc_utf8.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		r'[$p:pipeline ([stage [argv "printf" "\\377\\376"]])]' + '\n', probe_budget_ms)
	assert !dflt.killed, 'the encoding utf-8 probe exceeded ${probe_budget_ms}ms'
	assert dflt.out.contains('CXER4008'), 'the default encoding="utf-8" did not raise E_PROC_ENCODING_INVALID on invalid bytes — \$encoding is still inert (#1028); got: ${dflt.out}'
	raw := run_cx('cx_1028_enc_bytes.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		r'[$p:pipeline ([stage [argv "printf" "\\377\\376"]]) encoding=:bytes]' + '\n',
		probe_budget_ms)
	assert !raw.killed, 'the encoding :bytes probe exceeded ${probe_budget_ms}ms'
	assert !raw.out.contains('CXER4008'), 'encoding=:bytes still ran the utf-8 decode; got: ${raw.out}'
	assert raw.out.contains('stdout::bytes='), 'encoding=:bytes returned a decoded string instead of bytes — the §4.7 text-vs-bytes split is not observable; got: ${raw.out}'
}

// A misspelled encoding must not silently fall back to the default, because the
// default is a DECODE and the caller who misspelled it was asking for raw bytes
// (the #956/#986 rule: honored or refused BY NAME).
fn test_pipeline_unknown_encoding_is_refused_by_name() {
	r := run_cx('cx_1028_enc_bad.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[\$p:pipeline ([stage [argv 'echo' 'hi']]) encoding='latin-1']\n", probe_budget_ms)
	assert !r.killed, 'the unknown-encoding probe exceeded ${probe_budget_ms}ms'
	assert r.out.contains('CXER0100'), 'an unknown \$encoding was accepted; got: ${r.out}'
	assert r.out.contains('latin-1'), 'the refusal did not name the value it refused; got: ${r.out}'
}

// §5/§4.1: a missing `$cwd` is CXER4001, and it is raised BEFORE any stage
// spawns — checked at both levels, since a per-stage cwd is a second way in.
fn test_pipeline_missing_cwd_raises_cxer4001() {
	$if windows {
		eprintln('SKIP: POSIX process semantics (§4.9)')
		return
	}
	top := run_cx('cx_1028_cwd_missing.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[\$p:pipeline ([stage [argv 'pwd']]) cwd='/definitely-not-a-real-dir-xyz']\n",
		probe_budget_ms)
	assert !top.killed, 'the missing-cwd probe exceeded ${probe_budget_ms}ms'
	assert top.out.contains('CXER4001'), 'a missing pipeline \$cwd did not raise E_PROC_NOT_FOUND; got: ${top.out}'
	stage := run_cx('cx_1028_stage_cwd_missing.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[\$p:pipeline ([stage [argv 'pwd'] [opts cwd='/definitely-not-a-real-dir-xyz']])]\n",
		probe_budget_ms)
	assert !stage.killed, 'the missing stage-cwd probe exceeded ${probe_budget_ms}ms'
	assert stage.out.contains('CXER4001'), 'a missing per-stage [opts cwd=…] did not raise E_PROC_NOT_FOUND; got: ${stage.out}'
}

// #793: every key inside `[opts …]` that is NOT honored is an operand fault
// NAMING the key. Six of these are named by §3.3's "same keys as run" clause
// and refused anyway, because §4.3 / §3.3 elsewhere scope them to the whole
// pipeline — see proc_stage_opts_refusal and the #1028 report. An inert accept
// would be the defect this issue is about, one level in.
fn test_pipeline_stage_opts_unhonored_keys_are_refused_by_name() {
	for key in ['timeout-ms=50', 'kill-on-timeout=false', 'new-process-group=true',
		'encoding=:bytes', 'check=true', 'nonsense=1'] {
		name := key.all_before('=')
		r := run_cx('cx_1028_refuse_${name}.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
			"[\$p:pipeline ([stage [argv 'echo' 'hi'] [opts ${key}]])]\n", probe_budget_ms)
		assert !r.killed, 'the [opts ${name}] refusal probe exceeded ${probe_budget_ms}ms'
		assert r.out.contains('CXER0100'), 'a per-stage [opts ${name}=…] was silently accepted instead of refused (#793); got: ${r.out}'
		assert r.out.contains(name), 'the [opts …] refusal did not NAME the key it refused; got: ${r.out}'
	}
}

// A map-valued `env` still has no ATTRIBUTE form (attributes are scalar-only,
// code.md §6.4.1 / #396 ruling 1b), so `env=` stays refused by name. Under
// #1047 / CO-15 the refusal now points somewhere real — the `[env {…}]` child
// element — instead of at a dead end, so this pins both halves: the attribute
// is refused, and the refusal names the spelling that works.
fn test_pipeline_stage_opts_env_attribute_is_refused_by_name() {
	r := run_cx('cx_1047_refuse_env_attr.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[\$p:pipeline ([stage [argv 'echo' 'hi'] [opts env='x']])]\n", probe_budget_ms)
	assert !r.killed, 'the [opts env=…] refusal probe exceeded ${probe_budget_ms}ms'
	assert r.out.contains('CXER0100'), 'a per-stage `env=` attribute was silently accepted; got: ${r.out}'
	assert r.out.contains('env'), 'the refusal did not name `env`; got: ${r.out}'
	assert r.out.contains('child element'), 'the `env=` refusal did not point at the [env {…}] child-element spelling that IS honored (#1047); got: ${r.out}'
}

// ── per-stage `[env {…}]` — the FOURTH stage key (#1047, RULED: CO-15) ──
//
// Every probe below was RED on the pre-fix binary with the same message: "`env`
// is REFUSED … §3.3 gives no child-element spelling". The spelling exists now,
// so the refusal has to stop covering the whole surface and start covering only
// the malformed shapes.

// The POSIX shape this issue is named for: `FOO=1 cmd1 | BAR=2 cmd2`. Two
// stages, DIFFERENT variables, each child printing its own. Stage 2 also `cat`s
// stage 1's output first, so the inter-stage feed is proven still connected —
// a per-stage environment that broke the chain would be no use.
fn test_pipeline_stage_opts_env_gives_each_stage_its_own() {
	$if windows {
		eprintln('SKIP: POSIX process semantics (§4.9)')
		return
	}
	r := run_cx('cx_1047_posix_shape.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[\$p:pipeline ([stage [argv 'sh' '-c' 'printenv CXPROBE1047A'] [opts [env {CXPROBE1047A: 'one'}]]], " +
		"[stage [argv 'sh' '-c' 'cat; printenv CXPROBE1047B'] [opts [env {CXPROBE1047B: 'two'}]]])]\n",
		probe_budget_ms)
	assert !r.killed, 'the per-stage env probe exceeded ${probe_budget_ms}ms'
	assert r.out.contains("stdout='one\\ntwo\\n'"), 'a per-stage [opts [env {…}]] did not give each stage its own variable (#1047); got: ${r.out}'
}

// Neither stage may see the OTHER's variable. Without this, an implementation
// that merged every stage's `[env …]` into one pipeline-wide set would pass the
// probe above — and would be a different feature from the one CO-15 ruled.
fn test_pipeline_stage_opts_env_does_not_leak_between_stages() {
	$if windows {
		eprintln('SKIP: POSIX process semantics (§4.9)')
		return
	}
	// The marker words and the VALUES must share no substring: `stage1-done`
	// contains `one`, which is exactly the kind of accidental match that would
	// make this probe fail on a correct implementation. `ok1`/`ok2` against
	// `alpha`/`beta` cannot collide, and neither can collide with the `[argv …]`
	// echo of the program text that the result element also carries.
	r := run_cx('cx_1047_no_leak.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[\$p:pipeline ([stage [argv 'sh' '-c' 'printenv CXPROBE1047B; echo ok1'] [opts [env {CXPROBE1047A: 'alpha'}]]], " +
		"[stage [argv 'sh' '-c' 'cat; printenv CXPROBE1047A; echo ok2'] [opts [env {CXPROBE1047B: 'beta'}]]])]\n",
		probe_budget_ms)
	assert !r.killed, 'the per-stage env leak probe exceeded ${probe_budget_ms}ms'
	assert r.out.contains("stdout='ok1\\nok2\\n'"), "a stage saw the OTHER stage's variable — per-stage [env …] is being merged pipeline-wide instead of staying per stage; got: ${r.out}"
}

// CO-15's override is per KEY, and per key WITHIN `env`: the stage's `[env …]`
// OVERLAYS the pipeline's `$env` rather than replacing it. A stage that
// overrides A must still receive B and C. This is the probe that separates an
// overlay from a substitution — the two agree on everything else.
fn test_pipeline_stage_opts_env_overlays_pipeline_env_per_key() {
	$if windows {
		eprintln('SKIP: POSIX process semantics (§4.9)')
		return
	}
	r := run_cx('cx_1047_per_key.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[\$p:pipeline ([stage [argv 'sh' '-c' 'printenv CXPROBE1047A; printenv CXPROBE1047B; printenv CXPROBE1047C'] " +
		"[opts [env {CXPROBE1047A: 'stage'}]]]) env=[map CXPROBE1047A='pipe' CXPROBE1047B='pipe' CXPROBE1047C='pipe']]\n",
		probe_budget_ms)
	assert !r.killed, 'the env overlay probe exceeded ${probe_budget_ms}ms'
	assert r.out.contains("stdout='stage\\npipe\\npipe\\n'"), 'a stage [env …] REPLACED the pipeline \$env instead of overlaying it per key (#1047); got: ${r.out}'
}

// Composition with `env-clear`, order 1: the STAGE asks to be hermetic and
// supplies its own set. Asserted as an exact single line — an implementation
// that overlaid the stage set onto the inherited environment would emit PATH
// and dozens of others alongside it.
fn test_pipeline_stage_opts_env_composes_with_stage_env_clear() {
	$if windows {
		eprintln('SKIP: POSIX process semantics (§4.9)')
		return
	}
	r := run_cx('cx_1047_clear_stage.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[\$p:pipeline ([stage [argv 'env'] [opts env-clear=true [env {CXPROBE1047ONLY: 'x'}]]])]\n",
		probe_budget_ms)
	assert !r.killed, 'the stage env-clear composition probe exceeded ${probe_budget_ms}ms'
	assert r.out.contains("stdout='CXPROBE1047ONLY=x\\n'"), 'a stage [env …] under its own env-clear=true did not yield exactly the stage set (#1047); got: ${r.out}'
	assert !r.out.contains('PATH='), 'env-clear=true with a stage [env …] still leaked the parent environment; got: ${r.out}'
}

// Composition with `env-clear`, order 2: the PIPELINE is hermetic and supplies
// the set, and the stage overrides ONE key of it. This is the whole RULED
// order — env-clear picks the base, pipeline $env lands, stage [env …] lands
// last — observable in a single child's complete environment.
//
// The body reads the variables with the `echo` BUILTIN, not `printenv`, and
// under `env-clear` it has to (#1051). §4.2 gives the child EXACTLY the
// declared set, so it has no PATH; asking the child shell to resolve an
// external `printenv` against nothing makes the outcome a property of
// whichever `sh` §4.1 resolved from the PARENT's PATH. Measured on one binary:
// macOS /bin/sh falls back to a default PATH and finds printenv, the nix bash
// that `devbox run -- make` puts first falls back to `/no-such-path` and exits
// 127 with EMPTY stdout. A builtin needs no PATH, so this probe measures the
// layering instead of the invoker's PATH. The `printenv` probes above stay as
// they are: they run under the augment default and inherit PATH.
fn test_pipeline_stage_opts_env_composes_with_pipeline_env_clear() {
	$if windows {
		eprintln('SKIP: POSIX process semantics (§4.9)')
		return
	}
	r := run_cx('cx_1047_clear_pipeline.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[\$p:pipeline ([stage [argv 'sh' '-c' 'echo \$CXPROBE1047A; echo \$CXPROBE1047B'] [opts [env {CXPROBE1047B: 'stage'}]]]) " +
		"env-clear=true env=[map CXPROBE1047A='pipe' CXPROBE1047B='pipe']]\n",
		probe_budget_ms)
	assert !r.killed, 'the pipeline env-clear composition probe exceeded ${probe_budget_ms}ms'
	assert r.out.contains("stdout='pipe\\nstage\\n'"), 'the RULED order env-clear -> pipeline \$env -> stage [env …] did not hold (#1047); got: ${r.out}'
}

// §4.2's null-value delete, reached through the stage layer: the pipeline sets
// the key for every stage and ONE stage removes it. Without this the stage
// layer could only ever add, and "override per key" would be half true.
fn test_pipeline_stage_opts_env_null_deletes_a_pipeline_key() {
	$if windows {
		eprintln('SKIP: POSIX process semantics (§4.9)')
		return
	}
	r := run_cx('cx_1047_delete.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		"[\$p:pipeline ([stage [argv 'sh' '-c' 'printenv CXPROBE1047A || echo gone'] [opts [env {CXPROBE1047A: null}]]]) " +
		"env=[map CXPROBE1047A='pipe']]\n", probe_budget_ms)
	assert !r.killed, 'the stage env delete probe exceeded ${probe_budget_ms}ms'
	assert r.out.contains("stdout='gone\\n'"), 'a null-valued stage [env …] entry did not DELETE the pipeline key (§4.2); got: ${r.out}'
}

// The malformed bodies. Each is refused by name rather than read as an empty
// overlay — an env map that silently became `{}` is exactly the #793 shape this
// whole surface exists to keep out, one level deeper than #1028 found it.
fn test_pipeline_stage_opts_env_malformed_bodies_are_refused() {
	shapes := {
		'nonmap':    "[opts [env 'notamap']]"
		'missing':   '[opts [env]]'
		'nonscalar': "[opts [env {K: {N: '1'}}]]"
		'duplicate': "[opts [env {A: '1'}] [env {B: '2'}]]"
		'unknown':   "[opts [envx {A: '1'}]]"
	}
	for name, opts in shapes {
		r := run_cx('cx_1047_bad_${name}.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
			"[\$p:pipeline ([stage [argv 'echo' 'hi'] ${opts}])]\n", probe_budget_ms)
		assert !r.killed, 'the [env …] ${name} refusal probe exceeded ${probe_budget_ms}ms'
		assert r.out.contains('CXER0100'), 'a malformed stage [env …] (${name}) was silently accepted instead of refused (#793); got: ${r.out}'
		assert r.out.contains('env'), 'the ${name} refusal did not name `env`; got: ${r.out}'
	}
}

// The new options must COMPOSE with #1022's drain rather than sit in front of
// it: the same over-capacity stderr flood, now under a pipeline that also sets
// cwd and env. If the option wiring re-ordered or short-circuited the drain
// loop, this deadlocks exactly as it did before #1022.
fn test_pipeline_options_compose_with_the_stderr_drain() {
	$if windows {
		eprintln('SKIP: POSIX process semantics (§4.9)')
		return
	}
	r := run_cx('cx_1028_compose_drain.cx', "[?lib 'cx-stdlib/process' :as p]\n" +
		'[\$p:pipeline ([stage [argv \'sh\' \'-c\' "printf \'%0${stderr_flood_bytes}d\' 1 1>&2; pwd"]], [stage [argv \'cat\']]) cwd=\'/\' env=[map CXPROBE1028=\'reached\']]\n',
		probe_budget_ms)
	assert !r.killed, 'a pipeline carrying §3.3 options deadlocked on ${stderr_flood_bytes} stderr bytes — the #1028 wiring broke #1022 drain'
	assert r.out.contains("stdout='/\\n'"), 'the composed pipeline lost cwd or the stdout→stdin chaining; got: ${r.out}'
}

// ── `run`'s `$capture`: the SAME vocabulary (#1023 / RULED: CO-16) ───
//
// THE MEASURED HARM, and it was two harms stacked. §4.3 said outright that
// "`run`'s only per-stream choice is capture-or-inherit … it has no file
// target", so a caller who wanted a BOUNDED child whose output lands in a FILE
// had nothing to reach for: `run` gave the bound and no file, `spawn` gave the
// file and no bound. probe.cx therefore shelled out to `sh -c '… > file'` and
// lost the `$timeout-ms` bound that is the entire reason to call `run`.
//
// Underneath that, the closed four-atom `$capture` did not merely lack the
// vocabulary — it SWALLOWED it. `proc_arg_atom(args[7]) or { 'both' }` fell back
// to `:both` for any non-atom, so on the pre-change binary (measured 2026-08-26)
// `[$run <200,000-byte child> capture={stdout: "/tmp/out.log"}]` returned
// exit-code=0 with all 200,000 bytes on `stdout=`, and /tmp/out.log was NEVER
// CREATED. A silent fallback to the opposite of what was asked — the #793 class,
// and exactly what §3.2's "a misspelled disposition is never silently the
// default" exists to prevent. `capture=:discard` at least refused BY NAME on
// that binary, which is how narrow the closed set was.
//
// CO-16 ruled ONE vocabulary across all entry points, read by ONE reader
// (proc_redirect_of), so `run` cannot drift from `spawn` on which values are
// accepted. The probes below are the disposition × timeout × encoding matrix
// that keeps it one.

// A stdout flood sized past every platform's pipe capacity.
const stdout_flood_bytes = 200000

const stdout_flood_child = "('sh', '-c', \"printf '%0${stdout_flood_bytes}d' 1\")"

// A child that outlives any budget WITHOUT leaving a grandchild: `exec` replaces
// the shell, so the pid `run` signals is the pid that hangs. A non-exec `sleep`
// here would orphan a grandchild holding this harness's own stdout pipe — which
// is a property of the probe, not of `run`, and would report as a hang in the
// wrong place (measured while building this file).
const hung_child_after_output = "('sh', '-c', \"echo EARLY; exec sleep 3600\")"

// THE CASE #1023 WAS FILED FOR: bounded run, output in a file, nothing resident.
// Red-proven — this exact call returned the bytes in memory and created no file
// on the pre-change binary.
fn test_run_capture_file_target_is_bounded_and_never_resident() {
	$if windows {
		eprintln('SKIP: POSIX descriptor staging (§4.9)')
		return
	}
	dir := probe_dir('1023-outfile')
	outf := os.join_path(dir, 'out.log')
	r := run_cx('cx_1023_outfile.cx', preamble + '[\$p:run ${stdout_flood_child} ' +
		"capture={stdout: '${outf}'} timeout-ms=${probe_budget_ms}]\n", probe_budget_ms)
	assert !r.killed, 'the bounded file-target run exceeded ${probe_budget_ms}ms'
	assert os.exists(outf), 'capture={stdout: <path>} never created ${outf} — the disposition is being swallowed exactly as it was pre-change'
	sz := os.file_size(outf)
	assert sz == u64(stdout_flood_bytes), 'the file target holds ${sz} bytes, expected exactly ${stdout_flood_bytes}'
	// NOT RESIDENT. A non-`:pipe` stream was never ours, so it carries no
	// attribute on the [proc-result …] at all — §4.6's rule that an empty stream
	// would assert a non-fact, carried to `run`, where absence is how it is said.
	assert !r.out.contains('stdout='), 'the file-targeted stdout came back on the proc-result as well — it was captured into memory too; got ${r.out.len} bytes'
	assert r.out.len < 1000, 'the run materialized the flood despite the file target (${r.out.len} bytes of result)'
	assert r.out.contains('exit-code=0'), 'the file-target run did not report a clean exit; got: ${r.out}'
	os.rmdir_all(dir) or {}
}

// dispositions × TIMEOUT. A file target cannot fill, so the budget is the only
// thing that can end this child — and it must still end it. The pre-change
// substitute for "bounded + file" was `sh -c '… > file'`, which has no budget at
// all; this is the row saying the two now compose.
fn test_run_capture_file_target_composes_with_the_timeout() {
	$if windows {
		eprintln('SKIP: POSIX descriptor staging (§4.9)')
		return
	}
	dir := probe_dir('1023-outfile-timeout')
	outf := os.join_path(dir, 'out.log')
	r := run_cx('cx_1023_outfile_timeout.cx', preamble + '[\$p:run ${hung_child_after_output} ' +
		"capture={stdout: '${outf}'} timeout-ms=600]\n", probe_budget_ms)
	assert !r.killed, 'a file-targeted run under a 600ms budget was not bounded — the probe had to kill it at ${probe_budget_ms}ms'
	assert r.out.contains('timed-out=true'), 'the file-targeted run did not report timed-out=true; got: ${r.out}'
	// §2.3: a forced kill reports the platform's signal-encoded status.
	assert r.out.contains('signaled=true'), 'the timed-out file-target run did not report signaled=true; got: ${r.out}'
	// A file target KEEPS what it got — it is not a discard with extra steps.
	got := os.read_file(outf) or { '' }
	assert got.contains('EARLY'), 'the file target lost the bytes written before the deadline; got: ${got}'
	os.rmdir_all(dir) or {}
}

// dispositions × ENCODING. §4.7 decodes what the call CAPTURED, and only that.
// The same invalid-UTF-8 child faults under `:pipe` and does not fault when its
// stdout goes to a file — those bytes were never ours to decode, and the file
// holds them raw. Both directions in one probe, so neither can rot alone.
fn test_run_capture_encoding_scopes_to_captured_streams_only() {
	$if windows {
		eprintln('SKIP: POSIX descriptor staging (§4.9)')
		return
	}
	dir := probe_dir('1023-enc')
	outf := os.join_path(dir, 'raw.bin')
	bad := "('sh', '-c', \"printf '\\\\377'\")"
	rp := run_cx('cx_1023_enc_pipe.cx', preamble + '[\$p:run ${bad}]\n', probe_budget_ms)
	assert rp.out.contains('CXER4008'), 'a CAPTURED invalid-utf-8 stdout stopped raising CXER4008 — §4.7 no longer reaches the capture; got: ${rp.out}'
	rf := run_cx('cx_1023_enc_file.cx', preamble + '[\$p:run ${bad} ' +
		"capture={stdout: '${outf}'}]\n", probe_budget_ms)
	assert !rf.out.contains('CXER4008'), 'a FILE-targeted stdout raised the capture encoding fault — §4.7 is decoding bytes that were never captured; got: ${rf.out}'
	assert rf.out.contains('exit-code=0'), 'the file-targeted invalid-utf-8 run did not complete cleanly; got: ${rf.out}'
	raw := os.read_file(outf) or { '' }
	assert raw.len == 1 && raw[0] == 0xFF, 'the file target did not hold the raw byte undecoded; got ${raw.len} bytes'
	// And `:bytes` still reaches the stream that IS captured, alongside a file
	// target on the other one — the two options are independent.
	e2 := os.join_path(dir, 'e2.log')
	rb := run_cx('cx_1023_enc_bytes_mix.cx', preamble +
		"[\$p:run ('sh', '-c', \"printf 'hi'; printf 'EE' 1>&2\") capture={stderr: '${e2}'} encoding=:bytes]\n",
		probe_budget_ms)
	assert rb.out.contains('stdout::bytes=hi'), 'encoding=:bytes stopped reaching the captured stream when the other stream had a file target; got: ${rb.out}'
	assert (os.read_file(e2) or { '' }) == 'EE', 'the file-targeted stderr did not receive its bytes alongside a :bytes capture'
	os.rmdir_all(dir) or {}
}

// The map is applied PER KEY, and an unnamed key keeps `$capture`'s default for
// its stream — `:pipe`. CO-15's per-KEY layering rule, one section over.
fn test_run_capture_map_is_per_key_with_the_default_kept() {
	$if windows {
		eprintln('SKIP: POSIX descriptor staging (§4.9)')
		return
	}
	dir := probe_dir('1023-perkey')
	errf := os.join_path(dir, 'err.log')
	r := run_cx('cx_1023_perkey.cx', preamble +
		"[\$p:run ('sh', '-c', \"echo OUT; echo ERR 1>&2\") capture={stderr: '${errf}'}]\n",
		probe_budget_ms)
	assert !r.killed, 'the per-key capture probe exceeded ${probe_budget_ms}ms'
	assert r.out.contains("stdout='OUT\\n'"), 'naming only `stderr` lost the DEFAULT capture of stdout — the map is replacing the default rather than overlaying it per key; got: ${r.out}'
	assert !r.out.contains('stderr='), 'the file-targeted stderr still came back on the proc-result; got: ${r.out}'
	assert (os.read_file(errf) or { '' }) == 'ERR\n', 'the per-key stderr file target did not receive the bytes'
	os.rmdir_all(dir) or {}
}

// The four shipped atoms are ABBREVIATIONS for pairs of dispositions, and this
// is the table. It doubles as the compatibility proof: every one of these
// behaved exactly this way before CO-16 and must go on doing so.
fn test_run_capture_legacy_atoms_are_the_documented_pairs() {
	$if windows {
		eprintln('SKIP: POSIX process semantics (§4.9)')
		return
	}
	child := "('sh', '-c', \"echo OUT; echo ERR 1>&2\")"
	rb := run_cx('cx_1023_both.cx', preamble + '[\$p:run ${child} capture=:both]\n',
		probe_budget_ms)
	assert rb.out.contains("stdout='OUT\\n'") && rb.out.contains("stderr='ERR\\n'"), ':both stopped capturing both streams; got: ${rb.out}'
	ro := run_cx('cx_1023_stdout.cx', preamble + '[\$p:run ${child} capture=:stdout]\n',
		probe_budget_ms)
	assert ro.out.contains("stdout='OUT\\n'") && !ro.out.contains('stderr='), ':stdout is no longer stdout-captured/stderr-inherited; got: ${ro.out}'
	assert ro.out.contains('ERR'), ":stdout stopped letting stderr reach the parent's own descriptor; got: ${ro.out}"
	re := run_cx('cx_1023_stderr.cx', preamble + '[\$p:run ${child} capture=:stderr]\n',
		probe_budget_ms)
	assert re.out.contains("stderr='ERR\\n'") && !re.out.contains('stdout='), ':stderr is no longer stderr-captured/stdout-inherited; got: ${re.out}'
	rn := run_cx('cx_1023_none.cx', preamble + '[\$p:run ${child} capture=:none]\n',
		probe_budget_ms)
	assert !rn.out.contains('stdout=') && !rn.out.contains('stderr='), ':none captured something; got: ${rn.out}'
	assert rn.out.contains('OUT') && rn.out.contains('ERR'), ':none stopped letting both streams reach the parent; got: ${rn.out}'
}

// The vocabulary's own atoms, applied to both output streams. `:pipe` and
// `:inherit` are synonyms for `:both` / `:none` — the price of one vocabulary,
// and cheaper than a caller having to remember which entry point wants which
// word. `:discard` bare is the one genuinely new whole-capture value, and it was
// refused BY NAME on the pre-change binary (measured).
fn test_run_capture_bare_dispositions_apply_to_both_streams() {
	$if windows {
		eprintln('SKIP: POSIX descriptor staging (§4.9)')
		return
	}
	child := "('sh', '-c', \"echo OUT; echo ERR 1>&2\")"
	rp := run_cx('cx_1023_bare_pipe.cx', preamble + '[\$p:run ${child} capture=:pipe]\n',
		probe_budget_ms)
	assert rp.out.contains("stdout='OUT\\n'") && rp.out.contains("stderr='ERR\\n'"), 'capture=:pipe did not capture both streams like :both; got: ${rp.out}'
	ri := run_cx('cx_1023_bare_inherit.cx', preamble + '[\$p:run ${child} capture=:inherit]\n',
		probe_budget_ms)
	assert !ri.out.contains('stdout=') && !ri.out.contains('stderr='), 'capture=:inherit captured something; got: ${ri.out}'
	assert ri.out.contains('OUT') && ri.out.contains('ERR'), 'capture=:inherit did not send both streams to the parent; got: ${ri.out}'
	rd := run_cx('cx_1023_bare_discard.cx', preamble + '[\$p:run ${child} capture=:discard]\n',
		probe_budget_ms)
	assert !rd.out.contains('CXER'), 'capture=:discard is still refused — the vocabulary did not reach `run`; got: ${rd.out}'
	assert !rd.out.contains('stdout=') && !rd.out.contains('stderr='), 'capture=:discard captured something; got: ${rd.out}'
	// Discarded means discarded: neither stream reached the parent either.
	assert !rd.out.contains('OUT') && !rd.out.contains('ERR'), 'capture=:discard leaked a stream to the parent instead of the null device; got: ${rd.out}'
	assert rd.out.contains('exit-code=0'), 'capture=:discard did not report a clean exit; got: ${rd.out}'
}

// A BARE PATH is the one cell CO-16 does not rule. It would have to mean both
// output streams into one file — a MERGE, POSIX's `>f 2>&1`, a shared file
// offset between two independent writers — and §3.2's file disposition is stated
// PER STREAM ("an output stream creates-or-truncates it"), so applying it to two
// is either two truncations racing or a semantic this module has never defined.
// It refuses BY NAME and points at the spelling that IS defined. Refusal-by-name
// is the forward-compatible shape: a ruled merge can land here later without
// breaking a caller, whereas a guess now could not be taken back.
fn test_run_capture_bare_path_is_refused_by_name() {
	$if windows {
		eprintln('SKIP: POSIX descriptor staging (§4.9)')
		return
	}
	dir := probe_dir('1023-barepath')
	bare := os.join_path(dir, 'bare.log')
	r := run_cx('cx_1023_bare_path.cx', preamble +
		"[\$p:run ('echo', 'hi') capture='${bare}']\n", probe_budget_ms)
	assert r.out.contains('CXER0100'), 'a bare-path capture was ACCEPTED — it must not guess a merge semantic; got: ${r.out}'
	assert r.out.contains('merge'), 'the bare-path refusal does not say WHY it refuses; got: ${r.out}'
	assert r.out.contains('capture={stdout:'), 'the bare-path refusal does not name the spelling that works; got: ${r.out}'
	assert !os.exists(bare), 'the refused bare path was created anyway — the refusal is not fail-closed'
	os.rmdir_all(dir) or {}
}

// Every other malformed `$capture` refuses BY NAME too. A misspelled disposition
// is never silently the default — which is precisely what the closed four-atom
// set did to a map, and what made #1023 a silent wrong answer rather than merely
// a missing feature.
fn test_run_capture_malformed_forms_refuse_by_name() {
	$if windows {
		eprintln('SKIP: POSIX process semantics (§4.9)')
		return
	}
	// `run`'s stdin is a PAYLOAD, not a disposition — refused, and it says where.
	rs := run_cx('cx_1023_cap_stdin.cx', preamble +
		"[\$p:run ('cat',) capture={stdin: :discard}]\n", probe_budget_ms)
	assert rs.out.contains('CXER0100'), 'a `stdin` capture key was accepted; got: ${rs.out}'
	assert rs.out.contains('PAYLOAD'), "the `stdin` refusal does not say where run's stdin lives; got: ${rs.out}"
	rk := run_cx('cx_1023_cap_unknown_key.cx', preamble +
		"[\$p:run ('echo', 'hi') capture={stdrr: :discard}]\n", probe_budget_ms)
	assert rk.out.contains('CXER0100') && rk.out.contains('stdrr'), 'an unknown capture key was not refused BY NAME; got: ${rk.out}'
	// An unknown disposition inside a well-formed map — refused by the SAME
	// reader `spawn` uses, so the accepted set cannot drift between them.
	rd := run_cx('cx_1023_cap_unknown_disp.cx', preamble +
		"[\$p:run ('echo', 'hi') capture={stdout: :swallow}]\n", probe_budget_ms)
	assert rd.out.contains('CXER0100') && rd.out.contains(':swallow'), 'an unknown disposition was not refused BY NAME; got: ${rd.out}'
	assert rd.out.contains(':pipe/:inherit/:discard'), 'the disposition refusal does not name the accepted set; got: ${rd.out}'
	// An unknown whole-capture atom still refuses, as it always did — but the
	// message now names the WHOLE accepted set, not just the four legacy atoms.
	ra := run_cx('cx_1023_cap_unknown_atom.cx', preamble +
		"[\$p:run ('echo', 'hi') capture=:everything]\n", probe_budget_ms)
	assert ra.out.contains('CXER0100') && ra.out.contains(':everything'), 'an unknown capture atom was not refused BY NAME; got: ${ra.out}'
	assert ra.out.contains(':pipe/:inherit/:discard'), 'the capture refusal still advertises only the four legacy atoms; got: ${ra.out}'
	// An empty file path is not a file.
	rz := run_cx('cx_1023_cap_empty_path.cx', preamble +
		'[\$p:run (\'echo\', \'hi\') capture={stdout: ""}]\n', probe_budget_ms)
	assert rz.out.contains('CXER0100'), 'an empty capture file path was accepted; got: ${rz.out}'
	// A non-map, non-atom capture.
	rn := run_cx('cx_1023_cap_nonmap.cx', preamble +
		"[\$p:run ('echo', 'hi') capture=[foo]]\n", probe_budget_ms)
	assert rn.out.contains('CXER0100') && rn.out.contains('not a map'), 'a non-map capture element was not refused BY NAME; got: ${rn.out}'
}

// An unopenable file target is CXER4001/CXER4002 raised BEFORE the fork — the
// fail-closed discipline §3.2's dispositions already carry, now on `run` too.
// The marker proves the child never ran: a half-spawned run that then faulted on
// its redirect would leave the side effect behind.
fn test_run_capture_unopenable_target_faults_before_the_spawn() {
	$if windows {
		eprintln('SKIP: POSIX descriptor staging (§4.9)')
		return
	}
	dir := probe_dir('1023-badtarget')
	marker := os.join_path(dir, 'child-ran')
	bad := os.join_path(dir, 'no-such-dir', 'out.log')
	r := run_cx('cx_1023_badtarget.cx', preamble +
		"[\$p:run ('sh', '-c', \"touch '${marker}'\") capture={stdout: '${bad}'}]\n",
		probe_budget_ms)
	assert r.out.contains('CXER4001') || r.out.contains('CXER4002'), 'an unopenable capture target did not fault; got: ${r.out}'
	assert !os.exists(marker), 'the child RAN before the unopenable redirect faulted — the check is not before the spawn'
	os.rmdir_all(dir) or {}
}

// The `$stdin` PAYLOAD and the new output dispositions are independent axes, and
// #1030's non-blocking feed must keep working underneath a file target: the
// payload goes in through a pipe of ours, the answer comes out into a file
// neither of us has to drain.
fn test_run_capture_file_target_composes_with_the_stdin_payload() {
	$if windows {
		eprintln('SKIP: POSIX descriptor staging (§4.9)')
		return
	}
	dir := probe_dir('1023-fed')
	outf := os.join_path(dir, 'fed.log')
	r := run_cx('cx_1023_fed.cx', preamble +
		"[\$p:run ('cat',) stdin='FED-PAYLOAD' capture={stdout: '${outf}'}]\n",
		probe_budget_ms)
	assert !r.killed, 'the payload+file-target run exceeded ${probe_budget_ms}ms — the feed never got its EOF'
	assert r.out.contains('exit-code=0'), 'the payload+file-target run did not complete cleanly; got: ${r.out}'
	assert (os.read_file(outf) or { '' }) == 'FED-PAYLOAD', 'the stdin payload did not round-trip into the file-targeted stdout'
	os.rmdir_all(dir) or {}
}

// §4.4's descriptor-release contract, extended over the new dispositions. The
// file and discard paths stage the PARENT's own descriptors across the fork and
// put them back; if either that staging or the capture-fd release leaked, the
// count climbs. process-058's shape, run over the dispositions CO-16 added.
fn test_run_capture_dispositions_release_every_descriptor() {
	$if windows {
		eprintln('SKIP: POSIX descriptor staging (§4.9)')
		return
	}
	dir := probe_dir('1023-fds')
	outf := os.join_path(dir, 'sink.log')
	count := "('sh', '-c', 'ls /dev/fd | wc -l')"
	r := run_cx('cx_1023_fds.cx', preamble + "[?lib 'cx-stdlib/strings' :as s]\n" + '[?let\n' +
		"  [= \$a [\$p:run ${count} capture={stdout: '${outf}'}]]\n" +
		'  [= \$b [\$p:run ${count} capture=:discard]]\n' +
		"  [= \$c [\$p:run ${count} capture={stderr: '${outf}'}]]\n" +
		'  [= \$d [\$p:run ${count}]]\n' + '  [= \$e [\$p:run ${count}]]\n' +
		'  ([\$s:trim \$d@stdout], [\$s:trim \$e@stdout])]\n', probe_budget_ms)
	assert !r.killed, 'the descriptor-release probe exceeded ${probe_budget_ms}ms'
	parts := r.out.trim_space().trim_string_left('(').trim_string_right(')').split(', ')
	assert parts.len == 2, 'the descriptor probe did not report two counts; got: ${r.out}'
	assert parts[0] == parts[1], 'the parent open-descriptor count MOVED across runs (${parts[0]} then ${parts[1]}) — a capture fd or a staged descriptor leaks on the new dispositions'
}
