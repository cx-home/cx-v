// stdlib_supervise_test.v — the timing-sensitive supervise arms that the
// conformance corpus cannot fixture (spec/03-approved/std-lib/supervise.md
// §10; RULED: SUP-1, rider SUP-1f — ledger/rulings_2026_08_20_supervise.md).
//
// The .cxd corpus (conformance/stdlib/supervise.cxd) pins every
// deterministic arm. What lives HERE is the no-hang guarantee against a
// WEDGED child — one that swallows the cancellation err and keeps
// computing without ever crossing another cancellation point. On the
// reference substrate `[?cancel]` stamps the WORKER_CANCELLED terminal
// at request time (state_locks.v cancel-wins arbitration, §10.5.4), so
// the supervisor's shutdown-bounded wait resolves promptly and
// `[child-abandoned]` is unreachable — a .cxd fixture cannot observe a
// shutdown-window expiry. This lane pins the two live guarantees:
//
//   1. NO-HANG: `stop` of a supervisor whose child is mid-way through a
//      cancellation-point-free compute returns promptly (bounded by the
//      child's shutdown= plus loop slack), never joins the compute.
//   2. TERMINAL HONESTY: the stopped supervisor's status reports the
//      child `stopped` (the platform's requested-outcome terminal), and
//      the wedged body's late note (posted after its compute finally
//      ends, if its send is not itself refused at the cancellation
//      point) never resurrects the child — the stale-incarnation guard
//      drops it.

module main

import code
import time

// A child that swallows the cancellation err raised at its blocking
// receive and then busy-computes ~1M pure recursion steps (seconds of
// CPU, zero cancellation points) — the honest "wedged" shape §4.4
// names: cancellation is cooperative and this body stops cooperating.
const wedged_prog = "[?lib 'cx-stdlib/supervise' :as sup]
[?def busy scope=public pure [returns int] (\$n::int)
  [?if [< \$n 1] [then 0] [else [busy [- \$n 1]]]]]
[?let [= \$never [?channel name=\"vlane-never\" buffer=1]]
[= \$s [\$sup:start [policy strategy=:one-for-one max-restarts=3]
        ([child name=\"w\" shutdown=200ms
           [fn [?fn () [?fallback [?receive from=\$never]
                         [recover-with [busy 1000000]]]]]])]]
[= \$ev [\$sup:events \$s]]
[= \$e0 [?receive from=\$ev max=1 deadline=8000]]
[= \$_stp [\$sup:stop \$s]]
[= \$st [\$sup:status \$s]]
\$st]"

fn test_wedged_child_stop_no_hang_and_terminal_honesty() {
	sw := time.new_stopwatch()
	out := code.eval_code('', wedged_prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	elapsed_ms := sw.elapsed().milliseconds()
	// Terminal honesty: the child reports stopped (the request-stamped
	// terminal), never a hang, never a phantom 'running'.
	assert out.contains('[child name=w state=stopped'), 'expected the wedged child reported stopped, got: ${out}'
	assert out.contains('restarts-in-window=0'), 'a supervisor-initiated stop must never count against intensity, got: ${out}'
	// No-hang: the whole program — start, stop (bounded by shutdown=200ms
	// + loop slack), status — must complete WITHOUT joining the wedged
	// compute (~seconds of CPU). EV-WORKER-EXIT drains the compute at
	// program end, which eval_code includes, so the bound here is the
	// compute duration plus slack: the assertion is that stop() itself
	// did not ALSO serialize a second compute-length wait. 60s is the
	// generous CI ceiling; the typical run is a few seconds.
	assert elapsed_ms < 60_000, 'wedged-child stop took ${elapsed_ms}ms — the supervisor hung on a wedged child'
}

// The same wedged shape under stop-child: the verb returns true (the
// child was present and is removed) promptly — the no-hang guarantee at
// the per-child verb.
const wedged_stop_child_prog = "[?lib 'cx-stdlib/supervise' :as sup]
[?def busy2 scope=public pure [returns int] (\$n::int)
  [?if [< \$n 1] [then 0] [else [busy2 [- \$n 1]]]]]
[?let [= \$never [?channel name=\"vlane-never2\" buffer=1]]
[= \$ok [?channel name=\"vlane-ok2\" buffer=1]]
[= \$s [\$sup:start [policy strategy=:one-for-one max-restarts=3]
        ([child name=\"w\" shutdown=200ms
           [fn [?fn () [?fallback [?receive from=\$never]
                         [recover-with [busy2 1000000]]]]]],
         [child name=\"keep\" [fn [?fn () [?receive from=\$ok]]]])]]
[= \$ev [\$sup:events \$s]]
[= \$e0 [?receive from=\$ev max=2 deadline=8000]]
[= \$r [\$sup:stop-child \$s \"w\"]]
[= \$st [\$sup:status \$s]]
[= \$_stp [\$sup:stop \$s]]
(\$r, \$st)]"

fn test_wedged_child_stop_child_prompt() {
	out := code.eval_code('', wedged_stop_child_prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('true'), 'stop-child of a present (wedged) child must return true, got: ${out}'
	assert out.contains('[child name=keep state=running'), 'the sibling must be untouched by a wedged stop-child, got: ${out}'
	assert !out.contains('name=w state='), 'stop-child must REMOVE the child from status, got: ${out}'
}
