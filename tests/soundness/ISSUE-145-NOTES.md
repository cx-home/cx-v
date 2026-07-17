# #145 — multi-reactor http:serve GC residual: investigation runbook

Status: **RESOLVED (2026-06-28).** Root cause was a **macOS-arm64-only** async mach-suspend
register/SP capture gap in the vgc STW (Linux's signal-suspend was always sound). Fixed by
switching the darwin STW peer-suspend to a signal-based mechanism (third_party/v
`vgc_platform.h`, fork `7b15dbcec4`). Gate-green `bf1=0 + crash=0` on macOS native arm64 AND
Linux Docker arm64 at the #144 churn cadence, at comparable/higher throughput; multi-reactor
default restored (`min(4, cores)`). Full history + evidence below.

## TL;DR (resolved)
A live per-request env-clone key buffer was reclaimed by vgc (sweep-while-live UAF) under
**multi-reactor** `http:serve` + **frequent collection** (PR #144 churn cadence) — but ONLY on
macOS arm64. The Linux production target was always sound (verified at 20× macOS throughput,
0 events). The macOS defect was the async `thread_suspend`+`thread_get_state` capturing a peer
at a weaker stop point than a kernel-delivered signal; the fix gives darwin the same precise
signal-suspend Linux uses. See "Session-4 BREAKTHROUGH" and "Session-4 RESOLUTION" below.
(Earlier sessions' "single-reactor is the only correct posture / `CX_HTTP_N=1`" is SUPERSEDED.)

## Reproduce (macOS arm64; masking-proof oracle)
Build the light detector (oracle lives in the fork, gated):
```
cd vcx && ../third_party/v/v -n -w -cc cc -gc e -d vgc_passive -d vgc_nosweep \
    -o target/cx_coop_det cmd/
```
Run the #144 production cadence at high reactor count:
```
CX_HTTP_N=24 CX_HTTP_GC_KB=4 vcx/target/cx_coop_det --allow-all \
    vcx/tests/soundness/serve_churn_heavy.cx     # + wrk -t12 -c200 -d4s http://127.0.0.1:9031/
```
Oracle: a `tag=0x...bf1` line on stderr = a freed map-key buffer read in `map_clone_string`
(masking-proof: caught at the use site regardless of timing). Measured: **41 oracle catches
+ 3 crashes / 20 rounds** at N=24 churn; ~80% per-round event rate. Crashes alone reproduce
on a normal `-gc e` build (no detector).

## Acceptance criterion (closes #145)
`make test-vcx-concurrency-soundness` GREEN with the #145 churn stressor on macOS AND Linux
(Docker cxbuild — #63 historically reproduced harder there), at COMPARABLE throughput
(paired vs the unfixed binary; a 0-result at reduced throughput is masking, not a fix), with
NO perf regression (single-reactor throughput + bench/parallel-alloc). The gate's anti-hollow
canary must keep the oracle real (it aborts if the fork lacks `vgc_uaf_check_buf`).

## Verified facts (paired, masking-proof)
- vgc-specific: **boehm 0 crashes @ 5.8× the load**; BOTH coop (default) and legacy
  (`-d vgc_legacy_stw`) vgc reproduce ⇒ vgc-common, not cooperative-specific.
- multi-reactor only: **N=1 → 30 rounds / 21,753 req / 0 oracle / 0 crash** (sound);
  rate scales with N (N=8 3/15, N=16 9/15, N=24 12/15).
- victim = a per-request env-clone COPY of stdlib import-member / closure-name keys
  (`s:at`, `http:put`, `handler`), 24B noscan map-key buffers, swept (alloc bit clear).

## Ruled OUT (with evidence — do not re-chase)
- Build/gate false-passes (FIXED this pass): fork churn commit was unpushed + gitlink
  unbumped (clean clone couldn't compile); the soundness gate's oracle was ABSENT from the
  shipping fork so `-d vgc_passive` was a no-op and `0xbf1` could never match (hollow gate).
- STW incompleteness: a once-per-GC probe (tag `0x57ab`, count peers neither parked nor
  mach-suspended at mark) = **0 when the UAF fires** ⇒ all peers covered + scanned.
- Register/stack capture: legacy mach-suspends ALL peers + scans 95 GP+NEON regs + full
  stack, and STILL reproduces ⇒ the holder pointer IS captured.
- `vgc_shade` static boundary/reject logic: same logic runs at N=1 (clean).
- parallel-mark race: mark is single-threaded under full STW.
- mark work-queue overflow: queue is a dynamically-grown linked list (no silent drop).
- park/suspend memory ordering: default atomics are `__ATOMIC_RELEASE`/`ACQUIRE` (correct).
- `stack_base`: `vgc_get_stack_bounds` uses `pthread_self()` per-thread (correct).
- `vgc_find_span`: hint-miss → linear scan over all arenas; ACQUIRE/RELEASE paired (the
  prior P3 span-lookup bug is fixed; lookup is as complete as the allspans sweep).
- handler rooting: `gc_pin(h)` does NOT fix ⇒ victim is per-request, not the shared
  handler closure (`h.enclosing_*`, already retained via the `__DATA` `cx_http_live_handlers`).

## Characterized root cause (the open bug)
A vgc **mark/sweep consistency** bug: under N≥2, `vgc_shade` is called on a captured, live
holder yet it ends up unmarked and swept. NOT coverage, NOT STW-incompleteness, NOT capture.
The exact freeing instant is unobservable without masking — every heavy localizer
(`-d vgc_verify`/rootfind, the slog GOLD correlation, `wait_full`) slows the collector enough
to close the race window; the light oracle reproduces but cannot pin the holder at the
freeing GC. This is the same residual as the long-standing #57/#63/#52 lineage
("rarer object-level GC reclamation UAF, TSan-invisible, repros on Linux").

## Next step (deep fix)
A **record-replay** harness (deterministic re-execution of the multi-reactor schedule) is the
identified path to observe the freeing GC without perturbing timing. Alternatively, a
marked-vs-unmarked-holder-at-sweep check restricted to the victim class (risk: masks).
Fork: third_party/v `17465cd9b0` carries the gated oracle/localizers/stwprobe (default build
byte-identical). Detector binaries: `vcx/target/cx_{coop_det,legacy_det,boehm,keytext,stwprobe}`.

---
## Session-3 (deep-fix A) — findings, refuted fixes, and the corrected diagnosis (2026-06-28)

Branch `cxstore/145-A-deep-fix` off `release/0.13.0`. Repro confirmed live. Two prior-pass
claims were CORRECTED here:

- **`renv` is NOT a vgc-heap object.** A one-shot probe (push-time arena check, tag `0xe5a7`)
  showed `&renv` and every `&extended` are v=0 (NOT in the arena) — they are STACK values, not
  heap. The earlier "renv is heap (addr in arena)" reading came from a `stack_base` probe that
  compared addresses across DIFFERENT reactor threads (mismatched stacks) → bogus. So the env
  structs are stack-resident; their bindings *maps* carry the heap (arena) `key_values.keys`
  array, which holds the victim key buffers.
- **The keys-array span is SCAN, not noscan** (probe tags `0x6b59`=0, `0x6b5a` elem_size
  144/640). So `.str` buffers *should* be traced when the array is marked.

### What was PROVEN
- **Root miss, not a broken mark closure.** Lean closure check `-d vgc_closlean`
  (`vgc_verify_mark_closure` restricted to SCAN referrers, no rootfind): a `0xbf1` UAF fires
  with the closure-violation count (`0xc105`/`0x5ca0`) = **0 in the same round** ⇒ the swept
  victim is unreachable from the *marked* set = a ROOT MISS (a root that should start the
  holder chain is not shaded), NOT a marked-referrer→unmarked-referent descent break.
- The earlier `-d vgc_closonly` "15-26 closure violations/round" were **stale-tail FALSE
  POSITIVES**: full-slot zero-fill of small noscan allocations (the `-d vgc_verify` path
  already does this) drove them to **0**. `vgc_malloc` zero-fills only the requested `n`, not
  the slot's `elem_size`, so a recycled noscan slot's tail bytes were misread as pointers.

### Fix hypotheses TESTED and REFUTED (paired, per-req rate vs baseline ~1/120-200 req)
- **Boehm-parity external conservative scan** (`-d vgc_extroots`: shade arena pointers found in
  every non-arena writable region incl. full thread stacks, during mark): bf1 rate UNCHANGED
  (3/322 ≈ baseline). ⇒ the missed root is NOT in external memory or a thread-stack region
  beyond `[sp,stack_base]`. (And boehm-clean is partly because boehm IGNORES `CX_HTTP_GC_KB`
  and collects far less — infrequent collection avoids the race — NOT superior scanning.)
- **Explicit-free disabled for small noscan buffers** (`-d cx_nofree_small`: skip `vgc_free`'s
  eager alloc-bit clear for ≤32B noscan, like the existing `is_tiny` skip): bf1 PERSISTS
  (6/1337). ⇒ the victims are SWEPT by the collector, not explicitly freed.
- **Explicit env-rooting** (`-d vgc_envroots`: a per-reactor lock-free root list scanned by
  `vgc_mark_roots`; push the arena keys-array object of every source/dest map in
  `map_clone_string`, reset per request — covers renv.bindings + all `[?let]` child clones,
  TCO-safe): bf1 only PARTIALLY reduced (4-8/run, high variance) and **crashes persist (3-7)**.
  Rooting (marking) the SCAN keys-array does NOT reliably protect its `.str` buffers — which is
  itself anomalous (a marked SCAN array's `.str` should be traced; closlean confirms no
  marked-array→unmarked-buffer edge). NOTE: an initial `&renv`-pin run scored bf1=1 and looked
  like a 10x win — a REPRODUCIBILITY re-run gave bf1=8 (baseline). The bf1=1 was a lucky
  low-variance run; **single short runs are underpowered — require repeated paired runs.**

### Corrected open diagnosis
A multi-reactor **sweep/root-miss** of SCAN keys-array key buffers that (a) is not fixed by
conservative external scanning, (b) is not an explicit free, (c) is only partially mitigated by
explicitly rooting the holder array, and (d) leaves residual crashes in paths the
`map_clone_string` oracle does not catch. The contradiction "holder array is SCAN + rooting it
marks it, yet its `.str` buffers are still swept" indicates the missed root is HIGHER than the
keys-array (the stack reference to the env / map struct that owns it) and/or the residual lives
in closures/`dyn_context`/deeper clone paths not covered by the bindings-array push. Pinning the
exact freeing instant remains blocked by the masking wall (every heavy localizer slows the
collector and closes the window); record-replay is infeasible here (`rr` needs hardware perf
counters absent on Docker/macOS-arm64). **Posture: `CX_HTTP_N=1` (default since PR #146) is the
verified-sound production stance; multi-reactor stays opt-in with the startup caveat; #145
remains a tracked vgc residual.** Env-rooting is the most promising lead for the deep fix
follow-up (partial reduction observed) but needs comprehensive clone-site coverage + a fix for
the residual crash path + repeated-run statistical validation, and likely a TCO-safe
per-reactor root mechanism.

---
## Session-4 (deep-fix A cont.) — the THROUGHPUT/COVERAGE wall, quantified (2026-06-28)

Branch `cxstore/145-A-deep-fix`. Baseline reconfirmed (macOS arm64, gitlink `9194b85fc8`):
**full gate N=24 15 rounds → bf1=8, crashes=3 (FAIL)**; paired churn-only N=24 12 rounds →
bf1=6 crash=2; single clean 10s run → **19.5 rps, bf1=4**. Repro is strong and reproducible.

Two new fix mechanisms were implemented (fork, all gated, default byte-identical; experiment
diff archived in `session4-experiments.patch`, reverted from the tree) and DECISIVELY refuted:

### (1) Clone-root ring — `-d vgc_cloneroots` (the proper, non-resetting envroots)
A per-thread, NON-resetting ring (512 slots/thread) of string-keyed map **backing arrays**,
registered at the `map.clone()` chokepoint (covers all env clones: bindings/closures/dyn) and
(comprehensive variant) at `DenseArray.expand()` (covers post-clone map GROWS), shaded by
`vgc_mark_roots`. Distinct from the refuted envroots: no per-request reset, chokepoint coverage.
- **Instrumentation PROVED the ring is active and effective at what it does** (`-d vgc_cloneroots_diag`,
  tags 0xc70/0xc71/0xc72): 600–780 registrations/run, and **every ring entry is LIVE (in-use span)
  at every GC** (c72==c71). So rooting+marking the SCAN keys arrays is happening on live objects.
- **Clone-only coverage → full throughput, PARTIAL: bf1 8→5** (≈ baseline variance). Misses the
  buffers created by post-clone map GROW (`DenseArray.expand` reallocates the keys backing OUTSIDE
  `map.clone`, so the clone hook never sees the new buffer).
- **Comprehensive coverage (clone+expand) → bf1=0 BUT throughput COLLAPSES ~2.4×**
  (single clean 10s run: **8.0 rps vs baseline 19.5 rps**), AND crashes persist (1). Rooting only
  the KEYS arrays (not the cx.Node VALUES arrays) gave the SAME 8.0 rps → the slowdown is the
  per-GC cost of shading/tracing the whole per-request working set at the GC_KB=4 churn cadence,
  NOT Node over-retention. **A bf1=0 at <half throughput is a MASKING pass (acceptance D:
  "reduced speed = invalid"), not a fix** — the slower collector simply closes the race window.

### (2) Deferred sweep / one-cycle grace — `-d vgc_sweepdrag`
Per-span `grace_bits`; an object is freed only after TWO consecutive unmarked sweeps. Coverage-
independent: a live buffer whose sole holder was transiently in a register the scan missed
survives the missing cycle and is re-marked next cycle.
- **Full throughput, PARTIAL: bf1 6→4, crash 2→1** at *higher* rps (221 vs 190 over 12 rounds —
  so NOT throughput-masking; a genuine ~33% reduction). One cycle catches single-GC misses; the
  residual is objects missed at ≥2 consecutive GCs. Increasing the grace to N cycles would drive
  bf1 toward 0 only by RETAINING all garbage for N cycles = retention-masking + an RSS regression
  (conflicts #131) — a gate-green by retention, not a technical resolution.

### THE WALL, quantified (the decisive new result)
There is **no rooting or deferral configuration that yields bf1=0 AND crashes=0 at COMPARABLE
throughput.** The mechanism is now sharply bounded:
- **Coverage ⟺ speed are in direct tension.** Zeroing bf1 requires rooting the entire per-request
  env working set on every GC; at the #144 churn cadence (GC every 4 KB) that rooting cost
  dominates → the collector slows ~2.4× → the bf1=0 it produces is masking. Rooting cheaply
  enough to keep full throughput (clone-only) leaves the post-grow buffers uncovered → partial.
- **A residual CRASH never reaches 0** in ANY arm (baseline 2–3, every fix 1–3) — a UAF on a
  path the `map_clone_string` oracle does not catch; object class still unidentified.
- Static root coverage is provably complete (collector self-spills callee-saved via
  `vgc_run_gc_spilled` — and the #144 churn path `gc_collect_if_churned → gc_collect →
  vgc_force_collect` routes through that SAME trampoline; peers captured via setjmp/mach;
  `[sp,stack_base]` refreshed per-GC; data segs + pins scanned). The miss is an intermittent
  register-timing root miss that no coverage-, rooting-, or deferral-based fix closes without
  masking. Pinning the exact freeing instant still needs record-replay (infeasible on arm64).

### Conclusion / honest status
Phase-1 directions (construction/clone-site rooting; boehm-parity-via-new-mechanism; marked-
holder/deferred-sweep guard) are EXHAUSTED with the documented, paired, throughput-controlled
refutations above. A clean technical resolution at the #144 churn cadence appears to require a
GC-architecture change beyond Phase-1 scope (e.g. a per-reactor nursery / write-barrier
remembered-set for per-request allocations so the working set is rooted in O(survivors) not
O(working-set)-per-GC, or a deterministic record-replay harness to pin the freeing instant) —
both multi-day and requiring explicit authorization. Interim production posture unchanged:
`CX_HTTP_N=1` (verified sound, PR #146); multi-reactor opt-in + startup caveat; #145 open.

---
## Session-4 BREAKTHROUGH — the bug is macOS-arm64-SPECIFIC; LINUX is SOUND (2026-06-28)

The "Linux reproduces harder" assumption (carried in this runbook from the #63 lineage) was
**NEVER actually measured in sessions 1–3.** Running the real Linux/arm64 Docker gate this
session FALSIFIES it. Harness: `scripts/concurrency_soundness_gate_docker.sh` (native
`arm64v8/gcc:latest`, in-tree `vc/v.c` bootstrap, builds the RE2 shim + `libre2-dev`/`libssh2`).

**Paired result, SAME default `-gc e` detector, SAME fixture (serve_churn_heavy, N=24, GC_KB=4):**

| target | rps | req/round | bf1 | crashes |
|---|---|---|---|---|
| macOS native arm64 | ~19 | ~110–190 | 4–8 | 2–3 |
| **Linux Docker arm64** | **~400** | **2300–2548** | **0** | **0** |

Linux ran the churn workload at **20× the throughput → 20× the GC exposure** (≈7400 requests over
3 probe rounds, plus a clean 10-round gate PASS) with **zero** oracle catches and **zero** crashes.
This is the OPPOSITE of masking (masking = a 0-result at REDUCED exposure; here exposure is 20×
HIGHER). At the macOS event rate, 7400 requests would predict ~tens of bf1; observing 0 is
overwhelming evidence the residual **does not exist on Linux**.

### Why macOS-only — localized to the async mach-suspend capture (NOT register coverage)
- macOS `vgc_thread_regs` captures MORE than Linux: x0–x28 + fp + lr + **all 64 NEON lanes (95
  values)**; Linux captures GP-only from the signal `ucontext` (no NEON). macOS captures strictly
  more yet FAILS → **the bug is NOT register/NEON coverage** (this finally refutes the
  long-standing "q-reg-across-memcpy" NEON-gap theory in the vgc_platform.h comment).
- Both compute `[stack_lo,stack_hi]` correctly (macOS `pthread_get_stackaddr_np`+size; Linux
  `pthread_attr_getstack`). Not a stack-bounds bug.
- The real asymmetry is the SUSPEND/CAPTURE PROTOCOL. **Linux**: the collector sends SIGRTMIN+6;
  each peer's handler captures its OWN interrupted register file from the kernel-delivered
  `ucontext` at a clean instruction boundary, publishes an ACK, and parks IN the handler — the
  collector spins on `acked==1`, so every peer is provably frozen at a precise point before mark
  begins. **macOS**: `thread_suspend()` is ASYNCHRONOUS and the captured state comes from an
  external `thread_get_state()` gated only by a heuristic spin-until-(SP,PC)-stable. That is a
  strictly WEAKER stop-settle than the kernel-delivered signal point, and it is the macOS-only
  defect window: a peer's in-flight live pointer can be missed at the async capture instant that
  the Linux signal capture would have frozen precisely.

### Consequence for #145
- **Acceptance C (Linux Docker green) is ALREADY MET by the shipping default binary** — multi-
  reactor `http:serve` under `-gc e` at the #144 churn cadence is sound on the Linux production
  target (verified, comparable+higher throughput, no masking).
- The remaining defect is **macOS arm64 (a dev environment)** and is sharply localized to the
  darwin `mach_suspend` async-capture path in `thirdparty/vgc/vgc_platform.h`. Candidate fix:
  port the Linux signal-suspend mechanism to macOS (`pthread_kill` + a SIGRTMIN-style handler that
  captures the `ucontext` + ACK, replacing async `thread_suspend`+`thread_get_state`), so macOS
  uses the same precise, kernel-delivered capture that is proven sound on Linux. Bounded, fork-
  level, macOS-only; the Linux implementation in the same file is the reference template.

---
## Session-4 RESOLUTION — macOS signal-suspend STW (the fix) (2026-06-28)

Implemented the fix above: the darwin block of `thirdparty/vgc/vgc_platform.h` now stops peers
with a **signal-based suspend** (default), mirroring the proven-sound Linux path; the async
`mach_suspend` path is retained behind `-DVGC_MACH_SUSPEND` as a fallback. Mechanism: the
collector `pthread_kill`s each peer (`SIGURG`, via `pthread_from_mach_thread_np` on the stored
mach port); the peer's handler captures its OWN interrupted register file (x0–x28+fp+lr+SP, plus
all NEON lanes) from the signal `ucontext` at a kernel-delivered instruction boundary, publishes
an ACK, and PARKS in the handler until released. The collector spins on the ACK before trusting
the captured SP/regs. The V layer (`vgc_scan_suspended_roots`, `C.vgc_suspend_thread/_thread_regs/
_resume_thread`) is UNCHANGED — the entire port lives in the three C functions, keyed by the same
`mach_port` field.

### Validation (macOS native arm64, paired vs the mach baseline, serve_churn_heavy N=24 GC_KB=4)
| build | bf1 | crashes | throughput |
|---|---|---|---|
| mach-suspend (baseline) | 4–8 | 2–3 | ~16–19 rps |
| **signal-suspend (fix)** | **0** | **0** | **~370 rps (~23×)** |

- Churn 12 rounds: **bf1=0, crashes=0**, sum_rps 4445 (~370 avg) vs baseline 190 (~16 avg).
- **Full gate `make test-vcx-concurrency-soundness` (15 rounds × 3 stressors): PASS (0xbf1=0,
  crashes=0).**
- **Not masking — the OPPOSITE:** soundness was achieved at ~23× HIGHER throughput. The async
  `mach_suspend` (thread_suspend + spin-until-(SP,PC)-stable + per-thread per-GC `thread_get_state`
  ×95 regs) was BOTH the root-miss bug AND a severe per-GC bottleneck; the signal path is cheaper
  (each peer captures itself once) so macOS now runs the churn workload at Linux-class throughput.

This resolves the macOS-arm64 residual. Acceptance A (zero sweep-while-live) and B (macOS gate
green) are met; C (Linux) was already met (the linux block is unchanged); D (no masking) is met
emphatically (throughput up). Remaining for land: re-confirm Linux gate with the new tree, perf
non-regression (`baseline_gc.sh`), full `make test-vcx`, fork push + gitlink bump, restore the
multi-reactor default, PR to release/0.13.0.
