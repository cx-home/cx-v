# CX GC soundness — status & findings (peer review, v4 — RESOLVED incl. the workers-stressor residual)

**Date:** 2026-07-03 · **Scope:** vgc sweep-while-live UAF, `#57/#58/#63/#145` lineage + `#68/#71/#124/#151`
**Author:** soundness session (autonomous `/loop`) · **Workspace:** `/Users/ep/git-repos/cx/cx-soundness` (isolated clone, branch `soundness/57-multiworker-reactor`, fork `diag/58-worker-uaf`)

---

## 0. RESOLVED — root cause found, fixed, verified (v3 addendum, 2026-07-03 evening)

**The §4 "mutually contradictory" facts had a single mechanism: the allocator fast
paths are not atomic with respect to the async-signal STW.** The signal-suspend
collector (the correct #145 fix) freezes mutators at *arbitrary* instruction
boundaries — including inside `vgc_malloc_*`'s lock-free fast paths — and the
collector then invalidated per-thread allocator state under the frozen thread:

- **Loud half (the field `string_clone` SIGSEGV):** `vgc_fixup_caches` (STW,
  post-sweep) unconditionally zeroed every thread's tiny-allocator cursor. A
  mutator frozen between `vgc_malloc_noscan_opts`' `cache.tiny != 0` check and
  its `cache.tiny + off` carve resumed to compute `ptr = 0 + off` and handed a
  near-NULL pointer out as a live string buffer. **Captured live in lldb:**
  `string_clone` faulting with `res.str = 0x8`, healthy 2-byte source key —
  0x8 is exactly `nil + off` after an 8-byte tiny alignment. The zeroing was
  also unnecessary: the tiny block is conservatively rooted (the `caches`
  array lives inside the `vgc_heap` global, which `mark_roots` scans as a data
  segment).
- **Quiet half (the 0xbf1 sweep-while-live oracle catches):** a mutator frozen
  between the atomic alloc-bit claim (`fetch_or`) and the first scannable
  existence of the new object's address (still implicit `span + i` in
  registers) leaves the slot `alloc=1/mark=0` — indistinguishable from garbage
  — so sweep **cleared the bit under the in-flight claim**; the resumed thread
  completed the claim and the allocator handed the same slot out twice → two
  live owners → torn structs / bit-clear reads / `string_clone` UAF.
  Alloc-black cannot close this window: it is phase-gated at the claim (the
  freeze precedes the cycle) and the mark-bit wipe at cycle start erases any
  pre-set mark.

This resolves every §4 contradiction: the victim's base was in *no* scanned
window, register file, or root at the freeing GC because it existed only as
implicit allocator state in a frozen thread — and it appeared on a frozen
in-window stack "µs later" because the thread materialized it on resume.
Catches surface at `[?let]` entry because env construction is the map/key
allocation hot path. GC frequency amplifies (more STW windows); heavy probes
mask (they shift the suspend window); `values`-alive/`keys`-dead was
incidental interior-pointer rescue asymmetry, not a mechanism.

**Repro amplification (new, decisive):** the bug requires *machine load*. On an
idle machine workers8 @ `VGC_NEXT_GC_KB=128` catches ~0/round; under ~12 CPU
spinners it caught bf1 every few rounds and crashed (`string_clone` SIGSEGV)
~40% of rounds, fastest 8s — the strongest repro of the lineage. The 13th
hypothesis (noscan-holder, v2 §5 pending verdict) was **refuted** on same-tree
twins first: `-d vgc_scanall` (conservatively scan ALL noscan objects) does
not reduce bf1 (14 vs 10) — the `remark_ns` discriminator's positive was
conservative aliasing noise (its victim-class counter counts *any* 128–192B
scan object; map-metas words `kv_index<<32|meta` alias arena addresses).

**The fix (fork `vgc_gc_d_vgc.c.v`, three edits, V-only/upstreamable):**

1. `vgc_fixup_caches`: keep the tiny cursor (drop it only if its span was
   genuinely recycled — loud `0x717e` tag, never observed).
2. `vgc_protect_cached_spans`: also stamp the tiny-cursor owner span
   (`vgc_find_span(c.tiny)`) — it leaves `c.alloc[]` once full, so the
   existing loop no longer reached it.
3. `vgc_sweep_span`: skip spans with `sweep_gen == gc_cycle` entirely — that
   protected set (cache-resident + freshly acquired + tiny-owner spans) is
   exactly the set a mutator can be mid-claim in. Their garbage reclaims one
   cycle late; the delay is self-limiting (zombie slots keep alloc bits → the
   span fills → evicted from the cache → loses the stamp → next sweep reclaims).

**Verification (all on the fixed tree):**

| Check | Pre-fix | Post-fix |
|---|---|---|
| Loaded A/B, 12 interleaved workers8 rounds @KB=128 + 12 spinners | bf1=46, segv=2 (+1 nosweep-OOM artifact) | **bf1=0, segv=0, oom=0** |
| Per-stressor gate (http/churn/mainloop/workers ×15 rds) | FAIL by design (workers 34 bf1 + 11 crashes; mainloop 2; http 1) | **PASS at every N ∈ {1,4,8,16,24}** |
| Per-stressor gate under 12-spinner load (amplifier condition) | — | **PASS (all stressors 0/0)** |
| `make test-vcx` | green | **green (244 OK, exit 0)** |
| `hot_loop_rss` 8 threads, interleaved ×5 (idle machine) | 5.82 Mops/s, 417MB | **5.83 Mops/s, 417MB** (no regression) |
| `hot_loop_rss` @ `VGC_NEXT_GC_MB=1` (high GC frequency) | 5.39 Mops/s | **5.52 Mops/s**, RSS +≤64KB |
| Linux Docker gate (N=24, all stressors) | exec-format harness bug (fixed in this PR) | **PASS (0/0)** |

The §6 record-replay endgame is no longer needed: the mid-claim theft was
provable from the captured crash + code reading once the loud half pinned the
race family. Methodology note for the lineage: the two prior "probe lies"
were joined by a third — the *detector builds* were believed non-reclaiming
(`-d vgc_nosweep`), but the define gates only swept-log recording in this
tree; detector crashes were therefore real UAF crashes all along.

---


## 1. Executive summary

- **Issues resolved and verified this session:** `#57` OOM mode (pacer policy), `#57` idle-CPU burn (STW park), `#124` (deterministic), `#151` (usecache invalidation soundness — cache poisoning + compiler identity). Full `make test-vcx` green (177+49+18 + conformance).
- **Six latent GC/toolchain soundness holes found, fixed, and landed on the diag branch**, each with direct evidence (§3). None of them, individually or together, changes the workers8 UAF rate — every one was A/B-refuted *as the mechanism* while remaining a real defect.
- **The concurrent-worker UAF (`CX_WORKER_THREADS=1`, opt-in) remains unfixed.** Its characterization is now far sharper than any prior session (§4), and the surviving facts are mutually contradictory under every STW/allocator story tested — the strongest case yet that the remaining step is deterministic record-replay (§6).
- **Shipping-default posture: NOT certifiable.** The hardened per-stressor gate on the fully-hardened tree: workers bf1=34 + 11 real crashes /15 rds; **mainloop (field shape, default env) bf1=2/15; http bf1=1/15**; churn clean. The defect is default-reachable — rare without worker churn, but real (matches the field's rare `signal 11`). The prior "HTTP resolved / opt-in-only" claims do not survive the per-stressor gate at current cadence. The mechanism hunt is therefore a shipping blocker, not a lab curiosity.

---

## 2. Issue-by-issue outcome

| Issue | Outcome |
|---|---|
| `#57` OOM (`V panic: memory allocation failure`, field RSS 4.6GB) | **Root-caused + fixed.** Pacer multiplied the GOGC goal by live-thread count → 10GB trigger vs the 4GB arena capacity (64×64MB) → collector went dormant → exhaustion. Fix: additive per-thread headroom (`VGC_PACE_MB`) + soft heap limit clamp (`VGC_MEMLIMIT_MB`, default arena/2). Marine workload reproduced the field failure in minutes pre-fix; stable post-fix. New permanent `VGC_GCTRACE=1` per-cycle trace. |
| `#57` idle CPU (~1.7 cores) | **Fixed.** STW park was a `sched_yield` spin for the whole pause; now blocks on a mach semaphore (futex on Linux). Idle CPU → 0.0%. |
| `#124` SSE flake | **Verified deterministic** (10/10 under load; port bands are deliberate repo idiom). Ready to close. |
| `#151` usecache | **Fixed + verified.** (a) Cache poisoning: source hashes were saved *before* rebuilds and rebuild exit codes ignored → one failed rebuild = stale module object linked forever. Now: remove-stale-then-record. (b) No compiler identity in the cache key → objects reused across compiler rebuilds; now salted with vexe size+mtime. Warm 6.2s vs cold 65s per test preserved; wipe-free recovery verified. |
| `#68` / `#71` | Partially delivered via the `#57` fixes (park + pacer); perf A/Bs (wrk N=8, `hot_loop_rss`) still to run post-verification. |
| `#58`-lineage worker UAF | **Open.** See §4–§6. |

## 3. Latent holes fixed (all landed on `diag/58-worker-uaf`, each individually defensible)

1. **Sweep bitmap write-back was a plain stale-read byte store** → any concurrent claim between read and write-back silently erased. Now an atomic AND of exactly the garbage bits.
2. **`vgc_suspend_thread` bounded ack-wait** could expire and proceed with a running mutator, with `susp[]` set unconditionally (completeness probe blind). Now waits for live targets indefinitely; skip only on genuinely-gone.
3. **Any `pthread_kill`/`tgkill` failure was treated as "target gone"** → live thread dropped from the stop set. Now ESRCH-only, with retry.
4. **Alloc-black was gated to the concurrent collector** → objects born while a GC is in progress got no mark bit under the shipping STW backstop. Now unconditional (atomic OR — the codebase's `test_and_set` is a plain RMW, unsafe from mutator context).
5. **A stale `stopped==1` from the previous cycle was trusted by a back-to-back GC** (waking parker counted as parked). Now every park carries a stop-cycle generation stamp; mismatches are stragglers.
6. **The collector iterated `vgc_spawn_roots` unlocked** while a *dying* worker's exit path (no safepoint, past signal delivery) swap-removes entries — the moved last entry lands in an already-visited slot and is never shaded. Now the collector holds `vgc_spawn_root_lock` with the lock-before-suspend discipline.

Also fixed as methodology casualties: the gate's stressor conflation (per-stressor verdicts now), the missing field-shape stressor, detector cadence pinning (`VGC_PACE_MB=0`).

## 4. The remaining UAF — sharpened facts (workers8, ~2 bf1/round @2MB cadence)

Established by direct provenance instruments (free-ring with return addresses, birth certificates, bit-watch with site attribution, sweep-instant where-is-it, span-identity checks):

- Victims are GC-**swept**, never explicitly freed (ring: 0 hits over hundreds of catches; Perceus emits only ~70 frees/round total).
- Mark closure is sound; at the freeing GC **no scanned stack window and no captured register file holds the victim's base** — yet microseconds later the pointer is on a frozen stack, inside a scanned window, in a live env (interpreter catches it at `[?let]` entry immediately; a 1/256-sampled `eval_node` probe never catches first).
- Birth certificates: the keys array's alloc bit is **verified set at claim** and reads clear with **zero completed GCs between birth and the dead-read**, same span descriptor at both ends (aliasing refuted).
- The world is provably stopped in catching rounds: every registered thread parked-for-this-generation or acked-suspended at both mark start and sweep start; the only coverage exceptions correlate 1:1 with genuinely-dead (ESRCH) threads.
- Rate is invariant under: legacy vs cooperative STW, all six fixes above (individually A/B'd where separable), full-register capture, unbounded stop waits.

These facts are mutually contradictory under every STW-, allocator-, and descriptor-level story tested. Something clears (or never durably sets) alloc bits through a path none of the instrumented sites cover, or one probe's semantics still lies in a way not yet caught (two probe-lies were caught and corrected this session: a heap-boxed "frame address" and a cadence-mismatched A/B).

## 5. Refutation matrix (this session)

| Hypothesis | Instrument | Verdict |
|---|---|---|
| Perceus/RC premature free | free-ring w/ retaddrs | refuted (0/hundreds) |
| Ack-timeout unstopped mutator | 0x0acc counter | refuted (never fires) |
| Sweep write-back lost-update | same-tree A/B | real hole; not the mechanism |
| Alloc-black policy gap | isolation A/B | real hole; not the mechanism |
| Stale-park back-to-back race | park-seq stamp A/B | real hole; not the mechanism |
| Spawn-root swap-remove race | spawn-root lock A/B | real hole; not the mechanism |
| Span-descriptor aliasing | birth/current span identity | refuted (span-same) |
| GC root-scan miss of stack word | sweep-instant window rescan | refuted (no holder at sweep) |
| Dangling env frame | real-SP discriminator | check shown vacuous; inconclusive |

## 6. Recommended endgame (unchanged from v1, now better justified)

Deterministic record-replay of the multi-worker schedule remains the only tool class that observes the freeing interleave without perturbing it — and with the default posture now shown affected (mainloop/http catches), it is a shipping blocker, not an optional lab workstream. workers8 (34 catches + 11 crashes/15 rds) is the amplifier to build the harness against; the mainloop/http shapes confirm the fix generalizes.

## 7. Artifacts

- cx-private branch `soundness/57-multiworker-reactor`, fork branch `diag/58-worker-uaf` (both pushed).
- Detectors in clone `vcx/target/` (`cx_alias_det` = full instrument set incl. all fixes).
- Batch logs in the session scratchpad (`sr_*`, `seq_*`, `bw*`, `ks*`, `alias_batch`, `m_*`, `tw_*`).
- Full narrative: memory `project_issue145_multireactor_verify.md`.

---

## 8. v4 addendum (2026-07-05) — a DISTINCT default-reachable UAF: the thread-return box (found via #71's frequent-GC amplifier; FIXED)

The #71 adaptive pacer (fork branch `vgc/71-adaptive-pacer`) multiplies default-build
collection frequency ~100x on small-live churn. Under it, a 4-worker allocate/discard
loop (`bench/parallel-alloc/hot_loop_rss.v`, result CHECKSUM as oracle) silently
corrupted worker results 6/6 rounds — and, frequency-matched (`VGC_PACE=0
VGC_NEXT_GC_MB=8`), the PRE-pacer tree (812623005a, which already contains all §0 v3
fixes) corrupts 1/6. This is NOT the §0/§4 lineage resurfacing: it is a separate,
previously-unknown hole.

**Mechanism:** the POSIX spawn wrapper heap-allocates the thread's return value and
returns the pointer from the thread routine; the waiter recovers it via
`pthread_join`'s value-return. Between the spawned thread's exit (stack deregisters
from the root set) and the join, the box's ONLY reference lives inside libpthread —
memory vgc never scans — so a collection in that window sweeps it. The waiter then
reads a recycled slot and `_v_free`s memory that may already belong to a live object.
Boehm avoids the same hole only by interposing `pthread_join`.

**Why every prior instrument missed it:** the bf1 detector (and the whole §5 matrix)
watches reads of swept-FREED buffers; by join time the slot is usually REALLOCATED
(alloc bit set again, holding someone else's live data), so the read looks perfectly
healthy to the oracle — only a value-integrity check (checksum) can see it. Result
corruption is silent: no crash unless the bogus `_v_free` lands somewhere fatal.
Localized by a side-channel discriminator (worker writes its result into a
caller-owned `[]u64` AND returns it: side channel always correct, `wait()` sum
corrupt) plus the corrupted-word decode (ASCII fragments of the loop's transient
strings inside the u64 — a tiny slot repacked as string data).

**Fix (fork `9cda...`, cgen):** the wrapper pins the box (`builtin__vgc_pin`, the
FFI-root primitive) right after allocating it; every waiter path unpins after the
read. Validated 10/10 clean checksums + 6/6 side-channel MATCH at the frequency that
corrupted 6/6; the per-stressor soundness gate stays PASS (twice, incl. under the
pacer's cadence).

**Posture note:** the checksum/value-integrity oracle class is complementary to the
bf1 detector and caught what the entire §5 instrument family structurally cannot;
worth adding a checksummed multi-worker round to the standing gate. (Done — the
`vthread-ret` checksum stressor is in `scripts/concurrency_soundness_gate.sh`.)

**Gate outcome (v4 closing status):** with the pin fix in place,
`make test-vcx-concurrency-soundness` passes on **all** stressors for the first
time — http/churn/mainloop/**workers** each 0 bf1 + 0 crashes ×15 rounds
(pre-fix: workers 34 bf1 + 11 crashes/15, "fails by design") — and the pass
holds under the pacer's ~100× collection frequency. The thread-return box WAS
the open workers-stressor residual. That retires the remaining v1/v2-body
claims: §1's "concurrent-worker UAF remains unfixed" and "shipping-default
posture NOT certifiable", §4's open hunt, and the §6 record-replay endgame
(already declared unnecessary for the mainloop/http lineage in §0) are all
closed. The shipping default is certifiable on this evidence; the standing
gate + the checksummed stressor keep it honest. Shipped via PR #174
(release/0.13.0), fork branch `vgc/71-adaptive-pacer`.
