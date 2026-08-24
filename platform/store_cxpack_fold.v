@[has_globals]
module platform

import cxstore
import sync
import time

// ── #779-class: orphaned-worker quiescence (stream 20 W2) ────────────────────
//
// A background fold worker can outlive its store's FINAL close (close never
// joins it — it must not: close runs under the op-lock the worker needs to
// finish). A same-root REOPEN then builds a FRESH MemStore (new op-lock
// identity) whose open-time discovery/load races the orphaned worker's
// segment renames/removals — the same different-lock-identity class #779
// fixed on the rotation path (observed: store_lazy_load's close→eager-reopen
// failing on a segment the old worker folded away mid-walk). The fix point is
// OPEN: a per-root active-worker registry (its own mutex — never the op-lock,
// so the worker can always finish); opening a root waits until no orphan is
// folding there. Same-root opens that SHARE the live instance (#628) never
// wait — their worker is legitimately theirs.

const g_fold_reg_lock = &sync.Mutex(sync.new_mutex())

__global (
	g_fold_active map[string]int
)

fn fold_reg_enter(root string) {
	mut l := unsafe { g_fold_reg_lock }
	l.@lock()
	g_fold_active[root]++
	l.unlock()
}

fn fold_reg_exit(root string) {
	mut l := unsafe { g_fold_reg_lock }
	l.@lock()
	g_fold_active[root]--
	if g_fold_active[root] <= 0 {
		g_fold_active.delete(root)
	}
	l.unlock()
}

// store_fold_quiesce_root blocks until no fold worker is active on root —
// called by the open path BEFORE building a fresh instance over an existing
// directory. The worker's iterations are bounded (file I/O + µs-scale locked
// bookkeeping), so the wait is short and always terminates.
fn store_fold_quiesce_root(root string) {
	for {
		mut l := unsafe { g_fold_reg_lock }
		l.@lock()
		n := g_fold_active[root]
		l.unlock()
		if n <= 0 {
			return
		}
		time.sleep(time.millisecond)
	}
}

// store_cxpack_fold.v — #617: the #603 size-tiered segment fold, driven OFF
// the flush turn.
//
// The fold is pure amortization work (it merges already-durable segment packs;
// the flush's receipt is complete before any fold starts), but it used to run
// inline inside flush_segment — so at every binary-counter doubling point a
// live publisher's receipt waited on a geometric merge cascade (measured
// 69–720ms at the tail, under the daemon's global sequencer lock: the single
// biggest contributor to the #617 write-back gap).
//
// Here the refs layer drives the backend's fold primitives instead:
//
//   locked store  → a background worker (at most one per store, ms.fold_running)
//                   loops plan → perform → commit; PERFORM (the pack I/O) runs
//                   with NO op-lock held, so publishes flow concurrently and
//                   only the µs-scale plan/commit bookkeeping contends. A
//                   compaction or reload racing the I/O bumps the backend
//                   generation and the commit abandons cleanly.
//   lockless store → folds drain inline (a MemStore without an op-lock is a
//                   single-threaded direct-model store — tests, embedded
//                   fixtures; a worker without a lock would race it). This is
//                   exactly the pre-#617 cascade, byte-for-byte deterministic.
//
// Failure posture: folding is fail-open but LOUD (like the #606 reducer) — a
// fold error never fails the mutation that scheduled it (that data is already
// durable); it logs to stderr and pauses folding until the next flush re-kicks.

// store_cxpack_fold_kick schedules any due segment folds after a flush.
// Caller holds the store op-lock (the flush path always does).
fn store_cxpack_fold_kick(mut ms MemStore) ! {
	if ms.obj_pack == unsafe { nil } {
		return
	}
	if !ms.obj_pack.fold_pending() {
		return
	}
	if ms.op_lock == unsafe { nil } {
		return ms.obj_pack.fold_drain()
	}
	if ms.fold_running {
		return
	}
	ms.fold_running = true
	// Registered BEFORE the spawn (under the fold registry's own lock), so a
	// close→reopen sequence can never observe zero activity between the kick
	// and the worker's first instruction.
	fold_reg_enter(ms.root)
	spawn store_cxpack_fold_worker(mut ms)
}

// store_cxpack_fold_worker runs due folds until none remain, then exits
// (cleared fold_running lets the next flush kick a fresh worker). The op-lock
// is held only for plan and commit; the pack read/merge/write I/O in between
// runs unlocked against immutable source segments.
fn store_cxpack_fold_worker(mut ms MemStore) {
	defer {
		fold_reg_exit(ms.root)
	}
	tr := fab_trace_on()
	for {
		store_lock_enter(mut ms)
		plan := ms.obj_pack.fold_plan() or {
			ms.fold_running = false
			store_lock_exit(mut ms)
			return
		}
		store_lock_exit(mut ms)

		t0 := time.sys_mono_now()
		merged := cxstore.fold_perform(plan) or {
			// A concurrent compaction/reload deletes source segments AFTER
			// bumping the generation — distinguish that benign race from a
			// genuine I/O failure by re-checking the generation.
			store_lock_enter(mut ms)
			stale := ms.obj_pack.generation() != plan.gen
			if !stale {
				ms.fold_running = false
			}
			store_lock_exit(mut ms)
			if stale {
				continue // the plan's world is gone; re-plan against the new state
			}
			eprintln('cx store: ${ms.root}: background segment fold failed (folding pauses until the next flush): ${err.msg()}')
			return
		}
		t_io := time.sys_mono_now()

		store_lock_enter(mut ms)
		committed := ms.obj_pack.fold_commit(plan, merged) or {
			ms.fold_running = false
			store_lock_exit(mut ms)
			eprintln('cx store: ${ms.root}: segment fold commit failed (folding pauses until the next flush): ${err.msg()}')
			return
		}
		store_lock_exit(mut ms)
		if tr {
			t1 := time.sys_mono_now()
			eprintln('[fab-trace side=store step=seg-fold lo=${plan.lo_idx} hi=${plan.hi_idx} objs=${merged} committed=${committed} io-us=${(t_io - t0) / 1000} commit-us=${(t1 - t_io) / 1000}]')
		}
	}
}
