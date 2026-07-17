module main

import runtime

// vgc_large_span_reclaim_test.v — guards the V-fork vgc fix for cx-private #52/#57.
//
// Root cause (third_party/v vlib/builtin/vgc_d_vgc.c.v): the span free-list
// `free_spans` was indexed by npages over [32], and both vgc_get_free_span and
// vgc_put_free_span refused npages >= 32. A "large" object is anything over
// 32 KB (vgc_max_small_size), allocated as a dedicated multi-page span; the
// arena it is carved from is a bump allocator whose used-offset never rewinds.
// So a transient object of 32..8191 pages (256 KB .. ~64 MB) — e.g. the ~1 MB
// zstd dst buffer in the data-bin streaming-write loop, or a large HTTP
// response / cx:parse tree in the reactor — was swept empty but NEVER recycled
// and NEVER returned, so RSS climbed ~linearly and unbounded until the process
// OOM-panicked.
//
// Fix: size free_spans to a full arena (vgc_max_pooled_pages) so every span
// that fits in one arena is pooled and reused. With a periodic gc_collect()
// driving the sweep, a tight alloc-discard loop of >256 KB transients now holds
// RSS to its working set instead of growing without bound.
//
// This test is CX-free on purpose: the bug and fix live entirely in V's GC, and
// the repro is a plain alloc-discard loop. It must run under `-gc e` (the
// shipped collector) to be meaningful; under boehm it trivially passes.

fn rss() u64 {
	return runtime.used_memory() or { 0 }
}

// alloc_discard_loop builds and drops `iters` transient buffers of `sz` bytes,
// forcing a collection every `gc_every` iterations. Returns the RSS growth
// ratio (end / baseline) measured after a warmup so the baseline is past the
// initial arena/working-set ramp.
fn alloc_discard_loop(sz int, iters int, gc_every int) f64 {
	mut sink := u8(0)
	// Warm up so the baseline reflects steady state, not first-touch arena growth.
	for w in 0 .. 32 {
		mut buf := []u8{len: sz}
		buf[w % sz] = u8(w)
		sink ^= buf[w % sz]
		if w % gc_every == 0 {
			gc_collect()
		}
	}
	gc_collect()
	baseline := rss()
	for i in 0 .. iters {
		mut buf := []u8{len: sz}
		buf[i % sz] = u8(i)
		sink ^= buf[i % sz]
		if i % gc_every == 0 {
			gc_collect()
		}
	}
	gc_collect()
	end := rss()
	// keep `sink` observable so the optimizer can't elide the allocations
	if sink == 0xff && baseline == 0 {
		println('unreachable ${sink}')
	}
	if baseline == 0 {
		return 1.0 // RSS unmeasurable on this platform; don't fail spuriously
	}
	return f64(end) / f64(baseline)
}

// A >256 KB transient (the regressed "large" span class, npages >= 32) must be
// reclaimed and reused so RSS stays bounded across a long loop. Before the fix
// this ratio was ~20x+ and climbing; after, it plateaus near 1x.
fn test_large_span_transients_are_bounded() {
	ratio := alloc_discard_loop(1 * 1024 * 1024, 3000, 8) // 1 MiB = 128 pages
	assert ratio < 2.5, 'large-span (1 MiB) transients leaked: RSS ratio ${ratio:.2f} (want < 2.5; pre-fix was ~20x and climbing)'
}

// The small-span path (<= 256 KB) was already recyclable; assert it stays so —
// a regression guard that the free_spans resize didn't disturb small spans.
fn test_small_span_transients_stay_bounded() {
	ratio := alloc_discard_loop(64 * 1024, 3000, 16) // 64 KiB = 8 pages
	assert ratio < 2.0, 'small-span (64 KiB) transients leaked: RSS ratio ${ratio:.2f} (want < 2.0)'
}

// An object spanning multiple megabytes (still within one 64 MB arena) must also
// be poolable now that free_spans covers a full arena.
fn test_multi_megabyte_span_is_bounded() {
	ratio := alloc_discard_loop(8 * 1024 * 1024, 600, 4) // 8 MiB = 1024 pages
	assert ratio < 3.0, 'multi-MiB (8 MiB) transients leaked: RSS ratio ${ratio:.2f} (want < 3.0)'
}

// ── cx #71: pacer-only variants — NO manual gc_collect() anywhere ────────────
// The adaptive pacer (third_party/v vgc, goal = marked + adaptive headroom)
// must bound the same transient loops entirely on its own trigger. This is the
// behavioral guard that the #52-era "force a collect every N bytes" call-site
// crutches stay retired: if the pacer regresses to needing a manual sweep
// drive, these ratios climb with the loop length exactly like the pre-fix bug.

// Same shape as alloc_discard_loop but with zero manual collection drives.
fn alloc_discard_loop_pacer_only(sz int, iters int) {
	mut sink := u8(0)
	for i in 0 .. iters {
		mut buf := []u8{len: sz}
		buf[i % sz] = u8(i)
		sink ^= buf[i % sz]
	}
	if sink == 0xff && iters == -1 {
		println('unreachable ${sink}')
	}
}

// plateau_growth runs the SAME churn twice and returns end2/end1: the pacer's
// contract is BOUNDEDNESS — once at steady state, doubling the total churn must
// not grow RSS. Pre-#71 (fixed 256 MB floor / broken large-span pooling) the
// growth was ~linear in churn (ratio → ~2.0 and climbing with iters); a pacer
// that reclaims by construction plateaus (~1.0x). Deliberately NOT an absolute
// bound: process RSS is cumulative across the tests in this binary, and the
// equilibrium headroom scales with build opt-level — the invariant that
// actually guards the retired #52-era gc_collect crutches is "no creep".
fn plateau_growth(sz int, iters int) f64 {
	alloc_discard_loop_pacer_only(sz, iters) // reach the pacer's steady state
	mid := rss()
	alloc_discard_loop_pacer_only(sz, iters) // the same churn AGAIN
	end := rss()
	if mid == 0 || end == 0 {
		return 1.0 // RSS unmeasurable; don't fail spuriously
	}
	return f64(end) / f64(mid)
}

// 1 MiB transients (dedicated large spans), ~3 GB of churn per pass against an
// O(1) live set — the #52 fd-streaming shape without its manual gc_collect.
fn test_large_span_transients_bounded_by_pacer_alone() {
	growth := plateau_growth(1 * 1024 * 1024, 3000)
	assert growth < 1.25, 'pacer alone did not bound 1 MiB transients: RSS grew ${growth:.2f}x across a second identical churn pass (want plateau < 1.25x) — the #71 adaptive pacer regressed (call sites must NOT get their gc_collect crutches back)'
}

// The 64 KiB large-object class under the pacer alone. Passes are sized so the
// FIRST pass fully saturates the adaptive headroom (its growth is geometric, so
// a too-small first pass leaves adaptation still ramping in the second pass and
// reads as spurious growth).
fn test_small_span_transients_bounded_by_pacer_alone() {
	growth := plateau_growth(64 * 1024, 12000)
	assert growth < 1.25, 'pacer alone did not bound 64 KiB transients: RSS grew ${growth:.2f}x across a second identical churn pass (want plateau < 1.25x)'
}

// ── cx #52: an EXPLICIT gc_collect() returns the free-span pool to the OS ────
// Automatic cycles keep freed spans committed for reuse (that pool ≈ the
// pacer's headroom, so steady-state RSS sits ~2x the goal — by design), but an
// explicit gc_collect() is the caller saying "memory back NOW": it must finish
// with the unbudgeted pool trim (vgc_pool_trim_all) so RSS drops to the live
// set. This is what makes post-collect RSS snapshots (cmp-005's bounded-memory
// assertion, embedder idle hooks) reflect retention instead of the reuse pool.
fn test_explicit_collect_returns_pool_to_os() {
	$if !vgc ? {
		return // the release-os contract is the vgc collector's; boehm keeps its heap
	}
	// Reach the pacer's steady state: the reuse pool now holds roughly one
	// cycle of dead 1 MiB transients (>= the ~8 MB headroom floor), committed.
	alloc_discard_loop_pacer_only(1 * 1024 * 1024, 3000)
	peak := rss()
	gc_collect()
	after := rss()
	if peak == 0 || after == 0 {
		return // RSS unmeasurable on this platform; don't fail spuriously
	}
	// At least a few MB of pool must actually go back to the OS. Same process,
	// same build, seconds apart — the delta isolates the explicit trim, and the
	// 4 MB bar sits well under the >= 8 MB the headroom floor guarantees the
	// pool holds at any point of the steady churn.
	assert after + 4 * 1024 * 1024 <= peak, 'explicit gc_collect() did not return the span pool to the OS: RSS ${peak / (1024 * 1024)} MB -> ${after / (1024 * 1024)} MB (want a >= 4 MB drop; the vgc_pool_trim_all path regressed)'
}
