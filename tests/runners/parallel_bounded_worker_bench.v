// parallel_bounded_worker_bench.v — does the region scale for its INTENDED
// shape: a bounded work unit whose transient footprint FITS the per-thread
// block and resets per unit?
//
// The companion parallel_worker_scaling_bench.v showed a HIGH-CHURN bulk body
// (range→map→sum over 40 000) overflows the block and falls back to GC_MALLOC
// under the global lock → no scaling. This bench uses a SMALL body (default
// range 2 000) that fits the block, so all of its transient cx.Node allocation
// is region-bumped (no global lock) and the block is reset at scope exit. The
// program is tiny (cheap parse) and the result is a single integer (cheap
// render), so the regioned body compute dominates per-eval allocation — the
// condition under which the region should let throughput SCALE 1→8 threads.
//
// Build WITH -d cx_regions (set CX_REGION_BLOCK big enough that region_stats
// shows ~0 fallbacks for the chosen N) and WITHOUT it (baseline). Run the same
// binary at 1/2/4/8 threads; the region build's aggregate evals/s should grow
// with threads where the baseline collapses.
//
// Run: CX_REGION_BLOCK=$((16*1024*1024)) third_party/v/v -enable-globals \
//        -d cx_regions run vcx/tests/runners/parallel_bounded_worker_bench.v THREADS ITERS [RANGE]
module main

import code
import time
import sync
import os

fn worker(prog string, iters int, mut wg sync.WaitGroup) {
	for _ in 0 .. iters {
		_ := code.eval_code('', prog, 'text') or { panic('eval failed: ${err}') }
	}
	wg.done()
}

fn main() {
	nth := if os.args.len > 1 { os.args[1].int() } else { 1 }
	iters := if os.args.len > 2 { os.args[2].int() } else { 400 }
	rng := if os.args.len > 3 { os.args[3].int() } else { 2000 }

	// Tiny program, small bounded body, single-integer result. The worker body
	// is the dominant allocator and (for a small rng) fits the region block.
	prog := r"[?let [= $w [?worker name='w' [body [$sum [$map [$range 1 " + rng.str() +
		r"] [?fn ($x) [* $x 2]]]]]]] [?wait-for worker=$w]]"

	code.eval_code('', prog, 'text') or { panic('warmup: ${err}') } // warm GC + create block

	sw := time.new_stopwatch()
	mut wg := sync.new_waitgroup()
	wg.add(nth)
	for _ in 0 .. nth {
		spawn worker(prog, iters, mut wg)
	}
	wg.wait()
	el := sw.elapsed().milliseconds()
	total := nth * iters
	eps := f64(total) * 1000.0 / f64(el)
	println('range=${rng} threads=${nth} iters/thread=${iters} total=${total} wall_ms=${el} evals/s=${eps:.0} per_thread_evals/s=${eps / f64(nth):.0}')
}
