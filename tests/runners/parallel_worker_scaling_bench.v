// parallel_worker_scaling_bench.v — does cx eval scale across cores when the
// allocation-heavy work runs inside a [?worker] region?
//
// Companion to parallel_eval_bench.v (which showed plain parallel eval DEGRADES
// under the stock Boehm allocation lock — bench/parallel-alloc). Here the hot,
// allocation-heavy compute (range→map→sum) is the body of a [?worker]. Built
// with `-d cx_regions`, each thread bump-allocates the worker body's transient
// nodes in its OWN per-thread region block instead of contending on Boehm's
// single global allocation mutex, then deep-copies only the small result out.
// The prediction: aggregate evals/s should now SCALE 1→8 threads instead of
// collapsing.
//
// Run the SAME binary at 1/2/4/8 threads and compare aggregate evals/s:
//   third_party/v/v -enable-globals -d cx_regions run \
//     vcx/tests/runners/parallel_worker_scaling_bench.v THREADS ITERS
// Build WITHOUT -d cx_regions for the baseline (regions inert → plain eval).
module main

import code
import time
import sync
import os

// The allocation-heavy work lives inside the [?worker] body, so under
// `-d cx_regions` its transient nodes are region-allocated per thread.
const program = r"[?let [= $w [?worker name='w' [$sum [$map [$range 1 40000] [?fn ($x) [* $x 2]]]]]] [?wait-for [worker $w]]]"

fn worker(iters int, mut wg sync.WaitGroup) {
	for _ in 0 .. iters {
		_ := code.eval_code('', program, 'text') or { panic('eval failed: ${err}') }
	}
	wg.done()
}

fn main() {
	nth := if os.args.len > 1 { os.args[1].int() } else { 1 }
	iters := if os.args.len > 2 { os.args[2].int() } else { 100 }

	// Warm up (GC steady state + per-thread region block created lazily).
	code.eval_code('', program, 'text') or { panic('warmup: ${err}') }

	sw := time.new_stopwatch()
	mut wg := sync.new_waitgroup()
	wg.add(nth)
	for _ in 0 .. nth {
		spawn worker(iters, mut wg)
	}
	wg.wait()
	el := sw.elapsed().milliseconds()
	total := nth * iters
	eps := f64(total) * 1000.0 / f64(el)
	println('threads=${nth} iters/thread=${iters} total=${total} wall_ms=${el} evals/s=${eps:.0} per_thread_evals/s=${eps / f64(nth):.0}')
}
