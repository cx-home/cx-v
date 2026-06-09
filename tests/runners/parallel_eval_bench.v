// parallel_eval_bench.v — does cx EVAL scale across cores?
//
// Each thread runs an allocation-heavy, I/O-free cx program (range→map→sum)
// in a loop via code.eval_code (fresh env per call → no shared cx state; the
// only cross-thread resource is the GC). Reports aggregate + per-thread
// evals/sec at the given thread count. Perfect scaling => aggregate grows ~N×
// and per-thread stays flat. The parallel-allocation finding (bench/
// parallel-alloc) predicts the stock Boehm allocator will make per-thread
// throughput COLLAPSE as N grows — this measures that at the cx level and is
// the baseline the arena-allocation fix must beat.
//
// Run: third_party/v/v -enable-globals run vcx/tests/runners/parallel_eval_bench.v THREADS ITERS
module main

import code
import time
import sync
import os

const program = '[\$sum [\$map [\$range 1 20000] [?fn (\$x) [* \$x 2]]]]'

fn worker(iters int, mut wg sync.WaitGroup) {
	for _ in 0 .. iters {
		_ := code.eval_code('', program, 'text') or { panic('eval failed: ${err}') }
	}
	wg.done()
}

fn main() {
	nth := if os.args.len > 1 { os.args[1].int() } else { 1 }
	iters := if os.args.len > 2 { os.args[2].int() } else { 200 }

	// Warm up (let the GC reach steady state, fill per-thread structures).
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
