// region_corruption_bench.v — escape-safety corruption battery for the
// scope-aware region allocator (bench/parallel-alloc/INTEGRATION-DESIGN.md §7).
//
// Builds with `-d cx_regions` so every [?worker] body runs inside a per-thread
// region (transient nodes bump-allocated in a raw block, result deep-copied to
// GC via region_export, block reset at scope exit). The battery hunts for the
// failure mode that scheme can produce — a missed escape channel leaving a live
// pointer into the just-reset block → use-after-reset corruption — by stacking
// every stressor at once:
//
//   * N threads each eval a [?worker] program M times (M region enter/reset
//     cycles per thread, all concurrent).
//   * A heavy worker RESULT tree (hundreds of nested elements) that is fully
//     rendered into the output, so corruption anywhere in the exported tree
//     shows up as a byte difference.
//   * A GC-hammer thread forcing GC_gcollect() throughout: a dangling region
//     pointer that the GC has not been told about (or a region object the GC
//     wrongly reclaims) corrupts here.
//   * CX_REGION_BLOCK can be set tiny by the caller to force frequent
//     overflow-fallback (region → GC_MALLOC) + reset churn.
//
// PASS criterion: every one of the N*M concurrent outputs is byte-identical to
// a serial reference computed before any threads start, and the process does
// not crash. Any mismatch or crash = a real escape-safety bug.
//
// Run: third_party/v/v -enable-globals -d cx_regions run \
//        vcx/tests/runners/region_corruption_bench.v THREADS ITERS
module main

import code
import sync
import os
import time

fn C.GC_gcollect()

// Heavy worker: a 300-row bundle, each row carrying a nested element. The whole
// tree is the worker result → deep-copied by region_export → rendered, so the
// output reflects the entire exported structure.
const program = r'[?let [= $w [?worker name=' + "'cw'" +
	r' [bundle [?for [in $x [$range 1 300]] [yield [row i=$x sq=[* $x $x] dbl=[* $x 2] t=[k a=$x b=[* $x 7] c=[* $x $x]]]]]]]] [?wait-for [worker $w]]]'

struct Stop {
mut:
	flag bool
}

fn gc_hammer(shared s Stop) {
	for {
		rlock s {
			if s.flag {
				return
			}
		}
		C.GC_gcollect()
		time.sleep(time.millisecond)
	}
}

// worker evals `program` `iters` times, comparing each rendered output to
// `reference`; sends its mismatch count down `ch`.
fn battery_worker(iters int, reference string, ch chan int) {
	mut bad := 0
	for _ in 0 .. iters {
		got := code.eval_code('', program, 'text') or {
			eprintln('eval failed: ${err}')
			bad++
			continue
		}
		if got != reference {
			bad++
		}
	}
	ch <- bad
}

fn main() {
	nth := if os.args.len > 1 { os.args[1].int() } else { 8 }
	iters := if os.args.len > 2 { os.args[2].int() } else { 200 }

	// Serial reference — computed single-threaded, before any GC hammering or
	// region contention, so it is the known-good byte string.
	reference := code.eval_code('', program, 'text') or { panic('reference eval failed: ${err}') }
	if reference.len < 100 {
		panic('reference output suspiciously small (${reference.len} bytes) — program changed?')
	}

	hammer := os.getenv('CX_NO_HAMMER') == ''
	shared stop := &Stop{}
	if hammer {
		spawn gc_hammer(shared stop)
	}

	ch := chan int{cap: nth}
	sw := time.new_stopwatch()
	for _ in 0 .. nth {
		spawn battery_worker(iters, reference, ch)
	}
	mut total_bad := 0
	for _ in 0 .. nth {
		total_bad += <-ch
	}
	el := sw.elapsed().milliseconds()

	lock stop {
		stop.flag = true
	}

	total := nth * iters
	block_env := os.getenv('CX_REGION_BLOCK')
	block_note := if block_env != '' { 'CX_REGION_BLOCK=${block_env}' } else { 'block=default(2MiB)' }
	if total_bad == 0 {
		println('PASS region-corruption: threads=${nth} iters/thread=${iters} evals=${total} ref_bytes=${reference.len} ${block_note} wall_ms=${el} mismatches=0')
	} else {
		println('FAIL region-corruption: threads=${nth} iters/thread=${iters} evals=${total} ${block_note} wall_ms=${el} mismatches=${total_bad}')
		exit(1)
	}
}
