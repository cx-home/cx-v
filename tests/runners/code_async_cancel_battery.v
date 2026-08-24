// §11.6 Gate 8 — async cancellation battery.
//
// Threshold: zero non-deterministic failures across 10 000 iterations.
//
// Workload. Each iteration runs the canonical cancellation pattern
// (program-async-012-cancel-honored-at-sleep): an [?async] body that
// would otherwise block on [?sleep 10s] is cancelled before any
// runnable yield-point hits the sleep, then awaited. The contract
// per `spec/code.md` §10.5 says the await MUST observe
// the cancellation as CXER0260. Any iteration that:
//   - completes the body (returning the post-sleep value),
//   - reports a different error code,
//   - or hangs past the per-iteration wall-clock budget,
// is counted as a battery failure. Gate 8 passes iff zero such
// failures occur across the full iteration count.
//
// Cadence. Per `spec/code.md` §11.6 gate 8 the canonical battery
// is 10 000 iterations. The harness exposes both an iteration count
// and a per-iteration wall-clock cap; defaults run in well under a
// minute on the reference hardware (§11.4.5) so the battery can be
// part of the CI fan-out, not just a release-candidate check.
//
// Env overrides:
//   GATE8_ITERATIONS      — total iterations (default 10_000)
//   GATE8_ITER_TIMEOUT_MS — per-iteration wall-clock cap (default 200)

module main

import code
import platform as _
import time
import os

const default_iterations      = 10_000
const default_iter_timeout_ms = 200
const expected_err_code       = 'cx-err:CXER0260'

fn env_int(name string, dflt int) int {
	v := os.getenv(name)
	if v == '' { return dflt }
	return v.int()
}

// canonical cancellation program: synthesize a future whose body
// would sleep 10s (mock — simulated time, no wall-clock wait),
// cancel it immediately, await — expect CXER0260.
// (#805/audit AF-5: carried the retired pre-reshape `[?let $x = …
// :in …]` spelling — 10,000/10,000 hard eval errors; repaired to the
// ENFORCED program-async-004 fixture's exact program, the W6
// gate-14/16 pattern.)
const cancel_program = '[?let [= \$f [?async [?let [= \$_ [?sleep 10s mock]] never]]] [= \$_ [?cancel \$f]] [?await \$f]]'

fn main() {
	iterations      := env_int('GATE8_ITERATIONS', default_iterations)
	iter_timeout_ms := env_int('GATE8_ITER_TIMEOUT_MS', default_iter_timeout_ms)

	println('CX §11.6 gate-8 async-cancellation battery')
	println('  iterations        : ${iterations}')
	println('  per-iter timeout  : ${iter_timeout_ms} ms')

	mut completed       := 0
	mut wrong_shape     := 0
	mut slow_iterations := 0
	mut hard_errors     := 0
	mut max_iter_us     := i64(0)

	for i in 0 .. iterations {
		iter_start := time.now()
		out := code.eval_code('', cancel_program, 'text') or {
			hard_errors++
			if hard_errors <= 5 {
				eprintln('iteration ${i}: hard eval error: ${err}')
			}
			continue
		}
		elapsed_us := time.since(iter_start).microseconds()
		if elapsed_us > max_iter_us { max_iter_us = elapsed_us }
		if elapsed_us > i64(iter_timeout_ms) * 1000 {
			slow_iterations++
		}
		// Spec contract: result must be [err :code "cx-err:CXER0260"].
		// same_shape-style comparison: just check the err-code token
		// appears bare; verbose shape comparison is covered by the
		// fixture suite, not the battery.
		if out.contains(expected_err_code) {
			completed++
		} else {
			wrong_shape++
			if wrong_shape <= 5 {
				eprintln('iteration ${i}: wrong shape, got: ${out}')
			}
		}
		if (i + 1) % 1000 == 0 {
			println('  ... ${i + 1} iterations done (max iter ${max_iter_us} µs)')
		}
	}

	println('')
	println('  cancellations observed : ${completed} / ${iterations}')
	println('  wrong-shape failures   : ${wrong_shape}')
	println('  slow iterations        : ${slow_iterations}')
	println('  hard eval errors       : ${hard_errors}')
	println('  max iter wall-clock    : ${max_iter_us} µs')

	if wrong_shape > 0 || hard_errors > 0 {
		eprintln('gate-8 FAIL  (${wrong_shape} wrong-shape, ${hard_errors} hard errors)')
		exit(1)
	}
	if slow_iterations > 0 {
		eprintln('gate-8 FAIL  (${slow_iterations} iteration${if slow_iterations > 1 { "s" } else { "" }} exceeded ${iter_timeout_ms} ms)')
		exit(1)
	}
	if completed != iterations {
		eprintln('gate-8 FAIL  (only ${completed}/${iterations} observed cancellation)')
		exit(1)
	}
	println('gate-8 PASS  (${completed}/${iterations} cancellations observed, max iter ${max_iter_us} µs)')
}
