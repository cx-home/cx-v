// T1 — evaluator-feature microbench harness.
//
// Standalone runnable benchmark — `make bench-eval` (or `v run`).
// Measures the median latency of each evaluator-surface addition on
// a representative input so per-feature regressions show up in the
// V7 perf gate. Each bench case lives in its own stanza for
// `scripts/run_bench_json.cx` to parse.
//
// Coverage (T1):
//   - FLWOR clauses (where, count, order-by, group-by)
//   - ?fn calls (high-frequency invocation)
//   - Partial application
//   - Pipeline operator
//   - Arrow operator
//   - ?match
//   - Regex (matches via vendored RE2)
//
// CI integration (>10/30% regression gate) lives in V7. This
// file is the per-arc measurement tool, not a CI test.

module main

import code
import platform as _
import time
import os

const fixture_path = 'fixtures/bench/bench_medium.cx'
const warmup_runs = 5
const measured_runs = 25

fn run_once(input string, program string) i64 {
	t0 := time.now()
	_ := code.eval_code(input, program, '') or {
		panic('eval_code failed for "${program}": ${err}')
	}
	return time.since(t0).microseconds()
}

fn bench(label string, input string, program string) {
	for _ in 0 .. warmup_runs {
		run_once(input, program)
	}
	mut times := []i64{cap: measured_runs}
	for _ in 0 .. measured_runs {
		times << run_once(input, program)
	}
	times.sort()
	median_us := times[measured_runs / 2]
	min_us := times[0]
	max_us := times[measured_runs - 1]
	println('  ${label:-32s}  median=${f64(median_us)/1000.0:7.3f}ms  min=${f64(min_us)/1000.0:7.3f}ms  max=${f64(max_us)/1000.0:7.3f}ms')
}

fn main() {
	if !os.exists(fixture_path) {
		println('SKIP: ${fixture_path} not present; run `make bench-fixtures` first')
		return
	}
	input := os.read_file(fixture_path) or {
		panic('cannot read ${fixture_path}: ${err}')
	}

	println('Evaluator-feature microbench (T1)')
	println('  fixture        : ${fixture_path} (${input.len} bytes)')
	println('  warmup runs    : ${warmup_runs}')
	println('  measured runs  : ${measured_runs}')
	println('')

	// (#805 gate-truth batch, audit AF-5: every row carried the retired
	// pre-reshape surface — `:in/:where/:return`, `:be`, `|>`, `=>`,
	// infix `to` ranges — and panicked at the first eval. Rewritten to
	// the ENFORCED code.cxd spellings, semantically parallel rows; the
	// labels stay stable for the T1.* baseline keys.)

	// FLWOR — additions over the bare ?for baseline.
	bench('flwor.where',
		input,
		'[?for [in \$s \$doc//service] [where [> \$s/@id 0]] [yield \$s/@id]]')
	// (the `:count n` CLAUSE is retired — the aggregation equivalent
	// counts the assembled walk.)
	bench('flwor.count',
		input,
		'[\$count [?for [in \$s \$doc//service] [yield \$s/@id]]]')
	bench('flwor.order_by',
		input,
		'[?for [in \$s \$doc//service] [order-by \$s/@id] [yield \$s/@id]]')
	bench('flwor.group_by',
		input,
		'[?for [service @id=\$id] [group-by \$id] [yield \$id]]')

	// ?fn invocations — measured by calling a small fn many times
	// inside a for-loop.
	bench('fn.call_x500',
		'[p]',
		'[?let [= \$f [?fn \$x \$x]] [?for [in \$i [\$range 1 500]] [yield [\$f \$i]]]]')

	// Partial application — placeholder partial invoked 500 times.
	bench('partial.invoke_x500',
		'[p]',
		"[?lib 'cx-stdlib/math']\n[?let [= \$sq [\$math:pow _ 2]] [?for [in \$i [\$range 1 500]] [yield [\$sq \$i]]]]")

	// Pipeline directive — the walk piped into the count stage.
	bench('op.pipeline',
		input,
		'[?pipe [?for [in \$s \$doc//service] [yield \$s/@id]] \$count]')

	// (`op.arrow` is RETIRED with the postfix arrow itself — the
	// reshape has one application form; no replacement row.)

	// ?match — structured dispatch over each service's @id.
	bench('match.string',
		input,
		'[?for [in \$s \$doc//service] [yield [?match \$s/@id [case 1 :a] [case 2 :b] [else :x]]]]')

	// Regex via RE2 — 500 matches of a small compiled pattern.
	bench('regex.matches_x500',
		'[p]',
		"[?lib 'cx-stdlib/re']\n[?let [= \$p [\$re:compile \"[a-z]+[0-9]+\"]] [?for [in \$i [\$range 1 500]] [yield [\$re:matches \$p \"hello42world\"]]]]")

	// Range materialisation up to a cap well below the budget floor.
	bench('op.to_range_10k',
		'[p]',
		'[?for [in \$i [\$range 1 10000]] [yield \$i]]')

	// (The `flwor.tumbling` case is RETIRED with the `[?for-tumbling]`
	// head itself — L98, planar_algebra.md: windows are out of v1 and the
	// future form is a CLAUSE under `[?for]`, never a new head. Stream 13
	// deleted the implementation; stream-2 W2 deletes the reservation.)

	println('')
}
