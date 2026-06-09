// T1 — evaluator-feature microbench harness.
//
// Standalone runnable benchmark — `make bench-eval` (or `v run`).
// Measures the median latency of each evaluator-surface addition on
// a representative input so per-feature regressions show up in the
// V7 perf gate. Each bench case lives in its own stanza for
// `scripts/run_bench_json.py` to parse.
//
// Coverage (T1):
//   - FLWOR clauses (where, count, order-by, group-by, tumbling)
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

	// FLWOR — additions over the bare ?for baseline.
	bench('flwor.where',
		input,
		'[?for s :in //service :where @id :return [?=s/@id];]')
	bench('flwor.count',
		input,
		'[?for s :in //service :count n :return [?=n]:[?=s/@id];]')
	bench('flwor.order_by',
		input,
		'[?for s :in //service :order-by @id :return [?=s/@id];]')
	bench('flwor.group_by',
		input,
		'[?for s :in //service :group-by [k, s/@id] :return [?=k];]')

	// ?fn invocations — measured by calling a small fn many times
	// inside a for-loop. The 1..500 range exercises call_depth book-
	// keeping per call without pushing past max_call_depth=256
	// (recursion is iterative, not nested).
	bench('fn.call_x500',
		'[p]',
		'[?let f :be [?fn :params [x] :body [?=x]] :return [?for i :in 1 to 500 :return [?f [i]]]]')

	// Partial application — build a partial and invoke it 500 times.
	bench('partial.invoke_x500',
		'[p]',
		'[?let f :be [?partial [[?fn-ref [concat, 2]], \'_\']] :return [?for i :in 1 to 500 :return [?=[?apply [f, i]]]]]')

	// Pipeline operator — chained string transforms.
	bench('op.pipeline',
		input,
		'[?for s :in //service :return [?=s/@id |> upper];]')

	// Arrow operator — fn-application syntax sugar.
	bench('op.arrow',
		input,
		'[?for s :in //service :return [?=s/@id => upper()];]')

	// ?match — exercised against each service's @id; structured
	// dispatch over a small case set.
	bench('match.string',
		input,
		'[?for s :in //service :return [?match [s/@id, [a, A], [b, B], [*, X]]];]')

	// Regex via RE2 — 500 matches of a small pattern.
	bench('regex.matches_x500',
		'[p s=\'hello42world\']',
		"[?for i :in 1 to 500 :return [?=[?matches ['[a-z]+[0-9]+', @s]]];]")

	// to / range operator — sequence materialisation up to a cap
	// well below max_sequence_len (1M).
	bench('op.to_range_10k',
		'[p]',
		'[?for i :in 1 to 10000 :return [?=i];]')

	// Tumbling windows — the A13 ?for-tumbling addition.
	bench('flwor.tumbling',
		input,
		'[?for-tumbling w :in //service :size 5 :return [?for x :in w :return [?=x/@id]];]')

	println('')
}
