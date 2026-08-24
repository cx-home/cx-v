// diagram_bench_gate_test.v — the DR-6 performance gate (#758, RULED
// 2026-08-20; ledger/rulings_2026_08_20_diagram_renderer.md), rebuilt on
// a load-invariant measure (#893, RULED: ISW-1;
// ledger/rulings_2026_08_21_issue_sweep_893.md).
//
// WHY THIS GATE NO LONGER ASSERTS A WALL TIME.
//
// It used to assert "a 200-node Mermaid render best-of-5 < 25ms". #893
// reported it RED at 55ms; re-measured on a quiet machine the SAME tree
// passes at ~17ms. The 55ms was recorded with five agents compiling in
// parallel. So nothing had regressed — the gate was reporting the load
// average of a shared build box. A gate that goes red because of a
// neighbour's `clang` is worse than a gate that is red: it teaches the
// house to re-run instead of to read.
//
// `parse_amplification_test.v` settled this class for LIM-2 and its
// header is the precedent quoted here: assert a DETERMINISTIC bound,
// PRINT the time as an advisory, never assert it. This gate follows.
//
// WHAT IS ASSERTED (deterministic, load-immune, machine-immune):
//
//   1. LINEARITY of render work in program size. Render at N and 4N
//      nodes and assert
//        steps(4N) <= 4 * steps(N) + slack
//      where `steps` is the F4 evaluation budget's own work counter
//      (eval_node entries, S6.2 — see code.diagram_render_steps). A
//      renderer that starts doing quadratic per-node work goes red here
//      on every machine; a renderer that merely gets 10% heavier does
//      not, and neither does the diagram module growing new kinds. That
//      is the right sensitivity for a tripwire: it catches the ALGORITHM
//      changing shape, which is the only thing a fixed ceiling was ever
//      really guarding, and it needs no recalibration when the module or
//      the machine changes.
//   2. Output linearity — bytes(4N) <= 4 * bytes(N) + slack — so a
//      render that stays cheap in steps while amplifying its output is
//      caught too.
//   3. The render still produces a Mermaid flowchart at both sizes.
//
// WHAT IS PRINTED, NEVER ASSERTED:
//
//   the best-of-5 wall time for the 200-node render, so drift stays
//   visible in the logs. DR-6's 25ms figure and its 12-18ms landing
//   measurement live on in spec/03-approved/std-lib/diagram.md §8 as a
//   CALIBRATION NOTE naming the machine and conditions they were taken
//   under — a recorded measurement, not a pass/fail criterion this gate
//   can honestly own.
//
// Calibration of the slack terms (2026-08-21, this tree, Apple silicon,
// load average ~3, and load-INDEPENDENT by construction): the 99-stage
// render costs 52381 eval steps and the 396-stage render 205336 — ratio
// 3.92 for 4x the stages. Fitting steps = a·stages + b gives a ≈ 515 per
// stage and a FIXED per-render cost b ≈ 1400 steps, which is what the
// slack term exists to cover; 25000 is ~18x that fixed cost, i.e. ~12%
// headroom over the measured 205336 against a 234524 bound. A quadratic
// renderer would need ~838000 at the same size, so the bound separates
// the two by nearly 4x. Both ratios are printed on every run, so a future
// reader sees the real numbers next to the bound instead of trusting this
// comment.

module main

import time
import cx
import code
import platform as _

// The linearity bound: work at 4N may be at most 4x the work at N, plus
// a slack term for the fixed per-render cost (module entry, PI strip,
// patches, envelope) that does not scale with the program. Slack is
// deliberately generous — this gate exists to catch a change of SHAPE
// (quadratic), not a change of constant.
const bench_linearity_slack = u64(25_000)
const bench_bytes_slack = 4096

// build_n_node_program builds a pipeline with `stages` [?fn] stages —
// 1 input + `stages` stage nodes + start/result — and per-stage labels,
// i.e. roughly `stages` rendered nodes' worth of per-node dispatch +
// label + emit work.
fn build_n_node_program(stages int) string {
	mut src := '[?pipe (1, 2, 3)'
	for i in 0 .. stages {
		src += ' through=[?fn (\$x) [* \$x ${i}]]'
	}
	src += ']'
	return src
}

fn build_200_node_program() string {
	return build_n_node_program(99)
}

fn test_mermaid_render_work_is_linear_in_program_size() {
	small_src := build_n_node_program(99) // ~200 rendered nodes
	big_src := build_n_node_program(396) // 4x the stages
	cx.parse_program(small_src) or {
		assert false, 'bench program parse (small): ${err}'
		return
	}
	cx.parse_program(big_src) or {
		assert false, 'bench program parse (big): ${err}'
		return
	}
	// Warm-up: loads + caches the module so the fixed module-load cost is
	// not attributed to the small render (it would deflate the ratio).
	_, _ := code.diagram_render_steps(small_src, 'mermaid') or {
		assert false, 'warm-up render: ${err}'
		return
	}
	small_out, small_steps := code.diagram_render_steps(small_src, 'mermaid') or {
		assert false, 'small render: ${err}'
		return
	}
	big_out, big_steps := code.diagram_render_steps(big_src, 'mermaid') or {
		assert false, 'big render: ${err}'
		return
	}
	assert small_out.contains('flowchart TD')
	assert big_out.contains('flowchart TD')
	assert small_steps > 0, 'the step counter must actually count (got 0) — a silent nil budget would make this gate vacuous'

	bound := 4 * small_steps + bench_linearity_slack
	eprintln('diagram-bench: eval steps 99-stage=${small_steps} 396-stage=${big_steps} ratio=${f64(big_steps) / f64(small_steps):.2} bound=${bound}')
	assert big_steps <= bound, 'mermaid render work is superlinear in program size: 4x the stages cost ${big_steps} eval steps against a linear bound of ${bound} (= 4 * ${small_steps} + ${bench_linearity_slack})'

	byte_bound := 4 * small_out.len + bench_bytes_slack
	eprintln('diagram-bench: output bytes 99-stage=${small_out.len} 396-stage=${big_out.len} ratio=${f64(big_out.len) / f64(small_out.len):.2} bound=${byte_bound}')
	assert big_out.len <= byte_bound, 'mermaid output amplifies: 4x the stages emitted ${big_out.len} bytes against a linear bound of ${byte_bound}'
}

// The wall-time ADVISORY. Never asserted — see the header. It runs the
// same best-of-5 the old gate ran so the number in the logs stays
// comparable with the DR-6 landing measurement, and it prints the DR-6
// budget alongside so a reader can see the headroom without the build
// machine's load average getting a vote on the exit code.
fn test_mermaid_render_wall_time_advisory() {
	src := build_200_node_program()
	_ := code.render_diagram(src, 'mermaid') or {
		assert false, 'warm-up render: ${err}'
		return
	}
	mut samples := []i64{}
	for _ in 0 .. 5 {
		sw := time.new_stopwatch()
		out := code.render_diagram(src, 'mermaid') or {
			assert false, 'render: ${err}'
			return
		}
		samples << sw.elapsed().microseconds()
		assert out.contains('flowchart TD')
	}
	samples.sort()
	best := samples[0]
	median := samples[2]
	worst := samples[4]
	verdict := if best < 25_000 { 'within' } else { 'OVER' }
	// best / median / worst are all printed on purpose: the SPREAD is the
	// evidence for why this is an advisory. Measured 2026-08-21 on this
	// tree, the eval-step counts above are bit-identical between a quiet
	// machine (load ~3) and one carrying five parallel V+clang compiles
	// (load ~51) — while the wall-time spread widens with load. Timing
	// belongs in the log; the exit code belongs to the linearity bound.
	eprintln('diagram-bench: 200-node mermaid render of 5 — best=${best}µs median=${median}µs worst=${worst}µs (best is ${verdict} the DR-6 calibration figure of 25000µs — ADVISORY, not asserted: these are properties of the machine and its load, not of the renderer; the asserted property is linearity, above)')
}
