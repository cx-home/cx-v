// §11.6 Gate 14 — Pattern compilation microbench.
//
// Threshold: p99 compile time for a depth-8, 32-binding pattern
// MUST be ≤ 1 ms (spec/code.md §11.4.4 gate 14; sample size
// ≥ 1 000 patterns per spec). The mean is reported for context but
// the verdict tracks p99.
//
// "Compilation" here means `cx.parse_program(SRC)` — taking the
// raw CX-program source text and producing the AST that the
// matcher consumes. The matcher itself walks the AST live (no
// separate codegen step in the reference impl), so parse is
// the entire compile cost the spec gate covers.
//
// The pattern is generated programmatically so depth + binding
// count can be varied without hand-edits. The default shape is
//
//   [?for
//     [e0 $b1
//       [e1 $b2
//         [e2 $b3
//           [e3 $b4
//             [e4 $b5
//               [e5 $b6
//                 [e6 $b7
//                   [e7 $b8
//                     ...   (depth-8, 8 bindings on the spine)
//                     :a1 $b9 :a2 $b10 ... :a24 $b32  (24 attr bindings on the leaf)]]]]]]]]
//     :yield ($b1, $b2, $b3, $b4, $b5, $b6, $b7, $b8)]
//
// Yielding 8 spine-bindings + 24 attribute bindings = 32 total
// bindings as the gate calls for. The leaf carries the attr bindings
// so the parser exercises both element-body recursion and
// attribute-predicate parsing within a single pattern.
//
// Output:
//
//   gate-14 mean=NN.NNNus  p50=NN.NNNus  p99=NN.NNNus  max=NN.NNNus
//   gate-14 PASS|FAIL  (p99 NN.NNNms vs 1.000ms threshold)
//
// Env overrides (all optional):
//   GATE14_DEPTH     — pattern depth (default 8)
//   GATE14_BINDINGS  — total bindings (default 32; min = depth)
//   GATE14_ITERS     — sample count (default 2000)
//   GATE14_WARMUP    — warmup count (default 200)

module main
import cx

import code
import platform as _
import time
import os
import strings

const default_depth     = 8
const default_bindings  = 32
const default_iters     = 2000
const default_warmup    = 200
const threshold_ms      = 1.0

// build_pattern emits the depth-D, B-binding pattern described above.
// `depth` MUST be ≥ 1; `bindings` MUST be ≥ `depth` (so each spine
// level gets one head-bind; any surplus is attached as
// wildcard-bound siblings inside the leaf — `*$bN` form, which is
// the canonical "match any child and bind it" pattern shape per
// spec/code.md §5.2).
//
// Shape:
//   [?for
//     [e0 $b1
//       [e1 $b2
//         ...
//           [e7 $b8 *$b9 *$b10 ... *$b32] ...] ]
//     :yield ($b1, $b2, ..., $b8)]
//
// Why wildcard-bound siblings: the pattern grammar's
// `parse_binding_with_path` treats `@name` as an attribute path step,
// so a chain like `@a=$x @b=$y` lexes the second `@` as a path
// continuation of `$x`. Wildcard-bound siblings sidestep that
// without losing binding-count realism — each `*$bN` is a distinct
// binding introduction the matcher MUST track at compile time.
fn build_pattern(depth int, bindings int) string {
	assert depth >= 1
	assert bindings >= depth
	mut b := strings.new_builder(512)
	// #710 item 4 (I5-s17 W6): the builder carried the retired
	// pre-reshape `[?for PATTERN :yield ...]` spelling and the bench
	// crashed at the warmup parse. The measured artifact — parsing a
	// depth-D, B-binding pattern — now rides the current `[?match]`
	// case-pattern form; each `\$bN` is a distinct binding
	// introduction the pattern compiler must track, same realism.
	b.write_string('[?match [probe] [case ')
	// Open `depth` nested spine elements, each with one head-bind.
	for i in 0 .. depth {
		b.write_string('[e${i} \$b${i + 1} ')
	}
	// Leaf carries (bindings - depth) bound siblings.
	for j in 0 .. (bindings - depth) {
		idx := depth + j + 1
		if j > 0 { b.write_string(' ') }
		b.write_string('\$b${idx}')
	}
	// Close all `depth` elements.
	for _ in 0 .. depth {
		b.write_string(']')
	}
	// The arm body yields the spine bindings as a sequence.
	b.write_string(' (')
	for i in 0 .. depth {
		if i > 0 { b.write_string(', ') }
		b.write_string('\$b${i + 1}')
	}
	b.write_string(')] [else []]]')
	return b.str()
}

fn env_int(name string, dflt int) int {
	v := os.getenv(name)
	if v == '' { return dflt }
	return v.int()
}

fn fmt_time_us(us f64) string {
	if us >= 1000.0 {
		return '${us / 1000.0:8.3f}ms'
	}
	return '${us:8.3f}us'
}

fn main() {
	depth     := env_int('GATE14_DEPTH', default_depth)
	bindings  := env_int('GATE14_BINDINGS', default_bindings)
	iters     := env_int('GATE14_ITERS', default_iters)
	warmup    := env_int('GATE14_WARMUP', default_warmup)
	assert iters >= 100, 'iter count too low for p99 stability (need ≥ 100)'

	src := build_pattern(depth, bindings)

	println('CX §11.6 gate-14 pattern-compilation bench')
	println('  pattern depth   : ${depth}')
	println('  pattern bindings: ${bindings}')
	println('  pattern length  : ${src.len} bytes')
	println('  iterations      : ${iters}  (warmup ${warmup})')

	// Warmup (let the V GC settle and the parser allocator stabilise).
	for _ in 0 .. warmup {
		_ := cx.parse_program(src) or { panic('warmup parse failed: ${err}') }
	}

	mut samples_us := []f64{cap: iters}
	for _ in 0 .. iters {
		t0 := time.now()
		_ := cx.parse_program(src) or { panic('parse failed: ${err}') }
		samples_us << f64(time.since(t0).nanoseconds()) / 1000.0
	}
	samples_us.sort()
	mut sum := 0.0
	for v in samples_us { sum += v }
	mean_us := sum / f64(iters)
	p50_us  := samples_us[iters / 2]
	p99_us  := samples_us[(iters * 99) / 100]
	max_us  := samples_us[iters - 1]

	println('')
	println('  mean = ${fmt_time_us(mean_us)}')
	println('  p50  = ${fmt_time_us(p50_us)}')
	println('  p99  = ${fmt_time_us(p99_us)}')
	println('  max  = ${fmt_time_us(max_us)}')
	println('')
	p99_ms := p99_us / 1000.0
	verdict := if p99_ms <= threshold_ms { 'PASS' } else { 'FAIL' }
	println('gate-14 ${verdict}  (p99 ${p99_ms:.3f}ms vs ${threshold_ms:.3f}ms threshold)')
	if verdict == 'FAIL' {
		exit(1)
	}
}
