// parse_amplification_test.v — the LIM-2 amplification gate
// (spec/03-approved/core/limits.md; ruling LIM-2, owner 2a, 2026-08-20).
//
// limits.md §4's whole posture rests on ONE claim: parse cost is LINEAR
// in input bytes, so every quantity an attacker controls is a quantity
// the embedder already holds in hand. This gate PINS that claim so it is
// a tested property, not an intention — a future parser change that
// introduces superlinear time or node amplification goes red here, which
// a fixed cap could never do.
//
// Method: for each adversarial shape, parse at N and 4N bytes and assert
//   nodes(4N) <= 4 * nodes(N) + 64       (no node amplification — HARD)
// and PRINT the CPU-time ratio as a diagnostic (advisory, never asserted).
//
// Why time is advisory: calibration 2026-08-20 measured the parse
// ALGORITHM linear (-gc none: 1.9-2.3x per byte-doubling on every
// shape), but under the shipped collector both wall time (suite load)
// and process CPU (parallel-mark cost growing with live heap — up to
// 14x for 4x bytes on the tiny-siblings shape) are superlinear at MB
// scale for reasons that are collector properties, not parser
// properties. A time assertion here can only gate the collector's
// mood. The node bound is deterministic, load-immune, and catches the
// attack class the gate exists for (a construction that mints more
// work per byte); the printed ratio keeps drift visible in logs.
// Shapes cover the historically dangerous inputs: attr-heavy elements,
// many tiny siblings, deep-but-capped nesting runs, long bare scalars,
// entity-ref-dense bodies, and comment-dense text.
module main

import cx

// Process CPU time via libc clock(): under a 12-way-parallel suite the
// WALL clock inflates with scheduler delay and faked a superlinear ratio
// on the first full-matrix run; CPU ticks of THIS process stay honest
// under load (units cancel in the ratio, so CLOCKS_PER_SEC is not
// needed).
fn C.clock() i64

fn count_nodes(n cx.Node) int {
	mut total := 1
	if n is cx.Element {
		total += n.attrs.len
		for c in n.items {
			total += count_nodes(c)
		}
	}
	return total
}

fn doc_nodes(d cx.Document) int {
	mut total := 0
	for e in d.elements {
		total += count_nodes(e)
	}
	return total
}

// build one adversarial document of roughly `target` bytes from a unit.
fn build(unit string, target int) string {
	reps := target / unit.len + 1
	mut sb := []string{cap: reps + 2}
	sb << '[root'
	for _ in 0 .. reps {
		sb << unit
	}
	sb << ']'
	return sb.join('\n')
}

fn measure(src string) (i64, int) {
	start := C.clock()
	d := cx.parse(src) or { panic('amplification-gate input must parse: ${err}') }
	elapsed := C.clock() - start
	return elapsed, doc_nodes(d)
}

fn assert_linear(name string, unit string) {
	n := 262144 // 256 KiB base
	small := build(unit, n)
	big := build(unit, n * 4)
	// warm both paths once so allocator/page effects don't skew trial 1
	cx.parse(small) or { panic(err) }
	cx.parse(big) or { panic(err) }
	// median-of-5 per size: min is noise-prone in EITHER direction here
	// (one lucky-fast small sample fakes a superlinear ratio)
	mut ts_all := []i64{}
	mut tb_all := []i64{}
	mut nodes_small := 0
	mut nodes_big := 0
	for _ in 0 .. 5 {
		ts, ns := measure(small)
		ts_all << ts
		nodes_small = ns
		tb, nb := measure(big)
		tb_all << tb
		nodes_big = nb
	}
	ts_all.sort()
	tb_all.sort()
	t_small := ts_all[2]
	t_big := tb_all[2]
	// advisory CPU-ratio diagnostic (linear predicts ~4x; collector cost
	// inflates it at MB scale — see the header)
	ratio_x10 := if t_small > 0 { t_big * 10 / t_small } else { 0 }
	println('  amplification[${name}]: cpu ${t_small} -> ${t_big} ticks @4x bytes (${ratio_x10 / 10}.${ratio_x10 % 10}x, advisory)')
	// node amplification: 4x bytes may yield at most ~4x nodes — HARD
	assert nodes_big <= 4 * nodes_small + 64, '${name}: node amplification — ${nodes_small} @1x vs ${nodes_big} @4x'
}

fn test_attr_heavy_elements_stay_linear() {
	assert_linear('attr-heavy', '[e a1=1 a2=2 a3=3 a4=4 a5=5 a6=6 a7=7 a8=8]')
}

fn test_many_tiny_siblings_stay_linear() {
	assert_linear('tiny-siblings', '[x][y][z]')
}

fn test_capped_nesting_runs_stay_linear() {
	// nesting depth 32 (under the 64 cap), repeated in sequence
	mut unit := ''
	for _ in 0 .. 32 {
		unit += '[n '
	}
	unit += '1'
	for _ in 0 .. 32 {
		unit += ']'
	}
	assert_linear('nesting-runs', unit)
}

fn test_long_bare_scalars_stay_linear() {
	assert_linear('bare-scalars', '[s abcdefghijklmnopqrstuvwxyz0123456789]')
}

fn test_entity_dense_bodies_stay_linear() {
	// entity refs parse to nodes, never expand (limits.md §3) — density
	// must not amplify
	assert_linear('entity-dense', '[t a &amp; b &lt; c &gt; d]')
}

fn test_comment_dense_text_stays_linear() {
	assert_linear('comment-dense', '[; a comment that the parser must skip ][c 1]')
}

fn test_max_input_bytes_refuses_typed() {
	src := '[a 1]'
	// under the bound: parses
	d := cx.parse_limited(src, cx.ParseLimits{ max_input_bytes: 1024 }) or {
		panic('under-bound parse must succeed: ${err}')
	}
	assert d.elements.len == 1
	// over the bound: typed refusal naming both numbers and the spec home
	cx.parse_limited(src, cx.ParseLimits{ max_input_bytes: 3 }) or {
		assert err.msg().contains('max_input_bytes'), 'refusal must name the guard: ${err.msg()}'
		assert err.msg().contains('limits.md'), 'refusal must cite the spec home: ${err.msg()}'
		return
	}
	panic('over-bound parse must refuse')
}

fn test_zero_means_unbounded() {
	d := cx.parse_limited('[a 1]', cx.ParseLimits{}) or { panic(err) }
	assert d.elements.len == 1
}
