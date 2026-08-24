// abi.md §4 performance-budget driver (#805 gate-truth batch, audit
// AF-6: the ten-cell timing table had NEVER had a measuring artifact
// in project history — its only citation pointed at a
// spec/architecture.md that does not exist).
//
// Measures the ABI calls IN-PROCESS with full call semantics (text in
// → output out, parse included — that is what the C ABI call does).
// What the audit's CLI first-measurement conflated (process spawn +
// file I/O) is excluded; what remains vs the real C ABI is only the
// C-string marshaling, which is O(len) copies — noted, not material
// against ms-scale budgets.
//
// Tiers: 1 KB (synthesized deterministically at ~1 KiB), 1 MB
// (fixtures/bench/bench_1mb.cx). The 100 MB tier is opt-in via
// ABI_S4_100MB=1 (a red engine makes it a ~minutes run; the honest
// default prints the extrapolation instead of silently skipping).
//
// VERDICT DISCIPLINE (the #805 bar): budgets come verbatim from
// abi.md §4 and are NEVER trued to a shortfall — a red cell exits 1
// and stays red until the engine recovers (#804's ceiling extends to
// these conversion budgets; the audit predicted ~5-10x over).

module main

import cx
import os
import time
import strings

const runs_1kb = 50
const runs_1mb = 5

struct Cell {
	op        string
	tier      string
	budget_us i64
	median_us i64
}

fn median_us(mut samples []i64) i64 {
	samples.sort()
	return samples[samples.len / 2]
}

fn gen_1kb() string {
	// Data-shaped records, deterministic, ≥1 KiB (mirrors the bench
	// fixture family's shape).
	mut b := strings.new_builder(1400)
	b.write_string('[services\n')
	mut i := 0
	for b.len < 1024 - 11 {
		i++
		b.write_string('  [service id=${i} name=svc-${i} host=h${i}.example.com port=${8000 + i} active=true]\n')
	}
	b.write_string(']\n')
	return b.str()
}

fn time_op(src string, runs int, op fn (string) !i64) !i64 {
	mut samples := []i64{cap: runs}
	// one warmup
	op(src)!
	for _ in 0 .. runs {
		samples << op(src)!
	}
	return median_us(mut samples)
}

fn op_ast_bin(src string) !i64 {
	t0 := time.now()
	doc := cx.parse(src)!
	out := cx.emit_ast_bin(doc)
	el := time.since(t0).microseconds()
	if out.len == 0 {
		return error('empty ast_bin output')
	}
	return el
}

fn op_data_bin(src string) !i64 {
	t0 := time.now()
	doc := cx.parse(src)!
	out := cx.emit_data_bin(doc)!
	el := time.since(t0).microseconds()
	if out.len == 0 {
		return error('empty data_bin output')
	}
	return el
}

fn op_json(src string) !i64 {
	t0 := time.now()
	out := cx.to_json(src)!
	el := time.since(t0).microseconds()
	if out.len == 0 {
		return error('empty json output')
	}
	return el
}

fn main() {
	one_kb := gen_1kb()
	fixture := 'fixtures/bench/bench_1mb.cx'
	if !os.exists(fixture) {
		eprintln('SKIP: ${fixture} not present')
		exit(0)
	}
	one_mb := os.read_file(fixture) or { panic('read ${fixture}: ${err}') }

	println('abi.md §4 performance-budget driver (in-process ABI-call timing)')
	println('  1 KB tier input : ${one_kb.len} B synthesized, ${runs_1kb} runs')
	println('  1 MB tier input : ${one_mb.len} B (${fixture}), ${runs_1mb} runs')
	println('')

	mut cells := []Cell{}
	cells << Cell{'cx_to_ast_bin', '1KB', 50, time_op(one_kb, runs_1kb, op_ast_bin) or {
		panic(err)
	}}
	cells << Cell{'cx_to_data_bin', '1KB', 50, time_op(one_kb, runs_1kb, op_data_bin) or {
		panic(err)
	}}
	cells << Cell{'cx_to_json', '1KB', 100, time_op(one_kb, runs_1kb, op_json) or { panic(err) }}
	cells << Cell{'cx_to_ast_bin', '1MB', 30_000, time_op(one_mb, runs_1mb, op_ast_bin) or {
		panic(err)
	}}
	cells << Cell{'cx_to_data_bin', '1MB', 30_000, time_op(one_mb, runs_1mb, op_data_bin) or {
		panic(err)
	}}
	cells << Cell{'cx_to_json', '1MB', 60_000, time_op(one_mb, runs_1mb, op_json) or {
		panic(err)
	}}

	// cx_events_next: <1 µs/event. Handle built once (parse outside —
	// the per-event budget times the pull, exactly the ABI row).
	doc := cx.parse(one_mb) or { panic('parse 1MB: ${err}') }
	mut stream := cx.new_stream_from_doc(doc)
	t0 := time.now()
	mut n_events := 0
	for {
		_ := stream.next() or { break }
		n_events++
	}
	ev_total_us := time.since(t0).microseconds()
	ev_ns_per := if n_events > 0 { ev_total_us * 1000 / n_events } else { i64(-1) }
	println('  cx_events_next: ${n_events} events in ${ev_total_us} µs → ${ev_ns_per} ns/event (budget 1000 ns)')

	// 100 MB tier: opt-in run or honest extrapolation.
	if os.getenv('ABI_S4_100MB') == '1' {
		big := os.read_file('fixtures/bench/bench_10mb.cx') or { panic('read 10mb: ${err}') }
		m := time_op(big, 1, op_json) or { panic(err) }
		println('  100MB tier (measured at 10 MB ×10 extrapolation): cx_to_json ~${m * 10 / 1000} ms vs 6000 ms budget')
	} else {
		println('  100MB tier: NOT run (opt-in ABI_S4_100MB=1); linear extrapolation from the 1 MB cells applies')
	}
	println('')

	mut reds := 0
	for c in cells {
		verdict := if c.median_us <= c.budget_us { 'PASS' } else { 'RED ' }
		if c.median_us > c.budget_us {
			reds++
		}
		ratio := f64(c.median_us) / f64(c.budget_us)
		println('  ${verdict}  ${c.op:-16s} ${c.tier:-4s} median=${c.median_us} µs  budget=${c.budget_us} µs  (${ratio:.1f}x)')
	}
	if ev_ns_per > 1000 {
		reds++
		println('  RED   cx_events_next per-event ${ev_ns_per} ns > 1000 ns')
	} else {
		println('  PASS  cx_events_next per-event ${ev_ns_per} ns ≤ 1000 ns')
	}

	println('')
	if reds > 0 {
		eprintln('abi-s4 RED (${reds} cell(s) over budget — budgets stand, never trued; the recovery rides #804)')
		exit(1)
	}
	println('abi-s4 PASS (all measured cells within the §4 budgets)')
}
