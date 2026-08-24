// cxparse PERF BASELINE — Phase 0 of the parser unification
// (spec/02-inprogress/cxparse_unification_PLAN.md, mandate N3 + §6).
//
// Standalone runnable benchmark. Run it via `make bench-cxparse`, which uses
// the patched V at third_party/v/ — DO NOT build this with the V on PATH /
// devbox `v` in `-prod` on macOS: that V bundles a boehm GC source-compile that
// corrupts the heap during collection, segfaulting (signal 11, inside
// GC_malloc_kind_aligned at the next allocation after a collection) on the very
// first measured parse. The patched V carries the macOS hardened-runtime libgc
// source-compile bypass (Makefile §bench-streaming, vlang/v #27178/#27179) that
// makes `-prod` safe. Dev mode (no `-prod`) is unaffected with either V.
// Manual invocation: `third_party/v/v -prod run …` with
// VFLAGS='-path "@vlib|@vmodules|vcx"'. It captures the CURRENT
// throughput of BOTH parsers on identical inputs, so every later phase can
// prove "no regression vs baseline" before it lands:
//
//   • cx.parse        — the scannerless DATA engine (cx/parser.v)
//   • cx.tokenize   — the program LEXER alone (code/lexer.v) — measures the
//                       token-array cost the unified tokenize-then-parse design
//                       adds (D-ARCH's one perf question)
//   • code.parse      — the full PROGRAM parser (tokenize + parse, no eval)
//
// All three run over the SAME bytes (the program parser is a superset that
// also parses pure data), so the numbers are directly comparable — exactly
// the head-to-head the unification cares about. Inputs the program parser
// rejects (data-only surface) are reported as REJECT, not timed.
//
// Methodology: warmup then N timed iterations, report min / median / max
// wall-clock ms + MB/s throughput off the median. Single-threaded; build with
// the patched V in -prod (see the header note) for stable numbers. Allocation
// profiling is left to the V GC
// stats path (not wired here); throughput is the N3 gate dimension.

module main

import cx
import code
import platform as _
import os
import time

const fixtures_bench = os.join_path(os.dir(@FILE), '..', '..', '..', 'fixtures', 'bench')

fn load(name string) string {
	return os.read_file(os.join_path(fixtures_bench, name)) or {
		panic('could not read fixture ${name}: ${err}')
	}
}

struct Stat {
	ok     bool
	min_ms f64
	med_ms f64
	max_ms f64
	mbps   f64
}

// time_fn runs `f` warmup+n times; `f` returns true on success. If the first
// call fails the benchmark is reported as not-ok (parser rejects the input).
fn time_fn(n int, warmup int, nbytes int, f fn () bool) Stat {
	if !f() {
		return Stat{ ok: false }
	}
	for _ in 0 .. warmup {
		f()
	}
	mut times := []f64{cap: n}
	for _ in 0 .. n {
		t0 := time.now()
		f()
		times << f64(time.since(t0).nanoseconds()) / 1_000_000.0
	}
	times.sort()
	med := times[n / 2]
	mbps := if med > 0 { (f64(nbytes) / 1_048_576.0) / (med / 1000.0) } else { 0.0 }
	return Stat{
		ok:     true
		min_ms: times[0]
		med_ms: med
		max_ms: times[times.len - 1]
		mbps:   mbps
	}
}

fn show(label string, s Stat) {
	if !s.ok {
		println('  ${label:-26s}  REJECT (parser does not accept this input)')
		return
	}
	println('  ${label:-26s}  min=${s.min_ms:8.3f}ms  med=${s.med_ms:8.3f}ms  max=${s.max_ms:8.3f}ms  ${s.mbps:8.1f} MB/s')
}

fn run_group(label string, src string, n int, warmup int) {
	println('\n── ${label}  (${src.len} bytes) ──')
	nbytes := src.len
	show('cx.parse    (data)', time_fn(n, warmup, nbytes, fn [src] () bool {
		cx.parse(src) or { return false }
		return true
	}))
	show('cx.tokenize (lexer)', time_fn(n, warmup, nbytes, fn [src] () bool {
		cx.tokenize(src) or { return false }
		return true
	}))
	show('code.parse  (program)', time_fn(n, warmup, nbytes, fn [src] () bool {
		cx.parse_program(src) or { return false }
		return true
	}))
}

// gen_program builds a representative PROGRAM input the program parser
// accepts (the data bench fixtures use data-only surface code.parse rejects).
// A mix of element-literal construction, attributes, child elements, scalar
// bodies, and a directive — repeated `n` times as top-level Program nodes.
fn gen_program(n int) string {
	mut b := []string{cap: n}
	for i in 0 .. n {
		b << "[user id=${i} name=alice [role admin] [age ${i}] [email 'a@b.com']]"
		b << '[?def f${i} (x) [* x 2]]'
	}
	return b.join('\n')
}

fn main() {
	println('cxparse perf baseline — Phase 0 (two parsers, identical inputs)')
	println('build: ${@FILE}')

	// (iterations, warmup) scaled down as inputs grow.
	run_group('small',  load('bench_small.cx'),  500, 50)
	run_group('medium', load('bench_medium.cx'), 200, 20)
	run_group('large',  load('bench_large.cx'),  100, 10)
	run_group('1mb',    load('bench_1mb.cx'),     40,  5)

	// Program-shaped inputs (code.parse accepts these; the data fixtures
	// above it rejects). Lets code.parse get a real full-parse baseline.
	run_group('program-small',  gen_program(50),   500, 50)
	run_group('program-medium', gen_program(2000), 100, 10)
	println('')
}
