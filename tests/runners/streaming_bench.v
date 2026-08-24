// Streaming evaluator throughput benchmark (Y6).
//
// Standalone runnable benchmark — `make bench-streaming` (or `v run`).
// Measures the streaming-mode evaluator's sustained emit throughput
// for a representative `?for`-over-large-sequence workload. Buffered
// eval_code (buffered) is included as a reference point; the streaming path's
// win comes from not materialising the full output buffer when the
// sink absorbs chunks as they arrive.
//
// CI integration (>10% regression gate) lives in T7 / V7. This file
// is the per-arc measurement tool, not a CI test.

module main

import code
import platform as _
import time
import os

const fixture_path = 'fixtures/bench/bench_medium.cx'

fn build_program(n int) string {
	// Iterate $doc//service N times, emitting a small value per
	// iteration. We wrap in an outer ?for over a range to amplify
	// without growing the input fixture. (#710 item 4, I5-s17 W6: the
	// retired `:in 1 to N :return` + `[?=…]` interpolation spellings
	// crashed at parse; current forms per conformance/code.cxd.)
	return '[?for [in \$k [\$range 1 ${n}]] [yield [?for [in \$s \$doc//service] [yield (\$s@id, \$s@name)]]]]'
}

fn run_buffered(input string, program string) (int, i64) {
	start := time.now()
	out := code.eval_code(input, program, '') or {
		panic('eval_code failed: ${err}')
	}
	elapsed_ms := time.since(start).milliseconds()
	return out.len, elapsed_ms
}

fn run_streaming(input string, program string) (int, i64) {
	bc := &ByteCounter{ total: 0 }
	sink := fn [bc] (chunk string) ! {
		unsafe { bc.total += chunk.len }
	}
	start := time.now()
	// Use a realistic chunk-batching threshold (64 KiB). Setting this
	// to 0 forces a flush every iteration, which dominates the wall
	// time with sink-callback overhead — bench measures evaluator
	// throughput, not the sink's per-call cost. Production callers
	// invariably want bigger chunks anyway (write(2) syscall amortisation,
	// network MTU alignment, less per-callback allocator pressure).
	// 64 KiB is the typical pipe-buffer / page-cluster size on macOS+Linux.
	code.eval_code_streaming(input, program, '', sink) or {
		panic('eval_code_streaming failed: ${err}')
	}
	elapsed_ms := time.since(start).milliseconds()
	return bc.total, elapsed_ms
}

struct ByteCounter {
mut:
	total int
}

fn fmt_throughput(bytes int, ms i64) string {
	if ms == 0 { return '∞ MB/s (sub-ms)' }
	mb_per_s := f64(bytes) * 1000.0 / f64(ms) / (1024.0 * 1024.0)
	return '${mb_per_s:6.1f} MB/s'
}

fn main() {
	if !os.exists(fixture_path) {
		println('SKIP: ${fixture_path} not present; run `make bench-fixtures` first')
		return
	}
	input := os.read_file(fixture_path) or {
		panic('cannot read ${fixture_path}: ${err}')
	}
	// 500 iterations × ~300 services in the medium fixture ≈ 150k
	// emit units; runs in a few seconds on a recent laptop.
	n_env := os.getenv('BENCH_N')
	n := if n_env != '' { n_env.int() } else { 500 }
	program := build_program(n)

	buf_bytes, buf_ms := run_buffered(input, program)
	stream_bytes, stream_ms := run_streaming(input, program)

	// Sanity: both paths must emit the same number of bytes.
	if buf_bytes != stream_bytes {
		panic('buffered/streaming byte-count mismatch: buf=${buf_bytes} stream=${stream_bytes}')
	}

	println('')
	println('Streaming evaluator throughput (Y6)')
	println('  fixture        : ${fixture_path} (${input.len} bytes)')
	println('  iterations     : ${n}')
	println('  output bytes   : ${buf_bytes}')
	println('  buffered       : ${buf_ms} ms → ${fmt_throughput(buf_bytes, buf_ms)}')
	println('  streaming      : ${stream_ms} ms → ${fmt_throughput(stream_bytes, stream_ms)}')
	speedup_str := if buf_ms == 0 || stream_ms == 0 {
		'(sub-ms, ratio unreliable)'
	} else {
		'(${f64(buf_ms) / f64(stream_ms):4.2f}× speedup)'
	}
	println('  comparison     : ${speedup_str}')
	println('')
}
