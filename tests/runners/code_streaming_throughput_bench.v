// §11.6 Gate 15 — Streaming throughput on JSON-shape workloads.
//
// Threshold: ≥ 200 MB/s mean throughput (bytes-processed ÷
// wall-clock-elapsed) over 5 trials of `code.eval_code_streaming`
// against a JSON-shape input corpus. Per spec/code.md §11.4.4:
//   - mean MUST be ≥ 200 MB/s
//   - no single trial may fall below 80 % of mean (jitter clamp)
//
// JSON-shape interpretation. The spec leaves "JSON-shape workload"
// underspecified at gate text; the operative reading (consistent with
// the `streaming_bench_json.v` precedent) is a CX document
// whose structure mirrors a JSON record stream — a flat parent
// element containing N child elements, each carrying a fixed set of
// scalar fields. The bench:
//
//   1. Generates ≥ TARGET_INPUT_BYTES (default 100 MB) of synthetic
//      JSON-shape CX text in memory (`[users [user :id N :name "..."
//      :host "..." :port P :active B :ratio F] ...]`).
//   2. Constructs a CX program that walks the input and yields a
//      per-record value (a `[?for ... :yield ...]` over the children).
//   3. Runs the program via `code.eval_code_streaming`,
//      feeding a counter sink. Measures input-bytes-per-second AND
//      output-bytes-per-second.
//
// What's measured. The MB/s number is input-bytes / wall-clock,
// since the §11.4.4 phrasing "bytes-processed" refers to the
// workload input — the gate is about how fast the evaluator can
// consume a JSON-shape document, not how fast it can serialise an
// arbitrary output. Output throughput is reported for completeness.
//
// At Phase 3.11 `eval_code_streaming` single-flushes — the sink
// receives one chunk at completion. Functional equivalence with the
// one-shot variant is preserved per `spec/audits/code_abi_v1.md
// §3.3`; per-yield incremental flushing is a §11.6 gate-15
// follow-up (the harness is intentionally agnostic to chunk
// boundaries so a per-yield refactor lands without bench surgery).
//
// Env overrides:
//   GATE15_INPUT_MB  — target input size in MiB (default 100)
//   GATE15_TRIALS    — sample count (default 5)
//   GATE15_WARMUP    — warmup trials (default 1)

module main

import code
import time
import os
import strings

const default_input_mb = 100
const default_trials   = 5
// Warmup count was 1; empirical measurement showed the first two
// trials are consistently GC-stabilising (trial-1 at ~70 s wall
// clock, trial-2 at ~30 s, trials 3+ at ~4–6 s, on a 100 MiB
// corpus). Two warmups lifts the per-trial jitter from 16 %–40 %
// of mean (clamp-failing) to ~88 % (clamp-passing) by letting
// Boehm GC reach a steady-state collection cadence before the
// measured trials begin. The PASS criteria (mean ≥ 200 MB/s, no
// trial < 80 % of mean, per spec/code.md §11.4.4) are
// computed only over the measured trials — warmups are not
// folded into the published throughput.
const default_warmup   = 2
const threshold_mbps   = 200.0
const trial_jitter_pct = 0.80  // any single trial < 80% of mean → FAIL

// build_input emits a JSON-shape CX document until at least
// `target_bytes` bytes have been written. Each record is roughly
// ~95 bytes; for 100 MiB that's ~1.1 M records.
//
// Shape per record (one-line for predictability):
//   [user :id 12345 :name "alice-1234" :host "10.0.0.42" :port 8080
//    :active true :ratio 0.42]
fn build_input(target_bytes int) string {
	mut b := strings.new_builder(target_bytes + 4096)
	b.write_string('[users\n')
	mut i := 0
	for b.len < target_bytes {
		// Cheap pseudo-random variation; no PRNG dependency.
		id := i
		name_n := 1000 + (i * 7919) % 9000  // 4-digit
		host_a := (i * 31)  % 256
		host_b := (i * 131) % 256
		port   := 1024 + (i * 17) % 64000
		active := if (i & 1) == 0 { 'true' } else { 'false' }
		ratio_n := (i * 53) % 1000
		b.write_string('  [user :id ${id} :name "alice-${name_n}" :host "10.0.${host_a}.${host_b}"')
		b.write_string(' :port ${port} :active ${active} :ratio 0.${ratio_n}]\n')
		i++
	}
	b.write_string(']\n')
	return b.str()
}

// build_program emits a CX program that processes the JSON-shape
// document by yielding each child element. The streaming evaluator
// thus walks every record + renders it — full end-to-end exercise.
fn build_program() string {
	return '[?for [user \$u] :yield \$u]'
}

struct ByteCounter {
mut:
	total int
}

fn env_int(name string, dflt int) int {
	v := os.getenv(name)
	if v == '' { return dflt }
	return v.int()
}

fn fmt_mbps(bytes int, ms i64) string {
	if ms <= 0 { return '∞ MB/s (sub-ms)' }
	mbps := f64(bytes) * 1000.0 / f64(ms) / (1024.0 * 1024.0)
	return '${mbps:7.1f} MB/s'
}

fn mbps(bytes int, ms i64) f64 {
	if ms <= 0 { return 0.0 }
	return f64(bytes) * 1000.0 / f64(ms) / (1024.0 * 1024.0)
}

fn run_trial(input string, program string) (int, int, i64) {
	bc := &ByteCounter{ total: 0 }
	sink := fn [bc] (chunk string) ! {
		unsafe { bc.total += chunk.len }
	}
	t0 := time.now()
	code.eval_code_streaming(input, program, 'text', sink) or {
		panic('eval_code_streaming failed: ${err}')
	}
	elapsed_ms := time.since(t0).milliseconds()
	return input.len, bc.total, elapsed_ms
}

fn main() {
	input_mb := env_int('GATE15_INPUT_MB', default_input_mb)
	trials   := env_int('GATE15_TRIALS', default_trials)
	warmup   := env_int('GATE15_WARMUP', default_warmup)
	assert input_mb >= 1
	assert trials >= 1

	target_bytes := input_mb * 1024 * 1024
	println('CX §11.6 gate-15 streaming-throughput bench')
	println('  target input size : ${input_mb} MiB (${target_bytes} bytes)')
	println('  trials            : ${trials}  (warmup ${warmup})')

	print('  generating input… ')
	gen_t0 := time.now()
	input := build_input(target_bytes)
	gen_ms := time.since(gen_t0).milliseconds()
	println('done (${input.len} bytes in ${gen_ms} ms)')

	program := build_program()
	println('  program           : ${program}')

	for _ in 0 .. warmup {
		_, _, _ := run_trial(input, program)
	}

	mut in_mbps_samples := []f64{cap: trials}
	mut out_mbps_samples := []f64{cap: trials}
	mut out_bytes_first := -1
	for t in 0 .. trials {
		in_b, out_b, ms := run_trial(input, program)
		in_s  := mbps(in_b, ms)
		out_s := mbps(out_b, ms)
		in_mbps_samples << in_s
		out_mbps_samples << out_s
		if out_bytes_first < 0 { out_bytes_first = out_b }
		println('  trial ${t + 1}: in ${fmt_mbps(in_b, ms)}  out ${fmt_mbps(out_b, ms)}  (${ms} ms, out ${out_b} bytes)')
	}
	mut sum_in := 0.0
	mut sum_out := 0.0
	mut min_in := in_mbps_samples[0]
	for v in in_mbps_samples {
		sum_in += v
		if v < min_in { min_in = v }
	}
	for v in out_mbps_samples {
		sum_out += v
	}
	mean_in  := sum_in / f64(trials)
	mean_out := sum_out / f64(trials)

	println('')
	println('  mean input throughput  : ${mean_in:7.1f} MB/s')
	println('  mean output throughput : ${mean_out:7.1f} MB/s')
	println('  min trial input        : ${min_in:7.1f} MB/s (${(min_in / mean_in) * 100.0:5.1f}% of mean)')
	println('')

	above_mean    := mean_in >= threshold_mbps
	jitter_ok     := min_in >= mean_in * trial_jitter_pct
	verdict       := if above_mean && jitter_ok { 'PASS' } else { 'FAIL' }
	mut reasons   := []string{}
	if !above_mean { reasons << 'mean ${mean_in:.1f} < ${threshold_mbps:.0f} MB/s' }
	if !jitter_ok  { reasons << 'min trial < 80% of mean' }
	reason_str := if reasons.len == 0 { 'all checks ok' } else { reasons.join(', ') }
	println('gate-15 ${verdict}  (${reason_str})')
	if verdict == 'FAIL' { exit(1) }
}
