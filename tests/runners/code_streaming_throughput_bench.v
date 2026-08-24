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
//   2. Constructs TWO CX programs that walk the input and produce a
//      per-record value — a `[?for … [yield …]]` comprehension and the
//      `[?map]` lane over the same records (#823; see `shapes`).
//   3. Runs each program via `code.eval_code_streaming`, feeding a
//      counter sink. Measures input-bytes-per-second AND
//      output-bytes-per-second, and counts SINK CHUNKS — a shape that
//      delivers one chunk over a 100 MiB corpus buffered its result
//      instead of streaming it, whatever it reports.
//      Every shape is threshold-bearing; the gate's verdict is the
//      conjunction over all of them.
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
import platform as _
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

// The gate drives TWO shapes over the same corpus, and both are
// threshold-bearing (#823).
//
// `[?for]` walks every record and yields it — the original shape.
//
// `[?map]` produces the SAME records through the map lane, and it is here
// because a shape that is only ever benched cannot regress quietly while a
// shape that is never benched can. `[?map]` was excluded from streaming for
// exactly that reason: its streamed path emitted `[?for]`-style items
// instead of the sequence literal one-shot renders, and gate 15 did not
// notice because gate 15 drove `[?for]` only — whose rendering is
// newline-separated on BOTH paths. The exclusion that followed was correct
// and honest, and it carried an unmeasured cost: a buffered `[?map]` holds
// the whole result, which is the 514 MiB-on-10 MB profile #822 closed. With
// the shape benched, neither the divergence nor the buffering can return
// without this gate saying so.
//
// #710 item 4: the `[?for]` program used to carry the retired pre-reshape
// slot spelling `[?for [user $u] :yield $u]` (version-literal-ok: the
// surface-reshape era) and the bench crashed at parse.
struct Shape {
	name string
	prog string
}

const shapes = [
	Shape{'for', '[?for [in \$u \$doc/user] [yield \$u]]'},
	Shape{'map', '[?map \$doc/user [using [?fn \$u \$u]]]'},
]

struct ByteCounter {
mut:
	total  int
	chunks int
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

struct Trial {
	in_bytes  int
	out_bytes int
	chunks    int
	ms        i64
}

fn run_trial(input string, program string) Trial {
	bc := &ByteCounter{ total: 0, chunks: 0 }
	sink := fn [bc] (chunk string) ! {
		unsafe {
			bc.total += chunk.len
			bc.chunks++
		}
	}
	t0 := time.now()
	code.eval_code_streaming(input, program, 'text', sink) or {
		panic('eval_code_streaming failed: ${err}')
	}
	elapsed_ms := time.since(t0).milliseconds()
	return Trial{
		in_bytes:  input.len
		out_bytes: bc.total
		chunks:    bc.chunks
		ms:        elapsed_ms
	}
}

// ShapeResult is one shape's measured outcome.
struct ShapeResult {
	name    string
	mean_in f64
	min_in  f64
	chunks  int
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

	mut results := []ShapeResult{}
	mut reasons := []string{}

	for sh in shapes {
		println('')
		println('  shape ${sh.name} : ${sh.prog}')

		// The shape MUST take the streaming path. Without this the
		// throughput rows below pass vacuously for a shape that quietly
		// buffers: a one-shot fallback still produces the right bytes, just
		// with the whole result resident. `[?map]` spent a release excluded
		// exactly here (#823), so the gate asks the same authority callers
		// ask (eval_code_stream_mode) rather than inferring from timings.
		if !code.eval_code_streamable(sh.prog, 'text') {
			reasons << '${sh.name}: NOT STREAMING — the shape fell back to the buffered path'
			println('  !! ${sh.name} reports buffered — the streaming exclusion is back (#823)')
			continue
		}

		for _ in 0 .. warmup {
			run_trial(input, sh.prog)
		}

		mut in_mbps_samples := []f64{cap: trials}
		mut out_mbps_samples := []f64{cap: trials}
		mut chunks_min := 0
		for t in 0 .. trials {
			tr := run_trial(input, sh.prog)
			in_s := mbps(tr.in_bytes, tr.ms)
			out_s := mbps(tr.out_bytes, tr.ms)
			in_mbps_samples << in_s
			out_mbps_samples << out_s
			if t == 0 || tr.chunks < chunks_min { chunks_min = tr.chunks }
			println('  trial ${t + 1}: in ${fmt_mbps(tr.in_bytes, tr.ms)}  out ${fmt_mbps(tr.out_bytes, tr.ms)}  (${tr.ms} ms, out ${tr.out_bytes} bytes, ${tr.chunks} chunks)')
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
		mean_in := sum_in / f64(trials)
		mean_out := sum_out / f64(trials)

		println('  mean input throughput  : ${mean_in:7.1f} MB/s')
		println('  mean output throughput : ${mean_out:7.1f} MB/s')
		println('  min trial input        : ${min_in:7.1f} MB/s (${(min_in / mean_in) * 100.0:5.1f}% of mean)')
		println('  min trial chunks       : ${chunks_min}')

		results << ShapeResult{
			name:    sh.name
			mean_in: mean_in
			min_in:  min_in
			chunks:  chunks_min
		}

		if mean_in < threshold_mbps {
			reasons << '${sh.name}: mean ${mean_in:.1f} < ${threshold_mbps:.0f} MB/s'
		}
		if min_in < mean_in * trial_jitter_pct {
			reasons << '${sh.name}: min trial < 80% of mean'
		}
		// A single chunk on a corpus this size IS the buffered shape:
		// the one-shot fallback delivers the entire result in one sink
		// call. The mode check above catches an honest exclusion; this
		// catches a path that CLAIMS to stream and then single-flushes.
		if chunks_min < 2 {
			reasons << '${sh.name}: delivered ${chunks_min} chunk(s) — the result was buffered, not streamed'
		}
	}

	if results.len != shapes.len {
		reasons << 'only ${results.len} of ${shapes.len} shapes were measured'
	}

	println('')
	verdict := if reasons.len == 0 { 'PASS' } else { 'FAIL' }
	reason_str := if reasons.len == 0 { 'all checks ok' } else { reasons.join('; ') }
	println('gate-15 ${verdict}  (${reason_str})')
	if verdict == 'FAIL' { exit(1) }
}
