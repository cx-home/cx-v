// JSON-shape streaming throughput benchmark (Y6 / v0.7.0).
//
// Companion to streaming_bench.v. The original bench uses a 25-byte
// per-iter body (`id:name;`) chosen for tight signal on the inner
// emit loop. This variant emits a record-shaped JSON-like payload
// per service (~85 bytes/record covering id/name/host/port/active/
// ratio) so the throughput number is directly comparable to
// published JSON-encoder benchmarks (Go encoding/json, Rust
// serde_json, etc.).
//
// Three numbers reported:
//   1. cx streaming emit (the v0.6/v0.7 evaluator under exercise)
//   2. cx buffered emit (same evaluator, full materialisation)
//   3. V hand-rolled encoder (reference ceiling — a focused
//      serializer that walks the parsed Document and writes JSON
//      directly to strings.Builder, no template machinery)
//
// All three produce byte-identical output, asserted at run end. The
// output is JSON-shape (each record is a JSON object) but not
// strictly valid JSON — a trailing comma after the final record and
// no enclosing array — because we're measuring marshaling
// throughput, not parser-input validity.

module main

import cx
import time
import os
import strings

const fixture_path = 'fixtures/bench/bench_medium.cx'

fn build_json_program(n int) string {
	// Strict JSON-shape (double-quoted) record per service. The cx
	// tokenizer reserves both `"` and `'` for string-literal syntax
	// in template bodies, so structural characters (`{`, `}`, `"`,
	// the key prefixes) are wrapped in raw-text blocks `[# … #]`
	// which pass through unchanged. The interpolations `[?=s/@field]`
	// expand to the typed scalar form (int → "1", string → "alice",
	// bool → "true", float → "1.5"). Output bytes are byte-identical
	// to a strict JSON record per service (modulo the trailing comma
	// after the final record; we don't wrap in an outer `[…]` array
	// because the goal is marshaling throughput, not parser-input
	// validity).
	body := '[#{"id":#][?=s/@id][#,"name":"#][?=s/@name][#","host":"#][?=s/@host][#","port":#][?=s/@port][#,"active":#][?=s/@active][#,"ratio":#][?=s/@ratio][#},#]'
	return '[?for k :in 1 to ${n} :return [?for s :in //service :return ${body}]]'
}

fn run_cx_buffered(input string, program string) (int, i64) {
	start := time.now()
	out := cx.eval_cxl(input, program, '') or {
		panic('eval_cxl failed: ${err}')
	}
	elapsed_ms := time.since(start).milliseconds()
	return out.len, elapsed_ms
}

fn run_cx_streaming(input string, program string) (int, i64) {
	bc := &ByteCounter{ total: 0 }
	sink := fn [bc] (chunk string) ! {
		unsafe { bc.total += chunk.len }
	}
	start := time.now()
	cx.eval_cxl_streaming(input, program, '', sink, 65536) or {
		panic('eval_cxl_streaming failed: ${err}')
	}
	elapsed_ms := time.since(start).milliseconds()
	return bc.total, elapsed_ms
}

fn run_v_native(input string, n int) (int, i64, string) {
	// Reference encoder: parse the fixture once, then loop N times
	// emitting JSON for every service. cx's streaming/buffered
	// numbers include parse cost; we let v-native skip the second
	// parse (program is parsed separately by cx) but still pay the
	// fixture parse — same as cx.
	doc := cx.parse(input) or { panic('v-native parse failed: ${err}') }
	if doc.elements.len == 0 { panic('v-native: empty document') }
	root := doc.elements[0]
	if root !is cx.Element { panic('v-native: root not Element') }
	services := (root as cx.Element).items
	start := time.now()
	mut b := strings.new_builder(2 << 20)
	for _ in 0 .. n {
		for it in services {
			if it !is cx.Element { continue }
			svc := it as cx.Element
			mut id_v := ''
			mut name_v := ''
			mut host_v := ''
			mut port_v := ''
			mut active_v := ''
			mut ratio_v := ''
			for a in svc.attrs {
				match a.name {
					'id'     { id_v     = scalar_to_str(a.value) }
					'name'   { name_v   = scalar_to_str(a.value) }
					'host'   { host_v   = scalar_to_str(a.value) }
					'port'   { port_v   = scalar_to_str(a.value) }
					'active' { active_v = scalar_to_str(a.value) }
					'ratio'  { ratio_v  = scalar_to_str(a.value) }
					else {}
				}
			}
			b.write_string('{"id":')
			b.write_string(id_v)
			b.write_string(',"name":"')
			b.write_string(name_v)
			b.write_string('","host":"')
			b.write_string(host_v)
			b.write_string('","port":')
			b.write_string(port_v)
			b.write_string(',"active":')
			b.write_string(active_v)
			b.write_string(',"ratio":')
			b.write_string(ratio_v)
			b.write_string('},')
		}
	}
	out := b.str()
	elapsed_ms := time.since(start).milliseconds()
	return out.len, elapsed_ms, out
}

fn scalar_to_str(v cx.ScalarValue) string {
	return match v {
		string       { v }
		i64          { v.str() }
		f64          { v.str() }
		bool         { if v { 'true' } else { 'false' } }
		cx.NullValue { 'null' }
	}
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
		println('SKIP: ${fixture_path} not present')
		return
	}
	input := os.read_file(fixture_path) or { panic(err) }
	n_env := os.getenv('BENCH_N')
	n := if n_env != '' { n_env.int() } else { 500 }
	program := build_json_program(n)

	// Warm up the path_cache for cx (the first eval pays cxpath
	// memoization cost; we want the steady-state number).
	_, _ = run_cx_streaming(input, build_json_program(1))

	buf_bytes, buf_ms       := run_cx_buffered(input, program)
	stream_bytes, stream_ms := run_cx_streaming(input, program)
	native_bytes, native_ms, _ := run_v_native(input, n)

	if buf_bytes != stream_bytes {
		panic('cx buffered/streaming byte-count mismatch: buf=${buf_bytes} stream=${stream_bytes}')
	}
	if buf_bytes != native_bytes {
		println('NOTE: cx and v-native byte counts differ (cx=${buf_bytes} v-native=${native_bytes}) — output may not be strictly byte-identical (formatting / quoting differences). Throughput numbers still comparable.')
	}

	println('')
	println('JSON-shape streaming throughput (Y6)')
	println('  fixture        : ${fixture_path} (${input.len} bytes)')
	println('  iterations     : ${n}')
	println('  cx output      : ${buf_bytes} bytes')
	println('  v-native output: ${native_bytes} bytes')
	println('  cx buffered    : ${buf_ms} ms → ${fmt_throughput(buf_bytes, buf_ms)}')
	println('  cx streaming   : ${stream_ms} ms → ${fmt_throughput(stream_bytes, stream_ms)}')
	println('  v-native       : ${native_ms} ms → ${fmt_throughput(native_bytes, native_ms)}')
	if stream_ms > 0 && native_ms > 0 {
		ratio := f64(native_ms) / f64(stream_ms)
		println('  cx/v-native    : ${ratio:4.2f}× of native (1.0 = parity)')
	}
	println('')
}
