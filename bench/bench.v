module main

import cx
import os
import time
import x.json2

// ── fixture loader ─────────────────────────────────────────────────────────────

const fixtures_bench = os.join_path(os.dir(@FILE), '..', '..', 'fixtures', 'bench')

fn load(name string) string {
	return os.read_file(os.join_path(fixtures_bench, name)) or {
		panic('could not read fixture ${name}: ${err}')
	}
}

// ── timer ──────────────────────────────────────────────────────────────────────

fn bench(name string, n int, warmup int, f fn()) {
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
	mn  := times[0]
	med := times[n / 2]
	mx  := times[times.len - 1]
	println('  ${name:-32s}  min=${mn:7.3f}ms  med=${med:7.3f}ms  max=${mx:7.3f}ms')
}

// ── benchmark groups ───────────────────────────────────────────────────────────

fn run_group(label string, cx_str string) {
	println('\n── ${label} (${cx_str.len} bytes) ──')

	// Document API
	bench('parse (CX → Document)',      200, 20, fn [cx_str]() {
		_ := cx.parse(cx_str) or { panic(err) }
	})
	bench('to_cx (CX → CX round-trip)', 200, 20, fn [cx_str]() {
		_ := cx.to_cx(cx_str) or { panic(err) }
	})

	// Streaming
	bench('stream (CX → all events)',   200, 20, fn [cx_str]() {
		mut s := cx.new_stream(cx_str) or { panic(err) }
		_ = s.collect()
	})

	// Format conversion
	bench('to_json (CX → JSON)',        200, 20, fn [cx_str]() {
		_ := cx.to_json(cx_str) or { panic(err) }
	})
	bench('to_xml  (CX → XML)',         200, 20, fn [cx_str]() {
		_ := cx.to_xml(cx_str) or { panic(err) }
	})
	bench('to_yaml (CX → YAML)',        200, 20, fn [cx_str]() {
		_ := cx.to_yaml(cx_str) or { panic(err) }
	})
	bench('to_toml (CX → TOML)',        200, 20, fn [cx_str]() {
		_ := cx.to_toml(cx_str) or { panic(err) }
	})

	// Data binding
	bench('loads   (CX → native any)',  200, 20, fn [cx_str]() {
		json_out := cx.to_json(cx_str) or { panic(err) }
		_ := json2.decode[json2.Any](json_out) or { panic(err) }
	})
	json_str := cx.to_json(cx_str) or { panic('to_json failed') }
	bench('dumps   (JSON → CX)',        200, 20, fn [json_str]() {
		_ := cx.convert(json_str, .json, .cx) or { panic(err) }
	})

	// Reverse conversion
	xml_str := cx.to_xml(cx_str) or { panic('to_xml failed') }
	bench('xml→cx  (XML → CX)',         200, 20, fn [xml_str]() {
		_ := cx.from_xml(xml_str) or { panic(err) }
	})
}

fn main() {
	println('CX V benchmark')

	small  := load('bench_small.cx')
	medium := load('bench_medium.cx')
	large  := load('bench_large.cx')

	run_group('small  (20 services)',   small)
	run_group('medium (200 services)',  medium)
	run_group('large  (2000 services)', large)

	println('')
}
