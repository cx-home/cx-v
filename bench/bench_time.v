module main

import cx
import os
import time

fn main() {
	base := os.join_path(os.dir(@FILE), '..', '..', 'fixtures', 'bench')
	medium := os.read_file(os.join_path(base, 'bench_medium.cx')) or { panic(err) }

	parse_med := time_median(100, 20, fn [medium]() {
		_ := cx.parse(medium) or { panic(err) }
	})
	stream_med := time_median(100, 20, fn [medium]() {
		mut s := cx.new_stream(medium) or { panic(err) }
		_ = s.collect()
	})

	println('parse=${parse_med:.3f} stream=${stream_med:.3f}')
}

fn time_median(n int, warmup int, f fn()) f64 {
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
	return times[n / 2]
}
