// cx_ast_scaling_test.v — the #941 regression guard.
//
// cx:ast was quadratic in source size (measured 2026-08-23: 3.4 KB →
// 3.1 ms, 34.9 KB → 147 ms, 354 KB → 5,178 ms; ~1670x time for 100x
// input). The mechanism was json_str (emitter_json.v): per-byte string
// `+=` on an immutable V string reallocates and copies the whole
// accumulator each step — O(n²) — and cx_mod_ast feeds it whole verbatim
// module spans via json_str_public. Fixed with a strings.Builder
// (354 KB: 5,178 ms → ~4.5 ms).
//
// This guard pins the MECHANISM at its seam: escape an S-byte and an
// 8S-byte string and assert the process-CPU ratio stays linear-ish
// (<= 24; linear ≈ 8, the old quadratic ≈ 64). Relative, never absolute
// wall time — the parse_amplification_test calibration showed absolute
// ceilings gate the machine's mood, not the algorithm; and process CPU
// via C.clock() stays honest under a parallel suite where wall does not.
// Correctness of the escaping itself is asserted alongside (the fix must
// not change one byte of output).
module main

import cx

fn C.clock() i64

fn escape_input(n int) string {
	// Realistic span content: mostly plain bytes with periodic escapes
	// (quotes, backslashes, newlines) so both match arms run.
	base := 'plain text with "quotes" and \\ backslash and\n\tcontrol\r chars '
	mut b := []u8{cap: n + base.len}
	for b.len < n {
		b << base.bytes()
	}
	return b[..n].bytestr()
}

fn cpu_of_escape(s string, reps int) i64 {
	mut best := i64(9223372036854775807)
	for _ in 0 .. reps {
		t0 := C.clock()
		out := cx.json_str_public(s)
		t1 := C.clock()
		assert out.len > s.len // escapes present → strictly longer, +2 quotes
		d := t1 - t0
		if d < best {
			best = d
		}
	}
	return best
}

fn test_json_str_scales_linearly() {
	// Byte-exactness first: the guard must not outlive a broken escape.
	assert cx.json_str_public('a"b\\c\nd\te\rf') == '"a\\"b\\\\c\\nd\\te\\rf"'
	assert cx.json_str_public('\x01') == '"\\u0001"'
	assert cx.json_str_public('') == '""'

	small := escape_input(131072) // 128 KB
	big := escape_input(1048576) // 1 MB — 8x
	// Warm both paths once before timing.
	_ := cx.json_str_public(small)
	t_small := cpu_of_escape(small, 3)
	t_big := cpu_of_escape(big, 3)
	// Guard against a zero-tick small measurement on a fast machine:
	// clock() granularity can floor tiny runs. Repeat the small input
	// enough times to register at least ~50 ticks.
	if t_small < 50 {
		mut reps_ticks := i64(0)
		t0 := C.clock()
		for _ in 0 .. 32 {
			_ := cx.json_str_public(small)
		}
		reps_ticks = C.clock() - t0
		avg := if reps_ticks > 0 { reps_ticks / 32 } else { i64(1) }
		ratio := f64(t_big) / f64(avg)
		println('json_str scaling (averaged small): 128KB=${avg} ticks 1MB=${t_big} ticks ratio=${ratio:.1f} (linear ~8, quadratic ~64)')
		assert ratio <= 24.0, 'json_str is superlinear again (#941): 8x input cost ${ratio:.1f}x CPU'
		return
	}
	ratio := f64(t_big) / f64(t_small)
	println('json_str scaling: 128KB=${t_small} ticks 1MB=${t_big} ticks ratio=${ratio:.1f} (linear ~8, quadratic ~64)')
	assert ratio <= 24.0, 'json_str is superlinear again (#941): 8x input cost ${ratio:.1f}x CPU'
}
