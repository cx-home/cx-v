module main

import os
import testenv
import runtime

// par_width_test.v — #94 [par] redesign, Stage 1: `[par]` owns its width
// (`[par]` / `[par N]` / `[par max]`), map/reduce run a BOUNDED worker pool of
// that width, invalid widths fail loud, and the bound is proven by the
// instrumented peak-worker counter (the authoritative §5 gate, not wall-clock).

fn cx_bin_pw() string {
	return testenv.cx_bin()
}

fn run_pw(src string, env_peak bool) os.Result {
	f := os.join_path(os.temp_dir(), 'cx_pw_${os.getpid()}_${src.len}.cx')
	os.write_file(f, src) or { panic('write: ${err}') }
	defer { os.rm(f) or {} }
	prefix := if env_peak { 'CX_PAR_PEAK=1 ' } else { '' }
	return os.execute('${prefix}${cx_bin_pw()} --allow-all ${f}')
}

fn default_width() int {
	ncpu := runtime.nr_cpus()
	w := if ncpu < 4 { ncpu } else { 4 }
	return if w < 1 { 1 } else { w }
}

// parse `peak=N` out of the `cx-par-peak: …` instrumentation line.
fn peak_of(out string) int {
	for line in out.split('\n') {
		if line.contains('cx-par-peak:') {
			i := line.index('peak=') or { continue }
			return line[i + 5..].trim_space().int()
		}
	}
	return -1
}

// ── §4 invalid-width edges — all must error ──────────────────────────────────

fn test_map_invalid_widths_error() {
	cases := {
		'0':         'CXER0100'
		'-3':        'CXER0100'
		'1.5':       'CXER0100'
		'foo':       'CXER0100'
		'100000000': 'CXER0153' // > 64×ncpu → fail-loud cap
	}
	for w, code in cases {
		r := run_pw('[?map (1,2,3) [using [?fn \$x \$x]] [par ${w}]]', false)
		assert r.exit_code != 0, '[par ${w}] should error, got: ${r.output}'
		assert r.output.contains(code), '[par ${w}] expected ${code}, got: ${r.output}'
	}
}

fn test_for_clause_invalid_widths_fail_loud() {
	// A bad width inside `[?for … [par …]]` is program intent — it must fail
	// loud (CXER0100), not silently data-fall-back to a data echo (#18 class).
	for w in ['0', 'foo', '8 9', '1.5'] {
		r := run_pw('[?for [in \$x (1,2,3)] [yield \$x] [par ${w}]]', false)
		assert r.exit_code != 0, 'for [par ${w}] should fail loud, got: ${r.output}'
		assert r.output.contains('CXER0100'), 'for [par ${w}] expected CXER0100, got: ${r.output}'
		assert !r.output.contains('[?for'), 'for [par ${w}] data-fell-back (echoed program): ${r.output}'
	}
}

// ── valid width forms parse + evaluate (results are width-independent) ────────

fn test_map_width_forms_results_unchanged() {
	for clause in ['[par]', '[par 1]', '[par 2]', '[par max]'] {
		r := run_pw('[?map (1,2,3,4) [using [?fn \$x [* \$x \$x]]] ${clause} [ordered]]', false)
		assert r.exit_code == 0, '${clause} errored: ${r.output}'
		assert r.output.trim_space() == '(1, 4, 9, 16)', '${clause} wrong result: ${r.output}'
	}
}

fn test_reduce_width_forms_results_unchanged() {
	for clause in ['[par]', '[par 1]', '[par 3]', '[par max]'] {
		r := run_pw('[?reduce (1,2,3,4,5,6,7,8) [using [?fn (\$a \$b) [+ \$a \$b]]] [init 0] ${clause}]',
			false)
		assert r.exit_code == 0, 'reduce ${clause} errored: ${r.output}'
		assert r.output.trim_space() == '36', 'reduce ${clause} wrong result: ${r.output}'
	}
}

// ── §5 peak-worker proof (the authoritative parallelism gate) ────────────────
//
// A real `[?sleep]` body opens a window in which all min(W,n) workers are
// simultaneously in-flight; the COUNTER (not the timing) is the assertion.

fn test_map_peak_equals_min_width_n() {
	// 8 items, [par 4] → exactly 4 concurrent.
	r := run_pw('[?map (1,2,3,4,5,6,7,8) [using [?fn \$x [?let [= \$_ [?sleep 80ms]] [* \$x \$x]]]] [par 4] [ordered]]',
		true)
	assert r.exit_code == 0, 'peak map errored: ${r.output}'
	assert peak_of(r.output) == 4, 'expected peak=4 (min(4,8)), got: ${r.output}'
}

fn test_map_peak_respects_smaller_width() {
	r := run_pw('[?map (1,2,3,4,5,6,7,8) [using [?fn \$x [?let [= \$_ [?sleep 80ms]] [* \$x \$x]]]] [par 2] [ordered]]',
		true)
	assert r.exit_code == 0, 'peak map errored: ${r.output}'
	assert peak_of(r.output) == 2, 'expected peak=2, got: ${r.output}'
}

fn test_map_peak_capped_by_item_count() {
	// 3 items, [par 8] → peak == min(8,3) == 3 (never more workers than items).
	r := run_pw('[?map (1,2,3) [using [?fn \$x [?let [= \$_ [?sleep 80ms]] [* \$x \$x]]]] [par 8] [ordered]]',
		true)
	assert r.exit_code == 0, 'peak map errored: ${r.output}'
	assert peak_of(r.output) == 3, 'expected peak=3 (min(8,3)), got: ${r.output}'
}

fn test_map_peak_default_width() {
	// bare [par] → default min(4,ncpu).
	want := default_width()
	r := run_pw('[?map (1,2,3,4,5,6,7,8,9,10) [using [?fn \$x [?let [= \$_ [?sleep 80ms]] [* \$x \$x]]]] [par] [ordered]]',
		true)
	assert r.exit_code == 0, 'peak map errored: ${r.output}'
	assert peak_of(r.output) == want, 'expected peak=${want} (default), got: ${r.output}'
}

fn test_reduce_peak_equals_width() {
	r := run_pw('[?reduce (1,2,3,4,5,6,7,8) [using [?fn (\$a \$b) [?let [= \$_ [?sleep 80ms]] [+ \$a \$b]]]] [init 0] [par 4]]',
		true)
	assert r.exit_code == 0, 'peak reduce errored: ${r.output}'
	assert peak_of(r.output) == 4, 'expected reduce peak=4, got: ${r.output}'
}

// ── HTTP worker count shares the fail-loud cap (#94 §2) ──────────────────────

fn test_http_workers_over_cap_fails_loud() {
	// HTTP worker count over 64×ncpu must raise CXER0153 (no silent 256 clamp).
	// #97: CX_HTTP_N is the primary name; CX_HTTP_WORKERS is a deprecated alias.
	f := os.join_path(os.temp_dir(), 'cx_pw_serve_${os.getpid()}.cx')
	os.write_file(f, "[?lib 'cx-stdlib/http' :as http]
[?def h impure (\$req) [response status=200 [body \"hi\"]]]
[\$http:serve \"tcp://127.0.0.1:0\" \$h {block: true}]
") or { panic('write: ${err}') }
	defer { os.rm(f) or {} }
	// New name CX_HTTP_N: over-cap fails loud, naming the new var.
	rn := os.execute('CX_HTTP_N=100000000 ${cx_bin_pw()} --allow-all ${f}')
	assert rn.output.contains('CXER0153'), 'over-cap CX_HTTP_N should fail loud (CXER0153), got: ${rn.output}'
	assert rn.output.contains('CX_HTTP_N=100000000'), 'error should name CX_HTTP_N, got: ${rn.output}'
	// Deprecated alias CX_HTTP_WORKERS still honored, with a deprecation warning.
	ra := os.execute('CX_HTTP_WORKERS=100000000 ${cx_bin_pw()} --allow-all ${f}')
	assert ra.output.contains('CXER0153'), 'alias CX_HTTP_WORKERS should still be honored, got: ${ra.output}'
	assert ra.output.contains('deprecated'), 'alias CX_HTTP_WORKERS should warn deprecated, got: ${ra.output}'
}
