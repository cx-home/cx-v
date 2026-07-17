module main

import os
import testenv
import runtime

// par_for_test.v — #94 Stage 2: real for-par. `[?for … [par]]` (a sequential
// no-op before) now runs the OUTERMOST generator across a bounded worker pool:
// correct results, [ordered] reassembles source order, the peak-worker counter
// proves min(W,n) concurrency, and order/position-dependent shapes
// (takewhile/dropwhile, $_position) safely fall back to the sequential walk.

fn cx_bin_pf() string {
	return testenv.cx_bin()
}

fn run_pf(src string, peak bool) os.Result {
	f := os.join_path(os.temp_dir(), 'cx_pf_${os.getpid()}_${src.len}.cx')
	os.write_file(f, src) or { panic('write: ${err}') }
	defer { os.rm(f) or {} }
	pre := if peak { 'CX_PAR_PEAK=1 ' } else { '' }
	return os.execute('${pre}${cx_bin_pf()} --allow-all ${f}')
}

fn default_width_pf() int {
	ncpu := runtime.nr_cpus()
	w := if ncpu < 4 { ncpu } else { 4 }
	return if w < 1 { 1 } else { w }
}

fn peak_of_pf(out string) int {
	for line in out.split('\n') {
		if line.contains('cx-par-peak:') {
			i := line.index('peak=') or { continue }
			return line[i + 5..].trim_space().int()
		}
	}
	return -1
}

// normalize whitespace so multi-line emit compares stably.
fn flat(s string) string {
	return s.split_any(' \n\t').filter(it != '').join(' ')
}

// ── ordered for-par == sequential (determinism) ──────────────────────────────

fn test_for_par_ordered_equals_sequential() {
	par := run_pf('[?for [in \$x (1,2,3,4,5)] [yield [* \$x \$x]] [par] [ordered]]', false)
	seq := run_pf('[?for [in \$x (1,2,3,4,5)] [yield [* \$x \$x]]]', false)
	assert par.exit_code == 0 && seq.exit_code == 0, 'errored: ${par.output} / ${seq.output}'
	assert flat(par.output) == flat(seq.output), 'par-ordered != sequential:\n  ${par.output}\n  ${seq.output}'
	assert flat(par.output) == '1 4 9 16 25', 'wrong result: ${par.output}'
}

fn test_for_par_where_filter_ordered() {
	r := run_pf('[?for [in \$x (1,2,3,4,5)] [where [> \$x 2]] [yield [n \$x]] [par] [ordered]]',
		false)
	assert r.exit_code == 0, 'errored: ${r.output}'
	assert flat(r.output) == '[n 3] [n 4] [n 5]', 'wrong filtered result: ${r.output}'
}

fn test_for_par_take_post_applied() {
	// take is post-applied to the assembled (ordered) list.
	r := run_pf('[?for [in \$x (1,2,3,4,5)] [yield [* \$x \$x]] [take 2] [par] [ordered]]', false)
	assert r.exit_code == 0, 'errored: ${r.output}'
	assert flat(r.output) == '1 4', 'take under par wrong: ${r.output}'
}

// ── unordered for-par preserves the multiset ─────────────────────────────────

fn test_for_par_unordered_multiset() {
	r := run_pf('[?for [in \$x (1,2,3,4,5,6)] [yield \$x] [par 2]]', false)
	assert r.exit_code == 0, 'errored: ${r.output}'
	got := flat(r.output).split(' ').map(it.int())
	mut sum := 0
	for v in got {
		sum += v
	}
	assert got.len == 6, 'expected 6 items, got: ${r.output}'
	assert sum == 21, 'multiset not preserved (sum != 21): ${r.output}'
}

// ── §5 peak-worker proof for the for path ────────────────────────────────────

fn test_for_par_peak_equals_min_width_n() {
	r := run_pf('[?for [in \$x (1,2,3,4,5,6,7,8)] [yield [?let [= \$_ [?sleep 80ms]] [n \$x]]] [par 4] [ordered]]',
		true)
	assert r.exit_code == 0, 'errored: ${r.output}'
	assert peak_of_pf(r.output) == 4, 'expected for peak=4, got: ${r.output}'
}

fn test_for_par_peak_default_width() {
	want := default_width_pf()
	r := run_pf('[?for [in \$x (1,2,3,4,5,6,7,8,9,10)] [yield [?let [= \$_ [?sleep 80ms]] [n \$x]]] [par]]',
		true)
	assert r.exit_code == 0, 'errored: ${r.output}'
	assert peak_of_pf(r.output) == want, 'expected for peak=${want}, got: ${r.output}'
}

// ── safe sequential fallbacks (correctness over parallelism) ─────────────────

fn test_for_par_position_falls_back_sequential() {
	// $_position is order-dependent → sequential fallback with correct indices.
	r := run_pf('[?for [in \$x (10,20,30)] [yield [p pos=\$_position v=\$x]] [par]]', false)
	assert r.exit_code == 0, 'errored: ${r.output}'
	assert flat(r.output) == '[p pos=1 v=10] [p pos=2 v=20] [p pos=3 v=30]', 'position fallback wrong: ${r.output}'
}

fn test_for_par_takewhile_falls_back_sequential() {
	r := run_pf('[?for [in \$x (1,2,3,4,5)] [takewhile [< \$x 4]] [yield \$x] [par]]', false)
	assert r.exit_code == 0, 'errored: ${r.output}'
	assert flat(r.output) == '1 2 3', 'takewhile fallback wrong: ${r.output}'
}

// ── multi-source: outermost generator parallel, inner sequential ─────────────

fn test_for_par_multi_source_ordered() {
	r := run_pf('[?for [in \$a (1,2)] [in \$b (10,20)] [yield [p a=\$a b=\$b]] [par] [ordered]]',
		false)
	assert r.exit_code == 0, 'errored: ${r.output}'
	assert flat(r.output) == '[p a=1 b=10] [p a=1 b=20] [p a=2 b=10] [p a=2 b=20]', 'multi-source order wrong: ${r.output}'
}
