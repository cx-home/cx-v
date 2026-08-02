module main

import os
import testenv
import time

// random_streams_test.v — #625: the implicit PRNG is one stream PER THREAD
// (spec random.md §2) and stateful generator handles (§3.7) are private
// deterministic streams. Pre-fix, one process-global Xoshiro raced across
// [?worker] threads: two workers that each seed(42)+draw interleaved on the
// shared state and produced different outputs run to run — the #625
// deterministic-generation failure.

fn rs_run(prog string) string {
	tmp := os.join_path(os.temp_dir(), 'cx-rand-${os.getpid()}-${time.now().unix_nano()}.cx')
	os.write_file(tmp, prog) or { panic(err) }
	defer {
		os.rm(tmp) or {}
	}
	res := os.execute('CX_WORKER_THREADS=4 ${testenv.cx_bin()} ${tmp}')
	return res.output.trim_space()
}

const golden_42 = '7510639304993616975' // the pinned §4.1 seed-42 first draw

fn test_worker_seed_and_draw_is_deterministic() {
	prog := "[?lib 'cx-stdlib/random' :as random]
[?let
  [= \$w1 [?worker name='w1' [?let [= \$s [\$random:seed 42]] [\$random:next-int]]]]
  [= \$w2 [?worker name='w2' [?let [= \$s [\$random:seed 42]] [\$random:next-int]]]]
  [= \$v1 [?wait-for [worker \$w1]]]
  [= \$v2 [?wait-for [worker \$w2]]]
  [out [?str '{\$v1}|{\$v2}']]]
"
	// three runs: both workers always produce the pinned value — no cross-
	// worker interleaving, no run-to-run drift.
	for i in 0 .. 3 {
		out := rs_run(prog)
		assert out.contains('${golden_42}|${golden_42}'), 'worker draw not deterministic (run ${i}): ${out}'
	}
}

fn test_worker_draws_do_not_perturb_main_stream() {
	prog := "[?lib 'cx-stdlib/random' :as random]
[?let
  [= \$s [\$random:seed 42]]
  [= \$w [?worker name='noise' [\$random:next-ints 64]]]
  [= \$sync [?wait-for [worker \$w]]]
  [out [\$random:next-int]]]
"
	out := rs_run(prog)
	assert out.contains(golden_42), 'a worker draining ITS stream must not advance the main thread stream: ${out}'
}

fn test_handle_draw_on_freed_handle_refuses() {
	prog := "[?lib 'cx-stdlib/random' :as random]
[?let
  [= \$g [\$random:new 7]]
  [= \$v [\$random:gen-int \$g]]
  [= \$f [\$random:free \$g]]
  [out [\$random:gen-int \$g]]]
"
	out := rs_run(prog)
	assert out.contains('CXER1906'), 'a draw on a freed handle must refuse with E_RANDOM_HANDLE_INVALID: ${out}'
}

fn test_handles_are_concurrency_safe_private_streams() {
	// 4 workers share ONE handle: draws serialize (no crash / no torn state)
	// and drain exactly the handle's seeded sequence — the union of the
	// workers' draws equals the single-threaded prefix of the same length.
	prog := "[?lib 'cx-stdlib/random' :as random]
[?let
  [= \$g [\$random:new 42]]
  [= \$w1 [?worker name='a' [\$random:gen-ints \$g 50]]]
  [= \$w2 [?worker name='b' [\$random:gen-ints \$g 50]]]
  [= \$r1 [?wait-for [worker \$w1]]]
  [= \$r2 [?wait-for [worker \$w2]]]
  [= \$ref [\$random:gen-ints [\$random:new 42] 100]]
  [= \$all [?for [in \$v (\$r1, \$r2)] [yield \$v]]]
  [= \$n [\$count \$all]]
  [out [?str '{\$n}|{[\$cx:equal [\$sort \$all] [\$sort \$ref]]}']]]
"
	out := rs_run(prog)
	// sorted equality is order-independent: the two workers' interleaved
	// draws drain EXACTLY the handle's seeded 100-draw prefix, partitioned —
	// no torn state, no duplicated or lost draws.
	assert out.contains('100|true'), 'concurrent draws on one handle must drain exactly its seeded sequence: ${out}'
}
