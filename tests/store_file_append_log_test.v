module main

import os
import testenv
import time

// store_file_append_log_test.v — #74 Defect 1: the file:// backend persists via
// an APPEND-ONLY log (one record per mutation) instead of rewriting the entire
// index on every put-doc/set-alias (the O(n) per-op → O(n^2)-total cost that
// made file:// unusable past a few thousand keys). These tests pin the
// behavioral contract that makes the append log safe:
//   1. the log replays identically across a reopen (separate process),
//   2. alias updates are last-write-wins and the log COMPACTS (does not grow
//      unboundedly with redundant records),
//   3. many keyed writes reopen with the full set intact (and complete fast —
//      a soft tripwire against an O(n^2) regression).

fn cx_bin_sfa() string {
	return testenv.cx_bin()
}

fn run_prog(src string) os.Result {
	f := os.join_path(os.temp_dir(), 'cx_sfa_${os.getpid()}_${src.len}.cx')
	os.write_file(f, src) or { panic('write: ${err}') }
	defer { os.rm(f) or {} }
	return os.execute('${cx_bin_sfa()} --allow-all ${f}')
}

fn store_dir(label string) string {
	d := os.join_path(os.temp_dir(), 'cx_sfa_store_${label}_${os.getpid()}')
	os.rmdir_all(d) or {}
	return d
}

// 1. The append log replays across a reopen in a SEPARATE process.
fn test_append_log_roundtrips_across_reopen() {
	dir := store_dir('roundtrip')
	defer { os.rmdir_all(dir) or {} }
	w := run_prog("[?lib 'cx-stdlib/store']
[?let [= \$s [\$store:open \"document+file://${dir}\"]]
  [?let [= \$h1 [\$store:put-doc \$s [doc [v 1]]]]
   [?let [= \$h2 [\$store:put-doc \$s [doc [v 2]]]]
    [?let [= \$_a [\$store:set-alias \$s \"one\" \$h1]]
     [?let [= \$_b [\$store:set-alias \$s \"two\" \$h2]] :wrote]]]]]
")
	assert w.exit_code == 0, 'write failed: ${w.output}'

	// The fetched documents are ELEMENTS, so they ride in child position —
	// attributes are strictly scalar (code.md §6.4.1; #466/#268 ruling).
	r := run_prog("[?lib 'cx-stdlib/store']
[?let [= \$s [\$store:open \"document+file://${dir}\"]]
  [results
    [one [\$store:get-doc \$s [\$store:get-alias \$s \"one\"]]]
    [two [\$store:get-doc \$s [\$store:get-alias \$s \"two\"]]]
    ndocs=[\$count [\$store:list-docs \$s]]]]
")
	assert r.exit_code == 0, 'reopen read failed: ${r.output}'
	assert r.output.contains('[one [doc [v 1]]]'), 'alias one lost across reopen: ${r.output}'
	assert r.output.contains('[two [doc [v 2]]]'), 'alias two lost across reopen: ${r.output}'
	assert r.output.contains('ndocs=2'), 'doc count wrong after reopen: ${r.output}'
}

// 2. Repeated alias updates are last-write-wins after reopen, and the on-disk
//    log COMPACTS — its size stays bounded, not ~one-record-per-update.
fn test_alias_updates_last_write_wins_and_compact() {
	dir := store_dir('compact')
	defer { os.rmdir_all(dir) or {} }
	w := run_prog("[?lib 'cx-stdlib/store']
[?let [= \$s [\$store:open \"document+file://${dir}\"]]
  [?let [= \$h1 [\$store:put-doc \$s [doc [n 1]]]]
   [?let [= \$h2 [\$store:put-doc \$s [doc [n 2]]]]
    [?reduce [\$range 1 500] [using [?fn (\$a \$i)
      [?let [= \$_ [\$store:set-alias \$s \"k\" [?if [> \$i 250] [then \$h2] [else \$h1]]]] [+ \$a 1]]]] [init 0]]]]]
")
	assert w.exit_code == 0, 'update run failed: ${w.output}'

	// Element-valued field in child position (attrs are scalar-only, §6.4.1).
	r := run_prog("[?lib 'cx-stdlib/store']
[?let [= \$s [\$store:open \"document+file://${dir}\"]]
  [final [k [\$store:get-doc \$s [\$store:get-alias \$s \"k\"]]] naliases=[\$count [\$store:list-aliases \$s]]]]
")
	assert r.exit_code == 0, 'reopen after updates failed: ${r.output}'
	assert r.output.contains('[k [doc [n 2]]]'), 'alias update not last-write-wins: ${r.output}'
	assert r.output.contains('naliases=1'), 'expected exactly 1 alias: ${r.output}'

	// Compaction guard: 500 updates to one alias must NOT leave 500 records on
	// disk. A compacted index holds ~2 docs + 1 alias (a few hundred bytes);
	// an uncompacted append log would be many KB. Generous ceiling.
	idx := os.join_path(dir, '.cxstore-index')
	assert os.is_file(idx), 'index file missing: ${idx}'
	sz := os.file_size(idx)
	assert sz < 4096, 'append log did not compact — index is ${sz} bytes after 500 alias updates'
}

// 3. Many unique keyed writes reopen with the full set intact, and complete
//    promptly — a soft tripwire against a return to the O(n^2) full-rewrite.
fn test_many_keyed_writes_reopen_intact() {
	dir := store_dir('scale')
	defer { os.rmdir_all(dir) or {} }
	sw := time.now()
	w := run_prog("[?lib 'cx-stdlib/store']
[?let [= \$s [\$store:open \"document+file://${dir}\"]]
  [?reduce [\$range 1 8000] [using [?fn (\$a \$i)
    [?let [= \$h [\$store:put-doc \$s [doc [v \$i]]]]
      [?let [= \$x [\$store:set-alias \$s [?str \"k{\$i}\"] \$h]] [+ \$a 1]]]]] [init 0]]]
")
	elapsed_ms := f64(time.now() - sw) / f64(time.millisecond)
	assert w.exit_code == 0, '8000 keyed writes failed: ${w.output}'
	// This is the fail-before/pass-after guard for the append-log fix. With the
	// old full-index-rewrite-per-op (O(n^2)) 8000 keyed writes did not complete
	// in tens of seconds (the issue reported >120s); the append log makes it
	// O(n) (sub-second). 30s is a catastrophic-regression tripwire with a huge
	// margin over the linear time even under heavy parallel CI load — not a perf
	// benchmark.
	assert elapsed_ms < 30_000.0, '8000 keyed writes took ${elapsed_ms}ms — O(n^2) full-index rewrite regression (append log broken?)'

	r := run_prog("[?lib 'cx-stdlib/store']
[?let [= \$s [\$store:open \"document+file://${dir}\"]]
  [n ndocs=[\$count [\$store:list-docs \$s]] naliases=[\$count [\$store:list-aliases \$s]]]]
")
	assert r.exit_code == 0, 'reopen after scale write failed: ${r.output}'
	assert r.output.contains('ndocs=8000'), 'not all docs persisted/replayed: ${r.output}'
	assert r.output.contains('naliases=8000'), 'not all aliases persisted/replayed: ${r.output}'
}
