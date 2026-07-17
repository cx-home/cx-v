module main

import os
import testenv

// store_snapshot_streaming_test.v — #283: the file:// index snapshot must not
// materialize the whole index in memory.
//
// The failure this pins: store_persist built the entire snapshot in ONE
// strings.Builder. The buffer tracks index size, so once the marine helm's
// index passed 32 MB the Builder's doubling asked vgc for >64 MB — larger
// than an arena, needing a dedicated oversized arena slot — and at arena
// exhaustion every persist died (the #277 field OOM; both crash traces sat in
// store_encode_index). Snapshots now stream record-by-record to the temp file
// (store_write_index), bounding the persist's allocation to one record header
// regardless of index size.
//
// Tests:
//   1. wire-format fidelity: a compaction-forced STREAMED snapshot reopens
//      identically in a separate process, including a body carrying raw tab
//      bytes (the length-prefixed no-escaping contract);
//   2. bounded memory: under VGC_MAX_ARENAS=4 (256 MB) a store holding
//      ~140 MB of docs survives a compaction snapshot. The monolithic encode
//      could not: docs (~140 MB live) + the encode buffer (~140 MB) + the
//      doubling's previous generation (~70 MB) exceed the cap by arithmetic,
//      before fragmentation. Streaming needs docs + one record header.

fn cx_bin_sss() string {
	return testenv.cx_bin()
}

fn run_prog_sss(src string, env_prefix string) os.Result {
	f := os.join_path(os.temp_dir(), 'cx_sss_${os.getpid()}_${src.len}.cx')
	os.write_file(f, src) or { panic('write: ${err}') }
	defer {
		os.rm(f) or {}
	}
	return os.execute('${env_prefix}${cx_bin_sss()} --allow-all ${f} 2>&1')
}

fn store_dir_sss(label string) string {
	d := os.join_path(os.temp_dir(), 'cx_sss_store_${label}_${os.getpid()}')
	os.rmdir_all(d) or {}
	return d
}

// 1. A compaction-forced streamed snapshot replays identically across a reopen,
// with a record payload containing raw tab bytes.
fn test_streamed_snapshot_roundtrips_awkward_bytes() {
	dir := store_dir_sss('fmt')
	defer {
		os.rmdir_all(dir) or {}
	}
	// Two docs (one carrying raw tabs), then enough redundant alias updates to
	// cross the compaction threshold (log_records > 2*live + 64), which
	// rewrites the log as a STREAMED snapshot.
	w := run_prog_sss("[?lib 'cx-stdlib/store']
[?def spin impure (\$s \$h \$i)
  [?if [= \$i 0] [then :done]
    [else [?let [= \$_ [\$store:set-alias \$s \"churn\" \$h]] [spin \$s \$h [- \$i 1]]]]]]
[?let [= \$s [\$store:open \"document+file://${dir}\"]]
 [?let [= \$h1 [\$store:put-doc \$s [doc [line \"a\tb\tc\"] [line \"plain\"]]]]
  [?let [= \$h2 [\$store:put-doc \$s [doc [v \"second\"]]]]
   [?let [= \$_a [\$store:set-alias \$s \"keep\" \$h1]]
    [?let [= \$_b [spin \$s \$h2 80]] :wrote]]]]]
", '')
	assert w.exit_code == 0, 'write/compact failed: ${w.output}'
	// The compacted index is a snapshot (fresh header at byte 0, no torn tail).
	idx := os.read_file(os.join_path(dir, '.cxstore-index')) or {
		assert false, 'index missing after compaction'
		return
	}
	assert idx.starts_with('CXSTORE\tv1\n')
	// Reopen in a SEPARATE process: the tab-carrying doc resolves through the
	// streamed snapshot byte-identically (raw tab bytes in the printed form).
	r := run_prog_sss("[?lib 'cx-stdlib/store']
[?let [= \$s [\$store:open \"document+file://${dir}\"]]
 [\$store:get-doc \$s [\$store:get-alias \$s \"keep\"]]]
", '')
	assert r.exit_code == 0, 'reopen failed: ${r.output}'
	assert r.output.contains("[line 'a\tb\tc']"), 'tab-carrying body did not survive the snapshot: ${r.output}'
}

// 2. The snapshot completes with the whole index far larger than the memory
// the monolithic encode would have needed. VGC_MAX_ARENAS=4 caps the heap at
// 256 MB; ~140 MB of docs + a compaction-forced snapshot must succeed.
fn test_snapshot_bounded_memory_under_arena_cap() {
	dir := store_dir_sss('big')
	defer {
		os.rmdir_all(dir) or {}
	}
	// 120 docs x ~1.2 MB body (a ~36 B seed doubled 15 times, with a distinct
	// prefix per doc so hashes differ), then alias churn to force compaction.
	w := run_prog_sss("[?lib 'cx-stdlib/store']
[?def grow impure (\$s \$i)
  [?if [= \$i 0] [then \$s]
    [else [grow [\$concat \$s \$s] [- \$i 1]]]]]
[?def fill impure (\$st \$seed \$i \$last)
  [?if [= \$i 0] [then \$last]
    [else [fill \$st \$seed [- \$i 1]
      [\$store:put-doc \$st [doc [n [\$text \$i]] [payload [\$concat [\$text \$i] \$seed]]]]]]]]
[?def spin impure (\$st \$h \$i)
  [?if [= \$i 0] [then :done]
    [else [?let [= \$_ [\$store:set-alias \$st \"churn\" \$h]] [spin \$st \$h [- \$i 1]]]]]]
[?let [= \$seed [grow \"abcdefghijklmnop-0123456789-ABCDEFGH\" 15]]
 [?let [= \$st [\$store:open \"document+file://${dir}\"]]
  [?let [= \$h [fill \$st \$seed 120 :none]]
   [?let [= \$_ [spin \$st \$h 320]] :snapshotted]]]]
", 'VGC_MAX_ARENAS=4 VNOBUGREPORT=1 ')
	assert w.exit_code == 0, 'big-store snapshot under arena cap failed (monolithic-encode regression?):\n${w.output}'
	// The snapshot really landed and is index-sized (not a stub).
	idx_path := os.join_path(dir, '.cxstore-index')
	assert os.is_file(idx_path), 'index missing'
	sz := os.file_size(idx_path)
	assert sz > u64(100) * 1024 * 1024, 'index unexpectedly small: ${sz}'
	// REOPEN under the same cap: the read side must be bounded too. The former
	// whole-string decode needed the file as one string (~140 MB) plus the doc
	// bodies (~140 MB) — over the 256 MB cap by arithmetic. The streamed reader
	// (store_read_index) needs the bodies plus one reader buffer.
	r := run_prog_sss("[?lib 'cx-stdlib/store']
[?let [= \$st [\$store:open \"document+file://${dir}\"]]
 [\$count [\$store:list-docs \$st]]]
", 'VGC_MAX_ARENAS=4 VNOBUGREPORT=1 ')
	assert r.exit_code == 0, 'big-store reopen under arena cap failed (monolithic-decode regression?):\n${r.output}'
	assert r.output.contains('120'), 'doc count wrong after capped reopen: ${r.output}'
}
