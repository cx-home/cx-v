module main

import os
import testenv
import time

// store_shared_root_test.v — #628 ruling (a): WRITABLE opens of one canonical
// file:// root share the live MemStore in-process. Pre-fix each open built a
// private MemStore with its own segment counter, so two writers clobbered each
// other's segment files (data loss), and a second handle was a stale snapshot.
// Pinned here: the live shared view, chain consistency under CONCURRENT
// two-handle publishers, per-op serialization, the at-rest-options conflict
// refusal, and handle-close refcounting.

fn sr_run(prog string) string {
	tmp := os.join_path(os.temp_dir(), 'cx-shared-${os.getpid()}-${time.now().unix_nano()}.cx')
	os.write_file(tmp, prog) or { panic(err) }
	defer {
		os.rm(tmp) or {}
	}
	res := os.execute('CX_WORKER_THREADS=4 ${testenv.cx_bin()} --allow-read --allow-write ${tmp}')
	return res.output.trim_space()
}

fn sr_root(tag string) string {
	return os.join_path(os.temp_dir(), 'cx-shared-root-${tag}-${os.getpid()}')
}

// Two handles on one root: writes through one are LIVE through the other
// (same store), and a fresh-process reopen sees one consistent chain.
fn test_second_writable_open_is_a_live_view() {
	root := sr_root('live')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	out := sr_run("[?lib 'cx-fabric' :as fabric]
[?lib 'cx-stdlib/journal' :as journal]
[?let
  [= \$j1 [\$journal:open 'file://${root}' 'bench']]
  [= \$j2 [\$journal:open 'file://${root}' 'bench']]
  [= \$f [\$fabric:open \$j1]]
  [= \$n [\$count [?for [in \$i [\$range 1 12]]
    [yield [\$fabric:publish \$f 'acts' [act [n \$i]] {actor: 'a' authority: 'bench'}]]]]]
  [out [chk [n \$n] [h2 [\$journal:head \$j2 'acts']]]]]
")
	assert out.contains('[n 12]'), 'publisher must land 12: ${out}'
	assert out.contains('seq=12'), 'second handle must be a LIVE view of the shared root (#628): ${out}'
}

// CONCURRENT publishers through TWO handles on one root: every publish lands,
// the chain stays hash-consistent, and a fresh process replays all of it.
// Pre-fix this was the segment-numbering collision (silent data loss).
fn test_concurrent_two_handle_publishers_keep_one_chain() {
	root := sr_root('conc')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	out := sr_run("[?lib 'cx-fabric' :as fabric]
[?lib 'cx-stdlib/journal' :as journal]
[?let
  [= \$w1 [?worker name='p1' [?let
      [= \$f [\$fabric:open [\$journal:open 'file://${root}' 'bench']]]
      [\$count [?for [in \$i [\$range 1 25]]
        [yield [\$fabric:publish \$f 'acts' [act [w 1] [n \$i]] {actor: 'p1' authority: 'bench'}]]]]]]]
  [= \$w2 [?worker name='p2' [?let
      [= \$f [\$fabric:open [\$journal:open 'file://${root}' 'bench']]]
      [\$count [?for [in \$i [\$range 1 25]]
        [yield [\$fabric:publish \$f 'acts' [act [w 2] [n \$i]] {actor: 'p2' authority: 'bench'}]]]]]]]
  [= \$n1 [?wait-for [worker \$w1]]]
  [= \$n2 [?wait-for [worker \$w2]]]
  [out [?str '{\$n1}|{\$n2}']]]
")
	assert out.contains('25|25'), 'both concurrent publishers must land every publish: ${out}'
	// fresh process: the chain replays whole — head at 50, all 50 entries.
	out2 := sr_run("[?lib 'cx-stdlib/journal' :as journal]
[?let [= \$j [\$journal:open 'file://${root}' 'bench']]
  [out [chk [n [\$count [\$journal:since \$j 1 'acts']]] [head [\$journal:head \$j 'acts']]]]]
")
	assert out2.contains('[n 50]') && out2.contains('seq=50'), 'reopen must replay every concurrently-published entry (#628 pre-fix lost segments): ${out2}'
}

// A writable open with DIFFERENT at-rest options on a live root refuses loudly
// (sharing would silently apply one opener's options to the other's writes).
fn test_writable_open_with_conflicting_options_refuses() {
	root := sr_root('conflict')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	out := sr_run("[?lib 'cx-stdlib/store' :as store]
[?let
  [= \$a [\$store:open 'file://${root}']]
  [out [\$store:open-opts 'file://${root}' {encoding: 'cxtext'}]]]
")
	assert out.contains('CXER1143'), 'conflicting-options open on a live writable root must refuse (#628): ${out}'
}

// close retires ONE handle: the sibling stays live; ops on the closed handle
// refuse; the store closes with its last handle.
fn test_close_is_per_handle_refcounted() {
	root := sr_root('close')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	out := sr_run("[?lib 'cx-stdlib/store' :as store]
[?let
  [= \$a [\$store:open 'file://${root}']]
  [= \$b [\$store:open 'file://${root}']]
  [= \$h [\$store:put-doc \$a [doc [v 1]]]]
  [= \$c [\$store:close \$a]]
  [= \$dead [\$store:get-doc \$a \$h]]
  [= \$alive [\$store:get-doc \$b \$h]]
  [out [check [dead \$dead] [alive \$alive]]]]
")
	assert out.contains('[dead [err'), 'closed handle must refuse: ${out}'
	assert out.contains('[alive [doc [v 1]]]'), 'sibling handle must stay live after one close: ${out}'
}
