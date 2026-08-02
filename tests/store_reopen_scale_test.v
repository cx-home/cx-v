module main

import os
import testenv

// store_reopen_scale_test.v — #613: reopening a file:// journal store that has
// grown past the collector's first-GC threshold must load cleanly and see the
// durable head. Pre-fix this SEGFAULTed deterministically: the cxpack loader's
// object getter is a V closure whose captured context (an interface box over
// the object sink) was reachable ONLY through the closure — memory vgc never
// scanned — so the first GC cycle during a ~2000-entry load swept it and the
// next getter call read freed memory. Small stores (a few hundred entries)
// never triggered a GC mid-load and masked the bug; -gc boehm was clean. The
// root fix lives in the V fork (malloc_uncollectable = pinned GC root, with
// CX-free teeth in bench/parallel-alloc/closure_ctx_root_test.v); this lane
// pins the user-visible contract at the store surface.

const rs_entries = 2000

fn rs_run(args string, prog string) os.Result {
	return os.execute('${testenv.cx_bin()} ${args} ${prog}')
}

fn test_journal_reopen_at_scale_sees_head() {
	tmp := os.join_path(os.temp_dir(), 'cx-store-reopen-${os.getpid()}')
	os.rmdir_all(tmp) or {}
	os.mkdir_all(tmp) or { panic(err) }
	defer {
		os.rmdir_all(tmp) or {}
	}
	url := 'file://${os.join_path(tmp, 'jrn')}'

	seed := os.join_path(tmp, 'seed.cx')
	os.write_file(seed, "[?lib 'cx-fabric' :as fabric]
[?lib 'cx-stdlib/journal' :as journal]
[?let
  [= \$f [\$fabric:open [\$journal:open '${url}' 'bench']]]
  [out [\$count [?for [in \$i [\$range 1 ${rs_entries}]]
    [yield [\$fabric:publish \$f 'acts' [act [n \$i]] {actor: 'seed' authority: 'bench'}]]]]]]
") or { panic(err) }
	sres := rs_run('--allow-read --allow-write', seed)
	assert sres.exit_code == 0, 'seed failed (${sres.exit_code}): ${sres.output}'
	assert sres.output.contains('[out ${rs_entries}]'), 'seed did not publish ${rs_entries}: ${sres.output}'

	// The pinned behavior: a FRESH process reopens the grown store. Pre-fix
	// this crashed (signal, nonzero exit) inside store_cxpack_load once the
	// load's allocations triggered the first GC cycle.
	reopen := os.join_path(tmp, 'reopen.cx')
	os.write_file(reopen, "[?lib 'cx-stdlib/journal' :as journal]
[out [\$journal:head [\$journal:open '${url}' 'bench'] 'acts']]
") or { panic(err) }
	rres := rs_run('--allow-read --allow-write', reopen)
	assert rres.exit_code == 0, 'reopen crashed (${rres.exit_code}): ${rres.output}'
	assert rres.output.contains('seq=${rs_entries}'), 'reopened head wrong: ${rres.output}'

	// #613's second observation: an in-process SECOND open right after writes
	// must see the same durable head, not a stale/genesis view.
	twice := os.join_path(tmp, 'twice.cx')
	os.write_file(twice, "[?lib 'cx-fabric' :as fabric]
[?lib 'cx-stdlib/journal' :as journal]
[?let
  [= \$j1 [\$journal:open '${url}' 'bench']]
  [= \$f [\$fabric:open \$j1]]
  [= \$n [\$count [?for [in \$i [\$range 1 20]]
    [yield [\$fabric:publish \$f 'acts' [act [n \$i]] {actor: 'seed' authority: 'bench'}]]]]]
  [= \$j2 [\$journal:open '${url}' 'bench']]
  [out [heads [h1 [\$journal:head \$j1 'acts']] [h2 [\$journal:head \$j2 'acts']]]]]
") or { panic(err) }
	tres := rs_run('--allow-read --allow-write', twice)
	assert tres.exit_code == 0, 'double-open crashed (${tres.exit_code}): ${tres.output}'
	want := 'seq=${rs_entries + 20}'
	// both handles report the same post-write head
	assert tres.output.count(want) == 2, 'second in-process open sees a stale head: ${tres.output}'
}
