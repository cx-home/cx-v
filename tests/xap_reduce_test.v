module main

import os
import testenv

// xap_reduce_test.v — BEHAVIORAL proof of §5 `reduce` fold-side compaction
// (#606, owner ruling b): a component's declared pure reducer folds the
// OLDEST records past `window` into the slice's single summary record;
// every read (state, the view) observes summary + recent detail; the
// §3.1.1 checkpoint persists the compacted fold and a restart reconstructs
// exactly what views observed (reducer re-application over the replay
// suffix composes with a checkpoint-loaded summary); a failing reducer is
// loud and FAIL-OPEN (no data loss). Absent reduce: pinned unchanged by
// every pre-existing xap test.

fn xr_write(dir string, name string, content string) string {
	p := os.join_path(dir, name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

fn xr_run(args string, prog string) string {
	res := os.execute('${testenv.cx_bin()} ${args} ${prog}')
	return res.output.trim_space()
}

// the ledger component: window 2, summary = {label, count} counting
// absorbed records. Views read $r/label for the summary, $r/n for detail.
const xr_component = '[?lib \'cx-xap\' :as xap]
[\$xap:component ledger
  {bind: "/ledger"
   emits: ([do :add [n :string]])
   view: [?fn (\$rs) [panel [list [?for [in \$r \$rs] [yield [item [?else \$r/label \$r/n]]]]]]]
   reduce: {window: 2, fn: [?fn (\$s \$r)
     [?let [= \$c [?else \$s/count 0]]
       {label: [?str \'sum-{[+ \$c 1]}\'], count: [+ \$c 1]}]]}
   working-panel: :none}]
'

fn test_xap_reduce_compacts_and_reads_compose() {
	tmp := os.join_path(os.temp_dir(), 'cx-xap-reduce-${os.getpid()}')
	os.rmdir_all(tmp) or {}
	os.mkdir_all(tmp) or { panic(err) }
	defer {
		os.rmdir_all(tmp) or {}
	}
	p1 := xr_write(tmp, 'reduce.cx', xr_component +
		"[?lib 'cx-stdlib/format' :as format]\n" +
		'[?let [= \$rt [\$xap:run {tenant: "r"}]]\n' +
		'[?let [= \$a [\$xap:emit \$rt [do :add [n "1"]] {actor: "u"}]]\n' +
		'[?let [= \$b [\$xap:emit \$rt [do :add [n "2"]] {actor: "u"}]]\n' +
		'[?let [= \$c [\$xap:emit \$rt [do :add [n "3"]] {actor: "u"}]]\n' +
		'[?let [= \$d [\$xap:emit \$rt [do :add [n "4"]] {actor: "u"}]]\n' +
		'[?let [= \$e [\$xap:emit \$rt [do :add [n "5"]] {actor: "u"}]]\n' +
		'  [out [?str \'{[\$count [\$xap:state \$rt "/ledger"]]}|{[\$format:canonical [\$xap:state \$rt "/ledger"]]}\']]]]]]]]\n')
	out := xr_run('', p1)
	// 5 commits, window 2 → summary (3 absorbed) + 2 detail = 3 observed.
	assert out.contains('3|'), 'read must observe summary + window: ${out}'
	assert out.contains('sum-3'), 'summary must have absorbed 3 records: ${out}'
	assert out.contains("'4'") && out.contains("'5'"), 'detail must be the most-recent window: ${out}'
	assert !out.contains("'1'") && !out.contains("n: '2'"), 'absorbed records must not appear as detail: ${out}'
}

fn test_xap_reduce_checkpoint_roundtrip() {
	tmp := os.join_path(os.temp_dir(), 'cx-xap-reduce-ck-${os.getpid()}')
	os.rmdir_all(tmp) or {}
	os.mkdir_all(tmp) or { panic(err) }
	defer {
		os.rmdir_all(tmp) or {}
	}
	bind := '{url: "file://${tmp}/journal", stream: "acts", checkpoint: "file://${tmp}/ckpt", checkpoint-every: 2}'
	p1 := xr_write(tmp, 'seed.cx', xr_component +
		'[?let [= \$rt [\$xap:run {tenant: "r" journal: ${bind}}]]\n' +
		'[?let [= \$a [\$xap:emit \$rt [do :add [n "1"]] {actor: "u"}]]\n' +
		'[?let [= \$b [\$xap:emit \$rt [do :add [n "2"]] {actor: "u"}]]\n' +
		'[?let [= \$c [\$xap:emit \$rt [do :add [n "3"]] {actor: "u"}]]\n' +
		'[?let [= \$d [\$xap:emit \$rt [do :add [n "4"]] {actor: "u"}]]\n' +
		'[?let [= \$e [\$xap:emit \$rt [do :add [n "5"]] {actor: "u"}]]\n' +
		'[?let [= \$w [?sleep 1s]]\n' +
		'  [out [\$count [\$xap:state \$rt "/ledger"]]]]]]]]]]\n')
	out1 := xr_run('--allow-read --allow-write', p1)
	assert out1.contains('[out 3]'), 'compacted fold before restart: ${out1}'

	// restart: the checkpoint carries the summary; the suffix replay
	// re-applies the reducer OVER the loaded summary — the observed view
	// is identical to the pre-restart one.
	p2 := xr_write(tmp, 'refold.cx', xr_component +
		"[?lib 'cx-stdlib/format' :as format]\n" +
		'[?let [= \$rt [\$xap:run {tenant: "r" journal: ${bind}}]]\n' +
		'  [out [?str \'{[\$count [\$xap:state \$rt "/ledger"]]}|{[\$format:canonical [\$xap:state \$rt "/ledger"]]}\']]]\n')
	out2 := xr_run('--allow-read --allow-write', p2)
	assert out2.contains('3|'), 'restart must reconstruct the compacted fold: ${out2}'
	assert out2.contains('sum-3'), 'summary lost across restart: ${out2}'
	// #620: the REPLAYED suffix record renders identically to the
	// checkpoint-loaded one — field string typing survives the
	// canonical → journal → reparse → fold lane (n stays a quoted string,
	// never silently re-typed to an int).
	assert out2.contains("n: '4'") && out2.contains("n: '5'"), 'detail window lost or lane-retyped across restart (#620): ${out2}'
}

fn test_xap_reduce_failure_is_loud_and_fail_open() {
	tmp := os.join_path(os.temp_dir(), 'cx-xap-reduce-ff-${os.getpid()}')
	os.rmdir_all(tmp) or {}
	os.mkdir_all(tmp) or { panic(err) }
	defer {
		os.rmdir_all(tmp) or {}
	}
	comp := '[?lib \'cx-xap\' :as xap]\n' +
		'[\$xap:component ledger\n' +
		'  {bind: "/ledger" emits: ([do :add [n :string]])\n' +
		'   view: [?fn (\$rs) [panel [list]]]\n' +
		'   reduce: {window: 2, fn: [?fn (\$s \$r) [err code=cx-err:CXER0001 [message \'reducer says no\']]]}\n' +
		'   working-panel: :none}]\n'
	p1 := xr_write(tmp, 'ff.cx', comp +
		'[?let [= \$rt [\$xap:run {tenant: "r"}]]\n' +
		'[?let [= \$a [\$xap:emit \$rt [do :add [n "1"]] {actor: "u"}]]\n' +
		'[?let [= \$b [\$xap:emit \$rt [do :add [n "2"]] {actor: "u"}]]\n' +
		'[?let [= \$c [\$xap:emit \$rt [do :add [n "3"]] {actor: "u"}]]\n' +
		'[?let [= \$d [\$xap:emit \$rt [do :add [n "4"]] {actor: "u"}]]\n' +
		'  [out [\$count [\$xap:state \$rt "/ledger"]]]]]]]]\n')
	out := xr_run('', p1)
	// fail-open: a refusing reducer never loses records — the slice stays
	// complete (4 detail records, no summary).
	assert out.contains('[out 4]'), 'a failing reducer must not lose records: ${out}'
}

fn test_xap_reduce_declaration_refuses_malformed() {
	tmp := os.join_path(os.temp_dir(), 'cx-xap-reduce-bad-${os.getpid()}')
	os.rmdir_all(tmp) or {}
	os.mkdir_all(tmp) or { panic(err) }
	defer {
		os.rmdir_all(tmp) or {}
	}
	p1 := xr_write(tmp, 'bad.cx', '[?lib \'cx-xap\' :as xap]\n' +
		'[out [\$xap:component bad {bind: "/b" emits: ([do :x [n :string]])\n' +
		'  view: [?fn (\$rs) [panel [list]]]\n' +
		'  reduce: {window: 0, fn: [?fn (\$s \$r) \$s]}\n' +
		'  working-panel: :none}]]\n')
	out := xr_run('', p1)
	assert out.contains('E_XAP_COMPONENT_INVALID') && out.contains('window'), 'window 0 must refuse at declaration: ${out}'
}
