module code

import cx

// xap_log_reduce_test.v — #606 (owner ruling b, 4b: log-cap absorbed into
// fold-side compaction): the run-level `log-reduce` opt compacts the
// in-process log through its declared pure reducer, and log READERS (the
// governance-fold surface, via xap_log_view) observe summary + the
// most-recent `window` events. Engine-level pin: the public surface drives
// ([$xap:run {log-reduce: …}] + emits), the runtime registry is inspected
// directly — no public read of the raw log exists by design.

fn test_log_reduce_compacts_and_composes_the_view() {
	prog := "[?lib 'cx-xap' :as xap]\n" +
		'[\$xap:component lr {bind: "/lr" emits: ([do :tick [n :string]])\n' +
		'  view: [?fn (\$rs) [panel [list]]] working-panel: :none}]\n' +
		'[?let [= \$rt [\$xap:run {tenant: "lr"\n' +
		'    log-reduce: {window: 2, fn: [?fn (\$s \$r) [+ [?else \$s 0] 1]]}}]]\n' +
		'[?let [= \$a [\$xap:emit \$rt [do :tick [n "1"]] {actor: "u"}]]\n' +
		'[?let [= \$b [\$xap:emit \$rt [do :tick [n "2"]] {actor: "u"}]]\n' +
		'[?let [= \$c [\$xap:emit \$rt [do :tick [n "3"]] {actor: "u"}]]\n' +
		'[?let [= \$d [\$xap:emit \$rt [do :tick [n "4"]] {actor: "u"}]]\n' +
		'[?let [= \$e [\$xap:emit \$rt [do :tick [n "5"]] {actor: "u"}]]\n' +
		'  [\$count [\$xap:state \$rt "/lr"]]]]]]]]\n'
	out := eval_code('[empty]', prog, 'text') or { panic('eval failed: ${err}') }
	assert out.contains('5'), 'state fold regressed under log-reduce: ${out}'

	reg := xap_reg()
	mut found := false
	for _, rt in reg.runtimes {
		if rt.tenant == 'lr' {
			found = true
			// 5 committed events, window 2 → 3 folded into the summary,
			// the most-recent 2 kept as detail.
			assert rt.has_log_reduce, 'log-reduce not armed'
			assert rt.log.len == 2, 'log not compacted to the window: len ${rt.log.len}'
			assert rt.has_log_summary, 'no log summary after overflow'
			sv := rt.log_summary
			if sv is cx.ScalarNode {
				assert cx.scalar_value_str_public(sv.value) == '3', 'summary count wrong'
			} else {
				assert false, 'summary is not the reducer scalar'
			}
			view := xap_log_view(rt)
			assert view.len == 3, 'log view must compose summary + window: len ${view.len}'
		}
	}
	assert found, 'runtime not registered'
}
