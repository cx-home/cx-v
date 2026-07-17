module main

import os
import testenv
import time

// vgc_softlimit_progress_test.v — BEHAVIORAL guard for cx-private #272
// (pacer guaranteed progress under the soft heap limit).
//
// The pacer's goal is clamped to the soft heap limit (VGC_MEMLIMIT_MB). When
// the MARKED (live) set itself reaches that limit, a bare clamp puts the goal
// at or below heap_live, so every allocation-side pacing check fires another
// full collection: a mutator livelock, not pacing. Measured pre-fix: a
// workload that completes in ~1s unclamped spent 99.6% of a 5-minute window
// inside back-to-back collections (3286 cycles) and never finished — the
// exact shape of the xap-marine helm HTTP wedge scaled to a fixture.
//
// The fix keeps a minimum mutator budget above the marked set (marked/16,
// floored at the adaptive headroom minimum) even when that overshoots the
// soft limit — a soft limit is a pacing target; the hard cap remains the
// physical arena ceiling. This test pins the contract: a program whose live
// set exceeds VGC_MEMLIMIT_MB must still COMPLETE.

const timeout = 180 * time.second

fn cx_bin() string {
	return testenv.cx_bin()
}

fn test_live_set_above_soft_limit_still_completes() {
	// ~150k strings held live at once (well above the 16 MB limit below,
	// comfortably below the arena ceiling). The comprehension's result list
	// is live for the whole run — the #272 large-live-set operating point.
	prog := '[?let [= \$rows [?for [in \$i [\$range 1 150000]] [yield [\$concat "row-" [\$text \$i] "-abcdefghijklmnopqrstuvwxyz0123456789"]]]] "completed"]'
	dir := os.join_path(os.temp_dir(), 'cx_272_softlimit_${os.getpid()}')
	os.mkdir_all(dir) or { panic('mkdir: ${err}') }
	defer {
		os.rmdir_all(dir) or {}
	}
	src := os.join_path(dir, 'big_live.cx')
	os.write_file(src, prog) or { panic('write: ${err}') }

	mut p := os.new_process(cx_bin())
	p.set_args([src])
	p.set_environment({
		'VGC_MEMLIMIT_MB': '16'
		'VNOBUGREPORT':    '1'
	})
	p.set_redirect_stdio()
	p.run()
	start := time.now()
	for p.is_alive() {
		if time.since(start) > timeout {
			p.signal_kill()
			assert false, '#272 regressed: live set above VGC_MEMLIMIT_MB livelocked the pacer (no completion within ${timeout})'
		}
		time.sleep(200 * time.millisecond)
	}
	out := p.stdout_slurp()
	p.close()
	assert p.code == 0, 'cx exited ${p.code} (stderr: ${p.stderr_slurp()})'
	assert out.contains('completed'), 'unexpected output: ${out}'
}
