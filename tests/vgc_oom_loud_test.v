module main

import os
import testenv

// vgc_oom_loud_test.v — terminal heap exhaustion must be a LOUD memory panic,
// never a SIGSEGV (#277).
//
// The failure this pins: the vgc allocator returned nil at terminal exhaustion
// (arenas physically full after the force-collect retries), and not every V
// allocation entry point nil-checks (`malloc_uninit` et al. return the vgc
// result directly), so the caller's first write to the "allocated" block was a
// wild deref. The xap-marine helm died exactly this way minutes after boot —
// `signal 11` at builtin__alloc_array_data_uninit+28 under
// strings__Builder_write_string in store_encode_index — once the #274
// soft-limit progress guard let its (separately pathological) heap growth
// march past the 2 GB pacing clamp to the compiled 64x64 MB arena ceiling.
// The fix routes all three terminal-exhaustion sites (small scan, small
// noscan, large) through vgc_oom_report + _memory_panic in the fork.
//
// Child: the cx binary doubling a string until the VGC_MAX_ARENAS-capped arena
// space (3 x 64 MB) is exhausted — contiguous growth, the same large-alloc
// path as the field crash. Sub-second.
//
// Asserts:
//   1. the child did NOT die by SIGSEGV (pre-fix shape: shell exit 139),
//   2. stderr names the real condition: the vgc forensics line + the V
//      memory-allocation panic.

fn cx_bin_oom() string {
	return testenv.cx_bin()
}

fn test_vgc_terminal_oom_is_loud_not_segv() {
	prog := os.join_path(os.temp_dir(), 'vgc_oom_grow_${os.getpid()}.cx')
	// 40 doublings of a ~40-byte seed is unreachable (~44 TB): the run MUST end
	// at the arena wall, whatever the cap. Tail recursion — cx trampolines it.
	os.write_file(prog, '[?def grow impure (\$s \$i)\n' +
		'  [?if [= \$i 0]\n' +
		'    [then "unreachable-under-arena-cap"]\n' +
		'    [else [grow [\$concat \$s \$s] [- \$i 1]]]]]\n' +
		'[grow "seed-abcdefghijklmnopqrstuvwxyz-0123456789" 40]\n')!
	defer {
		os.rm(prog) or {}
	}
	res := os.execute('VGC_MAX_ARENAS=3 VNOBUGREPORT=1 ${cx_bin_oom()} ${prog} 2>&1')
	// 139 = the shell reporting death by SIGSEGV — the exact pre-fix failure.
	assert res.exit_code != 139, 'terminal OOM segfaulted (pre-#277-fix shape):\n${res.output}'
	assert res.exit_code != 0, 'the grower cannot succeed under a 192 MB arena cap'
	assert res.output.contains('vgc: out of memory'), 'missing vgc forensics line:\n${res.output}'
	assert res.output.contains('memory allocation failure'), 'missing V memory panic:\n${res.output}'
}
