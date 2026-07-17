module main

import os

// vgc_arena_ceiling_raise_test.v — the compiled 4 GB arena ceiling is gone (#282).
//
// Before #282 the vgc heap was hard-walled at vgc_max_arenas = 64 arenas x
// 64 MB, compiled in: a server legitimately holding multi-GB live data could
// not run under `-gc e` at all (the xap-marine helm hit the wall at heap_live
// 2765 MB — span packing eats the rest of the nominal 4 GB). The raise moved
// the per-arena page->span map OUT of VGC_Arena (it embedded 8192 span
// pointers = 64 KB per arena, and mark_roots conservatively scans the whole
// vgc_heap global every STW cycle — the mcache tiny cursors in it are
// load-bearing roots — so a bigger embedded table would have taxed every
// pause), lifted the architectural maximum to 1024 arenas (64 GB), made the
// default effective ceiling RAM-derived, and gave VGC_MAX_ARENAS the power to
// move the wall BOTH ways within [1, 1024] (#277 shipped it lower-only).
//
// The child cx program holds ~4.34 GiB LIVE: 120 distinct ~37 MiB strings,
// each bound by a level of deliberately NON-tail recursion and probed
// ([$starts-with] on its distinct prefix) only AFTER the recursive call
// returns, so every binding must survive to the deepest frame. Each string
// needs >4096 pages, so each occupies its own 64 MB arena: past the old wall
// on BOTH axes (>64 arenas by count, >4 GiB by bytes — RSS measured ~4.98 GB,
// gctrace showed 112+ arenas / marked 4090 MB).
//
// Asserts (the #273/#277 control-A/B precedent):
//   RED  — pinned to the OLD ceiling (VGC_MAX_ARENAS=64) the identical
//          program dies at the wall, LOUDLY ("arenas 64/64" #277 forensics,
//          no SIGSEGV);
//   GREEN — under the raised (RAM-derived) default ceiling it completes and
//          reports every chunk intact, a live total > 4 GiB by arithmetic.
//
// Run notes: the child shell raises its stack rlimit (deep non-tail cx eval;
// ~120 levels need >8 MB) and pins the pacer at 2 GB headroom so the run is a
// couple of multi-GB cycles instead of a rescan every ~64 MB of growth (the
// adaptive cap; VGC_MEMLIMIT_MB moves only the PACING clamp, never the wall).
// Skipped (loudly) on boxes with < 12 GB RAM — the green run peaks ~5 GB RSS.

fn cx_bin_ceiling() string {
	abs := os.real_path('vcx/target/cx')
	if !os.is_file(abs) {
		panic('vcx/target/cx not found at ${abs} — run `make build-vcx` first')
	}
	return abs
}

// Physical RAM in bytes (darwin sysctl / linux /proc/meminfo); 0 = unknown.
fn phys_mem_bytes() u64 {
	$if macos {
		r := os.execute('sysctl -n hw.memsize')
		if r.exit_code == 0 {
			return r.output.trim_space().u64()
		}
	}
	meminfo := os.read_file('/proc/meminfo') or { return 0 }
	for line in meminfo.split_into_lines() {
		if line.starts_with('MemTotal:') {
			return line.all_after(':').trim_space().all_before(' ').u64() * 1024
		}
	}
	return 0
}

// The 37-char seed doubled 20 times = 37 MiB exactly; 120 chunks of
// (prefix + '|' + seed) = ~4.34 GiB live — past the old 4 GiB wall.
const ceiling_seed_len = u64(37) * 1024 * 1024
const ceiling_chunks = 120

fn ceiling_prog_path() string {
	prog := os.join_path(os.temp_dir(), 'vgc_ceiling_${os.getpid()}.cx')
	// grow: concat-double the seed to 37 MiB (tail — cx trampolines it).
	// hold: bind one DISTINCT ~37 MiB string per level; the [$starts-with]
	// probe of its unique '<i>|' prefix runs only AFTER the recursive call
	// (non-tail on purpose), so all 120 strings are simultaneously live at
	// the deepest frame and each is verified intact on the way back up.
	// Result: '<intact-chunk-count>:<seed-byte-length>'.
	os.write_file(prog, '[?def grow impure (\$s \$i)\n' +
		'  [?if [= \$i 0]\n' +
		'    [then \$s]\n' +
		'    [else [grow [\$concat \$s \$s] [- \$i 1]]]]]\n' +
		'[?def hold impure (\$seed \$i)\n' +
		'  [?if [= \$i 0]\n' +
		'    [then 0]\n' +
		'    [else [?let [= \$b [\$concat [\$text \$i] "|" \$seed]]\n' +
		'      [+ [hold \$seed [- \$i 1]]\n' +
		'         [?if [\$starts-with \$b [\$concat [\$text \$i] "|"]] [then 1] [else 0]]]]]]]\n' +
		'[?let [= \$seed [grow "abcdefghijklmnopqrstuvwxyz-0123456789" 20]]\n' +
		'  [\$concat [\$text [hold \$seed ${ceiling_chunks}]] ":" [\$text [\$string-length \$seed]]]]\n') or {
		panic(err)
	}
	return prog
}

// Child invocation: raise the stack rlimit first (macos hard cap is 65520 KB;
// linux typically allows unlimited), then exec cx under the given vgc env.
fn run_ceiling_child(env string, prog string) os.Result {
	return os.execute('ulimit -s unlimited 2>/dev/null || ulimit -s 65520 2>/dev/null; ' +
		'${env} VNOBUGREPORT=1 exec ${cx_bin_ceiling()} ${prog} 2>&1')
}

fn test_old_wall_still_bites_when_pinned_and_is_loud() {
	if phys_mem_bytes() < u64(12) * 1024 * 1024 * 1024 {
		eprintln('SKIP: <12 GB RAM — the #282 wall-crossing runs need the memory to exist')
		return
	}
	prog := ceiling_prog_path()
	defer {
		os.rm(prog) or {}
	}
	// Pinned to the OLD compiled capacity: the identical workload must hit the
	// wall (each ~37 MiB string burns one arena slot — two don't fit in 64 MB)
	// and die LOUDLY (#277), never by SIGSEGV. This red half proves the green
	// run below actually crosses the old ceiling rather than fitting under it.
	res := run_ceiling_child('VGC_MAX_ARENAS=64 VGC_NEXT_GC_MB=2048 VGC_MEMLIMIT_MB=8192',
		prog)
	assert res.exit_code != 139, 'old-ceiling death regressed to SIGSEGV:\n${res.output.limit(2000)}'
	assert res.exit_code != 0, 'workload sized past the old ceiling cannot fit in 64 arenas'
	assert res.output.contains('vgc: out of memory'), 'missing #277 forensics at the pinned wall:\n${res.output.limit(2000)}'
	assert res.output.contains('arenas 64/64'), 'died before/past the pinned 64-arena wall — workload no longer wall-shaped:\n${res.output.limit(2000)}'
}

fn test_multi_gb_live_set_crosses_old_4gb_wall() {
	if phys_mem_bytes() < u64(12) * 1024 * 1024 * 1024 {
		eprintln('SKIP: <12 GB RAM — the #282 wall-crossing runs need the memory to exist')
		return
	}
	prog := ceiling_prog_path()
	defer {
		os.rm(prog) or {}
	}
	// Default (RAM-derived) effective ceiling — no VGC_MAX_ARENAS.
	res := run_ceiling_child('VGC_NEXT_GC_MB=2048 VGC_MEMLIMIT_MB=8192', prog)
	assert res.exit_code == 0, 'multi-GB live set died under the raised ceiling:\n${res.output.limit(2000)}'
	// Every chunk intact + the measured seed length. Live total is then
	// chunks x (seed + prefix + separator) > 4 GiB by arithmetic.
	assert res.output.contains('${ceiling_chunks}:${ceiling_seed_len}'), 'chunk probe/seed-length mismatch (expected ${ceiling_chunks}:${ceiling_seed_len}):\n${res.output.limit(2000)}'
	assert u64(ceiling_chunks) * ceiling_seed_len > u64(4) * 1024 * 1024 * 1024, 'test bug: target live set must exceed the old 4 GiB wall'
}
