module main

import os
import testenv
import time

// async_eager_test.v — BEHAVIORAL gate for #541: [?async EXPR] spawns
// EAGERLY per §10.5.1 ("evaluates EXPR in a new asynchronous context and
// returns immediately"): a fire-and-forget side effect fires whether or
// not the future is ever awaited — the issue's exact repro, which the
// lazy substrate failed (the marker file was never created). Also pins
// the escape hatch: CX_WORKER_THREADS=0 restores the lazy substrate, so
// the same program does NOT fire the effect there (drive-at-await only).

fn test_fire_and_forget_side_effect_fires() {
	tmp := os.temp_dir()
	marker := os.join_path(tmp, 'cx-eager-async-${os.getpid()}.marker')
	os.rm(marker) or {}
	prog := os.join_path(tmp, 'eager-async-${os.getpid()}.cx')
	os.write_file(prog, "[?lib 'cx-stdlib/io' :as io]
[?let
  [= \$t [?async [\$io:write-file '${marker}' 'ran']]]
  [= \$z [?sleep 500ms]]
  'main-done']
") or { panic(err) }
	defer {
		os.rm(prog) or {}
		os.rm(marker) or {}
	}
	res := os.execute('${testenv.cx_bin()} --allow-write=${tmp} ${prog}')
	assert res.exit_code == 0, 'program failed: ${res.output}'
	assert res.output.contains('main-done'), 'unexpected output: ${res.output}'
	assert os.exists(marker), '#541: the un-awaited [?async] body never ran (marker missing)'
}

fn test_lazy_escape_hatch_still_lazy() {
	tmp := os.temp_dir()
	marker := os.join_path(tmp, 'cx-lazy-async-${os.getpid()}.marker')
	os.rm(marker) or {}
	prog := os.join_path(tmp, 'lazy-async-${os.getpid()}.cx')
	os.write_file(prog, "[?lib 'cx-stdlib/io' :as io]
[?let
  [= \$t [?async [\$io:write-file '${marker}' 'ran']]]
  [= \$z [?sleep 200ms]]
  'main-done']
") or { panic(err) }
	defer {
		os.rm(prog) or {}
		os.rm(marker) or {}
	}
	res := os.execute('CX_WORKER_THREADS=0 ${testenv.cx_bin()} --allow-write=${tmp} ${prog}')
	assert res.exit_code == 0, 'program failed: ${res.output}'
	time.sleep(100 * time.millisecond)
	assert !os.exists(marker), 'lazy escape hatch: an un-awaited body must NOT run under CX_WORKER_THREADS=0'
}
