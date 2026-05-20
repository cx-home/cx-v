module main

import os

// I2 v0.7.0: `cx upgrade-config` idempotency tests. Running the
// migration twice produces the same output as running it once.

fn tmp_path(label string) string {
	return os.join_path(os.temp_dir(), 'cx_upgrade_${label}_${os.getpid()}.cx')
}

fn run_upgrade(path string) {
	cx_bin := os.join_path(@VMODROOT, 'target', 'cx')
	result := os.execute('${cx_bin} upgrade-config ${path}')
	assert result.exit_code == 0, 'upgrade-config failed: ${result.output}'
}

fn test_i2_idempotent_cxl_version() {
	path := tmp_path('m2')
	defer { os.rm(path) or {} }
	os.write_file(path, '[?cx cxl-version=1.0]\n[doc hi]\n') or { panic(err) }
	run_upgrade(path)
	first := os.read_file(path) or { panic(err) }
	assert first.contains('cx-eval-version='), 'M2 rename did not apply: ${first}'
	run_upgrade(path)
	second := os.read_file(path) or { panic(err) }
	assert first == second, 'second run changed content: "${first}" vs "${second}"'
}

fn test_i2_idempotent_path_rename() {
	path := tmp_path('m3')
	defer { os.rm(path) or {} }
	os.write_file(path, '[doc # see spec/cxl.md for details\n]\n') or { panic(err) }
	run_upgrade(path)
	first := os.read_file(path) or { panic(err) }
	assert first.contains('spec/eval.md'), 'M3 rename did not apply: ${first}'
	assert !first.contains('spec/cxl.md'), 'old path still present: ${first}'
	run_upgrade(path)
	second := os.read_file(path) or { panic(err) }
	assert first == second, 'second run changed content'
}

fn test_i2_idempotent_no_edits_when_clean() {
	path := tmp_path('clean')
	defer { os.rm(path) or {} }
	content := '[?cx cx-eval-version=4.0]\n[doc # see spec/eval.md\n]\n'
	os.write_file(path, content) or { panic(err) }
	run_upgrade(path)
	first := os.read_file(path) or { panic(err) }
	assert first == content, 'clean file should not change'
	run_upgrade(path)
	second := os.read_file(path) or { panic(err) }
	assert first == second, 'second run on clean file should still be no-op'
}
