module main

import os
import cx

// Phase 2.18 — `cx lock` CLI subcommand tests.
//
// Drives the compiled `cx` binary as a subprocess to assert:
//
//   - `cx lock FILE.cx` writes a syntactically-valid cx.lock that
//     parses back through vcx/cx/lockfile_reader.v.
//   - The emitted lockfile carries one `[module]` entry per
//     distinct [?lib] resolver in the input.
//   - Bundled cx-stdlib imports resolve to :resolved "bundled:0.8.0".
//   - File-path imports resolve to :resolved equal to the resolver.
//   - HTTPS imports preserve :sri + :version from any prior lockfile.
//   - `cx lock --check` exits 0 when the lockfile is in sync.
//   - `cx lock --check` exits 1 when it has drifted.
//   - `cx lock --update NAME` refreshes only the named module.
//
// Cross-references:
// (lockfile + CLI).
//   - spec/lockfile.md §3 + §4 (format + module entries).

fn cx_bin() string {
	return os.join_path(@VMODROOT, 'target', 'cx')
}

fn tmp_project_dir(label string) string {
	d := os.join_path(os.temp_dir(), 'cx_lock_${label}_${os.getpid()}')
	os.mkdir_all(d) or { panic(err) }
	return d
}

fn write_program(dir string, name string, content string) string {
	path := os.join_path(dir, name)
	os.write_file(path, content) or { panic(err) }
	return path
}

fn run_cx_lock(args []string) os.Result {
	cmd := '${cx_bin()} lock ${args.join(' ')}'
	return os.execute(cmd)
}

// ── 1. `cx lock FILE.cx` generates a cx.lock with bundled entry ──────────────

fn test_cx_lock_generates_bundled_stdlib_entry() {
	dir := tmp_project_dir('bundled')
	defer { os.rmdir_all(dir) or {} }
	src := write_program(dir, 'app.cx', '[?lib "cx-stdlib/strings"]\n')
	lock_path := os.join_path(dir, 'cx.lock')
	r := run_cx_lock(['--output', lock_path, src])
	assert r.exit_code == 0, 'cx lock failed: ${r.output}'
	assert os.exists(lock_path), 'cx.lock not written'

	lf := cx.read_lockfile(lock_path) or {
		assert false, 'parse failure: ${err}'
		return
	}
	assert lf.schema_version == '1'
	assert lf.modules.len == 1
	assert lf.modules[0].name == 'cx-stdlib/strings'
	assert lf.modules[0].resolved == 'bundled:0.8.0',
		'expected bundled:0.8.0, got ${lf.modules[0].resolved}'
}

// ── 2. File-path resolver lands in :resolved verbatim ────────────────────────

fn test_cx_lock_file_path_resolver_round_trip() {
	dir := tmp_project_dir('filepath')
	defer { os.rmdir_all(dir) or {} }
	src := write_program(dir, 'app.cx', '[?lib "./helpers.cx"]\n')
	lock_path := os.join_path(dir, 'cx.lock')
	r := run_cx_lock(['--output', lock_path, src])
	assert r.exit_code == 0, 'cx lock failed: ${r.output}'

	lf := cx.read_lockfile(lock_path) or {
		assert false, 'parse failure: ${err}'
		return
	}
	assert lf.modules.len == 1
	assert lf.modules[0].name == './helpers.cx'
	assert lf.modules[0].resolved == './helpers.cx'
}

// ── 3. Multiple [?lib]s in one source produce multiple entries ───────────────

fn test_cx_lock_multiple_libs() {
	dir := tmp_project_dir('multi')
	defer { os.rmdir_all(dir) or {} }
	src := write_program(dir, 'app.cx',
		'[?lib "cx-stdlib/strings"]\n[?lib "cx-stdlib/json"]\n[?lib "./local.cx"]\n')
	lock_path := os.join_path(dir, 'cx.lock')
	r := run_cx_lock(['--output', lock_path, src])
	assert r.exit_code == 0, 'cx lock failed: ${r.output}'

	lf := cx.read_lockfile(lock_path) or {
		assert false, 'parse failure: ${err}'
		return
	}
	assert lf.modules.len == 3, 'expected 3 modules, got ${lf.modules.len}'
}

// ── 4. Duplicate resolvers are de-duplicated ─────────────────────────────────

fn test_cx_lock_dedupes_repeated_libs() {
	dir := tmp_project_dir('dedupe')
	defer { os.rmdir_all(dir) or {} }
	src := write_program(dir, 'app.cx',
		'[?lib "cx-stdlib/strings"]\n[?lib "cx-stdlib/strings"]\n')
	lock_path := os.join_path(dir, 'cx.lock')
	r := run_cx_lock(['--output', lock_path, src])
	assert r.exit_code == 0
	lf := cx.read_lockfile(lock_path) or {
		assert false, 'parse failure: ${err}'
		return
	}
	assert lf.modules.len == 1, 'expected dedup, got ${lf.modules.len}'
}

// ── 5. --check exits 0 when in sync ──────────────────────────────────────────

fn test_cx_lock_check_in_sync() {
	dir := tmp_project_dir('check-sync')
	defer { os.rmdir_all(dir) or {} }
	src := write_program(dir, 'app.cx', '[?lib "cx-stdlib/strings"]\n')
	lock_path := os.join_path(dir, 'cx.lock')
	// Generate first.
	r := run_cx_lock(['--output', lock_path, src])
	assert r.exit_code == 0
	// Then --check.
	r2 := run_cx_lock(['--check', '--output', lock_path, src])
	assert r2.exit_code == 0, '--check expected 0 in sync, got ${r2.exit_code}: ${r2.output}'
}

// ── 6. --check exits 1 when drift detected ───────────────────────────────────

fn test_cx_lock_check_drift() {
	dir := tmp_project_dir('check-drift')
	defer { os.rmdir_all(dir) or {} }
	src := write_program(dir, 'app.cx', '[?lib "cx-stdlib/strings"]\n')
	lock_path := os.join_path(dir, 'cx.lock')
	r := run_cx_lock(['--output', lock_path, src])
	assert r.exit_code == 0
	// Add a second lib without re-running cx lock — cx.lock now drifts.
	os.write_file(src, '[?lib "cx-stdlib/strings"]\n[?lib "cx-stdlib/json"]\n') or {
		panic(err)
	}
	r2 := run_cx_lock(['--check', '--output', lock_path, src])
	assert r2.exit_code == 1, '--check expected 1 on drift, got ${r2.exit_code}'
}

// ── 7. SRI shape preserved across re-lock for HTTPS entries ──────────────────

fn test_cx_lock_preserves_https_sri_across_rerun() {
	dir := tmp_project_dir('https-sri')
	defer { os.rmdir_all(dir) or {} }
	src := write_program(dir, 'app.cx', '[?lib "https://example.com/lib.zip"]\n')
	lock_path := os.join_path(dir, 'cx.lock')
	// Hand-seed cx.lock with a fake SRI (the CLI cannot recompute SRI
	// at Phase 2.18; preserve-not-clobber is the contract).
	seed := '[cx.lock version="1"
  [modules
    [module name="https://example.com/lib.zip"
      resolved="https://example.com/lib.zip"
      version="1.2.3"
      sri="sha384-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]]]
'
	os.write_file(lock_path, seed) or { panic(err) }
	r := run_cx_lock(['--output', lock_path, src])
	assert r.exit_code == 0, 'cx lock failed: ${r.output}'
	lf := cx.read_lockfile(lock_path) or {
		assert false, 'parse failure: ${err}'
		return
	}
	assert lf.modules.len == 1
	if sri := lf.modules[0].integrity {
		assert sri.starts_with('sha384-'), 'sri preserved: ${sri}'
	} else {
		assert false, 'sri not preserved'
	}
	if v := lf.modules[0].version {
		assert v == '1.2.3'
	} else {
		assert false, 'version not preserved'
	}
}

// ── 8. --update NAME refreshes the named module only ────────────────────────

fn test_cx_lock_update_named_only() {
	dir := tmp_project_dir('update')
	defer { os.rmdir_all(dir) or {} }
	src := write_program(dir, 'app.cx',
		'[?lib "cx-stdlib/strings"]\n[?lib "./local.cx"]\n')
	lock_path := os.join_path(dir, 'cx.lock')
	// Initial lock.
	r := run_cx_lock(['--output', lock_path, src])
	assert r.exit_code == 0
	// Reset cx.lock to a stale shape — pretend strings was at an older
	// bundled version — then run --update on the local resolver. The
	// stdlib entry should be left as-is.
	stale := '[cx.lock version="1"
  [modules
    [module name="cx-stdlib/strings" resolved="bundled:0.7.9"]
    [module name="./local.cx" resolved="./local.cx"]]]
'
	os.write_file(lock_path, stale) or { panic(err) }
	r2 := run_cx_lock(['--update', './local.cx', '--output', lock_path, src])
	assert r2.exit_code == 0, 'update failed: ${r2.output}'
	lf := cx.read_lockfile(lock_path) or {
		assert false, 'parse failure: ${err}'
		return
	}
	// Stale strings entry preserved (per --update contract).
	mut found_strings := false
	mut found_local := false
	for ml in lf.modules {
		if ml.name == 'cx-stdlib/strings' {
			assert ml.resolved == 'bundled:0.7.9',
				'--update should not touch strings; got resolved=${ml.resolved}'
			found_strings = true
		}
		if ml.name == './local.cx' {
			found_local = true
		}
	}
	assert found_strings && found_local
}
