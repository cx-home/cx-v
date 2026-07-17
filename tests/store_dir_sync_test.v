module main

import os
import testenv

// store_dir_sync_test.v — BEHAVIORAL test for the directory<->store ingest/sync
// recipe (examples/cxstore/dir-sync, #128). It runs the SHIPPED ingest.cx +
// materialize.cx against the example's sample/ tree and asserts:
//   1. ingest stores the .cxd docs (content-addressed) and names them by path;
//   2. re-running ingest is idempotent (identical output → same hashes/aliases);
//   3. materialize round-trips each doc back to ./restored under its named path,
//      canonical-equal to the source.
// Black-box: spawns the prebuilt vcx/target/cx (run `make build-vcx` first), in
// the example directory. Generated out-store/ and restored/ are cleaned up.

fn dirsync_cx_binary() string {
	return testenv.cx_bin()
}

fn dirsync_example_dir() string {
	abs := os.real_path('examples/cxstore/dir-sync')
	if !os.is_dir(abs) {
		panic('example dir not found at ${abs}')
	}
	return abs
}

fn dirsync_clean(ex string) {
	os.rmdir_all(os.join_path(ex, 'out-store')) or {}
	os.rmdir_all(os.join_path(ex, 'restored')) or {}
}

fn test_dir_sync_ingest_materialize_roundtrip() {
	cx := dirsync_cx_binary()
	ex := dirsync_example_dir()
	dirsync_clean(ex)
	defer {
		dirsync_clean(ex)
	}

	// (1) ingest: stores the sample docs, named by path.
	r1 := os.execute('cd "${ex}" && "${cx}" --allow-all ingest.cx')
	assert r1.exit_code == 0, 'ingest failed: ${r1.output}'
	assert r1.output.contains("path='sample/notes/hello.cxd'"), 'hello.cxd not ingested: ${r1.output}'
	assert r1.output.contains('hash='), 'no content hash emitted: ${r1.output}'
	// (1b) #128-A: the .cx CODE file is ingested as code (put-def, Tier-2), NOT
	// as data — and is retrievable by its path alias via get-def.
	assert r1.output.contains("kind=code path='sample/code/greet.cx'"), 'greet.cx not ingested as code: ${r1.output}'
	assert !r1.output.contains('CXER'), 'ingest emitted an error: ${r1.output}'
	// retrieve the code def by its path alias: get-alias -> Tier-2 hash -> get-def.
	probe := '[?lib \'cx-stdlib/store\' :as store] [?let [= \$c [\$store:open "file://./out-store"]] [\$store:get-def \$c [\$store:get-alias \$c "sample/code/greet.cx"]]]'
	pp := os.join_path(ex, 'getdef_probe.cx')
	os.write_file(pp, probe) or { panic('write probe: ${err}') }
	g := os.execute('cd "${ex}" && "${cx}" --allow-all getdef_probe.cx')
	os.rm(pp) or {}
	assert g.output.contains('?def greet'), 'code def not retrievable by alias via get-def: ${g.output}'
	// the cxpack store persisted to disk. #129-B persists incrementally, so a
	// small ingest writes segment packs (store-NNNN.cxpack) + the append-only
	// manifest; the single store.cxpack only appears after a compaction. Assert
	// the layout-agnostic invariant: a manifest plus at least one pack file.
	store_dir := os.join_path(ex, 'out-store')
	assert os.exists(os.join_path(store_dir, '.cxpack-manifest')), 'store manifest not persisted'
	mut pack_files := 0
	for e in os.ls(store_dir) or { []string{} } {
		if e.ends_with('.cxpack') {
			pack_files++
		}
	}
	assert pack_files > 0, 'no cxpack pack file persisted in ${store_dir}'

	// (2) idempotent: a second ingest of the unchanged tree yields identical
	// output (same hashes + aliases — re-put is a content-addressed no-op).
	r2 := os.execute('cd "${ex}" && "${cx}" --allow-all ingest.cx')
	assert r2.exit_code == 0, 'second ingest failed: ${r2.output}'
	assert r2.output == r1.output, 'ingest not idempotent:\n--- run1 ---\n${r1.output}\n--- run2 ---\n${r2.output}'

	// (3) materialize: write the store back out, recreating the named tree.
	m := os.execute('cd "${ex}" && "${cx}" --allow-all materialize.cx')
	assert m.exit_code == 0, 'materialize failed: ${m.output}'
	restored := os.read_file(os.join_path(ex, 'restored/sample/notes/hello.cxd')) or {
		panic('restored hello.cxd missing: ${err}')
	}
	// canonical round-trip: same content + structure (store re-emits canonical form).
	assert restored.contains('note id=hello'), 'restored doc not canonical note: ${restored}'
	assert restored.contains('first note'), 'restored doc lost body: ${restored}'
	// a nested-dir doc round-trips too (tree structure preserved).
	assert os.exists(os.join_path(ex, 'restored/sample/archive/old.cxd')), 'nested doc not restored'
}
