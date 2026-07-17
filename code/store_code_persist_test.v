module code

import os

// store_code_persist_test.v — #128-A. CX code is stored by Tier-2 identity and
// persists across a reopen on the object-graph (cxpack) backend — as a raw-leaf
// object, since code source does not data-parse. Before #128-A, code: entries
// lived only in the bypassed `docs` map and were silently dropped on cxpack
// persist; this proves they survive.

fn test_cxpack_code_persist_and_dedup() {
	root := os.join_path(os.temp_dir(), 'cxpack_code_${os.getpid()}')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	mut ms := &MemStore{
		url:     'file://${root}'
		backend: 'cxpack'
		root:    root
		is_open: true
	}
	src := '[?def add (\$a \$b) [+ \$a \$b]]'
	alpha := '[?def add (\$x \$y) [+ \$x \$y]]' // alpha-variant: same Tier-2 identity
	h1 := cx_code_store_put_def(mut ms, src) or { panic('put: ${err}') }
	h2 := cx_code_store_put_def(mut ms, alpha) or { panic('put alpha: ${err}') }
	assert h1 == h2, 'alpha-variants must dedup to one Tier-2 hash (${h1} vs ${h2})'

	store_cxpack_compact(mut ms) or { panic('compact: ${err.msg()}') }
	// reopen: code must come back (it lives in the object graph as a raw leaf).
	mut ms2 := &MemStore{
		backend: 'cxpack'
		root:    root
		is_open: true
	}
	store_cxpack_load(mut ms2) or { panic('load: ${err}') }
	got := cx_code_store_get_def(ms2, h1) or {
		panic('code def lost across reopen — #128-A regression')
	}
	assert got == src, 'code source changed across reopen: ${got}'
}
