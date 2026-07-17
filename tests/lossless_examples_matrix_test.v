module main

import os
import cx
import code

// lossless_examples_matrix_test.v — #475: the examples/*.cx corpus as an
// end-to-end lossless-structure matrix (conversions.md §2.2.1 / §2.3.1).
//
// Every top-level example that parses as a DATA document (strict canonical
// accepts it) must round-trip CX → json|yaml (--lossless) → CX
// strict-canonical-identically through the registry — the same
// convert_by_name path the CLI uses. Program sources the data/canonical
// parser rejects (code-tour.cx, cxpath-tour.cx, match-multi.cx,
// modify-crud.cx) are skipped by the same criterion the CLI applies: they
// are programs, and program directives are outside every conversion lane's
// lossless domain (§0.2).

fn examples_dir() string {
	// tests run with cwd = vcx/ (v test vcx/tests/...); the corpus lives at
	// the repo root
	mut dir := os.join_path(os.dir(@FILE), '..', '..', 'examples')
	return os.real_path(dir)
}

fn test_examples_roundtrip_matrix() {
	code.caps_set_all() // retain `code` so its init() registers the json parser
	dir := examples_dir()
	assert os.is_dir(dir), 'examples corpus not found at ${dir}'
	mut files := os.ls(dir) or { panic('ls ${dir}: ${err}') }
	files.sort()
	mut covered := 0
	mut skipped := []string{}
	for f in files {
		if !f.ends_with('.cx') {
			continue
		}
		path := os.join_path(dir, f)
		if !os.is_file(path) {
			continue
		}
		src := os.read_file(path) or { panic('read ${path}: ${err}') }
		orig := cx.cx_text_canonical(src) or {
			skipped << f // program source — not a data document
			continue
		}
		for lane in ['json', 'yaml'] {
			emitted := cx.convert_by_name(src, 'cx', lane, true) or {
				assert false, '${f} ${lane}: lossless emit failed: ${err}'
				return
			}
			back := cx.convert_by_name(emitted, lane, 'cx', false) or {
				assert false, '${f} ${lane}: import failed: ${err}'
				return
			}
			got := cx.cx_text_canonical(back) or {
				assert false, '${f} ${lane}: recovered text not canonicalizable: ${err}\n${back}'
				return
			}
			assert got == orig, '${f} ${lane}: round-trip not strict-canonical-eq'
		}
		covered++
	}
	// the corpus has 15 data documents today; guard against silent shrinkage
	assert covered >= 15, 'examples matrix shrank: only ${covered} data docs round-tripped (skipped: ${skipped})'
}
