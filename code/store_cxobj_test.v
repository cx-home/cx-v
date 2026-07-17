module code

import cx
import cxstore
import os

// store_cxobj_test.v — #129 spec §6 conformance for the cxobj:// substrate
// (local-fs × subtree × object-per-key). The SAME subtree object model as cxpack,
// over a different at-rest encoding (one file per object via DirObjectBackend),
// proving model ⟂ substrate. Covers gate items 1 (round-trip), 2 (dedup),
// 3 (version sharing), 6 (universal integrity / CXER1120).

fn co_canon_hash(text string) (string, string) {
	doc := cx.parse(text) or { return text, '' }
	c := render_canonical(doc.elements[0])
	h := cx.cx_text_hash(c) or { return c, '' }
	return c, h
}

fn co_root(tag string) string {
	return os.join_path(os.temp_dir(), 'cxobj_${tag}_${os.getpid()}')
}

fn co_new(root string) &MemStore {
	return &MemStore{
		url:     'file://${root}?encoding=object-per-key'
		backend: 'cxobj'
		root:    root
		is_open: true
	}
}

// a put mirroring the real mutation hook: decompose into the live graph, then
// persist the delta (store_persist routes to store_cxobj_flush for cxobj).
fn co_put(mut ms MemStore, text string) string {
	c, h := co_canon_hash(text)
	store_put_canonical(mut ms, h, c) or { panic('put: ' + err.msg()) }
	store_cxobj_flush(mut ms) or { panic('flush: ${err.msg()}') }
	return h
}

fn co_object_count(root string) int {
	mut be := cxstore.open_dir_object_backend(os.join_path(root, 'objects')) or { return -1 }
	return be.object_count()
}

// GATE 1 (round-trip) + 6 (integrity by reconstruction): a doc put into a cxobj
// store reconstructs byte-identically, and survives a full reopen from disk.
fn test_cxobj_roundtrip_and_reopen() {
	root := co_root('rt')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	text := '[order [id 1] [customer [name "Acme"] [addr [city "NYC"]]] [lines [item [sku "A"] [qty 2]]]]'
	c, h := co_canon_hash(text)

	mut ms := co_new(root)
	put_h := co_put(mut ms, text)
	assert put_h == h
	got := store_doc_text(ms, h) or { panic('get: ${err.msg()}') }
	assert got == c, 'in-session round-trip not byte-identical'

	// reopen from disk only (fresh MemStore): the object files + manifest must
	// reconstruct the same canonical text — objects resolved lazily per-key.
	mut ms2 := co_new(root)
	store_cxobj_load(mut ms2) or { panic('reopen: ${err.msg()}') }
	assert store_doc_present(ms2, h), 'doc missing after reopen'
	got2 := store_doc_text(ms2, h) or { panic('get after reopen: ${err.msg()}') }
	assert got2 == c, 'reopened round-trip not byte-identical'
}

// GATE 2 (dedup): two docs sharing a subtree store fewer distinct objects than two
// disjoint docs — on the object-per-key substrate, same as in packs.
fn test_cxobj_dedup_across_docs() {
	root := co_root('dedup')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	big := '[customer [name "Acme"] [addr [street "1 Main"] [city "NYC"]] [tags [t "a"] [t "b"]]]'

	mut ms := co_new(root)
	co_put(mut ms, '[order [id 1] ${big}]')
	after1 := co_object_count(root)
	co_put(mut ms, '[order [id 2] ${big}]')
	after2 := co_object_count(root)

	added := after2 - after1
	assert added > 0 && added < after1, 'second doc sharing `big` must add only its delta: doc1=${after1}, doc2 added ${added}'

	// disjoint control: two docs with NO shared subtree add roughly twice as much.
	root2 := co_root('disjoint')
	os.rmdir_all(root2) or {}
	defer {
		os.rmdir_all(root2) or {}
	}
	mut md := co_new(root2)
	co_put(mut md, '[order [id 1] [a [p "aaa"] [q "bbb"]]]')
	d1 := co_object_count(root2)
	co_put(mut md, '[order [id 2] [z [r "ccc"] [s "ddd"]]]')
	d2 := co_object_count(root2)
	assert (d2 - d1) > added, 'disjoint docs must add more objects than subtree-sharing docs'
}

// GATE 3 (version sharing): a one-field-different version re-stores only the
// changed root-to-node path; every untouched subtree object is shared.
fn test_cxobj_version_sharing() {
	root := co_root('ver')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	mut ms := co_new(root)
	v1 := '[doc [meta [author "x"] [ver 1]] [body [p "long stable paragraph one"] [p "long stable paragraph two"] [p "long stable paragraph three"]]]'
	co_put(mut ms, v1)
	base := co_object_count(root)
	// change only [ver 1] → [ver 2]; the whole [body …] subtree is unchanged.
	v2 := '[doc [meta [author "x"] [ver 2]] [body [p "long stable paragraph one"] [p "long stable paragraph two"] [p "long stable paragraph three"]]]'
	co_put(mut ms, v2)
	added := co_object_count(root) - base
	// only the changed root→node path objects are new; the large body is shared.
	assert added > 0 && added < base, 'new version must share the untouched body subtree (added ${added}, base ${base})'
}

// GATE 6 (universal integrity / CXER1120): a corrupted object file on the substrate
// makes the affected doc fail HARD on reopen — never a silent drop.
fn test_cxobj_corruption_is_hard_error() {
	root := co_root('corrupt')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	mut ms := co_new(root)
	co_put(mut ms, '[order [id 1] [customer [name "Acme"] [addr [city "NYC"]]]]')

	// corrupt every stored object file in place (truncate to a non-matching body).
	objdir := os.join_path(root, 'objects')
	mut corrupted := 0
	for sh in os.ls(objdir) or { []string{} } {
		sub := os.join_path(objdir, sh)
		if !os.is_dir(sub) {
			continue
		}
		for f in os.ls(sub) or { []string{} } {
			os.write_file(os.join_path(sub, f), 'tampered') or { continue }
			corrupted++
		}
	}
	assert corrupted > 0, 'precondition: at least one object file to corrupt'

	// reopen must FAIL hard (integrity), not silently return an empty/partial store.
	mut ms2 := co_new(root)
	if _ := store_cxobj_load_result(mut ms2) {
		assert false, 'reopen of a corrupted cxobj store must be a hard error, not a silent success'
	}
}

// helper: store_cxobj_load returns `!`; wrap as `?` so the test can assert failure.
fn store_cxobj_load_result(mut ms MemStore) ?bool {
	store_cxobj_load(mut ms) or { return none }
	return true
}
