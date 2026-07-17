module code

import cx
import os

// §6 + §4.6 for the DEGENERATE document model (#129 B2): `model=document` stores each
// doc as ONE object ("don't decompose") on any object-graph substrate, reusing the
// same seam + store_graph refs/replay. The model is INVISIBLE to the Layer-1 API:
// the same doc has the same store-key and the same byte-identical round-trip under
// both models; the only observable difference is object count (document = 1/doc,
// subtree = many) — i.e. document trades dedup for simplicity.

fn dm_canon_hash(text string) (string, string) {
	c := render_canonical(cx.parse(text) or { panic('parse: ${err.msg()}') }.elements[0])
	h := cx.cx_text_hash(c) or { panic('hash: ${err.msg()}') }
	return c, h
}

fn test_document_model_mem_api_invisibility() {
	text := '[order [id 1] [customer [name "Acme"] [addr [city "NYC"] [zip "10001"]]]]'
	c, h := dm_canon_hash(text)

	// document model (mem)
	mut doc_ms := &MemStore{
		backend: 'mem'
		is_open: true
		model:   'document'
	}
	assert store_objgraph_active(doc_ms)
	store_put_canonical(mut doc_ms, h, c) or { panic('doc put: ${err.msg()}') }
	got_doc := store_doc_text(doc_ms, h) or { panic('doc get: ${err.msg()}') }
	doc_objs := doc_ms.obj_sink.objects.len

	// subtree model (mem, default)
	mut sub_ms := &MemStore{
		backend: 'mem'
		is_open: true
	}
	store_put_canonical(mut sub_ms, h, c) or { panic('sub put: ${err.msg()}') }
	got_sub := store_doc_text(sub_ms, h) or { panic('sub get: ${err.msg()}') }
	sub_objs := sub_ms.obj_sink.objects.len

	// API-invisible: identical store-key (same h used) + identical round-trip text.
	assert got_doc == c, 'document round-trip not byte-identical'
	assert got_sub == c, 'subtree round-trip not byte-identical'
	assert got_doc == got_sub, 'document and subtree must return identical text for the same doc'
	// The model shows ONLY in object count: document = exactly 1 object, subtree = many.
	assert doc_objs == 1, 'document model must store exactly one object per doc, got ${doc_objs}'
	assert sub_objs > 1, 'subtree model must decompose into multiple objects, got ${sub_objs}'
}

fn test_document_model_cxobj_reopen() {
	root := os.join_path(os.temp_dir(), 'cxobj_docmodel_${os.getpid()}')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	c, h := dm_canon_hash('[note [meta [author "ep"]] [body "hello document model"]]')

	mut ms := &MemStore{
		backend: 'cxobj'
		root:    root
		is_open: true
		model:   'document'
	}
	store_cxobj_backend(mut ms) or { panic('attach: ${err.msg()}') }
	store_put_canonical(mut ms, h, c) or { panic('put: ${err.msg()}') }
	store_cxobj_flush(mut ms) or { panic('flush: ${err.msg()}') }

	// reopen with model=document → replay restores the raw object (no decompose),
	// round-trip byte-identical.
	mut ms2 := &MemStore{
		backend: 'cxobj'
		root:    root
		is_open: true
		model:   'document'
	}
	store_cxobj_load(mut ms2) or { panic('reopen: ${err.msg()}') }
	assert store_doc_present(ms2, h), 'doc must survive a document-mode reopen'
	got := store_doc_text(ms2, h) or { panic('get: ${err.msg()}') }
	assert got == c, 'document reopen round-trip not byte-identical'
}

// #129 PR-H: the canonical `document+` URI prefix selects the document model on
// the mem / sqlite / s3 substrates (consistent with file://), and a bare substrate
// URI is subtree by default — both via the live open dispatcher (not just opts).
fn test_document_prefix_open_dispatch() {
	// document+mem:// → document model (hermetic; mem is capability-free).
	h := store_open_impl('document+mem://', '', '', false, true, map[string]string{})
	id := store_handle_of(h) or { panic('document+mem:// did not return a handle: ${h}') }
	ms := store_lookup(id) or { panic('no store for document+mem://') }
	assert ms.backend == 'mem', 'document+mem:// substrate should be mem, got ${ms.backend}'
	assert ms.model == 'document', 'document+mem:// must select the document model'

	// bare mem:// → subtree default.
	h2 := store_open_impl('mem://', '', '', false, true, map[string]string{})
	ms2 := store_lookup(store_handle_of(h2) or { panic('no handle for mem://') }) or {
		panic('no store for mem://')
	}
	assert ms2.model == '', 'bare mem:// must be the subtree default, got model=${ms2.model}'

	// the legacy [opts model=document] surface still selects document (back-compat).
	h3 := store_open_impl('mem://', '', '', false, true, {
		'model': 'document'
	})
	ms3 := store_lookup(store_handle_of(h3) or { panic('no handle for opts mem://') }) or {
		panic('no store for opts mem://')
	}
	assert ms3.model == 'document', '[opts model=document] must still select document'
}
