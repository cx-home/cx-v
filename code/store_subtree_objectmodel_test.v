module code

import cx
import cxstore

// store_subtree_objectmodel_test.v — #129 foundation evidence. Proves the
// vcx/cxstore subtree object-graph engine delivers, at the code-module
// integration boundary (with render_canonical, the store's hash input), the
// three properties the subtree storage model must guarantee:
//
//   (1) canonical-text round-trip — a doc reconstructed from the object graph
//       re-renders to byte-identical canonical text, so the content hash
//       (cx_text_hash(render_canonical(...))) is preserved. This is the
//       "render_canonical <-> emit_node_bin" reconciliation that store_cxpack.v
//       flagged as the blocker; the probe cases show it holds.
//   (2) cross-document subtree dedup — an identical subtree in two unrelated
//       documents shares object(s).
//   (3) modify structural sharing — a one-field change reuses every untouched
//       subtree object; only the path from the change to the root is new.
//
// This validates the engine before the [$store] backend wiring (the next brick).

// obj_keys returns the set of object-hash keys produced by content-addressing a
// document into a fresh sink.
fn obj_keys(src string) map[string]bool {
	mut keys := map[string]bool{}
	doc := cx.parse(src) or { return keys }
	mut sink := cxstore.ObjectSink{}
	cxstore.store_document(mut sink, doc, cxstore.default_fanout)
	for k, _ in sink.objects {
		keys[k] = true
	}
	return keys
}

fn intersect_count(a map[string]bool, b map[string]bool) int {
	mut n := 0
	for k, _ in a {
		if k in b {
			n++
		}
	}
	return n
}

// (1) canonical-text round-trip across varied + adversarial constructs.
fn probe_rc_roundtrip(src string) (string, string) {
	doc := cx.parse(src) or { return 'PARSE_ERR: ${err}', '' }
	if doc.elements.len == 0 {
		return 'NO_ELEMENTS', ''
	}
	c0 := render_canonical(doc.elements[0])
	mut sink := cxstore.ObjectSink{}
	root := cxstore.store_document(mut sink, doc, cxstore.default_fanout)
	getter := fn [sink] (h []u8) ?[]u8 {
		return sink.get(h)
	}
	doc2 := cxstore.load_document_from(getter, root) or { return c0, 'LOAD_ERR: ${err}' }
	if doc2.elements.len == 0 {
		return c0, 'NO_ELEMENTS_AFTER'
	}
	c1 := render_canonical(doc2.elements[0])
	return c0, c1
}

fn test_subtree_canonical_text_roundtrip() {
	cases := [
		'[note id="x" [title "Hello"] [body "first"]]',
		'[db [meta [version 1] [name "store"]] [rec [id 1] [name "alice"] [tags [t "a"] [t "b"]]]]',
		'[m a=1 b="two" c=true [child [leaf 3.14]]]',
		'[x p="a b" q=\'single\' n=42 f=1.5 t=true]',
		'[doc [empty] [nested [deep [deeper "v"]]]]',
		'[el xmlns:b="urn:b" xmlns:a="urn:a" a:x="1" b:y="2"]',
		'[n neg=-5 z=0 f=-3.14 e=1.5e10 big=123456789012345678]',
		'[s a="he said \\"hi\\"" b="line1\\nline2" c="it\'s" d="tab\\there"]',
		'[p "leading text" [b "bold"] "trailing text"]',
		'[u name="café" emoji="🜨" cjk="日本語"]',
		'[doc [; a comment ] [keep "v"]]',
		'[f flag enabled="" zero=0]',
	]
	mut failures := []string{}
	for src in cases {
		c0, c1 := probe_rc_roundtrip(src)
		if c0 != c1 {
			failures << 'MISMATCH\n  src: ${src}\n  c0:  ${c0}\n  c1:  ${c1}'
		}
	}
	if failures.len > 0 {
		assert false, '\n' + failures.join('\n---\n')
	}
}

// (2) cross-document subtree dedup: an identical subtree in two unrelated docs
// shares object(s).
fn test_cross_doc_subtree_dedup() {
	d1 := '[doc1 [unique1 "u1"] [common [k "same"] [k2 "same2"]]]'
	d2 := '[doc2 [unique2 "u2"] [common [k "same"] [k2 "same2"]]]'
	common := intersect_count(obj_keys(d1), obj_keys(d2))
	assert common > 0, 'expected common subtree objects across unrelated docs, got 0'
}

// (3) modify structural sharing: a one-field deep change reuses untouched
// subtree objects — only the changed path is new.
fn test_modify_structural_sharing() {
	// A large untouched subtree (`keep`) + one small mutable field (`mut/v`), so
	// reuse dominates: only the v->root path should be rehashed.
	d := '[doc [keep [a "1"] [b "2"] [c "3"] [d "4"] [e "5"] [f "6"]] [mut [v "ORIGINAL"]]]'
	dp := '[doc [keep [a "1"] [b "2"] [c "3"] [d "4"] [e "5"] [f "6"]] [mut [v "CHANGED"]]]'

	d_alone := obj_keys(d)
	dp_alone := obj_keys(dp)

	// the untouched `keep` subtree contributes common objects to both versions.
	common := intersect_count(d_alone, dp_alone)
	assert common >= 3, 'expected the untouched subtree to share >=3 objects, got ${common}'

	// storing D' on top of D adds only the changed path (b/y + ancestors), far
	// fewer than D' has in total — i.e. untouched subtrees are reused, not rewritten.
	doc_d := cx.parse(d) or {
		assert false, 'parse d'
		return
	}
	doc_dp := cx.parse(dp) or {
		assert false, 'parse dp'
		return
	}
	mut sink := cxstore.ObjectSink{}
	cxstore.store_document(mut sink, doc_d, cxstore.default_fanout)
	before := sink.objects.len
	cxstore.store_document(mut sink, doc_dp, cxstore.default_fanout)
	added := sink.objects.len - before
	assert added < dp_alone.len, 'no reuse: D\' added ${added} objects, has ${dp_alone.len} total'
	// the changed path is small; most of D' was reused.
	assert added < common, 'expected fewer new objects (${added}) than common/reused (${common})'
}
