// resolved_projection_test.v — the ANC-1 resolve-pass gate (#877).
//
// ast.md "Parse AST vs. Resolved AST" (ruling ANC-1, 2026-08-20): the
// evaluator's document seams and every LOSSY projection work from the
// Resolved AST — aliases expanded, merges applied — matching strict
// canonical's resolved form. The LOSSLESS lanes (default CX output, the
// XML cx:* carry per conversions.md, --lossless sidecar modes) preserve
// authored anchors/merges as presentation. This gate pins both halves so
// neither can silently regress to the pre-#877 world where an alias
// projected to nothing and a merge inherited nothing.
module main

import cx
import code

// One document exercising all three shapes: an anchor definition, a bare
// alias, and a merge host with a local attribute.
const src = '[menu
  [item &base price=9.5 [qty 1]]
  [*base]
  [special *base name=deluxe]]'

fn test_lossy_json_resolves() {
	out := cx.convert_by_name(src, 'cx', 'json', false) or { panic(err) }
	// the alias expands to a second full item …
	assert out.count('"qty": 1') == 3, 'alias + merge must both carry qty: ${out}'
	// … and the merge host inherits the anchor attribute alongside its own
	assert out.contains('"name": "deluxe"')
	assert !out.contains('cx:'), 'no carry markers on a lossy lane: ${out}'
}

fn test_lossy_yaml_resolves() {
	out := cx.convert_by_name(src, 'cx', 'yaml', false) or { panic(err) }
	assert out.count('qty: 1') == 3, 'yaml projection must resolve: ${out}'
	assert out.contains('name: deluxe')
}

fn test_lossy_csv_resolves() {
	// a flat table whose second row is an alias of the first
	tbl := '[table [row &r a=1 b=2] [*r]]'
	out := cx.to_csv(tbl) or { panic(err) }
	assert out.count('1,2') == 2, 'the aliased row must project as a full row: ${out}'
}

fn test_default_cx_preserves_carry() {
	out := cx.convert_by_name(src, 'cx', 'cx', false) or { panic(err) }
	assert out.contains('&base'), 'default CX output keeps the authored anchor'
	assert out.contains('[*base]'), 'default CX output keeps the authored alias'
	assert out.contains('*base'), 'default CX output keeps the authored merge'
}

fn test_xml_keeps_the_conversions_md_carry() {
	out := cx.convert_by_name(src, 'cx', 'xml', false) or { panic(err) }
	assert out.contains('cx:anchor="base"'), 'XML is the lossless carry twin: ${out}'
	assert out.contains('<cx:alias name="base"/>')
	assert out.contains('cx:merge="base"')
}

fn test_lossless_json_preserves() {
	out := cx.convert_by_name(src, 'cx', 'json', true) or { panic(err) }
	// the bijective sidecar mode must NOT resolve — one deluxe-free base
	// item plus the alias/merge carry, not three expanded copies
	assert out.count('9.5') < 3, '--lossless keeps the authored sharing: ${out}'
}

fn test_doc_binding_is_semantic() {
	// CXPath over $doc counts the alias as its referent (the pre-#877
	// engine answered 2: the alias child projected to nothing)
	out := code.eval_code(src, '[$count $doc/*]', 'cx') or { panic(err) }
	assert out.trim_space() == '3', 'resolved \$doc: ${out}'
	// and a merge host answers for its inherited attribute
	price := code.eval_code(src, '[$string $doc/special@price]', 'cx') or { panic(err) }
	assert price.contains('9.5'), 'merge-inherited attr via \$doc: ${price}'
}

fn test_dangling_alias_refuses_on_lossy() {
	// no resolved form exists → the lossy projection refuses loudly
	// (same contract as strict canonical, canonical.md §2.8)
	if _ := cx.convert_by_name('[m [*ghost]]', 'cx', 'json', false) {
		panic('dangling alias must refuse on a lossy lane')
	}
}
