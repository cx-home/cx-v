module main

import cx
import code

// v0.8.0 — codec registry spine (design D2/D6/D7, spec/03-approved/core/codec.md
// §1/§3/§6). Covers:
//   • the cx-layer node entry points (codec_parse_node / codec_emit_node /
//     *_bytes) over the single registry;
//   • the transparent DocumentNode carrier round-tripping single- AND
//     multi-root documents (D7);
//   • the in-program `[$cx:parse]` / `[$cx:emit]` / `[$xml:emit]` surface,
//     reached via `[?lib 'cx-stdlib/<codec>']` (synthesized module sources).

// ── cx-layer node entry points ───────────────────────────────────────────────

fn test_cx_parse_node_single_root_returns_element() {
	// #39 / codec.md §7: a SINGLE top-level node (no prolog/doctype) parses to
	// that node DIRECTLY, so it is navigable as the element (`$f@attr`) — not
	// wrapped in a DocumentNode that only the descendant axis can reach.
	n := cx.codec_parse_node('cx', '[a x=1]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n is cx.Element, 'single-root cx:parse must return the Element, got ${typeof(n).name}'
	assert (n as cx.Element).name == 'a'
}

fn test_cx_parse_node_multi_root_returns_document_node() {
	// A multi-top-level document keeps the transparent DocumentNode carrier
	// (navigate with `//`); this is the case no single-Node carrier represents.
	n := cx.codec_parse_node('cx', '[a 1]\n[b 2]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n is cx.DocumentNode, 'multi-root cx:parse must return a DocumentNode, got ${typeof(n).name}'
}

fn test_cx_single_root_roundtrip() {
	n := cx.codec_parse_node('cx', '[doc [a 1] [b 2]]') or {
		assert false, '${err}'
		return
	}
	out := cx.codec_emit_node('cx', n, false) or {
		assert false, '${err}'
		return
	}
	// re-parse(emit(t)) ≡ t (idempotent pivot, §3.1)
	n2 := cx.codec_parse_node('cx', out) or {
		assert false, '${err}'
		return
	}
	assert cx.codec_emit_node('cx', n2, false) or { '' } == out, 'not idempotent: ${out}'
	assert out.contains('[doc'), 'missing root: ${out}'
}

fn test_cx_multi_root_roundtrip() {
	// D7 — a genuinely multi-root document must round-trip; this is the case
	// no existing single-Node carrier (SequenceNode/Block) could represent.
	src := '[a 1]\n[b 2]'
	n := cx.codec_parse_node('cx', src) or {
		assert false, '${err}'
		return
	}
	out := cx.codec_emit_node('cx', n, false) or {
		assert false, '${err}'
		return
	}
	assert out.contains('[a 1]') && out.contains('[b 2]'), 'lost a root: ${out}'
}

fn test_cx_bytes_roundtrip() {
	n := cx.codec_parse_node('cx', '[a 1]') or {
		assert false, '${err}'
		return
	}
	b := cx.codec_emit_bytes_node('cx', n) or {
		assert false, '${err}'
		return
	}
	n2 := cx.codec_parse_bytes_node('cx', b) or {
		assert false, '${err}'
		return
	}
	assert cx.codec_emit_node('cx', n2, false) or { '' } == cx.codec_emit_node('cx', n, false) or { 'x' }
}

fn test_cross_codec_cx_to_xml() {
	n := cx.codec_parse_node('cx', '[foo [bar baz]]') or {
		assert false, '${err}'
		return
	}
	out := cx.codec_emit_node('xml', n, false) or {
		assert false, '${err}'
		return
	}
	assert out.contains('<foo>') && out.contains('<bar>baz</bar>'), 'bad xml: ${out}'
}

// ── in-program surface via [?lib] ─────────────────────────────────────────────

fn test_in_program_cx_roundtrip() {
	prog := "[?lib 'cx-stdlib/cx'] [\$cx:emit [\$cx:parse '[doc [a 1]]']]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('[doc'), 'in-program cx round-trip failed: ${out}'
}

fn test_in_program_cx_to_xml() {
	prog := "[?lib 'cx-stdlib/cx'] [?lib 'cx-stdlib/xml'] [\$xml:emit [\$cx:parse '[foo [bar baz]]']]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('<foo>') && out.contains('<bar>baz</bar>'), 'in-program xml emit failed: ${out}'
}

fn test_convert_sugar() {
	// S4 / codec.md §7 — [$convert SRC :from <codec> :to <codec>] over the
	// one registry. Codec names accepted as atom or string.
	//
	// JSON → CX is the lossless map/array/scalar read (item C, conversions.md
	// §4.1): `{"a":1}` parses to the CXDM Map `{a: 1}`, NOT a synthesised
	// `[a 1]` element — so json→xml emits the `<cx:map>` value image and
	// json→cx emits the map literal.
	out := code.eval_code('', "[\$convert '{\"a\":1}' :from json :to xml]", 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('<cx:map><entry key="a">1</entry></cx:map>'), 'convert json→xml failed: ${out}'
	out2 := code.eval_code('', "[\$convert '{\"a\":1}' :from :json :to :cx]", 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out2.contains('{a: 1}'), 'convert with atom names failed: ${out2}'
}

fn test_in_program_cx_to_html() {
	// S3 — html:serialize accepts the DocumentNode from [$cx:parse] (the
	// guide's cx→HTML path). Multi-root children serialize in order.
	prog := "[?lib 'cx-stdlib/cx'] [?lib 'cx-stdlib/html'] [\$html:serialize [\$cx:parse '[div [p hi] [p bye]]']]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('<div><p>hi</p><p>bye</p></div>'), 'in-program html serialize failed: ${out}'
}

fn test_cxpath_descends_into_parsed_document_node() {
	// A `[$cx:parse]` result is a transparent DocumentNode (D7). Path
	// expressions / iteration must descend into it as the root context —
	// the same unwrap `[?modify $doc //x]` already does — so an in-program
	// read→walk pipeline (the guide driver) can select with CXPath, exactly
	// like `--data`'s root-element binding.
	prog := "[?lib 'cx-stdlib/cx'] [?let [= \$d [\$cx:parse '[doc [section id=x title=T [child id=y]]]']] [?for [in \$s \$d//section] [yield [hit \$s@id \$s@title]]]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains("[hit 'x' 'T']"), 'CXPath did not descend into parsed DocumentNode: ${out}'
	// Child axis (`/child`) also unwraps the root DocumentNode (not fast-path
	// eligible, so it routes through the same node-set walker).
	pchild := "[?lib 'cx-stdlib/cx'] [?let [= \$d [\$cx:parse '[doc [section id=x]]']] [?for [in \$s \$d/section] [yield [child-hit \$s@id]]]]"
	out2 := code.eval_code('', pchild, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out2.contains("[child-hit 'x']"), 'child step did not descend into parsed DocumentNode: ${out2}'
}
