module main

import cx

// Pass-2 D-I — PEReference node in the DOCTYPE internal subset.
//
// Per spec/core/grammar.ebnf [38]/[39]/[68]: the DTD internal subset is
// stored VERBATIM; a parameter-entity reference `%name;` appears as a
// DeclSep and is kept as an OPAQUE PEReferenceNode — never expanded —
// so it round-trips unchanged to both CX and XML. This fixes the prior
// defect where a `%name;` broke the CX parse loop (and was silently
// dropped char-by-char by the XML reader).

const dtd_cx = "[!DOCTYPE doc [
  [!ENTITY % common 'name CDATA #IMPLIED']
  %common;
  [!ELEMENT doc (#PCDATA)]
]]
"

// ── 1. CX parse stores a PEReferenceNode in the int subset ───────────────────

fn test_cx_parse_keeps_pe_reference_node() {
	doc := cx.parse(dtd_cx) or {
		assert false, 'parse failed: ${err}'
		return
	}
	dt := doc.doctype or {
		assert false, 'no doctype parsed'
		return
	}
	mut pe_count := 0
	mut pe_name := ''
	for n in dt.int_subset {
		if n is cx.PEReferenceNode {
			pe_count++
			pe_name = n.name
		}
	}
	assert pe_count == 1, 'expected exactly 1 PEReferenceNode, got ${pe_count}'
	assert pe_name == 'common', 'expected PEReference name "common", got "${pe_name}"'
}

// ── 2. CX → CX round-trip preserves `%common;` verbatim ──────────────────────

fn test_cx_roundtrip_preserves_pe_reference() {
	doc := cx.parse(dtd_cx) or {
		assert false, 'parse failed: ${err}'
		return
	}
	out := cx.emit_cx(doc)
	assert out.contains('%common;'), 'PEReference dropped on CX emit: ${out}'
	// Re-parse the emitted text — idempotent round-trip.
	doc2 := cx.parse(out) or {
		assert false, 're-parse failed: ${err}'
		return
	}
	assert cx.emit_cx(doc2) == out, 'CX round-trip not idempotent'
}

// ── 3. CX → XML emits `%common;` (mirrors XML's PEReference) ─────────────────

fn test_cx_to_xml_emits_pe_reference() {
	doc := cx.parse(dtd_cx) or {
		assert false, 'parse failed: ${err}'
		return
	}
	xml := cx.emit_xml(doc)
	assert xml.contains('%common;'), 'PEReference not emitted to XML: ${xml}'
	assert xml.contains('<!DOCTYPE doc'), 'doctype not emitted to XML: ${xml}'
}

// ── 4. XML reader preserves a `%name;` PEReference (was dropped before) ──────

fn test_xml_reader_preserves_pe_reference() {
	xml_src := '<!DOCTYPE doc [
  <!ENTITY % common "name CDATA #IMPLIED">
  %common;
  <!ELEMENT doc (#PCDATA)>
]>
<doc/>'
	doc := cx.parse_xml(xml_src) or {
		assert false, 'xml parse failed: ${err}'
		return
	}
	dt := doc.doctype or {
		assert false, 'no doctype parsed from XML'
		return
	}
	mut found := false
	for n in dt.int_subset {
		if n is cx.PEReferenceNode {
			found = found || n.name == 'common'
		}
	}
	assert found, 'XML reader dropped the %common; PEReference'
}

// ── 5. A `%name;` with no semicolon is a parse error ─────────────────────────

fn test_cx_pe_reference_requires_semicolon() {
	bad := '[!DOCTYPE doc [\n  %common\n]]\n'
	if _ := cx.parse(bad) {
		assert false, 'expected parse error for unterminated PEReference'
	}
}
