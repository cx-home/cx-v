module main

import cx

// C19 — XPath 4.0 JSON function surface additions.
//   parse-json (existing) → C-row baseline
//   serialize-json (existing) → C-row baseline
//   json-to-xml (new at v0.7.0)
//   xml-to-json (new at v0.7.0)
//   json-doc (new at v0.7.0 — equivalent to parse-json until v0.8.0 file: module)

fn test_c19_json_to_xml_simple() {
	out := cx.eval_cxl('[p]',
		"[?=[?json-to-xml ['{\"a\": 1}']]]", '') or { panic('${err}') }
	assert out.contains('<a>'), 'expected <a> in XML output, got: "${out}"'
	assert out.contains('1'), 'expected value 1 in XML output, got: "${out}"'
}

fn test_c19_xml_to_json_simple() {
	out := cx.eval_cxl('[p]',
		"[?=[?xml-to-json ['<a>1</a>']]]", '') or { panic('${err}') }
	assert out.contains('"a"'), 'expected "a" key, got: "${out}"'
}

fn test_c19_json_doc_aliases_parse_json() {
	// json-doc and parse-json have the same parsed-value shape per
	// XPath 4.0 §G. At v0.7.0 json-doc accepts content directly
	// (URI fetcher is v0.8.0 file: module).
	out := cx.eval_cxl('[p]',
		"[?=[?json-doc ['{\"x\": 42}']]]", '') or { panic('${err}') }
	assert out.contains('42'), 'expected 42 in output, got: "${out}"'
}

// C25 — Misc XPath 4.0 §G additions.

fn test_c25_all_different_distinct_via_path() {
	out := cx.eval_cxl('[seq [n 1] [n 2] [n 3]]',
		"[?=[?all-different [//n]]]", '') or { panic('${err}') }
	assert out == 'true', 'expected true, got: "${out}"'
}

fn test_c25_all_different_dup_via_path() {
	out := cx.eval_cxl('[seq [n 1] [n 1]]',
		"[?=[?all-different [//n]]]", '') or { panic('${err}') }
	assert out == 'false', 'expected false, got: "${out}"'
}

fn test_c25_characters_count() {
	// Use ?characters output's length via ?count to avoid nested-
	// directive in ?for :in slot (slot evaluator parses the slot
	// before dispatching; nested directives there are a separate
	// parser interaction). Slot-friendly form: nested directive
	// inside ?= interpolation works fine.
	out := cx.eval_cxl('[p]',
		"[?=[?count [[?characters ['abc']]]]]", '') or { panic('${err}') }
	assert out == '3', 'expected 3 chars, got: "${out}"'
}
