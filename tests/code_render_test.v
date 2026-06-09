module main

import code

// ── Phase 3.11 follow-up: json/yaml/xml/csv/tsv renderers ──────────────────
//
// Exercises the non-canonical output targets wired by `vcx/code/render.v`.
// Each format-specific test pins a documented shape per
// `spec/audits/code_abi_v1.md §3.1` and the renderer prose at the
// top of `vcx/code/render.v`.

// ── JSON: AST-JSON shape ──────────────────────────────────────────────────

fn test_json_simple_record() {
	out := code.eval_code('', '[ok value=1]', 'json') or {
		assert false, 'eval failed: ${err}'
		return
	}
	// `[ok value=1]` constructs the `ok` element with a `value` attribute
	// (the v0.8.0 spec surface; the retired `:value 1` colon-slot is gone,
	// D014). The AST-JSON wire form carries the attribute name.
	assert out.contains('"type":"Element"'), 'expected AST-JSON element shape; got: ${out}'
	assert out.contains('"name":"ok"'), 'expected ok element; got: ${out}'
	assert out.contains('"name":"value"'), 'expected value attribute; got: ${out}'
	assert !out.contains('__cx_slot'), 'slot prefix must not leak into JSON wire form: ${out}'
}

fn test_json_scalar() {
	out := code.eval_code('', '[?let [= \$x 42] \$x]', 'json') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out == '{"type":"Scalar","dataType":"int","value":42}', 'got: ${out}'
}

fn test_json_string_scalar() {
	out := code.eval_code('', '[?let [= \$x "hi"] \$x]', 'json') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out == '{"type":"Scalar","dataType":"string","value":"hi"}', 'got: ${out}'
}

fn test_json_sequence_literal_is_json_array() {
	out := code.eval_code('', '[?let [= \$x (1, 2, 3)] \$x]', 'json') or {
		assert false, 'eval failed: ${err}'
		return
	}
	// Sequence markers project to a JSON array of AST-JSON scalars.
	assert out.starts_with('['), 'expected JSON array; got: ${out}'
	assert out.ends_with(']'), 'expected JSON array; got: ${out}'
	assert out.contains('"value":1') && out.contains('"value":2') && out.contains('"value":3'),
		'expected three integer scalars; got: ${out}'
}

fn test_json_array_literal_is_json_array() {
	out := code.eval_code('', '[?let [= \$x [1, 2, 3]] \$x]', 'json') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.starts_with('['), 'expected JSON array; got: ${out}'
	assert out.contains('"value":1') && out.contains('"value":2') && out.contains('"value":3'),
		'expected three integer scalars; got: ${out}'
}

fn test_json_for_comp_multi_yield_is_json_array() {
	out := code.eval_code('', '[?for [in \$i (1, 2, 3)] [yield [item n=\$i]]]', 'json') or {
		assert false, 'eval failed: ${err}'
		return
	}
	// Multi-item top-level wrapper renders as a JSON array of items.
	assert out.starts_with('[{'), 'expected JSON array of objects; got: ${out}'
	assert out.contains('"name":"item"'), 'expected item element; got: ${out}'
}

// ── YAML: cx.emit_yaml via Document wrap ───────────────────────────────────

fn test_yaml_simple_record() {
	// Programs lift the rendered Element into a Document; emit_yaml
	// then maps the root element name to a YAML top-level key.
	out := code.eval_code('', '[ok value=1]', 'yaml') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('ok:'), 'expected ok: key; got: ${out}'
	assert out.contains('value'), 'expected value key; got: ${out}'
	assert out.contains('1'), 'expected 1; got: ${out}'
}

fn test_yaml_sequence_wraps_in_result_key() {
	out := code.eval_code('', '[?let [= \$x (1, 2, 3)] \$x]', 'yaml') or {
		assert false, 'eval failed: ${err}'
		return
	}
	// Bare sequence/array at top level wraps in a `result:` key so it
	// fits the YAML object-at-root convention. The Sequence body renders
	// as a YAML list.
	assert out.contains('result'), 'expected result wrapper; got: ${out}'
	assert out.contains('- 1') && out.contains('- 2') && out.contains('- 3'),
		'expected YAML list items; got: ${out}'
}

// ── XML: cx.emit_xml via Document wrap ─────────────────────────────────────

fn test_xml_simple_record() {
	out := code.eval_code('', '[ok value=1]', 'xml') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('<ok'), 'expected <ok> element; got: ${out}'
	assert out.contains('value="1"') || out.contains('<value>1</value>'),
		'expected value attr or child; got: ${out}'
}

fn test_xml_sequence_lifts_to_cx_seq() {
	out := code.eval_code('', '[?let [= \$x (1, 2, 3)] \$x]', 'xml') or {
		assert false, 'eval failed: ${err}'
		return
	}
	// Top-level sequence routes through emit_xml_sequence as `<cx:seq>`.
	assert out.contains('<cx:seq>'), 'expected cx:seq wrapper; got: ${out}'
	assert out.contains('<item>1</item>'), 'expected <item>1</item>; got: ${out}'
	assert out.contains('<item>2</item>'), 'got: ${out}'
	assert out.contains('<item>3</item>'), 'got: ${out}'
}

fn test_xml_array_lifts_to_cx_arr() {
	out := code.eval_code('', '[?let [= \$x [1, 2, 3]] \$x]', 'xml') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('<cx:arr>'), 'expected cx:arr wrapper; got: ${out}'
}

// ── CSV / TSV: sequence-of-records → header + rows ─────────────────────────

fn test_csv_records_emit_header_and_rows() {
	doc := '[doc [order id=1 status="open"] [order id=2 status="closed"]]'
	out := code.eval_code(doc, '[?for [order \$m] [yield \$m]]', 'csv') or {
		assert false, 'eval failed: ${err}'
		return
	}
	lines := out.split('\n')
	assert lines.len == 3, 'expected 3 lines (header + 2 rows); got: ${out}'
	assert lines[0] == 'id,status', 'expected header; got: ${lines[0]}'
	assert lines[1] == '1,open', 'expected first row; got: ${lines[1]}'
	assert lines[2] == '2,closed', 'expected second row; got: ${lines[2]}'
}

fn test_tsv_records_emit_header_and_rows() {
	doc := '[doc [order id=1 status="open"] [order id=2 status="closed"]]'
	out := code.eval_code(doc, '[?for [order \$m] [yield \$m]]', 'tsv') or {
		assert false, 'eval failed: ${err}'
		return
	}
	lines := out.split('\n')
	assert lines.len == 3, 'expected 3 lines; got: ${out}'
	assert lines[0] == 'id\tstatus', 'expected tab-separated header; got: ${lines[0]}'
	assert lines[1] == '1\topen', 'got: ${lines[1]}'
}

fn test_csv_escapes_fields_with_special_chars() {
	// Field containing comma → must be quoted (RFC 4180 §2.6).
	doc := '[doc [r v="a,b"] [r v="plain"]]'
	out := code.eval_code(doc, '[?for [r \$m] [yield \$m]]', 'csv') or {
		assert false, 'eval failed: ${err}'
		return
	}
	lines := out.split('\n')
	assert lines.len == 3, 'got: ${out}'
	assert lines[1] == '"a,b"', 'expected quoted-comma field; got: ${lines[1]}'
	assert lines[2] == 'plain', 'expected unquoted plain field; got: ${lines[2]}'
}

fn test_csv_rejects_non_tabular_shape() {
	if _ := code.eval_code('', '[?let [= \$x 42] \$x]', 'csv') {
		assert false, 'scalar result should not be tabular'
		return
	} else {
		assert err.msg().contains('cx-err:CXER0100')
		assert err.msg().contains('not a sequence of records')
	}
}

fn test_csv_rejects_pure_value_sequence() {
	// A sequence of integers is not a tabular shape — no records.
	if _ := code.eval_code('', '[?let [= \$x (1, 2, 3)] \$x]', 'csv') {
		assert false, 'sequence of scalars should be rejected for csv'
		return
	} else {
		assert err.msg().contains('cx-err:CXER0100')
		assert err.msg().contains('not a sequence of records')
	}
}
