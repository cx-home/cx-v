module main

import os
import testenv

// #413 / #414 / #416 — [table] content in the conversion lanes, cx diff,
// and the --lossless flag surface, exercised through the compiled `cx`
// binary (the exact release-audit repros from the issues):
//
//   • #413a: CX→XML(--lossless)→CX preserves [table] rows exactly — the
//     pre-fix emitter dropped every row (`<formats cx:type="table"/>`).
//   • #414: cx diff reports the table-content difference and exits 1,
//     consistent with cx eq / cx hash — the pre-fix walker never read the
//     pooled TableData payload and reported "no changes" (exit 0).
//   • #416: --lossless is a hard error on lanes whose emitter ignores it
//     (json/yaml/toml/csv/…), never a silent no-op; csv emit of a
//     non-tabular document is a clear shape error, never blank output.

fn cx_bin() string {
	return testenv.cx_bin()
}

fn tmp_file(label string, content string) string {
	path := os.join_path(os.temp_dir(), 'cx_table_lanes_${label}_${os.getpid()}.cx')
	os.write_file(path, content) or { panic(err) }
	return path
}

const table_doc = '[doc title="guide"
  [h1 Tables]
  [formats [table[format::string input::bool output::bool]]
    CX   true true
    XML  true true
    JSON true true
  ]
]
'

const table_doc_row_lost = '[doc title="guide"
  [h1 Tables]
  [formats [table[format::string input::bool output::bool]]
    CX   true true
    XML  true true
  ]
]
'

const non_tabular_doc = '[server host=localhost
  [port 8080]
  [workers 4]
]
'

// ── #413a: lossless XML lane preserves the table ─────────────────────────────

fn test_lossless_xml_roundtrip_preserves_table() {
	f := tmp_file('rt_src', table_doc)
	defer { os.rm(f) or {} }
	xml_path := f + '.xml'
	rt_path := f + '.rt.cx'
	defer {
		os.rm(xml_path) or {}
		os.rm(rt_path) or {}
	}

	r1 := os.execute('${cx_bin()} --from=cx --to=xml --lossless ${f} > ${xml_path}')
	assert r1.exit_code == 0, 'to=xml --lossless failed: ${r1.output}'
	xml := os.read_file(xml_path) or { panic(err) }
	assert xml.contains('cx:cols="format::string input::bool output::bool"'), 'cx:cols sidecar missing: ${xml}'
	assert xml.contains('<cx:row><cx:cell>CX</cx:cell>'), 'row carriers missing: ${xml}'

	r2 := os.execute('${cx_bin()} --from=xml --to=cx ${xml_path} > ${rt_path}')
	assert r2.exit_code == 0, 'from=xml failed: ${r2.output}'

	req := os.execute('${cx_bin()} eq ${f} ${rt_path}')
	assert req.exit_code == 0, 'cx eq: round-trip lost content:\n${os.read_file(rt_path) or { '' }}'

	// hash agreement (the #413 repro compared canonical hashes)
	h1 := os.execute('${cx_bin()} hash ${f}')
	h2 := os.execute('${cx_bin()} hash ${rt_path}')
	assert h1.exit_code == 0 && h2.exit_code == 0
	assert h1.output.trim_space() == h2.output.trim_space(), 'canonical hashes differ after round-trip'
}

// ── #414: eq / hash / diff agree on table-content differences ────────────────

fn test_diff_reports_table_row_loss_and_agrees_with_eq() {
	a := tmp_file('diff_a', table_doc)
	b := tmp_file('diff_b', table_doc_row_lost)
	defer {
		os.rm(a) or {}
		os.rm(b) or {}
	}

	req := os.execute('${cx_bin()} eq ${a} ${b}')
	assert req.exit_code == 1, 'cx eq should see the row loss'

	rdiff := os.execute('${cx_bin()} diff --no-color ${a} ${b}')
	assert rdiff.exit_code == 1, 'cx diff must exit 1 when eq disagrees (#414 false-negative), got ${rdiff.exit_code}'
	assert rdiff.output.trim_space().len > 0, 'cx diff must print the table difference'
	assert rdiff.output.contains('JSON true true'), 'diff should name the removed row: ${rdiff.output}'

	rsum := os.execute('${cx_bin()} diff --format=summary ${a} ${b}')
	assert rsum.exit_code == 1
	assert rsum.output.contains('1 change(s)'), 'summary: ${rsum.output}'
}

fn test_diff_identical_tables_clean() {
	a := tmp_file('same_a', table_doc)
	b := tmp_file('same_b', table_doc)
	defer {
		os.rm(a) or {}
		os.rm(b) or {}
	}
	req := os.execute('${cx_bin()} eq ${a} ${b}')
	assert req.exit_code == 0
	rdiff := os.execute('${cx_bin()} diff --no-color ${a} ${b}')
	assert rdiff.exit_code == 0, 'identical tables must diff clean: ${rdiff.output}'
	assert rdiff.output.trim_space() == ''
}

// ── #416: --lossless is a hard error on unimplemented lanes ──────────────────
// #444 implemented the conversions.md §0.2 lossless JSON (`cx:type` sidecar)
// and YAML (`!!cx:T` tags) emits, so those lanes now ACCEPT the flag; TOML/MD
// lossless stays spec'd-unsupported and the delimited lanes have no lossless
// image — all keep the #416 hard error.

fn test_lossless_rejected_for_unsupported_targets() {
	f := tmp_file('lossless_src', non_tabular_doc)
	defer { os.rm(f) or {} }
	for target in ['toml', 'md', 'csv', 'tsv', 'psv'] {
		r := os.execute('${cx_bin()} --from=cx --to=${target} --lossless ${f}')
		assert r.exit_code != 0, '--lossless --to=${target} must be a hard error, got exit 0'
		assert r.output.contains('--lossless is not supported for --to=${target}'), 'missing rejection message for ${target}: ${r.output}'
		assert r.output.contains('supported: cx, json, xml, yaml'), 'rejection must name the supported lanes: ${r.output}'
	}
}

fn test_lossless_accepted_for_lossless_capable_targets() {
	f := tmp_file('lossless_ok', non_tabular_doc)
	defer { os.rm(f) or {} }
	for target in ['cx', 'xml', 'json', 'yaml'] {
		r := os.execute('${cx_bin()} --from=cx --to=${target} --lossless ${f}')
		assert r.exit_code == 0, '--lossless --to=${target} must be accepted (#444): ${r.output}'
	}
}

// ── #416: csv of a non-tabular document is a clear error, not blank output ───

fn test_csv_non_tabular_is_error_convert_lane() {
	f := tmp_file('csv_conv', non_tabular_doc)
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} --from=cx --to=csv ${f}')
	assert r.exit_code != 0, 'csv of non-tabular doc must error (was blank output, exit 0)'
	assert r.output.contains('does not flatten to a tabular shape'), 'error must explain the shape problem: ${r.output}'
}

fn test_csv_non_tabular_is_error_eval_lane() {
	// Attribute-less element children: the eval-render record extractor
	// finds a "record" but zero attribute columns — the pre-fix output was
	// a blank header + blank row with exit 0.
	f := tmp_file('csv_eval', '[server\n  [port 8080]\n  [workers 4]\n]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} --to=csv ${f}')
	assert r.exit_code != 0, 'bare --to=csv of non-tabular doc must error, got exit 0 with: "${r.output}"'
	assert r.output.contains('not tabular') || r.output.contains('tabular shape'), 'error must explain the shape problem: ${r.output}'
}

fn test_csv_non_tabular_is_error_eval_fallback_lane() {
	// `::u16` typed bodies fail the program parse, so this doc reaches csv
	// through the data-fallback convert pipeline — the emit diagnostic
	// (not the unrelated program-parse error) must surface.
	f := tmp_file('csv_evalfb', '[server host=0.0.0.0\n  [port ::u16 8080]\n]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} --to=csv ${f}')
	assert r.exit_code != 0, 'fallback --to=csv of non-tabular doc must error'
	assert r.output.contains('does not flatten to a tabular shape'), 'emit diagnostic must surface, got: ${r.output}'
}

fn test_csv_table_doc_still_works() {
	f := tmp_file('csv_table', '[users [table[name::string age::int]]\n  alice 30\n  bob 25\n]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} --from=cx --to=csv ${f}')
	assert r.exit_code == 0, 'table doc → csv must keep working: ${r.output}'
	assert r.output.contains('name,age'), 'header: ${r.output}'
	assert r.output.contains('alice,30'), 'row: ${r.output}'
}

// ── #443: AST-JSON projection carries the table payload ──────────────────────

const simple_table_doc = '[users [table[name::string age::int]]\n  alice 30\n  bob 25\n]\n'

fn test_ast_projection_carries_table_rows() {
	f := tmp_file('ast_tbl', simple_table_doc)
	defer { os.rm(f) or {} }
	// `cx --ast FILE` — the data-path AST projection (issue repro 1).
	r := os.execute('${cx_bin()} --ast ${f}')
	assert r.exit_code == 0, '--ast failed: ${r.output}'
	assert r.output.contains('"table":{"cols":[{"name":"name","dataType":"string"},{"name":"age","dataType":"int"}],"rows":[["alice",30],["bob",25]]}'), 'AST-JSON table payload missing: ${r.output}'
	assert !r.output.contains('"items":[]'), 'rowless items:[] must not survive for table elements: ${r.output}'
}

fn test_eval_json_render_carries_table_rows() {
	f := tmp_file('eval_json_tbl', simple_table_doc)
	defer { os.rm(f) or {} }
	// `cx FILE --json` — the eval render routes through the same AST-JSON
	// element encoding (issue repro 2).
	r := os.execute('${cx_bin()} ${f} --json')
	assert r.exit_code == 0, 'eval --json failed: ${r.output}'
	assert r.output.contains('"rows":[["alice",30],["bob",25]]'), 'eval --json dropped the rows: ${r.output}'
}

// ── #443: MD emit renders a [table] block as a GFM pipe table ────────────────

fn test_md_emit_renders_pipe_table() {
	f := tmp_file('md_tbl', simple_table_doc)
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} --from=cx --to=md ${f}')
	assert r.exit_code == 0, '--to=md failed: ${r.output}'
	assert r.output.contains('| name | age |'), 'header row missing: ${r.output}'
	assert r.output.contains('| --- | --- |'), 'separator row missing: ${r.output}'
	assert r.output.contains('| alice | 30 |'), 'data row missing: ${r.output}'
	assert r.output.contains('| bob | 25 |'), 'data row missing: ${r.output}'
	assert !r.output.contains('<!--'), 'the pre-fix HTML-comment fallback must be gone: ${r.output}'
}

