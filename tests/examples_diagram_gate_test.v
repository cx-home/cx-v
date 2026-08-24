// examples_diagram_gate_test.v — the EXAMPLES-DIAGRAM GATE.
//
// RULED: EDL-1 / EDL-1a (#913 addendum + the #910 lane suggestion, homed;
// ledger/rulings_2026_08_21_diagram_vector_data.md): every shipped
// `examples/*.cx` (and `examples/comparisons/*.cx`) diagrams with CONTENT,
// not exit codes. Exit-code sweeps measurably lie here — the #913 blanks
// (an 8pt empty svg canvas for every data example) all exited 0, and both
// #910 (the empty erDiagram placeholder) and #913 would have been caught
// at a release by these assertions.
//
// HERMETIC: the mermaid assertion runs `render_diagram` and the vector
// assertion runs `[$diagram:of-source … "dot"]` — the exact DOT text the
// svg/png hop feeds graphviz — never the graphviz subprocess, so the gate
// needs no `dot` installed.
//
// Assertions per example (the ruled content bar):
//   * mermaid renders, carries at least one node line and one edge, and is
//     never the collapsed single-`…`-leaf shape (#913's flowchart symptom);
//   * the DOT text declares at least one node (#913's empty-canvas symptom);
//   * a doc whose code-diagram classification is the ERD is POPULATED —
//     never the bare `erDiagram` placeholder (#910's symptom).
//
// ZERO exclusions. #914 (the TI-1 table image) landed, so table-carrying
// docs render like every other example and the EDL-1a carve-out that named
// them is GONE. Per TI-1 point 5 this gate, green over the FULL corpus with
// no exclusions, IS that issue's completion criterion — so the gate asserts
// it directly (`ran == files.len`) and keeps no skip path that could drift.

module main

import encoding.base64
import cx
import code
import os
import platform as _

fn examples_dir() string {
	return os.real_path(os.join_path(os.dir(@FILE), '..', '..', 'examples'))
}

fn gate_cx_string_literal(s string) string {
	return '"' + s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n') + '"'
}

// gate_render_dot — the of-source DOT text through the engine, base64-clad
// so the comparison is over bytes (the diagram_of_source_test pattern).
fn gate_render_dot(src string) !string {
	prog := "[?lib 'cx-stdlib/diagram' as=diagram]\n" +
		"[?lib 'cx-stdlib/bytes' as=bytes]\n" +
		'[\$bytes:to-base64 [\$bytes:from-string-utf8 [\$diagram:of-source ${gate_cx_string_literal(src)} "dot" detail="min"]]]'
	out := code.eval_code('', prog, 'text')!
	trimmed := out.trim_space().trim("'")
	return base64.decode_str(trimmed)
}

fn gate_example_files() []string {
	mut files := []string{}
	dir := examples_dir()
	for f in os.ls(dir) or { [] } {
		if f.ends_with('.cx') {
			files << f
		}
	}
	for f in os.ls(os.join_path(dir, 'comparisons')) or { [] } {
		if f.ends_with('.cx') {
			files << os.join_path('comparisons', f)
		}
	}
	files.sort()
	return files
}

fn test_every_shipped_example_diagrams_with_content() {
	files := gate_example_files()
	assert files.len >= 20, 'expected the shipped example corpus, found ${files.len} files'
	mut failures := []string{}
	mut ran := 0
	for rel in files {
		src := os.read_file(os.join_path(examples_dir(), rel)) or {
			failures << '${rel}: read: ${err}'
			continue
		}
		// ── mermaid: renders, with nodes and edges, never the collapse ──
		mm := code.render_diagram(src, 'mermaid') or {
			failures << '${rel}: mermaid render refused: ${err.msg()}'
			continue
		}
		if mm.contains('["…"]') {
			failures << '${rel}: mermaid collapsed to an ellipsis leaf (the #913 flowchart symptom)'
		}
		if !mm.contains('["') {
			// At least one node line. NOT an edge assertion: a flat document
			// of childless elements (logs.cx logfmt lines, books.cx's shelf)
			// legitimately renders nodes with no containment edges.
			failures << '${rel}: mermaid render carries no node'
		}
		// ── the DOT text (the svg/png stdin): at least one declared node ──
		dot := gate_render_dot(src) or {
			failures << '${rel}: of-source dot refused: ${err.msg()}'
			continue
		}
		if !dot.contains(' [label=') {
			failures << '${rel}: DOT text declares no node (the #913 empty-canvas symptom)'
		}
		// ── the ERD lane: when a doc classifies as ERD it must be populated ──
		erd := code.code_diagram(src) or {
			failures << '${rel}: code-diagram refused: ${err.msg()}'
			continue
		}
		if erd.contains('erDiagram') && erd.trim_space() == 'erDiagram' {
			failures << '${rel}: empty erDiagram placeholder (the #910 symptom)'
		}
		ran++
	}
	if failures.len > 0 {
		println('${failures.len} examples-diagram gate failure(s):')
		for f in failures {
			println('  ${f}')
		}
	}
	assert failures.len == 0
	// RULED: TI-1 point 5 — the FULL corpus, no exclusions. Equality, not a
	// floor: a re-introduced skip path fails HERE rather than silently
	// shrinking what the gate covers.
	assert ran == files.len, 'expected the full corpus asserted, ran ${ran} of ${files.len}'
}
