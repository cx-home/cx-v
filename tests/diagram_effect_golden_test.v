// diagram_effect_golden_test.v — the byte gate for the EFFECT/CAPABILITY
// graph (RULED: DGX-1 / DGX-1d,
// ledger/rulings_2026_08_21_diagram_capabilities.md).
//
// The corpus under vcx/tests/testdata/diagram_effect_golden/ is AUTHORED
// rather than captured: this kind never shipped in V, so the DR-8
// capture-then-cut-over instrument the other three corpora used does not
// exist for it. Every byte was read and reviewed at landing, and the
// corpus is frozen from that point under the same rule — regenerating it
// (vcx/tools/regen_diagram_effect_golden) is GOLDEN MOVEMENT, forbidden
// except under a mini-ruling recorded in the ledger BEFORE the bytes
// move.
//
// Each id carries `<id>.source` beside `<id>.<level>.golden`; this
// renderer embeds no source marker (it is in the `code-diagram` family).

module main

import os
import code
import platform as _

fn deg_golden_dir() string {
	return os.real_path(os.join_path(os.dir(@FILE), 'testdata', 'diagram_effect_golden'))
}

fn test_effect_graph_output_matches_the_authored_goldens_bit_for_bit() {
	dir := deg_golden_dir()
	mut files := os.ls(dir) or {
		assert false, 'golden dir missing: ${dir}'
		return
	}
	files.sort()
	mut ran := 0
	mut failures := []string{}
	for f in files {
		if !f.ends_with('.golden') {
			continue
		}
		golden := os.read_file(os.join_path(dir, f)) or {
			failures << '${f}: read: ${err}'
			continue
		}
		stem := f.all_before_last('.golden')
		level := stem.all_after_last('.')
		id := stem.all_before_last('.')
		assert level in ['min', 'compact', 'full'], '${f}: unrecognised level'
		source := os.read_file(os.join_path(dir, '${id}.source')) or {
			failures << '${f}: missing source sidecar ${id}.source: ${err}'
			continue
		}
		rendered := code.effect_graph_with_level(source, code.parse_code_diagram_level(level)) or {
			failures << '${f}: render: ${err}'
			continue
		}
		if rendered != golden {
			failures << '${f}: BYTE DIVERGENCE (rendered ${rendered.len}B vs golden ${golden.len}B)\n--- rendered ---\n${rendered}\n--- golden ---\n${golden}'
		}
		ran++
	}
	if failures.len > 0 {
		println('${failures.len} effect-graph golden failure(s):')
		for fl in failures {
			println('  ${fl}')
		}
	}
	assert failures.len == 0
	assert ran >= 87, 'expected the full 29-source × 3-rung corpus, ran ${ran}'
}

// The CLI and a CX program's own call must produce the same bytes for
// the same source — the same "one path, no twin" property #889 pinned
// for `of-source`. `cx code-diagram --view=effects` reaches
// `effect_graph_with_level`, which is what this asserts against the
// module entry the corpus was captured through.
fn test_effect_graph_default_level_is_compact() {
	src := '[\$io:read-file "/etc/hosts"]'
	via_default := code.effect_graph_with_level(src, code.parse_code_diagram_level('')) or {
		assert false, 'render: ${err}'
		return
	}
	via_compact := code.effect_graph_with_level(src, .compact) or {
		assert false, 'render: ${err}'
		return
	}
	assert via_default == via_compact
}

// DGX-1c is normative and this is its teeth at the OUTPUT level: a
// source carrying an opacity site must never render a graph that omits
// it. Checked here rather than only in the corpus so the property
// survives a corpus edit.
fn test_every_opacity_source_renders_an_unknown_edge() {
	cases := {
		'[?eval \$t]':                             'unk_eval'
		'[\$nosuchmod:go 1]':                      'unk_call'
		'[+ x=1 [\$io:read-file "/y"] 2]':         'unk_dynamic'
		"[?lib './x.cx' as=h]\n[ok]":              'unk_lib'
		'[\$journal:read \$j]':                    'unk_ring2'
	}
	for src, want in cases {
		out := code.effect_graph_with_level(src, .min) or {
			assert false, 'render ${src}: ${err}'
			continue
		}
		assert out.contains(want), 'source ${src} must render ${want}; got:\n${out}'
		assert out.contains('any granted capability'), 'source ${src} must carry the any-capability sink; got:\n${out}'
	}
}
