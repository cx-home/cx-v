// diagram_mermaid_golden_test.v — the DR-8 bit-for-bit gate (#758,
// RULED DR-1…DR-11 2026-08-20).
//
// The corpus under vcx/tests/testdata/diagram_mermaid_golden/ was
// captured ONCE from the unmodified V reference renderer at the wave-1
// head (vcx/tools/regen_diagram_golden regenerates it — regeneration
// after the cutover is GOLDEN MOVEMENT, forbidden except under a DR-8
// mini-ruling recorded in the ledger BEFORE the bytes move). Every
// golden embeds its own source in the `%%cx:<base64>%%` marker, so the
// gate is self-contained:
//
//   for each *.golden: reverse_parse (mermaid extract) → source;
//   render_diagram(source, `mermaid:<detail-from-name>`) — the lift is internal;
//   assert BYTE EQUALITY with the golden.
//
// This doubles as the extract-mermaid gate: a broken extractor fails
// every file loudly.

module main

import os
import cx
import code
import platform as _

fn golden_dir() string {
	return os.real_path(os.join_path(os.dir(@FILE), 'testdata', 'diagram_mermaid_golden'))
}

fn test_mermaid_output_matches_captured_goldens_bit_for_bit() {
	dir := golden_dir()
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
		// <id>.<detail>.golden
		stem := f.all_before_last('.golden')
		detail := stem.all_after_last('.')
		assert detail in ['min', 'compact', 'full'], '${f}: unrecognised detail rung'
		source := code.reverse_parse_diagram(golden, 'mermaid') or {
			failures << '${f}: extract-mermaid: ${err}'
			continue
		}
		// The embedded source must still PARSE (a broken extractor
		// would otherwise sail past); the render lifts from it itself.
		cx.parse_program(source) or {
			failures << '${f}: parse(embedded source): ${err}'
			continue
		}
		rendered := code.render_diagram(source, 'mermaid:${detail}') or {
			failures << '${f}: render: ${err}'
			continue
		}
		if rendered != golden {
			mut first_diff := -1
			min_len := if rendered.len < golden.len { rendered.len } else { golden.len }
			for i in 0 .. min_len {
				if rendered[i] != golden[i] {
					first_diff = i
					break
				}
			}
			failures << '${f}: BYTE DIVERGENCE at offset ${first_diff} (rendered ${rendered.len}B vs golden ${golden.len}B)\n--- rendered ---\n${rendered}\n--- golden ---\n${golden}'
		}
		ran++
	}
	if failures.len > 0 {
		println('${failures.len} golden failure(s):')
		for fl in failures {
			println('  ${fl}')
		}
	}
	assert failures.len == 0
	assert ran >= 120, 'expected the full 40-source × 3-rung corpus, ran ${ran}'
}
