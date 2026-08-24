// code_diagram_golden_test.v — the DR-8 bit-for-bit gate for WAVE 3 of
// the diagram port (#889, RULED DRW3-1 —
// ledger/rulings_2026_08_20_diagram_wave3.md).
//
// The corpus under vcx/tests/testdata/code_diagram_golden/ was captured
// ONCE from the UNMODIFIED V playground emitter at the wave-3 head
// (vcx/tools/regen_code_diagram_golden regenerates it — regeneration
// after the cutover is GOLDEN MOVEMENT, forbidden except under a DR-8
// mini-ruling recorded in the ledger BEFORE the bytes move). Each id
// carries `<id>.source` beside `<id>.<level>.golden`, since this
// renderer's output embeds no source marker.
//
// The conformance runner (scripts/check_code_diagram_fixtures.py)
// compares node-SETS and edge-SETS; it cannot see line order, node-id
// minting order, or label bytes. This gate does.

module main

import os
import code
import platform as _

fn cdg_golden_dir() string {
	return os.real_path(os.join_path(os.dir(@FILE), 'testdata', 'code_diagram_golden'))
}

fn test_code_diagram_output_matches_captured_goldens_bit_for_bit() {
	dir := cdg_golden_dir()
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
		// <id>.<level>.golden
		stem := f.all_before_last('.golden')
		level := stem.all_after_last('.')
		id := stem.all_before_last('.')
		assert level in ['min', 'compact', 'full'], '${f}: unrecognised level'
		source := os.read_file(os.join_path(dir, '${id}.source')) or {
			failures << '${f}: missing source sidecar ${id}.source: ${err}'
			continue
		}
		rendered := code.code_diagram_with_level(source, code.parse_code_diagram_level(level)) or {
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
	assert ran >= 264, 'expected the full 88-source × 3-level corpus, ran ${ran}'
}
