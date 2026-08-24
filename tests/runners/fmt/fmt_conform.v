module main

// Runner for conformance/fmt.cxd (G6, authored at the I3 open of the
// partition campaign). Drives code.fmt_source — the program-faithful,
// fail-closed formatter behind `cx fmt FILE` — and enforces the
// formatting.md contract on every positive case:
//
//   1. byte-pinned output:  fmt(in_cx) == out_fmt (exact);
//   2. §1 purity:           cx_text_canonical(fmt(in_cx)) ==
//                           cx_text_canonical(in_cx) — same tree in,
//                           same tree out (presentation only);
//   3. §7 idempotence:      fmt(fmt(in_cx)) == fmt(in_cx).
//
// A case with out-err pins the fail-closed lane instead: fmt_source must
// refuse the input with an error containing the given code. Purity and
// idempotence are mechanical here (not per-case sections), so every new
// fixture added to fmt.cxd inherits the full invariant battery.

import os
import cx
import code
import platform as _
import fixtures

fn strip_blank_edges(s string) string {
	mut lines := s.split('\n')
	for lines.len > 0 && lines[0].trim_space() == '' { lines.delete(0) }
	for lines.len > 0 && lines[lines.len - 1].trim_space() == '' { lines.delete(lines.len - 1) }
	return lines.join('\n')
}

fn main() {
	if os.args.len < 2 {
		eprintln('Usage: fmt_conform <fmt.cxd>')
		exit(2)
	}
	path := os.args[1]
	mut passed := 0
	mut failed := 0
	for c in fixtures.load_fixtures(path) {
		input := strip_blank_edges(c.sections['in_cx'] or { '' })
		if 'out_err' in c.sections {
			expected_code := strip_blank_edges(c.sections['out_err'] or { '' })
			if out := code.fmt_source(input) {
				eprintln('FAIL ${c.name}: expected error containing "${expected_code}", got output: ${out}')
				failed++
			} else {
				if !err.msg().contains(expected_code) {
					eprintln('FAIL ${c.name}: expected error containing "${expected_code}", got: ${err.msg()}')
					failed++
				} else {
					passed++
				}
			}
			continue
		}
		expected := strip_blank_edges(c.sections['out_fmt'] or { '' })
		out := code.fmt_source(input) or {
			eprintln('FAIL ${c.name}: fmt_source error: ${err.msg()}')
			failed++
			continue
		}
		mut local_fail := false
		if strip_blank_edges(out) != expected {
			eprintln('FAIL ${c.name} (bytes):\n expected: ${expected.replace('\n', '\\n')}\n actual:   ${strip_blank_edges(out).replace('\n', '\\n')}')
			local_fail = true
		}
		// §1 purity — formatting never changes the data.
		canon_in := cx.cx_text_canonical(input) or {
			eprintln('FAIL ${c.name} (purity): canonical(in) error: ${err.msg()}')
			failed++
			continue
		}
		canon_out := cx.cx_text_canonical(out) or {
			eprintln('FAIL ${c.name} (purity): canonical(fmt) error: ${err.msg()}')
			failed++
			continue
		}
		if canon_in != canon_out {
			eprintln('FAIL ${c.name} (purity): canonical form changed\n before: ${canon_in.replace('\n', '\\n')}\n after:  ${canon_out.replace('\n', '\\n')}')
			local_fail = true
		}
		// §7 idempotence — the formatted form is a fixed point.
		twice := code.fmt_source(out) or {
			eprintln('FAIL ${c.name} (idempotence): second fmt errored: ${err.msg()}')
			failed++
			continue
		}
		if strip_blank_edges(twice) != strip_blank_edges(out) {
			eprintln('FAIL ${c.name} (idempotence): fmt(fmt(x)) != fmt(x)')
			local_fail = true
		}
		if local_fail {
			failed++
		} else {
			passed++
		}
	}
	println('${path}: ${passed} passed, ${failed} failed')
	if failed > 0 { exit(1) }
}
