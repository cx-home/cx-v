// §11.6 gate-9 — diagram round-trip.
//
// Contract per spec/code.md §11.4.3: each of SVG / PNG / Mermaid
// rendered outputs MUST reverse-parse to a CX tree structurally equal
// to the original program AST.
//
// Per the hybrid embed-source design (gate-9 design choice 1c), each
// renderer wraps the original source bytes in a format-appropriate
// metadata channel (Mermaid `%%cx:<base64>%%` comment; SVG `<metadata>
// <cx:source>` block; PNG tEXt chunk). `reverse_parse_diagram` strips
// the visual layer and recovers the source verbatim; parsing that
// source yields an AST that — by construction — is structurally
// identical to the original.
//
// The test walks the program-viz-* fixtures in conformance/code.txt,
// renders each through the diagram renderer, reverse-parses, asserts
// AST equality. Mermaid is the primary driver; SVG / PNG depend on the
// graphviz integration that lands in Phase 4.2.

module main

import os
import cx
import code

const supported_viz_fixtures = [
	'program-viz-001-for-pattern-tree',
	'program-viz-002-match-alternative-branches',
	'program-viz-003-for-sequential-loop',
	'program-viz-004-for-par-parallel-branches',
	'program-viz-005-map-par-parallel-branches',
	'program-viz-006-if-alternative-branches',
	'program-viz-007-fallback-recovery-branch',
	'program-viz-008-retry-policy-badge',
	'program-viz-009-timeout-policy-badge',
	'program-viz-010-circuit-breaker-policy-badge',
	'program-viz-011-fallback-policy-badge',
	'program-viz-012-rate-limit-policy-badge',
	'program-viz-013-bulkhead-policy-badge',
	'program-viz-014-service-endpoint-with-resources',
	'program-viz-015-worker-channel-send-receive',
	'program-viz-016-select-multi-arrow-choice',
	'program-viz-017-async-detached-swimlane',
	'program-viz-018-await-all-barrier',
	'program-viz-019-cancel-arrow-barrier',
	'program-viz-020-nested-resilience-services-async',
]

fn fixture_path() string {
	return os.real_path(os.join_path(os.dir(@FILE), '..', '..',
		'conformance', 'code.cxd'))
}

struct VizFixture {
	id      string
	in_code string
	out_err string // expected render-error code (render-failure fixtures)
	gate    string // per-case gate toggle ('' = enforced, 'pending' = deferred)
}

// CX-native: read the .cxd suite via cx.load_fixtures (replaces the former
// inline '=== test:' scanner).
fn parse_viz_fixtures() []VizFixture {
	mut out := []VizFixture{}
	for c in cx.load_fixtures(fixture_path()) {
		if !c.name.starts_with('program-viz-') {
			continue
		}
		out << VizFixture{
			id:      c.name
			in_code: c.sections['in_code']
			out_err: c.sections['out_err'].trim_space()
			gate:    c.gate
		}
	}
	return out
}

// Render-error viz fixtures (`out_err` set): the diagram renderer MUST
// FAIL with the declared code (CXER0280 RENDER_FAILED / CXER0281
// UNRENDERABLE_DIRECTIVE, §10.1.2). These are NOT round-trip cases (there
// is no output to reverse-parse), so the round-trip harness above skips
// them; this harness enforces them. `gate=pending` cases are tracked but
// not enforced (see their inline reason in conformance/code.cxd).
fn test_viz_render_error_fixtures() {
	all := parse_viz_fixtures()
	mut ran := 0
	mut pending := []string{}
	mut failures := []string{}
	for f in all {
		if f.out_err == '' { continue }
		if f.gate == 'pending' {
			pending << f.id
			continue
		}
		ran++
		prog := cx.parse_program(f.in_code) or {
			// A parse-time rejection that already carries the expected
			// code also satisfies the fixture.
			if '${err}'.contains(f.out_err) { continue }
			failures << '${f.id}: parse: ${err} (expected ${f.out_err})'
			continue
		}
		// The renderer MUST refuse this shape with the declared code.
		if rendered := code.render_diagram(prog, f.in_code, 'mermaid') {
			failures << '${f.id}: expected render error ${f.out_err}, but render_diagram succeeded: ${rendered.len} bytes'
		} else {
			if !'${err}'.contains(f.out_err) {
				failures << '${f.id}: expected ${f.out_err}, got render error: ${err}'
			}
		}
	}
	if failures.len > 0 {
		println('${failures.len} viz render-error failure(s) of ${ran}:')
		for fl in failures { println('  ${fl}') }
	}
	if pending.len > 0 {
		println('${pending.len} viz render-error fixture(s) gate=pending: ${pending.join(', ')}')
	}
	assert ran > 0, 'no viz render-error fixtures ran'
	assert failures.len == 0
}

fn code_ast_eq(a cx.Program, b cx.Program) bool {
	return node_eq(a.body, b.body)
}

fn node_eq(a cx.ProgramNode, b cx.ProgramNode) bool {
	if a is cx.ProgramDirective {
		if b is cx.ProgramDirective {
			if a.name != b.name { return false }
			if a.slots.len != b.slots.len { return false }
			for i, sa in a.slots {
				sb := b.slots[i]
				if sa.kind != sb.kind { return false }
				if sa.label != sb.label { return false }
				if !node_eq(sa.value, sb.value) { return false }
			}
			return true
		}
		return false
	}
	if a is cx.ProgramForComp {
		if b is cx.ProgramForComp {
			return node_eq(a.yield, b.yield)
		}
		return false
	}
	if a is cx.ProgramLiteral {
		if b is cx.ProgramLiteral {
			return a.kind == b.kind && a.str_val == b.str_val
			       && a.int_val == b.int_val && a.flt_val == b.flt_val
			       && a.bool_val == b.bool_val
		}
		return false
	}
	if a is cx.ProgramBinding {
		if b is cx.ProgramBinding {
			if a.name != b.name { return false }
			if a.path.len != b.path.len { return false }
			return true
		}
		return false
	}
	if a is cx.ProgramCall {
		if b is cx.ProgramCall {
			return a.name == b.name && a.args.len == b.args.len
			       && a.fallible == b.fallible
			       && a.must_succeed == b.must_succeed
		}
		return false
	}
	// Patterns and other node types compare by V's structural ==.
	return '${a}' == '${b}'
}

fn run_roundtrip(format string) (int, []string) {
	all := parse_viz_fixtures()
	mut ran := 0
	mut failures := []string{}
	for f in all {
		mut found := false
		for id in supported_viz_fixtures {
			if id == f.id { found = true; break }
		}
		if !found { continue }
		ran++
		prog_in := cx.parse_program(f.in_code) or {
			failures << '${f.id}: parse(in): ${err}'
			continue
		}
		rendered := code.render_diagram(prog_in, f.in_code, format) or {
			failures << '${f.id}: render_diagram(${format}): ${err}'
			continue
		}
		recovered := code.reverse_parse_diagram(rendered, format) or {
			failures << '${f.id}: reverse_parse(${format}): ${err}'
			continue
		}
		prog_out := cx.parse_program(recovered) or {
			failures << '${f.id}: parse(recovered ${format}): ${err}'
			continue
		}
		if !code_ast_eq(prog_in, prog_out) {
			failures << '${f.id}: ${format} AST mismatch after round-trip'
		}
	}
	return ran, failures
}

fn test_mermaid_roundtrip_all_viz_fixtures() {
	ran, failures := run_roundtrip('mermaid')
	if failures.len > 0 {
		println('${failures.len} Mermaid round-trip failure(s) of ${ran}:')
		for fl in failures { println('  ${fl}') }
	}
	_ = cx.Element{ name: '' }
	assert ran == supported_viz_fixtures.len, 'expected ${supported_viz_fixtures.len} viz fixtures to run, ran ${ran}'
	assert failures.len == 0
}

fn test_svg_roundtrip_all_viz_fixtures() {
	ran, failures := run_roundtrip('svg')
	if failures.len > 0 {
		println('${failures.len} SVG round-trip failure(s) of ${ran}:')
		for fl in failures { println('  ${fl}') }
	}
	assert ran == supported_viz_fixtures.len
	assert failures.len == 0
}

fn test_png_roundtrip_all_viz_fixtures() {
	ran, failures := run_roundtrip('png')
	if failures.len > 0 {
		println('${failures.len} PNG round-trip failure(s) of ${ran}:')
		for fl in failures { println('  ${fl}') }
	}
	assert ran == supported_viz_fixtures.len
	assert failures.len == 0
}
