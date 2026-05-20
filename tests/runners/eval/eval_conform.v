module main

import os
import cx

// ── CXL conformance runner ───────────────────────────────────────────────────
//
// Runs the fixtures in conformance/eval.txt (and other CXL suites)
// through the V reference evaluator. Pattern mirrors
// `tests/runners/conformance/conformance_run.v` but with the CXL-
// specific fixture shape:
//
//   --- in_cx       input CX document
//   --- in_cxl      CXL program source
//   --- out_text    expected byte-exact rendered output (PASS path)
//   --- out_err     expected error-message substring (error path)
//
// Per spec/eval.md §9 (Conformance fixture layout) and ADR 0016 R8
// (V reference is the conformance target; per-binding evaluators
// MUST produce byte-identical output). New in v0.6.0 as part of
// ADR 0020 V-reference rollout.

struct Test {
mut:
	name     string
	level    string
	tags     []string
	pending  string
	sections map[string]string
}

fn parse_suite(path string) []Test {
	src := os.read_file(path) or {
		eprintln('could not read suite file: ${path}')
		return []
	}
	mut tests := []Test{}
	mut cur := ?Test(none)
	mut section := ?string(none)
	mut lines_buf := []string{}

	// Note: section-flush is inlined rather than expressed as a
	// closure. V closures capture mutable optionals by value, so a
	// closure that mutated `cur` would silently drop section data.
	// The conformance_run.v file documents this in detail.

	for raw in src.split_into_lines() {
		if raw.starts_with('=== test:') {
			if sec := section {
				for lines_buf.len > 0 && lines_buf[0].trim_space() == '' { lines_buf.delete(0) }
				for lines_buf.len > 0 && lines_buf[lines_buf.len-1].trim_space() == '' { lines_buf.delete(lines_buf.len-1) }
				val := lines_buf.join('\n')
				if mut t := cur {
					t.sections[sec] = val
					cur = t
				}
			}
			lines_buf = []string{}
			if t := cur { tests << t }
			cur = Test{
				name: raw[9..].trim_space()
				sections: map[string]string{}
			}
			section = none
		} else if raw.starts_with('level:') {
			if mut t := cur { t.level = raw[6..].trim_space(); cur = t }
		} else if raw.starts_with('tags:') {
			if mut t := cur { t.tags = raw[5..].trim_space().split_any(' \t'); cur = t }
		} else if raw.starts_with('pending:') {
			if mut t := cur { t.pending = raw[8..].trim_space(); cur = t }
		} else if raw.starts_with('--- ') {
			if sec := section {
				for lines_buf.len > 0 && lines_buf[0].trim_space() == '' { lines_buf.delete(0) }
				for lines_buf.len > 0 && lines_buf[lines_buf.len-1].trim_space() == '' { lines_buf.delete(lines_buf.len-1) }
				val := lines_buf.join('\n')
				if mut t := cur {
					t.sections[sec] = val
					cur = t
				}
			}
			lines_buf = []string{}
			if cur != none { section = raw[4..].trim_space() }
		} else {
			if section != none && cur != none {
				lines_buf << raw
			}
		}
	}
	if sec := section {
		for lines_buf.len > 0 && lines_buf[0].trim_space() == '' { lines_buf.delete(0) }
		for lines_buf.len > 0 && lines_buf[lines_buf.len-1].trim_space() == '' { lines_buf.delete(lines_buf.len-1) }
		val := lines_buf.join('\n')
		if mut t := cur {
			t.sections[sec] = val
			cur = t
		}
	}
	if t := cur { tests << t }
	return tests
}

fn run_test(t Test) []string {
	mut failures := []string{}
	in_cx  := t.sections['in_cx']  or { '' }
	in_cxl := t.sections['in_cxl'] or { '' }
	if in_cxl == '' {
		failures << 'fixture missing required `in_cxl` section'
		return failures
	}
	// CXL fixtures must supply in_cx (the input document). Empty
	// input is permitted only when the program contains no
	// CXPath that depends on document content.
	expected_text := t.sections['out_text'] or { '' }
	expected_err  := t.sections['out_err']  or { '' }

	if expected_err != '' {
		// Error-path fixture: evaluation MUST fail with a message
		// containing the expected_err substring.
		_ := cx.eval_cxl(in_cx, in_cxl, '') or {
			if err.msg().contains(expected_err.trim_space()) {
				return failures
			}
			failures << 'expected error containing "${expected_err}", got: "${err.msg()}"'
			return failures
		}
		failures << 'expected error containing "${expected_err}", but eval succeeded'
		return failures
	}

	// Success-path fixture: out_text must match byte-exact (after
	// normalizing trailing whitespace, which the fixture format
	// already strips during parse).
	got := cx.eval_cxl(in_cx, in_cxl, '') or {
		failures << 'eval failed: ${err.msg()}'
		return failures
	}
	got_norm := got.trim_right(' \t\n\r')
	want_norm := expected_text.trim_right(' \t\n\r')
	if got_norm != want_norm {
		failures << 'output mismatch'
		failures << '  expected: ${want_norm}'
		failures << '  got:      ${got_norm}'
		return failures
	}
	return failures
}

fn run_suite(path string) bool {
	tests := parse_suite(path)
	mut pass := 0
	mut fail := 0
	mut skip := 0
	for t in tests {
		if t.pending != '' {
			skip++
			println('SKIP ${t.name} (pending: ${t.pending})')
			continue
		}
		failures := run_test(t)
		if failures.len == 0 {
			pass++
			println('PASS ${t.name}')
		} else {
			fail++
			println('FAIL ${t.name}')
			for f in failures { println('     ${f}') }
		}
	}
	println('${path}: ${pass} passed, ${fail} failed, ${skip} skipped')
	return fail == 0
}

fn main() {
	args := os.args[1..]
	suites := if args.len > 0 {
		args
	} else {
		['../conformance/eval.txt']
	}
	mut all_pass := true
	for suite in suites {
		if !run_suite(suite) { all_pass = false }
	}
	if !all_pass { exit(1) }
}
