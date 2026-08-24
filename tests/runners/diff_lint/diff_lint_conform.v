module main

// Runner for conformance/diff.txt and conformance/lint.txt fixture
// files. Mirrors conformance_run.v's section-parsing format but
// runs cx_text_diff / cx_text_lint instead of parse/emit.
//
// Per internal design record internal design record

import os
import cx
import fixtures

struct DiffLintCase {
mut:
	name string
	level string
	tags []string
	sections map[string]string
}

// strip_blank_edges reproduces the former flush() normalization: drop
// leading/trailing BLANK lines from a section body, applied to the loader's
// byte-exact body so the runner sees byte-identical sections vs the old .txt.
fn strip_blank_edges(s string) string {
	mut lines := s.split('\n')
	for lines.len > 0 && lines[0].trim_space() == '' { lines.delete(0) }
	for lines.len > 0 && lines[lines.len - 1].trim_space() == '' { lines.delete(lines.len - 1) }
	return lines.join('\n')
}

// parse_suite loads a .cxd suite (diff.cxd / lint.cxd) via fixtures.load_fixtures,
// replacing the bespoke `=== test:` / `--- key` scanner. level/tags come from
// the case attr / [tags] element; the runner keys into t.sections[name] by
// presence exactly as before.
fn parse_suite(path string) []DiffLintCase {
	mut tests := []DiffLintCase{}
	for c in fixtures.load_fixtures(path) {
		mut t := DiffLintCase{
			name:     c.name
			level:    c.level
			tags:     c.tags
			sections: map[string]string{}
		}
		for k, v in c.sections {
			t.sections[k] = strip_blank_edges(v)
		}
		tests << t
	}
	return tests
}

// ── diff runner ──────────────────────────────────────────────────────────────

fn run_diff_suite(path string) (int, int) {
	tests := parse_suite(path)
	mut passed := 0
	mut failed := 0
	for t in tests {
		a := t.sections['in_a'] or { '' }
		b := t.sections['in_b'] or { '' }
		expected_unified := t.sections['expected_unified'] or { '' }
		expected_summary := t.sections['expected_summary'] or { '' }

		changes := cx.cx_text_diff(a, b) or {
			eprintln('FAIL ${t.name}: cx_text_diff error: ${err}')
			failed++
			continue
		}
		actual_unified := cx.diff_render_unified(changes, false)
		actual_summary := cx.diff_render_summary(changes)

		mut local_fail := false
		// Compare unified output only when the fixture declares an
		// expected_unified section. Many summary-only fixtures
		// (where expected_summary is the only assertion) intentionally
		// omit expected_unified — the unified output is non-empty for
		// any non-equivalent pair, so requiring it == '' would be a
		// blanket failure for everything but the no-op case.
		if 'expected_unified' in t.sections {
			if actual_unified != expected_unified {
				eprintln('FAIL ${t.name} (unified):\n expected: ${expected_unified.replace('\n', '\\n')}\n actual: ${actual_unified.replace('\n', '\\n')}')
				local_fail = true
			}
		}
		if expected_summary != '' {
			if actual_summary != expected_summary {
				eprintln('FAIL ${t.name} (summary): expected "${expected_summary}", actual "${actual_summary}"')
				local_fail = true
			}
		}
		if local_fail {
			failed++
		} else {
			passed++
		}
	}
	return passed, failed
}

// ── lint runner ──────────────────────────────────────────────────────────────

fn run_lint_suite(path string) (int, int) {
	tests := parse_suite(path)
	mut passed := 0
	mut failed := 0
	for t in tests {
		input := t.sections['in_cx'] or { '' }
		expected_count_str := t.sections['expected_check_count'] or { '' }
		expected_check := t.sections['expected_check'] or { '' }
		expected_severity := t.sections['expected_severity'] or { '' }

		findings := cx.cx_text_lint(input, cx.LintOptions{ disabled: []string{}, only: '' }) or {
			eprintln('FAIL ${t.name}: cx_text_lint error: ${err}')
			failed++
			continue
		}

		mut local_fail := false
		if expected_count_str != '' {
			expected_count := expected_count_str.int()
			if findings.len != expected_count {
				eprintln('FAIL ${t.name}: expected ${expected_count} finding(s), got ${findings.len}')
				for f in findings {
					eprintln(' - ${f.check} ${cx.severity_str_pub(f.severity)}: ${f.message}')
				}
				local_fail = true
			}
		}
		if !local_fail && findings.len == 1 {
			if expected_check != '' && findings[0].check != expected_check {
				eprintln('FAIL ${t.name}: expected check ${expected_check}, got ${findings[0].check}')
				local_fail = true
			}
			if expected_severity != '' && cx.severity_str_pub(findings[0].severity) != expected_severity {
				eprintln('FAIL ${t.name}: expected severity ${expected_severity}, got ${cx.severity_str_pub(findings[0].severity)}')
				local_fail = true
			}
		}

		if local_fail {
			failed++
		} else {
			passed++
		}
	}
	return passed, failed
}

fn main() {
	args := os.args[1..]
	if args.len == 0 {
		eprintln('Usage: diff_lint_conform <diff|lint> <fixture.txt>')
		exit(2)
	}
	mode := args[0]
	path := args[1]
	mut p := 0
	mut f := 0
	if mode == 'diff' {
		p, f = run_diff_suite(path)
	} else if mode == 'lint' {
		p, f = run_lint_suite(path)
	} else {
		eprintln('unknown mode: ${mode}')
		exit(2)
	}
	println('${path}: ${p} passed, ${f} failed')
	if f > 0 { exit(1) }
}
