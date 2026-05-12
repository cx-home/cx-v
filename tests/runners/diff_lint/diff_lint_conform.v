module main

// Runner for conformance/diff.txt and conformance/lint.txt fixture
// files. Mirrors conformance_run.v's section-parsing format but
// runs cx_text_diff / cx_text_lint instead of parse/emit.
//
// Per internal design record internal design record

import os
import cx

struct DiffLintCase {
mut:
	name string
	level string
	tags []string
	sections map[string]string
}

fn parse_suite(path string) []DiffLintCase {
	src := os.read_file(path) or {
		eprintln('could not read suite file: ${path}')
		return []
	}
	mut tests := []DiffLintCase{}
	mut cur := ?DiffLintCase(none)
	mut section := ?string(none)
	mut lines_buf := []string{}

	// Note: section flushing is inlined as for-body rather than a
	// closure. V closures capture mutated optionals by value, so
	// `cur = t` inside a closure does not propagate back to the
	// outer `cur` — same trap fixed in conformance_run.v session 5
	// where it had been silently passing every fixture mismatch.

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
			cur = DiffLintCase{ name: raw[9..].trim_space(), sections: map[string]string{} }
			section = none
			continue
		}
		if raw.starts_with('level:') {
			if mut t := cur { t.level = raw[6..].trim_space(); cur = t }
			continue
		}
		if raw.starts_with('tags:') {
			if mut t := cur { t.tags = raw[5..].trim_space().split(' '); cur = t }
			continue
		}
		if raw.starts_with('--- ') {
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
			continue
		}
		if raw.starts_with('#') || raw.trim_space() == '' {
			if section != none { lines_buf << raw }
			continue
		}
		if section != none { lines_buf << raw }
	}
	// flush trailing section
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
