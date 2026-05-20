// I1 v0.7.0: `cx upgrade-config` — migration tool for v0.6.0 → v0.7.0
// breaking changes per docs/migrations/v0.6-to-v0.7.md.
//
// Mechanical-fix coverage:
//   M2  cxl-version attribute → cx-eval-version (ADR 0022 §D6)
//   M3  spec/cxl.md / docs/CXL.md path-renames in CX-source comments
//        and link-references (best-effort textual replace; non-CX
//        code paths are out of scope)
//   M7  [ref ...] strict reservation lint (ADR 0003 D1 / GG12) —
//        flags non-conforming `[ref ...]` usages, suggests rename
//        to `[reference ...]` or any non-reserved element name
//
// Usage:
//   cx upgrade-config [--dry-run] [--lint-ref-elements] FILE...
//   cx upgrade-config --dry-run config.cx config-2.cx
//   cx upgrade-config --lint-ref-elements docs/
//
// Idempotent: running twice produces identical output to running once.
// `--dry-run` reports planned changes without writing files.
// `--lint-ref-elements` reports M7 candidates without rewriting (M7
// is a parser-strict reservation; mechanical fix requires authoring
// intent that the tool can't infer).

module main

import os
import strings

struct UpgradeOpts {
mut:
	dry_run            bool
	lint_ref_elements  bool
	paths              []string
}

fn parse_upgrade_opts(args []string) UpgradeOpts {
	mut o := UpgradeOpts{}
	for a in args {
		match a {
			'--dry-run'           { o.dry_run = true }
			'--lint-ref-elements' { o.lint_ref_elements = true }
			'--help', '-h' {
				print_upgrade_usage()
				exit(0)
			}
			else {
				if a.starts_with('--') {
					eprintln('cx upgrade-config: unknown option ${a}')
					exit(2)
				}
				o.paths << a
			}
		}
	}
	return o
}

fn print_upgrade_usage() {
	println('Usage: cx upgrade-config [--dry-run] [--lint-ref-elements] FILE...')
	println('')
	println('Migrate v0.6.0 CX source to v0.7.0 conventions:')
	println('  M2  cxl-version attribute → cx-eval-version')
	println('  M3  path-renames in CX-source comments (spec/cxl.md → spec/eval.md)')
	println('  M7  [ref ...] strict-reservation lint (with --lint-ref-elements)')
	println('')
	println('Flags:')
	println('  --dry-run             Report planned changes without writing files')
	println('  --lint-ref-elements   Add M7 lint scan (non-rewriting)')
	println('  --help                Show this message')
}

fn run_upgrade_config(args []string) {
	o := parse_upgrade_opts(args)
	if o.paths.len == 0 {
		print_upgrade_usage()
		exit(2)
	}
	mut total_files := 0
	mut total_edits := 0
	for path in o.paths {
		if os.is_dir(path) {
			files := collect_cx_files(path)
			for f in files {
				edits := upgrade_one_file(f, o)
				if edits > 0 {
					total_edits += edits
					total_files++
				}
			}
		} else {
			edits := upgrade_one_file(path, o)
			if edits > 0 {
				total_edits += edits
				total_files++
			}
		}
	}
	if o.dry_run {
		println('cx upgrade-config: dry-run — ${total_edits} edit(s) across ${total_files} file(s) would land')
	} else {
		println('cx upgrade-config: ${total_edits} edit(s) applied across ${total_files} file(s)')
	}
}

fn collect_cx_files(dir string) []string {
	mut out := []string{}
	entries := os.walk_ext(dir, '.cx')
	for e in entries { out << e }
	cxl_entries := os.walk_ext(dir, '.cxl')
	for e in cxl_entries { out << e }
	return out
}

fn upgrade_one_file(path string, o UpgradeOpts) int {
	original := os.read_file(path) or {
		eprintln('cx upgrade-config: cannot read "${path}": ${err}')
		return 0
	}
	mut content := original
	mut edits := 0
	// M2: cxl-version → cx-eval-version
	if content.contains('cxl-version=') {
		content = content.replace('cxl-version=', 'cx-eval-version=')
		edits += original.split('cxl-version=').len - 1
	}
	// M3: spec/cxl.md → spec/eval.md (in comments + link references)
	if content.contains('spec/cxl.md') {
		content = content.replace('spec/cxl.md', 'spec/eval.md')
		edits++
	}
	// M7: lint scan for non-conforming `[ref ...]` usages. Doesn't
	// rewrite (intent is ambiguous); reports findings to stderr.
	if o.lint_ref_elements {
		findings := scan_ref_element_issues(content)
		for f in findings {
			eprintln('${path}:${f.line}: M7 lint: ${f.message}')
		}
	}
	if edits > 0 && !o.dry_run {
		os.write_file(path, content) or {
			eprintln('cx upgrade-config: cannot write "${path}": ${err}')
			return 0
		}
	}
	if o.dry_run && edits > 0 {
		println('${path}: ${edits} edit(s) planned')
	} else if edits > 0 {
		println('${path}: ${edits} edit(s) applied')
	}
	return edits
}

struct RefLintFinding {
	line    int
	message string
}

// scan_ref_element_issues flags `[ref ...]` patterns that v0.7.0's
// strict reservation (ADR 0003 D1 / GG12) would reject. Heuristic
// only — the V parser is authoritative; this scan helps authors
// pre-emptively migrate.
fn scan_ref_element_issues(content string) []RefLintFinding {
	mut out := []RefLintFinding{}
	mut lineno := 0
	for line in content.split_into_lines() {
		lineno++
		// Find `[ref ` followed by something other than `@<Name>]`.
		mut s := line
		for {
			idx := s.index('[ref ') or { break }
			rest := s[idx + 5..]
			// Conforming form: `@<Name>]` (no attrs, no body)
			if rest.starts_with('@') {
				// Check it's bare-@id with no space/comma/= before `]`
				end := rest.index(']') or {
					s = rest
					continue
				}
				body := rest[1..end]
				if !body.contains(' ') && !body.contains('=') && !body.contains(',') {
					// Conforming
					s = rest[end..]
					continue
				}
			}
			out << RefLintFinding{
				line: lineno
				message: '`[ref ...]` non-conforming at v0.7.0 strict — rename to `[reference ...]` or wrap in a non-reserved element name (see docs/migrations/v0.6-to-v0.7.md §M7)'
			}
			s = rest
		}
	}
	return out
}
