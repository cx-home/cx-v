module main

import os
import testenv

// #417 — the CLI help is generated from the ONE subcommand registry that
// also drives dispatch (vcx/cmd/main.v `subcommands`), the run surface and
// capability flags are documented, the --from/--to lists match the codec
// registry, and EVERY subcommand answers -h/--help with usage + exit 0.
//
// These tests drive the compiled `cx` binary as a subprocess. The expected
// sets below are deliberately hardcoded (NOT read from the binary) so a
// subcommand or capability dropped from the registry fails here instead of
// silently vanishing from both dispatch and help.

// The full dispatch surface — 22 subcommands (#417 inventory + `select` #462
// + `version` #426b).
const all_subcommands = ['fmt', 'canonical', 'hash', 'eq', 'diff', 'lint', 'validate', 'eval',
	'version', 'select', 'diagram', 'code-diagram', 'code-tree', 'table', 'scaffold', 'demo',
	'lock', 'lsp', 'store-serve', 'store-health', 'store-token', 'store-rotate-kek']

// The capability grant surface (code.capability_names + the blanket opt-out).
const all_allow_flags = ['--allow-read', '--allow-write', '--allow-net', '--allow-env',
	'--allow-clock', '--allow-random', '--allow-subprocess', '--allow-eval',
	'--allow-secret-reveal', '--allow-all']

// The text-convertible codec set (registry entries with a text parse half;
// the emit half is currently the same set).
const convert_formats = ['cx', 'xml', 'json', 'yaml', 'toml', 'md', 'csv', 'tsv', 'psv']

fn cx_bin() string {
	return testenv.cx_bin()
}

fn help_output() string {
	r := os.execute('${cx_bin()} --help 2>&1')
	assert r.exit_code == 0, 'cx --help must exit 0, got ${r.exit_code}: ${r.output}'
	return r.output
}

// ── (a) every dispatch-table subcommand appears in `cx --help` ───────────────

fn test_help_lists_every_subcommand() {
	out := help_output()
	for name in all_subcommands {
		assert out.contains('\n  ${name} '), 'subcommand `${name}` missing from cx --help'
	}
}

fn test_help_documents_the_run_surface() {
	out := help_output()
	// The primary run-a-program usage (#417: was absent entirely).
	assert out.contains('cx FILE.cx'), 'primary run usage missing from cx --help'
	assert out.contains('stdin'), 'stdin behavior missing from cx --help'
	assert out.contains("-e 'PROGRAM'"), 'inline-program usage missing from cx --help'
	// The separate data input (#415) and the unknown-flag contract.
	assert out.contains('--data='), 'run-surface --data flag missing from cx --help'
	assert out.contains('Unknown flags are hard usage errors'), 'unknown-flag contract missing from cx --help'
	// Every capability grant flag.
	for flag in all_allow_flags {
		assert out.contains(flag), 'capability flag ${flag} missing from cx --help'
	}
	// The old dangling parenthetical (`Public Table API surface ().`) is gone.
	assert !out.contains('().'), 'dangling empty parenthetical back in cx --help'
}

// ── (b) `cx <sub> --help` exits 0 with usage — uniformly, all 22 ─────────────

fn test_every_subcommand_help_exits_zero_with_usage() {
	for name in all_subcommands {
		for flag in ['--help', '-h'] {
			r := os.execute('${cx_bin()} ${name} ${flag} 2>&1')
			assert r.exit_code == 0, 'cx ${name} ${flag} must exit 0, got ${r.exit_code}: ${r.output}'
			assert r.output.starts_with('Usage: cx ${name}'), 'cx ${name} ${flag} must print its usage, got: ${r.output}'
		}
	}
}

// ── (c) the --from/--to lists in help match the accepted set ─────────────────

fn extract_format_list(out string, label string) []string {
	for line in out.split('\n') {
		t := line.trim_space()
		if t.starts_with(label) {
			return t.all_after(label).trim_space().split('|')
		}
	}
	assert false, '`${label}` line missing from cx --help'
	return []
}

fn test_help_from_to_lists_match_accepted_set() {
	out := help_output()
	from_list := extract_format_list(out, '--from:')
	to_list := extract_format_list(out, '--to:')
	assert from_list == convert_formats, 'help --from list ${from_list} != accepted ${convert_formats}'
	assert to_list == convert_formats, 'help --to list ${to_list} != accepted ${convert_formats}'
	// Behavior probe: every advertised format is accepted by the convert
	// pipeline (no "unknown source format" / "has no text parser"), …
	for f in from_list {
		r := os.execute("printf 'x' | ${cx_bin()} --from=${f} --to=cx - 2>&1")
		assert !r.output.contains('unknown source format'), '--from=${f} advertised but rejected: ${r.output}'
		assert !r.output.contains('has no text parser'), '--from=${f} advertised but has no parser: ${r.output}'
	}
	// … and a name outside the list is rejected with the registry error.
	r := os.execute("printf 'x' | ${cx_bin()} --from=nope --to=cx - 2>&1")
	assert r.exit_code != 0, '--from=nope must fail'
	assert r.output.contains('unknown source format'), 'unknown --from must name the registry error, got: ${r.output}'
}
