module main

import os
import cx
import code

const version = '0.8.0'

fn main() {
	args := os.args[1..]
	// No args: print usage when stdin is a TTY (interactive), but fall
	// through to the default program reading when stdin is piped — `echo
	// '[+ 1 2]' | cx` evaluates stdin (spec/code.md §1.3: stdin EVALUATES).
	if args.len == 0 && os.is_atty(0) != 0 {
		print_usage_and_exit(1)
	}

	if args.len > 0 {
		if args[0] == '-v' || args[0] == '--version' {
			println('cx ${version}')
			exit(0)
		}
		if args[0] == '-h' || args[0] == '--help' {
			print_usage_and_exit(0)
		}

		// ── Subcommand dispatch (Phase 6 / spec/canonical.md) ─────────────────
		// `cx fmt FILE` — lossless canonical text
		// `cx canonical FILE` — strict canonical text
		// `cx hash FILE` — SHA-256 hex of strict canonical bytes
		// `cx eq A.cx B.cx` — exit 0 iff canonical(A) == canonical(B)
		match args[0] {
			'fmt' { run_fmt(args[1..]); return }
			'canonical' { run_canonical(args[1..]); return }
			'hash' { run_hash(args[1..]); return }
			'eq' { run_eq(args[1..]); return }
			'diff' { run_diff(args[1..]); return }
			'lint' { run_lint(args[1..]); return }
			'validate' { run_validate(args[1..]); return }
			'table' { run_table(args[1..]); return }
			'demo' { run_demo(args[1..]); return }
			'scaffold' { run_scaffold(args[1..]); return }
			'eval' { run_eval(args[1..]); return }
			'diagram' { run_diagram(args[1..]); return }
			'code-diagram' { run_code_diagram(args[1..]); return }
			'code-tree' { run_code_tree(args[1..]); return }
			'lock' { run_cx_lock(args[1..]); return }
			'lsp' { run_lsp(args[1..]); return }
			else {} // fall through to legacy --flag form
		}
	}

	// Determine input
	mut input := ''
	mut input_file := ''
	for arg in args {
		if !arg.starts_with('--') {
			input_file = arg
			input = os.read_file(arg) or {
				eprintln('error reading file ${arg}: ${err}')
				exit(1)
			}
			break
		}
	}
	if input.len == 0 {
		input = os.get_raw_lines_joined()
	}

	// Parse flags
	mut mode := ''
	mut compact := false
	mut lossless := false
	mut explicit_from := false
	mut from_fmt := 'cx'
	mut to_fmt := 'cx'
	mut include_root := ''
	// Capability grants for the default program reading (deny-by-default,
	// matching `cx eval` — spec/security.md §3). `--allow-all` opts out;
	// `--allow-<cap>` grants one capability.
	mut allow_all := false
	mut allow_caps := []string{}
	mut net_specs := []string{}
	for arg in args {
		if arg == '--ast' { mode = 'ast' }
		else if arg == '--cx' { mode = 'cx' }
		else if arg == '--xml' { mode = 'xml' }
		else if arg == '--json' { mode = 'json' }
		else if arg == '--yaml' { mode = 'yaml' }
		else if arg == '--toml' { mode = 'toml' }
		else if arg == '--md' { mode = 'md' }
		else if arg == '--csv' { mode = 'csv' }
		else if arg == '--tsv' { mode = 'tsv' }
		else if arg == '--psv' { mode = 'psv' }
		else if arg == '--cxcol' { mode = 'cxcol' }
		else if arg == '--compact' { compact = true }
		else if arg == '--lossless' { lossless = true }
		else if arg == '--allow-all' { allow_all = true }
		else if arg.starts_with('--allow-') {
			rest_cap := arg['--allow-'.len..]
			cap_name := rest_cap.all_before('=')
			if cap_name != '' {
				allow_caps << cap_name
				if cap_name == 'net' && rest_cap.contains('=') { net_specs << rest_cap.all_after('=') }
			}
		}
		else if arg.starts_with('--from=') { from_fmt = arg[7..]; explicit_from = true }
		else if arg.starts_with('--to=') { to_fmt = arg[5..] }
		else if arg.starts_with('--include-root=') { include_root = arg[15..] }
	}

	// When --include-root is supplied, resolve `[?cx include=…]`
	// directives in the input before format conversion. Done by
	// pre-parsing through the include resolver and re-emitting as
	// CX text, which the downstream pipeline then re-parses normally.
	// One extra round-trip in exchange for not duplicating every
	// to_* entry point.
	if include_root != '' && from_fmt == 'cx' {
		input = resolve_includes_text(input, include_root) or {
			eprintln('error resolving includes: ${err}')
			exit(1)
		}
	}

	// Auto-detect input format from file extension if not explicit
	if !explicit_from && input_file.len > 0 {
		if input_file.ends_with('.xml') { from_fmt = 'xml' }
		else if input_file.ends_with('.json') { from_fmt = 'json' }
		else if input_file.ends_with('.yaml') || input_file.ends_with('.yml') { from_fmt = 'yaml' }
		else if input_file.ends_with('.toml') { from_fmt = 'toml' }
		else if input_file.ends_with('.md') { from_fmt = 'md' }
	}

	if mode.len == 0 { mode = to_fmt }

	// ── CLI DEFAULT = the program reading (spec/code.md §1.3, D-A1) ──────────
	// A bare CX resource EVALUATES: `cx <file|->` ≡ `cx eval <file|->`. The
	// result is rendered per the requested target; the default is canonical
	// CX, and --xml/--json/--yaml/--csv/--tsv/--to render the RESULT. A pure
	// data document evaluates to itself, so this is a no-op there.
	//
	// An EXPLICIT --from=… selects the CONVERT pipeline (the data reading),
	// per the ruling's "--from=/convert" surface — the escape hatch for the
	// lossless CX⇄XML/JSON bijection and for ingesting foreign formats
	// (`cx --from=cx --to=xml d.cx` converts; `cx d.cx --xml` evaluates).
	// Auto-detected non-CX inputs (.xml/.json/…) also stay on convert.
	// Structural/inspection modes the result-renderer doesn't cover
	// (ast/cxcol/toml/psv, and --compact) also stay on the data path.
	eval_targets := ['cx', 'xml', 'json', 'yaml', 'csv', 'tsv']
	if from_fmt == 'cx' && !explicit_from && !compact && !lossless && mode in eval_targets {
		// Install the capability set before eval (deny-by-default).
		if allow_all {
			code.caps_set_all()
		} else {
			code.caps_set_list(allow_caps)
			if net_specs.len > 0 {
				code.caps_set_net_hosts(net_specs)
			}
		}
		// The resource IS the program; there is no separate data input.
		out := code.eval_code('', input, mode) or { eprintln('error: ${err}'); exit(1) }
		print(out)
		return
	}

	out := if mode == 'ast' {
		cx.to_ast(input) or { eprintln('error: ${err}'); exit(1) }
	} else if mode == 'cx' && compact {
		cx.to_cx_compact(input) or { eprintln('error: ${err}'); exit(1) }
	} else if mode == 'csv' {
		cx.to_csv(input) or { eprintln('error: ${err}'); exit(1) }
	} else if mode == 'tsv' {
		cx.to_tsv(input) or { eprintln('error: ${err}'); exit(1) }
	} else if mode == 'psv' {
		cx.to_psv(input) or { eprintln('error: ${err}'); exit(1) }
	} else if mode == 'cxcol' {
		doc := cx.parse(input) or { eprintln('error: ${err}'); exit(1) }
		bytes := cx.emit_data_bin(doc)
		C.write(1, bytes.data, bytes.len)
		return
	} else {
		// --from/--to convert pipeline: a registry lookup + compose
		// (codec.md §6). Names pass through verbatim to the one registry —
		// any registered codec is reachable, and an unknown name errors
		// ("unknown source/target format: …") rather than silently folding
		// to cx (G6).
		cx.convert_by_name(input, from_fmt, mode, lossless) or {
			eprintln('error: ${err}')
			exit(1)
		}
	}
	println(out)
}

// ── Subcommand handlers ──────────────────────────────────────────────────────

fn run_fmt(args []string) {
	src := read_one_input(args, 'fmt')
	out := cx.cx_text_fmt(src) or { eprintln('cx fmt: ${err}'); exit(1) }
	println(out)
}

fn run_canonical(args []string) {
	src := read_one_input(args, 'canonical')
	out := cx.cx_text_canonical(src) or { eprintln('cx canonical: ${err}'); exit(1) }
	println(out)
}

fn run_hash(args []string) {
	src := read_one_input(args, 'hash')
	out := cx.cx_text_hash(src) or { eprintln('cx hash: ${err}'); exit(1) }
	println(out)
}

fn run_eq(args []string) {
	if args.len != 2 {
		eprintln('Usage: cx eq FILE_A FILE_B')
		eprintln('Exits 0 if strict-canonical(A) == strict-canonical(B), 1 if not, 2 on error.')
		exit(2)
	}
	a := os.read_file(args[0]) or { eprintln('cx eq: ${err}'); exit(2) }
	b := os.read_file(args[1]) or { eprintln('cx eq: ${err}'); exit(2) }
	eq := cx.cx_text_eq(a, b) or { eprintln('cx eq: ${err}'); exit(2) }
	exit(if eq { 0 } else { 1 })
}

// run_diff implements `cx diff [--format=unified|json|summary] [--no-color] A B`
// per internal design record Exit codes 0/1/2.
fn run_diff(args []string) {
	mut format := 'unified'
	mut color_pref := 'auto'
	mut files := []string{}
	for arg in args {
		if arg.starts_with('--format=') {
			format = arg[9..]
		} else if arg == '--no-color' {
			color_pref = 'never'
		} else if arg == '--color' || arg.starts_with('--color=') {
			val := if arg == '--color' { 'always' } else { arg[8..] }
			color_pref = val
		} else if arg.starts_with('--') {
			eprintln('cx diff: unknown flag ${arg}')
			eprintln('Usage: cx diff [--format=unified|json|summary] [--no-color] A.cx B.cx')
			exit(2)
		} else {
			files << arg
		}
	}
	if files.len != 2 {
		eprintln('Usage: cx diff [--format=unified|json|summary] [--no-color] A.cx B.cx')
		eprintln('Exit 0 if data-equivalent, 1 if differs, 2 on error.')
		exit(2)
	}
	a := os.read_file(files[0]) or { eprintln('cx diff: ${err}'); exit(2) }
	b := os.read_file(files[1]) or { eprintln('cx diff: ${err}'); exit(2) }
	changes := cx.cx_text_diff(a, b) or { eprintln('cx diff: ${err}'); exit(2) }

	color := match color_pref {
		'always' { true }
		'never' { false }
		else { os.is_atty(1) > 0 } // auto: TTY check
	}

	out := match format {
		'unified' { cx.diff_render_unified(changes, color) }
		'json' { cx.diff_render_json(changes) }
		'summary' { cx.diff_render_summary(changes) }
		else {
			eprintln('cx diff: unknown --format=${format} (use unified|json|summary)')
			exit(2)
		}
	}
	if out.len > 0 {
		println(out)
	}
	exit(if changes.len == 0 { 0 } else { 1 })
}

// run_lint implements `cx lint [--format=text|json|summary] [--fail-on=info|warn|error|none]
// [--disable=ID1,ID2] [--only=ID] [--config=path] [--no-config] FILE` per
// internal design record When --config is omitted and --no-config
// is not set, the CLI walks up from FILE's directory (or cwd for stdin)
// looking for the nearest `.cxlint.cx` and merges its disable list and
// severity overrides into the active LintOptions.
fn run_lint(args []string) {
	mut format := 'text'
	mut fail_on := 'error'
	mut disabled := []string{}
	mut only := ''
	mut config_path := ''
	mut no_config := false
	mut files := []string{}
	for arg in args {
		if arg.starts_with('--format=') {
			format = arg[9..]
		} else if arg.starts_with('--fail-on=') {
			fail_on = arg[10..]
		} else if arg.starts_with('--disable=') {
			disabled = arg[10..].split(',')
		} else if arg.starts_with('--only=') {
			only = arg[7..]
		} else if arg.starts_with('--config=') {
			config_path = arg[9..]
		} else if arg == '--no-config' {
			no_config = true
		} else if arg.starts_with('--') {
			eprintln('cx lint: unknown flag ${arg}')
			eprintln('Usage: cx lint [--format=text|json|summary] [--fail-on=info|warn|error|none]')
			eprintln(' [--disable=ID1,ID2] [--only=ID]')
			eprintln(' [--config=path | --no-config] FILE')
			exit(2)
		} else {
			files << arg
		}
	}
	if files.len > 1 {
		eprintln('Usage: cx lint [opts] [FILE]')
		eprintln('Reads from FILE if given, otherwise stdin.')
		exit(2)
	}
	src := if files.len == 1 && files[0] != '-' {
		os.read_file(files[0]) or { eprintln('cx lint: ${err}'); exit(2) }
	} else {
		os.get_raw_lines_joined()
	}

	// Discover and apply .cxlint.cx config (D7 second mechanism).
	mut cfg := cx.LintConfig{}
	if !no_config {
		cfg_text := if config_path != '' {
			os.read_file(config_path) or { eprintln('cx lint: ${err}'); exit(2) }
		} else if files.len == 1 && files[0] != '-' {
			discover_cxlint_config(os.dir(files[0]))
		} else {
			discover_cxlint_config(os.getwd())
		}
		cfg = cx.load_lint_config_from(cfg_text) or {
			eprintln('cx lint: invalid .cxlint.cx: ${err}')
			exit(2)
		}
	}
	base_opts := cx.LintOptions{ disabled: disabled, only: only }
	opts := cx.merge_config_into_options(cfg, base_opts)
	mut findings := cx.cx_text_lint(src, opts) or { eprintln('cx lint: ${err}'); exit(2) }
	if cfg.severity_override.len > 0 {
		findings = cx.apply_severity_overrides(findings, cfg.severity_override)
	}

	out := match format {
		'text' { cx.lint_render_text(findings) }
		'json' { cx.lint_render_json(findings) }
		'summary' { cx.lint_render_summary(findings) }
		else {
			eprintln('cx lint: unknown --format=${format} (use text|json|summary)')
			exit(2)
		}
	}
	if out.len > 0 {
		println(out)
	}

	threshold := match fail_on {
		'info' { cx.Severity.info }
		'warn' { cx.Severity.warn }
		'error' { cx.Severity.error_severity }
		'none' { exit(0) }
		else {
			eprintln('cx lint: unknown --fail-on=${fail_on} (use info|warn|error|none)')
			exit(2)
		}
	}
	exit(if cx.findings_at_or_above_threshold(findings, threshold) { 1 } else { 0 })
}

// run_validate implements `cx validate FILE --schema=SCHEMA.cxs` per
// spec/schema.md §10 (). Exit codes:
// 0 — no diagnostics at or above --fail-on threshold
// 1 — diagnostics at or above threshold
// 2 — usage / I/O / schema-load failure
// Default --fail-on=error matches `cx lint`. The validator is
// currently the bootstrap validator (4 of 14 rules end-to-end; the rest
// are TODO(phase-7.74d) inside vcx/cx/schema_validate.v).
fn run_validate(args []string) {
	mut schema_path := ''
	mut fail_on := 'error'
	mut mode_override := ''
	mut apply_defaults := false
	mut doc_files := []string{}
	for arg in args {
		if arg.starts_with('--schema=') {
			schema_path = arg[9..]
		} else if arg == '--schema' {
			eprintln('cx validate: --schema requires a value (use --schema=FILE)')
			exit(2)
		} else if arg.starts_with('--fail-on=') {
			fail_on = arg[10..]
		} else if arg.starts_with('--mode=') {
			mode_override = arg[7..]
		} else if arg == '--apply-defaults' {
			apply_defaults = true
		} else if arg.starts_with('--') {
			eprintln('cx validate: unknown flag ${arg}')
			eprintln('Usage: cx validate FILE --schema=SCHEMA.cxs')
			eprintln(' [--fail-on=info|warn|error|none] [--mode=open|strict|closed]')
			eprintln(' [--apply-defaults]')
			exit(2)
		} else {
			doc_files << arg
		}
	}
	if doc_files.len != 1 {
		eprintln('Usage: cx validate FILE --schema=SCHEMA.cxs [opts]')
		eprintln('Exit 0 if no diagnostics at/above --fail-on threshold (default error),')
		eprintln(' 1 if any diagnostic at/above threshold, 2 on I/O / schema-load failure.')
		exit(2)
	}
	if schema_path == '' {
		eprintln('cx validate: --schema=SCHEMA.cxs is required')
		exit(2)
	}
	doc_path := doc_files[0]
	doc_src := os.read_file(doc_path) or { eprintln('cx validate: ${err}'); exit(2) }
	schema_src := os.read_file(schema_path) or { eprintln('cx validate: ${err}'); exit(2) }
	doc := cx.parse_cx(doc_src) or { eprintln('cx validate: parse error: ${err}'); exit(2) }
	doc_single := doc.single or {
		eprintln('cx validate: multi-document inputs not yet supported')
		exit(2)
	}
	mut opts := cx.ValidateOptions{}
	if mode_override != '' {
		opts = cx.ValidateOptions{
			mode_override: match mode_override {
				'open' { ?cx.SchemaMode(cx.SchemaMode.open) }
				'strict' { ?cx.SchemaMode(cx.SchemaMode.strict) }
				'closed' { ?cx.SchemaMode(cx.SchemaMode.closed) }
				else {
					eprintln('cx validate: unknown --mode=${mode_override} (use open|strict|closed)')
					exit(2)
				}
			}
		}
	}
	report := if apply_defaults {
		cx.validate_with_defaults(doc_single, schema_src, opts) or {
			eprintln('cx validate: ${err}')
			exit(2)
		}
	} else {
		cx.validate(doc_single, schema_src, opts) or {
			eprintln('cx validate: ${err}')
			exit(2)
		}
	}
	if report.diagnostics.len > 0 {
		println(report.render(doc_path))
	}
	threshold := match fail_on {
		'info' { cx.Severity.info }
		'warn' { cx.Severity.warn }
		'error' { cx.Severity.error_severity }
		'none' { exit(0) }
		else {
			eprintln('cx validate: unknown --fail-on=${fail_on} (use info|warn|error|none)')
			exit(2)
		}
	}
	exit(if report.has_at_or_above_severity(threshold) { 1 } else { 0 })
}

// discover_cxlint_config walks up from `start_dir` looking for the
// nearest `.cxlint.cx`. Returns its contents on first match, or an
// empty string when no config exists between start_dir and the
// filesystem root. Following common conventions ('.gitignore'-style
// search), the walk stops at root or when the path no longer
// changes.
fn discover_cxlint_config(start_dir string) string {
	mut dir := start_dir
	for dir.len > 0 {
		path := os.join_path(dir, '.cxlint.cx')
		if os.exists(path) && !os.is_dir(path) {
			content := os.read_file(path) or { return '' }
			return content
		}
		parent := os.dir(dir)
		if parent == dir { break }
		dir = parent
	}
	return ''
}

// resolve_includes_text parses the given CX source with include
// resolution enabled against `root`, then emits the resolved AST
// back to canonical CX text. Used by the legacy format-dispatch
// and `cx eval` to bolt `--include-root` onto entry points whose
// downstream library calls only accept raw text. Round-trip cost
// is one extra parse + emit; acceptable for the doc-gen + ad-hoc
// CLI use cases that need this flag.
fn resolve_includes_text(src string, root string) !string {
	if root == '' {
		return src
	}
	doc := cx.parse_with_include_root(src, root)!
	return cx.emit_cx(doc)
}

fn read_one_input(args []string, cmd string) string {
	if args.len > 1 {
		eprintln('Usage: cx ${cmd} [FILE]')
		eprintln('Reads from FILE if given, otherwise stdin.')
		exit(2)
	}
	if args.len == 1 {
		return os.read_file(args[0]) or { eprintln('cx ${cmd}: ${err}'); exit(2) }
	}
	return os.get_raw_lines_joined()
}

fn print_usage_and_exit(exit_code int) {
	eprintln('Usage: cx <subcommand> [args...]')
	eprintln(' cx --ast|--cx|--xml|--json|--yaml|--toml|--md|--csv|--tsv|--psv [--compact] [input_file]')
	eprintln(' cx --from=cx|xml|md --to=cx|xml|json|yaml|toml|md|csv|tsv|psv [--compact] [--lossless] [input_file]')
	eprintln('   --lossless: XML carries per-value types (`<cx:T>`) for an exact CX round-trip')
	eprintln(' cx -v|--version')
	eprintln('')
	eprintln('Subcommands:')
	eprintln(' fmt [FILE] Lossless canonical formatter (preserves comments,')
	eprintln(' anchors, etc.; normalizes whitespace and quoting).')
	eprintln(' canonical [FILE] Strict canonical text (strips comments and other')
	eprintln(' presentation; output is data-equivalent).')
	eprintln(' hash [FILE] SHA-256 hex of the strict canonical bytes.')
	eprintln(' eq A.cx B.cx Exit 0 iff strict-canonical(A) == strict-canonical(B);')
	eprintln(' exit 1 if they differ; exit 2 on error.')
	eprintln(' diff [opts] A.cx B.cx Semantic diff (walks strict-canonical forms).')
	eprintln(' --format=unified|json|summary (default unified).')
	eprintln(' --no-color disables ANSI color in unified output.')
	eprintln(' Exit 0 if data-equivalent, 1 if differs, 2 on error.')
	eprintln(' lint [opts] FILE Style + correctness warnings.')
	eprintln(' --format=text|json|summary (default text).')
	eprintln(' --fail-on=info|warn|error|none (default error).')
	eprintln(' --disable=ID1,ID2 to suppress checks; --only=ID to run one.')
	eprintln(' validate FILE --schema=SCHEMA.cxs')
	eprintln(' Validate FILE against the schema.')
	eprintln(' --fail-on=info|warn|error|none (default error).')
	eprintln(' --mode=open|strict|closed overrides the schema-mode directive.')
	eprintln(' --apply-defaults inserts schema-default attribute values.')
	eprintln(' Exit 0 if no diagnostics at/above --fail-on,')
	eprintln(' 1 if any, 2 on I/O / schema failure.')
	eprintln(' table <verb> [args...] Public Table API surface ().')
	eprintln(' info FILE — column/row counts, types, byte size.')
	eprintln(' dump FILE --to=cx — round-trip via Table API.')
	eprintln(' load FILE --to=cx — symmetric inverse.')
	eprintln(' --to=parquet|arrow defers to libcx_arrow Phase C (post-v0.6.0).')
	eprintln(' demo Self-contained showcase: typed round-trip,')
	eprintln(' :table → CSV, CX program, comparison.')
	eprintln(' No file I/O, no network. < 1s wall-clock.')
	eprintln(' scaffold <kind> Drop a typed, commented skeleton on stdout.')
	eprintln(' kind ∈ {config, data, doc, log, table}.')
	exit(exit_code)
}
