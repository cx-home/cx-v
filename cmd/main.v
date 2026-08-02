module main

import os
import cx
import code

// Build-stamped version info. The values are injected at build time via V
// compile-time string defines (`-d cx_version=… -d cx_commit=…`), wired in
// vcx/Makefile. `cx_version` derives from the repo-root VERSION file (the single
// source of truth); commit/date/gc/vfork come from git + the build. Defaults
// apply only outside the Makefile (e.g. a bare `v run cmd/`) — a non-stamped
// dev build, hence the obviously-unreleased `0.0.0-dev`.
const version = $d('cx_version', '0.0.0-dev')
const cx_commit = $d('cx_commit', 'unknown')
const cx_build_date = $d('cx_build_date', 'unknown')
const cx_gc = $d('cx_gc', 'unknown')
const cx_vfork = $d('cx_vfork', 'unknown')

// compiled_engines reports the DB engines compiled into THIS binary, probed
// from the `$if` build gates themselves (#520) — the same gates that select
// the engine in sql_open_impl / stdlib_dispatch, so the line can never drift
// from what the binary resolves. Scripts probe capability here instead of
// tripping CXER1100 (`cx -v | grep -q 'engines.*sqlite'`).
fn compiled_engines() string {
	mut e := []string{}
	$if cx_db_sqlite ? {
		e << 'sqlite'
	}
	$if cx_db_pg ? {
		e << 'postgres'
	}
	$if cx_db_mysql ? {
		e << 'mysql'
	}
	$if cx_db_redis ? {
		e << 'redis'
	}
	return if e.len == 0 { '(none)' } else { e.join(' ') }
}

// compiled_features reports the other optional gated backends compiled into
// this binary — the store substrates and transports that, like the DB
// engines, are `-d`-gated because they link (or enable) something the bare
// build must not assume.
fn compiled_features() string {
	mut f := []string{}
	$if cxstore_sqlite ? {
		f << 'store-sqlite'
	}
	$if cxstore_columnar ? {
		f << 'store-columnar'
	}
	$if cx_arrow_files ? {
		f << 'arrow-files'
	}
	$if cx_sftp ? {
		f << 'sftp'
	}
	return if f.len == 0 { '(none)' } else { f.join(' ') }
}

// print_version emits expanded build/version info (commit, build time, GC model,
// V-fork gitlink, compiled-in engines/features) — `cx --version` / `cx -v`.
fn print_version() {
	gc_desc := match cx_gc {
		'e' { 'e — Perceus RC front line + precise STW vgc backstop' }
		'vgc' { 'vgc — precise STW tracing collector' }
		'boehm' { 'boehm — conservative tracing collector' }
		else { cx_gc }
	}
	println('cx v${version}')
	println('  commit   ${cx_commit}')
	println('  built    ${cx_build_date}')
	println('  gc       ${gc_desc}')
	println('  V fork   ${cx_vfork}')
	println('  engines  ${compiled_engines()}')
	println('  features ${compiled_features()}')
}

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
			print_version()
			exit(0)
		}
		if args[0] == '-h' || args[0] == '--help' {
			print_usage_and_exit(0)
		}

		// ── Subcommand dispatch — driven by the ONE registry (#417) ───────────
		// `subcommands` below is the single source of truth: the same table
		// drives this dispatch, the `cx --help` catalog, and every
		// per-subcommand `cx <name> --help`. A subcommand cannot exist
		// without being documented, and help can never drift from dispatch.
		for sc in subcommands {
			if args[0] == sc.name {
				rest := args[1..]
				// Uniform -h/--help for EVERY subcommand: print the
				// registered usage on stdout and exit 0 — no handler
				// treats `--help` as a filename or unknown flag again.
				if '--help' in rest || '-h' in rest {
					print_subcommand_help(sc)
					exit(0)
				}
				sc.run(rest)
				return
			}
		}
		// No subcommand matched: fall through to the default program /
		// convert readings below (legacy --flag form).
	}

	// ── Bare run / convert surface: ONE strict argv pass (#415) ─────────────
	// Every argument is either a recognised flag, a recognised
	// flag-with-value, `-e EXPR`, `-` (program from stdin), or the single
	// positional input FILE. Anything else is a hard usage error (exit 2)
	// per spec/misc/cli.md §3.7 — the pre-#415 surface silently swallowed
	// unknown flags (`--data=…` no-op'd with rc=0), which is how four
	// flagship example tours ran empty for a whole release.
	//
	// Program sources mirror `cx eval`'s (the never-`cx eval` rule):
	//   cx FILE        — program from FILE
	//   cx -           — program from stdin (explicit)
	//   cx -e EXPR     — inline program EXPR (also --expression)
	//   echo P | cx    — program from stdin (pipe; the no-input fall-through)
	mut input := ''
	mut input_file := ''
	mut got_input := false
	mut stdin_program := false
	mut mode := ''
	mut compact := false
	mut lossless := false
	mut explicit_from := false
	mut from_fmt := 'cx'
	mut to_fmt := 'cx'
	mut include_root := ''
	// Separate data input (spec/code.md §1.3): `--data=FILE|-` is loaded via
	// the DATA reading and bound as $doc / $input before evaluation; the
	// caller-supplied input WINS over the program's own data roots.
	mut data_file := ''
	mut data_given := false
	// Capability grants for the default program reading (deny-by-default,
	// matching `cx eval` — spec/security.md §3). `--allow-all` opts out;
	// `--allow-<cap>` grants one capability.
	mut allow_all := false
	mut allow_caps := []string{}
	mut net_specs := []string{}
	mut i := 0
	for i < args.len {
		arg := args[i]
		if arg == '-e' || arg == '--expression' {
			if got_input {
				eprintln('cx: unexpected ${arg} — a program input was already given')
				exit(2)
			}
			if i + 1 >= args.len {
				eprintln('cx ${arg}: missing expression argument')
				exit(2)
			}
			input = args[i + 1]
			got_input = true
			i += 2
			continue
		}
		if arg == '-' {
			if got_input {
				eprintln('cx: unexpected `-` — a program input was already given')
				exit(2)
			}
			stdin_program = true
			got_input = true
			i++
			continue
		}
		if arg == '-h' || arg == '--help' {
			print_usage_and_exit(0)
		}
		if arg == '-v' || arg == '--version' {
			print_version()
			exit(0)
		}
		if !arg.starts_with('-') {
			if got_input {
				eprintln('cx: unexpected extra argument ${arg} — the run surface takes one input FILE')
				exit(2)
			}
			input_file = arg
			got_input = true
			i++
			continue
		}
		// Flag namespace — a closed set; unknown names are hard errors.
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
			// A misspelled grant is an unknown flag, never a silent
			// no-grant (spec/misc/cli.md §3.7).
			if cap_name == '' || cap_name !in code.capability_names() {
				mut grant_flags := code.capability_names().map('--allow-' + it)
				grant_flags << '--allow-all'
				eprintln('cx: unknown flag ${arg}')
				eprintln('accepted capability grants: ${grant_flags.join(' ')}')
				eprintln('run `cx --help` for the full flag set')
				exit(2)
			}
			allow_caps << cap_name
			if cap_name == 'net' && rest_cap.contains('=') { net_specs << rest_cap.all_after('=') }
		}
		else if arg.starts_with('--from=') { from_fmt = arg[7..]; explicit_from = true }
		else if arg.starts_with('--to=') { to_fmt = arg[5..] }
		else if arg.starts_with('--include-root=') { include_root = arg[15..] }
		else if arg.starts_with('--data=') {
			data_file = arg[7..]
			data_given = true
			if data_file == '' {
				eprintln('cx: --data requires a value (use --data=FILE, or --data=- for stdin)')
				exit(2)
			}
		}
		else if arg in ['--data', '--from', '--to', '--include-root'] {
			eprintln('cx: ${arg} requires a value (use ${arg}=…)')
			exit(2)
		}
		else {
			eprintln('cx: unknown flag ${arg}')
			eprintln('run `cx --help` for the accepted run / convert flag set')
			exit(2)
		}
		i++
	}

	// Resolve the program source. Stdin is read at most once here; the
	// `--data=-` lane below guards against a double-read.
	mut program_reads_stdin := false
	if stdin_program {
		input = os.get_raw_lines_joined()
		program_reads_stdin = true
	} else if input_file != '' {
		input = os.read_file(input_file) or {
			eprintln('error reading file ${input_file}: ${err}')
			exit(1)
		}
	} else if !got_input {
		// Pipe fall-through: `echo P | cx [flags]`. A flags-only TTY
		// invocation gets the usage nudge instead of hanging on stdin.
		if os.is_atty(0) != 0 {
			print_usage_and_exit(1)
		}
		input = os.get_raw_lines_joined()
		program_reads_stdin = true
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

	// #416/#444: --lossless is honored only by lanes whose emitter implements
	// a lossless image (conversions.md §0.2): cx, xml (`<cx:T>` carriers),
	// json (`cx:type` sidecar) and yaml (`!!cx:T` tags) — read from the codec
	// registry's capability flag, the single source of truth. TOML/MD
	// lossless is spec'd as unsupported; every non-lossless lane REJECTS the
	// flag loudly (the pre-#416 CLI accepted it as a silent no-op). Checked
	// here (not only in convert_by_name) because csv/tsv/psv/ast/cxcol
	// dispatch bypasses the codec-registry compose.
	if lossless {
		mode_lossless := (cx.codec_lookup(mode) or { cx.Codec{} }).lossless
		if !mode_lossless {
			eprintln('error: --lossless is not supported for --to=${mode}; supported: ${cx.lossless_codec_names().join(', ')}')
			exit(2)
		}
	}

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
	run_surface := from_fmt == 'cx' && !explicit_from && !compact && !lossless
		&& mode in eval_targets

	// ── Separate data input, `--data=FILE|-` (#415; spec/misc/cli.md §3.7) ──
	// Run-surface only: on the convert pipeline there is no evaluation and
	// hence no $doc to bind, so the combination is a usage error rather than
	// a silent no-op. The input is loaded via the DATA reading (respecting
	// --include-root) and handed to the same eval_code seam `cx eval` uses:
	// it binds $doc / $input, and per spec/code.md §1.3 the caller-supplied
	// input WINS — the program's own data roots never rebind it.
	mut data_input := ''
	if data_given {
		if !run_surface {
			eprintln('cx: --data applies to the run surface only; it cannot combine with --from/--compact/--lossless or the structural projections (--ast/--toml/--md/--psv/--cxcol)')
			exit(2)
		}
		if data_file == '-' {
			if program_reads_stdin {
				eprintln('cx: the program and --data=- cannot both read stdin')
				exit(2)
			}
			data_input = os.get_raw_lines_joined()
		} else {
			data_input = os.read_file(data_file) or {
				eprintln('cx: error reading --data file ${data_file}: ${err}')
				exit(1)
			}
		}
		if include_root != '' {
			data_input = resolve_includes_text(data_input, include_root) or {
				eprintln('error resolving includes in --data input: ${err}')
				exit(1)
			}
		}
	}

	if run_surface {
		// Install the capability set before eval (deny-by-default).
		if allow_all {
			code.caps_set_all()
		} else {
			code.caps_set_list(allow_caps)
			if net_specs.len > 0 {
				code.caps_set_net_hosts(net_specs)
			}
		}
		out := code.eval_code(data_input, input, mode) or { eprintln('error: ${err}'); exit(1) }
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
	// `--migrate-predicates` (#110): the predicate-surface cutover sweep.
	// Character-anchored parser-based rewrite (never regex), fail-closed per
	// file via the program-parse oracle in code.migrate_predicates. Same
	// file-kind routing as --collapse-lets: .cxd fixtures and .md fences are
	// island-aware. `-w` writes changed files in place.
	if '--migrate-predicates' in args {
		mut write := false
		mut files := []string{}
		for a in args {
			if a == '--migrate-predicates' {
				continue
			} else if a == '-w' {
				write = true
			} else {
				files << a
			}
		}
		if files.len == 0 || (!write && files.len != 1) {
			eprintln('Usage: cx fmt --migrate-predicates [-w] FILE...   (-w required for multiple files)')
			exit(2)
		}
		mut changed := 0
		for f in files {
			src := os.read_file(f) or {
				eprintln('cx fmt: ${f}: ${err}')
				exit(1)
			}
			out := if f.ends_with('.cxd') {
				code.migrate_predicates_cxd(src) or {
					eprintln('cx fmt: ${f}: ${err}')
					exit(1)
				}
			} else if f.ends_with('.md') {
				code.migrate_predicates_md(src) or {
					eprintln('cx fmt: ${f}: ${err}')
					exit(1)
				}
			} else {
				code.migrate_predicates(src) or {
					eprintln('cx fmt: ${f}: ${err}')
					exit(1)
				}
			}
			if write {
				if out != src {
					os.write_file(f, out) or {
						eprintln('cx fmt: ${f}: ${err}')
						exit(1)
					}
					changed++
					println('migrated: ${f}')
				}
			} else {
				print(out)
			}
		}
		if write {
			println('${changed}/${files.len} file(s) changed')
		}
		return
	}
	// `--collapse-lets` (#361): the cascading-let idiom sweep. Token-anchored
	// parser-based rewrite (never regex), fail-closed per file via the
	// canonical-form oracle in code.collapse_nested_lets. `.cxd` fixture
	// documents are handled raw-block-aware: only `[in-cx [#…#]]` program
	// islands are rewritten, expected outputs stay byte-identical. `-w`
	// writes changed files in place; without it the result prints to stdout
	// (single file only).
	if '--collapse-lets' in args {
		mut write := false
		mut files := []string{}
		for a in args {
			if a == '--collapse-lets' {
				continue
			} else if a == '-w' {
				write = true
			} else {
				files << a
			}
		}
		if files.len == 0 || (!write && files.len != 1) {
			eprintln('Usage: cx fmt --collapse-lets [-w] FILE...   (-w required for multiple files)')
			exit(2)
		}
		mut changed := 0
		for f in files {
			src := os.read_file(f) or {
				eprintln('cx fmt: ${f}: ${err}')
				exit(1)
			}
			out := if f.ends_with('.cxd') {
				code.collapse_nested_lets_cxd(src) or {
					eprintln('cx fmt: ${f}: ${err}')
					exit(1)
				}
			} else if f.ends_with('.md') {
				code.collapse_nested_lets_md(src) or {
					eprintln('cx fmt: ${f}: ${err}')
					exit(1)
				}
			} else {
				code.collapse_nested_lets(src) or {
					eprintln('cx fmt: ${f}: ${err}')
					exit(1)
				}
			}
			if write {
				if out != src {
					os.write_file(f, out) or {
						eprintln('cx fmt: ${f}: ${err}')
						exit(1)
					}
					changed++
					println('collapsed: ${f}')
				}
			} else {
				print(out)
			}
		}
		if write {
			println('${changed}/${files.len} file(s) changed')
		}
		return
	}
	src := read_one_input(args, 'fmt')
	// code.fmt_source is program-faithful + fail-closed: it never rewrites a
	// program file through the data emitter (#118 — data loss on save).
	out := code.fmt_source(src) or { eprintln('cx fmt: ${err}'); exit(1) }
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

// ── CLI subcommand registry (#417) ───────────────────────────────────────────
//
// ONE table drives BOTH the dispatch in main() and every help surface: the
// `cx --help` catalog is generated from `name` + `summary`, and
// `cx <name> --help` prints `help` verbatim. Adding a subcommand here is the
// only way to make it dispatchable, so the help can never drift from the
// real surface again. ALL subcommands are documented — none are internal
// (`eval` is a documented alias of the default run action; the docs-src
// 08-tooling catalog mirrors this list).

struct SubcommandSpec {
	name    string
	summary string   // one-liner for the `cx --help` catalog
	help    []string // `cx <name> --help` body; first line is `Usage: cx <name> …`
	run     fn ([]string) @[required]
}

const subcommands = build_subcommands()

fn build_subcommands() []SubcommandSpec {
	return [
		SubcommandSpec{
			name:    'fmt'
			summary: 'Lossless canonical formatter (preserves comments/anchors).'
			help:    [
				'Usage: cx fmt [FILE]',
				'       cx fmt --migrate-predicates [-w] FILE...',
				'       cx fmt --collapse-lets [-w] FILE...',
				'',
				'Lossless canonical formatter: preserves comments, anchors, and authorial',
				'structure; normalizes whitespace and quoting. Reads FILE, or stdin if absent.',
				'',
				'Migration sweeps (parser-based, fail-closed per file):',
				'  --migrate-predicates   rewrite legacy predicate surface to prefix form',
				'  --collapse-lets        collapse cascading [?let] nests to the flat form',
				'  -w                     write changed files in place (required for multiple FILEs)',
			]
			run:     run_fmt
		},
		SubcommandSpec{
			name:    'canonical'
			summary: 'Strict canonical text (strips presentation; data-equivalent).'
			help:    [
				'Usage: cx canonical [FILE]',
				'',
				'Strict canonical text: strips comments and other presentation; the output',
				'is data-equivalent to the input. Reads FILE, or stdin if absent.',
			]
			run:     run_canonical
		},
		SubcommandSpec{
			name:    'hash'
			summary: 'SHA-256 hex of the strict-canonical bytes.'
			help:    [
				'Usage: cx hash [FILE]',
				'',
				'SHA-256 hex digest of the strict-canonical bytes — the content address of',
				'the document. Reads FILE, or stdin if absent.',
			]
			run:     run_hash
		},
		SubcommandSpec{
			name:    'eq'
			summary: 'Exit 0 iff strict-canonical(A) == strict-canonical(B).'
			help:    [
				'Usage: cx eq A.cx B.cx',
				'',
				'Compares the strict-canonical forms of two documents.',
				'Exit 0 if equal, 1 if they differ, 2 on error.',
			]
			run:     run_eq
		},
		SubcommandSpec{
			name:    'diff'
			summary: 'Semantic diff (walks the strict-canonical forms).'
			help:    [
				'Usage: cx diff [--format=unified|json|summary] [--no-color] A.cx B.cx',
				'',
				'Semantic diff over the strict-canonical forms.',
				'  --format=unified|json|summary   (default unified)',
				'  --no-color                      disable ANSI color in unified output',
				'  --color[=always|never|auto]     color policy (default auto: TTY only)',
				'Exit 0 if data-equivalent, 1 if the documents differ, 2 on error.',
			]
			run:     run_diff
		},
		SubcommandSpec{
			name:    'lint'
			summary: 'Style + correctness warnings.'
			help:    [
				'Usage: cx lint [opts] [FILE]',
				'',
				'Style + correctness warnings. Reads FILE, or stdin if absent.',
				'  --format=text|json|summary      (default text)',
				'  --fail-on=info|warn|error|none  exit-1 threshold (default error)',
				'  --disable=ID1,ID2               suppress specific checks',
				'  --only=ID                       run a single check',
				'  --config=PATH | --no-config     lint config (nearest .cxlint.cx is',
				'                                  auto-discovered when neither is given)',
				'Exit 0 if no findings at/above --fail-on, 1 if any, 2 on error.',
			]
			run:     run_lint
		},
		SubcommandSpec{
			name:    'validate'
			summary: 'Validate a document against a CX schema (.cxs).'
			help:    [
				'Usage: cx validate FILE --schema=SCHEMA.cxs [opts]',
				'',
				'Validates FILE against the schema.',
				'  --fail-on=info|warn|error|none  exit-1 threshold (default error)',
				'  --mode=open|strict|closed       override the schema-mode directive',
				'  --apply-defaults                insert schema-default attribute values',
				'Exit 0 if no diagnostics at/above --fail-on, 1 if any,',
				'2 on I/O / schema-load failure.',
			]
			run:     run_validate
		},
		SubcommandSpec{
			name:    'eval'
			summary: 'Evaluate a CX program (alias of the default run action; prefer `cx FILE`).'
			help:    [
				'Usage: cx eval PROGRAM.cx [--data=INPUT.cx] [--target=FMT] [--allow-*]',
				'',
				'Evaluates a CX program — an alias of the default run action; prefer the',
				'plain `cx PROGRAM.cx` spelling.',
				"  -e 'PROGRAM' | --expression     inline program",
				"  -d 'INPUT' | --data-text        inline input document",
				'  --data=FILE|-                   input document from a file (or stdin: -)',
				'  --target=text|cx|json|yaml|xml|csv|tsv   output rendering (default text)',
				'  --allow-<cap>[=SCOPE] / --allow-all       capability grants (see cx --help)',
			]
			run:     run_eval
		},
		SubcommandSpec{
			name:    'version'
			summary: 'Version / build info (same output as -v / --version).'
			help:    [
				'Usage: cx version',
				'',
				'Prints expanded version / build info — version, commit, build date,',
				'GC model, V-fork gitlink — exactly as `cx -v` / `cx --version` do.',
				'Exists as a verb so `cx version` can never fall through to the run',
				'surface: on a case-insensitive filesystem at the repo root the bare',
				'word used to resolve to ./VERSION and evaluate it as a program (#426).',
			]
			run:     run_version
		},
		SubcommandSpec{
			name:    'select'
			summary: 'CXPath query over a document (matches in canonical CX).'
			help:    [
				"Usage: cx select 'PATH' [FILE]",
				'',
				'Evaluates the CXPath expression PATH against the document read from',
				'FILE (or stdin if `-` / absent), which is bound as $doc (and $input).',
				"PATH is a CXPath value expression (spec/code.md §5.5): '\$doc/…'-anchored,",
				"document-rooted '/…', or descendant '//…'; predicates apply.",
				'',
				'Matches print one per line, in document order, in canonical CX.',
				'Attribute-axis matches materialize as [name value] fields; a single',
				'plain child-chain attribute read prints its typed scalar value.',
				'A pure read — needs (and accepts) no capability grants.',
				'Exit 0 if at least one node matched, 1 if the match set is empty,',
				'2 on error (usage, unreadable FILE, document/path parse error).',
			]
			run:     run_select
		},
		SubcommandSpec{
			name:    'diagram'
			summary: 'Render a CX program as a diagram (mermaid/svg/png).'
			help:    [
				'Usage: cx diagram PROGRAM.cx [--format=mermaid|svg|png] [-o OUT]',
				'',
				'Renders a CX program as a diagram. Output goes to stdout by default;',
				'-o PATH writes a file (recommended for svg/png). Every format embeds the',
				'original source bytes, so the diagram reverse-parses to the same AST.',
			]
			run:     run_diagram
		},
		SubcommandSpec{
			name:    'code-diagram'
			summary: 'Mermaid diagram of a CX source (flowchart / erDiagram).'
			help:    [
				'Usage: cx code-diagram [FILE|-] [--level=min|compact|full]',
				'',
				'Auto-detecting Mermaid emitter: flowchart TD for code sources, erDiagram',
				'for data sources. Reads FILE, or stdin if `-` / absent.',
				'  --level=min|compact|full   detail level (default compact)',
			]
			run:     run_code_diagram
		},
		SubcommandSpec{
			name:    'code-tree'
			summary: 'Tree View JSON of a CX source.'
			help:    [
				'Usage: cx code-tree [FILE|-]',
				'',
				'Prints the Tree View JSON rendering of a CX source.',
				'Reads FILE, or stdin if `-` / absent.',
			]
			run:     run_code_tree
		},
		SubcommandSpec{
			name:    'table'
			summary: 'Table API over [table[...]] blocks (info / dump / load).'
			help:    [
				'Usage: cx table <verb> [args...]',
				'',
				'Public Table API surface over [table[...]] blocks.',
				'  cx table info FILE          column/row counts, types, byte size',
				'  cx table dump FILE [--to=cx|parquet|arrow] [--output=FILE]',
				'  cx table load FILE [--from=cx|parquet|arrow] [--to=cx] [--output=FILE]',
				'FILE may be omitted to read stdin. Parquet/Arrow I/O needs libcx_arrow',
				'built with -d cx_arrow_files.',
			]
			run:     run_table
		},
		SubcommandSpec{
			name:    'scaffold'
			summary: 'Typed, commented skeleton on stdout (config/data/doc/log/table).'
			help:    [
				'Usage: cx scaffold <kind>',
				'',
				'Drops a typed, commented skeleton on stdout.',
				'kind: config | data | doc | log | table',
				'',
				'Examples:',
				'  cx scaffold config > my_config.cx',
				'  cx scaffold table | cx --json',
			]
			run:     run_scaffold
		},
		SubcommandSpec{
			name:    'demo'
			summary: 'Self-contained showcase (no file I/O, no network, < 1s).'
			help:    [
				'Usage: cx demo',
				'',
				'Self-contained showcase: typed round-trip, a [table[...]] block to CSV,',
				'a CX program, and the format comparison. No file I/O, no network; runs',
				'in under a second. Takes no arguments.',
			]
			run:     run_demo
		},
		SubcommandSpec{
			name:    'lock'
			summary: 'Generate / verify cx.lock from [?lib] directives.'
			help:    [
				'Usage: cx lock [opts] [FILE...]',
				'',
				"Generates / verifies cx.lock from a project's [?lib] directives.",
				'FILE may be one or more .cx sources; defaults to every *.cx in cwd.',
				'  --check          verify the existing cx.lock matches; exit 1 on drift',
				'  --update NAME    refresh a single module entry, keep the rest verbatim',
				'  --output PATH    write to PATH instead of ./cx.lock',
			]
			run:     run_cx_lock
		},
		SubcommandSpec{
			name:    'lsp'
			summary: 'Language server (LSP) on stdio.'
			help:    [
				'Usage: cx lsp [--verbose]',
				'',
				'Runs the CX language server on stdio — the entry point the editor',
				'integrations (VS Code, Neovim) spawn.',
				'  --verbose   trace protocol messages on stderr (silent by default)',
			]
			run:     run_lsp
		},
		SubcommandSpec{
			name:    'store-serve'
			summary: 'Run the CX store service daemon from a config.'
			help:    [
				'Usage: cx store-serve --config PATH [--allow-net[=host:port]] [--allow-*]',
				'',
				'Runs the single-node CX store service daemon: loads + validates the',
				'cxstore.service.cx config, opens the store mount, and serves until',
				'SIGTERM/SIGINT, then drains gracefully.',
			]
			run:     run_store_serve
		},
		SubcommandSpec{
			name:    'fabric-serve'
			summary: 'Run the CX fabric eventing daemon from a config.'
			help:    [
				'Usage: cx fabric-serve --config PATH [--allow-net[=host:port]] [--allow-*]',
				'',
				'Runs the single-node cx-fabric served tier: loads + validates the',
				'fabric.service.cx config, mounts the configured fabrics (journal-backed',
				'durable streams + transient channels), and serves XSP-AUTH-attached',
				'clients over raw XSP frames until SIGTERM/SIGINT, then drains.',
				'Health/ready probes ride the optional [health addr=…] listener',
				'(compatible with `cx store-health --url`).',
			]
			run:     run_fabric_serve
		},
		SubcommandSpec{
			name:    'store-health'
			summary: 'Store readiness probe (exit 0 iff accepting).'
			help:    [
				'Usage: cx store-health --url READY_URL',
				'',
				'Readiness probe for the store daemon (Docker HEALTHCHECK / systemd / LB):',
				'exit 0 iff the daemon at READY_URL reports accepting, else non-zero.',
			]
			run:     run_store_health
		},
		SubcommandSpec{
			name:    'store-token'
			summary: 'Mint a store bearer token + ready-to-paste config stanza.'
			help:    [
				'Usage: cx store-token --id NAME [--roles r1,r2] [--tenant SPEC]',
				'',
				'Generates a cryptographically-random bearer token: the [static [token ...]]',
				'config stanza goes to stdout (pipeable), the secret to stderr — shown once,',
				'never stored (the config carries only the hash).',
				'  --roles    reader|writer|admin|metrics, comma-separated (default admin)',
				"  --tenant   tenant scope (default \"*\")",
			]
			run:     run_store_token
		},
		SubcommandSpec{
			name:    'store-rotate-kek'
			summary: 'Rotate a store key-encryption key (re-wrap envelopes).'
			help:    [
				'Usage: cx store-rotate-kek --url STORE_URL --encrypt-key-id OLD --new-key-id NEW',
				'',
				"Re-wraps every at-rest envelope's data key under the new tenant KEK",
				'(payloads and content addresses untouched; atomic per object, resumable,',
				'fail-closed) and prints the [rotation-report ...].',
				'Requires env CX_STORE_KEK_<OLD> and CX_STORE_KEK_<NEW> (64 hex chars each).',
			]
			run:     run_store_rotate_kek
		},
	]
}

// run_version implements the `cx version` verb — identical output to
// `cx -v` / `cx --version`. A verb (not only a flag) so the bare word can
// never fall through to the run surface and evaluate a ./VERSION file on a
// case-insensitive filesystem (#426 item b).
fn run_version(args []string) {
	if args.len > 0 {
		eprintln('cx version: takes no arguments')
		exit(2)
	}
	print_version()
	exit(0)
}

// print_subcommand_help prints the registered `cx <name> --help` body on
// stdout — the uniform -h/--help handler for every subcommand.
fn print_subcommand_help(sc SubcommandSpec) {
	for line in sc.help {
		println(line)
	}
}

// convert_text_format_names lists the codec-registry names usable as
// `--from` (kind 'from': codecs with a text parser) or `--to` (kind 'to':
// codecs with a text emitter). Derived from the live registry so the help
// matches the accepted set by construction; a preferred display order is
// applied, any future codec lands sorted at the end.
fn convert_text_format_names(kind string) []string {
	preferred := ['cx', 'xml', 'json', 'yaml', 'toml', 'md', 'csv', 'tsv', 'psv']
	mut avail := []string{}
	for n in cx.codec_names() {
		c := cx.codec_lookup(n) or { continue }
		if kind == 'from' {
			if _ := c.parse {
				avail << n
			}
		} else {
			if _ := c.emit {
				avail << n
			}
		}
	}
	mut out := []string{}
	for p in preferred {
		if p in avail {
			out << p
		}
	}
	mut rest := avail.filter(it !in preferred)
	rest.sort()
	out << rest
	return out
}

fn usage_text() string {
	// Capability flags derive from the accepted set (code.capability_names),
	// the --from/--to lists from the codec registry, and the subcommand
	// catalog from the dispatch table — no hand-maintained copies.
	mut allow_flags := code.capability_names().map('--allow-' + it)
	allow_flags << '--allow-all'
	mut b := []string{}
	b << 'Usage:'
	b << '  cx FILE.cx [flags]        Run a CX resource (the default action): parse and'
	b << '                            evaluate. A pure-data document evaluates to itself.'
	b << '  cx - [flags]              Run a program from stdin (a pipe into bare `cx`'
	b << '                            with no FILE also evaluates stdin).'
	b << "  cx -e 'PROGRAM' [flags]   Run an inline program (also --expression)."
	b << '  cx <subcommand> [args]    One of the subcommands below.'
	b << '  cx -v | --version         Version / build info.'
	b << '  cx -h | --help            This help.'
	b << ''
	b << 'Run flags (the default action):'
	b << '  --cx (default) | --xml | --json | --yaml | --csv | --tsv   render the RESULT'
	b << '  --data=FILE|-             separate data input: loaded via the data reading'
	b << '                            and bound as $doc/$input before evaluation; the'
	b << '                            caller input WINS over the program\'s data roots.'
	b << '  Unknown flags are hard usage errors (exit 2) — nothing is ignored.'
	b << '  Capabilities are deny-by-default (spec/core/security.md); grant explicitly:'
	b << '    ' + allow_flags[..5].join(' ')
	b << '    ' + allow_flags[5..].join(' ')
	b << '    (--allow-net takes an optional scope: --allow-net=host[:port])'
	b << ''
	b << 'Convert flags (the data reading; an explicit --from selects it):'
	b << '  cx --from=FMT [--to=FMT] [--compact] [--lossless] [--include-root=DIR] [FILE]'
	b << '    --from: ' + convert_text_format_names('from').join('|')
	b << '            (.xml/.json/.yaml/.toml/.md files auto-detect their format)'
	b << '    --to:   ' + convert_text_format_names('to').join('|')
	b << '  Projection shorthands: --ast --cx --xml --json --yaml --toml --md --csv'
	b << '                         --tsv --psv --cxcol'
	b << '  --compact              minimised output'
	b << '  --lossless             emit round-trip-preserving output (conversions.md'
	b << '                         0.2/2.2.1): xml carries cx: markers; json/yaml'
	b << '                         carry the \$tag structure envelope plus a `cx:type`'
	b << '                         sidecar / `!!cx:T` tags — element docs re-import'
	b << '                         byte-identically (cx/xml/json/yaml targets; other'
	b << '                         lanes reject the flag)'
	b << '  --include-root=DIR     resolve [?cx include=...] against DIR first'
	b << ''
	b << 'Subcommands (`cx <subcommand> --help` for details):'
	for sc in subcommands {
		b << '  ${sc.name:-17} ${sc.summary}'
	}
	return b.join('\n') + '\n'
}

fn print_usage_and_exit(exit_code int) {
	// --help goes to stdout (exit 0); the no-input usage nudge goes to stderr.
	text := usage_text()
	if exit_code == 0 {
		print(text)
	} else {
		eprint(text)
	}
	exit(exit_code)
}
