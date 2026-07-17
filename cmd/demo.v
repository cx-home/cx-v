// `cx demo` subcommand per the evaluation-experience checklist (60s tier).
//
// Self-contained showcase: no file I/O, no network, no dependencies.
// Demonstrates type fidelity, a [table[…]] block → CSV, a CX program
// evaluating, and the CX-vs-JSON comparison framing in under 1s wall-clock.
//
// Deterministic output — diff-able byte-for-byte against
// fixtures/expected_demo_output.txt (tools/smoke-eval.sh gate).
//
// Every internal step FAILS LOUDLY: a conversion or evaluation error prints
// to stderr and exits non-zero (#418 — the old demo swallowed an
// emit_delimited error mid-demo and still exited 0).

module main

import cx
import code

// demo_fail reports a broken demo step and exits non-zero — a demo that
// demonstrates an error must never look like a success.
@[noreturn]
fn demo_fail(step string, err IError) {
	eprintln('cx demo: ${step} failed: ${err.msg()}')
	exit(1)
}

fn run_demo(args []string) {
	println('╭──────────────────────────────────────────────────────────────╮')
	println('│ CX — one format for config, data, docs, and tabular data │')
	println('╰──────────────────────────────────────────────────────────────╯')
	println('')

	// ── Demo 1: typed round-trip CX ↔ JSON ─────────────────────────────────
	println('1. Typed round-trip: integers stay integers across format hops')
	println('─────────────────────────────────────────────────────────────────')
	println('')
	src := '[config
 [port::u16 8080]
 [user_id::i64 9007199254740993]
 [pi::f64 3.141592653589793]
]'
	println(' CX source:')
	for line in src.split('\n') { println(' ${line}') }
	println('')

	json_out := cx.to_json(src) or { demo_fail('typed CX → JSON', err) }
	println(' Converted to JSON (cx --from=cx --to=json):')
	for line in json_out.trim_space().split('\n') { println(' ${line}') }
	println('')
	println(' JSON would silently float 9007199254740993 → 9007199254740992')
	println(' in JavaScript / browsers / many parsers. CX/CXCol preserves')
	println(' int64 exactly. This is the type-fidelity contract that makes')
	println(' CX an honest source-of-truth format.')
	println('')

	// ── Demo 2: [table[…]] block round-tripped to CSV ──────────────────────
	println('2. [table[…]] — tabular data as a first-class shape (CSV round-trippable)')
	println('─────────────────────────────────────────────────────────────────')
	println('')
	tbl := '[users [table[name age::int city]]
 alice 30 portland
 bob 25 austin
 carol 40 lisbon
]'
	println(' CX source:')
	for line in tbl.split('\n') { println(' ${line}') }
	println('')

	csv_out := cx.to_csv(tbl) or { demo_fail('[table[…]] → CSV', err) }
	println(' Converted to CSV (cx --csv — RFC 4180):')
	for line in csv_out.trim_space().split('\n') { println(' ${line}') }
	println('')

	// ── Demo 3: CX program ───────────────────────────────────────────────
	println('3. CX code — programs share the data syntax, one parser, one model')
	println('─────────────────────────────────────────────────────────────────')
	println('')
	prog := "[?let [= \$name erik] [= \$verbose true]
 [greeting [?if \$verbose
   [then [?str 'Hello, {\$name}!']]
   [else [?str 'Hello, friend!']]]]]"
	println(' Program:')
	for line in prog.split('\n') { println(' ${line}') }
	println('')

	result := code.eval_code('', prog, 'cx') or { demo_fail('CX program evaluation', err) }
	println(' Evaluates to: ${result.trim_space()}')
	println(' (Run any file the same way: cx program.cx — or pipe one in:')
	println(' cat data.cx program.cx | cx)')
	println('')

	// ── Demo 4: side-by-side comparison ────────────────────────────────────
	println('4. Why CX over JSON / YAML / TOML?')
	println('─────────────────────────────────────────────────────────────────')
	println('')
	println(' | feature | JSON | YAML | TOML | CX |')
	println(' |----------------------------------|------|------|------|----|')
	println(' | Comments | - | ✓ | ✓ | ✓ |')
	println(' | Sized integer types | - | - | - | ✓ |')
	println(' | int64 / bigint precision | - | ✓ | ✓ | ✓ |')
	println(' | One syntax for data + docs | - | - | - | ✓ |')
	println(' | Canonical hash for content addr | - | - | - | ✓ |')
	println(' | Tabular `[table[…]]` block | - | - | - | ✓ |')
	println(' | logfmt mode (top-level kv) | - | - | - | ✓ |')
	println(' | Lossless round-trip to all 5 | - | - | - | ✓ |')
	println('')

	// ── Next steps ────────────────────────────────────────────────────────
	println('────────────────────────────────────────────────────────────────')
	println(' Next: cx scaffold config > my.cx # start a real file')
	println(' cx --json my.cx # render it as JSON')
	println(' cx canonical my.cx | cx hash # content-address it')
	println(' cx scaffold table | cx table info # inspect a [table[…]] block')
	println('')
	println(' Docs: https://cx-home.github.io/cx/')
	println(' Help: cx --help (cx <subcommand> --help for details)')
	println('────────────────────────────────────────────────────────────────')

	_ = args // unused; subcommand accepts no flags
}
