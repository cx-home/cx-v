// `cx demo` subcommand per the evaluation-experience checklist (60s tier).
//
// Self-contained showcase: no file I/O, no network, no dependencies.
// Demonstrates type fidelity, :table → CSV, CX code templating, and the
// CX-vs-JSON comparison framing in under 60s wall-clock.
//
// Deterministic output — diff-able byte-for-byte against
// fixtures/expected_demo_output.txt.

module main

import cx

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
 [port :u16 8080]
 [user_id :i64 9007199254740993]
 [pi :f64 3.141592653589793]
]'
	println(' CX source:')
	for line in src.split('\n') { println(' ${line}') }
	println('')

	json_out := cx.to_json(src) or { 'error: ${err}' }
	println(' Converted to JSON:')
	for line in json_out.trim_space().split('\n') { println(' ${line}') }
	println('')
	println(' JSON would silently float 9007199254740993 → 9007199254740992')
	println(' in JavaScript / browsers / many parsers. CX/CXCol preserves')
	println(' int64 exactly. This is the type-fidelity contract that makes')
	println(' CX an honest source-of-truth format.')
	println('')

	// ── Demo 2: :table round-tripped to CSV ────────────────────────────────
	println('2. :table block as a first-class shape (CSV-natively round-trippable)')
	println('─────────────────────────────────────────────────────────────────')
	println('')
	tbl := '[users :table[name age:int city]
 alice 30 portland
 bob 25 austin
 carol 40 lisbon
]'
	println(' CX source:')
	for line in tbl.split('\n') { println(' ${line}') }
	println('')

	csv_out := cx.to_csv(tbl) or { 'error: ${err}' }
	println(' Converted to CSV ( — RFC 4180):')
	for line in csv_out.trim_space().split('\n') { println(' ${line}') }
	println('')

	// ── Demo 3: CX program ───────────────────────────────────────────────
	println('3. CX code — CX-native templating that shares one parser & data model')
	println('─────────────────────────────────────────────────────────────────')
	println('')
	tmpl := '[greeting [?if @verbose :then [?= @name] :else friend]]'
	data := '[ctx name=erik verbose=true]'
	println(' Template: ${tmpl}')
	println(' Data: ${data}')
	println('')

	// CX code eval at runtime needs context; demo a static parse to show
	// the form is recognised.
	parsed := cx.to_cx(tmpl) or { 'parse error: ${err}' }
	println(' Parses cleanly: ${parsed.trim_space()}')
	println(' (Full CX code eval: cx eval template.cx --data=data.cx)')
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
	println(' | Tabular `:table` block | - | - | - | ✓ |')
	println(' | logfmt mode (top-level kv) | - | - | - | ✓ |')
	println(' | Lossless round-trip to all 5 | - | - | - | ✓ |')
	println('')
	println(' Full comparison: docs/COMPARISON.md')
	println('')

	// ── Next steps ────────────────────────────────────────────────────────
	println('────────────────────────────────────────────────────────────────')
	println(' Next: cx scaffold config > my.cx # start a real file')
	println(' cx --json my.cx # convert to JSON')
	println(' cx canonical my.cx | cx hash # content-address it')
	println(' cx table info my.cx # inspect a :table block')
	println('')
	println(' Docs: https://github.com/cx-home/cx#readme')
	println(' docs/TUTORIAL.md docs/CHEATSHEET.md docs/FAQ.md')
	println('────────────────────────────────────────────────────────────────')

	_ = args // unused; subcommand accepts no flags
}
