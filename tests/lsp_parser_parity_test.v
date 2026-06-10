module main

import cx

// LSP diagnostic / parser parity.
//
// One cxparse ENGINE, two reading MODES. A `.cx` resource is well-formed if it
// parses under EITHER:
//   • the DATA reading   (cx.parse)         — scannerless; prose, `[- … ]`
//     comments, mixed-content markup (a tour / doc);
//   • the PROGRAM reading (cx.parse_program) — tokenised; `[$call]`, directives,
//     operator heads, program map literals.
// These are modes of the SAME engine, NOT two separate parsers. The LSP
// (vcx/cmd/lsp.v `publish_diagnostics`) therefore raises a syntax diagnostic
// only when BOTH readings fail — exactly the rule this test pins.
//
// Regression history:
//   • Operator heads `[> a b]` / program maps `{k: v k: v}` were flagged as
//     false errors when nvim ran a stale pre-unification binary (its program
//     parser rejected them). Fixed by pointing the editor at the trunk build.
//   • Collapsing the LSP to program-ONLY then wrongly flagged valid DATA
//     documents — a `;` or em-dash in prose / a `[- … ]` comment is fine under
//     the data reading but is not a program token. Hence: accept-under-EITHER.

// Valid under the PROGRAM reading (data reading may reject — that's fine).
const valid_programs = [
	'[> 1 0]',
	'[?if [> [$count 3] 0] [then "yes"] [else "no"]]',
	'{a: 1, b: 2}',
	'{a: 1 b: 2}',
	'{observe: "errors" intents: ([do :add-stock [sym "AAPL"]])}',
	'[?for [in $g $s//group] [where [= $g@name "n"]] [yield $g]]',
	'[?lib \'./x.cx\' as=wl]',
	'[card total=[$count $items]]',
]

// Valid under the DATA reading (program reading rejects the prose/markup —
// `;`, em-dash bytes, mixed content — and that MUST NOT produce a diagnostic).
const valid_data_docs = [
	'[- a block comment with ; and , punctuation ]',
	'[doc [li bare prose with a ; semicolon]]',
	'[doc [p plain mixed content [strong bold] tail]]',
	'[server host=localhost [port::u16 8080]]',
	'[tags::string[] admin user]',
	'[- top comment ]\n[a 1]',
]

// Fails under BOTH readings → a genuine syntax error the LSP SHOULD flag.
const broken_both = [
	'[?if [> 1 0]',   // unterminated
	'[a 1',           // unterminated element
	'{a: 1,,b: 2}',   // empty map slot (rejected by program reading; data too)
]

fn parses_either(src string) bool {
	if _ := cx.parse(src) { return true }
	if _ := cx.parse_program(src) { return true }
	return false
}

fn test_valid_programs_accepted() {
	for src in valid_programs {
		assert parses_either(src), 'LSP would FALSE-flag a valid program: |${src}|'
		// specifically the program reading accepts it
		if _ := cx.parse_program(src) {} else {
			assert false, 'program reading rejected a valid program: |${src}|'
		}
	}
}

fn test_valid_data_docs_accepted() {
	for src in valid_data_docs {
		assert parses_either(src), 'LSP would FALSE-flag a valid data document: |${src}|'
		// specifically the data reading accepts it
		if _ := cx.parse(src) {} else {
			assert false, 'data reading rejected a valid data document: |${src}|'
		}
	}
}

fn test_broken_flagged() {
	for src in broken_both {
		assert !parses_either(src), 'expected BOTH readings to reject (LSP should flag): |${src}|'
	}
}
