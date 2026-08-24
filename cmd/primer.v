module main

// `cx primer` — the LLM onboarding door that cannot go stale (#938).
//
// CX post-dates every language model's training data, so an assistant's
// proficiency has to come entirely from context the project supplies. Three
// doors serve the same generated text: AGENTS.md at the repo root, /llms.txt
// on the site, and this subcommand. This one is the durable one: "run
// `cx primer` before writing any CX" always yields the primer matching the
// binary in the caller's PATH, with no checkout and no network.
//
// The text is EMBEDDED at compile time from docs/llm/primer.md — the
// generated artifact `make docs` produces (scripts/gen_docs/primer_build.cx),
// whose every code block is a conformance fixture replayed against the
// binary. Same $embed_file idiom as vcx/code/stdlib_bundle.v, and the same
// consequence: the file must exist in a fresh clone for the toolchain to
// build at all, which is why docs/llm/ is generated-and-COMMITTED while the
// HTML guide under docs/guide/ is not.
//
// VERSION DISCIPLINE. There is exactly one source of truth for the version —
// the repo-root VERSION file. It reaches this command down two independent
// paths: primer_build.cx stamps the primer's own heading from it, and
// vcx/Makefile stamps `cx_version` from it. Neither is a hand-kept copy, and
// this command ASSERTS they agree: a disagreement means the binary and the
// embedded document were produced at different versions (the usual cause is a
// VERSION bump followed by a rebuild without `make docs`, or the reverse).
// That is reported on STDERR, loudly, while stdout stays byte-exact — so
// `cx primer` remains pipeable and `cx primer | diff - docs/llm/primer.md`
// stays a usable freshness gate.

const primer_text = $embed_file('../../docs/llm/primer.md').to_string()

// primer_version_matches reports whether the embedded primer's heading carries
// the same version this binary was stamped with. The heading is written
// `# CX primer for LLM assistants — vX.Y.Z` by primer_build.cx; the check is
// deliberately a substring test on `v<version>` rather than a parse of the
// heading shape, so a prose change to the template cannot turn this into a
// vacuous pass or a false alarm.
fn primer_version_matches() bool {
	return primer_text.contains('v${version}')
}

fn run_primer(args []string) {
	if args.len > 0 {
		eprintln('cx primer: takes no arguments')
		eprintln("run 'cx primer --help' for what this prints")
		exit(2)
	}
	if !primer_version_matches() {
		eprintln('cx primer: WARNING — this binary is stamped v${version}, but the')
		eprintln('  embedded primer does not carry that version. The binary and the')
		eprintln('  document were built from different states of the VERSION file.')
		eprintln('  Fix: run `make docs` and then `make build-vcx`, in that order.')
	}
	// Verbatim, no added header: stdout must stay byte-identical to
	// docs/llm/primer.md so the freshness gate can diff the two.
	print(primer_text)
	flush_stdout()
	exit(0)
}
