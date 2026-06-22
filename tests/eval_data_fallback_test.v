module main

import os

// eval_data_fallback_test.v — #11: the eval/program reading must honour the
// spec invariant "a pure-data resource evaluates to itself" (code.md §1.3) even
// for prose/markup DATA documents whose element-body content the tokenized
// program reader cannot lex (em-dash, `;`, `,`, bullets, …) but the scannerless
// DATA reader accepts.
//
// Before the fix, `cx doc.cx` / `cx doc.cx --json` errored with CXER0100 on such
// documents (the data ⊂ program seam). The fix: when the program parse fails and
// there is no `$doc` input, fall back to the data reading via the SAME pipeline
// as `cx --from=cx --to=<target>` — so the eval output is byte-identical to the
// documented data path. A genuine program error that ALSO fails to parse as data
// still surfaces the original program error.

fn cx_bin() string {
	return os.join_path(@VMODROOT, 'target', 'cx')
}

fn tmp_doc(label string, content string) string {
	path := os.join_path(os.temp_dir(), 'cx_dfb_${label}_${os.getpid()}.cx')
	os.write_file(path, content) or { panic(err) }
	return path
}

// Each case is a prose/markup data document that the program lexer/parser cannot
// read but the data reader accepts.
const prose_cases = [
	'[p hello — world]\n', // em-dash (non-ASCII byte 0xe2…)
	'[p one, two. three]\n', // comma + period punctuation
	'[p a; b]\n', // semicolon
	'[note • bullet item]\n', // bullet (non-ASCII)
	'[doc [title A — B] [body x; y, z.]]\n', // nested prose
]

// ── 1. eval default (cx) == data path (--from=cx --to=cx) ────────────────────

fn test_eval_default_matches_data_path_cx() {
	for i, src in prose_cases {
		f := tmp_doc('cx${i}', src)
		defer { os.rm(f) or {} }
		ev := os.execute('${cx_bin()} ${f}')
		dp := os.execute('${cx_bin()} --from=cx --to=cx ${f}')
		assert ev.exit_code == 0, 'case ${i}: eval errored: ${ev.output}'
		assert dp.exit_code == 0, 'case ${i}: data path errored: ${dp.output}'
		assert ev.output.trim_space() == dp.output.trim_space(),
			'case ${i}: eval(cx) != data path:\n  eval: ${ev.output}\n  data: ${dp.output}'
	}
}

// ── 2. eval --json == data path --to=json ────────────────────────────────────

fn test_eval_json_matches_data_path_json() {
	for i, src in prose_cases {
		f := tmp_doc('json${i}', src)
		defer { os.rm(f) or {} }
		ev := os.execute('${cx_bin()} --json ${f}')
		dp := os.execute('${cx_bin()} --from=cx --to=json ${f}')
		assert ev.exit_code == 0, 'case ${i}: eval --json errored: ${ev.output}'
		assert dp.exit_code == 0, 'case ${i}: data --to=json errored: ${dp.output}'
		assert ev.output.trim_space() == dp.output.trim_space(),
			'case ${i}: eval(json) != data path:\n  eval: ${ev.output}\n  data: ${dp.output}'
	}
}

// ── 3. The reported repro: em-dash in prose no longer errors ─────────────────

fn test_em_dash_prose_no_longer_errors() {
	f := tmp_doc('emdash', '[p hello — world]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} --json ${f}')
	assert r.exit_code == 0, 'em-dash prose still errors: ${r.output}'
	assert r.output.contains('hello — world'), 'content lost: ${r.output}'
}

// ── 4. A program that is valid PROGRAM still evaluates (no spurious fallback) ─

fn test_valid_program_still_evaluates() {
	f := tmp_doc('prog', '[+ 1 2]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code == 0, 'program errored: ${r.output}'
	assert r.output.trim_space() == '3', 'program did not evaluate (fallback fired wrongly?): ${r.output}'
}

// ── 5. A genuinely BROKEN resource (bad as program AND data) still errors ────

fn test_broken_resource_still_errors() {
	f := tmp_doc('broken', '[?def foo ($x)\n') // unterminated directive — bad both ways
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code != 0, 'broken resource should error, got: ${r.output}'
	assert r.output.contains('CXER0100'), 'expected a parse error, got: ${r.output}'
}

// ── 6. A lexable pure-data document still round-trips as identity via eval ───

fn test_lexable_data_identity_unaffected() {
	f := tmp_doc('cfg', '[config host=localhost]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code == 0, 'identity case errored: ${r.output}'
	assert r.output.trim_space() == '[config host=localhost]', 'identity broken: ${r.output}'
}

// ── 7. An UNKNOWN directive must STAY fail-loud, NOT fall back to data ───────
//
// Regression guard: the #11 data-fallback was gated too broadly (ANY program
// parse failure). An unknown `[?directive]` tokenizes fine and is REJECTED at
// the parse level (CXER0100), but it is ALSO a valid data element, so the
// fallback re-read it as data and silently round-tripped `[?nope]` instead of
// erroring. The fallback now fires only on a tokenizer (LexError) failure —
// real prose/markup — so a parse-level directive rejection surfaces the error.

fn test_unknown_directive_does_not_fall_back_to_data() {
	f := tmp_doc('unkdir', '[?this-directive-does-not-exist]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code != 0, 'unknown directive must error, not data-fall-back: ${r.output}'
	assert r.output.contains('CXER0100'), 'expected CXER0100, got: ${r.output}'
	assert r.output.contains('unknown directive'), 'expected the unknown-directive diagnostic, got: ${r.output}'
}

// ── 8. A RETIRED directive (`[?try]`, §2.5 tombstone) likewise stays an error ─

fn test_retired_try_directive_does_not_fall_back_to_data() {
	f := tmp_doc('rettry', '[?try [/ 10 0] [catch \$err 0]]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code != 0, 'retired [?try] must error, not data-fall-back: ${r.output}'
	assert r.output.contains('CXER0100'), 'expected CXER0100, got: ${r.output}'
}
