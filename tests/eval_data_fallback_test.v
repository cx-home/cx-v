module main

import os
import testenv

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
	return testenv.cx_bin()
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

// ── 9. #18: infix `=` inside [where] must FAIL LOUD with the prefix-form hint, ─
//        NOT silently data-fall-back to a data echo of the program source.
//
// `[?for … [where $x/@a=v] …]` is unambiguous PROGRAM intent — the parser
// committed to the `[where]` clause before hitting the infix `=`. Before the
// fix the program parse failed, the whole source re-read as a data element, and
// the helpful "use the prefix form" diagnostic (added on main, 4f17da73) was
// buried behind a data echo. The parser now flags this error program_committed
// so the eval boundary surfaces it instead of falling back.

fn test_where_infix_eq_fails_loud_not_data_fallback() {
	src := '[?let [= \$users [users [u active=true [email "a@x"]] [u active=false [email "b@x"]]]]\n' +
		'  [?for [in \$u \$users//u] [where \$u/@active=true] [yield \$u/email]]]\n'
	f := tmp_doc('whereinfix', src)
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code != 0, 'infix = in [where] must error, not data-fall-back: ${r.output}'
	assert r.output.contains('CXER0100'), 'expected CXER0100, got: ${r.output}'
	assert r.output.contains('PREFIX predicate'), 'expected the prefix-form hint, got: ${r.output}'
	// And it must NOT have silently echoed the source as data.
	assert !r.output.contains('[?for'), 'data-fallback fired (program echoed as data): ${r.output}'
}

// ── 10. A program-SHAPED resource (registered [?directive] in its data ────────
//        reading) whose program parse fails must FAIL LOUD, not echo as data.
//
// Field repro (xap-marine stage-2): a broken program — here a bare unquoted
// CXPath attr value inside [?for], which the program parser rejects — silently
// re-read as a DATA document and echoed itself back with exit 0. In a make
// target or CI that reads as success while the program never evaluated. The
// eval boundary now scans the data reading for registered program directives
// (string-aware: directives inside quoted prose are text) and surfaces the
// original program error for program-shaped sources.

fn test_program_shaped_lex_failure_fails_loud_not_data_echo() {
	src := '[?for \$f :in [\$doc select=//features/feature] :yield [out [\$f]]]\n'
	f := tmp_doc('progshape', src)
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code != 0, 'program-shaped source must error, not data-fall-back: ${r.output}'
	assert r.output.contains('CXER0100'), 'expected CXER0100, got: ${r.output}'
	assert !r.output.contains('[?for'), 'data-fallback fired (program echoed as data): ${r.output}'
}

// A TOKENIZER (LexError) failure inside a directive body — em-dash prose the
// program lexer cannot read — is the class the #11/#18 flags never see
// (tokenize() fails before the parser can set unknown_directive /
// program_committed). With a [?let] present the source is program-shaped, so
// it must error, not echo.

fn test_program_shaped_tokenizer_failure_fails_loud() {
	f := tmp_doc('progshapelex', '[?let [= \$x 1] [p a — b]]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code != 0, 'lexer breakage in a [?let] must error, not data-fall-back: ${r.output}'
	assert r.output.contains('CXER0100'), 'expected CXER0100, got: ${r.output}'
	assert !r.output.contains('[?let'), 'data-fallback fired (program echoed as data): ${r.output}'
}

// String-awareness guard: prose that MENTIONS a directive inside quoted text
// is NOT program-shaped — the quoted span parses as text content, not as a
// directive node — so the prose fallback still applies.

fn test_prose_mentioning_directive_in_quotes_still_falls_back() {
	f := tmp_doc('prosequote', '[note — "use [?let] for bindings"]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code == 0, 'quoted-directive prose must still fall back: ${r.output}'
	assert r.output.contains('use [?let] for bindings'), 'content lost: ${r.output}'
}

// The corrected PREFIX form still computes (no over-broad fail-loud regression).

fn test_where_prefix_form_still_computes() {
	src := '[?let [= \$users [users [u active=true [email "a@x"]] [u active=false [email "b@x"]] [u active=true [email "c@x"]]]]\n' +
		'  [?for [in \$u \$users//u] [where [= \$u/@active true]] [yield \$u/email]]]\n'
	f := tmp_doc('whereprefix', src)
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code == 0, 'prefix [where] errored: ${r.output}'
	assert r.output.contains('a@x') && r.output.contains('c@x'), 'prefix filter wrong: ${r.output}'
	assert !r.output.contains('b@x'), 'prefix filter did not exclude inactive: ${r.output}'
}

// ── #472: rooted-path glued `@attr` tail after a predicate fails LOUD ─────────
//
// `//team/member[= $_@name "alpha"]@id` in element-body position silently
// degraded to a text run: the glued `@` tail is not a rooted-PathExpr surface
// (grammar [130a] separates steps with '/'; canonical.md §2.12.6 — the glued
// `@attr` tail is BindingPath-only, [135a]/[162]), the unconsumed `@` failed the
// program parse with a generic error, and the eval boundary silently re-read the
// whole resource as DATA (rc=0, silent wrong answer). A fused [159b] predicate
// body is not prose: once a step carries a parsed predicate the parser has
// committed to a program construct, so the error is program_committed and the
// diagnostic (pointing at the `/@attr` spelling) must surface.

fn test_rooted_path_attr_tail_after_predicate_fails_loud() {
	src := '[teams\n' +
		'  [team name="alpha" [member id=1] [member id=2]]\n' +
		'  [team name="beta" [member id=3]]]\n' +
		'[r //team/member[= \$_@name "alpha"]@id]\n'
	f := tmp_doc('attrtailpred', src)
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code != 0, 'glued @attr tail after a predicate must error, not data-fall-back: ${r.output}'
	assert r.output.contains('CXER0100'), 'expected CXER0100, got: ${r.output}'
	assert r.output.contains('/@attr'), 'expected the /@attr rewrite hint, got: ${r.output}'
	// And it must NOT have silently echoed the path source as a text run.
	assert !r.output.contains("'//team/member"), 'data-fallback fired (path echoed as text): ${r.output}'
}

// The spelled `/@attr` step after a predicate computes (the grammar-conformant
// form of the same query — no over-broad fail-loud regression).

fn test_rooted_path_predicate_then_slash_attr_still_computes() {
	src := '[teams\n' +
		'  [team name="alpha" [member id=1] [member id=2]]\n' +
		'  [team name="beta" [member id=3]]]\n' +
		'[r //team/member[= \$_@id 1]/@id]\n'
	f := tmp_doc('attrtailslash', src)
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code == 0, 'spelled /@attr after predicate errored: ${r.output}'
	assert r.output.contains('[id 1]'), 'expected the attribute node, got: ${r.output}'
}

// Binding-path glued tails (`$doc//team/member[pred]@id`) are grammar-
// sanctioned surface ([135a] BindingStep / [162] BindingPostfix) and keep
// working.

fn test_binding_path_glued_attr_tail_still_computes() {
	src := '[?let [= \$d [teams [team name="alpha" [member id=1] [member id=2]] [team name="beta" [member id=3]]]]\n' +
		' [r \$d//team/member[= \$_@id 1]@id]]\n'
	f := tmp_doc('attrtailbind', src)
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code == 0, 'binding-path glued @attr tail errored: ${r.output}'
	assert r.output.contains('[id 1]'), 'expected the attribute node, got: ${r.output}'
}

// The bare (predicate-free) glued tail stays PROSE-ELIGIBLE: `//host/share@snap`
// -like spans are legitimate data text, so a document whose program reading
// trips only on a bare glued tail still falls back to the data reading. The
// decision boundary is the predicate: fused predicate = program intent (loud),
// bare tail = prose (data echo).

fn test_rooted_path_bare_attr_tail_prose_still_falls_back() {
	f := tmp_doc('attrtailprose', '[note see //docs/readme@main for details]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code == 0, 'bare glued-tail prose must still fall back: ${r.output}'
	assert r.output.contains('//docs/readme@main'), 'prose content lost: ${r.output}'
}

// ── #471: [?modify] focus predicate referencing a free/outer binding ──────────
//
// The standalone modify bridge's predicate filter evaluates against an empty
// env; a focus predicate referencing a binding beyond the reserved $_ /
// $_position / $_last set identity-passed EVERY candidate (both members
// flagged, rc=0). The bridge now declines such paths: a genuinely unbound
// binding surfaces CXER0001 via the legacy evaluator's full program-eval
// predicates; a bound outer binding filters correctly. (Conformance:
// program-modify-outer-pred-001…005 in conformance/code.cxd.)

fn test_modify_focus_predicate_unbound_binding_raises() {
	src := '[?let [= \$d [teams [team name="alpha" [member id=1]] [team name="beta" [member id=2]]]]\n' +
		' [?modify \$d //team/member[= \$qqq@name "alpha"] [set-attr flagged true]]]\n'
	f := tmp_doc('modunbound', src)
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code != 0, 'unbound \$qqq in modify focus predicate must raise, not identity-pass: ${r.output}'
	assert r.output.contains('CXER0001'), 'expected CXER0001, got: ${r.output}'
}

fn test_modify_focus_predicate_bound_outer_binding_filters() {
	src := '[?let [= \$d [teams [team name="alpha" [member id=1]] [team name="beta" [member id=2]]]]\n' +
		' [?let [= \$flag "alpha"]\n' +
		'  [?modify \$d //team[= \$_@name \$flag]/member [set-attr flagged true]]]]\n'
	f := tmp_doc('modbound', src)
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code == 0, 'bound outer binding in modify focus predicate errored: ${r.output}'
	assert r.output.contains('[team name=alpha [member id=1 flagged=true]]'), 'alpha member not flagged: ${r.output}'
	assert r.output.contains('[team name=beta [member id=2]]'), 'beta member wrongly flagged (identity-pass): ${r.output}'
}

// ── #421: the [?cx …] PI/config namespace is NOT a §4.1 directive ────────────
//
// Regression guard: the unknown-directive fail-loud classification (the class-1
// flag added for #11) treated EVERY registry miss as program intent — including
// the `cx` CXDirective namespace (grammar [34]; the [59a] note: the bare name
// `cx` is NOT an EvalName). That broke the approved code.md §13 include surface
// (`[?cx include=…]` — preserved verbatim when no include root is supplied) and
// every bare `[?cx …]` config PI, in .cx and .cxd alike. The fix classifies the
// `cx` head BEFORE the §4.1 registry lookup and parses the directive via the
// node_lit DATA↔PROGRAM seam, so the program reading of a CXDirective IS the
// data reading. Unknown `[?name]` heads other than `cx` stay fail-closed
// (tests 7/8 above pin that).

fn test_cx_include_directive_preserved_in_program_mode() {
	f := tmp_doc('cxinc', '[config [?cx include=defaults.cx] [a 1]]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code == 0, '[?cx include] must parse in program mode: ${r.output}'
	assert r.output.contains('[?cx include=defaults.cx]'),
		'include directive not preserved verbatim: ${r.output}'
	assert r.output.contains('[a 1]'), 'sibling content lost: ${r.output}'
}

fn test_bare_cx_config_pi_passes_through() {
	path := os.join_path(os.temp_dir(), 'cx_dfb_cxpi_${os.getpid()}.cxd')
	os.write_file(path, '[?cx version=1.0]\n[config [a 1]]\n') or { panic(err) }
	defer { os.rm(path) or {} }
	r := os.execute('${cx_bin()} ${path}')
	assert r.exit_code == 0, 'bare [?cx version=…] PI must not error: ${r.output}'
	assert r.output.contains('[?cx version=1.0]'), 'config PI not preserved: ${r.output}'
	assert r.output.contains('[a 1]'), 'document content lost: ${r.output}'
}

fn test_unknown_cx_key_passes_through() {
	// grammar [34] admits any CXAttr list on [?cx …]; the layer that consumes
	// each attr is selected by attr name, so an unrecognized key rides along
	// verbatim (no error, no drop).
	f := tmp_doc('cxbogus', '[?cx bogus=1]\n')
	defer { os.rm(f) or {} }
	r := os.execute('${cx_bin()} ${f}')
	assert r.exit_code == 0, 'unknown [?cx key must pass through, not error: ${r.output}'
	assert r.output.trim_space() == '[?cx bogus=1]', 'unknown-key PI not preserved: ${r.output}'
}
