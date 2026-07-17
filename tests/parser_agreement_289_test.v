module main

import cx
import code

// parser_agreement_289_test.v — issue #289: `cx fmt`, the [?lib] module
// loader, and eval must AGREE (accept or reject identically) on the same
// source. Three live divergences drove this:
//
//   1. xap-marine composer.cx carried ONE stray top-level `]` (line 372,
//      the apply def's closer chain): `cx fmt` correctly rejected the file,
//      but the loader's directive scanner silently skipped the stray closer
//      and served the module in production.
//   2. A module with a stray top-level `]` between defs loaded and ran via
//      [?lib] while direct eval rejected it — and `cx fmt` fell back to the
//      DATA reading, which absorbed the `]` into a top-level TextNode
//      (grammar violation: BareValue [L70] excludes `]`) and emitted a
//      MANGLED document with exit 0.
//   3. A `#` line comment ([30b]) containing an apostrophe (`don't`) inside
//      a [?def] body: the program lexer skipped it as a comment, but the
//      loader's find-close-bracket balancer and the def-body capture scanner
//      treated the apostrophe as a canonical-string opener and swallowed
//      brackets — each shifting balance its own way.
//
// Entry points under test (the funnels every CLI surface goes through):
//   - cx.parse_program — eval + fmt's program reading
//   - cx.parse         — the data reading (fmt's fallback)
//   - code.fmt_source  — `cx fmt`
//   - code.load_module — the [?lib] loader
//   - cx.parse_def     — [?def] capture (direct eval and the loader share it)
//
// Spec authority: lexicon.ebnf [L2]/[L3]/[L70], grammar.ebnf [30]/[30b]/[31].

fn loader_accepts(src string) bool {
	mut table := code.new_module_table()
	code.load_module(src, 'm-289', mut table) or { return false }
	return true
}

fn loader_def_count(src string) int {
	mut table := code.new_module_table()
	mod := code.load_module(src, 'm-289-count', mut table) or { return -1 }
	return mod.defs.len
}

fn fmt_accepts(src string) bool {
	code.fmt_source(src) or { return false }
	return true
}

fn program_accepts(src string) bool {
	cx.parse_program(src) or { return false }
	return true
}

fn data_accepts(src string) bool {
	cx.parse(src) or { return false }
	return true
}

// def_parses asserts the [?def] capture path BOTH eval and the loader use:
// parse_def to split the surface, then parse_program on the captured body
// (exactly what eval_def / the loader's Pass-2 do).
fn def_parses(src string) bool {
	def := cx.parse_def(src) or { return false }
	cx.parse_program(def.body) or { return false }
	return true
}

// ── Defect 2: a stray top-level `]` must be rejected EVERYWHERE ──────────────

fn test_stray_closer_between_defs_rejected_everywhere() {
	src := '[?def hello scope=public (\$x) [\$concat "hi " \$x]]\n' + ']\n' +
		'[?def bye scope=public (\$x) [\$concat "bye " \$x]]\n'
	assert !program_accepts(src), 'program reading must reject a stray top-level `]`'
	assert !data_accepts(src), 'data reading must reject a stray top-level `]` (GR-STRAY-CLOSE)'
	assert !fmt_accepts(src), 'cx fmt must reject, not data-mangle, a stray top-level `]`'
	assert !loader_accepts(src), 'the [?lib] loader must reject a stray top-level `]`'
}

fn test_stray_closer_glued_to_closer_chain_rejected_everywhere() {
	// The composer.cx shape: ONE extra `]` glued to a def's closer chain.
	src := '[?def f (\$v) [?if [= \$v 1] [then \$v] [else \$v]]]]\n'
	assert !program_accepts(src)
	assert !data_accepts(src)
	assert !fmt_accepts(src)
	assert !loader_accepts(src)
}

fn test_balanced_closer_chain_accepted_everywhere() {
	// Same shape WITHOUT the stray closer — every entry point accepts.
	src := '[?def f (\$v) [?if [= \$v 1] [then \$v] [else \$v]]]\n'
	assert program_accepts(src)
	assert data_accepts(src)
	assert fmt_accepts(src)
	assert loader_accepts(src)
	assert def_parses(src)
}

fn test_leading_stray_closer_rejected_everywhere() {
	src := ']\n[?def f (\$x) \$x]\n'
	assert !program_accepts(src)
	assert !data_accepts(src)
	assert !fmt_accepts(src)
	assert !loader_accepts(src)
}

// ── Defect 3: `#` line comments with apostrophes ([30b]) ─────────────────────

fn test_hash_comment_with_apostrophe_at_top_level_accepted_everywhere() {
	src := "# module header — don't panic\n" + '[?def hello scope=public (\$x) \$x]\n'
	assert program_accepts(src)
	assert data_accepts(src)
	assert fmt_accepts(src)
	assert loader_accepts(src)
}

fn test_hash_comment_with_apostrophe_inside_def_body_accepted_everywhere() {
	// The xap-marine shape: a trailing `# …` comment with an apostrophe
	// INSIDE a def body. The apostrophe must not open a string span in any
	// scanner — the second def must still be discovered.
	src := '[?def hello scope=public (\$x)   # record the turn — don' + "'" +
		't panic\n  [\$concat "hi " \$x]]\n' +
		'[?def bye scope=public (\$x) [\$concat "bye " \$x]]\n'
	assert program_accepts(src), 'program reading must skip the # comment'
	assert fmt_accepts(src), 'cx fmt must accept the # comment'
	assert loader_accepts(src), 'loader must not let the apostrophe swallow brackets'
	assert loader_def_count(src) == 2, 'both defs must survive the # comment'
	first_def := '[?def hello scope=public (\$x)   # record the turn — don' + "'" +
		't panic\n  [\$concat "hi " \$x]]'
	assert def_parses(first_def), '[?def] capture must skip the # comment'
}

fn test_hash_comment_swallow_would_shift_balance() {
	// Adversarial: if the apostrophe opened a string, it would close at the
	// apostrophe inside the SECOND def's string ("y'all") and mis-balance.
	src := '[?def a scope=public (\$x)  # don' + "'" + 't\n  \$x]\n' +
		'[?def b scope=public (\$x) [\$concat "y' + "'" + 'all " \$x]]\n'
	assert program_accepts(src)
	assert fmt_accepts(src)
	assert loader_accepts(src)
	assert loader_def_count(src) == 2
}

// ── `[; … ]` block comments with apostrophes inside a def body ───────────────

fn test_block_comment_with_apostrophe_inside_def_body_accepted_everywhere() {
	// The composer.cx §201-204 shape moved INSIDE a def: bracketed prose
	// plus an apostrophe. (The top-level variant is covered by
	// comment_bracket_balance_test.v.)
	src := '[?def f scope=public (\$x) [; the caller' + "'" +
		's [?else] — see [ok]/[err] ] [\$concat "hi " \$x]]\n' +
		'[?def g scope=public (\$x) \$x]\n'
	assert program_accepts(src)
	assert fmt_accepts(src)
	assert loader_accepts(src)
	assert loader_def_count(src) == 2
}

// ── `[#…#]` raw text with quotes/brackets inside a def body ──────────────────

fn test_raw_span_with_apostrophe_and_brackets_inside_def_body() {
	// Raw text is verbatim [31]: apostrophes and lone brackets inside it
	// must not affect string state or bracket depth in ANY scanner.
	src := '[?def f (\$x) [?let [= \$d [# raw don' + "'" +
		't [not-a-form ] #]] \$x]]\n' + '[?def g (\$x) \$x]\n'
	assert program_accepts(src)
	assert fmt_accepts(src)
	assert loader_accepts(src)
	assert loader_def_count(src) == 2
}

// ── string / comment / bracket interaction matrix ────────────────────────────

fn test_string_containing_bracket_and_hash_not_a_comment() {
	// `#` and `]`/`[` INSIDE a quoted string are content, never comments.
	src := '[?def f scope=public (\$x) [\$concat "] tail # not-a-comment [" \$x]]\n' +
		'[?def g scope=public (\$x) \$x]\n'
	assert program_accepts(src)
	assert fmt_accepts(src)
	assert loader_accepts(src)
	assert loader_def_count(src) == 2
}

fn test_hash_comment_containing_brackets_and_quotes() {
	// Everything after `# ` to EOL is opaque: brackets AND quotes.
	src := '[?def f scope=public (\$x)  # see [?match] and "quoted ] text" and \'more\n  \$x]\n' +
		'[?def g scope=public (\$x) \$x]\n'
	assert program_accepts(src)
	assert fmt_accepts(src)
	assert loader_accepts(src)
	assert loader_def_count(src) == 2
}

fn test_hash_glued_to_bareword_is_not_a_comment() {
	// [30b]: `#` inside a BareValue is literal — `tag#anchor` stays one token.
	src := '[?def f scope=public (\$x) [\$concat "u" "rl#frag"]]\n'
	assert program_accepts(src)
	assert fmt_accepts(src)
	assert loader_accepts(src)
}

fn test_unterminated_block_comment_in_def_body_rejected_everywhere() {
	src := '[?def f (\$x) [; never closed \$x'
	assert !program_accepts(src)
	assert !fmt_accepts(src)
	assert !loader_accepts(src)
}

// ── [?const] value capture — same opaque-span rules ──────────────────────────

fn test_const_with_hash_comment_apostrophe_in_value() {
	src := '[?const GREETING [\$concat "hi"   # don' + "'" + 't mind me\n  " there"]]\n' +
		'[?def g scope=public (\$x) \$x]\n'
	assert program_accepts(src)
	assert fmt_accepts(src)
	assert loader_accepts(src)
	assert loader_def_count(src) == 1
}
