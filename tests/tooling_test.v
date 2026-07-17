module main

import cx

// Tests for the canonical-form tooling C ABI (Phase 6 / spec/abi.md §2.6):
//   cx_text_fmt        — lossless canonical (preserves comments)
//   cx_text_canonical  — strict canonical (strips presentation)
//   cx_text_hash       — SHA-256 hex of strict canonical bytes
//   cx_text_eq         — strict canonical equality

fn test_fmt_preserves_comments() {
	src := '[config
  [; a comment ]
  [server host=localhost port=8080]
]'
	out := cx.cx_text_fmt(src) or { panic(err) }
	assert out.contains('a comment'), 'fmt must preserve comments; got: ${out}'
	assert out.contains('host=localhost')
}

fn test_canonical_strips_comments() {
	src := '[config
  [; a comment ]
  [server host=localhost port=8080]
]'
	out := cx.cx_text_canonical(src) or { panic(err) }
	assert !out.contains('a comment'), 'canonical must strip comments; got: ${out}'
	assert out.contains('host=localhost')
}

fn test_canonical_normalizes_whitespace() {
	src1 := '[config
  [server host=localhost port=8080]
]'
	src2 := '[config [server host=localhost port=8080]]'
	c1 := cx.cx_text_canonical(src1) or { panic(err) }
	c2 := cx.cx_text_canonical(src2) or { panic(err) }
	assert c1 == c2, 'whitespace-equivalent inputs must canonicalize the same\nc1=${c1}\nc2=${c2}'
}

fn test_hash_is_64_hex_chars() {
	src := '[config [server host=localhost]]'
	h := cx.cx_text_hash(src) or { panic(err) }
	assert h.len == 64, 'sha256 hex is 64 chars; got len=${h.len}'
	for c in h {
		ok := (c >= `0` && c <= `9`) || (c >= `a` && c <= `f`)
		assert ok, 'hash must be lowercase hex; got char ${rune(c).str()}'
	}
}

fn test_hash_is_stable() {
	src := '[config [server host=localhost port=8080]]'
	h1 := cx.cx_text_hash(src) or { panic(err) }
	h2 := cx.cx_text_hash(src) or { panic(err) }
	assert h1 == h2
}

fn test_hash_changes_when_data_changes() {
	a := '[config [server host=localhost port=8080]]'
	b := '[config [server host=localhost port=8081]]'
	ha := cx.cx_text_hash(a) or { panic(err) }
	hb := cx.cx_text_hash(b) or { panic(err) }
	assert ha != hb, 'different ports must hash differently'
}

fn test_eq_equivalent_inputs() {
	a := '[config
  [; comment one ]
  [server host=localhost port=8080]
]'
	b := '[config [server host=localhost port=8080]]'
	assert cx.cx_text_eq(a, b) or { panic(err) }
}

fn test_eq_different_inputs() {
	a := '[config [server host=a]]'
	b := '[config [server host=b]]'
	assert !cx.cx_text_eq(a, b) or { panic(err) }
}

fn test_fmt_idempotent() {
	src := '[config
  [server host=localhost port=8080 active=true]
  [database host=db.example.com]
]'
	once := cx.cx_text_fmt(src) or { panic(err) }
	twice := cx.cx_text_fmt(once) or { panic(err) }
	assert once == twice, 'fmt must be idempotent\nonce=${once}\ntwice=${twice}'
}

fn test_canonical_idempotent() {
	src := '[config
  [- ignore]
  [server host=localhost]
]'
	once := cx.cx_text_canonical(src) or { panic(err) }
	twice := cx.cx_text_canonical(once) or { panic(err) }
	assert once == twice, 'canonical must be idempotent'
}

// ── #455: a [; comment ] child must not terminate the attribute run ─────────
// Comments are lexical trivia (lexicon.ebnf §1 [L2]/[L3]: "skipped; never
// reach the parser"). A bare `key=value` line after a `[; … ]` child is the
// SAME attribute it is without the comment — pre-fix the data reader broke
// the ElementMeta loop at `[;` and read it as TEXT, splitting the strict-
// canonical (hash-bearing) lane away from fmt/--json/eval.

fn test_canonical_attr_after_comment_child() {
	src := '[config
 [; c ]
 env=dev
 [server host=localhost]
]'
	out := cx.cx_text_canonical(src) or { panic(err) }
	assert out.contains('env=dev'), 'env=dev must stay an attribute; got: ${out}'
	assert !out.contains("' env=dev '"), 'env=dev must not degrade to text; got: ${out}'
}

fn test_hash_is_comment_insensitive_around_attrs() {
	// Identical data, comment in three positions (absent / before the attr
	// line / after it) — strict canonical strips comments (canonical.md
	// §2.9), so all three MUST share one hash.
	bare := '[config
 env=dev
 [server host=localhost]
]'
	comment_first := '[config
 [; c ]
 env=dev
 [server host=localhost]
]'
	comment_after := '[config
 env=dev
 [; c ]
 [server host=localhost]
]'
	h0 := cx.cx_text_hash(bare) or { panic(err) }
	h1 := cx.cx_text_hash(comment_first) or { panic(err) }
	h2 := cx.cx_text_hash(comment_after) or { panic(err) }
	assert h0 == h2, 'comment after the attr line must not move the hash'
	assert h0 == h1, 'comment before the attr line must not move the hash (#455)'
	assert cx.cx_text_eq(comment_first, bare) or { panic(err) }
}

fn test_cx_text_fmt_attr_after_comment_child() {
	// The lossless data formatter's own reading of the doc: env=dev stays an
	// attribute and the comment survives on its own body line. (The CLI-lane
	// `cx fmt` quoting-flip regression is pinned in fmt_lossless_test.v,
	// which can exercise code.fmt_source.)
	src := '[config
 [; c ]
 env=dev
 [server host=localhost]
]'
	out := cx.cx_text_fmt(src) or { panic(err) }
	assert out.contains('[; c ]'), 'fmt must preserve the comment; got: ${out}'
	assert out.contains('env=dev'), 'fmt must keep the attr; got: ${out}'
	assert !out.contains("' env=dev '"), 'env=dev must not degrade to text; got: ${out}'
}

// ── #469 zone 1: a comment between bare text runs is canonical-inert ────────
// Comments are lexical trivia (lexicon.ebnf §1 [L2]/[L3]) — a bare text run
// interrupted by a `[; … ]` block comment or a `# …` line comment reads as
// the SAME single text node it is without the comment ("a b"), so strict
// canonical / hash / eq are those of the comment-free document. Pre-fix the
// body reader flushed the run at the comment, splitting it into two text
// nodes ('a ' / ' b') and moving the hash.

fn test_hash_is_comment_insensitive_in_text_runs() {
	bare := '[config a b]'
	block_mid := '[config a [; c ] b]'
	line_mid := '[config a\n # c\n b\n]'
	block_lead := '[config [; c ] a b]'
	block_trail := '[config a b [; c ]]'
	h0 := cx.cx_text_hash(bare) or { panic(err) }
	assert (cx.cx_text_hash(block_mid) or { panic(err) }) == h0, 'block comment mid-run must not move the hash (#469)'
	assert (cx.cx_text_hash(line_mid) or { panic(err) }) == h0, 'line comment mid-run must not move the hash (#469)'
	assert (cx.cx_text_hash(block_lead) or { panic(err) }) == h0, 'leading comment must not move the hash (#469)'
	assert (cx.cx_text_hash(block_trail) or { panic(err) }) == h0, 'trailing comment must not move the hash (#469)'
	assert cx.cx_text_eq(block_mid, bare) or { panic(err) }
}

fn test_canonical_text_run_not_split_by_comment() {
	out := cx.cx_text_canonical('[config a [; c ] b]') or { panic(err) }
	assert out.trim_space() == '[config a b]', 'comment must not split the text run; got: ${out}'
}

fn test_comment_erasure_glue_semantics_in_text_runs() {
	// The comment contributes NOTHING to the text; the real whitespace
	// around it is what separates. (A comment opener GLUED to the left
	// token — `a[; c ]b` — is not a comment at all: mid-token `[` stays
	// text under the body tokenizer, pre-existing surface.)
	left_ws := cx.cx_text_canonical('[config a [; c ]b]') or { panic(err) }
	assert left_ws.trim_space() == '[config a b]', 'pre-comment space survives erasure; got: ${left_ws}'
	both_ws := cx.cx_text_canonical('[config a [; c ] b]') or { panic(err) }
	assert both_ws.trim_space() == '[config a b]', 'ws on both sides joins once; got: ${both_ws}'
}

// ── #469 zone 2: ElementMeta `# …` line comments are hash-inert AND kept ────

fn test_hash_is_comment_insensitive_elementmeta_line_comment() {
	bare := '[config\n [child v]\n]'
	with_line := '[config\n # c\n [child v]\n]'
	h0 := cx.cx_text_hash(bare) or { panic(err) }
	assert (cx.cx_text_hash(with_line) or { panic(err) }) == h0, 'ElementMeta line comment must not move the hash'
}

fn test_cx_text_fmt_keeps_elementmeta_line_comment() {
	src := '[config\n # c\n [child v]\n]'
	out := cx.cx_text_fmt(src) or { panic(err) }
	assert out.contains('# c'), 'lossless fmt must keep the ElementMeta line comment (#469); got: ${out}'
	twice := cx.cx_text_fmt(out) or { panic(err) }
	assert twice == out, 'fmt must be idempotent on the retained line comment; got: ${twice}'
}

// ── #469 zone 3: the pooled table emitter re-emits retained head comments ───

fn test_cx_text_fmt_keeps_comment_before_table_head() {
	src := '[users [; c ] [table[name age]]\n alice 30\n bob 25\n]'
	out := cx.cx_text_fmt(src) or { panic(err) }
	assert out.contains('[; c ]'), 'table emit must keep the retained head comment (#469); got: ${out}'
	assert out.contains('[table[name age]]'), 'pooled table head must survive; got: ${out}'
	assert out.contains('alice 30'), 'rows must survive; got: ${out}'
	twice := cx.cx_text_fmt(out) or { panic(err) }
	assert twice == out, 'fmt must be idempotent on the comment-bearing table; got: ${twice}'
	// strict canonical still strips it — hash is comment-insensitive
	bare := '[users [table[name age]]\n alice 30\n bob 25\n]'
	h0 := cx.cx_text_hash(bare) or { panic(err) }
	assert (cx.cx_text_hash(src) or { panic(err) }) == h0, 'table head comment must not move the hash'
}

fn test_cx_text_fmt_keeps_line_comment_before_table_head() {
	src := '[users # c\n [table[name age]]\n alice 30\n]'
	out := cx.cx_text_fmt(src) or { panic(err) }
	assert out.contains('# c'), 'table emit must keep the retained line comment (#469); got: ${out}'
	twice := cx.cx_text_fmt(out) or { panic(err) }
	assert twice == out, 'fmt must be idempotent; got: ${twice}'
}
