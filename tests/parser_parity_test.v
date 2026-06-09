module main

import code
import cx

// parser_parity_test — the parser-parity gate (consolidation step 1+2).
//
// HISTORY: this gate was built to de-risk consolidation step 2 (replace the
// dispatcher bridge's source round-trip — code.parse → program_node_to_source
// → cx.parse_match / cx.parse_modify — with AST→AST lowering). During the
// swap it asserted `lowering == cx.parse_*(emit)` (hash-identical). That swap
// is DONE (commit 3588a577): production lowers directly via
// code.lower_{match,modify}_source_to_node and no longer calls cx.parse_* at
// all. The D014 cutover then moved the emitter to clause form, so the old
// `cx.parse_*(emit)` round-trip is intentionally dead — it is NOT a valid
// oracle any more.
//
// POST-SWAP ROLE (this file): a surface-independent regression lock on the
// lowering, in two layers:
//   1. DETERMINISM — lower(src) is stable across calls (structural).
//   2. BEHAVIORAL DISPATCH PARITY — the production dispatcher (eval_code),
//      which now routes [?match]/[?modify] through the lowering, produces the
//      expected output for a representative corpus. This is the meaningful,
//      surface-independent contract; it survives emitter/grammar changes.
//
// Spec: grammar.ebnf [136]-[148e]. See
// _gate_evidence/PARSER_ARCHITECTURE_ASSESSMENT.md (steps 1-2 + addendum).

// match_corpus — representative [?match] shapes.
const match_corpus = [
	'[?match 200 [case 200 :ok] [case 404 :not-found] [else :err]]',
	'[?match "ok" [case "ok" :pass] [else :fail]]',
	'[?match 500 [case 200 :ok] [case 404 :not-found]]',
	'[?match 200 [case 200 :http-ok] [case _ :other]]',
	'[?match \$x [when true :big] [else :small]]',
]

// modify_corpus — representative [?modify] shapes.
const modify_corpus = [
	'[?modify \$doc //user [set-attr status "active"]]',
	'[?modify \$doc //user[@active=false] [delete]]',
	'[?modify \$doc //user/@name [set "Alicia"]]',
	'[?modify \$doc //widget [rename component]]',
	'[?modify \$doc //section [append [para "Hi"]]]',
	'[?modify \$doc //user/email [set "redacted"]]',
]

// ── Layer 1: lowering determinism (structural) ────────────────────────────

fn test_match_lowering_deterministic() {
	mut pass := 0
	mut fails := []string{}
	for src in match_corpus {
		a := code.lower_match_source_to_node(src) or {
			fails << '${src}\n    lowering returned none'
			continue
		}
		b := code.lower_match_source_to_node(src) or {
			fails << '${src}\n    second lowering returned none'
			continue
		}
		if cx.match_node_hash(a) != cx.match_node_hash(b) {
			fails << '${src}\n    non-deterministic lowering'
			continue
		}
		pass++
	}
	println('[parity] match lowering deterministic: ${pass}/${match_corpus.len}')
	assert fails.len == 0, 'match lowering non-deterministic:\n  ' + fails.join('\n  ')
}

fn test_modify_lowering_deterministic() {
	mut pass := 0
	mut fails := []string{}
	for src in modify_corpus {
		a := code.lower_modify_source_to_node(src) or {
			fails << '${src}\n    lowering returned none'
			continue
		}
		b := code.lower_modify_source_to_node(src) or {
			fails << '${src}\n    second lowering returned none'
			continue
		}
		if cx.modify_node_hash(a) != cx.modify_node_hash(b) {
			fails << '${src}\n    non-deterministic lowering'
			continue
		}
		pass++
	}
	println('[parity] modify lowering deterministic: ${pass}/${modify_corpus.len}')
	assert fails.len == 0, 'modify lowering non-deterministic:\n  ' + fails.join('\n  ')
}

// ── Layer 2: behavioral dispatch parity (production path → lowering) ───────

// run_eval evaluates a program against an input doc through the production
// dispatcher (eval_code), which routes [?match]/[?modify] through the
// lowering. Surface-independent: tests behavior, not parse internals.
fn run_eval(in_cx string, program_src string) !string {
	return code.eval_code(in_cx, program_src, 'text')!
}

fn test_match_dispatch_behavioral() {
	cases := {
		'[?match 200 [case 200 :ok] [case 404 :not-found] [else :err]]': ':ok'
		'[?match 404 [case 200 :ok] [case 404 :not-found] [else :err]]': ':not-found'
		'[?match 500 [case 200 :ok] [case 404 :not-found] [else :err]]': ':err'
		'[?match "ok" [case "ok" :pass] [else :fail]]':                   ':pass'
	}
	for program, want in cases {
		got := run_eval('[doc]', program) or {
			assert false, 'eval failed for `${program}`: ${err}'
			return
		}
		assert got == want, 'match dispatch: `${program}` → got `${got}` want `${want}`'
	}
	println('[parity] match dispatch behavioral: ${cases.len}/${cases.len}')
}

fn test_modify_dispatch_behavioral() {
	// [?modify] via the production dispatcher (bridge → lowering).
	in_cx := '[users [user active=true [name Alice]] [user active=false [name Bob]]]'
	// Predicate-focus delete: Bob dropped, Alice kept.
	got := run_eval(in_cx, '[?modify \$doc //user[@active=false] [delete]]') or {
		assert false, 'modify delete eval failed: ${err}'
		return
	}
	assert got.contains('Alice'), 'modify delete: Alice should remain, got ${got}'
	assert !got.contains('Bob'), 'modify delete: Bob should be dropped, got ${got}'

	// set-attr on element focus.
	in2 := '[doc [user [name Alice]]]'
	got2 := run_eval(in2, '[?modify \$doc //user [set-attr status "active"]]') or {
		assert false, 'modify set-attr eval failed: ${err}'
		return
	}
	assert got2.contains('status=active'), 'modify set-attr: expected status=active, got ${got2}'
	println('[parity] modify dispatch behavioral: 2/2')
}

// ── Layer 3: CROSS-PARSER parity (cx.parse vs code.parse) ──────────────────
//
// This is the step-1 gate the assessment §6.1 calls for and the piece the
// prior layers did NOT cover: a DIFFERENTIAL between the two top-level
// parsers over the shared data grammar (element / attribute / scalar /
// nesting). It measures and locks the exact drift class D014 exposed —
// "the same bytes parse to a structurally different tree depending on which
// top-level entry point the caller used" (§3.1).
//
// SUBSTRATE: both sides are reduced to a `cx.Node` and rendered through the
// SAME canonical renderer (`code.render_canonical`), so a mismatch is a
// genuine structural divergence, not an emitter-convention artifact:
//   - cx side:   cx.parse(src).elements[0]                  (data parser)
//   - code side: code.program_parse_to_typed_node(src)      (program parser
//                 → eval; for pure DATA, eval is identity, so this reflects
//                 code.parse's structure)
// Corpus is restricted to the pure-data subset where eval is identity, so
// the comparison isolates PARSE structure. Directives, bindings, and calls
// are out of scope here (eval is not identity for them) — they are covered
// by the behavioral layers above and the full conformance suite.
//
// CONTRACT: the two parsers must agree on EVERY corpus item (0 drift). A new
// divergence — a parser change that makes the two disagree — fails this gate
// immediately, before it can reach a directive sub-surface as a D014-style
// colon-vs-clause defect.

// data_corpus_agree — pure-data shapes where the two top-level parsers MUST
// produce a structurally identical tree. A new divergence here fails the gate
// (a parser change made the two disagree → a D014-class regression).
const data_corpus_agree = [
	// Bare / empty elements.
	'[user]',
	'[user-profile]',
	// Single scalar children, across scalar types.
	'[n 42]',
	'[r 3.14]',
	'[b true]',
	'[b false]',
	'[s "hello world"]',
	'[a :ok]',
	'[name Alice]',
	// Attributes (the colon-vs-clause D014 surface) — clause form `name=val`.
	'[user active=true]',
	'[user name=Alice]',
	'[user count=42]',
	'[user ratio=3.14]',
	'[user label="full name"]',
	'[user role=:admin]',
	// Attributes + children combined.
	'[user active=true [name Alice]]',
	'[user id=7 [name Alice] [age 30]]',
	// Nested elements.
	'[doc [section [para Hi]]]',
	'[users [user [name Alice]] [user [name Bob]]]',
	'[a [b [c [d 1]]]]',
	// Multiple attributes.
	'[box w=10 h=20 fill=red]',
	// Negative + null scalars (single child / attr — no AutoArray).
	'[n -7]',
	'[r -0.5]',
	'[nil null]',
	'[u a=1 b=2 c=3]',
	'[u x=-5]',
	// Hyphenated element head (lexed as one Name by both).
	'[a-b-c 1]',
	// Sequence literals in data position (flat).
	'[pair (1, 2)]',
	'[seq (1, 2, 3)]',
	// Recoverable typed arrays (AUTOARRAY). Render-(a) drops the redundant
	// `::T[]`, so cx.parse's array body renders identically to code.parse's
	// separate-scalar form — the two now AGREE at the render level. (cx's
	// tree is still a typed array and code's is separate scalars; the deeper
	// tree convergence is workstream B and invisible to this render gate.)
	'[items 1 2 3]',
	'[fs 1.0 2.0 3.0]',
	'[bs true false true]',
	'[neg -1 -2 -3]',
	// Temporal scalars (cluster 1 LEXER/DATETIME converged): the program
	// lexer now reads `2024-01-15` / `…T..Z` as ONE token → date/datetime
	// scalar, matching cx.parse. A single temporal child renders quoted
	// through code.render_canonical on both sides; an attribute date value
	// likewise. (The whitespace date ARRAY `[ds …]` stays divergent until
	// cluster 2 AUTOARRAY.)
	'[d 2024-01-15]',
	'[dt 2024-01-15T10:30:00Z]',
	'[u d=2024-01-15]',
	// NAME-RULE (cluster 5): `_`-leading head is a valid Name ([6]/[L10]).
	// This is the one cluster where cx.parse was the bug; now fixed to match
	// code.parse, which was already spec-faithful.
	'[_private 1]',
	'[_ 1]',
	// NAMESPACE (cluster 4): byte-adjacent `prefix:local` is a QName element
	// head ([L11]/[7a]), folded by the program parser instead of read as a
	// `:local` atom child. A space-separated `:rect` is still an atom child.
	'[svg:rect]',
	'[svg:rect x=1]',
	'[prefix:local child]',
	// ATTR-TYPE (cluster 4): a bare attribute value auto-types via [L25a] —
	// `null` → the null scalar, not the string "null".
	'[u nil=null]',
	// TYPE-ANN (cluster 3): the program parser accepts a glued head
	// TypeAnnotation `::T` / `::T[]` / `::[]` ([L50]/[L25d]); decision-(a)
	// drops the redundant annotation from recoverable arrays.
	'[port::u16 8080]',
	'[count::int 5]',
	'[xs::int[] 1 2 3]',
	'[tags::string[] admin user]',
	'[xs::[] 1 2 3]',
	// AUTOARRAY / CONTENT (cluster 2, §9 [L25a-b]): code.parse now applies
	// the body-value rule — a homogeneous non-string whitespace run
	// auto-arrays (int+float promote to float; dates → date[]), and a
	// bareword / bareword+number run is PROSE (one Text run).
	'[ns 1 2.0 3]',
	'[ds 2024-01-15 2024-02-20]',
	'[words alpha beta gamma]',
	'[map x 1]',
	// CONTENT self-delimiting list (§9 [L25b], 3a/[L25b] amendment): a no-comma
	// body containing a QUOTED STRING or ATOM is a heterogeneous list of typed
	// items (quotes/atoms self-delimit). cx.parse now classifies it per-token
	// (was a broken mis-segmented prose run); code.parse already did. Both →
	// `[mixed 1 'two' :three true]`.
	'[mixed 1 "two" :three true]',
	'[sequence "b" "a"]',
]

// data_corpus_divergent — shapes where cx.parse and code.parse currently
// DISAGREE on structure. This is measured drift (the assessment §3.1 class),
// recorded here so it is (1) visible and (2) LOCKED: if either parser's
// rendering of one of these changes, the gate fails — so the divergence can
// only shrink deliberately (by removing an item once the parsers converge),
// never grow or mutate silently. The two renders are the exact current
// `code.render_canonical` outputs.
//
// KNOWN DIVERGENCES — the full enumerated drift surface (step-a map). Each
// case records the EXACT current render from both parsers (or the `REJECT:`
// sentinel when a parser declines). Surfaced to the user as the step-3
// reconciliation list; grouped by root cause in `category`.
//
// SPEC VERDICT per cluster (which parser matched the grammar). Workstream B
// (2026-06-03) converged code.parse to lexicon §9 for clusters 1-5; the
// `correct` side named below was the convergence target. RESOLVED rows are
// now in data_corpus_agree; only the two OUT-OF-SCOPE rows remain divergent.
//
//   LEXER      [L23] `2024-01-15` is ONE date token.        correct: cx  RESOLVED (cl.1)
//   DATETIME   [L24] `…T10:30:00Z` is ONE datetime token.   correct: cx  RESOLVED (cl.1)
//   AUTOARRAY  [L25a-b] homogeneous non-string ⇒ typed array. correct: cx RESOLVED (cl.2)
//   CONTENT    [L25b] bareword/mixed whitespace ⇒ prose;     correct: cx  RESOLVED (cl.2
//              quoted/atom body ⇒ self-delimiting list.                   + [L25b] amend)
//   TYPE-ANN   [L50] glued `::T`/`::T[]`/`::[]` on the head. correct: cx  RESOLVED (cl.3)
//   NAMESPACE  [L11]/[7a] QName `prefix:local` head.         correct: cx  RESOLVED (cl.4)
//   ATTR-TYPE  [L25a]/§10 bare attr values auto-typed.       correct: cx  RESOLVED (cl.4)
//   NAME-RULE  [L10]/[6] `_`-leading is a valid Name.        correct: code RESOLVED (cl.5)
//   SEQ-NEST   [L80] SequenceLiteral flattens nested seqs.   LEGITIMATE LAYER DIFF
//
// All cluster-1..5 divergences plus the §9 CONTENT fork are resolved — both
// parsers agree on those (data_corpus_agree). The CONTENT fork was closed by
// amending §9 [L25b] (a quoted-string/atom no-comma body is a self-delimiting
// list, not verbatim prose) + converging cx.parse to it.
//
// SEQ-NEST remains divergent — and that is CORRECT, not a gap. [L80] sequence-
// flattening is a DATA-layer document convention (CXDM §1.2): `[nested (1, (2,
// 3))]` parsed as data flattens to `(1, 2, 3)`. The PROGRAM layer evaluates a
// sequence as a FIRST-CLASS structured value, where nesting carries meaning —
// multi-axis slices (rank), `[?to-map]` 2-tuples, and geo polygon rings all
// require `((…), (…))` to stay nested. Flattening in code.parse breaks them
// (verified: it regressed 7 code.cxd + 2 geo.cxd fixtures). Unlike §9 [L25b]
// (which lexicon.ebnf binds BOTH layers to), [L80] has no shared-rule clause,
// so the layers legitimately differ. Locked here so neither side drifts.
struct DivergentCase {
	src        string
	category   string
	cx_canon   string // current fn_cx_canon(src)   ('REJECT: …' if declined)
	code_canon string // current fn_code_canon(src) ('REJECT: …' if declined)
}

const data_corpus_divergent = [
	// SEQ-NEST — data flattens ([L80]/CXDM §1.2); program preserves first-class
	// sequence rank. A legitimate layer difference, not drift (see note above).
	DivergentCase{
		src: '[nested (1, (2, 3))]', category: 'SEQ-NEST'
		cx_canon: '[nested (1, 2, 3)]', code_canon: '[nested (1, (2, 3))]'
	},
]

// EVAL-CONFOUND — excluded from the gate corpus. Operator-named data heads
// (e.g. `[and 1 2]` → `true`) are EVALUATED by the program path, so the
// difference is not parser drift. `program_parse_to_typed_node` evals, so
// these are out of scope for the data-parity gate; the full conformance
// suite covers operator semantics.

// fn_cx_canon renders src through the cx-data parser, or 'REJECT: …'.
fn fn_cx_canon(src string) string {
	doc := cx.parse(src) or { return 'REJECT: cx.parse: ${err}' }
	if doc.elements.len != 1 {
		return 'REJECT: cx.parse produced ${doc.elements.len} top-level elements'
	}
	return code.render_canonical(doc.elements[0])
}

// fn_code_canon renders src through the program parser (+eval), or 'REJECT: …'.
fn fn_code_canon(src string) string {
	n := code.program_parse_to_typed_node(src) or { return 'REJECT: parse/eval declined' }
	return code.render_canonical(n)
}

fn test_cross_parser_data_parity() {
	mut pass := 0
	mut fails := []string{}
	for src in data_corpus_agree {
		a := fn_cx_canon(src)
		b := fn_code_canon(src)
		if a != b {
			fails << '${src}\n    cx.parse   → `${a}`\n    code.parse → `${b}`'
			continue
		}
		pass++
	}
	println('[parity] cross-parser data parity (agree): ${pass}/${data_corpus_agree.len}')
	assert fails.len == 0, 'NEW cross-parser drift detected (cx.parse vs code.parse):\n  ' +
		fails.join('\n  ')
}

// test_cross_parser_known_divergence LOCKS the enumerated drift map: each
// parser must still render exactly its recorded value. A failure means a
// parser changed — either it converged (good: move the item to
// data_corpus_agree) or it drifted further (bad). Either way the change must
// be deliberate, not silent. This is the regression lock the step-b
// convergence work will retire items from, one cluster at a time.
fn test_cross_parser_known_divergence() {
	mut fails := []string{}
	for c in data_corpus_divergent {
		a := fn_cx_canon(c.src)
		b := fn_code_canon(c.src)
		if a != c.cx_canon {
			fails << '[${c.category}] ${c.src}\n    cx.parse render changed: was `${c.cx_canon}` now `${a}`'
		}
		if b != c.code_canon {
			fails << '[${c.category}] ${c.src}\n    code.parse render changed: was `${c.code_canon}` now `${b}`'
		}
		if a == b {
			fails << '[${c.category}] ${c.src}\n    parsers CONVERGED (`${a}`) — move to data_corpus_agree'
		}
	}
	println('[parity] cross-parser known divergence locked: ${data_corpus_divergent.len} case(s)')
	assert fails.len == 0, 'known-divergence lock broke (deliberately update the corpus):\n  ' +
		fails.join('\n  ')
}
