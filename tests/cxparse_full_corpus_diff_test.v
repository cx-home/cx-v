module main

import code
import cx
import os

// cxparse_full_corpus_diff_test — Phase 0 of the cxparse unification
// (spec/02-inprogress/cxparse_unification_PLAN.md).
//
// The comprehensive DIFFERENTIAL ORACLE: it diffs the two CURRENT parsers
// (cx.parse data path vs code.parse program path) over EVERY `in-cx` data
// input in the whole conformance corpus — not the ~50 hand-picked items in
// parser_parity_test.v. This is the safety net Phase 1+ diffs the unified
// parser against: once the agreement set is locked here, any structural
// drift introduced while merging the parsers fails this gate immediately.
//
// SUBSTRATE (identical to parser_parity_test.v): both sides reduce to a
// `cx.Node` rendered through the SAME canonical renderer, so a mismatch is a
// genuine structural divergence, not an emitter artifact.
//   cx side:   cx.parse(src).elements[0]               (data parser)
//   code side: code.program_parse_to_typed_node(src)   (program parser → eval;
//              for pure DATA, eval is identity, so this reflects code.parse's
//              structure)
//
// BUCKETS (every `in-cx` input lands in exactly one):
//   agree       both accept a single element and render identically  → the locked baseline
//   diverge     both accept a single element but render differently   → must match KNOWN list or FAIL
//   cx_only     cx parses 1 element; code rejects                     → data-only surface (XML/DTD/md/table/…)
//   code_only   code accepts; cx rejects                              → (expected ~0)
//   multi       cx yields ≠1 top-level element (multi-doc/prolog)      → not a single-element comparison
//   both_reject neither yields a comparable single element            → header/sentinel rows
//
// Phase 0 = MEASURE then LOCK. The first run reports the catalog; the
// `known_diverge` list below is then frozen to it, so the gate fails on any
// NEW divergence (a real Phase-1 regression) while tolerating the
// already-understood ones (SEQ-NEST + operator-head eval-confound).

fn conformance_dir() string {
	return os.real_path(os.join_path(os.dir(@FILE), '..', '..', 'conformance'))
}

// diff_cx_canon renders src via the cx DATA parser, or a sentinel.
fn diff_cx_canon(src string) string {
	doc := cx.parse(src) or { return 'REJECT' }
	if doc.elements.len != 1 {
		return 'MULTI'
	}
	return code.render_canonical(doc.elements[0])
}

// diff_code_canon renders src via the PROGRAM parser (+eval), or REJECT.
fn diff_code_canon(src string) string {
	n := code.program_parse_to_typed_node(src) or { return 'REJECT' }
	return code.render_canonical(n)
}

struct DiffRow {
	suite string
	name  string
	src   string
	cx    string
	code  string
}

fn test_full_corpus_data_differential() {
	files := os.ls(conformance_dir()) or {
		assert false, 'cannot list conformance dir'
		return
	}
	mut total := 0
	mut agree := 0
	mut cx_only := 0
	mut code_only := 0
	mut both_reject := 0
	mut multi := 0
	mut diverge := []DiffRow{}
	for f in files {
		if !f.ends_with('.cxd') {
			continue
		}
		path := os.join_path(conformance_dir(), f)
		for c in cx.load_fixtures(path) {
			src := c.sections['in_cx'].trim_space()
			if src == '' || src == '[ignored]' || src == '[empty]' {
				continue
			}
			total++
			a := diff_cx_canon(src)
			b := diff_code_canon(src)
			if a == 'MULTI' {
				multi++
				continue
			}
			if a == 'REJECT' && b == 'REJECT' {
				both_reject++
				continue
			}
			if a == 'REJECT' {
				code_only++
				continue
			}
			if b == 'REJECT' {
				cx_only++
				continue
			}
			if a == b {
				agree++
			} else {
				diverge << DiffRow{
					suite: f
					name:  c.name
					src:   src
					cx:    a
					code:  b
				}
			}
		}
	}
	mut r := []string{}
	r << '[cxparse-diff] corpus data differential over ${total} in-cx inputs:'
	r << '  total=${total} agree=${agree} diverge=${diverge.len} cx_only=${cx_only} code_only=${code_only} multi=${multi} both_reject=${both_reject}'
	for d in diverge {
		r << '  [${d.suite}] ${d.name}'
		r << '    src : ${d.src}'
		r << '    cx  : ${d.cx}'
		r << '    code: ${d.code}'
	}
	report := r.join('\n')

	// BASELINE LOCK (Phase 0, 2026-06-04). Frozen to the first full-corpus run.
	// This is the merge oracle: a Phase-1+ change that makes a previously-
	// agreeing input diverge drops `agree` / raises `diverge` and fails here.
	// A change that CONVERGES a known divergence also fails ("deliberately
	// update the baseline") — same philosophy as the parser_parity gate.
	// The divergences are CATALOGUED + classified in
	// _gate_evidence/cxparse_phase0_differential.md (data-only surface,
	// eval-confound, render-convention, and the genuine Class-D latents).
	// Class-D RESOLUTION (2026-06-04): D1/D2/D4 (code bugs) + D3 (cx bug) were
	// fixed pre-merge, moving the baseline 37→32 diverge (383→388 agree). D5
	// (`[root 42 [x]]` mixed-content §9-scope) is DEFERRED to Phase 3's "§9 to
	// one layer" step — it converges there by construction; ext-011 + pred-006
	// remain the two known D5 rows. See the catalog's Class-D RESOLUTION table.
	// Phase 4.2 NUMBER-FORK CONVERGENCE (2026-06-04): the program lexer now
	// implements lexicon [L20] (hex `0x…`, `_` separators) like the data parser,
	// so two previously program-rejected hex inputs — `[flags 0xFF]`
	// (extended.cxd) and `[mask 0xCAFE]` (lint.cxd) — now parse and AGREE. That
	// moves cx_only 108→106 and agree 388→390 (a deliberate convergence bump;
	// diverge unchanged at 32).
	// @CHOICE-1 §9-ONE-LAYER, SLICE A (2026-06-05): the data parser's whitespace
	// auto-array (try_auto_array → a single `T[]` element) is RETIRED — a typed
	// whitespace scalar run is now N discrete typed CHILDREN (body_is_typed_list),
	// AND the typed-list classifier now handles mixed content (child elements
	// interleaved). That CONVERGES the two known D5 mixed-content rows (ext-011 +
	// pred-006, the `[root 42 [x]]` §9-scope cases the comment above predicted
	// "converges by construction" here): cx no longer merges `42 4.2`-style runs
	// into one quoted Text, matching the program parser. diverge 32→30, agree
	// 390→392 (deliberate convergence; no new rejects — cx_only/code_only/both
	// unchanged).
	// D-B MARKDOWN REMOVAL (2026-06-05): markdown is no longer CX syntax (the
	// parser sigil arms `~ ^ \` > [#heading [--- [* italic`, the CX↔MD layer,
	// and conformance/md.cxd were all removed). Deleting md.cxd drops its 27
	// in_cx rows from the corpus: total 556→529, agree 392→379 (−13),
	// diverge 30→27 (−3), cx_only 106→95 (−11). code_only/multi/both_reject
	// unchanged — a pure corpus-shrink, no new divergence among surviving rows.
	// DATA↔PROGRAM SEAM CLOSURE (2026-06-05): the program reader now admits the
	// pure-data constructs it previously forked on / rejected — raw text `[#…#]`,
	// entity / char refs `&…;`, and declarations `[!…]` / `[!DOCTYPE …]` — via a
	// `node_lit` literal that delegates to the data reader (cx.parse_data_node).
	// 4 corpus rows that were cx_only (data accepted, program rejected) now
	// AGREE: agree 379→383 (+4), cx_only 95→91 (−4). diverge/code_only/multi/
	// both_reject unchanged — a strict convergence improvement, no regressions.
	// D-B MARKDOWN CONVERSION RESTORED (2026-06-06): the CX↔MD conversion layer
	// (parser_md.v / emitter_md.v / Format.md / CLI --md) and conformance/md.cxd
	// were restored — WITHOUT re-adding the markdown sigil arms to the CX parser
	// (no `~ ^ \` > [#heading` surface). md.cxd was pruned to its CONVERSION cases
	// (HTML-style element names + md→cx); its 10 sigil-input cases were dropped
	// since that surface stays removed. The surviving 17 in_cx rows rejoin the
	// corpus: total 529→546 (+17); agree 383→396 (+13), diverge 27→28 (+1),
	// cx_only 91→94 (+3), code_only/multi/both_reject unchanged. Deterministic.
	// TRIPLE-QUOTE BIJECTION FIXTURES (2026-06-08): extended.cxd cases 048/049
	// (triple-quote `\"` round-trip + canonical fixed point) add 2 in_cx rows;
	// both parsers AGREE on each. total 546→548 (+2), agree 396→398 (+2); all
	// other categories unchanged.
	// PROGRAM-MODE `:table` BLOCK PARSE (2026-06-09): the program parser gained
	// `[table[…]]` recognition (program_parser.v at_table_block_body /
	// reparse_table_element_as_node) — it now delegates a table-bearing element
	// to the data reader via the DATA↔PROGRAM `node_lit` seam, so a `:table`
	// input that the program parser previously REJECTED (and the data parser
	// accepted → counted cx_only/diverge) now parses identically in both engines.
	// Pure convergence, no regressions: agree 398→441 (+43), diverge 28→10 (−18),
	// cx_only 94→69 (−25); code_only/multi/both_reject/total unchanged. The
	// remaining 10 divergences are the known mixed-content / comment / single-
	// colon-attr forks (no tables).
	baseline := {
		'total':       548
		'agree':       441
		'diverge':     10
		'cx_only':     69
		'code_only':   1
		'multi':       25
		'both_reject': 2
	}
	got := {
		'total':       total
		'agree':       agree
		'diverge':     diverge.len
		'cx_only':     cx_only
		'code_only':   code_only
		'multi':       multi
		'both_reject': both_reject
	}
	assert got == baseline, 'cxparse differential baseline moved (review + update deliberately):\n' +
		'  baseline=${baseline}\n  got     =${got}\n' + report
}
