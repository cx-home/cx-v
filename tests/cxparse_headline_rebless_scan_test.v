module main

import cx
import os

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  HEADLINE RE-BLESS SCOPING SCAN (A+B+C+D) — NOT a gate                      ║
// ╚══════════════════════════════════════════════════════════════════════════╝
// Scopes the @CHOICE-1 headline re-bless BEFORE landing (user ruling 3a). For
// every conformance `in_cx` it runs the CURRENT cx.parse and classifies which
// bucket would re-shape the tree, so the affected-fixture list can be signed off
// in advance. The test never fails — it writes _gate_evidence/
// cxparse_headline_rebless_scope.md. Buckets:
//   A-WS    auto whitespace-array  ([ports 80 443] → cx:type="int[]"; contract: mixed children, no array)
//   B-COMMA auto comma-array       ([ports 80, 443] → cx:type="int[]"; contract: <cx:array>)
//   C-INFER inferred ::[]          ([xs::[] 1 2.0] → promotes to float[]; contract: keep [] heterogeneous)
//   D-TOP   bare scalar/atom doc   (`42` / `:ok` → cx:string; contract: cx:int / cx:atom)
// Explicit `::T[]` (T nonempty) is REPORTED separately as UNCHANGED (the contract
// keeps those — M-TYPED-ARRAY-1 already passes).

fn conformance_dir2() string {
	return os.real_path(os.join_path(os.dir(@FILE), '..', '..', 'conformance'))
}

// has_top_level_comma reports a comma at bracket-depth 0 outside quotes in the
// element BODY (everything after the first WS run following the head name). Used
// only to split auto-arrays into WS- vs comma-shaped for the scope report.
fn has_top_level_comma(src string) bool {
	mut depth := 0
	mut in_sq := false
	mut in_dq := false
	for c in src {
		if in_sq {
			if c == `'` { in_sq = false }
			continue
		}
		if in_dq {
			if c == `"` { in_dq = false }
			continue
		}
		match c {
			`'` { in_sq = true }
			`"` { in_dq = true }
			`[`, `{`, `(` { depth++ }
			`]`, `}`, `)` { depth-- }
			`,` { if depth == 1 { return true } }
			else {}
		}
	}
	return false
}

struct ScopeRow {
	suite    string
	name     string
	bucket   string
	src      string
	dt       string
	sections string
}

// looks_typed reports whether a body token would autotype to a NON-string scalar
// (int/float/bool/atom/null/date) — the signal that a merged-text body would
// re-shape into typed children under @CHOICE-1. Cheap surface check (not the full
// classifier); used only for scope estimation of the MIXED bucket.
fn looks_typed(tok string) bool {
	if tok.len == 0 {
		return false
	}
	if tok == 'true' || tok == 'false' || tok == 'null' {
		return true
	}
	if tok[0] == `:` && tok.len > 1 {
		return true // atom
	}
	c0 := tok[0]
	if (c0 >= `0` && c0 <= `9`) || ((c0 == `-` || c0 == `+`) && tok.len > 1) {
		// numeric-ish (int/float/date all start with a digit or sign)
		mut seen_digit := false
		for ch in tok {
			if ch >= `0` && ch <= `9` {
				seen_digit = true
			} else if ch in [`.`, `-`, `+`, `e`, `E`, `_`, `:`, `T`, `Z`, `x`, `X`] {
				continue
			} else if (ch >= `a` && ch <= `f`) || (ch >= `A` && ch <= `F`) {
				continue // hex
			} else {
				return false // a bareword like `a-b` or `404-error`
			}
		}
		return seen_digit
	}
	return false
}

// mixed_text_reshapes reports whether any TextNode child carries ≥2 WS tokens of
// which ≥1 looks_typed — i.e. the contract would split it into typed items where
// the current parser merged prose+scalars into one text node (@CHOICE-1 bucket A).
fn mixed_text_reshapes(e cx.Element) bool {
	mut typed_items := 0
	mut text_typed := false
	for it in e.items {
		if it is cx.TextNode {
			toks := it.value.split_any(' \t\r\n').filter(it.len > 0)
			if toks.len >= 2 {
				mut n := 0
				for t in toks {
					if looks_typed(t) {
						n++
					}
				}
				if n >= 1 {
					text_typed = true
				}
			}
		}
		if it is cx.ScalarNode {
			typed_items++
		}
	}
	// also: a body that is ≥2 items mixing a scalar with text/child (already split)
	return text_typed || (typed_items >= 1 && e.items.len >= 2)
}

fn classify_in_cx(src string) (string, string) {
	// returns (bucket, data_type-or-note); '' bucket = no re-shape
	doc := cx.parse(src) or { return '', 'REJECT' }
	roots := doc.elements
	if roots.len == 0 {
		return '', 'empty'
	}
	// D-TOP: a single bare scalar/atom/number document (no element wrapper).
	if roots.len == 1 {
		r0 := roots[0]
		if r0 is cx.ScalarNode {
			if r0.data_type == .string_type {
				return 'D-TOP', 'top-string (would retype int/atom/…)'
			}
		}
		if r0 is cx.TextNode {
			return 'D-TOP', 'top-text (would retype)'
		}
	}
	if roots.len != 1 {
		return '', 'multi'
	}
	el := roots[0]
	if el !is cx.Element {
		return '', 'non-element'
	}
	e := el as cx.Element
	dt := e.data_type() or { '' }
	explicit_ann := src.contains('::')
	if explicit_ann && src.contains('::[]') {
		return 'C-INFER', dt
	}
	if dt.ends_with('[]') {
		if explicit_ann {
			return 'UNCHANGED-EXPLICIT', dt // ::T[] — contract keeps it
		}
		if has_top_level_comma(src) {
			return 'B-COMMA', dt
		}
		return 'A-WS', dt
	}
	// A-MIXED: merged prose+scalar body the contract would split into typed items.
	if mixed_text_reshapes(e) {
		return 'A-MIXED', dt
	}
	return '', dt
}

fn test_headline_rebless_scope() {
	files := os.ls(conformance_dir2()) or {
		assert false, 'cannot list conformance dir'
		return
	}
	mut rows := []ScopeRow{}
	mut counts := map[string]int{}
	mut total := 0
	for f in files {
		if !f.ends_with('.cxd') {
			continue
		}
		path := os.join_path(conformance_dir2(), f)
		for c in cx.load_fixtures(path) {
			src := c.sections['in_cx'].trim_space()
			if src == '' || src == '[ignored]' || src == '[empty]' {
				continue
			}
			total++
			bucket, dt := classify_in_cx(src)
			if bucket == '' {
				continue
			}
			// which expected sections this fixture carries (what re-blesses)
			mut secs := []string{}
			for k, _ in c.sections {
				if k.starts_with('out_') {
					secs << k
				}
			}
			secs.sort()
			counts[bucket]++
			rows << ScopeRow{
				suite:    f
				name:     c.name
				bucket:   bucket
				src:      src.replace('\n', '\\n')
				dt:       dt
				sections: secs.join(',')
			}
		}
	}

	mut r := []string{}
	r << '# cxparse headline (A+B+C+D) re-bless SCOPE'
	r << ''
	r << 'Generated by cxparse_headline_rebless_scan_test.v over conformance/*.cxd.'
	r << 'Classifies each `in_cx` by the bucket that would re-shape its parse tree'
	r << 'under the @CHOICE-1 headline. UNCHANGED-EXPLICIT = `::T[]` annotated arrays'
	r << 'the contract KEEPS (listed for contrast, NOT a re-bless).'
	r << ''
	r << '## Counts (over ${total} in-cx inputs)'
	r << ''
	mut keys := []string{}
	for k, _ in counts {
		keys << k
	}
	keys.sort()
	for k in keys {
		r << '- **${k}**: ${counts[k]}'
	}
	r << ''
	r << '## Affected fixtures (re-bless candidates; UNCHANGED-EXPLICIT excluded)'
	r << ''
	for want in ['A-WS', 'A-MIXED', 'B-COMMA', 'C-INFER', 'D-TOP'] {
		r << '### ${want}'
		r << ''
		for row in rows {
			if row.bucket == want {
				r << '- [${row.suite}] ${row.name} — `${row.src}` → dt=`${row.dt}` (out: ${row.sections})'
			}
		}
		r << ''
	}
	r << '## UNCHANGED-EXPLICIT (`::T[]` — contract keeps; for contrast only)'
	r << ''
	for row in rows {
		if row.bucket == 'UNCHANGED-EXPLICIT' {
			r << '- [${row.suite}] ${row.name} — `${row.src}` → dt=`${row.dt}`'
		}
	}

	out := os.join_path(conformance_dir2(), '..', '_gate_evidence', 'cxparse_headline_rebless_scope.md')
	os.write_file(out, r.join('\n')) or { panic('cannot write scope report: ${err}') }
	assert true
}
