module main

import cx
import code
import os
import math

// ── End-to-end fixture-evaluation test ───────────────────────────────────────
//
// Runs EVERY fixture in conformance/code.txt through parse → eval, and
// compares the result against the fixture's declared output. There is no
// whitelist: a fixture that is spec-inconsistent or depends on an
// unimplemented feature / absent module FAILS the gate until fixed.
//
// Comparison is shape-based: the actual result is rendered to a
// canonical text form via render_value, then compared to the
// fixture's out_text / out_multiset / out_err (whitespace-normalised).

fn fixture_path_eval() string {
	return os.real_path(os.join_path(os.dir(@FILE), '..', '..',
		'conformance', 'code.cxd'))
}

struct ParsedFixture {
	id           string
	in_cx        string
	in_code      string
	out_text     string
	out_multiset string  // comma-separated multiset matcher for :par-unordered fixtures
	out_err      string
	gate         string  // per-case gate toggle: enforced|advisory|pending|skip ('' = unset)
	grant        string  // Effort B least-privilege grant: space-separated capability list ('' = host default)
	tol          f64     // relative float tolerance for out_text match (0 = exact)
	level        string  // family label: core|resilience|async|visualization|…
	tags         []string // case tags (e.g. 'strict-mode' enables --strict typing)
}

// CX-native: read code.cxd via cx.load_fixtures (replaces the inline
// '=== test:' scanner + extract_section + strip_format_fences). The
// doc-example template and fence handling are done by the converter; the
// section-body clamp the old extract_section applied is baked into the .cxd.
fn parse_all_fixtures() []ParsedFixture {
	mut out := []ParsedFixture{}
	for c in cx.load_fixtures(fixture_path_eval()) {
		out << parsed_from(c)
	}
	return out
}

fn parsed_from(c cx.FixtureCase) ParsedFixture {
	return ParsedFixture{
		id:           c.name
		in_cx:        clamp_section(c.sections['in_cx'])
		in_code:      clamp_section(c.sections['in_code'])
		out_text:     clamp_section(c.sections['out_text'])
		out_multiset: clamp_section(c.sections['out_multiset'])
		out_err:      clamp_section(c.sections['out_err'])
		gate:         c.gate
		grant:        c.grant
		tol:          c.tol
		level:        c.level
		tags:         c.tags
	}
}

// clamp_section reproduces the former extract_section end-detection, applied
// to the loader's (already section-bounded) byte-exact body. A section's text
// ends at the first of: a bare `---` line or `--- \n` (legacy section-end /
// horizontal-rule marker the converter does NOT split on), or a
// blank-line-then-comment boundary (`\n\n#` inter-test heading mis-captured
// into the last section). This clamp is consumer-specific (eval) and lives
// here, not in the shared loader (conformance_run never clamped).
fn clamp_section(s string) string {
	mut end := s.len
	mut probe := 0
	for probe < s.len {
		next := s.index_after('\n---', probe) or { break }
		if next + 4 < s.len {
			c := s[next + 4]
			if c == ` ` || c == `\n` {
				end = next
				break
			}
		} else {
			// trailing `\n---` (optionally `\n--- `) at end of body
			end = next
			break
		}
		probe = next + 1
	}
	if ci := s.index('\n\n#') {
		if ci < end {
			end = ci
		}
	}
	return s[..end].trim_right(' \t\n')
}

// render_value renders a cx.Node to a compact textual form for
// shape comparison against fixture out_text.
const slot_prefix = '__cx_slot:'

fn render_value(n cx.Node) string {
	match n {
		cx.TextNode {
			return n.value
		}
		cx.ScalarNode {
			v := n.value
			match v {
				string {
					// Atom scalars render with leading `:`.
					if n.data_type == cx.ScalarType.atom_type {
						return ':${v}'
					}
					// Date/datetime-TYPED scalars render bare — the value
					// IS the canonical §2.6 literal and re-parses to the
					// same type. (A string-TYPED value that merely looks
					// like a date must quote — handled by cx_autotypes
					// below.)
					if n.data_type == cx.ScalarType.date_type
					   || n.data_type == cx.ScalarType.datetime_type {
						return v
					}
					// Duration literals are stored as strings tagged
					// via the source-text suffix — render bare when
					// the value looks like NN<suffix>.
					if looks_like_duration(v) {
						return v
					}
					return quote_if_needed(v)
				}
				i64    { return v.str() }
				f64    { return v.str() }
				bool   { return v.str() }
				cx.NullValue { return 'null' }
			}
		}
		cx.Element {
			// Top-level program output (name=''): newline-separated.
			if n.name == '' {
				mut lines := []string{}
				for it in n.items {
					lines << render_value(it)
				}
				return lines.join('\n')
			}
			// Explicit sequence literal: paren-separated form `(a, b, c)`.
			if n.name == '__cx_seq__' {
				mut parts := []string{}
				for it in n.items {
					parts << render_value(it)
				}
				return '(${parts.join(', ')})'
			}
			// Array literal: bracketed form `[a, b, c]`.
			if n.name == '__cx_arr__' {
				mut parts := []string{}
				for it in n.items {
					parts << render_value(it)
				}
				return '[${parts.join(', ')}]'
			}
			// Map literal: `{k: v, k: v}`. The
			// `__cx_map__` marker carries entries as Element items with
			// name=key, items=[value]. Matches eval_map's representation
			// and `:yield-map` accumulation.
			if n.name == '__cx_map__' {
				mut parts := []string{}
				for it in n.items {
					if it is cx.Element {
						val_str := if it.items.len > 0 {
							render_value(it.items[0])
						} else { '' }
						parts << '${it.name}: ${val_str}'
					}
				}
				return '{${parts.join(', ')}}'
			}
			mut s := '[${n.name}'
			for a in n.attrs {
				// CX-native attribute form `name=value` matches fixture
				// out_text shape ([figure id=f1]). Quoted strings use
				// bare form when single-word, quoted otherwise.
				s += ' ${a.name}='
				av := a.value
				match av {
					string {
						if looks_like_duration(av) {
							s += av
						} else {
							s += quote_if_needed(av)
						}
					}
					i64    { s += av.str() }
					f64    { s += av.str() }
					bool   { s += av.str() }
					cx.NullValue { s += 'null' }
				}
			}
			for it in n.items {
				if it is cx.Element && it.name.starts_with(slot_prefix) {
					label := it.name[slot_prefix.len..]
					body := if it.items.len > 0 {
						render_body_value(it.items[0])
					} else { '' }
					s += ' :${label} ${body}'
				} else {
					s += ' ' + render_body_value(it)
				}
			}
			s += ']'
			return s
		}
		cx.SequenceNode { return cx.cx_emit_sequence_inline(n, true) }
		cx.ArrayNode    { return cx.cx_emit_array_inline(n, true) }
		cx.MapNode      { return cx.cx_emit_map_inline(n, true) }
		cx.IteratorNode {
			// materialize the iterator's memo at the
			// host (test renderer) boundary. Force-pull via
			// iterate_pub() so combinator-produced iterators
			// (W3c) materialise correctly, and render
			// each item through `render_value` recursively so nested
			// sequence / array / map markers (from `[?zip]` /
			// `[?enumerate]` / `[?chunks]` / `[?partition]`) emit
			// in their canonical paren / bracket / brace forms.
			items := code.iterate_pub(n)
			mut parts := []string{cap: items.len}
			for it in items {
				parts << render_value(it)
			}
			return '(${parts.join(', ')})'
		}
		else {
			return '<${n}>'
		}
	}
}

// render_body_value renders a child node of an Element body. Mirrors
// the production renderer's `render_body_item` (vcx/code/render.v):
// bare TextNodes in body position render with quote wrappers so the
// fixture-comparison shape matches the `cx eval` output. Without this
// the test harness diverged from production rendering — TextNodes
// (produced by `cx.parse` of `in_cx`) lost their quote shape on the
// way through `[?modify]`-style transforms (task #43, 2026-05-23).
// Quote-style picker mirrors `choose_render_quote` in render.v:
// prefer `"`; fall back to `'` when the value contains `"`; degrade
// to triple-quoted forms when both collide.
fn render_body_value(n cx.Node) string {
	if n is cx.TextNode {
		if n.value.trim_space() == '' {
			return n.value
		}
		return quote_if_needed(n.value)
	}
	// A `name==''` sequence wrapper (the multi-value shape produced by a
	// nested `[?for]` comprehension) is the "top-level program output"
	// shape; at top level it renders newline-joined, but inside a named
	// element's body the newline form is non-round-trippable. In body
	// position it serialises as a paren sequence `(a, b, c)` — the
	// canonical sequence-value form (program-conc-018).
	if n is cx.Element && n.name == '' {
		mut parts := []string{cap: n.items.len}
		for it in n.items {
			parts << render_value(it)
		}
		return '(${parts.join(', ')})'
	}
	return render_value(n)
}

fn choose_test_quote(s string) string {
	// Single-quote preferred per spec/canonical.md §651 (mirrors
	// render.v::choose_render_quote).
	has_double := s.contains('"')
	has_single := s.contains("'")
	if !has_single { return "'${s}'" }
	if !has_double { return '"${s}"' }
	if !s.contains("'''") { return "'''${s}'''" }
	if !s.contains('"""') { return '"""${s}"""' }
	return "'${s}'"
}

fn needs_quotes(s string) bool {
	if s.len == 0 { return true }
	// Leading sigil would re-parse as ref/anchor/merge/id/atom
	// (`@id`, `&a`, `*m`, `#i`, `:t`) — mirrors emitter_cx.v.
	c0 := s[0]
	if c0 == `@` || c0 == `&` || c0 == `*` || c0 == `#` || c0 == `:` {
		return true
	}
	for c in s {
		// BareChar-excluded set per canonical.md §2.3: whitespace,
		// `[`, `]`, `=`, `'`, `"`. (Comma is NOT excluded — the shipped
		// emitter renders comma-bearing scalars bare, e.g. a close-order
		// log `inner,outer`; sequence-item ambiguity is a known
		// round-trip nuance, not a quoting trigger.)
		if c == ` ` || c == `\t` || c == `\n` || c == `[` || c == `]`
		   || c == `=` || c == `'` || c == `"` {
			return true
		}
	}
	return false
}

// looks_like_temporal reports whether a bare string would re-parse as a
// date (`YYYY-MM-DD`) or datetime (`YYYY-MM-DDT…`) literal — the two
// auto-typing temporal forms in canonical.md §2.3 / grammar [23][24].
// UUIDs (8-4-4-4-12) and version strings fail the YYYY-MM- prefix test.
fn looks_like_temporal(s string) bool {
	if s.len < 10 { return false }
	for k in [0, 1, 2, 3, 5, 6, 8, 9] {
		if !(s[k] >= `0` && s[k] <= `9`) { return false }
	}
	if s[4] != `-` || s[7] != `-` { return false }
	if s.len == 10 { return true } // date
	return s[10] == `T` // datetime
}

// cx_autotypes reports whether a bare string would re-parse as a
// non-string scalar (int / float / bool / null / hex) — mirrors
// emitter_cx.v::cx_would_autotype. Such values MUST stay quoted so the
// string kind survives a round-trip (the string "7" is '7', not int 7).
fn cx_autotypes(s string) bool {
	if s.len == 0 { return false }
	if s == 'true' || s == 'false' || s == 'null' { return true }
	if s.starts_with('0x') || s.starts_with('0X') { return true }
	if looks_like_temporal(s) { return true }
	mut i := 0
	if s[0] == `-` {
		if s.len == 1 { return false }
		i = 1
	}
	mut all_digit := true
	for j in i .. s.len {
		c := s[j]
		if !(c >= `0` && c <= `9`) { all_digit = false break }
	}
	if all_digit { return true }
	if s.contains('.') {
		mut seen_dot := false
		mut ok := true
		for j in i .. s.len {
			c := s[j]
			if c == `.` { if seen_dot { ok = false break } seen_dot = true }
			else if !(c >= `0` && c <= `9`) { ok = false break }
		}
		if ok && seen_dot { return true }
	}
	return false
}

// quote_if_needed applies the §2.3 idiomatic rule (bare > single > double):
// bare when BareChar-eligible AND non-auto-typing; quoted otherwise.
fn quote_if_needed(s string) string {
	if needs_quotes(s) || cx_autotypes(s) { return choose_test_quote(s) }
	return s
}

fn looks_like_duration(s string) bool {
	for suf in ['us', 'ms', 's', 'm', 'h'] {
		if s.ends_with(suf) {
			prefix := s[..s.len - suf.len]
			if prefix.len == 0 { continue }
			mut all_digit := true
			for c in prefix {
				if !(c >= `0` && c <= `9`) {
					all_digit = false
					break
				}
			}
			if all_digit { return true }
		}
	}
	return false
}


// quote_only_diff reports whether `got` and `exp` differ ONLY by string-
// quoting (the render_value→render_canonical convention shift): strip every
// `'`/`"` and whitespace-normalise both; equal-but-not-identical means the
// sole difference is quote marks. Used to gate the CX_BLESS re-derivation so a
// genuine structural/value change is never silently adopted.
fn quote_only_diff(got string, exp string) bool {
	if got == exp {
		return false
	}
	g := got.replace("'", '').replace('"', '').fields().join(' ')
	e := exp.replace("'", '').replace('"', '').fields().join(' ')
	return g == e
}

// bless_emit appends a re-derived expected-output record for the offline
// rewriter (scripts/apply_blesses.py). Marker-delimited to survive multi-line
// values without JSON escaping.
fn bless_emit(file string, id string, new_text string) {
	mut fh := os.open_append('/tmp/cx_blesses.txt') or { return }
	fh.write_string('<<<BLESS file=${file} id=${id}>>>\n${new_text}\n<<<ENDBLESS>>>\n') or {}
	fh.close()
}

fn test_all_code_fixtures_evaluate() {
	bless := os.getenv('CX_BLESS') == '1'
	// Runs EVERY fixture in conformance/code.txt end-to-end (parse -> eval
	// -> render) against the fixture's OWN declared output (out_err /
	// out_multiset / out_text). NO whitelist and NO test-side overrides:
	// a new fixture is covered the moment it lands, and any fixture that
	// is spec-inconsistent or depends on an unimplemented feature / absent
	// module FAILS this gate until it is made spec-consistent. The
	// fixture's declared output is the spec-expected output.
	all := parse_all_fixtures()
	mut ran := 0
	mut failures := []string{}
	mut adv_ids := map[string]bool{}
	mut pending := []string{}
	for f in all {
		if f.in_code.trim_space() == '' { continue } // section/header rows carry no program
		// `level=visualization` fixtures are RENDER-spec, not eval: their
		// out-text is the structure recovered by rendering to a diagram and
		// reverse-parsing it (§11.6 gate 9), not an evaluation result. They are
		// validated by code_diagram_roundtrip_test.v (mermaid/svg/png round-trip).
		// Evaluating them here is the wrong harness — skip.
		if f.level == 'visualization' { continue }
		// Per-case `gate=pending`: a fixture explicitly deferred with a
		// documented reason (e.g. an unbuilt tier-3 surface, or a test of
		// an internal-only invariant unreachable from conformant user
		// code). Tracked, not silently whitelisted — the case carries its
		// reason inline. Excluded from the enforced assertion until the
		// gate is flipped back to enforced.
		if f.gate == 'pending' {
			pending << f.id
			continue
		}
		ran++
		// Per-case `gate=advisory` (the TDD expected-red state, SAP migration):
		// the fixture RUNS and a failure is REPORTED but does NOT block the
		// gate — flipped to enforced when its impl lands. Partitioned at the
		// end of the loop by this id->advisory map (mirrors the stdlib runner).
		adv_ids[f.id] = f.gate == 'advisory'
		mut env := code.new_env()
		// A `strict-mode`-tagged fixture runs under --strict type
		// validation (§12.7: CXER0206/0207). Default fixtures erase
		// `::T` / `[returns T]` annotations.
		if 'strict-mode' in f.tags {
			env.state.strict = true
		}
		if f.in_cx != '' && f.in_cx != '[ignored]' && f.in_cx != '[empty]' {
			if doc := cx.parse(f.in_cx) {
				for i in 0 .. doc.elements.len {
					n := doc.elements[i]
					if n is cx.Element {
						env.bindings['doc'] = n
						env.bindings['input'] = n
						break
					}
				}
			}
		}
		// Capability-set injection (security.md §3): code.cxd is core
		// language (no effect points), so grant in full; a CXER0271-
		// expecting case (none today) would run empty.
		if f.out_err.contains('CXER0271') {
			code.caps_set_empty()
		} else {
			code.caps_set_all()
		}
		prog := cx.parse_program(f.in_code) or {
			if f.out_err != '' { continue } // legitimately expects a parse-time error
			failures << '${f.id}: parse: ${err}'
			continue
		}
		result := code.eval(prog.body, mut env) or {
			if f.out_err != '' { continue } // legitimately expects an eval-time error
			failures << '${f.id}: eval: ${err}'
			continue
		}
		// Serialization boundary: a function value reaching the program
		// result is not data-serialisable — CXER0291 (§8.6), mirroring
		// code.render()'s guard.
		if code.is_fn_value(result) {
			if f.out_err != '' {
				if !f.out_err.contains('CXER0291') {
					failures << '${f.id}: expected ${f.out_err}, got function value (CXER0291)'
				}
			} else {
				failures << '${f.id}: function value not serialisable (CXER0291), expected ${f.out_text.trim_space()}'
			}
			continue
		}
		rendered := code.render_canonical(result).trim_space()
		if f.out_err != '' {
			if !rendered.contains(f.out_err) {
				failures << '${f.id}: expected ${f.out_err}, got ${rendered}'
			}
		} else if f.out_multiset != '' {
			if !same_multiset(rendered, f.out_multiset.trim_space()) {
				failures << '${f.id}: multiset mismatch\n  got:      ${rendered}\n  expected: ${f.out_multiset.trim_space()} (as multiset)'
			}
		} else {
			exp := f.out_text.trim_space()
			if !same_shape(rendered, exp) {
				if bless && quote_only_diff(rendered, exp) {
					bless_emit('code.cxd', f.id, rendered)
				} else {
					failures << '${f.id}: shape mismatch\n  got:      ${rendered}\n  expected: ${exp}'
				}
			}
		}
	}
	// Partition failures by per-case gate: `advisory` cases (the SAP migration's
	// TDD expected-red frontier) are reported but NOT blocking; everything else
	// is enforced. Mirrors the stdlib runner's adv_ids partition.
	mut enforced := []string{}
	mut advisory := []string{}
	for fl in failures {
		if adv_ids[fl.all_before(': ')] {
			advisory << fl
		} else {
			enforced << fl
		}
	}
	if advisory.len > 0 {
		eprintln('${advisory.len} advisory code.cxd fixture failure(s) of ${ran} — spec-first frontier (unimplemented), reported not blocking:')
		for fl in advisory {
			eprintln('  ${fl}')
		}
	}
	if enforced.len > 0 {
		eprintln('${enforced.len} ENFORCED code.cxd fixture failure(s) of ${ran} run:')
		for fl in enforced {
			eprintln('  ${fl}')
		}
	}
	if pending.len > 0 {
		eprintln('${pending.len} fixture(s) gate=pending (tracked, not enforced): ${pending.join(', ')}')
	}
	assert ran > 0, 'no fixtures ran'
	if !bless {
		assert enforced.len == 0
	}
}

// parse_fixtures_in parses a fixtures file at an arbitrary path (same
// format as conformance/code.txt). Used by the per-module stdlib
// conformance auto-runner.
fn parse_fixtures_in(path string) []ParsedFixture {
	if !os.exists(path) {
		return []
	}
	mut out := []ParsedFixture{}
	for c in cx.load_fixtures(path) {
		out << parsed_from(c)
	}
	return out
}

// test_stdlib_module_fixtures auto-discovers every conformance/stdlib/*.txt
// file and runs ALL its fixtures end-to-end (no whitelist). Each
// cx-stdlib module owns one such file (its spec §6 conformance list),
// named for the module (e.g. conformance/stdlib/bytes.txt); the
// per-module isolation lets module implementations land in parallel
// without touching a shared whitelist. Runs clean (ran == 0) before the
// stdlib/ directory or any module file exists, so it is safe to land
// ahead of the modules.
// load_gate_policy reads conformance/gates.cxd and returns a module->gate map
// for the given suite. Toggle: 'enforced' failures block the gate; 'advisory'
// failures are reported but do NOT block (spec-first frontier / unimplemented).
// An absent module yields '' which the caller treats as enforced
// (deny-by-default, mirroring the capability grant model).
fn load_gate_policy(suite string) map[string]string {
	mut m := map[string]string{}
	path := os.real_path(os.join_path(os.dir(@FILE), '..', '..', 'conformance', 'gates.cxd'))
	src := os.read_file(path) or { return m }
	doc := cx.parse(src) or { return m }
	for node in doc.elements {
		if node is cx.Element {
			if node.name == 'gate-policy' {
				for s in node.items {
					if s is cx.Element {
						if s.name == 'suite' {
							mut sname := ''
							for a in s.attrs {
								if a.name == 'name' {
									sname = cx.scalar_value_str_public(a.value)
								}
							}
							if sname != suite {
								continue
							}
							for md in s.items {
								if md is cx.Element {
									if md.name == 'module' {
										mut mn := ''
										mut mg := ''
										for a in md.attrs {
											if a.name == 'name' {
												mn = cx.scalar_value_str_public(a.value)
											}
											if a.name == 'gate' {
												mg = cx.scalar_value_str_public(a.value)
											}
										}
										if mn != '' {
											m[mn] = mg
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return m
}

fn test_stdlib_module_fixtures() {
	bless := os.getenv('CX_BLESS') == '1'
	dir := os.join_path(os.dir(fixture_path_eval()), 'stdlib')
	entries := os.ls(dir) or { return }
	mut files := []string{}
	for e in entries {
		if e.ends_with('.cxd') {
			files << e
		}
	}
	files.sort()
	mut ran := 0
	mut failures := []string{}
	module_gate := load_gate_policy('stdlib')
	mut adv_ids := map[string]bool{}
	for fname in files {
		fixtures := parse_fixtures_in(os.join_path(dir, fname))
		for f in fixtures {
			// effective gate: per-case overrides module policy overrides enforced.
			eff_gate := if f.gate != '' { f.gate } else { module_gate[fname.all_before('.cxd')] }
			if eff_gate == 'skip' || eff_gate == 'pending' {
				continue // excluded from the gate (not run)
			}
			ran++
			adv_ids['${fname}/${f.id}'] = eff_gate == 'advisory'
			mut env := code.new_env()
			if f.in_cx != '' && f.in_cx != '[empty]' {
				if doc := cx.parse(f.in_cx) {
					for i in 0 .. doc.elements.len {
						n := doc.elements[i]
						if n is cx.Element {
							env.bindings['doc'] = n
							env.bindings['input'] = n
							break
						}
					}
				}
			}
			// Capability-set injection (security.md §3, Effort A/B). The
			// conformance runner is the host here: deny-lane cases (those
			// expecting CXER0271) run under the EMPTY set so the effect
			// point denies; every other (behavior) case runs under a full
			// grant so real effects proceed. No fixture edits — the host
			// chooses the set, exactly as a CLI `--allow-*` / embedding would.
			if f.grant != '' {
				// Effort B: explicit per-fixture least-privilege grant.
				code.caps_set_list(f.grant.split_any(' \t,').filter(it != ''))
			} else if f.out_err.contains('CXER0271') {
				code.caps_set_empty()
			} else {
				code.caps_set_all()
			}
			prog := cx.parse_program(f.in_code) or {
				if f.out_err != '' {
					continue
				}
				failures << '${fname}/${f.id}: parse: ${err}'
				continue
			}
			result := code.eval(prog.body, mut env) or {
				if f.out_err != '' {
					continue
				}
				failures << '${fname}/${f.id}: eval: ${err}'
				continue
			}
			if f.out_err != '' {
				// Expected an err: accept a V-error (handled above) or an
				// err-value whose render carries the expected CXER code.
				if !code.render_canonical(result).contains(f.out_err) {
					failures << '${fname}/${f.id}: expected ${f.out_err}, got ${code.render_canonical(result)}'
				}
				continue
			}
			rendered := code.render_canonical(result).trim_space()
			if f.out_multiset != '' {
				expected := f.out_multiset.trim_space()
				if !same_multiset(rendered, expected) {
					failures << '${fname}/${f.id}: multiset mismatch\n  got:      ${rendered}\n  expected: ${expected}'
				}
			} else {
				expected := f.out_text.trim_space()
				if f.tol > 0 {
					// Tolerant float match: PASS when |actual-expected| <= tol*|expected|.
					actual_f := rendered.f64()
					expected_f := expected.f64()
					if math.abs(actual_f - expected_f) > f.tol * math.abs(expected_f) {
						failures << '${fname}/${f.id}: tol mismatch (tol=${f.tol})\n  got:      ${rendered}\n  expected: ${expected}'
					}
				} else if !same_shape(rendered, expected) {
					if bless && quote_only_diff(rendered, expected) {
						bless_emit(fname, f.id, rendered)
					} else {
						failures << '${fname}/${f.id}: mismatch\n  got:      ${rendered}\n  expected: ${expected}'
					}
				}
			}
		}
	}
	// Partition failures by the per-module gate policy (conformance/gates.cxd):
	// 'advisory' modules are the spec-first frontier (unimplemented) — reported
	// but NOT blocking; everything else is enforced (deny-by-default).
	mut enforced := []string{}
	mut advisory := []string{}
	for fl in failures {
		if adv_ids[fl.all_before(': ')] {
			advisory << fl
		} else {
			enforced << fl
		}
	}
	if advisory.len > 0 {
		println('${advisory.len} advisory stdlib fixture failure(s) of ${ran} — frontier/unimplemented modules, reported not blocking.')
	}
	if enforced.len > 0 {
		println('${enforced.len} ENFORCED stdlib fixture failure(s) of ${ran}:')
		for fl in enforced {
			println('  ${fl}')
		}
	}
	if !bless {
		assert enforced.len == 0
	}
}

// same_shape compares two render outputs ignoring whitespace
// differences (lines, multi-space, leading/trailing). Both must have
// the same nonblank tokens in the same order.
fn same_shape(a string, b string) bool {
	at := a.fields()
	bt := b.fields()
	if at.len != bt.len { return false }
	for i, t in at {
		if t != bt[i] { return false }
	}
	return true
}

// same_multiset compares two render outputs as multisets
// D11 — used for :par-unordered fixtures where worker completion order
// is non-deterministic but membership IS contracted. Parses both sides
// by stripping outer `()` parens + splitting on `,` (handling the CX
// sequence-literal render shape `(a, b, c)`), trims items, sorts both
// sides, compares element-by-element. Asserts that the multiset of
// items is identical, irrespective of emission order.
fn same_multiset(a string, b string) bool {
	mut ai := multiset_items(a)
	mut bi := multiset_items(b)
	if ai.len != bi.len { return false }
	ai.sort()
	bi.sort()
	for i, t in ai {
		if t != bi[i] { return false }
	}
	return true
}

fn multiset_items(s string) []string {
	mut inner := s.trim_space()
	if inner.starts_with('(') && inner.ends_with(')') {
		inner = inner[1..inner.len - 1]
	}
	mut items := []string{}
	for part in inner.split(',') {
		t := part.trim_space()
		if t != '' { items << t }
	}
	return items
}
