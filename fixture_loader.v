module cx

import os

// CX-native conformance fixture loader.
//
// The canonical fixture format is the CX document (`conformance/*.cxd`,
// schema `conformance/fixtures.cxs`). This loader reads a suite via the CX
// parser itself — dogfooding the parser on every test run — and reconstructs
// each `[case …]` into the legacy-shaped fields the test consumers expect,
// replacing the per-consumer hand-rolled `=== test:` / `--- key` text parsers.
//
// Section keys are returned in their LEGACY snake_case form (`in_cx`,
// `out_ast`, `sv_expected_codes`, …) so consumers key into `sections` exactly
// as they did against the old `.txt`. Typed sections (atom arrays / bools) are
// rendered back to their legacy textual form.

pub struct FixtureCase {
pub mut:
	name     string            // legacy test name: id, plus ' ' + title when titled
	level    string            // '' when the case carried no level
	gate     string            // gate toggle: enforced|advisory|pending|skip ('' = unset → enforced)
	grant    string            // Effort B least-privilege grant: space-separated capability list (e.g. 'read write'); '' = host default
	tol      f64               // relative float tolerance for out-text match (0 = exact, as today)
	tags     []string
	meta     map[string]string // extra header lines: view/kind/note/chunk_at/pending/…
	sections map[string]string // legacy section key -> normalized body
	order    []string          // section keys, document order
}

// load_fixtures parses a `.cxd` conformance suite and returns its cases.
pub fn load_fixtures(path string) []FixtureCase {
	src := os.read_file(path) or { panic('load_fixtures: cannot read ${path}: ${err}') }
	return parse_fixture_suite(src, path)
}

// parse_fixture_suite parses suite text already in memory (path is for errors).
//
// Uses parse_cx (not parse): a suite payload may contain a `---` line inside a
// RawText block (CX multi-doc *examples* under test). parse_cx routes through
// the lexer-driven parse_stream, which consumes `---` inside RawText correctly
// and only treats a top-level `---` as a separator — so such a suite parses to
// a single intact document.
pub fn parse_fixture_suite(src string, path string) []FixtureCase {
	res := parse_cx(src) or { panic('load_fixtures: parse error in ${path}: ${err}') }
	mut docs := []Document{}
	if m := res.multi {
		for d in m {
			docs << d
		}
	} else if d := res.single {
		docs << d
	}
	mut cases := []FixtureCase{}
	for doc in docs {
		for node in doc.elements {
			if node is Element {
				if node.name == 'test-suite' {
					for child in node.items {
						if child is Element {
							if child.name == 'case' {
								cases << fixture_case_from(child)
							}
						}
					}
				}
			}
		}
	}
	return cases
}

fn fixture_case_from(c Element) FixtureCase {
	mut fc := FixtureCase{
		sections: map[string]string{}
		meta:     map[string]string{}
	}
	mut id := ''
	for a in c.attrs {
		match a.name {
			'id' { id = scalar_value_str_public(a.value) }
			'level' { fc.level = scalar_value_str_public(a.value) }
			'gate' { fc.gate = scalar_value_str_public(a.value) }
			'grant' { fc.grant = scalar_value_str_public(a.value) }
			'tol' { fc.tol = scalar_value_str_public(a.value).f64() }
			else {}
		}
	}
	mut title := ''
	for child in c.items {
		if child !is Element {
			continue
		}
		el := child as Element
		match el.name {
			'title' {
				title = fixture_rawtext(el) // inline [#…#] — exact, no normalize
			}
			'tags' {
				fc.tags = fixture_text(el).split_any(' \t').filter(it != '')
			}
			'meta' {
				body := fixture_normalize(fixture_rawtext(el))
				for line in body.split('\n') {
					idx := line.index(':') or { continue }
					fc.meta[line[..idx].trim_space()] = line[idx + 1..].trim_space()
				}
			}
			'expect-valid' {
				fc.sections['sv_assert_valid'] = if fixture_bool(el) { '1' } else { '0' }
				fc.order << 'sv_assert_valid'
			}
			'expect-codes' {
				fc.sections['sv_expected_codes'] = fixture_atom_csv(el)
				fc.order << 'sv_expected_codes'
			}
			'expect-warn-codes' {
				fc.sections['sv_expected_warn_codes'] = fixture_atom_csv(el)
				fc.order << 'sv_expected_warn_codes'
			}
			else {
				key := el.name.replace('-', '_')
				fc.sections[key] = fixture_normalize(fixture_rawtext(el))
				fc.order << key
			}
		}
	}
	fc.name = if title != '' { '${id} ${title}' } else { id }
	return fc
}

// fixture_rawtext concatenates the RawText payload(s) of a section element.
// (A literal `#]` in the payload is carried as adjacent RawText siblings;
// concatenation rejoins them.)
fn fixture_rawtext(e Element) string {
	mut s := ''
	for it in e.items {
		if it is RawTextNode {
			s += it.value
		}
	}
	return s
}

// fixture_text joins text/scalar body (used for the tags line).
fn fixture_text(e Element) string {
	mut s := ''
	for it in e.items {
		match it {
			TextNode { s += it.value }
			ScalarNode { s += scalar_value_str_public(it.value) }
			else {}
		}
	}
	return s
}

// fixture_normalize is the loader rule: strip one leading and one trailing
// newline (the ones introduced by the `[#` ⏎ … ⏎ `#]` layout).
fn fixture_normalize(raw string) string {
	mut s := raw
	if s.starts_with('\n') {
		s = s[1..]
	}
	if s.ends_with('\n') {
		s = s[..s.len - 1]
	}
	return s
}

fn fixture_bool(e Element) bool {
	for it in e.items {
		if it is ScalarNode {
			v := it.value
			if v is bool {
				return v
			}
		}
	}
	return false
}

fn fixture_atom_csv(e Element) string {
	mut names := []string{}
	for it in e.items {
		if it is ArrayNode {
			for item in it.items {
				if item is ScalarNode {
					v := item.value
					if v is string {
						names << v
					}
				}
			}
		}
	}
	return names.join(',')
}
