module cx

import os

// Regression tests for the CX-native fixture loader: a parser canary (inline,
// file-free bootstrap guard) plus validation against the hardest .cxd suites
// (code.cxd: 591 cases, `---` inside RawText, `#]` splits; schema_validate:
// typed atom-array / bool sections).

fn probe_base() string {
	return os.join_path(os.dir(@FILE), '..', '..', 'conformance')
}

// Parser canary (bootstrap guard). Parses a tiny INLINE .cxd-shaped document
// — no file load — and asserts the loader's parse path is alive. If the
// structural CX parser regresses, THIS fails with a precise error independent
// of any conformance/*.cxd file, pinpointing "the parser that reads fixtures
// is broken" vs "a fixture's logic failed". The file-based loaders panic
// loudly; this canary names the cause.
fn test_loader_parser_canary() {
	src := '[test-suite name=canary
 [case id=c1 level=core
  [tags smoke]
  [in-cx [#
[p hi]
#]]
  [out-text [#
HI
#]]
 ]
]
'
	cases := parse_fixture_suite(src, '<canary>')
	assert cases.len == 1, 'canary: expected 1 case, got ${cases.len}'
	c := cases[0]
	assert c.name == 'c1', 'canary: name=${c.name}'
	assert c.level == 'core', 'canary: level=${c.level}'
	assert c.tags == ['smoke'], 'canary: tags=${c.tags}'
	assert c.sections['in_cx'] == '[p hi]', 'canary: in_cx=${c.sections['in_cx']}'
	assert c.sections['out_text'] == 'HI', 'canary: out_text=${c.sections['out_text']}'
}

fn test_probe_loader_counts() {
	// Load the hardest suites; each must yield cases, each with a name.
	// (Exact counts aren't asserted — the conformance .txt churn; the Python
	// audit proves .cxd ≡ .txt losslessly.)
	for f in ['code.cxd', 'core.cxd', 'code_diagram.cxd', 'extended.cxd', 'xml.cxd',
		'schema_validate.cxd'] {
		cases := load_fixtures(os.join_path(probe_base(), f))
		eprintln('${f}: ${cases.len} cases')
		assert cases.len > 0, '${f}: no cases'
		for c in cases {
			assert c.name != '', '${f}: empty case name'
		}
	}
}

fn test_probe_schema_validate_typed() {
	sv := load_fixtures(os.join_path(probe_base(), 'schema_validate.cxd'))
	mut saw_codes := false
	mut saw_valid := false
	for c in sv {
		if codes := c.sections['sv_expected_codes'] {
			// must be a bare comma-joined code list, e.g. "S002,S004"
			assert !codes.contains(':'), 'codes leaked atom colon: ${codes}'
			assert !codes.contains('['), 'codes leaked array bracket: ${codes}'
			saw_codes = true
		}
		if v := c.sections['sv_assert_valid'] {
			assert v == '1' || v == '0', 'sv_assert_valid not 1/0: ${v}'
			saw_valid = true
		}
	}
	assert saw_codes, 'no sv_expected_codes reconstructed'
	assert saw_valid, 'no sv_assert_valid reconstructed'
}

fn test_probe_rawtext_hash_split() {
	// extended.cxd carries `[message body=[# raw [literal] content #]]` whose
	// payload contains a literal `#]` (split across RawText siblings). Verify
	// it rejoins exactly.
	ex := load_fixtures(os.join_path(probe_base(), 'extended.cxd'))
	mut saw := false
	for c in ex {
		for _, body in c.sections {
			if body.contains('raw [literal] content #]') {
				saw = true
			}
		}
	}
	assert saw, 'literal #] payload did not rejoin'
}
