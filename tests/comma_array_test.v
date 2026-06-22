module main

import cx
import code

// v08_comma_array_test — lexicon.ebnf §9 [L25c] comma-separated element bodies
// in cx.parse. A TOP-LEVEL comma in an unannotated, child-free body is the
// universal list signal: it produces a single ARRAY node holding the items
// (each auto-typed per [L25a]). This is the "cx flavor" rule.
//
// @CHOICE-1 §9-ONE-LAYER (slice B): a comma body is ALWAYS a nested Array node
// — NOT a `T[]`-typed flat body, and NOT int→float promoted. Canonical render
// is therefore the uniform nested array literal `[name [item, item, …]]`, which
// is DISTINCT from a whitespace typed list (`[name a b]` → discrete children)
// and from an explicit `[name::T[] …]` (a `T[]`-typed element). String items
// inside the literal are always quoted (3a) so they round-trip as strings; all
// forms are idempotent through cx.parse (bijection).

fn canon(src string) string {
	doc := cx.parse(src) or { return 'REJECT: ${err}' }
	if doc.elements.len != 1 {
		return 'REJECT: ${doc.elements.len} top-level elements'
	}
	return code.render_canonical(doc.elements[0])
}

// ── comma body → nested array literal (uniform across item types) ──────────

fn test_comma_string_array() {
	// Without commas this is prose ("web prod"); the comma makes it an array.
	assert canon('[tags web, prod]') == "[tags ['web', 'prod']]", canon('[tags web, prod]')
	assert canon('[tags web, prod, us-east]') == "[tags ['web', 'prod', 'us-east']]", canon('[tags web, prod, us-east]')
}

fn test_comma_int_array() {
	assert canon('[ports 80, 443]') == '[ports [80, 443]]', canon('[ports 80, 443]')
}

fn test_comma_float_array() {
	assert canon('[ratios 1.0, 2.5]') == '[ratios [1.0, 2.5]]', canon('[ratios 1.0, 2.5]')
}

fn test_comma_no_promotion() {
	// Heterogeneous per-item types are PRESERVED — no int→float promotion
	// (the old `[xs 1.0 2.0 3.0]` float[] form is retired).
	assert canon('[xs 1, 2.0, 3]') == '[xs [1, 2.0, 3]]', canon('[xs 1, 2.0, 3]')
}

// ── trailing-comma singleton: a 1-item comma array ─────────────────────────

fn test_trailing_comma_singleton() {
	assert canon('[xs a,]') == "[xs ['a']]", canon('[xs a,]')
	// No comma → scalar, NOT a 1-array.
	assert canon('[xs a]') == "[xs 'a']", canon('[xs a]')
}

// ── comma inside quotes is literal; string items always quoted ─────────────

fn test_quoted_comma_literal() {
	// "a, b" contains a comma → it stays one quoted item inside the literal.
	assert canon("[xs 'a, b', c]") == "[xs ['a, b', 'c']]", canon("[xs 'a, b', c]")
}

fn test_string_item_quote_when_autotypes() {
	// A quoted "80" must stay quoted inside the literal or it would re-parse as
	// an int (3a / bijection). `prod` is a bare-name string → also quoted.
	assert canon("[xs '80', prod]") == "[xs ['80', 'prod']]", canon("[xs '80', prod]")
	// Unquoted 80 is genuinely an int; the mixed array keeps it bare, `prod`
	// quoted as a string item.
	assert canon('[xs 80, prod]') == "[xs [80, 'prod']]", canon('[xs 80, prod]')
}

// ── heterogeneous mix → nested array literal ───────────────────────────────

fn test_comma_mixed_array() {
	got := canon('[row 1, two, true]')
	// `1`/`true` stay bare (typed scalars); the bare-name string `two` is quoted.
	assert got == "[row [1, 'two', true]]", got
}

// ── negative controls: no top-level comma → not a comma array ──────────────

fn test_no_comma_unchanged() {
	// whitespace scalar run → typed list of discrete children (slice A).
	assert canon('[items 1 2 3]') == '[items 1 2 3]', canon('[items 1 2 3]')
	// whitespace words → prose ([L25b]).
	assert canon('[words a b c]') == "[words 'a b c']", canon('[words a b c]')
	// comma inside a sequence literal is NOT a top-level body comma.
	assert canon('[pair (1, 2)]') == '[pair (1, 2)]', canon('[pair (1, 2)]')
}

// ── bijection: render is idempotent (re-parse → re-render stable) ──────────

fn test_comma_array_round_trip() {
	srcs := ['[tags web, prod]', '[ports 80, 443]', '[xs a,]', "[xs 'a, b', c]",
		'[row 1, two, true]', '[ratios 1.0, 2.5]', "[xs '80', prod]"]
	for s in srcs {
		once := canon(s)
		twice := canon(once)
		assert once == twice, '${s}: not idempotent: `${once}` → `${twice}`'
	}
}
