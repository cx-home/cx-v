module main

import cx

// v08_codepoint_charref_test — D-K (lexicon [L32] CODEPOINT VALIDITY): an XML
// character reference `&#…;` whose decoded value is a UTF-16 surrogate
// (U+D800–U+DFFF) or is > U+10FFFF is REJECTED (cx-err:CXERLEX-CODEPOINT),
// matching the `\u`/`\U` escape rule (already enforced). Valid char-refs still
// resolve to their character.

fn test_charref_hex_surrogate_rejected() {
	if _ := cx.parse('[x &#xD800;]') {
		assert false, 'surrogate char-ref &#xD800; must be rejected'
	}
}

fn test_charref_hex_over_range_rejected() {
	if _ := cx.parse('[x &#x110000;]') {
		assert false, 'over-range char-ref &#x110000; must be rejected'
	}
}

fn test_charref_decimal_surrogate_rejected() {
	// 55296 == 0xD800
	if _ := cx.parse('[x &#55296;]') {
		assert false, 'decimal surrogate char-ref &#55296; must be rejected'
	}
}

fn test_valid_charrefs_still_resolve() {
	doc := cx.parse('[x &#65;]') or { panic('valid &#65; should parse: ${err}') }
	assert doc.elements.len == 1
	doc2 := cx.parse('[x &#x41;]') or { panic('valid &#x41; should parse: ${err}') }
	assert doc2.elements.len == 1
	// U+10FFFF is the highest valid scalar — must be accepted.
	doc3 := cx.parse('[x &#x10FFFF;]') or { panic('U+10FFFF should parse: ${err}') }
	assert doc3.elements.len == 1
}
