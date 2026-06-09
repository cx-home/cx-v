module main

import cx

// LR-ESCAPE (formal lexicon): a quoted body string left unterminated *because*
// a backslash escape consumed the would-be closing quote (`'ab\']`) — or a
// dangling `\` at EOF — is the CXERLEX-ESCAPE lexical fault, distinct from a
// plain unterminated string (`'abc]`), which is NOT retagged.

fn parse_msg(src string) string {
	cx.parse(src) or { return err.msg() }
	return '<accepted>'
}

fn test_escaped_closer_is_escape_error() {
	// `[s 'ab\']` — the `\'` escapes the quote that would have closed the string.
	msg := parse_msg("[s 'ab\\']")
	assert msg.contains('CXERLEX-ESCAPE'), 'want CXERLEX-ESCAPE, got: ${msg}'
}

fn test_plain_unterminated_is_not_retagged() {
	// `[s 'abc]` — plain unterminated, no escape involved → NOT CXERLEX-ESCAPE.
	msg := parse_msg("[s 'abc]")
	assert msg.contains('unterminated'), 'want an unterminated error, got: ${msg}'
	assert !msg.contains('CXERLEX-ESCAPE'), 'plain unterminated must not be CXERLEX-ESCAPE: ${msg}'
}

fn test_valid_escaped_quote_still_parses() {
	// `[s 'a\'b']` — an escaped quote mid-string is content; the string closes
	// normally and parses cleanly.
	cx.parse("[s 'a\\'b']") or { assert false, 'should parse: ${err.msg()}' }
}
