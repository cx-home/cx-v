module main

import cx

// Tests for v3.4 line comments (# to end-of-line). Spec:
// spec/grammar.ebnf [30b], spec/policies.md.

// ── Top-level line comments ──────────────────────────────────────────────────

fn test_line_comment_before_element() {
	src := '# this is a config
[server host=localhost]'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.name == 'server'
	assert root.attr('host') == 'localhost'
}

fn test_multiple_line_comments_before_element() {
	src := '# line one
# line two
# line three
[server host=localhost]'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.name == 'server'
}

fn test_line_comment_terminated_by_eof() {
	src := '[server host=localhost]
# trailing comment with no newline'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.name == 'server'
}

fn test_line_comment_between_top_level_elements() {
	src := '[a]
# comment between
[b]'
	doc := cx.parse(src) or { panic(err) }
	// A line comment between root nodes is now PRESERVED as a CommentNode
	// sibling (lossless `cx fmt` — canonical.md §2.1), so elements holds
	// [Element a, CommentNode, Element b]. The two real elements are still
	// present; the comment rides between them in document order.
	mut element_count := 0
	for n in doc.elements {
		if n is cx.Element {
			element_count++
		}
	}
	assert element_count == 2
	assert cx.emit_cx(doc).contains('# comment between')
}

// ── Line comments inside element body ────────────────────────────────────────

fn test_line_comment_inside_body() {
	src := '[server
  # web frontend
  host=localhost
  port=8080
]'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.attr('host') == 'localhost'
	assert root.attr('port') == '8080'
}

fn test_line_comment_after_attribute_eol() {
	src := '[server host=localhost  # production host
  port=8080
]'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.attr('host') == 'localhost'
	assert root.attr('port') == '8080'
}

// ── # inside BareValue is preserved (not treated as comment) ─────────────────

fn test_hash_in_bare_value_preserved() {
	// '#' inside a bare value (no leading whitespace) is part of the
	// token. This is essential for URL fragments and tag refs.
	src := '[link href=http://example.com/page#section]'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.attr('href') == 'http://example.com/page#section'
}

fn test_hash_in_quoted_string_preserved() {
	src := "[note text='use # for line comments']"
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.attr('text') == 'use # for line comments'
}

// ── Empty / whitespace-only line comments ────────────────────────────────────

fn test_empty_line_comment() {
	src := '#
[a]'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.name == 'a'
}

fn test_line_comment_with_special_chars() {
	src := '# !@\$%^&*()_+-=[]{}|\\:";\\\'<>,.?/~`
[a]'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.name == 'a'
}
