module main

import cx

// Tests for the Phase 2d CXPath C ABI plumbing. The CXPath algorithm
// itself is exercised by the existing test suite; these tests verify
// that the wrapper Document construction (single match → framed AST,
// many matches → synthetic 'cx:results' wrapper) round-trips through
// bin_to_doc cleanly.

fn test_cxpath_select_first_match_framing() {
	src := '[config
  [server host=primary]
  [server host=secondary]
]'
	doc := cx.parse(src) or { panic(err) }
	first := doc.select('//server') or { panic('expected match') }
	// Wrap as the cabi cx_select function does and verify the binary
	// AST round-trips with the matched element intact.
	wrapped := cx.Document{ elements: [cx.Node(first)] }
	bytes := cx.emit_ast_bin(wrapped)
	doc2 := cx.bin_to_doc(bytes) or { panic('decode: ${err}') }
	root := doc2.root() or { panic('no root') }
	assert root.name == 'server'
	assert root.attr('host') == 'primary', 'expected first match'
}

fn test_cxpath_select_all_wrapper_name() {
	src := '[config
  [server host=a]
  [server host=b]
  [server host=c]
]'
	doc := cx.parse(src) or { panic(err) }
	matches := doc.select_all('//server')
	assert matches.len == 3
	mut items := []cx.Node{cap: matches.len}
	for e in matches {
		items << cx.Node(e)
	}
	wrapper := cx.Element{ name: 'cx:results', items: items }
	wrapped := cx.Document{ elements: [cx.Node(wrapper)] }
	bytes := cx.emit_ast_bin(wrapped)
	doc2 := cx.bin_to_doc(bytes) or { panic(err) }
	root := doc2.root() or { panic('no root') }
	assert root.name == 'cx:results', 'wrapper element must be cx:results'
	assert root.items.len == 3
}

fn test_cxpath_select_no_match_returns_none() {
	src := '[config [server host=primary]]'
	doc := cx.parse(src) or { panic(err) }
	if _ := doc.select('//nonexistent') {
		assert false, 'expected no match'
	}
}

fn test_cxpath_select_all_empty_result() {
	src := '[config [server host=primary]]'
	doc := cx.parse(src) or { panic(err) }
	matches := doc.select_all('//nonexistent')
	assert matches.len == 0
	// The wrapper still works; empty children list.
	wrapper := cx.Element{ name: 'cx:results', items: []cx.Node{} }
	wrapped := cx.Document{ elements: [cx.Node(wrapper)] }
	bytes := cx.emit_ast_bin(wrapped)
	doc2 := cx.bin_to_doc(bytes) or { panic(err) }
	root := doc2.root() or { panic('no root') }
	assert root.name == 'cx:results'
	assert root.items.len == 0
}
