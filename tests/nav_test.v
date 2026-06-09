module main

import cx

fn test_document_at() {
	doc := cx.parse('[config [server host=localhost port=8080]]') or { panic(err) }
	server := doc.at('config/server') or { panic('not found') }
	assert server.name == 'server'
}

fn test_element_attr_string() {
	doc := cx.parse('[config [server host=localhost port=8080]]') or { panic(err) }
	server := doc.at('config/server') or { panic('not found') }
	assert server.attr('host') == 'localhost'
	assert server.attr('port') == '8080'
	assert server.attr('missing') == ''
}

fn test_element_attr_bool() {
	doc := cx.parse('[item active=true]') or { panic(err) }
	item := doc.root() or { panic('') }
	assert item.attr('active') == 'true'
}

fn test_has_attr() {
	doc := cx.parse('[el x=1]') or { panic(err) }
	el := doc.root() or { panic('') }
	assert el.has_attr('x') == true
	assert el.has_attr('y') == false
}

fn test_document_get() {
	doc := cx.parse('[config]\n[other]') or { panic(err) }
	cfg := doc.get('config') or { panic('not found') }
	assert cfg.name == 'config'
}

fn test_document_root() {
	doc := cx.parse('[root]') or { panic(err) }
	root := doc.root() or { panic('') }
	assert root.name == 'root'
}

fn test_element_get() {
	doc := cx.parse('[parent [child x=1] [child x=2]]') or { panic(err) }
	parent := doc.root() or { panic('') }
	child := parent.get('child') or { panic('') }
	assert child.attr('x') == '1'
}

fn test_element_get_all() {
	doc := cx.parse('[parent [item a=1] [item a=2] [item a=3]]') or { panic(err) }
	parent := doc.root() or { panic('') }
	items := parent.get_all('item')
	assert items.len == 3
	assert items[2].attr('a') == '3'
}

fn test_find_all() {
	doc := cx.parse('[root [a [b [a]]] [a]]') or { panic(err) }
	all_a := doc.find_all('a')
	assert all_a.len == 3
}

fn test_find_first() {
	doc := cx.parse('[root [a x=1] [a x=2]]') or { panic(err) }
	first := doc.find_first('a') or { panic('') }
	assert first.attr('x') == '1'
}

fn test_children() {
	doc := cx.parse('[root [a] text [b]]') or { panic(err) }
	root := doc.root() or { panic('') }
	children := root.children()
	assert children.len == 2
	assert children[0].name == 'a'
	assert children[1].name == 'b'
}

fn test_text() {
	doc := cx.parse('[p Hello world]') or { panic(err) }
	p := doc.root() or { panic('') }
	assert p.text() == 'Hello world'
}

fn test_set_attr() {
	doc := cx.parse('[item x=1]') or { panic(err) }
	mut el := doc.root() or { panic('') }
	el.set_attr('x', cx.ScalarValue('updated'))
	assert el.attr('x') == 'updated'
}

fn test_to_cx() {
	src := '[config host=localhost]'
	doc := cx.parse(src) or { panic(err) }
	out := doc.to_cx()
	assert out.contains('config')
	assert out.contains('host=localhost')
}

fn test_document_append_prepend() {
	mut doc := cx.parse('[a]') or { panic(err) }
	doc.append(cx.Node(cx.Element{ name: 'b' }))
	doc.prepend(cx.Node(cx.Element{ name: 'z' }))
	assert (doc.get('z') or { panic('') }).name == 'z'
	assert (doc.get('b') or { panic('') }).name == 'b'
}

// CXPath `Document.select` / `Document.select_all` and the
// `Document.transform` / `Document.transform_all` shape-mutation
// helpers were removed when cxpath.v + transform.v were deleted per
// The replacement is the CX code language — `[?for pattern
// :yield expr]` for selection (CXPath §7.5 pattern-generator form),
// or `[?for $m :in (…) :yield …]` for projection.
// See spec/code.md §5 + §7 and the programs API tests in
// vcx/tests/code_api_test.v.

fn test_stream_function() {
	events := cx.stream('[config host=localhost]') or { panic(err) }
	type_names := events.map(match it {
		cx.StreamStartDoc     { 'StartDoc' }
		cx.StreamEndDoc       { 'EndDoc' }
		cx.StreamStartElement { 'StartElement' }
		cx.StreamEndElement   { 'EndElement' }
		else                  { 'Other' }
	})
	assert 'StartDoc' in type_names
	assert 'StartElement' in type_names
	assert 'EndDoc' in type_names
}
