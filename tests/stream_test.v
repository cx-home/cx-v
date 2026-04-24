module main

import cx
import os

// ── fixture loader ────────────────────────────────────────────────────────────

const fixtures = os.join_path(os.dir(@FILE), '..', '..', 'fixtures')

fn fx(name string) string {
	return os.read_file(os.join_path(fixtures, name)) or {
		panic('could not read fixture ${name}: ${err}')
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn event_type_name(e cx.StreamEvent) string {
	return match e {
		cx.StreamStartDoc     { 'StartDoc' }
		cx.StreamEndDoc       { 'EndDoc' }
		cx.StreamStartElement { 'StartElement' }
		cx.StreamEndElement   { 'EndElement' }
		cx.StreamText         { 'Text' }
		cx.StreamScalar       { 'Scalar' }
		cx.StreamComment      { 'Comment' }
		cx.StreamPI           { 'PI' }
		cx.StreamEntityRef    { 'EntityRef' }
		cx.StreamRawText      { 'RawText' }
		cx.StreamAlias        { 'Alias' }
	}
}

// ── Tests ─────────────────────────────────────────────────────────────────────

fn test_empty_doc() {
	mut s := cx.new_stream('') or { panic('parse failed: ${err}') }
	events := s.collect()
	assert events.len == 2, 'expected 2 events, got ${events.len}'
	assert event_type_name(events[0]) == 'StartDoc'
	assert event_type_name(events[1]) == 'EndDoc'
}

fn test_simple_element() {
	// [br] is a self-closing empty element in CX
	mut s := cx.new_stream('[br]') or { panic('parse failed: ${err}') }
	events := s.collect()
	// StartDoc, StartElement(br), EndElement(br), EndDoc
	assert events.len == 4, 'expected 4 events, got ${events.len}: ${events.map(event_type_name(it))}'
	assert event_type_name(events[0]) == 'StartDoc'
	assert event_type_name(events[1]) == 'StartElement'
	assert event_type_name(events[2]) == 'EndElement'
	assert event_type_name(events[3]) == 'EndDoc'
	se := events[1] as cx.StreamStartElement
	assert se.name == 'br', 'StartElement name: expected "br", got "${se.name}"'
	ee := events[2] as cx.StreamEndElement
	assert ee.name == 'br', 'EndElement name: expected "br", got "${ee.name}"'
}

fn test_element_with_attrs() {
	// [config host=localhost port=8080] — attrs-only element
	mut s := cx.new_stream('[config host=localhost port=8080]') or { panic('parse failed: ${err}') }
	events := s.collect()
	assert events.len == 4, 'expected 4 events, got ${events.len}'
	se := events[1] as cx.StreamStartElement
	assert se.name == 'config'
	assert se.attrs.len == 2, 'expected 2 attrs, got ${se.attrs.len}'
	assert se.attrs[0].name == 'host'
	assert se.attrs[1].name == 'port'
}

fn test_text_node() {
	// [p Hello world] — element with inline text content
	mut s := cx.new_stream('[p Hello world]') or { panic('parse failed: ${err}') }
	events := s.collect()
	// StartDoc, StartElement(p), Text("Hello world"), EndElement(p), EndDoc
	assert events.len == 5, 'expected 5 events, got ${events.len}: ${events.map(event_type_name(it))}'
	assert event_type_name(events[2]) == 'Text', 'events[2] should be Text, got ${event_type_name(events[2])}'
	txt := events[2] as cx.StreamText
	assert txt.value == 'Hello world', 'text: expected "Hello world", got "${txt.value}"'
}

fn test_nested_elements() {
	// [root[child]] — nested element syntax
	mut s := cx.new_stream('[root[child]]') or { panic('parse failed: ${err}') }
	events := s.collect()
	// StartDoc, StartElement(root), StartElement(child), EndElement(child), EndElement(root), EndDoc
	assert events.len == 6, 'expected 6 events, got ${events.len}: ${events.map(event_type_name(it))}'
	names := events.map(event_type_name(it))
	assert names == ['StartDoc','StartElement','StartElement','EndElement','EndElement','EndDoc']
	outer := events[1] as cx.StreamStartElement
	assert outer.name == 'root'
	inner := events[2] as cx.StreamStartElement
	assert inner.name == 'child'
}

fn test_pull_model() {
	mut s := cx.new_stream('[br]') or { panic('parse failed: ${err}') }
	e0 := s.next() or { panic('expected event 0') }
	assert event_type_name(e0) == 'StartDoc'
	e1 := s.next() or { panic('expected event 1') }
	assert event_type_name(e1) == 'StartElement'
	e2 := s.next() or { panic('expected event 2') }
	assert event_type_name(e2) == 'EndElement'
	e3 := s.next() or { panic('expected event 3') }
	assert event_type_name(e3) == 'EndDoc'
	// Exhausted — next() should return none
	e4 := s.next()
	assert e4 == none, 'expected none after exhaustion'
}

fn test_collect_partial() {
	// After calling next() once, collect() returns the rest
	mut s := cx.new_stream('[br]') or { panic('parse failed: ${err}') }
	_ := s.next() or { panic('expected StartDoc') }
	rest := s.collect()
	// Should be 3: StartElement, EndElement, EndDoc
	assert rest.len == 3, 'expected 3 remaining events, got ${rest.len}'
	assert event_type_name(rest[0]) == 'StartElement'
}

fn test_event_to_json_startdoc() {
	j := cx.event_to_json(cx.StreamStartDoc{})
	assert j == '{"type":"StartDoc"}', 'got ${j}'
}

fn test_event_to_json_enddoc() {
	j := cx.event_to_json(cx.StreamEndDoc{})
	assert j == '{"type":"EndDoc"}', 'got ${j}'
}

fn test_event_to_json_text() {
	j := cx.event_to_json(cx.StreamText{ value: 'hello' })
	assert j == '{"type":"Text","value":"hello"}', 'got ${j}'
}

fn test_event_to_json_comment() {
	j := cx.event_to_json(cx.StreamComment{ value: 'note' })
	assert j == '{"type":"Comment","value":"note"}', 'got ${j}'
}

fn test_event_to_json_endelement() {
	j := cx.event_to_json(cx.StreamEndElement{ name: 'config' })
	assert j == '{"type":"EndElement","name":"config"}', 'got ${j}'
}

fn test_event_to_json_entityref() {
	j := cx.event_to_json(cx.StreamEntityRef{ name: 'amp' })
	assert j == '{"type":"EntityRef","name":"amp"}', 'got ${j}'
}

fn test_event_to_json_alias() {
	j := cx.event_to_json(cx.StreamAlias{ name: 'myanchor' })
	assert j == '{"type":"Alias","name":"myanchor"}', 'got ${j}'
}

fn test_event_to_json_rawtext() {
	j := cx.event_to_json(cx.StreamRawText{ value: 'raw' })
	assert j.contains('"type":"RawText"'), 'missing type RawText in: ${j}'
	assert j.contains('"raw"'), 'missing value in: ${j}'
}

fn test_event_to_json_pi_no_data() {
	j := cx.event_to_json(cx.StreamPI{ target: 'xml', data: none })
	assert j == '{"type":"PI","target":"xml"}', 'got ${j}'
}

fn test_event_to_json_pi_with_data() {
	j := cx.event_to_json(cx.StreamPI{ target: 'xml', data: ?string('version=1.0') })
	assert j == '{"type":"PI","target":"xml","data":"version=1.0"}', 'got ${j}'
}

fn test_event_to_json_startelement_no_attrs() {
	j := cx.event_to_json(cx.StreamStartElement{ name: 'br', attrs: [] })
	assert j == '{"type":"StartElement","name":"br","attrs":[]}', 'got ${j}'
}

fn test_event_to_json_scalar_int() {
	j := cx.event_to_json(cx.StreamScalar{ data_type: 'int', value: i64(42) })
	assert j == '{"type":"Scalar","dataType":"int","value":42}', 'got ${j}'
}

fn test_full_round_trip_json() {
	input := '[config host=localhost]'
	mut s := cx.new_stream(input) or { panic('parse failed: ${err}') }
	events := s.collect()
	parts := events.map(cx.event_to_json(it))
	json_out := '[${parts.join(",")}]'
	assert json_out.contains('"type":"StartDoc"'), 'missing StartDoc'
	assert json_out.contains('"type":"StartElement"'), 'missing StartElement'
	assert json_out.contains('"name":"config"'), 'missing element name'
	assert json_out.contains('"type":"EndDoc"'), 'missing EndDoc'
}

fn test_new_stream_from_doc() {
	doc := cx.parse('[item x=1]') or { panic('parse failed: ${err}') }
	mut s := cx.new_stream_from_doc(doc)
	events := s.collect()
	assert events.len == 4, 'expected 4 events, got ${events.len}'
	se := events[1] as cx.StreamStartElement
	assert se.name == 'item'
	assert se.attrs.len == 1, 'expected 1 attr, got ${se.attrs.len}'
}

fn test_multiple_top_level_elements() {
	mut s := cx.new_stream('[a]\n[b]') or { panic('parse failed: ${err}') }
	events := s.collect()
	// StartDoc, StartElement(a), EndElement(a), StartElement(b), EndElement(b), EndDoc
	assert events.len == 6, 'expected 6 events, got ${events.len}: ${events.map(event_type_name(it))}'
}

// ── fixture-based tests ────────────────────────────────────────────────────────

fn test_fixture_all_event_types() {
	mut s := cx.new_stream(fx('stream/stream_events.cx')) or { panic('parse failed: ${err}') }
	events := s.collect()
	types := events.map(event_type_name(it))
	for want in ['StartDoc', 'EndDoc', 'StartElement', 'EndElement', 'Text',
		'Scalar', 'Comment', 'PI', 'EntityRef', 'RawText', 'Alias'] {
		assert want in types, 'missing event type: ${want}'
	}
}

fn test_fixture_comment_value() {
	mut s := cx.new_stream(fx('stream/stream_events.cx')) or { panic('parse failed: ${err}') }
	events := s.collect()
	comments := events.filter(event_type_name(it) == 'Comment')
	assert comments.len == 1
	c := comments[0] as cx.StreamComment
	assert c.value == 'a comment node', 'got "${c.value}"'
}

fn test_fixture_pi_value() {
	mut s := cx.new_stream(fx('stream/stream_events.cx')) or { panic('parse failed: ${err}') }
	events := s.collect()
	pis := events.filter(event_type_name(it) == 'PI')
	assert pis.len == 1
	pi := pis[0] as cx.StreamPI
	assert pi.target == 'pi', 'PI target: got "${pi.target}"'
	d := pi.data or { '' }
	assert d == 'pi data here', 'PI data: got "${d}"'
}

fn test_fixture_scalars() {
	mut s := cx.new_stream(fx('stream/stream_events.cx')) or { panic('parse failed: ${err}') }
	events := s.collect()
	scalars := events.filter(event_type_name(it) == 'Scalar')
	assert scalars.len == 2, 'expected 2 scalars, got ${scalars.len}'
	s0 := scalars[0] as cx.StreamScalar
	assert s0.data_type == 'int', 'first scalar type: got "${s0.data_type}"'
	s1 := scalars[1] as cx.StreamScalar
	assert s1.data_type == 'bool', 'second scalar type: got "${s1.data_type}"'
}

fn test_fixture_alias() {
	mut s := cx.new_stream(fx('stream/stream_events.cx')) or { panic('parse failed: ${err}') }
	events := s.collect()
	aliases := events.filter(event_type_name(it) == 'Alias')
	assert aliases.len == 1
	a := aliases[0] as cx.StreamAlias
	assert a.name == 'srv', 'alias name: got "${a.name}"'
}

fn test_fixture_nested_depth() {
	mut s := cx.new_stream(fx('stream/stream_nested.cx')) or { panic('parse failed: ${err}') }
	events := s.collect()
	starts := events.filter(event_type_name(it) == 'StartElement')
	names := starts.map((it as cx.StreamStartElement).name)
	assert 'level1' in names, 'missing level1'
	assert 'level6' in names, 'missing level6'
	assert names.len == 8, 'expected 8 start elements, got ${names.len}: ${names}'
}
