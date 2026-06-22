module main

import cx

// Tests for v3.4 logfmt mode. Spec: spec/grammar.ebnf [2].
// A document consisting entirely of top-level Name=Value attributes
// parses as a single synthetic Element named '_' carrying those
// attributes.

// ── Basic logfmt parsing ─────────────────────────────────────────────────────

fn test_logfmt_single_attr() {
	doc := cx.parse('time=2026-05-06T12:00:00Z') or { panic(err) }
	assert doc.elements.len == 1
	root := doc.root() or { panic('no root') }
	assert root.name == '_'
	assert root.attr('time') == '2026-05-06T12:00:00Z'
}

fn test_logfmt_multiple_attrs() {
	src := 'time=2026-05-06T12:00:00Z level=INFO svc=web req=GET path=/foo'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.name == '_'
	assert root.attr('level') == 'INFO'
	assert root.attr('svc') == 'web'
	assert root.attr('req') == 'GET'
	assert root.attr('path') == '/foo'
}

fn test_logfmt_with_typed_values() {
	src := 'level=INFO count=42 active=true ratio=1.5'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.attr('level') == 'INFO'
	assert root.attr('count') == '42'
	assert root.attr('active') == 'true'
	assert root.attr('ratio') == '1.5'
}

fn test_logfmt_with_quoted_value() {
	src := "msg='request completed' status=ok"
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.attr('msg') == 'request completed'
	assert root.attr('status') == 'ok'
}

// ── Disambiguation: regular CX still works ───────────────────────────────────

fn test_regular_cx_not_treated_as_logfmt() {
	// Starts with `[`, so it's a normal element document.
	doc := cx.parse('[server host=localhost]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.name == 'server'
	assert root.attr('host') == 'localhost'
}

fn test_regular_cx_with_prolog_not_logfmt() {
	src := '[?cx version=3.4]
[server host=localhost]'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.name == 'server'
}

// ── Comments + logfmt ────────────────────────────────────────────────────────

fn test_logfmt_with_leading_comment() {
	src := '# log line for the API
time=2026-05-06T12:00:00Z level=INFO'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.name == '_'
	assert root.attr('level') == 'INFO'
}

// ── Multi-line logfmt (one synthetic element per record per Phase 7.56) ─────
//
// Per spec/grammar.ebnf §9 (and Phase 7.56 of branch native-data-binding),
// each newline-terminated record in a logfmt document produces its own
// synthetic [_ ...] element. The old single-element-merged behavior was
// dropped because last-write-wins on duplicate keys silently lost data
// for streams of many records.

fn test_logfmt_one_element_per_record() {
	src := 'time=2026-05-06T12:00:00Z level=INFO
time=2026-05-06T12:00:01Z level=WARN
time=2026-05-06T12:00:02Z level=ERROR'
	doc := cx.parse(src) or { panic(err) }
	assert doc.elements.len == 3, 'expected 3 synthetic elements, got ${doc.elements.len}'
	first := doc.elements[0] as cx.Element
	second := doc.elements[1] as cx.Element
	third := doc.elements[2] as cx.Element
	assert first.name == '_'
	assert first.attr('level') == 'INFO'
	assert second.attr('level') == 'WARN'
	assert third.attr('level') == 'ERROR'
}

// ── Empty input is not logfmt ────────────────────────────────────────────────

fn test_empty_input_no_logfmt() {
	doc := cx.parse('') or { panic(err) }
	assert doc.elements.len == 0
}

fn test_whitespace_only_input_no_logfmt() {
	doc := cx.parse('   \n\n  \t  ') or { panic(err) }
	assert doc.elements.len == 0
}
