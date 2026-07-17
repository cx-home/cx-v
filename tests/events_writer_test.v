module main

import cx

// Phase 7.74g G2 — V-core streaming-write writer tests.
// Verifies state machine validation (W001-W013 codes) and CX-format
// emission against §6.1 / §6.5 / §6.6.

fn test_basic_lifecycle_in_memory() {
	mut w := cx.new_events_writer_bytes('cx') or { panic('open: ${err}') }
	w.emit_start_doc() or { panic('start_doc: ${err}') }
	w.emit_start_element('greet', none, none, none, []u8{}) or {
		panic('start_element: ${err}')
	}
	w.emit_text('hello') or { panic('text: ${err}') }
	w.emit_end_element('greet') or { panic('end_element: ${err}') }
	w.emit_end_doc() or { panic('end_doc: ${err}') }
	out := w.close_get_bytes() or { panic('close: ${err}') }
	s := out.bytestr()
	assert s.contains('[greet'), 'expected [greet in output; got: "${s}"'
	assert s.contains('hello'), 'expected hello in output; got: "${s}"'
}

fn test_w001_double_start_doc() {
	mut w := cx.new_events_writer_bytes('cx') or { panic('open: ${err}') }
	w.emit_start_doc() or { panic('first start_doc: ${err}') }
	w.emit_start_doc() or {
		assert err.msg().contains('W001'), 'expected W001; got "${err.msg()}"'
		return
	}
	assert false, 'expected W001 error'
}

fn test_w002_event_before_start_doc() {
	mut w := cx.new_events_writer_bytes('cx') or { panic('open: ${err}') }
	w.emit_text('hello') or {
		assert err.msg().contains('W002'), 'expected W002; got "${err.msg()}"'
		return
	}
	assert false, 'expected W002 error'
}

fn test_w004_end_doc_with_unclosed_element() {
	mut w := cx.new_events_writer_bytes('cx') or { panic('open: ${err}') }
	w.emit_start_doc() or { panic('start_doc: ${err}') }
	w.emit_start_element('greet', none, none, none, []u8{}) or { panic('start_element: ${err}') }
	w.emit_end_doc() or {
		assert err.msg().contains('W004'), 'expected W004; got "${err.msg()}"'
		return
	}
	assert false, 'expected W004 error'
}

fn test_w005_end_element_name_mismatch() {
	mut w := cx.new_events_writer_bytes('cx') or { panic('open: ${err}') }
	w.emit_start_doc() or { panic('start_doc: ${err}') }
	w.emit_start_element('greet', none, none, none, []u8{}) or { panic('start_element: ${err}') }
	w.emit_end_element('farewell') or {
		assert err.msg().contains('W005'), 'expected W005; got "${err.msg()}"'
		return
	}
	assert false, 'expected W005 error'
}

fn test_w006_end_element_without_start() {
	mut w := cx.new_events_writer_bytes('cx') or { panic('open: ${err}') }
	w.emit_start_doc() or { panic('start_doc: ${err}') }
	w.emit_end_element('foo') or {
		assert err.msg().contains('W006'), 'expected W006; got "${err.msg()}"'
		return
	}
	assert false, 'expected W006 error'
}

fn test_w008_invalid_data_type() {
	mut w := cx.new_events_writer_bytes('cx') or { panic('open: ${err}') }
	w.emit_start_doc() or { panic('start_doc: ${err}') }
	w.emit_scalar(?string('not_a_real_type'), '42') or {
		assert err.msg().contains('W008'), 'expected W008; got "${err.msg()}"'
		return
	}
	assert false, 'expected W008 error'
}

fn test_w009_chunked_table_on_non_cx_format() {
	mut w := cx.new_events_writer_bytes('json') or { panic('open: ${err}') }
	w.emit_start_doc() or {
		// json StartDoc may itself trip the not-yet-implemented stub —
		// surface that path early so this test focuses on chunked
		// rejection. We just verify the chunked-on-json case below
		// explicitly.
	}
	// Build a one-column col_spec.
	mut col_spec := []u8{cap: 16}
	col_spec << u8(1); col_spec << u8(0); col_spec << u8(0); col_spec << u8(0)
	col_spec << u8(1); col_spec << u8(0); col_spec << u8(0); col_spec << u8(0)
	col_spec << u8(`x`)
	col_spec << u8(0x12) // i32
	w.emit_start_table(col_spec) or {
		// Acceptable diagnostics: W009 (chunked on non-cx) or earlier
		// W009 (StartDoc on non-cx not yet implemented). Either is a
		// W-code, which is the contract.
		assert err.msg().contains('W009'), 'expected W009; got "${err.msg()}"'
		return
	}
	assert false, 'expected W009 error'
}

fn test_w010_nested_start_table() {
	mut w := cx.new_events_writer_bytes('cx') or { panic('open: ${err}') }
	w.emit_start_doc() or { panic('start_doc: ${err}') }
	mut col_spec := []u8{cap: 16}
	col_spec << u8(1); col_spec << u8(0); col_spec << u8(0); col_spec << u8(0)
	col_spec << u8(1); col_spec << u8(0); col_spec << u8(0); col_spec << u8(0)
	col_spec << u8(`x`)
	col_spec << u8(0x12) // i32
	w.emit_start_table(col_spec) or { panic('start_table: ${err}') }
	w.emit_start_table(col_spec) or {
		assert err.msg().contains('W010'), 'expected W010; got "${err.msg()}"'
		return
	}
	assert false, 'expected W010 error'
}

fn test_w012_row_group_without_start_table() {
	mut w := cx.new_events_writer_bytes('cx') or { panic('open: ${err}') }
	w.emit_start_doc() or { panic('start_doc: ${err}') }
	w.emit_row_group([u8(1)]) or {
		assert err.msg().contains('W012'), 'expected W012; got "${err.msg()}"'
		return
	}
	assert false, 'expected W012 error'
}

fn test_w013_end_table_without_start() {
	mut w := cx.new_events_writer_bytes('cx') or { panic('open: ${err}') }
	w.emit_start_doc() or { panic('start_doc: ${err}') }
	w.emit_end_table() or {
		assert err.msg().contains('W013'), 'expected W013; got "${err.msg()}"'
		return
	}
	assert false, 'expected W013 error'
}

// `test_w011_shape_engine_not_implemented` was removed when 
// was superseded by (2026-05-10) — the declarative shape-
// rewrite engine and its `new_events_writer_shaped` entry point were
// deleted. CX code 1.0 is the sole output-shape mechanism; shape-engine
// W011 no longer exists as an error code.

fn test_chunked_table_round_trip_through_writer() {
	// Build one chunked-table event sequence end-to-end and assert the
	// resulting CX text re-parses.
	mut w := cx.new_events_writer_bytes('cx') or { panic('open: ${err}') }
	w.emit_start_doc() or { panic('start_doc: ${err}') }
	w.emit_start_element('points', none, none, none, []u8{}) or {
		panic('start_element: ${err}')
	}
	// col_spec: 2 columns — name:string, score:i32.
	mut col_spec := []u8{cap: 32}
	col_spec << u8(2); col_spec << u8(0); col_spec << u8(0); col_spec << u8(0) // count=2
	col_spec << u8(4); col_spec << u8(0); col_spec << u8(0); col_spec << u8(0); col_spec << u8(`n`); col_spec << u8(`a`); col_spec << u8(`m`); col_spec << u8(`e`)
	col_spec << u8(0x30) // string
	col_spec << u8(5); col_spec << u8(0); col_spec << u8(0); col_spec << u8(0); col_spec << u8(`s`); col_spec << u8(`c`); col_spec << u8(`o`); col_spec << u8(`r`); col_spec << u8(`e`)
	col_spec << u8(0x12) // i32
	w.emit_start_table(col_spec) or { panic('start_table: ${err}') }
	// Row group plain body: uvarint(2) + col-payload (col-major):
	//   col 1 (string): "alice"(uvarint=5), "bob"(uvarint=3)
	//   col 2 (i32 LE): 91, 88
	mut payload := []u8{cap: 32}
	payload << u8(2)             // uvarint(row_count=2)
	payload << u8(5); payload << u8(`a`); payload << u8(`l`); payload << u8(`i`); payload << u8(`c`); payload << u8(`e`)
	payload << u8(3); payload << u8(`b`); payload << u8(`o`); payload << u8(`b`)
	payload << u8(91); payload << u8(0); payload << u8(0); payload << u8(0)
	payload << u8(88); payload << u8(0); payload << u8(0); payload << u8(0)
	w.emit_row_group(payload) or { panic('row_group: ${err}') }
	w.emit_end_table() or { panic('end_table: ${err}') }
	w.emit_end_element('points') or { panic('end_element: ${err}') }
	w.emit_end_doc() or { panic('end_doc: ${err}') }
	out := w.close_get_bytes() or { panic('close: ${err}') }
	s := out.bytestr()
	// #487 re-bless: the writer previously emitted the RETIRED pre-cutover
	// surface `[points :table[name:string score:i32]` (v0.7 meta-slot
	// opener + single-colon column types) — text the live grammar rejects,
	// which the old `doc.elements.len > 0` assert could not see (the
	// parser produced silent non-table garbage). The pin is now the
	// CURRENT `[table[name::type …]]` clause-child form (grammar [29]/[29b])
	// plus a STRUCTURAL re-parse: the table element must come back as a
	// real TableData payload with the typed cells intact. (String columns
	// render UNANNOTATED — grammar [29b]: untyped defaults to ::string;
	// column_type_name_from_code drops the string tag on emit.)
	assert s.contains('[table[name score::i32]]'), 'expected current [table[…]] clause form in output; got "${s}"'
	assert s.contains('alice'), 'expected alice in output; got "${s}"'
	assert s.contains('91'), 'expected 91 in output; got "${s}"'
	doc := cx.parse(s) or { panic('reparse failed (${err}); src=${s}') }
	assert doc.elements.len == 1, 'expected a single root; got ${doc.elements.len}'
	root := doc.elements[0]
	assert root is cx.Element, 'expected Element root'
	outer := root as cx.Element
	assert outer.name == 'points'
	// The chunked table rides as the (writer-convention) same-named child
	// element of the enclosing StartElement.
	mut found_table := false
	for it in outer.items {
		if it is cx.Element {
			inner := it as cx.Element
			if inner.name == 'points' {
				td := inner.table_opt() or { continue }
				assert td.cols.len == 2
				assert td.cols[0].name == 'name'
				assert td.cols[0].type_name == '' // string default, unannotated
				assert td.cols[1].name == 'score'
				assert td.cols[1].type_name == 'i32'
				assert td.rows.len == 2
				c00 := td.rows[0][0]
				c01 := td.rows[0][1]
				c10 := td.rows[1][0]
				c11 := td.rows[1][1]
				assert c00 is string && c00 as string == 'alice'
				assert c01 is i64 && c01 as i64 == 91
				assert c10 is string && c10 as string == 'bob'
				assert c11 is i64 && c11 as i64 == 88
				found_table = true
			}
		}
	}
	assert found_table, 'chunked table did not re-parse as a TableData element; src=${s}'
}

// emit_xml_inline previously dropped SequenceNode / ArrayNode / MapNode
// children of a named element (the inline dispatch's `else {}` arm).
// Regression for Phase 3.11 follow-up — collection markers must round-
// trip even when nested inside a named element body.
fn test_xml_inline_sequence_round_trip() {
	doc := cx.Document{
		elements: [
			cx.Node(cx.Element{
				name:  'parent'
				items: [cx.Node(cx.SequenceNode{
					items: [
						cx.Node(cx.ScalarNode{ value: i64(1), data_type: cx.ScalarType.int_type }),
						cx.Node(cx.ScalarNode{ value: i64(2), data_type: cx.ScalarType.int_type }),
					]
				})]
			}),
		]
	}
	out := cx.emit_xml(doc)
	assert out.contains('<cx:seq>'), 'expected nested <cx:seq> inside <parent>; got: ${out}'
	assert out.contains('<cx:item>1</cx:item>'), 'expected <cx:item>1</cx:item>; got: ${out}'
	assert out.contains('<cx:item>2</cx:item>'), 'expected <cx:item>2</cx:item>; got: ${out}'
}

fn test_xml_inline_array_round_trip() {
	doc := cx.Document{
		elements: [
			cx.Node(cx.Element{
				name:  'parent'
				items: [cx.Node(cx.ArrayNode{
					items: [
						cx.Node(cx.ScalarNode{ value: 'a', data_type: cx.ScalarType.string_type }),
						cx.Node(cx.ScalarNode{ value: 'b', data_type: cx.ScalarType.string_type }),
					]
				})]
			}),
		]
	}
	out := cx.emit_xml(doc)
	assert out.contains('<cx:arr>'), 'expected nested <cx:arr> inside <parent>; got: ${out}'
	assert out.contains('<cx:item>a</cx:item>'), 'expected <cx:item>a</cx:item>; got: ${out}'
	assert out.contains('<cx:item>b</cx:item>'), 'expected <cx:item>b</cx:item>; got: ${out}'
}

fn test_xml_inline_map_round_trip() {
	doc := cx.Document{
		elements: [
			cx.Node(cx.Element{
				name:  'parent'
				items: [cx.Node(cx.MapNode{
					entries: [cx.MapEntry{
						key_type:  cx.ScalarType.string_type
						key_value: cx.ScalarValue('k')
						value:     cx.Node(cx.ScalarNode{
							value: 'v', data_type: cx.ScalarType.string_type
						})
					}]
				})]
			}),
		]
	}
	out := cx.emit_xml(doc)
	assert out.contains('<cx:map>'), 'expected nested <cx:map> inside <parent>; got: ${out}'
	assert out.contains('<cx:entry cx:key="k">'), 'expected cx:entry cx:key="k"; got: ${out}'
}

fn test_xml_emit_basic() {
	mut w := cx.new_events_writer_bytes('xml') or { panic('open: ${err}') }
	w.emit_start_doc() or { panic('start_doc: ${err}') }
	w.emit_start_element('greet', none, none, none, []u8{}) or {
		panic('start_element: ${err}')
	}
	w.emit_text('hello & welcome') or { panic('text: ${err}') }
	w.emit_end_element('greet') or { panic('end_element: ${err}') }
	w.emit_end_doc() or { panic('end_doc: ${err}') }
	out := w.close_get_bytes() or { panic('close: ${err}') }
	s := out.bytestr()
	assert s.contains('<?xml version="1.0"?>'), 'expected XML decl; got "${s}"'
	assert s.contains('<greet>'), 'expected <greet>; got "${s}"'
	assert s.contains('hello &amp; welcome'), 'expected escaped text; got "${s}"'
	assert s.contains('</greet>'), 'expected </greet>; got "${s}"'
}

fn test_xml_emit_alias_w009() {
	mut w := cx.new_events_writer_bytes('xml') or { panic('open: ${err}') }
	w.emit_start_doc() or { panic('start_doc: ${err}') }
	w.emit_alias('ref') or {
		assert err.msg().contains('W009'), 'expected W009 for Alias on xml; got "${err.msg()}"'
		return
	}
	assert false, 'expected W009 error'
}

fn test_fail_closed_after_first_error() {
	mut w := cx.new_events_writer_bytes('cx') or { panic('open: ${err}') }
	w.emit_start_doc() or { panic('start_doc: ${err}') }
	// Force a W005 by closing a different element.
	w.emit_start_element('a', none, none, none, []u8{}) or { panic('start_a: ${err}') }
	w.emit_end_element('b') or {
		// Intentional W005.
	}
	// Subsequent emits must surface the same error code without effect.
	w.emit_text('after-error') or {
		assert err.msg().contains('W005'), 'expected fail-closed to keep W005; got "${err.msg()}"'
		return
	}
	assert false, 'expected fail-closed error'
}
