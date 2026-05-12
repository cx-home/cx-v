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

fn test_w011_shape_engine_not_implemented() {
	shape := [u8(`a`), u8(`b`)]
	cx.new_events_writer_shaped('cx', shape) or {
		assert err.msg().contains('W011'), 'expected W011; got "${err.msg()}"'
		return
	}
	assert false, 'expected W011 error'
}

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
	assert s.contains(':table'), 'expected :table in output; got "${s}"'
	assert s.contains('alice'), 'expected alice in output; got "${s}"'
	assert s.contains('91'), 'expected 91 in output; got "${s}"'
	// Re-parse to assert structural integrity.
	doc := cx.parse(s) or { panic('reparse failed (${err}); src=${s}') }
	assert doc.elements.len > 0, 'expected non-empty round-trip parse'
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
