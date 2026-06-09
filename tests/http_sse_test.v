module main

import cx
import code

// http_sse_test.v — the §3.6 SSE [event] SYMMETRY INVARIANT
// (spec/02-working/stdlib_http.md §3.6, §10): what the server frames with
// `send-event` parses back EQUAL on the client via `sse-events`. Both
// halves share ONE pure framing codec (code.http_sse_frame_event /
// code.http_sse_parse_event), so the round-trip holds by construction —
// this test pins both the exact wire format and the value round-trip.

fn ev_attr(e cx.Element, name string) string {
	for a in e.attrs {
		if a.name == name {
			return cx.scalar_value_str_public(a.value)
		}
	}
	return '<<absent>>'
}

fn mk_event(attrs []cx.Attribute) cx.Element {
	return cx.Element{
		name:  'event'
		attrs: attrs
	}
}

// ── exact canonical wire format ──────────────────────────────────────
fn test_sse_frame_canonical_wire() {
	ev := mk_event([
		cx.Attribute{ name: 'id', value: cx.ScalarValue('42') },
		cx.Attribute{ name: 'event', value: cx.ScalarValue('order-updated') },
		cx.Attribute{ name: 'data', value: cx.ScalarValue('hello\nworld') },
		cx.Attribute{ name: 'retry', value: cx.ScalarValue(i64(3000)) },
	])
	framed := code.http_sse_frame_event(ev)
	wire := if framed is cx.ScalarNode {
		v := framed.value
		if v is string { v } else { '' }
	} else {
		''
	}
	expected := 'id: 42\nevent: order-updated\ndata: hello\ndata: world\nretry: 3000\n\n'
	assert wire == expected, 'SSE wire mismatch:\n got: ${wire}\nwant: ${expected}'
}

// ── the symmetry invariant: frame → parse is identity ────────────────
fn test_sse_frame_parse_round_trip() {
	cases := [
		mk_event([
			cx.Attribute{ name: 'id', value: cx.ScalarValue('1') },
			cx.Attribute{ name: 'event', value: cx.ScalarValue('ping') },
			cx.Attribute{ name: 'data', value: cx.ScalarValue('payload') },
		]),
		mk_event([
			cx.Attribute{ name: 'data', value: cx.ScalarValue('only-data') },
		]),
		mk_event([
			cx.Attribute{ name: 'id', value: cx.ScalarValue('99') },
			cx.Attribute{ name: 'data', value: cx.ScalarValue('multi\nline\ndata') },
			cx.Attribute{ name: 'retry', value: cx.ScalarValue(i64(5000)) },
		]),
	]
	for ev in cases {
		framed := code.http_sse_frame_event(ev)
		wire := if framed is cx.ScalarNode {
			v := framed.value
			if v is string { v } else { '' }
		} else {
			assert false, 'frame returned a non-string (err?) for ${ev}'
			''
		}
		parsed := code.http_sse_parse_event(wire) or {
			assert false, 'parse failed for wire: ${wire}'
			return
		}
		// every attribute the server wrote parses back equal on the client
		assert ev_attr(parsed, 'id') == ev_attr(ev, 'id'), 'id drift: ${wire}'
		assert ev_attr(parsed, 'event') == ev_attr(ev, 'event'), 'event drift: ${wire}'
		assert ev_attr(parsed, 'data') == ev_attr(ev, 'data'), 'data drift: ${wire}'
		assert ev_attr(parsed, 'retry') == ev_attr(ev, 'retry'), 'retry drift: ${wire}'
	}
}

// ── comment / heartbeat frames are consumed silently (→ none) ────────
fn test_sse_parse_comment_only_is_none() {
	if _ := code.http_sse_parse_event(': keep-alive comment\n') {
		assert false, 'a comment-only frame must parse to none (silently consumed)'
	}
}

// ── empty [event] → CXER4539; CR/LF in id/event → CXER4531 ───────────
fn test_sse_frame_validation() {
	empty := code.http_sse_frame_event(mk_event([]))
	assert empty is cx.Element && (empty as cx.Element).name == 'err',
		'empty [event] must frame to an err'
	crlf := code.http_sse_frame_event(mk_event([
		cx.Attribute{ name: 'id', value: cx.ScalarValue('a\nb') },
		cx.Attribute{ name: 'data', value: cx.ScalarValue('x') },
	]))
	assert crlf is cx.Element && (crlf as cx.Element).name == 'err',
		'CR/LF in id must frame to an err'
}

// ── HOSTILE (audit): CR in DATA breaks the symmetry invariant ────────
// A `data` value ending in CR was framed verbatim then silently stripped by
// the parser's trim_right('\r'), so frame→parse was NOT identity. CR in data
// must now be rejected (CXER4531), the same as id/event; LF (the legitimate
// multi-line separator) still round-trips.
fn test_sse_data_cr_rejected() {
	cr := code.http_sse_frame_event(mk_event([
		cx.Attribute{ name: 'data', value: cx.ScalarValue('payload\r') },
	]))
	assert cr is cx.Element && (cr as cx.Element).name == 'err' &&
		ev_attr(cr as cx.Element, 'code') == 'cx-err:CXER4531',
		'CR in data must frame to CXER4531'
	// LF-bearing multi-line data still frames + round-trips (symmetry holds)
	ml := code.http_sse_frame_event(mk_event([
		cx.Attribute{ name: 'data', value: cx.ScalarValue('a\nb\nc') },
	]))
	assert !(ml is cx.Element && (ml as cx.Element).name == 'err'),
		'multi-line (LF) data must still frame'
}

// ── HOSTILE (audit): an unknown-attr-only [event] has nothing to send ──
// `[event foo="bar"]` carries no SSE field; the prior `&& attrs.len == 0`
// guard let it slip through and frame an empty wire. It must fault (CXER4539).
fn test_sse_unknown_attr_event_is_empty() {
	e := code.http_sse_frame_event(mk_event([
		cx.Attribute{ name: 'foo', value: cx.ScalarValue('bar') },
	]))
	assert e is cx.Element && (e as cx.Element).name == 'err' &&
		ev_attr(e as cx.Element, 'code') == 'cx-err:CXER4539',
		'an event with only unknown attrs must fault CXER4539'
}

// ── HOSTILE (audit): malformed-frame detection (the CXER4551 gate) ────
// sse-events used to `or { continue }` past every unparseable frame, so the
// declared CXER4551 was unreachable. A frame carrying an embedded CR (a byte
// our framer never emits) is now detected as malformed; sse-events raises
// CXER4551 on it instead of swallowing it. A clean / comment-only frame is
// NOT malformed.
fn test_sse_block_malformed_detection() {
	assert code.http_sse_block_malformed('data: a\rb\ndata: c'),
		'an embedded CR must be detected as a malformed frame'
	assert !code.http_sse_block_malformed('data: a\ndata: b'),
		'a clean LF-separated frame is not malformed'
	assert !code.http_sse_block_malformed(': heartbeat comment'),
		'a comment/heartbeat frame is not malformed'
	assert !code.http_sse_block_malformed('data: trailing\r'),
		'a trailing CR (CRLF line ending) is not malformed'
}
