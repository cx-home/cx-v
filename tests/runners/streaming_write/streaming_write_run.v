module main

import os
import cx
import fixtures

// streaming_write.cxd V runner — closes corpus-audit gap G12 (pre-I2): the
// 17-case streaming-write family (incl. the W001–W013 negative contract) was
// driven ONLY by the python/go/rust FFI harnesses; the reference
// implementation itself had no lane. This runner drives the V-native
// CxEventsWriter (vcx/cx/events_writer.v — the same engine the C ABI wraps)
// and grades with the exact semantics of lang/python/conformance.py's
// run_streaming_write_test, so the V lane and the binding lanes can never
// disagree about what a fixture means.
//
// Usage: v run streaming_write_run.v ../conformance/streaming_write.cxd

fn dequote(s string) string {
	t := s.trim_space()
	if t.starts_with('"') && t.ends_with('"') && t.len >= 2 {
		return t[1..t.len - 1]
	}
	return t
}

fn first_nonblank_noncomment(text string) string {
	for line in text.split_into_lines() {
		t := line.trim_space()
		if t != '' && !t.starts_with('#') {
			return t
		}
	}
	return ''
}

fn strip_comments(text string) string {
	mut out := []string{}
	for line in text.split_into_lines() {
		if !line.trim_space().starts_with('#') {
			out << line
		}
	}
	return out.join('\n')
}

fn decode_hex(s string) ![]u8 {
	if s.len % 2 != 0 {
		return error('odd hex length')
	}
	mut out := []u8{cap: s.len / 2}
	for i := 0; i < s.len; i += 2 {
		hi := hex_val(s[i]) or { return error('bad hex char') }
		lo := hex_val(s[i + 1]) or { return error('bad hex char') }
		out << u8(hi << 4 | lo)
	}
	return out
}

fn hex_val(c u8) ?int {
	if c >= `0` && c <= `9` {
		return int(c - `0`)
	}
	if c >= `a` && c <= `f` {
		return int(c - `a`) + 10
	}
	if c >= `A` && c <= `F` {
		return int(c - `A`) + 10
	}
	return none
}

fn dispatch_event(mut w cx.CxEventsWriter, op string, rest string) ! {
	match op {
		'StartDoc' {
			w.emit_start_doc()!
		}
		'EndDoc' {
			w.emit_end_doc()!
		}
		'StartElement' {
			toks := rest.split(' ').filter(it != '')
			name := toks[0]
			mut anchor := ?string(none)
			mut data_type := ?string(none)
			mut merge := ?string(none)
			for t in toks[1..] {
				if t.starts_with('anchor=') {
					anchor = t[7..]
				} else if t.starts_with('data_type=') {
					data_type = t[10..]
				} else if t.starts_with('merge=') {
					merge = t[6..]
				}
			}
			w.emit_start_element(name, anchor, data_type, merge, [])!
		}
		'EndElement' {
			w.emit_end_element(rest.trim_space())!
		}
		'Text' {
			w.emit_text(dequote(rest))!
		}
		'Scalar' {
			typ := rest.all_before(':').trim_space()
			val := rest.all_after(':')
			dt := if typ == '' { ?string(none) } else { ?string(typ) }
			w.emit_scalar(dt, val)!
		}
		'Comment' {
			w.emit_comment(dequote(rest))!
		}
		'PI' {
			toks := rest.split_nth(' ', 2)
			target := toks[0]
			mut data := ?string(none)
			if toks.len > 1 && toks[1].trim_space().starts_with('data=') {
				data = dequote(toks[1].trim_space()[5..])
			}
			w.emit_pi(target, data)!
		}
		'EntityRef' {
			w.emit_entity_ref(rest.trim_space())!
		}
		'RawText' {
			w.emit_raw_text(dequote(rest))!
		}
		'Alias' {
			w.emit_alias(rest.trim_space())!
		}
		'StartTable' {
			w.emit_start_table(decode_hex(rest.trim_space())!)!
		}
		'RowGroup' {
			w.emit_row_group(decode_hex(rest.trim_space())!)!
		}
		'EndTable' {
			w.emit_end_table()!
		}
		else {
			return error('unknown event op: ${op}')
		}
	}
}

// run_case mirrors lang/python run_streaming_write_test; returns failures.
fn run_case(c fixtures.FixtureCase) []string {
	fmt := c.sections['format'] or { return ['missing format section'] }.trim_space()
	events := c.sections['events'] or { return ['missing events section'] }
	expect_err := first_nonblank_noncomment(c.sections['expect_err'] or { '' })
	has_ok := 'expect_ok' in c.sections
	expect_ok := strip_comments(c.sections['expect_ok'] or { '' })
	expect_ok_contains := strip_comments(c.sections['expect_ok_contains'] or { '' })

	mut w := cx.new_events_writer_bytes(fmt) or {
		if expect_err != '' && err.msg().contains(expect_err) {
			return []
		}
		return ['new_events_writer_bytes(${fmt}) failed: ${err}']
	}
	mut triggered := ''
	for raw_line in events.split_into_lines() {
		line := raw_line.trim_space()
		if line == '' {
			continue
		}
		op := line.all_before(' ')
		rest := if line.contains(' ') { line.all_after(' ') } else { '' }
		dispatch_event(mut w, op, rest) or {
			triggered = err.msg()
			break
		}
	}
	if expect_err != '' {
		if triggered == '' {
			// Maybe the error surfaces on close.
			if _ := w.close_get_bytes() {
				return ['expected ${expect_err} but writer produced no error']
			} else {
				triggered = err.msg()
			}
		} else {
			w.writer_close()
		}
		if !triggered.contains(expect_err) {
			return ['expected ${expect_err} in error, got: ${triggered}']
		}
		return []
	}
	// Happy path.
	if triggered != '' {
		w.writer_close()
		return ['unexpected error: ${triggered}']
	}
	out_bytes := w.close_get_bytes() or { return ['close_get_bytes failed: ${err}'] }
	out_str := out_bytes.bytestr()
	mut failures := []string{}
	if has_ok {
		if expect_ok.trim_space() != out_str.trim_space() {
			failures << 'expect_ok mismatch\n  expected:\n${expect_ok}\n  got:\n${out_str}'
		}
	}
	for needle_line in expect_ok_contains.split_into_lines() {
		needle := needle_line.trim_space()
		if needle != '' && !out_str.contains(needle) {
			failures << 'expect_ok_contains: missing ${needle} in output:\n${out_str}'
		}
	}
	return failures
}

fn main() {
	path := if os.args.len > 1 { os.args[1] } else { 'conformance/streaming_write.cxd' }
	cases := fixtures.load_fixtures(path)
	if cases.len == 0 {
		eprintln('no cases loaded from ${path}')
		exit(2)
	}
	mut passed := 0
	mut failed := 0
	for c in cases {
		failures := run_case(c)
		if failures.len == 0 {
			println('PASS ${c.name}')
			passed++
		} else {
			failed++
			println('FAIL ${c.name}')
			for f in failures {
				println('  ${f}')
			}
		}
	}
	println('${path}: ${passed} passed, ${failed} failed')
	if failed > 0 {
		exit(1)
	}
}
