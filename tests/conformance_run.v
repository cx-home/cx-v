module main

import os
import cx

struct Test {
mut:
	name     string
	level    string
	tags     []string
	sections map[string]string
}

fn parse_suite(path string) []Test {
	src := os.read_file(path) or {
		eprintln('could not read suite file: ${path}')
		return []
	}
	mut tests := []Test{}
	mut cur := ?Test(none)
	mut section := ?string(none)
	mut lines_buf := []string{}

	flush_section := fn [mut cur, mut section, mut lines_buf]() {
		if sec := section {
			// strip leading/trailing blank lines
			for lines_buf.len > 0 && lines_buf[0].trim_space() == '' { lines_buf.delete(0) }
			for lines_buf.len > 0 && lines_buf[lines_buf.len-1].trim_space() == '' { lines_buf.delete(lines_buf.len-1) }
			val := lines_buf.join('\n')
			if mut t := cur {
				t.sections[sec] = val
				cur = t
			}
		}
		lines_buf = []string{}
	}

	for raw in src.split_into_lines() {
		if raw.starts_with('=== test:') {
			flush_section()
			if t := cur { tests << t }
			cur = Test{
				name: raw[9..].trim_space()
				sections: map[string]string{}
			}
			section = none
		} else if raw.starts_with('level:') {
			if mut t := cur { t.level = raw[6..].trim_space() }
		} else if raw.starts_with('tags:') {
			if mut t := cur {
				t.tags = raw[5..].trim_space().split_any(' \t')
			}
		} else if raw.starts_with('--- ') {
			flush_section()
			if cur != none { section = raw[4..].trim_space() }
		} else {
			if section != none && cur != none {
				lines_buf << raw
			}
		}
	}
	flush_section()
	if t := cur { tests << t }
	return tests
}

fn run_test(t Test) []string {
	mut failures := []string{}

	input_src, parse_fmt := if 'in_cx' in t.sections {
		t.sections['in_cx'] or { '' }, 'cx'
	} else if 'in_xml' in t.sections {
		t.sections['in_xml'] or { '' }, 'xml'
	} else if 'in_md' in t.sections {
		t.sections['in_md'] or { '' }, 'md'
	} else {
		return failures
	}

	// Parse
	result := if parse_fmt == 'xml' {
		cx.parse_xml_cx(input_src) or {
			failures << 'parse error: ${err}'
			return failures
		}
	} else if parse_fmt == 'md' {
		cx.parse_md_cx(input_src) or {
			failures << 'parse error: ${err}'
			return failures
		}
	} else {
		cx.parse_cx(input_src) or {
			failures << 'parse error: ${err}'
			return failures
		}
	}

	// ── out_ast ───────────────────────────────────────────────────────────────
	if 'out_ast' in t.sections {
		expected_ast := t.sections['out_ast'] or { '' }
		got_json := if result.is_multi {
			docs := result.multi or { [] }
			cx.emit_ast_json_docs(docs)
		} else {
			doc := result.single or { cx.Document{} }
			cx.emit_ast_json(doc)
		}
		if !json_equal(expected_ast, got_json) {
			failures << 'out_ast mismatch\n  expected: ${expected_ast}\n  got:      ${got_json}'
		}
	}

	// ── out_xml ───────────────────────────────────────────────────────────────
	if 'out_xml' in t.sections {
		expected_xml := t.sections['out_xml'] or { '' }
		got_xml := if result.is_multi {
			docs := result.multi or { [] }
			cx.emit_xml_docs(docs)
		} else {
			doc := result.single or { cx.Document{} }
			cx.emit_xml(doc)
		}
		if expected_xml.trim_space() != got_xml.trim_space() {
			failures << 'out_xml mismatch\n  expected:\n${expected_xml}\n  got:\n${got_xml}'
		}
	}

	// ── out_json ──────────────────────────────────────────────────────────────
	if 'out_json' in t.sections {
		expected_json := t.sections['out_json'] or { '' }
		got_json := if result.is_multi {
			docs := result.multi or { [] }
			cx.emit_semantic_json_docs(docs)
		} else {
			doc := result.single or { cx.Document{} }
			cx.emit_semantic_json(doc)
		}
		if !json_equal(expected_json, got_json) {
			failures << 'out_json mismatch\n  expected: ${expected_json}\n  got:      ${got_json}'
		}
	}

	// ── out_cx ────────────────────────────────────────────────────────────────
	if 'out_cx' in t.sections {
		expected_cx := t.sections['out_cx'] or { '' }
		got_cx := if result.is_multi {
			docs := result.multi or { [] }
			cx.emit_cx_docs(docs)
		} else {
			doc := result.single or { cx.Document{} }
			cx.emit_cx(doc)
		}
		if expected_cx.trim_space() != got_cx.trim_space() {
			failures << 'out_cx mismatch\n  expected:\n${expected_cx}\n  got:\n${got_cx}'
		}
	}

	// ── out_md ────────────────────────────────────────────────────────────────
	if 'out_md' in t.sections {
		expected_md := t.sections['out_md'] or { '' }
		got_md := if result.is_multi {
			docs := result.multi or { [] }
			cx.emit_md_docs(docs)
		} else {
			doc := result.single or { cx.Document{} }
			cx.emit_md(doc)
		}
		if expected_md.trim_space() != got_md.trim_space() {
			failures << 'out_md mismatch\n  expected:\n${expected_md}\n  got:\n${got_md}'
		}
	}

	return failures
}

// ── Simple JSON value equality (parse and compare) ────────────────────────────

fn json_equal(a string, b string) bool {
	va := parse_json_val(a.trim_space())
	vb := parse_json_val(b.trim_space())
	return json_vals_equal(va, vb)
}

type JVal = JNull | bool | f64 | string | []JVal | map[string]JVal

struct JNull {}

fn json_vals_equal(a JVal, b JVal) bool {
	return match a {
		JNull    { b is JNull }
		bool     { b is bool && (a as bool) == (b as bool) }
		f64      { b is f64 && (a as f64) == (b as f64) }
		string   { b is string && (a as string) == (b as string) }
		[]JVal   {
			if b !is []JVal { return false }
			ba := b as []JVal
			aa := a as []JVal
			if aa.len != ba.len { return false }
			for i in 0..aa.len {
				if !json_vals_equal(aa[i], ba[i]) { return false }
			}
			true
		}
		map[string]JVal {
			if b !is map[string]JVal { return false }
			am := a as map[string]JVal
			bm := b as map[string]JVal
			if am.len != bm.len { return false }
			for k, v in am {
				bv := bm[k] or { return false }
				if !json_vals_equal(v, bv) { return false }
			}
			true
		}
	}
}

struct JsonReader {
mut:
	src []u8
	pos int
}

fn parse_json_val(src string) JVal {
	mut r := JsonReader{ src: src.bytes(), pos: 0 }
	return r.read_val()
}

fn json_is_ws(b u8) bool {
	return b == ` ` || b == `\t` || b == `\n` || b == `\r`
}

fn (mut r JsonReader) skip_ws() {
	for r.pos < r.src.len && json_is_ws(r.src[r.pos]) { r.pos++ }
}

fn (mut r JsonReader) peek() u8 {
	if r.pos < r.src.len { return r.src[r.pos] }
	return 0
}

fn (mut r JsonReader) read_val() JVal {
	r.skip_ws()
	if r.pos >= r.src.len { return JVal(JNull{}) }
	b := r.peek()
	return match b {
		`"` { r.read_json_str() }
		`{` { r.read_json_obj() }
		`[` { r.read_json_arr() }
		`t` { r.pos += 4; JVal(true) }
		`f` { r.pos += 5; JVal(false) }
		`n` { r.pos += 4; JVal(JNull{}) }
		else { r.read_json_num() }
	}
}

fn (mut r JsonReader) read_json_str() JVal {
	r.pos++ // '"'
	mut s := []u8{}
	for r.pos < r.src.len {
		b := r.src[r.pos]
		if b == `"` { r.pos++; break }
		if b == `\\` {
			r.pos++
			if r.pos < r.src.len {
				esc := r.src[r.pos]
				r.pos++
				match esc {
					`n` { s << `\n` }
					`r` { s << `\r` }
					`t` { s << `\t` }
					`"` { s << `"` }
					`\\` { s << `\\` }
					else { s << `\\`; s << esc }
				}
			}
		} else {
			s << b
			r.pos++
		}
	}
	return JVal(s.bytestr())
}

fn (mut r JsonReader) read_json_obj() JVal {
	r.pos++ // '{'
	mut obj := map[string]JVal{}
	r.skip_ws()
	if r.pos < r.src.len && r.peek() == `}` { r.pos++; return JVal(obj) }
	for r.pos < r.src.len {
		r.skip_ws()
		key_val := r.read_val()
		key := if key_val is string { key_val as string } else { '' }
		r.skip_ws()
		if r.peek() == `:` { r.pos++ }
		val := r.read_val()
		obj[key] = val
		r.skip_ws()
		if r.peek() == `,` { r.pos++; continue }
		if r.peek() == `}` { r.pos++; break }
		break
	}
	return JVal(obj)
}

fn (mut r JsonReader) read_json_arr() JVal {
	r.pos++ // '['
	mut arr := []JVal{}
	r.skip_ws()
	if r.pos < r.src.len && r.peek() == `]` { r.pos++; return JVal(arr) }
	for r.pos < r.src.len {
		val := r.read_val()
		arr << val
		r.skip_ws()
		if r.peek() == `,` { r.pos++; continue }
		if r.peek() == `]` { r.pos++; break }
		break
	}
	return JVal(arr)
}

fn (mut r JsonReader) read_json_num() JVal {
	mut s := []u8{}
	for r.pos < r.src.len {
		b := r.src[r.pos]
		if b == `,` || b == `}` || b == `]` || json_is_ws(b) { break }
		s << b
		r.pos++
	}
	num_str := s.bytestr()
	if num_str == 'null' { return JVal(JNull{}) }
	if num_str == 'true' { return JVal(true) }
	if num_str == 'false' { return JVal(false) }
	// try as float
	fv := num_str.f64()
	if fv != 0.0 || num_str == '0' || num_str == '0.0' {
		return JVal(fv)
	}
	return JVal(f64(0))
}

// ── Test runner ───────────────────────────────────────────────────────────────

fn run_suite(path string) bool {
	tests := parse_suite(path)
	mut pass := 0
	mut fail := 0

	for t in tests {
		failures := run_test(t)
		if failures.len == 0 {
			pass++
			println('PASS ${t.name}')
		} else {
			fail++
			println('FAIL ${t.name}')
			for f in failures { println('     ${f}') }
		}
	}
	println('${path}: ${pass} passed, ${fail} failed')
	return fail == 0
}

fn main() {
	args := os.args[1..]

	// Default: run all suites
	suites := if args.len > 0 {
		args
	} else {
		[
			'../conformance/core.txt',
			'../conformance/extended.txt',
			'../conformance/xml.txt',
			'../conformance/md.txt',
		]
	}

	mut all_pass := true
	for suite in suites {
		if !run_suite(suite) { all_pass = false }
	}

	if !all_pass { exit(1) }
}
