module main

import os
import cx
import arrow

// CXCol ↔ Apache Arrow C-Data ABI conformance runner.
//
// Reads a fixture suite (default: ../conformance/data_bin_arrow.txt)
// and exercises round-trip identity through libcx_arrow's export +
// import paths, + spec/abi.md §2.11.
//
// Round-trip rather than byte-equality is the verification model:
// Arrow's binary form isn't stable across versions, so we compare
// CXCol-decoded structural content (every value listed in
// `expect_values` must appear in both the input and the
// round-tripped output, after re-parse + emit_cx).
//
// Optional assertions:
//   --- arrow_children_formats   per-column Arrow format strings,
//                                one per line ('l', 'tdD', etc.)
//   --- arrow_chunk_lengths      per-chunk row counts emitted by
//                                the export stream, one per line
//   --- expected_export_error    substring of the error returned by
//                                arrow.round_trip_cxcol (negative case)
//
// The runner separates from conformance_run.v because it imports
// the `arrow` module, which requires `-enable-globals` at build
// time (module-level registry state). Keeping the core conformance
// runner Arrow-free preserves its simpler build invocation.

struct Test {
mut:
	name     string
	level    string
	tags     []string
	pending  string
	chunk_at int = 1 << 20
	sections map[string]string
}

// strip_blank_edges reproduces the former flush() normalization: drop
// leading/trailing BLANK lines from a section body, applied to the loader's
// byte-exact body so the runner sees byte-identical sections vs the old .txt.
fn strip_blank_edges(s string) string {
	mut lines := s.split('\n')
	for lines.len > 0 && lines[0].trim_space() == '' { lines.delete(0) }
	for lines.len > 0 && lines[lines.len - 1].trim_space() == '' { lines.delete(lines.len - 1) }
	return lines.join('\n')
}

// parse_suite loads a .cxd conformance suite via cx.load_fixtures, replacing
// the bespoke `=== test:` / `--- key` scanner. pending + chunk_at come from
// the [meta] block; level/tags from the case attr / [tags] element.
fn parse_suite(path string) []Test {
	mut tests := []Test{}
	for c in cx.load_fixtures(path) {
		mut t := Test{
			name:     c.name
			level:    c.level
			tags:     c.tags
			pending:  c.meta['pending'] or { '' }
			sections: map[string]string{}
		}
		if 'chunk_at' in c.meta {
			t.chunk_at = (c.meta['chunk_at'] or { '' }).int()
			if t.chunk_at <= 0 { t.chunk_at = 1 << 20 }
		}
		for k, v in c.sections {
			t.sections[k] = strip_blank_edges(v)
		}
		tests << t
	}
	return tests
}

fn split_nonempty_lines(s string) []string {
	mut out := []string{}
	for line in s.split_into_lines() {
		// Strip line-tail comments after `# ` (matches conformance_run.v
		// hex helper convention) but NOT bare `#` so that fixtures can
		// embed values like `#FF00DE` if ever needed.
		mut l := line
		if hash := l.index(' #') {
			l = l[..hash]
		}
		t := l.trim_space()
		if t.len > 0 {
			out << t
		}
	}
	return out
}

fn run_test(t Test) []string {
	mut failures := []string{}

	in_cx := t.sections['in_cx'] or { '' }
	if in_cx.trim_space() == '' {
		failures << 'in_cx section missing or empty'
		return failures
	}

	// Parse + emit chunked CXCol.
	parse_res := cx.parse_cx(in_cx) or {
		failures << 'parse error: ${err}'
		return failures
	}
	doc := if parse_res.is_multi {
		docs := parse_res.multi or { [] }
		if docs.len > 0 { docs[0] } else { cx.Document{} }
	} else {
		parse_res.single or { cx.Document{} }
	}
	opts := cx.ChunkedEmitOptions{ chunk_size: t.chunk_at, compress: .never }
	bytes_in := cx.emit_data_bin_chunked(doc, opts) or {
		failures << 'emit_data_bin_chunked error: ${err}'
		return failures
	}

	// Negative-test path: round_trip_cxcol (or its export side) must
	// surface an error containing the expected substring.
	if 'expected_export_error' in t.sections {
		expected := (t.sections['expected_export_error'] or { '' }).trim_space()
		_ := arrow.round_trip_cxcol(bytes_in) or {
			if expected != '' && err.msg().contains(expected) {
				return failures
			}
			failures << 'expected_export_error: got "${err.msg()}", expected substring "${expected}"'
			return failures
		}
		failures << 'expected_export_error: round-trip succeeded; expected substring "${expected}"'
		return failures
	}

	// Optional schema check (decode-side, non-destructive — uses a
	// fresh stream).
	if 'arrow_children_formats' in t.sections {
		want := split_nonempty_lines(t.sections['arrow_children_formats'] or { '' })
		got := arrow.schema_formats(bytes_in) or {
			failures << 'schema_formats error: ${err}'
			return failures
		}
		if got.len != want.len {
			failures << 'arrow_children_formats: got ${got.len} columns, want ${want.len} (got=${got}; want=${want})'
		} else {
			for i in 0 .. want.len {
				if got[i] != want[i] {
					failures << 'arrow_children_formats[${i}]: got "${got[i]}", want "${want[i]}"'
				}
			}
		}
	}

	// Optional chunk-length check (uses a fresh stream).
	if 'arrow_chunk_lengths' in t.sections {
		want_strs := split_nonempty_lines(t.sections['arrow_chunk_lengths'] or { '' })
		mut want := []int{cap: want_strs.len}
		for s in want_strs {
			want << s.int()
		}
		got := arrow.chunk_lengths(bytes_in) or {
			failures << 'chunk_lengths error: ${err}'
			return failures
		}
		if got.len != want.len {
			failures << 'arrow_chunk_lengths: got ${got.len} chunks, want ${want.len} (got=${got}; want=${want})'
		} else {
			for i in 0 .. want.len {
				if got[i] != want[i] {
					failures << 'arrow_chunk_lengths[${i}]: got ${got[i]}, want ${want[i]}'
				}
			}
		}
	}

	// Round-trip identity assertion.
	bytes_out := arrow.round_trip_cxcol(bytes_in) or {
		failures << 'round_trip_cxcol error: ${err}'
		return failures
	}

	// Re-parse both sides through parse_data_bin and compare against
	// `expect_values` if supplied. The chunked-streaming path drops
	// the outer single-pair-map wrapper (writer doesn't preserve the
	// table's element name), so byte-equality is too strict; the
	// per-value contains check matches the V-side arrow_test.v
	// pattern.
	doc_in_again := cx.parse_data_bin(bytes_in) or {
		failures << 'parse_data_bin(bytes_in) error: ${err}'
		return failures
	}
	doc_out := cx.parse_data_bin(bytes_out) or {
		failures << 'parse_data_bin(bytes_out) error: ${err}'
		return failures
	}
	txt_in := cx.emit_cx(doc_in_again)
	txt_out := cx.emit_cx(doc_out)

	if 'expect_values' in t.sections {
		needles := split_nonempty_lines(t.sections['expect_values'] or { '' })
		for needle in needles {
			if !txt_in.contains(needle) {
				failures << 'expect_values: txt_in missing "${needle}"\n  txt_in=${txt_in}'
			}
			if !txt_out.contains(needle) {
				failures << 'expect_values: txt_out missing "${needle}"\n  txt_out=${txt_out}'
			}
		}
	}

	return failures
}

fn run_suite(path string) bool {
	tests := parse_suite(path)
	mut pass := 0
	mut fail := 0
	mut skip := 0
	for t in tests {
		if t.pending != '' {
			skip++
			println('SKIP ${t.name} (pending: ${t.pending})')
			continue
		}
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
	println('${path}: ${pass} passed, ${fail} failed, ${skip} skipped')
	return fail == 0
}

fn main() {
	args := os.args[1..]
	suites := if args.len > 0 {
		args
	} else {
		['../conformance/data_bin_arrow.cxd']
	}
	mut all_pass := true
	for suite in suites {
		if !run_suite(suite) { all_pass = false }
	}
	if !all_pass { exit(1) }
}
