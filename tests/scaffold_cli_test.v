module main

import os
import testenv

// #448 — `cx scaffold <kind>` must emit CURRENT-surface CX for every kind.
//
// The retired single-colon type annotations (`port:u16=8080`,
// `[date :date …]`) parse on the current surface as namespace-qualified
// names (lexicon.ebnf [L50]/[L51]): `cx scaffold config | cx --json` showed
// a `"port:u16"` KEY instead of a u16-typed `port` — on the tool whose demo
// advertises exactly that pipeline to newcomers. These lanes drive the BUILT
// BINARY over every scaffold kind and assert (a) the output parses and
// round-trips (`--json`, `canonical`, `eq` self), (b) no retired surface
// pattern survives in the emitted text, and (c) a per-kind semantic probe
// (typed port / decimal price / ::date element / logfmt events / table
// info). AST-level assertions on the template constants live in
// vcx/cmd/scaffold_test.v.

const scaffold_kinds = ['config', 'data', 'doc', 'log', 'table']

fn cx_bin() string {
	return testenv.cx_bin()
}

fn scaffold_out(kind string) string {
	r := os.execute('${cx_bin()} scaffold ${kind}')
	assert r.exit_code == 0, 'cx scaffold ${kind} exited ${r.exit_code}: ${r.output}'
	assert r.output.len > 0, 'cx scaffold ${kind} emitted nothing'
	return r.output
}

fn tmp_scaffold_file(kind string) string {
	path := os.join_path(os.temp_dir(), 'cx_scaffold_${kind}_${os.getpid()}.cx')
	os.write_file(path, scaffold_out(kind)) or { panic(err) }
	return path
}

// Scalar type names that the RETIRED single-colon annotation could glue.
// Current surface glues types with a DOUBLE colon (`::u16`); a single glued
// colon is the namespace qualifier.
const retired_glued_types = ['u8', 'u16', 'u32', 'u64', 'i8', 'i16', 'i32', 'i64', 'f16', 'f32',
	'f64', 'int', 'float', 'bool', 'decimal', 'bigint', 'date', 'datetime', 'time', 'atom',
	'bytes', 'string', 'null']

// first_single_colon_type returns the first retired single-colon type
// annotation (`name:type=…`, `[name :type …]`) found in src, or none.
// A `::` never matches: the first colon is skipped because the NEXT char is
// a colon, the second because the PREVIOUS char is one.
fn first_single_colon_type(src string) ?string {
	for i := 0; i < src.len; i++ {
		if src[i] != `:` {
			continue
		}
		if i > 0 && src[i - 1] == `:` {
			continue
		}
		if i + 1 < src.len && src[i + 1] == `:` {
			continue
		}
		rest := src[i + 1..]
		for t in retired_glued_types {
			if !rest.starts_with(t) {
				continue
			}
			j := i + 1 + t.len
			if j >= src.len {
				return src[i..]
			}
			nc := src[j]
			if nc == `=` || nc == ` ` || nc == `]` || nc == `[` || nc == `\n` {
				return src[i..j]
			}
		}
	}
	return none
}

// ── (a) every kind parses and round-trips through the same binary ────────────

fn test_every_kind_parses_and_round_trips() {
	for kind in scaffold_kinds {
		f := tmp_scaffold_file(kind)
		j := os.execute('${cx_bin()} --json ${f}')
		assert j.exit_code == 0, 'cx --json on scaffold ${kind} exited ${j.exit_code}: ${j.output}'
		c := os.execute('${cx_bin()} canonical ${f}')
		assert c.exit_code == 0, 'cx canonical on scaffold ${kind} exited ${c.exit_code}: ${c.output}'
		e := os.execute('${cx_bin()} eq ${f} ${f}')
		assert e.exit_code == 0, 'cx eq self on scaffold ${kind} exited ${e.exit_code}: ${e.output}'
		os.rm(f) or {}
	}
}

// ── (b) no retired surface pattern in the emitted text ───────────────────────

fn test_every_kind_emits_no_retired_surface() {
	for kind in scaffold_kinds {
		out := scaffold_out(kind)
		assert !out.contains(':table['), 'cx scaffold ${kind} emits the retired :table[ block form'
		if hit := first_single_colon_type(out) {
			assert false, 'cx scaffold ${kind} emits a retired single-colon type annotation: `${hit}` (current surface glues types with `::`)'
		}
	}
}

// ── (c) per-kind semantic probes ──────────────────────────────────────────────

fn test_config_semantics() {
	f := tmp_scaffold_file('config')
	defer {
		os.rm(f) or {}
	}
	c := os.execute('${cx_bin()} canonical ${f}')
	assert c.exit_code == 0, c.output
	assert c.output.contains('port::u16=8080'), 'canonical config lost the typed port: ${c.output}'
	assert c.output.contains('pool_size::u8=16'), 'canonical config lost the typed pool_size: ${c.output}'
	assert c.output.contains('connect_timeout_ms::u32=5000'), 'canonical config lost the typed connect_timeout_ms: ${c.output}'
	assert c.output.contains('env=dev'), 'canonical config lost the env attribute: ${c.output}'
	assert !c.output.contains("' env=dev '"), 'env=dev mis-parsed as a TEXT child instead of an attribute: ${c.output}'
	j := os.execute('${cx_bin()} --json ${f}')
	assert j.exit_code == 0, j.output
	assert !j.output.contains('port:u16'), 'JSON view shows a namespace-qualified "port:u16" key: ${j.output}'
	assert j.output.contains('8080'), 'JSON view lost the port value: ${j.output}'
}

fn test_data_semantics() {
	f := tmp_scaffold_file('data')
	defer {
		os.rm(f) or {}
	}
	c := os.execute('${cx_bin()} canonical ${f}')
	assert c.exit_code == 0, c.output
	assert c.output.contains('price::decimal=12.50'), 'canonical data lost the typed decimal price: ${c.output}'
	j := os.execute('${cx_bin()} --json ${f}')
	assert j.exit_code == 0, j.output
	assert !j.output.contains('price:decimal'), 'JSON view shows a namespace-qualified "price:decimal" key: ${j.output}'
	// decimal converts to a JSON STRING (precision-preserving, conversions.md)
	assert j.output.contains('"12.50"'), 'JSON view lost the decimal price (expected precision-preserving "12.50"): ${j.output}'
}

fn test_doc_semantics() {
	f := tmp_scaffold_file('doc')
	defer {
		os.rm(f) or {}
	}
	c := os.execute('${cx_bin()} canonical ${f}')
	assert c.exit_code == 0, c.output
	assert c.output.contains('[date::date 2026-05-12]'), 'canonical doc lost the ::date element type: ${c.output}'
	j := os.execute('${cx_bin()} --json ${f}')
	assert j.exit_code == 0, j.output
	assert !j.output.contains('":date"'), 'JSON view shows the retired ` :date ` annotation as a child token: ${j.output}'
	assert j.output.contains('2026-05-12'), 'JSON view lost the date value: ${j.output}'
}

fn test_log_semantics() {
	f := tmp_scaffold_file('log')
	defer {
		os.rm(f) or {}
	}
	c := os.execute('${cx_bin()} canonical ${f}')
	assert c.exit_code == 0, c.output
	assert c.output.contains('level=info'), 'canonical log lost the logfmt attributes: ${c.output}'
	assert c.output.contains("err='connection refused'"), 'canonical log lost the quoted err value: ${c.output}'
}

fn test_table_semantics() {
	f := tmp_scaffold_file('table')
	defer {
		os.rm(f) or {}
	}
	r := os.execute('${cx_bin()} table info ${f}')
	assert r.exit_code == 0, 'cx table info on its own scaffold exited ${r.exit_code}: ${r.output}'
	assert r.output.contains('rows: 3'), r.output
	assert r.output.contains('cols: 5'), r.output
}
