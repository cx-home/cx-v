module code

import cx

// program_fmt_test.v — #118 regression gate: code.fmt_source must NEVER rewrite
// a PROGRAM through the data emitter (the silent data-loss-on-save bug), must
// format DATA losslessly, and must be fail-closed (never emit a meaning-changing
// surface). This is the round-trip gate the data-only idempotence check missed.

const prog_118 = '[?lib \'cx-stdlib/store\' :as store]\n[?let\n  [= \$c [\$store:open "mem://"]]\n  [= \$h [\$store:put-doc \$c [note [body "hi"]]]]\n  \$h]'

fn test_program_not_data_corrupted() {
	out := fmt_source(prog_118) or { panic('fmt_source errored on a valid program: ${err}') }
	// the data-mangled `[('= …)]` sequence form must NEVER appear.
	assert !out.contains("[('"), 'program was data-corrupted:\n${out}'
	// the output must still parse as a program AND mean the same thing as the
	// input (compared via the position-free canonical program form).
	cf_in := program_node_to_source(cx.parse_program(prog_118) or { panic(err) }.body)
	cf_out := program_node_to_source(cx.parse_program(out) or {
		panic('fmt output no longer parses as a program: ${err}')
	}.body)
	assert cf_in == cf_out, 'fmt changed the program meaning:\nIN  ${cf_in}\nOUT ${cf_out}'
}

fn test_program_fmt_idempotent() {
	a := fmt_source(prog_118) or { panic(err) }
	b := fmt_source(a) or { panic(err) }
	assert a == b, 'fmt_source(fmt_source(program)) != fmt_source(program)'
}

fn test_data_formats_losslessly() {
	src := '[note [body "x"] [n 1]]'
	out := fmt_source(src) or { panic('fmt_source errored on data: ${err}') }
	assert out.contains('[note'), out
	assert !out.contains("[('"), out
	// lossless as data: re-parses to the same data tree.
	d1 := cx.parse(src) or { panic(err) }
	d2 := cx.parse(out) or { panic('formatted data no longer parses: ${err}') }
	assert cx.emit_cx(d1) == cx.emit_cx(d2), 'data fmt was not lossless'
}

fn test_config_data_formats() {
	src := '[cxstore-service [bind addr="127.0.0.1:7800"] [stores [store name="t" url="mem://x"]]]'
	out := fmt_source(src) or { panic('fmt_source errored on config: ${err}') }
	assert out.contains('[cxstore-service'), out
	assert !out.contains("[('"), out
}

fn test_data_with_url_and_slashes_formats() {
	// data containing `//` (URLs) and `:` atoms must still format, not error
	// (these are NOT program surface — the earlier naive token-scan broke here).
	src := '[store [url "http://h//p"] [alt "mem://x"]]'
	out := fmt_source(src) or { panic('fmt_source errored on url data: ${err}') }
	assert out.contains('[store'), out
}
