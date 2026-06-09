module main

import cx

// GR-SLICE-STEP-ZERO (formal grammar.ebnf): a slice axis with a LITERAL `0`
// step is rejected at PARSE time with CXER0100, pointing at the `0`. This
// converges the parser to the contract (which makes step-of-zero a parse-layer
// reject); the eval-time D21 check (apply_range_slice) still guards a COMPUTED
// zero step (`[::$n]`, $n==0), which is invisible to the parser.

fn parse_err_code(src string) string {
	cx.parse_program(src) or { return err.msg() }
	return '<accepted>'
}

fn test_slice_step_zero_open_rejected() {
	// `[out $m[::0]]` — the `0` is at byte offset 10.
	msg := parse_err_code('[out \$m[::0]]')
	assert msg.contains('CXER0100'), 'want CXER0100, got: ${msg}'
	assert msg.contains('step'), 'message should name the step: ${msg}'
}

fn test_slice_step_zero_closed_rejected() {
	// `$xs[2:5:0]` — closed range with a literal-zero step.
	msg := parse_err_code('[out \$xs[2:5:0]]')
	assert msg.contains('CXER0100'), 'want CXER0100, got: ${msg}'
}

fn test_slice_step_nonzero_still_parses() {
	// The valid strided / reversed / single-index forms must keep parsing.
	for src in ['[out \$xs[::2]]', '[out \$xs[::-1]]', '[out \$xs[2:5]]', '[out \$xs[*]]'] {
		cx.parse_program(src) or { assert false, 'should parse: ${src} — ${err.msg()}' }
	}
}
