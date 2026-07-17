// module_scan_string_literal_test.v — issue #260: the module pre-scan
// (module_loader_scan_directives, the pass the §1.2 exports gate shares)
// must agree with the real lexer about string literals. A lone `[` or `]`
// inside a quoted string must not shift bracket balance — historically a
// def body containing "[err " swallowed every later [?def], so pkg-verify
// raised CXER4884 for defs that plainly exist.
module main

import code

// The directive struct's fields are module-private; the defect (#260) is a
// COUNT defect — a string literal swallowing brackets makes every later
// [?def] vanish from the scan — so counting recognised directives is the
// full assertion. Each source below contains exactly two defs.
fn scan_count(src string) int {
	directives := code.module_loader_scan_directives(src) or { return -1 }
	return directives.len
}

fn test_lone_open_bracket_in_double_quoted_string() {
	src := '[?def is-err (\$x) [\$s:starts-with [\$cx:emit \$x] "[err "]]\n' +
		'[?def readout scope=public impure (\$store \$t) [\$concat "" \$t]]\n'
	assert scan_count(src) == 2
}

fn test_lone_open_bracket_in_single_quoted_string() {
	src := "[?def pfx (\$_) '[err ']\n[?def second (\$_) 1]\n"
	assert scan_count(src) == 2
}

fn test_lone_close_bracket_in_string() {
	src := '[?def sfx (\$_) "] tail"]\n[?def third (\$_) 2]\n'
	assert scan_count(src) == 2
}

fn test_escaped_quote_inside_string() {
	src := '[?def esc (\$_) "a \\" [ b"]\n[?def fourth (\$_) 3]\n'
	assert scan_count(src) == 2
}
