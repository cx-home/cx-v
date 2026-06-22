module main

import code
import cx

// v08_underscore_name_test — cluster 5 (NAME-RULE) of the parser-parity
// convergence. This is the ONE cluster where code.parse is spec-faithful and
// cx.parse is the bug: [6] NameStartChar INCLUDES `_`, so `_private` is a
// valid element name. cx.parse historically rejected `_`-leading heads
// (routing them to the `[__ …]` markdown-underline shorthand). Fix: only the
// double-underscore form `[__ body]` is the underline shorthand; everything
// else is a regular element name.

fn cx_render(src string) string {
	doc := cx.parse(src) or { return 'REJECT: ${err}' }
	if doc.elements.len != 1 {
		return 'REJECT: ${doc.elements.len} elements'
	}
	return code.render_canonical(doc.elements[0])
}

fn test_underscore_leading_name_accepted() {
	assert cx_render('[_private 1]') == '[_private 1]'
}

fn test_bare_underscore_name() {
	assert cx_render('[_ 1]') == '[_ 1]'
}

fn test_underscore_name_with_children() {
	assert cx_render('[_internal [_field 2]]') == '[_internal [_field 2]]'
}

fn test_double_underscore_is_plain_element() {
	// D-B (markdown removed): the former `[__ body]` underline shorthand is
	// gone. `__` is an ordinary element name ([6] NameStartChar includes `_`),
	// so `[__ hello]` is the element `__` with text child `hello` — no <u>.
	doc := cx.parse('[__ hello]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert doc.elements.len == 1
	el := doc.elements[0]
	if el is cx.Element {
		assert el.name == '__', 'expected element __, got ${el.name}'
	} else {
		assert false, 'expected Element'
	}
}

fn test_underscore_parity_with_code() {
	cx_out := cx_render('[_private 1]')
	n := code.program_parse_to_typed_node('[_private 1]') or {
		assert false, 'code parse failed: ${err}'
		return
	}
	code_out := code.render_canonical(n)
	assert cx_out == code_out, 'cx=${cx_out} code=${code_out}'
}
