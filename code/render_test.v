module code

import cx

// render_test.v — unit tests for render_element_to / render_attr_value_to.
// Gate: attribute values that contain `"` must survive round-trip without
// breaking the surrounding quotes (Bug A fix: route through choose_render_quote).

fn test_attr_value_with_embedded_double_quote_uses_single_quote() {
	// Value contains a `"` character — the renderer must pick single-quote
	// wrapping, not the broken `"value with "quotes""` form.
	el := cx.Element{
		name:  'row'
		attrs: [cx.Attribute{ name: 'notes', value: cx.ScalarValue('value with "embedded" quotes') }]
		items: []
	}
	got := render_element(el)
	// The rendered form must NOT contain `"value with` (which would mean a
	// raw double-quote wrap starting at the embedded double-quote boundary).
	// It must contain the single-quoted form instead.
	assert got.contains("'value with \"embedded\" quotes'"),
		'expected single-quoted attr value, got: ${got}'
	assert !got.starts_with('[row notes="value with'),
		'double-quote wrap would break re-parse, got: ${got}'
}

fn test_attr_value_plain_string_round_trips() {
	// Plain value (no special chars) still renders as bare unquoted form.
	el := cx.Element{
		name:  'item'
		attrs: [cx.Attribute{ name: 'id', value: cx.ScalarValue('abc') }]
		items: []
	}
	got := render_element(el)
	assert got == '[item id=abc]', 'expected bare unquoted attr, got: ${got}'
}

fn test_attr_value_with_spaces_uses_single_quote() {
	// Value with spaces but no `'` — single-quoted (the default quoting
	// form per spec/core/canonical.md §2.3; single is preferred over double).
	el := cx.Element{
		name:  'p'
		attrs: [cx.Attribute{ name: 'class', value: cx.ScalarValue('foo bar') }]
		items: []
	}
	got := render_element(el)
	assert got == "[p class='foo bar']", 'expected single-quoted attr, got: ${got}'
}

fn test_attr_value_with_both_quote_styles_uses_single_escaped() {
	// Value with both `"` and `'` — single-quoted with `\'` escape (the
	// §2.3 line 130 tiebreak; the `"` needs no escape inside `'…'`).
	// Triple-quoting is multiline-only, NOT an escape-avoidance device.
	el := cx.Element{
		name:  'x'
		attrs: [cx.Attribute{ name: 'v', value: cx.ScalarValue("it's a \"test\"") }]
		items: []
	}
	got := render_element(el)
	assert got == '[x v=\'it\\\'s a "test"\']', 'expected single-escaped attr, got: ${got}'
}
