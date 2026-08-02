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

// #620: a TextNode in ITEM position (map row value / sequence / array entry)
// renders with the same round-trip quoting rule as element bodies — bare text
// that would auto-type or split must quote, bare-safe names stay bare. The
// observed defect: journal-replayed records (whose fields are data-parsed
// TextNodes) rendered `n: 5` where the live lane rendered `n: '5'` — a silent
// type flip on re-import, violating the #587/#618 lane-parity invariant.
fn test_map_row_text_item_quotes_for_round_trip() {
	rec := cx.Element{
		name:  '__cx_map__'
		items: [
			cx.Node(cx.Element{ name: 'actor', items: [cx.Node(cx.TextNode{ value: 'u' })] }),
			cx.Node(cx.Element{ name: 'n', items: [cx.Node(cx.TextNode{ value: '5' })] }),
			cx.Node(cx.Element{ name: 's', items: [
				cx.Node(cx.ScalarNode{ value: cx.ScalarValue('5'), data_type: cx.ScalarType.string_type }),
			] }),
		]
	}
	got := render_canonical(rec)
	// bare-safe text stays bare; auto-typing text quotes; and the TextNode
	// renders IDENTICALLY to the equal string scalar (lane parity).
	assert got == "{actor: u, n: '5', s: '5'}", 'map-row text quoting wrong: ${got}'
}

fn test_sequence_text_item_quotes_for_round_trip() {
	seq := cx.Element{
		name:  '__cx_seq__'
		items: [
			cx.Node(cx.TextNode{ value: 'plain' }),
			cx.Node(cx.TextNode{ value: '42' }),
			cx.Node(cx.TextNode{ value: 'two words' }),
		]
	}
	got := render_canonical(seq)
	assert got == "(plain, '42', 'two words')", 'sequence text quoting wrong: ${got}'
}
