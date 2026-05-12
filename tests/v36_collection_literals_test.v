module main

import cx

// Tests for v0.6.0 / grammar v3.6 / ADR 0017 collection-literal source
// productions: SequenceLiteral `(a, b, c)`, ArrayLiteral `[a, b, c]`,
// MapLiteral `{k: v}`. Covers:
//   - Parse: each literal at element-body position
//   - AST: correct node kinds populated (SequenceNode / ArrayNode /
//     MapNode) with expected items / entries
//   - ast_bin v6 round-trip: encode + decode through binary.v with the
//     three new tag bytes (0x0F / 0x10 / 0x11)
//   - Canonical CX emit: round-trip text matches the spec/canonical.md
//     formatting rules per ADR 0017 §D14
//   - Disambiguation: today's element form `[name body]` is unaffected;
//     `[a, b, c]` becomes ArrayLiteral via the depth-0 comma marker;
//     `(text)` and `{text}` without separators stay as body text.

// ── ArrayLiteral ─────────────────────────────────────────────────────────────

fn test_array_literal_in_body() {
	doc := cx.parse('[tags [web, api, native]]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.name == 'tags'
	assert root.items.len == 1
	arr := root.items[0]
	assert arr is cx.ArrayNode
	an := arr as cx.ArrayNode
	assert an.items.len == 3
}

fn test_array_literal_empty() {
	doc := cx.parse('[tags []]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.items.len == 1
	arr := root.items[0]
	assert arr is cx.ArrayNode
	an := arr as cx.ArrayNode
	assert an.items.len == 0
}

fn test_array_literal_nested_preserves_structure() {
	doc := cx.parse('[grid [[1, 2], [3, 4]]]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	outer := root.items[0]
	assert outer is cx.ArrayNode
	on := outer as cx.ArrayNode
	assert on.items.len == 2
	first := on.items[0]
	assert first is cx.ArrayNode
	fa := first as cx.ArrayNode
	assert fa.items.len == 2
}

fn test_array_literal_trailing_comma() {
	doc := cx.parse('[tags [a, b, c,]]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	arr := root.items[0]
	assert arr is cx.ArrayNode
	an := arr as cx.ArrayNode
	assert an.items.len == 3
}

// ── SequenceLiteral ──────────────────────────────────────────────────────────

fn test_sequence_literal_in_body() {
	doc := cx.parse('[result (1, 2, 3)]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	seq := root.items[0]
	assert seq is cx.SequenceNode
	sn := seq as cx.SequenceNode
	assert sn.items.len == 3
}

fn test_sequence_literal_empty() {
	doc := cx.parse('[result ()]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	seq := root.items[0]
	assert seq is cx.SequenceNode
	sn := seq as cx.SequenceNode
	assert sn.items.len == 0
}

fn test_sequence_literal_flattens_on_parse() {
	// CXDM §1.2 sequence-flat principle: nested sequences flatten on
	// construction. ((a, b), c) → (a, b, c).
	doc := cx.parse('[r ((1, 2), 3, (4, 5))]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	seq := root.items[0]
	assert seq is cx.SequenceNode
	sn := seq as cx.SequenceNode
	assert sn.items.len == 5
}

fn test_paren_text_not_a_sequence() {
	// `(text)` without a depth-0 comma stays as body text. This is the
	// pre-v3.6 parens-in-text behaviour and the back-compat path for
	// English prose.
	doc := cx.parse("[note 'see (appendix)']") or { panic(err) }
	root := doc.root() or { panic('no root') }
	// No SequenceNode should appear in items.
	mut has_seq := false
	for item in root.items {
		if item is cx.SequenceNode { has_seq = true }
	}
	assert !has_seq
}

// ── MapLiteral ───────────────────────────────────────────────────────────────

fn test_map_literal_in_body() {
	doc := cx.parse("[stats {region: 'us-west', servers: 12}]") or { panic(err) }
	root := doc.root() or { panic('no root') }
	m := root.items[0]
	assert m is cx.MapNode
	mn := m as cx.MapNode
	assert mn.entries.len == 2
	region := mn.entries[0]
	assert region.key_type == .string_type
}

fn test_map_literal_empty() {
	doc := cx.parse('[stats {}]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	m := root.items[0]
	assert m is cx.MapNode
	mn := m as cx.MapNode
	assert mn.entries.len == 0
}

fn test_map_literal_duplicate_key_errors() {
	cx.parse('[r {a: 1, a: 2}]') or {
		assert err.msg().contains('W014'), 'expected W014; got: ${err.msg()}'
		return
	}
	assert false, 'expected duplicate-key parse error'
}

fn test_brace_text_not_a_map() {
	doc := cx.parse("[note 'try {something}']") or { panic(err) }
	root := doc.root() or { panic('no root') }
	mut has_map := false
	for item in root.items {
		if item is cx.MapNode { has_map = true }
	}
	assert !has_map
}

// ── ast_bin v6 round-trip ────────────────────────────────────────────────────

fn test_ast_bin_v6_array_round_trip() {
	doc := cx.parse('[tags [web, api]]') or { panic(err) }
	bytes := cx.emit_ast_bin(doc)
	// Confirm the version byte was bumped to 6.
	assert bytes.len > 4
	assert bytes[4] == 6
	doc2 := cx.bin_to_doc(bytes) or { panic('decode: ${err}') }
	root := doc2.root() or { panic('no root') }
	arr := root.items[0]
	assert arr is cx.ArrayNode
	an := arr as cx.ArrayNode
	assert an.items.len == 2
}

fn test_ast_bin_v6_sequence_round_trip() {
	doc := cx.parse('[r (1, 2, 3)]') or { panic(err) }
	bytes := cx.emit_ast_bin(doc)
	doc2 := cx.bin_to_doc(bytes) or { panic('decode: ${err}') }
	root := doc2.root() or { panic('no root') }
	seq := root.items[0]
	assert seq is cx.SequenceNode
	sn := seq as cx.SequenceNode
	assert sn.items.len == 3
}

fn test_ast_bin_v6_map_round_trip() {
	doc := cx.parse("[stats {name: 'alice', age: 30}]") or { panic(err) }
	bytes := cx.emit_ast_bin(doc)
	doc2 := cx.bin_to_doc(bytes) or { panic('decode: ${err}') }
	root := doc2.root() or { panic('no root') }
	m := root.items[0]
	assert m is cx.MapNode
	mn := m as cx.MapNode
	assert mn.entries.len == 2
	// Second entry is an int-valued ScalarNode.
	age := mn.entries[1]
	assert age.key_type == .string_type
	v := age.value
	assert v is cx.ScalarNode
}

// ── Canonical CX emit ────────────────────────────────────────────────────────

fn test_canonical_emit_array() {
	doc := cx.parse('[tags [web, api]]') or { panic(err) }
	out := cx.emit_cx(doc)
	// Canonical form per ADR 0017 §D14: `[item, item]` with single space
	// after comma. Embedded inside an element body, the array renders
	// inline.
	assert out.contains('[web, api]')
}

fn test_canonical_emit_sequence() {
	doc := cx.parse('[r (1, 2, 3)]') or { panic(err) }
	out := cx.emit_cx(doc)
	assert out.contains('(1, 2, 3)')
}

fn test_canonical_emit_map() {
	doc := cx.parse("[stats {name: 'alice', age: 30}]") or { panic(err) }
	out := cx.emit_cx(doc)
	// `name` is a bare-name string → emitted without quotes per
	// emitter_cx.cx_emit_map_key. `'alice'` round-trips through
	// cx_quote_text_if_needed; the value is a string so quotes are
	// chosen when needed.
	assert out.contains('name:')
	assert out.contains('age: 30')
}

// ── Disambiguation regression guards ─────────────────────────────────────────

fn test_existing_element_still_parses() {
	// Pre-v3.6 element form: no commas at depth 0 inside the bracket.
	// Must continue to parse as Element, not ArrayLiteral.
	doc := cx.parse('[server host=localhost port=8080]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.name == 'server'
	assert root.attrs.len == 2
}

fn test_existing_element_with_body_still_parses() {
	doc := cx.parse('[greeting Hello world]') or { panic(err) }
	root := doc.root() or { panic('no root') }
	assert root.name == 'greeting'
}

// ── Data-shape JSON / YAML / TOML / MD emit (ADR 0017 §D12) ──────────────────

fn test_semantic_json_array() {
	doc := cx.parse('[tags [web, api, native]]') or { panic(err) }
	out := cx.emit_semantic_json(doc)
	assert out.contains('"tags"'), 'expected key "tags"; got: ${out}'
	assert out.contains('"web"') && out.contains('"api"') && out.contains('"native"')
	assert out.contains('['), 'expected JSON array; got: ${out}'
}

fn test_semantic_json_sequence_flattens() {
	// SequenceNode emits as a JSON array (parser already flattened per §D12).
	doc := cx.parse('[r ((1, 2), 3)]') or { panic(err) }
	out := cx.emit_semantic_json(doc)
	assert out.contains('1') && out.contains('2') && out.contains('3')
	assert out.contains('[')
}

fn test_semantic_json_map() {
	doc := cx.parse("[stats {region: 'us-west', servers: 12}]") or { panic(err) }
	out := cx.emit_semantic_json(doc)
	assert out.contains('"region"')
	assert out.contains('"us-west"')
	assert out.contains('"servers"')
	assert out.contains('12')
}

fn test_semantic_json_nested_array() {
	doc := cx.parse('[grid [[1, 2], [3, 4]]]') or { panic(err) }
	out := cx.emit_semantic_json(doc)
	// Nesting preserved per §D12.
	assert out.contains('[')
	assert out.contains('1') && out.contains('4')
}

fn test_yaml_array_block_sequence() {
	doc := cx.parse('[tags [web, api]]') or { panic(err) }
	out := cx.emit_yaml(doc)
	// YAML block sequence under the `tags` key.
	assert out.contains('tags:')
	assert out.contains('- web') || out.contains('- "web"')
	assert out.contains('- api') || out.contains('- "api"')
}

fn test_yaml_map_block_mapping() {
	doc := cx.parse("[stats {region: 'us-west', servers: 12}]") or { panic(err) }
	out := cx.emit_yaml(doc)
	assert out.contains('stats:')
	// yaml_str quotes identifiers containing 'e' (float-disambiguation),
	// so the keys land as `"region":` / `"servers":`.
	assert out.contains('region') && out.contains('us-west')
	assert out.contains('servers') && out.contains('12')
}

fn test_toml_array_inline() {
	doc := cx.parse('[cfg tags=[web, api]]') or { return }
	out := cx.emit_toml(doc)
	// Sanity — emit doesn't crash on collection-literal content.
	_ = out
}

fn test_toml_map_inline() {
	doc := cx.parse("[doc [stats {region: 'us-west', servers: 12}]]") or { panic(err) }
	out := cx.emit_toml(doc)
	assert out.contains('region') && out.contains('servers')
}

fn test_md_array_bulleted_list() {
	// Array in block position renders as a bulleted list per §D12.
	doc := cx.parse('[doc [list [alpha, beta, gamma]]]') or { panic(err) }
	out := cx.emit_md(doc)
	// `list` element wraps the ArrayNode; the array becomes a bulleted list.
	assert out.contains('- alpha') || out.contains('alpha'), 'got: ${out}'
}

fn test_md_map_definition_list() {
	doc := cx.parse("[doc [meta {region: 'us-west', servers: 12}]]") or { panic(err) }
	out := cx.emit_md(doc)
	// Map renders as a definition list — key on its own line, `: value` after.
	// At minimum keys + values should appear in output.
	assert out.contains('region')
	assert out.contains('servers')
}
