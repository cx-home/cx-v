module main

import cx

// toml_lossless_test.v — #5: TOML imports LOSSLESSLY to the native value
// model (MapNode / ArrayNode / scalars), matching JSON/YAML — not the old
// synthesized-element shape (`[server [port 8080]]`). TOML tables → nested
// maps; arrays → Arrays; nested `[a.b]` tables → nested maps.

fn test_toml_table_imports_as_map() {
	doc := cx.parse_toml('[server]\nport = 8080\n') or { panic('parse_toml: ${err}') }
	assert doc.elements.len == 1, 'expected a single value root, got ${doc.elements.len}'
	root := doc.elements[0]
	assert root is cx.MapNode, 'top-level TOML must import as MapNode, got ${typeof(root).name}'
	out := cx.emit_cx(doc)
	assert out.contains('{server:'), 'expected lossless map {server: …}, got: ${out}'
	assert out.contains('port: 8080'), 'expected nested map value, got: ${out}'
	assert !out.contains('[server'), 'must NOT synthesize elements: ${out}'
}

fn test_toml_nested_table_and_array() {
	doc := cx.parse_toml('[server]\nhosts = ["a", "b"]\n[server.db]\nname = "main"\n') or {
		panic('parse_toml: ${err}')
	}
	out := cx.emit_cx(doc)
	assert out.contains("['a', 'b']") || out.contains('[a, b]'),
		'TOML array must import as an Array, got: ${out}'
	assert out.contains('db: {name:'), 'nested [server.db] table must be a nested map, got: ${out}'
}
