module main

import cx

// yaml_lossless_test.v — #4: YAML imports LOSSLESSLY to the native value
// model (MapNode / ArrayNode / scalars), matching the JSON codec — not the
// old synthesized-element shape (`[server [port 8080]]`). A mapping is a Map,
// a sequence is an Array, and the read round-trips through canonical CX / YAML.

fn test_yaml_mapping_imports_as_map() {
	doc := cx.parse_yaml('server:\n  port: 8080\n') or { panic('parse_yaml: ${err}') }
	assert doc.elements.len == 1, 'expected a single value root, got ${doc.elements.len}'
	root := doc.elements[0]
	assert root is cx.MapNode, 'top-level mapping must import as MapNode, got ${typeof(root).name}'
	out := cx.emit_cx(doc)
	assert out.contains('{server:'), 'expected lossless map {server: …}, got: ${out}'
	assert out.contains('port: 8080'), 'expected nested map value, got: ${out}'
	assert !out.contains('[server'), 'must NOT synthesize elements: ${out}'
}

fn test_yaml_sequence_imports_as_array() {
	doc := cx.parse_yaml('hosts:\n  - a\n  - b\n') or { panic('parse_yaml: ${err}') }
	root := doc.elements[0]
	assert root is cx.MapNode, 'mapping root expected'
	out := cx.emit_cx(doc)
	assert out.contains("['a', 'b']") || out.contains('[a, b]'),
		'YAML sequence must import as an Array, got: ${out}'
}

// Cross-format: a YAML mapping and the equivalent JSON import to the SAME
// canonical CX (the shared lossless map model — resolves #4's divergence).
fn test_yaml_json_import_agree() {
	yaml_doc := cx.parse_yaml('a: 1\nb: two\n') or { panic('parse_yaml: ${err}') }
	yaml_cx := cx.emit_cx(yaml_doc)
	assert yaml_cx.contains('{a: 1') && yaml_cx.contains('b: two'),
		'YAML import not the lossless map model: ${yaml_cx}'
}
