module main

import cx

// Round-trip tests for the data_bin one-shot loaders/dumpers per
// spec/abi.md §2.4–§2.5. Each test exercises the same composition the
// new C ABI symbols (cx_<fmt>_to_data_bin / cx_data_bin_to_<fmt>)
// wrap, hitting the per-format parser, emit_data_bin, parse_data_bin,
// and the per-format emitter in one round-trip.

// ── XML one-shot ─────────────────────────────────────────────────────────────

fn test_xml_round_trip_through_data_bin() {
	src := '<server><host>localhost</host><port>8080</port></server>'
	// xml → data_bin
	doc := cx.parse_xml(src) or { panic('parse_xml: ${err}') }
	bytes := cx.emit_data_bin(doc)
	assert bytes.len > 8, 'expected non-empty data_bin payload'
	// data_bin → xml (round-trip)
	doc2 := cx.parse_data_bin(bytes) or { panic('parse_data_bin: ${err}') }
	out := cx.emit_xml(doc2)
	// CX's XML round-trip may choose attribute or child-element shape
	// for scalar-bodied children; both are valid representations of
	// the same semantic content. Assert on data preservation, not
	// specific shape.
	assert out.contains('server'), 'expected server in xml output, got: ${out}'
	assert out.contains('localhost'), 'expected localhost in xml output, got: ${out}'
	assert out.contains('8080'), 'expected 8080 in xml output, got: ${out}'
}

// ── JSON one-shot ────────────────────────────────────────────────────────────

fn test_json_round_trip_through_data_bin() {
	src := '{"name": "alice", "id": 1}'
	doc := cx.parse_json(src) or { panic('parse_json: ${err}') }
	bytes := cx.emit_data_bin(doc)
	assert bytes.len > 8
	doc2 := cx.parse_data_bin(bytes) or { panic('parse_data_bin: ${err}') }
	out := cx.emit_semantic_json(doc2)
	assert out.contains('alice'), 'expected alice in json output, got: ${out}'
	assert out.contains('1'), 'expected 1 in json output, got: ${out}'
}

// ── YAML one-shot ────────────────────────────────────────────────────────────

fn test_yaml_round_trip_through_data_bin() {
	src := 'name: alice
id: 1
'
	doc := cx.parse_yaml(src) or { panic('parse_yaml: ${err}') }
	bytes := cx.emit_data_bin(doc)
	assert bytes.len > 8
	doc2 := cx.parse_data_bin(bytes) or { panic('parse_data_bin: ${err}') }
	out := cx.emit_yaml(doc2)
	assert out.contains('alice'), 'expected alice in yaml output, got: ${out}'
}

// ── TOML one-shot ────────────────────────────────────────────────────────────

fn test_toml_round_trip_through_data_bin() {
	src := 'name = "alice"
id = 1
'
	doc := cx.parse_toml(src) or { panic('parse_toml: ${err}') }
	bytes := cx.emit_data_bin(doc)
	assert bytes.len > 8
	doc2 := cx.parse_data_bin(bytes) or { panic('parse_data_bin: ${err}') }
	out := cx.emit_toml(doc2)
	assert out.contains('alice'), 'expected alice in toml output, got: ${out}'
}

// ── Markdown one-shot ────────────────────────────────────────────────────────

fn test_md_round_trip_through_data_bin() {
	src := '# Title

A paragraph.
'
	res := cx.parse_md_cx(src) or { panic('parse_md_cx: ${err}') }
	doc := res.single or { panic('expected single-doc markdown') }
	bytes := cx.emit_data_bin(doc)
	assert bytes.len > 8
	doc2 := cx.parse_data_bin(bytes) or { panic('parse_data_bin: ${err}') }
	out := cx.emit_md(doc2)
	assert out.contains('Title'), 'expected Title in md output, got: ${out}'
}

// ── Cross-format dumper: xml → data_bin → json ────────────────────────────────

fn test_xml_to_data_bin_to_json() {
	src := '<user id="1" name="alice"/>'
	doc := cx.parse_xml(src) or { panic('parse_xml: ${err}') }
	bytes := cx.emit_data_bin(doc)
	doc2 := cx.parse_data_bin(bytes) or { panic('parse_data_bin: ${err}') }
	out := cx.emit_semantic_json(doc2)
	assert out.contains('alice'), 'expected alice in json output, got: ${out}'
	assert out.contains('1'), 'expected id 1 in json output, got: ${out}'
}

// ── Cross-format loader: json → data_bin → yaml ──────────────────────────────

fn test_json_to_data_bin_to_yaml() {
	src := '{"name": "alice", "active": true}'
	doc := cx.parse_json(src) or { panic('parse_json: ${err}') }
	bytes := cx.emit_data_bin(doc)
	doc2 := cx.parse_data_bin(bytes) or { panic('parse_data_bin: ${err}') }
	out := cx.emit_yaml(doc2)
	assert out.contains('alice'), 'expected alice in yaml output, got: ${out}'
}
