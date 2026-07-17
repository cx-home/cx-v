module main

import cx

// #443 — the AST-JSON projection carries the pooled TableData payload
// ("table": {"cols": …, "rows": …}) and parser_ast_json reconstructs it,
// so CX → emit_ast_json → parse_ast_json → emit_cx is the identity on
// table-bearing documents. Before the fix the projection emitted a
// rowless `"items":[]` and the round-trip silently produced a bare
// `[name::table]`.

// round-trips SRC through the AST-JSON wire and asserts the recovered
// canonical CX equals the direct canonical CX of the source.
fn assert_ast_json_roundtrip(src string) {
	want := cx.to_cx(src) or { panic('to_cx: ${err}') }
	wire := cx.to_ast(src) or { panic('to_ast: ${err}') }
	got := cx.ast_to_cx(wire) or { panic('ast_to_cx: ${err}') }
	assert got == want, 'AST-JSON round-trip drifted\n  src:  ${src}\n  wire: ${wire}\n  want: ${want}\n  got:  ${got}'
}

fn test_ast_json_table_scalar_cells_roundtrip() {
	assert_ast_json_roundtrip('[users [table[name::string age::int active::bool score::float]]
  alice 30 true 1.5
  bob 25 false 2.0
]')
}

fn test_ast_json_table_null_empty_and_quoted_cells_roundtrip() {
	// '' (empty string), null, a string that looks numeric under a string
	// column, and a quoted string in an int-typed column context.
	assert_ast_json_roundtrip("[t [table[a b]]
  '' null
  '12' x
]")
}

fn test_ast_json_table_collection_cells_roundtrip() {
	assert_ast_json_roundtrip('[t [table[name value]]
  tags [admin, user]
  meta {role: admin, age: 30}
  ports (80, 443)
]')
}

fn test_ast_json_table_header_only_roundtrip() {
	assert_ast_json_roundtrip('[t [table[a::int b]]
]')
}

fn test_ast_json_table_wire_shape() {
	wire := cx.to_ast('[users [table[name::string age::int]]
  alice 30
]') or { panic(err) }
	// cols carry name + dataType; rows are arrays of JSON-native cells;
	// the redundant empty "items" is suppressed when "table" is present.
	assert wire.contains('"table":{"cols":[{"name":"name","dataType":"string"},{"name":"age","dataType":"int"}],"rows":[["alice",30]]}')
	assert !wire.contains('"items"')
}

fn test_ast_json_untyped_column_omits_datatype() {
	wire := cx.to_ast('[t [table[a::int b]]
]') or { panic(err) }
	assert wire.contains('{"name":"a","dataType":"int"},{"name":"b"}')
}

// The collection-node importer arms added for table cells also unlock
// collection literals in ordinary body position (emit_ast_json has
// always produced them; the importer used to reject the wire with
// "unknown AST node type: Array").
fn test_ast_json_body_collection_literals_roundtrip() {
	assert_ast_json_roundtrip("[t [tags ['admin', 'user']] [ports (80, 443)] [meta {role: admin}]]")
}
