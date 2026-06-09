module main

import cx

// Tests for spec/schema.md schema
// validator container productions `arr[T]`, `seq[T]`, `map[K, V]`.
// Each test parses a schema declaring a container body, validates a
// target document, and asserts the resulting diagnostics.

// ── arr[T] ───────────────────────────────────────────────────────────────────

fn test_arr_t_happy_path() {
	schema := '[?cx schema-of ports]
[ports
  [body arr[u16] [len 1..16]]
]'
	doc := cx.parse('[ports [80, 443, 8080]]') or { panic(err) }
	rep := cx.validate(doc, schema) or { panic(err) }
	assert rep.is_valid(), 'unexpected: ${rep.diagnostics.map(it.code + " " + it.message)}'
}

fn test_arr_t_item_type_mismatch() {
	schema := '[?cx schema-of ports]
[ports
  [body arr[u16]]
]'
	doc := cx.parse("[ports [80, 'not-a-number', 443]]") or { panic(err) }
	rep := cx.validate(doc, schema) or { panic(err) }
	mut s005 := 0
	for d in rep.diagnostics {
		if d.code == 'S005' { s005++ }
	}
	assert s005 >= 1, 'expected at least one S005 for non-int item; got ${rep.diagnostics.map(it.code)}'
}

fn test_arr_t_len_under_min() {
	schema := '[?cx schema-of ports]
[ports
  [body arr[u16] [len 2..4]]
]'
	// Single-item arrays need trailing-comma form `[80,]` per the
	// disambiguation rule (comma is the array marker; `[80]` without
	// a comma parses as an element named `80`).
	doc := cx.parse('[ports [80,]]') or { panic(err) }
	rep := cx.validate(doc, schema) or { panic(err) }
	mut s018 := 0
	for d in rep.diagnostics {
		if d.code == 'S018' { s018++ }
	}
	assert s018 == 1, 'expected one S018; got ${rep.diagnostics.map(it.code + " " + it.message)}'
}

fn test_arr_t_len_over_max() {
	schema := '[?cx schema-of ports]
[ports
  [body arr[u16] [len 1..2]]
]'
	doc := cx.parse('[ports [80, 81, 82]]') or { panic(err) }
	rep := cx.validate(doc, schema) or { panic(err) }
	mut s018 := 0
	for d in rep.diagnostics {
		if d.code == 'S018' { s018++ }
	}
	assert s018 == 1
}

fn test_arr_t_wrong_container_shape() {
	// Schema declares arr but the body carries a map literal.
	schema := '[?cx schema-of ports]
[ports
  [body arr[u16]]
]'
	doc := cx.parse('[ports {a: 1, b: 2}]') or { panic(err) }
	rep := cx.validate(doc, schema) or { panic(err) }
	mut s005 := 0
	for d in rep.diagnostics {
		if d.code == 'S005' { s005++ }
	}
	assert s005 >= 1
}

// ── seq[T] ───────────────────────────────────────────────────────────────────

fn test_seq_t_happy_path() {
	schema := '[?cx schema-of result]
[result
  [body seq[string]]
]'
	doc := cx.parse("[result ('alpha', 'beta', 'gamma')]") or { panic(err) }
	rep := cx.validate(doc, schema) or { panic(err) }
	assert rep.is_valid(), 'unexpected: ${rep.diagnostics.map(it.code + " " + it.message)}'
}

fn test_seq_t_item_type_mismatch() {
	schema := '[?cx schema-of result]
[result
  [body seq[int]]
]'
	doc := cx.parse("[result (1, 'two', 3)]") or { panic(err) }
	rep := cx.validate(doc, schema) or { panic(err) }
	mut s005 := 0
	for d in rep.diagnostics {
		if d.code == 'S005' { s005++ }
	}
	assert s005 >= 1
}

// ── map[K, V] ────────────────────────────────────────────────────────────────

fn test_map_kv_happy_path() {
	schema := '[?cx schema-of stats]
[stats
  [body map[string, int]]
]'
	doc := cx.parse("[stats {region: 1, servers: 12}]") or { panic(err) }
	rep := cx.validate(doc, schema) or { panic(err) }
	assert rep.is_valid(), 'unexpected: ${rep.diagnostics.map(it.code + " " + it.message)}'
}

fn test_map_kv_value_type_mismatch() {
	schema := '[?cx schema-of stats]
[stats
  [body map[string, int]]
]'
	doc := cx.parse("[stats {region: 'us-west', servers: 12}]") or { panic(err) }
	rep := cx.validate(doc, schema) or { panic(err) }
	mut s005 := 0
	for d in rep.diagnostics {
		if d.code == 'S005' { s005++ }
	}
	assert s005 >= 1
}

// ── Nested productions ──────────────────────────────────────────────────────

fn test_nested_arr_of_arr() {
	schema := '[?cx schema-of grid]
[grid
  [body arr[arr[int]]]
]'
	doc := cx.parse('[grid [[1, 2], [3, 4]]]') or { panic(err) }
	rep := cx.validate(doc, schema) or { panic(err) }
	assert rep.is_valid(), 'unexpected: ${rep.diagnostics.map(it.code + " " + it.message)}'
}

fn test_nested_arr_of_arr_inner_mismatch() {
	schema := '[?cx schema-of grid]
[grid
  [body arr[arr[int]]]
]'
	doc := cx.parse("[grid [[1, 2], ['x', 4]]]") or { panic(err) }
	rep := cx.validate(doc, schema) or { panic(err) }
	mut s005 := 0
	for d in rep.diagnostics {
		if d.code == 'S005' { s005++ }
	}
	assert s005 >= 1
}

fn test_nested_map_of_arr() {
	schema := '[?cx schema-of lookup]
[lookup
  [body map[string, arr[int]]]
]'
	doc := cx.parse("[lookup {primary: [1, 2, 3], backup: [4, 5]}]") or { panic(err) }
	rep := cx.validate(doc, schema) or { panic(err) }
	assert rep.is_valid(), 'unexpected: ${rep.diagnostics.map(it.code + " " + it.message)}'
}

// ── Legacy :T[] desugar ─────────────────────────────────────

fn test_legacy_t_brackets_desugars_to_arr() {
	// `:i32[]` (legacy) parses identically to `arr[i32]` per §D19.
	schema := '[?cx schema-of ports]
[ports
  [body :u16[]]
]'
	doc := cx.parse('[ports [80, 443]]') or { panic(err) }
	rep := cx.validate(doc, schema) or { panic(err) }
	assert rep.is_valid(), 'unexpected: ${rep.diagnostics.map(it.code + " " + it.message)}'
}

// ── Existing v1.0 schema fixtures continue to validate ──────────────────────

fn test_scalar_bodies_still_work() {
	schema := '[?cx schema-of port]
[port
  [body u16 [range 1..65535]]
]'
	good := cx.parse('[port 8080]') or { panic(err) }
	bad := cx.parse('[port 99999]') or { panic(err) }
	gr := cx.validate(good, schema) or { panic(err) }
	br := cx.validate(bad, schema) or { panic(err) }
	assert gr.is_valid()
	assert !br.is_valid()
}
