module main

import cx

// Tests for v3.4 :table CX-text emitter (round-trip via emit_cx).
// Spec: spec/grammar.ebnf [29], spec/canonical.md §2.

fn test_table_round_trip_basic() {
	src := '[users :table[name:string age:int active:bool]
  alice 30 true
  bob 25 false
]'
	out := cx.to_cx(src) or { panic(err) }
	// Re-parse the emitted output and verify the table data round-trips.
	doc2 := cx.parse(out) or { panic(err) }
	root := doc2.root() or { panic('no root after round-trip') }
	t := root.table or { panic('table data lost on round-trip') }
	assert t.cols.len == 3
	assert t.cols[0].name == 'name'
	assert t.cols[0].type_name == 'string'
	assert t.rows.len == 2
}

fn test_table_round_trip_untyped() {
	src := '[t :table[a b c]
  x y z
  p q r
]'
	out := cx.to_cx(src) or { panic(err) }
	doc2 := cx.parse(out) or { panic(err) }
	root := doc2.root() or { panic('no root') }
	t := root.table or { panic('table data lost') }
	assert t.cols.len == 3
	for col in t.cols {
		assert col.type_name == ''
	}
}

fn test_table_round_trip_typed_cells_preserve_values() {
	src := '[stats :table[count:int ratio:float active:bool]
  100 1.5 true
  200 2.5 false
]'
	out := cx.to_cx(src) or { panic(err) }
	doc2 := cx.parse(out) or { panic(err) }
	root := doc2.root() or { panic('no root') }
	t := root.table or { panic('table data lost') }
	if v := t.rows[0][0] {
		if v is i64 { assert v == 100 } else { assert false, 'expected i64' }
	}
	if v := t.rows[1][1] {
		if v is f64 { assert v == 2.5 } else { assert false, 'expected f64' }
	}
}

fn test_table_round_trip_with_nulls() {
	src := '[t :table[a b]
  alice null
  null 30
]'
	out := cx.to_cx(src) or { panic(err) }
	doc2 := cx.parse(out) or { panic(err) }
	root := doc2.root() or { panic('no root') }
	t := root.table or { panic('table data lost') }
	c1 := t.rows[0][1]
	c2 := t.rows[1][0]
	assert c1 is cx.NullValue
	assert c2 is cx.NullValue
}

fn test_table_round_trip_quoted_strings() {
	src := "[u :table[name:string]
  'alice jones'
  'bob smith'
]"
	out := cx.to_cx(src) or { panic(err) }
	doc2 := cx.parse(out) or { panic(err) }
	root := doc2.root() or { panic('no root') }
	t := root.table or { panic('table data lost') }
	if v := t.rows[0][0] {
		if v is string { assert v == 'alice jones' } else { assert false, 'expected string' }
	}
}

fn test_table_emitter_idempotent() {
	src := '[u :table[name age:int]
  alice 30
  bob 25
]'
	out1 := cx.to_cx(src) or { panic(err) }
	out2 := cx.to_cx(out1) or { panic(err) }
	assert out1 == out2, 'fmt(fmt(x)) must equal fmt(x); got:\n${out1}\nvs\n${out2}'
}

fn test_table_emitter_compact_form() {
	src := '[t :table[a b]
  x y
  p q
]'
	out := cx.to_cx_compact(src) or { panic(err) }
	// Compact form: no newlines.
	assert !out.contains('\n'), 'compact output should have no newlines: ${out}'
	// Re-parse must still work.
	doc2 := cx.parse(out) or { panic(err) }
	root := doc2.root() or { panic('no root') }
	t := root.table or { panic('table data lost') }
	assert t.rows.len == 2
}

fn test_table_emitter_empty_rows() {
	src := '[t :table[a b]]'
	out := cx.to_cx(src) or { panic(err) }
	doc2 := cx.parse(out) or { panic(err) }
	root := doc2.root() or { panic('no root') }
	t := root.table or { panic('table data lost') }
	assert t.cols.len == 2
	assert t.rows.len == 0
}
