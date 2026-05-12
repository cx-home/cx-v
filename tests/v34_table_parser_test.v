module main

import cx

// Tests for v3.4 :table block parser. Spec: grammar.ebnf [29].

// ── Header parsing ───────────────────────────────────────────────────────────

fn test_table_header_typed_columns() {
	src := '[users :table[name:string age:int active:bool]
  alice 30 true
  bob 25 false
]'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	t := root.table or { panic('expected table data on element') }
	assert t.cols.len == 3
	assert t.cols[0].name == 'name'
	assert t.cols[0].type_name == 'string'
	assert t.cols[1].name == 'age'
	assert t.cols[1].type_name == 'int'
	assert t.cols[2].name == 'active'
	assert t.cols[2].type_name == 'bool'
}

fn test_table_untyped_columns_default_string() {
	src := '[t :table[a b c]
  x y z
  p q r
]'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	t := root.table or { panic('expected table data') }
	assert t.cols.len == 3
	for col in t.cols {
		assert col.type_name == ''
	}
}

fn test_table_mixed_typed_untyped() {
	src := '[t :table[name age:int tag]
  alice 30 admin
  bob 25 user
]'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	t := root.table or { panic('expected table data') }
	assert t.cols[0].type_name == ''
	assert t.cols[1].type_name == 'int'
	assert t.cols[2].type_name == ''
}

// ── Row parsing ──────────────────────────────────────────────────────────────

fn test_table_row_count() {
	src := '[t :table[a b]
  x y
  p q
  m n
]'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	t := root.table or { panic('expected table data') }
	assert t.rows.len == 3
}

fn test_table_typed_int_cells() {
	src := '[t :table[n:int]
  1
  2
  3
]'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	t := root.table or { panic('expected table data') }
	assert t.rows.len == 3
	if v := t.rows[0][0] {
		if v is i64 { assert v == 1 } else { assert false, 'expected i64' }
	}
}

fn test_table_typed_bool_cells() {
	src := '[t :table[active:bool]
  true
  false
  true
]'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	t := root.table or { panic('expected table data') }
	assert t.rows.len == 3
	for row in t.rows {
		c := row[0]
		assert c is bool, 'expected bool, got something else'
	}
}

fn test_table_typed_float_cells() {
	src := '[t :table[ratio:float]
  1.5
  2.5
  3.5
]'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	t := root.table or { panic('expected table data') }
	assert t.rows.len == 3
	if v := t.rows[1][0] {
		if v is f64 { assert v == 2.5 } else { assert false, 'expected f64' }
	}
}

// ── Quoted cells / null ──────────────────────────────────────────────────────

fn test_table_quoted_cell() {
	src := "[users :table[name:string age:int]
  'alice jones' 30
  bob 25
]"
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	t := root.table or { panic('expected table data') }
	if v := t.rows[0][0] {
		if v is string { assert v == 'alice jones' } else { assert false, 'expected string' }
	}
}

fn test_table_null_cell() {
	src := '[t :table[a b]
  alice null
  bob 30
]'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	t := root.table or { panic('expected table data') }
	c := t.rows[0][1]
	assert c is cx.NullValue, 'expected NullValue'
}

// ── Edge cases ───────────────────────────────────────────────────────────────

fn test_table_single_column_single_row() {
	src := '[t :table[v:int]
  42
]'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	t := root.table or { panic('expected table data') }
	assert t.cols.len == 1
	assert t.rows.len == 1
}

fn test_table_with_underscores_in_int_cells() {
	src := '[stats :table[count:int]
  1_000_000
  2_500_000
]'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	t := root.table or { panic('expected table data') }
	if v := t.rows[0][0] {
		if v is i64 { assert v == 1000000 } else { assert false, 'expected i64' }
	}
}

// ── Disambiguation: regular elements still work ──────────────────────────────

fn test_regular_element_with_string_array_unaffected() {
	// :string[] is the existing array annotation; must still work.
	src := '[tags :string[] web api docs]'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	if _ := root.table {
		assert false, 'regular element should not have table data'
	}
}

fn test_regular_element_with_typed_scalar_unaffected() {
	src := '[count :int 42]'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	if _ := root.table {
		assert false, 'scalar element should not have table data'
	}
}
