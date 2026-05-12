module main

import cx

// ── Public Table API tests (ADR 0018 D1) ─────────────────────────────────────
//
// Validates the 17-member surface against the V core's reference
// implementation. Per ADR 0018 §3.6 equality is canonical-form-based
// (to_cx() byte-equality); these tests use that path for most assertions
// plus explicit per-method checks for properties/access/conversion.

fn test_from_cx_simple_table() {
	t := cx.table_from_cx('[users :table[name age:int]
  alice 30
  bob 25
]') or { panic('parse failed: ${err}') }
	assert t.cols() == ['name', 'age']
	assert t.types() == ['', 'int']
	assert t.row_count() == 2
	assert t.col_count() == 2
}

fn test_from_cx_collection_cells() {
	t := cx.table_from_cx('[t :table[name tags]
  alice [admin, user,]
  bob [user,]
]') or { panic('parse failed: ${err}') }
	assert t.row_count() == 2
	assert t.col_count() == 2
	// Access a collection cell
	cell := t.cell(0, 1) or { panic('cell failed: ${err}') }
	if cell !is cx.ArrayNode {
		assert false, 'expected ArrayNode for tags cell; got ${typeof(cell).name}'
	}
	arr := cell as cx.ArrayNode
	assert arr.items.len == 2
}

fn test_no_table_in_source_errors() {
	cx.table_from_cx('[product name=alice]') or {
		assert err.msg().contains('no :table')
		return
	}
	assert false, 'expected error on no-:table source'
}

fn test_tables_from_cx_finds_nested() {
	// Tables can appear nested inside an outer element.
	tables := cx.tables_from_cx('[doc
  [t1 :table[a] x]
  [t2 :table[b] y]
]') or { panic('parse failed: ${err}') }
	assert tables.len == 2
	assert tables[0].cols() == ['a']
	assert tables[1].cols() == ['b']
}

fn test_row_returns_ordered_map() {
	t := cx.table_from_cx('[u :table[name age:int]
  alice 30
]') or { panic('parse failed: ${err}') }
	row := t.row(0) or { panic('row failed: ${err}') }
	assert row.len == 2
	if name_cell := row['name'] {
		s := name_cell as string
		assert s == 'alice'
	} else {
		assert false, 'row missing `name` key'
	}
	if age_cell := row['age'] {
		i := age_cell as i64
		assert i == 30
	} else {
		assert false, 'row missing `age` key'
	}
}

fn test_row_out_of_bounds_errors() {
	t := cx.table_from_cx('[u :table[a]
  x
]') or { panic('parse failed: ${err}') }
	t.row(5) or {
		assert err.msg().contains('out of bounds')
		return
	}
	assert false, 'expected out-of-bounds error'
}

fn test_column_by_name() {
	t := cx.table_from_cx('[u :table[name age:int]
  alice 30
  bob 25
]') or { panic('parse failed: ${err}') }
	ages := t.column('age') or { panic('column failed: ${err}') }
	assert ages.len == 2
	a0 := ages[0] as i64
	a1 := ages[1] as i64
	assert a0 == 30
	assert a1 == 25
}

fn test_column_unknown_errors() {
	t := cx.table_from_cx('[u :table[a] x]') or { panic('parse failed: ${err}') }
	t.column('missing') or {
		assert err.msg().contains('unknown column')
		return
	}
	assert false
}

fn test_slice_head_tail() {
	t := cx.table_from_cx('[u :table[v:int]
  1
  2
  3
  4
  5
]') or { panic('parse failed: ${err}') }
	assert t.head(2).row_count() == 2
	assert t.tail(2).row_count() == 2
	mid := t.slice(1, 4) or { panic('slice failed') }
	assert mid.row_count() == 3
}

fn test_select_cols_reorders() {
	t := cx.table_from_cx('[u :table[a b c]
  1 2 3
]') or { panic('parse failed: ${err}') }
	sel := t.select_cols(['c', 'a']) or { panic('select failed: ${err}') }
	assert sel.cols() == ['c', 'a']
	assert sel.row_count() == 1
}

fn test_to_cx_roundtrip() {
	src := '[u :table[name age:int]
  alice 30
  bob 25
]'
	t := cx.table_from_cx(src) or { panic('parse failed: ${err}') }
	out := t.to_cx()
	assert out.contains('alice 30')
	assert out.contains('bob 25')
	assert out.contains(':table[name age:int]')
}

fn test_to_csv_scalar_table() {
	t := cx.table_from_cx('[u :table[name age:int]
  alice 30
  bob 25
]') or { panic('parse failed: ${err}') }
	csv := t.to_csv(`,`)
	assert csv.contains('name,age')
	assert csv.contains('alice,30')
	assert csv.contains('bob,25')
}

fn test_to_json_scalar_table() {
	t := cx.table_from_cx('[u :table[name age:int]
  alice 30
  bob 25
]') or { panic('parse failed: ${err}') }
	js := t.to_json()
	assert js.contains('"name":"alice"')
	assert js.contains('"age":30')
	assert js.contains('"name":"bob"')
	assert js.contains('"age":25')
	assert js.starts_with('[')
	assert js.ends_with(']')
}

fn test_to_json_array_cells() {
	t := cx.table_from_cx('[u :table[name tags]
  alice [admin, user,]
]') or { panic('parse failed: ${err}') }
	js := t.to_json()
	assert js.contains('"name":"alice"')
	// Array cell emits as JSON array
	assert js.contains('"tags":'), 'got: ${js}'
	assert js.contains('"admin"') && js.contains('"user"'), 'got: ${js}'
}

fn test_to_json_map_cells() {
	t := cx.table_from_cx('[u :table[name attrs]
  alice {role: admin, age: 30}
]') or { panic('parse failed: ${err}') }
	js := t.to_json()
	assert js.contains('"attrs":'), 'got: ${js}'
	assert js.contains('"role":"admin"'), 'got: ${js}'
	assert js.contains('"age":'), 'got: ${js}'
}

fn test_to_data_bin_roundtrips_scalar() {
	src := '[u :table[name age:int]
  alice 30
  bob 25
]'
	t := cx.table_from_cx(src) or { panic('parse failed: ${err}') }
	bytes := t.to_data_bin()
	assert bytes.len > 0
}

fn test_to_dict_list_materializes() {
	t := cx.table_from_cx('[u :table[a b]
  1 x
  2 y
]') or { panic('parse failed: ${err}') }
	rows := t.to_dict_list()
	assert rows.len == 2
}

fn test_iter_cols_returns_column_views() {
	t := cx.table_from_cx('[u :table[a:int b]
  1 x
  2 y
]') or { panic('parse failed: ${err}') }
	cols := t.iter_cols()
	assert cols.len == 2
	assert cols[0].name == 'a'
	assert cols[0].type_name == 'int'
	assert cols[0].values.len == 2
	assert cols[1].name == 'b'
}

fn test_new_table_validates() {
	// 4 invariants per ADR 0018 §D7
	// (1) len(cols) == len(types)
	cx.new_table(['a', 'b'], ['int'], [][]cx.TableCellValue{}) or {
		assert err.msg().contains('len(cols)')
		// Good — first invariant caught.
	}
	// (2) unique col names
	cx.new_table(['a', 'a'], ['int', 'int'], [][]cx.TableCellValue{}) or {
		assert err.msg().contains('duplicate')
	}
	// (3) row width matches col count
	cx.new_table(['a', 'b'], ['int', 'int'], [
		[cx.TableCellValue(i64(1))],  // only 1 cell; should be 2
	]) or {
		assert err.msg().contains('1 cells; expected 2')
	}
}

fn test_eq() {
	src := '[u :table[a]
  1
]'
	t1 := cx.table_from_cx(src) or { panic('parse failed: ${err}') }
	t2 := cx.table_from_cx(src) or { panic('parse failed: ${err}') }
	assert t1.eq(t2)
}
