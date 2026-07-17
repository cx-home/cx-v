module code

import cx

// Gated SQL surface test. Body is behind `$if cx_db_sqlite ?` so the default
// build (no flag) compiles this as a no-op and never links libsqlite3; with
// `-d cx_db_sqlite` it exercises exec/query (cap-free) via an in-memory DB.
fn test_sql_exec_and_query() {
	$if cx_db_sqlite ? {
		h := sql_open_memory_for_test()
		sql_exec_impl([h, store_str('CREATE TABLE t (id INTEGER, name TEXT, role TEXT)')])
		sql_exec_impl([h, store_str('INSERT INTO t VALUES (?, ?, ?)'), store_str('1'),
			store_str('alice'), store_str('admin')])
		sql_exec_impl([h, store_str('INSERT INTO t VALUES (?, ?, ?)'), store_str('2'),
			store_str('bob'), store_str('viewer')])
		sql_exec_impl([h, store_str('INSERT INTO t VALUES (?, ?, ?)'), store_str('3'),
			store_str('carol'), store_str('admin')])

		// parameterized SELECT → CX rows, filtered + ordered by SQL
		res := sql_query_impl([h, store_str('SELECT name, role FROM t WHERE role = ? ORDER BY name'),
			store_str('admin')])
		assert res is cx.Element
		if res is cx.Element {
			assert res.name == 'rows'
			assert res.items.len == 2 // alice + carol
			first := res.items[0]
			assert first is cx.Element
			if first is cx.Element {
				assert first.name == 'row'
				// columns preserved in SELECT order: name, role
				assert first.items.len == 2
			}
		}

		// aggregate (unique-to-SQL power): GROUP BY + COUNT
		agg := sql_query_impl([h, store_str('SELECT role, COUNT(*) AS n FROM t GROUP BY role ORDER BY role')])
		assert agg is cx.Element
		if agg is cx.Element {
			assert agg.items.len == 2 // admin, viewer
		}
	}
}
