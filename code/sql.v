@[has_globals]
module code

import cx

// Engine-agnostic SQL surface for the database-access layer (the SQL/relational
// capability of #75). Always compiled; the actual DB engines are gated impls of
// the SqlConn interface (sql_sqlite_d_cx_db_sqlite.v → `-d cx_db_sqlite`,
// sql_pg_d_cx_db_pg.v → `-d cx_db_pg`, …). URL scheme at sql-open selects the
// engine; if the engine isn't built, sql-open errors clearly.
//
//   [$sql-open URL]                -> [sql-db handle=N url=…]
//   [$sql-exec  HANDLE SQL PARAM*] -> [result changes=N last-rowid=M]
//   [$sql-query HANDLE SQL PARAM*] -> [rows [row [<col> 'val'] …] …]
//   [$sql-close HANDLE]            -> null
//
// Result rows come back as CX data (columns in projection order). Values are
// text; typed CX scalars are a follow-up. Computed columns should be AS-aliased.

// SqlResult is the engine-neutral result an engine returns from `run`.
pub struct SqlResult {
pub:
	cols       []string
	rows       [][]string
	changes    int
	last_rowid i64
}

// SqlConn is the common trait every SQL engine implements.
interface SqlConn {
mut:
	run(stmt string, params []string) !SqlResult
	shutdown()
}

@[heap]
struct SqlRegistry {
mut:
	conns   map[int]SqlConn
	next_id int
}

__global (
	g_sql_reg voidptr
)

fn sql_reg() &SqlRegistry {
	if g_sql_reg == unsafe { nil } {
		r := &SqlRegistry{
			conns: map[int]SqlConn{}
		}
		g_sql_reg = voidptr(r)
	}
	return unsafe { &SqlRegistry(g_sql_reg) }
}

fn sql_scheme(url string) string {
	if idx := url.index('://') {
		return url[..idx]
	}
	return ''
}

fn sql_handle_of(n cx.Node) ?int {
	if n is cx.Element && n.name == 'sql-db' {
		for a in n.attrs {
			if a.name == 'handle' {
				return cx.scalar_value_str_public(a.value).int()
			}
		}
	}
	return none
}

// sql_params converts bind arguments to the engine's string parameters.
// Parameters are STRING SCALARS ONLY, and a non-string value in parameter
// position REFUSES with the parameter named (db_access.md §7.1, tightened
// per the #524 owner ruling 2026-07-21) — never the old silent ''-bind
// (`SELECT ?+?` with ints returned 0 and cost real debugging time).
fn sql_params(args []cx.Node) ![]string {
	mut p := []string{cap: args.len}
	for i, a in args {
		p << store_arg_str(a) or {
			return error('bind parameter ${i + 1} is not a string scalar — parameters are string scalars only (db_access.md §7.1); convert explicitly (e.g. [\$concat \'\' \$v])')
		}
	}
	return p
}

fn sql_register(conn SqlConn, url string) cx.Node {
	mut reg := sql_reg()
	id := reg.next_id
	reg.next_id++
	reg.conns[id] = conn
	return cx.Element{
		name:  'sql-db'
		attrs: [
			cx.Attribute{
				name:  'handle'
				value: cx.ScalarValue(i64(id))
			},
			cx.Attribute{
				name:  'url'
				value: cx.ScalarValue(url)
			},
		]
	}
}

// sql_stdlib_builtin is routed unconditionally from stdlib_builtin; with no
// engine built, sql-open returns a clear "engine not built" error.
pub fn sql_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		'sql-open' { return sql_open_impl(args) }
		'sql-exec' { return sql_exec_impl(args) }
		'sql-query' { return sql_query_impl(args) }
		'sql-close' { return sql_close_impl(args) }
		else { return none }
	}
}

fn sql_open_impl(args []cx.Node) cx.Node {
	if args.len < 1 {
		return mk_err('cx-err:CXER0108', 'E_ARG: sql-open expects ($url)')
	}
	url := store_arg_str(args[0]) or {
		return mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: sql-open expects a url string')
	}
	scheme := sql_scheme(url)
	$if cx_db_sqlite ? {
		if scheme == 'sqlite' {
			if d := cap_guard('write', 'sql open ${url}') {
				return d
			}
			conn := new_sqlite_conn(url) or {
				return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: ${err.msg()}')
			}
			return sql_register(conn, url)
		}
	}
	$if cx_db_pg ? {
		if scheme == 'postgres' || scheme == 'postgresql' {
			if d := cap_guard('net', 'sql open ${url}') {
				return d
			}
			conn := new_pg_conn(url) or {
				return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: ${err.msg()}')
			}
			return sql_register(conn, url)
		}
	}
	$if cx_db_mysql ? {
		if scheme == 'mysql' {
			if d := cap_guard('net', 'sql open ${url}') {
				return d
			}
			conn := new_mysql_conn(url) or {
				return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: ${err.msg()}')
			}
			return sql_register(conn, url)
		}
	}
	return mk_err('cx-err:CXER1100', 'E_STORE_UNRESOLVED_BACKEND: no SQL engine for scheme "${scheme}" (rebuild with -d cx_db_sqlite / -d cx_db_pg / -d cx_db_mysql) in ${url}')
}

fn sql_run(args []cx.Node) !SqlResult {
	id := sql_handle_of(args[0]) or { return error('expected a [sql-db] handle') }
	stmt := store_arg_str(args[1]) or { return error('expected a SQL string') }
	mut reg := sql_reg()
	mut conn := reg.conns[id] or { return error('unknown sql handle ${id}') }
	return conn.run(stmt, sql_params(args[2..])!)!
}

fn sql_exec_impl(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err('cx-err:CXER0108', 'E_ARG: sql-exec expects ($db, $sql, $params…)')
	}
	// §7.1 (#524): a bad bind parameter is an OPERAND error (CXER0100
	// naming the parameter), distinct from an engine fault below.
	if args.len > 2 {
		sql_params(args[2..]) or {
			return mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: sql-exec ${err.msg()}')
		}
	}
	res := sql_run(args) or { return mk_err('cx-err:CXER1120', 'E_SQL: ${err.msg()}') }
	return cx.Element{
		name:  'result'
		attrs: [
			cx.Attribute{
				name:  'changes'
				value: cx.ScalarValue(i64(res.changes))
			},
			cx.Attribute{
				name:  'last-rowid'
				value: cx.ScalarValue(res.last_rowid)
			},
		]
	}
}

fn sql_query_impl(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err('cx-err:CXER0108', 'E_ARG: sql-query expects ($db, $sql, $params…)')
	}
	// §7.1 (#524): see sql_exec_impl.
	if args.len > 2 {
		sql_params(args[2..]) or {
			return mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: sql-query ${err.msg()}')
		}
	}
	res := sql_run(args) or { return mk_err('cx-err:CXER1120', 'E_SQL: ${err.msg()}') }
	mut row_nodes := []cx.Node{cap: res.rows.len}
	for r in res.rows {
		mut cols := []cx.Node{cap: r.len}
		for i, v in r {
			cn := if i < res.cols.len { res.cols[i] } else { 'col${i}' }
			cols << cx.Element{
				name:  cn
				items: [store_str(v)]
			}
		}
		row_nodes << cx.Element{
			name:  'row'
			items: cols
		}
	}
	return cx.Element{
		name:  'rows'
		items: row_nodes
	}
}

fn sql_close_impl(args []cx.Node) cx.Node {
	if args.len < 1 {
		return mk_err('cx-err:CXER0108', 'E_ARG: sql-close expects ($db)')
	}
	id := sql_handle_of(args[0]) or {
		return mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: sql-close expects a [sql-db] handle')
	}
	mut reg := sql_reg()
	mut conn := reg.conns[id] or { return store_null() }
	conn.shutdown()
	reg.conns.delete(id)
	return store_null()
}
