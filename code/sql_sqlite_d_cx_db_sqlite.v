module code

import cx
import db.sqlite

// sqlite engine for the SQL surface (sql.v) — gated `-d cx_db_sqlite`, so the
// default/wasm build never links libsqlite3. Implements the SqlConn trait.

struct SqliteConn {
mut:
	db sqlite.DB
}

fn new_sqlite_conn(url string) !SqlConn {
	mut path := url
	if path.starts_with('sqlite://') {
		path = path['sqlite://'.len..]
	}
	if path == '' {
		return error('malformed sqlite URL ${url}')
	}
	db := sqlite.connect(path)!
	return &SqliteConn{
		db: db
	}
}

fn (mut c SqliteConn) run(stmt string, params []string) !SqlResult {
	rows := if params.len == 0 {
		c.db.exec(stmt)!
	} else {
		c.db.exec_param_many(stmt, sqlite.Params(params))!
	}
	mut cols := []string{}
	mut data := [][]string{cap: rows.len}
	for i, r in rows {
		if i == 0 {
			cols = r.names.clone()
		}
		data << r.vals.clone()
	}
	return SqlResult{
		cols:       cols
		rows:       data
		changes:    c.db.get_affected_rows_count()
		last_rowid: c.db.last_insert_rowid()
	}
}

fn (mut c SqliteConn) shutdown() {
	c.db.close() or {}
}

// sql_open_memory_for_test registers an in-memory conn without the cap gate, so
// gated tests can exercise exec/query directly.
fn sql_open_memory_for_test() cx.Node {
	conn := new_sqlite_conn('sqlite://:memory:') or {
		return mk_err('cx-err:CXER1101', 'connect: ${err.msg()}')
	}
	return sql_register(conn, ':memory:')
}
