module platform

import db.pg

// postgres engine for the SQL surface (sql.v) — gated `-d cx_db_pg`, so the
// default/wasm build never links libpq. Implements the SqlConn trait. The
// sql-open URL is a libpq conninfo / `postgres://` URI (libpq parses both);
// networked, so sql-open cap-guards `net`.

struct PgConn {
mut:
	db &pg.DB = unsafe { nil }
}

fn new_pg_conn(url string) !SqlConn {
	db := pg.connect_with_conninfo(url, pg.PoolConfig{})!
	return &PgConn{
		db: db
	}
}

fn (mut c PgConn) run(stmt string, params []string) !SqlResult {
	res := if params.len == 0 {
		c.db.exec_result(stmt)!
	} else {
		c.db.exec_param_many_result(stmt, params)!
	}
	// Result.cols is name->index; invert to ordered column names
	mut cols := []string{len: res.cols.len, init: ''}
	for name, idx in res.cols {
		if idx >= 0 && idx < cols.len {
			cols[idx] = name
		}
	}
	mut data := [][]string{cap: res.rows.len}
	for r in res.rows {
		data << r.values() // NULL flattened to ''
	}
	// pg has no sqlite-style rowid; changes is row count (note: affected-row
	// count for INSERT/UPDATE is a follow-up — use RETURNING for ids).
	return SqlResult{
		cols:       cols
		rows:       data
		changes:    res.rows.len
		last_rowid: 0
	}
}

fn (mut c PgConn) shutdown() {
	c.db.close() or {}
}
